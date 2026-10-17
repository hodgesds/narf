//! seccomp(2): strict mode and classic-BPF syscall filters
//! (`kernel/seccomp.c`).
//!
//! A task's seccomp state is a mode plus a singly linked chain of filters,
//! newest first. Each `SECCOMP_SET_MODE_FILTER` pushes a filter on top of the
//! chain; `fork`/`clone` share the chain (`Arc`), and `execve` keeps it.
//! Nothing ever removes a filter: seccomp is one-way.
//!
//! At every syscall entry ([`secure_computing`]) every filter in the chain
//! runs over a [`SeccompData`] built from the registers, and the action with
//! the lowest `SECCOMP_RET_ACTION_FULL` value (as a signed 32-bit number, so
//! `KILL_PROCESS` outranks everything) decides what happens:
//!
//! | action        | effect                                                    |
//! |---------------|-----------------------------------------------------------|
//! | KILL_PROCESS  | SIGSYS, core dump, the whole thread group dies            |
//! | KILL_THREAD   | the thread exits with SIGSYS (the group too if it is last)|
//! | TRAP          | syscall skipped, SIGSYS with `SYS_SECCOMP` and `si_errno` |
//! | ERRNO         | syscall skipped, returns `-data` (capped at MAX_ERRNO)    |
//! | USER_NOTIF    | queue `seccomp_notif`; listener answers `RECV` / `SEND`   |
//! | TRACE         | ptrace event stop if the tracer asked, else `-ENOSYS`     |
//! | LOG, ALLOW    | the syscall runs                                          |
//!
//! The filter validator is Linux's `bpf_check_classic` followed by
//! `seccomp_check_filter`, so a program Linux accepts is accepted here and one
//! Linux rejects with EINVAL is rejected with EINVAL.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_IN};
use narf_lib::sync::IrqSafeSpinLock;

use crate::errno::{to_ret as err, *};
use crate::handlers::{copy_from_user, copy_to_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};

// ── UAPI (`include/uapi/linux/seccomp.h`, `include/linux/seccomp.h`) ──

pub const SECCOMP_MODE_DISABLED: u8 = 0;
pub const SECCOMP_MODE_STRICT: u8 = 1;
pub const SECCOMP_MODE_FILTER: u8 = 2;
/// Internal: a task a `RET_KILL_*` has condemned (`SECCOMP_MODE_DEAD`).
const SECCOMP_MODE_DEAD: u8 = SECCOMP_MODE_FILTER + 1;

const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;
const SECCOMP_FILTER_FLAG_MASK: u32 = SECCOMP_FILTER_FLAG_TSYNC
    | SECCOMP_FILTER_FLAG_LOG
    | SECCOMP_FILTER_FLAG_SPEC_ALLOW
    | SECCOMP_FILTER_FLAG_NEW_LISTENER
    | SECCOMP_FILTER_FLAG_TSYNC_ESRCH
    | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
/// `SECCOMP_IOCTL_NOTIF_RECV` / `SEND` / `ID_VALID`. These use the common
/// Linux `_IOC` layout on x86_64 and aarch64.
const SECCOMP_IOCTL_NOTIF_RECV: u32 = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: u32 = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: u32 = 0x4008_2102;

/// `MAX_ERRNO` (`include/linux/err.h`).
const MAX_ERRNO: u32 = 4095;

/// `SYS_SECCOMP`, the SIGSYS `si_code` for a seccomp TRAP.
pub const SYS_SECCOMP: i32 = 1;

/// `AUDIT_ARCH_*` for `seccomp_data.arch` / `si_arch`.
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(target_arch = "aarch64"))]
pub const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64

/// `BPF_MAXINSNS`.
const BPF_MAXINSNS: usize = 4096;
/// `MAX_INSNS_PER_PATH`: 256 KiB of `sock_filter`s along any chain.
const MAX_INSNS_PER_PATH: usize = (1 << 18) / 8;
/// `BPF_MEMWORDS`.
const BPF_MEMWORDS: u32 = 16;
/// `sizeof(struct seccomp_data)`.
const SECCOMP_DATA_SIZE: u32 = 64;

/// The mode-1 syscalls (`mode1_syscalls[]`): read, write, exit, rt_sigreturn.
#[cfg(target_arch = "aarch64")]
const STRICT_ALLOWED: [u32; 4] = [63, 64, 93, 139];
#[cfg(not(target_arch = "aarch64"))]
const STRICT_ALLOWED: [u32; 4] = [0, 1, 60, 15];

// ── classic BPF (`include/uapi/linux/filter.h`, `bpf_common.h`) ──

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

/// `SKF_AD_OFF`: ancillary-data loads start here.
const SKF_AD_OFF: u32 = 0xffff_f000;
/// The ancillary offsets `bpf_anc_helper` knows (`SKF_AD_PROTOCOL` ..
/// `SKF_AD_RANDOM`, plus `SKF_AD_VLAN_TPID`): `SKF_AD_OFF + 0 ..= +60`, in
/// steps of 4. A load from any other ancillary offset is "unknown or
/// unsupported" and `bpf_check_classic` rejects it.
const SKF_AD_MAX: u32 = 64;

/// `struct sock_filter`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    fn from_bytes(b: &[u8]) -> Self {
        Self {
            code: u16::from_ne_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// `struct seccomp_data`.
#[derive(Copy, Clone, Debug, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    /// The 32-bit word at byte offset `off` (validated aligned and in range
    /// by `seccomp_check_filter`), in native byte order as Linux leaves it.
    fn word(&self, off: u32) -> u32 {
        match off {
            0 => self.nr as u32,
            4 => self.arch,
            8 => self.instruction_pointer as u32,
            12 => (self.instruction_pointer >> 32) as u32,
            o => {
                let i = ((o - 16) / 8) as usize;
                let v = self.args[i];
                if (o - 16) % 8 == 0 {
                    v as u32
                } else {
                    (v >> 32) as u32
                }
            }
        }
    }
}

/// One attached filter. `prev` is the filter that was on top when this one
/// was attached (Linux `seccomp_filter.prev`).
pub struct SeccompFilter {
    prog: Vec<SockFilter>,
    prev: Option<Arc<SeccompFilter>>,
    /// `SECCOMP_FILTER_FLAG_LOG`.
    log: bool,
    /// The single user-notification listener created with this filter, if
    /// any. The filter retains it after its returned fd is closed, just as
    /// Linux keeps the notification object attached to the filter chain.
    listener: Option<Arc<UserNotifListener>>,
}

impl core::fmt::Debug for SeccompFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SeccompFilter")
            .field("len", &self.prog.len())
            .field("log", &self.log)
            .field("has_listener", &self.listener.is_some())
            .field("has_prev", &self.prev.is_some())
            .finish()
    }
}

impl Drop for SeccompFilter {
    /// Unlink the chain iteratively. A chain may be thousands of filters
    /// long; the derived recursive drop would walk the kernel stack once per
    /// filter (Linux `__put_seccomp_filter` is a loop for the same reason).
    fn drop(&mut self) {
        let mut next = self.prev.take();
        while let Some(f) = next {
            match Arc::try_unwrap(f) {
                Ok(mut owned) => next = owned.prev.take(),
                Err(_) => break,
            }
        }
    }
}

impl SeccompFilter {
    /// Filters on the chain starting at `self`.
    fn chain_len(self: &Arc<Self>) -> usize {
        let mut n = 0;
        let mut f = Some(self);
        while let Some(cur) = f {
            n += 1;
            f = cur.prev.as_ref();
        }
        n
    }
}

/// Is `ancestor` on `child`'s chain? `None` is everybody's ancestor
/// (`is_ancestor`).
fn is_ancestor(ancestor: Option<&Arc<SeccompFilter>>, child: Option<&Arc<SeccompFilter>>) -> bool {
    let Some(a) = ancestor else {
        return true;
    };
    let mut c = child;
    while let Some(f) = c {
        if Arc::ptr_eq(f, a) {
            return true;
        }
        c = f.prev.as_ref();
    }
    false
}

// ── Validation ──

/// `chk_code_allowed` — the opcodes classic BPF knows at all.
fn chk_code_allowed(code: u16) -> bool {
    matches!(
        code,
        c if c == BPF_ALU | BPF_ADD | BPF_K
            || c == BPF_ALU | BPF_ADD | BPF_X
            || c == BPF_ALU | BPF_SUB | BPF_K
            || c == BPF_ALU | BPF_SUB | BPF_X
            || c == BPF_ALU | BPF_MUL | BPF_K
            || c == BPF_ALU | BPF_MUL | BPF_X
            || c == BPF_ALU | BPF_DIV | BPF_K
            || c == BPF_ALU | BPF_DIV | BPF_X
            || c == BPF_ALU | BPF_MOD | BPF_K
            || c == BPF_ALU | BPF_MOD | BPF_X
            || c == BPF_ALU | BPF_AND | BPF_K
            || c == BPF_ALU | BPF_AND | BPF_X
            || c == BPF_ALU | BPF_OR | BPF_K
            || c == BPF_ALU | BPF_OR | BPF_X
            || c == BPF_ALU | BPF_XOR | BPF_K
            || c == BPF_ALU | BPF_XOR | BPF_X
            || c == BPF_ALU | BPF_LSH | BPF_K
            || c == BPF_ALU | BPF_LSH | BPF_X
            || c == BPF_ALU | BPF_RSH | BPF_K
            || c == BPF_ALU | BPF_RSH | BPF_X
            || c == BPF_ALU | BPF_NEG
            || c == BPF_LD | BPF_W | BPF_ABS
            || c == BPF_LD | BPF_H | BPF_ABS
            || c == BPF_LD | BPF_B | BPF_ABS
            || c == BPF_LD | BPF_W | BPF_LEN
            || c == BPF_LD | BPF_W | BPF_IND
            || c == BPF_LD | BPF_H | BPF_IND
            || c == BPF_LD | BPF_B | BPF_IND
            || c == BPF_LD | BPF_IMM
            || c == BPF_LD | BPF_MEM
            || c == BPF_LDX | BPF_W | BPF_LEN
            || c == BPF_LDX | BPF_B | BPF_MSH
            || c == BPF_LDX | BPF_IMM
            || c == BPF_LDX | BPF_MEM
            || c == BPF_ST
            || c == BPF_STX
            || c == BPF_MISC | BPF_TAX
            || c == BPF_MISC | BPF_TXA
            || c == BPF_RET | BPF_K
            || c == BPF_RET | BPF_A
            || c == BPF_JMP | BPF_JA
            || c == BPF_JMP | BPF_JEQ | BPF_K
            || c == BPF_JMP | BPF_JEQ | BPF_X
            || c == BPF_JMP | BPF_JGE | BPF_K
            || c == BPF_JMP | BPF_JGE | BPF_X
            || c == BPF_JMP | BPF_JGT | BPF_K
            || c == BPF_JMP | BPF_JGT | BPF_X
            || c == BPF_JMP | BPF_JSET | BPF_K
            || c == BPF_JMP | BPF_JSET | BPF_X
    )
}

fn is_cond_jump(code: u16) -> bool {
    code & 0x07 == BPF_JMP && code != (BPF_JMP | BPF_JA)
}

/// `check_load_and_stores`: no scratch cell may be read on any path before
/// it is written.
fn check_load_and_stores(prog: &[SockFilter]) -> bool {
    let flen = prog.len();
    let mut masks = alloc::vec![0xffffu16; flen];
    let mut memvalid: u16 = 0;
    for (pc, ins) in prog.iter().enumerate() {
        memvalid &= masks[pc];
        match ins.code {
            c if c == BPF_ST || c == BPF_STX => memvalid |= 1 << ins.k,
            c if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM => {
                if memvalid & (1 << ins.k) == 0 {
                    return false;
                }
            }
            c if c == BPF_JMP | BPF_JA => {
                masks[pc + 1 + ins.k as usize] &= memvalid;
                memvalid = !0;
            }
            c if is_cond_jump(c) => {
                masks[pc + 1 + ins.jt as usize] &= memvalid;
                masks[pc + 1 + ins.jf as usize] &= memvalid;
                memvalid = !0;
            }
            _ => {}
        }
    }
    true
}

/// `bpf_check_classic`.
fn bpf_check_classic(prog: &[SockFilter]) -> bool {
    let flen = prog.len();
    for (pc, ins) in prog.iter().enumerate() {
        if !chk_code_allowed(ins.code) {
            return false;
        }
        let c = ins.code;
        if c == BPF_ALU | BPF_DIV | BPF_K || c == BPF_ALU | BPF_MOD | BPF_K {
            if ins.k == 0 {
                return false;
            }
        } else if c == BPF_ALU | BPF_LSH | BPF_K || c == BPF_ALU | BPF_RSH | BPF_K {
            if ins.k >= 32 {
                return false;
            }
        } else if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM || c == BPF_ST || c == BPF_STX {
            if ins.k >= BPF_MEMWORDS {
                return false;
            }
        } else if c == BPF_JMP | BPF_JA {
            if ins.k as usize >= flen - pc - 1 {
                return false;
            }
        } else if is_cond_jump(c) {
            if pc + ins.jt as usize + 1 >= flen || pc + ins.jf as usize + 1 >= flen {
                return false;
            }
        } else if c == BPF_LD | BPF_W | BPF_ABS
            || c == BPF_LD | BPF_H | BPF_ABS
            || c == BPF_LD | BPF_B | BPF_ABS
        {
            // `bpf_anc_helper`: only the known ancillary offsets.
            let anc = ins.k >= SKF_AD_OFF && (ins.k - SKF_AD_OFF) < SKF_AD_MAX && ins.k % 4 == 0;
            if !anc && ins.k >= SKF_AD_OFF {
                return false;
            }
        }
    }
    match prog[flen - 1].code {
        c if c == BPF_RET | BPF_K || c == BPF_RET | BPF_A => check_load_and_stores(prog),
        _ => false,
    }
}

/// `seccomp_check_filter`: the seccomp subset, rewriting the two `LEN`
/// loads into immediates of `sizeof(struct seccomp_data)`.
fn seccomp_check_filter(prog: &mut [SockFilter]) -> bool {
    for ins in prog.iter_mut() {
        let c = ins.code;
        if c == BPF_LD | BPF_W | BPF_ABS {
            if ins.k >= SECCOMP_DATA_SIZE || ins.k & 3 != 0 {
                return false;
            }
            continue;
        }
        if c == BPF_LD | BPF_W | BPF_LEN {
            ins.code = BPF_LD | BPF_IMM;
            ins.k = SECCOMP_DATA_SIZE;
            continue;
        }
        if c == BPF_LDX | BPF_W | BPF_LEN {
            ins.code = BPF_LDX | BPF_IMM;
            ins.k = SECCOMP_DATA_SIZE;
            continue;
        }
        let allowed = c == BPF_RET | BPF_K
            || c == BPF_RET | BPF_A
            || c == BPF_ALU | BPF_ADD | BPF_K
            || c == BPF_ALU | BPF_ADD | BPF_X
            || c == BPF_ALU | BPF_SUB | BPF_K
            || c == BPF_ALU | BPF_SUB | BPF_X
            || c == BPF_ALU | BPF_MUL | BPF_K
            || c == BPF_ALU | BPF_MUL | BPF_X
            || c == BPF_ALU | BPF_DIV | BPF_K
            || c == BPF_ALU | BPF_DIV | BPF_X
            || c == BPF_ALU | BPF_AND | BPF_K
            || c == BPF_ALU | BPF_AND | BPF_X
            || c == BPF_ALU | BPF_OR | BPF_K
            || c == BPF_ALU | BPF_OR | BPF_X
            || c == BPF_ALU | BPF_XOR | BPF_K
            || c == BPF_ALU | BPF_XOR | BPF_X
            || c == BPF_ALU | BPF_LSH | BPF_K
            || c == BPF_ALU | BPF_LSH | BPF_X
            || c == BPF_ALU | BPF_RSH | BPF_K
            || c == BPF_ALU | BPF_RSH | BPF_X
            || c == BPF_ALU | BPF_NEG
            || c == BPF_LD | BPF_IMM
            || c == BPF_LDX | BPF_IMM
            || c == BPF_MISC | BPF_TAX
            || c == BPF_MISC | BPF_TXA
            || c == BPF_LD | BPF_MEM
            || c == BPF_LDX | BPF_MEM
            || c == BPF_ST
            || c == BPF_STX
            || c == BPF_JMP | BPF_JA
            || c == BPF_JMP | BPF_JEQ | BPF_K
            || c == BPF_JMP | BPF_JEQ | BPF_X
            || c == BPF_JMP | BPF_JGE | BPF_K
            || c == BPF_JMP | BPF_JGE | BPF_X
            || c == BPF_JMP | BPF_JGT | BPF_K
            || c == BPF_JMP | BPF_JGT | BPF_X
            || c == BPF_JMP | BPF_JSET | BPF_K
            || c == BPF_JMP | BPF_JSET | BPF_X;
        if !allowed {
            return false;
        }
    }
    true
}

/// Validate a user program exactly as `bpf_prepare_filter(fp,
/// seccomp_check_filter)` does: the generic classic-BPF checks first, then
/// the seccomp subset (which also rewrites the `LEN` loads).
pub fn validate(mut prog: Vec<SockFilter>) -> Option<Vec<SockFilter>> {
    if prog.is_empty() || prog.len() > BPF_MAXINSNS {
        return None;
    }
    if !bpf_check_classic(&prog) || !seccomp_check_filter(&mut prog) {
        return None;
    }
    Some(prog)
}

// ── Interpreter ──

/// Run one validated program. Semantics are the classic-BPF interpreter's
/// as Linux converts it to eBPF: 32-bit ALU, a runtime divide or modulo by
/// zero in `X` returns 0 from the program, shifts by `X` use its low five
/// bits (the x86 `shl`/`shr` the JIT emits).
pub fn run(prog: &[SockFilter], sd: &SeccompData) -> u32 {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; BPF_MEMWORDS as usize];
    let mut pc = 0usize;
    // Validation guarantees every jump is forward and in range and the last
    // instruction returns, so this loop terminates within prog.len() steps.
    while pc < prog.len() {
        let ins = prog[pc];
        let k = ins.k;
        pc += 1;
        match ins.code {
            c if c == BPF_RET | BPF_K => return k,
            c if c == BPF_RET | BPF_A => return a,
            c if c == BPF_LD | BPF_W | BPF_ABS => a = sd.word(k),
            c if c == BPF_LD | BPF_IMM => a = k,
            c if c == BPF_LDX | BPF_IMM => x = k,
            c if c == BPF_LD | BPF_MEM => a = mem[k as usize],
            c if c == BPF_LDX | BPF_MEM => x = mem[k as usize],
            c if c == BPF_ST => mem[k as usize] = a,
            c if c == BPF_STX => mem[k as usize] = x,
            c if c == BPF_MISC | BPF_TAX => x = a,
            c if c == BPF_MISC | BPF_TXA => a = x,
            c if c == BPF_ALU | BPF_NEG => a = a.wrapping_neg(),
            c if c & 0x07 == BPF_ALU => {
                let src = if c & BPF_X != 0 { x } else { k };
                a = match c & 0xf0 {
                    BPF_ADD => a.wrapping_add(src),
                    BPF_SUB => a.wrapping_sub(src),
                    BPF_MUL => a.wrapping_mul(src),
                    BPF_DIV => {
                        if src == 0 {
                            return 0;
                        }
                        a / src
                    }
                    BPF_MOD => {
                        if src == 0 {
                            return 0;
                        }
                        a % src
                    }
                    BPF_AND => a & src,
                    BPF_OR => a | src,
                    BPF_XOR => a ^ src,
                    BPF_LSH => a.wrapping_shl(src & 31),
                    BPF_RSH => a.wrapping_shr(src & 31),
                    _ => return 0,
                };
            }
            c if c == BPF_JMP | BPF_JA => pc += k as usize,
            c if c & 0x07 == BPF_JMP => {
                let src = if c & BPF_X != 0 { x } else { k };
                let taken = match c & 0xf0 {
                    BPF_JEQ => a == src,
                    BPF_JGT => a > src,
                    BPF_JGE => a >= src,
                    BPF_JSET => a & src != 0,
                    _ => return 0,
                };
                pc += if taken { ins.jt } else { ins.jf } as usize;
            }
            _ => return 0,
        }
    }
    0
}

/// `ACTION_ONLY`: the action bits as a signed number, so the comparison puts
/// `KILL_PROCESS` (0x80000000) below everything.
fn action_only(ret: u32) -> i32 {
    (ret & SECCOMP_RET_ACTION_FULL) as i32
}

/// `seccomp_run_filters`: the lowest action across the chain wins; returns
/// the full return value, whether the matching filter asked to log, and the
/// winning filter's user-notification listener (if it has one).
fn run_filters(
    top: &Arc<SeccompFilter>,
    sd: &SeccompData,
) -> (u32, bool, Option<Arc<UserNotifListener>>) {
    let mut ret = SECCOMP_RET_ALLOW;
    let mut log = false;
    let mut listener = None;
    let mut f = Some(top);
    while let Some(cur) = f {
        let r = run(&cur.prog, sd);
        if action_only(r) < action_only(ret) {
            ret = r;
            log = cur.log;
            listener = cur.listener.clone();
        }
        f = cur.prev.as_ref();
    }
    (ret, log, listener)
}

fn chain_has_listener(top: Option<&Arc<SeccompFilter>>) -> bool {
    let mut filter = top;
    while let Some(current) = filter {
        if current.listener.is_some() {
            return true;
        }
        filter = current.prev.as_ref();
    }
    false
}

/// One target syscall that has crossed a `RET_USER_NOTIF` filter.
#[derive(Clone)]
struct UserNotification {
    id: u64,
    task: u64,
    data: SeccompData,
    delivered: bool,
    response: Option<UserNotifResponse>,
}

#[derive(Copy, Clone)]
struct UserNotifResponse {
    value: i64,
    error: i32,
    flags: u32,
}

struct UserNotifState {
    next_id: u64,
    pending: Vec<UserNotification>,
}

/// Backing state of a Linux `struct seccomp_notif` listener fd. It is held by
/// the filter rather than by an fd-table entry, so the task's seccomp policy
/// outlives an individual duplicate/close of the listener descriptor. Public only because
/// [`Verdict::UserNotif`] is part of the seccomp evaluation surface; callers
/// receive it from the kernel path and cannot construct or mutate it directly.
pub struct UserNotifListener {
    state: IrqSafeSpinLock<UserNotifState>,
    readiness: narf_lib::readiness::Readiness,
}

impl core::fmt::Debug for UserNotifListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserNotifListener").finish_non_exhaustive()
    }
}

enum UserNotifWait {
    Queued,
    Waiting,
    Response(UserNotifResponse),
}

impl UserNotifListener {
    fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(UserNotifState {
                // Zero is not a valid notification id. Saturation is harmless
                // in practice, but preserve non-zero ids even then.
                next_id: 1,
                pending: Vec::new(),
            }),
            readiness: narf_lib::readiness::Readiness::new(0),
        }
    }

    fn sync_readiness(&self, notify: bool) {
        let queued = self
            .state
            .lock()
            .pending
            .iter()
            .any(|n| !n.delivered && n.response.is_none());
        if queued {
            self.readiness.set(POLL_IN, 0);
            if notify {
                self.readiness.notify(POLL_IN);
            }
        } else {
            self.readiness.set(0, POLL_IN);
        }
    }

    /// Return an already supplied answer for this re-executed syscall, or
    /// append one notification exactly once. An interrupted syscall that is
    /// later replaced by a different one invalidates its old id instead of
    /// accidentally delivering the old listener reply to the new call.
    fn wait_or_queue(&self, task: u64, data: SeccompData) -> UserNotifWait {
        let mut state = self.state.lock();
        if let Some(pos) = state.pending.iter().position(|n| n.task == task) {
            if state.pending[pos].data.nr == data.nr
                && state.pending[pos].data.instruction_pointer == data.instruction_pointer
                && state.pending[pos].data.args == data.args
            {
                if let Some(response) = state.pending[pos].response.take() {
                    state.pending.remove(pos);
                    drop(state);
                    self.sync_readiness(false);
                    return UserNotifWait::Response(response);
                }
                return UserNotifWait::Waiting;
            }
            state.pending.remove(pos);
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        state.pending.push(UserNotification {
            id,
            task,
            data,
            delivered: false,
            response: None,
        });
        drop(state);
        self.sync_readiness(true);
        UserNotifWait::Queued
    }

    fn cancel_task(&self, task: u64) {
        let mut state = self.state.lock();
        state
            .pending
            .retain(|notification| notification.task != task);
        drop(state);
        self.sync_readiness(false);
    }

    fn receive(&self) -> Result<(u64, [u8; 80]), FsError> {
        let mut state = self.state.lock();
        let notification = state
            .pending
            .iter_mut()
            .find(|notification| !notification.delivered && notification.response.is_none())
            .ok_or(FsError::WouldBlock)?;
        notification.delivered = true;
        let id = notification.id;
        let mut out = [0u8; 80];
        out[0..8].copy_from_slice(&notification.id.to_ne_bytes());
        // Process leaders live in the process-id map, whereas non-leader
        // CLONE_THREAD tasks have their own Linux tid entry.  seccomp_notif's
        // pid identifies the task that issued the syscall, so prefer the tid
        // mapping but fall back to the leader's visible pid rather than
        // leaking the scheduler TaskId.
        let pid = crate::handlers::task_to_linux_tid_raw(notification.task)
            .or_else(|| crate::handlers::task_to_pid_raw(notification.task))
            .unwrap_or(notification.task) as u32;
        out[8..12].copy_from_slice(&pid.to_ne_bytes());
        out[16..20].copy_from_slice(&notification.data.nr.to_ne_bytes());
        out[20..24].copy_from_slice(&notification.data.arch.to_ne_bytes());
        out[24..32].copy_from_slice(&notification.data.instruction_pointer.to_ne_bytes());
        for (index, arg) in notification.data.args.iter().enumerate() {
            let offset = 32 + index * 8;
            out[offset..offset + 8].copy_from_slice(&arg.to_ne_bytes());
        }
        drop(state);
        self.sync_readiness(false);
        Ok((id, out))
    }

    fn undeliver(&self, id: u64) {
        let mut state = self.state.lock();
        if let Some(notification) = state
            .pending
            .iter_mut()
            .find(|notification| notification.id == id && notification.response.is_none())
        {
            notification.delivered = false;
        }
        drop(state);
        self.sync_readiness(true);
    }

    fn send(&self, response: UserNotifResponse, id: u64) -> Result<(), FsError> {
        if response.error > 0 || response.flags & !SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
            return Err(FsError::InvalidData);
        }
        // CONTINUE has no accompanying return/error. Linux ignores these
        // fields, but refusing a contradictory response keeps an accidental
        // monitor bug from looking like a successfully emulated syscall.
        if response.flags & SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
            && (response.value != 0 || response.error != 0)
        {
            return Err(FsError::InvalidData);
        }
        let mut state = self.state.lock();
        let notification = state
            .pending
            .iter_mut()
            .find(|notification| notification.id == id && notification.delivered)
            .ok_or(FsError::NotFound)?;
        if notification.response.is_some() {
            return Err(FsError::NotFound);
        }
        notification.response = Some(response);
        Ok(())
    }
}

impl FileOps for UserNotifListener {
    fn ino(&self) -> u64 {
        narf_filesystem::inode_id::anon_inode().ino
    }
    fn anon_name(&self) -> Option<&'static str> {
        Some("seccomp notify")
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::inode_id::anon_inode().attrs()
    }

    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        if self
            .state
            .lock()
            .pending
            .iter()
            .any(|notification| !notification.delivered && notification.response.is_none())
        {
            POLL_IN
        } else {
            0
        }
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        Some(&self.readiness)
    }

    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            match cmd {
                SECCOMP_IOCTL_NOTIF_RECV => match self.receive() {
                    Ok((id, notification)) => {
                        if let Err(error) = context.write(arg, &notification) {
                            self.undeliver(id);
                            return Err(error);
                        }
                        Ok(0)
                    }
                    Err(FsError::WouldBlock) if !context.nonblocking() => {
                        // `NOTIF_RECV` is a blocking ioctl. Ask the generic
                        // ioctl path to rewind and retry, just like Linux's
                        // interruptible wait queue; the listener's readiness
                        // wakes poll/epoll observers immediately as well.
                        let _ = context.restart_after(1_000_000);
                        Err(FsError::WouldBlock)
                    }
                    Err(error) => Err(error),
                },
                SECCOMP_IOCTL_NOTIF_SEND => {
                    let mut input = [0u8; 24];
                    context.read(arg, &mut input)?;
                    let id = u64::from_ne_bytes(input[0..8].try_into().unwrap_or([0; 8]));
                    let value = i64::from_ne_bytes(input[8..16].try_into().unwrap_or([0; 8]));
                    let error = i32::from_ne_bytes(input[16..20].try_into().unwrap_or([0; 4]));
                    let flags = u32::from_ne_bytes(input[20..24].try_into().unwrap_or([0; 4]));
                    self.send(
                        UserNotifResponse {
                            value,
                            error,
                            flags,
                        },
                        id,
                    )?;
                    Ok(0)
                }
                SECCOMP_IOCTL_NOTIF_ID_VALID => {
                    let mut input = [0u8; 8];
                    context.read(arg, &mut input)?;
                    let id = u64::from_ne_bytes(input);
                    let valid = self.state.lock().pending.iter().any(|notification| {
                        notification.id == id && notification.response.is_none()
                    });
                    if valid {
                        Ok(0)
                    } else {
                        Err(FsError::NotFound)
                    }
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

// ── Per-task state ──

#[derive(Clone, Default)]
struct TaskSeccomp {
    mode: u8,
    filter: Option<Arc<SeccompFilter>>,
}

const SHARDS: usize = 64;

#[repr(align(64))]
struct Shard(IrqSafeSpinLock<BTreeMap<u64, TaskSeccomp>>);

static TABLE: [Shard; SHARDS] = [const { Shard(IrqSafeSpinLock::new(BTreeMap::new())) }; SHARDS];

/// Number of tasks with a non-disabled mode. Zero keeps the syscall-entry
/// hook to a single atomic load on a system that never used seccomp.
static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Serialises every filter attach (with TSYNC's whole-group update) and the
/// fork-time copy against each other, standing in for Linux's `siglock` +
/// `cred_guard_mutex`. The syscall-entry reader takes only its shard lock.
static MUTATION: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

fn shard(task: u64) -> &'static IrqSafeSpinLock<BTreeMap<u64, TaskSeccomp>> {
    &TABLE[task as usize % SHARDS].0
}

fn get(task: u64) -> TaskSeccomp {
    shard(task).lock().get(&task).cloned().unwrap_or_default()
}

fn set(task: u64, st: TaskSeccomp) {
    let mut g = shard(task).lock();
    let was = g.get(&task).map_or(SECCOMP_MODE_DISABLED, |s| s.mode);
    let now = st.mode;
    if now == SECCOMP_MODE_DISABLED {
        g.remove(&task);
    } else {
        g.insert(task, st);
    }
    drop(g);
    match (was == SECCOMP_MODE_DISABLED, now == SECCOMP_MODE_DISABLED) {
        (true, false) => {
            ACTIVE_TASKS.fetch_add(1, Ordering::Release);
        }
        (false, true) => {
            ACTIVE_TASKS.fetch_sub(1, Ordering::Release);
        }
        _ => {}
    }
}

/// `PR_GET_SECCOMP` / `/proc/<pid>/status` `Seccomp:` — `seccomp.mode`
/// verbatim, so a task a `RET_KILL` condemned reads `SECCOMP_MODE_DEAD` (3)
/// while it dies, as on Linux.
pub fn mode_of(task: u64) -> u8 {
    if ACTIVE_TASKS.load(Ordering::Acquire) == 0 {
        return SECCOMP_MODE_DISABLED;
    }
    get(task).mode
}

/// `/proc/<pid>/status` `Seccomp_filters:` — `atomic_read(&filter_count)`.
pub fn filter_count_of(task: u64) -> usize {
    if ACTIVE_TASKS.load(Ordering::Acquire) == 0 {
        return 0;
    }
    get(task)
        .filter
        .as_ref()
        .map_or(0, SeccompFilter::chain_len)
}

/// `copy_seccomp` (kernel/fork.c): a child of any `clone` shares its
/// parent's filter chain and mode.
pub fn fork(parent: u64, child: u64) {
    if ACTIVE_TASKS.load(Ordering::Acquire) == 0 {
        return;
    }
    let _m = MUTATION.lock();
    let st = get(parent);
    if st.mode != SECCOMP_MODE_DISABLED {
        set(child, st);
    }
}

/// Task teardown (`seccomp_filter_release`).
pub fn release_task(task: u64) {
    if ACTIVE_TASKS.load(Ordering::Acquire) == 0 {
        return;
    }
    if let Some(top) = get(task).filter {
        let mut filter = Some(&top);
        while let Some(current) = filter {
            if let Some(listener) = current.listener.as_ref() {
                listener.cancel_task(task);
            }
            filter = current.prev.as_ref();
        }
    }
    set(task, TaskSeccomp::default());
}

#[doc(hidden)]
pub fn __test_reset_task(task: u64) {
    release_task(task);
}

// ── Syscall-entry enforcement ──

/// What [`evaluate`] decided for one syscall.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Run the syscall.
    Allow,
    /// Skip it and return this value (already a negated errno).
    Return(i64),
    /// Skip it and raise SIGSYS (`SYS_SECCOMP`, `si_errno = data`).
    Trap(u16),
    /// Kill the whole thread group with SIGSYS and a core dump.
    KillProcess(u16),
    /// Kill only this thread with SIGSYS (others remain).
    KillThread,
    /// Strict mode: a syscall outside the four; the thread dies of SIGKILL.
    StrictKill,
    /// RET_TRACE with a tracer that asked for PTRACE_EVENT_SECCOMP.
    TraceEvent(u16),
    /// RET_USER_NOTIF with the listener from the filter that won action
    /// precedence. The listener queues its ABI record before the tracee
    /// parks and retries the syscall entry.
    UserNotif(Arc<UserNotifListener>),
}

/// The decision for syscall `nr` of `task`, without acting on it.
pub fn evaluate(task: u64, nr: u32, ip: u64, args: [u64; 6]) -> Verdict {
    let st = get(task);
    match st.mode {
        SECCOMP_MODE_DISABLED => Verdict::Allow,
        SECCOMP_MODE_STRICT => {
            if STRICT_ALLOWED.contains(&nr) {
                Verdict::Allow
            } else {
                Verdict::StrictKill
            }
        }
        SECCOMP_MODE_FILTER => {
            let Some(top) = st.filter else {
                // "Ensure unexpected behavior doesn't result in failing open."
                return Verdict::KillProcess(0);
            };
            let sd = SeccompData {
                nr: nr as i32,
                arch: AUDIT_ARCH_NATIVE,
                instruction_pointer: ip,
                args,
            };
            let (ret, _log, listener) = run_filters(&top, &sd);
            let data = (ret & SECCOMP_RET_DATA) as u16;
            match ret & SECCOMP_RET_ACTION_FULL {
                SECCOMP_RET_ERRNO => Verdict::Return(-(i64::from(u32::from(data).min(MAX_ERRNO)))),
                SECCOMP_RET_TRAP => Verdict::Trap(data),
                SECCOMP_RET_TRACE => {
                    if crate::ptrace::seccomp_event_enabled(task) {
                        Verdict::TraceEvent(data)
                    } else {
                        Verdict::Return(-ENOSYS)
                    }
                }
                // A user-notification action may come from a filter installed
                // without NEW_LISTENER. Linux answers ENOSYS in that case.
                SECCOMP_RET_USER_NOTIF => listener
                    .map(Verdict::UserNotif)
                    .unwrap_or(Verdict::Return(-ENOSYS)),
                SECCOMP_RET_LOG | SECCOMP_RET_ALLOW => Verdict::Allow,
                SECCOMP_RET_KILL_THREAD => {
                    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
                    if crate::handlers::thread_group_live_count(pid) <= 1 {
                        Verdict::KillProcess(data)
                    } else {
                        Verdict::KillThread
                    }
                }
                _ => Verdict::KillProcess(data),
            }
        }
        // Surviving a RET_KILL is meant to be impossible; die again.
        _ => Verdict::StrictKill,
    }
}

/// True when the calling task is under seccomp (one atomic load when no task
/// in the system is).
#[inline]
pub fn active() -> bool {
    ACTIVE_TASKS.load(Ordering::Acquire) != 0 && get(current_task_id()).mode != 0
}

/// `__secure_computing`, run at syscall entry after the ptrace entry stop.
/// Returns the syscall number that must be dispatched. `None` means the
/// filter (or its ptrace stop) consumed the call; its return value or signal
/// frame has then been installed on `ctx`.
#[inline]
pub fn secure_computing(ctx: &mut dyn TrapContext, nr: u32) -> Option<u32> {
    if ACTIVE_TASKS.load(Ordering::Acquire) == 0 {
        return Some(nr);
    }
    secure_computing_slow(ctx, nr)
}

#[inline(never)]
fn secure_computing_slow(ctx: &mut dyn TrapContext, nr: u32) -> Option<u32> {
    let task = current_task_id();
    // `if (IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) && unlikely(current->ptrace &
    // PT_SUSPEND_SECCOMP)) return 0;`
    if crate::ptrace::seccomp_suspended(task) {
        return Some(nr);
    }
    let a = *ctx.args();
    let args = [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5];
    match evaluate(task, nr, ctx.rip(), args) {
        Verdict::Allow => Some(nr),
        Verdict::Return(v) => {
            ctx.set_return(SyscallReturn::ok(v as u64));
            None
        }
        Verdict::Trap(data) => {
            // `syscall_rollback`: the handler sees the original registers,
            // the syscall number in the return register included.
            ctx.set_return(SyscallReturn::ok(u64::from(nr)));
            crate::handlers::force_sigsys_seccomp(ctx, task, nr, AUDIT_ARCH_NATIVE, data, false);
            None
        }
        Verdict::KillProcess(data) => {
            mark_dead(task);
            ctx.set_return(SyscallReturn::ok(u64::from(nr)));
            crate::handlers::force_sigsys_seccomp(ctx, task, nr, AUDIT_ARCH_NATIVE, data, true);
            None
        }
        Verdict::KillThread => {
            mark_dead(task);
            // `do_exit(SIGSYS)`: this thread only, killed-by-signal status.
            crate::handlers::exit_current_thread(ctx, 31);
            None
        }
        Verdict::StrictKill => {
            mark_dead(task);
            // `do_exit(SIGKILL)`.
            crate::handlers::exit_current_thread(ctx, 9);
            None
        }
        Verdict::TraceEvent(data) => {
            match crate::ptrace::ptrace_report_seccomp(ctx, nr, u64::from(data)) {
                // The tracer let it through (or replaced the number with
                // another allowed one): recheck, as `__seccomp_filter(.., true)`.
                Some(new_nr) if new_nr >= 0 => {
                    let new_nr = new_nr as u32;
                    let a = *ctx.args();
                    let args = [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5];
                    match evaluate(task, new_nr, ctx.rip(), args) {
                        Verdict::Allow | Verdict::TraceEvent(_) => Some(new_nr),
                        _ => {
                            // A recheck that is not ALLOW skips without a
                            // second action, like `__seccomp_filter`
                            // returning -1 from the recursive call.
                            None
                        }
                    }
                }
                // Skipped by the tracer (nr set to -1) or a fatal signal.
                _ => None,
            }
        }
        Verdict::UserNotif(listener) => match listener.wait_or_queue(
            task,
            SeccompData {
                nr: nr as i32,
                arch: AUDIT_ARCH_NATIVE,
                instruction_pointer: ctx.rip(),
                args,
            },
        ) {
            UserNotifWait::Response(response)
                if response.flags & SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 =>
            {
                Some(nr)
            }
            UserNotifWait::Response(response) => {
                let value = if response.error == 0 {
                    response.value
                } else {
                    i64::from(response.error)
                };
                ctx.set_return(SyscallReturn::ok(value as u64));
                None
            }
            UserNotifWait::Queued | UserNotifWait::Waiting => {
                // The target is not permitted to dispatch until the monitor
                // answers. Re-execution preserves its original registers;
                // each retry finds the same request or consumes its reply.
                if crate::handlers::has_interrupting_signal(task) {
                    listener.cancel_task(task);
                    ctx.set_return(SyscallReturn::ok((-EINTR) as u64));
                } else if !crate::handlers::park_reexecute_on_io(ctx) {
                    // Kernel-test/early contexts have no user-task executor to
                    // park. Surface the same unavailable-monitor result rather
                    // than busy-spinning in Ring 0.
                    listener.cancel_task(task);
                    ctx.set_return(SyscallReturn::ok((-ENOSYS) as u64));
                }
                None
            }
        },
    }
}

fn mark_dead(task: u64) {
    let mut st = get(task);
    st.mode = SECCOMP_MODE_DEAD;
    set(task, st);
}

// ── seccomp(2) / prctl(PR_SET_SECCOMP) ──

/// `seccomp_set_mode_strict`.
fn set_mode_strict() -> SyscallReturn {
    let task = current_task_id();
    let _m = MUTATION.lock();
    let mut st = get(task);
    if st.mode != SECCOMP_MODE_DISABLED && st.mode != SECCOMP_MODE_STRICT {
        return err(EINVAL);
    }
    st.mode = SECCOMP_MODE_STRICT;
    set(task, st);
    SyscallReturn::ok(0)
}

/// `seccomp_prepare_user_filter` + `seccomp_prepare_filter` +
/// `bpf_prog_create_from_user`, in their errno order.
fn prepare_user_filter(task: u64, uargs: u64) -> Result<Vec<SockFilter>, i64> {
    // struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    let mut fprog = [0u8; 16];
    // SAFETY: copy_from_user range-checks and fault-contains the user source.
    if unsafe { copy_from_user(&mut fprog, uargs) }.is_err() {
        return Err(EFAULT);
    }
    let len = u16::from_ne_bytes([fprog[0], fprog[1]]) as usize;
    let filter = u64::from_ne_bytes(fprog[8..16].try_into().unwrap_or([0; 8]));
    if len == 0 || len > BPF_MAXINSNS {
        return Err(EINVAL);
    }
    // CAP_SYS_ADMIN in the task's user namespace, or no_new_privs.
    const CAP_SYS_ADMIN: u32 = 21;
    if !crate::handlers::task_no_new_privs(task)
        && !crate::handlers::capable_in_own_ns(CAP_SYS_ADMIN)
    {
        return Err(EACCES);
    }
    // bpf_check_basics_ok: a NULL program is EINVAL.
    if filter == 0 {
        return Err(EINVAL);
    }
    let mut raw = alloc::vec![0u8; len * 8];
    // SAFETY: as above.
    if unsafe { copy_from_user(&mut raw, filter) }.is_err() {
        return Err(EFAULT);
    }
    let prog: Vec<SockFilter> = raw.chunks_exact(8).map(SockFilter::from_bytes).collect();
    validate(prog).ok_or(EINVAL)
}

/// `seccomp_set_mode_filter`.
fn set_mode_filter(flags: u32, uargs: u64) -> SyscallReturn {
    let task = current_task_id();
    if flags & !SECCOMP_FILTER_FLAG_MASK != 0 {
        return err(EINVAL);
    }
    if flags & SECCOMP_FILTER_FLAG_TSYNC != 0
        && flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0
        && flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH == 0
    {
        return err(EINVAL);
    }
    if flags & SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0
        && flags & SECCOMP_FILTER_FLAG_NEW_LISTENER == 0
    {
        return err(EINVAL);
    }
    let prog = match prepare_user_filter(task, uargs) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let _m = MUTATION.lock();
    let st = get(task);
    // seccomp_may_assign_mode.
    if st.mode != SECCOMP_MODE_DISABLED && st.mode != SECCOMP_MODE_FILTER {
        return err(EINVAL);
    }
    // seccomp_attach_filter: the path length, 4 instructions of penalty per
    // filter already on the chain.
    let mut total = prog.len();
    let mut w = st.filter.as_ref();
    while let Some(f) = w {
        total += f.prog.len() + 4;
        w = f.prev.as_ref();
    }
    if total > MAX_INSNS_PER_PATH {
        return err(ENOMEM);
    }
    // Linux allows one listener-bearing filter on a chain.  The returned fd
    // can be duplicated or passed over SCM_RIGHTS, but attaching a second
    // listener is EBUSY even if the original fd has since been closed.
    if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 && chain_has_listener(st.filter.as_ref()) {
        return err(EBUSY);
    }
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let siblings: Vec<u64> = if flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
        crate::handlers::thread_group_members(pid)
            .into_iter()
            .filter(|&t| t != task && !crate::handlers::task_is_exiting(t))
            .collect()
    } else {
        Vec::new()
    };
    // seccomp_can_sync_threads: every other live thread is unfiltered or
    // already runs an ancestor of the caller's chain.
    for &t in &siblings {
        let ts = get(t);
        let ok = ts.mode == SECCOMP_MODE_DISABLED
            || (ts.mode == SECCOMP_MODE_FILTER
                && is_ancestor(ts.filter.as_ref(), st.filter.as_ref()));
        if !ok {
            if flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH != 0 {
                return err(ESRCH);
            }
            let tid = crate::handlers::task_to_linux_tid_raw(t).unwrap_or(t);
            return SyscallReturn::ok(crate::handlers::report_pid_to(task, tid));
        }
    }
    let listener =
        (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0).then(|| Arc::new(UserNotifListener::new()));
    let filter = Arc::new(SeccompFilter {
        prog,
        prev: st.filter.clone(),
        log: flags & SECCOMP_FILTER_FLAG_LOG != 0,
        listener: listener.clone(),
    });
    // Reserve the descriptor before publishing the filter: an EMFILE must not
    // leave a task permanently subject to RET_USER_NOTIF with no monitor able
    // to receive the request.  `fd::install` honours RLIMIT_NOFILE.
    let listener_fd = if let Some(listener) = listener.as_ref() {
        let ops: Arc<dyn FileOps> = listener.clone();
        match crate::fd::install(
            task,
            crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            },
        ) {
            Some(fd) => Some(fd),
            None => return err(EMFILE),
        }
    } else {
        None
    };
    set(
        task,
        TaskSeccomp {
            mode: SECCOMP_MODE_FILTER,
            filter: Some(filter.clone()),
        },
    );
    // seccomp_sync_threads.
    let nnp = crate::handlers::task_no_new_privs(task);
    for &t in &siblings {
        if nnp {
            crate::handlers::task_set_no_new_privs(t);
        }
        set(
            t,
            TaskSeccomp {
                mode: SECCOMP_MODE_FILTER,
                filter: Some(filter.clone()),
            },
        );
    }
    SyscallReturn::ok(listener_fd.unwrap_or(0) as u64)
}

/// `seccomp_get_action_avail`.
fn get_action_avail(uargs: u64) -> SyscallReturn {
    let mut b = [0u8; 4];
    // SAFETY: copy_from_user range-checks and fault-contains the source.
    if unsafe { copy_from_user(&mut b, uargs) }.is_err() {
        return err(EFAULT);
    }
    match u32::from_ne_bytes(b) {
        SECCOMP_RET_KILL_PROCESS
        | SECCOMP_RET_KILL_THREAD
        | SECCOMP_RET_TRAP
        | SECCOMP_RET_ERRNO
        | SECCOMP_RET_USER_NOTIF
        | SECCOMP_RET_TRACE
        | SECCOMP_RET_LOG
        | SECCOMP_RET_ALLOW => SyscallReturn::ok(0),
        _ => err(EOPNOTSUPP),
    }
}

/// `seccomp_get_notif_sizes`: `struct seccomp_notif_sizes { __u16
/// seccomp_notif, seccomp_notif_resp, seccomp_data; }`.
fn get_notif_sizes(uargs: u64) -> SyscallReturn {
    let mut b = [0u8; 6];
    // sizeof struct seccomp_notif, seccomp_notif_resp, seccomp_data.
    b[0..2].copy_from_slice(&80u16.to_ne_bytes());
    b[2..4].copy_from_slice(&24u16.to_ne_bytes());
    b[4..6].copy_from_slice(&64u16.to_ne_bytes());

    // SAFETY: copy_to_user range-checks and fault-contains the destination.
    if unsafe { copy_to_user(uargs, &b) }.is_err() {
        return err(EFAULT);
    }
    SyscallReturn::ok(0)
}

/// `do_seccomp` — shared by `seccomp(2)` and `prctl(PR_SET_SECCOMP)`.
pub fn do_seccomp(op: u32, flags: u32, uargs: u64) -> SyscallReturn {
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || uargs != 0 {
                return err(EINVAL);
            }
            set_mode_strict()
        }
        SECCOMP_SET_MODE_FILTER => set_mode_filter(flags, uargs),
        SECCOMP_GET_ACTION_AVAIL => {
            if flags != 0 {
                return err(EINVAL);
            }
            get_action_avail(uargs)
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if flags != 0 {
                return err(EINVAL);
            }
            get_notif_sizes(uargs)
        }
        _ => err(EINVAL),
    }
}

/// `prctl_set_seccomp`.
pub fn prctl_set_seccomp(mode: u64, filter: u64) -> SyscallReturn {
    match mode {
        1 => do_seccomp(SECCOMP_SET_MODE_STRICT, 0, 0),
        2 => do_seccomp(SECCOMP_SET_MODE_FILTER, 0, filter),
        _ => err(EINVAL),
    }
}

// ── Tests ──

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const fn stmt(code: u16, k: u32) -> SockFilter {
        SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    fn sd(nr: i32) -> SeccompData {
        SeccompData {
            nr,
            arch: AUDIT_ARCH_NATIVE,
            instruction_pointer: 0x1234_5678_9abc,
            args: [1, 2, 3, 0xdead_beef_0000_0007, 5, 6],
        }
    }

    /// The validator accepts what Linux accepts and refuses what it refuses.
    fn smoke_seccomp_validator_matches_linux() -> TestResult {
        let ok = |p: &[SockFilter]| validate(p.to_vec()).is_some();
        let ret_allow = stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        if !ok(&[ret_allow]) {
            return TestResult::Fail("RET ALLOW refused");
        }
        if ok(&[]) {
            return TestResult::Fail("empty program accepted");
        }
        if ok(&[stmt(BPF_LD | BPF_W | BPF_ABS, 0)]) {
            return TestResult::Fail("program not ending in RET accepted");
        }
        // Misaligned and out-of-range seccomp_data loads.
        if ok(&[stmt(BPF_LD | BPF_W | BPF_ABS, 2), ret_allow]) {
            return TestResult::Fail("misaligned load accepted");
        }
        if ok(&[stmt(BPF_LD | BPF_W | BPF_ABS, 64), ret_allow]) {
            return TestResult::Fail("load past seccomp_data accepted");
        }
        // Half-word / byte / indirect loads are classic BPF but not seccomp.
        if ok(&[stmt(BPF_LD | BPF_H | BPF_ABS, 0), ret_allow]) {
            return TestResult::Fail("BPF_H load accepted");
        }
        if ok(&[stmt(BPF_LD | BPF_W | BPF_IND, 0), ret_allow]) {
            return TestResult::Fail("BPF_IND load accepted");
        }
        // BPF_MOD passes bpf_check_classic but not seccomp_check_filter.
        if ok(&[stmt(BPF_ALU | BPF_MOD | BPF_K, 3), ret_allow]) {
            return TestResult::Fail("BPF_MOD accepted");
        }
        // Division by a zero constant, an oversized shift, a jump past the end.
        if ok(&[stmt(BPF_ALU | BPF_DIV | BPF_K, 0), ret_allow]) {
            return TestResult::Fail("DIV by constant 0 accepted");
        }
        if ok(&[stmt(BPF_ALU | BPF_LSH | BPF_K, 32), ret_allow]) {
            return TestResult::Fail("LSH by 32 accepted");
        }
        if ok(&[jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0), ret_allow]) {
            return TestResult::Fail("jump past the end accepted");
        }
        if ok(&[stmt(BPF_JMP | BPF_JA, 1), ret_allow]) {
            return TestResult::Fail("JA past the end accepted");
        }
        // Reading a scratch cell nobody wrote.
        if ok(&[stmt(BPF_LD | BPF_MEM, 0), ret_allow]) {
            return TestResult::Fail("read of an unwritten scratch cell accepted");
        }
        if !ok(&[stmt(BPF_ST, 0), stmt(BPF_LD | BPF_MEM, 0), ret_allow]) {
            return TestResult::Fail("store-then-load refused");
        }
        if ok(&[stmt(BPF_ST, 16), ret_allow]) {
            return TestResult::Fail("scratch cell 16 accepted");
        }
        // LEN becomes an immediate 64.
        match validate(alloc::vec![
            stmt(BPF_LD | BPF_W | BPF_LEN, 0),
            stmt(BPF_RET | BPF_A, 0)
        ]) {
            Some(p) if run(&p, &sd(0)) == 64 => {}
            _ => return TestResult::Fail("BPF_LEN did not load sizeof(seccomp_data)"),
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace/seccomp", smoke_seccomp_validator_matches_linux);

    /// The interpreter reads seccomp_data the way Linux lays it out, and
    /// runtime division by zero ends the program with 0 (KILL_THREAD).
    fn smoke_seccomp_interpreter_semantics() -> TestResult {
        // nr == 39 ? ERRNO(7) : ALLOW
        let p = validate(alloc::vec![
            stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            jump(BPF_JMP | BPF_JEQ | BPF_K, 39, 0, 1),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 7),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        ])
        .unwrap_or_default();
        if run(&p, &sd(39)) != SECCOMP_RET_ERRNO | 7 || run(&p, &sd(40)) != SECCOMP_RET_ALLOW {
            return TestResult::Fail("nr match");
        }
        // args[3] high word, instruction pointer halves, arch.
        let load = |off: u32| {
            let p = validate(alloc::vec![
                stmt(BPF_LD | BPF_W | BPF_ABS, off),
                stmt(BPF_RET | BPF_A, 0)
            ])
            .unwrap_or_default();
            run(&p, &sd(1))
        };
        if load(4) != AUDIT_ARCH_NATIVE
            || load(8) != 0x5678_9abc
            || load(12) != 0x1234
            || load(16 + 3 * 8) != 7
            || load(16 + 3 * 8 + 4) != 0xdead_beef
        {
            return TestResult::Fail("seccomp_data field offsets");
        }
        // A / X with 0.
        let p = validate(alloc::vec![
            stmt(BPF_LD | BPF_IMM, 10),
            stmt(BPF_LDX | BPF_IMM, 0),
            stmt(BPF_ALU | BPF_DIV | BPF_X, 0),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        ])
        .unwrap_or_default();
        if run(&p, &sd(0)) != 0 {
            return TestResult::Fail("runtime divide by zero did not return 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace/seccomp", smoke_seccomp_interpreter_semantics);

    /// Across a chain the lowest action wins, KILL_PROCESS below everything.
    fn smoke_seccomp_chain_precedence() -> TestResult {
        let f = |ret: u32, prev: Option<Arc<SeccompFilter>>| {
            Arc::new(SeccompFilter {
                prog: alloc::vec![stmt(BPF_RET | BPF_K, ret)],
                prev,
                log: false,
                listener: None,
            })
        };
        let a = f(SECCOMP_RET_ALLOW, None);
        let b = f(SECCOMP_RET_ERRNO | 1, Some(a.clone()));
        let c = f(SECCOMP_RET_TRAP | 2, Some(b.clone()));
        if run_filters(&c, &sd(0)).0 != SECCOMP_RET_TRAP | 2 {
            return TestResult::Fail("TRAP did not outrank ERRNO");
        }
        let d = f(SECCOMP_RET_KILL_PROCESS, Some(c.clone()));
        if run_filters(&d, &sd(0)).0 != SECCOMP_RET_KILL_PROCESS {
            return TestResult::Fail("KILL_PROCESS did not outrank everything");
        }
        if !is_ancestor(Some(&a), Some(&d)) || is_ancestor(Some(&d), Some(&a)) {
            return TestResult::Fail("is_ancestor");
        }
        if d.chain_len() != 4 {
            return TestResult::Fail("chain length");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace/seccomp", smoke_seccomp_chain_precedence);

    /// Listener IDs remain valid until SEND, RECV describes the exact
    /// seccomp_data payload, and CONTINUE is distinguishable from an emulated
    /// result before syscall dispatch re-enters the filter chain.
    fn smoke_seccomp_user_notification_queue() -> TestResult {
        let listener = UserNotifListener::new();
        let request = sd(110);
        if !matches!(listener.wait_or_queue(41, request), UserNotifWait::Queued) {
            return TestResult::Fail("first notification was not queued");
        }
        let (id, wire) = match listener.receive() {
            Ok(notification) => notification,
            Err(_) => return TestResult::Fail("listener did not receive queued notification"),
        };
        if id == 0
            || u64::from_ne_bytes(wire[0..8].try_into().unwrap_or([0; 8])) != id
            || i32::from_ne_bytes(wire[16..20].try_into().unwrap_or([0; 4])) != request.nr
            || u64::from_ne_bytes(wire[24..32].try_into().unwrap_or([0; 8]))
                != request.instruction_pointer
            || u64::from_ne_bytes(wire[56..64].try_into().unwrap_or([0; 8])) != request.args[3]
        {
            return TestResult::Fail("seccomp_notif wire layout");
        }
        if listener
            .send(
                UserNotifResponse {
                    value: 1234,
                    error: 0,
                    flags: 0,
                },
                id,
            )
            .is_err()
        {
            return TestResult::Fail("listener rejected response");
        }
        if listener
            .send(
                UserNotifResponse {
                    value: 0,
                    error: 0,
                    flags: 0,
                },
                id,
            )
            .is_ok()
        {
            return TestResult::Fail("listener accepted duplicate response");
        }
        match listener.wait_or_queue(41, request) {
            UserNotifWait::Response(response)
                if response.value == 1234 && response.error == 0 && response.flags == 0 => {}
            _ => return TestResult::Fail("listener did not deliver response once"),
        }
        if !matches!(listener.wait_or_queue(42, request), UserNotifWait::Queued) {
            return TestResult::Fail("continue notification was not queued");
        }
        let (id, _) = match listener.receive() {
            Ok(notification) => notification,
            Err(_) => return TestResult::Fail("continue notification was not received"),
        };
        if listener
            .send(
                UserNotifResponse {
                    value: 0,
                    error: 0,
                    flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                },
                id,
            )
            .is_err()
        {
            return TestResult::Fail("listener rejected CONTINUE");
        }
        match listener.wait_or_queue(42, request) {
            UserNotifWait::Response(response)
                if response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE => {}
            _ => return TestResult::Fail("listener did not retain CONTINUE"),
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace/seccomp", smoke_seccomp_user_notification_queue);
}
