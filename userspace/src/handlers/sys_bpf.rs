//! `bpf(2)` — load and run BPF programs.
//!
//! `bpf(int cmd, union bpf_attr *attr, unsigned int size)`.
//!
//! NARF is **instruction-set compatible with Linux and ABI-divergent**
//! (`bpf/specification/spec.md` §1). `union bpf_attr` is Linux's layout
//! verbatim, so a `libbpf`-shaped loader works unchanged for the commands that
//! map cleanly. Everything else returns `ENOTSUP` with a `// LINUX-GAP` note at
//! its arm, rather than a plausible-looking lie.
//!
//! Phase 1 implements two commands:
//!
//! * `BPF_PROG_LOAD` (5) — verify and load, returning a program fd.
//! * `BPF_PROG_TEST_RUN` (10) — run once with a caller-supplied context and
//!   report the return value in `attr.test.retval`.
//!
//! Both require privilege (§4.10: there is no unprivileged mode and no second
//! set of limits). The check is `task_may_load_bpf`, on per-task credentials;
//! the `Cap<BpfProgLoad, Grant>` threaded into `BpfProg::load` is a type-level
//! statement that loading is privileged, not the check itself — it is minted
//! by this handler, so it cannot authorise the handler.

#[allow(unused_imports)]
use super::*;

use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadRequest, ProgFile};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, Grant};

// Errno values this handler returns. `handlers/mod.rs` names only the few it
// needs; the rest are spelled out here rather than widening that set.
const EPERM: i64 = 1;
const EBADF_: i64 = 9;
const EAGAIN: i64 = 11;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
/// Linux's `ENOTSUPP` is an internal 524; the userspace-visible spelling is
/// `EOPNOTSUPP`, which on Linux equals `ENOTSUP` (95).
const ENOTSUP: i64 = 95;

// ── `enum bpf_cmd`, from include/uapi/linux/bpf.h ───────────────────

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_TEST_RUN: u32 = 10;

/// `union bpf_attr` is 120+ bytes and grows with every kernel release. Linux
/// accepts any size and zero-extends, so that an older binary works on a newer
/// kernel and vice versa (`kernel/bpf/syscall.c::bpf_check_uarg_tail_zero`).
/// Mirror that: copy what the caller supplied into a zeroed buffer of our own.
const ATTR_BUF: usize = 256;

// `struct { … } prog_load` field offsets within `union bpf_attr`.
const PL_PROG_TYPE: usize = 0;
const PL_INSN_CNT: usize = 4;
const PL_INSNS: usize = 8;
const PL_PROG_NAME: usize = 48;
const PROG_NAME_LEN: usize = 16;

// `struct { … } test` field offsets.
const T_PROG_FD: usize = 0;
const T_RETVAL: usize = 4;
const T_CTX_SIZE_IN: usize = 40;
const T_CTX_IN: usize = 48;

/// `enum bpf_prog_type`. NARF maps the two Linux tracing types onto its own
/// two execution contexts and rejects the rest, because a context is declared
/// by the *hook* here — spec §4.5. `BPF_PROG_TYPE_TRACING` (26) is the
/// fentry/fexit family, which NARF's dynamic probes are; the sleepable
/// counterpart is `BPF_PROG_TYPE_SYSCALL` (31), whose whole point in Linux is
/// that it runs in process context and may sleep.
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_SYSCALL: u32 = 31;

/// The `Cap<BpfProgLoad, Grant>` this handler presents.
///
/// Minted once, and — importantly — **this is not the authorisation check**.
/// A capability the syscall mints for itself proves nothing; `check_live()` on
/// it only proves nothing has revoked it since. The real gate is
/// [`task_may_load_bpf`], which reads per-task credentials.
///
/// This exists because `BpfProg::load` takes a `Cap<BpfProgLoad, Grant>` as
/// the type-level statement that loading is privileged. It becomes a genuine
/// per-task grant once NARF has a per-task capability table (`sys_bootstrap`
/// still hands out ad-hoc integer ids). Until then the cap is plumbing and the
/// credential check is the security boundary — do not reverse those roles.
fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfProgLoad,
            Grant,
        >::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64_at(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Whether the calling task may use `bpf(2)` at all.
///
/// Deliberately checks per-task credential state rather than a capability the
/// syscall mints for itself. See the call site for why.
fn task_may_load_bpf() -> bool {
    super::read_uidgid(super::current_task_id()).euid == 0
}

pub(crate) fn sys_bpf(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let cmd = args.arg0 as u32;
    let attr_uptr = args.arg1;
    let size = args.arg2 as usize;

    // Privilege gate, before anything reads the attribute block.
    //
    // `load_cap()` below *mints* the capability it hands to `BpfProg::load`,
    // so `cap.check_live()` there proves only that nothing has revoked a
    // capability this syscall created for itself — it is not an authorisation
    // check and never was. Without this, any unprivileged process could load
    // and run BPF, which makes the verifier the sole barrier and turns every
    // verifier bug into an unprivileged primitive.
    //
    // euid 0 is a placeholder for the per-task capability table NARF does not
    // have yet (`sys_bootstrap` still hands out ad-hoc integer ids). It is
    // coarse, but it is a real check against real per-task state, which
    // `Cap::bootstrap()` is not. Spec §4.10 — there is no unprivileged mode.
    if !task_may_load_bpf() {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    let ret = match cmd {
        BPF_PROG_LOAD => prog_load(attr_uptr, size),
        BPF_PROG_TEST_RUN => prog_test_run(attr_uptr, size),

        // LINUX-GAP: maps are Phase 3 (`bpf/specification/spec.md` §3.4 —
        // five native kinds behind an ~8-method trait, against Linux's 45-slot
        // `bpf_map_ops` union).
        BPF_MAP_CREATE | BPF_MAP_LOOKUP_ELEM | BPF_MAP_UPDATE_ELEM | BPF_MAP_DELETE_ELEM
        | BPF_MAP_GET_NEXT_KEY => -ENOTSUP,

        // LINUX-GAP: everything else — `BPF_OBJ_PIN`/`BPF_OBJ_GET` (bpffs
        // pinning), `BPF_PROG_ATTACH`/`DETACH` and `LINK_CREATE` (attach is
        // Phase 6), `BPF_BTF_LOAD` and the `*_GET_FD_BY_ID` family, and the
        // token/iterator commands. `ENOTSUP` rather than `EINVAL` so a probing
        // loader can tell "this kernel does not do that" from "you passed
        // nonsense".
        _ => -ENOTSUP,
    };
    ctx.set_return(SyscallReturn::ok(ret as u64));
}

fn read_attr(attr_uptr: u64, size: usize) -> Result<[u8; ATTR_BUF], i64> {
    if attr_uptr == 0 || size == 0 || size > ATTR_BUF {
        return Err(-EINVAL);
    }
    let mut buf = [0u8; ATTR_BUF];
    // SAFETY: caller-supplied pointer, range-validated inside
    // `copy_from_user`, which also opens and closes the SMAP window and
    // converts a fault into `Err(EFAULT)` rather than a kernel panic.
    unsafe { copy_from_user(&mut buf[..size], attr_uptr) }.map_err(|e| -(e as i64))?;
    Ok(buf)
}

fn prog_load(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < PL_INSNS + 8 {
        return -EINVAL;
    }

    let prog_type = u32_at(&attr, PL_PROG_TYPE);
    let insn_cnt = u32_at(&attr, PL_INSN_CNT) as usize;
    let insns_uptr = u64_at(&attr, PL_INSNS);

    // Sleepability is a property of the hook, not a program flag. Linux uses
    // `BPF_F_SLEEPABLE` in `prog_flags` and then checks it against an
    // allowlist of attach types; here the program type selects the context it
    // is verified *for*, and attaching to a hook that provides the other one
    // is rejected by type at attach (spec §4.5).
    let context = match prog_type {
        BPF_PROG_TYPE_TRACING => Context::Atomic,
        BPF_PROG_TYPE_SYSCALL => Context::Sleepable,
        // LINUX-GAP: socket filters, XDP, cgroup hooks, LSM, struct_ops, and
        // the rest arrive with their attach surfaces in Phase 5/6.
        _ => return -ENOTSUP,
    };

    if insn_cnt == 0 || insn_cnt > narf_bpf::prog::MAX_INSNS {
        return -EINVAL;
    }
    let byte_len = insn_cnt * core::mem::size_of::<narf_bpf_isa::Insn>();
    // SAFETY: `copy_from_user_vec` validates the range and the length bound
    // before it allocates, so a bogus `insn_cnt` never reaches the allocator.
    let bytes = match unsafe { copy_from_user_vec(insns_uptr, byte_len) } {
        Ok(b) => b,
        Err(e) => return -(e as i64),
    };
    let Some(slots) = narf_bpf_isa::slots_from_bytes(&bytes) else {
        return -EINVAL;
    };
    let insns: alloc::vec::Vec<narf_bpf_isa::Insn> = slots.collect();

    // `prog_name` is a fixed 16-byte NUL-padded field inside `bpf_attr`, not a
    // pointer — so it is already in the buffer we copied.
    let name = if size >= PL_PROG_NAME + PROG_NAME_LEN {
        let raw = &attr[PL_PROG_NAME..PL_PROG_NAME + PROG_NAME_LEN];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(PROG_NAME_LEN);
        alloc::string::String::from_utf8_lossy(&raw[..end]).into_owned()
    } else {
        alloc::string::String::new()
    };

    let prog = match BpfProg::load(
        load_cap(),
        LoadRequest {
            name,
            insns,
            context,
        },
    ) {
        Ok(p) => p,
        // Linux returns -EINVAL for a rejected program and puts the reason in
        // `log_buf`. NARF's `VerifyError` carries an instruction index for
        // every variant that has one; surfacing it through `log_buf` is the
        // Phase 2 job, when there is a verifier producing them.
        Err(narf_bpf::LoadError::AuthorityRevoked) => return -EPERM,
        Err(_) => return -EINVAL,
    };

    let ops: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(ProgFile::new(prog));
    let task = current_task_id();
    match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            // Linux always sets close-on-exec on a bpf fd
            // (`kernel/bpf/syscall.c::bpf_prog_new_fd` passes `O_CLOEXEC`),
            // because a leaked program fd is a leaked capability.
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}

fn prog_test_run(attr_uptr: u64, size: usize) -> i64 {
    let mut attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < T_RETVAL + 4 {
        return -EINVAL;
    }
    let prog_fd = u32_at(&attr, T_PROG_FD);

    let task = current_task_id();
    let ops = match fd::with_table(task, |t| t.get(prog_fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return -EBADF_,
    };
    let Some(file) = ops.as_any().and_then(|a| a.downcast_ref::<ProgFile>()) else {
        return -EINVAL;
    };
    let prog = file.prog();

    // The context tuple. Linux's `ctx_in` is a program-type-specific struct;
    // for NARF's probe context it is the `[u64; 4]` the probe ABI already
    // uses, so there is nothing to translate.
    let mut ctx = [0u64; narf_bpf::interp::MAX_CTX_WORDS];
    let mut ctx_len = 0usize;
    if size >= T_CTX_IN + 8 {
        let ctx_size = u32_at(&attr, T_CTX_SIZE_IN) as usize;
        let ctx_uptr = u64_at(&attr, T_CTX_IN);
        if ctx_uptr != 0 && ctx_size != 0 {
            if ctx_size > ctx.len() * 8 || ctx_size % 8 != 0 {
                return -EINVAL;
            }
            let mut raw = [0u8; narf_bpf::interp::MAX_CTX_WORDS * 8];
            // SAFETY: range-validated inside `copy_from_user`.
            if let Err(e) = unsafe { copy_from_user(&mut raw[..ctx_size], ctx_uptr) } {
                return -(e as i64);
            }
            ctx_len = ctx_size / 8;
            for (i, w) in ctx.iter_mut().take(ctx_len).enumerate() {
                let mut b = [0u8; 8];
                b.copy_from_slice(&raw[i * 8..i * 8 + 8]);
                *w = u64::from_le_bytes(b);
            }
        }
    }

    let outcome = match prog.context() {
        Context::Atomic => prog.run_atomic(ctx, ctx_len),
        // A sleepable program's only await point is `narf_yield()`, which
        // wakes itself, so driving it to completion here terminates. A kfunc
        // that parks on real I/O would need an executor task instead — the
        // Phase-2 question recorded in `bpf/specification/spec.md` §8.
        Context::Sleepable => narf_bpf::interp::drive(prog.run_sleepable(ctx, ctx_len)),
    };
    let Some(outcome) = outcome else {
        // The per-CPU stack provider declined: a nested invocation, per §1.5's
        // depth counter. `EAGAIN` rather than an error, because retrying is
        // exactly the right response.
        return -EAGAIN;
    };

    // Linux reports the program's return value in `attr.test.retval` and the
    // syscall itself succeeds; a trapped program is still a successful *run*
    // whose result happens to be zero.
    let retval = (outcome.value() & 0xFFFF_FFFF) as u32;
    attr[T_RETVAL..T_RETVAL + 4].copy_from_slice(&retval.to_le_bytes());
    // SAFETY: `copy_to_user` range-validates and brackets SMAP; writing back
    // only the four bytes the caller asked about avoids clobbering fields a
    // newer userspace put beyond what this kernel understands.
    if let Err(e) = unsafe { copy_to_user(attr_uptr + T_RETVAL as u64, &retval.to_le_bytes()) } {
        return -(e as i64);
    }
    0
}
