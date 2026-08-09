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
//! Implemented here:
//!
//! * `BPF_PROG_LOAD` (5) — verify and load, returning a program fd.
//!   The Linux license string is copied, classified, and retained for program
//!   introspection. Atomic fentry and raw-tracepoint types retain their distinct
//!   Linux identities even though they share one verifier context.
//! * `BPF_PROG_TEST_RUN` (10) — run a generic program with a caller-supplied
//!   context, or an XDP program over copied `data_in`, and report its result.
//! * `BPF_MAP_CREATE` (0), the five keyed element commands, batch commands,
//!   and `BPF_MAP_FREEZE` (22), over the keyed map kinds in `narf_bpf::map`.
//! * `BPF_PROG_BIND_MAP` (35) — add a map lifetime reference to an already
//!   loaded program without making the map addressable by its instructions.
//! * `BPF_ENABLE_STATS` (32) — fd-lifetime-gated program `run_cnt` and
//!   `run_time_ns` accounting.
//!
//! The element commands take the **syscall** view of a per-CPU map: the value
//! buffer spans every CPU at an 8-byte stride, exactly as Linux's
//! `bpf_percpu_array_copy` lays it out. A program sees one CPU's slot instead;
//! `narf_bpf::map::BpfMapOps` keeps the two views as separate methods so that
//! neither caller can accidentally take the other's.
//!
//! Both require privilege (§4.10: there is no unprivileged mode and no second
//! set of limits). The check is `task_may_load_bpf`, on per-task credentials;
//! the `Cap<BpfProgLoad, Grant>` threaded into `BpfProg::load` is a type-level
//! statement that loading is privileged, not the check itself — it is minted
//! by this handler, so it cannot authorise the handler.

#[allow(unused_imports)]
use super::*;

use narf_bpf::map::{
    BpfMap, BpfMapCap, MapAccess, MapAttr, MapError, MapFile, MapKind,
};
use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadMetadata, LoadRequest, ProgFile};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, Grant};

// Errno values this handler returns. `handlers/mod.rs` names only the few it
// needs; the rest are spelled out here rather than widening that set.
const EPERM: i64 = 1;
const E2BIG: i64 = 7;
const EBADF_: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const EFAULT: i64 = 14;
const ENOENT: i64 = 2;
const EBUSY: i64 = 16;
const EPROTO: i64 = 71;
const ENOSPC: i64 = 28;
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
const BPF_OBJ_PIN: u32 = 6;
const BPF_OBJ_GET: u32 = 7;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_PROG_TEST_RUN: u32 = 10;
const BPF_BTF_LOAD: u32 = 18;
const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_MAP_GET_NEXT_ID: u32 = 12;
const BPF_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_BTF_GET_FD_BY_ID: u32 = 19;
const BPF_MAP_FREEZE: u32 = 22;
const BPF_BTF_GET_NEXT_ID: u32 = 23;
const BPF_PROG_QUERY: u32 = 16;
const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;
const BPF_TASK_FD_QUERY: u32 = 20;
const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
const BPF_ITER_CREATE: u32 = 33;
const BPF_LINK_CREATE: u32 = 28;
const BPF_LINK_UPDATE: u32 = 29;
// Linux numbers these 30/31 (an earlier draft had 32/33, which are actually
// `BPF_ENABLE_STATS` and `BPF_ITER_CREATE`). Corrected so a libbpf loader's
// `BPF_LINK_GET_*_BY_ID` reaches this handler and its iterator commands do not.
const BPF_LINK_GET_FD_BY_ID: u32 = 30;
const BPF_LINK_GET_NEXT_ID: u32 = 31;
const BPF_ENABLE_STATS: u32 = 32;
const BPF_LINK_DETACH: u32 = 34;
const BPF_PROG_BIND_MAP: u32 = 35;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;
const BPF_MAP_LOOKUP_AND_DELETE_BATCH: u32 = 25;
const BPF_MAP_UPDATE_BATCH: u32 = 26;
const BPF_MAP_DELETE_BATCH: u32 = 27;

/// `union bpf_attr` is 120+ bytes and grows with every kernel release. Linux
/// accepts any size and zero-extends, so that an older binary works on a newer
/// kernel and vice versa (`kernel/bpf/syscall.c::bpf_check_uarg_tail_zero`).
/// Mirror that: copy what the caller supplied into a zeroed buffer of our own.
const ATTR_BUF: usize = 256;

// `struct { … } prog_load` field offsets within `union bpf_attr`.
const PL_PROG_TYPE: usize = 0;
const PL_INSN_CNT: usize = 4;
const PL_INSNS: usize = 8;
const PL_LICENSE: usize = 16;
const PL_LOG_LEVEL: usize = 24;
const PL_LOG_SIZE: usize = 28;
const PL_LOG_BUF: usize = 32;
const PL_PROG_NAME: usize = 48;
const PL_FD_ARRAY: usize = 120;
const PL_LOG_TRUE_SIZE: usize = 140;
const PL_FD_ARRAY_CNT: usize = 148;
const PROG_NAME_LEN: usize = 16;

/// `BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2 | BPF_LOG_STATS | BPF_LOG_FIXED`.
const BPF_LOG_MASK: u32 = 15;

// `struct { … } test` field offsets.
const T_PROG_FD: usize = 0;
const T_RETVAL: usize = 4;
const T_DATA_SIZE_IN: usize = 8;
const T_DATA_SIZE_OUT: usize = 12;
const T_DATA_IN: usize = 16;
const T_DATA_OUT: usize = 24;
const T_REPEAT: usize = 32;
const T_DURATION: usize = 36;
const T_CTX_SIZE_IN: usize = 40;
const T_CTX_SIZE_OUT: usize = 44;
const T_CTX_IN: usize = 48;
const T_CTX_OUT: usize = 56;
const T_FLAGS: usize = 64;
const T_CPU: usize = 68;
const T_BATCH_SIZE: usize = 72;

/// One synchronous syscall must not monopolise the kernel indefinitely.
const MAX_XDP_TEST_REPEAT: u32 = 1024;
/// XDP test frames are ordinary link-layer packets, not an allocation API.
const MAX_XDP_TEST_DATA: usize = 64 * 1024;
const ETH_HLEN: usize = 14;

/// `enum bpf_prog_type` values NARF accepts. Program type remains object
/// identity even when two types share an execution context: raw tracepoints
/// and fentry are both atomic, but Linux does not permit attaching one through
/// the other's API.
const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_SYSCALL: u32 = 31;
const BPF_PROG_TYPE_XDP: u32 = 6;

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
    super::task_may_use_bpf()
}

/// Copy and classify `BPF_PROG_LOAD.license` exactly as Linux does.
///
/// Linux reads at most 127 bytes into a 128-byte buffer, forcibly terminates
/// the last byte, and compares the resulting byte string against six accepted
/// spellings. A missing terminator is therefore accepted but cannot classify
/// as GPL-compatible unless the truncated bytes exactly match one of those
/// short spellings (which they cannot).
fn read_prog_license(uptr: u64) -> Result<bool, i64> {
    const MAX_COPY: usize = 127;
    const GPL: [&[u8]; 6] = [
        b"GPL",
        b"GPL v2",
        b"GPL and additional rights",
        b"Dual BSD/GPL",
        b"Dual MIT/GPL",
        b"Dual MPL/GPL",
    ];

    if uptr == 0 {
        return Err(-EFAULT);
    }
    let mut license = [0u8; MAX_COPY];
    let mut len = MAX_COPY;
    for (i, byte) in license.iter_mut().enumerate() {
        let src = uptr.checked_add(i as u64).ok_or(-EFAULT)?;
        // SAFETY: one caller-provided byte, range-validated and SMAP-bracketed
        // by `copy_from_user`; a fault is returned as `EFAULT`.
        unsafe { copy_from_user(core::slice::from_mut(byte), src) }.map_err(|_| -EFAULT)?;
        if *byte == 0 {
            len = i;
            break;
        }
    }
    Ok(GPL.iter().any(|accepted| *accepted == &license[..len]))
}

/// One bounded verifier diagnostic destined for `BPF_PROG_LOAD.log_buf`.
struct ProgLog {
    ubuf: u64,
    size: u32,
    attr_uptr: u64,
    attr_size: usize,
    wanted: bool,
}

impl ProgLog {
    /// Validate Linux's three coupled verifier-log fields.
    fn new(attr_uptr: u64, attr_size: usize, attr: &[u8; ATTR_BUF]) -> Result<Self, i64> {
        let level = u32_at(attr, PL_LOG_LEVEL);
        let size = u32_at(attr, PL_LOG_SIZE);
        let ubuf = u64_at(attr, PL_LOG_BUF);
        if (ubuf != 0) != (size != 0)
            || (ubuf != 0 && level == 0)
            || level & !BPF_LOG_MASK != 0
            || size > u32::MAX >> 2
        {
            return Err(-EINVAL);
        }
        Ok(Self {
            ubuf,
            size,
            attr_uptr,
            attr_size,
            wanted: ubuf != 0 && level != 0,
        })
    }

    /// Copy a NUL-terminated diagnostic and publish its untruncated size.
    ///
    /// As in Linux, a bad log pointer returns `EFAULT`, and a buffer too small
    /// for the full message returns `ENOSPC`; either error supersedes the
    /// verifier's verdict because the requested diagnostic was not delivered.
    fn emit(&self, msg: &str) -> Result<(), i64> {
        let true_size = if self.wanted {
            msg.len().saturating_add(1)
        } else {
            0
        };
        let mut copy_error = None;
        if self.wanted {
            let cap = self.size as usize;
            let keep = core::cmp::min(msg.len(), cap - 1);
            let mut out = alloc::vec::Vec::with_capacity(keep + 1);
            out.extend_from_slice(&msg.as_bytes()[..keep]);
            out.push(0);
            // SAFETY: the caller supplied this buffer; `copy_to_user`
            // range-validates it and SMAP-brackets the bounded copy.
            if unsafe { copy_to_user(self.ubuf, &out) }.is_err() {
                copy_error = Some(-EFAULT);
            }
        }

        if self.attr_size >= PL_LOG_TRUE_SIZE + 4 {
            let dst = self
                .attr_uptr
                .checked_add(PL_LOG_TRUE_SIZE as u64)
                .ok_or(-EFAULT)?;
            let value = u32::try_from(true_size).unwrap_or(u32::MAX);
            // SAFETY: four-byte output inside the caller's supplied attr.
            unsafe { copy_to_user(dst, &value.to_le_bytes()) }.map_err(|_| -EFAULT)?;
        }
        if let Some(e) = copy_error {
            return Err(e);
        }
        if self.wanted && true_size > self.size as usize {
            return Err(-ENOSPC);
        }
        Ok(())
    }
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

        BPF_MAP_CREATE => map_create(attr_uptr, size),
        BPF_MAP_LOOKUP_ELEM => map_lookup_elem(attr_uptr, size),
        BPF_MAP_UPDATE_ELEM => map_update_elem(attr_uptr, size),
        BPF_MAP_DELETE_ELEM => map_delete_elem(attr_uptr, size),
        BPF_MAP_GET_NEXT_KEY => map_get_next_key(attr_uptr, size),
        BPF_MAP_LOOKUP_AND_DELETE_ELEM => map_lookup_and_delete_elem(attr_uptr, size),

        // Batch element commands — `sys_bpf.rs`, built on the same element ops.
        BPF_MAP_LOOKUP_BATCH => map_batch_read(attr_uptr, size, false),
        BPF_MAP_LOOKUP_AND_DELETE_BATCH => map_batch_read(attr_uptr, size, true),
        BPF_MAP_UPDATE_BATCH => map_batch_write(attr_uptr, size, false),
        BPF_MAP_DELETE_BATCH => map_batch_write(attr_uptr, size, true),

        // BTF — `sys_bpf_btf.rs`.
        BPF_BTF_LOAD => btf_load(attr_uptr, size),

        // Introspection — `sys_bpf_info.rs`.
        BPF_OBJ_GET_INFO_BY_FD => super::bpf_obj_get_info_by_fd(attr_uptr, size),
        BPF_PROG_GET_NEXT_ID => super::bpf_prog_get_next_id(attr_uptr, size),
        BPF_MAP_GET_NEXT_ID => super::bpf_map_get_next_id(attr_uptr, size),
        BPF_PROG_GET_FD_BY_ID => super::bpf_prog_get_fd_by_id(attr_uptr, size),
        BPF_MAP_GET_FD_BY_ID => super::bpf_map_get_fd_by_id(attr_uptr, size),
        BPF_LINK_GET_NEXT_ID => super::bpf_link_get_next_id(attr_uptr, size),
        BPF_LINK_GET_FD_BY_ID => super::bpf_link_get_fd_by_id(attr_uptr, size),
        BPF_BTF_GET_NEXT_ID => super::bpf_btf_get_next_id(attr_uptr, size),
        BPF_BTF_GET_FD_BY_ID => super::bpf_btf_get_fd_by_id(attr_uptr, size),

        // Make the userspace view permanently read-only while preserving
        // program-side updates — `BPF_MAP_FREEZE` (22).
        BPF_MAP_FREEZE => map_freeze(attr_uptr, size),

        // bpffs pinning — `sys_bpf_pin.rs`.
        BPF_OBJ_PIN => super::bpf_obj_pin(attr_uptr, size),
        BPF_OBJ_GET => super::bpf_obj_get(attr_uptr, size),

        // Attach — `sys_bpf_attach.rs`.
        BPF_PROG_ATTACH => bpf_prog_attach(attr_uptr, size),
        BPF_PROG_DETACH => bpf_prog_detach(attr_uptr, size),
        BPF_RAW_TRACEPOINT_OPEN => bpf_raw_tracepoint_open(attr_uptr, size),
        BPF_LINK_CREATE => bpf_link_create(attr_uptr, size),
        BPF_LINK_UPDATE => bpf_link_update(attr_uptr, size),
        BPF_LINK_DETACH => bpf_link_detach(attr_uptr, size),
        BPF_PROG_QUERY => bpf_prog_query(attr_uptr, size),
        BPF_TASK_FD_QUERY => task_fd_query(attr_uptr, size),
        BPF_ITER_CREATE => bpf_iter_create(attr_uptr, size),
        BPF_ENABLE_STATS => enable_stats(attr_uptr, size),

        // Post-load object lifetime binding; this does not extend the
        // verifier-visible map set.
        BPF_PROG_BIND_MAP => prog_bind_map(attr_uptr, size),

        // LINUX-GAP: everything else — the BPF token commands (`BPF_TOKEN_CREATE`
        // — NARF has no token, and the privilege gate above is a credential check
        // rather than a delegable one), and related newer commands. `ENOTSUP`
        // rather than `EINVAL` lets a
        // probing loader tell "this kernel does not do that" from "you passed
        // nonsense". The implemented `BPF_MAP_FREEZE` handler separately
        // returns `EOPNOTSUPP` for ring buffers.
        //
        // The batch element commands are NOT in that list any more:
        // `BPF_MAP_{LOOKUP,LOOKUP_AND_DELETE,UPDATE,DELETE}_BATCH` are
        // implemented above, built on the same element ops as the single-key
        // commands.
        //
        // Pinning is NOT in that list any more: `BPF_OBJ_PIN`/`BPF_OBJ_GET` are
        // implemented above via `filesystem::bpffs`. Both sides of this merge
        // had rewritten this comment against a tree where the other's work did
        // not exist, so taking either verbatim would have re-asserted a gap that
        // had just been closed — the exact failure this comment has already
        // been rewritten twice to avoid.
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

// `struct { … } task_fd_query` field offsets.
const TFQ_PID: usize = 0;
const TFQ_FD: usize = 4;
const TFQ_FLAGS: usize = 8;
const TFQ_BUF_LEN: usize = 12;
const TFQ_BUF: usize = 16;
const TFQ_PROG_ID: usize = 24;
const TFQ_FD_TYPE: usize = 28;
const TFQ_PROBE_OFFSET: usize = 32;
const TFQ_PROBE_ADDR: usize = 40;

/// Resolve the program `(id, fd_type)` behind a task fd. Backed by the
/// perf-event layer, a `linux-compat` feature; without it there is no fd kind
/// that carries a program, so this is `None` and the query returns `ENOTSUP`.
#[cfg(feature = "linux-compat")]
fn task_fd_prog_id(fd: u32) -> Option<(u32, u32)> {
    crate::perf_event::bpf_task_fd_query(fd)
}
#[cfg(not(feature = "linux-compat"))]
fn task_fd_prog_id(_fd: u32) -> Option<(u32, u32)> {
    None
}

/// `BPF_TASK_FD_QUERY` — given a task's fd that carries a BPF program, report
/// which program and what kind of fd it is.
///
/// NARF answers for the *calling* task's fds: `pid` must be zero or the caller's
/// own pid. The one fd kind that carries a program is a perf event with one
/// attached through `PERF_EVENT_IOC_SET_BPF`, which is tracepoint-shaped; the
/// name buffer comes back empty, because NARF names its probes by id rather than
/// by string. // LINUX-GAP: no cross-task query and no tracepoint-name string.
fn task_fd_query(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < TFQ_PROBE_ADDR + 8 {
        return -EINVAL;
    }
    if u32_at(&attr, TFQ_FLAGS) != 0 {
        return -EINVAL;
    }
    let pid = u32_at(&attr, TFQ_PID);
    let me = task_to_pid_raw(current_task_id()).unwrap_or(0) as u32;
    if pid != 0 && pid != me {
        return -ENOTSUP;
    }
    let (prog_id, fd_type) = match task_fd_prog_id(u32_at(&attr, TFQ_FD)) {
        Some(x) => x,
        // An fd with no BPF program attached — Linux's `ENOTSUPP`.
        None => return -ENOTSUP,
    };

    // Write the out-fields back into the caller's `attr`. Each is one field,
    // range-checked inside `copy_to_user`, which brackets SMAP and turns a fault
    // into `Err(EFAULT)`.
    let put = |off: usize, bytes: &[u8]| -> Result<(), i64> {
        // SAFETY: `copy_to_user` validates `[attr_uptr + off, +bytes.len())`.
        unsafe { copy_to_user(attr_uptr + off as u64, bytes) }.map_err(|e| -(e as i64))
    };
    if let Err(e) = put(TFQ_PROG_ID, &prog_id.to_le_bytes())
        .and_then(|()| put(TFQ_FD_TYPE, &fd_type.to_le_bytes()))
        .and_then(|()| put(TFQ_PROBE_OFFSET, &0u64.to_le_bytes()))
        .and_then(|()| put(TFQ_PROBE_ADDR, &0u64.to_le_bytes()))
        // Empty name: report length 0.
        .and_then(|()| put(TFQ_BUF_LEN, &0u32.to_le_bytes()))
    {
        return e;
    }
    // If the caller offered a name buffer, terminate it.
    let buf_uptr = u64_at(&attr, TFQ_BUF);
    if buf_uptr != 0 && u32_at(&attr, TFQ_BUF_LEN) > 0 {
        // SAFETY: caller-supplied pointer, range-checked inside `copy_to_user`.
        if let Err(e) = unsafe { copy_to_user(buf_uptr, &[0u8]) } {
            return -(e as i64);
        }
    }
    0
}

fn prog_load(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < PL_LICENSE + 8 {
        return -EINVAL;
    }
    let log = match ProgLog::new(attr_uptr, size, &attr) {
        Ok(log) => log,
        Err(e) => return e,
    };

    let prog_type = u32_at(&attr, PL_PROG_TYPE);
    let insn_cnt = u32_at(&attr, PL_INSN_CNT) as usize;
    let insns_uptr = u64_at(&attr, PL_INSNS);

    // Sleepability is a property of the hook, not a program flag. Linux uses
    // `BPF_F_SLEEPABLE` in `prog_flags` and then checks it against an
    // allowlist of attach types; here the program type selects the context it
    // is verified *for*, and attaching to a hook that provides the other one
    // is rejected by type at attach (spec §4.5).
    let context = match prog_type {
        BPF_PROG_TYPE_XDP | BPF_PROG_TYPE_RAW_TRACEPOINT | BPF_PROG_TYPE_TRACING => {
            Context::Atomic
        }
        BPF_PROG_TYPE_SYSCALL => Context::Sleepable,
        // LINUX-GAP: socket filters, cgroup hooks, LSM, struct_ops, and
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
    let gpl_compatible = match read_prog_license(u64_at(&attr, PL_LICENSE)) {
        Ok(compatible) => compatible,
        Err(e) => return e,
    };

    // Every map the program's `LD_IMM64` immediates name, resolved through the
    // caller's fd table. The `Arc`s travel into the program and keep the maps
    // alive after the creating fds are closed.
    let fd_array = u64_at(&attr, PL_FD_ARRAY);
    let fd_array_cnt = u32_at(&attr, PL_FD_ARRAY_CNT);
    let resolved = match resolve_prog_maps(&insns, fd_array, fd_array_cnt) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let load_result = BpfProg::load_with_metadata(
        load_cap(),
        LoadRequest {
            name,
            insns,
            context,
            maps: resolved.maps,
            map_indices: resolved.map_indices,
            load_references: resolved.load_references,
        },
        LoadMetadata {
            gpl_compatible,
            created_by_uid: read_uidgid(current_task_id()).euid,
            linux_prog_type: Some(prog_type),
        },
    );
    let prog = match load_result {
        Ok(p) => {
            let message = alloc::format!("verification accepted: {} instructions\n", p.len());
            if let Err(e) = log.emit(&message) {
                return e;
            }
            p
        }
        Err(narf_bpf::LoadError::AuthorityRevoked) => {
            return log
                .emit("program load authority was revoked\n")
                .err()
                .unwrap_or(-EPERM);
        }
        Err(e) => {
            let message = alloc::format!("verification rejected: {e:?}\n");
            return match log.emit(&message) {
                Ok(()) => -EINVAL,
                Err(log_error) => log_error,
            };
        }
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
    let attr = match read_attr(attr_uptr, size) {
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
    if prog.linux_prog_type() == Some(BPF_PROG_TYPE_XDP) {
        return prog_test_run_xdp(&prog, attr_uptr, size, &attr);
    }

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
    // SAFETY: `copy_to_user` range-validates and brackets SMAP; writing back
    // only the four bytes the caller asked about avoids clobbering fields a
    // newer userspace put beyond what this kernel understands.
    if let Err(e) = unsafe { copy_to_user(attr_uptr + T_RETVAL as u64, &retval.to_le_bytes()) } {
        return -(e as i64);
    }
    0
}

/// Linux-shaped XDP test execution without exposing native context pointers.
///
/// `data_in` is copied into an owned kernel allocation first. [`BpfProg::run_xdp`]
/// then constructs `data`/`data_end` from that exact immutable slice, preserving
/// the same pointer provenance as the live classifier path. NARF does not yet
/// translate Linux's optional `xdp_md`, CPU selection, or batched test mode;
/// accepting any of them partially would make the ABI look safer than it is.
fn prog_test_run_xdp(
    prog: &BpfProg,
    attr_uptr: u64,
    size: usize,
    attr: &[u8; ATTR_BUF],
) -> i64 {
    if size < T_DURATION + 4 {
        return -EINVAL;
    }

    let data_size_in = u32_at(attr, T_DATA_SIZE_IN) as usize;
    let data_size_out = u32_at(attr, T_DATA_SIZE_OUT) as usize;
    let data_in = u64_at(attr, T_DATA_IN);
    let data_out = u64_at(attr, T_DATA_OUT);
    let repeat = u32_at(attr, T_REPEAT).max(1);

    if data_in == 0 || data_size_in < ETH_HLEN {
        return -EINVAL;
    }
    if data_size_in > MAX_XDP_TEST_DATA || repeat > MAX_XDP_TEST_REPEAT {
        return -E2BIG;
    }
    if (data_out == 0) != (data_size_out == 0)
        || u32_at(attr, T_CTX_SIZE_IN) != 0
        || u32_at(attr, T_CTX_SIZE_OUT) != 0
        || u64_at(attr, T_CTX_IN) != 0
        || u64_at(attr, T_CTX_OUT) != 0
        || u32_at(attr, T_FLAGS) != 0
        || u32_at(attr, T_CPU) != 0
        || u32_at(attr, T_BATCH_SIZE) != 0
    {
        return -EINVAL;
    }

    // SAFETY: the helper validates the complete userspace range before
    // allocation/copy and enforces the global syscall-copy limit. The tighter
    // XDP limit above additionally bounds synchronous execution cost.
    let frame = match unsafe { copy_from_user_vec(data_in, data_size_in) } {
        Ok(frame) => frame,
        Err(e) => return -(e as i64),
    };

    let start = narf_time::monotonic_ns();
    let mut retval = 0u32;
    for _ in 0..repeat {
        let Some(outcome) = prog.run_xdp(&frame) else {
            return -EAGAIN;
        };
        retval = (outcome.value() & 0xFFFF_FFFF) as u32;
    }
    let duration = narf_time::monotonic_ns()
        .saturating_sub(start)
        .checked_div(u64::from(repeat))
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;

    let copied = core::cmp::min(frame.len(), data_size_out);
    if copied != 0 {
        // SAFETY: `copy_to_user` validates the requested output prefix and
        // brackets SMAP. The source remains the owned immutable frame.
        if let Err(e) = unsafe { copy_to_user(data_out, &frame[..copied]) } {
            return -(e as i64);
        }
    }
    let actual_size = frame.len() as u32;
    for (off, bytes) in [
        (T_DATA_SIZE_OUT, actual_size.to_le_bytes()),
        (T_RETVAL, retval.to_le_bytes()),
        (T_DURATION, duration.to_le_bytes()),
    ] {
        // SAFETY: every field is within the attr prefix required above.
        if let Err(e) = unsafe { copy_to_user(attr_uptr + off as u64, &bytes) } {
            return -(e as i64);
        }
    }

    if data_size_out < frame.len() && data_out != 0 {
        -ENOSPC
    } else {
        0
    }
}
// ── maps ────────────────────────────────────────────────────────────

/// The `Cap<BpfMapCap, Grant>` this handler presents to `BpfMap::create`.
///
/// Minted and cached once, for the same two reasons as [`load_cap`]: it is
/// plumbing rather than the authorisation check ([`task_may_load_bpf`] is
/// that), and `Cap::bootstrap()` allocates an object-table slot per call, so
/// minting per syscall would leak one per `BPF_MAP_CREATE`.
fn map_cap() -> &'static Cap<BpfMapCap, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfMapCap, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfMapCap,
            Grant,
        >::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

// `struct { … } map_create` field offsets within `union bpf_attr`.
const MC_MAP_TYPE: usize = 0;
const MC_KEY_SIZE: usize = 4;
const MC_VALUE_SIZE: usize = 8;
const MC_MAX_ENTRIES: usize = 12;
const MC_MAP_FLAGS: usize = 16;
const MC_MAP_NAME: usize = 28;

// `struct { … } map_elem` field offsets. `value` and `next_key` are the same
// union member, so one offset serves both.
const ME_MAP_FD: usize = 0;
const ME_KEY: usize = 8;
const ME_VALUE: usize = 16;
const ME_FLAGS: usize = 24;

/// `BPF_F_NO_PREALLOC`.
///
/// Accepted and ignored. NARF's hash maps are always pre-sized — spec §4.6
/// forbids allocating on the program-run path, which is the whole reason Linux
/// has this flag as an *option* and NARF does not. A map created with it behaves
/// identically; only its memory profile differs, and it differs in the safe
/// direction.
///
/// // LINUX-GAP: on Linux this flag changes when memory is charged and lets a
/// hash map hold more entries than were reserved. Here it cannot, and a loader
/// that sets it (libbpf sets it for most hash maps) gets a working map rather
/// than `EINVAL`.
const BPF_F_NO_PREALLOC: u32 = 1;

/// Descriptor-local map access flags shared by `BPF_MAP_CREATE`,
/// `BPF_OBJ_GET`, and `BPF_MAP_GET_FD_BY_ID`.
pub(crate) const BPF_F_RDONLY: u32 = 1 << 3;
pub(crate) const BPF_F_WRONLY: u32 = 1 << 4;

/// `BPF_F_ZERO_SEED`.
///
/// Accepted because it is already true: `crate::map`'s hash is unseeded, since
/// there is no unprivileged BPF for a seed to defend against (spec §4.10).
const BPF_F_ZERO_SEED: u32 = 64;

pub(crate) fn map_access_from_flags(flags: u32) -> Result<MapAccess, i64> {
    match flags & (BPF_F_RDONLY | BPF_F_WRONLY) {
        0 => Ok(MapAccess::ReadWrite),
        BPF_F_RDONLY => Ok(MapAccess::ReadOnly),
        BPF_F_WRONLY => Ok(MapAccess::WriteOnly),
        _ => Err(-EINVAL),
    }
}

/// Install one map fd with matching `F_GETFL` and `bpf(2)` access modes.
pub(crate) fn install_map_fd(map: alloc::sync::Arc<BpfMap>, access: MapAccess) -> i64 {
    let status_flags = match access {
        MapAccess::ReadWrite => crate::fd::O_RDWR,
        MapAccess::ReadOnly => crate::fd::O_RDONLY,
        MapAccess::WriteOnly => crate::fd::O_WRONLY,
    };
    let ops: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(MapFile::with_access(map, access));
    match fd::with_table(current_task_id(), |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            // Linux's `bpf_map_new_fd` always adds `O_CLOEXEC`: a leaked map
            // fd is a leaked authority, regardless of its access mode.
            flags: crate::fd::FD_CLOEXEC,
            status_flags,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}

fn map_create(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < MC_MAX_ENTRIES + 4 {
        return -EINVAL;
    }
    let map_type = u32_at(&attr, MC_MAP_TYPE);
    // LINUX-GAP: the map-type zoo beyond the native kinds — LRU, LPM tries,
    // bloom filters, queues/stacks, map-in-map, and the whole
    // graph-data-structure API — is deliberately absent (spec §3.4). Those
    // become arena + kfunc libraries, not kernel map types, so `ENOTSUP` is the
    // permanent answer rather than a placeholder. `RINGBUF` is the one that will
    // arrive later.
    let Some(kind) = MapKind::from_linux(map_type) else {
        return -ENOTSUP;
    };
    let map_flags = if size >= MC_MAP_FLAGS + 4 {
        u32_at(&attr, MC_MAP_FLAGS)
    } else {
        0
    };
    if map_flags
        & !(BPF_F_NO_PREALLOC | BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_ZERO_SEED)
        != 0
    {
        // Every remaining flag changes observable behaviour — mmapability,
        // NUMA placement, LRU tuning — so accepting one silently
        // would be a lie about what the map does. `EINVAL` is what Linux
        // returns for a flag a map type does not support.
        return -EINVAL;
    }
    let access = match map_access_from_flags(map_flags) {
        Ok(a) => a,
        Err(e) => return e,
    };

    let map_attr = MapAttr {
        kind,
        key_size: u32_at(&attr, MC_KEY_SIZE),
        value_size: u32_at(&attr, MC_VALUE_SIZE),
        max_entries: u32_at(&attr, MC_MAX_ENTRIES),
    };

    // `map_name` is a fixed 16-byte NUL-padded field inside `bpf_attr`, not a
    // pointer, so it is already in the buffer.
    let name = if size >= MC_MAP_NAME + PROG_NAME_LEN {
        let raw = &attr[MC_MAP_NAME..MC_MAP_NAME + PROG_NAME_LEN];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(PROG_NAME_LEN);
        alloc::string::String::from_utf8_lossy(&raw[..end]).into_owned()
    } else {
        alloc::string::String::new()
    };

    let map = match BpfMap::create(map_cap(), map_attr, name) {
        Ok(m) => m,
        Err(e) => return -(i64::from(e.errno())),
    };

    install_map_fd(map, access)
}

/// Recover the map and descriptor-local access behind a file descriptor.
fn map_file_from_fd(
    fd: u32,
) -> Result<(alloc::sync::Arc<narf_bpf::map::BpfMap>, MapAccess), i64> {
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return Err(-EBADF_),
    };
    let file = ops
        .as_any()
        .and_then(|a| a.downcast_ref::<MapFile>())
        .ok_or(-EINVAL)?;
    Ok((file.map(), file.access()))
}

/// Recover the object without applying descriptor-local syscall permissions.
/// Program load, program-map binding, pinning, and info queries name the map
/// object itself; `BPF_F_RDONLY`/`WRONLY` constrain only map syscalls.
fn map_from_fd(fd: u32) -> Result<alloc::sync::Arc<narf_bpf::map::BpfMap>, i64> {
    map_file_from_fd(fd).map(|(map, _)| map)
}

fn require_map_access(access: MapAccess, read: bool, write: bool) -> Result<(), i64> {
    if (read && !access.can_read()) || (write && !access.can_write()) {
        Err(-EPERM)
    } else {
        Ok(())
    }
}

/// Recover the program behind a file descriptor.
fn prog_from_fd(fd: u32) -> Result<alloc::sync::Arc<BpfProg>, i64> {
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return Err(-EBADF_),
    };
    ops.as_any()
        .and_then(|a| a.downcast_ref::<ProgFile>())
        .map(ProgFile::prog)
        .ok_or(-EINVAL)
}

/// `BPF_PROG_BIND_MAP` — make a program hold a map lifetime reference.
///
/// The three-field ABI is `(prog_fd, map_fd, flags)`, with flags currently
/// required to be zero. Binding an object the program already holds is a
/// successful no-op. The bound map is deliberately absent from the
/// verifier/runtime lookup table: as on Linux, this command promises lifetime,
/// not executable access.
fn prog_bind_map(attr_uptr: u64, size: usize) -> i64 {
    const END: usize = 12;
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < END || u32_at(&attr, 8) != 0 || attr[END..size].iter().any(|b| *b != 0) {
        return -EINVAL;
    }

    let prog = match prog_from_fd(u32_at(&attr, 0)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let map = match map_from_fd(u32_at(&attr, 4)) {
        Ok(m) => m,
        Err(e) => return e,
    };
    match prog.bind_map(map) {
        Ok(()) => 0,
        Err(narf_bpf::prog::BindError::NoMemory) => -ENOMEM,
    }
}

/// `BPF_ENABLE_STATS(BPF_STATS_RUN_TIME)` — enable global runtime accounting.
///
/// Each successful call owns one global enable reference through the returned
/// anonymous file description. Duplicating that fd shares the same reference;
/// another enable call creates another. Accounting stops only when the last
/// independent stats file is closed.
fn enable_stats(attr_uptr: u64, size: usize) -> i64 {
    const END: usize = 4;
    const BPF_STATS_RUN_TIME: u32 = 0;

    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < END
        || u32_at(&attr, 0) != BPF_STATS_RUN_TIME
        || attr[END..size].iter().any(|b| *b != 0)
    {
        return -EINVAL;
    }

    let file = match narf_bpf::stats::StatsFile::enable() {
        Ok(f) => f,
        Err(narf_bpf::stats::StatsError::Busy) => return -EBUSY,
    };
    let ops: alloc::sync::Arc<dyn narf_filesystem::FileOps> = alloc::sync::Arc::new(file);
    match fd::with_table(current_task_id(), |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}

/// The three fields every element command reads: the map, the key, and the
/// user pointer for the value or next key.
///
/// Factored out because the five keyed element commands agree on the layout and on
/// the order the errnos come in — `EBADF` for the fd before `EFAULT` for the
/// key — and copies of that order are how one of them ends up different.
struct ElemArgs {
    map: alloc::sync::Arc<narf_bpf::map::BpfMap>,
    key: alloc::vec::Vec<u8>,
    value_uptr: u64,
    flags: u64,
}

fn elem_args_from(
    attr: &[u8; ATTR_BUF],
    size: usize,
    need_value: bool,
    read: bool,
    write: bool,
) -> Result<ElemArgs, i64> {
    if size < ME_VALUE + 8 {
        return Err(-EINVAL);
    }
    let (map, access) = map_file_from_fd(u32_at(attr, ME_MAP_FD))?;
    require_map_access(access, read, write)?;
    let key_uptr = u64_at(attr, ME_KEY);
    let value_uptr = u64_at(attr, ME_VALUE);
    if key_uptr == 0 || (need_value && value_uptr == 0) {
        // Linux takes a NULL key as `EFAULT` from `copy_from_user`, not as
        // `EINVAL` — the exception is `GET_NEXT_KEY`, where NULL means "start
        // at the first key" and the caller below never comes through here.
        return Err(-EFAULT);
    }
    let key_size = map.attr().key_size as usize;
    // SAFETY: `copy_from_user_vec` validates the range and length before it
    // allocates, and converts a fault into `Err(EFAULT)`.
    let key = unsafe { copy_from_user_vec(key_uptr, key_size) }.map_err(|e| -(e as i64))?;
    Ok(ElemArgs {
        map,
        key,
        value_uptr,
        flags: if size >= ME_FLAGS + 8 {
            u64_at(attr, ME_FLAGS)
        } else {
            0
        },
    })
}

fn elem_args(
    attr_uptr: u64,
    size: usize,
    need_value: bool,
    read: bool,
    write: bool,
) -> Result<ElemArgs, i64> {
    let attr = read_attr(attr_uptr, size)?;
    elem_args_from(&attr, size, need_value, read, write)
}

fn map_lookup_elem(attr_uptr: u64, size: usize) -> i64 {
    let a = match elem_args(attr_uptr, size, true, true, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // The syscall view: for a per-CPU kind this is every CPU's slot, so the
    // caller's buffer is `cpus * round_up(value_size, 8)` bytes. Linux requires
    // exactly the same and the man page says so; getting it wrong here would
    // read past a userspace buffer.
    let mut out = alloc::vec![0u8; a.map.syscall_value_bytes()];
    if let Err(e) = a.map.lookup(&a.key, &mut out) {
        return -(i64::from(e.errno()));
    }
    // SAFETY: range-validated inside `copy_to_user`, which also brackets SMAP.
    match unsafe { copy_to_user(a.value_uptr, &out) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn map_update_elem(attr_uptr: u64, size: usize) -> i64 {
    let a = match elem_args(attr_uptr, size, true, false, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // SAFETY: as `elem_args`' key copy.
    let value = match unsafe { copy_from_user_vec(a.value_uptr, a.map.syscall_value_bytes()) } {
        Ok(v) => v,
        Err(e) => return -(e as i64),
    };
    let write = match a.map.begin_sys_write() {
        Ok(w) => w,
        Err(e) => return -(i64::from(e.errno())),
    };
    match write.update(&a.key, &value, a.flags) {
        Ok(()) => 0,
        Err(e) => -(i64::from(e.errno())),
    }
}

fn map_delete_elem(attr_uptr: u64, size: usize) -> i64 {
    let a = match elem_args(attr_uptr, size, false, false, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let write = match a.map.begin_sys_write() {
        Ok(w) => w,
        Err(e) => return -(i64::from(e.errno())),
    };
    match write.delete(&a.key) {
        Ok(()) => 0,
        Err(e) => -(i64::from(e.errno())),
    }
}

/// `BPF_MAP_LOOKUP_AND_DELETE_ELEM` — atomically return and remove one entry.
///
/// Linux defines this only for hash-family and queue/stack maps. NARF's native
/// subset therefore accepts Hash and PerCpuHash and reports `EOPNOTSUPP` for
/// arrays and ring buffers. The value copy occurs after the map operation, so
/// an `EFAULT` writing userspace can still leave the entry consumed, matching
/// Linux's syscall ordering.
fn map_lookup_and_delete_elem(attr_uptr: u64, size: usize) -> i64 {
    const END: usize = ME_FLAGS + 8;

    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < ME_VALUE + 8 || (size > END && attr[END..size].iter().any(|b| *b != 0)) {
        return -EINVAL;
    }
    // `BPF_F_LOCK` is the only Linux-defined bit. NARF has no BTF-described
    // spin-locked values, so it is invalid here, as are all unknown bits.
    if u64_at(&attr, ME_FLAGS) != 0 {
        return -EINVAL;
    }
    // The value is output-only. Linux resolves and removes the entry before
    // touching it, so even a NULL output pointer must not fail early.
    let a = match elem_args_from(&attr, size, false, true, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let mut out = alloc::vec![0u8; a.map.syscall_value_bytes()];
    let write = match a.map.begin_sys_write() {
        Ok(w) => w,
        Err(e) => return -(i64::from(e.errno())),
    };
    if let Err(e) = write.lookup_and_delete(&a.key, &mut out) {
        return -(i64::from(e.errno()));
    }
    // SAFETY: range-validated inside `copy_to_user`, which also brackets SMAP.
    match unsafe { copy_to_user(a.value_uptr, &out) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn map_get_next_key(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < ME_VALUE + 8 {
        return -EINVAL;
    }
    let (map, access) = match map_file_from_fd(u32_at(&attr, ME_MAP_FD)) {
        Ok(m) => m,
        Err(e) => return e,
    };
    if let Err(e) = require_map_access(access, true, false) {
        return e;
    }
    let key_uptr = u64_at(&attr, ME_KEY);
    let next_uptr = u64_at(&attr, ME_VALUE);
    if next_uptr == 0 {
        return -EFAULT;
    }
    let key_size = map.attr().key_size as usize;
    // A NULL key means "start at the first key" — this is the one element
    // command where NULL is a value rather than a fault.
    let key = if key_uptr == 0 {
        None
    } else {
        // SAFETY: as above.
        match unsafe { copy_from_user_vec(key_uptr, key_size) } {
            Ok(k) => Some(k),
            Err(e) => return -(e as i64),
        }
    };
    let mut out = alloc::vec![0u8; key_size];
    if let Err(e) = map.next_key(key.as_deref(), &mut out) {
        return -(i64::from(e.errno()));
    }
    // SAFETY: as above.
    match unsafe { copy_to_user(next_uptr, &out) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// `BPF_MAP_FREEZE` — permanently remove syscall-side write permission.
///
/// Only `map_fd` is input. Linux returns `EBUSY` both for a repeated freeze and
/// when a syscall writer is already active, and leaves program-side writes
/// enabled; [`BpfMap`] owns those semantics so every fd for the object observes
/// the same state. NARF refuses ring buffers for now: their consumer page is
/// writable through `mmap`, and the mapping layer does not yet expose the
/// write-accounting hook needed to prove no writable alias survives the call.
fn map_freeze(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < 4 || attr[4..size].iter().any(|b| *b != 0) {
        return -EINVAL;
    }
    let (map, access) = match map_file_from_fd(u32_at(&attr, 0)) {
        Ok(m) => m,
        Err(e) => return e,
    };
    if let Err(e) = require_map_access(access, false, true) {
        return e;
    }
    match map.freeze() {
        Ok(()) => 0,
        Err(e) => -(i64::from(e.errno())),
    }
}

// `struct { … } batch` field offsets within `union bpf_attr`. Distinct from
// the `ME_*` element offsets — the batch struct puts `map_fd` at 36, not 0.
const BA_IN_BATCH: usize = 0;
const BA_OUT_BATCH: usize = 8;
const BA_KEYS: usize = 16;
const BA_VALUES: usize = 24;
const BA_COUNT: usize = 32;
const BA_MAP_FD: usize = 36;
const BA_ELEM_FLAGS: usize = 40;
const BA_FLAGS: usize = 48;

/// `BPF_MAP_LOOKUP_BATCH` and `BPF_MAP_LOOKUP_AND_DELETE_BATCH`.
///
/// Walks the map with its own `next_key`, resuming *after* the caller's
/// `in_batch` cursor — the last key the previous call handed back, or the first
/// key when `in_batch` is NULL. Fills up to `count` (key, value) pairs into the
/// caller's arrays, writes the resume cursor to `out_batch`, writes the number
/// filled back to `count`, and returns `-ENOENT` once the walk is exhausted
/// (with `count` still set), which is the terminating condition libbpf's
/// `bpf_map_lookup_batch` loop keys off. `and_delete` removes each pair it
/// returns, so it drains the map — and because `next_key` restarts at the first
/// key when handed one the map no longer holds, a cursor pointing at a
/// just-deleted key resumes correctly on the surviving elements.
fn map_batch_read(attr_uptr: u64, size: usize, and_delete: bool) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < BA_MAP_FD + 4 {
        return -EINVAL;
    }
    let (map, access) = match map_file_from_fd(u32_at(&attr, BA_MAP_FD)) {
        Ok(m) => m,
        Err(e) => return e,
    };
    if let Err(e) = require_map_access(access, true, and_delete) {
        return e;
    }
    // No batch-level flags, and no per-element `BPF_F_LOCK`: NARF has no
    // spin-locked maps, so any set bit names behaviour that would not happen.
    if u64_at(&attr, BA_FLAGS) != 0 || u64_at(&attr, BA_ELEM_FLAGS) != 0 {
        return -EINVAL;
    }
    let key_size = map.attr().key_size as usize;
    let value_bytes = map.syscall_value_bytes();
    let count_in = u32_at(&attr, BA_COUNT);
    let keys_uptr = u64_at(&attr, BA_KEYS);
    let values_uptr = u64_at(&attr, BA_VALUES);
    let in_batch = u64_at(&attr, BA_IN_BATCH);
    let out_batch = u64_at(&attr, BA_OUT_BATCH);
    if count_in != 0 && (keys_uptr == 0 || values_uptr == 0) {
        return -EINVAL;
    }
    let write = if and_delete {
        match map.begin_sys_write() {
            Ok(w) => Some(w),
            Err(e) => return -(i64::from(e.errno())),
        }
    } else {
        None
    };

    // The resume cursor: the key to walk *after*. A NULL `in_batch` starts the
    // walk; otherwise it is the key-sized token a previous call handed back.
    let mut prev: Option<alloc::vec::Vec<u8>> = if in_batch == 0 {
        None
    } else {
        // SAFETY: `copy_from_user_vec` range-validates and brackets SMAP.
        match unsafe { copy_from_user_vec(in_batch, key_size) } {
            Ok(k) => Some(k),
            Err(e) => return -(e as i64),
        }
    };

    let mut key_buf = alloc::vec![0u8; key_size];
    let mut val_buf = alloc::vec![0u8; value_bytes];
    let mut filled: u32 = 0;
    let mut result: i64 = 0;

    while filled < count_in {
        match map.next_key(prev.as_deref(), &mut key_buf) {
            Ok(()) => {}
            // The walk is done: the batch's terminating condition.
            Err(MapError::NotFound) => {
                result = -ENOENT;
                break;
            }
            Err(e) => {
                result = -(i64::from(e.errno()));
                break;
            }
        }
        // A key `next_key` just handed us that `lookup` cannot find raced away
        // under a concurrent delete. Stop cleanly; the caller re-drives from
        // the cursor written below.
        if map.lookup(&key_buf, &mut val_buf).is_err() {
            break;
        }
        if and_delete {
            match write.as_ref().expect("and_delete admitted a writer").delete(&key_buf) {
                Ok(()) => {}
                // Same race — skip without counting it.
                Err(MapError::NotFound) => {
                    prev = Some(key_buf.clone());
                    continue;
                }
                // e.g. an array kind, which has no removable slots.
                Err(e) => {
                    result = -(i64::from(e.errno()));
                    break;
                }
            }
        }
        // SAFETY: each destination is range-validated inside `copy_to_user`.
        let wrote_key =
            unsafe { copy_to_user(keys_uptr + u64::from(filled) * key_size as u64, &key_buf) };
        if let Err(e) = wrote_key {
            return -(e as i64);
        }
        // SAFETY: as above.
        let wrote_val =
            unsafe { copy_to_user(values_uptr + u64::from(filled) * value_bytes as u64, &val_buf) };
        if let Err(e) = wrote_val {
            return -(e as i64);
        }
        prev = Some(key_buf.clone());
        filled += 1;
    }

    // Hand back the resume cursor and the count where Linux writes them, so
    // libbpf's next iteration finds them.
    if out_batch != 0 {
        if let Some(p) = &prev {
            // SAFETY: `out_batch` is a caller-supplied key-sized buffer,
            // range-validated inside `copy_to_user`.
            if let Err(e) = unsafe { copy_to_user(out_batch, p) } {
                return -(e as i64);
            }
        }
    }
    // SAFETY: `attr_uptr + BA_COUNT` lies inside the caller's `bpf_attr`.
    if let Err(e) = unsafe { copy_to_user(attr_uptr + BA_COUNT as u64, &filled.to_le_bytes()) } {
        return -(e as i64);
    }
    result
}

/// `BPF_MAP_UPDATE_BATCH` and `BPF_MAP_DELETE_BATCH`.
///
/// A straight walk over the caller's `keys` (and `values`, for update) array,
/// applying the element op to each. No cursor — the caller supplies the keys.
/// On the first element that fails it stops and writes the number that
/// succeeded back to `count`, matching Linux's partial-progress contract, so a
/// caller can tell exactly how far the batch got.
fn map_batch_write(attr_uptr: u64, size: usize, delete: bool) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < BA_MAP_FD + 4 {
        return -EINVAL;
    }
    let (map, access) = match map_file_from_fd(u32_at(&attr, BA_MAP_FD)) {
        Ok(m) => m,
        Err(e) => return e,
    };
    if let Err(e) = require_map_access(access, false, true) {
        return e;
    }
    if u64_at(&attr, BA_FLAGS) != 0 {
        return -EINVAL;
    }
    let key_size = map.attr().key_size as usize;
    let value_bytes = map.syscall_value_bytes();
    let count_in = u32_at(&attr, BA_COUNT);
    let keys_uptr = u64_at(&attr, BA_KEYS);
    let values_uptr = u64_at(&attr, BA_VALUES);
    // For update this carries the per-element flags (`BPF_ANY`/`NOEXIST`/
    // `EXIST`), validated inside `ops.update`. Delete takes no flags.
    let elem_flags = u64_at(&attr, BA_ELEM_FLAGS);
    if delete && elem_flags != 0 {
        return -EINVAL;
    }
    if count_in != 0 && (keys_uptr == 0 || (!delete && values_uptr == 0)) {
        return -EINVAL;
    }
    let write = match map.begin_sys_write() {
        Ok(w) => w,
        Err(e) => return -(i64::from(e.errno())),
    };

    let mut done: u32 = 0;
    let mut result: i64 = 0;
    while done < count_in {
        let koff = keys_uptr + u64::from(done) * key_size as u64;
        // SAFETY: `copy_from_user_vec` range-validates and brackets SMAP.
        let key = match unsafe { copy_from_user_vec(koff, key_size) } {
            Ok(k) => k,
            Err(e) => return -(e as i64),
        };
        let r = if delete {
            write.delete(&key)
        } else {
            let voff = values_uptr + u64::from(done) * value_bytes as u64;
            // SAFETY: as above.
            let value = match unsafe { copy_from_user_vec(voff, value_bytes) } {
                Ok(v) => v,
                Err(e) => return -(e as i64),
            };
            write.update(&key, &value, elem_flags)
        };
        if let Err(e) = r {
            result = -(i64::from(e.errno()));
            break;
        }
        done += 1;
    }
    // SAFETY: `attr_uptr + BA_COUNT` lies inside the caller's `bpf_attr`.
    if let Err(e) = unsafe { copy_to_user(attr_uptr + BA_COUNT as u64, &done.to_le_bytes()) } {
        return -(e as i64);
    }
    result
}

/// Objects resolved from `BPF_PROG_LOAD`'s instruction image and fd array.
struct ResolvedProgMaps {
    maps: alloc::vec::Vec<(i32, alloc::sync::Arc<narf_bpf::map::BpfMap>)>,
    map_indices: alloc::vec::Vec<narf_bpf::prog::IndexedMap>,
    load_references:
        alloc::vec::Vec<alloc::sync::Arc<dyn narf_bpf::prog::LoadReference>>,
}

/// Read one signed descriptor from the caller's fd array.
fn fd_array_entry(uptr: u64, index: u64) -> Result<i32, i64> {
    let offset = index.checked_mul(4).ok_or(-EFAULT)?;
    let at = uptr.checked_add(offset).ok_or(-EFAULT)?;
    let mut raw = [0u8; 4];
    // SAFETY: `copy_from_user` validates the four-byte range and SMAP-brackets
    // it. Linux performs the same per-entry copy rather than trusting `count`
    // as an allocation size.
    unsafe { copy_from_user(&mut raw, at) }.map_err(|e| -(e as i64))?;
    Ok(i32::from_le_bytes(raw))
}

/// Add one map lifetime/reference entry, enforcing Linux's 64-object limit.
///
/// Array scanning only needs one reference per object. Direct `MapFd`
/// instructions additionally need their exact fd alias retained because NARF
/// resolves immutable instructions at run time rather than rewriting them.
fn add_prog_map(
    maps: &mut alloc::vec::Vec<(i32, alloc::sync::Arc<narf_bpf::map::BpfMap>)>,
    fd: i32,
    map: alloc::sync::Arc<narf_bpf::map::BpfMap>,
    retain_fd_alias: bool,
) -> Result<(), i64> {
    if maps.iter().any(|(known_fd, known)| {
        alloc::sync::Arc::ptr_eq(known, &map) && (!retain_fd_alias || *known_fd == fd)
    }) {
        return Ok(());
    }
    let is_new_object = !maps
        .iter()
        .any(|(_, known)| alloc::sync::Arc::ptr_eq(known, &map));
    if is_new_object && distinct_prog_maps(maps) >= 64 {
        return Err(-E2BIG);
    }
    maps.push((fd, map));
    Ok(())
}

fn distinct_prog_maps(
    maps: &[(i32, alloc::sync::Arc<narf_bpf::map::BpfMap>)],
) -> usize {
    maps.iter()
        .enumerate()
        .filter(|(i, (_, map))| {
            !maps[..*i]
                .iter()
                .any(|(_, earlier)| alloc::sync::Arc::ptr_eq(earlier, map))
        })
        .count()
}

/// Resolve every map a program's `LD_IMM64` immediates name and every object
/// eagerly bound through `fd_array_cnt`.
///
/// Linux does this in `resolve_pseudo_ldimm64` and *rewrites the instruction*
/// to hold the map's kernel address. NARF does not rewrite: verification does
/// not touch instructions (spec §1.7), so the resolved set travels beside the
/// image and the interpreter resolves each reference again at run time from the
/// same list. The cost is one lookup per `LD_IMM64`; the gain is that there is
/// no second, patched copy of the program to keep consistent.
///
/// Duplicate objects collapse for lifetime and info reporting. Exact fd aliases
/// used by immutable `MapFd` instructions remain as lookup descriptors, while
/// sparse array indices travel in their own table and cannot be renumbered by
/// a BTF entry or duplicate map.
fn resolve_prog_maps(
    insns: &[narf_bpf_isa::Insn],
    fd_array: u64,
    fd_array_cnt: u32,
) -> Result<ResolvedProgMaps, i64> {
    use narf_bpf_isa::{Decoded, Imm64};

    if fd_array_cnt >= u32::MAX / 4 {
        return Err(-EINVAL);
    }

    let mut maps = alloc::vec::Vec::new();
    let mut map_indices = alloc::vec::Vec::new();
    let mut load_references = alloc::vec::Vec::new();
    let mut btf_ids = alloc::vec::Vec::new();

    // A non-zero count selects Linux's continuous-array API: every entry must
    // be a map or BTF fd and is bound even when no instruction names it.
    for index in 0..fd_array_cnt {
        let fd = fd_array_entry(fd_array, u64::from(index))?;
        let ops = match fd::with_table(current_task_id(), |t| {
            u32::try_from(fd)
                .ok()
                .and_then(|n| t.get(n).map(|entry| entry.ops.clone()))
        }) {
            Some(Some(ops)) => ops,
            _ => return Err(-EBADF_),
        };
        let Some(any) = ops.as_any() else {
            return Err(-EINVAL);
        };
        if let Some(file) = any.downcast_ref::<MapFile>() {
            let map = file.map();
            add_prog_map(&mut maps, fd, map, false)?;
            continue;
        }
        if let Some(file) = any.downcast_ref::<BtfFile>() {
            let id = file.id();
            if !btf_ids.contains(&id) {
                if btf_ids.len() >= 64 {
                    return Err(-E2BIG);
                }
                btf_ids.push(id);
                let reference: alloc::sync::Arc<dyn narf_bpf::prog::LoadReference> = file.blob();
                load_references.push(reference);
            }
            continue;
        }
        return Err(-EINVAL);
    }

    let mut i = 0usize;
    while i < insns.len() {
        // An undecodable instruction is not this function's error to report:
        // `BpfProg::load` decodes the whole image and names the offending slot.
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Ok(ResolvedProgMaps {
                maps,
                map_indices,
                load_references,
            });
        };
        if let Decoded::LoadImm64 { value, .. } = d {
            match value {
                Imm64::MapFd(fd) | Imm64::MapValue { fd, .. } => {
                    let map = map_from_fd(fd as u32)?;
                    add_prog_map(&mut maps, fd, map, true)?;
                }
                Imm64::MapIdx(index) | Imm64::MapIdxValue { idx: index, .. } => {
                    if fd_array == 0 {
                        return Err(-EPROTO);
                    }
                    let fd = fd_array_entry(
                        fd_array,
                        u64::try_from(index).map_err(|_| -EFAULT)?,
                    )?;
                    let map = map_from_fd(fd as u32)?;
                    add_prog_map(&mut maps, fd, alloc::sync::Arc::clone(&map), false)?;
                    if !map_indices.iter().any(
                        |known: &narf_bpf::prog::IndexedMap| known.index == index,
                    ) {
                        map_indices.push(narf_bpf::prog::IndexedMap { index, fd, map });
                    }
                }
                _ => {}
            }
        }
        i += width;
    }
    Ok(ResolvedProgMaps {
        maps,
        map_indices,
        load_references,
    })
}
