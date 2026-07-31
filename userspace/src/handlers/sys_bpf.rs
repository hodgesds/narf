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
//! * `BPF_PROG_TEST_RUN` (10) — run once with a caller-supplied context and
//!   report the return value in `attr.test.retval`.
//! * `BPF_MAP_CREATE` (0) and the four element commands (1..=4), over the four
//!   keyed map kinds in `narf_bpf::map`.
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

use narf_bpf::map::{BpfMap, BpfMapCap, MapAttr, MapFile, MapKind};
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
const EFAULT: i64 = 14;
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
const BPF_BTF_LOAD: u32 = 18;

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

        BPF_MAP_CREATE => map_create(attr_uptr, size),
        BPF_MAP_LOOKUP_ELEM => map_lookup_elem(attr_uptr, size),
        BPF_MAP_UPDATE_ELEM => map_update_elem(attr_uptr, size),
        BPF_MAP_DELETE_ELEM => map_delete_elem(attr_uptr, size),
        BPF_MAP_GET_NEXT_KEY => map_get_next_key(attr_uptr, size),

        // `sys_bpf_btf.rs`. Kept out of this file because three commands'
        // worth of BTF glue does not belong in the dispatcher, and because
        // this file is edited concurrently.
        BPF_BTF_LOAD => btf_load(attr_uptr, size),

        // LINUX-GAP: everything else — `BPF_OBJ_PIN`/`BPF_OBJ_GET` (bpffs
        // pinning), `BPF_PROG_ATTACH`/`DETACH` and `LINK_CREATE` (attach is
        // Phase 6), the `*_GET_FD_BY_ID` and `*_GET_NEXT_ID` families
        // (including BTF's — they need a kernel-wide id registry that does not
        // exist yet), and the token/iterator commands. `ENOTSUP` rather than
        // `EINVAL` so a probing loader can tell "this kernel does not do that"
        // from "you passed nonsense".
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

    // Every map the program's `LD_IMM64` immediates name, resolved through the
    // caller's fd table. The `Arc`s travel into the program and keep the maps
    // alive after the creating fds are closed.
    let maps = match resolve_prog_maps(&insns) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let prog = match BpfProg::load(
        load_cap(),
        LoadRequest {
            name,
            insns,
            context,
            maps,
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

/// `BPF_F_ZERO_SEED`.
///
/// Accepted because it is already true: `crate::map`'s hash is unseeded, since
/// there is no unprivileged BPF for a seed to defend against (spec §4.10).
const BPF_F_ZERO_SEED: u32 = 64;

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
    if map_flags & !(BPF_F_NO_PREALLOC | BPF_F_ZERO_SEED) != 0 {
        // Every remaining flag changes observable behaviour — read-only maps,
        // mmapability, NUMA placement, LRU tuning — so accepting one silently
        // would be a lie about what the map does. `EINVAL` is what Linux
        // returns for a flag a map type does not support.
        return -EINVAL;
    }

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

    let ops: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(MapFile::new(map));
    match fd::with_table(current_task_id(), |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            // As for a program fd: Linux's `bpf_map_new_fd` passes `O_CLOEXEC`,
            // because a leaked map fd is a leaked capability.
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}

/// Recover the map behind a file descriptor.
fn map_from_fd(fd: u32) -> Result<alloc::sync::Arc<narf_bpf::map::BpfMap>, i64> {
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return Err(-EBADF_),
    };
    ops.as_any()
        .and_then(|a| a.downcast_ref::<MapFile>())
        .map(MapFile::map)
        .ok_or(-EINVAL)
}

/// The three fields every element command reads: the map, the key, and the
/// user pointer for the value or next key.
///
/// Factored out because the four element commands agree on the layout and on
/// the order the errnos come in — `EBADF` for the fd before `EFAULT` for the
/// key — and four copies of that order is how one of them ends up different.
struct ElemArgs {
    map: alloc::sync::Arc<narf_bpf::map::BpfMap>,
    key: alloc::vec::Vec<u8>,
    value_uptr: u64,
    flags: u64,
}

fn elem_args(attr_uptr: u64, size: usize, need_value: bool) -> Result<ElemArgs, i64> {
    let attr = read_attr(attr_uptr, size)?;
    if size < ME_VALUE + 8 {
        return Err(-EINVAL);
    }
    let map = map_from_fd(u32_at(&attr, ME_MAP_FD))?;
    let key_uptr = u64_at(&attr, ME_KEY);
    let value_uptr = u64_at(&attr, ME_VALUE);
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
            u64_at(&attr, ME_FLAGS)
        } else {
            0
        },
    })
}

fn map_lookup_elem(attr_uptr: u64, size: usize) -> i64 {
    let a = match elem_args(attr_uptr, size, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ops = a.map.ops();
    // The syscall view: for a per-CPU kind this is every CPU's slot, so the
    // caller's buffer is `cpus * round_up(value_size, 8)` bytes. Linux requires
    // exactly the same and the man page says so; getting it wrong here would
    // read past a userspace buffer.
    let mut out = alloc::vec![0u8; ops.syscall_value_bytes()];
    if let Err(e) = ops.lookup(&a.key, &mut out) {
        return -(i64::from(e.errno()));
    }
    // SAFETY: range-validated inside `copy_to_user`, which also brackets SMAP.
    match unsafe { copy_to_user(a.value_uptr, &out) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn map_update_elem(attr_uptr: u64, size: usize) -> i64 {
    let a = match elem_args(attr_uptr, size, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ops = a.map.ops();
    // SAFETY: as `elem_args`' key copy.
    let value = match unsafe { copy_from_user_vec(a.value_uptr, ops.syscall_value_bytes()) } {
        Ok(v) => v,
        Err(e) => return -(e as i64),
    };
    match ops.update(&a.key, &value, a.flags) {
        Ok(()) => 0,
        Err(e) => -(i64::from(e.errno())),
    }
}

fn map_delete_elem(attr_uptr: u64, size: usize) -> i64 {
    let a = match elem_args(attr_uptr, size, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match a.map.ops().delete(&a.key) {
        Ok(()) => 0,
        Err(e) => -(i64::from(e.errno())),
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
    let map = match map_from_fd(u32_at(&attr, ME_MAP_FD)) {
        Ok(m) => m,
        Err(e) => return e,
    };
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
    if let Err(e) = map.ops().next_key(key.as_deref(), &mut out) {
        return -(i64::from(e.errno()));
    }
    // SAFETY: as above.
    match unsafe { copy_to_user(next_uptr, &out) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// Resolve every map a program's `LD_IMM64` immediates name.
///
/// Linux does this in `resolve_pseudo_ldimm64` and *rewrites the instruction*
/// to hold the map's kernel address. NARF does not rewrite: verification does
/// not touch instructions (spec §1.7), so the resolved set travels beside the
/// image and the interpreter resolves each reference again at run time from the
/// same list. The cost is one lookup per `LD_IMM64`; the gain is that there is
/// no second, patched copy of the program to keep consistent.
///
/// Duplicate fds collapse to one entry, so a program that names the same map
/// twenty times holds one reference and the verifier sees one descriptor.
fn resolve_prog_maps(
    insns: &[narf_bpf_isa::Insn],
) -> Result<alloc::vec::Vec<(i32, alloc::sync::Arc<narf_bpf::map::BpfMap>)>, i64> {
    use narf_bpf_isa::{Decoded, Imm64};

    let mut out: alloc::vec::Vec<(i32, alloc::sync::Arc<narf_bpf::map::BpfMap>)> =
        alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < insns.len() {
        // An undecodable instruction is not this function's error to report:
        // `BpfProg::load` decodes the whole image and names the offending slot.
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Ok(out);
        };
        if let Decoded::LoadImm64 { value, .. } = d {
            let fd = match value {
                Imm64::MapFd(fd) | Imm64::MapValue { fd, .. } => Some(fd),
                // The `MapIdx` forms index this very list, so there is no fd to
                // resolve — the loader must have named its maps by fd at least
                // once for the array to exist. A program using only the index
                // forms therefore resolves to an empty set and the verifier
                // reports `UnknownMap`, which is the honest answer: NARF has no
                // separate `fd_array` attribute to populate it from.
                //
                // LINUX-GAP: `bpf_attr.prog_load.fd_array` is not implemented,
                // so `BPF_PSEUDO_MAP_IDX{,_VALUE}` cannot resolve. The verifier
                // supports the forms; the syscall has nowhere to get the array.
                Imm64::MapIdx(_) | Imm64::MapIdxValue { .. } => None,
                _ => None,
            };
            if let Some(fd) = fd {
                if !out.iter().any(|(f, _)| *f == fd) {
                    let m = map_from_fd(fd as u32)?;
                    out.push((fd, m));
                }
            }
        }
        i += width;
    }
    Ok(out)
}
