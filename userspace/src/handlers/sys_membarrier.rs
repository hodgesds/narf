//! `membarrier(2)` — `kernel/sched/membarrier.c`.
//!
//! The expedited commands are a RENDEZVOUS: the call returns only once
//! every CPU that could be running a thread of the caller's address space
//! has executed a full memory barrier. That is the entire product. A
//! handler that validates the command and returns 0 without interrupting
//! anyone implements the signature and none of the contract — which is what
//! this one used to do, on the since-falsified premise of "the cooperative
//! single-CPU kernel". User tasks run on application processors now
//! (`narf_scheduler::enable_user_task_smp`), so a userspace RCU or a JIT
//! that trusts the returned 0 gets silent memory-ordering corruption,
//! exactly as `rseq(2)` did before it was made to answer -ENOSYS.
//!
//! The cross-CPU half lives in `narf_lib::smp::remote_barrier`, which
//! mirrors Linux's `smp_call_function_many(mask, ipi_mb, NULL, 1)`.
//!
//! What NARF does NOT have, and therefore does not advertise — both are
//! configurations Linux itself ships, so the shape is faithful rather than
//! a deviation:
//!
//! * `*_SYNC_CORE` needs `sync_core_before_usermode()`, the instruction-
//!   pipeline serialization a JIT relies on after patching code. Linux
//!   gates the pair on `CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE`; with it off
//!   the bits are absent from the QUERY mask and both commands are -EINVAL.
//! * `*_RSEQ` needs restartable sequences. `sys_rseq` answers -ENOSYS here,
//!   so this is Linux's `CONFIG_RSEQ=n` arm, same treatment.


#[allow(unused_imports)]
use super::*;

// ── enum membarrier_cmd (include/uapi/linux/membarrier.h) ────────────
const CMD_QUERY: i32 = 0;
const CMD_GLOBAL: i32 = 1 << 0;
const CMD_GLOBAL_EXPEDITED: i32 = 1 << 1;
const CMD_REGISTER_GLOBAL_EXPEDITED: i32 = 1 << 2;
const CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
const CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
const CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
const CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
const CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
const CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 8;
const CMD_GET_REGISTRATIONS: i32 = 1 << 9;

/// `MEMBARRIER_CMD_FLAG_CPU` — the only defined flag, and only for
/// `PRIVATE_EXPEDITED_RSEQ`.
const FLAG_CPU: u32 = 1 << 0;

// ── enum membarrier_state (include/linux/sched/mm.h) ─────────────────
const ST_PRIVATE_EXPEDITED_READY: u32 = 1 << 0;
const ST_PRIVATE_EXPEDITED: u32 = 1 << 1;
const ST_GLOBAL_EXPEDITED_READY: u32 = 1 << 2;
const ST_GLOBAL_EXPEDITED: u32 = 1 << 3;
const ST_PRIVATE_EXPEDITED_SYNC_CORE_READY: u32 = 1 << 4;
const ST_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 5;
const ST_PRIVATE_EXPEDITED_RSEQ_READY: u32 = 1 << 6;
const ST_PRIVATE_EXPEDITED_RSEQ: u32 = 1 << 7;

/// Every command in `enum membarrier_cmd` except QUERY itself.
const ALL_CMDS: i32 = CMD_GLOBAL
    | CMD_GLOBAL_EXPEDITED
    | CMD_REGISTER_GLOBAL_EXPEDITED
    | CMD_PRIVATE_EXPEDITED
    | CMD_REGISTER_PRIVATE_EXPEDITED
    | CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_PRIVATE_EXPEDITED_RSEQ
    | CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
    | CMD_GET_REGISTRATIONS;

/// The pairs this configuration does not implement, each corresponding to a
/// Linux `CONFIG` that can be off — see the module note. Subtracted rather
/// than omitted so that adding a command above cannot silently fail to
/// appear in the QUERY mask, and so the reason a command is missing is
/// stated where the mask is built.
const UNSUPPORTED: i32 = CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_PRIVATE_EXPEDITED_RSEQ
    | CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ;

/// `MEMBARRIER_CMD_BITMASK` for this configuration.
const SUPPORTED: i32 = ALL_CMDS & !UNSUPPORTED;

/// CPUs to interrupt for an expedited barrier.
///
/// Linux narrows this to the CPUs whose `rq->curr->mm` is the caller's mm
/// (private) or whose runqueue carries `MEMBARRIER_STATE_GLOBAL_EXPEDITED`
/// (global). NARF over-approximates to every online CPU. That direction of
/// error is the safe one — a CPU interrupted without a pending request
/// finds an empty bitmap and returns, whereas MISSING a CPU that runs one
/// of the caller's threads silently breaks the guarantee. The cost is
/// bounded by the early-outs below, which Linux has too and which discard
/// the single-threaded and uniprocessor cases before any IPI.
fn expedited_targets() -> u64 {
    narf_lib::smp::online_bitmap()
}

/// Run the rendezvous over [`expedited_targets`], with Linux's
/// `num_online_cpus() == 1` early-out.
///
/// This is the whole of `membarrier_global_expedited` and, once the
/// registration gate has passed, of `membarrier_private_expedited` too. The
/// two differ in Linux only in which peers they select — a distinction NARF
/// does not draw, because it over-approximates both to every online CPU
/// (see [`expedited_targets`]).
fn barrier_all() -> i64 {
    if narf_lib::smp::online_count() <= 1 {
        return 0;
    }
    if narf_lib::smp::remote_barrier(expedited_targets()) {
        0
    } else {
        // Reported available at entry but unavailable now: a CPU came online
        // between the two reads. Refusing is the only honest answer.
        -EINVAL
    }
}

/// Linux `membarrier_private_expedited(0, cpu_id)`.
///
/// `cpu_id` is accepted but cannot narrow the target set here: it is only
/// ever non-negative for `PRIVATE_EXPEDITED_RSEQ` (the sole command that
/// takes `MEMBARRIER_CMD_FLAG_CPU`), which this configuration rejects
/// before reaching any of this.
fn private_expedited(as_ref: &alloc::sync::Arc<narf_memory::AddressSpace>) -> i64 {
    if as_ref.membarrier_state() & ST_PRIVATE_EXPEDITED_READY == 0 {
        // "Registration is required" — an unregistered mm gets -EPERM, not
        // a silent success, so a caller that skipped REGISTER finds out.
        return -EPERM;
    }
    // Linux: `atomic_read(&mm->mm_users) == 1 || num_online_cpus() == 1`.
    // A single-threaded process has no peer thread whose accesses could
    // need ordering, and a uniprocessor has no peer CPU.
    if !as_ref.is_vm_shared() {
        return 0;
    }
    barrier_all()
}

/// Linux `membarrier_register_private_expedited` /
/// `membarrier_register_global_expedited`.
///
/// Linux sets the command bit, runs `sync_runqueues_membarrier_state` to
/// push the mm's state into every runqueue's cache, and only then sets the
/// READY bit — the two-phase dance exists because the fast path reads the
/// per-runqueue copy. NARF's barrier path reads `mm->membarrier_state`
/// directly and keeps no runqueue cache, so there is nothing to push and
/// the two bits are set together. The fence is still required, and is the
/// reason `membarrier_state_or` is an `AcqRel` RMW: no access issued after
/// registration may be reordered before it.
fn register(as_ref: &alloc::sync::Arc<narf_memory::AddressSpace>, set: u32, ready: u32) -> i64 {
    if as_ref.membarrier_state() & ready == ready {
        return 0;
    }
    as_ref.membarrier_state_or(set | ready);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    0
}

/// Linux `membarrier_get_registrations` — map the mm's state back to the
/// REGISTER commands that would have produced it.
fn get_registrations(state: u32) -> i64 {
    const PAIRS: [(u32, i32); 4] = [
        (
            ST_GLOBAL_EXPEDITED | ST_GLOBAL_EXPEDITED_READY,
            CMD_REGISTER_GLOBAL_EXPEDITED,
        ),
        (
            ST_PRIVATE_EXPEDITED | ST_PRIVATE_EXPEDITED_READY,
            CMD_REGISTER_PRIVATE_EXPEDITED,
        ),
        (
            ST_PRIVATE_EXPEDITED_SYNC_CORE | ST_PRIVATE_EXPEDITED_SYNC_CORE_READY,
            CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        ),
        (
            ST_PRIVATE_EXPEDITED_RSEQ | ST_PRIVATE_EXPEDITED_RSEQ_READY,
            CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
        ),
    ];
    let mut out = 0i32;
    for (states, cmd) in PAIRS {
        if state & states != 0 {
            out |= cmd;
        }
    }
    out as i64
}

/// `membarrier(cmd, flags, cpu_id)`.
pub(crate) fn sys_membarrier(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let cmd = a.arg0 as i32;
    let flags = a.arg1 as u32;
    // `cpu_id` (arg2) is deliberately unread. Linux forces it to -1 unless
    // `MEMBARRIER_CMD_FLAG_CPU` is set, and that flag is accepted only for
    // PRIVATE_EXPEDITED_RSEQ — rejected below — so no path here can reach a
    // value that would narrow the target set.

    // Flag validation comes first and is per-command, exactly as Linux
    // orders it: FLAG_CPU is meaningful only for PRIVATE_EXPEDITED_RSEQ,
    // and every other command rejects ANY non-zero flags. This used to be
    // unread entirely, so `membarrier(CMD_GLOBAL, 0xdeadbeef, 0)` was a
    // success.
    let flags_ok = if cmd == CMD_PRIVATE_EXPEDITED_RSEQ {
        flags == 0 || flags == FLAG_CPU
    } else {
        flags == 0
    };
    if !flags_ok {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // Without a working rendezvous nothing but QUERY can be honoured, and
    // QUERY then reports an empty mask so every caller falls back to its
    // own barriers rather than trusting a no-op. See
    // `narf_lib::smp::remote_barrier_available`.
    let available = narf_lib::smp::remote_barrier_available();
    if cmd == CMD_QUERY {
        let mask = if available { SUPPORTED } else { 0 };
        ctx.set_return(SyscallReturn::ok(mask as u64));
        return;
    }
    if !available || cmd <= 0 || !(cmd as u32).is_power_of_two() || SUPPORTED & cmd != cmd {
        // Not a single defined command bit, or one this configuration does
        // not implement (SYNC_CORE, RSEQ). Linux's `default:` arm and its
        // `CONFIG`-off arms both answer -EINVAL.
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // The mm is fetched only where Linux reads `current->mm`. Neither GLOBAL
    // nor GLOBAL_EXPEDITED does — GLOBAL_EXPEDITED inspects its PEERS' mms,
    // never its own — so a caller with no address space can still issue them.
    let mm = || current_address_space();

    let r = match cmd {
        // Linux issues `synchronize_rcu()` here, on the reasoning that an
        // RCU grace period implies the barrier on every CPU that passed
        // through it. `narf_rcu::sync()` will NOT do: it abandons the wait
        // after eight rounds rather than deadlock, so it cannot be the
        // basis of a guarantee. The rendezvous is stronger and bounded, and
        // GLOBAL needs no registration, which is the property that actually
        // distinguishes it from GLOBAL_EXPEDITED.
        CMD_GLOBAL => barrier_all(),
        CMD_GLOBAL_EXPEDITED => barrier_all(),
        CMD_REGISTER_GLOBAL_EXPEDITED => match mm() {
            Some(as_ref) => register(&as_ref, ST_GLOBAL_EXPEDITED, ST_GLOBAL_EXPEDITED_READY),
            None => -ENOMEM,
        },
        CMD_PRIVATE_EXPEDITED => match mm() {
            Some(as_ref) => private_expedited(&as_ref),
            None => -ENOMEM,
        },
        CMD_REGISTER_PRIVATE_EXPEDITED => match mm() {
            Some(as_ref) => register(&as_ref, ST_PRIVATE_EXPEDITED, ST_PRIVATE_EXPEDITED_READY),
            None => -ENOMEM,
        },
        CMD_GET_REGISTRATIONS => match mm() {
            Some(as_ref) => get_registrations(as_ref.membarrier_state()),
            None => -ENOMEM,
        },
        _ => -EINVAL,
    };
    ctx.set_return(SyscallReturn::ok(r as u64));
}
