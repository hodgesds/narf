//! Ptrace syscall implementation.
//! Linux-compatible ptrace(2) interface.
//!
//! ## Errno model
//!
//! `kernel/ptrace.c::SYSCALL_DEFINE4(ptrace, ...)` decides which error
//! wins when several apply, and the order is not the obvious one:
//!
//! 1. `find_get_task_by_vpid(pid)` — no such pid in the CALLER's pid
//!    namespace is **ESRCH**.
//! 2. `ptrace_check_attach()` — "not traced by me" / "not stopped" is
//!    **ESRCH**, not EPERM. It runs for every request except TRACEME,
//!    ATTACH and SEIZE, and it runs *before* `arch_ptrace()`, so a
//!    stranger's pid reports ESRCH even when the request code is
//!    garbage and the pointers fault.
//! 3. Only then the per-request checks, where ptrace's own dialect is
//!    **EIO**, not EINVAL: an unrecognised request code, an unaligned
//!    or out-of-range PEEKUSER/POKEUSER offset, a tracee word that
//!    cannot be read or written, an invalid resume/detach signal.
//!    EFAULT is reserved for a fault on the *tracer's own* buffer —
//!    the `data` word, the iovec, the `user_regs_struct`.
//!
//! EPERM survives in exactly three places, all in `ptrace_attach` /
//! `ptrace_traceme`: attaching to a process that already has a tracer,
//! TRACEME when already traced, and attaching to yourself.

use crate::errno::to_ret as errno_ret;
use crate::errno::*;
use crate::handlers::{
    clear_pending_signal_bits, copy_from_user, copy_to_user, current_task_id, push_stopcont_report,
    raise_signal_pending,
};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::RemoteBuf;

// Ptrace requests
pub const PTRACE_TRACEME: u64 = 0;
pub const PTRACE_PEEKTEXT: u64 = 1;
pub const PTRACE_PEEKDATA: u64 = 2;
pub const PTRACE_PEEKUSER: u64 = 3;
pub const PTRACE_POKETEXT: u64 = 4;
pub const PTRACE_POKEDATA: u64 = 5;
pub const PTRACE_POKEUSER: u64 = 6;
pub const PTRACE_CONT: u64 = 7;
pub const PTRACE_KILL: u64 = 8;
pub const PTRACE_SINGLESTEP: u64 = 9;
pub const PTRACE_GETREGS: u64 = 12;
pub const PTRACE_SETREGS: u64 = 13;
pub const PTRACE_ATTACH: u64 = 16;
pub const PTRACE_DETACH: u64 = 17;
pub const PTRACE_SYSCALL: u64 = 24;
pub const PTRACE_SETOPTIONS: u64 = 0x4200;
pub const PTRACE_GETEVENTMSG: u64 = 0x4201;
pub const PTRACE_GETSIGINFO: u64 = 0x4202;
pub const PTRACE_GETREGSET: u64 = 0x4204;
pub const PTRACE_SETREGSET: u64 = 0x4205;

/// `NT_PRSTATUS` regset id used with PTRACE_GETREGSET/SETREGSET; the
/// payload is a `user_regs_struct`.
pub const NT_PRSTATUS: u64 = 1;

/// x86 legacy floating-point regset used by Crashpad and other ptrace
/// consumers. The payload is the 512-byte FXSAVE-compatible prefix of XSAVE.
#[cfg(target_arch = "x86_64")]
pub const NT_PRFPREG: u64 = 2;

/// PTRACE_O_TRACESYSGOOD: OR 0x80 into the SIGTRAP stop signal at a
/// syscall-stop so the tracer can distinguish it from an ordinary
/// SIGTRAP.
pub const PTRACE_O_TRACESYSGOOD: u64 = 1;

/// PTRACE_O_TRACEEXEC: report a successful execve as a PTRACE_EVENT_EXEC stop
/// instead of the legacy SIGTRAP. The two are not interchangeable and they do
/// not even arrive at the same point — see [`ptrace_report_exec`].
pub const PTRACE_O_TRACEEXEC: u64 = 0x10;

/// `PTRACE_EVENT_EXEC`, as it appears in a wait status: the stop signal is
/// `SIGTRAP | (PTRACE_EVENT_EXEC << 8)`, so a tracer reads the event back as
/// `status >> 16`.
pub const PTRACE_EVENT_EXEC: u32 = 4;

/// Follow-the-children options and their events (`include/uapi/linux/ptrace.h`).
pub const PTRACE_O_TRACEFORK: u64 = 0x02;
pub const PTRACE_O_TRACEVFORK: u64 = 0x04;
pub const PTRACE_O_TRACECLONE: u64 = 0x08;
pub const PTRACE_O_TRACEVFORKDONE: u64 = 0x20;
pub const PTRACE_O_TRACEEXIT: u64 = 0x40;
pub const PTRACE_O_SUSPEND_SECCOMP: u64 = 1 << 21;

/// `PT_SUSPEND_SECCOMP`: the task's tracer suspended its seccomp filters
/// (CRIU checkpointing a sandboxed process). `__secure_computing` returns 0
/// for such a task without running any filter.
pub fn seccomp_suspended(task: u64) -> bool {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let pid = tid_to_pid(task);
    get_task_tracer(pid).is_some() && ptrace_options(pid) & PTRACE_O_SUSPEND_SECCOMP != 0
}
pub const PTRACE_EVENT_EXIT: u32 = 6;
pub const PTRACE_O_EXITKILL: u64 = 1 << 20;
pub const PTRACE_EVENT_FORK: u32 = 1;
pub const PTRACE_EVENT_VFORK: u32 = 2;
pub const PTRACE_EVENT_CLONE: u32 = 3;
pub const PTRACE_EVENT_VFORK_DONE: u32 = 5;

const CLONE_VFORK: u64 = 0x0000_4000;
const CLONE_PTRACE: u64 = 0x0000_2000;
const CLONE_UNTRACED: u64 = 0x0080_0000;
const SIGCHLD: u64 = 17;
const SIGSTOP: u32 = 19;

/// The set of PTRACE_SETOPTIONS bits Linux will accept, from
/// `include/uapi/linux/ptrace.h`:
///
/// ```text
/// #define PTRACE_O_MASK        (\
///    0x000000ff | PTRACE_O_EXITKILL | PTRACE_O_SUSPEND_SECCOMP)
/// ```
///
/// with PTRACE_O_EXITKILL = 1<<20 and PTRACE_O_SUSPEND_SECCOMP = 1<<21.
/// `kernel/ptrace.c::check_ptrace_options` rejects anything outside it
/// with EINVAL; see PTRACE_SETOPTIONS below for why silently storing
/// unknown bits is worse than rejecting them.
pub const PTRACE_O_MASK: u64 = 0x0000_00ff | (1 << 20) | (1 << 21);

/// `kernel/ptrace.c::ptrace_check_attach`:
///
/// ```text
/// static int ptrace_check_attach(struct task_struct *child, bool ignore_state)
/// {
///    int ret = -ESRCH;
///    ...
///    if (child->ptrace && child->parent == current) {
///        if (ignore_state || ptrace_freeze_traced(child))
///            ret = 0;
///    }
///    ...
///    return ret;
/// }
/// ```
///
/// "you are not this process's tracer" is **ESRCH**, not EPERM — and
/// `SYSCALL_DEFINE4(ptrace)` calls this before `arch_ptrace()`, so it
/// outranks a bad request code (EIO) and a faulting pointer (EFAULT).
///
/// The distinction is load-bearing. A tracer races the tracee's exit on
/// every single request: strace and gdb read ESRCH as "the tracee died
/// or left its ptrace-stop", go reap it with waitpid, and carry on. They
/// report EPERM to the user as a fatal "Operation not permitted" and
/// abandon the session. Answering EPERM for a tracee that merely exited
/// turns a routine race into a hard failure.
const ESRCH_NOT_TRACER: u64 = wire::ESRCH as u64;

/// Per-tracee syscall-stop phase. A PTRACE_SYSCALL resume arms the
/// tracee to stop at the *next* syscall boundary; the boundary toggles
/// entry → exit → (disarmed).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SyscallStopPhase {
    /// Not tracing syscalls (PTRACE_CONT or never armed).
    #[default]
    None,
    /// Armed by PTRACE_SYSCALL — stop at the next syscall ENTRY.
    Entry,
    /// Stopped at entry (or resumed past it) — stop at the matching EXIT.
    Exit,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct user_regs_struct {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct user_regs_struct {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct user_regs_struct {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// A dequeued signal's queued payload: `(si_code, si_value, si_pid)`.
pub type StopPayload = (i32, u64, u32);

#[derive(Debug, Default)]
pub struct PtraceRegistry {
    /// Maps tracee Process ID -> tracer Process ID
    pub tracers: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> whether the tracee is stopped for ptrace
    pub stopped: BTreeMap<u64, bool>,
    /// Maps tracee Process ID -> signal that stopped the tracee
    pub stop_signal: BTreeMap<u64, u32>,
    /// Maps tracee Process ID -> signal bypass mask (signal number -> bypass)
    pub signal_bypass: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> the queued payload `(si_code, si_value,
    /// si_pid)` of the signal its current signal-delivery stop dequeued,
    /// redelivered with it if the tracer resumes with the same signal.
    pub stop_payload: BTreeMap<u64, StopPayload>,
    /// Maps tracee Process ID -> next syscall-stop phase (PTRACE_SYSCALL).
    pub syscall_stop: BTreeMap<u64, SyscallStopPhase>,
    /// Maps tracee Process ID -> PTRACE_SETOPTIONS bitset (TRACESYSGOOD, ...).
    pub options: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> orig_rax captured at the last syscall
    /// ENTRY-stop, so the matching EXIT-stop reports the syscall number
    /// (state.rax holds the return value by then, not the number).
    pub orig_rax: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> the `rax` a tracer must observe at the
    /// CURRENT syscall-stop, which is not the `rax` the tracee resumes with.
    ///
    /// Linux stamps the two stops differently
    /// (`arch/x86/entry/entry_64.S`):
    ///
    /// ```text
    /// pushq   %rax                    /* pt_regs->orig_ax */
    /// PUSH_AND_CLEAR_REGS rax=$-ENOSYS
    /// ```
    ///
    /// so an entry-stop shows -ENOSYS and only the exit-stop shows the result.
    /// Neither value can ride in the TRACEE's saved state: at entry it must
    /// keep the syscall number so a resumed dispatch still works, and at exit
    /// the folded result is not in the snapshot yet (the asm stores it after
    /// the dispatcher returns). Set only by the syscall-stop path and cleared
    /// by a signal-stop and by every resume, so a tracer never reads a stale
    /// one.
    pub stop_rax: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> `ptrace_message`, the PTRACE_GETEVENTMSG
    /// value of its last event stop.
    pub event_msg: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> `last_siginfo` of its current stop, what
    /// PTRACE_GETSIGINFO copies out. Absent while running.
    pub last_siginfo: BTreeMap<u64, [u8; 128]>,
}

pub static PTRACE_STATE: IrqSafeSpinLock<Option<PtraceRegistry>> = IrqSafeSpinLock::new(None);
/// Exact number of entries in `PtraceRegistry::tracers`. The syscall entry/
/// exit hooks consult this before task-id translation or taking the registry
/// lock, making ptrace-disabled syscall dispatch a single atomic read.
static PTRACE_TRACEES: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub(crate) fn __test_tracee_count() -> usize {
    PTRACE_TRACEES.load(Ordering::Acquire)
}

fn pid_to_tid(pid: u64) -> u64 {
    crate::handlers::linux_tid_to_task_raw(pid)
        .or_else(|| crate::handlers::pid_to_task_raw(pid))
        .unwrap_or(pid)
}

fn tid_to_pid(tid: u64) -> u64 {
    crate::handlers::task_to_linux_tid_raw(tid)
        .or_else(|| crate::handlers::task_to_pid_raw(tid))
        .unwrap_or(tid)
}

pub fn ptrace_init() {
    let mut state = PTRACE_STATE.lock();
    *state = Some(PtraceRegistry::default());
    PTRACE_TRACEES.store(0, Ordering::Release);
}

/// Drop every per-tracee row of `pid` (not the `tracers` link itself).
fn forget_tracee_state(r: &mut PtraceRegistry, pid: u64) {
    r.stopped.remove(&pid);
    r.stop_signal.remove(&pid);
    r.signal_bypass.remove(&pid);
    r.syscall_stop.remove(&pid);
    r.options.remove(&pid);
    r.orig_rax.remove(&pid);
    r.stop_rax.remove(&pid);
    r.event_msg.remove(&pid);
    r.last_siginfo.remove(&pid);
    r.stop_payload.remove(&pid);
}

/// Retire every ptrace row owned by an exiting process.
///
/// PIDs are recycled, so leaving a dead tracee in `tracers` makes the next
/// owner of that PID look already traced and turns PTRACE_TRACEME into EPERM.
/// If the exiting process was itself a tracer, detach and wake its tracees so
/// they do not remain parked forever — or, for a tracee whose tracer set
/// `PTRACE_O_EXITKILL`, kill it (`exit_ptrace` → `__ptrace_detach` sends
/// SIGKILL when `PT_EXITKILL` is set).
pub(crate) fn release_process(pid: u64) {
    let detached = {
        let mut g = PTRACE_STATE.lock();
        let Some(r) = g.as_mut() else {
            return;
        };
        let tracees_before = r.tracers.len();

        r.tracers.remove(&pid);
        forget_tracee_state(r, pid);

        let tracees: alloc::vec::Vec<(u64, bool)> = r
            .tracers
            .iter()
            .filter_map(|(&tracee, &tracer)| (tracer == pid).then_some(tracee))
            .map(|tracee| {
                let kill = r.options.get(&tracee).copied().unwrap_or(0) & PTRACE_O_EXITKILL != 0;
                (tracee, kill)
            })
            .collect();
        for (tracee, _) in &tracees {
            r.tracers.remove(tracee);
            forget_tracee_state(r, *tracee);
        }
        let removed = tracees_before - r.tracers.len();
        if removed != 0 {
            PTRACE_TRACEES.fetch_sub(removed, Ordering::Release);
        }
        tracees
    };

    for (tracee, kill) in detached {
        let tid = pid_to_tid(tracee);
        if kill {
            raise_signal_pending(tid, 9);
        }
        crate::user_task::with_user_task_ctx(tid, |uc| {
            uc.sleep_deadline_ns.store(0, Ordering::Release);
        });
        crate::handlers::wake_signal(tid);
    }
}

pub fn get_task_tracer(child_pid: u64) -> Option<u64> {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return None;
    }
    let g = PTRACE_STATE.lock();
    g.as_ref()?.tracers.get(&child_pid).copied()
}

/// The TASK id of the tracer of `task` (a task id), if it is traced —
/// `current->ptrace` plus the tracer, which the exec credential step needs
/// for `ptracer_capable`.
pub(crate) fn tracer_task_of(task: u64) -> Option<u64> {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return None;
    }
    get_task_tracer(tid_to_pid(task)).map(pid_to_tid)
}

/// Test-only: make `tracer` (a task id) the tracer of `tracee` (a task id),
/// or detach it with `None`, without a live PTRACE_ATTACH. Keeps
/// `PTRACE_TRACEES` exact, as every real attach/detach does.
#[doc(hidden)]
pub fn __test_set_tracer(tracee: u64, tracer: Option<u64>) {
    let mut g = PTRACE_STATE.lock();
    let r = g.get_or_insert_with(PtraceRegistry::default);
    let key = tid_to_pid(tracee);
    let had = r.tracers.remove(&key).is_some();
    if had {
        PTRACE_TRACEES.fetch_sub(1, Ordering::Release);
    }
    if let Some(t) = tracer {
        r.tracers.insert(key, tid_to_pid(t));
        PTRACE_TRACEES.fetch_add(1, Ordering::Release);
    }
}

pub fn is_task_traced(child_pid: u64) -> bool {
    get_task_tracer(child_pid).is_some()
}

pub fn is_task_ptrace_stopped(task_id: u64) -> bool {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let g = PTRACE_STATE.lock();
    let pid = tid_to_pid(task_id);
    g.as_ref()
        .and_then(|r| r.stopped.get(&pid).copied())
        .unwrap_or(false)
}

/// Test-only counterpart to delivering a ptrace-stop signal.  The ABI-only
/// tests intentionally do not run a tracee through the full signal-return
/// path, but every request other than `PTRACE_KILL` still has to satisfy
/// Linux's `ptrace_check_attach()` stopped-state rule.
#[doc(hidden)]
pub fn __test_set_tracee_stopped(tracee: u64, stopped: bool) {
    let mut g = PTRACE_STATE.lock();
    let r = g.get_or_insert_with(PtraceRegistry::default);
    let pid = tid_to_pid(tracee);
    if stopped {
        r.stopped.insert(pid, true);
    } else {
        r.stopped.remove(&pid);
    }
}

/// Linux's `ptrace_check_attach(child, ignore_state)`, after the caller's pid
/// namespace has resolved `pid`.  Besides matching the observable errno
/// ordering, the stopped-state half is the memory-safety boundary for remote
/// demand paging below: an inactive tracee root may be changed only while its
/// task cannot execute concurrently.
fn ptrace_check_attach(pid: u64, caller_pid: u64, ignore_state: bool) -> bool {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let g = PTRACE_STATE.lock();
    let Some(r) = g.as_ref() else {
        return false;
    };
    r.tracers.get(&pid).copied() == Some(caller_pid)
        && (ignore_state || r.stopped.get(&pid).copied().unwrap_or(false))
}

/// Does `tracer_task` trace anything a wait for `want` would select?
///
/// `tracer_task` is a scheduler TaskId, which is what the wait path carries;
/// `tracers` is keyed and valued in the ptrace ABI's pid space, and the two
/// diverge the moment a task forks. Convert here rather than at the call site,
/// so a caller cannot get the space wrong: passing a TaskId straight through
/// made `do_wait`'s tracee check silently never match, and a tracer that had
/// attached to a non-child got ECHILD from `wait4(-1, …, __WALL)` instead of
/// its tracee's stop. That is the first thing `strace -p` does after
/// attaching, so it could not trace anything it had not itself forked.
///
/// Linux `do_wait` walks `tsk->ptraced` alongside `tsk->children`
/// (kernel/exit.c), which is the list this stands in for.
pub fn is_tracer_of_any(tracer_task: u64, want: i64) -> bool {
    let g = PTRACE_STATE.lock();
    let r = match g.as_ref() {
        Some(r) => r,
        None => return false,
    };
    let tracer_pid = tid_to_pid(tracer_task);
    if want > 0 {
        r.tracers.get(&(want as u64)).copied() == Some(tracer_pid)
    } else {
        r.tracers.values().any(|&t| t == tracer_pid)
    }
}

pub fn get_wait_recipient(child_pid: u64) -> Option<u64> {
    if let Some(tracer_pid) = get_task_tracer(child_pid) {
        // The `tracers` map is visible-pid → visible-pid (the ptrace ABI
        // namespace), but the wait path (push_stopcont_report / sys_wait4)
        // keys by TASK id — so hand back the tracer's task id, matching the
        // `parent_of_get` (also a task id) fallback below.
        Some(pid_to_tid(tracer_pid))
    } else {
        crate::handlers::parent_of_get(child_pid)
    }
}

/// True when a STOP of `child_pid` (visible pid) is a ptrace-stop owned by
/// `parent_task` (task id) — such stops are reported to the tracer's `wait4`
/// unconditionally (Linux reports ptrace-stops regardless of `WUNTRACED`;
/// `WUNTRACED` only gates job-control stops of NON-traced children).
pub fn is_ptrace_stop_recipient(parent_task: u64, child_pid: u64) -> bool {
    get_task_tracer(child_pid).map(pid_to_tid) == Some(parent_task)
}

/// Bit for `signum` (1..=64) in a 64-bit signal mask, or 0 for an invalid one.
fn bypass_bit(signum: u32) -> u64 {
    if (1..=64).contains(&signum) {
        1u64 << (signum - 1)
    } else {
        0
    }
}

pub fn is_ptrace_signal_bypass(child_pid: u64, signum: u32) -> bool {
    let g = PTRACE_STATE.lock();
    if let Some(r) = g.as_ref() {
        if let Some(&mask) = r.signal_bypass.get(&child_pid) {
            return mask & bypass_bit(signum) != 0;
        }
    }
    false
}

pub fn clear_ptrace_signal_bypass(child_pid: u64, signum: u32) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        if let Some(mask) = r.signal_bypass.get_mut(&child_pid) {
            *mask &= !bypass_bit(signum);
        }
    }
}

/// Mark `signum` — injected by the tracer at a resume — to be delivered
/// without a second signal-delivery stop. Any signal 1..=64 may be injected
/// (`ptrace_resume`: `valid_signal(data)`), realtime ones included.
pub fn set_ptrace_signal_bypass(child_pid: u64, signum: u32) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        let mask = r.signal_bypass.entry(child_pid).or_insert(0);
        *mask |= bypass_bit(signum);
    }
}

/// Current syscall-stop phase for `pid`, or `None` if not syscall-tracing.
pub fn syscall_stop_phase(pid: u64) -> SyscallStopPhase {
    let g = PTRACE_STATE.lock();
    g.as_ref()
        .and_then(|r| r.syscall_stop.get(&pid).copied())
        .unwrap_or(SyscallStopPhase::None)
}

fn set_syscall_stop_phase(pid: u64, phase: SyscallStopPhase) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        if phase == SyscallStopPhase::None {
            r.syscall_stop.remove(&pid);
        } else {
            r.syscall_stop.insert(pid, phase);
        }
    }
}

fn ptrace_options(pid: u64) -> u64 {
    let g = PTRACE_STATE.lock();
    g.as_ref()
        .and_then(|r| r.options.get(&pid).copied())
        .unwrap_or(0)
}

/// The stop signal delivered to the tracer at a syscall-stop: SIGTRAP,
/// or SIGTRAP|0x80 when PTRACE_O_TRACESYSGOOD is set.
fn syscall_stop_signal(pid: u64) -> u32 {
    const SIGTRAP: u32 = 5;
    if ptrace_options(pid) & PTRACE_O_TRACESYSGOOD != 0 {
        SIGTRAP | 0x80
    } else {
        SIGTRAP
    }
}

fn save_orig_rax(pid: u64, orig: u64) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        r.orig_rax.insert(pid, orig);
    }
}

/// True if `pid`'s reported orig_rax should be pinned (used by the exit
/// stop so GETREGS shows the syscall number, not the return value).
/// Consulted only by the x86_64 GETREGS path.
#[cfg(target_arch = "x86_64")]
fn pinned_orig_rax(pid: u64) -> Option<u64> {
    let g = PTRACE_STATE.lock();
    g.as_ref().and_then(|r| r.orig_rax.get(&pid).copied())
}

/// Record the `rax` a tracer must see at the syscall-stop `pid` is entering.
/// See [`PtraceRegistry::stop_rax`].
fn pin_stop_rax(pid: u64, rax: u64) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        r.stop_rax.insert(pid, rax);
    }
}

/// Drop the syscall-stop `rax` pin. A SIGNAL-stop reports the tracee's real
/// registers, so a pin left over from an earlier syscall-stop must not leak
/// into it.
fn clear_stop_rax(pid: u64) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        r.stop_rax.remove(&pid);
    }
}

#[cfg(target_arch = "x86_64")]
fn pinned_stop_rax(pid: u64) -> Option<u64> {
    let g = PTRACE_STATE.lock();
    g.as_ref().and_then(|r| r.stop_rax.get(&pid).copied())
}

/// Syscall-entry/exit stop hook. Called from the live musl syscall
/// dispatch (`kernel_syscall_entry_plain_with_state`) around the actual
/// syscall body. `at_entry` selects the entry-stop (before the syscall
/// runs) vs the exit-stop (after). Returns immediately (a no-op) unless
/// the current task is traced AND armed for a syscall-stop of the
/// requested kind; otherwise it reports a SIGTRAP-stop to the tracer and
/// parks the tracee until PTRACE_SYSCALL/PTRACE_CONT resumes it.
///
/// `orig_rax` is the syscall number (state.rax at entry). At the exit
/// stop we pin it in the tracee's reported registers so a tracer that
/// reads orig_rax sees the syscall number rather than the return value.
// Inline the inactive gate into syscall entry/exit without duplicating the
// tracing machinery at both call sites.
#[inline]
pub fn ptrace_syscall_stop(ctx: &mut dyn TrapContext, at_entry: bool, orig_rax: u64) {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return;
    }
    ptrace_syscall_stop_active(ctx, at_entry, orig_rax);
}

#[inline(never)]
fn ptrace_syscall_stop_active(ctx: &mut dyn TrapContext, at_entry: bool, orig_rax: u64) {
    let task = current_task_id();
    let pid = tid_to_pid(task);
    if get_task_tracer(pid).is_none() {
        return;
    }
    let phase = syscall_stop_phase(pid);
    if at_entry {
        if phase != SyscallStopPhase::Entry {
            return;
        }
        // Remember the syscall number so the exit-stop can report it.
        save_orig_rax(pid, orig_rax);
        // `entry_64.S` pushes the user's rax into `orig_ax` and then presets
        // `ax` to -ENOSYS, so a tracer at an entry-stop sees -ENOSYS and only
        // the exit-stop carries a result. That is not cosmetic: an ATTACHING
        // tracer cannot know whether the first syscall-stop it sees is an entry
        // or an exit, and -ENOSYS in rax is how it tells. Reporting the syscall
        // NUMBER here instead made strace pair the stops off by one and print
        // the number where the return value belongs — a traced `ppoll` read
        // `= 271`, which is `__NR_ppoll`.
        pin_stop_rax(pid, wire::ENOSYS as u64);
        // Advance to the exit phase; PTRACE_SYSCALL from the tracer
        // re-arms whichever phase comes next when it resumes us.
        set_syscall_stop_phase(pid, SyscallStopPhase::Exit);
    } else {
        if phase != SyscallStopPhase::Exit {
            return;
        }
        // Pin the syscall number so the tracer's GETREGS at the exit-stop
        // reports orig_rax as the nr.
        // Cleared by the resume path (PTRACE_SYSCALL/CONT).
        save_orig_rax(pid, orig_rax);
        // And pin the RESULT for the tracer's rax. It cannot be read out of the
        // saved user state: the exit asm folds the dispatcher's return into the
        // snapshot's rax slot only AFTER the dispatcher returns, so while we
        // stand inside the dispatch that state still holds the ENTRY register
        // file — rax = the syscall number. `pending_return` is what userspace is
        // about to receive, folded exactly as the asm folds it.
        if let Some(ret) = ctx.pending_return() {
            pin_stop_rax(pid, ret.user_rax());
        }
        // Consumed on this exit stop.
        set_syscall_stop_phase(pid, SyscallStopPhase::None);
    }
    let sig = syscall_stop_signal(pid);
    set_last_siginfo(pid, crate::handlers::ptrace_notify_siginfo(task, sig));
    let tracer_tid = pid_to_tid(get_task_tracer(pid).unwrap_or(pid));
    // At the exit-stop the dispatcher already mirrored the syscall's real
    // return value into the live user-state's rax slot; capture it so the
    // stop park preserves it (rather than clobbering rax with 0) — the
    // tracer's GETREGS must observe the real return value.
    let preserve_rax = if at_entry {
        // Entry stop: keep the syscall number visible in rax (Linux shows
        // the nr / -ENOSYS at entry) rather than clobbering it with 0.
        Some(orig_rax)
    } else {
        // Syscall-stop is x86_64-only (orig_rax/rax ABI); aarch64 UserState has
        // no `rax` and never reaches here (the syscall.rs hooks are x86_64).
        #[cfg(target_arch = "x86_64")]
        {
            crate::user_task::current_user_task().map(|uctx| {
                // SAFETY: uctx is the current, poller-pinned task ctx (single-CPU
                // cooperative execution), and its `state` points at the live
                // UserState the dispatcher just wrote the return value into.
                unsafe { (*(*uctx).state.get()).rax }
            })
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            None
        }
    };
    // The orig_rax pin persists across the stop so the tracer's GETREGS
    // (issued WHILE the tracee is parked here) reports the syscall number.
    // It is cleared by the resume path (PTRACE_SYSCALL/CONT), not here.
    enter_ptrace_stopped_inner(ctx, task, tracer_tid, sig, preserve_rax);
}

pub fn ptrace_intercept_signal(ctx: &mut dyn TrapContext, signum: u32) -> bool {
    ptrace_intercept_signal_info(ctx, signum, None)
}

/// [`ptrace_intercept_signal`] for a signal whose siginfo the caller already
/// built (a synchronous fault: `si_code` and `si_addr` come from the trap,
/// not from a queue). `None` takes the signal's queued payload.
pub fn ptrace_intercept_signal_info(
    ctx: &mut dyn TrapContext,
    signum: u32,
    info: Option<[u8; 128]>,
) -> bool {
    // SIGKILL (9) is never interceptable — it must always terminate, even a
    // traced (and ptrace-stopped, just-woken) tracee. Letting it be turned
    // into a ptrace signal-delivery-stop would make a tracee unkillable and
    // hang the tracer's waitpid. (Linux: SIGKILL is not reported to the
    // tracer and cannot be suppressed/redirected.)
    if signum == 9 {
        return false;
    }
    let task = current_task_id();
    let pid = tid_to_pid(task);
    if let Some(tracer_pid) = get_task_tracer(pid) {
        if is_ptrace_signal_bypass(pid, signum) {
            clear_ptrace_signal_bypass(pid, signum);
            return false;
        }

        // Dequeue the signal so it is not processed again — from BOTH sets,
        // the way `dequeue_signal` does, because a signal sent to the PROCESS
        // lives in the thread group's shared set and not in this thread's
        // private one. Clearing only the private bit left a process-directed
        // signal pending forever: it was re-delivered at every signal-delivery
        // point, so a tracer stepping a tracee saw a signal-stop for it after
        // every single syscall. `kill(getpid(), SIGSTOP)` is the ordinary way
        // to raise one — it is how strace's own startup handshake works — so
        // this hit the most common case there is.
        //
        // The siginfo is captured first: PTRACE_GETSIGINFO at this stop must
        // describe the signal being delivered.
        let info = info.unwrap_or_else(|| crate::handlers::ptrace_signal_siginfo(task, signum));
        set_last_siginfo(pid, info);
        // `dequeue_signal` takes the siginfo with the signal; it travels with
        // the stop and comes back if the tracer resumes with the same signal
        // (`ptrace_signal` delivers `current->last_siginfo`). Left queued, a
        // re-injected sigqueue() signal reached its handler without its value.
        let src = if crate::handlers::signal_pending_private(task)
            & crate::handlers::sig_bit(signum)
            != 0
        {
            task
        } else {
            crate::handlers::shared_pending_key(task)
        };
        let payload = crate::handlers::take_sigqueue_info(src, signum);
        {
            let mut g = PTRACE_STATE.lock();
            if let Some(r) = g.as_mut() {
                match payload {
                    Some(p) => r.stop_payload.insert(pid, p),
                    None => r.stop_payload.remove(&pid),
                };
            }
        }
        clear_pending_signal_bits(task, crate::handlers::sig_bit(signum));
        clear_pending_signal_bits(
            crate::handlers::shared_pending_key(task),
            crate::handlers::sig_bit(signum),
        );

        let tracer_tid = pid_to_tid(tracer_pid);
        // Put the task into ptrace stop!
        enter_ptrace_stopped(ctx, task, tracer_tid, signum);
        true
    } else {
        false
    }
}

/// Report a successful `execve` to the tracer, in the order Linux reports it.
///
/// There are TWO reports here, not one, and which comes first depends on
/// `PTRACE_O_TRACEEXEC`. Measured on Linux 7.3 with a tracer stepping
/// `PTRACE_SYSCALL` across `execve("/bin/true")` (`fedora-ptrace-probe.py`,
/// case `execseq-*`), where `sys:N` is a syscall-stop for syscall N:
///
/// ```text
/// without TRACEEXEC:  sys:59, sys:59, sig:5,  <new image's syscalls>
/// with    TRACEEXEC:  sys:59, ev:4,   sys:59, <new image's syscalls>
/// ```
///
/// So the execve syscall-EXIT stop happens either way — it is what prints
/// `execve(...) = 0` — and the exec report is an event stop BEFORE it, or a
/// SIGTRAP AFTER it. The difference in position is not arbitrary:
/// `ptrace_event(PTRACE_EVENT_EXEC)` stops inside `begin_new_exec`, while the
/// legacy `send_sig(SIGTRAP, current, 0)` merely queues a signal that is
/// delivered later, in the exit-to-user loop that runs after the syscall-exit
/// work.
///
/// NARF emitted only the first stop of either sequence: the exec path DIVERGES
/// into the new image instead of returning through the syscall exit, so no
/// exit stop was ever taken, and no exec report was sent at all. A tracer was
/// left waiting for a stop that never came — `strace <cmd>` hung with its
/// trace ending at the startup `--- stopped by SIGSTOP ---`.
///
/// Both halves must land together. Sending only the SIGTRAP was measured too:
/// strace, still waiting for the exit stop, took the report for an ordinary
/// signal and injected it, killing `/bin/true` with SIGTRAP. Half of this
/// contract is worse than none of it.
///
/// Called after the point of no return and before the jump into the new image,
/// which is where Linux's reports sit relative to the exec. Each stop parks
/// and returns here when the tracer resumes, so the jump still happens.
pub fn ptrace_report_exec(ctx: &mut dyn TrapContext) {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return;
    }
    let task = current_task_id();
    let pid = tid_to_pid(task);
    let Some(tracer_pid) = get_task_tracer(pid) else {
        return;
    };
    let tracer_tid = pid_to_tid(tracer_pid);
    let trace_exec = ptrace_options(pid) & PTRACE_O_TRACEEXEC != 0;

    const SIGTRAP: u32 = 5;
    if trace_exec {
        let code = SIGTRAP | (PTRACE_EVENT_EXEC << 8);
        set_last_siginfo(pid, crate::handlers::ptrace_notify_siginfo(task, code));
        enter_ptrace_stopped(ctx, task, tracer_tid, code);
    }
    // The exec succeeded, so the syscall-exit stop must report 0 — the value
    // userspace would have seen had this syscall returned normally.
    ctx.set_return(SyscallReturn::ok(0));
    ptrace_syscall_stop(ctx, false, u64::from(crate::syscall::Syscall::Execve.raw()));
    if !trace_exec {
        set_last_siginfo(pid, crate::handlers::ptrace_signal_siginfo(task, SIGTRAP));
        enter_ptrace_stopped(ctx, task, tracer_tid, SIGTRAP);
    }
}

/// `PTRACE_O_TRACESECCOMP` and its event (`PTRACE_EVENT_SECCOMP`).
pub const PTRACE_O_TRACESECCOMP: u64 = 0x80;
pub const PTRACE_EVENT_SECCOMP: u32 = 7;

/// `ptrace_event_enabled(task, PTRACE_EVENT_SECCOMP)`: traced, and the tracer
/// asked for seccomp events. A seccomp `RET_TRACE` with nobody listening is
/// `-ENOSYS`.
pub fn seccomp_event_enabled(task: u64) -> bool {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let pid = tid_to_pid(task);
    get_task_tracer(pid).is_some() && ptrace_options(pid) & PTRACE_O_TRACESECCOMP != 0
}

/// `ptrace_event(PTRACE_EVENT_SECCOMP, data)` from `__seccomp_filter`'s
/// `RET_TRACE` arm: stop with `SIGTRAP | PTRACE_EVENT_SECCOMP << 8`, the
/// filter's data as the event message. Returns the syscall number to
/// recheck, or `None` when the syscall must be skipped because a fatal
/// signal arrived during the stop.
///
/// A tracer can rewrite the syscall by setting `orig_rax` while the tracee is
/// stopped. The resumed seccomp path rechecks that replacement once, just as
/// Linux's `__seccomp_filter(..., true)` does.
pub fn ptrace_report_seccomp(ctx: &mut dyn TrapContext, nr: u32, data: u64) -> Option<i64> {
    let task = current_task_id();
    let pid = tid_to_pid(task);
    let tracer = get_task_tracer(pid)?;
    set_event_msg(pid, data);
    let code = SIGTRAP_EVENT_BASE | (PTRACE_EVENT_SECCOMP << 8);
    set_last_siginfo(pid, crate::handlers::ptrace_notify_siginfo(task, code));
    // Preserve the intercepted number in the saved syscall frame while the
    // tracee is stopped. Besides making PEEKUSER's `orig_rax` truthful, this
    // gives POKEUSER/SETREGS a concrete slot to replace before the seccomp
    // path rechecks and dispatches the replacement.
    enter_ptrace_stopped_inner(ctx, task, pid_to_tid(tracer), code, Some(u64::from(nr)));
    if crate::handlers::current_task_fatal_signal_pending() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::user_task::current_user_task()
            .map(|uctx| {
                // SAFETY: this is the in-flight, poller-pinned task. The
                // ptrace stop has ended, so PTRACE_SETREGS' replacement is
                // now the authoritative syscall number in its saved frame.
                unsafe { (*(*uctx).state.get()).rax as i64 }
            })
            .or(Some(i64::from(nr)))
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::user_task::current_user_task()
            .map(|uctx| {
                // SAFETY: as above. AArch64 carries the syscall number in x8.
                unsafe { (*(*uctx).state.get()).x[8] as i64 }
            })
            .or(Some(i64::from(nr)))
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Some(i64::from(nr))
    }
}

const SIGTRAP_EVENT_BASE: u32 = 5;

/// What `kernel_clone` decided for a new child of a traced task.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CloneTrace {
    /// `PTRACE_EVENT_{FORK,VFORK,CLONE}` to report to the tracer, or 0.
    event: u32,
}

impl CloneTrace {
    pub const NONE: CloneTrace = CloneTrace { event: 0 };
}

/// `kernel_clone` + `copy_process` + `ptrace_init_task`, run BEFORE the child
/// can execute: pick the event a traced parent reports, and auto-attach the
/// child to the parent's tracer when that event is enabled (or the caller
/// passed CLONE_PTRACE).
///
/// ```text
/// if (!(clone_flags & CLONE_UNTRACED)) {
///         if (clone_flags & CLONE_VFORK)          trace = PTRACE_EVENT_VFORK;
///         else if (args->exit_signal != SIGCHLD)  trace = PTRACE_EVENT_CLONE;
///         else                                    trace = PTRACE_EVENT_FORK;
///         if (likely(!ptrace_event_enabled(current, trace)))
///                 trace = 0;
/// }
/// ...
/// ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);
/// ```
///
/// An attached child shares its parent's tracer and options and starts in a
/// SIGSTOP signal-delivery stop (`sigaddset(&child->pending.signal,
/// SIGSTOP)`), reported to the tracer like any stop. NARF parks the child in
/// that stop before its first instruction rather than queueing the signal,
/// which is the same thing the tracer can observe: the child's first stop is
/// SIGSTOP, and nothing it does happens before the tracer resumes it.
pub fn attach_new_child(
    parent_task: u64,
    child_task: u64,
    clone_flags: u64,
    exit_signal: u64,
) -> CloneTrace {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return CloneTrace::NONE;
    }
    let parent = tid_to_pid(parent_task);
    let Some(tracer) = get_task_tracer(parent) else {
        return CloneTrace::NONE;
    };
    let options = ptrace_options(parent);
    let mut event = 0;
    if clone_flags & CLONE_UNTRACED == 0 {
        let (ev, opt) = if clone_flags & CLONE_VFORK != 0 {
            (PTRACE_EVENT_VFORK, PTRACE_O_TRACEVFORK)
        } else if exit_signal != SIGCHLD {
            (PTRACE_EVENT_CLONE, PTRACE_O_TRACECLONE)
        } else {
            (PTRACE_EVENT_FORK, PTRACE_O_TRACEFORK)
        };
        if options & opt != 0 {
            event = ev;
        }
    }
    if clone_flags & CLONE_PTRACE == 0 && event == 0 {
        return CloneTrace::NONE;
    }
    let child = tid_to_pid(child_task);
    {
        let mut g = PTRACE_STATE.lock();
        let Some(r) = g.as_mut() else {
            return CloneTrace::NONE;
        };
        if r.tracers.insert(child, tracer).is_none() {
            PTRACE_TRACEES.fetch_add(1, Ordering::Release);
        }
        r.options.insert(child, options);
        r.stopped.insert(child, true);
        r.stop_signal.insert(child, SIGSTOP);
    }
    let info = crate::handlers::ptrace_signal_siginfo(child_task, SIGSTOP);
    set_last_siginfo(child, info);
    // `(SIGSTOP << 8) | 0x7f`: the stop the tracer's wait4 sees first.
    push_stopcont_report(child_task, ((SIGSTOP as i32) << 8) | 0x7f, false);
    CloneTrace { event }
}

/// `ptrace_event_pid(trace, pid)` after the child is running: stop the
/// parent with `SIGTRAP | event << 8`, the child's pid in the TRACER's pid
/// namespace as the event message. `ret` is the clone syscall's return value,
/// which the parent still returns once the tracer resumes it.
pub fn report_clone_event(ctx: &mut dyn TrapContext, trace: CloneTrace, child_task: u64, ret: u64) {
    if trace.event == 0 {
        return;
    }
    report_child_event(ctx, trace.event, child_task, ret);
}

/// `ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid)`, after a vfork parent's
/// wait for its child ended, when the tracer asked for it.
pub fn report_vfork_done(ctx: &mut dyn TrapContext, child_task: u64, ret: u64) {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return;
    }
    let parent = tid_to_pid(current_task_id());
    if get_task_tracer(parent).is_none() || ptrace_options(parent) & PTRACE_O_TRACEVFORKDONE == 0 {
        return;
    }
    report_child_event(ctx, PTRACE_EVENT_VFORK_DONE, child_task, ret);
}

fn report_child_event(ctx: &mut dyn TrapContext, event: u32, child_task: u64, ret: u64) {
    let task = current_task_id();
    let parent = tid_to_pid(task);
    let Some(tracer) = get_task_tracer(parent) else {
        return;
    };
    let tracer_task = pid_to_tid(tracer);
    let child_tid = tid_to_pid(child_task);
    set_event_msg(
        parent,
        crate::handlers::report_pid_to(tracer_task, child_tid),
    );
    let code = SIGTRAP_EVENT_BASE | (event << 8);
    set_last_siginfo(parent, crate::handlers::ptrace_notify_siginfo(task, code));
    clear_stop_rax(parent);
    enter_ptrace_stopped_inner(ctx, task, tracer_task, code, Some(ret));
    ctx.set_return(SyscallReturn::ok(ret));
}

/// `ptrace_event(PTRACE_EVENT_EXIT, code)` at the top of `do_exit`, before
/// any teardown: a tracee whose tracer set PTRACE_O_TRACEEXIT stops with
/// `SIGTRAP | PTRACE_EVENT_EXIT << 8`, its pending exit status (the wait
/// status it is about to leave) as the event message, while its registers
/// and memory are still there to inspect. Not when SIGKILL is pending:
/// `ptrace_stop` refuses to stop a task with a fatal signal queued.
pub fn ptrace_report_exit(ctx: &mut dyn TrapContext, wstatus: i32) {
    if PTRACE_TRACEES.load(Ordering::Acquire) == 0 {
        return;
    }
    let task = current_task_id();
    let pid = tid_to_pid(task);
    let Some(tracer) = get_task_tracer(pid) else {
        return;
    };
    if ptrace_options(pid) & PTRACE_O_TRACEEXIT == 0
        || crate::handlers::current_task_fatal_signal_pending()
    {
        return;
    }
    set_event_msg(pid, wstatus as u32 as u64);
    let code = SIGTRAP_EVENT_BASE | (PTRACE_EVENT_EXIT << 8);
    set_last_siginfo(pid, crate::handlers::ptrace_notify_siginfo(task, code));
    enter_ptrace_stopped(ctx, task, pid_to_tid(tracer), code);
}

fn set_last_siginfo(pid: u64, info: [u8; 128]) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        r.last_siginfo.insert(pid, info);
    }
}

/// `child->ptrace_message`, read back with PTRACE_GETEVENTMSG.
fn set_event_msg(pid: u64, msg: u64) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        r.event_msg.insert(pid, msg);
    }
}

pub fn enter_ptrace_stopped(ctx: &mut dyn TrapContext, task: u64, tracer: u64, signum: u32) {
    // A signal-stop reports the tracee's real registers, so drop any pin left
    // by an earlier syscall-stop rather than letting it answer for them.
    clear_stop_rax(tid_to_pid(task));
    enter_ptrace_stopped_inner(ctx, task, tracer, signum, None);
}

/// Core ptrace-stop park. `preserve_rax`, when set, is written into the
/// saved user-state's rax slot INSTEAD of 0 — the syscall-stop path uses
/// this so a tracer's GETREGS at the exit-stop sees the syscall's real
/// return value (a signal-stop, which restarts the interrupted syscall
/// on resume, keeps the 0-into-rax default and never sets this).
fn enter_ptrace_stopped_inner(
    ctx: &mut dyn TrapContext,
    task: u64,
    _tracer: u64,
    signum: u32,
    preserve_rax: Option<u64>,
) {
    {
        let mut g = PTRACE_STATE.lock();
        if let Some(r) = g.as_mut() {
            let pid = tid_to_pid(task);
            r.stopped.insert(pid, true);
            r.stop_signal.insert(pid, signum);
        }
    }
    // Arm the park deadline BEFORE publishing the report. The report is what
    // lets the tracer resume us, and a resume zeroes this field (see
    // PTRACE_CONT/SYSCALL) — so setting it first means a resume that beats us
    // to the park leaves a zeroed deadline behind, and `park_should_block`
    // declines to block instead of stranding the tracee on u64::MAX. Setting it
    // afterwards would overwrite the resume's clear and lose the wake.
    //
    // Gated on the YIELD HOOK as well as the task ctx, which is the same pair
    // the park below requires: with no executor wired (the kernel-test
    // context) this function returns WITHOUT parking, and arming a deadline
    // that nothing will ever consume leaves the harness task asleep-forever
    // from the next test onward.
    let parking = crate::user_task::current_user_task().zip(crate::user_task::yield_hook());
    if let Some((uctx, _)) = parking {
        // SAFETY: uctx is the current task's live ctx; this is an atomic store.
        unsafe {
            (*uctx).sleep_deadline_ns.store(u64::MAX, Ordering::Release);
        }
    }
    // Notify tracer via push_stopcont_report
    // Linux wstatus for stopped tracee: (signum << 8) | 0x7f
    let wstatus = ((signum as i32) << 8) | 0x7f;
    push_stopcont_report(task, wstatus, false);

    if let Some((uctx, hook)) = parking {
        // SAFETY: uctx is current task, yield hook never returns
        unsafe {
            let uc = &*uctx;
            ctx.set_return(SyscallReturn::ok(preserve_rax.unwrap_or(0)));
            uc.sleep_deadline_ns.store(u64::MAX, Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                crate::handlers::own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
    }
}

fn get_tracee_regs(pid: u64) -> Option<user_regs_struct> {
    let tid = pid_to_tid(pid);
    // At a syscall-EXIT stop, state.rax holds the return value; report the
    // pinned syscall number as orig_rax (Linux orig_ax semantics). Absent a
    // pin (entry-stop / signal-stop) orig_rax == the current rax.
    #[cfg(target_arch = "x86_64")]
    let orig_rax_pin = pinned_orig_rax(pid);
    #[cfg(target_arch = "x86_64")]
    let stop_rax_pin = pinned_stop_rax(pid);
    crate::user_task::with_user_task_ctx(tid, |uctx| {
        // SAFETY: tracee is registered and stopped, so its state pointer is valid and stable.
        let state = unsafe { *uctx.state.get() };

        #[cfg(target_arch = "x86_64")]
        {
            let fs_base = uctx.pending_fs_base.load(Ordering::Acquire);
            let orig_rax = orig_rax_pin.unwrap_or(state.rax);
            // At a syscall-stop the tracer's `rax` comes from the pin, not the
            // saved state: see `PtraceRegistry::stop_rax`. A signal-stop has no
            // pin and reports the tracee's real register.
            let rax = stop_rax_pin.unwrap_or(state.rax);
            user_regs_struct {
                r15: state.r15,
                r14: state.r14,
                r13: state.r13,
                r12: state.r12,
                rbp: state.rbp,
                rbx: state.rbx,
                r11: state.r11,
                r10: state.r10,
                r9: state.r9,
                r8: state.r8,
                rax,
                rcx: state.rcx,
                rdx: state.rdx,
                rsi: state.rsi,
                rdi: state.rdi,
                orig_rax,
                rip: state.rip,
                cs: 0x2b,
                eflags: state.rflags,
                rsp: state.rsp,
                ss: 0x23,
                fs_base,
                gs_base: 0,
                ds: 0,
                es: 0,
                fs: 0,
                gs: 0,
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            user_regs_struct {
                regs: state.x,
                sp: state.sp,
                pc: state.pc,
                pstate: state.spsr,
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            user_regs_struct {
                regs: state.x,
                sp: state.sp,
                pc: state.pc,
                pstate: state.spsr,
            }
        }
    })
}

fn set_tracee_regs(pid: u64, regs: user_regs_struct) -> bool {
    #[cfg(target_arch = "x86_64")]
    let seccomp_event_stop = {
        let g = PTRACE_STATE.lock();
        g.as_ref().is_some_and(|r| {
            r.stop_signal.get(&pid).copied()
                == Some(SIGTRAP_EVENT_BASE | (PTRACE_EVENT_SECCOMP << 8))
        })
    };
    let tid = pid_to_tid(pid);
    crate::user_task::with_user_task_ctx(tid, |uctx| {
        // SAFETY: tracee is registered and stopped, so its state pointer is valid and stable.
        let state = unsafe { &mut *uctx.state.get() };
        #[cfg(target_arch = "x86_64")]
        {
            state.r15 = regs.r15;
            state.r14 = regs.r14;
            state.r13 = regs.r13;
            state.r12 = regs.r12;
            state.rbp = regs.rbp;
            state.rbx = regs.rbx;
            state.r11 = regs.r11;
            state.r10 = regs.r10;
            state.r9 = regs.r9;
            state.r8 = regs.r8;
            // At a seccomp event stop Linux lets the tracer replace the
            // pending syscall through orig_rax. Preserve the normal rax path
            // for all other stops; a signal-stop's orig_rax is descriptive,
            // not a second writable register.
            state.rax = if seccomp_event_stop {
                regs.orig_rax
            } else {
                regs.rax
            };
            state.rcx = regs.rcx;
            state.rdx = regs.rdx;
            state.rsi = regs.rsi;
            state.rdi = regs.rdi;
            state.rip = regs.rip;
            state.rflags = regs.eflags;
            state.rsp = regs.rsp;
            uctx.pending_fs_base.store(regs.fs_base, Ordering::Release);
        }
        #[cfg(target_arch = "aarch64")]
        {
            state.x = regs.regs;
            state.sp = regs.sp;
            state.pc = regs.pc;
            state.spsr = regs.pstate;
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            state.x = regs.regs;
            state.sp = regs.sp;
            state.pc = regs.pc;
            state.spsr = regs.pstate;
        }
    })
    .is_some()
}

fn enable_tracee_singlestep(pid: u64) {
    let tid = pid_to_tid(pid);
    crate::user_task::with_user_task_ctx(tid, |uctx| {
        // SAFETY: tracee is registered and stopped, so its state pointer is valid and stable.
        let state = unsafe { &mut *uctx.state.get() };
        #[cfg(target_arch = "x86_64")]
        {
            state.rflags |= 1 << 8;
        }
        #[cfg(target_arch = "aarch64")]
        {
            state.spsr |= 1 << 21;
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = state;
        }
    });
}

fn bytes_of<T>(val: &T) -> &[u8] {
    // SAFETY: val is a valid reference; reinterpret its bytes read-only.
    unsafe { core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>()) }
}

fn bytes_of_mut<T>(val: &mut T) -> &mut [u8] {
    // SAFETY: val is a valid mutable reference; reinterpret its bytes.
    unsafe { core::slice::from_raw_parts_mut(val as *mut T as *mut u8, core::mem::size_of::<T>()) }
}

unsafe fn slice_from_ref<T>(val: &T) -> &[u8] {
    // SAFETY: val is a valid reference, and size matches.
    unsafe { core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>()) }
}

unsafe fn slice_from_ref_mut<T>(val: &mut T) -> &mut [u8] {
    // SAFETY: val is a valid mutable reference, and size matches.
    unsafe { core::slice::from_raw_parts_mut(val as *mut T as *mut u8, core::mem::size_of::<T>()) }
}

pub fn sys_ptrace(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let request = args.arg0;
    let pid = args.arg1;
    // The pid exactly as userspace wrote it (a `pid_t` in the caller's pid
    // namespace), for the requests that resolve it with find_task_by_vpid.
    let user_pid = args.arg1 as i32;
    let addr = args.arg2;
    let data = args.arg3;

    let caller = current_task_id();
    let caller_pid = tid_to_pid(caller);

    // Every ptrace request except TRACEME names its target by pid, interpreted
    // in the CALLER's pid namespace (Linux resolves it via
    // find_get_task_by_vpid, kernel/ptrace.c). The `tracers` map and every
    // ownership check key on the OUTER/visible pid — `caller_pid` above is
    // `tid_to_pid(caller)`, the outer ProcessId — so the incoming pid MUST be
    // translated inner->outer here. Untranslated, a containerized tracer could
    // PTRACE_ATTACH + PTRACE_POKEDATA a host process (or SEIZE host pid 1) by
    // its inner-namespace number: a containment escape with write primitives.
    // An inner pid not bound in the caller's namespace is ESRCH.
    #[cfg(feature = "container")]
    let pid = if request == PTRACE_TRACEME {
        pid
    } else {
        match crate::pid_ns::resolve_inner_pid(caller, pid) {
            Some(outer) => outer,
            None => {
                ctx.set_return(errno_ret(ESRCH));
                return;
            }
        }
    };

    // `ptrace_check_attach()` runs before request-specific validation.  This
    // is also what makes page-in of a sparse tracee VMA safe: only a stopped
    // tracee can have its inactive page tables changed by the tracer.
    if !matches!(request, PTRACE_TRACEME | PTRACE_ATTACH)
        && !ptrace_check_attach(pid, caller_pid, request == PTRACE_KILL)
    {
        ctx.set_return(errno_ret(ESRCH));
        return;
    }

    match request {
        PTRACE_TRACEME => {
            // `parent_of` stores the parent's TASK id, but the `tracers` map is
            // visible-pid → visible-pid (matching PTRACE_ATTACH's
            // `insert(pid, caller_pid)` and every ownership check, which use
            // `tid_to_pid` visible pids). Storing the raw task id here made all
            // the ownership checks fail with EPERM for a self-traced child.
            let parent_pid = match crate::handlers::parent_of_get(caller_pid) {
                Some(p) => tid_to_pid(p),
                None => {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
            };
            let mut g = PTRACE_STATE.lock();
            if let Some(r) = g.as_mut() {
                // `kernel/ptrace.c::ptrace_traceme` opens with
                // `int ret = -EPERM;` and only `if (!current->ptrace)`
                // clears it — one tracer per process. A genuine EPERM,
                // not the -1 sentinel.
                if r.tracers.contains_key(&caller_pid) {
                    ctx.set_return(errno_ret(EPERM));
                    return;
                }
                PTRACE_TRACEES.fetch_add(1, Ordering::Release);
                r.tracers.insert(caller_pid, parent_pid);
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(errno_ret(ENOSYS));
            }
        }
        PTRACE_ATTACH => {
            // `SYSCALL_DEFINE4(ptrace)` resolves the pid FIRST
            // (`find_get_task_by_vpid` → -ESRCH) and only then calls
            // `ptrace_attach`, so a pid that does not exist outranks every
            // attach-time check below.
            // `find_get_task_by_vpid` finds ANY thread — a non-leader's tid
            // included — and never a raw scheduler TaskId.
            let Some(tid) = crate::handlers::find_task_by_vpid(caller, user_pid)
                .filter(|&t| crate::user_task::with_user_task_ctx(t, |_| ()).is_some())
            else {
                ctx.set_return(errno_ret(ESRCH));
                return;
            };
            // `kernel/ptrace.c::ptrace_attach`:
            //
            //     if (unlikely(task->flags & PF_KTHREAD))
            //             return -EPERM;
            //     if (same_thread_group(task, current))
            //             return -EPERM;
            //
            // Attaching to yourself is EPERM, not EINVAL. EINVAL tells a
            // caller "the request you built is malformed" — a library
            // probing whether it may self-trace (gdb, sanitizers, crash
            // handlers that fork a helper) treats that as a bug in its own
            // argument marshalling, while EPERM correctly says the target
            // is off limits and the probe should fall back.
            // `same_thread_group`, not "same tid": a thread may not trace its
            // own leader or a sibling either.
            if crate::handlers::same_thread_group(tid, caller) {
                ctx.set_return(errno_ret(EPERM));
                return;
            }
            // `ptrace_attach` -> `__ptrace_may_access(task,
            // PTRACE_MODE_ATTACH_REALCREDS)`. Nothing here asked whose
            // process the target was, so any task could attach to any other
            // and then `PTRACE_POKEDATA` into it — a write primitive into a
            // more privileged process. The REALCREDS mode is why the check
            // compares the caller's REAL uid: this is a syscall that
            // explicitly names another process, not a filesystem access.
            if !crate::handlers::ptrace_may_access(caller, tid) {
                ctx.set_return(errno_ret(EPERM));
                return;
            }
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    // `ptrace_attach`: `if (task->ptrace) return -EPERM;`
                    // — a process can have only ONE tracer. A genuine
                    // EPERM, not the -1 sentinel.
                    if r.tracers.contains_key(&pid) {
                        ctx.set_return(errno_ret(EPERM));
                        return;
                    }
                    PTRACE_TRACEES.fetch_add(1, Ordering::Release);
                    r.tracers.insert(pid, caller_pid);
                } else {
                    ctx.set_return(errno_ret(ENOSYS));
                    return;
                }
            }
            raise_signal_pending(tid, 19); // SIGSTOP
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_DETACH => {
            let mut g = PTRACE_STATE.lock();
            if let Some(r) = g.as_mut() {
                if r.tracers.get(&pid).copied() != Some(caller_pid) {
                    // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                    ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                    return;
                }
                // `kernel/ptrace.c::ptrace_detach`:
                //
                //     static int ptrace_detach(struct task_struct *child,
                //                              unsigned int data)
                //     {
                //             if (!valid_signal(data))
                //                     return -EIO;
                //
                // `data` names the signal to deliver as the tracee
                // resumes. Note the parameter WIDTH: `unsigned int`, so
                // only the low 32 bits are examined — 0x1_0000_0000
                // detaches with signal 0 instead of failing.
                // valid_signal() is `sig <= _NSIG` (64).
                //
                // A tracer that passes a bad signal must learn its detach
                // did NOT happen; returning 0 would leave it believing the
                // tracee was released while it is still stopped and still
                // attached, and its next waitpid would hang.
                if (data as u32) as u64 > 64 {
                    ctx.set_return(errno_ret(EIO));
                    return;
                }
                if r.tracers.remove(&pid).is_some() {
                    PTRACE_TRACEES.fetch_sub(1, Ordering::Release);
                }
                forget_tracee_state(r, pid);
            }
            let tid = pid_to_tid(pid);
            // As for a resume: a tracee parked on the stop's infinite
            // deadline (or born stopped and never run) must not stay parked.
            crate::user_task::with_user_task_ctx(tid, |uc| {
                uc.sleep_deadline_ns.store(0, Ordering::Release);
            });
            crate::handlers::wake_signal(tid);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            // `kernel/ptrace.c::generic_ptrace_peekdata`:
            //
            //     copied = ptrace_access_vm(tsk, addr, &tmp,
            //                               sizeof(tmp), FOLL_FORCE);
            //     if (copied != sizeof(tmp))
            //             return -EIO;
            //     return put_user(tmp, (unsigned long __user *)data);
            //
            // The word goes to the TRACER's `*data` and the syscall itself
            // returns 0 (libc's ptrace() wrapper passes `&ret` as `data` and
            // returns that). An address the TRACEE has not mapped is EIO,
            // not EFAULT — EFAULT would accuse the tracer of passing a bad
            // pointer of its own; gdb's unwinder keys on EIO to mean "that
            // address isn't there". Only the write-back to `data` is EFAULT.
            //
            // The bytes come from the tracee's region table through
            // `access_remote` — never from a walk of its page-table leaves,
            // which (a) named the 4 KiB frame without the in-page offset,
            // so every byte of the word read the page's first byte, and (b)
            // cannot see a PROT_NONE page's data at all.
            let tid = pid_to_tid(pid);
            let mut word = [0u8; core::mem::size_of::<u64>()];
            let copied =
                crate::handlers::ptrace_access_vm(caller, tid, addr, RemoteBuf::Read(&mut word));
            if copied != word.len() {
                ctx.set_return(errno_ret(EIO));
                return;
            }
            // SAFETY: `data` is the tracer's user pointer; copy_to_user
            // range-validates it and contains a fault.
            if unsafe { copy_to_user(data, &word) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            // `kernel/ptrace.c::generic_ptrace_pokedata`:
            //
            //     copied = ptrace_access_vm(tsk, addr, &data, sizeof(data),
            //                               FOLL_FORCE | FOLL_WRITE);
            //     return (copied == sizeof(data)) ? 0 : -EIO;
            //
            // FOLL_FORCE lets a breakpoint land in read-only text; the write
            // breaks COW in the tracee only, so neither a fork sibling still
            // sharing the frame nor the file behind the mapping sees it. A
            // word crossing into an unwritable page is written up to that
            // page and still reports EIO, as Linux's short copy does.
            let tid = pid_to_tid(pid);
            let bytes = data.to_ne_bytes();
            let copied =
                crate::handlers::ptrace_access_vm(caller, tid, addr, RemoteBuf::Write(&bytes));
            if copied == bytes.len() {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(errno_ret(EIO));
            }
        }
        PTRACE_GETREGS => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            let regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(errno_ret(ESRCH));
                    return;
                }
            };
            // SAFETY: data is a user pointer, range-checked by copy_to_user.
            if unsafe { copy_to_user(data, slice_from_ref(&regs)) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        PTRACE_SETREGS => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            let mut regs = user_regs_struct::default();
            // SAFETY: data is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(slice_from_ref_mut(&mut regs), data) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            if set_tracee_regs(pid, regs) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(errno_ret(ESRCH));
            }
        }
        PTRACE_CONT | PTRACE_SINGLESTEP | PTRACE_SYSCALL => {
            // The stop's own signal and its dequeued payload, for an injection
            // of that same signal below.
            let mut stopped_with: Option<(u32, Option<StopPayload>)> = None;
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                    // `kernel/ptrace.c::ptrace_resume`:
                    //
                    //     if (!valid_signal(data))
                    //             return -EIO;
                    //
                    // `valid_signal()` is `sig <= _NSIG` (64). This runs
                    // before the tracee is woken, so a bad signal number
                    // leaves the tracee stopped — the tracer must learn
                    // that from the errno. Returning 0 while quietly
                    // dropping the signal (what this arm did for anything
                    // >= 32) tells a tracer its SIGCONT/SIGTERM injection
                    // succeeded when nothing was delivered.
                    if data > 64 {
                        ctx.set_return(errno_ret(EIO));
                        return;
                    }
                    r.stopped.remove(&pid);
                    if let Some(sig) = r.stop_signal.remove(&pid) {
                        stopped_with = Some((sig, r.stop_payload.remove(&pid)));
                    }
                    // The tracee is leaving the stop: the exit-stop's pinned
                    // orig_rax was there only for the tracer's GETREGS while
                    // stopped, so drop it now (state.rax resumes as truth).
                    r.orig_rax.remove(&pid);
                    r.stop_rax.remove(&pid);
                    r.last_siginfo.remove(&pid);
                    // PTRACE_SYSCALL arms a stop at the next syscall boundary.
                    // The syscall-stop hook (ptrace_syscall_stop) toggles this
                    // Entry → Exit → None; whichever phase is pending now is
                    // re-armed here so the tracee stops at that boundary next.
                    // PTRACE_CONT/SINGLESTEP clear syscall tracing entirely.
                    if request == PTRACE_SYSCALL {
                        let next = match r
                            .syscall_stop
                            .get(&pid)
                            .copied()
                            .unwrap_or(SyscallStopPhase::None)
                        {
                            // Mid-syscall (stopped at entry) → stop at the exit.
                            SyscallStopPhase::Exit => SyscallStopPhase::Exit,
                            // At an exit stop or freshly resumed → stop at the
                            // next entry.
                            _ => SyscallStopPhase::Entry,
                        };
                        r.syscall_stop.insert(pid, next);
                    } else {
                        r.syscall_stop.remove(&pid);
                    }
                }
            }
            if request == PTRACE_SINGLESTEP {
                enable_tracee_singlestep(pid);
            }
            let tid = pid_to_tid(pid);
            if data != 0 {
                // `ptrace_signal`: resuming with the stop's own signal delivers
                // it with its original siginfo (a sigqueue value, SIGCHLD's
                // status); any other signal is a new one from the tracer.
                if let Some((sig, Some((code, value, sender)))) = stopped_with {
                    if sig == data as u32 {
                        let _ = crate::handlers::store_sigqueue_info(tid, sig, code, value, sender);
                    }
                }
                set_ptrace_signal_bypass(pid, data as u32);
                raise_signal_pending(tid, data as u32);
            }
            // Clear the tracee's infinite park deadline as well as waking it.
            // `wake_signal` alone is a nudge: if the tracee has not reached its
            // park loop yet there is no waker registered to receive it, and it
            // would then park on the u64::MAX deadline the stop armed with
            // nobody left to wake it. Zeroing the deadline makes the resume
            // durable — `park_should_block` sees a park with no deadline and
            // declines to block.
            crate::user_task::with_user_task_ctx(tid, |uc| {
                uc.sleep_deadline_ns.store(0, Ordering::Release);
            });
            crate::handlers::wake_signal(tid);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_SETOPTIONS => {
            // `check_ptrace_options`, PTRACE_O_SUSPEND_SECCOMP arm (after the
            // mask test below): CAP_SYS_ADMIN, and a tracer that is neither
            // under seccomp itself nor suspended-from-it by its own tracer —
            // otherwise a sandboxed task could lift its children's filters.
            // Evaluated before PTRACE_STATE is taken: it reads other tables.
            let suspend_seccomp_refusal = if data & PTRACE_O_SUSPEND_SECCOMP != 0 {
                const CAP_SYS_ADMIN: u32 = 21;
                if !crate::handlers::capable(CAP_SYS_ADMIN)
                    || crate::seccomp::mode_of(caller) != 0
                    || ptrace_options(caller_pid) & PTRACE_O_SUSPEND_SECCOMP != 0
                {
                    Some(EPERM)
                } else {
                    None
                }
            } else {
                None
            };
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                    // `kernel/ptrace.c::check_ptrace_options`, reached via
                    // `ptrace_setoptions`:
                    //
                    //     if (data & ~(unsigned long)PTRACE_O_MASK)
                    //             return -EINVAL;
                    //
                    // Storing a bit OUTSIDE PTRACE_O_MASK and answering 0
                    // is the silent kind of divergence: PTRACE_SETOPTIONS
                    // is how a tracer feature-probes: it sets the bit it
                    // wants and reads the errno. Told "accepted" for a
                    // PTRACE_O_* this kernel has never heard of, it stops
                    // arranging a fallback and then waits forever for a
                    // stop that will never be reported. EINVAL — the same
                    // answer a real kernel too old for that option gives —
                    // keeps the probe honest.
                    //
                    // Every bit inside the mask is acted on: TRACESYSGOOD,
                    // TRACEEXEC, TRACEFORK/VFORK/CLONE (auto-attach plus the
                    // event stop — `attach_new_child`), TRACEVFORKDONE,
                    // TRACEEXIT, TRACESECCOMP, EXITKILL and SUSPEND_SECCOMP.
                    if data & !PTRACE_O_MASK != 0 {
                        ctx.set_return(errno_ret(EINVAL));
                        return;
                    }
                    if let Some(e) = suspend_seccomp_refusal {
                        ctx.set_return(errno_ret(e));
                        return;
                    }
                    r.options.insert(pid, data);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_GETEVENTMSG => {
            // `ptrace_request`:
            //
            //     case PTRACE_GETEVENTMSG:
            //             ret = put_user(child->ptrace_message, datalp);
            //
            // The message of the last event stop (a new child's pid, an exit
            // status, a seccomp filter's data); 0 if there never was one.
            let msg = PTRACE_STATE
                .lock()
                .as_ref()
                .and_then(|r| r.event_msg.get(&pid).copied())
                .unwrap_or(0);
            // SAFETY: `data` is the tracer's user pointer; copy_to_user
            // range-checks it and contains a fault.
            if unsafe { copy_to_user(data, &msg.to_ne_bytes()) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        PTRACE_GETSIGINFO => {
            // `ptrace_getsiginfo`: EINVAL when the stop has no siginfo (a
            // group-stop), then `copy_siginfo_to_user` → EFAULT.
            let info = PTRACE_STATE
                .lock()
                .as_ref()
                .and_then(|r| r.last_siginfo.get(&pid).copied());
            let Some(info) = info else {
                ctx.set_return(errno_ret(EINVAL));
                return;
            };
            // SAFETY: as above.
            if unsafe { copy_to_user(data, &info) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        PTRACE_GETREGSET => {
            // addr = regset id (NT_PRSTATUS / x86 NT_PRFPREG); data = iovec*
            // {base, len}.
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            // `kernel/ptrace.c::ptrace_request`, case PTRACE_GETREGSET:
            //
            //     if (!access_ok(uiov, sizeof(*uiov)))
            //             return -EFAULT;
            //     if (__get_user(kiov.iov_base, &uiov->iov_base) ||
            //         __get_user(kiov.iov_len, &uiov->iov_len))
            //             return -EFAULT;
            //     ret = ptrace_regset(child, request, addr, &kiov);
            //
            // ORDER: the iovec is read BEFORE `ptrace_regset` looks at the
            // regset id, so a faulting iovec beats an unknown regset. A
            // tool that feature-probes regsets (CRIU asks for NT_X86_XSTATE
            // and friends) must be able to tell "this kernel has no such
            // regset" (EINVAL) from "I handed you a bad iovec" (EFAULT);
            // checking the id first reports EINVAL for both and makes it
            // silently skip a regset it should have retried.
            //
            // Read the caller's iovec (two u64s: iov_base, iov_len).
            let mut iov = [0u64; 2];
            // SAFETY: `data` is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(bytes_of_mut(&mut iov), data) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            // WIDTH: `ptrace_regset(struct task_struct *task, int req,
            // unsigned int type, struct iovec *kiov)` takes the regset id
            // as `unsigned int`, so only the low 32 bits of `addr` select
            // it — supported regsets with junk in the high half still resolve.
            // `ptrace_regset` returns EINVAL when `find_regset` misses.
            match addr as u32 as u64 {
                NT_PRSTATUS => {
                    let regs = match get_tracee_regs(pid) {
                        Some(r) => r,
                        None => {
                            ctx.set_return(errno_ret(ESRCH));
                            return;
                        }
                    };
                    let full = core::mem::size_of::<user_regs_struct>();
                    let n = core::cmp::min(iov[1] as usize, full);
                    // SAFETY: regs is a valid stack value; slice its first `n` bytes.
                    let src = unsafe { slice_from_ref(&regs) };
                    // SAFETY: iov[0] is a user pointer, range-checked by copy_to_user.
                    if iov[0] != 0 && unsafe { copy_to_user(iov[0], &src[..n]) }.is_err() {
                        ctx.set_return(errno_ret(EFAULT));
                        return;
                    }
                    // Report the number of bytes actually written back in iov_len.
                    iov[1] = n as u64;
                }
                #[cfg(target_arch = "x86_64")]
                NT_PRFPREG => {
                    // Keep the same liveness/error contract as PRSTATUS.
                    // The process is ptrace-stopped at this point, so its
                    // saved FPU image is authoritative rather than live CPU
                    // register state.
                    if get_tracee_regs(pid).is_none() {
                        ctx.set_return(errno_ret(ESRCH));
                        return;
                    }
                    let regs = crate::user_task::ptrace_legacy_fpu(pid_to_tid(pid));
                    let n = core::cmp::min(iov[1] as usize, regs.len());
                    // SAFETY: iov[0] is a user pointer, range-checked by copy_to_user.
                    if iov[0] != 0 && unsafe { copy_to_user(iov[0], &regs[..n]) }.is_err() {
                        ctx.set_return(errno_ret(EFAULT));
                        return;
                    }
                    iov[1] = n as u64;
                }
                _ => {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
            }
            // SAFETY: `data` is a user pointer, range-checked by copy_to_user.
            let _ = unsafe { copy_to_user(data, bytes_of(&iov)) };
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_SETREGSET => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            // Same order as PTRACE_GETREGSET above: `ptrace_request`
            // faults on the iovec first, `ptrace_regset` validates the
            // regset id second.
            let mut iov = [0u64; 2];
            // SAFETY: `data` is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(bytes_of_mut(&mut iov), data) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            // WIDTH: the regset id is `unsigned int` in `ptrace_regset`.
            if addr as u32 as u64 != NT_PRSTATUS {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
            // `ptrace_regset`: `if (!regset || (kiov->iov_len %
            // regset->size) != 0) return -EINVAL;`
            //
            // LINUX-GAP: Linux only requires the length to be a multiple of
            // the register size (8) and then clamps it, so a partial
            // SETREGSET writes the leading registers; NARF has no partial
            // path and requires the whole struct. The errno for a rejected
            // length is EINVAL either way.
            let full = core::mem::size_of::<user_regs_struct>();
            if (iov[1] as usize) < full {
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
            let mut regs = user_regs_struct::default();
            // SAFETY: iov[0] is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(slice_from_ref_mut(&mut regs), iov[0]) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            if set_tracee_regs(pid, regs) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(errno_ret(ESRCH));
            }
        }
        PTRACE_PEEKUSER => {
            // addr = byte offset into user_regs_struct (index*8).
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            // `arch/x86/kernel/ptrace.c::arch_ptrace`, case PTRACE_PEEKUSR:
            //
            //     ret = -EIO;
            //     if ((addr & (sizeof(data) - 1)) ||
            //         addr >= sizeof(struct user))
            //             break;
            //
            // A misaligned or out-of-range USER-area offset is EIO, not
            // EFAULT: `addr` is an offset into a kernel-side struct, not a
            // pointer, so there is no fault to report. libthread_db and
            // gdb probe this offset space to discover which registers a
            // kernel exposes, and they read EIO as "no such register"
            // while EFAULT looks like a broken tracer buffer.
            //
            // ORDER: this guard sits at the top of arch_ptrace's case, so
            // the offset is rejected before the tracee's saved registers
            // are even fetched.
            //
            // LINUX-GAP: Linux bounds this by `sizeof(struct user)` (which
            // also covers u_debugreg and the a.out header fields) and
            // returns 0 for in-range offsets past user_regs_struct; NARF
            // only models user_regs_struct, so those offsets are EIO here.
            let nregs = core::mem::size_of::<user_regs_struct>() / 8;
            let idx = (addr as usize) / 8;
            if addr % 8 != 0 || idx >= nregs {
                ctx.set_return(errno_ret(EIO));
                return;
            }
            let regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(errno_ret(ESRCH));
                    return;
                }
            };
            // SAFETY: idx is in bounds of the [u64; nregs]-shaped regs struct.
            let val = unsafe { *(&regs as *const user_regs_struct as *const u64).add(idx) };
            // PEEKUSER returns the word as the syscall value; glibc/musl also
            // accept it written to `data` (PTRACE_PEEK* variant), so mirror it.
            // SAFETY: `data` is a user pointer, range-checked by copy_to_user.
            if data != 0 && unsafe { copy_to_user(data, &val.to_ne_bytes()) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            ctx.set_return(SyscallReturn::ok(val));
        }
        PTRACE_POKEUSER => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        // ESRCH, not EPERM: see `ESRCH_NOT_TRACER`.
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            // `arch/x86/kernel/ptrace.c::arch_ptrace`, case PTRACE_POKEUSR,
            // uses the identical `ret = -EIO;` guard as PEEKUSR above:
            //
            //     if ((addr & (sizeof(data) - 1)) ||
            //         addr >= sizeof(struct user))
            //             break;
            let nregs = core::mem::size_of::<user_regs_struct>() / 8;
            let idx = (addr as usize) / 8;
            if addr % 8 != 0 || idx >= nregs {
                ctx.set_return(errno_ret(EIO));
                return;
            }
            let mut regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(errno_ret(ESRCH));
                    return;
                }
            };
            // SAFETY: idx is in bounds of the [u64; nregs]-shaped regs struct.
            unsafe { *(&mut regs as *mut user_regs_struct as *mut u64).add(idx) = data };
            if set_tracee_regs(pid, regs) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(errno_ret(ESRCH));
            }
        }
        PTRACE_KILL => {
            // `SYSCALL_DEFINE4(ptrace)` still runs
            //
            //     ret = ptrace_check_attach(child, request == PTRACE_KILL ||
            //                               request == PTRACE_INTERRUPT);
            //
            // for PTRACE_KILL — `ignore_state` only waives the "must be in
            // TASK_TRACED" half; `child->ptrace && child->parent ==
            // current` is still required, and failing it is ESRCH. Without
            // this check any process could SIGKILL any pid through
            // ptrace(2), and a tracer whose tracee has already exited would
            // be told the kill "worked".
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            let tid = pid_to_tid(pid);
            // Clear the ptrace-stop so the parked tracee actually RESUMES (as
            // PTRACE_CONT does) and then terminates on the pending SIGKILL it
            // wakes into. Without dropping the stop + waking, the tracee stays
            // parked in own_stack_block forever and the tracer's waitpid never
            // reaps it.
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    r.stopped.remove(&pid);
                    r.stop_signal.remove(&pid);
                    r.syscall_stop.remove(&pid);
                    r.stop_rax.remove(&pid);
                    r.last_siginfo.remove(&pid);
                    r.stop_rax.remove(&pid);
                }
            }
            raise_signal_pending(tid, 9); // SIGKILL
            crate::handlers::wake_signal(tid);
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => {
            // ORDER: `ptrace_check_attach` has already run by the time an
            // unknown request reaches `ptrace_request`, so "not my tracee"
            // (ESRCH) outranks "no such request" (EIO).
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok(ESRCH_NOT_TRACER));
                        return;
                    }
                }
            }
            // `kernel/ptrace.c::ptrace_request` opens with `int ret =
            // -EIO;` and its `default:` label only `break`s, so an
            // unrecognised request code returns EIO.
            //
            // ENOSYS (what this arm returned) is a different claim: glibc
            // renders it "Function not implemented", so a tracer probing
            // for an optional request — PTRACE_GETSIGINFO, PTRACE_SEIZE,
            // PTRACE_GET_SYSCALL_INFO — concludes that ptrace(2) itself is
            // missing and disables tracing wholesale, instead of falling
            // back to the requests this kernel does implement.
            ctx.set_return(errno_ret(EIO));
        }
    }
}
