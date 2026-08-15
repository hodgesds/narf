//! Ptrace syscall implementation.
//! Linux-compatible ptrace(2) interface.

use crate::handlers::{
    clear_pending_signal_bits, copy_from_user, copy_to_user, current_task_id, push_stopcont_report,
    raise_signal_pending,
};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{paging::translate, VirtAddr};
use narf_scheduler::address_space_of;

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
pub const PTRACE_GETREGSET: u64 = 0x4204;
pub const PTRACE_SETREGSET: u64 = 0x4205;

/// `NT_PRSTATUS` regset id used with PTRACE_GETREGSET/SETREGSET; the
/// payload is a `user_regs_struct`.
pub const NT_PRSTATUS: u64 = 1;

/// PTRACE_O_TRACESYSGOOD: OR 0x80 into the SIGTRAP stop signal at a
/// syscall-stop so the tracer can distinguish it from an ordinary
/// SIGTRAP.
pub const PTRACE_O_TRACESYSGOOD: u64 = 1;

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

#[derive(Debug, Default)]
pub struct PtraceRegistry {
    /// Maps tracee Process ID -> tracer Process ID
    pub tracers: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> whether the tracee is stopped for ptrace
    pub stopped: BTreeMap<u64, bool>,
    /// Maps tracee Process ID -> signal that stopped the tracee
    pub stop_signal: BTreeMap<u64, u32>,
    /// Maps tracee Process ID -> signal bypass mask (signal number -> bypass)
    pub signal_bypass: BTreeMap<u64, u32>,
    /// Maps tracee Process ID -> next syscall-stop phase (PTRACE_SYSCALL).
    pub syscall_stop: BTreeMap<u64, SyscallStopPhase>,
    /// Maps tracee Process ID -> PTRACE_SETOPTIONS bitset (TRACESYSGOOD, ...).
    pub options: BTreeMap<u64, u64>,
    /// Maps tracee Process ID -> orig_rax captured at the last syscall
    /// ENTRY-stop, so the matching EXIT-stop reports the syscall number
    /// (state.rax holds the return value by then, not the number).
    pub orig_rax: BTreeMap<u64, u64>,
}

pub static PTRACE_STATE: IrqSafeSpinLock<Option<PtraceRegistry>> = IrqSafeSpinLock::new(None);

fn pid_to_tid(pid: u64) -> u64 {
    crate::handlers::pid_to_task_raw(pid).unwrap_or(pid)
}

fn tid_to_pid(tid: u64) -> u64 {
    crate::handlers::task_to_pid_raw(tid).unwrap_or(tid)
}

pub fn ptrace_init() {
    *PTRACE_STATE.lock() = Some(PtraceRegistry::default());
}

/// Retire every ptrace row owned by an exiting process.
///
/// PIDs are recycled, so leaving a dead tracee in `tracers` makes the next
/// owner of that PID look already traced and turns PTRACE_TRACEME into EPERM.
/// If the exiting process was itself a tracer, detach and wake its tracees so
/// they do not remain parked forever.
pub(crate) fn release_process(pid: u64) {
    let detached = {
        let mut g = PTRACE_STATE.lock();
        let Some(r) = g.as_mut() else {
            return;
        };

        r.tracers.remove(&pid);
        r.stopped.remove(&pid);
        r.stop_signal.remove(&pid);
        r.signal_bypass.remove(&pid);
        r.syscall_stop.remove(&pid);
        r.options.remove(&pid);
        r.orig_rax.remove(&pid);

        let tracees: alloc::vec::Vec<u64> = r
            .tracers
            .iter()
            .filter_map(|(&tracee, &tracer)| (tracer == pid).then_some(tracee))
            .collect();
        for tracee in &tracees {
            r.tracers.remove(tracee);
            r.stopped.remove(tracee);
            r.stop_signal.remove(tracee);
            r.signal_bypass.remove(tracee);
            r.syscall_stop.remove(tracee);
            r.options.remove(tracee);
            r.orig_rax.remove(tracee);
        }
        tracees
    };

    for tracee in detached {
        crate::handlers::wake_signal(pid_to_tid(tracee));
    }
}

pub fn get_task_tracer(child_pid: u64) -> Option<u64> {
    let g = PTRACE_STATE.lock();
    g.as_ref()?.tracers.get(&child_pid).copied()
}

pub fn is_task_traced(child_pid: u64) -> bool {
    get_task_tracer(child_pid).is_some()
}

pub fn is_task_ptrace_stopped(task_id: u64) -> bool {
    let g = PTRACE_STATE.lock();
    let pid = tid_to_pid(task_id);
    g.as_ref()
        .and_then(|r| r.stopped.get(&pid).copied())
        .unwrap_or(false)
}

pub fn is_tracer_of_any(tracer_pid: u64, want: i64) -> bool {
    let g = PTRACE_STATE.lock();
    let r = match g.as_ref() {
        Some(r) => r,
        None => return false,
    };
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

pub fn is_ptrace_signal_bypass(child_pid: u64, signum: u32) -> bool {
    let g = PTRACE_STATE.lock();
    if let Some(r) = g.as_ref() {
        if let Some(&mask) = r.signal_bypass.get(&child_pid) {
            // The bypass map is a u32; the setter only stores standard
            // signals (data < 32), so a >= 32 signum can never have an
            // entry — return false instead of a `1u32 << 64` shift UB
            // (now reachable since RT signals raise signum up to 64).
            return signum < 32 && (mask & (1u32 << signum)) != 0;
        }
    }
    false
}

pub fn clear_ptrace_signal_bypass(child_pid: u64, signum: u32) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        if let Some(mask) = r.signal_bypass.get_mut(&child_pid) {
            if signum < 32 {
                *mask &= !(1u32 << signum);
            }
        }
    }
}

pub fn set_ptrace_signal_bypass(child_pid: u64, signum: u32) {
    let mut g = PTRACE_STATE.lock();
    if let Some(r) = g.as_mut() {
        let mask = r.signal_bypass.entry(child_pid).or_insert(0);
        *mask |= 1 << signum;
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
pub fn ptrace_syscall_stop(ctx: &mut dyn TrapContext, at_entry: bool, orig_rax: u64) {
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
        // Advance to the exit phase; PTRACE_SYSCALL from the tracer
        // re-arms whichever phase comes next when it resumes us.
        set_syscall_stop_phase(pid, SyscallStopPhase::Exit);
    } else {
        if phase != SyscallStopPhase::Exit {
            return;
        }
        // Pin the syscall number so the tracer's GETREGS at the exit-stop
        // reports orig_rax as the nr (state.rax now holds the return value).
        // Cleared by the resume path (PTRACE_SYSCALL/CONT).
        save_orig_rax(pid, orig_rax);
        // Consumed on this exit stop.
        set_syscall_stop_phase(pid, SyscallStopPhase::None);
    }
    let sig = syscall_stop_signal(pid);
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

        // Clear the pending bit so we don't process it again (it's intercepted)
        clear_pending_signal_bits(task, crate::handlers::sig_bit(signum));

        let tracer_tid = pid_to_tid(tracer_pid);
        // Put the task into ptrace stop!
        enter_ptrace_stopped(ctx, task, tracer_tid, signum);
        true
    } else {
        false
    }
}

pub fn enter_ptrace_stopped(ctx: &mut dyn TrapContext, task: u64, tracer: u64, signum: u32) {
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
    // Notify tracer via push_stopcont_report
    // Linux wstatus for stopped tracee: (signum << 8) | 0x7f
    let wstatus = ((signum as i32) << 8) | 0x7f;
    push_stopcont_report(task, wstatus, false);

    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
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
    crate::user_task::with_user_task_ctx(tid, |uctx| {
        // SAFETY: tracee is registered and stopped, so its state pointer is valid and stable.
        let state = unsafe { *uctx.state.get() };

        #[cfg(target_arch = "x86_64")]
        {
            let fs_base = uctx.pending_fs_base.load(Ordering::Acquire);
            let orig_rax = orig_rax_pin.unwrap_or(state.rax);
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
                rax: state.rax,
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
            state.rax = regs.rax;
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
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    };

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
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                    return;
                }
            };
            let mut g = PTRACE_STATE.lock();
            if let Some(r) = g.as_mut() {
                // One tracer per process (Linux: EPERM if already traced).
                if r.tracers.contains_key(&caller_pid) {
                    ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                    return;
                }
                r.tracers.insert(caller_pid, parent_pid);
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(SyscallReturn::ok((-38i64) as u64)); // ENOSYS
            }
        }
        PTRACE_ATTACH => {
            if pid == caller_pid {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            let tid = pid_to_tid(pid);
            let has_task = crate::user_task::with_user_task_ctx(tid, |_| ()).is_some();
            if !has_task {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    // A process can have only ONE tracer (Linux: EPERM to
                    // attach to an already-traced tracee).
                    if r.tracers.contains_key(&pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                    r.tracers.insert(pid, caller_pid);
                } else {
                    ctx.set_return(SyscallReturn::ok((-38i64) as u64)); // ENOSYS
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
                    ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                    return;
                }
                r.tracers.remove(&pid);
                r.stopped.remove(&pid);
                r.stop_signal.remove(&pid);
                r.signal_bypass.remove(&pid);
                r.syscall_stop.remove(&pid);
                r.options.remove(&pid);
                r.orig_rax.remove(&pid);
            }
            let tid = pid_to_tid(pid);
            crate::handlers::wake_signal(tid);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            let tid = pid_to_tid(pid);
            let target_as = match address_space_of(narf_scheduler::TaskId(tid)) {
                Some(a) => a,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            };
            // SAFETY: paging is initialized and target_as has a valid root.
            let phys = unsafe { translate(target_as.root, VirtAddr::new(addr)) };
            match phys {
                Some(p) => {
                    // SAFETY: p is a valid physical address mapped in the kernel's virtual space.
                    let val = unsafe { *p.kernel_ptr::<u64>() };
                    // SAFETY: data is a user pointer, checked by copy_to_user.
                    if data != 0 && unsafe { copy_to_user(data, &val.to_ne_bytes()) }.is_err() {
                        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                        return;
                    }
                    ctx.set_return(SyscallReturn::ok(val));
                }
                None => {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                }
            }
        }
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            let tid = pid_to_tid(pid);
            let target_as = match address_space_of(narf_scheduler::TaskId(tid)) {
                Some(a) => a,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            };
            // SAFETY: paging is initialized and target_as has a valid root.
            let phys = unsafe { translate(target_as.root, VirtAddr::new(addr)) };
            match phys {
                Some(p) => {
                    // SAFETY: p is a valid physical address mapped writeable in the kernel's virtual space.
                    unsafe {
                        *p.kernel_mut_ptr::<u64>() = data;
                    }
                    ctx.set_return(SyscallReturn::ok(0));
                }
                None => {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                }
            }
        }
        PTRACE_GETREGS => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            let regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            };
            // SAFETY: data is a user pointer, range-checked by copy_to_user.
            if unsafe { copy_to_user(data, slice_from_ref(&regs)) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        PTRACE_SETREGS => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            let mut regs = user_regs_struct::default();
            // SAFETY: data is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(slice_from_ref_mut(&mut regs), data) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            if set_tracee_regs(pid, regs) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            }
        }
        PTRACE_CONT | PTRACE_SINGLESTEP | PTRACE_SYSCALL => {
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                    r.stopped.remove(&pid);
                    r.stop_signal.remove(&pid);
                    // The tracee is leaving the stop: the exit-stop's pinned
                    // orig_rax was there only for the tracer's GETREGS while
                    // stopped, so drop it now (state.rax resumes as truth).
                    r.orig_rax.remove(&pid);
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
            if data != 0 && data < 32 {
                set_ptrace_signal_bypass(pid, data as u32);
                raise_signal_pending(tid, data as u32);
            }
            crate::handlers::wake_signal(tid);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_SETOPTIONS => {
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                    r.options.insert(pid, data);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_GETREGSET => {
            // addr = regset id (NT_PRSTATUS); data = iovec* {base, len}.
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            if addr != NT_PRSTATUS {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            // Read the caller's iovec (two u64s: iov_base, iov_len).
            let mut iov = [0u64; 2];
            // SAFETY: `data` is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(bytes_of_mut(&mut iov), data) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            let regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            };
            let full = core::mem::size_of::<user_regs_struct>();
            let n = core::cmp::min(iov[1] as usize, full);
            // SAFETY: regs is a valid stack value; slice its first `n` bytes.
            let src = unsafe { slice_from_ref(&regs) };
            // SAFETY: iov[0] is a user pointer, range-checked by copy_to_user.
            if iov[0] != 0 && unsafe { copy_to_user(iov[0], &src[..n]) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            // Report the number of bytes actually written back in iov_len.
            iov[1] = n as u64;
            // SAFETY: `data` is a user pointer, range-checked by copy_to_user.
            let _ = unsafe { copy_to_user(data, bytes_of(&iov)) };
            ctx.set_return(SyscallReturn::ok(0));
        }
        PTRACE_SETREGSET => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            if addr != NT_PRSTATUS {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            let mut iov = [0u64; 2];
            // SAFETY: `data` is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(bytes_of_mut(&mut iov), data) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            let full = core::mem::size_of::<user_regs_struct>();
            if (iov[1] as usize) < full {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            let mut regs = user_regs_struct::default();
            // SAFETY: iov[0] is a user pointer, range-checked by copy_from_user.
            if unsafe { copy_from_user(slice_from_ref_mut(&mut regs), iov[0]) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            if set_tracee_regs(pid, regs) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            }
        }
        PTRACE_PEEKUSER => {
            // addr = byte offset into user_regs_struct (index*8).
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            let regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            };
            let nregs = core::mem::size_of::<user_regs_struct>() / 8;
            let idx = (addr as usize) / 8;
            if addr % 8 != 0 || idx >= nregs {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            // SAFETY: idx is in bounds of the [u64; nregs]-shaped regs struct.
            let val = unsafe { *(&regs as *const user_regs_struct as *const u64).add(idx) };
            // PEEKUSER returns the word as the syscall value; glibc/musl also
            // accept it written to `data` (PTRACE_PEEK* variant), so mirror it.
            // SAFETY: `data` is a user pointer, range-checked by copy_to_user.
            if data != 0 && unsafe { copy_to_user(data, &val.to_ne_bytes()) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            ctx.set_return(SyscallReturn::ok(val));
        }
        PTRACE_POKEUSER => {
            {
                let g = PTRACE_STATE.lock();
                if let Some(r) = g.as_ref() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                }
            }
            let mut regs = match get_tracee_regs(pid) {
                Some(r) => r,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            };
            let nregs = core::mem::size_of::<user_regs_struct>() / 8;
            let idx = (addr as usize) / 8;
            if addr % 8 != 0 || idx >= nregs {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            // SAFETY: idx is in bounds of the [u64; nregs]-shaped regs struct.
            unsafe { *(&mut regs as *mut user_regs_struct as *mut u64).add(idx) = data };
            if set_tracee_regs(pid, regs) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            }
        }
        PTRACE_KILL => {
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
                    r.orig_rax.remove(&pid);
                }
            }
            raise_signal_pending(tid, 9); // SIGKILL
            crate::handlers::wake_signal(tid);
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-38i64) as u64)); // ENOSYS
        }
    }
}
