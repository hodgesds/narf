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
    if let Some(tracer) = get_task_tracer(child_pid) {
        Some(tracer)
    } else {
        crate::handlers::parent_of_get(child_pid)
    }
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

pub fn ptrace_intercept_signal(ctx: &mut dyn TrapContext, signum: u32) -> bool {
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

pub fn enter_ptrace_stopped(ctx: &mut dyn TrapContext, task: u64, _tracer: u64, signum: u32) {
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
            ctx.set_return(SyscallReturn::ok(0));
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
    crate::user_task::with_user_task_ctx(tid, |uctx| {
        // SAFETY: tracee is registered and stopped, so its state pointer is valid and stable.
        let state = unsafe { *uctx.state.get() };

        #[cfg(target_arch = "x86_64")]
        {
            let fs_base = uctx.pending_fs_base.load(Ordering::Acquire);
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
                orig_rax: state.rax,
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

    match request {
        PTRACE_TRACEME => {
            let parent_pid = match crate::handlers::parent_of_get(caller_pid) {
                Some(p) => p,
                None => {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                    return;
                }
            };
            let mut g = PTRACE_STATE.lock();
            if let Some(r) = g.as_mut() {
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
        PTRACE_CONT | PTRACE_SINGLESTEP => {
            {
                let mut g = PTRACE_STATE.lock();
                if let Some(r) = g.as_mut() {
                    if r.tracers.get(&pid).copied() != Some(caller_pid) {
                        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                        return;
                    }
                    r.stopped.remove(&pid);
                    r.stop_signal.remove(&pid);
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
        PTRACE_KILL => {
            let tid = pid_to_tid(pid);
            raise_signal_pending(tid, 9); // SIGKILL
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-38i64) as u64)); // ENOSYS
        }
    }
}
