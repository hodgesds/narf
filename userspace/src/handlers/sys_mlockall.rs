#[allow(unused_imports)]
use super::*;

/// `mlockall(flags)` — atomically replace the address space's future-lock
/// policy and, when MCL_CURRENT is present, lock every existing ordinary VMA.
///
/// `mm/mlock.c::SYSCALL_DEFINE1(mlockall)`:
///
/// ```text
///     SYSCALL_DEFINE1(mlockall, int, flags)
///     if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) ||
///         flags == MCL_ONFAULT)
///             return -EINVAL;
///     if (!can_do_mlock())
///             return -EPERM;
///     ... /* over RLIMIT_MEMLOCK with MCL_CURRENT and no CAP_IPC_LOCK => -ENOMEM */
/// ```
///
/// `flags` is declared **`int`**, so the kernel only ever inspects the low 32
/// bits; the upper half of the register is not part of the request. Reading
/// the whole 64-bit argument made `mlockall(MCL_CURRENT)` fail with EINVAL
/// whenever a caller left garbage in the high half of `rdi` — which a libc
/// wrapper that stores the argument as `int` and sign-/zero-extends
/// inconsistently, or a language runtime marshalling through a `long`, can
/// easily do. EINVAL here reads as "this kernel does not support these
/// MCL_ flags" and makes a runtime disable memory locking wholesale, where
/// EPERM would have told it to ask for privilege instead.
pub(crate) fn sys_mlockall(ctx: &mut dyn TrapContext) {
    const MCL_CURRENT: u32 = 1;
    const MCL_FUTURE: u32 = 2;
    const MCL_ONFAULT: u32 = 4;
    let flags = ctx.args().arg0 as u32;
    if flags == 0
        || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
        || flags & MCL_ONFAULT != 0 && flags & (MCL_CURRENT | MCL_FUTURE) == 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let authority = current_mlock_authority();
    if !can_do_mlock(authority) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let mode = if flags & MCL_ONFAULT != 0 {
        narf_memory::FutureLockPolicy::OnFault
    } else {
        narf_memory::FutureLockPolicy::Eager
    };
    let current = (flags & MCL_CURRENT != 0).then_some(mode);
    let future = if flags & MCL_FUTURE != 0 {
        mode
    } else {
        narf_memory::FutureLockPolicy::None
    };
    match as_ref.update_mlockall_limited(
        current,
        future,
        authority.limit_bytes,
        authority.bypass_limit,
    ) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(error) => ctx.set_return(SyscallReturn::ok(
            (-super::handler_sys_mlock::mlock_errno(error)) as u64,
        )),
    }
}
