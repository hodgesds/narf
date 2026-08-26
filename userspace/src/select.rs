//! Linux-compatible `select(2)` and `pselect6(2)`.
//!
//! The kernel ABI is scalable: libc's 1024-bit `fd_set` is not a kernel
//! ceiling. Linux clamps `nfds` to the calling process's current fdtable
//! extent, copies only the required native-word prefix, and leaves the tail
//! of each userspace set untouched.

use alloc::vec::Vec;
use core::mem::size_of;

use crate::handlers::current_task_id;
use crate::poll::{
    complete_kernel_poll_park, poll_wait_kernel, KernelPollWait, PollFd, POLL_ERR, POLL_HUP,
    POLL_IN, POLL_NVAL, POLL_OUT, POLL_PRI,
};
use crate::syscall::{Syscall, SyscallReturn, TrapContext};

/// libc's conventional fd_set size. Kept as public ABI information; raw
/// select syscalls may pass larger bitmaps when the fdtable has grown.
pub const FD_SETSIZE: usize = 1024;
pub const FD_SET_BYTES: usize = FD_SETSIZE / 8;

const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EINTR: i64 = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SelectError {
    BadFd,
    NoMem,
    Fault,
    Invalid,
    Interrupted,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SelectCoreResult {
    Complete(Result<usize, SelectError>),
    Parked,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TimeoutKind {
    Timeval,
    Timespec,
}

#[derive(Copy, Clone, Debug)]
struct ParsedTimeout {
    /// None = infinite; Some(0) = nonblocking; otherwise relative ns.
    duration_ns: Option<u64>,
    user_ptr: u64,
    kind: TimeoutKind,
}

/// Kernel-staged select invocation retained while a task is parked. The type
/// is crate-visible solely so `Task` can own it; select.rs owns all access.
pub(crate) struct SelectParkSnapshot {
    syscall_no: u32,
    task_id: u64,
    set_bytes: usize,
    bits: Vec<u8>,
    items: Vec<PollFd>,
    readfds: Option<*mut u8>,
    writefds: Option<*mut u8>,
    exceptfds: Option<*mut u8>,
    timeout: ParsedTimeout,
    mask_active: bool,
}

// SAFETY: the raw pointers are user virtual addresses, never dereferenced
// without guarded copy helpers. Moving the staged record between scheduler
// CPUs does not change their address-space meaning.
unsafe impl Send for SelectParkSnapshot {}

#[inline]
fn errno(value: i64) -> SyscallReturn {
    SyscallReturn::ok((-value) as u64)
}

#[inline]
fn result_to_return(result: Result<usize, SelectError>) -> SyscallReturn {
    match result {
        Ok(count) => SyscallReturn::ok(count as u64),
        Err(SelectError::BadFd) => errno(EBADF),
        Err(SelectError::NoMem) => errno(ENOMEM),
        Err(SelectError::Fault) => errno(EFAULT),
        Err(SelectError::Invalid) => errno(EINVAL),
        Err(SelectError::Interrupted) => errno(EINTR),
    }
}

#[inline]
fn fd_set_copy_bytes(nfds: usize) -> usize {
    nfds.div_ceil(usize::BITS as usize) * size_of::<usize>()
}

#[inline]
fn bit_is_set(set: &[u8], fd: usize) -> bool {
    set.get(fd / 8)
        .is_some_and(|byte| byte & (1u8 << (fd % 8)) != 0)
}

#[inline]
fn set_bit(set: &mut [u8], fd: usize) {
    if let Some(byte) = set.get_mut(fd / 8) {
        *byte |= 1u8 << (fd % 8);
    }
}

fn copy_set_in(ptr: Option<*mut u8>, dst: &mut [u8]) -> Result<(), SelectError> {
    if dst.is_empty() || ptr.is_none() {
        return Ok(());
    }
    // SAFETY: guarded copy validates the exact native-word-rounded prefix.
    unsafe { crate::handlers::copy_from_user(dst, ptr.unwrap() as u64) }
        .map_err(|_| SelectError::Fault)
}

fn copy_set_out(ptr: Option<*mut u8>, src: &[u8]) -> Result<(), SelectError> {
    if src.is_empty() || ptr.is_none() {
        return Ok(());
    }
    // SAFETY: guarded copy validates the exact native-word-rounded prefix.
    unsafe { crate::handlers::copy_to_user(ptr.unwrap() as u64, src) }
        .map_err(|_| SelectError::Fault)
}

fn allocate_zeroed(len: usize) -> Result<Vec<u8>, SelectError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| SelectError::NoMem)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

/// Linux `core_sys_select`: allocate all kernel storage before user fd-set
/// access, clamp to the fdtable extent, validate selected descriptors, then
/// perform an interruptible poll and copy only result prefixes on success.
#[allow(clippy::too_many_arguments)]
fn do_select(
    ctx: &mut dyn TrapContext,
    syscall_no: u32,
    task_id: u64,
    nfds: i32,
    readfds: Option<*mut u8>,
    writefds: Option<*mut u8>,
    exceptfds: Option<*mut u8>,
    timeout: ParsedTimeout,
    mask_active: bool,
) -> (SelectCoreResult, Option<u64>) {
    if nfds < 0 {
        return (SelectCoreResult::Complete(Err(SelectError::Invalid)), None);
    }

    let max_fds = crate::fd::with_table(task_id, |table| table.max_fds()).unwrap_or(64);
    let nfds = (nfds as usize).min(max_fds);
    let set_bytes = fd_set_copy_bytes(nfds);

    // Linux reserves six bitmaps as one operation before get_fd_set(). Keep
    // the same failure precedence (ENOMEM before a bad fd-set pointer).
    let Some(all_bytes) = set_bytes.checked_mul(6) else {
        return (SelectCoreResult::Complete(Err(SelectError::NoMem)), None);
    };
    let mut bits = match allocate_zeroed(all_bytes) {
        Ok(bits) => bits,
        Err(error) => return (SelectCoreResult::Complete(Err(error)), None),
    };
    let mut items = Vec::new();
    if items.try_reserve(nfds).is_err() {
        return (SelectCoreResult::Complete(Err(SelectError::NoMem)), None);
    }

    let (in_r_at, in_w_at, in_e_at) = (0, set_bytes, set_bytes * 2);
    if let Err(error) = copy_set_in(readfds, &mut bits[in_r_at..in_r_at + set_bytes])
        .and_then(|()| copy_set_in(writefds, &mut bits[in_w_at..in_w_at + set_bytes]))
        .and_then(|()| copy_set_in(exceptfds, &mut bits[in_e_at..in_e_at + set_bytes]))
    {
        return (SelectCoreResult::Complete(Err(error)), None);
    }

    for fd in 0..nfds {
        let want_r = bit_is_set(&bits[in_r_at..in_r_at + set_bytes], fd);
        let want_w = bit_is_set(&bits[in_w_at..in_w_at + set_bytes], fd);
        let want_e = bit_is_set(&bits[in_e_at..in_e_at + set_bytes], fd);
        if want_r || want_w || want_e {
            let mut events = 0u16;
            if want_r {
                events |= POLL_IN as u16;
            }
            if want_w {
                events |= POLL_OUT as u16;
            }
            if want_e {
                events |= POLL_PRI as u16;
            }
            items.push(PollFd {
                fd: fd as i32,
                events,
                revents: 0,
            });
        }
    }

    let all_valid = crate::fd::with_table(task_id, |table| {
        items.iter().all(|item| table.get(item.fd as u32).is_some())
    })
    .unwrap_or(false);
    if !all_valid {
        return (SelectCoreResult::Complete(Err(SelectError::BadFd)), None);
    }

    execute_snapshot(
        ctx,
        SelectParkSnapshot {
            syscall_no,
            task_id,
            set_bytes,
            bits,
            items,
            readfds,
            writefds,
            exceptfds,
            timeout,
            mask_active,
        },
    )
}

fn load_snapshot(task_id: u64, syscall_no: u32) -> Option<SelectParkSnapshot> {
    crate::task::task_get_local(task_id).and_then(|task| {
        let mut slot = task.select_park.lock();
        if slot
            .as_ref()
            .is_some_and(|state| state.syscall_no == syscall_no)
        {
            slot.take()
        } else {
            None
        }
    })
}

fn store_snapshot(snapshot: SelectParkSnapshot) {
    if let Some(task) = crate::task::task_get_local(snapshot.task_id) {
        *task.select_park.lock() = Some(snapshot);
    }
}

fn clear_snapshot(task_id: u64) {
    if let Some(task) = crate::task::task_get_local(task_id) {
        *task.select_park.lock() = None;
    }
}

fn execute_snapshot(
    ctx: &mut dyn TrapContext,
    mut snapshot: SelectParkSnapshot,
) -> (SelectCoreResult, Option<u64>) {
    let wait = poll_wait_kernel(
        ctx,
        snapshot.task_id,
        &mut snapshot.items,
        snapshot.timeout.duration_ns,
        snapshot.syscall_no,
    );
    let deadline_ns = match wait {
        KernelPollWait::Parked => {
            store_snapshot(snapshot);
            complete_kernel_poll_park(ctx);
            return (SelectCoreResult::Parked, None);
        }
        KernelPollWait::Interrupted { deadline_ns } => {
            clear_snapshot(snapshot.task_id);
            return (
                SelectCoreResult::Complete(Err(SelectError::Interrupted)),
                deadline_ns,
            );
        }
        KernelPollWait::TimedOut { deadline_ns } => deadline_ns,
        KernelPollWait::Ready { deadline_ns, .. } => deadline_ns,
    };
    clear_snapshot(snapshot.task_id);

    let mut count = 0usize;
    let set_bytes = snapshot.set_bytes;
    let (in_r_at, in_w_at, in_e_at) = (0, set_bytes, set_bytes * 2);
    let (out_r_at, out_w_at, out_e_at) = (set_bytes * 3, set_bytes * 4, set_bytes * 5);
    for item in &snapshot.items {
        let fd = item.fd as usize;
        let revents = item.revents;
        if bit_is_set(&snapshot.bits[in_r_at..in_r_at + set_bytes], fd)
            && revents & (POLL_IN | POLL_HUP | POLL_ERR | POLL_NVAL) as u16 != 0
        {
            set_bit(&mut snapshot.bits[out_r_at..out_r_at + set_bytes], fd);
            count += 1;
        }
        if bit_is_set(&snapshot.bits[in_w_at..in_w_at + set_bytes], fd)
            && revents & (POLL_OUT | POLL_ERR | POLL_NVAL) as u16 != 0
        {
            set_bit(&mut snapshot.bits[out_w_at..out_w_at + set_bytes], fd);
            count += 1;
        }
        if bit_is_set(&snapshot.bits[in_e_at..in_e_at + set_bytes], fd)
            && revents & (POLL_PRI | POLL_NVAL) as u16 != 0
        {
            set_bit(&mut snapshot.bits[out_e_at..out_e_at + set_bytes], fd);
            count += 1;
        }
    }

    let copied = copy_set_out(
        snapshot.readfds,
        &snapshot.bits[out_r_at..out_r_at + set_bytes],
    )
    .and_then(|()| {
        copy_set_out(
            snapshot.writefds,
            &snapshot.bits[out_w_at..out_w_at + set_bytes],
        )
    })
    .and_then(|()| {
        copy_set_out(
            snapshot.exceptfds,
            &snapshot.bits[out_e_at..out_e_at + set_bytes],
        )
    });
    match copied {
        Ok(()) => (SelectCoreResult::Complete(Ok(count)), deadline_ns),
        Err(error) => (SelectCoreResult::Complete(Err(error)), deadline_ns),
    }
}

fn finish_invocation(
    ctx: &mut dyn TrapContext,
    task_id: u64,
    result: SelectCoreResult,
    deadline_ns: Option<u64>,
    timeout: ParsedTimeout,
    mask_active: bool,
    parsed_deadline: Option<u64>,
) {
    let SelectCoreResult::Complete(result) = result else {
        return;
    };
    if mask_active {
        crate::handlers::restore_temporary_signal_mask(task_id);
    }
    write_remaining_timeout(timeout, deadline_ns.or(parsed_deadline));
    ctx.set_return(result_to_return(result));
}

fn parse_timeval(ptr: u64) -> Result<ParsedTimeout, SelectError> {
    if ptr == 0 {
        return Ok(ParsedTimeout {
            duration_ns: None,
            user_ptr: 0,
            kind: TimeoutKind::Timeval,
        });
    }
    let mut bytes = [0u8; 16];
    // SAFETY: guarded copy validates the complete timeval.
    unsafe { crate::handlers::copy_from_user(&mut bytes, ptr) }.map_err(|_| SelectError::Fault)?;
    let sec = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let usec = i64::from_ne_bytes(bytes[8..].try_into().unwrap());

    // Linux normalizes microseconds before validating the resulting timespec.
    // Rust division/remainder have the same truncation-toward-zero behavior as
    // C, including {-1, 1_000_000} normalizing to an immediate timeout.
    let normalized_sec = i128::from(sec) + i128::from(usec / 1_000_000);
    let normalized_nsec = i128::from(usec % 1_000_000) * 1_000;
    if normalized_sec < 0 || !(0..1_000_000_000).contains(&normalized_nsec) {
        return Err(SelectError::Invalid);
    }
    let duration = normalized_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(normalized_nsec)
        .min(i128::from(u64::MAX - 1)) as u64;
    Ok(ParsedTimeout {
        duration_ns: Some(duration),
        user_ptr: ptr,
        kind: TimeoutKind::Timeval,
    })
}

fn parse_timespec(ptr: u64) -> Result<ParsedTimeout, SelectError> {
    if ptr == 0 {
        return Ok(ParsedTimeout {
            duration_ns: None,
            user_ptr: 0,
            kind: TimeoutKind::Timespec,
        });
    }
    let mut bytes = [0u8; 16];
    // SAFETY: guarded copy validates the complete timespec.
    unsafe { crate::handlers::copy_from_user(&mut bytes, ptr) }.map_err(|_| SelectError::Fault)?;
    let sec = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(bytes[8..].try_into().unwrap());
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(SelectError::Invalid);
    }
    let duration = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64)
        .min(u64::MAX - 1);
    Ok(ParsedTimeout {
        duration_ns: Some(duration),
        user_ptr: ptr,
        kind: TimeoutKind::Timespec,
    })
}

fn write_remaining_timeout(timeout: ParsedTimeout, deadline_ns: Option<u64>) {
    if timeout.user_ptr == 0 || timeout.duration_ns == Some(0) {
        return;
    }
    let remaining = deadline_ns
        .map(|deadline| deadline.saturating_sub(narf_scheduler::narf_time::monotonic_ns()))
        .unwrap_or(0);
    let sec = (remaining / 1_000_000_000) as i64;
    let subsec = match timeout.kind {
        TimeoutKind::Timeval => (remaining % 1_000_000_000) / 1_000,
        TimeoutKind::Timespec => remaining % 1_000_000_000,
    } as i64;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&sec.to_ne_bytes());
    bytes[8..].copy_from_slice(&subsec.to_ne_bytes());
    // Linux deliberately preserves the syscall's original result if timeout
    // write-back faults (e.g. a readable but read-only timeout mapping).
    // SAFETY: guarded user copy validates the complete timeout output range.
    let _ = unsafe { crate::handlers::copy_to_user(timeout.user_ptr, &bytes) };
}

fn set_ptr(raw: u64) -> Option<*mut u8> {
    (raw != 0).then_some(raw as *mut u8)
}

/// select(nfds, readfds, writefds, exceptfds, timeval*).
pub fn sys_select(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let task = current_task_id();
    if let Some(snapshot) = load_snapshot(task, Syscall::Select.raw()) {
        let timeout = snapshot.timeout;
        let mask_active = snapshot.mask_active;
        let (result, deadline_ns) = execute_snapshot(ctx, snapshot);
        finish_invocation(ctx, task, result, deadline_ns, timeout, mask_active, None);
        return;
    }
    let timeout = match parse_timeval(args.arg4) {
        Ok(timeout) => timeout,
        Err(error) => {
            ctx.set_return(result_to_return(Err(error)));
            return;
        }
    };
    let parsed_deadline = timeout.duration_ns.map(|duration| {
        if duration == 0 {
            0
        } else {
            narf_scheduler::narf_time::monotonic_ns().saturating_add(duration)
        }
    });
    let (result, deadline_ns) = do_select(
        ctx,
        Syscall::Select.raw(),
        task,
        args.arg0 as u32 as i32,
        set_ptr(args.arg1),
        set_ptr(args.arg2),
        set_ptr(args.arg3),
        timeout,
        false,
    );
    finish_invocation(
        ctx,
        task,
        result,
        deadline_ns,
        timeout,
        false,
        parsed_deadline,
    );
}

/// pselect6(nfds, readfds, writefds, exceptfds, timespec*, sigset_argpack*).
pub fn sys_pselect6(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let task = current_task_id();
    if let Some(snapshot) = load_snapshot(task, Syscall::Pselect6.raw()) {
        let timeout = snapshot.timeout;
        let mask_active = snapshot.mask_active;
        let (result, deadline_ns) = execute_snapshot(ctx, snapshot);
        finish_invocation(ctx, task, result, deadline_ns, timeout, mask_active, None);
        return;
    }

    // Linux copies the outer argpack before even reading the timeout.
    let (sigmask_ptr, sigmask_size) = if args.arg5 == 0 {
        (0, 0)
    } else {
        let mut pair = [0u8; 16];
        // SAFETY: guarded user copy validates the complete sigset argpack.
        if unsafe { crate::handlers::copy_from_user(&mut pair, args.arg5) }.is_err() {
            ctx.set_return(errno(EFAULT));
            return;
        }
        (
            u64::from_ne_bytes(pair[..8].try_into().unwrap()),
            u64::from_ne_bytes(pair[8..].try_into().unwrap()),
        )
    };

    let timeout = match parse_timespec(args.arg4) {
        Ok(timeout) => timeout,
        Err(error) => {
            ctx.set_return(result_to_return(Err(error)));
            return;
        }
    };
    let parsed_deadline = timeout.duration_ns.map(|duration| {
        if duration == 0 {
            0
        } else {
            narf_scheduler::narf_time::monotonic_ns().saturating_add(duration)
        }
    });

    // A null mask pointer ignores size. A non-null pointer requires the
    // kernel sigset size before the pointer itself is dereferenced.
    let mask = if sigmask_ptr == 0 {
        None
    } else {
        if sigmask_size != size_of::<u64>() as u64 {
            ctx.set_return(errno(EINVAL));
            return;
        }
        let mut bytes = [0u8; size_of::<u64>()];
        // SAFETY: size was validated and guarded copy checks the pointed set.
        if unsafe { crate::handlers::copy_from_user(&mut bytes, sigmask_ptr) }.is_err() {
            ctx.set_return(errno(EFAULT));
            return;
        }
        Some(u64::from_ne_bytes(bytes))
    };

    if let Some(mask) = mask {
        crate::handlers::install_temporary_signal_mask(task, mask);
    }
    let (result, deadline_ns) = do_select(
        ctx,
        Syscall::Pselect6.raw(),
        task,
        args.arg0 as u32 as i32,
        set_ptr(args.arg1),
        set_ptr(args.arg2),
        set_ptr(args.arg3),
        timeout,
        mask.is_some(),
    );
    finish_invocation(
        ctx,
        task,
        result,
        deadline_ns,
        timeout,
        mask.is_some(),
        parsed_deadline,
    );
}
