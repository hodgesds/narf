//! The task view an in-kernel syscall-interception backend reports to a Tool.
//!
//! A Reverie Tool running inside the kernel sees a task the way a tracer in
//! the root PID namespace sees it under Linux: thread and process IDs are the
//! outer (root-namespace) values, and memory is the current task's own address
//! space. These helpers expose exactly that view over the handlers' private
//! identity maps and user-copy primitives, so the backend never reaches into
//! those maps or the trap frame itself.

use alloc::vec::Vec;

/// Linux identity of one task in the root PID namespace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinuxTaskIds {
    /// Thread ID: the process ID for a thread-group leader, otherwise the
    /// thread's own ID.
    pub tid: u64,
    /// Process (thread-group) ID.
    pub pid: u64,
    /// Parent process ID, or `None` when the process has no recorded parent.
    pub ppid: Option<u64>,
}

/// Root-namespace Linux identity of scheduler task `task`, or `None` for a
/// task with no registered process ID (a kernel-only task).
///
/// This is `gettid`/`getpid`/`getppid` without the caller's PID-namespace
/// translation: the IDs a tracer outside every container would report.
pub fn linux_task_ids(task: u64) -> Option<LinuxTaskIds> {
    let pid = super::task_to_pid_raw(task)?;
    let tid = match super::task_to_linux_tid_raw(task) {
        Some(tid) => tid,
        None if super::pid_to_task_raw(pid) == Some(task) => pid,
        None => task,
    };
    let ppid = super::parent_of_get(pid)
        .map(|parent_task| super::task_to_pid_raw(parent_task).unwrap_or(parent_task));
    Some(LinuxTaskIds { tid, pid, ppid })
}

/// Copies `dst.len()` bytes from user address `src` of the current address
/// space. Returns the Linux errno on failure.
///
/// Refuses with `EFAULT`, touching no memory, when no user task is running
/// on this CPU. A kernel task, such as a Tool's background future, runs on
/// the kernel's own page tables, which hold no user memory; under the
/// `nosmp` boot flag they still map the AP trampoline pages
/// (`narf_memory::mmu::AP_TRAMPOLINE_EXEC_BASE`), which a user copy would
/// otherwise reach.
///
/// # Safety
///
/// When a user task is running, the active address space must be the one
/// of the task whose memory the caller means to read, as it is for the
/// duration of that task's syscall interception. Must not be called from
/// IRQ context.
pub unsafe fn read_current_user(dst: &mut [u8], src: u64) -> Result<(), u64> {
    if crate::user_task::current_user_task().is_none() {
        return Err(crate::errno::EFAULT as u64);
    }
    // SAFETY: a user task is running; the rest is forwarded verbatim from
    // this function's contract.
    unsafe { super::copy_from_user(dst, src) }
}

/// Copies `src` to user address `dst` of the current address space. Returns
/// the Linux errno on failure, and refuses as [`read_current_user`] does
/// when no user task is running.
///
/// # Safety
///
/// Same contract as [`read_current_user`].
pub unsafe fn write_current_user(dst: u64, src: &[u8]) -> Result<(), u64> {
    if crate::user_task::current_user_task().is_none() {
        return Err(crate::errno::EFAULT as u64);
    }
    // SAFETY: as in `read_current_user`.
    unsafe { super::copy_to_user(dst, src) }
}

/// The auxiliary vector recorded for process `pid`, as `(key, value)` pairs
/// without the terminating `AT_NULL`. Empty when none was recorded.
pub fn auxv_pairs(pid: u64) -> Vec<(u64, u64)> {
    let packed = super::proc_auxv_of(pid);
    let mut pairs = Vec::new();
    for entry in packed.chunks_exact(16) {
        let mut key = [0u8; 8];
        let mut value = [0u8; 8];
        key.copy_from_slice(&entry[..8]);
        value.copy_from_slice(&entry[8..]);
        let key = u64::from_le_bytes(key);
        if key == 0 {
            break;
        }
        pairs.push((key, u64::from_le_bytes(value)));
    }
    pairs
}

/// Kills process `pid` (root namespace) with `SIGKILL`, as `kill(pid,
/// SIGKILL)` from the kernel: every live thread of the process gets the
/// signal and is woken. Returns `false` when no such process exists.
///
/// A backend uses it to abort the process tree it hosts, as Linux kills a
/// tracee whose tracer exits with `PTRACE_O_EXITKILL`. It sends no signal to
/// any process the backend does not name, and leaves the kernel running.
pub fn kill_process_sigkill(pid: u64) -> bool {
    super::kill_process(pid, 9)
}

/// The wait status the kernel will report for process `pid`'s termination,
/// if one has been staged, without consuming it.
pub fn pending_termination(pid: u64) -> Option<i32> {
    super::peek_pending_termination(pid)
}
