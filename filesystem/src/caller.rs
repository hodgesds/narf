//! The calling task's process identity, for drivers that attribute work
//! to the process that submitted it (a GPU devcoredump's "Process:" line).
//!
//! Process names and PIDs live in the userspace tables, which this crate
//! cannot see; userspace installs an accessor ([`install_hook`]), as it
//! does for the PTY credentials. With no hook (in-kernel tests, early boot)
//! there is no caller to name.

use core::sync::atomic::{AtomicUsize, Ordering};

/// `TASK_COMM_LEN`.
pub const COMM_LEN: usize = 16;

/// A task's `comm` (at most `TASK_COMM_LEN - 1` bytes) and its PID in the
/// initial namespace, as Linux records for a DRM file (`task->comm`,
/// `task->pid`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    comm: [u8; COMM_LEN],
    len: u8,
}

impl Caller {
    /// `name` clamped to `TASK_COMM_LEN - 1` bytes on a character boundary.
    pub fn new(name: &str, pid: u32) -> Self {
        let mut len = name.len().min(COMM_LEN - 1);
        while !name.is_char_boundary(len) {
            len -= 1;
        }
        let mut comm = [0; COMM_LEN];
        comm[..len].copy_from_slice(&name.as_bytes()[..len]);
        Self {
            pid,
            comm,
            len: len as u8,
        }
    }

    pub fn comm(&self) -> &str {
        core::str::from_utf8(&self.comm[..usize::from(self.len)]).unwrap_or("")
    }
}

/// `fn(&mut comm) -> (pid, comm length)` for the calling task; length 0 when
/// it has no name.
pub type Hook = fn(&mut [u8; COMM_LEN]) -> (u64, usize);

static HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the calling-task accessor.
pub fn install_hook(hook: Hook) {
    HOOK.store(hook as usize, Ordering::Release);
}

/// The calling task, when a hook is installed and the task is named.
pub fn current() -> Option<Caller> {
    let raw = HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return None;
    }
    // SAFETY: `raw` was stored by `install_hook` from a `Hook`, the only
    // writer of this slot, and function pointers are never unmapped.
    let hook: Hook = unsafe { core::mem::transmute(raw) };
    let mut comm = [0; COMM_LEN];
    let (pid, len) = hook(&mut comm);
    let name = core::str::from_utf8(&comm[..len.min(COMM_LEN)]).ok()?;
    (!name.is_empty()).then(|| Caller::new(name, u32::try_from(pid).unwrap_or(u32::MAX)))
}

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A name is clamped to fifteen bytes without splitting a character.
    fn smoke_caller_comm_clamps_to_task_comm_len() -> TestResult {
        let caller = Caller::new("weston-terminal-x", 42);
        let accented = Caller::new("abcdefghijklmn\u{e9}", 7);
        if caller.comm() != "weston-terminal"
            || caller.pid != 42
            || accented.comm() != "abcdefghijklmn"
            || Caller::new("", 1).comm() != ""
        {
            return TestResult::Fail("comm follows TASK_COMM_LEN");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/caller",
        smoke_caller_comm_clamps_to_task_comm_len
    );
}
