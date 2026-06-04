//! PID-1 ("init") orchestration.
//!
//! After the kernel reaches userspace-ready state — root filesystem
//! mounted, drivers bound, scheduler running — the boot path calls
//! `spawn_pid1_from_initramfs("/sbin/init")` (or
//! `spawn_pid1_from_bytes(ELF_BLOB)`) to load and start the first
//! user process. Once running, init is responsible for everything
//! above the kernel: forking shell sessions, daemons, login screens.
//!
//! The spawn path glues:
//!   1. `process::load_user_process(bytes)` — ELF parse → UserProcess
//!   2. `user_task::UserTaskFuture::new(process)` — polling future
//!   3. `narf_scheduler::spawn_user(future, spec, addr_space)` —
//!      enqueue on the scheduler
//!
//! Argv / envp / aux can be passed via `spawn_pid1_with_argv`; the
//! single-arg `spawn_pid1_from_bytes` uses an empty argv (init
//! reads its config from the staged initramfs or hardcoded paths).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::process::{load_user_process, load_user_process_with, ProcessLoadError};
use crate::user_task::UserTaskFuture;
use narf_scheduler::{spawn_user, TaskId, TaskSpec};

/// Errors specific to PID-1 spawn.
#[derive(Debug)]
pub enum InitError {
    /// ELF parse / address-space setup failed.
    Load(ProcessLoadError),
    /// Initramfs wasn't staged at boot, so we can't read the init
    /// binary from it.
    InitramfsNotStaged,
    /// The named path doesn't exist in the staged initramfs.
    NotFound(String),
}

impl From<ProcessLoadError> for InitError {
    fn from(e: ProcessLoadError) -> Self {
        InitError::Load(e)
    }
}

/// Load `bytes` as PID 1 with an empty argv/envp. Returns the
/// scheduler task id so callers can observe completion.
///
/// # Safety
/// - The kernel must have a live identity map covering the low
///   4 GiB (the load_user_process contract).
/// - Frame allocator + scheduler must be initialised.
/// - This is the first user process; caller's responsibility to
///   not call it twice (the existing scheduler tracks no
///   "PID 1 was already spawned" guard).
pub unsafe fn spawn_pid1_from_bytes(bytes: &[u8]) -> Result<TaskId, InitError> {
    // SAFETY: forwarding the caller's contract.
    let process = unsafe { load_user_process(bytes)? };
    let addr_space = process.address_space.clone();
    let future = UserTaskFuture::new(process);
    Ok(spawn_user(future, TaskSpec::default(), addr_space))
}

/// Load `bytes` as PID 1 with the given argv + envp. Useful for
/// passing the kernel cmdline's `init.argv=...` tail to init.
///
/// # Safety
/// Same as [`spawn_pid1_from_bytes`].
pub unsafe fn spawn_pid1_with_argv(
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<TaskId, InitError> {
    // SAFETY: forwarding.
    let process = unsafe { load_user_process_with(bytes, argv, envp, &[])? };
    let addr_space = process.address_space.clone();
    let future = UserTaskFuture::new(process);
    Ok(spawn_user(future, TaskSpec::default(), addr_space))
}

/// Convenience: read `path` from the staged initramfs and spawn
/// it as PID 1.
///
/// # Safety
/// Same as [`spawn_pid1_from_bytes`].
pub unsafe fn spawn_pid1_from_initramfs(path: &str) -> Result<TaskId, InitError> {
    let fs = narf_initramfs::staged().ok_or(InitError::InitramfsNotStaged)?;
    let bytes = fs
        .iter_files()
        .find(|(n, _)| *n == path)
        .map(|(_, d)| d)
        .ok_or_else(|| InitError::NotFound(String::from(path)))?;
    // SAFETY: forwarding.
    unsafe { spawn_pid1_from_bytes(bytes) }
}

/// What [`spawn_pid1_*`] callers might want to know post-spawn for
/// the boot log: the scheduled TaskId, the entry RIP, and the
/// initial RSP. Returned by the helpers when callers want the
/// detail rather than just the TaskId.
#[derive(Copy, Clone, Debug)]
pub struct Pid1SpawnReport {
    pub task_id: TaskId,
    pub entry: u64,
    pub stack_top: u64,
}

/// Same as `spawn_pid1_from_bytes` but returns a detailed report.
///
/// # Safety
/// Same as [`spawn_pid1_from_bytes`].
pub unsafe fn spawn_pid1_from_bytes_report(bytes: &[u8]) -> Result<Pid1SpawnReport, InitError> {
    // SAFETY: forwarding.
    let process = unsafe { load_user_process(bytes)? };
    let entry = process.entry.0.raw();
    let stack_top = process.stack_top.as_u64();
    let addr_space = process.address_space.clone();
    let future = UserTaskFuture::new(process);
    let task_id = spawn_user(future, TaskSpec::default(), addr_space);
    Ok(Pid1SpawnReport {
        task_id,
        entry,
        stack_top,
    })
}

/// `Vec<String>` helper for the boot log: list every file in the
/// staged initramfs. Useful for "init not found at /sbin/init —
/// here's what IS present" diagnostics.
pub fn initramfs_file_listing() -> Option<Vec<String>> {
    let fs = narf_initramfs::staged()?;
    Some(fs.iter_files().map(|(n, _)| String::from(n)).collect())
}
