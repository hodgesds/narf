//! Shared harness for the Linux syscall ABI conformance test groups
//! (`abi_*_tests.rs`). Gated under `linux-compat`.
//!
//! Each category module does `use crate::abi_test_support::*;` and writes
//! `smoke_abi_*` tests registered with `kernel_test_in!("syscall_abi", ..)`.
//! Every test calls [`call`] / [`call_raw`] against `kernel_syscall_entry`
//! with a crafted [`AbiCtx`], so the groups are deterministic and immune
//! to the executor (no user mode, no scheduler).
#![cfg(feature = "linux-compat")]

use core::sync::atomic::{AtomicU64, Ordering};

pub use narf_capabilities::{Cap, Grant};
pub use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};
pub use narf_kernel_test::{kernel_test_in, TestResult};

pub use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
pub use crate::{
    fd, install_core_syscalls, install_global, install_task_id_lookup,
    syscall::__test_clear_global,
};

// ── Linux errno wire values (negative, in `SyscallReturn.value`, status Ok) ──
pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EBADF: i64 = -9;
pub const ECHILD: i64 = -10;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ENOTTY: i64 = -25;
pub const ESPIPE: i64 = -29;
pub const ERANGE: i64 = -34;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;

/// The pid every ABI test runs as (overridable per test via [`set_task`]).
pub const FAKE_TASK: u64 = 99;
static TASK_SLOT: AtomicU64 = AtomicU64::new(FAKE_TASK);

fn task_lookup() -> u64 {
    TASK_SLOT.load(Ordering::Relaxed)
}

/// Override the current-task id the harness reports. Resets to
/// [`FAKE_TASK`] on the next [`setup`].
pub fn set_task(id: u64) {
    TASK_SLOT.store(id, Ordering::Relaxed);
}

/// Minimal `TrapContext`: carries args in, captures the return.
pub struct AbiCtx {
    pub args: SyscallArgs,
    pub ret: Option<SyscallReturn>,
}
impl TrapContext for AbiCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = Some(r);
    }
    fn user_rsp(&self) -> u64 {
        0
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
}

/// Install the syscall table + a fake task (pid [`FAKE_TASK`]) + a fresh
/// fd table, AND initialise the real per-task kernel state subsystems
/// (signal-pending, rlimits, sched params, uid/gid, nice, umask, cwd,
/// brk, pgid/sid, wait, …) the same way the boot path does — so handler
/// SUCCESS paths are reachable and the tests cover real behavior, not
/// just the "state-missing" error branches. Call at the top of every
/// test; pair with [`teardown`].
pub fn setup() {
    TASK_SLOT.store(FAKE_TASK, Ordering::Relaxed);
    __test_clear_global();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    // Real per-task state (resets every test): SIGNAL_PENDING, rlimits,
    // sched params, creds, nice, umask, etc. Without this, kill/getrlimit/
    // sched_* and friends only ever hit their "uninitialised → fail" path.
    crate::handlers::init_per_task_state();
    // pid<->tid identity for FAKE_TASK so signal/wait/pid syscalls resolve.
    crate::handlers::register_task_to_pid(FAKE_TASK, FAKE_TASK);
}

pub fn teardown() {
    __test_clear_global();
    fd::__test_reset();
}

/// Invoke `num` with `args`; return the result decoded as a signed Linux
/// value when the handler reported NARF `Ok`, else `None` (a non-Ok NARF
/// status — an un-Linux-ified failure shape).
pub fn call(num: u32, args: SyscallArgs) -> Option<i64> {
    let r = call_raw(num, args);
    if r.status == SyscallReturn::OK {
        Some(r.value as i64)
    } else {
        None
    }
}

/// Invoke `num` and return the raw `SyscallReturn` (for tests that need to
/// distinguish the NARF status, e.g. `InvalidOp` vs `Ok(-errno)`).
pub fn call_raw(num: u32, args: SyscallArgs) -> SyscallReturn {
    let mut ctx = AbiCtx { args, ret: None };
    kernel_syscall_entry(num, &mut ctx);
    ctx.ret
        .unwrap_or_else(|| SyscallReturn::ok(0xDEAD_u64)) // no set_return => sentinel
}

// ── Arg builders (the rest default to 0) ──
pub fn a0(arg0: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        ..Default::default()
    }
}
pub fn a1(arg0: u64, arg1: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        ..Default::default()
    }
}
pub fn a2(arg0: u64, arg1: u64, arg2: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        arg2,
        ..Default::default()
    }
}
pub fn a3(arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        arg2,
        arg3,
        ..Default::default()
    }
}

/// Mount a fresh MemFs (named `fs_name`) at `mount` with `seeds`, run
/// `body`, unmount + teardown. `fs_name` / `mount` are `'static` because
/// `MemFs::with_seeds` takes a `&'static str` name. `body` returns
/// `Ok(())` to pass or `Err(msg)` to fail.
pub fn with_memfs(
    mount: &'static str,
    fs_name: &'static str,
    seeds: &[(&str, &[u8])],
    body: impl FnOnce() -> Result<(), &'static str>,
) -> TestResult {
    setup();
    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds(fs_name, seeds);
    let handle = match registry().mount(&auth, mount, fs) {
        Ok(h) => h,
        Err(_) => {
            teardown();
            return TestResult::Fail("memfs mount failed");
        }
    };
    let outcome = body();
    let _ = registry().unmount(&handle, mount);
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}

/// Run `body` with just the syscall table + fake task + fresh fd table
/// (no mount). Teardown is automatic.
pub fn with_setup(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    setup();
    let outcome = body();
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
