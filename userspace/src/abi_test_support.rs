//! Shared harness for the Linux syscall ABI conformance test groups
//! (`abi_*_tests.rs`). Gated under `linux-compat`.
//!
//! Each category module does `use crate::abi_test_support::*;` and writes
//! `smoke_abi_*` tests registered with `kernel_test_in!("syscall_abi", ..)`.
//! Every test calls [`call`] / [`call_raw`] against `kernel_syscall_entry`
//! with a crafted [`AbiCtx`], so the groups are deterministic and immune
//! to the executor (no user mode, no scheduler).
#![cfg(feature = "linux-compat")]
#![allow(dead_code)] // errno/flag reference table + harness helpers

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use narf_memory::AddressSpace;

pub use narf_capabilities::{Cap, Grant};
pub use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};
pub use narf_kernel_test::{kernel_test_in, TestResult};

pub use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
pub use crate::{
    fd, install_core_syscalls, install_global, install_task_id_lookup, syscall::__test_clear_global,
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
pub const EPIPE: i64 = -32;
pub const ERANGE: i64 = -34;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;

/// The pid every ABI test runs as (overridable per test via [`set_task`]).
pub const FAKE_TASK: u64 = 99;
static TASK_SLOT: AtomicU64 = AtomicU64::new(FAKE_TASK);
type TestAsLookupFn = fn() -> Option<Arc<AddressSpace>>;
static SAVED_AS_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<TestAsLookupFn>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

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
    // The kernel-test registry shares one image, and process/VM tests install
    // a global scheduler bridge. ABI smokes promise a no-AS baseline unless
    // their own body installs one, so save and clear that bridge explicitly
    // instead of depending on registry order.
    *SAVED_AS_LOOKUP.lock() = crate::handlers::address_space_lookup();
    crate::handlers::restore_address_space_lookup(None);
    // ABI smokes share the kernel image. A preceding CLONE_NEWNS/unshare test
    // must not leave FAKE_TASK resolving paths in its private namespace: this
    // harness promises a fresh task view to every test.
    crate::handlers::__test_mount_namespaces_reset();
    crate::handlers::__test_root_dir_reset();
    #[cfg(feature = "container")]
    crate::pid_ns::__test_reset();
    __test_clear_global();
    fd::__test_reset();
    install_task_id_lookup(task_lookup);
    // The no-AS baseline this harness promises is established above, by the
    // save-clear-restore of `address_space_lookup()`. An earlier version of this
    // file also installed a `None`-returning lookup here; upstream arrived at
    // the same fix independently and scoped it properly (restored in
    // `teardown`, so a test body that installs its own bridge still works),
    // which makes the second mechanism redundant. Two mechanisms for one
    // invariant is how invariants rot, so the duplicate is gone rather than
    // left as belt-and-braces.
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    // Real per-task state (resets every test): SIGNAL_PENDING, rlimits,
    // sched params, creds, nice, umask, etc. Without this, kill/getrlimit/
    // sched_* and friends only ever hit their "uninitialised → fail" path.
    crate::handlers::init_per_task_state();
    // pid<->tid identity for FAKE_TASK so signal/wait/pid syscalls resolve.
    crate::handlers::register_task_to_pid(FAKE_TASK, FAKE_TASK);
    crate::handlers::register_pid_task_mapping(FAKE_TASK, FAKE_TASK);
    // Refcounted-task registry entry: tkill/tgkill/kill now report
    // ESRCH for tids the registry doesn't know, so the harness task
    // must exist like a real spawned task would.
    if crate::task::task_get(FAKE_TASK).is_none() {
        let _ = crate::task::Task::new_registered(FAKE_TASK, FAKE_TASK);
    }
}

pub fn teardown() {
    crate::handlers::__test_mount_namespaces_reset();
    crate::handlers::__test_root_dir_reset();
    #[cfg(feature = "container")]
    crate::pid_ns::__test_reset();
    __test_clear_global();
    fd::__test_reset();
    crate::handlers::restore_address_space_lookup(*SAVED_AS_LOOKUP.lock());
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
    ctx.ret.unwrap_or_else(|| SyscallReturn::ok(0xDEAD_u64)) // no set_return => sentinel
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

pub fn call_open(path_ptr: u64, flags: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::OpenFile.raw(), a1(path_ptr, flags))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Openat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: flags,
                ..Default::default()
            },
        )
    }
}

pub fn call_readlink(path_ptr: u64, buf_ptr: u64, len: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Readlink.raw(), a2(path_ptr, buf_ptr, len))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Readlinkat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: buf_ptr,
                arg3: len,
                ..Default::default()
            },
        )
    }
}

pub fn call_stat(path_ptr: u64, sb_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Stat.raw(), a1(path_ptr, sb_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Newfstatat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: sb_ptr,
                arg3: 0, // flags
                ..Default::default()
            },
        )
    }
}

pub fn call_lstat(path_ptr: u64, sb_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Lstat.raw(), a1(path_ptr, sb_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Newfstatat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: sb_ptr,
                arg3: 0x100, // AT_SYMLINK_NOFOLLOW
                ..Default::default()
            },
        )
    }
}

pub fn call_dup2(oldfd: u64, newfd: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Dup2.raw(), a1(oldfd, newfd))
    }
    #[cfg(target_arch = "aarch64")]
    {
        if oldfd == newfd {
            let res = call(Syscall::Fcntl.raw(), a1(oldfd, 1));
            if res.is_some() && res.unwrap() >= 0 {
                Some(oldfd as i64)
            } else {
                Some(EBADF)
            }
        } else {
            call(Syscall::Dup3.raw(), a2(oldfd, newfd, 0))
        }
    }
}

pub fn call_symlink(target_ptr: u64, link_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Symlink.raw(), a1(target_ptr, link_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Symlinkat.raw(),
            SyscallArgs {
                arg0: target_ptr,
                arg1: 0xffffffffffffff9c,
                arg2: link_ptr,
                ..Default::default()
            },
        )
    }
}

pub fn call_mkdir(path_ptr: u64, mode: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Mkdir.raw(), a1(path_ptr, mode))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Mkdirat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c,
                arg1: path_ptr,
                arg2: mode,
                ..Default::default()
            },
        )
    }
}

pub fn call_chmod(path_ptr: u64, mode: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Chmod.raw(), a1(path_ptr, mode))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Fchmodat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c,
                arg1: path_ptr,
                arg2: mode,
                ..Default::default()
            },
        )
    }
}

pub fn call_chown(path_ptr: u64, owner: u64, group: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Chown.raw(), a2(path_ptr, owner, group))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Fchownat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c,
                arg1: path_ptr,
                arg2: owner,
                arg3: group,
                arg4: 0,
                ..Default::default()
            },
        )
    }
}

pub fn call_lchown(path_ptr: u64, owner: u64, group: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Lchown.raw(), a2(path_ptr, owner, group))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Fchownat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c,
                arg1: path_ptr,
                arg2: owner,
                arg3: group,
                arg4: 0x100,
                ..Default::default()
            },
        )
    }
}

pub fn call_access(path_ptr: u64, mode: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Access.raw(), a1(path_ptr, mode))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Faccessat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c,
                arg1: path_ptr,
                arg2: mode,
                arg3: 0,
                ..Default::default()
            },
        )
    }
}

pub fn call_utimes(path_ptr: u64, tv_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Utimes.raw(), a1(path_ptr, tv_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        if path_ptr == 0 {
            Some(EFAULT)
        } else {
            call(
                Syscall::Utimensat.raw(),
                SyscallArgs {
                    arg0: 0xffffffffffffff9c,
                    arg1: path_ptr,
                    arg2: tv_ptr,
                    arg3: 0,
                    ..Default::default()
                },
            )
        }
    }
}

pub fn call_utime(path_ptr: u64, utx_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Utime.raw(), a1(path_ptr, utx_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        if path_ptr == 0 {
            Some(EFAULT)
        } else {
            call(
                Syscall::Utimensat.raw(),
                SyscallArgs {
                    arg0: 0xffffffffffffff9c,
                    arg1: path_ptr,
                    arg2: utx_ptr,
                    arg3: 0,
                    ..Default::default()
                },
            )
        }
    }
}

pub fn call_creat(path_ptr: u64, mode: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Creat.raw(), a1(path_ptr, mode))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Openat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: 0o100 | 0o1 | 0o1000, // O_CREAT | O_WRONLY | O_TRUNC
                arg3: mode,
                ..Default::default()
            },
        )
    }
}

pub fn call_unlink(path_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Unlink.raw(), a0(path_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Unlinkat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: 0,
                ..Default::default()
            },
        )
    }
}

pub fn call_link(old_ptr: u64, new_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Link.raw(), a1(old_ptr, new_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Linkat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c,
                arg1: old_ptr,
                arg2: 0xffffffffffffff9c,
                arg3: new_ptr,
                ..Default::default()
            },
        )
    }
}

pub fn call_rename(old_ptr: u64, new_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Rename.raw(), a1(old_ptr, new_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Renameat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: old_ptr,
                arg2: 0xffffffffffffff9c, // AT_FDCWD
                arg3: new_ptr,
                ..Default::default()
            },
        )
    }
}

pub fn call_rmdir(path_ptr: u64) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Rmdir.raw(), a0(path_ptr))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Unlinkat.raw(),
            SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: path_ptr,
                arg2: 0x200, // AT_REMOVEDIR
                ..Default::default()
            },
        )
    }
}

pub fn call_getpgrp() -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        call(Syscall::Getpgrp.raw(), a0(0))
    }
    #[cfg(target_arch = "aarch64")]
    {
        call(
            Syscall::Getpgid.raw(),
            SyscallArgs {
                arg0: 0,
                ..Default::default()
            },
        )
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
    let outcome = crate::handlers::with_kernel_buffers(body);
    let _ = registry().unmount(&handle, mount);
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}

/// Run `body` with just the syscall table + fake task + fresh fd table
/// (no mount). Teardown is automatic.
///
/// The body runs inside [`crate::handlers::with_kernel_buffers`]. These
/// smokes have no user address space by construction — they call
/// `kernel_syscall_entry` directly and hand it pointers to kernel `.rodata`
/// string literals and kernel stack/heap scratch buffers, all of which sit
/// in the kernel half on both architectures (x86_64 links higher-half:
/// `.rodata` at 0xFFFF_FFFF_81E2_E000; aarch64 runs entirely out of
/// TTBR1). `validate_user_range` confines a real syscall's ranges to the
/// user half, so without the opt-in 339 of these smokes would EFAULT on
/// their own fixture rather than on the behaviour they test.
///
/// The opt-in is dynamically scoped and keyed on the CPU, so it covers
/// exactly this harness — not the rest of the `kernel-test` suite, not a
/// concurrent task, and it is not compiled at all outside `kernel-test`.
/// Tests whose subject *is* the boundary use [`with_setup_strict`].
pub fn with_setup(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    setup();
    let outcome = crate::handlers::with_kernel_buffers(body);
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}

/// [`with_setup`] **without** the kernel-buffer opt-in: the syscalls the
/// body issues see the same `validate_user_range` predicate a real user
/// task does.
///
/// Use this for any test whose subject *is* the user/kernel address
/// boundary — `abi_uaccess_tests.rs`. A test asserting that a kernel-half
/// pointer is rejected would be vacuous under `with_setup`, which opens
/// the opt-in precisely so kernel scratch buffers pass.
pub fn with_setup_strict(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    setup();
    let outcome = body();
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
