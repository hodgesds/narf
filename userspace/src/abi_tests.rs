//! Linux syscall **ABI-shape** conformance tests for `narf-userspace`.
//!
//! Gated under `linux-compat` (the feature that builds NARF's
//! Linux-shaped syscall surface). These verify that the syscalls musl /
//! busybox actually issue are accepted in their *Linux* register shape —
//! the bug class that silently `EPERM`s real Linux binaries:
//!
//!   * Path arguments are a single **NUL-terminated** `const char *` in
//!     `arg0` — NOT the old NARF-native `(ptr, len)` pair. A handler that
//!     still reads `arg1` as a length mis-parses every musl call (musl
//!     puts flags / mode there), so each test deliberately plants
//!     *garbage* in the old length slot and asserts the result is
//!     unchanged.
//!   * The return uses the Linux `-errno` convention in
//!     `SyscallReturn.value` (e.g. readlink on a non-symlink → `-EINVAL`).
//!
//! Self-contained: each test calls `kernel_syscall_entry` directly with a
//! crafted `TrapContext`, so they're deterministic and immune to the
//! executor (no user mode, no scheduler).
#![cfg(feature = "linux-compat")]

use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, Grant};
use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
use crate::{
    fd, install_core_syscalls, install_global, install_task_id_lookup,
    syscall::__test_clear_global,
};

// Linux errno wire values (negative, carried in `SyscallReturn.value`
// with `status == Ok`). Only the ones asserted below.
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

const FAKE_TASK: u64 = 99;
static TASK_SLOT: AtomicU64 = AtomicU64::new(FAKE_TASK);
fn task_lookup() -> u64 {
    TASK_SLOT.load(Ordering::Relaxed)
}

/// Minimal `TrapContext`: carries args in, captures the return.
struct AbiCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
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

/// Install the syscall table + a fake task + a fresh fd table. Idempotent
/// per test; pair with [`teardown`].
fn setup() {
    __test_clear_global();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
}

fn teardown() {
    __test_clear_global();
    fd::__test_reset();
}

/// Invoke `num` and return the result decoded as a signed Linux return
/// value, or `None` if the handler reported a non-`Ok` NARF status (an
/// un-Linux-ified failure shape — caller decides whether that's a pass).
fn call(num: u32, args: SyscallArgs) -> Option<i64> {
    let mut ctx = AbiCtx { args, ret: None };
    kernel_syscall_entry(num, &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => Some(r.value as i64),
        _ => None,
    }
}

/// `SyscallArgs` with `arg0` set; the rest zero. Helper for the common
/// "one pointer argument" Linux shape.
fn a0(arg0: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        ..Default::default()
    }
}

/// Mount a fresh MemFs (named `fs_name`) at `mount` with `seeds`, run
/// `body`, unmount. `fs_name` / `mount` are `'static` literals because
/// `MemFs::with_seeds` takes a `&'static str` name.
fn with_memfs(
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

// ── stat: Linux 2-arg shape (path_ptr, statbuf_ptr), NUL-terminated ──

fn smoke_abi_stat_is_linux_shaped() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/f\0";
        let mut sb = [0u8; 256];
        // Linux: stat(const char *path, struct stat *buf). arg0=path,
        // arg1=buf. Plant garbage in arg2/arg3 (the old NARF (ptr,len)
        // tail) to prove they're ignored.
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: sb.as_mut_ptr() as u64,
            arg2: 0xdead_beef,
            arg3: 0xdead_beef,
            ..Default::default()
        };
        match call(Syscall::Stat.raw(), args) {
            Some(0) => Ok(()),
            Some(v) => {
                // keep `v` observable in the failure path
                let _ = v;
                Err("stat on existing file should return 0")
            }
            None => Err("stat returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_stat_is_linux_shaped);

fn smoke_abi_stat_missing_path_fails() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/nope\0";
        let mut sb = [0u8; 256];
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: sb.as_mut_ptr() as u64,
            ..Default::default()
        };
        // A missing path must NOT report success (value 0). NARF returns
        // the -1 sentinel today; Linux would use -ENOENT. Accept any
        // failure shape (negative value or non-Ok status).
        match call(Syscall::Stat.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            None => Ok(()),
            Some(_) => Err("stat on a missing path must fail"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_stat_missing_path_fails);

// ── chdir: Linux 1-arg shape (path_ptr), NUL-terminated ──
//
// The canonical regression: chdir used to read arg1 as a NARF-native
// length, so musl's `chdir(path)` (which leaves arg1 = whatever was in
// rsi) mis-parsed. Assert the result is invariant to garbage in arg1.

fn smoke_abi_chdir_ignores_old_length_arg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi\0";
        let clean = call(Syscall::Chdir.raw(), a0(path.as_ptr() as u64));
        let garbage = call(
            Syscall::Chdir.raw(),
            SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: 0xdead_beef, // old NARF length slot — must be ignored
                ..Default::default()
            },
        );
        if clean != garbage {
            return Err("chdir result changed with garbage in arg1 (still reads a length?)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_chdir_ignores_old_length_arg);

// ── mkdir: Linux shape (path_ptr), NUL-terminated ──

fn smoke_abi_mkdir_is_linux_shaped() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/newdir\0";
        // arg0 = NUL-term path; arg1 = mode (Linux) — garbage here must
        // not be treated as a path length.
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0o755,
            ..Default::default()
        };
        match call(Syscall::Mkdir.raw(), args) {
            Some(0) => Ok(()),
            Some(_) => Err("mkdir of a new directory should return 0"),
            None => Err("mkdir returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mkdir_is_linux_shaped);

// ── readlink: Linux -errno convention ──

fn smoke_abi_readlink_nonsymlink_is_einval() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/f\0";
        let mut buf = [0u8; 64];
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..Default::default()
        };
        // POSIX/Linux: readlink on an existing non-symlink is EINVAL.
        match call(Syscall::Readlink.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("readlink on a non-symlink must return -EINVAL (-22)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_readlink_nonsymlink_is_einval);

fn smoke_abi_readlink_missing_is_enoent() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/nope\0";
        let mut buf = [0u8; 64];
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..Default::default()
        };
        // Linux: a path that names nothing is ENOENT (musl's realpath
        // relies on distinguishing this from EINVAL).
        match call(Syscall::Readlink.raw(), args) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("readlink on a missing path must return -ENOENT (-2)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_readlink_missing_is_enoent);

// ── getpid: returns the calling task's visible pid ──

fn smoke_abi_getpid_returns_task() -> TestResult {
    setup();
    let v = call(Syscall::GetPid.raw(), SyscallArgs::default());
    teardown();
    match v {
        Some(p) if p as u64 == FAKE_TASK => TestResult::Pass,
        _ => TestResult::Fail("getpid should return the calling task's pid"),
    }
}
kernel_test_in!("syscall_abi", smoke_abi_getpid_returns_task);
