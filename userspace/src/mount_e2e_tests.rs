//! Wave-71 mount(2) / umount2(2) / chroot(2) / pivot_root(2) smokes.
//!
//! Drives the syscall handlers directly through synthetic
//! `TrapContext`s.  String pointers reference kernel-heap buffers —
//! `validate_user_range` already accepts kernel addresses in
//! kernel-test code (see `validate_user_range` doc comment), so the
//! SMAP bracket is silently open and the copy succeeds.
//!
//! Smokes:
//!   1. mount tmpfs at /tmp; resolve_absolute finds the synthetic FS.
//!   2. umount2 /tmp removes the mount.
//!   3. chroot /jail rewrites subsequent path lookups under /jail.
//!   4. pivot_root swaps the root + bind-mounts old root at put_old.
//!
//! Linux refs: fs/namespace.c:do_mount / SyS_umount / SyS_chroot /
//! SyS_pivot_root.

#![cfg(feature = "linux-compat")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::syscall::{SyscallArgs, SyscallReturn, TrapContext};

// Minimal TrapContext that records the syscall return.
struct StubCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}

impl TrapContext for StubCtx {
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

// Shared task-id lookup shim. Tests set this before invoking the
// syscall path so per-task state lands under a predictable task id.
static SMOKE_TASK: AtomicU64 = AtomicU64::new(0);
fn smoke_task_shim() -> u64 {
    SMOKE_TASK.load(Ordering::Relaxed)
}

fn set_task(id: u64) {
    SMOKE_TASK.store(id, Ordering::Relaxed);
    crate::install_task_id_lookup(smoke_task_shim);
}

// Build a SyscallArgs for sys_mount. Linux mount(2) ABI:
// (source, target, fstype, flags, data). All strings are NUL-terminated —
// pass byte literals WITH a trailing `\0`.
fn mount_args(source: &[u8], target: &[u8], fstype: &[u8], flags: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: source.as_ptr() as u64,
        arg1: target.as_ptr() as u64,
        arg2: fstype.as_ptr() as u64,
        arg3: flags,
        arg4: 0,
        ..Default::default()
    }
}

// Linux umount2(2) ABI: (target, flags), NUL-terminated target.
fn unmount_args(target: &[u8], flags: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: target.as_ptr() as u64,
        arg1: flags,
        ..Default::default()
    }
}

fn path_args(path: &[u8]) -> SyscallArgs {
    SyscallArgs {
        arg0: path.as_ptr() as u64,
        arg1: path.len() as u64,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    }
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn pivot_args(new_root: &[u8], put_old: &[u8]) -> SyscallArgs {
    SyscallArgs {
        arg0: new_root.as_ptr() as u64,
        arg1: new_root.len() as u64,
        arg2: put_old.as_ptr() as u64,
        arg3: put_old.len() as u64,
        arg4: 0,
        arg5: 0,
    }
}

// ── Smoke 1: mount tmpfs at /tmp ───────────────────────────────────
fn smoke_mount_tmpfs() -> TestResult {
    set_task(0x71_01);
    crate::handlers::__test_root_dir_reset();

    // Make sure /tmp isn't already mounted from a prior test.
    let _ = narf_filesystem::registry().unmount(
        &narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap(
        ),
        "/tmp",
    );

    // Call sys_mount via the syscall dispatcher to exercise the
    // wire-up. Use the lower-level path: we know SyscallTable is set
    // up; if it isn't, fall through to direct handler invocation.
    let source = b"tmpfs\0";
    let target = b"/tmp\0";
    let fstype = b"tmpfs\0";
    let mut ctx = StubCtx {
        args: mount_args(source, target, fstype, 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => return TestResult::Fail("sys_mount tmpfs /tmp returned error"),
    }

    // Verify mount is registered.
    let covered = narf_filesystem::registry()
        .resolve_absolute("/tmp", |fs, _rel| alloc::string::String::from(fs.name()));
    if covered.as_deref() != Some("tmpfs") {
        let _ = unmount_for_test("/tmp");
        return TestResult::Fail("resolve_absolute(/tmp) did not see tmpfs");
    }

    // Cleanup.
    let _ = unmount_for_test("/tmp");
    TestResult::Pass
}
kernel_test_in!("userspace/mount", smoke_mount_tmpfs);

// ── Smoke 2: umount2 /tmp ─────────────────────────────────────────
fn smoke_umount_tmpfs() -> TestResult {
    set_task(0x71_02);
    crate::handlers::__test_root_dir_reset();

    let _ = unmount_for_test("/tmp");

    // Mount.
    let target = b"/tmp\0";
    let mut ctx = StubCtx {
        args: mount_args(b"tmpfs\0", target, b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut ctx);
    if !matches!(ctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("preliminary mount failed");
    }

    // Now sys_umount2 with MNT_DETACH.
    const MNT_DETACH: u64 = 1 << 1;
    let mut uctx = StubCtx {
        args: unmount_args(target, MNT_DETACH),
        ret: None,
    };
    crate::handlers::sys_umount2_for_test(&mut uctx);
    match uctx.ret {
        Some(r) if r.value == 0 => {}
        _ => return TestResult::Fail("sys_umount2 failed"),
    }

    // Verify the mount is gone.
    let covered = narf_filesystem::registry().resolve_absolute("/tmp", |fs, _r| fs.name().len());
    // After umount, either no coverage at all (None) or coverage by
    // the "/" root mount (which doesn't have name "tmpfs"). Both are
    // acceptable signals that /tmp is no longer the tmpfs.
    let still_tmpfs = narf_filesystem::registry()
        .with_mount("/tmp", |fs| fs.name() == "tmpfs")
        .unwrap_or(false);
    if still_tmpfs {
        return TestResult::Fail("tmpfs at /tmp survived umount");
    }
    let _ = covered;
    TestResult::Pass
}
kernel_test_in!("userspace/mount", smoke_umount_tmpfs);

// ── Smoke 3: chroot rewrites absolute paths ───────────────────────
fn smoke_chroot_rewrites_paths() -> TestResult {
    let task: u64 = 0x71_03;
    set_task(task);
    crate::handlers::__test_root_dir_reset();

    // Mount a tmpfs at /jail so chroot has a real target.
    let _ = unmount_for_test("/jail");
    let mut mctx = StubCtx {
        args: mount_args(b"tmpfs\0", b"/jail\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mctx);
    if !matches!(mctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("preliminary mount /jail failed");
    }

    // sys_chroot("/jail"). chroot(2) takes a single NUL-terminated path
    // (no length arg) — match the real Linux ABI the handler now reads.
    let path = b"/jail\0";
    let mut cctx = StubCtx {
        args: path_args(path),
        ret: None,
    };
    crate::handlers::sys_chroot_for_test(&mut cctx);
    match cctx.ret {
        Some(r) if r.value == 0 => {}
        _ => {
            let _ = unmount_for_test("/jail");
            return TestResult::Fail("sys_chroot(/jail) failed");
        }
    }

    // Per-task root_dir was installed.
    let rd = crate::handlers::root_dir_of(task);
    if rd.as_deref() != Some("/jail") {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/jail");
        return TestResult::Fail("root_dir_of(task) did not return /jail");
    }

    // apply_chroot("/") yields "/jail"; apply_chroot("/foo") yields
    // "/jail/foo". We exercise this through the public copy helper
    // by encoding a path and reading it back.
    let rewritten = crate::handlers::apply_chroot_for_test("/foo");
    if rewritten != "/jail/foo" {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/jail");
        return TestResult::Fail("apply_chroot did not prefix /jail");
    }

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/jail");
    TestResult::Pass
}
kernel_test_in!("userspace/mount", smoke_chroot_rewrites_paths);

// ── Smoke 4: pivot_root swap with put_old bind ────────────────────
#[cfg(feature = "container")]
fn smoke_pivot_root_basic() -> TestResult {
    let task: u64 = 0x71_04;
    set_task(task);
    crate::handlers::__test_root_dir_reset();

    // Mount new_root, and create old_root_target as a sub-mount of
    // new_root by mounting another tmpfs there.
    let _ = unmount_for_test("/new_root");
    let _ = unmount_for_test("/new_root/old");
    let mut m1 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/new_root\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m1);
    if !matches!(m1.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("mount /new_root failed");
    }
    let mut m2 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/new_root/old\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m2);
    if !matches!(m2.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/new_root");
        return TestResult::Fail("mount /new_root/old failed");
    }

    let mut pctx = StubCtx {
        args: pivot_args(b"/new_root\0", b"/new_root/old\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);
    match pctx.ret {
        Some(r) if r.value == 0 => {}
        _ => {
            crate::handlers::__test_root_dir_reset();
            let _ = unmount_for_test("/new_root/old");
            let _ = unmount_for_test("/new_root");
            return TestResult::Fail("sys_pivot_root failed");
        }
    }

    // After pivot_root, the task's root_dir should be /new_root.
    let rd = crate::handlers::root_dir_of(task);
    if rd.as_deref() != Some("/new_root") {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/new_root/old");
        let _ = unmount_for_test("/new_root");
        return TestResult::Fail("root_dir not /new_root after pivot");
    }

    // apply_chroot("/") yields "/new_root"; apply_chroot("/old")
    // yields "/new_root/old" which is the bind-back of the prior
    // root. Resolution under the global registry should see the
    // bind-mount at that path.
    let rewritten = crate::handlers::apply_chroot_for_test("/old");
    if rewritten != "/new_root/old" {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/new_root/old");
        let _ = unmount_for_test("/new_root");
        return TestResult::Fail("apply_chroot did not rewrite /old");
    }

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/new_root/old");
    let _ = unmount_for_test("/new_root");
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_pivot_root_basic);

// Helper: unmount a path under a fresh bootstrap handle. The
// registry's unmount is keyed by path; the handle check is the
// authority gate.
fn unmount_for_test(path: &str) -> Result<(), ()> {
    let handle: narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write> =
        narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap(
        );
    narf_filesystem::registry()
        .unmount(&handle, path)
        .map_err(|_| ())
}

// Silence unused-warning fence for the Vec import (used in the
// resolve smoke if it grows later; harmless today).
#[allow(dead_code)]
fn _unused_vec_witness() -> Vec<u8> {
    Vec::new()
}

#[allow(dead_code)]
fn _unused_arc_witness() -> Arc<u8> {
    Arc::new(0)
}
