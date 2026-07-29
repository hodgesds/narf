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
        arg1: put_old.as_ptr() as u64,
        arg2: 0,
        arg3: 0,
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

// Direct kernel boot has no userspace chroot launcher. It must nevertheless
// install the exact same per-task root before a dynamic PID 1 starts resolving
// its interpreter and first pathname.
fn smoke_boot_root_is_visible_before_first_task_instruction() -> TestResult {
    const TASK: u64 = 0x71_03_01;
    set_task(TASK);
    crate::handlers::__test_root_dir_reset();

    let installed = crate::handlers::install_root_dir(TASK, "/mnt/");
    let root = crate::handlers::root_dir_of(TASK);
    let resolved = crate::handlers::apply_chroot_for_test("/lib64/ld-linux-x86-64.so.2");

    crate::handlers::__test_root_dir_reset();
    if !installed {
        return TestResult::Fail("direct boot root was rejected");
    }
    if root.as_deref() != Some("/mnt") {
        return TestResult::Fail("direct boot root was not normalized");
    }
    if resolved != "/mnt/lib64/ld-linux-x86-64.so.2" {
        return TestResult::Fail("direct boot root did not resolve PT_INTERP path");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/mount",
    smoke_boot_root_is_visible_before_first_task_instruction
);

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

// ── Smoke 4b: pivot_root(".", ".") — the container idiom ───────────
// systemd's mount_switch_root_pivot (and runc, crun, …) do
// `fchdir(new_root_fd); pivot_root(".", ".")`, passing RELATIVE "." paths.
// pivot_root must resolve them against the cwd, not reject non-absolute
// paths. Rejecting them made systemd-udevd's PrivateMounts=yes sandbox fail
// 226/EXIT_NAMESPACE and restart-loop, wedging Fedora boot before dbus.
#[cfg(feature = "container")]
fn smoke_pivot_root_relative_dot() -> TestResult {
    let task: u64 = 0x71_05;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    let _ = unmount_for_test("/new_root2");
    let mut m1 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/new_root2\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m1);
    if !matches!(m1.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("mount /new_root2 failed");
    }

    // cwd := /new_root2 (as systemd does via fchdir on the new-root fd).
    let cwd_path = b"/new_root2\0";
    let mut cd = StubCtx {
        args: SyscallArgs {
            arg0: cwd_path.as_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_chdir(&mut cd);
    if !matches!(cd.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/new_root2");
        return TestResult::Fail("chdir /new_root2 failed");
    }

    // pivot_root(".", ".") — both relative to the cwd.
    let mut pctx = StubCtx {
        args: pivot_args(b".\0", b".\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);
    let ok = matches!(pctx.ret, Some(r) if r.value == 0)
        && crate::handlers::root_dir_of(task).as_deref() == Some("/new_root2");

    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/new_root2");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("pivot_root(\".\", \".\") should resolve cwd and swap root")
    }
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_pivot_root_relative_dot);

// The full systemd switch-root sequence: fchdir(new_root); pivot_root(".",".");
// umount2(".", MNT_DETACH). After pivot_root moves the root, the relative "."
// must still resolve to the cwd (the new root) — NOT a doubly-chroot-prefixed
// path. A double prefix made umount2 (and the MS_MOVE fallback) return ENOENT →
// "Failed to set up mount namespacing: No such file or directory" →
// 226/EXIT_NAMESPACE, restart-looping systemd-udevd.
#[cfg(feature = "container")]
fn smoke_pivot_root_switch_root_umount_dot() -> TestResult {
    let task: u64 = 0x71_06;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/swr");
    let mut m1 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/swr\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m1);
    if !matches!(m1.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("mount /swr failed");
    }

    // fchdir-equivalent: cwd := /swr (systemd fchdir's the new-root fd).
    let cwd_path = b"/swr\0";
    let mut cd = StubCtx {
        args: SyscallArgs {
            arg0: cwd_path.as_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_chdir(&mut cd);
    if !matches!(cd.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/swr");
        return TestResult::Fail("chdir /swr failed");
    }

    // pivot_root(".", ".") — moves the root to /swr.
    let mut pctx = StubCtx {
        args: pivot_args(b".\0", b".\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);
    if !matches!(pctx.ret, Some(r) if r.value == 0) {
        crate::handlers::__test_root_dir_reset();
        crate::handlers::__test_cwd_reset();
        let _ = unmount_for_test("/swr");
        return TestResult::Fail("pivot_root(\".\",\".\") failed");
    }

    // umount2(".", MNT_DETACH=2): "." must resolve to the cwd (the new root),
    // not "/swr/swr", so it finds the mount and returns 0.
    let dot = b".\0";
    let mut um = StubCtx {
        args: SyscallArgs {
            arg0: dot.as_ptr() as u64,
            arg1: 2,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_umount2_for_test(&mut um);
    let umount_ok = matches!(um.ret, Some(r) if r.value == 0);

    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/swr");
    let _ = unmount_for_test("/swr");

    if umount_ok {
        TestResult::Pass
    } else {
        TestResult::Fail(
            "umount2(\".\") after pivot_root must resolve to the cwd (new root) and return 0",
        )
    }
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_pivot_root_switch_root_umount_dot);

// Build SyscallArgs for a single-word syscall (arg0 only), e.g. unshare(flags).
fn flags_args(flags: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: flags,
        ..Default::default()
    }
}

// Build SyscallArgs for open_tree(dfd, path, flags).
fn open_tree_args(dfd: u64, path: &[u8], flags: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: dfd,
        arg1: path.as_ptr() as u64,
        arg2: flags,
        ..Default::default()
    }
}

// Build SyscallArgs for move_mount(from_dfd, from_path, to_dfd, to_path, flags).
fn move_mount_args(from_dfd: u64, from_path: &[u8], to_dfd: u64, to_path: &[u8]) -> SyscallArgs {
    SyscallArgs {
        arg0: from_dfd,
        arg1: from_path.as_ptr() as u64,
        arg2: to_dfd,
        arg3: to_path.as_ptr() as u64,
        arg4: 0,
        arg5: 0,
    }
}

// ── Smoke 5: mount-namespace isolation ─────────────────────────────
// unshare(CLONE_NEWNS) snapshots the caller's mount table into a
// private MountNamespace. A tmpfs mounted AFTER the unshare is visible
// to the task (via its namespace) but NOT in the global VfsRegistry or
// to a task that still shares the global view. A mount that existed
// BEFORE the unshare survives in the private snapshot.
// Linux ref: fs/namespace.c:copy_mnt_ns / do_new_mount.
fn smoke_mount_ns_isolation() -> TestResult {
    let task: u64 = 0x71_06;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    // Start from a clean private-namespace slot for this task.
    crate::handlers::clear_current_mount_namespace_for_test();

    // A mount that exists BEFORE unshare, in the global registry.
    let _ = unmount_for_test("/pre_ns");
    let mut mpre = StubCtx {
        args: mount_args(b"tmpfs\0", b"/pre_ns\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mpre);
    if !matches!(mpre.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("preliminary global mount /pre_ns failed");
    }

    // unshare(CLONE_NEWNS): snapshot the current (global) table privately.
    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/pre_ns");
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    let ns = match crate::handlers::current_mount_namespace() {
        Some(ns) => ns,
        None => {
            let _ = unmount_for_test("/pre_ns");
            return TestResult::Fail("no private mount namespace after unshare");
        }
    };

    // The pre-unshare mount survives in the private snapshot.
    if ns.mount_id_at("/pre_ns").is_none() {
        crate::handlers::clear_current_mount_namespace_for_test();
        let _ = unmount_for_test("/pre_ns");
        return TestResult::Fail("pre-unshare mount missing from snapshot");
    }

    // Now mount a tmpfs AFTER the unshare — it lands in the private ns.
    let mut mpriv = StubCtx {
        args: mount_args(b"tmpfs\0", b"/priv_ns\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mpriv);
    if !matches!(mpriv.ret, Some(r) if r.value == 0) {
        crate::handlers::clear_current_mount_namespace_for_test();
        let _ = unmount_for_test("/pre_ns");
        return TestResult::Fail("private mount /priv_ns failed");
    }

    // Visible in the task's private namespace…  Use an EXACT mount-path check
    // (`list()`), NOT `mount_id_at` — the latter does longest-prefix matching
    // and the root `/` mount always matches as a fallback, so it can't tell
    // whether `/priv_ns` is specifically mounted.
    let seen_priv = crate::handlers::current_mount_namespace()
        .map(|ns| ns.list().iter().any(|p| p == "/priv_ns"))
        .unwrap_or(false);
    // …but NOT in the global registry.
    let global_has_priv = narf_filesystem::registry()
        .list()
        .iter()
        .any(|p| p == "/priv_ns");

    // A task that never unshared sees the global registry only. Switch the
    // task-id shim to a different task and confirm it can't see /priv_ns.
    set_task(0x71_06_ff);
    crate::handlers::clear_current_mount_namespace_for_test(); // no-op; other task
    let other_sees_priv = crate::handlers::current_mount_namespace().is_some()
        || narf_filesystem::registry()
            .list()
            .iter()
            .any(|p| p == "/priv_ns");

    // Cleanup: drop the private namespace + the global pre mount.
    set_task(task);
    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/pre_ns");
    // /priv_ns lived only in the (now-dropped) private ns; nothing to unmount
    // globally, but be defensive.
    let _ = unmount_for_test("/priv_ns");

    if !seen_priv {
        return TestResult::Fail("private mount not visible in own namespace");
    }
    if global_has_priv {
        return TestResult::Fail("private mount leaked into global registry");
    }
    if other_sees_priv {
        return TestResult::Fail("private mount visible to a non-unshared task");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/mount", smoke_mount_ns_isolation);

// ── Smoke 5g: umount2 of a private pseudo-fs actually removes it ────
// systemd's mount_private_dev (PrivateDevices=/ProtectProc=/… — userdbd,
// logind, most sandboxed services) builds a private /dev tmpfs+devfs, then
// umount_recursive()s everything under the target before MS_MOVE'ing it into
// place. umount_recursive reads /proc/self/mountinfo, unmounts each entry, and
// LOOPS until none remain. NARF protects the GLOBAL singleton /dev,/proc,/sys
// from a destructive umount by returning success-without-removing — but that
// no-op must NOT apply inside a private mount namespace, where umount pops only
// that namespace's entry. Applying it there left the devfs in mountinfo, so
// umount_recursive spun FOREVER and the service's executor hung before execve
// (Type=notify timeout). Assert umount2 of a private devfs truly removes it.
#[cfg(feature = "container")]
fn smoke_umount_private_pseudofs_actually_removes() -> TestResult {
    let task: u64 = 0x71_10;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // unshare(CLONE_NEWNS): private mount table.
    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // Mount a devfs (a "protected" pseudo-fs name) in the private namespace.
    let _ = unmount_for_test("/priv_dev");
    let mut md = StubCtx {
        args: mount_args(b"devtmpfs\0", b"/priv_dev\0", b"devtmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut md);
    if !matches!(md.ret, Some(r) if r.value == 0) {
        crate::handlers::clear_current_mount_namespace_for_test();
        return TestResult::Fail("mount devtmpfs /priv_dev failed");
    }
    let present_before = crate::handlers::current_mount_namespace()
        .map(|ns| ns.list().iter().any(|p| p == "/priv_dev"))
        .unwrap_or(false);

    // umount2("/priv_dev", UMOUNT_NOFOLLOW) — must actually pop the entry.
    const UMOUNT_NOFOLLOW: u64 = 0x8;
    let mut um = StubCtx {
        args: unmount_args(b"/priv_dev\0", UMOUNT_NOFOLLOW),
        ret: None,
    };
    crate::handlers::sys_umount2_for_test(&mut um);
    let umount_ok = matches!(um.ret, Some(r) if r.value == 0);
    let present_after = crate::handlers::current_mount_namespace()
        .map(|ns| ns.list().iter().any(|p| p == "/priv_dev"))
        .unwrap_or(false);

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    if !present_before {
        return TestResult::Fail("private devfs mount was not registered");
    }
    if !umount_ok {
        return TestResult::Fail("umount2 of a private devfs did not return 0");
    }
    if present_after {
        return TestResult::Fail(
            "umount2 no-op'd a private devfs (still mounted) — umount_recursive would loop",
        );
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!(
    "userspace/mount",
    smoke_umount_private_pseudofs_actually_removes
);

// ── Smoke 5b: pivot_root's put_old bind stays in the private ns ─────
// A systemd service sandbox does `unshare(CLONE_NEWNS)` and only then
// `pivot_root`. The put_old bind pivot_root installs (so the old root is
// reachable from inside the new root) must land in the caller's PRIVATE
// mount table — NOT the global registry. Leaking it globally made every
// executor's root assembly order-dependent: a fresh service's
// find_executable() intermittently hit ENOENT / 203/EXIT_EXEC while a later
// one, snapshotting the polluted global table, happened to succeed.
// Regression guard for the `registry().bind_mount` → `current_bind_mount`
// fix in sys_pivot_root.
#[cfg(feature = "container")]
fn smoke_pivot_root_putold_bind_private() -> TestResult {
    let task: u64 = 0x71_0b;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // The new root must exist as a directory before the pivot.
    let _ = unmount_for_test("/pvr_new");
    let _ = unmount_for_test("/pvr_new/old");
    let mut mnr = StubCtx {
        args: mount_args(b"tmpfs\0", b"/pvr_new\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mnr);
    if !matches!(mnr.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("mount /pvr_new failed");
    }

    // unshare(CLONE_NEWNS): the task now has a private mount table.
    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/pvr_new");
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // pivot_root(new_root, put_old): binds the prior root (/) at put_old.
    let mut pctx = StubCtx {
        args: pivot_args(b"/pvr_new\0", b"/pvr_new/old\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);
    let pivot_ok = matches!(pctx.ret, Some(r) if r.value == 0);

    // The put_old bind must be present in the PRIVATE namespace…
    let priv_has_putold = crate::handlers::current_mount_namespace()
        .map(|ns| ns.list().iter().any(|p| p == "/pvr_new/old"))
        .unwrap_or(false);
    // …and must NOT have leaked into the global registry.
    let global_has_putold = narf_filesystem::registry()
        .list()
        .iter()
        .any(|p| p == "/pvr_new/old");

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/pvr_new/old");
    let _ = unmount_for_test("/pvr_new");

    if !pivot_ok {
        return TestResult::Fail("pivot_root in a private namespace failed");
    }
    if !priv_has_putold {
        return TestResult::Fail("put_old bind missing from the private namespace");
    }
    if global_has_putold {
        return TestResult::Fail("put_old bind leaked into the global registry");
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_pivot_root_putold_bind_private);

// ── Smoke 5c: recursive bind of / exposes the whole subtree ────────
// A systemd service sandbox recursively binds the host root
// (`mount("/", "/run/systemd/mount-rootfs", MS_BIND|MS_REC)`) as the first
// step of building its private root, then pivot_roots into it. If the
// recursive bind fails to expose the source's subtree, the sandboxed
// service's find_executable("/usr/lib/systemd/…") hits ENOENT and dies
// 203/EXIT_EXEC. Assert the bound tree resolves a deep source directory.
// Skips gracefully when the boot rootfs lacks /usr (non-distro test images).
#[cfg(feature = "container")]
fn smoke_recursive_bind_exposes_subtree() -> TestResult {
    let task: u64 = 0x71_0c;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // Baseline: only run where the boot rootfs actually has /usr (the Fedora
    // vblk image). Otherwise there is nothing to expose — skip.
    let global_has_usr = narf_filesystem::registry().clone_tree_at("/usr").is_some();
    if !global_has_usr {
        return TestResult::Skip("boot rootfs has no /usr to bind");
    }

    // unshare(CLONE_NEWNS): private mount table.
    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // Recursive bind: mount("/", "/swr_rb", MS_BIND|MS_REC).
    const MS_BIND: u64 = 0x1000;
    const MS_REC: u64 = 0x4000;
    let _ = unmount_for_test("/swr_rb");
    let mut mb = StubCtx {
        args: mount_args(b"/\0", b"/swr_rb\0", b"none\0", MS_BIND | MS_REC),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mb);
    let bind_ok = matches!(mb.ret, Some(r) if r.value == 0);

    // The bound root must expose the source's /usr subtree at /swr_rb/usr.
    let exposed = crate::handlers::current_mount_namespace()
        .and_then(|ns| ns.clone_tree_at("/swr_rb/usr"))
        .is_some();

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/swr_rb");

    if !bind_ok {
        return TestResult::Fail("recursive bind of / failed");
    }
    if !exposed {
        return TestResult::Fail("recursive bind of / did not expose /usr subtree");
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_recursive_bind_exposes_subtree);

// ── Smoke 5d: full systemd sandbox root swap keeps deep paths resolvable ─
// Reproduces the exact sequence a systemd service sandbox runs after
// unshare(CLONE_NEWNS): recursively bind a source root onto the mount-rootfs
// dir, chdir into it, pivot_root(".", "."), umount2(".", MNT_DETACH). After
// the swap, opening a deep path (systemd does
// open("/usr/lib/systemd/systemd-udevd", O_PATH) in find_executable) must
// still resolve — i.e. apply_chroot() + the private namespace must reach the
// bound subtree. A regression here is a service dying 203/EXIT_EXEC
// ("Unable to locate executable").
#[cfg(feature = "container")]
fn smoke_sandbox_root_swap_deep_path_resolves() -> TestResult {
    let task: u64 = 0x71_0d;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // A source root (tmpfs) with a deep subdir, mounted before the unshare so
    // it stands in for the host "/" that the sandbox binds.
    let _ = unmount_for_test("/srcr");
    let mut msrc = StubCtx {
        args: mount_args(b"tmpfs\0", b"/srcr\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut msrc);
    if !matches!(msrc.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("mount /srcr tmpfs failed");
    }
    for dir in [b"/srcr/usr\0".as_slice(), b"/srcr/usr/lib\0".as_slice()] {
        let mut mk = StubCtx {
            args: SyscallArgs {
                arg0: dir.as_ptr() as u64,
                arg1: 0o755,
                ..Default::default()
            },
            ret: None,
        };
        crate::handlers::sys_mkdir(&mut mk);
        // 0 (created) or -EEXIST are both fine.
    }

    // unshare(CLONE_NEWNS).
    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/srcr");
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // Recursively bind the source root onto the mount-rootfs dir.
    const MS_BIND: u64 = 0x1000;
    const MS_REC: u64 = 0x4000;
    let _ = unmount_for_test("/mrfs");
    let mut mb = StubCtx {
        args: mount_args(b"/srcr\0", b"/mrfs\0", b"none\0", MS_BIND | MS_REC),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mb);
    if !matches!(mb.ret, Some(r) if r.value == 0) {
        crate::handlers::clear_current_mount_namespace_for_test();
        let _ = unmount_for_test("/srcr");
        return TestResult::Fail("recursive bind /srcr -> /mrfs failed");
    }

    // systemd opens the new root O_PATH|O_DIRECTORY|O_CLOEXEC (0x290000) and
    // fchdir's THAT fd — not chdir(path). Reproduce faithfully: an O_PATH fd
    // opened through the bind, then fchdir, then pivot_root(".", ".").
    const AT_FDCWD: u64 = 0xffff_ffff_ffff_ff9c;
    let nr_path = b"/mrfs\0";
    let mut op = StubCtx {
        args: SyscallArgs {
            arg0: AT_FDCWD,
            arg1: nr_path.as_ptr() as u64,
            arg2: 0x29_0000, // O_PATH|O_DIRECTORY|O_CLOEXEC
            arg3: 0,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_openat(&mut op);
    let nr_fd = match op.ret {
        Some(r) if (r.value as i64) >= 0 => r.value,
        _ => {
            crate::handlers::clear_current_mount_namespace_for_test();
            let _ = unmount_for_test("/mrfs");
            let _ = unmount_for_test("/srcr");
            return TestResult::Fail("openat(/mrfs, O_PATH) failed");
        }
    };
    let mut cd = StubCtx {
        args: SyscallArgs {
            arg0: nr_fd,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_fchdir(&mut cd);
    if !matches!(cd.ret, Some(r) if r.value == 0) {
        crate::handlers::clear_current_mount_namespace_for_test();
        let _ = unmount_for_test("/mrfs");
        let _ = unmount_for_test("/srcr");
        return TestResult::Fail("fchdir(new_root fd) failed");
    }
    let mut pctx = StubCtx {
        args: pivot_args(b".\0", b".\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);
    let pivot_ok = matches!(pctx.ret, Some(r) if r.value == 0);
    // umount2(".", MNT_DETACH): drop the stacked old root.
    let mut um = StubCtx {
        args: unmount_args(b".\0", 2),
        ret: None,
    };
    crate::handlers::sys_umount2_for_test(&mut um);

    // After the swap, root == /mrfs. Opening "/usr/lib" must resolve to the
    // bound source subtree. Mirror open_impl: apply_chroot, then resolve in
    // the private namespace.
    let resolved = crate::handlers::apply_chroot_for_test("/usr/lib");
    let deep_ok = crate::handlers::current_mount_namespace()
        .and_then(|ns| ns.clone_tree_at(&resolved))
        .is_some();

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/mrfs");
    let _ = unmount_for_test("/srcr");

    if !pivot_ok {
        return TestResult::Fail("pivot_root(\".\",\".\") in sandbox failed");
    }
    if !deep_ok {
        return TestResult::Fail("deep path /usr/lib unresolvable after sandbox root swap");
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!(
    "userspace/mount",
    smoke_sandbox_root_swap_deep_path_resolves
);

// ── Smoke 5e: execve resolves the binary via the PRIVATE namespace ─
// A systemd service sandbox unshare(CLONE_NEWNS)s and binds its rootfs into a
// private mount before pivot_root, so the service binary is reachable ONLY via
// the task's private mount table. execve must resolve namespace-aware (like the
// O_PATH open in find_executable does) — resolving against the GLOBAL registry
// makes a pivoted service's binary invisible → ENOENT → 203/EXIT_EXEC. Mount a
// (bogus) binary ONLY in the private namespace and assert execve does NOT
// return ENOENT: it resolves the bytes, then fails ELF validation with a
// different error. Global-registry resolution would return ENOENT here.
#[cfg(feature = "container")]
fn smoke_execve_resolves_private_ns_binary() -> TestResult {
    let task: u64 = 0x71_0e;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // unshare(CLONE_NEWNS): private mount table.
    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // A memfs holding a non-ELF "binary", mounted ONLY in the private ns.
    // Non-ELF bytes (no \x7fELF magic) so execve rejects at validation without
    // building a user context.
    let junk = [0xAAu8; 128];
    let fs: Arc<dyn narf_filesystem::FsInstance> = Arc::new(narf_filesystem::MemFs::with_seeds(
        "pxprog",
        &[("prog", &junk)],
    ));
    let auth = narf_filesystem::bootstrap_mount_authority();
    if crate::handlers::current_mount_arc(&auth, "/pxns_bin", fs).is_err() {
        crate::handlers::clear_current_mount_namespace_for_test();
        return TestResult::Fail("private mount of /pxns_bin failed");
    }

    // Sanity: the path is NOT visible in the global registry.
    let global_has = narf_filesystem::registry()
        .list()
        .iter()
        .any(|p| p == "/pxns_bin");

    // execve("/pxns_bin/prog", ["prog"], []).
    let path = b"/pxns_bin/prog\0";
    let arg0 = b"prog\0";
    let argv: [u64; 2] = [arg0.as_ptr() as u64, 0];
    let envp: [u64; 1] = [0];
    let mut ectx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: argv.as_ptr() as u64,
            arg2: envp.as_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_execve(&mut ectx);
    // ENOENT (-2) means execve could NOT resolve the private-ns binary.
    let is_enoent = matches!(ectx.ret, Some(r) if (r.value as i64) == -2);

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    if global_has {
        return TestResult::Fail("private mount leaked into global registry");
    }
    if is_enoent {
        return TestResult::Fail(
            "execve resolved binary via global registry, not private ns (ENOENT)",
        );
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_execve_resolves_private_ns_binary);

// ── Smoke 5f: the ELF-interpreter read resolves via the private ns ─
// execve loads a dynamic binary's interpreter (ld.so) via read_path_from_vfs.
// A pivoted service sandbox reaches /lib64/ld-linux-*.so.2 ONLY through its
// private mount namespace; a global-registry read returns None → the PIE loads
// with no interpreter → it jumps to a null entry (#PF faultva=0 rip=0, SIGSEGV)
// before any syscall. Assert the interpreter read sees a file mounted only in
// the private namespace.
#[cfg(feature = "container")]
fn smoke_interp_read_uses_private_ns() -> TestResult {
    let task: u64 = 0x71_0f;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    const CLONE_NEWNS: u64 = 0x0002_0000;
    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // A memfs "ld.so" mounted ONLY in the private namespace.
    let payload = b"\x7fELF-fake-interpreter-bytes";
    let fs: Arc<dyn narf_filesystem::FsInstance> = Arc::new(narf_filesystem::MemFs::with_seeds(
        "pxld",
        &[("ld.so", payload.as_slice())],
    ));
    let auth = narf_filesystem::bootstrap_mount_authority();
    if crate::handlers::current_mount_arc(&auth, "/pxinterp", fs).is_err() {
        crate::handlers::clear_current_mount_namespace_for_test();
        return TestResult::Fail("private mount of /pxinterp failed");
    }

    // Global read must miss; namespace-aware read must hit.
    let global_hit = narf_filesystem::registry()
        .resolve_absolute("/pxinterp/ld.so", |fs, rel| {
            crate::handlers::poll_blocking(narf_filesystem::resolve_async(fs.root(), rel))
                .and_then(|r| r.ok())
        })
        .flatten()
        .is_some();
    let ns_read = crate::process::read_path_from_vfs("/pxinterp/ld.so");

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    if global_hit {
        return TestResult::Fail("interpreter leaked into global registry");
    }
    match ns_read {
        Some(bytes) if bytes == payload => TestResult::Pass,
        Some(_) => TestResult::Fail("interpreter read returned wrong bytes"),
        None => TestResult::Fail("interpreter read missed the private-ns file"),
    }
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_interp_read_uses_private_ns);

// ── Smoke 6: pivot_root to a missing new_root fails ────────────────
// pivot_root must reject a new_root that doesn't exist under the prior
// root (returns -1); the task's root_dir must be left untouched.
// Linux ref: fs/namespace.c:do_move_mount / SyS_pivot_root ENOENT path.
#[cfg(feature = "container")]
fn smoke_pivot_root_missing_target() -> TestResult {
    let task: u64 = 0x71_07;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    // Ensure the target really doesn't exist.
    let _ = unmount_for_test("/does_not_exist");

    let mut pctx = StubCtx {
        args: pivot_args(b"/does_not_exist\0", b"/does_not_exist/old\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);
    let rejected = matches!(pctx.ret, Some(r) if r.value == (-1i64) as u64);
    // root_dir must be unchanged (still the default: no per-task entry).
    let root_untouched = crate::handlers::root_dir_of(task).is_none();

    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    if rejected && root_untouched {
        TestResult::Pass
    } else {
        TestResult::Fail("pivot_root(missing new_root) must fail and leave root unchanged")
    }
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_pivot_root_missing_target);

// ── Smoke 7: pivot_root container idiom via chdir + relative put_old ─
// A different scenario from smoke_pivot_root_relative_dot: chdir into a
// PARENT dir, mount the new root and its put_old target as a sub-mount,
// then pivot_root with a relative new_root and a relative put_old that
// resolve against the cwd. Confirms the root swaps and the old root is
// reachable at the resolved put_old.
#[cfg(feature = "container")]
fn smoke_pivot_root_relative_paths() -> TestResult {
    let task: u64 = 0x71_08;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    let _ = unmount_for_test("/stage/root8");
    let _ = unmount_for_test("/stage/root8/old");
    let _ = unmount_for_test("/stage");

    // new_root at /stage/root8, put_old target as a sub-mount below it.
    let mut m0 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/stage\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m0);
    let mut m1 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/stage/root8\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m1);
    let mut m2 = StubCtx {
        args: mount_args(b"tmpfs\0", b"/stage/root8/old\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut m2);
    if !matches!(m1.ret, Some(r) if r.value == 0) || !matches!(m2.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/stage/root8/old");
        let _ = unmount_for_test("/stage/root8");
        let _ = unmount_for_test("/stage");
        return TestResult::Fail("staging mounts for relative pivot_root failed");
    }

    // cwd := /stage, then pivot_root("root8", "root8/old") — both relative.
    let cwd_path = b"/stage\0";
    let mut cd = StubCtx {
        args: SyscallArgs {
            arg0: cwd_path.as_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_chdir(&mut cd);

    let mut pctx = StubCtx {
        args: pivot_args(b"root8\0", b"root8/old\0"),
        ret: None,
    };
    crate::handlers::sys_pivot_root_for_test(&mut pctx);

    let swapped = matches!(pctx.ret, Some(r) if r.value == 0)
        && crate::handlers::root_dir_of(task).as_deref() == Some("/stage/root8");
    // apply_chroot("/old") rewrites to /stage/root8/old — the bind-back
    // of the prior root under the new root.
    let old_reachable = crate::handlers::apply_chroot_for_test("/old") == "/stage/root8/old";

    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/stage/root8/old");
    let _ = unmount_for_test("/stage/root8");
    let _ = unmount_for_test("/stage");

    if swapped && old_reachable {
        TestResult::Pass
    } else {
        TestResult::Fail("relative pivot_root(root8, root8/old) should swap root + bind old")
    }
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/mount", smoke_pivot_root_relative_paths);

// ── Smoke 8: open_tree(CLONE) → move_mount round-trip ──────────────
// open_tree(dfd, path, OPEN_TREE_CLONE) clones the mount covering a
// path into a detached-mount fd; move_mount then re-attaches that fd at
// a fresh target. Assert the fs resolves at the new target afterward.
// Linux ref: fs/namespace.c:SyS_open_tree / SyS_move_mount.
fn smoke_open_tree_move_mount() -> TestResult {
    let task: u64 = 0x71_09;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/ot_src");
    let _ = unmount_for_test("/ot_dst");

    // Source mount to clone.
    let mut msrc = StubCtx {
        args: mount_args(b"tmpfs\0", b"/ot_src\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut msrc);
    if !matches!(msrc.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("source mount /ot_src failed");
    }

    // open_tree("/ot_src", OPEN_TREE_CLONE) → detached-mount fd.
    const OPEN_TREE_CLONE: u64 = 0x0000_0001;
    let mut otctx = StubCtx {
        args: open_tree_args(0, b"/ot_src\0", OPEN_TREE_CLONE),
        ret: None,
    };
    crate::mount_api::sys_open_tree(&mut otctx);
    let tree_fd = match otctx.ret {
        Some(r) if r.status == SyscallReturn::OK && (r.value as i64) >= 0 => r.value,
        _ => {
            let _ = unmount_for_test("/ot_src");
            return TestResult::Fail("open_tree(CLONE) did not return an fd");
        }
    };

    // move_mount(tree_fd, "", AT_FDCWD, "/ot_dst").
    let mut mmctx = StubCtx {
        args: move_mount_args(tree_fd, b"\0", 0, b"/ot_dst\0"),
        ret: None,
    };
    crate::mount_api::sys_move_mount(&mut mmctx);
    let moved = matches!(mmctx.ret, Some(r) if r.value == 0);

    // The moved subtree resolves at the new target.
    let resolves_at_dst = narf_filesystem::registry()
        .resolve_absolute("/ot_dst", |fs, _rel| alloc::string::String::from(fs.name()))
        .as_deref()
        == Some("tmpfs");

    // Cleanup: close the detached fd (consumed by move_mount already) +
    // both mount points + the task's fd table.
    crate::fd::detach(task);
    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/ot_dst");
    let _ = unmount_for_test("/ot_src");

    if moved && resolves_at_dst {
        TestResult::Pass
    } else {
        TestResult::Fail("open_tree(CLONE)+move_mount should re-attach the fs at the new target")
    }
}
kernel_test_in!("userspace/mount", smoke_open_tree_move_mount);

// ── Smoke 8b: move_mount onto an OCCUPIED path stacks, not EBUSY ───
// systemd's ProtectHostname= sandbox clones /proc/sys/kernel/domainname with
// open_tree(CLONE) and move_mount()s the read-only copy back over the live
// one. NARF's registry rejected the overmount with EBUSY, so sys_move_mount
// returned -16 and the whole service namespace setup failed with
// 226/EXIT_NAMESPACE (udevd restart-loop, wedging the Fedora boot). With mount
// stacking the overmount succeeds and leaves TWO entries at the target.
// Linux ref: fs/namespace.c:do_move_mount (overmount allowed).
fn smoke_move_mount_overmount_no_ebusy() -> TestResult {
    let task: u64 = 0x71_20;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/omm_src");
    let _ = unmount_for_test("/omm_dst");
    let _ = unmount_for_test("/omm_dst");

    // A source to clone and an ALREADY-OCCUPIED destination.
    let mut msrc = StubCtx {
        args: mount_args(b"tmpfs\0", b"/omm_src\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut msrc);
    let mut mdst = StubCtx {
        args: mount_args(b"tmpfs\0", b"/omm_dst\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mdst);
    if !matches!(msrc.ret, Some(r) if r.value == 0) || !matches!(mdst.ret, Some(r) if r.value == 0)
    {
        return TestResult::Fail("setup mounts failed");
    }

    const OPEN_TREE_CLONE: u64 = 0x0000_0001;
    let mut otctx = StubCtx {
        args: open_tree_args(0, b"/omm_src\0", OPEN_TREE_CLONE),
        ret: None,
    };
    crate::mount_api::sys_open_tree(&mut otctx);
    let tree_fd = match otctx.ret {
        Some(r) if r.status == SyscallReturn::OK && (r.value as i64) >= 0 => r.value,
        _ => {
            crate::fd::detach(task);
            let _ = unmount_for_test("/omm_dst");
            let _ = unmount_for_test("/omm_src");
            return TestResult::Fail("open_tree(CLONE) did not return an fd");
        }
    };

    // move_mount onto the OCCUPIED /omm_dst.
    let mut mmctx = StubCtx {
        args: move_mount_args(tree_fd, b"\0", 0, b"/omm_dst\0"),
        ret: None,
    };
    crate::mount_api::sys_move_mount(&mut mmctx);
    let ret = mmctx.ret.map(|r| r.value as i64);

    // Two stacked entries at /omm_dst now (original + moved-over).
    let count = narf_filesystem::registry()
        .list()
        .iter()
        .filter(|p| p.as_str() == "/omm_dst")
        .count();

    crate::fd::detach(task);
    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/omm_dst");
    let _ = unmount_for_test("/omm_dst");
    let _ = unmount_for_test("/omm_src");

    if ret == Some(0) && count == 2 {
        TestResult::Pass
    } else {
        TestResult::Fail("move_mount onto an occupied path must stack (ok + 2 entries), not EBUSY")
    }
}
kernel_test_in!("userspace/mount", smoke_move_mount_overmount_no_ebusy);

// ── Smoke 9: chroot applied exactly once ───────────────────────────
// apply_chroot must prefix the root exactly ONCE — a double-prefix
// ("/jail9/jail9/...") was a real container bug. Also confirm the root
// path itself ("/") maps to the jail root, not "/jail9/".
fn smoke_chroot_applied_once() -> TestResult {
    let task: u64 = 0x71_0a;
    set_task(task);
    crate::handlers::__test_root_dir_reset();

    let _ = unmount_for_test("/jail9");
    let mut mctx = StubCtx {
        args: mount_args(b"tmpfs\0", b"/jail9\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mctx);
    if !matches!(mctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("preliminary mount /jail9 failed");
    }

    let mut cctx = StubCtx {
        args: path_args(b"/jail9\0"),
        ret: None,
    };
    crate::handlers::sys_chroot_for_test(&mut cctx);
    if !matches!(cctx.ret, Some(r) if r.value == 0) {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/jail9");
        return TestResult::Fail("sys_chroot(/jail9) failed");
    }

    let once = crate::handlers::apply_chroot_for_test("/etc/passwd") == "/jail9/etc/passwd";
    let root_maps = crate::handlers::apply_chroot_for_test("/") == "/jail9/";

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/jail9");

    if once && root_maps {
        TestResult::Pass
    } else {
        TestResult::Fail("apply_chroot must prefix /jail9 exactly once")
    }
}
kernel_test_in!("userspace/mount", smoke_chroot_applied_once);

// ── Smoke 10: chroot + `..` escape is contained ────────────────────
// A chrooted task must not break out of its jail via `..`. resolve_cwd_path
// normalizes `..` in the USER view first (so `../../etc` from "/" collapses
// to "/etc") THEN re-roots under the chroot — the result stays under the
// jail, never above it. Also exercises the chroot+cwd interaction: a
// relative path resolves against the cwd and lands under the jail.
fn smoke_chroot_escape_contained() -> TestResult {
    let task: u64 = 0x71_0b;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();

    let _ = unmount_for_test("/jailB");
    let mut mctx = StubCtx {
        args: mount_args(b"tmpfs\0", b"/jailB\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mctx);
    if !matches!(mctx.ret, Some(r) if r.value == 0) {
        return TestResult::Fail("preliminary mount /jailB failed");
    }

    let mut cctx = StubCtx {
        args: path_args(b"/jailB\0"),
        ret: None,
    };
    crate::handlers::sys_chroot_for_test(&mut cctx);
    if !matches!(cctx.ret, Some(r) if r.value == 0) {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/jailB");
        return TestResult::Fail("sys_chroot(/jailB) failed");
    }

    // An absolute path trying to climb out with `..` collapses to a path
    // still under the jail.
    let escape = crate::handlers::resolve_cwd_path(task, "/../../../etc/shadow");
    let contained = escape == "/jailB/etc/shadow";

    // chroot + cwd: chdir("/work"), then a relative path resolves under
    // the cwd and re-roots under the jail exactly once. chdir(2) validates the
    // target is a real directory, so make `/work` (== /jailB/work under the
    // jail) exist first by mounting a tmpfs there (mount targets are
    // chroot-resolved, so "/work" lands at /jailB/work).
    let mut mwork = StubCtx {
        args: mount_args(b"tmpfs\0", b"/work\0", b"tmpfs\0", 0),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut mwork);
    let cwd_path = b"/work\0";
    let mut cd = StubCtx {
        args: SyscallArgs {
            arg0: cwd_path.as_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_chdir(&mut cd);
    let cd_ok = matches!(cd.ret, Some(r) if r.value == 0);
    let rel = crate::handlers::resolve_cwd_path(task, "sub/file");
    let cwd_ok = cd_ok && rel == "/jailB/work/sub/file";

    let _ = unmount_for_test("/jailB/work");
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    let _ = unmount_for_test("/jailB");

    if contained && cwd_ok {
        TestResult::Pass
    } else {
        TestResult::Fail("chroot must contain `..` escapes and re-root cwd-relative paths once")
    }
}
kernel_test_in!("userspace/mount", smoke_chroot_escape_contained);

// ── Flag constants (mirror handlers/mod.rs; Linux mount(2) ABI) ────
const MS_REMOUNT: u64 = 1 << 5; // 0x0020
const MS_BIND: u64 = 1 << 12; // 0x1000
const MS_MOVE: u64 = 1 << 13; // 0x2000
const MS_REC: u64 = 1 << 14; // 0x4000
const MS_PRIVATE: u64 = 1 << 18; // 0x40000
const MS_SLAVE: u64 = 1 << 19; // 0x80000
const CLONE_NEWNS: u64 = 0x0002_0000;

// Convenience: run sys_mount and report whether it returned value==0.
fn mount_ok(source: &[u8], target: &[u8], fstype: &[u8], flags: u64) -> bool {
    let mut ctx = StubCtx {
        args: mount_args(source, target, fstype, flags),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut ctx);
    matches!(ctx.ret, Some(r) if r.value == 0)
}

// True iff `path` is an EXACT mount entry in the global registry. Uses
// `list()`, NOT `mount_id_at` (which longest-prefix-matches and always falls
// back to the root `/` mount — that fallback caused a false test failure).
fn registry_has(path: &str) -> bool {
    narf_filesystem::registry().list().iter().any(|p| p == path)
}

// Name of the FsInstance visible at an absolute path (via the global
// registry), or None if nothing distinct covers it.
fn fs_name_at(path: &str) -> Option<alloc::string::String> {
    narf_filesystem::registry()
        .resolve_absolute(path, |fs, _rel| alloc::string::String::from(fs.name()))
}

// ── Smoke 11: bind mount makes the source subtree visible at dst ───
// mount(src, dst, MS_BIND) forwards dst's root to src's DirOps. A file
// created in the source tmpfs is then reachable through the dst path.
// Linux ref: fs/namespace.c:do_loopback (mount --bind).
fn smoke_bind_mount_file_visible() -> TestResult {
    set_task(0x71_0c);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/bind_src");
    let _ = unmount_for_test("/bind_dst");

    if !mount_ok(b"tmpfs\0", b"/bind_src\0", b"tmpfs\0", 0) {
        return TestResult::Fail("mount /bind_src failed");
    }

    // Create a marker file in the source tmpfs root.
    let created = narf_filesystem::registry()
        .resolve_absolute("/bind_src", |fs, _rel| {
            matches!(
                crate::handlers::poll_blocking(fs.root().create("marker")),
                Some(Ok(_))
            )
        })
        .unwrap_or(false);
    if !created {
        let _ = unmount_for_test("/bind_src");
        return TestResult::Fail("could not create marker in /bind_src");
    }

    // Bind /bind_src → /bind_dst.
    if !mount_ok(b"/bind_src\0", b"/bind_dst\0", b"\0", MS_BIND) {
        let _ = unmount_for_test("/bind_src");
        return TestResult::Fail("bind mount /bind_src → /bind_dst failed");
    }

    // The bind is registered at dst and forwards the source fs name.
    let registered = registry_has("/bind_dst");
    let name_ok = fs_name_at("/bind_dst").as_deref() == Some("tmpfs");
    // The marker created via src is visible through dst.
    let visible = narf_filesystem::registry()
        .resolve_absolute("/bind_dst", |fs, _rel| fs.root().lookup("marker").is_some())
        .unwrap_or(false);

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/bind_dst");
    let _ = unmount_for_test("/bind_src");

    if registered && name_ok && visible {
        TestResult::Pass
    } else {
        TestResult::Fail("bind mount must expose the source subtree (incl. its files) at dst")
    }
}
kernel_test_in!("userspace/mount", smoke_bind_mount_file_visible);

// ── Smoke 12: recursive bind (MS_BIND|MS_REC) clones sub-mounts ────
// A mount nested UNDER the source must reappear nested under the target.
// Linux ref: fs/namespace.c:do_loopback with recurse=1 (mount --rbind).
fn smoke_recursive_bind_clones_submount() -> TestResult {
    set_task(0x71_0d);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/rb_src/nested");
    let _ = unmount_for_test("/rb_src");
    let _ = unmount_for_test("/rb_dst/nested");
    let _ = unmount_for_test("/rb_dst");

    if !mount_ok(b"tmpfs\0", b"/rb_src\0", b"tmpfs\0", 0)
        || !mount_ok(b"tmpfs\0", b"/rb_src/nested\0", b"tmpfs\0", 0)
    {
        let _ = unmount_for_test("/rb_src/nested");
        let _ = unmount_for_test("/rb_src");
        return TestResult::Fail("staging mounts for recursive bind failed");
    }

    // Recursive bind: /rb_src (+ its /rb_src/nested sub-mount) → /rb_dst.
    if !mount_ok(b"/rb_src\0", b"/rb_dst\0", b"\0", MS_BIND | MS_REC) {
        let _ = unmount_for_test("/rb_src/nested");
        let _ = unmount_for_test("/rb_src");
        return TestResult::Fail("recursive bind /rb_src → /rb_dst failed");
    }

    let dst_root = registry_has("/rb_dst");
    let dst_nested = registry_has("/rb_dst/nested");

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/rb_dst/nested");
    let _ = unmount_for_test("/rb_dst");
    let _ = unmount_for_test("/rb_src/nested");
    let _ = unmount_for_test("/rb_src");

    if dst_root && dst_nested {
        TestResult::Pass
    } else {
        TestResult::Fail("MS_REC bind must clone the nested sub-mount under the target")
    }
}
kernel_test_in!("userspace/mount", smoke_recursive_bind_clones_submount);

// ── Smoke 13: MS_MOVE relocates a mount ────────────────────────────
// mount(old, new, MS_MOVE) detaches the mount at `old` and re-attaches it
// at `new`: it resolves at `new` and no longer at `old`.
// Linux ref: fs/namespace.c:do_move_mount.
fn smoke_move_mount_relocates() -> TestResult {
    set_task(0x71_0e);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/mv_from");
    let _ = unmount_for_test("/mv_to");

    if !mount_ok(b"tmpfs\0", b"/mv_from\0", b"tmpfs\0", 0) {
        return TestResult::Fail("mount /mv_from failed");
    }

    // MS_MOVE: source == old path, target == new path, NULL fstype.
    if !mount_ok(b"/mv_from\0", b"/mv_to\0", b"\0", MS_MOVE) {
        let _ = unmount_for_test("/mv_from");
        return TestResult::Fail("MS_MOVE /mv_from → /mv_to failed");
    }

    let at_new = registry_has("/mv_to");
    let gone_from_old = !registry_has("/mv_from");
    let name_ok = fs_name_at("/mv_to").as_deref() == Some("tmpfs");

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/mv_to");
    let _ = unmount_for_test("/mv_from");

    if at_new && gone_from_old && name_ok {
        TestResult::Pass
    } else {
        TestResult::Fail("MS_MOVE must relocate the mount to the new path and clear the old")
    }
}
kernel_test_in!("userspace/mount", smoke_move_mount_relocates);

// ── Smoke 14: pseudo-fs double-mount is idempotent (single entry) ──
// The registry supports mount stacking for real binds/overmounts (see
// smoke_registry_overmount_stacks), but the sys_mount pseudo-fs arm
// deliberately DEDUPS API filesystems: re-mounting a tmpfs onto an
// already-mounted target short-circuits to success BEFORE reaching the
// registry, so it reports ok and leaves exactly ONE entry for that path
// (NARF's pseudo-fs are shared singletons; stacking identical views is
// pointless). This runs the pseudo-fs arm, not the stacking path.
// Linux ref: fs/namespace.c:do_new_mount (repeated API-fs mount).
fn smoke_double_mount_idempotent() -> TestResult {
    set_task(0x71_0f);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/dbl");

    if !mount_ok(b"tmpfs\0", b"/dbl\0", b"tmpfs\0", 0) {
        return TestResult::Fail("first mount /dbl failed");
    }
    // Second mount of the same fstype at the same path: idempotent success.
    let second_ok = mount_ok(b"tmpfs\0", b"/dbl\0", b"tmpfs\0", 0);

    // Exactly one entry for /dbl (no stacking / duplicate).
    let count = narf_filesystem::registry()
        .list()
        .iter()
        .filter(|p| p.as_str() == "/dbl")
        .count();

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/dbl");

    if second_ok && count == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("tmpfs double-mount must be idempotent (ok, single registry entry)")
    }
}
kernel_test_in!("userspace/mount", smoke_double_mount_idempotent);

// ── Smoke 15: propagation-only mount is a no-op success ────────────
// mount(NULL, target, NULL, MS_SLAVE|MS_REC) / MS_PRIVATE changes only the
// propagation type of an existing mount. NARF has no propagation model, so
// it returns success and creates NO new mount at the target.
// systemd does `mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)` right after
// clone(CLONE_NEWNS); failing it aborts the sandbox ("Protocol error").
// Linux ref: fs/namespace.c:do_change_type.
fn smoke_propagation_only_noop() -> TestResult {
    set_task(0x71_10);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // A propagation-only change on "/" (SLAVE|REC) succeeds and adds nothing.
    let before = narf_filesystem::registry().list().len();
    let slave_ok = mount_ok(b"\0", b"/\0", b"\0", MS_SLAVE | MS_REC);
    // MS_PRIVATE|MS_REC on an unmounted path also succeeds without creating it.
    let priv_ok = mount_ok(b"\0", b"/prop_none\0", b"\0", MS_PRIVATE | MS_REC);
    let after = narf_filesystem::registry().list().len();
    let no_new_mount = !registry_has("/prop_none");
    let count_stable = before == after;

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/prop_none");

    if slave_ok && priv_ok && no_new_mount && count_stable {
        TestResult::Pass
    } else {
        TestResult::Fail("propagation-only mount must succeed and create no new mount")
    }
}
kernel_test_in!("userspace/mount", smoke_propagation_only_noop);

// ── Smoke 16: mount_setattr size validation ────────────────────────
// mount_setattr(dfd, path, flags, attr, size): a well-formed size (1..=64)
// returns 0; size 0 or > 64 returns -EINVAL. NARF doesn't enforce per-mount
// attrs, so a valid call just succeeds.
// Linux ref: fs/namespace.c:SyS_mount_setattr (usize check).
fn smoke_mount_setattr_size_validation() -> TestResult {
    set_task(0x71_11);

    const EINVAL: u64 = (-22i64) as u64;
    // Well-formed: size == 32 (sizeof struct mount_attr) → 0.
    let mut good = StubCtx {
        args: SyscallArgs {
            arg4: 32,
            ..Default::default()
        },
        ret: None,
    };
    crate::mount_api::sys_mount_setattr(&mut good);
    let good_ok = matches!(good.ret, Some(r) if r.value == 0);

    // size == 0 → EINVAL.
    let mut zero = StubCtx {
        args: SyscallArgs {
            arg4: 0,
            ..Default::default()
        },
        ret: None,
    };
    crate::mount_api::sys_mount_setattr(&mut zero);
    let zero_einval = matches!(zero.ret, Some(r) if r.value == EINVAL);

    // size == 65 (> 64) → EINVAL.
    let mut big = StubCtx {
        args: SyscallArgs {
            arg4: 65,
            ..Default::default()
        },
        ret: None,
    };
    crate::mount_api::sys_mount_setattr(&mut big);
    let big_einval = matches!(big.ret, Some(r) if r.value == EINVAL);

    if good_ok && zero_einval && big_einval {
        TestResult::Pass
    } else {
        TestResult::Fail("mount_setattr: size 1..=64 → 0, size 0 or >64 → EINVAL")
    }
}
kernel_test_in!("userspace/mount", smoke_mount_setattr_size_validation);

// ── Smoke 17: mount-namespace snapshot depth ───────────────────────
// A deeper look at unshare(CLONE_NEWNS) than smoke_mount_ns_isolation: a
// mount made AFTER the unshare must live ONLY in the private namespace's
// `list()` and be absent from the GLOBAL registry snapshot; a mount that
// predates the unshare must be present in the private snapshot.
// Linux ref: fs/namespace.c:copy_mnt_ns.
fn smoke_mount_ns_snapshot_depth() -> TestResult {
    let task: u64 = 0x71_12;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    // Predates unshare — lands in the global registry.
    let _ = unmount_for_test("/ns_pre");
    if !mount_ok(b"tmpfs\0", b"/ns_pre\0", b"tmpfs\0", 0) {
        return TestResult::Fail("pre-unshare mount /ns_pre failed");
    }

    let mut uctx = StubCtx {
        args: flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        let _ = unmount_for_test("/ns_pre");
        return TestResult::Fail("unshare(CLONE_NEWNS) failed");
    }

    // The pre-existing mount is captured in the private snapshot's list().
    let snapshot_has_pre = crate::handlers::current_mount_namespace()
        .map(|ns| ns.list().iter().any(|p| p == "/ns_pre"))
        .unwrap_or(false);

    // A mount made AFTER unshare lands only in the private namespace.
    if !mount_ok(b"tmpfs\0", b"/ns_post\0", b"tmpfs\0", 0) {
        crate::handlers::clear_current_mount_namespace_for_test();
        let _ = unmount_for_test("/ns_pre");
        return TestResult::Fail("post-unshare private mount /ns_post failed");
    }
    let priv_has_post = crate::handlers::current_mount_namespace()
        .map(|ns| ns.list().iter().any(|p| p == "/ns_post"))
        .unwrap_or(false);
    // …and is invisible in the global registry snapshot.
    let global_lacks_post = !registry_has("/ns_post");

    crate::handlers::clear_current_mount_namespace_for_test();
    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/ns_pre");
    let _ = unmount_for_test("/ns_post");

    if snapshot_has_pre && priv_has_post && global_lacks_post {
        TestResult::Pass
    } else {
        TestResult::Fail("CLONE_NEWNS snapshot must keep pre-mounts + isolate post-mounts")
    }
}
kernel_test_in!("userspace/mount", smoke_mount_ns_snapshot_depth);

// ── Smoke 18: umount2 real-vs-nonmount return semantics ────────────
// umount2 of a real mount returns 0 and drops it from registry().list();
// umount2 of a path that is not a mount point returns the -1 sentinel
// (SyscallReturn::ok(!0)) and leaves the table unchanged.
// Linux ref: fs/namespace.c:SyS_umount (EINVAL on non-mount).
fn smoke_umount_real_vs_nonmount() -> TestResult {
    set_task(0x71_13);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/um_real");

    if !mount_ok(b"tmpfs\0", b"/um_real\0", b"tmpfs\0", 0) {
        return TestResult::Fail("mount /um_real failed");
    }
    let present_before = registry_has("/um_real");

    // umount2 of the real mount → 0, and it disappears from the registry.
    let mut u1 = StubCtx {
        args: unmount_args(b"/um_real\0", 0),
        ret: None,
    };
    crate::handlers::sys_umount2_for_test(&mut u1);
    let real_ok = matches!(u1.ret, Some(r) if r.value == 0);
    let removed = !registry_has("/um_real");

    // umount2 of a path that was never mounted → the -1 sentinel (!0).
    let mut u2 = StubCtx {
        args: unmount_args(b"/um_never\0", 0),
        ret: None,
    };
    crate::handlers::sys_umount2_for_test(&mut u2);
    let nonmount_sentinel = matches!(u2.ret, Some(r) if r.value == (-1i64) as u64);

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/um_real");

    if present_before && real_ok && removed && nonmount_sentinel {
        TestResult::Pass
    } else {
        TestResult::Fail("umount2: real mount → 0 + removed; non-mount → -1 sentinel")
    }
}
kernel_test_in!("userspace/mount", smoke_umount_real_vs_nonmount);

// ── Smoke 19: MS_REMOUNT of a live mount succeeds; of nothing → ENOENT ─
// A bind-remount (MS_REMOUNT, NULL fstype) validates the target: an existing
// mount accepts the flag update (0); a path with no mount / dir / file
// returns -ENOENT. NARF doesn't persist per-mount VFS flags, so the update
// is accept-and-record only. systemd read-only-remounts each API fs after
// mounting it.
// Linux ref: fs/namespace.c:do_remount.
fn smoke_remount_flag_update() -> TestResult {
    set_task(0x71_14);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/rmnt");

    if !mount_ok(b"tmpfs\0", b"/rmnt\0", b"tmpfs\0", 0) {
        return TestResult::Fail("mount /rmnt failed");
    }

    // Remount the live mount (NULL fstype) → success (0).
    let remount_live = mount_ok(b"\0", b"/rmnt\0", b"\0", MS_REMOUNT);

    // Remount a path that is neither a mount nor an existing dir/file → ENOENT.
    let mut miss = StubCtx {
        args: mount_args(b"\0", b"/rmnt_missing\0", b"\0", MS_REMOUNT),
        ret: None,
    };
    crate::handlers::sys_mount_for_test(&mut miss);
    let remount_missing_enoent = matches!(miss.ret, Some(r) if r.value == (-2i64) as u64);

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/rmnt");

    if remount_live && remount_missing_enoent {
        TestResult::Pass
    } else {
        TestResult::Fail("MS_REMOUNT: live mount → 0, missing target → -ENOENT")
    }
}
kernel_test_in!("userspace/mount", smoke_remount_flag_update);

// clone3(CLONE_INTO_CGROUP) resolves the cgroup fd's path to a cgroup-relative
// path by stripping the ACTUAL cgroup2 mount prefix from the live mount table —
// cgroup2 is not fixed at /sys/fs/cgroup (systemd can mount it anywhere, and a
// chroot makes the recorded path host-view). A hardcoded "/sys/fs/cgroup" strip
// would miss a cgroup2 mounted elsewhere, so the service would fall back to the
// parent cgroup and PID 1 could not attribute its sd_notify(READY=1) → the unit
// (manager_get_unit_by_pidref_cgroup) → Type=notify start timeout.
#[cfg(feature = "cgroup")]
fn smoke_clone_into_cgroup_rel_path_dynamic() -> TestResult {
    set_task(0x71_40);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let auth = narf_filesystem::bootstrap_mount_authority();
    // Mount cgroup2 at a NON-standard location.
    let _ = unmount_for_test("/oddloc/cg");
    let h = match narf_filesystem::registry().mount_arc(
        &auth,
        "/oddloc/cg",
        alloc::sync::Arc::new(narf_filesystem::CgroupFs::new()),
    ) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("mount cgroup2 at /oddloc/cg failed"),
    };

    // A path under the (non-standard) cgroup2 mount strips to the cgroup path.
    let rel = crate::handlers::cgroup_rel_path("/oddloc/cg/system.slice/test.service");
    // The mount point itself maps to the cgroup root "/".
    let root_rel = crate::handlers::cgroup_rel_path("/oddloc/cg");
    // A path under NO cgroup2 mount → None (clone3 then inherits the parent cg).
    let none = crate::handlers::cgroup_rel_path("/definitely/not/a/cgroup/x");

    let _ = narf_filesystem::registry().unmount(&h, "/oddloc/cg");

    if rel.as_deref() == Some("/system.slice/test.service")
        && root_rel.as_deref() == Some("/")
        && none.is_none()
    {
        TestResult::Pass
    } else {
        TestResult::Fail(
            "cgroup_rel_path must strip the live cgroup2 mount prefix wherever it is mounted",
        )
    }
}
#[cfg(feature = "cgroup")]
kernel_test_in!("userspace/mount", smoke_clone_into_cgroup_rel_path_dynamic);

// ── Smoke 20: chroot re-roots mount targets into the jail ──────────
// While chrooted to /cjail, mounting "/x" must register at /cjail/x in the
// GLOBAL registry (mount targets are chroot-resolved via apply_chroot). The
// jail-relative "/x" must NOT appear as a top-level registry entry.
// Linux ref: fs/namespace.c:user_path (target resolved under the task root).
fn smoke_chroot_mount_target_rerooted() -> TestResult {
    let task: u64 = 0x71_15;
    set_task(task);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    let _ = unmount_for_test("/cjail/x");
    let _ = unmount_for_test("/cjail");
    let _ = unmount_for_test("/x");

    if !mount_ok(b"tmpfs\0", b"/cjail\0", b"tmpfs\0", 0) {
        return TestResult::Fail("mount /cjail failed");
    }

    // chroot into /cjail.
    let mut cctx = StubCtx {
        args: path_args(b"/cjail\0"),
        ret: None,
    };
    crate::handlers::sys_chroot_for_test(&mut cctx);
    if !matches!(cctx.ret, Some(r) if r.value == 0) {
        crate::handlers::__test_root_dir_reset();
        let _ = unmount_for_test("/cjail");
        return TestResult::Fail("chroot /cjail failed");
    }

    // From inside the jail, mount tmpfs at "/x" — chroot-resolved to /cjail/x.
    let mounted = mount_ok(b"tmpfs\0", b"/x\0", b"tmpfs\0", 0);
    let rerooted = registry_has("/cjail/x");
    // The un-rerooted "/x" must not be a registry entry.
    let no_bare_x = !registry_has("/x");

    crate::handlers::__test_root_dir_reset();
    let _ = unmount_for_test("/cjail/x");
    let _ = unmount_for_test("/cjail");
    let _ = unmount_for_test("/x");

    if mounted && rerooted && no_bare_x {
        TestResult::Pass
    } else {
        TestResult::Fail("chroot must re-root a mount target into the jail (/cjail/x)")
    }
}
kernel_test_in!("userspace/mount", smoke_chroot_mount_target_rerooted);

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
