#![cfg(feature = "cgroup")]
//! Smoke tests for `cgroupfs` (cgroup-v2 unified hierarchy).
//!
//! Driven through the public VFS surface (`DirOps` / `FileOps`) plus
//! the membership lifecycle hooks, against the global cgroup tree.
//! Each test uses a uniquely-named child cgroup and distinct fake pids
//! so they don't perturb each other or the boot-time root membership.
//!
//! Covers:
//!   1. mkdir creates a child; lookup_dir + enumerate reflect it; dup → Busy
//!   2. Control-file set: root omits type/events/freeze; children have them
//!   3. cgroup.procs write→read roundtrip; task_exited clears membership
//!   4. cgroup.events `populated` tracks membership (0 → 1 → 0)
//!   5. rmdir refuses populated / non-empty cgroups, succeeds when empty
//!   6. fork_inherit places a child process in its parent's cgroup
//!   7. subtree_control rejects enabling an unavailable controller

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::cgroupfs::{fork_inherit, task_exited, CgroupFs};
use crate::{DirOps, FileType, FsInstance};

// Single-poll future driver — every cgroupfs future is Ready on first
// poll (no external await points).
fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    unsafe fn no_op(_: *const ()) {}
    unsafe fn no_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
    // SAFETY: the vtable's clone/wake/drop are all no-ops over a null
    // data pointer, so the Waker is inert — sound to construct and
    // never observed after this single-threaded poll.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local owned by this frame and never moved
    // again before the pinned poll below completes.
    let pinned = unsafe { core::pin::Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

fn root_dir() -> Arc<dyn DirOps> {
    CgroupFs::new().root()
}

/// Read an attribute file's full contents as a String.
fn read_attr(dir: &Arc<dyn DirOps>, name: &str) -> Option<String> {
    let f = dir.lookup(name)?;
    let mut out = String::new();
    let mut off = 0u64;
    let mut buf = [0u8; 256];
    loop {
        let n = poll_once(f.read(off, &mut buf))?.ok()?;
        if n == 0 {
            break;
        }
        out.push_str(core::str::from_utf8(&buf[..n]).ok()?);
        off += n as u64;
    }
    Some(out)
}

/// Write bytes to an attribute file. Returns Ok(()) on success.
fn write_attr(dir: &Arc<dyn DirOps>, name: &str, data: &[u8]) -> Result<(), ()> {
    let f = dir.lookup(name).ok_or(())?;
    match poll_once(f.write(0, data)) {
        Some(Ok(_)) => Ok(()),
        _ => Err(()),
    }
}

/// Move a pid into `dir`'s cgroup via a cgroup.procs write.
fn attach_pid(dir: &Arc<dyn DirOps>, pid: u64) -> Result<(), ()> {
    write_attr(dir, "cgroup.procs", pid.to_string().as_bytes())
}

fn enumerate_has(dir: &Arc<dyn DirOps>, name: &str, ft: FileType) -> bool {
    dir.enumerate(0, 256)
        .into_iter()
        .any(|(n, t)| n == name && t == ft)
}

// ── 1. mkdir / lookup_dir / enumerate / dup ─────────────────────────

fn smoke_cgroup_mkdir_creates_child() -> TestResult {
    let root = root_dir();
    let name = "t_mkdir";
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    if root.lookup_dir(name).is_none() {
        return TestResult::Fail("lookup_dir missing after mkdir");
    }
    if !enumerate_has(&root, name, FileType::Dir) {
        return TestResult::Fail("enumerate missing child dir");
    }
    // Duplicate mkdir → Busy.
    if poll_once(root.mkdir(name)).map(|r| r.is_err()) != Some(true) {
        return TestResult::Fail("duplicate mkdir did not fail");
    }
    let _ = child;
    // Cleanup.
    let _ = poll_once(root.rmdir(name));
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_mkdir_creates_child);

// ── 2. Control-file set differs root vs child ───────────────────────

fn smoke_cgroup_control_files() -> TestResult {
    let root = root_dir();
    // Root has controllers/subtree_control/procs but NOT type/events/freeze.
    if root.lookup("cgroup.controllers").is_none() {
        return TestResult::Fail("root missing cgroup.controllers");
    }
    if root.lookup("cgroup.procs").is_none() {
        return TestResult::Fail("root missing cgroup.procs");
    }
    if root.lookup("cgroup.type").is_some() {
        return TestResult::Fail("root unexpectedly has cgroup.type");
    }
    if root.lookup("cgroup.events").is_some() {
        return TestResult::Fail("root unexpectedly has cgroup.events");
    }
    // Child has the non-root files.
    let name = "t_files";
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let ok = child.lookup("cgroup.type").is_some()
        && child.lookup("cgroup.events").is_some()
        && child.lookup("cgroup.freeze").is_some()
        && child.lookup("cgroup.procs").is_some();
    let _ = poll_once(root.rmdir(name));
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("child missing a non-root control file")
    }
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_control_files);

// ── 3. cgroup.procs write → read roundtrip ──────────────────────────

fn smoke_cgroup_procs_roundtrip() -> TestResult {
    let root = root_dir();
    let name = "t_procs";
    let pid: u64 = 3_300_000_001;
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    if attach_pid(&child, pid).is_err() {
        return TestResult::Fail("write cgroup.procs failed");
    }
    let body = read_attr(&child, "cgroup.procs").unwrap_or_default();
    if !body.contains(&pid.to_string()) {
        let _ = poll_once(root.rmdir(name));
        return TestResult::Fail("member pid not listed after write");
    }
    // Exit clears membership.
    task_exited(pid);
    let after = read_attr(&child, "cgroup.procs").unwrap_or_default();
    let _ = poll_once(root.rmdir(name));
    if after.contains(&pid.to_string()) {
        return TestResult::Fail("member still listed after task_exited");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_procs_roundtrip);

// ── 4. cgroup.events populated tracking ─────────────────────────────

fn smoke_cgroup_events_populated() -> TestResult {
    let root = root_dir();
    let name = "t_events";
    let pid: u64 = 3_300_000_002;
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let empty = read_attr(&child, "cgroup.events").unwrap_or_default();
    if !empty.contains("populated 0") {
        let _ = poll_once(root.rmdir(name));
        return TestResult::Fail("fresh cgroup not populated 0");
    }
    let _ = attach_pid(&child, pid);
    let full = read_attr(&child, "cgroup.events").unwrap_or_default();
    if !full.contains("populated 1") {
        task_exited(pid);
        let _ = poll_once(root.rmdir(name));
        return TestResult::Fail("populated did not flip to 1");
    }
    task_exited(pid);
    let cleared = read_attr(&child, "cgroup.events").unwrap_or_default();
    let _ = poll_once(root.rmdir(name));
    if !cleared.contains("populated 0") {
        return TestResult::Fail("populated did not fall back to 0");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_events_populated);

// ── 5. rmdir rules ──────────────────────────────────────────────────

fn smoke_cgroup_rmdir_rules() -> TestResult {
    let root = root_dir();
    let name = "t_rmdir";
    let pid: u64 = 3_300_000_003;
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    // Populated → Busy.
    let _ = attach_pid(&child, pid);
    if poll_once(root.rmdir(name)).map(|r| r.is_err()) != Some(true) {
        task_exited(pid);
        let _ = poll_once(root.rmdir(name));
        return TestResult::Fail("rmdir of populated cgroup did not fail");
    }
    // Non-empty (has subchild) → Busy.
    task_exited(pid);
    let _ = poll_once(child.mkdir("inner"));
    if poll_once(root.rmdir(name)).map(|r| r.is_err()) != Some(true) {
        return TestResult::Fail("rmdir of non-empty cgroup did not fail");
    }
    let _ = poll_once(child.rmdir("inner"));
    // Now empty → ok.
    if poll_once(root.rmdir(name)).map(|r| r.is_ok()) != Some(true) {
        return TestResult::Fail("rmdir of empty cgroup failed");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_rmdir_rules);

// ── 6. fork_inherit ─────────────────────────────────────────────────

fn smoke_cgroup_fork_inherit() -> TestResult {
    let root = root_dir();
    let name = "t_fork";
    let parent: u64 = 3_300_000_010;
    let child_pid: u64 = 3_300_000_011;
    let cg = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    // Put the parent into the child cgroup, then fork.
    let _ = attach_pid(&cg, parent);
    fork_inherit(parent, child_pid);
    let body = read_attr(&cg, "cgroup.procs").unwrap_or_default();
    let ok = body.contains(&parent.to_string()) && body.contains(&child_pid.to_string());
    task_exited(parent);
    task_exited(child_pid);
    let _ = poll_once(root.rmdir(name));
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("forked child did not inherit parent cgroup")
    }
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_fork_inherit);

// ── 7. subtree_control rejects unavailable controllers ──────────────

fn smoke_cgroup_subtree_control() -> TestResult {
    let root = root_dir();
    let name = "t_subtree";
    let cg = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    // No controllers available → "+memory" must be rejected.
    let plus = write_attr(&cg, "cgroup.subtree_control", b"+memory");
    // Disable writes are accepted no-ops.
    let minus = write_attr(&cg, "cgroup.subtree_control", b"-memory");
    let _ = poll_once(root.rmdir(name));
    match (plus, minus) {
        (Err(()), Ok(())) => TestResult::Pass,
        (Ok(()), _) => TestResult::Fail("enabling unavailable controller was accepted"),
        _ => TestResult::Fail("disabling controller was rejected"),
    }
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_subtree_control);

// ── Controller smokes ───────────────────────────────────────────────
//
// A controller's interface files appear on a cgroup only when its name
// is in the *parent's* subtree_control. To exercise a controller we
// enable it on the root, operate on a root child (which then carries
// the files), and always disable it again so the shared root is left
// pristine for other tests.
#[cfg(any(feature = "cgroup-pids", feature = "cgroup-misc"))]
fn with_root_controller(
    ctrl: &str,
    child: &str,
    f: impl FnOnce(&Arc<dyn DirOps>) -> TestResult,
) -> TestResult {
    let root = root_dir();
    let mut plus = String::from("+");
    plus.push_str(ctrl);
    if write_attr(&root, "cgroup.subtree_control", plus.as_bytes()).is_err() {
        return TestResult::Fail("could not enable controller on root");
    }
    let disable = |root: &Arc<dyn DirOps>| {
        let mut minus = String::from("-");
        minus.push_str(ctrl);
        let _ = write_attr(root, "cgroup.subtree_control", minus.as_bytes());
    };
    let cg = match poll_once(root.mkdir(child)) {
        Some(Ok(c)) => c,
        _ => {
            disable(&root);
            return TestResult::Fail("mkdir failed");
        }
    };
    let result = f(&cg);
    let _ = poll_once(root.rmdir(child));
    disable(&root);
    result
}

#[cfg(feature = "cgroup-pids")]
fn smoke_cgroup_pids() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::pids::PidsController));
    with_root_controller("pids", "t_pids", |cg| {
        if cg.lookup("pids.max").is_none() {
            return TestResult::Fail("pids.max absent after enabling pids");
        }
        if write_attr(cg, "pids.max", b"1").is_err() {
            return TestResult::Fail("set pids.max failed");
        }
        let a: u64 = 4_100_000_001;
        let b: u64 = 4_100_000_002;
        let r1 = attach_pid(cg, a); // within limit
        let r2 = attach_pid(cg, b); // exceeds pids.max=1
        let cur = read_attr(cg, "pids.current").unwrap_or_default();
        task_exited(a);
        task_exited(b);
        match (r1, r2) {
            (Ok(()), Err(())) if cur.trim() == "1" => TestResult::Pass,
            (Ok(()), Ok(())) => TestResult::Fail("pids.max not enforced"),
            _ => TestResult::Fail("unexpected pids attach result"),
        }
    })
}
#[cfg(feature = "cgroup-pids")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_pids);

#[cfg(feature = "cgroup-misc")]
fn smoke_cgroup_misc() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::misc::MiscController));
    crate::cgroupfs::misc::register_misc_resource("testres", 100);
    with_root_controller("misc", "t_misc", |cg| {
        if cg.lookup("misc.max").is_none() {
            return TestResult::Fail("misc.max absent after enabling misc");
        }
        let w1 = write_attr(cg, "misc.max", b"testres 50"); // known key
        let body = read_attr(cg, "misc.max").unwrap_or_default();
        let w2 = write_attr(cg, "misc.max", b"bogus 10"); // unknown key → EINVAL
        match (w1, w2) {
            (Ok(()), Err(())) if body.contains("testres 50") => TestResult::Pass,
            (Ok(()), Ok(())) => TestResult::Fail("misc.max accepted unknown key"),
            _ => TestResult::Fail("unexpected misc.max behavior"),
        }
    })
}
#[cfg(feature = "cgroup-misc")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_misc);

#[cfg(feature = "cgroup-psi")]
fn smoke_cgroup_psi() -> TestResult {
    let root = root_dir();
    let cg = match poll_once(root.mkdir("t_psi")) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let has = cg.lookup("cpu.pressure").is_some()
        && cg.lookup("memory.pressure").is_some()
        && cg.lookup("io.pressure").is_some();
    let body = read_attr(&cg, "cpu.pressure").unwrap_or_default();
    // PSI pressure files are non-root only.
    let root_absent = root.lookup("cpu.pressure").is_none();
    let _ = poll_once(root.rmdir("t_psi"));
    if has && body.contains("some avg10=") && root_absent {
        TestResult::Pass
    } else {
        TestResult::Fail("psi pressure files missing or malformed")
    }
}
#[cfg(feature = "cgroup-psi")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_psi);
