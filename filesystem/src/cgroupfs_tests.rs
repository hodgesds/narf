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
//!   8. /proc/[pid]/cgroup renders the v2 `0::<path>` single line
//!   9. base cpu.stat exists on every cgroup (root included) without
//!      the cpu controller; mkdir can't shadow an interface file
//!  10. cgroup.pressure round-trips 1 → 0 → 1
//!  11. freezing a parent reports `frozen 1` in a child's events
//!      (effective state) while the child's own cgroup.freeze stays 0
//!  12. the systemd manager startup shape: enable controllers on the
//!      root, mkdir a slice, no-internal-process rules, leaf placement

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

/// Each cgroup carries a unique, stable, nonzero inode (surfaced as its
/// `DirOps::ino()` and the cgroup id an init reads via `name_to_handle_at`).
/// Distinct cgroups must never share an id.
fn smoke_cgroup_inodes_distinct() -> TestResult {
    let root = root_dir();
    let a = match poll_once(root.mkdir("t_ino_a")) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir a failed"),
    };
    let b = match poll_once(root.mkdir("t_ino_b")) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir b failed"),
    };
    // A nested child too, to exercise deeper allocation.
    let a2 = match poll_once(a.mkdir("t_ino_a2")) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir a/a2 failed"),
    };
    let (ir, ia, ib, ia2) = (root.ino(), a.ino(), b.ino(), a2.ino());
    let _ = (poll_once(a.rmdir("t_ino_a2")),);
    let _ = poll_once(root.rmdir("t_ino_a"));
    let _ = poll_once(root.rmdir("t_ino_b"));
    if ir == 0 || ia == 0 || ib == 0 || ia2 == 0 {
        return TestResult::Fail("a cgroup reported inode 0");
    }
    if ia == ib || ia == ir || ia == ia2 || ib == ia2 || ib == ir {
        return TestResult::Fail("cgroup inodes collided");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_inodes_distinct);

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

// ── 4b. cgroup.events POLLPRI edge notification ─────────────────────

fn smoke_cgroup_events_pollpri_edge() -> TestResult {
    use crate::{FileOps, POLL_IN, POLL_PRI};

    let root = root_dir();
    let name = "t_events_pri";
    let pid: u64 = 3_300_000_009;
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };

    // A single, persistent open of cgroup.events — the fd whose edge
    // state we track across transitions (re-looking-up would mint a
    // fresh fd already level with the live generation).
    let ev: Arc<dyn FileOps> = match child.lookup("cgroup.events") {
        Some(f) => f,
        None => {
            let _ = poll_once(root.rmdir(name));
            return TestResult::Fail("cgroup.events absent on child");
        }
    };

    let fail = |msg: &'static str, pid: u64, name: &str| -> TestResult {
        task_exited(pid);
        let _ = poll_once(root_dir().rmdir(name));
        TestResult::Fail(msg)
    };

    // Freshly opened, level with live state: readable, no pending edge.
    if ev.poll_readiness() & POLL_PRI != 0 {
        return fail("spurious POLLPRI on fresh events fd", pid, name);
    }
    if ev.poll_readiness() & POLL_IN == 0 {
        return fail("events fd not reported readable", pid, name);
    }

    // populated 0 → 1 is an edge: POLLPRI must latch on the held fd.
    let _ = attach_pid(&child, pid);
    if ev.poll_readiness() & POLL_PRI == 0 {
        return fail("POLLPRI not set after populated transition", pid, name);
    }

    // Reading consumes the edge: POLLPRI clears, POLLIN stays.
    let mut buf = [0u8; 64];
    let _ = poll_once(ev.read(0, &mut buf));
    if ev.poll_readiness() & POLL_PRI != 0 {
        return fail("POLLPRI not cleared after read", pid, name);
    }

    // populated 1 → 0 is a fresh edge on the same fd.
    task_exited(pid);
    if ev.poll_readiness() & POLL_PRI == 0 {
        return fail("POLLPRI not re-armed after empty transition", pid, name);
    }

    let _ = poll_once(root.rmdir(name));
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_events_pollpri_edge);

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

// ── 8. /proc/[pid]/cgroup v2 format ─────────────────────────────────

fn smoke_cgroup_proc_pid_format() -> TestResult {
    use crate::cgroupfs::proc_pid_cgroup;

    // An unplaced pid is implicitly in the root cgroup: "0::/\n".
    let unplaced: u64 = 3_300_000_020;
    if proc_pid_cgroup(unplaced, unplaced) != b"0::/\n" {
        return TestResult::Fail("unplaced pid not rendered as 0::/");
    }
    // A placed pid renders its absolute cgroup path after "0::".
    let root = root_dir();
    let name = "t_pfmt";
    let pid: u64 = 3_300_000_021;
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let _ = attach_pid(&child, pid);
    let line = proc_pid_cgroup(pid, pid);
    task_exited(pid);
    let _ = poll_once(root.rmdir(name));
    if line == b"0::/t_pfmt\n" {
        TestResult::Pass
    } else {
        TestResult::Fail("placed pid not rendered as 0::/t_pfmt")
    }
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_proc_pid_format);

// clone3(CLONE_INTO_CGROUP) attaches a child to a NESTED cgroup path (systemd
// spawns every service into /<slice>/<unit>) via attach_by_path;
// /proc/<pid>/cgroup then reports that exact path — which is how PID 1 matches a
// service's sd_notify(READY=1) datagram back to its unit. A path naming a
// non-existent cgroup must be rejected so the caller falls back to inheritance.
fn smoke_cgroup_attach_by_path_nested_roundtrip() -> TestResult {
    use crate::cgroupfs::{attach_by_path, proc_pid_cgroup, task_exited};
    let root = root_dir();
    let slice = match poll_once(root.mkdir("t_cia_slice")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir t_cia_slice failed"),
    };
    let _svc = match poll_once(slice.mkdir("t_cia_svc")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir t_cia_svc failed"),
    };

    let pid: u64 = 3_300_000_050;
    let placed = attach_by_path("/t_cia_slice/t_cia_svc", pid).is_ok();
    let line = proc_pid_cgroup(pid, pid);
    // A path naming a cgroup that does not exist must NOT place the pid.
    let bogus_rejected = attach_by_path("/t_cia_slice/nope", 3_300_000_051).is_err();

    task_exited(pid);
    let _ = poll_once(slice.rmdir("t_cia_svc"));
    let _ = poll_once(root.rmdir("t_cia_slice"));

    if placed && line == b"0::/t_cia_slice/t_cia_svc\n" && bogus_rejected {
        TestResult::Pass
    } else {
        TestResult::Fail("nested attach_by_path + /proc/<pid>/cgroup roundtrip mismatch")
    }
}
kernel_test_in!(
    "filesystem/cgroupfs",
    smoke_cgroup_attach_by_path_nested_roundtrip
);

// /proc/<pid>/cgroup renders relative to the READER's cgroup namespace, not the
// target's (Linux). A process in a cgroup namespace (systemd services with
// ProtectControlGroups= unshare CLONE_NEWCGROUP) reads its OWN cgroup as "/",
// but a reader OUTSIDE that namespace (PID 1) must see the ABSOLUTE path — that
// is what lets PID 1 attribute a service's sd_notify(READY=1) to its unit
// (manager_get_unit_by_pidref_cgroup reads /proc/<service>/cgroup). Keying the
// relativization on the TARGET's namespace made a namespaced service read back
// as 0::/ to PID 1, so every ProtectControlGroups= Type=notify service timed out.
fn smoke_cgroup_proc_pid_relative_to_reader_ns() -> TestResult {
    use crate::cgroupfs::{attach_by_path, proc_pid_cgroup, task_exited, unshare_cgroup_ns};
    let root = root_dir();
    let slice = match poll_once(root.mkdir("t_rns_slice")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir t_rns_slice failed"),
    };
    let _svc = match poll_once(slice.mkdir("t_rns_svc")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir t_rns_svc failed"),
    };

    let target: u64 = 3_300_000_060;
    let reader_outside: u64 = 3_300_000_061; // in NO cgroup namespace (e.g. PID 1)
    if attach_by_path("/t_rns_slice/t_rns_svc", target).is_err() {
        return TestResult::Fail("attach target failed");
    }
    // Target enters a cgroup namespace rooted at its current cgroup.
    unshare_cgroup_ns(target);

    // A reader OUTSIDE any cgroup ns must see the ABSOLUTE path.
    let outside = proc_pid_cgroup(target, reader_outside);
    // The target reading its OWN cgroup sees the ns-relative root "/".
    let selfview = proc_pid_cgroup(target, target);

    task_exited(target);
    let _ = poll_once(slice.rmdir("t_rns_svc"));
    let _ = poll_once(root.rmdir("t_rns_slice"));

    if outside == b"0::/t_rns_slice/t_rns_svc\n" && selfview == b"0::/\n" {
        TestResult::Pass
    } else {
        TestResult::Fail(
            "proc_pid_cgroup must render relative to the READER's cgroup ns (absolute for an outside reader)",
        )
    }
}
kernel_test_in!(
    "filesystem/cgroupfs",
    smoke_cgroup_proc_pid_relative_to_reader_ns
);

// ── 9. Base cpu.stat is a core file ─────────────────────────────────

fn smoke_cgroup_base_cpu_stat() -> TestResult {
    let root = root_dir();
    // Root: no cpu controller state ever, yet cpu.stat must read.
    let body = read_attr(&root, "cpu.stat").unwrap_or_default();
    if !body.contains("usage_usec") || !body.contains("system_usec") {
        return TestResult::Fail("root cpu.stat missing/malformed");
    }
    // A fresh child without the cpu controller also has it.
    let name = "t_cpustat";
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let cbody = read_attr(&child, "cpu.stat").unwrap_or_default();
    // A directory may not shadow an interface file.
    let shadow = poll_once(child.mkdir("cpu.stat"));
    let _ = poll_once(root.rmdir(name));
    if !cbody.contains("usage_usec") {
        return TestResult::Fail("child cpu.stat missing without cpu controller");
    }
    if shadow.map(|r| r.is_err()) != Some(true) {
        return TestResult::Fail("mkdir cpu.stat was allowed to shadow the file");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_base_cpu_stat);

// ── 10. cgroup.pressure round-trip ──────────────────────────────────

fn smoke_cgroup_pressure_toggle() -> TestResult {
    let root = root_dir();
    let name = "t_press";
    let child = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let initial = read_attr(&child, "cgroup.pressure").unwrap_or_default();
    let off = write_attr(&child, "cgroup.pressure", b"0");
    let after_off = read_attr(&child, "cgroup.pressure").unwrap_or_default();
    let on = write_attr(&child, "cgroup.pressure", b"1");
    let after_on = read_attr(&child, "cgroup.pressure").unwrap_or_default();
    let bogus = write_attr(&child, "cgroup.pressure", b"2");
    let _ = poll_once(root.rmdir(name));
    if initial.trim() != "1" {
        return TestResult::Fail("cgroup.pressure default is not 1");
    }
    if off.is_err() || after_off.trim() != "0" || on.is_err() || after_on.trim() != "1" {
        return TestResult::Fail("cgroup.pressure toggle did not round-trip");
    }
    if bogus.is_ok() {
        return TestResult::Fail("cgroup.pressure accepted a non-0/1 write");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_pressure_toggle);

// ── 11. Effective frozen state in cgroup.events ─────────────────────

fn smoke_cgroup_freeze_effective() -> TestResult {
    let root = root_dir();
    let name = "t_frz";
    let outer = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let inner = match poll_once(outer.mkdir("inner")) {
        Some(Ok(c)) => c,
        _ => {
            let _ = poll_once(root.rmdir(name));
            return TestResult::Fail("inner mkdir failed");
        }
    };
    let cleanup = |outer: &Arc<dyn DirOps>| {
        let _ = write_attr(outer, "cgroup.freeze", b"0");
        let _ = poll_once(outer.rmdir("inner"));
        let _ = poll_once(root_dir().rmdir(name));
    };
    // Freeze the parent: the child's events must report frozen 1
    // (effective state), while its own cgroup.freeze stays 0.
    if write_attr(&outer, "cgroup.freeze", b"1").is_err() {
        cleanup(&outer);
        return TestResult::Fail("freeze write failed");
    }
    let inner_ev = read_attr(&inner, "cgroup.events").unwrap_or_default();
    let inner_freeze = read_attr(&inner, "cgroup.freeze").unwrap_or_default();
    if !inner_ev.contains("frozen 1") || inner_freeze.trim() != "0" {
        cleanup(&outer);
        return TestResult::Fail("child did not inherit effective frozen state");
    }
    // Thaw: effective state falls back to 0.
    let _ = write_attr(&outer, "cgroup.freeze", b"0");
    let thawed = read_attr(&inner, "cgroup.events").unwrap_or_default();
    cleanup(&outer);
    if thawed.contains("frozen 1") {
        return TestResult::Fail("child stayed frozen after parent thaw");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_freeze_effective);

// ── 12. systemd manager startup shape ───────────────────────────────
//
// The exact sequence systemd's manager performs against a cgroup2
// mount: enable controllers on the root's subtree_control (multi-token
// write), mkdir a slice, verify the slice inherited the controllers
// and their interface files, then exercise both halves of the
// no-internal-process constraint before placing a process in a leaf.
#[cfg(all(feature = "cgroup-memory", feature = "cgroup-pids"))]
fn smoke_cgroup_systemd_sequence() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::memory::MemoryController));
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::pids::PidsController));

    let root = root_dir();
    let pid: u64 = 3_300_000_030;
    let slice = "t_sysd.slice";
    let leaf = "t_leaf.scope";

    let cleanup = || {
        task_exited(pid);
        let root = root_dir();
        if let Some(s) = root.lookup_dir(slice) {
            let _ = poll_once(s.rmdir(leaf));
        }
        let _ = poll_once(root.rmdir(slice));
        let _ = write_attr(&root, "cgroup.subtree_control", b"-memory -pids");
    };

    // Multi-token enable on the root, systemd-style.
    if write_attr(&root, "cgroup.subtree_control", b"+memory +pids").is_err() {
        return TestResult::Fail("root +memory +pids rejected");
    }
    let sc = read_attr(&root, "cgroup.subtree_control").unwrap_or_default();
    if !sc.contains("memory") || !sc.contains("pids") {
        cleanup();
        return TestResult::Fail("root subtree_control readback missing controllers");
    }
    let cg = match poll_once(root.mkdir(slice)) {
        Some(Ok(c)) => c,
        _ => {
            cleanup();
            return TestResult::Fail("mkdir slice failed");
        }
    };
    // The slice's available controllers = the root's enabled set, and
    // the controller interface files must be materialized.
    let ctrls = read_attr(&cg, "cgroup.controllers").unwrap_or_default();
    if !ctrls.contains("memory") || !ctrls.contains("pids") {
        cleanup();
        return TestResult::Fail("slice cgroup.controllers missing inherited controllers");
    }
    if cg.lookup("memory.current").is_none()
        || cg.lookup("memory.max").is_none()
        || cg.lookup("pids.current").is_none()
        || cg.lookup("pids.max").is_none()
    {
        cleanup();
        return TestResult::Fail("slice missing controller interface files");
    }
    // Internal process present → enabling distribution must fail...
    if attach_pid(&cg, pid).is_err() {
        cleanup();
        return TestResult::Fail("attach to fresh slice failed");
    }
    if write_attr(&cg, "cgroup.subtree_control", b"+memory").is_ok() {
        cleanup();
        return TestResult::Fail("subtree_control accepted with internal process");
    }
    // ...until the process moves away (back to the root, root-exempt).
    if attach_pid(&root, pid).is_err() {
        cleanup();
        return TestResult::Fail("move back to root failed");
    }
    if write_attr(&cg, "cgroup.subtree_control", b"+memory").is_err() {
        cleanup();
        return TestResult::Fail("subtree_control rejected on empty slice");
    }
    // Now the slice distributes: direct placement is refused, a leaf
    // child works and inherits the memory files.
    let leaf_dir = match poll_once(cg.mkdir(leaf)) {
        Some(Ok(c)) => c,
        _ => {
            cleanup();
            return TestResult::Fail("mkdir leaf failed");
        }
    };
    if attach_pid(&cg, pid).is_ok() {
        cleanup();
        return TestResult::Fail("attach into distributing slice was allowed");
    }
    if leaf_dir.lookup("memory.current").is_none() {
        cleanup();
        return TestResult::Fail("leaf missing inherited memory files");
    }
    if attach_pid(&leaf_dir, pid).is_err() {
        cleanup();
        return TestResult::Fail("attach into leaf failed");
    }
    let ev = read_attr(&cg, "cgroup.events").unwrap_or_default();
    cleanup();
    if !ev.contains("populated 1") {
        return TestResult::Fail("slice events not populated with leaf member");
    }
    TestResult::Pass
}
#[cfg(all(feature = "cgroup-memory", feature = "cgroup-pids"))]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_systemd_sequence);

// ── Controller smokes ───────────────────────────────────────────────
//
// A controller's interface files appear on a cgroup only when its name
// is in the *parent's* subtree_control. To exercise a controller we
// enable it on the root, operate on a root child (which then carries
// the files), and always disable it again so the shared root is left
// pristine for other tests.
#[cfg(any(
    feature = "cgroup-pids",
    feature = "cgroup-misc",
    feature = "cgroup-memory",
    feature = "cgroup-io",
    feature = "cgroup-cpu",
    feature = "cgroup-cpuset"
))]
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
    // PSI pressure files exist at the root too (Linux mirrors
    // /proc/pressure there).
    let root_has = root.lookup("cpu.pressure").is_some()
        && root.lookup("memory.pressure").is_some()
        && root.lookup("io.pressure").is_some();
    let _ = poll_once(root.rmdir("t_psi"));
    if has && body.contains("some avg10=") && root_has {
        TestResult::Pass
    } else {
        TestResult::Fail("psi pressure files missing or malformed")
    }
}
#[cfg(feature = "cgroup-psi")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_psi);

#[cfg(feature = "cgroup-memory")]
fn smoke_cgroup_memory() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::memory::MemoryController));
    with_root_controller("memory", "t_mem", |cg| {
        if cg.lookup("memory.max").is_none() || cg.lookup("memory.current").is_none() {
            return TestResult::Fail("memory.* files absent after enabling memory");
        }
        if write_attr(cg, "memory.max", b"4096").is_err() {
            return TestResult::Fail("set memory.max failed");
        }
        let max = read_attr(cg, "memory.max").unwrap_or_default();
        let cur = read_attr(cg, "memory.current").unwrap_or_default();
        // "max" round-trips; current is 0 with no charging in the test.
        if max.trim() != "4096" || cur.trim() != "0" {
            return TestResult::Fail("memory.max/current unexpected");
        }
        // memory.oom.group round-trips (systemd's OOMPolicy path).
        if write_attr(cg, "memory.oom.group", b"1").is_err()
            || read_attr(cg, "memory.oom.group").unwrap_or_default().trim() != "1"
        {
            return TestResult::Fail("memory.oom.group did not round-trip");
        }
        // memory.reclaim accepts a well-formed request, rejects junk.
        if write_attr(cg, "memory.reclaim", b"1048576").is_err() {
            return TestResult::Fail("memory.reclaim rejected a valid write");
        }
        if write_attr(cg, "memory.reclaim", b"lots").is_ok() {
            return TestResult::Fail("memory.reclaim accepted junk");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-memory")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_memory);

// Regression: every `memory.*` limit file systemd 257 reads back during
// `cgroup_context_dump` must return its string content with NO read error.
// `read_attr` returns `None` if any `FileOps::read` yields an `Err` — the
// exact path `sys_read` drives — so a non-`None`, correctly-valued result
// proves the cgroupfs read surface is clean. (The "Owner died"/EOWNERDEAD
// lines seen from real systemd come from systemd's own internal
// `-EOWNERDEAD` sentinel when a unit has no cgroup_path under `--test`; NO
// NARF syscall on these files is involved. This test pins the NARF side so
// a genuine leak here would be caught.) `memory.zswap.max`/`.current` are
// included so systemd reads them back rather than hitting ENOENT.
#[cfg(feature = "cgroup-memory")]
fn smoke_cgroup_memory_limit_files_read_clean() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::memory::MemoryController));
    with_root_controller("memory", "t_mem_read", |cg| {
        // Unset limits read back as "max\n"; the two "current" counters as
        // "0\n"; min/low as "0\n". None of these reads may error.
        let cases: &[(&str, &str)] = &[
            ("memory.max", "max"),
            ("memory.high", "max"),
            ("memory.swap.max", "max"),
            ("memory.zswap.max", "max"),
            ("memory.zswap.current", "0"),
            ("memory.min", "0"),
            ("memory.low", "0"),
        ];
        for (file, want) in cases {
            match read_attr(cg, file) {
                Some(body) if body.trim() == *want => {}
                Some(body) => {
                    let _ = body;
                    return TestResult::Fail("memory limit file read wrong content");
                }
                None => return TestResult::Fail("memory limit file read errored"),
            }
        }
        // The writable limit knobs round-trip a real value (systemd both
        // reads and, when applying, writes these).
        if write_attr(cg, "memory.zswap.max", b"8192").is_err() {
            return TestResult::Fail("set memory.zswap.max failed");
        }
        match read_attr(cg, "memory.zswap.max") {
            Some(body) if body.trim() == "8192" => TestResult::Pass,
            Some(_) => TestResult::Fail("memory.zswap.max round-trip wrong"),
            None => TestResult::Fail("memory.zswap.max re-read errored"),
        }
    })
}
#[cfg(feature = "cgroup-memory")]
kernel_test_in!(
    "filesystem/cgroupfs",
    smoke_cgroup_memory_limit_files_read_clean
);

#[cfg(feature = "cgroup-io")]
fn smoke_cgroup_io() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::io::IoController));
    with_root_controller("io", "t_io", |cg| {
        if cg.lookup("io.weight").is_none() || cg.lookup("io.max").is_none() {
            return TestResult::Fail("io.* files absent after enabling io");
        }
        if write_attr(cg, "io.weight", b"default 200").is_err() {
            return TestResult::Fail("set io.weight failed");
        }
        let w = read_attr(cg, "io.weight").unwrap_or_default();
        if write_attr(cg, "io.max", b"8:0 wbps=1048576").is_err() {
            return TestResult::Fail("set io.max failed");
        }
        let m = read_attr(cg, "io.max").unwrap_or_default();
        if !w.contains("200") || !m.contains("8:0") || !m.contains("wbps=1048576") {
            return TestResult::Fail("io.weight/io.max round-trip failed");
        }
        // io.latency (systemd IODeviceLatencyTargetSec=) round-trips;
        // target=0 clears the entry.
        if write_attr(cg, "io.latency", b"8:0 target=75000").is_err() {
            return TestResult::Fail("set io.latency failed");
        }
        let lat = read_attr(cg, "io.latency").unwrap_or_default();
        if !lat.contains("8:0 target=75000") {
            return TestResult::Fail("io.latency round-trip failed");
        }
        if write_attr(cg, "io.latency", b"8:0 target=0").is_err()
            || !read_attr(cg, "io.latency").unwrap_or_default().is_empty()
        {
            return TestResult::Fail("io.latency clear failed");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-io")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_io);

#[cfg(feature = "cgroup-cpu")]
fn smoke_cgroup_cpu() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::cpu::CpuController));
    with_root_controller("cpu", "t_cpu", |cg| {
        if cg.lookup("cpu.weight").is_none() || cg.lookup("cpu.max").is_none() {
            return TestResult::Fail("cpu.* files absent after enabling cpu");
        }
        if write_attr(cg, "cpu.weight", b"200").is_err() {
            return TestResult::Fail("set cpu.weight failed");
        }
        let w = read_attr(cg, "cpu.weight").unwrap_or_default();
        if write_attr(cg, "cpu.max", b"50000 100000").is_err() {
            return TestResult::Fail("set cpu.max failed");
        }
        let m = read_attr(cg, "cpu.max").unwrap_or_default();
        let stat = read_attr(cg, "cpu.stat").unwrap_or_default();
        if w.trim() == "200" && m.trim() == "50000 100000" && stat.contains("usage_usec") {
            TestResult::Pass
        } else {
            TestResult::Fail("cpu.weight/cpu.max/cpu.stat unexpected")
        }
    })
}
#[cfg(feature = "cgroup-cpu")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_cpu);

#[cfg(feature = "cgroup-cpuset")]
fn smoke_cgroup_cpuset() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::cpuset::CpuSetController));
    with_root_controller("cpuset", "t_cpuset", |cg| {
        if cg.lookup("cpuset.cpus").is_none() || cg.lookup("cpuset.cpus.effective").is_none() {
            return TestResult::Fail("cpuset.* files absent after enabling cpuset");
        }
        // CPU 0 is always online, so requesting it yields a non-empty
        // effective set regardless of the machine's CPU count.
        if write_attr(cg, "cpuset.cpus", b"0").is_err() {
            return TestResult::Fail("set cpuset.cpus failed");
        }
        let c = read_attr(cg, "cpuset.cpus").unwrap_or_default();
        let eff = read_attr(cg, "cpuset.cpus.effective").unwrap_or_default();
        if c.trim() == "0" && eff.contains('0') {
            TestResult::Pass
        } else {
            TestResult::Fail("cpuset.cpus / effective unexpected")
        }
    })
}
#[cfg(feature = "cgroup-cpuset")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_cpuset);

// ── Memory charge hook / chain walk (deterministic, no allocation) ──
//
// These drive the `memory` controller's charge path directly through
// test-only seams rather than a live frame allocation, so the accounting
// is fully deterministic. Each enables `memory` on the root, operates on
// a root child (which then carries `MemoryState`), places a distinct
// fake pid in it via cgroup.procs, and always tears the pid + cgroup +
// root subtree_control back down so the shared root is left pristine.

// Read `memory.current` for a cgroup as a u64 (0 on any parse trouble).
#[cfg(feature = "cgroup-memory")]
fn read_current(cg: &Arc<dyn DirOps>) -> u64 {
    read_attr(cg, "memory.current")
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(u64::MAX)
}

// ── charge_hook re-entrancy guard ───────────────────────────────────
//
// A nested `charge_hook` entry (the guard already raised, as happens
// when the charge path itself allocates) must short-circuit to `true`
// WITHOUT touching accounting — otherwise a charge would recurse and
// double-count. We synthesise the nested state deterministically with
// the guard seam, then confirm the happy (non-reentrant) path both
// leaves the guard clear and actually charges.
#[cfg(feature = "cgroup-memory")]
fn smoke_cgroup_charge_reentrancy_guard() -> TestResult {
    use crate::cgroupfs::memory;
    crate::cgroupfs::register_controller(Arc::new(memory::MemoryController));
    with_root_controller("memory", "t_mem_reentry", |cg| {
        let pid: u64 = 4_200_000_001;
        if attach_pid(cg, pid).is_err() {
            return TestResult::Fail("attach pid failed");
        }
        // Guard must start clear on this path.
        if memory::in_charge_for_test() {
            task_exited(pid);
            return TestResult::Fail("IN_CHARGE was set before any charge");
        }
        let before = read_current(cg);

        // Simulate "a charge is already in progress" and re-enter: the
        // guard must make the nested call a no-op returning true.
        let prev = memory::set_in_charge_for_test(true);
        let nested = memory::charge_hook_for_test(pid, 4096);
        // Restore the guard to whatever it was (clear).
        memory::set_in_charge_for_test(prev);
        let after_nested = read_current(cg);
        if !nested {
            task_exited(pid);
            return TestResult::Fail("re-entrant charge did not return true");
        }
        if after_nested != before {
            task_exited(pid);
            return TestResult::Fail("re-entrant charge mutated accounting");
        }

        // Happy path: a normal (non-reentrant) charge commits and leaves
        // the guard clear again (Drop of the internal guard).
        if !memory::charge_hook_for_test(pid, 4096) {
            task_exited(pid);
            return TestResult::Fail("non-reentrant charge was denied");
        }
        if memory::in_charge_for_test() {
            task_exited(pid);
            return TestResult::Fail("IN_CHARGE left set after charge returned");
        }
        let after = read_current(cg);
        // Free it back so the shared root chain is accounting-neutral.
        let _ = memory::charge_hook_for_test(pid, -4096);
        task_exited(pid);
        if after != before + 4096 {
            return TestResult::Fail("non-reentrant charge did not update usage");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-memory")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_charge_reentrancy_guard);

// ── memory.max two-phase enforcement ────────────────────────────────
//
// A positive charge that would push a level over `memory.max` is denied
// (returns false) and — because charging is two-phase (pre-check ALL
// levels, only then commit) — leaves `memory.current` untouched. A
// charge within the limit commits; a free (negative delta) always
// succeeds and reduces usage.
#[cfg(feature = "cgroup-memory")]
fn smoke_cgroup_memory_max_two_phase() -> TestResult {
    use crate::cgroupfs::memory;
    crate::cgroupfs::register_controller(Arc::new(memory::MemoryController));
    with_root_controller("memory", "t_mem_max", |cg| {
        let pid: u64 = 4_200_000_002;
        if attach_pid(cg, pid).is_err() {
            return TestResult::Fail("attach pid failed");
        }
        if write_attr(cg, "memory.max", b"8192").is_err() {
            task_exited(pid);
            return TestResult::Fail("set memory.max failed");
        }
        let fail = |msg: &'static str, pid: u64| -> TestResult {
            let _ = pid;
            task_exited(pid);
            TestResult::Fail(msg)
        };

        // Within the limit: commits and updates usage.
        if !memory::charge_hook_for_test(pid, 4096) {
            return fail("charge within memory.max was denied", pid);
        }
        if read_current(cg) != 4096 {
            return fail("in-limit charge did not update current", pid);
        }

        // Over the limit (4096 + 8192 > 8192): denied, accounting frozen.
        if memory::charge_hook_for_test(pid, 8192) {
            return fail("over-limit charge was allowed", pid);
        }
        if read_current(cg) != 4096 {
            return fail("denied charge mutated current (not two-phase)", pid);
        }
        // The breach is recorded in memory.events (max + oom counters).
        let events = read_attr(cg, "memory.events").unwrap_or_default();
        if !events.contains("max 1") {
            return fail("memory.events max counter not bumped on denial", pid);
        }

        // A charge that exactly reaches the limit is allowed.
        if !memory::charge_hook_for_test(pid, 4096) {
            return fail("charge up to exactly memory.max was denied", pid);
        }
        if read_current(cg) != 8192 {
            return fail("boundary charge did not update current", pid);
        }

        // A free (negative delta) always returns true and reduces usage.
        if !memory::charge_hook_for_test(pid, -8192) {
            return fail("free (negative delta) returned false", pid);
        }
        if read_current(cg) != 0 {
            return fail("free did not reduce current to 0", pid);
        }
        task_exited(pid);
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-memory")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_memory_max_two_phase);

// ── with_chain_states walks the cgroup + every ancestor ─────────────
//
// Enable memory on the root AND on a mid-level cgroup, so a leaf pid's
// chain has memory state at two levels (leaf + mid). `with_chain_states`
// must visit each level that carries the named state, bottom-up to the
// root, exactly once. We verify coverage and per-level accounting by
// charging the leaf and confirming BOTH levels' `memory.current` moved.
#[cfg(feature = "cgroup-memory")]
fn smoke_cgroup_with_chain_states_walk() -> TestResult {
    use crate::cgroupfs::{memory, with_chain_states, ControllerState};
    crate::cgroupfs::register_controller(Arc::new(memory::MemoryController));

    let root = root_dir();
    // Enable memory on the root so `mid` (a root child) carries state.
    if write_attr(&root, "cgroup.subtree_control", b"+memory").is_err() {
        return TestResult::Fail("enable memory on root failed");
    }
    let cleanup_root = || {
        let root = root_dir();
        let _ = write_attr(&root, "cgroup.subtree_control", b"-memory");
    };
    let mid = match poll_once(root.mkdir("t_chain_mid")) {
        Some(Ok(c)) => c,
        _ => {
            cleanup_root();
            return TestResult::Fail("mkdir mid failed");
        }
    };
    // Enable memory on `mid` too so its `leaf` child also carries state.
    if write_attr(&mid, "cgroup.subtree_control", b"+memory").is_err() {
        let _ = poll_once(root.rmdir("t_chain_mid"));
        cleanup_root();
        return TestResult::Fail("enable memory on mid failed");
    }
    let leaf = match poll_once(mid.mkdir("t_chain_leaf")) {
        Some(Ok(c)) => c,
        _ => {
            let _ = poll_once(root.rmdir("t_chain_mid"));
            cleanup_root();
            return TestResult::Fail("mkdir leaf failed");
        }
    };

    let pid: u64 = 4_200_000_003;
    let teardown = |pid: u64| {
        task_exited(pid);
        let root = root_dir();
        if let Some(mid) = root.lookup_dir("t_chain_mid") {
            let _ = poll_once(mid.rmdir("t_chain_leaf"));
        }
        let _ = poll_once(root.rmdir("t_chain_mid"));
        let _ = write_attr(&root, "cgroup.subtree_control", b"-memory");
    };

    if attach_pid(&leaf, pid).is_err() {
        teardown(pid);
        return TestResult::Fail("attach pid to leaf failed");
    }

    // The chain must carry memory state at exactly two levels: leaf and
    // mid (root has no memory state — memory is only enabled for its
    // children, not on the root itself). Order is bottom-up.
    let mut visited = 0usize;
    let mut currents = alloc::vec::Vec::new();
    with_chain_states(pid, "memory", |s: &Arc<dyn ControllerState>| {
        visited += 1;
        currents.push(s.read("memory.current"));
    });
    if visited != 2 {
        teardown(pid);
        return TestResult::Fail("with_chain_states did not visit leaf+mid exactly");
    }

    // Charge the leaf's chain: both levels must move (chain-wide charge).
    if !memory::charge_hook_for_test(pid, 4096) {
        teardown(pid);
        return TestResult::Fail("chain charge denied");
    }
    let leaf_cur = read_current(&leaf);
    let mid_cur = read_current(&mid);
    let _ = memory::charge_hook_for_test(pid, -4096);
    teardown(pid);
    if leaf_cur != 4096 || mid_cur != 4096 {
        return TestResult::Fail("chain walk did not charge both leaf and mid");
    }
    TestResult::Pass
}
#[cfg(feature = "cgroup-memory")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_with_chain_states_walk);

// ── Nested hierarchy: cgroup.procs membership + placement ───────────
//
// Create nested cgroups, place a pid in a leaf, and verify membership is
// reflected in cgroup.procs at the leaf (and NOT at the parent), then
// move the pid up a level and confirm the membership followed it.
fn smoke_cgroup_nested_procs_membership() -> TestResult {
    let root = root_dir();
    let outer = match poll_once(root.mkdir("t_nest")) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir outer failed"),
    };
    let inner = match poll_once(outer.mkdir("inner")) {
        Some(Ok(c)) => c,
        _ => {
            let _ = poll_once(root.rmdir("t_nest"));
            return TestResult::Fail("mkdir inner failed");
        }
    };
    let pid: u64 = 4_200_000_004;
    let teardown = |pid: u64| {
        task_exited(pid);
        let root = root_dir();
        if let Some(outer) = root.lookup_dir("t_nest") {
            let _ = poll_once(outer.rmdir("inner"));
        }
        let _ = poll_once(root.rmdir("t_nest"));
    };

    // Place in the inner leaf: listed there, absent from the outer.
    if attach_pid(&inner, pid).is_err() {
        teardown(pid);
        return TestResult::Fail("attach to inner failed");
    }
    let inner_body = read_attr(&inner, "cgroup.procs").unwrap_or_default();
    let outer_body = read_attr(&outer, "cgroup.procs").unwrap_or_default();
    if !inner_body.contains(&pid.to_string()) {
        teardown(pid);
        return TestResult::Fail("pid not listed in inner after attach");
    }
    if outer_body.contains(&pid.to_string()) {
        teardown(pid);
        return TestResult::Fail("pid leaked into outer's own membership");
    }

    // Move the pid up to the outer cgroup: now listed there, gone from
    // inner (v2: a process is in exactly one cgroup).
    if attach_pid(&outer, pid).is_err() {
        teardown(pid);
        return TestResult::Fail("move to outer failed");
    }
    let inner_after = read_attr(&inner, "cgroup.procs").unwrap_or_default();
    let outer_after = read_attr(&outer, "cgroup.procs").unwrap_or_default();
    // The pid moved out of inner, so inner is now rmdir-able while it
    // holds no members — proving membership really left it.
    let inner_empty_ok = poll_once(outer.rmdir("inner")).map(|r| r.is_ok()) == Some(true);
    teardown(pid);
    if inner_after.contains(&pid.to_string()) {
        return TestResult::Fail("pid still in inner after moving to outer");
    }
    if !outer_after.contains(&pid.to_string()) {
        return TestResult::Fail("pid not in outer after move");
    }
    if !inner_empty_ok {
        return TestResult::Fail("emptied inner cgroup was not removable");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_nested_procs_membership);

// ── pids: events counter + free decrements current ──────────────────
//
// Sets pids.max=2, then: two attaches succeed and drive pids.current to
// 2; a third attach is denied and increments the pids.events `max`
// counter; freeing a member (task_exited) decrements pids.current so the
// slot can be reused by a subsequent attach.
#[cfg(feature = "cgroup-pids")]
fn smoke_cgroup_pids_events_and_free() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::pids::PidsController));
    with_root_controller("pids", "t_pids_ev", |cg| {
        if write_attr(cg, "pids.max", b"2").is_err() {
            return TestResult::Fail("set pids.max=2 failed");
        }
        let a: u64 = 4_300_000_001;
        let b: u64 = 4_300_000_002;
        let c: u64 = 4_300_000_003;
        // Two attaches within the limit.
        if attach_pid(cg, a).is_err() || attach_pid(cg, b).is_err() {
            task_exited(a);
            task_exited(b);
            return TestResult::Fail("attach within pids.max was denied");
        }
        if read_attr(cg, "pids.current").unwrap_or_default().trim() != "2" {
            task_exited(a);
            task_exited(b);
            return TestResult::Fail("pids.current did not reach 2");
        }
        // pids.events shows no denials yet.
        if !read_attr(cg, "pids.events")
            .unwrap_or_default()
            .contains("max 0")
        {
            task_exited(a);
            task_exited(b);
            return TestResult::Fail("pids.events not initially 'max 0'");
        }
        // Third attach is denied and bumps the events `max` counter.
        if attach_pid(cg, c).is_ok() {
            task_exited(a);
            task_exited(b);
            task_exited(c);
            return TestResult::Fail("over-limit attach was allowed");
        }
        if !read_attr(cg, "pids.events")
            .unwrap_or_default()
            .contains("max 1")
        {
            task_exited(a);
            task_exited(b);
            return TestResult::Fail("pids.events max counter not incremented on denial");
        }
        // Free one member: pids.current falls to 1, freeing a slot.
        task_exited(b);
        if read_attr(cg, "pids.current").unwrap_or_default().trim() != "1" {
            task_exited(a);
            return TestResult::Fail("free did not decrement pids.current");
        }
        // The freed slot is reusable: attach now succeeds again.
        if attach_pid(cg, c).is_err() {
            task_exited(a);
            task_exited(c);
            return TestResult::Fail("attach after free was denied");
        }
        let cur = read_attr(cg, "pids.current").unwrap_or_default();
        task_exited(a);
        task_exited(c);
        if cur.trim() == "2" {
            TestResult::Pass
        } else {
            TestResult::Fail("pids.current wrong after slot reuse")
        }
    })
}
#[cfg(feature = "cgroup-pids")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_pids_events_and_free);

// ── cpu: weight.nice round-trip + full cpu.stat field set ───────────
//
// cpu.weight.nice writes convert to a weight and read back the same
// nice (nice 0 ↔ weight 100 anchor); a bare cpu.max quota with no period
// keeps the default period; cpu.stat exposes every v2 field name with
// the bandwidth counters at zero (cpu.max is not enforced).
#[cfg(feature = "cgroup-cpu")]
fn smoke_cgroup_cpu_nice_and_stat_fields() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::cpu::CpuController));
    with_root_controller("cpu", "t_cpu_nice", |cg| {
        // nice 0 is the anchor: weight must read back as the default 100.
        if write_attr(cg, "cpu.weight.nice", b"0").is_err() {
            return TestResult::Fail("set cpu.weight.nice=0 failed");
        }
        if read_attr(cg, "cpu.weight").unwrap_or_default().trim() != "100" {
            return TestResult::Fail("nice 0 did not map to weight 100");
        }
        if read_attr(cg, "cpu.weight.nice").unwrap_or_default().trim() != "0" {
            return TestResult::Fail("cpu.weight.nice=0 did not round-trip");
        }
        // Out-of-range nice is rejected, leaving state untouched.
        if write_attr(cg, "cpu.weight.nice", b"20").is_ok() {
            return TestResult::Fail("cpu.weight.nice accepted out-of-range value");
        }
        // "max" quota round-trips, keeping the default 100000 period.
        if write_attr(cg, "cpu.max", b"max").is_err() {
            return TestResult::Fail("set cpu.max=max failed");
        }
        if read_attr(cg, "cpu.max").unwrap_or_default().trim() != "max 100000" {
            return TestResult::Fail("cpu.max=max did not render 'max 100000'");
        }
        // cpu.stat exposes the full v2 field set; the bandwidth counters
        // are zero because cpu.max is not enforced.
        let stat = read_attr(cg, "cpu.stat").unwrap_or_default();
        for field in [
            "usage_usec",
            "user_usec",
            "system_usec",
            "nr_periods",
            "nr_throttled",
            "throttled_usec",
        ] {
            if !stat.contains(field) {
                return TestResult::Fail("cpu.stat missing a required field");
            }
        }
        if !stat.contains("nr_throttled 0") || !stat.contains("throttled_usec 0") {
            return TestResult::Fail("cpu.stat throttle counters not zero");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-cpu")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_cpu_nice_and_stat_fields);

// ── cpuset: mems round-trip + effective reflects parent when unset ──
//
// A fresh cpuset cgroup with no requested cpus/mems inherits the
// parent's effective sets, so cpuset.cpus/mems read empty while
// cpuset.cpus.effective/mems.effective are non-empty (mirror the
// parent). Writing cpuset.mems=0 (node 0 is always populated) sets both
// the requested list and a non-empty effective mems set.
#[cfg(feature = "cgroup-cpuset")]
fn smoke_cgroup_cpuset_mems_and_inherit() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::cpuset::CpuSetController));
    with_root_controller("cpuset", "t_cpuset_mems", |cg| {
        // Unset: requested lists are empty, but effective inherits the
        // parent (root = all online cpus / all memory nodes).
        let cpus = read_attr(cg, "cpuset.cpus").unwrap_or_default();
        let mems = read_attr(cg, "cpuset.mems").unwrap_or_default();
        if !cpus.trim().is_empty() || !mems.trim().is_empty() {
            return TestResult::Fail("fresh cpuset requested lists not empty");
        }
        let eff_cpus = read_attr(cg, "cpuset.cpus.effective").unwrap_or_default();
        let eff_mems = read_attr(cg, "cpuset.mems.effective").unwrap_or_default();
        if eff_cpus.trim().is_empty() || eff_mems.trim().is_empty() {
            return TestResult::Fail("effective set empty despite parent inheritance");
        }
        // Requesting node 0 (always populated) round-trips and yields a
        // non-empty effective mems set including node 0.
        if write_attr(cg, "cpuset.mems", b"0").is_err() {
            return TestResult::Fail("set cpuset.mems=0 failed");
        }
        if read_attr(cg, "cpuset.mems").unwrap_or_default().trim() != "0" {
            return TestResult::Fail("cpuset.mems did not round-trip");
        }
        let eff_after = read_attr(cg, "cpuset.mems.effective").unwrap_or_default();
        if !eff_after.contains('0') {
            return TestResult::Fail("cpuset.mems.effective missing requested node 0");
        }
        // Malformed cpulists are rejected, leaving requested state intact.
        if write_attr(cg, "cpuset.cpus", b"0-").is_ok() {
            return TestResult::Fail("cpuset.cpus accepted malformed list");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-cpuset")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_cpuset_mems_and_inherit);

// ── io: io.stat shape + io.max multi-field per-device parse ─────────
//
// A fresh io cgroup with no charged traffic has an empty io.stat.
// io.max parses several MAJ:MIN fields in one write and merges a later
// partial write into the same device row (v2 merge semantics); "max"
// clears a single field.
#[cfg(feature = "cgroup-io")]
fn smoke_cgroup_io_stat_and_max_merge() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::io::IoController));
    with_root_controller("io", "t_io_merge", |cg| {
        // No traffic charged in the test → io.stat is empty (well-formed).
        if !read_attr(cg, "io.stat").unwrap_or_default().is_empty() {
            return TestResult::Fail("fresh io.stat not empty");
        }
        // Multi-field per-device write.
        if write_attr(cg, "io.max", b"8:16 rbps=1000 wbps=2000 riops=30").is_err() {
            return TestResult::Fail("multi-field io.max write failed");
        }
        let m1 = read_attr(cg, "io.max").unwrap_or_default();
        if !m1.contains("8:16")
            || !m1.contains("rbps=1000")
            || !m1.contains("wbps=2000")
            || !m1.contains("riops=30")
        {
            return TestResult::Fail("io.max multi-field row not rendered");
        }
        // Partial write merges into the existing row: only wbps changes,
        // the others persist.
        if write_attr(cg, "io.max", b"8:16 wbps=9999").is_err() {
            return TestResult::Fail("io.max merge write failed");
        }
        let m2 = read_attr(cg, "io.max").unwrap_or_default();
        if !m2.contains("wbps=9999") || !m2.contains("rbps=1000") || !m2.contains("riops=30") {
            return TestResult::Fail("io.max merge did not preserve prior fields");
        }
        // "max" clears a single field (it renders back as key=max).
        if write_attr(cg, "io.max", b"8:16 rbps=max").is_err() {
            return TestResult::Fail("io.max rbps=max write failed");
        }
        let m3 = read_attr(cg, "io.max").unwrap_or_default();
        if !m3.contains("rbps=max") || !m3.contains("wbps=9999") {
            return TestResult::Fail("io.max did not clear a single field to 'max'");
        }
        // A bad field key is rejected.
        if write_attr(cg, "io.max", b"8:16 bogus=1").is_ok() {
            return TestResult::Fail("io.max accepted an unknown field key");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-io")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_io_stat_and_max_merge);

// ── misc: misc.max round-trip + "max" unset; misc.current shape ─────
//
// With a registered resource, misc.max round-trips a numeric limit and
// unsets it back to capacity via a "max" write (dropping the row).
// misc.current is well-formed (empty with no accounting).
#[cfg(feature = "cgroup-misc")]
fn smoke_cgroup_misc_max_unset_and_current() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::misc::MiscController));
    crate::cgroupfs::misc::register_misc_resource("t_res_b", 4096);
    with_root_controller("misc", "t_misc_unset", |cg| {
        // misc.current is well-formed (no usage accounted → empty).
        if !read_attr(cg, "misc.current").unwrap_or_default().is_empty() {
            return TestResult::Fail("fresh misc.current not empty");
        }
        // Set a numeric limit; it round-trips as "<key> <n>".
        if write_attr(cg, "misc.max", b"t_res_b 512").is_err() {
            return TestResult::Fail("set misc.max failed");
        }
        if !read_attr(cg, "misc.max")
            .unwrap_or_default()
            .contains("t_res_b 512")
        {
            return TestResult::Fail("misc.max did not round-trip");
        }
        // Writing "max" unsets the limit (row is dropped).
        if write_attr(cg, "misc.max", b"t_res_b max").is_err() {
            return TestResult::Fail("misc.max 'max' unset failed");
        }
        if read_attr(cg, "misc.max")
            .unwrap_or_default()
            .contains("t_res_b")
        {
            return TestResult::Fail("misc.max row not dropped after 'max'");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "cgroup-misc")]
kernel_test_in!(
    "filesystem/cgroupfs",
    smoke_cgroup_misc_max_unset_and_current
);

// ── psi: every axis is PSI-shaped (some + full lines) ───────────────
//
// Each pressure file (cpu/memory/io) begins with a `some avg10=` line;
// all three also carry a `full` line in NARF's renderer, matching the
// v2 wire format userspace parsers expect.
#[cfg(feature = "cgroup-psi")]
fn smoke_cgroup_psi_shape_all_axes() -> TestResult {
    let root = root_dir();
    let cg = match poll_once(root.mkdir("t_psi_shape")) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let axes = ["cpu.pressure", "memory.pressure", "io.pressure"];
    let mut ok = true;
    for axis in axes {
        let body = read_attr(&cg, axis).unwrap_or_default();
        // PSI-shaped: leading `some avg10=`, and a `full` line present.
        if !body.starts_with("some avg10=") || !body.contains("full avg10=") {
            ok = false;
            break;
        }
        // The trigger-write path is not yet supported (read-only).
        if write_attr(&cg, axis, b"some 150000 1000000").is_ok() {
            ok = false;
            break;
        }
    }
    let _ = poll_once(root.rmdir("t_psi_shape"));
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("a pressure axis was not PSI-shaped / was writable")
    }
}
#[cfg(feature = "cgroup-psi")]
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_psi_shape_all_axes);

// ── core: cgroup.type default + domain→threaded transition ──────────
//
// A fresh non-root cgroup reads cgroup.type as "domain". Writing
// "threaded" transitions it (the only accepted write); any other value
// is rejected.
fn smoke_cgroup_type_threaded() -> TestResult {
    let root = root_dir();
    let name = "t_type";
    let cg = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let fail = |msg: &'static str| -> TestResult {
        let _ = poll_once(root_dir().rmdir(name));
        TestResult::Fail(msg)
    };
    if read_attr(&cg, "cgroup.type").unwrap_or_default().trim() != "domain" {
        return fail("fresh cgroup.type not 'domain'");
    }
    // A junk write is rejected, leaving the type unchanged.
    if write_attr(&cg, "cgroup.type", b"bogus").is_ok() {
        return fail("cgroup.type accepted a junk value");
    }
    if read_attr(&cg, "cgroup.type").unwrap_or_default().trim() != "domain" {
        return fail("rejected cgroup.type write mutated the type");
    }
    // The domain→threaded transition is accepted and reads back.
    if write_attr(&cg, "cgroup.type", b"threaded").is_err() {
        return fail("cgroup.type 'threaded' transition rejected");
    }
    if read_attr(&cg, "cgroup.type").unwrap_or_default().trim() != "threaded" {
        return fail("cgroup.type did not become 'threaded'");
    }
    let _ = poll_once(root.rmdir(name));
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_type_threaded);

// ── core: cgroup.freeze toggles this cgroup's own events `frozen` ────
//
// A cgroup's own cgroup.freeze write flips the `frozen` field of its own
// cgroup.events (self-frozen ⇒ effective-frozen), and thawing clears it.
// Complements smoke_cgroup_freeze_effective (which tests the ANCESTOR
// propagation path) by exercising the self-freeze path in isolation.
fn smoke_cgroup_freeze_self_events() -> TestResult {
    let root = root_dir();
    let name = "t_frz_self";
    let cg = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let cleanup = || {
        let root = root_dir();
        if let Some(cg) = root.lookup_dir(name) {
            let _ = write_attr(&cg, "cgroup.freeze", b"0");
        }
        let _ = poll_once(root.rmdir(name));
    };
    // Fresh: not frozen.
    let ev0 = read_attr(&cg, "cgroup.events").unwrap_or_default();
    if !ev0.contains("frozen 0") {
        cleanup();
        return TestResult::Fail("fresh cgroup.events not 'frozen 0'");
    }
    // Freeze self: own freeze reads 1 and events reports frozen 1.
    if write_attr(&cg, "cgroup.freeze", b"1").is_err() {
        cleanup();
        return TestResult::Fail("self cgroup.freeze=1 failed");
    }
    if read_attr(&cg, "cgroup.freeze").unwrap_or_default().trim() != "1"
        || !read_attr(&cg, "cgroup.events")
            .unwrap_or_default()
            .contains("frozen 1")
    {
        cleanup();
        return TestResult::Fail("self-freeze not reflected in freeze/events");
    }
    // A non-0/1 freeze write is rejected.
    if write_attr(&cg, "cgroup.freeze", b"2").is_ok() {
        cleanup();
        return TestResult::Fail("cgroup.freeze accepted a non-0/1 value");
    }
    // Thaw: events falls back to frozen 0.
    if write_attr(&cg, "cgroup.freeze", b"0").is_err() {
        cleanup();
        return TestResult::Fail("self cgroup.freeze=0 failed");
    }
    let ev1 = read_attr(&cg, "cgroup.events").unwrap_or_default();
    let _ = poll_once(root.rmdir(name));
    if ev1.contains("frozen 1") {
        return TestResult::Fail("cgroup stayed frozen after self-thaw");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/cgroupfs", smoke_cgroup_freeze_self_events);

// ── core: subtree_control delegates controllers to children ─────────
//
// Enabling a controller on a parent's cgroup.subtree_control makes it
// appear in a child's cgroup.controllers (delegation), materializes the
// controller's interface files on the child, and materializes them ONLY
// while enabled (disabling removes them from a freshly-created child).
#[cfg(feature = "cgroup-pids")]
fn smoke_cgroup_subtree_control_delegates() -> TestResult {
    crate::cgroupfs::register_controller(Arc::new(crate::cgroupfs::pids::PidsController));
    let root = root_dir();
    let name = "t_deleg";
    // Before enabling on the root, a fresh child has no pids files.
    let cleanup = || {
        let root = root_dir();
        if let Some(p) = root.lookup_dir(name) {
            let _ = poll_once(p.rmdir("child"));
        }
        let _ = poll_once(root.rmdir(name));
        let _ = write_attr(&root, "cgroup.subtree_control", b"-pids");
    };
    // Top-down constraint (cgroup v2): a controller must be in this
    // cgroup's own `cgroup.controllers` before it can be enabled in its
    // subtree_control. For a direct child of root, that means the
    // controller must first be enabled in the root's subtree_control.
    if write_attr(&root, "cgroup.subtree_control", b"+pids").is_err() {
        return TestResult::Fail("+pids on root rejected");
    }
    let parent = match poll_once(root.mkdir(name)) {
        Some(Ok(c)) => c,
        _ => {
            let _ = write_attr(&root, "cgroup.subtree_control", b"-pids");
            return TestResult::Fail("mkdir parent failed");
        }
    };
    // Enable pids on the parent's subtree_control; readback lists it.
    if write_attr(&parent, "cgroup.subtree_control", b"+pids").is_err() {
        cleanup();
        return TestResult::Fail("+pids on parent rejected");
    }
    if !read_attr(&parent, "cgroup.subtree_control")
        .unwrap_or_default()
        .contains("pids")
    {
        cleanup();
        return TestResult::Fail("subtree_control readback missing pids");
    }
    // A child created now sees pids in cgroup.controllers and carries the
    // controller's interface files.
    let child = match poll_once(parent.mkdir("child")) {
        Some(Ok(c)) => c,
        _ => {
            cleanup();
            return TestResult::Fail("mkdir child failed");
        }
    };
    if !read_attr(&child, "cgroup.controllers")
        .unwrap_or_default()
        .contains("pids")
    {
        cleanup();
        return TestResult::Fail("child cgroup.controllers missing delegated pids");
    }
    if child.lookup("pids.max").is_none() || child.lookup("pids.current").is_none() {
        cleanup();
        return TestResult::Fail("child missing delegated pids interface files");
    }
    cleanup();
    TestResult::Pass
}
#[cfg(feature = "cgroup-pids")]
kernel_test_in!(
    "filesystem/cgroupfs",
    smoke_cgroup_subtree_control_delegates
);
