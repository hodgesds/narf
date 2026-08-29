//! debugfs `sched/` knob suite.
//!
//! Drives the [`crate::debugfs::DebugFs`] `FsInstance`/`DirOps`/`FileOps`
//! surface directly (no VFS): the `wake_placement` core feature flag
//! round-trips through write→state→read, and the read-only reflectors
//! (`policy`, `steal_strategy`) render a value yet reject writes.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{debugfs::DebugFs, FileOps, FsError, FsInstance};

// The debugfs futures are always immediately ready (each knob is a synchronous
// atomic load/store), so a single poll completes them. Mirrors memfs_tests.
fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: the vtable's no-op fns are sound for a single-threaded test poll.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local that outlives this block and is not moved.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

fn read_str(file: &Arc<dyn FileOps>) -> String {
    let mut buf = vec![0u8; 64];
    match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => String::from_utf8_lossy(&buf[..n]).into_owned(),
        _ => String::new(),
    }
}

fn sched_knob(name: &str) -> Option<Arc<dyn FileOps>> {
    let fs = DebugFs::new();
    fs.root().lookup_dir("sched")?.lookup(name)
}

fn smoke_debugfs_wake_placement_toggle() -> TestResult {
    let file = match sched_knob("wake_placement") {
        Some(f) => f,
        None => return TestResult::Fail("sched/wake_placement knob missing"),
    };
    let initial = narf_scheduler::wake_placement_enabled();
    let restore = |on: bool| {
        if on {
            narf_scheduler::enable_wake_placement();
        } else {
            narf_scheduler::disable_wake_placement();
        }
    };

    // `echo 1` enables; state + read reflect it.
    if poll_once(file.write(0, b"1\n")).map(|r| r.is_ok()) != Some(true) {
        restore(initial);
        return TestResult::Fail("write '1' failed");
    }
    if !narf_scheduler::wake_placement_enabled() {
        restore(initial);
        return TestResult::Fail("write '1' did not enable wake placement");
    }
    if read_str(&file) != "1\n" {
        restore(initial);
        return TestResult::Fail("read after enable did not return \"1\\n\"");
    }

    // `echo 0` disables.
    if poll_once(file.write(0, b"0")).map(|r| r.is_ok()) != Some(true) {
        restore(initial);
        return TestResult::Fail("write '0' failed");
    }
    if narf_scheduler::wake_placement_enabled() {
        restore(initial);
        return TestResult::Fail("write '0' did not disable wake placement");
    }
    if read_str(&file) != "0\n" {
        restore(initial);
        return TestResult::Fail("read after disable did not return \"0\\n\"");
    }

    restore(initial);
    TestResult::Pass
}
kernel_test_in!("filesystem/debugfs", smoke_debugfs_wake_placement_toggle);

fn smoke_debugfs_reflectors_are_read_only() -> TestResult {
    for name in ["policy", "steal_strategy"] {
        let file = match sched_knob(name) {
            Some(f) => f,
            None => return TestResult::Fail("reflector knob missing"),
        };
        // Renders a newline-terminated value (the active name, or "(none)").
        let value = read_str(&file);
        if value.is_empty() || !value.ends_with('\n') {
            return TestResult::Fail("reflector read did not render a value");
        }
        // A read-only knob rejects writes with EPERM.
        match poll_once(file.write(0, b"x")) {
            Some(Err(FsError::PermissionDenied)) => {}
            _ => return TestResult::Fail("read-only reflector accepted a write"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/debugfs", smoke_debugfs_reflectors_are_read_only);
