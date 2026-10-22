//! Prime the normal USB supervisor before an installed root is mounted.
//!
//! The future is retained and later spawned intact: claimed ports, pending
//! transfers and timer wakers remain owned by the one supervisor.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub(super) fn prepare<F: Future<Output = ()>>(mut supervisor: Pin<&mut F>) {
    if !narf_block::disk_policy::policy().is_root_policy() {
        return;
    }
    let Some(uuid) = narf_block::disk_policy::root_uuid_arg() else {
        return;
    };
    let uuid = narf_block::registry::format_uuid_bytes(&uuid);
    let ready = || narf_block::find_by_fs_uuid(&uuid).is_some();
    if ready() {
        return;
    }
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "  usb: preparing selected root UUID={uuid} before root mount (30 s limit)"
    );
    let deadline = narf_time::Deadline::after_ms(30_000);
    // Late initcall context, outside the executor. USB transfers poll their
    // event rings and the supervisor's delays are timer-driven; no other
    // scheduler task is needed to enumerate the disk. No lock is held here.
    let found = narf_scheduler::block_on_spin(core::future::poll_fn(|cx| {
        poll_bootstrap(supervisor.as_mut(), cx, ready, || deadline.expired())
    }));
    let _ = writeln!(
        narf_console::Writer,
        "  usb: selected root UUID={uuid} {}",
        if found {
            "registered"
        } else {
            "not registered before deadline"
        }
    );
}

fn poll_bootstrap<F: Future<Output = ()>>(
    mut supervisor: Pin<&mut F>,
    cx: &mut Context<'_>,
    ready: impl Fn() -> bool,
    expired: impl Fn() -> bool,
) -> Poll<bool> {
    if ready() {
        return Poll::Ready(true);
    }
    if expired() || supervisor.as_mut().poll(cx).is_ready() {
        return Poll::Ready(false);
    }
    if ready() {
        return Poll::Ready(true);
    }
    cx.waker().wake_by_ref();
    Poll::Pending
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    fn smoke_bootstrap_preserves_supervisor_state() -> TestResult {
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        struct Supervisor<'a>(&'a Cell<u32>, &'a Cell<bool>);
        impl Future for Supervisor<'_> {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                self.0.set(self.0.get() + 1);
                Poll::Pending
            }
        }
        impl Drop for Supervisor<'_> {
            fn drop(&mut self) {
                self.1.set(true);
            }
        }
        let mut supervisor = core::pin::pin!(Supervisor(&polls, &dropped));
        let waker = Arc::new(Noop).into();
        let mut cx = Context::from_waker(&waker);
        let result = poll_bootstrap(supervisor.as_mut(), &mut cx, || polls.get() == 1, || false);
        if result != Poll::Ready(true) || dropped.get() {
            return TestResult::Fail("root bootstrap dropped or failed to prime the supervisor");
        }
        // The executor resumes this exact future, including claimed-port state.
        let _ = supervisor.as_mut().poll(&mut cx);
        if polls.get() != 2 || dropped.get() {
            return TestResult::Fail("supervisor did not resume after bootstrap");
        }
        let result = poll_bootstrap(supervisor.as_mut(), &mut cx, || false, || true);
        if result != Poll::Ready(false) || polls.get() != 2 || dropped.get() {
            return TestResult::Fail("expired bootstrap polled or discarded the supervisor");
        }
        let result = poll_bootstrap(supervisor.as_mut(), &mut cx, || true, || false);
        if result != Poll::Ready(true) || polls.get() != 2 {
            return TestResult::Fail("registered root unnecessarily polled the supervisor");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb", smoke_bootstrap_preserves_supervisor_state);
}
