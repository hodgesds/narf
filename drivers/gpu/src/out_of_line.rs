//! Await a large sub-future in its own stack frame.
//!
//! An `async fn` that awaits another inlines the callee's poll into its
//! own, so a display step's poll frame holds every nested step's locals at
//! once: the Navi48 display monitor reached 26 KiB of a 64 KiB task stack
//! that way. `Box::pin(step).await` moves the step's state to the heap but
//! neither stops LLVM inlining its poll (`Pin<Box<F>>::poll` is a direct
//! call) nor keeps the future off the caller's frame: the future is built
//! on the caller's stack (at its full size, tens of KiB for a modeset step)
//! and then moved into the box. [`boxed!`] builds it in a function of its
//! own, called and returned from before the caller awaits, straight into
//! the allocation, and polls it through a function of its own, entered only
//! while the step runs.
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// `boxed!(future)`: the future built on the heap out of line and polled
/// out of line. The expression is evaluated in a closure: it may not use
/// `?` or `.await`.
macro_rules! boxed {
    ($fut:expr) => {
        $crate::out_of_line::OutOfLine::build(|| $fut)
    };
}
pub(crate) use boxed;

/// See [`boxed!`].
#[must_use = "futures do nothing unless awaited"]
pub(crate) struct OutOfLine<F>(Pin<Box<F>>);

impl<F> OutOfLine<F> {
    /// `make`'s future, built in this frame (not the caller's) into a fresh
    /// allocation.
    #[inline(never)]
    pub(crate) fn build(make: impl FnOnce() -> F) -> Self {
        Self(Box::into_pin(Box::write(Box::new_uninit(), make())))
    }
}

impl<F: Future> Future for OutOfLine<F> {
    type Output = F::Output;

    #[inline(never)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        self.0.as_mut().poll(cx)
    }
}
