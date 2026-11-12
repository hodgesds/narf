//! Await a large sub-future in its own stack frame.
//!
//! An `async fn` that awaits another inlines the callee's poll into its
//! own, so a display step's poll frame holds every nested step's locals at
//! once: the Navi48 display monitor reached 26 KiB of a 64 KiB task stack
//! that way. `Box::pin(step).await` moves the step's state to the heap but
//! neither stops LLVM inlining its poll (`Pin<Box<F>>::poll` is a direct
//! call) nor keeps the future off the caller's frame: `Box::pin(f)` builds
//! `f` (tens of KiB for a modeset step) on the stack before allocating.
//! [`boxed!`] allocates first and builds the future into the allocation,
//! and polls it through a function of its own, entered only while the step
//! runs.
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// `boxed!(future)`: the future built on the heap and polled out of line.
macro_rules! boxed {
    ($fut:expr) => {
        $crate::out_of_line::OutOfLine::new(::alloc::boxed::Box::write(
            ::alloc::boxed::Box::new_uninit(),
            $fut,
        ))
    };
}
pub(crate) use boxed;

/// See [`boxed!`].
#[must_use = "futures do nothing unless awaited"]
pub(crate) struct OutOfLine<F>(Pin<Box<F>>);

impl<F> OutOfLine<F> {
    #[inline(always)]
    pub(crate) fn new(fut: Box<F>) -> Self {
        Self(Box::into_pin(fut))
    }
}

impl<F: Future> Future for OutOfLine<F> {
    type Output = F::Output;

    #[inline(never)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        self.0.as_mut().poll(cx)
    }
}
