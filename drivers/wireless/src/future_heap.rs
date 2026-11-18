// SPDX-License-Identifier: GPL-2.0-or-later
//! Heap-retain infrequent driver control futures outside their callers.
use alloc::boxed::Box;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Construct without polling, then retain the original future and its
/// cancellation guards in pinned heap storage. The separate construction
/// frame prevents a parent's poll from reserving its child's full state.
#[inline(never)]
pub(crate) fn build<F: Future>(make: impl FnOnce() -> F) -> HeapFuture<F> {
    HeapFuture {
        inner: Box::pin(make()),
    }
}

pub(crate) struct HeapFuture<F> {
    inner: Pin<Box<F>>,
}

impl<F: Future> Future for HeapFuture<F> {
    type Output = F::Output;

    // Keep reconstruction/control polling separate under fat LTO too.
    // This indirection is used only outside packet/IRQ fast paths.
    #[inline(never)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}
