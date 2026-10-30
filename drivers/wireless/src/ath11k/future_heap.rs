// SPDX-License-Identifier: GPL-2.0-or-later
//! Keep large transport reconstruction futures out of their caller's stack.
use alloc::boxed::Box;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Construct in a transient frame, then retain the future in heap storage.
/// The closure avoids reserving the future's full return-place in a parent
/// async poll that must also call into the transport/console. No operation
/// is polled here; cancellation still drops the original future and guards.
#[inline(never)]
pub(super) fn build<F: Future>(make: impl FnOnce() -> F) -> HeapFuture<F> {
    HeapFuture {
        inner: Box::pin(make()),
    }
}

pub(super) struct HeapFuture<F> {
    inner: Pin<Box<F>>,
}

impl<F: Future> Future for HeapFuture<F> {
    type Output = F::Output;

    // Fat LTO must not merge the child's large reconstruction poll frame
    // into the caller's MLME/recovery poll. The indirection is confined to
    // infrequent recovery, outside the packet fast path.
    #[inline(never)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}
