//! `narf_ipc` for the module: the bounded single-producer/single-consumer
//! channel the station shell's frame rings are built from.
//!
//! Built in, these are Narf-Ring zero-copy rings shared with the network
//! stack. In the module both halves stay inside the `.ko` (the stack is
//! reached through the netif bridge, which copies), so a locked queue with
//! the same capacity and the same `try_send` / `try_recv` contract serves.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use super::narf_lib::sync::IrqSafeSpinLock;

struct Ring<T> {
    queue: IrqSafeSpinLock<VecDeque<T>>,
}

/// The sending half.
pub struct Producer<T, const N: usize>(Arc<Ring<T>>);
/// The receiving half.
pub struct Consumer<T, const N: usize>(Arc<Ring<T>>);

/// Why a send failed; the message comes back.
#[derive(Debug)]
pub enum TrySendError<T> {
    Full(T),
    Closed(T),
}

/// Why a receive failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    Closed,
}

/// A channel of capacity `N`.
pub fn channel<T, const N: usize>() -> (Producer<T, N>, Consumer<T, N>) {
    let ring = Arc::new(Ring {
        queue: IrqSafeSpinLock::new(VecDeque::new()),
    });
    (Producer(ring.clone()), Consumer(ring))
}

impl<T, const N: usize> Producer<T, N> {
    pub fn try_send(&mut self, msg: T) -> Result<(), TrySendError<T>> {
        let mut queue = self.0.queue.lock();
        if queue.len() >= N {
            return Err(TrySendError::Full(msg));
        }
        queue.push_back(msg);
        Ok(())
    }
}

impl<T, const N: usize> Consumer<T, N> {
    pub fn try_recv(&mut self) -> Result<Option<T>, RecvError> {
        Ok(self.0.queue.lock().pop_front())
    }
}
