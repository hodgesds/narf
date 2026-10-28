// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained owner of one function's published FullMAC shell across its
//! transport generations, and the teardown that ends it.
//!
//! Linux v7.2 `brcmfmac/pcie.c::brcmf_pcie_remove` marks the bus down,
//! cancels reset work (`brcmf_bus_cancel_reset_work`), detaches the
//! common layer (`brcmf_detach`), releases the IRQ and only then the
//! scratch and ring buffers. Here the shell withdraws first and the
//! transport generation is stopped and released under the station mutex;
//! the published memory is freed only behind a complete stop proof.
use super::*;

/// Outcome of [`Generation::remove`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    /// No transport generation was attached.
    Absent,
    /// A complete stop proof released every published mapping.
    Reclaimed,
    /// The stop was unproven: published memory stays pinned.
    Pinned,
}
impl Removal {
    /// Whether nothing remains mapped for the device.
    pub fn released(self) -> bool {
        self != Self::Pinned
    }
}

/// The current shell of one function. Removal and every generation swap
/// serialize on `current`, so a removal observes either the old shell or
/// the replacement, never a half-published one.
pub struct Generation<R: Fullmac> {
    current: Mutex<Option<Arc<Device<R>>>>,
    /// `bus_if->removing`: no later generation may be published.
    removed: AtomicBool,
}
impl<R: Fullmac> core::fmt::Debug for Generation<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacGeneration")
            .field("removed", &self.removed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
impl<R: Fullmac + 'static> Generation<R> {
    pub fn new(device: Arc<Device<R>>) -> Self {
        Self {
            current: Mutex::new(Some(device)),
            removed: AtomicBool::new(false),
        }
    }
    pub fn removed(&self) -> bool {
        self.removed.load(Ordering::Acquire)
    }
    /// The current shell, if any (it may be withdrawn).
    pub fn current(&self) -> Option<Arc<Device<R>>> {
        self.current.try_lock().and_then(|current| current.clone())
    }
    /// Linux `brcmf_pcie_remove` for the retained owner: no later
    /// generation may start, then the current shell is withdrawn and its
    /// transport stopped and released.
    pub async fn remove(&self) -> Removal {
        self.removed.store(true, Ordering::Release);
        let mut current = self.current.lock().await;
        let Some(device) = current.take() else {
            return Removal::Absent;
        };
        if device.teardown().await {
            Removal::Reclaimed
        } else {
            Removal::Pinned
        }
    }
}
