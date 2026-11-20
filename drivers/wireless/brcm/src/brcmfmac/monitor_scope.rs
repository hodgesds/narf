// SPDX-License-Identifier: GPL-2.0-or-later
//! Original monitor receive owner. Interface observations carry no grant:
//! actual native device/firmware authority and current signed receive policy
//! remain independent of administration and AF_PACKET token identity.
use super::{
    ap_scope::{Epoch, Policy},
    ap_source::Source,
};
use crate::cyw43439::runtime::Error;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone)]
pub struct Capture {
    pub(super) native: Source,
    pub(super) event: narf_net::iface::OpenStopEvent,
    pub(super) policy: Policy,
    pub(super) mode: Arc<AtomicU64>,
    pub(super) generation: u64,
    pub(super) epoch: Epoch,
    pub(super) active: Arc<AtomicBool>,
    pub(super) frequency: u16,
    pub(super) chanspec: u16,
}
impl core::fmt::Debug for Capture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacMonitorCapture")
            .field("frequency", &self.frequency)
            .field("mode_generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl Capture {
    fn fixed(&self) -> bool {
        self.event.up()
            && self.event.current()
            && self.policy.current()
            && self.epoch.current()
            && self.generation != 0
            && self.generation != u64::MAX
            && self.mode.load(Ordering::Acquire) == self.generation
    }
    /// Native configuration calls may precede activation. This check never
    /// invokes an interface/socket/provider callback or recaptures a receiver.
    pub(super) fn command_current(&self) -> Result<(), Error> {
        if !self.fixed() {
            return Err(Error::Authority);
        }
        self.native.current().map_err(|_| Error::Authority)
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        if !self.active.load(Ordering::Acquire) {
            return Err(Error::Authority);
        }
        self.command_current()
    }
    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.epoch.close();
    }
    pub(crate) fn publish<T>(&self, copy: impl FnOnce() -> T) -> Result<T, Error> {
        self.native
            .invoke(|| {
                if !self.fixed() || !self.active.load(Ordering::Acquire) {
                    Err(Error::Authority)
                } else {
                    Ok(copy())
                }
            })
            .map_err(|_| Error::Authority)?
    }
    pub(crate) fn receiver(&self) -> narf_net::iface::NetIfaceSnapshot {
        self.event.original_snapshot()
    }
    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.mode, &other.mode)
            && self.generation == other.generation
            && self.epoch.same_owner(&other.epoch)
    }
}
pub struct Received {
    bytes: alloc::vec::Vec<u8>,
    original: Capture,
}
impl core::fmt::Debug for Received {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacMonitorReceived")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl Received {
    pub(super) fn new(bytes: alloc::vec::Vec<u8>, original: Capture) -> Self {
        Self { bytes, original }
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn original(&self) -> &Capture {
        &self.original
    }
}
