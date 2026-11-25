// SPDX-License-Identifier: GPL-2.0-or-later
//! Module build: no AP Program scope can be captured.
//!
//! Built in, `ap_scope.rs` fixes the AP role/peer/DATA copy generations an
//! AP transmission is admitted under; capturing one needs the native AP
//! source and the kernel's AP emission authority, neither of which a module
//! has. [`Capture`] is therefore uninhabited here (it holds an uninhabited
//! [`Source`]), which keeps the shared FullMAC seam's signatures while
//! making every AP path statically unreachable.
use super::{ap_source::Source, runtime::Error};
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;

/// The signed-domain instance an AP or monitor role was admitted under;
/// uninhabited in the module build like the roles themselves.
#[derive(Clone)]
pub(crate) struct Policy {
    native: Source,
}
impl Policy {
    pub(crate) fn domain(&self) -> &Arc<narf_wireless::reg::RegulatoryDomain> {
        self.native.absurd()
    }
    pub(crate) fn current(&self) -> bool {
        self.native.absurd()
    }
}

/// Uninhabited in the module build (see the module documentation).
#[derive(Clone)]
pub struct Capture {
    pub(super) native: Source,
}
impl core::fmt::Debug for Capture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.native.fmt(f)
    }
}
impl Capture {
    fn never(&self) -> ! {
        self.native.absurd()
    }
    pub(crate) fn interface_index(&self) -> u8 {
        self.never()
    }
    pub(crate) fn program_event_blocks(
        &self,
        _header: &crate::cyw43439::events::EventHeader,
    ) -> bool {
        self.never()
    }
    pub(crate) fn belongs_to(&self, live: &Arc<AtomicBool>) -> bool {
        self.native.belongs_to(live)
    }
    pub(crate) fn lifecycle(&self) -> bool {
        self.never()
    }
    pub(crate) fn transmit(&self, _bytes: &[u8]) -> bool {
        self.never()
    }
    pub(crate) fn same_role(&self, _other: &Self) -> bool {
        self.never()
    }
    pub(crate) fn role_current(&self) -> Result<(), Error> {
        self.native.current()
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        self.native.current()
    }
    pub(crate) fn publish<T>(&self, copy: impl FnOnce() -> T) -> Result<T, Error> {
        self.native.invoke(copy)
    }
}
