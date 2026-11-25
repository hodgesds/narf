// SPDX-License-Identifier: GPL-2.0-or-later
//! Module build: the original native AP source does not exist.
//!
//! Built in, `ap_source.rs` retains the PCI/SDIO device authority a native
//! AP role is entered with. `brcmfmac.ko` carries no AP role, and its
//! backplane never offers a source (`runtime::Bus::ap_source` keeps its
//! `None` default), so this [`Source`] is uninhabited: the shared FullMAC
//! seam keeps its signatures and every AP path is statically unreachable.
use super::runtime::Error;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;

#[derive(Clone, Copy)]
enum Never {}

/// Uninhabited: no value of this type can be created in the module build.
#[derive(Clone)]
pub struct Source {
    never: Never,
}
impl core::fmt::Debug for Source {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.never {}
    }
}
impl Source {
    /// The proof that no value exists.
    pub(crate) fn absurd(&self) -> ! {
        match self.never {}
    }
    pub(crate) fn retain(self, _live: &Arc<AtomicBool>) -> Self {
        match self.never {}
    }
    pub(crate) fn belongs_to(&self, _live: &Arc<AtomicBool>) -> bool {
        match self.never {}
    }
    pub(super) fn same_generation(&self, _other: &Self) -> bool {
        match self.never {}
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        match self.never {}
    }
    pub(crate) fn invoke<T>(&self, _copy: impl FnOnce() -> T) -> Result<T, Error> {
        match self.never {}
    }
}
