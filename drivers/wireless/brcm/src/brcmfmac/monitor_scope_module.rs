// SPDX-License-Identifier: GPL-2.0-or-later
//! Module build: no monitor receive owner can be captured.
//!
//! Built in, `monitor_scope.rs` binds a monitor capture to the native source,
//! the netdev's open/stop generation and the signed receive policy.
//! `brcmfmac.ko` carries no monitor role, so [`Capture`] is uninhabited (it
//! holds an uninhabited [`Source`]) and [`Received`] cannot be built either.
use super::ap_source::Source;
use crate::cyw43439::runtime::Error;

/// Uninhabited in the module build (see the module documentation).
#[derive(Clone)]
pub struct Capture {
    pub(super) native: Source,
    pub(super) frequency: u16,
    pub(super) chanspec: u16,
}
impl core::fmt::Debug for Capture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.native.fmt(f)
    }
}
impl Capture {
    pub(super) fn command_current(&self) -> Result<(), Error> {
        self.native.absurd()
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        self.native.absurd()
    }
    pub(crate) fn retire(&self) {
        self.native.absurd()
    }
    pub(crate) fn publish<T>(&self, _copy: impl FnOnce() -> T) -> Result<T, Error> {
        self.native.absurd()
    }
    pub(super) fn same_owner(&self, _other: &Self) -> bool {
        self.native.absurd()
    }
}

/// A received monitor frame; uninhabited with its [`Capture`].
pub struct Received {
    original: Capture,
}
impl core::fmt::Debug for Received {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.original.fmt(f)
    }
}
impl Received {
    pub(super) fn new(_bytes: alloc::vec::Vec<u8>, original: Capture) -> Self {
        Self { original }
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.original.native.absurd()
    }
    pub(crate) fn original(&self) -> &Capture {
        &self.original
    }
}
