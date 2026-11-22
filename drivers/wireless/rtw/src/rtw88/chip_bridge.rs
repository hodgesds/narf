// SPDX-License-Identifier: GPL-2.0-or-later
//! Bridge the native firmware-owner `Io` to the shared chip core's `RegIo`.
//!
//! The `mac`/`phy`/`radio` register programming lives in
//! `narf-drivers-wireless-rtl-chip`, generic over `RegIo`. `RegIo` is foreign
//! to this crate, so an orphan-rule-clean [`IoReg`] newtype carries the impl;
//! it forwards each access 1:1 (no extra register traffic, so the byte-exact
//! register trace is preserved).
//!
//! `ChipError` is a deliberately small set, so it cannot represent the richer
//! native errors (e.g. a `Checked` policy wrapper's `Error::Power`/`State`).
//! The bridge therefore *captures* the exact native error of the last failed
//! access; a shim maps the core's `ChipError` back with [`IoReg::err`], which
//! prefers that captured error over the lossy `ChipError` round-trip.
use super::firmware_transport::{Error, Io};
use narf_drivers_wireless_rtl_chip::{ChipError, RegIo};

/// `Io` (a `Send` superset of `RegIo`) wrapped as a `RegIo` for the chip core.
/// Build with [`bridge`]; map the core result with [`IoReg::err`].
pub(super) struct IoReg<'a, T: Io> {
    io: &'a mut T,
    err: Option<Error>,
}

/// Wrap `io` for a chip-core call.
pub(super) fn bridge<T: Io>(io: &mut T) -> IoReg<'_, T> {
    IoReg { io, err: None }
}

impl<T: Io> IoReg<'_, T> {
    /// Map a chip-core error back into the native error set, preferring the
    /// exact native error captured during the run (policy/power/state errors
    /// `ChipError` cannot carry) over the lossy `ChipError` round-trip.
    pub(super) fn err(&mut self, chip: ChipError) -> Error {
        self.err.take().unwrap_or_else(|| from_chip(chip))
    }
}

/// Map the chip core's result back into the native error set. A plain fn (not a
/// `From` impl) keeps the broad `Error: From<_>` inference at unrelated `?`
/// sites unchanged.
pub(super) fn from_chip(err: ChipError) -> Error {
    match err {
        ChipError::Access => Error::Access,
        ChipError::Gone => Error::Gone,
        ChipError::Timeout => Error::Timeout,
        ChipError::Prerequisite => Error::Prerequisite,
        ChipError::Unsupported => Error::Unsupported,
    }
}
/// Map a native register-transport error into the chip core's narrower set.
/// Register access only yields `Gone` (the device vanished) or `Access`.
fn to_chip(err: Error) -> ChipError {
    match err {
        Error::Gone => ChipError::Gone,
        Error::Timeout => ChipError::Timeout,
        Error::Prerequisite => ChipError::Prerequisite,
        Error::Unsupported => ChipError::Unsupported,
        _ => ChipError::Access,
    }
}

impl<T: Io> RegIo for IoReg<'_, T> {
    async fn read8(&mut self, reg: u16) -> Result<u8, ChipError> {
        self.io.read8(reg).await.map_err(|e| {
            self.err = Some(e);
            to_chip(e)
        })
    }
    async fn read16(&mut self, reg: u16) -> Result<u16, ChipError> {
        self.io.read16(reg).await.map_err(|e| {
            self.err = Some(e);
            to_chip(e)
        })
    }
    async fn read32(&mut self, reg: u16) -> Result<u32, ChipError> {
        self.io.read32(reg).await.map_err(|e| {
            self.err = Some(e);
            to_chip(e)
        })
    }
    async fn write8(&mut self, reg: u16, value: u8) -> Result<(), ChipError> {
        self.io.write8(reg, value).await.map_err(|e| {
            self.err = Some(e);
            to_chip(e)
        })
    }
    async fn write16(&mut self, reg: u16, value: u16) -> Result<(), ChipError> {
        self.io.write16(reg, value).await.map_err(|e| {
            self.err = Some(e);
            to_chip(e)
        })
    }
    async fn write32(&mut self, reg: u16, value: u32) -> Result<(), ChipError> {
        self.io.write32(reg, value).await.map_err(|e| {
            self.err = Some(e);
            to_chip(e)
        })
    }
    async fn delay_us(&mut self, us: u32) {
        self.io.delay_us(u64::from(us)).await
    }
}
