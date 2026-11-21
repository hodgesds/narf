// SPDX-License-Identifier: GPL-2.0-or-later
//! Bridge the native firmware-owner `Io` to the shared chip core's `RegIo`.
//!
//! The `mac`/`phy`/(later `radio`) register programming lives in
//! `narf-drivers-wireless-rtl-chip`, generic over `RegIo`. `RegIo` is foreign
//! to this crate, so an orphan-rule-clean [`IoReg`] newtype carries the impl;
//! it forwards each access 1:1 (no extra register traffic, so the byte-exact
//! register trace is preserved) and maps the error type.
use super::firmware_transport::{Error, Io};
use narf_drivers_wireless_rtl_chip::{ChipError, RegIo};

/// `Io` (a `Send` superset of `RegIo`) wrapped as a `RegIo` for the chip core.
pub(super) struct IoReg<'a, T: Io>(pub(super) &'a mut T);

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
        self.0.read8(reg).await.map_err(to_chip)
    }
    async fn read16(&mut self, reg: u16) -> Result<u16, ChipError> {
        self.0.read16(reg).await.map_err(to_chip)
    }
    async fn read32(&mut self, reg: u16) -> Result<u32, ChipError> {
        self.0.read32(reg).await.map_err(to_chip)
    }
    async fn write8(&mut self, reg: u16, value: u8) -> Result<(), ChipError> {
        self.0.write8(reg, value).await.map_err(to_chip)
    }
    async fn write16(&mut self, reg: u16, value: u16) -> Result<(), ChipError> {
        self.0.write16(reg, value).await.map_err(to_chip)
    }
    async fn write32(&mut self, reg: u16, value: u32) -> Result<(), ChipError> {
        self.0.write32(reg, value).await.map_err(to_chip)
    }
    async fn delay_us(&mut self, us: u32) {
        self.0.delay_us(u64::from(us)).await
    }
}
