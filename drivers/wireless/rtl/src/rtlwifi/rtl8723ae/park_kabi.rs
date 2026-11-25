// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted below the module's `firmware_native`: the scalar adapter the
//! RTL8723AE/RTL8821AE terminal parks drive (the built-in `park_native`),
//! each access re-checking the function's command gate and identity.
use super::*;
pub(super) struct ParkIo<'a>(pub(super) &'a PciIo);
impl ParkIo<'_> {
    fn access<T>(
        &self,
        reg: u16,
        width: usize,
        f: impl FnOnce(&MmioRegion) -> T,
    ) -> Result<T, Error> {
        self.0.access(reg, width, || {
            self.0.check_identity()?;
            Ok(f(&self.0.registers))
        })?
    }
}
#[async_trait::async_trait]
impl Io for ParkIo<'_> {
    fn read8(&self, r: u16) -> Result<u8, Error> {
        // SAFETY: bounded extent and current identity checked by `access`.
        self.access(r, 1, |m| unsafe { m.read8(u64::from(r)) })
    }
    fn read16(&self, r: u16) -> Result<u16, Error> {
        if r & 1 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned word; extent checked by `access`.
        self.access(r, 2, |m| unsafe { m.read16(u64::from(r)) })
    }
    fn read32(&self, r: u16) -> Result<u32, Error> {
        if r & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword; extent checked by `access`.
        self.access(r, 4, |m| unsafe { m.read32(u64::from(r)) })
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), Error> {
        // SAFETY: as `read8`.
        self.access(r, 1, |m| unsafe { m.write8(u64::from(r), v) })
    }
    fn write16(&self, _r: u16, _v: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), Error> {
        if r & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: as `read32`.
        self.access(r, 4, |m| unsafe { m.write32(u64::from(r), v) })
    }
    fn write_bytes(&self, _r: u16, _b: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
