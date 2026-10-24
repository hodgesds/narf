//! Source register transactions shared only by the initial TSSI/DPK owners.
use super::{Error, Interface};
use crate::rtw89::{power, rfk::Entry};
pub(in crate::rtw89) struct Access<'a, I>(pub(in crate::rtw89) &'a mut I);
impl<I: Interface> Access<'_, I> {
    pub(in crate::rtw89) fn bb(&mut self, address: u32, mask: u32) -> Result<u32, Error> {
        if address > 0xffff || address & 3 != 0 || mask == 0 {
            return Err(Error::Table);
        }
        self.0.admit()?;
        let value = self.0.read32(0x10000 + address)?;
        if value == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok((value & mask) >> mask.trailing_zeros())
    }
    pub(in crate::rtw89) fn wm(
        &mut self,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let old = self.bb(address, u32::MAX)?;
        if mask == 0 {
            return Err(Error::Table);
        }
        self.0.admit()?;
        self.0.write32(
            0x10000 + address,
            (old & !mask) | (value << mask.trailing_zeros() & mask),
        )?;
        Ok(())
    }
    pub(in crate::rtw89) fn write(&mut self, address: u32, value: u32) -> Result<(), Error> {
        if address > 0xffff || address & 3 != 0 {
            return Err(Error::Table);
        }
        self.0.admit()?;
        self.0.write32(0x10000 + address, value)?;
        Ok(())
    }
    pub(in crate::rtw89) fn set(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        let old = self.bb(address, u32::MAX)?;
        self.0.admit()?;
        self.0.write32(0x10000 + address, old | mask)?;
        Ok(())
    }
    pub(in crate::rtw89) fn clear(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        let old = self.bb(address, u32::MAX)?;
        self.0.admit()?;
        self.0.write32(0x10000 + address, old & !mask)?;
        Ok(())
    }
    pub(in crate::rtw89) async fn rr(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
    ) -> Result<u32, Error> {
        self.0.admit()?;
        let result = self.0.rf_read(path, address, mask).await?;
        self.0.admit()?;
        if result == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok(result)
    }
    pub(in crate::rtw89) async fn wr(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.0.admit()?;
        self.0.rf_write(path, address, mask, value).await?;
        self.0.admit()
    }
    pub(in crate::rtw89) async fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()
    }
    pub(in crate::rtw89) async fn table(&mut self, entries: &[Entry]) -> Result<(), Error> {
        for &Entry(kind, path, address, mask, value) in entries {
            match kind {
                0 => self.wr(path, address, mask, value).await?,
                1 => self.wm(address, mask, value)?,
                2 => self.set(address, mask)?,
                3 => self.clear(address, mask)?,
                4 => self.delay(u64::from(value)).await?,
                _ => return Err(Error::Table),
            }
        }
        Ok(())
    }
    pub(in crate::rtw89) async fn poll(
        &mut self,
        address: u32,
        mask: u32,
        expected: u32,
        step: u64,
        budget: u64,
    ) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.bb(address, mask)? == expected {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= budget {
                return Err(power::Error::Timeout.into());
            }
            self.delay(step).await?;
        }
    }
    pub(in crate::rtw89) async fn rx_idle(&mut self) -> Result<(), Error> {
        for path in 0..2 {
            let start = self.0.now_us();
            loop {
                // Source _wait_rx_mode: neither path may remain in TX mode2.
                if self.rr(path, 0, 0xf0000).await? != 2 {
                    break;
                }
                if self.0.now_us().saturating_sub(start) >= 5000 {
                    return Err(power::Error::Timeout.into());
                }
                self.delay(2).await?;
            }
        }
        Ok(())
    }
}
