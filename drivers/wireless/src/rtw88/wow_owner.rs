// SPDX-License-Identifier: GPL-2.0-or-later
//! `wow::Io` on the retained station firmware owner, Linux 7.3-rc4
//! `rtw88/wow.c` (`rtw_wow_swap_fw`, `rtw_wow_config_*_rsvd_page`) over the
//! native swap window (`reserved_page::Backend` swap mode + `pci_swap.rs`).
//! Every operation requires the exact `Phase::Station` owner; a failed
//! firmware swap poisons it (`Phase::Failed`) and later calls refuse, so the
//! caller can only take the cold full-restart path.
use super::{Error, Io, Owner, Phase, PreparedImage};
use alloc::boxed::Box;

impl<I: Io> Owner<I> {
    fn wow_live(&self) -> Result<(), Error> {
        if self.phase != Phase::Station || self.did != 0xc822 {
            return Err(Error::State);
        }
        Ok(())
    }
    /// `rtw_wow_swap_fw`: `rtw_download_firmware`, then
    /// `rtw_fw_send_general_info` / `rtw_fw_send_phydm_info` for the fresh
    /// image (`rtw_wow_fw_media_status` is the caller's mailbox H2C).
    pub(super) async fn wow_swap(&mut self, image: &PreparedImage) -> Result<(), Error> {
        self.wow_live()?;
        let mac = self.mac.ok_or(Error::State)?;
        let phy = self.phy.ok_or(Error::State)?;
        self.swap_firmware(image).await?;
        self.phase = Phase::Failed;
        super::super::command::send(&mut self.io, &super::super::command::general(mac, 0)?).await?;
        super::super::command::send(&mut self.io, &super::super::command::phydm(phy, 1)?).await?;
        self.phase = Phase::Station;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<I: Io> super::super::wow::Io for Owner<I> {
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        self.wow_live()?;
        self.io.read8(reg)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.wow_live()?;
        self.io.read32(reg)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.wow_live()?;
        self.io.write8(reg, value)
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.wow_live()?;
        self.io.write32(reg, value)
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
    async fn download(&mut self, image: &PreparedImage) -> Result<(), Error> {
        self.wow_swap(image).await
    }
    async fn reserved_page(&mut self, pages: &[u8]) -> Result<(), Error> {
        self.wow_live()?;
        self.io.swap_page(pages).await
    }
    async fn h2c(&mut self, command: [u8; 8]) -> Result<(), Error> {
        self.wow_live()?;
        super::super::station_control::send(&mut self.io, command, None).await
    }
    fn hci_stop(&mut self) -> Result<(), Error> {
        self.wow_live()?;
        self.io.hci_stop()
    }
    async fn hci_restart(&mut self) -> Result<(), Error> {
        self.wow_live()?;
        self.io.hci_restart()
    }
    fn end_swap(&mut self) -> Result<(), Error> {
        self.wow_live()?;
        self.io.end_swap()
    }
}
