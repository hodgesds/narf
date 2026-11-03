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
        // mac.c::__rtw_download_firmware resets `h2c.seq` per download, so
        // the swapped image's info packets carry 0/1 exactly as at bring-up
        // (the native swap window enforces that running counter).
        super::super::command::send(&mut self.io, &super::super::command::general(mac, 0)?).await?;
        super::super::command::send(&mut self.io, &super::super::command::phydm(phy, 1)?).await?;
        self.phase = Phase::Station;
        Ok(())
    }
    /// `rtw_wow_suspend` inputs from the managed-linked, settled station:
    /// own address, AP, AID, WMM and the AOAC temporal keys. Refuses an
    /// unassociated, handshaking, switching or retuning station.
    pub(in super::super) fn wow_plan(
        &self,
        config: &narf_wireless::WowlanConfig,
    ) -> Result<super::super::wow::Plan, super::super::wow::Error> {
        use super::super::wow::Error as WowError;
        self.wow_live()?;
        let station = self.station.as_deref().ok_or(WowError::Unsupported)?;
        if !station.ready() || station.phase() != super::super::station::Phase::Open {
            return Err(WowError::Unsupported);
        }
        let peer = station.peer().ok_or(WowError::Unsupported)?;
        let aid = station.aid().ok_or(WowError::Unsupported)?;
        let wmm = station.wmm().ok_or(WowError::Unsupported)?;
        let keys = station.suspend_keys().map_err(|_| WowError::Unsupported)?;
        super::super::wow::Plan::new(
            self.did,
            config,
            station.local(),
            peer,
            aid,
            wmm,
            keys.as_ref(),
        )
    }
    /// `rtw_wow_suspend` on this retained station owner: the WoW image is
    /// opened through the same registry/signature authority as the NIC
    /// image. The caller holds the retained mutex and has closed host
    /// packet publication; an error leaves the owner for the cold path.
    pub(in super::super) async fn wow_suspend(
        &mut self,
        config: &narf_wireless::WowlanConfig,
    ) -> Result<super::super::wow::Armed, super::super::wow::Error> {
        let plan = self.wow_plan(config)?;
        let image = super::registered_wow_image(self.did)?;
        super::super::wow::suspend(self, &plan, &image).await
    }
    /// `rtw_wow_resume`: restores a freshly registered normal image (never a
    /// cached copy). The report is returned even when the restore fails.
    pub(in super::super) async fn wow_resume(
        &mut self,
        armed: super::super::wow::Armed,
    ) -> (
        Option<super::super::wow::WakeReport>,
        Result<(), super::super::wow::Error>,
    ) {
        let image = match super::registered_image(self.did) {
            Ok(image) => image,
            Err(e) => {
                // The WoW firmware stays armed; the caller takes the cold
                // full-restart path. Still capture the wake reason.
                let report = self
                    .io
                    .read8(super::super::wow::REG_WOWLAN_WAKE_REASON)
                    .ok()
                    .map(super::super::wow::decode);
                drop(armed);
                return (report, Err(e.into()));
            }
        };
        let (report, mut result) = super::super::wow::resume(self, armed, &image).await;
        if result.is_ok() && report.as_ref().is_some_and(super::super::wow::keeps_link) {
            if let Some(station) = self.station.as_deref_mut() {
                result = station
                    .wow_resumed()
                    .map_err(|_| super::super::wow::Error::Unsupported);
            }
        }
        (report, result)
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
