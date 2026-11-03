// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B WoW firmware swap on the one retained Startup, Linux 7.3-rc4
//! `wow.c::rtw89_wow_swap_fw`. The WoW image is selected from the file the
//! running normal image came from, through the same trusted registry
//! authority; the normal image is loaded again (never cached) on resume.
//! Any failure after the first download write terminalizes this owner;
//! the caller then takes the existing cold retirement path.
use super::{firmware_boot, firmware_registry, Attempt, Phase, Startup};
use crate::rtw89::{
    download_plan::DownloadPlan,
    lps_packets::{Namespace, Packets},
    mac::ChipId,
    power,
    secure::Blacklist,
    station_control::Admission,
    wow_security::Keys,
};

/// State that lives exactly as long as the WoW image runs.
pub(super) struct Window {
    /// PS-Poll/NULL/QoS-NULL templates installed in the WoW image.
    pub(super) packets: Packets,
}

impl Startup {
    fn wow_plan(&self, wow: bool) -> Result<DownloadPlan, power::Error> {
        let identity = self.identity.ok_or(power::Error::Terminal)?;
        if identity.chip() != ChipId::Rtl8852B {
            return Err(power::Error::Unsupported);
        }
        let image = if wow {
            let name = self
                .firmware
                .as_ref()
                .ok_or(power::Error::Terminal)?
                .image_name();
            firmware_registry::load_wow(name, identity.chip(), identity.cut())
        } else {
            firmware_registry::load(identity.chip(), identity.cut())
        }
        .map_err(|_| power::Error::Unsupported)?;
        DownloadPlan::new(
            image,
            identity.fuses(),
            Blacklist::upstream(identity.chip()),
        )
        .map_err(|_| power::Error::Unsupported)
    }
    fn wow_station_ready(&self) -> Result<(), power::Error> {
        if self.phase != Phase::RadioReady
            || self.monitor.is_some()
            || self
                .station_controller
                .as_ref()
                .and_then(|c| c.restore_facts())
                .is_none()
            || self.sleep.as_ref().is_some_and(|s| !s.wow_ready())
        {
            return Err(power::Error::Terminal);
        }
        Ok(())
    }
    /// `rtw89_wow_swap_fw(wow = true)`, between `wow_trx_enter_pre` and
    /// `wow_trx_enter_post`. `cam` is the address CAM body for the WoW
    /// window (security entries and WoL bits attached by the caller).
    pub(in crate::rtw89) async fn wow_swap_in(
        &mut self,
        cam: &[u8; 60],
        admission: &Admission,
    ) -> Result<(), power::Error> {
        self.wow_station_ready()?;
        if self.wow.is_some() {
            return Err(power::Error::Terminal);
        }
        // Resolve the image before any hardware write: a missing or
        // unverifiable WoW image leaves the awake station untouched.
        let plan = self.wow_plan(true)?;
        let mut attempt = Attempt::new(self);
        let result = attempt
            .owner_mut()
            .wow_swap(plan, cam, admission, true)
            .await;
        attempt.committed = result.is_ok();
        result
    }
    /// `rtw89_wow_swap_fw(wow = false)`, between `wow_trx_leave_pre` and
    /// `wow_trx_leave_post`, after the WoW image's `fw_stop`. Restores a
    /// freshly loaded normal image and the plain associated address CAM.
    pub(in crate::rtw89) async fn wow_swap_out(
        &mut self,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        let mut attempt = Attempt::new(self);
        let result = async {
            let owner = attempt.owner_mut();
            owner.wow.take().ok_or(power::Error::Terminal)?;
            owner.wow_station_ready()?;
            let cam = owner
                .station_controller
                .as_ref()
                .and_then(|c| c.associated_cam())
                .ok_or(power::Error::Terminal)?;
            let plan = owner.wow_plan(false)?;
            owner.wow_swap(plan, &cam, admission, false).await
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    async fn wow_swap(
        &mut self,
        plan: DownloadPlan,
        cam: &[u8; 60],
        admission: &Admission,
        wow: bool,
    ) -> Result<(), power::Error> {
        let namespace = match self.sleep.as_mut() {
            Some(sleep) => sleep.wow_swapped()?,
            None => Namespace::after_firmware(1).ok_or(power::Error::Terminal)?,
        };
        let firmware = self.firmware.as_mut().ok_or(power::Error::Terminal)?;
        firmware.swap(plan).await.map_err(|error| match error {
            firmware_boot::Error::Register(error) => error,
            _ => power::Error::Access,
        })?;
        let native = firmware.transport_mut();
        native.wow_firmware_loaded()?;
        native
            .wow_rf_pages(self.assets.as_ref().ok_or(power::Error::Terminal)?)
            .await?;
        let controller = self
            .station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?;
        controller
            .restore(&mut native.station_access(), cam, admission)
            .await?;
        // `rtw89_mac_hw_mgnt_sec(rtwdev, wow)` closes `rtw89_wow_swap_fw`.
        native.wow_mgnt_sec(wow)?;
        if !wow {
            // The normal image's general packets are the LPS owner's to
            // reinstall in the fresh namespace (`rtw89_fw_h2c_general_pkt`
            // runs again on its next install); none run before it.
            return Ok(());
        }
        let (peer, aid, wmm) = controller.restore_facts().ok_or(power::Error::Terminal)?;
        let mut namespace = namespace;
        let mut packets = namespace
            .reserve(peer, 1, aid, wmm)
            .map_err(|_| power::Error::Terminal)?;
        native.wow_general_packets(&mut packets, admission).await?;
        self.wow = Some(Window { packets });
        Ok(())
    }
    /// The security CAM entries of the snapshot, written by the running
    /// normal image after `wow_trx_enter_pre` and before `wow_swap_in`, as
    /// Linux's keys reached the CAM at association (`rtw89_cam_sec_key_add`).
    /// The WoW address CAM passed to `wow_swap_in` then attaches them.
    pub(in crate::rtw89) async fn wow_keys_in(
        &mut self,
        keys: &Keys,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        self.wow_station_ready()?;
        if self.wow.is_some() {
            return Err(power::Error::Terminal);
        }
        let mut attempt = Attempt::new(self);
        let result = async {
            attempt
                .owner_mut()
                .station_native()?
                .wow_sec_cam(&keys.entries, false, admission)
                .await
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    /// After `wow_swap_out` (plain associated CAM, management decryption
    /// off): overwrite every written entry with a zero key and prove
    /// `B_AX_{UC,BMC}_MGNT_DEC` clear again, so host CCMP/BIP alone sees
    /// RX once `wow_trx_leave_post` reopens the filters. Linux keeps its
    /// hardware keys; NARF's awake path never had any.
    pub(in crate::rtw89) async fn wow_keys_out(
        &mut self,
        keys: &Keys,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        let mut attempt = Attempt::new(self);
        let result = async {
            let owner = attempt.owner_mut();
            if owner.wow.is_some() {
                return Err(power::Error::Terminal);
            }
            owner.wow_station_ready()?;
            let native = owner.station_native()?;
            native.wow_sec_cam(&keys.entries, true, admission).await?;
            native.wow_mgnt_sec(false)
        }
        .await;
        attempt.committed = result.is_ok();
        result
    }
    /// The WoW address CAM (`rtw89_cam_fill_addr_cam_info` with
    /// `wowlan_pattern`/`wowlan_magic` and the security entries) on the
    /// plain associated body `commit_peer` installed.
    pub(in crate::rtw89) fn wow_cam(
        &self,
        keys: &Keys,
        pattern: bool,
        magic: bool,
    ) -> Option<[u8; 60]> {
        let base = self.station_controller.as_ref()?.associated_cam()?;
        Some(crate::rtw89::wow_security::wow_cam(
            &base, keys, pattern, magic,
        ))
    }
}
