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
    wow_wire,
};
use alloc::vec::Vec;

/// The station's firmware MAC id (`profile_fingerprint`: STA MACID0).
const STATION_MAC_ID: u8 = 0;

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
    /// `rtw89_fw_h2c_keep_alive` (DONE_ACK) on the WoW image with the
    /// window's NULL data template (`lps_packets` NULL offload, installed by
    /// `wow_general_packets`). Linux offloads an ARP response that the
    /// firmware protects under `ptk_alg`; this profile keeps the firmware
    /// free of protected transmissions, so host transmit PNs stay unique
    /// without the AOAC `ptk_tx_iv` write-back (GTK/ARP offload stay off).
    /// Disabling sends packet id 0, as Linux.
    pub(in crate::rtw89) async fn wow_keep_alive(
        &mut self,
        enable: bool,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        let packet = self
            .wow
            .as_ref()
            .ok_or(power::Error::Terminal)?
            .packets
            .null_id();
        let body = wow_wire::keep_alive(enable, packet, STATION_MAC_ID);
        self.station_native()?
            .wow_command(
                wow_wire::H2C_CL_MAC_WOW,
                wow_wire::H2C_FUNC_KEEP_ALIVE,
                &body,
                true,
                admission,
            )
            .await
    }
}

/// Wake inputs retained from [`Startup::wow_suspend`] to
/// [`Startup::wow_resume`] (`struct rtw89_wow_param` subset).
pub(super) struct Armed {
    keys: Keys,
    patterns: Vec<wow_wire::Pattern>,
    magic: bool,
    disconnect: bool,
}
impl core::fmt::Debug for Armed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89WowArmed")
            .field("patterns", &self.patterns.len())
            .field("magic", &self.magic)
            .field("disconnect", &self.disconnect)
            .finish_non_exhaustive()
    }
}

impl Startup {
    async fn wow_h2c(
        &mut self,
        function: u8,
        body: &[u8],
        done: bool,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        self.station_native()?
            .wow_command(wow_wire::H2C_CL_MAC_WOW, function, body, done, admission)
            .await
    }
    /// `rtw89_wow_cfg_wake`: `WAKEUP_CTRL`, the address CAM
    /// (`RTW89_ROLE_INFO_CHANGE`; RTL8852B has no `h2c_dctl_sec_cam`) and
    /// `WOW_GLOBAL`. Disabling follows `rtw89_wow_key_clear`, so the global
    /// carries zero algorithms and key info, and the CAM drops the WoL bits
    /// but keeps the security entries until the swap restores the plain one.
    async fn wow_cfg_wake(
        &mut self,
        armed: &Armed,
        wow: bool,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        let patterns = wow && !armed.patterns.is_empty();
        let magic = wow && armed.magic;
        let ctrl = wow_wire::wakeup_ctrl(
            wow,
            !armed.patterns.is_empty(),
            armed.magic,
            armed.disconnect,
            STATION_MAC_ID,
        );
        self.wow_h2c(wow_wire::H2C_FUNC_WAKEUP_CTRL, &ctrl, true, admission)
            .await?;
        let cam = self
            .wow_cam(&armed.keys, patterns, magic)
            .ok_or(power::Error::Terminal)?;
        self.station_native()?.wow_addr_cam(&cam, admission).await?;
        let global = if wow {
            wow_wire::wow_global(
                true,
                STATION_MAC_ID,
                armed.keys.pairwise,
                armed.keys.group,
                &armed.keys.key_info,
            )
        } else {
            wow_wire::wow_global(
                false,
                STATION_MAC_ID,
                wow_wire::Alg::None,
                wow_wire::Alg::None,
                &wow_wire::KeyInfo::default(),
            )
        };
        self.wow_h2c(wow_wire::H2C_FUNC_WOW_GLOBAL, &global, true, admission)
            .await
    }
    /// `rtw89_wow_check_fw_status`: `R_AX_WOW_CTRL` & `B_AX_WOW_WOWEN`
    /// every 50us for at most 50ms.
    async fn wow_fw_status(&mut self, enable: bool) -> Result<(), power::Error> {
        use crate::rtw89::power::Io as _;
        let native = self.station_native()?;
        let start = native.now_us();
        loop {
            let on = native.read8(wow_wire::R_AX_WOW_CTRL)? & wow_wire::B_AX_WOW_WOWEN != 0;
            if on == enable {
                return Ok(());
            }
            if native.now_us().saturating_sub(start) >= wow_wire::WOW_STATUS_TIMEOUT_US {
                return Err(power::Error::Timeout);
            }
            native.delay_us(wow_wire::WOW_STATUS_POLL_US).await;
        }
    }
    /// `rtw89_wow_fw_start` (connected): pattern CAM, keep-alive,
    /// disconnect detection, `rtw89_wow_cfg_wake(true)`, then WOW_EN.
    /// GTK offload is not sent (no rekey data; RTL8852B declares no
    /// GTK-rekey wake) and ARP offload stays off.
    async fn wow_fw_start(
        &mut self,
        armed: &Armed,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        for (index, pattern) in armed.patterns.iter().enumerate() {
            let body = wow_wire::cam_update(index as u8, Some(pattern))
                .ok_or(power::Error::Unsupported)?;
            self.wow_h2c(wow_wire::H2C_FUNC_WOW_CAM_UPD, &body, true, admission)
                .await?;
        }
        self.wow_keep_alive(true, admission).await?;
        let detect = wow_wire::disconnect_detect(true, armed.disconnect, STATION_MAC_ID);
        self.wow_h2c(
            wow_wire::H2C_FUNC_DISCONNECT_DETECT,
            &detect,
            true,
            admission,
        )
        .await?;
        self.wow_cfg_wake(armed, true, admission).await?;
        self.wow_fw_status(true).await
    }
    /// `rtw89_wow_fw_stop` (connected): pattern CAM clear, keep-alive and
    /// disconnect detection off, `rtw89_wow_cfg_wake(false)`, WOW_EN clear.
    async fn wow_fw_stop(
        &mut self,
        armed: &Armed,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        for index in 0..armed.patterns.len() {
            let body = wow_wire::cam_update(index as u8, None).ok_or(power::Error::Unsupported)?;
            self.wow_h2c(wow_wire::H2C_FUNC_WOW_CAM_UPD, &body, true, admission)
                .await?;
        }
        self.wow_keep_alive(false, admission).await?;
        let detect = wow_wire::disconnect_detect(false, armed.disconnect, STATION_MAC_ID);
        self.wow_h2c(
            wow_wire::H2C_FUNC_DISCONNECT_DETECT,
            &detect,
            true,
            admission,
        )
        .await?;
        self.wow_cfg_wake(armed, false, admission).await?;
        self.wow_fw_status(false).await
    }
    /// The AOAC report by packet (`rtw89_fw_h2c_wow_request_aoac`, RECV_ACK,
    /// answered by C2H MAC class 3 function 0), only for a secured link
    /// (`ptk_alg`). Linux ignores its failure; so does this owner, which
    /// uses it only for the pattern index (host PN state is not updated).
    async fn wow_aoac(
        &mut self,
        armed: &Armed,
        admission: &Admission,
    ) -> Option<wow_wire::AoacReport> {
        if !armed.keys.secured() {
            return None;
        }
        self.wow_h2c(
            wow_wire::H2C_FUNC_AOAC_REPORT_REQ,
            &wow_wire::aoac_request(),
            false,
            admission,
        )
        .await
        .ok()?;
        let bytes = self
            .station_native()
            .ok()?
            .wow_c2h(1, wow_wire::C2H_CLASS_WOW, wow_wire::C2H_FUNC_AOAC_REPORT)
            .await
            .ok()?;
        wow_wire::decode_aoac(bytes.get(8..)?)
    }
    /// `rtw89_wow_suspend` -> `rtw89_wow_enable` on the associated,
    /// settled station: validate every wake input before any write
    /// (`rtw89_wow_set_wakeups`), then `enable_trx_pre`, the security CAM,
    /// `swap_fw(true)`, `fw_start` and `enable_trx_post`. Any failure
    /// terminalizes this owner for the existing cold path. Linux's WoW LPS
    /// (`rtw89_wow_enter_ps`) is not entered: the radio stays awake.
    pub(in crate::rtw89) async fn wow_suspend(
        &mut self,
        config: &narf_wireless::WowlanConfig,
        keys: Option<&narf_wireless::station_security::SuspendKeys>,
        floors: Option<&narf_wireless::station_security::SuspendFloors>,
        admission: &Admission,
    ) -> Result<(), power::Error> {
        self.wow_station_ready()?;
        if self.wow.is_some() || self.wow_armed.is_some() {
            return Err(power::Error::Terminal);
        }
        let own = self.identity.ok_or(power::Error::Terminal)?.mac();
        let patterns = wow_wire::validate(config, own).map_err(|_| power::Error::Unsupported)?;
        let keys = crate::rtw89::wow_security::plan(keys, floors)
            .map_err(|_| power::Error::Unsupported)?;
        let cpu_io_rx = crate::rtw89::wow_trx::CpuIoRx::for_8852b(
            self.assets
                .as_ref()
                .ok_or(power::Error::Terminal)?
                .firmware_version(),
        );
        let armed = Armed {
            keys,
            patterns,
            magic: config.magic_packet,
            disconnect: config.disconnect,
        };
        let mut attempt = Attempt::new(self);
        let result = async {
            let owner = attempt.owner_mut();
            owner.station_native()?.wow_trx_enter_pre().await?;
            owner.wow_keys_in(&armed.keys, admission).await?;
            let cam = owner
                .wow_cam(&armed.keys, !armed.patterns.is_empty(), armed.magic)
                .ok_or(power::Error::Terminal)?;
            owner.wow_swap_in(&cam, admission).await?;
            owner.wow_fw_start(&armed, admission).await?;
            owner.station_native()?.wow_trx_enter_post(cpu_io_rx).await
        }
        .await;
        attempt.committed = result.is_ok();
        if result.is_ok() {
            attempt.owner_mut().wow_armed = Some(armed);
        }
        result
    }
    /// `rtw89_wow_resume`: the wake reason (`rtw89_wow_show_wakeup_reason`),
    /// `disable_trx_pre` with the AOAC report, `fw_stop`, `swap_fw(false)`,
    /// the security CAM clear and `disable_trx_post`. The report is returned
    /// even when the restore fails; any failure terminalizes this owner for
    /// the cold path.
    pub(in crate::rtw89) async fn wow_resume(
        &mut self,
        admission: &Admission,
    ) -> (Option<wow_wire::WakeReport>, Result<(), power::Error>) {
        use crate::rtw89::power::Io as _;
        let Some(armed) = self.wow_armed.take() else {
            return (None, Err(power::Error::Terminal));
        };
        let mut attempt = Attempt::new(self);
        let mut report = None;
        let result = async {
            let owner = attempt.owner_mut();
            let reason = owner.station_native()?.read8(wow_wire::WAKE_REASON_REG)?;
            owner.station_native()?.wow_trx_leave_pre().await?;
            let aoac = owner.wow_aoac(&armed, admission).await;
            report = Some(wow_wire::decode_reason(reason, aoac.as_ref()));
            owner.wow_fw_stop(&armed, admission).await?;
            owner.wow_swap_out(admission).await?;
            owner.wow_keys_out(&armed.keys, admission).await?;
            owner.station_native()?.wow_trx_leave_post()
        }
        .await;
        attempt.committed = result.is_ok();
        (report, result)
    }
    /// True while the WoW image owns the radio (between a successful
    /// [`Self::wow_suspend`] and [`Self::wow_resume`]).
    pub(in crate::rtw89) fn wow_armed(&self) -> bool {
        self.wow_armed.is_some()
    }
}
