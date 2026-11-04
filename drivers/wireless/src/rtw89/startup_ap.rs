// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Borrowed AP adapter: Startup retains the `ApController` beside the same
//! Firmware<Native> the station uses. The AP and station control owners are
//! mutually exclusive (both hold MACID0/port0/address CAM 0). The controller
//! is retained before every awaited command, like the station controller.
use super::*;
use crate::rtw89::{
    ap_control::{ApController, Phase as ApPhase, PortConfig},
    packet_core as packet, station_control as control,
};

impl Startup {
    fn ap_parts(&mut self) -> Result<(&mut ApController, &mut Native), power::Error> {
        if self.phase == Phase::Terminal {
            return Err(power::Error::Terminal);
        }
        let controller = self.ap_controller.as_mut().ok_or(power::Error::Terminal)?;
        let firmware = self.firmware.as_mut().ok_or(power::Error::Terminal)?;
        if firmware.phase() != firmware_boot::Phase::Running {
            return Err(power::Error::Terminal);
        }
        Ok((controller, firmware.transport_mut()))
    }
    /// RTL8852B radio ready, no station/monitor owner.
    pub(super) fn ap_admissible(&mut self) -> Result<(), power::Error> {
        if self.monitor.is_some() || self.station_controller.is_some() {
            return Err(power::Error::Terminal);
        }
        if self
            .identity
            .is_none_or(|identity| identity.chip() != crate::rtw89::mac::ChipId::Rtl8852B)
        {
            return Err(power::Error::Unsupported);
        }
        self.station_native()?.ordinary_current()
    }
    /// Signed AP channel/power admission and program. Linux reaches the AP
    /// channel through chanctx assignment before `rtw89_ops_start_ap`:
    /// chan.c `rtw89_chanctx_ops_assign_vif` -> core.c `rtw89_set_channel`
    /// and `rtw89_chip_rfk_channel` (rtw8852b.c `rtw8852b_rfk_channel`).
    /// Here that is the same signed full-radio retune the station uses
    /// (`Native::retune_full_radio`), so only a primary with a current
    /// signed full program (N52B channel 1, N52C otherwise) whose host rule
    /// permits active emission is admitted. rtw89 registers no
    /// `radar_detect_widths` (core.c `rtw89_iface_combs`), so cfg80211
    /// (`cfg80211_reg_can_beacon`) never lets it beacon on a RADAR or NO_IR
    /// channel; such a primary is refused here as well. Runs before
    /// `ap_prepare`, with no AP packet owner or peer.
    pub(super) async fn ap_channel(
        &mut self,
        primary: u8,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        self.ap_admissible()?;
        if self.ap_controller.is_some() {
            return Err(power::Error::Terminal);
        }
        let native = self.station_native()?;
        if !crate::rtw89::station::channel_admitted(native.admitted_channels()?, primary) {
            return Err(power::Error::Unsupported);
        }
        if crate::rtw89::station::passive_only(native.station_regulatory()?.as_ref(), primary) {
            return Err(power::Error::Unsupported);
        }
        admission.check()?;
        let epoch = self.retune_channel(primary, false).await?;
        admission.check()?;
        self.ap_admissible()?;
        Ok(epoch)
    }
    /// `rtw89_ops_add_interface` (AP): `rtw89_mac_vif_init`, then the AP
    /// packet owner with the CH9 high queue published.
    pub(super) async fn ap_prepare(
        &mut self,
        own: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        self.ap_admissible()?;
        if self.ap_controller.is_some() || self.identity.ok_or(power::Error::Terminal)?.mac() != own
        {
            return Err(power::Error::Terminal);
        }
        let controller = self.station_native()?.ap_controller()?;
        self.ap_controller = Some(controller); // retained before await
        let (controller, native) = self.ap_parts()?;
        controller
            .initialize(&mut native.station_access(), admission)
            .await?;
        let port = controller.link().port;
        native
            .prepare_ap_packets(own, port)
            .map_err(|_| power::Error::Access)
    }
    pub(super) async fn ap_start(
        &mut self,
        config: PortConfig,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        let (controller, native) = self.ap_parts()?;
        controller
            .start(&mut native.station_access(), config, admission)
            .await
    }
    pub(super) async fn ap_publish_beacon(
        &mut self,
        beacon: &[u8],
        tim_at: usize,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        let (controller, native) = self.ap_parts()?;
        controller
            .publish_beacon(&mut native.station_access(), beacon, tim_at, admission)
            .await
    }
    /// `rtw89_core_sta_link_add` (AP) and the packet MACID binding.
    pub(super) async fn ap_add_peer(
        &mut self,
        addr: [u8; 6],
        admission: &control::Admission,
    ) -> Result<u8, power::Error> {
        let (controller, native) = self.ap_parts()?;
        let macid = controller
            .add_peer(&mut native.station_access(), addr, admission)
            .await?;
        native.ap_bind_peer(addr, macid)?;
        Ok(macid)
    }
    pub(super) async fn ap_associate_peer(
        &mut self,
        addr: [u8; 6],
        aid: u16,
        ra: [u8; 16],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        let (controller, native) = self.ap_parts()?;
        controller
            .associate_peer(&mut native.station_access(), addr, aid, ra, admission)
            .await
    }
    /// The packet binding is withdrawn first, so no frame is published on
    /// the MACID while `rtw89_core_sta_link_remove` releases it.
    pub(super) async fn ap_remove_peer(
        &mut self,
        addr: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        let (controller, native) = self.ap_parts()?;
        native.ap_unbind_peer(addr);
        controller
            .remove_peer(&mut native.station_access(), addr, admission)
            .await
    }
    pub(super) async fn ap_stop(
        &mut self,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        let (controller, native) = self.ap_parts()?;
        controller
            .stop(&mut native.station_access(), admission)
            .await
    }
    pub(super) fn ap_phase(&self) -> Option<ApPhase> {
        self.ap_controller.as_ref().map(ApController::phase)
    }
    pub(super) fn ap_packet_ready(&self) -> bool {
        self.phase != Phase::Terminal
            && self.ap_phase() == Some(ApPhase::Started)
            && self
                .firmware
                .as_ref()
                .is_some_and(|firmware| firmware.transport().packets_ready())
    }
    pub(super) fn ap_submit(
        &mut self,
        bytes: &[u8],
        after_dtim: bool,
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        if self.ap_phase() != Some(ApPhase::Started) {
            return Err(packet::Error::State);
        }
        self.station_native()?
            .submit_ap_packet(bytes, after_dtim, report, rate)
    }
    /// The AP floor rate (`rtw89_core_get_mgmt_rate` band floor).
    pub(super) fn ap_lowest_rate(&mut self) -> Result<u8, power::Error> {
        Ok(self.station_native()?.lowest_rate())
    }
}
