// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Borrowed station adapter; Startup permanently retains Firmware<Native>.
use super::*;
use crate::rtw89::{packet_core as packet, station::Io, station_control as control};
use alloc::boxed::Box;

impl Startup {
    pub(super) fn station_native(&mut self) -> Result<&mut Native, power::Error> {
        if self.phase == Phase::Terminal {
            return Err(power::Error::Terminal);
        }
        let firmware = self.firmware.as_mut().ok_or(power::Error::Terminal)?;
        if firmware.phase() != firmware_boot::Phase::Running {
            return Err(power::Error::Terminal);
        }
        Ok(firmware.transport_mut())
    }
    /// Terminal closure plus the DMA-stop proof and reclamation for removal.
    /// A cold-only owner never published system-memory rings.
    pub(in crate::rtw89) fn retire_published_dma(&mut self) -> bool {
        self.fail();
        if let Some(native) = self.native.as_mut() {
            return native.retire_dma();
        }
        self.firmware
            .as_mut()
            .is_none_or(|firmware| firmware.transport_mut().retire_dma())
    }
    /// Terminal analog closure on the same owner, after source packet/command
    /// closure. Success is not a DMA/resource reclamation receipt.
    pub(in crate::rtw89) async fn finish_station_shutdown(&mut self) -> Result<(), power::Error> {
        if self.phase != Phase::Terminal {
            return Err(power::Error::Terminal);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        if native.sleeping()
            && self
                .sleep
                .as_ref()
                .is_some_and(|runtime| runtime.has_owner())
        {
            if native.dma_reclaimed() {
                return Ok(());
            }
            return native.sleep_reset_terminal().await;
        }
        native.finish_radio_shutdown().await
    }
}
#[async_trait::async_trait]
// SAFETY: no Native or transport is reconstructed or moved out of Startup.
// Source controller state is retained before awaited commands. Packet/command
// adapters invoke current device authority and sealed full RF/peer receipts at
// publication; failure closes and retains every published DMA mapping.
unsafe impl Io for Startup {
    fn monitor_capable(&mut self) -> Result<bool, power::Error> {
        if self.phase != Phase::RadioReady {
            return Ok(false);
        }
        self.station_native()?.ordinary_current()?;
        Ok(self
            .identity
            .is_some_and(|identity| identity.chip() == crate::rtw89::mac::ChipId::Rtl8852B))
    }
    fn monitor_active(&self) -> bool {
        self.monitor.is_some()
    }

    async fn monitor_start(
        &mut self,
        desired: alloc::sync::Arc<crate::rtw89::monitor::Desired>,
        admission: control::Admission,
    ) -> Result<crate::rtw89::monitor::Source, power::Error> {
        self.start_monitor(desired, admission).await
    }
    fn monitor_poll(&mut self) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, power::Error> {
        self.poll_monitor()
    }
    fn monitor_stop(&mut self) -> Result<(), power::Error> {
        self.stop_monitor()
    }
    fn station_allowed(&mut self) -> Result<(), power::Error> {
        if self.monitor.is_some() {
            return Err(power::Error::Terminal);
        }
        // RTL8852A/B, or RTL8852C / RTL8851B once its signed program
        // installed its ordinary grant (`Native::prepare_radio_c` /
        // `prepare_radio_51`): 2.4/5GHz station without B companion
        // programs. RTL8852A takes B's ordinary station path: its
        // `support_bands` are 2.4/5GHz and `support_bandwidths` 20/40/80MHz
        // (`rtw8852a.c:2410..2416` @ 05441d6), and the station codec is
        // B's (see `station_control::Controller::new`).
        if self.identity.is_none_or(|identity| {
            !matches!(
                identity.chip(),
                super::super::mac::ChipId::Rtl8852A
                    | super::super::mac::ChipId::Rtl8852B
                    | super::super::mac::ChipId::Rtl8852C
                    | super::super::mac::ChipId::Rtl8851B
            )
        }) {
            return Err(power::Error::Unsupported);
        }
        self.station_native()?.ordinary_current()
    }
    fn station_wow_capable(&mut self) -> bool {
        // The WoW owner is RTL8852B-only.
        self.identity
            .is_some_and(|identity| identity.chip() == super::super::mac::ChipId::Rtl8852B)
            && self.station_allowed().is_ok()
            && self.assets.as_ref().is_some_and(|assets| {
                crate::rtw89::wow_trx::CpuIoRx::for_8852b(assets.firmware_version())
                    == crate::rtw89::wow_trx::CpuIoRx::Absent
            })
    }
    async fn station_wow_suspend(
        &mut self,
        config: &narf_wireless::WowlanConfig,
        keys: Option<&narf_wireless::station_security::SuspendKeys>,
        floors: Option<&narf_wireless::station_security::SuspendFloors>,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        self.station_allowed()?;
        self.wow_suspend(config, keys, floors, admission).await
    }
    async fn station_wow_resume(
        &mut self,
        admission: &control::Admission,
    ) -> (
        Option<crate::rtw89::wow_wire::WakeReport>,
        Result<(), power::Error>,
    ) {
        self.wow_resume(admission).await
    }
    fn station_own(&mut self) -> Result<[u8; 6], power::Error> {
        self.station_allowed()?;
        Ok(self.identity.ok_or(power::Error::Terminal)?.mac())
    }
    fn station_wmm_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_wmm_allowed()
    }
    fn station_firmware_ra_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_firmware_ra_allowed()
    }
    async fn station_configure_ba(
        &mut self,
        valid: bool,
        tid: u8,
        buf: u16,
        ssn: u16,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if valid && !self.station_ht_allowed()? {
            return Err(power::Error::Unsupported);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .configure_ba(
                &mut native.station_access(),
                valid,
                tid,
                buf,
                ssn,
                admission,
            )
            .await
    }
    fn station_ht_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_ht_allowed()
    }
    async fn station_scan_address(
        &mut self,
        address: Option<[u8; 6]>,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .scan_address(&mut native.station_access(), address, admission)
            .await
    }
    fn station_channels(&mut self) -> Result<u64, power::Error> {
        self.station_allowed()?;
        // The whole 2.4GHz + 5GHz slot mask: probe/basic-rate/TX-rate/RA/
        // CMAC/EDCA/CSA paths are band-aware (`station::ghz5`).
        self.station_native()?.admitted_channels()
    }
    fn station_regulatory(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>>, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_regulatory()
    }
    fn station_passive_tx(
        &mut self,
        grant: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    ) -> Result<(), power::Error> {
        // Withdrawal must reach the native gate even while closing.
        if grant.is_some() {
            self.station_allowed()?;
        }
        self.station_native()?.station_passive_tx(grant)
    }
    async fn station_retune(
        &mut self,
        primary: u8,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        self.station_allowed()?;
        admission.check()?;
        let epoch = self.retune_channel(primary, false).await?;
        admission.check()?;
        Ok(epoch)
    }
    fn station_wide_channels(
        &mut self,
    ) -> Result<alloc::vec::Vec<crate::rtw89::operating_channel::Profile>, power::Error> {
        self.station_allowed()?;
        // No full-radio wide scope (no signed wide record path): 20MHz only.
        match self.station_native()?.admitted_wide() {
            Err(power::Error::Unsupported) => Ok(alloc::vec::Vec::new()),
            other => other,
        }
    }
    async fn station_retune_wide(
        &mut self,
        profile: crate::rtw89::operating_channel::Profile,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        self.station_allowed()?;
        admission.check()?;
        let epoch = self.retune_wide(profile, false).await?;
        admission.check()?;
        Ok(epoch)
    }
    async fn station_switch_channel(
        &mut self,
        primary: u8,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        self.station_allowed()?;
        admission.check()?;
        let epoch = self.retune_channel(primary, true).await?;
        admission.check()?;
        Ok(epoch)
    }
    async fn station_switch_wide_channel(
        &mut self,
        profile: crate::rtw89::operating_channel::Profile,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        self.station_allowed()?;
        admission.check()?;
        let epoch = self.retune_wide(profile, true).await?;
        admission.check()?;
        Ok(epoch)
    }
    fn station_six_ghz_channels(
        &mut self,
    ) -> Result<alloc::vec::Vec<crate::rtw89::command_native::SixGhzChannel>, power::Error> {
        self.station_allowed()?;
        self.station_native()?.admitted_six_ghz()
    }
    fn station_six_ghz_regulatory(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>>, power::Error> {
        self.station_allowed()?;
        self.station_native()?.six_ghz_regulatory()
    }
    async fn station_retune_6ghz(
        &mut self,
        channel: crate::rtw89::command_native::SixGhzChannel,
        tpe: Option<i8>,
        linked: bool,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        self.station_allowed()?;
        admission.check()?;
        let profile = crate::rtw89::operating_channel_c::Profile::new20(
            crate::rtw89::operating_channel_c::Band::Ghz6,
            channel.primary,
        )
        .ok_or(power::Error::Unsupported)?;
        let epoch = self
            .retune_channel_c(profile, Some((channel.six, tpe)), linked)
            .await?;
        admission.check()?;
        Ok(epoch)
    }
    fn station_sleep_capable(&mut self) -> Result<bool, power::Error> {
        self.sleep_prepare()
    }
    fn station_sleep_blocked(&self) -> bool {
        self.firmware
            .as_ref()
            .is_some_and(|firmware| firmware.transport().sleeping())
    }
    async fn station_sleep_service(
        &mut self,
        identity: Option<narf_net::native_emission::Lifetime>,
        enabled: bool,
        idle: bool,
        force: bool,
        admission: &control::Admission,
    ) -> Result<(bool, bool), power::Error> {
        self.sleep_service(identity, enabled, idle, force, admission)
            .await
    }
    async fn station_rf_tracking(
        &mut self,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        self.station_allowed()?;
        if self
            .identity
            .is_some_and(|identity| identity.chip() == super::super::mac::ChipId::Rtl8851B)
        {
            // track.rs `run` returns before any RF step while scanning
            // (`rtw89_track_work` checks `rtwdev->scanning`).
            self.station_native()?;
            let firmware = self.firmware.as_mut().ok_or(power::Error::Terminal)?;
            // SAFETY: the same retained Startup prepared `radio_51`; track
            // work runs under the station's retained lock (no concurrent
            // RFK/PHY/reset/PM owner).
            return unsafe {
                firmware
                    .transport_mut()
                    .track_radio_51(&mut self.radio_51, admission, false)
                    .await
            };
        }
        self.station_native()?.station_rf_tracking(admission)
    }
    fn station_track_read(&mut self, address: u32) -> Result<u32, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_track_read(address)
    }
    fn station_track_write(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_track_write(address, value)
    }
    fn station_track_profile(&mut self) -> Result<crate::rtw89::track::Profile, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_track_profile()
    }
    fn station_track_layout(
        &mut self,
    ) -> Result<(crate::rtw89::track::Layout, bool), power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_track_layout()
    }
    async fn station_track_crystal(&mut self, cap: u8) -> Result<u8, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_track_crystal(cap).await
    }
    fn station_single_stream(&mut self) -> bool {
        self.identity
            .is_some_and(|identity| identity.chip() == super::super::mac::ChipId::Rtl8851B)
    }
    fn station_he_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_he_allowed()
    }
    fn station_amsdu_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_amsdu_allowed()
    }
    fn station_ampdu_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_ampdu_allowed()
    }
    async fn station_configure_agg_limit(
        &mut self,
        agg_num: Option<u16>,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if agg_num.is_some() && !self.station_ampdu_allowed()? {
            return Err(power::Error::Unsupported);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .configure_agg_limit(&mut native.station_access(), agg_num, admission)
    }
    fn packet_ready_aggregate(&self) -> bool {
        self.packet_ready()
            && self
                .firmware
                .as_ref()
                .is_some_and(|firmware| firmware.transport().packets_ready_aggregate())
    }
    fn packet_submit_agg(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
        agg: crate::rtw89::packet_format::Agg,
    ) -> Result<u64, packet::Error> {
        self.station_native()?
            .submit_packet_agg(bytes, report, rate, agg)
    }

    async fn station_configure_ra_wide(
        &mut self,
        rates: u16,
        ht: control::HtRa,
        he: Option<control::HeRa>,
        wide: control::WideRa,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if !self.station_ht_allowed()?
            || he.is_some() && !self.station_he_allowed()?
            || !self.station_firmware_ra_allowed()?
        {
            return Err(power::Error::Unsupported);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .configure_ra_wide(&mut native.station_access(), rates, ht, he, wide, admission)
            .await
    }
    async fn station_configure_ra(
        &mut self,
        rates: u16,
        ht: Option<control::HtRa>,
        he: Option<control::HeRa>,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if ht.is_some() && !self.station_ht_allowed()? {
            return Err(power::Error::Unsupported);
        }
        if he.is_some() && !self.station_he_allowed()? {
            return Err(power::Error::Unsupported);
        }
        if !self.station_firmware_ra_allowed()? {
            return Err(power::Error::Unsupported);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .configure_ra(&mut native.station_access(), rates, ht, he, admission)
            .await
    }
    fn station_qos_all_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_qos_all_allowed()
    }
    async fn station_configure_wmm(
        &mut self,
        p: narf_wireless::wmm::Parameters,
        short: bool,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if !self.station_wmm_allowed()? {
            return Err(power::Error::Unsupported);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        let controller = self
            .station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?;
        controller
            .configure_wmm(&mut native.station_access(), p, short, admission)
            .await?;
        if native.station_qos_all_allowed()? {
            controller.admit_all_tids(admission)?;
        }
        Ok(())
    }
    async fn station_update_wmm(
        &mut self,
        p: narf_wireless::wmm::Parameters,
        short: bool,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if !self.station_wmm_allowed()? {
            return Err(power::Error::Unsupported);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .update_wmm(&mut native.station_access(), p, short, admission)
            .await
    }
    async fn station_prepare_initial(
        &mut self,
        own: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if self.station_controller.is_some() || self.station_own()? != own {
            return Err(power::Error::Terminal);
        }
        let controller = self.station_native()?.station_controller()?;
        self.station_controller = Some(controller); // retained before await
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .initialize(&mut native.station_access(), admission)
            .await
    }
    async fn station_prepare_peer(
        &mut self,
        peer: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        self.station_allowed()?;
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        let binding = self
            .station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .prepare_peer(&mut native.station_access(), peer, admission)
            .await?;
        native.station_peer(binding)?;
        self.station_binding = Some(peer);
        Ok(())
    }
    async fn station_commit_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        short_slot: bool,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        self.station_allowed()?;
        if self.station_binding != Some(peer) {
            return Err(power::Error::Terminal);
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .commit_peer(
                &mut native.station_access(),
                peer,
                aid,
                short_slot,
                admission,
            )
            .await?;
        if let Some(sleep) = self.sleep.as_mut() {
            sleep.committed(aid)?;
        }
        Ok(())
    }
    async fn station_disconnect(
        &mut self,
        peer: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        if self.station_binding != Some(peer) {
            return Err(power::Error::Terminal);
        }
        self.station_binding = None;
        if self
            .sleep
            .as_ref()
            .is_some_and(|runtime| runtime.has_owner())
        {
            self.firmware
                .as_mut()
                .ok_or(power::Error::Terminal)?
                .transport_mut()
                .sleep_reset_terminal()
                .await?;
            return Ok(());
        }
        let native = self
            .firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut();
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .disconnect(&mut native.station_cleanup(), admission)
            .await
    }
    fn ap_allowed(&mut self) -> Result<(), power::Error> {
        self.ap_admissible()
    }
    async fn ap_channel(
        &mut self,
        primary: u8,
        admission: &control::Admission,
    ) -> Result<u32, power::Error> {
        Startup::ap_channel(self, primary, admission).await
    }
    async fn ap_prepare(
        &mut self,
        own: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        Startup::ap_prepare(self, own, admission).await
    }
    async fn ap_start(
        &mut self,
        config: crate::rtw89::ap_control::PortConfig,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        Startup::ap_start(self, config, admission).await
    }
    async fn ap_publish_beacon(
        &mut self,
        beacon: &[u8],
        tim_at: usize,
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        Startup::ap_publish_beacon(self, beacon, tim_at, admission).await
    }
    async fn ap_add_peer(
        &mut self,
        addr: [u8; 6],
        admission: &control::Admission,
    ) -> Result<u8, power::Error> {
        Startup::ap_add_peer(self, addr, admission).await
    }
    async fn ap_associate_peer(
        &mut self,
        addr: [u8; 6],
        aid: u16,
        ra: [u8; 16],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        Startup::ap_associate_peer(self, addr, aid, ra, admission).await
    }
    async fn ap_remove_peer(
        &mut self,
        addr: [u8; 6],
        admission: &control::Admission,
    ) -> Result<(), power::Error> {
        Startup::ap_remove_peer(self, addr, admission).await
    }
    async fn ap_stop(&mut self, admission: &control::Admission) -> Result<(), power::Error> {
        Startup::ap_stop(self, admission).await
    }
    fn ap_packet_ready(&self) -> bool {
        Startup::ap_packet_ready(self)
    }
    fn ap_lowest_rate(&mut self) -> Result<u8, power::Error> {
        Startup::ap_lowest_rate(self)
    }
    fn packet_submit_ap(
        &mut self,
        bytes: &[u8],
        after_dtim: bool,
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        self.ap_submit(bytes, after_dtim, report, rate)
    }
    fn packet_prepare(&mut self, own: [u8; 6], macid: u8) -> Result<(), packet::Error> {
        if self.station_controller.as_ref().is_none_or(|controller| {
            controller.phase() != control::Phase::Passive || controller.own() != own
        }) {
            return Err(packet::Error::State);
        }
        self.station_native()?.prepare_packets(own, macid)
    }
    fn packet_scan_address(&mut self, scan: Option<[u8; 6]>) -> Result<(), packet::Error> {
        self.station_native()?.scan_address_packets(scan)
    }
    fn packet_start(&mut self) -> Result<(), packet::Error> {
        self.station_native()?.start_packets()
    }
    fn packet_ready(&self) -> bool {
        self.phase != Phase::Terminal
            && self
                .firmware
                .as_ref()
                .is_some_and(|firmware| firmware.transport().packets_ready())
            && self.station_controller.as_ref().is_some_and(|controller| {
                matches!(
                    controller.phase(),
                    control::Phase::PeerPrepared | control::Phase::Associated
                )
            })
    }
    fn station_fragments_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_fragments_allowed()
    }
    fn packet_fragment_binding(
        &mut self,
        admission: &control::Admission,
    ) -> Result<crate::rtw89::command_native::FragmentBinding, power::Error> {
        self.station_allowed()?;
        self.station_native()?.fragment_binding(admission)
    }
    fn packet_submit_fragment(
        &mut self,
        part: &crate::rtw89::command_native::FragmentPart,
        report: bool,
    ) -> Result<u64, packet::Error> {
        self.station_native()?.submit_fragment(part, report)
    }
    fn packet_submit(&mut self, bytes: &[u8], report: bool) -> Result<u64, packet::Error> {
        self.station_native()?.submit_packet(bytes, report)
    }
    fn packet_submit_rate(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        self.station_native()?
            .submit_packet_rate(bytes, report, rate)
    }
    fn packet_poll(&mut self) -> Result<packet::Step, packet::Error> {
        self.station_native()?.poll_packets()
    }
    fn irq_start(
        &mut self,
        line: &alloc::sync::Arc<crate::rtw89::irq::Line>,
    ) -> Result<u8, power::Error> {
        self.station_native()?.irq_start(line)
    }
    fn irq_service(&mut self) -> Result<crate::rtw89::irq::Events, power::Error> {
        self.station_native()?.irq_service()
    }
    fn irq_rearm(&mut self) -> Result<(), power::Error> {
        self.station_native()?.irq_rearm()
    }
    fn retire_dma(&mut self) -> bool {
        self.retire_published_dma()
    }
    fn packet_stop(&mut self) -> Result<(), packet::Error> {
        if let Some(controller) = self.station_controller.as_mut() {
            controller.invalidate();
        }
        self.station_binding = None;
        self.phase = Phase::Terminal;
        self.firmware
            .as_mut()
            .ok_or(packet::Error::State)?
            .transport_mut()
            .stop_packets()
    }
}
