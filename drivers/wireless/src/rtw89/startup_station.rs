// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Borrowed station adapter; Startup permanently retains Firmware<Native>.
use super::*;
use crate::rtw89::{packet_core as packet, station::Io, station_control as control};
use alloc::boxed::Box;

impl Startup {
    fn station_native(&mut self) -> Result<&mut Native, power::Error> {
        if self.phase == Phase::Terminal {
            return Err(power::Error::Terminal);
        }
        let firmware = self.firmware.as_mut().ok_or(power::Error::Terminal)?;
        if firmware.phase() != firmware_boot::Phase::Running {
            return Err(power::Error::Terminal);
        }
        Ok(firmware.transport_mut())
    }
    /// Terminal analog closure on the same owner, after source packet/command
    /// closure. Success is not a DMA/resource reclamation receipt.
    pub(in crate::rtw89) async fn finish_station_shutdown(&mut self) -> Result<(), power::Error> {
        if self.phase != Phase::Terminal {
            return Err(power::Error::Terminal);
        }
        self.firmware
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .transport_mut()
            .finish_radio_shutdown()
            .await
    }
}
#[async_trait::async_trait]
// SAFETY: no Native or transport is reconstructed or moved out of Startup.
// Source controller state is retained before awaited commands. Packet/command
// adapters invoke current device authority and sealed full RF/peer receipts at
// publication; failure closes and retains every published DMA mapping.
unsafe impl Io for Startup {
    fn station_allowed(&mut self) -> Result<(), power::Error> {
        if self
            .identity
            .is_none_or(|identity| identity.chip() != super::super::mac::ChipId::Rtl8852B)
        {
            return Err(power::Error::Unsupported);
        }
        self.station_native()?.ordinary_current()
    }
    fn station_own(&mut self) -> Result<[u8; 6], power::Error> {
        self.station_allowed()?;
        Ok(self.identity.ok_or(power::Error::Terminal)?.mac())
    }
    fn station_wmm_allowed(&mut self) -> Result<bool, power::Error> {
        self.station_allowed()?;
        self.station_native()?.station_wmm_allowed()
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
        self.station_controller
            .as_mut()
            .ok_or(power::Error::Terminal)?
            .configure_wmm(&mut native.station_access(), p, short, admission)
            .await
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
            .await
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
    fn packet_prepare(&mut self, own: [u8; 6], macid: u8) -> Result<(), packet::Error> {
        if self.station_controller.as_ref().is_none_or(|controller| {
            controller.phase() != control::Phase::Passive || controller.own() != own
        }) {
            return Err(packet::Error::State);
        }
        self.station_native()?.prepare_packets(own, macid)
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
