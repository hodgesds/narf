// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Adapters borrowing the one retained Native. No diagnostic rings or IO clone.
use super::*;
use crate::rtw89::{packet_core as packet, power, rx_dma, rx_packet, station_control as control};
use alloc::boxed::Box;
use alloc::collections::VecDeque;

#[derive(Default)]
pub(super) struct Runtime {
    pub(super) monitor: Option<super::monitor::Mode>,
    pub(super) core: Option<packet::Core>,
    pub(super) peer: Option<control::Peer>,
    pub(super) backlog: VecDeque<rx_packet::Event>,
    started: bool,
    pub(super) rf_tracking: Option<crate::rtw89::rf_tracking::Tracker>,
    /// AP-role packet binding (`command_native/ap.rs`); None for a station.
    pub(super) ap: Option<super::ap::ApBinding>,
}
impl Runtime {
    pub(super) fn started(&self) -> bool {
        self.started
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn model_started(&mut self) {
        self.started = true;
    }
}
pub(in crate::rtw89) struct Access<'a> {
    native: &'a mut Native,
    cleanup: bool,
    fragment: Option<super::fragment::Part>,
}
impl Native {
    pub(in crate::rtw89) fn station_access(&mut self) -> Access<'_> {
        Access {
            native: self,
            cleanup: false,
            fragment: None,
        }
    }
    pub(in crate::rtw89) fn station_cleanup(&mut self) -> Access<'_> {
        Access {
            native: self,
            cleanup: true,
            fragment: None,
        }
    }
    pub(in crate::rtw89) fn station_controller(&self) -> Result<control::Controller, power::Error> {
        self.ordinary_current()?;
        control::Controller::new(self.factory.as_ref().ok_or(power::Error::Unsupported)?)
    }
    pub(in crate::rtw89) fn station_peer(
        &mut self,
        peer: control::Peer,
    ) -> Result<(), power::Error> {
        self.ordinary_current()?;
        peer.current()?;
        if self
            .identity()
            .is_none_or(|identity| identity.mac() != peer.own())
            || peer.mac_id() != 0
        {
            return Err(power::Error::Unsupported);
        }
        self.station_runtime.peer = Some(peer);
        Ok(())
    }
    pub(super) fn rx_hardware_step(
        &mut self,
        budget: usize,
    ) -> Result<rx_dma::Batch, rx_dma::Error> {
        let cap = self.authority;
        crate::rtw88::pci_park::invoke(&cap, || {
            if self.state != State::Active {
                return Err(rx_dma::Error::Terminal);
            }
            if self.wow_parked() {
                // HCI RX is off: unreaped RX is dropped by the ring rewind.
                return Ok(rx_dma::Batch {
                    events: alloc::vec::Vec::new(),
                    consumed: false,
                });
            }
            if self.wow_trx_open() {
                // Halted or restarting WoW window: the RX filters drop every
                // frame type, but the firmware swap still needs its C2H/ACK
                // stream (`rtw89_wow_swap_fw` runs with RX alive). Anything
                // but a firmware message is discarded here.
                self.ordinary_current()?;
                // SAFETY: as below; the same retained RXQ/RPQ owner.
                let mut batch = unsafe { self.receive.poll_station_step(&mut self.io, budget) }?;
                batch
                    .events
                    .retain(|event| matches!(event, rx_packet::Event::Firmware(_)));
                return Ok(batch);
            }
            if self.station_runtime.started {
                self.ordinary_current()?;
                // SAFETY: same retained RXQ/RPQ owner, whole actual current
                // invocation, and sealed full ordinary RF/response grant.
                unsafe { self.receive.poll_station_step(&mut self.io, budget) }
            } else {
                self.receive.poll_step(&mut self.io, budget)
            }
        })
        .map_err(|_| rx_dma::Error::Register(power::Error::Access))?
    }
    pub(super) fn retain_event(&mut self, event: rx_packet::Event) -> Result<(), power::Error> {
        if self.station_runtime.backlog.len() >= 256 {
            return Err(power::Error::Terminal);
        }
        self.station_runtime.backlog.push_back(event);
        Ok(())
    }
    pub(in crate::rtw89) fn prepare_packets(
        &mut self,
        own: [u8; 6],
        macid: u8,
    ) -> Result<(), packet::Error> {
        if self.station_runtime.monitor.is_some() || self.station_runtime.core.is_some() {
            return Err(packet::Error::State);
        }
        self.ordinary_current()?;
        let qos_all = self.station_qos_all_allowed().unwrap_or(false);
        let ht = self.station_ht_allowed().unwrap_or(false);
        let he = self.station_he_allowed().unwrap_or(false);
        let rx = packet::RxPhy::from_programs(ht, he);
        // HE-only (6GHz) also aggregates: the `Ampdu` program, not HT
        // negotiation, is the grant — `from_programs` maps it to `He`.
        let ampdu = (ht || he) && self.station_ampdu_allowed().unwrap_or(false);
        let amsdu = ampdu && self.station_amsdu_allowed()?;
        let core = packet::Core::prepare_with(&mut self.station_access(), own, macid, qos_all, rx)
            .and_then(|mut core| {
                if ampdu {
                    core.enable_aggregation()?;
                }
                if amsdu {
                    core.enable_amsdu(crate::rtw89::tx_amsdu::MAX_BODY)?;
                }
                Ok(core)
            });
        match core {
            Ok(core) => {
                self.station_runtime.core = Some(core);
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    pub(super) fn packet_operation<T>(
        &mut self,
        operation: impl FnOnce(&mut packet::Core, &mut Access<'_>) -> Result<T, packet::Error>,
    ) -> Result<T, packet::Error> {
        let mut core = self
            .station_runtime
            .core
            .take()
            .ok_or(packet::Error::State)?;
        let result = operation(&mut core, &mut self.station_access());
        self.station_runtime.core = Some(core);
        if result.is_err() && result.as_ref().err() != Some(&packet::Error::Busy) {
            self.fail();
        }
        result
    }
    pub(in crate::rtw89) fn start_packets(&mut self) -> Result<(), packet::Error> {
        self.packet_operation(|core, port| core.start(port))
    }
    pub(in crate::rtw89) fn scan_address_packets(
        &mut self,
        scan: Option<[u8; 6]>,
    ) -> Result<(), packet::Error> {
        self.packet_operation(|core, _| core.set_scan_address(scan))
    }
    pub(in crate::rtw89) fn packets_ready(&self) -> bool {
        self.state == State::Active
            && !self.sleep_blocked
            && !self.wow_trx_open()
            && self
                .station_runtime
                .core
                .as_ref()
                .is_some_and(packet::Core::ready)
    }
    pub(in crate::rtw89) fn packets_ready_aggregate(&self) -> bool {
        self.state == State::Active
            && !self.sleep_blocked
            && self
                .station_runtime
                .core
                .as_ref()
                .is_some_and(packet::Core::ready_aggregate)
    }
    /// Frame-TX regulatory gate (`Qualification::tx_current`): on a
    /// passive-only (DFS / NO_IR) active primary only a station witness
    /// grant admits a frame. Without a full-radio scope only the base
    /// 2.4GHz channel can be active, which is never passive-admitted.
    /// RTL8852C (`radio_policy_c::Qualification::tx_current`) refuses every
    /// frame on a DFS/NO_IR active span: it has no witness grant.
    pub(super) fn station_tx_current(&self) -> Result<(), packet::Error> {
        if let Some(a) = self.qualification_a.as_ref() {
            return a.tx_current().map_err(|_| packet::Error::Access);
        }
        if let Some(c) = self.qualification_c.as_ref() {
            return c.tx_current().map_err(|_| packet::Error::Access);
        }
        // RTL8851B (`radio_policy_51::Qualification::tx_current`): likewise
        // no witness grant.
        if let Some(n51) = self.qualification_51.as_ref() {
            return n51.tx_current().map_err(|_| packet::Error::Access);
        }
        match self.full_radio_scope() {
            Some(qualification) => qualification
                .tx_current()
                .map_err(|_| packet::Error::Access),
            None => Ok(()),
        }
    }
    /// The host policy snapshot the active envelope is checked against.
    pub(in crate::rtw89) fn station_regulatory(
        &self,
    ) -> Result<Option<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>>, power::Error> {
        match self.full_radio_scope() {
            Some(qualification) => qualification
                .policy()
                .map(Some)
                .map_err(|_| power::Error::Access),
            None => Ok(None),
        }
    }
    /// Grant / withdraw station TX on a witnessed passive-only primary.
    pub(in crate::rtw89) fn station_passive_tx(
        &self,
        grant: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    ) -> Result<(), power::Error> {
        let qualification = self.full_radio_scope();
        match (qualification, grant) {
            (Some(qualification), grant) => {
                qualification.grant_passive_tx(grant);
                Ok(())
            }
            (None, None) => Ok(()),
            (None, Some(_)) => Err(power::Error::Unsupported),
        }
    }
    pub(in crate::rtw89) fn submit_packet_agg(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
        agg: crate::rtw89::packet_format::Agg,
    ) -> Result<u64, packet::Error> {
        if !self.station_ampdu_allowed()? || !self.station_firmware_ra_allowed()? {
            return Err(packet::Error::Access);
        }
        self.station_tx_current()?;
        self.packet_operation(|core, port| core.submit_agg(port, bytes, report, rate, Some(agg)))
    }
    pub(in crate::rtw89) fn submit_fragment(
        &mut self,
        part: &super::fragment::Part,
        report: bool,
    ) -> Result<u64, packet::Error> {
        self.station_tx_current()?;
        let mut core = self
            .station_runtime
            .core
            .take()
            .ok_or(packet::Error::State)?;
        let rate = self.lowest_rate();
        let result = core.submit_fragment(
            &mut Access {
                native: self,
                cleanup: false,
                fragment: Some(part.clone()),
            },
            part,
            report,
            rate,
        );
        self.station_runtime.core = Some(core);
        if result.is_err() && result != Err(packet::Error::Busy) {
            self.fail();
        }
        result
    }
    pub(in crate::rtw89) fn submit_packet(
        &mut self,
        bytes: &[u8],
        report: bool,
    ) -> Result<u64, packet::Error> {
        if self.lowest_rate() != 0 {
            return Err(packet::Error::Access);
        }
        self.station_tx_current()?;
        self.packet_operation(|core, port| core.submit(port, bytes, report))
    }
    /// core.c `rtw89_core_get_mgmt_rate` band floor of the current typed
    /// primary: `RTW89_HW_RATE_CCK1` on 2.4GHz, `RTW89_HW_RATE_OFDM6` on 5GHz.
    pub(in crate::rtw89) fn lowest_rate(&self) -> u8 {
        if self
            .operating_channel()
            .is_some_and(|(channel, _)| channel.ofdm_only())
        {
            crate::rtw89::packet_format::OFDM6
        } else {
            0
        }
    }
    pub(in crate::rtw89) fn submit_packet_rate(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        let lowest = self.lowest_rate();
        // A fixed CCK rate is never published on 5GHz; the band's lowest
        // rate (core.c `rtw89_core_get_mgmt_rate`: CCK1 / OFDM6) is the
        // management/EAPOL rate and needs no WMM program.
        let fixed = rate
            & !(crate::rtw89::packet_format::FIRMWARE_RA | crate::rtw89::packet_format::DATA_ER);
        if rate & crate::rtw89::packet_format::FIRMWARE_RA == 0 && fixed < lowest {
            return Err(packet::Error::Access);
        }
        if rate != lowest && !self.station_wmm_allowed()? {
            return Err(packet::Error::Access);
        }
        if rate & crate::rtw89::packet_format::FIRMWARE_RA != 0
            && !self.station_firmware_ra_allowed()?
        {
            return Err(packet::Error::Access);
        }
        self.station_tx_current()?;
        self.packet_operation(|core, port| core.submit_rate(port, bytes, report, rate))
    }
    /// `rtw89_pci_request_irq` + `rtw89_pci_ops_start`: bind one MSI vector
    /// to `line` and enable the AX interrupt mask once the packet runtime is
    /// started. Returns the CPU vector.
    pub(in crate::rtw89) fn irq_start(
        &mut self,
        line: &alloc::sync::Arc<crate::rtw89::irq::Line>,
    ) -> Result<u8, power::Error> {
        if self.irq.is_some() || self.state != State::Active || !self.station_runtime.started {
            return Err(power::Error::Terminal);
        }
        let binding =
            crate::rtw89::irq::Binding::bind(self.chip, &self.device, &self.authority, line)
                .map_err(|error| match error {
                    crate::rtw89::irq::Error::Unsupported => power::Error::Unsupported,
                    _ => power::Error::Access,
                })?;
        if binding.start(&mut self.io).is_err() {
            binding.release(&mut self.io, &self.authority);
            return Err(power::Error::Access);
        }
        let vector = binding.vector();
        self.irq = Some(binding);
        Ok(vector)
    }
    pub(in crate::rtw89) fn irq_armed(&self) -> bool {
        self.irq.is_some()
    }
    /// Worker half of the Linux hard/threaded handlers: mask, then
    /// recognize and acknowledge enabled sources. Without a binding the
    /// worker is in polled mode and nothing is reported.
    pub(in crate::rtw89) fn irq_service(
        &mut self,
    ) -> Result<crate::rtw89::irq::Events, power::Error> {
        let Some(binding) = self.irq.as_ref() else {
            return Ok(crate::rtw89::irq::Events::default());
        };
        let result = binding.service(&mut self.io).map(|isrs| isrs.events());
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// NAPI-completion re-enable after RPQ/RXQ were drained.
    pub(in crate::rtw89) fn irq_rearm(&mut self) -> Result<(), power::Error> {
        let Some(binding) = self.irq.as_ref() else {
            return Ok(());
        };
        if self.state != State::Active {
            return Err(power::Error::Terminal);
        }
        let result = binding.rearm(&mut self.io);
        if result.is_err() {
            self.fail();
        }
        result
    }
    pub(super) fn irq_release(&mut self) {
        if let Some(binding) = self.irq.take() {
            binding.release(&mut self.io, &self.authority);
        }
    }
    pub(in crate::rtw89) fn poll_packets(&mut self) -> Result<packet::Step, packet::Error> {
        self.packet_operation(|core, port| core.poll(port))
    }
    pub(in crate::rtw89) fn stop_packets(&mut self) -> Result<(), packet::Error> {
        if self.sleep_reset.is_some() {
            return Err(packet::Error::State);
        }
        if self.sleep_blocked {
            self.fail();
            return Err(packet::Error::State);
        }
        let result = if let Some(mut core) = self.station_runtime.core.take() {
            let result = core.stop(&mut self.station_cleanup());
            self.station_runtime.core = Some(core);
            result
        } else {
            // Private CH12/RX already exists during source controller setup.
            packet::Port::stop(&mut self.station_cleanup())
        };
        self.station_runtime.peer = None;
        self.station_runtime.ap = None;
        self.station_runtime.started = false;
        self.fail();
        result?;
        if self.command().map_err(|_| packet::Error::Access)? & narf_bus::pci::cmd::BUS_MASTER != 0
        {
            return Err(packet::Error::Access);
        }
        // Teardown frees published DMA only behind the idle proof; an
        // unproven stop keeps every ring and packet pinned for the boot.
        let _ = self.reclaim_dma();
        Ok(())
    }
}
impl power::Io for Access<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        self.native.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        self.native.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        self.native.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        self.native.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        let rings = addr_set_for_chip(self.native.chip).tx;
        if let Some(part) = &self.fragment {
            // This exact part is already issued. A prepared-part predicate
            // would deny every valid doorbell or tempt an unsafe bypass.
            let part = part.clone();
            let queue = crate::rtw89::packet_format::classify_fragment(
                part.bytes(),
                part.bytes()
                    .get(10..16)
                    .and_then(|a| a.try_into().ok())
                    .ok_or(power::Error::Terminal)?,
            )
            .map_err(|_| power::Error::Terminal)?;
            if u64::from(a) == queue.regs().idx {
                return self.native.with_ordinary_current(|native| {
                    native
                        .fragment_part_current(&part, part.bytes(), true, true)
                        .map_err(|_| power::Error::Access)?;
                    control::awake(&mut native.io)?;
                    native.io.write16(a, v)
                });
            }
            return Err(power::Error::Unsupported);
        }
        if u64::from(a) == rings[0].idx || u64::from(a) == rings[8].idx {
            self.native.with_ordinary_current(|native| {
                native
                    .station_runtime
                    .peer
                    .as_ref()
                    .ok_or(power::Error::Terminal)?
                    .current()?;
                control::awake(&mut native.io)?;
                native.io.write16(a, v)
            })
        } else {
            self.native.io.write16(a, v)
        }
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        self.native.io.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.native.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.native.io.delay_us(us).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
#[async_trait::async_trait]
impl control::Interface for Access<'_> {
    fn ghz5(&mut self) -> bool {
        self.native
            .operating_channel()
            .is_some_and(|(channel, _)| channel.ofdm_only())
    }
    fn preflight(&mut self, indirect: bool) -> Result<(), power::Error> {
        if self.native.state != State::Active {
            return Err(power::Error::Terminal);
        }
        match self.native.chip {
            ChipId::Rtl8852A => self.native.io.a_station_window(indirect)?,
            ChipId::Rtl8852B => self.native.io.b_station_window(indirect)?,
            ChipId::Rtl8852C => self.native.io.c_station_window(indirect)?,
            ChipId::Rtl8851B => self.native.io.n51_station_window(indirect)?,
            _ => return Err(power::Error::Terminal),
        }
        if self.cleanup {
            // Stop ordinary responses/queues while CH12/private RX remain
            // available for cleanup ACKs after power qualification is lost.
            packet::Port::stop(self).map_err(|_| power::Error::Access)?;
        } else {
            if self.native.sleep_blocked {
                return Err(power::Error::Terminal);
            }
            self.native.ordinary_current()?;
        }
        Ok(())
    }
    fn with_current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(power::Error::Terminal);
        }
        let cap = self.native.authority;
        if self.cleanup {
            // Teardown remains possible after the emission grant is revoked.
            // It closes ordinary engines under current device authority only.
            return crate::rtw88::pci_park::invoke(&cap, || {
                self.preflight(false)?;
                operation(self)
            })
            .map_err(|_| power::Error::Access)?;
        }
        crate::rtw88::pci_park::invoke(&cap, || {
            let qualification = self
                .native
                .ordinary
                .as_ref()
                .ok_or(power::Error::Unsupported)?
                .clone();
            // A successful earlier sample is not authority for later port,
            // crypto or table MMIO. Retain the exact signed grant through the
            // complete transaction, including native masked readbacks.
            qualification.with_current(|| {
                self.preflight(false)?;
                operation(self)
            })
        })
        .map_err(|_| power::Error::Access)?
    }
    async fn command(
        &mut self,
        category: u8,
        class: u8,
        function: u8,
        body: &[u8],
        done_ack: bool,
        admission: Option<&control::Admission>,
    ) -> Result<(), power::Error> {
        let permit = match admission {
            Some(admission) if !self.cleanup => Permit::Station(admission),
            None if self.cleanup => Permit::Cleanup,
            _ => return Err(power::Error::Terminal),
        };
        self.native
            .runtime_command(category, class, function, body, done_ack, permit)
            .await
    }
}
// SAFETY: Access exclusively borrows the exact actual Native; its raw
// register adapter invokes that same current capability for each access,
// and current encloses complete DMA/descriptor/cache/doorbell transactions.
// Full RF/response and opaque peer receipts remain separately mandatory.
unsafe impl packet::Port for Access<'_> {
    fn current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, packet::Error>,
    ) -> Result<T, packet::Error> {
        let cap = self.native.authority;
        crate::rtw88::pci_park::invoke(&cap, || operation(self))
            .map_err(|_| packet::Error::Access)?
    }
    fn chip(&self) -> ChipId {
        self.native.chip
    }
    fn ordinary_allowed(&mut self) -> Result<(), packet::Error> {
        if self.native.sleep_blocked {
            return Err(packet::Error::Busy);
        }
        self.native
            .with_ordinary_current(|native| control::awake(&mut native.io))
            .map_err(Into::into)
    }
    fn peer_allowed(&mut self, bytes: &[u8]) -> Result<(), packet::Error> {
        if let Some(ap) = self.native.station_runtime.ap.as_ref() {
            return ap.admits(bytes);
        }
        if self
            .native
            .station_runtime
            .peer
            .as_ref()
            .is_some_and(|peer| {
                if crate::rtw89::packet_format::amsdu(bytes) {
                    peer.admits_amsdu(bytes)
                } else {
                    peer.admits(bytes)
                }
            })
        {
            Ok(())
        } else {
            Err(packet::Error::Packet)
        }
    }
    fn amsdu_allowed(&mut self) -> Result<Option<usize>, packet::Error> {
        if self.native.station_amsdu_allowed()? {
            Ok(Some(crate::rtw89::tx_amsdu::MAX_BODY))
        } else {
            Ok(None)
        }
    }
    fn fragment_ready(&mut self, part: &super::fragment::Part) -> Result<(), packet::Error> {
        if self
            .fragment
            .as_ref()
            .is_none_or(|original| !original.same(part))
        {
            return Err(packet::Error::Access);
        }
        self.native
            .fragment_part_current(part, part.bytes(), true, false)
    }
    fn fragment_publish<T>(
        &mut self,
        part: &super::fragment::Part,
        operation: impl FnOnce(&mut Self) -> Result<T, packet::Error>,
    ) -> Result<T, packet::Error> {
        if self
            .fragment
            .as_ref()
            .is_none_or(|original| !original.same(part))
        {
            return Err(packet::Error::Access);
        }
        let authority = self.native.authority;
        let qualification = self
            .native
            .ordinary
            .as_ref()
            .ok_or(packet::Error::Access)?
            .clone();
        // Preserve genuine unpublished Busy separately from cap-scope failures.
        crate::rtw88::pci_park::invoke(&authority, || {
            qualification.with_current(|| {
                Ok((|| {
                    self.native
                        .fragment_part_current(part, part.bytes(), true, false)?;
                    control::awake(&mut self.native.io)?;
                    operation(self)
                })())
            })
        })
        .map_err(|_| packet::Error::Access)?
        .map_err(|_| packet::Error::Access)?
    }
    fn allocate(&mut self, length: usize) -> Result<DmaBuffer, packet::Error> {
        alloc_coherent_masked(length, DomainId::DRIVER_0, DEVICE_DMA_MASK)
            .map_err(|_| packet::Error::Memory)
    }
    fn receive(&mut self) -> Result<packet::RxStep, packet::Error> {
        if let Some(event) = self.native.station_runtime.backlog.pop_front() {
            return Ok(packet::RxStep {
                consumed: true,
                event: Some(event),
            });
        }
        let batch = self
            .native
            .rx_hardware_step(1)
            .map_err(|_| packet::Error::Access)?;
        for event in batch.events {
            self.native.retain_event(event)?;
        }
        Ok(packet::RxStep {
            consumed: batch.consumed,
            event: self.native.station_runtime.backlog.pop_front(),
        })
    }
    fn start(&mut self, open: u32) -> Result<(), packet::Error> {
        if open & !self.native.tx_stop_all() != 0 || open & ORDINARY_STOP != ORDINARY_STOP {
            return Err(packet::Error::State);
        }
        self.native
            .with_ordinary_current(|native| {
                native.ordinary_current()?;
                control::awake(&mut native.io)?;
                // CH12/RX/RPQ and both HCI directions must still be this owner's.
                // RTL8852C: `B_AX_RXHCI_EN_V1` and `R_AX_HCI_FUNC_EN_V1`
                // (rtw8852ce.c `rtw8852c_pci_info`) with `B_AX_TXHCI_EN_V1`,
                // which the CH12 download already opened. RTL8851B takes
                // B's (rtw8851be.c `rtw8851b_pci_info` == rtw8852be.c's).
                let (hci, function) = if native.chip == ChipId::Rtl8852C {
                    (1 << 15 | 1 << 7, 0x7880)
                } else {
                    (3 << 12, 0x8380)
                };
                if native.receive.state() != rx_dma::State::Polling
                    || native.command().map_err(|_| power::Error::Access)?
                        & narf_bus::pci::cmd::BUS_MASTER
                        == 0
                    || native.io.read32(0x1000)? & hci != hci
                    || native.io.read32(function)? & 3 != 3
                {
                    return Err(power::Error::Access);
                }
                let stopped = native.io.read32(0x1010)?;
                if stopped == u32::MAX || stopped & open != open {
                    return Err(power::Error::Access);
                }
                native.io.write32(0x1010, stopped & !open)?;
                native.ordinary_current()?;
                let functions = native.io.read32(0xc000)?;
                if functions == u32::MAX {
                    return Err(power::Error::Access);
                }
                native.io.write32(0xc000, functions | 1 << 29)?;
                native.station_runtime.started = true;
                Ok(())
            })
            .map_err(Into::into)
    }
    fn stop(&mut self) -> Result<(), packet::Error> {
        if self.native.sleep_reset.is_some() {
            return Err(packet::Error::State);
        }
        // Cleanup does not require a still-valid power grant. Always attempt
        // both independent closes under current device authority.
        let functions = self.native.io.read32(0xc000);
        let cmac = functions.and_then(|v| {
            if v == u32::MAX {
                return Err(power::Error::Gone);
            }
            self.native.io.write32(0xc000, v & !(1 << 29))
        });
        let stop_all = self.native.tx_stop_all();
        let dma = self.native.io.read32(0x1010).and_then(|v| {
            if v == u32::MAX {
                return Err(power::Error::Gone);
            }
            self.native.io.write32(0x1010, v | stop_all)
        });
        self.native.station_runtime.started = false;
        cmac?;
        dma?;
        if self.native.io.read32(0xc000)? & (1 << 29) != 0
            || self.native.io.read32(0x1010)? & stop_all != stop_all
        {
            return Err(packet::Error::Access);
        }
        Ok(())
    }
}
const ORDINARY_STOP: u32 = 1 << 8 | 1 << 16 | 1 << 19;

#[derive(Clone, Copy)]
pub(super) enum Permit<'a> {
    Legacy,
    Station(&'a control::Admission),
    Cleanup,
    Sleep(&'a crate::rtw89::lps::Binding),
    SleepEnter(&'a crate::rtw89::lps::Binding),
}
impl Native {
    fn command_permitted(&mut self, permit: Permit<'_>) -> Result<(), Error> {
        if self.state != State::Active {
            return Err(Error::Terminal);
        }
        if self.wow_parked() {
            // HCI DMA is off until `wow_trx_leave_pre`.
            return Err(Error::Busy);
        }
        if self.sleep_blocked && matches!(permit, Permit::Legacy | Permit::Station(_)) {
            return Err(Error::Busy);
        }
        match permit {
            Permit::Legacy => self.command_admission(),
            Permit::Station(admission) => {
                admission.check().map_err(|_| Error::Access)?;
                if self.station_runtime.monitor.is_some() {
                    self.monitor_request_current(admission)
                        .map_err(|_| Error::Access)?;
                }
                self.ordinary_current().map_err(|_| Error::Access)
            }
            Permit::Cleanup => self.authority.check_live().map_err(|_| Error::Access),
            Permit::Sleep(binding) | Permit::SleepEnter(binding) => {
                self.sleep_current(binding).map_err(|_| Error::Access)
            }
        }
    }
    pub(super) async fn send_permit(
        &mut self,
        kind: Kind,
        bytes: &[u8],
        permit: Permit<'_>,
    ) -> Result<(), Error> {
        self.command_permitted(permit)?;
        if let Permit::SleepEnter(binding) = permit {
            if !self
                .sleep_prefix(binding)
                .map_err(|_| Error::Access)?
                .unwrap_or(false)
            {
                return Err(Error::Busy);
            }
        }
        self.poll()?;
        let start = self.io.now_us();
        while self.queue.is_full() {
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                self.state = State::Terminal;
                return Err(Error::Timeout);
            }
            self.io.delay_us(50).await;
            self.command_permitted(permit)?;
            self.poll()?;
        }
        self.command_permitted(permit)?;
        if let Permit::SleepEnter(binding) = permit {
            if !self
                .sleep_prefix(binding)
                .map_err(|_| Error::Access)?
                .unwrap_or(false)
            {
                return Err(Error::Busy);
            }
        }
        let header = command_queue::descriptor(self.chip, kind, bytes.len())?;
        let packet = alloc_coherent_masked(
            header.len() + bytes.len(),
            DomainId::DRIVER_0,
            DEVICE_DMA_MASK,
        )
        .map_err(|_| Error::NoMemory)?;
        let bd = command_queue::txbd(packet.dma_addr().raw(), header.len() + bytes.len())?;
        let ring = self.ring.as_ref().ok_or(Error::Terminal)?;
        let calibration = &self.calibration;
        let full = self.full_radio_scope();
        let ordinary = &self.ordinary;
        let sleep_enter = matches!(permit, Permit::SleepEnter(_));
        let monitoring = self.station_runtime.monitor.is_some();
        let receive = &self.receive;
        let backlog_pending = !self.station_runtime.backlog.is_empty();
        let authority = self.authority;
        let io = &mut self.io;
        let idx = self.regs.idx as u32;
        let queue = &mut self.queue;
        let mut packet = Some(packet);
        let mut publication = || -> Result<(), Error> {
            // This strict denial occurs INSIDE all original current scopes,
            // but BEFORE CommandQueue marks issued or touches descriptors.
            // Busy here is genuinely unpublished and preserves queue state.
            if sleep_enter && (backlog_pending || receive.pending(io).map_err(|_| Error::Access)?) {
                return Err(Error::Busy);
            }
            if monitoring
                && io.read32(0xc000).map_err(|_| Error::Access)?
                    & crate::rtw89::monitor_wire::CMAC_TX
                    != 0
            {
                return Err(Error::Access);
            }
            let packet = packet.take().ok_or(Error::Terminal)?;
            match queue.submit(packet, |slot, next, packet| {
                // SAFETY: original current scopes enclose the whole queue
                // issue/descriptor/cache/doorbell transaction. Once issued,
                // an ambiguous error stays terminal with storage retained.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        header.as_ptr(),
                        packet.as_mut_ptr(),
                        header.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        packet.as_mut_ptr().add(header.len()),
                        bytes.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        bd.as_ptr(),
                        ring.as_mut_ptr().add(usize::from(slot) * 8),
                        8,
                    );
                }
                packet.sync(0, header.len() + bytes.len());
                ring.sync(usize::from(slot) * 8, 8);
                barrier();
                io.write16(idx, next).map_err(|_| Error::Access)
            }) {
                Ok(_) => Ok(()),
                Err((error, unpublished)) => {
                    drop(unpublished);
                    Err(error)
                }
            }
        };
        let result = crate::rtw88::pci_park::invoke(&authority, || {
            match permit {
                Permit::Station(admission) => admission
                    .run(|| {
                        let grant = ordinary.as_ref().ok_or(power::Error::Unsupported)?;
                        grant.with_current(|| Ok(publication()))
                    })
                    .map_err(|_| Error::Access)?,
                Permit::Legacy => {
                    if let Some(full) = full.as_ref() {
                        full.with_current(|| Ok(publication()))
                            .map_err(|_| Error::Access)?
                    } else if let Some(calibration) = calibration {
                        calibration
                            .with_current(|| Ok(publication()))
                            .map_err(|_| Error::Access)?
                    } else {
                        publication()
                    }
                }
                Permit::Cleanup => publication(),
                Permit::Sleep(binding) | Permit::SleepEnter(binding) => binding
                    .run(|| {
                        let grant = ordinary.as_ref().ok_or(power::Error::Access)?;
                        if grant
                            .b()
                            .ok_or(power::Error::Unsupported)?
                            .sleep_profile()
                            .map_err(|_| power::Error::Access)?
                            .is_none()
                        {
                            return Err(power::Error::Unsupported);
                        }
                        // Preserve the inner publication error separately from
                        // cap/source failure: an actual unpublished Busy defers.
                        grant.with_current(|| Ok(publication()))
                    })
                    .map_err(|_| Error::Access)?,
            }
        })
        .map_err(|_| Error::Access)
        .and_then(|result| result);
        // Only a guard refusal leaves this owned, unpublished allocation.
        drop(packet);
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                if !matches!(permit, Permit::SleepEnter(_)) || error != Error::Busy {
                    self.state = State::Terminal;
                }
                Err(error)
            }
        }
    }
    pub(super) async fn runtime_command(
        &mut self,
        category: u8,
        class: u8,
        function: u8,
        bytes: &[u8],
        done: bool,
        permit: Permit<'_>,
    ) -> Result<(), power::Error> {
        self.command_permitted(permit)
            .map_err(|_| power::Error::Access)?;
        if self.runtime_sequence >= 256 || bytes.is_empty() || bytes.len() > 2000 {
            return Err(power::Error::Unsupported);
        }
        let sequence = self.runtime_sequence as u8;
        self.runtime_sequence += 1;
        let receive_ack = matches!((category, class, function), (1, 9, 1 | 8)) || sequence % 4 == 0;
        let mut packet = alloc::vec![0; 8 + bytes.len()];
        super::super::txrx::encode_h2c_header(
            category,
            class,
            function,
            sequence,
            bytes.len() as u16,
            receive_ack,
            done,
            &mut packet,
        )
        .ok_or(power::Error::Unsupported)?;
        packet[8..].copy_from_slice(bytes);
        self.send_permit(Kind::Header, &packet, permit)
            .await
            .map_err(|error| {
                if error == Error::Busy
                    && matches!(permit, Permit::SleepEnter(_))
                    && self.state == State::Active
                {
                    power::Error::Busy
                } else {
                    power::Error::Access
                }
            })?;
        let start = self.io.now_us();
        let require_receive = (category, class, function) == (1, 9, 1)
            && matches!(permit, Permit::Sleep(_) | Permit::SleepEnter(_));
        let mut completed = !done;
        let mut received = false;
        loop {
            self.command_permitted(permit)
                .map_err(|_| power::Error::Access)?;
            self.poll().map_err(|_| power::Error::Access)?;
            let batch = self
                .rx_hardware_step(32)
                .map_err(|_| power::Error::Access)?;
            for event in batch.events {
                let mut matched = false;
                if let rx_packet::Event::Firmware(message) = &event {
                    if let Some(ack) = message.ack().map_err(|_| power::Error::Access)? {
                        if (ack.category, ack.class, ack.function, ack.sequence)
                            == (category, class, function, sequence)
                        {
                            matched = true;
                            match ack.result {
                                Some(status) if done && status == 0 && !completed => {
                                    completed = true
                                }
                                Some(_) => return Err(power::Error::Access),
                                None if receive_ack && !received => received = true,
                                None => return Err(power::Error::Access),
                            }
                        }
                    }
                }
                if !matched {
                    self.retain_event(event)?;
                }
            }
            // RECV_ACK is not execution. The source pause continuation also
            // verifies the actual MACID pause register before proceeding.
            if completed && (!require_receive || received) && self.queue.pending() == 0 {
                self.command_permitted(permit)
                    .map_err(|_| power::Error::Access)?;
                return Ok(());
            }
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(power::Error::Timeout);
            }
            self.io.delay_us(50).await;
        }
    }
}
