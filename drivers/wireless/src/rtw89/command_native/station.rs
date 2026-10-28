// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Adapters borrowing the one retained Native. No diagnostic rings or IO clone.
use super::*;
use crate::rtw89::{packet_core as packet, power, rx_dma, rx_packet, station_control as control};
use alloc::boxed::Box;
use alloc::collections::VecDeque;

#[derive(Default)]
pub(super) struct Runtime {
    pub(super) core: Option<packet::Core>,
    peer: Option<control::Peer>,
    backlog: VecDeque<rx_packet::Event>,
    started: bool,
}
pub(in crate::rtw89) struct Access<'a> {
    native: &'a mut Native,
    cleanup: bool,
}
impl Native {
    pub(in crate::rtw89) fn station_access(&mut self) -> Access<'_> {
        Access {
            native: self,
            cleanup: false,
        }
    }
    pub(in crate::rtw89) fn station_cleanup(&mut self) -> Access<'_> {
        Access {
            native: self,
            cleanup: true,
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
    fn rx_hardware_step(&mut self, budget: usize) -> Result<rx_dma::Batch, rx_dma::Error> {
        let cap = self.authority;
        crate::rtw88::pci_park::invoke(&cap, || {
            if self.state != State::Active {
                return Err(rx_dma::Error::Terminal);
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
    fn retain_event(&mut self, event: rx_packet::Event) -> Result<(), power::Error> {
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
        if self.station_runtime.core.is_some() {
            return Err(packet::Error::State);
        }
        self.ordinary_current()?;
        let qos_all = self.station_qos_all_allowed().unwrap_or(false);
        let ht = self.station_ht_allowed().unwrap_or(false);
        let he = self.station_he_allowed().unwrap_or(false);
        let rx = packet::RxPhy::from_programs(ht, he);
        let core = packet::Core::prepare_with(&mut self.station_access(), own, macid, qos_all, rx);
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
    fn packet_operation<T>(
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
            && self
                .station_runtime
                .core
                .as_ref()
                .is_some_and(packet::Core::ready)
    }
    pub(in crate::rtw89) fn submit_packet(
        &mut self,
        bytes: &[u8],
        report: bool,
    ) -> Result<u64, packet::Error> {
        self.packet_operation(|core, port| core.submit(port, bytes, report))
    }
    pub(in crate::rtw89) fn submit_packet_rate(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        if rate != 0 && !self.station_wmm_allowed()? {
            return Err(packet::Error::Access);
        }
        if rate & crate::rtw89::packet_format::FIRMWARE_RA != 0
            && !self.station_firmware_ra_allowed()?
        {
            return Err(packet::Error::Access);
        }
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
        let result = if let Some(mut core) = self.station_runtime.core.take() {
            let result = core.stop(&mut self.station_cleanup());
            self.station_runtime.core = Some(core);
            result
        } else {
            // Private CH12/RX already exists during source controller setup.
            packet::Port::stop(&mut self.station_cleanup())
        };
        self.station_runtime.peer = None;
        self.station_runtime.started = false;
        self.fail();
        result?;
        if self.command().map_err(|_| packet::Error::Access)? & narf_bus::pci::cmd::BUS_MASTER != 0
        {
            return Err(packet::Error::Access);
        }
        Ok(())
    }
}
impl power::Io for Access<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.native.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.native.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.native.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.native.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        let rings = addr_set_for_chip(ChipId::Rtl8852B).tx;
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
    fn preflight(&mut self, indirect: bool) -> Result<(), power::Error> {
        if self.native.state != State::Active || self.native.chip != ChipId::Rtl8852B {
            return Err(power::Error::Terminal);
        }
        self.native.io.b_station_window(indirect)?;
        if self.cleanup {
            // Stop ordinary responses/queues while CH12/private RX remain
            // available for cleanup ACKs after power qualification is lost.
            packet::Port::stop(self).map_err(|_| power::Error::Access)?;
        } else {
            self.native.ordinary_current()?;
        }
        Ok(())
    }
    fn with_current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
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
                .qualification
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
    fn ordinary_allowed(&mut self) -> Result<(), packet::Error> {
        self.native
            .with_ordinary_current(|native| control::awake(&mut native.io))
            .map_err(Into::into)
    }
    fn peer_allowed(&mut self, bytes: &[u8]) -> Result<(), packet::Error> {
        if self
            .native
            .station_runtime
            .peer
            .as_ref()
            .is_some_and(|peer| peer.admits(bytes))
        {
            Ok(())
        } else {
            Err(packet::Error::Packet)
        }
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
        if open & !crate::rtw89::packet_format::STOP_ALL != 0
            || open & ORDINARY_STOP != ORDINARY_STOP
        {
            return Err(packet::Error::State);
        }
        self.native
            .with_ordinary_current(|native| {
                native.ordinary_current()?;
                control::awake(&mut native.io)?;
                // CH12/RX/RPQ and both HCI directions must still be this owner's.
                if native.receive.state() != rx_dma::State::Polling
                    || native.command().map_err(|_| power::Error::Access)?
                        & narf_bus::pci::cmd::BUS_MASTER
                        == 0
                    || native.io.read32(0x1000)? & (3 << 12) != 3 << 12
                    || native.io.read32(0x8380)? & 3 != 3
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
        // Cleanup does not require a still-valid power grant. Always attempt
        // both independent closes under current device authority.
        let functions = self.native.io.read32(0xc000);
        let cmac = functions.and_then(|v| {
            if v == u32::MAX {
                return Err(power::Error::Gone);
            }
            self.native.io.write32(0xc000, v & !(1 << 29))
        });
        let dma = self.native.io.read32(0x1010).and_then(|v| {
            if v == u32::MAX {
                return Err(power::Error::Gone);
            }
            self.native
                .io
                .write32(0x1010, v | crate::rtw89::packet_format::STOP_ALL)
        });
        self.native.station_runtime.started = false;
        cmac?;
        dma?;
        if self.native.io.read32(0xc000)? & (1 << 29) != 0
            || self.native.io.read32(0x1010)? & crate::rtw89::packet_format::STOP_ALL
                != crate::rtw89::packet_format::STOP_ALL
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
}
impl Native {
    fn command_permitted(&mut self, permit: Permit<'_>) -> Result<(), Error> {
        if self.state != State::Active {
            return Err(Error::Terminal);
        }
        match permit {
            Permit::Legacy => self.command_admission(),
            Permit::Station(admission) => {
                admission.check().map_err(|_| Error::Access)?;
                self.ordinary_current().map_err(|_| Error::Access)
            }
            Permit::Cleanup => self.authority.check_live().map_err(|_| Error::Access),
        }
    }
    pub(super) async fn send_permit(
        &mut self,
        kind: Kind,
        bytes: &[u8],
        permit: Permit<'_>,
    ) -> Result<(), Error> {
        self.command_permitted(permit)?;
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
        let authority = self.authority;
        let io = &mut self.io;
        let idx = self.regs.idx as u32;
        let result = self.queue.submit(packet, |slot, next, packet| {
            crate::rtw88::pci_park::invoke(&authority, || {
                let mut publish = || -> Result<(), Error> {
                    // SAFETY: exact owned packet/ring extents; all CPU DMA,
                    // cache maintenance and actual doorbell are inside this
                    // current invocation and the station publication guard.
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
                };
                match permit {
                    Permit::Station(admission) => admission
                        .run(|| {
                            let grant = ordinary.as_ref().ok_or(power::Error::Unsupported)?;
                            grant
                                .qualification
                                .with_current(|| publish().map_err(|_| power::Error::Access))
                        })
                        .map_err(|_| Error::Access),
                    Permit::Legacy => {
                        if let Some(full) = full.as_ref() {
                            full.with_current(|| publish().map_err(|_| power::Error::Access))
                                .map_err(|_| Error::Access)
                        } else if let Some(calibration) = calibration {
                            calibration
                                .with_current(|| publish().map_err(|_| power::Error::Access))
                                .map_err(|_| Error::Access)
                        } else {
                            publish()
                        }
                    }
                    Permit::Cleanup => publish(),
                }
            })
            .map_err(|_| Error::Access)?
        });
        match result {
            Ok(_) => Ok(()),
            Err((error, unpublished)) => {
                drop(unpublished);
                self.state = State::Terminal;
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
        let receive_ack = (category, class, function) == (1, 9, 8) || sequence % 4 == 0;
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
            .map_err(|_| power::Error::Access)?;
        let start = self.io.now_us();
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
            if completed && self.queue.pending() == 0 {
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
