// SPDX-License-Identifier: GPL-2.0-or-later
//! Child of the exact firmware PCI backend: no new device/cap/ring owner.
use super::{barrier, dma_address, Native, Registers, State};
use crate::rtw88::{
    packet_core::{self as packet, Core, Port},
    packet_format::{self as format, Queue},
};
use alloc::vec::Vec;
use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
use narf_io::DmaBuffer;

fn access_error(_: crate::rtw88::firmware_transport::Error) -> packet::Error {
    packet::Error::Access
}
fn bytes(memory: &DmaBuffer, offset: usize, length: usize) -> Result<Vec<u8>, packet::Error> {
    if offset
        .checked_add(length)
        .is_none_or(|end| end > memory.len())
    {
        return Err(packet::Error::Address);
    }
    memory.sync(offset, length);
    barrier();
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| packet::Error::Memory)?;
    for position in offset..offset + length {
        // SAFETY: bounded retained CPU map, called only inside current PCI invoke.
        result.push(unsafe { memory.cpu_ptr_at::<u8>(position as u64).read_volatile() });
    }
    Ok(result)
}
fn write(memory: &DmaBuffer, offset: usize, data: &[u8]) -> Result<(), packet::Error> {
    if offset
        .checked_add(data.len())
        .is_none_or(|end| end > memory.len())
    {
        return Err(packet::Error::Address);
    }
    for (position, value) in data.iter().copied().enumerate() {
        // SAFETY: host owns this bounded CPU extent, within current PCI invoke.
        unsafe {
            memory
                .cpu_mut_ptr_at::<u8>((offset + position) as u64)
                .write_volatile(value);
        }
    }
    memory.sync(offset, data.len());
    barrier();
    Ok(())
}
impl Native {
    pub(in crate::rtw88) fn configure_packet_profile(
        &mut self,
        profile: format::DataProfile,
    ) -> Result<(), crate::rtw88::firmware_transport::Error> {
        self.with_packet(|core, _| core.configure_data(profile))
            .map_err(|_| crate::rtw88::firmware_transport::Error::State)
    }
    fn packet_memory<T>(
        &mut self,
        operation: impl FnOnce(&Self) -> Result<T, packet::Error>,
    ) -> Result<T, packet::Error> {
        if !matches!(self.state, State::Calibrated | State::Packets) {
            return Err(packet::Error::State);
        }
        let gate = self.packet_gate.clone().ok_or(packet::Error::Access)?;
        let result = gate
            .invoke(|| {
                crate::rtw88::pci_park::invoke(&self.cap, || {
                    self.command(self.state == State::Packets)?;
                    operation(self).map_err(|_| crate::rtw88::firmware_transport::Error::Access)
                })
                .map_err(|_| crate::rtw88::firmware_transport::Error::Access)?
            })
            .map_err(access_error);
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    pub(in crate::rtw88) fn prepare_packets(
        &mut self,
        own: [u8; 6],
        mac_id: u8,
    ) -> Result<(), packet::Error> {
        if self.state != State::Calibrated
            || self.packet.is_some()
            || self
                .packet_gate
                .as_ref()
                .is_none_or(|gate| gate.own() != own)
        {
            return Err(packet::Error::State);
        }
        match Core::prepare(self, own, mac_id) {
            Ok(core) => {
                self.packet = Some(core);
                Ok(())
            }
            Err(error) => {
                self.state = State::Terminal;
                Err(error)
            }
        }
    }
    fn with_packet<T>(
        &mut self,
        operation: impl FnOnce(&mut Core, &mut Self) -> Result<T, packet::Error>,
    ) -> Result<T, packet::Error> {
        let mut core = self.packet.take().ok_or(packet::Error::State)?;
        let result = operation(&mut core, self);
        // No await/reentrant callback occurs while this sync borrow holds the
        // slot. Restore the exact core on every Result, including native loss.
        self.packet = Some(core);
        if result
            .as_ref()
            .is_err_and(|error| *error != packet::Error::Busy)
        {
            let _ = Port::stop(self);
            self.state = State::Terminal;
        }
        result
    }
    pub(in crate::rtw88) fn start_packets(&mut self) -> Result<(), packet::Error> {
        self.with_packet(|core, port| core.start(port))
    }
    pub(in crate::rtw88) fn packets_ready(&self) -> bool {
        self.state == State::Packets && self.packet.as_ref().is_some_and(Core::ready)
    }
    pub(in crate::rtw88) fn submit_packet(
        &mut self,
        frame: &[u8],
        radio_report: bool,
    ) -> Result<u64, packet::Error> {
        self.with_packet(|core, port| core.submit(port, frame, radio_report))
    }
    pub(in crate::rtw88) fn poll_packets(&mut self) -> Result<packet::Step, packet::Error> {
        self.with_packet(|core, port| core.poll(port))
    }
    pub(in crate::rtw88) fn stop_packets(&mut self) -> Result<(), packet::Error> {
        self.with_packet(|core, port| core.stop(port))
    }
}
// SAFETY: this is the same retained, non-cloneable Native after sealed radio
// qualification. CPU and register accesses invoke its actual current cap;
// original rings and every published payload stay retained on every exit.
unsafe impl Port for Native {
    fn transmit_allowed(&mut self) -> Result<(), packet::Error> {
        self.check_packet_permission().map_err(access_error)
    }
    fn memory<T>(
        &mut self,
        operation: impl FnOnce() -> Result<T, packet::Error>,
    ) -> Result<T, packet::Error> {
        self.packet_memory(|_| operation())
    }
    fn allocate(&mut self, length: usize) -> Result<DmaBuffer, packet::Error> {
        if self.state != State::Calibrated {
            return Err(packet::Error::State);
        }
        Native::allocate(self, length).map_err(access_error)
    }
    fn index(&mut self, register: u16) -> Result<u32, packet::Error> {
        if !matches!(register, 0x3a8 | 0x3b0 | 0x3b4) {
            return Err(packet::Error::Address);
        }
        let value = self.read32(register).map_err(access_error)?;
        if value == u32::MAX {
            return Err(packet::Error::Access);
        }
        Ok(value)
    }
    fn publish(&mut self, register: u16, host: u16) -> Result<(), packet::Error> {
        if !matches!(register, 0x3a8 | 0x3b0 | 0x3b4) {
            return Err(packet::Error::Address);
        }
        self.check_packet_permission().map_err(access_error)?;
        // Hardware's read pointer is the upper half: never echo a32-bit read
        // into a host doorbell. Only the lower16-bit WP/RP is host writable.
        self.write16(register, host).map_err(access_error)?;
        if self.read16(register).map_err(access_error)? & 0xfff != host {
            return Err(packet::Error::Access);
        }
        Ok(())
    }
    fn tx_descriptor(
        &mut self,
        queue: Queue,
        slot: usize,
        descriptor: &[u8; 16],
    ) -> Result<(), packet::Error> {
        self.packet_memory(|owner| {
            let index = match queue {
                Queue::Management => 5,
                Queue::Data => 2,
            };
            let ring = owner.tx.get(index).ok_or(packet::Error::State)?;
            if ring.index != queue.index() || ring.depth != queue.depth() || slot >= ring.depth {
                return Err(packet::Error::Address);
            }
            write(&ring.memory, slot * format::TX_BD, descriptor)
        })
    }
    fn rx_descriptor(&mut self, slot: usize) -> Result<[u8; 8], packet::Error> {
        self.packet_memory(|owner| {
            let ring = owner.rx.as_ref().ok_or(packet::Error::State)?;
            let buffer = owner.buffers.get(slot).ok_or(packet::Error::Address)?;
            let data = bytes(ring, slot * format::RX_BD, format::RX_BD)?;
            let descriptor: [u8; 8] = data.try_into().map_err(|_| packet::Error::Packet)?;
            if u32::from_le_bytes(descriptor[4..8].try_into().unwrap())
                != dma_address(buffer, format::RX_BYTES).map_err(access_error)?
            {
                return Err(packet::Error::Address);
            }
            Ok(descriptor)
        })
    }
    fn rx_bytes(
        &mut self,
        slot: usize,
        offset: usize,
        length: usize,
    ) -> Result<Vec<u8>, packet::Error> {
        self.packet_memory(|owner| {
            if offset
                .checked_add(length)
                .is_none_or(|end| end > format::RX_BYTES)
            {
                return Err(packet::Error::Address);
            }
            bytes(
                owner.buffers.get(slot).ok_or(packet::Error::Address)?,
                offset,
                length,
            )
        })
    }
    fn rx_repost(&mut self, slot: usize) -> Result<(), packet::Error> {
        self.packet_memory(|owner| {
            let buffer = owner.buffers.get(slot).ok_or(packet::Error::Address)?;
            let ring = owner.rx.as_ref().ok_or(packet::Error::State)?;
            buffer.sync(0, format::RX_BYTES);
            barrier();
            let mut descriptor = [0; 8];
            descriptor[..4].copy_from_slice(&(format::RX_BYTES as u32).to_le_bytes());
            descriptor[4..8].copy_from_slice(
                &dma_address(buffer, format::RX_BYTES)
                    .map_err(access_error)?
                    .to_le_bytes(),
            );
            write(ring, slot * format::RX_BD, &descriptor)
        })
    }
    fn start(&mut self) -> Result<(), packet::Error> {
        if self.state != State::Calibrated || self.command_ring.pending() {
            return Err(packet::Error::State);
        }
        self.check_packet_permission().map_err(access_error)?;
        // Current Linux uses303 as configuration, not queue-stop evidence.
        // All seven original rings remain owned; unused producer indices stay
        // empty and only MGMT/BE producers will advance. Beacon is sealed by
        // the completed radio continuation before this method is reachable.
        for slot in 0..self.tx.len() {
            let tx = &self.tx[slot];
            let (base, count, index, depth, address) = (
                tx.base,
                tx.count,
                tx.index,
                tx.depth,
                dma_address(&tx.memory, tx.depth * 16).map_err(access_error)?,
            );
            let position = self.read32(index).map_err(access_error)?;
            let expected = if slot == 0 {
                u32::from(self.command_ring.producer())
                    | u32::from(self.command_ring.producer()) << 16
            } else {
                0
            };
            if self.read32(base).map_err(access_error)? != address
                || self.read16(count).map_err(access_error)? & 0xfff != depth as u16
                || position & 0x0fff_0fff != expected
            {
                return Err(packet::Error::Access);
            }
        }
        let base = dma_address(self.rx.as_ref().ok_or(packet::Error::State)?, 512 * 8)
            .map_err(access_error)?;
        if self.read32(0x338).map_err(access_error)? != base
            || self.read16(0x382).map_err(access_error)? & 0xfff != 512
            || self.read32(0x3b4).map_err(access_error)? & 0x0fff_0fff != 0
            || self.read16(0x100).map_err(access_error)? & 0x200 != 0
        {
            return Err(packet::Error::Access);
        }
        for register in [0xb0, 0xb8, 0x10b8] {
            if self.read32(register).map_err(access_error)? != 0 {
                return Err(packet::Error::Access);
            }
        }
        let own = self.packet_gate.as_ref().ok_or(packet::Error::State)?.own();
        for (index, byte) in own.into_iter().enumerate() {
            self.write8(0x610 + index as u16, byte)
                .map_err(access_error)?;
        }
        // CR lowbyte enables HCI/packet DMA and MAC. Security engine remains
        // disabled in highbyte; software owns the original CCMP ciphertext.
        self.write8(0x100, 0xff).map_err(access_error)?;
        self.write8(0x522, 0).map_err(access_error)?;
        if self.read8(0x100).map_err(access_error)? != 255
            || self.read8(0x522).map_err(access_error)? != 0
        {
            return Err(packet::Error::Access);
        }
        self.check_packet_permission().map_err(access_error)?;
        let gate = self.packet_gate.clone().ok_or(packet::Error::State)?;
        gate.invoke(|| {
            crate::rtw88::pci_park::invoke(&self.cap, || {
                self.command(false)?;
                barrier();
                narf_bus::pci::set_command(&self.cap, &self.device, BUS_MASTER)
                    .map_err(|_| crate::rtw88::firmware_transport::Error::Access)?;
                self.command(true)
            })
            .map_err(|_| crate::rtw88::firmware_transport::Error::Access)?
        })
        .map_err(access_error)?;
        self.state = State::Packets;
        Ok(())
    }
    fn stop(&mut self) -> Result<(), packet::Error> {
        // Teardown must still work after native protocol failure. It uses
        // current authority directly rather than manufacturing a live state.
        let result = crate::rtw88::pci_park::invoke(&self.cap, || {
            let command = narf_bus::pci::read_command(&self.cap, &self.device)
                .map_err(|_| packet::Error::Access)?;
            if command == u16::MAX {
                return Err(packet::Error::Access);
            }
            let mut good = true;
            if command & MEM_SPACE != 0 {
                // SAFETY: constructor retained the complete exact BAR, and
                // all actual MMIO in this bounded shutdown is within invoke.
                unsafe {
                    for register in [0xb0, 0xb8, 0x10b8] {
                        self.mmio.write32(register, 0);
                        good &= self.mmio.read32(register) == 0;
                    }
                    self.mmio.write8(0x522, 255);
                    let cr = self.mmio.read8(0x100);
                    self.mmio.write8(0x100, cr & !0xcf);
                    good &= self.mmio.read8(0x100) & 0xcf == 0 && self.mmio.read8(0x522) == 255;
                }
            }
            // Even a failed MMIO readback must still attempt PCI BME closure.
            narf_bus::pci::clear_command(&self.cap, &self.device, BUS_MASTER)
                .map_err(|_| packet::Error::Access)?;
            let after = narf_bus::pci::read_command(&self.cap, &self.device)
                .map_err(|_| packet::Error::Access)?;
            if after == u16::MAX || after & BUS_MASTER != 0 || after & INTX_DISABLE == 0 || !good {
                return Err(packet::Error::Access);
            }
            barrier();
            Ok(())
        })
        .map_err(|_| packet::Error::Access)
        .and_then(|value| value);
        self.state = State::Terminal;
        result
    }
    fn now_us(&self) -> u64 {
        narf_time::monotonic_ns() / 1000
    }
}

#[cfg(feature = "kernel-test")]
fn smoke_rtw8822ce_native_packet_revocation_precedes_cpu_dma_config_and_mmio(
) -> narf_kernel_test::TestResult {
    use narf_bus::{
        BarKind, BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, MmioRegion, PcieAddr,
    };
    use narf_capabilities::{Cap, Write};
    let address = PcieAddr::new(0, 0, 7, 0);
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let mut native = Native {
        device: BusDevice {
            addr: BusAddr::Pcie(address),
            id: DeviceId {
                vendor: 0x10ec,
                device: 0xc822,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        },
        cap,
        mmio: MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x5000,
            kind: BarKind::Mmio32 {
                prefetchable: false,
            },
        },
        tx: Vec::new(),
        rx: None,
        buffers: Vec::new(),
        beacon: None,
        state: State::Calibrated,
        published: false,
        command_buffer: None,
        command_ring: Default::default(),
        packet: None,
        packet_gate: None,
        mailbox_cursor: 0,
        mailbox_pending: false,
    };
    cap.revoke();
    // Invalid physical config/BAR and absent allocations are deliberate. The
    // actual object-table epoch must reject before any callback or access.
    let mut entered = false;
    if Port::memory(&mut native, || {
        entered = true;
        Ok(())
    }) != Err(packet::Error::Access)
        || entered
    {
        return narf_kernel_test::TestResult::Fail("revoked CPU callback entered");
    }
    native.state = State::Calibrated;
    if Port::allocate(&mut native, 128).is_ok() {
        return narf_kernel_test::TestResult::Fail("revoked DMA allocation entered");
    }
    native.state = State::Packets;
    if Port::index(&mut native, 0x3b4) != Err(packet::Error::Access) {
        return narf_kernel_test::TestResult::Fail("revoked MMIO entered");
    }
    native.state = State::Packets;
    if Port::rx_descriptor(&mut native, 0) != Err(packet::Error::Access) {
        return narf_kernel_test::TestResult::Fail("revoked descriptor access entered");
    }
    if Port::stop(&mut native) != Err(packet::Error::Access) {
        return narf_kernel_test::TestResult::Fail("revoked teardown config entered");
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/rtw88/packet",
    smoke_rtw8822ce_native_packet_revocation_precedes_cpu_dma_config_and_mmio
);
