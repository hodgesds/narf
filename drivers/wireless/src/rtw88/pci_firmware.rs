//! Private RTL8821CE/RTL8822CE firmware-only PCI owner; Linux rtw88/pci.c/mac.c/util.c.
//! All native rings are retained before BME. MAC TX/RX and IRQ stay closed.
use super::{
    firmware_transport::Error,
    reserved_page::{Backend, Memory, Registers},
};
use alloc::{boxed::Box, vec::Vec};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent_masked, DmaBuffer};
use narf_lib::id::DomainId;
#[path = "pci_packet.rs"]
mod packet;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Allocated,
    Configuring,
    Active,
    Parked,
    MacPrepared,
    PhyTablesPrepared,
    Calibrating8821c,
    Calibration8821cPrepared,
    Operating8821cPrepared,
    Commands,
    Calibrated,
    Packets,
    Terminal,
}
struct Tx {
    base: u16,
    count: u16,
    index: u16,
    depth: usize,
    memory: DmaBuffer,
}
const TX: [(u16, u16, u16, usize); 7] = [
    (0x1320, 0x1328, 0x132c, 128), // H2C
    (0x330, 0x38a, 0x3ac, 128),    // BK
    (0x328, 0x388, 0x3a8, 256),    // BE
    (0x318, 0x384, 0x3a0, 128),    // VO
    (0x320, 0x386, 0x3a4, 128),    // VI
    (0x310, 0x380, 0x3b0, 128),    // MGMT
    (0x340, 0x38c, 0x3b8, 128),    // HIGH
];
const RX_DEPTH: usize = 512;
const RX_BYTES: usize = 11454 + 24;
pub(super) struct Native {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    tx: Vec<Tx>,
    rx: Option<DmaBuffer>,
    buffers: Vec<DmaBuffer>,
    beacon: Option<u32>,
    state: State,
    published: bool,
    command_buffer: Option<DmaBuffer>,
    command_ring: super::command::Ring,
    packet: Option<super::packet_core::Core>,
    packet_gate: Option<super::power_policy::Gate>,
    mailbox_cursor: u8,
    mailbox_pending: bool,
}
impl core::fmt::Debug for Native {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88FirmwarePci")
            .field("address", &self.device.addr)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub(super) struct Coherent(DmaBuffer);
fn barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: PCI ownership crosses the outer-shareable device domain.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
// SAFETY: private exclusively allocated coherent CPU/device mappings; outer
// backend pins published buffers on every ambiguous/cancel/Drop path.
unsafe impl Memory for Coherent {
    fn address(&self) -> u64 {
        self.0.dma_addr().raw()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.0.len())
        {
            return Err(Error::Memory);
        }
        // SAFETY: exclusive CPU mapping and entire byte extent checked above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.0.cpu_mut_ptr_at::<u8>(offset as u64),
                bytes.len(),
            );
        }
        Ok(())
    }
    fn sync(&self) {
        self.0.sync(0, self.0.len());
        barrier();
    }
    fn acquire(&self) {
        barrier();
    }
}
fn dma_address(memory: &DmaBuffer, needed: usize) -> Result<u32, Error> {
    let base = memory.dma_addr().raw();
    if memory.len() < needed
        || base & 255 != 0
        || base
            .checked_add(needed as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Memory);
    }
    Ok(base as u32)
}
impl Native {
    /// # Safety
    /// The exact RTL8821CE/RTL8822CE completed the real chip/cut card-disable→enable
    /// cold power flow and factory EFUSE stage, exclusively under this cap.
    /// BME is parked; no previous firmware/packet/reset owner may exist.
    /// Coherent addresses must be physical/identity-mapped for this PCI device.
    unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        mmio: MmioRegion,
    ) -> Result<Self, Error> {
        if device.id.vendor != 0x10ec
            || !matches!(device.id.device, 0xc821 | 0xc822)
            || mmio.len < 0x170c
            || narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain
        {
            return Err(Error::Unsupported);
        }
        let mut owner = Self {
            device,
            cap,
            mmio,
            tx: Vec::new(),
            rx: None,
            buffers: Vec::new(),
            beacon: None,
            state: State::Allocated,
            published: false,
            command_buffer: None,
            command_ring: super::command::Ring::default(),
            packet: None,
            packet_gate: None,
            mailbox_cursor: 0,
            mailbox_pending: false,
        };
        owner
            .tx
            .try_reserve_exact(TX.len())
            .map_err(|_| Error::Memory)?;
        owner
            .buffers
            .try_reserve_exact(RX_DEPTH)
            .map_err(|_| Error::Memory)?;
        for (base, count, index, depth) in TX {
            let memory = owner.allocate(depth * 16)?;
            owner.tx.push(Tx {
                base,
                count,
                index,
                depth,
                memory,
            });
        }
        let rx = owner.allocate(RX_DEPTH * 8)?;
        for slot in 0..RX_DEPTH {
            let buffer = owner.allocate(RX_BYTES)?;
            let address = dma_address(&buffer, RX_BYTES)?;
            // SAFETY: fresh owned RX BD array covers every aligned8-byte entry;
            // BME is still parked and no base is published during construction.
            unsafe {
                rx.cpu_mut_ptr_at::<u32>((slot * 8) as u64)
                    .write_volatile((RX_BYTES as u32).to_le());
                rx.cpu_mut_ptr_at::<u32>((slot * 8 + 4) as u64)
                    .write_volatile(address.to_le());
            }
            buffer.sync(0, RX_BYTES);
            owner.buffers.push(buffer);
        }
        rx.sync(0, RX_DEPTH * 8);
        barrier();
        owner.rx = Some(rx);
        Ok(owner)
    }
    fn allocate(&self, len: usize) -> Result<DmaBuffer, Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.command(false)?;
            let memory = alloc_coherent_masked(len, DomainId::DRIVER_0, u64::from(u32::MAX))
                .map_err(|_| Error::Memory)?;
            dma_address(&memory, len)?;
            // SAFETY: fresh exclusively owned coherent mapping covers len.
            unsafe {
                core::ptr::write_bytes(memory.cpu_mut_ptr_at::<u8>(0), 0, len);
            }
            memory.sync(0, len);
            barrier();
            Ok(memory)
        })
        .map_err(|_| Error::Access)?
    }
    fn command(&self, active: bool) -> Result<(), Error> {
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        let command =
            narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
        let expected = MEM_SPACE | INTX_DISABLE | if active { BUS_MASTER } else { 0 };
        if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != expected {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn access<T>(
        &mut self,
        reg: u16,
        width: usize,
        operation: impl FnOnce(MmioRegion) -> T,
    ) -> Result<T, Error> {
        if !matches!(
            self.state,
            State::Configuring
                | State::Active
                | State::MacPrepared
                | State::PhyTablesPrepared
                | State::Calibrating8821c
                | State::Calibration8821cPrepared
                | State::Operating8821cPrepared
                | State::Commands
                | State::Calibrated
                | State::Packets
        ) {
            return Err(Error::State);
        }
        let active = matches!(self.state, State::Active | State::Commands | State::Packets);
        let gate = self.packet_gate.clone();
        let access = || {
            crate::rtw88::pci_park::invoke(&self.cap, || {
                self.command(active)?;
                if usize::from(reg) % width != 0 || u64::from(reg) + width as u64 > self.mmio.len {
                    return Err(Error::Access);
                }
                Ok(operation(self.mmio))
            })
            .map_err(|_| Error::Access)
            .and_then(|value| value)
        };
        let result = match gate {
            Some(gate) => gate.invoke(access),
            None => access(),
        };
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn registers(&mut self, beacon: u32) -> Result<(), Error> {
        self.published = true; // before any base can be visible to the device
        let config = self.read8(0x303)?;
        self.write8(0x303, config | 0xf7)?;
        let cr = self.read8(0x100)?;
        self.write8(0x100, cr & !0xcf)?;
        for register in [0xb0, 0xb8, 0x10b8] {
            self.write32(register, 0)?;
            if self.read32(register)? != 0 {
                return Err(Error::Prerequisite);
            }
        }
        if self.read8(0x303)? & 0xf7 != 0xf7 || self.read8(0x100)? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        self.write32(0x308, beacon)?;
        for slot in 0..self.tx.len() {
            let tx = &self.tx[slot];
            let (base, count, depth) = (tx.base, tx.count, tx.depth);
            let address = dma_address(&tx.memory, depth * 16)?;
            self.write16(count, depth as u16)?;
            self.write32(base, address)?;
            if self.read32(base)? != address || self.read16(count)? & 0xfff != depth as u16 {
                return Err(Error::Prerequisite);
            }
        }
        let rx = dma_address(self.rx.as_ref().ok_or(Error::State)?, RX_DEPTH * 8)?;
        self.write16(0x382, RX_DEPTH as u16)?;
        self.write32(0x338, rx)?;
        if self.read32(0x308)? != beacon
            || self.read32(0x338)? != rx
            || self.read16(0x382)? & 0xfff != RX_DEPTH as u16
        {
            return Err(Error::Prerequisite);
        }
        self.write32(0x39c, u32::MAX)?;
        let h2c = self.read32(0x1330)?;
        self.write32(0x1330, h2c | 1 << 16 | 1 << 8)?;
        let ctrl = self.read32(0x300)?;
        if ctrl == u32::MAX {
            return Err(Error::Gone);
        }
        self.write32(0x300, ctrl | 1 << 20 | 1 << 15)?;
        for slot in 0..self.tx.len() {
            let index = self.tx[slot].index;
            if self.read32(index)? & 0x0fff_0fff != 0 {
                return Err(Error::Prerequisite);
            }
        }
        if self.read32(0x3b4)? & 0x0fff_0fff != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn activate(&mut self) -> Result<(), Error> {
        // The source303|f7 value is PCI DMA configuration, not a queue
        // pause map. Empty producer indices and CR's MAC/RX gates constrain
        // the retained firmware-only publication; BME is enabled last.
        use narf_bus::pci::cmd::BUS_MASTER;
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.command(false)?;
            barrier();
            narf_bus::pci::set_command(&self.cap, &self.device, BUS_MASTER)
                .map_err(|_| Error::Access)?;
            self.command(true)
        })
        .map_err(|_| Error::Access)??;
        self.state = State::Active;
        Ok(())
    }
    async fn poll(&mut self, reg: u16, mask: u32, target: u32) -> Result<(), Error> {
        for _ in 0..1000 {
            let value = self.read32(reg)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            if value & mask == target {
                return Ok(());
            }
            self.delay_us(10).await;
        }
        Err(Error::Timeout)
    }
    fn park(&mut self) -> Result<(), Error> {
        let config = self.read8(0x303)?;
        self.write8(0x303, config | 0xf7)?;
        let cr = self.read8(0x100)?;
        self.write8(0x100, cr & !0xcf)?;
        if self.read8(0x303)? & 0xf7 != 0xf7 || self.read8(0x100)? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.command(true)?;
            narf_bus::pci::clear_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                .map_err(|_| Error::Access)?;
            self.command(false)
        })
        .map_err(|_| Error::Access)??;
        self.state = State::Configuring;
        Ok(())
    }
}
#[async_trait::async_trait]
// SAFETY: Native owns all non-beacon ring mappings, requires a pristine cold
// chip at construction, publishes them with all packet/IRQ gates parked, and
// enables BME only after exact base/count/index checks. All real operations
// execute inside current Cap::invoke; every published mapping stays retained.
unsafe impl Registers for Native {
    fn claim_firmware_dma(&mut self, beacon: u32) -> Result<(), Error> {
        if self.state != State::Allocated {
            return Err(Error::Prerequisite);
        }
        self.state = State::Configuring;
        self.beacon = Some(beacon);
        let result = self
            .registers(beacon)
            .and_then(|()| self.activate())
            .and_then(|()| {
                // Linux main.c::rtw_chip_efuse_enable requests this report before
                // loading/starting the MCU. It binds later antenna/NSS selection
                // to a real response from this exact retained firmware generation.
                self.write8(0x1a0, 0xfd)
            });
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        // SAFETY: current authority, command state and complete byte checked.
        self.access(reg, 1, |mmio| unsafe { mmio.read8(u64::from(reg)) })
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        // SAFETY: current authority and complete aligned word checked.
        self.access(reg, 2, |mmio| unsafe { mmio.read16(u64::from(reg)) })
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        // SAFETY: current authority and complete aligned dword checked.
        self.access(reg, 4, |mmio| unsafe { mmio.read32(u64::from(reg)) })
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        // SAFETY: current authority, command state and complete byte checked.
        self.access(reg, 1, |mmio| unsafe { mmio.write8(u64::from(reg), value) })
    }
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        // SAFETY: current authority and complete aligned word checked.
        self.access(reg, 2, |mmio| unsafe {
            mmio.write16(u64::from(reg), value)
        })
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        // SAFETY: current authority and complete aligned dword checked.
        self.access(reg, 4, |mmio| unsafe {
            mmio.write32(u64::from(reg), value)
        })
    }
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.poll(0x1700, 1 << 29, 1 << 29).await?;
        self.write32(0x1700, 0x800f0038)?;
        self.read32(0x1708)
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        self.poll(0x1700, 1 << 29, 1 << 29).await?;
        self.write32(0x1704, value)?;
        self.write32(0x1700, 0xc00f0038)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        if self.state != State::Active {
            return Err(Error::State);
        }
        let result = (|| {
            self.park()?;
            let beacon = self.beacon.ok_or(Error::State)?;
            self.registers(beacon)?;
            self.state = State::Parked;
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        if self.state != State::Parked {
            return Err(Error::State);
        }
        self.state = State::Configuring;
        let result = (|| {
            // All accesses still invoke the retained current PCI capability.
            // Reuse only the actual firmware-ready/parked native generation.
            if self.read16(0x80)? & 0xcfff != 0xc078
                || self.read8(0x303)? & 0xf7 != 0xf7
                || self.read8(0x100)? & 0xcf != 0
            {
                return Err(Error::Prerequisite);
            }
            for register in [0xb0, 0xb8, 0x10b8] {
                if self.read32(register)? != 0 {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        if self.state != State::Configuring {
            return Err(Error::State);
        }
        let result = (|| {
            if self.read8(0x303)? & 0xf7 != 0xf7
                || self.read8(0x100)? & 0xcf != 0
                || self.read8(0x522)? != 255
            {
                return Err(Error::Prerequisite);
            }
            for register in [0xb0, 0xb8, 0x10b8] {
                if self.read32(register)? != 0 {
                    return Err(Error::Prerequisite);
                }
            }
            Ok(())
        })();
        self.state = if result.is_ok() {
            State::MacPrepared
        } else {
            State::Terminal
        };
        result
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        if self.state != State::MacPrepared {
            return Err(Error::State);
        }
        let extent = if self.device.id.device == 0xc821 {
            0x2000
        } else {
            0x5000
        };
        if self.mmio.len < extent {
            return Err(Error::Unsupported);
        }
        self.state = State::Configuring;
        if self.read8(0x100)? & 0xcf != 0 || self.read8(0x303)? & 0xf7 != 0xf7 {
            self.state = State::Terminal;
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.finish_mac()?;
        self.state = State::PhyTablesPrepared;
        Ok(())
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        if self.device.id.device != 0xc821 || self.state != State::PhyTablesPrepared {
            return Err(Error::State);
        }
        if self.mmio.len < 0x2c00 {
            return Err(Error::Unsupported);
        }
        self.state = State::Calibrating8821c;
        if self.read8(0x100)? & 0xcf != 0
            || self.read8(0x522)? != 255
            || self.read8(0x303)? & 0xf7 != 0xf7
        {
            self.state = State::Terminal;
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        if self.device.id.device != 0xc821
            || self.state != State::Configuring
            || self.command_ring.pending()
        {
            return Err(Error::State);
        }
        self.finish_mac()?;
        self.state = State::Calibration8821cPrepared;
        Ok(())
    }
    fn begin_operating8821c(&mut self) -> Result<(), Error> {
        if self.device.id.device != 0xc821
            || self.state != State::Calibration8821cPrepared
            || self.command_ring.pending()
        {
            return Err(Error::State);
        }
        self.state = State::Configuring;
        if self.read8(0x100)? & 0xcf != 0
            || self.read8(0x522)? != 255
            || self.read8(0x303)? & 0xf7 != 0xf7
        {
            self.state = State::Terminal;
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn finish_operating8821c(&mut self) -> Result<(), Error> {
        if self.device.id.device != 0xc821 || self.state != State::Configuring {
            return Err(Error::State);
        }
        self.finish_mac()?;
        self.state = State::Operating8821cPrepared;
        Ok(())
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        if self.device.id.device != 0xc821
            || self.state != State::Operating8821cPrepared
            || self.command_ring.pending()
        {
            return Err(Error::State);
        }
        self.state = State::Configuring;
        self.finish_mac()?; // actual closed CR/TXPAUSE/IRQ and parked PCI receipts
        self.state = State::Configuring;
        Ok(())
    }
    fn finish_station8821c(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        if self.device.id.device != 0xc821
            || self.state != State::Configuring
            || gate.did() != 0xc821
        {
            return Err(Error::State);
        }
        gate.current().map_err(Error::Power)?;
        self.finish_mac()?;
        self.packet_gate = Some(gate);
        self.state = State::Calibrated;
        Ok(())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        if !(self.state == State::PhyTablesPrepared
            || self.device.id.device == 0xc821 && self.state == State::Calibrating8821c)
            || self.command_buffer.is_some()
        {
            return Err(Error::State);
        }
        let result = (|| {
            // Allocate and retain before BME can be set. This buffer is separate
            // from the pinned firmware beacon bounce and all ordinary packets.
            self.command_buffer = Some(self.allocate(80)?);
            let tx = self.tx.first().ok_or(Error::State)?;
            let base = dma_address(&tx.memory, tx.depth * 16)?;
            if self.read32(0x1320)? != base
                || self.read16(0x1328)? & 0xfff != 128
                || self.read32(0x132c)? & 0x0fff_0fff != 0
                || self.read8(0x303)? & 0xf7 != 0xf7
                || self.read8(0x100)? & 0xcf != 0
                || self.read8(0x522)? != 255
            {
                return Err(Error::Prerequisite);
            }
            for reg in [0xb0, 0xb8, 0x10b8] {
                if self.read32(reg)? != 0 {
                    return Err(Error::Prerequisite);
                }
            }
            // Only the H2C producer can advance. All ordinary ring indices
            // remain empty; MAC TX/RX and HCI RXDMA are disabled.303 is source
            // PCI DMA configuration, not an inferred queue-pause bitmap.
            self.write8(0x100, 0x33)?;
            crate::rtw88::pci_park::invoke(&self.cap, || {
                self.command(false)?;
                barrier();
                narf_bus::pci::set_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                    .map_err(|_| Error::Access)?;
                self.command(true)
            })
            .map_err(|_| Error::Access)??;
            self.state = State::Commands;
            if self.read8(0x100)? != 0x33 || self.read8(0x303)? & 0xf7 != 0xf7 {
                return Err(Error::Prerequisite);
            }
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn submit_h2c(&mut self, packet: &[u8; 32]) -> Result<(), Error> {
        if self.state != State::Commands || self.command_ring.pending() {
            return Err(Error::State);
        }
        let result = (|| {
            let index = self.read32(0x132c)?;
            if index == u32::MAX {
                return Err(Error::Gone);
            }
            // Occupancy is committed before touching any reusable byte; errors
            // and cancellation cannot treat an ambiguous descriptor as idle.
            let (slot, next) = self.command_ring.reserve(index)?;
            let cap = self.cap;
            crate::rtw88::pci_park::invoke(&cap, || {
                self.command(true)?;
                let payload = self.command_buffer.as_mut().ok_or(Error::State)?;
                let base = dma_address(payload, 80)?;
                let descriptor = super::command::descriptor();
                // SAFETY: exact retained80-byte mapping, single current CPU owner;
                // the preceding hardware head proves the old command has retired.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        descriptor.as_ptr(),
                        payload.cpu_mut_ptr_at::<u8>(0),
                        48,
                    );
                    core::ptr::copy_nonoverlapping(
                        packet.as_ptr(),
                        payload.cpu_mut_ptr_at::<u8>(48),
                        32,
                    );
                }
                payload.sync(0, 80);
                let tx = self.tx.first().ok_or(Error::State)?;
                let offset = u64::from(slot) * 16;
                // SAFETY: producer is modulo128 and retained H2C BD storage is
                //128×16 bytes. Both segments reference this retained command.
                unsafe {
                    let words = tx.memory.cpu_mut_ptr_at::<u32>(offset);
                    words.write_volatile((48u32 | 1 << 16).to_le());
                    words.add(1).write_volatile(base.to_le());
                    words.add(2).write_volatile(32u32.to_le());
                    words.add(3).write_volatile((base + 48).to_le());
                }
                tx.memory.sync(offset as usize, 16);
                barrier();
                Ok(())
            })
            .map_err(|_| Error::Access)??;
            self.write16(0x132c, next)
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        if self.state != State::Commands || !self.command_ring.pending() {
            return Err(Error::State);
        }
        let result = (|| {
            let index = self.read32(0x132c)?;
            if index == u32::MAX {
                return Err(Error::Gone);
            }
            if !self.command_ring.poll(index)? {
                return Ok(false);
            }
            barrier(); // exact terminal DMA receipt precedes CPU buffer reuse.
            Ok(true)
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        if self.state != State::Commands || self.command_ring.pending() {
            return Err(Error::State);
        }
        let result = (|| {
            self.park()?;
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn finish_radio(&mut self, gate: super::power_policy::Gate) -> Result<(), Error> {
        if self.device.id.device != 0xc822
            || gate.did() != 0xc822
            || self.state != State::Configuring
        {
            return Err(Error::State);
        }
        let result = (|| {
            gate.current().map_err(Error::Power)?;
            self.finish_mac()?;
            self.packet_gate = Some(gate);
            self.state = State::Calibrated;
            Ok(())
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn station_allowed(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Calibrated | State::Packets) {
            return Err(Error::State);
        }
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.command(self.state == State::Packets)?;
            self.check_packet_permission()
        })
        .map_err(|_| Error::Access)?
    }
    fn station_publication(&mut self) -> Result<super::publication::Publication, Error> {
        self.station_allowed()?;
        if self.state != State::Packets {
            return Err(Error::State);
        }
        Ok(super::publication::Publication::native(
            self.packet_gate.as_ref().ok_or(Error::State)?.clone(),
            self.device,
            self.cap,
        ))
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.station_allowed()?;
        Ok(self.packet_gate.as_ref().ok_or(Error::State)?.own())
    }
    fn station_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::station_profile::Grant>>, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        if gate.extension_request().is_none() {
            return Ok(None);
        }
        // Optional qualification lookup is pure. Missing/malformed assets
        // preserve the original fully qualified legacy connection profile.
        Ok(super::station_profile::Source::Registered
            .load(gate.clone())
            .ok())
    }
    fn station_bind_extension(
        &mut self,
        grant: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_extension(grant)?,
        );
        Ok(())
    }
    fn packet_profile(&mut self, profile: super::packet_format::DataProfile) -> Result<(), Error> {
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?.clone();
        if !gate.allows_profile(profile) {
            return Err(Error::Unsupported);
        }
        gate.invoke(|| self.configure_packet_profile(profile))
    }
    fn station_profile_readback(&mut self) -> Result<(), Error> {
        if let Some(g) = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::ht_grant)
        {
            return g.readback(|r| self.read32(r));
        }
        if let Some(indices) = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::c21_indices)
        {
            return super::radio8821c::operating_readback(|r| self.read32(r), indices);
        }
        let gains = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::cck_gains)
            .ok_or(Error::Unsupported)?;
        super::wmm::readback(|r| self.read32(r), gains)
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        if !matches!(self.state, State::Calibrated | State::Packets) || self.mailbox_pending {
            return Err(Error::State);
        }
        let state = self.read8(0x1cc)?;
        if state == 255 {
            return Err(Error::Gone);
        }
        Ok(state & (1 << self.mailbox_cursor) == 0)
    }
    fn station_ht_facts(&self) -> Option<super::ht::Facts> {
        self.packet_gate.as_ref()?.ht_facts()
    }
    fn station_rx_ba_extension(
        &mut self,
        base: alloc::sync::Arc<super::ht::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::rx_ba_power::Grant>>, Error> {
        self.station_allowed()?;
        Ok(super::rx_ba_power::Source::Registered.load(base).ok())
    }
    fn station_tx_ba_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::tx_ba_power::Grant>>, Error> {
        self.station_allowed()?;
        let base = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::tx_base)
            .ok_or(Error::State)?;
        Ok(super::tx_ba_power::Source::Registered.load(base).ok())
    }
    fn station_protection_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::protection::Grant>>, Error> {
        self.station_allowed()?;
        let base = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::protection_base)
            .ok_or(Error::State)?;
        Ok(super::protection::Source::Registered.load(base).ok())
    }
    fn station_bind_protection(
        &mut self,
        g: alloc::sync::Arc<super::protection::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_protection(g)?,
        );
        Ok(())
    }
    fn station_bind_continuation(
        &mut self,
        g: alloc::sync::Arc<super::qualification::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_continuation(g)?,
        );
        Ok(())
    }
    fn station_continuation(
        &mut self,
        kind: &'static super::qualification::Kind,
    ) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        Ok(super::qualification::Source::Registered
            .load(kind, gate)
            .ok())
    }
    fn station_continuation_request(
        &mut self,
        kind: &'static super::qualification::Kind,
    ) -> Result<super::ContinuationRequest, Error> {
        self.station_allowed()?;
        super::qualification::request(kind, self.packet_gate.as_ref().ok_or(Error::State)?)
    }
    fn station_gate(&mut self) -> Result<super::power_policy::Gate, Error> {
        self.station_allowed()?;
        self.packet_gate.clone().ok_or(Error::State)
    }
    fn station_rts_request(&mut self) -> Result<super::RtsRequest, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        if let Some(g) = gate.protection_grant() {
            return Ok(g.request());
        }
        super::protection::request(&super::protection::registered_base(gate)?)
    }
    fn station_bind_tx_ba(
        &mut self,
        g: alloc::sync::Arc<super::tx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_tx_ba(g)?,
        );
        Ok(())
    }
    fn station_tx_ba_request(&mut self) -> Result<super::TxBaRequest, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        if let Some(g) = gate.tx_grant() {
            return Ok(g.request());
        }
        let base = match gate.tx_base() {
            Some(b) => b,
            None => {
                let l = match gate.ht_base() {
                    Some(l) => l,
                    None => super::station_profile::Source::Registered.load(gate.clone())?,
                };
                let h = super::ht::Source::Registered.load(l)?;
                match super::rx_ba_power::Source::Registered.load(h.clone()).ok() {
                    Some(r) => super::tx_ba_power::Base::R(r),
                    None => super::tx_ba_power::Base::H(h),
                }
            }
        };
        super::tx_ba_power::request(&base)
    }
    fn packet_aggregation(
        &mut self,
        cfg: Option<super::packet_format::Aggregation>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        if cfg.is_some_and(|c| {
            self.packet_gate
                .as_ref()
                .and_then(super::power_policy::Gate::tx_grant)
                .is_none_or(|g| !g.allows(c))
        }) {
            return Err(Error::Prerequisite);
        }
        self.configure_packet_aggregation(cfg)
            .map_err(|_| Error::State)
    }
    fn packet_submit_batch(
        &mut self,
        b: &[alloc::vec::Vec<u8>],
    ) -> Result<alloc::vec::Vec<u64>, super::packet_core::Error> {
        self.submit_packet_batch(b)
    }
    fn station_bind_rx_ba(
        &mut self,
        g: alloc::sync::Arc<super::rx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_rx_ba(g)?,
        );
        Ok(())
    }
    fn station_rx_ba_request(&mut self) -> Result<super::RxBaRequest, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        let h = match gate.ht_grant() {
            Some(h) => h,
            None => {
                let base = match gate.ht_base() {
                    Some(b) => b,
                    None => super::station_profile::Source::Registered.load(gate.clone())?,
                };
                super::ht::Source::Registered.load(base)?
            }
        };
        super::rx_ba_power::request(&h)
    }
    fn station_ht_extension(
        &mut self,
        base: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::ht::Grant>>, Error> {
        self.station_allowed()?;
        Ok(super::ht::Source::Registered.load(base).ok())
    }
    fn station_bind_ht(&mut self, g: alloc::sync::Arc<super::ht::Grant>) -> Result<(), Error> {
        self.station_allowed()?;
        self.packet_gate = Some(self.packet_gate.as_ref().ok_or(Error::State)?.with_ht(g)?);
        Ok(())
    }
    fn station_ht_request(&mut self) -> Result<super::ht::Request, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        if let Some(g) = gate.ht_grant() {
            return Ok(g.request());
        }
        let base = match gate.ht_base() {
            Some(b) => b,
            None => super::station_profile::Source::Registered.load(gate.clone())?,
        };
        super::ht::request(&base)
    }
    fn mailbox_submit(&mut self, words: [u8; 8]) -> Result<(), Error> {
        if !self.mailbox_ready()? {
            return Err(Error::State);
        }
        let cleanup = words == [1, 0, 0, 0, 0, 0, 0, 0];
        if !cleanup {
            self.check_packet_permission()?;
        }
        self.mailbox_pending = true;
        let result = (|| {
            let ext = u32::from_le_bytes(words[4..].try_into().unwrap());
            let body = u32::from_le_bytes(words[..4].try_into().unwrap());
            self.write32(0x1f0 + u16::from(self.mailbox_cursor) * 4, ext)?;
            if !cleanup {
                self.check_packet_permission()?;
            }
            self.write32(0x1d0 + u16::from(self.mailbox_cursor) * 4, body)
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        if !matches!(self.state, State::Calibrated | State::Packets) || !self.mailbox_pending {
            return Err(Error::State);
        }
        let state = self.read8(0x1cc)?;
        if state == 255 {
            return Err(Error::Gone);
        }
        if state & (1 << self.mailbox_cursor) != 0 {
            return Ok(false);
        }
        barrier();
        self.mailbox_pending = false;
        self.mailbox_cursor = (self.mailbox_cursor + 1) % 4;
        Ok(true)
    }
    fn mailbox_pending(&self) -> bool {
        self.mailbox_pending
    }
    fn packet_prepare(
        &mut self,
        own: [u8; 6],
        mac_id: u8,
    ) -> Result<(), super::packet_core::Error> {
        self.prepare_packets(own, mac_id)
    }
    fn packet_start(&mut self) -> Result<(), super::packet_core::Error> {
        self.start_packets()
    }
    fn packet_ready(&self) -> bool {
        self.packets_ready()
    }
    fn packet_submit(
        &mut self,
        frame: &[u8],
        report: bool,
    ) -> Result<u64, super::packet_core::Error> {
        self.submit_packet(frame, report)
    }
    fn packet_poll(&mut self) -> Result<super::packet_core::Step, super::packet_core::Error> {
        self.poll_packets()
    }
    fn packet_stop(&mut self) -> Result<(), super::packet_core::Error> {
        self.stop_packets()
    }
    fn parked_cpu<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        if self.state != State::Configuring {
            return Err(Error::State);
        }
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.command(false)?;
            operation()
        })
        .map_err(|_| Error::Access)?
    }
}
impl Native {
    fn check_packet_permission(&self) -> Result<(), Error> {
        self.packet_gate
            .as_ref()
            .ok_or(Error::State)?
            .current()
            .map_err(Error::Power)
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if self.published {
            core::mem::forget(core::mem::take(&mut self.tx));
            core::mem::forget(self.rx.take());
            core::mem::forget(core::mem::take(&mut self.buffers));
            core::mem::forget(self.command_buffer.take());
        }
    }
}
pub(super) type Transport = Backend<Native, Coherent>;
/// # Safety
/// Same exact-device/exclusive post-cold-power contract as Native::new.
pub(super) unsafe fn allocate(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
) -> Result<Transport, Error> {
    // SAFETY: caller's same-device post-cold-power/exclusive contract.
    let native = unsafe { Native::new(device, cap, mmio) }?;
    let ring = Coherent(native.allocate(16)?);
    let frame = Coherent(native.allocate(48 + 4096)?);
    Backend::new(native, ring, frame, 0)
}
