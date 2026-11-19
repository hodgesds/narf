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
#[path = "pci_swap.rs"]
mod swap;
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
    /// `rtw_wow_swap_fw` window (`pci_swap.rs`): packet producers closed,
    /// BME/CR/mappings live, firmware page/H2C/mailbox channels open.
    Swap,
    /// `rtw_hci_stop`: ring pointers reset, BME/CR/mappings retained;
    /// only `restart_packets` leaves it (or a failure -> Terminal).
    Halted,
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
    /// Station TX grant on a passive-only (DFS / NO_IR) 5GHz primary: the
    /// station admitted it under its `narf_wireless::reg::witness` beacon
    /// witness taken under exactly this policy snapshot. A retune to any
    /// other primary drops it.
    passive_tx: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    mailbox_cursor: u8,
    mailbox_pending: bool,
    tracking_maintenance: bool,
    tracking_sequence: u16,
    /// Target primary while a native retune owns the radio. New TX
    /// publication is refused and hardware TX stays paused until finish;
    /// cancellation leaves it set (fail closed, non-Ready).
    retune: Option<u8>,
    /// `station_width_begin` started the current retune (N2xB / N2xV
    /// widening).
    widening: bool,
    /// The N2xB 40MHz or N2xV 80MHz program is committed
    /// (`station_retune_finish` after widening); HT readbacks then expect
    /// the HT40 / VHT80 selection.
    wide: bool,
    /// State `halt_packets` left; `restart_packets` returns to it.
    halted_from: Option<State>,
    /// Committed operating primary and completed retune programs.
    channel: u8,
    channel_epoch: u64,
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
            || !matches!(device.id.device, 0xc821 | 0xc822 | 0xb822)
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
            passive_tx: None,
            mailbox_cursor: 0,
            mailbox_pending: false,
            tracking_maintenance: false,
            tracking_sequence: 3,
            retune: None,
            widening: false,
            wide: false,
            halted_from: None,
            channel: 1,
            channel_epoch: 1,
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
                | State::Swap
                | State::Halted
        ) {
            return Err(Error::State);
        }
        let active = matches!(
            self.state,
            State::Active | State::Commands | State::Packets | State::Swap | State::Halted
        );
        let gate = self.packet_gate.clone().map(|g| {
            if self.tracking_maintenance {
                g.without_power_tracking()
            } else {
                g
            }
        });
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
    /// Also the RTL8822BE (`0xb822`) `N2BQ` calibration envelope: the same
    /// closed-MAC/parked-PCI state machine around one firmware IQK program.
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        let did = self.device.id.device;
        if !matches!(did, 0xc821 | 0xb822) || self.state != State::PhyTablesPrepared {
            return Err(Error::State);
        }
        if self.mmio.len < if did == 0xb822 { 0x5000 } else { 0x2c00 } {
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
        if !matches!(self.device.id.device, 0xc821 | 0xb822)
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
        // C21 N21P and B22 N2BP parked operating power share this gate.
        if !matches!(self.device.id.device, 0xc821 | 0xb822)
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
        if !matches!(self.device.id.device, 0xc821 | 0xb822) || self.state != State::Configuring {
            return Err(Error::State);
        }
        self.finish_mac()?;
        self.state = State::Operating8821cPrepared;
        Ok(())
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        // C21 `radio8821c::prepare_station` and B22 `radio8822b::prepare_station`.
        if !matches!(self.device.id.device, 0xc821 | 0xb822)
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
        if !matches!(self.device.id.device, 0xc821 | 0xb822)
            || self.state != State::Configuring
            || gate.did() != self.device.id.device
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
            || matches!(self.device.id.device, 0xc821 | 0xb822)
                && self.state == State::Calibrating8821c)
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
        let retune = self.state == State::Packets && self.retune.is_some();
        let mission = self.state == State::Packets && self.tracking_maintenance || retune;
        let expected = if retune || self.device.id.device == 0xb822 {
            self.retune_iqk_packet()
        } else {
            super::command::iqk8821c_associated(self.tracking_sequence)
        };
        // The swap window carries the swapped image's general/phydm info
        // (`rtw_wow_swap_fw`) on the same retained H2C ring.
        // Inside the swap window only the swapped image's
        // `rtw_fw_send_general_info` (13) / `rtw_fw_send_phydm_info` (17)
        // packets may run, each carrying Linux's running `h2c.seq`
        // (`rtw_fw_send_h2c_packet`), reset by the download.
        let swap = self.state == State::Swap;
        let swap_ok = !swap
            || matches!(u16::from_le_bytes([packet[2], packet[3]]), 13 | 17)
                && packet[..2] == [1, 255]
                && u16::from_le_bytes([packet[6], packet[7]]) == self.tracking_sequence;
        if (!matches!(self.state, State::Commands | State::Swap) && !mission)
            || self.command_ring.pending()
            || mission && *packet != expected
            || !swap_ok
        {
            return Err(Error::State);
        }
        if mission || swap {
            self.tracking_sequence = self.tracking_sequence.checked_add(1).ok_or(Error::State)?;
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
        if (!matches!(self.state, State::Commands | State::Swap)
            && !(self.state == State::Packets
                && (self.tracking_maintenance || self.retune.is_some())))
            || !self.command_ring.pending()
        {
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
        let cap = self.cap;
        crate::rtw88::pci_park::invoke(&cap, || {
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
        if let Some(w) = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::power_tracking)
        {
            super::firmware_transport::ready_now(
                w.readback(super::firmware_transport::Sampled(|r| self.read32(r))),
            )?;
            w.temperature(((self.read32(0x2908)? >> 10) & 63) as u8)?;
        }
        if let Some(g) = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::ht_grant)
        {
            let wide = self.committed_wide()?;
            return super::firmware_transport::ready_now(g.readback_at(
                super::firmware_transport::Sampled(|r| self.read32(r)),
                wide.as_ref(),
            ));
        }
        if let Some((indices, channel)) = self
            .packet_gate
            .as_ref()
            .and_then(|g| Some((g.c21_indices()?, g.channel())))
        {
            return super::firmware_transport::ready_now(super::radio8821c::operating_readback(
                super::firmware_transport::Sampled(|r| self.read32(r)),
                indices,
                channel,
            ));
        }
        if let Some((ofdm, diffs)) = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::ofdm5)
        {
            return super::firmware_transport::ready_now(super::wmm::readback5(
                super::firmware_transport::Sampled(|r| self.read32(r)),
                ofdm,
                diffs,
            ));
        }
        let gains = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::cck_gains)
            .ok_or(Error::Unsupported)?;
        super::firmware_transport::ready_now(super::wmm::readback(
            super::firmware_transport::Sampled(|r| self.read32(r)),
            gains,
        ))
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        if !matches!(self.state, State::Calibrated | State::Packets | State::Swap)
            || self.mailbox_pending
        {
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
    fn station_power_tracking_request(
        &mut self,
        t: u8,
        dm: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> Result<super::PowerTrackingRequest, Error> {
        self.station_allowed()?;
        let gate = self.packet_gate.clone().ok_or(Error::State)?;
        if let Some(g) = gate.power_tracking() {
            return Ok(g.request());
        }
        if self.read32(0xc94)? & 0x7e != 0 {
            return Err(Error::Prerequisite);
        }
        let scale = (self.read32(0xc1c)? >> 21) as u16;
        super::tracking8821c::request(&gate, t, scale, dm.as_ref())
    }
    fn station_power_tracking_extension(
        &mut self,
        thermal: u8,
        dm: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> Result<Option<alloc::sync::Arc<super::tracking8821c::Grant>>, Error> {
        self.station_allowed()?;
        if self.device.id.device != 0xc821 {
            return Ok(None);
        }
        let gate = self.packet_gate.clone().ok_or(Error::State)?;
        if gate.ht_grant().is_none() || gate.power_tracking().is_some() {
            return Ok(None);
        }
        if self.read32(0xc94)? & 0x7e != 0 {
            return Ok(None);
        }
        let swing = (self.read32(0xc1c)? >> 21) as u16;
        // Optional authenticated continuation: absent/unqualified W preserves
        // the original static profile and performs no emitting mutation.
        Ok(super::tracking8821c::Source::Registered
            .load(gate, thermal, swing, dm)
            .ok())
    }
    fn station_bind_power_tracking(
        &mut self,
        g: alloc::sync::Arc<super::tracking8821c::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        super::firmware_transport::ready_now(
            g.readback(super::firmware_transport::Sampled(|r| self.read32(r))),
        )?;
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_power_tracking(g)?,
        );
        Ok(())
    }
    fn station_power_tracking_begin(
        &mut self,
        g: &alloc::sync::Arc<super::tracking8821c::Grant>,
        restore: bool,
    ) -> Result<bool, Error> {
        if self.state != State::Packets
            || self.tracking_maintenance
            || self.mailbox_pending
            || self.command_ring.pending()
            || self
                .packet_gate
                .as_ref()
                .and_then(super::power_policy::Gate::power_tracking)
                .as_ref()
                .is_none_or(|w| !alloc::sync::Arc::ptr_eq(w, g))
        {
            return Err(Error::State);
        }
        // Only this original exclusive owner may inspect/restore a revoked W.
        // Packet/copy paths keep the unchanged W-aware Gate and cannot use it.
        self.tracking_maintenance = true;
        let result = (|| {
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .invoke_base(|| Ok(()))?;
            super::firmware_transport::ready_now(
                g.readback(super::firmware_transport::Sampled(|r| self.read32(r))),
            )?;
            if !self.station_power_tracking_quiet()? {
                return Ok(false);
            }
            if restore {
                g.begin_restore()?;
            } else {
                g.begin()?;
            }
            Ok(true)
        })();
        if !matches!(result, Ok(true)) {
            self.tracking_maintenance = false;
        }
        result
    }
    fn station_power_tracking_quiet(&mut self) -> Result<bool, Error> {
        if !self.tracking_maintenance || self.mailbox_pending || self.command_ring.pending() {
            return Err(Error::State);
        }
        if !self
            .with_packet(|core, port| {
                core.maintenance_quiet(|r| super::packet_core::Port::index(port, r))
            })
            .map_err(|_| Error::State)?
        {
            return Ok(false);
        }
        for r in super::dma_stop::TX_INDEX {
            let v = self.read32(r)?;
            if v == u32::MAX {
                return Err(Error::Gone);
            }
            if v & 0xfff != (v >> 16) & 0xfff {
                return Ok(false);
            }
        }
        if self.read16(0x10c)? != 0xc5a0 {
            return Err(Error::Prerequisite);
        }
        for (r, n) in [0x230, 0x234, 0x238, 0x23c]
            .into_iter()
            .zip(self.fifo_pages())
        {
            if self.read16(r)? != n {
                return Err(Error::Prerequisite);
            }
            if self.read16(r + 2)? != n {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn station_power_tracking_iqk(&mut self) -> Result<(), Error> {
        if !self.tracking_maintenance {
            return Err(Error::State);
        }
        let g = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::power_tracking)
            .ok_or(Error::State)?;
        let packet = super::command::iqk8821c_associated(self.tracking_sequence);
        g.authority(|| self.submit_h2c(&packet))
    }
    fn station_power_tracking_finish(
        &mut self,
        p: Option<super::tracking8821c::Program>,
    ) -> Result<(), Error> {
        if !self.tracking_maintenance
            || self.command_ring.pending()
            || !self.station_power_tracking_quiet()?
            || self.read8(0x522)? != 255
            || self.read32(super::dma_stop::RXPKT_NUM)?
                & (super::dma_stop::RXDMA_IDLE | super::dma_stop::RW_RELEASE)
                != (super::dma_stop::RXDMA_IDLE | super::dma_stop::RW_RELEASE)
        {
            return Err(Error::Prerequisite);
        }
        let gate = self.packet_gate.clone().ok_or(Error::State)?;
        let g = gate.power_tracking().ok_or(Error::State)?;
        let actual = p.unwrap_or_else(|| g.initial_program());
        super::firmware_transport::ready_now(super::tracking8821c::Grant::read_program(
            actual,
            &mut super::firmware_transport::Sampled(|r| self.read32(r)),
        ))?;
        let ht = gate.ht_grant().ok_or(Error::State)?;
        super::firmware_transport::ready_now(
            ht.readback(super::firmware_transport::Sampled(|r| self.read32(r))),
        )?;
        if p.is_some() {
            g.temperature(((self.read32(0x2908)? >> 10) & 63) as u8)?;
        }
        let rx = self.read32(super::dma_stop::RXPKT_NUM)?;
        self.write32(
            super::dma_stop::RXPKT_NUM,
            rx & !super::dma_stop::RW_RELEASE,
        )?;
        self.write8(0x522, 0)?;
        if self.read32(super::dma_stop::RXPKT_NUM)? & super::dma_stop::RW_RELEASE != 0
            || self.read8(0x522)? != 0
        {
            return Err(Error::Prerequisite);
        }
        match p {
            Some(p) => g.commit(p)?,
            None => {
                g.retire();
                self.packet_gate = Some(gate.without_power_tracking());
            }
        }
        self.tracking_maintenance = false;
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
    fn station_channel(&self) -> (u8, u64) {
        (self.channel, self.channel_epoch)
    }
    fn station_band5_capability(
        &mut self,
        channel: u8,
    ) -> Result<Option<super::vht::Band5Capability>, Error> {
        self.station_allowed()?;
        let base = self.packet_gate.clone().ok_or(Error::State)?;
        super::vht::band5_capability(&base, channel, |c| self.station_channel_grant(c))
    }
    fn station_channel_grant(
        &mut self,
        channel: u8,
    ) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error> {
        self.station_allowed()?;
        let kind = super::channel_policy::kind(channel).ok_or(Error::Unsupported)?;
        let base = self
            .packet_gate
            .as_ref()
            .ok_or(Error::State)?
            .without_channel();
        // Unprovisioned or unadmitted records leave the channel unavailable.
        Ok(super::qualification::Source::Registered
            .load(kind, &base)
            .ok()
            .filter(|g| base.with_channel(g.clone()).is_ok()))
    }
    fn station_regulatory(
        &self,
    ) -> Result<Option<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>>, Error> {
        // The installed shared snapshot; its `Arc` identity scopes the
        // station's beacon witnesses and the passive TX grant.
        Ok(narf_wireless::reg::db::snapshot())
    }
    fn station_passive_tx(
        &mut self,
        grant: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    ) -> Result<(), Error> {
        if let Some((primary, _)) = &grant {
            if self.retune.is_some() || *primary != self.channel {
                return Err(Error::State);
            }
        }
        self.passive_tx = grant;
        Ok(())
    }
    fn station_retune_begin(
        &mut self,
        channel: u8,
        grant: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> Result<bool, Error> {
        if self.state != State::Packets
            || self.tracking_maintenance
            || self.mailbox_pending
            || self.command_ring.pending()
            || self.retune.is_some_and(|c| c != channel)
            || self.widening
            || (channel == 1) != grant.is_none()
        {
            return Err(Error::State);
        }
        if self.retune.is_none() {
            if self.passive_tx.as_ref().is_some_and(|(p, _)| *p != channel) {
                self.passive_tx = None;
            }
            let current = self.packet_gate.as_ref().ok_or(Error::State)?;
            if !current.base_only() {
                return Err(Error::State);
            }
            let base = current.without_channel();
            let target = match grant {
                Some(g) => base.with_channel(g)?,
                None => base,
            };
            if target.channel() != channel {
                return Err(Error::State);
            }
            target.current().map_err(Error::Power)?;
            // From here no new TX is published; every retune write runs under
            // the target channel's gate (its regulatory span and the base).
            self.retune = Some(channel);
            self.packet_gate = Some(target);
            self.with_packet(|core, _| {
                core.set_operating_channel(channel);
                Ok(())
            })
            .map_err(|_| Error::State)?;
            // REG_TXPAUSE: hold every queue across the RF/BB rewrite.
            self.write8(0x522, 0xff)?;
        }
        if self.read8(0x522)? != 0xff {
            return Err(Error::Prerequisite);
        }
        self.retune_quiet()
    }
    fn station_width_begin(&mut self) -> Result<bool, Error> {
        if self.state != State::Packets
            || self.tracking_maintenance
            || self.mailbox_pending
            || self.command_ring.pending()
            || self.retune.is_some_and(|c| c != self.channel)
        {
            return Err(Error::State);
        }
        if self.retune.is_none() {
            if self.wide {
                return Err(Error::State);
            }
            let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
            // N2xV (80MHz, RTW bandwidth code 2) or N2xB (40MHz, code 1).
            let (primary, width) = match (gate.vht_record(), gate.ht40_record()) {
                (Some(v), None) => (v.primary, 2),
                (None, Some(r)) => (r.primary, 1),
                _ => return Err(Error::State),
            };
            if primary != self.channel || gate.channel() != self.channel {
                return Err(Error::State);
            }
            gate.current().map_err(Error::Power)?;
            // From here no new TX is published (the retune owner), and RX PHY
            // admission follows `query_phy_status_page1` at BW40 / BW80.
            self.retune = Some(self.channel);
            self.widening = true;
            self.with_packet(|core, _| {
                core.set_operating_width(width);
                Ok(())
            })
            .map_err(|_| Error::State)?;
            self.write8(0x522, 0xff)?;
        }
        if self.read8(0x522)? != 0xff {
            return Err(Error::Prerequisite);
        }
        self.retune_quiet()
    }
    fn station_retune_iqk(&mut self) -> Result<(), Error> {
        if self.retune.is_none() {
            return Err(Error::State);
        }
        let packet = self.retune_iqk_packet();
        self.submit_h2c(&packet)
    }
    /// RTL8822BE associated `rtw8822b_do_iqk` maintenance (`N2BW`). Begin
    /// holds every queue (TXPAUSE 0xff) and requests the RXDMA park
    /// (`wow.c::rtw_wow_rx_dma_stop` `BIT_RW_RELEASE`); Quiet reports the
    /// retune receipts plus `BIT_RXDMA_IDLE`; Submit sends the
    /// `rtw8822b_do_iqk` H2C (clear 0, segment 0) on the retained ring;
    /// Finish, after a consumed command and still-quiet hardware, releases
    /// RXDMA and TXPAUSE with readback.
    fn station_b22_iqk(&mut self, step: super::tracking8822b::Step) -> Result<bool, Error> {
        use super::dma_stop::{RW_RELEASE, RXPKT_NUM};
        use super::tracking8822b::Step;
        if self.device.id.device != 0xb822 || self.state != State::Packets {
            return Err(Error::State);
        }
        match step {
            Step::Begin => {
                if self.tracking_maintenance
                    || self.retune.is_some()
                    || self.widening
                    || self.mailbox_pending
                    || self.command_ring.pending()
                {
                    return Err(Error::State);
                }
                let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
                if gate.did() != 0xb822 {
                    return Err(Error::State);
                }
                gate.current().map_err(Error::Power)?;
                if self.read8(0x522)? != 0 || self.read32(RXPKT_NUM)? & RW_RELEASE != 0 {
                    return Err(Error::Prerequisite);
                }
                self.tracking_maintenance = true;
                self.write8(0x522, 0xff)?;
                let rx = self.read32(RXPKT_NUM)?;
                self.write32(RXPKT_NUM, rx | RW_RELEASE)?;
                self.b22_iqk_quiet()
            }
            Step::Quiet => {
                if !self.tracking_maintenance {
                    return Err(Error::State);
                }
                self.b22_iqk_quiet()
            }
            Step::Submit => {
                if !self.tracking_maintenance || !self.b22_iqk_quiet()? {
                    return Err(Error::State);
                }
                let packet = self.retune_iqk_packet();
                self.submit_h2c(&packet)?;
                Ok(true)
            }
            Step::Finish => {
                if !self.tracking_maintenance
                    || self.command_ring.pending()
                    || self.read8(0x522)? != 0xff
                    || !self.b22_iqk_quiet()?
                {
                    return Err(Error::Prerequisite);
                }
                self.packet_gate
                    .as_ref()
                    .ok_or(Error::State)?
                    .current()
                    .map_err(Error::Power)?;
                let rx = self.read32(RXPKT_NUM)?;
                self.write32(RXPKT_NUM, rx & !RW_RELEASE)?;
                self.write8(0x522, 0)?;
                if self.read32(RXPKT_NUM)? & RW_RELEASE != 0 || self.read8(0x522)? != 0 {
                    return Err(Error::Prerequisite);
                }
                self.tracking_maintenance = false;
                Ok(true)
            }
        }
    }
    fn station_retune_finish(&mut self, channel: u8) -> Result<u64, Error> {
        if self.retune != Some(channel)
            || self.command_ring.pending()
            || self.read8(0x522)? != 0xff
            || !self.retune_quiet()?
        {
            return Err(Error::State);
        }
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        if gate.channel() != channel {
            return Err(Error::State);
        }
        gate.current().map_err(Error::Power)?;
        self.write8(0x522, 0)?;
        if self.read8(0x522)? != 0 {
            return Err(Error::Prerequisite);
        }
        self.channel = channel;
        self.channel_epoch = self.channel_epoch.checked_add(1).ok_or(Error::State)?;
        self.retune = None;
        if core::mem::take(&mut self.widening) {
            self.wide = true;
        }
        Ok(self.channel_epoch)
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
    fn station_bind_host(
        &mut self,
        host: narf_net::native_emission::Lifetime,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        if !self.packets_ready() || self.mailbox_pending || self.command_ring.pending() {
            return Err(Error::State);
        }
        self.packet_gate = Some(
            self.packet_gate
                .as_ref()
                .ok_or(Error::State)?
                .with_host(host)?,
        );
        Ok(())
    }
    fn station_ht_program_quiet(&mut self) -> Result<bool, Error> {
        self.station_allowed()?;
        if self.state != State::Packets || self.mailbox_pending || self.command_ring.pending() {
            return Ok(false);
        }
        if !self
            .with_packet(|core, port| {
                core.transmit_quiet(|r| super::packet_core::Port::index(port, r))
            })
            .map_err(|_| Error::State)?
        {
            return Ok(false);
        }
        for r in super::dma_stop::TX_INDEX {
            let v = self.read32(r)?;
            if v == u32::MAX {
                return Err(Error::Gone);
            }
            if v & 0xfff != (v >> 16) & 0xfff {
                return Ok(false);
            }
        }
        if self.read16(0x10c)? != 0xc5a0 {
            return Err(Error::Prerequisite);
        }
        for (r, n) in [0x230, 0x234, 0x238, 0x23c]
            .into_iter()
            .zip(self.fifo_pages())
        {
            if self.read16(r)? != n {
                return Err(Error::Prerequisite);
            }
            if self.read16(r + 2)? != n {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn station_ps_rx_quiet(&mut self) -> Result<bool, Error> {
        if !self.station_ht_program_quiet()? {
            return Ok(false);
        }
        self.with_packet(|core, port| {
            core.maintenance_quiet(|r| super::packet_core::Port::index(port, r))
        })
        .map_err(|_| Error::State)
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
        if self.retune.is_some() || !self.mailbox_ready()? {
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
    fn ps_mailbox_submit(
        &mut self,
        words: [u8; 8],
        scope: &mut super::firmware_transport::PsScope<'_>,
    ) -> Result<super::firmware_transport::PsSubmit, Error> {
        use super::firmware_transport::PsSubmit;
        // Linux fw.c rtw_fw_send_h2c_command: HMETFR box free, then
        // HMEBOX_EXT (w1), then HMEBOX (w0). Firmware latches the command on
        // the low-word write only, so the extended staging alone is inert.
        if self.state != State::Packets || self.retune.is_some() || !self.mailbox_ready()? {
            return Err(Error::State);
        }
        self.check_packet_permission()?;
        let cursor = self.mailbox_cursor;
        let bit = 1u8 << cursor;
        let ext = u32::from_le_bytes(words[4..].try_into().unwrap());
        let body = u32::from_le_bytes(words[..4].try_into().unwrap());
        self.mailbox_pending = true;
        let mut published = false;
        let result = self
            .write32(0x1f0 + u16::from(cursor) * 4, ext)
            .and_then(|()| {
                // Original PS source, actual native Core RX-prefix receipt and
                // TX/command quiescence are rechecked after staging, immediately
                // before the publishing low word. New peer-loss/key/control RX in
                // this gap leaves the command unissued.
                scope(&mut || {
                    if self.state != State::Packets || self.command_ring.pending() {
                        return Err(Error::State);
                    }
                    let state = self.read8(0x1cc)?;
                    if state == 255 {
                        return Err(Error::Gone);
                    }
                    if state & bit != 0 {
                        return Err(Error::State);
                    }
                    if !self
                        .with_packet(|core, port| {
                            core.maintenance_quiet(|r| super::packet_core::Port::index(port, r))
                        })
                        .map_err(|_| Error::State)?
                    {
                        return Ok(false);
                    }
                    self.check_packet_permission()?;
                    published = true;
                    self.write32(0x1d0 + u16::from(cursor) * 4, body)?;
                    Ok(true)
                })
            });
        match result {
            Ok(true) if published => Ok(PsSubmit::Issued),
            Ok(false) if !published => {
                self.mailbox_pending = false;
                Ok(PsSubmit::Unissued)
            }
            Err(e) if !published => {
                self.mailbox_pending = false;
                Err(e)
            }
            // Low word written (or the scope misreported): ownership of the
            // mailbox is ambiguous; never retry it.
            Ok(_) => {
                self.state = State::Terminal;
                Err(Error::State)
            }
            Err(e) => {
                self.state = State::Terminal;
                Err(e)
            }
        }
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        if !matches!(self.state, State::Calibrated | State::Packets | State::Swap)
            || !self.mailbox_pending
        {
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
    fn packet_scan_address(
        &mut self,
        address: Option<[u8; 6]>,
    ) -> Result<(), super::packet_core::Error> {
        self.scan_packet_address(address)
    }
    fn packet_poll(&mut self) -> Result<super::packet_core::Step, super::packet_core::Error> {
        self.poll_packets()
    }
    fn packet_stop(&mut self) -> Result<(), super::packet_core::Error> {
        self.stop_packets()
    }
    async fn quiesce_dma(&mut self) -> Result<(), Error> {
        self.quiesce().await
    }
    fn hci_stop(&mut self) -> Result<(), Error> {
        self.halt_packets()
    }
    fn hci_restart(&mut self) -> Result<(), Error> {
        self.restart_packets()
    }
    fn claim_swap(&mut self) -> Result<(), Error> {
        self.enter_swap()
    }
    fn finish_swap(&mut self) -> Result<(), Error> {
        self.complete_swap()
    }
    fn end_swap(&mut self) -> Result<(), Error> {
        self.leave_swap()
    }
    fn dma_reclaimable(&self) -> bool {
        !self.published
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
/// Teardown register view over the exact BAR under current PCI authority;
/// usable after `Port::stop` made the owner Terminal.
struct Teardown<'a>(&'a mut Native);
#[async_trait::async_trait]
impl super::dma_stop::Quiesce for Teardown<'_> {
    fn bus_master_closed(&mut self) -> Result<bool, Error> {
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        let native = &*self.0;
        let command = crate::rtw88::pci_park::invoke(&native.cap, || {
            narf_bus::pci::read_command(&native.cap, &native.device).map_err(|_| Error::Access)
        })
        .map_err(|_| Error::Access)??;
        if command == u16::MAX {
            return Err(Error::Gone);
        }
        Ok(command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) == MEM_SPACE | INTX_DISABLE)
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        self.0.teardown(reg, 1, |mmio| {
            // SAFETY: complete byte within the retained BAR, inside invoke.
            unsafe { mmio.read8(u64::from(reg)) }
        })
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.0.teardown(reg, 4, |mmio| {
            // SAFETY: complete aligned dword within the retained BAR.
            unsafe { mmio.read32(u64::from(reg)) }
        })
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.0.teardown(reg, 4, |mmio| {
            // SAFETY: complete aligned dword within the retained BAR.
            unsafe { mmio.write32(u64::from(reg), value) }
        })
    }
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
}
impl Native {
    fn teardown<T>(
        &self,
        reg: u16,
        width: usize,
        operation: impl FnOnce(MmioRegion) -> T,
    ) -> Result<T, Error> {
        if self.state != State::Terminal
            || usize::from(reg) % width != 0
            || u64::from(reg) + width as u64 > self.mmio.len
        {
            return Err(Error::State);
        }
        crate::rtw88::pci_park::invoke(&self.cap, || operation(self.mmio))
            .map_err(|_| Error::Access)
    }
    /// Linux `rtw_pci_stop` (HIMRs zero, TXPAUSE, CR DMA gates, BME off)
    /// followed by the DMA idle proof. Every exit before success leaves
    /// all rings, RX buffers, H2C and packet buffers retained.
    async fn quiesce(&mut self) -> Result<(), Error> {
        if !self.published {
            return Err(Error::State);
        }
        let stopped = match self.packet.take() {
            Some(mut core) => {
                let result = core.stop(self);
                self.packet = Some(core);
                result
            }
            None => packet::stop_native(self),
        };
        self.state = State::Terminal;
        stopped.map_err(|_| Error::Access)?;
        super::dma_stop::prove(&mut Teardown(self)).await?;
        if let Some(core) = self.packet.as_mut() {
            core.release().map_err(|_| Error::State)?;
        }
        self.published = false;
        Ok(())
    }
    /// Linux pre-association IQK H2C for this chip during a retune:
    /// `rtw8822c_do_iqk` clear=1, `rtw8821c_do_iqk` clear=0/segment=0.
    fn retune_iqk_packet(&self) -> [u8; 32] {
        if self.device.id.device == 0xc822 {
            super::command::iqk(self.tracking_sequence)
        } else {
            super::command::iqk8821c(self.tracking_sequence)
        }
    }
    /// `__priority_queue_cfg` FIFOPAGE_INFO_1..4 (hq/lq/nq/exq) as
    /// `mac::prepare_on` programmed them for this PCI chip: C21
    /// `page_table_8821c[1]` 16/16/16/14, C22/B22 `page_table_8822{c,b}[1]`
    /// 64/64/64/64. Quiet receipts compare the configured and free counts
    /// against these.
    fn fifo_pages(&self) -> [u16; 4] {
        if self.device.id.device == 0xc821 {
            [16, 16, 16, 14]
        } else {
            [64; 4]
        }
    }
    /// B22 associated IQK quiet: TXPAUSE held, the retune receipts and the
    /// parked RXDMA idle.
    fn b22_iqk_quiet(&mut self) -> Result<bool, Error> {
        use super::dma_stop::{RW_RELEASE, RXDMA_IDLE, RXPKT_NUM};
        if self.read8(0x522)? != 0xff || !self.retune_quiet()? {
            return Ok(false);
        }
        let rx = self.read32(RXPKT_NUM)?;
        if rx == u32::MAX {
            return Err(Error::Gone);
        }
        if rx & RW_RELEASE == 0 {
            return Err(Error::Prerequisite);
        }
        Ok(rx & RXDMA_IDLE != 0)
    }
    /// Every TX ring and the packet core have retired and the MAC queues
    /// report their reserved pages free (same receipts as tracking quiet).
    fn retune_quiet(&mut self) -> Result<bool, Error> {
        if !self
            .with_packet(|core, port| {
                core.maintenance_quiet(|r| super::packet_core::Port::index(port, r))
            })
            .map_err(|_| Error::State)?
        {
            return Ok(false);
        }
        for r in super::dma_stop::TX_INDEX {
            let v = self.read32(r)?;
            if v == u32::MAX {
                return Err(Error::Gone);
            }
            if v & 0xfff != (v >> 16) & 0xfff {
                return Ok(false);
            }
        }
        if self.read16(0x10c)? != 0xc5a0 {
            return Err(Error::Prerequisite);
        }
        for (r, n) in [0x230, 0x234, 0x238, 0x23c]
            .into_iter()
            .zip(self.fifo_pages())
        {
            if self.read16(r)? != n {
                return Err(Error::Prerequisite);
            }
            if self.read16(r + 2)? != n {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// The N2xB (40MHz) or N2xV (80MHz) record whose program is committed
    /// in hardware, if any.
    fn committed_wide(&self) -> Result<Option<super::ht::Wide>, Error> {
        if !self.wide {
            return Ok(None);
        }
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        match (gate.vht_record(), gate.ht40_record()) {
            (Some(v), None) => Ok(Some(super::ht::Wide::Eighty(v))),
            (None, Some(r)) => Ok(Some(super::ht::Wide::Forty(r))),
            _ => Err(Error::State),
        }
    }
    pub(super) fn retune_active(&self) -> bool {
        self.retune.is_some()
    }
    /// Frame-TX regulatory rule on top of `check_packet_permission`: on a
    /// passive-only (DFS / NO_IR) committed primary a frame is published
    /// only under the station's passive TX grant for this exact primary and
    /// current policy snapshot (mac80211 never probes there; a station
    /// transmits only to an AP whose Beacon it heard). RX is unaffected.
    pub(super) fn passive_tx_allowed(&self) -> Result<(), Error> {
        let gate = self.packet_gate.as_ref().ok_or(Error::State)?;
        // Without an installed policy the gate's own live check (`Core::submit`
        // -> `transmit_allowed`) already refuses every bound N2xO record.
        let Some(policy) = narf_wireless::reg::db::snapshot() else {
            return Ok(());
        };
        if !gate.passive_in(&policy).map_err(Error::Power)? {
            return Ok(());
        }
        match &self.passive_tx {
            Some((primary, granted))
                if *primary == gate.channel()
                    && *primary == self.channel
                    && alloc::sync::Arc::ptr_eq(granted, &policy) =>
            {
                Ok(())
            }
            _ => Err(Error::Power(super::power_policy::Error::Policy)),
        }
    }
    fn check_packet_permission(&mut self) -> Result<(), Error> {
        if let Some(g) = self
            .packet_gate
            .as_ref()
            .and_then(super::power_policy::Gate::power_tracking)
        {
            super::firmware_transport::ready_now(
                g.readback(super::firmware_transport::Sampled(|r| self.read32(r))),
            )?;
            g.temperature(((self.read32(0x2908)? >> 10) & 63) as u8)?;
        }
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
