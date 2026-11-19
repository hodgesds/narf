// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained RTL8852B/RTL8852C polling RXQ/RPQ ownership. No IRQ or NIC
//! publication.
use super::{
    dma::{addr_set_for_chip, RxRingRegs},
    mac::ChipId,
    pcie::Interface,
    power::{self, Io},
    rx_packet::{self, Assembler, Event, BUFFER_SIZE},
};
use alloc::vec::Vec;
use narf_io::{alloc_coherent_masked, DmaBuffer};
use narf_lib::id::DomainId;

const DMA_MASK: u64 = (1 << 40) - 1;
// Match Linux's negotiated device limit, independently of the40-bit BD format.
const DEVICE_DMA_MASK: u64 = (1 << 36) - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    Memory,
    Index,
    Descriptor(rx_packet::Error),
    Terminal,
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
        Self::Register(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    New,
    Publishing,
    Polling,
    Terminal,
}
struct Ring {
    regs: RxRingRegs,
    descriptors: Option<DmaBuffer>,
    buffers: Vec<DmaBuffer>,
    assembler: Assembler,
    wp: u16,
}
impl Ring {
    fn allocate(regs: RxRingRegs, depth: u16, chip: ChipId) -> Result<Self, Error> {
        let descriptors =
            alloc_coherent_masked(usize::from(depth) * 8, DomainId::DRIVER_0, DEVICE_DMA_MASK)
                .map_err(|_| Error::Memory)?;
        let mut buffers = Vec::with_capacity(depth as usize);
        for slot in 0..depth {
            let buffer = alloc_coherent_masked(BUFFER_SIZE, DomainId::DRIVER_0, DEVICE_DMA_MASK)
                .map_err(|_| Error::Memory)?;
            let bd = descriptor(buffer.dma_addr().raw(), BUFFER_SIZE)?;
            // SAFETY: fresh owned allocations; slot is below depth and each
            // descriptor occupies exactly eight bytes inside depth*8 storage.
            unsafe {
                core::ptr::write_bytes(buffer.as_mut_ptr(), 0, BUFFER_SIZE);
                core::ptr::copy_nonoverlapping(
                    bd.as_ptr(),
                    descriptors.as_mut_ptr().add(usize::from(slot) * 8),
                    8,
                );
            }
            buffer.sync(0, BUFFER_SIZE);
            buffers.push(buffer);
        }
        descriptors.sync(0, depth as usize * 8);
        Ok(Self {
            regs,
            descriptors: Some(descriptors),
            buffers,
            assembler: Assembler::for_chip(chip),
            wp: 0,
        })
    }
    fn publish(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let ring = self.descriptors.as_ref().ok_or(Error::Terminal)?;
        let address = ring.dma_addr().raw();
        barrier();
        io.write16(self.regs.num as u32, self.buffers.len() as u16)?;
        io.write32(self.regs.desa_l as u32, address as u32)?;
        io.write32(self.regs.desa_h as u32, (address >> 32) as u32)?;
        if io.read16(self.regs.num as u32)? != self.buffers.len() as u16
            || read(io, self.regs.desa_l as u32)? != address as u32
            || read(io, self.regs.desa_h as u32)? != (address >> 32) as u32
            || read(io, self.regs.idx as u32)? & 0x0fff_0fff != 0
        {
            return Err(Error::Index);
        }
        Ok(())
    }
    fn poll(
        &mut self,
        io: &mut impl Io,
        budget: usize,
        reports: bool,
    ) -> Result<(Vec<Event>, usize), Error> {
        let index = read(io, self.regs.idx as u32)?;
        let count = available(self.buffers.len() as u16, self.wp, index)?;
        let count = usize::from(count).min(budget);
        let mut events = Vec::new();
        for _ in 0..count {
            let buffer = &self.buffers[self.wp as usize];
            // The actual hardware upper-half RP, observed above under current
            // authority, transferred this buffer to the host. Never inspect a
            // pre-publication packet copy or turn its DMA address into a CPU VA.
            buffer.sync(0, BUFFER_SIZE);
            barrier();
            let event = self
                .assembler
                .segment(&buffer.as_slice()[..BUFFER_SIZE], reports)
                .map_err(Error::Descriptor)?;
            if let Some(event) = event {
                events.push(event);
            }
            // Clear stale metadata before handing this exact buffer back to
            // DMA. CPU copies above are independent of the retained DMA map.
            // SAFETY: exclusive ownership of a completed buffer covers the
            // four-byte RXBD-info header; hardware cannot reuse before WP.
            unsafe {
                core::ptr::write_bytes(buffer.as_mut_ptr(), 0, 4);
            }
            buffer.sync(0, BUFFER_SIZE);
            self.wp = (self.wp + 1) % self.buffers.len() as u16;
        }
        if count != 0 {
            barrier();
            // Never overwrite the independent hardware upper-half RP.
            io.write16(self.regs.idx as u32, self.wp)?;
            if read(io, self.regs.idx as u32)? & 0xfff != u32::from(self.wp) {
                return Err(Error::Index);
            }
        }
        Ok((events, count))
    }
    fn retain(&mut self) {
        if let Some(memory) = self.descriptors.take() {
            core::mem::forget(memory);
        }
        for memory in self.buffers.drain(..) {
            core::mem::forget(memory);
        }
    }
}
pub(super) struct Rx {
    state: State,
    rings: Option<[Ring; 2]>,
    armed: bool,
    chip: ChipId,
}
pub(super) struct Batch {
    pub(super) events: Vec<Event>,
    /// Descriptor progress remains observable for partial FS/LS assemblies
    /// and reports that emit no Wifi event. It cannot become an idle fence.
    pub(super) consumed: bool,
}
impl Default for Rx {
    fn default() -> Self {
        Self {
            state: State::New,
            rings: None,
            armed: false,
            chip: ChipId::Rtl8852B,
        }
    }
}
impl Rx {
    /// Observe only current HCI producer indices. B keeps this geometry live
    /// during clock gating; no RX memory/BB is read or returned to DMA here.
    pub(super) fn pending(&self, io: &mut impl Io) -> Result<bool, Error> {
        if self.state != State::Polling {
            return Err(Error::Terminal);
        }
        let rings = self.rings.as_ref().ok_or(Error::Terminal)?;
        for ring in rings {
            let index = read(io, ring.regs.idx as u32)?;
            if available(ring.buffers.len() as u16, ring.wp, index)? != 0 {
                return Ok(true);
            }
        }
        Ok(self.assembling())
    }
    pub(super) fn assembling(&self) -> bool {
        self.rings
            .as_ref()
            .is_some_and(|rings| rings.iter().any(|ring| ring.assembler.assembling()))
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Same independently fenced inherited-DMA, retained cold/firmware/MAC0
    /// owner. Both RX layers are still disabled, all unowned packet queues
    /// stopped, CH12 retains its own live ring and no reset/IRQ/PHY peer exists.
    /// The outer attempt terminalizes/retains this owner on cancellation.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        depth: u16,
    ) -> Result<(), Error> {
        // SAFETY: forwarded caller contract.
        unsafe { self.prepare_for(io, ChipId::Rtl8852B, depth).await }
    }
    /// [`Self::prepare`] for B or C. C uses its own HAXI geometry
    /// (rtw8852ce.c `rtw8852c_pci_info`): `rtw89_pci_ch_dma_addr_set_v1`
    /// RXQ/RPQ, `R_AX_RXBD_RWPTR_CLR_V1`, `rtw89_pci_ltr_set_v1`, no 8-byte
    /// address-info post-init, and RX release through `R_AX_HCI_FUNC_EN_V1`
    /// plus `B_AX_RXHCI_EN_V1` (HAXI_DMA_STOP1 has no RXQ/RPQ stop bits).
    /// # Safety
    /// As [`Self::prepare`], on the identified chip's own device.
    pub async unsafe fn prepare_for(
        &mut self,
        io: &mut impl Interface,
        chip: ChipId,
        depth: u16,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        // RTL8851B: rtw8851be.c `rtw89_8851be_info` is field-for-field
        // rtw8852be.c's (DMA address set, LTR, RX ring/descriptor), so it
        // takes B's geometry and prerequisite. RTL8852A takes the same
        // non-V1 geometry: rtw8852ae.c `rtw8852a_pci_info.dma_addr_set` is
        // `&rtw89_pci_ch_dma_addr_set` (same as 8852be/8851be, @ 05441d6),
        // and its DMA-stop mask is a superset of B's
        // (`B_AX_TX_STOP1_MASK` vs `_V1`, plus `B_AX_TX_STOP2_ALL`),
        // so the shared stopped readback below holds for A too.
        if !matches!(
            chip,
            ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B
        ) {
            return Err(power::Error::Unsupported.into());
        }
        self.state = State::Publishing;
        self.chip = chip;
        let result = self.prepare_inner(io, depth).await;
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    async fn prepare_inner(&mut self, io: &mut impl Interface, depth: u16) -> Result<(), Error> {
        if !(2..=256).contains(&depth) || !depth.is_power_of_two() {
            return Err(Error::Index);
        }
        let chip = self.chip;
        let c = chip == ChipId::Rtl8852C;
        stopped(io, chip)?;
        if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
            return Err(power::Error::Unsupported.into());
        }
        let regs = addr_set_for_chip(chip).rx;
        self.rings = Some([
            Ring::allocate(regs[0], depth, chip)?,
            Ring::allocate(regs[1], depth, chip)?,
        ]);
        // LTR follows the actual PCIe DEVCTL2 value; no caller boolean can
        // invent host permission. The existing bounded/cycle-checked walker
        // rejects malformed or absent PCIe capabilities.
        let capability = super::pci_basic::pcie_capability(io).await?;
        if io.config_read16(capability + 2).await? & 15 < 2 {
            return Err(power::Error::Unsupported.into());
        }
        let control = io.config_read16(capability + 0x28).await?;
        if control == u16::MAX {
            return Err(power::Error::Gone.into());
        }
        if control & (1 << 10) != 0 {
            if c {
                ltr_v1(io)?;
            } else {
                ltr(io)?;
            }
        }
        // RTL8852A-only LTR software trigger (pci.c
        // `rtw89_pci_ops_mac_post_init_ax` @ 05441d6, after `ltr_set`):
        // `R_AX_LTR_CTRL_0` (0x8410) `B_AX_APP_LTR_ACT` (bit 5, reg.h).
        // Unconditional in Linux, so it runs even when DEVCTL2 left LTR
        // unprogrammed above; read back the bit, not the whole register.
        if chip == ChipId::Rtl8852A {
            modify(io, LTR_CTRL_0, 0, 1 << 5)?;
            if read(io, LTR_CTRL_0)? & (1 << 5) == 0 {
                return Err(power::Error::Access.into());
            }
        }
        if c {
            // rtw89_pci_clr_idx_all_ax RX part, on the C V1 clear register;
            // both RX HCI layers are still disabled.
            modify(io, RXBD_RWPTR_CLR_V1, 0, CLR_RXQ_IDX | CLR_RPQ_IDX)?;
        }
        // Pin every descriptor/buffer before the first base can become visible.
        self.armed = true;
        for ring in self.rings.as_mut().unwrap() {
            ring.publish(io)?;
        }
        stopped(io, chip)?;
        if c {
            // rtw89_pci_ops_mac_post_init_ax: no 8-byte address-info mode
            // (8852A/885xB only). TX channels and WPDMA stay stopped as on B;
            // only RX HCI (V1 function enable, then HAXI RXHCI) is released.
            modify(io, HCI_FUNC_EN_V1, 0, 2)?;
            barrier();
            modify(io, HAXI_INIT_CFG1, 0, RXHCI_EN_V1)?;
            if read(io, HAXI_INIT_CFG1)? & RXHCI_EN_V1 == 0
                || read(io, HCI_FUNC_EN_V1)? & 2 == 0
                || read(io, 0x1010)? & C_STOPPED != C_STOPPED
            {
                return Err(power::Error::Access.into());
            }
            self.state = State::Polling;
            return Ok(());
        }
        // Linux AX baseline post-init: native TX address-info is eight bytes.
        modify(io, 0x8810, 0, 1)?;
        modify(io, 0x9a00, 2, 0)?;
        if read(io, 0x8810)? & 1 == 0 || read(io, 0x9a00)? & 2 != 0 {
            return Err(power::Error::Access.into());
        }
        // Release only RXQ/RPQ plus global RX HCI. WPDMA and every packet TX
        // channel remain stopped until their own real ring/PHY composition.
        modify(io, 0x1010, 3, 0)?;
        modify(io, 0x8380, 0, 2)?;
        barrier();
        modify(io, 0x1000, 0, 1 << 13)?;
        if read(io, 0x1000)? & (1 << 13) == 0
            || read(io, 0x8380)? & 2 == 0
            || read(io, 0x1010)? & (0xb0f00 | 3) != 0xb0f00
        {
            return Err(power::Error::Access.into());
        }
        self.state = State::Polling;
        Ok(())
    }
    /// Two finite queues, at most budget descriptors from each per invocation.
    /// Events remain private to the composed startup/station owner.
    pub fn poll(&mut self, io: &mut impl Io, budget: usize) -> Result<Vec<Event>, Error> {
        self.poll_inner(io, budget, false).map(|batch| batch.events)
    }
    pub(super) fn poll_step(&mut self, io: &mut impl Io, budget: usize) -> Result<Batch, Error> {
        self.poll_inner(io, budget, false)
    }
    /// # Safety
    /// Caller is the same retained native station owner and encloses the
    /// complete operation in its current device invocation. The sealed full
    /// RF/response qualification is current; basic calibration is insufficient.
    pub(super) unsafe fn poll_station_step(
        &mut self,
        io: &mut impl Io,
        budget: usize,
    ) -> Result<Batch, Error> {
        self.poll_inner(io, budget, true)
    }
    fn poll_inner(
        &mut self,
        io: &mut impl Io,
        budget: usize,
        qualified_station: bool,
    ) -> Result<Batch, Error> {
        if self.state != State::Polling || budget == 0 || budget > 256 {
            return Err(Error::Terminal);
        }
        let result = (|| {
            // Until the later signed station/response owner takes over, RX
            // transport alone must not permit an autonomous CMAC ACK/CTS.
            if !qualified_station && read(io, 0xc000)? & (1 << 29) != 0 {
                return Err(power::Error::Access.into());
            }
            let rings = self.rings.as_mut().ok_or(Error::Terminal)?;
            let (mut events, reports) = rings[1].poll(io, budget, true)?;
            let (wifi, received) = rings[0].poll(io, budget, false)?;
            events.extend(wifi);
            Ok(Batch {
                events,
                consumed: reports != 0 || received != 0,
            })
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    /// WoW halt: the RXQ/RPQ host half of `rtw89_pci_reset_trx_rings`
    /// (`wp = rp = 0`, no partial delivery or target RX tag). Unreaped
    /// buffers are dropped as Linux drops them; every buffer stays mapped and
    /// referenced by its descriptor. Returns the bases to re-publish.
    pub(super) fn wow_rewind(&mut self) -> Result<[(RxRingRegs, u64, u16); 2], Error> {
        if self.state != State::Polling {
            return Err(Error::Terminal);
        }
        let rings = self.rings.as_mut().ok_or(Error::Terminal)?;
        let mut bases = [(rings[0].regs, 0, 0); 2];
        for (ring, base) in rings.iter_mut().zip(bases.iter_mut()) {
            let address = ring
                .descriptors
                .as_ref()
                .ok_or(Error::Terminal)?
                .dma_addr()
                .raw();
            for buffer in &ring.buffers {
                // SAFETY: the caller stopped RX HCI (INIT_CFG1) and observed
                // TX/RX DMA idle; the four-byte RXBD-info header of every
                // owned buffer is rewritten before the ring is re-published.
                unsafe {
                    core::ptr::write_bytes(buffer.as_mut_ptr(), 0, 4);
                }
                buffer.sync(0, BUFFER_SIZE);
            }
            ring.wp = 0;
            ring.assembler = Assembler::for_chip(self.chip);
            *base = (ring.regs, address, ring.buffers.len() as u16);
        }
        Ok(bases)
    }
    pub fn fail(&mut self) {
        self.state = State::Terminal;
    }
    /// Release both RXQ/RPQ descriptor rings and all their buffers. The
    /// owner stays terminal; storage is returned for the caller to free.
    ///
    /// # Safety
    /// Actual DMA/prefetch/posted transactions are fenced: the caller holds a
    /// current `dma_stop::Idle` proof (RXQ/RPQ stopped and idle, BME off and
    /// flushed). BME off, stop bits or revocation alone are not that proof.
    pub(super) unsafe fn reclaim_fenced(&mut self) -> Vec<DmaBuffer> {
        self.state = State::Terminal;
        self.armed = false;
        let mut storage = Vec::new();
        for ring in self.rings.take().into_iter().flatten() {
            let Ring {
                descriptors,
                buffers,
                ..
            } = ring;
            storage.extend(descriptors);
            storage.extend(buffers);
        }
        storage
    }
}
impl Drop for Rx {
    fn drop(&mut self) {
        if self.armed {
            if let Some(rings) = self.rings.as_mut() {
                for ring in rings {
                    ring.retain();
                }
            }
        }
    }
}
fn descriptor(address: u64, length: usize) -> Result<[u8; 8], Error> {
    if length == 0
        || length > u16::MAX as usize
        || address
            .checked_add(length as u64 - 1)
            .is_none_or(|end| end > DMA_MASK)
    {
        return Err(Error::Memory);
    }
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(((address >> 32) as u16) << 6).to_le_bytes());
    bytes[4..].copy_from_slice(&(address as u32).to_le_bytes());
    Ok(bytes)
}
fn available(depth: u16, wp: u16, index: u32) -> Result<u16, Error> {
    let rp = ((index >> 16) & 0xfff) as u16;
    if index == u32::MAX || depth < 2 || wp >= depth || rp >= depth || index & 0xfff != wp as u32 {
        return Err(Error::Index);
    }
    Ok((rp + depth - wp) % depth)
}
pub(super) fn barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: device DMA ownership crosses the outer-shareable device domain.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
fn read(io: &mut impl Io, address: u32) -> Result<u32, power::Error> {
    let value = io.read32(address)?;
    if value == u32::MAX {
        Err(power::Error::Gone)
    } else {
        Ok(value)
    }
}
fn modify(io: &mut impl Io, address: u32, clear: u32, set: u32) -> Result<(), power::Error> {
    let value = read(io, address)?;
    io.write32(address, (value & !clear) | set)
}
/// C HAXI registers (reg.h / pci.h).
const HAXI_INIT_CFG1: u32 = 0x1000;
const RXHCI_EN_V1: u32 = 1 << 15;
const HCI_FUNC_EN_V1: u32 = 0x7880;
const RXBD_RWPTR_CLR_V1: u32 = 0x1200;
const CLR_RXQ_IDX: u32 = 1 << 0;
const CLR_RPQ_IDX: u32 = 1 << 1;
/// C download geometry: ACH0..7/CH8..11 and WPDMA stopped (CH12 open).
const C_STOPPED: u32 = 0x000b_ff00;
const LTR_CTRL_0: u32 = 0x8410;
const LTR_CTRL_1: u32 = 0x8414;
const LTR_DEC_CTRL: u32 = 0x1600;
const LTR_LATENCY_IDX0: u32 = 0x1604;
const LTR_LATENCY_IDX3: u32 = 0x1610;
fn stopped(io: &mut impl Io, chip: ChipId) -> Result<(), power::Error> {
    if chip == ChipId::Rtl8852C {
        if read(io, HAXI_INIT_CFG1)? & RXHCI_EN_V1 != 0
            || read(io, HCI_FUNC_EN_V1)? & 2 != 0
            || read(io, 0x1010)? & C_STOPPED != C_STOPPED
            || read(io, 0xc000)? & (1 << 29) != 0
        {
            return Err(power::Error::Access);
        }
        return Ok(());
    }
    if read(io, 0x1000)? & (1 << 13) != 0
        || read(io, 0x8380)? & 2 != 0
        || read(io, 0x1010)? & 0xb0f00 != 0xb0f00
        || read(io, 0xc000)? & (1 << 29) != 0
    {
        return Err(power::Error::Access);
    }
    Ok(())
}
fn ltr(io: &mut impl Io) -> Result<(), power::Error> {
    for address in [0x8410, 0x8414, 0x8418, 0x841c] {
        if read(io, address)? == 0xeaea_eaea {
            return Err(power::Error::Access);
        }
    }
    modify(io, 0x8410, 0, 0x43)?;
    modify(io, 0x8410, 0x3000, 2 << 12)?;
    modify(io, 0x8410, 0x700, 7 << 8)?;
    modify(io, 0x8414, 0xfff, 0x28)?;
    modify(io, 0x8414, 0xfff0000, 0x280000)?;
    io.write32(0x8418, 0x9003_9003)?;
    io.write32(0x841c, 0x880b_880b)?;
    if read(io, 0x8410)? & 0x3743 != 0x2743
        || read(io, 0x8414)? & 0x0fff_0fff != 0x0028_0028
        || read(io, 0x8418)? != 0x9003_9003
        || read(io, 0x841c)? != 0x880b_880b
    {
        return Err(power::Error::Access);
    }
    Ok(())
}

/// pci.c `rtw89_pci_ltr_set_v1(en = true)`: reject the 0xeaeaeaea error
/// value on every LTR register, enable HW decision with the 500us space
/// index, WD non-empty check + HW enable, 3.2ms idle timer, RX0/RX1
/// thresholds 0x28 and the IDX3/IDX0 latencies; every result read back.
fn ltr_v1(io: &mut impl Io) -> Result<(), power::Error> {
    let mut dec = 0;
    for address in [
        LTR_CTRL_0,
        LTR_CTRL_1,
        LTR_DEC_CTRL,
        LTR_LATENCY_IDX3,
        LTR_LATENCY_IDX0,
    ] {
        let value = read(io, address)?;
        if value == 0xeaea_eaea {
            return Err(power::Error::Access);
        }
        if address == LTR_DEC_CTRL {
            dec = value;
        }
    }
    // B_AX_LTR_HW_DEC_EN, then B_AX_LTR_SPACE_IDX_V1_MASK = PCI_LTR_SPC_500US.
    let dec = (dec | 1 << 2) & !3 | 2;
    modify(io, LTR_CTRL_0, 0, 3)?;
    modify(io, LTR_CTRL_0, 0x700, 7 << 8)?;
    modify(io, LTR_CTRL_1, 0xfff, 0x28)?;
    modify(io, LTR_CTRL_1, 0xfff_0000, 0x28_0000)?;
    io.write32(LTR_DEC_CTRL, dec)?;
    io.write32(LTR_LATENCY_IDX3, 0x9003_9003)?;
    io.write32(LTR_LATENCY_IDX0, 0x880b_880b)?;
    if read(io, LTR_CTRL_0)? & 0x703 != 0x703
        || read(io, LTR_CTRL_1)? & 0x0fff_0fff != 0x0028_0028
        || read(io, LTR_DEC_CTRL)? & 7 != 6
        || read(io, LTR_LATENCY_IDX3)? != 0x9003_9003
        || read(io, LTR_LATENCY_IDX0)? != 0x880b_880b
    {
        return Err(power::Error::Access);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "rx_dma/tests.rs"]
pub(super) mod tests;
