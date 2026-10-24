// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained RTL8852B polling RXQ/RPQ ownership. No IRQ or NIC publication.
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
    fn allocate(regs: RxRingRegs, depth: u16) -> Result<Self, Error> {
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
            assembler: Assembler::default(),
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
    ) -> Result<Vec<Event>, Error> {
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
        Ok(events)
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
}
impl Default for Rx {
    fn default() -> Self {
        Self {
            state: State::New,
            rings: None,
            armed: false,
        }
    }
}
impl Rx {
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
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Publishing;
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
        stopped(io)?;
        if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
            return Err(power::Error::Unsupported.into());
        }
        let regs = addr_set_for_chip(ChipId::Rtl8852B).rx;
        self.rings = Some([
            Ring::allocate(regs[0], depth)?,
            Ring::allocate(regs[1], depth)?,
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
            ltr(io)?;
        }
        // Pin every descriptor/buffer before the first base can become visible.
        self.armed = true;
        for ring in self.rings.as_mut().unwrap() {
            ring.publish(io)?;
        }
        stopped(io)?;
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
        if self.state != State::Polling || budget == 0 || budget > 256 {
            return Err(Error::Terminal);
        }
        let result = (|| {
            let rings = self.rings.as_mut().ok_or(Error::Terminal)?;
            let mut events = rings[1].poll(io, budget, true)?;
            events.extend(rings[0].poll(io, budget, false)?);
            Ok(events)
        })();
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    pub fn fail(&mut self) {
        self.state = State::Terminal;
    }
    /// # Safety
    /// Actual DMA/prefetch/posted transactions are independently fenced; BME
    /// off, stop bits, revocation and a missing IRQ are not sufficient proof.
    #[cfg(any(test, feature = "kernel-test"))]
    unsafe fn reclaim_fenced(&mut self) {
        self.state = State::Terminal;
        self.armed = false;
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
fn stopped(io: &mut impl Io) -> Result<(), power::Error> {
    if read(io, 0x1000)? & (1 << 13) != 0
        || read(io, 0x8380)? & 2 != 0
        || read(io, 0x1010)? & 0xb0f00 != 0xb0f00
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "rx_dma/tests.rs"]
mod tests;
