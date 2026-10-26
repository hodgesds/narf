//! Coherent PCI backend for x86_64 and aarch64.
//! Linux reference: ecd997b0189a mt792x_dma.c.
use super::{Backend, Error, Firmware, RadioInfo, Report, Retained, Session, State, MAX_FRAME};
use crate::mt7921::{packet_tx, registers, regs::*};
use alloc::{collections::VecDeque, vec, vec::Vec};
#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::fence;
use core::sync::atomic::Ordering;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::DmaBuffer;

// A CPU atomic fence is inner-shareable on ARM. Device ownership also needs
// the outer-shareable domain used by PCI DMA (Linux dma_rmb/dma_wmb).
fn dma_barrier() {
    #[cfg(target_arch = "aarch64")]
    {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: DMB only orders accesses; no register or memory operand.
        unsafe {
            core::arch::asm!("dmb osh", options(nostack, preserves_flags));
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
    #[cfg(not(target_arch = "aarch64"))]
    fence(Ordering::SeqCst);
}

const DEPTH: usize = 16;
const GLOBAL: u32 = 0xd4208;
const BUSY: u32 = 0xa;
const ENABLE: u32 = 5;
const OMIT: u32 = (1 << 15) | (1 << 21) | (1 << 27) | (1 << 28);
const DONE: u32 = 1 << 31;
const LAST: u32 = 1 << 30;
const TX_FWDL: u32 = 0xd4300 + 16 * 16;
const TX_WM: u32 = 0xd4300 + 17 * 16;
const RX_PRE: u32 = 0xd4500;
const RX_POST: u32 = 0xd4540;
const RX_DATA: u32 = 0xd4520;
const TX_DATA: u32 = 0xd4300;

#[derive(Debug)]
struct Ring {
    descriptors: DmaBuffer,
    buffers: Vec<DmaBuffer>,
    index: usize,
    pending: bool,
    base: u32,
}
impl Ring {
    fn allocate(base: u32, rx: bool) -> Result<Self, Error> {
        let descriptors = narf_io::alloc_coherent_masked(
            DEPTH * 16,
            narf_lib::id::DomainId::DRIVER_0,
            u64::from(u32::MAX),
        )
        .map_err(|_| Error::Allocation)?;
        // Hardware descriptor-base registers have no upper-address field.
        if descriptors
            .dma_addr()
            .raw()
            .checked_add((DEPTH * 16 - 1) as u64)
            .is_none_or(|end| end > u64::from(u32::MAX))
        {
            return Err(Error::DmaAddress);
        }
        let mut buffers = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            let mask = if base == TX_DATA {
                u64::from(u32::MAX)
            } else {
                (1u64 << 36) - 1
            };
            let buffer =
                narf_io::alloc_coherent_masked(MAX_FRAME, narf_lib::id::DomainId::DRIVER_0, mask)
                    .map_err(|_| Error::Allocation)?;
            if buffer
                .dma_addr()
                .raw()
                .checked_add((MAX_FRAME - 1) as u64)
                .is_none_or(|end| end >= 1 << 36)
            {
                return Err(Error::DmaAddress);
            }
            buffers.push(buffer);
        }
        let ring = Self {
            descriptors,
            buffers,
            index: 0,
            pending: false,
            base,
        };
        for index in 0..DEPTH {
            if rx {
                ring.arm_rx(index);
            } else {
                ring.set_word(index, 1, DONE);
            }
        }
        Ok(ring)
    }
    fn word(&self, slot: usize, word: usize) -> u32 {
        // SAFETY: fixed descriptor geometry; coherent device-owned field sampled volatile.
        u32::from_le(unsafe {
            self.descriptors
                .cpu_ptr::<u32>()
                .add(slot * 4 + word)
                .read_volatile()
        })
    }
    fn set_word(&self, slot: usize, word: usize, value: u32) {
        // SAFETY: fixed geometry; caller owns this descriptor or has stopped DMA.
        unsafe {
            self.descriptors
                .cpu_mut_ptr::<u32>()
                .add(slot * 4 + word)
                .write_volatile(value.to_le())
        };
    }
    fn arm_rx(&self, slot: usize) {
        let address = self.buffers[slot].dma_addr().raw();
        self.set_word(slot, 0, address as u32);
        self.set_word(slot, 2, 0); // buf1 is a second segment, NOT address-high bits.
        self.set_word(slot, 3, (address >> 32) as u32 & 15);
        self.set_word(slot, 1, (MAX_FRAME as u32) << 16);
    }
}
#[derive(Debug)]
struct Storage {
    wm: Ring,
    fwdl: Ring,
    rx: [Ring; 3],
    data: Ring,
    tokens: packet_tx::Tokens,
    pending_events: VecDeque<Vec<u8>>,
    pending_data: VecDeque<Vec<u8>>,
}
impl Storage {
    // Caller has proved device quiescence and retired every hardware ring reference.
    fn recycle(&mut self) {
        for ring in [&mut self.wm, &mut self.fwdl, &mut self.data] {
            ring.index = 0;
            ring.pending = false;
            for slot in 0..DEPTH {
                for word in 0..4 {
                    ring.set_word(slot, word, 0);
                }
                ring.set_word(slot, 1, DONE);
            }
            for buffer in &mut ring.buffers {
                buffer.as_mut_slice().fill(0);
            }
        }
        for ring in &mut self.rx {
            ring.index = 0;
            ring.pending = false;
            for slot in 0..DEPTH {
                ring.arm_rx(slot);
            }
        }
        self.tokens = packet_tx::Tokens::new();
        self.pending_events.clear();
        self.pending_data.clear();
        dma_barrier();
    }
}
#[derive(Debug)]
struct Hardware {
    mmio: MmioRegion,
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    owner: Retained<Storage>,
}
impl Hardware {
    fn receive_ring(&mut self, which: usize) -> Result<Option<Vec<u8>>, Error> {
        self.check()?;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let ring = &storage.rx[which];
        let didx = self.read(ring.base + 12)? as usize;
        if didx >= DEPTH {
            return Err(Error::Ring);
        }
        if didx == ring.index {
            return Ok(None);
        }
        dma_barrier();
        let ctrl = ring.word(ring.index, 1);
        let len = ((ctrl >> 16) & 0x3fff) as usize;
        if ctrl & (DONE | LAST) != (DONE | LAST) || !(8..=MAX_FRAME).contains(&len) {
            return Err(Error::MalformedEvent);
        }
        dma_barrier(); // device payload writes precede observed DDONE
        let mut frame = vec![0u8; len];
        // SAFETY: completion/length verified; copy before returning buffer to DMA.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ring.buffers[ring.index].cpu_ptr::<u8>(),
                frame.as_mut_ptr(),
                len,
            )
        };
        let rxd = u32::from_le_bytes(frame[..4].try_into().map_err(|_| Error::MalformedEvent)?);
        let packet_len = (rxd & 0xffff) as usize;
        if !(8..=len).contains(&packet_len) {
            return Err(Error::MalformedEvent);
        }
        frame.truncate(packet_len);
        let slot = ring.index;
        ring.arm_rx(slot);
        dma_barrier();
        let base = ring.base;
        self.write(base + 8, slot as u32)?;
        self.owner.storage.as_mut().ok_or(Error::Busy)?.rx[which].index = (slot + 1) % DEPTH;
        Ok(Some(frame))
    }
    fn route_rx(&mut self, event: Option<bool>) -> Result<Option<Vec<u8>>, Error> {
        self.check()?;
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if let Some(packet) = match event {
            Some(true) => storage.pending_events.pop_front(),
            Some(false) => storage.pending_data.pop_front(),
            None => None,
        } {
            return Ok(Some(packet));
        }
        for which in 0..3 {
            let Some(packet) = self.receive_ring(which)? else {
                continue;
            };
            let rxd = u32::from_le_bytes(packet[..4].try_into().unwrap());
            let kind = rxd >> 27;
            let normal = kind == 2 || kind == 7 && (rxd >> 16) & 15 == 1;
            if kind == 0 {
                let releases = packet_tx::releases(&packet)?;
                self.owner
                    .storage
                    .as_mut()
                    .ok_or(Error::Busy)?
                    .tokens
                    .firmware_done(&releases)?;
            } else if normal || kind == 7 {
                if !normal && packet.len() < 32 {
                    return Err(Error::MalformedEvent);
                }
                if event == Some(!normal) {
                    return Ok(Some(packet));
                }
                let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
                let queue = if normal {
                    &mut storage.pending_data
                } else {
                    &mut storage.pending_events
                };
                if queue.len() == 32 {
                    if !normal {
                        return Err(Error::EventOverflow);
                    }
                    queue.pop_front(); // bounded RX loss under overload, never drop an MCU reply
                }
                queue.push_back(packet);
            }
            // TX-status and unknown reports do not satisfy a command waiter.
        }
        Ok(None)
    }

    // Private until association supplies a verified transmit-capable channel.
    fn submit_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let token = storage.tokens.available()?;
        let ring = &storage.data;
        let slot = ring.index;
        if ring.pending || ring.word(slot, 1) & DONE == 0 {
            return Err(Error::Busy);
        }
        let address = ring.buffers[slot].dma_addr().raw();
        let payload = address
            .checked_add(packet_tx::HEADER as u64)
            .ok_or(Error::DmaAddress)?;
        let header = packet_tx::management(frame, payload, token, wcid, rate)?;
        // SAFETY: fully validated lengths; this slot has neither DMA nor
        // firmware ownership until the publication below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                header.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                header.len(),
            );
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>().add(header.len()),
                frame.len(),
            );
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        storage.tokens.begin(token)?;
        let ring = &mut storage.data;
        ring.pending = true; // conservative on any later doorbell failure
        ring.set_word(slot, 0, address as u32);
        ring.set_word(slot, 2, 0);
        ring.set_word(slot, 3, (address >> 32) as u32 & 15);
        dma_barrier();
        ring.set_word(slot, 1, ((packet_tx::HEADER as u32) << 16) | LAST);
        dma_barrier();
        self.write(TX_DATA + 8, ((slot + 1) % DEPTH) as u32)
    }
    fn submit_data(&mut self, frame: &[u8], protected: bool, qos: bool) -> Result<(), Error> {
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let token = storage.tokens.available()?;
        let ring = &storage.data;
        let slot = ring.index;
        if ring.pending || ring.word(slot, 1) & DONE == 0 {
            return Err(Error::Busy);
        }
        let address = ring.buffers[slot].dma_addr().raw();
        let payload = address
            .checked_add(packet_tx::HEADER as u64)
            .ok_or(Error::DmaAddress)?;
        let header = if qos {
            packet_tx::ethernet_qos(frame, payload, token, 1, protected, true)?
        } else {
            packet_tx::ethernet(frame, payload, token, 1, protected)?
        };
        // SAFETY: fully validated lengths; this slot has neither DMA nor
        // firmware ownership until the publication below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                header.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                header.len(),
            );
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>().add(header.len()),
                frame.len(),
            );
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        storage.tokens.begin(token)?;
        let ring = &mut storage.data;
        ring.pending = true; // conservative on any later doorbell failure
        ring.set_word(slot, 0, address as u32);
        ring.set_word(slot, 2, 0);
        ring.set_word(slot, 3, (address >> 32) as u32 & 15);
        dma_barrier();
        ring.set_word(slot, 1, ((packet_tx::HEADER as u32) << 16) | LAST);
        dma_barrier();
        self.write(TX_DATA + 8, ((slot + 1) % DEPTH) as u32)
    }
    fn management_complete(&mut self) -> Result<Option<packet_tx::Completion>, Error> {
        self.check()?;
        let ring = &self.owner.storage.as_ref().ok_or(Error::Busy)?.data;
        if !ring.pending {
            return Err(Error::Ring);
        }
        let next = (ring.index + 1) % DEPTH;
        let didx = self.read(TX_DATA + 12)? as usize;
        if didx >= DEPTH || didx != ring.index && didx != next {
            return Err(Error::Ring);
        }
        let done = didx == next && ring.word(ring.index, 1) & DONE != 0;
        dma_barrier();
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if done {
            storage.tokens.dma_done()?;
        }
        let mut result = storage.tokens.finish();
        if result.is_none() {
            // Poll reports without consuming queued/fresh MCU replies.
            let _ = self.route_rx(None)?;
            let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
            result = storage.tokens.finish();
        }
        if result.is_some() {
            let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
            storage.data.pending = false;
            storage.data.index = next;
        }
        Ok(result)
    }
    fn read(&self, addr: u32) -> Result<u32, Error> {
        crate::mt7921::pci::invoke(&self.authority, || {
            // SAFETY: exclusive retained aperture/L1 latch inside current invocation.
            let value =
                unsafe { registers::read32(&self.mmio, addr) }.map_err(|_| Error::Register)?;
            if value == u32::MAX {
                Err(Error::DeviceGone)
            } else {
                Ok(value)
            }
        })
        .map_err(|_| Error::Authority)?
    }
    fn write(&self, addr: u32, value: u32) -> Result<(), Error> {
        crate::mt7921::pci::invoke(&self.authority, || {
            // SAFETY: bounded register plan and current retained PCI invocation.
            unsafe { registers::write32(&self.mmio, addr, value) }.map_err(|_| Error::Register)
        })
        .map_err(|_| Error::Authority)?
    }
    fn command(&self, clear: u16, set: u16) -> Result<u16, Error> {
        crate::mt7921::pci::invoke(&self.authority, || {
            if clear != 0 {
                narf_bus::pci::clear_command(&self.authority, &self.device, clear)
                    .map_err(|_| Error::Authority)?;
            }
            if set != 0 {
                narf_bus::pci::set_command(&self.authority, &self.device, set)
                    .map_err(|_| Error::Authority)?;
            }
            let value = narf_bus::pci::read_command(&self.authority, &self.device)
                .map_err(|_| Error::Authority)?;
            if value == u16::MAX {
                Err(Error::DeviceGone)
            } else {
                Ok(value)
            }
        })
        .map_err(|_| Error::Authority)?
    }
    fn update(&self, addr: u32, clear: u32, set: u32) -> Result<(), Error> {
        self.write(addr, (self.read(addr)? & !clear) | set)
    }
    fn program(&self, ring: &Ring, rx: bool) -> Result<(), Error> {
        self.write(ring.base, ring.descriptors.dma_addr().raw() as u32)?;
        self.write(ring.base + 4, DEPTH as u32)?;
        self.write(ring.base + 8, if rx { (DEPTH - 1) as u32 } else { 0 })?;
        self.write(ring.base + 12, 0)
    }
    fn clear_rings(&self) -> Result<(), Error> {
        // Clear inherited ring bases too: enabling a global DMA engine must
        // not expose buffers belonging to the previous OS/firmware client.
        for (base, count) in [(0xd4300, 18), (0xd4500, 6)] {
            for ring in 0..count {
                for word in 0..4 {
                    self.write(base + ring * 16 + word * 4, 0)?;
                }
            }
        }
        Ok(())
    }
}
impl Backend for Hardware {
    fn progress(&mut self, stage: super::Stage) {
        use core::fmt::Write;
        let _ = writeln!(narf_console::Writer, "mt76: firmware {stage:?}");
    }
    fn now_ns(&self) -> u64 {
        narf_time::wall::monotonic_ns()
    }
    fn check(&self) -> Result<(), Error> {
        crate::mt7921::pci::invoke(&self.authority, || ()).map_err(|_| Error::Authority)
    }
    fn check_tx_permission(
        &self,
        permission: crate::mt7921::association::TxPermission,
    ) -> Result<(), Error> {
        self.check()?;
        super::current_station_permission(permission, narf_wireless::reg::db::snapshot())
    }
    fn park_bus_master(&mut self) -> Result<(), Error> {
        if self.command(narf_bus::pci::cmd::BUS_MASTER, 0)? & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn assert_reset(&mut self) -> Result<(), Error> {
        self.update(MT_WFSYS_SW_RST_B, 1, 0)?;
        if self.read(MT_WFSYS_SW_RST_B)? & 1 != 0 {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn request_link_own(&mut self) -> Result<(), Error> {
        self.write(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_CLR_OWN)
    }
    fn link_owned(&mut self) -> Result<bool, Error> {
        Ok(self.read(MT_CONN_ON_LPCTL)? & PCIE_LPCR_HOST_OWN_SYNC == 0)
    }
    fn release_reset(&mut self) -> Result<(), Error> {
        self.update(MT_WFSYS_SW_RST_B, 0, 1)?;
        if self.read(MT_WFSYS_SW_RST_B)? & 1 == 0 {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn reset_done(&mut self) -> Result<bool, Error> {
        Ok(self.read(MT_WFSYS_SW_RST_B)? & (1 << 4) != 0)
    }
    fn recycle(&mut self) -> Result<(), Error> {
        if self.owner.published || !self.idle()? || self.read(GLOBAL)? & ENABLE != 0 {
            return Err(Error::Busy);
        }
        if self.command(0, 0)? & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(Error::Busy);
        }
        self.owner.storage.as_mut().ok_or(Error::Busy)?.recycle();
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), Error> {
        self.write(MT_PCIE_MAC_INT_ENABLE, 0)?;
        self.write(MT_WFDMA0_HOST_INT_ENA, 0)?;
        self.write(MT_MCU2HOST_SW_INT_ENA, 0)?;
        self.update(GLOBAL, ENABLE | OMIT, 0)?;
        let _ = self.read(GLOBAL)?; // push disable before waiting for idle
        Ok(())
    }
    fn idle(&mut self) -> Result<bool, Error> {
        Ok(self.read(GLOBAL)? & BUSY == 0)
    }
    fn initialize(&mut self) -> Result<(), Error> {
        if !self.idle()? {
            return Err(Error::Busy);
        }
        self.write(0x0041f23c, 0)?; // MT_SWDEF_MODE: normal firmware operation.
        self.update(0xd42b0, 1 << 6, 0)?; // disable DMASHDL
        self.update(0x7c026004, 0, 1 << 28)?; // bypass scheduler
        self.update(MT_WFDMA0_RST, 0x30, 0)?;
        self.update(MT_WFDMA0_RST, 0, 0x30)?;
        self.clear_rings()?;
        self.write(0xd420c, u32::MAX)?;
        // Conservatively mark published BEFORE the first ring base write.
        self.owner.published = true;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        dma_barrier();
        self.program(&storage.wm, false)?;
        self.program(&storage.fwdl, false)?;
        self.program(&storage.data, false)?;
        for ring in &storage.rx {
            self.program(ring, true)?;
        }
        for (index, base) in [(0, 0), (2, 0x40), (3, 0x80), (4, 0xc0), (5, 0x100)] {
            self.write(0xd4680 + index * 4, (base << 16) | 4)?;
        }
        for (index, base) in [
            (0, 0x140),
            (1, 0x180),
            (2, 0x1c0),
            (3, 0x200),
            (4, 0x240),
            (5, 0x280),
            (6, 0x2c0),
            (16, 0x340),
            (17, 0x380),
        ] {
            self.write(0xd4600 + index * 4, (base << 16) | 4)?;
        }
        self.write(0xd42f0, 0)?;
        self.update(
            GLOBAL,
            ENABLE | (1 << 27),
            (3 << 4)
                | (1 << 6)
                | (1 << 11)
                | (1 << 12)
                | (1 << 13)
                | (1 << 15)
                | (1 << 21)
                | (1 << 28)
                | (1 << 30),
        )?;
        self.update(0x54000120, 0, 2)?;
        self.update(MT_PCIE_MAC_PM, 0, MT_PCIE_MAC_PM_L0S_DIS)?;
        // All published addresses are owned and bounded before enabling DMA.
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        if self.command(0, BUS_MASTER)? & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
            != BUS_MASTER | MEM_SPACE | INTX_DISABLE
        {
            return Err(Error::Authority);
        }
        self.update(GLOBAL, 0, ENABLE)?;
        let _ = self.read(GLOBAL)?;
        Ok(())
    }
    fn request_driver_own(&mut self) -> Result<(), Error> {
        self.write(0x18060010, 2)
    }
    fn driver_owned(&mut self) -> Result<bool, Error> {
        Ok(self.read(0x18060010)? & 1 == 0)
    }
    fn fw_state(&mut self) -> Result<u32, Error> {
        self.read(0x7c0600f0)
    }
    fn configure_mac(&mut self) -> Result<(), Error> {
        self.update(0x820cd004, 0xfff8, 1536 << 3)?;
        self.update(0x820cd000, 0, (1 << 15) | (1 << 19))?;
        for band in [0u32, 0x10000] {
            self.update(0x820e40f4 + band, 0x3f, 0x3f | (3 << 17))?;
            self.update(0x820e53c4 + band, 0, 1 << 30)?;
            self.update(0x820e5380 + band, 0, 1 << 30)?;
            self.update(0x820ed004 + band, 0, 3 << 8)?;
            self.update(0x820e7000 + band, 0xfff8 | (1 << 23), 1536 << 3)?;
            self.update(0x820e9008 + band, (3 << 30) | (3 << 24), 3 << 24)?;
        }
        Ok(())
    }
    fn clear_wtbl(&mut self, index: u8) -> Result<(), Error> {
        if index >= 20 {
            return Err(Error::Bounds);
        }
        self.update(0x820d4230, 0x3ff, u32::from(index) | (1 << 12))
    }
    fn wtbl_idle(&mut self) -> Result<bool, Error> {
        Ok(self.read(0x820d4230)? & (1 << 31) == 0)
    }
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        self.check()?;
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return Err(Error::Bounds);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        let ring = if scatter {
            &mut storage.fwdl
        } else {
            &mut storage.wm
        };
        if ring.pending {
            return Err(Error::Busy);
        }
        let slot = ring.index;
        // SAFETY: TX completion was verified before this slot is reused.
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                frame.len(),
            )
        };
        let address = ring.buffers[slot].dma_addr().raw();
        ring.set_word(slot, 0, address as u32);
        ring.set_word(slot, 2, 0);
        ring.set_word(slot, 3, (address >> 32) as u32 & 15);
        dma_barrier();
        ring.set_word(slot, 1, ((frame.len() as u32) << 16) | LAST);
        dma_barrier();
        ring.pending = true;
        let base = ring.base;
        let next = (slot + 1) % DEPTH;
        self.write(base + 8, next as u32)
    }
    fn tx_complete(&mut self, scatter: bool) -> Result<bool, Error> {
        self.check()?;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let ring = if scatter { &storage.fwdl } else { &storage.wm };
        let didx = self.read(ring.base + 12)? as usize;
        if didx >= DEPTH {
            return Err(Error::Ring);
        }
        if !ring.pending {
            return Err(Error::Ring);
        }
        let next = (ring.index + 1) % DEPTH;
        if didx != ring.index && didx != next {
            return Err(Error::Ring);
        }
        dma_barrier();
        if didx != next || ring.word(ring.index, 1) & DONE == 0 {
            return Ok(false);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        let ring = if scatter {
            &mut storage.fwdl
        } else {
            &mut storage.wm
        };
        ring.index = next;
        ring.pending = false;
        Ok(true)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.route_rx(Some(true))
    }
    fn receive_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.route_rx(Some(false))
    }
    fn release(&mut self) -> Result<(), Error> {
        if !self.idle()? || self.read(GLOBAL)? & ENABLE != 0 {
            return Err(Error::Busy);
        }
        self.park_bus_master()?;
        self.clear_rings()?;
        let _ = self.read(GLOBAL)?;
        self.owner.published = false;
        Ok(())
    }
    fn submit_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.submit_management(frame, wcid, rate)
    }
    fn submit_data(&mut self, frame: &[u8], protected: bool, qos: bool) -> Result<(), Error> {
        self.submit_data(frame, protected, qos)
    }
    fn management_complete(
        &mut self,
    ) -> Result<Option<crate::mt7921::packet_tx::Completion>, Error> {
        self.management_complete()
    }
}
/// Retained coherent MCU/FWDL transport with verified reset/recovery.
#[derive(Debug)]
pub struct Transport {
    session: Session<Hardware>,
}

#[path = "firmware_transport_hw_tests.rs"]
mod tests;
impl Transport {
    /// Allocate all rings without device writes.
    ///
    /// # Safety
    /// Caller exclusively owns this posted CONNAC2 device, its BAR0/L1 latch,
    /// DMA/reset/power controls and permanent mappings. No other client may
    /// access them until verified shutdown. The PCI function must be in a
    /// coherent identity DMA domain (or have no IOMMU). This is not VF/reset
    /// recovery. Firmware must be prepared for this exact chip. Initially
    /// PCI bus mastering must be disabled by the caller.
    pub unsafe fn new(
        mmio: MmioRegion,
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
        firmware: Firmware,
    ) -> Result<Self, Error> {
        crate::mt7921::pci::invoke(&authority, || {
            authority.check_live().map_err(|_| Error::Authority)?;
            if !matches!(device.id.vendor, 0x14c3 | 0x0e8d)
                || !matches!(device.id.device, 0x0616 | 0x0608 | 0x7922 | 0x7961 | 0x7920)
            {
                return Err(Error::Bounds);
            }
            if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
                return Err(Error::DmaAddress);
            }
            if narf_bus::pci::read_command(&authority, &device).map_err(|_| Error::Authority)?
                & narf_bus::pci::cmd::BUS_MASTER
                != 0
            {
                return Err(Error::Busy);
            }
            // Highest programmed register and the L1 selector must be mapped.
            for addr in [0xd46ff, MT_HIF_REMAP_L1] {
                if u64::from(addr) + 4 > mmio.len {
                    return Err(Error::Bounds);
                }
            }
            let storage = Storage {
                wm: Ring::allocate(TX_WM, false)?,
                fwdl: Ring::allocate(TX_FWDL, false)?,
                data: Ring::allocate(TX_DATA, false)?,
                tokens: packet_tx::Tokens::new(),
                pending_events: VecDeque::new(),
                pending_data: VecDeque::new(),
                rx: [
                    Ring::allocate(RX_PRE, true)?,
                    Ring::allocate(RX_POST, true)?,
                    Ring::allocate(RX_DATA, true)?,
                ],
            };
            Ok(Self {
                session: Session::new(
                    Hardware {
                        mmio,
                        device,
                        authority,
                        owner: Retained {
                            storage: Some(storage),
                            published: false,
                        },
                    },
                    firmware,
                ),
            })
        })
        .map_err(|_| Error::Authority)?
    }
    /// Start once. Dropping this borrowed future requests no reset/replay.
    pub async fn run(&mut self) -> Result<Report, Error> {
        self.session.run().await
    }
    /// Query the real radio identity and select on-chip EFUSE calibration.
    /// This does not yet enable packet transmission or register an interface.
    pub async fn initialize_radio(&mut self) -> Result<RadioInfo, Error> {
        self.session.initialize_radio().await
    }
    /// Perform a bounded, receive-only scan on world 2.4 GHz channels 1..=11.
    pub async fn scan_passive(&mut self, channels: &[u8]) -> Result<super::ScanReport, Error> {
        self.session.scan_passive(channels).await
    }
    /// Directed/wildcard probes on currently policy-authorized 20 MHz channels.
    /// Nonempty SSID lists (up to four, including wildcard entries) select
    /// active scanning. A completed scan returns to a NO_IR-only idle domain.
    pub async fn scan_active(
        &mut self,
        channels: &[u8],
        ssids: &[Vec<u8>],
    ) -> Result<super::ScanReport, Error> {
        // Bootstrap only at this explicit admission boundary. The running
        // scan must observe a cleared installation rather than reload it.
        narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Authority)?;
        self.session
            .scan_active_with_policy(channels, ssids, || {
                narf_wireless::reg::db::get_domain().ok_or(Error::Authority)
            })
            .await
    }
    /// Prepare the bounded native HT20 RX/A-MSDU owner from actual radio/AP
    /// capabilities. This does not enable HT MLME, peer firmware state or TX.
    /// Legacy association invalidates the preparation; no HT facade is exposed.
    pub fn prepare_ht20_receive(
        &mut self,
        bss: &super::ScanBss,
    ) -> Result<super::Ht20ReceiveInfo, Error> {
        self.session.prepare_ht20_receive(bss)
    }
    /// Associate with an Access Point using legacy rates on channels 1..=11.
    pub async fn associate_station(
        &mut self,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: crate::mt7921::association::Security,
    ) -> Result<u16, Error> {
        self.associate_station_with_ies(bss, ssid, security, &[])
            .await
    }
    /// Associate while retaining checked optional SME association elements.
    pub async fn associate_station_with_ies(
        &mut self,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: crate::mt7921::association::Security,
        extra_ies: &[u8],
    ) -> Result<u16, Error> {
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Authority)?;
        let info = match self.session.state {
            State::RadioReady(info) | State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        let permission = crate::mt7921::association::TxPermission::from_ap(&domain, info, bss)
            .ok_or(Error::Authority)?;
        self.session
            .associate_station(bss, ssid, security, permission, extra_ies)
            .await
    }
    /// Send deauthentication and tear down peer station record.
    pub async fn disassociate_station(&mut self) -> Result<(), Error> {
        self.session.disassociate_station().await
    }
    /// Stop DMA, verify idle, clear bus mastering and retire ring bases.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.session.shutdown().await
    }
    /// Park DMA, reset WFSYS, retire old ring ownership, and reload firmware.
    /// The caller closes carrier before awaiting. No association/key replay is
    /// attempted; a fresh scan/association is required after successful recovery.
    pub async fn recover(&mut self, expected_mac: [u8; 6]) -> Result<RadioInfo, Error> {
        self.session.recover(expected_mac).await
    }
    pub(super) async fn recover_unregistered(&mut self) -> Result<RadioInfo, Error> {
        self.session.recover_unregistered().await
    }
    /// Last observed boot stage/result, also preserved after cancellation.
    pub fn state(&self) -> State {
        self.session.state
    }
    /// Drain unrelated bounded MCU notifications retained while awaiting replies.
    pub fn pop_event(&mut self) -> Option<Vec<u8>> {
        self.session.events.pop_front()
    }
    /// Transmit an 802.3 Ethernet data frame.
    pub async fn transmit_ethernet(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.session.send_ethernet(frame).await.map(|_| ())
    }
    /// Receive a data frame from the data queue.
    pub async fn receive_data_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.session.receive_ethernet()
    }

    pub(super) fn step_network(&mut self, tx: Option<&[u8]>) -> Result<super::PacketStep, Error> {
        self.session.step_network(tx)
    }

    pub(super) async fn service_keys(&mut self) -> Result<(), Error> {
        self.session.service_keys().await
    }

    pub(super) fn keys_pending(&self) -> bool {
        self.session.keys_pending()
    }
}
