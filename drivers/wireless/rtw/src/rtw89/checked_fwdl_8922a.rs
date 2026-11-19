// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked BE-only ring/FWCMD owner. Existing AX/BE source APIs intact.
//! All ring, RX and pending payload mappings move into this owner; dropping an
//! owner without its own checked stop/reset receipt pins them, never frees them.
//! Native source programs remain separate from their closed safety sequencing.
use super::{
    cold_8922a as cold,
    dma::{self, RingState, BE_DMA_ADDR_SET, TXCH_NUM},
    dma_be as d, power,
};
use alloc::{collections::VecDeque, vec::Vec};
#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::fence;
use core::sync::atomic::{compiler_fence, Ordering};
use narf_io::DmaBuffer;
#[path = "checked_packet_8922a.rs"]
pub(super) mod packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Io(power::Error),
    State,
    Identity,
    Geometry,
    Readback(u32),
    Full,
    Ring,
    Memory,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    New,
    Resetting,
    ProgrammedStopped,
    Enabled,
    FirmwareStopped,
    Failed(Error),
    Released,
}
/// Stable owned DMA mappings; implementing this does not grant any hardware.
/// # Safety
/// DMA address, extent and CPU storage name the same allocation until Drop.
/// Writes stay inside that allocation; sync makes them visible to this device.
/// No other CPU writer aliases these mappings during the checked owner borrow.
pub(super) unsafe trait Memory {
    fn address(&self) -> u64;
    fn length(&self) -> usize;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    /// Snapshot stable device-owned bytes only after its terminal RX index
    /// receipt. Invalidates device writes before reading; never aliases a
    /// concurrently CPU-written slice.
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;
    fn sync(&self, offset: usize, length: usize);
}
// SAFETY: DmaBuffer owns one stable mapped allocation; its bounds and sync
// operations supply exactly the mapping contract. Owner serializes CPU writes.
unsafe impl Memory for DmaBuffer {
    fn address(&self) -> u64 {
        self.dma_addr().raw()
    }
    fn length(&self) -> usize {
        self.len()
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len())
        {
            return Err(Error::Memory);
        }
        // SAFETY: bounds checked above; unique owner supplies exclusive CPU writes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.as_mut_ptr().add(offset),
                bytes.len(),
            )
        };
        Ok(())
    }
    fn sync(&self, offset: usize, length: usize) {
        DmaBuffer::sync(self, offset, length)
    }
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len())
        {
            return Err(Error::Memory);
        }
        self.sync_for_cpu(offset, bytes.len(), narf_io::DmaDirection::FromDevice);
        dma_barrier();
        // SAFETY: checked extent and original owner holds the RX terminal
        // index receipt; DMA cannot overwrite the slot before our doorbell.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.as_ptr().add(offset),
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        Ok(())
    }
}
pub(super) struct Storage<M: Memory> {
    pub(super) tx: [M; TXCH_NUM],
    pub(super) rx: [M; 2],
    pub(super) receive: [Vec<M>; 2],
}
/// Configuration receipt under positively held original-controller gates.
/// It is not a temporal reset or permission to retire a prefetched mapping.
struct HeldStop {
    binding: cold::Binding,
    serial: u64,
}
struct Configuration {
    stop: HeldStop,
}
pub(super) struct Owner<M: Memory> {
    storage: Option<Storage<M>>,
    legacy: Vec<M>,
    pending: VecDeque<M>,
    consumed: VecDeque<M>,
    binding: Option<cold::Binding>,
    reset: Option<Configuration>,
    serial: u64,
    state: State,
    ring: RingState,
    rx_depth: u16,
    rx_wp: u16,
    assembler: super::completion_8922a::BeAssembler,
    packet: Option<packet::Transport<M>>,
}
impl<M: Memory> Drop for Owner<M> {
    fn drop(&mut self) {
        // No destructor can acquire a new hardware stop proof. Keep every mapping
        // potentially named by a ring/descriptor, even when a caller drops Err work.
        if let Some(storage) = self.storage.take() {
            core::mem::forget(storage)
        }
        for m in self.legacy.drain(..) {
            core::mem::forget(m)
        }
        for m in self.pending.drain(..) {
            core::mem::forget(m)
        }
        for m in self.consumed.drain(..) {
            core::mem::forget(m)
        }
    }
}
impl<M: Memory> Owner<M> {
    /// Adopt all BE ring/RX storage and every previously referenced payload.
    /// # Safety
    /// Exactly one original RTL8922A controller owns these mappings. `legacy`
    /// contains ALL old Prepared data/H2C/FWCMD-retained mappings; none remain
    /// externally droppable. No other ring owner, producer, reset or IRQ worker
    /// may use them. The caller's closed Cold owner remains retained separately.
    /// No programmed/reset/firmware readiness is assumed at this entry.
    pub(super) unsafe fn adopt(
        storage: Storage<M>,
        legacy: Vec<M>,
        tx_depth: u16,
        rx_depth: u16,
    ) -> Self {
        Self {
            storage: Some(storage),
            legacy,
            pending: VecDeque::new(),
            consumed: VecDeque::new(),
            binding: None,
            reset: None,
            serial: 0,
            state: State::New,
            ring: RingState::new(tx_depth),
            rx_depth,
            rx_wp: rx_depth.saturating_sub(1),
            assembler: super::completion_8922a::BeAssembler::default(),
            packet: None,
        }
    }
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// Outer boot failure also fences this DMA owner, including failures
    /// before a payload allocation or submit reached any native register.
    pub(super) fn poison(&mut self) {
        if self.state != State::Released {
            self.state = State::Failed(Error::State)
        }
    }
    /// Reobserve the original held configuration. This releases no legacy
    /// payload owner and establishes no new temporal-reset generation.
    pub(super) fn reset_current(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.state != State::ProgrammedStopped {
            return Err(Error::State);
        }
        let result = (|| {
            self.stopped(io)?;
            check(io, 0x88, 0x802, 0x802)?;
            let reset = self.reset.as_ref().ok_or(Error::State)?;
            if Some(reset.stop.binding) != self.binding || reset.stop.serial != self.serial {
                return Err(Error::Identity);
            }
            Ok(())
        })();
        self.terminal(result)
    }
    pub(super) fn held(&self) -> (usize, usize, usize) {
        (self.legacy.len(), self.pending.len(), self.consumed.len())
    }
    fn terminal<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if let Err(e) = result {
            self.state = State::Failed(e)
        }
        result
    }
    fn bind(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        io.current()?;
        let binding = io.binding();
        match self.binding {
            Some(old) if old != binding => Err(Error::Identity),
            Some(_) => Ok(()),
            None => {
                self.binding = Some(binding);
                Ok(())
            }
        }
    }
    fn geometry(&self) -> Result<(), Error> {
        if !(2..=256).contains(&self.ring.len) || !(2..=256).contains(&self.rx_depth) {
            return Err(Error::Geometry);
        }
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        for m in &storage.tx {
            mapping(m, usize::from(self.ring.len) * 8)?
        }
        for (index, m) in storage.rx.iter().enumerate() {
            mapping(m, usize::from(self.rx_depth) * 8)?;
            if storage.receive[index].len() != usize::from(self.rx_depth) {
                return Err(Error::Geometry);
            }
            for packet in &storage.receive[index] {
                mapping(packet, 1)?;
                if packet.length() > u16::MAX as usize {
                    return Err(Error::Geometry);
                }
            }
        }
        Ok(())
    }
    fn guard(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        self.bind(io)?;
        closed(io)
    }
    fn write32(&mut self, io: &mut impl cold::Regs, a: u32, v: u32) -> Result<(), Error> {
        self.guard(io)?;
        io.write32(a, v)?;
        self.guard(io)
    }
    fn write16(&mut self, io: &mut impl cold::Regs, a: u32, v: u16) -> Result<(), Error> {
        self.guard(io)?;
        io.write16(a, v)?;
        self.guard(io)
    }
    fn modify(
        &mut self,
        io: &mut impl cold::Regs,
        a: u32,
        clear: u32,
        set: u32,
    ) -> Result<(), Error> {
        self.guard(io)?;
        let old = read(io, a)?;
        self.write32(io, a, (old & !clear) | set)
    }
    fn stopped(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        self.guard(io)?;
        if read(io, d::DMA_STOP1)? & 0x8000_7fff != 0x8000_7fff {
            return Err(Error::Readback(d::DMA_STOP1));
        }
        if read(io, d::INIT_CFG1)? & 0xb0 != 0x80 {
            return Err(Error::Readback(d::INIT_CFG1));
        }
        Ok(())
    }
    fn stop_indices(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        self.guard(io)?;
        // Source CPU-disable prefix, positively held before DMA reset. This
        // native denial-only prelude prevents old firmware re-enabling DMA.
        self.modify(io, 0x88, 2, 0)?;
        check(io, 0x88, 2, 0)?;
        self.modify(io, 0x88, 0, 0x800)?;
        check(io, 0x88, 0x800, 0x800)?;
        self.modify(io, 0x88, 0, 2)?;
        check(io, 0x88, 0x802, 0x802)?;
        // Extra native stop of every TX channel is denial-only. Source preinit
        // then stops WPDMA/global TRX, clears indices, and observes DMA idle.
        self.modify(io, d::DMA_STOP1, 0, 0x8000_7fff)?;
        check(io, d::DMA_STOP1, 0x8000_7fff, 0x8000_7fff)?;
        self.modify(io, d::INIT_CFG1, 0x30, 0x80)?;
        self.stopped(io)?;
        self.write32(io, d::TXBD_RWPTR_CLR1, 0x7fff)?;
        self.write32(io, d::RXBD_RWPTR_CLR1_V1, 3)?;
        self.write16(io, d::RXQ0_RXBD_IDX_V1, self.rx_depth - 1)?;
        self.write16(io, d::RPQ0_RXBD_IDX_V1, self.rx_depth - 1)?;
        io.poll32(d::DMA_BUSY1, 0x7fff, 0, 1000)?;
        io.poll32(d::DMA_BUSY1, 0x30000, 0, 1000)?;
        // Actual IO idle is also needed before releasing retained mappings.
        io.poll32(d::DMA_BUSY1, 0x8000_0000, 0, 1000)?;
        for r in &BE_DMA_ADDR_SET.tx {
            check(io, r.idx as u32, 0x0fff_0fff, 0)?
        }
        for r in &BE_DMA_ADDR_SET.rx {
            check(io, r.idx as u32, 0x0fff_0fff, u32::from(self.rx_depth - 1))?
        }
        self.stopped(io)
    }
    fn finish_configuration(&mut self, io: &mut impl cold::Regs) -> Result<Configuration, Error> {
        self.stopped(io)?;
        check(io, 0x88, 0x802, 0x802)?;
        if read(io, d::INIT_CFG1)? & 0x10000 != 0 {
            return Err(Error::Readback(d::INIT_CFG1));
        }
        self.modify(io, d::INIT_CFG1, 0, 0x10000)?;
        // Source request+clear polling does not prove a separate memory-
        // retirement/reset epoch. Every legacy/prefetched mapping stays owned.
        io.poll32(d::INIT_CFG1, 0x10000, 0, 500_000)?;
        self.stopped(io)?;
        check(io, 0x88, 0x802, 0x802)?;
        Ok(Configuration {
            stop: self.held_stop_receipt(io)?,
        })
    }
    fn held_stop_receipt(&mut self, io: &mut impl cold::Regs) -> Result<HeldStop, Error> {
        self.stopped(io)?;
        check(io, 0x88, 0x802, 0x802)?;
        check(io, d::DMA_BUSY1, 0x8003_7fff, 0)?;
        self.guard(io)?;
        self.serial = self.serial.checked_add(1).ok_or(Error::State)?;
        Ok(HeldStop {
            binding: io.binding(),
            serial: self.serial,
        })
    }
    fn release_old(&mut self, receipt: &HeldStop) -> Result<(), Error> {
        if Some(receipt.binding) != self.binding || receipt.serial != self.serial {
            return Err(Error::Identity);
        }
        self.legacy.clear();
        self.pending.clear();
        self.consumed.clear();
        Ok(())
    }
    pub(super) fn reset_program(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::State);
        }
        self.state = State::Resetting;
        let result = (|| {
            self.geometry()?;
            self.stop_indices(io)?;
            // Source 8922AE mode_op, with every register operation fallible.
            let init = read(io, d::INIT_CFG1)?;
            let append = read(io, d::RX_APPEND_MODE)?;
            let exp = read(io, d::EXP_CTRL_V1)?;
            self.write32(io, d::INIT_CFG1, (init & !0xff00_180f) | 0x1100_0006)?;
            self.write32(io, d::RX_APPEND_MODE, append)?;
            self.write32(io, d::EXP_CTRL_V1, (exp & !0xf) | 7)?;
            // CPU writes below occur only behind the complete observed stop.
            let storage = self.storage.as_mut().ok_or(Error::State)?;
            for m in &mut storage.tx {
                for i in 0..self.ring.len {
                    io.dma_memory(|| m.write(usize::from(i) * 8, &[0; 8]))?
                }
                io.dma_memory(|| {
                    m.sync(0, usize::from(self.ring.len) * 8);
                    Ok(())
                })?
            }
            for (ring, packets) in storage.rx.iter_mut().zip(&storage.receive) {
                for (i, packet) in packets.iter().enumerate() {
                    let mut bd = dma::RxBd {
                        buf_size: packet.length() as u16,
                        ..Default::default()
                    };
                    bd.set_phys(packet.address());
                    let mut bytes = [0; 8];
                    bytes[..2].copy_from_slice(&bd.buf_size.to_le_bytes());
                    bytes[2..4].copy_from_slice(&bd.opt.to_le_bytes());
                    bytes[4..].copy_from_slice(&bd.dma.to_le_bytes());
                    io.dma_memory(|| ring.write(i * 8, &bytes))?;
                }
                io.dma_memory(|| {
                    ring.sync(0, usize::from(self.rx_depth) * 8);
                    Ok(())
                })?
            }
            // Linux NUM then DESA_L/H, all TX then RX, then WP-select.
            for i in 0..TXCH_NUM {
                let address = self.storage.as_ref().ok_or(Error::State)?.tx[i].address();
                let r = BE_DMA_ADDR_SET.tx[i];
                self.write16(io, r.num as u32, self.ring.len)?;
                self.write32(io, r.desa_l as u32, address as u32)?;
                self.write32(io, r.desa_h as u32, (address >> 32) as u32)?;
                ring_readback(io, r.num, r.desa_l, r.desa_h, self.ring.len, address)?;
            }
            for i in 0..2 {
                let address = self.storage.as_ref().ok_or(Error::State)?.rx[i].address();
                let r = BE_DMA_ADDR_SET.rx[i];
                self.write16(io, r.num as u32, self.rx_depth)?;
                self.write32(io, r.desa_l as u32, address as u32)?;
                self.write32(io, r.desa_h as u32, (address >> 32) as u32)?;
                self.write16(io, r.idx as u32, self.rx_depth - 1)?;
                ring_readback(io, r.num, r.desa_l, r.desa_h, self.rx_depth, address)?;
            }
            for group in [0u32, 4, 8, 12] {
                let v = group | ((group + 1) << 8) | ((group + 2) << 16) | ((group + 3) << 24);
                self.write32(io, 0xb420 + group, v)?;
                check(io, 0xb420 + group, u32::MAX, v)?;
            }
            let receipt = self.finish_configuration(io)?;
            // This is configuration under observed held gates, not a new
            // temporal-reset/retirement epoch. Do not free original mappings.
            self.reset = Some(receipt);
            self.ring = RingState::new(self.ring.len);
            Ok(())
        })();
        self.terminal(result)?;
        self.state = State::ProgrammedStopped;
        Ok(())
    }
    /// Source PCI pre-init tail only; caller retains the same controller.
    /// # Safety
    /// Actual checked DLFW DLE/HFC + PCI recovery/power/settings prerequisites
    /// completed on this function. PCI BME has its own current checked grant;
    /// no guessed callback/bool supplies those missing composed stage receipts.
    /// This method alone is not a completed cold boot or ordinary DMA route.
    pub(super) unsafe fn enable_ch12(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.state != State::ProgrammedStopped {
            return Err(Error::State);
        }
        let result = (|| {
            self.stopped(io)?;
            let reset = self.reset.as_ref().ok_or(Error::State)?;
            if Some(reset.stop.binding) != self.binding || reset.stop.serial != self.serial {
                return Err(Error::Identity);
            }
            self.modify(io, d::DMA_STOP1, 0, 0x6fff)?;
            self.modify(io, d::DMA_STOP1, 0x1000, 0)?;
            self.modify(io, d::INIT_CFG1, 0x80, 0x30)?;
            self.modify(io, d::MST_WDT_TIMEOUT_SEL_V1, 0x1f, 4)?;
            active(io)?;
            Ok(())
        })();
        self.terminal(result)?;
        self.state = State::Enabled;
        Ok(())
    }
    pub(super) fn dma_current(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.state != State::Enabled {
            return Err(Error::State);
        }
        let result = self.guard(io).and_then(|()| active(io));
        self.terminal(result)
    }
    /// Close HAXI for the source post-FW SCC DLE/TRX transition. Firmware
    /// readiness alone does not consume descriptors: observe the original
    /// CH12 RP through every pending packet first. All consumed/legacy maps
    /// remain retained; WCPU stays alive and no reset/retirement is claimed.
    pub(super) fn stop_for_trx(&mut self, io: &mut impl cold::Regs) -> Result<(), Error> {
        if self.state != State::Enabled {
            return Err(Error::State);
        }
        let result = (|| {
            let mut error = None;
            let done = narf_scheduler::responsive_spin_until(
                || match self.reclaim(io) {
                    Ok(_) => self.pending.is_empty(),
                    Err(e) => {
                        error = Some(e);
                        true
                    }
                },
                narf_time::Deadline::after_us(1_000_000),
            );
            if let Some(e) = error {
                return Err(e);
            }
            if !done {
                return Err(power::Error::Timeout.into());
            }
            self.modify(io, d::DMA_STOP1, 0, 0x8000_7fff)?;
            self.modify(io, d::INIT_CFG1, 0x30, 0x80)?;
            self.stopped(io)?;
            io.poll32(d::DMA_BUSY1, 0x8003_7fff, 0, 1000)?;
            self.stopped(io)
        })();
        self.terminal(result)?;
        self.state = State::FirmwareStopped;
        Ok(())
    }
    /// # Safety
    /// The original checked post-FW SCC/TRX owner completed with MAC0 TX/RX
    /// closed, MAC1 off, no ordinary producer and every map still retained.
    /// This only restores bounded CH12/global DMA; ordinary TX/WPDMA stay off.
    pub(super) unsafe fn resume_ch12_after_trx(
        &mut self,
        io: &mut impl cold::Regs,
    ) -> Result<(), Error> {
        if self.state != State::FirmwareStopped {
            return Err(Error::State);
        }
        let result = (|| {
            self.stopped(io)?;
            self.modify(io, d::DMA_STOP1, 0x1000, 0)?;
            self.modify(io, d::INIT_CFG1, 0x80, 0x30)?;
            active(io)
        })();
        self.terminal(result)?;
        self.state = State::Enabled;
        Ok(())
    }
    pub(super) fn reclaim(&mut self, io: &mut impl cold::Regs) -> Result<u16, Error> {
        if self.state != State::Enabled {
            return Err(Error::State);
        }
        let result = (|| {
            self.dma_current(io)?;
            let r = BE_DMA_ADDR_SET.tx[12];
            let raw = read(io, r.idx as u32)?;
            let (rp, wp) = dma::split_idx(raw);
            if rp >= self.ring.len || wp != self.ring.wp {
                return Err(Error::Ring);
            }
            let count = if rp >= self.ring.rp {
                rp - self.ring.rp
            } else {
                self.ring.len - (self.ring.rp - rp)
            };
            let flight = self.ring.len - 1 - self.ring.avail();
            if count > flight || usize::from(count) > self.pending.len() {
                return Err(Error::Ring);
            }
            self.guard(io)?;
            self.ring.set_rp(rp);
            for _ in 0..count {
                self.consumed
                    .push_back(self.pending.pop_front().ok_or(Error::Ring)?)
            }
            // Keep the source multitag window and every earlier consumed
            // bootstrap buffer until permanent stop. Slot credit is separate
            // from permission to free prefetched/current firmware DMA memory.
            Ok(self.ring.avail())
        })();
        self.terminal(result)
    }
    pub(super) fn submit(&mut self, io: &mut impl cold::Regs, payload: M) -> Result<u16, Error> {
        if self.state != State::Enabled {
            return Err(Error::State);
        }
        let result = (|| {
            mapping(&payload, 1)?;
            if payload.length() > u16::MAX as usize {
                return Err(Error::Geometry);
            }
            if self.reclaim(io)? == 0 {
                return Err(Error::Full);
            }
            let slot = self.ring.wp;
            let address = payload.address();
            let length = payload.length();
            self.pending.push_back(payload); // retained BEFORE TXBD can name it
            let mut bd = dma::TxBd {
                length: length as u16,
                opt: dma::TXBD_OPT_LS,
                ..Default::default()
            };
            bd.set_phys(address);
            let mut bytes = [0; 8];
            bytes[..2].copy_from_slice(&bd.length.to_le_bytes());
            bytes[2..4].copy_from_slice(&bd.opt.to_le_bytes());
            bytes[4..].copy_from_slice(&bd.dma.to_le_bytes());
            let ring = &mut self.storage.as_mut().ok_or(Error::State)?.tx[12];
            io.dma_memory(|| ring.write(usize::from(slot) * 8, &bytes))?;
            io.dma_memory(|| {
                self.pending.back().ok_or(Error::Ring)?.sync(0, length);
                Ok(())
            })?;
            io.dma_memory(|| {
                ring.sync(usize::from(slot) * 8, 8);
                Ok(())
            })?;
            dma_barrier();
            self.dma_current(io)?;
            self.ring.advance_wp(1);
            let wp = self.ring.wp;
            let idx = BE_DMA_ADDR_SET.tx[12].idx as u32;
            // A failed/readback-uncertain kick keeps the reservation/payload;
            // it never rolls back into retry credit or releases a mapping.
            self.write16(io, idx, wp)?;
            check(io, idx, 0xfff, u32::from(wp))?;
            self.guard(io)?;
            Ok(slot)
        })();
        self.terminal(result)
    }
    /// Closed bootstrap RX: consume the actual RXQ index, snapshot each owned
    /// terminal slot, parse its source BE segments, then clear/fence/doorbell.
    /// Only C2H is returned. Wifi/PPDU never gains an ordinary publication path.
    /// Native wraps this entire memory + MMIO operation in current Cap::invoke.
    fn receive_firmware(
        &mut self,
        io: &mut impl cold::Regs,
        budget: usize,
    ) -> Result<FirmwareRx, Error> {
        if self.state != State::Enabled {
            return Err(Error::State);
        }
        if !(1..=256).contains(&budget) {
            return Err(Error::Geometry);
        }
        let result = (|| {
            self.dma_current(io)?;
            let idx = BE_DMA_ADDR_SET.rx[0].idx as u32;
            let index = read(io, idx)?;
            let count = usize::from(
                super::completion_8922a::available_be(index, self.rx_wp, self.rx_depth)
                    .map_err(|_| Error::Ring)?,
            )
            .min(budget);
            let mut outcome = FirmwareRx::default();
            for _ in 0..count {
                self.dma_current(io)?;
                let slot = (self.rx_wp + 1) % self.rx_depth;
                let storage = self.storage.as_mut().ok_or(Error::State)?;
                let packet = &mut storage.receive[0][usize::from(slot)];
                let mut bytes = alloc::vec::Vec::new();
                bytes
                    .try_reserve_exact(packet.length())
                    .map_err(|_| Error::Memory)?;
                bytes.resize(packet.length(), 0);
                io.dma_memory(|| packet.read(0, &mut bytes))?;
                match self.assembler.segment(&bytes) {
                    Ok(Some(super::completion_8922a::BeEvent::Firmware(c2h))) => {
                        outcome.c2h.push(c2h)
                    }
                    Ok(Some(_)) => outcome.dropped += 1,
                    Ok(None) => {}
                    Err(_) => {
                        self.assembler.reset();
                        outcome.dropped += 1;
                    }
                }
                // No returned message escapes until the original source
                // authority, zero-header visibility and doorbell readback
                // complete. Error retains the consumed cursor and all maps.
                io.dma_memory(|| packet.write(0, &[0; 4]))?;
                io.dma_memory(|| {
                    packet.sync(0, 4);
                    Ok(())
                })?;
                dma_barrier();
                self.dma_current(io)?;
                self.rx_wp = slot;
                self.write16(io, idx, slot)?;
                check(io, idx, 0xfff, u32::from(slot))?;
                self.dma_current(io)?;
                outcome.work += 1;
            }
            Ok(outcome)
        })();
        self.terminal(result)
    }
    /// Explicit denial-only cleanup, also allowed after a failed kick/reset.
    /// All original storage stays owned until this complete checked receipt.
    fn stop_release(&mut self, io: &mut impl cold::Regs) -> Result<Storage<M>, Error> {
        if self.state == State::Released {
            return Err(Error::State);
        }
        let result = (|| {
            self.geometry()?;
            self.stop_indices(io)?;
            // Permanent terminal retirement needs the positively held stop,
            // not sampling BDRAM's arbitrarily short self-clear pulse. No
            // later enable/reprogram path exists on this Released owner.
            let receipt = self.held_stop_receipt(io)?;
            self.release_old(&receipt)?;
            let storage = self.storage.take().ok_or(Error::State)?;
            self.reset = None;
            Ok(storage)
        })();
        let storage = self.terminal(result)?;
        self.state = State::Released;
        Ok(storage)
    }
}
#[derive(Default)]
pub(super) struct FirmwareRx {
    pub(super) c2h: Vec<super::completion_8922a::RoutedC2h>,
    pub(super) work: usize,
    pub(super) dropped: usize,
}
fn mapping(m: &impl Memory, minimum: usize) -> Result<(), Error> {
    if m.length() < minimum
        || m.address() & 7 != 0
        || m.address()
            .checked_add(m.length().saturating_sub(1) as u64)
            .is_none_or(|end| end > 0xff_ffff_ffff)
    {
        Err(Error::Geometry)
    } else {
        Ok(())
    }
}
fn read(io: &mut impl cold::Regs, a: u32) -> Result<u32, Error> {
    let v = io.read32(a)?;
    if v == u32::MAX {
        Err(power::Error::Gone.into())
    } else {
        Ok(v)
    }
}
fn check(io: &mut impl cold::Regs, a: u32, mask: u32, want: u32) -> Result<(), Error> {
    if read(io, a)? & mask != want {
        Err(Error::Readback(a))
    } else {
        Ok(())
    }
}
fn closed(io: &mut impl cold::Regs) -> Result<(), Error> {
    io.current()?;
    // Full common power tuples before any possibly off-domain bank read.
    check(io, 0x24, 0x1f00_001f, 0x1f00_0000)?;
    // BB0 platform release after the original successful FWDL is owned by
    // closed SystemConfigured. DMA safety continues to require MAC1 fully
    // off/BB1 held and both MAC0 packet gates closed, not BB0 platform reset.
    check(io, 0x84, 0x0303_0300, 0x0201_0000)?;
    check(io, 0x10000, 0x3000_0000, 0)
}
fn active(io: &mut impl cold::Regs) -> Result<(), Error> {
    closed(io)?;
    check(io, d::DMA_STOP1, 0x8000_7fff, 0x8000_6fff)?;
    check(io, d::INIT_CFG1, 0xb0, 0x30)
}
fn ring_readback(
    io: &mut impl cold::Regs,
    num: u64,
    low: u64,
    high: u64,
    depth: u16,
    address: u64,
) -> Result<(), Error> {
    let len = io.read16(num as u32)?;
    if len == u16::MAX {
        return Err(power::Error::Gone.into());
    }
    if len != depth {
        return Err(Error::Readback(num as u32));
    }
    check(io, low as u32, u32::MAX, address as u32)?;
    check(io, high as u32, u32::MAX, (address >> 32) as u32)
}

fn dma_barrier() {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: source PCI DMA ownership barrier orders normal memory before MMIO.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

/// Native port for checked DMA and the following source FWDL CPU controls.
/// Common power/packet gates are read-only here; no broad raw MMIO adapter.
pub(super) struct Native<'a> {
    region: &'a narf_bus::MmioRegion,
    cap: &'a narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    fault: Option<power::Error>,
    cancelled: Option<&'a core::sync::atomic::AtomicBool>,
    qualification: Option<super::be_qualification::Grant<'a>>,
}
impl<'a> Native<'a> {
    fn packet_source(&self) -> Result<(), power::Error> {
        if let Some(response) = self.qualification.and_then(|grant| grant.packet_response()) {
            super::be_packet_qualification::closed(self.region)?;
            response.check(self.region)?;
        }
        Ok(())
    }
    /// # Safety
    /// One exclusive actual RTL8922A BAR/current PCI capability; mapping remains
    /// live. All original possibly referenced DMA mappings are retained by the
    /// checked owner. No competing producer, reset, removal or interrupt worker.
    pub(super) unsafe fn new(
        region: &'a narf_bus::MmioRegion,
        cap: &'a narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Self {
        Self {
            region,
            cap,
            fault: None,
            cancelled: None,
            qualification: None,
        }
    }
    pub(super) fn cancel_with(mut self, flag: &'a core::sync::atomic::AtomicBool) -> Self {
        self.cancelled = Some(flag);
        self
    }
    pub(super) fn qualify(mut self, grant: &'a super::be_qualification::Partial) -> Self {
        self.qualification = Some(super::be_qualification::Grant::Partial(grant));
        self
    }
    pub(super) fn qualify_scope(mut self, grant: super::be_qualification::Grant<'a>) -> Self {
        self.qualification = Some(grant);
        self
    }
    /// One bounded poll under actual current authority for the whole owned
    /// DMA snapshot/recycle operation; nested register invokes are lock-free
    /// capability checks, with no Rtw89Device/source-scope callback recursion.
    pub(super) fn receive_firmware<M: Memory>(
        &mut self,
        owner: &mut Owner<M>,
        budget: usize,
    ) -> Result<FirmwareRx, Error> {
        if let Err(error) = self.cancellation() {
            return owner.terminal(Err(error.into()));
        }
        let cap = *self.cap;
        let qualification = self.qualification;
        let mut operation = || {
            crate::rtw88::pci_park::invoke(&cap, || {
                self.cancellation()?;
                owner.receive_firmware(self, budget)
            })
            .map_err(|_| Error::Io(power::Error::Access))
            .and_then(core::convert::identity)
        };
        let result = if let Some(grant) = qualification {
            grant.with_current(operation)
        } else {
            operation()
        };
        owner.terminal(result)
    }
    /// Publish one fresh private command allocation under the exact current
    /// capability invocation, including every owned descriptor memory effect.
    /// A failed invocation before publication may drop only this fresh map;
    /// the original owner and all previously referenced maps remain terminal.
    pub(super) fn submit_command<M: Memory>(
        &mut self,
        owner: &mut Owner<M>,
        payload: M,
    ) -> Result<u16, Error> {
        if let Err(error) = self.cancellation() {
            return owner.terminal(Err(error.into()));
        }
        let cap = *self.cap;
        let qualification = self.qualification;
        let operation = || {
            crate::rtw88::pci_park::invoke(&cap, || {
                self.cancellation()?;
                owner.submit(self, payload)
            })
            .map_err(|_| Error::Io(power::Error::Access))
            .and_then(core::convert::identity)
        };
        let result = if let Some(grant) = qualification {
            grant.with_current(operation)
        } else {
            operation()
        };
        owner.terminal(result)
    }
    fn cancellation(&mut self) -> Result<(), power::Error> {
        if self
            .cancelled
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return self.latch(Err(power::Error::Access));
        }
        Ok(())
    }
    /// Consume the sole native DMA port when retiring the controller. It is
    /// never returned alongside freed storage, so this instance cannot later
    /// re-enable the stopped engine with stale ring addresses.
    pub(super) fn retire(
        mut self,
        owner: &mut Owner<DmaBuffer>,
    ) -> Result<Storage<DmaBuffer>, Error> {
        owner.stop_release(&mut self)
    }
    fn latch<T>(&mut self, result: Result<T, power::Error>) -> Result<T, power::Error> {
        if let Some(e) = self.fault {
            return Err(e);
        }
        if let Err(e) = result {
            self.fault = Some(e)
        }
        result
    }
    fn access<T>(
        &mut self,
        a: u32,
        width: u32,
        write: bool,
        op: impl FnOnce(&narf_bus::MmioRegion, u64) -> T,
    ) -> Result<T, power::Error> {
        self.cancellation()?;
        if let Some(e) = self.fault {
            return Err(e);
        }
        let qualification = self.qualification;
        let operation = || {
            crate::rtw88::pci_park::invoke(self.cap, || {
                self.packet_source()?;
                use super::fwdl_be as f;
                let control = [
                    f::R_BE_PLATFORM_ENABLE,
                    f::R_BE_WCPU_FW_CTRL,
                    f::R_BE_DCPU_PLATFORM_ENABLE,
                    f::R_BE_UDM0,
                    f::R_BE_UDM1,
                    f::R_BE_UDM2,
                    f::R_BE_HALT_C2H,
                    f::R_BE_HALT_H2C,
                    f::R_BE_BOOT_DBG,
                    f::R_BE_HALT_H2C_CTRL,
                    f::R_BE_HALT_C2H_CTRL,
                    f::R_BE_HISR0,
                    f::R_BE_SYS_CLK_CTRL,
                    f::R_BE_SYS_CFG5,
                    f::R_BE_SECURE_BOOT_MALLOC_INFO,
                    f::R_BE_GPIO_MUXCFG,
                    f::R_BE_FW_AUTO_CAL_DELAY,
                ];
                let ring32 = BE_DMA_ADDR_SET.tx.iter().any(|r| {
                    a == r.desa_l as u32 || a == r.desa_h as u32 || !write && a == r.idx as u32
                }) || BE_DMA_ADDR_SET.rx.iter().any(|r| {
                    a == r.desa_l as u32 || a == r.desa_h as u32 || !write && a == r.idx as u32
                });
                let ring16 = BE_DMA_ADDR_SET.tx.iter().any(|r| a == r.num as u32)
                    || BE_DMA_ADDR_SET
                        .rx
                        .iter()
                        .any(|r| a == r.num as u32 || write && a == r.idx as u32)
                    || write && a == BE_DMA_ADDR_SET.tx[12].idx as u32;
                let allowed = match width {
                    1 => [0x7160, 0x7164, 0x1f5].contains(&a),
                    2 => a == f::R_BE_BOOT_REASON || ring16,
                    4 => {
                        control.contains(&a)
                            || (0x7140..=0x714c).contains(&a) && a % 4 == 0
                            || !write
                                && ((0x7150..=0x715c).contains(&a) && a % 4 == 0 || a == 0x3f0)
                            || a == 0x68
                            || a == 0x10398
                            || super::pci_pre_init_8922a::checked::permits32(a, write)
                            || ring32
                            || [
                                d::INIT_CFG1,
                                d::DMA_STOP1,
                                d::TXBD_RWPTR_CLR1,
                                d::RXBD_RWPTR_CLR1_V1,
                                d::RX_APPEND_MODE,
                                d::EXP_CTRL_V1,
                                d::MST_WDT_TIMEOUT_SEL_V1,
                                0xb420,
                                0xb424,
                                0xb428,
                                0xb42c,
                            ]
                            .contains(&a)
                            || !write && [d::DMA_BUSY1, 0x24, 0x84, 0x10000].contains(&a)
                    }
                    _ => false,
                };
                let offset = u64::from(a);
                if !allowed
                    || a & (width - 1) != 0
                    || offset
                        .checked_add(u64::from(width))
                        .is_none_or(|end| end > self.region.len)
                {
                    return Err(power::Error::Access);
                }
                let result = op(self.region, offset);
                self.packet_source()?;
                Ok(result)
            })
            .map_err(|_| power::Error::Access)
            .and_then(core::convert::identity)
        };
        let result = if let Some(grant) = qualification {
            grant.with_current(operation)
        } else {
            operation()
        };
        self.latch(result)
    }
}
impl cold::Regs for Native<'_> {
    fn binding(&self) -> cold::Binding {
        cold::Binding::observe(self.region, self.cap)
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.cancellation()?;
        if let Some(e) = self.fault {
            return Err(e);
        }
        let operation = || {
            crate::rtw88::pci_park::invoke(self.cap, || self.packet_source())
                .map_err(|_| power::Error::Access)?
        };
        let result = if let Some(grant) = self.qualification {
            grant.with_current(operation)
        } else {
            operation()
        };
        self.latch(result)
    }
    fn dma_memory<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.current()?;
        let invoke = || {
            crate::rtw88::pci_park::invoke(self.cap, || {
                self.packet_source()?;
                operation()
            })
            .map_err(|_| Error::Io(power::Error::Access))
            .and_then(core::convert::identity)
        };
        let result = if let Some(grant) = self.qualification {
            grant.with_current(invoke)
        } else {
            invoke()
        };
        let result = result.and_then(|value| {
            self.current()?;
            Ok(value)
        });
        if result.is_err() {
            self.fault = Some(power::Error::Access);
        }
        result
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        let result = self
            .access(a, 1, false, |r, o| {
                // SAFETY: current original grant, exact source byte register and
                // checked mapping extent inside this invocation.
                unsafe { r.read8(o) }
            })
            .and_then(|value| {
                // UDM1+1 is two legitimate four-bit software counters;
                // both may be15. Control/trigger bytes cannot be all ones.
                (value != u8::MAX || a == 0x1f5)
                    .then_some(value)
                    .ok_or(power::Error::Gone)
            });
        self.latch(result)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access(a, 1, true, |r, o| {
            // SAFETY: current original grant, exact permitted source byte
            // register and mapped extent checked before this sole effect.
            unsafe { r.write8(o, v) }
        })
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        let result = self
            .access(a, 2, false, |r, o| {
                // SAFETY: current original grant, source whitelist, width/alignment
                // and mapping extent checked within this invocation.
                unsafe { r.read16(o) }
            })
            .and_then(|v| (v != u16::MAX).then_some(v).ok_or(power::Error::Gone));
        self.latch(result)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        let result = self
            .access(a, 4, false, |r, o| {
                // SAFETY: current original grant, source whitelist, width/alignment
                // and mapping extent checked within this invocation.
                unsafe { r.read32(o) }
            })
            .and_then(|v| (v != u32::MAX).then_some(v).ok_or(power::Error::Gone));
        self.latch(result)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access(a, 2, true, |r, o| {
            // SAFETY: current original grant, permitted source register, width,
            // alignment and mapping extent checked before this sole effect.
            unsafe { r.write16(o, v) }
        })
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        // This port can only stop all TX or unstop CH12, never enable an
        // ordinary TX channel or WPDMA. Source global DMA bits remain separate.
        if a == d::DMA_STOP1 && v & 0x8000_6fff != 0x8000_6fff {
            return self.latch(Err(power::Error::Access));
        }
        self.access(a, 4, true, |r, o| {
            // SAFETY: current original grant, permitted source register, width,
            // alignment and mapping extent checked before this sole effect.
            unsafe { r.write32(o, v) }
        })
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, us: u64) -> Result<(), power::Error> {
        self.current()?;
        if m == 0 || v & !m != 0 || !(1..=1_000_000).contains(&us) {
            return self.latch(Err(power::Error::Access));
        }
        let mut fault = None;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read32(a) {
                Ok(x) => x & m == v,
                Err(e) => {
                    fault = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        let result = match fault {
            Some(e) => Err(e),
            None if done => self.current(),
            None => Err(power::Error::Timeout),
        };
        self.latch(result)
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.current()?;
        if us > 5000 {
            return self.latch(Err(power::Error::Access));
        }
        let mut fault = None;
        let _ = narf_scheduler::responsive_spin_until(
            || match self.current() {
                Ok(()) => false,
                Err(e) => {
                    fault = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        let result = fault.map_or_else(|| self.current(), Err);
        self.latch(result)
    }
}

/// Direct disjoint borrows under one Prepared lock; no Rtw89Device callback
/// or recursive source-scope invocation. The retained native supervisor owns
/// the actual storage move and checked DLE/HFC/PCI composition. Descriptor
/// publication has an outer capability invocation plus per-register checks;
/// these capability checks acquire no Rtw89Device/source mutex.
pub(super) struct Port<'a, 'b> {
    owner: &'a mut Owner<DmaBuffer>,
    io: &'a mut Native<'b>,
}
impl<'a, 'b> Port<'a, 'b> {
    /// # Safety
    /// Same retained Cold/checked DMA owner and original function, actual signed
    /// NORMAL+BBMCU0 plans, no competing producer/reset/removal. Successful
    /// checked DLE/HFC/PCI prerequisites and separately invoked BME authority
    /// preceded enable_ch12. Held configuration never claims a sampled reset
    /// epoch or permits freeing legacy/prefetched payloads.
    pub(super) unsafe fn new(
        owner: &'a mut Owner<DmaBuffer>,
        io: &'a mut Native<'b>,
    ) -> Result<Self, Error> {
        owner.dma_current(io)?;
        Ok(Self { owner, io })
    }
}
impl cold::Regs for Port<'_, '_> {
    fn binding(&self) -> cold::Binding {
        self.io.binding()
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.io.current()
    }
    fn dma_memory<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.io.dma_memory(operation)
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.io.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.io.write32(a, v)
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, us: u64) -> Result<(), power::Error> {
        self.io.poll32(a, m, v, us)
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.io.delay_us(us)
    }
}
// SAFETY: Owner owns every ring/RX/payload mapping, retains before descriptor
// writes/doorbells, validates current raw RP and multitag8, pins on error/drop,
// and retirement requires its permanent original-controller held-stop/idle.
// Native invokes each current source once per actual bounded register effect.
// The retained CheckedPrepared/native supervisor supplies actual checked
// DLE/HFC/PCI/BME and original one-shot download ownership.
unsafe impl cold::DownloadPort for Port<'_, '_> {
    fn dma_current(&mut self) -> Result<(), power::Error> {
        self.owner.dma_current(self.io).map_err(|e| match e {
            Error::Io(e) => e,
            _ => power::Error::Access,
        })
    }
    fn submit_retained(&mut self, bytes: &[u8], fwdl: bool) -> Result<(), super::fwdl_be::Error> {
        use super::{fwcmd_8922a as fw, fwdl_be as f};
        let descriptor = fw::fwcmd_txdesc(bytes.len(), fwdl).ok_or(f::Error::Transport)?;
        let length = fw::FWCMD_TXDESC_LEN
            .checked_add(bytes.len())
            .ok_or(f::Error::Transport)?;
        let mut memory = narf_io::alloc_coherent_masked(
            length,
            narf_lib::id::DomainId::DRIVER_0,
            0xff_ffff_ffff,
        )
        .map_err(|_| f::Error::Transport)?;
        memory
            .write(0, &descriptor)
            .map_err(|_| f::Error::Transport)?;
        memory
            .write(fw::FWCMD_TXDESC_LEN, bytes)
            .map_err(|_| f::Error::Transport)?;
        self.io
            .submit_command(self.owner, memory)
            .map(|_| ())
            .map_err(|_| f::Error::Transport)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "checked_fwdl_8922a_tests.rs"]
mod tests;
