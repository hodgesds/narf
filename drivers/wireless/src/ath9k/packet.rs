// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! Retained AR9285 non-EDMA ownership. Rings end in NULL, never self-link.
use super::descriptor::{self, Mpdu, TxStatus, WORDS};
use alloc::vec::Vec;
use narf_io::DmaBuffer;
const STRIDE: usize = 128; // a96-byte descriptor never straddles a4KiB boundary.
const _: () = assert!(descriptor::BYTES <= STRIDE && 4096 % STRIDE == 0);
const RX_DEPTH: usize = 8;
const TX_DEPTH: usize = 2;
const RXDP: u64 = 0xc;
const CR: u64 = 8;
const QTXDP: u64 = 0x800;
const QTXE: u64 = 0x840;
const QTXD: u64 = 0x880;
const QSTS: u64 = 0xa00;
const DIAG: u64 = 0x8048;
const RX_PARK: u32 = 0x0200_0020;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Busy,
    Access,
    Address,
    Memory,
    Descriptor,
    Packet,
    Timeout,
}

#[cfg(feature = "kernel-test")]
#[path = "packet/tests.rs"]
pub(super) mod tests;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Running,
    Failed,
    Stopped,
}
pub(super) trait Port {
    fn tx_ba_grant(&self) -> Option<alloc::sync::Arc<super::tx_ba::Grant>> {
        None
    }
    fn ht_grant(&self) -> Option<alloc::sync::Arc<super::ht::Grant>> {
        None
    }
    fn rx_ba_grant(&self) -> Option<alloc::sync::Arc<super::rx_ba::Grant>> {
        None
    }
    fn transmit_allowed(&self) -> Result<(), Error>;
    /// Actual CPU payload/descriptor access occurs in current device invocation.
    fn access<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error>;
    fn read(&self, register: u64) -> Result<u32, Error>;
    fn write(&self, register: u64, value: u32) -> Result<(), Error>;
    fn allocate(&self, bytes: usize) -> Result<DmaBuffer, Error>;
    fn master(&self, enabled: bool) -> Result<(), Error>;
    fn now_us(&self) -> u64;
}
struct Memory(DmaBuffer);
impl Memory {
    fn address(&self) -> u32 {
        self.0.dma_addr().raw() as u32
    }
    fn sync(&self) {
        self.0.sync(0, self.0.len());
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(target_arch = "aarch64")]
        // SAFETY: orders this retained coherent CPU map against device ownership.
        unsafe {
            core::arch::asm!("dmb osh", options(nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "aarch64"))]
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    fn word(&self, byte: usize) -> Result<u32, Error> {
        if byte & 3 != 0 || byte.checked_add(4).is_none_or(|end| end > self.0.len()) {
            return Err(Error::Address);
        }
        // SAFETY: complete aligned dword in this owned CPU map, never DMA cast.
        Ok(u32::from_le(unsafe {
            self.0.cpu_ptr_at::<u32>(byte as u64).read_volatile()
        }))
    }
    fn put(&self, byte: usize, value: u32) -> Result<(), Error> {
        if byte & 3 != 0 || byte.checked_add(4).is_none_or(|end| end > self.0.len()) {
            return Err(Error::Address);
        }
        // SAFETY: checked owned CPU map; caller owns descriptor mutation phase.
        unsafe {
            self.0
                .cpu_mut_ptr_at::<u32>(byte as u64)
                .write_volatile(value.to_le());
        }
        Ok(())
    }
    fn words(&self, slot: usize) -> Result<[u32; WORDS], Error> {
        let start = slot.checked_mul(STRIDE).ok_or(Error::Address)?;
        let mut result = [0; WORDS];
        for (word, value) in result.iter_mut().enumerate() {
            *value = self.word(start + word * 4)?;
        }
        Ok(result)
    }
    fn put_words(&self, slot: usize, words: &[u32; WORDS]) -> Result<(), Error> {
        let start = slot.checked_mul(STRIDE).ok_or(Error::Address)?;
        for (word, value) in words.iter().copied().enumerate() {
            self.put(start + word * 4, value)?;
        }
        Ok(())
    }
    fn write_bytes(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.0.len() {
            return Err(Error::Address);
        }
        for (index, value) in bytes.iter().copied().enumerate() {
            // SAFETY: validated byte extent in this retained CPU allocation.
            unsafe {
                self.0
                    .cpu_mut_ptr_at::<u8>(index as u64)
                    .write_volatile(value);
            }
        }
        Ok(())
    }
    fn bytes(&self, length: usize) -> Result<Vec<u8>, Error> {
        if length > self.0.len() {
            return Err(Error::Address);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| Error::Memory)?;
        for index in 0..length {
            // SAFETY: complete payload extent in retained CPU map after sync.
            bytes.push(unsafe { self.0.cpu_ptr_at::<u8>(index as u64).read_volatile() });
        }
        Ok(bytes)
    }
}
struct Storage {
    tx: Memory,
    rx: Memory,
    tx_bytes: Vec<Memory>,
    rx_bytes: Vec<Memory>,
}
impl Storage {
    fn allocate(port: &impl Port) -> Result<Self, Error> {
        let mut blocks: Vec<Memory> = Vec::new();
        for length in [TX_DEPTH * STRIDE, RX_DEPTH * STRIDE]
            .into_iter()
            .chain(core::iter::repeat_n(descriptor::MAX_MPDU + 2, TX_DEPTH))
            .chain(core::iter::repeat_n(descriptor::RX_BYTES, RX_DEPTH))
        {
            let buffer = port.allocate(length)?;
            let address = buffer.dma_addr().raw();
            if buffer.len() < length
                || address == 0
                || address & 127 != 0
                || address
                    .checked_add(buffer.len() as u64 - 1)
                    .is_none_or(|end| end > u64::from(u32::MAX))
                || blocks.iter().any(|old| {
                    address < u64::from(old.address()) + old.0.len() as u64
                        && u64::from(old.address()) < address + buffer.len() as u64
                })
            {
                return Err(Error::Address);
            }
            blocks.push(Memory(buffer));
        }
        let mut blocks = blocks.into_iter();
        Ok(Self {
            tx: blocks.next().ok_or(Error::Memory)?,
            rx: blocks.next().ok_or(Error::Memory)?,
            tx_bytes: blocks.by_ref().take(TX_DEPTH).collect(),
            rx_bytes: blocks.collect(),
        })
    }
}
struct Pending {
    slot: usize,
    id: u64,
    length: usize,
    group: bool,
    words: [u32; WORDS],
    deadline: u64,
    original: Vec<u8>,
    dma: Vec<u8>,
}
struct PairPending {
    slots: [usize; 2],
    id: u64,
    words: [[u32; WORDS]; 2],
    originals: [Vec<u8>; 2],
    dma: [Vec<u8>; 2],
    seq: [u16; 2],
    deadline: u64,
}
pub(super) struct PairDelivery {
    pub id: u64,
    pub originals: [Vec<u8>; 2],
    pub acked: [bool; 2],
    pub feedback: super::rates::Feedback,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Delivery {
    pub id: u64,
    pub delivered: bool,
    pub bytes: Vec<u8>,
    pub feedback: super::rates::Feedback,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ReceiveStep {
    pub consumed: bool,
    pub frame: Option<Mpdu>,
}
pub(super) struct Packet<P: Port> {
    port: P,
    storage: Option<Storage>,
    phase: Phase,
    published: bool,
    local: [u8; 6],
    serial: u64,
    next_tx: usize,
    pending: Option<Pending>,
    pair: Option<PairPending>,
    head: usize,
    tail: usize,
    held: Option<usize>,
    next_rx: [Option<usize>; RX_DEPTH],
    ht: Option<super::ht::Profile>,
    slot_us: u32,
    edca: Option<u32>,
    ba: bool,
    tx_ba: bool,
}
impl<P: Port> core::fmt::Debug for Packet<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ar9285Packet")
            .field("phase", &self.phase)
            .field("published", &self.published)
            .finish_non_exhaustive()
    }
}
impl<P: Port> Drop for Packet<P> {
    fn drop(&mut self) {
        if self.published {
            core::mem::forget(self.storage.take());
        }
    }
}
impl<P: Port> Packet<P> {
    /// # Safety
    /// The same serialized owner identified and calibrated this AR9285, reset
    /// the complete key cache and configured legacy station MAC/queue0 while
    /// BME, RX, all TX queues and IRQ delivery remained off. No inherited DMA
    /// may refer to these fresh mappings. No other actor can start the engines.
    pub(super) unsafe fn prepare(port: P, local: [u8; 6]) -> Result<Self, Error> {
        if local[0] & 1 != 0 || local == [0; 6] {
            return Err(Error::Packet);
        }
        if port.read(CR)? & 4 != 0
            || port.read(QTXE)? & 0x3ff != 0
            || port.read(0x24)? & 1 != 0
            || port.read(DIAG)? & RX_PARK != RX_PARK
        {
            return Err(Error::State);
        }
        let storage = Storage::allocate(&port)?;
        let mut next_rx = [None; RX_DEPTH];
        port.access(false, || {
            for slot in 0..TX_DEPTH {
                storage.tx.put_words(slot, &[0; WORDS])?;
            }
            for (slot, next) in next_rx.iter_mut().enumerate() {
                *next = (slot + 1 < RX_DEPTH).then_some(slot + 1);
                let link = next.map_or(0, |index| {
                    u64::from(storage.rx.address()) + (index * STRIDE) as u64
                });
                let words = descriptor::receive_descriptor(
                    u64::from(storage.rx_bytes[slot].address()),
                    link,
                )
                .map_err(|_| Error::Descriptor)?;
                storage.rx.put_words(slot, &words)?;
                storage.rx_bytes[slot].sync();
            }
            storage.rx.sync();
            storage.tx.sync();
            Ok(())
        })?;
        Ok(Self {
            port,
            storage: Some(storage),
            phase: Phase::Prepared,
            published: false,
            local,
            serial: 0,
            next_tx: 0,
            pending: None,
            pair: None,
            head: 0,
            tail: RX_DEPTH - 1,
            held: None,
            next_rx,
            ht: None,
            slot_us: 20,
            edca: None,
            ba: false,
            tx_ba: false,
        })
    }
    pub(super) fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) fn check_transmit(&self) -> Result<(), Error> {
        self.port.transmit_allowed()?;
        if self.ht.is_some()
            && (self.port.read(0x1030)? != 8 * 44
                || self.port.read(0x1070)? != self.slot_us * 44
                || self.port.read(0x8014)? & 0x3fff_3fff != (64 * 44) | ((48 * 44) << 16)
                || self.port.read(0x801c)? & 0x7f != 43)
        {
            return Err(Error::Descriptor);
        }
        if let Some(word) = self.edca {
            if self.port.read(0x1040)? != word || self.port.read(0x10c0)? != 0 {
                return Err(Error::Descriptor);
            }
        }
        if self.ba {
            self.port
                .rx_ba_grant()
                .ok_or(Error::Access)?
                .readback(&self.port)?;
        }
        if self.tx_ba {
            self.port
                .tx_ba_grant()
                .ok_or(Error::Access)?
                .readback(&self.port)?;
        }
        if (self.ba || self.tx_ba)
            && self.port.read(0x803c)? != 0x17 | if self.ba { 0x400 } else { 0 }
        {
            return Err(Error::Descriptor);
        }
        self.port.access(self.phase != Phase::Prepared, || Ok(()))
    }
    pub(super) fn ht_grant(&self) -> Option<alloc::sync::Arc<super::ht::Grant>> {
        self.port.ht_grant()
    }
    pub(super) fn rx_ba_grant(&self) -> Option<alloc::sync::Arc<super::rx_ba::Grant>> {
        self.port.rx_ba_grant()
    }
    pub(super) fn tx_ba_grant(&self) -> Option<alloc::sync::Arc<super::tx_ba::Grant>> {
        self.port.tx_ba_grant()
    }
    pub(super) fn enable_tx_ba(
        &mut self,
        grant: &alloc::sync::Arc<super::tx_ba::Grant>,
    ) -> Result<(), Error> {
        if self.phase != Phase::Running
            || self.ht.is_none()
            || self.pending.is_some()
            || self.pair.is_some()
            || self.tx_ba
            || self
                .port
                .tx_ba_grant()
                .is_none_or(|g| !alloc::sync::Arc::ptr_eq(&g, grant))
        {
            return Err(Error::State);
        }
        grant.check()?;
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        let old = 0x17 | if self.ba { 0x400 } else { 0 };
        if self.port.read(0x803c)? != old {
            return Err(Error::Descriptor);
        }
        grant.readback(&self.port)?;
        self.tx_ba = true;
        self.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn enable_rx_ba(
        &mut self,
        grant: &alloc::sync::Arc<super::rx_ba::Grant>,
    ) -> Result<(), Error> {
        if self.phase != Phase::Running
            || self.ht.is_none()
            || self.ba
            || self.pending.is_some()
            || self.pair.is_some()
            || self
                .port
                .rx_ba_grant()
                .is_none_or(|g| !alloc::sync::Arc::ptr_eq(&g, grant))
        {
            return Err(Error::State);
        }
        grant.check()?;
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        let old = 0x17;
        if self.port.read(0x803c)? != old {
            return Err(Error::Descriptor);
        }
        self.port.write(0x803c, old | 0x400)?;
        grant.readback(&self.port)?;
        self.ba = true;
        self.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn set_ht(&mut self, profile: super::ht::Profile) -> Result<(), Error> {
        if self.phase != Phase::Running || self.pending.is_some() || self.ht.is_some() {
            return Err(Error::State);
        }
        let grant = self.port.ht_grant().ok_or(Error::Access)?;
        if profile.mcs() & !grant.mcs() != 0 {
            return Err(Error::Packet);
        }
        let be = profile.be();
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        grant.readback(&self.port)?;
        super::mac::edca(&self.port, be)?;
        grant.readback(&self.port)?;
        self.ht = Some(profile);
        self.edca =
            Some(u32::from(be.cw_min()) | u32::from(be.cw_max()) << 10 | u32::from(be.aifsn) << 20);
        self.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn observe_ht(
        &mut self,
        offer: &narf_wireless::association::phy::Offer,
        ies: &[u8],
        basic: usize,
    ) -> Result<(), Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.check_transmit()?;
        self.ht = Some(self.ht.ok_or(Error::State)?.observe(offer, ies, basic)?);
        Ok(())
    }
    pub(super) fn set_peer(
        &mut self,
        peer: Option<([u8; 6], u16)>,
        slot_us: u32,
    ) -> Result<(), Error> {
        if self.phase != Phase::Running || self.pending.is_some() {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        super::mac::peer(&self.port, peer, slot_us)?;
        self.slot_us = slot_us;
        self.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn start(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.port.access(false, || {
            for slot in 0..RX_DEPTH {
                let next = if slot + 1 < RX_DEPTH {
                    u64::from(storage.rx.address()) + ((slot + 1) * STRIDE) as u64
                } else {
                    0
                };
                let expected = descriptor::receive_descriptor(
                    u64::from(storage.rx_bytes[slot].address()),
                    next,
                )
                .map_err(|_| Error::Descriptor)?;
                storage.rx.sync();
                if storage.rx.words(slot)? != expected {
                    return Err(Error::Descriptor);
                }
            }
            Ok(())
        })?;
        // Retention starts before the first address write, including a failed
        // posted write. BME is enabled only after the owned RX list is named.
        self.published = true;
        self.port.write(RXDP, storage.rx.address())?;
        if self.port.read(RXDP)? != storage.rx.address() {
            return Err(Error::Descriptor);
        }
        self.port.master(true)?;
        self.port.write(CR, 4)?;
        let diag = self.port.read(DIAG)?;
        self.port.write(DIAG, diag & !RX_PARK)?;
        if self.port.read(CR)? & 4 == 0
            || self.port.read(DIAG)? & RX_PARK != 0
            || self.port.read(0x24)? & 1 != 0
        {
            return Err(Error::Descriptor);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn submit(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        let local = self.local;
        self.submit_inner(frame, |address| {
            descriptor::transmit(frame, local, address, rate)
        })
    }
    pub(super) fn submit_rates(
        &mut self,
        frame: &[u8],
        series: super::rates::Series,
    ) -> Result<u64, Error> {
        let local = self.local;
        self.submit_inner(frame, |address| {
            descriptor::transmit_series(frame, local, address, series)
        })
    }
    pub(super) fn submit_ba_response(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        if !self.ba {
            return Err(Error::State);
        }
        let local = self.local;
        self.submit_inner(frame, |address| {
            descriptor::transmit_ba_response(frame, local, address, rate)
        })
    }
    pub(super) fn submit_delba(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        if !self.ba {
            return Err(Error::State);
        }
        let local = self.local;
        self.submit_inner(frame, |address| {
            descriptor::transmit_delba(frame, local, address, rate)
        })
    }
    pub(super) fn submit_ht(&mut self, frame: &[u8], mcs: u8, basic: usize) -> Result<u64, Error> {
        if self.ht.is_none()
            || mcs > 7
            || self
                .port
                .ht_grant()
                .is_none_or(|g| g.mcs() & (1 << mcs) == 0)
        {
            return Err(Error::Packet);
        }
        let local = self.local;
        let profile = self.ht.ok_or(Error::State)?;
        self.submit_inner(frame, |address| {
            descriptor::transmit_ht(frame, local, address, mcs, basic, profile)
        })
    }
    pub(super) fn submit_sender_action(
        &mut self,
        frame: &[u8],
        basic: usize,
    ) -> Result<u64, Error> {
        if !self.tx_ba {
            return Err(Error::State);
        }
        let local = self.local;
        self.submit_inner(frame, |address| {
            super::descriptor::transmit_sender_action(frame, local, address, basic)
        })
    }
    pub(super) fn submit_bar(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error> {
        if !self.tx_ba {
            return Err(Error::State);
        }
        let local = self.local;
        self.submit_inner(frame, |address| {
            super::descriptor::transmit_bar(frame, local, address, basic)
        })
    }
    pub(super) fn submit_pair(
        &mut self,
        frames: &[Vec<u8>; 2],
        mcs: u8,
        basic: usize,
        permit: super::tx_ba::PairPermit,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running || !self.tx_ba {
            return Err(Error::State);
        }
        if self.pending.is_some() || self.pair.is_some() {
            return Err(Error::Busy);
        }
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        let slots = [self.next_tx, (self.next_tx + 1) % TX_DEPTH];
        let words = descriptor::transmit_pair(
            [&frames[0], &frames[1]],
            self.local,
            descriptor::PairAddresses {
                payloads: slots.map(|s| u64::from(storage.tx_bytes[s].address())),
                tail: u64::from(storage.tx.address()) + (slots[1] * STRIDE) as u64,
            },
            mcs,
            basic,
            self.ht.ok_or(Error::State)?,
            permit,
        )
        .map_err(|_| Error::Packet)?;
        let dma = [
            descriptor::dma_bytes(&frames[0]).map_err(|_| Error::Packet)?,
            descriptor::dma_bytes(&frames[1]).map_err(|_| Error::Packet)?,
        ];
        let originals = frames.clone();
        let id = self.serial.checked_add(1).ok_or(Error::State)?;
        let deadline = self
            .port
            .now_us()
            .checked_add(1_000_000)
            .ok_or(Error::Timeout)?;
        self.phase = Phase::Failed;
        self.check_transmit()?;
        if self.port.read(QTXE)? & 1 != 0 || self.port.read(QSTS)? & 3 != 0 {
            return Err(Error::Descriptor);
        }
        self.port.access(true, || {
            for i in 0..2 {
                storage.tx_bytes[slots[i]].write_bytes(&dma[i])?;
                storage.tx_bytes[slots[i]].sync();
                storage.tx.put_words(slots[i], &words[i])?;
            }
            storage.tx.sync();
            Ok(())
        })?;
        self.serial = id;
        self.pair = Some(PairPending {
            slots,
            id,
            words,
            originals,
            dma,
            seq: permit.seq,
            deadline,
        });
        let address = storage.tx.address() + (slots[0] * STRIDE) as u32;
        self.port.write(QTXDP, address)?;
        if self.port.read(QTXDP)? != address {
            return Err(Error::Descriptor);
        }
        self.port.transmit_allowed()?;
        self.port.write(QTXE, 1)?;
        self.phase = Phase::Running;
        Ok(id)
    }
    pub(super) fn pair_delivery(&mut self) -> Result<Option<PairDelivery>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let Some(p) = self.pair.as_ref() else {
            return Ok(None);
        };
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.check_transmit()?;
        let result = self.port.access(true, || {
            storage.tx.sync();
            if storage
                .tx
                .word(p.slots[1] * STRIDE + descriptor::TX_DONE * 4)?
                & 1
                == 0
            {
                if self.port.now_us() >= p.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(None);
            }
            storage.tx.sync();
            let words = [storage.tx.words(p.slots[0])?, storage.tx.words(p.slots[1])?];
            for (i, w) in words.iter().enumerate() {
                if w[..14] != p.words[i][..14] {
                    return Err(Error::Descriptor);
                }
                storage.tx_bytes[p.slots[i]].sync();
                if storage.tx_bytes[p.slots[i]].bytes(p.dma[i].len())? != p.dma[i] {
                    return Err(Error::Descriptor);
                }
            }
            if self.port.read(QTXE)? & 1 != 0 || self.port.read(QSTS)? & 3 != 0 {
                if self.port.now_us() >= p.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(None);
            }
            let (acked, feedback) = descriptor::pair_status(&words[0], &words[1], p.seq)
                .map_err(|_| Error::Descriptor)?;
            Ok(Some(PairDelivery {
                id: p.id,
                originals: p.originals.clone(),
                acked,
                feedback,
            }))
        })?;
        if result.is_some() {
            self.pair = None;
            self.next_tx = (self.next_tx + 2) % TX_DEPTH;
        }
        self.phase = Phase::Running;
        Ok(result)
    }
    fn submit_inner(
        &mut self,
        frame: &[u8],
        encode: impl FnOnce(u64) -> Result<[u32; WORDS], descriptor::Error>,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.pending.is_some() || self.pair.is_some() {
            return Err(Error::Busy);
        }
        let slot = self.next_tx;
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        let words =
            encode(u64::from(storage.tx_bytes[slot].address())).map_err(|_| Error::Packet)?;
        let dma = descriptor::dma_bytes(frame).map_err(|_| Error::Packet)?;
        self.phase = Phase::Failed;
        self.check_transmit()?;
        if self.port.read(QTXE)? & 1 != 0 || self.port.read(QSTS)? & 3 != 0 {
            // No Pending owner exists here. A live queue is ambiguous DMA,
            // not reusable credit after restoring a policy or status word.
            return Err(Error::Descriptor);
        }
        let id = self.serial.checked_add(1).ok_or(Error::State)?;
        let deadline = self
            .port
            .now_us()
            .checked_add(1_000_000)
            .ok_or(Error::Timeout)?;
        self.phase = Phase::Failed;
        self.port.access(true, || {
            storage.tx_bytes[slot].write_bytes(&dma)?;
            storage.tx_bytes[slot].sync();
            storage.tx.put_words(slot, &words)?;
            storage.tx.sync();
            Ok(())
        })?;
        self.serial = id;
        self.pending = Some(Pending {
            slot,
            id,
            length: dma.len(),
            group: frame[4] & 1 != 0,
            words,
            deadline,
            original: frame.to_vec(),
            dma,
        });
        self.port
            .write(QTXDP, storage.tx.address() + (slot * STRIDE) as u32)?;
        if self.port.read(QTXDP)? != storage.tx.address() + (slot * STRIDE) as u32 {
            return Err(Error::Descriptor);
        }
        self.port.transmit_allowed()?;
        self.port.write(QTXE, 1)?;
        self.phase = Phase::Running;
        Ok(id)
    }
    pub(super) fn delivery(&mut self) -> Result<Option<Delivery>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let Some(pending) = self.pending.as_ref() else {
            return Ok(None);
        };
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.check_transmit()?;
        let delivery = self.port.access(true, || {
            storage.tx.sync();
            let done = storage
                .tx
                .word(pending.slot * STRIDE + descriptor::TX_DONE * 4)?;
            if done & 1 == 0 {
                if self.port.now_us() >= pending.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(None);
            }
            // Completion is the device's ownership release. Acquire it before
            // fetching the other status words or payload, including on ARM.
            storage.tx.sync();
            let words = storage.tx.words(pending.slot)?;
            if words[..14] != pending.words[..14] {
                return Err(Error::Descriptor);
            }
            let result = if pending.original.first() == Some(&0x84) {
                descriptor::bar_status(&words, &pending.original)
            } else {
                descriptor::transmit_status(&words, pending.group)
            }
            .map_err(|_| Error::Descriptor)?;
            if result == TxStatus::Pending {
                if self.port.now_us() >= pending.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(None);
            }
            if self.port.read(QTXE)? & 1 != 0 || self.port.read(QSTS)? & 3 != 0 {
                if self.port.now_us() >= pending.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(None);
            }
            storage.tx_bytes[pending.slot].sync();
            if storage.tx_bytes[pending.slot].bytes(pending.length)? != pending.dma {
                return Err(Error::Descriptor);
            }
            Ok(Some(Delivery {
                id: pending.id,
                delivered: result == TxStatus::Delivered,
                bytes: pending.original.clone(),
                feedback: descriptor::transmit_feedback(&words).map_err(|_| Error::Descriptor)?,
            }))
        })?;
        if delivery.is_some() {
            self.pending = None;
            self.next_tx = (self.next_tx + 1) % TX_DEPTH;
        }
        self.phase = Phase::Running;
        Ok(delivery)
    }
    pub(super) fn receive(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let slot = self.head;
        // Keep the last processed descriptor held until a successor completes;
        // Linux's buf_hold prevents descriptor prefetch from racing rearm.
        if self.held == Some(slot) {
            return Ok(ReceiveStep {
                consumed: false,
                frame: None,
            });
        }
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.check_transmit()?;
        let (consumed, frame) = self.port.access(true, || {
            storage.rx.sync();
            if storage.rx.word(slot * STRIDE + descriptor::RX_DONE * 4)? & 1 == 0 {
                return Ok((false, None));
            }
            // Read the terminal ownership bit before the DMA status snapshot.
            storage.rx.sync();
            let words = storage.rx.words(slot)?;
            let next = self.next_rx[slot].ok_or(Error::Descriptor)?;
            let expected = u64::from(storage.rx.address()) + (next * STRIDE) as u64;
            if u64::from(words[0]) != expected
                || words[1] != storage.rx_bytes[slot].address()
                || words[2] != 0
                || words[3] != descriptor::RX_BYTES as u32
            {
                return Err(Error::Descriptor);
            }
            let length = (words[5] & 0xfff) as usize;
            if length > descriptor::RX_BYTES {
                return Err(Error::Descriptor);
            }
            storage.rx_bytes[slot].sync();
            let payload = storage.rx_bytes[slot].bytes(length)?;
            let frame = if self.ba {
                descriptor::receive_ba(&words, &payload, self.ht.ok_or(Error::State)?)
            } else if let Some(profile) = self.ht {
                descriptor::receive_profile(&words, &payload, profile)
            } else {
                descriptor::receive(&words, &payload)
            }
            .map_err(|_| Error::Descriptor)?;
            if let Some(held) = self.held {
                let reset =
                    descriptor::receive_descriptor(u64::from(storage.rx_bytes[held].address()), 0)
                        .map_err(|_| Error::Descriptor)?;
                storage.rx.put_words(held, &reset)?;
                storage.rx_bytes[held].sync();
                storage.rx.sync();
                // Complete the fresh descriptor before linking the old tail.
                storage.rx.put(
                    self.tail * STRIDE,
                    storage.rx.address() + (held * STRIDE) as u32,
                )?;
                storage.rx.sync();
                self.port.write(CR, 4)?;
            }
            Ok((true, frame))
        })?;
        if consumed {
            self.head = self.next_rx[slot].ok_or(Error::Descriptor)?;
            if let Some(held) = self.held {
                self.next_rx[held] = None;
                self.next_rx[self.tail] = Some(held);
                self.tail = held;
            }
            self.held = Some(slot);
        }
        self.phase = Phase::Running;
        Ok(ReceiveStep { consumed, frame })
    }
    /// Close every independent packet gate, trying the PCI gate even if BAR
    /// access failed. This terminal park never claims a reclamation proof.
    pub(super) fn stop(&mut self) -> Result<(), Error> {
        if self.phase == Phase::Stopped {
            return Err(Error::State);
        }
        self.phase = Phase::Stopped;
        let diag = self
            .port
            .read(DIAG)
            .and_then(|value| self.port.write(DIAG, value | RX_PARK));
        let rx = self.port.write(CR, 0x20);
        let tx = self.port.write(QTXD, 0x3ff);
        let irq = self.port.write(0x24, 0);
        let master = self.port.master(false);
        diag.and(rx).and(tx).and(irq).and(master)
    }
}
