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
//! The AR9300 EDMA packet DMA owner, parallel to (and independent of) the
//! AR9002 `packet::Packet`: it allocates the TX status ring
//! (`xmit.c::ath_tx_edma_init`), the `ar9003_txc` descriptors, the payload
//! buffers and the high/low priority receive FIFO buffers
//! (`recv.c::ath_rx_edma_init`), programs `AR_Q_STATUS_RING_*` and
//! `AR_DATABUF_SIZE` while every engine is off, then follows
//! `ath_edma_start_recv` (`ar9003_hw_rx_enable` writes `AR_CR` 0, both
//! FIFOs fed by `ath_rx_edma_buf_link`, `ath9k_hw_startpcureceive`),
//! `ath_tx_txqaddbuf` (EDMA: `ath9k_hw_puttxbuf` pushes the QCU FIFO, no
//! `AR_Q_TXE`), `ath_tx_edma_tasklet` (status ring) and `ath_edma_get_buffers`
//! (HP before LP, `ath_rx_tasklet` order) to the terminal
//! `ath_stoprecv`/`ath9k_hw_stopdmarecv` (`AR_CR_RXE` 0xc poll, no
//! pre-AR9300 DMADBG hang test) and `ath_drain_all_txq` stop.
//!
//! One queue-0 frame is in flight at a time, as in the AR9002 owner. The
//! `ar9003_txs` status words 3 and 8 and the `ar9003_rxs` status words
//! 1..5 and 11 carry exactly the AR5416 `ds_txstatus1`/`ds_txstatus9` and
//! `ds_rxstatus0..4`/`ds_rxstatus8` layouts (`ar9003_mac.h` against
//! `mac.h`), and `ctl11..18`/`ctl20..22` the AR5416 `ctl0..7`/`ctl9..11`
//! fields, so the legacy frame encoder and the RX/TX admission of the
//! shared `descriptor` module apply unchanged; only the container differs.
//! Policy over Linux: a multi-buffer (`rs_more`) receive is dropped
//! together with its continuation buffers instead of being reassembled, a
//! corrupt (`-EINVAL`) receive status or a foreign status-ring entry fails
//! the owner instead of being skipped, and the receive buffers are one
//! 4 KiB page (4048 data bytes, the AR9002 owner's single-buffer bound)
//! instead of `IEEE80211_MAX_MPDU_LEN / 2`.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::edma::{self, RxQueue, Series, StatusRing, TxInfo, RXS_BYTES, TXC_WORDS, TXS_WORDS};
use super::irq;
use crate::ath9k::descriptor::{self, TxStatus as LegacyStatus, WORDS};
use crate::ath9k::identity::{BringUpError, RegisterIo};
use crate::ath9k::packet::{Delivery, Error, Phase, Port, ReceiveStep};
use alloc::vec::Vec;
use narf_io::DmaBuffer;

/// One `ar9003_txc` (128 bytes, so it never straddles a 4 KiB boundary).
const TXC_BYTES: usize = TXC_WORDS * 4;
const TX_DEPTH: usize = 2;
/// Entries of the TX status ring (Linux uses `ATH_TXSTATUS_RING_SIZE`
/// 512; one frame in flight needs far fewer, any size is valid hardware).
const TS_ENTRIES: usize = 16;
const TXS_BYTES: usize = TXS_WORDS * 4;
/// Receive buffers posted per FIFO (at most `RX_HP_QDEPTH`/`RX_LP_QDEPTH`).
const RX_HP: usize = 4;
const RX_LP: usize = 8;
const RX_BUFFER: usize = 4096;
/// `ath9k_hw_set_rx_bufsize(rx_bufsize - rx_status_len)`.
const RX_DATA: u16 = (RX_BUFFER - RXS_BYTES) as u16;
const _: () = assert!(RX_HP <= edma::RX_HP_QDEPTH && RX_LP <= edma::RX_LP_QDEPTH);
const _: () = assert!((RX_DATA as usize) <= 0xfff && TXC_BYTES == 128);

const CR: u64 = 8;
/// `AR_CR_RXE(ah)` for `AR_SREV_9300_20_OR_LATER` (HP | LP enables).
const CR_RXE: u32 = 0xc;
const CR_RXD: u32 = 0x20;
const QTXDP: u64 = 0x800;
const QTXE: u64 = 0x840;
const QTXD: u64 = 0x880;
const QSTS: u64 = 0xa00;
const DIAG: u64 = 0x8048;
const RX_PARK: u32 = 0x0200_0020;
const RX_FILTER: u64 = 0x803c;
const PCU_MISC: u64 = 0x8120;
const PCU_QUIET: u32 = 0x0004_0000 | 0x0100_0000;
const DIAG_IDLE_HIGH: u32 = 0x0100_0000;
const IFS_MISC: u64 = 0x10f0;
const IGNORE_BACKOFF: u32 = 0x1000_0000;
const QUEUES: u64 = 10;
const RX_STOP_POLLS: u32 = 1000;
const TX_ABORT_POLLS: u32 = 1000;
const MACMISC: u64 = 0x0058;
const Q_STATUS_RING_START: u64 = 0x0830;
const Q_STATUS_RING_END: u64 = 0x0834;
const DATABUF_SIZE: u64 = 0x0060;

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
    fn words<const N: usize>(&self, start: usize) -> Result<[u32; N], Error> {
        let mut result = [0; N];
        for (index, value) in result.iter_mut().enumerate() {
            *value = self.word(start + index * 4)?;
        }
        Ok(result)
    }
    fn put_words(&self, start: usize, words: &[u32]) -> Result<(), Error> {
        for (index, value) in words.iter().copied().enumerate() {
            self.put(start + index * 4, value)?;
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
    fn bytes(&self, start: usize, length: usize) -> Result<Vec<u8>, Error> {
        if start
            .checked_add(length)
            .is_none_or(|end| end > self.0.len())
        {
            return Err(Error::Address);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| Error::Memory)?;
        for index in start..start + length {
            // SAFETY: complete extent in the retained CPU map after sync.
            bytes.push(unsafe { self.0.cpu_ptr_at::<u8>(index as u64).read_volatile() });
        }
        Ok(bytes)
    }
}

struct Storage {
    tx: Memory,
    status: Memory,
    tx_bytes: Vec<Memory>,
    /// `RX_HP` high-priority then `RX_LP` low-priority buffers.
    rx: Vec<Memory>,
}
impl Storage {
    fn allocate(port: &impl Port) -> Result<Self, Error> {
        let mut blocks: Vec<Memory> = Vec::new();
        for length in [TX_DEPTH * TXC_BYTES, TS_ENTRIES * TXS_BYTES]
            .into_iter()
            .chain(core::iter::repeat_n(descriptor::MAX_MPDU + 2, TX_DEPTH))
            .chain(core::iter::repeat_n(RX_BUFFER, RX_HP + RX_LP))
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
            status: blocks.next().ok_or(Error::Memory)?,
            tx_bytes: blocks.by_ref().take(TX_DEPTH).collect(),
            rx: blocks.collect(),
        })
    }
}

/// `RegisterIo` over a packet `Port`: the first failure is retained and
/// every later access is suppressed (reads return the removed-card value).
struct Io<'a, P: Port> {
    port: &'a P,
    error: Option<Error>,
}
impl<P: Port> RegisterIo for Io<'_, P> {
    fn authorized(&self) -> bool {
        self.error.is_none()
    }
    fn read32(&mut self, offset: u64) -> u32 {
        if self.error.is_some() {
            return u32::MAX;
        }
        self.port.read(offset).unwrap_or_else(|error| {
            self.error = Some(error);
            u32::MAX
        })
    }
    fn write32(&mut self, offset: u64, value: u32) {
        if self.error.is_none() {
            if let Err(error) = self.port.write(offset, value) {
                self.error = Some(error);
            }
        }
    }
}
fn with_io<P: Port, T>(
    port: &P,
    operation: impl FnOnce(&mut Io<'_, P>) -> Result<T, BringUpError>,
) -> Result<T, Error> {
    let mut io = Io { port, error: None };
    let result = operation(&mut io);
    if let Some(error) = io.error {
        return Err(error);
    }
    result.map_err(|_| Error::Descriptor)
}

/// The `ar9003_txc` of a legacy AR5416-layout control block (`ctl0..11` in
/// words 2..13) for QCU 0, with `chains` as every series' `ChainSel`.
fn control(legacy: &[u32; WORDS], chains: u8) -> Result<TxInfo, Error> {
    let [ctl0, ctl1, ctl2, ctl3, ctl4, ctl5, ctl6, ctl7] =
        <[u32; 8]>::try_from(&legacy[2..10]).map_err(|_| Error::Packet)?;
    // Single-buffer, unaggregated, no key-cache index.
    if ctl1 & 0x1000 != 0 || ctl1 & 0x6000_0000 != 0 || ctl6 != 0 || ctl0 & 0x4000_0000 != 0 {
        return Err(Error::Packet);
    }
    if !(1..=7).contains(&chains) {
        return Err(Error::Packet);
    }
    let bit = |word: u32, mask: u32, flag: u32| if word & mask != 0 { flag } else { 0 };
    let flags = bit(ctl1, 0x100_0000, edma::flag::NOACK)
        | bit(ctl0, 0x40_0000, edma::flag::RTSENA)
        | bit(ctl0, 0x8000_0000, edma::flag::CTSENA)
        | bit(ctl0, 0x80_0000, edma::flag::VEOL)
        | bit(ctl1, 0x800_0000, edma::flag::EXT_ONLY)
        | bit(ctl1, 0x1000_0000, edma::flag::EXT_AND_CTL)
        | bit(ctl0, 0x1000, edma::flag::VMF)
        | bit(ctl0, 0x100_0000, edma::flag::CLRDMASK);
    let rates = core::array::from_fn(|i| {
        let tries = ((ctl2 >> (16 + 4 * i)) & 0xf) as u8;
        let duration = if i < 2 { ctl4 } else { ctl5 } >> (16 * (i % 2));
        Series {
            tries,
            rate: (ctl3 >> (8 * i)) as u8,
            packet_duration: (duration & 0x7fff) as u16,
            chain_select: if tries != 0 { chains } else { 0 },
            rts_cts: duration & 0x8000 != 0,
            ht40: ctl7 & (1 << (5 * i)) != 0,
            half_gi: ctl7 & (1 << (1 + 5 * i)) != 0,
            stbc: ctl7 & (1 << (28 + i)) != 0,
        }
    });
    Ok(TxInfo {
        qcu: 0,
        link: 0,
        buffers: [(legacy[1], (ctl1 & 0xfff) as u16), (0, 0), (0, 0), (0, 0)],
        is_first: true,
        is_last: true,
        pkt_len: (ctl0 & 0xfff) as u16,
        frame_type: ((ctl1 >> 20) & 0xf) as u8,
        flags,
        keyix: None,
        dur_update: ctl2 & 0x8000 != 0,
        rates,
        rtscts_rate: (ctl7 >> 20) as u8,
        txpower: [
            ((ctl0 >> 16) & 0x3f) as u8,
            ((legacy[11] >> 24) & 0x3f) as u8,
            ((legacy[12] >> 24) & 0x3f) as u8,
            ((legacy[13] >> 24) & 0x3f) as u8,
        ],
    })
}

struct Pending {
    slot: usize,
    id: u64,
    length: usize,
    group: bool,
    legacy: [u32; WORDS],
    words: [u32; TXC_WORDS],
    deadline: u64,
    original: Vec<u8>,
    dma: Vec<u8>,
}

/// One receive FIFO: buffer indices in hardware consumption order.
struct Fifo {
    queue: RxQueue,
    order: Vec<usize>,
    /// Dropping the continuation buffers of an `rs_more` chain.
    discarding: bool,
}

pub(in crate::ath9k) struct Packet<P: Port> {
    port: P,
    storage: Option<Storage>,
    ring: StatusRing,
    phase: Phase,
    published: bool,
    local: [u8; 6],
    serial: u64,
    next_tx: usize,
    pending: Option<Pending>,
    fifos: [Fifo; 2],
    reclaimed: bool,
    irq: Option<irq::Mask>,
    full_imr: u32,
}
impl<P: Port> core::fmt::Debug for Packet<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ar9300Packet")
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
    /// The same serialized owner identified, prepared and calibrated this
    /// AR9300 and configured the legacy station MAC/queue 0 while bus
    /// mastering, both receive FIFOs, every TX queue and IRQ delivery were
    /// off. No inherited DMA may refer to these fresh mappings and no other
    /// actor can start the engines.
    pub(in crate::ath9k) unsafe fn prepare(port: P, local: [u8; 6]) -> Result<Self, Error> {
        if local[0] & 1 != 0 || local == [0; 6] {
            return Err(Error::Packet);
        }
        if port.read(CR)? & CR_RXE != 0
            || port.read(QTXE)? & 0x3ff != 0
            || port.read(irq::IER)? & 1 != 0
            || port.read(DIAG)? & RX_PARK != RX_PARK
        {
            return Err(Error::State);
        }
        let storage = Storage::allocate(&port)?;
        port.access(false, || {
            storage.tx.put_words(0, &[0; TX_DEPTH * TXC_WORDS])?;
            // ath9k_hw_reset_txstatus_ring: the entries start cleared.
            storage.status.put_words(0, &[0; TS_ENTRIES * TXS_WORDS])?;
            for buffer in &storage.rx {
                buffer.put_words(0, &[0; RXS_BYTES / 4])?;
                buffer.sync();
            }
            storage.status.sync();
            storage.tx.sync();
            Ok(())
        })?;
        let start = storage.status.address();
        let ring = with_io(&port, |io| {
            let ring = StatusRing::setup(io, start, TS_ENTRIES as u16)?;
            edma::set_rx_bufsize(io, RX_DATA)?;
            Ok(ring)
        })?;
        if port.read(Q_STATUS_RING_START)? != start
            || port.read(Q_STATUS_RING_END)? != start + (TS_ENTRIES * TXS_BYTES) as u32
            || port.read(DATABUF_SIZE)? & 0xfff != u32::from(RX_DATA)
        {
            return Err(Error::Descriptor);
        }
        Ok(Self {
            port,
            storage: Some(storage),
            ring,
            phase: Phase::Prepared,
            published: false,
            local,
            serial: 0,
            next_tx: 0,
            pending: None,
            fifos: [
                Fifo {
                    queue: RxQueue::High,
                    order: (0..RX_HP).collect(),
                    discarding: false,
                },
                Fifo {
                    queue: RxQueue::Low,
                    order: (RX_HP..RX_HP + RX_LP).collect(),
                    discarding: false,
                },
            ],
            reclaimed: false,
            irq: None,
            full_imr: 0,
        })
    }
    pub(in crate::ath9k) fn phase(&self) -> Phase {
        self.phase
    }
    /// True only after the terminal stop proved every RX/TX DMA engine idle
    /// with bus mastering off and released the packet allocations.
    pub(in crate::ath9k) fn reclaimed(&self) -> bool {
        self.reclaimed
    }
    pub(in crate::ath9k) fn idle_admissible(&self) -> bool {
        self.phase == Phase::Running && self.pending.is_none()
    }
    /// `ath_edma_start_recv`: `ar9003_hw_rx_enable`, both FIFOs fed
    /// (`ath_rx_addbuffer_edma` HP then LP), bus mastering, then
    /// `ath9k_hw_startpcureceive` clears `AR_DIAG_RX_DIS | RX_ABORT`.
    pub(in crate::ath9k) fn start(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.port.access(false, || {
            for buffer in &storage.rx {
                buffer.sync();
                if buffer.words::<{ RXS_BYTES / 4 }>(0)? != [0; RXS_BYTES / 4] {
                    return Err(Error::Descriptor);
                }
            }
            Ok(())
        })?;
        // Retention starts before the first FIFO push, including a failed
        // posted write. BME is enabled only after both FIFOs are named.
        self.published = true;
        self.port.write(CR, 0)?;
        for fifo in &self.fifos {
            for &index in &fifo.order {
                let address = storage.rx[index].address();
                with_io(&self.port, |io| {
                    edma::add_rx_buffer(io, fifo.queue, address)
                })?;
            }
        }
        self.port.master(true)?;
        let diag = self.port.read(DIAG)?;
        self.port.write(DIAG, diag & !RX_PARK)?;
        if self.port.read(DIAG)? & RX_PARK != 0 || self.port.read(irq::IER)? & 1 != 0 {
            return Err(Error::Descriptor);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    /// The AR9002 `Packet::check_transmit` without the HT/EDCA/QoS/BA
    /// programs this owner does not carry: the port's transmit permission
    /// and its physical re-proof.
    pub(in crate::ath9k) fn check_transmit(&self) -> Result<(), Error> {
        self.port.transmit_allowed()?;
        self.port.access(self.phase != Phase::Prepared, || Ok(()))
    }
    /// `ath9k_bss_info_changed` BSSID/AID and slot time
    /// (`ath9k_hw_write_associd`, `ath9k_hw_setslottime` at the band's
    /// `ath9k_hw_set_clockrate` clock), as the AR9002 owner does.
    pub(in crate::ath9k) fn set_peer(
        &mut self,
        peer: Option<([u8; 6], u16)>,
        slot_us: u32,
    ) -> Result<(), Error> {
        if self.phase != Phase::Running || self.pending.is_some() {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        crate::ath9k::mac::peer_clocked(&self.port, peer, slot_us, self.port.mac_clock())?;
        self.phase = Phase::Running;
        Ok(())
    }
    /// The port's periodic calibration step of a running owner with no
    /// transmission in flight (`ath_ani_calibrate` runs from its own timer;
    /// this owner serializes it against the single queue-0 frame).
    pub(in crate::ath9k) fn long_calibration(&mut self) -> Result<Option<i32>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.port.long_calibration()
    }
    /// Legacy frame at `rate` (`descriptor::transmit`).
    pub(in crate::ath9k) fn submit(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        let local = self.local;
        self.submit_with(frame, |address| {
            descriptor::transmit(frame, local, address, rate)
        })
    }
    /// Legacy frame with a rate-control series (`descriptor::transmit_series`).
    pub(in crate::ath9k) fn submit_rates(
        &mut self,
        frame: &[u8],
        series: crate::ath9k::rates::Series,
    ) -> Result<u64, Error> {
        let local = self.local;
        self.submit_with(frame, |address| {
            descriptor::transmit_series(frame, local, address, series)
        })
    }
    fn submit_with(
        &mut self,
        frame: &[u8],
        encode: impl FnOnce(u64) -> Result<[u32; WORDS], descriptor::Error>,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let slot = self.next_tx;
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        let legacy =
            encode(u64::from(storage.tx_bytes[slot].address())).map_err(|_| Error::Packet)?;
        // xmit.c::ath_buf_set_rate: the port supplies the reduced
        // (`ath_txchainmask_reduction`) TX chain mask.
        let words = edma::tx_control(&control(&legacy, self.port.tx_chainmask())?);
        let dma = descriptor::dma_bytes(frame).map_err(|_| Error::Packet)?;
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        if self.port.read(QTXE)? & 1 != 0 || self.port.read(QSTS)? & 3 != 0 {
            // No Pending owner exists: a live queue is ambiguous DMA.
            return Err(Error::Descriptor);
        }
        let id = self.serial.checked_add(1).ok_or(Error::State)?;
        let deadline = self
            .port
            .now_us()
            .checked_add(1_000_000)
            .ok_or(Error::Timeout)?;
        self.port.access(true, || {
            storage.tx_bytes[slot].write_bytes(&dma)?;
            storage.tx_bytes[slot].sync();
            storage.tx.put_words(slot * TXC_BYTES, &words)?;
            storage.tx.sync();
            Ok(())
        })?;
        self.serial = id;
        self.pending = Some(Pending {
            slot,
            id,
            length: dma.len(),
            group: frame[4] & 1 != 0,
            legacy,
            words,
            deadline,
            original: frame.to_vec(),
            dma,
        });
        self.port.transmit_allowed()?;
        // ath9k_hw_puttxbuf: the EDMA QTXDP write is a FIFO push (never
        // read back) and starts the queue without AR_Q_TXE.
        self.port
            .write(QTXDP, storage.tx.address() + (slot * TXC_BYTES) as u32)?;
        self.phase = Phase::Running;
        Ok(id)
    }
    /// `ath_tx_edma_tasklet` for the queue-0 frame in flight.
    pub(in crate::ath9k) fn delivery(&mut self) -> Result<Option<Delivery>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let Some(pending) = self.pending.as_ref() else {
            return Ok(None);
        };
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        let mut ring = self.ring;
        let delivery = self.port.access(true, || {
            let offset = usize::from(ring.tail) * TXS_BYTES;
            storage.status.sync();
            if storage.status.word(offset + 8 * 4)? & 1 == 0 {
                if self.port.now_us() >= pending.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(None);
            }
            // AR_TxDone is the device's ownership release; acquire it before
            // the other status words and the payload, including on ARM.
            storage.status.sync();
            let raw = storage.status.words::<TXS_WORDS>(offset)?;
            let mut entry = raw;
            let status = ring
                .process(&mut entry)
                .map_err(|_| Error::Descriptor)?
                .ok_or(Error::Descriptor)?;
            // ath9k_hw_clear_txstatus.
            storage.status.put_words(offset, &entry)?;
            storage.status.sync();
            if status.qid != 0 {
                return Err(Error::Descriptor);
            }
            if storage.tx.words::<TXC_WORDS>(pending.slot * TXC_BYTES)? != pending.words {
                return Err(Error::Descriptor);
            }
            let mut words = pending.legacy;
            words[15] = raw[3];
            words[descriptor::TX_DONE] = raw[8];
            let result = descriptor::transmit_status(&words, pending.group)
                .map_err(|_| Error::Descriptor)?;
            if result == LegacyStatus::Pending {
                return Err(Error::Descriptor);
            }
            storage.tx_bytes[pending.slot].sync();
            if storage.tx_bytes[pending.slot].bytes(0, pending.length)? != pending.dma {
                return Err(Error::Descriptor);
            }
            Ok(Some(Delivery {
                id: pending.id,
                delivered: result == LegacyStatus::Delivered,
                bytes: pending.original.clone(),
                feedback: descriptor::transmit_feedback(&words).map_err(|_| Error::Descriptor)?,
            }))
        })?;
        self.ring = ring;
        if delivery.is_some() {
            // The completed frame left the QCU; nothing else was queued.
            if self.port.read(QSTS)? & 3 != 0 {
                return Err(Error::Descriptor);
            }
            self.pending = None;
            self.next_tx = (self.next_tx + 1) % TX_DEPTH;
        }
        self.phase = Phase::Running;
        Ok(delivery)
    }
    /// `ath_edma_get_buffers` on the high-priority FIFO, then the low one.
    pub(in crate::ath9k) fn receive(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let storage = self.storage.as_ref().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.port.transmit_allowed()?;
        let port = &self.port;
        for fifo in self.fifos.iter_mut() {
            let index = *fifo.order.first().ok_or(Error::State)?;
            let buffer = &storage.rx[index];
            let step = port.access(true, || {
                buffer.sync();
                // AR_RxDone first and alone; the status words and payload
                // are snapshotted only once it is acquired, so the length
                // and `more` below belong to the completed status.
                let Some(head) =
                    edma::sample_rx_status(|index| buffer.word(4 * index), || buffer.sync())?
                else {
                    return Ok(None);
                };
                let Some(status) = edma::process_rx(&head).map_err(|_| Error::Descriptor)? else {
                    return Ok(None);
                };
                let length = usize::from(status.datalen);
                if length > usize::from(RX_DATA) {
                    return Err(Error::Descriptor);
                }
                let payload = buffer.bytes(RXS_BYTES, length)?;
                let frame = if fifo.discarding || status.more {
                    None
                } else {
                    let w: [u32; RXS_BYTES / 4] = core::array::from_fn(|i| {
                        u32::from_le_bytes(head[4 * i..4 * i + 4].try_into().unwrap_or([0; 4]))
                    });
                    let mut legacy = [0; WORDS];
                    legacy[4..9].copy_from_slice(&w[1..6]);
                    legacy[descriptor::RX_DONE] = w[11];
                    descriptor::receive(&legacy, &payload).map_err(|_| Error::Descriptor)?
                };
                fifo.discarding = status.more;
                // ath_rx_edma_buf_link: clear the status, hand it back.
                buffer.put_words(0, &[0; RXS_BYTES / 4])?;
                buffer.sync();
                Ok(Some(frame))
            })?;
            if let Some(frame) = step {
                let address = buffer.address();
                with_io(port, |io| edma::add_rx_buffer(io, fifo.queue, address))?;
                fifo.order.rotate_left(1);
                self.phase = Phase::Running;
                return Ok(ReceiveStep {
                    consumed: true,
                    frame,
                });
            }
        }
        self.phase = Phase::Running;
        Ok(ReceiveStep {
            consumed: false,
            frame: None,
        })
    }
    /// Program the EDMA station interrupt mask and open MSI delivery once
    /// the FIFOs run. Without an installed vector the owner stays polled.
    pub(in crate::ath9k) fn enable_interrupts(&mut self) -> Result<bool, Error> {
        if self.phase != Phase::Running || self.irq.is_some() {
            return Err(Error::State);
        }
        if self.port.interrupt().is_none() {
            return Ok(false);
        }
        self.phase = Phase::Failed;
        let mask = irq::enable(&self.port, true)?;
        self.irq = Some(mask);
        self.full_imr = mask.imr;
        self.port.deliver(true)?;
        self.phase = Phase::Running;
        Ok(true)
    }
    /// The wake source, only while chip interrupts are programmed.
    pub(in crate::ath9k) fn interrupt(
        &self,
    ) -> Option<alloc::sync::Arc<crate::ath9k::irq::Signal>> {
        self.irq.and_then(|_| self.port.interrupt())
    }
    /// `ath_isr` bottom half: read/clear causes and kill IER until
    /// [`Self::service_end`]. FATAL or the BB watchdog (`goto chip_reset`)
    /// closes this owner, the native counterpart of Linux's chip reset.
    pub(in crate::ath9k) fn service_begin(&mut self) -> Result<Option<irq::Events>, Error> {
        let Some(mask) = self.irq else {
            return Ok(None);
        };
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        // No MCI engine is owned yet (follow-up: live-owner
        // integration); MCI interrupts are not routed.
        let events = irq::cause(&self.port, mask.imr, false)?;
        irq::kill(&self.port, mask.msi)?;
        let Some(events) = events else {
            return Ok(None);
        };
        if events.reset() {
            self.phase = Phase::Failed;
            return Err(Error::Access);
        }
        if events.rx_eol && mask.imr & irq::RX_EOL_ORN != 0 {
            // ath_isr: drop RXEOL|RXORN until the RX tasklet ran.
            let imr = mask.imr & !irq::RX_EOL_ORN;
            self.port.write(irq::IMR, imr)?;
            self.irq = Some(irq::Mask { imr, ..mask });
        }
        Ok(Some(events))
    }
    /// `ath9k_tasklet` tail: restore RXEOL|RXORN once RX was serviced, then
    /// `ath9k_hw_resume_interrupts`.
    pub(in crate::ath9k) fn service_end(&mut self) -> Result<(), Error> {
        let Some(mut mask) = self.irq else {
            return Ok(());
        };
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if mask.imr != self.full_imr {
            self.port.write(irq::IMR, self.full_imr)?;
            mask.imr = self.full_imr;
            self.irq = Some(mask);
        }
        irq::resume(&self.port, mask)
    }

    /// `ath_stoprecv`: `ath9k_hw_abortpcurecv`, filter 0, then
    /// `ath9k_hw_stopdmarecv` (`AR_CR_RXD`, poll `AR_CR_RXE(ah)` 0xc; the
    /// DMADBG_7 hang signature is pre-AR9300 only).
    fn stop_receive(&self) -> Result<(), Error> {
        let diag = self.port.read(DIAG)?;
        self.port.write(DIAG, diag | RX_PARK)?;
        self.port.write(RX_FILTER, 0)?;
        self.port.write(MACMISC, (8 << 5) | (1 << 15))?;
        self.port.write(CR, CR_RXD)?;
        for _ in 0..RX_STOP_POLLS {
            if self.port.read(CR)? & CR_RXE == 0 {
                return Ok(());
            }
            self.port.delay_us(10);
        }
        Err(Error::Timeout)
    }
    /// `mac.c::ath9k_hw_numtxpending(q) == 0`.
    fn tx_idle(&self, queue: u64) -> Result<bool, Error> {
        Ok(self.port.read(QSTS + queue * 4)? & 3 == 0 && self.port.read(QTXE)? & (1 << queue) == 0)
    }
    /// `mac.c::ath9k_hw_abort_tx_dma`; the terminal owner keeps AR_Q_TXD set.
    fn abort_transmit(&self) -> Result<(), Error> {
        self.port.write(QTXD, 0x3ff)?;
        let misc = self.port.read(PCU_MISC)?;
        self.port.write(PCU_MISC, misc | PCU_QUIET)?;
        let diag = self.port.read(DIAG)?;
        self.port.write(DIAG, diag | DIAG_IDLE_HIGH)?;
        let ifs = self.port.read(IFS_MISC)?;
        self.port.write(IFS_MISC, ifs | IGNORE_BACKOFF)?;
        let mut idle = true;
        for queue in 0..QUEUES {
            let mut drained = false;
            for poll in 0..TX_ABORT_POLLS {
                if poll != 0 {
                    self.port.delay_us(5);
                }
                if self.tx_idle(queue)? {
                    drained = true;
                    break;
                }
            }
            idle &= drained;
        }
        let misc = self.port.read(PCU_MISC)?;
        self.port.write(PCU_MISC, misc & !PCU_QUIET)?;
        let diag = self.port.read(DIAG)?;
        self.port.write(DIAG, diag & !DIAG_IDLE_HIGH)?;
        let ifs = self.port.read(IFS_MISC)?;
        self.port.write(IFS_MISC, ifs & !IGNORE_BACKOFF)?;
        if idle {
            Ok(())
        } else {
            Err(Error::Timeout)
        }
    }
    /// After verified BME-off, non-posted BAR reads order behind any earlier
    /// device-originated posted DMA write, so idle engines prove quiescence.
    fn quiescent(&self) -> Result<bool, Error> {
        if !self.port.ordered() {
            return Ok(false);
        }
        if self.port.read(CR)? & CR_RXE != 0 || self.port.read(DIAG)? & RX_PARK != RX_PARK {
            return Ok(false);
        }
        for queue in 0..QUEUES {
            if !self.tx_idle(queue)? {
                return Ok(false);
            }
        }
        Ok(self.port.read(irq::IER)? & 1 == 0)
    }
    /// Close every packet gate, trying the PCI gate even if BAR access
    /// failed. Only a complete stop plus the post-BME-off idle proof
    /// releases the rings and buffers; otherwise they stay pinned.
    pub(in crate::ath9k) fn stop(&mut self) -> Result<(), Error> {
        if self.phase == Phase::Stopped {
            return Err(Error::State);
        }
        self.phase = Phase::Stopped;
        let rx = self.stop_receive();
        let tx = self.abort_transmit();
        let interrupts = irq::kill(&self.port, self.irq.is_some_and(|m| m.msi)).and(
            if self.irq.take().is_some() || self.port.interrupt().is_some() {
                self.port.deliver(false)
            } else {
                Ok(())
            },
        );
        let master = self.port.master(false);
        rx.and(tx).and(interrupts).and(master)?;
        if !self.quiescent()? {
            return Err(Error::Timeout);
        }
        self.reclaim();
        Ok(())
    }
    fn reclaim(&mut self) {
        self.pending = None;
        if let Some(storage) = self.storage.take() {
            let Storage {
                tx,
                status,
                tx_bytes,
                rx,
            } = storage;
            let mut buffers = Vec::new();
            buffers.push(tx.0);
            buffers.push(status.0);
            buffers.extend(tx_bytes.into_iter().map(|m| m.0));
            buffers.extend(rx.into_iter().map(|m| m.0));
            self.port.release(buffers);
        }
        self.published = false;
        self.reclaimed = true;
    }
}

mod engine;

#[cfg(feature = "kernel-test")]
mod tests;
