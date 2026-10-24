// SPDX-License-Identifier: GPL-2.0-or-later
//! Native RTL8188EE linked-descriptor packet ownership, initially polled.
//! No host receipt implies AP acknowledgement. OWN clear is the vendor's
//! terminal host/DMA receipt; publication, RX and stop keep exact DMA owners.
use super::{
    extent, Error, Io, Memory, Phase, Prepared, RX_BASE, RX_BUFFER, RX_BYTES, TX_BASES, TX_BYTES,
};
use alloc::vec::Vec;

/// A transport operation executes inside current PCI authority, including
/// actual descriptor/payload accesses. No DMA pointer or authority escapes.
pub trait Port: Io {
    type Buffer: Memory;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error>;
    fn allocate_packet(&self, bytes: usize) -> Result<Self::Buffer, Error>;
    fn master(&self, enabled: bool) -> Result<(), Error>;
    fn kick(&self, queue_bit: u16) -> Result<(), Error>;
}

pub(super) struct State<M: Memory> {
    pub(super) local: Option<[u8; 6]>,
    next: [usize; 7],
    receive: usize,
    serial: u64,
    pending: Option<Pending<M>>,
}
impl<M: Memory> State<M> {
    pub(super) fn new() -> Self {
        Self {
            local: None,
            next: [0; 7],
            receive: 0,
            serial: 0,
            pending: None,
        }
    }
    pub(super) fn retain(&mut self) {
        // Published descriptors may still name the current TX allocation.
        // BME clear alone never permits releasing it at a terminal stop.
        core::mem::forget(self.pending.take());
    }
}
struct Pending<M: Memory> {
    buffer: M,
    id: u64,
    queue: usize,
    slot: usize,
    length: usize,
    prefix: [u32; 10],
}
#[derive(Debug, PartialEq, Eq)]
pub struct Delivery {
    pub id: u64,
    /// Bytes read from the retained DMA payload after matching OWN clear.
    pub bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Mpdu {
    bytes: Vec<u8>,
    channel: u8,
}
impl Mpdu {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn channel(&self) -> u8 {
        self.channel
    }
}
impl narf_wireless::station_security::RawFrame for Mpdu {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        true
    }
}

const OWN: u32 = 1 << 31;
const MAX_MPDU: usize = 2304;

fn queue(frame: &[u8], local: [u8; 6]) -> Result<(usize, u16, u8), Error> {
    if !(24..=MAX_MPDU).contains(&frame.len()) || frame[10..16] != local || frame[22] & 15 != 0 {
        return Err(Error::Packet);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x9403 != 0 {
        return Err(Error::Packet); // version, fragments, order, PM.
    }
    match (fc >> 2) & 3 {
        0 if fc & 0x4300 == 0 && matches!((fc >> 4) & 15, 0 | 4 | 10 | 11 | 12) => {
            // MGMT vector1, Linux MGNT_QUEUE6, QSLT_MGNT0x12.
            Ok((1, 1 << 6, 0x12))
        }
        2 if fc & 0x03f0 == 0x0100 => {
            // BE vector4, Linux BE_QUEUE1, firmware priority/TID0.
            Ok((4, 1 << 1, 0))
        }
        _ => Err(Error::Packet),
    }
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    /// Open the already owned native rings. The one-shot operational MAC,
    /// factory IQ/LC calibration and opaque channel/power grant are required.
    /// Device interrupts remain masked; no native netdev is raised here.
    pub(crate) fn start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.permission.is_none()
        {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(false, || self.validate_rings())?;
        super::super::radio::parked(&self.io).map_err(Error::Radio)?;
        if self.io.read32(0x608)? != super::super::packet_mac::RCR
            || self.io.read32(0x604)? != super::super::packet_mac::TCR
            || self.io.read8(0x680)? != 0
        {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        // Linux init_mac CR2ff then CR+1=06. DMA remains independently
        // stopped until the complete owned descriptor/MAC state is ready.
        self.io.write_bytes(0x100, &[0xff, 6])?;
        self.io.write8(0x301, 0)?;
        self.io.write8(0x522, 0)?;
        if self.io.read8(0x100)? != 0xff
            || self.io.read8(0x101)? != 6
            || self.io.read8(0x301)? != 0
            || self.io.read32(0xb0)? != 0
            || self.io.read32(0xb8)? != 0
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    fn validate_rings(&self) -> Result<(), Error> {
        for (queue, ring) in self.tx.iter().enumerate() {
            ring.sync();
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            if self.io.read32(TX_BASES[queue])? != base {
                return Err(Error::Readback);
            }
            for slot in 0..self.depth {
                if ring.read32(slot * TX_BYTES)? & OWN != 0
                    || ring.read32(slot * TX_BYTES + 40)?
                        != base + (((slot + 1) % self.depth) * TX_BYTES) as u32
                    || ring.read32(slot * TX_BYTES + 44)? != 0
                {
                    return Err(Error::Descriptor);
                }
            }
        }
        let receive = self.receive.as_ref().ok_or(Error::State)?;
        receive.sync();
        if self.io.read32(RX_BASE)? != extent(receive, self.depth * RX_BYTES, 256)? {
            return Err(Error::Readback);
        }
        for (slot, buffer) in self.buffers.iter().enumerate() {
            let end = if slot + 1 == self.depth { 1 << 30 } else { 0 };
            if receive.read32(slot * RX_BYTES)? != RX_BUFFER as u32 | OWN | end
                || receive.read32(slot * RX_BYTES + 24)? != extent(buffer, RX_BUFFER, 4)?
                || receive.read32(slot * RX_BYTES + 28)? != 0
            {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }
    /// One outstanding native frame is retained across both active queues.
    /// A free descriptor alone cannot substitute a different pending payload.
    pub(crate) fn submit(&mut self, frame: &[u8], rate: u8) -> Result<u64, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_some() {
            return Err(Error::State);
        }
        if rate > 11 {
            return Err(Error::Packet);
        }
        let (queue, poll, selector) = queue(frame, self.packet.local.ok_or(Error::State)?)?;
        let id = self.packet.serial.checked_add(1).ok_or(Error::State)?;
        let mut buffer = self.io.allocate_packet(frame.len())?;
        let address = extent(&buffer, frame.len(), 4)?;
        let end = u64::from(address) + frame.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        let slot = self.packet.next[queue];
        let mut prefix = [0; 10];
        prefix[0] = frame.len() as u32 | (32 << 16) | (1 << 26) | (1 << 27);
        let destination = if queue == 4 {
            &frame[16..22]
        } else {
            &frame[4..10]
        };
        if destination[0] & 1 != 0 {
            prefix[0] |= 1 << 24;
        }
        prefix[1] = u32::from(selector) << 8; // MACID0, rateID0, security0.
        prefix[3] = u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4) << 16;
        prefix[4] = (1 << 8) | (1 << 10); // forced legacy rate, no fallback.
        prefix[5] = u32::from(rate) | (0x1f << 8) | (15 << 13);
        prefix[7] = frame.len() as u32;
        prefix[8] = address;
        // Fill through the actual live DMA mapping before it can be named
        // by OWN. Retain its owner before the first descriptor mutation.
        self.io.authority(true, || {
            buffer.write_bytes(0, frame)?;
            buffer.sync();
            Ok(())
        })?;
        self.packet.pending = Some(Pending {
            buffer,
            id,
            queue,
            slot,
            length: frame.len(),
            prefix,
        });
        self.packet.serial = id;
        self.phase = Phase::Failed;
        let ring = &mut self.tx[queue];
        self.io.authority(true, || {
            ring.sync();
            let offset = slot * TX_BYTES;
            if ring.read32(offset)? & OWN != 0 {
                return Err(Error::Descriptor);
            }
            // clear_pci_tx_desc_content preserves DW10's linked-next pointer.
            for (word, value) in prefix.iter().copied().enumerate() {
                ring.write32(offset + word * 4, value)?;
            }
            ring.sync();
            ring.write32(offset, prefix[0] | OWN)?;
            ring.sync();
            Ok(())
        })?;
        self.io.kick(poll)?;
        self.phase = Phase::Running;
        Ok(id)
    }
    fn delivery(&mut self) -> Result<Option<Delivery>, Error> {
        let Some(pending) = self.packet.pending.as_ref() else {
            return Ok(None);
        };
        let ring = &self.tx[pending.queue];
        let delivery = self.io.authority(true, || {
            ring.sync();
            let offset = pending.slot * TX_BYTES;
            if ring.read32(offset)? & OWN != 0 {
                return Ok(None);
            }
            // Retry counters and hardware FIFO page fields are not receipt
            // identities. Match the stable buffer/queue/length fields that
            // Linux uses to retire this exact descriptor, not mutable status.
            for word in [0, 1, 7, 8, 9] {
                if ring.read32(offset + word * 4)? != pending.prefix[word] {
                    return Err(Error::Descriptor);
                }
            }
            if ring.read32(offset + 40)?
                != ring.address() as u32 + (((pending.slot + 1) % self.depth) * TX_BYTES) as u32
                || ring.read32(offset + 44)? != 0
            {
                return Err(Error::Descriptor);
            }
            pending.buffer.sync();
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(pending.length)
                .map_err(|_| Error::Memory)?;
            bytes.resize(pending.length, 0);
            pending.buffer.read_bytes(0, &mut bytes)?;
            Ok(Some(Delivery {
                id: pending.id,
                bytes,
            }))
        })?;
        if delivery.is_some() {
            let queue = pending.queue;
            self.packet.next[queue] = (pending.slot + 1) % self.depth;
            self.packet.pending = None; // exact vendor terminal DMA receipt.
        }
        Ok(delivery)
    }
    pub(crate) fn poll_delivery(&mut self) -> Result<Option<Delivery>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let result = self.delivery()?;
        self.phase = Phase::Running;
        Ok(result)
    }
    /// The complete owner stays retained if this future is dropped at any
    /// actual wait. No re-submission or completion can reopen the phase.
    pub(crate) async fn wait_delivery(&mut self, budget: usize) -> Result<Delivery, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_none() || budget == 0 {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        for _ in 0..budget.min(10_000) {
            if let Some(delivery) = self.delivery()? {
                self.phase = Phase::Running;
                return Ok(delivery);
            }
            self.io.delay_us(100).await;
        }
        Err(Error::PacketTimeout)
    }
    pub(crate) fn poll_receive(&mut self) -> Result<Option<Mpdu>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let slot = self.packet.receive;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let channel = self.permission.ok_or(Error::State)?.channel();
        let (consumed, packet) = self.io.authority(true, || {
            ring.sync();
            let offset = slot * RX_BYTES;
            let status = ring.read32(offset)?;
            if status & OWN != 0 {
                return Ok((false, None));
            }
            let end = if slot + 1 == self.depth { 1 << 30 } else { 0 };
            if status & (1 << 30) != end
                || ring.read32(offset + 24)? != extent(buffer, RX_BUFFER, 4)?
                || ring.read32(offset + 28)? != 0
            {
                return Err(Error::Descriptor);
            }
            let extra = ring.read32(offset + 4)?;
            let sequence = ring.read32(offset + 8)?;
            let report = ring.read32(offset + 12)?;
            let length = (status & 0x3fff) as usize;
            let start = (((status >> 16) & 15) * 8 + ((status >> 24) & 3)) as usize;
            let ordinary = report & 0xc000 == 0;
            if ordinary && (length < 4 || start.checked_add(length).is_none_or(|n| n > RX_BUFFER)) {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            if ordinary
                && status & 0xc000 == 0
                && status & 0x3000_0000 == 0x3000_0000
                && extra & ((3 << 14) | (1 << 27)) == 0
                && sequence & 0xf000 == 0
                && report & ((1 << 6) | (1 << 9)) == 0
                && report & 63 <= 11
                && (28..=MAX_MPDU + 4).contains(&length)
            {
                buffer.sync();
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length - 4)
                    .map_err(|_| Error::Memory)?;
                bytes.resize(length - 4, 0);
                buffer.read_bytes(start, &mut bytes)?;
                let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
                // Open frames may legitimately have SWDEC clear (Linux trx.c).
                // Protected frames must retain their IV/CCMP ciphertext/MIC.
                if fc & 0x400 == 0
                    && bytes[22] & 15 == 0
                    && (fc & 0x4000 == 0 || status & (1 << 27) != 0)
                {
                    packet = Some(Mpdu { bytes, channel });
                }
            }
            for word in 0..6 {
                ring.write32(offset + word * 4, 0)?;
            }
            buffer.sync();
            ring.sync();
            ring.write32(offset, RX_BUFFER as u32 | end | OWN)?;
            ring.sync();
            Ok((true, packet))
        })?;
        if consumed {
            self.packet.receive = (slot + 1) % self.depth;
        }
        self.phase = Phase::Running;
        Ok(packet)
    }
    /// Terminal stop closes host admission first, attempts all independent
    /// packet/IRQ/PCI gates, and retains every published allocation. A parked
    /// command register is not presented as a DMA-prefetch reclamation proof.
    pub(crate) fn stop_packets(&mut self) -> Result<(), Error> {
        if matches!(
            self.phase,
            Phase::Stopped | Phase::Stopping | Phase::Allocated
        ) {
            return Err(Error::State);
        }
        self.phase = Phase::Stopping;
        let mut result = Ok(());
        for operation in [
            self.io.write32(0xb0, 0).map_err(Error::from),
            self.io.write32(0xb8, 0).map_err(Error::from),
            self.io.write8(0x522, 0xff).map_err(Error::from),
            self.io.write8(0x301, 0xff).map_err(Error::from),
        ] {
            if result.is_ok() {
                result = operation;
            }
        }
        let close = (|| {
            let cr = self.io.read8(0x100)?;
            self.io.write8(0x100, cr & !0xcf)?;
            if self.io.read8(0x100)? & 0xcf != 0
                || self.io.read8(0x301)? != 0xff
                || self.io.read32(0xb0)? != 0
                || self.io.read32(0xb8)? != 0
            {
                return Err(Error::Readback);
            }
            Ok(())
        })();
        if result.is_ok() {
            result = close;
        }
        let park = self.io.master(false);
        if result.is_ok() {
            result = park;
        }
        self.phase = if result.is_ok() {
            Phase::Stopped
        } else {
            Phase::Failed
        };
        result
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_tests.rs"]
pub(crate) mod tests;
