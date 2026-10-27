// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE/RTL8822CE control and bounded four-buffer DATA ownership;
//! native rings stay in their original firmware backend. No reset,
//! descriptor-owner reconstruction or IRQ service.
use super::packet_format::{self as format, Queue};
use alloc::{collections::VecDeque, vec::Vec};
use narf_io::DmaBuffer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Busy,
    Access,
    Address,
    Memory,
    Packet,
    Timeout,
}
impl From<format::Error> for Error {
    fn from(_: format::Error) -> Self {
        Self::Packet
    }
}
/// # Safety
/// The exact retained native firmware/radio owner exclusively owns both
/// ordinary TX rings and all512 RX mappings. No reset, IRQ or H2C client may
/// mutate these rings. All CPU/config/MMIO access executes inside current
/// device capability invocation. Device-to-CPU ownership observations include
/// cache maintenance and outer-shareable acquire order before buffer reads.
/// Every possibly published mapping survives failure, cancellation and drop.
pub(super) unsafe trait Port {
    fn rts_threshold(&self) -> Option<u32> {
        None
    }
    fn originator_ba_allowed(&self) -> bool {
        false
    }
    fn recipient_ba_allowed(&self) -> bool {
        false
    }
    fn receive_chip(&self) -> Result<super::packet_phy::Chip, Error>;
    fn transmit_allowed(&mut self) -> Result<(), Error>;
    fn memory<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error>;
    fn allocate(&mut self, length: usize) -> Result<DmaBuffer, Error>;
    fn index(&mut self, register: u16) -> Result<u32, Error>;
    fn publish(&mut self, register: u16, host: u16) -> Result<(), Error>;
    fn tx_descriptor(
        &mut self,
        queue: Queue,
        slot: usize,
        descriptor: &[u8; 16],
    ) -> Result<(), Error>;
    fn rx_descriptor(&mut self, slot: usize) -> Result<[u8; 8], Error>;
    fn rx_bytes(&mut self, slot: usize, offset: usize, length: usize) -> Result<Vec<u8>, Error>;
    fn rx_repost(&mut self, slot: usize) -> Result<(), Error>;
    fn start(&mut self) -> Result<(), Error>;
    fn stop(&mut self) -> Result<(), Error>;
    fn now_us(&self) -> u64;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Running,
    Stopped,
    Failed,
}
struct Pending {
    id: u64,
    queue: Queue,
    length: usize,
    next: u16,
    sequence: Option<u8>,
    report: Option<bool>,
    consumed: bool,
    started: u64,
}
#[derive(Debug)]
pub(super) struct Receipt {
    pub(super) id: u64,
    /// Read from the actual retained DMA body after terminal ownership.
    pub(super) bytes: Vec<u8>,
    pub(super) radio_acknowledged: bool,
}
#[derive(Debug)]
pub(super) struct Frame {
    bytes: Vec<u8>,
    pub(super) rate: u8,
    pub(super) phy: Option<super::packet_phy::Evidence>,
}
impl narf_wireless::station_security::RawFrame for Frame {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        true
    }
}
#[derive(Default, Debug)]
pub(super) struct Step {
    /// False only after an actual native RX index observation found no work.
    pub(super) consumed_rx: bool,
    pub(super) frame: Option<Frame>,
    pub(super) c2h: Option<Vec<u8>>,
    pub(super) receipt: Option<Receipt>,
}
pub(super) struct Core {
    phase: Phase,
    frame: Option<DmaBuffer>,
    batch_buffers: Vec<DmaBuffer>,
    batch_pending: VecDeque<batch::Pending>,
    aggregation: Option<format::Aggregation>,
    batch_published: bool,
    own: [u8; 6],
    mac_id: u8,
    data_profile: format::DataProfile,
    receive_chip: super::packet_phy::Chip,
    tx_host: [u16; 2],
    tx_device: [u16; 2],
    rx: u16,
    tag: u16,
    next_id: u64,
    reports: u8,
    rx_idle: bool,
    pending: Option<Pending>,
    published: bool,
}
fn queue_slot(queue: Queue) -> usize {
    match queue {
        Queue::Management => 0,
        Queue::Data => 1,
    }
}
fn barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: coherent PCI ownership crosses the outer-shareable domain.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
fn copy_from(memory: &DmaBuffer, offset: usize, length: usize) -> Result<Vec<u8>, Error> {
    if offset
        .checked_add(length)
        .is_none_or(|end| end > memory.len())
    {
        return Err(Error::Address);
    }
    memory.sync(offset, length);
    barrier();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Error::Memory)?;
    for index in offset..offset + length {
        // SAFETY: checked complete retained CPU mapping, after device acquire.
        bytes.push(unsafe { memory.cpu_ptr_at::<u8>(index as u64).read_volatile() });
    }
    Ok(bytes)
}
fn copy_to(memory: &DmaBuffer, offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if offset
        .checked_add(bytes.len())
        .is_none_or(|end| end > memory.len())
    {
        return Err(Error::Address);
    }
    for (index, value) in bytes.iter().copied().enumerate() {
        // SAFETY: caller owns the buffer; complete CPU extent checked above.
        unsafe {
            memory
                .cpu_mut_ptr_at::<u8>((offset + index) as u64)
                .write_volatile(value);
        }
    }
    memory.sync(offset, bytes.len());
    barrier();
    Ok(())
}
impl Core {
    pub(super) fn prepare(port: &mut impl Port, own: [u8; 6], mac_id: u8) -> Result<Self, Error> {
        if own == [0; 6] || own[0] & 1 != 0 || mac_id > 127 {
            return Err(Error::Packet);
        }
        port.transmit_allowed()?;
        let receive_chip = port.receive_chip()?;
        for queue in [Queue::Management, Queue::Data] {
            if port.index(queue.index())? & 0x0fff_0fff != 0 {
                return Err(Error::State);
            }
        }
        if port.index(0x3b4)? & 0x0fff_0fff != 0 {
            return Err(Error::State);
        }
        let frame = port.allocate(format::TX_DESC + format::MAX_MPDU)?;
        let base = frame.dma_addr().raw();
        if frame.len() < format::TX_DESC + format::MAX_MPDU
            || base == 0
            || base & 3 != 0
            || base
                .checked_add(frame.len() as u64 - 1)
                .is_none_or(|end| end > u64::from(u32::MAX))
        {
            return Err(Error::Address);
        }
        port.memory(|| copy_to(&frame, 0, &[0; format::TX_DESC]))?;
        let mut batch_buffers = Vec::new();
        batch_buffers
            .try_reserve_exact(4)
            .map_err(|_| Error::Memory)?;
        for _ in 0..4 {
            let buffer = port.allocate(format::TX_DESC + format::MAX_MPDU)?;
            format::buffer_descriptor(buffer.dma_addr().raw(), format::MAX_MPDU)?;
            if buffer.len() < format::TX_DESC + format::MAX_MPDU {
                return Err(Error::Address);
            }
            port.memory(|| copy_to(&buffer, 0, &[0; format::TX_DESC]))?;
            batch_buffers.push(buffer);
        }
        Ok(Self {
            phase: Phase::Prepared,
            frame: Some(frame),
            batch_buffers,
            batch_pending: VecDeque::new(),
            aggregation: None,
            batch_published: false,
            own,
            mac_id,
            data_profile: format::DataProfile::LEGACY,
            receive_chip,
            tx_host: [0; 2],
            tx_device: [0; 2],
            rx: 0,
            tag: 0,
            next_id: 1,
            reports: 0,
            rx_idle: false,
            pending: None,
            published: false,
        })
    }
    pub(super) fn start(&mut self, port: &mut impl Port) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        port.transmit_allowed()?;
        port.start()?;
        self.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn ready(&self) -> bool {
        self.phase == Phase::Running && self.pending.is_none() && self.batch_pending.is_empty()
    }
    pub(super) fn configure_data(&mut self, profile: format::DataProfile) -> Result<(), Error> {
        if !self.ready() || !profile.valid() {
            return Err(Error::State);
        }
        self.data_profile = profile;
        Ok(())
    }
    pub(super) fn submit(
        &mut self,
        port: &mut impl Port,
        frame: &[u8],
        radio_report: bool,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.pending.is_some() || !self.batch_pending.is_empty() {
            return Err(Error::Busy);
        }
        // The64 native six-bit CCX identities may be reused only after every
        // previous report retired and an actual RX-idle fence. Timeout/error
        // poisons this whole owner, so an ambiguous report never reuses an ID.
        if radio_report && self.reports == 64 {
            if !self.rx_idle {
                return Err(Error::Busy);
            }
            let index = port.index(0x3b4)?;
            if index & 0xfff != u32::from(self.rx) || (index >> 16) & 0xfff != u32::from(self.rx) {
                self.rx_idle = false;
                return Err(Error::Busy);
            }
            self.reports = 0;
        }
        let sequence = radio_report.then_some(self.reports << 2);
        if format::recipient_control(frame) && !port.recipient_ba_allowed() {
            return Err(Error::Access);
        }
        if format::originator_control(frame) && !port.originator_ba_allowed() {
            return Err(Error::Access);
        }
        let (mut descriptor, queue) =
            format::transmit_profile(frame, self.own, self.mac_id, sequence, self.data_profile)?;
        if queue == Queue::Data && (!radio_report || frame[0] == 0x88) {
            super::protection::descriptor(&mut descriptor, frame.len(), port.rts_threshold());
        }
        let memory = self.frame.as_ref().ok_or(Error::State)?;
        let bd = format::buffer_descriptor(memory.dma_addr().raw(), frame.len())?;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or(Error::State)?;
        port.transmit_allowed()?;
        let slot = queue_slot(queue);
        let host = self.tx_host[slot];
        let next = (usize::from(host) + 1) % queue.depth();
        let result = (|| {
            port.memory(|| {
                copy_to(memory, 0, &descriptor)?;
                copy_to(memory, format::TX_DESC, frame)
            })?;
            // Retain identity and immutable payload before the first visible BD.
            self.pending = Some(Pending {
                id,
                queue,
                length: frame.len(),
                next: next as u16,
                sequence,
                report: None,
                consumed: false,
                started: port.now_us(),
            });
            self.published = true;
            port.tx_descriptor(queue, usize::from(host), &bd)?;
            port.transmit_allowed()?;
            barrier();
            port.publish(queue.index(), next as u16)?;
            self.tx_host[slot] = next as u16;
            self.next_id = next_id;
            if radio_report {
                self.reports += 1;
            }
            self.rx_idle = false;
            Ok(id)
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    fn receive(&mut self, port: &mut impl Port, step: &mut Step) -> Result<(), Error> {
        let index = port.index(0x3b4)?;
        let host = (index & 0xfff) as u16;
        let device = ((index >> 16) & 0xfff) as u16;
        if host != self.rx || device >= 512 {
            return Err(Error::Packet);
        }
        if device == self.rx {
            self.rx_idle = true;
            return Ok(());
        }
        self.rx_idle = false;
        step.consumed_rx = true;
        let slot = usize::from(self.rx);
        let bd = port.rx_descriptor(slot)?;
        // RX-tag mode stores a13-bit sequence, not a packet byte count.
        if u16::from_le_bytes([bd[2], bd[3]]) != self.tag {
            return Err(Error::Packet);
        }
        let descriptor = port.rx_bytes(slot, 0, format::RX_DESC)?;
        if let Ok(descriptor) = <&[u8; format::RX_DESC]>::try_from(descriptor.as_slice()) {
            if let Ok(metadata) = format::receive_profile(descriptor, self.data_profile.mcs != 0) {
                let mut body =
                    port.rx_bytes(slot, metadata.payload.start, metadata.payload.len())?;
                if body.len() != metadata.payload.len() {
                    return Err(Error::Packet);
                }
                if metadata.c2h {
                    if let Some(report) = format::report(&body)? {
                        if let Some(pending) = self.pending.as_mut() {
                            if pending.sequence == Some(report.sequence)
                                && pending.report.replace(report.acknowledged).is_some()
                            {
                                return Err(Error::Packet);
                            }
                        }
                        for pending in &mut self.batch_pending {
                            if pending.report_sequence == report.sequence
                                && pending.report.replace(report.acknowledged).is_some()
                            {
                                return Err(Error::Packet);
                            }
                        }
                    }
                    step.c2h = Some(body);
                } else {
                    let phy = match format::phy_status(descriptor) {
                        Some(range) => {
                            let bytes = port.rx_bytes(slot, range.start, range.len())?;
                            super::packet_phy::parse(self.receive_chip, metadata.rate, &bytes)
                                .ok()
                                .filter(|p| p.initial_channel())
                                .map(Some)
                        }
                        None => Some(None),
                    };
                    if let Some(phy) = phy {
                        body.truncate(body.len() - 4);
                        if body.len() >= 24 || format::native_bar(&body) {
                            step.frame = Some(Frame {
                                bytes: body,
                                rate: metadata.rate,
                                phy,
                            });
                        }
                    }
                }
            }
        } else {
            return Err(Error::Packet);
        }
        port.rx_repost(slot)?;
        self.rx = (self.rx + 1) % 512;
        self.tag = (self.tag + 1) % 8192;
        barrier();
        port.publish(0x3b4, self.rx)?;
        Ok(())
    }
    fn complete(&mut self, port: &mut impl Port) -> Result<Option<Receipt>, Error> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        let index = port.index(pending.queue.index())?;
        let slot = queue_slot(pending.queue);
        let host = (index & 0xfff) as u16;
        let device = ((index >> 16) & 0xfff) as u16;
        if host != self.tx_host[slot]
            || usize::from(device) >= pending.queue.depth()
            || device != self.tx_device[slot] && device != pending.next
        {
            return Err(Error::Packet);
        }
        if device == pending.next {
            pending.consumed = true;
            self.tx_device[slot] = device;
        }
        if port.now_us().saturating_sub(pending.started) >= 1_000_000 {
            return Err(Error::Timeout);
        }
        if !pending.consumed || pending.sequence.is_some() && pending.report.is_none() {
            return Ok(None);
        }
        if pending.report == Some(false) {
            return Err(Error::Packet);
        }
        let memory = self.frame.as_ref().ok_or(Error::State)?;
        let bytes = port.memory(|| copy_from(memory, format::TX_DESC, pending.length))?;
        let receipt = Receipt {
            id: pending.id,
            bytes,
            radio_acknowledged: pending.report == Some(true),
        };
        self.pending = None;
        Ok(Some(receipt))
    }
    pub(super) fn poll(&mut self, port: &mut impl Port) -> Result<Step, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let result = (|| {
            port.transmit_allowed()?;
            let mut step = Step::default();
            self.receive(port, &mut step)?;
            step.receipt = match self.complete(port)? {
                Some(receipt) => Some(receipt),
                None => self.complete_batch(port)?,
            };
            Ok(step)
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    pub(super) fn stop(&mut self, port: &mut impl Port) -> Result<(), Error> {
        self.phase = Phase::Stopped;
        self.rx_idle = false;
        // BME-off/stop bits do not release published allocations.
        port.stop()
    }
}
impl Drop for Core {
    fn drop(&mut self) {
        if self.published {
            if let Some(memory) = self.frame.take() {
                core::mem::forget(memory);
            }
        }
        if self.batch_published {
            core::mem::forget(core::mem::take(&mut self.batch_buffers));
        }
    }
}
#[path = "packet_core/batch.rs"]
mod batch;

#[cfg(feature = "kernel-test")]
#[path = "packet_core/tests.rs"]
pub(super) mod tests;
