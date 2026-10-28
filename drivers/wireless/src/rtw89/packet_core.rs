// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fresh RTL8852B BE0/MGMT8 TX rings attached to one retained RX/RPQ owner.
//! Consumption and firmware release are separate ownership facts. No reset,
//! diagnostic-ring reuse, guessed RF receipt, IRQ worker or sustained service.
use super::{packet_format as format, power, rx_packet, tx_transport};
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
    fn from(value: format::Error) -> Self {
        match value {
            format::Error::Address => Self::Address,
            _ => Self::Packet,
        }
    }
}
impl From<tx_transport::Error> for Error {
    fn from(_: tx_transport::Error) -> Self {
        Self::Packet
    }
}
impl From<power::Error> for Error {
    fn from(_: power::Error) -> Self {
        Self::Access
    }
}
pub(super) struct RxStep {
    /// False only after actual retained RXQ and RPQ index observations find
    /// no work. Buffered events must keep this true even if no Wifi is emitted.
    pub(super) consumed: bool,
    pub(super) event: Option<rx_packet::Event>,
}
/// # Safety
/// One retained RTL8852B owner exclusively owns these fresh ordinary rings,
/// the initialized RXQ/RPQ, firmware command channel and hardware lifetime.
/// `current` invokes the SAME currently valid BusDevice capability around the
/// complete closure (including all DMA access, cache maintenance, fences and
/// MMIO); it must not validate then execute outside that invocation.
/// `ordinary_allowed` validates the retained opaque ordinary RF receipt,
/// including current board/firmware/channel/power and every reachable hardware
/// response rate. No public boolean/basic-calibration/DMA receipt qualifies it.
/// `peer_allowed` validates the exact current station_control::Peer token and
/// its own-TA/peer-RA admission before allocation and actual publication. RX
/// polling and initial radio start must remain independent of that peer token.
/// `start` repeats that check and opens only BE0/MGMT8/WPDMA and qualified CMAC
/// TX, preserving CH12/RX/RPQ and all inherited DMA fencing ownership.
/// `receive` consumes actual retained DMA after device acquire, never fabricated
/// firmware/status shortcuts. `stop` is bounded and closes ordinary DMA/TX.
/// Neither stop nor drop proves quiescence or releases published mappings.
pub(super) unsafe trait Port: power::Io {
    fn current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error>;
    fn ordinary_allowed(&mut self) -> Result<(), Error>;
    fn peer_allowed(&mut self, frame: &[u8]) -> Result<(), Error>;
    fn allocate(&mut self, length: usize) -> Result<DmaBuffer, Error>;
    fn receive(&mut self) -> Result<RxStep, Error>;
    /// Clear exactly the `open` DMA stop bits (BE/MGMT/WPDMA, plus BK/VI/VO
    /// for the all-AC program) and enable CMAC TX.
    fn start(&mut self, open: u32) -> Result<(), Error>;
    /// Close every ordinary stop bit (`format::STOP_ALL`) and CMAC TX.
    fn stop(&mut self) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Running,
    Stopped,
    Failed,
}
struct Packet {
    header: DmaBuffer,
    body: DmaBuffer,
    id: u64,
    length: usize,
}
struct Ring {
    descriptors: Option<DmaBuffer>,
    queue: tx_transport::TxQueue<Packet>,
    kind: format::Queue,
    armed: bool,
}
impl Drop for Ring {
    fn drop(&mut self) {
        if self.armed {
            if let Some(memory) = self.descriptors.take() {
                core::mem::forget(memory);
            }
        }
        // TxQueue independently retains every published packet on drop.
    }
}
struct Pending {
    ticket: tx_transport::Ticket,
    queue: format::Queue,
    started: u64,
    report: bool,
}
#[derive(Debug)]
pub(super) struct Receipt {
    pub(super) id: u64,
    /// Acquired from the actual retained DMA body after BOTH terminal facts.
    pub(super) bytes: Vec<u8>,
    /// RPQ TX_DONE, not an additional AP/on-air acknowledgement requirement.
    pub(super) radio_acknowledged: bool,
}
#[derive(Debug)]
pub(super) struct Frame {
    bytes: Vec<u8>,
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
    pub(super) consumed_rx: bool,
    pub(super) frame: Option<Frame>,
    pub(super) c2h: Option<Vec<u8>>,
    pub(super) receipt: Option<Receipt>,
}
pub(super) struct Core {
    phase: Phase,
    own: [u8; 6],
    mac_id: u8,
    rings: Vec<Ring>,
    /// Stop bits of exactly the rings this owner published.
    stop: u32,
    /// Highest signed RX PHY program admitted for this owner.
    rx: RxPhy,
    /// Random scan source address the controller put in the address CAM.
    scan: Option<[u8; 6]>,
    next_id: u64,
    pending: Option<Pending>,
    completions: VecDeque<Receipt>,
}
const STOP: u32 = 1 << 8 | 1 << 16 | 1 << 19;
/// Receive PHY admission granted by the signed operating programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RxPhy {
    /// CCK1..OFDM54 only.
    Legacy,
    /// `Program::Ht`: plus 20MHz HT MCS0..15 and A-MPDU subframes.
    Ht,
    /// `Program::He`: plus 20MHz HE NSS1/NSS2 MCS0..11 on any GI/LTF.
    He,
}
impl RxPhy {
    pub(super) fn from_programs(ht: bool, he: bool) -> Self {
        match (ht, he) {
            (true, true) => Self::He,
            (true, false) => Self::Ht,
            _ => Self::Legacy,
        }
    }
    /// Whether a received `RX_DATARATE` is inside this admission.
    pub(super) fn admits(self, rate: u16) -> bool {
        rate <= 11
            || self >= Self::Ht && (0x80..=0x8f).contains(&rate)
            || self >= Self::He && rx_packet::he_rate(rate)
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
fn copy_to(memory: &DmaBuffer, offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if offset
        .checked_add(bytes.len())
        .is_none_or(|end| end > memory.len())
    {
        return Err(Error::Address);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        // SAFETY: exclusively host-owned complete retained CPU extent checked.
        unsafe {
            memory
                .cpu_mut_ptr_at::<u8>((offset + index) as u64)
                .write_volatile(byte);
        }
    }
    memory.sync(offset, bytes.len());
    barrier();
    Ok(())
}
fn copy_from(memory: &DmaBuffer, length: usize) -> Result<Vec<u8>, Error> {
    if length > memory.len() {
        return Err(Error::Address);
    }
    memory.sync(0, length);
    barrier();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Error::Memory)?;
    for index in 0..length {
        // SAFETY: acquired complete retained CPU extent checked above.
        bytes.push(unsafe { memory.cpu_ptr_at::<u8>(index as u64).read_volatile() });
    }
    Ok(bytes)
}
fn allocate(port: &mut impl Port, length: usize) -> Result<DmaBuffer, Error> {
    let memory = port.allocate(length)?;
    if memory.len() < length {
        return Err(Error::Address);
    }
    format::extent(memory.dma_addr().raw(), memory.len())?;
    Ok(memory)
}
impl Core {
    pub(super) fn prepare(port: &mut impl Port, own: [u8; 6], mac_id: u8) -> Result<Self, Error> {
        Self::prepare_with(port, own, mac_id, false, RxPhy::Legacy)
    }
    /// `qos_all` additionally publishes ACH1..3 (BK/VI/VO) for the separately
    /// qualified all-AC QoS program.
    pub(super) fn prepare_with(
        port: &mut impl Port,
        own: [u8; 6],
        mac_id: u8,
        qos_all: bool,
        rx: RxPhy,
    ) -> Result<Self, Error> {
        if own == [0; 6] || own[0] & 1 != 0 || mac_id != 0 {
            return Err(Error::Packet);
        }
        let queues = format::Queue::ordinary(qos_all);
        let stop = queues
            .iter()
            .fold(format::STOP_WPDMA, |mask, queue| mask | queue.stop_bit());
        port.current(|port| {
            if port.read32(0x1010)? & stop != stop || port.read32(0xc000)? & (1 << 29) != 0 {
                return Err(Error::State);
            }
            let mut make = |kind: format::Queue| -> Result<Ring, Error> {
                let memory = allocate(port, usize::from(format::DEPTH) * 8)?;
                copy_to(&memory, 0, &alloc::vec![0; usize::from(format::DEPTH) * 8])?;
                Ok(Ring {
                    descriptors: Some(memory),
                    queue: tx_transport::TxQueue::new(kind.channel(), format::DEPTH)?,
                    kind,
                    armed: false,
                })
            };
            let mut owner = Self {
                phase: Phase::Prepared,
                own,
                mac_id,
                rings: {
                    let mut rings = Vec::new();
                    for queue in queues {
                        rings.push(make(*queue)?);
                    }
                    rings
                },
                stop,
                rx,
                scan: None,
                next_id: 1,
                pending: None,
                completions: VecDeque::new(),
            };
            for ring in &mut owner.rings {
                let regs = ring.kind.regs();
                if port.read32(regs.idx as u32)? & 0x0fff_0fff != 0 {
                    return Err(Error::State);
                }
                let memory = ring.descriptors.as_ref().ok_or(Error::State)?;
                let address = memory.dma_addr().raw();
                // A partially accepted base publication still retains the map.
                ring.armed = true;
                port.write32(regs.desa_l as u32, address as u32)?;
                port.write32(regs.desa_h as u32, (address >> 32) as u32)?;
                port.write16(regs.num as u32, format::DEPTH)?;
                if port.read32(regs.desa_l as u32)? != address as u32
                    || port.read32(regs.desa_h as u32)? != (address >> 32) as u32
                    || port.read16(regs.num as u32)? & 0x0fff != format::DEPTH
                {
                    return Err(Error::Access);
                }
            }
            Ok(owner)
        })
    }
    pub(super) fn start(&mut self, port: &mut impl Port) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let stop = self.stop;
        let result = port.current(|port| {
            port.ordinary_allowed()?;
            port.start(stop)?;
            if port.read32(0x1010)? & stop != 0 || port.read32(0xc000)? & (1 << 29) == 0 {
                return Err(Error::State);
            }
            port.ordinary_allowed()
        });
        if let Err(error) = result {
            let _ = Self::close_dma(port, stop);
            return Err(error);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    /// Mirror the controller's scan address CAM update (`None` restores the
    /// own address). Only between frames: a probe in flight keeps its source.
    pub(super) fn set_scan_address(&mut self, scan: Option<[u8; 6]>) -> Result<(), Error> {
        if self.phase != Phase::Running
            || self.pending.is_some()
            || scan.is_some_and(|a| a[0] & 1 != 0 || a == [0; 6] || a == self.own)
        {
            return Err(Error::State);
        }
        self.scan = scan;
        Ok(())
    }
    pub(super) fn ready(&self) -> bool {
        self.phase == Phase::Running && self.pending.is_none() && self.completions.is_empty()
    }
    pub(super) fn submit(
        &mut self,
        port: &mut impl Port,
        bytes: &[u8],
        radio_report: bool,
    ) -> Result<u64, Error> {
        self.submit_rate(port, bytes, radio_report, 0)
    }
    pub(super) fn submit_rate(
        &mut self,
        port: &mut impl Port,
        bytes: &[u8],
        radio_report: bool,
        rate: u8,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        // HE extended-range SU TX belongs to the signed HE program only.
        if rate & format::DATA_ER != 0 && self.rx < RxPhy::He {
            return Err(Error::Packet);
        }
        if !self.ready() {
            return Err(Error::Busy);
        }
        // A probe request from the current random scan address is the only
        // frame with a source other than the own address.
        let source = match self.scan {
            Some(scan) if format::probe_request(bytes, scan) => scan,
            _ => self.own,
        };
        let kind = format::classify(bytes, source)?;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or(Error::State)?;
        let result = port.current(|port| {
            port.ordinary_allowed()?;
            // An active-scan probe request has no peer; everything else
            // needs the current peer token.
            if !format::probe_request(bytes, source) {
                port.peer_allowed(bytes)?;
            }
            let packet = Packet {
                header: allocate(port, format::HEADER)?,
                body: allocate(port, bytes.len())?,
                id,
                length: bytes.len(),
            };
            let ring = self
                .rings
                .iter_mut()
                .find(|ring| ring.kind == kind)
                .ok_or(Error::Packet)?;
            let ticket = ring
                .queue
                .reserve(packet, self.mac_id, kind.qsel())
                .map_err(|(e, _)| Error::from(e))?;
            if ticket.sequence >= format::IDENTITIES {
                let _ = ring.queue.abort(ticket)?;
                return Err(Error::State);
            }
            let packet = ring.queue.reserved_mut(ticket)?;
            let preparation = (|| {
                let (header, actual) = if rate == 0 {
                    format::transmit(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                    )
                } else {
                    format::transmit_rate(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                        rate,
                    )
                }?;
                if actual != kind {
                    return Err(Error::Packet);
                }
                copy_to(&packet.body, 0, bytes)?;
                copy_to(&packet.header, 0, &header)?;
                format::descriptor(packet.header.dma_addr().raw()).map_err(Error::from)
            })();
            let descriptor = match preparation {
                Ok(value) => value,
                Err(error) => {
                    let _ = ring.queue.abort(ticket)?;
                    return Err(error);
                }
            };
            port.ordinary_allowed()?;
            if !format::probe_request(bytes, source) {
                port.peer_allowed(bytes)?;
            }
            // Before the FIRST descriptor write, the queue holds both DMA maps
            // as published; every uncertain failure retains them permanently.
            ring.queue.publish(ticket)?;
            self.pending = Some(Pending {
                ticket,
                queue: kind,
                started: port.now_us(),
                report: false,
            });
            copy_to(
                ring.descriptors.as_ref().ok_or(Error::State)?,
                usize::from(ticket.slot) * 8,
                &descriptor,
            )?;
            barrier();
            port.write16(kind.regs().idx as u32, ring.queue.write_pointer())?;
            if port.read16(kind.regs().idx as u32)? & 0x0fff != ring.queue.write_pointer() {
                return Err(Error::Access);
            }
            self.next_id = next_id;
            Ok(id)
        });
        if result.is_err() {
            self.phase = Phase::Failed;
            let _ = Self::close_dma(port, self.stop);
        }
        result
    }
    /// Whether this owner published the ring for `queue`.
    pub(super) fn has_queue(&self, queue: format::Queue) -> bool {
        self.rings.iter().any(|ring| ring.kind == queue)
    }
    fn completed(&mut self, completion: tx_transport::Completion<Packet>) -> Result<(), Error> {
        // All non-success release statuses are terminal; ownership is no longer
        // ambiguous but the station must never consume a success receipt.
        if completion.status != 0 {
            return Err(Error::Packet);
        }
        let packet = completion.resource;
        let bytes = copy_from(&packet.body, packet.length)?;
        self.completions.push_back(Receipt {
            id: packet.id,
            bytes,
            radio_acknowledged: true,
        });
        self.pending = None;
        Ok(())
    }
    fn receive(&mut self, port: &mut impl Port, step: &mut Step) -> Result<(), Error> {
        let received = port.receive()?;
        if received.event.is_some() && !received.consumed {
            return Err(Error::Packet);
        }
        step.consumed_rx = received.consumed;
        match received.event {
            None | Some(rx_packet::Event::Dropped) => {}
            Some(rx_packet::Event::Firmware(event)) => step.c2h = Some(event.bytes),
            // A PPDU above the signed RX PHY program (HT without `Ht`, HE
            // without `He`) is dropped exactly as the assembler dropped every
            // non-legacy rate before, without closing the station.
            Some(rx_packet::Event::Wifi(meta, _))
                if !self.rx.admits(meta.rate) || meta.ampdu && self.rx < RxPhy::Ht => {}
            // Linux forwards control frames to the host (RTW89_CTRL ->
            // RTW89_FWD_TO_HOST). Those shorter than an ordinary header are
            // surfaced from 16 bytes (PS-Poll/BAR); malformed ones are dropped.
            Some(rx_packet::Event::Wifi(meta, bytes))
                if bytes.first().is_some_and(|fc| fc & 0x0c == 0x04) =>
            {
                if !meta.crc_error
                    && !meta.icv_error
                    && !meta.hardware_decrypted
                    && !meta.aggregate
                    && meta.bandwidth == 0
                    && (16..=format::MAX_MPDU).contains(&bytes.len())
                    && meta.size == bytes.len() + 4
                {
                    step.frame = Some(Frame { bytes });
                }
            }
            Some(rx_packet::Event::Wifi(meta, bytes)) => {
                if meta.crc_error
                    || meta.icv_error
                    || meta.hardware_decrypted
                    || meta.aggregate
                    || meta.bandwidth != 0
                    || !self.rx.admits(meta.rate)
                    || bytes.len() < 24
                    || bytes.len() > format::MAX_MPDU
                    || meta.size != bytes.len() + 4
                {
                    return Err(Error::Packet);
                }
                step.frame = Some(Frame { bytes });
            }
            Some(rx_packet::Event::Releases(reports)) => {
                if reports.is_empty() || reports.len() > 256 {
                    return Err(Error::Packet);
                }
                for report in reports {
                    let pending = self.pending.as_mut().ok_or(Error::Packet)?;
                    if pending.report
                        || report.sequence != pending.ticket.sequence
                        || report.channel != pending.queue.channel()
                        || report.qsel != pending.queue.qsel()
                        || report.mac_id != self.mac_id
                    {
                        return Err(Error::Packet);
                    }
                    pending.report = true;
                    let queue = pending.queue;
                    let ring = self
                        .rings
                        .iter_mut()
                        .find(|ring| ring.kind == queue)
                        .ok_or(Error::Packet)?;
                    if let Some(completion) = ring.queue.observe_report(report)? {
                        self.completed(completion)?;
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, port: &mut impl Port) -> Result<Step, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let result =
            port.current(|port| {
                port.ordinary_allowed()?;
                let mut step = Step::default();
                self.receive(port, &mut step)?;
                for slot in 0..self.rings.len() {
                    let ring = &mut self.rings[slot];
                    let index = port.read32(ring.kind.regs().idx as u32)?;
                    if index & 0x0fff != u32::from(ring.queue.write_pointer()) {
                        return Err(Error::Packet);
                    }
                    let completions = ring
                        .queue
                        .observe_read_pointer(((index >> 16) & 0x0fff) as u16)?;
                    barrier();
                    for completion in completions {
                        self.completed(completion)?;
                    }
                }
                if self.pending.as_ref().is_some_and(|pending| {
                    port.now_us().saturating_sub(pending.started) >= 1_000_000
                }) {
                    return Err(Error::Timeout);
                }
                step.receipt = self.completions.pop_front();
                Ok(step)
            });
        if result.is_err() {
            self.phase = Phase::Failed;
            let _ = Self::close_dma(port, self.stop);
        }
        result
    }
    /// Release every descriptor ring and every reserved, published or
    /// unretired packet. Returns the storage so the caller decides when it
    /// is freed; the owner is permanently stopped afterwards.
    ///
    /// # Safety
    /// The caller holds a current `dma_stop::Idle` proof for this function:
    /// every TX channel is stopped and idle with bus mastering off.
    pub(super) unsafe fn reclaim_fenced(&mut self) -> Vec<DmaBuffer> {
        self.phase = Phase::Stopped;
        self.pending = None;
        self.completions.clear();
        let mut storage = Vec::new();
        for ring in &mut self.rings {
            ring.armed = false;
            storage.extend(ring.descriptors.take());
            // SAFETY: the caller's idle proof covers this ring's channel.
            for packet in unsafe { ring.queue.reclaim_fenced() } {
                storage.push(packet.header);
                storage.push(packet.body);
            }
        }
        storage
    }
    /// True once `reclaim_fenced` released the rings.
    pub(super) fn reclaimed(&self) -> bool {
        self.phase == Phase::Stopped
            && self
                .rings
                .iter()
                .all(|ring| !ring.armed && ring.descriptors.is_none())
    }
    pub(super) fn stop(&mut self, port: &mut impl Port) -> Result<(), Error> {
        self.phase = Phase::Stopped;
        // Keep published descriptors AND packets regardless of stop readback.
        Self::close_dma(port, self.stop)
    }
    fn close_dma(port: &mut impl Port, stop: u32) -> Result<(), Error> {
        port.current(|port| {
            port.stop()?;
            if port.read32(0x1010)? & stop != stop || port.read32(0xc000)? & (1 << 29) != 0 {
                return Err(Error::Access);
            }
            Ok(())
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "packet_core/tests.rs"]
pub(super) mod tests;
