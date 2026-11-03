// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU USB packet owner: the queue/URB-shaped counterpart of
//! `packet_core::Core` (which is shaped around PCI TXBD/RXBD rings).
//!
//! Port of Linux 7.3-rc4 `rtw88/usb.c`:
//! - TX: `rtw_usb_tx_write` (descriptor + `rtw_tx_fill_txdesc_checksum`,
//!   queued on `tx_queue[qsel_to_ep(qsel)]`), `rtw_usb_tx_handler` (pipes
//!   walked from the highest index down, `rtw_usb_tx_agg_skb` per URB) and
//!   `rtw_usb_write_port_tx_complete` (frames that requested a TX status wait
//!   for the firmware CCX report, `rtw_tx_report_enqueue`; everything else
//!   completes on the USB completion alone).
//! - RX: one persistent bulk-IN receipt (`rtw_usb_rx_resubmit`), each
//!   completed URB split by `usb::split_rx` (`rtw_usb_rx_handler`) and every
//!   record admitted by the same `packet_format::receive_rates` /
//!   `packet_phy` rules the PCI owner applies.
//!
//! Transfers use the persistent begin/poll bulk receipts of the NARF USB
//! stack (`rtl8xxxu::packet_transport::Io`, `USBDevice::begin_bulk_*`), so
//! [`Owner::poll`] never blocks or spins: an incomplete receipt is simply
//! still pending. A USB completion proves only host-to-device transfer, never
//! a radio ACK: such receipts carry `radio_acknowledged = false`, exactly as
//! PCI receipts without a CCX report do. Linux's `IEEE80211_TX_STAT_ACK` for
//! those frames is a mac80211 bookkeeping choice, not hardware evidence.
//! Any USB error (including the xHCI halting codes) fails the owner; the
//! 8188EU halt-recovery sequence is not ported here.
use super::{
    packet_core::{Error, Frame, Receipt},
    packet_format as format,
    usb::{self, Endpoints, EP_MAX, MAX_RECVBUF, QSEL_HIGH},
};
use crate::rtl8xxxu::packet_transport::Io;
use alloc::{collections::VecDeque, vec::Vec};

/// Frames queued on all bulk-OUT pipes together (Linux bounds the queues by
/// mac80211 flow control; this owner refuses with `Busy` instead).
pub(super) const MAX_QUEUED: usize = 32;
/// Firmware CCX report deadline, the same 1 s the PCI owner uses.
const REPORT_TIMEOUT_US: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Running,
    Stopped,
    Failed,
}
struct Queued {
    id: u64,
    /// TX descriptor (48 bytes, checksummed) followed by the MPDU.
    packet: Vec<u8>,
    sequence: Option<u8>,
}
struct Inflight<R> {
    receipt: R,
    length: usize,
    packets: Vec<Queued>,
}
struct Awaiting {
    id: u64,
    sequence: u8,
    bytes: Vec<u8>,
    started: u64,
    /// Its CCX ACK arrived; released once every earlier frame is too.
    acknowledged: bool,
}
/// Everything one [`Owner::poll`] observed.
#[derive(Default, Debug)]
pub(super) struct Step {
    /// A bulk-IN URB completed (and was re-posted).
    pub(super) consumed_rx: bool,
    pub(super) frames: Vec<Frame>,
    pub(super) c2h: Vec<Vec<u8>>,
    pub(super) receipts: Vec<Receipt>,
}

/// One admitted bulk-IN record.
pub(super) enum Record {
    Frame(Frame),
    C2h(Vec<u8>),
}
/// Admission of one `usb::split_rx` record under the PCI owner's rules
/// (`packet_core::Core::receive`): descriptor admission at the current
/// rate profile, PHY status on the operating channel/width, FCS removed,
/// MPDUs shorter than a header dropped unless they are a native BAR. `None`
/// is a record Linux would also not deliver (or this owner refuses).
pub(super) fn admit(
    record: &usb::RxRecord<'_>,
    profile: format::DataProfile,
    chip: super::packet_phy::Chip,
    channel: u8,
    width: u8,
) -> Option<Record> {
    let descriptor: &[u8; format::RX_DESC] =
        record.bytes.get(..format::RX_DESC)?.try_into().ok()?;
    let metadata =
        format::receive_rates(descriptor, profile.rx_mcs, profile.vht.map_or(0, |v| v.rx)).ok()?;
    let mut body = record.bytes.get(metadata.payload.clone())?.to_vec();
    if metadata.c2h {
        return Some(Record::C2h(body));
    }
    let mut status = None;
    let phy = match format::phy_status(descriptor) {
        Some(range) => {
            let bytes = record.bytes.get(range)?;
            status = <[u8; 32]>::try_from(bytes).ok().map(alloc::boxed::Box::new);
            Some(
                super::packet_phy::parse_at(chip, metadata.rate, bytes, width)
                    .ok()
                    .filter(|p| p.on_operating(channel, width))?,
            )
        }
        None => None,
    };
    body.truncate(body.len().checked_sub(4)?);
    if body.len() < 24 && !format::native_bar(&body) {
        return None;
    }
    Some(Record::Frame(Frame::received(
        body,
        metadata.rate,
        phy,
        status,
    )))
}

/// `rtw_usb_tx_write` for one station MPDU: the PCI owner's descriptor
/// (`packet_format::transmit_profile` + RTS protection) with the USB queue
/// selection (`rtw_usb_tx_queue_mapping_to_qsel`), MORE_DATA for the HIGH
/// queue (`rtw_tx_fill_tx_desc`) and the USB checksum. Returns the packet
/// and its qsel.
pub(super) fn transmit_packet(
    frame: &[u8],
    source: [u8; 6],
    mac_id: u8,
    sequence: Option<u8>,
    profile: format::DataProfile,
    rts_threshold: Option<u32>,
) -> Result<(Vec<u8>, u8), Error> {
    build(
        frame,
        source,
        mac_id,
        sequence,
        profile,
        rts_threshold,
        None,
    )
    .map(|(packet, qsel, _)| (packet, qsel))
}

/// [`transmit_packet`] for one MPDU of an A-MPDU burst
/// (`tx.c::rtw_tx_pkt_info_update_rate`/`rtw_tx_fill_tx_desc` with
/// `pkt_info->ampdu_en`): the `packet_core` batch descriptor (W2 AGG_EN,
/// AMPDU_DENSITY; W3 MAX_AGG_NUM) before RTS protection, then the USB qsel
/// and checksum. Returns the packet, its qsel and the descriptor queue.
pub(super) fn ampdu_packet(
    frame: &[u8],
    source: [u8; 6],
    mac_id: u8,
    sequence: u8,
    profile: format::DataProfile,
    rts_threshold: Option<u32>,
    density: u8,
) -> Result<(Vec<u8>, u8, format::Queue), Error> {
    build(
        frame,
        source,
        mac_id,
        Some(sequence),
        profile,
        rts_threshold,
        Some(density),
    )
}

fn build(
    frame: &[u8],
    source: [u8; 6],
    mac_id: u8,
    sequence: Option<u8>,
    profile: format::DataProfile,
    rts_threshold: Option<u32>,
    density: Option<u8>,
) -> Result<(Vec<u8>, u8, format::Queue), Error> {
    let (mut descriptor, queue) =
        format::transmit_profile(frame, source, mac_id, sequence, profile)?;
    if let Some(density) = density {
        let word2 = u32::from_le_bytes(descriptor[8..12].try_into().unwrap())
            | (1 << 12)
            | u32::from(density) << 20;
        let word3 = u32::from_le_bytes(descriptor[12..16].try_into().unwrap()) | 3 << 17;
        descriptor[8..12].copy_from_slice(&word2.to_le_bytes());
        descriptor[12..16].copy_from_slice(&word3.to_le_bytes());
    }
    if queue.data() && (sequence.is_none() || frame[0] == 0x88) {
        super::protection::descriptor(&mut descriptor, frame.len(), rts_threshold);
    }
    let tid = if frame[0] == 0x88 { frame[24] & 7 } else { 0 };
    let qsel = usb::tx_qsel(frame, tid).ok_or(Error::Packet)?;
    let w1 = u32::from_le_bytes(descriptor[4..8].try_into().unwrap());
    let w1 =
        w1 & !(0x1f << 8 | 1 << 29) | u32::from(qsel) << 8 | u32::from(qsel == QSEL_HIGH) << 29;
    descriptor[4..8].copy_from_slice(&w1.to_le_bytes());
    usb::fill_checksum(&mut descriptor);
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(format::TX_DESC + frame.len())
        .map_err(|_| Error::Memory)?;
    packet.extend_from_slice(&descriptor);
    packet.extend_from_slice(frame);
    Ok((packet, qsel, queue))
}

/// Persistent RTL8821CU packet owner over one claimed vendor interface.
pub(super) struct Owner<I: Io> {
    io: I,
    endpoints: Endpoints,
    phase: Phase,
    own: [u8; 6],
    scan: Option<[u8; 6]>,
    mac_id: u8,
    data_profile: format::DataProfile,
    receive_chip: super::packet_phy::Chip,
    operating_channel: u8,
    operating_width: u8,
    rts_threshold: Option<u32>,
    /// Committed N21T A-MPDU envelope (`packet_core::Core::aggregation`).
    aggregation: Option<format::Aggregation>,
    /// `rtwusb->tx_queue[]`, indexed like `out_ep[]`.
    queues: [VecDeque<Queued>; EP_MAX],
    /// One URB in flight per bulk-OUT pipe.
    inflight: [Option<Inflight<I::Receipt>>; EP_MAX],
    awaiting: VecDeque<Awaiting>,
    receive: Option<I::Receipt>,
    scratch: Vec<u8>,
    next_id: u64,
    next_sequence: u8,
}
impl<I: Io> Owner<I> {
    pub(super) fn prepare(
        io: I,
        endpoints: Endpoints,
        own: [u8; 6],
        mac_id: u8,
        receive_chip: super::packet_phy::Chip,
    ) -> Result<Self, Error> {
        if own == [0; 6] || own[0] & 1 != 0 || mac_id > 127 {
            return Err(Error::Packet);
        }
        if endpoints.bulk_in & 0x80 == 0
            || endpoints.out_count == 0
            || usize::from(endpoints.out_count) > EP_MAX
        {
            return Err(Error::Address);
        }
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(MAX_RECVBUF)
            .map_err(|_| Error::Memory)?;
        scratch.resize(MAX_RECVBUF, 0);
        Ok(Self {
            io,
            endpoints,
            phase: Phase::Prepared,
            own,
            scan: None,
            mac_id,
            data_profile: format::DataProfile::LEGACY,
            receive_chip,
            operating_channel: 1,
            operating_width: 0,
            rts_threshold: None,
            aggregation: None,
            queues: Default::default(),
            inflight: Default::default(),
            awaiting: VecDeque::new(),
            receive: None,
            scratch,
            next_id: 1,
            next_sequence: 0,
        })
    }
    /// Post the persistent bulk-IN receipt before the MAC RX gate opens.
    pub(super) fn start(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.post()?;
        self.phase = Phase::Running;
        Ok(())
    }
    fn post(&mut self) -> Result<(), Error> {
        let dci = narf_drivers_usb::bulk::dci_for(self.endpoints.bulk_in);
        match self.io.begin_receive(dci, MAX_RECVBUF) {
            Ok(receipt) => {
                self.receive = Some(receipt);
                Ok(())
            }
            Err(_) => {
                self.phase = Phase::Failed;
                Err(Error::Access)
            }
        }
    }
    pub(super) fn running(&self) -> bool {
        self.phase == Phase::Running
    }
    /// No frame queued, in flight or waiting for its CCX report.
    pub(super) fn ready(&self) -> bool {
        self.running()
            && self.awaiting.is_empty()
            && self.queues.iter().all(VecDeque::is_empty)
            && self.inflight.iter().all(Option::is_none)
    }
    pub(super) fn set_rts_threshold(&mut self, threshold: Option<u32>) {
        self.rts_threshold = threshold;
    }
    pub(super) fn set_operating_width(&mut self, width: u8) {
        self.operating_width = width;
    }
    /// `packet_core::Core::set_operating_channel`: a band crossing resets
    /// DATA to that band's base profile.
    pub(super) fn set_operating_channel(&mut self, channel: u8) {
        self.operating_channel = channel;
        let band5 = super::band5::primary(channel);
        if self.data_profile.band5 != band5 {
            self.data_profile = if band5 {
                format::DataProfile::LEGACY5
            } else {
                format::DataProfile::LEGACY
            };
        }
    }
    pub(super) fn set_scan(&mut self, address: Option<[u8; 6]>) -> Result<(), Error> {
        if address.is_some_and(|a| a == [0; 6] || a[0] & 1 != 0 || a == self.own)
            || address.is_some() == self.scan.is_some()
        {
            return Err(Error::State);
        }
        self.scan = address;
        Ok(())
    }
    pub(super) fn configure_data(&mut self, profile: format::DataProfile) -> Result<(), Error> {
        if !self.ready() || !profile.valid() {
            return Err(Error::State);
        }
        self.data_profile = profile;
        Ok(())
    }
    pub(super) fn data_profile(&self) -> format::DataProfile {
        self.data_profile
    }
    fn sequence_busy(&self, sequence: u8) -> bool {
        self.awaiting.iter().any(|a| a.sequence == sequence)
            || self
                .queues
                .iter()
                .flatten()
                .chain(
                    self.inflight
                        .iter()
                        .flatten()
                        .flat_map(|i| i.packets.iter()),
                )
                .any(|q| q.sequence == Some(sequence))
    }
    /// Six-bit CCX identity (`sn << 2` in TX descriptor W6) not held by any
    /// queued, in-flight or awaiting frame.
    fn allocate_sequence(&mut self) -> Result<u8, Error> {
        for _ in 0..64 {
            let sequence = self.next_sequence << 2;
            self.next_sequence = (self.next_sequence + 1) & 63;
            if !self.sequence_busy(sequence) {
                return Ok(sequence);
            }
        }
        Err(Error::Busy)
    }
    /// `rtw_usb_tx_write` + `rtw_usb_tx_kick_off`: queue one MPDU on its
    /// pipe and start every idle pipe. `radio_report` requests the firmware
    /// CCX report as the terminal receipt.
    pub(super) fn submit(&mut self, frame: &[u8], radio_report: bool) -> Result<u64, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.queues.iter().map(VecDeque::len).sum::<usize>() >= MAX_QUEUED {
            return Err(Error::Busy);
        }
        let source = match self.scan {
            Some(scan)
                if frame.len() >= 24
                    && frame[..4] == [0x40, 0, 0, 0]
                    && frame[4..10] == [255; 6]
                    && frame[10..16] == scan =>
            {
                scan
            }
            _ => self.own,
        };
        let sequence = if radio_report {
            Some(self.allocate_sequence()?)
        } else {
            None
        };
        let (packet, qsel) = transmit_packet(
            frame,
            source,
            self.mac_id,
            sequence,
            self.data_profile,
            self.rts_threshold,
        )?;
        let pipe = usize::from(
            self.endpoints
                .qsel_to_ep
                .get(usize::from(qsel))
                .copied()
                .flatten()
                .ok_or(Error::Packet)?,
        );
        if pipe >= usize::from(self.endpoints.out_count) {
            return Err(Error::Packet);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Error::State)?;
        self.queues[pipe].push_back(Queued {
            id,
            packet,
            sequence,
        });
        self.kick()?;
        Ok(id)
    }
    /// `packet_core::Core::aggregation`: install or clear the N21T envelope
    /// while nothing is queued, in flight or awaiting a report.
    pub(super) fn aggregation(&mut self, cfg: Option<format::Aggregation>) -> Result<(), Error> {
        if !self.ready() || cfg.is_some_and(|c| !c.valid()) {
            return Err(Error::State);
        }
        self.aggregation = cfg;
        Ok(())
    }
    /// The QoS TID (A-MSDU-present bit cleared) every frame of a batch must
    /// carry (`packet_core::Core::submit_batch`).
    pub(super) fn batch_tid(frames: &[Vec<u8>]) -> Result<u8, Error> {
        Ok(frames
            .first()
            .and_then(|f| f.get(24))
            .ok_or(Error::Packet)?
            & 0x7f)
    }
    /// `packet_core::Core::submit_batch` over the USB queues (Linux
    /// `rtw_usb_tx_write` per MPDU of a mac80211 A-MPDU session, then
    /// `rtw_usb_tx_handler`'s `rtw_usb_tx_agg_skb` URB packing): one
    /// same-TID burst admitted by the committed envelope, fixed-rate without
    /// fallback, each MPDU with AGG_EN/density and its own CCX report, all on
    /// the TID's pipe. Only from an idle owner, so the burst's report
    /// sequences are distinct and no other frame interleaves in the queue.
    /// The caller proves the signed gate (`Port::batch_allowed` /
    /// `batch_publication`).
    pub(super) fn submit_batch(&mut self, frames: &[Vec<u8>]) -> Result<Vec<u64>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if !self.ready() {
            return Err(Error::Busy);
        }
        let cfg = self.aggregation.ok_or(Error::State)?;
        if !cfg.admits(self.data_profile, frames) || frames.len() > MAX_QUEUED {
            return Err(Error::Access);
        }
        let tid = Self::batch_tid(frames)?;
        let queue = self.data_profile.tid_queue(tid).ok_or(Error::Packet)?;
        let profile = format::DataProfile {
            fallback: false,
            ..self.data_profile
        };
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(frames.len())
            .map_err(|_| Error::Memory)?;
        let mut pipe = None;
        let start = self.next_sequence;
        for frame in frames {
            if frame.len() < 26 || frame[0] != 0x88 || frame[24] & 0x7f != tid || frame[25] != 0 {
                self.next_sequence = start;
                return Err(Error::Packet);
            }
            // Idle owner: consecutive allocations are distinct (count <= 4).
            let sequence = self.allocate_sequence()?;
            let built = ampdu_packet(
                frame,
                self.own,
                self.mac_id,
                sequence,
                profile,
                self.rts_threshold,
                cfg.density,
            );
            let (packet, qsel, actual) = match built {
                Ok(built) => built,
                Err(error) => {
                    self.next_sequence = start;
                    return Err(error);
                }
            };
            let ep = self
                .endpoints
                .qsel_to_ep
                .get(usize::from(qsel))
                .copied()
                .flatten()
                .map(usize::from);
            if actual != queue
                || !queue.data()
                || queue == format::Queue::Voice
                || ep.is_none_or(|ep| ep >= usize::from(self.endpoints.out_count))
                || pipe.is_some_and(|p| Some(p) != ep)
            {
                self.next_sequence = start;
                return Err(Error::Packet);
            }
            pipe = ep;
            prepared.push((packet, sequence));
        }
        let pipe = pipe.ok_or(Error::Packet)?;
        let first = self.next_id;
        let next_id = first
            .checked_add(prepared.len() as u64)
            .ok_or(Error::State)?;
        let mut ids = Vec::new();
        ids.try_reserve_exact(prepared.len())
            .map_err(|_| Error::Memory)?;
        self.queues[pipe]
            .try_reserve(prepared.len())
            .map_err(|_| Error::Memory)?;
        for (slot, (packet, sequence)) in prepared.into_iter().enumerate() {
            let id = first + slot as u64;
            self.queues[pipe].push_back(Queued {
                id,
                packet,
                sequence: Some(sequence),
            });
            ids.push(id);
        }
        self.next_id = next_id;
        self.kick()?;
        Ok(ids)
    }
    /// `rtw_usb_tx_handler`: from the highest pipe down, every idle pipe
    /// sends one `rtw_usb_tx_agg_skb` aggregate of its queue head.
    fn kick(&mut self) -> Result<(), Error> {
        for pipe in (0..usize::from(self.endpoints.out_count)).rev() {
            if self.inflight[pipe].is_some() || self.queues[pipe].is_empty() {
                continue;
            }
            let head: Vec<Vec<u8>> = self.queues[pipe]
                .iter()
                .take(usize::from(usb::TX_AGG_DESC_NUM))
                .map(|q| q.packet.clone())
                .collect();
            let (urb, count) = usb::aggregate(&head).map_err(|_| Error::Packet)?;
            let dci = narf_drivers_usb::bulk::dci_for(self.endpoints.out[pipe]);
            let receipt = match self.io.begin_send(dci, &urb) {
                Ok(receipt) => receipt,
                Err(_) => {
                    self.phase = Phase::Failed;
                    return Err(Error::Access);
                }
            };
            let packets = self.queues[pipe].drain(..count).collect();
            self.inflight[pipe] = Some(Inflight {
                receipt,
                length: urb.len(),
                packets,
            });
        }
        Ok(())
    }
    /// One non-blocking service pass: TX completions (re-kicking freed
    /// pipes), at most one bulk-IN URB, CCX report matching and the report
    /// deadline. Any error leaves the owner failed.
    pub(super) fn poll(&mut self, now_us: u64) -> Result<Step, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let result = self.service(now_us);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    fn service(&mut self, now_us: u64) -> Result<Step, Error> {
        let mut step = Step::default();
        // rtw_usb_write_port_tx_complete.
        for pipe in 0..usize::from(self.endpoints.out_count) {
            let Some(inflight) = self.inflight[pipe].as_ref() else {
                continue;
            };
            match self.io.poll_send(&inflight.receipt) {
                Ok(None) => continue,
                Ok(Some(n)) if n == inflight.length => {}
                Ok(Some(_)) => return Err(Error::Packet),
                Err(_) => return Err(Error::Access),
            }
            let inflight = self.inflight[pipe].take().ok_or(Error::State)?;
            for queued in inflight.packets {
                let bytes = queued.packet[format::TX_DESC..].to_vec();
                match queued.sequence {
                    Some(sequence) => self.awaiting.push_back(Awaiting {
                        id: queued.id,
                        sequence,
                        bytes,
                        started: now_us,
                        acknowledged: false,
                    }),
                    None => step.receipts.push(Receipt {
                        id: queued.id,
                        bytes,
                        radio_acknowledged: false,
                    }),
                }
            }
        }
        self.kick()?;
        // rtw_usb_read_port_complete -> rtw_usb_rx_handler.
        if let Some(receipt) = self.receive.as_ref() {
            match self.io.poll_receive(receipt, &mut self.scratch) {
                Ok(None) => {}
                Ok(Some(length)) => {
                    if length > self.scratch.len() {
                        return Err(Error::Packet);
                    }
                    // The terminal completion released the endpoint page:
                    // parse a private copy, then re-post before delivery.
                    self.receive = None;
                    let urb = self.scratch[..length].to_vec();
                    self.post()?;
                    step.consumed_rx = true;
                    for record in usb::split_rx(&urb) {
                        match admit(
                            &record,
                            self.data_profile,
                            self.receive_chip,
                            self.operating_channel,
                            self.operating_width,
                        ) {
                            Some(Record::Frame(frame)) => step.frames.push(frame),
                            Some(Record::C2h(body)) => {
                                self.report(&body, &mut step)?;
                                step.c2h.push(body);
                            }
                            None => {}
                        }
                    }
                }
                Err(_) => return Err(Error::Access),
            }
        } else {
            return Err(Error::State);
        }
        if self
            .awaiting
            .iter()
            .any(|a| now_us.saturating_sub(a.started) >= REPORT_TIMEOUT_US)
        {
            return Err(Error::Timeout);
        }
        Ok(step)
    }
    /// `rtw_tx_report_handle`: a CCX report acknowledges the frame holding
    /// its sequence. A NACK is terminal for the owner, as on PCI. Reports
    /// of an A-MPDU burst may arrive out of order; receipts are released in
    /// submission order only (`packet_core::Core::complete_batch`), because
    /// the station retires its pending DATA FIFO.
    fn report(&mut self, body: &[u8], step: &mut Step) -> Result<(), Error> {
        let Some(report) = format::report(body)? else {
            return Ok(());
        };
        let Some(awaiting) = self
            .awaiting
            .iter_mut()
            .find(|a| a.sequence == report.sequence && !a.acknowledged)
        else {
            return Ok(());
        };
        if !report.acknowledged {
            return Err(Error::Packet);
        }
        awaiting.acknowledged = true;
        while self.awaiting.front().is_some_and(|a| a.acknowledged) {
            let awaiting = self.awaiting.pop_front().ok_or(Error::State)?;
            step.receipts.push(Receipt {
                id: awaiting.id,
                bytes: awaiting.bytes,
                radio_acknowledged: true,
            });
        }
        Ok(())
    }
    /// `rtw_usb_cancel_rx_bufs` + `rtw_usb_tx_queue_purge`: stop every
    /// retained receipt (the controller proves each endpoint stopped) and
    /// drop the queues. Any stop error leaves the owner failed with its
    /// remaining receipts retained.
    pub(super) async fn stop(&mut self) -> Result<(), Error> {
        self.phase = Phase::Failed;
        if let Some(receipt) = self.receive.as_ref() {
            self.io.stop(receipt).await.map_err(|_| Error::Access)?;
            self.receive = None;
        }
        for pipe in 0..EP_MAX {
            if let Some(inflight) = self.inflight[pipe].as_ref() {
                self.io
                    .stop(&inflight.receipt)
                    .await
                    .map_err(|_| Error::Access)?;
                self.inflight[pipe] = None;
            }
            self.queues[pipe].clear();
        }
        self.awaiting.clear();
        self.phase = Phase::Stopped;
        Ok(())
    }
    pub(super) fn stopped(&self) -> bool {
        self.phase == Phase::Stopped
    }
}
