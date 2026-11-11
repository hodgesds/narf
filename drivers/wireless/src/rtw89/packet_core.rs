// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fresh RTL8852B BE0/MGMT8 TX rings attached to one retained RX/RPQ owner.
//! Consumption and firmware release are separate ownership facts. No reset,
//! diagnostic-ring reuse, guessed RF receipt, IRQ worker or sustained service.
use super::{mac::ChipId, packet_format as format, power, rx_packet, tx_transport};
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
/// `amsdu_allowed` invokes the original current companion full-program cap
/// bound to that exact installed base record; only its explicit body ceiling
/// admits the expanded TX shape, at both actual publication checks.
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
    /// The exact retained chip: selects the ring registers
    /// (`rtw89_pci_ch_dma_addr_set{,_v1}`) and the TXWD layout
    /// (`rtw89_core_fill_txdesc{,_v1}`). Old fixtures are RTL8852B.
    fn chip(&self) -> ChipId {
        ChipId::Rtl8852B
    }
    fn peer_allowed(&mut self, frame: &[u8]) -> Result<(), Error>;
    /// Separate current full A-MSDU emitter. Default old profiles deny.
    fn amsdu_allowed(&mut self) -> Result<Option<usize>, Error> {
        Ok(None)
    }
    /// Enclose the final quiet-prefix proof, one-shot issue, descriptor writes
    /// and doorbell in the SAME original device and full joint-program grants.
    /// A refusal before issue is Busy; failures after issue retain ownership.
    /// Last exact prefix/current part check AFTER every preceding callback/
    /// virtual/current query and immediately before the one-shot part issue.
    fn fragment_ready(&mut self, _part: &super::command_native::FragmentPart) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn fragment_publish<T>(
        &mut self,
        _part: &super::command_native::FragmentPart,
        _operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        Err(Error::Access)
    }
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
    /// Reversible WoW halt: rings published, producers refused.
    Halted,
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
    id: u64,
    ticket: tx_transport::Ticket,
    queue: format::Queue,
    started: u64,
    report: bool,
    /// Published with TXWD AGG_EN (an operational originator session).
    agg: bool,
    fragment: Option<super::command_native::FragmentPart>,
    /// TXWD MACID (always the owner MACID for a station).
    mac_id: u8,
}
/// Most data MPDUs the aggregate emitter keeps in flight at once
/// (`radio_policy::Program::Ampdu`). Every other frame is alone in flight.
pub(super) const AGG_WINDOW: usize = 32;
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
impl Frame {
    /// A host-admitted copy (PMF management with CCMP/BIP removed).
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
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
    /// PPDU status `RSSI_AVG` for this owner's MACID (`rtw89_core_rx_process_phy_ppdu_iter`).
    pub(super) rssi: Option<u8>,
    /// IE01 CFO for this owner's MACID (`rtw89_phy_cfo_parse`).
    pub(super) cfo: Option<i16>,
    /// One-path antenna-diversity PPDU observation for this owner's
    /// MACID (phy.c `rtw89_phy_antdiv_parse`): class, `RSSI_AVG`, IE01
    /// EVM. Fed to the retained diversity owner by the station's
    /// `packet_poll`; `None` when no PPDU status arrived on this poll.
    pub(super) antdiv: Option<rx_packet::AntDivObservation>,
    /// AP role only: the long-RXD `AX_RXD_MAC_ID` of `frame` (zero for a
    /// short RXD), the hardware address-CAM classification of the peer.
    pub(super) rx_mac_id: Option<u8>,
}
struct Submission<'a> {
    bytes: &'a [u8],
    radio_report: bool,
    rate: u8,
    agg: Option<format::Agg>,
    fragment: Option<&'a super::command_native::FragmentPart>,
}
pub(super) struct Core {
    phase: Phase,
    /// RTL8852A, RTL8852B or RTL8852C (ordinary station rings only, plus
    /// the AP role on A/B).
    chip: ChipId,
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
    /// In-flight frames, each owning its own TxQueue slot and DMA maps.
    pending: Vec<Pending>,
    completions: VecDeque<Receipt>,
    /// Signed aggregate emitter granted (`Program::Ampdu`).
    aggregate: bool,
    amsdu: Option<usize>,
    /// Last published A-Control form (`rtwvif_link->last_a_ctrl`).
    last_a_ctrl: bool,
    /// AP role (`prepare_ap`): multi-peer MACIDs, CH9 HIQ, unacknowledged
    /// RPQ releases are ordinary TX status rather than a failure.
    ap: bool,
    /// RX bandwidth bound (`enum rtw89_bandwidth`) of the programmed
    /// operating channel (`set_operating_width`); 0 = 20MHz.
    rx_width: u8,
    /// VHT PPDUs admitted (an HT-program owner on a 5GHz wide channel).
    rx_vht: bool,
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
        // HE without HT is the 6GHz HE-only station (no HT/VHT on 6GHz):
        // it is an `He` owner, not `Legacy` — otherwise its TX A-MPDU
        // (`enable_aggregation` needs `rx >= Ht`) and its HE RX rates
        // (`admits`) would both be refused.
        match (ht, he) {
            (_, true) => Self::He,
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
        Self::prepare_role(
            port,
            own,
            mac_id,
            format::Queue::ordinary(qos_all),
            rx,
            false,
        )
    }
    /// AP role for the vif on MACID0/port0: the ordinary rings plus the CH9
    /// high queue (pci.c `rtw89_pci_init_tx_ring` for `RTW89_TXCH_CH9`, the
    /// RTL8852B `B0HIQ` HFC channel already sized by `mac_runtime`).
    pub(super) fn prepare_ap(
        port: &mut impl Port,
        own: [u8; 6],
        qos_all: bool,
        rx: RxPhy,
    ) -> Result<Self, Error> {
        let queues = format::ap_queues(qos_all);
        Self::prepare_role(port, own, 0, &queues, rx, true)
    }
    fn prepare_role(
        port: &mut impl Port,
        own: [u8; 6],
        mac_id: u8,
        queues: &[format::Queue],
        rx: RxPhy,
        ap: bool,
    ) -> Result<Self, Error> {
        let chip = port.chip();
        if own == [0; 6]
            || own[0] & 1 != 0
            || mac_id != 0
            || !matches!(
                chip,
                ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B
            )
            // C and RTL8851B: the ordinary station rings only (BE0/MGMT8,
            // plus ACH1..3 under the signed all-AC QoS program); no AP role.
            // A admits the same rings and the AP role as B: both use the
            // AX TXWD v0 path (`rtw89_core_fill_txdesc`) and the same
            // `AX_DMA_ADDR_SET` ring registers.
            || matches!(chip, ChipId::Rtl8852C | ChipId::Rtl8851B)
                && (ap
                    || queues != format::Queue::ordinary(false)
                        && queues != format::Queue::ordinary(true))
        {
            return Err(Error::Packet);
        }
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
                chip,
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
                pending: Vec::new(),
                completions: VecDeque::new(),
                aggregate: false,
                amsdu: None,
                last_a_ctrl: false,
                ap,
                rx_width: 0,
                rx_vht: false,
            };
            for ring in &mut owner.rings {
                let regs = ring.kind.regs_for(chip);
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
    /// Admit up to `AGG_WINDOW` aggregated data frames in flight. Only the
    /// signed aggregate program (`Program::Ampdu`, which requires HT20)
    /// enables this, before `start`. RTL8852A has no A-domain aggregate
    /// program yet (the `Program::Ampdu` recipe is RTL8852B-labeled), so
    /// it stays refused here until that program lands.
    pub(super) fn enable_aggregation(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared
            || self.rx < RxPhy::Ht
            || !matches!(
                self.chip,
                ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B
            )
        {
            return Err(Error::State);
        }
        self.aggregate = true;
        Ok(())
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
            || !self.pending.is_empty()
            || scan.is_some_and(|a| a[0] & 1 != 0 || a == [0; 6] || a == self.own)
        {
            return Err(Error::State);
        }
        self.scan = scan;
        Ok(())
    }
    pub(super) fn enable_amsdu(&mut self, limit: usize) -> Result<(), Error> {
        // A admits A-MSDU only to its own `max_amsdu_limit` (3500), not B's
        // 5000 (`rtw8852a_chip_info` vs `rtw8852b_chip_info`).
        let ceiling = if self.chip == ChipId::Rtl8852A {
            super::tx_amsdu::MAX_BODY_A
        } else {
            super::tx_amsdu::MAX_BODY
        };
        if self.phase != Phase::Prepared
            || self.rx < RxPhy::Ht
            || !self.aggregate
            // No C or RTL8851B A-MSDU path (`transmit_c`/`transmit_51`
            // refuse A-MSDU subframes); A takes B's v0 path (`transmit_a`).
            || matches!(self.chip, ChipId::Rtl8852C | ChipId::Rtl8851B)
            || limit == 0
            || limit > ceiling
        {
            return Err(Error::State);
        }
        self.amsdu = Some(limit);
        Ok(())
    }
    pub(super) fn ready(&self) -> bool {
        self.phase == Phase::Running && self.pending.is_empty() && self.completions.is_empty()
    }
    /// Room for one more aggregated data frame: every frame in flight is
    /// itself aggregated and the window (including unread receipts) is open.
    pub(super) fn ready_aggregate(&self) -> bool {
        self.phase == Phase::Running
            && self.aggregate
            && self.pending.iter().all(|pending| pending.agg)
            && self.pending.len() + self.completions.len() < AGG_WINDOW
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
        self.submit_agg(port, bytes, radio_report, rate, None)
    }
    /// `submit_rate` with TXWD A-MPDU fields. An aggregated frame may join
    /// other aggregated frames in flight (`ready_aggregate`).
    pub(super) fn submit_agg(
        &mut self,
        port: &mut impl Port,
        bytes: &[u8],
        radio_report: bool,
        rate: u8,
        agg: Option<format::Agg>,
    ) -> Result<u64, Error> {
        self.submit_inner(
            port,
            Submission {
                bytes,
                radio_report,
                rate,
                agg,
                fragment: None,
            },
        )
    }
    pub(super) fn submit_fragment(
        &mut self,
        port: &mut impl Port,
        part: &super::command_native::FragmentPart,
        radio_report: bool,
        rate: u8,
    ) -> Result<u64, Error> {
        self.submit_inner(
            port,
            Submission {
                bytes: part.bytes(),
                radio_report,
                rate,
                agg: None,
                fragment: Some(part),
            },
        )
    }
    fn submit_inner<P: Port>(
        &mut self,
        port: &mut P,
        submission: Submission<'_>,
    ) -> Result<u64, Error> {
        let Submission {
            bytes,
            radio_report,
            rate,
            agg,
            fragment,
        } = submission;
        if self.phase != Phase::Running || self.ap {
            return Err(Error::State);
        }
        if agg.is_some() && !self.aggregate
            || matches!(
                self.chip,
                ChipId::Rtl8852A | ChipId::Rtl8852C | ChipId::Rtl8851B
            ) && fragment.is_some()
        {
            return Err(Error::Packet);
        }
        // HE extended-range SU TX belongs to the signed HE program only.
        if (rate & format::DATA_ER != 0 || bytes.get(1).is_some_and(|fc| fc & 0x80 != 0))
            && self.rx < RxPhy::He
        {
            return Err(Error::Packet);
        }
        if if agg.is_some() {
            !self.ready_aggregate()
        } else {
            !self.ready()
        } {
            return Err(Error::Busy);
        }
        // A probe request from the current random scan address is the only
        // frame with a source other than the own address.
        let source = match self.scan {
            Some(scan) if format::probe_request(bytes, scan) => scan,
            _ => self.own,
        };
        let kind = if fragment.is_some() {
            format::classify_fragment(bytes, source)?
        } else {
            format::classify_with(bytes, source, self.amsdu)?
        };
        let amsdu = format::amsdu(bytes);
        let a_ctrl = bytes[1] & 0x80 != 0;
        let break_aggregation = a_ctrl != self.last_a_ctrl;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or(Error::State)?;
        let mut issued = false;
        let result = port.current(|port| {
            port.ordinary_allowed()?;
            if let Some(part) = fragment {
                part.current().map_err(|_| Error::Access)?;
                if part.bytes() != bytes {
                    return Err(Error::Packet);
                }
            }
            if amsdu && port.amsdu_allowed()? != self.amsdu {
                return Err(Error::Access);
            }
            // An active-scan probe request has no peer; everything else
            // needs the current peer token.
            if !format::probe_request(bytes, source) {
                port.peer_allowed(bytes)?;
            }
            let header_capacity = if self.chip == ChipId::Rtl8852C {
                format::C_HEADER_MAX
            } else {
                format::HEADER
            };
            let packet = Packet {
                header: allocate(port, header_capacity)?,
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
                let (mut header, actual) = if self.chip == ChipId::Rtl8852C {
                    format::transmit_c(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                        rate,
                        agg,
                    )?
                } else if self.chip == ChipId::Rtl8852A {
                    format::transmit_a(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                        rate,
                        agg,
                        self.amsdu,
                    )?
                } else if self.chip == ChipId::Rtl8851B {
                    format::transmit_51(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                        rate,
                        agg,
                    )?
                } else if fragment.is_some() {
                    format::transmit_fragment(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                        rate,
                    )?
                } else {
                    format::transmit_profile(
                        bytes,
                        source,
                        self.mac_id,
                        ticket.sequence,
                        packet.body.dma_addr().raw(),
                        radio_report,
                        rate,
                        agg,
                        self.amsdu,
                    )?
                };
                if actual != kind {
                    return Err(Error::Packet);
                }
                // A-Control form changes must begin a fresh hardware
                // aggregate (rtw89_core_tx_update_he_qos_htc desc_bk).
                if break_aggregation {
                    let body3 = u32::from_le_bytes(header[12..16].try_into().unwrap());
                    header[12..16].copy_from_slice(&(body3 | 1 << 13).to_le_bytes());
                }
                copy_to(&packet.body, 0, bytes)?;
                copy_to(&packet.header, 0, &header)?;
                format::descriptor_len(packet.header.dma_addr().raw(), header.len())
                    .map_err(Error::from)
            })();
            let descriptor = match preparation {
                Ok(value) => value,
                Err(error) => {
                    let _ = ring.queue.abort(ticket)?;
                    return Err(error);
                }
            };
            let mut publish = |port: &mut P| {
                port.ordinary_allowed()?;
                if amsdu && port.amsdu_allowed()? != self.amsdu {
                    return Err(Error::Access);
                }
                if !format::probe_request(bytes, source) {
                    port.peer_allowed(bytes)?;
                }
                if let Some(part) = fragment {
                    port.fragment_ready(part)?;
                    part.issue().map_err(|_| Error::Access)?;
                }
                // Issue is recorded before the FIRST descriptor write. No Busy
                // after this point may release or retry uncertain native DMA.
                issued = true;
                ring.queue.publish(ticket)?;
                self.pending.push(Pending {
                    id,
                    ticket,
                    queue: kind,
                    started: port.now_us(),
                    report: false,
                    agg: agg.is_some(),
                    fragment: fragment.cloned(),
                    mac_id: self.mac_id,
                });
                copy_to(
                    ring.descriptors.as_ref().ok_or(Error::State)?,
                    usize::from(ticket.slot) * 8,
                    &descriptor,
                )?;
                barrier();
                let regs = kind.regs_for(self.chip);
                port.write16(regs.idx as u32, ring.queue.write_pointer())?;
                if port.read16(regs.idx as u32)? & 0x0fff != ring.queue.write_pointer() {
                    return Err(Error::Access);
                }
                self.next_id = next_id;
                self.last_a_ctrl = a_ctrl;
                Ok(id)
            };
            let result = match fragment {
                Some(part) => port.fragment_publish(part, publish),
                None => publish(port),
            };
            if result.is_err() && !issued {
                let _ = ring.queue.abort(ticket)?;
            }
            result
        });
        if result.is_err() && (fragment.is_none() || issued || result != Err(Error::Busy)) {
            self.phase = Phase::Failed;
            let _ = Self::close_dma(port, self.stop);
        }
        result
    }
    /// AP role: one frame on its `classify_ap` ring with the caller-resolved
    /// peer MACID (`Port::peer_allowed` re-proves the binding at both
    /// publication checks). Every frame is alone in flight.
    pub(super) fn submit_ap<P: Port>(
        &mut self,
        port: &mut P,
        bytes: &[u8],
        tx: format::ApTx,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running || !self.ap {
            return Err(Error::State);
        }
        if !self.ready() {
            return Err(Error::Busy);
        }
        let kind = format::classify_ap(bytes, self.own, tx.after_dtim)?;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or(Error::State)?;
        let mut issued = false;
        let result = port.current(|port| {
            port.ordinary_allowed()?;
            port.peer_allowed(bytes)?;
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
                .reserve(packet, tx.mac_id, kind.qsel())
                .map_err(|(e, _)| Error::from(e))?;
            if ticket.sequence >= format::IDENTITIES {
                let _ = ring.queue.abort(ticket)?;
                return Err(Error::State);
            }
            let packet = ring.queue.reserved_mut(ticket)?;
            let preparation = (|| {
                let (header, actual) = format::transmit_ap(
                    bytes,
                    self.own,
                    tx,
                    ticket.sequence,
                    packet.body.dma_addr().raw(),
                )?;
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
            let result = (|| {
                port.ordinary_allowed()?;
                port.peer_allowed(bytes)?;
                issued = true;
                ring.queue.publish(ticket)?;
                self.pending.push(Pending {
                    id,
                    ticket,
                    queue: kind,
                    started: port.now_us(),
                    report: false,
                    agg: false,
                    fragment: None,
                    mac_id: tx.mac_id,
                });
                copy_to(
                    ring.descriptors.as_ref().ok_or(Error::State)?,
                    usize::from(ticket.slot) * 8,
                    &descriptor,
                )?;
                barrier();
                port.write16(
                    kind.regs_for(self.chip).idx as u32,
                    ring.queue.write_pointer(),
                )?;
                if port.read16(kind.regs_for(self.chip).idx as u32)? & 0x0fff
                    != ring.queue.write_pointer()
                {
                    return Err(Error::Access);
                }
                self.next_id = next_id;
                Ok(id)
            })();
            if result.is_err() && !issued {
                let _ = ring.queue.abort(ticket)?;
            }
            result
        });
        if result.is_err() && (issued || result != Err(Error::Busy)) {
            self.phase = Phase::Failed;
            let _ = Self::close_dma(port, self.stop);
        }
        result
    }
    /// Whether this owner is the AP role.
    pub(super) fn ap(&self) -> bool {
        self.ap
    }
    /// Whether this owner published the ring for `queue`.
    pub(super) fn has_queue(&self, queue: format::Queue) -> bool {
        self.rings.iter().any(|ring| ring.kind == queue)
    }
    fn completed(&mut self, completion: tx_transport::Completion<Packet>) -> Result<(), Error> {
        // All non-success release statuses are terminal; ownership is no longer
        // ambiguous but the station must never consume a success receipt.
        // AP role: pci.c `rtw89_pci_tx_status` maps any non-TX_DONE release
        // (retry limit, lifetime, MACID drop) to a frame without
        // IEEE80211_TX_STAT_ACK; it is ordinary peer TX status.
        if completion.status != 0 && !self.ap {
            return Err(Error::Packet);
        }
        let acknowledged = completion.status == 0;
        let packet = completion.resource;
        let index = self
            .pending
            .iter()
            .position(|pending| pending.id == packet.id)
            .ok_or(Error::Packet)?;
        let bytes = copy_from(&packet.body, packet.length)?;
        if let Some(part) = &self.pending[index].fragment {
            part.terminal(&bytes).map_err(|_| Error::Packet)?;
        }
        self.completions.push_back(Receipt {
            id: packet.id,
            bytes,
            radio_acknowledged: acknowledged,
        });
        self.pending.remove(index);
        Ok(())
    }
    /// The programmed operating channel's RX bound: `width` (0/1/2/3 =
    /// 20/40/80/160MHz; 160MHz only on RTL8852C, whose `support_bandwidths`
    /// has it, RTL8852B is clamped to 80MHz) and whether VHT rates are
    /// admitted (5GHz wide channel). Linux rtw89 reports every PPDU the tuned
    /// BB decodes; this owner additionally never admits a bandwidth the radio
    /// was not tuned to.
    pub(super) fn set_operating_width(&mut self, width: u8, vht: bool) {
        let max = if self.chip == ChipId::Rtl8852C { 3 } else { 2 };
        self.rx_width = width.min(max);
        self.rx_vht = vht && self.rx_width != 0;
    }
    fn admits_rate(&self, rate: u16) -> bool {
        self.rx.admits(rate) || self.rx_vht && self.rx >= RxPhy::Ht && rx_packet::vht_rate(rate)
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
            Some(rx_packet::Event::PhyStatus(status)) => {
                if status.mac_id == self.mac_id {
                    step.rssi = Some(status.rssi);
                    step.cfo = status.cfo;
                    step.antdiv = Some(rx_packet::AntDivObservation {
                        class: status.class,
                        rssi: status.rssi,
                        evm: status.evm,
                    });
                }
            }
            // A PPDU above the signed RX PHY program (HT without `Ht`, HE
            // without `He`, VHT off a wide 5GHz channel) or wider than the
            // programmed channel is dropped exactly as the assembler dropped
            // every non-legacy rate before, without closing the station.
            Some(rx_packet::Event::Wifi(meta, _))
                if !self.admits_rate(meta.rate)
                    || meta.bandwidth > self.rx_width
                    || meta.ampdu && self.rx < RxPhy::Ht => {}
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
                    && meta.bandwidth <= self.rx_width
                    && (16..=format::MAX_MPDU).contains(&bytes.len())
                    && meta.size == bytes.len() + 4
                {
                    if self.ap {
                        step.rx_mac_id = Some(meta.mac_id);
                    }
                    step.frame = Some(Frame { bytes });
                }
            }
            Some(rx_packet::Event::Wifi(meta, bytes)) => {
                if meta.crc_error
                    || meta.icv_error
                    || meta.hardware_decrypted
                    || meta.aggregate
                    || meta.bandwidth > self.rx_width
                    || !self.admits_rate(meta.rate)
                    || bytes.len() < 24
                    || bytes.len()
                        > if super::fragment_rx::fragmented(&bytes) {
                            format::FRAGMENT_MAX_MPDU
                        } else {
                            format::MAX_MPDU
                        }
                    || meta.size != bytes.len() + 4
                {
                    return Err(Error::Packet);
                }
                // An actual A-MPDU subframe is DONTFRAG. Raw fragment
                // numbers cannot enter ordinary BA reorder as equal-SN DATA.
                if !meta.ampdu || !super::fragment_rx::fragmented(&bytes) {
                    if self.ap {
                        step.rx_mac_id = Some(meta.mac_id);
                    }
                    step.frame = Some(Frame { bytes });
                }
            }
            Some(rx_packet::Event::Releases(reports)) => {
                if reports.is_empty() || reports.len() > 256 {
                    return Err(Error::Packet);
                }
                for report in reports {
                    // Multi-entry RPQ retirement: each report names exactly
                    // one unreported in-flight frame by WD sequence, queue
                    // and MACID; anything else is a stale/forged release.
                    if !self.ap && report.mac_id != self.mac_id {
                        return Err(Error::Packet);
                    }
                    let pending = self
                        .pending
                        .iter_mut()
                        .find(|pending| {
                            !pending.report
                                && report.mac_id == pending.mac_id
                                && report.sequence == pending.ticket.sequence
                                && report.channel == pending.queue.channel()
                                && report.qsel == pending.queue.qsel()
                        })
                        .ok_or(Error::Packet)?;
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
        let result = port.current(|port| {
            port.ordinary_allowed()?;
            let mut step = Step::default();
            self.receive(port, &mut step)?;
            for slot in 0..self.rings.len() {
                let ring = &mut self.rings[slot];
                let index = port.read32(ring.kind.regs_for(self.chip).idx as u32)?;
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
            let now = port.now_us();
            if self
                .pending
                .iter()
                .any(|pending| now.saturating_sub(pending.started) >= 1_000_000)
            {
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
        self.pending.clear();
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
    /// `rtw89_wow_enable_trx_pre` host half: only a running, transmit-quiet
    /// owner (no published frame awaiting BD consumption or RPQ release)
    /// halts. Submission and polling are refused until [`Self::wow_resume`].
    pub(super) fn wow_halt(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || !self.pending.is_empty() {
            return Err(Error::Busy);
        }
        self.phase = Phase::Halted;
        Ok(())
    }
    /// `rtw89_pci_ops_reset` host half: every TX ring back to index zero
    /// with zeroed descriptors; returns (channel, regs, base, depth) for
    /// `rtw89_pci_reset_trx_rings`.
    pub(super) fn wow_rewind(
        &mut self,
    ) -> Result<Vec<(usize, super::dma::TxRingRegs, u64, u16)>, Error> {
        if self.phase != Phase::Halted {
            return Err(Error::State);
        }
        let mut bases = Vec::new();
        for ring in &mut self.rings {
            ring.queue.rewind()?;
            let memory = ring.descriptors.as_ref().ok_or(Error::State)?;
            copy_to(memory, 0, &alloc::vec![0; usize::from(format::DEPTH) * 8])?;
            bases.push((
                usize::from(ring.kind.channel()),
                ring.kind.regs_for(self.chip),
                memory.dma_addr().raw(),
                format::DEPTH,
            ));
        }
        Ok(bases)
    }
    /// Halted -> Running once the restart sequence re-opened the channels.
    pub(super) fn wow_resume(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Halted {
            return Err(Error::State);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    /// The exact TX stop bits of the rings this owner published.
    pub(super) fn stop_mask(&self) -> u32 {
        self.stop
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
