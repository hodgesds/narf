//! Intel DP MST session layer — multi-stream transport over
//! one DisplayPort link (#1017, tracker #1093 lane Q11).
//!
//! An MST branch device (a hub, a dock, a daisy-chained
//! monitor) turns one DP link into several logical streams.
//! This module is the Intel session layer over the
//! vendor-neutral MST stack that already lives in this crate:
//!
//! - [`crate::dp_mst`] — the sideband codec (message framing,
//!   CRCs, request/reply bodies, PBN math), ported from the
//!   DP 1.4a specification's messaging rules as Linux's
//!   `drm_dp_mst_topology.c` implements them;
//! - [`crate::dp_mst_mgr`] — the topology manager: MST enable,
//!   payload-table reset, branch enumeration (LINK_ADDRESS +
//!   ENUM_PATH_RESOURCES), sideband transactions with typed
//!   Nak / timeout / malformed outcomes, up-request service,
//!   remote EDID reads, and the source payload-table writer.
//!
//! What this module adds is the composition with #1092's
//! Intel machinery, and nothing else — there is no second
//! link-training or sideband implementation here:
//!
//! - [`IntelMstAux`] adapts the Intel AUX channel
//!   (`intel_gpu_aux::IntelAux`, the same transport the SST
//!   session trains over) to the manager's async `MstAux`.
//!   The manager's futures never pend on anything but the
//!   adapter's delay, so the synchronous session layer drives
//!   them with `narf_scheduler::block_on_spin` — the bridge
//!   primitive the repo reserves for callers holding an
//!   `IrqSafeSpinLock` or running with IRQs off (the HPD path
//!   is both, at different times).
//! - [`MstLink`] is one MST link on one DDI: connect (MST
//!   enable), topology probe, and per-stream bring-up /
//!   teardown. A stream is: a pipe claimed from
//!   `intel_gpu_multipipe`, a modeset on that pipe whose
//!   transcoder binds the DDI in DP-MST mode, and a VC payload
//!   allocation (source payload table first, then the
//!   ALLOCATE_PAYLOAD sideband message to the stream's end
//!   branch — the two-part order Linux and the AMD MST session
//!   in this crate both use).
//! - The *first* stream on a link negotiates and trains it
//!   through the shared link-training core, inside its
//!   modeset (the orchestrator's MST-primary entry). Later
//!   streams reuse the trained link verbatim: their modesets
//!   program only their own pipe/transcoder — per-stream M/N
//!   against the trained link — and never retrain.
//!
//! ## Failure discipline
//!
//! - Bandwidth is checked *locally before any allocation
//!   traffic*: the per-port PBN ledger built at probe time is
//!   walked along the sink's whole path, and a stream whose
//!   PBN exceeds any hop's available PBN is refused with
//!   [`MstError::InsufficientBandwidth`] before its modeset
//!   even runs — an existing stream's registers, payload
//!   entries and ledger shares are provably untouched (the
//!   fixtures pin this).
//! - A branch that refuses anyway (NAK, a short allocation, a
//!   payload-table failure) rolls the stream back in reverse
//!   order — payload deallocated, source table entry cleared,
//!   pipe modeset torn down — and the error surfaces typed.
//!   Streams already live are never touched by a failed add.
//! - Sideband timeouts and malformed replies surface as
//!   `MstError::Mgr(MstError::Timeout | MstError::Malformed)`;
//!   nothing in this layer retries silently or panics.
//!
//! ## Named remainders (not faked here)
//!
//! - Per-stream display audio (ELD publication is per-sink in
//!   the SST session; MST sinks get video only in this lane).
//! - DSC / FEC stream compression: `ENUM_PATH_RESOURCES`' FEC
//!   flag is recorded by the manager's topology but streams
//!   here are uncompressed 24 bpp.
//! - MST on Type-C DDIs inherits the orchestrator's TC PHY
//!   PLL remainder (see `intel_gpu_modeset::dpll_index_for`).

extern crate alloc;

use alloc::vec::Vec;

use crate::dp_aux::AuxError;
use crate::dp_link_training::{negotiate, stream_demand_kbps, DpcdCaps, TrainedLink};
use crate::dp_mst;
use crate::dp_mst_mgr::{Manager, MstError as MgrError, Sink, Topology};
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_dp::{mode_from_edid, DpError, INTEL_SOURCE_CAPS};
use crate::intel_gpu_modeset::{Framebuffer, LinkPlan, Mode, Modeset, ModesetError};
use crate::intel_gpu_pipes::Pipe;

/// Usable MTP time slots per link frame: 64 slots, slot 0 is
/// the MTP header (DP 1.4a §2.7.4 / MST transport). Payload
/// allocations live in slots 1..=63 — the same model the AMD
/// MST session in this crate uses.
const TOTAL_SLOTS: u8 = 63;

/// How [`MstLink`]'s adapter waits. Production waits spin on
/// the time counter (the manager's waits are register polls —
/// 1 ms reply polls, 10 ms payload-table polls — and the
/// session layer is synchronous); fixtures substitute a
/// counting delayer so a 4 s sideband timeout costs no wall
/// time. The manager's timeout *logic* (4000 polls) runs
/// identically under both.
pub trait MstDelayer {
    fn delay_us(&mut self, us: u64);
}

/// The production delayer: spin on `narf_time` cycles.
#[derive(Debug, Default)]
pub struct SpinDelayer;

impl MstDelayer for SpinDelayer {
    fn delay_us(&mut self, us: u64) {
        let budget = narf_time::wall::ns_to_cycles(us.saturating_mul(1_000));
        let start = narf_time::now_cycles();
        while narf_time::now_cycles().wrapping_sub(start) < budget {
            core::hint::spin_loop();
        }
    }
}

/// The Intel `MstAux`: DPCD reads/writes over `IntelAux`,
/// chunked to the 16-byte native-AUX transaction limit the
/// `AuxChannel` contract enforces (the same chunking the AMD
/// native-AUX adapter does).
#[derive(Debug)]
pub struct IntelMstAux<'a, M: MmioWindow + ?Sized, D: MstDelayer = SpinDelayer> {
    aux: IntelAux<'a, M>,
    delayer: D,
}

impl<'a, M: MmioWindow + ?Sized> IntelMstAux<'a, M, SpinDelayer> {
    pub fn new(mmio: &'a M, ddi: Ddi) -> Self {
        Self::with_delayer(mmio, ddi, SpinDelayer)
    }
}

impl<'a, M: MmioWindow + ?Sized, D: MstDelayer> IntelMstAux<'a, M, D> {
    pub fn with_delayer(mmio: &'a M, ddi: Ddi, delayer: D) -> Self {
        Self {
            aux: IntelAux::new(mmio, ddi),
            delayer,
        }
    }
}

impl<M: MmioWindow + ?Sized, D: MstDelayer> crate::dp_mst_mgr::MstAux for IntelMstAux<'_, M, D> {
    type Error = AuxError;

    async fn read(&mut self, address: u32, buf: &mut [u8]) -> Result<(), AuxError> {
        use crate::dp_aux::AuxChannel;
        let mut at = 0;
        while at < buf.len() {
            let n = (buf.len() - at).min(16);
            self.aux
                .dpcd_read(address + at as u32, &mut buf[at..at + n])?;
            at += n;
        }
        Ok(())
    }

    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), AuxError> {
        use crate::dp_aux::AuxChannel;
        let mut at = 0;
        while at < data.len() {
            let n = (data.len() - at).min(16);
            self.aux
                .dpcd_write(address + at as u32, &data[at..at + n])?;
            at += n;
        }
        Ok(())
    }

    async fn delay(&mut self, us: u64) {
        self.delayer.delay_us(us);
    }
}

/// Errors the MST session returns. Every failure names its
/// layer; allocation refusals carry the numbers that decided
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MstError {
    /// The underlying AUX channel failed.
    Aux(AuxError),
    /// The topology manager failed (sideband timeout, NAK,
    /// malformed reply, payload-table failure, not-MST).
    Mgr(MgrError<AuxError>),
    /// EDID read/parse for a sink failed (via the SST
    /// session's error shape).
    Edid(DpError),
    /// A stream's modeset failed.
    Modeset(ModesetError),
    /// `connect` has not run (or the link was disconnected).
    NotConnected,
    /// No topology has been probed yet.
    NotProbed,
    /// The sink is not in the probed topology.
    UnknownSink,
    /// The sink already has a live stream.
    AlreadyStreaming,
    /// No live stream exists for the sink.
    StreamNotFound,
    /// The stream's PBN exceeds the available PBN on some hop
    /// of its path. Raised locally, before any allocation
    /// traffic; carries the deciding numbers.
    InsufficientBandwidth { needed_pbn: u32, available_pbn: u32 },
    /// No VCPI or no contiguous run of MTP time slots remains
    /// on the link.
    PayloadCapacityExhausted,
}

impl From<AuxError> for MstError {
    fn from(e: AuxError) -> Self {
        MstError::Aux(e)
    }
}

impl From<MgrError<AuxError>> for MstError {
    fn from(e: MgrError<AuxError>) -> Self {
        MstError::Mgr(e)
    }
}

impl From<ModesetError> for MstError {
    fn from(e: ModesetError) -> Self {
        MstError::Modeset(e)
    }
}

/// One live MST stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MstStream {
    /// The end device this stream displays to.
    pub sink: Sink,
    /// The pipe scanning the stream out (owned via
    /// `intel_gpu_multipipe` by the glue, recorded here).
    pub pipe: Pipe,
    /// The mode being scanned out.
    pub mode: Mode,
    /// VC payload id (1..=63).
    pub vcpi: u8,
    /// First MTP time slot of the allocation (1..=63).
    pub start_slot: u8,
    /// Number of time slots allocated.
    pub slots: u8,
    /// Payload bandwidth number allocated, in PBN.
    pub pbn: u32,
}

/// A branch notification, surfaced from the manager's up
/// requests (DP 1.4a §2.7.2: CONNECTION_STATUS_NOTIFY /
/// RESOURCE_STATUS_NOTIFY).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MstEvent {
    /// A sink appeared or disappeared behind a branch port.
    ConnectionStatus {
        /// GUID of the branch that sent the notification.
        guid: [u8; 16],
        port: u8,
        /// `dp_plug || legacy_plug` from the notification.
        connected: bool,
        peer_device_type: u8,
    },
    /// A branch port's available PBN changed. The session's
    /// ledger is updated from the notification before the
    /// event is returned.
    ResourceStatus {
        guid: [u8; 16],
        port: u8,
        available_pbn: u16,
    },
}

/// One MST link: the manager, the probed topology, the
/// trained link (once the primary stream trained it), the
/// per-hop PBN ledger, and the live streams.
#[derive(Debug)]
pub struct MstLink {
    ddi: Ddi,
    mgr: Manager,
    caps: Option<DpcdCaps>,
    topology: Option<Topology>,
    trained: Option<TrainedLink>,
    /// Available PBN per connected output hop, keyed by the
    /// hop's (branch, port) `Sink` address. Seeded at probe
    /// from ENUM_PATH_RESOURCES, debited/credited as streams
    /// come and go, refreshed by RESOURCE_STATUS_NOTIFY.
    ledger: Vec<(Sink, u16)>,
    streams: Vec<MstStream>,
}

impl MstLink {
    pub fn new(ddi: Ddi) -> Self {
        Self {
            ddi,
            mgr: Manager::new(),
            caps: None,
            topology: None,
            trained: None,
            ledger: Vec::new(),
            streams: Vec::new(),
        }
    }

    pub fn ddi(&self) -> Ddi {
        self.ddi
    }

    pub fn streams(&self) -> &[MstStream] {
        &self.streams
    }

    pub fn trained(&self) -> Option<TrainedLink> {
        self.trained
    }

    pub fn topology(&self) -> Option<&Topology> {
        self.topology.as_ref()
    }

    /// Available PBN remaining on the hop out of `hop`
    /// (a branch/port address), if the ledger tracks it.
    pub fn available_pbn(&self, hop: Sink) -> Option<u16> {
        self.ledger
            .iter()
            .find(|(s, _)| *s == hop)
            .map(|(_, avail)| *avail)
    }

    /// Enable MST on the branch device at the other end of
    /// this DDI (`drm_dp_mst_topology_mgr_set_mst(true)` via
    /// the manager: MSTM_CAP check, MSTM_CTRL write, payload
    /// table reset). `caps` / `raw_caps` are the sink's DPCD
    /// receiver capabilities as the SST probe reads them
    /// (`dp_link_training::read_caps` + the raw 16 bytes).
    pub fn connect<A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        aux: &mut A,
        caps: DpcdCaps,
        raw_caps: &[u8; 16],
    ) -> Result<(), MstError> {
        narf_scheduler::block_on_spin(self.mgr.start(aux, raw_caps))?;
        self.caps = Some(caps);
        Ok(())
    }

    /// Disable MST on the branch and drop all session state.
    /// Stream teardown is the caller's job first (pipes and
    /// payloads outlive a bare `stop` otherwise); this clears
    /// the bookkeeping regardless, as a failed connect path
    /// also lands here.
    pub fn disconnect<A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(&mut self, aux: &mut A) {
        narf_scheduler::block_on_spin(self.mgr.stop(aux));
        self.caps = None;
        self.topology = None;
        self.trained = None;
        self.ledger.clear();
        self.streams.clear();
    }

    /// Enumerate the branch tree (LINK_ADDRESS walk +
    /// ENUM_PATH_RESOURCES per connected output port) and seed
    /// the PBN ledger from the replies.
    pub fn probe_topology<A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        aux: &mut A,
    ) -> Result<(), MstError> {
        if self.caps.is_none() {
            return Err(MstError::NotConnected);
        }
        let topology = narf_scheduler::block_on_spin(self.mgr.probe(aux))?;
        self.ledger.clear();
        for (branch_idx, branch) in topology.branches.iter().enumerate() {
            for port in &branch.ports {
                if !port.info.input && port.info.ddps {
                    self.ledger.push((
                        Sink {
                            branch: branch_idx,
                            port: port.info.port,
                        },
                        port.available_pbn,
                    ));
                }
            }
        }
        self.topology = Some(topology);
        Ok(())
    }

    /// Read `sink`'s EDID through its branch (REMOTE_I2C_READ)
    /// and convert the preferred timing to a modeset `Mode`,
    /// the same conversion the SST session uses.
    pub fn sink_mode<A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        aux: &mut A,
        sink: Sink,
    ) -> Result<Mode, MstError> {
        let topology = self.topology.as_ref().ok_or(MstError::NotProbed)?;
        let block =
            narf_scheduler::block_on_spin(self.mgr.read_edid_block(aux, topology, sink, 0))?;
        mode_from_edid(&block).map_err(MstError::Edid)
    }

    /// The trained link's per-slot PBN divider basis: payload
    /// bandwidth of the trained configuration, in kbps.
    fn link_payload_kbps(&self, plan: Option<LinkPlan>) -> u32 {
        match (self.trained, plan) {
            (Some(t), _) => t.rate.payload_kbps(t.lanes) as u32,
            (None, Some(p)) => p.rate.payload_kbps(p.lanes) as u32,
            (None, None) => 0,
        }
    }

    /// First-fit a run of `slots` MTP time slots in 1..=63
    /// around the live streams' allocations.
    fn alloc_slots(&self, slots: u8) -> Option<u8> {
        if slots == 0 || slots > TOTAL_SLOTS {
            return None;
        }
        let mut start = 1u8;
        while start + slots - 1 <= TOTAL_SLOTS {
            let end = start + slots;
            let clash = self
                .streams
                .iter()
                .any(|s| start < s.start_slot + s.slots && s.start_slot < end);
            if !clash {
                return Some(start);
            }
            start += 1;
        }
        None
    }

    /// The lowest free VC payload id (1..=63).
    fn alloc_vcpi(&self) -> Option<u8> {
        (1..=63u8).find(|v| self.streams.iter().all(|s| s.vcpi != *v))
    }

    /// Bring one stream up: modeset on `pipe` (training the
    /// link if this is the first stream), payload allocation,
    /// ledger debit. `mode` is the sink's preferred mode (see
    /// [`MstLink::sink_mode`]); `fb` scans out on `pipe`;
    /// `dbuf_share` is the pipe's share under the post-add
    /// active set, when the coordinator computed one.
    ///
    /// On any failure after the modeset, the stream is rolled
    /// back (payload deallocated, pipe torn down) and no live
    /// stream's state changes; on a bandwidth refusal, nothing
    /// is touched at all (see the module docs).
    #[allow(clippy::too_many_arguments)]
    pub fn add_stream<M: MmioWindow + ?Sized, A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        mmio: &M,
        aux: &mut A,
        sink: Sink,
        mode: Mode,
        pipe: Pipe,
        fb: &Framebuffer,
        dbuf_share: Option<(u16, u16)>,
    ) -> Result<MstStream, MstError> {
        let topology = self.topology.as_ref().ok_or(MstError::NotProbed)?;
        let caps = self.caps.ok_or(MstError::NotConnected)?;
        if self.streams.iter().any(|s| s.sink == sink) {
            return Err(MstError::AlreadyStreaming);
        }
        let port = *topology.port(sink).ok_or(MstError::UnknownSink)?;
        let path = topology.path(sink).ok_or(MstError::UnknownSink)?;

        // Bandwidth arithmetic first: PBN and slots from the
        // DP spec's math (dp_mst, Linux-derived), against the
        // link this stream will run on — the negotiated plan
        // for a primary stream, the trained link for a
        // secondary.
        let primary = self.trained.is_none();
        let plan = if primary {
            let demand = stream_demand_kbps(mode.pixel_clock_khz, 24);
            let negotiated = negotiate(&INTEL_SOURCE_CAPS, &caps, demand);
            Some(LinkPlan {
                rate: negotiated.rate,
                lanes: negotiated.lanes,
            })
        } else {
            None
        };
        let link_kbps = self.link_payload_kbps(plan);
        let pbn = dp_mst::calc_pbn_mode(mode.pixel_clock_khz, 24 * 16);
        let slots = dp_mst::time_slots(pbn, dp_mst::pbn_div(link_kbps));
        if slots == 0 || slots > TOTAL_SLOTS as u32 {
            return Err(MstError::InsufficientBandwidth {
                needed_pbn: pbn,
                available_pbn: 0,
            });
        }
        let slots = slots as u8;

        // The local refusal: every hop of the path must carry
        // the stream's PBN out of what the ledger says remains.
        // This happens before the modeset and before any
        // allocation traffic — a refused stream changes nothing.
        for hop in &path {
            let available = self.available_pbn(*hop).unwrap_or(0);
            if (available as u32) < pbn {
                return Err(MstError::InsufficientBandwidth {
                    needed_pbn: pbn,
                    available_pbn: available as u32,
                });
            }
        }

        let vcpi = self
            .alloc_vcpi()
            .ok_or(MstError::PayloadCapacityExhausted)?;
        let start_slot = self
            .alloc_slots(slots)
            .ok_or(MstError::PayloadCapacityExhausted)?;

        // Modeset. The primary stream trains the link (MST
        // mode from the start); a secondary stream programs
        // only its own pipe from the trained configuration.
        let mut modeset = Modeset::for_pipe(mmio, self.ddi, pipe);
        if let Some((start, end)) = dbuf_share {
            modeset.set_dbuf_share(start, end);
        }
        let trained_now = if primary {
            let (.., trained) = modeset.modeset_mst_primary(fb, &mode, plan.unwrap())?;
            Some(trained)
        } else {
            modeset.modeset_mst_secondary(fb, &mode, self.trained.unwrap())?;
            None
        };
        if let Some(trained) = trained_now {
            self.trained = Some(trained);
        }

        // Payload, part 1: the source payload table on the
        // primary branch (drm_dp_dpcd_write_payload).
        if let Err(e) = narf_scheduler::block_on_spin(crate::dp_mst_mgr::write_payload(
            aux, vcpi, start_slot, slots,
        )) {
            self.rollback_modeset(mmio, pipe);
            return Err(MstError::Mgr(e));
        }

        // Payload, part 2: ALLOCATE_PAYLOAD to the stream's
        // end branch (drm_dp_send_payload_msgs).
        let branch = topology.branches[sink.branch].clone();
        let request = dp_mst::Request::AllocatePayload {
            port: sink.port,
            vcpi,
            pbn: pbn as u16,
            sdp_stream_sinks: (0..port.info.sdp_streams).collect(),
        };
        let allocated = narf_scheduler::block_on_spin(self.mgr.transact(
            aux,
            branch.lct,
            &branch.rad,
            &request,
        ));
        match allocated {
            Ok(dp_mst::Reply::AllocatePayload {
                port: reply_port,
                pbn: granted,
                ..
            }) if reply_port == sink.port && granted as u32 == pbn => {}
            Ok(dp_mst::Reply::AllocatePayload { pbn: granted, .. }) => {
                // The branch granted less than the stream needs
                // (or answered for another port): a refusal.
                self.rollback_payload(aux, sink, &branch, vcpi, start_slot);
                self.rollback_modeset(mmio, pipe);
                return Err(MstError::InsufficientBandwidth {
                    needed_pbn: pbn,
                    available_pbn: granted as u32,
                });
            }
            Ok(_) => {
                self.rollback_payload(aux, sink, &branch, vcpi, start_slot);
                self.rollback_modeset(mmio, pipe);
                return Err(MstError::Mgr(MgrError::Malformed));
            }
            Err(e) => {
                self.rollback_payload(aux, sink, &branch, vcpi, start_slot);
                self.rollback_modeset(mmio, pipe);
                return Err(MstError::Mgr(e));
            }
        }

        // Success: debit the ledger along the path and record
        // the stream.
        for hop in &path {
            if let Some(entry) = self.ledger.iter_mut().find(|(s, _)| s == hop) {
                entry.1 = entry.1.saturating_sub(pbn as u16);
            }
        }
        let stream = MstStream {
            sink,
            pipe,
            mode,
            vcpi,
            start_slot,
            slots,
            pbn,
        };
        self.streams.push(stream);
        Ok(stream)
    }

    /// Undo a failed stream's modeset: a stream that never
    /// carried payload leaves its pipe dark; if it was the
    /// link's only (primary) stream, the whole pipeline —
    /// DDI buffer included — comes down and the link is
    /// untrained again.
    fn rollback_modeset<M: MmioWindow + ?Sized>(&mut self, mmio: &M, pipe: Pipe) {
        let mut modeset = Modeset::for_pipe(mmio, self.ddi, pipe);
        if self.streams.is_empty() {
            modeset.teardown();
            self.trained = None;
        } else {
            modeset.teardown_stream();
        }
    }

    /// Undo a failed stream's payload allocation, best-effort
    /// in the order Linux tolerates: ALLOCATE_PAYLOAD with
    /// PBN 0 to the end branch, then the source table entry
    /// cleared (drm_dp_remove_payload_part2 / part1 failure
    /// handling).
    fn rollback_payload<A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        aux: &mut A,
        sink: Sink,
        branch: &crate::dp_mst_mgr::Branch,
        vcpi: u8,
        start_slot: u8,
    ) {
        let request = dp_mst::Request::AllocatePayload {
            port: sink.port,
            vcpi,
            pbn: 0,
            sdp_stream_sinks: Vec::new(),
        };
        let _ = narf_scheduler::block_on_spin(self.mgr.transact(
            aux,
            branch.lct,
            &branch.rad,
            &request,
        ));
        let _ = narf_scheduler::block_on_spin(crate::dp_mst_mgr::write_payload(
            aux, vcpi, start_slot, 0,
        ));
    }

    /// Take one stream down: deallocate its payload (branch
    /// message, then source table entry — failures tolerated,
    /// as Linux tolerates them on a possibly-dead branch),
    /// tear its pipe down, credit the ledger, and compact the
    /// surviving streams' slot allocations down over the gap
    /// (the payload table is kept dense, as
    /// `drm_dp_remove_payload_part1` leaves it). Removing the
    /// last stream tears the whole link pipeline down and
    /// untrains the link.
    pub fn remove_stream<M: MmioWindow + ?Sized, A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        mmio: &M,
        aux: &mut A,
        sink: Sink,
    ) -> Result<MstStream, MstError> {
        let index = self
            .streams
            .iter()
            .position(|s| s.sink == sink)
            .ok_or(MstError::StreamNotFound)?;
        let stream = self.streams[index];
        let topology = self.topology.as_ref().ok_or(MstError::NotProbed)?;

        if let Some(branch) = topology.branches.get(sink.branch) {
            let request = dp_mst::Request::AllocatePayload {
                port: sink.port,
                vcpi: stream.vcpi,
                pbn: 0,
                sdp_stream_sinks: Vec::new(),
            };
            let _ = narf_scheduler::block_on_spin(self.mgr.transact(
                aux,
                branch.lct,
                &branch.rad,
                &request,
            ));
        }
        let _ = narf_scheduler::block_on_spin(crate::dp_mst_mgr::write_payload(
            aux,
            stream.vcpi,
            stream.start_slot,
            0,
        ));

        // Pipe teardown: the last stream takes the DDI buffer
        // and the trained state down with it; any other stream
        // leaves the link running for its survivors.
        let mut modeset = Modeset::for_pipe(mmio, self.ddi, stream.pipe);
        if self.streams.len() == 1 {
            modeset.teardown();
            self.trained = None;
        } else {
            modeset.teardown_stream();
        }

        // Credit the ledger along the stream's path.
        if let Some(path) = topology.path(sink) {
            for hop in &path {
                if let Some(entry) = self.ledger.iter_mut().find(|(s, _)| s == hop) {
                    entry.1 = entry.1.saturating_add(stream.pbn as u16);
                }
            }
        }

        self.streams.remove(index);

        // Compaction: streams allocated above the gap move
        // down over it, and their source-table entries are
        // rewritten at the new start (failures tolerated —
        // the local record is authoritative for the next add).
        for later in self
            .streams
            .iter_mut()
            .filter(|s| s.start_slot > stream.start_slot)
        {
            later.start_slot -= stream.slots;
            let _ = narf_scheduler::block_on_spin(crate::dp_mst_mgr::write_payload(
                aux,
                later.vcpi,
                later.start_slot,
                later.slots,
            ));
        }
        Ok(stream)
    }

    /// Service pending branch notifications (bounded per
    /// call by the manager) and return them as session events.
    /// RESOURCE_STATUS_NOTIFY also refreshes the ledger entry
    /// it names, so a later `add_stream` decides against the
    /// branch's own latest numbers.
    pub fn poll_notifications<A: crate::dp_mst_mgr::MstAux<Error = AuxError>>(
        &mut self,
        aux: &mut A,
    ) -> Result<Vec<MstEvent>, MstError> {
        narf_scheduler::block_on_spin(self.mgr.poll_up_requests(aux))?;
        let mut events = Vec::new();
        for up in self.mgr.events.drain(..) {
            match up {
                dp_mst::UpRequest::ConnectionStatus {
                    port,
                    guid,
                    legacy_plug,
                    dp_plug,
                    peer_device_type,
                    ..
                } => events.push(MstEvent::ConnectionStatus {
                    guid,
                    port,
                    connected: dp_plug || legacy_plug,
                    peer_device_type,
                }),
                dp_mst::UpRequest::ResourceStatus {
                    port,
                    guid,
                    available_pbn,
                } => {
                    if let Some(topology) = self.topology.as_ref() {
                        if let Some(branch_idx) =
                            topology.branches.iter().position(|b| b.guid == guid)
                        {
                            let hop = Sink {
                                branch: branch_idx,
                                port,
                            };
                            if let Some(entry) = self.ledger.iter_mut().find(|(s, _)| *s == hop) {
                                entry.1 = available_pbn;
                            }
                        }
                    }
                    events.push(MstEvent::ResourceStatus {
                        guid,
                        port,
                        available_pbn,
                    });
                }
            }
        }
        Ok(events)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! MST hub fixtures. `HubMmio` is a register-level model of
    //! the Gen12 display block (the same hardware mirrors the
    //! multipipe fixtures use) whose AUX channel talks to a
    //! two-branch MST topology model.
    //!
    //! The hub is an independent party to the conversation, in
    //! the spec-fixture sense: it decodes AUX frames itself
    //! (DP 1.4a §2.7.4), decodes sideband messages itself
    //! (header layout, CRC-4 over the header nibbles, CRC-8
    //! 0xD5 per body piece — both implemented here from the
    //! polynomial definitions), routes by (LCT, RAD), and
    //! answers from its own per-branch state: port tables for
    //! LINK_ADDRESS, a PBN ledger per port for
    //! ENUM_PATH_RESOURCES / ALLOCATE_PAYLOAD, EDID stores
    //! behind REMOTE_I2C_READ, the source payload table behind
    //! DP_PAYLOAD_ALLOCATE_SET, and ESI ready bits driven by
    //! its message queues. Nothing in the hub calls the
    //! production codec or manager; agreement between the two
    //! sides is what the smokes pin.

    extern crate alloc;

    use super::*;
    use crate::dp_aux::AuxChannel as _;
    use crate::intel_gpu_aux::{
        AUX_CTL_DONE, AUX_CTL_MSGSIZE_MASK, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY,
        DDI_AUX_CTL_OFFSET, DDI_AUX_DATA_OFFSET,
    };
    use crate::intel_gpu_ddi::DDI_BUF_CTL_OFFSET;
    use crate::intel_gpu_pipes::{Transcoder, PIPECONF_OFFSET};
    use alloc::collections::{BTreeMap, VecDeque};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Virtual time ────────────────────────────────────────

    /// A delayer that counts virtual microseconds instead of
    /// spinning: the manager's 4 s reply timeout becomes 4000
    /// instant polls (its logic — the poll count, the typed
    /// error — runs unchanged).
    #[derive(Debug, Default)]
    struct CountingDelayer {
        total_us: u64,
    }

    impl MstDelayer for CountingDelayer {
        fn delay_us(&mut self, us: u64) {
            self.total_us = self.total_us.saturating_add(us);
        }
    }

    type TestAux<'a> = IntelMstAux<'a, HubMmio, CountingDelayer>;

    fn test_aux(mmio: &HubMmio) -> TestAux<'_> {
        IntelMstAux::with_delayer(mmio, Ddi::B, CountingDelayer::default())
    }

    // ── Sideband wire codec (fixture's own) ─────────────────
    //
    // Written from DP 1.4a §2.7 (sideband messaging): header =
    // (LCT<<4 | LCR), RAD nibbles packed one byte per two hops,
    // a byte with broadcast<<7 | path<<6 | msg_len (body bytes
    // in this message, CRC included), a byte with SOMT<<7 |
    // EOMT<<6 | seqno<<4 | header CRC-4 in the low nibble.
    // CRC-4: polynomial x^4+x+1 over the header nibbles except
    // the CRC nibble itself. CRC-8 ("data CRC"): polynomial
    // 0xD5 over each message's body piece.

    fn fixture_header_crc4(data: &[u8], nibbles: usize) -> u8 {
        let mut remainder: u8 = 0;
        for bit in 0..nibbles * 4 {
            remainder = (remainder << 1) | ((data[bit / 8] >> (7 - bit % 8)) & 1);
            if remainder & 0x10 != 0 {
                remainder ^= 0x13;
            }
        }
        for _ in 0..4 {
            remainder <<= 1;
            if remainder & 0x10 != 0 {
                remainder ^= 0x13;
            }
        }
        remainder & 0xF
    }

    fn fixture_data_crc(data: &[u8]) -> u8 {
        let mut remainder: u16 = 0;
        for bit in 0..data.len() * 8 {
            remainder = (remainder << 1) | u16::from((data[bit / 8] >> (7 - bit % 8)) & 1);
            if remainder & 0x100 != 0 {
                remainder ^= 0xD5;
            }
        }
        for _ in 0..8 {
            remainder <<= 1;
            if remainder & 0x100 != 0 {
                remainder ^= 0xD5;
            }
        }
        remainder as u8
    }

    /// Split `body` into sideband messages for (lct, rad),
    /// each ≤ 48 bytes with its own header + data CRC.
    fn fixture_sb_messages(lct: u8, rad: &[u8; 8], body: &[u8]) -> Vec<Vec<u8>> {
        let n_rad = (lct / 2) as usize;
        let hdrlen = 3 + n_rad;
        let space = 48 - 1 - hdrlen;
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let send = (body.len() - offset).min(space);
            let piece = &body[offset..offset + send];
            let mut msg = Vec::new();
            msg.push((lct << 4) | (lct.saturating_sub(1) & 0xF));
            msg.extend_from_slice(&rad[..n_rad]);
            msg.push((piece.len() as u8 + 1) & 0x3F);
            let mut tail = 0u8;
            if offset == 0 {
                tail |= 1 << 7; // SOMT
            }
            if offset + send == body.len() {
                tail |= 1 << 6; // EOMT
            }
            msg.push(tail);
            let crc = fixture_header_crc4(&msg, msg.len() * 2 - 1);
            *msg.last_mut().unwrap() |= crc;
            msg.extend_from_slice(piece);
            msg.push(fixture_data_crc(piece));
            out.push(msg);
            offset += send;
            if offset == body.len() {
                return out;
            }
        }
    }

    /// Decode one sideband message from the front of `buf`;
    /// returns (lct, rad, body piece, total bytes consumed).
    /// The fixture's own header parse — a bad header CRC makes
    /// the message undecodable, exactly as the hub would treat
    /// a garbled request (it drops it).
    fn fixture_sb_decode(buf: &[u8]) -> Option<(u8, [u8; 8], Vec<u8>, usize)> {
        if buf.len() < 3 || buf[0] == 0 {
            return None;
        }
        let lct = buf[0] >> 4;
        let n_rad = (lct / 2) as usize;
        let hdrlen = 3 + n_rad;
        if buf.len() < hdrlen {
            return None;
        }
        if fixture_header_crc4(buf, hdrlen * 2 - 1) != buf[hdrlen - 1] & 0xF {
            return None;
        }
        let msg_len = (buf[1 + n_rad] & 0x3F) as usize;
        if msg_len < 1 || buf.len() < hdrlen + msg_len {
            return None;
        }
        let mut rad = [0u8; 8];
        rad[..n_rad].copy_from_slice(&buf[1..1 + n_rad]);
        let body = buf[hdrlen..hdrlen + msg_len - 1].to_vec();
        Some((lct, rad, body, hdrlen + msg_len))
    }

    // ── EDID fixture ────────────────────────────────────────

    /// One detailed-timing descriptor, E-EDID §3.10 layout.
    fn fixture_detailed_timing(
        out: &mut [u8],
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        v_active: u16,
        v_blank: u16,
    ) {
        let pclk_10k = (pclk_khz / 10) as u16;
        out[0] = pclk_10k as u8;
        out[1] = (pclk_10k >> 8) as u8;
        out[2] = h_active as u8;
        out[3] = h_blank as u8;
        out[4] = (((h_active >> 8) as u8 & 0xF) << 4) | ((h_blank >> 8) as u8 & 0xF);
        out[5] = v_active as u8;
        out[6] = v_blank as u8;
        out[7] = (((v_active >> 8) as u8 & 0xF) << 4) | ((v_blank >> 8) as u8 & 0xF);
        out[8] = 88; // h sync offset
        out[9] = 44; // h sync width
        out[10] = (4 << 4) | 5; // v sync offset 4, width 5
        out[12] = 52;
        out[13] = 29;
        out[17] = 0x1E; // digital separate sync, +H +V
    }

    /// A complete, checksummed 128-byte EDID base block whose
    /// preferred timing is the given mode.
    fn fixture_edid(
        pclk_khz: u32,
        h_active: u16,
        h_blank: u16,
        v_active: u16,
        v_blank: u16,
    ) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        let mfr: u16 = (14 << 10) | (1 << 5) | 18; // "NAR"
        e[8] = (mfr >> 8) as u8;
        e[9] = mfr as u8;
        e[18] = 1;
        e[19] = 4;
        fixture_detailed_timing(
            &mut e[0x36..0x36 + 18],
            pclk_khz,
            h_active,
            h_blank,
            v_active,
            v_blank,
        );
        let sum: u32 = e[..127].iter().map(|b| *b as u32).sum();
        e[127] = ((256 - (sum % 256)) % 256) as u8;
        e
    }

    fn edid_1080p() -> [u8; 128] {
        fixture_edid(148_500, 1920, 280, 1080, 45)
    }

    fn edid_1440p() -> [u8; 128] {
        fixture_edid(241_500, 2560, 160, 1440, 21)
    }

    // ── The hub topology model ──────────────────────────────

    const ROOT_GUID: [u8; 16] = [0xA0; 16];
    const CHILD_GUID: [u8; 16] = [0xB0; 16];

    #[derive(Debug, Clone)]
    struct HubPort {
        number: u8,
        input: bool,
        peer: u8,
        mcs: bool,
        ddps: bool,
        child: Option<usize>,
        edid: Option<[u8; 128]>,
        full_pbn: u16,
        avail_pbn: u16,
    }

    #[derive(Debug)]
    struct HubBranch {
        guid: [u8; 16],
        ports: Vec<HubPort>,
        /// Live sideband allocations: (vcpi, port, pbn).
        allocated: Vec<(u8, u8, u16)>,
    }

    #[derive(Debug)]
    struct Hub {
        branches: Vec<HubBranch>,
        mst_capable: bool,
        /// Refuse every ALLOCATE_PAYLOAD with a NAK.
        nak_allocate: bool,
        /// Corrupt the header CRC of the first reply message.
        corrupt_replies: bool,
        /// Never answer down requests at all.
        deaf: bool,
        // Root-device DPCD state.
        caps: [u8; 16],
        mstm_ctrl: u8,
        pattern: u8,
        polls: u32,
        powered: bool,
        /// Source payload table: vcpi → (start, count).
        source_table: BTreeMap<u8, (u8, u8)>,
        /// Every payload-table write, in order (vcpi, start, count).
        payload_log: Vec<(u8, u8, u8)>,
        payload_updated: bool,
        // Sideband plumbing.
        down_req_buf: Vec<u8>,
        /// Body pieces of the down request being reassembled.
        assembly: Vec<u8>,
        down_rep_queue: VecDeque<Vec<u8>>,
        up_req_queue: VecDeque<Vec<u8>>,
        up_rep_buf: Vec<u8>,
        /// Completed up-reply bodies (the manager's ACKs).
        up_rep_bodies: Vec<Vec<u8>>,
        /// Every completed down request: (kind, lct).
        request_log: Vec<(u8, u8)>,
        /// Every AUX wire frame, verbatim.
        wire_log: Vec<Vec<u8>>,
        training_pattern_writes: u32,
    }

    impl Hub {
        fn new(branches: Vec<HubBranch>) -> Self {
            let mut caps = [0u8; 16];
            caps[0] = 0x14; // DP 1.4
            caps[1] = 0x14; // HBR2
            caps[2] = 0xC4; // 4 lanes | TPS3 | enhanced framing
            Self {
                branches,
                mst_capable: true,
                nak_allocate: false,
                corrupt_replies: false,
                deaf: false,
                caps,
                mstm_ctrl: 0,
                pattern: 0,
                polls: 0,
                powered: false,
                source_table: BTreeMap::new(),
                payload_log: Vec::new(),
                payload_updated: false,
                down_req_buf: Vec::new(),
                assembly: Vec::new(),
                down_rep_queue: VecDeque::new(),
                up_req_queue: VecDeque::new(),
                up_rep_buf: Vec::new(),
                up_rep_bodies: Vec::new(),
                request_log: Vec::new(),
                wire_log: Vec::new(),
                training_pattern_writes: 0,
            }
        }

        fn cr_locked(&self) -> bool {
            self.powered && self.pattern >= 1
        }

        fn eq_done(&self) -> bool {
            self.pattern >= 2 && self.polls >= 1 && self.cr_locked()
        }

        fn lane_status_byte(&self) -> u8 {
            let mut nibble = 0u8;
            if self.cr_locked() {
                nibble |= 0x1;
            }
            if self.eq_done() {
                nibble |= 0x2 | 0x4;
            }
            nibble | (nibble << 4)
        }

        fn esi0(&self) -> u8 {
            let mut v = 0u8;
            if !self.down_rep_queue.is_empty() {
                v |= 0x10; // DOWN_REP_MSG_RDY
            }
            if !self.up_req_queue.is_empty() {
                v |= 0x20; // UP_REQ_MSG_RDY
            }
            v
        }

        fn dpcd_read(&mut self, addr: u32, len: usize) -> Vec<u8> {
            let mut out = Vec::new();
            for i in 0..len {
                let a = addr + i as u32;
                out.push(match a {
                    0x000..=0x00F => self.caps[a as usize],
                    0x021 => {
                        if self.mst_capable {
                            1
                        } else {
                            0
                        }
                    }
                    0x111 => self.mstm_ctrl,
                    0x202 => {
                        self.polls += 1;
                        self.lane_status_byte()
                    }
                    0x203 => self.lane_status_byte(),
                    0x204 => {
                        if self.eq_done() {
                            0x01
                        } else {
                            0x00
                        }
                    }
                    0x2C0 => {
                        if self.payload_updated {
                            1
                        } else {
                            0
                        }
                    }
                    0x2003 => self.esi0(),
                    0x1400..=0x15FF => self
                        .down_rep_queue
                        .front()
                        .and_then(|m| m.get((a - 0x1400) as usize).copied())
                        .unwrap_or(0),
                    0x1600..=0x17FF => self
                        .up_req_queue
                        .front()
                        .and_then(|m| m.get((a - 0x1600) as usize).copied())
                        .unwrap_or(0),
                    _ => 0,
                });
            }
            out
        }

        fn dpcd_write(&mut self, addr: u32, data: &[u8]) {
            // The payload-table entry write is one 3-byte
            // transaction at DP_PAYLOAD_ALLOCATE_SET.
            if addr == 0x1C0 && data.len() == 3 {
                let (vcpi, start, count) = (data[0], data[1], data[2]);
                self.payload_log.push((vcpi, start, count));
                if vcpi == 0 {
                    self.source_table.clear();
                } else if count == 0 {
                    self.source_table.remove(&vcpi);
                } else {
                    self.source_table.insert(vcpi, (start, count));
                }
                self.payload_updated = true;
                return;
            }
            for (i, b) in data.iter().enumerate() {
                let a = addr + i as u32;
                match a {
                    0x111 => self.mstm_ctrl = *b,
                    0x102 => {
                        self.pattern = b & 0x7;
                        self.polls = 0;
                        self.training_pattern_writes += 1;
                    }
                    0x600 => self.powered = b & 0x1 != 0,
                    0x2C0 => {
                        if b & 1 != 0 {
                            self.payload_updated = false;
                        }
                    }
                    0x2003 => {
                        if b & 0x10 != 0 {
                            self.down_rep_queue.pop_front();
                        }
                        if b & 0x20 != 0 {
                            self.up_req_queue.pop_front();
                        }
                    }
                    0x1000..=0x10FF => {
                        let off = (a - 0x1000) as usize;
                        if self.down_req_buf.len() <= off {
                            self.down_req_buf.resize(off + 1, 0);
                        }
                        self.down_req_buf[off] = *b;
                    }
                    0x1200..=0x12FF => {
                        let off = (a - 0x1200) as usize;
                        if self.up_rep_buf.len() <= off {
                            self.up_rep_buf.resize(off + 1, 0);
                        }
                        self.up_rep_buf[off] = *b;
                    }
                    _ => {}
                }
            }
            self.drain_buffers();
        }

        /// Extract and process any complete sideband messages
        /// sitting in the down-request / up-reply buffers.
        fn drain_buffers(&mut self) {
            while let Some((lct, rad, piece, consumed)) = fixture_sb_decode(&self.down_req_buf) {
                self.down_req_buf.drain(..consumed);
                self.on_down_piece(lct, &rad, &piece);
            }
            while let Some((_, _, piece, consumed)) = fixture_sb_decode(&self.up_rep_buf) {
                self.up_rep_buf.drain(..consumed);
                self.up_rep_bodies.push(piece);
            }
        }

        /// Down-request reassembly: pieces of one request
        /// arrive as separate sideband messages and the hub
        /// dispatches once the accumulated body parses as a
        /// complete request for its kind
        /// (`fixture_request_complete`). Fixture requests from
        /// the production side are small; REMOTE_I2C_READ is
        /// the only variable-length one and is sized by its
        /// own write-list fields.
        fn on_down_piece(&mut self, lct: u8, rad: &[u8; 8], piece: &[u8]) {
            self.assembly.extend_from_slice(piece);
            let body = self.assembly.clone();
            if !fixture_request_complete(&body) {
                return;
            }
            self.assembly.clear();
            self.on_down_request(lct, rad, &body);
        }

        fn on_down_request(&mut self, lct: u8, rad: &[u8; 8], body: &[u8]) {
            let kind = body[0] & 0x7F;
            self.request_log.push((kind, lct));
            if self.deaf {
                return;
            }
            let reply = self.dispatch(lct, rad, body);
            if let Some(reply_body) = reply {
                let mut msgs = fixture_sb_messages(lct, rad, &reply_body);
                if self.corrupt_replies {
                    if let Some(first) = msgs.first_mut() {
                        // Break the header CRC nibble.
                        let hdrlen = 3 + (lct / 2) as usize;
                        first[hdrlen - 1] ^= 0x0F;
                    }
                    self.corrupt_replies = false;
                }
                self.down_rep_queue.extend(msgs);
            }
        }

        /// Answer one down request from branch state. Returns
        /// the reply body (kind byte first, NAKs with bit 7).
        fn dispatch(&mut self, lct: u8, rad: &[u8; 8], body: &[u8]) -> Option<Vec<u8>> {
            let kind = body[0] & 0x7F;
            // Split the borrow: routing needs the branch, NAKs
            // need its GUID.
            let branch_idx = if lct == 1 {
                0
            } else if lct == 2 {
                let port_no = rad[0] & 0xF;
                self.branches.first()?.ports.iter().find_map(|p| {
                    if p.number == port_no {
                        p.child
                    } else {
                        None
                    }
                })?
            } else {
                return None;
            };
            let branch = &mut self.branches[branch_idx];
            match kind {
                // LINK_ADDRESS
                0x01 => {
                    let mut out = alloc::vec![0x01];
                    out.extend_from_slice(&branch.guid);
                    out.push(branch.ports.len() as u8 & 0xF);
                    for p in &branch.ports {
                        out.push(
                            (if p.input { 0x80 } else { 0 })
                                | ((p.peer & 0x7) << 4)
                                | (p.number & 0xF),
                        );
                        out.push((if p.mcs { 0x80 } else { 0 }) | (if p.ddps { 0x40 } else { 0 }));
                        if !p.input {
                            out.push(0x14); // peer DPCD revision: DP 1.4
                            out.extend_from_slice(&[0u8; 16]); // peer GUID
                            out.push(0); // SDP streams / sinks
                        }
                    }
                    Some(out)
                }
                // ENUM_PATH_RESOURCES
                0x10 => {
                    let port_no = body[1] >> 4;
                    let p = branch.ports.iter().find(|p| p.number == port_no)?;
                    let mut out = alloc::vec![0x10, port_no << 4];
                    out.extend_from_slice(&p.full_pbn.to_be_bytes());
                    out.extend_from_slice(&p.avail_pbn.to_be_bytes());
                    Some(out)
                }
                // ALLOCATE_PAYLOAD
                0x11 => {
                    let parent = self.parent_hop(branch_idx);
                    self.dispatch_allocate(branch_idx, parent, body)
                }
                // CLEAR_PAYLOAD_ID_TABLE
                0x14 => {
                    for (_, port, pbn) in core::mem::take(&mut branch.allocated) {
                        if let Some(p) = branch.ports.iter_mut().find(|p| p.number == port) {
                            p.avail_pbn = p.avail_pbn.saturating_add(pbn);
                        }
                    }
                    Some(alloc::vec![0x14])
                }
                // REMOTE_I2C_READ
                0x22 => {
                    let port_no = body[1] >> 4;
                    let n_writes = (body[1] & 0x3) as usize;
                    let mut idx = 2;
                    let mut offset = 0usize;
                    for _ in 0..n_writes {
                        let _device = body[idx];
                        let n = body[idx + 1] as usize;
                        let bytes = &body[idx + 2..idx + 2 + n];
                        if !bytes.is_empty() {
                            offset = bytes[0] as usize;
                        }
                        idx += 2 + n + 1; // + stop/delay byte
                    }
                    let _read_device = body[idx];
                    let read_len = body[idx + 1] as usize;
                    let p = branch.ports.iter().find(|p| p.number == port_no)?;
                    let edid = p.edid?;
                    let mut out = alloc::vec![0x22, port_no & 0xF, read_len as u8];
                    for i in 0..read_len {
                        out.push(edid.get(offset + i).copied().unwrap_or(0));
                    }
                    Some(out)
                }
                _ => Some(nak_body(kind, &branch.guid, 0x01)),
            }
        }

        /// The hop (branch index, port) that leads to branch
        /// `target`, if it has a parent in this tree.
        fn parent_hop(&self, target: usize) -> Option<(usize, u8)> {
            self.branches.iter().enumerate().find_map(|(bi, b)| {
                b.ports
                    .iter()
                    .find(|p| p.child == Some(target))
                    .map(|p| (bi, p.number))
            })
        }

        /// ALLOCATE_PAYLOAD against branch `branch_idx`. A
        /// successful allocation also debits the parent hop's
        /// available PBN (and a deallocation credits it): a
        /// branch's ENUM_PATH_RESOURCES answer reflects the
        /// payloads in transit through it, which is the whole
        /// point of path resources — the hub models that
        /// honestly instead of letting the end branch's books
        /// diverge from the path's.
        fn dispatch_allocate(
            &mut self,
            branch_idx: usize,
            parent: Option<(usize, u8)>,
            body: &[u8],
        ) -> Option<Vec<u8>> {
            let port_no = body[1] >> 4;
            let vcpi = body[2] & 0x7F;
            let pbn = u16::from_be_bytes([body[3], body[4]]);
            let guid = self.branches[branch_idx].guid;
            if self.nak_allocate && pbn != 0 {
                return Some(nak_body(0x11, &guid, 0x01));
            }
            if pbn == 0 {
                let removed = {
                    let branch = &mut self.branches[branch_idx];
                    branch
                        .allocated
                        .iter()
                        .position(|(v, _, _)| *v == vcpi)
                        .map(|pos| branch.allocated.remove(pos))
                };
                if let Some((_, port, old)) = removed {
                    let branch = &mut self.branches[branch_idx];
                    if let Some(p) = branch.ports.iter_mut().find(|p| p.number == port) {
                        p.avail_pbn = p.avail_pbn.saturating_add(old);
                    }
                    if let Some((pbi, pport)) = parent {
                        if let Some(p) = self.branches[pbi]
                            .ports
                            .iter_mut()
                            .find(|p| p.number == pport)
                        {
                            p.avail_pbn = p.avail_pbn.saturating_add(old);
                        }
                    }
                }
                let mut out = alloc::vec![0x11, port_no << 4, vcpi];
                out.extend_from_slice(&0u16.to_be_bytes());
                return Some(out);
            }
            {
                let branch = &mut self.branches[branch_idx];
                let p = branch.ports.iter_mut().find(|p| p.number == port_no)?;
                if pbn > p.avail_pbn {
                    return Some(nak_body(0x11, &guid, 0x01));
                }
                p.avail_pbn -= pbn;
                branch.allocated.push((vcpi, port_no, pbn));
            }
            if let Some((pbi, pport)) = parent {
                if let Some(p) = self.branches[pbi]
                    .ports
                    .iter_mut()
                    .find(|p| p.number == pport)
                {
                    p.avail_pbn = p.avail_pbn.saturating_sub(pbn);
                }
            }
            let mut out = alloc::vec![0x11, port_no << 4, vcpi];
            out.extend_from_slice(&pbn.to_be_bytes());
            Some(out)
        }

        /// Queue a CONNECTION_STATUS_NOTIFY up request from
        /// `branch_idx` for `port` (the branch device detects a
        /// plug change and tells the source).
        fn queue_connection_status(&mut self, branch_idx: usize, port: u8, plugged: bool) {
            let branch = &self.branches[branch_idx];
            let peer = branch
                .ports
                .iter()
                .find(|p| p.number == port)
                .map(|p| p.peer)
                .unwrap_or(0);
            let mut body = alloc::vec![0x02, port << 4];
            body.extend_from_slice(&branch.guid);
            let mut flags = (peer & 0x7) | (1 << 4); // message capable
            if plugged {
                flags |= 1 << 5; // DP plug
            }
            body.push(flags);
            for msg in fixture_sb_messages(1, &[0; 8], &body) {
                self.up_req_queue.push_back(msg);
            }
        }

        /// Queue a RESOURCE_STATUS_NOTIFY for a root port.
        fn queue_resource_status(&mut self, port: u8, available_pbn: u16) {
            let mut body = alloc::vec![0x13, port << 4];
            body.extend_from_slice(&ROOT_GUID);
            body.extend_from_slice(&available_pbn.to_be_bytes());
            for msg in fixture_sb_messages(1, &[0; 8], &body) {
                self.up_req_queue.push_back(msg);
            }
        }

        /// One AUX transaction against the root device (the
        /// frame decode is DP 1.4a §2.7.4, as in Q4's fixture).
        fn transact(&mut self, wire: &[u8]) -> Vec<u8> {
            self.wire_log.push(wire.to_vec());
            let cmd = wire[0] >> 4;
            let addr = (((wire[0] & 0x0F) as u32) << 16) | ((wire[1] as u32) << 8) | wire[2] as u32;
            let len = wire[3] as usize + 1;
            match cmd {
                0x8 => {
                    self.dpcd_write(addr, &wire[4..4 + len]);
                    alloc::vec![0x00]
                }
                0x9 => {
                    let mut reply = alloc::vec![0x00];
                    reply.extend_from_slice(&self.dpcd_read(addr, len));
                    reply
                }
                _ => alloc::vec![0x10],
            }
        }
    }

    /// Whether the accumulated down-request body is complete
    /// for its kind (fixed-length kinds by table;
    /// REMOTE_I2C_READ by walking its write list).
    fn fixture_request_complete(body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        match body[0] & 0x7F {
            0x01 | 0x14 => true, // LINK_ADDRESS, CLEAR_PAYLOAD_ID_TABLE
            0x10 => body.len() >= 2,
            0x11 => {
                if body.len() < 5 {
                    return false;
                }
                let n_sinks = (body[1] & 0xF) as usize;
                body.len() >= 5 + n_sinks.div_ceil(2)
            }
            0x22 => {
                if body.len() < 2 {
                    return false;
                }
                let n_writes = (body[1] & 0x3) as usize;
                let mut idx = 2;
                for _ in 0..n_writes {
                    if body.len() < idx + 2 {
                        return false;
                    }
                    let n = body[idx + 1] as usize;
                    idx += 2 + n + 1;
                }
                body.len() >= idx + 2
            }
            _ => true,
        }
    }

    fn nak_body(kind: u8, guid: &[u8; 16], reason: u8) -> Vec<u8> {
        let mut out = alloc::vec![kind | 0x80];
        out.extend_from_slice(guid);
        out.push(reason);
        out.push(0);
        out
    }

    // ── The MMIO register model ─────────────────────────────

    const PWR_WELL_CTL2: u64 = 0x4_5404;
    const PLL_POWER_STATE: u32 = 1 << 26;
    const PLL_LOCK: u32 = 1 << 30;

    #[derive(Debug)]
    struct HubMmio {
        regs: RefCell<BTreeMap<u64, u32>>,
        pub writes: RefCell<Vec<(u64, u32)>>,
        hub: RefCell<Hub>,
        ddi: Ddi,
        aux_reply: RefCell<Vec<u8>>,
        aux_data: RefCell<[u8; 20]>,
        aux_ctl_state: RefCell<u32>,
    }

    impl HubMmio {
        fn new(hub: Hub) -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
                writes: RefCell::new(Vec::new()),
                hub: RefCell::new(hub),
                ddi: Ddi::B,
                aux_reply: RefCell::new(Vec::new()),
                aux_data: RefCell::new([0u8; 20]),
                aux_ctl_state: RefCell::new(0),
            }
        }

        fn stored(&self, off: u64) -> u32 {
            self.regs.borrow().get(&off).copied().unwrap_or(0)
        }

        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        pub fn any_write_in(&self, lo: u64, hi: u64) -> bool {
            self.writes
                .borrow()
                .iter()
                .any(|(o, _)| *o >= lo && *o < hi)
        }

        fn aux_ctl_off(&self) -> u64 {
            self.ddi.base() + DDI_AUX_CTL_OFFSET
        }

        fn is_aux_data(&self, off: u64) -> Option<usize> {
            let base = self.ddi.base() + DDI_AUX_DATA_OFFSET;
            if off >= base && off < base + 20 && (off - base) % 4 == 0 {
                Some(((off - base) / 4) as usize)
            } else {
                None
            }
        }
    }

    impl MmioWindow for HubMmio {
        fn read32(&self, off: u64) -> u32 {
            if off == self.aux_ctl_off() {
                return *self.aux_ctl_state.borrow();
            }
            if let Some(idx) = self.is_aux_data(off) {
                let reply = self.aux_reply.borrow();
                let mut v: u32 = 0;
                for b in 0..4 {
                    let byte = reply.get(idx * 4 + b).copied().unwrap_or(0);
                    v |= (byte as u32) << (24 - 8 * b);
                }
                return v;
            }
            let v = self.stored(off);
            if off == PWR_WELL_CTL2 {
                return v | ((v & 0xAAAA_AAAA) >> 1);
            }
            if (0x4_6010..=0x4_6018).contains(&off) && (off - 0x4_6010) % 4 == 0 {
                return v | PLL_POWER_STATE | PLL_LOCK;
            }
            for pipe in [Pipe::A, Pipe::B, Pipe::C] {
                if off == pipe.base() + PIPECONF_OFFSET {
                    use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
                    let state = if v & PIPECONF_ENABLE != 0 {
                        PIPECONF_STATE
                    } else {
                        0
                    };
                    return (v & !PIPECONF_STATE) | state;
                }
            }
            if off == self.ddi.base() + DDI_BUF_CTL_OFFSET {
                use crate::intel_gpu_ddi::{DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS};
                let idle = if v & DDI_BUF_CTL_ENABLE != 0 {
                    0
                } else {
                    DDI_BUF_CTL_IDLE_STATUS
                };
                return (v & !DDI_BUF_CTL_IDLE_STATUS) | idle;
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            self.regs.borrow_mut().insert(off, val);
            if let Some(idx) = self.is_aux_data(off) {
                let mut data = self.aux_data.borrow_mut();
                for b in 0..4 {
                    data[idx * 4 + b] = (val >> (24 - 8 * b)) as u8;
                }
            }
            if off == self.aux_ctl_off() {
                if val & AUX_CTL_SEND_BUSY != 0 {
                    let msgsize = ((val & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
                    let wire = self.aux_data.borrow()[..msgsize].to_vec();
                    let reply = self.hub.borrow_mut().transact(&wire);
                    let total = reply.len() as u32;
                    *self.aux_reply.borrow_mut() = reply;
                    *self.aux_ctl_state.borrow_mut() =
                        AUX_CTL_DONE | (total << AUX_CTL_MSGSIZE_SHIFT);
                } else {
                    *self.aux_ctl_state.borrow_mut() = 0;
                }
            }
        }
    }

    // ── Topology builders ───────────────────────────────────

    fn hub_port(
        number: u8,
        peer: u8,
        ddps: bool,
        edid: Option<[u8; 128]>,
        full_pbn: u16,
    ) -> HubPort {
        HubPort {
            number,
            input: false,
            peer,
            mcs: false,
            ddps,
            child: None,
            edid,
            full_pbn,
            avail_pbn: full_pbn,
        }
    }

    fn input_port(number: u8) -> HubPort {
        HubPort {
            number,
            input: true,
            peer: 1, // SOURCE_OR_SST_SINK peer type on an input is "source"
            mcs: false,
            ddps: false,
            child: None,
            edid: None,
            full_pbn: 0,
            avail_pbn: 0,
        }
    }

    /// Root branch: port 1 = 1080p SST sink, port 2 = child
    /// branch (1440p sink behind it), port 3 = empty. The
    /// path through root port 2 advertises 4000 PBN.
    fn two_level_hub() -> Hub {
        let mut root2 = hub_port(2, dp_mst::PEER_MST_BRANCHING, true, None, 4000);
        root2.mcs = true;
        root2.child = Some(1);
        Hub::new(vec![
            HubBranch {
                guid: ROOT_GUID,
                ports: vec![
                    input_port(0),
                    hub_port(1, dp_mst::PEER_SST_SINK, true, Some(edid_1080p()), 2520),
                    root2,
                    hub_port(3, dp_mst::PEER_SST_SINK, false, None, 0),
                ],
                allocated: Vec::new(),
            },
            HubBranch {
                guid: CHILD_GUID,
                ports: vec![
                    input_port(0),
                    hub_port(1, dp_mst::PEER_SST_SINK, true, Some(edid_1440p()), 4000),
                ],
                allocated: Vec::new(),
            },
        ])
    }

    /// Two sinks on the root branch; the second sink's path
    /// advertises only 100 PBN — far below any real stream —
    /// so a second stream must be refused locally.
    fn capacity_hub() -> Hub {
        Hub::new(vec![HubBranch {
            guid: ROOT_GUID,
            ports: vec![
                input_port(0),
                hub_port(1, dp_mst::PEER_SST_SINK, true, Some(edid_1080p()), 2520),
                hub_port(2, dp_mst::PEER_SST_SINK, true, Some(edid_1440p()), 100),
            ],
            allocated: Vec::new(),
        }])
    }

    // ── Session scaffolding ─────────────────────────────────

    struct Fixture {
        mmio: HubMmio,
        link: MstLink,
    }

    impl Fixture {
        fn new(hub: Hub) -> Self {
            Self {
                mmio: HubMmio::new(hub),
                link: MstLink::new(Ddi::B),
            }
        }

        /// Glue-shaped connect: caps over a plain IntelAux,
        /// then the manager start over the MST adapter.
        fn connect(&mut self) -> Result<(), MstError> {
            let mut plain = IntelAux::new(&self.mmio, Ddi::B);
            let caps = crate::dp_link_training::read_caps(&mut plain).map_err(|e| {
                MstError::Aux(match e {
                    crate::dp_link_training::LinkError::AuxFailure(a) => a,
                    _ => AuxError::UnknownStatus,
                })
            })?;
            let mut raw = [0u8; 16];
            plain.dpcd_read(0, &mut raw).map_err(MstError::Aux)?;
            let mut aux = test_aux(&self.mmio);
            self.link.connect(&mut aux, caps, &raw)
        }

        fn probe(&mut self) -> Result<(), MstError> {
            let mut aux = test_aux(&self.mmio);
            self.link.probe_topology(&mut aux)
        }

        fn connect_and_probe(&mut self) -> Result<(), MstError> {
            self.connect()?;
            self.probe()
        }

        fn mode_of(&mut self, sink: Sink) -> Result<Mode, MstError> {
            let mut aux = test_aux(&self.mmio);
            self.link.sink_mode(&mut aux, sink)
        }

        fn add(
            &mut self,
            sink: Sink,
            pipe: Pipe,
            fb_phys: u64,
            stride: u32,
        ) -> Result<MstStream, MstError> {
            let mode = self.mode_of(sink)?;
            let fb = Framebuffer {
                phys_addr: fb_phys,
                stride_bytes: stride,
                format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
            };
            let mut aux = test_aux(&self.mmio);
            self.link
                .add_stream(&self.mmio, &mut aux, sink, mode, pipe, &fb, None)
        }

        fn hub<R>(&self, f: impl FnOnce(&Hub) -> R) -> R {
            f(&self.mmio.hub.borrow())
        }
    }

    fn fb_1080p(phys: u64) -> (u64, u32) {
        (phys, 7680)
    }

    // ── Smokes ──────────────────────────────────────────────

    fn smoke_mst_rejects_non_mst_sink() -> TestResult {
        let mut hub = two_level_hub();
        hub.mst_capable = false;
        let mut fx = Fixture::new(hub);
        match fx.connect() {
            Err(MstError::Mgr(MgrError::NotMst)) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("MST-incapable sink must surface NotMst")
            }
        }
    }
    kernel_test_in!("drivers/gpu/intel_gpu_mst", smoke_mst_rejects_non_mst_sink);

    fn smoke_mst_probe_topology_and_ledger() -> TestResult {
        let mut fx = Fixture::new(two_level_hub());
        if fx.connect_and_probe().is_err() {
            return TestResult::Fail("connect+probe against the hub");
        }
        // MSTM_CTRL was written with MST_EN | UP_REQ_EN |
        // UPSTREAM_IS_SRC (0x07) at DPCD 0x111.
        if fx.hub(|h| h.mstm_ctrl) != 0x07 {
            return TestResult::Fail("MSTM_CTRL must be 0x07 after connect");
        }
        let topo = match fx.link.topology() {
            Some(t) => t,
            None => return TestResult::Fail("topology stored"),
        };
        if topo.branches.len() != 2 {
            return TestResult::Fail("two branches expected");
        }
        let sinks = topo.sinks();
        if sinks != alloc::vec![Sink { branch: 0, port: 1 }, Sink { branch: 1, port: 1 },] {
            return TestResult::Fail("sinks: root port 1 + child port 1 only");
        }
        // Ledger seeded from ENUM_PATH_RESOURCES.
        if fx.link.available_pbn(Sink { branch: 0, port: 1 }) != Some(2520)
            || fx.link.available_pbn(Sink { branch: 0, port: 2 }) != Some(4000)
            || fx.link.available_pbn(Sink { branch: 1, port: 1 }) != Some(4000)
        {
            return TestResult::Fail("ledger must mirror the hub's ENUM replies");
        }
        // Wire order: payload-table clear first, then the
        // LINK_ADDRESS walk (root, then child at LCT 2).
        let log = fx.hub(|h| h.request_log.clone());
        if log.first() != Some(&(dp_mst::CLEAR_PAYLOAD_ID_TABLE, 1)) {
            return TestResult::Fail("first request must be CLEAR_PAYLOAD_ID_TABLE");
        }
        if !log.contains(&(dp_mst::LINK_ADDRESS, 1)) || !log.contains(&(dp_mst::LINK_ADDRESS, 2)) {
            return TestResult::Fail("LINK_ADDRESS must walk root then child");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_probe_topology_and_ledger
    );

    fn smoke_mst_two_streams_one_trained_link() -> TestResult {
        use crate::intel_gpu_pipes::{TRANS_DDI_FUNC_CTL_OFFSET, TRANS_DDI_MODE_DP_MST};
        let mut fx = Fixture::new(two_level_hub());
        if fx.connect_and_probe().is_err() {
            return TestResult::Fail("connect+probe");
        }
        let sink1 = Sink { branch: 0, port: 1 };
        let sink2 = Sink { branch: 1, port: 1 };
        let (phys, stride) = fb_1080p(0x300_0000);
        let s1 = match fx.add(sink1, Pipe::B, phys, stride) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("stream 1 add"),
        };
        let pattern_writes_after_s1 = fx.hub(|h| h.training_pattern_writes);
        let s2 = match fx.add(sink2, Pipe::C, 0x500_0000, 10240) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("stream 2 add"),
        };
        // The link trained exactly once: stream 2's modeset
        // never touched the training pattern register.
        if fx.hub(|h| h.training_pattern_writes) != pattern_writes_after_s1 {
            return TestResult::Fail("second stream must not retrain the link");
        }
        if fx.link.trained().is_none() || fx.link.streams().len() != 2 {
            return TestResult::Fail("two streams, one trained link");
        }
        // Source payload table on the hub: both VCPIs present,
        // slot runs inside 1..=63 and disjoint.
        let table = fx.hub(|h| h.source_table.clone());
        let e1 = table.get(&s1.vcpi).copied();
        let e2 = table.get(&s2.vcpi).copied();
        match (e1, e2) {
            (Some((st1, c1)), Some((st2, c2))) => {
                if (st1, c1) != (s1.start_slot, s1.slots) || (st2, c2) != (s2.start_slot, s2.slots)
                {
                    return TestResult::Fail("payload table must mirror the streams");
                }
                if st1 < 1 || st1 + c1 - 1 > 63 || st2 < 1 || st2 + c2 - 1 > 63 {
                    return TestResult::Fail("slot runs must live in 1..=63");
                }
                if st1 < st2 + c2 && st2 < st1 + c1 {
                    return TestResult::Fail("slot runs must not overlap");
                }
            }
            _ => return TestResult::Fail("both VCPIs must be in the source table"),
        }
        // Both branches' ledgers debited along each path, and
        // the session ledger agrees with the hub's own books.
        if fx.hub(|h| h.branches[0].ports[1].avail_pbn) != 2520 - s1.pbn as u16 {
            return TestResult::Fail("root port 1 must be debited by stream 1's PBN");
        }
        if fx.hub(|h| h.branches[0].ports[2].avail_pbn) != 4000 - s2.pbn as u16
            || fx.hub(|h| h.branches[1].ports[1].avail_pbn) != 4000 - s2.pbn as u16
        {
            return TestResult::Fail("stream 2's path hops must both be debited");
        }
        if fx.link.available_pbn(Sink { branch: 0, port: 2 }) != Some(4000 - s2.pbn as u16) {
            return TestResult::Fail("session ledger must agree with the hub");
        }
        // Both transcoders bound in DP-MST mode.
        for trans in [Transcoder::B, Transcoder::C] {
            let writes = fx.mmio.writes_to(trans.base() + TRANS_DDI_FUNC_CTL_OFFSET);
            let last = writes.last().copied().unwrap_or(0);
            if (last >> 24) & 0x7 != (TRANS_DDI_MODE_DP_MST >> 24) & 0x7 {
                return TestResult::Fail("TRANS_DDI_FUNC_CTL must carry DP-MST mode");
            }
        }
        // Pipe A was never touched.
        if fx.mmio.any_write_in(Pipe::A.base(), Pipe::B.base()) {
            return TestResult::Fail("streams on B/C must not write Pipe A's block");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_two_streams_one_trained_link
    );

    fn smoke_mst_over_capacity_stream_refused_cleanly() -> TestResult {
        let mut fx = Fixture::new(capacity_hub());
        if fx.connect_and_probe().is_err() {
            return TestResult::Fail("connect+probe");
        }
        let sink1 = Sink { branch: 0, port: 1 };
        let sink2 = Sink { branch: 0, port: 2 };
        let (phys, stride) = fb_1080p(0x300_0000);
        if fx.add(sink1, Pipe::B, phys, stride).is_err() {
            return TestResult::Fail("stream 1 add");
        }
        // Snapshot everything the refused add must not touch.
        let requests_before = fx.hub(|h| h.request_log.len());
        let table_before = fx.hub(|h| h.source_table.clone());
        let writes_before = fx.mmio.writes.borrow().len();
        let avail_before = fx.hub(|h| h.branches[0].ports[1].avail_pbn);
        match fx.add(sink2, Pipe::C, 0x500_0000, 10240) {
            Err(MstError::InsufficientBandwidth {
                needed_pbn,
                available_pbn,
            }) => {
                if available_pbn != 100 || needed_pbn <= 100 {
                    return TestResult::Fail("refusal must carry (needed > 100, available 100)");
                }
            }
            other => {
                let _ = other;
                return TestResult::Fail("over-capacity stream must be refused");
            }
        }
        // The refusal was local: no sideband request, no
        // payload-table change, no register write at all — the
        // live stream is provably untouched, and Pipe C never
        // saw a modeset.
        if fx.hub(|h| h.request_log.len()) != requests_before {
            return TestResult::Fail("refused add must not send sideband requests");
        }
        if fx.hub(|h| h.source_table.clone()) != table_before {
            return TestResult::Fail("refused add must not touch the payload table");
        }
        if fx.mmio.writes.borrow().len() != writes_before {
            return TestResult::Fail("refused add must not write any register");
        }
        if fx.hub(|h| h.branches[0].ports[1].avail_pbn) != avail_before {
            return TestResult::Fail("refused add must not debit the live stream's ledger");
        }
        if fx.link.streams().len() != 1 {
            return TestResult::Fail("only stream 1 may be live");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_over_capacity_stream_refused_cleanly
    );

    fn smoke_mst_branch_nak_rolls_back() -> TestResult {
        let mut hub = two_level_hub();
        hub.nak_allocate = true;
        let mut fx = Fixture::new(hub);
        if fx.connect_and_probe().is_err() {
            return TestResult::Fail("connect+probe");
        }
        let sink1 = Sink { branch: 0, port: 1 };
        let (phys, stride) = fb_1080p(0x300_0000);
        match fx.add(sink1, Pipe::B, phys, stride) {
            Err(MstError::Mgr(MgrError::Nak(0x01))) => {}
            other => {
                let _ = other;
                return TestResult::Fail("branch NAK must surface typed");
            }
        }
        // Rollback: the source table entry was written then
        // cleared (payload log shows set-then-zero for the
        // same VCPI), the branch holds no allocation, no
        // stream is recorded, the link is untrained again, and
        // the stream's pipe + the DDI buffer were torn down.
        let log = fx.hub(|h| h.payload_log.clone());
        let sets: Vec<&(u8, u8, u8)> = log.iter().filter(|e| e.2 != 0 && e.0 != 0).collect();
        let clears: Vec<&(u8, u8, u8)> = log.iter().filter(|e| e.2 == 0 && e.0 != 0).collect();
        if sets.len() != 1 || clears.len() != 1 || sets[0].0 != clears[0].0 {
            return TestResult::Fail("rollback must clear the payload entry it set");
        }
        if !fx.hub(|h| h.source_table.is_empty()) {
            return TestResult::Fail("source table must be empty after rollback");
        }
        if !fx.hub(|h| h.branches[0].allocated.is_empty()) {
            return TestResult::Fail("branch must hold no allocation after NAK");
        }
        if !fx.link.streams().is_empty() || fx.link.trained().is_some() {
            return TestResult::Fail("no stream, no trained link after rollback");
        }
        let pipeconf = fx.mmio.stored(Pipe::B.base() + PIPECONF_OFFSET);
        if pipeconf & crate::intel_gpu_pipes::PIPECONF_ENABLE != 0 {
            return TestResult::Fail("rolled-back pipe must be disabled");
        }
        let buf = fx.mmio.stored(Ddi::B.base() + DDI_BUF_CTL_OFFSET);
        if buf & crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE != 0 {
            return TestResult::Fail("sole-stream rollback must drop the DDI buffer");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_mst", smoke_mst_branch_nak_rolls_back);

    fn smoke_mst_sideband_timeout_is_typed() -> TestResult {
        let mut hub = two_level_hub();
        hub.deaf = true;
        let mut fx = Fixture::new(hub);
        if fx.connect().is_err() {
            return TestResult::Fail("connect (payload reset is DPCD, not sideband)");
        }
        match fx.probe() {
            Err(MstError::Mgr(MgrError::Timeout)) => {}
            other => {
                let _ = other;
                return TestResult::Fail("deaf hub must produce a typed Timeout");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_sideband_timeout_is_typed
    );

    fn smoke_mst_corrupt_reply_is_malformed() -> TestResult {
        let mut hub = two_level_hub();
        hub.corrupt_replies = true;
        let mut fx = Fixture::new(hub);
        if fx.connect().is_err() {
            return TestResult::Fail("connect");
        }
        match fx.probe() {
            Err(MstError::Mgr(MgrError::Malformed)) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("header-corrupt reply must be Malformed, never a panic")
            }
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_corrupt_reply_is_malformed
    );

    fn smoke_mst_notifications_surface_and_update_ledger() -> TestResult {
        let mut fx = Fixture::new(two_level_hub());
        if fx.connect_and_probe().is_err() {
            return TestResult::Fail("connect+probe");
        }
        fx.mmio
            .hub
            .borrow_mut()
            .queue_connection_status(1, 1, false);
        fx.mmio.hub.borrow_mut().queue_resource_status(2, 3000);
        let mut aux = test_aux(&fx.mmio);
        let events = match fx.link.poll_notifications(&mut aux) {
            Ok(e) => e,
            Err(_) => return TestResult::Fail("poll_notifications"),
        };
        if events.len() != 2 {
            return TestResult::Fail("both notifications must surface");
        }
        match events[0] {
            MstEvent::ConnectionStatus {
                guid,
                port,
                connected,
                peer_device_type,
            } => {
                if guid != CHILD_GUID || port != 1 || connected || peer_device_type != 3 {
                    return TestResult::Fail("connection-status event shape");
                }
            }
            _ => return TestResult::Fail("first event must be ConnectionStatus"),
        }
        match events[1] {
            MstEvent::ResourceStatus {
                guid,
                port,
                available_pbn,
            } => {
                if guid != ROOT_GUID || port != 2 || available_pbn != 3000 {
                    return TestResult::Fail("resource-status event shape");
                }
            }
            _ => return TestResult::Fail("second event must be ResourceStatus"),
        }
        // The ledger followed the resource-status notification.
        if fx.link.available_pbn(Sink { branch: 0, port: 2 }) != Some(3000) {
            return TestResult::Fail("ledger must take the notified available PBN");
        }
        // The manager's sideband ACKs reached the hub.
        let bodies = fx.hub(|h| h.up_rep_bodies.clone());
        if bodies.len() != 2
            || bodies[0].first().copied() != Some(dp_mst::CONNECTION_STATUS_NOTIFY)
            || bodies[1].first().copied() != Some(dp_mst::RESOURCE_STATUS_NOTIFY)
        {
            return TestResult::Fail("each notification must be ACKed at UP_REP");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_notifications_surface_and_update_ledger
    );

    fn smoke_mst_remove_stream_compacts_and_restores() -> TestResult {
        let mut fx = Fixture::new(two_level_hub());
        if fx.connect_and_probe().is_err() {
            return TestResult::Fail("connect+probe");
        }
        let sink1 = Sink { branch: 0, port: 1 };
        let sink2 = Sink { branch: 1, port: 1 };
        let (phys, stride) = fb_1080p(0x300_0000);
        let s1 = match fx.add(sink1, Pipe::B, phys, stride) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("stream 1 add"),
        };
        let s2 = match fx.add(sink2, Pipe::C, 0x500_0000, 10240) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("stream 2 add"),
        };
        if s2.start_slot <= s1.start_slot {
            return TestResult::Fail("fixture expects stream 2 above stream 1 in the table");
        }
        // Remove stream 1: stream 2 compacts down to slot 1 in
        // both the session record and the hub's source table,
        // stream 1's hops are credited back, the link stays
        // trained for the survivor.
        let mut aux = test_aux(&fx.mmio);
        match fx.link.remove_stream(&fx.mmio, &mut aux, sink1) {
            Ok(removed) => {
                if removed.vcpi != s1.vcpi {
                    return TestResult::Fail("removed stream must be stream 1");
                }
            }
            Err(_) => return TestResult::Fail("remove stream 1"),
        }
        let streams = fx.link.streams();
        if streams.len() != 1 || streams[0].start_slot != 1 {
            return TestResult::Fail("survivor must compact to slot 1");
        }
        let table = fx.hub(|h| h.source_table.clone());
        if table.get(&s2.vcpi).copied() != Some((1, s2.slots)) {
            return TestResult::Fail("hub table must show the compacted entry");
        }
        if table.contains_key(&s1.vcpi) {
            return TestResult::Fail("removed VCPI must leave the table");
        }
        if fx.hub(|h| h.branches[0].ports[1].avail_pbn) != 2520 {
            return TestResult::Fail("stream 1's hop must be credited back in full");
        }
        if fx.link.trained().is_none() {
            return TestResult::Fail("link must stay trained for the survivor");
        }
        // Removing the last stream untrains and drops the
        // DDI buffer.
        let mut aux = test_aux(&fx.mmio);
        if fx.link.remove_stream(&fx.mmio, &mut aux, sink2).is_err() {
            return TestResult::Fail("remove stream 2");
        }
        if fx.link.trained().is_some() || !fx.link.streams().is_empty() {
            return TestResult::Fail("link must be fully down after last removal");
        }
        let buf = fx.mmio.stored(Ddi::B.base() + DDI_BUF_CTL_OFFSET);
        if buf & crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE != 0 {
            return TestResult::Fail("DDI buffer must be off after last removal");
        }
        if !fx.hub(|h| h.source_table.is_empty()) {
            return TestResult::Fail("source table must be empty at the end");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_remove_stream_compacts_and_restores
    );

    fn smoke_mst_aux_transactions_chunk_at_16() -> TestResult {
        // The adapter must never hand the AUX channel a
        // transaction longer than the 16-byte native limit:
        // read 40 bytes at the sideband reply base and check
        // every NATIVE_READ frame on the hub's wire log.
        use crate::dp_mst_mgr::MstAux as _;
        let fx = Fixture::new(two_level_hub());
        let mut aux = test_aux(&fx.mmio);
        let mut buf = [0u8; 40];
        if narf_scheduler::block_on_spin(aux.read(0x1400, &mut buf)).is_err() {
            return TestResult::Fail("chunked read must succeed");
        }
        let hub = fx.mmio.hub.borrow();
        let mut reads = 0usize;
        for wire in &hub.wire_log {
            if wire.len() < 4 {
                continue;
            }
            // NATIVE_READ frames only (command nibble 0x9);
            // wire[3] is LEN-1, so <= 15 means <= 16 bytes.
            if wire[0] >> 4 == 0x9 {
                reads += 1;
                if wire[3] > 15 {
                    return TestResult::Fail("AUX read frame exceeded 16 bytes");
                }
            }
        }
        if reads < 3 {
            return TestResult::Fail("40-byte read must split into >= 3 AUX frames");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_mst",
        smoke_mst_aux_transactions_chunk_at_16
    );
}
