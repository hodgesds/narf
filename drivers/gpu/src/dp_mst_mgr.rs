//! A DisplayPort MST topology manager after Linux's
//! drm_dp_mst_topology.c, driven by polling instead of HPD IRQs:
//!
//! - `start` is drm_dp_mst_topology_mgr_set_mst(true): MST, up requests
//!   and "upstream is source" on, the payload table reset;
//! - `transact` sends one down request (process_single_tx_qlock's
//!   sideband messages at DOWN_REQ_BASE in 16-byte AUX writes) and waits
//!   up to Linux's 4 s for its reply, reading each sideband message as
//!   drm_dp_get_one_sb_msg does once ESI's DOWN_REP_MSG_RDY rises and
//!   acknowledging it; up requests arriving meanwhile are read, answered
//!   with drm_dp_send_up_ack_reply's ACK and queued;
//! - `poll_up_requests` services those notifications without a down
//!   transaction, with bounded work and reassembly retained between calls;
//! - `probe` is drm_dp_mst_link_probe_work: CLEAR_PAYLOAD_ID_TABLE once,
//!   then LINK_ADDRESS down the tree with ENUM_PATH_RESOURCES for every
//!   connected output port (drm_dp_mst_handle_link_address_port);
//! - `read_edid` is drm_do_probe_ddc_edid through drm_dp_mst_i2c_read.
use crate::dp_mst::{self, Reply, Request, Rx, UpRequest};
use alloc::vec::Vec;
use core::future::Future;

/// DP_MSTM_CAP, DP_MSTM_CTRL and their bits.
pub const MSTM_CAP: u32 = 0x21;
const MSTM_CTRL: u32 = 0x111;
const MST_EN: u8 = 1;
const UP_REQ_EN: u8 = 2;
const UPSTREAM_IS_SRC: u8 = 4;
/// DP_DEVICE_SERVICE_IRQ_VECTOR_ESI0 and its sideband bits.
const ESI0: u32 = 0x2003;
const DOWN_REP_MSG_RDY: u8 = 0x10;
const UP_REQ_MSG_RDY: u8 = 0x20;
/// DP_PAYLOAD_ALLOCATE_SET and DP_PAYLOAD_TABLE_UPDATE_STATUS.
pub const PAYLOAD_ALLOCATE_SET: u32 = 0x1c0;
pub const PAYLOAD_TABLE_UPDATE_STATUS: u32 = 0x2c0;
const PAYLOAD_TABLE_UPDATED: u8 = 1;
/// drm_dp_mst_wait_tx_reply's 4 s, polled every millisecond.
const REPLY_TIMEOUT_MS: u32 = 4000;
/// Bound one idle service pass and the retained notification queue.
const UP_CHUNKS_PER_POLL: usize = 8;
const MAX_UP_EVENTS: usize = 64;

/// The DPCD side of an MST link.
pub trait MstAux {
    type Error;
    fn read(
        &mut self,
        address: u32,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn write(&mut self, address: u32, data: &[u8])
        -> impl Future<Output = Result<(), Self::Error>>;
    fn delay(&mut self, us: u64) -> impl Future<Output = ()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MstError<E> {
    Aux(E),
    /// The sink is not MST capable (DPCD below 1.2 or no MSTM_CAP).
    NotMst,
    Timeout,
    /// The branch refused: DP_NAK_* reason.
    Nak(u8),
    /// A reply that does not parse or answers another request.
    Malformed,
    /// The payload table did not report its update.
    PayloadTable,
    /// Drain `Manager::events` before servicing more up requests. The next
    /// chunk stays unacknowledged at the branch, so no event is discarded.
    EventsFull,
}

/// A port of a branch, as its LINK_ADDRESS reply and ENUM_PATH_RESOURCES
/// describe it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    pub info: dp_mst::LinkPort,
    pub full_pbn: u16,
    pub available_pbn: u16,
    pub fec: bool,
    /// The branch behind an MST-capable branching port (an index into
    /// `Topology::branches`).
    pub branch: Option<usize>,
}

/// A branch device at (`lct`, `rad`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    pub lct: u8,
    pub rad: [u8; 8],
    pub guid: [u8; 16],
    pub ports: Vec<Port>,
}

/// An end device: a port on a branch with an SST sink or legacy converter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sink {
    pub branch: usize,
    pub port: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Topology {
    pub branches: Vec<Branch>,
}
impl Topology {
    /// Connected end devices (drm_dp_mst_is_end_device), branch by branch.
    pub fn sinks(&self) -> Vec<Sink> {
        let mut out = Vec::new();
        for (b, branch) in self.branches.iter().enumerate() {
            for p in &branch.ports {
                let i = &p.info;
                let end = match i.peer_device_type {
                    dp_mst::PEER_DP_LEGACY_CONV | dp_mst::PEER_SST_SINK => true,
                    dp_mst::PEER_MST_BRANCHING => !i.mcs,
                    _ => false,
                };
                if !i.input && i.ddps && end {
                    out.push(Sink {
                        branch: b,
                        port: i.port,
                    });
                }
            }
        }
        out
    }
    pub fn port(&self, sink: Sink) -> Option<&Port> {
        self.branches
            .get(sink.branch)?
            .ports
            .iter()
            .find(|p| p.info.port == sink.port)
    }
    /// Every connected output hop, from the end port back to the root.
    /// Reject missing, cyclic or ambiguous parentage instead of omitting a
    /// bandwidth constraint. Probe-created trees have at most 64 branches.
    pub(crate) fn path(&self, mut sink: Sink) -> Option<Vec<Sink>> {
        let mut out = Vec::new();
        for _ in 0..self.branches.len().min(64) {
            let port = self.port(sink)?;
            if port.info.input || !port.info.ddps || out.contains(&sink) {
                return None;
            }
            out.push(sink);
            if sink.branch == 0 {
                return Some(out);
            }
            let child = sink.branch;
            let mut parents = self.branches.iter().enumerate().flat_map(|(branch, b)| {
                b.ports.iter().filter_map(move |p| {
                    (p.branch == Some(child)).then_some(Sink {
                        branch,
                        port: p.info.port,
                    })
                })
            });
            sink = parents.next()?;
            if parents.next().is_some() {
                return None;
            }
        }
        None
    }
}

/// drm_dp_calculate_rad: the relative address of the branch behind
/// `port` of the branch at (`lct`, `rad`).
pub fn child_rad(lct: u8, rad: &[u8; 8], port: u8) -> (u8, [u8; 8]) {
    let mut out = [0u8; 8];
    let idx = usize::from(lct.saturating_sub(1) / 2);
    let shift = if lct > 1 {
        out[..=idx].copy_from_slice(&rad[..=idx]);
        if lct % 2 == 1 {
            4
        } else {
            0
        }
    } else {
        4
    };
    out[idx] |= port << shift;
    (lct + 1, out)
}

/// A branch being probed: its ports in reply order, the next one, and a
/// port waiting for the branch behind it.
struct Frame {
    index: usize,
    lct: u8,
    rad: [u8; 8],
    ports: Vec<dp_mst::LinkPort>,
    next: usize,
    pending: Option<Port>,
}

#[derive(Debug)]
pub struct Manager {
    /// Up requests received by transactions or idle polling. Consumers drain
    /// these before retrying `EventsFull`.
    pub events: Vec<UpRequest>,
    // An up request can span a transaction's reply or an idle poll budget.
    up: Option<Rx>,
    cleared: bool,
}
impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}
impl Manager {
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            up: None,
            cleared: false,
        }
    }
    /// drm_dp_mst_topology_mgr_set_mst(true) on a sink whose DPCD
    /// receiver caps are `dpcd`.
    pub async fn start<A: MstAux>(
        &mut self,
        aux: &mut A,
        dpcd: &[u8; 16],
    ) -> Result<(), MstError<A::Error>> {
        if dpcd[0] < 0x12 {
            return Err(MstError::NotMst);
        }
        let mut cap = [0];
        aux.read(MSTM_CAP, &mut cap).await.map_err(MstError::Aux)?;
        if cap[0] & 1 == 0 {
            return Err(MstError::NotMst);
        }
        aux.write(MSTM_CTRL, &[MST_EN | UP_REQ_EN | UPSTREAM_IS_SRC])
            .await
            .map_err(MstError::Aux)?;
        self.cleared = false;
        self.events.clear();
        self.up = None;
        write_payload(aux, 0, 0, 0x3f).await
    }
    /// drm_dp_mst_topology_mgr_set_mst(false): MST off (the sink may be
    /// gone, so unchecked).
    pub async fn stop<A: MstAux>(&mut self, aux: &mut A) {
        let _ = aux.write(MSTM_CTRL, &[0]).await;
        self.cleared = false;
        self.events.clear();
        self.up = None;
    }
    /// One sideband message from `base` (drm_dp_get_one_sb_msg).
    async fn read_one<A: MstAux>(
        aux: &mut A,
        base: u32,
        rx: &mut Rx,
    ) -> Result<(), MstError<A::Error>> {
        let mut block = [0u8; 16];
        aux.read(base, &mut block).await.map_err(MstError::Aux)?;
        let (hdr, hdrlen) = dp_mst::Header::decode(&block).ok_or(MstError::Malformed)?;
        let total = hdrlen + usize::from(hdr.msg_len);
        let mut raw = Vec::with_capacity(total.max(16));
        raw.extend_from_slice(&block);
        let mut at = 16;
        while at < total {
            let n = (total - at).min(16);
            let mut piece = [0u8; 16];
            aux.read(base + at as u32, &mut piece[..n])
                .await
                .map_err(MstError::Aux)?;
            raw.extend_from_slice(&piece[..n]);
            at += n;
        }
        raw.truncate(total);
        if !rx.add(&raw) {
            return Err(MstError::Malformed);
        }
        Ok(())
    }
    /// Write sideband messages at `base`, 16 bytes per AUX write
    /// (drm_dp_send_sideband_msg).
    async fn send<A: MstAux>(
        aux: &mut A,
        base: u32,
        msgs: &[Vec<u8>],
    ) -> Result<(), MstError<A::Error>> {
        for msg in msgs {
            for (i, piece) in msg.chunks(16).enumerate() {
                aux.write(base + 16 * i as u32, piece)
                    .await
                    .map_err(MstError::Aux)?;
            }
        }
        Ok(())
    }
    /// An up request: read, acknowledged in ESI, answered, queued.
    async fn up_request<A: MstAux>(&mut self, aux: &mut A) -> Result<(), MstError<A::Error>> {
        if self.events.len() >= MAX_UP_EVENTS {
            return Err(MstError::EventsFull);
        }
        let rx = self.up.get_or_insert_with(Rx::default);
        Self::read_one(aux, dp_mst::UP_REQ_BASE, rx).await?;
        aux.write(ESI0, &[UP_REQ_MSG_RDY])
            .await
            .map_err(MstError::Aux)?;
        if !rx.complete() {
            return Ok(());
        }
        let rx = self.up.take().ok_or(MstError::Malformed)?;
        let kind = rx.msg[0] & 0x7f;
        // The raw codec deliberately mirrors Linux's permissive parser for
        // reference parity. The live manager must not synthesize fields
        // from the zero-filled tail of a truncated notification.
        let required = match kind {
            dp_mst::CONNECTION_STATUS_NOTIFY => 19,
            dp_mst::RESOURCE_STATUS_NOTIFY => 20,
            _ => return Err(MstError::Malformed),
        };
        if usize::from(rx.len) < required {
            return Err(MstError::Malformed);
        }
        let parsed = UpRequest::parse(&rx).ok_or(MstError::Malformed)?;
        // ESI was acknowledged: retain the notification even if sending
        // its sideband ACK fails. The caller can drain it after the error.
        self.events.push(parsed);
        // drm_dp_send_up_ack_reply(mgr, mst_primary, ...): the ACK goes to the
        // primary branch whichever downstream branch sent the notification
        // (a broadcast at LCT 1 for both notification kinds).
        let ack = dp_mst::chunks(1, &[0; 8], false, &UpRequest::ack(kind));
        Self::send(aux, dp_mst::UP_REP_BASE, &ack).await?;
        Ok(())
    }
    /// Service idle HPD-RX notifications, as drm_dp_mst_hpd_irq_handle_event
    /// services UP_REQ_MSG_RDY. Consume at most eight chunks, never wait for
    /// a notification, and acknowledge only the up-request ESI bit. Complete
    /// messages enter `events`; partial messages survive the next call or
    /// transaction. Returns the number of chunks consumed.
    pub async fn poll_up_requests<A: MstAux>(
        &mut self,
        aux: &mut A,
    ) -> Result<usize, MstError<A::Error>> {
        let mut consumed = 0;
        for _ in 0..UP_CHUNKS_PER_POLL {
            let mut esi = [0];
            aux.read(ESI0, &mut esi).await.map_err(MstError::Aux)?;
            if esi[0] & UP_REQ_MSG_RDY == 0 {
                break;
            }
            self.up_request(aux).await?;
            consumed += 1;
        }
        Ok(consumed)
    }
    /// Send `request` to the branch at (`lct`, `rad`) and wait for its
    /// reply.
    pub async fn transact<A: MstAux>(
        &mut self,
        aux: &mut A,
        lct: u8,
        rad: &[u8; 8],
        request: &Request,
    ) -> Result<Reply, MstError<A::Error>> {
        let body = request.encode();
        Self::send(
            aux,
            dp_mst::DOWN_REQ_BASE,
            &dp_mst::chunks(lct, rad, false, &body),
        )
        .await?;
        let mut rx = Rx::default();
        for _ in 0..REPLY_TIMEOUT_MS {
            let mut esi = [0];
            aux.read(ESI0, &mut esi).await.map_err(MstError::Aux)?;
            // Backpressure on up requests must not abandon an outstanding
            // down transaction (and leave its reply to poison the next one).
            if esi[0] & UP_REQ_MSG_RDY != 0 && self.events.len() < MAX_UP_EVENTS {
                self.up_request(aux).await?;
            }
            if esi[0] & DOWN_REP_MSG_RDY != 0 {
                Self::read_one(aux, dp_mst::DOWN_REP_BASE, &mut rx).await?;
                aux.write(ESI0, &[DOWN_REP_MSG_RDY])
                    .await
                    .map_err(MstError::Aux)?;
                if rx.complete() {
                    // verify_rx_request_type, then the reply itself.
                    if rx.msg[0] & 0x7f != request.kind() {
                        return Err(MstError::Malformed);
                    }
                    return match Reply::parse(&rx) {
                        Some(Reply::Nak { reason, .. }) => Err(MstError::Nak(reason)),
                        Some(reply) => Ok(reply),
                        None => Err(MstError::Malformed),
                    };
                }
                continue;
            }
            aux.delay(1000).await;
        }
        Err(MstError::Timeout)
    }
    /// drm_dp_mst_link_probe_work from the primary branch (LCT 1).
    pub async fn probe<A: MstAux>(&mut self, aux: &mut A) -> Result<Topology, MstError<A::Error>> {
        if !self.cleared {
            self.cleared = true;
            self.transact(aux, 1, &[0; 8], &Request::ClearPayloadIdTable)
                .await?;
        }
        // drm_dp_send_link_address and, per port in reply order,
        // drm_dp_mst_handle_link_address_port: ENUM_PATH_RESOURCES for a
        // connected output port, then at once the LINK_ADDRESS of a new
        // branch behind it (depth first, as Linux sends them).
        let mut topology = Topology::default();
        let mut stack = alloc::vec![self.link_address(aux, 1, [0; 8], &mut topology).await?];
        while let Some(top) = stack.last_mut() {
            if top.next == top.ports.len() {
                let done = stack.pop().ok_or(MstError::Malformed)?;
                if let Some(parent) = stack.last_mut() {
                    let mut port = parent.pending.take().ok_or(MstError::Malformed)?;
                    port.branch = Some(done.index);
                    topology.branches[parent.index].ports.push(port);
                }
                continue;
            }
            let info = top.ports[top.next];
            top.next += 1;
            let (index, lct, rad) = (top.index, top.lct, top.rad);
            let mut port = Port {
                info,
                full_pbn: 0,
                available_pbn: 0,
                fec: false,
                branch: None,
            };
            if info.ddps && !info.input {
                (port.fec, port.full_pbn, port.available_pbn) =
                    self.path_resources(aux, lct, &rad, info.port).await?;
                if info.peer_device_type == dp_mst::PEER_MST_BRANCHING && info.mcs {
                    // LCT is a four-bit wire field. Refuse a deeper tree before
                    // child_rad or the encoded route can overflow.
                    if lct >= 15 {
                        return Err(MstError::Malformed);
                    }
                    let (clct, crad) = child_rad(lct, &rad, info.port);
                    let child = self.link_address(aux, clct, crad, &mut topology).await?;
                    if let Some(top) = stack.last_mut() {
                        top.pending = Some(port);
                    }
                    stack.push(child);
                    continue;
                }
            }
            topology.branches[index].ports.push(port);
        }
        Ok(topology)
    }
    /// An authoritative resource snapshot, bound to the requested port.
    pub(crate) async fn path_resources<A: MstAux>(
        &mut self,
        aux: &mut A,
        lct: u8,
        rad: &[u8; 8],
        port: u8,
    ) -> Result<(bool, u16, u16), MstError<A::Error>> {
        match self
            .transact(aux, lct, rad, &Request::EnumPathResources { port })
            .await?
        {
            Reply::EnumPathResources {
                port: reply_port,
                fec,
                full_pbn,
                available_pbn,
            } if reply_port == port && available_pbn <= full_pbn => {
                Ok((fec, full_pbn, available_pbn))
            }
            _ => Err(MstError::Malformed),
        }
    }
    /// LINK_ADDRESS of the branch at (`lct`, `rad`), recorded in
    /// `topology` with no ports yet.
    async fn link_address<A: MstAux>(
        &mut self,
        aux: &mut A,
        lct: u8,
        rad: [u8; 8],
        topology: &mut Topology,
    ) -> Result<Frame, MstError<A::Error>> {
        // Bound work and retained memory when notifications trigger probes.
        if topology.branches.len() >= 64 {
            return Err(MstError::Malformed);
        }
        let Reply::LinkAddress { guid, ports } =
            self.transact(aux, lct, &rad, &Request::LinkAddress).await?
        else {
            return Err(MstError::Malformed);
        };
        let index = topology.branches.len();
        topology.branches.push(Branch {
            lct,
            rad,
            guid,
            ports: Vec::new(),
        });
        Ok(Frame {
            index,
            lct,
            rad,
            ports,
            next: 0,
            pending: None,
        })
    }
    /// drm_dp_send_dpcd_read: `len` bytes of the DPCD behind `port` (an
    /// output port's own AUX, drm_dp_mst_port's `aux`) from `address`,
    /// through the port's branch. A short or misdirected reply is Malformed.
    pub async fn remote_dpcd_read<A: MstAux>(
        &mut self,
        aux: &mut A,
        topology: &Topology,
        port: Sink,
        address: u32,
        len: u8,
    ) -> Result<Vec<u8>, MstError<A::Error>> {
        let branch = topology
            .branches
            .get(port.branch)
            .ok_or(MstError::Malformed)?;
        let request = Request::RemoteDpcdRead {
            port: port.port,
            address,
            len,
        };
        match self
            .transact(aux, branch.lct, &branch.rad, &request)
            .await?
        {
            Reply::RemoteDpcdRead { port: p, bytes }
                if p == port.port && bytes.len() == usize::from(len) =>
            {
                Ok(bytes)
            }
            _ => Err(MstError::Malformed),
        }
    }
    /// drm_dp_send_dpcd_write: `bytes` to the DPCD behind `port` at
    /// `address`, through the port's branch.
    pub async fn remote_dpcd_write<A: MstAux>(
        &mut self,
        aux: &mut A,
        topology: &Topology,
        port: Sink,
        address: u32,
        bytes: &[u8],
    ) -> Result<(), MstError<A::Error>> {
        let branch = topology
            .branches
            .get(port.branch)
            .ok_or(MstError::Malformed)?;
        let request = Request::RemoteDpcdWrite {
            port: port.port,
            address,
            bytes: bytes.to_vec(),
        };
        match self
            .transact(aux, branch.lct, &branch.rad, &request)
            .await?
        {
            Reply::RemoteDpcdWrite { port: p } if p == port.port => Ok(()),
            _ => Err(MstError::Malformed),
        }
    }
    /// Read EDID block `block` of an end device through its branch
    /// (drm_do_probe_ddc_edid over drm_dp_mst_i2c_read).
    pub async fn read_edid_block<A: MstAux>(
        &mut self,
        aux: &mut A,
        topology: &Topology,
        sink: Sink,
        block: u8,
    ) -> Result<[u8; 128], MstError<A::Error>> {
        let branch = topology
            .branches
            .get(sink.branch)
            .ok_or(MstError::Malformed)?;
        let write = |device: u8, byte: u8| dp_mst::I2cWrite {
            device,
            bytes: alloc::vec![byte],
            no_stop: true,
            delay: 0,
        };
        let mut writes = Vec::new();
        if block / 2 != 0 {
            writes.push(write(0x30, block / 2));
        }
        writes.push(write(0x50, (block % 2) * 128));
        let request = Request::RemoteI2cRead {
            port: sink.port,
            writes,
            device: 0x50,
            len: 128,
        };
        match self
            .transact(aux, branch.lct, &branch.rad, &request)
            .await?
        {
            Reply::RemoteI2cRead { bytes, .. } if bytes.len() == 128 => {
                Ok(bytes.try_into().map_err(|_| MstError::Malformed)?)
            }
            _ => Err(MstError::Malformed),
        }
    }
}

/// drm_dp_dpcd_write_payload: the payload table entry for `vcpi`, then up
/// to 20 polls of its update status 10 ms apart.
pub async fn write_payload<A: MstAux>(
    aux: &mut A,
    vcpi: u8,
    start: u8,
    count: u8,
) -> Result<(), MstError<A::Error>> {
    // Unchecked, as Linux leaves it.
    let _ = aux
        .write(PAYLOAD_TABLE_UPDATE_STATUS, &[PAYLOAD_TABLE_UPDATED])
        .await;
    aux.write(PAYLOAD_ALLOCATE_SET, &[vcpi, start, count])
        .await
        .map_err(MstError::Aux)?;
    for retries in 1..=20 {
        let mut status = [0];
        aux.read(PAYLOAD_TABLE_UPDATE_STATUS, &mut status)
            .await
            .map_err(MstError::Aux)?;
        if status[0] & PAYLOAD_TABLE_UPDATED != 0 {
            return Ok(());
        }
        if retries < 20 {
            aux.delay(10_000).await;
        }
    }
    Err(MstError::PayloadTable)
}

#[cfg(feature = "kernel-test")]
#[path = "dp_mst_mgr_tests.rs"]
pub(crate) mod tests;
