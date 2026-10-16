//! DP MST on the native Navi48 display path: the topology manager over the
//! port's DMUB AUX channel, and each stream's payload added and removed as
//! amdgpu's allocate_mst_payload / deallocate_mst_payload drive DRM's
//! payload helpers and DC's source programming.
use super::modeset::{self, Configuration, DpRate, ModesetError, Selection};
use super::*;
use crate::amdgpu_dml::Timing;
use crate::dp_mst;
use crate::dp_mst::{Reply, Request};
use crate::dp_mst_mgr::{self, Manager, MstAux, MstError, Topology};

#[path = "amdgpu_navi48_mst_topology.rs"]
mod topology;
use topology::ProbeState;
pub use topology::{MstOutput, MstOutputId};

/// The port's AUX channel through DMUB, in 16-byte native transactions
/// with the display probe's DEFER retries.
struct DmubAux<'a> {
    dmub: &'a mut dmub::Dmub,
    instance: u8,
}
impl DmubAux<'_> {
    async fn transfer(
        &mut self,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        for attempt in 0..7 {
            match self.dmub.aux(self.instance, action, address, data).await {
                Err(dmub::Error::Aux(2 | 8)) if attempt != 6 => {
                    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await
                }
                result => return result,
            }
        }
        unreachable!()
    }
}
impl MstAux for DmubAux<'_> {
    type Error = dmub::Error;
    async fn read(&mut self, address: u32, buf: &mut [u8]) -> Result<(), dmub::Error> {
        for (i, piece) in buf.chunks_mut(16).enumerate() {
            self.transfer(0x90, address + 16 * i as u32, piece).await?;
        }
        Ok(())
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), dmub::Error> {
        for (i, piece) in data.chunks(16).enumerate() {
            let mut buf = [0u8; 16];
            buf[..piece.len()].copy_from_slice(piece);
            self.transfer(0x80, address + 16 * i as u32, &mut buf[..piece.len()])
                .await?;
        }
        Ok(())
    }
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}

/// One stream's VC payload on an MST link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstPayload {
    pub sink: dp_mst_mgr::Sink,
    /// VCPI (1..=63).
    pub vcpi: u8,
    pub start: u8,
    pub slots: u8,
    pub pbn: u16,
    /// The DIO stream encoder carrying it.
    pub stream: u8,
}

/// A payload transaction started but has not completed its required steps.
/// Retained after errors or cancellation; it is not permission to replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MstPayloadChange {
    Adding(u8),
    Removing(u8),
}

/// A port running MST: its manager, topology and payloads.
#[derive(Debug, Default)]
pub struct MstLink {
    /// The pipe whose display owns the trained link, while one runs.
    pub owner: Option<u8>,
    pub manager: Manager,
    pub topology: Topology,
    pub payloads: Vec<MstPayload>,
    /// Stable KMS slots, including reservations for disconnected sinks.
    pub outputs: [Option<MstOutput>; 4],
    payload_change: Option<MstPayloadChange>,
    resource_ports: Vec<dp_mst_mgr::Sink>,
    resource_query: bool,
    state: ProbeState,
    dirty: bool,
}

impl MstLink {
    /// Started payload work without a completion witness, including returned
    /// errors and dropped futures. No automatic replay/reset is provided.
    pub fn payload_change(&self) -> Option<MstPayloadChange> {
        self.payload_change
    }
    /// A resource query whose sideband completion is unproven. Failed and
    /// cancelled queries retain this marker and refuse other transactions.
    pub fn resource_query_pending(&self) -> bool {
        self.resource_query
    }
    pub(super) fn require_transaction_idle<E>(&self) -> Result<(), MstFailure<E>> {
        if self.payload_change.is_some() || self.resource_query {
            return Err(otg::Error::Busy.into());
        }
        Ok(())
    }
    fn has_stream_resources(&self) -> bool {
        self.owner.is_some()
            || !self.payloads.is_empty()
            || self.payload_change.is_some()
            || self.resource_query
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MstFailure<E = dmub::Error> {
    Mst(MstError<E>),
    Display(otg::Error),
    /// The port runs no MST, or the request names nothing in it.
    Invalid,
}
impl<E> From<MstError<E>> for MstFailure<E> {
    fn from(e: MstError<E>) -> Self {
        Self::Mst(e)
    }
}
impl<E> From<otg::Error> for MstFailure<E> {
    fn from(e: otg::Error) -> Self {
        Self::Display(e)
    }
}

/// DP_PAYLOAD_ACT_HANDLED in DP_PAYLOAD_TABLE_UPDATE_STATUS.
const ACT_HANDLED: u8 = 2;

/// The source half of a payload change: the link's allocation table with
/// ACT, and a stream's VC rate.
pub(crate) trait MstSource {
    fn allocation(
        &mut self,
        table: &[otg::MstAllocation],
    ) -> impl core::future::Future<Output = Result<(), otg::Error>>;
    fn vc_rate(
        &mut self,
        stream: u8,
        rate: (u32, u32),
    ) -> impl core::future::Future<Output = Result<(), otg::Error>>;
}

/// drm_dp_check_act_status: up to 3 s for ACT handled, 200 us apart.
async fn act_handled<A: MstAux>(aux: &mut A) -> Result<(), MstFailure<A::Error>> {
    for _ in 0..15_000 {
        let mut status = [0];
        aux.read(dp_mst_mgr::PAYLOAD_TABLE_UPDATE_STATUS, &mut status)
            .await
            .map_err(MstError::Aux)?;
        if status[0] & ACT_HANDLED != 0 {
            return Ok(());
        }
        aux.delay(200).await;
    }
    Err(MstFailure::Mst(MstError::Timeout))
}

/// The source's allocation table: every payload by start slot.
fn table(payloads: &[MstPayload]) -> Vec<otg::MstAllocation> {
    let mut p: Vec<&MstPayload> = payloads.iter().collect();
    p.sort_by_key(|x| x.start);
    p.iter()
        .map(|x| otg::MstAllocation {
            stream: x.stream,
            slots: x.slots,
        })
        .collect()
}

/// allocate_mst_payload for DIO `stream` to `sink`: the lowest free VCPI
/// at the next start slot in the sink's payload table
/// (drm_dp_add_payload_part1), the source table with ACT, ACT handled,
/// ALLOCATE_PAYLOAD to the sink's branch (drm_dp_add_payload_part2), then
/// the stream's VC rate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn add_payload<A: MstAux, S: MstSource>(
    link: &mut MstLink,
    aux: &mut A,
    source: &mut S,
    sink: dp_mst_mgr::Sink,
    stream: u8,
    pbn: u16,
    slots: u8,
    rate: (u32, u32),
) -> Result<MstPayload, MstFailure<A::Error>> {
    link.require_transaction_idle()?;
    let info = link.topology.port(sink).ok_or(MstFailure::Invalid)?.info;
    let branch = link.topology.branches[sink.branch].clone();
    let allocated: Vec<_> = link.payloads.iter().map(|p| (p.sink, p.pbn)).collect();
    if link.dirty
        || pbn == 0
        || slots == 0
        || topology::path_budget(&link.topology, sink, &allocated).is_none_or(|free| pbn > free)
    {
        return Err(MstFailure::Invalid);
    }
    if link
        .payloads
        .iter()
        .any(|p| p.stream == stream || p.sink == sink)
    {
        return Err(MstFailure::Invalid);
    }
    let vcpi = (1..=63u8)
        .find(|v| link.payloads.iter().all(|p| p.vcpi != *v))
        .ok_or(MstFailure::Invalid)?;
    let start = 1 + link
        .payloads
        .iter()
        .map(|p| u32::from(p.slots))
        .sum::<u32>();
    if start + u32::from(slots) > 64 {
        return Err(MstFailure::Invalid);
    }
    let payload = MstPayload {
        sink,
        vcpi,
        start: start as u8,
        slots,
        pbn,
        stream,
    };
    // Persist before the first remote write, even before payloads.push. An
    // error or dropped future may leave the receiver ahead of our bookkeeping.
    link.payload_change = Some(MstPayloadChange::Adding(stream));
    dp_mst_mgr::write_payload(aux, vcpi, payload.start, slots).await?;
    link.payloads.push(payload);
    source.allocation(&table(&link.payloads)).await?;
    act_handled(aux).await?;
    let request = Request::AllocatePayload {
        port: info.port,
        vcpi,
        pbn,
        sdp_stream_sinks: (0..info.sdp_streams).collect(),
    };
    match link
        .manager
        .transact(aux, branch.lct, &branch.rad, &request)
        .await?
    {
        Reply::AllocatePayload { .. } => {}
        _ => return Err(MstFailure::Mst(MstError::Malformed)),
    }
    source.vc_rate(stream, rate).await?;
    link.payload_change = None;
    Ok(payload)
}

/// deallocate_mst_payload for DIO `stream`: VC rate zero, the remote and
/// DPCD allocations removed (drm_dp_remove_payload_part1, failures
/// tolerated as Linux does), the source table without it and ACT handled
/// (unchecked), then later payloads' start slots moved down
/// (drm_dp_remove_payload_part2).
pub(crate) async fn remove_payload<A: MstAux, S: MstSource>(
    link: &mut MstLink,
    aux: &mut A,
    source: &mut S,
    stream: u8,
    connected: bool,
) -> Result<(), MstFailure<A::Error>> {
    link.require_transaction_idle()?;
    let index = link
        .payloads
        .iter()
        .position(|p| p.stream == stream)
        .ok_or(MstFailure::Invalid)?;
    let payload = link.payloads[index];
    link.payload_change = Some(MstPayloadChange::Removing(stream));
    source.vc_rate(stream, (0, 0)).await?;
    if let (true, Some(branch), Some(port)) = (
        connected,
        link.topology.branches.get(payload.sink.branch).cloned(),
        link.topology.port(payload.sink).copied(),
    ) {
        let request = Request::AllocatePayload {
            port: port.info.port,
            vcpi: payload.vcpi,
            pbn: 0,
            sdp_stream_sinks: (0..port.info.sdp_streams).collect(),
        };
        let _ = link
            .manager
            .transact(aux, branch.lct, &branch.rad, &request)
            .await;
    }
    if connected {
        let _ = dp_mst_mgr::write_payload(aux, payload.vcpi, payload.start, 0).await;
    }
    link.payloads.remove(index);
    source.allocation(&table(&link.payloads)).await?;
    if connected {
        let _ = act_handled(aux).await;
    }
    for p in link.payloads.iter_mut().filter(|p| p.start > payload.start) {
        p.start -= payload.slots;
    }
    link.payload_change = None;
    Ok(())
}

/// The selected display's source programming on the port's MST link.
struct OtgSource<'a> {
    otg: &'a mut otg::Otg,
    transmitter: u8,
}
impl MstSource for OtgSource<'_> {
    async fn allocation(&mut self, table: &[otg::MstAllocation]) -> Result<(), otg::Error> {
        // SAFETY: the table mirrors the sink's payload table.
        unsafe {
            self.otg
                .update_mst_allocation(self.transmitter, table)
                .await
        }
    }
    async fn vc_rate(&mut self, stream: u8, rate: (u32, u32)) -> Result<(), otg::Error> {
        // SAFETY: `stream` carries (or carried) a payload on this link.
        unsafe {
            self.otg
                .set_mst_vc_rate(self.transmitter, stream, rate)
                .await
        }
    }
}

impl ColdBoot {
    fn mst_path(&mut self, port: usize) -> Result<(u8, u8), MstFailure> {
        let path = self.dp_phy_path(port)?;
        Ok((path.aux.ok_or(MstFailure::Invalid)?, path.transmitter))
    }
    /// Start once, or reprobe a dirty session after its streams stop. Clean
    /// sessions retain their topology and connector slots without AUX traffic.
    pub async fn start_display_mst(&mut self, port: usize) -> Result<Topology, MstFailure> {
        let (instance, _) = self.mst_path(port)?;
        // Keep the session in its owner across every await, including failure
        // and cancellation. Re-entering an incomplete probe is refused.
        let link = self.mst.entry(port).or_default();
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        link.prepare(&mut aux).await?;
        Ok(link.topology.clone())
    }
    /// Whether DP `port`'s sink is an MST branch (DPCD 1.2 and MSTM_CAP),
    /// which Linux drives in MST mode (dc_connection_mst_branch).
    pub async fn display_mst_capable(&mut self, port: usize) -> bool {
        let Ok((instance, _)) = self.mst_path(port) else {
            return false;
        };
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        let (mut rev, mut cap) = ([0u8], [0u8]);
        aux.read(0, &mut rev).await.is_ok()
            && rev[0] >= 0x12
            && aux.read(dp_mst_mgr::MSTM_CAP, &mut cap).await.is_ok()
            && cap[0] & 1 != 0
    }
    pub fn display_mst(&self, port: usize) -> Option<&MstLink> {
        self.mst.get(&port)
    }
    /// Service downstream connection/resource changes, preserving the old
    /// topology until the platform has retired its streams. Drain before and
    /// after polling so a full queue cannot block down-transaction progress.
    pub async fn service_display_mst(&mut self, port: usize) -> Result<bool, MstFailure> {
        self.mst
            .get_mut(&port)
            .ok_or(MstFailure::Invalid)?
            .consume_events();
        let result = self.poll_display_mst(port).await;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        link.consume_events();
        result?;
        let (instance, _) = self.mst_path(port)?;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        link.refresh_resources(&mut aux).await?;
        Ok(link.dirty)
    }
    /// Forget a physically removed branch only after its last stream stops.
    /// No AUX access is made to the absent device.
    pub fn forget_unplugged_display_mst(&mut self, port: usize) -> Result<(), MstFailure> {
        if self.display_hpd(port) != Ok(false)
            || self
                .mst
                .get(&port)
                .is_some_and(MstLink::has_stream_resources)
        {
            return Err(MstFailure::Invalid);
        }
        self.mst.remove(&port);
        Ok(())
    }
    /// Service a connected branch's idle up requests over DMUB AUX. Complete
    /// notifications remain in `display_mst(port).manager.events`; the caller
    /// drains them with `take_display_mst_events` before the queue fills.
    /// This does not change the topology or any live payload's sink identity.
    pub async fn poll_display_mst(&mut self, port: usize) -> Result<usize, MstFailure> {
        let (instance, _) = self.mst_path(port)?;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        link.require_transaction_idle()?;
        if link.state != ProbeState::Ready {
            return Err(MstFailure::Invalid);
        }
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        Ok(link.manager.poll_up_requests(&mut aux).await?)
    }
    /// Take the branch notifications, including any retained before a failed
    /// poll. Consuming them does not acknowledge a topology reconfiguration.
    pub fn take_display_mst_events(&mut self, port: usize) -> Vec<dp_mst::UpRequest> {
        self.mst
            .get_mut(&port)
            .map(|link| core::mem::take(&mut link.manager.events))
            .unwrap_or_default()
    }
    /// The EDID of an end device behind the port: block 0 and its
    /// extensions, through REMOTE_I2C_READ.
    pub async fn read_display_mst_edid(
        &mut self,
        port: usize,
        sink: dp_mst_mgr::Sink,
    ) -> Result<Vec<u8>, MstFailure> {
        let (instance, _) = self.mst_path(port)?;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        link.require_transaction_idle()?;
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        topology::read_edid(&mut link.manager, &mut aux, &link.topology, sink).await
    }
    /// Add DIO stream `stream`'s payload for `sink` (`add_payload`).
    /// Incomplete transactions retain their marker and refuse further changes.
    /// # Safety
    /// The selected display's frontend on `stream` runs on the port's MST
    /// link, its video not yet started.
    pub async unsafe fn add_display_mst_payload(
        &mut self,
        port: usize,
        sink: dp_mst_mgr::Sink,
        stream: u8,
        pbn: u16,
        slots: u8,
        rate: (u32, u32),
    ) -> Result<MstPayload, MstFailure> {
        let (instance, transmitter) = self.mst_path(port)?;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        let mut source = OtgSource {
            otg: self.otg.as_mut().map_err(|e| *e)?,
            transmitter,
        };
        add_payload(link, &mut aux, &mut source, sink, stream, pbn, slots, rate).await
    }
    /// Remove DIO stream `stream`'s payload (`remove_payload`).
    /// Failure/cancellation retains the transaction even if its list entry
    /// has already been removed; that does not prove source/sink completion.
    /// # Safety
    /// The selected display's video on `stream` is stopped.
    pub async unsafe fn remove_display_mst_payload(
        &mut self,
        port: usize,
        stream: u8,
    ) -> Result<(), MstFailure> {
        let connected = self.display_hpd(port) != Ok(false);
        let (instance, transmitter) = self.mst_path(port)?;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        let mut source = OtgSource {
            otg: self.otg.as_mut().map_err(|e| *e)?,
            transmitter,
        };
        remove_payload(link, &mut aux, &mut source, stream, connected).await
    }
    /// drm_dp_mst_topology_mgr_set_mst(false), the port's MST state dropped.
    /// A session with a source owner, payloads or an incomplete payload change
    /// is left untouched.
    pub async fn stop_display_mst(&mut self, port: usize) {
        if self
            .mst
            .get(&port)
            .is_some_and(MstLink::has_stream_resources)
        {
            return;
        }
        let Ok((instance, _)) = self.mst_path(port) else {
            return;
        };
        if let Some(mut link) = self.mst.remove(&port) {
            let mut aux = DmubAux {
                dmub: &mut self.sequence.backend.dmub,
                instance,
            };
            link.manager.stop(&mut aux).await;
        }
    }
}

/// 8-bit RGB, as MST streams are selected (bpp in 1/16).
const MST_BPP_X16: u32 = 24 * 16;

/// The PBN and time slots of `timing` on an MST link of `lanes` at
/// `rate`
/// (drm_dp_calc_pbn_mode, dm_mst_get_pbn_divider,
/// drm_dp_atomic_find_time_slots); None past the 63 slots.
pub(super) fn mst_slots(timing: &Timing, lanes: u8, rate: DpRate, fec: bool) -> Option<(u16, u8)> {
    let DpRate::Legacy(rate) = rate else {
        return None;
    };
    let link_kbps = modeset::legacy_kbps(lanes, rate, fec) as u32;
    let pbn = dp_mst::calc_pbn_mode(timing.pixel_clock_khz, MST_BPP_X16);
    let div = dp_mst::pbn_div(link_kbps);
    if div == 0 {
        return None;
    }
    let slots = dp_mst::time_slots(pbn, div);
    (slots <= 63 && pbn <= u32::from(u16::MAX)).then_some((pbn as u16, slots as u8))
}

/// The streams one MST port lights, as amdgpu_dm's MST atomic check
/// admits them: each end device (in topology order, at most
/// `MAX_DISPLAYS`) at the timing `want(k)` asks of device k where its EDID
/// lists it and its payload fits, else the first of its EDID timings that
/// does, at 8 bpc RGB on the port's maximum 8b/10b link. A payload fits
/// the slots the earlier streams left of 63 and its port's available PBN
/// (ENUM_PATH_RESOURCES). Devices nothing fits stay dark. `devices` are
/// each end device, its EDID and available PBN. Zero PBN is exhausted capacity.
/// The topology modeset additionally enforces every shared upstream hop.
pub fn select_mst(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
) -> Vec<Selection> {
    select_mst_with_budget(port, caps, devices, want, &|_, _| u16::MAX)
}

fn select_mst_with_budget(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
    budget: &dyn Fn(dp_mst_mgr::Sink, &[Selection]) -> u16,
) -> Vec<Selection> {
    let mut free = 63u8;
    let mut out = Vec::new();
    for (k, (sink, edid, available)) in devices.iter().enumerate() {
        if out.len() == modeset::MAX_DISPLAYS {
            break;
        }
        let Some(base) = edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let (lanes, rate) = (caps.lanes, DpRate::Legacy(caps.rate));
        let available = (*available).min(budget(*sink, &out));
        let fits = |t: &Timing| {
            mst_slots(t, lanes, rate, caps.fec)
                .filter(|&(pbn, slots)| slots <= free && pbn <= available)
        };
        let timings = modeset::edid_timings(edid);
        let chosen = want(k)
            .filter(|w| timings.contains(w))
            .and_then(|w| fits(&w).map(|f| (w, f)))
            .or_else(|| timings.iter().find_map(|t| fits(t).map(|f| (*t, f))));
        let Some((timing, (pbn, slots))) = chosen else {
            continue;
        };
        let link_kbps = modeset::legacy_kbps(lanes, caps.rate, caps.fec) as u32;
        let Some(vc) = otg::vc_rate(timing.pixel_clock_khz * 24, link_kbps) else {
            continue;
        };
        free -= slots;
        let s = Selection {
            port,
            timing,
            lanes,
            rate,
            caps,
            edid: base,
            hdmi: false,
            scdc: false,
            depth: otg::ColorDepth::Bpc8,
            // MST audio (per-stream SDPs) is not implemented.
            audio: None,
            avi: otg::Avi::default(),
            limited: false,
            ycbcr420: false,
            frl: None,
            dsc: None,
            mst: Some(modeset::MstStream {
                sink: *sink,
                pbn,
                slots,
                rate: vc,
            }),
        };
        out.push(s);
    }
    out
}

/// Keep a sink's output assignment even when an earlier sink is disabled,
/// has an unreadable EDID, or cannot fit. `pipes[k]` belongs to device k.
pub(super) fn select_mst_outputs(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
    pipes: &[Option<u8>],
    budget: &dyn Fn(dp_mst_mgr::Sink, &[Selection]) -> u16,
) -> Vec<(Selection, u8)> {
    let enabled: Vec<usize> = (0..devices.len())
        .filter(|&k| pipes.get(k).is_some_and(Option::is_some))
        .collect();
    let selected: Vec<_> = enabled.iter().map(|&k| devices[k].clone()).collect();
    select_mst_with_budget(port, caps, &selected, &|k| want(enabled[k]), budget)
        .into_iter()
        .filter_map(|s| {
            let k = devices
                .iter()
                .position(|d| Some(d.0) == s.mst.map(|m| m.sink))?;
            Some((s, pipes[k]?))
        })
        .collect()
}

/// Timings a dark connector could add beside the running streams. Each
/// candidate is independent: advertising a mode reserves neither a payload
/// nor a pipe, and enabling multiple connectors still needs joint admission.
pub(super) fn dark_mst_modes(
    soc: &crate::amdgpu_dcn401_dml::Soc,
    caps: modeset::DpCaps,
    edid: &[u8],
    available: u16,
    lit: &[Selection],
) -> Vec<Timing> {
    let used = lit.iter().try_fold(0u8, |n, s| n.checked_add(s.mst?.slots));
    let Some(free) = used.and_then(|n| 63u8.checked_sub(n)) else {
        return Vec::new();
    };
    let mut joint: Vec<_> = lit.iter().map(modeset::selection_mode).collect();
    let mut offered = Vec::new();
    for t in modeset::edid_timings(edid) {
        if offered.len() == modeset::MAX_MODES {
            break;
        }
        if !mst_slots(&t, caps.lanes, DpRate::Legacy(caps.rate), caps.fec)
            .is_some_and(|(pbn, slots)| slots <= free && pbn <= available)
        {
            continue;
        }
        joint.push(modeset::mode(t));
        if crate::amdgpu_dcn401_dml::admit_all(soc, &joint).is_ok() {
            offered.push(t);
        }
        joint.pop();
    }
    offered
}

impl ColdBoot {
    /// Light the end devices behind DP `port`'s MST branch (`select_mst`),
    /// stable output k on `pipes[k]` (its display slot too), skipping None, as one
    /// configuration like `modeset_displays`: MST started and the topology
    /// probed, each device's EDID read, the admitted streams' clocks
    /// programmed, then each stream lit: the first trains the port's MST
    /// link, the others attach to it, and each adds its payload before its
    /// video starts. `want(k)` is the timing asked of output k. An empty
    /// configuration keeps the manager enabled for downstream hotplug.
    /// On success, dark outputs carry independently admitted `MstOutput::modes`
    /// beside the lit streams, including when every requested pipe is None.
    /// # Safety
    /// As for `modeset_displays`.
    pub async unsafe fn modeset_mst_displays(
        &mut self,
        port: usize,
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipes: &[Option<u8>],
    ) -> Result<Configuration, ModesetError> {
        self.teardowns.check_idle()?;
        if pipes.is_empty()
            || pipes.len() > modeset::MAX_DISPLAYS
            || pipes.iter().flatten().any(|&p| p >= 4)
            || pipes
                .iter()
                .enumerate()
                .any(|(k, p)| p.is_some() && pipes[..k].contains(p))
            || self.mst.get(&port).is_some_and(|l| l.owner.is_some())
        {
            return Err(ModesetError::Display(otg::Error::Invalid));
        }
        self.start_display_mst(port).await?;
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        let mut devices = Vec::new();
        let mut slots = Vec::new();
        for (k, output) in link.outputs.iter().enumerate() {
            if let Some(o) = output {
                if let Some(sink) = o.sink {
                    devices.push((
                        sink,
                        o.edid.clone(),
                        link.topology.port(sink).map_or(0, |p| p.available_pbn),
                    ));
                    slots.push(k);
                }
            }
        }
        let assigned: Vec<_> = slots
            .iter()
            .map(|&k| pipes.get(k).copied().flatten())
            .collect();
        if devices.is_empty() {
            return Ok(Configuration {
                displays: Vec::new(),
                failed: None,
            });
        }
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let path = *self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .get(port)
            .ok_or(ModesetError::NoSink)?;
        let caps = ports
            .iter()
            .find(|p| p.path == path)
            .and_then(|p| p.sink.as_ref().ok())
            .and_then(|sink| modeset::dp_caps(&path, sink))
            .ok_or(ModesetError::NoSink)?;
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        let budget = |sink, selected: &[Selection]| {
            let allocated: Vec<_> = selected
                .iter()
                .filter_map(|s| s.mst.map(|m| (m.sink, m.pbn)))
                .collect();
            topology::path_budget(&link.topology, sink, &allocated).unwrap_or(0)
        };
        let (mut selections, pipes): (Vec<_>, Vec<_>) = select_mst_outputs(
            port,
            caps,
            &devices,
            &|k| want(slots[k]),
            &assigned,
            &budget,
        )
        .into_iter()
        .unzip();
        // Discard old admission before any asynchronous clock/startup work.
        if let Some(link) = self.mst.get_mut(&port) {
            for output in link.outputs.iter_mut().flatten() {
                output.modes.clear();
            }
        }
        self.select_display(pipes.first().copied().unwrap_or(0))?;
        let soc = self.prepare_configuration(&selections).await?;
        if selections.is_empty() {
            self.admit_dark_mst_outputs(port, &soc, caps, &devices, &[]);
            return Ok(Configuration {
                displays: Vec::new(),
                failed: None,
            });
        }
        let limited = modeset::limited_range(modeset::broadcast_rgb());
        for s in &mut selections {
            s.limited = limited;
        }
        let plans = modeset::admit_displays(&soc, &selections).map_err(otg::Error::Admission)?;
        selections.truncate(plans.len());
        self.prepare_pipes(&selections, &plans, &pipes).await?;
        let mut lit = Vec::with_capacity(selections.len());
        let mut failed = None;
        for ((selection, plan), &pipe) in selections.iter().zip(&plans).zip(&pipes) {
            // SAFETY: the caller's obligations; every earlier display is lit
            // in its own slot and left to it by each step.
            match unsafe { self.light(pipe, *selection, *plan, &mut fill) }.await {
                Ok(m) => lit.push(m),
                Err(e) if lit.is_empty() => return Err(e),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        for k in 0..lit.len() {
            let edid = devices
                .iter()
                .find(|d| Some(d.0) == lit[k].selection.mst.map(|m| m.sink))
                .map(|d| d.1.clone())
                .unwrap_or_default();
            lit[k].modes = self.offered_modes(&soc, &lit, k, &edid);
        }
        let running: Vec<_> = lit.iter().map(|m| m.selection).collect();
        if failed.is_none() {
            self.admit_dark_mst_outputs(port, &soc, caps, &devices, &running);
        }
        Ok(Configuration {
            displays: lit,
            failed,
        })
    }
    fn admit_dark_mst_outputs(
        &mut self,
        port: usize,
        soc: &crate::amdgpu_dcn401_dml::Soc,
        caps: modeset::DpCaps,
        devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
        lit: &[Selection],
    ) {
        if let Some(link) = self.mst.get_mut(&port) {
            let allocated: Vec<_> = lit
                .iter()
                .filter_map(|s| s.mst.map(|m| (m.sink, m.pbn)))
                .collect();
            for output in link.outputs.iter_mut().flatten() {
                output.modes.clear();
                if lit.iter().any(|s| s.mst.map(|m| m.sink) == output.sink) {
                    continue;
                }
                if let Some((sink, edid, _)) = devices.iter().find(|d| Some(d.0) == output.sink) {
                    let available =
                        topology::path_budget(&link.topology, *sink, &allocated).unwrap_or(0);
                    output.modes = dark_mst_modes(soc, caps, edid, available, lit);
                }
            }
        }
    }
    /// Start `selection`'s MST stream on staged `pipe` (DIO stream `pipe`):
    /// the first stream trains the port's MST link at the selected
    /// setting (no fallback: every payload was sized for it), later ones
    /// attach to it; then the frontend, the payload, video and scanout.
    /// # Safety
    /// As for `start_link`.
    pub(super) async unsafe fn start_mst_stream(
        &mut self,
        port: usize,
        stream: modeset::MstStream,
        selection: &Selection,
        pipe: u8,
    ) -> Result<otg::ScanoutRunning, ModesetError> {
        let DpRate::Legacy(rate) = selection.rate else {
            return Err(ModesetError::Link);
        };
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        link.require_transaction_idle()?;
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            if link.owner.is_none() {
                self.enable_display_dp_phy(
                    port,
                    otg::DpPhySettings {
                        lanes: selection.lanes,
                        rate,
                        mst: true,
                    },
                )
                .await?;
                if let Err(e) = self.train_display_dp_link(port, false).await {
                    let _ = self.stop_display_dp_link(port).await;
                    return Err(e.into());
                }
                if let Some(link) = self.mst.get_mut(&port) {
                    link.owner = Some(pipe);
                }
            } else {
                self.attach_display_mst_link(port)?;
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Link);
            self.prepare_display_dp_frontend(port, otg::DpFrontendRequest { stream: pipe, pipe })
                .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Frontend);
            self.add_display_mst_payload(
                port,
                stream.sink,
                pipe,
                stream.pbn,
                stream.slots,
                stream.rate,
            )
            .await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Payload);
            self.start_display_dp_video(port).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            Ok(self.start_display_scanout(pipe).await?)
        }
    }
    /// Finish teardown after video, payload and frontend have stopped:
    /// an attached display detaches, while the link's owner hands the link to a
    /// remaining stream's display or, the last, stops the link (without
    /// addressing an `unplugged` sink). A connected root keeps its manager
    /// and connector reservations even after the last stream stops.
    /// # Safety
    /// As for `stop_modeset`.
    pub(super) async unsafe fn finish_mst_stream(
        &mut self,
        port: usize,
        pipe: u8,
        unplugged: bool,
    ) -> Result<(), ModesetError> {
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        link.require_transaction_idle()?;
        let owner = link.owner == Some(pipe);
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            if !owner {
                return Ok(self.detach_display_mst_link(port)?);
            }
            // Display k runs on pipe k: the next owner is a remaining
            // stream's pipe.
            let next = self
                .mst
                .get(&port)
                .and_then(|l| l.payloads.first())
                .map(|p| p.stream);
            if let Some(to) = next {
                let transmitter = self.dp_phy_path(port)?.transmitter;
                self.otg
                    .as_mut()
                    .map_err(|e| *e)?
                    .hand_over_mst_link(transmitter, to)?;
                if let Some(link) = self.mst.get_mut(&port) {
                    link.owner = Some(to);
                }
                return Ok(());
            }
            if unplugged {
                self.stop_unplugged_display_dp_link(port).await?;
            } else {
                self.stop_display_dp_link(port).await?;
            }
        }
        if let Some(link) = self.mst.get_mut(&port) {
            link.owner = None;
        }
        if unplugged {
            self.forget_unplugged_display_mst(port)?;
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_mst_tests.rs"]
mod tests;
