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
#[path = "amdgpu_navi48_mst_dsc.rs"]
pub(super) mod dsc;
pub use dsc::{DscAux, MstDsc};

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
    /// The stream encoder carrying it: DIO on 8b/10b, HPO on 128b/132b.
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
    /// The owner's link codes 128b/132b: HPO encoders carry the streams and
    /// payloads start at slot 0 (drm_dp_mst_update_slots).
    pub uhbr: bool,
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
    /// End device `sink`'s depth cap on board port `port`: its connector's
    /// "max bpc" (the KMS slot it holds in `outputs`) within
    /// `amdgpu.max_bpc` (`modeset::connector_max_bpc`).
    pub(super) fn max_bpc(&self, port: usize, sink: dp_mst_mgr::Sink) -> u8 {
        self.outputs
            .iter()
            .position(|o| o.as_ref().is_some_and(|o| o.sink == Some(sink)))
            .map_or_else(modeset::max_bpc, |slot| {
                modeset::connector_max_bpc(port, Some(slot as u8))
            })
    }
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
    /// Only a completed payload may expose its stream's audio endpoint.
    pub(super) fn audio_slots(&self, stream: u8) -> Result<u8, otg::Error> {
        if self.payload_change.is_some() || self.resource_query {
            return Err(otg::Error::Busy);
        }
        let mut owned = self.payloads.iter().filter(|p| p.stream == stream);
        let p = owned.next().ok_or(otg::Error::Invalid)?;
        if owned.next().is_some() || self.owner.is_none() || !(1..=63).contains(&p.slots) {
            return Err(otg::Error::Invalid);
        }
        Ok(p.slots)
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

/// allocate_mst_payload for stream encoder `stream` to `sink`: the lowest
/// free VCPI at the next start slot in the sink's payload table
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
    let first = u32::from(!link.uhbr);
    let start = first
        + link
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

/// deallocate_mst_payload for stream encoder `stream`: VC rate zero, the remote and
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

/// The selected display's source programming on the port's MST link: the
/// DIO link and stream encoders on 8b/10b, the HPO ones on 128b/132b.
struct OtgSource<'a> {
    otg: &'a mut otg::Otg,
    transmitter: u8,
    uhbr: bool,
}
impl MstSource for OtgSource<'_> {
    async fn allocation(&mut self, table: &[otg::MstAllocation]) -> Result<(), otg::Error> {
        // SAFETY: the table mirrors the sink's payload table.
        unsafe {
            if self.uhbr {
                self.otg
                    .update_uhbr_mst_allocation(self.transmitter, table)
                    .await
            } else {
                self.otg
                    .update_mst_allocation(self.transmitter, table)
                    .await
            }
        }
    }
    async fn vc_rate(&mut self, stream: u8, rate: (u32, u32)) -> Result<(), otg::Error> {
        // SAFETY: `stream` carries (or carried) a payload on this link.
        unsafe {
            if self.uhbr {
                self.otg
                    .set_uhbr_mst_vc_rate(self.transmitter, stream, rate)
                    .await
            } else {
                self.otg
                    .set_mst_vc_rate(self.transmitter, stream, rate)
                    .await
            }
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
    /// Service downstream connection/resource changes. A change that leaves
    /// every running stream's route intact (a downstream branch or device
    /// added or removed elsewhere in the tree) is adopted at once, as Linux
    /// keeps unaffected streams (`MstLink::reprobe_live`); dark outputs are
    /// then readmitted beside the running streams. Otherwise the old
    /// topology stays until the platform has retired its streams. Returns
    /// whether the configuration must be relit: a route was lost, or a new
    /// end device appeared for the routing to consider. Drain before and
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
        if !link.dirty || !link.has_stream_resources() {
            return Ok(link.dirty);
        }
        let present = |l: &MstLink| -> Vec<MstOutputId> {
            l.outputs
                .iter()
                .flatten()
                .filter(|o| o.sink.is_some())
                .map(|o| o.id)
                .collect()
        };
        let before = present(link);
        if !link.reprobe_live(&mut aux).await? {
            return Ok(true);
        }
        let added = present(link).iter().any(|id| !before.contains(id));
        self.readmit_dark_mst_outputs(port);
        Ok(added)
    }
    /// Admit each dark end device's timings beside the running displays
    /// after a live topology change (as a configuration's last step does).
    fn readmit_dark_mst_outputs(&mut self, port: usize) {
        let running: Vec<Selection> = self
            .display_modesets()
            .into_iter()
            .flatten()
            .map(|m| m.selection)
            .collect();
        let Some(caps) = running
            .iter()
            .find(|s| s.port == port && s.mst.is_some())
            .map(|s| s.caps)
        else {
            return;
        };
        let Ok(soc) = self.display_soc() else {
            return;
        };
        let Some(link) = self.mst.get(&port) else {
            return;
        };
        let devices: Vec<_> = link
            .outputs
            .iter()
            .flatten()
            .filter_map(|o| {
                let sink = o.sink?;
                Some((
                    sink,
                    o.edid.clone(),
                    link.topology.port(sink).map_or(0, |p| p.available_pbn),
                ))
            })
            .collect();
        self.admit_dark_mst_outputs(port, &soc, caps, &devices, &running);
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
    /// Add stream encoder `stream`'s payload for `sink` (`add_payload`).
    /// Incomplete transactions retain their marker and refuse further changes.
    /// # Safety
    /// The selected display's frontend (DIO) or blank stream (HPO) on
    /// `stream` runs on the port's MST link, its video not yet started.
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
            uhbr: link.uhbr,
        };
        add_payload(link, &mut aux, &mut source, sink, stream, pbn, slots, rate).await
    }
    /// Remove stream encoder `stream`'s payload (`remove_payload`).
    /// Failure/cancellation retains the transaction even if its list entry
    /// has already been removed; that does not prove source/sink completion.
    /// # Safety
    /// The selected display's video on `stream` is stopped (DIO) or
    /// blanked (HPO).
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
            uhbr: link.uhbr,
        };
        remove_payload(link, &mut aux, &mut source, stream, connected).await
    }
    /// dm_helpers_dp_write_dsc_enable for an MST stream decoded by `dsc`:
    /// DP_DSC_ENABLE on its decoder (and passthrough peer) through the
    /// port's manager. Enabling reads the decoder back.
    pub(super) async fn set_display_mst_dsc(
        &mut self,
        port: usize,
        dsc: &MstDsc,
        enable: bool,
    ) -> Result<(), MstFailure> {
        let (instance, _) = self.mst_path(port)?;
        let link = self.mst.get_mut(&port).ok_or(MstFailure::Invalid)?;
        link.require_transaction_idle()?;
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        dsc::set_rx(&mut link.manager, &mut aux, &link.topology, dsc, enable).await?;
        if enable && !dsc::rx_enabled(&mut link.manager, &mut aux, &link.topology, dsc).await? {
            return Err(MstFailure::Mst(MstError::Malformed));
        }
        Ok(())
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

/// decide_mst_link_settings: an MST link trains at the sink's verified
/// link cap, its best 128b/132b rate where it codes one (Linux's
/// mst_decide_link_encoding_format then picks 128b/132b), else its best
/// 8b/10b link.
pub(super) fn mst_link(caps: modeset::DpCaps) -> (u8, DpRate) {
    match caps.uhbr_rates().last() {
        Some(r) => (caps.lanes, DpRate::Uhbr(r)),
        None => (caps.lanes, DpRate::Legacy(caps.rate)),
    }
}

/// drm_dp_mst_update_slots: the time slots streams may take, 63 after the
/// 8b/10b MTP header slot, all 64 on 128b/132b.
pub(super) fn mst_total_slots(rate: DpRate) -> u8 {
    match rate {
        DpRate::Legacy(_) => 63,
        DpRate::Uhbr(_) => 64,
    }
}

/// The PBN and time slots of `timing` on an MST link of `lanes` at
/// `rate`
/// (drm_dp_calc_pbn_mode, dm_mst_get_pbn_divider of the link's
/// dc_link_bandwidth_kbps, drm_dp_atomic_find_time_slots); None past the
/// link's slots.
pub(super) fn mst_slots(timing: &Timing, lanes: u8, rate: DpRate, fec: bool) -> Option<(u16, u8)> {
    let link_kbps = match rate {
        DpRate::Legacy(r) => modeset::legacy_kbps(lanes, r, fec),
        DpRate::Uhbr(r) => modeset::uhbr_kbps(lanes, r),
    };
    let pbn = dp_mst::calc_pbn_mode(timing.pixel_clock_khz, MST_BPP_X16);
    let div = dp_mst::pbn_div(u32::try_from(link_kbps).ok()?);
    if div == 0 {
        return None;
    }
    let slots = dp_mst::time_slots(pbn, div);
    (slots <= u32::from(mst_total_slots(rate)) && pbn <= u32::from(u16::MAX))
        .then_some((pbn as u16, slots as u8))
}

/// The source VC rate (X, Y) of an RGB MST stream at `bpc`: Y in 1/2^26 on
/// 8b/10b (`otg::vc_rate`), 1/2^25 on 128b/132b (`otg::uhbr_mst_rate`).
fn mst_vc_rate(timing: &Timing, bpc: u8, lanes: u8, rate: DpRate, fec: bool) -> Option<(u32, u32)> {
    match rate {
        DpRate::Legacy(r) => otg::vc_rate(
            timing.pixel_clock_khz.checked_mul(3 * u32::from(bpc))?,
            modeset::legacy_kbps(lanes, r, fec) as u32,
        ),
        DpRate::Uhbr(rate) => {
            let settings = otg::UhbrSettings {
                lanes,
                rate,
                mst: true,
            };
            otg::uhbr_mst_rate(timing, u32::from(bpc), settings)
                .map(|(v, _)| (v >> 25, v & ((1 << 25) - 1)))
        }
    }
}

/// The streams one MST port lights, as amdgpu_dm's MST atomic check
/// admits them: each end device (in topology order, at most
/// `MAX_DISPLAYS`) at the timing `want(k)` asks of device k where its EDID
/// lists it and its payload fits, else the first of its EDID timings that
/// does, at 8 bpc RGB on the port's MST link (`mst_link`). A payload fits
/// the slots the earlier streams left of the link's and its port's available PBN
/// (ENUM_PATH_RESOURCES). Devices nothing fits stay dark. `devices` are
/// each end device, its EDID and available PBN. Zero PBN is exhausted capacity.
/// The topology modeset additionally enforces every shared upstream hop.
pub fn select_mst(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
) -> Vec<Selection> {
    select_mst_with_budget(port, caps, devices, want, &|_, _| u16::MAX, None)
}

/// What MST DSC needs beyond the selection's inputs: the topology, each end
/// device's decoder (`MstOutput::dsc`), the board's highest DISPCLK and
/// each end device's requested maximum depth (its connector's
/// max_requested_bpc within `amdgpu.max_bpc`,
/// `modeset::connector_max_bpc`).
pub struct MstDscContext<'a> {
    pub topology: &'a Topology,
    pub dsc_of: &'a dyn Fn(dp_mst_mgr::Sink) -> Option<MstDsc>,
    pub max_dispclk_khz: u32,
    pub max_bpc: &'a dyn Fn(dp_mst_mgr::Sink) -> u8,
}

/// The payloads (end device and PBN) of `selected`.
fn allocations(selected: &[Selection]) -> Vec<(dp_mst_mgr::Sink, u16)> {
    selected
        .iter()
        .filter_map(|s| s.mst.map(|m| (m.sink, m.pbn)))
        .collect()
}

/// The MST link as the DSC fairness search sees it.
pub(super) fn dsc_link(caps: modeset::DpCaps, max_dispclk_khz: u32) -> Option<dsc::DscLink> {
    let (lanes, rate) = mst_link(caps);
    let (encoding, kbps) = match rate {
        DpRate::Legacy(r) => (
            crate::amdgpu_dsc::LinkEncoding::Dp8b10b,
            modeset::legacy_kbps(lanes, r, caps.fec),
        ),
        DpRate::Uhbr(r) => (
            crate::amdgpu_dsc::LinkEncoding::Dp128b132b,
            modeset::uhbr_kbps(lanes, r),
        ),
    };
    Some(dsc::DscLink {
        encoding,
        kbps: u32::try_from(kbps).ok()?,
        slots: mst_total_slots(rate),
        max_dispclk_khz,
    })
}

/// The stream's VC rate for `kbps` (its dc_bandwidth_in_kbps_from_timing):
/// a compressed one's compressed bandwidth.
fn mst_vc_rate_dsc(
    timing: &Timing,
    cfg: &crate::amdgpu_dsc::DscConfig,
    lanes: u8,
    rate: DpRate,
    fec: bool,
) -> Option<(u32, u32)> {
    let t = dsc::mst_dsc_timing(timing, cfg.bpc);
    let kbps = crate::amdgpu_dsc::dsc_kbps(&t, cfg.bpp_x16, cfg.slices_h);
    match rate {
        DpRate::Legacy(r) => otg::vc_rate(kbps, modeset::legacy_kbps(lanes, r, fec) as u32),
        DpRate::Uhbr(rate) => {
            let settings = otg::UhbrSettings {
                lanes,
                rate,
                mst: true,
            };
            otg::uhbr_mst_dsc_rate(timing, cfg, settings)
                .map(|(v, _)| (v >> 25, v & ((1 << 25) - 1)))
        }
    }
}

/// The streams an MST link lights once one of its end devices has a DSC
/// decoder, as amdgpu_dm admits them: each device (in topology order, at
/// most `MAX_DISPLAYS`) at the timing `want(k)` asks, else its first EDID
/// timing, at the deepest of its depths (`modeset::dp_depths` up to
/// `ctx.max_bpc(sink)`, create_validate_stream_for_sink's loop) that
/// dm_dp_mst_is_port_support_mode accepts and with which
/// compute_mst_dsc_configs_for_link finds a configuration for every stream
/// so far; a device nothing fits stays dark. Every stream's PBN, slots and
/// DSC are that last search's (it may change earlier streams' bpp); each
/// stream, compressed or not, leaves at its depth. A compressed stream
/// keeps its audio, budgeted at its DSC bits per pixel.
fn select_mst_dsc(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
    budget: &Budget<'_>,
    ctx: &MstDscContext<'_>,
) -> Vec<Selection> {
    let (lanes, rate) = mst_link(caps);
    let Some(link) = dsc_link(caps, ctx.max_dispclk_khz) else {
        return Vec::new();
    };
    let fits = |alloc: &[(dp_mst_mgr::Sink, u16)]| {
        alloc.iter().enumerate().all(|(i, &(sink, pbn))| {
            let others: Vec<_> = alloc
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, &a)| a)
                .collect();
            let available = devices.iter().find(|d| d.0 == sink).map_or(0, |d| d.2);
            pbn <= available.min(budget(sink, &others))
        })
    };
    let mut chosen: Vec<(usize, dsc::DscStream)> = Vec::new();
    let mut payloads = Vec::new();
    for (k, (sink, edid, _)) in devices.iter().enumerate() {
        if chosen.len() == modeset::MAX_DISPLAYS {
            break;
        }
        if edid.len() < 128 {
            continue;
        }
        let decoder = (ctx.dsc_of)(*sink);
        let timings = modeset::edid_timings(edid);
        let wanted = want(k).filter(|w| timings.contains(w));
        let depths = modeset::dp_depths(edid, (ctx.max_bpc)(*sink));
        let found = wanted
            .into_iter()
            .chain(timings.iter().copied())
            .find_map(|t| {
                depths.iter().find_map(|&depth| {
                    let bpc = modeset::depth_bpc(depth);
                    if !dsc::port_supports_mode(
                        &t,
                        bpc,
                        ctx.topology,
                        *sink,
                        decoder.as_ref(),
                        &link,
                    ) {
                        return None;
                    }
                    let mut streams: Vec<_> = chosen.iter().map(|c| c.1).collect();
                    streams.push(dsc::DscStream {
                        sink: *sink,
                        timing: t,
                        dsc: decoder.map(|d| d.caps),
                        bpc,
                    });
                    let p = dsc::compute(&streams, &link, &fits)?;
                    Some((*streams.last()?, p))
                })
            });
        if let Some((stream, p)) = found {
            chosen.push((k, stream));
            payloads = p;
        }
    }
    let mut out = Vec::new();
    for ((k, stream), p) in chosen.iter().zip(&payloads) {
        let (sink, edid, _) = &devices[*k];
        let Some(base) = edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let timing = stream.timing;
        let depth = match stream.bpc {
            12 => otg::ColorDepth::Bpc12,
            10 => otg::ColorDepth::Bpc10,
            _ => otg::ColorDepth::Bpc8,
        };
        let vc = match &p.dsc {
            Some(cfg) => mst_vc_rate_dsc(&timing, cfg, lanes, rate, caps.fec),
            None => mst_vc_rate(&timing, stream.bpc, lanes, rate, caps.fec),
        };
        let Some(vc) = vc else {
            return Vec::new();
        };
        out.push(Selection {
            port,
            timing,
            lanes,
            rate,
            caps,
            edid: base,
            hdmi: false,
            scdc: false,
            depth,
            audio: mst_audio(edid, &timing, stream.bpc, lanes, rate, caps, p.dsc.as_ref()),
            avi: otg::Avi::default(),
            limited: false,
            ycbcr420: false,
            frl: None,
            dsc: p.dsc,
            mst: Some(modeset::MstStream {
                sink: *sink,
                pbn: p.pbn,
                slots: p.slots,
                rate: vc,
                dsc: p.dsc.and((ctx.dsc_of)(*sink)),
            }),
            vrr: None,
            format: otg::SurfaceFormat::Xrgb8888,
            planes: modeset::PlaneSetup::NONE,
            colorspace: 0,
            hdr: None,
            vsc_colorimetry: false,
        });
    }
    out
}

/// LPCM rates an MST stream's blanking carries at `bpc`: on 8b/10b its
/// share of the MTP, on 128b/132b the whole link as for SST. A compressed
/// stream budgets its DSC bits per pixel and slices (build_audio_output's
/// dsc_cfg).
fn mst_audio(
    edid: &[u8],
    timing: &Timing,
    bpc: u8,
    lanes: u8,
    rate: DpRate,
    caps: modeset::DpCaps,
    dsc: Option<&crate::amdgpu_dsc::DscConfig>,
) -> Option<otg::AudioInfo> {
    modeset::sink_audio_info(edid).and_then(|info| match rate {
        DpRate::Legacy(_) => otg::mst_audio_info_with(
            info,
            timing,
            u32::from(bpc),
            otg::DpPhySettings {
                lanes,
                rate: caps.rate,
                mst: true,
            },
            dsc,
        ),
        DpRate::Uhbr(rate) => otg::uhbr_audio_info_with(
            info,
            timing,
            u32::from(bpc),
            otg::UhbrSettings {
                lanes,
                rate,
                mst: true,
            },
            dsc,
        ),
    })
}

fn select_mst_with_budget(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
    budget: &Budget<'_>,
    dsc: Option<&MstDscContext<'_>>,
) -> Vec<Selection> {
    // compute_mst_dsc_configs_for_state recomputes a link only when one of
    // its streams' sinks has a decoder; otherwise each payload keeps
    // drm_dp_calc_pbn_mode's PBN.
    if let Some(ctx) = dsc.filter(|c| devices.iter().any(|d| (c.dsc_of)(d.0).is_some())) {
        return select_mst_dsc(port, caps, devices, want, budget, ctx);
    }
    let (lanes, rate) = mst_link(caps);
    let mut free = mst_total_slots(rate);
    let mut out = Vec::new();
    for (k, (sink, edid, available)) in devices.iter().enumerate() {
        if out.len() == modeset::MAX_DISPLAYS {
            break;
        }
        let Some(base) = edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        let available = (*available).min(budget(*sink, &allocations(&out)));
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
        let Some(vc) = mst_vc_rate(&timing, 8, lanes, rate, caps.fec) else {
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
            audio: mst_audio(edid, &timing, 8, lanes, rate, caps, None),
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
                dsc: None,
            }),
            // VRR is DP SST only here (no MST stream features).
            vrr: None,
            format: otg::SurfaceFormat::Xrgb8888,
            planes: modeset::PlaneSetup::NONE,
            // The connector's Colorspace and HDR metadata (and the root's
            // VSC colorimetry support) are set when the route is planned.
            colorspace: 0,
            hdr: None,
            vsc_colorimetry: false,
        };
        out.push(s);
    }
    out
}

/// An end device's available PBN beside the given allocations.
pub(super) type Budget<'a> = dyn Fn(dp_mst_mgr::Sink, &[(dp_mst_mgr::Sink, u16)]) -> u16 + 'a;

/// Keep a sink's output assignment even when an earlier sink is disabled,
/// has an unreadable EDID, or cannot fit. `pipes[k]` belongs to device k.
/// (The DSC-less form the model tests drive.)
#[cfg(feature = "kernel-test")]
pub(super) fn select_mst_outputs(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
    pipes: &[Option<u8>],
    budget: &Budget<'_>,
) -> Vec<(Selection, u8)> {
    select_mst_outputs_with(port, caps, devices, want, pipes, budget, None)
}

/// `select_mst_outputs` with the link's DSC context (`select_mst_dsc`).
pub(super) fn select_mst_outputs_with(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
    pipes: &[Option<u8>],
    budget: &Budget<'_>,
    dsc: Option<&MstDscContext<'_>>,
) -> Vec<(Selection, u8)> {
    let enabled: Vec<usize> = (0..devices.len())
        .filter(|&k| pipes.get(k).is_some_and(Option::is_some))
        .collect();
    let selected: Vec<_> = enabled.iter().map(|&k| devices[k].clone()).collect();
    select_mst_with_budget(port, caps, &selected, &|k| want(enabled[k]), budget, dsc)
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
/// (The DSC-less form the model tests drive.)
#[cfg(feature = "kernel-test")]
pub(super) fn dark_mst_modes(
    soc: &crate::amdgpu_dcn401_dml::Soc,
    caps: modeset::DpCaps,
    edid: &[u8],
    available: u16,
    lit: &[Selection],
) -> Vec<Timing> {
    dark_mst_modes_with(soc, caps, edid, available, lit, None)
}

/// `dark_mst_modes` for end device `sink` of a link with a DSC context:
/// on such a link amdgpu_dm validates a mode with
/// dm_dp_mst_is_port_support_mode and recomputes every stream's DSC
/// (compute_mst_dsc_configs_for_link) beside the running ones, so a mode
/// that fits only compressed is offered when that search, the device's
/// available PBN and DML admission of the compressed mode allow it.
pub(super) fn dark_mst_modes_with(
    soc: &crate::amdgpu_dcn401_dml::Soc,
    caps: modeset::DpCaps,
    edid: &[u8],
    available: u16,
    lit: &[Selection],
    dsc: Option<(dp_mst_mgr::Sink, &MstDscContext<'_>)>,
) -> Vec<Timing> {
    let compressed = |t: &Timing| -> Option<crate::amdgpu_dcn401_dml::Mode> {
        let (sink, ctx) = dsc?;
        let decoder = (ctx.dsc_of)(sink)?;
        let link = dsc_link(caps, soc.dispclk_max_khz)?;
        let lit_streams: Vec<_> = lit
            .iter()
            .filter_map(|s| {
                let m = s.mst?;
                Some(dsc::DscStream {
                    sink: m.sink,
                    timing: s.timing,
                    dsc: (ctx.dsc_of)(m.sink).map(|d| d.caps),
                    bpc: modeset::depth_bpc(s.depth),
                })
            })
            .collect();
        let fits =
            |alloc: &[(dp_mst_mgr::Sink, u16)]| alloc.last().is_some_and(|a| a.1 <= available);
        // The deepest of the device's depths the port and the link's
        // fairness search take, as for a lit stream (`select_mst_dsc`).
        let payload = modeset::dp_depths(edid, (ctx.max_bpc)(sink))
            .into_iter()
            .find_map(|depth| {
                let bpc = modeset::depth_bpc(depth);
                if !dsc::port_supports_mode(t, bpc, ctx.topology, sink, Some(&decoder), &link) {
                    return None;
                }
                let mut streams = lit_streams.clone();
                streams.push(dsc::DscStream {
                    sink,
                    timing: *t,
                    dsc: Some(decoder.caps),
                    bpc,
                });
                dsc::compute(&streams, &link, &fits)?.last().copied()
            })?;
        Some(crate::amdgpu_dcn401_dml::Mode {
            dsc: payload.dsc.map(|c| crate::amdgpu_dcn401_dml::Dsc {
                slices: c.slices_h,
                bpp_x16: c.bpp_x16,
            }),
            ..modeset::mode(*t)
        })
    };
    // Slots are the MST streams'; DML admission is every running display's.
    let used = lit
        .iter()
        .filter_map(|s| s.mst)
        .try_fold(0u8, |n, m| n.checked_add(m.slots));
    let (lanes, rate) = mst_link(caps);
    let Some(free) = used.and_then(|n| mst_total_slots(rate).checked_sub(n)) else {
        return Vec::new();
    };
    let mut joint: Vec<_> = lit.iter().map(modeset::selection_mode).collect();
    let mut offered = Vec::new();
    for t in modeset::edid_timings(edid) {
        if offered.len() == modeset::MAX_MODES {
            break;
        }
        let candidate = if mst_slots(&t, lanes, rate, caps.fec)
            .is_some_and(|(pbn, slots)| slots <= free && pbn <= available)
        {
            modeset::mode(t)
        } else if let Some(m) = compressed(&t) {
            m
        } else {
            continue;
        };
        joint.push(candidate);
        if crate::amdgpu_dcn401_dml::admit_native(soc, &joint).is_ok() {
            offered.push(t);
        }
        joint.pop();
    }
    offered
}

/// An MST route's planned streams for one configuration.
#[derive(Debug)]
pub(super) struct MstPlan {
    pub port: usize,
    /// The root's link caps; None when the branch has no end device.
    pub caps: Option<modeset::DpCaps>,
    pub devices: Vec<(dp_mst_mgr::Sink, Vec<u8>, u16)>,
    pub selections: Vec<(Selection, u8)>,
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
        fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing> + Sync,
        pipes: &[Option<u8>],
    ) -> Result<Configuration, ModesetError> {
        let route = modeset::MstRoute {
            port,
            pipes,
            want: &want,
        };
        // SAFETY: the caller's obligations.
        unsafe { self.modeset_routed(fill, |_| None, |_| None, Some(route)) }.await
    }
    /// Validate an MST route and start its branch: MST enabled and the
    /// topology probed, before the configuration scans the board.
    pub(super) async fn start_mst_route(
        &mut self,
        route: &modeset::MstRoute<'_>,
    ) -> Result<(), ModesetError> {
        let pipes = route.pipes;
        if pipes.is_empty()
            || pipes.len() > modeset::MAX_DISPLAYS
            || pipes.iter().flatten().any(|&p| p >= 4)
            || pipes
                .iter()
                .enumerate()
                .any(|(k, p)| p.is_some() && pipes[..k].contains(p))
            || self.mst.get(&route.port).is_some_and(|l| l.owner.is_some())
        {
            return Err(ModesetError::Display(otg::Error::Invalid));
        }
        self.start_display_mst(route.port).await?;
        Ok(())
    }
    /// The route's end devices (EDID, available PBN) and the streams
    /// selected for them with their pipes, against the scanned root caps.
    /// Old dark-output admission is discarded before any async startup.
    pub(super) fn plan_mst_route(
        &mut self,
        route: &modeset::MstRoute<'_>,
        ports: &[display::Port],
    ) -> Result<MstPlan, ModesetError> {
        let port = route.port;
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
        if devices.is_empty() {
            return Ok(MstPlan {
                port,
                caps: None,
                devices,
                selections: Vec::new(),
            });
        }
        let path = *self
            .display_paths()
            .map_err(|_| ModesetError::NoSink)?
            .get(port)
            .ok_or(ModesetError::NoSink)?;
        let root = ports
            .iter()
            .find(|p| p.path == path)
            .and_then(|p| p.sink.as_ref().ok());
        let caps = root
            .and_then(|sink| modeset::dp_caps(&path, sink))
            .ok_or(ModesetError::NoSink)?;
        // create_stream_for_sink's use_vsc_sdp_for_colorimetry reads the
        // stream's link (the root branch's DPCD), MST or not.
        let vsc_colorimetry = root.is_some_and(|sink| {
            sink.dpcd.as_ref().is_some_and(|d| {
                crate::amdgpu_hdr::use_vsc_sdp_for_colorimetry(d[0], sink.dprx_feature)
            })
        });
        let assigned: Vec<_> = slots
            .iter()
            .map(|&k| route.pipes.get(k).copied().flatten())
            .collect();
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        let budget = |sink, allocated: &[(dp_mst_mgr::Sink, u16)]| {
            topology::path_budget(&link.topology, sink, allocated).unwrap_or(0)
        };
        let decoders: Vec<_> = link
            .outputs
            .iter()
            .flatten()
            .filter_map(|o| Some((o.sink?, o.dsc?)))
            .collect();
        let dsc_of = |sink| decoders.iter().find(|d| d.0 == sink).map(|d| d.1);
        let max_bpc = |sink| link.max_bpc(port, sink);
        let ctx = MstDscContext {
            topology: &link.topology,
            dsc_of: &dsc_of,
            // As for SST DSC, before the board's levels are read;
            // `refine_dsc` checks the shapes against them.
            max_dispclk_khz: modeset::NOMINAL_DISPCLK_KHZ,
            max_bpc: &max_bpc,
        };
        let mut selections = select_mst_outputs_with(
            port,
            caps,
            &devices,
            &|k| (route.want)(slots[k]),
            &assigned,
            &budget,
            Some(&ctx),
        );
        for (s, _) in selections.iter_mut() {
            s.vsc_colorimetry = vsc_colorimetry;
        }
        if let Some(link) = self.mst.get_mut(&port) {
            for output in link.outputs.iter_mut().flatten() {
                output.modes.clear();
            }
        }
        Ok(MstPlan {
            port,
            caps: Some(caps),
            devices,
            selections,
        })
    }
    /// Admit each dark end device's timings beside every running display.
    pub(super) fn finish_mst_plan(
        &mut self,
        plan: &MstPlan,
        soc: &crate::amdgpu_dcn401_dml::Soc,
        running: &[Selection],
    ) {
        if let Some(caps) = plan.caps {
            self.admit_dark_mst_outputs(plan.port, soc, caps, &plan.devices, running);
        }
    }
    /// An MST display's EDID, from the plan's devices.
    pub(super) fn mst_plan_edid(plan: &MstPlan, s: &Selection) -> Option<Vec<u8>> {
        plan.devices
            .iter()
            .find(|d| Some(d.0) == s.mst.map(|m| m.sink))
            .map(|d| d.1.clone())
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
            let allocated = allocations(lit);
            let decoders: Vec<_> = link
                .outputs
                .iter()
                .flatten()
                .filter_map(|o| Some((o.sink?, o.dsc?)))
                .collect();
            let dsc_of = |sink| decoders.iter().find(|d| d.0 == sink).map(|d| d.1);
            let caps_of: Vec<_> = link
                .outputs
                .iter()
                .flatten()
                .filter_map(|o| Some((o.sink?, link.max_bpc(port, o.sink?))))
                .collect();
            let max_bpc = |sink| {
                caps_of
                    .iter()
                    .find(|c| c.0 == sink)
                    .map_or_else(modeset::max_bpc, |c| c.1)
            };
            let ctx = MstDscContext {
                topology: &link.topology,
                dsc_of: &dsc_of,
                max_dispclk_khz: soc.dispclk_max_khz,
                max_bpc: &max_bpc,
            };
            let mut modes = Vec::new();
            for output in link.outputs.iter().flatten() {
                if lit.iter().any(|s| s.mst.map(|m| m.sink) == output.sink) {
                    modes.push(Vec::new());
                    continue;
                }
                let found = devices.iter().find(|d| Some(d.0) == output.sink);
                modes.push(found.map_or_else(Vec::new, |(sink, edid, _)| {
                    let available =
                        topology::path_budget(&link.topology, *sink, &allocated).unwrap_or(0);
                    dark_mst_modes_with(soc, caps, edid, available, lit, Some((*sink, &ctx)))
                }));
            }
            for (output, m) in link.outputs.iter_mut().flatten().zip(modes) {
                output.modes = m;
            }
        }
    }
    /// Start `selection`'s MST stream on staged `pipe` (stream encoder
    /// `pipe`): the first stream trains the port's MST link at the selected
    /// setting (no fallback: every payload was sized for it), later ones
    /// attach to it; then the frontend, payload, video, scanout and LPCM
    /// audio. On a 128b/132b link the HPO stream is prepared blank in place
    /// of the frontend, and unblanked as its video.
    /// # Safety
    /// As for `start_link`.
    pub(super) async unsafe fn start_mst_stream(
        &mut self,
        port: usize,
        stream: modeset::MstStream,
        selection: &Selection,
        pipe: u8,
    ) -> Result<otg::ScanoutRunning, ModesetError> {
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        link.require_transaction_idle()?;
        let uhbr = matches!(selection.rate, DpRate::Uhbr(_));
        if link.owner.is_some() && link.uhbr != uhbr {
            return Err(ModesetError::Link);
        }
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            if link.owner.is_none() {
                self.train_mst_link(port, selection, pipe).await?;
                if let Some(link) = self.mst.get_mut(&port) {
                    link.owner = Some(pipe);
                    link.uhbr = uhbr;
                }
            } else {
                self.attach_display_mst_link(port)?;
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Link);
            if uhbr {
                self.prepare_display_uhbr_mst_stream(
                    port,
                    pipe,
                    pipe,
                    stream.slots,
                    selection.uhbr_sdp(),
                )
                .await?;
            } else {
                // The stream's VSC/HDR SDPs, as for SST (enc401's
                // update_dp_info_packets serves DIO MST streams too).
                self.prepare_display_dp_frontend(
                    port,
                    otg::DpFrontendRequest {
                        vsc_colorimetry: selection.vsc_colorimetry,
                        hdr: selection.hdr_packet(),
                        ..otg::DpFrontendRequest::new(pipe, pipe)
                    },
                )
                .await?;
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Frontend);
            // A compressed stream's decoder after enable_stream and before
            // its payload (dp_set_dsc_on_rx); the PPS follows with the
            // video, after the payload.
            if let Some(d) = stream.dsc {
                self.set_display_mst_dsc(port, &d, true).await?;
            }
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
            if uhbr {
                self.start_display_uhbr_mst_video(port).await?;
            } else {
                self.start_display_dp_video(port).await?;
            }
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Video);
            let scanout = self.start_display_scanout(pipe).await?;
            self.teardowns
                .checkpoint_activation(pipe, super::TeardownStep::Scanout);
            if let Some(info) = selection.audio {
                self.start_display_audio(port, false, info).await?;
            }
            Ok(scanout)
        }
    }
    /// Train the port's MST link at `selection`'s setting for the selected
    /// display: 8b/10b on the DIO, 128b/132b on HPO link encoder `pipe`
    /// (the display's own, as for SST). A refused link is stopped again.
    /// # Safety
    /// As for `start_link`.
    async unsafe fn train_mst_link(
        &mut self,
        port: usize,
        selection: &Selection,
        pipe: u8,
    ) -> Result<(), ModesetError> {
        let lanes = selection.lanes;
        // SAFETY: the caller's obligations.
        unsafe {
            match selection.rate {
                DpRate::Legacy(rate) => {
                    let settings = otg::DpPhySettings {
                        lanes,
                        rate,
                        mst: true,
                    };
                    self.enable_display_dp_phy(port, settings).await?;
                    if let Err(e) = self.train_display_dp_link(port, false).await {
                        let _ = self.stop_display_dp_link(port).await;
                        return Err(e.into());
                    }
                }
                DpRate::Uhbr(rate) => {
                    let settings = otg::UhbrSettings {
                        lanes,
                        rate,
                        mst: true,
                    };
                    let transmitter = self.dp_phy_path(port)?.transmitter;
                    if let Err(e) = self.train_display_uhbr_link(port, settings, pipe).await {
                        if self
                            .display_timing_status()
                            .is_ok_and(|s| s.state == otg::State::UhbrLinkRefused(transmitter))
                        {
                            self.stop_display_uhbr_link(port, false).await?;
                        }
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(())
    }
    /// Finish teardown after video, payload and frontend (or HPO stream)
    /// have stopped:
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
            let uhbr = self.mst.get(&port).is_some_and(|l| l.uhbr);
            if uhbr {
                self.stop_display_uhbr_link(port, unplugged).await?;
            } else if unplugged {
                self.stop_unplugged_display_dp_link(port).await?;
            } else {
                self.stop_display_dp_link(port).await?;
            }
        }
        if let Some(link) = self.mst.get_mut(&port) {
            link.owner = None;
            link.uhbr = false;
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
