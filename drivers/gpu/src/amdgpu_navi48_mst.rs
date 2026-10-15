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

/// A port running MST: its manager, topology and payloads.
#[derive(Debug, Default)]
pub struct MstLink {
    /// The pipe whose display trained the link, while one runs.
    pub owner: Option<u8>,
    pub manager: Manager,
    pub topology: Topology,
    pub payloads: Vec<MstPayload>,
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
    let info = link.topology.port(sink).ok_or(MstFailure::Invalid)?.info;
    let branch = link.topology.branches[sink.branch].clone();
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
) -> Result<(), MstFailure<A::Error>> {
    let index = link
        .payloads
        .iter()
        .position(|p| p.stream == stream)
        .ok_or(MstFailure::Invalid)?;
    let payload = link.payloads[index];
    source.vc_rate(stream, (0, 0)).await?;
    if let (Some(branch), Some(port)) = (
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
    let _ = dp_mst_mgr::write_payload(aux, payload.vcpi, payload.start, 0).await;
    link.payloads.remove(index);
    source.allocation(&table(&link.payloads)).await?;
    let _ = act_handled(aux).await;
    for p in link.payloads.iter_mut().filter(|p| p.start > payload.start) {
        p.start -= payload.slots;
    }
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
    /// drm_dp_mst_topology_mgr_set_mst(true) on the port, then the probe.
    pub async fn start_display_mst(&mut self, port: usize) -> Result<Topology, MstFailure> {
        let (instance, _) = self.mst_path(port)?;
        let mut link = self.mst.remove(&port).unwrap_or_default();
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        let result = async {
            let mut dpcd = [0u8; 16];
            aux.read(0, &mut dpcd).await.map_err(MstError::Aux)?;
            link.manager.start(&mut aux, &dpcd).await?;
            link.topology = link.manager.probe(&mut aux).await?;
            link.payloads.clear();
            Ok::<_, MstFailure>(link.topology.clone())
        }
        .await;
        self.mst.insert(port, link);
        result
    }
    pub fn display_mst(&self, port: usize) -> Option<&MstLink> {
        self.mst.get(&port)
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
        let mut aux = DmubAux {
            dmub: &mut self.sequence.backend.dmub,
            instance,
        };
        let first = link
            .manager
            .read_edid_block(&mut aux, &link.topology, sink, 0)
            .await?;
        let mut edid = first.to_vec();
        for block in 1..=first[126] {
            let b = link
                .manager
                .read_edid_block(&mut aux, &link.topology, sink, block)
                .await?;
            edid.extend_from_slice(&b);
        }
        Ok(edid)
    }
    /// Add DIO stream `stream`'s payload for `sink` (`add_payload`).
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
    /// # Safety
    /// The selected display's video on `stream` is stopped.
    pub async unsafe fn remove_display_mst_payload(
        &mut self,
        port: usize,
        stream: u8,
    ) -> Result<(), MstFailure> {
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
        remove_payload(link, &mut aux, &mut source, stream).await
    }
    /// drm_dp_mst_topology_mgr_set_mst(false), the port's MST state dropped.
    pub async fn stop_display_mst(&mut self, port: usize) {
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
/// each end device, its EDID and available PBN.
pub fn select_mst(
    port: usize,
    caps: modeset::DpCaps,
    devices: &[(dp_mst_mgr::Sink, Vec<u8>, u16)],
    want: &dyn Fn(usize) -> Option<Timing>,
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
        let fits = |t: &Timing| {
            mst_slots(t, lanes, rate, caps.fec)
                .filter(|&(pbn, slots)| slots <= free && (*available == 0 || pbn <= *available))
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

impl ColdBoot {
    /// Light the end devices behind DP `port`'s MST branch (`select_mst`),
    /// display k on `pipes[k]` (its display slot too), as one
    /// configuration like `modeset_displays`: MST started and the topology
    /// probed, each device's EDID read, the admitted streams' clocks
    /// programmed, then each stream lit: the first trains the port's MST
    /// link, the others attach to it, and each adds its payload before its
    /// video starts. `want(k)` is the timing asked of device k.
    /// # Safety
    /// As for `modeset_displays`.
    pub async unsafe fn modeset_mst_displays(
        &mut self,
        port: usize,
        mut fill: impl FnMut(u8, u32, &mut [u32]),
        want: impl Fn(usize) -> Option<Timing>,
        pipes: &[u8],
    ) -> Result<Configuration, ModesetError> {
        if pipes.is_empty()
            || pipes.iter().any(|&p| p >= 4)
            || self.mst.get(&port).is_some_and(|l| l.owner.is_some())
        {
            return Err(ModesetError::Display(otg::Error::Invalid));
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
        let topology = self.start_display_mst(port).await?;
        let mut devices = Vec::new();
        for sink in topology.sinks().into_iter().take(pipes.len()) {
            let available = topology.port(sink).map_or(0, |p| p.available_pbn);
            // A device whose EDID can't be read stays dark.
            if let Ok(edid) = self.read_display_mst_edid(port, sink).await {
                devices.push((sink, edid, available));
            }
        }
        let mut selections = select_mst(port, caps, &devices, &want);
        if selections.is_empty() {
            self.stop_display_mst(port).await;
            return Err(ModesetError::NoSink);
        }
        let limited = modeset::limited_range(modeset::broadcast_rgb());
        for s in &mut selections {
            s.limited = limited;
        }
        let pipes = &pipes[..selections.len()];
        self.select_display(pipes[0])?;
        let soc = self.prepare_configuration(&selections).await?;
        let plans = modeset::admit_displays(&soc, &selections).map_err(otg::Error::Admission)?;
        selections.truncate(plans.len());
        self.prepare_pipes(&selections, &plans, pipes).await?;
        let mut lit = Vec::with_capacity(selections.len());
        let mut failed = None;
        for ((selection, plan), &pipe) in selections.iter().zip(&plans).zip(pipes) {
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
        Ok(Configuration {
            displays: lit,
            failed,
        })
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
            self.prepare_display_dp_frontend(port, otg::DpFrontendRequest { stream: pipe, pipe })
                .await?;
            self.add_display_mst_payload(
                port,
                stream.sink,
                pipe,
                stream.pbn,
                stream.slots,
                stream.rate,
            )
            .await?;
            self.start_display_dp_video(port).await?;
            Ok(self.start_display_scanout(pipe).await?)
        }
    }
    /// Whether pipe `pipe`'s MST stream on `port` may stop now: the
    /// display that trained the link stops last.
    pub(super) fn mst_stop_allowed(&self, port: usize, pipe: u8) -> Result<(), ModesetError> {
        let link = self.mst.get(&port).ok_or(MstFailure::Invalid)?;
        if link.owner == Some(pipe) && link.payloads.iter().any(|p| p.stream != pipe) {
            return Err(ModesetError::Display(otg::Error::Busy));
        }
        Ok(())
    }
    /// deallocate_mst_payload's teardown of pipe `pipe`'s stream, its
    /// scanout stopped: video, the payload, the frontend; then the link's
    /// owner stops the link (without addressing an `unplugged` sink) and
    /// MST, while an attached display detaches.
    /// # Safety
    /// As for `stop_modeset`.
    pub(super) async unsafe fn stop_mst_stream(
        &mut self,
        port: usize,
        pipe: u8,
        unplugged: bool,
    ) -> Result<(), ModesetError> {
        self.mst_stop_allowed(port, pipe)?;
        let owner = self.mst.get(&port).is_some_and(|l| l.owner == Some(pipe));
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            self.stop_display_dp_video(port).await?;
            self.remove_display_mst_payload(port, pipe).await?;
            self.stop_display_dp_frontend(port).await?;
            if !owner {
                return Ok(self.detach_display_mst_link(port)?);
            }
            if unplugged {
                self.stop_unplugged_display_dp_link(port).await?;
            } else {
                self.stop_display_dp_link(port).await?;
            }
        }
        self.stop_display_mst(port).await;
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_mst_tests.rs"]
mod tests;
