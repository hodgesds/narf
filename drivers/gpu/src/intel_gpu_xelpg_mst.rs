//! Display-14 MST ownership over the shared sideband manager. The first
//! stream owns the link/transport; secondary streams own only their pipe.
//! A topology change rebuilds the stream set in reverse stop order, keeping
//! the primary transport alive until the last secondary has stopped.
//!
//! Under `narf.intel.uhbr=1` a hub whose best common configuration is UHBR
//! runs 128b/132b MST (`intel_dp_mst.c` over a UHBR link,
//! [`super::UhbrMstLink`]): the 64 MTP slots from slot 0 with
//! `drm_dp_get_vc_payload_bw`'s divider and each stream's remote TU
//! ([`super::uhbr::mst_stream`]); the primary trains the link at 128b/132b
//! with no SST payload; every stream sets `TRANS_DP2_CTL`, the VFREQ pair and
//! `TRANS_DDI_FUNC_CTL` in 128b/132b mode on the master's MST transport (a
//! secondary configures it before its enable,
//! `intel_ddi_config_transcoder_func`); and each stream's payload follows
//! `mst_stream_pre_enable` / `mst_stream_enable`: the DPCD payload table
//! (`drm_dp_add_payload_part1`), the function, the ACT, the sink's ACT
//! handled, then ALLOCATE_PAYLOAD (`drm_dp_add_payload_part2`). Through a
//! DP tunnel (display-30+ Thunderbolt alt mode) each stream's
//! `intel_dp_config_required_rate` is checked beside the live streams'
//! ([`tunnel_stream`]) and the tunnel's allocation is their sum before each
//! enable and after each stop. A failed 128b/132b training of the link
//! retries every stream once at the BW-order reduction ([`mst_fallback`]).
//! The 8b/10b MST route is unchanged.
use super::*;
use crate::dp_mst_mgr::{Manager, MstAux, Sink, Topology};
use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MstFailure {
    Sideband,
    Act,
    Bandwidth,
    NoSinks,
    Quarantined,
}

/// The display AUX adapter completes every operation synchronously,
/// including its bounded register delays. Poll the protocol future once;
/// it must never depend on another executor task. This is valid inside the
/// display actor's poll and does not re-enter the executor via block_on.
fn complete<T, E>(future: impl Future<Output = Result<T, E>>) -> Result<T, ExternalError> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(value)) => Ok(value),
        _ => Err(ExternalError::Mst(MstFailure::Sideband)),
    }
}

/// Clear stale ACT, toggle this stream's payload bit, and require a new
/// local ACT. DP_TP_STATUS is W1C; the primary transport sends every ACT.
pub(super) fn source_payload<M: MmioWindow + ?Sized>(
    io: &M,
    trans: Transcoder,
    master: Transcoder,
    on: bool,
) -> Result<(), ExternalError> {
    let status = dp_tp_ctl(master) + 4;
    write(io, status, 1 << 24)?;
    let func = read(io, trans_ddi_func_ctl(trans))?;
    write(
        io,
        trans_ddi_func_ctl(trans),
        (func & !(1 << 8)) | if on { 1 << 8 } else { 0 },
    )?;
    if !wait_bit(io, status, 1 << 24, true, 1_000_000) {
        return Err(ExternalError::Mst(MstFailure::Act));
    }
    Ok(())
}

fn sink_act<A: MstAux>(aux: &mut A) -> Result<(), ExternalError> {
    // drm_dp_dpcd_poll_act_handled: a bounded wait for the branch to
    // apply the table before ALLOCATE_PAYLOAD part 2 and stream enable.
    for _ in 0..3000 {
        let mut status = [0];
        complete(aux.read(0x2C0, &mut status))?;
        if status[0] & 2 != 0 {
            return Ok(());
        }
        complete(async {
            aux.delay(1000).await;
            Ok::<(), ()>(())
        })?;
    }
    Err(ExternalError::Mst(MstFailure::Act))
}

#[derive(Debug)]
struct Stream {
    sink: Sink,
    vcpi: u8,
    slot: u8,
    route: MtlExternalRoute,
    /// The stream's bandwidth in the link's DP tunnel
    /// (`drm_dp_tunnel_atomic_set_stream_bw`), 0 without one.
    tunnel_bw: u32,
}

#[derive(Debug)]
pub struct MtlMstRoute {
    link: LinkProbe,
    manager: Manager,
    topology: Option<Topology>,
    streams: Vec<Stream>,
    failed: Option<MtlExternalRoute>,
    first: Option<(Pipe, Mode, Framebuffer)>,
    stopped: bool,
    /// The sibling route's Pipe B–D owner (`narf.intel.ext_routes=2`) the
    /// first stream plans beside, until it has.
    beside: Option<Pipes>,
    /// The Pipe B–D owner the last stopped stream left, until a sibling
    /// route adopts it ([`Self::take_shared_pipes`]).
    retired: Option<Pipes>,
    /// The DP tunnel with BW allocation enabled a 128b/132b link runs
    /// through (display-30+ Thunderbolt alt mode), until it is handed back.
    tunnel: Option<tunnel::Tunnel>,
    /// `narf.intel.hdmi14_ext=1`: each stream reads its sink's whole EDID
    /// and takes audio (`mst_stream_compute_config`'s
    /// `intel_dp_audio_compute_config`).
    audio: bool,
}

impl MtlMstRoute {
    pub fn port(&self) -> XeLpgPort {
        self.link.port
    }
    pub fn first(&self) -> Option<(Pipe, Mode, Framebuffer)> {
        self.first
    }
    /// The DP tunnel with BW allocation this route's 128b/132b link runs
    /// through, if any (the second route's group check,
    /// `mst_tunnel_group_admits`).
    pub(crate) fn bw_tunnel(&self) -> Option<tunnel::Tunnel> {
        self.tunnel.filter(|t| t.bw_alloc_enabled)
    }
    pub fn live(&self) -> bool {
        !self.stopped && !self.streams.is_empty() && self.failed.is_none()
    }
    pub fn stopped(&self) -> bool {
        self.stopped
    }
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
    /// HDCP (`crate::intel_hdcp_live`): the primary branch's AUX (its
    /// base and Thunderbolt mode) and the live streams as (CPU transcoder,
    /// VCPI), the master's first.
    pub(crate) fn hdcp_streams(&self) -> (u64, bool, Vec<(u8, u8)>) {
        (
            self.link.port.aux_base(),
            self.link.tbt(),
            self.streams
                .iter()
                .map(|s| (s.route.pipe().transcoder() as u8, s.vcpi))
                .collect(),
        )
    }
    /// The primary branch's AUX, for HDCP (its DPCD and the short pulse's
    /// CP_IRQ in ESI0).
    pub(crate) fn link_aux<'a, M: MmioWindow + ?Sized>(&self, io: &'a M) -> IntelAux<'a, M> {
        self.link.aux(io)
    }

    /// The Pipe B–D owner a sibling route plans beside: the newest one this
    /// route holds (a failed stream's reservation, else the last stream's;
    /// every live stream holds the same owner).
    pub(super) fn shared_pipes(&self) -> Option<&Pipes> {
        self.failed
            .as_ref()
            .and_then(MtlExternalRoute::shared_pipes)
            .or_else(|| self.streams.last().and_then(|s| s.route.shared_pipes()))
    }

    /// Every reserved stream adopts a sibling route's newer owner.
    pub(super) fn adopt_shared_pipes(&mut self, pipes: &Pipes) {
        for stream in &mut self.streams {
            stream.route.adopt_shared_pipes(pipes);
        }
        if let Some(failed) = self.failed.as_mut() {
            failed.adopt_shared_pipes(pipes);
        }
    }

    /// The owner a sibling adopts after this route changed it: the held
    /// one, or once every stream stopped the owner the last stop left.
    pub(super) fn take_shared_pipes(&mut self) -> Option<Pipes> {
        if let Some(pipes) = self.shared_pipes() {
            return Some(pipes.clone());
        }
        self.failed
            .as_mut()
            .and_then(MtlExternalRoute::take_shared_pipes)
            .or_else(|| self.retired.take())
    }

    /// `beside` is a live sibling route's Pipe B–D owner
    /// (`narf.intel.ext_routes=2`): the first stream joins that layout, as
    /// Linux's atomic check plans the MST CRTCs against every CRTC already
    /// active (`intel_atomic_check`); the streams after it plan from the
    /// stream before, as without a sibling.
    pub(super) fn connect<M: MmioWindow + ?Sized>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        uhbr: Option<UhbrMstLink>,
        beside: Option<Pipes>,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        let mut aux = crate::intel_gpu_mst::IntelMstAux::xelpdp(io, link.port, link.tbt());
        Self::connect_aux_beside(io, link, decl, display, alloc, &mut aux, uhbr, beside)
    }

    #[cfg(feature = "kernel-test")]
    fn connect_aux<M: MmioWindow + ?Sized, A: MstAux>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        Self::connect_aux_with(io, link, decl, display, alloc, aux, None)
    }

    #[cfg(feature = "kernel-test")]
    fn connect_aux_with<M: MmioWindow + ?Sized, A: MstAux>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
        uhbr: Option<UhbrMstLink>,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        Self::connect_aux_beside(io, link, decl, display, alloc, aux, uhbr, None)
    }

    /// [`Self::connect`] over `aux`, the first stream beside `beside`; the
    /// streams take audio under `narf.intel.hdmi14_ext=1`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn connect_aux_beside<M: MmioWindow + ?Sized, A: MstAux>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
        uhbr: Option<UhbrMstLink>,
        beside: Option<Pipes>,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        let audio = super::color::opted_in();
        Self::connect_owner(io, link, decl, display, alloc, aux, uhbr, beside, audio)
    }

    /// [`Self::connect_aux`] with the streams' audio on
    /// (`narf.intel.hdmi14_ext=1`).
    #[cfg(feature = "kernel-test")]
    fn connect_aux_audio<M: MmioWindow + ?Sized, A: MstAux>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        Self::connect_owner(io, link, decl, display, alloc, aux, None, None, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_owner<M: MmioWindow + ?Sized, A: MstAux>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
        uhbr: Option<UhbrMstLink>,
        beside: Option<Pipes>,
        audio: bool,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        let mut owner = Box::new(Self {
            link,
            manager: Manager::new(),
            topology: None,
            streams: Vec::new(),
            failed: None,
            first: None,
            stopped: false,
            beside,
            retired: None,
            tunnel: uhbr.and_then(|u| u.tunnel),
            audio,
        });
        let result = owner.start(io, decl, display, alloc, aux, uhbr);
        match result {
            Ok(()) => Ok(owner),
            Err(error) => Err((owner, error)),
        }
    }

    fn start<M: MmioWindow + ?Sized, A: MstAux>(
        &mut self,
        io: &M,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
        uhbr: Option<UhbrMstLink>,
    ) -> Result<(), ExternalError> {
        complete(self.manager.start(aux, &self.link.raw))?;
        let topology = complete(self.manager.probe(aux))?;
        let mut ledger: Vec<(Sink, u16)> = Vec::new();
        for (branch, entry) in topology.branches.iter().enumerate() {
            for port in &entry.ports {
                if !port.info.input && port.info.ddps {
                    ledger.push((
                        Sink {
                            branch,
                            port: port.info.port,
                        },
                        port.available_pbn,
                    ));
                }
            }
        }
        let sinks = topology.sinks();
        self.topology = Some(topology);
        let first = self.streams_at(io, &decl, display, alloc, aux, uhbr, None, &sinks, &ledger);
        // intel_dp_start_link_train's failure on the link's first stream:
        // intel_dp_get_link_train_fallback_values in the MST (BW) order and
        // the modeset retry of every stream on the link, once, from the
        // proven stop (no stream was enabled, no payload allocated).
        match (first, uhbr) {
            (Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Training(f))), Some(u))
                if self.streams.is_empty()
                    && self
                        .failed
                        .as_ref()
                        .is_some_and(|r| r.state == RouteState::Stopped) =>
            {
                let Some(next) = mst_fallback(&u) else {
                    return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Training(f)));
                };
                self.failed = None;
                let (uhbr, forced) = match next {
                    MstRetry::Uhbr(u) => (Some(u), None),
                    MstRetry::EightTenB(rate, lanes) => {
                        // The 8b/10b MST link does not speak BW allocation.
                        tunnel_off(io, self.link, &mut self.tunnel);
                        (None, Some((rate, lanes)))
                    }
                };
                self.streams_at(
                    io, &decl, display, alloc, aux, uhbr, forced, &sinks, &ledger,
                )
            }
            (result, _) => result,
        }
    }

    /// The stream loop of [`Self::start`] on one link: the 128b/132b link
    /// `uhbr`, else 8b/10b at the source/sink maximum or at `forced` (an
    /// MST retry's reduced configuration). `ledger` is each output port's
    /// available PBN before any stream.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn streams_at<M: MmioWindow + ?Sized, A: MstAux>(
        &mut self,
        io: &M,
        decl: &MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
        uhbr: Option<UhbrMstLink>,
        forced: Option<(TrainRate, u8)>,
        sinks: &[Sink],
        ledger: &[(Sink, u16)],
    ) -> Result<(), ExternalError> {
        let mut ledger = ledger.to_vec();
        let caps = DpcdCaps::decode(&self.link.raw);
        let source = SourceCaps {
            max_rate: TrainRate::Hbr3,
            max_lanes: self.link.tc.map_or(4, |tc| tc.max_lanes),
        };
        let mut negotiated = negotiate(&source, &caps, u64::MAX);
        if let Some((rate, lanes)) = forced {
            negotiated.rate = rate;
            negotiated.lanes = lanes;
            negotiated.payload_kbps = rate.payload_kbps(lanes);
        }
        let link_kbps = negotiated.rate.payload_kbps(negotiated.lanes) as u32;
        if let Some(u) = uhbr {
            negotiated.lanes = u.lanes;
        }
        // drm_dp_mst_update_slots: 8b/10b keeps slot 0 for the MTP header.
        let mut slot = if uhbr.is_some() {
            uhbr::MST_START_SLOT
        } else {
            1u8
        };
        for &sink in sinks {
            let topology = self.topology.as_ref().expect("probed");
            let edid = complete(self.manager.read_edid_block(aux, topology, sink, 0))?;
            let mode = crate::intel_gpu_dp::mode_from_edid(&edid)
                .map_err(|_| ExternalError::Mst(MstFailure::Sideband))?;
            // 128b/132b: mst_stream_compute_link_config at the link's rate.
            let stream = uhbr.and_then(|u| uhbr_stream(&u, &mode));
            if uhbr.is_some() && stream.is_none() {
                continue;
            }
            // Through a DP tunnel: the stream's bandwidth beside the live
            // streams' must pass the tunnel's check ([`tunnel_stream`]).
            let live_bw: u32 = self.streams.iter().map(|s| s.tunnel_bw).sum();
            let (stream, tunnel_bw) = match (uhbr, self.tunnel) {
                (Some(u), Some(t)) => match tunnel_stream(&t, &u, &mode, live_bw) {
                    Some((s, bw)) => (Some(s), bw),
                    None => continue,
                },
                _ => (stream, 0),
            };
            let (pbn, slots) = match &stream {
                Some(s) => (s.pbn, u32::from(s.slots)),
                None => {
                    // intel_dp_compute_config_limits: MST streams stop at
                    // 8 bpc (deep colour is not taken over MST).
                    let pbn = crate::dp_mst::calc_pbn_mode(
                        mode.pixel_clock_khz,
                        super::color::MST_MAX_PIPE_BPP * 16,
                    );
                    (
                        pbn,
                        crate::dp_mst::time_slots(pbn, crate::dp_mst::pbn_div(link_kbps)),
                    )
                }
            };
            let path = topology
                .path(sink)
                .ok_or(ExternalError::Mst(MstFailure::Sideband))?;
            if slots == 0
                || (uhbr.is_none() && slots > 63)
                || u32::from(slot) + slots > 64
                || path.iter().any(|hop| {
                    ledger
                        .iter()
                        .find(|(key, _)| key == hop)
                        .is_none_or(|(_, available)| pbn > u32::from(*available))
                })
            {
                // Local admission leaves all already-running streams alone.
                continue;
            }
            let pipe = match free_pipe(io, ExternalDisplayProfile::for_ip(self.link.display_ip)) {
                Ok(pipe) => pipe,
                Err(ExternalError::NoFreePipe) => break,
                Err(error) => return Err(error),
            };
            let vcpi = pipe as u8 + 1; // Intel's payload ID is pipe + 1.
            let fb =
                alloc(&mode).ok_or(ExternalError::Modeset(ModesetError::InvalidFramebuffer))?;
            let master = self
                .streams
                .first()
                .map_or(pipe.transcoder(), |s| s.route.pipe.transcoder());
            let mut probe = MtlSinkProbe {
                display_ip: self.link.display_ip,
                mst: Some(MstStreamConfig {
                    master,
                    slots: slots as u8,
                }),
                lane_reversal: decl.lane_reversal,
                port: self.link.port,
                tc: self.link.tc,
                caps,
                mode,
                negotiated,
                max_downspread: self.link.raw[DP_MAX_DOWNSPREAD],
                ssc: false,
                edid: Box::new([0; EDID_CAPACITY]),
                edid_len: 128,
                dsc: None,
                pipe_bpp: stream
                    .as_ref()
                    .map_or(super::color::MST_MAX_PIPE_BPP, |s| s.pipe_bpp),
                uhbr: uhbr.zip(stream.as_ref()).map(|(u, s)| uhbr_plan(&u, s)),
                output: super::color::DpOutput::default(),
                audio: None,
                c20_uhbr_vspeo: decl.c20_uhbr_vspeo.filter(|_| uhbr.is_some()).map(Box::new),
                dp14_vspeo: decl.dp14_vspeo,
                // The 8b/10b MST link trains end to end.
                lttpr_per_hop: false,
            };
            // Copy the EDID straight into the probe's own buffer: a
            // separate 512-byte staging array is a second stack slot in
            // this frame, and `connect` is 120 bytes over the 8 KiB
            // budget (CI run 43627487921).
            probe.edid[..128].copy_from_slice(&edid);
            if self.audio {
                stream_audio(&mut self.manager, aux, topology, sink, &mut probe)?;
            }
            crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &mode)?;
            let branch = topology.branches[sink.branch].clone();
            let sdp_streams = topology
                .port(sink)
                .ok_or(ExternalError::Mst(MstFailure::Sideband))?
                .info
                .sdp_streams;
            // 8b/10b: the DPCD payload table now; 128b/132b: at the
            // stream's activation (drm_dp_add_payload_part1 follows the
            // primary's training).
            if uhbr.is_none() {
                complete(crate::dp_mst_mgr::write_payload(
                    aux,
                    vcpi,
                    slot,
                    slots as u8,
                ))?;
            }
            // intel_dp_tunnel_atomic_alloc_bw before the stream's enable: the
            // tunnel's allocation becomes the streams' sum.
            if tunnel_bw != 0 {
                tunnel_alloc(io, self.link, &mut self.tunnel, live_bw + tunnel_bw)?;
            }
            let start_slot = slot;
            let mut allocate = |_: Transcoder, step: PayloadStep| {
                if step == PayloadStep::Part1 {
                    if uhbr.is_some() {
                        complete(crate::dp_mst_mgr::write_payload(
                            aux,
                            vcpi,
                            start_slot,
                            slots as u8,
                        ))?;
                    }
                    return Ok(());
                }
                sink_act(aux)?;
                let request = crate::dp_mst::Request::AllocatePayload {
                    port: sink.port,
                    vcpi,
                    pbn: pbn as u16,
                    sdp_stream_sinks: (0..sdp_streams).collect(),
                };
                match complete(
                    self.manager
                        .transact(aux, branch.lct, &branch.rad, &request),
                )? {
                    crate::dp_mst::Reply::AllocatePayload {
                        port, pbn: grant, ..
                    } if port == sink.port && u32::from(grant) == pbn => Ok(()),
                    _ => Err(ExternalError::Mst(MstFailure::Bandwidth)),
                }
            };
            let result = match self.streams.last() {
                None => {
                    activate_with_payload(io, probe, fb, display, self.beside.take(), &mut allocate)
                }
                Some(previous) => activate_secondary(
                    io,
                    probe,
                    fb,
                    display,
                    previous
                        .route
                        .reservation
                        .as_ref()
                        .expect("live")
                        .pipes
                        .clone(),
                    &mut allocate,
                ),
            };
            let route = match result {
                Ok(route) => route,
                Err(ActivateError::Refused(_, error)) => return Err(error),
                Err(ActivateError::Failed(route, error)) => {
                    self.failed = Some(route);
                    return Err(error);
                }
            };
            if self.first.is_none() {
                self.first = Some((route.pipe(), mode, fb));
            }
            let pipes = route.reservation.as_ref().expect("live").pipes.clone();
            for stream in &mut self.streams {
                stream.route.reservation.as_mut().expect("live").pipes = pipes.clone();
            }
            for hop in path {
                if let Some((_, available)) = ledger.iter_mut().find(|(key, _)| *key == hop) {
                    *available -= pbn as u16;
                }
            }
            self.streams.push(Stream {
                sink,
                vcpi,
                slot,
                route,
                tunnel_bw,
            });
            slot += slots as u8;
        }
        if self.streams.is_empty() {
            return Err(ExternalError::Mst(MstFailure::NoSinks));
        }
        Ok(())
    }

    pub fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), ExternalError> {
        let mut aux =
            crate::intel_gpu_mst::IntelMstAux::xelpdp(io, self.link.port, self.link.tbt());
        self.stop_aux(io, &mut aux)
    }

    pub(super) fn stop_aux<M: MmioWindow + ?Sized, A: MstAux>(
        &mut self,
        io: &M,
        aux: &mut A,
    ) -> Result<(), ExternalError> {
        if self.stopped {
            return Ok(());
        }
        if let Some(mut failed) = self.failed.take() {
            if let Err(error) = stop_stream(io, &mut failed, !self.streams.is_empty()) {
                self.failed = Some(failed);
                return Err(error);
            }
            if let Some(rp) = failed.reservation.as_ref() {
                for stream in &mut self.streams {
                    if let Some(own) = stream.route.reservation.as_mut() {
                        own.pipes = rp.pipes.clone();
                    }
                }
            }
            // A sibling route plans from what the stop left.
            if let Some(pipes) = failed.take_shared_pipes() {
                self.retired = Some(pipes);
            }
        }
        while !self.streams.is_empty() {
            let index = self.streams.len() - 1;
            let stream = &mut self.streams[index];
            let master = stream.route.probe.mst.expect("MST stream").master;
            source_payload(io, stream.route.pipe.transcoder(), master, false)?;
            stop_stream(io, &mut stream.route, index != 0)?;
            let pipes = stream.route.reservation.as_ref().map(|rp| rp.pipes.clone());
            let mut stream = self.streams.pop().expect("selected");
            if let Some(left) = stream.route.take_shared_pipes() {
                self.retired = Some(left);
            }
            if let Some(topology) = &self.topology {
                if let Some(branch) = topology.branches.get(stream.sink.branch) {
                    let request = crate::dp_mst::Request::AllocatePayload {
                        port: stream.sink.port,
                        vcpi: stream.vcpi,
                        pbn: 0,
                        sdp_stream_sinks: Vec::new(),
                    };
                    let _ = complete(
                        self.manager
                            .transact(aux, branch.lct, &branch.rad, &request),
                    );
                }
            }
            let _ = complete(crate::dp_mst_mgr::write_payload(
                aux,
                stream.vcpi,
                stream.slot,
                0,
            ));
            // atomic_decrease_bw after the stream's disable (best effort).
            if stream.tunnel_bw != 0 {
                let remaining: u32 = self.streams.iter().map(|s| s.tunnel_bw).sum();
                let _ = tunnel_alloc(io, self.link, &mut self.tunnel, remaining);
            }
            if let Some(pipes) = pipes {
                for remaining in &mut self.streams {
                    if let Some(rp) = remaining.route.reservation.as_mut() {
                        rp.pipes = pipes.clone();
                    }
                }
            }
        }
        complete(async {
            self.manager.stop(aux).await;
            Ok::<(), ()>(())
        })?;
        tunnel_off(io, self.link, &mut self.tunnel);
        self.stopped = true;
        Ok(())
    }

    pub fn release<M: MmioWindow + ?Sized>(
        self: Box<Self>,
        io: &M,
    ) -> Result<(), (Box<Self>, ExternalError)> {
        if !self.stopped {
            return Err((self, ExternalError::Mst(MstFailure::Quarantined)));
        }
        self.link.release(io).map_err(|error| (self, error))
    }

    pub fn unchanged<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<bool, ExternalError> {
        let mut aux =
            crate::intel_gpu_mst::IntelMstAux::xelpdp(io, self.link.port, self.link.tbt());
        complete(self.manager.poll_up_requests(&mut aux))?;
        if !self.manager.events.is_empty() {
            self.manager.events.clear();
            return Ok(false);
        }
        match self.streams.first() {
            Some(stream) => stream.route.link_ok(io),
            None => Ok(false),
        }
    }
}

/// A 128b/132b MST stream through a DP tunnel
/// (`intel_dp_tunnel_atomic_compute_stream_bw`): its
/// `intel_dp_config_required_rate` beside the `live` streams' must pass the
/// tunnel's check (`intel_dp_tunnel_atomic_check_link`,
/// [`tunnel::Tunnel::check_stream_bws`]); when it does not,
/// `intel_link_bw_reduce_bpp` lowers the stream's bpp limit below its pipe
/// bpp and `mst_stream_compute_link_config` recomputes it (24, then 18
/// bpp). `None` when even 18 bpp does not fit. Linux reduces the
/// highest-bpp stream of the whole commit (the lowest pipe on a tie); this
/// owner lights streams one at a time and never re-modesets a live one (as
/// its PBN admission), so the new stream is the one reduced, and one that
/// cannot fit is left dark instead of failing the others.
#[inline(never)]
fn tunnel_stream(
    t: &tunnel::Tunnel,
    link: &UhbrMstLink,
    mode: &Mode,
    live: u32,
) -> Option<(uhbr::MstUhbrStream, u32)> {
    let mut max_bpp = dsc::PIPE_BPP;
    loop {
        let s = uhbr::mst_stream(link.rate, link.lanes, mode, max_bpp)?;
        // intel_dp_config_required_rate: intel_dp_link_required at the
        // stream's pipe bpp, no BW overhead flags.
        let bw = uhbr::link_required(
            u32::from(link.lanes),
            mode.pixel_clock_khz,
            u32::from(mode.h_active),
            s.pipe_bpp * 16,
        );
        let bw = u32::try_from(bw).unwrap_or(u32::MAX);
        if t.check_stream_bws(live.saturating_add(bw)) {
            return Some((s, bw));
        }
        if s.pipe_bpp <= dsc::MIN_PIPE_BPP {
            return None;
        }
        max_bpp = s.pipe_bpp - 1;
    }
}

/// `intel_dp_tunnel_atomic_alloc_bw` for the link's streams: the tunnel's
/// allocation set to `total` kBps (`drm_dp_tunnel_alloc_bw`). Linux only
/// queues a re-detect after a failed request and enables the stream anyway;
/// this owner refuses it ([`uhbr::UhbrRefusal::Tunnel`]), as the SST route
/// does.
fn tunnel_alloc<M: MmioWindow + ?Sized>(
    io: &M,
    link: LinkProbe,
    found: &mut Option<tunnel::Tunnel>,
    total: u32,
) -> Result<(), ExternalError> {
    let Some(t) = found.as_mut() else {
        return Ok(());
    };
    let mut aux = link.aux(io);
    tunnel::alloc_bw(&mut aux, &mut uhbr::SystemClock, t, total)
        .map_err(|e| ExternalError::Uhbr(uhbr::UhbrRefusal::Tunnel(e)))
}

/// The tunnel handed back with the link: the streams' allocation freed and
/// BW allocation disabled (`drm_dp_tunnel_disable_bw_alloc`), as the SST
/// route's stop. Best effort, as the hub may be gone.
fn tunnel_off<M: MmioWindow + ?Sized>(io: &M, link: LinkProbe, found: &mut Option<tunnel::Tunnel>) {
    let Some(mut t) = found.take() else {
        return;
    };
    let mut aux = link.aux(io);
    if t.allocated_bw.is_some_and(|bw| bw != 0) {
        let _ = tunnel::alloc_bw(&mut aux, &mut uhbr::SystemClock, &mut t, 0);
    }
    let _ = tunnel::disable_bw_alloc(&mut aux, &mut t);
}

/// The link an MST retry runs ([`mst_fallback`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MstRetry {
    /// 128b/132b at the reduced configuration.
    Uhbr(UhbrMstLink),
    /// 8b/10b at this rate and lane count.
    EightTenB(TrainRate, u8),
}

/// `intel_dp_get_link_train_fallback_values` after the 128b/132b MST link
/// failed to train: [`uhbr::LinkCaps::fallback`] in
/// `intel_dp_link_caps_connector_fallback_order(is_mst)`
/// (`INTEL_DP_LINK_CAPS_ORDER_KEY_BW`, descending), then the retry's link,
/// `intel_dp_get_connector_max_link_config`: the highest-bandwidth
/// configuration still allowed (with the reduced maximum limits, the
/// fallback's own). `None` when nothing follows (Linux marks the link
/// `INTEL_DP_LINK_RECOVERY_NO_FALLBACK`).
fn mst_fallback(link: &UhbrMstLink) -> Option<MstRetry> {
    let mut caps = link.caps;
    caps.fallback(link.rate.link_rate(), link.lanes, true)?;
    let (order, n) = caps.ordered(uhbr::FallbackOrder::Bw);
    let &(rate, lanes) = order[..n]
        .iter()
        .rev()
        .find(|&&(r, l)| caps.allowed(r, l))?;
    Some(match uhbr::UhbrRate::from_link_rate(rate) {
        Some(rate) => MstRetry::Uhbr(UhbrMstLink {
            rate,
            lanes,
            caps,
            ..*link
        }),
        None => MstRetry::EightTenB(train_rate_for(rate)?, lanes),
    })
}

/// `narf.intel.hdmi14_ext=1` for one MST stream whose base EDID block
/// `probe` holds: `drm_dp_mst_edid_read`'s extension blocks (as many as
/// block 0 announces and the probe's buffer holds), then
/// `intel_dp_audio_compute_config`'s `intel_dp_has_audio` (every display-12+
/// port; a sink that declares audio) and the connector ELD
/// (`drm_edid_to_eld`). Out of line: the connect loop's frame stays small.
#[inline(never)]
fn stream_audio<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    sink: Sink,
    probe: &mut MtlSinkProbe,
) -> Result<(), ExternalError> {
    let blocks = (1 + usize::from(probe.edid[126])).min(EDID_CAPACITY / 128);
    for block in 1..blocks {
        let data = complete(manager.read_edid_block(aux, topology, sink, block as u8))?;
        probe.edid[block * 128..(block + 1) * 128].copy_from_slice(&data);
    }
    probe.edid_len = blocks * 128;
    let edid = &probe.edid[..probe.edid_len];
    if super::audio::edid_has_audio(edid) {
        let mut eld = Box::new([0u8; super::audio::MAX_ELD_BYTES]);
        *eld = super::audio::eld_from_edid(edid, true);
        probe.audio = Some(eld);
    }
    Ok(())
}

/// The stream of [`uhbr::mst_stream`] for `mode` on the 128b/132b link
/// (out of line: the connect loop's frame stays small).
#[inline(never)]
fn uhbr_stream(link: &UhbrMstLink, mode: &Mode) -> Option<uhbr::MstUhbrStream> {
    uhbr::mst_stream(link.rate, link.lanes, mode, dsc::PIPE_BPP)
}

/// The boxed plan a 128b/132b MST stream's probe carries.
#[inline(never)]
fn uhbr_plan(link: &UhbrMstLink, stream: &uhbr::MstUhbrStream) -> Box<UhbrPlan> {
    Box::new(UhbrPlan {
        link: uhbr::UhbrLink {
            rate: link.rate,
            lanes: link.lanes,
            pipe_bpp: stream.pipe_bpp,
        },
        stream: stream.stream,
        post_lt_adj_req: link.post_lt_adj_req,
        tunnel: None,
        caps: link.caps,
        max_bpp: dsc::PIPE_BPP as u8,
        dsc_sink: None,
    })
}

#[allow(clippy::result_large_err)]
fn activate_secondary<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlSinkProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
    pipes: Pipes,
    payload: &mut dyn FnMut(Transcoder, PayloadStep) -> Result<(), ExternalError>,
) -> Result<MtlExternalRoute, ActivateError> {
    let pipe = match free_pipe(io, ExternalDisplayProfile::for_ip(probe.display_ip)) {
        Ok(pipe) => pipe,
        Err(error) => return Err(ActivateError::Refused(probe, error)),
    };
    let choice = PipeChoice { pipe, pipes };
    let mut ext = match external_pipe(
        &choice,
        probe.port,
        &probe.mode,
        &fb,
        probe.port_clock_khz(),
        None,
        probe.pipe_bpp,
    ) {
        Ok(ext) => ext,
        Err(error) => return Err(ActivateError::Refused(probe, error)),
    };
    // intel_dp_compute_min_hblank: display 30 programs it for 128b/132b MST.
    if probe.uhbr.is_some() && probe.display_ip.is_display30() {
        ext.min_hblank = uhbr::min_hblank(&probe.mode, probe.pipe_bpp);
    }
    // intel_dp_audio_compute_config: the stream's audio joins the CDCLK
    // floor (intel_audio_min_cdclk).
    ext.audio = probe.audio.is_some();
    if let Err(error) = choice.pipes.admit(io, &ext) {
        return Err(ActivateError::Refused(probe, error.into()));
    }
    let trained = TrainedLink {
        rate: probe.negotiated.rate,
        lanes: probe.negotiated.lanes,
        vswing_pe: Default::default(),
    };
    let mut route = MtlExternalRoute {
        probe,
        fb,
        trained,
        pipe,
        reservation: None,
        retired: None,
        awaiting_fec_stop: false,
        state: RouteState::Stopped,
        uhbr: None,
        lttprs: 0,
        audio: None,
    };
    let result = (|| {
        request_pipe_wells(io, pipe)?;
        route.reservation = Some(crate::intel_gpu_xelpg_hdmi::reserve_audio_pipe(
            io,
            choice,
            &ext,
            display.pipe_dmc,
        )?);
        write(
            io,
            trans_clk_sel(pipe.transcoder()),
            trans_clk_sel_port(route.port()),
        )?;
        // intel_ddi_config_transcoder_func for a following stream (display
        // 13+): TRANS_DP2_CTL and the function without ENABLE (128b/132b).
        if let Some(plan) = route.probe.uhbr.as_deref().copied() {
            let trans = pipe.transcoder();
            write(io, trans_dp2_ctl(trans), TRANS_DP2_128B132B_CHANNEL_CODING)?;
            write(
                io,
                trans_ddi_func_ctl(trans),
                uhbr_func(&route.probe, trans, plan.link.lanes) & !TRANS_DDI_FUNC_ENABLE,
            )?;
        }
        finish(io, &mut route, &trained, payload)
    })();
    match result {
        Ok(()) => {
            route.state = RouteState::Live;
            Ok(route)
        }
        Err(error) => {
            route.state = RouteState::Quarantined;
            Err(ActivateError::Failed(route, error))
        }
    }
}

fn stop_stream<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
    shared: bool,
) -> Result<(), ExternalError> {
    if !shared {
        stop_local(io, route)?;
    } else if let Some(rp) = route.reservation.as_mut() {
        // mst_stream_disable: intel_audio_codec_disable before the planes
        // go (best effort: the stop proof is the pipe's).
        if let Some(stream) = route.audio.take() {
            let _ = super::audio::audio_codec_disable(io, &stream);
        }
        rp.pipes.disable_primary(io, rp.pipe)?;
        rp.pipes.disable(io, rp.pipe)?;
        let trans = rp.transcoder();
        let func = read(io, trans_ddi_func_ctl(trans))?;
        write(
            io,
            trans_ddi_func_ctl(trans),
            func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE | (1 << 8)),
        )?;
        // intel_ddi_disable_transcoder_func on a slave: the DP2 configuration
        // off too.
        if route.probe.uhbr.is_some() {
            write(io, trans_dp2_ctl(trans), 0)?;
        }
        write(io, trans_clk_sel(trans), 0)?;
        release_audio_pipe(io, rp, route.probe.audio.is_some())?;
    }
    route.state = RouteState::Stopped;
    Ok(())
}

#[cfg(feature = "kernel-test")]
pub(super) mod tests {
    use super::*;
    use crate::dp_mst_mgr::tests::Hub;
    use crate::intel_gpu_xelpg_external::tests::{edid_for, ExtFake, Sink as DpSink};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The fake hub's sideband, with its ACT-handled bit following the
    /// source's ACT sent (`DP_TP_STATUS`) on `io` (also the two-route
    /// fixtures').
    pub(crate) struct Branch<'a> {
        hub: Hub,
        io: &'a ExtFake,
    }
    impl MstAux for Branch<'_> {
        type Error = ();
        async fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), ()> {
            self.hub.read(address, out).await?;
            if address == 0x2C0
                && (0..4).any(|pipe| self.io.read32(0x60544 + pipe * 0x1000) & (1 << 24) != 0)
            {
                out[0] |= 2;
            }
            Ok(())
        }
        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), ()> {
            self.hub.write(address, data).await
        }
        async fn delay(&mut self, _: u64) {}
    }

    fn edid() -> Vec<u8> {
        edid_for(65_000, 1024, 320, 24, 136, 768, 38, 3, 6)
    }
    /// A two-sink hub whose sinks report 1024x768 at 65 MHz.
    pub(crate) fn branch(io: &ExtFake) -> Branch<'_> {
        let mut hub = Hub::new();
        hub.edid[..128].copy_from_slice(&edid());
        Branch { hub, io }
    }
    fn fb(mode: &Mode, index: &mut u32) -> Framebuffer {
        *index += 1;
        Framebuffer {
            phys_addr: u64::from(*index) * 0x0080_0000,
            stride_bytes: u32::from(mode.h_active) * 4,
            format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
        }
    }

    fn smoke_mtl_mst_two_streams_share_transport_and_stop_in_reverse() -> TestResult {
        let io = ExtFake::new(XeLpgPort::Tc1, DpSink::new(0x14, edid()));
        io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
        let link = probe_link(&io, Generation::MeteorLake, XeLpgPort::Tc1, false).unwrap();
        let mut aux = branch(&io);
        let mut index = 0;
        let mut owner = match MtlMstRoute::connect_aux(
            &io,
            link,
            MtlPortDecl::USB_C,
            &MtlDisplay::NONE,
            &mut |mode| Some(fb(mode, &mut index)),
            &mut aux,
        ) {
            Ok(owner) => owner,
            Err((_, error)) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "MST connect: {error:?}");
                return TestResult::Fail("MST must light two remote-EDID sinks");
            }
        };
        if owner.stream_count() != 2
            || owner.streams[0].route.pipe != Pipe::B
            || owner.streams[1].route.pipe != Pipe::C
            || owner.streams[0].route.fb.phys_addr == owner.streams[1].route.fb.phys_addr
            || owner
                .streams
                .iter()
                .any(|s| s.route.trained.lanes > 2 || s.vcpi != s.route.pipe as u8 + 1)
        {
            return TestResult::Fail(
                "MST needs independent pipes/surfaces, bounded pin-D width and pipe VCPI",
            );
        }
        if io.read32(0x61540) & ((1 << 27) | (1 << 18)) != 1 << 27
            || io.sink.borrow().training_writes_to(0x101) != [2]
            || io.read32(0x62540) & (1 << 31) != 0
            || io.read32(0x62400) & (3 << 10) != 1 << 10
        {
            return TestResult::Fail("only primary B must own the shared MST transport");
        }
        if owner.stop_aux(&io, &mut aux).is_err() || !owner.stopped() || owner.release(&io).is_err()
        {
            return TestResult::Fail("MST must stop secondary before primary then release TC/AUX");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_mtl_mst_two_streams_share_transport_and_stop_in_reverse
    );

    /// DP MST audio (`narf.intel.hdmi14_ext=1`, Linux 7.4 `intel_dp_mst.c`
    /// `mst_stream_compute_config` / `mst_stream_enable` /
    /// `mst_stream_disable`, `intel_audio.c`): the hub's sinks carry a CTA
    /// extension with an LPCM SAD, so each stream reads its EDID's
    /// extension block (`drm_dp_mst_edid_read`), takes audio
    /// (`intel_dp_has_audio`) and its connector ELD, and enables it on its
    /// own transcoder: `AUDIO_OUTPUT_ENABLE` and `AUD_CONFIG`'s
    /// `N_VALUE_INDEX` for B and C, `HBLANK_EARLY_ENABLE_TGL` for both, and
    /// `pin_eld_notify(PORT_TC1 = PORT_D = 3, cpu_transcoder)` per stream
    /// (`intel_audio_needs_cpu_transcoder_id`). `find_audio_state` answers
    /// (3, 1) and (3, 2) with the streams' ELDs and the legacy lookups (3,
    /// -1) and (3, 0) with nothing. The stop disables both and notifies
    /// again. Without the option no extension is read and no audio runs.
    fn smoke_mtl_mst_streams_take_audio_per_transcoder() -> TestResult {
        use narf_drivers_sound::display_audio as acomp;
        super::audio::reset_for_test();
        acomp::register_display_audio_codec(&super::audio::tests::SCRIPTED_HDA);
        let result = mst_audio_sequence();
        acomp::unregister_display_audio_codec();
        super::audio::reset_for_test();
        result
    }

    fn mst_audio_sequence() -> TestResult {
        use super::audio::tests::{NOTIFY_COUNT, NOTIFY_PIPE, NOTIFY_PORT};
        use super::audio::{component_get_eld, AUD_CONFIG_BE};
        use crate::intel_gpu_audio::{aud_eld_valid, aud_output_enable, HSW_AUD_PIN_ELD_CP_VLD};
        use core::sync::atomic::Ordering;
        // An audio data block: LPCM, 2 channels, 32/44.1/48 kHz, 16/20/24 bit.
        let audio_edid = crate::intel_gpu_xelpg_external::color::tests::with_cta(
            edid(),
            &[(1 << 5) | 3, 0x09, 0x07, 0x07],
        );
        let connect = |io: &ExtFake, aux: &mut Branch<'_>, audio: bool, index: &mut u32| {
            let link = probe_link(io, Generation::MeteorLake, XeLpgPort::Tc1, false).ok()?;
            let alloc = &mut |mode: &Mode| Some(fb(mode, index));
            let owner = if audio {
                MtlMstRoute::connect_aux_audio(
                    io,
                    link,
                    MtlPortDecl::USB_C,
                    &MtlDisplay::NONE,
                    alloc,
                    aux,
                )
            } else {
                MtlMstRoute::connect_aux(
                    io,
                    link,
                    MtlPortDecl::USB_C,
                    &MtlDisplay::NONE,
                    alloc,
                    aux,
                )
            };
            owner.ok()
        };
        let io = ExtFake::new(XeLpgPort::Tc1, DpSink::new(0x14, edid()));
        io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
        let mut aux = branch(&io);
        aux.hub.edid.copy_from_slice(&audio_edid);
        let mut index = 0;
        let before = NOTIFY_COUNT.load(Ordering::SeqCst);
        let Some(mut owner) = connect(&io, &mut aux, true, &mut index) else {
            return TestResult::Fail("MST must light two audio sinks");
        };
        let i2c_reads = aux
            .hub
            .bodies
            .iter()
            .filter(|b| b.first() == Some(&crate::dp_mst::REMOTE_I2C_READ))
            .count();
        if owner.stream_count() != 2
            || i2c_reads != 4
            || owner
                .streams
                .iter()
                .any(|s| s.route.probe.edid_len != 256 || s.route.audio.is_none())
        {
            return TestResult::Fail("each stream must read its extension block and take audio");
        }
        let pin = io.read32(HSW_AUD_PIN_ELD_CP_VLD);
        let both = aud_output_enable(Transcoder::B) | aud_output_enable(Transcoder::C);
        if pin & both != both
            || pin & (aud_eld_valid(Transcoder::B) | aud_eld_valid(Transcoder::C)) != 0
            || io.read32(crate::intel_gpu_audio::aud_cfg_off(Transcoder::B))
                & crate::intel_gpu_audio::AUD_CONFIG_N_VALUE_INDEX
                == 0
            || io.read32(crate::intel_gpu_audio::aud_cfg_off(Transcoder::C))
                & crate::intel_gpu_audio::AUD_CONFIG_N_VALUE_INDEX
                == 0
            || io.read32(AUD_CONFIG_BE) & ((1 << 25) | (1 << 26)) != (1 << 25) | (1 << 26)
        {
            return TestResult::Fail("each MST transcoder must run its own audio enable");
        }
        if NOTIFY_COUNT.load(Ordering::SeqCst) != before + 2
            || NOTIFY_PORT.load(Ordering::SeqCst) != 3
            || NOTIFY_PIPE.load(Ordering::SeqCst) != 2
        {
            return TestResult::Fail("each stream must notify pin_eld_notify(3, its transcoder)");
        }
        let mut buf = [0u8; 128];
        let eld_of = |pipe: i32, buf: &mut [u8; 128]| component_get_eld(3, pipe, buf);
        if eld_of(1, &mut buf).map(|(on, n)| on && n > 20 && buf[5] >> 4 == 1) != Ok(true)
            || eld_of(2, &mut buf).map(|(on, _)| on) != Ok(true)
            || eld_of(-1, &mut buf).is_ok()
            || eld_of(0, &mut buf).is_ok()
        {
            return TestResult::Fail("find_audio_state must address MST streams by transcoder");
        }
        if owner.stop_aux(&io, &mut aux).is_err()
            || io.read32(HSW_AUD_PIN_ELD_CP_VLD) & both != 0
            || NOTIFY_COUNT.load(Ordering::SeqCst) != before + 4
            || eld_of(1, &mut buf).is_ok()
            || eld_of(2, &mut buf).is_ok()
            || owner.release(&io).is_err()
        {
            return TestResult::Fail("the stop must disable each stream's audio and notify");
        }
        // narf.intel.hdmi14_ext off: block 0 only, no audio.
        let io = ExtFake::new(XeLpgPort::Tc1, DpSink::new(0x14, edid()));
        io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
        let mut aux = branch(&io);
        aux.hub.edid.copy_from_slice(&audio_edid);
        let before = NOTIFY_COUNT.load(Ordering::SeqCst);
        let Some(mut owner) = connect(&io, &mut aux, false, &mut index) else {
            return TestResult::Fail("MST must light without the option");
        };
        let i2c_reads = aux
            .hub
            .bodies
            .iter()
            .filter(|b| b.first() == Some(&crate::dp_mst::REMOTE_I2C_READ))
            .count();
        let quiet = i2c_reads == 2
            && owner.streams.iter().all(|s| s.route.audio.is_none())
            && NOTIFY_COUNT.load(Ordering::SeqCst) == before
            && io.read32(HSW_AUD_PIN_ELD_CP_VLD) == 0;
        let _ = owner.stop_aux(&io, &mut aux);
        let _ = owner.release(&io);
        if quiet {
            TestResult::Pass
        } else {
            TestResult::Fail("without the option MST must take no audio")
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_mtl_mst_streams_take_audio_per_transcoder
    );

    fn smoke_mtl_mst_missing_act_retains_failed_route_and_blocks_release() -> TestResult {
        let io = ExtFake::new(XeLpgPort::Tc2, DpSink::new(0x14, edid()));
        io.act_stuck.set(true);
        let link = probe_link(&io, Generation::MeteorLake, XeLpgPort::Tc2, false).unwrap();
        let mut aux = branch(&io);
        let mut index = 0;
        match MtlMstRoute::connect_aux(
            &io,
            link,
            MtlPortDecl::USB_C,
            &MtlDisplay::NONE,
            &mut |mode| Some(fb(mode, &mut index)),
            &mut aux,
        ) {
            Err((mut owner, ExternalError::Mst(MstFailure::Act))) => {
                if owner.failed.is_none() || owner.stopped() {
                    return TestResult::Fail("missing ACT must retain failed source ownership");
                }
                io.act_stuck.set(false);
                if owner.stop_aux(&io, &mut aux).is_err() || owner.release(&io).is_err() {
                    return TestResult::Fail(
                        "failed MST must remain cleanable after a proven local stop",
                    );
                }
            }
            _ => return TestResult::Fail("MST without fresh ACT must fail"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_mtl_mst_missing_act_retains_failed_route_and_blocks_release
    );

    /// Nova Lake-S MST over LT port B beside the lit display-35 panel,
    /// through the display-35 view. The first stream owns the link, so the
    /// LT PHY is enabled for it alone (`intel_lt_phy_pll_enable` at the
    /// shared link's DP 1.4 image, `xe3plpd_lt_dp_tables`) and carries its
    /// trained `xe3plpd_lt_trans_dp14` levels; every LT access precedes the
    /// second stream, which takes only Pipe C, its transcoder and payload
    /// against the transcoder-B transport. The stop runs the second stream
    /// first and releases MacCLK with the first (`intel_lt_phy_pll_disable`),
    /// then the release returns AUX. No display-14 PHY offset or Cx0
    /// transaction is reached.
    fn smoke_nvl_mst_two_streams_over_lt_port_b() -> TestResult {
        use crate::intel_gpu_lt_phy::{dp_pll_state, signal_level, LtDpRate, LtSignalProtocol};
        use crate::intel_gpu_xelpg::lane_pclk_pll_request;
        use crate::intel_gpu_xelpg_external::tests::nova::{nova_lt_lit, NovaExt};
        let port = XeLpgPort::B;
        let io = NovaExt::new(ExtFake::new(port, DpSink::new(0x14, edid())));
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let Ok(link) = probe_link_profile(&view, profile, port, false) else {
            return TestResult::Fail("Nova DDI B must read the branch's DPCD over PICA AUX");
        };
        let mut aux = branch(&io.ext);
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        let mut index = 0;
        let mut owner = match MtlMstRoute::connect_aux(
            &view,
            link,
            MtlPortDecl::COMBO_DP_HDMI,
            &display,
            &mut |mode| Some(fb(mode, &mut index)),
            &mut aux,
        ) {
            Ok(owner) => owner,
            Err((_, error)) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "Nova MST connect: {error:?}");
                return TestResult::Fail("Nova MST must light two remote-EDID sinks");
            }
        };
        if owner.stream_count() != 2
            || owner.streams[0].route.pipe != Pipe::B
            || owner.streams[1].route.pipe != Pipe::C
            || owner
                .streams
                .iter()
                .any(|s| s.vcpi != s.route.pipe as u8 + 1)
        {
            return TestResult::Fail("Nova MST needs Pipes B and C with the pipe's VCPI");
        }
        if io.ext.read32(0x61540) & ((1 << 27) | (1 << 18)) != 1 << 27
            || io.ext.read32(0x62540) & (1 << 31) != 0
            || io.ext.read32(0x62400) & (3 << 10) != 1 << 10
        {
            return TestResult::Fail("only transcoder B may own the shared MST transport");
        }
        let first = &owner.streams[0].route;
        let Some(rate) = LtDpRate::from_clock_khz(link_clock_khz(first.trained.rate))
            .filter(|rate| !rate.is_uhbr())
        else {
            return TestResult::Fail("the MST link trains at a DP 1.4 rate");
        };
        let levels: Vec<_> = first.trained.vswing_pe.lanes[..usize::from(first.trained.lanes)]
            .iter()
            .map(|lane| {
                signal_level(
                    LtSignalProtocol::Dp14,
                    crate::intel_gpu_xelpg::preset_index(lane.swing, lane.pre_emph),
                )
                .unwrap()
            })
            .collect();
        if let Err(e) = nova_lt_lit(&io, dp_pll_state(rate), &levels) {
            return TestResult::Fail(e);
        }
        let second = io.ext.first_write(|r, _| r == trans_clk_sel(Transcoder::C));
        let last_lt = io.ext.last_write(|r, _| io.lt_reg(r));
        if !matches!((last_lt, second), (Some(l), Some(c)) if l < c) {
            return TestResult::Fail("the second stream must not reach the LT PHY");
        }
        io.ext.writes.borrow_mut().clear();
        if owner.stop_aux(&view, &mut aux).is_err() || !owner.stopped() {
            return TestResult::Fail("Nova MST must stop both streams");
        }
        let second_off = io.ext.first_write(|r, v| {
            r == trans_ddi_func_ctl(Transcoder::C) && v & TRANS_DDI_FUNC_ENABLE == 0
        });
        let macclk_off = io
            .ext
            .first_write(|r, v| r == 0x16_fc60 && v & lane_pclk_pll_request(0) == 0);
        if !matches!((second_off, macclk_off), (Some(s), Some(m)) if s < m)
            || view.read32(port.port_clock_ctl()) & (3 << 30) != 0
            || view.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
            || !io.strays.borrow().is_empty()
        {
            return TestResult::Fail("the first stream's stop must release the LT PHY last");
        }
        if owner.release(&view).is_err() {
            return TestResult::Fail("Nova MST must release AUX after the proven stop");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_nvl_mst_two_streams_over_lt_port_b
    );
    /// [`Branch`] that also records each DPCD payload-table write
    /// (`DP_PAYLOAD_ALLOCATE_SET`: VCPID, start slot, slot count) with the
    /// number of MMIO writes the source had made by then.
    struct Logged<'a> {
        inner: Branch<'a>,
        payload: Vec<([u8; 3], usize)>,
    }
    impl MstAux for Logged<'_> {
        type Error = ();
        async fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), ()> {
            self.inner.read(address, out).await
        }
        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), ()> {
            if address == 0x1C0 && data.len() == 3 {
                let at = self.inner.io.writes.borrow().len();
                self.payload.push(([data[0], data[1], data[2]], at));
            }
            self.inner.write(address, data).await
        }
        async fn delay(&mut self, us: u64) {
            self.inner.delay(us).await
        }
    }

    /// 128b/132b MST (`intel_dp_mst.c` over a UHBR link) on Meteor Lake TC1
    /// (pin C, four lanes) behind a DP 2.0 hub with UHBR10/20: Linux takes
    /// the highest-bandwidth common configuration, UHBR20 x4. Each 1024x768
    /// 65 MHz stream (`intel_dp_mtp_tu_compute_config`, values from Linux
    /// 7.4's formulas): `drm_dp_get_vc_payload_bw(2000000, 4)` = 733563
    /// (20.12), the remote PBN `DIV_ROUND_UP(rate * 64, 54000)` = 233 with the
    /// SSC margin, the remote TU 2, the allocated PBN 358 and two slots from
    /// slot 0 (`drm_dp_mst_update_slots(DP_CAP_ANSI_128B132B)`), `DATA_M` =
    /// `TU_SIZE(2)` | 0x0294b6, `LINK_M` 65000 / 625000 at N 0x80000 =
    /// 0xd4fd. The primary trains at 128b/132b and writes no SST payload; its
    /// DPCD payload (VCPID 2, slots 0..2) follows the training and precedes
    /// its function enable (`drm_dp_add_payload_part1` in
    /// `mst_stream_pre_enable`); the second stream (VCPID 3, slots 2..4)
    /// configures `TRANS_DP2_CTL` and its 128b/132b function on transcoder
    /// B's transport; both program the VFREQ pair (65 MHz: 0x300 /
    /// 0xdfd24000). HDCP sees both streams for stream encryption
    /// (`intel_hdcp_mst.rs`). The stop clears both DP2 configurations.
    fn smoke_mtl_mst_128b132b_two_streams_on_uhbr20() -> TestResult {
        let io = ExtFake::new(
            XeLpgPort::Tc1,
            DpSink::dp20(0x14, edid(), uhbr::DP_UHBR10 | uhbr::DP_UHBR20),
        );
        let Ok(link) = probe_link(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) else {
            return TestResult::Fail("the DP 2.0 hub must answer its DPCD");
        };
        let u = match uhbr_mst_link(&io, &link) {
            Ok(Some(u)) if u.rate == uhbr::UhbrRate::Uhbr20 && u.lanes == 4 => u,
            _ => return TestResult::Fail("Linux runs MST at the highest bandwidth: UHBR20 x4"),
        };
        let mut aux = Logged {
            inner: branch(&io),
            payload: Vec::new(),
        };
        let mut index = 0;
        let owner = match MtlMstRoute::connect_aux_with(
            &io,
            link,
            MtlPortDecl::USB_C,
            &MtlDisplay::NONE,
            &mut |mode| Some(fb(mode, &mut index)),
            &mut aux,
            Some(u),
        ) {
            Ok(owner) => owner,
            Err((_, error)) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "128b/132b MST connect: {error:?}");
                return TestResult::Fail("128b/132b MST must light two remote-EDID sinks");
            }
        };
        let mn = [(1 << 25) | 0x02_94b6, 0x80_0000, 0xd4fd, 0x8_0000];
        if owner.stream_count() != 2
            || owner.streams[0].route.pipe != Pipe::B
            || owner.streams[1].route.pipe != Pipe::C
            || owner.streams[0].slot != 0
            || owner.streams[1].slot != 2
            || owner.streams.iter().any(|s| {
                s.vcpi != s.route.pipe as u8 + 1
                    || s.route.probe.mst.map(|m| m.slots) != Some(2)
                    || s.route
                        .probe
                        .uhbr
                        .as_deref()
                        .map(|p| (p.link, p.stream.tu, p.stream.m_n))
                        != Some((
                            uhbr::UhbrLink {
                                rate: uhbr::UhbrRate::Uhbr20,
                                lanes: 4,
                                pipe_bpp: 24,
                            },
                            2,
                            mn,
                        ))
            })
        {
            return TestResult::Fail("two 128b/132b streams: Linux's slots from 0, TU and M/N");
        }
        // The hub's payload table: the reset, then VCPID 2 at slot 0 and
        // VCPID 3 at slot 2, two slots each; never the SST VCPID 1.
        let tables: Vec<[u8; 3]> = aux.payload.iter().map(|&(t, _)| t).collect();
        if tables != [[0, 0, 0x3f], [2, 0, 2], [3, 2, 2]] {
            return TestResult::Fail("payload part 1 must allocate slots 0..2 and 2..4");
        }
        let at = aux.payload[1].1;
        let trained =
            io.first_write(|r, v| r == dp_tp_ctl(Transcoder::B) && v & (7 << 8) == 3 << 8);
        let func_on = io.first_write(|r, v| {
            r == trans_ddi_func_ctl(Transcoder::B) && v & TRANS_DDI_FUNC_ENABLE != 0
        });
        if !matches!((trained, func_on), (Some(t), Some(f)) if t < at && at <= f) {
            return TestResult::Fail("part 1 follows the training and precedes the function");
        }
        let func_c = io.writes_to(trans_ddi_func_ctl(Transcoder::C));
        let want_c = (crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
            XeLpgPort::Tc1.func_ctl_index(),
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
            4,
        ) & !(7 << 24))
            | TRANS_DDI_MODE_128B132B
            | (1 << 10);
        if io.writes_to(trans_dp2_ctl(Transcoder::B)).first()
            != Some(&TRANS_DP2_128B132B_CHANNEL_CODING)
            || io.writes_to(trans_dp2_ctl(Transcoder::C)).first()
                != Some(&TRANS_DP2_128B132B_CHANNEL_CODING)
            || func_c.first() != Some(&(want_c & !TRANS_DDI_FUNC_ENABLE))
            || func_c.last() != Some(&(want_c | (1 << 8)))
            || io.writes_to(trans_dp2_vfreqhigh(Transcoder::C)) != [0x300]
            || io.writes_to(trans_dp2_vfreqlow(Transcoder::C)) != [0xdfd2_4000]
            || io.writes_to(trans_dp2_vfreqhigh(Transcoder::B)) != [0x300]
            || io.read32(0x62540) & DP_TP_CTL_ENABLE != 0
            || io.read32(dp_tp_ctl(Transcoder::B)) & DP_TP_CTL_MODE_MST == 0
        {
            return TestResult::Fail("each stream runs 128b/132b on transcoder B's transport");
        }
        for t in [Transcoder::B, Transcoder::C] {
            let m1 = io.read32(t.base() + crate::intel_gpu_pipes::PIPE_DATA_M1_OFFSET);
            if m1 != mn[0] {
                return TestResult::Fail("each stream's TU_SIZE(2) and data M");
            }
        }
        // HDCP 2.x stream encryption takes both streams, master first.
        let route = MtlRoute::Mst(owner);
        let streams = crate::intel_hdcp_live::MstStreams::new(&[(1, 2), (2, 3)]);
        match hdcp_route_of(&route) {
            Some(r) if Some(r.mst) == streams && r.transcoder == 1 => {}
            _ => return TestResult::Fail("HDCP must see both 128b/132b MST streams"),
        }
        let MtlRoute::Mst(mut owner) = route else {
            return TestResult::Fail("the route is MST");
        };
        if owner.stop_aux(&io, &mut aux).is_err() || !owner.stopped() {
            return TestResult::Fail("128b/132b MST must stop both streams");
        }
        if io.writes_to(trans_dp2_ctl(Transcoder::C)).last() != Some(&0)
            || io.writes_to(trans_dp2_ctl(Transcoder::B)).last() != Some(&0)
            || owner.release(&io).is_err()
        {
            return TestResult::Fail("the stop must clear both DP2 configurations and release");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_mtl_mst_128b132b_two_streams_on_uhbr20
    );

    /// The reduced-parameter retry of a 128b/132b MST link
    /// (`intel_dp_get_link_train_fallback_values` with `is_mst`, then the
    /// modeset retry of the link's streams): the UHBR10/20 hub of
    /// [`smoke_mtl_mst_128b132b_two_streams_on_uhbr20`] reports
    /// `DP_128B132B_LT_FAILED` on four lanes, so the primary's UHBR20 x4
    /// training fails and the route stops before any payload. In
    /// `INTEL_DP_LINK_CAPS_ORDER_KEY_BW` order (descending) the next
    /// configuration is UHBR20 x2 (4835500 kBps, above UHBR10 x4's equal
    /// bandwidth by rate): UHBR20 x4 is disabled and the maximum limits are
    /// UHBR20 x2. Both 1024x768 65 MHz streams run there (Linux 7.4's
    /// formulas): `drm_dp_get_vc_payload_bw(2000000, 2)` = 366781, the
    /// remote TU 4 (aligned to 4 / 2 lanes), the allocated PBN 358 and four
    /// slots each, from slot 0 and slot 4, `DATA_M` = `TU_SIZE(4)` |
    /// 0x05296d, `LINK_M` 0xd4fd at N 0x80000. Training writes UHBR20 with
    /// four lanes, then with two.
    fn smoke_mtl_mst_128b132b_training_fallback_retry() -> TestResult {
        let mut hub = DpSink::dp20(0x14, edid(), uhbr::DP_UHBR10 | uhbr::DP_UHBR20);
        hub.uhbr_lt_fail_lanes = 2;
        let io = ExtFake::new(XeLpgPort::Tc1, hub);
        let Ok(link) = probe_link(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) else {
            return TestResult::Fail("the DP 2.0 hub must answer its DPCD");
        };
        let u = match uhbr_mst_link(&io, &link) {
            Ok(Some(u)) if u.rate == uhbr::UhbrRate::Uhbr20 && u.lanes == 4 => u,
            _ => return TestResult::Fail("Linux runs MST at the highest bandwidth: UHBR20 x4"),
        };
        let mut aux = Logged {
            inner: branch(&io),
            payload: Vec::new(),
        };
        let mut index = 0;
        let mut owner = match MtlMstRoute::connect_aux_with(
            &io,
            link,
            MtlPortDecl::USB_C,
            &MtlDisplay::NONE,
            &mut |mode| Some(fb(mode, &mut index)),
            &mut aux,
            Some(u),
        ) {
            Ok(owner) => owner,
            Err((_, error)) => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "128b/132b MST retry: {error:?}");
                return TestResult::Fail("the reduced retry must light both streams");
            }
        };
        let mn = [(3 << 25) | 0x05_296d, 0x80_0000, 0xd4fd, 0x8_0000];
        if owner.stream_count() != 2
            || owner.streams[0].route.pipe != Pipe::B
            || owner.streams[0].slot != 0
            || owner.streams[1].slot != 4
            || owner.streams.iter().any(|s| {
                s.route.probe.mst.map(|m| m.slots) != Some(4)
                    || s.route.probe.uhbr.as_deref().map(|p| {
                        (
                            p.link,
                            p.stream.tu,
                            p.stream.m_n,
                            p.caps.allowed(2_000_000, 4),
                            p.caps.max_limits(),
                        )
                    }) != Some((
                        uhbr::UhbrLink {
                            rate: uhbr::UhbrRate::Uhbr20,
                            lanes: 2,
                            pipe_bpp: 24,
                        },
                        4,
                        mn,
                        false,
                        (2_000_000, 2),
                    ))
            })
        {
            return TestResult::Fail("the retry runs both streams at UHBR20 x2 with Linux's slots");
        }
        let tables: Vec<[u8; 3]> = aux.payload.iter().map(|&(t, _)| t).collect();
        if tables != [[0, 0, 0x3f], [2, 0, 4], [3, 4, 4]] {
            return TestResult::Fail("only the retry allocates payloads: slots 0..4 and 4..8");
        }
        {
            let sink = io.sink.borrow();
            let bw: Vec<u8> = sink
                .uhbr_log
                .iter()
                .filter_map(|&(a, v)| (a == 0x100).then_some(v))
                .collect();
            if bw != [0x02, 0x02] || sink.training_writes_to(0x101) != [4, 2] {
                return TestResult::Fail("training must try UHBR20 x4, then UHBR20 x2");
            }
        }
        if owner.stop_aux(&io, &mut aux).is_err() || !owner.stopped() || owner.release(&io).is_err()
        {
            return TestResult::Fail("the retried MST link must stop and release");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_mtl_mst_128b132b_training_fallback_retry
    );

    /// 128b/132b MST through a DP tunnel (Panther Lake TC2 in Thunderbolt
    /// alt mode, `narf.intel.uhbr=1`): the hub reports no 128b/132b rate in
    /// its own DPCD; after the unconditional `DP_128B132B_SUPPORTED_LINK_RATES`
    /// read, `drm_dp_tunnel_detect` and BW allocation (0xc0) the USB4
    /// adapter's UHBR10 x2 DPRX is the highest-bandwidth configuration
    /// (2417750 kBps over HBR3 x2's 1620000). Each 1024x768 65 MHz stream
    /// there (Linux 7.4's formulas): `drm_dp_get_vc_payload_bw(1000000, 2)` =
    /// 366781, the remote TU and slots 6 (PBN 268), `DATA_M` = `TU_SIZE(6)` |
    /// 0x0a52da, `LINK_M` 0x1a9fb at N 0x80000, and a tunnel bandwidth of
    /// 195000 kBps (`intel_dp_config_required_rate`). With 72 units
    /// (2250000 kBps) estimated both streams fit and `drm_dp_tunnel_alloc_bw`
    /// asks for the sum before each enable: 7, then 13 units of 31250 kBps;
    /// the stop decreases to 7, frees the rest, then disables BW allocation.
    /// With 6 units (187500 kBps) and one sink the stream's
    /// `DIV_ROUND_UP`-to-granularity 218750 kBps fails
    /// `drm_dp_tunnel_atomic_check_stream_bws`, so `intel_link_bw_reduce_bpp`
    /// takes it to 18 bpp: TU 4, `DATA_M` = `TU_SIZE(4)` | 0x07be23, 146250
    /// kBps, a request of 5 units.
    fn smoke_ptl_mst_128b132b_through_dp_tunnel() -> TestResult {
        use crate::intel_gpu_xelpg_external::tests::usb4_adapter;
        let ctl = tunnel::DP_DPTX_BW_ALLOCATION_MODE_CONTROL;
        let cases: [(u8, bool, u32, u8, [u32; 4], &[u8], &[u8]); 2] = [
            (
                72,
                false,
                24,
                6,
                [(5 << 25) | 0x0a_52da, 0x80_0000, 0x1_a9fb, 0x8_0000],
                &[7, 13],
                &[7, 13, 7, 0],
            ),
            (
                6,
                true,
                18,
                4,
                [(3 << 25) | 0x07_be23, 0x80_0000, 0x1_a9fb, 0x8_0000],
                &[5],
                &[5, 0],
            ),
        ];
        for (estimated, one_sink, bpp, tu, mn, requests, after_stop) in cases {
            let mut hub = DpSink::new(0x14, edid());
            let mut adapter = usb4_adapter();
            adapter[0x23] = estimated;
            hub.tunnel = Some(adapter);
            let io = ExtFake::new(XeLpgPort::Tc2, hub);
            let Some(panel) = io.light_panel_ip(DisplayIp::Xe3Lpd) else {
                return TestResult::Fail("the fixture must light the display-30 panel");
            };
            io.pica_isr
                .set(crate::intel_gpu_xelpg_hpd::pica_tbt_hotplug(1));
            let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd);
            let Ok(link) = probe_link_profile(&io, profile, XeLpgPort::Tc2, false) else {
                return TestResult::Fail("the tunnelled hub must answer its DPCD");
            };
            let u = match uhbr_mst_link(&io, &link) {
                Ok(Some(u))
                    if link.tbt()
                        && u.rate == uhbr::UhbrRate::Uhbr10
                        && u.lanes == 2
                        && u.tunnel.is_some_and(|t| t.bw_alloc_enabled) =>
                {
                    u
                }
                other => {
                    use core::fmt::Write as _;
                    let _ = writeln!(narf_console::Writer, "tunnel MST link: {other:?}");
                    return TestResult::Fail("the tunnel's UHBR10 x2 is the hub's MST link");
                }
            };
            if io.sink.borrow().tunnel_log != [(ctl, 0xc0)] {
                return TestResult::Fail("the MST link keeps the tunnel's BW allocation");
            }
            let mut aux = branch(&io);
            aux.hub.child_present = !one_sink;
            let display = MtlDisplay {
                panel: Some(panel),
                pipe_dmc: &NoPipeDmc,
            };
            let mut index = 0;
            let mut owner = match MtlMstRoute::connect_aux_with(
                &io,
                link,
                MtlPortDecl::USB_C,
                &display,
                &mut |mode| Some(fb(mode, &mut index)),
                &mut aux,
                Some(u),
            ) {
                Ok(owner) => owner,
                Err((_, error)) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(narf_console::Writer, "tunnel MST connect: {error:?}");
                    return TestResult::Fail("128b/132b MST must light through the tunnel");
                }
            };
            let streams = if one_sink { 1 } else { 2 };
            if owner.stream_count() != streams
                || owner.streams.iter().any(|s| {
                    s.route.probe.uhbr.as_deref().map(|p| {
                        (
                            p.link.pipe_bpp,
                            p.stream.tu,
                            p.stream.m_n,
                            p.tunnel.is_none(),
                        )
                    }) != Some((bpp, tu, mn, true))
                })
            {
                return TestResult::Fail("each stream runs Linux's UHBR10 x2 MTP at its bpp");
            }
            let bw_requests = |io: &ExtFake| -> Vec<u8> {
                io.sink
                    .borrow()
                    .tunnel_log
                    .iter()
                    .filter_map(|&(a, v)| (a == tunnel::DP_REQUEST_BW).then_some(v))
                    .collect()
            };
            if bw_requests(&io) != requests {
                return TestResult::Fail("the tunnel allocation is the streams' sum before each");
            }
            let clock = io.read32(XeLpgPort::Tc2.port_clock_ctl());
            if clock & crate::intel_gpu_xelpg::XE3_DDI_CLOCK_SELECT_MASK
                != crate::intel_gpu_xelpg::DDI_CLOCK_SELECT_TBT_312_5 << 12
            {
                return TestResult::Fail("UHBR10 over TBT runs the fabric's 312.5 MHz select");
            }
            if owner.stop_aux(&io, &mut aux).is_err() || !owner.stopped() {
                return TestResult::Fail("the tunnelled MST link must stop");
            }
            {
                let sink = io.sink.borrow();
                let last_request = sink
                    .tunnel_log
                    .iter()
                    .rposition(|&(a, _)| a == tunnel::DP_REQUEST_BW);
                let off = sink.tunnel_log.iter().rposition(|&w| w == (ctl, 0x00));
                if !matches!((last_request, off), (Some(r), Some(o)) if r < o) {
                    return TestResult::Fail("stop: the allocation freed, then BWA disabled");
                }
            }
            if bw_requests(&io) != after_stop || owner.tunnel.is_some() {
                return TestResult::Fail("each stream's stop decreases the allocation to 0");
            }
            if owner.release(&io).is_err() {
                return TestResult::Fail("the tunnelled MST link must release");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_ptl_mst_128b132b_through_dp_tunnel
    );

    /// What keeps a hub off 128b/132b MST under `narf.intel.uhbr=1`: no
    /// 128b/132b support (the 8b/10b MST route stands), and Thunderbolt alt
    /// mode, refused typed before any sideband message (display 14: no TBT
    /// UHBR clock).
    fn smoke_mtl_mst_uhbr_link_choice() -> TestResult {
        let io = ExtFake::new(XeLpgPort::Tc1, DpSink::new(0x14, edid()));
        let Ok(link) = probe_link(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) else {
            return TestResult::Fail("the hub must answer its DPCD");
        };
        if uhbr_mst_link(&io, &link) != Ok(None) || link.release(&io).is_err() {
            return TestResult::Fail("an 8b/10b hub keeps 8b/10b MST");
        }
        let io = ExtFake::new(
            XeLpgPort::Tc2,
            DpSink::dp20(0x14, edid(), uhbr::DP_UHBR10 | uhbr::DP_UHBR20),
        );
        io.pica_isr
            .set(crate::intel_gpu_xelpg_hpd::pica_tbt_hotplug(1));
        let Ok(link) = probe_link(&io, Generation::MeteorLake, XeLpgPort::Tc2, false) else {
            return TestResult::Fail("the TBT hub must answer its DPCD");
        };
        if !link.tbt()
            || uhbr_mst_link(&io, &link) != Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Tbt))
        {
            return TestResult::Fail("display-14 TBT has no UHBR clock: typed Tbt");
        }
        let _ = link.release(&io);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_mst",
        smoke_mtl_mst_uhbr_link_choice
    );
}
