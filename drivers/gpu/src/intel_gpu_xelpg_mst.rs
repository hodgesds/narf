//! Display-14 MST ownership over the shared sideband manager. The first
//! stream owns the link/transport; secondary streams own only their pipe.
//! A topology change rebuilds the stream set in reverse stop order, keeping
//! the primary transport alive until the last secondary has stopped.
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
}

impl MtlMstRoute {
    pub fn port(&self) -> XeLpgPort {
        self.link.port
    }
    pub fn first(&self) -> Option<(Pipe, Mode, Framebuffer)> {
        self.first
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

    pub(super) fn connect<M: MmioWindow + ?Sized>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        let mut aux = crate::intel_gpu_mst::IntelMstAux::xelpdp(io, link.port, link.tbt());
        Self::connect_aux(io, link, decl, display, alloc, &mut aux)
    }

    fn connect_aux<M: MmioWindow + ?Sized, A: MstAux>(
        io: &M,
        link: LinkProbe,
        decl: MtlPortDecl,
        display: &MtlDisplay,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
        aux: &mut A,
    ) -> Result<Box<Self>, (Box<Self>, ExternalError)> {
        let mut owner = Box::new(Self {
            link,
            manager: Manager::new(),
            topology: None,
            streams: Vec::new(),
            failed: None,
            first: None,
            stopped: false,
        });
        let result = owner.start(io, decl, display, alloc, aux);
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
        let caps = DpcdCaps::decode(&self.link.raw);
        let source = SourceCaps {
            max_rate: TrainRate::Hbr3,
            max_lanes: self.link.tc.map_or(4, |tc| tc.max_lanes),
        };
        let negotiated = negotiate(&source, &caps, u64::MAX);
        let link_kbps = negotiated.rate.payload_kbps(negotiated.lanes) as u32;
        let mut slot = 1u8;
        for sink in sinks {
            let topology = self.topology.as_ref().expect("probed");
            let edid = complete(self.manager.read_edid_block(aux, topology, sink, 0))?;
            let mode = crate::intel_gpu_dp::mode_from_edid(&edid)
                .map_err(|_| ExternalError::Mst(MstFailure::Sideband))?;
            let pbn = crate::dp_mst::calc_pbn_mode(mode.pixel_clock_khz, 24 * 16);
            let slots = crate::dp_mst::time_slots(pbn, crate::dp_mst::pbn_div(link_kbps));
            let path = topology
                .path(sink)
                .ok_or(ExternalError::Mst(MstFailure::Sideband))?;
            if slots == 0
                || slots > 63
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
            let pipe = match free_pipe(io) {
                Ok(pipe) => pipe,
                Err(ExternalError::NoFreePipe) => break,
                Err(error) => return Err(error),
            };
            let vcpi = pipe as u8 + 1; // Intel's payload ID is pipe + 1.
            let fb =
                alloc(&mode).ok_or(ExternalError::Modeset(ModesetError::InvalidFramebuffer))?;
            let mut raw_edid = [0; EDID_CAPACITY];
            raw_edid[..128].copy_from_slice(&edid);
            let master = self
                .streams
                .first()
                .map_or(pipe.transcoder(), |s| s.route.pipe.transcoder());
            let probe = MtlSinkProbe {
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
                edid: raw_edid,
                edid_len: 128,
                dsc: None,
                pipe_bpp: 24,
            };
            crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &mode)?;
            let branch = topology.branches[sink.branch].clone();
            let endpoint = *topology
                .port(sink)
                .ok_or(ExternalError::Mst(MstFailure::Sideband))?;
            complete(crate::dp_mst_mgr::write_payload(
                aux,
                vcpi,
                slot,
                slots as u8,
            ))?;
            let mut allocate = |_| {
                sink_act(aux)?;
                let request = crate::dp_mst::Request::AllocatePayload {
                    port: sink.port,
                    vcpi,
                    pbn: pbn as u16,
                    sdp_stream_sinks: (0..endpoint.info.sdp_streams).collect(),
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
                None => activate_with_payload(io, probe, fb, display, &mut allocate),
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

    fn stop_aux<M: MmioWindow + ?Sized, A: MstAux>(
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
        }
        while !self.streams.is_empty() {
            let index = self.streams.len() - 1;
            let stream = &mut self.streams[index];
            let master = stream.route.probe.mst.expect("MST stream").master;
            source_payload(io, stream.route.pipe.transcoder(), master, false)?;
            stop_stream(io, &mut stream.route, index != 0)?;
            let pipes = stream.route.reservation.as_ref().map(|rp| rp.pipes.clone());
            let stream = self.streams.pop().expect("selected");
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

#[allow(clippy::result_large_err)]
fn activate_secondary<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlSinkProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
    pipes: Pipes,
    payload: &mut dyn FnMut(Transcoder) -> Result<(), ExternalError>,
) -> Result<MtlExternalRoute, ActivateError> {
    let pipe = match free_pipe(io) {
        Ok(pipe) => pipe,
        Err(error) => return Err(ActivateError::Refused(probe, error)),
    };
    let choice = PipeChoice { pipe, pipes };
    let ext = match external_pipe(
        &choice,
        probe.port,
        &probe.mode,
        &fb,
        link_clock_khz(probe.negotiated.rate),
        None,
        24,
    ) {
        Ok(ext) => ext,
        Err(error) => return Err(ActivateError::Refused(probe, error)),
    };
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
        state: RouteState::Stopped,
    };
    let result = (|| {
        request_pipe_wells(io, pipe)?;
        route.reservation = Some(reserve_pipe(io, choice, &ext, display.pipe_dmc)?);
        write(
            io,
            trans_clk_sel(pipe.transcoder()),
            trans_clk_sel_port(route.port()),
        )?;
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
        rp.pipes.disable_primary(io, rp.pipe)?;
        rp.pipes.disable(io, rp.pipe)?;
        let trans = rp.transcoder();
        let func = read(io, trans_ddi_func_ctl(trans))?;
        write(
            io,
            trans_ddi_func_ctl(trans),
            func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE | (1 << 8)),
        )?;
        write(io, trans_clk_sel(trans), 0)?;
        rp.pipes.release(io, rp.pipe, rp.dmc)?;
    }
    route.state = RouteState::Stopped;
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::dp_mst_mgr::tests::Hub;
    use crate::intel_gpu_xelpg_external::tests::{edid_for, ExtFake, Sink as DpSink};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Branch<'a> {
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
    fn branch(io: &ExtFake) -> Branch<'_> {
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
        if io.read32(0x61540) & (1 << 27) == 0
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
}
