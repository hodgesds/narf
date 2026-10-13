//! Orchestrated native Navi48 modeset on one legacy DP SST or TMDS HDMI
//! connector: choose the first answering DisplayPort sink (else the first HDMI
//! sink) and its EDID preferred mode, admit it,
//! then run the retained owners' preparations in their dependency order and
//! make the uploaded surface visible. Inherited (GOP) consumers must already
//! be retired; the clock owners refuse otherwise.
use super::*;
use crate::amdgpu_dcn401_dml as dml;
use crate::amdgpu_dml::Timing;
use crate::dp_link_training::LinkRate;

/// The DIO stream and pipe are independent of the PHY; the first native
/// scanout uses one index for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModesetError {
    /// No routed DP connector answered with DPCD and an EDID preferred mode,
    /// and no HDMI connector with an HDMI (not DVI) sink.
    NoSink,
    /// The preferred mode cannot be carried by the sink's maximum link.
    Link,
    Boot(Error),
    Clocks(clocks::Error),
    PipeClocks(dccg::Error),
    Display(otg::Error),
}
impl From<otg::Error> for ModesetError {
    fn from(e: otg::Error) -> Self {
        Self::Display(e)
    }
}

/// A sink chosen for the first native scanout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// Index into `display_paths()`, the `port` of every DP operation.
    pub port: usize,
    pub timing: Timing,
    /// DP link settings; unused (zero lanes) for HDMI.
    pub lanes: u8,
    pub rate: LinkRate,
    /// The sink's base EDID block, reported to DRM verbatim.
    pub edid: [u8; 128],
    /// A TMDS HDMI sink rather than DP SST.
    pub hdmi: bool,
}

/// The result of a successful modeset, retained by the caller for teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modeset {
    pub selection: Selection,
    pub pipe: u8,
    pub plan: dml::Plan,
    pub scanout: otg::ScanoutRunning,
}

/// What a periodic check of a running modeset found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// Sink present, link locked, scanout fetching; the fresh frame count.
    Running(u32),
    /// Debounced HPD low: tear down with `unplug_modeset`.
    Unplugged,
    /// The D0 sink lost lane lock: `retrain_modeset` (Linux's link loss).
    LinkLost(otg::DpLinkStatus),
}

/// Maximum DPCD link of a DP receiver: MAX_LINK_RATE and MAX_LANE_COUNT.
fn max_link(dpcd: &[u8; 16]) -> Option<(u8, LinkRate)> {
    let lanes = dpcd[2] & 0x1f;
    let rate = LinkRate::from_dpcd_byte(dpcd[1])?;
    matches!(lanes, 1 | 2 | 4).then_some((lanes, rate))
}

/// The frontend's 8b/10b payload ceiling for 8-bpc RGB.
pub fn link_fits(timing: &Timing, lanes: u8, rate: LinkRate) -> bool {
    u64::from(timing.pixel_clock_khz) * 3 * 8 <= rate as u64 * 27_000 * 8 * u64::from(lanes)
}

/// An HDMI sink, not DVI: some CTA-861 extension carries the HDMI Licensing
/// VSDB. HDMI data islands (GC and AVI packets) must not reach a DVI sink.
pub fn hdmi_sink(edid: &[u8]) -> bool {
    edid.chunks_exact(128).skip(1).any(|block| {
        narf_edid::cta861::CtaExtension::parse(block)
            .ok()
            .and_then(|c| c.hdmi_vsdb())
            .is_some()
    })
}

/// The base block's preferred mode. Extension blocks follow the base block in
/// the scanned EDID; the base parser takes exactly one 128-byte block.
fn preferred(edid: &[u8]) -> Option<Timing> {
    narf_edid::Block::parse(edid.get(..128)?)
        .ok()
        .and_then(|b| b.preferred_mode())
        .and_then(|d| crate::amdgpu_dcn_display::timing_from_edid(&d).ok())
}

/// First routed DP port whose sink answered with DPCD and an EDID preferred
/// mode the DCN timing model accepts, at the sink's maximum link; failing
/// that, the first HDMI sink whose preferred mode fits unscrambled TMDS.
pub fn select(
    paths: &[inventory::Path],
    ports: &[display::Port],
) -> Result<Selection, ModesetError> {
    let mut link_short = false;
    for port in ports {
        if port.path.connector != inventory::Connector::DisplayPort {
            continue;
        }
        let Ok(sink) = &port.sink else { continue };
        let Some((lanes, rate)) = sink.dpcd.as_ref().and_then(max_link) else {
            continue;
        };
        let Some(timing) = preferred(&sink.edid) else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        if !link_fits(&timing, lanes, rate) {
            link_short = true;
            continue;
        }
        return Ok(Selection {
            port: index,
            timing,
            lanes,
            rate,
            edid,
            hdmi: false,
        });
    }
    for port in ports {
        if port.path.connector != inventory::Connector::HdmiTypeA {
            continue;
        }
        let Ok(sink) = &port.sink else { continue };
        if !hdmi_sink(&sink.edid) {
            continue;
        }
        let Some(timing) = preferred(&sink.edid) else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
            continue;
        };
        let Some(edid) = sink.edid.get(..128).and_then(|b| b.try_into().ok()) else {
            continue;
        };
        if timing.pixel_clock_khz > otg::TMDS_MAX_KHZ {
            link_short = true;
            continue;
        }
        return Ok(Selection {
            port: index,
            timing,
            lanes: 0,
            rate: LinkRate::Rbr,
            edid,
            hdmi: true,
        });
    }
    Err(if link_short {
        ModesetError::Link
    } else {
        ModesetError::NoSink
    })
}

/// Link settings to try, best first: drop the rate; below RBR halve the lanes
/// and restart from the sink's maximum rate (narf's documented DP fallback
/// ladder, as in `dp_link_training`). Settings that cannot carry the mode are
/// never tried.
pub fn link_candidates(timing: &Timing, lanes: u8, rate: LinkRate) -> Vec<(u8, LinkRate)> {
    let mut out = Vec::new();
    let mut l = lanes;
    while l >= 1 {
        let mut r = Some(rate);
        while let Some(current) = r {
            if link_fits(timing, l, current) {
                out.push((l, current));
            }
            r = current.next_lower();
        }
        l /= 2;
    }
    out
}

/// Linear XRGB8888 pitch in pixels: 64-pixel (256-byte) aligned.
pub fn mode(timing: Timing) -> dml::Mode {
    dml::Mode {
        timing,
        pitch: (timing.h_active + 63) & !63,
    }
}

/// Global clocks at least as fast as the plan's DISPCLK and DPPREFCLK.
pub fn clock_request(plan: &dml::Plan) -> clocks::Request {
    clocks::Request {
        displays: 1,
        display_khz: plan.clocks.dispclk_khz,
        dpp_khz: plan.clocks.dpprefclk_khz,
        dtb_khz: 1, // legacy DIO: lowest DTB level
    }
}

/// DP's DPREF DTO, or for RGB TMDS the divide-by-four pixel rate (Linux's
/// dcn401_calculate_dccg_tmds_div_value) from the PHY PLL.
pub fn pipe_clock_request(pipe: u8, plan: &dml::Plan, hdmi: bool) -> dccg::Request {
    dccg::Request {
        pipe,
        dpp_khz: plan.clocks.dppclk_khz,
        pixel: if hdmi {
            dccg::PixelClock::Tmds {
                divider: dccg::TmdsDivider::By4,
            }
        } else {
            dccg::PixelClock::DisplayPort {
                pixel_hz: u64::from(plan.mode.timing.pixel_clock_khz) * 1000,
            }
        },
    }
}

pub fn timing_request(pipe: u8, plan: &dml::Plan, hdmi: bool) -> otg::Request {
    otg::Request {
        pipe,
        timing: plan.mode.timing,
        sync: plan.sync,
        signal: if hdmi {
            otg::Signal::Tmds
        } else {
            otg::Signal::DisplayPort
        },
    }
}

/// What retiring the inherited (GOP) display found and stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritedRetired {
    /// DIO streams whose video was active on entry.
    pub active_streams: u8,
    /// Timing generators found running after the streams were disabled.
    pub running_timing: u8,
    /// DIO frontends found routed to a DP SST backend, by bit.
    pub routed_frontends: u8,
    /// `display_paths()` indices whose transmitter firmware disable was sent.
    pub disabled_ports: u8,
}

impl ColdBoot {
    /// Retire whatever legacy DP SST output the firmware left running, in
    /// native dependency order: blank every DIO stream (a no-op when already
    /// blank), disable each board-routed DP backend that has a frontend
    /// routed to it, retire those encoders, then the planes and all timing.
    /// A port with no routed frontend is refused during planning, before any
    /// write, and skipped; any other failure stops here and quarantines.
    /// # Safety
    /// Stop every CPU writer of the inherited framebuffer's scanout role (its
    /// memory stays excluded from the pool), and exclude firmware/FAMS and
    /// concurrent display/audio/link/clock/power writers. HDMI, HPO and MST
    /// output are not retired here; their live state makes this fail.
    pub async unsafe fn retire_inherited_display(
        &mut self,
    ) -> Result<InheritedRetired, ModesetError> {
        let mut found = InheritedRetired {
            active_streams: 0,
            running_timing: 0,
            routed_frontends: 0,
            disabled_ports: 0,
        };
        // SAFETY: as documented; every step validates its own preconditions.
        unsafe {
            for i in 0..4 {
                if self
                    .blank_display_dp_stream(otg::DpStream::Dio(i))
                    .await?
                    .was_active
                {
                    found.active_streams |= 1 << i;
                }
            }
            let ports = self
                .display_paths()
                .map_err(|_| ModesetError::NoSink)?
                .len();
            for port in 0..ports.min(8) {
                let path = self.display_paths().map_err(|_| ModesetError::NoSink)?[port];
                if path.connector != inventory::Connector::DisplayPort {
                    continue;
                }
                match self.disable_display_dp_sst(port).await {
                    Ok(d) => {
                        found.routed_frontends |= 1 << d.frontend;
                        if d.command_sent {
                            found.disabled_ports |= 1 << port;
                        }
                    }
                    // Planning refusals (no single routed frontend) write
                    // nothing and leave the owner reusable.
                    Err(otg::Error::Unsupported)
                        if self
                            .display_timing_status()
                            .is_ok_and(|s| s.state.reusable()) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            // An active stream must have been found behind some backend.
            if found.active_streams & !found.routed_frontends != 0 {
                return Err(ModesetError::Display(otg::Error::Busy));
            }
            for i in 0..4 {
                if found.routed_frontends & 1 << i != 0 {
                    self.retire_display_dp_encoder(otg::DpStream::Dio(i))
                        .await?;
                }
            }
            self.retire_display_planes().await?;
            // Only running generators: an idle (or soft-reset) OTG needs none.
            let running = self.display_running_timing()?;
            found.running_timing = running;
            for pipe in 0..4 {
                if running & 1 << pipe != 0 {
                    self.retire_display_timing(pipe).await?;
                }
            }
        }
        Ok(found)
    }
    /// Light the first answering DP SST sink at its preferred mode on `pipe`,
    /// with `fill(y, row)` supplying each visible row before fetch starts.
    /// # Safety
    /// Inherited display consumers must be retired. Exclude firmware/FAMS and
    /// concurrent display/hub/VM/IRQ/clock/reset/power/link writers; retain
    /// every owner and allocation on every outcome, including cancellation.
    /// A failure leaves the owners where they stopped; nothing is unwound.
    pub async unsafe fn modeset_display(
        &mut self,
        pipe: u8,
        mut fill: impl FnMut(u32, &mut [u32]),
    ) -> Result<Modeset, ModesetError> {
        if pipe >= 4 {
            return Err(ModesetError::Display(otg::Error::Invalid));
        }
        let ports = self.scan_display().await.map_err(ModesetError::Boot)?;
        let paths = self.display_paths().map_err(|_| ModesetError::NoSink)?;
        let selection = select(paths, &ports)?;
        let mode = mode(selection.timing);
        // The first clock request starts PMFW and publishes the DPM levels
        // admission needs; requests are clamped up to each clock's minimum.
        let floor = clocks::Request {
            displays: 1,
            display_khz: 1,
            dpp_khz: 1,
            dtb_khz: 1,
        };
        self.prepare_display_clocks(floor)
            .await
            .map_err(ModesetError::Clocks)?;
        let plan = self.display_admission(&mode)?;
        self.prepare_display_clocks(clock_request(&plan))
            .await
            .map_err(ModesetError::Clocks)?;
        self.prepare_display_pipe_clocks(pipe_clock_request(pipe, &plan, selection.hdmi))
            .await
            .map_err(ModesetError::PipeClocks)?;
        let (width, height) = (selection.timing.h_active, selection.timing.v_active);
        // SAFETY: the caller's exclusion and retention obligations cover each
        // retained owner below; every step validates its own preconditions.
        unsafe {
            self.retire_display_planes().await?;
            self.set_display_hubp_power(pipe, true).await?;
            self.prepare_display_surface(otg::SurfaceRequest {
                pipe,
                width,
                height,
                format: otg::SurfaceFormat::Xrgb8888,
            })
            .await?;
            let mut row = alloc::vec![0u32; width as usize];
            for y in 0..height {
                fill(y, &mut row);
                self.upload_display_surface(pipe, 0, y, &row)?;
            }
            self.prepare_display_memory(pipe).await?;
            self.prepare_display_timing(timing_request(pipe, &plan, selection.hdmi))
                .await?;
            self.prepare_display_blank(otg::BlankRequest {
                pipe,
                depth: otg::ColorDepth::Bpc8,
            })
            .await?;
            self.prepare_display_dpp(pipe).await?;
            self.prepare_display_mpc(pipe)?;
            self.prepare_display_requestor(pipe).await?;
            self.prepare_display_deadlines(pipe, &plan).await?;
            match self.enable_display_hpd(selection.port) {
                // A board without an HPD selector still lights; monitoring
                // then reports Unsupported.
                Ok(()) | Err(otg::Error::Unsupported) => {}
                Err(e) => return Err(e.into()),
            }
            let (selection, scanout) = self.start_link(selection, pipe).await?;
            Ok(Modeset {
                selection,
                pipe,
                plan,
                scanout,
            })
        }
    }
    /// Train the selected sink down the fallback ladder from its selection,
    /// then start the frontend, video and scanout of the staged `pipe`.
    /// # Safety
    /// As for `modeset_display`, with the pipe's timing, surface and
    /// deadlines prepared and the port's PHY disabled.
    async unsafe fn start_link(
        &mut self,
        selection: Selection,
        pipe: u8,
    ) -> Result<(Selection, otg::ScanoutRunning), ModesetError> {
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            let port = selection.port;
            if selection.hdmi {
                let request = otg::HdmiLinkRequest { stream: pipe, pipe };
                self.prepare_display_hdmi_link(port, request).await?;
                self.start_display_hdmi_video(port).await?;
                let scanout = self.start_display_scanout(pipe).await?;
                return Ok((selection, scanout));
            }
            let mut selection = selection;
            let mut trained = false;
            let mut refused = ModesetError::Link;
            let transmitter =
                self.display_paths().map_err(|_| ModesetError::NoSink)?[port].transmitter;
            for (lanes, rate) in link_candidates(&selection.timing, selection.lanes, selection.rate)
            {
                self.enable_display_dp_phy(port, otg::DpPhySettings { lanes, rate })
                    .await?;
                match self.train_display_dp_link(port, false).await {
                    Ok(_) => {
                        (selection.lanes, selection.rate) = (lanes, rate);
                        trained = true;
                        break;
                    }
                    // The sink refused this link and training proved its idle
                    // exit: stop the link (sink D3, PHY off) and try the next
                    // setting, as Linux's training retries do.
                    Err(e @ otg::Error::DpTraining(_))
                        if self
                            .display_timing_status()
                            .is_ok_and(|s| s.state == otg::State::DpLinkRefused(transmitter)) =>
                    {
                        refused = e.into();
                        self.stop_display_dp_link(port).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if !trained {
                return Err(refused);
            }
            self.prepare_display_dp_frontend(port, otg::DpFrontendRequest { stream: pipe, pipe })
                .await?;
            self.start_display_dp_video(port).await?;
            let scanout = self.start_display_scanout(pipe).await?;
            Ok((selection, scanout))
        }
    }
    /// Check a running modeset: hot-plug first (no AUX to an absent sink),
    /// then the sink's lane lock, then the scanout itself.
    /// # Safety
    /// As for `modeset_display`; exclude other AUX users of the port.
    pub async unsafe fn check_modeset(&mut self, m: &Modeset) -> Result<Health, ModesetError> {
        let port = m.selection.port;
        if !self.display_hpd(port)? {
            return Ok(Health::Unplugged);
        }
        // SAFETY: as documented above.
        unsafe {
            // TMDS has no sink-side lock status to read.
            if !m.selection.hdmi {
                let link = self.display_dp_link_status(port).await?;
                if link.lost() {
                    return Ok(Health::LinkLost(link));
                }
            }
            Ok(Health::Running(self.check_display_scanout(m.pipe).await?))
        }
    }
    /// Linux's dp_handle_link_loss: stop the stream and link, then train
    /// again from the current setting (falling back as needed) and restart
    /// video and scanout of the retained surface.
    /// # Safety
    /// As for `modeset_display`; stop every CPU writer of the surface first.
    pub async unsafe fn retrain_modeset(&mut self, m: &mut Modeset) -> Result<(), ModesetError> {
        let port = m.selection.port;
        if m.selection.hdmi {
            return Err(ModesetError::Display(otg::Error::Unsupported));
        }
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            self.stop_display_scanout(m.pipe).await?;
            self.stop_display_dp_video(port).await?;
            self.stop_display_dp_frontend(port).await?;
            self.stop_display_dp_link(port).await?;
            (m.selection, m.scanout) = self.start_link(m.selection, m.pipe).await?;
        }
        Ok(())
    }
    /// Tear down a modeset whose sink left: as `stop_modeset`, but the link
    /// stops without addressing the sink, and only while HPD stays low.
    /// # Safety
    /// As for `stop_modeset`.
    pub async unsafe fn unplug_modeset(&mut self, m: &Modeset) -> Result<(), ModesetError> {
        let port = m.selection.port;
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            self.stop_display_scanout(m.pipe).await?;
            if m.selection.hdmi {
                // TMDS addresses no sink: the ordinary stop applies.
                self.stop_hdmi(port).await?;
            } else {
                self.stop_display_dp_video(port).await?;
                self.stop_display_dp_frontend(port).await?;
                self.stop_unplugged_display_dp_link(port).await?;
            }
            self.retire_display_timing(m.pipe).await?;
            self.retire_display_planes().await?;
        }
        Ok(())
    }
    /// Reverse a successful modeset down to a disabled PHY with timing and
    /// planes retired. The surface allocation is retained by its pipe.
    /// # Safety
    /// As for `modeset_display`; stop every CPU writer of the surface first.
    pub async unsafe fn stop_modeset(&mut self, m: &Modeset) -> Result<(), ModesetError> {
        let port = m.selection.port;
        // SAFETY: as documented above; each step checks its predecessor state.
        unsafe {
            self.stop_display_scanout(m.pipe).await?;
            if m.selection.hdmi {
                self.stop_hdmi(port).await?;
            } else {
                self.stop_display_dp_video(port).await?;
                self.stop_display_dp_frontend(port).await?;
                self.stop_display_dp_link(port).await?;
            }
            self.retire_display_timing(m.pipe).await?;
            self.retire_display_planes().await?;
        }
        Ok(())
    }
    /// Mute and stop HDMI video, then the transmitter and frontend.
    /// # Safety
    /// As for `stop_modeset`, with scanout stopped.
    async unsafe fn stop_hdmi(&mut self, port: usize) -> Result<(), ModesetError> {
        // SAFETY: the caller's obligations; each step checks its predecessor.
        unsafe {
            self.stop_display_hdmi_video(port).await?;
            self.stop_display_hdmi_link(port).await?;
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_modeset_tests.rs"]
mod tests;
