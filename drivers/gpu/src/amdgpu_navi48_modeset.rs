//! Orchestrated native Navi48 modeset on one legacy DP SST connector: choose
//! the first answering DisplayPort sink and its EDID preferred mode, admit it,
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
    /// No routed DP connector answered with DPCD and an EDID preferred mode.
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
    pub lanes: u8,
    pub rate: LinkRate,
}

/// The result of a successful modeset, retained by the caller for teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modeset {
    pub selection: Selection,
    pub pipe: u8,
    pub plan: dml::Plan,
    pub scanout: otg::ScanoutRunning,
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

/// First routed DP port whose sink answered with DPCD and an EDID preferred
/// mode the DCN timing model accepts, at the sink's maximum link.
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
        let Some(timing) = narf_edid::Block::parse(&sink.edid)
            .ok()
            .and_then(|b| b.preferred_mode())
            .and_then(|d| crate::amdgpu_dcn_display::timing_from_edid(&d).ok())
        else {
            continue;
        };
        let Some(index) = paths.iter().position(|p| *p == port.path) else {
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
        });
    }
    Err(if link_short {
        ModesetError::Link
    } else {
        ModesetError::NoSink
    })
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

pub fn pipe_clock_request(pipe: u8, plan: &dml::Plan) -> dccg::Request {
    dccg::Request {
        pipe,
        dpp_khz: plan.clocks.dppclk_khz,
        pixel: dccg::PixelClock::DisplayPort {
            pixel_hz: u64::from(plan.mode.timing.pixel_clock_khz) * 1000,
        },
    }
}

pub fn timing_request(pipe: u8, plan: &dml::Plan) -> otg::Request {
    otg::Request {
        pipe,
        timing: plan.mode.timing,
        sync: plan.sync,
        signal: otg::Signal::DisplayPort,
    }
}

impl ColdBoot {
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
        self.prepare_display_pipe_clocks(pipe_clock_request(pipe, &plan))
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
            self.prepare_display_timing(timing_request(pipe, &plan))
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
            let port = selection.port;
            self.enable_display_dp_phy(
                port,
                otg::DpPhySettings {
                    lanes: selection.lanes,
                    rate: selection.rate,
                },
            )
            .await?;
            self.train_display_dp_link(port, false).await?;
            self.prepare_display_dp_frontend(port, otg::DpFrontendRequest { stream: pipe, pipe })
                .await?;
            self.start_display_dp_video(port).await?;
            let scanout = self.start_display_scanout(pipe).await?;
            Ok(Modeset {
                selection,
                pipe,
                plan,
                scanout,
            })
        }
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
            self.stop_display_dp_video(port).await?;
            self.stop_display_dp_frontend(port).await?;
            self.stop_display_dp_link(port).await?;
            self.retire_display_timing(m.pipe).await?;
            self.retire_display_planes().await?;
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_modeset_tests.rs"]
mod tests;
