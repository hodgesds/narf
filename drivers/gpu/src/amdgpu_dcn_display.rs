//! The DCN314 external DisplayPort bring-up: choose a mode from the sink's
//! EDID, reserve a scanout, derive the mode math, and drive every block in the
//! order Linux's `dcn20_hwseq.c` enable-stream path uses.
//!
//! This module owns no registers of its own. It is the sequence, and the order
//! is the substance: clocks before timing, timing before the plane, a blanked
//! plane before the timing generator starts, a trained link before the stream
//! encoder describes it, and pixels released only once all of that holds.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_clk::{self as clk, ClockManager},
    amdgpu_dcn_dccg::{Dccg, Divider, SinglePipe},
    amdgpu_dcn_hubp::{Hubp, Surface},
    amdgpu_dcn_inventory as inventory,
    amdgpu_dcn_otg::{GlobalSync, Otg},
    amdgpu_dcn_plane::{Dpp, Encoding, Mpc, Opp},
    amdgpu_dcn_stream::{Depth, Stream},
    amdgpu_dio::{self, Route},
    amdgpu_dml::{self as dml, ClockState, Config, Format, Memory, Plane, Timing},
    amdgpu_dml_regs::Registers,
    amdgpu_dmub_boot::Loader,
    amdgpu_dp_training::Limits,
    amdgpu_vram::{Pool, Reservation},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};
use narf_edid::DetailedTiming;
use narf_graphics_driver::generic::GenericFb;
use narf_lib::sync::IrqSafeSpinLock;

/// Scanout surfaces are fetched in 256-byte requests, so the pitch is rounded
/// out to one; the base is page aligned because the pool allocates pages.
const PITCH_ALIGN: u32 = 256;
/// The widest and tallest mode this single-pipe path will drive, taken from the
/// blocks that have to carry them rather than restated here.
///
/// Horizontally that is [`crate::amdgpu_dcn_otg::MAX_SEGMENT_WIDTH`] — 8191,
/// the `OPTC_SEGMENT_WIDTH` field, since this path bypasses ODM and so puts
/// the whole active width into one OPP segment. It used to be 8192, described
/// as "the DML linear swath ceiling", which is neither the right number nor the
/// right reason: the OTG then refused the one extra column, so a 8192-wide
/// sink was accepted here and rejected three steps later.
///
/// Vertically it is the 14-bit `RECOUT_HEIGHT` / `DPG_ACTIVE_HEIGHT` fields
/// `amdgpu_dcn_plane` programs, which bound the plane at 16383 lines.
const MAX_WIDTH: u32 = crate::amdgpu_dcn_otg::MAX_SEGMENT_WIDTH;
const MAX_HEIGHT: u32 = crate::amdgpu_dcn_plane::MAX_DIMENSION;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The sink asks for something this pipeline does not drive.
    Unsupported,
    Invalid,
    Allocation,
    /// The mode needs more than the clocks or buffers can give.
    Bandwidth,
    Mode(dml::Error),
    Hardware(clk::Error),
    Link(crate::amdgpu_dp_training::Error),
    /// The platform's own tables could not answer for something.
    Inventory(inventory::Error),
    /// The USB4 tunnel will not carry this mode.
    Tunnel(crate::amdgpu_dp_tunnel::Error),
}
impl From<dml::Error> for Error {
    fn from(error: dml::Error) -> Self {
        Error::Mode(error)
    }
}
impl From<clk::Error> for Error {
    fn from(error: clk::Error) -> Self {
        Error::Hardware(error)
    }
}
impl From<crate::amdgpu_dp_training::Error> for Error {
    fn from(error: crate::amdgpu_dp_training::Error) -> Self {
        Error::Link(error)
    }
}

/// Translate an EDID detailed timing into the pipeline's shared description.
/// Interlaced modes and anything whose blanking cannot hold its own sync are
/// refused here rather than part way through programming.
pub fn timing_from_edid(detailed: &DetailedTiming) -> Result<Timing, Error> {
    if detailed.interlaced {
        return Err(Error::Unsupported);
    }
    let h_active = detailed.h_active as u32;
    let v_active = detailed.v_active as u32;
    let h_total = h_active + detailed.h_blanking as u32;
    let v_total = v_active + detailed.v_blanking as u32;
    let timing = Timing {
        pixel_clock_khz: detailed.pixel_clock_khz,
        h_active,
        h_total,
        h_front_porch: detailed.h_sync_offset as u32,
        h_sync_width: detailed.h_sync_width as u32,
        v_active,
        v_total,
        v_front_porch: detailed.v_sync_offset as u32,
        v_sync_width: detailed.v_sync_width as u32,
        h_sync_positive: detailed.h_sync_positive,
        v_sync_positive: detailed.v_sync_positive,
    };
    if h_active == 0
        || v_active == 0
        || h_active > MAX_WIDTH
        || v_active > MAX_HEIGHT
        || timing.pixel_clock_khz == 0
        || h_total <= h_active
        || v_total <= v_active
    {
        return Err(Error::Unsupported);
    }
    // The front porch and sync have to fit the blanking they live in; an EDID
    // that says otherwise is malformed, not a mode to approximate.
    if detailed.h_sync_offset as u32 + detailed.h_sync_width as u32 >= h_total - h_active
        || detailed.v_sync_offset as u32 + detailed.v_sync_width as u32 >= v_total - v_active
    {
        return Err(Error::Invalid);
    }
    Ok(timing)
}

/// A scanout reserved from the display pool. Dropping it returns the memory to
/// the pool, so it must outlive every pipe that fetches from it.
#[derive(Debug)]
pub struct Scanout {
    reservation: Reservation,
    width: u32,
    height: u32,
    pitch: u32,
    format: Format,
}
impl Scanout {
    /// Reserve a linear surface for this mode. The pitch is rounded out to a
    /// whole 256-byte request so a line never straddles a partial one.
    pub fn reserve(pool: &Pool, timing: &Timing, format: Format) -> Result<Self, Error> {
        let bytes_per_pixel = format.bytes_per_pixel() as u32;
        let pitch_bytes = timing
            .h_active
            .checked_mul(bytes_per_pixel)
            .ok_or(Error::Invalid)?;
        let pitch_bytes = pitch_bytes.next_multiple_of(PITCH_ALIGN);
        let pitch = pitch_bytes / bytes_per_pixel;
        let size = (pitch_bytes as u64)
            .checked_mul(timing.v_active as u64)
            .ok_or(Error::Invalid)?;
        let reservation = pool.reserve(size).map_err(|_| Error::Allocation)?;
        Ok(Self {
            reservation,
            width: timing.h_active,
            height: timing.v_active,
            pitch,
            format,
        })
    }
    /// The GPU address a hub pixel pipe fetches from.
    pub fn gpu_address(&self) -> u64 {
        self.reservation.address()
    }
    /// Pitch in pixels.
    pub fn pitch(&self) -> u32 {
        self.pitch
    }
    pub fn size(&self) -> u64 {
        self.reservation.size()
    }
    /// Zero the surface. A reservation comes back holding whatever was in that
    /// VRAM, so without this a newly enabled stream shows garbage rather than
    /// black. Yields every page: a 4K surface is tens of megabytes.
    pub async fn clear(&mut self) {
        let mapping = self.reservation.mapping();
        let mut offset = 0;
        while offset + 4 <= mapping.len {
            // SAFETY: the pool holds a permanent CPU mapping of this range, and
            // the reservation is ours until it is dropped.
            unsafe { mapping.write32(offset, 0) };
            offset += 4;
            if offset % 4096 == 0 {
                narf_scheduler::yield_now().await;
            }
        }
        // The pipe must not fetch ahead of these writes.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    /// The surface as a generic framebuffer, addressed by the host-physical
    /// address of its mapping — the same convention the boot framebuffer uses.
    /// Publishing it is not the same as attaching it to a console.
    pub fn generic_fb(&self) -> GenericFb {
        let mapping = self.reservation.mapping();
        GenericFb::new(
            mapping.phys.raw(),
            self.width,
            self.height,
            self.pitch * self.format.bytes_per_pixel() as u32,
            self.format.bytes_per_pixel() as u8 * 8,
        )
    }
    fn surface(&self) -> Surface {
        Surface {
            address: self.gpu_address(),
            format: self.format,
            pitch: self.pitch,
            viewport_width: self.width,
            viewport_height: self.height,
        }
    }
}

/// The active external scanout, and whoever wants to be told when it changes.
///
/// The framebuffer crate calls into this driver, so this driver cannot call back
/// into it. An observer is how the dependency stays one-way: that crate installs
/// a function pointer, the same way it installs the DRM fbdev hook, and this
/// module calls it when a stream comes up or goes down.
/// Told when the active external scanout appears or goes away.
pub type ScanoutObserver = fn(Option<GenericFb>);
static ACTIVE: IrqSafeSpinLock<Option<GenericFb>> = IrqSafeSpinLock::new(None);
static OBSERVER: IrqSafeSpinLock<Option<ScanoutObserver>> = IrqSafeSpinLock::new(None);
pub fn active_scanout() -> Option<GenericFb> {
    *ACTIVE.lock()
}
/// Install the observer. Called once during Late init, before any stream exists.
/// If a stream somehow already runs, the observer is told about it immediately so
/// it cannot miss the edge.
pub fn register_scanout_observer(observer: ScanoutObserver) {
    *OBSERVER.lock() = Some(observer);
    let current = *ACTIVE.lock();
    if current.is_some() {
        observer(current);
    }
}
/// Install an observer and recover the previous one, so a test can put the
/// running system's observer back when it is done.
#[cfg(feature = "kernel-test")]
pub(crate) fn swap_scanout_observer_for_test(
    observer: Option<ScanoutObserver>,
) -> Option<ScanoutObserver> {
    let previous = *OBSERVER.lock();
    *OBSERVER.lock() = observer;
    previous
}
#[cfg(feature = "kernel-test")]
pub(crate) fn publish_for_test(scanout: Option<GenericFb>) {
    publish(scanout);
}
/// Publish a change and notify. The locks are released before the observer runs,
/// so an observer that reads `active_scanout` cannot deadlock against this.
fn publish(scanout: Option<GenericFb>) {
    *ACTIVE.lock() = scanout;
    let observer = *OBSERVER.lock();
    if let Some(observer) = observer {
        observer(scanout);
    }
}

/// Everything one external DisplayPort stream needs, on one pipe.
#[derive(Debug)]
pub struct Pipeline {
    clocks: ClockManager,
    dccg: Dccg,
    otg: Otg,
    hubp: Hubp,
    dpp: Dpp,
    mpc: Mpc,
    opp: Opp,
    stream: Stream,
    source: amdgpu_dio::Source,
    pipe: u8,
    route: Route,
    streaming: bool,
}

/// What the platform must tell the pipeline about itself. None of it can be
/// guessed: the memory configuration sets every watermark, the DCHUB reference
/// scales every latency register, and the VCO decides which clocks exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub memory: Memory,
    pub dchub_refclk_khz: u32,
    pub dentist_vco_khz: u32,
}

impl Pipeline {
    /// # Safety
    /// Caller exclusively owns every block this claims — the clock mailbox, the
    /// clock generator, and the OTG, HUBP, DPP, MPCC, OPP and stream frontend at
    /// `pipe` — plus the `route`'s physical transmitter, for the object's
    /// lifetime. `route` must come from this GPU's VBIOS or the DPIA allocator,
    /// never a UCSI connector number. PCI authority and all register and pool
    /// mappings must be permanent.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        pipe: u8,
        route: Route,
    ) -> Result<Self, Error> {
        // SAFETY: every claim below is covered by this constructor's contract.
        unsafe {
            Ok(Self {
                clocks: ClockManager::new(gpu, authority, pool)?,
                dccg: Dccg::new(gpu, authority)?,
                otg: Otg::new(gpu, authority, pipe)?,
                hubp: Hubp::new(gpu, authority, pipe)?,
                dpp: Dpp::new(gpu, authority, pipe)?,
                mpc: Mpc::new(gpu, authority, pipe)?,
                opp: Opp::new(gpu, authority, pipe)?,
                stream: Stream::new(gpu, authority, route.frontend)?,
                source: amdgpu_dio::Source::new(gpu, authority, route).map_err(Error::Link)?,
                pipe,
                route,
                streaming: false,
            })
        }
    }
    /// Construct the pipeline for a discovered sink, deriving its route from the
    /// board's own display topology instead of leaving the caller to assemble
    /// one. The stream frontend is the route's, so the DIG that carries the
    /// stream is the one the board wired to that connector.
    ///
    /// # Safety
    /// Same contract as [`Pipeline::new`], except that the route is derived here
    /// rather than supplied, so the caller no longer has to guarantee it came
    /// from the VBIOS — only that `vbios` is this device's validated snapshot.
    pub unsafe fn for_sink(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        pipe: u8,
        vbios: &[u8],
        sink: &crate::amdgpu_usbc::Sink,
    ) -> Result<Self, Error> {
        let paths = inventory::display_paths(vbios).map_err(Error::Inventory)?;
        let routes = inventory::routes_for_sink(&paths, sink, pipe).map_err(Error::Inventory)?;
        // A native sink has exactly one route; a tunnelled one borrows a
        // transmitter, so the candidates are tried in preference order. The busy
        // probe comes first because building a pipeline reserves pool memory, and
        // a rejected candidate must not cost any.
        let mut refused = Error::Inventory(inventory::Error::Unsupported);
        for route in routes {
            // SAFETY: live PCI authority and a permanent register mapping.
            match unsafe { inventory::transmitter_busy(gpu, &authority, route.backend) } {
                Ok(false) => {}
                Ok(true) => continue,
                Err(error) => return Err(Error::Inventory(error)),
            }
            // SAFETY: forwarded unchanged; the route is now board-derived.
            match unsafe { Self::new(gpu, authority, pool, pipe, route) } {
                Ok(pipeline) => return Ok(pipeline),
                Err(error) => refused = error,
            }
        }
        Err(refused)
    }
    /// Read the platform constants this pipeline needs. Only valid after
    /// [`Pipeline::start`], since the memory data rate comes from the DPM table.
    ///
    /// # Safety
    /// Caller holds matching PCI authority and a permanent register mapping, and
    /// `vbios` must be this device's validated snapshot.
    pub unsafe fn platform(
        &self,
        gpu: &AmdGpu,
        authority: &Cap<BusDeviceCap, Write>,
        vbios: &[u8],
    ) -> Result<Platform, Error> {
        let levels = self.clocks.levels().ok_or(Error::Invalid)?;
        // SAFETY: forwarded unchanged from this function's contract.
        unsafe { inventory::platform(gpu, authority, vbios, &levels) }.map_err(Error::Inventory)
    }
    pub fn streaming(&self) -> bool {
        self.streaming
    }
    /// Latch the firmware's clock levels. Nothing can be validated until this
    /// succeeds, so it is separate from construction.
    pub async fn start(&mut self) -> Result<(), Error> {
        self.clocks.start().await?;
        Ok(())
    }
    /// Everything a modeset needs, derived without touching any hardware. A
    /// mode that needs more than the firmware's own DPM ceiling is refused here
    /// rather than part way through programming.
    pub fn plan(
        &self,
        timing: &Timing,
        scanout: &Scanout,
        platform: &Platform,
    ) -> Result<Plan, Error> {
        let levels = self.clocks.levels().ok_or(Error::Invalid)?;
        let config = Config {
            timing: *timing,
            plane: Plane {
                format: scanout.format,
                surface_width: scanout.width,
                surface_height: scanout.height,
                viewport_width: scanout.width,
                viewport_height: scanout.height,
                pitch: scanout.pitch,
                // The scaler is bypassed, so one tap each.
                h_taps: 1,
                v_taps: 1,
            },
            dentist_vco_khz: platform.dentist_vco_khz,
            cursors: 0,
        };
        let geometry = config.geometry()?;
        let requirements = config.requirements(&geometry, levels.max_dispclk_khz())?;
        // `requirements` reports the real need even when it exceeds the ceiling,
        // so the refusal is ours to make.
        if requirements.dispclk_khz > levels.max_dispclk_khz()
            || requirements.dppclk_khz > levels.max_dppclk_khz()
        {
            return Err(Error::Bandwidth);
        }
        let clocks = ClockState {
            dcfclk_khz: levels.max_dcfclk_khz(),
            fclk_khz: levels.max_fclk_khz(),
            socclk_khz: levels.max_socclk_khz(),
            dispclk_khz: requirements.dispclk_khz,
            dppclk_khz: requirements.dppclk_khz,
            deep_sleep_dcfclk_khz: requirements.deep_sleep_dcfclk_khz,
        };
        let watermarks = config.watermarks(&platform.memory, &clocks)?;
        let prefetch = config.prefetch(&geometry, &clocks, &watermarks)?;
        let registers = Registers::new(
            &config,
            &geometry,
            &clocks,
            &watermarks,
            &prefetch,
            platform.dchub_refclk_khz,
        )?;
        Ok(Plan {
            clocks,
            registers,
            sync: GlobalSync {
                v_startup_lines: prefetch.v_startup,
                v_update_offset_pix: prefetch.v_update_offset_pix,
                v_update_width_pix: prefetch.v_update_width_pix,
                v_ready_offset_pix: prefetch.v_ready_offset_pix,
            },
        })
    }
    /// Bring the stream up. The order is the substance: clocks before timing,
    /// timing before the plane, a blanked plane before the generator starts, a
    /// trained link before the encoder describes it, and pixels released last.
    /// A failure part way through leaves the stream blanked, not half running.
    pub async fn enable(
        &mut self,
        loader: &mut Loader,
        scanout: &Scanout,
        timing: &Timing,
        platform: &Platform,
        depth: Depth,
        sink_caps: [u8; 16],
    ) -> Result<(), Error> {
        if self.streaming {
            return Err(Error::Invalid);
        }
        let plan = self.plan(timing, scanout, platform)?;
        match self
            .bring_up(loader, scanout, timing, &plan, depth, sink_caps)
            .await
        {
            Ok(()) => {
                self.streaming = true;
                publish(Some(scanout.generic_fb()));
                Ok(())
            }
            Err(error) => {
                // Put the pipe back to blanked so no block is left fetching or
                // sending against a surface the caller is about to release.
                let _ = self.tear_down(loader).await;
                Err(error)
            }
        }
    }
    async fn bring_up(
        &mut self,
        loader: &mut Loader,
        scanout: &Scanout,
        timing: &Timing,
        plan: &Plan,
        depth: Depth,
        sink_caps: [u8; 16],
    ) -> Result<(), Error> {
        // 1. Clocks, with the per-pipe dividers following the global change.
        let mut consumers = SinglePipe {
            dccg: &mut self.dccg,
            pipe: self.pipe,
        };
        // The clock manager takes the subset it owns; DTBCLK is only needed to
        // source a tunnelled stream's clock.
        let requested = clk::Clocks {
            dispclk_khz: plan.clocks.dispclk_khz,
            dppclk_khz: plan.clocks.dppclk_khz,
            dcfclk_khz: plan.clocks.dcfclk_khz,
            deep_sleep_dcfclk_khz: plan.clocks.deep_sleep_dcfclk_khz,
            dtbclk_enabled: self.route.channel == crate::amdgpu_dmub::Channel::Dpia,
        };
        self.clocks.update(requested, false, &mut consumers).await?;
        self.clocks.enter_mission_mode().await?;
        // A DisplayPort stream with one pixel per container and no ODM combine.
        self.dccg
            .set_pixel_rate_div(self.pipe, Divider::By1, Divider::By4)?;
        if self.route.channel == crate::amdgpu_dmub::Channel::Dpia {
            self.dccg.set_dp_stream_clock(
                self.route.aux,
                self.pipe,
                crate::amdgpu_dcn_dccg::StreamClock::Dtbclk,
            )?;
        }

        // 2. Timing, with the global sync the prefetch schedule settled on.
        self.otg.program_timing(timing, &plan.sync)?;

        // 3. The plane, blanked. The pattern generator paints black until the
        // link is up, so nothing undefined is ever sent to the sink.
        self.dpp
            .program(scanout.format, scanout.width, scanout.height)?;
        self.mpc.mux_plane(self.pipe, self.pipe)?;
        self.opp
            .program(Encoding::Rgb, scanout.width, scanout.height)?;
        self.opp.set_blank(true)?;

        // 4. The pipe, still blanked, with the deadlines this surface needs.
        self.hubp.program(&scanout.surface(), &plan.registers)?;
        self.hubp.blank().await?;

        // 5. Start the timing generator. It now sends blanked frames, which is
        // what the sink needs to see before and during training.
        self.otg.enable()?;

        // 6. On a tunnel, ask the host router for the bandwidth this mode needs
        // before the link comes up. A tunnel shares its router with USB data and
        // the other endpoints, so the bandwidth has to be asked for; an endpoint
        // that does no allocation keeps the fixed allocation it was created with,
        // which is not a failure. The endpoint's own non-reduced maxima then
        // bound training, independently of what the sink reports.
        let mut limits = Limits {
            rate: 30,
            lanes: 4,
            pixel_clock_khz: timing.pixel_clock_khz,
            bits_per_pixel: depth.bits_per_pixel() as u8,
            // `train` overwrites this from the route, which is the authority on
            // whether the link is tunnelled.
            dpia: false,
        };
        if self.route.channel == crate::amdgpu_dmub::Channel::Dpia {
            let required = timing
                .pixel_clock_khz
                .saturating_mul(depth.bits_per_pixel());
            match crate::amdgpu_dp_tunnel::allocate(loader, self.route.aux, required).await {
                Ok(allocation) => {
                    if allocation.max_link_rate != 0 {
                        limits.rate = limits.rate.min(allocation.max_link_rate);
                    }
                    if allocation.max_lanes != 0 {
                        limits.lanes = limits.lanes.min(allocation.max_lanes);
                    }
                }
                Err(crate::amdgpu_dp_tunnel::Error::Unsupported) => {}
                Err(error) => return Err(Error::Tunnel(error)),
            }
        }

        // 7. Train the link. The pixel clock and depth bound what rate and lane
        // count are acceptable, so an untrainable mode fails here.
        let settings = self.source.train(loader, sink_caps, limits).await?;

        // 8. Describe the stream to the sink at the rate training settled on.
        self.stream.program(timing, depth, settings.rate)?;

        // 9. Release pixels: the pipe first, then the encoder, then the
        // formatter. Unblanking the formatter last means the sink never sees a
        // frame the pipe was not yet fetching for.
        self.hubp.unblank().await?;
        self.stream.unblank().await?;
        self.opp.set_blank(false)?;
        Ok(())
    }
    /// Take the stream down in the reverse order, and keep going past a failing
    /// step: a block left running would keep fetching from released memory.
    async fn tear_down(&mut self, loader: &mut Loader) -> Result<(), Error> {
        let mut first = Ok(());
        let mut record = |result: Result<(), Error>| {
            if first.is_ok() {
                first = result;
            }
        };
        record(self.opp.set_blank(true).map_err(Error::Hardware));
        record(self.stream.blank().await.map_err(Error::Hardware));
        record(self.hubp.blank().await.map_err(Error::Hardware));
        record(self.source.disable(loader).await.map_err(Error::Link));
        if self.route.channel == crate::amdgpu_dmub::Channel::Dpia {
            // Hand the tunnel's bandwidth back, or the other endpoints on this
            // router never see it again.
            record(
                crate::amdgpu_dp_tunnel::release(loader, self.route.aux)
                    .await
                    .map_err(Error::Tunnel),
            );
        }
        record(self.otg.disable().await.map_err(Error::Hardware));
        record(self.mpc.release(self.pipe).map_err(Error::Hardware));
        if self.route.channel == crate::amdgpu_dmub::Channel::Dpia {
            record(
                self.dccg
                    .set_dp_stream_clock(
                        self.route.aux,
                        self.pipe,
                        crate::amdgpu_dcn_dccg::StreamClock::Disabled,
                    )
                    .map_err(Error::Hardware),
            );
        }
        self.streaming = false;
        publish(None);
        first
    }
    /// Take the stream down. The scanout is safe to release once this returns.
    pub async fn disable(&mut self, loader: &mut Loader) -> Result<(), Error> {
        self.tear_down(loader).await
    }
}

/// A validated modeset, derived entirely from the mode math.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub clocks: ClockState,
    pub registers: Registers,
    pub sync: GlobalSync,
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_display_tests.rs"]
mod tests;
