//! Native Navi22 HDMI TMDS scanout on one pipe: the orchestration Linux DC
//! performs for a single 8-bpc RGB stream at or below 340 MHz, from a reset
//! DCN. Order follows `dcn30_init_hw` (`dccg2_init`, `dcn10_bios_golden_init`
//! when the VBIOS is not in accelerated mode), `hubbub3_program_watermarks`
//! with every pipe idle, the DAL clock update, `dcn20_enable_stream_timing`
//! (`dcn3_program_pix_clk` → VBIOS SetPixelClock, OTG timing and global
//! sync), the plane path (DPP, MPCC, OPP blanked, HUBP with the DML30
//! deadlines, still blanked), OTG start, `enable_link_hdmi` (link-encoder
//! setup, stream frontend, VBIOS STREAM_SETUP, HDMI attributes, AVI
//! InfoFrame, VBIOS transmitter ENABLE) and only then pixels: HUBP fetch,
//! then the OPP pattern generator released. The stop path runs the same
//! blocks in reverse and keeps going past a failing step.
//!
//! Everything is retained on failure: the owners, the published scanout
//! reservation and the step that failed. Nothing is retried or reset.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn30_clk::ClockManager,
    amdgpu_dcn30_hdmi::{self as hdmi, Hdmi},
    amdgpu_dcn30_hubbub::{self as hubbub, Hubbub},
    amdgpu_dcn_hubp::{Hubp, Surface},
    amdgpu_dcn_otg::{GlobalSync, Otg},
    amdgpu_dcn_plane::{Dpp, Encoding, Mpc, Opp},
    amdgpu_dml::{self as dml, Config, Format, Plane, Timing},
    amdgpu_dml30 as dml30,
    amdgpu_navi22_bios::{
        self as bios, PipeAction, PixelClock, Tables, Transmitter, TransmitterAction,
    },
    amdgpu_navi22_display::{Connector, Sink},
    amdgpu_vram::{Pool, Reservation},
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// The console pipe: OTG, HUBP, DPP, MPCC tree and OPP 0, and combo PHY PLL 0
/// (`dc_resource_find_first_free_pll` for the first HDMI stream).
const PIPE: u8 = 0;
const PLL: u8 = 0;
/// No scrambling, so no SCDC handshake: HDMI 1.4 rates only.
pub const MAX_TMDS_KHZ: u32 = hdmi::TMDS_SCRAMBLE_KHZ - 1;
const PITCH_ALIGN: u32 = 256;
// dccg2_init, DCN base index 1 (`dcn_3_0_0_offset.h`).
const MILLISECOND_TIME_BASE_DIV: u64 = 0x0070;
const DISPCLK_FREQ_CHANGE_CNTL: u64 = 0x0071;
const MICROSECOND_TIME_BASE_DIV: u64 = 0x007b;
const REFCLK_CNTL: u64 = 0x0049;
// power_on_plane_resources / hubp1_clk_cntl, DCN base index 2.
const DOMAIN0_PG_CONFIG: u64 = 0x0080;
const DOMAIN1_PG_CONFIG: u64 = 0x0082;
const DOMAIN_POWER_GATE: u32 = 1 << 8;
const DOMAIN_PGFSM_PWR_STATUS: u32 = 0xc000_0000;
const DC_IP_REQUEST_CNTL: u64 = 0x00b2;
const HUBP0_HUBP_CLK_CNTL: u64 = 0x05f4;
const HUBP_CLOCK_ENABLE: u32 = 1 << 0;
/// `BIOS_SCRATCH_6` (nbio 2.3, base index 1) and `ATOM_S6_ACC_MODE`.
const BIOS_SCRATCH_6: u64 = 0x003e;
const ATOM_S6_ACC_MODE: u32 = 1 << 4;
/// The HDP flush page and NBIO's MEMSIZE read for posting (`hdp_v5_0_flush_hdp`).
const HDP_FLUSH: u64 = 0x7f000;
const NBIO_MEMSIZE: u64 = 0xc3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    /// The sink is not an HDMI connector, or nothing usable is connected.
    NoSink,
    /// No EDID timing fits the TMDS, clock or bandwidth limits.
    NoMode,
    Block(crate::amdgpu_dcn_clk::Error),
    Mode(dml::Error),
    Hubbub(hubbub::Error),
    Bios(bios::Error),
    Hdmi(hdmi::Error),
    Inventory(crate::amdgpu_dcn_inventory::Error),
}
impl From<crate::amdgpu_dcn_clk::Error> for Error {
    fn from(e: crate::amdgpu_dcn_clk::Error) -> Self {
        Error::Block(e)
    }
}
impl From<hdmi::Error> for Error {
    fn from(e: hdmi::Error) -> Self {
        Error::Hdmi(e)
    }
}
impl From<bios::Error> for Error {
    fn from(e: bios::Error) -> Self {
        Error::Bios(e)
    }
}

/// Where the sequence is, retained across failure and cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Prepared,
    InitHw,
    Watermarks,
    Clocks,
    PixelClock,
    Timing,
    Plane,
    Fetch,
    Start,
    Link,
    Unblank,
    Running,
    Stopping,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    At(Step),
    Failed { step: Step, error: Error },
}

/// What a lit display reports.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub connector: Connector,
    pub timing: Timing,
    pub prefetch_mode: u8,
    pub v_startup: u32,
    pub dispclk_khz: u32,
    pub dppclk_khz: u32,
    pub scanout: narf_graphics_driver::generic::GenericFb,
}

/// Choose the first EDID timing (EDID order, so the preferred mode first)
/// that a non-scrambled TMDS link, the sink's VSDB ceiling and the DCN30 mode
/// math all accept, with the AVI InfoFrame Linux's `set_avi_info_frame`
/// would send for it. DVI sinks get no InfoFrame.
pub(crate) fn select(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
) -> Result<(Timing, Option<[u8; 36]>, dml30::Plan), Error> {
    use crate::amdgpu_navi48_boot as navi48;
    let caps = navi48::hdmi_caps(&sink.edid);
    let ceiling = if caps.vsdb_max_khz != 0 {
        caps.vsdb_max_khz.min(MAX_TMDS_KHZ)
    } else {
        MAX_TMDS_KHZ
    };
    for timing in navi48::edid_timings(&sink.edid) {
        if timing.pixel_clock_khz > ceiling || timing.pixel_clock_khz < 25_000 {
            continue;
        }
        let Ok(plan) = dml30::plan(&config(&timing, vco_khz), soc) else {
            continue;
        };
        let avi = caps.hdmi.then(|| {
            crate::amdgpu_dcn401_otg::avi_infoframe(
                &timing,
                navi48::hdmi_avi(caps, &timing),
                navi48::limited_range(navi48::broadcast_rgb()),
                false,
            )
        });
        return Ok((timing, avi, plan));
    }
    Err(Error::NoMode)
}
fn pitch(timing: &Timing) -> u32 {
    (timing.h_active * 4).next_multiple_of(PITCH_ALIGN) / 4
}
fn config(timing: &Timing, vco_khz: u32) -> Config {
    Config {
        timing: *timing,
        plane: Plane {
            format: Format::Rgb32,
            surface_width: timing.h_active,
            surface_height: timing.v_active,
            viewport_width: timing.h_active,
            viewport_height: timing.v_active,
            pitch: pitch(timing),
            h_taps: 1,
            v_taps: 1,
        },
        dentist_vco_khz: vco_khz,
        cursors: 0,
    }
}

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

/// The retained single-pipe HDMI output.
pub struct Pipeline {
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    connector: Connector,
    clocks: ClockManager,
    hubbub: Hubbub,
    otg: Otg,
    hubp: Hubp,
    dpp: Dpp,
    mpc: Mpc,
    opp: Opp,
    hdmi: Hdmi,
    /// DCN base indices 1 and 2 and NBIO base indices 1 and 2, as byte offsets.
    dcn1: u64,
    dcn2: u64,
    nbio1: u64,
    nbio2: u64,
    scanout: Option<Reservation>,
    state: State,
    output: Option<Output>,
}
impl core::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pipeline")
            .field("connector", &self.connector)
            .field("state", &self.state)
            .field("output", &self.output)
            .finish()
    }
}

impl Pipeline {
    /// # Safety
    /// Caller exclusively owns this Navi22 GPU's display engine (every pipe
    /// block, the DAL clock mailbox, DCCG, HUBBUB, DIG/VPG/PHY of `connector`)
    /// and the pool, with permanent mappings and PCI authority. No DMUB or
    /// VBIOS client may program display concurrently.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        connector: Connector,
    ) -> Result<Self, Error> {
        let transmitter = connector.path.transmitter;
        let dcn1 = crate::amdgpu_dcn_profile::Profile::Navi22.bank(
            gpu,
            1,
            MICROSECOND_TIME_BASE_DIV as u32,
        )?;
        let nbif = |index, last| {
            crate::amdgpu_psp_ring::bank(
                gpu,
                crate::amdgpu_discovery::HW_ID_NBIF,
                &[
                    (2, 3, 0),
                    (2, 3, 1),
                    (2, 3, 2),
                    (3, 3, 0),
                    (3, 3, 1),
                    (3, 3, 2),
                    (3, 3, 3),
                ],
                index,
                last,
            )
            .map_err(|_| Error::Unsupported)
        };
        // SAFETY: every claim is the caller's exclusive display ownership.
        unsafe {
            Ok(Self {
                gpu: snapshot(gpu)?,
                authority,
                connector,
                clocks: ClockManager::new(gpu, authority).map_err(Error::Block)?,
                hubbub: Hubbub::new(gpu, authority).map_err(Error::Hubbub)?,
                otg: Otg::new(gpu, authority, PIPE)?,
                hubp: Hubp::new(gpu, authority, PIPE)?,
                dpp: Dpp::new(gpu, authority, PIPE)?,
                mpc: Mpc::new(gpu, authority, PIPE)?,
                opp: Opp::new(gpu, authority, PIPE)?,
                hdmi: Hdmi::new(gpu, authority, transmitter, transmitter)?,
                dcn1,
                dcn2: crate::amdgpu_dcn_profile::Profile::Navi22.bank(
                    gpu,
                    2,
                    HUBP0_HUBP_CLK_CNTL as u32,
                )?,
                nbio1: nbif(1, BIOS_SCRATCH_6 as u32)?,
                nbio2: nbif(2, NBIO_MEMSIZE as u32)?,
                scanout: None,
                state: State::At(Step::Prepared),
                output: None,
            })
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn output(&self) -> Option<Output> {
        self.output
    }
    fn reg(&mut self, offset: u64, value: Option<u32>) -> Result<u32, Error> {
        let regs = self.gpu.regs;
        self.authority
            .invoke(Op(|| match value {
                // SAFETY: offsets come from bounded discovery banks.
                Some(v) => unsafe {
                    regs.write32(offset, v);
                    v
                },
                // SAFETY: as above.
                None => unsafe { regs.read32(offset) },
            }))
            .map_err(|_| Error::Block(crate::amdgpu_dcn_clk::Error::Revoked))
    }
    fn bus(&self) -> Rc<RefCell<bios::Mmio>> {
        // SAFETY: Pipeline::new's exclusive display ownership.
        Rc::new(RefCell::new(unsafe {
            bios::Mmio::new(self.gpu.regs, self.authority)
        }))
    }
    /// `dccg2_init` and, when the VBIOS has not entered accelerated mode,
    /// `dcn10_bios_golden_init` (global init then every pipe gated).
    fn init_hw(&mut self, tables: &Tables) -> Result<(), Error> {
        for (reg, value) in [
            (MICROSECOND_TIME_BASE_DIV, 0x0012_0264),
            (MILLISECOND_TIME_BASE_DIV, 0x0011_86a0),
            (DISPCLK_FREQ_CHANGE_CNTL, 0x0e01_003c),
            (REFCLK_CNTL, 0),
        ] {
            self.reg(self.dcn1 + reg * 4, Some(value))?;
        }
        let scratch = self.reg(self.nbio1 + BIOS_SCRATCH_6 * 4, None)?;
        if scratch == u32::MAX {
            return Err(Error::Block(crate::amdgpu_dcn_clk::Error::DeviceGone));
        }
        if scratch & ATOM_S6_ACC_MODE == 0 {
            tables.pipe_power_gating(self.bus(), 0, PipeAction::Init)?;
            for pipe in 0..6 {
                tables.pipe_power_gating(self.bus(), pipe, PipeAction::Disable)?;
            }
        }
        Ok(())
    }
    /// `power_on_plane_resources` (DPP0 is DOMAIN1, HUBP0 DOMAIN0, each waited
    /// to PGFSM on for up to 1000 us) and `hubp1_clk_cntl(true)`.
    async fn power_on_plane(&mut self) -> Result<(), Error> {
        let dcn = self.dcn2;
        self.reg(dcn + DC_IP_REQUEST_CNTL * 4, Some(1))?;
        for config in [DOMAIN1_PG_CONFIG, DOMAIN0_PG_CONFIG] {
            let value = self.reg(dcn + config * 4, None)?;
            self.reg(dcn + config * 4, Some(value & !DOMAIN_POWER_GATE))?;
            let deadline = narf_time::Deadline::after_us(1000);
            loop {
                let status = self.reg(dcn + (config + 1) * 4, None)?;
                if status == u32::MAX {
                    return Err(Error::Block(crate::amdgpu_dcn_clk::Error::DeviceGone));
                }
                if status & DOMAIN_PGFSM_PWR_STATUS == 0 {
                    break;
                }
                if deadline.expired() {
                    let _ = self.reg(dcn + DC_IP_REQUEST_CNTL * 4, Some(0));
                    return Err(Error::Block(crate::amdgpu_dcn_clk::Error::Timeout));
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
            }
        }
        self.reg(dcn + DC_IP_REQUEST_CNTL * 4, Some(0))?;
        let clock = self.reg(dcn + HUBP0_HUBP_CLK_CNTL * 4, None)?;
        self.reg(
            dcn + HUBP0_HUBP_CLK_CNTL * 4,
            Some(clock | HUBP_CLOCK_ENABLE),
        )?;
        Ok(())
    }
    /// Light the connector with `sink`'s best TMDS mode. `draw` fills each
    /// scanout row (XRGB8888) before the plane is unblanked.
    ///
    /// # Safety
    /// As [`Pipeline::new`]; `smu` is this GPU's retained SMU owner and
    /// `pool` the exclusive VRAM pool; no CPU writer may touch the scanout
    /// once it is published except through the returned framebuffer.
    #[allow(clippy::too_many_arguments)]
    pub async unsafe fn enable(
        &mut self,
        smu: &mut crate::amdgpu_smu_navi22::Smu,
        pool: &Pool,
        tables: &Tables<'_>,
        vbios: &[u8],
        crystal_khz: u32,
        sink: &Sink,
        draw: impl Fn(u32, &mut [u32]),
    ) -> Result<Output, Error> {
        if self.state != State::At(Step::Prepared) {
            return Err(Error::Busy);
        }
        match self
            .bring_up(smu, pool, tables, vbios, crystal_khz, sink, draw)
            .await
        {
            Ok(output) => {
                self.state = State::At(Step::Running);
                self.output = Some(output);
                Ok(output)
            }
            Err(error) => {
                let step = match self.state {
                    State::At(step) => step,
                    State::Failed { step, .. } => step,
                };
                // Blank and stop whatever started; the reservation stays
                // published (retained) because hardware may have fetched it.
                let _ = self.tear_down(tables).await;
                self.state = State::Failed { step, error };
                Err(error)
            }
        }
    }
    fn at(&mut self, step: Step) {
        self.state = State::At(step);
    }
    #[allow(clippy::too_many_arguments)]
    async fn bring_up(
        &mut self,
        smu: &mut crate::amdgpu_smu_navi22::Smu,
        pool: &Pool,
        tables: &Tables<'_>,
        vbios: &[u8],
        crystal_khz: u32,
        sink: &Sink,
        draw: impl Fn(u32, &mut [u32]),
    ) -> Result<Output, Error> {
        let transmitter = self.connector.path.transmitter;
        self.hdmi.check_idle()?;
        // Board data first; nothing below is touched if no mode fits.
        let levels = self.clocks.start(smu).await.map_err(Error::Block)?;
        self.at(Step::InitHw);
        self.init_hw(tables)?;
        let refclk = self
            .hubbub
            .dchub_refclk_khz(crystal_khz)
            .map_err(Error::Hubbub)?;
        let (channels, width) =
            crate::amdgpu_dcn_inventory::vram_channels(vbios).map_err(Error::Inventory)?;
        let soc = dml30::Soc::from_board(&levels, channels, width, refclk).map_err(Error::Mode)?;
        let (timing, avi, plan) = select(sink, &soc, levels.vco_khz)?;
        if avi.is_none() {
            // A DVI sink: no data islands may be sent, which this owner's
            // HDMI attribute path always enables.
            return Err(Error::NoSink);
        }
        let avi = avi.unwrap();
        // Reserve and draw the surface before any pipe can fetch it.
        let pitch = pitch(&timing);
        let bytes = u64::from(pitch) * 4 * u64::from(timing.v_active);
        let mut reservation = pool.reserve(bytes).map_err(|_| Error::Allocation)?;
        let mapping = reservation.mapping();
        fill(mapping, pitch, timing.h_active, timing.v_active, &draw);
        self.hdp_flush()?;
        reservation.publish();
        let surface = Surface {
            address: reservation.address(),
            format: Format::Rgb32,
            pitch,
            viewport_width: timing.h_active,
            viewport_height: timing.v_active,
        };
        let fb = narf_graphics_driver::generic::GenericFb::new(
            mapping.phys.raw(),
            timing.h_active,
            timing.v_active,
            pitch * 4,
            32,
        );
        self.scanout = Some(reservation);

        // 1. Watermarks with every pipe idle (ClockManager::start checked).
        self.at(Step::Watermarks);
        // SAFETY: no HUBP fetches yet.
        unsafe { self.hubbub.program(&plan.hubbub, refclk) }.map_err(Error::Hubbub)?;
        // 2. DISPCLK/DPPCLK/DCFCLK, then this pipe's DPP DTO.
        self.at(Step::Clocks);
        let clocks = levels
            .plan(
                plan.clocks.dispclk_khz,
                plan.clocks.dppclk_khz,
                plan.clocks.dcfclk_khz,
            )
            .map_err(Error::Block)?;
        self.clocks.prepare(clocks).await.map_err(Error::Block)?;
        self.clocks
            .pipe_clock(PIPE, plan.clocks.dppclk_khz)
            .map_err(Error::Block)?;
        // 3. The PHY PLL through VBIOS SetPixelClock.
        self.at(Step::PixelClock);
        tables.set_pixel_clock(
            self.bus(),
            &PixelClock {
                otg: PIPE,
                pll: PLL,
                transmitter,
                pixel_khz: timing.pixel_clock_khz,
            },
        )?;
        // 4. Timing and global sync.
        self.at(Step::Timing);
        let sync = GlobalSync {
            v_startup_lines: plan.prefetch.v_startup,
            v_update_offset_pix: plan.prefetch.v_update_offset_pix,
            v_update_width_pix: plan.prefetch.v_update_width_pix,
            v_ready_offset_pix: plan.prefetch.v_ready_offset_pix,
        };
        self.otg.program_tmds_timing(&timing, &sync)?;
        // 5. The plane path, blanked by the OPP pattern generator (black).
        self.at(Step::Plane);
        self.power_on_plane().await?;
        self.dpp
            .program(Format::Rgb32, timing.h_active, timing.v_active)?;
        self.mpc.mux_plane(PIPE, PIPE)?;
        self.opp
            .program(Encoding::Rgb, timing.h_active, timing.v_active)?;
        self.opp.set_blank(true)?;
        // 6. HUBP with the DML30 deadlines, still blanked.
        self.at(Step::Fetch);
        self.hubp.program(&surface, &plan.registers)?;
        self.hubp.blank().await?;
        // 7. Start the timing generator: black frames from here on.
        self.at(Step::Start);
        self.otg.enable()?;
        // 8. enable_link_hdmi.
        self.at(Step::Link);
        self.hdmi.route(PIPE)?;
        tables.hdmi_stream_setup(self.bus(), transmitter, timing.pixel_clock_khz)?;
        self.hdmi.stream_attribute(timing.pixel_clock_khz)?;
        self.hdmi.info_packets(&avi).await?;
        tables.transmitter(
            self.bus(),
            &Transmitter {
                action: TransmitterAction::Enable,
                transmitter,
                hdmi: true,
                hpd: self.connector.hpd,
                symbol_khz: timing.pixel_clock_khz,
            },
        )?;
        // 9. Pixels: fetch first, then release the pattern generator.
        self.at(Step::Unblank);
        self.hubp.unblank().await?;
        self.opp.set_blank(false)?;
        Ok(Output {
            connector: self.connector,
            timing,
            prefetch_mode: plan.prefetch_mode,
            v_startup: plan.prefetch.v_startup,
            dispclk_khz: clocks.display_khz,
            dppclk_khz: clocks.pixel_khz,
            scanout: fb,
        })
    }
    /// Make CPU writes to the running scanout visible to display fetch.
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.state != State::At(Step::Running) {
            return Err(Error::Busy);
        }
        self.hdp_flush()
    }
    /// `hdp_v5_0_flush_hdp` through the remap page, posted by an NBIO read.
    fn hdp_flush(&mut self) -> Result<(), Error> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if HDP_FLUSH + 4 > self.gpu.regs.len {
            return Err(Error::Unsupported);
        }
        self.reg(HDP_FLUSH, Some(0))?;
        self.reg(self.nbio2 + NBIO_MEMSIZE * 4, None)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    /// Reverse order; every step runs even after a failure.
    async fn tear_down(&mut self, tables: &Tables<'_>) -> Result<(), Error> {
        let transmitter = self.connector.path.transmitter;
        let mut first = Ok(());
        let mut record = |r: Result<(), Error>| {
            if first.is_ok() {
                first = r;
            }
        };
        record(self.opp.set_blank(true).map_err(Error::Block));
        record(self.hubp.blank().await.map_err(Error::Block));
        record(
            tables
                .transmitter(
                    self.bus(),
                    &Transmitter {
                        action: TransmitterAction::Disable,
                        transmitter,
                        hdmi: true,
                        hpd: self.connector.hpd,
                        symbol_khz: 0,
                    },
                )
                .map_err(Error::Bios),
        );
        record(self.hdmi.stop().map_err(Error::Hdmi));
        record(self.otg.disable().await.map_err(Error::Block));
        record(self.mpc.release(PIPE).map_err(Error::Block));
        // dce110_clock_source_power_down: SetPixelClock with a zero clock.
        record(
            tables
                .set_pixel_clock(
                    self.bus(),
                    &PixelClock {
                        otg: PIPE,
                        pll: PLL,
                        transmitter,
                        pixel_khz: 0,
                    },
                )
                .map_err(Error::Bios),
        );
        first
    }
    /// Stop the stream. The scanout stays published (excluded from reuse)
    /// until the caller proves the HUBP idle across a reset.
    pub async fn disable(&mut self, tables: &Tables<'_>) -> Result<(), Error> {
        if self.state != State::At(Step::Running) {
            return Err(Error::Busy);
        }
        self.at(Step::Stopping);
        let result = self.tear_down(tables).await;
        self.state = match result {
            Ok(()) => State::At(Step::Stopped),
            Err(error) => State::Failed {
                step: Step::Stopping,
                error,
            },
        };
        self.output = None;
        result
    }
}

/// Write the surface row by row through the pool's CPU mapping.
fn fill(mapping: MmioRegion, pitch: u32, width: u32, height: u32, draw: &impl Fn(u32, &mut [u32])) {
    let mut row: Vec<u32> = alloc::vec![0; width as usize];
    for y in 0..height {
        row.iter_mut().for_each(|p| *p = 0);
        draw(y, &mut row);
        let base = u64::from(y) * u64::from(pitch) * 4;
        for (x, pixel) in row.iter().enumerate() {
            // SAFETY: inside this reservation's permanent mapping.
            unsafe { mapping.write32(base + x as u64 * 4, *pixel) };
        }
    }
}

/// Copy only the immutable register/identity layout the owners consume.
fn snapshot(gpu: &AmdGpu) -> Result<AmdGpu, Error> {
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(gpu.ip_blocks.len())
        .map_err(|_| Error::Allocation)?;
    blocks.extend_from_slice(&gpu.ip_blocks);
    Ok(AmdGpu {
        fb_bar: gpu.fb_bar,
        regs: gpu.regs,
        chip: gpu.chip,
        vram: gpu.vram,
        ip_blocks: blocks,
        gc_info: None,
        vbios: None,
        mode: None,
        fw_loaded: false,
    })
}

/// A colour-bar test pattern for the first native frame: eight SMPTE-order
/// bars across whatever width the chosen mode has.
pub fn test_pattern(_line: u32, row: &mut [u32]) {
    const BARS: [u32; 8] = [
        0x00ff_ffff,
        0x00ff_ff00,
        0x0000_ffff,
        0x0000_ff00,
        0x00ff_00ff,
        0x00ff_0000,
        0x0000_00ff,
        0x0000_0000,
    ];
    let width = row.len().max(1);
    for (x, pixel) in row.iter_mut().enumerate() {
        *pixel = BARS[x * 8 / width];
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_modeset_tests.rs"]
mod tests;
