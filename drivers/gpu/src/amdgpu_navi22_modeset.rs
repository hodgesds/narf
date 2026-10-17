//! Native Navi22 single-stream scanout: the orchestration Linux DC performs
//! for one 8-bpc RGB stream (HDMI TMDS up to 340 MHz, or DisplayPort SST
//! 8b/10b) on DCN3.0, in Linux's global order.
//!
//! 1. `dcn30_init_hw`: `dccg2_init`, `dcn10_bios_golden_init` (VBIOS
//!    EnableDispPowerGating) when the VBIOS is not in accelerated mode, and
//!    `dcn20_disable_vga`; then the GOP takeover — `enc3_hw_init`,
//!    `dcn20_enable_power_gating_plane`, `dcn10_init_pipes`,
//!    `dce110_power_down` ([`crate::amdgpu_dcn30_takeover`]). A cold UEFI
//!    boot leaves the GOP stream lit; it is retired here, not refused.
//! 2. The DAL clock owner starts (board DPM levels), the mode is chosen, and
//!    `dcn30_prepare_bandwidth` → `dcn20_prepare_bandwidth`: clocks
//!    (`dcn3_update_clocks`), then `hubbub3_program_watermarks`.
//! 3. `dce110_apply_ctx_to_hw` → `dce110_apply_single_controller_ctx_to_hw`:
//!    `dcn20_enable_stream_timing` (`optc1_enable_optc_clock`,
//!    `dcn3_program_pix_clk` — VBIOS SetPixelClock on the route's PHY PLL for
//!    TMDS, the DP DTO for DisplayPort — OTG timing, OPP clock and format,
//!    `blank_pixel_data(true)`, `enable_crtc`, one frame), then
//!    `dig_connect_to_otg` and `link_set_dpms_on`: link-encoder setup,
//!    stream attributes (stereo sync; VBIOS STREAM_SETUP + HDMI attributes,
//!    or the DP MSA), InfoFrames/SDPs, `enable_link` (VBIOS transmitter
//!    ENABLE for TMDS; for DP the DIG backend connected, then 8b/10b link
//!    training through native AUX with rate/lane fallback), setup again,
//!    `dcn20_enable_stream` (backend connected, InfoFrames again), DP
//!    unblank, the audio hook, AVMUTE released.
//! 4. `dcn20_program_front_end_for_ctx` under the OTG master lock
//!    (`optc3_lock`): `blank_pixel_data(false)`, `dcn20_enable_plane`
//!    (plane power domains, HUBP clock), `dcn20_update_dchubp_dpp` (DPP DTO,
//!    DPP, MPCC, HUBP, `set_blank(false)`), then the unlock.
//!
//! After the unlock the pipe is watched for two frames: an OTG or HUBP
//! underflow turns the stream black and quarantines it (Linux only logs it,
//! `dcn10_log_hw_state`). The stop path is `dcn20_program_front_end_for_ctx`'s
//! plane removal then `dcn20_reset_back_end_for_pipe`/`link_set_dpms_off`; it
//! undoes only the steps that ran, continuing past a failing one.
//!
//! Resources follow the DCN3.0 pool (`dcn30_resource.c`): the first free
//! pipe, `dcn10_find_first_free_match_stream_enc_for_link` for the DIG
//! frontend and `dc_resource_find_first_free_pll` for a TMDS stream's PHY PLL.
//!
//! Everything is retained on failure: the owners, the published scanout
//! reservation and the step that failed. Nothing is retried or reset.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn30_audio::{Audio, AudioStream},
    amdgpu_dcn30_clk::{Clock, ClockManager},
    amdgpu_dcn30_dp::{self as dp, Aux, Depth},
    amdgpu_dcn30_hdmi::{self as hdmi, DigMode, Hdmi},
    amdgpu_dcn30_hubbub::{self as hubbub, Hubbub},
    amdgpu_dcn30_takeover::{self as takeover, Inherited, Regs, Takeover},
    amdgpu_dcn_hubp::{Hubp, Surface},
    amdgpu_dcn_otg::{GlobalSync, Otg},
    amdgpu_dcn_plane::{Dpp, Encoding, Mpc, Opp},
    amdgpu_dml::{self as dml, Config, Format, Plane, Timing},
    amdgpu_dml30 as dml30, amdgpu_dp_training as training,
    amdgpu_navi22_bios::{
        self as bios, PipeAction, PixelClock, Tables, Transmitter, TransmitterAction,
        TransmitterMode,
    },
    amdgpu_navi22_display::{Connector, Detection, Report, Signal, Sink},
    amdgpu_reg_window::Window,
    amdgpu_vram::{Pool, Reservation},
};
use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, future::Future};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

/// DCN3.0 has six pipes (OTG/HUBP/DPP/MPCC/OPP), six DIG frontends and six
/// combo PHY PLLs (`dcn30_resource.c` `res_cap_dcn3`, `DCN30_CLK_SRC_PLL0..5`).
pub const PIPES: u8 = 6;
pub const STREAMS: u8 = 6;
pub const PLLS: u8 = 6;
/// No scrambling, so no SCDC handshake: HDMI 1.4 rates only.
pub const MAX_TMDS_KHZ: u32 = hdmi::TMDS_SCRAMBLE_KHZ - 1;
/// `dcn20_link_encoder_get_max_link_cap`: HBR3 on four lanes.
pub const MAX_DP_RATE: u8 = 0x1e;
pub const MAX_DP_LANES: u8 = 4;
const PITCH_ALIGN: u32 = 256;
// dccg2_init and the clock source, DCN base index 1 (`dcn_3_0_0_offset.h`).
const REFCLK_CNTL: u64 = 0x0049;
const MILLISECOND_TIME_BASE_DIV: u64 = 0x0070;
const DISPCLK_FREQ_CHANGE_CNTL: u64 = 0x0071;
const MICROSECOND_TIME_BASE_DIV: u64 = 0x007b;
/// `OTGn_PIXEL_RATE_CNTL`, `DP_DTOn_PHASE`, `DP_DTOn_MODULO`, stride 4.
const OTG0_PIXEL_RATE_CNTL: u64 = 0x0080;
const DP_DTO0_PHASE: u64 = 0x0081;
const DP_DTO0_MODULO: u64 = 0x0082;
const DTO_STRIDE: u64 = 4;
const DP_DTO0_ENABLE: u32 = 1 << 4;
/// `PHYPLLx_PIXCLK_RESYNC_CNTL` per combo PHY PLL A..F, and its
/// `PHYPLLA_DCCG_DEEP_COLOR_CNTL` field (the only one in DCN3.0's mask list).
const PIXCLK_RESYNC_CNTL: [u64; 6] = [0x0040, 0x0041, 0x0042, 0x0043, 0x004c, 0x007e];
const DCCG_DEEP_COLOR_CNTL: u32 = 0x30;
/// `clk_mgr->dprefclk_khz` on DCN3.0: `dcn3_clk_mgr_construct` sets 730 MHz
/// and `dcn3_dump_clk_registers` never replaces it.
const DPREFCLK_KHZ: u32 = 730_000;
const LAST_DCN1: u32 = MICROSECOND_TIME_BASE_DIV as u32;
// dcn20_dpp_pg_control / dcn20_hubp_pg_control, DCN base index 2: HUBP n is
// DOMAIN(2n), DPP n DOMAIN(2n + 1); each STATUS follows its CONFIG.
const DOMAIN0_PG_CONFIG: u64 = 0x0080;
const DOMAIN_POWER_GATE: u32 = 1 << 8;
const DOMAIN_PGFSM_PWR_STATUS: u32 = 0xc000_0000;
const DC_IP_REQUEST_CNTL: u64 = 0x00b2;
// HUBP instance block, stride 0xdc.
const HUBP_STRIDE: u64 = 0xdc;
const HUBP0_DCHUBP_CNTL: u64 = 0x05f3;
const HUBP0_HUBP_CLK_CNTL: u64 = 0x05f4;
const HUBP_CLOCK_ENABLE: u32 = 1 << 0;
/// `HUBPREQn_DCN_CUR0_TTU_CNTL0/1`: REFCYC_PER_REQ_DELIVERY (23 bits),
/// QoS_LEVEL_FIXED and QoS_RAMP_DISABLE; REFCYC_PER_REQ_DELIVERY_PRE.
const HUBP0_DCN_CUR0_TTU_CNTL0: u64 = 0x0630;
const HUBP0_DCN_CUR0_TTU_CNTL1: u64 = 0x0631;
/// `DCHUBP_CNTL.HUBP_UNDERFLOW_STATUS` (3 bits) and `HUBP_UNDERFLOW_CLEAR`.
const HUBP_UNDERFLOW_STATUS: u32 = 0x7000_0000;
const HUBP_UNDERFLOW_CLEAR: u32 = 0x8000_0000;
// OTG instance block, stride 0x80.
const OTG_STRIDE: u64 = 0x80;
const OTG0_OTG_CLOCK_CONTROL: u64 = 0x1b86;
const OTG_CLOCK_EN: u32 = 1 << 0;
const OTG_CLOCK_GATE_DIS: u32 = 1 << 1;
const OTG_CLOCK_ON: u32 = 1 << 8;
const OTG0_OTG_MASTER_UPDATE_LOCK: u64 = 0x1b8b;
const OTG0_OTG_GLOBAL_CONTROL2: u64 = 0x1b92;
const OTG_MASTER_UPDATE_LOCK: u32 = 1 << 0;
const UPDATE_LOCK_STATUS: u32 = 1 << 8;
const OTG_MASTER_UPDATE_LOCK_SEL: u32 = 0x0e00_0000;
// ODM instance block, stride 0x10.
const ODM_STRIDE: u64 = 0x10;
const ODM0_OPTC_INPUT_GLOBAL_CONTROL: u64 = 0x1aca;
const OPTC_UNDERFLOW_OCCURRED_STATUS: u32 = 0x400;
const OPTC_UNDERFLOW_CLEAR: u32 = 0x1000;
const ODM0_OPTC_INPUT_CLOCK_CONTROL: u64 = 0x1acf;
const OPTC_INPUT_CLK_GATE_DIS: u32 = 1 << 0;
const OPTC_INPUT_CLK_EN: u32 = 1 << 1;
const OPTC_INPUT_CLK_ON: u32 = 1 << 2;
/// The last register this owner touches directly in bank 2.
const LAST_DCN2: u32 = {
    let own = OTG0_OTG_GLOBAL_CONTROL2 as u32 + 5 * OTG_STRIDE as u32;
    let dp = dp::LAST_REG;
    let take = takeover::LAST_DCN2;
    let max = if own > dp { own } else { dp };
    if max > take {
        max
    } else {
        take
    }
};
/// `BIOS_SCRATCH_6` (nbio 2.3, base index 1) and `ATOM_S6_ACC_MODE`.
const BIOS_SCRATCH_6: u64 = 0x003e;
const ATOM_S6_ACC_MODE: u32 = 1 << 4;
/// The HDP flush page and NBIO's MEMSIZE read for posting (`hdp_v5_0_flush_hdp`).
const HDP_FLUSH: u64 = 0x7f000;
const NBIO_MEMSIZE: u64 = 0xc3;
/// Frames watched for underflow after the front end latches.
const VERIFY_FRAMES: u32 = 2;
/// `link_set_dpms_off`'s `msleep(60)` after blanking a non-eDP DP stream.
const DP_BLANK_SETTLE_US: u64 = 60_000;
/// `dp_transition_to_video_idle` without POST_LT_ADJ_REQ: 5 ms of idle.
const DP_IDLE_US: u64 = 5_000;
/// `video_optimized_pixel_rates[]` (`dce_clock_source.c`): requested pixel
/// clock range in kHz, the target rate, and the DTO multiplier/divider.
const VIDEO_OPTIMIZED_RATES: [(u32, u32, u32, u32, u32); 28] = [
    (25170, 25180, 25200, 1000, 1001),
    (59340, 59350, 59400, 1000, 1001),
    (74170, 74180, 74250, 1000, 1001),
    (89910, 90000, 90000, 1000, 1001),
    (125870, 125880, 126000, 1000, 1001),
    (148350, 148360, 148500, 1000, 1001),
    (167830, 167840, 168000, 1000, 1001),
    (222520, 222530, 222750, 1000, 1001),
    (257140, 257150, 257400, 1000, 1001),
    (296700, 296710, 297000, 1000, 1001),
    (342850, 342860, 343200, 1000, 1001),
    (395600, 395610, 396000, 1000, 1001),
    (409090, 409100, 409500, 1000, 1001),
    (445050, 445060, 445500, 1000, 1001),
    (467530, 467540, 468000, 1000, 1001),
    (519230, 519240, 519750, 1000, 1001),
    (525970, 525980, 526500, 1000, 1001),
    (545450, 545460, 546000, 1000, 1001),
    (593400, 593410, 594000, 1000, 1001),
    (623370, 623380, 624000, 1000, 1001),
    (692300, 692310, 693000, 1000, 1001),
    (701290, 701300, 702000, 1000, 1001),
    (791200, 791210, 792000, 1000, 1001),
    (890100, 890110, 891000, 1000, 1001),
    (1186810, 1186820, 1188000, 1000, 1001),
    (27020, 27030, 27000, 1001, 1000),
    (54050, 54060, 54000, 1001, 1000),
    (108100, 108110, 108000, 1001, 1000),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    /// The sink is not usable on this connector, or nothing is connected.
    NoSink,
    /// No EDID timing fits the link, clock or bandwidth limits.
    NoMode,
    Block(crate::amdgpu_dcn_clk::Error),
    Mode(dml::Error),
    Hubbub(hubbub::Error),
    Bios(bios::Error),
    Hdmi(hdmi::Error),
    Inventory(crate::amdgpu_dcn_inventory::Error),
    /// An AUX transaction to the DP sink failed.
    Aux,
    /// 8b/10b link training failed at every rate/lane combination tried.
    Training(training::Error),
    /// The OTG or HUBP reported an underflow; the stream is black.
    Underflow(Underflow),
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

/// What feeds the stream's pixel clock: a combo PHY PLL (TMDS) or the DP
/// DTO (`dcn30_resource.c` `dp_clock_source`, `CLOCK_SOURCE_ID_DP_DTO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockSource {
    Pll(u8),
    DpDto,
}
/// The DCN resources one stream uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// OTG, HUBP, DPP, MPCC and OPP instance (one pipe, no ODM/MPO).
    pub pipe: u8,
    /// DIG frontend (stream encoder) instance.
    pub stream: u8,
    pub clock: ClockSource,
}
/// The DCN3.0 resource pool's allocation state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pipes: u8,
    streams: u8,
    plls: u8,
}
fn first_free(used: u8, count: u8) -> Option<u8> {
    (0..count).find(|i| used & 1 << i == 0)
}
impl Resources {
    pub const fn new() -> Self {
        Self {
            pipes: 0,
            streams: 0,
            plls: 0,
        }
    }
    /// `resource_map_pool_resources` for one SST stream on `connector`:
    /// the first free pipe; the link encoder's `preferred_engine` (DIG FE
    /// equal to its transmitter, `dcn10_link_encoder_construct`) when free,
    /// else the *last* free frontend, exactly as
    /// `dcn10_find_first_free_match_stream_enc_for_link` keeps overwriting
    /// its fallback; `dc_resource_find_first_free_pll` for TMDS and the DP
    /// DTO for DisplayPort (`resource_map_clock_resources`). PLL sharing
    /// between identical TMDS timings is not attempted.
    pub fn acquire(&mut self, connector: &Connector) -> Result<Route, Error> {
        let pipe = first_free(self.pipes, PIPES).ok_or(Error::Busy)?;
        let preferred = connector.path.transmitter;
        if preferred >= STREAMS {
            return Err(Error::Invalid);
        }
        let stream = if self.streams & 1 << preferred == 0 {
            preferred
        } else {
            (0..STREAMS)
                .rev()
                .find(|i| self.streams & 1 << i == 0)
                .ok_or(Error::Busy)?
        };
        let clock = match connector.signal {
            Signal::Hdmi => ClockSource::Pll(first_free(self.plls, PLLS).ok_or(Error::Busy)?),
            Signal::DisplayPort => ClockSource::DpDto,
        };
        self.pipes |= 1 << pipe;
        self.streams |= 1 << stream;
        if let ClockSource::Pll(pll) = clock {
            self.plls |= 1 << pll;
        }
        Ok(Route {
            pipe,
            stream,
            clock,
        })
    }
    /// Return a retired stream's resources to the pool.
    pub fn release(&mut self, route: Route) {
        self.pipes &= !(1 << route.pipe);
        self.streams &= !(1 << route.stream);
        if let ClockSource::Pll(pll) = route.clock {
            self.plls &= !(1 << pll);
        }
    }
}

/// The connector Linux would light first: a connected HDMI sink, else the
/// first DisplayPort sink that answered with both EDID and receiver caps
/// (Navi48's policy: HPD asserted, EDID read, DPCD read). Report order is
/// VBIOS table order.
pub fn choose(reports: &[Report]) -> Option<(Connector, &Sink)> {
    let connected = |want: Signal| {
        reports.iter().find_map(|r| match &r.detection {
            Detection::Connected(sink)
                if r.connector.signal == want
                    && !sink.edid.is_empty()
                    && (want == Signal::Hdmi || sink.dpcd.is_some()) =>
            {
                Some((r.connector, sink))
            }
            _ => None,
        })
    };
    connected(Signal::Hdmi).or_else(|| connected(Signal::DisplayPort))
}

/// Underflow status as the hardware latched it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Underflow {
    /// `OPTC_UNDERFLOW_OCCURRED_STATUS` (sticky).
    pub otg: bool,
    /// `HUBP_UNDERFLOW_STATUS`, three bits.
    pub hubp: u8,
}

/// Where the sequence is, retained across failure and cancellation. The
/// order is the enable order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Prepared,
    InitHw,
    Clocks,
    Watermarks,
    PixelClock,
    Timing,
    Start,
    Link,
    Plane,
    Verify,
    Running,
    Stopping,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    At(Step),
    Failed {
        step: Step,
        error: Error,
    },
    /// The stream underflowed and was turned black; the pipe, link and
    /// scanout stay owned until [`Pipeline::disable`].
    Quarantined(Underflow),
}

/// A trained DisplayPort link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpLink {
    /// DPCD link-rate code (6, 10, 20, 30).
    pub rate: u8,
    pub lanes: u8,
}

/// What a lit display reports.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub connector: Connector,
    pub route: Route,
    pub timing: Timing,
    pub link: Option<DpLink>,
    pub prefetch_mode: u8,
    pub v_startup: u32,
    pub dispclk_khz: u32,
    pub dppclk_khz: u32,
    /// What the takeover found lit by the firmware.
    pub inherited: Inherited,
    pub scanout: narf_graphics_driver::generic::GenericFb,
}

/// Board data the mode math needs: the VBIOS crystal and memory width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Board {
    pub crystal_khz: u32,
    pub channels: u32,
    pub channel_width_bytes: u32,
}
impl Board {
    pub fn from_vbios(vbios: &[u8], crystal_khz: u32) -> Result<Self, Error> {
        let (channels, channel_width_bytes) =
            crate::amdgpu_dcn_inventory::vram_channels(vbios).map_err(Error::Inventory)?;
        Ok(Self {
            crystal_khz,
            channels,
            channel_width_bytes,
        })
    }
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
/// The sink's link ceiling against the DCN3.0 encoder's: the lower rate
/// code and lane count (`dp_get_max_link_cap`, without LTTPR).
fn dp_ceiling(caps: &[u8; 16]) -> Result<(u8, u8), Error> {
    let rate = caps[1].min(MAX_DP_RATE);
    let lanes = (caps[2] & 0x1f).min(MAX_DP_LANES);
    if !matches!(rate, 6 | 10 | 20 | 30) || !matches!(lanes, 1 | 2 | 4) {
        return Err(Error::NoSink);
    }
    Ok((rate, lanes))
}
/// 8b/10b payload: rate code x 27 MHz x 8 bits per lane.
fn dp_fits(pixel_khz: u32, bpp: u8, rate: u8, lanes: u8) -> bool {
    u64::from(pixel_khz) * u64::from(bpp)
        <= u64::from(rate) * u64::from(dp::LINK_RATE_REF_KHZ) * 8 * u64::from(lanes)
}
/// The first EDID timing the sink's maximum DP link carries at 8 bpc and
/// the DCN30 mode math accepts (`dp_validate_mode_timing`).
pub(crate) fn select_dp(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
) -> Result<(Timing, dml30::Plan), Error> {
    let caps = sink.dpcd.as_ref().ok_or(Error::NoSink)?;
    let (rate, lanes) = dp_ceiling(caps)?;
    for timing in crate::amdgpu_navi48_boot::edid_timings(&sink.edid) {
        if timing.pixel_clock_khz < 25_000
            || !dp_fits(
                timing.pixel_clock_khz,
                Depth::Bpc8.bits_per_pixel(),
                rate,
                lanes,
            )
        {
            continue;
        }
        let Ok(plan) = dml30::plan(&config(&timing, vco_khz), soc) else {
            continue;
        };
        return Ok((timing, plan));
    }
    Err(Error::NoMode)
}
/// `dcn3_program_pix_clk`'s DP DTO phase and modulo for `pixel_khz`.
pub(crate) fn dp_dto(pixel_khz: u32) -> (u32, u32) {
    match VIDEO_OPTIMIZED_RATES
        .iter()
        .find(|e| e.0 <= pixel_khz && pixel_khz <= e.1)
    {
        Some(&(_, _, target, mult, div)) => (target * mult, DPREFCLK_KHZ * div),
        // actual_pix_clk_100hz * 100 (Hz) over dprefclk in Hz.
        None => (pixel_khz * 1000, DPREFCLK_KHZ * 1000),
    }
}
/// The DCN30 admission of a lit sink, retained for KMS: the board SoC
/// inputs and DCHUB reference clock it was computed with, the plan being
/// scanned out, and every EDID timing the same checks admit (EDID order).
#[derive(Clone, Debug)]
pub struct Admitted {
    pub soc: dml30::Soc,
    pub refclk_khz: u32,
    pub plan: dml30::Plan,
    pub offered: Vec<Timing>,
}

/// The TMDS clock ceiling `select` applies to `sink`.
fn tmds_ceiling(sink: &Sink) -> u32 {
    let caps = crate::amdgpu_navi48_boot::hdmi_caps(&sink.edid);
    if caps.vsdb_max_khz != 0 {
        caps.vsdb_max_khz.min(MAX_TMDS_KHZ)
    } else {
        MAX_TMDS_KHZ
    }
}

/// Every distinct EDID timing `select`/`select_dp` could choose: inside the
/// TMDS ceiling (HDMI) or the sink's maximum 8b/10b link at 8 bpc (a sink
/// with DPCD, i.e. DisplayPort), and admitted by the DCN30 mode math. This is
/// what KMS offers; a DRM TEST_ONLY or SETCRTC is checked against it.
pub(crate) fn offered(sink: &Sink, soc: &dml30::Soc, vco_khz: u32) -> Vec<Timing> {
    let ceiling = tmds_ceiling(sink);
    let link = sink.dpcd.as_ref().map(dp_ceiling);
    let mut out: Vec<Timing> = Vec::new();
    for timing in crate::amdgpu_navi48_boot::edid_timings(&sink.edid) {
        let fits = match link {
            None => timing.pixel_clock_khz <= ceiling,
            Some(Ok((rate, lanes))) => dp_fits(
                timing.pixel_clock_khz,
                Depth::Bpc8.bits_per_pixel(),
                rate,
                lanes,
            ),
            Some(Err(_)) => false,
        };
        if !fits || timing.pixel_clock_khz < 25_000 || out.contains(&timing) {
            continue;
        }
        if dml30::plan(&config(&timing, vco_khz), soc).is_ok() && out.try_reserve(1).is_ok() {
            out.push(timing);
        }
    }
    out
}

/// `select_dp`, or exactly `want` when DRM asked for a timing `offered`
/// admits.
pub(crate) fn select_dp_wanted(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
    want: Option<Timing>,
) -> Result<(Timing, dml30::Plan), Error> {
    let Some(want) = want else {
        return select_dp(sink, soc, vco_khz);
    };
    if !offered(sink, soc, vco_khz).contains(&want) {
        return Err(Error::NoMode);
    }
    let plan = dml30::plan(&config(&want, vco_khz), soc).map_err(Error::Mode)?;
    Ok((want, plan))
}

/// `select`, or exactly `want` when DRM asked for a timing: it must be one
/// that `offered` admits, or the modeset fails before any device write.
pub(crate) fn select_wanted(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
    want: Option<Timing>,
) -> Result<(Timing, Option<[u8; 36]>, dml30::Plan), Error> {
    use crate::amdgpu_navi48_boot as navi48;
    let Some(want) = want else {
        return select(sink, soc, vco_khz);
    };
    if !offered(sink, soc, vco_khz).contains(&want) {
        return Err(Error::NoMode);
    }
    let plan = dml30::plan(&config(&want, vco_khz), soc).map_err(Error::Mode)?;
    let caps = navi48::hdmi_caps(&sink.edid);
    let avi = caps.hdmi.then(|| {
        crate::amdgpu_dcn401_otg::avi_infoframe(
            &want,
            navi48::hdmi_avi(caps, &want),
            navi48::limited_range(navi48::broadcast_rgb()),
            false,
        )
    });
    Ok((want, avi, plan))
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
        // dcn20_populate_dml_pipes_from_context budgets DCN30's one cursor
        // for every graphics plane, shown or not.
        cursors: 1,
    }
}
/// One frame of `timing`, rounded up, in microseconds.
fn frame_us(timing: &Timing) -> u64 {
    (u64::from(timing.h_total) * u64::from(timing.v_total) * 1000)
        .div_ceil(u64::from(timing.pixel_clock_khz.max(1)))
}
async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
/// The VBIOS register bus for one table execution.
pub(crate) fn bios_bus(
    gpu: &AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
) -> Rc<RefCell<bios::Mmio>> {
    // SAFETY: callers own the display engine exclusively (Pipeline::new).
    Rc::new(RefCell::new(unsafe {
        bios::Mmio::new(gpu.regs, authority)
    }))
}

/// The VBIOS transmitter calls of one DP connector, for the trainer.
struct DpPhy<'a> {
    tables: &'a Tables<'a>,
    regs: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    connector: Connector,
}
impl DpPhy<'_> {
    fn call(&mut self, control: Transmitter, lane_set: u8) -> Result<(), Error> {
        // SAFETY: Pipeline::new's exclusive display ownership.
        let bus = Rc::new(RefCell::new(unsafe {
            bios::Mmio::new(self.regs, self.authority)
        }));
        Ok(self.tables.transmitter_lane(bus, &control, lane_set)?)
    }
    fn control(
        &self,
        action: TransmitterAction,
        rate: u8,
        lanes: u8,
        connector: u8,
    ) -> Transmitter {
        Transmitter {
            action,
            transmitter: self.connector.path.transmitter,
            mode: TransmitterMode::DisplayPort,
            lanes,
            hpd: self.connector.hpd,
            connector,
            symbol_khz: u32::from(rate) * dp::LINK_RATE_REF_KHZ,
        }
    }
}
impl dp::Phy for DpPhy<'_> {
    fn enable(&mut self, rate: u8, lanes: u8) -> Result<(), Error> {
        let control = self.control(TransmitterAction::Enable, rate, lanes, 0);
        self.call(control, 0)
    }
    fn lane_settings(&mut self, rate: u8, lanes: u8, lane_set: u8) -> Result<(), Error> {
        let id = self.connector.object_id();
        let control = self.control(TransmitterAction::SetupVsemph, rate, lanes, id);
        self.call(control, lane_set)
    }
    fn disable(&mut self) -> Result<(), Error> {
        let id = self.connector.object_id();
        let control = self.control(TransmitterAction::Disable, 0, 0, id);
        self.call(control, 0)
    }
}

/// The retained single-stream output.
pub struct Pipeline {
    gpu: AmdGpu,
    regs: Regs,
    connector: Connector,
    route: Route,
    clocks: ClockManager,
    hubbub: Hubbub,
    otg: Otg,
    hubp: Hubp,
    dpp: Dpp,
    mpc: Mpc,
    opp: Opp,
    /// The route's DIG frontend and the connector's DIG backend.
    dig: Hdmi,
    dp_link: dp::Link,
    dp_stream: dp::Stream,
    /// The stream's audio (Azalia endpoint, wall clock, AFMT/DP packets).
    audio: Audio,
    /// DCN base indices 1–3 and NBIO base indices 1 and 2, as byte offsets.
    dcn1: u64,
    dcn2: u64,
    dcn3: u64,
    nbio1: u64,
    nbio2: u64,
    scanout: Option<Reservation>,
    state: State,
    /// The furthest enable step that started; what the stop path undoes.
    reached: Step,
    link: Option<DpLink>,
    inherited: Inherited,
    output: Option<Output>,
    underflow: Option<Underflow>,
    /// KMS hooks (amdgpu_navi22_kms): the timing DRM asked for, and what
    /// the DCN30 admission of the lit sink produced.
    want: Option<Timing>,
    admitted: Option<Admitted>,
}
impl core::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pipeline")
            .field("connector", &self.connector)
            .field("route", &self.route)
            .field("state", &self.state)
            .field("output", &self.output)
            .field("underflow", &self.underflow)
            .finish()
    }
}

impl Pipeline {
    /// # Safety
    /// Caller exclusively owns this Navi22 GPU's display engine (every pipe,
    /// DIG, PHY, the DAL clock mailbox, DCCG and HUBBUB — the takeover
    /// touches all six of each) and the pool, with permanent mappings and PCI
    /// authority. No DMUB or VBIOS client may program display concurrently.
    /// `route` must come from the caller's [`Resources`].
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        connector: Connector,
        route: Route,
    ) -> Result<Self, Error> {
        if route.pipe >= PIPES
            || route.stream >= STREAMS
            || matches!(route.clock, ClockSource::Pll(p) if p >= PLLS)
            || matches!(
                (connector.signal, route.clock),
                (Signal::Hdmi, ClockSource::DpDto) | (Signal::DisplayPort, ClockSource::Pll(_))
            )
        {
            return Err(Error::Invalid);
        }
        let transmitter = connector.path.transmitter;
        let profile = crate::amdgpu_dcn_profile::Profile::Navi22;
        let dcn1 = profile.bank(gpu, 1, LAST_DCN1.max(takeover::LAST_DCN1))?;
        let dcn2 = profile.bank(gpu, 2, LAST_DCN2)?;
        let dcn3 = profile.bank(gpu, 3, takeover::LAST_DCN3)?;
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
        let regs = Regs {
            window: Window::new(gpu.regs),
            authority,
        };
        let pipe = route.pipe;
        // SAFETY: every claim is the caller's exclusive display ownership.
        unsafe {
            Ok(Self {
                gpu: snapshot(gpu)?,
                regs,
                connector,
                route,
                clocks: ClockManager::new(gpu, authority).map_err(Error::Block)?,
                hubbub: Hubbub::new(gpu, authority).map_err(Error::Hubbub)?,
                otg: Otg::new(gpu, authority, pipe)?,
                hubp: Hubp::new(gpu, authority, pipe)?,
                dpp: Dpp::new(gpu, authority, pipe)?,
                mpc: Mpc::new(gpu, authority, pipe)?,
                opp: Opp::new(gpu, authority, pipe)?,
                dig: Hdmi::new(gpu, authority, route.stream, transmitter)?,
                dp_link: dp::Link::new(regs, dcn2, transmitter)?,
                dp_stream: dp::Stream::new(regs, dcn2, route.stream)?,
                audio: Audio::new(gpu, authority).map_err(|_| Error::Unsupported)?,
                dcn1,
                dcn2,
                dcn3,
                nbio1: nbif(1, BIOS_SCRATCH_6 as u32)?,
                nbio2: nbif(2, NBIO_MEMSIZE as u32)?,
                scanout: None,
                state: State::At(Step::Prepared),
                reached: Step::Prepared,
                link: None,
                inherited: Inherited::default(),
                output: None,
                underflow: None,
                want: None,
                admitted: None,
            })
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn output(&self) -> Option<Output> {
        self.output
    }
    pub fn route(&self) -> Route {
        self.route
    }
    pub fn connector(&self) -> Connector {
        self.connector
    }
    /// The last underflow this pipe latched, kept across quarantine.
    pub fn underflow(&self) -> Option<Underflow> {
        self.underflow
    }
    /// What the takeover found lit by the firmware.
    pub fn inherited(&self) -> Inherited {
        self.inherited
    }
    /// The scanout reservation, retained (published) once drawn.
    pub fn scanout(&self) -> Option<&Reservation> {
        self.scanout.as_ref()
    }
    fn bus(&self) -> Rc<RefCell<bios::Mmio>> {
        bios_bus(&self.gpu, self.regs.authority)
    }
    fn takeover(&self) -> Takeover<'_> {
        Takeover {
            gpu: &self.gpu,
            regs: self.regs,
            dcn1: self.dcn1,
            dcn2: self.dcn2,
            dcn3: self.dcn3,
        }
    }
    fn at(&mut self, step: Step) {
        self.state = State::At(step);
        self.reached = self.reached.max(step);
    }
    fn d1(&self, reg: u64) -> u64 {
        self.dcn1 + reg * 4
    }
    fn d2(&self, reg: u64) -> u64 {
        self.dcn2 + reg * 4
    }
    /// `dcn30_init_hw` up to the first modeset: `dccg2_init`, golden init
    /// and VGA off unless the VBIOS is in accelerated mode, then the GOP
    /// takeover over every board link.
    async fn init_hw(&mut self, tables: &Tables<'_>, links: &[Connector]) -> Result<(), Error> {
        for (reg, value) in [
            (MICROSECOND_TIME_BASE_DIV, 0x0012_0264),
            (MILLISECOND_TIME_BASE_DIV, 0x0011_86a0),
            (DISPCLK_FREQ_CHANGE_CNTL, 0x0e01_003c),
            (REFCLK_CNTL, 0),
        ] {
            self.regs.write(self.d1(reg), value)?;
        }
        let scratch = self.regs.read(self.nbio1 + BIOS_SCRATCH_6 * 4)?;
        let mut takeover = self.takeover();
        if scratch & ATOM_S6_ACC_MODE == 0 {
            tables.pipe_power_gating(self.bus(), 0, PipeAction::Init)?;
            for pipe in 0..PIPES {
                tables.pipe_power_gating(self.bus(), pipe, PipeAction::Disable)?;
            }
            takeover.disable_vga()?;
        }
        let mut all = Vec::new();
        all.try_reserve_exact(links.len() + 1)
            .map_err(|_| Error::Allocation)?;
        all.extend_from_slice(links);
        if !all
            .iter()
            .any(|c| c.path.transmitter == self.connector.path.transmitter)
        {
            all.push(self.connector);
        }
        let inherited = takeover.retire(tables, &all).await?;
        if scratch & ATOM_S6_ACC_MODE == 0 {
            takeover.init_watermarks()?;
        }
        self.inherited = inherited;
        // A stream the takeover could not retire stops everything here.
        self.takeover().check_idle()
    }
    /// `optc1_enable_optc_clock(true)`: the OPTC input clock, then the OTG
    /// clock, each waited up to 1000 x 1 us. Linux only logs a timeout; an
    /// OTG without clocks never starts, so this fails closed.
    async fn enable_optc_clock(&mut self) -> Result<(), Error> {
        let pipe = u64::from(self.route.pipe);
        let input = self.d2(ODM0_OPTC_INPUT_CLOCK_CONTROL + pipe * ODM_STRIDE);
        self.regs.update(
            input,
            OPTC_INPUT_CLK_EN | OPTC_INPUT_CLK_GATE_DIS,
            OPTC_INPUT_CLK_EN | OPTC_INPUT_CLK_GATE_DIS,
        )?;
        let on = self
            .regs
            .wait(input, OPTC_INPUT_CLK_ON, OPTC_INPUT_CLK_ON, 1, 1000)
            .await?;
        let clock = self.d2(OTG0_OTG_CLOCK_CONTROL + pipe * OTG_STRIDE);
        self.regs.update(
            clock,
            OTG_CLOCK_EN | OTG_CLOCK_GATE_DIS,
            OTG_CLOCK_EN | OTG_CLOCK_GATE_DIS,
        )?;
        let otg_on = self
            .regs
            .wait(clock, OTG_CLOCK_ON, OTG_CLOCK_ON, 1, 1000)
            .await?;
        if !(on && otg_on) {
            return Err(Error::Block(crate::amdgpu_dcn_clk::Error::Timeout));
        }
        Ok(())
    }
    /// `optc1_enable_optc_clock(false)`, clearing a latched underflow first.
    fn disable_optc_clock(&mut self) -> Result<(), Error> {
        let pipe = u64::from(self.route.pipe);
        let (optc, _) = self.underflow_regs();
        if self.regs.read(optc)? & OPTC_UNDERFLOW_OCCURRED_STATUS != 0 {
            self.regs
                .update(optc, OPTC_UNDERFLOW_CLEAR, OPTC_UNDERFLOW_CLEAR)?;
        }
        let clock = self.d2(OTG0_OTG_CLOCK_CONTROL + pipe * OTG_STRIDE);
        self.regs
            .update(clock, OTG_CLOCK_EN | OTG_CLOCK_GATE_DIS, 0)?;
        let input = self.d2(ODM0_OPTC_INPUT_CLOCK_CONTROL + pipe * ODM_STRIDE);
        self.regs
            .update(input, OPTC_INPUT_CLK_EN | OPTC_INPUT_CLK_GATE_DIS, 0)
    }
    /// `dcn3_program_pix_clk`: VBIOS SetPixelClock and the PHY PLL's deep
    /// colour resync (8 bpc: 1:1) for TMDS; the DP DTO for DisplayPort.
    fn program_pix_clk(&mut self, tables: &Tables<'_>, pixel_khz: u32) -> Result<(), Error> {
        let pipe = u64::from(self.route.pipe);
        match self.route.clock {
            ClockSource::Pll(pll) => {
                tables.set_pixel_clock(
                    self.bus(),
                    &PixelClock {
                        otg: self.route.pipe,
                        pll,
                        transmitter: self.connector.path.transmitter,
                        pixel_khz,
                    },
                )?;
                let resync = self.d1(PIXCLK_RESYNC_CNTL[usize::from(pll)]);
                self.regs.update(resync, DCCG_DEEP_COLOR_CNTL, 0)
            }
            ClockSource::DpDto => {
                let (phase, modulo) = dp_dto(pixel_khz);
                self.regs
                    .write(self.d1(DP_DTO0_PHASE + pipe * DTO_STRIDE), phase)?;
                self.regs
                    .write(self.d1(DP_DTO0_MODULO + pipe * DTO_STRIDE), modulo)?;
                let cntl = self.d1(OTG0_PIXEL_RATE_CNTL + pipe * DTO_STRIDE);
                self.regs.update(cntl, DP_DTO0_ENABLE, DP_DTO0_ENABLE)
            }
        }
    }
    /// `dcn20_power_on_plane_resources` (DPP n is DOMAIN 2n+1, HUBP n DOMAIN
    /// 2n, each waited to PGFSM on for up to 1000 us) and `hubp1_clk_cntl`.
    /// Pipe 5's domains are never touched: `dcn20_{dpp,hubp}_pg_control`
    /// leave them at the hardware default (power gating there is
    /// de-featured and may hard-reset the GPU).
    async fn power_on_plane(&mut self) -> Result<(), Error> {
        let pipe = u64::from(self.route.pipe);
        let request = self.d2(DC_IP_REQUEST_CNTL);
        self.regs.write(request, 1)?;
        if self.route.pipe != 5 {
            for domain in [2 * pipe + 1, 2 * pipe] {
                let config = self.d2(DOMAIN0_PG_CONFIG + 2 * domain);
                self.regs.update(config, DOMAIN_POWER_GATE, 0)?;
                if !self
                    .regs
                    .wait(config + 4, DOMAIN_PGFSM_PWR_STATUS, 0, 1, 1000)
                    .await?
                {
                    let _ = self.regs.write(request, 0);
                    return Err(Error::Block(crate::amdgpu_dcn_clk::Error::Timeout));
                }
            }
        }
        self.regs.write(request, 0)?;
        let clock = self.d2(HUBP0_HUBP_CLK_CNTL + pipe * HUBP_STRIDE);
        self.regs
            .update(clock, HUBP_CLOCK_ENABLE, HUBP_CLOCK_ENABLE)
    }
    /// `hubp2_program_deadline`'s cursor half: the cursor's request pacing
    /// from the plan, so a cursor shown later fetches on the budget the
    /// watermarks were computed with.
    fn program_cursor_ttu(&mut self, ttu: Option<dml30::CursorTtu>) -> Result<(), Error> {
        let Some(ttu) = ttu else {
            return Ok(());
        };
        let hubp = u64::from(self.route.pipe) * HUBP_STRIDE;
        self.regs.write(
            self.d2(HUBP0_DCN_CUR0_TTU_CNTL0 + hubp),
            ttu.refcyc_per_req_delivery & 0x007f_ffff
                | (ttu.qos_level_fixed & 0xf) << 24
                | (ttu.qos_ramp_disable & 1) << 28,
        )?;
        self.regs.write(
            self.d2(HUBP0_DCN_CUR0_TTU_CNTL1 + hubp),
            ttu.refcyc_per_req_delivery_pre & 0x007f_ffff,
        )
    }
    fn otg_reg(&self, reg: u64) -> u64 {
        self.d2(reg + u64::from(self.route.pipe) * OTG_STRIDE)
    }
    /// `optc3_lock`: select this OTG and take its master update lock. Linux's
    /// `REG_WAIT` for the status only logs a timeout (10 x 1 us); so does this.
    async fn lock(&mut self) -> Result<(), Error> {
        let pipe = u32::from(self.route.pipe);
        let control2 = self.otg_reg(OTG0_OTG_GLOBAL_CONTROL2);
        self.regs.update(
            control2,
            OTG_MASTER_UPDATE_LOCK_SEL,
            pipe << OTG_MASTER_UPDATE_LOCK_SEL.trailing_zeros(),
        )?;
        let lock = self.otg_reg(OTG0_OTG_MASTER_UPDATE_LOCK);
        self.regs.write(lock, OTG_MASTER_UPDATE_LOCK)?;
        self.regs
            .wait(lock, UPDATE_LOCK_STATUS, UPDATE_LOCK_STATUS, 1, 10)
            .await?;
        Ok(())
    }
    /// `optc1_unlock`.
    fn unlock(&mut self) -> Result<(), Error> {
        let lock = self.otg_reg(OTG0_OTG_MASTER_UPDATE_LOCK);
        self.regs.write(lock, 0)
    }
    fn underflow_regs(&self) -> (u64, u64) {
        let pipe = u64::from(self.route.pipe);
        (
            self.d2(ODM0_OPTC_INPUT_GLOBAL_CONTROL + pipe * ODM_STRIDE),
            self.d2(HUBP0_DCHUBP_CNTL + pipe * HUBP_STRIDE),
        )
    }
    /// `optc1_clear_optc_underflow` and `hubp2_clear_underflow`.
    fn clear_underflow(&mut self) -> Result<(), Error> {
        let (optc, hubp) = self.underflow_regs();
        self.regs
            .update(optc, OPTC_UNDERFLOW_CLEAR, OPTC_UNDERFLOW_CLEAR)?;
        self.regs
            .update(hubp, HUBP_UNDERFLOW_CLEAR, HUBP_UNDERFLOW_CLEAR)
    }
    /// `optc1_is_optc_underflow_occurred` and `hubp1_get_underflow_status`.
    fn read_underflow(&mut self) -> Result<Option<Underflow>, Error> {
        let (optc, hubp) = self.underflow_regs();
        let otg = self.regs.read(optc)? & OPTC_UNDERFLOW_OCCURRED_STATUS != 0;
        let hubp = ((self.regs.read(hubp)? & HUBP_UNDERFLOW_STATUS) >> 28) as u8;
        Ok((otg || hubp != 0).then_some(Underflow { otg, hubp }))
    }
    /// Turn an underflowing stream black and quarantine it: the OPP pattern
    /// generator replaces the pixels at once, independent of the fetch.
    fn quarantine(&mut self, underflow: Underflow) -> Error {
        self.underflow = Some(underflow);
        let _ = self.opp.set_blank(true);
        self.state = State::Quarantined(underflow);
        Error::Underflow(underflow)
    }
    /// Poll a running stream for underflow. A latched underflow blanks the
    /// stream and quarantines the pipe; the caller decides when to stop it.
    pub fn check_underflow(&mut self) -> Result<Option<Underflow>, Error> {
        match self.state {
            State::At(Step::Running) => {}
            State::Quarantined(u) => return Ok(Some(u)),
            _ => return Err(Error::Busy),
        }
        match self.read_underflow()? {
            Some(u) => {
                self.quarantine(u);
                Ok(Some(u))
            }
            None => Ok(None),
        }
    }

    /// Light the connector with `sink`'s best mode. `draw` fills each scanout
    /// row (XRGB8888) before the plane is unblanked. `power` is the retained
    /// SMU's display-power step ([`crate::amdgpu_dcn30_clk::display_power`]);
    /// `links` are every board connector (the takeover powers all of them
    /// down); `aux` reaches this connector's sink (DP only).
    ///
    /// # Safety
    /// As [`Pipeline::new`]; `power` must enable this GPU's display power;
    /// `pool` is the exclusive VRAM pool; no CPU writer may touch the
    /// scanout once it is published except through the returned framebuffer.
    #[allow(clippy::too_many_arguments)]
    pub async unsafe fn enable<A: Aux + Send>(
        &mut self,
        power: impl Future<Output = Result<(), crate::amdgpu_dcn_clk::Error>>,
        pool: &Pool,
        tables: &Tables<'_>,
        board: Board,
        links: &[Connector],
        sink: &Sink,
        aux: &mut A,
        draw: impl Fn(u32, &mut [u32]),
    ) -> Result<Output, Error> {
        if self.state != State::At(Step::Prepared) {
            return Err(Error::Busy);
        }
        match self
            .bring_up(power, pool, tables, board, links, sink, aux, draw)
            .await
        {
            Ok(output) => {
                self.state = State::At(Step::Running);
                self.output = Some(output);
                Ok(output)
            }
            Err(error) => {
                let step = match self.state {
                    State::At(step) | State::Failed { step, .. } => step,
                    State::Quarantined(_) => Step::Verify,
                };
                // Blank and stop whatever started; the reservation stays
                // published (retained) because hardware may have fetched it.
                let _ = self.tear_down(tables, aux).await;
                self.state = State::Failed { step, error };
                Err(error)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn bring_up<A: Aux + Send>(
        &mut self,
        power: impl Future<Output = Result<(), crate::amdgpu_dcn_clk::Error>>,
        pool: &Pool,
        tables: &Tables<'_>,
        board: Board,
        links: &[Connector],
        sink: &Sink,
        aux: &mut A,
        draw: impl Fn(u32, &mut [u32]),
    ) -> Result<Output, Error> {
        let pipe = self.route.pipe;
        let signal = self.connector.signal;
        if signal == Signal::DisplayPort && sink.dpcd.is_none() {
            return Err(Error::NoSink);
        }
        // dcn30_init_hw and the takeover of whatever the GOP left lit.
        self.at(Step::InitHw);
        self.init_hw(tables, links).await?;
        // Board data next; no stream is touched if no mode fits.
        let levels = self.clocks.start_with(power).await.map_err(Error::Block)?;
        let refclk = self
            .hubbub
            .dchub_refclk_khz(board.crystal_khz)
            .map_err(Error::Hubbub)?;
        let soc =
            dml30::Soc::from_board(&levels, board.channels, board.channel_width_bytes, refclk)
                .map_err(Error::Mode)?;
        let (timing, avi, plan) = match signal {
            Signal::Hdmi => select_wanted(sink, &soc, levels.vco_khz, self.want)?,
            Signal::DisplayPort => {
                let (timing, plan) = select_dp_wanted(sink, &soc, levels.vco_khz, self.want)?;
                (timing, None, plan)
            }
        };
        self.admitted = Some(Admitted {
            soc,
            refclk_khz: refclk,
            plan,
            offered: offered(sink, &soc, levels.vco_khz),
        });
        // A DVI sink: no data islands may be sent, which this owner's HDMI
        // attribute path always enables.
        if signal == Signal::Hdmi && avi.is_none() {
            return Err(Error::NoSink);
        }
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

        // dc_commit_state_no_check: dce110_enable_accelerated_mode
        // (bios_set_scratch_acc_mode_change), so a later init skips golden
        // init; then prepare_bandwidth: clocks, then watermarks.
        self.at(Step::Clocks);
        self.regs.update(
            self.nbio1 + BIOS_SCRATCH_6 * 4,
            ATOM_S6_ACC_MODE,
            ATOM_S6_ACC_MODE,
        )?;
        let clocks = levels
            .plan(
                plan.clocks.dispclk_khz,
                plan.clocks.dppclk_khz,
                plan.clocks.dcfclk_khz,
            )
            .map_err(Error::Block)?;
        self.clocks.prepare(clocks).await.map_err(Error::Block)?;
        self.at(Step::Watermarks);
        // SAFETY: no HUBP fetches yet.
        unsafe { self.hubbub.program(&plan.hubbub, refclk) }.map_err(Error::Hubbub)?;
        // enable_stream_timing: OPTC clocks, then the pixel clock.
        self.at(Step::PixelClock);
        self.enable_optc_clock().await?;
        self.program_pix_clk(tables, timing.pixel_clock_khz)?;
        // Timing and global sync, the OPP clock and format, then black.
        self.at(Step::Timing);
        let sync = GlobalSync {
            v_startup_lines: plan.prefetch.v_startup,
            v_update_offset_pix: plan.prefetch.v_update_offset_pix,
            v_update_width_pix: plan.prefetch.v_update_width_pix,
            v_ready_offset_pix: plan.prefetch.v_ready_offset_pix,
        };
        match signal {
            Signal::Hdmi => self.otg.program_tmds_timing(&timing, &sync)?,
            Signal::DisplayPort => self.otg.program_timing(&timing, &sync)?,
        }
        self.opp
            .program(Encoding::Rgb, timing.h_active, timing.v_active)?;
        self.opp.set_blank(true)?;
        // enable_crtc, then one frame for the timing to settle.
        self.at(Step::Start);
        self.otg.enable()?;
        sleep_us(frame_us(&timing)).await;
        // dig_connect_to_otg and link_set_dpms_on.
        self.at(Step::Link);
        self.dig.connect_to_otg(pipe)?;
        match (signal, avi) {
            (Signal::Hdmi, Some(avi)) => self.link_hdmi(tables, &timing, &avi).await?,
            _ => self.link_dp(tables, &timing, sink, aux).await?,
        }
        // The front end, latched together at the unlock.
        self.at(Step::Plane);
        self.lock().await?;
        self.opp.set_blank(false)?;
        self.power_on_plane().await?;
        self.clocks
            .pipe_clock(pipe, plan.clocks.dppclk_khz)
            .map_err(Error::Block)?;
        self.dpp
            .program(Format::Rgb32, timing.h_active, timing.v_active)?;
        self.mpc.mux_plane(pipe, pipe)?;
        self.hubp.program(&surface, &plan.registers)?;
        self.program_cursor_ttu(plan.cursor)?;
        self.hubp.unblank().await?;
        self.clear_underflow()?;
        self.unlock()?;
        self.start_audio(&timing, sink).await;
        // Bounded watch: an underflow goes black and quarantines the pipe.
        self.at(Step::Verify);
        sleep_us(frame_us(&timing) * u64::from(VERIFY_FRAMES)).await;
        if let Some(underflow) = self.read_underflow()? {
            return Err(self.quarantine(underflow));
        }
        Ok(Output {
            connector: self.connector,
            route: self.route,
            timing,
            link: self.link,
            prefetch_mode: plan.prefetch_mode,
            v_startup: plan.prefetch.v_startup,
            dispclk_khz: clocks.display_khz,
            dppclk_khz: clocks.pixel_khz,
            inherited: self.inherited,
            scanout: fb,
        })
    }
    /// The stream's audio once pixels flow (`dce110_enable_audio_stream`
    /// and its setup half, as the DCN30 audio owner orders them). Audio never
    /// fails the display: an error is logged and the stream stays lit.
    async fn start_audio(&mut self, timing: &Timing, sink: &Sink) {
        let (otg, dig) = (self.route.pipe, self.route.stream);
        let stream = match self.connector.signal {
            Signal::Hdmi => AudioStream::hdmi(otg, dig, *timing),
            Signal::DisplayPort => AudioStream::dp(otg, dig, *timing),
        };
        // SAFETY: the stream is live and stays live until tear_down stops
        // its audio first; this pipeline owns the DIG and the endpoints.
        let result = unsafe {
            self.audio
                .start_for_sink(stream, &sink.edid, &mut self.clocks)
                .await
        };
        if let Err(error) = result {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 audio on DIG {dig} unavailable ({error:?}); display unaffected"
            );
        }
    }
    /// `link_set_dpms_on` for HDMI.
    async fn link_hdmi(
        &mut self,
        tables: &Tables<'_>,
        timing: &Timing,
        avi: &[u8; 36],
    ) -> Result<(), Error> {
        let transmitter = self.connector.path.transmitter;
        self.dig.setup(DigMode::Hdmi)?;
        // setup_dio_stream_attribute: stereo sync, then
        // enc3_stream_encoder_hdmi_set_stream_attribute.
        self.dig.setup_stereo_sync(self.route.pipe)?;
        tables.hdmi_stream_setup(self.bus(), self.route.stream, timing.pixel_clock_khz)?;
        self.dig.stream_attribute(timing.pixel_clock_khz)?;
        self.dig.info_packets(avi).await?;
        // enable_link_hdmi → dcn10_link_encoder_enable_tmds_output.
        tables.transmitter(
            self.bus(),
            &Transmitter {
                action: TransmitterAction::Enable,
                transmitter,
                mode: TransmitterMode::Hdmi,
                lanes: 4,
                hpd: self.connector.hpd,
                connector: 0,
                symbol_khz: timing.pixel_clock_khz,
            },
        )?;
        // The second setup Linux issues after transmitter control.
        self.dig.setup(DigMode::Hdmi)?;
        // dcn20_enable_stream: setup_dio_stream_encoder, update_info_frame.
        self.dig.connect_be_to_fe(true)?;
        self.dig.info_packets(avi).await?;
        self.dig.set_avmute(false)?;
        Ok(())
    }
    /// `link_set_dpms_on` for DisplayPort SST.
    async fn link_dp<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        timing: &Timing,
        sink: &Sink,
        aux: &mut A,
    ) -> Result<(), Error> {
        let caps = sink.dpcd.ok_or(Error::NoSink)?;
        let (rate, lanes) = dp_ceiling(&caps)?;
        self.dig.setup(DigMode::DisplayPort)?;
        self.dig.setup_stereo_sync(self.route.pipe)?;
        // DPRX_FEATURE_ENUMERATION_LIST (DPCD 1.4+): SST_SPLIT_SDP_CAP bit 1,
        // VSC_SDP_COLORIMETRY_SUPPORTED bit 3.
        let mut feature = [0u8];
        if caps[0] >= 0x14 {
            aux.read(dp::DPCD_DPRX_FEATURE_ENUMERATION_LIST, &mut feature)
                .await?;
        }
        let vsc_colorimetry = feature[0] & 1 << 3 != 0;
        let vsc = vsc_colorimetry.then(|| dp::vsc_packet(Depth::Bpc8));
        self.dp_stream.set_stream_attribute(
            timing,
            Depth::Bpc8,
            vsc_colorimetry,
            feature[0] & 1 << 1 != 0,
        )?;
        self.dp_stream.update_info_packets(vsc.as_ref()).await?;
        // enable_link_dp: the PHY clock floor (dcn30_notify_link_rate_change,
        // at the highest rate training may try), then the DIG backend
        // connected (setup_dio_stream_encoder) before training.
        let phy_max = self
            .clocks
            .levels()
            .map_or(0, |l| l.range(Clock::Phy).max_khz());
        let link_khz = (u32::from(rate) * dp::LINK_RATE_REF_KHZ).min(phy_max);
        self.clocks
            .phy_floor(link_khz)
            .await
            .map_err(Error::Block)?;
        self.dig.connect_be_to_fe(true)?;
        let mut phy = DpPhy {
            tables,
            regs: self.gpu.regs,
            authority: self.regs.authority,
            connector: self.connector,
        };
        let mut trainer = dp::Trainer {
            aux: &mut *aux,
            link: self.dp_link,
            phy: &mut phy,
            settings: None,
        };
        let settings = training::train(
            &mut trainer,
            caps,
            training::Limits {
                rate,
                lanes,
                pixel_clock_khz: timing.pixel_clock_khz,
                bits_per_pixel: Depth::Bpc8.bits_per_pixel(),
                dpia: false,
            },
        )
        .await
        .map_err(Error::Training)?;
        self.link = Some(DpLink {
            rate: settings.rate,
            lanes: settings.lanes,
        });
        sleep_us(DP_IDLE_US).await;
        self.dig.setup(DigMode::DisplayPort)?;
        // dcn20_enable_stream, then dcn20_unblank_stream.
        self.dig.connect_be_to_fe(true)?;
        self.dp_stream.update_info_packets(vsc.as_ref()).await?;
        self.dp_stream
            .unblank(timing.pixel_clock_khz, settings.rate)
            .await
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
        if HDP_FLUSH + 4 > self.regs.window.len() {
            return Err(Error::Unsupported);
        }
        self.regs.write(HDP_FLUSH, 0)?;
        self.regs.read(self.nbio2 + NBIO_MEMSIZE * 4)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    /// Undo every step that started, in Linux's stop order; each runs even
    /// after an earlier one failed.
    async fn tear_down<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut A,
    ) -> Result<(), Error> {
        let reached = self.reached;
        // Audio first, before the stream blanks (dce110_disable_audio_stream);
        // logged, never fatal to the display teardown.
        let dig = self.route.stream;
        if reached >= Step::Plane && self.audio.record(dig).is_some() {
            if let Err(error) = self.audio.stop(dig, &mut self.clocks).await {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 audio stop on DIG {dig} failed ({error:?})"
                );
            }
        }
        let mut first = Ok(());
        let mut record = |r: Result<(), Error>| {
            if first.is_ok() {
                first = r;
            }
        };
        // Front end: blank_pixel_data(true), MPCC removal, HUBP blank.
        if reached >= Step::Timing {
            record(self.opp.set_blank(true).map_err(Error::Block));
        }
        if reached >= Step::Plane {
            record(self.mpc.release(self.route.pipe).map_err(Error::Block));
            record(self.hubp.blank().await.map_err(Error::Block));
        }
        if reached >= Step::Link {
            match self.connector.signal {
                Signal::Hdmi => record(self.unlink_hdmi(tables)),
                Signal::DisplayPort => record(self.unlink_dp(tables, aux).await),
            }
        }
        // dcn20_reset_back_end_for_pipe: disable_crtc, then the OPTC clocks.
        // The PHY PLL is not powered down: dce110_clock_source_power_down's
        // SetPixelClock with CONTROLLER_ID_UNDEFINED is refused by
        // set_pixel_clock_v7, so Linux never runs it.
        if reached >= Step::Start {
            record(self.otg.disable().await.map_err(Error::Block));
        }
        if reached >= Step::PixelClock {
            record(self.disable_optc_clock());
        }
        first
    }
    /// `link_set_dpms_off` for HDMI: AVMUTE, `disable_stream` (InfoFrames
    /// stopped, frontend dropped from the backend), `disable_link`.
    fn unlink_hdmi(&mut self, tables: &Tables<'_>) -> Result<(), Error> {
        let mut first = Ok(());
        let mut record = |r: Result<(), Error>| {
            if first.is_ok() {
                first = r;
            }
        };
        record(self.dig.set_avmute(true).map_err(Error::Hdmi));
        record(self.dig.stop_info_packets().map_err(Error::Hdmi));
        record(self.dig.connect_be_to_fe(false).map_err(Error::Hdmi));
        // dcn10_link_encoder_disable_output returns early for an idle DIG.
        if !matches!(self.dp_link.enabled(), Ok(true)) {
            return first;
        }
        record(
            tables
                .transmitter(
                    self.bus(),
                    &Transmitter {
                        action: TransmitterAction::Disable,
                        transmitter: self.connector.path.transmitter,
                        mode: TransmitterMode::Hdmi,
                        lanes: 0,
                        hpd: self.connector.hpd,
                        connector: self.connector.object_id(),
                        symbol_khz: 0,
                    },
                )
                .map_err(Error::Bios),
        );
        first
    }
    /// `link_set_dpms_off` for DP SST: blank (60 ms), then `disable_link`
    /// before `disable_stream`, so the sink never sees TPS1 under video.
    async fn unlink_dp<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut A,
    ) -> Result<(), Error> {
        let mut first = Ok(());
        let mut record = |r: Result<(), Error>| {
            if first.is_ok() {
                first = r;
            }
        };
        record(self.dp_stream.blank().await);
        sleep_us(DP_BLANK_SETTLE_US).await;
        // dp_disable_link_phy: sink to D3, then disable_output and the
        // encoder reset for an enabled DIG.
        let _ = aux.write(dp::DPCD_SET_POWER, &[dp::SET_POWER_D3]).await;
        match self.dp_link.enabled() {
            Ok(true) => {
                let mut phy = DpPhy {
                    tables,
                    regs: self.gpu.regs,
                    authority: self.regs.authority,
                    connector: self.connector,
                };
                record(dp::Phy::disable(&mut phy));
                record(self.dp_link.reset());
            }
            Ok(false) => {}
            Err(error) => record(Err(error)),
        }
        record(self.dp_stream.stop_info_packets());
        record(self.dig.connect_be_to_fe(false).map_err(Error::Hdmi));
        self.link = None;
        first
    }
    /// Stop the stream: a running or quarantined one, or a bring-up whose
    /// future was cancelled. The scanout stays published (excluded from
    /// reuse) until the caller proves the HUBP idle across a reset.
    pub async fn disable<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut A,
    ) -> Result<(), Error> {
        match self.state {
            State::At(Step::Prepared | Step::Stopping | Step::Stopped) | State::Failed { .. } => {
                return Err(Error::Busy)
            }
            _ => {}
        }
        self.at(Step::Stopping);
        let result = self.tear_down(tables, aux).await;
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

/// No sink to reach: the AUX an HDMI pipeline is given.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAux;
impl Aux for NoAux {
    async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Aux)
    }
    async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), Error> {
        Err(Error::Aux)
    }
}

/// KMS hooks (amdgpu_navi22_kms / amdgpu_navi22_scanout).
impl Pipeline {
    /// Ask `enable` for exactly this timing (None: the sink's preferred).
    pub fn request(&mut self, timing: Option<Timing>) {
        self.want = timing;
    }
    /// The admission of the lit (or last attempted) sink.
    pub fn admitted(&self) -> Option<&Admitted> {
        self.admitted.as_ref()
    }
    /// GPU address of the activation surface, while one is reserved.
    pub fn scanout_address(&self) -> Option<u64> {
        self.scanout.as_ref().map(Reservation::address)
    }
    /// CPU mapping of the activation surface, while one is reserved.
    pub(crate) fn scanout_mapping(&self) -> Option<MmioRegion> {
        self.scanout.as_ref().map(Reservation::mapping)
    }
    /// Return the activation surface to the pool after a successful stop.
    ///
    /// # Safety
    /// `disable` returned Ok: the HUBP was blanked after its outstanding
    /// requests retired and the OTG stopped, so no fetch reads the surface,
    /// and no CPU view of it remains (`scanout_access::wait_retired`).
    pub unsafe fn release_scanout(&mut self) -> Result<(), Error> {
        if self.state != State::At(Step::Stopped) {
            return Err(Error::Busy);
        }
        if let Some(mut reservation) = self.scanout.take() {
            // SAFETY: the caller's proof that the display engine is idle.
            unsafe { reservation.stopped() };
        }
        Ok(())
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
