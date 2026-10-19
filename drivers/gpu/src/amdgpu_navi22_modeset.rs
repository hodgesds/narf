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
    amdgpu_dcn30_dp_link as dp_link,
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
pub const PIPES: u8 = 6; // linux: n/a (dcn30_resource.c res_cap_dcn3.num_timing_generator = 6)
pub const STREAMS: u8 = 6; // linux: n/a (dcn30_resource.c res_cap_dcn3.num_stream_encoder = 6)
pub const PLLS: u8 = 6; // linux: n/a (dcn30_resource.c res_cap_dcn3.num_pll = 6)
/// The highest unscrambled TMDS rate; above it [`hdmi::stream_for`]
/// scrambles and configures the sink over SCDC.
pub const MAX_TMDS_KHZ: u32 = hdmi::TMDS_SCRAMBLE_KHZ - 1;
/// `dcn20_link_encoder_get_max_link_cap`: HBR3 on four lanes.
pub const MAX_DP_RATE: u8 = 0x1e; // linux: LINK_RATE_HIGH3
pub const MAX_DP_LANES: u8 = 4; // linux: LANE_COUNT_FOUR
const PITCH_ALIGN: u32 = 256; // linux: n/a (NARF scanout pitch alignment)
                              // dccg2_init and the clock source, DCN base index 1 (`dcn_3_0_0_offset.h`).
                              // linux-ctx: hdr=dcn seg=1
const REFCLK_CNTL: u64 = 0x0049; // linux: mmREFCLK_CNTL
const MILLISECOND_TIME_BASE_DIV: u64 = 0x0070; // linux: mmMILLISECOND_TIME_BASE_DIV
const DISPCLK_FREQ_CHANGE_CNTL: u64 = 0x0071; // linux: mmDISPCLK_FREQ_CHANGE_CNTL
const MICROSECOND_TIME_BASE_DIV: u64 = 0x007b; // linux: mmMICROSECOND_TIME_BASE_DIV
/// `OTGn_PIXEL_RATE_CNTL`, `DP_DTOn_PHASE`, `DP_DTOn_MODULO`, stride 4.
const OTG0_PIXEL_RATE_CNTL: u64 = 0x0080; // linux: mmOTG0_PIXEL_RATE_CNTL
const DP_DTO0_PHASE: u64 = 0x0081; // linux: mmDP_DTO0_PHASE
const DP_DTO0_MODULO: u64 = 0x0082; // linux: mmDP_DTO0_MODULO
const DTO_STRIDE: u64 = 4; // linux: mmOTG1_PIXEL_RATE_CNTL - mmOTG0_PIXEL_RATE_CNTL
const DP_DTO0_ENABLE: u32 = 1 << 4; // linux: OTG0_PIXEL_RATE_CNTL__DP_DTO0_ENABLE_MASK
/// `PHYPLLx_PIXCLK_RESYNC_CNTL` per combo PHY PLL A..F, and its
/// `PHYPLLA_DCCG_DEEP_COLOR_CNTL` field (the only one in DCN3.0's mask list).
// linux: mmPHYPLLA_PIXCLK_RESYNC_CNTL; mmPHYPLLB_PIXCLK_RESYNC_CNTL; mmPHYPLLC_PIXCLK_RESYNC_CNTL
// linux: mmPHYPLLD_PIXCLK_RESYNC_CNTL; mmPHYPLLE_PIXCLK_RESYNC_CNTL; mmPHYPLLF_PIXCLK_RESYNC_CNTL
const PIXCLK_RESYNC_CNTL: [u64; 6] = [0x0040, 0x0041, 0x0042, 0x0043, 0x004c, 0x007e];
// linux: PHYPLLA_PIXCLK_RESYNC_CNTL__PHYPLLA_DCCG_DEEP_COLOR_CNTL_MASK
const DCCG_DEEP_COLOR_CNTL: u32 = 0x30;
/// `clk_mgr->dprefclk_khz` on DCN3.0: `dcn3_clk_mgr_construct` sets 730 MHz
/// and `dcn3_dump_clk_registers` never replaces it.
// linux: n/a (dcn30_clk_mgr.c dcn3_clk_mgr_construct: dprefclk_khz = 730000)
const DPREFCLK_KHZ: u32 = 730_000;
const LAST_DCN1: u32 = MICROSECOND_TIME_BASE_DIV as u32; // linux: mmMICROSECOND_TIME_BASE_DIV
                                                         // dcn20_dpp_pg_control / dcn20_hubp_pg_control, DCN base index 2: HUBP n is
                                                         // DOMAIN(2n), DPP n DOMAIN(2n + 1); each STATUS follows its CONFIG.
                                                         // linux-ctx: hdr=dcn seg=2
const DOMAIN0_PG_CONFIG: u64 = 0x0080; // linux: mmDOMAIN0_PG_CONFIG
const DOMAIN_POWER_GATE: u32 = 1 << 8; // linux: DOMAIN0_PG_CONFIG__DOMAIN0_POWER_GATE_MASK
                                       // linux: DOMAIN0_PG_STATUS__DOMAIN0_PGFSM_PWR_STATUS_MASK
const DOMAIN_PGFSM_PWR_STATUS: u32 = 0xc000_0000;
const DC_IP_REQUEST_CNTL: u64 = 0x00b2; // linux: mmDC_IP_REQUEST_CNTL
                                        // HUBP instance block, stride 0xdc.
const HUBP_STRIDE: u64 = 0xdc; // linux: mmHUBP1_HUBP_CLK_CNTL - mmHUBP0_HUBP_CLK_CNTL
const HUBP0_DCHUBP_CNTL: u64 = 0x05f3; // linux: mmHUBP0_DCHUBP_CNTL
const HUBP0_HUBP_CLK_CNTL: u64 = 0x05f4; // linux: mmHUBP0_HUBP_CLK_CNTL
const HUBP_CLOCK_ENABLE: u32 = 1 << 0; // linux: HUBP0_HUBP_CLK_CNTL__HUBP_CLOCK_ENABLE_MASK
/// `HUBPREQn_DCN_CUR0_TTU_CNTL0/1`: REFCYC_PER_REQ_DELIVERY (23 bits),
/// QoS_LEVEL_FIXED and QoS_RAMP_DISABLE; REFCYC_PER_REQ_DELIVERY_PRE.
const HUBP0_DCN_CUR0_TTU_CNTL0: u64 = 0x0630; // linux: mmHUBPREQ0_DCN_CUR0_TTU_CNTL0
const HUBP0_DCN_CUR0_TTU_CNTL1: u64 = 0x0631; // linux: mmHUBPREQ0_DCN_CUR0_TTU_CNTL1
/// `DCHUBP_CNTL.HUBP_UNDERFLOW_STATUS` (3 bits) and `HUBP_UNDERFLOW_CLEAR`.
// linux: HUBP0_DCHUBP_CNTL__HUBP_UNDERFLOW_STATUS_MASK
const HUBP_UNDERFLOW_STATUS: u32 = 0x7000_0000;
// linux: HUBP0_DCHUBP_CNTL__HUBP_UNDERFLOW_CLEAR_MASK
const HUBP_UNDERFLOW_CLEAR: u32 = 0x8000_0000;
// OTG instance block, stride 0x80.
const OTG_STRIDE: u64 = 0x80; // linux: mmOTG1_OTG_CONTROL - mmOTG0_OTG_CONTROL
const OTG0_OTG_CLOCK_CONTROL: u64 = 0x1b86; // linux: mmOTG0_OTG_CLOCK_CONTROL
const OTG_CLOCK_EN: u32 = 1 << 0; // linux: OTG0_OTG_CLOCK_CONTROL__OTG_CLOCK_EN_MASK
const OTG_CLOCK_GATE_DIS: u32 = 1 << 1; // linux: OTG0_OTG_CLOCK_CONTROL__OTG_CLOCK_GATE_DIS_MASK
const OTG_CLOCK_ON: u32 = 1 << 8; // linux: OTG0_OTG_CLOCK_CONTROL__OTG_CLOCK_ON_MASK
const OTG0_OTG_MASTER_UPDATE_LOCK: u64 = 0x1b8b; // linux: mmOTG0_OTG_MASTER_UPDATE_LOCK
const OTG0_OTG_GLOBAL_CONTROL2: u64 = 0x1b92; // linux: mmOTG0_OTG_GLOBAL_CONTROL2
                                              // linux: OTG0_OTG_MASTER_UPDATE_LOCK__OTG_MASTER_UPDATE_LOCK_MASK
const OTG_MASTER_UPDATE_LOCK: u32 = 1 << 0;
// linux: OTG0_OTG_MASTER_UPDATE_LOCK__UPDATE_LOCK_STATUS_MASK
const UPDATE_LOCK_STATUS: u32 = 1 << 8;
// linux: OTG0_OTG_GLOBAL_CONTROL2__OTG_MASTER_UPDATE_LOCK_SEL_MASK
const OTG_MASTER_UPDATE_LOCK_SEL: u32 = 0x0e00_0000;
// ODM instance block, stride 0x10.
// linux: mmODM1_OPTC_DATA_SOURCE_SELECT - mmODM0_OPTC_DATA_SOURCE_SELECT
const ODM_STRIDE: u64 = 0x10;
const ODM0_OPTC_INPUT_GLOBAL_CONTROL: u64 = 0x1aca; // linux: mmODM0_OPTC_INPUT_GLOBAL_CONTROL
                                                    // linux: ODM0_OPTC_INPUT_GLOBAL_CONTROL__OPTC_UNDERFLOW_OCCURRED_STATUS_MASK
const OPTC_UNDERFLOW_OCCURRED_STATUS: u32 = 0x400;
// linux: ODM0_OPTC_INPUT_GLOBAL_CONTROL__OPTC_UNDERFLOW_CLEAR_MASK
const OPTC_UNDERFLOW_CLEAR: u32 = 0x1000;
const ODM0_OPTC_INPUT_CLOCK_CONTROL: u64 = 0x1acf; // linux: mmODM0_OPTC_INPUT_CLOCK_CONTROL
                                                   // linux: ODM0_OPTC_INPUT_CLOCK_CONTROL__OPTC_INPUT_CLK_GATE_DIS_MASK
const OPTC_INPUT_CLK_GATE_DIS: u32 = 1 << 0;
// linux: ODM0_OPTC_INPUT_CLOCK_CONTROL__OPTC_INPUT_CLK_EN_MASK
const OPTC_INPUT_CLK_EN: u32 = 1 << 1;
// linux: ODM0_OPTC_INPUT_CLOCK_CONTROL__OPTC_INPUT_CLK_ON_MASK
const OPTC_INPUT_CLK_ON: u32 = 1 << 2;
/// The last register this owner touches directly in bank 2.
// linux-ctx: reset
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
// linux-ctx: hdr=nbio seg=1
const BIOS_SCRATCH_6: u64 = 0x003e; // linux: mmBIOS_SCRATCH_6
                                    // linux-ctx: reset
const ATOM_S6_ACC_MODE: u32 = 1 << 4; // linux: ATOM_S6_ACC_MODE
/// The HDP flush page and NBIO's MEMSIZE read for posting (`hdp_v5_0_flush_hdp`).
// linux: n/a (MMIO_REG_HOLE_OFFSET 0x80000 - PAGE_SIZE, local in nbio_v2_3.c)
const HDP_FLUSH: u64 = 0x7f000;
// linux-ctx: hdr=nbio seg=2
const NBIO_MEMSIZE: u64 = 0xc3; // linux: mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
/// Frames watched for underflow after the front end latches.
// linux-ctx: reset
const VERIFY_FRAMES: u32 = 2; // linux: n/a (NARF policy)
/// `link_set_dpms_off`'s `msleep(60)` after blanking a non-eDP DP stream.
const DP_BLANK_SETTLE_US: u64 = 60_000; // linux: n/a (msleep(60), literal in link_set_dpms_off)
/// `video_optimized_pixel_rates[]` (`dce_clock_source.c`): requested pixel
/// clock range in kHz, the target rate, and the DTO multiplier/divider.
// linux: n/a (dce_clock_source.c video_optimized_pixel_rates[], verified row by row)
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
    pub(super) capacity: u8,
    pipes: u8,
    streams: u8,
    plls: u8,
    /// Multi-stream (`acquire_stream`): streams sharing each PHY PLL beyond
    /// its first (`resource_reference_clock_source`), the timing a shared
    /// PLL runs, and the DSC engines in use.
    pll_sharers: [u8; PLLS as usize],
    pll_timing: [Option<Timing>; PLLS as usize],
    dscs: u8,
}
fn first_free(used: u8, count: u8) -> Option<u8> {
    (0..count).find(|i| used & 1 << i == 0)
}
impl Resources {
    pub const fn new() -> Self {
        Self {
            capacity: PIPES,
            pipes: 0,
            streams: 0,
            plls: 0,
            pll_sharers: [0; PLLS as usize],
            pll_timing: [None; PLLS as usize],
            dscs: 0,
        }
    }
    pub fn for_gpu(gpu: &AmdGpu) -> Result<Self, Error> {
        let profile = crate::amdgpu_dcn_profile::Profile::resolve(gpu)?;
        if !profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            capacity: profile.pipes(),
            ..Self::new()
        })
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
        let pipe = first_free(self.pipes, self.capacity).ok_or(Error::Busy)?;
        let preferred = connector.path.transmitter;
        if preferred >= self.capacity {
            return Err(Error::Invalid);
        }
        let stream = if self.streams & 1 << preferred == 0 {
            preferred
        } else {
            (0..self.capacity)
                .rev()
                .find(|i| self.streams & 1 << i == 0)
                .ok_or(Error::Busy)?
        };
        let clock = match connector.signal {
            Signal::Hdmi => {
                ClockSource::Pll(first_free(self.plls, self.capacity).ok_or(Error::Busy)?)
            }
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
            if !self.unshare_pll(pll) {
                self.plls &= !(1 << pll);
            }
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
/// that the sink, the DCN3.0 TMDS encoder (HDMI 2.0 scrambling above 340
/// MHz, deep colour, 4:2:0; [`hdmi::stream_for`]) and the DCN30 mode math all
/// accept, with the AVI InfoFrame Linux's `set_avi_info_frame` would send
/// for it. DVI sinks get no InfoFrame.
#[cfg(feature = "kernel-test")]
pub(crate) fn select(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
) -> Result<(Timing, Option<[u8; 36]>, dml30::Plan), Error> {
    select_hdmi(sink, soc, vco_khz, None, hdmi::Limits::DEFAULT).map(|(t, s, p)| (t, s.avi, p))
}
/// The HDMI stream of `timing` on `sink` under the board's `limits`, with
/// DML30's HDMI output bound (`min(600, PHYCLK)`), the `amdgpu.max_bpc`
/// ceiling and "Broadcast RGB" shared with the Navi48 path.
pub(crate) fn hdmi_stream(
    sink: &Sink,
    timing: &Timing,
    soc: &dml30::Soc,
    limits: hdmi::Limits,
) -> Option<hdmi::Stream> {
    use crate::amdgpu_navi48_boot as navi48;
    let limits = hdmi::Limits {
        max_phy_khz: limits.max_phy_khz.min(soc.max_phyclk_khz),
        ..limits
    };
    hdmi::stream_for(
        &sink.edid,
        timing,
        navi48::max_bpc(),
        navi48::limited_range(navi48::broadcast_rgb()),
        limits,
    )
}
/// [`select`] with the whole stream, or exactly `want` when DRM asked for a
/// timing the same checks admit.
pub(crate) fn select_hdmi(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
    want: Option<Timing>,
    limits: hdmi::Limits,
) -> Result<(Timing, hdmi::Stream, dml30::Plan), Error> {
    if let Some(want) = want {
        if !offered(sink, soc, vco_khz).contains(&want) {
            return Err(Error::NoMode);
        }
        let stream = hdmi_stream(sink, &want, soc, limits).ok_or(Error::NoMode)?;
        let plan = dml30::plan(&config(&want, vco_khz), soc).map_err(Error::Mode)?;
        return Ok((want, stream, plan));
    }
    for timing in crate::amdgpu_navi48_boot::edid_timings(&sink.edid) {
        let Some(stream) = hdmi_stream(sink, &timing, soc, limits) else {
            continue;
        };
        let Ok(plan) = dml30::plan(&config(&timing, vco_khz), soc) else {
            continue;
        };
        return Ok((timing, stream, plan));
    }
    Err(Error::NoMode)
}
/// The link a DP sink's modes are checked against: its verified link, or
/// before verification what its receiver caps bound
/// (`verify_link_capability_non_destructive`'s `dp_get_max_link_cap`).
fn dp_link_cap(sink: &Sink, verified: Option<DpLink>) -> Option<DpLink> {
    verified.or_else(|| dp_link::Caps::from_dpcd(sink.dpcd?).max_link())
}
/// `dp_validate_mode_timing` at 8 bpc RGB against `link`.
fn dp_fits(timing: &Timing, link: DpLink) -> bool {
    dp_link::mode_fits(
        link,
        timing.h_active,
        timing.v_active,
        timing.pixel_clock_khz,
        Depth::Bpc8.bits_per_pixel(),
    )
}
/// The DP mode: exactly `want` when DRM asked for one `offered_on` admits,
/// else the first (EDID order, so preferred first) the link and the DCN30
/// mode math accept.
pub(crate) fn select_dp_on(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
    want: Option<Timing>,
    verified: Option<DpLink>,
) -> Result<(Timing, dml30::Plan), Error> {
    if sink.dpcd.is_none() {
        return Err(Error::NoSink);
    }
    let offered = offered_on(sink, soc, vco_khz, verified);
    let timing = match want {
        Some(want) if offered.contains(&want) => want,
        Some(_) => return Err(Error::NoMode),
        None => *offered.first().ok_or(Error::NoMode)?,
    };
    let plan = dml30::plan(&config(&timing, vco_khz), soc).map_err(Error::Mode)?;
    Ok((timing, plan))
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

/// Every distinct EDID timing `select_hdmi`/`select_dp_on` could choose: a
/// stream the DCN3.0 TMDS encoder carries (HDMI) or inside the sink's link at
/// 8 bpc (a sink with DPCD, i.e. DisplayPort: its receiver-caps ceiling until
/// verified), and admitted by the DCN30 mode math. This is what KMS offers;
/// a DRM TEST_ONLY or SETCRTC is checked against it.
pub(crate) fn offered(sink: &Sink, soc: &dml30::Soc, vco_khz: u32) -> Vec<Timing> {
    offered_on(sink, soc, vco_khz, None)
}
/// `offered` for a DP sink whose link was verified at `verified`
/// (`dp_validate_mode_timing` against `verified_link_cap`).
pub(crate) fn offered_on(
    sink: &Sink,
    soc: &dml30::Soc,
    vco_khz: u32,
    verified: Option<DpLink>,
) -> Vec<Timing> {
    let link = sink.dpcd.map(|_| dp_link_cap(sink, verified));
    let mut out: Vec<Timing> = Vec::new();
    for timing in crate::amdgpu_navi48_boot::edid_timings(&sink.edid) {
        let fits = match link {
            None => hdmi_stream(sink, &timing, soc, hdmi::Limits::DEFAULT).is_some(),
            Some(Some(link)) => dp_fits(&timing, link),
            Some(None) => false,
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
    /// The DP link layer's state (`amdgpu_dcn30_dp_link`).
    dp: DpState,
    /// m5hdmi: the pipe's output format stages (FMT, OTG 4:2:0, OCSC, DPG
    /// black), and the admitted HDMI stream (format, clocks, scrambling).
    format: hdmi::Formatter,
    hdmi: Option<hdmi::Stream>,
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
        let profile = crate::amdgpu_dcn_profile::Profile::resolve(gpu)?;
        if !profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        if route.pipe >= profile.pipes()
            || route.stream >= profile.streams()
            || matches!(route.clock, ClockSource::Pll(p) if p >= profile.channels())
            || matches!(
                (connector.signal, route.clock),
                (Signal::Hdmi, ClockSource::DpDto) | (Signal::DisplayPort, ClockSource::Pll(_))
            )
        {
            return Err(Error::Invalid);
        }
        let transmitter = connector.path.transmitter;
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
                dp: DpState::default(),
                format: hdmi::Formatter::new(gpu, authority, pipe)?,
                hdmi: None,
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
            // linux: n/a (literal in dcn20_dccg.c:dccg2_init)
            (MICROSECOND_TIME_BASE_DIV, 0x0012_0264),
            // linux: n/a (literal in dcn20_dccg.c:dccg2_init)
            (MILLISECOND_TIME_BASE_DIV, 0x0011_86a0),
            // linux: n/a (literal in dcn20_dccg.c:dccg2_init)
            (DISPCLK_FREQ_CHANGE_CNTL, 0x0e01_003c),
            (REFCLK_CNTL, 0),
        ] {
            self.regs.write(self.d1(reg), value)?;
        }
        let scratch = self.regs.read(self.nbio1 + BIOS_SCRATCH_6 * 4)?;
        let mut takeover = self.takeover();
        if scratch & ATOM_S6_ACC_MODE == 0 {
            tables.pipe_power_gating(self.bus(), 0, PipeAction::Init)?;
            for pipe in 0..crate::amdgpu_dcn_profile::Profile::resolve(&self.gpu)?.pipes() {
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
    /// colour resync for TMDS (`dce112_program_pix_clk`: the target is the
    /// deep-colour-scaled clock of the 4:2:0-halved pixel clock, and
    /// DCCG_DEEP_COLOR_CNTL the depth); the DP DTO for DisplayPort.
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
                        pixel_100hz: self.hdmi.map_or(pixel_khz * 10, |s| s.character_100hz),
                        // dce112_program_pix_clk never sets bp_pc_params.color_depth:
                        // the table gets DEEPCOLOR_RATIO_DIS and the deep-colour DTO is
                        // the resync below (dce112_program_pixel_clk_resync).
                        deep_color: 0, // linux: PIXEL_CLOCK_V7_DEEPCOLOR_RATIO_DIS
                    },
                )?;
                let resync = self.d1(PIXCLK_RESYNC_CNTL[usize::from(pll)]);
                let deep = self.hdmi.map_or(0, |s| s.format.depth.code() << 4);
                self.regs.update(resync, DCCG_DEEP_COLOR_CNTL, deep)
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
        if !crate::amdgpu_dcn_profile::Profile::resolve(&self.gpu)?.has_plane_power_gating() {
            let clock = self.d2(HUBP0_HUBP_CLK_CNTL + pipe * HUBP_STRIDE);
            return self
                .regs
                .update(clock, HUBP_CLOCK_ENABLE, HUBP_CLOCK_ENABLE);
        }
        self.regs.write(request, 1)?; // linux-lit: 1=DC_IP_REQUEST_CNTL__IP_REQUEST_EN_MASK
        if self.route.pipe != 5 {
            // linux: n/a (pipe 5 power gating de-featured, dcn20_hwseq.c)
            // linux-lit: 2=mmDOMAIN1_PG_CONFIG - mmDOMAIN0_PG_CONFIG
            for domain in [2 * pipe + 1, 2 * pipe] {
                let config = self.d2(DOMAIN0_PG_CONFIG + 2 * domain);
                self.regs.update(config, DOMAIN_POWER_GATE, 0)?;
                if !self
                    .regs
                    // linux-lit: 4=(mmDOMAIN0_PG_STATUS - mmDOMAIN0_PG_CONFIG) * 4
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
            // linux-lit: 0x007f_ffff=HUBPREQ0_DCN_CUR0_TTU_CNTL0__REFCYC_PER_REQ_DELIVERY_MASK
            ttu.refcyc_per_req_delivery & 0x007f_ffff
                // linux-lit: 24=HUBPREQ0_DCN_CUR0_TTU_CNTL0__QoS_LEVEL_FIXED__SHIFT
                // linux-lit: 0xf=HUBPREQ0_DCN_CUR0_TTU_CNTL0__QoS_LEVEL_FIXED_MASK >> 24
                | (ttu.qos_level_fixed & 0xf) << 24
                // linux-lit: 28=HUBPREQ0_DCN_CUR0_TTU_CNTL0__QoS_RAMP_DISABLE__SHIFT
                | (ttu.qos_ramp_disable & 1) << 28,
        )?;
        self.regs.write(
            self.d2(HUBP0_DCN_CUR0_TTU_CNTL1 + hubp),
            // linux-lit: 0x007f_ffff=HUBPREQ0_DCN_CUR0_TTU_CNTL1__REFCYC_PER_REQ_DELIVERY_PRE_MASK
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
        // linux-lit: 28=HUBP0_DCHUBP_CNTL__HUBP_UNDERFLOW_STATUS__SHIFT
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
                .and_then(|soc| soc.for_gpu(&self.gpu))
                .map_err(Error::Mode)?;
        // Detection's link half for DP (retrieve_link_cap, then the
        // destructive verify_link_capability): modes are what it verified.
        let verified = match signal {
            Signal::DisplayPort => Some(self.discover_dp(tables, sink, aux).await?),
            Signal::Hdmi => None,
        };
        let (timing, avi, plan) = match signal {
            Signal::Hdmi => {
                let limits = self.hdmi_limits(tables);
                let (t, stream, plan) = select_hdmi(sink, &soc, levels.vco_khz, self.want, limits)?;
                self.hdmi = Some(stream);
                (t, stream.avi, plan)
            }
            Signal::DisplayPort => {
                let (timing, plan) = select_dp_on(sink, &soc, levels.vco_khz, self.want, verified)?;
                (timing, None, plan)
            }
        };
        self.admitted = Some(Admitted {
            soc,
            refclk_khz: refclk,
            plan,
            offered: offered_on(sink, &soc, levels.vco_khz, verified),
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
        self.hdmi_format().await?;
        // enable_crtc, then one frame for the timing to settle.
        self.at(Step::Start);
        self.otg.enable()?;
        sleep_us(frame_us(&timing)).await;
        // dig_connect_to_otg and link_set_dpms_on.
        self.at(Step::Link);
        self.dig.connect_to_otg(pipe)?;
        match (signal, avi) {
            (Signal::Hdmi, Some(_)) => self.link_hdmi(tables, aux).await?,
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
        self.hubp.select_vtg(pipe)?;
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
    async fn link_hdmi<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut A,
    ) -> Result<(), Error> {
        let stream = self.hdmi.ok_or(Error::Invalid)?;
        let transmitter = self.connector.path.transmitter;
        self.dig.setup(DigMode::Hdmi)?;
        // setup_dio_stream_attribute: stereo sync, then
        // enc3_stream_encoder_hdmi_set_stream_attribute at phy_pix_clk.
        self.dig.setup_stereo_sync(self.route.pipe)?;
        tables.hdmi_stream_setup(self.bus(), self.route.stream, stream.character_khz)?;
        self.dig.hdmi_stream_attribute(&stream)?;
        self.dig.hdmi_info_packets(&stream).await?;
        // enable_link_hdmi: write_scdc_data, then setup_dio_stream_encoder
        // (the backend takes the frontend first, so a 1/4-rate clock channel
        // is in place above 340 MHz), dcn10_link_encoder_enable_tmds_output
        // at phy_pix_clk, read_scdc_data.
        hdmi::write_scdc_data(aux, &stream).await?;
        self.dig.connect_be_to_fe(true)?;
        tables.transmitter(
            self.bus(),
            &Transmitter {
                action: TransmitterAction::Enable,
                transmitter,
                mode: TransmitterMode::Hdmi,
                lanes: 4,
                hpd: self.connector.hpd,
                connector: 0,
                symbol_khz: stream.character_khz,
            },
        )?;
        if let Some(status) = hdmi::read_scdc_data(aux, &stream).await {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 HDMI {} kHz {} bpc{} SCDC TMDS_Config {:#x} scrambler {:?} flags {:?}",
                stream.character_khz,
                stream.format.depth.bpc(),
                if stream.format.ycbcr420 { " 4:2:0" } else { "" },
                status.tmds_config,
                status.scrambler_status,
                status.status_flags,
            );
        }
        // The second setup Linux issues after transmitter control.
        self.dig.setup(DigMode::Hdmi)?;
        // dcn20_enable_stream: setup_dio_stream_encoder, update_info_frame.
        self.dig.connect_be_to_fe(true)?;
        self.dig.hdmi_info_packets(&stream).await?;
        self.dig.set_avmute(false)?;
        Ok(())
    }
    /// m5hdmi: the board's HDMI ceilings, from the VBIOS encoder caps of
    /// this connector's transmitter (`dcn30_link_encoder_construct`: no
    /// record keeps HDMI_6GB_EN 1).
    fn hdmi_limits(&self, tables: &Tables<'_>) -> hdmi::Limits {
        let caps = crate::amdgpu_dcn_inventory::encoder_caps(
            tables.image(),
            self.connector.path.transmitter,
        );
        hdmi::Limits {
            hdmi6g: !matches!(caps, Ok(Some(c)) if c & crate::amdgpu_dcn_inventory::ENCODER_CAP_HDMI6GBPS_EN == 0),
            ..hdmi::Limits::DEFAULT
        }
    }
    /// m5hdmi: the HDMI stream's output format on the pipe, after the timing
    /// and before the OTG starts: OTG 4:2:0 container, FMT dither/clamp/
    /// encoding, OCSC and the DPG's black for the colour space.
    async fn hdmi_format(&mut self) -> Result<(), Error> {
        let Some(stream) = self.hdmi.filter(|_| self.connector.signal == Signal::Hdmi) else {
            return Ok(());
        };
        let format = stream.format;
        self.format.program_otg(format)?;
        self.format.program_fmt(format)?;
        self.format.program_ocsc(format).await?;
        self.format.set_blank_color(format)?;
        Ok(())
    }
    /// m5hdmi: the admitted HDMI stream (format, clocks, SCDC), for the link
    /// owner's unplug path ([`hdmi::write_scdc_legacy`]).
    pub fn hdmi_output(&self) -> Option<hdmi::Stream> {
        self.hdmi
    }
    /// `link_set_dpms_on` for DisplayPort SST at the least link the
    /// verified one has that carries the stream (`decide_dp_link_settings`).
    async fn link_dp<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        timing: &Timing,
        _sink: &Sink,
        aux: &mut A,
    ) -> Result<(), Error> {
        let caps = self.dp.caps.ok_or(Error::NoSink)?;
        let verified = self.dp.verified.ok_or(Error::NoSink)?;
        let setting = dp_link::decide_link_settings(
            verified,
            timing.pixel_clock_khz,
            Depth::Bpc8.bits_per_pixel(),
        )
        .ok_or(Error::NoMode)?;
        self.link_dp_at(tables, timing, &caps, setting, aux).await
    }
    /// `link_set_dpms_on` for DisplayPort SST at `setting`: DIG setup, stream
    /// attributes and SDPs, the PHY clock, the backend connected
    /// (`setup_dio_stream_encoder` before training), training with retries
    /// (`perform_link_training_with_retries`), then `dcn20_enable_stream`
    /// and `dcn20_unblank_stream`.
    async fn link_dp_at<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        timing: &Timing,
        caps: &dp_link::Caps,
        setting: DpLink,
        aux: &mut A,
    ) -> Result<(), Error> {
        self.dig.setup(DigMode::DisplayPort)?;
        self.dig.setup_stereo_sync(self.route.pipe)?;
        // DPRX_FEATURE_ENUMERATION_LIST (retrieve_link_cap, extended caps
        // only): SST_SPLIT_SDP_CAP bit 1, VSC_SDP_COLORIMETRY_SUPPORTED bit 3.
        let feature = caps.dprx_feature;
        let vsc_colorimetry = feature & 1 << 3 != 0;
        let vsc = vsc_colorimetry.then(|| dp::vsc_packet(Depth::Bpc8));
        self.dp_stream.set_stream_attribute(
            timing,
            Depth::Bpc8,
            vsc_colorimetry,
            feature & 1 << 1 != 0,
        )?;
        self.dp_stream.update_info_packets(vsc.as_ref()).await?;
        // enable_link_dp: the PHY clock (requested_sym_clk, through
        // dcn30_notify_link_rate_change), then the DIG backend connected.
        let phy_max = self
            .clocks
            .levels()
            .map_or(0, |l| l.range(Clock::Phy).max_khz());
        let link_khz = (u32::from(setting.rate) * dp::LINK_RATE_REF_KHZ).min(phy_max);
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
        let mut source = dp::DioSource {
            link: self.dp_link,
            phy: &mut phy,
        };
        let trained = dp_link::train_with_retries(aux, &mut source, caps, setting).await?;
        self.link = Some(trained);
        self.dig.setup(DigMode::DisplayPort)?;
        // dcn20_enable_stream, then dcn20_unblank_stream.
        self.dig.connect_be_to_fe(true)?;
        self.dp_stream.update_info_packets(vsc.as_ref()).await?;
        self.dp_stream
            .unblank(timing.pixel_clock_khz, trained.rate)
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
            if let Some(s) = self.hdmi.filter(|_| self.connector.signal == Signal::Hdmi) {
                record(self.format.set_blank_color(s.format).map_err(Error::Hdmi));
            }
        }
        if reached >= Step::Plane {
            record(self.mpc.release(self.route.pipe).map_err(Error::Block));
            record(self.hubp.blank().await.map_err(Error::Block));
        }
        // A link verification the future dropped may have left the PHY on.
        if self.dp.probing {
            record(self.stop_dp_probe(tables, aux).await);
        }
        if reached >= Step::Link {
            match self.connector.signal {
                Signal::Hdmi => {
                    // link_set_dpms_off: AVMUTE, then the legacy SCDC write.
                    record(self.dig.set_avmute(true).map_err(Error::Hdmi));
                    hdmi::write_scdc_legacy(aux, self.hdmi.is_some_and(|s| s.scdc)).await;
                    record(self.unlink_hdmi(tables))
                }
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

/// The DP link layer's view of the pipeline's sink.
#[derive(Clone, Debug, Default)]
struct DpState {
    /// The board's VBIOS LTTPR policy.
    lttpr: dp_link::VbiosLttpr,
    /// `retrieve_link_cap`'s result for the sink being lit.
    caps: Option<dp_link::Caps>,
    /// `verified_link_cap`: assumed from an earlier verification of the same
    /// sink, or found by `discover_dp`.
    verified: Option<DpLink>,
    /// A verification is in flight: the PHY may be on outside `Step::Link`.
    probing: bool,
    /// The sink's EDID, for the audio a retrain restarts.
    edid: Vec<u8>,
}

/// What a DP link check of a running stream found
/// (`amdgpu_dcn30_dp_link::handle_hpd_rx_irq`).
pub use crate::amdgpu_dcn30_dp_link::RxEvent;

/// The DP link layer (`amdgpu_dcn30_dp_link`): detection's capability
/// retrieval and link verification, link-loss checks, retraining and
/// unplug teardown.
impl Pipeline {
    /// The board's VBIOS LTTPR policy (`dcn30_resource_construct`), before
    /// `enable`.
    pub fn set_lttpr_policy(&mut self, policy: dp_link::VbiosLttpr) {
        self.dp.lttpr = policy;
    }
    /// A link this DP sink (same receiver caps) was verified at before:
    /// `enable` then skips the destructive verification, as Linux keeps
    /// `verified_link_cap` until the next long-pulse detection.
    pub fn assume_link_cap(&mut self, link: Option<DpLink>) {
        self.dp.verified = link;
    }
    /// The DP sink's verified link (after `enable` reached detection).
    pub fn link_cap(&self) -> Option<DpLink> {
        self.dp.verified
    }
    /// The DP sink's capabilities as `enable` retrieved them.
    pub fn dp_caps(&self) -> Option<&dp_link::Caps> {
        self.dp.caps.as_ref()
    }
    /// `retrieve_link_cap`, then (unless a verified link is assumed and still
    /// within the caps) `dp_verify_link_cap_with_retries` from the maximum
    /// link, with the PHY clock floor at that link. Runs after `init_hw`
    /// with no stream, as Linux's detection does.
    async fn discover_dp<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        sink: &Sink,
        aux: &mut A,
    ) -> Result<DpLink, Error> {
        use core::fmt::Write;
        if sink.dpcd.is_none() {
            return Err(Error::NoSink);
        }
        let caps = dp_link::retrieve_caps(aux, self.dp.lttpr).await?;
        let max = caps.max_link().ok_or(Error::NoSink)?;
        self.dp.caps = Some(caps);
        self.dp.edid.clone_from(&sink.edid);
        if let Some(v) = self
            .dp
            .verified
            .filter(|v| v.rate <= max.rate && v.lanes <= max.lanes)
        {
            return Ok(v);
        }
        self.dp.verified = None;
        let phy_max = self
            .clocks
            .levels()
            .map_or(0, |l| l.range(Clock::Phy).max_khz());
        self.clocks
            .link_rate_floor((u32::from(max.rate) * dp::LINK_RATE_REF_KHZ).min(phy_max))
            .await
            .map_err(Error::Block)?;
        let mut phy = DpPhy {
            tables,
            regs: self.gpu.regs,
            authority: self.regs.authority,
            connector: self.connector,
        };
        let mut source = dp::DioSource {
            link: self.dp_link,
            phy: &mut phy,
        };
        self.dp.probing = true;
        let result = dp_link::verify_link_cap(aux, &mut source, &caps).await;
        // Every verification exit disables the link, cancellation aside.
        self.dp.probing = false;
        let verified = result?;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 DP{} link verified at rate 0x{:x} x{} ({}, LTTPR {:?})",
            self.connector.path.transmitter,
            verified.link.rate,
            verified.link.lanes,
            if verified.clean {
                "clean"
            } else {
                "after failures"
            },
            caps.mode,
        );
        self.dp.verified = Some(verified.link);
        Ok(verified.link)
    }
    /// Disable a link a dropped verification left on (`dp_disable_link_phy`).
    async fn stop_dp_probe<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut A,
    ) -> Result<(), Error> {
        let mut phy = DpPhy {
            tables,
            regs: self.gpu.regs,
            authority: self.regs.authority,
            connector: self.connector,
        };
        let mut source = dp::DioSource {
            link: self.dp_link,
            phy: &mut phy,
        };
        let result = dp_link::disable_link_phy(aux, &mut source).await;
        self.dp.probing = false;
        result
    }
    /// The running DP stream's link, checked as an HPD-RX short pulse is
    /// (`dp_handle_hpd_rx_irq`'s SST part): an automated-test request is
    /// acknowledged; a lost lock with the sink in D0 is `LinkLoss`. Nothing
    /// for HDMI or a pipeline that is not running.
    pub async fn check_dp_link<A: Aux + Send>(&mut self, aux: &mut A) -> Result<RxEvent, Error> {
        if self.state != State::At(Step::Running) || self.connector.signal != Signal::DisplayPort {
            return Ok(RxEvent::None);
        }
        let (Some(caps), Some(link)) = (self.dp.caps, self.link) else {
            return Ok(RxEvent::None);
        };
        dp_link::handle_hpd_rx_irq(aux, caps.rev(), link.lanes).await
    }
    /// `dp_handle_link_loss` for the running SST stream:
    /// `link_set_dpms_off` (audio, blank, link disabled, stream stopped) and
    /// `link_set_dpms_on` at the same link setting with the commit's retries.
    /// The front end keeps scanning out the same surface throughout. On
    /// failure the link stays down and the pipeline must be disabled (the
    /// state is `At(Step::Link)`); the next lighting verifies the link again.
    pub async fn retrain<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut A,
    ) -> Result<DpLink, Error> {
        if self.state != State::At(Step::Running) || self.connector.signal != Signal::DisplayPort {
            return Err(Error::Busy);
        }
        let output = self.output.ok_or(Error::Invalid)?;
        let caps = self.dp.caps.ok_or(Error::Invalid)?;
        let setting = self.link.ok_or(Error::Invalid)?;
        self.state = State::At(Step::Link);
        let dig = self.route.stream;
        if self.audio.record(dig).is_some() {
            if let Err(error) = self.audio.stop(dig, &mut self.clocks).await {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 audio stop on DIG {dig} failed ({error:?})"
                );
            }
        }
        self.unlink_dp(tables, aux).await?;
        sleep_us(DP_BLANK_SETTLE_US).await;
        self.link_dp_at(tables, &output.timing, &caps, setting, aux)
            .await?;
        self.state = State::At(Step::Running);
        let sink = Sink {
            edid: core::mem::take(&mut self.dp.edid),
            preferred: None,
            hdmi: false,
            dpcd: None,
        };
        self.start_audio(&output.timing, &sink).await;
        self.dp.edid = sink.edid;
        Ok(setting)
    }
    /// `disable` after the sink left (debounced HPD low): the same teardown
    /// with no DPCD transaction to the absent sink (`dp_disable_link_phy`
    /// skips SET_POWER once `link->type` is none). An HDMI stream still gets
    /// `link_set_dpms_off`'s legacy SCDC TMDS_Config write over `ddc`,
    /// unchecked and only for a sink that declared SCDC
    /// ([`hdmi::write_scdc_legacy`]), as Linux sends it whether or not a sink
    /// answers. Also resumes a stop that was interrupted.
    pub async fn disable_unplugged<A: Aux + Send>(
        &mut self,
        tables: &Tables<'_>,
        ddc: &mut A,
    ) -> Result<(), Error> {
        if self.state == State::At(Step::Stopping) {
            self.state = State::At(Step::Link);
        }
        self.disable(tables, &mut ScdcOnly(ddc)).await
    }
}

/// The transport of an unplugged sink: SCDC (I2C) only, which Linux still
/// writes on disable; every DPCD transaction is refused unsent.
struct ScdcOnly<'a, A>(&'a mut A);
impl<A: Aux + Send> Aux for ScdcOnly<'_, A> {
    async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Aux)
    }
    async fn write(&mut self, _: u32, _: &[u8]) -> Result<(), Error> {
        Err(Error::Aux)
    }
    async fn connected(&mut self) -> bool {
        false
    }
    async fn scdc_read(&mut self, offset: u8) -> Result<u8, Error> {
        self.0.scdc_read(offset).await
    }
    async fn scdc_write(&mut self, offset: u8, value: u8) -> Result<(), Error> {
        self.0.scdc_write(offset, value).await
    }
}

/// No sink to reach: the AUX an HDMI pipeline is given.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAux;
impl Aux for NoAux {
    async fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Aux)
    }
    async fn connected(&mut self) -> bool {
        false
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

/// Opt-in power saving (amdgpu_navi22_power_policy): the DAL clock owner,
/// for memory/fabric floors and the PMFW watermark table.
impl Pipeline {
    pub(crate) fn clock_manager(&mut self) -> &mut ClockManager {
        &mut self.clocks
    }
}

#[path = "amdgpu_navi22_multi.rs"]
mod multi;
pub use multi::*;

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_modeset_tests.rs"]
mod tests;
