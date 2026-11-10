//! Intel Xe-LPDP (Meteor Lake / Arrow Lake) owned external DP SST route.
//!
//! The internal-panel orchestrator ([`crate::intel_gpu_modeset_xelpg`])
//! only re-programs an already-enabled DDI A. An external sink arrives
//! with its DDI, PHY PLL, D2D link and (on Type-C) PHY ownership all off,
//! so this module owns the complete off→on→off route for one DisplayPort
//! SST stream on DDI B (C10) or TC1–TC4 (C20, DP-alt or declared legacy):
//!
//! 1. [`probe_sink`] — Type-C connect ([`crate::intel_gpu_xelpg_tc`]), the
//!    Xe-LPDP AUX power well, DPCD capabilities, complete EDID and
//!    negotiation against the source envelope (HBR3 × the TC lane limit).
//! 2. [`activate`] — on the lowest free Pipe B–D with its transcoder, in
//!    `intel_atomic_commit_tail` / `hsw_crtc_enable` /
//!    `mtl_ddi_pre_enable_dp` / `intel_ddi_enable` order: the pipe's power
//!    wells (PW_1, PW_2, PW_B..D), the Pipe B–D owner's pre-plane resource
//!    transaction with the internal panel kept lit and the pipe DMC enable
//!    ([`crate::intel_gpu_xelpg_pipes::Pipes::reserve`]), Cx0 PLL enable
//!    (`intel_cx0pll_enable`), `TRANS_CLK_SEL`, `TRANS_DDI_FUNC_CTL`
//!    (configured, not yet enabled), `mtl_ddi_prepare_link_retrain`
//!    (DP_TP_CTL TPS1, D2D enable, signal levels, PORT_BUF_CTL1 width,
//!    DDI_CTL_DE enable + PHY_IDLE clear), shared DPCD link training,
//!    trained levels, DP_TP_CTL normal (`intel_dp_stop_link_train`), M/N,
//!    pipe source size, timings and RGB bypass, `TRANS_DDI_FUNC_CTL`
//!    enable, transcoder enable, the primary armed under vblank evasion and
//!    a fresh-frame witness. A training fallback stops the port and runs
//!    one retry at the trained configuration (i915's modeset retry) on the
//!    same reservation; a second mismatch refuses.
//! 3. [`MtlExternalRoute::stop`] — `hsw_crtc_disable` /
//!    `intel_ddi_post_disable_dp` order: plane off, transcoder off,
//!    function deselect, sink D3 (best effort), DDI_CTL_DE off + PHY_IDLE,
//!    D2D off, DP_TP_CTL off, TRANS_CLK_SEL off, `intel_cx0pll_disable`,
//!    TBT IO deselect, then the pipe DMC disable and the post-plane
//!    repartition back to the panel alone
//!    ([`crate::intel_gpu_xelpg_pipes::Pipes::release`]).
//! 4. [`MtlExternalRoute::release`] — AUX power off and Type-C disconnect,
//!    only after a proven local stop.
//!
//! [`MtlExternalService`] composes this with the hotplug owner
//! ([`crate::intel_gpu_xelpg_hpd`]): connect on `Connected`, withdraw on
//! `Disconnected`, revalidate/retrain on `ShortPulse` (DP only), re-probe
//! on `Redetect`; [`service_mtl_external`] is the process-wide entry.
//!
//! ## DP or HDMI
//!
//! The service owns one [`MtlRoute`]: this module's DP route or the HDMI
//! TMDS route of [`crate::intel_gpu_xelpg_hdmi`]. Which one a port may
//! carry is a board fact Linux reads from the VBT child device
//! (`intel_ddi_init`: `init_dp`/`init_hdmi`, Type-C legacy = neither
//! USB-C nor TBT). Without a VBT parser the facts are an explicit
//! [`MtlPortPolicy`]; production uses [`MtlPortPolicy::NO_VBT`]: DDI B is
//! DP + HDMI (`init_vbt_missing_defaults`), TC1..TC4 are USB-C DP-alt
//! only (Linux creates no Type-C encoder without a VBT), so no legacy
//! Type-C port and no Type-C HDMI exist until declared. Linux registers
//! both connectors on a dual port and each detects on its own (DPCD for
//! DP, a digital DDC EDID for HDMI); with one owned route the order is
//! [`route_plan`]: DP first, HDMI only when the DPCD read failed
//! ([`dpcd_absent`]). Any other DP failure (EDID, bandwidth, Type-C)
//! refuses without touching DDC. HDMI never runs over DP-alt or TBT-alt.
//!
//! ## Qualified profile
//!
//! Pipes B–D with their transcoders, never Pipe A: the lowest Pipe B–D
//! whose `TRANSCONF`, primary plane and `TRANS_DDI_FUNC_CTL` are off
//! ([`ExternalError::NoFreePipe`] otherwise), and only while the target
//! DDI and its PLL are off. Pipe A lit is adopted, never stopped or
//! replaned, and only as the owned panel profile of the display context's
//! panel mode ([`MtlDisplay`]); any other lit Pipe A refuses `PipeBusy`.
//! The resource transaction keeps the panel lit; its refusals are typed
//! ([`ExternalError::Pipe`]) and, like every refusal above, precede the
//! first write. PM demand is computed with the route's chosen port clock
//! (the negotiated DP link rate or the HDMI TMDS clock), as Linux's
//! `crtc_state->port_clock`; the owned panel keeps its HBR3 reservation
//! (the KMS fixed profile requires it). RGB at 8 bpc, or at 6 bpc
//! (`intel_dp_compute_link_config`: the sink's EDID bpc caps the pipe,
//! `compute_sink_pipe_bpp`, and the link drops to 18 bpp before DSC);
//! a 6 bpc route takes Linux's link (`intel_dp_compute_link_config_wide`),
//! `TRANS_DDI_FUNC_CTL` BPC_6, the dithered `PIPE_MISC` of the Pipes owner,
//! the 6 bpc MSA (`intel_ddi_set_dp_msa`) and `intel_link_compute_m_n` at
//! 18 bpp; the 8 bpc route is unchanged. DP 1.4 rates RBR–HBR3 with the
//! C10/C20 tables in [`crate::intel_gpu_xelpg`]; a stream that neither
//! bpp carries refuses unless the sink decompresses DSC (below).
//! UHBR (128b/132b, C20 MPLLA) and audio remain unadvertised. Live TBT
//! routes select fabric-owned AUX/clocking. MST uses the shared sideband
//! manager and a single primary transport across independent Pipe B-D
//! streams. Native/legacy VBT lane reversal reaches the PHY; DP-alt cable
//! flip remains a TCSS mux operation.
//!
//! ## DSC with FEC
//!
//! A DPCD 1.4+ sink reports its DSC and FEC capabilities at probe
//! (`intel_dp_get_dsc_sink_cap`). For a sink that decompresses,
//! `intel_dp_compute_link_config` decides with the 8 bpc pipe
//! ([`crate::intel_gpu_xelpg_dsc::decide_dp`]): 24 bpp that fits keeps the
//! uncompressed negotiation; otherwise the route compresses at Linux's
//! highest fitting bpp, rate and lane count with FEC, or refuses typed
//! ([`ExternalError::Dsc`]). A compressed route follows
//! `mtl_ddi_pre_enable_dp`: `DP_SET_POWER` D0, `DP_DSC_ENABLE` and
//! `DP_FEC_CONFIGURATION` before training, `DP_TP_CTL` FEC enable and the
//! PPS SDP after the normal pattern; then `hsw_crtc_enable`'s
//! `intel_dsc_enable` on the route's pipe, the compressed M/N, and after the
//! transcoder enable `intel_ddi_wait_for_fec_status` (best effort, as Linux
//! only logs it). The stop reverses it: sink decompression off before the
//! transcoder, `intel_dsc_disable` and the PPS SDP enable after the function
//! deselect, FEC off after `DP_TP_CTL`, then the sink's FEC ready. The
//! Pipes owner already sets display 14's `DP_FEC_BS_JITTER_WA`. The shared
//! training loop programs each source pattern and drive level before its
//! matching sink write. A rate/width fallback stops the buffer before
//! retuning the owned PHY or fabric clock and restarting CR/EQ.
//!
//! Sources (Linux b90c984d): `intel_ddi.c` (`mtl_ddi_pre_enable_dp`,
//! `mtl_ddi_prepare_link_retrain`, `intel_ddi_init_dp_buf_reg`,
//! `intel_ddi_buf_enable`/`_disable`, `intel_ddi_post_disable_dp`,
//! `intel_ddi_enable_transcoder_clock`, `intel_ddi_disable_transcoder_func`),
//! `intel_cx0_phy.c`, `intel_tc.c`, `intel_display_power_map.c`
//! (`xelpdp_pwdoms_pw_2` carries pipes B–D and the TC1–4 DDI lanes),
//! `intel_display.c` (`intel_atomic_commit_tail`, `hsw_crtc_enable`,
//! `hsw_crtc_disable`, `hsw_configure_cpu_transcoder`).

use core::sync::atomic::{compiler_fence, AtomicU8, Ordering};

#[path = "intel_gpu_xelpg_mst.rs"]
mod mst;
pub use mst::{MstFailure, MtlMstRoute};

use crate::dp_aux::AuxChannel as _;
use crate::dp_edid::{read_full_edid, EdidReadError};
use crate::dp_link_training::{
    negotiate, stream_demand_kbps, train_link, DpcdCaps, LinkError, LinkRate as TrainRate,
    NegotiatedLink, SourceCaps, TrainedLink,
};
use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_dc_states::{NoPipeDmc, PipeDmc, ServicePipeDmc};
use crate::intel_gpu_gmbus::PinPair;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_pipes::{Pipe, Transcoder};
use crate::intel_gpu_vbt::{dp_ssc_enabled, Vbt, VbtEncoder, VbtPlatform, DP_MAX_DOWNSPREAD};
use crate::intel_gpu_xelpg::{
    disable_d2d, disable_port_pll_lanes, disable_tbt_clock, dp_pll_request, enable_d2d,
    enable_port_pll_state, enable_tbt_clock, program_port_buf_ctl, set_signal_levels,
    wait_port_buf_active, wait_port_buf_idle, Cx0Error, Cx0Phy, PhyLaneConfig, XeLpgPort,
    PORT_BUF_IO_SELECT_TBT, PORT_BUF_PHY_IDLE,
};
use crate::intel_gpu_xelpg_dsc::{self as dsc, DscPlan, DscRefusal};
use crate::intel_gpu_xelpg_hdmi::{
    activate_hdmi, probe_hdmi, release_hdmi_probe, HdmiError, HdmiRouteState, MtlHdmiRoute,
};
use crate::intel_gpu_xelpg_hpd::{LiveMode, MtlHpdConfig, MtlHpdEvent, MtlHpdKind, MtlHpdPin};
use crate::intel_gpu_xelpg_pipes::{ExternalPipe, PipeEnableError, Pipes};
use crate::intel_gpu_xelpg_resources::ResourceError;
use crate::intel_gpu_xelpg_tc::{
    aux_power_disable, aux_power_enable, connect as tc_connect, connection_intact,
    disconnect as tc_disconnect, TcConnection, TcError, TcMode,
};

/// DPCD receiver-capability bytes read at probe (0x000..0x00F, the span
/// `read_caps` decodes; `DP_MAX_DOWNSPREAD` is byte 3).
const DPCD_RECEIVER_CAP_BYTES: usize = 16;

/// Largest EDID retained (base + three extensions).
pub const EDID_CAPACITY: usize = 512;

// Registers this route owns on its pipe/transcoder (`intel_display_regs.h`).
const PWR_WELL_CTL2: u64 = 0x4_5404;
const PW_1_IDX: u32 = 0;
/// `ICL_PW_CTL_IDX_PW_2` — on Xe-LPDP it powers pipes/transcoders B–D and
/// the TC1–4 DDI lanes (`XELPDP_PW_2_POWER_DOMAINS`).
const PW_2_IDX: u32 = 1;
/// `XELPD_PW_CTL_IDX_PW_A`; `XELPD_PW_CTL_IDX_PW_B..D` follow (6..8).
const PW_A_IDX: u32 = 5;
/// `TRANSCONF`, `PIPE_FRMCOUNT_G4X`, primary `PLANE_CTL` / `PLANE_SURF` /
/// `PLANE_SURFLIVE`, relative to [`Pipe::base`].
const CONF: u64 = 0x008;
const FRMCOUNT: u64 = 0x040;
const PLANE_CTL_1: u64 = 0x180;
const PLANE_SURF_1: u64 = 0x19C;
const PLANE_SURFLIVE_1: u64 = 0x1AC;
const DP_TP_CTL_ENABLE: u32 = 1 << 31;
const DP_TP_CTL_ENHANCED_FRAME: u32 = 1 << 18;
const DP_TP_CTL_LINK_TRAIN_MASK: u32 = 0x7 << 8;
const DP_TP_CTL_LINK_TRAIN_PAT1: u32 = 0;
const DP_TP_CTL_LINK_TRAIN_NORMAL: u32 = 3 << 8;
const TRANS_DDI_FUNC_ENABLE: u32 = 1 << 31;
/// `TGL_TRANS_DDI_PORT_MASK | TRANS_DDI_MODE_SELECT_MASK`.
const TRANS_DDI_PORT_AND_MODE: u32 = (0xF << 27) | (0x7 << 24);
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
const ENABLE: u32 = 1 << 31;
const STATE: u32 = 1 << 30;
/// `DP_SET_POWER` and its D0/D3 values.
const DPCD_SET_POWER: u32 = 0x600;
const DP_SET_POWER_D3: u8 = 2;

const fn pwr_well_req(idx: u32) -> u32 {
    0x2 << (idx * 2)
}
const fn pwr_well_state(idx: u32) -> u32 {
    0x1 << (idx * 2)
}
/// The pipe's own power well (`XELPD_PW_CTL_IDX_PW_A..D`).
pub(crate) const fn pipe_well(pipe: Pipe) -> u32 {
    PW_A_IDX + pipe as u32
}
/// `TRANS_DDI_FUNC_CTL(trans)`.
pub(crate) const fn trans_ddi_func_ctl(trans: Transcoder) -> u64 {
    trans.base() + 0x400
}
/// `TRANS_CLK_SEL(trans)` (`_TRANS_CLK_SEL_A` 0x46140, stride 4).
pub(crate) const fn trans_clk_sel(trans: Transcoder) -> u64 {
    0x4_6140 + 4 * trans as u64
}
/// `TGL_DP_TP_CTL(trans)`.
pub(crate) const fn dp_tp_ctl(trans: Transcoder) -> u64 {
    trans.base() + 0x540
}
/// `TGL_TRANS_CLK_SEL_PORT(phy)`.
pub(crate) const fn trans_clk_sel_port(port: XeLpgPort) -> u32 {
    (port.phy_index() + 1) << 28
}
/// `DDI_PORT_WIDTH(lanes)` (bits 3:1, 3 lanes encode as 4).
const fn ddi_port_width(lanes: u8) -> u32 {
    let w = if lanes == 3 { 4 } else { lanes as u32 - 1 };
    w << 1
}

/// Typed refusal or failure of the MTL external route.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExternalError {
    Mst(MstFailure),
    /// Not a Meteor Lake (display 14) device.
    UnsupportedGeneration,
    /// DDI A is the internal panel port; it is never an external route.
    UnsupportedPort,
    /// Type-C ownership or AUX power failed.
    Tc(TcError),
    /// AUX/DPCD capability read or link training failed.
    Link(LinkError),
    /// EDID could not be read or parsed.
    Edid(EdidReadError),
    /// The stream needs more than the negotiated ceiling carries.
    OverBudget {
        /// Stream demand in kbps.
        demand_kbps: u64,
        /// Best mutually supported payload in kbps.
        payload_kbps: u64,
    },
    /// Pipe A is lit (or mid-transition) without an owned panel profile
    /// this route can adopt.
    PipeBusy,
    /// Every Pipe B–D is lit, has its primary enabled or has its
    /// transcoder function selected.
    NoFreePipe,
    /// The Pipe B–D owner refused before any write, or failed (its
    /// resource transaction restored what it touched).
    Pipe(PipeRefusal),
    /// The target DDI or its PHY PLL is already active.
    PortBusy,
    /// A fallback retry trained at yet another configuration.
    TrainingMismatch,
    /// Programming or observation failed.
    Modeset(ModesetError),
    /// Register authority was lost.
    AccessLost,
    /// The route could not be locally stopped and stays quarantined.
    Quarantined,
    /// Display DC states could not be exited; nothing was touched.
    DisplayPower,
    /// The stream needs a DSC configuration Linux would not choose or this
    /// driver does not qualify (nothing was programmed).
    Dsc(DscRefusal),
}

impl From<TcError> for ExternalError {
    fn from(e: TcError) -> Self {
        if e == TcError::AccessLost {
            ExternalError::AccessLost
        } else {
            ExternalError::Tc(e)
        }
    }
}

impl From<ModesetError> for ExternalError {
    fn from(e: ModesetError) -> Self {
        ExternalError::Modeset(e)
    }
}

/// Why the Pipe B–D owner ([`crate::intel_gpu_xelpg_pipes`]) and its
/// display-14 resource transaction refused or failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PipeRefusal {
    /// The mode or surface is outside the owner's qualified profile.
    Unsupported,
    /// No watermark level fits the vblank budget.
    VblankTooShort,
    /// The DDB cannot hold level 0 of every plane.
    DdbExhausted,
    /// The required CDCLK exceeds the 652.8 MHz maximum.
    CdclkUnsatisfiable,
    /// SAGV is allowed but no QGV point carries the display data rate.
    BandwidthExceeded,
    /// A pipe, plane, cursor, DSB or FBC that must stay idle is live.
    Busy,
    /// The hardware no longer holds the adopted resource state.
    Diverged,
    /// A lit pipe's configuration would change (that needs its modeset).
    LivePipeChanged,
    /// No lit pipe can take its new DDB without overlapping another.
    DdbOrdering,
    /// The firmware CDCLK is unknown: the change needs every pipe off.
    RequiresPipesOff,
    /// A hardware acknowledgement did not arrive.
    Timeout,
    /// A written value did not read back.
    Readback,
    /// The CDCLK change failed.
    Clock,
    /// The owner's reserve → enable → disable → release order was broken.
    Sequence,
}

impl From<ResourceError> for ExternalError {
    fn from(e: ResourceError) -> Self {
        ExternalError::Pipe(match e {
            ResourceError::NoDevice => return ExternalError::AccessLost,
            ResourceError::Unsupported => PipeRefusal::Unsupported,
            ResourceError::VblankTooShort => PipeRefusal::VblankTooShort,
            ResourceError::DdbExhausted => PipeRefusal::DdbExhausted,
            ResourceError::CdclkUnsatisfiable => PipeRefusal::CdclkUnsatisfiable,
            ResourceError::BandwidthExceeded => PipeRefusal::BandwidthExceeded,
            ResourceError::Busy => PipeRefusal::Busy,
            ResourceError::Timeout => PipeRefusal::Timeout,
            ResourceError::Readback => PipeRefusal::Readback,
            ResourceError::Clock(_) => PipeRefusal::Clock,
            ResourceError::DdbOrdering => PipeRefusal::DdbOrdering,
            ResourceError::LivePipeChanged => PipeRefusal::LivePipeChanged,
            ResourceError::RequiresPipesOff => PipeRefusal::RequiresPipesOff,
            ResourceError::Diverged => PipeRefusal::Diverged,
        })
    }
}

impl From<PipeEnableError> for ExternalError {
    fn from(e: PipeEnableError) -> Self {
        match e {
            PipeEnableError::NoDevice => ExternalError::AccessLost,
            PipeEnableError::Unsupported => ExternalError::Pipe(PipeRefusal::Unsupported),
            PipeEnableError::Busy => ExternalError::Pipe(PipeRefusal::Busy),
            PipeEnableError::NotReserved | PipeEnableError::NotLit => {
                ExternalError::Pipe(PipeRefusal::Sequence)
            }
            PipeEnableError::Timeout => ExternalError::Pipe(PipeRefusal::Timeout),
            PipeEnableError::Resource(r) => r.into(),
        }
    }
}

/// What an external activation shares the display with. The display
/// runtime builds one per pass ([`MtlDisplay::production`]); fixtures use
/// [`MtlDisplay::NONE`] or their own pipe-DMC sink.
#[derive(Clone, Copy)]
pub struct MtlDisplay {
    /// The owned internal panel's mode on Pipe A
    /// ([`crate::intel_gpu_modeset_xelpg::owned_panel_mode`]). A lit Pipe A
    /// is adopted only as this mode's owned resource profile.
    pub panel: Option<Mode>,
    /// Where each external pipe's DMC lifetime is reported.
    pub pipe_dmc: &'static (dyn PipeDmc + Sync),
}

impl MtlDisplay {
    /// No owned panel, no pipe-DMC reporting.
    pub const NONE: Self = Self {
        panel: None,
        pipe_dmc: &NoPipeDmc,
    };

    /// The production context: the owned panel (if any) and the display-14
    /// DC service's pipe-DMC sink.
    pub const fn production(panel: Option<Mode>) -> Self {
        Self {
            panel,
            pipe_dmc: &ServicePipeDmc,
        }
    }
}

impl core::fmt::Debug for MtlDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MtlDisplay")
            .field("panel", &self.panel)
            .finish_non_exhaustive()
    }
}

/// The Pipe B–D a route drives, the owner that reserved it and the sink
/// its pipe DMC was reported to.
#[derive(Clone)]
pub(crate) struct RoutePipe {
    pub(crate) pipe: Pipe,
    pub(crate) pipes: Pipes,
    pub(crate) dmc: &'static (dyn PipeDmc + Sync),
}

impl core::fmt::Debug for RoutePipe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RoutePipe")
            .field("pipe", &self.pipe)
            .field("pipes", &self.pipes)
            .finish_non_exhaustive()
    }
}

impl RoutePipe {
    /// The transcoder this route's port feeds.
    pub(crate) fn transcoder(&self) -> Transcoder {
        self.pipe.transcoder()
    }

    /// The pipe's register block base.
    pub(crate) fn base(&self) -> u64 {
        self.pipe.base()
    }
}

/// The Pipe B–D [`activate`] would take for a route and the owner holding
/// what Pipe A runs, chosen without a write.
#[derive(Clone, Debug)]
pub(crate) struct PipeChoice {
    pub(crate) pipe: Pipe,
    pub(crate) pipes: Pipes,
}

/// `intel_modeset_get_crtc_power_domains` for an external pipe, enabled top
/// to bottom: PW_1, PW_2 (pipes B–D, TC1–4 DDI lanes), the pipe's well.
pub(crate) fn request_pipe_wells<M: MmioWindow + ?Sized>(
    io: &M,
    pipe: Pipe,
) -> Result<(), ExternalError> {
    request_well(io, PW_1_IDX)?;
    request_well(io, PW_2_IDX)?;
    request_well(io, pipe_well(pipe))
}

/// The lowest Pipe B–D whose transcoder, primary plane and transcoder
/// function are all off (Linux assigns CRTCs; Pipe A stays the panel's).
fn free_pipe<M: MmioWindow + ?Sized>(io: &M) -> Result<Pipe, ExternalError> {
    for pipe in [Pipe::B, Pipe::C, Pipe::D] {
        let conf = read(io, pipe.base() + CONF)?;
        let plane = read(io, pipe.base() + PLANE_CTL_1)?;
        let func = read(io, trans_ddi_func_ctl(pipe.transcoder()))?;
        if conf & (ENABLE | STATE) == 0 && plane & ENABLE == 0 && func & TRANS_DDI_FUNC_ENABLE == 0
        {
            return Ok(pipe);
        }
    }
    Err(ExternalError::NoFreePipe)
}

/// No-write preflight: the target DDI and its PLL are off, a Pipe B–D is
/// free, and whatever Pipe A runs is adopted — nothing when it is off, the
/// owned panel profile for `display.panel` when it is lit.
pub(crate) fn preflight<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    display: &MtlDisplay,
) -> Result<PipeChoice, ExternalError> {
    preflight_lanes(io, port, display, PhyLaneConfig::NATIVE)
}

fn pll_clock_mask(lanes: PhyLaneConfig) -> u32 {
    let mut mask = 0;
    for lane in 0..2 {
        if lanes.owned_mask() & (1 << lane) != 0 {
            mask |= crate::intel_gpu_xelpg::lane_pclk_pll_request(lane)
                | crate::intel_gpu_xelpg::lane_pclk_pll_ack(lane);
        }
    }
    mask
}

fn preflight_lanes<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    display: &MtlDisplay,
    lanes: PhyLaneConfig,
) -> Result<PipeChoice, ExternalError> {
    preflight_clock(io, port, display, pll_clock_mask(lanes))
}

fn preflight_clock<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    display: &MtlDisplay,
    clock_mask: u32,
) -> Result<PipeChoice, ExternalError> {
    if !io.display_access_ok() {
        return Err(ExternalError::AccessLost);
    }
    let ddi = read(io, port.ddi_buf_ctl())?;
    let clock = read(io, port.port_clock_ctl())?;
    if ddi & DDI_BUF_CTL_ENABLE != 0 || clock & clock_mask != 0 {
        return Err(ExternalError::PortBusy);
    }
    let pipe = free_pipe(io)?;
    let panel = read(io, Pipe::A.base() + CONF)? & (ENABLE | STATE);
    let pipes = match (panel, display.panel) {
        (0, _) => Pipes::adopt(None, 0),
        (lit, Some(mode)) if lit == ENABLE | STATE => Pipes::adopt_panel(io, &mode)?,
        _ => return Err(ExternalError::PipeBusy),
    };
    Ok(PipeChoice { pipe, pipes })
}

/// The Pipe B–D request for a route on `choice`: the scanout surface and
/// the port clock it runs at (`crtc_state->port_clock`).
pub(crate) fn external_pipe(
    choice: &PipeChoice,
    port: XeLpgPort,
    mode: &Mode,
    fb: &Framebuffer,
    port_clock_khz: u32,
    dsc: Option<dsc::DscTerm>,
    pipe_bpp: u32,
) -> Result<ExternalPipe, ExternalError> {
    let surface = u32::try_from(fb.phys_addr)
        .map_err(|_| ExternalError::Modeset(ModesetError::InvalidFramebuffer))?;
    Ok(ExternalPipe {
        pipe: choice.pipe,
        mode: *mode,
        surface,
        stride_bytes: fb.stride_bytes,
        port_clock_khz,
        combo_phy: port.tc_index().is_none().then_some(port.phy_index() as u8),
        dsc,
        pipe_bpp,
    })
}

/// The pre-plane update and pipe DMC enable for `ext` on `choice` (after
/// the pipe's wells are up): the route's [`RoutePipe`].
pub(crate) fn reserve_pipe<M: MmioWindow + ?Sized>(
    io: &M,
    choice: PipeChoice,
    ext: &ExternalPipe,
    dmc: &'static (dyn PipeDmc + Sync),
) -> Result<RoutePipe, ExternalError> {
    let mut pipes = choice.pipes;
    pipes.reserve(io, ext, dmc)?;
    Ok(RoutePipe {
        pipe: choice.pipe,
        pipes,
        dmc,
    })
}

/// The DP port clock of `rate` in kHz (`crtc_state->port_clock`).
fn link_clock_khz(rate: TrainRate) -> u32 {
    crate::intel_gpu_modeset::to_pll_rate(rate).megabits_per_sec() * 100
}

fn phy_err(e: Cx0Error) -> ExternalError {
    ExternalError::Modeset(match e {
        Cx0Error::PhyError | Cx0Error::ProtocolMismatch => ModesetError::PhyBusFailure,
        Cx0Error::Timeout | Cx0Error::UnsupportedRate => ModesetError::PllLockTimeout,
    })
}

/// Everything [`activate`] needs, owning the Type-C connection and the
/// AUX power request from probe until [`release_probe`] or a route
/// release.
#[derive(Clone, Debug)]
pub struct MtlSinkProbe {
    /// MST stream transport; absent for SST.
    pub mst: Option<MstStreamConfig>,
    /// Board wiring from the VBT; DP-alt cable flip is handled by TCSS.
    pub lane_reversal: bool,
    /// The external port.
    pub port: XeLpgPort,
    /// Type-C ownership (TC ports only).
    pub tc: Option<TcConnection>,
    /// Sink DPCD capabilities.
    pub caps: DpcdCaps,
    /// The sink's preferred mode.
    pub mode: Mode,
    /// Negotiated starting link configuration.
    pub negotiated: NegotiatedLink,
    /// The sink's raw `DP_MAX_DOWNSPREAD` byte.
    pub max_downspread: u8,
    /// `pll_state->ssc_enabled` for this sink: [`dp_ssc_enabled`] of the
    /// board's SSC preference and `max_downspread` (set at probe with the
    /// no-VBT preference, which is on; the service applies its policy).
    pub ssc: bool,
    /// Complete EDID bytes (`edid_len` valid).
    pub edid: [u8; EDID_CAPACITY],
    /// Valid EDID length.
    pub edid_len: usize,
    /// The DSC configuration when the stream needs compression; the
    /// negotiated link is then the plan's.
    pub dsc: Option<DscPlan>,
    /// `crtc_state->pipe_bpp`: 24, or 18 (6 bpc, dithered) when the sink's
    /// EDID limits the pipe to it or only 18 bpp fits the link; the
    /// negotiated link is then Linux's (`intel_dp_compute_link_config_wide`).
    pub pipe_bpp: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct MstStreamConfig {
    pub master: Transcoder,
    pub slots: u8,
}

impl MtlSinkProbe {
    fn tbt(&self) -> bool {
        self.tc.is_some_and(|tc| tc.mode == TcMode::TbtAlt)
    }
    fn clock_mask(&self) -> Result<u32, ExternalError> {
        Ok(if self.tbt() {
            crate::intel_gpu_xelpg::TBT_CLOCK_REQUEST | crate::intel_gpu_xelpg::TBT_CLOCK_ACK
        } else {
            pll_clock_mask(self.phy_lanes()?)
        })
    }
    fn phy_lanes(&self) -> Result<PhyLaneConfig, ExternalError> {
        PhyLaneConfig::for_route(
            self.dp_alt(),
            self.tc.map_or(4, |tc| tc.max_lanes),
            self.lane_reversal,
        )
        .map_err(phy_err)
    }
    fn dp_alt(&self) -> bool {
        self.tc.is_some_and(|tc| tc.mode == TcMode::DpAlt)
    }
    fn legacy(&self) -> bool {
        self.tc.is_some_and(|tc| tc.mode == TcMode::Legacy)
    }
}

/// Release a probe's AUX power request and Type-C ownership.
pub fn release_probe<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlSinkProbe,
) -> Result<(), ExternalError> {
    let aux = aux_power_disable(io, probe.port);
    let tc = match probe.tc {
        Some(conn) => tc_disconnect(io, &conn),
        None => Ok(()),
    };
    aux?;
    tc?;
    Ok(())
}

/// Phase 1: connect, power AUX, read caps + EDID and negotiate. Only the
/// port's TC/AUX/FIA registers are touched; every failure after the
/// Type-C connect rolls it back.
fn probe_link<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<LinkProbe, ExternalError> {
    if generation != Generation::MeteorLake {
        return Err(ExternalError::UnsupportedGeneration);
    }
    if port == XeLpgPort::A {
        return Err(ExternalError::UnsupportedPort);
    }
    // Do not acquire/release Type-C ownership behind an inherited live DDI.
    if read(io, port.ddi_buf_ctl())? & DDI_BUF_CTL_ENABLE != 0 {
        return Err(ExternalError::PortBusy);
    }
    let tc = match port.tc_index() {
        Some(_) => Some(tc_connect(io, port, legacy_port, 1)?),
        None => None,
    };
    let rollback = |e: ExternalError| {
        let _ = aux_power_disable(io, port);
        if let Some(conn) = tc {
            let _ = tc_disconnect(io, &conn);
        }
        e
    };
    if let Err(e) = aux_power_enable(io, port) {
        if let Some(conn) = tc {
            let _ = tc_disconnect(io, &conn);
        }
        return Err(e.into());
    }
    let mut aux = IntelAux::xelpdp(
        io,
        port.aux_base(),
        tc.is_some_and(|conn| conn.mode == TcMode::TbtAlt),
    );
    // `read_caps`'s DPCD read, keeping the raw bytes for DP_MAX_DOWNSPREAD.
    let mut raw = [0u8; DPCD_RECEIVER_CAP_BYTES];
    aux.dpcd_read(0, &mut raw)
        .map_err(|e| rollback(ExternalError::Link(LinkError::AuxFailure(e))))?;
    Ok(LinkProbe { port, tc, raw })
}

#[derive(Copy, Clone, Debug)]
struct LinkProbe {
    port: XeLpgPort,
    tc: Option<TcConnection>,
    raw: [u8; 16],
}
impl LinkProbe {
    fn tbt(self) -> bool {
        self.tc.is_some_and(|tc| tc.mode == TcMode::TbtAlt)
    }
    fn aux<'a, M: MmioWindow + ?Sized>(self, io: &'a M) -> IntelAux<'a, M> {
        IntelAux::xelpdp(io, self.port.aux_base(), self.tbt())
    }
    fn release<M: MmioWindow + ?Sized>(self, io: &M) -> Result<(), ExternalError> {
        aux_power_disable(io, self.port)?;
        if let Some(tc) = self.tc {
            tc_disconnect(io, &tc)?;
        }
        Ok(())
    }
}

pub fn probe_sink<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    let link = probe_link(io, generation, port, legacy_port)?;
    probe_sink_link(io, link)
}

fn probe_sink_link<M: MmioWindow + ?Sized>(
    io: &M,
    link: LinkProbe,
) -> Result<MtlSinkProbe, ExternalError> {
    let LinkProbe { port, tc, raw } = link;
    let rollback = |error| {
        let _ = link.release(io);
        error
    };
    let mut aux = link.aux(io);
    let caps = DpcdCaps::decode(&raw);
    let max_downspread = raw[DP_MAX_DOWNSPREAD];
    let mut edid = [0u8; EDID_CAPACITY];
    let edid_len =
        read_full_edid(&mut aux, &mut edid).map_err(|e| rollback(ExternalError::Edid(e)))?;
    let mode = crate::intel_gpu_dp::mode_from_edid(&edid[..edid_len]).map_err(|e| {
        rollback(match e {
            crate::intel_gpu_dp::DpError::Edid(e) => ExternalError::Edid(e),
            crate::intel_gpu_dp::DpError::Link(e) => ExternalError::Link(e),
            crate::intel_gpu_dp::DpError::Modeset(e) => ExternalError::Modeset(e),
        })
    })?;
    let source = SourceCaps {
        max_rate: TrainRate::Hbr3,
        max_lanes: tc.map_or(4, |conn| conn.max_lanes),
    };
    let mut negotiated = negotiate(&source, &caps, stream_demand_kbps(mode.pixel_clock_khz, 24));
    // intel_dp_get_dsc_sink_cap, then intel_dp_compute_link_config: the
    // pipe's maximum from the EDID's bpc (compute_sink_pipe_bpp), the
    // uncompressed bpp descent (24, then 18) and, for a sink that
    // decompresses, DSC.
    let sink = dsc::read_dp_sink(&mut aux, &raw)
        .map_err(|e| rollback(ExternalError::Link(LinkError::AuxFailure(e))))?;
    let max_bpp = dsc::max_pipe_bpp(dsc::edid_display_bpc(&edid[..edid_len]), 0);
    let ceiling = if source.max_rate.rate_kbps() <= caps.max_rate.rate_kbps() {
        source.max_rate
    } else {
        caps.max_rate
    };
    let limits = dsc::LinkLimits::standard(
        link_clock_khz(ceiling),
        source.max_lanes.min(caps.max_lanes),
    );
    let mut plan = None;
    let mut pipe_bpp = dsc::PIPE_BPP;
    // A 6 bpc link: Linux's own (intel_dp_compute_link_config_wide).
    let six_bpc = |link: dsc::UncompressedLink| {
        let rate = train_rate_for(link.link_rate)?;
        Some(NegotiatedLink {
            rate,
            lanes: link.lanes,
            demand_kbps: stream_demand_kbps(mode.pixel_clock_khz, link.pipe_bpp),
            payload_kbps: rate.payload_kbps(link.lanes),
            over_budget: false,
        })
    };
    if !sink.dsc.dpcd.supports_dsc() && (negotiated.over_budget || max_bpp < dsc::PIPE_BPP) {
        // No DSC: 24 bpp that the negotiation carries keeps it; otherwise
        // the bpp descent, or the existing over-budget refusal.
        if let Some(link) = dsc::uncompressed_link(&limits, &mode, max_bpp)
            .filter(|link| link.pipe_bpp < dsc::PIPE_BPP)
        {
            negotiated = six_bpc(link)
                .ok_or_else(|| rollback(ExternalError::Dsc(DscRefusal::LinkRateUnqualified)))?;
            pipe_bpp = link.pipe_bpp;
        }
    } else if sink.dsc.dpcd.supports_dsc() {
        match dsc::decide_dp(&sink, &limits, &mode, max_bpp) {
            Ok(dsc::LinkDecision::Uncompressed(link)) if link.pipe_bpp == dsc::PIPE_BPP => {}
            Ok(dsc::LinkDecision::Uncompressed(link)) => {
                negotiated = six_bpc(link)
                    .ok_or_else(|| rollback(ExternalError::Dsc(DscRefusal::LinkRateUnqualified)))?;
                pipe_bpp = link.pipe_bpp;
            }
            Ok(dsc::LinkDecision::Dsc(p)) => {
                let rate = train_rate_for(p.link_rate)
                    .ok_or_else(|| rollback(ExternalError::Dsc(DscRefusal::LinkRateUnqualified)))?;
                negotiated = NegotiatedLink {
                    rate,
                    lanes: p.lanes,
                    demand_kbps: dsc::link_required(
                        u32::from(p.lanes),
                        mode.pixel_clock_khz,
                        u32::from(mode.h_active),
                        u32::from(p.compressed_bpp_x16),
                        p.fec,
                    ) * 8,
                    payload_kbps: rate.payload_kbps(p.lanes),
                    over_budget: false,
                };
                plan = Some(p);
            }
            Err(refusal) => return Err(rollback(ExternalError::Dsc(refusal))),
        }
    }
    if negotiated.over_budget {
        return Err(rollback(ExternalError::OverBudget {
            demand_kbps: negotiated.demand_kbps,
            payload_kbps: negotiated.payload_kbps,
        }));
    }
    if !io.display_access_ok() {
        return Err(rollback(ExternalError::AccessLost));
    }
    Ok(MtlSinkProbe {
        mst: None,
        lane_reversal: false,
        port,
        tc,
        caps,
        mode,
        negotiated,
        max_downspread,
        ssc: dp_ssc_enabled(true, max_downspread),
        edid,
        edid_len,
        dsc: plan,
        pipe_bpp,
    })
}

/// The training rate of a Linux link rate (RBR..HBR3).
fn train_rate_for(link_rate: u32) -> Option<TrainRate> {
    match link_rate {
        162_000 => Some(TrainRate::Rbr),
        270_000 => Some(TrainRate::Hbr),
        540_000 => Some(TrainRate::Hbr2),
        810_000 => Some(TrainRate::Hbr3),
        _ => None,
    }
}

/// Route lifecycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RouteState {
    /// Scanning out with a fresh-frame witness.
    Live,
    /// Every local stop step was observed; Type-C/AUX still owned.
    Stopped,
    /// A stop step was not observed; every lease stays retained.
    Quarantined,
}

/// One owned external SST route on a Pipe B–D.
#[derive(Clone, Debug)]
pub struct MtlExternalRoute {
    /// The probe (Type-C/AUX ownership, caps, EDID, mode).
    pub probe: MtlSinkProbe,
    /// The scanned-out framebuffer (owned by the caller's allocation).
    pub fb: Framebuffer,
    /// The trained link.
    pub trained: TrainedLink,
    state: RouteState,
    /// The Pipe B–D (and transcoder) the route was activated on.
    pipe: Pipe,
    /// The pipe's reservation until its post-plane release is proven.
    reservation: Option<RoutePipe>,
}

/// Why [`activate`] did not produce a live route.
///
/// Both variants hand the owner back by value, once per activation; the
/// route's size is its retained reservation, not a hot-path copy.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ActivateError {
    /// Refused before any programming; the probe is handed back intact.
    Refused(MtlSinkProbe, ExternalError),
    /// Programming failed; the route is `Stopped` (locally proven off) or
    /// `Quarantined` (retained).
    Failed(MtlExternalRoute, ExternalError),
}

pub(crate) fn wait_bit<M: MmioWindow + ?Sized>(
    io: &M,
    off: u64,
    mask: u32,
    want_set: bool,
    timeout_ns: u64,
) -> bool {
    let mut refused = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(off);
            refused = v == u32::MAX || !io.display_access_ok();
            refused || v & mask == if want_set { mask } else { 0 }
        },
        narf_time::Deadline::after_ns(timeout_ns),
    );
    done && !refused
}

fn write<M: MmioWindow + ?Sized>(io: &M, off: u64, value: u32) -> Result<(), ExternalError> {
    io.write32(off, value);
    compiler_fence(Ordering::SeqCst);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(ExternalError::AccessLost)
    }
}

fn read<M: MmioWindow + ?Sized>(io: &M, off: u64) -> Result<u32, ExternalError> {
    let v = io.read32(off);
    if v == u32::MAX || !io.display_access_ok() {
        Err(ExternalError::AccessLost)
    } else {
        Ok(v)
    }
}

pub(crate) fn request_well<M: MmioWindow + ?Sized>(io: &M, idx: u32) -> Result<(), ExternalError> {
    let cur = read(io, PWR_WELL_CTL2)?;
    write(io, PWR_WELL_CTL2, cur | pwr_well_req(idx))?;
    if wait_bit(
        io,
        PWR_WELL_CTL2,
        pwr_well_req(idx) | pwr_well_state(idx),
        true,
        1_000_000,
    ) {
        Ok(())
    } else {
        Err(ExternalError::Modeset(ModesetError::PowerWellTimeout))
    }
}

/// Phase 2: program and light the route on a free Pipe B–D next to what
/// Pipe A runs (`display`). See the module header for the sequence. The
/// probe must come from [`probe_sink`] on this window. Every refusal
/// (framebuffer, busy port, no free pipe, unadoptable Pipe A, Type-C
/// loss, resource admission) precedes the first write.
// Refusal hands the owned probe/route back inline: it must not allocate.
#[allow(clippy::result_large_err)]
pub fn activate<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlSinkProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
) -> Result<MtlExternalRoute, ActivateError> {
    activate_with_payload(io, probe, fb, display, &mut |_| Ok(()))
}

#[allow(clippy::result_large_err)]
fn activate_with_payload<M: MmioWindow + ?Sized>(
    io: &M,
    mut probe: MtlSinkProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
    payload: &mut dyn FnMut(Transcoder) -> Result<(), ExternalError>,
) -> Result<MtlExternalRoute, ActivateError> {
    if let Err(e) = probe.phy_lanes() {
        return Err(ActivateError::Refused(probe, e));
    }
    if let Err(e) = crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &probe.mode) {
        return Err(ActivateError::Refused(probe, e.into()));
    }
    let choice = match preflight_clock(
        io,
        probe.port,
        display,
        probe.clock_mask().expect("validated above"),
    ) {
        Ok(choice) => choice,
        Err(e) => return Err(ActivateError::Refused(probe, e)),
    };
    if let Some(mst) = probe.mst.as_mut() {
        mst.master = choice.pipe.transcoder();
    }
    if let Some(conn) = probe.tc {
        match connection_intact(io, &conn) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ActivateError::Refused(
                    probe,
                    ExternalError::Tc(TcError::SuddenDisconnect),
                ))
            }
            Err(e) => return Err(ActivateError::Refused(probe, e.into())),
        }
    }
    let negotiated = probe.negotiated;
    // intel_pmdemand_atomic_check takes crtc_state->port_clock, chosen
    // before training: here the negotiated rate. negotiate() picks the
    // lowest rate that carries the stream and the fallback ladder never
    // raises it, so a fallback that still carries the stream trains at
    // this same rate (fewer lanes) and the reservation is exact.
    let ext = match external_pipe(
        &choice,
        probe.port,
        &probe.mode,
        &fb,
        link_clock_khz(negotiated.rate),
        probe.dsc.map(|plan| plan.term(&probe.mode)),
        probe.pipe_bpp,
    ) {
        Ok(ext) => ext,
        Err(e) => return Err(ActivateError::Refused(probe, e)),
    };
    if let Err(e) = choice.pipes.admit(io, &ext) {
        return Err(ActivateError::Refused(probe, e.into()));
    }
    let mut route = MtlExternalRoute {
        probe,
        fb,
        trained: TrainedLink {
            rate: negotiated.rate,
            lanes: negotiated.lanes,
            vswing_pe: Default::default(),
        },
        state: RouteState::Stopped,
        pipe: choice.pipe,
        reservation: None,
    };
    match program(io, &mut route, choice, &ext, display.pipe_dmc, payload) {
        Ok(()) => {
            route.state = RouteState::Live;
            Ok(route)
        }
        Err(e) => {
            route.state = match stop_local(io, &mut route) {
                Ok(()) => RouteState::Stopped,
                Err(_) => RouteState::Quarantined,
            };
            Err(ActivateError::Failed(route, e))
        }
    }
}

fn program<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
    choice: PipeChoice,
    ext: &ExternalPipe,
    dmc: &'static (dyn PipeDmc + Sync),
    payload: &mut dyn FnMut(Transcoder) -> Result<(), ExternalError>,
) -> Result<(), ExternalError> {
    // 1. Power wells (intel_modeset_get_crtc_power_domains), then the
    // pre-plane update and the first step of hsw_crtc_enable
    // (intel_dmc_enable_pipe). 2. PM demand is part of the reservation.
    request_pipe_wells(io, ext.pipe)?;
    route.reservation = Some(reserve_pipe(io, choice, ext, dmc)?);
    let (rate, lanes) = (route.probe.negotiated.rate, route.probe.negotiated.lanes);
    let mut trained = enable_port(io, route, rate, lanes)?;
    if (route.probe.dsc.is_some() || route.probe.mst.is_some())
        && (trained.rate != rate || trained.lanes != lanes)
    {
        // The DSC configuration was computed for this link.
        return Err(ExternalError::Dsc(DscRefusal::TrainingFallback));
    }
    if trained.rate != rate || trained.lanes != lanes {
        // The fallback link must still carry the stream (no DSC) at the
        // pipe bpp.
        let demand_kbps =
            stream_demand_kbps(route.probe.mode.pixel_clock_khz, route.probe.pipe_bpp);
        let payload_kbps = trained.rate.payload_kbps(trained.lanes);
        if payload_kbps < demand_kbps {
            return Err(ExternalError::OverBudget {
                demand_kbps,
                payload_kbps,
            });
        }
        // Modeset retry at the trained configuration: the port is stopped
        // and re-enabled; the pipe keeps its reservation. Its PM demand
        // keeps the reserved port clock: a carried fallback only drops
        // lanes at that rate (see activate), so this is exact, and a lower
        // rate would be the documented over-request, never an under-one.
        stop_port(io, route)?;
        let retry = enable_port(io, route, trained.rate, trained.lanes)?;
        if retry.rate != trained.rate || retry.lanes != trained.lanes {
            return Err(ExternalError::TrainingMismatch);
        }
        trained = retry;
    }
    finish(io, route, &trained, payload)?;
    route.trained = trained;
    Ok(())
}

/// The route's pipe (present from the reservation on).
fn route_pipe(route: &MtlExternalRoute) -> Result<&RoutePipe, ExternalError> {
    route
        .reservation
        .as_ref()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))
}

/// `mtl_ddi_pre_enable_dp` steps 5–6.k for the route's transcoder: port
/// PLL, `TRANS_CLK_SEL`, `TRANS_DDI_FUNC_CTL` configured without ENABLE,
/// `mtl_ddi_prepare_link_retrain` and DPCD link training. Returns what the
/// link trained at.
fn enable_port<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
    rate: TrainRate,
    lanes: u8,
) -> Result<TrainedLink, ExternalError> {
    let port = route.probe.port;
    let trans = route_pipe(route)?.transcoder();
    let pll_rate = crate::intel_gpu_modeset::to_pll_rate(rate);
    // 5. Port PLL (intel_cx0pll_enable) for the planned width.
    // A legacy-mode C20 port also clears the MPLLB CAL_DONE banks first
    // (intel_c20_protocol_switch_valid).
    enable_clock(io, &route.probe, pll_rate, lanes)?;
    // 6.a TRANS_CLK_SEL = TGL_TRANS_CLK_SEL_PORT(phy).
    write(io, trans_clk_sel(trans), trans_clk_sel_port(port))?;
    // 6.c TRANS_DDI_FUNC_CTL configured without ENABLE.
    let func = stream_func(&route.probe, lanes);
    write(io, trans_ddi_func_ctl(trans), func & !TRANS_DDI_FUNC_ENABLE)?;
    // intel_dp_set_power(D0), intel_dp_sink_enable_decompression and
    // intel_dp_sink_set_fec_ready, before training.
    if let Some(plan) = route.probe.dsc {
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
        let link = |e| ExternalError::Link(LinkError::AuxFailure(e));
        aux.dpcd_write(dsc::DP_SET_POWER, &[dsc::DP_SET_POWER_D0])
            .map_err(link)?;
        dsc::set_sink_decompression(&mut aux, true).map_err(link)?;
        if plan.fec {
            dsc::set_sink_fec_ready(&mut aux, true).map_err(link)?;
        }
    }
    // mtl_ddi_prepare_link_retrain: 6.d DP_TP_CTL TPS1 (SST), 6.f D2D,
    // 6.g levels, 6.h PORT_BUF_CTL1, 6.i DDI_CTL_DE + buffer active.
    let enhanced = if route.probe.caps.enhanced_framing {
        DP_TP_CTL_ENHANCED_FRAME
    } else {
        0
    };
    write(
        io,
        dp_tp_ctl(trans),
        DP_TP_CTL_ENABLE
            | DP_TP_CTL_LINK_TRAIN_PAT1
            | enhanced
            | if route.probe.mst.is_some() {
                1 << 27
            } else {
                0
            },
    )?;
    enable_d2d(io, port).map_err(phy_err)?;
    let phy = Cx0Phy::with_lanes(io, port, route.probe.phy_lanes()?);
    if !route.probe.tbt()
        && route
            .probe
            .mst
            .is_none_or(|mst| mst.master == route.pipe.transcoder())
    {
        set_signal_levels(&phy, pll_rate, lanes, &[(0, 0); 4]).map_err(phy_err)?;
    }
    program_port_buf_ctl(io, port, lanes);
    write(
        io,
        port.ddi_buf_ctl(),
        ddi_port_width(lanes) | DDI_BUF_CTL_ENABLE,
    )?;
    wait_port_buf_active(io, port).map_err(phy_err)?;
    // 6.k DisplayPort training over the owned AUX channel.
    let aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
    let mut failure = None;
    let mut aux = crate::intel_gpu_modeset::training::TrainingAux::new(
        aux,
        crate::intel_gpu_modeset::training::State::new(pll_rate, lanes),
        |state: &crate::intel_gpu_modeset::training::State, change| {
            training_update(io, route, state, change).map_err(|error| {
                failure = Some(error);
                crate::dp_aux::AuxError::Nacked
            })
        },
    );
    let result = train_link(&mut aux, rate, lanes, |us| {
        let _ = narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_ns(us as u64 * 1_000),
        );
    })
    .map_err(ExternalError::Link);
    match failure {
        Some(error) => Err(error),
        None => result,
    }
}

fn enable_clock<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlSinkProbe,
    rate: crate::intel_gpu_pll::LinkRate,
    lanes: u8,
) -> Result<(), ExternalError> {
    let port = probe.port;
    let buf = read(io, port.buf_ctl1())?;
    write(
        io,
        port.buf_ctl1(),
        (buf & !PORT_BUF_IO_SELECT_TBT)
            | if probe.tbt() {
                PORT_BUF_IO_SELECT_TBT
            } else {
                0
            },
    )?;
    if probe.tbt() {
        enable_tbt_clock(io, port, rate).map_err(phy_err)?;
    } else {
        let mut request =
            dp_pll_request(port, rate, lanes, probe.dp_alt(), probe.legacy(), probe.ssc)
                .map_err(phy_err)?;
        request.lanes = probe.phy_lanes()?;
        enable_port_pll_state(io, port, &request).map_err(phy_err)?;
    }
    Ok(())
}

fn training_update<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
    state: &crate::intel_gpu_modeset::training::State,
    change: crate::intel_gpu_modeset::training::Change,
) -> Result<(), ExternalError> {
    use crate::intel_gpu_modeset::training::Change;
    let probe = &route.probe;
    let port = probe.port;
    let trans = route_pipe(route)?.transcoder();
    match change {
        Change::Configure => Ok(()),
        Change::Levels if !state.dirty && !probe.tbt() => set_signal_levels(
            &Cx0Phy::with_lanes(io, port, probe.phy_lanes()?),
            state.rate,
            state.lanes,
            &state.levels,
        )
        .map_err(phy_err),
        Change::Levels => Ok(()),
        Change::Pattern => {
            if state.pattern == 1 && state.dirty {
                if state.lanes > probe.tc.map_or(4, |tc| tc.max_lanes) {
                    return Err(ExternalError::TrainingMismatch);
                }
                let ddi = read(io, port.ddi_buf_ctl())?;
                write(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
                wait_port_buf_idle(io, port).map_err(phy_err)?;
                disable_d2d(io, port).map_err(phy_err)?;
                if probe.tbt() {
                    disable_tbt_clock(io, port).map_err(phy_err)?;
                } else {
                    disable_port_pll_lanes(io, port, probe.phy_lanes()?).map_err(phy_err)?;
                }
                enable_clock(io, probe, state.rate, state.lanes)?;
                if !probe.tbt() {
                    set_signal_levels(
                        &Cx0Phy::with_lanes(io, port, probe.phy_lanes()?),
                        state.rate,
                        state.lanes,
                        &state.levels,
                    )
                    .map_err(phy_err)?;
                }
                enable_d2d(io, port).map_err(phy_err)?;
                program_port_buf_ctl(io, port, state.lanes);
                write(
                    io,
                    port.ddi_buf_ctl(),
                    ddi_port_width(state.lanes) | DDI_BUF_CTL_ENABLE,
                )?;
                wait_port_buf_active(io, port).map_err(phy_err)?;
            }
            let old = read(io, dp_tp_ctl(trans))?;
            let bits = state
                .pattern_bits()
                .map_err(|_| ExternalError::TrainingMismatch)?;
            write(
                io,
                dp_tp_ctl(trans),
                (old & !(DP_TP_CTL_LINK_TRAIN_MASK | (1 << 7))) | bits,
            )
        }
    }
}

/// `TRANS_DDI_FUNC_CTL` for DP SST on `port` at `lanes`, with the pipe's
/// BPC field (`TRANS_DDI_BPC_8` is 0).
fn dp_func(port: XeLpgPort, lanes: u8, pipe_bpp: u32) -> u32 {
    crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        port.func_ctl_index(),
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        lanes,
    ) | dsc::trans_ddi_bpc(pipe_bpp)
}

fn stream_func(probe: &MtlSinkProbe, lanes: u8) -> u32 {
    let sst = dp_func(probe.port, lanes, probe.pipe_bpp);
    match probe.mst {
        Some(mst) => {
            (sst & !(7 << 24))
                | crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_MST
                | ((mst.master as u32) << 10)
        }
        None => sst,
    }
}

/// `intel_cpu_transcoder_set_m1_n1` for `trans`; `LINK_N1` last, it
/// triggers the update. The 8 bpc route keeps its `dp_mn` values; a 6 bpc
/// route writes `intel_link_compute_m_n` at 18 bpp.
fn program_mn<M: MmioWindow + ?Sized>(
    io: &M,
    trans: Transcoder,
    mode: &Mode,
    rate: crate::intel_gpu_pll::LinkRate,
    lanes: u8,
    pipe_bpp: u32,
) -> Result<(), ExternalError> {
    use crate::intel_gpu_pipes::{
        dp_mn, PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET,
    };
    let ls_khz = rate.megabits_per_sec() * 100;
    if pipe_bpp != dsc::PIPE_BPP {
        let m_n = dsc::link_m_n(
            pipe_bpp * 16,
            u32::from(lanes),
            mode.pixel_clock_khz,
            ls_khz,
            false,
        );
        return dsc::write_m_n(io, trans, &m_n).map_err(|_| ExternalError::AccessLost);
    }
    let (dm, dn, lm, ln) = dp_mn(mode.pixel_clock_khz, ls_khz, u32::from(lanes), 3);
    let base = trans.base();
    write(io, base + PIPE_DATA_M1_OFFSET, dm)?;
    write(io, base + PIPE_DATA_N1_OFFSET, dn)?;
    write(io, base + PIPE_LINK_M1_OFFSET, lm)?;
    write(io, base + PIPE_LINK_N1_OFFSET, ln)
}

/// The rest of `mtl_ddi_pre_enable_dp` (trained levels, 6.n DP_TP_CTL
/// normal), `hsw_crtc_enable` (M/N, source size, timings, RGB bypass),
/// `intel_ddi_enable` (`TRANS_DDI_FUNC_CTL` enable, transcoder enable) and
/// `intel_update_crtc` (the primary armed under vblank evasion), then the
/// route witness.
fn finish<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
    trained: &TrainedLink,
    payload: &mut dyn FnMut(Transcoder) -> Result<(), ExternalError>,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    let pll_rate = crate::intel_gpu_modeset::to_pll_rate(trained.rate);
    let lanes = trained.lanes;
    let mut levels = [(0u8, 0u8); 4];
    for (i, lane) in trained.vswing_pe.lanes.iter().enumerate() {
        levels[i] = (lane.swing, lane.pre_emph);
    }
    if !route.probe.tbt()
        && route
            .probe
            .mst
            .is_none_or(|mst| mst.master == route.pipe.transcoder())
    {
        set_signal_levels(
            &Cx0Phy::with_lanes(io, port, route.probe.phy_lanes()?),
            pll_rate,
            lanes,
            &levels,
        )
        .map_err(phy_err)?;
    }
    let rp = route
        .reservation
        .as_mut()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))?;
    let (pipe, trans) = (rp.pipe, rp.transcoder());
    let master = route.probe.mst.map_or(trans, |mst| mst.master);
    let tp = read(io, dp_tp_ctl(master))?;
    if route.probe.mst.is_some() && master == trans {
        write(
            io,
            dp_tp_ctl(master),
            (tp & !DP_TP_CTL_LINK_TRAIN_MASK) | (2 << 8),
        )?;
        if !wait_bit(io, dp_tp_ctl(master) + 4, 1 << 25, true, 800_000) {
            return Err(ExternalError::Mst(MstFailure::Act));
        }
    }
    write(
        io,
        dp_tp_ctl(master),
        (tp & !DP_TP_CTL_LINK_TRAIN_MASK) | DP_TP_CTL_LINK_TRAIN_NORMAL,
    )?;
    let lost = |_| ExternalError::AccessLost;
    let pipe_bpp = route.probe.pipe_bpp;
    // intel_ddi_set_dp_msa, the last step of intel_ddi_pre_enable_dp. The
    // 8 bpc route keeps its write stream (and leaves the MSA as it is); a
    // 6 bpc route writes its 6 bpc MSA, and its stop restores 8 bpc.
    if pipe_bpp != dsc::PIPE_BPP {
        write(
            io,
            trans.base() + dsc::TRANS_MSA_MISC_OFFSET,
            dsc::msa_misc(pipe_bpp),
        )?;
    }
    let plan = route.probe.dsc;
    if let Some(plan) = &plan {
        // intel_ddi_enable_fec, then intel_dsc_dp_pps_write; then
        // hsw_crtc_enable's intel_dsc_enable on the route's pipe.
        if plan.fec {
            dsc::enable_fec(io, trans).map_err(lost)?;
        }
        dsc::write_pps_sdp(io, trans, plan).map_err(lost)?;
        dsc::enable_engines(io, pipe, plan).map_err(lost)?;
    }
    // hsw_configure_cpu_transcoder: M/N with the timings; the transcoder
    // is off, so nothing here latches before its enable.
    match &plan {
        Some(plan) => dsc::write_m_n(io, trans, &plan.m_n(&mode)).map_err(lost)?,
        None => program_mn(io, trans, &mode, pll_rate, lanes, pipe_bpp)?,
    }
    rp.pipes.program_timings(io, pipe)?;
    // intel_ddi_enable: function, then the transcoder.
    let mut func = stream_func(&route.probe, lanes);
    if let Some(mst) = route.probe.mst {
        let off = trans.base() + crate::intel_gpu_pipes::PIPE_DATA_M1_OFFSET;
        let mn = read(io, off)?;
        write(
            io,
            off,
            (mn & !(0x7F << 25)) | (u32::from(mst.slots - 1) << 25),
        )?;
        func |= 1 << 8;
        write(io, trans_ddi_func_ctl(trans), func & !(1 << 8))?;
        mst::source_payload(io, trans, master, true)?;
        payload(trans)?;
    }
    write(io, trans_ddi_func_ctl(trans), func)?;
    let start = read(io, pipe.base() + FRMCOUNT)?;
    rp.pipes.enable(io, pipe)?;
    // intel_ddi_wait_for_fec_status(true): Linux only logs a timeout.
    if plan.is_some_and(|p| p.fec) {
        let _ = dsc::wait_fec_live(io, trans, true);
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
        let _ = dsc::wait_fec_detected(&mut aux, |us| {
            let _ = narf_scheduler::responsive_spin_until(
                || false,
                narf_time::Deadline::after_ns(u64::from(us) * 1_000),
            );
        });
    }
    rp.pipes.arm_primary(io, pipe)?;
    observe_live(io, route, func, start)
}

/// Bounded fresh-frame witness: the primary LIVE surface equals the
/// programmed SURF, the route/function/clock/pattern read back, the DDI
/// buffer is active and the frame counter advanced.
fn observe_live<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
    func: u32,
    start: u32,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    let rp = route_pipe(route)?;
    let (base, trans) = (rp.base(), rp.transcoder());
    let plane = crate::intel_gpu_pipes::build_primary_plane(
        mode.h_active,
        mode.v_active,
        route.fb.stride_bytes,
        route.fb.phys_addr as u32,
        crate::intel_gpu_pipes::PixelFormat::Argb8888,
    )
    .map_err(|_| ExternalError::Modeset(ModesetError::InvalidFramebuffer))?;
    let mut refused = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let frame = io.read32(base + FRMCOUNT);
            let surf = io.read32(base + PLANE_SURF_1);
            let live = io.read32(base + PLANE_SURFLIVE_1);
            let route_now = io.read32(trans_ddi_func_ctl(trans));
            let clock = io.read32(trans_clk_sel(trans));
            let tp = io.read32(dp_tp_ctl(route.probe.mst.map_or(trans, |mst| mst.master)));
            let buf = io.read32(port.buf_ctl1());
            let ddi = io.read32(port.ddi_buf_ctl());
            refused = !io.display_access_ok() || frame == u32::MAX || ddi == u32::MAX;
            refused
                || (frame != start
                    && surf == plane.plane_surf
                    && live == surf
                    && route_now == func
                    && clock == trans_clk_sel_port(port)
                    && tp & (DP_TP_CTL_ENABLE | DP_TP_CTL_LINK_TRAIN_MASK)
                        == DP_TP_CTL_ENABLE | DP_TP_CTL_LINK_TRAIN_NORMAL
                    && buf & PORT_BUF_PHY_IDLE == 0
                    && ddi & DDI_BUF_CTL_ENABLE != 0)
        },
        narf_time::Deadline::after_ns(100_000_000),
    );
    if !done || refused {
        return Err(ExternalError::Modeset(
            ModesetError::PipelineEnableUnavailable,
        ));
    }
    Ok(())
}

/// The port side of `intel_ddi_post_disable_dp`, with the transcoder off:
/// function deselect, sink D3, `intel_ddi_buf_disable`, `TRANS_CLK_SEL`
/// off, `intel_cx0pll_disable` and TBT IO deselect, each observed.
fn stop_port<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let trans = route_pipe(route)?.transcoder();
    let stop_failed = ExternalError::Modeset(ModesetError::PipelineStopUnavailable);
    // intel_ddi_disable_transcoder_func (TGL+ SST): enable, port, mode.
    let func = read(io, trans_ddi_func_ctl(trans))?;
    write(
        io,
        trans_ddi_func_ctl(trans),
        func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE),
    )?;
    // A 6 bpc route leaves the MSA at 8 bpc: the 8 bpc route does not
    // write it (its write stream predates the MSA), and Linux's
    // intel_ddi_set_dp_msa would write 8 bpc at its next enable.
    if route.probe.pipe_bpp != dsc::PIPE_BPP {
        write(
            io,
            trans.base() + dsc::TRANS_MSA_MISC_OFFSET,
            dsc::msa_misc(dsc::PIPE_BPP),
        )?;
    }
    // intel_dsc_disable, then intel_dp_set_infoframes(false)'s PPS SDP.
    let pipe = route_pipe(route)?.pipe;
    dsc::disable_engines(io, pipe).map_err(|_| ExternalError::AccessLost)?;
    dsc::disable_pps_sdp(io, trans).map_err(|_| ExternalError::AccessLost)?;
    let fec = route.probe.dsc.is_some_and(|p| p.fec);
    // Sink to D3 before the port goes down (a NACK never replaces the
    // local idle proof).
    if route.probe.caps.dpcd_rev >= 0x11 {
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
        let _ = aux.dpcd_write(DPCD_SET_POWER, &[DP_SET_POWER_D3]);
    }
    // intel_ddi_buf_disable (display 14): DDI_CTL_DE off, PHY idle, D2D
    // off, DP_TP_CTL off.
    let ddi = read(io, port.ddi_buf_ctl())?;
    write(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
    wait_port_buf_idle(io, port).map_err(|_| stop_failed)?;
    disable_d2d(io, port).map_err(|_| stop_failed)?;
    let tp = read(io, dp_tp_ctl(trans))?;
    write(io, dp_tp_ctl(trans), tp & !DP_TP_CTL_ENABLE)?;
    // intel_ddi_disable_fec and intel_ddi_wait_for_fec_status(false) (a
    // logged timeout in Linux), then intel_dp_sink_set_fec_ready(false).
    if fec {
        dsc::disable_fec(io, trans).map_err(|_| ExternalError::AccessLost)?;
        let _ = dsc::wait_fec_live(io, trans, false);
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
        let _ = dsc::set_sink_fec_ready(&mut aux, false);
    }
    // TRANS_CLK_SEL: no clock to the transcoder.
    write(io, trans_clk_sel(trans), 0)?;
    // intel_cx0pll_disable, then deselect Thunderbolt IO.
    if route.probe.tbt() {
        disable_tbt_clock(io, port).map_err(|_| stop_failed)?;
    } else {
        disable_port_pll_lanes(io, port, route.probe.phy_lanes()?).map_err(|_| stop_failed)?;
    }
    let buf = read(io, port.buf_ctl1())?;
    write(io, port.buf_ctl1(), buf & !PORT_BUF_IO_SELECT_TBT)?;
    // Final observation of every stopped port resource.
    let ddi = read(io, port.ddi_buf_ctl())?;
    let buf = read(io, port.buf_ctl1())?;
    let clock = read(io, port.port_clock_ctl())?;
    if ddi & DDI_BUF_CTL_ENABLE != 0
        || buf & PORT_BUF_PHY_IDLE == 0
        || clock & route.probe.clock_mask()? != 0
    {
        return Err(stop_failed);
    }
    Ok(())
}

/// Local stop in `hsw_crtc_disable` / `intel_ddi_post_disable_dp` order:
/// primary off, transcoder off, the port side ([`stop_port`]), then the
/// pipe DMC disable and the post-plane repartition without the pipe. Every
/// step is observed; any failure leaves the remaining state (and the
/// pipe's reservation) for quarantine. A route that failed before its
/// reservation has nothing to stop: its port is programmed only after it.
fn stop_local<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
) -> Result<(), ExternalError> {
    let stop_failed = ExternalError::Modeset(ModesetError::PipelineStopUnavailable);
    let Some(rp) = route.reservation.as_mut() else {
        return Ok(());
    };
    let pipe = rp.pipe;
    rp.pipes.disable_primary(io, pipe)?;
    // intel_ddi_disable_dp: the sink's decompression off before the
    // transcoder (best effort, as in Linux).
    if route.probe.dsc.is_some() {
        let mut aux = IntelAux::xelpdp(io, route.probe.port.aux_base(), route.probe.tbt());
        let _ = dsc::set_sink_decompression(&mut aux, false);
    }
    let rp = route
        .reservation
        .as_mut()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))?;
    rp.pipes.disable(io, pipe).map_err(|e| match e {
        PipeEnableError::Timeout => stop_failed,
        e => e.into(),
    })?;
    stop_port(io, route)?;
    let rp = route
        .reservation
        .as_mut()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))?;
    rp.pipes.release(io, rp.pipe, rp.dmc)?;
    route.reservation = None;
    Ok(())
}

impl MtlExternalRoute {
    /// Current lifecycle state.
    pub fn state(&self) -> RouteState {
        self.state
    }

    /// The external port.
    pub fn port(&self) -> XeLpgPort {
        self.probe.port
    }

    /// The Pipe B–D (and same-index transcoder) the route was activated on.
    pub fn pipe(&self) -> Pipe {
        self.pipe
    }

    /// Whether the pipe's display resources are still reserved (live, or
    /// retained by a stop that did not complete its release).
    pub fn reserved(&self) -> bool {
        self.reservation.is_some()
    }

    /// Locally stop the route. A stopped route stays stopped; a failed
    /// stop quarantines it (resources retained, never released).
    pub fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), ExternalError> {
        match self.state {
            RouteState::Stopped => Ok(()),
            RouteState::Quarantined => Err(ExternalError::Quarantined),
            RouteState::Live => match stop_local(io, self) {
                Ok(()) => {
                    self.state = RouteState::Stopped;
                    Ok(())
                }
                Err(e) => {
                    self.state = RouteState::Quarantined;
                    Err(e)
                }
            },
        }
    }

    /// Release AUX power and Type-C ownership of a stopped route. A live
    /// or quarantined route is handed back.
    // The retained route returns inline on refusal: it must not allocate.
    #[allow(clippy::result_large_err)]
    pub fn release<M: MmioWindow + ?Sized>(
        self,
        io: &M,
    ) -> Result<(), (MtlExternalRoute, ExternalError)> {
        if self.state != RouteState::Stopped {
            return Err((self, ExternalError::Quarantined));
        }
        release_probe(io, &self.probe).map_err(|e| (self, e))
    }

    /// Short-pulse revalidation (DPCD 0x202..0x204): every trained lane
    /// reports CR_DONE | CHANNEL_EQ_DONE | SYMBOL_LOCKED and inter-lane
    /// alignment is done.
    pub fn link_ok<M: MmioWindow + ?Sized>(&self, io: &M) -> Result<bool, ExternalError> {
        let mut aux = IntelAux::xelpdp(io, self.probe.port.aux_base(), self.probe.tbt());
        let mut status = [0u8; 3];
        aux.dpcd_read(0x202, &mut status)
            .map_err(|e| ExternalError::Link(LinkError::AuxFailure(e)))?;
        let lanes = self.trained.lanes.min(4) as usize;
        for lane in 0..lanes {
            let nibble = (status[lane / 2] >> (4 * (lane % 2))) & 0x7;
            if nibble != 0x7 {
                return Ok(false);
            }
        }
        Ok(status[2] & 0x01 != 0)
    }
}

/// Board declaration for one external port: the facts a VBT child device
/// carries (`intel_bios.c`): `intel_bios_encoder_supports_dp`
/// (`DEVICE_TYPE_DISPLAYPORT_OUTPUT`), the HDMI connector
/// (`DEVICE_TYPE_TMDS_DVI_SIGNALING` and a usable DDC pin) and, for
/// Type-C, `intel_ddi_init`'s legacy test (neither `dp_usb_type_c` nor
/// `tbt`). A parsed VBT yields it through [`MtlPortPolicy::from_vbt`];
/// without one production uses [`MtlPortPolicy::NO_VBT`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlPortDecl {
    /// VBT board lane reversal (never the USB-C cable orientation).
    pub lane_reversal: bool,
    /// The port carries DisplayPort.
    pub dp: bool,
    /// The port carries native HDMI (TMDS).
    pub hdmi: bool,
    /// Type-C only: the PHY is wired to a fixed DP/HDMI connector.
    pub legacy: bool,
    /// The HDMI DDC pin `intel_hdmi_ddc_pin` resolved from the VBT; `None`
    /// for a hand declaration, which uses the port's
    /// [`crate::intel_gpu_xelpg_hdmi::ddc_pin`].
    pub ddc_pin: Option<PinPair>,
}

impl MtlPortDecl {
    /// No output on this port.
    pub const NONE: Self = Self {
        lane_reversal: false,
        dp: false,
        hdmi: false,
        legacy: false,
        ddc_pin: None,
    };
    /// `init_vbt_missing_defaults` for a non-TC port other than A and E:
    /// `DEVICE_TYPE_TMDS_DVI_SIGNALING | DEVICE_TYPE_DISPLAYPORT_OUTPUT`.
    pub const COMBO_DP_HDMI: Self = Self {
        lane_reversal: false,
        dp: true,
        hdmi: true,
        legacy: false,
        ddc_pin: None,
    };
    /// A USB-C connector: DP-alt only.
    pub const USB_C: Self = Self {
        lane_reversal: false,
        dp: true,
        hdmi: false,
        legacy: false,
        ddc_pin: None,
    };
    /// A Type-C PHY wired to a native HDMI connector.
    pub const LEGACY_HDMI: Self = Self {
        lane_reversal: false,
        dp: false,
        hdmi: true,
        legacy: true,
        ddc_pin: None,
    };

    /// `intel_ddi_init`: a Type-C port declared non-legacy but with HDMI
    /// and without DP is treated as legacy.
    pub const fn legacy_effective(self) -> bool {
        self.legacy || (self.hdmi && !self.dp)
    }
}

/// Declarations for DDI B and TC1..TC4, plus the board's SSC preference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlPortPolicy {
    /// DDI B (C10 combo PHY).
    pub ddi_b: MtlPortDecl,
    /// TC1..TC4.
    pub tc: [MtlPortDecl; 4],
    /// `intel_panel_use_ssc` (the VBT's `lvds_use_ssc`): DP SSC is only
    /// enabled when this holds and the sink advertises 0.5% downspread.
    pub use_ssc: bool,
}

impl MtlPortPolicy {
    /// The production policy without a VBT. DDI B follows Linux's
    /// `init_vbt_missing_defaults` (DP + HDMI). Linux creates no Type-C
    /// encoder without a VBT ("VBT has the TypeC mode ... we don't want to
    /// detect it"); this tree keeps the USB-C DP-alt route it already
    /// owns and declares no legacy or HDMI Type-C port, so the policy
    /// matches [`MtlHpdConfig::TYPE_C`]. `init_vbt_defaults` turns SSC on.
    pub const NO_VBT: Self = Self {
        ddi_b: MtlPortDecl::COMBO_DP_HDMI,
        tc: [MtlPortDecl::USB_C; 4],
        use_ssc: true,
    };

    /// The policy a parsed VBT declares: one declaration per external port
    /// `intel_ddi_init` would create an encoder for
    /// ([`Vbt::encoders`]), every other external port [`MtlPortDecl::NONE`]
    /// (Linux creates no encoder for a port the VBT omits), and the VBT's
    /// SSC preference. See [`decl_from_encoder`] for the per-port mapping
    /// and the declarations this route cannot drive.
    pub fn from_vbt(vbt: &Vbt) -> Self {
        let mut policy = Self {
            ddi_b: MtlPortDecl::NONE,
            tc: [MtlPortDecl::NONE; 4],
            use_ssc: vbt.use_ssc(),
        };
        for encoder in vbt.encoders(VbtPlatform::MeteorLake) {
            let port = match encoder.port {
                1 => XeLpgPort::B,
                3 => XeLpgPort::Tc1,
                4 => XeLpgPort::Tc2,
                5 => XeLpgPort::Tc3,
                6 => XeLpgPort::Tc4,
                _ => continue,
            };
            let decl = decl_from_encoder(port, &encoder);
            match port.tc_index() {
                Some(tc) => policy.tc[tc as usize] = decl,
                None => policy.ddi_b = decl,
            }
        }
        policy
    }

    /// The HDMI DDC pin for `port`: the VBT-resolved pin, else the port's
    /// default ([`crate::intel_gpu_xelpg_hdmi::ddc_pin`]).
    pub const fn ddc_pin(&self, port: XeLpgPort) -> Option<PinPair> {
        match self.decl(port).ddc_pin {
            Some(pin) => Some(pin),
            None => crate::intel_gpu_xelpg_hdmi::ddc_pin(port),
        }
    }

    /// The declaration for `port` (DDI A is never external).
    pub const fn decl(&self, port: XeLpgPort) -> MtlPortDecl {
        match port {
            XeLpgPort::A => MtlPortDecl::NONE,
            XeLpgPort::B => self.ddi_b,
            XeLpgPort::Tc1 => self.tc[0],
            XeLpgPort::Tc2 => self.tc[1],
            XeLpgPort::Tc3 => self.tc[2],
            XeLpgPort::Tc4 => self.tc[3],
        }
    }

    /// The hotplug configuration this policy implies: legacy SDE sources
    /// exactly for the effectively legacy Type-C ports.
    pub const fn hpd_config(&self) -> MtlHpdConfig {
        MtlHpdConfig {
            legacy_tc: [
                self.tc[0].legacy_effective(),
                self.tc[1].legacy_effective(),
                self.tc[2].legacy_effective(),
                self.tc[3].legacy_effective(),
            ],
        }
    }
}

/// The declaration for one VBT encoder on an external MTL port. DP and
/// HDMI follow the encoder's connectors (`init_dp`, an HDMI connector with
/// its `intel_hdmi_ddc_pin`), legacy follows `intel_ddi_init`'s Type-C
/// rule. Encoders this route cannot drive as declared become
/// [`MtlPortDecl::NONE`] (fail closed): DSI and eDP encoders, a VBT AUX
/// channel other than the port's own (`default_aux_ch`; the AUX, power
/// and Type-C paths are keyed by port), and a Type-C port marked dedicated external
/// (Linux then treats it as non-Type-C; this route always owns it through
/// TCSS).
pub fn decl_from_encoder(port: XeLpgPort, encoder: &VbtEncoder) -> MtlPortDecl {
    let type_c = port.tc_index().is_some();
    let foreign_aux = encoder
        .aux_ch
        .is_some_and(|aux| u32::from(aux) != port.port_enum());
    if encoder.dsi || encoder.edp || foreign_aux || (type_c && !encoder.type_c) {
        return MtlPortDecl::NONE;
    }
    let hdmi = encoder.hdmi_ddc.is_some();
    if !encoder.dp && !hdmi {
        return MtlPortDecl::NONE;
    }
    MtlPortDecl {
        lane_reversal: encoder.lane_reversal,
        dp: encoder.dp,
        hdmi,
        legacy: type_c && encoder.tc_legacy,
        ddc_pin: encoder.hdmi_ddc,
    }
}

/// The protocols the service tries for a connected sink.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RoutePlan {
    /// DisplayPort only.
    Dp,
    /// Native HDMI only.
    Hdmi,
    /// DisplayPort first; HDMI when no DPCD answers.
    DpThenHdmi,
    /// The declaration admits nothing in this live mode.
    Refuse,
}

/// The DP-versus-HDMI decision for a sink attached in `live` mode. Linux
/// registers both a DP and an HDMI connector on a port whose VBT child
/// declares both (`intel_ddi_init`); the DP connector reports connected
/// only when DPCD answers (`intel_dp_detect`), the HDMI one only when DDC
/// returns a digital EDID (`intel_hdmi_set_edid`). With a single owned
/// route this is ordered: DP first, HDMI only on a DPCD read failure.
/// Native HDMI needs DDI B or a declared legacy Type-C port; DP-alt and
/// TBT-alt never carry TMDS. A TBT route carries only its live DP tunnel.
pub const fn route_plan(port: XeLpgPort, decl: MtlPortDecl, live: LiveMode) -> RoutePlan {
    let type_c = port.tc_index().is_some();
    let mode_ok = match live {
        LiveMode::Native => !type_c && !matches!(port, XeLpgPort::A),
        LiveMode::Legacy => type_c && decl.legacy_effective(),
        LiveMode::DpAlt => type_c,
        LiveMode::TbtAlt => type_c,
    };
    if !mode_ok {
        return RoutePlan::Refuse;
    }
    let dp = decl.dp;
    let hdmi = decl.hdmi && !matches!(live, LiveMode::DpAlt | LiveMode::TbtAlt);
    match (dp, hdmi) {
        (true, true) => RoutePlan::DpThenHdmi,
        (true, false) => RoutePlan::Dp,
        (false, true) => RoutePlan::Hdmi,
        (false, false) => RoutePlan::Refuse,
    }
}

/// Whether a DP probe failure means no DPCD answered (`intel_dp_detect`
/// reports disconnected), the only DP failure that lets HDMI be tried.
pub const fn dpcd_absent(error: &ExternalError) -> bool {
    matches!(error, ExternalError::Link(LinkError::AuxFailure(_)))
}

/// Which protocol a route drives.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtlProtocol {
    /// DisplayPort SST.
    Dp,
    /// HDMI TMDS.
    Hdmi,
    DpMst,
}

/// A refusal or failure from either route.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// From the DP route (or a policy refusal).
    Dp(ExternalError),
    /// From the HDMI route.
    Hdmi(HdmiError),
}

/// One owned external route of either protocol.
#[derive(Debug)]
pub enum MtlRoute {
    /// DisplayPort SST.
    Dp(MtlExternalRoute),
    /// HDMI TMDS.
    Hdmi(MtlHdmiRoute),
    Mst(alloc::boxed::Box<MtlMstRoute>),
}

impl MtlRoute {
    /// The external port.
    pub fn port(&self) -> XeLpgPort {
        match self {
            MtlRoute::Dp(r) => r.port(),
            MtlRoute::Hdmi(r) => r.port(),
            MtlRoute::Mst(r) => r.port(),
        }
    }

    /// The protocol.
    pub fn protocol(&self) -> MtlProtocol {
        match self {
            MtlRoute::Dp(_) => MtlProtocol::Dp,
            MtlRoute::Hdmi(_) => MtlProtocol::Hdmi,
            MtlRoute::Mst(_) => MtlProtocol::DpMst,
        }
    }

    /// The Pipe B–D (CRTC) and same-index transcoder the route drives.
    pub fn pipe(&self) -> Pipe {
        match self {
            MtlRoute::Dp(r) => r.pipe(),
            MtlRoute::Hdmi(r) => r.pipe(),
            MtlRoute::Mst(r) => r.first().map_or(Pipe::B, |(pipe, _, _)| pipe),
        }
    }

    /// Scanning out.
    pub fn live(&self) -> bool {
        match self {
            MtlRoute::Dp(r) => r.state() == RouteState::Live,
            MtlRoute::Hdmi(r) => r.state() == HdmiRouteState::Live,
            MtlRoute::Mst(r) => r.live(),
        }
    }

    /// Locally stopped (its hardware is off).
    pub fn stopped(&self) -> bool {
        match self {
            MtlRoute::Dp(r) => r.state() == RouteState::Stopped,
            MtlRoute::Hdmi(r) => r.state() == HdmiRouteState::Stopped,
            MtlRoute::Mst(r) => r.stopped(),
        }
    }

    fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), RouteError> {
        match self {
            MtlRoute::Dp(r) => r.stop(io).map_err(RouteError::Dp),
            MtlRoute::Hdmi(r) => r.stop(io).map_err(RouteError::Hdmi),
            MtlRoute::Mst(r) => r.stop(io).map_err(RouteError::Dp),
        }
    }

    // The retained route returns inline on refusal: it must not allocate.
    #[allow(clippy::result_large_err)]
    fn release<M: MmioWindow + ?Sized>(self, io: &M) -> Result<(), (MtlRoute, RouteError)> {
        match self {
            MtlRoute::Dp(r) => r
                .release(io)
                .map_err(|(r, e)| (MtlRoute::Dp(r), RouteError::Dp(e))),
            MtlRoute::Hdmi(r) => r
                .release(io)
                .map_err(|(r, e)| (MtlRoute::Hdmi(r), RouteError::Hdmi(e))),
            MtlRoute::Mst(r) => r
                .release(io)
                .map_err(|(r, error)| (MtlRoute::Mst(r), RouteError::Dp(error))),
        }
    }
}

/// What one service pass did.
#[derive(Clone, Debug)]
pub enum ServiceOutcome {
    /// A new route is live; the caller publishes `fb` at `mode` on `pipe`.
    Activated {
        /// The external port.
        port: XeLpgPort,
        /// The protocol driving it.
        protocol: MtlProtocol,
        /// The Pipe B–D (CRTC) scanning it out.
        pipe: Pipe,
        /// The scanned-out mode.
        mode: Mode,
        /// The scanned-out framebuffer.
        fb: Framebuffer,
    },
    /// The event's sink was not admitted; no route was created.
    Refused {
        /// The external port.
        port: XeLpgPort,
        /// Why (from the last protocol tried).
        error: RouteError,
    },
    /// The route was stopped and released; the caller withdraws it.
    Withdrawn {
        /// The external port.
        port: XeLpgPort,
    },
    /// The route could not be stopped or released and stays retained.
    Retained {
        /// The external port.
        port: XeLpgPort,
        /// Why.
        error: RouteError,
    },
    /// The event needed no change (link still trained, other pin, …).
    Unchanged,
}

/// The route presence a service publishes for lock-free readers
/// ([`routes_stopped`], [`route_live`]): absent, live, locally stopped, or
/// retained without a proven stop. It changes only when a service pass
/// ends, so a reader racing a pass sees the last completed pass's route,
/// never a transient "not stopped" from the pass merely holding the lock.
/// Passes that light or stop hardware are serialized against the display
/// power-management readers by the display's legacy guard, and against
/// DC5/DC6 re-entry by their `DcUser::External` reference and the
/// contended-lock rule of [`external_route_blocks_dc`].
#[derive(Debug)]
pub struct RoutePresence(AtomicU8);

const PRESENCE_ABSENT: u8 = 0;
const PRESENCE_LIVE: u8 = 1;
const PRESENCE_STOPPED: u8 = 2;
const PRESENCE_RETAINED: u8 = 3;

impl RoutePresence {
    /// No route.
    pub const fn new() -> Self {
        Self(AtomicU8::new(PRESENCE_ABSENT))
    }

    fn publish(&self, route: Option<&MtlRoute>) {
        let code = match route {
            None => PRESENCE_ABSENT,
            Some(route) if route.live() => PRESENCE_LIVE,
            Some(route) if route.stopped() => PRESENCE_STOPPED,
            Some(_) => PRESENCE_RETAINED,
        };
        self.0.store(code, Ordering::Release);
    }

    /// No route, or a locally stopped one (its hardware is off).
    pub fn stopped(&self) -> bool {
        matches!(
            self.0.load(Ordering::Acquire),
            PRESENCE_ABSENT | PRESENCE_STOPPED
        )
    }

    /// A route is scanning out.
    pub fn live(&self) -> bool {
        self.0.load(Ordering::Acquire) == PRESENCE_LIVE
    }
}

impl Default for RoutePresence {
    fn default() -> Self {
        Self::new()
    }
}

/// Owner of at most one MTL external route, driven by hotplug events.
#[derive(Debug)]
pub struct MtlExternalService {
    route: Option<MtlRoute>,
    /// The live mode the retained route was connected in (for `Redetect`).
    live: LiveMode,
    policy: MtlPortPolicy,
    /// What activations share the display with (panel, pipe-DMC sink).
    display: MtlDisplay,
    /// Where this service publishes its route presence, if anywhere.
    presence: Option<&'static RoutePresence>,
}

impl Default for MtlExternalService {
    fn default() -> Self {
        Self::new()
    }
}

impl MtlExternalService {
    /// An empty service under the no-VBT policy.
    pub const fn new() -> Self {
        Self::with_policy(MtlPortPolicy::NO_VBT)
    }

    /// An empty service under an explicit port policy.
    pub const fn with_policy(policy: MtlPortPolicy) -> Self {
        Self {
            route: None,
            live: LiveMode::Native,
            policy,
            display: MtlDisplay::NONE,
            presence: None,
        }
    }

    /// An empty service that publishes its route presence to `presence`
    /// at the end of every pass.
    pub const fn with_presence(presence: &'static RoutePresence) -> Self {
        let mut service = Self::new();
        service.presence = Some(presence);
        service
    }

    /// What activations share the display with.
    pub fn display(&self) -> MtlDisplay {
        self.display
    }

    /// Replace the display context (the owned panel, the pipe-DMC sink)
    /// used by later activations; a live route keeps the pipe-DMC sink it
    /// reported to.
    pub fn set_display(&mut self, display: MtlDisplay) {
        self.display = display;
    }

    fn publish(&self) {
        if let Some(presence) = self.presence {
            presence.publish(self.route.as_ref());
        }
    }

    /// The port policy.
    pub fn policy(&self) -> MtlPortPolicy {
        self.policy
    }

    /// Replace the port policy (the VBT found at probe). Refused while a
    /// route is owned: its probe, PLL and DDC choices came from the old
    /// policy.
    pub fn set_policy(&mut self, policy: MtlPortPolicy) -> bool {
        if self.route.is_some() {
            return self.policy == policy;
        }
        self.policy = policy;
        true
    }

    /// The retained route, if any.
    pub fn route(&self) -> Option<&MtlRoute> {
        self.route.as_ref()
    }

    fn connect<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        port: XeLpgPort,
        live: LiveMode,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let legacy = live == LiveMode::Legacy;
        let plan = route_plan(port, self.policy.decl(port), live);
        let outcome = match plan {
            RoutePlan::Refuse => ServiceOutcome::Refused {
                port,
                error: RouteError::Dp(match live {
                    LiveMode::TbtAlt => ExternalError::Tc(TcError::TunnelUnavailable),
                    _ => ExternalError::UnsupportedPort,
                }),
            },
            RoutePlan::Hdmi => self.connect_hdmi(io, port, legacy, alloc),
            RoutePlan::Dp | RoutePlan::DpThenHdmi => {
                match probe_link(io, Generation::MeteorLake, port, legacy) {
                    Ok(link) => self.connect_output(io, link, alloc),
                    Err(e) if plan == RoutePlan::DpThenHdmi && dpcd_absent(&e) => {
                        self.connect_hdmi(io, port, legacy, alloc)
                    }
                    Err(error) => ServiceOutcome::Refused {
                        port,
                        error: RouteError::Dp(error),
                    },
                }
            }
        };
        if self.route.is_some() {
            self.live = live;
        }
        outcome
    }

    fn connect_output<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        link: LinkProbe,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let port = link.port;
        let mut cap = [0];
        if link.raw[0] >= 0x12 {
            if let Err(error) = link.aux(io).dpcd_read(0x21, &mut cap) {
                let _ = link.release(io);
                return ServiceOutcome::Refused {
                    port,
                    error: RouteError::Dp(ExternalError::Link(LinkError::AuxFailure(error))),
                };
            }
        }
        if cap[0] & 1 != 0 {
            match MtlMstRoute::connect(io, link, self.policy.decl(port), &self.display, alloc) {
                Ok(route) => {
                    let (pipe, mode, fb) = route.first().expect("live MST has a first stream");
                    self.route = Some(MtlRoute::Mst(route));
                    ServiceOutcome::Activated {
                        port,
                        protocol: MtlProtocol::DpMst,
                        pipe,
                        mode,
                        fb,
                    }
                }
                Err((mut route, error)) => {
                    let _ = route.stop(io);
                    self.settle_failed(io, MtlRoute::Mst(route), RouteError::Dp(error))
                }
            }
        } else {
            match probe_sink_link(io, link) {
                Ok(mut probe) => {
                    probe.lane_reversal = self.policy.decl(port).lane_reversal;
                    probe.ssc = dp_ssc_enabled(self.policy.use_ssc, probe.max_downspread);
                    self.connect_dp(io, probe, alloc)
                }
                Err(error) => ServiceOutcome::Refused {
                    port,
                    error: RouteError::Dp(error),
                },
            }
        }
    }

    fn connect_dp<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        probe: MtlSinkProbe,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let port = probe.port;
        let fb = match alloc(&probe.mode) {
            Some(fb) => fb,
            None => {
                let _ = release_probe(io, &probe);
                return ServiceOutcome::Refused {
                    port,
                    error: RouteError::Dp(ExternalError::Modeset(ModesetError::InvalidFramebuffer)),
                };
            }
        };
        match activate(io, probe, fb, &self.display) {
            Ok(route) => {
                let outcome = ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Dp,
                    pipe: route.pipe(),
                    mode: route.probe.mode,
                    fb,
                };
                self.route = Some(MtlRoute::Dp(route));
                outcome
            }
            Err(ActivateError::Refused(probe, error)) => {
                let _ = release_probe(io, &probe);
                ServiceOutcome::Refused {
                    port,
                    error: RouteError::Dp(error),
                }
            }
            Err(ActivateError::Failed(route, error)) => {
                self.settle_failed(io, MtlRoute::Dp(route), RouteError::Dp(error))
            }
        }
    }

    fn connect_hdmi<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        port: XeLpgPort,
        legacy: bool,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let ddc = self.policy.ddc_pin(port);
        let mut probe = match probe_hdmi(io, Generation::MeteorLake, port, legacy, ddc) {
            Ok(probe) => probe,
            Err(e) => {
                return ServiceOutcome::Refused {
                    port,
                    error: RouteError::Hdmi(e),
                }
            }
        };
        probe.pll.lanes = PhyLaneConfig::for_route(false, 4, self.policy.decl(port).lane_reversal)
            .expect("native PHY has both lanes");
        let fb = match alloc(&probe.mode) {
            Some(fb) => fb,
            None => {
                let _ = release_hdmi_probe(io, &probe);
                return ServiceOutcome::Refused {
                    port,
                    error: RouteError::Hdmi(HdmiError::Route(ExternalError::Modeset(
                        ModesetError::InvalidFramebuffer,
                    ))),
                };
            }
        };
        match activate_hdmi(io, probe, fb, &self.display) {
            Ok(route) => {
                let outcome = ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Hdmi,
                    pipe: route.pipe(),
                    mode: route.probe.mode,
                    fb,
                };
                self.route = Some(MtlRoute::Hdmi(route));
                outcome
            }
            Err((Err(probe), error)) => {
                let _ = release_hdmi_probe(io, &probe);
                ServiceOutcome::Refused {
                    port,
                    error: RouteError::Hdmi(error),
                }
            }
            Err((Ok(route), error)) => {
                self.settle_failed(io, MtlRoute::Hdmi(route), RouteError::Hdmi(error))
            }
        }
    }

    /// A failed activation: release a locally stopped route, retain
    /// anything else.
    fn settle_failed<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        route: MtlRoute,
        error: RouteError,
    ) -> ServiceOutcome {
        let port = route.port();
        if !route.stopped() {
            self.route = Some(route);
            return ServiceOutcome::Retained { port, error };
        }
        match route.release(io) {
            Ok(()) => ServiceOutcome::Refused { port, error },
            Err((route, e)) => {
                self.route = Some(route);
                ServiceOutcome::Retained { port, error: e }
            }
        }
    }

    fn withdraw<M: MmioWindow + ?Sized>(&mut self, io: &M) -> ServiceOutcome {
        let Some(mut route) = self.route.take() else {
            return ServiceOutcome::Unchanged;
        };
        let port = route.port();
        if let Err(error) = route.stop(io) {
            self.route = Some(route);
            return ServiceOutcome::Retained { port, error };
        }
        match route.release(io) {
            Ok(()) => ServiceOutcome::Withdrawn { port },
            Err((route, error)) => {
                self.route = Some(route);
                ServiceOutcome::Retained { port, error }
            }
        }
    }

    /// Act on one hotplug event. `alloc` supplies a scanout framebuffer
    /// for a newly probed mode (the caller owns its GGTT lifetime). The
    /// route presence is published when the pass ends.
    pub fn handle<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        event: MtlHpdEvent,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let outcome = self.handle_event(io, event, alloc);
        self.publish();
        outcome
    }

    fn handle_event<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        event: MtlHpdEvent,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let port = event.pin.port();
        let owned = self.route.as_ref().map(|r| (r.port(), r.protocol()));
        let owns = owned.map(|(p, _)| p) == Some(port);
        match event.kind {
            MtlHpdKind::Connected(live) if self.route.is_none() => {
                self.connect(io, port, live, alloc)
            }
            MtlHpdKind::Connected(_) => ServiceOutcome::Unchanged,
            MtlHpdKind::Disconnected if owns => self.withdraw(io),
            MtlHpdKind::ShortPulse if owned == Some((port, MtlProtocol::DpMst)) => {
                let unchanged = match self.route.as_mut() {
                    Some(MtlRoute::Mst(route)) => route.unchanged(io) == Ok(true),
                    _ => false,
                };
                if unchanged {
                    ServiceOutcome::Unchanged
                } else {
                    let live = self.live;
                    match self.withdraw(io) {
                        ServiceOutcome::Withdrawn { .. } => self.connect(io, port, live, alloc),
                        other => other,
                    }
                }
            }
            // HDMI has no IRQ_HPD (`intel_hdmi` installs no hpd_pulse).
            MtlHpdKind::ShortPulse if owned == Some((port, MtlProtocol::Dp)) => {
                let healthy = match self.route.as_ref() {
                    Some(MtlRoute::Dp(route)) => Some(route.link_ok(io)),
                    _ => None,
                };
                match healthy {
                    Some(Ok(true)) => ServiceOutcome::Unchanged,
                    _ => self.retrain(io),
                }
            }
            MtlHpdKind::Redetect if owns => {
                let live = self.live;
                match self.withdraw(io) {
                    ServiceOutcome::Withdrawn { .. } => self.connect(io, port, live, alloc),
                    other => other,
                }
            }
            _ => ServiceOutcome::Unchanged,
        }
    }

    /// Lost link on a live DP route: local stop, then a fresh activation
    /// on the same probe and framebuffer.
    fn retrain<M: MmioWindow + ?Sized>(&mut self, io: &M) -> ServiceOutcome {
        let mut route = match self.route.take() {
            Some(MtlRoute::Dp(route)) => route,
            other => {
                self.route = other;
                return ServiceOutcome::Unchanged;
            }
        };
        let port = route.port();
        if let Err(error) = route.stop(io) {
            self.route = Some(MtlRoute::Dp(route));
            return ServiceOutcome::Retained {
                port,
                error: RouteError::Dp(error),
            };
        }
        let fb = route.fb;
        match activate(io, route.probe.clone(), fb, &self.display) {
            Ok(live) => {
                let (mode, pipe) = (live.probe.mode, live.pipe());
                self.route = Some(MtlRoute::Dp(live));
                ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Dp,
                    pipe,
                    mode,
                    fb,
                }
            }
            Err(ActivateError::Refused(_, error)) => {
                // The stopped route still owns TC/AUX; release it.
                match route.release(io) {
                    Ok(()) => ServiceOutcome::Refused {
                        port,
                        error: RouteError::Dp(error),
                    },
                    Err((route, e)) => {
                        self.route = Some(MtlRoute::Dp(route));
                        ServiceOutcome::Retained {
                            port,
                            error: RouteError::Dp(e),
                        }
                    }
                }
            }
            Err(ActivateError::Failed(failed, error)) => {
                self.route = Some(MtlRoute::Dp(failed));
                ServiceOutcome::Retained {
                    port,
                    error: RouteError::Dp(error),
                }
            }
        }
    }

    /// Reset/suspend: stop and release the route. Returns whether nothing
    /// external remains owned.
    pub fn teardown<M: MmioWindow + ?Sized>(&mut self, io: &M) -> bool {
        let done = matches!(
            self.withdraw(io),
            ServiceOutcome::Withdrawn { .. } | ServiceOutcome::Unchanged
        );
        self.publish();
        done
    }
}

/// The process-wide service's published route presence.
static PRESENCE: RoutePresence = RoutePresence::new();

static SERVICE: narf_lib::mutex::Mutex<MtlExternalService> =
    narf_lib::mutex::Mutex::new(MtlExternalService::with_presence(&PRESENCE));

/// DC-off bracket for every hardware touch of the MTL external route:
/// hotplug service, Type-C connect/disconnect, probe, activate, stop and
/// teardown all run inside it. One `DcUser::External` reference exits
/// DC5/DC6 before `f` and is released when `f` returns. A route that stays
/// live between passes keeps DC5/DC6 refused through
/// [`external_route_blocks_dc`], registered with the DC service.
fn with_dc_off<R>(f: impl FnOnce() -> R) -> Result<R, ExternalError> {
    pass_bracket(
        || crate::intel_gpu_dc_states::acquire(crate::intel_gpu_dc_states::DcUser::External),
        f,
    )
}

/// The bracket itself: `f` runs only after `acquire` returned its guard,
/// which is dropped after `f` returns. A refused acquisition runs nothing.
/// Never call it from interrupt context.
pub(crate) fn pass_bracket<G, E, R>(
    acquire: impl FnOnce() -> Result<G, E>,
    f: impl FnOnce() -> R,
) -> Result<R, ExternalError> {
    let _power = acquire().map_err(|_| ExternalError::DisplayPower)?;
    Ok(f())
}

/// Whether `service`'s route keeps display DC5/DC6 refused between passes:
/// any route that is not locally stopped (live or quarantined).
pub(crate) fn service_blocks_dc(service: &MtlExternalService) -> bool {
    service.route().is_some_and(|route| !route.stopped())
}

/// The process-wide predicate registered with the DC service: a live or
/// quarantined route, or a service pass in progress (the service is
/// contended), refuses DC5/DC6 re-entry. Unlike [`routes_stopped`] it
/// reads the service itself, so a pass lighting a route is covered before
/// it publishes. Never touches registers or blocks.
pub fn external_route_blocks_dc() -> bool {
    SERVICE
        .try_lock()
        .is_none_or(|service| service_blocks_dc(&service))
}

/// Install the board policy found at probe into the process-wide service
/// and the hotplug monitor (its legacy Type-C sources,
/// [`MtlPortPolicy::hpd_config`]). Refused (`false`, nothing changed) while
/// a service pass runs, a route is owned or the hotplug sources are
/// already established under another configuration.
pub fn install_mtl_port_policy(policy: MtlPortPolicy) -> bool {
    let Some(mut service) = SERVICE.try_lock() else {
        return false;
    };
    if service.route().is_some() && service.policy() != policy {
        return false;
    }
    if !crate::intel_gpu_xelpg_hpd::configure_hpd(policy.hpd_config()) {
        return false;
    }
    service.set_policy(policy)
}

/// The process-wide service's port policy (`None` while a pass runs).
pub fn installed_mtl_port_policy() -> Option<MtlPortPolicy> {
    SERVICE.try_lock().map(|service| service.policy())
}

/// Act on one hotplug event with the process-wide service, activating
/// next to `display` (the owned panel and the pipe-DMC sink). `None` when
/// a concurrent pass owns the service (never waits).
pub fn handle_mtl_event<M: MmioWindow + ?Sized>(
    io: &M,
    event: MtlHpdEvent,
    display: &MtlDisplay,
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let mut service = SERVICE.try_lock()?;
    service.set_display(*display);
    let port = event.pin.port();
    // A refused DC exit is protocol-neutral; it is reported through the
    // DP route error that carries ExternalError::DisplayPower.
    Some(
        with_dc_off(|| service.handle(io, event, alloc)).unwrap_or_else(|error| {
            ServiceOutcome::Refused {
                port,
                error: RouteError::Dp(error),
            }
        }),
    )
}

/// Poll the process-wide MTL hotplug owner once (inside the DC-off
/// bracket). Non-MTL generations return `None` before any access.
pub fn poll_mtl_event<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
) -> Option<MtlHpdEvent> {
    if generation != Generation::MeteorLake {
        return None;
    }
    with_dc_off(|| crate::intel_gpu_xelpg_hpd::poll_hpd_event(io, generation))
        .ok()
        .flatten()
}

/// Process-wide entry for the display runtime: poll the MTL hotplug owner
/// once and act on the event. Non-MTL generations return `None` before
/// any register access; a concurrent service pass returns `None` rather
/// than waiting.
pub fn service_mtl_external<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    display: &MtlDisplay,
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let event = poll_mtl_event(io, generation)?;
    handle_mtl_event(io, event, display, alloc)
}

/// Whether the process-wide MTL route is absent or locally stopped (its
/// hardware is off), as the last completed service pass published it
/// ([`RoutePresence`]). A live or quarantined route reports `false`; a
/// pass merely holding the service does not. Never touches registers or
/// takes a lock.
pub fn routes_stopped() -> bool {
    PRESENCE.stopped()
}

/// Whether the process-wide MTL route is live (scanning out), as the last
/// completed service pass published it. DC5/DC6 re-entry is gated by
/// [`external_route_blocks_dc`], which also refuses while a pass runs.
pub fn route_live() -> bool {
    PRESENCE.live()
}

/// Process-wide reset/suspend teardown: stop/release the route, then
/// withdraw the hotplug sources. `false` when anything stays retained.
pub fn teardown_mtl_external<M: MmioWindow + ?Sized>(io: &M, generation: Generation) -> bool {
    if generation != Generation::MeteorLake {
        return true;
    }
    let Some(mut service) = SERVICE.try_lock() else {
        return false;
    };
    with_dc_off(|| {
        let route = service.teardown(io);
        let hpd = crate::intel_gpu_xelpg_hpd::teardown_hpd(io, generation);
        route && hpd
    })
    .unwrap_or(false)
}

/// The pin an external port's hotplug arrives on.
pub const fn hpd_pin_for(port: XeLpgPort) -> Option<MtlHpdPin> {
    MtlHpdPin::from_port(port)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_external_tests.rs"]
pub mod tests;
