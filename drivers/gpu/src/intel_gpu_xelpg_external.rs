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
//! 2. [`activate`] — `mtl_ddi_pre_enable_dp` order: power wells, RGB
//!    bypass, display resources + CDCLK floor, Cx0 PLL enable
//!    (`intel_cx0pll_enable`), `TRANS_CLK_SEL`, transcoder timings and
//!    `TRANS_DDI_FUNC_CTL` (configured, not yet enabled), primary plane,
//!    `mtl_ddi_prepare_link_retrain` (DP_TP_CTL TPS1, D2D enable, signal
//!    levels, PORT_BUF_CTL1 width, DDI_CTL_DE enable + PHY_IDLE clear),
//!    shared DPCD link training, trained levels and M/N, DP_TP_CTL normal,
//!    `TRANS_DDI_FUNC_CTL` enable, transcoder enable and a fresh-frame
//!    primary witness. A training fallback runs the local stop and one
//!    full retry at the trained configuration (i915's modeset retry);
//!    a second mismatch refuses.
//! 3. [`MtlExternalRoute::stop`] — `intel_ddi_post_disable_dp` order:
//!    plane off, transcoder off, function deselect, sink D3 (best effort),
//!    DDI_CTL_DE off + PHY_IDLE, D2D off, DP_TP_CTL off, TRANS_CLK_SEL
//!    off, `intel_cx0pll_disable`, TBT IO deselect.
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
//! Pipe A / transcoder A only, and only while pipe A, its primary plane,
//! transcoder A's DDI function and the target DDI are all off (an
//! internal panel lit on pipe A refuses `PipeBusy`; concurrent multi-pipe
//! needs DBUF/watermark repartition this slice does not own). 8 bpc RGB,
//! DP 1.4 rates RBR–HBR3 with the C10/C20 tables in
//! [`crate::intel_gpu_xelpg`]; a stream whose demand exceeds the
//! negotiated ceiling refuses (no DSC). UHBR (128b/132b, C20 MPLLA),
//! MST, FEC/DSC, TBT-alt tunnels, audio and lane reversal are refused or
//! unadvertised (HDMI is the separate route described below). Per-iteration source pattern/level updates
//! inside the shared training loop keep the existing MTL simplification:
//! TPS1 and zero levels are staged before training, the trained levels
//! after.
//!
//! Sources (Linux b90c984d): `intel_ddi.c` (`mtl_ddi_pre_enable_dp`,
//! `mtl_ddi_prepare_link_retrain`, `intel_ddi_init_dp_buf_reg`,
//! `intel_ddi_buf_enable`/`_disable`, `intel_ddi_post_disable_dp`,
//! `intel_ddi_enable_transcoder_clock`, `intel_ddi_disable_transcoder_func`),
//! `intel_cx0_phy.c`, `intel_tc.c`, `intel_display_power_map.c`
//! (`xelpdp_pwdoms_pw_2` carries the TC1–4 DDI lanes).

use core::sync::atomic::{compiler_fence, Ordering};

use crate::dp_aux::AuxChannel as _;
use crate::dp_edid::{read_full_edid, EdidReadError};
use crate::dp_link_training::{
    negotiate, read_caps, stream_demand_kbps, train_link, DpcdCaps, LinkError,
    LinkRate as TrainRate, NegotiatedLink, SourceCaps, TrainedLink,
};
use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_modeset_xelpg::{
    acknowledged_cdclk, mtl_cdclk_for_pixel_clock, program_cdclk_floor, XeLpgModeset,
};
use crate::intel_gpu_xelpg::{
    disable_d2d, disable_port_pll_complete, dp_pll_request, enable_d2d, enable_port_pll_state,
    program_port_buf_ctl, set_signal_levels, wait_port_buf_active, wait_port_buf_idle, Cx0Error,
    Cx0Phy, XeLpgPort, PORT_BUF_IO_SELECT_TBT, PORT_BUF_PHY_IDLE,
};
use crate::intel_gpu_xelpg_hdmi::{
    activate_hdmi, probe_hdmi, release_hdmi_probe, HdmiError, HdmiRouteState, MtlHdmiRoute,
};
use crate::intel_gpu_xelpg_hpd::{LiveMode, MtlHpdConfig, MtlHpdEvent, MtlHpdKind, MtlHpdPin};
use crate::intel_gpu_xelpg_tc::{
    aux_power_disable, aux_power_enable, connect as tc_connect, connection_intact,
    disconnect as tc_disconnect, TcConnection, TcError, TcMode,
};

/// Largest EDID retained (base + three extensions).
pub const EDID_CAPACITY: usize = 512;

// Registers this route owns on pipe/transcoder A (`intel_display_regs.h`).
const PWR_WELL_CTL2: u64 = 0x4_5404;
const PW_1_IDX: u32 = 0;
/// `ICL_PW_CTL_IDX_PW_2` — on Xe-LPDP it powers the TC1–4 DDI lanes.
const PW_2_IDX: u32 = 1;
/// `XELPD_PW_CTL_IDX_PW_A`.
const PW_A_IDX: u32 = 5;
const PIPECONF_A: u64 = 0x7_0008;
const PIPE_FRMCOUNT_A: u64 = 0x7_0040;
const PLANE_CTL_1_A: u64 = 0x7_0180;
const PLANE_SURF_1_A: u64 = 0x7_019C;
const PLANE_SURFLIVE_1_A: u64 = 0x7_01AC;
const TRANS_DDI_FUNC_CTL_A: u64 = 0x6_0400;
const TRANS_CLK_SEL_A: u64 = 0x4_6140;
/// `TGL_DP_TP_CTL(A)`.
const DP_TP_CTL_A: u64 = 0x6_0540;
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
/// `DDI_PORT_WIDTH(lanes)` (bits 3:1, 3 lanes encode as 4).
const fn ddi_port_width(lanes: u8) -> u32 {
    let w = if lanes == 3 { 4 } else { lanes as u32 - 1 };
    w << 1
}

/// Typed refusal or failure of the MTL external route.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExternalError {
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
    /// Pipe A, its primary plane or transcoder A is already active.
    PipeBusy,
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
    /// Complete EDID bytes (`edid_len` valid).
    pub edid: [u8; EDID_CAPACITY],
    /// Valid EDID length.
    pub edid_len: usize,
}

impl MtlSinkProbe {
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
pub fn probe_sink<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    if generation != Generation::MeteorLake {
        return Err(ExternalError::UnsupportedGeneration);
    }
    if port == XeLpgPort::A {
        return Err(ExternalError::UnsupportedPort);
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
    let mut aux = IntelAux::xelpdp(io, port.aux_base(), false);
    let caps = read_caps(&mut aux).map_err(|e| rollback(ExternalError::Link(e)))?;
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
    let negotiated = negotiate(&source, &caps, stream_demand_kbps(mode.pixel_clock_khz, 24));
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
        port,
        tc,
        caps,
        mode,
        negotiated,
        edid,
        edid_len,
    })
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

/// One owned external SST route on pipe A.
#[derive(Clone, Debug)]
pub struct MtlExternalRoute {
    /// The probe (Type-C/AUX ownership, caps, EDID, mode).
    pub probe: MtlSinkProbe,
    /// The scanned-out framebuffer (owned by the caller's allocation).
    pub fb: Framebuffer,
    /// The trained link.
    pub trained: TrainedLink,
    state: RouteState,
}

/// Why [`activate`] did not produce a live route.
#[derive(Debug)]
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

/// No-write preflight: pipe A, its primary plane, transcoder A's DDI
/// function and the target DDI/PLL must all be off.
pub(crate) fn preflight_idle<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
) -> Result<(), ExternalError> {
    if !io.display_access_ok() {
        return Err(ExternalError::AccessLost);
    }
    let conf = read(io, PIPECONF_A)?;
    let plane = read(io, PLANE_CTL_1_A)?;
    let func = read(io, TRANS_DDI_FUNC_CTL_A)?;
    if conf & (ENABLE | STATE) != 0 || plane & ENABLE != 0 || func & TRANS_DDI_FUNC_ENABLE != 0 {
        return Err(ExternalError::PipeBusy);
    }
    let ddi = read(io, port.ddi_buf_ctl())?;
    let clock = read(io, port.port_clock_ctl())?;
    if ddi & DDI_BUF_CTL_ENABLE != 0 || clock & 0xCC00_0000 != 0 {
        return Err(ExternalError::PortBusy);
    }
    Ok(())
}

/// Phase 2: program and light the route. See the module header for the
/// sequence. The probe must come from [`probe_sink`] on this window.
// Refusal hands the owned probe/route back inline: it must not allocate.
#[allow(clippy::result_large_err)]
pub fn activate<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlSinkProbe,
    fb: Framebuffer,
) -> Result<MtlExternalRoute, ActivateError> {
    if let Err(e) = crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &probe.mode) {
        return Err(ActivateError::Refused(probe, e.into()));
    }
    if let Err(e) = preflight_idle(io, probe.port) {
        return Err(ActivateError::Refused(probe, e));
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
    let mut route = MtlExternalRoute {
        probe,
        fb,
        trained: TrainedLink {
            rate: negotiated.rate,
            lanes: negotiated.lanes,
            vswing_pe: Default::default(),
        },
        state: RouteState::Stopped,
    };
    match program(io, &mut route, negotiated.rate, negotiated.lanes, true) {
        Ok(()) => {
            route.state = RouteState::Live;
            Ok(route)
        }
        Err(e) => {
            route.state = match stop_local(io, &route) {
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
    rate: TrainRate,
    lanes: u8,
    allow_fallback: bool,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    let pll_rate = crate::intel_gpu_modeset::to_pll_rate(rate);
    // 1. Power wells: PW_1, PW_2 (TC DDI lanes), PW_A (pipe A).
    request_well(io, PW_1_IDX)?;
    if port.tc_index().is_some() {
        request_well(io, PW_2_IDX)?;
    }
    request_well(io, PW_A_IDX)?;
    // Pipe off: own the color pipeline instead of inheriting it.
    crate::intel_gpu_color::initialize_rgb_bypass(io)
        .map_err(|_| ExternalError::Modeset(ModesetError::ColorPipelineUnavailable))?;
    // Pipe A resources and the CDCLK floor (shared MTL transaction).
    let current = acknowledged_cdclk(io)?;
    let target = mtl_cdclk_for_pixel_clock(mode.pixel_clock_khz)
        .map_or(current, |entry| current.max(entry.cdclk_khz));
    crate::intel_gpu_display_resources::initialize(io, &mode, target)
        .map_err(|_| ExternalError::Modeset(ModesetError::DisplayResourceUnavailable))?;
    program_cdclk_floor(io, &mode)?;
    // 5. Port PLL (intel_cx0pll_enable) for the planned width.
    // A legacy-mode C20 port also clears the MPLLB CAL_DONE banks first
    // (intel_c20_protocol_switch_valid).
    let request = dp_pll_request(
        port,
        pll_rate,
        lanes,
        route.probe.dp_alt(),
        route.probe.legacy(),
    )
    .map_err(phy_err)?;
    enable_port_pll_state(io, port, &request).map_err(phy_err)?;
    // 6.a TRANS_CLK_SEL = TGL_TRANS_CLK_SEL_PORT(phy).
    write(io, TRANS_CLK_SEL_A, (port.phy_index() + 1) << 28)?;
    // Timings, then 6.c TRANS_DDI_FUNC_CTL configured without ENABLE.
    let mut ms = XeLpgModeset::new(io, port);
    ms.program_transcoder(&mode);
    ms.program_pipe(&mode);
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        port.func_ctl_index(),
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        lanes,
    );
    write(io, TRANS_DDI_FUNC_CTL_A, func & !TRANS_DDI_FUNC_ENABLE)?;
    ms.program_plane(&route.fb, &mode);
    // mtl_ddi_prepare_link_retrain: 6.d DP_TP_CTL TPS1 (SST), 6.f D2D,
    // 6.g levels, 6.h PORT_BUF_CTL1, 6.i DDI_CTL_DE + buffer active.
    let enhanced = if route.probe.caps.enhanced_framing {
        DP_TP_CTL_ENHANCED_FRAME
    } else {
        0
    };
    write(
        io,
        DP_TP_CTL_A,
        DP_TP_CTL_ENABLE | DP_TP_CTL_LINK_TRAIN_PAT1 | enhanced,
    )?;
    enable_d2d(io, port).map_err(phy_err)?;
    let phy = Cx0Phy::new(io, port);
    set_signal_levels(&phy, pll_rate, lanes, &[(0, 0); 4]).map_err(phy_err)?;
    program_port_buf_ctl(io, port, lanes);
    write(
        io,
        port.ddi_buf_ctl(),
        ddi_port_width(lanes) | DDI_BUF_CTL_ENABLE,
    )?;
    wait_port_buf_active(io, port).map_err(phy_err)?;
    // 6.k DisplayPort training over the owned AUX channel.
    let mut aux = IntelAux::xelpdp(io, port.aux_base(), false);
    let trained = train_link(&mut aux, rate, lanes, |us| {
        let _ = narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_ns(us as u64 * 1_000),
        );
    })
    .map_err(ExternalError::Link)?;
    if trained.rate != rate || trained.lanes != lanes {
        if !allow_fallback {
            return Err(ExternalError::TrainingMismatch);
        }
        // The fallback link must still carry the stream (no DSC).
        let demand_kbps = stream_demand_kbps(mode.pixel_clock_khz, 24);
        let payload_kbps = trained.rate.payload_kbps(trained.lanes);
        if payload_kbps < demand_kbps {
            return Err(ExternalError::OverBudget {
                demand_kbps,
                payload_kbps,
            });
        }
        // Modeset retry at the trained configuration.
        stop_local(io, route)?;
        return program(io, route, trained.rate, trained.lanes, false);
    }
    let mut levels = [(0u8, 0u8); 4];
    for (i, lane) in trained.vswing_pe.lanes.iter().enumerate() {
        levels[i] = (lane.swing, lane.pre_emph);
    }
    set_signal_levels(&phy, pll_rate, lanes, &levels).map_err(phy_err)?;
    ms.program_mn(&mode, pll_rate, lanes);
    // 6.n DP_TP_CTL normal, then function and transcoder enable.
    let tp = read(io, DP_TP_CTL_A)?;
    write(
        io,
        DP_TP_CTL_A,
        (tp & !DP_TP_CTL_LINK_TRAIN_MASK) | DP_TP_CTL_LINK_TRAIN_NORMAL,
    )?;
    write(io, TRANS_DDI_FUNC_CTL_A, func)?;
    let start = read(io, PIPE_FRMCOUNT_A)?;
    let conf = read(io, PIPECONF_A)?;
    write(io, PIPECONF_A, conf | ENABLE)?;
    if !wait_bit(io, PIPECONF_A, ENABLE | STATE, true, 100_000_000) {
        return Err(ExternalError::Modeset(
            ModesetError::PipelineEnableUnavailable,
        ));
    }
    observe_live(io, route, func, start)?;
    route.trained = trained;
    Ok(())
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
            let frame = io.read32(PIPE_FRMCOUNT_A);
            let surf = io.read32(PLANE_SURF_1_A);
            let live = io.read32(PLANE_SURFLIVE_1_A);
            let route_now = io.read32(TRANS_DDI_FUNC_CTL_A);
            let clock = io.read32(TRANS_CLK_SEL_A);
            let tp = io.read32(DP_TP_CTL_A);
            let buf = io.read32(port.buf_ctl1());
            let ddi = io.read32(port.ddi_buf_ctl());
            refused = !io.display_access_ok() || frame == u32::MAX || ddi == u32::MAX;
            refused
                || (frame != start
                    && surf == plane.plane_surf
                    && live == surf
                    && route_now == func
                    && clock == (port.phy_index() + 1) << 28
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

/// Local stop in `intel_ddi_post_disable_dp` order. Every step is
/// observed; any failure leaves the remaining state for quarantine.
fn stop_local<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let stop_failed = ExternalError::Modeset(ModesetError::PipelineStopUnavailable);
    // Plane off with a SURF write to latch it.
    let ctl = read(io, PLANE_CTL_1_A)?;
    write(io, PLANE_CTL_1_A, ctl & !ENABLE)?;
    let surf = read(io, PLANE_SURF_1_A)?;
    write(io, PLANE_SURF_1_A, surf)?;
    // Transcoder/pipe off.
    let conf = read(io, PIPECONF_A)?;
    write(io, PIPECONF_A, conf & !ENABLE)?;
    if !wait_bit(io, PIPECONF_A, ENABLE | STATE, false, 100_000_000) {
        return Err(stop_failed);
    }
    // intel_ddi_disable_transcoder_func (TGL+ SST): enable, port, mode.
    let func = read(io, TRANS_DDI_FUNC_CTL_A)?;
    write(
        io,
        TRANS_DDI_FUNC_CTL_A,
        func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE),
    )?;
    // Sink to D3 before the port goes down (a NACK never replaces the
    // local idle proof).
    if route.probe.caps.dpcd_rev >= 0x11 {
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), false);
        let _ = aux.dpcd_write(DPCD_SET_POWER, &[DP_SET_POWER_D3]);
    }
    // intel_ddi_buf_disable (display 14): DDI_CTL_DE off, PHY idle, D2D
    // off, DP_TP_CTL off.
    let ddi = read(io, port.ddi_buf_ctl())?;
    write(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
    wait_port_buf_idle(io, port).map_err(|_| stop_failed)?;
    disable_d2d(io, port).map_err(|_| stop_failed)?;
    let tp = read(io, DP_TP_CTL_A)?;
    write(io, DP_TP_CTL_A, tp & !DP_TP_CTL_ENABLE)?;
    // TRANS_CLK_SEL: no clock to the transcoder.
    write(io, TRANS_CLK_SEL_A, 0)?;
    // intel_cx0pll_disable, then deselect Thunderbolt IO.
    disable_port_pll_complete(io, port).map_err(|_| stop_failed)?;
    let buf = read(io, port.buf_ctl1())?;
    write(io, port.buf_ctl1(), buf & !PORT_BUF_IO_SELECT_TBT)?;
    // Final observation of every stopped resource.
    let conf = read(io, PIPECONF_A)?;
    let ddi = read(io, port.ddi_buf_ctl())?;
    let buf = read(io, port.buf_ctl1())?;
    let clock = read(io, port.port_clock_ctl())?;
    if conf & (ENABLE | STATE) != 0
        || ddi & DDI_BUF_CTL_ENABLE != 0
        || buf & PORT_BUF_PHY_IDLE == 0
        || clock & 0xCC00_0000 != 0
    {
        return Err(stop_failed);
    }
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
        let mut aux = IntelAux::xelpdp(io, self.probe.port.aux_base(), false);
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
/// (`DEVICE_TYPE_DISPLAYPORT_OUTPUT`), `intel_bios_encoder_supports_hdmi`
/// (`DEVICE_TYPE_TMDS_DVI_SIGNALING` without `DEVICE_TYPE_NOT_HDMI_OUTPUT`)
/// and, for Type-C, `intel_ddi_init`'s legacy test (neither
/// `dp_usb_type_c` nor `tbt`). No VBT parser exists in this tree, so the
/// declaration is supplied instead of parsed; see [`MtlPortPolicy::NO_VBT`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlPortDecl {
    /// The port carries DisplayPort.
    pub dp: bool,
    /// The port carries native HDMI (TMDS).
    pub hdmi: bool,
    /// Type-C only: the PHY is wired to a fixed DP/HDMI connector.
    pub legacy: bool,
}

impl MtlPortDecl {
    /// No output on this port.
    pub const NONE: Self = Self {
        dp: false,
        hdmi: false,
        legacy: false,
    };
    /// `init_vbt_missing_defaults` for a non-TC port other than A and E:
    /// `DEVICE_TYPE_TMDS_DVI_SIGNALING | DEVICE_TYPE_DISPLAYPORT_OUTPUT`.
    pub const COMBO_DP_HDMI: Self = Self {
        dp: true,
        hdmi: true,
        legacy: false,
    };
    /// A USB-C connector: DP-alt only.
    pub const USB_C: Self = Self {
        dp: true,
        hdmi: false,
        legacy: false,
    };
    /// A Type-C PHY wired to a native HDMI connector.
    pub const LEGACY_HDMI: Self = Self {
        dp: false,
        hdmi: true,
        legacy: true,
    };

    /// `intel_ddi_init`: a Type-C port declared non-legacy but with HDMI
    /// and without DP is treated as legacy.
    pub const fn legacy_effective(self) -> bool {
        self.legacy || (self.hdmi && !self.dp)
    }
}

/// Declarations for DDI B and TC1..TC4.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlPortPolicy {
    /// DDI B (C10 combo PHY).
    pub ddi_b: MtlPortDecl,
    /// TC1..TC4.
    pub tc: [MtlPortDecl; 4],
}

impl MtlPortPolicy {
    /// The production policy without a VBT. DDI B follows Linux's
    /// `init_vbt_missing_defaults` (DP + HDMI). Linux creates no Type-C
    /// encoder without a VBT ("VBT has the TypeC mode ... we don't want to
    /// detect it"); this tree keeps the USB-C DP-alt route it already
    /// owns and declares no legacy or HDMI Type-C port, so the policy
    /// matches [`MtlHpdConfig::TYPE_C`].
    pub const NO_VBT: Self = Self {
        ddi_b: MtlPortDecl::COMBO_DP_HDMI,
        tc: [MtlPortDecl::USB_C; 4],
    };

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
/// TBT-alt never carry TMDS, and TBT-alt carries nothing owned here.
pub const fn route_plan(port: XeLpgPort, decl: MtlPortDecl, live: LiveMode) -> RoutePlan {
    let type_c = port.tc_index().is_some();
    let mode_ok = match live {
        LiveMode::Native => !type_c && !matches!(port, XeLpgPort::A),
        LiveMode::Legacy => type_c && decl.legacy_effective(),
        LiveMode::DpAlt => type_c,
        LiveMode::TbtAlt => false,
    };
    if !mode_ok {
        return RoutePlan::Refuse;
    }
    let dp = decl.dp;
    let hdmi = decl.hdmi && !matches!(live, LiveMode::DpAlt);
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
#[derive(Clone, Debug)]
pub enum MtlRoute {
    /// DisplayPort SST.
    Dp(MtlExternalRoute),
    /// HDMI TMDS.
    Hdmi(MtlHdmiRoute),
}

impl MtlRoute {
    /// The external port.
    pub fn port(&self) -> XeLpgPort {
        match self {
            MtlRoute::Dp(r) => r.port(),
            MtlRoute::Hdmi(r) => r.port(),
        }
    }

    /// The protocol.
    pub fn protocol(&self) -> MtlProtocol {
        match self {
            MtlRoute::Dp(_) => MtlProtocol::Dp,
            MtlRoute::Hdmi(_) => MtlProtocol::Hdmi,
        }
    }

    /// Scanning out.
    pub fn live(&self) -> bool {
        match self {
            MtlRoute::Dp(r) => r.state() == RouteState::Live,
            MtlRoute::Hdmi(r) => r.state() == HdmiRouteState::Live,
        }
    }

    /// Locally stopped (its hardware is off).
    pub fn stopped(&self) -> bool {
        match self {
            MtlRoute::Dp(r) => r.state() == RouteState::Stopped,
            MtlRoute::Hdmi(r) => r.state() == HdmiRouteState::Stopped,
        }
    }

    fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), RouteError> {
        match self {
            MtlRoute::Dp(r) => r.stop(io).map_err(RouteError::Dp),
            MtlRoute::Hdmi(r) => r.stop(io).map_err(RouteError::Hdmi),
        }
    }

    fn release<M: MmioWindow + ?Sized>(self, io: &M) -> Result<(), (MtlRoute, RouteError)> {
        match self {
            MtlRoute::Dp(r) => r
                .release(io)
                .map_err(|(r, e)| (MtlRoute::Dp(r), RouteError::Dp(e))),
            MtlRoute::Hdmi(r) => r
                .release(io)
                .map_err(|(r, e)| (MtlRoute::Hdmi(r), RouteError::Hdmi(e))),
        }
    }
}

/// What one service pass did.
#[derive(Clone, Debug)]
pub enum ServiceOutcome {
    /// A new route is live; the caller publishes `fb` at `mode`.
    Activated {
        /// The external port.
        port: XeLpgPort,
        /// The protocol driving it.
        protocol: MtlProtocol,
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

/// Owner of at most one MTL external route, driven by hotplug events.
#[derive(Debug)]
pub struct MtlExternalService {
    route: Option<MtlRoute>,
    /// The live mode the retained route was connected in (for `Redetect`).
    live: LiveMode,
    policy: MtlPortPolicy,
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
        }
    }

    /// The port policy.
    pub fn policy(&self) -> MtlPortPolicy {
        self.policy
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
                    LiveMode::TbtAlt => ExternalError::Tc(TcError::TbtAltUnsupported),
                    _ => ExternalError::UnsupportedPort,
                }),
            },
            RoutePlan::Hdmi => self.connect_hdmi(io, port, legacy, alloc),
            RoutePlan::Dp | RoutePlan::DpThenHdmi => {
                match probe_sink(io, Generation::MeteorLake, port, legacy) {
                    Ok(probe) => self.connect_dp(io, probe, alloc),
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
        match activate(io, probe, fb) {
            Ok(route) => {
                let outcome = ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Dp,
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
        let probe = match probe_hdmi(io, Generation::MeteorLake, port, legacy) {
            Ok(probe) => probe,
            Err(e) => {
                return ServiceOutcome::Refused {
                    port,
                    error: RouteError::Hdmi(e),
                }
            }
        };
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
        match activate_hdmi(io, probe, fb) {
            Ok(route) => {
                let outcome = ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Hdmi,
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
    /// for a newly probed mode (the caller owns its GGTT lifetime).
    pub fn handle<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        event: MtlHpdEvent,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let port = event.pin.port();
        let owned = self.route.as_ref().map(|r| (r.port(), r.protocol()));
        let owns = owned.map(|(p, _)| p) == Some(port);
        match event.kind {
            MtlHpdKind::Connected(LiveMode::TbtAlt) => ServiceOutcome::Refused {
                port,
                error: RouteError::Dp(ExternalError::Tc(TcError::TbtAltUnsupported)),
            },
            MtlHpdKind::Connected(live) if self.route.is_none() => {
                self.connect(io, port, live, alloc)
            }
            MtlHpdKind::Connected(_) => ServiceOutcome::Unchanged,
            MtlHpdKind::Disconnected if owns => self.withdraw(io),
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
        match activate(io, route.probe.clone(), fb) {
            Ok(live) => {
                let mode = live.probe.mode;
                self.route = Some(MtlRoute::Dp(live));
                ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Dp,
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
        matches!(
            self.withdraw(io),
            ServiceOutcome::Withdrawn { .. } | ServiceOutcome::Unchanged
        )
    }
}

static SERVICE: narf_lib::mutex::Mutex<MtlExternalService> =
    narf_lib::mutex::Mutex::new(MtlExternalService::new());

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

/// The process-wide predicate registered with the DC service
/// (`route_live() || !routes_stopped()`): a live or quarantined route, or a
/// service pass in progress, refuses DC5/DC6 re-entry. Never touches
/// registers or blocks.
pub fn external_route_blocks_dc() -> bool {
    SERVICE
        .try_lock()
        .is_none_or(|service| service_blocks_dc(&service))
}

/// Act on one hotplug event with the process-wide service. `None` when a
/// concurrent pass owns the service (never waits).
pub fn handle_mtl_event<M: MmioWindow + ?Sized>(
    io: &M,
    event: MtlHpdEvent,
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let mut service = SERVICE.try_lock()?;
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
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let event = poll_mtl_event(io, generation)?;
    handle_mtl_event(io, event, alloc)
}

/// Whether the process-wide MTL route is absent or locally stopped (its
/// hardware is off). A live or quarantined route, or a service pass in
/// progress, reports `false`. Never touches registers.
pub fn routes_stopped() -> bool {
    SERVICE
        .try_lock()
        .is_some_and(|service| service.route().is_none_or(MtlRoute::stopped))
}

/// Whether the process-wide MTL route is currently live (scanning out).
/// The DC-state owner must refuse DC entry while this is true.
pub fn route_live() -> bool {
    SERVICE
        .try_lock()
        .is_none_or(|service| service.route().is_some_and(MtlRoute::live))
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
