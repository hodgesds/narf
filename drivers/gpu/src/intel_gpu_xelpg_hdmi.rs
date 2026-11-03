//! Intel Xe-LPDP (Meteor Lake / Arrow Lake) HDMI TMDS output.
//!
//! The HDMI counterpart of [`crate::intel_gpu_xelpg_external`]: one
//! owned TMDS stream on pipe/transcoder A over DDI B (C10) or a Type-C
//! port in legacy mode (C20).
//!
//! ## Sources (Linux b90c984d)
//!
//! - `intel_cx0_phy.c`: `mtl_c10_hdmi_tables[]` and the TMDS entries of
//!   `mtl_c20_hdmi_tables[]` (generated verbatim into
//!   `intel_gpu_xelpg_hdmi_tables.rs`), `intel_c10pll_update_pll` (no
//!   HDMI SSC: PLL bytes 4..8 zeroed), `intel_c20_calc_vdr_params`
//!   (TMDS: width 0, no serdes bits, HDMI rate 0),
//!   `intel_program_port_clock_ctl` (maxPCLK, no SSC), the C10
//!   Wa_13013502646 powerdown toggle and `intel_cx0_phy_set_signal_levels`
//!   with the HDMI TX levels — all in [`crate::intel_gpu_xelpg`].
//! - `intel_ddi.c`: `intel_ddi_pre_enable_hdmi` (PLL, transcoder clock,
//!   infoframes), `intel_ddi_enable` (transcoder function, then the
//!   transcoder), `intel_ddi_enable_hdmi` (D2D, signal levels,
//!   PORT_BUF_CTL1 width, DDI_CTL_DE with the lane width — display 14
//!   fills it for TMDS), `intel_ddi_post_disable_hdmi` (infoframes off,
//!   `intel_ddi_buf_disable`, transcoder clock off, PLL off).
//! - `intel_hdmi.c::icl_encoder_to_ddc_pin` / `intel_gmbus.c`
//!   `gmbus_pins_mtp`: DDI B's DDC is GMBUS pin 2 ("dpb").
//!
//! ## Qualified profile and refusals
//!
//! TMDS clocks up to 340 MHz from the source tables, 8 bpc RGB, AVI
//! infoframe. Refused with typed errors: clocks above 340 MHz (they need
//! SCDC scrambling, not owned here), FRL and the FRL-ambiguous TMDS
//! clocks 300/600 MHz (`intel_hdmi_is_frl` would select FRL clocking),
//! clocks without a source table (the SNPS C10 and computed C20
//! algorithms are not implemented; the latter also needs the MTL-U /
//! ARL-S `tx_misc` platform fact), Type-C DP-alt (HDMI needs a legacy
//! port), Type-C DDC (GMBUS pins 9-12 are not representable by the shared
//! pin-pair encoder), a busy pipe A or an active DDI. Audio, deep color,
//! YCbCr and HDMI 2.1 FRL remain out of scope.
//!
//! The shared Gen12 GMBUS `PinPair` enum is used only as a raw pin
//! number here: `PinPair::DdiA` encodes 2, which on the MTP pin table is
//! `GMBUS_PIN_2_BXT` = DDI B.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gmbus::PinPair;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_modeset_xelpg::{
    acknowledged_cdclk, mtl_cdclk_for_pixel_clock, program_cdclk_floor, XeLpgModeset,
};
use crate::intel_gpu_pipes::Transcoder;
use crate::intel_gpu_xelpg::{
    disable_d2d, disable_port_pll_complete, enable_d2d, enable_port_pll_state, port_width,
    set_signal_levels_hdmi, wait_port_buf_active, wait_port_buf_idle, C10PllState, C20PllState,
    C20Vdr, Cx0Error, Cx0Phy, Cx0PllState, PhyKind, PllRequest, XeLpgPort, PORT_BUF_PHY_IDLE,
    PORT_BUF_REVERSAL, PORT_WIDTH_MASK,
};
use crate::intel_gpu_xelpg_external::{preflight_idle, request_well, wait_bit, ExternalError};
use crate::intel_gpu_xelpg_tc::{
    connect as tc_connect, connection_intact, disconnect as tc_disconnect, TcConnection, TcMode,
};

include!("intel_gpu_xelpg_hdmi_tables.rs");

/// Highest TMDS character clock this slice drives without scrambling.
pub const MAX_TMDS_KHZ_UNSCRAMBLED: u32 = 340_000;
/// Lowest HDMI TMDS clock (`intel_c20_get_hdmi_rate` range floor).
pub const MIN_TMDS_KHZ: u32 = 25_000;
/// `intel_hdmi_is_frl` clocks.
const FRL_CLOCKS_KHZ: [u32; 5] = [300_000, 600_000, 800_000, 1_000_000, 1_200_000];

const PWR_1: u32 = 0;
const PWR_2: u32 = 1;
const PWR_A: u32 = 5;
const PIPECONF_A: u64 = 0x7_0008;
const PIPE_FRMCOUNT_A: u64 = 0x7_0040;
const PLANE_CTL_1_A: u64 = 0x7_0180;
const PLANE_SURF_1_A: u64 = 0x7_019C;
const PLANE_SURFLIVE_1_A: u64 = 0x7_01AC;
const TRANS_DDI_FUNC_CTL_A: u64 = 0x6_0400;
const TRANS_CLK_SEL_A: u64 = 0x4_6140;
const TRANS_DDI_FUNC_ENABLE: u32 = 1 << 31;
const TRANS_DDI_PORT_AND_MODE: u32 = (0xF << 27) | (0x7 << 24);
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
const ENABLE: u32 = 1 << 31;
const STATE: u32 = 1 << 30;
/// HDMI TMDS always drives four lanes.
const HDMI_LANES: u8 = 4;

/// Typed HDMI refusal or failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdmiError {
    /// The clock has no source table on this PHY (or is below the TMDS
    /// floor).
    UnsupportedClock(u32),
    /// The clock is an FRL rate or FRL-ambiguous.
    FrlClock(u32),
    /// The clock needs TMDS scrambling (> 340 MHz).
    ScramblingRequired(u32),
    /// The port's DDC is not reachable through the shared GMBUS encoder.
    DdcUnavailable,
    /// DDC transfer failed.
    Ddc(crate::intel_gpu_hdmi::DdcError),
    /// EDID did not parse to a preferred mode.
    Edid,
    /// A Type-C port not in legacy mode cannot carry native HDMI.
    NotLegacy,
    /// Route-level refusal or failure (shared with DP).
    Route(ExternalError),
}

impl From<ExternalError> for HdmiError {
    fn from(e: ExternalError) -> Self {
        HdmiError::Route(e)
    }
}

impl From<crate::intel_gpu_xelpg_tc::TcError> for HdmiError {
    fn from(e: crate::intel_gpu_xelpg_tc::TcError) -> Self {
        HdmiError::Route(e.into())
    }
}

fn phy_err(e: Cx0Error) -> HdmiError {
    HdmiError::Route(ExternalError::Modeset(match e {
        Cx0Error::PhyError | Cx0Error::ProtocolMismatch => ModesetError::PhyBusFailure,
        Cx0Error::Timeout | Cx0Error::UnsupportedRate => ModesetError::PllLockTimeout,
    }))
}

/// Resolve the HDMI TMDS PLL request for `port` at `clock_khz`
/// (`intel_c10pll_calc_state` / `intel_c20pll_calc_state`, table path).
pub fn hdmi_pll_request(
    port: XeLpgPort,
    clock_khz: u32,
    legacy: bool,
) -> Result<PllRequest, HdmiError> {
    if FRL_CLOCKS_KHZ.contains(&clock_khz) {
        return Err(HdmiError::FrlClock(clock_khz));
    }
    if clock_khz < MIN_TMDS_KHZ {
        return Err(HdmiError::UnsupportedClock(clock_khz));
    }
    if clock_khz > MAX_TMDS_KHZ_UNSCRAMBLED {
        return Err(HdmiError::ScramblingRequired(clock_khz));
    }
    let state = match port.phy() {
        PhyKind::C10 => {
            let mut state = C10_HDMI_TABLES
                .iter()
                .find(|(clock, _)| *clock == clock_khz)
                .map(|(_, state)| *state)
                .ok_or(HdmiError::UnsupportedClock(clock_khz))?;
            // intel_c10pll_update_pll: HDMI has no SSC.
            for byte in &mut state.pll[4..9] {
                *byte = 0;
            }
            Cx0PllState::C10(state)
        }
        PhyKind::C20 => {
            let state = C20_HDMI_TMDS_TABLES
                .iter()
                .find(|(clock, _)| *clock == clock_khz)
                .map(|(_, state)| *state)
                .ok_or(HdmiError::UnsupportedClock(clock_khz))?;
            Cx0PllState::C20(state, C20Vdr::hdmi_tmds())
        }
    };
    Ok(PllRequest {
        state,
        port_clock_khz: clock_khz,
        lane_count: HDMI_LANES,
        dp_alt: false,
        ssc: false,
        hdmi: true,
        protocol_switch: legacy && port.phy() == PhyKind::C20,
    })
}

/// The DDC pin for an HDMI-capable MTL port (see module header).
pub const fn ddc_pin(port: XeLpgPort) -> Option<PinPair> {
    match port {
        XeLpgPort::B => Some(PinPair::DdiA),
        _ => None,
    }
}

/// Probe result owning the (legacy) Type-C connection.
#[derive(Clone, Debug)]
pub struct MtlHdmiProbe {
    /// The port.
    pub port: XeLpgPort,
    /// Legacy Type-C ownership (TC ports only).
    pub tc: Option<TcConnection>,
    /// Preferred mode.
    pub mode: Mode,
    /// The resolved PLL request for the mode's TMDS clock.
    pub pll: PllRequest,
    /// EDID bytes (`edid_len` valid).
    pub edid: [u8; crate::intel_gpu_hdmi::EDID_CAPACITY],
    /// Valid EDID length.
    pub edid_len: usize,
}

/// Probe an HDMI sink: Type-C legacy connect (TC only), DDC EDID,
/// preferred mode and its TMDS PLL request. Refusals precede MMIO where
/// possible; a Type-C connection is rolled back on failure.
pub fn probe_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<MtlHdmiProbe, HdmiError> {
    if generation != Generation::MeteorLake {
        return Err(ExternalError::UnsupportedGeneration.into());
    }
    if port == XeLpgPort::A {
        return Err(ExternalError::UnsupportedPort.into());
    }
    if port.tc_index().is_some() && !legacy_port {
        return Err(HdmiError::NotLegacy);
    }
    let pin = ddc_pin(port).ok_or(HdmiError::DdcUnavailable)?;
    let (edid, edid_len) = crate::intel_gpu_hdmi::read_edid(io, pin).map_err(HdmiError::Ddc)?;
    let mode =
        crate::intel_gpu_dp::mode_from_edid(&edid[..edid_len]).map_err(|_| HdmiError::Edid)?;
    let pll = hdmi_pll_request(port, mode.pixel_clock_khz, false)?;
    if !io.display_access_ok() {
        return Err(ExternalError::AccessLost.into());
    }
    Ok(MtlHdmiProbe {
        port,
        tc: None,
        mode,
        pll,
        edid,
        edid_len,
    })
}

/// Connect a declared legacy Type-C port for HDMI and resolve its PLL
/// for `mode` (the DDC for Type-C is refused by [`probe_hdmi`]; callers
/// with an out-of-band mode use this).
pub fn connect_legacy_tc<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    mode: Mode,
) -> Result<MtlHdmiProbe, HdmiError> {
    let pll = hdmi_pll_request(port, mode.pixel_clock_khz, true)?;
    let conn = tc_connect(io, port, true, HDMI_LANES)?;
    if conn.mode != TcMode::Legacy {
        let _ = tc_disconnect(io, &conn);
        return Err(HdmiError::NotLegacy);
    }
    Ok(MtlHdmiProbe {
        port,
        tc: Some(conn),
        mode,
        pll,
        edid: [0; crate::intel_gpu_hdmi::EDID_CAPACITY],
        edid_len: 0,
    })
}

/// Lifecycle of an HDMI route (same meaning as the DP route's).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdmiRouteState {
    /// Scanning out.
    Live,
    /// Locally stopped and observed.
    Stopped,
    /// A stop step was not observed; leases retained.
    Quarantined,
}

/// One owned HDMI route on pipe A.
#[derive(Clone, Debug)]
pub struct MtlHdmiRoute {
    /// The probe.
    pub probe: MtlHdmiProbe,
    /// The scanned-out framebuffer.
    pub fb: Framebuffer,
    state: HdmiRouteState,
}

fn wr<M: MmioWindow + ?Sized>(io: &M, off: u64, value: u32) -> Result<(), HdmiError> {
    io.write32(off, value);
    compiler_fence(Ordering::SeqCst);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(ExternalError::AccessLost.into())
    }
}

fn rd<M: MmioWindow + ?Sized>(io: &M, off: u64) -> Result<u32, HdmiError> {
    let v = io.read32(off);
    if v == u32::MAX || !io.display_access_ok() {
        Err(ExternalError::AccessLost.into())
    } else {
        Ok(v)
    }
}

/// Program and light the HDMI route in `intel_ddi_pre_enable_hdmi` →
/// `intel_ddi_enable` → `intel_ddi_enable_hdmi` order. Refusals return the
/// probe; programming failures return a `Stopped` or `Quarantined` route.
pub fn activate_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlHdmiProbe,
    fb: Framebuffer,
) -> Result<MtlHdmiRoute, (Result<MtlHdmiRoute, MtlHdmiProbe>, HdmiError)> {
    if let Err(e) = crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &probe.mode) {
        return Err((Err(probe), ExternalError::Modeset(e).into()));
    }
    if let Err(e) = preflight_idle(io, probe.port) {
        return Err((Err(probe), e.into()));
    }
    if let Some(conn) = probe.tc {
        if connection_intact(io, &conn) != Ok(true) {
            return Err((Err(probe), HdmiError::NotLegacy));
        }
    }
    let mut route = MtlHdmiRoute {
        probe,
        fb,
        state: HdmiRouteState::Stopped,
    };
    match program_hdmi(io, &route) {
        Ok(()) => {
            route.state = HdmiRouteState::Live;
            Ok(route)
        }
        Err(e) => {
            route.state = match stop_hdmi_local(io, &route) {
                Ok(()) => HdmiRouteState::Stopped,
                Err(_) => HdmiRouteState::Quarantined,
            };
            Err((Ok(route), e))
        }
    }
}

fn program_hdmi<M: MmioWindow + ?Sized>(io: &M, route: &MtlHdmiRoute) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    request_well(io, PWR_1)?;
    if port.tc_index().is_some() {
        request_well(io, PWR_2)?;
    }
    request_well(io, PWR_A)?;
    crate::intel_gpu_color::initialize_rgb_bypass(io)
        .map_err(|_| ExternalError::Modeset(ModesetError::ColorPipelineUnavailable))?;
    let current = acknowledged_cdclk(io).map_err(ExternalError::Modeset)?;
    let target = mtl_cdclk_for_pixel_clock(mode.pixel_clock_khz)
        .map_or(current, |entry| current.max(entry.cdclk_khz));
    crate::intel_gpu_display_resources::initialize(io, &mode, target)
        .map_err(|_| ExternalError::Modeset(ModesetError::DisplayResourceUnavailable))?;
    program_cdclk_floor(io, &mode).map_err(ExternalError::Modeset)?;
    // intel_ddi_pre_enable_hdmi: PLL, transcoder clock, infoframes.
    enable_port_pll_state(io, port, &route.probe.pll).map_err(phy_err)?;
    wr(io, TRANS_CLK_SEL_A, (port.phy_index() + 1) << 28)?;
    let mut ms = XeLpgModeset::new(io, port);
    ms.program_transcoder(&mode);
    ms.program_pipe(&mode);
    crate::intel_gpu_hdmi::write_avi_infoframe(
        io,
        Transcoder::A,
        &crate::intel_gpu_hdmi::pack_avi_infoframe(&mode),
    );
    ms.program_plane(&route.fb, &mode);
    // intel_ddi_enable: transcoder function, then the transcoder.
    let func =
        crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(port.func_ctl_index(), false, false);
    wr(io, TRANS_DDI_FUNC_CTL_A, func)?;
    let start = rd(io, PIPE_FRMCOUNT_A)?;
    let conf = rd(io, PIPECONF_A)?;
    wr(io, PIPECONF_A, conf | ENABLE)?;
    if !wait_bit(io, PIPECONF_A, ENABLE | STATE, true, 100_000_000) {
        return Err(ExternalError::Modeset(ModesetError::PipelineEnableUnavailable).into());
    }
    // intel_ddi_enable_hdmi (display 14): D2D, levels, PORT_BUF_CTL1
    // width, DDI_CTL_DE with the TMDS lane width, buffer active.
    enable_d2d(io, port).map_err(phy_err)?;
    set_signal_levels_hdmi(&Cx0Phy::new(io, port)).map_err(phy_err)?;
    let buf = rd(io, port.buf_ctl1())?;
    wr(
        io,
        port.buf_ctl1(),
        (buf & !(PORT_WIDTH_MASK | PORT_BUF_REVERSAL)) | port_width(HDMI_LANES),
    )?;
    wr(
        io,
        port.ddi_buf_ctl(),
        port_width(HDMI_LANES) | DDI_BUF_CTL_ENABLE,
    )?;
    wait_port_buf_active(io, port).map_err(phy_err)?;
    observe_hdmi(io, route, func, start)
}

fn observe_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlHdmiRoute,
    func: u32,
    start: u32,
) -> Result<(), HdmiError> {
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
    let dip = Transcoder::A.base() + crate::intel_gpu_hdmi::VIDEO_DIP_CTL_OFFSET;
    let mut refused = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let frame = io.read32(PIPE_FRMCOUNT_A);
            let surf = io.read32(PLANE_SURF_1_A);
            let live = io.read32(PLANE_SURFLIVE_1_A);
            let route_now = io.read32(TRANS_DDI_FUNC_CTL_A);
            let clock = io.read32(TRANS_CLK_SEL_A);
            let infoframes = io.read32(dip);
            let buf = io.read32(port.buf_ctl1());
            let ddi = io.read32(port.ddi_buf_ctl());
            refused = !io.display_access_ok() || frame == u32::MAX || ddi == u32::MAX;
            refused
                || (frame != start
                    && surf == plane.plane_surf
                    && live == surf
                    && route_now == func
                    && clock == (port.phy_index() + 1) << 28
                    && infoframes & crate::intel_gpu_hdmi::VIDEO_DIP_ENABLE_AVI != 0
                    && buf & PORT_BUF_PHY_IDLE == 0
                    && ddi & DDI_BUF_CTL_ENABLE != 0)
        },
        narf_time::Deadline::after_ns(100_000_000),
    );
    if !done || refused {
        return Err(ExternalError::Modeset(ModesetError::PipelineEnableUnavailable).into());
    }
    Ok(())
}

/// Local stop: plane, transcoder, function deselect, then
/// `intel_ddi_post_disable_hdmi` (infoframes off, DDI_CTL_DE off + PHY
/// idle, D2D off, transcoder clock off, `intel_cx0pll_disable`).
fn stop_hdmi_local<M: MmioWindow + ?Sized>(io: &M, route: &MtlHdmiRoute) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let stop_failed: HdmiError =
        ExternalError::Modeset(ModesetError::PipelineStopUnavailable).into();
    let ctl = rd(io, PLANE_CTL_1_A)?;
    wr(io, PLANE_CTL_1_A, ctl & !ENABLE)?;
    let surf = rd(io, PLANE_SURF_1_A)?;
    wr(io, PLANE_SURF_1_A, surf)?;
    let conf = rd(io, PIPECONF_A)?;
    wr(io, PIPECONF_A, conf & !ENABLE)?;
    if !wait_bit(io, PIPECONF_A, ENABLE | STATE, false, 100_000_000) {
        return Err(stop_failed);
    }
    let func = rd(io, TRANS_DDI_FUNC_CTL_A)?;
    wr(
        io,
        TRANS_DDI_FUNC_CTL_A,
        func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE),
    )?;
    crate::intel_gpu_hdmi::disable_infoframes(io, Transcoder::A);
    let ddi = rd(io, port.ddi_buf_ctl())?;
    wr(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
    wait_port_buf_idle(io, port).map_err(|_| stop_failed)?;
    disable_d2d(io, port).map_err(|_| stop_failed)?;
    wr(io, TRANS_CLK_SEL_A, 0)?;
    disable_port_pll_complete(io, port).map_err(|_| stop_failed)?;
    let conf = rd(io, PIPECONF_A)?;
    let ddi = rd(io, port.ddi_buf_ctl())?;
    let buf = rd(io, port.buf_ctl1())?;
    let clock = rd(io, port.port_clock_ctl())?;
    if conf & (ENABLE | STATE) != 0
        || ddi & DDI_BUF_CTL_ENABLE != 0
        || buf & PORT_BUF_PHY_IDLE == 0
        || clock & 0xCC00_0000 != 0
    {
        return Err(stop_failed);
    }
    Ok(())
}

impl MtlHdmiRoute {
    /// Lifecycle state.
    pub fn state(&self) -> HdmiRouteState {
        self.state
    }

    /// Locally stop; a failed stop quarantines the route.
    pub fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), HdmiError> {
        match self.state {
            HdmiRouteState::Stopped => Ok(()),
            HdmiRouteState::Quarantined => Err(ExternalError::Quarantined.into()),
            HdmiRouteState::Live => match stop_hdmi_local(io, self) {
                Ok(()) => {
                    self.state = HdmiRouteState::Stopped;
                    Ok(())
                }
                Err(e) => {
                    self.state = HdmiRouteState::Quarantined;
                    Err(e)
                }
            },
        }
    }

    /// Release the Type-C connection of a stopped route.
    pub fn release<M: MmioWindow + ?Sized>(self, io: &M) -> Result<(), (MtlHdmiRoute, HdmiError)> {
        if self.state != HdmiRouteState::Stopped {
            return Err((self, ExternalError::Quarantined.into()));
        }
        match self.probe.tc {
            Some(conn) => tc_disconnect(io, &conn).map_err(|e| (self, e.into())),
            None => Ok(()),
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_hdmi_tests.rs"]
pub mod tests;
