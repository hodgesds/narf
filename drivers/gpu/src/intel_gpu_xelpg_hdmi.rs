//! Intel Xe-LPDP (Meteor Lake / Arrow Lake) HDMI TMDS output.
//!
//! The HDMI counterpart of [`crate::intel_gpu_xelpg_external`]: one
//! owned TMDS stream on a Pipe B–D and its transcoder over DDI B (C10) or
//! a Type-C port in legacy mode (C20), next to the lit internal panel. The
//! pipe side (power wells, resource transaction, pipe DMC, timings, plane
//! arm, release) is the shared Pipe B–D owner
//! ([`crate::intel_gpu_xelpg_pipes`]) through the DP route's helpers.
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
//! - `intel_hdmi.c` (`intel_hdmi_compute_config` scrambling,
//!   `intel_hdmi_handle_sink_scrambling`, `intel_hdmi_default_ddc_pin`),
//!   `intel_ddi.c::intel_ddi_disable_hdmi`, `drm_scdc_helper.c`
//!   (`drm_scdc_set_high_tmds_clock_ratio`, `drm_scdc_set_scrambling`)
//!   and `drm_edid.c::drm_parse_hdmi_forum_scds`; `intel_gmbus.c`
//!   `gmbus_pins_mtp`: DDI B's DDC is GMBUS pin 2 ("dpb").
//! - `drm_edid.c::drm_do_probe_ddc_edid` over `intel_gmbus.c::gmbus_xfer`:
//!   each EDID block is an offset write + read at slave 0x50, an
//!   INDEX-cycle transfer on the shared GMBUS transport
//!   ([`crate::intel_gpu_gmbus::GmbusBus`]), with the E-DDC segment
//!   pointer chained ahead of blocks 2 and 3; see [`read_edid_ddc`].
//!
//! [`probe_hdmi`] owns a legacy Type-C PHY in legacy mode before its DDC
//! is used (rolled back on any failure), and the hotplug service
//! ([`crate::intel_gpu_xelpg_external::MtlExternalService`]) selects this
//! route per its port policy.
//!
//! ## Qualified profile and refusals
//!
//! TMDS clocks from the source tables, 8 bpc RGB, AVI infoframe. Above
//! 340 MHz (C10 497.75/592/593.407/594 MHz, C20 594 MHz) HDMI 2.0
//! scrambling runs as `intel_hdmi_compute_config` decides it from the
//! sink's HF-VSDB/HF-SCDB (`drm_parse_hdmi_forum_scds`, [`parse_sink_scdc`],
//! [`tmds_link`]): `TRANS_DDI_HDMI_SCRAMBLING` +
//! `TRANS_DDI_HIGH_TMDS_CHAR_RATE` in the function control, and the sink's
//! SCDC TMDS_CONFIG (1/40 ratio, 1 ms, then scrambling;
//! `intel_hdmi_handle_sink_scrambling`) after the transcoder and before
//! the DDI buffer, reset before the transcoder stops. A sink with
//! LTE_340Mcsc_Scramble is scrambled at lower clocks too; any
//! scrambling-capable sink gets its SCDC written (cleared) on every
//! enable, as in Linux. Refused with typed errors: a clock above 340 MHz
//! the sink declares no scrambling for or above its declared maximum,
//! FRL and the FRL-ambiguous TMDS clocks 300/600 MHz (`intel_hdmi_is_frl`
//! would select FRL clocking), clocks above the 600 MHz source maximum
//! or without a source table (the SNPS C10 and computed C20 algorithms
//! are not implemented; the latter also needs the MTL-U / ARL-S
//! `tx_misc` platform fact), Type-C DP-alt (HDMI needs a legacy port), an
//! active DDI, no free Pipe B–D, a lit Pipe A that is not the owned panel
//! profile, and the Pipe B–D owner's resource refusals (all before the
//! first write). PM demand runs at the TMDS clock (Linux's
//! `crtc_state->port_clock` for HDMI). Linux only logs an SCDC failure; here a
//! stream that needs the sink scrambling fails activation instead (and
//! is locally stopped). Audio, deep color, YCbCr and HDMI 2.1 FRL remain
//! out of scope.
//!
//! DDC pins come from the corrected GMBUS numbering
//! ([`crate::intel_gpu_gmbus::PinPair`], `gmbus_pins_mtp`): DDI B is pin 2
//! ("dpb"), a declared legacy TCn is pin 8 + n ("tc1".."tc4"); see
//! [`ddc_pin`].

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gmbus::PinPair;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_pipes::Pipe;
use crate::intel_gpu_xelpg::{
    disable_d2d, disable_port_pll_complete, enable_d2d, enable_port_pll_state, port_width,
    set_signal_levels_hdmi, wait_port_buf_active, wait_port_buf_idle, C10PllState, C20PllState,
    C20Vdr, Cx0Error, Cx0Phy, Cx0PllState, PhyKind, PllRequest, XeLpgPort, PORT_BUF_PHY_IDLE,
    PORT_WIDTH_MASK,
};
use crate::intel_gpu_xelpg_external::{
    external_pipe, preflight, request_pipe_wells, reserve_pipe, trans_clk_sel, trans_clk_sel_port,
    trans_ddi_func_ctl, ExternalError, MtlDisplay, PipeRefusal, RoutePipe,
};
use crate::intel_gpu_xelpg_pipes::PipeEnableError;
use crate::intel_gpu_xelpg_tc::{
    connect as tc_connect, connection_intact, disconnect as tc_disconnect, TcConnection, TcMode,
};

include!("intel_gpu_xelpg_hdmi_tables.rs");

/// Highest TMDS character clock driven without the 1/40 clock ratio
/// (HDMI 2.0 scrambling threshold, `intel_hdmi_compute_config`).
pub const MAX_TMDS_KHZ_UNSCRAMBLED: u32 = 340_000;
/// Lowest HDMI TMDS clock (`intel_c20_get_hdmi_rate` range floor).
pub const MIN_TMDS_KHZ: u32 = 25_000;
/// `intel_hdmi_is_frl` clocks.
const FRL_CLOCKS_KHZ: [u32; 5] = [300_000, 600_000, 800_000, 1_000_000, 1_200_000];

/// `PIPE_FRMCOUNT_G4X`, primary `PLANE_SURF` / `PLANE_SURFLIVE`, relative
/// to [`Pipe::base`].
const FRMCOUNT: u64 = 0x040;
const PLANE_SURF_1: u64 = 0x19C;
const PLANE_SURFLIVE_1: u64 = 0x1AC;
const TRANS_DDI_FUNC_ENABLE: u32 = 1 << 31;
const TRANS_DDI_PORT_AND_MODE: u32 = (0xF << 27) | (0x7 << 24);
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
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
    /// The clock is above 340 MHz and the sink declares no scrambling
    /// (no SCDC or no Max_TMDS_Character_Rate in its HF-VSDB/HF-SCDB).
    ScramblingRequired(u32),
    /// The clock is above the sink's declared `max_tmds_clock`.
    SinkClockLimit {
        /// The mode's TMDS clock in kHz.
        clock_khz: u32,
        /// The sink's limit in kHz (0: none declared above 340 MHz).
        max_khz: u32,
    },
    /// An SCDC transfer the stream depends on failed.
    Scdc(crate::intel_gpu_hdmi::DdcError),
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

// ── Sink scrambling capability (HF-VSDB / HF-SCDB) ───────────────────

/// `intel_hdmi_source_max_tmds_clock` for display 13 and later (no VBT
/// `max_tmds_clock` cap without a VBT).
pub const SOURCE_MAX_TMDS_KHZ: u32 = 600_000;
/// `HDMI_FORUM_IEEE_OUI` 0xc45dd8 as stored in a vendor block (LSB first).
const HDMI_FORUM_OUI: [u8; 3] = [0xD8, 0x5D, 0xC4];
/// `CEA_EXT`.
const CEA_EXT: u8 = 0x02;
/// `CTA_DB_VENDOR` and `CTA_DB_EXTENDED_TAG`.
const CTA_DB_VENDOR: u8 = 3;
const CTA_DB_EXTENDED_TAG: u8 = 7;
/// `CTA_EXT_DB_HF_SCDB`.
const CTA_EXT_DB_HF_SCDB: u8 = 0x79;

/// The sink's SCDC and scrambling capability as
/// `drm_edid.c::drm_parse_hdmi_forum_scds` records it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SinkScdc {
    /// `hdmi.scdc.supported` (SCDC_Present, flags bit 7).
    pub scdc: bool,
    /// `hdmi.scdc.scrambling.supported`: SCDC present and a non-zero
    /// Max_TMDS_Character_Rate.
    pub scrambling: bool,
    /// `hdmi.scdc.scrambling.low_rates` (LTE_340Mcsc_Scramble, bit 3).
    pub low_rates: bool,
    /// `display_info.max_tmds_clock` when the block raised it above
    /// 340 MHz (rate byte × 5000 kHz), else 0.
    pub max_tmds_clock_khz: u32,
}

/// Parse the HDMI Forum blocks of `edid`'s CTA extensions. A block is the
/// HF-VSDB (`cea_db_is_hdmi_forum_vsdb`: vendor tag, HDMI Forum OUI) or
/// the HF-SCDB (`cea_db_is_hdmi_forum_scdb`: extended tag 0x79), each
/// with a payload of at least 7 bytes; both share the `hf_scds` layout
/// (byte 5 the rate, byte 6 the flags). Only revision 3+ CTA extensions
/// with a valid checksum are walked, over the data block collection
/// `cea_db_collection_size` bounds (bytes 4..d, d in 4..=127).
pub fn parse_sink_scdc(edid: &[u8]) -> SinkScdc {
    let mut out = SinkScdc::default();
    for ext in edid.chunks_exact(128).skip(1) {
        let sum = ext.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        if ext[0] != CEA_EXT || ext[1] < 3 || sum != 0 {
            continue;
        }
        let end = ext[2] as usize;
        if !(4..=127).contains(&end) {
            continue;
        }
        let mut index = 4usize;
        while index < end {
            let tag = ext[index] >> 5;
            let len = (ext[index] & 0x1F) as usize;
            if index + 1 + len > end {
                break;
            }
            let hf = &ext[index..index + 1 + len];
            let forum = len >= 7
                && ((tag == CTA_DB_VENDOR && hf[1..4] == HDMI_FORUM_OUI)
                    || (tag == CTA_DB_EXTENDED_TAG && hf[1] == CTA_EXT_DB_HF_SCDB));
            if forum {
                if hf[6] & 0x80 != 0 {
                    out.scdc = true;
                }
                if hf[5] != 0 {
                    let max = u32::from(hf[5]) * 5_000;
                    if max > MAX_TMDS_KHZ_UNSCRAMBLED {
                        out.max_tmds_clock_khz = max;
                    }
                    if out.scdc {
                        out.scrambling = true;
                        if hf[6] & 0x08 != 0 {
                            out.low_rates = true;
                        }
                    }
                }
            }
            index += 1 + len;
        }
    }
    out
}

/// The TMDS link state the source drives: `crtc_state->hdmi_scrambling`
/// and `hdmi_high_tmds_clock_ratio`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TmdsLink {
    /// `TRANS_DDI_HDMI_SCRAMBLING` and SCDC scrambling enable.
    pub scrambling: bool,
    /// `TRANS_DDI_HIGH_TMDS_CHAR_RATE` and the SCDC 1/40 clock ratio.
    pub high_tmds_clock_ratio: bool,
}

/// `intel_hdmi_compute_config`'s scrambling decision for `clock_khz`
/// against `sink` (`source_supports_scrambling` holds: the source maximum
/// is 600 MHz): scramble when the sink supports it and either it accepts
/// low-rate scrambling or the clock is above 340 MHz, and use the 1/40
/// ratio above 340 MHz. A clock above 340 MHz is refused when the sink
/// declares no scrambling or a lower `max_tmds_clock`
/// (`hdmi_port_clock_limit` with downstream limits).
pub fn tmds_link(clock_khz: u32, sink: &SinkScdc) -> Result<TmdsLink, HdmiError> {
    let high = clock_khz > MAX_TMDS_KHZ_UNSCRAMBLED;
    if high && !sink.scrambling {
        return Err(HdmiError::ScramblingRequired(clock_khz));
    }
    if high && clock_khz > sink.max_tmds_clock_khz {
        return Err(HdmiError::SinkClockLimit {
            clock_khz,
            max_khz: sink.max_tmds_clock_khz,
        });
    }
    Ok(TmdsLink {
        scrambling: sink.scrambling && (sink.low_rates || high),
        high_tmds_clock_ratio: sink.scrambling && high,
    })
}

// ── SCDC (drm_scdc_helper.c over the GMBUS transport) ─────────────────

/// `SCDC_I2C_SLAVE_ADDRESS`.
pub const SCDC_I2C_SLAVE_ADDRESS: u8 = 0x54;
/// `SCDC_TMDS_CONFIG`.
pub const SCDC_TMDS_CONFIG: u8 = 0x20;
/// `SCDC_TMDS_BIT_CLOCK_RATIO_BY_40`.
pub const SCDC_TMDS_BIT_CLOCK_RATIO_BY_40: u8 = 1 << 1;
/// `SCDC_SCRAMBLING_ENABLE`.
pub const SCDC_SCRAMBLING_ENABLE: u8 = 1 << 0;

/// `intel_hdmi_handle_sink_scrambling` for a sink whose scrambling is
/// supported: `drm_scdc_set_high_tmds_clock_ratio` (read-modify-write of
/// TMDS_CONFIG bit 1, then at least 1 ms before the sink is relied on),
/// then `drm_scdc_set_scrambling` (read-modify-write of bit 0). The
/// sequence is shared with Gen12
/// ([`crate::intel_gpu_hdmi::handle_sink_scrambling`]).
pub fn sink_scrambling<M: MmioWindow + ?Sized>(
    io: &M,
    pin: PinPair,
    high_tmds_clock_ratio: bool,
    scrambling: bool,
) -> Result<(), HdmiError> {
    crate::intel_gpu_hdmi::handle_sink_scrambling(io, pin, high_tmds_clock_ratio, scrambling)
        .map_err(HdmiError::Scdc)
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
    if clock_khz > SOURCE_MAX_TMDS_KHZ {
        return Err(HdmiError::UnsupportedClock(clock_khz));
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
        lanes: crate::intel_gpu_xelpg::PhyLaneConfig::NATIVE,
        state,
        port_clock_khz: clock_khz,
        lane_count: HDMI_LANES,
        dp_alt: false,
        ssc: false,
        hdmi: true,
        protocol_switch: legacy && port.phy() == PhyKind::C20,
    })
}

/// The DDC pin of an HDMI-capable MTL port, valid in `gmbus_pins_mtp`.
/// DDI B is `intel_hdmi_default_ddc_pin`'s `dg1_encoder_to_ddc_pin`
/// (`PCH_MTL >= PCH_DG1`: PHY B + 1 = `GMBUS_PIN_2_BXT`, "dpb"). That
/// formula gives Type-C (PHY F..I) pins 6..9, which the MTP table does
/// not wire to TC1..TC4, so Linux takes a Type-C port's DDC only from its
/// VBT child (`intel_bios_hdmi_ddc_pin`, mapped by `map_ddc_pin` with
/// `adlp_ddc_pin_map`: `ADLP_DDC_BUS_PORT_TCn` = `GMBUS_PIN_9_TC1_ICP +
/// n - 1`, "tc1".."tc4"). A hand-declared legacy port carries that VBT
/// fact here: TCn's DDC is the MTP "tcn" pin. DDI A (internal) has none.
/// A policy derived from a parsed VBT carries `intel_hdmi_ddc_pin`'s
/// own result instead (`MtlPortDecl::ddc_pin`).
pub const fn ddc_pin(port: XeLpgPort) -> Option<PinPair> {
    match port {
        XeLpgPort::A => None,
        XeLpgPort::B => Some(PinPair::Pin2Bxt),
        XeLpgPort::Tc1 => Some(PinPair::Pin9Tc1),
        XeLpgPort::Tc2 => Some(PinPair::Pin10Tc2),
        XeLpgPort::Tc3 => Some(PinPair::Pin11Tc3),
        XeLpgPort::Tc4 => Some(PinPair::Pin12Tc4),
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
    /// The sink's SCDC/scrambling capability.
    pub sink: SinkScdc,
    /// The scrambling state the source drives for the mode.
    pub link: TmdsLink,
    /// The DDC pin EDID and SCDC traffic use (the port policy's
    /// `intel_hdmi_ddc_pin` result).
    pub ddc: PinPair,
    /// EDID bytes (`edid_len` valid).
    pub edid: [u8; crate::intel_gpu_hdmi::EDID_CAPACITY],
    /// Valid EDID length.
    pub edid_len: usize,
}

/// Read the sink's EDID over DDC the way `drm_do_probe_ddc_edid` does:
/// each 128-byte block is an offset write followed by a read at slave
/// 0x50, which `intel_gmbus.c::do_gmbus_xfer` runs as one INDEX-cycle
/// transfer; blocks 2 and 3 chain the E-DDC segment pointer ahead of it
/// with a repeated START ([`crate::intel_gpu_gmbus::read_edid_eddc`]).
pub fn read_edid_ddc<M: MmioWindow + ?Sized>(
    io: &M,
    pin: PinPair,
) -> Result<([u8; crate::intel_gpu_hdmi::EDID_CAPACITY], usize), HdmiError> {
    crate::intel_gpu_hdmi::read_edid(io, pin).map_err(HdmiError::Ddc)
}

/// Probe an HDMI sink: Type-C legacy connect (TC only), DDC EDID,
/// preferred mode and its TMDS PLL request. `ddc` is the port's DDC pin
/// from the board policy (`None`: the port has no usable DDC pin, as
/// `intel_hdmi_init_connector` refuses). Refusals precede MMIO where
/// possible; a Type-C connection is rolled back on failure.
pub fn probe_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
    ddc: Option<PinPair>,
) -> Result<MtlHdmiProbe, HdmiError> {
    if generation != Generation::MeteorLake {
        return Err(ExternalError::UnsupportedGeneration.into());
    }
    if port == XeLpgPort::A {
        return Err(ExternalError::UnsupportedPort.into());
    }
    let type_c = port.tc_index().is_some();
    if type_c && !legacy_port {
        return Err(HdmiError::NotLegacy);
    }
    let pin = ddc.ok_or(HdmiError::DdcUnavailable)?;
    // A legacy Type-C port is owned in legacy mode before its DDC is used,
    // as the DP probe owns the PHY before AUX.
    let tc = if type_c {
        let conn = tc_connect(io, port, true, HDMI_LANES)?;
        if conn.mode != TcMode::Legacy {
            let _ = tc_disconnect(io, &conn);
            return Err(HdmiError::NotLegacy);
        }
        Some(conn)
    } else {
        None
    };
    let rollback = |e: HdmiError| {
        if let Some(conn) = tc {
            let _ = tc_disconnect(io, &conn);
        }
        e
    };
    let (edid, edid_len) = read_edid_ddc(io, pin).map_err(rollback)?;
    let mode = crate::intel_gpu_dp::mode_from_edid(&edid[..edid_len])
        .map_err(|_| rollback(HdmiError::Edid))?;
    let pll = hdmi_pll_request(port, mode.pixel_clock_khz, type_c).map_err(rollback)?;
    let sink = parse_sink_scdc(&edid[..edid_len]);
    let link = tmds_link(mode.pixel_clock_khz, &sink).map_err(rollback)?;
    if !io.display_access_ok() {
        return Err(rollback(ExternalError::AccessLost.into()));
    }
    Ok(MtlHdmiProbe {
        port,
        tc,
        mode,
        pll,
        sink,
        link,
        ddc: pin,
        edid,
        edid_len,
    })
}

/// Release a probe's Type-C ownership (DDI B owns nothing).
pub fn release_hdmi_probe<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlHdmiProbe,
) -> Result<(), HdmiError> {
    match probe.tc {
        Some(conn) => tc_disconnect(io, &conn).map_err(HdmiError::from),
        None => Ok(()),
    }
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

/// One owned HDMI route on a Pipe B–D.
#[derive(Clone, Debug)]
pub struct MtlHdmiRoute {
    /// The probe.
    pub probe: MtlHdmiProbe,
    /// The scanned-out framebuffer.
    pub fb: Framebuffer,
    state: HdmiRouteState,
    /// The Pipe B–D (and transcoder) the route was activated on.
    pipe: Pipe,
    /// The pipe's reservation until its post-plane release is proven.
    reservation: Option<RoutePipe>,
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

impl From<PipeEnableError> for HdmiError {
    fn from(e: PipeEnableError) -> Self {
        HdmiError::Route(e.into())
    }
}

/// Program and light the HDMI route on a free Pipe B–D next to what Pipe A
/// runs (`display`), in `intel_atomic_commit_tail` (pre-plane resources)
/// → `hsw_crtc_enable` (pipe DMC, `intel_ddi_pre_enable_hdmi`, pipe and
/// transcoder) → `intel_ddi_enable` → `intel_ddi_enable_hdmi` →
/// `intel_update_crtc` order. Every refusal precedes the first write and
/// returns the probe; programming failures return a `Stopped` or
/// `Quarantined` route.
// Refusal hands the owned probe/route back inline: it must not allocate.
#[allow(clippy::result_large_err)]
pub fn activate_hdmi<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlHdmiProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
) -> Result<MtlHdmiRoute, (Result<MtlHdmiRoute, MtlHdmiProbe>, HdmiError)> {
    if let Err(e) = crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &probe.mode) {
        return Err((Err(probe), ExternalError::Modeset(e).into()));
    }
    let choice = match preflight(io, probe.port, display) {
        Ok(choice) => choice,
        Err(e) => return Err((Err(probe), e.into())),
    };
    if let Some(conn) = probe.tc {
        if connection_intact(io, &conn) != Ok(true) {
            return Err((Err(probe), HdmiError::NotLegacy));
        }
    }
    // crtc_state->port_clock is the TMDS clock for HDMI.
    let ext = match external_pipe(
        &choice,
        probe.port,
        &probe.mode,
        &fb,
        probe.pll.port_clock_khz,
        None,
        crate::intel_gpu_xelpg_dsc::PIPE_BPP,
    ) {
        Ok(ext) => ext,
        Err(e) => return Err((Err(probe), e.into())),
    };
    if let Err(e) = choice.pipes.admit(io, &ext) {
        return Err((Err(probe), e.into()));
    }
    let mut route = MtlHdmiRoute {
        probe,
        fb,
        state: HdmiRouteState::Stopped,
        pipe: choice.pipe,
        reservation: None,
    };
    let dmc = display.pipe_dmc;
    let result = request_pipe_wells(io, ext.pipe)
        .and_then(|()| reserve_pipe(io, choice, &ext, dmc))
        .map_err(HdmiError::from)
        .and_then(|rp| {
            route.reservation = Some(rp);
            program_hdmi(io, &mut route)
        });
    match result {
        Ok(()) => {
            route.state = HdmiRouteState::Live;
            Ok(route)
        }
        Err(e) => {
            route.state = match stop_hdmi_local(io, &mut route) {
                Ok(()) => HdmiRouteState::Stopped,
                Err(_) => HdmiRouteState::Quarantined,
            };
            Err((Ok(route), e))
        }
    }
}

fn reservation(route: &mut MtlHdmiRoute) -> Result<&mut RoutePipe, HdmiError> {
    route
        .reservation
        .as_mut()
        .ok_or(HdmiError::Route(ExternalError::Pipe(PipeRefusal::Sequence)))
}

fn program_hdmi<M: MmioWindow + ?Sized>(io: &M, route: &mut MtlHdmiRoute) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let mode = route.probe.mode;
    let link = route.probe.link;
    let (scrambling, ddc, pll) = (
        route.probe.sink.scrambling,
        route.probe.ddc,
        route.probe.pll,
    );
    let rp = reservation(route)?;
    let (pipe, trans) = (rp.pipe, rp.transcoder());
    // intel_ddi_pre_enable_hdmi: PLL, transcoder clock, infoframes.
    enable_port_pll_state(io, port, &pll).map_err(phy_err)?;
    wr(io, trans_clk_sel(trans), trans_clk_sel_port(port))?;
    crate::intel_gpu_hdmi::write_avi_infoframe(
        io,
        trans,
        &crate::intel_gpu_hdmi::pack_avi_infoframe(&mode),
    );
    // hsw_crtc_enable: source size, timings, RGB bypass (pipe off).
    rp.pipes.program_timings(io, pipe)?;
    // intel_ddi_enable: transcoder function, then the transcoder.
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(
        port.func_ctl_index(),
        link.scrambling,
        link.high_tmds_clock_ratio,
    );
    wr(io, trans_ddi_func_ctl(trans), func)?;
    let start = rd(io, pipe.base() + FRMCOUNT)?;
    rp.pipes.enable(io, pipe)?;
    // intel_ddi_enable_hdmi (display 14): sink scrambling/ratio over
    // SCDC (only for a scrambling-capable sink), D2D, levels,
    // PORT_BUF_CTL1 width, DDI_CTL_DE with the TMDS lane width, buffer
    // active. Linux only logs an SCDC failure; a stream that needs the
    // sink scrambling cannot work without it, so that failure stops here.
    if scrambling {
        let scdc = sink_scrambling(io, ddc, link.high_tmds_clock_ratio, link.scrambling);
        if scdc.is_err() && (link.scrambling || link.high_tmds_clock_ratio) {
            return scdc;
        }
    }
    enable_d2d(io, port).map_err(phy_err)?;
    set_signal_levels_hdmi(&Cx0Phy::with_lanes(io, port, pll.lanes)).map_err(phy_err)?;
    let buf = rd(io, port.buf_ctl1())?;
    wr(
        io,
        port.buf_ctl1(),
        (buf & !PORT_WIDTH_MASK) | port_width(HDMI_LANES),
    )?;
    wr(
        io,
        port.ddi_buf_ctl(),
        port_width(HDMI_LANES) | DDI_BUF_CTL_ENABLE,
    )?;
    wait_port_buf_active(io, port).map_err(phy_err)?;
    // intel_update_crtc: the primary, armed under vblank evasion.
    rp.pipes.arm_primary(io, pipe)?;
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
    let (base, trans) = (route.pipe.base(), route.pipe.transcoder());
    let plane = crate::intel_gpu_pipes::build_primary_plane(
        mode.h_active,
        mode.v_active,
        route.fb.stride_bytes,
        route.fb.phys_addr as u32,
        crate::intel_gpu_pipes::PixelFormat::Argb8888,
    )
    .map_err(|_| ExternalError::Modeset(ModesetError::InvalidFramebuffer))?;
    let dip = trans.base() + crate::intel_gpu_hdmi::VIDEO_DIP_CTL_OFFSET;
    let mut refused = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let frame = io.read32(base + FRMCOUNT);
            let surf = io.read32(base + PLANE_SURF_1);
            let live = io.read32(base + PLANE_SURFLIVE_1);
            let route_now = io.read32(trans_ddi_func_ctl(trans));
            let clock = io.read32(trans_clk_sel(trans));
            let infoframes = io.read32(dip);
            let buf = io.read32(port.buf_ctl1());
            let ddi = io.read32(port.ddi_buf_ctl());
            refused = !io.display_access_ok() || frame == u32::MAX || ddi == u32::MAX;
            refused
                || (frame != start
                    && surf == plane.plane_surf
                    && live == surf
                    && route_now == func
                    && clock == trans_clk_sel_port(port)
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

/// Local stop in `hsw_crtc_disable` order: plane off
/// (`intel_crtc_disable_planes`), sink scrambling reset
/// (`intel_ddi_disable_hdmi`), transcoder off, function deselect, then
/// `intel_ddi_post_disable_hdmi` (infoframes off, DDI_CTL_DE off + PHY
/// idle, D2D off, transcoder clock off, `intel_cx0pll_disable`), the pipe
/// DMC disable and the post-plane repartition without the pipe. A route
/// that failed before its reservation has nothing to stop: its port is
/// programmed only after it.
fn stop_hdmi_local<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlHdmiRoute,
) -> Result<(), HdmiError> {
    let port = route.probe.port;
    let (scrambling, ddc) = (route.probe.sink.scrambling, route.probe.ddc);
    let stop_failed: HdmiError =
        ExternalError::Modeset(ModesetError::PipelineStopUnavailable).into();
    let Some(rp) = route.reservation.as_mut() else {
        return Ok(());
    };
    let (pipe, trans) = (rp.pipe, rp.transcoder());
    rp.pipes.disable_primary(io, pipe)?;
    // intel_ddi_disable_hdmi (encoder disable, before the transcoder):
    // reset sink scrambling and the 1/10 ratio, best effort as in Linux
    // (an SCDC NACK never replaces the local stop proof).
    if scrambling {
        let _ = sink_scrambling(io, ddc, false, false);
    }
    rp.pipes.disable(io, pipe).map_err(|e| match e {
        PipeEnableError::Timeout => stop_failed,
        e => e.into(),
    })?;
    let func = rd(io, trans_ddi_func_ctl(trans))?;
    wr(
        io,
        trans_ddi_func_ctl(trans),
        func & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE),
    )?;
    crate::intel_gpu_hdmi::disable_infoframes(io, trans);
    let ddi = rd(io, port.ddi_buf_ctl())?;
    wr(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
    wait_port_buf_idle(io, port).map_err(|_| stop_failed)?;
    disable_d2d(io, port).map_err(|_| stop_failed)?;
    wr(io, trans_clk_sel(trans), 0)?;
    disable_port_pll_complete(io, port).map_err(|_| stop_failed)?;
    let ddi = rd(io, port.ddi_buf_ctl())?;
    let buf = rd(io, port.buf_ctl1())?;
    let clock = rd(io, port.port_clock_ctl())?;
    if ddi & DDI_BUF_CTL_ENABLE != 0 || buf & PORT_BUF_PHY_IDLE == 0 || clock & 0xCC00_0000 != 0 {
        return Err(stop_failed);
    }
    rp.pipes.release(io, pipe, rp.dmc)?;
    route.reservation = None;
    Ok(())
}

impl MtlHdmiRoute {
    /// Lifecycle state.
    pub fn state(&self) -> HdmiRouteState {
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

    /// Whether the pipe's display resources are still reserved.
    pub fn reserved(&self) -> bool {
        self.reservation.is_some()
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
    // The retained route returns inline on refusal: it must not allocate.
    #[allow(clippy::result_large_err)]
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
