//! Intel Xe-LPDP/Xe2_LPD/Xe3_LPD owned external DP SST route (Meteor/Arrow,
//! Lunar, Panther and Wildcat Lake USB-C).
//!
//! The internal-panel orchestrator ([`crate::intel_gpu_modeset_xelpg`])
//! only re-programs an already-enabled DDI A. An external sink arrives
//! with its DDI, PHY PLL, D2D link and (on Type-C) PHY ownership all off,
//! so this module owns the complete off→on→off route for one DisplayPort
//! SST stream on DDI B (C10) or TC1–TC4 (C20, DP-alt or declared legacy).
//! Wildcat Lake's exact profile narrows this to TC1/TC2 and Pipes B/C:
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
//! The service owns one [`MtlRoute`] (two under `narf.intel.ext_routes=2`,
//! see [`MtlExternalService`]): this module's DP route or the HDMI
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
//! DP 2.0 UHBR (128b/132b) runs only under `narf.intel.uhbr=1` (below);
//! deep colour, the YCbCr 4:4:4 PCON route ([`color`]) and SST audio
//! ([`audio`]) only under `narf.intel.hdmi14_ext=1`. Live TBT
//! routes select fabric-owned AUX/clocking. MST uses the shared sideband
//! manager and a single primary transport across independent Pipe B-D
//! streams. Native/legacy VBT lane reversal reaches the PHY; DP-alt cable
//! flip remains a TCSS mux operation.
//! Lunar Lake admits combo DDI B (C10, through the display-20 PICA register
//! view) and TC1–TC4; Panther Lake its C20 DDI B (through the display-30
//! view) and TC1–TC4. PICA power and display-20+
//! TCSS pin assignment are retained by the probe and D2D enable/state move
//! to `DDI_BUF_CTL`. The Pipe B–D owner uses the exact display-20/30
//! resource transaction; on display 30 it also computes the fixed-refresh
//! guardband and runs the mandatory VRR timing generator. Both take HDMI
//! TMDS on DDI B and declared legacy Type-C ports through the same
//! display-20/30 steps ([`crate::intel_gpu_xelpg_hdmi`]).
//! Wildcat Lake retains the same display-30 C20/PICA sequence but its distinct
//! descriptor admits only TC1/TC2 and Pipes A–C. The service stores an exact
//! [`ExternalDisplayProfile`] so broad `Generation::PantherLake` can never
//! widen it to TC3/TC4 or Pipe D. The production hotplug entry receives that
//! profile from the exact KMS owner; native fixtures also select it directly.
//! Nova Lake-S display 35 admits LT port B (DP, HDMI TMDS) and TC1/TC2
//! (DP-alt, declared legacy) through the display-35 view
//! ([`crate::intel_gpu_xe3plpd::View`]): the port PLL, its disable and the
//! signal levels take the LT PHY (`intel_lt_phy_pll_enable`,
//! `intel_lt_phy_pll_disable`, `intel_lt_phy_set_signal_levels` over
//! `xe3plpd_lt_trans_dp14`), and a profile whose PHY family the view does not
//! report is refused before MMIO ([`ExternalDisplayProfile::admits_view`]).
//! Thunderbolt alt mode on TC1/TC2 runs as on display 14: the Type-C connect
//! takes no PHY (display 35 powers PICA_TC for the tunnel's AUX and lanes),
//! AUX selects TBT IO, and the port clock is the fabric's
//! (`intel_mtl_tbt_pll_enable_clock` with the display-30 five-bit select and
//! `DDI_CLK_VALFREQ`, `PORT_BUF_CTL1` TBT IO select); the LT PHY takes no PLL
//! or signal-level transaction (`xe3plpd_tbt_pll_funcs` enable is a no-op,
//! `intel_lt_phy_set_signal_levels` returns in TBT alt mode).
//!
//! ## DP 2.0 UHBR (`narf.intel.uhbr=1`)
//!
//! With the strict boot option ([`uhbr::BOOT_OPTION`], default off) the
//! probe adds the sink's 128b/132b rates to Linux's
//! `intel_dp_compute_link_config_wide` search ([`uhbr::wide_link`]). Only
//! when no 8b/10b link carries the stream at a bpp does a UHBR one take it:
//! UHBR10 or UHBR20 on the C20 Type-C ports (and Panther Lake's C20 DDI B)
//! and on Nova Lake's LT ports, never on a C10 PHY or Wildcat Lake
//! (`mtl_max_source_rate`). Such a route follows `mtl_ddi_pre_enable_dp` /
//! `intel_ddi_enable` for 128b/132b SST: the UHBR port PLL (C20 MPLLA/MPLLB
//! image or LT UHBR image, `DDI_CLK_VALFREQ` at the 32-bit symbol clock),
//! `TRANS_DP2_CTL`, `TRANS_DDI_FUNC_CTL` in 128b/132b mode with its own MST
//! transport, `DP_TP_CTL` in MST mode, the 40-bit `PORT_BUF_CTL1` and
//! `DDI_CTL_DE`, the 128b/132b training with TX FFE presets
//! ([`uhbr::train`]), the sink's VC payload and its ACT, the MTP M/N, the
//! `TRANS_DP2_VFREQ` pair and, on display 30+, `DP_MIN_HBLANK_CTL`. The stop
//! reverses it and hands the sink back to 8b/10b channel coding. 128b/132b
//! MST, DSC on a UHBR link, Thunderbolt alt mode, LTTPRs, a failed
//! training's reduced retry and HDCP are refused typed
//! ([`ExternalError::Uhbr`]) or not offered. Without the option no
//! 128b/132b register is touched.
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
//! transcoder enable `intel_ddi_wait_for_fec_status`. The stop reverses it:
//! sink decompression off before the transcoder, `intel_dsc_disable` and
//! the PPS SDP enable after the function
//! deselect, FEC off after `DP_TP_CTL`, then the sink's FEC ready. The
//! Pipes owner already sets display 14's `DP_FEC_BS_JITTER_WA`. The shared
//! training loop programs each source pattern and drive level before its
//! matching sink write. A rate/width fallback stops the buffer before
//! retuning the owned PHY or fabric clock and restarting CR/EQ.
//! Display 30 confirms both source FEC live and sink decode before the PPS.
//! Up to three disable/enable retries precede rollback of a failed handshake.
//! Its source must still report FEC live after the transcoder is enabled and
//! must acknowledge FEC off before the port clock or reservation is released.
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

#[path = "intel_gpu_dp_uhbr.rs"]
pub(crate) mod uhbr;

#[path = "intel_gpu_xelpg_color.rs"]
pub mod color;

#[path = "intel_gpu_xelpg_audio.rs"]
pub mod audio;

use crate::dp_aux::AuxChannel as _;
use crate::dp_edid::{read_full_edid, EdidReadError};
use crate::dp_link_training::{
    negotiate, stream_demand_kbps, train_link_with_receiver, DpcdCaps, LinkError,
    LinkRate as TrainRate, NegotiatedLink, ReceiverTraining, SourceCaps, TrainedLink,
};
use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_dc_states::{NoPipeDmc, PipeDmc, ServicePipeDmc};
use crate::intel_gpu_gmbus::PinPair;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_pipes::{Pipe, Transcoder};
use crate::intel_gpu_vbt::{dp_ssc_enabled, Vbt, VbtEncoder, VbtPlatform, DP_MAX_DOWNSPREAD};
use crate::intel_gpu_xe2lpd::{disable_d2d, enable_d2d, DisplayIp, DDI_BUF_D2D_LINK_ENABLE};
use crate::intel_gpu_xelpg::{
    disable_port_pll_lanes, disable_tbt_clock, dp_pll_request, dp_uhbr_pll_request,
    enable_port_pll_state, enable_tbt_clock, program_port_buf_ctl, program_port_buf_ctl_width,
    set_signal_levels, set_signal_levels_uhbr, wait_port_buf_active, wait_port_buf_idle, Cx0Error,
    Cx0Phy, PhyKind, PhyLaneConfig, XeLpgPort, PORT_BUF_IO_SELECT_TBT, PORT_BUF_PHY_IDLE,
};
use crate::intel_gpu_xelpg_dsc::{self as dsc, DscPlan, DscRefusal};
use crate::intel_gpu_xelpg_hdmi::{
    activate_hdmi_beside, probe_hdmi_profile_ext, release_hdmi_probe, HdmiError, HdmiRouteState,
    MtlHdmiRoute,
};
use crate::intel_gpu_xelpg_hpd::{LiveMode, MtlHpdConfig, MtlHpdEvent, MtlHpdKind, MtlHpdPin};
use crate::intel_gpu_xelpg_pipes::{ExternalPipe, PipeEnableError, Pipes};
use crate::intel_gpu_xelpg_resources::ResourceError;
use crate::intel_gpu_xelpg_tc::{
    aux_power_disable, aux_power_enable, connect_for as tc_connect_for, connection_intact,
    disconnect as tc_disconnect, TcConnection, TcDisplayProfile, TcError, TcMode,
};

/// Source-qualified external-display limits which cannot be inferred from
/// [`Generation`].  Wildcat Lake shares the Panther Lake graphics generation
/// but has the distinct display-30.02 descriptor: only external TC1/TC2 and
/// Pipes A-C. Keeping that identity here prevents a future C20 route from
/// silently inheriting Panther Lake's TC3/TC4 or Pipe D.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalDisplayProfile {
    display_ip: DisplayIp,
    generation: Generation,
}

impl ExternalDisplayProfile {
    #[cfg(any(test, doc, feature = "kernel-test"))]
    pub(crate) const WILDCAT_LAKE: Self = Self {
        display_ip: DisplayIp::WildcatLake,
        generation: Generation::PantherLake,
    };

    pub(crate) const fn for_generation(generation: Generation) -> Option<Self> {
        match DisplayIp::for_generation(generation) {
            Some(display_ip) => Some(Self {
                display_ip,
                generation,
            }),
            None => None,
        }
    }

    pub(crate) const fn for_ip(display_ip: DisplayIp) -> Self {
        let generation = match display_ip {
            DisplayIp::Xelpdp => Generation::MeteorLake,
            DisplayIp::Xe2Lpd => Generation::LunarLake,
            // Nova Lake-S has no generation of its own; its profile admits
            // no external port (see `admits_port`).
            DisplayIp::Xe3Lpd | DisplayIp::WildcatLake | DisplayIp::NovaLakeS => {
                Generation::PantherLake
            }
        };
        Self {
            display_ip,
            generation,
        }
    }

    pub(crate) const fn display_ip(self) -> DisplayIp {
        self.display_ip
    }

    /// Whether this source's DDI B is a C20 PHY (Panther Lake 30.00; see
    /// [`crate::intel_gpu_aux::MmioWindow::cx0_c20_port_b`]).
    pub(crate) const fn c20_port_b(self) -> bool {
        matches!(self.display_ip, DisplayIp::Xe3Lpd)
    }

    pub(crate) const fn tc_profile(self) -> TcDisplayProfile {
        match self.display_ip {
            DisplayIp::Xelpdp => TcDisplayProfile::XeLpdp,
            DisplayIp::Xe2Lpd => TcDisplayProfile::Xe2Lpd,
            DisplayIp::Xe3Lpd => TcDisplayProfile::Xe3Lpd,
            DisplayIp::WildcatLake => TcDisplayProfile::WildcatLake,
            DisplayIp::NovaLakeS => TcDisplayProfile::NovaLakeS,
        }
    }

    const fn generation(self) -> Generation {
        self.generation
    }

    /// The external ports this source drives. Lunar Lake's combo DDI B is
    /// C10 like Meteor Lake's (`intel_encoder_is_c10phy`) and Panther
    /// Lake's is a non-Type-C C20 ([`crate::intel_gpu_xelpg::phy_kind`],
    /// the `mtl_c20_dp_*` states `xe3lpd_c20_dp_edp_tables` carries at the
    /// DP 1.4 rates). Both reach their PHY and AUX through the PICA view
    /// their pass applies ([`crate::intel_gpu_xe2lpd::PicaFlushed`],
    /// [`crate::intel_gpu_xe3lpd::View`]).
    pub(crate) const fn admits_port(self, port: XeLpgPort) -> bool {
        match self.display_ip {
            DisplayIp::Xelpdp => !matches!(port, XeLpgPort::A),
            DisplayIp::Xe2Lpd | DisplayIp::Xe3Lpd => {
                matches!(port, XeLpgPort::B) || port.tc_index().is_some()
            }
            DisplayIp::WildcatLake => {
                matches!(port, XeLpgPort::Tc1 | XeLpgPort::Tc2)
            }
            // Display 35: LT port B and TC1/TC2 (`HAS_LT_PHY`); every PHY
            // step of the route takes the LT PHY through the display-35 view
            // ([`crate::intel_gpu_xe3plpd::View`]), never a Cx0 sequence.
            DisplayIp::NovaLakeS => {
                matches!(port, XeLpgPort::B | XeLpgPort::Tc1 | XeLpgPort::Tc2)
            }
        }
    }

    /// Whether `io` is this profile's PHY family: the LT PHY exactly on
    /// display 35 (`HAS_LT_PHY` is `platform.novalake`), Cx0 elsewhere.
    pub(crate) fn admits_view<M: MmioWindow + ?Sized>(self, io: &M) -> bool {
        io.has_lt_phy() == matches!(self.display_ip, DisplayIp::NovaLakeS)
            && !(io.has_lt_phy() && io.cx0_xe3())
    }
}

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
const DP_TP_CTL_LINK_TRAIN_PAT2: u32 = 1 << 8;
const DP_TP_CTL_LINK_TRAIN_NORMAL: u32 = 3 << 8;
/// `DP_TP_CTL_MODE_MST`: MST, and 128b/132b SST (`mtl_ddi_prepare_link_retrain`).
const DP_TP_CTL_MODE_MST: u32 = 1 << 27;
const TRANS_DDI_FUNC_ENABLE: u32 = 1 << 31;
/// `TRANS_DDI_MODE_SELECT_FDI_OR_128B132B` (display 14+: 128b/132b).
const TRANS_DDI_MODE_128B132B: u32 = 4 << 24;
/// `TRANS_DDI_MODE_SELECT_MASK`.
const TRANS_DDI_MODE_MASK: u32 = 7 << 24;
/// `TRANS_DDI_MST_TRANSPORT_SELECT(trans)` (bits 11:10).
const fn trans_ddi_mst_transport(trans: Transcoder) -> u32 {
    (trans as u32) << 10
}
/// `TRANS_DDI_DP_VC_PAYLOAD_ALLOC`.
const TRANS_DDI_DP_VC_PAYLOAD_ALLOC: u32 = 1 << 8;
/// `TRANS_DP2_CTL(trans)` (`_TRANS_DP2_CTL_A` 0x600a0) and its
/// `TRANS_DP2_128B132B_CHANNEL_CODING`.
const fn trans_dp2_ctl(trans: Transcoder) -> u64 {
    trans.base() + 0xa0
}
const TRANS_DP2_128B132B_CHANNEL_CODING: u32 = 1 << 31;
/// `TRANS_DP2_VFREQHIGH(trans)` / `TRANS_DP2_VFREQLOW(trans)` (0x600a4/a8),
/// `TRANS_DP2_VFREQ_PIXEL_CLOCK` in bits 31:8.
const fn trans_dp2_vfreqhigh(trans: Transcoder) -> u64 {
    trans.base() + 0xa4
}
const fn trans_dp2_vfreqlow(trans: Transcoder) -> u64 {
    trans.base() + 0xa8
}
/// `DDI_BUF_PORT_DATA_40BIT` (display 14+, `intel_ddi_init_dp_buf_reg`).
const DDI_BUF_PORT_DATA_40BIT: u32 = 2 << 18;
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

/// `intel_dp->DP` when `intel_ddi_buf_enable` starts the port. Linux keeps
/// the display >= 20 D2D request in `DDI_BUF_CTL` across that full write.
pub(crate) const fn ddi_enable_value(ip: DisplayIp, lanes: u8) -> u32 {
    ddi_port_width(lanes)
        | DDI_BUF_CTL_ENABLE
        | if ip.xe2_plus() {
            DDI_BUF_D2D_LINK_ENABLE
        } else {
            0
        }
}

/// Typed refusal or failure of the MTL external route.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExternalError {
    Mst(MstFailure),
    /// Not a qualified Xe-LPDP/Xe2_LPD/Xe3_LPD display route.
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
    /// Display 30 could not confirm FEC for a compressed output.
    FecNotReady,
    /// Display 30 did not acknowledge disabling the source FEC encoder.
    FecStopTimeout,
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
    /// A 128b/132b (UHBR) route `narf.intel.uhbr=1` would run is refused or
    /// failed ([`uhbr::UhbrRefusal`]).
    Uhbr(uhbr::UhbrRefusal),
    /// A second concurrent route (`narf.intel.ext_routes=2`) is refused
    /// beside the route already owned ([`SecondRouteRefusal`]).
    SecondRoute(SecondRouteRefusal),
    /// The output format `narf.intel.hdmi14_ext=1` would drive is refused
    /// ([`color::ColorRefusal`]).
    Color(color::ColorRefusal),
}

/// Why a second concurrent external route is refused under
/// `narf.intel.ext_routes=2`. Nothing was programmed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecondRouteRefusal {
    /// The owned route is not live (quarantined, or stopped and retained):
    /// its reservation is not a proven layout to plan beside.
    SiblingNotLive,
    /// The owned route is DP MST, which already shares its pipes among its
    /// own streams; a second independent route beside it is not qualified.
    SiblingMst,
    /// The owned route runs 128b/132b; a second route beside it is not
    /// qualified.
    SiblingUhbr,
    /// The new sink is a DP MST branch.
    Mst,
    /// The new sink needs a 128b/132b link.
    Uhbr,
}

/// `narf.intel.ext_routes=2`: the strict default-off option for a second
/// concurrent external route ([`MtlExternalService`]).
pub const EXT_ROUTES_OPTION: &str = "narf.intel.ext_routes";

/// Whether the boot command line carries exactly `narf.intel.ext_routes=2`.
pub fn ext_routes_opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_is(narf_boot::args(), EXT_ROUTES_OPTION, "2")
}

/// How many external routes the service owns at once.
pub const MAX_ROUTES: usize = 2;

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

/// The lowest real external pipe whose transcoder, primary plane and
/// transcoder function are all off (Linux assigns CRTCs; Pipe A stays the
/// panel's). WCL has no Pipe D, so its profile never reads Pipe-D MMIO.
fn free_pipe<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
) -> Result<Pipe, ExternalError> {
    for pipe in [Pipe::B, Pipe::C, Pipe::D] {
        if pipe as usize >= profile.display_ip.pipe_count() {
            continue;
        }
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

/// No-write preflight on display IP `ip`: the target DDI and its PLL are
/// off, a Pipe B–D the IP has is free, and whatever Pipe A runs is adopted
/// — nothing when it is off, the owned panel profile for `display.panel`
/// when it is lit.
pub(crate) fn preflight_ip<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    display: &MtlDisplay,
    ip: DisplayIp,
    beside: Option<Pipes>,
) -> Result<PipeChoice, ExternalError> {
    preflight_clock_ip(
        io,
        port,
        display,
        pll_clock_mask(PhyLaneConfig::NATIVE),
        ip,
        beside,
    )
}

/// `beside` is the Pipe B–D owner of a live sibling route
/// ([`MtlExternalService`] under `narf.intel.ext_routes=2`): the new route
/// joins the layout that owner holds programmed (Pipe A and the sibling's
/// pipe), as Linux's atomic check plans a second CRTC against the CRTCs
/// already active (`intel_atomic_check`), instead of adopting the panel
/// profile alone, which a lit Pipe B–D refuses.
fn preflight_clock_ip<M: MmioWindow + ?Sized>(
    io: &M,
    port: XeLpgPort,
    display: &MtlDisplay,
    clock_mask: u32,
    ip: DisplayIp,
    beside: Option<Pipes>,
) -> Result<PipeChoice, ExternalError> {
    if !io.display_access_ok() {
        return Err(ExternalError::AccessLost);
    }
    let ddi = read(io, port.ddi_buf_ctl())?;
    let clock = read(io, port.port_clock_ctl())?;
    if ddi & DDI_BUF_CTL_ENABLE != 0 || clock & clock_mask != 0 {
        return Err(ExternalError::PortBusy);
    }
    let pipe = free_pipe(io, ExternalDisplayProfile::for_ip(ip))?;
    if let Some(pipes) = beside {
        // The owner's own admission re-proves every lit pipe it holds
        // (`check_pipes`) before the joint transaction's first write.
        return Ok(PipeChoice { pipe, pipes });
    }
    let panel = read(io, Pipe::A.base() + CONF)? & (ENABLE | STATE);
    let pipes = match (panel, display.panel) {
        (0, _) => Pipes::adopt_ip(ip, None, 0),
        (lit, Some(mode)) if lit == ENABLE | STATE => Pipes::adopt_panel_ip(io, &mode, ip)?,
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
        scaler: None,
        min_hblank: 0,
        audio: false,
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

/// The post-plane release of `rp`'s pipe, bracketed for a pipe with audio
/// by `intel_audio_cdclk_change_pre` / `_post` (the release may lower
/// CDCLK, and `AUD_TS_CDCLK_M/N` follow it).
pub(crate) fn release_audio_pipe<M: MmioWindow + ?Sized>(
    io: &M,
    rp: &mut RoutePipe,
    audio_pipe: bool,
) -> Result<(), PipeEnableError> {
    if audio_pipe {
        let _ = audio::cdclk_change_pre(io);
    }
    let result = rp.pipes.release(io, rp.pipe, rp.dmc);
    if audio_pipe {
        let _ = audio::cdclk_change_post(io);
    }
    result
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

fn d2d_err(_: crate::intel_gpu_xe2lpd::IpError) -> ExternalError {
    // The display-14 helper reports the same failed 100-us state
    // observation as a PHY timeout.
    phy_err(Cx0Error::Timeout)
}

// ── The port's PHY: LT on display 35, Cx0 elsewhere ─────────────

/// The LT PHY behind the probe's port on a display-35 view (`HAS_LT_PHY`),
/// owning the probe's lanes (DP-alt, the connection's lane limit, the VBT
/// reversal); `None` on every Cx0 view.
pub(crate) fn lt_phy<'a, M: MmioWindow + ?Sized>(
    io: &'a M,
    port: XeLpgPort,
    dp_alt: bool,
    max_lanes: u8,
    reversed: bool,
) -> Result<Option<crate::intel_gpu_lt_phy::LtPhy<'a, M>>, ExternalError> {
    if !io.has_lt_phy() {
        return Ok(None);
    }
    let port =
        crate::intel_gpu_lt_phy::LtPort::from_xelpg(port).ok_or(ExternalError::UnsupportedPort)?;
    crate::intel_gpu_lt_phy::LtPhy::new(io, port, dp_alt, max_lanes, reversed)
        .map(Some)
        .map_err(phy_err)
}

/// The LT PHY behind `probe`. A Thunderbolt-alt connection's PHY belongs to
/// the TBT fabric, so no LT transaction may reach it: `intel_xe3plpd_pll_disable`
/// takes the TBT clock instead of `intel_lt_phy_pll_disable`, and the TBT PLL's
/// enable is a no-op (`xe3plpd_tbt_pll_funcs`).
fn probe_lt_phy<'a, M: MmioWindow + ?Sized>(
    io: &'a M,
    probe: &MtlSinkProbe,
) -> Result<Option<crate::intel_gpu_lt_phy::LtPhy<'a, M>>, ExternalError> {
    if probe.tbt() && io.has_lt_phy() {
        return Err(phy_err(Cx0Error::ProtocolMismatch));
    }
    lt_phy(
        io,
        probe.port,
        probe.dp_alt(),
        probe.tc.map_or(4, |tc| tc.max_lanes),
        probe.lane_reversal,
    )
}

/// `encoder->set_signal_levels` on an 8b/10b link's `lanes` at `levels`:
/// `intel_lt_phy_set_signal_levels` over the DP 1.4 table
/// (`xe3plpd_lt_trans_dp14`; UHBR takes [`uhbr_levels`]) at each lane's
/// `intel_ddi_dp_level`, or `intel_cx0_phy_set_signal_levels`. Both return
/// without a transaction in Thunderbolt alt mode: the fabric drives the
/// lanes.
fn port_levels<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlSinkProbe,
    rate: crate::intel_gpu_pll::LinkRate,
    lanes: u8,
    levels: &[(u8, u8); 4],
) -> Result<(), ExternalError> {
    if probe.tbt() {
        return Ok(());
    }
    match probe_lt_phy(io, probe)? {
        Some(lt) => {
            let lanes = usize::from(lanes);
            if !(1..=levels.len()).contains(&lanes) {
                return Err(phy_err(Cx0Error::ProtocolMismatch));
            }
            let mut index = [0u8; 4];
            for (slot, &(swing, pre_emph)) in index.iter_mut().zip(levels) {
                *slot = crate::intel_gpu_xelpg::preset_index(swing, pre_emph) as u8;
            }
            lt.program_signal_levels(
                crate::intel_gpu_lt_phy::LtSignalProtocol::Dp14,
                &index[..lanes],
            )
            .map_err(phy_err)
        }
        None => set_signal_levels(
            &Cx0Phy::with_lanes(io, probe.port, probe.phy_lanes()?),
            rate,
            lanes,
            levels,
        )
        .map_err(phy_err),
    }
}

/// `intel_ddi_disable_clock` for a non-TBT route: `intel_lt_phy_pll_disable`
/// or `intel_cx0pll_disable` of the probe's lanes. A TBT route takes
/// [`disable_tbt_clock`] instead (`intel_xe3plpd_pll_disable`,
/// `intel_mtl_pll_disable_clock`).
fn port_pll_disable<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlSinkProbe,
) -> Result<(), ExternalError> {
    match probe_lt_phy(io, probe)? {
        Some(lt) => lt.disable().map_err(phy_err),
        None => disable_port_pll_lanes(io, probe.port, probe.phy_lanes()?).map_err(phy_err),
    }
}

/// Everything [`activate`] needs, owning the Type-C connection and the
/// AUX power request from probe until [`release_probe`] or a route
/// release.
#[derive(Clone, Debug)]
pub struct MtlSinkProbe {
    /// Qualified display register layout retained from probe.
    display_ip: DisplayIp,
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
    pub edid: alloc::boxed::Box<[u8; EDID_CAPACITY]>,
    /// Valid EDID length.
    pub edid_len: usize,
    /// The DSC configuration when the stream needs compression; the
    /// negotiated link is then the plan's.
    pub dsc: Option<DscPlan>,
    /// `crtc_state->pipe_bpp`: 24, or 18 (6 bpc, dithered) when the sink's
    /// EDID limits the pipe to it or only 18 bpp fits the link; the
    /// negotiated link is then Linux's (`intel_dp_compute_link_config_wide`).
    pub pipe_bpp: u32,
    /// The 128b/132b link when `narf.intel.uhbr=1` and only a UHBR rate
    /// carries the stream at its bpp. `negotiated` then carries the UHBR
    /// link's lane count and bandwidth beside the 8b/10b ceiling rate that
    /// could not.
    pub uhbr: Option<UhbrPlan>,
    /// The output format and protocol-converter setup
    /// (`narf.intel.hdmi14_ext=1`, [`color::dp_output`]); RGB with no PCON
    /// writes otherwise.
    pub output: color::DpOutput,
    /// The sink's ELD (`drm_edid_to_eld`) when the SST route enables audio
    /// (`narf.intel.hdmi14_ext=1`, `intel_dp_has_audio`: every display-12+
    /// port, a sink that declares basic audio or audio descriptors).
    pub audio: Option<alloc::boxed::Box<[u8; audio::MAX_ELD_BYTES]>>,
}

/// A 128b/132b SST route (`intel_dp_is_uhbr`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UhbrPlan {
    /// Rate, lanes and pipe bpp ([`uhbr::wide_link`]).
    pub link: uhbr::UhbrLink,
    /// MTP time slots and M/N ([`uhbr::mtp_tu`]).
    pub stream: uhbr::UhbrStream,
    /// `intel_dp_use_post_lt_adj_req` (the sink's
    /// `DP_POST_LT_ADJ_REQ_SUPPORTED`).
    pub post_lt_adj_req: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct MstStreamConfig {
    pub master: Transcoder,
    pub slots: u8,
}

impl MtlSinkProbe {
    /// Display version whose register layout this probe owns.
    pub fn display_version(&self) -> u16 {
        self.display_ip.ver()
    }

    /// `crtc_state->port_clock` of the planned link: the UHBR rate, or the
    /// negotiated 8b/10b rate.
    fn port_clock_khz(&self) -> u32 {
        match self.uhbr {
            Some(plan) => plan.link.rate.link_rate(),
            None => link_clock_khz(self.negotiated.rate),
        }
    }

    fn tbt(&self) -> bool {
        self.tc.is_some_and(|tc| tc.mode == TcMode::TbtAlt)
    }
    fn clock_mask(&self) -> Result<u32, ExternalError> {
        Ok(if self.tbt() {
            crate::intel_gpu_xelpg::TBT_CLOCK_REQUEST | crate::intel_gpu_xelpg::TBT_CLOCK_ACK
        } else if self.display_ip == DisplayIp::NovaLakeS {
            // The LT PHY requests MacCLK on lane 0 whichever lanes it owns
            // (`intel_lt_phy_pll_enable`).
            crate::intel_gpu_xelpg::lane_pclk_pll_request(0)
                | crate::intel_gpu_xelpg::lane_pclk_pll_ack(0)
        } else {
            pll_clock_mask(self.phy_lanes()?)
        })
    }
    /// `INTEL_TC_PIN_ASSIGNMENT_D`: the LT transmitter layout of a two-lane
    /// DP-alt connection that keeps USB.
    fn pin_assignment_d(&self) -> bool {
        self.tc.is_some_and(|tc| {
            tc.mode == TcMode::DpAlt
                && tc.pin_assignment == crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D
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
    let profile = ExternalDisplayProfile::for_generation(generation)
        .ok_or(ExternalError::UnsupportedGeneration)?;
    probe_link_profile(io, profile, port, legacy_port)
}

fn probe_link_profile<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<LinkProbe, ExternalError> {
    let display_ip = profile.display_ip;
    // Display >= 20 relocates combo DDI B's PHY/AUX register views into
    // PICA; the display-20 pass runs over `PicaFlushed`, which applies it.
    // TC1–TC4 already use the PICA-layout addresses carried by XeLpgPort.
    // Display 30's mandatory fixed-refresh VRR timing generator is owned by
    // Pipes.
    if !profile.admits_port(port) {
        return Err(ExternalError::UnsupportedPort);
    }
    if !profile.admits_view(io) {
        return Err(ExternalError::UnsupportedGeneration);
    }
    // Do not acquire/release Type-C ownership behind an inherited live DDI.
    if read(io, port.ddi_buf_ctl())? & DDI_BUF_CTL_ENABLE != 0 {
        return Err(ExternalError::PortBusy);
    }
    let tc = match port.tc_index() {
        Some(_) => Some(tc_connect_for(
            io,
            port,
            legacy_port,
            1,
            profile.tc_profile(),
        )?),
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
    let raw = crate::dp_link_training::read_receiver_caps(&mut aux)
        .map_err(|e| rollback(ExternalError::Link(LinkError::AuxFailure(e))))?;
    Ok(LinkProbe {
        display_ip,
        port,
        tc,
        raw,
    })
}

#[derive(Copy, Clone, Debug)]
struct LinkProbe {
    display_ip: DisplayIp,
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

/// Probe the sink on `port` (UHBR as `narf.intel.uhbr` says).
pub fn probe_sink<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    let link = probe_link(io, generation, port, legacy_port)?;
    probe_sink_link(io, link, uhbr::opted_in(), color::opted_in())
}

/// [`probe_sink`] for an exact source profile (Nova Lake-S has no
/// generation of its own), with UHBR off.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn probe_sink_profile<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    port: XeLpgPort,
    legacy_port: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    probe_sink_profile_uhbr(io, profile, port, legacy_port, false)
}

/// [`probe_sink_profile`] with an explicit `narf.intel.uhbr` decision.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn probe_sink_profile_uhbr<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    port: XeLpgPort,
    legacy_port: bool,
    uhbr: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    let link = probe_link_profile(io, profile, port, legacy_port)?;
    probe_sink_link(io, link, uhbr, false)
}

/// [`probe_sink_profile`] with an explicit `narf.intel.hdmi14_ext` decision
/// (UHBR off).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn probe_sink_profile_ext<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    port: XeLpgPort,
    legacy_port: bool,
    ext: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    let link = probe_link_profile(io, profile, port, legacy_port)?;
    probe_sink_link(io, link, false, ext)
}

/// Whether `port`'s PHY is a C10 (`intel_encoder_is_c10phy`): DDI A/B on
/// Meteor and Lunar Lake, DDI A on Panther Lake. Nova Lake's LT PHY is not.
fn c10_phy<M: MmioWindow + ?Sized>(io: &M, port: XeLpgPort) -> bool {
    !io.has_lt_phy() && crate::intel_gpu_xelpg::phy_kind(io, port) == PhyKind::C10
}

/// `intel_dp_compute_link_config_wide` with the 128b/132b common rates
/// (`narf.intel.uhbr=1`): `Ok(Some)` when only a UHBR rate carries the
/// stream at its bpp, `Ok(None)` when the 8b/10b negotiation stands (an
/// 8b/10b link carries it, no UHBR rate is common, or nothing fits a sink
/// without DSC), a typed refusal for what is not implemented.
fn plan_uhbr<A: crate::dp_aux::AuxChannel + ?Sized>(
    aux: &mut A,
    link: &LinkProbe,
    c10: bool,
    limits: &dsc::LinkLimits,
    mode: &Mode,
    max_bpp: u32,
    sink_dsc: bool,
) -> Result<Option<UhbrPlan>, ExternalError> {
    let source = uhbr::source_rates(link.display_ip, c10);
    if source == 0 {
        return Ok(None);
    }
    let sink = uhbr::read_sink(aux, &link.raw)
        .map_err(|e| ExternalError::Link(LinkError::AuxFailure(e)))?;
    let common = sink.rates & source;
    if common == 0 {
        return Ok(None);
    }
    match uhbr::wide_link(limits, common, mode, max_bpp) {
        uhbr::WideLink::Uhbr(chosen) => {
            if link.tbt() {
                return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Tbt));
            }
            if sink.lttpr {
                return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Lttpr));
            }
            let stream =
                uhbr::mtp_tu(&chosen, mode).ok_or(ExternalError::Uhbr(uhbr::UhbrRefusal::Slots))?;
            Ok(Some(UhbrPlan {
                link: chosen,
                stream,
                post_lt_adj_req: sink.post_lt_adj_req,
            }))
        }
        uhbr::WideLink::None if sink_dsc => Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Dsc)),
        uhbr::WideLink::EightTenB | uhbr::WideLink::None => Ok(None),
    }
}

fn probe_sink_link<M: MmioWindow + ?Sized>(
    io: &M,
    link: LinkProbe,
    uhbr_on: bool,
    ext: bool,
) -> Result<MtlSinkProbe, ExternalError> {
    let LinkProbe {
        display_ip,
        port,
        tc,
        raw,
    } = link;
    let rollback = |error| {
        let _ = link.release(io);
        error
    };
    let mut aux = link.aux(io);
    let caps = DpcdCaps::decode(&raw);
    let max_downspread = raw[DP_MAX_DOWNSPREAD];
    let mut edid = alloc::boxed::Box::new([0u8; EDID_CAPACITY]);
    let edid_len = read_full_edid(&mut aux, edid.as_mut_slice())
        .map_err(|e| rollback(ExternalError::Edid(e)))?;
    let mode = crate::intel_gpu_dp::mode_from_edid(&edid[..edid_len]).map_err(|e| {
        rollback(match e {
            crate::intel_gpu_dp::DpError::Edid(e) => ExternalError::Edid(e),
            crate::intel_gpu_dp::DpError::Link(e) => ExternalError::Link(e),
            crate::intel_gpu_dp::DpError::Modeset(e) => ExternalError::Modeset(e),
        })
    })?;
    // narf.intel.hdmi14_ext=1: intel_dp_update_420's DFP facts and
    // intel_dp_compute_formats' output format (YCbCr 4:4:4 into a PCON that
    // converts it to 4:2:0).
    let output = if ext {
        let dfp = color::read_dfp_caps(&mut aux, &raw)
            .map_err(|e| rollback(ExternalError::Link(LinkError::AuxFailure(e))))?;
        color::dp_output(&raw, dfp, &edid[..edid_len], &mode)
            .map_err(|e| rollback(ExternalError::Color(e)))?
    } else {
        color::DpOutput::default()
    };
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
    // narf.intel.hdmi14_ext=1: Linux's pipe maximum without the 8 bpc
    // ceiling (compute_sink_pipe_bpp with max_requested_bpc 12). A branch
    // device keeps the 8 bpc search: Linux bounds its depth by the DFP's
    // max bpc and TMDS clock (intel_dp_hdmi_compute_bpc), not modelled.
    let deep_bpp = if ext && !color::dp_is_branch(&raw) {
        color::max_pipe_bpp(color::sink_display_bpc(&edid[..edid_len]))
    } else {
        max_bpp
    };
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
    // narf.intel.uhbr=1: the same search over the UHBR common rates too.
    let uhbr_plan = if uhbr_on {
        plan_uhbr(
            &mut aux,
            &link,
            c10_phy(io, port),
            &limits,
            &mode,
            max_bpp,
            sink.dsc.dpcd.supports_dsc(),
        )
        .map_err(rollback)?
    } else {
        None
    };
    if let Some(p) = uhbr_plan {
        let lanes = u32::from(p.link.lanes);
        negotiated = NegotiatedLink {
            rate: ceiling,
            lanes: p.link.lanes,
            demand_kbps: uhbr::link_required(
                lanes,
                mode.pixel_clock_khz,
                u32::from(mode.h_active),
                p.link.pipe_bpp * 16,
            ) * 8,
            payload_kbps: uhbr::max_link_data_rate(p.link.rate, lanes) * 8,
            over_budget: false,
        };
        pipe_bpp = p.link.pipe_bpp;
    }
    // A 6 bpc (or, under narf.intel.hdmi14_ext=1, 10 or 12 bpc) link:
    // Linux's own (intel_dp_compute_link_config_wide).
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
    // intel_dp_compute_link_config_wide above 24 bpp (deep colour): the
    // deepest bpp an 8b/10b link carries, before any DSC. UHBR keeps its
    // 24 bpp search (a deep stream is never planned onto 128b/132b here).
    let deep = if uhbr_plan.is_none() && deep_bpp > dsc::PIPE_BPP {
        dsc::uncompressed_link_upto(&limits, &mode, deep_bpp)
            .filter(|link| link.pipe_bpp > dsc::PIPE_BPP)
    } else {
        None
    };
    if uhbr_plan.is_some() {
        // The 128b/132b link above is Linux's choice.
    } else if let Some(link) = deep {
        negotiated = six_bpc(link)
            .ok_or_else(|| rollback(ExternalError::Dsc(DscRefusal::LinkRateUnqualified)))?;
        pipe_bpp = link.pipe_bpp;
    } else if !sink.dsc.dpcd.supports_dsc() && (negotiated.over_budget || max_bpp < dsc::PIPE_BPP) {
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
    // intel_dp_audio_compute_config (intel_dp_has_audio: every display-12+
    // port; a sink with audio descriptors).
    let audio = (ext && audio::edid_has_audio(&edid[..edid_len]))
        .then(|| alloc::boxed::Box::new(audio::eld_from_edid(&edid[..edid_len], true)));
    // intel_dp_min_bpp: a YCbCr output has no 6 bpc pipe.
    if output.ycbcr444 && pipe_bpp < dsc::PIPE_BPP {
        return Err(rollback(ExternalError::Color(
            color::ColorRefusal::Ycbcr444Bpp,
        )));
    }
    if !io.display_access_ok() {
        return Err(rollback(ExternalError::AccessLost));
    }
    Ok(MtlSinkProbe {
        display_ip,
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
        uhbr: uhbr_plan,
        output,
        audio,
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
    /// The trained link. On a 128b/132b route only its lane count is the
    /// link's; the rate and presets are in `probe.uhbr` and `uhbr`.
    pub trained: TrainedLink,
    state: RouteState,
    /// The Pipe B–D (and transcoder) the route was activated on.
    pipe: Pipe,
    /// The pipe's reservation until its post-plane release is proven.
    reservation: Option<RoutePipe>,
    /// The Pipe B–D owner as the proven release left it, until a sibling
    /// route adopts it ([`MtlRoute::take_shared_pipes`]).
    retired: Option<Pipes>,
    /// Plane, transcoder and port are disabled. Only the source FEC-off
    /// acknowledgement is pending before clock teardown can resume.
    awaiting_fec_stop: bool,
    /// A 128b/132b route's trained TX FFE presets and payload state.
    pub uhbr: Option<UhbrTrained>,
    /// The audio stream `intel_audio_codec_enable` started, until its
    /// disable.
    audio: Option<audio::AudioStream>,
}

/// What a 128b/132b route has trained and allocated.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UhbrTrained {
    /// `intel_dp->train_set`: the per-lane TX FFE presets.
    pub presets: [u8; 4],
    /// The sink's payload table holds VCPID 1 (`drm_dp_dpcd_write_payload`).
    pub sink_payload: bool,
    /// `TRANS_DDI_DP_VC_PAYLOAD_ALLOC` is set.
    pub vc_payload: bool,
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
    activate_with_payload(io, probe, fb, display, None, &mut |_| Ok(()))
}

/// [`activate`] beside a live sibling route: the new pipe joins the
/// layout `beside` holds programmed (see [`preflight_clock_ip`]).
#[allow(clippy::result_large_err)]
pub(crate) fn activate_beside<M: MmioWindow + ?Sized>(
    io: &M,
    probe: MtlSinkProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
    beside: Option<Pipes>,
) -> Result<MtlExternalRoute, ActivateError> {
    activate_with_payload(io, probe, fb, display, beside, &mut |_| Ok(()))
}

#[allow(clippy::result_large_err)]
fn activate_with_payload<M: MmioWindow + ?Sized>(
    io: &M,
    mut probe: MtlSinkProbe,
    fb: Framebuffer,
    display: &MtlDisplay,
    beside: Option<Pipes>,
    payload: &mut dyn FnMut(Transcoder) -> Result<(), ExternalError>,
) -> Result<MtlExternalRoute, ActivateError> {
    if let Err(e) = probe.phy_lanes() {
        return Err(ActivateError::Refused(probe, e));
    }
    if let Err(e) = crate::intel_gpu_modeset::validate_framebuffer_mode(&fb, &probe.mode) {
        return Err(ActivateError::Refused(probe, e.into()));
    }
    let choice = match preflight_clock_ip(
        io,
        probe.port,
        display,
        probe.clock_mask().expect("validated above"),
        probe.display_ip,
        beside,
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
    let mut ext = match external_pipe(
        &choice,
        probe.port,
        &probe.mode,
        &fb,
        probe.port_clock_khz(),
        probe.dsc.map(|plan| plan.term(&probe.mode)),
        probe.pipe_bpp,
    ) {
        Ok(ext) => ext,
        Err(e) => return Err(ActivateError::Refused(probe, e)),
    };
    // intel_dp_compute_min_hblank: display 30+ programs DP_MIN_HBLANK_CTL
    // for 128b/132b SST (zero for 8b/10b SST).
    if probe.uhbr.is_some() && probe.display_ip.is_display30() {
        ext.min_hblank = uhbr::min_hblank(&probe.mode, probe.pipe_bpp);
    }
    ext.audio = probe.audio.is_some() && probe.mst.is_none();
    if let Err(e) = choice.pipes.admit(io, &ext) {
        return Err(ActivateError::Refused(probe, e.into()));
    }
    let route_uhbr = probe.uhbr.map(|_| UhbrTrained::default());
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
        retired: None,
        awaiting_fec_stop: false,
        uhbr: route_uhbr,
        audio: None,
    };
    match program(io, &mut route, choice, &ext, display.pipe_dmc, payload) {
        Ok(()) => {
            route.state = RouteState::Live;
            Ok(route)
        }
        Err(mut e) => {
            if let Err(stop_error) = stop_local(io, &mut route) {
                route.state = RouteState::Quarantined;
                if route.awaiting_fec_stop {
                    e = stop_error;
                }
            }
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
    route.reservation = Some(crate::intel_gpu_xelpg_hdmi::reserve_audio_pipe(
        io, choice, ext, dmc,
    )?);
    let (rate, lanes) = (route.probe.negotiated.rate, route.probe.negotiated.lanes);
    if let Some(plan) = route.probe.uhbr {
        // A 128b/132b link trains once at the planned rate and lanes; a
        // failure stops the route (Linux's reduced-parameter retry is not
        // run).
        enable_port_uhbr(io, route, &plan)?;
        let trained = TrainedLink {
            rate,
            lanes,
            vswing_pe: Default::default(),
        };
        finish(io, route, &trained, payload)?;
        route.trained = trained;
        return Ok(());
    }
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
        disable_port(io, route)?;
        finish_port_stop(io, route)?;
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
    // intel_dp_set_power(D0) and intel_dp_configure_protocol_converter for
    // a PCON under narf.intel.hdmi14_ext=1 (best effort, as in Linux).
    if let Some(pcon) = route.probe.output.pcon {
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
        let _ = aux.dpcd_write(dsc::DP_SET_POWER, &[dsc::DP_SET_POWER_D0]);
        color::configure_protocol_converter(&mut aux, &pcon);
    }
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
    let receiver = ReceiverTraining::for_receiver(
        &route.probe.caps,
        route.probe.max_downspread,
        route.probe.mst.is_some(),
    );
    let enhanced = if receiver.enhanced_framing {
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
    enable_d2d(io, route.probe.display_ip, port).map_err(d2d_err)?;
    if !route.probe.tbt()
        && route
            .probe
            .mst
            .is_none_or(|mst| mst.master == route.pipe.transcoder())
    {
        port_levels(io, &route.probe, pll_rate, lanes, &[(0, 0); 4])?;
    }
    program_port_buf_ctl(io, port, lanes);
    write(
        io,
        port.ddi_buf_ctl(),
        ddi_enable_value(route.probe.display_ip, lanes),
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
    let result = train_link_with_receiver(&mut aux, rate, lanes, Some(receiver), |us| {
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

/// `TRANS_DDI_FUNC_CTL` for 128b/132b SST (`intel_ddi_transcoder_func_reg_val_get`
/// with `intel_dp_is_uhbr`): `TRANS_DDI_MODE_SELECT_FDI_OR_128B132B`, the
/// port width and the MST transport select of the route's own transcoder
/// (`mst_master_transcoder = cpu_transcoder`).
fn uhbr_func(probe: &MtlSinkProbe, trans: Transcoder, lanes: u8) -> u32 {
    (dp_func(probe.port, lanes, probe.pipe_bpp) & !TRANS_DDI_MODE_MASK)
        | TRANS_DDI_MODE_128B132B
        | trans_ddi_mst_transport(trans)
}

/// `encoder->set_signal_levels` on a 128b/132b link: each lane's TX FFE
/// preset from `xe3plpd_lt_trans_uhbr` (`intel_lt_phy_set_signal_levels`)
/// or `mtl_c20_trans_uhbr` (`intel_cx0_phy_set_signal_levels`).
fn uhbr_levels<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlSinkProbe,
    lanes: u8,
    presets: &[u8; 4],
) -> Result<(), ExternalError> {
    match probe_lt_phy(io, probe)? {
        Some(lt) => {
            let lanes = usize::from(lanes);
            if !(1..=presets.len()).contains(&lanes) {
                return Err(phy_err(Cx0Error::ProtocolMismatch));
            }
            let mut index = [0u8; 4];
            for (slot, preset) in index.iter_mut().zip(presets) {
                *slot = preset & 0xf;
            }
            lt.program_signal_levels(
                crate::intel_gpu_lt_phy::LtSignalProtocol::Uhbr,
                &index[..lanes],
            )
            .map_err(phy_err)
        }
        None => set_signal_levels_uhbr(
            &Cx0Phy::with_lanes(io, probe.port, probe.phy_lanes()?),
            lanes,
            presets,
        )
        .map_err(phy_err),
    }
}

/// `intel_ddi_enable_clock` at a UHBR rate: `intel_lt_phy_pll_enable` over
/// `xe3plpd_lt_dp_uhbr*` or `intel_cx0pll_enable` over the C20 DP 2.0 image
/// ([`dp_uhbr_pll_request`]), after `mtl_port_buf_ctl_io_selection` (never
/// Thunderbolt: that refuses at probe).
fn enable_clock_uhbr<M: MmioWindow + ?Sized>(
    io: &M,
    probe: &MtlSinkProbe,
    rate: uhbr::UhbrRate,
    lanes: u8,
) -> Result<(), ExternalError> {
    let port = probe.port;
    if probe.tbt() {
        return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Tbt));
    }
    let buf = read(io, port.buf_ctl1())?;
    write(io, port.buf_ctl1(), buf & !PORT_BUF_IO_SELECT_TBT)?;
    match probe_lt_phy(io, probe)? {
        Some(lt) => {
            let rate = crate::intel_gpu_lt_phy::LtDpRate::from_clock_khz(rate.link_rate())
                .filter(|rate| rate.is_uhbr())
                .ok_or(phy_err(Cx0Error::UnsupportedRate))?;
            lt.enable_dp(crate::intel_gpu_lt_phy::LtDpEnable {
                rate,
                lane_count: lanes,
                pin_assignment_d: probe.pin_assignment_d(),
                ssc_enabled: probe.ssc,
            })
            .map_err(phy_err)
        }
        None => {
            let mut request = dp_uhbr_pll_request(
                crate::intel_gpu_xelpg::phy_kind(io, port),
                rate.link_rate(),
                lanes,
                probe.dp_alt(),
                probe.legacy(),
                probe.ssc,
                probe.display_ip.is_display30(),
            )
            .map_err(phy_err)?;
            request.lanes = probe.phy_lanes()?;
            enable_port_pll_state(io, port, &request).map_err(phy_err)
        }
    }
}

/// The source side of a 128b/132b training: `DP_TP_CTL`'s link-training
/// field (`intel_ddi_set_link_train`) and the TX FFE presets.
struct UhbrPort<'a, M: MmioWindow + ?Sized> {
    io: &'a M,
    probe: &'a MtlSinkProbe,
    trans: Transcoder,
    lanes: u8,
    presets: [u8; 4],
}

impl<M: MmioWindow + ?Sized> uhbr::UhbrSource for UhbrPort<'_, M> {
    type Error = ExternalError;
    fn pattern(&mut self, pattern: uhbr::SourcePattern) -> Result<(), ExternalError> {
        let bits = match pattern {
            uhbr::SourcePattern::Tps1 => DP_TP_CTL_LINK_TRAIN_PAT1,
            uhbr::SourcePattern::Tps2 => DP_TP_CTL_LINK_TRAIN_PAT2,
            uhbr::SourcePattern::Normal => DP_TP_CTL_LINK_TRAIN_NORMAL,
        };
        let old = read(self.io, dp_tp_ctl(self.trans))?;
        write(
            self.io,
            dp_tp_ctl(self.trans),
            (old & !DP_TP_CTL_LINK_TRAIN_MASK) | bits,
        )
    }
    fn presets(&mut self, presets: &[u8; 4]) -> Result<(), ExternalError> {
        uhbr_levels(self.io, self.probe, self.lanes, presets)?;
        self.presets = *presets;
        Ok(())
    }
}

/// `mtl_ddi_pre_enable_dp` steps 3-7.a on a 128b/132b link, preceded by
/// `intel_dp_128b132b_sdp_crc16`: the UHBR port PLL, `TRANS_CLK_SEL`,
/// `TRANS_DP2_CTL` 128b/132b and `TRANS_DDI_FUNC_CTL` configured without
/// ENABLE, `DP_SET_POWER` D0, `mtl_ddi_prepare_link_retrain` (`DP_TP_CTL`
/// TPS1 in MST mode, D2D, zeroed presets, the 40-bit `PORT_BUF_CTL1`, the
/// 40-bit `DDI_CTL_DE`), `intel_dp_prepare_link_train`, the 128b/132b
/// training and `intel_dp_stop_link_train`, then the sink's VC payload
/// (VCPID 1, slot 0, `tu` slots).
fn enable_port_uhbr<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
    plan: &UhbrPlan,
) -> Result<(), ExternalError> {
    let probe = &route.probe;
    let port = probe.port;
    let trans = route_pipe(route)?.transcoder();
    let (rate, lanes) = (plan.link.rate, plan.link.lanes);
    let mut aux = IntelAux::xelpdp(io, port.aux_base(), probe.tbt());
    let mut clock = uhbr::SystemClock;
    let link = |e| ExternalError::Link(LinkError::AuxFailure(e));
    // DP v2.0 SCR on SDP CRC16 for the 128b/132b link layer (best effort,
    // as Linux's unchecked write).
    let _ = aux.dpcd_write(
        uhbr::DP_SDP_ERROR_DETECTION_CONFIGURATION,
        &[uhbr::DP_SDP_CRC16_128B132B_EN],
    );
    // 3./5. TBT deselect and the port PLL.
    enable_clock_uhbr(io, probe, rate, lanes)?;
    // 6.a TRANS_CLK_SEL; 6.b TRANS_DP2_CTL; 6.c TRANS_DDI_FUNC_CTL.
    write(io, trans_clk_sel(trans), trans_clk_sel_port(port))?;
    write(io, trans_dp2_ctl(trans), TRANS_DP2_128B132B_CHANNEL_CODING)?;
    write(
        io,
        trans_ddi_func_ctl(trans),
        uhbr_func(probe, trans, lanes) & !TRANS_DDI_FUNC_ENABLE,
    )?;
    // intel_dp_set_power(D0): three tries 1 ms apart, failures only logged.
    for _ in 0..3 {
        if aux
            .dpcd_write(DPCD_SET_POWER, &[dsc::DP_SET_POWER_D0])
            .is_ok()
        {
            break;
        }
        uhbr::Clock::sleep_us(&mut clock, 1_000);
    }
    // mtl_ddi_prepare_link_retrain.
    write(
        io,
        dp_tp_ctl(trans),
        DP_TP_CTL_ENABLE | DP_TP_CTL_LINK_TRAIN_PAT1 | DP_TP_CTL_MODE_MST,
    )?;
    enable_d2d(io, probe.display_ip, port).map_err(d2d_err)?;
    uhbr_levels(io, probe, lanes, &[0; 4])?;
    program_port_buf_ctl_width(io, port, lanes, true);
    write(
        io,
        port.ddi_buf_ctl(),
        ddi_enable_value(probe.display_ip, lanes) | DDI_BUF_PORT_DATA_40BIT,
    )?;
    wait_port_buf_active(io, port).map_err(phy_err)?;
    // 6.k intel_dp_prepare_link_train (sink half) and the 128b/132b
    // training; no LTTPR is in the path (refused at probe).
    uhbr::prepare(&mut aux, rate, lanes, plan.post_lt_adj_req).map_err(link)?;
    let mut source = UhbrPort {
        io,
        probe,
        trans,
        lanes,
        presets: [0; 4],
    };
    let presets = match uhbr::train(&mut aux, &mut source, &mut clock, lanes, 0) {
        Ok(presets) => presets,
        Err(uhbr::TrainError::Link(failure)) => {
            return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Training(failure)))
        }
        Err(uhbr::TrainError::Source(error)) => return Err(error),
    };
    // 6.n intel_dp_stop_link_train: the normal pattern, then the intra-hop
    // indication (Linux only logs one that does not clear).
    let _ = uhbr::stop_train(&mut aux, &mut source, &mut clock)?;
    // 7.a 128b/132b SST: VCPID 1, start slot 0, tu slots.
    let sink_payload = uhbr::write_payload(&mut aux, &mut clock, 1, 0, plan.stream.tu);
    route.uhbr = Some(UhbrTrained {
        presets,
        sink_payload,
        vc_payload: false,
    });
    if !sink_payload {
        return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Payload));
    }
    Ok(())
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
    } else if let Some(lt) = probe_lt_phy(io, probe)? {
        // intel_lt_phy_pll_enable over xe3plpd_lt_dp_tables (DP 1.4 rates).
        let rate = crate::intel_gpu_lt_phy::LtDpRate::from_clock_khz(rate.megabits_per_sec() * 100)
            .filter(|rate| !rate.is_uhbr())
            .ok_or(phy_err(Cx0Error::UnsupportedRate))?;
        lt.enable_dp(crate::intel_gpu_lt_phy::LtDpEnable {
            rate,
            lane_count: lanes,
            pin_assignment_d: probe.pin_assignment_d(),
            ssc_enabled: probe.ssc,
        })
        .map_err(phy_err)?;
    } else {
        let mut request = dp_pll_request(
            crate::intel_gpu_xelpg::phy_kind(io, port),
            port,
            rate,
            lanes,
            probe.dp_alt(),
            probe.legacy(),
            probe.ssc,
        )
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
        Change::Levels if !state.dirty && !probe.tbt() => {
            port_levels(io, probe, state.rate, state.lanes, &state.levels)
        }
        Change::Levels => Ok(()),
        Change::Pattern => {
            if state.pattern == 1 && state.dirty {
                if state.lanes > probe.tc.map_or(4, |tc| tc.max_lanes) {
                    return Err(ExternalError::TrainingMismatch);
                }
                let ddi = read(io, port.ddi_buf_ctl())?;
                write(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
                wait_port_buf_idle(io, port).map_err(phy_err)?;
                disable_d2d(io, probe.display_ip, port).map_err(d2d_err)?;
                if probe.tbt() {
                    disable_tbt_clock(io, port).map_err(phy_err)?;
                } else {
                    port_pll_disable(io, probe)?;
                }
                enable_clock(io, probe, state.rate, state.lanes)?;
                if !probe.tbt() {
                    port_levels(io, probe, state.rate, state.lanes, &state.levels)?;
                }
                enable_d2d(io, probe.display_ip, port).map_err(d2d_err)?;
                program_port_buf_ctl(io, port, state.lanes);
                write(
                    io,
                    port.ddi_buf_ctl(),
                    ddi_enable_value(probe.display_ip, state.lanes),
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

fn sink_fec_detected<M: MmioWindow + ?Sized>(io: &M, probe: &MtlSinkProbe) -> bool {
    let mut aux = IntelAux::xelpdp(io, probe.port.aux_base(), probe.tbt());
    dsc::wait_fec_detected(&mut aux, |us| {
        let _ = narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_ns(u64::from(us) * 1_000),
        );
    })
}

/// Display 30's intel_ddi_enable_fec retries the source enable only after
/// observing it off. Some MST hubs never report decode-disabled over AUX.
fn enable_stream_fec<M: MmioWindow + ?Sized>(
    io: &M,
    trans: Transcoder,
    probe: &MtlSinkProbe,
) -> Result<(), ExternalError> {
    let lost = |_| ExternalError::AccessLost;
    for attempt in 0..=3 {
        if attempt > 0 {
            dsc::disable_fec(io, trans).map_err(lost)?;
            if !dsc::poll_fec_live(io, trans, false).map_err(lost)? {
                continue;
            }
        }
        dsc::enable_fec(io, trans).map_err(lost)?;
        if !probe.display_ip.is_display30()
            || (dsc::poll_fec_live(io, trans, true).map_err(lost)? && sink_fec_detected(io, probe))
        {
            return Ok(());
        }
    }
    Err(ExternalError::FecNotReady)
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
    let mode = route.probe.mode;
    let pll_rate = crate::intel_gpu_modeset::to_pll_rate(trained.rate);
    let lanes = trained.lanes;
    let uhbr_plan = route.probe.uhbr;
    let mut levels = [(0u8, 0u8); 4];
    for (i, lane) in trained.vswing_pe.lanes.iter().enumerate() {
        levels[i] = (lane.swing, lane.pre_emph);
    }
    // A 128b/132b link keeps the presets its training left and already runs
    // the normal pattern (intel_dp_stop_link_train in enable_port_uhbr).
    if uhbr_plan.is_none()
        && !route.probe.tbt()
        && route
            .probe
            .mst
            .is_none_or(|mst| mst.master == route.pipe.transcoder())
    {
        port_levels(io, &route.probe, pll_rate, lanes, &levels)?;
    }
    let rp = route
        .reservation
        .as_mut()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))?;
    let (pipe, trans) = (rp.pipe, rp.transcoder());
    let master = route.probe.mst.map_or(trans, |mst| mst.master);
    if uhbr_plan.is_none() {
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
    }
    let lost = |_| ExternalError::AccessLost;
    let pipe_bpp = route.probe.pipe_bpp;
    let ycbcr444 = route.probe.output.ycbcr444;
    // intel_ddi_set_dp_msa, the last step of intel_ddi_pre_enable_dp. The
    // 8 bpc RGB route keeps its write stream (and leaves the MSA as it is);
    // any other depth or a YCbCr 4:4:4 output writes its MSA, and its stop
    // restores the 8 bpc RGB one.
    if pipe_bpp != dsc::PIPE_BPP || ycbcr444 {
        write(
            io,
            trans.base() + dsc::TRANS_MSA_MISC_OFFSET,
            color::msa_misc(pipe_bpp, ycbcr444),
        )?;
    }
    let plan = route.probe.dsc;
    if let Some(plan) = &plan {
        // intel_ddi_enable_fec, then intel_dsc_dp_pps_write; then
        // hsw_crtc_enable's intel_dsc_enable on the route's pipe.
        if plan.fec {
            enable_stream_fec(io, trans, &route.probe)?;
        }
        dsc::write_pps_sdp(io, trans, plan).map_err(lost)?;
        dsc::enable_engines(io, pipe, plan).map_err(lost)?;
    }
    // hsw_configure_cpu_transcoder: M/N with the timings; the transcoder
    // is off, so nothing here latches before its enable.
    match (&plan, &uhbr_plan) {
        (Some(plan), _) => dsc::write_m_n(io, trans, &plan.m_n(&mode)).map_err(lost)?,
        // intel_dp_mtp_tu_compute_config: TU_SIZE(tu) in PIPE_DATA_M1.
        (None, Some(u)) => dsc::write_m_n(io, trans, &u.stream.m_n).map_err(lost)?,
        (None, None) => program_mn(io, trans, &mode, pll_rate, lanes, pipe_bpp)?,
    }
    rp.pipes.program_timings(io, pipe)?;
    // A YCbCr 4:4:4 output: bdw_set_pipe_misc's YUV colorspace and the
    // BT.709 output CSC, pipe off.
    if ycbcr444 {
        let misc = pipe.base() + dsc::PIPE_MISC_OFFSET;
        let cur = read(io, misc)?;
        write(io, misc, cur | color::PIPE_MISC_OUTPUT_COLORSPACE_YUV)?;
        crate::intel_gpu_modeset::program_output_csc_ycbcr(io, pipe);
    }
    // intel_ddi_enable: 128b/132b SST's TRANS_DP2_VFREQ pair (the pixel
    // clock in Hz, bits 31:8 of each), function, then the transcoder.
    if uhbr_plan.is_some() {
        let hz = u64::from(mode.pixel_clock_khz) * 1_000;
        write(io, trans_dp2_vfreqhigh(trans), ((hz >> 24) as u32) << 8)?;
        write(
            io,
            trans_dp2_vfreqlow(trans),
            ((hz & 0xff_ffff) as u32) << 8,
        )?;
    }
    let mut func = match &uhbr_plan {
        Some(u) => uhbr_func(&route.probe, trans, u.link.lanes),
        None => stream_func(&route.probe, lanes),
    };
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
    // Display 30 always scans out through the VRR timing generator. Linux
    // programs and enables it after TRANS_DDI_FUNC_CTL and before TRANSCONF.
    rp.pipes.enable_fixed_tg(io, pipe)?;
    // 128b/132b SST: intel_ddi_clear_act_sent, TRANS_DDI_DP_VC_PAYLOAD_ALLOC,
    // intel_ddi_wait_for_act_sent, then the sink's ACT handled.
    if uhbr_plan.is_some() {
        if let Some(state) = route.uhbr.as_mut() {
            state.vc_payload = true;
        }
        mst::source_payload(io, trans, trans, true).map_err(|e| match e {
            ExternalError::Mst(MstFailure::Act) => ExternalError::Uhbr(uhbr::UhbrRefusal::Payload),
            e => e,
        })?;
        func |= TRANS_DDI_DP_VC_PAYLOAD_ALLOC;
        let mut aux = IntelAux::xelpdp(io, route.probe.port.aux_base(), route.probe.tbt());
        if !uhbr::poll_act_handled(&mut aux, &mut uhbr::SystemClock) {
            return Err(ExternalError::Uhbr(uhbr::UhbrRefusal::Payload));
        }
    }
    let rp = route
        .reservation
        .as_mut()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))?;
    let start = read(io, pipe.base() + FRMCOUNT)?;
    rp.pipes.enable(io, pipe)?;
    // intel_ddi_wait_for_fec_status(true). Display 30 requires its source
    // to stay live through transcoder enable before arming the primary.
    if plan.is_some_and(|p| p.fec) {
        if dsc::poll_fec_live(io, trans, true).map_err(lost)? {
            let _ = sink_fec_detected(io, &route.probe);
        } else if route.probe.display_ip.is_display30() {
            return Err(ExternalError::FecNotReady);
        }
    }
    rp.pipes.arm_primary(io, pipe)?;
    observe_live(io, route, func, start)?;
    // intel_post_plane_update: intel_encoders_audio_enable (SST only).
    let Some(connector_eld) = route.probe.audio.clone().filter(|_| route.probe.mst.is_none())
    else {
        return Ok(());
    };
    let stream = audio::AudioStream {
        trans,
        pipe,
        port: route.probe.port.port_enum() as i32,
        dp: true,
        uhbr: uhbr_plan.is_some(),
        crtc_clock_khz: mode.pixel_clock_khz,
        port_clock_khz: match uhbr_plan {
            Some(u) => u.link.rate.link_rate(),
            None => link_clock_khz(trained.rate),
        },
        pipe_bpp,
        lane_count: uhbr_plan.map_or(lanes, |u| u.link.lanes),
        h_active: mode.h_active,
        h_total: mode.h_total,
        v_active: mode.v_active,
        dsc_bpp_x16: plan.map(|p| u32::from(p.compressed_bpp_x16)),
        ycbcr420: false,
        wa_14020863754: audio::needs_wa_14020863754(route.probe.display_ip),
    };
    let edid = &route.probe.edid[..route.probe.edid_len];
    let eld = audio::compute_eld(&connector_eld, edid, &stream);
    let publication = narf_drivers_sound::display_audio::build_eld(
        edid,
        narf_drivers_sound::display_audio::DisplayConnector::DisplayPort,
        0,
    );
    route.audio = Some(stream);
    audio::audio_codec_enable(io, &stream, &eld, publication).map_err(|_| ExternalError::AccessLost)
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
    if route.probe.display_ip.is_display30()
        && route.probe.dsc.is_some_and(|plan| plan.fec)
        && read(io, dp_tp_ctl(trans) + 4)? & dsc::DP_TP_STATUS_FEC_ENABLE_LIVE == 0
    {
        return Err(ExternalError::FecNotReady);
    }
    Ok(())
}

/// `intel_ddi_post_disable_hdmi_or_sst`'s 128b/132b SST step after the
/// transcoder disable: the sink's VCPID 1 payload cleared
/// (`drm_dp_dpcd_write_payload(aux, 1, 0, 0)`), `intel_ddi_clear_act_sent`,
/// `TRANS_DDI_DP_VC_PAYLOAD_ALLOC` off, `intel_ddi_wait_for_act_sent` and
/// `drm_dp_dpcd_poll_act_handled`. Linux only logs a missing ACT; so does
/// this. A failed activation undoes only what it allocated.
fn uhbr_payload_off<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
    trans: Transcoder,
) -> Result<(), ExternalError> {
    let state = route.uhbr.unwrap_or_default();
    let mut aux = IntelAux::xelpdp(io, route.probe.port.aux_base(), route.probe.tbt());
    let mut clock = uhbr::SystemClock;
    if state.sink_payload {
        let _ = uhbr::write_payload(&mut aux, &mut clock, 1, 0, 0);
    }
    if state.vc_payload {
        match mst::source_payload(io, trans, trans, false) {
            Ok(()) | Err(ExternalError::Mst(MstFailure::Act)) => {}
            Err(e) => return Err(e),
        }
        let _ = uhbr::poll_act_handled(&mut aux, &mut clock);
    }
    Ok(())
}

/// The port side of `intel_ddi_post_disable_dp`, with the transcoder off:
/// function deselect, sink D3, `intel_ddi_buf_disable` and FEC disable.
fn disable_port<M: MmioWindow + ?Sized>(
    io: &M,
    route: &MtlExternalRoute,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let trans = route_pipe(route)?.transcoder();
    let stop_failed = ExternalError::Modeset(ModesetError::PipelineStopUnavailable);
    let uhbr = route.probe.uhbr.is_some();
    if uhbr {
        uhbr_payload_off(io, route, trans)?;
    }
    // intel_ddi_disable_transcoder_func (TGL+ SST): enable, port, mode. A
    // 128b/132b SST transcoder is its own MST master: its port and mode
    // stay until intel_ddi_post_disable_dp, after the sink's D3.
    let func = read(io, trans_ddi_func_ctl(trans))?;
    write(
        io,
        trans_ddi_func_ctl(trans),
        func & !(TRANS_DDI_FUNC_ENABLE | if uhbr { 0 } else { TRANS_DDI_PORT_AND_MODE }),
    )?;
    // A 6, 10 or 12 bpc or YCbCr 4:4:4 route leaves the MSA at 8 bpc RGB:
    // the 8 bpc route does not write it (its write stream predates the
    // MSA), and Linux's intel_ddi_set_dp_msa would write it at its next
    // enable.
    if route.probe.pipe_bpp != dsc::PIPE_BPP || route.probe.output.ycbcr444 {
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
    let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
    // The 8b/10b route never runs intel_dp_link_training_set_mode, so a
    // 128b/132b route hands the sink back with DP_SET_ANSI_8B10B (best
    // effort, while the sink is still in D0).
    if uhbr {
        let _ = aux.dpcd_write(
            uhbr::DP_MAIN_LINK_CHANNEL_CODING_SET,
            &[uhbr::DP_SET_ANSI_8B10B],
        );
    }
    // Sink to D3 before the port goes down (a NACK never replaces the
    // local idle proof).
    if route.probe.caps.dpcd_rev >= 0x11 {
        let _ = aux.dpcd_write(DPCD_SET_POWER, &[DP_SET_POWER_D3]);
    }
    // intel_ddi_post_disable_dp (display 12+, 128b/132b): port and mode.
    if uhbr {
        let func = read(io, trans_ddi_func_ctl(trans))?;
        write(
            io,
            trans_ddi_func_ctl(trans),
            func & !TRANS_DDI_PORT_AND_MODE,
        )?;
    }
    // intel_ddi_buf_disable (display 14): DDI_CTL_DE off, PHY idle, D2D
    // off, DP_TP_CTL off.
    let ddi = read(io, port.ddi_buf_ctl())?;
    write(io, port.ddi_buf_ctl(), ddi & !DDI_BUF_CTL_ENABLE)?;
    wait_port_buf_idle(io, port).map_err(|_| stop_failed)?;
    disable_d2d(io, route.probe.display_ip, port).map_err(|_| stop_failed)?;
    let tp = read(io, dp_tp_ctl(trans))?;
    write(io, dp_tp_ctl(trans), tp & !DP_TP_CTL_ENABLE)?;
    if fec {
        dsc::disable_fec(io, trans).map_err(|_| ExternalError::AccessLost)?;
    }
    Ok(())
}

/// Wait for FEC off while the port's clock is still available, then
/// deselect the transcoder clock, disable the PLL and deselect TBT IO.
fn finish_port_stop<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
) -> Result<(), ExternalError> {
    let port = route.probe.port;
    let trans = route_pipe(route)?.transcoder();
    let stop_failed = ExternalError::Modeset(ModesetError::PipelineStopUnavailable);
    if route.probe.dsc.is_some_and(|p| p.fec) {
        if route.probe.display_ip.is_display30() {
            route.awaiting_fec_stop = true;
            if !dsc::poll_fec_live(io, trans, false).map_err(|_| ExternalError::AccessLost)? {
                return Err(ExternalError::FecStopTimeout);
            }
            route.awaiting_fec_stop = false;
        } else {
            let _ = dsc::wait_fec_live(io, trans, false);
        }
        let mut aux = IntelAux::xelpdp(io, port.aux_base(), route.probe.tbt());
        let _ = dsc::set_sink_fec_ready(&mut aux, false);
    }
    // intel_ddi_config_transcoder_dp2(false) on a 128b/132b route.
    if route.probe.uhbr.is_some() {
        write(io, trans_dp2_ctl(trans), 0)?;
    }
    // TRANS_CLK_SEL: no clock to the transcoder.
    write(io, trans_clk_sel(trans), 0)?;
    // intel_cx0pll_disable, then deselect Thunderbolt IO.
    if route.probe.tbt() {
        disable_tbt_clock(io, port).map_err(|_| stop_failed)?;
    } else {
        port_pll_disable(io, &route.probe).map_err(|_| stop_failed)?;
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
/// primary off, transcoder off, the port side, then the
/// pipe DMC disable and the post-plane repartition without the pipe. Every
/// step is observed; any failure leaves the remaining state (and the
/// pipe's reservation) for quarantine. A route that failed before its
/// reservation has nothing to stop: its port is programmed only after it.
fn stop_local<M: MmioWindow + ?Sized>(
    io: &M,
    route: &mut MtlExternalRoute,
) -> Result<(), ExternalError> {
    let stop_failed = ExternalError::Modeset(ModesetError::PipelineStopUnavailable);
    // intel_pre_plane_update: intel_encoders_audio_disable, before the
    // planes go (best effort: the stop proof is the pipe's).
    let audio_pipe = route.probe.audio.is_some() && route.probe.mst.is_none();
    if let Some(stream) = route.audio.take() {
        let _ = audio::audio_codec_disable(io, &stream);
    }
    let Some(rp) = route.reservation.as_mut() else {
        return Ok(());
    };
    if !route.awaiting_fec_stop {
        let pipe = rp.pipe;
        rp.pipes.disable_primary(io, pipe)?;
        // intel_ddi_disable_dp: the sink's decompression off before the
        // transcoder (best effort, as in Linux).
        if route.probe.dsc.is_some() {
            let mut aux = IntelAux::xelpdp(io, route.probe.port.aux_base(), route.probe.tbt());
            let _ = dsc::set_sink_decompression(&mut aux, false);
        }
        rp.pipes.disable(io, pipe).map_err(|e| match e {
            PipeEnableError::Timeout => stop_failed,
            e => e.into(),
        })?;
        // The YCbCr 4:4:4 output CSC and PIPE_MISC encoding, pipe off.
        if route.probe.output.ycbcr444 {
            crate::intel_gpu_modeset::clear_output_csc_ycbcr(io, pipe);
        }
        disable_port(io, route)?;
    }
    finish_port_stop(io, route)?;
    let rp = route
        .reservation
        .as_mut()
        .ok_or(ExternalError::Pipe(PipeRefusal::Sequence))?;
    release_audio_pipe(io, rp, audio_pipe)?;
    route.retired = route.reservation.take().map(|rp| rp.pipes);
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

    /// The Pipe B–D owner this route's reservation holds.
    pub(crate) fn shared_pipes(&self) -> Option<&Pipes> {
        self.reservation.as_ref().map(|rp| &rp.pipes)
    }

    /// Adopt a sibling route's newer Pipe B–D owner; a route without a
    /// reservation keeps none.
    pub(crate) fn adopt_shared_pipes(&mut self, pipes: &Pipes) {
        if let Some(rp) = self.reservation.as_mut() {
            rp.pipes = pipes.clone();
        }
    }

    /// The owner a sibling adopts after this route changed it: the
    /// reservation's, or once the post-release owner the proven stop left.
    pub(crate) fn take_shared_pipes(&mut self) -> Option<Pipes> {
        match self.reservation.as_ref() {
            Some(rp) => Some(rp.pipes.clone()),
            None => self.retired.take(),
        }
    }

    /// Locally stop the route. A stopped route stays stopped; a failed
    /// stop quarantines it. A pending display-30 FEC-off acknowledgement
    /// can be sampled again with the same leases and clock still held.
    pub fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), ExternalError> {
        match self.state {
            RouteState::Stopped => Ok(()),
            RouteState::Quarantined if !self.awaiting_fec_stop => Err(ExternalError::Quarantined),
            RouteState::Live | RouteState::Quarantined => match stop_local(io, self) {
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
    /// alignment is done; on 128b/132b, every lane's CHANNEL_EQ_DONE and
    /// the interlane alignment (`intel_dp_link_ok`).
    pub fn link_ok<M: MmioWindow + ?Sized>(&self, io: &M) -> Result<bool, ExternalError> {
        let mut aux = IntelAux::xelpdp(io, self.probe.port.aux_base(), self.probe.tbt());
        let mut status = [0u8; 3];
        aux.dpcd_read(0x202, &mut status)
            .map_err(|e| ExternalError::Link(LinkError::AuxFailure(e)))?;
        let lanes = self.trained.lanes.min(4) as usize;
        if self.probe.uhbr.is_some() {
            // intel_dp_link_ok on 128b/132b:
            // drm_dp_128b132b_lane_channel_eq_done.
            let mut full = [0u8; uhbr::LINK_STATUS_SIZE];
            full[..3].copy_from_slice(&status);
            return Ok(uhbr::lane_channel_eq_done(&full, lanes as u8));
        }
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

    /// The Pipe B–D owner a sibling SST or HDMI route plans beside.
    fn shared_pipes(&self) -> Option<&Pipes> {
        match self {
            MtlRoute::Dp(r) => r.shared_pipes(),
            MtlRoute::Hdmi(r) => r.shared_pipes(),
            MtlRoute::Mst(_) => None,
        }
    }

    fn adopt_shared_pipes(&mut self, pipes: &Pipes) {
        match self {
            MtlRoute::Dp(r) => r.adopt_shared_pipes(pipes),
            MtlRoute::Hdmi(r) => r.adopt_shared_pipes(pipes),
            MtlRoute::Mst(_) => {}
        }
    }

    fn take_shared_pipes(&mut self) -> Option<Pipes> {
        match self {
            MtlRoute::Dp(r) => r.take_shared_pipes(),
            MtlRoute::Hdmi(r) => r.take_shared_pipes(),
            MtlRoute::Mst(_) => None,
        }
    }

    /// Whether a second independent route may be planned beside this one.
    fn admits_sibling(&self) -> Result<(), SecondRouteRefusal> {
        match self {
            MtlRoute::Mst(_) => Err(SecondRouteRefusal::SiblingMst),
            MtlRoute::Dp(r) if r.probe.uhbr.is_some() => Err(SecondRouteRefusal::SiblingUhbr),
            route if !route.live() || route.shared_pipes().is_none() => {
                Err(SecondRouteRefusal::SiblingNotLive)
            }
            _ => Ok(()),
        }
    }

    fn stop<M: MmioWindow + ?Sized>(&mut self, io: &M) -> Result<(), RouteError> {
        // HDCP off before the transcoder goes down (`intel_hdcp_disable`);
        // inert without `narf.intel.hdcp=1`.
        crate::intel_hdcp_live::route_stopping(
            io,
            crate::intel_hdcp_live::xelpg_key(self.port() as u8, self.pipe().transcoder() as u8),
        );
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
/// ([`routes_stopped`], [`route_live`], [`slot_live`]): whether any route
/// is live, whether any is not locally stopped (live or retained without a
/// proven stop), and which route slots scan out. It changes only when a
/// service pass ends, so a reader racing a pass sees the last completed
/// pass's routes, never a transient "not stopped" from the pass merely
/// holding the lock. Passes that light or stop hardware are serialized
/// against the display power-management readers by the display's legacy
/// guard, and against DC5/DC6 re-entry by their `DcUser::External`
/// reference and the contended-lock rule of [`external_route_blocks_dc`].
#[derive(Debug)]
pub struct RoutePresence(AtomicU8);

/// Some route scans out.
const PRESENCE_LIVE: u8 = 1;
/// Some route is not locally stopped.
const PRESENCE_HELD: u8 = 2;
/// Route slot `slot` scans out.
const fn presence_slot_live(slot: usize) -> u8 {
    4 << slot
}

impl RoutePresence {
    /// No route.
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    fn publish(&self, routes: &[Option<MtlRoute>; MAX_ROUTES]) {
        let mut code = 0;
        for (slot, route) in routes.iter().enumerate() {
            match route {
                Some(route) if route.live() => {
                    code |= PRESENCE_LIVE | PRESENCE_HELD | presence_slot_live(slot);
                }
                Some(route) if !route.stopped() => code |= PRESENCE_HELD,
                _ => {}
            }
        }
        self.0.store(code, Ordering::Release);
    }

    /// No route, or only locally stopped ones (their hardware is off).
    pub fn stopped(&self) -> bool {
        self.0.load(Ordering::Acquire) & PRESENCE_HELD == 0
    }

    /// Some route is scanning out.
    pub fn live(&self) -> bool {
        self.0.load(Ordering::Acquire) & PRESENCE_LIVE != 0
    }

    /// The route in `slot` is scanning out.
    pub fn slot_live(&self, slot: usize) -> bool {
        slot < MAX_ROUTES && self.0.load(Ordering::Acquire) & presence_slot_live(slot) != 0
    }
}

impl Default for RoutePresence {
    fn default() -> Self {
        Self::new()
    }
}

/// Owner of the MTL external routes, driven by hotplug events: one route,
/// or under `narf.intel.ext_routes=2` ([`EXT_ROUTES_OPTION`]) two
/// independent ones on distinct ports and pipes beside the lit panel.
///
/// ## Two routes
///
/// Linux lights a second CRTC through the same atomic commit as the first
/// (`intel_atomic_check` with two active CRTCs: `intel_cdclk_atomic_check`
/// takes the highest minimum CDCLK, `skl_compute_ddb` and
/// `skl_compute_dbuf_slices` repartition the DBUF across every active pipe,
/// `intel_pmdemand_atomic_check` counts the active pipes and combo PHYs and
/// the highest port clock). Here the second route's pipe joins the layout
/// the first route's Pipe B–D owner holds programmed: its admission and its
/// pre-plane transaction are computed over Pipe A, the sibling's pipe and
/// the new one, with every lit pipe kept lit; a stop's post-plane
/// repartition keeps the sibling. Each route keeps its own port, PLL,
/// hotplug pin, retrain and teardown; after every change the sibling adopts
/// the owner the changed route left, so the two never plan from diverged
/// layouts. A second route is refused typed ([`SecondRouteRefusal`]) beside
/// an MST or 128b/132b route, beside a route that is not live, and when it
/// would itself be MST or 128b/132b. HDCP follows the first owned route
/// ([`hdcp_route`]).
#[derive(Debug)]
pub struct MtlExternalService {
    routes: [Option<MtlRoute>; MAX_ROUTES],
    /// The live mode each retained route was connected in (for `Redetect`).
    live: [LiveMode; MAX_ROUTES],
    /// Active source-qualified display profile for probe/resource decisions;
    /// absent for a generation outside this owner.
    profile: Option<ExternalDisplayProfile>,
    policy: MtlPortPolicy,
    /// What activations share the display with (panel, pipe-DMC sink).
    display: MtlDisplay,
    /// Where this service publishes its route presence, if anywhere.
    presence: Option<&'static RoutePresence>,
    /// The `narf.intel.uhbr` decision for later probes; `None` reads the
    /// boot option at each connect.
    uhbr: Option<bool>,
    /// The `narf.intel.ext_routes=2` decision; `None` reads the boot option
    /// at each connect.
    two_routes: Option<bool>,
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
            routes: [None, None],
            live: [LiveMode::Native; MAX_ROUTES],
            profile: Some(ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp)),
            policy,
            display: MtlDisplay::NONE,
            presence: None,
            uhbr: None,
            two_routes: None,
        }
    }

    /// An empty service that publishes its route presence to `presence`
    /// at the end of every pass.
    pub const fn with_presence(presence: &'static RoutePresence) -> Self {
        let mut service = Self::new();
        service.presence = Some(presence);
        service
    }

    /// Set the display generation (`MeteorLake`, `LunarLake`, `PantherLake`)
    /// used on subsequent connect passes. Wildcat Lake needs
    /// [`Self::set_profile`] because graphics generation is not a sufficient
    /// display identity.
    pub fn set_generation(&mut self, generation: Generation) {
        self.profile = ExternalDisplayProfile::for_generation(generation);
    }

    /// Select an exact external-display profile which broad graphics
    /// generation cannot distinguish (currently Wildcat Lake 30.02).
    pub(crate) fn set_profile(&mut self, profile: ExternalDisplayProfile) {
        self.profile = Some(profile);
    }

    /// What activations share the display with.
    pub fn display(&self) -> MtlDisplay {
        self.display
    }

    /// Decide `narf.intel.uhbr` for later probes instead of reading the
    /// boot option (fixtures).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn set_uhbr(&mut self, on: bool) {
        self.uhbr = Some(on);
    }

    fn uhbr_on(&self) -> bool {
        self.uhbr.unwrap_or_else(uhbr::opted_in)
    }

    /// Decide `narf.intel.ext_routes=2` instead of reading the boot option
    /// (fixtures).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn set_two_routes(&mut self, on: bool) {
        self.two_routes = Some(on);
    }

    fn two_routes_on(&self) -> bool {
        self.two_routes.unwrap_or_else(ext_routes_opted_in)
    }

    /// Replace the display context (the owned panel, the pipe-DMC sink)
    /// used by later activations; a live route keeps the pipe-DMC sink it
    /// reported to.
    pub fn set_display(&mut self, display: MtlDisplay) {
        self.display = display;
    }

    fn publish(&self) {
        if let Some(presence) = self.presence {
            presence.publish(&self.routes);
            let non_psr_pipes = self
                .routes
                .iter()
                .flatten()
                .filter(|route| route.live())
                .fold(0u8, |mask, route| mask | 1u8 << (route.pipe() as u8));
            crate::intel_gpu_psr::set_non_psr_pipes(non_psr_pipes);
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
        if self.routes.iter().any(Option::is_some) {
            return self.policy == policy;
        }
        self.policy = policy;
        true
    }

    /// The first retained route, if any (the only one without
    /// `narf.intel.ext_routes=2`).
    pub fn route(&self) -> Option<&MtlRoute> {
        self.routes.iter().flatten().next()
    }

    /// The route in `slot` (0 or 1), if any.
    pub fn route_in(&self, slot: usize) -> Option<&MtlRoute> {
        self.routes.get(slot)?.as_ref()
    }

    /// The route owning `port`, if any.
    pub fn route_on(&self, port: XeLpgPort) -> Option<&MtlRoute> {
        self.routes.iter().flatten().find(|route| route.port() == port)
    }

    /// Every retained route.
    pub fn routes(&self) -> impl Iterator<Item = &MtlRoute> {
        self.routes.iter().flatten()
    }

    fn slot_of(&self, port: XeLpgPort) -> Option<usize> {
        self.routes
            .iter()
            .position(|route| route.as_ref().is_some_and(|r| r.port() == port))
    }

    /// The slot a newly connected sink takes: the first, while nothing is
    /// owned; under `narf.intel.ext_routes=2` the free one beside a live
    /// SST or HDMI route. `Ok(None)`: the service is full (or single-route
    /// and owned), the event changes nothing.
    fn connect_slot(&self) -> Result<Option<usize>, SecondRouteRefusal> {
        let free = self.routes.iter().position(Option::is_none);
        let owned: Option<&MtlRoute> = self.route();
        match (free, owned) {
            (Some(slot), None) => Ok(Some(slot)),
            (Some(_), Some(_)) if !self.two_routes_on() => Ok(None),
            (Some(slot), Some(sibling)) => sibling.admits_sibling().map(|()| Some(slot)),
            (None, _) => Ok(None),
        }
    }

    /// The slot an event on `port` lights or relights a route in, read
    /// before the pass so the caller can key its scanout allocation: the
    /// slot owning `port`, else the one a newly connected sink would take
    /// (`0` whenever a pass would not light a second route).
    pub fn event_slot(&self, port: XeLpgPort) -> usize {
        self.slot_of(port)
            .or_else(|| self.connect_slot().ok().flatten())
            .unwrap_or(0)
    }

    /// The sibling's Pipe B–D owner for an activation into `slot`.
    fn beside(&self, slot: usize) -> Option<Pipes> {
        self.routes[1 - slot]
            .as_ref()
            .and_then(MtlRoute::shared_pipes)
            .cloned()
    }

    /// After the route in (or just taken from) `slot` changed the Pipe B–D
    /// owner, the sibling adopts it.
    fn share_from(&mut self, slot: usize, route: &mut MtlRoute) {
        let pipes = route.take_shared_pipes();
        self.share(slot, pipes);
    }

    fn share(&mut self, slot: usize, pipes: Option<Pipes>) {
        if let (Some(pipes), Some(sibling)) = (pipes, self.routes[1 - slot].as_mut()) {
            sibling.adopt_shared_pipes(&pipes);
        }
    }

    /// Store a route that now holds `slot`, sharing its owner first.
    fn hold(&mut self, slot: usize, mut route: MtlRoute) {
        self.share_from(slot, &mut route);
        self.routes[slot] = Some(route);
    }

    fn connect<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        slot: usize,
        port: XeLpgPort,
        live: LiveMode,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let Some(profile) = self.profile else {
            return ServiceOutcome::Refused {
                port,
                error: RouteError::Dp(ExternalError::UnsupportedGeneration),
            };
        };
        let legacy = live == LiveMode::Legacy;
        let mut plan = route_plan(port, self.policy.decl(port), live);
        // Lunar and Panther Lake HDMI runs on their display-20/30 D2D,
        // DDI_BUF_CTL and (display 30) VRR-TG steps. Wildcat Lake's exact
        // 30.02 profile has no qualified HDMI route.
        if profile.display_ip == DisplayIp::WildcatLake {
            plan = match plan {
                RoutePlan::DpThenHdmi => RoutePlan::Dp,
                RoutePlan::Hdmi => RoutePlan::Refuse,
                other => other,
            };
        }
        let outcome = match plan {
            RoutePlan::Refuse => ServiceOutcome::Refused {
                port,
                error: RouteError::Dp(match live {
                    LiveMode::TbtAlt => ExternalError::Tc(TcError::TunnelUnavailable),
                    _ => ExternalError::UnsupportedPort,
                }),
            },
            RoutePlan::Hdmi => self.connect_hdmi(io, slot, port, legacy, alloc),
            RoutePlan::Dp | RoutePlan::DpThenHdmi => {
                match probe_link_profile(io, profile, port, legacy) {
                    Ok(link) => self.connect_output(io, slot, link, alloc),
                    Err(e) if plan == RoutePlan::DpThenHdmi && dpcd_absent(&e) => {
                        self.connect_hdmi(io, slot, port, legacy, alloc)
                    }
                    Err(error) => ServiceOutcome::Refused {
                        port,
                        error: RouteError::Dp(error),
                    },
                }
            }
        };
        if self.routes[slot].is_some() {
            self.live[slot] = live;
        }
        outcome
    }

    fn connect_output<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        slot: usize,
        link: LinkProbe,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let port = link.port;
        let second = self.routes[1 - slot].is_some();
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
        if cap[0] & 1 != 0 && second {
            let _ = link.release(io);
            return ServiceOutcome::Refused {
                port,
                error: RouteError::Dp(ExternalError::SecondRoute(SecondRouteRefusal::Mst)),
            };
        }
        let uhbr_on = self.uhbr_on();
        if cap[0] & 1 != 0 && uhbr_on {
            // Linux runs an MST link at its highest common bandwidth
            // (INTEL_DP_LINK_CAPS_ORDER_KEY_BW): a hub with a common UHBR
            // rate would carry 128b/132b MST, which is not implemented.
            let source = uhbr::source_rates(link.display_ip, c10_phy(io, port));
            let sink = if source == 0 {
                Ok(uhbr::UhbrSink::default())
            } else {
                uhbr::read_sink(&mut link.aux(io), &link.raw)
            };
            let error = match sink {
                Ok(sink) if sink.rates & source == 0 => None,
                Ok(_) => Some(ExternalError::Uhbr(uhbr::UhbrRefusal::Mst)),
                Err(e) => Some(ExternalError::Link(LinkError::AuxFailure(e))),
            };
            if let Some(error) = error {
                let _ = link.release(io);
                return ServiceOutcome::Refused {
                    port,
                    error: RouteError::Dp(error),
                };
            }
        }
        if cap[0] & 1 != 0 {
            match MtlMstRoute::connect(io, link, self.policy.decl(port), &self.display, alloc) {
                Ok(route) => {
                    let (pipe, mode, fb) = route.first().expect("live MST has a first stream");
                    self.routes[slot] = Some(MtlRoute::Mst(route));
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
                    self.settle_failed(io, slot, MtlRoute::Mst(route), RouteError::Dp(error))
                }
            }
        } else {
            match probe_sink_link(io, link, uhbr_on, color::opted_in()) {
                Ok(probe) if second && probe.uhbr.is_some() => {
                    let _ = release_probe(io, &probe);
                    ServiceOutcome::Refused {
                        port,
                        error: RouteError::Dp(ExternalError::SecondRoute(
                            SecondRouteRefusal::Uhbr,
                        )),
                    }
                }
                Ok(mut probe) => {
                    probe.lane_reversal = self.policy.decl(port).lane_reversal;
                    probe.ssc = dp_ssc_enabled(self.policy.use_ssc, probe.max_downspread);
                    self.connect_dp(io, slot, probe, alloc)
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
        slot: usize,
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
        let beside = self.beside(slot);
        match activate_beside(io, probe, fb, &self.display, beside) {
            Ok(route) => {
                let outcome = ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Dp,
                    pipe: route.pipe(),
                    mode: route.probe.mode,
                    fb,
                };
                self.hold(slot, MtlRoute::Dp(route));
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
                self.settle_failed(io, slot, MtlRoute::Dp(route), RouteError::Dp(error))
            }
        }
    }

    fn connect_hdmi<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        slot: usize,
        port: XeLpgPort,
        legacy: bool,
        alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
    ) -> ServiceOutcome {
        let ddc = self.policy.ddc_pin(port);
        let profile = self
            .profile
            .expect("HDMI connect follows a source-qualified route plan");
        let mut probe = match probe_hdmi_profile_ext(
            io,
            profile,
            port,
            legacy,
            ddc,
            color::opted_in(),
        ) {
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
        let beside = self.beside(slot);
        match activate_hdmi_beside(io, probe, fb, &self.display, beside) {
            Ok(route) => {
                let outcome = ServiceOutcome::Activated {
                    port,
                    protocol: MtlProtocol::Hdmi,
                    pipe: route.pipe(),
                    mode: route.probe.mode,
                    fb,
                };
                self.hold(slot, MtlRoute::Hdmi(route));
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
                self.settle_failed(io, slot, MtlRoute::Hdmi(route), RouteError::Hdmi(error))
            }
        }
    }

    /// A failed activation: release a locally stopped route, retain
    /// anything else. Either way the sibling adopts the owner it left.
    fn settle_failed<M: MmioWindow + ?Sized>(
        &mut self,
        io: &M,
        slot: usize,
        mut route: MtlRoute,
        error: RouteError,
    ) -> ServiceOutcome {
        let port = route.port();
        self.share_from(slot, &mut route);
        if !route.stopped() {
            self.routes[slot] = Some(route);
            return ServiceOutcome::Retained { port, error };
        }
        match route.release(io) {
            Ok(()) => ServiceOutcome::Refused { port, error },
            Err((route, e)) => {
                self.routes[slot] = Some(route);
                ServiceOutcome::Retained { port, error: e }
            }
        }
    }

    fn withdraw<M: MmioWindow + ?Sized>(&mut self, io: &M, slot: usize) -> ServiceOutcome {
        let Some(mut route) = self.routes[slot].take() else {
            return ServiceOutcome::Unchanged;
        };
        let port = route.port();
        let stopped = route.stop(io);
        // The post-plane repartition without this pipe (or whatever a
        // failed stop left reserved) is what the sibling now plans from.
        self.share_from(slot, &mut route);
        if let Err(error) = stopped {
            self.routes[slot] = Some(route);
            return ServiceOutcome::Retained { port, error };
        }
        match route.release(io) {
            Ok(()) => ServiceOutcome::Withdrawn { port },
            Err((route, error)) => {
                self.routes[slot] = Some(route);
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
        let Some(slot) = self.slot_of(port) else {
            return match event.kind {
                MtlHpdKind::Connected(live) => match self.connect_slot() {
                    Ok(Some(slot)) => self.connect(io, slot, port, live, alloc),
                    Ok(None) => ServiceOutcome::Unchanged,
                    Err(refusal) => ServiceOutcome::Refused {
                        port,
                        error: RouteError::Dp(ExternalError::SecondRoute(refusal)),
                    },
                },
                _ => ServiceOutcome::Unchanged,
            };
        };
        let protocol = self.routes[slot].as_ref().map(MtlRoute::protocol);
        match event.kind {
            MtlHpdKind::Connected(_) => ServiceOutcome::Unchanged,
            MtlHpdKind::Disconnected => self.withdraw(io, slot),
            MtlHpdKind::ShortPulse if protocol == Some(MtlProtocol::DpMst) => {
                // The sink's CP_IRQ to HDCP first (`intel_dp_mst_hpd_irq`).
                if let Some(MtlRoute::Mst(route)) = self.routes[slot].as_ref() {
                    let key = crate::intel_hdcp_live::xelpg_key(
                        port as u8,
                        self.routes[slot]
                            .as_ref()
                            .map_or(0, |r| r.pipe().transcoder() as u8),
                    );
                    crate::intel_hdcp_live::short_pulse(&mut route.link_aux(io), key, true);
                }
                let unchanged = match self.routes[slot].as_mut() {
                    Some(MtlRoute::Mst(route)) => route.unchanged(io) == Ok(true),
                    _ => false,
                };
                if unchanged {
                    ServiceOutcome::Unchanged
                } else {
                    let live = self.live[slot];
                    match self.withdraw(io, slot) {
                        ServiceOutcome::Withdrawn { .. } => {
                            self.connect(io, slot, port, live, alloc)
                        }
                        other => other,
                    }
                }
            }
            // HDMI has no IRQ_HPD (`intel_hdmi` installs no hpd_pulse).
            MtlHpdKind::ShortPulse if protocol == Some(MtlProtocol::Dp) => {
                // The sink's CP_IRQ to HDCP first (`intel_dp_short_pulse`'s
                // device service IRQ).
                if let Some(MtlRoute::Dp(route)) = self.routes[slot].as_ref() {
                    let mut aux =
                        IntelAux::xelpdp(io, route.probe.port.aux_base(), route.probe.tbt());
                    crate::intel_hdcp_live::short_pulse(
                        &mut aux,
                        crate::intel_hdcp_live::xelpg_key(
                            route.port() as u8,
                            route.pipe().transcoder() as u8,
                        ),
                        false,
                    );
                }
                let healthy = match self.routes[slot].as_ref() {
                    Some(MtlRoute::Dp(route)) => Some(route.link_ok(io)),
                    _ => None,
                };
                match healthy {
                    Some(Ok(true)) => ServiceOutcome::Unchanged,
                    _ => self.retrain(io, slot),
                }
            }
            MtlHpdKind::Redetect => {
                let live = self.live[slot];
                match self.withdraw(io, slot) {
                    ServiceOutcome::Withdrawn { .. } => self.connect(io, slot, port, live, alloc),
                    other => other,
                }
            }
            _ => ServiceOutcome::Unchanged,
        }
    }

    /// Lost link on a live DP route: local stop, then a fresh activation
    /// on the same probe and framebuffer (beside the sibling route, if
    /// any, which keeps scanning out).
    fn retrain<M: MmioWindow + ?Sized>(&mut self, io: &M, slot: usize) -> ServiceOutcome {
        let mut route = match self.routes[slot].take() {
            Some(MtlRoute::Dp(route)) => route,
            other => {
                self.routes[slot] = other;
                return ServiceOutcome::Unchanged;
            }
        };
        let port = route.port();
        let stopped = route.stop(io);
        let pipes = route.take_shared_pipes();
        self.share(slot, pipes);
        if let Err(error) = stopped {
            self.routes[slot] = Some(MtlRoute::Dp(route));
            return ServiceOutcome::Retained {
                port,
                error: RouteError::Dp(error),
            };
        }
        let fb = route.fb;
        let beside = self.beside(slot);
        match activate_beside(io, route.probe.clone(), fb, &self.display, beside) {
            Ok(live) => {
                let (mode, pipe) = (live.probe.mode, live.pipe());
                self.hold(slot, MtlRoute::Dp(live));
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
                        self.routes[slot] = Some(MtlRoute::Dp(route));
                        ServiceOutcome::Retained {
                            port,
                            error: RouteError::Dp(e),
                        }
                    }
                }
            }
            Err(ActivateError::Failed(failed, error)) => {
                self.hold(slot, MtlRoute::Dp(failed));
                ServiceOutcome::Retained {
                    port,
                    error: RouteError::Dp(error),
                }
            }
        }
    }

    /// Reset/suspend: stop and release every route (the second first, as
    /// one commit disables every CRTC). Returns whether nothing external
    /// remains owned.
    pub fn teardown<M: MmioWindow + ?Sized>(&mut self, io: &M) -> bool {
        let mut done = true;
        for slot in (0..MAX_ROUTES).rev() {
            done &= matches!(
                self.withdraw(io, slot),
                ServiceOutcome::Withdrawn { .. } | ServiceOutcome::Unchanged
            );
        }
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
    service.routes().any(|route| !route.stopped())
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
    handle_mtl_event_for(io, Generation::MeteorLake, event, display, alloc)
}

/// Act on one hotplug event for `generation` (`MeteorLake`, `LunarLake`,
/// `PantherLake`) with the process-wide service.
pub fn handle_mtl_event_for<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    event: MtlHpdEvent,
    display: &MtlDisplay,
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let profile = ExternalDisplayProfile::for_generation(generation)?;
    handle_mtl_event_for_profile(io, profile, event, display, alloc)
}

/// Act on one hotplug event under an exact display identity. This is the
/// production entry for identities which share a graphics generation (WCL
/// 30.02 and PTL 30.00).
pub(crate) fn handle_mtl_event_for_profile<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
    event: MtlHpdEvent,
    display: &MtlDisplay,
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let mut service = SERVICE.try_lock()?;
    service.set_display(*display);
    service.set_profile(profile);
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

/// Poll the process-wide MTL/LNL/PTL hotplug owner once (inside the DC-off
/// bracket). Earlier generations return `None` before any access.
pub fn poll_mtl_event<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
) -> Option<MtlHpdEvent> {
    if !crate::intel_gpu_xelpg_hpd::hpd_generation_supported(generation) {
        return None;
    }
    with_dc_off(|| crate::intel_gpu_xelpg_hpd::poll_hpd_event(io, generation))
        .ok()
        .flatten()
}

/// Poll under an exact display profile and discard pins the source descriptor
/// does not own. In particular WCL never turns a TC3/TC4 or DDI-B pulse into
/// an external-display transaction.
pub(crate) fn poll_mtl_event_for_profile<M: MmioWindow + ?Sized>(
    io: &M,
    profile: ExternalDisplayProfile,
) -> Option<MtlHpdEvent> {
    poll_mtl_event(io, profile.generation()).filter(|event| profile.admits_port(event.pin.port()))
}

/// Process-wide entry for the display runtime: poll the PICA/XELPDP hotplug
/// owner once and act on the event.
pub fn service_mtl_external<M: MmioWindow + ?Sized>(
    io: &M,
    generation: Generation,
    display: &MtlDisplay,
    alloc: &mut dyn FnMut(&Mode) -> Option<Framebuffer>,
) -> Option<ServiceOutcome> {
    let event = poll_mtl_event(io, generation)?;
    handle_mtl_event_for(io, generation, event, display, alloc)
}

/// Whether the process-wide MTL route is absent or locally stopped (its
/// hardware is off), as the last completed service pass published it
/// ([`RoutePresence`]). A live or quarantined route reports `false`; a
/// pass merely holding the service does not. Never touches registers or
/// takes a lock.
pub fn routes_stopped() -> bool {
    PRESENCE.stopped()
}

/// Whether a process-wide MTL route is live (scanning out), as the last
/// completed service pass published it. DC5/DC6 re-entry is gated by
/// [`external_route_blocks_dc`], which also refuses while a pass runs.
pub fn route_live() -> bool {
    PRESENCE.live()
}

/// Whether the process-wide route in `slot` (0, or 1 under
/// `narf.intel.ext_routes=2`) is live, as the last completed pass
/// published it.
pub fn slot_live(slot: usize) -> bool {
    PRESENCE.slot_live(slot)
}

/// The slot the next process-wide pass on `port` lights a route in
/// ([`MtlExternalService::event_slot`]); `0` while a pass holds the
/// service.
pub fn event_slot(port: XeLpgPort) -> usize {
    SERVICE
        .try_lock()
        .map_or(0, |service| service.event_slot(port))
}

/// HDCP (`crate::intel_hdcp_live`): the live DP, HDMI or DP MST route,
/// unless a pass holds the service. An MST route reports its streams, the
/// master's first, and `transcoder` is the master's.
pub(crate) fn hdcp_route() -> Option<crate::intel_hdcp_live::XelpgRoute> {
    use crate::intel_hdcp_live::{MstStreams, RouteLink, XelpgRoute};
    let service = SERVICE.try_lock()?;
    // HDCP follows the first owned route; a second concurrent route is not
    // offered it.
    let route = service.route().filter(|r| r.live())?;
    let (protocol, link, mst) = match route {
        // HDCP is not offered on a 128b/132b route.
        MtlRoute::Dp(r) if r.probe.uhbr.is_some() => return None,
        MtlRoute::Dp(r) => (
            crate::intel_hdcp::Protocol::Dp,
            RouteLink::Dp(crate::intel_hdcp_shim::AuxPort::XeLpdp {
                base: r.probe.port.aux_base(),
                tbt_io: r.probe.tbt(),
            }),
            MstStreams::default(),
        ),
        MtlRoute::Hdmi(r) => (
            crate::intel_hdcp::Protocol::Hdmi,
            RouteLink::Hdmi(r.probe.ddc),
            MstStreams::default(),
        ),
        MtlRoute::Mst(r) => {
            let (base, tbt_io, streams) = r.hdcp_streams();
            (
                crate::intel_hdcp::Protocol::Dp,
                RouteLink::Dp(crate::intel_hdcp_shim::AuxPort::XeLpdp { base, tbt_io }),
                MstStreams::new(&streams)?,
            )
        }
    };
    let transcoder = match mst.as_slice().first() {
        Some(&(master, _)) => master,
        None => route.pipe().transcoder() as u8,
    };
    Some(XelpgRoute {
        port: route.port() as u8,
        transcoder,
        protocol,
        link,
        mst,
    })
}

/// Process-wide reset/suspend teardown: stop/release the route, then
/// withdraw the hotplug sources. `false` when anything stays retained.
pub fn teardown_mtl_external<M: MmioWindow + ?Sized>(io: &M, generation: Generation) -> bool {
    if !crate::intel_gpu_xelpg_hpd::hpd_generation_supported(generation) {
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_two_routes_tests.rs"]
mod two_routes_tests;
