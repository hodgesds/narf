//! Display version 30 — Xe3_LPD (Panther Lake): identification, the
//! opted-in per-device route and the display-30 deltas the display-14/20
//! chain dispatches on.
//!
//! Pinned source: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//!
//! ## Identification
//!
//! `intel_display_device.c::gmdid_display_map` maps 30.00 to
//! `xe2_lpd_display` (the display-20 descriptor: four pipes, FBC A–D) and
//! 30.02 to `wcl_display` (Wildcat Lake: pipes A–C, ports A/B/TC1/TC2).
//! `INTEL_PTL_IDS` and `INTEL_WCL_IDS` both bind `ptl_desc`, which carries
//! no display info, so the IP is known only from `GMD_ID_DISPLAY`.
//! [`DisplayIp::decode_all`] admits 30.00 only; 30.02 stays a typed refusal
//! (the WCL PCI IDs are not in the driver table, and its PHY map, DMC
//! container, CDCLK ceiling and bandwidth parameters differ). For display
//! \>= 30 `__intel_display_device_info_runtime_init` also reads
//! `PICA_PHY_CONFIG_CONTROL.EDP_ON_TYPEC` (`edp_typec_support`).
//!
//! ## Route
//!
//! Panther Lake's existing profile is the headless main GT
//! ([`crate::intel_gpu_lnl_takeover`]), whose driver FLR would reset the
//! panel. The display route (`narf.intel.ptl_display=1`, the strict Intel
//! opt-in grammar) never runs it: it adopts the firmware-lit Pipe A on
//! DDI A, exactly like the Lunar Lake route. The decision reads
//! `GMD_ID_DISPLAY` (twice), `SKL_DFSM`, `PICA_PHY_CONFIG_CONTROL` and
//! `TRANSCONF_A`, and nothing without the option. eDP on a Type-C port
//! (`EDP_ON_TYPEC`) is refused: that panel is driven by a C20 PHY with
//! `xe3lpd_c20_dp_edp_tables`, which are not transcribed.
//!
//! ## Display-30 deltas (each against display 20)
//!
//! - Power wells (`intel_display_power_map.c::xe3lpd_power_wells`): PW_B
//!   hangs off PG1 instead of PW_2 (PW_2 keeps C/D, transcoders C/D, VGA and
//!   the TC lanes) and DC_off also covers the PW_2 domains and
//!   `AUDIO_PLAYBACK`. The Pipe-A eDP chain (PW_1, PW_A, the AUX A request)
//!   is unchanged ([`PIPE_A_EDP_WELLS`], [`parent`]).
//! - CDCLK (`intel_cdclk.c`): [`CDCLK_TABLE`] (`xe3lpd_cdclk_table`: nine
//!   squashed rungs at ratio 16, then crawl-only rungs to 691.2 MHz);
//!   `bxt_cdclk_ctl` keeps the CD2X divider at 1 and writes no CD2X pipe
//!   field; `xe3lpd_calc_voltage_level` is 0; wa_15010685871 does not apply
//!   (`pll_enable_wa_needed`) and Wa_13012396614 (30.00) selects CD2XCLK as
//!   the MDCLK source before the PLL is disabled (`icl_cdclk_pll_disable`).
//!   The MDCLK/CDCLK ratio programming is display 20's.
//! - PM demand (`intel_pmdemand.c`): no DBUF slice count and a 4-bit
//!   `XE3_PMDEMAND_PIPES` field ([`crate::intel_gpu_pmdemand::Layout`]).
//! - Watermarks and DDB (`skl_watermark.c`, `skl_universal_plane.c`): no
//!   added block in `skl_compute_plane_wm`, a Tile4 line adds a block only
//!   when panned, `PLANE_WM_AUTO_MIN_ALLOC_EN` on level 0 and SAGV of
//!   every universal plane, `PLANE_MIN_BUF_CFG` (minimum and interim DDB)
//!   in `skl_write_plane_wm`; the bandwidth limit is `xe3lpd_sa_info`.
//! - VRR timing generator (`intel_vrr.c::intel_vrr_always_use_vrr_tg`):
//!   every display-30 transcoder runs through it at fixed refresh. The
//!   guardband of `intel_vrr_compute_guardband` ([`vrr_guardband`]) moves
//!   `crtc_vblank_start` and so becomes the vblank prefill budget of the
//!   watermarks; `intel_set_transcoder_timings` writes `TRANS_VTOTAL`
//!   without its vtotal field and `DP_MIN_HBLANK_CTL`;
//!   `intel_vrr_set_transcoder_timings` writes the fixed VMIN/VMAX/FLIPLINE,
//!   `TRANS_VRR_VSYNC` and `EMP_AS_SDP_TL`; the generator is enabled after
//!   `TRANS_DDI_FUNC_CTL` and disabled after the transcoder.
//! - PHY (`intel_cx0_phy.c`, `intel_cx0_phy_regs.h`, `intel_dp_aux_regs.h`):
//!   only PHY A is C10 on Panther Lake (`intel_encoder_is_c10phy`), with the
//!   shared `mtl_c10_edp_tables`; the message bus is not reset after each
//!   completed transaction; `XELPDP_DDI_CLOCK_SELECT_MASK` widens to 16:12;
//!   a C20 eDP PHY powers down to P2PG (`cx0_power_control_disable_val`).
//!   As on every display >= 20, DDI A/B's PHY and AUX registers live in the
//!   PICA block (`__xe2lpd_port_idx`, `__xe2lpd_aux_ch_idx`): [`View`]
//!   relocates them for the display-14 PHY code.
//! - DMC (`intel_dmc.c`): `xe3lpd_dmc.bin` under the 0x8000 ceiling; pipe A
//!   and B DMC need no MMIO restore, pipes C/D do (`need_pipedmc_load_mmio`).
//!   `intel_dmc_wl` enables the DMC wakelock by default on display 30.
//! - Wa_15015404425 (xe_device_wa_oob.rules `PLATFORM(PANTHERLAKE)`):
//!   disabled by `xe_device_probe` before `xe_display_init` on a media GT
//!   at or after B0 ([`wa_15015404425`]).
//!
//! Supported on display 30: opted-in eDP takeover, linear, X-tiled and
//! Tile4 primary flips through DPT, the 64x64 cursor, CTM and double-buffered
//! LUTs, DSB transactions, and the Xe `SCANOUT` create flag.
//! Refused on display 30: eDP on Type-C, the C20 tables, every external
//! output, PSR and panel replay, FBC (and its dirty rectangles), compressed
//! primaries, DC states, system suspend and relight, and Wildcat Lake (30.02).

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError};
use crate::intel_gpu_xe2lpd::{DisplayIp, IpError, DFSM_PIPE_A_DISABLE, SKL_DFSM};
use crate::intel_gpu_xelpg::{PhyKind, XeLpgPort};
use crate::intel_gpu_xelpg_cdclk::Rung;
use crate::intel_gpu_xelpg_wm::Latency;

// ── Route ────────────────────────────────────────────────────────

/// The boot option requesting the Panther Lake display route.
pub(crate) const OPT_IN: &str = "narf.intel.ptl_display";

/// `narf.intel.ptl_display=1`, with the strict grammar every Intel
/// destructive opt-in uses ([`crate::intel_gpu_gt::boot_opt_in`]).
pub(crate) fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, OPT_IN)
}

/// `PICA_PHY_CONFIG_CONTROL` and `EDP_ON_TYPEC` (`intel_cx0_phy_regs.h`).
pub(crate) const PICA_PHY_CONFIG_CONTROL: u64 = 0x16fe68;
pub(crate) const EDP_ON_TYPEC: u32 = 1 << 31;
/// `TRANSCONF(A)`.
const TRANSCONF_A: u64 = 0x70008;

/// Why a Panther Lake function keeps its headless profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteRefusal {
    /// Not a Panther Lake function.
    NotPantherLake,
    /// `narf.intel.ptl_display=1` was not given.
    NotRequested,
    /// The display IP is not 30.00 (absent, Wildcat Lake's 30.02, foreign
    /// or unreadable).
    Ip(IpError),
    /// `SKL_DFSM` fuses Pipe A off.
    PipeAFused,
    /// `PICA_PHY_CONFIG_CONTROL.EDP_ON_TYPEC`: the panel is on a C20 Type-C
    /// PHY (`xe3lpd_c20_dp_edp_tables`), which is not owned.
    EdpOnTypeC,
    /// Firmware left Pipe A dark: there is no panel pipeline to take over.
    PipeADark,
}

/// Decide the display route for one Panther Lake function. Read-only: no
/// register is written, so every refusal leaves the function exactly as the
/// headless profile expects to find it.
pub(crate) fn display_route(
    generation: crate::intel_gpu::Generation,
    requested: bool,
    io: &(impl MmioWindow + ?Sized),
) -> Result<DisplayIp, RouteRefusal> {
    if generation != crate::intel_gpu::Generation::PantherLake {
        return Err(RouteRefusal::NotPantherLake);
    }
    if !requested {
        return Err(RouteRefusal::NotRequested);
    }
    let ip = DisplayIp::read_all(io).map_err(RouteRefusal::Ip)?;
    if ip != DisplayIp::Xe3Lpd {
        return Err(RouteRefusal::Ip(IpError::Unqualified {
            ver: ip.ver(),
            rel: 0,
        }));
    }
    let dfsm = io.read32(SKL_DFSM);
    let pica = io.read32(PICA_PHY_CONFIG_CONTROL);
    let conf = io.read32(TRANSCONF_A);
    if dfsm == u32::MAX || pica == u32::MAX || conf == u32::MAX || !io.display_access_ok() {
        return Err(RouteRefusal::Ip(IpError::NoDevice));
    }
    if dfsm & DFSM_PIPE_A_DISABLE != 0 {
        return Err(RouteRefusal::PipeAFused);
    }
    if pica & EDP_ON_TYPEC != 0 {
        return Err(RouteRefusal::EdpOnTypeC);
    }
    if conf & (3 << 30) != 3 << 30 {
        return Err(RouteRefusal::PipeADark);
    }
    Ok(ip)
}

/// The probe's route decision for one Panther Lake function: `true` only
/// when [`display_route`] admits the display. Without the option no
/// register is touched (and BAR0 is not even mapped), so the headless
/// profile's probe runs exactly as before.
pub(crate) fn probe_route(
    device: &narf_bus::BusDevice,
    cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> bool {
    let ptl = crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
        .is_some_and(|p| p.is_ptl());
    if !ptl || !requested(narf_boot::args()) {
        return false;
    }
    if narf_bus::pci::set_command(
        cap,
        device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .is_err()
    {
        return false;
    }
    // SAFETY: the PCI probe grants exclusive ownership of this function's
    // BAR0; an identical later mapping reuses the same typed VA.
    let Ok(bar) = (unsafe { narf_bus::bar::map_bar(device, 0) }) else {
        return false;
    };
    let route = display_route(
        crate::intel_gpu::Generation::PantherLake,
        true,
        &crate::intel_gpu_edp::BarWindow(&bar),
    );
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "intel-gpu: Panther Lake display route (PCI {:04x}:{:04x}): {:?}",
            device.id.vendor,
            device.id.device,
            route,
        );
    }
    route.is_ok()
}

// ── Wa_15015404425 and the display-30 register view ──────────────

/// The media GT's `GMD_ID` (`MEDIA_GT_GSI_OFFSET` + `GMD_ID`).
pub(crate) const MEDIA_GMD_ID: u64 = 0x380d8c;

/// Whether Wa_15015404425 is still active when display is taken over:
/// xe_device_wa_oob.rules lists `PLATFORM(PANTHERLAKE)`, and
/// `xe_device_probe` disables it after `xe_gt_init` (and before
/// `xe_display_init`) when the media GT takes `15015404425_disable`
/// (xe_wa_oob.rules: `MEDIA_STEP(B0, FOREVER)`; `xe_step_gmdid_get` steps
/// are `STEP_A0 + GMD_ID_REVID`, so B0 is revid 4). Without a readable
/// media GT the device workaround stays.
pub(crate) const fn wa_15015404425(media_gmd: u32) -> bool {
    if media_gmd == 0 || media_gmd == u32::MAX {
        return true;
    }
    media_gmd & 0x3f < 4
}

/// [`wa_15015404425`] for the function behind `io` (one read of the media
/// `GMD_ID`, which needs no forcewake).
pub(crate) fn wa_15015404425_active(io: &(impl MmioWindow + ?Sized)) -> bool {
    wa_15015404425(io.read32(MEDIA_GMD_ID))
}

/// `__xe2lpd_port_idx` / `__xe2lpd_aux_ch_idx`: on display >= 20 DDI A and
/// B's PHY (`XELPDP_PORT_BUF_CTL1..3`, `XELPDP_PORT_M2P_MSGBUS_CTL`,
/// `XELPDP_PORT_P2M_MSGBUS_STATUS`, `XELPDP_PORT_MSGBUS_TIMER`,
/// `XELPDP_PORT_CLOCK_CTL`) and AUX (`XELPDP_DP_AUX_CH_CTL`, `_DATA1..5`)
/// registers are indexed as the ports after TC4, i.e. in the PICA block at
/// the TC1 layout plus `(PORT_TC4 + 1 + port - PORT_TC1) * 0x200`. `off` is
/// the display-14 offset the PHY code uses; `None` for every other register
/// (`DDI_BUF_CTL` and `DDI_CLK_VALFREQ` stay `_MMIO_PORT`).
pub(crate) const fn pica_port_reg(off: u64) -> Option<u64> {
    let (port, rel) = match off {
        0x64000..=0x640ff => (0u64, off - 0x64000),
        0x64100..=0x641ff => (1u64, off - 0x64100),
        _ => return None,
    };
    if rel % 4 != 0 {
        return None;
    }
    // PORT_TC4 (6) + 1 + port, relative to PORT_TC1 (3).
    let base = 0x16f200 + (7 + port - 3) * 0x200;
    let pica = match rel {
        // PORT_BUF_CTL1..3: 0x64004 on DDI A, +0x00 in the TC layout.
        0x04..=0x0c => rel - 0x04,
        // DP_AUX_CH_CTL and DATA1..5.
        0x10..=0x24 => rel,
        // M2P_MSGBUS_CTL ln0/ln1, P2M_MSGBUS_STATUS ln0/ln1.
        0x40..=0x4c => rel,
        // PORT_MSGBUS_TIMER ln0/ln1: 0x640d8 on DDI A, +0x58 in TC.
        0xd8 | 0xdc => rel - 0x80,
        // PORT_CLOCK_CTL: 0x640e0 on DDI A, +0x60 in TC.
        0xe0 => 0x60,
        _ => return None,
    };
    Some(base + pica)
}

/// The display-30 register view of the route and its owned modeset: DDI A/B
/// PHY and AUX registers are relocated into the PICA block
/// ([`pica_port_reg`]), the Cx0 PHY code takes the display-30 message-bus
/// and clock-select dialect ([`MmioWindow::cx0_xe3`]), and with `flush`
/// every read follows Wa_15015404425's four dummy writes
/// (xe_mmio.c::mmio_flush_pending_writes).
pub(crate) struct View<'a, M: MmioWindow + ?Sized> {
    raw: &'a M,
    flush: bool,
}

impl<'a, M: MmioWindow + ?Sized> View<'a, M> {
    pub(crate) fn new(raw: &'a M, flush: bool) -> Self {
        Self { raw, flush }
    }
}

impl<M: MmioWindow + ?Sized> MmioWindow for View<'_, M> {
    fn display_access_ok(&self) -> bool {
        self.raw.display_access_ok()
    }
    fn cx0_xe3(&self) -> bool {
        true
    }
    fn read32(&self, off: u64) -> u32 {
        if self.flush {
            for _ in 0..4 {
                self.raw
                    .write32(crate::intel_gpu_xe2lpd::MMIO_FLUSH_DUMMY, 0);
            }
        }
        self.raw.read32(pica_port_reg(off).unwrap_or(off))
    }
    fn write32(&self, off: u64, val: u32) {
        self.raw.write32(pica_port_reg(off).unwrap_or(off), val)
    }
}

// ── Owned modeset ────────────────────────────────────────────────

/// The display-30 owned Pipe-A modeset, through the display-14 orchestrator
/// dispatched on Xe3_LPD. `mmio` must be a [`View`]. Refused read-only
/// unless the hardware reports display 30.00: the generation never selects
/// it ([`crate::intel_gpu_modeset::modeset_display`] keeps refusing
/// Panther Lake).
pub(crate) fn modeset<M: MmioWindow + ?Sized>(
    mmio: &M,
    fb: &Framebuffer,
    mode: Option<&Mode>,
) -> Result<Mode, ModesetError> {
    if !mmio.cx0_xe3() || DisplayIp::read_all(mmio) != Ok(DisplayIp::Xe3Lpd) {
        return Err(ModesetError::UnsupportedGeneration);
    }
    let mut ms = crate::intel_gpu_modeset_xelpg::XeLpgModeset::new(mmio, XeLpgPort::A)
        .with_display_ip(DisplayIp::Xe3Lpd);
    match mode {
        Some(mode) => ms.modeset_fixed(fb, mode),
        None => ms.modeset(fb, None),
    }
}

/// Take over the firmware-lit Pipe A at its current surface, running the
/// display-30 modeset at the panel's EDID mode.
pub(crate) fn takeover<M: MmioWindow + ?Sized>(mmio: &M) -> Option<Mode> {
    use crate::intel_gpu_pipes::{
        Pipe, PIPECONF_ENABLE, PIPECONF_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_STRIDE_OFFSET,
        PLANE_SURF_OFFSET,
    };
    let pipe_base = Pipe::A.base();
    let conf = mmio.read32(pipe_base + PIPECONF_OFFSET);
    if conf == u32::MAX || conf & PIPECONF_ENABLE == 0 {
        return None;
    }
    let plane_base = pipe_base + PLANE_PRIMARY_OFFSET;
    let surf = mmio.read32(plane_base + PLANE_SURF_OFFSET);
    let stride = mmio.read32(plane_base + PLANE_STRIDE_OFFSET);
    if surf == u32::MAX || stride == u32::MAX {
        return None;
    }
    let fb = Framebuffer {
        phys_addr: u64::from(surf & !0xFFF),
        stride_bytes: stride.checked_mul(64)?,
        format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
    };
    modeset(mmio, &fb, None).ok()
}

/// The route's probe-time modeset window: eDP panel power sequencing on
/// `pps`, `light` (production: [`takeover`]) on `mode`, and the PPS
/// backlight gate once the panel is lit, all through [`View`] (with
/// Wa_15015404425's flush when `flush`). `Err` is a panel power failure,
/// with nothing lit; `Ok(None)` a refused takeover.
pub(crate) fn probe_window<P, M, T>(
    pps: &P,
    mode: &M,
    flush: bool,
    light: impl FnOnce(&View<'_, M>) -> Option<T>,
) -> Result<Option<T>, crate::intel_gpu_edp::PpsError>
where
    P: MmioWindow + ?Sized,
    M: MmioWindow + ?Sized,
{
    let pps = View::new(pps, flush);
    let mut sequencer = crate::intel_gpu_edp::PanelPowerSequencer::new(&pps);
    sequencer.init_registers();
    sequencer.power_on()?;
    let lit = light(&View::new(mode, flush));
    if lit.is_some() {
        let _ = sequencer.backlight_on();
    }
    Ok(lit)
}

// ── Power wells (model) ──────────────────────────────────────────

/// The `PWR_WELL_CTL2` wells of the display-30 main map (`.hsw.idx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Well {
    /// `ICL_PW_CTL_IDX_PW_1` (0).
    Pw1,
    /// `ICL_PW_CTL_IDX_PW_2` (1).
    Pw2,
    /// `XELPD_PW_CTL_IDX_PW_A` (5) .. `_PW_D` (8).
    PwA,
    PwB,
    PwC,
    PwD,
}

impl Well {
    /// The `HSW_PWR_WELL_CTL` index.
    pub(crate) const fn idx(self) -> u32 {
        match self {
            Self::Pw1 => 0,
            Self::Pw2 => 1,
            Self::PwA => 5,
            Self::PwB => 6,
            Self::PwC => 7,
            Self::PwD => 8,
        }
    }
}

/// The power-gate parent of `well` (the comment above
/// `xe3lpd_power_wells`: PG1 → PGA, PGB, PG2; PG2 → PGC, PGD), against
/// display 14/20 where PW_2 also parents PW_B (`XELPDP_PW_2_POWER_DOMAINS`
/// includes `XELPD_PW_B_POWER_DOMAINS`).
pub(crate) const fn parent(ip: DisplayIp, well: Well) -> Option<Well> {
    match (ip, well) {
        (_, Well::Pw1) => None,
        (_, Well::Pw2 | Well::PwA) => Some(Well::Pw1),
        (DisplayIp::Xe3Lpd, Well::PwB) => Some(Well::Pw1),
        (DisplayIp::Xelpdp | DisplayIp::Xe2Lpd, Well::PwB) => Some(Well::Pw2),
        (_, Well::PwC | Well::PwD) => Some(Well::Pw2),
    }
}

/// The wells the owned Pipe-A eDP modeset requests, in order: PW_1
/// (transcoder A, DDI A/B), PW_A (pipe A) and the AUX A channel request
/// (`xelpdp_power_wells_aux`). Identical on display 14, 20 and 30.
pub(crate) const PIPE_A_EDP_WELLS: [Well; 2] = [Well::Pw1, Well::PwA];

/// Power domains named by the DC_off well delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Domain {
    PipeB,
    PipeC,
    PipeD,
    TranscoderC,
    TranscoderD,
    Vga,
    DdiLanesTc,
    AudioMmio,
    AudioPlayback,
}

/// The domains of DC_off beyond `POWER_DOMAIN_DC_OFF` and `INIT`:
/// `xe2lpd_pwdoms_dc_off` (`XELPD_PW_C/D_POWER_DOMAINS`, `AUDIO_MMIO`) on
/// display 20, `xe3lpd_pwdoms_dc_off` (`XE3LPD_PW_2/C/D_POWER_DOMAINS`,
/// `AUDIO_MMIO`, `AUDIO_PLAYBACK`) on display 30.
pub(crate) const fn dc_off_domains(ip: DisplayIp) -> &'static [Domain] {
    match ip {
        DisplayIp::Xe3Lpd => &[
            Domain::PipeC,
            Domain::PipeD,
            Domain::TranscoderC,
            Domain::TranscoderD,
            Domain::Vga,
            Domain::DdiLanesTc,
            Domain::AudioMmio,
            Domain::AudioPlayback,
        ],
        DisplayIp::Xelpdp | DisplayIp::Xe2Lpd => &[
            Domain::PipeC,
            Domain::PipeD,
            Domain::TranscoderC,
            Domain::TranscoderD,
            Domain::AudioMmio,
        ],
    }
}

// ── CDCLK ────────────────────────────────────────────────────────

const fn rung(cdclk_khz: u32, ratio: u32, waveform: u16) -> Rung {
    Rung {
        cdclk_khz,
        ratio,
        waveform,
    }
}

/// `xe3lpd_cdclk_table` (38.4 MHz reference).
pub(crate) const CDCLK_TABLE: [Rung; 29] = [
    rung(153_600, 16, 0xaaaa),
    rung(172_800, 16, 0xad5a),
    rung(192_000, 16, 0xb6b6),
    rung(211_200, 16, 0xdbb6),
    rung(230_400, 16, 0xeeee),
    rung(249_600, 16, 0xf7de),
    rung(268_800, 16, 0xfefe),
    rung(288_000, 16, 0xfffe),
    rung(307_200, 16, 0xffff),
    rung(326_400, 17, 0xffff),
    rung(345_600, 18, 0xffff),
    rung(364_800, 19, 0xffff),
    rung(384_000, 20, 0xffff),
    rung(403_200, 21, 0xffff),
    rung(422_400, 22, 0xffff),
    rung(441_600, 23, 0xffff),
    rung(460_800, 24, 0xffff),
    rung(480_000, 25, 0xffff),
    rung(499_200, 26, 0xffff),
    rung(518_400, 27, 0xffff),
    rung(537_600, 28, 0xffff),
    rung(556_800, 29, 0xffff),
    rung(576_000, 30, 0xffff),
    rung(595_200, 31, 0xffff),
    rung(614_400, 32, 0xffff),
    rung(633_600, 33, 0xffff),
    rung(652_800, 34, 0xffff),
    rung(672_000, 35, 0xffff),
    rung(691_200, 36, 0xffff),
];

/// `intel_update_max_cdclk`, display 30.00.
pub(crate) const MAX_CDCLK_KHZ: u32 = 691_200;

// ── Bandwidth ────────────────────────────────────────────────────

/// `xe3lpd_sa_info.deprogbwlimit` (GB/s); deburst 32, displayrtids 256 and
/// derating 10 equal `mtl_sa_info`.
pub(crate) const DEPROGBWLIMIT_GBPS: i64 = 65;

// ── PHY ──────────────────────────────────────────────────────────

/// `intel_encoder_is_c10phy` on Panther Lake (not Wildcat Lake): only PHY A
/// is a C10; PHY B and the Type-C PHYs are C20.
pub(crate) const fn phy_kind(port: XeLpgPort) -> PhyKind {
    match port {
        XeLpgPort::A => PhyKind::C10,
        _ => PhyKind::C20,
    }
}

/// `cx0_power_control_disable_val` on display 30: P2PG on a C10 PHY and on
/// a C20 PHY driving eDP, P4PG otherwise.
pub(crate) const fn power_control_disable_val(kind: PhyKind, edp: bool) -> u32 {
    match (kind, edp) {
        (PhyKind::C10, _) | (PhyKind::C20, true) => crate::intel_gpu_xelpg::P2PG_STATE_DISABLE,
        (PhyKind::C20, false) => crate::intel_gpu_xelpg::P4PG_STATE_DISABLE,
    }
}

// ── VRR timing generator ─────────────────────────────────────────

/// Transcoder-A registers of `intel_vrr_regs.h` and `intel_display_regs.h`.
pub(crate) const TRANS_VRR_CTL_A: u64 = 0x60420;
pub(crate) const TRANS_VRR_VMAX_A: u64 = 0x60424;
pub(crate) const TRANS_VRR_STATUS_A: u64 = 0x6042c;
pub(crate) const TRANS_VRR_VMIN_A: u64 = 0x60434;
pub(crate) const TRANS_VRR_FLIPLINE_A: u64 = 0x60438;
pub(crate) const TRANS_VRR_VSYNC_A: u64 = 0x60078;
pub(crate) const TRANS_PUSH_A: u64 = 0x60a70;
pub(crate) const EMP_AS_SDP_TL_A: u64 = 0x60204;
pub(crate) const TRANS_SET_CONTEXT_LATENCY_A: u64 = 0x6007c;
pub(crate) const DP_MIN_HBLANK_CTL_A: u64 = 0x600ac;
pub(crate) const VRR_CTL_VRR_ENABLE: u32 = 1 << 31;
pub(crate) const VRR_CTL_FLIP_LINE_EN: u32 = 1 << 29;
pub(crate) const VRR_CTL_GUARDBAND_MASK: u32 = 0xffff;
pub(crate) const VRR_STATUS_VRR_EN_LIVE: u32 = 1 << 27;
pub(crate) const TRANS_PUSH_EN: u32 = 1 << 31;

const FX: u64 = 1 << 16;

/// `prefill_usecs_to_lines` (.16 lines) on the pipe's own clock.
fn usecs_to_lines(clock_khz: u64, htotal: u64, us: u64) -> u64 {
    (clock_khz * (us << 16)).div_ceil(htotal * 1000)
}

/// `prefill_adjust`.
fn adjust(value: u64, factor: u64) -> u64 {
    (value * factor).div_ceil(FX)
}

/// `intel_vrr_compute_guardband` for the owned Pipe-A eDP stream at fixed
/// refresh on display 30 (`intel_vrr_compute_fixed_rr_timings`: vmin =
/// vmax = flipline = vtotal; no PSR, so `set_context_latency` is 0;
/// `intel_vrr_use_optimized_guardband` holds for DP):
/// `intel_vrr_compute_optimized_guardband` is the worst-case prefill
/// (`skl_prefill_init_worst`: frame-start delay and 20 µs, the VDSC lines,
/// `num_scalers` worst-case scaler lines and adjustments,
/// `skl_wm0_prefill_lines_worst` and the CDCLK adjustment) plus the
/// larger of the SAGV block time and the highest level-1+ latency
/// (`skl_prefill_min_guardband`), at least `intel_dp_sdp_min_guardband(..,
/// true)` (gamut metadata 8, PPS 7, adaptive sync `vtotal - vsync_start +
/// 1`), capped by `intel_vrr_max_guardband` (`vtotal - vdisplay`, the
/// guardband field's 0xffff). `None` for a mode the computation cannot
/// describe.
pub(crate) fn vrr_guardband(
    mode: &Mode,
    latency: &Latency,
    dsc: bool,
    num_scalers: u8,
) -> Option<u16> {
    let clock = u64::from(mode.pixel_clock_khz);
    let htotal = u64::from(mode.h_total);
    if clock == 0
        || htotal == 0
        || mode.v_active == 0
        || mode.v_total <= mode.v_active
        || mode.v_sync_start > mode.v_total
    {
        return None;
    }
    // intel_compute_max_dotclk: ppc 2, guardband 100.
    let max_dotclk = 2 * u64::from(MAX_CDCLK_KHZ);
    // _skl_scaler_max_scale.
    let cap = |max: u64| max.min((max_dotclk << 16).div_ceil(clock));
    let (total_scale, hscale, scale) = if num_scalers == 0 {
        (FX, FX, FX)
    } else {
        let total = if num_scalers > 1 { 81 << 16 } else { 9 << 16 };
        (cap(total), cap(3 << 16), cap(9 << 16))
    };
    let pixel_rate = u32::try_from((total_scale * clock).div_ceil(FX)).ok()?;
    let width = u32::try_from((hscale * u64::from(mode.h_active)).div_ceil(FX)).ok()?;
    let wm0 = crate::intel_gpu_xelpg_wm::wm0_prefill_lines_worst_xe3(
        pixel_rate,
        u32::from(mode.h_total),
        width,
        latency,
    )
    .ok()?;
    let (scaler_1st, adj_1st) = if num_scalers > 0 {
        (4 << 16, scale)
    } else {
        (0, FX)
    };
    let (scaler_2nd, adj_2nd) = if num_scalers > 1 {
        (4 << 16, scale)
    } else {
        (0, FX)
    };
    // intel_cdclk_prefill_adjustment_worst: calc_cdclk at the pixel-rate
    // minimum (ppc 2, guardband 100), clamped to 1.
    let cdclk = u64::from(
        crate::intel_gpu_xelpg_cdclk::calc_cdclk_ip(
            DisplayIp::Xe3Lpd,
            u32::try_from(clock.div_ceil(2)).ok()?,
        )?
        .cdclk_khz,
    );
    let adj_cdclk = (clock << 16).div_ceil(2 * cdclk).min(FX);
    // prefill_lines_nocdclk.
    let dsc_lines = if dsc {
        crate::intel_gpu_xelpg_dsc::PREFILL_LINES
    } else {
        0
    };
    let mut prefill = adjust(dsc_lines, adj_2nd);
    prefill += scaler_2nd;
    prefill = adjust(prefill, adj_1st);
    prefill += scaler_1st;
    prefill += wm0;
    // prefill_lines_full: fixed (frame-start delay 1 + 20 µs) + cdclk.
    let full = (1 << 16) + usecs_to_lines(clock, htotal, 20) + adjust(prefill, adj_cdclk);
    // skl_watermark_max_latency(display, 1).
    let pkgc = latency.levels[1..]
        .iter()
        .rev()
        .copied()
        .find(|l| *l != 0)
        .unwrap_or(0);
    let pm_delay = u64::from(latency.sagv_block_us.max(pkgc));
    let mut guardband = (full + usecs_to_lines(clock, htotal, pm_delay)).div_ceil(FX);
    // intel_dp_sdp_min_guardband(crtc_state, true).
    let vsync_start = u64::from(mode.v_total - mode.v_sync_start);
    guardband = guardband.max(8).max(7).max(vsync_start + 1);
    let max = u64::from(mode.v_total - mode.v_active).min(u64::from(VRR_CTL_GUARDBAND_MASK));
    u16::try_from(guardband.min(max)).ok()
}

/// `__intel_display_device_info_runtime_init`'s scaler count for Pipe A:
/// two per pipe on display >= 11, one when `XE2LPD_DE_CAP` reports a single
/// scaler.
pub(crate) fn num_scalers(io: &(impl MmioWindow + ?Sized)) -> Result<u8, IpError> {
    let cap = crate::intel_gpu_xe2lpd::DeCap::read(io)?;
    Ok(if cap.single_scaler { 1 } else { 2 })
}

/// [`vrr_guardband`] for `mode` with the scaler count read from `io`.
pub(crate) fn vrr_guardband_for(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
    dsc: Option<crate::intel_gpu_xelpg_dsc::DscTerm>,
    latency: &Latency,
) -> Result<u16, IpError> {
    vrr_guardband(mode, latency, dsc.is_some(), num_scalers(io)?).ok_or(IpError::NoDevice)
}

/// `intel_vrr_transcoder_disable` → `intel_vrr_tg_disable` for the old
/// state read back (`intel_vrr_get_config`: VRR is possible when
/// `VRR_CTL_FLIP_LINE_EN` is set): `TRANS_VRR_CTL` keeps only the flip
/// line enable and the old guardband, `VRR_STATUS_VRR_EN_LIVE` clears
/// within 1 s, then `TRANS_PUSH` is cleared.
pub(crate) fn tg_disable(io: &(impl MmioWindow + ?Sized)) -> Result<(), IpError> {
    let ctl = read(io, TRANS_VRR_CTL_A)?;
    if ctl & VRR_CTL_FLIP_LINE_EN == 0 {
        return Ok(());
    }
    io.write32(
        TRANS_VRR_CTL_A,
        VRR_CTL_FLIP_LINE_EN | (ctl & VRR_CTL_GUARDBAND_MASK),
    );
    wait(io, TRANS_VRR_STATUS_A, VRR_STATUS_VRR_EN_LIVE, 0, 1_000_000)?;
    io.write32(TRANS_PUSH_A, 0);
    Ok(())
}

/// `TRANS_VTOTAL` on display 30: `intel_vrr_always_use_vrr_tg` makes
/// `intel_set_transcoder_timings` write `VTOTAL(1 - 1)`, keeping only
/// `VACTIVE(crtc_vdisplay - 1)`.
pub(crate) const fn trans_vtotal(mode: &Mode) -> u32 {
    (mode.v_active as u32).saturating_sub(1) & 0xffff
}

/// `intel_vrr_set_transcoder_timings` for Pipe A at fixed refresh
/// (`intel_vrr_compute_fixed_rr_timings`): `intel_vrr_set_fixed_rr_timings`
/// writes VMIN/VMAX/FLIPLINE = vtotal - 1 (no display < 13 offsets), then
/// `TRANS_VRR_VSYNC` (`HAS_AS_SDP`: `vtotal - vsync_end` / `vtotal -
/// vsync_start`) and `EMP_AS_SDP_TL` (display >= 20: the adaptive-sync
/// transmission line at `vtotal - vsync_start`). `TRANS_VRR_CTL` is left to
/// the enable: the timing generator is always used.
pub(crate) fn program_vrr_timings(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
) -> Result<(), IpError> {
    let vtotal = u32::from(mode.v_total);
    if mode.v_sync_end > mode.v_total || mode.v_sync_start > mode.v_sync_end || vtotal == 0 {
        return Err(IpError::NoDevice);
    }
    let vsync_start = vtotal - u32::from(mode.v_sync_start);
    let vsync_end = vtotal - u32::from(mode.v_sync_end);
    io.write32(TRANS_VRR_VMIN_A, vtotal - 1);
    io.write32(TRANS_VRR_VMAX_A, vtotal - 1);
    io.write32(TRANS_VRR_FLIPLINE_A, vtotal - 1);
    io.write32(
        TRANS_VRR_VSYNC_A,
        ((vsync_end & 0x1fff) << 16) | (vsync_start & 0x1fff),
    );
    io.write32(EMP_AS_SDP_TL_A, vsync_start & 0x1fff);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(IpError::NoDevice)
    }
}

/// `intel_vrr_transcoder_enable` → `intel_vrr_tg_enable` (no CMRR):
/// `TRANS_PUSH` = `TRANS_PUSH_EN`, then `TRANS_VRR_CTL` = enable, flip line
/// enable and the guardband (`trans_vrr_ctl`, display >= 14).
pub(crate) fn tg_enable(io: &(impl MmioWindow + ?Sized), guardband: u16) -> Result<(), IpError> {
    io.write32(TRANS_PUSH_A, TRANS_PUSH_EN);
    io.write32(
        TRANS_VRR_CTL_A,
        VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN | u32::from(guardband),
    );
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(IpError::NoDevice)
    }
}

fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, IpError> {
    let v = io.read32(r);
    if v == u32::MAX || !io.display_access_ok() {
        Err(IpError::NoDevice)
    } else {
        Ok(v)
    }
}

fn wait(
    io: &(impl MmioWindow + ?Sized),
    r: u64,
    mask: u32,
    want: u32,
    us: u64,
) -> Result<(), IpError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(r);
            lost = v == u32::MAX || !io.display_access_ok();
            lost || v & mask == want
        },
        narf_time::Deadline::after_us(us),
    );
    if lost || !done {
        Err(IpError::NoDevice)
    } else {
        Ok(())
    }
}

// ── DMC ──────────────────────────────────────────────────────────

/// `DMC_PATH(xe3lpd)`; its payload ceiling is `XE2LPD_DMC_MAX_FW_SIZE`.
pub(crate) const XE3LPD_DMC_FIRMWARE: &str = "i915/xe3lpd_dmc.bin";

/// `need_pipedmc_load_mmio` on display 30: pipe A/B DMC keeps its state,
/// pipe C/D DMC lives in PG0 and needs its MMIO restored.
pub(crate) const fn need_pipedmc_load_mmio(pipe: u32) -> bool {
    pipe >= 2
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xe3lpd_tests.rs"]
mod tests;
