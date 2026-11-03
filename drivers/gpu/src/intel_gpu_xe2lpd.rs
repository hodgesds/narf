//! Display version 20 — Xe2_LPD (Lunar Lake): identification, per-device
//! display admission, and the display-20 deltas the display-14 (Xe_LPD+,
//! Meteor/Arrow Lake) chain dispatches on.
//!
//! Pinned source: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//!
//! ## Identification
//!
//! `intel_display_device.c::probe_gmdid_display` reads `GMD_ID_DISPLAY`
//! (0x510a0): zero is "Device doesn't have display", otherwise the
//! architecture (31:22) and release (21:14) select `gmdid_display_map`.
//! 14.00 is `xe_lpdp_display` (MTL/ARL) and 20.00 is `xe2_lpd_display`
//! (LNL): `XE_LPDP_FEATURES` plus FBC on all four pipes and DBUF overlap
//! detection. 14.01 (BMG, `xe2_hpd_display`), 30.00/30.02 (PTL/WCL) and
//! 35.00 are other IPs and are refused by type here. `INTEL_LNL_IDS` binds
//! the three LNL PCI IDs to `lnl_desc`, which carries no display info:
//! display 20 is known only from the hardware's GMD.
//! `__intel_display_device_info_runtime_init` then drops fused pipes
//! (`SKL_DFSM`) and, for display >= 20, reads `XE2LPD_DE_CAP` (DSC
//! removed, single scaler).
//!
//! ## Admission and the headless profile
//!
//! Lunar Lake's existing profile is the headless main GT
//! ([`crate::intel_gpu_lnl_takeover`]), which owns the device through a
//! driver FLR. `xe_device.c::__xe_driver_flr` resets GT, display and stolen
//! memory, so that FLR would tear down the panel a display takeover adopts.
//! The display route therefore never runs a driver FLR: it adopts the
//! firmware-lit Pipe A exactly as the Meteor Lake takeover does. The two
//! owners are exclusive per function. This route is taken only when it is
//! requested (`narf.intel.lnl_display=1`), the GMD is display 20.00, Pipe A
//! is not fused off and firmware left Pipe A lit; every refusal keeps the
//! headless profile, which itself still refuses while a boot framebuffer
//! or a KMS display exists.
//!
//! ## Display-20 deltas (each against its display-14 counterpart)
//!
//! - Power wells (`intel_display_power_map.c::xe2lpd_power_wells`): the
//!   same PW_1, PW_2, PW_A–D (`xelpdp_power_wells_main`) and per-channel
//!   AUX requests (`xelpdp_power_wells_aux`); a new always-requested
//!   `PICA_TC` well (`XE2LPD_PICA_PW_CTL`, Type-C lanes and AUX only); and
//!   a DC_off well whose domains add pipes C/D and `AUDIO_MMIO`. The Pipe-A
//!   eDP sequence is unchanged.
//! - CDCLK (`intel_cdclk.c`): `xe2lpd_cdclk_table` (21 rungs, squash
//!   waveforms on every rung, 0xffff at the full VCO), the same
//!   `rplu_cdclk_funcs` voltage levels and 652.8 MHz maximum.
//!   `bxt_cdclk_ctl` writes `MDCLK_SOURCE_SEL_CDCLK_PLL` instead of the
//!   decimal field (`mdclk_source_is_cdclk_pll`), and `bxt_set_cdclk`
//!   reprograms the MDCLK/CDCLK ratio (`xe2lpd_mdclk_cdclk_ratio_program`)
//!   before lowering and after raising. Wa_13012396614 is 30.00 only;
//!   `pll_enable_wa_needed` covers 20.00.
//! - DBUF/MBUS (`skl_watermark.c`): the ratio is `DIV_ROUND_UP(vco,
//!   cdclk)` instead of 2; `intel_dbuf_mdclk_cdclk_ratio_update` writes
//!   `MBUS_TRANSLATION_THROTTLE_MIN(ratio - 1)` and each slice's
//!   `DBUF_MIN_TRACKER_STATE_SERVICE` with the ratio doubled when joined.
//!   `pipe_mbus_dbox_ctl` drops the 14.00-only BW credits.
//!   `intel_program_dpkgc_latency` programs `LNL_PKG_C_LATENCY`.
//! - PM demand (`intel_pmdemand.c`): the pre-Xe3 fields; display 20 polls
//!   `REQ_ENABLE` (Wa_14024400148), as the display-14 owner already does.
//! - PHY (`intel_cx0_phy.c::intel_encoder_is_c10phy`): ports A/B are C10
//!   on LNL as on MTL, so the DDI A eDP PLL tables are shared; the C20
//!   HDMI TMDS `tx_misc`/`term_ctl` differ (TC only).
//! - DDI (`intel_ddi.c`): `mtl_ddi_enable_d2d` moves the D2D link
//!   enable/state to `DDI_BUF_CTL` bits 29/28.
//! - Transcoder (`intel_display.c::intel_enable_transcoder`): display >= 14
//!   clears `DP_DSC_INSERT_SF_AT_EOL_WA`; only display 14 sets
//!   `DP_FEC_BS_JITTER_WA`.
//! - Planes (`intel_dpt_common.c::intel_dpt_configure`): the
//!   `PLANE_CHICKEN` no-DPT bit is display 14 only, so a tiled primary
//!   without DPT is not a display-20 profile; FBC moves to the HDR planes
//!   (`skl_plane_has_fbc`), Tile4 refuses horizontal flips and the LNL CCS
//!   modifier replaces the MTL ones.
//! - DMC (`intel_dmc.c`): `xe2lpd_dmc.bin` with an 0x8000 payload ceiling;
//!   no pipe-DMC MMIO restore and no Wa_16015201720; `DMC_FQ_W2_PTS_CFG_SEL`
//!   after every load; pipe enable/disable reset the flip queue and arm or
//!   mask `PIPEDMC_INTERRUPT`. `get_allowed_dc_mask` caps display 20 at
//!   DC6 (no DC3CO).
//! - PSR (`intel_psr.c`): no PSR1 max-sleep field, entry setup frames,
//!   Wa_16025596647 DMC package-C blocking and the SRD_STATUS set-context
//!   latency — none implemented, so PSR on display 20 stays refused.
//!
//! ## Panther Lake (display 30.00, Xe3_LPD) — refused, deltas recorded
//!
//! `xe3lpd_power_wells` (PW_B parented on PG1, new DC_off domains),
//! `xe3lpd_cdclk_table` (crawl-only rungs to 691.2 MHz, CD2X divider
//! fixed at 1, no CD2X pipe field, Wa_13012396614), PM demand without
//! DBUF slices and a 4-bit pipe field, `xe3lpd_c20_dp_edp_tables`, eDP on
//! Type-C (`PICA_PHY_CONFIG_CONTROL`), C10 only on PHY A (PHY A/B on WCL),
//! no message-bus reset after reads/writes, P2PG disable for C20 eDP,
//! `xe3lpd_dmc.bin`, pipe A/B DMC without PG0 save, double-buffered LUTs
//! and FBC dirty rectangles.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_xelpg::XeLpgPort;
use crate::intel_gpu_xelpg_cdclk::Rung;

// ── Identification ───────────────────────────────────────────────

/// `GMD_ID_DISPLAY`.
pub(crate) const GMD_ID_DISPLAY: u64 = 0x510a0;
/// `SKL_DFSM` and its `SKL_DFSM_PIPE_A_DISABLE`.
pub(crate) const SKL_DFSM: u64 = 0x51000;
pub(crate) const DFSM_PIPE_A_DISABLE: u32 = 1 << 30;
/// `XE2LPD_DE_CAP` (display >= 20).
pub(crate) const DE_CAP: u64 = 0x41100;

/// A display IP the display-14 chain is dispatched on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DisplayIp {
    /// 14.00 (`xe_lpdp_display`): Meteor Lake and Arrow Lake.
    Xelpdp,
    /// 20.00 (`xe2_lpd_display`): Lunar Lake.
    Xe2Lpd,
}

/// Why a display IP is not dispatched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IpError {
    /// Current access was lost, the read was all-ones or not stable.
    NoDevice,
    /// `GMD_ID_DISPLAY` reads zero: "Device doesn't have display".
    Absent,
    /// A display IP outside the qualified set (`gmdid_display_map` maps
    /// 14.01, 30.00, 30.02 and 35.00 to other descriptors).
    Unqualified { ver: u16, rel: u8 },
}

impl DisplayIp {
    /// `probe_gmdid_display` restricted to the qualified IPs.
    pub(crate) const fn decode(gmd: u32) -> Result<Self, IpError> {
        if gmd == 0 {
            return Err(IpError::Absent);
        }
        let ver = (gmd >> 22) as u16;
        let rel = ((gmd >> 14) & 0xff) as u8;
        match (ver, rel) {
            (14, 0) => Ok(Self::Xelpdp),
            (20, 0) => Ok(Self::Xe2Lpd),
            _ => Err(IpError::Unqualified { ver, rel }),
        }
    }

    /// Read and decode `GMD_ID_DISPLAY`; two equal reads are required.
    pub(crate) fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, IpError> {
        let a = io.read32(GMD_ID_DISPLAY);
        let b = io.read32(GMD_ID_DISPLAY);
        if a == u32::MAX || a != b || !io.display_access_ok() {
            return Err(IpError::NoDevice);
        }
        Self::decode(a)
    }

    /// The IP a PCI generation's display is (only for the platforms whose
    /// descriptor maps to exactly one qualified IP).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) const fn for_generation(generation: crate::intel_gpu::Generation) -> Option<Self> {
        match generation {
            crate::intel_gpu::Generation::MeteorLake => Some(Self::Xelpdp),
            crate::intel_gpu::Generation::LunarLake => Some(Self::Xe2Lpd),
            _ => None,
        }
    }

    /// `DISPLAY_VER`.
    pub(crate) const fn ver(self) -> u16 {
        match self {
            Self::Xelpdp => 14,
            Self::Xe2Lpd => 20,
        }
    }

    /// Number of FBC instances (`fbc_mask`): A–B on 14.00, A–D on 20.00.
    pub(crate) const fn fbc_instances(self) -> u64 {
        match self {
            Self::Xelpdp => 2,
            Self::Xe2Lpd => 4,
        }
    }

    /// `intel_dpt_configure`: only display 14 programs the `PLANE_CHICKEN`
    /// no-DPT bit a tiled primary without DPT depends on.
    pub(crate) const fn has_no_dpt_chicken(self) -> bool {
        matches!(self, Self::Xelpdp)
    }

    /// `get_allowed_dc_mask` (display parameters at their defaults):
    /// `max_dc` 4 on display 12–19 (DC3CO | DC6), 2 on display >= 20 (DC6),
    /// with DC9 always allowed on display >= 11. The DC service targets DC6
    /// on both; this records the display-20 cap for its install.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) const fn allowed_dc_mask(self) -> u32 {
        use crate::intel_gpu_dc_states::{
            DC_STATE_EN_DC3CO, DC_STATE_EN_DC9, DC_STATE_EN_UPTO_DC6,
        };
        match self {
            Self::Xelpdp => DC_STATE_EN_DC9 | DC_STATE_EN_DC3CO | DC_STATE_EN_UPTO_DC6,
            Self::Xe2Lpd => DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC6,
        }
    }

    /// `dmc_firmware_default`: the container and its payload ceiling.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) const fn dmc_firmware(self) -> (&'static str, usize) {
        match self {
            Self::Xelpdp => ("i915/mtl_dmc.bin", 0x7000),
            Self::Xe2Lpd => (XE2LPD_DMC_FIRMWARE, XE2LPD_DMC_MAX_FW_SIZE),
        }
    }

    /// `intel_enable_transcoder`'s `CHICKEN_TRANS` (clear, set) bits.
    pub(crate) const fn chicken_trans(self) -> (u32, u32) {
        match self {
            Self::Xelpdp => (DP_DSC_INSERT_SF_AT_EOL_WA, DP_FEC_BS_JITTER_WA),
            Self::Xe2Lpd => (DP_DSC_INSERT_SF_AT_EOL_WA, 0),
        }
    }

    /// The register and (enable, state) bits of the port's D2D link
    /// (`mtl_ddi_enable_d2d`).
    pub(crate) const fn d2d(self, port: XeLpgPort) -> (u64, u32, u32) {
        match self {
            Self::Xelpdp => (
                port.buf_ctl1(),
                crate::intel_gpu_xelpg::PORT_BUF_D2D_LINK_ENABLE,
                crate::intel_gpu_xelpg::PORT_BUF_D2D_LINK_STATE,
            ),
            Self::Xe2Lpd => (
                ddi_buf_ctl(port),
                DDI_BUF_D2D_LINK_ENABLE,
                DDI_BUF_D2D_LINK_STATE,
            ),
        }
    }
}

/// `DDI_BUF_CTL(port)` (`_MMIO_PORT`, keyed by i915 `enum port`).
pub(crate) const fn ddi_buf_ctl(port: XeLpgPort) -> u64 {
    0x64000 + 0x100 * port.port_enum() as u64
}
/// `XE2LPD_DDI_BUF_D2D_LINK_ENABLE` / `_STATE`.
pub(crate) const DDI_BUF_D2D_LINK_ENABLE: u32 = 1 << 29;
pub(crate) const DDI_BUF_D2D_LINK_STATE: u32 = 1 << 28;
/// `CHICKEN_TRANS` bits `intel_enable_transcoder` touches.
pub(crate) const DP_FEC_BS_JITTER_WA: u32 = 1 << 15;
pub(crate) const DP_DSC_INSERT_SF_AT_EOL_WA: u32 = 1 << 4;

/// Display-20 capability fuses (`XE2LPD_DE_CAP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeCap {
    /// `XE2LPD_DE_CAP_DSC_REMOVED`: `has_dsc` cleared.
    pub(crate) dsc_removed: bool,
    /// `XE2LPD_DE_CAP_SCALER_SINGLE`: one scaler per pipe.
    pub(crate) single_scaler: bool,
}

impl DeCap {
    pub(crate) const fn decode(cap: u32) -> Self {
        Self {
            dsc_removed: (cap >> 28) & 3 == 1,
            single_scaler: (cap >> 26) & 3 == 1,
        }
    }
    pub(crate) fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, IpError> {
        let cap = io.read32(DE_CAP);
        if cap == u32::MAX || !io.display_access_ok() {
            return Err(IpError::NoDevice);
        }
        Ok(Self::decode(cap))
    }
}

// ── Per-device admission (the LNL display route) ────────────────

/// The boot option requesting the Lunar Lake display route.
pub(crate) const OPT_IN: &str = "narf.intel.lnl_display";

/// `narf.intel.lnl_display=1`, with the strict grammar every Intel
/// destructive opt-in uses ([`crate::intel_gpu_gt::boot_opt_in`]).
pub(crate) fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, OPT_IN)
}

/// Why a Lunar Lake function keeps its headless profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteRefusal {
    /// Not a Lunar Lake function.
    NotLunarLake,
    /// `narf.intel.lnl_display=1` was not given.
    NotRequested,
    /// The display IP is not 20.00 (absent, foreign or unreadable).
    Ip(IpError),
    /// `SKL_DFSM` fuses Pipe A off.
    PipeAFused,
    /// Firmware left Pipe A dark: there is no panel pipeline to take over.
    PipeADark,
}

/// Decide the display route for one Lunar Lake function. Read-only: no
/// register is written, so every refusal leaves the function exactly as
/// the headless profile expects to find it.
pub(crate) fn display_route(
    generation: crate::intel_gpu::Generation,
    requested: bool,
    io: &(impl MmioWindow + ?Sized),
) -> Result<DisplayIp, RouteRefusal> {
    if generation != crate::intel_gpu::Generation::LunarLake {
        return Err(RouteRefusal::NotLunarLake);
    }
    if !requested {
        return Err(RouteRefusal::NotRequested);
    }
    let ip = DisplayIp::read(io).map_err(RouteRefusal::Ip)?;
    if ip != DisplayIp::Xe2Lpd {
        return Err(RouteRefusal::Ip(IpError::Unqualified {
            ver: ip.ver(),
            rel: 0,
        }));
    }
    let dfsm = io.read32(SKL_DFSM);
    let conf = io.read32(0x70008);
    if dfsm == u32::MAX || conf == u32::MAX || !io.display_access_ok() {
        return Err(RouteRefusal::Ip(IpError::NoDevice));
    }
    if dfsm & DFSM_PIPE_A_DISABLE != 0 {
        return Err(RouteRefusal::PipeAFused);
    }
    if conf & (3 << 30) != 3 << 30 {
        return Err(RouteRefusal::PipeADark);
    }
    Ok(ip)
}

/// The probe's route decision for one Lunar Lake function: `true` only when
/// [`display_route`] admits the display. Without the option no register is
/// touched, so the headless profile's probe runs exactly as before; with it,
/// the decision reads BAR0 (`GMD_ID_DISPLAY`, `SKL_DFSM`, `TRANSCONF_A`)
/// and nothing else.
pub(crate) fn probe_route(
    device: &narf_bus::BusDevice,
    cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> bool {
    let lnl = crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
        .is_some_and(|p| p.is_lnl());
    if !lnl || !requested(narf_boot::args()) {
        return false;
    }
    let generation = crate::intel_gpu::Generation::LunarLake;
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
    let route = display_route(generation, true, &crate::intel_gpu_edp::BarWindow(&bar));
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "intel-gpu: Lunar Lake display route (PCI {:04x}:{:04x}): {:?}",
            device.id.vendor,
            device.id.device,
            route,
        );
    }
    route.is_ok()
}

/// `DUMMY_REG_OFFSET` of xe_mmio.c::mmio_flush_pending_writes.
pub(crate) const MMIO_FLUSH_DUMMY: u64 = 0x130030;

/// A display-20 view with Wa_15015404425 (xe_device_wa_oob.rules:
/// `PLATFORM(LUNARLAKE)`): xe_mmio.c::mmio_flush_pending_writes issues four
/// dummy writes before every MMIO read, display reads included.
pub(crate) struct Flushed<'a, M: MmioWindow + ?Sized>(pub(crate) &'a M);

impl<M: MmioWindow + ?Sized> MmioWindow for Flushed<'_, M> {
    fn display_access_ok(&self) -> bool {
        self.0.display_access_ok()
    }
    fn read32(&self, off: u64) -> u32 {
        for _ in 0..4 {
            self.0.write32(MMIO_FLUSH_DUMMY, 0);
        }
        self.0.read32(off)
    }
    fn write32(&self, off: u64, val: u32) {
        self.0.write32(off, val)
    }
}

/// The GGTT PAT index of a present firmware scanout PTE (xe_ggtt.c
/// `xelpg_ggtt_pte_flags`, used on Xe2: `XELPG_GGTT_PTE_PAT0` bit 52,
/// `XELPG_GGTT_PTE_PAT1` bit 53). `None` for an absent or unreadable entry.
pub(crate) const fn firmware_pte_pat(low: u32, high: u32) -> Option<u8> {
    if low == u32::MAX || high == u32::MAX || low & 1 == 0 {
        return None;
    }
    Some(((high >> 20) & 3) as u8)
}

/// The PAT index the display-20 console is mapped with: the firmware's own
/// lit surface's, which must be 0. NARF's GT owner never redefines Xe2 PAT0
/// (it programs PAT1–5 and PAT7), so the console keeps exactly the
/// firmware's scanout cache policy; GEM flips use PAT3 only after the GT
/// owner programmed it.
pub(crate) const fn console_pat(firmware: Option<u8>) -> Option<u8> {
    match firmware {
        Some(0) => Some(0),
        _ => None,
    }
}

/// Whether the display route still holds Pipe A for its eDP panel (the claim
/// probe records after a successful [`takeover`]). The display-preserving GT
/// profile is admitted only beside that owner.
pub(crate) fn route_owns_pipe_a() -> bool {
    crate::intel_gpu_multipipe::pipe_owner(crate::intel_gpu_pipes::Pipe::A)
        == Some(crate::intel_gpu_multipipe::PipeOwner {
            ddi: crate::intel_gpu_ddi::Ddi::A,
            used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
        })
}

/// The display-20 owned Pipe-A modeset, through the display-14
/// orchestrator dispatched on Xe2_LPD. Refused read-only unless the
/// hardware reports display 20.00: the generation alone never selects it
/// ([`crate::intel_gpu_modeset::modeset_display`] keeps refusing Lunar
/// Lake).
pub(crate) fn modeset<M: MmioWindow + ?Sized>(
    mmio: &M,
    fb: &crate::intel_gpu_modeset::Framebuffer,
    mode: Option<&crate::intel_gpu_modeset::Mode>,
) -> Result<crate::intel_gpu_modeset::Mode, crate::intel_gpu_modeset::ModesetError> {
    if DisplayIp::read(mmio) != Ok(DisplayIp::Xe2Lpd) {
        return Err(crate::intel_gpu_modeset::ModesetError::UnsupportedGeneration);
    }
    let mut ms = crate::intel_gpu_modeset_xelpg::XeLpgModeset::new(mmio, XeLpgPort::A)
        .with_display_ip(DisplayIp::Xe2Lpd);
    match mode {
        Some(mode) => ms.modeset_fixed(fb, mode),
        None => ms.modeset(fb, None),
    }
}

/// Take over the firmware-lit Pipe A at its current surface
/// (`takeover_display`'s shape), running the display-20 modeset at the
/// panel's EDID mode.
pub(crate) fn takeover<M: MmioWindow + ?Sized>(mmio: &M) -> Option<crate::intel_gpu_modeset::Mode> {
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
    let fb = crate::intel_gpu_modeset::Framebuffer {
        phys_addr: u64::from(surf & !0xFFF),
        stride_bytes: stride.checked_mul(64)?,
        format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
    };
    modeset(mmio, &fb, None).ok()
}

/// The route's probe-time modeset window (§17 10.5): eDP panel power
/// sequencing on `pps`, `light` (production: [`takeover`]) on `mode`, and
/// the PPS backlight gate once the panel is lit. Both windows are
/// [`Flushed`]: every read in the window follows Wa_15015404425's four
/// dummy writes, as every Lunar Lake read does in xe
/// (xe_mmio.c::xe_mmio_read32 → `mmio_flush_pending_writes`). `Err` is a
/// panel power failure, with nothing lit; `Ok(None)` a refused takeover.
/// The route decision before it ([`display_route`]) stays read-only.
pub(crate) fn probe_window<P, M, T>(
    pps: &P,
    mode: &M,
    light: impl FnOnce(&Flushed<'_, M>) -> Option<T>,
) -> Result<Option<T>, crate::intel_gpu_edp::PpsError>
where
    P: MmioWindow + ?Sized,
    M: MmioWindow + ?Sized,
{
    let pps = Flushed(pps);
    let mut sequencer = crate::intel_gpu_edp::PanelPowerSequencer::new(&pps);
    sequencer.init_registers();
    sequencer.power_on()?;
    let lit = light(&Flushed(mode));
    if lit.is_some() {
        let _ = sequencer.backlight_on();
    }
    Ok(lit)
}

// ── CDCLK and MDCLK ──────────────────────────────────────────────

const fn rung(cdclk_khz: u32, ratio: u32, waveform: u16) -> Rung {
    Rung {
        cdclk_khz,
        ratio,
        waveform,
    }
}

/// `xe2lpd_cdclk_table` (38.4 MHz reference).
pub(crate) const CDCLK_TABLE: [Rung; 21] = [
    rung(153_600, 16, 0xaaaa),
    rung(172_800, 16, 0xad5a),
    rung(192_000, 16, 0xb6b6),
    rung(211_200, 16, 0xdbb6),
    rung(230_400, 16, 0xeeee),
    rung(249_600, 16, 0xf7de),
    rung(268_800, 16, 0xfefe),
    rung(288_000, 16, 0xfffe),
    rung(307_200, 16, 0xffff),
    rung(330_000, 25, 0xdbb6),
    rung(360_000, 25, 0xeeee),
    rung(390_000, 25, 0xf7de),
    rung(420_000, 25, 0xfefe),
    rung(450_000, 25, 0xfffe),
    rung(480_000, 25, 0xffff),
    rung(487_200, 29, 0xfefe),
    rung(522_000, 29, 0xfffe),
    rung(556_800, 29, 0xffff),
    rung(571_200, 34, 0xfefe),
    rung(612_000, 34, 0xfffe),
    rung(652_800, 34, 0xffff),
];

/// `MDCLK_SOURCE_SEL_CDCLK_PLL` (`CDCLK_CTL` bit 25), which
/// `bxt_cdclk_ctl` writes in place of the decimal field on display >= 20.
pub(crate) const MDCLK_SOURCE_SEL_CDCLK_PLL: u32 = 1 << 25;
/// `MBUS_TRANSLATION_THROTTLE_MIN_MASK` (display 20–34).
pub(crate) const MBUS_THROTTLE_MASK: u32 = 7 << 13;
/// `DBUF_MIN_TRACKER_STATE_SERVICE_MASK`.
pub(crate) const DBUF_MIN_TRACKER_MASK: u32 = 7 << 16;

/// `intel_mdclk_cdclk_ratio` with the MDCLK sourced from the CDCLK PLL:
/// `DIV_ROUND_UP(vco, cdclk)`.
pub(crate) fn mdclk_cdclk_ratio(r: Rung) -> u32 {
    (r.ratio * crate::intel_gpu_xelpg_cdclk::REF_KHZ).div_ceil(r.cdclk_khz)
}

/// `MBUS_TRANSLATION_THROTTLE_MIN(ratio - 1)`.
pub(crate) fn mbus_throttle(ratio: u32) -> u32 {
    (ratio.saturating_sub(1) << 13) & MBUS_THROTTLE_MASK
}

/// `DBUF_MIN_TRACKER_STATE_SERVICE(ratio - 1)`, the ratio doubled when the
/// MBUS is joined.
pub(crate) fn dbuf_min_tracker(ratio: u32, joined: bool) -> u32 {
    let ratio = if joined { ratio * 2 } else { ratio };
    (ratio.saturating_sub(1) << 16) & DBUF_MIN_TRACKER_MASK
}

/// `DBUF_CTL_S(slice)` on display 20 over `old`: the power request for
/// `enabled` and the MDCLK minimum tracker at `ratio`. The tracker state
/// service field (23:19) is preserved: Linux programs it only on display
/// 12 and DG2 (`gen12_dbuf_slices_config`).
pub(crate) fn dbuf_ctl(slice: usize, old: u32, enabled: u8, ratio: u32, joined: bool) -> u32 {
    let request = if enabled & (1 << slice) != 0 {
        1 << 31
    } else {
        0
    };
    (old & !((1 << 31) | (1 << 30) | DBUF_MIN_TRACKER_MASK))
        | request
        | dbuf_min_tracker(ratio, joined)
}

/// `pipe_mbus_dbox_ctl` for display 20: the display >= 14 credits without
/// the 14.00-only `MBUS_DBOX_BW_*CREDITS_MTL` field.
pub(crate) fn dbox(joined: bool) -> u32 {
    let mut v = 2 << 5; // I_CREDIT(2)
    v |= (16 << 20) | (1 << 17) | (1 << 16); // B2B max 16, delay 1, regulate
    v |= if joined { 12 } else { 8 }; // A_CREDIT
    v | (0xa << 8) // B_CREDIT
}

/// `intel_dbuf_mdclk_cdclk_ratio_update` on display 20 for `target`:
/// read-modify-write the MBUS throttle and every slice's minimum tracker.
/// Every write is read back.
pub(crate) fn program_mdclk_ratio(
    io: &(impl MmioWindow + ?Sized),
    target: Rung,
    joined: bool,
) -> Result<(), IpError> {
    let ratio = mdclk_cdclk_ratio(target);
    let read = |r| {
        let v = io.read32(r);
        if v == u32::MAX || !io.display_access_ok() {
            Err(IpError::NoDevice)
        } else {
            Ok(v)
        }
    };
    let mbus = crate::intel_gpu_xelpg_dbuf::MBUS_CTL;
    let value = (read(mbus)? & !MBUS_THROTTLE_MASK) | mbus_throttle(ratio);
    io.write32(mbus, value);
    if read(mbus)? & MBUS_THROTTLE_MASK != value & MBUS_THROTTLE_MASK {
        return Err(IpError::NoDevice);
    }
    for r in crate::intel_gpu_xelpg_dbuf::DBUF_CTL {
        let old = read(r)?;
        let value = (old & !(DBUF_MIN_TRACKER_MASK | (1 << 30))) | dbuf_min_tracker(ratio, joined);
        io.write32(r, value);
        if read(r)? & DBUF_MIN_TRACKER_MASK != value & DBUF_MIN_TRACKER_MASK {
            return Err(IpError::NoDevice);
        }
    }
    Ok(())
}

/// The inherited (raise-only) display-20 CDCLK floor: `bxt_set_cdclk` from
/// the current clock to the first `xe2lpd_cdclk_table` rung at or above
/// `floor_khz`, followed by the MDCLK ratio (raising programs it after the
/// clock) with the current MBUS join. A faster acknowledged clock is kept.
pub(crate) fn raise_cdclk_floor(
    io: &(impl MmioWindow + ?Sized),
    floor_khz: u32,
) -> Result<(), crate::intel_gpu_xelpg_cdclk::CdclkError> {
    use crate::intel_gpu_xelpg_cdclk::{self as cdclk, CdclkError};
    let current = cdclk::Current::read_ip(io, DisplayIp::Xe2Lpd)?;
    if current.known.is_some() && floor_khz <= current.actual_khz {
        return Ok(());
    }
    let target = cdclk::calc_cdclk_ip(DisplayIp::Xe2Lpd, floor_khz.max(current.actual_khz))
        .ok_or(CdclkError::Readback)?;
    cdclk::program_ip(io, DisplayIp::Xe2Lpd, &current, target)?;
    let joined = io.read32(crate::intel_gpu_xelpg_dbuf::MBUS_CTL);
    if joined == u32::MAX {
        return Err(CdclkError::NoDevice);
    }
    program_mdclk_ratio(io, target, joined & (1 << 31) != 0).map_err(|_| CdclkError::Readback)
}

// ── Package C latency ────────────────────────────────────────────

/// `LNL_PKG_C_LATENCY`.
pub(crate) const PKG_C_LATENCY: u64 = 0x46460;
/// `LNL_PKG_C_LATENCY_MASK` (12:0): its all-ones value is "no latency".
pub(crate) const PKG_C_LATENCY_MASK: u32 = 0x1fff;

/// `intel_program_dpkgc_latency` for the pipes `linetimes` lists (each a
/// `WM_LINETIME` value, 1/8 µs; none means no active pipe), with the
/// adjusted `latency` levels. No flip queue is used, so the added wake time
/// is zero (and Wa_22020432604 folds it into the latency anyway).
pub(crate) fn pkgc_latency(
    latency: &crate::intel_gpu_xelpg_wm::Latency,
    linetimes: &[u32],
) -> Option<u32> {
    // skl_watermark_max_latency(display, 1)
    let max_latency = latency.levels[1..]
        .iter()
        .rev()
        .copied()
        .find(|l| *l != 0)
        .map_or(0, u32::from);
    // pkgc_max_linetime: DIV_ROUND_UP(crtc_state->linetime, 8).
    let max_linetime = linetimes.iter().map(|l| l.div_ceil(8)).max().unwrap_or(0);
    let value = if max_linetime == 0 || max_latency == 0 {
        PKG_C_LATENCY_MASK
    } else {
        // Wa_22020299601: a multiple of the pipeline time.
        max_latency.div_ceil(max_linetime) * max_linetime
    };
    (value <= PKG_C_LATENCY_MASK).then_some(value)
}

/// Write `LNL_PKG_C_LATENCY` (added wake time zero) and read it back.
pub(crate) fn program_pkgc_latency(
    io: &(impl MmioWindow + ?Sized),
    value: u32,
) -> Result<(), IpError> {
    if value > PKG_C_LATENCY_MASK {
        return Err(IpError::NoDevice);
    }
    io.write32(PKG_C_LATENCY, value);
    let back = io.read32(PKG_C_LATENCY);
    if back == u32::MAX || !io.display_access_ok() || back != value {
        return Err(IpError::NoDevice);
    }
    Ok(())
}

// ── DMC ──────────────────────────────────────────────────────────

/// `DMC_PATH(xe2lpd)`, the container the display-20 DC service acquires.
pub(crate) const XE2LPD_DMC_FIRMWARE: &str = "i915/xe2lpd_dmc.bin";
/// `XE2LPD_DMC_MAX_FW_SIZE`.
pub(crate) const XE2LPD_DMC_MAX_FW_SIZE: usize = 0x8000;
/// `DMC_FQ_W2_PTS_CFG_SEL` and the value `intel_dmc_load_program` writes on
/// display >= 20 (each pipe's DMC selects its own pipe).
pub(crate) const DMC_FQ_W2_PTS_CFG_SEL: u64 = 0x8f240;
pub(crate) const W2_PTS_CONFIG: u32 = (3 << 24) | (2 << 16) | (1 << 8);
/// `PIPEDMC_INTERRUPT(pipe)` / `PIPEDMC_INTERRUPT_MASK(pipe)` (lnl+).
pub(crate) const fn pipedmc_interrupt(pipe: u32) -> u64 {
    0x5f190 + 0x400 * pipe as u64
}
pub(crate) const fn pipedmc_interrupt_mask(pipe: u32) -> u64 {
    0x5f194 + 0x400 * pipe as u64
}
/// `pipedmc_interrupt_mask`: FLIPQ_PROG_DONE | GTT_FAULT | ATS_FAULT
/// (PIPEDMC_ERROR stays off, as the pinned tree leaves it).
pub(crate) const PIPEDMC_IRQS: u32 = (1 << 3) | (1 << 1) | 1;
/// `intel_flipq_reset` registers for `pipe`, in source write order:
/// `PIPEDMC_FQ_CTRL`, `SCANLINECMPLOWER`, `SCANLINECMPUPPER`, then
/// `FPQ_HP` and `FPQ_CHP` of each of the five flip queues, then
/// `FPQ_ATOMIC_TP`.
pub(crate) const fn flipq_reset_registers(pipe: u32) -> [u64; 14] {
    let p = 0x400 * pipe as u64;
    // _PICK_EVEN_2RANGES(fq_id, INTEL_FLIPQ_PLANE_3, FPQ1, FPQ2, FPQ3, FPQ4)
    [
        0x5f078 + p,
        0x5f120 + p,
        0x5f124 + p,
        0x5f128 + p,
        0x5f130 + p,
        0x5f138 + p,
        0x5f140 + p,
        0x5f168 + p,
        0x5f170 + p,
        0x5f174 + p,
        0x5f17c + p,
        0x5f180 + p,
        0x5f188 + p,
        0x5f0a0 + p,
    ]
}

fn flipq_reset(io: &(impl MmioWindow + ?Sized), pipe: u32) {
    for r in flipq_reset_registers(pipe) {
        io.write32(r, 0);
    }
}

/// The display >= 20 half of `intel_dmc_enable_pipe` that precedes
/// `PIPEDMC_ENABLE_MTL`: reset the flip queue, clear and unmask the pipe
/// DMC interrupts.
pub(crate) fn pipe_dmc_enable_prologue(io: &(impl MmioWindow + ?Sized), pipe: u32) {
    flipq_reset(io, pipe);
    io.write32(pipedmc_interrupt(pipe), PIPEDMC_IRQS);
    io.write32(pipedmc_interrupt_mask(pipe), !PIPEDMC_IRQS);
}

/// The display >= 20 half of `intel_dmc_disable_pipe` that follows the
/// `PIPEDMC_ENABLE_MTL` clear: mask and clear the pipe DMC interrupts,
/// then reset the flip queue.
pub(crate) fn pipe_dmc_disable_epilogue(io: &(impl MmioWindow + ?Sized), pipe: u32) {
    io.write32(pipedmc_interrupt_mask(pipe), !0);
    io.write32(pipedmc_interrupt(pipe), PIPEDMC_IRQS);
    flipq_reset(io, pipe);
}

// ── PICA power well (Type-C) ─────────────────────────────────────
//
// Modeled for the display-20 Type-C routes, which stay refused: external
// outputs on Lunar Lake are not admitted, so nothing requests this well.

/// `XE2LPD_PICA_PW_CTL` and its request/status bits.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) const PICA_PW_CTL: u64 = 0x16fe04;
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) const PICA_POWER_REQUEST: u32 = 1 << 31;
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) const PICA_POWER_STATUS: u32 = 1 << 30;

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

/// `xe2lpd_pica_power_well_enable`: request, then status within 1 ms.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn pica_enable(io: &(impl MmioWindow + ?Sized)) -> Result<(), IpError> {
    io.write32(PICA_PW_CTL, PICA_POWER_REQUEST);
    wait(io, PICA_PW_CTL, PICA_POWER_STATUS, PICA_POWER_STATUS, 1_000)
}

/// `xe2lpd_pica_power_well_disable`: clear, then status off within 1 ms.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn pica_disable(io: &(impl MmioWindow + ?Sized)) -> Result<(), IpError> {
    io.write32(PICA_PW_CTL, 0);
    wait(io, PICA_PW_CTL, PICA_POWER_STATUS, 0, 1_000)
}

// ── D2D link ─────────────────────────────────────────────────────

/// `mtl_ddi_enable_d2d` on `ip`: set the enable bit, wait 100 µs for the
/// state bit.
pub(crate) fn enable_d2d(
    io: &(impl MmioWindow + ?Sized),
    ip: DisplayIp,
    port: XeLpgPort,
) -> Result<(), IpError> {
    let (reg, enable, state) = ip.d2d(port);
    let v = io.read32(reg);
    if v == u32::MAX || !io.display_access_ok() {
        return Err(IpError::NoDevice);
    }
    io.write32(reg, v | enable);
    wait(io, reg, state, state, 100)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xe2lpd_tests.rs"]
pub(crate) mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xe2lpd_gt_tests.rs"]
mod gt_tests;
