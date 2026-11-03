//! Intel Xe-LPG modeset orchestrator — Meteor Lake (#1016).
//!
//! The Meteor Lake counterpart of [`crate::intel_gpu_modeset`]:
//! same orchestration shape (mode → power → disable → clocks →
//! pipe/transcoder → plane → link training → enables), but every
//! generation-specific step is the Xe-LPG sequence from the MTL
//! display PRM, dispatched on the GPU's generation at the
//! takeover entry — the Gen12 orchestrator's code path is not
//! modified and stays byte-identical for Gen12 silicon.
//!
//! ## What differs from Gen12, and why
//!
//! - **Power wells.** Xe-LPD splits the per-pipe wells out:
//!   pipe A lives in `PW_A` (PWR_WELL_CTL2 index 5), not PG2.
//!   `PW_1` (index 0) is still software-requested for transcoder
//!   A + DDI A/B. Each port's AUX channel is powered through its own
//!   `XELPDP_DP_AUX_CH_CTL` power request (bit 19) before any
//!   AUX/PHY traffic — `xelpdp_aux_power_well_enable`: no LT PHY on
//!   MTL, so a fixed 600 µs wait follows the request and the status
//!   bit is not a completion signal (i915 `intel_display_power_map.c`
//!   `xelpdp_power_wells_aux`; the ICL `PWR_WELL_CTL_AUX2` wells do
//!   not exist in the display-14 map). The AUX transport keeps the
//!   request set on every transaction word (`intel_dp_aux.c`
//!   `skl_get_aux_send_ctl`, DISPLAY_VER >= 14).
//! - **CDCLK.** MTL's table runs on a fixed 38.4 MHz reference
//!   with PLL ratios and *squash waveforms* for the two lowest
//!   rungs; programming is PLL ratio (0x46070) + squash
//!   (CDCLK_SQUASH_CTL) + CDCLK_CTL decimal, per i915
//!   `intel_cdclk.c` (`mtl_cdclk_table`, `bxt_set_cdclk`).
//! - **Port PLL.** There is no DPLL/DPCLKA. The C10/C20 PHY PLL
//!   is programmed over the port message bus and the port clock
//!   is routed with `XELPDP_PORT_CLOCK_CTL` — see
//!   [`crate::intel_gpu_xelpg`].
//! - **Transcoder clock select.** `TRANS_CLK_SEL` is programmed
//!   with the PHY index (Gen12's path never writes it).
//! - **Port enable.** MTL retains DDI_CTL_DE at the historical
//!   DDI_BUF_CTL address. This path requires it already enabled and
//!   preserves it; a complete off/on transaction remains unqualified.
//!   It programs the D2D link enable + `PORT_BUF_CTL1` width
//!   programming in the link-retrain sequence, and the source
//!   pattern generator is driven through `DP_TP_CTL`.
//! - **Signal levels.** No `DDI_BUF_TRANS` register file: TX
//!   levels are VDR override registers in the PHY, programmed
//!   before training (initial drive) and again with the levels
//!   training converged on. Per-iteration level updates inside
//!   the DPCD training loop would need a source-side callback in
//!   `dp_link_training` (shared with the Gen12 path, which
//!   preloads a table instead); that is the same simplification
//!   class, named here rather than hidden.
//!
//! ## eDP DSC
//!
//! Before anything is stopped, the panel's link and DSC capabilities are
//! read (`intel_edp_init_dpcd`) and `intel_dp_compute_link_config` decides
//! with NARF's 8 bpc pipe ([`crate::intel_gpu_xelpg_dsc::decide_edp`]): a
//! panel that is not DSC capable, or whose link carries 24 bpp, takes the
//! uncompressed sequence unchanged; a stream only Linux's 6 bpc would carry
//! and every unqualified DSC configuration refuse with
//! [`ModesetError::Dsc`]. A compressed modeset follows
//! `mtl_ddi_pre_enable_dp` and `hsw_crtc_enable`: the resource transaction
//! carries the VDSC CDCLK and prefill terms, the PHY PLL and training run at
//! the plan's maximum link (eDP), `DP_DSC_ENABLE` is set after
//! `DP_SET_POWER` D0 and before training, the PPS SDP follows the normal
//! pattern, then Pipe A's VDSC engines, the compressed M/N and the
//! display-14 `CHICKEN_TRANS` bits precede the transcoder enable. eDP
//! needs no FEC. A firmware-compressed panel is torn down in
//! `intel_ddi_disable_dp` / `intel_ddi_post_disable` order: sink
//! decompression off before the transcoder stops, then `DSS_CTL1/2`
//! and the PPS SDP enable cleared.
//!
//! ## Named remainders (not programmed by this lane)
//!
//! - **Watermarks / DBUF allocation.** Qualified display14.00 with
//!   every pipe off runs the computed resource transaction
//!   ([`crate::intel_gpu_xelpg_resources`]); other cases keep
//!   firmware's allocation and the raise-only CDCLK floor.
//! - **HDMI / DP 2.0 UHBR / MST / multi-pipe** — out of scope,
//!   matching the Gen12 orchestrator's DP-SST single-pipe shape.
//! - **DVFS/pcode notifications** around CDCLK changes — display
//!   14 has no PCODE CDCLK mailbox; the owned transaction programs
//!   PM demand instead, the inherited path still sends none.

use core::cell::Cell;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError, PixelFormat};
use crate::intel_gpu_pll::LinkRate;
use crate::intel_gpu_xelpg::{
    disable_port_pll, enable_d2d, enable_port_pll, program_port_buf_ctl, reprogram_pll_rate,
    set_signal_levels, Cx0Error, Cx0Phy, XeLpgPort,
};
use crate::intel_gpu_xelpg_dsc::{DscPlan, DscRefusal};

/// Sticky current-access guard for this one synchronous modeset. No await or
/// retained transaction is introduced. An inaccessible source register must
/// not let a later void codec helper continue programming the device.
struct CheckedWindow<'a, M: MmioWindow + ?Sized> {
    raw: &'a M,
    failed: Cell<bool>,
}
impl<M: MmioWindow + ?Sized> MmioWindow for CheckedWindow<'_, M> {
    fn gen12_display_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        self.raw.gen12_display_family()
    }
    fn gen12_hpd_profile(&self) -> Option<crate::intel_gpu_dp::HpdProfile> {
        self.raw.gen12_hpd_profile()
    }
    fn display_access_ok(&self) -> bool {
        if self.failed.get() || !self.raw.display_access_ok() {
            self.failed.set(true);
            false
        } else {
            true
        }
    }
    fn read32(&self, off: u64) -> u32 {
        if !self.display_access_ok() {
            return u32::MAX;
        }
        let value = self.raw.read32(off);
        // PM-demand IMR permits an actually all-masked value. Current
        // authority, rather than its value, qualifies this exception.
        if !self.display_access_ok() || (value == u32::MAX && off != 0x44464) {
            self.failed.set(true);
            return u32::MAX;
        }
        value
    }
    fn write32(&self, off: u64, value: u32) {
        if self.display_access_ok() {
            self.raw.write32(off, value);
            let _ = self.display_access_ok();
        }
    }
}

// ── Power wells (Xe-LPD) ─────────────────────────────────────────
//
// HSW_PWR_WELL_CTL2 = 0x45404 (main wells, `intel_display_regs.h`),
// HSW request/state encoding (REQ = 0x2 << idx*2, STATE = 0x1 <<
// idx*2). AUX power is the per-channel XELPDP_DP_AUX_CH_CTL request
// (`intel_gpu_xelpg_tc::aux_power_enable`), not a PWR_WELL_CTL_AUX2 bit.

const PWR_WELL_CTL2: u64 = 0x4_5404;
/// `ICL_PW_CTL_IDX_PW_1` — transcoder A + DDI A/B on Xe-LPD.
const PW_1_IDX: u32 = 0;
/// `XELPD_PW_CTL_IDX_PW_A` — pipe A + panel fitter A.
const PW_A_IDX: u32 = 5;

const fn pwr_well_req(idx: u32) -> u32 {
    0x2 << (idx * 2)
}
const fn pwr_well_state(idx: u32) -> u32 {
    0x1 << (idx * 2)
}

// ── CDCLK (MTL) ──────────────────────────────────────────────────

const CDCLK_CTL: u64 = 0x4_6000;
const CDCLK_SQUASH_CTL: u64 = 0x4_6008;
/// `BXT_DE_PLL_ENABLE` — the CDCLK PLL control register (the
/// name is historical; the register is the CDCLK PLL's on every
/// BXT+ platform including MTL).
const CDCLK_PLL_ENABLE_REG: u64 = 0x4_6070;
const CDCLK_PLL_ENABLE: u32 = 1 << 31;
const CDCLK_PLL_LOCK: u32 = 1 << 30;
const CDCLK_PLL_RATIO_MASK: u32 = 0xFF;
const CDCLK_FREQ_DECIMAL_MASK: u32 = 0x7FF;
const CDCLK_SQUASH_ENABLE: u32 = 1 << 31;
const CDCLK_SQUASH_WINDOW_SIZE_15: u32 = 0xF << 24;
/// MTL reference clock: 38.4 MHz (the only refclk the MTL table
/// is published against).
const MTL_REFCLK_KHZ: u32 = 38_400;

/// One rung of `mtl_cdclk_table`: the PLL ratio (VCO = ratio ×
/// 38.4 MHz, CDCLK = VCO/2 before squash) and the squash
/// waveform (0 = no squash; otherwise CDCLK = VCO/2 ×
/// popcount(waveform)/16).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtlCdclkEntry {
    /// Resulting CDCLK in kHz.
    pub cdclk_khz: u32,
    /// CDCLK PLL ratio.
    pub ratio: u32,
    /// Squash waveform (16 bits).
    pub waveform: u16,
}

const MTL_CDCLK_TABLE: &[MtlCdclkEntry] = &[
    MtlCdclkEntry {
        cdclk_khz: 172_800,
        ratio: 16,
        waveform: 0xAD5A,
    },
    MtlCdclkEntry {
        cdclk_khz: 192_000,
        ratio: 16,
        waveform: 0xB6B6,
    },
    MtlCdclkEntry {
        cdclk_khz: 307_200,
        ratio: 16,
        waveform: 0x0000,
    },
    MtlCdclkEntry {
        cdclk_khz: 480_000,
        ratio: 25,
        waveform: 0x0000,
    },
    MtlCdclkEntry {
        cdclk_khz: 556_800,
        ratio: 29,
        waveform: 0x0000,
    },
    MtlCdclkEntry {
        cdclk_khz: 652_800,
        ratio: 34,
        waveform: 0x0000,
    },
];

/// Smallest MTL CDCLK table entry satisfying the floor rule
/// `pixel_clock <= 2 * CDCLK` (the rule the Gen12 orchestrator
/// documents from the PRM; MTL's full min-CDCLK rules also weigh
/// plane bandwidth, which a single-plane boot modeset is safely
/// inside). `None` past the table.
pub fn mtl_cdclk_for_pixel_clock(pixel_clock_khz: u32) -> Option<MtlCdclkEntry> {
    let floor_khz = pixel_clock_khz.div_ceil(2);
    MTL_CDCLK_TABLE
        .iter()
        .find(|e| e.cdclk_khz >= floor_khz)
        .copied()
}

/// Decode the currently programmed CDCLK (kHz) from the PLL
/// ratio + CDCLK_CTL divider + squash waveform — the readout
/// path i915's `bxt_get_cdclk` implements. 0 when the CDCLK PLL
/// is off or unlocked.
pub(crate) fn cdclk_current_khz<M: MmioWindow + ?Sized>(mmio: &M) -> u32 {
    let pll = mmio.read32(CDCLK_PLL_ENABLE_REG);
    if pll == u32::MAX
        || pll & (CDCLK_PLL_ENABLE | CDCLK_PLL_LOCK) != CDCLK_PLL_ENABLE | CDCLK_PLL_LOCK
    {
        return 0;
    }
    let vco = (pll & CDCLK_PLL_RATIO_MASK) * MTL_REFCLK_KHZ;
    let ctl = mmio.read32(CDCLK_CTL);
    // CD2X divider select (bits 23:22): cdclk = vco / {2,3,4,8}.
    let div2x = match (ctl >> 22) & 0x3 {
        0 => 2,
        1 => 3,
        2 => 4,
        _ => 8,
    };
    let squash = mmio.read32(CDCLK_SQUASH_CTL);
    let (numerator, divisor) = if squash & CDCLK_SQUASH_ENABLE != 0 {
        // bxt_get_cdclk: only the active high bits belong to the
        // programmed window. Firmware need not use our table's size16.
        let size = ((squash >> 24) & 15) + 1;
        let waveform = (squash as u16) >> (16 - size);
        (vco * waveform.count_ones(), size * div2x)
    } else {
        (vco, div2x)
    };
    // Source DIV_ROUND_CLOSEST on the full product, not a truncated
    // intermediate vco/divider. Maximum255*38400*16 fits in u32.
    (numerator + divisor / 2) / divisor
}

// Unlike a zero/off readout, an enabled but unlocked clock cannot authorize
// the fast path or subsequent resource/port programming. Source
// bxt_de_pll_readout requires both ENABLE and LOCK before trusting the ratio.
pub(crate) fn acknowledged_cdclk<M: MmioWindow + ?Sized>(mmio: &M) -> Result<u32, ModesetError> {
    let current = cdclk_current_khz(mmio);
    let pll = mmio.read32(CDCLK_PLL_ENABLE_REG);
    let enabled = pll & CDCLK_PLL_ENABLE != 0;
    if pll == u32::MAX
        || !mmio.display_access_ok()
        || (enabled && pll & CDCLK_PLL_LOCK == 0)
        || enabled != (current != 0)
    {
        return Err(ModesetError::PllLockTimeout);
    }
    Ok(current)
}

/// Raise CDCLK to the floor `mode` needs, MTL-style. Only ever
/// raises; a faster acknowledged firmware CDCLK is left alone.
/// Refuse if no table rung can meet the required floor; a table miss
/// cannot authorize later programming below that floor.
pub(crate) fn program_cdclk_floor<M: MmioWindow + ?Sized>(
    mmio: &M,
    mode: &Mode,
) -> Result<(), ModesetError> {
    program_cdclk_floor_khz(mmio, mode.pixel_clock_khz.div_ceil(2))
}

/// [`program_cdclk_floor`] for an explicit floor (a compressed panel adds
/// `intel_vdsc_min_cdclk` to the pixel-clock rule).
pub(crate) fn program_cdclk_floor_khz<M: MmioWindow + ?Sized>(
    mmio: &M,
    floor_khz: u32,
) -> Result<(), ModesetError> {
    let current = acknowledged_cdclk(mmio)?;
    if floor_khz <= current {
        return Ok(());
    }
    let entry = match MTL_CDCLK_TABLE.iter().find(|e| e.cdclk_khz >= floor_khz) {
        Some(e) => *e,
        None => return Err(ModesetError::PllLockTimeout),
    };
    let pll = mmio.read32(CDCLK_PLL_ENABLE_REG);
    let pll_on = pll & CDCLK_PLL_ENABLE != 0;
    let cur_ratio = pll & CDCLK_PLL_RATIO_MASK;
    // wa_15010685871 (dg2/mtl): when enabling the PLL from off,
    // clear the squash programming first.
    if !pll_on {
        mmio.write32(CDCLK_SQUASH_CTL, 0);
        compiler_fence(Ordering::SeqCst);
    }
    // `icl_cdclk_pll_update`: disable on a ratio change, then
    // enable at the new ratio and wait for lock (200 µs in i915;
    // 1 ms budget here matches the other PLL polls in-tree).
    if pll_on && cur_ratio != entry.ratio {
        mmio.write32(CDCLK_PLL_ENABLE_REG, 0);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(
            mmio,
            CDCLK_PLL_ENABLE_REG,
            CDCLK_PLL_ENABLE | CDCLK_PLL_LOCK,
            false,
            1_000_000,
        ) {
            return Err(ModesetError::PllLockTimeout);
        }
    }
    if !pll_on || cur_ratio != entry.ratio {
        mmio.write32(CDCLK_PLL_ENABLE_REG, entry.ratio);
        mmio.write32(CDCLK_PLL_ENABLE_REG, entry.ratio | CDCLK_PLL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(mmio, CDCLK_PLL_ENABLE_REG, CDCLK_PLL_LOCK, true, 1_000_000) {
            return Err(ModesetError::PllLockTimeout);
        }
    }
    let programmed = mmio.read32(CDCLK_PLL_ENABLE_REG);
    if programmed == u32::MAX
        || !mmio.display_access_ok()
        || programmed & (CDCLK_PLL_ENABLE | CDCLK_PLL_LOCK | CDCLK_PLL_RATIO_MASK)
            != CDCLK_PLL_ENABLE | CDCLK_PLL_LOCK | entry.ratio
    {
        return Err(ModesetError::PllLockTimeout);
    }
    // Squash waveform for the target rung (0 disables squash).
    let squash = if entry.waveform != 0 {
        CDCLK_SQUASH_ENABLE | CDCLK_SQUASH_WINDOW_SIZE_15 | (entry.waveform as u32)
    } else {
        0
    };
    mmio.write32(CDCLK_SQUASH_CTL, squash);
    // CDCLK_CTL: CD2X divider 1 (field 0) and the decimal
    // frequency, (kHz - 1000) / 500 rounded — the encoding the
    // pre-LNL decimal field carries (under squash the field is
    // nominal; the waveform sets the exact rate).
    let decimal = (entry.cdclk_khz - 1000 + 250) / 500;
    mmio.write32(CDCLK_CTL, decimal & CDCLK_FREQ_DECIMAL_MASK);
    compiler_fence(Ordering::SeqCst);
    if mmio.read32(CDCLK_SQUASH_CTL) != squash
        || mmio.read32(CDCLK_CTL) != decimal & CDCLK_FREQ_DECIMAL_MASK
        || !mmio.display_access_ok()
    {
        return Err(ModesetError::PllLockTimeout);
    }
    Ok(())
}

// ── Transcoder clock select + DP transport control ───────────────

/// `TRANS_CLK_SEL_A` — routes the port clock to transcoder A.
const TRANS_CLK_SEL_A: u64 = 0x4_6140;
/// `TGL_TRANS_CLK_SEL_PORT(phy)` = (phy + 1) << 28 (the
/// DISPLAY_VER >= 13 encoding MTL uses).
const fn trans_clk_sel_port(phy_index: u32) -> u32 {
    (phy_index + 1) << 28
}

/// `DP_TP_CTL` offset from the transcoder base (0x60540 abs).
const DP_TP_CTL_OFFSET: u64 = 0x540;
const DP_TP_CTL_ENABLE: u32 = 1 << 31;
const DP_TP_CTL_ENHANCED_FRAME: u32 = 1 << 18;
const DP_TP_CTL_LINK_TRAIN_MASK: u32 = 0x7 << 8;
const DP_TP_CTL_LINK_TRAIN_PAT1: u32 = 0 << 8;
const DP_TP_CTL_LINK_TRAIN_NORMAL: u32 = 3 << 8;

/// `CHICKEN_TRANS` (`_MTL_CHICKEN_TRANS_A` 0x604e0) and the display-14
/// bits `intel_enable_transcoder` sets and clears.
const CHICKEN_TRANS_OFFSET: u64 = 0x4e0;
const DP_FEC_BS_JITTER_WA: u32 = 1 << 15;
const DP_DSC_INSERT_SF_AT_EOL_WA: u32 = 1 << 4;

// Keep the narrow lane on the existing A/B source mapping. TC's inherited
// TRANS_DDI selector uses a separate, unqualified enumeration; fixing that
// full route is outside this immediate correction. Never derive DDI offsets
// from that selector (Linux PORT_TC1/2 are3/4, not9/10).
fn inherited_ddi_ctl(port: XeLpgPort) -> Option<u64> {
    match port {
        XeLpgPort::A => Some(0x64000),
        XeLpgPort::B => Some(0x64100),
        XeLpgPort::Tc1 | XeLpgPort::Tc2 | XeLpgPort::Tc3 | XeLpgPort::Tc4 => None,
    }
}

// ── Orchestrator ─────────────────────────────────────────────────

/// The mode the owned Pipe-A modeset last established with its owned
/// display-14 resource profile, cleared when Pipe A goes dark. The Pipe
/// B–D owner adopts a lit Pipe A only as this profile.
static OWNED_PANEL: narf_lib::sync::IrqSafeSpinLock<Option<Mode>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The owned panel mode on Pipe A: set by a successful owned modeset (one
/// whose display-14 resource transaction ran), cleared when the modeset
/// turns Pipe A off. `None` while Pipe A runs an inherited layout.
pub fn owned_panel_mode() -> Option<Mode> {
    *OWNED_PANEL.lock()
}

/// Xe-LPG modeset orchestrator for one port + pipe A. Stateless,
/// like its Gen12 counterpart.
pub struct XeLpgModeset<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    /// The physical port for this modeset.
    pub port: XeLpgPort,
    /// Where Pipe A's DMC lifetime is reported (`intel_dmc_enable_pipe` /
    /// `intel_dmc_disable_pipe` around this modeset's crtc enable/disable).
    pipe_dmc: &'a dyn crate::intel_gpu_dc_states::PipeDmc,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for XeLpgModeset<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XeLpgModeset")
            .field("port", &self.port)
            .finish()
    }
}

/// Per-lane DP signal levels: one (swing, pre-emphasis) pair
/// per main-link lane, as `dp_link_training` reports them and
/// `intel_gpu_xelpg::set_signal_levels` consumes them.
pub type LaneLevels = [(u8, u8); 4];

/// Map a PHY-layer failure onto the modeset error vocabulary:
/// bus-level failures (PHY error bit, wrong-generation ACK) are
/// `PhyBusFailure`; timeouts and missing tables mean the PLL
/// never locked.
fn map_cx0_err(e: Cx0Error) -> ModesetError {
    match e {
        Cx0Error::PhyError | Cx0Error::ProtocolMismatch => ModesetError::PhyBusFailure,
        Cx0Error::Timeout | Cx0Error::UnsupportedRate => ModesetError::PllLockTimeout,
    }
}

impl<'a, M: MmioWindow + ?Sized> XeLpgModeset<'a, M> {
    /// Create an orchestrator for a port + MMIO window pair, reporting
    /// Pipe A's DMC lifetime to the display-14 DC service.
    pub fn new(mmio: &'a M, port: XeLpgPort) -> Self {
        Self {
            mmio,
            port,
            pipe_dmc: &crate::intel_gpu_dc_states::ServicePipeDmc,
        }
    }

    /// Report Pipe A's DMC lifetime to `pipe_dmc` instead.
    pub fn with_pipe_dmc(mut self, pipe_dmc: &'a dyn crate::intel_gpu_dc_states::PipeDmc) -> Self {
        self.pipe_dmc = pipe_dmc;
        self
    }

    /// Run the MTL modeset. Step order mirrors the Gen12
    /// orchestrator's shape with the Xe-LPG sequences substituted
    /// (see the module header for the delta list).
    pub fn modeset(
        &mut self,
        primary_fb: &Framebuffer,
        fallback_mode: Option<&Mode>,
    ) -> Result<Mode, ModesetError> {
        // Step 0: validate inputs that don't require touching HW.
        validate_framebuffer(primary_fb)?;
        inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?;
        // DC_off for the EDID AUX read and everything after (AUX_A and the
        // CX0 message bus are DC_off domains); inert without a DC service.
        let _power =
            crate::intel_gpu_dc_states::acquire(crate::intel_gpu_dc_states::DcUser::Modeset)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
        // The EDID read below is AUX traffic: raise this port's Xe-LPDP AUX
        // power request first (intel_dp_aux_xfer holds the AUX power domain
        // across every transfer). modeset_checked re-asserts it for the
        // fixed-mode entry, which reaches the AUX channel only from there.
        crate::intel_gpu_xelpg_tc::aux_power_enable(self.mmio, self.port)
            .map_err(|_| ModesetError::PowerWellTimeout)?;

        // Step 1: pick the mode (EDID over this port's AUX, or
        // the caller's fallback).
        let mode = match self.read_preferred_mode_via_edid() {
            Ok(m) => m,
            Err(_) => match fallback_mode {
                Some(m) => *m,
                None => return Err(ModesetError::EdidUnavailable),
            },
        };

        self.modeset_fixed(primary_fb, &mode)
    }

    /// Restore exactly the caller's timing without an EDID mode substitution.
    pub fn modeset_fixed(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
    ) -> Result<Mode, ModesetError> {
        crate::intel_gpu_modeset::validate_framebuffer_mode(primary_fb, mode)?;
        inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?;
        // Nested under `modeset`'s reference when reached from there.
        let _power =
            crate::intel_gpu_dc_states::acquire(crate::intel_gpu_dc_states::DcUser::Modeset)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
        let checked = CheckedWindow {
            raw: self.mmio,
            failed: Cell::new(false),
        };
        let result = XeLpgModeset::new(&checked, self.port)
            .with_pipe_dmc(self.pipe_dmc)
            .modeset_checked(primary_fb, mode);
        if !checked.display_access_ok() {
            return Err(result
                .err()
                .unwrap_or(ModesetError::PipelineEnableUnavailable));
        }
        result
    }

    // Keep the existing synchronous entry and legacy lifetime: hardware-only
    // polls may run inside resume's executor poll, without a block_on bridge
    // or a new cancellation boundary. The GT mutex latency remains bounded
    // legacy behavior, not a retained async display-owner implementation.
    fn modeset_checked(
        &mut self,
        primary_fb: &Framebuffer,
        mode: &Mode,
    ) -> Result<Mode, ModesetError> {
        let mode = *mode;

        // Step 2: power wells — PW_1 (transcoder A / DDI A-B),
        // PW_A (pipe A), and this port's Xe-LPDP AUX power request
        // (`xelpdp_aux_power_well_enable`: XELPDP_DP_AUX_CH_CTL bit 19,
        // then a fixed 600 µs). Type-C routes never reach this inherited
        // path, so no TC port reference is required here.
        self.enable_power_well(PWR_WELL_CTL2, PW_1_IDX)?;
        self.enable_power_well(PWR_WELL_CTL2, PW_A_IDX)?;
        crate::intel_gpu_xelpg_tc::aux_power_enable(self.mmio, self.port)
            .map_err(|_| ModesetError::PowerWellTimeout)?;

        // intel_edp_init_dpcd + intel_dp_compute_link_config: decide DSC
        // before the first destructive write, so a refusal leaves the panel
        // as it was.
        let dsc = self.plan_edp_dsc(&mode)?;

        // This bounded correction preserves an already-enabled DDI. The
        // existing PHY helper does not implement a complete DDI-off/on pair;
        // do not destructively stop an off/unqualified inherited port.
        self.require_enabled_ddi()?;
        // Step 3: plane → the single pipe/transcoder CONF → PLL request.
        // This is not a full DDI/PHY/link retirement receipt. Pipe A is
        // dark from here: the owned profile no longer describes it, and
        // its pipe DMC is disabled last, as hsw_crtc_disable ends with
        // intel_dmc_disable_pipe after the port PLL.
        *OWNED_PANEL.lock() = None;
        self.disable_pipeline()?;
        self.pipe_dmc.disable_pipe(0);
        // This is a full owned modeset with the pipe off, not a KMS
        // inheritance path. Establish RGB bypass rather than depend on GOP
        // leaving its per-plane gamma/CSC controls in an admissible state.
        crate::intel_gpu_color::initialize_rgb_bypass(self.mmio)
            .map_err(|_| ModesetError::ColorPipelineUnavailable)?;

        // A qualified display14.00 resource transaction owns PM demand,
        // the computed CDCLK (raised or lowered), DBUF/MBUS, watermarks and
        // the cursor DDB reservation before any plane enable. Unsupported
        // preflight retains the historical inherited layout; a failed
        // transaction restores what it touched and keeps this pipe off.
        acknowledged_cdclk(self.mmio)?;
        let dsc_term = dsc.map(|plan| plan.term(&mode));
        let owned =
            crate::intel_gpu_display_resources::initialize_dsc(self.mmio, &mode, 0, dsc_term)
                .map_err(|e| match e {
                    crate::intel_gpu_xelpg_resources::ResourceError::Clock(_) => {
                        ModesetError::PllLockTimeout
                    }
                    _ => ModesetError::DisplayResourceUnavailable,
                })?;
        // Step 4: the inherited layout keeps the raise-only CDCLK floor,
        // with intel_vdsc_min_cdclk when the panel compresses.
        if owned.is_none() {
            let floor = mode
                .pixel_clock_khz
                .div_ceil(2)
                .max(dsc_term.map_or(0, |t| t.min_cdclk_khz));
            program_cdclk_floor_khz(self.mmio, floor)?;
        }
        // hsw_crtc_enable's first step, after the pre-plane update:
        // intel_dmc_enable_pipe. A later failure leaves it enabled until
        // the next disable, as Linux keeps it for the crtc's lifetime.
        self.pipe_dmc.enable_pipe(0);

        // Step 5: enable the port PLL at the rate this pixel
        // clock needs (the same bandwidth rule the Gen12 path
        // picks its DPLL rate with).
        // A compressed eDP stream runs at the plan's (maximum) link.
        let (mut pll_rate, lanes) = match &dsc {
            Some(plan) => (dsc_link_rate(plan)?, plan.lanes),
            None => (link_rate_for_pixel_clock(mode.pixel_clock_khz), 4),
        };
        enable_port_pll(self.mmio, self.port, pll_rate, lanes).map_err(map_cx0_err)?;

        // Step 6: route the port clock to transcoder A.
        self.mmio
            .write32(TRANS_CLK_SEL_A, trans_clk_sel_port(self.port.phy_index()));
        compiler_fence(Ordering::SeqCst);

        // Step 7: transcoder timing + pipe source size (register
        // block shared with Gen12 — the shared codecs build them).
        self.program_transcoder(&mode);
        self.program_pipe(&mode);

        // Step 8: bind transcoder A to this port (DP-SST, 8 bpc).
        self.program_trans_ddi_func_ctl(lanes);

        // Step 9: program the primary plane.
        self.program_plane(primary_fb, &mode);

        // Step 10: link-retrain preamble — D2D link up, port
        // buffer width, initial (zero) signal levels.
        enable_d2d(self.mmio, self.port).map_err(map_cx0_err)?;
        program_port_buf_ctl(self.mmio, self.port, lanes);
        let phy = Cx0Phy::new(self.mmio, self.port);
        set_signal_levels(&phy, pll_rate, lanes, &[(0, 0); 4]).map_err(map_cx0_err)?;

        // mtl_ddi_pre_enable_dp: intel_dp_set_power(D0), then
        // intel_dp_sink_enable_decompression, before training.
        if dsc.is_some() {
            self.sink_enable_decompression()?;
        }

        // Step 11: source pattern generator into TPS1 and run
        // DPCD link training over this port's AUX.
        self.program_dp_tp_ctl(DP_TP_CTL_LINK_TRAIN_PAT1);
        let trained = match &dsc {
            Some(plan) => {
                // The configuration was computed for the plan's link; a
                // fallback below it needs a new one (Linux's modeset retry).
                let trained = self.train_dp_link_at(train_rate(plan)?, plan.lanes)?;
                if trained.0 != pll_rate || trained.1 != plan.lanes {
                    return Err(ModesetError::Dsc(DscRefusal::TrainingFallback));
                }
                trained
            }
            None => self.train_dp_link()?,
        };
        let trained_rate = trained.0;
        let trained_lanes = trained.1;
        let trained_levels = trained.2;

        // Step 12: settle — if training converged below the PLL
        // rate (or on fewer lanes), re-target the PLL and the
        // width programming, then apply the trained levels.
        if trained_rate != pll_rate {
            reprogram_pll_rate(self.mmio, self.port, trained_rate).map_err(map_cx0_err)?;
            pll_rate = trained_rate;
        }
        if trained_lanes != lanes {
            program_port_buf_ctl(self.mmio, self.port, trained_lanes);
            self.program_trans_ddi_func_ctl(trained_lanes);
        }
        set_signal_levels(&phy, pll_rate, trained_lanes, &trained_levels).map_err(map_cx0_err)?;
        if dsc.is_none() {
            self.program_mn(&mode, pll_rate, trained_lanes);
        }

        // Step 13: pattern generator to normal data, then the
        // final enables in PRM order (transcoder → pipe → plane).
        self.program_dp_tp_ctl(DP_TP_CTL_LINK_TRAIN_NORMAL);
        if let Some(plan) = &dsc {
            self.enable_dsc(plan, &mode)?;
        }
        let frame = self.mmio.read32(0x70040);
        if frame == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        self.enable_transcoder()?;
        self.observe_plane(primary_fb, &mode, trained_lanes, frame)?;
        if owned.is_some() {
            *OWNED_PANEL.lock() = Some(mode);
        }

        Ok(mode)
    }

    /// Read the panel's caps and run Linux's DSC decision for `mode`.
    /// A panel whose caps cannot be read takes the uncompressed path, as
    /// before this decision existed.
    fn plan_edp_dsc(&mut self, mode: &Mode) -> Result<Option<DscPlan>, ModesetError> {
        use crate::intel_gpu_xelpg_dsc::{decide_edp, installed_edp_vbt, EdpCaps, EdpDecision};
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        let Ok(caps) = EdpCaps::read(&mut aux) else {
            return Ok(None);
        };
        match decide_edp(&caps, &installed_edp_vbt(), mode) {
            Ok(EdpDecision::Dsc(plan)) => Ok(Some(plan)),
            Ok(EdpDecision::NotCapable | EdpDecision::Uncompressed) => Ok(None),
            Err(refusal) => Err(ModesetError::Dsc(refusal)),
        }
    }

    /// `intel_dp_set_power(D0)` then `intel_dp_sink_enable_decompression`.
    fn sink_enable_decompression(&mut self) -> Result<(), ModesetError> {
        use crate::dp_aux::AuxChannel as _;
        use crate::intel_gpu_xelpg_dsc::{set_sink_decompression, DP_SET_POWER, DP_SET_POWER_D0};
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        aux.dpcd_write(DP_SET_POWER, &[DP_SET_POWER_D0])
            .map_err(ModesetError::AuxFailure)?;
        set_sink_decompression(&mut aux, true).map_err(ModesetError::AuxFailure)
    }

    /// The tail of `mtl_ddi_pre_enable_dp` (`intel_dsc_dp_pps_write`) and
    /// `hsw_crtc_enable`'s `intel_dsc_enable`, then the compressed M/N
    /// (`intel_cpu_transcoder_set_m1_n1`) and `intel_enable_transcoder`'s
    /// display-14 `CHICKEN_TRANS` bits, with the transcoder still off.
    fn enable_dsc(&mut self, plan: &DscPlan, mode: &Mode) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{Pipe as PipeIdx, Transcoder};
        use crate::intel_gpu_xelpg_dsc::{enable_engines, write_m_n, write_pps_sdp};
        let lost = |_| ModesetError::PipelineEnableUnavailable;
        write_pps_sdp(self.mmio, Transcoder::A, plan).map_err(lost)?;
        enable_engines(self.mmio, PipeIdx::A, plan).map_err(lost)?;
        write_m_n(self.mmio, Transcoder::A, &plan.m_n(mode)).map_err(lost)?;
        let chicken = Transcoder::A.base() + CHICKEN_TRANS_OFFSET;
        let v = self.mmio.read32(chicken);
        if v == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        self.mmio.write32(
            chicken,
            (v & !DP_DSC_INSERT_SF_AT_EOL_WA) | DP_FEC_BS_JITTER_WA,
        );
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// EDID readback over this port's AUX channel — identical
    /// transport and parsing to the Gen12 path; only the AUX
    /// register base differs (it is a per-port Xe-LPG address).
    fn read_preferred_mode_via_edid(&mut self) -> Result<Mode, ModesetError> {
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        let mut edid_buf = [0u8; 128];
        let edid = crate::dp_edid::read_panel_edid(&mut aux, &mut edid_buf)
            .map_err(|_| ModesetError::EdidUnavailable)?;
        let d = edid
            .preferred_timing()
            .map_err(|_| ModesetError::EdidUnavailable)?;
        Ok(Mode {
            pixel_clock_khz: d.pixel_clock_khz,
            h_active: d.h_active,
            h_total: d.h_active + d.h_blanking,
            h_sync_start: d.h_active + d.h_sync_offset,
            h_sync_end: d.h_active + d.h_sync_offset + d.h_sync_width,
            v_active: d.v_active,
            v_total: d.v_active + d.v_blanking,
            v_sync_start: d.v_active + d.v_sync_offset,
            v_sync_end: d.v_active + d.v_sync_offset + d.v_sync_width,
            h_sync_positive: d.h_sync_positive,
            v_sync_positive: d.v_sync_positive,
        })
    }

    // ── Power wells ──────────────────────────────────────────

    /// Drive one power-well enable in `reg` (HSW encoding, 1 ms
    /// grant budget — the same discipline as the Gen12 path).
    fn enable_power_well(&mut self, reg: u64, idx: u32) -> Result<(), ModesetError> {
        let cur = self.mmio.read32(reg);
        self.mmio.write32(reg, cur | pwr_well_req(idx));
        compiler_fence(Ordering::SeqCst);
        if wait_bit(
            self.mmio,
            reg,
            pwr_well_req(idx) | pwr_well_state(idx),
            true,
            1_000_000,
        ) {
            Ok(())
        } else {
            Err(ModesetError::PowerWellTimeout)
        }
    }

    // ── Pipeline disable ─────────────────────────────────────

    /// Source intel_ddi.c::intel_ddi_wait_for_buf_active selects MTL's
    /// PORT_BUF_CTL1.PHY_IDLE, not the historical DDI_BUF_CTL idle bit.
    /// PW1/PWA/AUX have actual owned REQUEST+STATE acknowledgements above.
    fn require_enabled_ddi(&self) -> Result<(), ModesetError> {
        let ddi = self
            .mmio
            .read32(inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?);
        let buf = self.mmio.read32(self.port.buf_ctl1());
        if ddi == u32::MAX
            || buf == u32::MAX
            || !self.mmio.display_access_ok()
            || ddi & (1 << 31) == 0
            || buf & (1 << 7) != 0
            || buf & (1 << 24) == 0
        {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        Ok(())
    }

    /// Observe the existing local stop before any color/resource/clock/PHY
    /// programming. Pipe A and transcoder A alias the same 0x70008 CONF.
    /// Do not clear DDI_CTL_DE here: full PHY/link stop and matching source
    /// re-enable, producer exclusion and DMA retirement remain follow-on work.
    fn disable_pipeline(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE, PLANE_CTL_ENABLE,
            PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET,
        };
        let plane_base = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        let ctl = self.mmio.read32(plane_base + PLANE_CTL_OFFSET);
        self.mmio
            .write32(plane_base + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE);
        let surf = self.mmio.read32(plane_base + PLANE_SURF_OFFSET);
        self.mmio.write32(plane_base + PLANE_SURF_OFFSET, surf);
        compiler_fence(Ordering::SeqCst);
        if !self.mmio.display_access_ok()
            || self.mmio.read32(plane_base + PLANE_CTL_OFFSET) & PLANE_CTL_ENABLE != 0
            || self.mmio.read32(plane_base + PLANE_SURF_OFFSET) != surf
        {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        // intel_ddi_disable_dp: a compressing panel's sink decompression
        // goes off before the transcoder (best effort, as in Linux).
        let compressed = crate::intel_gpu_xelpg_dsc::engines_enabled(self.mmio, PipeIdx::A)
            .map_err(|_| ModesetError::PipelineStopUnavailable)?;
        if compressed {
            let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
            let _ = crate::intel_gpu_xelpg_dsc::set_sink_decompression(&mut aux, false);
        }
        let off = PipeIdx::A.base() + PIPECONF_OFFSET;
        let conf = self.mmio.read32(off);
        self.mmio.write32(off, conf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(
            self.mmio,
            off,
            PIPECONF_ENABLE | PIPECONF_STATE,
            false,
            100_000_000,
        ) {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        // intel_ddi_post_disable: intel_dsc_disable, then
        // intel_dp_set_infoframes(false) clears the PPS SDP enable.
        crate::intel_gpu_xelpg_dsc::disable_engines(self.mmio, PipeIdx::A)
            .map_err(|_| ModesetError::PipelineStopUnavailable)?;
        crate::intel_gpu_xelpg_dsc::disable_pps_sdp(
            self.mmio,
            crate::intel_gpu_pipes::Transcoder::A,
        )
        .map_err(|_| ModesetError::PipelineStopUnavailable)?;
        disable_port_pll(self.mmio, self.port).map_err(map_cx0_err)?;
        // The old helper polls ACK0 only. A refused write must not leave a
        // lane1 request/ACK unnoticed. Keep its existing conservative 3.2ms
        // bound; this still is not the source complete 20us PHY-off sequence.
        if !wait_bit(
            self.mmio,
            self.port.port_clock_ctl(),
            0xcc00_0000,
            false,
            3_200_000,
        ) {
            return Err(ModesetError::PllLockTimeout);
        }
        Ok(())
    }

    // ── Shared pipe/transcoder/plane programming ─────────────
    //
    // The pipe, transcoder, and plane register blocks did not
    // move on Xe-LPG; these steps reuse the shared codecs exactly
    // as the Gen12 orchestrator does.

    pub(crate) fn program_transcoder(&mut self, mode: &Mode) {
        use crate::intel_gpu_pipes::{
            build_transcoder, Transcoder, TRANS_HBLANK_OFFSET, TRANS_HSYNC_OFFSET,
            TRANS_HTOTAL_OFFSET, TRANS_VBLANK_OFFSET, TRANS_VSYNC_OFFSET, TRANS_VTOTAL_OFFSET,
        };
        let timing = mode_to_display_timing(mode);
        let prog = match build_transcoder(&timing) {
            Ok(p) => p,
            Err(_) => return,
        };
        let base = Transcoder::A.base();
        self.mmio.write32(base + TRANS_HTOTAL_OFFSET, prog.htotal);
        self.mmio.write32(base + TRANS_HBLANK_OFFSET, prog.hblank);
        self.mmio.write32(base + TRANS_HSYNC_OFFSET, prog.hsync);
        self.mmio.write32(base + TRANS_VTOTAL_OFFSET, prog.vtotal);
        // Display 13+ clears VBLANK_START (intel_set_transcoder_timings).
        self.mmio
            .write32(base + TRANS_VBLANK_OFFSET, prog.vblank_display13());
        self.mmio.write32(base + TRANS_VSYNC_OFFSET, prog.vsync);
        compiler_fence(Ordering::SeqCst);
    }

    pub(crate) fn program_pipe(&mut self, mode: &Mode) {
        use crate::intel_gpu_pipes::{build_pipe, Pipe as PipeIdx, PIPE_SRCSZ_OFFSET};
        let timing = mode_to_display_timing(mode);
        let prog = match build_pipe(&timing) {
            Ok(p) => p,
            Err(_) => return,
        };
        self.mmio
            .write32(PipeIdx::A.trans_base() + PIPE_SRCSZ_OFFSET, prog.srcsz);
        compiler_fence(Ordering::SeqCst);
    }

    fn program_trans_ddi_func_ctl(&mut self, lanes: u8) {
        use crate::intel_gpu_pipes::{
            build_trans_ddi_func_ctl, Transcoder, TRANS_DDI_FUNC_CTL_OFFSET, TRANS_DDI_MODE_DP_SST,
        };
        let val =
            build_trans_ddi_func_ctl(self.port.func_ctl_index(), TRANS_DDI_MODE_DP_SST, lanes);
        self.mmio
            .write32(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET, val);
        compiler_fence(Ordering::SeqCst);
    }

    pub(crate) fn program_mn(&mut self, mode: &Mode, rate: LinkRate, lanes: u8) {
        use crate::intel_gpu_pipes::{
            dp_mn, Transcoder, PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET,
            PIPE_LINK_N1_OFFSET,
        };
        let ls_khz = rate.megabits_per_sec() * 100;
        let (dm, dn, lm, ln) = dp_mn(mode.pixel_clock_khz, ls_khz, lanes as u32, 3);
        let base = Transcoder::A.base();
        self.mmio.write32(base + PIPE_DATA_M1_OFFSET, dm);
        self.mmio.write32(base + PIPE_DATA_N1_OFFSET, dn);
        self.mmio.write32(base + PIPE_LINK_M1_OFFSET, lm);
        // LINK_N last: it triggers the hardware update.
        self.mmio.write32(base + PIPE_LINK_N1_OFFSET, ln);
        compiler_fence(Ordering::SeqCst);
    }

    pub(crate) fn program_plane(&mut self, fb: &Framebuffer, mode: &Mode) {
        use crate::intel_gpu_pipes::{
            build_primary_plane, Pipe as PipeIdx, PixelFormat as PipeFmt, PLANE_CTL_OFFSET,
            PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET,
            PLANE_SURF_OFFSET,
        };
        let pipe_fmt = match fb.format {
            PixelFormat::Xrgb8888 => PipeFmt::Argb8888,
        };
        let prog = match build_primary_plane(
            mode.h_active,
            mode.v_active,
            fb.stride_bytes,
            fb.phys_addr as u32,
            pipe_fmt,
        ) {
            Ok(p) => p,
            Err(_) => return,
        };
        let base = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        self.mmio
            .write32(base + PLANE_STRIDE_OFFSET, prog.plane_stride);
        self.mmio.write32(base + PLANE_SIZE_OFFSET, prog.plane_size);
        self.mmio
            .write32(base + PLANE_OFFSET_OFFSET, prog.plane_offset);
        self.mmio.write32(base + PLANE_CTL_OFFSET, prog.plane_ctl);
        self.mmio.write32(base + PLANE_SURF_OFFSET, prog.plane_surf);
        compiler_fence(Ordering::SeqCst);
    }

    // ── DP transport + training ──────────────────────────────

    /// Program DP_TP_CTL for transcoder A: enabled, SST,
    /// enhanced framing, with the given link-training pattern
    /// field (PAT1 while training, NORMAL once trained).
    fn program_dp_tp_ctl(&mut self, pattern: u32) {
        use crate::intel_gpu_pipes::Transcoder;
        let off = Transcoder::A.base() + DP_TP_CTL_OFFSET;
        let cur = self.mmio.read32(off);
        let val = (cur & !DP_TP_CTL_LINK_TRAIN_MASK)
            | DP_TP_CTL_ENABLE
            | DP_TP_CTL_ENHANCED_FRAME
            | pattern;
        self.mmio.write32(off, val);
        compiler_fence(Ordering::SeqCst);
    }

    /// Run DPCD link training over this port's AUX channel
    /// (the shared `dp_link_training` state machine; HBR2 start,
    /// 4 lanes, the codec's fallback ladder). Returns the
    /// trained (rate, lanes, per-lane (swing, pre-emphasis)).
    fn train_dp_link(&mut self) -> Result<(LinkRate, u8, LaneLevels), ModesetError> {
        self.train_dp_link_at(crate::dp_link_training::LinkRate::Hbr2, 4)
    }

    /// [`Self::train_dp_link`] from `rate` x `lanes`.
    fn train_dp_link_at(
        &mut self,
        rate: crate::dp_link_training::LinkRate,
        lanes: u8,
    ) -> Result<(LinkRate, u8, LaneLevels), ModesetError> {
        use crate::dp_link_training::{train_link, LinkError, LinkRate as TrainRate};
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        match train_link(&mut aux, rate, lanes, |_us| core::hint::spin_loop()) {
            Ok(trained) => {
                let rate = match trained.rate {
                    TrainRate::Rbr => LinkRate::DpRbr,
                    TrainRate::Hbr => LinkRate::DpHbr,
                    TrainRate::Hbr2 => LinkRate::DpHbr2,
                    TrainRate::Hbr3 => LinkRate::DpHbr3,
                };
                let mut levels = [(0u8, 0u8); 4];
                for (i, lane) in trained.vswing_pe.lanes.iter().enumerate() {
                    levels[i] = (lane.swing, lane.pre_emph);
                }
                Ok((rate, trained.lanes, levels))
            }
            Err(LinkError::CrFailed(_)) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::EqFailed(_)) => Err(ModesetError::LinkTrainingEq),
            Err(LinkError::Aborted) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::AuxFailure(e)) => Err(ModesetError::AuxFailure(e)),
        }
    }

    // ── Final enables ────────────────────────────────────────

    fn enable_transcoder(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{
            Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
        };
        let off = Transcoder::A.conf_base() + PIPECONF_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur | PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(
            self.mmio,
            off,
            PIPECONF_ENABLE | PIPECONF_STATE,
            true,
            100_000_000,
        ) {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        Ok(())
    }

    /// A fresh common frame, current source enable and the actual primary
    /// shadow/LIVE image replace the old unconditional 20ms delay. This is
    /// bounded software evidence, not sink training/visible-pixel acceptance
    /// or permission to reclaim an older scanout allocation.
    fn observe_plane(
        &self,
        fb: &Framebuffer,
        mode: &Mode,
        lanes: u8,
        start: u32,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{
            build_primary_plane, build_trans_ddi_func_ctl, PixelFormat as PipeFmt,
            TRANS_DDI_MODE_DP_SST,
        };
        let plane = build_primary_plane(
            mode.h_active,
            mode.v_active,
            fb.stride_bytes,
            fb.phys_addr as u32,
            PipeFmt::Argb8888,
        )
        .map_err(|_| ModesetError::InvalidFramebuffer)?;
        let ddi_reg = inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?;
        let route =
            build_trans_ddi_func_ctl(self.port.func_ctl_index(), TRANS_DDI_MODE_DP_SST, lanes);
        let mut refused = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let before = self.mmio.read32(0x70040);
                let conf = self.mmio.read32(0x70008);
                let ddi = self.mmio.read32(ddi_reg);
                let buf = self.mmio.read32(self.port.buf_ctl1());
                let source_route = self.mmio.read32(0x60400);
                let source_clock = self.mmio.read32(TRANS_CLK_SEL_A);
                let source_pattern = self.mmio.read32(0x60540);
                let image = [
                    (0x70180, plane.plane_ctl),
                    (0x70188, plane.plane_stride),
                    (0x70190, plane.plane_size),
                    (0x701a4, plane.plane_offset),
                    (0x7019c, plane.plane_surf),
                    (0x701ac, plane.plane_surf),
                ];
                let matches = image
                    .into_iter()
                    .all(|(off, expected)| self.mmio.read32(off) == expected);
                let after = self.mmio.read32(0x70040);
                refused = !self.mmio.display_access_ok()
                    || before == u32::MAX
                    || after == u32::MAX
                    || conf == u32::MAX
                    || ddi == u32::MAX;
                refused
                    || (matches
                        && source_route == route
                        && source_clock == trans_clk_sel_port(self.port.phy_index())
                        && source_pattern
                            & (DP_TP_CTL_ENABLE
                                | DP_TP_CTL_ENHANCED_FRAME
                                | DP_TP_CTL_LINK_TRAIN_MASK)
                            == DP_TP_CTL_ENABLE
                                | DP_TP_CTL_ENHANCED_FRAME
                                | DP_TP_CTL_LINK_TRAIN_NORMAL
                        && conf & (3 << 30) == 3 << 30
                        && ddi & (1 << 31) != 0
                        && buf & ((1 << 24) | (1 << 7)) == 1 << 24
                        && before != start
                        && before == after)
            },
            narf_time::Deadline::after_ns(100_000_000),
        );
        if !done || refused {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        Ok(())
    }
}

/// Pick the lowest DP link rate that can deliver
/// `pixel_clock_khz` of 24-bpp scanout over 4 lanes — the same
/// bandwidth rule as the Gen12 orchestrator (24 bpp / 0.8 coding
/// efficiency ⇒ required per-lane kbps = pixel_clock × 30 / 4).
fn link_rate_for_pixel_clock(pixel_clock_khz: u32) -> LinkRate {
    let required_kbps = (pixel_clock_khz.saturating_mul(30)) / 4;
    if required_kbps <= 1_620_000 {
        LinkRate::DpRbr
    } else if required_kbps <= 2_700_000 {
        LinkRate::DpHbr
    } else if required_kbps <= 5_400_000 {
        LinkRate::DpHbr2
    } else {
        LinkRate::DpHbr3
    }
}

/// The PHY PLL rate of a DSC plan's link (RBR..HBR3 only).
fn dsc_link_rate(plan: &DscPlan) -> Result<LinkRate, ModesetError> {
    Ok(crate::intel_gpu_modeset::to_pll_rate(train_rate(plan)?))
}

/// The training rate of a DSC plan's link.
fn train_rate(plan: &DscPlan) -> Result<crate::dp_link_training::LinkRate, ModesetError> {
    use crate::dp_link_training::LinkRate as TrainRate;
    match plan.link_rate {
        162_000 => Ok(TrainRate::Rbr),
        270_000 => Ok(TrainRate::Hbr),
        540_000 => Ok(TrainRate::Hbr2),
        810_000 => Ok(TrainRate::Hbr3),
        _ => Err(ModesetError::Dsc(DscRefusal::LinkRateUnqualified)),
    }
}

/// Convert our [`Mode`] into the codec layer's `DisplayTiming`
/// (same synthesis as the Gen12 orchestrator).
fn mode_to_display_timing(mode: &Mode) -> crate::intel_gpu_pipes::DisplayTiming {
    crate::intel_gpu_pipes::DisplayTiming {
        hactive: mode.h_active,
        hblank_start: mode.h_active,
        hblank_end: mode.h_total,
        hsync_start: mode.h_sync_start,
        hsync_end: mode.h_sync_end,
        htotal: mode.h_total,
        vactive: mode.v_active,
        vblank_start: mode.v_active,
        vblank_end: mode.v_total,
        vsync_start: mode.v_sync_start,
        vsync_end: mode.v_sync_end,
        vtotal: mode.v_total,
    }
}

/// Hardware-only bounded polling, also valid inside the existing async
/// resume poll. Never enter a block_on bridge or wait on another task here.
fn wait_bit<M: MmioWindow + ?Sized>(
    mmio: &M,
    off: u64,
    mask: u32,
    want_set: bool,
    timeout_ns: u64,
) -> bool {
    let mut refused = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            if !mmio.display_access_ok() {
                refused = true;
                return true;
            }
            let value = mmio.read32(off);
            refused = value == u32::MAX || !mmio.display_access_ok();
            refused || value & mask == if want_set { mask } else { 0 }
        },
        narf_time::Deadline::after_ns(timeout_ns),
    );
    done && !refused
}

fn validate_framebuffer(fb: &Framebuffer) -> Result<(), ModesetError> {
    if fb.stride_bytes % 64 != 0 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    if fb.phys_addr & 0xFFF != 0 {
        return Err(ModesetError::InvalidFramebuffer);
    }
    Ok(())
}

/// Attempt to take over the display from UEFI GOP on a Meteor
/// Lake GPU — the Xe-LPG counterpart of
/// [`crate::intel_gpu_modeset::takeover_display`], reached from
/// that function through the generation dispatch. The GOP
/// surface registers (PIPECONF / PLANE_SURF / PLANE_STRIDE) sit
/// at the same BAR0 offsets on Xe-LPG.
pub fn takeover_display(gpu: &crate::intel_gpu::IntelGpu) -> Option<Mode> {
    let window = gpu.mode_window();
    crate::intel_gpu_modeset::takeover_display_with(&window, gpu.chip.generation)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::intel_gpu_aux::{AUX_CTL_DONE, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY};
    use crate::intel_gpu_xelpg::tests::{Fail, FakePhy};
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    extern crate alloc;

    /// MTL-shaped register file: the C10/C20 message-bus model
    /// from `intel_gpu_xelpg::tests::FakePhy`, plus the pieces a
    /// full modeset conversation needs — power-well grant
    /// mirrors, the CDCLK PLL lock mirror, the PIPECONF state
    /// mirror, and a DPCD sink behind the port's AUX channel.
    ///
    /// The sink NACKs every I2C-over-AUX transaction (no EDID
    /// EEPROM modelled), so modesets run on the caller's
    /// fallback mode; native DPCD reads/writes behave (CR+EQ
    /// done, unless `hbr2_cr_fails` makes the sink refuse clock
    /// recovery at HBR2).
    #[derive(Debug)]
    pub struct MtlFake {
        phy: FakePhy,
        port: XeLpgPort,
        pub writes: RefCell<Vec<(u64, u32)>>,
        wells: RefCell<Vec<(u64, u32)>>,
        pub wells_dead: Cell<bool>,
        cdclk_pll: Cell<u32>,
        pipeconf: Cell<u32>,
        frame_pending: Cell<bool>,
        aux_data: RefCell<[u32; 5]>,
        aux_ctl_read: Cell<u32>,
        aux_reply: RefCell<Vec<u8>>,
        dpcd: RefCell<[u8; 0x1000]>,
        pub hbr2_cr_fails: Cell<bool>,
        refuse_color: Cell<u64>,
        /// Every native DPCD write byte with the register-write count at
        /// its arrival: (address, value, writes so far).
        pub dpcd_writes: RefCell<Vec<(usize, u8, usize)>>,
    }

    const PIPECONF_OFF: u64 = 0x7_0008;
    /// The ICL AUX well register the display-14 path must never use.
    const PWR_WELL_CTL_AUX2: u64 = 0x4_5444;

    impl MtlFake {
        pub fn new(port: XeLpgPort) -> Self {
            let phy = FakePhy::new(port);
            // This legacy lane preserves an inherited enabled DDI; an off
            // port needs a separately qualified complete enable sequence.
            if let Some(ddi) = inherited_ddi_ctl(port) {
                phy.write32(ddi, 1 << 31);
            }
            Self {
                phy,
                port,
                writes: RefCell::new(Vec::new()),
                wells: RefCell::new(Vec::new()),
                wells_dead: Cell::new(false),
                cdclk_pll: Cell::new(0),
                pipeconf: Cell::new(0),
                frame_pending: Cell::new(false),
                aux_data: RefCell::new([0; 5]),
                aux_ctl_read: Cell::new(0),
                aux_reply: RefCell::new(Vec::new()),
                dpcd: RefCell::new([0; 0x1000]),
                hbr2_cr_fails: Cell::new(false),
                refuse_color: Cell::new(u64::MAX),
                dpcd_writes: RefCell::new(Vec::new()),
            }
        }

        pub fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn well_stored(&self, off: u64) -> u32 {
            self.wells
                .borrow()
                .iter()
                .rev()
                .find(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .unwrap_or(0)
        }

        fn dpcd_read(&self, addr: usize) -> u8 {
            match addr {
                0x202 | 0x203 => {
                    if self.hbr2_cr_fails.get() && self.dpcd.borrow()[0x100] == 0x14 {
                        0x00
                    } else {
                        0x77
                    }
                }
                0x204 => 0x01,
                a => self.dpcd.borrow()[a & 0xFFF],
            }
        }

        fn aux_send(&self) {
            let mut wire = [0u8; 20];
            for (i, d) in self.aux_data.borrow().iter().enumerate() {
                wire[i * 4..i * 4 + 4].copy_from_slice(&d.to_be_bytes());
            }
            let cmd = wire[0] >> 4;
            let addr =
                (((wire[0] & 0xF) as usize) << 16) | ((wire[1] as usize) << 8) | wire[2] as usize;
            let len = wire[3] as usize + 1;
            let mut reply: Vec<u8> = Vec::new();
            match cmd {
                // NativeWrite — store payload into the DPCD file.
                0x8 => {
                    let at = self.writes.borrow().len();
                    for i in 0..len {
                        let a = (addr + i) & 0xFFF;
                        self.dpcd.borrow_mut()[a] = wire[4 + i];
                        self.dpcd_writes.borrow_mut().push((a, wire[4 + i], at));
                    }
                    reply.push(0x00);
                }
                // NativeRead — status byte + DPCD bytes.
                0x9 => {
                    reply.push(0x00);
                    for i in 0..len {
                        reply.push(self.dpcd_read(addr + i));
                    }
                }
                // I2C-over-AUX — no EEPROM behind this sink.
                _ => reply.push(0x40),
            }
            let msgsize = reply.len() as u32;
            *self.aux_reply.borrow_mut() = reply;
            self.aux_ctl_read
                .set(AUX_CTL_DONE | (msgsize << AUX_CTL_MSGSIZE_SHIFT));
        }
    }

    impl MmioWindow for MtlFake {
        fn read32(&self, off: u64) -> u32 {
            if off == PWR_WELL_CTL2 || off == PWR_WELL_CTL_AUX2 {
                if self.wells_dead.get() {
                    return 0;
                }
                let s = self.well_stored(off);
                // STATE bits mirror their REQUEST bits.
                return s | ((s & 0xAAAA_AAAA) >> 1);
            }
            if off == CDCLK_PLL_ENABLE_REG {
                let s = self.cdclk_pll.get();
                return if s & CDCLK_PLL_ENABLE != 0 {
                    s | CDCLK_PLL_LOCK
                } else {
                    s
                };
            }
            if off == PIPECONF_OFF {
                let s = self.pipeconf.get();
                return s | ((s & crate::intel_gpu_pipes::PIPECONF_ENABLE) >> 1);
            }
            if off == 0x70040 && self.frame_pending.replace(false) {
                let next = self.phy.read32(off).wrapping_add(1);
                self.phy.write32(off, next);
            }
            if off == 0x701ac && self.pipeconf.get() & (1 << 31) != 0 {
                return self.phy.read32(0x7019c);
            }
            if off == self.port.aux_ctl() {
                return self.aux_ctl_read.get();
            }
            let aux_data_base = self.port.aux_base() + 0x14;
            if off >= aux_data_base && off < aux_data_base + 20 {
                let idx = ((off - aux_data_base) / 4) as usize;
                let reply = self.aux_reply.borrow();
                let mut v = 0u32;
                for b in 0..4 {
                    let byte = reply.get(idx * 4 + b).copied().unwrap_or(0);
                    v |= (byte as u32) << (24 - 8 * b);
                }
                return v;
            }
            self.phy.read32(off)
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            if off == self.refuse_color.get() {
                return;
            }
            if off == PWR_WELL_CTL2 || off == PWR_WELL_CTL_AUX2 {
                self.wells.borrow_mut().push((off, val));
                return;
            }
            if off == CDCLK_PLL_ENABLE_REG {
                self.cdclk_pll.set(val);
                return;
            }
            if off == PIPECONF_OFF {
                // STATE is hardware-owned and follows ENABLE, including
                // read-modify-writes which carry the prior read-only state.
                let was_enabled = self.pipeconf.get() & (1 << 31) != 0;
                self.pipeconf
                    .set(val & !crate::intel_gpu_pipes::PIPECONF_STATE);
                self.frame_pending.set(val & (1 << 31) != 0 && !was_enabled);
                return;
            }
            if off == self.port.aux_ctl() {
                if val & AUX_CTL_SEND_BUSY != 0 {
                    self.aux_send();
                }
                return;
            }
            let aux_data_base = self.port.aux_base() + 0x14;
            if off >= aux_data_base && off < aux_data_base + 20 {
                let idx = ((off - aux_data_base) / 4) as usize;
                self.aux_data.borrow_mut()[idx] = val;
                return;
            }
            self.phy.write32(off, val)
        }
    }

    fn test_fb() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1024 * 4,
            format: PixelFormat::Xrgb8888,
        }
    }

    fn smoke_mtl_restore_uses_xelpg_sequence() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::A);
        let mode = Mode::VESA_1024X768_60;
        if crate::intel_gpu_modeset::modeset_display(
            &fake,
            crate::intel_gpu::Generation::MeteorLake,
            &test_fb(),
            Some(&mode),
        ) != Ok(mode)
        {
            return TestResult::Fail("MTL restore must complete through the shared dispatch");
        }
        if fake.writes_to(0x6_4040).is_empty() || fake.writes_to(0x6_40e0).is_empty() {
            return TestResult::Fail("MTL restore must use C10 message bus and port clock");
        }
        if fake.writes_to(TRANS_CLK_SEL_A) != [0x1000_0000] {
            return TestResult::Fail("MTL restore must route PHY A");
        }
        for off in [0x16_4280, 0x16_4284, 0x4_6010, 0x6_4000] {
            if !fake.writes_to(off).is_empty() {
                return TestResult::Fail("MTL restore must not write Gen12 clock registers");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_restore_uses_xelpg_sequence
    );

    fn smoke_mtl_modeset_ddi_a_full_run() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::A);
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A);
        let mode = match ms.modeset(&test_fb(), Some(&Mode::VESA_1024X768_60)) {
            Ok(m) => m,
            Err(_) => {
                return TestResult::Fail("MTL DDI A modeset must complete against the MTL fake");
            }
        };
        if mode.h_active != 1024 || mode.v_active != 768 {
            return TestResult::Fail("modeset must return the fallback mode");
        }
        // Xe-LPG conversation present: message bus, port clock
        // control, CDCLK squash programming for the 172.8 MHz
        // rung, transcoder clock select for PHY A.
        if fake.writes_to(0x6_4040).is_empty() || fake.writes_to(0x6_40E0).is_empty() {
            return TestResult::Fail("no C10 message-bus / clock-ctl traffic");
        }
        let squash = fake.writes_to(CDCLK_SQUASH_CTL);
        if squash.last() != Some(&(CDCLK_SQUASH_ENABLE | CDCLK_SQUASH_WINDOW_SIZE_15 | 0xAD5A)) {
            return TestResult::Fail("CDCLK squash waveform for 172800 not programmed");
        }
        if fake.writes_to(TRANS_CLK_SEL_A) != [0x1000_0000u32] {
            return TestResult::Fail("TRANS_CLK_SEL must route PHY A (0x10000000)");
        }
        // Training converged at HBR2 while the PLL started at
        // RBR for this pixel clock, so VALFREQ shows the
        // reprogram: 162000 then 540000.
        if fake.writes_to(0x6_4030) != [162_000u32, 540_000] {
            return TestResult::Fail("VALFREQ must show RBR then HBR2 after training fallback");
        }
        // Power wells: PW_1 + PW_A requested in CTL2; AUX_A powered
        // by its own XELPDP_DP_AUX_CH_CTL request (0x64010 bit 19,
        // xelpdp_aux_power_well_enable), never the ICL AUX2 well.
        let ctl2 = fake.writes_to(PWR_WELL_CTL2);
        if !ctl2.iter().any(|v| v & pwr_well_req(PW_1_IDX) != 0)
            || !ctl2.iter().any(|v| v & pwr_well_req(PW_A_IDX) != 0)
        {
            return TestResult::Fail("PW_1 / PW_A not requested");
        }
        let aux_ctl = fake.writes_to(0x6_4010);
        if aux_ctl.first() != Some(&(1 << 19)) {
            return TestResult::Fail("AUX_A power request must precede AUX traffic");
        }
        // Every later AUX control word preserves the request
        // (skl_get_aux_send_ctl, DISPLAY_VER >= 14).
        if aux_ctl.iter().any(|v| v & (1 << 19) == 0) {
            return TestResult::Fail("AUX transaction dropped the AUX_A power request");
        }
        if !fake.writes_to(PWR_WELL_CTL_AUX2).is_empty() {
            return TestResult::Fail("display 14 must not request the ICL AUX2 well");
        }
        // Pattern generator ends in NORMAL.
        let tp = fake.writes_to(0x6_0540);
        if tp.last()
            != Some(&(DP_TP_CTL_ENABLE | DP_TP_CTL_ENHANCED_FRAME | DP_TP_CTL_LINK_TRAIN_NORMAL))
        {
            return TestResult::Fail("DP_TP_CTL must end in NORMAL pattern");
        }
        // Gen12-only registers must never be written on MTL:
        // DPCLKA routing, DPLL_CFGCR0, DPLL0_ENABLE, DDI_BUF_CTL.
        for off in [0x16_4280u64, 0x16_4284, 0x4_6010, 0x6_4000] {
            if !fake.writes_to(off).is_empty() {
                return TestResult::Fail("Gen12-only register written during MTL modeset");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_ddi_a_full_run
    );

    /// Records each pipe-DMC report with the fake's write count at the call.
    struct DmcAt<'a> {
        fake: &'a MtlFake,
        events: RefCell<Vec<(u32, bool, usize)>>,
    }

    impl crate::intel_gpu_dc_states::PipeDmc for DmcAt<'_> {
        fn enable_pipe(&self, pipe: u32) {
            let at = self.fake.writes.borrow().len();
            self.events.borrow_mut().push((pipe, true, at));
        }
        fn disable_pipe(&self, pipe: u32) {
            let at = self.fake.writes.borrow().len();
            self.events.borrow_mut().push((pipe, false, at));
        }
    }

    fn smoke_mtl_modeset_reports_pipe_a_dmc_around_its_crtc() -> TestResult {
        // Linux hsw_crtc_disable ends with intel_dmc_disable_pipe (after
        // the transcoder and the port PLL are off); hsw_crtc_enable starts
        // with intel_dmc_enable_pipe (after the pre-plane update, before
        // the port PLL). The owned modeset reports Pipe A at exactly those
        // two points, once each.
        let fake = MtlFake::new(XeLpgPort::A);
        let dmc = DmcAt {
            fake: &fake,
            events: RefCell::new(Vec::new()),
        };
        let mode = Mode::VESA_1024X768_60;
        if XeLpgModeset::new(&fake, XeLpgPort::A)
            .with_pipe_dmc(&dmc)
            .modeset_fixed(&test_fb(), &mode)
            != Ok(mode)
        {
            return TestResult::Fail("the MTL modeset must complete against the MTL fake");
        }
        let events = dmc.events.borrow();
        let &[(0, false, dark), (0, true, lit)] = events.as_slice() else {
            return TestResult::Fail("Pipe A must be reported dark, then lit, once each");
        };
        let writes = fake.writes.borrow();
        let conf_off = writes
            .iter()
            .rposition(|&(r, v)| r == PIPECONF_OFF && v & (1 << 31) == 0);
        let pll_off = writes
            .iter()
            .position(|&(r, _)| r == XeLpgPort::A.port_clock_ctl());
        let pll_on = writes.iter().position(|&(r, _)| r == 0x6_4030);
        let conf_on = writes
            .iter()
            .rposition(|&(r, v)| r == PIPECONF_OFF && v & (1 << 31) != 0);
        match (conf_off, pll_off, pll_on, conf_on) {
            (Some(off), Some(pll), Some(on), Some(enabled))
                if off < dark && pll < dark && dark <= lit && lit <= on && on < enabled => {}
            _ => return TestResult::Fail("dark after the crtc stop, lit before the port PLL"),
        }
        // The inherited layout (no display-14 resource ownership in this
        // fake) leaves no owned panel profile behind.
        if owned_panel_mode().is_some() {
            return TestResult::Fail("an inherited-layout modeset must not record a panel");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_reports_pipe_a_dmc_around_its_crtc
    );

    fn smoke_mtl_modeset_trans_vblank_start_field_is_zero() -> TestResult {
        // intel_set_transcoder_timings, DISPLAY_VER >= 13: VBLANK_START is
        // cleared (crtc_vblank_start = 1). 1024x768 ends its vblank at
        // vtotal 806: TRANS_VBLANK = (806 - 1) << 16, written once.
        let fake = MtlFake::new(XeLpgPort::A);
        let mode = Mode::VESA_1024X768_60;
        if XeLpgModeset::new(&fake, XeLpgPort::A).modeset_fixed(&test_fb(), &mode) != Ok(mode) {
            return TestResult::Fail("the MTL modeset must complete against the MTL fake");
        }
        if fake.writes_to(0x6_0010) != [805 << 16] {
            return TestResult::Fail("Pipe A's TRANS_VBLANK must carry VBLANK_END only");
        }
        if fake.writes_to(0x6_000c) != [(805 << 16) | 767] {
            return TestResult::Fail("TRANS_VTOTAL keeps its active field");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_trans_vblank_start_field_is_zero
    );

    /// E1 of the DSC tests: a 2880x1800@120 eDP 1.4b OLED on HBR2 x2,
    /// DSC 1.2, 1/2/4 slices, at most 12 bpp.
    const OLED_DSC: [u8; 16] = [
        0x01, 0x21, 0x00, 0x0f, 0x0b, 0x00, 0x01, 0xc0, 0x00, 0x01, 0x06, 0x00, 0x08, 0x00, 0x00,
        0x00,
    ];

    fn oled_mode() -> Mode {
        Mode {
            pixel_clock_khz: 650_016,
            h_active: 2880,
            h_total: 2960,
            h_sync_start: 2928,
            h_sync_end: 2944,
            v_active: 1800,
            v_total: 1830,
            v_sync_start: 1803,
            v_sync_end: 1809,
            h_sync_positive: true,
            v_sync_positive: false,
        }
    }

    fn oled_fb() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 2880 * 4,
            format: PixelFormat::Xrgb8888,
        }
    }

    /// An eDP 1.4b panel: DPCD rev 1.4, `rate` code, `lanes`, DSC caps.
    fn oled_panel(fake: &MtlFake, rate: u8, lanes: u8) {
        let mut dpcd = fake.dpcd.borrow_mut();
        dpcd[..3].copy_from_slice(&[0x14, rate, 0x80 | lanes]);
        dpcd[0x700] = 0x05;
        dpcd[0x60..0x70].copy_from_slice(&OLED_DSC);
    }

    fn oled_plan() -> crate::intel_gpu_xelpg_dsc::DscPlan {
        use crate::intel_gpu_xelpg_dsc::{decide_edp, DscDpcd, EdpCaps, EdpDecision, EdpVbt};
        let mut receiver = [0u8; 16];
        receiver[..3].copy_from_slice(&[0x14, 0x14, 0x82]);
        let caps = EdpCaps {
            receiver,
            edp_rev: 0x05,
            link_rates: [0; 8],
            dsc: DscDpcd(OLED_DSC),
        };
        match decide_edp(&caps, &EdpVbt::Missing, &oled_mode()) {
            Ok(EdpDecision::Dsc(plan)) => plan,
            other => panic!("the OLED must compress: {other:?}"),
        }
    }

    fn smoke_mtl_edp_dsc_modeset_programs_vdsc_pps_and_sink() -> TestResult {
        use crate::intel_gpu_pipes::Pipe as PipeIdx;
        use crate::intel_gpu_xelpg_dsc::{install_edp_vbt, installed_edp_vbt, EdpVbt};
        let previous = installed_edp_vbt();
        install_edp_vbt(EdpVbt::Missing);
        let fake = MtlFake::new(XeLpgPort::A);
        oled_panel(&fake, 0x14, 2);
        let mode = oled_mode();
        let result = XeLpgModeset::new(&fake, XeLpgPort::A).modeset_fixed(&oled_fb(), &mode);
        install_edp_vbt(previous);
        if result != Ok(mode) {
            return TestResult::Fail("the compressed eDP modeset must complete");
        }
        let plan = oled_plan();
        let writes = fake.writes.borrow().clone();
        // The PHY PLL runs at the plan's HBR2 from the start; two lanes.
        let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
            XeLpgPort::A.func_ctl_index(),
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
            2,
        );
        if fake.writes_to(0x6_4030) != [540_000] || fake.writes_to(0x6_0400) != [func] {
            return TestResult::Fail("the PLL and function must take the plan's HBR2 x2 link");
        }
        // Inherited layout: CDCLK covers intel_vdsc_min_cdclk (331157 kHz,
        // above the 325008 kHz pixel floor): the 480 MHz rung, ratio 25.
        if fake.cdclk_pll.get() & 0xff != 25 || fake.writes_to(CDCLK_CTL).last() != Some(&958) {
            return TestResult::Fail("CDCLK must cover the VDSC minimum");
        }
        // intel_dsc_enable on Pipe A's own engines, in Linux's order.
        let engines: Vec<(u64, u32)> = writes
            .iter()
            .copied()
            .filter(|&(r, _)| (0x7_8000..0x7_8200).contains(&r))
            .collect();
        if engines != plan.engine_writes(PipeIdx::A) {
            return TestResult::Fail("Pipe A's VDSC engines must take the plan's image");
        }
        // The PPS SDP on transcoder A, enabled after its 33 dwords.
        let sdp = plan.pps_sdp();
        if (0..33).any(|i| fake.writes_to(0x6_0350 + 4 * i as u64) != [sdp[i]])
            || fake.writes_to(0x6_0200).last().map(|v| v & (1 << 24)) != Some(1 << 24)
        {
            return TestResult::Fail("the PPS SDP must be written and enabled");
        }
        // The compressed M/N alone, TU 64; CHICKEN_TRANS takes the
        // display-14 bits.
        let mn = plan.m_n(&mode);
        if fake.writes_to(0x6_0030) != [mn[0]]
            || fake.writes_to(0x6_0034) != [mn[1]]
            || fake.writes_to(0x6_0040) != [mn[2]]
            || fake.writes_to(0x6_0044) != [mn[3]]
            || fake.writes_to(0x6_04e0) != [1 << 15]
        {
            return TestResult::Fail("M/N must use the compressed bpp");
        }
        // Order: D0 then DP_DSC_ENABLE before LINK_BW_SET; the PPS SDP
        // after DP_TP_CTL normal; engines and M/N before TRANSCONF enable.
        let dpcd = fake.dpcd_writes.borrow().clone();
        let at = |addr: usize, v: u8| dpcd.iter().position(|&(a, b, _)| a == addr && b == v);
        let (Some(d0), Some(dsc), Some(bw)) = (at(0x600, 1), at(0x160, 1), at(0x100, 0x14)) else {
            return TestResult::Fail("the sink must see D0, DSC enable and HBR2");
        };
        let pos =
            |r: u64, f: &dyn Fn(u32) -> bool| writes.iter().position(|&(o, v)| o == r && f(v));
        let normal = pos(0x6_0540, &|v| v & (7 << 8) == 3 << 8);
        let pps = pos(0x6_0350, &|_| true);
        let ctl2 = pos(0x7_8004, &|_| true);
        let link_n = pos(0x6_0044, &|_| true);
        let enable = pos(PIPECONF_OFF, &|v| v & (1 << 31) != 0);
        match (normal, pps, ctl2, link_n, enable) {
            (Some(n), Some(p), Some(c), Some(l), Some(e))
                if d0 < dsc && dsc < bw && n < p && p < c && c < l && l < e => {}
            _ => return TestResult::Fail("the DSC steps must follow mtl_ddi_pre_enable_dp"),
        }
        if fake.dpcd.borrow()[0x160] != 1 {
            return TestResult::Fail("the sink's decompression stays enabled");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_dsc_modeset_programs_vdsc_pps_and_sink
    );

    fn smoke_mtl_edp_dsc_refusals_precede_every_write() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::{install_edp_vbt, installed_edp_vbt, DscRefusal, EdpVbt};
        let previous = installed_edp_vbt();
        let mode = oled_mode();
        let run = |rate: u8, lanes: u8, vbt: EdpVbt| {
            install_edp_vbt(vbt);
            let fake = MtlFake::new(XeLpgPort::A);
            oled_panel(&fake, rate, lanes);
            let result = XeLpgModeset::new(&fake, XeLpgPort::A).modeset_fixed(&oled_fb(), &mode);
            let untouched = fake.writes_to(PIPECONF_OFF).is_empty()
                && fake.writes_to(0x7_0180).is_empty()
                && fake.writes_to(0x6_4030).is_empty()
                && fake.writes_to(0x7_8004).is_empty();
            (result, untouched)
        };
        let cases = [
            // HBR3 x2 carries 18 bpp: Linux's 6 bpc, not this pipe's.
            (
                run(0x1e, 2, EdpVbt::Missing),
                Err(ModesetError::Dsc(DscRefusal::SixBpcUnqualified)),
            ),
            (
                run(
                    0x14,
                    2,
                    EdpVbt::Panel {
                        dsc_disable: true,
                        max_link_rate: 0,
                    },
                ),
                Err(ModesetError::Dsc(DscRefusal::VbtDisabled)),
            ),
            (
                run(0x14, 2, EdpVbt::PanelByPnpId),
                Err(ModesetError::Dsc(DscRefusal::VbtPanelUnknown)),
            ),
        ];
        install_edp_vbt(previous);
        for ((result, untouched), want) in cases {
            if result != want || !untouched {
                return TestResult::Fail("a DSC refusal must precede the pipeline stop");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_dsc_refusals_precede_every_write
    );

    fn smoke_mtl_modeset_tears_down_firmware_dsc_in_linux_order() -> TestResult {
        // A panel firmware left compressing (Pipe A's VDSC on, the PPS SDP
        // enabled, the sink decompressing) and a mode this driver carries
        // uncompressed: intel_ddi_disable_dp turns the sink's decompression
        // off before the transcoder stops; intel_ddi_post_disable clears
        // DSS_CTL1/2 and the PPS SDP enable after it.
        let fake = MtlFake::new(XeLpgPort::A);
        fake.phy.write32(0x7_8000, 1 << 30);
        fake.phy.write32(0x7_8004, (1 << 31) | (1 << 15));
        fake.phy.write32(0x6_0200, (1 << 24) | (1 << 12));
        fake.pipeconf.set(1 << 31);
        fake.dpcd.borrow_mut()[0x160] = 0x01;
        let mode = Mode::VESA_1024X768_60;
        if XeLpgModeset::new(&fake, XeLpgPort::A).modeset_fixed(&test_fb(), &mode) != Ok(mode) {
            return TestResult::Fail("the uncompressed modeset must complete");
        }
        let writes = fake.writes.borrow().clone();
        let stop = writes
            .iter()
            .position(|&(r, v)| r == PIPECONF_OFF && v & (1 << 31) == 0);
        let sink_off = fake
            .dpcd_writes
            .borrow()
            .iter()
            .find(|&&(a, v, _)| a == 0x160 && v == 0)
            .map(|&(_, _, at)| at);
        let ctl1 = writes.iter().position(|&(r, v)| r == 0x7_8000 && v == 0);
        let ctl2 = writes.iter().position(|&(r, v)| r == 0x7_8004 && v == 0);
        let dip = writes
            .iter()
            .position(|&(r, v)| r == 0x6_0200 && v == 1 << 12);
        match (sink_off, stop, ctl1, ctl2, dip) {
            (Some(s), Some(t), Some(c1), Some(c2), Some(d))
                if s <= t && t < c1 && c1 < c2 && c2 < d => {}
            _ => return TestResult::Fail("DSC teardown must follow intel_ddi_post_disable"),
        }
        // Nothing re-enables compression for the uncompressed mode.
        if fake.phy.read32(0x7_8004) != 0 || fake.dpcd.borrow()[0x160] != 0 {
            return TestResult::Fail("the uncompressed panel must stay uncompressed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_tears_down_firmware_dsc_in_linux_order
    );

    fn smoke_mtl_modeset_tc_ports_refuse_unqualified_route() -> TestResult {
        struct NoAccess;
        impl MmioWindow for NoAccess {
            fn read32(&self, _: u64) -> u32 {
                panic!("unqualified TC read");
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("unqualified TC write");
            }
        }
        for port in [
            XeLpgPort::Tc1,
            XeLpgPort::Tc2,
            XeLpgPort::Tc3,
            XeLpgPort::Tc4,
        ] {
            let mut ms = XeLpgModeset::new(&NoAccess, port);
            assert_eq!(
                ms.modeset(&test_fb(), Some(&Mode::VESA_1024X768_60)),
                Err(ModesetError::UnsupportedGeneration)
            );
            assert_eq!(
                ms.modeset_fixed(&test_fb(), &Mode::VESA_1024X768_60),
                Err(ModesetError::UnsupportedGeneration)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_tc_ports_refuse_unqualified_route
    );

    fn smoke_generation_separation() -> TestResult {
        // The masking-defeating case: a Gen12 SKU and an MTL SKU
        // through the same modeset entry shape must each run
        // their own generation's sequence. The Gen12 run is
        // configured to fail at PLL lock (its own fixture
        // recipe); the MTL run completes. Write logs must be
        // disjoint on the generation-defining registers.
        use crate::intel_gpu_ddi::Ddi;
        use crate::intel_gpu_modeset::tests::FakeMmio as Gen12Fake;
        use crate::intel_gpu_modeset::Modeset;
        let mut g12 = Gen12Fake::new();
        g12.set_read(0x4_5404, 0x1 | 0x4);
        g12.state_offset = 0x4_6010;
        g12.state_value = 1 << 26;
        let mut ms12 = Modeset::new(&g12, Ddi::A);
        match ms12.modeset(&test_fb(), Some(&Mode::VESA_1024X768_60)) {
            Err(ModesetError::PllLockTimeout) => {}
            _ => return TestResult::Fail("Gen12 control run must fail at PLL lock"),
        }
        if g12.writes_to(0x16_4284).is_empty() {
            return TestResult::Fail("Gen12 run must write DPLL_CFGCR0");
        }
        for off in [0x6_4040u64, 0x6_40E0, 0x16_F240] {
            if !g12.writes_to(off).is_empty() {
                return TestResult::Fail("Gen12 run touched an Xe-LPG register");
            }
        }

        let fake = MtlFake::new(XeLpgPort::A);
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A);
        if ms
            .modeset(&test_fb(), Some(&Mode::VESA_1024X768_60))
            .is_err()
        {
            return TestResult::Fail("MTL run must complete");
        }
        if fake.writes_to(0x6_4040).is_empty() {
            return TestResult::Fail("MTL run must use the message bus");
        }
        for off in [0x16_4280u64, 0x16_4284, 0x6_4000] {
            if !fake.writes_to(off).is_empty() {
                return TestResult::Fail("MTL run touched a Gen12 register");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_generation_separation
    );

    fn smoke_mtl_modeset_phy_error_fails() -> TestResult {
        // A PHY that answers with its error bit set — e.g. the
        // wrong generation behind the port — must fail the
        // modeset, not silently program through it.
        let fake = MtlFake::new(XeLpgPort::A);
        fake.phy.set_fail(Fail::ErrorBit);
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A);
        match ms.modeset(&test_fb(), Some(&Mode::VESA_1024X768_60)) {
            Err(ModesetError::PhyBusFailure) => TestResult::Pass,
            _ => TestResult::Fail("PHY error bit must surface as PhyBusFailure"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_phy_error_fails
    );

    fn smoke_mtl_modeset_power_well_timeout() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::A);
        fake.wells_dead.set(true);
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A);
        match ms.modeset(&test_fb(), Some(&Mode::VESA_1024X768_60)) {
            Err(ModesetError::PowerWellTimeout) => TestResult::Pass,
            _ => TestResult::Fail("ungranted power well must surface as PowerWellTimeout"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_power_well_timeout
    );

    fn smoke_mtl_modeset_training_fallback_reprograms_pll() -> TestResult {
        // Sink refuses clock recovery at HBR2; training falls
        // back to HBR and the PLL (started at RBR for this
        // pixel clock) must be reprogrammed to the trained
        // rate — VALFREQ tells the story: 162000, then 270000.
        let fake = MtlFake::new(XeLpgPort::A);
        fake.hbr2_cr_fails.set(true);
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A);
        if ms
            .modeset(&test_fb(), Some(&Mode::VESA_1024X768_60))
            .is_err()
        {
            return TestResult::Fail("fallback training must still complete the modeset");
        }
        if fake.writes_to(0x6_4030) != [162_000u32, 270_000] {
            return TestResult::Fail("PLL must be reprogrammed RBR -> HBR after fallback");
        }
        // The sink's final LINK_BW_SET is HBR (0x0A).
        if fake.dpcd.borrow()[0x100] != 0x0A {
            return TestResult::Fail("sink must end trained at HBR");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_training_fallback_reprograms_pll
    );

    fn smoke_mtl_cdclk_table_and_decode() -> TestResult {
        match mtl_cdclk_for_pixel_clock(65_000) {
            Some(e) if e.cdclk_khz == 172_800 && e.ratio == 16 && e.waveform == 0xAD5A => {}
            _ => return TestResult::Fail("65 MHz pixel clock must pick the 172800 squash rung"),
        }
        match mtl_cdclk_for_pixel_clock(500_000) {
            Some(e) if e.cdclk_khz == 307_200 && e.waveform == 0 => {}
            _ => return TestResult::Fail("500 MHz pixel clock must pick 307200"),
        }
        if mtl_cdclk_for_pixel_clock(1_400_000).is_some() {
            return TestResult::Fail("past-table pixel clock must return None");
        }
        // Decode: ratio 16 (VCO 614400) / 2 = 307200, squashed
        // by waveform 0xAD5A (popcount 9) -> 172800.
        let fake = MtlFake::new(XeLpgPort::A);
        fake.cdclk_pll.set(16 | CDCLK_PLL_ENABLE);
        fake.phy.write32(CDCLK_SQUASH_CTL, 0x8f00_ad5a); // enabled, window16
        if cdclk_current_khz(&fake) != 172_800 {
            return TestResult::Fail("CDCLK decode of ratio+squash must give 172800");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_cdclk_table_and_decode
    );

    // Full native production modeset conversations establish the prerequisite
    // consumed by CTM capture. No firmware color defaults are supplied.
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_color::{initialize_rgb_bypass, Owner, GAMMA, MODE};
    use narf_filesystem::FsError;

    const CONTROLS: [(u64, u32); 5] = [
        (0x70034, 0),
        (GAMMA, 0),
        (MODE, 0),
        (0x701c8, 0),
        (0x701cc, 1 << 13),
    ];
    fn inherited(fake: &MtlFake) {
        // Live inherited RGB surface with unowned output CSC and LUTs. The
        // production sequence must disable it and replace these control values.
        fake.phy.write32(0x70180, 0x84000000);
        fake.pipeconf.set(1 << 31);
        for (r, _) in CONTROLS {
            fake.phy.write32(r, 0xffffffff);
        }
        for r in [0x49128, 0x4ac80, 0x711cc, 0x71034, 0x49050, 0x70210] {
            fake.phy.write32(r, 0x12345678);
        }
    }
    fn smoke_mtl_owned_modeset_establishes_ctm_rgb_bypass_without_firmware_defaults() -> TestResult
    {
        let fake = MtlFake::new(XeLpgPort::A);
        inherited(&fake);
        assert!(Owner::capture(&fake, Generation::MeteorLake).is_err());
        let mode = Mode::VESA_1024X768_60;
        assert_eq!(
            crate::intel_gpu_modeset::modeset_display(
                &fake,
                Generation::MeteorLake,
                &test_fb(),
                Some(&mode)
            ),
            Ok(mode)
        );
        let mut owner = Owner::capture(&fake, Generation::MeteorLake)
            .expect("owned setup must admit CTM capture");
        owner
            .arm(
                &fake,
                Some([1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32]),
                100,
            )
            .unwrap();
        let frame = fake.read32(0x70040);
        fake.phy.write32(0x70040, frame.wrapping_add(1));
        assert!(owner.poll(&fake, 200).unwrap().is_some());
        // Restore CTM so control readback below also verifies baseline retention.
        owner.arm(&fake, None, 201).unwrap();
        fake.phy.write32(0x70040, frame.wrapping_add(2));
        assert!(owner.poll(&fake, 202).unwrap().is_some());
        for (r, value) in CONTROLS {
            assert_eq!(fake.read32(r), value);
        }
        for r in [0x49128, 0x4ac80, 0x711cc, 0x71034, 0x49050, 0x70210] {
            assert_eq!(fake.read32(r), 0x12345678);
            assert!(
                fake.writes_to(r).is_empty(),
                "other pipe or disabled matrix touched: {r:#x}"
            );
        }
        let writes = fake.writes.borrow();
        // ENABLE is the stop request. The RMW may carry the previous
        // read-only STATE bit; hardware/model owns its acknowledged value.
        // The dispatcher must observe STATE clear before RGB bypass, while
        // this write-order assertion checks the request precedes that setup.
        let disabled = writes
            .iter()
            .position(|&(r, v)| r == PIPECONF_OFF && v & (1 << 31) == 0)
            .expect("CONF stop request before RGB bypass");
        let color = writes
            .iter()
            .position(|&(r, v)| r == 0x701cc && v == 1 << 13)
            .unwrap();
        let enabled = writes
            .iter()
            .position(|&(r, v)| r == 0x70180 && v & (1 << 31) != 0)
            .unwrap();
        assert!(
            disabled < color && color < enabled,
            "RGB bypass must precede primary enable while pipe is off"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_owned_modeset_establishes_ctm_rgb_bypass_without_firmware_defaults
    );
    fn smoke_mtl_color_setup_rejects_live_or_unavailable_pipe_without_writes() -> TestResult {
        for (r, value) in [
            (0x70180, 1 << 31),
            (PIPECONF_OFF, 1 << 31),
            (PIPECONF_OFF, 1 << 30),
            (0x70180, u32::MAX),
        ] {
            let fake = MtlFake::new(XeLpgPort::A);
            if r == PIPECONF_OFF {
                fake.pipeconf.set(value);
            } else {
                fake.phy.write32(r, value);
            }
            assert!(matches!(
                initialize_rgb_bypass(&fake),
                Err(FsError::Busy | FsError::NoDevice)
            ));
            assert!(fake.writes.borrow().is_empty());
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_color_setup_rejects_live_or_unavailable_pipe_without_writes
    );
    fn smoke_mtl_color_readback_failure_aborts_owned_modeset_before_reenable() -> TestResult {
        for (register, _) in CONTROLS {
            let fake = MtlFake::new(XeLpgPort::A);
            inherited(&fake);
            fake.refuse_color.set(register);
            assert_eq!(
                crate::intel_gpu_modeset::modeset_display(
                    &fake,
                    Generation::MeteorLake,
                    &test_fb(),
                    Some(&Mode::VESA_1024X768_60)
                ),
                Err(ModesetError::ColorPipelineUnavailable)
            );
            assert!(fake.writes_to(0x70180).iter().all(|v| v & (1 << 31) == 0));
            assert_eq!(fake.read32(PIPECONF_OFF) & (3 << 30), 0);
            assert!(fake.writes_to(CDCLK_PLL_ENABLE_REG).is_empty());
            for r in [0x49128, 0x4ac80, 0x711cc, 0x71034] {
                assert!(fake.writes_to(r).is_empty());
            }
            assert!(Owner::capture(&fake, Generation::MeteorLake).is_err());
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_color_readback_failure_aborts_owned_modeset_before_reenable
    );
    include!("intel_gpu_modeset_xelpg_failclosed_tests.rs");
}
