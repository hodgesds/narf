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
//! ## Pipe bpp, the panel's link and eDP DSC
//!
//! Before anything is stopped, the panel's link and DSC capabilities are
//! read (`intel_edp_init_dpcd`), a lit eDP transcoder's bpp raises the
//! VBT's `edp.bpp` (`intel_edp_fixup_vbt_bpp`), and
//! `intel_dp_compute_link_config` decides
//! ([`crate::intel_gpu_xelpg_dsc::decide_edp`]) with the panel's EDID bpc
//! (cached from the last EDID read, [`panel_display_bpc`]) and the VBT's
//! `edp.bpp`. Three sequences follow:
//!
//! - 24 bpp fits and the panel has no rate table: the existing
//!   uncompressed sequence, unchanged (its rate rule, four lanes,
//!   `DP_LINK_BW_SET` and the training ladder). It only reads `PIPE_MISC`
//!   and rewrites it and the MSA to 8 bpc when an earlier 6 bpc modeset or
//!   firmware left a 6 bpc or dithered pipe.
//! - 18 bpp (6 bpc), or a panel that publishes `DP_SUPPORTED_LINK_RATES`:
//!   Linux's link (`intel_dp_compute_link_config_wide`, eDP intermediate
//!   rates included) on the C10 eDP PLL, `PIPE_MISC` (`BPC_6` with
//!   dithering at 18 bpp), `TRANS_DDI_FUNC_CTL` BPC, one training attempt
//!   with `DP_LINK_RATE_SET` when the panel has a table
//!   (`intel_dp_compute_rate`), the MSA (`intel_ddi_set_dp_msa`) and
//!   Linux's M/N at the pipe bpp. A failed attempt retries once at the
//!   panel's maximum link (`use_max_params`).
//! - DSC, when no uncompressed link fits.
//!
//! Every refusal is typed ([`ModesetError::Dsc`]). A compressed modeset follows
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

use crate::dp_link_training::RateSelect;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError, PixelFormat};
use crate::intel_gpu_pll::LinkRate;
use crate::intel_gpu_xelpg::{
    disable_port_pll, enable_d2d, enable_port_pll_khz, program_port_buf_ctl, reprogram_pll_khz,
    set_signal_levels_khz, Cx0Error, Cx0Phy, XeLpgPort,
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
    fn cx0_xe3(&self) -> bool {
        self.raw.cx0_xe3()
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
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn program_cdclk_floor<M: MmioWindow + ?Sized>(
    mmio: &M,
    mode: &Mode,
) -> Result<(), ModesetError> {
    program_cdclk_floor_khz(mmio, mode.pixel_clock_khz.div_ceil(2))
}

/// `program_cdclk_floor` for an explicit floor (a compressed panel adds
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
/// `DP_SET_POWER_D3`.
const DP_SET_POWER_D3: u8 = 2;

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

/// What [`XeLpgModeset::panel_off`] left for the next enable of the panel's
/// crtc: Linux keeps the same facts in the inactive crtc state and in
/// `intel_dp->DP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanelOff {
    /// The panel's port (DDI A).
    pub port: XeLpgPort,
    /// The owned panel mode the crtc ran (`None`: an inherited layout).
    pub mode: Option<Mode>,
    /// The `DDI_BUF_CTL` bit `intel_ddi_init_dp_buf_reg` carries into the
    /// next enable besides the width (`DDI_BUF_PORT_REVERSAL`);
    /// `DDI_A_4_LANES` is display < 11 only.
    buf_ctl: u32,
    /// The post-plane all-off settle ran (no other pipe was lit). When
    /// another pipe stayed lit, Pipe A's share of the layout stays
    /// programmed and covered by PM demand.
    pub settled: bool,
}

/// The panel's crtc is off by [`XeLpgModeset::panel_off`]; cleared by the
/// modeset that lights it again.
static PANEL_OFF: narf_lib::sync::IrqSafeSpinLock<Option<PanelOff>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The panel-off record, while the panel's crtc is off.
pub fn panel_off_record() -> Option<PanelOff> {
    *PANEL_OFF.lock()
}

/// Forget the panel-off record (fixtures that share the process-wide
/// owned-panel statics).
#[cfg(any(test, feature = "kernel-test"))]
pub fn forget_panel_off() {
    *PANEL_OFF.lock() = None;
}

/// `CURCNTR(PIPE_A)` and `CURBASE(PIPE_A)`; `MCURSOR_MODE_MASK`.
const CUR_CTL_A: u64 = 0x7_0080;
const CUR_BASE_A: u64 = 0x7_0084;
const CUR_MODE_MASK: u32 = 0x27;
/// `TRANS_DDI_FUNC_CTL2` relative to the transcoder (display 11+).
const TRANS_DDI_FUNC_CTL2_OFFSET: u64 = 0x404;
/// `TGL_TRANS_DDI_PORT_MASK | TRANS_DDI_MODE_SELECT_MASK`.
const TRANS_DDI_PORT_AND_MODE: u32 = (0xF << 27) | (0x7 << 24);
/// `DDI_BUF_CTL_ENABLE` and `DDI_BUF_PORT_REVERSAL`.
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
const DDI_BUF_PORT_REVERSAL: u32 = 1 << 16;
/// `PIPECONF`/`TRANSCONF` of Pipes B-D.
const OTHER_PIPECONFS: [u64; 3] = [0x7_1008, 0x7_2008, 0x7_3008];

/// `DDI_PORT_WIDTH(lanes)` (`DDI_PORT_WIDTH_MASK` bits 3:1; three lanes
/// encode as 4). `DDI_BUF_PORT_DATA_10BIT` is 0 on display 14 (8b/10b).
const fn ddi_port_width(lanes: u8) -> u32 {
    let field = if lanes == 3 { 4 } else { lanes as u32 - 1 };
    field << 1
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
    /// The display IP the sequence is dispatched on (14.00 unless a
    /// per-device display-20 admission selected Xe2_LPD).
    ip: crate::intel_gpu_xe2lpd::DisplayIp,
    /// Panel fitting configuration: (source width, source height, scaling mode, filter)
    panel_fit: Option<(
        u16,
        u16,
        crate::intel_gpu_xelpg_scaler::ScalingMode,
        crate::intel_gpu_xelpg_scaler::Filter,
    )>,
    /// Bigjoiner slave pipe when two pipes are joined to drive one output.
    bigjoiner_slave: Option<crate::intel_gpu_pipes::Pipe>,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for XeLpgModeset<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XeLpgModeset")
            .field("port", &self.port)
            .field("panel_fit", &self.panel_fit)
            .field("bigjoiner_slave", &self.bigjoiner_slave)
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
            ip: crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp,
            panel_fit: None,
            bigjoiner_slave: None,
        }
    }

    /// Report Pipe A's DMC lifetime to `pipe_dmc` instead.
    pub fn with_pipe_dmc(mut self, pipe_dmc: &'a dyn crate::intel_gpu_dc_states::PipeDmc) -> Self {
        self.pipe_dmc = pipe_dmc;
        self
    }

    /// Dispatch the sequence on `ip` (display 20 only through
    /// [`crate::intel_gpu_xe2lpd`]'s admitted entry, display 30 only through
    /// [`crate::intel_gpu_xe3lpd`]'s, over its PICA register view).
    pub(crate) fn with_display_ip(mut self, ip: crate::intel_gpu_xe2lpd::DisplayIp) -> Self {
        self.ip = ip;
        self
    }

    /// Configure panel fitting with a custom source size, scaling mode, and filter.
    pub fn with_panel_fit(
        mut self,
        src_w: u16,
        src_h: u16,
        mode: crate::intel_gpu_xelpg_scaler::ScalingMode,
        filter: crate::intel_gpu_xelpg_scaler::Filter,
    ) -> Self {
        self.panel_fit = Some((src_w, src_h, mode, filter));
        self
    }

    /// Configure bigjoiner with a slave pipe.
    pub fn with_bigjoiner(mut self, slave: crate::intel_gpu_pipes::Pipe) -> Self {
        self.bigjoiner_slave = Some(slave);
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
        let (src_w, src_h) = self
            .panel_fit
            .map_or((mode.h_active, mode.v_active), |(w, h, _, _)| (w, h));
        crate::intel_gpu_modeset::validate_framebuffer_sized(primary_fb, src_w, src_h)?;
        inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?;
        // Nested under `modeset`'s reference when reached from there.
        let _power =
            crate::intel_gpu_dc_states::acquire(crate::intel_gpu_dc_states::DcUser::Modeset)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
        let checked = CheckedWindow {
            raw: self.mmio,
            failed: Cell::new(false),
        };
        let mut child = XeLpgModeset::new(&checked, self.port)
            .with_pipe_dmc(self.pipe_dmc)
            .with_display_ip(self.ip);
        if let Some((w, h, smode, sfilter)) = self.panel_fit {
            child = child.with_panel_fit(w, h, smode, sfilter);
        }
        if let Some(slave) = self.bigjoiner_slave {
            child = child.with_bigjoiner(slave);
        }
        let result = child.modeset_checked(primary_fb, mode);
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
        let scaler_plan = if let Some((src_w, src_h, smode, sfilter)) = self.panel_fit {
            crate::intel_gpu_xelpg_scaler::plan(
                &mode,
                u32::from(src_w),
                u32::from(src_h),
                smode,
                sfilter,
            )
            .map_err(|_| ModesetError::DisplayResourceUnavailable)?
            .map(|scaler| (src_w, src_h, scaler))
        } else {
            None
        };

        // Step 2: power wells — PW_1 (transcoder A / DDI A-B),
        // PW_A (pipe A), and this port's Xe-LPDP AUX power request
        // (`xelpdp_aux_power_well_enable`: XELPDP_DP_AUX_CH_CTL bit 19,
        // then a fixed 600 µs). Type-C routes never reach this inherited
        // path, so no TC port reference is required here.
        self.enable_power_well(PWR_WELL_CTL2, PW_1_IDX)?;
        self.enable_power_well(PWR_WELL_CTL2, PW_A_IDX)?;
        crate::intel_gpu_xelpg_tc::aux_power_enable(self.mmio, self.port)
            .map_err(|_| ModesetError::PowerWellTimeout)?;

        // A panel this driver turned off ([`Self::panel_off`]) lights with
        // the whole `mtl_ddi_pre_enable_dp`: its DDI, port PLL and PPS are
        // off. `intel_dp_aux_xfer` holds eDP VDD around AUX traffic, so the
        // planning reads below run with VDD forced on.
        let cold = self.cold_panel()?;
        let mut pps = cold.map(|_| {
            crate::intel_gpu_edp::PanelPowerSequencer::with_delays(
                self.mmio,
                crate::intel_gpu_edp::panel_delays(),
            )
        });
        if let Some(pps) = pps.as_mut() {
            pps.vdd_on().map_err(|_| ModesetError::PanelPowerTimeout)?;
        }

        // intel_edp_init_dpcd + intel_dp_compute_link_config: decide the
        // pipe bpp, the link and DSC before the first destructive write, so
        // a refusal leaves the panel as it was.
        // A refusal before the first destructive write drops the forced VDD.
        let plan = self.plan_edp(&mode).and_then(|plan| {
            // Beside another lit pipe no all-off transaction can run: the
            // layout must still hold Pipe A's share, as the panel-off
            // left it.
            if cold.is_some() && self.other_pipe_lit()? {
                crate::intel_gpu_display_resources::Profile::capture(self.mmio, &mode)
                    .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
            }
            Ok(plan)
        });
        let plan = match plan {
            Ok(plan) => plan,
            Err(error) => {
                if let Some(pps) = pps.as_mut() {
                    pps.vdd_off();
                }
                return Err(error);
            }
        };
        let dsc = match plan {
            EdpPlan::Dsc { plan, .. } => Some(plan),
            _ => None,
        };
        let pipe_bpp = match plan {
            EdpPlan::Link { link, .. } => link.pipe_bpp,
            _ => crate::intel_gpu_xelpg_dsc::PIPE_BPP,
        };
        // Display 20 and 30 share the DISPLAY_VER >= 20 branches.
        let xe2 = self.ip.xe2_plus();
        // Display 20 drops DSC when XE2LPD_DE_CAP fuses it out
        // (has_dsc = 0): a stream that needs compression has no config.
        if xe2 && dsc.is_some() {
            let cap = crate::intel_gpu_xe2lpd::DeCap::read(self.mmio)
                .map_err(|_| ModesetError::PipelineStopUnavailable)?;
            if cap.dsc_removed {
                if let Some(pps) = pps.as_mut() {
                    pps.vdd_off();
                }
                return Err(ModesetError::DisplayResourceUnavailable);
            }
        }
        // Display 30 always scans out through the VRR timing generator
        // (intel_vrr_always_use_vrr_tg): its fixed-refresh guardband
        // (intel_vrr_compute_guardband) is known before the first
        // destructive write, and a mode it cannot describe is refused.
        let guardband = if self.ip == crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd {
            let latency = crate::intel_gpu_xelpg_wm::Latency::read(self.mmio)
                .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
            Some(
                crate::intel_gpu_xe3lpd::vrr_guardband_for(
                    self.mmio,
                    &mode,
                    dsc.map(|plan| plan.term(&mode)),
                    &latency,
                )
                .map_err(|_| ModesetError::DisplayResourceUnavailable)?,
            )
        } else {
            None
        };

        if cold.is_none() {
            // This bounded correction preserves an already-enabled DDI. A
            // firmware-off or unqualified port is never stopped here; only
            // a panel this driver turned off takes the full enable.
            self.require_enabled_ddi()?;
            // Step 3: plane → the single pipe/transcoder CONF → PLL request.
            // This is not a full DDI/PHY/link retirement receipt. Pipe A is
            // dark from here: the owned profile no longer describes it, and
            // its pipe DMC is disabled last, as hsw_crtc_disable ends with
            // intel_dmc_disable_pipe after the port PLL.
            *OWNED_PANEL.lock() = None;
            self.disable_pipeline()?;
            self.pipe_dmc.disable_pipe(0);
        }
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
            if xe2 {
                crate::intel_gpu_xe2lpd::raise_cdclk_floor_ip(self.mmio, self.ip, floor)
                    .map_err(|_| ModesetError::PllLockTimeout)?;
            } else {
                program_cdclk_floor_khz(self.mmio, floor)?;
            }
        }
        // hsw_crtc_enable's first step, after the pre-plane update:
        // intel_dmc_enable_pipe. A later failure leaves it enabled until
        // the next disable, as Linux keeps it for the crtc's lifetime.
        self.pipe_dmc.enable_pipe(0);
        // mtl_ddi_pre_enable_dp step 4: intel_pps_on, before the port PLL.
        if let Some(pps) = pps.as_mut() {
            pps.power_on()
                .map_err(|_| ModesetError::PanelPowerTimeout)?;
        }

        // Step 5: enable the port PLL. The existing 8 bpc sequence takes
        // the rate this pixel clock needs (the same bandwidth rule the
        // Gen12 path picks its DPLL rate with) on four lanes; a 6 bpc or
        // rate-table panel takes Linux's computed link; a compressed eDP
        // stream runs at the plan's (maximum) link.
        let (mut link_khz, mut lanes) = match plan {
            EdpPlan::Legacy => (
                link_rate_for_pixel_clock(mode.pixel_clock_khz).megabits_per_sec() * 100,
                4,
            ),
            EdpPlan::Link { link, .. } => (link.link_rate, link.lanes),
            EdpPlan::Dsc { plan, .. } => {
                (dsc_link_rate(&plan)?.megabits_per_sec() * 100, plan.lanes)
            }
        };
        enable_port_pll_khz(self.mmio, self.port, link_khz, lanes, false).map_err(map_cx0_err)?;

        // Step 6: route the port clock to transcoder A.
        self.mmio
            .write32(TRANS_CLK_SEL_A, trans_clk_sel_port(self.port.phy_index()));
        compiler_fence(Ordering::SeqCst);

        // Step 7: transcoder timing + pipe source size (register
        // block shared with Gen12 — the shared codecs build them),
        // then bdw_set_pipe_misc.
        self.program_transcoder(&mode);
        if guardband.is_some() {
            // hsw_configure_cpu_transcoder: intel_vrr_set_transcoder_timings
            // follows intel_set_transcoder_timings.
            crate::intel_gpu_xe3lpd::program_vrr_timings(self.mmio, &mode)
                .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
        }
        // Non-Xe3 VRR timings for the mode this run commits (the Xe3
        // branch above programs its always-on TG instead).
        self.program_vrr_for_modeset(&mode)?;
        if let Some((src_w, src_h, ref scaler)) = scaler_plan {
            self.program_pipe_source(src_w, src_h);
            self.program_scaler(scaler);
        } else {
            self.disable_scaler();
            self.program_pipe(&mode);
        }
        let program_msa = self.program_pipe_misc(pipe_bpp, matches!(plan, EdpPlan::Link { .. }))?;

        // Step 8: bind transcoder A to this port (DP-SST at the pipe bpp).
        // A cold port configures it without ENABLE
        // (intel_ddi_config_transcoder_func); intel_ddi_enable sets it.
        if cold.is_some() {
            self.configure_trans_ddi_func(lanes, pipe_bpp);
        } else {
            self.program_trans_ddi_func_ctl(lanes, pipe_bpp);
        }
        if let Some(slave) = self.bigjoiner_slave {
            self.program_bigjoiner(crate::intel_gpu_pipes::Pipe::A, slave, true);
        }

        // Step 9: program the primary plane.
        if let Some((src_w, src_h, _)) = scaler_plan {
            self.program_plane_sized(primary_fb, src_w, src_h);
        } else {
            self.program_plane(primary_fb, &mode);
        }

        // Step 10: link-retrain preamble — D2D link up, port
        // buffer width, initial (zero) signal levels.
        if xe2 {
            // mtl_ddi_enable_d2d, display >= 20: DDI_BUF_CTL bits 29/28.
            crate::intel_gpu_xe2lpd::enable_d2d(self.mmio, self.ip, self.port)
                .map_err(|_| ModesetError::PllLockTimeout)?;
        } else {
            enable_d2d(self.mmio, self.port).map_err(map_cx0_err)?;
        }
        program_port_buf_ctl(self.mmio, self.port, lanes);
        let phy = Cx0Phy::new(self.mmio, self.port);
        set_signal_levels_khz(&phy, link_khz, lanes, &[(0, 0); 4]).map_err(map_cx0_err)?;

        // mtl_ddi_pre_enable_dp: intel_dp_set_power(D0), then
        // intel_dp_sink_enable_decompression, before training.
        if dsc.is_some() {
            self.sink_enable_decompression()?;
        }

        // Step 11: source pattern generator into TPS1 and run
        // DPCD link training over this port's AUX.
        self.program_dp_tp_ctl(DP_TP_CTL_LINK_TRAIN_PAT1);
        // mtl_ddi_prepare_link_retrain 6.i on a cold port: DDI_CTL_DE with
        // intel_ddi_init_dp_buf_reg's value, then the buffer active
        // (PORT_BUF_CTL1 PHY_IDLE clear), before the DPCD training.
        if let Some(off) = cold {
            self.mmio.write32(
                inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?,
                off.buf_ctl | ddi_port_width(lanes) | DDI_BUF_CTL_ENABLE,
            );
            compiler_fence(Ordering::SeqCst);
            crate::intel_gpu_xelpg::wait_port_buf_active(self.mmio, self.port)
                .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
        }
        let (trained_khz, trained_lanes, trained_levels) = match plan {
            EdpPlan::Dsc { plan, select } => {
                // The configuration was computed for the plan's link; a
                // fallback below it needs a new one (Linux's modeset retry).
                let trained = match select {
                    Some(index) => (
                        link_khz,
                        plan.lanes,
                        self.train_select(
                            RateSelect::Table {
                                index,
                                link_rate: plan.link_rate,
                            },
                            plan.lanes,
                        )?,
                    ),
                    None => {
                        let (rate, lanes, levels) =
                            self.train_dp_link_at(train_rate(&plan)?, plan.lanes)?;
                        (rate.megabits_per_sec() * 100, lanes, levels)
                    }
                };
                if trained.0 != link_khz || trained.1 != plan.lanes {
                    return Err(ModesetError::Dsc(DscRefusal::TrainingFallback));
                }
                trained
            }
            EdpPlan::Link { link, select, caps } => {
                self.train_planned_link(&mode, link, select, &caps, &mut link_khz, &mut lanes)?
            }
            EdpPlan::Legacy => {
                let (rate, lanes, levels) = self.train_dp_link()?;
                (rate.megabits_per_sec() * 100, lanes, levels)
            }
        };

        // Step 12: settle — if training converged below the PLL
        // rate (or on fewer lanes), re-target the PLL and the
        // width programming, then apply the trained levels.
        if trained_khz != link_khz {
            reprogram_pll_khz(self.mmio, self.port, trained_khz).map_err(map_cx0_err)?;
            link_khz = trained_khz;
        }
        if trained_lanes != lanes {
            program_port_buf_ctl(self.mmio, self.port, trained_lanes);
            if cold.is_some() {
                self.configure_trans_ddi_func(trained_lanes, pipe_bpp);
            } else {
                self.program_trans_ddi_func_ctl(trained_lanes, pipe_bpp);
            }
        }
        set_signal_levels_khz(&phy, link_khz, trained_lanes, &trained_levels)
            .map_err(map_cx0_err)?;
        // intel_ddi_set_dp_msa, at the end of intel_ddi_pre_enable_dp.
        if program_msa {
            self.program_msa(pipe_bpp);
        }
        match plan {
            EdpPlan::Legacy => self.program_mn_khz(&mode, link_khz, trained_lanes),
            EdpPlan::Link { .. } => {
                // intel_link_compute_m_n at the pipe bpp, no FEC.
                let m_n = crate::intel_gpu_xelpg_dsc::link_m_n(
                    pipe_bpp * 16,
                    u32::from(trained_lanes),
                    mode.pixel_clock_khz,
                    link_khz,
                    false,
                );
                crate::intel_gpu_xelpg_dsc::write_m_n(
                    self.mmio,
                    crate::intel_gpu_pipes::Transcoder::A,
                    &m_n,
                )
                .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
            }
            EdpPlan::Dsc { .. } => {}
        }

        // Step 13: pattern generator to normal data, then the
        // final enables in PRM order (transcoder → pipe → plane).
        self.program_dp_tp_ctl(DP_TP_CTL_LINK_TRAIN_NORMAL);
        if let Some(plan) = &dsc {
            self.enable_dsc(plan, &mode)?;
        } else if xe2 {
            // intel_enable_transcoder, display >= 14, for every transcoder
            // enable on display 20 (no DP_FEC_BS_JITTER_WA there).
            self.chicken_trans()?;
        }
        if let Some(guardband) = guardband {
            // intel_ddi_enable_dp: intel_vrr_transcoder_enable between
            // intel_ddi_enable_transcoder_func and intel_enable_transcoder.
            crate::intel_gpu_xe3lpd::tg_enable(self.mmio, guardband)
                .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
        }
        let frame = self.mmio.read32(0x70040);
        if frame == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        // intel_ddi_enable: the transcoder function, then the transcoder.
        if cold.is_some() {
            self.program_trans_ddi_func_ctl(trained_lanes, pipe_bpp);
        }
        self.enable_transcoder()?;
        // VRR enable, after the transcoder is live (non-Xe3 only).
        self.enable_vrr_for_modeset()?;
        let (plane_w, plane_h) = scaler_plan
            .as_ref()
            .map_or((mode.h_active, mode.v_active), |(w, h, _)| (*w, *h));
        self.observe_plane(primary_fb, plane_w, plane_h, trained_lanes, pipe_bpp, frame)?;
        let panel_active = owned.is_some() || cold.is_some_and(|off| off.mode == Some(mode));
        if xe2 && panel_active {
            // intel_program_dpkgc_latency after commit_modeset_enables:
            // Pipe A is the only active pipe of the owned layout.
            let timing = crate::intel_gpu_xelpg_wm::Timing {
                pixel_rate_khz: mode.pixel_clock_khz,
                htotal: u32::from(mode.h_total),
                vtotal: u32::from(mode.v_total),
                vblank_start: u32::from(mode.v_active),
            };
            let latency = crate::intel_gpu_xelpg_wm::Latency::read(self.mmio)
                .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
            let linetime = crate::intel_gpu_xelpg_wm::linetime(timing)
                .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
            let value = crate::intel_gpu_xe2lpd::pkgc_latency(&latency, &[linetime])
                .ok_or(ModesetError::DisplayResourceUnavailable)?;
            crate::intel_gpu_xe2lpd::program_pkgc_latency(self.mmio, value)
                .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
        }
        if panel_active {
            *OWNED_PANEL.lock() = Some(mode);
        }
        if let Some(pps) = pps.as_mut() {
            // The panel holds its own power now; VDD was only forced for
            // the AUX traffic (the delayed edp_panel_vdd_off in Linux).
            pps.vdd_off();
            *PANEL_OFF.lock() = None;
        }

        Ok(mode)
    }

    /// Read the panel's caps (`intel_edp_init_dpcd`), apply
    /// `intel_edp_fixup_vbt_bpp` from a lit eDP transcoder, and run
    /// `intel_dp_compute_link_config` for `mode` with the panel's EDID bpc
    /// ([`panel_display_bpc`]). A panel whose caps cannot be read takes the
    /// existing uncompressed path, as before this decision existed.
    fn plan_edp(&mut self, mode: &Mode) -> Result<EdpPlan, ModesetError> {
        use crate::intel_gpu_xelpg_dsc::EdpCaps;
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        let Ok(caps) = EdpCaps::read(&mut aux) else {
            return Ok(EdpPlan::Legacy);
        };
        if let Some(bpp) = self.lit_pipe_bpp() {
            crate::intel_gpu_xelpg_dsc::fixup_vbt_bpp(bpp);
        }
        decide_plan(&caps, mode, false)
    }

    /// `intel_ddi_read_func_ctl`'s `pipe_bpp` of transcoder A when it is
    /// enabled and selects this port (the lit eDP readout).
    fn lit_pipe_bpp(&self) -> Option<u32> {
        use crate::intel_gpu_pipes::{
            Transcoder, TRANS_DDI_FUNC_CTL_DDI_SHIFT, TRANS_DDI_FUNC_CTL_ENABLE,
            TRANS_DDI_FUNC_CTL_OFFSET,
        };
        let func = self
            .mmio
            .read32(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET);
        let port = (func >> TRANS_DDI_FUNC_CTL_DDI_SHIFT) & 0xf;
        if func == u32::MAX
            || func & TRANS_DDI_FUNC_CTL_ENABLE == 0
            || port != u32::from(self.port.func_ctl_index()) + 1
        {
            return None;
        }
        match (func >> 20) & 7 {
            0 => Some(24),
            1 => Some(30),
            2 => Some(18),
            3 => Some(36),
            _ => None,
        }
    }

    /// One training attempt at exactly `select` x `lanes` (no fallback
    /// ladder), with this port's AUX: the converged levels.
    fn train_select(&mut self, select: RateSelect, lanes: u8) -> Result<LaneLevels, ModesetError> {
        use crate::dp_link_training::{train_link_select, LinkError};
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        match train_link_select(&mut aux, select, lanes, |_us| core::hint::spin_loop()) {
            Ok(trained) => {
                let mut levels = [(0u8, 0u8); 4];
                for (i, lane) in trained.lanes.iter().enumerate() {
                    levels[i] = (lane.swing, lane.pre_emph);
                }
                Ok(levels)
            }
            Err(LinkError::CrFailed(_)) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::EqFailed(_)) => Err(ModesetError::LinkTrainingEq),
            Err(LinkError::Aborted) => Err(ModesetError::LinkTrainingCr),
            Err(LinkError::AuxFailure(e)) => Err(ModesetError::AuxFailure(e)),
        }
    }

    /// Train Linux's computed link (a 6 bpc pipe, or a panel with a rate
    /// table), with `DP_LINK_RATE_SET` when the panel publishes a table,
    /// and on failure walk Linux's fallback (Linux b90c984d
    /// `intel_dp_link_training.c::intel_dp_get_link_train_fallback_values`,
    /// each step the modeset retry's recomputed link): first eDP's
    /// `use_max_params`, then `reduce_link_params_in_rate_lane_order` from
    /// the failed link while the panel's mode at 18 bpp still fits, else
    /// one more attempt at the same parameters. The PHY PLL, its TX lanes,
    /// the port width and `TRANS_DDI_FUNC_CTL` move to each new link
    /// (`pll_khz` / `pll_lanes` follow). A step that would change the pipe
    /// bpp or need DSC refuses (`Dsc(TrainingFallback)`); a ladder with
    /// nothing left refuses `LinkTrainingExhausted`.
    fn train_planned_link(
        &mut self,
        mode: &Mode,
        link: crate::intel_gpu_xelpg_dsc::UncompressedLink,
        select: Option<u8>,
        caps: &crate::intel_gpu_xelpg_dsc::EdpCaps,
        pll_khz: &mut u32,
        pll_lanes: &mut u8,
    ) -> Result<(u32, u8, LaneLevels), ModesetError> {
        use crate::intel_gpu_xelpg_dsc::{installed_edp_vbt, EdpFallback, Fallback};
        let common = caps.limits(installed_edp_vbt().max_link_rate());
        let mut use_max_params = false;
        let mut cap = None;
        let mut same_retried = false;
        let (mut current, mut current_select) = (link, select);
        for _ in 0..LINK_FALLBACK_ATTEMPTS {
            match self.train_select(
                rate_select(current.link_rate, current_select)?,
                current.lanes,
            ) {
                Ok(levels) => return Ok((current.link_rate, current.lanes, levels)),
                Err(ModesetError::LinkTrainingCr | ModesetError::LinkTrainingEq) => {}
                Err(e) => return Err(e),
            }
            match common.fallback(
                current.link_rate,
                current.lanes,
                Some(EdpFallback {
                    use_max_params,
                    fixed_mode: *mode,
                }),
            ) {
                Fallback::MaxParams => use_max_params = true,
                Fallback::Reduce {
                    max_rate,
                    max_lanes,
                } => cap = Some((max_rate, max_lanes)),
                Fallback::Same if !same_retried => same_retried = true,
                Fallback::Same | Fallback::Exhausted => {
                    return Err(ModesetError::LinkTrainingExhausted);
                }
            }
            let EdpPlan::Link {
                link: retry,
                select: retry_select,
                ..
            } = decide_plan_capped(caps, mode, use_max_params, cap)?
            else {
                return Err(ModesetError::Dsc(DscRefusal::TrainingFallback));
            };
            if retry.pipe_bpp != link.pipe_bpp {
                return Err(ModesetError::Dsc(DscRefusal::TrainingFallback));
            }
            if retry.link_rate != *pll_khz {
                reprogram_pll_khz(self.mmio, self.port, retry.link_rate).map_err(map_cx0_err)?;
                *pll_khz = retry.link_rate;
            }
            if retry.lanes != *pll_lanes {
                crate::intel_gpu_xelpg::reprogram_phy_lanes(
                    self.mmio,
                    self.port,
                    retry.lanes,
                    false,
                )
                .map_err(map_cx0_err)?;
                program_port_buf_ctl(self.mmio, self.port, retry.lanes);
                self.program_trans_ddi_func_ctl(retry.lanes, retry.pipe_bpp);
                *pll_lanes = retry.lanes;
            }
            let phy = Cx0Phy::new(self.mmio, self.port);
            set_signal_levels_khz(&phy, retry.link_rate, retry.lanes, &[(0, 0); 4])
                .map_err(map_cx0_err)?;
            current = retry;
            current_select = retry_select;
        }
        Err(ModesetError::LinkTrainingExhausted)
    }

    /// `bdw_set_pipe_misc` for Pipe A at `pipe_bpp`. The Linux-link path
    /// (`always`) writes it. The existing 8 bpc sequences keep their write
    /// stream: they read `PIPE_MISC` and rewrite it (and later the MSA)
    /// only when it still carries a 6 bpc or dithered pipe, left by an
    /// earlier 6 bpc modeset or by firmware. Returns whether the MSA must
    /// be written after training.
    fn program_pipe_misc(&mut self, pipe_bpp: u32, always: bool) -> Result<bool, ModesetError> {
        use crate::intel_gpu_pipes::Pipe as PipeIdx;
        use crate::intel_gpu_xelpg_dsc::{pipe_misc, PIPE_MISC_OFFSET};
        let off = PipeIdx::A.base() + PIPE_MISC_OFFSET;
        if !always {
            let v = self.mmio.read32(off);
            if v == u32::MAX || !self.mmio.display_access_ok() {
                return Err(ModesetError::PipelineEnableUnavailable);
            }
            if v & PIPE_MISC_STALE_BPC == 0 {
                return Ok(false);
            }
        }
        self.mmio.write32(off, pipe_misc(pipe_bpp));
        compiler_fence(Ordering::SeqCst);
        Ok(true)
    }

    /// `intel_ddi_set_dp_msa` for transcoder A at `pipe_bpp`.
    fn program_msa(&mut self, pipe_bpp: u32) {
        use crate::intel_gpu_pipes::Transcoder;
        use crate::intel_gpu_xelpg_dsc::{msa_misc, TRANS_MSA_MISC_OFFSET};
        self.mmio.write32(
            Transcoder::A.base() + TRANS_MSA_MISC_OFFSET,
            msa_misc(pipe_bpp),
        );
        compiler_fence(Ordering::SeqCst);
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
        self.chicken_trans()
    }

    /// `intel_enable_transcoder`'s `CHICKEN_TRANS` bits for this IP: clear
    /// `DP_DSC_INSERT_SF_AT_EOL_WA`, set `DP_FEC_BS_JITTER_WA` on 14.00 only.
    fn chicken_trans(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::Transcoder;
        let chicken = Transcoder::A.base() + CHICKEN_TRANS_OFFSET;
        let v = self.mmio.read32(chicken);
        if v == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        let (clear, set) = match self.ip {
            crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp => {
                (DP_DSC_INSERT_SF_AT_EOL_WA, DP_FEC_BS_JITTER_WA)
            }
            ip => ip.chicken_trans(),
        };
        self.mmio.write32(chicken, (v & !clear) | set);
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
        // drm_add_display_info: the panel's bpc for every later decision.
        set_panel_display_bpc(crate::intel_gpu_xelpg_dsc::edid_display_bpc(&edid_buf));
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

    /// The panel-off record when this modeset relights a panel this driver
    /// turned off: the record names this port and Pipe A, transcoder A and
    /// the DDI read off. A record whose hardware is not off refuses before
    /// any write; without a record the existing enabled-DDI path runs.
    fn cold_panel(&self) -> Result<Option<PanelOff>, ModesetError> {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
        };
        let Some(off) = *PANEL_OFF.lock() else {
            return Ok(None);
        };
        if off.port != self.port {
            return Ok(None);
        }
        let ddi = self
            .mmio
            .read32(inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?);
        let conf = self.mmio.read32(PipeIdx::A.base() + PIPECONF_OFFSET);
        if ddi == u32::MAX || conf == u32::MAX || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineEnableUnavailable);
        }
        if ddi & DDI_BUF_CTL_ENABLE != 0 || conf & (PIPECONF_ENABLE | PIPECONF_STATE) != 0 {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        Ok(Some(off))
    }

    /// Whether any of Pipes B-D is enabled.
    fn other_pipe_lit(&self) -> Result<bool, ModesetError> {
        use crate::intel_gpu_pipes::{PIPECONF_ENABLE, PIPECONF_STATE};
        let mut lit = false;
        for reg in OTHER_PIPECONFS {
            let conf = self.mmio.read32(reg);
            if conf == u32::MAX || !self.mmio.display_access_ok() {
                return Err(ModesetError::PipelineEnableUnavailable);
            }
            lit |= conf & (PIPECONF_ENABLE | PIPECONF_STATE) != 0;
        }
        Ok(lit)
    }

    /// `intel_ddi_config_transcoder_func`: `TRANS_DDI_FUNC_CTL` with its
    /// port and mode but without `TRANS_DDI_FUNC_ENABLE`.
    fn configure_trans_ddi_func(&mut self, lanes: u8, pipe_bpp: u32) {
        use crate::intel_gpu_pipes::{
            Transcoder, TRANS_DDI_FUNC_CTL_ENABLE, TRANS_DDI_FUNC_CTL_OFFSET,
        };
        let val = dp_sst_func_ctl(self.port, lanes, pipe_bpp) & !TRANS_DDI_FUNC_CTL_ENABLE;
        self.mmio
            .write32(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET, val);
        compiler_fence(Ordering::SeqCst);
    }

    /// `intel_crtc_disable_planes` for Pipe A, the first step of the panel's
    /// crtc disable after the pre-plane update (PSR and FBC off): the
    /// primary and an enabled cursor go off, each armed by its surface
    /// register (`PLANE_SURF`, `CURBASE`).
    pub fn disable_planes(&mut self) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET,
            PLANE_SURF_OFFSET,
        };
        let _power =
            crate::intel_gpu_dc_states::acquire(crate::intel_gpu_dc_states::DcUser::Modeset)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
        let plane = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        let ctl = self.mmio.read32(plane + PLANE_CTL_OFFSET);
        let surf = self.mmio.read32(plane + PLANE_SURF_OFFSET);
        let cursor = self.mmio.read32(CUR_CTL_A);
        let base = self.mmio.read32(CUR_BASE_A);
        if [ctl, surf, cursor, base].contains(&u32::MAX) || !self.mmio.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.mmio
            .write32(plane + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE);
        self.mmio.write32(plane + PLANE_SURF_OFFSET, surf);
        if cursor & CUR_MODE_MASK != 0 {
            self.mmio.write32(CUR_CTL_A, cursor & !CUR_MODE_MASK);
            self.mmio.write32(CUR_BASE_A, base);
        }
        compiler_fence(Ordering::SeqCst);
        if !self.mmio.display_access_ok()
            || self.mmio.read32(plane + PLANE_CTL_OFFSET) & PLANE_CTL_ENABLE != 0
            || self.mmio.read32(CUR_CTL_A) & CUR_MODE_MASK != 0
        {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.disable_scaler();
        if let Some(slave) = self.bigjoiner_slave {
            self.program_bigjoiner(PipeIdx::A, slave, false);
        }
        Ok(())
    }

    /// The rest of the panel's crtc disable after [`Self::disable_planes`]
    /// and the caller's `intel_edp_backlight_off` (Linux b90c984d
    /// `intel_display.c::hsw_crtc_disable` and `intel_atomic_commit_tail`
    /// with the crtc inactive; `intel_ddi.c::intel_ddi_disable_dp`,
    /// `intel_ddi_post_disable_hdmi_or_sst`, `intel_ddi_post_disable_dp`,
    /// `intel_ddi_buf_disable`; `intel_pps.c::intel_pps_off_unlocked`):
    ///
    /// 1. the PPS backlight gate, if the caller's backlight owner left it
    ///    open, with its T9 wait; the sink's decompression off;
    /// 2. `intel_disable_transcoder`, `intel_ddi_disable_transcoder_func`
    ///    (`TRANS_DDI_FUNC_CTL2` 0; enable, port and mode cleared),
    ///    `intel_dsc_disable`;
    /// 3. the PPS SDP off, the sink to D3 (`DP_SET_POWER`, DPCD 1.1+,
    ///    best effort), `intel_ddi_buf_disable` (DDI_CTL_DE off, PHY idle,
    ///    D2D off, `DP_TP_CTL` off), `TRANS_CLK_SEL` off;
    /// 4. `intel_pps_vdd_on` + `intel_pps_off`, `intel_cx0pll_disable`, the
    ///    Thunderbolt IO deselect;
    /// 5. `intel_dmc_disable_pipe` (the pipe's display wakeref follows);
    /// 6. the post-plane update: with no other pipe lit, the all-off settle
    ///    (`settle_all_off`: WM/DDB, DBUF, CDCLK, PM demand). Beside a lit
    ///    pipe nothing shared is written: Pipe A's share stays programmed.
    ///
    /// Refused before any write unless Pipe A, transcoder A and this DDI are
    /// lit as the panel and the primary is off. The record is kept for the
    /// panel-on modeset ([`panel_off_record`]).
    pub fn panel_off(&mut self) -> Result<PanelOff, ModesetError> {
        let ddi_reg = inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?;
        if !self.port.is_edp() {
            return Err(ModesetError::UnsupportedGeneration);
        }
        let _power =
            crate::intel_gpu_dc_states::acquire(crate::intel_gpu_dc_states::DcUser::Modeset)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
        let checked = CheckedWindow {
            raw: self.mmio,
            failed: Cell::new(false),
        };
        let mut child = XeLpgModeset::new(&checked, self.port)
            .with_pipe_dmc(self.pipe_dmc)
            .with_display_ip(self.ip);
        if let Some((w, h, smode, sfilter)) = self.panel_fit {
            child = child.with_panel_fit(w, h, smode, sfilter);
        }
        if let Some(slave) = self.bigjoiner_slave {
            child = child.with_bigjoiner(slave);
        }
        let result = child.panel_off_checked(ddi_reg);
        if !checked.display_access_ok() {
            return Err(result
                .err()
                .unwrap_or(ModesetError::PipelineStopUnavailable));
        }
        result
    }

    fn panel_off_checked(&mut self, ddi_reg: u64) -> Result<PanelOff, ModesetError> {
        use crate::dp_aux::AuxChannel as _;
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
            PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, TRANS_DDI_FUNC_CTL_DDI_SHIFT,
            TRANS_DDI_FUNC_CTL_ENABLE, TRANS_DDI_FUNC_CTL_OFFSET,
        };
        let stop = ModesetError::PipelineStopUnavailable;
        let conf_reg = PipeIdx::A.base() + PIPECONF_OFFSET;
        let func_reg = Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        let conf = self.mmio.read32(conf_reg);
        let func = self.mmio.read32(func_reg);
        let ddi = self.mmio.read32(ddi_reg);
        let primary = self
            .mmio
            .read32(PipeIdx::A.base() + PLANE_PRIMARY_OFFSET + PLANE_CTL_OFFSET);
        if [conf, func, ddi, primary].contains(&u32::MAX)
            || !self.mmio.display_access_ok()
            || conf & (PIPECONF_ENABLE | PIPECONF_STATE) != PIPECONF_ENABLE | PIPECONF_STATE
            || func & TRANS_DDI_FUNC_CTL_ENABLE == 0
            || (func >> TRANS_DDI_FUNC_CTL_DDI_SHIFT) & 0xf
                != u32::from(self.port.func_ctl_index()) + 1
            || ddi & DDI_BUF_CTL_ENABLE == 0
            || primary & PLANE_CTL_ENABLE != 0
        {
            return Err(stop);
        }
        let mode = *OWNED_PANEL.lock();
        let mut pps = crate::intel_gpu_edp::PanelPowerSequencer::with_delays(
            self.mmio,
            crate::intel_gpu_edp::panel_delays(),
        );
        // intel_ddi_disable_dp: intel_edp_backlight_off's PPS half when no
        // backlight owner closed the gate (T9 follows), then
        // intel_dp_sink_disable_decompression (best effort, as in Linux).
        if pps.backlight_gate_open() {
            pps.backlight_off();
        }
        let compressed =
            crate::intel_gpu_xelpg_dsc::engines_enabled(self.mmio, PipeIdx::A).map_err(|_| stop)?;
        if compressed {
            let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
            let _ = crate::intel_gpu_xelpg_dsc::set_sink_decompression(&mut aux, false);
        }
        // intel_ddi_post_disable_hdmi_or_sst: the transcoder, its function,
        // then intel_dsc_disable.
        self.mmio.write32(conf_reg, conf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(
            self.mmio,
            conf_reg,
            PIPECONF_ENABLE | PIPECONF_STATE,
            false,
            100_000_000,
        ) {
            return Err(stop);
        }
        self.mmio
            .write32(Transcoder::A.base() + TRANS_DDI_FUNC_CTL2_OFFSET, 0);
        self.mmio.write32(
            func_reg,
            func & !(TRANS_DDI_FUNC_CTL_ENABLE | TRANS_DDI_PORT_AND_MODE),
        );
        compiler_fence(Ordering::SeqCst);
        self.disable_scaler();
        if let Some(slave) = self.bigjoiner_slave {
            self.program_bigjoiner(PipeIdx::A, slave, false);
        }
        crate::intel_gpu_xelpg_dsc::disable_engines(self.mmio, PipeIdx::A).map_err(|_| stop)?;
        // intel_ddi_post_disable_dp: intel_dp_set_infoframes(false) clears
        // the PPS SDP; intel_dp_set_power(D3) for a DPCD 1.1+ sink.
        crate::intel_gpu_xelpg_dsc::disable_pps_sdp(self.mmio, Transcoder::A).map_err(|_| stop)?;
        {
            let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
            let mut rev = [0u8];
            if aux.dpcd_read(0x000, &mut rev).is_ok() && rev[0] >= 0x11 {
                let _ =
                    aux.dpcd_write(crate::intel_gpu_xelpg_dsc::DP_SET_POWER, &[DP_SET_POWER_D3]);
            }
        }
        // intel_ddi_buf_disable (display 14): DDI_CTL_DE off, the buffer
        // idle, D2D off, DP_TP_CTL off.
        self.mmio.write32(ddi_reg, ddi & !DDI_BUF_CTL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        crate::intel_gpu_xelpg::wait_port_buf_idle(self.mmio, self.port).map_err(|_| stop)?;
        crate::intel_gpu_xelpg::disable_d2d(self.mmio, self.port).map_err(|_| stop)?;
        let tp_reg = Transcoder::A.base() + DP_TP_CTL_OFFSET;
        let tp = self.mmio.read32(tp_reg);
        self.mmio.write32(tp_reg, tp & !DP_TP_CTL_ENABLE);
        // intel_ddi_disable_transcoder_clock: TGL_TRANS_CLK_SEL_DISABLED.
        self.mmio.write32(TRANS_CLK_SEL_A, 0);
        compiler_fence(Ordering::SeqCst);
        // intel_pps_vdd_on + intel_pps_off.
        pps.vdd_on_then_off()
            .map_err(|_| ModesetError::PanelPowerTimeout)?;
        // intel_ddi_disable_clock (intel_cx0pll_disable), then the
        // Thunderbolt IO deselect.
        crate::intel_gpu_xelpg::disable_port_pll_complete(self.mmio, self.port)
            .map_err(map_cx0_err)?;
        let buf = self.mmio.read32(self.port.buf_ctl1());
        self.mmio.write32(
            self.port.buf_ctl1(),
            buf & !crate::intel_gpu_xelpg::PORT_BUF_IO_SELECT_TBT,
        );
        compiler_fence(Ordering::SeqCst);
        if self.mmio.read32(ddi_reg) & DDI_BUF_CTL_ENABLE != 0
            || self.mmio.read32(self.port.buf_ctl1()) & crate::intel_gpu_xelpg::PORT_BUF_PHY_IDLE
                == 0
            || self.mmio.read32(self.port.port_clock_ctl()) & 0xcc00_0000 != 0
            || !self.mmio.display_access_ok()
        {
            return Err(stop);
        }
        // hsw_crtc_disable's last step; the crtc's power domains (its
        // display wakeref) are released after it.
        *OWNED_PANEL.lock() = None;
        self.pipe_dmc.disable_pipe(0);
        // The post-plane update: the all-off settle when every pipe is off.
        // Best effort; a refusal leaves the clocks and demand raised.
        let others_lit = OTHER_PIPECONFS
            .iter()
            .any(|reg| self.mmio.read32(*reg) & (PIPECONF_ENABLE | PIPECONF_STATE) != 0);
        let settled = !others_lit
            && crate::intel_gpu_xelpg_wm::Latency::read(self.mmio).is_ok_and(|latency| {
                crate::intel_gpu_xelpg_resources::settle_all_off(self.mmio, &latency).is_ok()
            });
        let record = PanelOff {
            port: self.port,
            mode,
            buf_ctl: ddi & DDI_BUF_PORT_REVERSAL,
            settled,
        };
        *PANEL_OFF.lock() = Some(record);
        Ok(record)
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
        // VRR off before the transcoder stops (non-Xe3 only; the
        // display-30 TG stops after the transcoder below).
        self.disable_vrr_for_modeset();
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
        // intel_ddi_post_disable_hdmi_or_sst, display 30: the always-used
        // VRR timing generator stops after the transcoder.
        if self.ip == crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd {
            crate::intel_gpu_xe3lpd::tg_disable(self.mmio)
                .map_err(|_| ModesetError::PipelineStopUnavailable)?;
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
        self.disable_scaler();
        if let Some(slave) = self.bigjoiner_slave {
            self.program_bigjoiner(PipeIdx::A, slave, false);
        }
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
        let xe3 = self.ip == crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd;
        if xe3 {
            // intel_set_transcoder_timings, display >= 13: the set-context
            // latency first — the VRR-TG value (1 while the TG runs on
            // CRTC 1, 0 otherwise; wa_14015401596 floor), which the
            // display-30 VRR guardband assumes.
            self.mmio.write32(
                crate::intel_gpu_xe3lpd::TRANS_SET_CONTEXT_LATENCY_A,
                crate::intel_gpu_vrr::set_context_latency_for_crtc(1),
            );
        }
        self.mmio.write32(base + TRANS_HTOTAL_OFFSET, prog.htotal);
        self.mmio.write32(base + TRANS_HBLANK_OFFSET, prog.hblank);
        self.mmio.write32(base + TRANS_HSYNC_OFFSET, prog.hsync);
        let vtotal = if xe3 {
            crate::intel_gpu_xe3lpd::trans_vtotal(mode)
        } else {
            prog.vtotal
        };
        self.mmio.write32(base + TRANS_VTOTAL_OFFSET, vtotal);
        // Display 13+ clears VBLANK_START (intel_set_transcoder_timings).
        self.mmio
            .write32(base + TRANS_VBLANK_OFFSET, prog.vblank_display13());
        self.mmio.write32(base + TRANS_VSYNC_OFFSET, prog.vsync);
        if xe3 {
            // DP_MIN_HBLANK_CTL = min_hblank: intel_dp_compute_min_hblank
            // gives 0 for an 8b/10b SST stream.
            self.mmio
                .write32(crate::intel_gpu_xe3lpd::DP_MIN_HBLANK_CTL_A, 0);
        }
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

    /// Program custom pipe source dimensions (e.g. for panel fitting) into `PIPE_SRCSZ`.
    pub(crate) fn program_pipe_source(&mut self, src_w: u16, src_h: u16) {
        use crate::intel_gpu_pipes::{Pipe as PipeIdx, PIPE_SRCSZ_OFFSET};
        let srcsz = (((src_w.saturating_sub(1)) as u32) << 16) | ((src_h.saturating_sub(1)) as u32);
        self.mmio
            .write32(PipeIdx::A.trans_base() + PIPE_SRCSZ_OFFSET, srcsz);
        compiler_fence(Ordering::SeqCst);
    }

    /// Program panel-fitting scaler registers for Pipe A.
    pub(crate) fn program_scaler(&mut self, scaler: &crate::intel_gpu_xelpg_scaler::PipeScaler) {
        use crate::intel_gpu_pipes::Pipe as PipeIdx;
        for (reg, val) in scaler.enable_writes(PipeIdx::A) {
            self.mmio.write32(reg, val);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Disable and detach scalers on Pipe A.
    pub(crate) fn disable_scaler(&mut self) {
        use crate::intel_gpu_pipes::Pipe as PipeIdx;
        for (reg, val) in crate::intel_gpu_xelpg_scaler::disable_writes(PipeIdx::A) {
            self.mmio.write32(reg, val);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Program DSS_CTL joiner registers when joining master and slave pipes.
    pub(crate) fn program_bigjoiner(
        &mut self,
        master: crate::intel_gpu_pipes::Pipe,
        slave: crate::intel_gpu_pipes::Pipe,
        enable: bool,
    ) {
        use crate::intel_gpu_xelpg_dsc::{dss_ctl1, JOINER_ENABLE};
        const SECONDARY_BIG_JOINER_ENABLE: u32 = 1 << 29;
        if enable {
            self.mmio.write32(dss_ctl1(master), JOINER_ENABLE);
            self.mmio
                .write32(dss_ctl1(slave), SECONDARY_BIG_JOINER_ENABLE);
        } else {
            self.mmio.write32(dss_ctl1(master), 0);
            self.mmio.write32(dss_ctl1(slave), 0);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// `TRANS_DDI_FUNC_CTL` for DP SST on this port at `lanes`, with the
    /// pipe's BPC field (`TRANS_DDI_BPC_8` is 0).
    fn program_trans_ddi_func_ctl(&mut self, lanes: u8, pipe_bpp: u32) {
        use crate::intel_gpu_pipes::{Transcoder, TRANS_DDI_FUNC_CTL_OFFSET};
        let val = dp_sst_func_ctl(self.port, lanes, pipe_bpp);
        self.mmio
            .write32(Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET, val);
        compiler_fence(Ordering::SeqCst);
    }

    /// The existing 8 bpc M/N (`dp_mn` at three bytes per pixel) for a
    /// link symbol clock of `link_khz`.
    pub(crate) fn program_mn_khz(&mut self, mode: &Mode, link_khz: u32, lanes: u8) {
        use crate::intel_gpu_pipes::{
            dp_mn, Transcoder, PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET,
            PIPE_LINK_N1_OFFSET,
        };
        let (dm, dn, lm, ln) = dp_mn(mode.pixel_clock_khz, link_khz, lanes as u32, 3);
        let base = Transcoder::A.base();
        self.mmio.write32(base + PIPE_DATA_M1_OFFSET, dm);
        self.mmio.write32(base + PIPE_DATA_N1_OFFSET, dn);
        self.mmio.write32(base + PIPE_LINK_M1_OFFSET, lm);
        // LINK_N last: it triggers the hardware update.
        self.mmio.write32(base + PIPE_LINK_N1_OFFSET, ln);
        compiler_fence(Ordering::SeqCst);
    }

    pub(crate) fn program_plane_sized(&mut self, fb: &Framebuffer, w: u16, h: u16) {
        use crate::intel_gpu_pipes::{
            build_primary_plane, Pipe as PipeIdx, PixelFormat as PipeFmt, PLANE_CTL_OFFSET,
            PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET,
            PLANE_SURF_OFFSET,
        };
        let pipe_fmt = match fb.format {
            PixelFormat::Xrgb8888 => PipeFmt::Argb8888,
        };
        let prog = match build_primary_plane(w, h, fb.stride_bytes, fb.phys_addr as u32, pipe_fmt) {
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

    pub(crate) fn program_plane(&mut self, fb: &Framebuffer, mode: &Mode) {
        self.program_plane_sized(fb, mode.h_active, mode.v_active);
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

    /// The VRR IP for this run's display IP (MTL/ARL 14.00, LNL
    /// 20.00). Display 30 (PTL) is `None`: its always-on VRR timing
    /// generator is owned by `intel_gpu_xe3lpd`, not the generic VRR
    /// path — the generic hooks below must never run on it.
    fn vrr_ip(&self) -> Option<crate::intel_gpu_vrr::DisplayVrrIp> {
        match self.ip {
            crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp => {
                Some(crate::intel_gpu_vrr::DisplayVrrIp::Display14)
            }
            crate::intel_gpu_xe2lpd::DisplayIp::Xe2Lpd => {
                Some(crate::intel_gpu_vrr::DisplayVrrIp::Display20)
            }
            crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd => None,
        }
    }

    /// Program this run's VRR timings for the mode being committed
    /// (`intel_vrr_set_transcoder_timings` follows
    /// `intel_set_transcoder_timings`). Same recompute-first shape as
    /// the Gen12 orchestrator's `program_vrr_for_modeset`: the stored
    /// timings describe the previous mode, never this one. Skipped
    /// entirely on display 30 (always-on TG owned by `intel_gpu_xe3lpd`).
    fn program_vrr_for_modeset(&mut self, mode: &Mode) -> Result<(), ModesetError> {
        let Some(ip) = self.vrr_ip() else {
            return Ok(());
        };
        // This orchestrator drives Pipe A / CRTC 1 only.
        let crtc = 1;
        // CMRR auto-enable is eDP-only: Port A is the built-in panel, so
        // it maps to EmbeddedDisplayPort; every other port conservatively
        // maps to Other (no auto-enable). This must agree with the
        // post-modeset recompute in `modeset_display_family` for the
        // same CRTC, or the auto-enable state would flap between the two.
        let kind = match self.port {
            XeLpgPort::A => crate::intel_gpu_vrr::VrrConnectorKind::EmbeddedDisplayPort,
            _ => crate::intel_gpu_vrr::VrrConnectorKind::Other,
        };
        let timings = crate::intel_gpu_vrr::recompute_timings_for_modeset(
            crtc,
            mode,
            crate::intel_gpu_vrr::VRR_STATE.range(crtc),
            ip,
            crate::intel_gpu_vrr::VrrComputeOpts::default(),
            kind,
        );
        if crate::intel_gpu_vrr::VRR_STATE.is_enabled(crtc) {
            if let Some(timings) = timings {
                let trans = crate::intel_gpu_vrr::VrrTranscoder::A;
                crate::intel_gpu_vrr::program_vrr_timings(self.mmio, trans, ip, &timings)
                    .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
            }
        }
        Ok(())
    }

    /// Enable VRR after the transcoder is live (`intel_vrr_enable`
    /// runs after `intel_enable_transcoder` in Linux's
    /// `intel_crtc_enable`). Only when VRR is requested and timings
    /// were programmed for this run. Skipped on display 30.
    fn enable_vrr_for_modeset(&mut self) -> Result<(), ModesetError> {
        let Some(ip) = self.vrr_ip() else {
            return Ok(());
        };
        let crtc = 1;
        if crate::intel_gpu_vrr::VRR_STATE.is_enabled(crtc) {
            if let Some(timings) = crate::intel_gpu_vrr::VRR_STATE.timings(crtc) {
                crate::intel_gpu_vrr::vrr_enable(
                    self.mmio,
                    crate::intel_gpu_vrr::VrrTranscoder::A,
                    ip,
                    timings.guardband,
                )
                .map_err(|_| ModesetError::PipelineEnableUnavailable)?;
            }
        }
        Ok(())
    }

    /// Disable VRR before the transcoder stops (`intel_vrr_disable`
    /// runs before the transcoder disable in Linux's
    /// `intel_crtc_disable`). Best effort: the pipeline is being torn
    /// down regardless (see the Gen12 orchestrator's
    /// `disable_vrr_for_modeset`). Skipped on display 30, whose TG
    /// stops after the transcoder below.
    fn disable_vrr_for_modeset(&mut self) {
        if let Some(ip) = self.vrr_ip() {
            let _ = crate::intel_gpu_vrr::vrr_disable(
                self.mmio,
                crate::intel_gpu_vrr::VrrTranscoder::A,
                ip,
            );
        }
    }

    /// A fresh common frame, current source enable and the actual primary
    /// shadow/LIVE image replace the old unconditional 20ms delay. This is
    /// bounded software evidence, not sink training/visible-pixel acceptance
    /// or permission to reclaim an older scanout allocation.
    fn observe_plane(
        &self,
        fb: &Framebuffer,
        w: u16,
        h: u16,
        lanes: u8,
        pipe_bpp: u32,
        start: u32,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_pipes::{build_primary_plane, PixelFormat as PipeFmt};
        let plane = build_primary_plane(
            w,
            h,
            fb.stride_bytes,
            fb.phys_addr as u32,
            PipeFmt::Argb8888,
        )
        .map_err(|_| ModesetError::InvalidFramebuffer)?;
        let ddi_reg = inherited_ddi_ctl(self.port).ok_or(ModesetError::UnsupportedGeneration)?;
        let route = dp_sst_func_ctl(self.port, lanes, pipe_bpp);
        // Display 20 keeps the D2D link in DDI_BUF_CTL (enable and state).
        let d2d_up = crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE
            | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_STATE;
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
                        && (self.ip == crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp
                            || ddi & d2d_up == d2d_up)
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
    train_rate_of(plan.link_rate)
}

/// The `DP_LINK_BW_SET` rate of a standard link rate (Linux link units).
fn train_rate_of(link_rate: u32) -> Result<crate::dp_link_training::LinkRate, ModesetError> {
    use crate::dp_link_training::LinkRate as TrainRate;
    match link_rate {
        162_000 => Ok(TrainRate::Rbr),
        270_000 => Ok(TrainRate::Hbr),
        540_000 => Ok(TrainRate::Hbr2),
        810_000 => Ok(TrainRate::Hbr3),
        _ => Err(ModesetError::Dsc(DscRefusal::LinkRateUnqualified)),
    }
}

/// `intel_dp_compute_rate`: `DP_LINK_RATE_SET` at `select` for a panel
/// with a rate table, `DP_LINK_BW_SET` otherwise.
fn rate_select(link_rate: u32, select: Option<u8>) -> Result<RateSelect, ModesetError> {
    match select {
        Some(index) => Ok(RateSelect::Table { index, link_rate }),
        None => Ok(RateSelect::LinkBw(train_rate_of(link_rate)?)),
    }
}

/// `TRANS_DDI_FUNC_CTL` for DP SST on `port` at `lanes` and `pipe_bpp`.
fn dp_sst_func_ctl(port: XeLpgPort, lanes: u8, pipe_bpp: u32) -> u32 {
    use crate::intel_gpu_pipes::{build_trans_ddi_func_ctl, TRANS_DDI_MODE_DP_SST};
    build_trans_ddi_func_ctl(port.func_ctl_index(), TRANS_DDI_MODE_DP_SST, lanes)
        | crate::intel_gpu_xelpg_dsc::trans_ddi_bpc(pipe_bpp)
}

/// `PIPE_MISC`'s BPC field and dither enable: a pipe other than an
/// undithered 8 bpc one.
const PIPE_MISC_STALE_BPC: u32 = (7 << 5) | (1 << 4);

/// How the Pipe A modeset drives the panel's link.
#[derive(Clone, Copy, Debug, PartialEq)]
enum EdpPlan {
    /// The existing uncompressed 8 bpc sequence (24 bpp fits, no rate
    /// table): the pixel-clock rate rule on four lanes, `DP_LINK_BW_SET`
    /// and the training ladder, byte for byte as before.
    Legacy,
    /// Linux's computed uncompressed link: a 6 bpc pipe, or a panel
    /// trained with `DP_LINK_RATE_SET` (`select`, its table index).
    Link {
        link: crate::intel_gpu_xelpg_dsc::UncompressedLink,
        select: Option<u8>,
        caps: crate::intel_gpu_xelpg_dsc::EdpCaps,
    },
    /// Compress with `plan` (`select` as for [`EdpPlan::Link`]).
    Dsc { plan: DscPlan, select: Option<u8> },
}

/// The bound on one modeset's training attempts: the eDP retry at maximum
/// parameters, one same-parameter retry, and a step for every lower rate
/// and lane count the ladder can reach.
const LINK_FALLBACK_ATTEMPTS: usize = 24;

/// `intel_dp_compute_link_config` for the panel, with `use_max_params`
/// forced by `use_max` (the retry after a failed training), mapped onto
/// the modeset's sequences.
fn decide_plan(
    caps: &crate::intel_gpu_xelpg_dsc::EdpCaps,
    mode: &Mode,
    use_max: bool,
) -> Result<EdpPlan, ModesetError> {
    decide_plan_capped(caps, mode, use_max, None)
}

/// [`decide_plan`] under a training fallback's `link.max_rate` and
/// `link.max_lane_count`.
fn decide_plan_capped(
    caps: &crate::intel_gpu_xelpg_dsc::EdpCaps,
    mode: &Mode,
    use_max: bool,
    cap: Option<(u32, u8)>,
) -> Result<EdpPlan, ModesetError> {
    use crate::intel_gpu_xelpg_dsc::{
        decide_edp_capped, installed_edp_vbt, LinkDecision, PIPE_BPP,
    };
    let decision = decide_edp_capped(
        caps,
        &installed_edp_vbt(),
        panel_display_bpc(),
        mode,
        use_max,
        cap,
    )
    .map_err(ModesetError::Dsc)?;
    let select = |rate: u32| -> Result<Option<u8>, ModesetError> {
        if !caps.has_rate_table() {
            return Ok(None);
        }
        caps.rate_select(rate)
            .map(Some)
            .ok_or(ModesetError::Dsc(DscRefusal::LinkRateUnqualified))
    };
    Ok(match decision {
        LinkDecision::Uncompressed(link)
            if link.pipe_bpp == PIPE_BPP && !caps.has_rate_table() && !use_max =>
        {
            EdpPlan::Legacy
        }
        LinkDecision::Uncompressed(link) => EdpPlan::Link {
            link,
            select: select(link.link_rate)?,
            caps: *caps,
        },
        LinkDecision::Dsc(plan) => EdpPlan::Dsc {
            select: select(plan.link_rate)?,
            plan,
        },
    })
}

/// The internal panel's `display_info.bpc`
/// ([`crate::intel_gpu_xelpg_dsc::edid_display_bpc`]) from the last EDID
/// the Pipe A modeset read; 0 (undefined) until one was read, as Linux's
/// eDP connector without an EDID.
static PANEL_DISPLAY_BPC: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The internal panel's cached `display_info.bpc`.
pub fn panel_display_bpc() -> u8 {
    PANEL_DISPLAY_BPC.load(Ordering::Relaxed)
}

/// Replace the internal panel's cached `display_info.bpc` (the EDID read,
/// and fixtures restoring it).
pub fn set_panel_display_bpc(bpc: u8) {
    PANEL_DISPLAY_BPC.store(bpc, Ordering::Relaxed);
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
        /// The sink refuses clock recovery while `DP_LINK_BW_SET` holds
        /// this code (0: never).
        pub cr_fails_at: Cell<u8>,
        refuse_color: Cell<u64>,
        /// Every native DPCD write byte with the register-write count at
        /// its arrival: (address, value, writes so far).
        pub dpcd_writes: RefCell<Vec<(usize, u8, usize)>>,
        /// When set, `PP_STATUS` follows `PP_CONTROL`: on-idle while the
        /// power target or VDD force is set, off-idle otherwise.
        pub pps: Cell<bool>,
        /// The sink refuses clock recovery at every link.
        pub cr_fails_all: Cell<bool>,
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
            // A valid eDP 1.3 receiver: DPCD 1.2, HBR2, four lanes with
            // enhanced framing (the all-zero DPCD is invalid: Linux would
            // fall back to RBR x1, `intel_dp_set_sink_rates`).
            let mut dpcd = [0u8; 0x1000];
            dpcd[..3].copy_from_slice(&[0x12, 0x14, 0x84]);
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
                dpcd: RefCell::new(dpcd),
                hbr2_cr_fails: Cell::new(false),
                cr_fails_at: Cell::new(0),
                refuse_color: Cell::new(u64::MAX),
                dpcd_writes: RefCell::new(Vec::new()),
                pps: Cell::new(false),
                cr_fails_all: Cell::new(false),
            }
        }

        /// Model what a full panel off/on observes: `PP_STATUS` following
        /// `PP_CONTROL`, `PHY_IDLE` following DDI_CTL_DE and the D2D link
        /// state following its enable.
        pub fn model_panel_power(&self) {
            self.pps.set(true);
            self.phy.model_ddi_idle.set(true);
            self.phy.model_d2d.set(true);
        }

        /// The index of the first write at or after `from` matching `f`.
        pub fn write_index(&self, from: usize, f: impl Fn(u64, u32) -> bool) -> Option<usize> {
            self.writes
                .borrow()
                .iter()
                .enumerate()
                .skip(from)
                .find(|(_, (o, v))| f(*o, *v))
                .map(|(i, _)| i)
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
                    let bw = self.dpcd.borrow()[0x100];
                    if self.cr_fails_all.get()
                        || (self.hbr2_cr_fails.get() && bw == 0x14)
                        || (self.cr_fails_at.get() != 0 && bw == self.cr_fails_at.get())
                    {
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
            if self.pps.get() && off == crate::intel_gpu_edp::PP_STATUS {
                let control = self.phy.read32(crate::intel_gpu_edp::PP_CONTROL);
                return if control & 1 != 0 { 0x8000_0008 } else { 0 };
            }
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
        use crate::intel_gpu_xelpg_dsc::{decide_edp, DscDpcd, EdpCaps, EdpVbt, LinkDecision};
        let mut receiver = [0u8; 16];
        receiver[..3].copy_from_slice(&[0x14, 0x14, 0x82]);
        let caps = EdpCaps {
            receiver,
            edp_rev: 0x05,
            link_rates: [0; 8],
            dsc: DscDpcd(OLED_DSC),
        };
        match decide_edp(&caps, &EdpVbt::Missing, 0, &oled_mode(), false) {
            Ok(LinkDecision::Dsc(plan)) => plan,
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
            // The VBT's 18 bpp (no EDID bpc) caps the DSC input too: its
            // 8 bpc minimum leaves no pipe bpp range (Linux's
            // intel_dp_dsc_compute_pipe_bpp_limits).
            (
                run(
                    0x14,
                    2,
                    EdpVbt::Panel {
                        dsc_disable: false,
                        max_link_rate: 0,
                        bpp: 18,
                    },
                ),
                Err(ModesetError::Dsc(DscRefusal::NoBppRange)),
            ),
            (
                run(
                    0x14,
                    2,
                    EdpVbt::Panel {
                        dsc_disable: true,
                        max_link_rate: 0,
                        bpp: 0,
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

    /// An eDP panel's receiver caps and eDP revision on `fake`.
    fn edp_panel(fake: &MtlFake, rate: u8, lanes: u8, edp_rev: u8) {
        let mut dpcd = fake.dpcd.borrow_mut();
        dpcd[..3].copy_from_slice(&[0x14, rate, 0x80 | lanes]);
        dpcd[0x700] = edp_rev;
    }

    /// `TRANS_DDI_FUNC_CTL` A for DP SST on DDI A with `bpc` bits.
    fn func_a(lanes: u8, bpc: u32) -> u32 {
        crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
            XeLpgPort::A.func_ctl_index(),
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
            lanes,
        ) | bpc
    }

    /// Run the fixed modeset with `vbt` installed and the panel's EDID bpc
    /// at `bpc`, restoring both.
    fn run_with(
        fake: &MtlFake,
        mode: &Mode,
        vbt: crate::intel_gpu_xelpg_dsc::EdpVbt,
        bpc: u8,
    ) -> Result<Mode, ModesetError> {
        use crate::intel_gpu_xelpg_dsc::{install_edp_vbt, installed_edp_vbt};
        let previous = installed_edp_vbt();
        let previous_bpc = panel_display_bpc();
        install_edp_vbt(vbt);
        set_panel_display_bpc(bpc);
        let result = XeLpgModeset::new(fake, XeLpgPort::A).modeset_fixed(&test_fb(), mode);
        set_panel_display_bpc(previous_bpc);
        install_edp_vbt(previous);
        result
    }

    fn smoke_mtl_edp_six_bpc_programs_pipe_misc_ddi_msa_and_mn() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::{link_m_n, EdpVbt};
        // An eDP 1.4 panel without a rate table on one RBR lane: 1024x768@60
        // needs 195000 kBps at 24 bpp and 146250 at 18; the lane carries
        // 162000. Linux drives 6 bpc (intel_dp_compute_link_config_wide).
        let fake = MtlFake::new(XeLpgPort::A);
        edp_panel(&fake, 0x06, 1, 0x03);
        let mode = Mode::VESA_1024X768_60;
        if run_with(&fake, &mode, EdpVbt::Missing, 0) != Ok(mode) {
            return TestResult::Fail("the 6 bpc eDP modeset must complete");
        }
        // The PLL at RBR; TRANS_DDI_FUNC_CTL one lane with BPC_6.
        if fake.writes_to(0x6_4030) != [162_000] || fake.writes_to(0x6_0400) != [func_a(1, 2 << 20)]
        {
            return TestResult::Fail("the link must be RBR x1 with TRANS_DDI BPC_6");
        }
        // bdw_set_pipe_misc: BPC_6 | DITHER_ENABLE | TRUNC; the MSA's
        // SYNC_CLOCK with 6 bpc; intel_link_compute_m_n at 18 bpp, TU 64.
        let mn = link_m_n(18 * 16, 1, mode.pixel_clock_khz, 162_000, false);
        if fake.writes_to(0x7_0030) != [0x150]
            || fake.writes_to(0x6_0410) != [0x01]
            || fake.writes_to(0x6_0030) != [mn[0]]
            || fake.writes_to(0x6_0034) != [mn[1]]
            || fake.writes_to(0x6_0040) != [mn[2]]
            || fake.writes_to(0x6_0044) != [mn[3]]
            || mn[0] >> 25 != 63
        {
            return TestResult::Fail("PIPE_MISC, the MSA and M/N must carry 6 bpc");
        }
        // DP_LINK_BW_SET (no rate table), never DP_LINK_RATE_SET.
        let dpcd = fake.dpcd_writes.borrow().clone();
        if !dpcd.iter().any(|&(a, v, _)| a == 0x100 && v == 0x06)
            || !dpcd.iter().any(|&(a, v, _)| a == 0x101 && v == 0x81)
            || dpcd.iter().any(|&(a, _, _)| a == 0x115)
        {
            return TestResult::Fail("a panel without a table trains with DP_LINK_BW_SET");
        }
        // PIPE_MISC follows PIPE_SRCSZ; the MSA follows training (the sink's
        // pattern off) and precedes the transcoder enable.
        let writes = fake.writes.borrow().clone();
        let pos =
            |r: u64, f: &dyn Fn(u32) -> bool| writes.iter().position(|&(o, v)| o == r && f(v));
        let trained = dpcd
            .iter()
            .rfind(|&&(a, v, _)| a == 0x102 && v == 0)
            .map(|&(_, _, at)| at);
        match (
            pos(0x6_001c, &|_| true),
            pos(0x7_0030, &|_| true),
            trained,
            pos(0x6_0410, &|_| true),
            pos(PIPECONF_OFF, &|v| v & (1 << 31) != 0),
        ) {
            (Some(src), Some(misc), Some(t), Some(msa), Some(on))
                if src < misc && t <= msa && msa < on => {}
            _ => return TestResult::Fail("the 6 bpc steps must follow hsw_crtc_enable"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_six_bpc_programs_pipe_misc_ddi_msa_and_mn
    );

    fn smoke_mtl_edp_rate_table_trains_with_link_rate_set() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::{link_m_n, EdpVbt};
        // An eDP 1.4 panel with DP_MAX_LINK_RATE 0 and the table 1.62, 2.16,
        // 2.43, 2.7 Gbps on two lanes. A 140 MHz 1024x768 needs 420000 kBps
        // at 24 bpp: 2.16 Gbps x2 (432000), the table's index 1.
        let fake = MtlFake::new(XeLpgPort::A);
        edp_panel(&fake, 0x00, 2, 0x03);
        fake.dpcd.borrow_mut()[0x10..0x18]
            .copy_from_slice(&[0xa4, 0x1f, 0x30, 0x2a, 0x76, 0x2f, 0xbc, 0x34]);
        let mode = Mode {
            pixel_clock_khz: 140_000,
            ..Mode::VESA_1024X768_60
        };
        if run_with(&fake, &mode, EdpVbt::Missing, 0) != Ok(mode) {
            return TestResult::Fail("the rate-table eDP modeset must complete");
        }
        // The C10 eDP PLL at the intermediate 2.16 Gbps, two lanes, 8 bpc.
        if fake.writes_to(0x6_4030) != [216_000] || fake.writes_to(0x6_0400) != [func_a(2, 0)] {
            return TestResult::Fail("the PLL and function must take 2.16 Gbps x2");
        }
        // intel_dp_link_training_set_bw: DP_LANE_COUNT_SET, then
        // DP_LINK_RATE_SET = 1; DP_LINK_BW_SET is never written.
        let dpcd = fake.dpcd_writes.borrow().clone();
        let lane = dpcd.iter().position(|&(a, v, _)| a == 0x101 && v == 0x82);
        let select = dpcd.iter().position(|&(a, v, _)| a == 0x115 && v == 1);
        match (lane, select) {
            (Some(l), Some(s)) if l < s => {}
            _ => return TestResult::Fail("the panel must train with DP_LINK_RATE_SET 1"),
        }
        if dpcd.iter().any(|&(a, _, _)| a == 0x100) {
            return TestResult::Fail("a rate-table panel must never see DP_LINK_BW_SET");
        }
        // Linux's link: PIPE_MISC and the MSA at 8 bpc, M/N at 2.16 Gbps.
        let mn = link_m_n(24 * 16, 2, 140_000, 216_000, false);
        if fake.writes_to(0x7_0030) != [0x100]
            || fake.writes_to(0x6_0410) != [0x21]
            || fake.writes_to(0x6_0030) != [mn[0]]
            || fake.writes_to(0x6_0044) != [mn[3]]
        {
            return TestResult::Fail("the rate-table link must program Linux's M/N");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_rate_table_trains_with_link_rate_set
    );

    fn smoke_mtl_edp_planned_link_retries_at_max_params() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::{link_m_n, EdpVbt};
        // An EDID 6 bpc panel (eDP 1.4, HBR2 x4): Linux's first link is
        // 18 bpp on RBR x1. The sink refuses clock recovery at RBR, so the
        // retry takes use_max_params: 18 bpp on HBR2 x4.
        let fake = MtlFake::new(XeLpgPort::A);
        edp_panel(&fake, 0x14, 4, 0x03);
        fake.cr_fails_at.set(0x06);
        let mode = Mode::VESA_1024X768_60;
        if run_with(&fake, &mode, EdpVbt::Missing, 6) != Ok(mode) {
            return TestResult::Fail("the retry at maximum parameters must light");
        }
        if fake.writes_to(0x6_4030) != [162_000, 540_000]
            || fake.writes_to(0x6_0400) != [func_a(1, 2 << 20), func_a(4, 2 << 20)]
        {
            return TestResult::Fail("the retry must move the PLL and function to HBR2 x4");
        }
        let bw: Vec<u8> = fake
            .dpcd_writes
            .borrow()
            .iter()
            .filter(|&&(a, _, _)| a == 0x100)
            .map(|&(_, v, _)| v)
            .collect();
        let mn = link_m_n(18 * 16, 4, 65_000, 540_000, false);
        if bw != [0x06, 0x14]
            || fake.writes_to(0x6_0030) != [mn[0]]
            || fake.writes_to(0x7_0030) != [0x150]
        {
            return TestResult::Fail("one attempt each, then 6 bpc M/N on HBR2 x4");
        }
        // A failure at the maximum parameters walks Linux's fallback: the
        // next lower common rate at the same lanes (HBR x4) lights.
        let fake = MtlFake::new(XeLpgPort::A);
        edp_panel(&fake, 0x14, 4, 0x03);
        fake.cr_fails_at.set(0x06);
        fake.hbr2_cr_fails.set(true);
        if run_with(&fake, &mode, EdpVbt::Missing, 6) != Ok(mode)
            || fake.writes_to(0x6_4030) != [162_000, 540_000, 270_000]
        {
            return TestResult::Fail("the fallback after the max-params retry must reach HBR x4");
        }
        // A sink that trains nowhere exhausts the ladder: typed refusal.
        let fake = MtlFake::new(XeLpgPort::A);
        edp_panel(&fake, 0x14, 4, 0x03);
        fake.cr_fails_all.set(true);
        if run_with(&fake, &mode, EdpVbt::Missing, 6) != Err(ModesetError::LinkTrainingExhausted) {
            return TestResult::Fail("an exhausted ladder must refuse LinkTrainingExhausted");
        }
        let bw: Vec<u8> = fake
            .dpcd_writes
            .borrow()
            .iter()
            .filter(|&&(a, _, _)| a == 0x100)
            .map(|&(_, v, _)| v)
            .collect();
        let lanes: Vec<u8> = fake
            .dpcd_writes
            .borrow()
            .iter()
            .filter(|&&(a, _, _)| a == 0x101)
            .map(|&(_, v, _)| v & 0x1f)
            .collect();
        if bw != [0x06, 0x14, 0x0a, 0x06, 0x14, 0x0a, 0x06, 0x14, 0x0a, 0x06]
            || lanes != [1, 4, 4, 4, 2, 2, 2, 1, 1, 1]
        {
            return TestResult::Fail("the ladder must step rate, then lanes, as Linux does");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_planned_link_retries_at_max_params
    );

    /// `intel_dp_get_link_train_fallback_values` as a pure decision: eDP
    /// first takes `use_max_params`; then the rate steps down the common
    /// rates at the same lanes; at the lowest rate the lanes halve with the
    /// rate back at the maximum; one lane at the lowest rate is exhausted;
    /// an eDP mode whose 18 bpp stream would not fit keeps its parameters.
    fn smoke_link_fallback_ladder_follows_rate_lane_order() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::{EdpFallback, Fallback, LinkLimits};
        let limits = LinkLimits::standard(540_000, 4);
        let small = Mode::VESA_1024X768_60;
        let edp = |use_max_params, fixed_mode| {
            Some(EdpFallback {
                use_max_params,
                fixed_mode,
            })
        };
        let cases = [
            (162_000, 1, edp(false, small), Fallback::MaxParams),
            (
                540_000,
                4,
                None,
                Fallback::Reduce {
                    max_rate: 270_000,
                    max_lanes: 4,
                },
            ),
            (
                162_000,
                4,
                edp(true, small),
                Fallback::Reduce {
                    max_rate: 540_000,
                    max_lanes: 2,
                },
            ),
            (162_000, 1, None, Fallback::Exhausted),
        ];
        for (rate, lanes, edp, want) in cases {
            if limits.fallback(rate, lanes, edp) != want {
                return TestResult::Fail("a fallback step left Linux's rate-lane order");
            }
        }
        // A 4K panel's 18 bpp stream does not fit RBR x4: same parameters.
        let big = Mode {
            pixel_clock_khz: 533_250,
            h_active: 3840,
            v_active: 2160,
            ..small
        };
        if limits.fallback(270_000, 4, edp(true, big)) != Fallback::Same {
            return TestResult::Fail("an eDP mode that no longer fits must keep its link");
        }
        // The capped limits keep the common rates up to the new maximum.
        let capped = limits.capped(270_000, 2);
        if capped.max_rate() != 270_000 || capped.max_lanes != 2 {
            return TestResult::Fail("the reduced limits must cap rate and lanes");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_link_fallback_ladder_follows_rate_lane_order
    );

    fn smoke_mtl_edp_eight_bpc_keeps_write_stream_and_clears_stale_six_bpc() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::EdpVbt;
        // 24 bpp fits and there is no rate table: the existing sequence
        // writes neither PIPE_MISC nor the MSA, and still trains with
        // DP_LINK_BW_SET from HBR2 (VALFREQ RBR, then HBR2).
        let fake = MtlFake::new(XeLpgPort::A);
        let mode = Mode::VESA_1024X768_60;
        if run_with(&fake, &mode, EdpVbt::Missing, 0) != Ok(mode)
            || !fake.writes_to(0x7_0030).is_empty()
            || !fake.writes_to(0x6_0410).is_empty()
            || fake.writes_to(0x6_4030) != [162_000, 540_000]
            || fake.writes_to(0x6_0400) != [func_a(4, 0)]
        {
            return TestResult::Fail("the 8 bpc sequence must keep its write stream");
        }
        // A 6 bpc, dithered PIPE_MISC left behind is rewritten to 8 bpc,
        // and the MSA with it.
        let fake = MtlFake::new(XeLpgPort::A);
        fake.phy.write32(0x7_0030, 0x150);
        if run_with(&fake, &mode, EdpVbt::Missing, 0) != Ok(mode)
            || fake.writes_to(0x7_0030) != [0x100]
            || fake.writes_to(0x6_0410) != [0x21]
        {
            return TestResult::Fail("a stale 6 bpc pipe must return to 8 bpc");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_eight_bpc_keeps_write_stream_and_clears_stale_six_bpc
    );

    fn smoke_mtl_edp_vbt_bpp_clamp_and_lit_pipe_fixup() -> TestResult {
        use crate::intel_gpu_xelpg_dsc::{install_edp_vbt, installed_edp_vbt, EdpVbt};
        let vbt18 = EdpVbt::Panel {
            dsc_disable: false,
            max_link_rate: 0,
            bpp: 18,
        };
        // The default panel (eDP 1.3, HBR2 x4, use_max_params) with the
        // VBT's 18 bpp and no EDID bpc: 18 bpp on HBR2 x4.
        let fake = MtlFake::new(XeLpgPort::A);
        let mode = Mode::VESA_1024X768_60;
        if run_with(&fake, &mode, vbt18, 0) != Ok(mode)
            || fake.writes_to(0x7_0030) != [0x150]
            || fake.writes_to(0x6_0400) != [func_a(4, 2 << 20)]
            || fake.writes_to(0x6_4030) != [540_000]
        {
            return TestResult::Fail("the VBT's 18 bpp must clamp an EDID without bpc");
        }
        // An EDID bpc overrides the VBT: the 8 bpc sequence.
        let fake = MtlFake::new(XeLpgPort::A);
        if run_with(&fake, &mode, vbt18, 8) != Ok(mode) || !fake.writes_to(0x7_0030).is_empty() {
            return TestResult::Fail("an EDID bpc must override the VBT's");
        }
        // intel_edp_fixup_vbt_bpp: transcoder A lit on DDI A at 8 bpc
        // raises the VBT's 18 to 24 before the decision.
        let previous = installed_edp_vbt();
        let fake = MtlFake::new(XeLpgPort::A);
        fake.phy.write32(0x6_0400, func_a(4, 0));
        let result = run_with(&fake, &mode, vbt18, 0);
        install_edp_vbt(vbt18);
        let fake2 = MtlFake::new(XeLpgPort::A);
        fake2.phy.write32(0x6_0400, func_a(4, 0));
        let fixed = XeLpgModeset::new(&fake2, XeLpgPort::A).modeset_fixed(&test_fb(), &mode);
        let raised = installed_edp_vbt().edp_bpp();
        install_edp_vbt(previous);
        if result != Ok(mode)
            || !fake.writes_to(0x7_0030).is_empty()
            || fixed != Ok(mode)
            || raised != 24
        {
            return TestResult::Fail("a lit 8 bpc pipe must raise the VBT's bpp");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_edp_vbt_bpp_clamp_and_lit_pipe_fixup
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
    /// A pipe-DMC sink that logs each report with the register-write count
    /// at the time: (enable?, pipe, writes so far).
    struct DmcLog<'a> {
        fake: &'a MtlFake,
        log: RefCell<Vec<(bool, u32, usize)>>,
    }
    impl crate::intel_gpu_dc_states::PipeDmc for DmcLog<'_> {
        fn enable_pipe(&self, pipe: u32) {
            let at = self.fake.writes.borrow().len();
            self.log.borrow_mut().push((true, pipe, at));
        }
        fn disable_pipe(&self, pipe: u32) {
            let at = self.fake.writes.borrow().len();
            self.log.borrow_mut().push((false, pipe, at));
        }
    }

    /// An MTL panel lit by the owned modeset on DDI A, powered and backlit
    /// through its PPS, with the PHY's idle and D2D state modelled.
    fn lit_panel(fake: &MtlFake, dmc: &DmcLog<'_>) -> Result<Mode, &'static str> {
        forget_panel_off();
        fake.pps.set(true);
        fake.phy.model_ddi_idle.set(true);
        fake.phy.model_d2d.set(true);
        let mode = Mode::VESA_1024X768_60;
        if XeLpgModeset::new(fake, XeLpgPort::A)
            .with_pipe_dmc(dmc)
            .modeset_fixed(&test_fb(), &mode)
            != Ok(mode)
        {
            return Err("the warm modeset must light the panel");
        }
        // A powered panel with its backlight gate open.
        fake.phy.write32(crate::intel_gpu_edp::PP_CONTROL, 1 | 4);
        fake.writes.borrow_mut().clear();
        fake.dpcd_writes.borrow_mut().clear();
        dmc.log.borrow_mut().clear();
        Ok(mode)
    }

    const PP_CONTROL: u64 = crate::intel_gpu_edp::PP_CONTROL;

    fn smoke_mtl_panel_off_follows_hsw_crtc_disable_order() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::A);
        let dmc = DmcLog {
            fake: &fake,
            log: RefCell::new(Vec::new()),
        };
        if let Err(e) = lit_panel(&fake, &dmc) {
            return TestResult::Fail(e);
        }
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A).with_pipe_dmc(&dmc);
        if ms.disable_planes().is_err() {
            return TestResult::Fail("the planes must go off");
        }
        let record = match ms.panel_off() {
            Ok(record) => record,
            Err(_) => return TestResult::Fail("the lit panel must turn off"),
        };
        let at = |f: &dyn Fn(u64, u32) -> bool| fake.write_index(0, f);
        // intel_crtc_disable_planes, then intel_edp_backlight_off's PPS gate
        // (power still on), intel_disable_transcoder, the function cleared,
        // intel_ddi_buf_disable, TRANS_CLK_SEL off, intel_pps_off, the PLL.
        let steps = [
            at(&|o, v| o == 0x70180 && v & (1 << 31) == 0),
            at(&|o, v| o == PP_CONTROL && v & 4 == 0 && v & 1 != 0),
            at(&|o, v| o == 0x70008 && v & (1 << 31) == 0),
            at(&|o, v| o == 0x60404 && v == 0),
            at(&|o, v| o == 0x60400 && v & (1 << 31) == 0 && v & TRANS_DDI_PORT_AND_MODE == 0),
            at(&|o, v| o == 0x64000 && v & DDI_BUF_CTL_ENABLE == 0),
            at(&|o, v| o == 0x60540 && v & DP_TP_CTL_ENABLE == 0),
            at(&|o, v| o == TRANS_CLK_SEL_A && v == 0),
            at(&|o, v| o == PP_CONTROL && v & 0xf == 0),
            at(&|o, _| o == XeLpgPort::A.port_clock_ctl()),
        ];
        let mut last = 0;
        for step in steps {
            match step {
                Some(i) if i >= last => last = i,
                _ => return TestResult::Fail("the crtc disable left hsw_crtc_disable's order"),
            }
        }
        // VDD was forced on for the power-off write (intel_pps_vdd_on).
        let vdd = at(&|o, v| o == PP_CONTROL && v & 8 != 0);
        if vdd.is_none_or(|i| i >= steps[8].unwrap()) {
            return TestResult::Fail("intel_pps_off must follow intel_pps_vdd_on");
        }
        // The sink goes to D3 after the transcoder and before the DDI.
        let d3 = fake
            .dpcd_writes
            .borrow()
            .iter()
            .find(|(a, v, _)| *a == 0x600 && *v == 2)
            .map(|(_, _, at)| *at);
        if !d3.is_some_and(|i| i > steps[2].unwrap() && i <= steps[5].unwrap()) {
            return TestResult::Fail("DP_SET_POWER D3 must precede the DDI buffer disable");
        }
        // intel_dmc_disable_pipe is the last step, after the PLL.
        let log = dmc.log.borrow().clone();
        if log.len() != 1 || log[0].0 || log[0].1 != 0 || log[0].2 < steps[9].unwrap() {
            return TestResult::Fail("the pipe DMC must be disabled once, after the port PLL");
        }
        if record.port != XeLpgPort::A
            || panel_off_record() != Some(record)
            || owned_panel_mode().is_some()
        {
            return TestResult::Fail("the panel-off must record the dark panel");
        }
        // A second off finds no lit panel and writes nothing.
        let before = fake.writes.borrow().len();
        if XeLpgModeset::new(&fake, XeLpgPort::A).panel_off()
            != Err(ModesetError::PipelineStopUnavailable)
            || fake.writes.borrow().len() != before
        {
            return TestResult::Fail("a dark panel must refuse a second off before any write");
        }
        forget_panel_off();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_panel_off_follows_hsw_crtc_disable_order
    );

    fn smoke_mtl_panel_on_after_off_runs_full_enable_and_restores_image() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::A);
        let dmc = DmcLog {
            fake: &fake,
            log: RefCell::new(Vec::new()),
        };
        let mode = match lit_panel(&fake, &dmc) {
            Ok(mode) => mode,
            Err(e) => return TestResult::Fail(e),
        };
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A).with_pipe_dmc(&dmc);
        if ms.disable_planes().is_err() || ms.panel_off().is_err() {
            return TestResult::Fail("the lit panel must turn off");
        }
        fake.writes.borrow_mut().clear();
        fake.dpcd_writes.borrow_mut().clear();
        dmc.log.borrow_mut().clear();
        // The warm path would refuse the off DDI; the cold path lights it.
        if XeLpgModeset::new(&fake, XeLpgPort::A)
            .with_pipe_dmc(&dmc)
            .modeset_fixed(&test_fb(), &mode)
            != Ok(mode)
        {
            return TestResult::Fail("the panel-on modeset must light the panel");
        }
        let at = |from: usize, f: &dyn Fn(u64, u32) -> bool| fake.write_index(from, f);
        let vdd = at(0, &|o, v| o == PP_CONTROL && v & 8 != 0);
        let power = at(0, &|o, v| o == PP_CONTROL && v & 1 != 0);
        let pll = at(0, &|o, _| o == XeLpgPort::A.port_clock_ctl());
        let tps1 = at(0, &|o, v| o == 0x60540 && v & DP_TP_CTL_ENABLE != 0);
        let ddi = at(0, &|o, v| {
            o == 0x64000 && v == (DDI_BUF_CTL_ENABLE | (3 << 1))
        });
        let func_off = at(0, &|o, v| o == 0x60400 && v & (1 << 31) == 0 && v != 0);
        let conf = at(0, &|o, v| o == 0x70008 && v & (1 << 31) != 0);
        let (Some(vdd), Some(power), Some(pll), Some(tps1), Some(ddi), Some(func_off), Some(conf)) =
            (vdd, power, pll, tps1, ddi, func_off, conf)
        else {
            return TestResult::Fail("the panel-on must run mtl_ddi_pre_enable_dp's writes");
        };
        // intel_pps_on precedes the port PLL, after the pipe DMC enable.
        let log = dmc.log.borrow().clone();
        if !(vdd <= power && power < pll)
            || log.len() != 1
            || !log[0].0
            || log[0].1 != 0
            || log[0].2 > power
        {
            return TestResult::Fail(
                "intel_pps_on must follow intel_dmc_enable_pipe, before the PLL",
            );
        }
        // DDI_CTL_DE comes after DP_TP_CTL TPS1 and before the DPCD training.
        let training = fake
            .dpcd_writes
            .borrow()
            .iter()
            .find(|(a, _, _)| *a == 0x100)
            .map(|(_, _, at)| *at);
        if !(tps1 < ddi && training.is_some_and(|t| t > ddi)) {
            return TestResult::Fail("DDI_CTL_DE must be enabled between TPS1 and the training");
        }
        // The function is configured without ENABLE, enabled before the
        // transcoder (intel_ddi_enable).
        let func_on = at(func_off, &|o, v| o == 0x60400 && v & (1 << 31) != 0);
        if func_on.is_none_or(|i| i >= conf) {
            return TestResult::Fail("TRANS_DDI_FUNC_CTL must be enabled just before TRANSCONF");
        }
        // The console image is back on the plane, VDD no longer forced, and
        // the record is gone.
        if fake.writes_to(0x7019c).last() != Some(&(test_fb().phys_addr as u32))
            || fake.writes_to(PP_CONTROL).last().is_none_or(|v| v & 8 != 0)
            || panel_off_record().is_some()
        {
            return TestResult::Fail("the panel-on must restore the image and forget the record");
        }
        forget_panel_off();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_panel_on_after_off_runs_full_enable_and_restores_image
    );

    fn smoke_mtl_panel_off_beside_lit_pipe_b_writes_only_the_panel() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::A);
        let dmc = DmcLog {
            fake: &fake,
            log: RefCell::new(Vec::new()),
        };
        let mode = match lit_panel(&fake, &dmc) {
            Ok(mode) => mode,
            Err(e) => return TestResult::Fail(e),
        };
        // An external lit on Pipe B / transcoder B.
        fake.phy.write32(0x71008, (1 << 31) | (1 << 30));
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A).with_pipe_dmc(&dmc);
        let record = match ms.disable_planes().and_then(|()| ms.panel_off()) {
            Ok(record) => record,
            Err(_) => return TestResult::Fail("the panel must turn off beside a lit external"),
        };
        let foreign = |o: u64| {
            (0x71000..0x74000).contains(&o)
                || (0x61000..0x64000).contains(&o)
                || o == 0x64100
                || (0x45230..=0x45238).contains(&o)
                || o == 0x46000
                || o == 0x46070
        };
        if record.settled || fake.writes.borrow().iter().any(|(o, _)| foreign(*o)) {
            return TestResult::Fail("panel off beside a lit pipe must write only the panel");
        }
        // Lighting it again needs Pipe A's share of the live layout; with
        // none proved it refuses before the PLL, the DDI or the transcoder.
        fake.writes.borrow_mut().clear();
        let result = XeLpgModeset::new(&fake, XeLpgPort::A)
            .with_pipe_dmc(&dmc)
            .modeset_fixed(&test_fb(), &mode);
        let touched = fake.writes.borrow().iter().any(|(o, _)| {
            foreign(*o) || *o == 0x64000 || *o == 0x70008 || *o == XeLpgPort::A.port_clock_ctl()
        });
        if result != Err(ModesetError::DisplayResourceUnavailable)
            || touched
            || fake.read32(0x71008) & (1 << 31) == 0
            || panel_off_record().is_none()
            || fake
                .writes_to(PP_CONTROL)
                .last()
                .is_some_and(|v| v & 8 != 0)
        {
            return TestResult::Fail(
                "an unproved panel-on beside the external must refuse cleanly",
            );
        }
        forget_panel_off();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_panel_off_beside_lit_pipe_b_writes_only_the_panel
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

    fn smoke_mtl_modeset_panel_fitting_scaler_and_pipe_source() -> TestResult {
        use crate::intel_gpu_xelpg_scaler::{Filter, ScalingMode, PS_SCALER_EN};

        let fake = MtlFake::new(XeLpgPort::A);
        // Native panel mode: 2880x1800 OLED
        let mode = oled_mode();
        oled_panel(&fake, 0x14, 2);

        // Framebuffer: 1920x1200 (aspect 16:10 matches panel 2880:1800)
        let fb = Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 1920 * 4,
            format: PixelFormat::Xrgb8888,
        };

        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A).with_panel_fit(
            1920,
            1200,
            ScalingMode::Aspect,
            Filter::Default,
        );
        let res = ms.modeset_fixed(&fb, &mode);
        if res != Ok(mode) {
            return TestResult::Fail("panel-fitting modeset must succeed");
        }

        // 1. PIPE_SRCSZ (0x6001c) must have source size (1919 << 16) | 1199
        let srcsz = fake.writes_to(0x6001c);
        if srcsz.last() != Some(&((1919 << 16) | 1199)) {
            return TestResult::Fail("PIPE_SRCSZ must receive custom source size (1919, 1199)");
        }

        // 2. SKL_PS_CTRL (0x68180) must have PS_SCALER_EN set
        let ps_ctrl = fake.writes_to(0x68180);
        if !ps_ctrl.iter().any(|&v| v & PS_SCALER_EN != 0) {
            return TestResult::Fail("SKL_PS_CTRL must have PS_SCALER_EN enabled");
        }

        // 3. SKL_PS_WIN_POS (0x68170) must be (0, 0)
        let ps_win_pos = fake.writes_to(0x68170);
        if ps_win_pos.last() != Some(&0) {
            return TestResult::Fail("SKL_PS_WIN_POS must be (0, 0) for 16:10 aspect match");
        }

        // 4. SKL_PS_WIN_SZ (0x68174) must be (2880 << 16) | 1800
        let ps_win_sz = fake.writes_to(0x68174);
        if ps_win_sz.last() != Some(&((2880 << 16) | 1800)) {
            return TestResult::Fail("SKL_PS_WIN_SZ must match panel window dimensions");
        }

        // 5. PLANE_SIZE_1_A (0x70190) must receive (1919 << 16) | 1199
        let plane_size = fake.writes_to(0x70190);
        if plane_size.last() != Some(&((1919 << 16) | 1199)) {
            return TestResult::Fail("PLANE_SIZE_1_A must receive source dimensions");
        }

        // 6. Disable/panel_off disables scaler registers
        if ms.disable_planes().is_err() || ms.panel_off().is_err() {
            return TestResult::Fail("panel_off must succeed");
        }
        if fake.writes_to(0x68180).last() != Some(&0) {
            return TestResult::Fail("SKL_PS_CTRL must be cleared on disable");
        }
        if fake.writes_to(0x68170).last() != Some(&0) {
            return TestResult::Fail("SKL_PS_WIN_POS must be cleared on disable");
        }
        if fake.writes_to(0x68174).last() != Some(&0) {
            return TestResult::Fail("SKL_PS_WIN_SZ must be cleared on disable");
        }

        forget_panel_off();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_panel_fitting_scaler_and_pipe_source
    );

    fn smoke_mtl_modeset_bigjoiner_join_and_disable() -> TestResult {
        use crate::intel_gpu_pipes::Pipe as PipeIdx;
        use crate::intel_gpu_xelpg_dsc::{dss_ctl1, JOINER_ENABLE};
        const SECONDARY_BIG_JOINER_ENABLE: u32 = 1 << 29;

        let fake = MtlFake::new(XeLpgPort::A);
        let mode = Mode::VESA_1024X768_60;
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::A).with_bigjoiner(PipeIdx::B);
        let res = ms.modeset_fixed(&test_fb(), &mode);
        if res != Ok(mode) {
            return TestResult::Fail("modeset_fixed with bigjoiner must succeed");
        }
        let master_dss = dss_ctl1(PipeIdx::A);
        let slave_dss = dss_ctl1(PipeIdx::B);
        if !fake.writes_to(master_dss).contains(&JOINER_ENABLE) {
            return TestResult::Fail("master pipe DSS_CTL1 must have JOINER_ENABLE");
        }
        if !fake
            .writes_to(slave_dss)
            .contains(&SECONDARY_BIG_JOINER_ENABLE)
        {
            return TestResult::Fail("slave pipe DSS_CTL1 must have SECONDARY_BIG_JOINER_ENABLE");
        }
        if ms.disable_planes().is_err() || ms.panel_off().is_err() {
            return TestResult::Fail("panel_off with bigjoiner must succeed");
        }
        if fake.writes_to(master_dss).last() != Some(&0) {
            return TestResult::Fail("master pipe DSS_CTL1 must be cleared on panel off");
        }
        if fake.writes_to(slave_dss).last() != Some(&0) {
            return TestResult::Fail("slave pipe DSS_CTL1 must be cleared on panel off");
        }
        forget_panel_off();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_bigjoiner_join_and_disable
    );

    /// Minimal MMIO window for the VRR sequencing fixture: records
    /// writes and serves canned reads (default 0). The VRR helpers
    /// only touch the transcoder VRR registers, so the full `MtlFake`
    /// sink model is not needed here.
    #[derive(Debug)]
    struct SeqMmio {
        writes: RefCell<Vec<(u64, u32)>>,
        reads: RefCell<Vec<(u64, u32)>>,
    }

    impl SeqMmio {
        fn new() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                reads: RefCell::new(Vec::new()),
            }
        }

        fn set_read(&self, off: u64, val: u32) {
            self.reads.borrow_mut().push((off, val));
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for SeqMmio {
        fn read32(&self, off: u64) -> u32 {
            let mut v = 0u32;
            for (o, val) in self.reads.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
        }
    }

    // ── VRR modeset sequencing (#1769) ───────────────────────────────────
    //
    // Drives the Xe-LPG VRR helpers directly (the full `modeset_checked`
    // needs the panel power sequencer + link training): timings
    // programmed, TG enabled after, disable clears CTL + PUSH + VSYNC.
    // Display 30 takes none of the generic path — its always-on TG is
    // owned by `intel_gpu_xe3lpd`.

    fn smoke_vrr_xelpg_sequences_timings_enable_disable_and_skips_xe3() -> TestResult {
        use crate::intel_gpu_pipes::Transcoder;
        use crate::intel_gpu_vrr::{
            DisplayVrrIp, VrrComputeOpts, VrrRange, VrrTimings, TRANS_PUSH_EN, TRANS_PUSH_OFFSET,
            TRANS_VRR_CTL_OFFSET, TRANS_VRR_VMAX_OFFSET, TRANS_VRR_VMIN_OFFSET,
            TRANS_VRR_VSYNC_OFFSET, VRR_CTL_FLIP_LINE_EN, VRR_CTL_VRR_ENABLE, VRR_STATE,
        };
        let mode = Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        };
        let range = VrrRange::new(48, 144).unwrap();
        VRR_STATE.set_range(1, Some(range));
        VRR_STATE.set_enabled(1, true);

        // Display 14 (MTL/ARL, the default IP): timings are programmed
        // with the −1 form, then the TG is enabled.
        let mmio = SeqMmio::new();
        let mut ms = XeLpgModeset::new(&mmio, XeLpgPort::A);
        if ms.program_vrr_for_modeset(&mode).is_err() {
            VRR_STATE.set_enabled(1, false);
            VRR_STATE.set_range(1, None);
            return TestResult::Fail("XeLPG VRR timings programming failed");
        }
        let expected = VrrTimings::compute_config(
            &mode,
            range,
            DisplayVrrIp::Display14,
            VrrComputeOpts::default(),
        )
        .expect("1080p60 against 48..144 computes on display 14");
        let base = Transcoder::A.base();
        // Display 14 writes val − 1.
        if mmio.writes_to(base + TRANS_VRR_VMIN_OFFSET) != alloc::vec![expected.vmin - 1] {
            VRR_STATE.set_enabled(1, false);
            VRR_STATE.set_range(1, None);
            return TestResult::Fail("XeLPG VRR VMIN must be the computed vmin − 1");
        }
        if mmio.writes_to(base + TRANS_VRR_VMAX_OFFSET) != alloc::vec![expected.vmax - 1] {
            VRR_STATE.set_enabled(1, false);
            VRR_STATE.set_range(1, None);
            return TestResult::Fail("XeLPG VRR VMAX must be the computed vmax − 1");
        }
        if ms.enable_vrr_for_modeset().is_err() {
            VRR_STATE.set_enabled(1, false);
            VRR_STATE.set_range(1, None);
            return TestResult::Fail("XeLPG VRR enable failed");
        }
        // Disable: CTL ENABLE clears and PUSH resets, with VSYNC
        // cleared too (display 14 is AS SDP).
        mmio.set_read(
            base + TRANS_VRR_CTL_OFFSET,
            VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN,
        );
        ms.disable_vrr_for_modeset();
        // The request is retained state, not a one-shot: clear it now so
        // later fixtures in this harness process start from fixed refresh.
        VRR_STATE.set_enabled(1, false);
        VRR_STATE.set_range(1, None);
        VRR_STATE.set_timings(1, None);
        VRR_STATE.set_mode(1, None);

        // Order: timings programmed before the TG is enabled.
        let writes = mmio.writes.borrow();
        let vmin_pos = writes
            .iter()
            .position(|(o, _)| *o == base + TRANS_VRR_VMIN_OFFSET);
        let ctl_pos = writes
            .iter()
            .position(|(o, v)| *o == base + TRANS_VRR_CTL_OFFSET && v & VRR_CTL_VRR_ENABLE != 0);
        if !matches!((vmin_pos, ctl_pos), (Some(v), Some(c)) if v < c) {
            return TestResult::Fail("XeLPG VRR order must be timings, then TG enable");
        }
        // The disable's CTL write is the last one and clears ENABLE
        // (flip-line kept); PUSH was reset to 0 and VSYNC cleared.
        if writes
            .iter()
            .filter(|(o, _)| *o == base + TRANS_VRR_CTL_OFFSET)
            .next_back()
            .map(|(_, v)| *v)
            != Some(VRR_CTL_FLIP_LINE_EN)
        {
            return TestResult::Fail("XeLPG VRR disable must clear CTL ENABLE last");
        }
        drop(writes);
        if mmio.writes_to(base + TRANS_PUSH_OFFSET) != alloc::vec![TRANS_PUSH_EN, 0] {
            return TestResult::Fail("XeLPG TRANS_PUSH must arm then reset to 0");
        }
        if mmio.writes_to(base + TRANS_VRR_VSYNC_OFFSET) != alloc::vec![0] {
            return TestResult::Fail("XeLPG VRR disable must clear VSYNC on AS SDP");
        }

        // Display 30 (PTL): the generic hooks are skipped entirely.
        let mmio3 = SeqMmio::new();
        let mut ms3 = XeLpgModeset::new(&mmio3, XeLpgPort::A)
            .with_display_ip(crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd);
        if ms3.program_vrr_for_modeset(&mode).is_err() || ms3.enable_vrr_for_modeset().is_err() {
            return TestResult::Fail("Xe3 VRR hooks must succeed by skipping");
        }
        ms3.disable_vrr_for_modeset();
        if !mmio3.writes.borrow().is_empty() {
            return TestResult::Fail("Xe3 must not take the generic VRR path");
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_vrr_xelpg_sequences_timings_enable_disable_and_skips_xe3
    );

    include!("intel_gpu_modeset_xelpg_failclosed_tests.rs");
}
