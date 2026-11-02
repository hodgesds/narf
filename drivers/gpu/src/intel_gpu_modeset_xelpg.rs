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
//!   A + DDI A/B. Each port's AUX channel has its own well in
//!   `PWR_WELL_CTL_AUX2` (AUX_A=0, AUX_USBC1=3), enabled before
//!   any AUX/PHY traffic. (i915 `intel_display_power_map.c`,
//!   `xelpd_power_wells`.)
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
//! - **Port enable.** There is no `DDI_BUF_CTL`. The port comes
//!   up through the D2D link enable + `PORT_BUF_CTL1` width
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
//! ## Named remainders (not programmed by this lane)
//!
//! - **Watermarks / DBUF allocation.** The Gen12 orchestrator's
//!   pre-boot constants are TGL PRM values; no MTL counterpart
//!   is published in the sources this lane grounds on, and i915
//!   computes MTL allocations from pcode latency tables.
//!   Firmware's allocation is left in place — the same posture
//!   the Gen12 path takes toward DBUF_CTL power sequencing.
//! - **HDMI / DP 2.0 UHBR / MST / multi-pipe** — out of scope,
//!   matching the Gen12 orchestrator's DP-SST single-pipe shape.
//! - **DVFS/pcode notifications** around CDCLK changes — the
//!   Gen12 path omits them as well.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError, PixelFormat};
use crate::intel_gpu_pll::LinkRate;
use crate::intel_gpu_xelpg::{
    disable_port_pll, enable_d2d, enable_port_pll, program_port_buf_ctl, reprogram_pll_rate,
    set_signal_levels, Cx0Error, Cx0Phy, XeLpgPort,
};

// ── Power wells (Xe-LPD) ─────────────────────────────────────────
//
// Register pair from i915 `intel_display_regs.h`:
// HSW_PWR_WELL_CTL2 = 0x45404 (main wells), ICL_PWR_WELL_CTL_AUX2
// = 0x45444 (AUX wells). Both use the HSW request/state encoding
// (REQ = 0x2 << idx*2, STATE = 0x1 << idx*2).

const PWR_WELL_CTL2: u64 = 0x4_5404;
const PWR_WELL_CTL_AUX2: u64 = 0x4_5444;
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
/// is off.
pub(crate) fn cdclk_current_khz<M: MmioWindow + ?Sized>(mmio: &M) -> u32 {
    let pll = mmio.read32(CDCLK_PLL_ENABLE_REG);
    if pll & CDCLK_PLL_ENABLE == 0 {
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
    let mut cdclk = vco / div2x;
    let squash = mmio.read32(CDCLK_SQUASH_CTL);
    if squash & CDCLK_SQUASH_ENABLE != 0 {
        let waveform = (squash & 0xFFFF) as u16;
        cdclk = cdclk * waveform.count_ones() / 16;
    }
    cdclk
}

/// Raise CDCLK to the floor `mode` needs, MTL-style. Only ever
/// raises; a faster firmware CDCLK is left alone (and if the
/// pixel clock is past the table, firmware's setting stands —
/// the pipe simply runs at the best available clock, the same
/// posture as the Gen12 ladder miss).
fn program_cdclk_floor<M: MmioWindow + ?Sized>(mmio: &M, mode: &Mode) -> Result<(), ModesetError> {
    let floor_khz = mode.pixel_clock_khz.div_ceil(2);
    if floor_khz <= cdclk_current_khz(mmio) {
        return Ok(());
    }
    let entry = match mtl_cdclk_for_pixel_clock(mode.pixel_clock_khz) {
        Some(e) => e,
        None => return Ok(()),
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
    }
    if !pll_on || cur_ratio != entry.ratio {
        mmio.write32(CDCLK_PLL_ENABLE_REG, entry.ratio);
        mmio.write32(CDCLK_PLL_ENABLE_REG, entry.ratio | CDCLK_PLL_ENABLE);
        compiler_fence(Ordering::SeqCst);
        if !wait_bit(mmio, CDCLK_PLL_ENABLE_REG, CDCLK_PLL_LOCK, true, 1_000_000) {
            return Err(ModesetError::PllLockTimeout);
        }
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

// ── Orchestrator ─────────────────────────────────────────────────

/// Xe-LPG modeset orchestrator for one port + pipe A. Stateless,
/// like its Gen12 counterpart.
pub struct XeLpgModeset<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    /// The physical port for this modeset.
    pub port: XeLpgPort,
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
    /// Create an orchestrator for a port + MMIO window pair.
    pub fn new(mmio: &'a M, port: XeLpgPort) -> Self {
        Self { mmio, port }
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
        let mode = *mode;

        // Step 2: power wells — PW_1 (transcoder A / DDI A-B),
        // PW_A (pipe A), and this port's AUX well (the PHY
        // message bus and AUX channel both hang off it).
        self.enable_power_well(PWR_WELL_CTL2, PW_1_IDX)?;
        self.enable_power_well(PWR_WELL_CTL2, PW_A_IDX)?;
        self.enable_power_well(PWR_WELL_CTL_AUX2, self.port.aux_well_index())?;

        // Step 3: disable the existing pipeline (plane → pipe →
        // transcoder → port PLL request dropped).
        self.disable_pipeline();
        // This is a full owned modeset with the pipe off, not a KMS
        // inheritance path. Establish RGB bypass rather than depend on GOP
        // leaving its per-plane gamma/CSC controls in an admissible state.
        crate::intel_gpu_color::initialize_rgb_bypass(self.mmio)
            .map_err(|_| ModesetError::ColorPipelineUnavailable)?;

        // A qualified display14.00 resource transaction owns no-SAGV,
        // joined MBUS and a cursor DDB reservation before any plane enable.
        // Unsupported preflight retains the historical inherited layout;
        // every partial request/programming failure keeps this pipe off.
        let current = cdclk_current_khz(self.mmio);
        let target = mtl_cdclk_for_pixel_clock(mode.pixel_clock_khz)
            .map_or(current, |entry| current.max(entry.cdclk_khz));
        crate::intel_gpu_display_resources::initialize(self.mmio, &mode, target)
            .map_err(|_| ModesetError::DisplayResourceUnavailable)?;
        // Step 4: CDCLK floor for the mode's pixel clock.
        program_cdclk_floor(self.mmio, &mode)?;

        // Step 5: enable the port PLL at the rate this pixel
        // clock needs (the same bandwidth rule the Gen12 path
        // picks its DPLL rate with).
        let mut pll_rate = link_rate_for_pixel_clock(mode.pixel_clock_khz);
        enable_port_pll(self.mmio, self.port, pll_rate, 4).map_err(map_cx0_err)?;

        // Step 6: route the port clock to transcoder A.
        self.mmio
            .write32(TRANS_CLK_SEL_A, trans_clk_sel_port(self.port.phy_index()));
        compiler_fence(Ordering::SeqCst);

        // Step 7: transcoder timing + pipe source size (register
        // block shared with Gen12 — the shared codecs build them).
        self.program_transcoder(&mode);
        self.program_pipe(&mode);

        // Step 8: bind transcoder A to this port (DP-SST, 8 bpc).
        self.program_trans_ddi_func_ctl(4);

        // Step 9: program the primary plane.
        self.program_plane(primary_fb, &mode);

        // Step 10: link-retrain preamble — D2D link up, port
        // buffer width, initial (zero) signal levels.
        enable_d2d(self.mmio, self.port).map_err(map_cx0_err)?;
        program_port_buf_ctl(self.mmio, self.port, 4);
        let phy = Cx0Phy::new(self.mmio, self.port);
        set_signal_levels(&phy, pll_rate, 4, &[(0, 0); 4]).map_err(map_cx0_err)?;

        // Step 11: source pattern generator into TPS1 and run
        // DPCD link training over this port's AUX.
        self.program_dp_tp_ctl(DP_TP_CTL_LINK_TRAIN_PAT1);
        let trained = self.train_dp_link()?;
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
        if trained_lanes != 4 {
            program_port_buf_ctl(self.mmio, self.port, trained_lanes);
            self.program_trans_ddi_func_ctl(trained_lanes);
        }
        set_signal_levels(&phy, pll_rate, trained_lanes, &trained_levels).map_err(map_cx0_err)?;
        self.program_mn(&mode, pll_rate, trained_lanes);

        // Step 13: pattern generator to normal data, then the
        // final enables in PRM order (transcoder → pipe → plane).
        self.program_dp_tp_ctl(DP_TP_CTL_LINK_TRAIN_NORMAL);
        self.enable_transcoder();
        self.enable_pipe();
        self.enable_plane();

        Ok(mode)
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
        if wait_bit(self.mmio, reg, pwr_well_state(idx), true, 1_000_000) {
            Ok(())
        } else {
            Err(ModesetError::PowerWellTimeout)
        }
    }

    // ── Pipeline disable ─────────────────────────────────────

    /// Disable the existing pipeline: plane → pipe → transcoder
    /// (the register block is shared with Gen12), then drop the
    /// port PLL request — Xe-LPG has no DDI_BUF_CTL to idle.
    fn disable_pipeline(&mut self) {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
            PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET,
        };
        let plane_base = PipeIdx::A.base() + PLANE_PRIMARY_OFFSET;
        let ctl = self.mmio.read32(plane_base + PLANE_CTL_OFFSET);
        self.mmio
            .write32(plane_base + PLANE_CTL_OFFSET, ctl & !PLANE_CTL_ENABLE);
        let surf = self.mmio.read32(plane_base + PLANE_SURF_OFFSET);
        self.mmio.write32(plane_base + PLANE_SURF_OFFSET, surf);
        compiler_fence(Ordering::SeqCst);

        let pipe_off = PipeIdx::A.base() + PIPECONF_OFFSET;
        let pconf = self.mmio.read32(pipe_off);
        self.mmio.write32(pipe_off, pconf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, pipe_off, PIPECONF_STATE, false, 100_000_000);

        let trans_off = Transcoder::A.conf_base() + PIPECONF_OFFSET;
        let tconf = self.mmio.read32(trans_off);
        self.mmio.write32(trans_off, tconf & !PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, trans_off, PIPECONF_STATE, false, 100_000_000);

        let _ = disable_port_pll(self.mmio, self.port);
    }

    // ── Shared pipe/transcoder/plane programming ─────────────
    //
    // The pipe, transcoder, and plane register blocks did not
    // move on Xe-LPG; these steps reuse the shared codecs exactly
    // as the Gen12 orchestrator does.

    fn program_transcoder(&mut self, mode: &Mode) {
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
        self.mmio.write32(base + TRANS_VBLANK_OFFSET, prog.vblank);
        self.mmio.write32(base + TRANS_VSYNC_OFFSET, prog.vsync);
        compiler_fence(Ordering::SeqCst);
    }

    fn program_pipe(&mut self, mode: &Mode) {
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

    fn program_mn(&mut self, mode: &Mode, rate: LinkRate, lanes: u8) {
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

    fn program_plane(&mut self, fb: &Framebuffer, mode: &Mode) {
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
        use crate::dp_link_training::{train_link, LinkError, LinkRate as TrainRate};
        let mut aux = IntelAux::with_base(self.mmio, self.port.aux_base());
        match train_link(&mut aux, TrainRate::Hbr2, 4, |_us| core::hint::spin_loop()) {
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

    fn enable_transcoder(&mut self) {
        use crate::intel_gpu_pipes::{
            Transcoder, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
        };
        let off = Transcoder::A.conf_base() + PIPECONF_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur | PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, off, PIPECONF_STATE, true, 100_000_000);
    }

    fn enable_pipe(&mut self) {
        use crate::intel_gpu_pipes::{
            Pipe as PipeIdx, PIPECONF_ENABLE, PIPECONF_OFFSET, PIPECONF_STATE,
        };
        let off = PipeIdx::A.base() + PIPECONF_OFFSET;
        let cur = self.mmio.read32(off);
        self.mmio.write32(off, cur | PIPECONF_ENABLE);
        compiler_fence(Ordering::SeqCst);
        let _ = wait_bit(self.mmio, off, PIPECONF_STATE, true, 100_000_000);
    }

    fn enable_plane(&mut self) {
        // Armed by program_plane's SURF write; spin one frame so
        // the flip lands before returning (same posture as the
        // Gen12 orchestrator's Stage-2 vblank barrier).
        let budget = narf_time::wall::ns_to_cycles(20_000_000);
        let start = narf_time::now_cycles();
        while narf_time::now_cycles().wrapping_sub(start) < budget {
            core::hint::spin_loop();
        }
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

/// Poll an MMIO register's `mask` bits (same helper shape as the
/// Gen12 modeset's `wait_bit`).
fn wait_bit<M: MmioWindow + ?Sized>(
    mmio: &M,
    off: u64,
    mask: u32,
    want_set: bool,
    timeout_ns: u64,
) -> bool {
    let budget = narf_time::wall::ns_to_cycles(timeout_ns);
    let start = narf_time::now_cycles();
    loop {
        let v = mmio.read32(off);
        if (v & mask != 0) == want_set {
            return true;
        }
        if narf_time::now_cycles().wrapping_sub(start) > budget {
            return false;
        }
        core::hint::spin_loop();
    }
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
        aux_data: RefCell<[u32; 5]>,
        aux_ctl_read: Cell<u32>,
        aux_reply: RefCell<Vec<u8>>,
        dpcd: RefCell<[u8; 0x1000]>,
        pub hbr2_cr_fails: Cell<bool>,
        refuse_color: Cell<u64>,
    }

    const PIPECONF_OFF: u64 = 0x7_0008;

    impl MtlFake {
        pub fn new(port: XeLpgPort) -> Self {
            Self {
                phy: FakePhy::new(port),
                port,
                writes: RefCell::new(Vec::new()),
                wells: RefCell::new(Vec::new()),
                wells_dead: Cell::new(false),
                cdclk_pll: Cell::new(0),
                pipeconf: Cell::new(0),
                aux_data: RefCell::new([0; 5]),
                aux_ctl_read: Cell::new(0),
                aux_reply: RefCell::new(Vec::new()),
                dpcd: RefCell::new([0; 0x1000]),
                hbr2_cr_fails: Cell::new(false),
                refuse_color: Cell::new(u64::MAX),
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
                    for i in 0..len {
                        let a = (addr + i) & 0xFFF;
                        self.dpcd.borrow_mut()[a] = wire[4 + i];
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
                self.pipeconf
                    .set(val & !crate::intel_gpu_pipes::PIPECONF_STATE);
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
        // Power wells: PW_1 + PW_A requested in CTL2, AUX_A in
        // AUX2.
        let ctl2 = fake.writes_to(PWR_WELL_CTL2);
        if !ctl2.iter().any(|v| v & pwr_well_req(PW_1_IDX) != 0)
            || !ctl2.iter().any(|v| v & pwr_well_req(PW_A_IDX) != 0)
        {
            return TestResult::Fail("PW_1 / PW_A not requested");
        }
        if !fake
            .writes_to(PWR_WELL_CTL_AUX2)
            .iter()
            .any(|v| v & pwr_well_req(0) != 0)
        {
            return TestResult::Fail("AUX_A well not requested");
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

    fn smoke_mtl_modeset_tc1_full_run() -> TestResult {
        let fake = MtlFake::new(XeLpgPort::Tc1);
        let mut ms = XeLpgModeset::new(&fake, XeLpgPort::Tc1);
        if ms
            .modeset(&test_fb(), Some(&Mode::VESA_1024X768_60))
            .is_err()
        {
            return TestResult::Fail("MTL TC1 modeset must complete against the MTL fake");
        }
        // C20 message bus lives at the TC block offsets.
        if fake.writes_to(0x16_F240).is_empty() {
            return TestResult::Fail("no C20 message-bus traffic at TC1 offsets");
        }
        // No VALFREQ register exists on C20 ports.
        if !fake.writes_to(0x6_4030).is_empty() || !fake.writes_to(0x6_4130).is_empty() {
            return TestResult::Fail("VALFREQ written for a C20 port");
        }
        // Transcoder clock select routes PHY TC1 (index 2).
        if fake.writes_to(TRANS_CLK_SEL_A) != [0x3000_0000u32] {
            return TestResult::Fail("TRANS_CLK_SEL must route PHY TC1 (0x30000000)");
        }
        // TRANS_DDI_FUNC_CTL carries the TC1 select encoding
        // (enum port 9, +1 in the field).
        let func = fake.writes_to(0x6_0400);
        match func.last() {
            Some(v) if (v >> 27) & 0xF == 10 => {}
            _ => return TestResult::Fail("TRANS_DDI_FUNC_CTL select must encode TC1 (10)"),
        }
        // AUX_USBC1 well (index 3) requested.
        if !fake
            .writes_to(PWR_WELL_CTL_AUX2)
            .iter()
            .any(|v| v & pwr_well_req(3) != 0)
        {
            return TestResult::Fail("AUX_USBC1 well not requested");
        }
        // The C20 PLL state landed in an SRAM context
        // (C20_B_MPLLB_CNTX_CFG = 0xCB4E with the fake's
        // toggle-clear start).
        if fake.phy.sram_get(0xCB4E) == 0 {
            return TestResult::Fail("C20 MPLLB context not programmed in SRAM");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_modeset_xelpg",
        smoke_mtl_modeset_tc1_full_run
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
        fake.phy
            .write32(CDCLK_SQUASH_CTL, CDCLK_SQUASH_ENABLE | 0xAD5A);
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
        fake.phy.write32(0x70040, 1);
        assert!(owner.poll(&fake, 200).unwrap().is_some());
        // Restore CTM so control readback below also verifies baseline retention.
        owner.arm(&fake, None, 201).unwrap();
        fake.phy.write32(0x70040, 2);
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
        let disabled = writes
            .iter()
            .position(|&(r, v)| r == PIPECONF_OFF && v & (3 << 30) == 0)
            .unwrap();
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
}
