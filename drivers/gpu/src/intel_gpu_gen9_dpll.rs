//! Gen9 (Skylake / Kaby Lake / Coffee Lake / Whiskey Lake /
//! Comet Lake) DPLL manager — the SKL WRPLL + CFGCR1/2 half
//! the Gen11 DPLL module explicitly left to this lane
//! (`intel_gpu_gen11_dpll` header: "the SKL CFGCR1/2
//! registers and the SKL WRPLL divider search
//! (`skl_ddi_calculate_wrpll` ...) are Gen9-lane work").
//!
//! Mirrors Linux `display/intel_dpll_mgr.c` (7.4-rc2,
//! `skl_pll_mgr`):
//! - register map: `skl_dpll_regs` — DPLL0 is `LCPLL1_CTL`
//!   0x46010 with no CFGCR (it drives CDCLK; see
//!   [`crate::intel_gpu_gen9_cdclk`]); DPLL1 is
//!   `LCPLL2_CTL` 0x46014 + `DPLL_CFGCR1/2` 0x6C040/0x6C044;
//!   DPLL2 is `WRPLL_CTL(0)` 0x46040 + 0x6C048/0x6C04C;
//!   DPLL3 is `WRPLL_CTL(1)` 0x46060 + 0x6C050/0x6C054.
//!   Lock status is `DPLL_STATUS` 0x6C060,
//!   `DPLL_LOCK(id)` = bit `id * 8`.
//! - DP: `skl_ddi_dp_set_dpll_hw_state` — the state is
//!   `DPLL_CTRL1` only (OVERRIDE + link rate), computed by
//!   the already-transcribed
//!   [`crate::intel_gpu_gen11_dpll::dp_ctrl1`]; there is no
//!   CFGCR state for DP. eDP takes DPLL0 only; external DP
//!   takes any of DPLL1/2/3 (`skl_get_dpll`).
//! - HDMI: `skl_ddi_hdmi_pll_dividers` — the state is
//!   `DPLL_CTRL1` OVERRIDE|HDMI_MODE plus the CFGCR1/2 pair
//!   packed from the SKL WRPLL divider search
//!   ([`calculate_wrpll`]).
//! - enable/disable: `skl_ddi_pll_enable` (write CTRL1, write
//!   CFGCR1/2, posting reads, RMW the CTL enable bit, wait
//!   `DPLL_STATUS` LOCK 5 ms) and `skl_ddi_pll_disable`
//!   (RMW the CTL enable bit clear, posting read). DPLL0's
//!   enable is CTRL1-only (`skl_ddi_dpll0_enable`) and its
//!   disable is a no-op (`skl_ddi_dpll0_disable` is empty —
//!   DPLL0 is always on, it drives CDCLK).
//! - port clock mux: `skl_ddi_enable_clock` /
//!   `skl_ddi_disable_clock` (`display/intel_ddi.c`) program
//!   `DPLL_CTRL2` 0x6C05C — per-port clock select (bits
//!   `port * 3 + 1`), select-override (bit `port * 3`) and
//!   clock-off (bit `port + 15`).
//!
//! ## The SKL WRPLL search is NOT the CNL/ICL one
//!
//! `intel_gpu_pll::hdmi_wrpll_coeffs` (`cnl_ddi_calculate_wrpll`)
//! searches one divider list for a DCO in the 7.998–10 GHz
//! window closest to its 8.999 GHz centre. The SKL search
//! (`skl_ddi_calculate_wrpll`) is a different algorithm and
//! its divider tables were NOT reused:
//! - two divider lists, even first (35 entries) then odd
//!   (3, 5, 7, 9, 15, 21, 35); an even solution always wins
//!   over an odd one;
//! - three central frequencies (8.4 / 9.0 / 9.6 GHz) with a
//!   per-candidate deviation window of +1% / -6%
//!   (`SKL_DCO_MAX_PDEVIATION` 100 / `SKL_DCO_MAX_NDEVIATION`
//!   600, in 0.01% units), keeping the smallest deviation;
//! - the winning total divider decomposes through
//!   `skl_wrpll_get_multipliers`, and
//!   `skl_wrpll_params_populate` packs it with the central
//!   frequency encoded 9.6 GHz → 0, 9.0 GHz → 1, 8.4 GHz → 3.
//!
//! The reference clock for the search is `nssc`, which
//! `skl_update_dpll_ref_clks` sets to the CDCLK reference —
//! the fixed 24 MHz (`intel_gpu_gen9_cdclk::REFCLK_KHZ`), not
//! a strap. Callers pass it in; the search itself is
//! refclk-parameterised.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gen11_dpll::{
    ctrl1_hdmi_mode, ctrl1_override, dp_ctrl1, read_ctrl1, write_ctrl1,
};

/// SKL shared DPLL identifiers (`DPLL_ID_SKL_DPLL0..3`,
/// `display/intel_dpll_mgr.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SklDpllId {
    /// DPLL 0 — drives CDCLK, DP/eDP only, no CFGCR.
    Dpll0,
    /// DPLL 1 — WRPLL, HDMI/DP.
    Dpll1,
    /// DPLL 2 — WRPLL, HDMI/DP.
    Dpll2,
    /// DPLL 3 — WRPLL, HDMI/DP.
    Dpll3,
}

impl SklDpllId {
    /// The shared PLL id (0-3).
    pub const fn id(self) -> u32 {
        match self {
            SklDpllId::Dpll0 => 0,
            SklDpllId::Dpll1 => 1,
            SklDpllId::Dpll2 => 2,
            SklDpllId::Dpll3 => 3,
        }
    }
}

/// `LCPLL1_CTL` 0x46010 (DPLL0 CTL, shared with the CDCLK
/// module).
pub const LCPLL1_CTL: u64 = 0x46010;
/// `LCPLL2_CTL` 0x46014 (DPLL1 CTL).
pub const LCPLL2_CTL: u64 = 0x46014;
/// `WRPLL_CTL(0)` 0x46040 (DPLL2 CTL).
pub const WRPLL_CTL_0: u64 = 0x46040;
/// `WRPLL_CTL(1)` 0x46060 (DPLL3 CTL).
pub const WRPLL_CTL_1: u64 = 0x46060;
/// `LCPLL_PLL_ENABLE` (bit 31, shared by the CTL registers).
pub const PLL_ENABLE: u32 = 1 << 31;

/// The CTL register for a DPLL (`skl_dpll_regs[].ctl`).
pub const fn ctl_reg(id: SklDpllId) -> u64 {
    match id {
        SklDpllId::Dpll0 => LCPLL1_CTL,
        SklDpllId::Dpll1 => LCPLL2_CTL,
        SklDpllId::Dpll2 => WRPLL_CTL_0,
        SklDpllId::Dpll3 => WRPLL_CTL_1,
    }
}

/// The CFGCR1 register for a DPLL (`DPLL_CFGCR1(id)`:
/// 0x6C040 + (id - 1) * 8). `None` for DPLL0, which has no
/// CFGCR.
pub const fn cfgcr1_reg(id: SklDpllId) -> Option<u64> {
    match id {
        SklDpllId::Dpll0 => None,
        SklDpllId::Dpll1 => Some(0x6C040),
        SklDpllId::Dpll2 => Some(0x6C048),
        SklDpllId::Dpll3 => Some(0x6C050),
    }
}

/// The CFGCR2 register for a DPLL (`DPLL_CFGCR2(id)`:
/// 0x6C044 + (id - 1) * 8). `None` for DPLL0.
pub const fn cfgcr2_reg(id: SklDpllId) -> Option<u64> {
    match id {
        SklDpllId::Dpll0 => None,
        SklDpllId::Dpll1 => Some(0x6C044),
        SklDpllId::Dpll2 => Some(0x6C04C),
        SklDpllId::Dpll3 => Some(0x6C054),
    }
}

/// `DPLL_STATUS` 0x6C060.
pub const DPLL_STATUS: u64 = 0x6C060;

/// `DPLL_LOCK(id)` — bit `id * 8` of `DPLL_STATUS`.
pub const fn dpll_lock_bit(id: SklDpllId) -> u32 {
    1 << (id.id() * 8)
}

/// `DPLL_CTRL2` 0x6C05C (DDI clock select).
pub const DPLL_CTRL2: u64 = 0x6C05C;

/// `DPLL_CTRL2_DDI_CLK_SEL(port)` — the PLL id for a port,
/// bits `port * 3 + 1`.
pub const fn ctrl2_clk_sel(port: Ddi, id: SklDpllId) -> u32 {
    id.id() << ((port as u32) * 3 + 1)
}

/// `DPLL_CTRL2_DDI_CLK_SEL_MASK(port)`.
pub const fn ctrl2_clk_sel_mask(port: Ddi) -> u32 {
    0x3 << ((port as u32) * 3 + 1)
}

/// `DPLL_CTRL2_DDI_SEL_OVERRIDE(port)` — bit `port * 3`.
pub const fn ctrl2_sel_override(port: Ddi) -> u32 {
    1 << ((port as u32) * 3)
}

/// `DPLL_CTRL2_DDI_CLK_OFF(port)` — bit `port + 15`.
pub const fn ctrl2_clk_off(port: Ddi) -> u32 {
    1 << ((port as u32) + 15)
}

/// `DPLL_CFGCR1_FREQ_ENABLE` (bit 31).
pub const CFGCR1_FREQ_ENABLE: u32 = 1 << 31;
/// `DPLL_CFGCR1_DCO_FRACTION(x)` — bits 23:9.
pub const fn cfgcr1_dco_fraction(frac: u32) -> u32 {
    (frac & 0x7fff) << 9
}
/// `DPLL_CFGCR1_DCO_INTEGER_MASK` — bits 8:0.
pub const CFGCR1_DCO_INTEGER_MASK: u32 = 0x1ff;
/// `DPLL_CFGCR2_QDIV_RATIO(x)` — bits 15:8.
pub const fn cfgcr2_qdiv_ratio(ratio: u32) -> u32 {
    (ratio & 0xff) << 8
}
/// `DPLL_CFGCR2_QDIV_MODE(x)` — bit 7.
pub const fn cfgcr2_qdiv_mode(mode: u32) -> u32 {
    (mode & 0x1) << 7
}
/// `DPLL_CFGCR2_KDIV(x)` — bits 6:5.
pub const fn cfgcr2_kdiv(kdiv: u32) -> u32 {
    (kdiv & 0x3) << 5
}
/// `DPLL_CFGCR2_PDIV(x)` — bits 4:2.
pub const fn cfgcr2_pdiv(pdiv: u32) -> u32 {
    (pdiv & 0x7) << 2
}

// ── SKL WRPLL divider search ─────────────────────────────────

/// `skl_wrpll_params`: the divider search's output, before
/// CFGCR packing. `central_freq` is the encoded value
/// (9.6 GHz → 0, 9.0 GHz → 1, 8.4 GHz → 3);
/// `pdiv`/`kdiv` are the encoded field values (PDIV 1/2/3/7
/// → 0/1/2/4, KDIV 5/2/3/1 → 0/1/2/3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SklWrpllParams {
    pub dco_fraction: u32,
    pub dco_integer: u32,
    pub qdiv_ratio: u32,
    pub qdiv_mode: u32,
    pub kdiv: u32,
    pub pdiv: u32,
    pub central_freq: u32,
}

/// Even total dividers, in search order
/// (`skl_ddi_calculate_wrpll`).
const EVEN_DIVIDERS: &[u8] = &[
    4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 30, 32, 36, 40, 42, 44, 48, 52, 54, 56, 60, 64, 66,
    68, 70, 72, 76, 78, 80, 84, 88, 90, 92, 96, 98,
];
/// Odd total dividers, in search order.
const ODD_DIVIDERS: &[u8] = &[3, 5, 7, 9, 15, 21, 35];
/// DCO central frequencies in Hz, in search order.
const DCO_CENTRAL_FREQ_HZ: &[u64] = &[8_400_000_000, 9_000_000_000, 9_600_000_000];
/// `SKL_DCO_MAX_PDEVIATION` — +1%, in 0.01% units.
const MAX_PDEVIATION: u64 = 100;
/// `SKL_DCO_MAX_NDEVIATION` — -6%, in 0.01% units.
const MAX_NDEVIATION: u64 = 600;

/// `skl_wrpll_try_divider`: accept a candidate whose DCO
/// sits within +1% / -6% of a central frequency and beats
/// the best deviation so far (strictly — ties keep the
/// first candidate found).
fn try_divider(
    best_dev: &mut u64,
    best_central: &mut u64,
    best_divider: &mut u32,
    central_freq: u64,
    dco_freq: u64,
    divider: u32,
) {
    let deviation = 10_000 * dco_freq.abs_diff(central_freq) / central_freq;
    if dco_freq >= central_freq {
        if deviation < MAX_PDEVIATION && deviation < *best_dev {
            *best_dev = deviation;
            *best_central = central_freq;
            *best_divider = divider;
        }
    } else if deviation < MAX_NDEVIATION && deviation < *best_dev {
        *best_dev = deviation;
        *best_central = central_freq;
        *best_divider = divider;
    }
}

/// `skl_wrpll_get_multipliers`: decompose a winning total
/// divider into (pdiv, qdiv, kdiv) — the *values* (1/2/3/7,
/// ratio, 1/2/3/5), not the encoded fields.
fn multipliers(divider: u32) -> Option<(u32, u32, u32)> {
    if divider % 2 == 0 {
        let half = divider / 2;
        if matches!(half, 1 | 2 | 3 | 5) {
            Some((2, 1, half))
        } else if half % 2 == 0 {
            Some((2, half / 2, 2))
        } else if half % 3 == 0 {
            Some((3, half / 3, 2))
        } else if half % 7 == 0 {
            Some((7, half / 7, 2))
        } else {
            None
        }
    } else if divider == 3 || divider == 9 {
        Some((3, 1, divider / 3))
    } else if divider == 5 || divider == 7 {
        Some((divider, 1, 1))
    } else if divider == 15 {
        Some((3, 1, 5))
    } else if divider == 21 {
        Some((7, 1, 3))
    } else if divider == 35 {
        Some((7, 1, 5))
    } else {
        None
    }
}

/// `skl_wrpll_params_populate`: DCO + dividers into the
/// parameter struct. `ref_clock_khz` is `nssc` (24 MHz on
/// SKL).
fn populate(
    afe_clock_hz: u64,
    ref_clock_khz: u32,
    central_freq: u64,
    p0: u32,
    p1: u32,
    p2: u32,
) -> SklWrpllParams {
    let central_freq_enc = match central_freq {
        9_600_000_000 => 0,
        9_000_000_000 => 1,
        _ => 3,
    };
    let pdiv = match p0 {
        1 => 0,
        2 => 1,
        3 => 2,
        _ => 4,
    };
    let kdiv = match p2 {
        5 => 0,
        2 => 1,
        3 => 2,
        _ => 3,
    };
    let dco_freq = p0 as u64 * p1 as u64 * p2 as u64 * afe_clock_hz;
    let dco_integer = (dco_freq / (ref_clock_khz as u64 * 1000)) as u32;
    // Linux: ((dco_freq / (ref_clock / 1000) - dco_integer *
    // 1_000_000) * 0x8000) / 1_000_000 — ref_clock/1000 is an
    // integer division (24000 kHz -> 24).
    let dco_fraction =
        (((dco_freq / (ref_clock_khz as u64 / 1000)) - dco_integer as u64 * 1_000_000) * 0x8000
            / 1_000_000) as u32;
    SklWrpllParams {
        dco_fraction,
        dco_integer,
        qdiv_ratio: p1,
        qdiv_mode: u32::from(p1 != 1),
        kdiv,
        pdiv,
        central_freq: central_freq_enc,
    }
}

/// `skl_ddi_calculate_wrpll`: the SKL WRPLL divider search
/// for a port clock in kHz under reference `ref_clock_khz`
/// (24 MHz on SKL). `None` when no (even, then odd) divider
/// lands a DCO within +1% / -6% of a central frequency.
pub fn calculate_wrpll(port_clock_khz: u32, ref_clock_khz: u32) -> Option<SklWrpllParams> {
    let afe_clock_hz = port_clock_khz as u64 * 1000 * 5;
    let mut best_dev = u64::MAX;
    let mut best_central = 0u64;
    let mut best_divider = 0u32;
    for (d, dividers) in [EVEN_DIVIDERS, ODD_DIVIDERS].iter().enumerate() {
        for &central in DCO_CENTRAL_FREQ_HZ {
            for &divider in dividers.iter() {
                let dco_freq = divider as u64 * afe_clock_hz;
                try_divider(
                    &mut best_dev,
                    &mut best_central,
                    &mut best_divider,
                    central,
                    dco_freq,
                    divider as u32,
                );
                // A zero deviation cannot be improved.
                if best_dev == 0 {
                    break;
                }
            }
            if best_dev == 0 {
                break;
            }
        }
        // An even-divider solution is preferred over any odd one.
        if d == 0 && best_divider != 0 {
            break;
        }
    }
    if best_divider == 0 {
        return None;
    }
    let (p0, p1, p2) = multipliers(best_divider)?;
    Some(populate(
        afe_clock_hz,
        ref_clock_khz,
        best_central,
        p0,
        p1,
        p2,
    ))
}

/// `skl_ddi_wrpll_get_freq`: recover the port clock (kHz) a
/// packed WRPLL state produces, under `ref_clock_khz`.
/// `None` for a state whose dividers do not decode (the
/// `PDIV_7_INVALID` BIOS quirk — an ASUS-Z170M setting the
/// hardware treats as PDIV_7 — is folded in, as in Linux).
pub fn wrpll_get_freq(params: &SklWrpllParams, ref_clock_khz: u32) -> Option<u32> {
    let p0 = match params.pdiv {
        0 => 1,
        1 => 2,
        2 => 3,
        4 | 5 => 7,
        _ => return None,
    };
    let p2 = match params.kdiv {
        0 => 5,
        1 => 2,
        2 => 3,
        3 => 1,
        _ => return None,
    };
    let p1 = if params.qdiv_mode == 1 {
        params.qdiv_ratio
    } else {
        1
    };
    if p0 == 0 || p1 == 0 || p2 == 0 {
        return None;
    }
    let mut dco_freq = params.dco_integer * ref_clock_khz;
    // Linux reads the packed CFGCR1 field, where the fraction
    // sits at bits 23:9, so it shifts right by 9 before
    // scaling; here `dco_fraction` is already the unshifted
    // 15-bit value, so it scales directly.
    dco_freq += (params.dco_fraction & 0x7fff) * ref_clock_khz / 0x8000;
    Some(dco_freq / (p0 * p1 * p2 * 5))
}

// ── Computed DPLL state ──────────────────────────────────────

/// The computed hardware state for one SKL DPLL: the
/// `DPLL_CTRL1` field (unshifted, id 0 — see the comment in
/// `intel_dpll_hw_state`) plus, for DPLL1/2/3 in HDMI mode,
/// the CFGCR1/2 pair. DP states carry `ctrl1` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SklDpllState {
    pub ctrl1: u32,
    pub cfgcr1: Option<u32>,
    pub cfgcr2: Option<u32>,
}

impl SklDpllState {
    /// Pack WRPLL parameters into the CFGCR1/2 pair
    /// (`skl_ddi_hdmi_pll_dividers`): CFGCR1 = FREQ_ENABLE |
    /// DCO fraction << 9 | DCO integer; CFGCR2 = QDIV ratio |
    /// QDIV mode | KDIV | PDIV | central frequency.
    pub const fn from_wrpll(params: &SklWrpllParams) -> Self {
        Self {
            // hdmi_ctrl1() is not const, so the OVERRIDE |
            // HDMI_MODE pair is spelled out with the const
            // helpers here.
            ctrl1: ctrl1_override(0) | ctrl1_hdmi_mode(0),
            cfgcr1: Some(
                CFGCR1_FREQ_ENABLE
                    | cfgcr1_dco_fraction(params.dco_fraction)
                    | (params.dco_integer & CFGCR1_DCO_INTEGER_MASK),
            ),
            cfgcr2: Some(
                cfgcr2_qdiv_ratio(params.qdiv_ratio)
                    | cfgcr2_qdiv_mode(params.qdiv_mode)
                    | cfgcr2_kdiv(params.kdiv)
                    | cfgcr2_pdiv(params.pdiv)
                    | (params.central_freq & 0x3),
            ),
        }
    }
}

/// `skl_ddi_hdmi_pll_dividers`: the HDMI state for a port
/// clock (kHz) under `ref_clock_khz`, plus the port clock
/// the packed state actually produces (the DCO fraction
/// quantises it — Linux writes the recomputed clock back
/// into `crtc_state->port_clock`).
pub fn hdmi_state(port_clock_khz: u32, ref_clock_khz: u32) -> Option<(SklDpllState, u32)> {
    let params = calculate_wrpll(port_clock_khz, ref_clock_khz)?;
    let state = SklDpllState::from_wrpll(&params);
    let actual = wrpll_get_freq(&params, ref_clock_khz)?;
    Some((state, actual))
}

/// `skl_ddi_dp_set_dpll_hw_state`: the DP state for a port
/// clock (kHz) — `DPLL_CTRL1` only. `None` for a port clock
/// with no programmed link rate.
pub fn dp_state(port_clock_khz: u32) -> Option<SklDpllState> {
    Some(SklDpllState {
        ctrl1: dp_ctrl1(port_clock_khz)?,
        cfgcr1: None,
        cfgcr2: None,
    })
}

/// `skl_get_dpll`: the DPLL pool for an output. eDP takes
/// DPLL0 only; every other output takes the first free of
/// DPLL1/2/3 (arbitration is the modeset's — this only
/// names the pool).
pub fn dpll_pool(is_edp: bool) -> &'static [SklDpllId] {
    if is_edp {
        &[SklDpllId::Dpll0]
    } else {
        &[SklDpllId::Dpll1, SklDpllId::Dpll2, SklDpllId::Dpll3]
    }
}

// ── Enable / disable ─────────────────────────────────────────

/// DPLL sequencing failure modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpllError {
    /// Current access was lost or a register read all-ones.
    NoDevice,
    /// A lock transition did not arrive inside 5 ms.
    Timeout,
}

fn wait_lock(io: &(impl MmioWindow + ?Sized), id: SklDpllId) -> Result<(), DpllError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let value = io.read32(DPLL_STATUS);
            lost = value == u32::MAX || !io.display_access_ok();
            lost || value & dpll_lock_bit(id) != 0
        },
        narf_time::Deadline::after_us(5_000),
    );
    if lost {
        Err(DpllError::NoDevice)
    } else if done {
        Ok(())
    } else {
        Err(DpllError::Timeout)
    }
}

/// `skl_ddi_pll_enable`: write CTRL1, write CFGCR1/2 (HDMI
/// states on DPLL1/2/3), posting-read them, RMW the CTL
/// enable bit, wait `DPLL_STATUS` LOCK (5 ms). DPLL0's
/// enable is CTRL1-only (`skl_ddi_dpll0_enable` — DPLL0 is
/// always on, it drives CDCLK).
pub fn pll_enable(
    io: &(impl MmioWindow + ?Sized),
    id: SklDpllId,
    state: &SklDpllState,
) -> Result<(), DpllError> {
    write_ctrl1(io, id.id(), state.ctrl1);
    if let (Some(cfgcr1), Some(cfgcr2)) = (state.cfgcr1, state.cfgcr2) {
        let r1 = cfgcr1_reg(id).expect("HDMI state needs a CFGCR1 register");
        let r2 = cfgcr2_reg(id).expect("HDMI state needs a CFGCR2 register");
        io.write32(r1, cfgcr1);
        io.write32(r2, cfgcr2);
        let _ = io.read32(r1);
        let _ = io.read32(r2);
    }
    let ctl = ctl_reg(id);
    let cur = io.read32(ctl);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(ctl, cur | PLL_ENABLE);
    wait_lock(io, id)
}

/// `skl_ddi_pll_disable`: RMW the CTL enable bit clear,
/// posting-read the CTL. DPLL0's disable is a no-op
/// (`skl_ddi_dpll0_disable` is empty).
pub fn pll_disable(io: &(impl MmioWindow + ?Sized), id: SklDpllId) -> Result<(), DpllError> {
    if matches!(id, SklDpllId::Dpll0) {
        return Ok(());
    }
    let ctl = ctl_reg(id);
    let cur = io.read32(ctl);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(ctl, cur & !PLL_ENABLE);
    let _ = io.read32(ctl);
    Ok(())
}

/// `skl_ddi_pll_get_hw_state` (ctrl1 half): the DPLL's
/// 6-bit field, unshifted — re-exported from the Gen11
/// module's SKL section for the readback path.
pub fn read_hw_ctrl1(io: &(impl MmioWindow + ?Sized), id: SklDpllId) -> u32 {
    read_ctrl1(io, id.id())
}

// ── DDI clock mux (`DPLL_CTRL2`, `intel_ddi.c`) ─────────────

/// `skl_ddi_enable_clock`: RMW `DPLL_CTRL2` — clear the
/// port's CLK_OFF and CLK_SEL, set CLK_SEL to `id` plus
/// SEL_OVERRIDE.
pub fn enable_clock(io: &(impl MmioWindow + ?Sized), port: Ddi, id: SklDpllId) {
    let cur = io.read32(DPLL_CTRL2);
    io.write32(
        DPLL_CTRL2,
        (cur & !(ctrl2_clk_off(port) | ctrl2_clk_sel_mask(port)))
            | ctrl2_clk_sel(port, id)
            | ctrl2_sel_override(port),
    );
}

/// `skl_ddi_disable_clock`: RMW `DPLL_CTRL2` — set the
/// port's CLK_OFF.
pub fn disable_clock(io: &(impl MmioWindow + ?Sized), port: Ddi) {
    let cur = io.read32(DPLL_CTRL2);
    io.write32(DPLL_CTRL2, cur | ctrl2_clk_off(port));
}

/// `skl_ddi_is_clock_enabled`: the port's CLK_OFF bit clear.
pub fn is_clock_enabled(io: &(impl MmioWindow + ?Sized), port: Ddi) -> bool {
    io.read32(DPLL_CTRL2) & ctrl2_clk_off(port) == 0
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::intel_gpu_gen11_dpll::{hdmi_ctrl1, DPLL_CTRL1};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted SKL DPLL endpoint: the four CTL registers, the
    /// CFGCR1/2 registers, `DPLL_STATUS` (LOCK follows ENABLE
    /// unless `grant_lock` is cleared), `DPLL_CTRL1` and
    /// `DPLL_CTRL2` stores.
    struct DpllMmio {
        ctl: RefCell<[u32; 4]>,
        cfgcr1: RefCell<[u32; 3]>,
        cfgcr2: RefCell<[u32; 3]>,
        ctrl1: RefCell<u32>,
        ctrl2: RefCell<u32>,
        grant_lock: bool,
        writes: RefCell<Vec<(u64, u32)>>,
    }

    impl DpllMmio {
        fn new() -> Self {
            Self {
                ctl: RefCell::new([0; 4]),
                cfgcr1: RefCell::new([0; 3]),
                cfgcr2: RefCell::new([0; 3]),
                ctrl1: RefCell::new(0),
                ctrl2: RefCell::new(0),
                grant_lock: true,
                writes: RefCell::new(Vec::new()),
            }
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }

        fn status(&self) -> u32 {
            let ctl = self.ctl.borrow();
            let mut status = 0u32;
            for (i, c) in ctl.iter().enumerate() {
                if self.grant_lock && c & PLL_ENABLE != 0 {
                    status |= dpll_lock_bit(match i {
                        0 => SklDpllId::Dpll0,
                        1 => SklDpllId::Dpll1,
                        2 => SklDpllId::Dpll2,
                        _ => SklDpllId::Dpll3,
                    });
                }
            }
            status
        }
    }

    impl MmioWindow for DpllMmio {
        fn read32(&self, off: u64) -> u32 {
            match off {
                o if o == LCPLL1_CTL => self.ctl.borrow()[0],
                o if o == LCPLL2_CTL => self.ctl.borrow()[1],
                o if o == WRPLL_CTL_0 => self.ctl.borrow()[2],
                o if o == WRPLL_CTL_1 => self.ctl.borrow()[3],
                o if o == 0x6C040 => self.cfgcr1.borrow()[0],
                o if o == 0x6C048 => self.cfgcr1.borrow()[1],
                o if o == 0x6C050 => self.cfgcr1.borrow()[2],
                o if o == 0x6C044 => self.cfgcr2.borrow()[0],
                o if o == 0x6C04C => self.cfgcr2.borrow()[1],
                o if o == 0x6C054 => self.cfgcr2.borrow()[2],
                o if o == DPLL_CTRL1 => *self.ctrl1.borrow(),
                o if o == DPLL_CTRL2 => *self.ctrl2.borrow(),
                o if o == DPLL_STATUS => self.status(),
                _ => 0,
            }
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            match off {
                o if o == LCPLL1_CTL => self.ctl.borrow_mut()[0] = val,
                o if o == LCPLL2_CTL => self.ctl.borrow_mut()[1] = val,
                o if o == WRPLL_CTL_0 => self.ctl.borrow_mut()[2] = val,
                o if o == WRPLL_CTL_1 => self.ctl.borrow_mut()[3] = val,
                o if o == 0x6C040 => self.cfgcr1.borrow_mut()[0] = val,
                o if o == 0x6C048 => self.cfgcr1.borrow_mut()[1] = val,
                o if o == 0x6C050 => self.cfgcr1.borrow_mut()[2] = val,
                o if o == 0x6C044 => self.cfgcr2.borrow_mut()[0] = val,
                o if o == 0x6C04C => self.cfgcr2.borrow_mut()[1] = val,
                o if o == 0x6C054 => self.cfgcr2.borrow_mut()[2] = val,
                o if o == DPLL_CTRL1 => *self.ctrl1.borrow_mut() = val,
                o if o == DPLL_CTRL2 => *self.ctrl2.borrow_mut() = val,
                _ => {}
            }
        }
    }

    fn smoke_skl_dpll_register_map() -> TestResult {
        if ctl_reg(SklDpllId::Dpll0) != 0x46010
            || ctl_reg(SklDpllId::Dpll1) != 0x46014
            || ctl_reg(SklDpllId::Dpll2) != 0x46040
            || ctl_reg(SklDpllId::Dpll3) != 0x46060
        {
            return TestResult::Fail("DPLL CTL register map wrong");
        }
        if cfgcr1_reg(SklDpllId::Dpll0).is_some() || cfgcr2_reg(SklDpllId::Dpll0).is_some() {
            return TestResult::Fail("DPLL0 must have no CFGCR registers");
        }
        if cfgcr1_reg(SklDpllId::Dpll1) != Some(0x6C040)
            || cfgcr2_reg(SklDpllId::Dpll1) != Some(0x6C044)
            || cfgcr1_reg(SklDpllId::Dpll2) != Some(0x6C048)
            || cfgcr2_reg(SklDpllId::Dpll2) != Some(0x6C04C)
            || cfgcr1_reg(SklDpllId::Dpll3) != Some(0x6C050)
            || cfgcr2_reg(SklDpllId::Dpll3) != Some(0x6C054)
        {
            return TestResult::Fail("DPLL CFGCR register map wrong");
        }
        if dpll_lock_bit(SklDpllId::Dpll0) != 1
            || dpll_lock_bit(SklDpllId::Dpll1) != 0x100
            || dpll_lock_bit(SklDpllId::Dpll2) != 0x10000
            || dpll_lock_bit(SklDpllId::Dpll3) != 0x1000000
        {
            return TestResult::Fail("DPLL_STATUS lock bits wrong");
        }
        // DPLL_CTRL2 field positions for port B.
        if ctrl2_clk_sel(Ddi::B, SklDpllId::Dpll2) != 2 << 4
            || ctrl2_clk_sel_mask(Ddi::B) != 0x3 << 4
            || ctrl2_sel_override(Ddi::B) != 1 << 3
            || ctrl2_clk_off(Ddi::B) != 1 << 16
        {
            return TestResult::Fail("DPLL_CTRL2 field positions wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dpll",
        smoke_skl_dpll_register_map
    );

    fn smoke_skl_wrpll_vectors() -> TestResult {
        // The search's output (divider, deviation, CFGCR pair
        // and recovered clock) for the reference port clocks,
        // computed against the Linux search.
        struct Case {
            clock: u32,
            cfgcr1: u32,
            cfgcr2: u32,
            recovered: u32,
        }
        const CASES: &[Case] = &[
            Case {
                clock: 27_000,
                cfgcr1: 2_151_678_323,
                cfgcr2: 2985,
                recovered: 27_000,
            },
            Case {
                clock: 74_250,
                cfgcr1: 2_151_678_323,
                cfgcr2: 1701,
                recovered: 74_250,
            },
            Case {
                clock: 148_500,
                cfgcr1: 2_151_678_323,
                cfgcr2: 933,
                recovered: 148_500,
            },
            Case {
                clock: 297_000,
                cfgcr1: 2_151_678_323,
                cfgcr2: 325,
                recovered: 297_000,
            },
            Case {
                clock: 594_000,
                cfgcr1: 2_151_678_323,
                cfgcr2: 361,
                recovered: 594_000,
            },
            Case {
                clock: 162_000,
                cfgcr1: 2_155_872_593,
                cfgcr2: 263,
                recovered: 162_000,
            },
            Case {
                clock: 540_000,
                cfgcr1: 2_155_872_593,
                cfgcr2: 363,
                recovered: 540_000,
            },
            Case {
                clock: 25_000,
                cfgcr1: 2_147_484_023,
                cfgcr2: 4773,
                recovered: 25_000,
            },
            // The DCO fraction quantises 65 MHz to 64999 kHz —
            // Linux writes the recomputed clock back, so the
            // search's output is 64999, not 65000.
            Case {
                clock: 65_000,
                cfgcr1: 2_150_280_059,
                cfgcr2: 1956,
                recovered: 64_999,
            },
        ];
        for case in CASES {
            let Some((state, actual)) = hdmi_state(case.clock, 24_000) else {
                return TestResult::Fail("WRPLL search must find a state");
            };
            if state.cfgcr1 != Some(case.cfgcr1) || state.cfgcr2 != Some(case.cfgcr2) {
                return TestResult::Fail("WRPLL CFGCR pair wrong");
            }
            if actual != case.recovered {
                return TestResult::Fail("WRPLL recovered clock wrong");
            }
            if state.ctrl1 != hdmi_ctrl1() {
                return TestResult::Fail("HDMI state must carry OVERRIDE|HDMI_MODE");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_dpll", smoke_skl_wrpll_vectors);

    fn smoke_skl_wrpll_odd_and_none() -> TestResult {
        // 25 MHz takes an even divider (72, deviation 0) — the
        // even list is preferred even when an odd divider also
        // lands inside the window.
        let Some(params) = calculate_wrpll(25_000, 24_000) else {
            return TestResult::Fail("25 MHz must find a WRPLL state");
        };
        if params.qdiv_ratio != 18 || params.qdiv_mode != 1 {
            return TestResult::Fail("25 MHz must take divider 72 = 2 * 18 * 2");
        }
        // A clock with no divider inside the window refuses.
        // 1 GHz: every even divider's DCO is ≥ 20 GHz, every
        // odd divider's ≥ 15 GHz — nothing within +1% / -6%
        // of 8.4 / 9.0 / 9.6 GHz.
        if calculate_wrpll(1_000_000, 24_000).is_some() {
            return TestResult::Fail("1 GHz must find no WRPLL state");
        }
        // The odd-divider decomposition is pinned directly
        // (no in-window clock in the test set wins on an odd
        // divider — the even list is preferred whenever it
        // lands inside the window at all).
        if multipliers(9) != Some((3, 1, 3))
            || multipliers(35) != Some((7, 1, 5))
            || multipliers(21) != Some((7, 1, 3))
        {
            return TestResult::Fail("odd divider decomposition wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dpll",
        smoke_skl_wrpll_odd_and_none
    );

    fn smoke_skl_dpll_dp_state_and_pool() -> TestResult {
        // DP state is CTRL1 only, no CFGCR.
        let Some(state) = dp_state(270_000) else {
            return TestResult::Fail("270 MHz DP must have a state");
        };
        if state.cfgcr1.is_some() || state.cfgcr2.is_some() {
            return TestResult::Fail("DP state must carry no CFGCR pair");
        }
        if state.ctrl1 != dp_ctrl1(270_000).unwrap() {
            return TestResult::Fail("DP state must be the DPLL_CTRL1 link rate");
        }
        // No link rate for an unprogrammed port clock.
        if dp_state(123_456).is_some() {
            return TestResult::Fail("an unprogrammed port clock must have no DP state");
        }
        // eDP takes DPLL0 only; everything else the pool.
        if dpll_pool(true) != &[SklDpllId::Dpll0] {
            return TestResult::Fail("eDP must take DPLL0 only");
        }
        if dpll_pool(false) != &[SklDpllId::Dpll1, SklDpllId::Dpll2, SklDpllId::Dpll3] {
            return TestResult::Fail("external outputs must take the DPLL1/2/3 pool");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dpll",
        smoke_skl_dpll_dp_state_and_pool
    );

    fn smoke_skl_dpll_enable_disable() -> TestResult {
        // HDMI enable on DPLL2: CTRL1, CFGCR1/2, CTL enable,
        // lock in DPLL_STATUS.
        let mmio = DpllMmio::new();
        let (state, _) = hdmi_state(148_500, 24_000).unwrap();
        if pll_enable(&mmio, SklDpllId::Dpll2, &state).is_err() {
            return TestResult::Fail("HDMI enable on DPLL2 must succeed");
        }
        if mmio.writes_to(DPLL_CTRL1) != alloc::vec![state.ctrl1] {
            return TestResult::Fail("enable must write CTRL1 once");
        }
        if mmio.writes_to(0x6C048) != alloc::vec![state.cfgcr1.unwrap()]
            || mmio.writes_to(0x6C04C) != alloc::vec![state.cfgcr2.unwrap()]
        {
            return TestResult::Fail("enable must write the CFGCR1/2 pair once");
        }
        if mmio.writes_to(WRPLL_CTL_0) != alloc::vec![PLL_ENABLE] {
            return TestResult::Fail("enable must set the CTL enable bit");
        }
        if mmio.status() & dpll_lock_bit(SklDpllId::Dpll2) == 0 {
            return TestResult::Fail("enabled DPLL2 must report locked");
        }
        // Disable clears the enable bit (and is a no-op on DPLL0).
        if pll_disable(&mmio, SklDpllId::Dpll2).is_err() {
            return TestResult::Fail("disable must succeed");
        }
        if mmio.writes_to(WRPLL_CTL_0) != alloc::vec![PLL_ENABLE, 0] {
            return TestResult::Fail("disable must clear the CTL enable bit");
        }
        let writes_before = mmio.writes.borrow().len();
        if pll_disable(&mmio, SklDpllId::Dpll0).is_err() {
            return TestResult::Fail("DPLL0 disable must succeed");
        }
        if mmio.writes.borrow().len() != writes_before {
            return TestResult::Fail("DPLL0 disable must be a no-op");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dpll",
        smoke_skl_dpll_enable_disable
    );

    fn smoke_skl_dpll_lock_timeout() -> TestResult {
        let mut mmio = DpllMmio::new();
        mmio.grant_lock = false;
        let (state, _) = hdmi_state(148_500, 24_000).unwrap();
        if pll_enable(&mmio, SklDpllId::Dpll1, &state) != Err(DpllError::Timeout) {
            return TestResult::Fail("a DPLL that never locks must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dpll",
        smoke_skl_dpll_lock_timeout
    );

    fn smoke_skl_dpll_clock_mux() -> TestResult {
        let mmio = DpllMmio::new();
        // Enable port B on DPLL2: SEL = 2, OVERRIDE set,
        // CLK_OFF clear.
        enable_clock(&mmio, Ddi::B, SklDpllId::Dpll2);
        let want = ctrl2_clk_sel(Ddi::B, SklDpllId::Dpll2) | ctrl2_sel_override(Ddi::B);
        if mmio.writes_to(DPLL_CTRL2) != alloc::vec![want] {
            return TestResult::Fail("enable_clock must set SEL + OVERRIDE");
        }
        if !is_clock_enabled(&mmio, Ddi::B) {
            return TestResult::Fail("enabled port clock must read as enabled");
        }
        // Disable sets CLK_OFF, preserving the SEL bits.
        disable_clock(&mmio, Ddi::B);
        if mmio.writes_to(DPLL_CTRL2) != alloc::vec![want, want | ctrl2_clk_off(Ddi::B)] {
            return TestResult::Fail("disable_clock must only set CLK_OFF");
        }
        if is_clock_enabled(&mmio, Ddi::B) {
            return TestResult::Fail("disabled port clock must read as disabled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_dpll", smoke_skl_dpll_clock_mux);
}
