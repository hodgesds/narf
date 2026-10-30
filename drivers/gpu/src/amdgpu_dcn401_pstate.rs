//! DCN4.0.1 UCLK P-state support with displays lit: Linux DML21's
//! `dml2_top_soc15_build_mode_programming` from the latency phase through
//! the UCLK P-state phase (`dml2_pmo_dcn4_fams2.c`), the stutter phase and
//! DPMM (`dml2_dpmm_dcn4.c`), on the board's whole UCLK DPM table
//! (`dml2_mcg_dcn4`'s min-clock table) instead of the native policy's one
//! pinned level.
//!
//! PMO's options are DC's for DCN401 (`dml21_populate_pmo_options` with
//! the debug defaults): vblank allowed; SubVP, DRR and FAMS2 only when the
//! DMUB firmware reports FAMS 2.1 (`fams2`); even-odd ("alternate") off.
//! The strategy lists, their permutations and DRR variants, the per-stream
//! P-state meta, the synchronized timing groups and the schedulability
//! checks are Linux's, and so is the candidate search with its latency
//! index increases. DCC includes the MRQ metadata-row blackout budget and
//! native mcache placement. `admit_with_drr` carries live refresh limits and
//! permits hardware vactive/vblank or FAMS2 clamped/stretch strategies.
//! SubVP remains pinned without a phantom-pipe/MALL owner; the runtime DRR
//! search skips those unavailable candidates. Raised DPMM clocks beyond the
//! latency state remain outside this port.
use super::*;

/// `enum dml2_pstate_method` (dml_top_types.h) values PMO assigns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Method {
    #[default]
    Na = 0,
    Vactive = 1,
    Vblank = 2,
    FwSvp = 6,
    FwVactiveDrr = 11,
    FwVblankDrr = 12,
    FwSvpDrr = 13,
    FwDrr = 21,
    Alternate = 23,
}

impl Method {
    /// PMO_FW_STRATEGY_MASK: methods the DMUB firmware schedules.
    pub fn firmware(self) -> bool {
        matches!(
            self,
            Self::FwSvp | Self::FwVactiveDrr | Self::FwVblankDrr | Self::FwSvpDrr | Self::FwDrr
        )
    }
    /// PMO_DRR_CLAMPED_STRATEGY_MASK (fw_vactive_drr..reserved_fw_drr_clamped).
    fn drr_clamped(self) -> bool {
        (11..=20).contains(&(self as u8))
    }
    /// PMO_DRR_VAR_STRATEGY_MASK (fw_drr..reserved_fw_drr_var).
    fn drr_var(self) -> bool {
        (21..=22).contains(&(self as u8))
    }
    /// convert_strategy_to_drr_variant.
    fn drr_variant(self) -> Self {
        match self {
            Self::Vactive => Self::FwVactiveDrr,
            Self::Vblank => Self::FwVblankDrr,
            Self::FwSvp => Self::FwSvpDrr,
            m => m,
        }
    }
    /// `enum fams2_stream_type` for the stream's FAMS2 base state.
    pub fn fams2_type(self) -> u8 {
        match self {
            Self::Vactive | Self::FwVactiveDrr => 2,
            Self::Vblank | Self::FwVblankDrr => 1,
            Self::FwDrr => 3,
            Self::FwSvp | Self::FwSvpDrr => 4,
            Self::Na | Self::Alternate => 0,
        }
    }
}

/// `struct dml2_pmo_pstate_strategy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Strategy {
    pub methods: [Method; MAX_STREAMS],
    pub allow_state_increase: bool,
}

const fn base(m: [Method; MAX_STREAMS], allow_state_increase: bool) -> Strategy {
    Strategy {
        methods: m,
        allow_state_increase,
    }
}
use Method::{Alternate as A, FwDrr as D, FwSvp as S, Na as N, Vactive as V, Vblank as B};
/// base_strategy_list_1_display..4_display.
const BASE: [&[Strategy]; MAX_STREAMS] = [
    &[
        base([V, N, N, N], true),
        base([S, N, N, N], true),
        base([A, N, N, N], true),
        base([B, N, N, N], false),
        base([D, N, N, N], true),
    ],
    &[
        base([V, V, N, N], true),
        base([A, A, N, N], true),
        base([V, B, N, N], false),
        base([B, B, N, N], false),
        base([S, B, N, N], false),
        base([S, D, N, N], true),
        base([S, S, N, N], true),
        base([V, D, N, N], true),
        base([D, D, N, N], true),
    ],
    &[
        base([V, V, V, N], true),
        base([A, A, A, N], true),
        base([V, V, B, N], false),
        base([B, B, B, N], false),
        base([D, D, D, N], true),
    ],
    &[
        base([V, V, V, V], true),
        base([A, A, A, A], true),
        base([V, V, V, B], false),
        base([B, B, B, B], false),
        base([D, D, D, D], true),
    ],
];

/// expand_base_strategy: every distinct permutation of the strategy's
/// per-stream methods, in Linux's iteration order.
fn expand_base(b: &Strategy, n: usize, out: &mut Vec<Strategy>) {
    let mut per = [0usize; MAX_STREAMS];
    let mut idx = [0usize; MAX_STREAMS];
    // Each method counted at its first occurrence.
    for m in &b.methods[..n] {
        if let Some(j) = b.methods[..n].iter().position(|x| x == m) {
            per[j] += 1;
        }
    }
    let mut cur = Strategy {
        allow_state_increase: b.allow_state_increase,
        ..Strategy::default()
    };
    let mut i = 0;
    while idx[0] < n {
        let (mut next, mut added, mut skip) = (false, false, false);
        if idx[i] < n && per[idx[i]] != 0 {
            cur.methods[i] = b.methods[idx[i]];
            per[idx[i]] -= 1;
            if i >= n - 1 {
                out.push(cur);
                added = true;
            } else {
                next = true;
            }
        } else {
            skip = true;
        }
        if next {
            i += 1;
        } else {
            if !skip {
                per[idx[i]] += 1;
            }
            idx[i] += 1;
            if (idx[i] >= n || added) && i > 0 {
                idx[i] = 0;
                i -= 1;
                per[idx[i]] += 1;
                idx[i] += 1;
            }
        }
    }
}

/// dcn4_expand_variant_strategy: the strategy with DRR variants for some
/// streams of each method, permuted (`permute`) or as listed.
fn expand_variants(b: &Strategy, n: usize, permute: bool, out: &mut Vec<Strategy>) {
    let mut per = [0usize; MAX_STREAMS];
    let mut variant_of = [Method::Na; MAX_STREAMS];
    for (i, m) in b.methods[..n].iter().enumerate() {
        if let Some(j) = b.methods[..n].iter().position(|x| x == m) {
            per[j] += 1;
        }
        variant_of[i] = m.drr_variant();
    }
    let mut nb = per;
    let mut nv = [0usize; MAX_STREAMS];
    let mut v = *b;
    let mut m = 0usize;
    while nb[0] > 0 || m != 0 {
        if m == n {
            let mut found = false;
            let mut s = 0;
            for i in 0..n {
                for _ in 0..nb[i] {
                    v.methods[s] = b.methods[i];
                    s += 1;
                }
                for _ in 0..nv[i] {
                    v.methods[s] = variant_of[i];
                    s += 1;
                    if b.methods[i] != variant_of[i] {
                        found = true;
                    }
                }
            }
            // is_variant_method_valid: no vblank with a vblank_drr, nor two
            // vblank_drr.
            let valid = (0..n).all(|i| {
                !(b.methods[i] == Method::Vblank && ((nb[i] > 0 && nv[i] > 0) || nv[i] > 1))
            });
            if found && valid {
                if permute {
                    expand_base(&v, n, out);
                } else {
                    out.push(v);
                }
            }
            m = n - 1;
            while m > 0 {
                if nb[m] != 0 {
                    break;
                }
                nb[m] = per[m];
                nv[m] = 0;
                m -= 1;
            }
        }
        if nb[m] != 0 {
            nb[m] -= 1;
            nv[m] += 1;
            m += 1;
        } else if m != 0 {
            m += 1;
        }
    }
}

/// pmo_dcn4_fams2_initialize's expanded list for `n` streams.
pub fn strategies(n: usize) -> Vec<Strategy> {
    let mut out = Vec::new();
    if (1..=MAX_STREAMS).contains(&n) {
        for b in BASE[n - 1] {
            expand_base(b, n, &mut out);
            expand_variants(b, n, true, &mut out);
        }
    }
    out
}

// dml2_dcn401_max_ip_caps.fams2 and dml2_socbb_dcn401's blackout.
const MAX_ALLOW_DELAY: f64 = 100_000.0;
const SCHEDULING_DELAY_US: f64 = 550.0;
const VINT_ACK_DELAY_US: u32 = 40;
const ALLOW_PROGRAMMING_DELAY_US: u32 = 18;
const MIN_ALLOW_WIDTH_US: f64 = 20.0;
const SUBVP_DF_THROTTLE_DELAY_US: f64 = 100.0;
const SUBVP_PROGRAMMING_DELAY_US: u32 = 200;
const SUBVP_PREFETCH_TO_MALL_DELAY_US: f64 = 18.0;
const DRR_PROGRAMMING_DELAY_US: u32 = 35;
const MAX_VACTIVE_DET_FILL_DELAY_US: f64 = 400.0;
const BLACKOUT_US: f64 = DRAM_CLK_CHANGE_US as f64;
/// MIN_VACTIVE_MARGIN_PCT of the blackout.
const MIN_VACTIVE_MARGIN_US: f64 = 0.25 * BLACKOUT_US;
/// pmo->fams_params.v2.subvp.refresh_rate_limit_max (min is 0).
const SUBVP_MAX_REFRESH_HZ: f64 = 175.0;
/// DML2_PMO_PSTATE_CANDIDATE_LIST_SIZE.
const CANDIDATES: usize = 10;
/// ip_caps.otg_count (DCN401: four).
const OTGS: usize = 4;

/// DML's math_ceil: `(int)(x + 0.99999)`.
fn ceil_int(x: f64) -> i32 {
    (x + 0.99999) as i32
}

/// `struct dml2_pstate_per_method_common_meta`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Common {
    allow_start: i32,
    allow_end: i32,
    period_us: f64,
    allow_time_us: f64,
    disallow_time_us: f64,
}

impl Common {
    /// build_method_scheduling_params.
    fn schedule(&mut self, vline_us: f64) {
        self.allow_time_us = f64::from(self.allow_end - self.allow_start) * vline_us;
        self.disallow_time_us = if self.allow_time_us >= self.period_us {
            0.0
        } else {
            self.period_us - self.allow_time_us
        };
    }
}

/// `struct dml2_pstate_meta` (what the hardware methods and the SubVP
/// candidacy check read).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Meta {
    vline_us: f64,
    scheduling: i32,
    vint_ack: i32,
    allow_to_target: i32,
    contention: i32,
    min_allow_width: i32,
    nom_vtotal: i32,
    vblank_start: i32,
    nom_refresh_hz: f64,
    max_vtotal: i32,
    blackout: i32,
    vactive_fill_lines: i32,
    vactive_fill_us: f64,
    vactive: Common,
    vblank: Common,
    subvp: Common,
    subvp_programming: i32,
    subvp_prefetch_to_mall: i32,
    phantom_vtotal: i32,
    drr: Common,
    drr_programming: i32,
}

/// build_pstate_meta_per_stream for a fixed-refresh stream of `t` among
/// `streams`; `phantom` is mode support's (phantom_min_v_active,
/// phantom_v_startup) for the stream.
fn meta(t: &Timing, streams: usize, phantom: (i32, i32)) -> Meta {
    let contention_us =
        (VINT_ACK_DELAY_US + SUBVP_PROGRAMMING_DELAY_US) * (streams as u32).saturating_sub(1);
    let vline = f64::from(t.h_total) / f64::from(t.pixel_clock_khz) * 1000.0;
    let lines = |us: f64| ceil_int(us / vline);
    let nom_vtotal = t.v_total as i32;
    let mut m = Meta {
        vline_us: vline,
        nom_vtotal,
        nom_refresh_hz: f64::from(t.pixel_clock_khz) * 1000.0
            / f64::from(t.v_total.wrapping_mul(t.h_total)),
        vblank_start: (t.v_blank_end() + t.v_active) as i32,
        max_vtotal: nom_vtotal,
        scheduling: lines(SCHEDULING_DELAY_US),
        vint_ack: lines(f64::from(VINT_ACK_DELAY_US)),
        contention: lines(f64::from(contention_us)),
        allow_to_target: lines(f64::from(
            VINT_ACK_DELAY_US + contention_us + ALLOW_PROGRAMMING_DELAY_US,
        )) + 1,
        min_allow_width: lines(MIN_ALLOW_WIDTH_US),
        blackout: lines(BLACKOUT_US),
        ..Meta::default()
    };
    let frame_us = f64::from(nom_vtotal) * vline;
    // vactive: one stream gets at least an instant of allow in vactive;
    // several are bounded by the IP's fill delay.
    m.vactive_fill_lines = if streams == 1 {
        let v = f64::from(t.v_active)
            - max_f(1.0, f64::from(m.min_allow_width))
            - f64::from(m.blackout);
        max_f(0.0, v) as i32
    } else {
        (MAX_VACTIVE_DET_FILL_DELAY_US / vline) as i32
    };
    m.vactive_fill_us = f64::from(m.vactive_fill_lines) * vline;
    if m.vactive_fill_us > 0.0 {
        m.vactive.allow_start = t.v_blank_end() as i32 + m.vactive_fill_lines;
        m.vactive.allow_end = m.vblank_start - m.blackout;
    }
    m.vactive.period_us = frame_us;
    m.vactive.schedule(vline);
    m.vblank.allow_start = m.vblank_start;
    m.vblank.allow_end = m.vblank_start + 1;
    m.vblank.period_us = frame_us;
    m.vblank.schedule(vline);
    // subvp
    m.subvp_programming = lines(f64::from(SUBVP_PROGRAMMING_DELAY_US));
    let df_throttle = lines(SUBVP_DF_THROTTLE_DELAY_US);
    m.subvp_prefetch_to_mall = lines(SUBVP_PREFETCH_TO_MALL_DELAY_US);
    let phantom_vactive = m.allow_to_target + m.min_allow_width + phantom.0;
    m.phantom_vtotal = phantom.1 + df_throttle + 1 + df_throttle + phantom_vactive;
    m.subvp.allow_start = t.v_blank_end() as i32
        + m.contention
        + m.subvp_programming
        + m.phantom_vtotal
        + m.subvp_prefetch_to_mall
        + m.allow_to_target;
    m.subvp.allow_end = m.vblank_start - m.blackout;
    m.subvp.period_us = frame_us;
    m.subvp.schedule(vline);
    // drr
    m.drr_programming = lines(f64::from(DRR_PROGRAMMING_DELAY_US));
    m.drr.allow_start = m.vblank_start + m.allow_to_target;
    m.drr.period_us = frame_us;
    let stretched = if streams <= 1 {
        nom_vtotal + m.allow_to_target + m.min_allow_width + m.blackout
    } else {
        nom_vtotal * 2 + m.allow_to_target + m.min_allow_width + m.blackout
    };
    m.drr.allow_end = stretched - m.blackout;
    m.drr.schedule(vline);
    m
}

/// What PMO knows of the configuration between candidates.
struct Pmo<'a> {
    modes: &'a [Mode],
    shapes: &'a [Shape],
    fams2: bool,
    drr: [Option<crate::amdgpu_freesync::Drr>; MAX_STREAMS],
    metas: [Meta; MAX_STREAMS],
    /// Each stream's planes (stream_plane_mask), as plane indices.
    planes: [u8; MAX_STREAMS],
    vactive_capable: u8,
    /// Synchronized timing groups: stream masks.
    groups: Vec<u8>,
}

/// dml2_timing_cfg equality (memcmp) for two native streams: the timing
/// DML takes, DSC and the output format (no DRR; DC passes every stream at
/// its own bpc, which the native modes leave out).
fn same_timing(a: &Mode, b: &Mode) -> bool {
    let (x, y) = (&a.timing, &b.timing);
    x.pixel_clock_khz == y.pixel_clock_khz
        && x.h_active == y.h_active
        && x.h_total == y.h_total
        && x.h_front_porch == y.h_front_porch
        && x.h_sync_width == y.h_sync_width
        && x.v_active == y.v_active
        && x.v_total == y.v_total
        && x.v_front_porch == y.v_front_porch
        && a.dsc == b.dsc
        && a.encoding == b.encoding
}

impl Pmo<'_> {
    fn streams(&self) -> usize {
        self.modes.len()
    }
    fn plane_mask(&self, s: usize) -> u8 {
        self.planes[s]
    }
    /// dcn4_get_vactive_pstate_margin.
    fn margin(&self, sup: &Support, s: usize) -> i32 {
        (0..MAX_PLANES)
            .filter(|&k| self.plane_mask(s) & 1 << k != 0)
            .map(|k| sup.vactive_margin_us[k])
            .min()
            .unwrap_or(0x0fff_ffff)
            .min(0x0fff_ffff)
    }
    /// get_vactive_det_fill_latency_delay_us.
    fn fill_delay(&self, sup: &Support, s: usize) -> u32 {
        (0..MAX_PLANES)
            .filter(|&k| self.plane_mask(s) & 1 << k != 0)
            .map(|k| sup.fill_delay_us[k])
            .max()
            .unwrap_or(0)
    }
    /// stream_matches_drr_policy with active variable refresh. Hardware
    /// exclusive methods remain valid for one stream; multiple streams need
    /// firmware clamping or stretching so their allow windows stay schedulable.
    fn drr_policy_ok(&self, method: Method, stream: usize) -> bool {
        let active = self.drr[stream].is_some();
        if method.firmware() && !self.fams2 {
            return false;
        }
        if method.drr_clamped() || method.drr_var() {
            return active && self.fams2;
        }
        !(active && (self.streams() > 1 || method.firmware()))
    }
    /// all_timings_support_svp, with every plane's rect_out spanning the
    /// stream's vactive unless an overlay shares it, and no rotation.
    fn svp_ok(&self, mask: u8) -> bool {
        let mut per_stream = [0u8; MAX_STREAMS];
        let mut mcaches = 0u32;
        for s in self.shapes {
            let mut own = s.mcaches;
            if mask & 1 << s.stream != 0 {
                per_stream[s.stream] += 1;
                let p = &s.plane;
                let out_h = if p.vertical_scan {
                    u64::from(p.viewport_width)
                } else {
                    u64::from(p.viewport_height)
                };
                let v = if p.vertical_scan {
                    p.h_ratio
                } else {
                    p.v_ratio
                };
                let dst = (out_h * u64::from(Plane::UNITY) + u64::from(v) / 2) / u64::from(v);
                if per_stream[s.stream] > 1 || dst < u64::from(s.t.v_active) || p.vertical_scan {
                    return false;
                }
                if p.dcc {
                    own *= 2;
                }
            }
            mcaches += own;
        }
        if mcaches > DCC_MCACHES {
            return false;
        }
        (0..self.streams())
            .filter(|&i| mask & 1 << i != 0)
            .all(|i| {
                let m = &self.metas[i];
                let micro = m.contention
                    + m.subvp_programming
                    + m.phantom_vtotal
                    + m.subvp_prefetch_to_mall
                    + m.blackout;
                micro < self.modes[i].timing.v_active as i32
                    && m.nom_refresh_hz <= SUBVP_MAX_REFRESH_HZ
            })
    }
    /// validate_pstate_support_strategy_cofunctionality.
    fn cofunctional(&self, st: &Strategy) -> bool {
        let n = self.streams();
        let (mut svp, mut vactive, mut vblank, mut drr, mut alternate) = (0u8, 0u8, 0u8, 0u8, 0u8);
        for (i, &m) in st.methods[..n].iter().enumerate() {
            if !self.drr_policy_ok(m, i) {
                return false;
            }
            let bit = 1 << i;
            match m {
                Method::FwSvp | Method::FwSvpDrr => svp |= bit,
                Method::FwDrr => drr |= bit,
                Method::Vactive | Method::FwVactiveDrr => vactive |= bit,
                Method::Vblank | Method::FwVblankDrr => vblank |= bit,
                Method::Alternate => alternate |= bit,
                Method::Na => {}
            }
        }
        if vactive != 0 && vactive & !self.vactive_capable != 0 {
            return false;
        }
        // all_timings_support_vblank: the vblank streams are one whole
        // synchronized group.
        if vblank != 0 {
            let first = vblank.trailing_zeros() as usize;
            if self.groups.iter().find(|&&g| g & 1 << first != 0) != Some(&vblank) {
                return false;
            }
        }
        if (0..n).filter(|&i| drr & (1 << i) != 0).any(|i| {
            let m = &self.metas[i];
            self.drr[i].is_none()
                || m.drr.allow_end + m.blackout > m.max_vtotal
                || !(119.0..=1000.0).contains(&m.nom_refresh_hz)
        }) {
            return false;
        }
        if svp != 0 && (!self.fams2 || !self.svp_ok(svp)) {
            return false;
        }
        // disable_alternate_memory_training.
        if alternate != 0 {
            return false;
        }
        self.schedulable(st)
    }
    fn common(&self, m: Method, s: usize) -> Option<Common> {
        let meta = &self.metas[s];
        match m {
            Method::Vactive | Method::FwVactiveDrr => Some(meta.vactive),
            Method::Vblank | Method::FwVblankDrr | Method::Alternate => Some(meta.vblank),
            Method::FwSvp | Method::FwSvpDrr => Some(meta.subvp),
            Method::FwDrr => Some(meta.drr),
            Method::Na => None,
        }
    }
    /// is_timing_group_schedulable.
    fn group(&self, st: &Strategy, g: u8) -> Option<Common> {
        let base = g.trailing_zeros() as usize;
        let mut c = self.common(st.methods[base], base)?;
        for i in base + 1..self.streams() {
            if g & 1 << i == 0 {
                continue;
            }
            let Some(m) = self.common(st.methods[i], i) else {
                continue;
            };
            c.allow_start = c.allow_start.max(m.allow_start);
            c.allow_end = c.allow_end.min(m.allow_end);
            if c.allow_start >= c.allow_end {
                return None;
            }
        }
        c.schedule(self.metas[base].vline_us);
        (c.allow_time_us > 0.0 && c.disallow_time_us < MAX_ALLOW_DELAY).then_some(c)
    }
    /// is_config_schedulable.
    fn schedulable(&self, st: &Strategy) -> bool {
        let mut groups = Vec::with_capacity(self.groups.len());
        let mut max_delay = 0.0;
        for &g in &self.groups {
            let Some(c) = self.group(st, g) else {
                return false;
            };
            max_delay += c.disallow_time_us;
            groups.push(c);
        }
        let n = groups.len();
        if n <= 1 {
            return true;
        }
        // STAGE 2: the worst disallow cannot mask any allow.
        let mut by_disallow: Vec<usize> = (0..n).collect();
        bubble(&mut by_disallow, |i| groups[i].disallow_time_us);
        let mut ok = true;
        for i in 0..n {
            if groups[i].disallow_time_us <= 0.0 {
                continue;
            }
            let mut max_allow = groups[i].allow_time_us;
            for &j in &by_disallow {
                if i != j && groups[j].disallow_time_us > 0.0 {
                    max_allow = min_f(
                        groups[j].allow_time_us,
                        (max_allow - groups[j].disallow_time_us) / 2.0,
                    );
                    if max_allow < 0.0 {
                        break;
                    }
                }
            }
            if max_allow <= 0.0 {
                ok = false;
                break;
            }
        }
        if ok && max_delay < MAX_ALLOW_DELAY {
            return true;
        }
        // STAGE 3: the larger allow fits every other period (no DRR).
        let mut by_period: Vec<usize> = (0..n).collect();
        bubble(&mut by_period, |i| groups[i].period_us);
        let ok = (0..n - 1).all(|i| {
            groups[by_period[i]].allow_time_us >= groups[by_period[i + 1]].period_us
                && !(0..self.streams()).any(|stream| {
                    self.groups[by_period[i + 1]] & (1 << stream) != 0 && self.drr[stream].is_some()
                })
        });
        if ok && max_delay < MAX_ALLOW_DELAY {
            return true;
        }
        // STAGE 4: two hardware-exclusive groups drifting apart.
        if n == 2 && !st.methods[0].firmware() && !st.methods[1].firmware() {
            let (lrg, sml) = if groups[0].period_us < groups[1].period_us {
                (1, 0)
            } else {
                (0, 1)
            };
            let ratio = groups[lrg].period_us / groups[sml].period_us;
            let shift = groups[sml].period_us * (ratio - f64::from(ratio as i32));
            let max_shift = groups[lrg].disallow_time_us - groups[sml].allow_time_us;
            let delay = max_shift / shift * groups[lrg].period_us;
            return shift > 0.0
                && shift < groups[lrg].allow_time_us + groups[sml].allow_time_us
                && delay < MAX_ALLOW_DELAY;
        }
        false
    }
}

/// The sort is_config_schedulable runs: greatest first, bubble passes that
/// stop once nothing swaps.
fn bubble(order: &mut [usize], key: impl Fn(usize) -> f64) {
    for _ in 0..order.len() {
        let mut swapped = false;
        for j in 0..order.len().saturating_sub(1) {
            if key(order[j]) < key(order[j + 1]) {
                order.swap(j, j + 1);
                swapped = true;
            }
        }
        if !swapped {
            break;
        }
    }
}

/// The board's UCLK DPM levels, ascending (the SMU's table DC hands DML),
/// as plans record them. At most eight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UclkLevels {
    khz: [u32; 8],
    count: u8,
}

impl UclkLevels {
    pub fn new(khz: &[u32]) -> Result<Self, Error> {
        if khz.is_empty() || khz.len() > 8 || khz.windows(2).any(|w| w[0] >= w[1]) || khz[0] == 0 {
            return Err(Error::Invalid);
        }
        let mut out = Self {
            khz: [0; 8],
            count: khz.len() as u8,
        };
        out.khz[..khz.len()].copy_from_slice(khz);
        Ok(out)
    }
    pub fn levels(&self) -> &[u32] {
        &self.khz[..usize::from(self.count)]
    }
}

/// What a P-state plan records of its configuration's search, so that it
/// can be admitted again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanPstate {
    pub uclk: UclkLevels,
    /// FAMS 2.1 firmware: SubVP, DRR and FAMS2 strategies were searched.
    pub fams2: bool,
    /// This stream's method.
    pub method: Method,
    pub drr: [Option<crate::amdgpu_freesync::Drr>; MAX_STREAMS],
}

/// DPMM's minimum clocks for one SoC state, in kHz.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinClocks {
    pub uclk_khz: u32,
    pub fclk_khz: u32,
    pub dcfclk_khz: u32,
}

/// One stream's FAMS2 static base state (`struct
/// dmub_fams2_cmd_stream_static_base_state`, v1) as
/// dml2_core_calcs_get_stream_fams2_programming fills it, and its legacy
/// sub-state. DC adds the OTG and pipe masks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fams2Stream {
    pub kind: u8,
    pub otg_vline_time_ns: u32,
    pub htotal: u16,
    pub vtotal: u16,
    pub vblank_start: u16,
    pub vblank_end: u16,
    pub max_vtotal: u16,
    pub allow_start_otg_vline: u16,
    pub allow_end_otg_vline: u16,
    pub drr_keepout_otg_vline: u16,
    pub scheduling_delay_otg_vlines: u16,
    pub contention_delay_otg_vlines: u16,
    pub vline_int_ack_delay_otg_vlines: u16,
    pub allow_to_target_delay_otg_vlines: u16,
    pub is_drr: bool,
    pub clamp_vtotal_min: bool,
    pub min_ttu_vblank_usable: bool,
    /// legacy.vactive_det_fill_delay_otg_vlines (vactive only).
    pub vactive_det_fill_delay_otg_vlines: u16,
    pub drr_state: Option<DrrSubstate>,
}

/// FAMS2's DRR static sub-state (legacy methods use the fill-delay field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrrSubstate {
    pub stretched_vtotal: u16,
    pub programming_delay: u16,
}

/// A configuration with UCLK P-state switching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Supported {
    /// Each stream's plan at the chosen level, in admission order.
    pub plans: Vec<Plan>,
    pub methods: [Method; MAX_STREAMS],
    /// The min-clock-table index the plans' latencies come from.
    pub level: u8,
    /// DPMM's active and idle minimums (dcn4x.active / .idle), after
    /// clamp_fclk_to_max when FCLK switching is not supported.
    pub active: MinClocks,
    pub idle: MinClocks,
    pub fclk_pstate: bool,
    /// fams2_required: a firmware method is in use.
    pub fams2_required: bool,
    pub fams2_streams: alloc::boxed::Box<[Fams2Stream; MAX_STREAMS]>,
}

/// Why a configuration keeps the pinned-UCLK policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pinned {
    /// DML has no UCLK P-state strategy for it (uclk_pstate_supported 0).
    Unsupported,
    /// Linux's search would try SubVP before a native method, but the
    /// port has no phantom-pipe/MALL owner.
    Firmware(Method),
    /// The configuration is outside what this port plans with P-state
    /// support (a DPMM clock above the latency state).
    Port,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pstate {
    Supported(Supported),
    Pinned(Pinned),
}

/// build_min_clk_table_fine_grained with fine-grained DCFCLK and FCLK:
/// per UCLK level its DRAM bandwidth and the balanced fabric clock, every
/// level above the first at least the level below's, clamped and pruned.
fn min_clock_table(soc: &Soc, uclk: &UclkLevels) -> Vec<Level> {
    let bytes_per_tick = u64::from(soc.umc_channels) * CHANNEL_BYTES * TRANSACTIONS_PER_CLOCK;
    let mut t: Vec<Level> = uclk
        .levels()
        .iter()
        .map(|&khz| {
            let bw = u64::from(khz) * bytes_per_tick;
            let fclk = ((bw as f64 * URGENT_ACTIVE[2] as f64 / 100.0)
                / (URGENT_ACTIVE[1] as f64 / 100.0))
                / RETURN_BUS_BYTES as f64;
            Level {
                uclk_khz: khz,
                fclk_khz: fclk as u32,
                dcfclk_khz: 0,
                dram_bw_kbps: bw,
            }
        })
        .collect();
    for i in (1..t.len()).rev() {
        let prev = t[i - 1].fclk_khz;
        let half = t[i].fclk_khz / 2;
        t[i].fclk_khz = prev.max(half);
    }
    if let Some(first) = t.first_mut() {
        first.fclk_khz /= 2;
    }
    for e in &mut t {
        e.fclk_khz = e.fclk_khz.max(soc.fclk_khz[0]);
        e.fclk_khz = e.fclk_khz.min(MAX_FCLK_FOR_UCLK_KHZ as u32);
        let dcf = u64::from(e.fclk_khz) * URGENT_ACTIVE[1] as u64 / URGENT_ACTIVE[0] as u64;
        e.dcfclk_khz = (dcf * RETURN_BUS_BYTES as u64 / RETURN_BUS_BYTES as u64) as u32;
    }
    if let Some(i) = t
        .iter()
        .position(|e| e.dcfclk_khz > soc.dcfclk_khz[1] || e.fclk_khz > soc.fclk_khz[1])
    {
        t.truncate(i);
    }
    let mut i = 0;
    while i + 1 < t.len() {
        if t[i] == t[i + 1]
            || (t[i].dcfclk_khz, t[i].fclk_khz, t[i].dram_bw_kbps)
                == (
                    t[i + 1].dcfclk_khz,
                    t[i + 1].fclk_khz,
                    t[i + 1].dram_bw_kbps,
                )
        {
            t.remove(i + 1);
        } else {
            i += 1;
        }
    }
    t
}

/// One mode-support run at table entry `index` (`Err` when DML refuses).
fn run(
    soc: &Soc,
    shapes: &[Shape],
    p: &Prepared,
    table: &[Level],
    uclk: &UclkLevels,
    index: usize,
    ov: &Overrides,
) -> Result<(Evaluation, Support), Error> {
    let ctx = ctx_at(table, uclk, index);
    support(soc, shapes, p, &ctx, ov)
}

fn ctx_at(table: &[Level], uclk: &UclkLevels, index: usize) -> Ctx {
    Ctx {
        level: table[index],
        index,
        max_dram_bw_kbps: table[table.len() - 1].dram_bw_kbps,
        max_uclk_khz: *uclk.levels().last().unwrap_or(&0),
        min_dcfclk_khz: table[0].dcfclk_khz,
    }
}

/// setup_display_config for strategy `st`: every plane's overrides.
fn setup(pmo: &Pmo, st: &Strategy) -> Option<Overrides> {
    let mut ov = Overrides::NONE;
    for s in 0..pmo.streams() {
        let m = st.methods[s];
        for k in (0..MAX_PLANES).filter(|&k| pmo.plane_mask(s) & 1 << k != 0) {
            match m {
                Method::Na => return None,
                Method::Vactive | Method::FwVactiveDrr => {
                    ov.vactive[k] = true;
                    ov.fill_delay_us[k] = pmo.metas[s].vactive_fill_us as u32;
                }
                Method::Vblank | Method::FwVblankDrr => {
                    ov.reserved_us[k] = ov.reserved_us[k].max(DRAM_CLK_CHANGE_US);
                }
                _ => {}
            }
        }
    }
    Some(ov)
}

/// pmo_dcn4_fams2_test_for_pstate_support.
fn test(pmo: &Pmo, st: &Strategy, ov: &Overrides, sup: &Support) -> bool {
    (0..pmo.streams()).all(|s| match st.methods[s] {
        Method::Vactive | Method::FwVactiveDrr => {
            f64::from(pmo.margin(sup, s)) >= MIN_VACTIVE_MARGIN_US
                && f64::from(pmo.fill_delay(sup, s)) <= pmo.metas[s].vactive_fill_us
        }
        Method::Vblank | Method::FwVblankDrr => {
            (0..MAX_PLANES)
                .filter(|&k| pmo.plane_mask(s) & 1 << k != 0)
                .map(|k| ov.reserved_us[k])
                .min()
                .unwrap_or(0xff_ffff)
                >= DRAM_CLK_CHANGE_US
        }
        Method::FwSvp | Method::FwSvpDrr => true,
        Method::FwDrr => true,
        Method::Na | Method::Alternate => false,
    })
}

/// Whether Linux's mode support of a SubVP candidate certainly fails: its
/// phantom planes (one DPP each at least) or phantom streams cannot be
/// placed beside the main ones (TotalAvailablePipesSupport,
/// NumberOfOTGSupport).
fn svp_impossible(pmo: &Pmo, st: &Strategy) -> bool {
    let svp: Vec<usize> = (0..pmo.streams())
        .filter(|&s| matches!(st.methods[s], Method::FwSvp | Method::FwSvpDrr))
        .collect();
    let dpps: u32 = pmo.shapes.iter().map(|s| s.dpps).sum();
    let phantom_planes: u32 = svp.iter().map(|&s| pmo.plane_mask(s).count_ones()).sum();
    dpps + phantom_planes > MAX_PIPES.min(crate::amdgpu_rdna4::available_pipes())
        || pmo.streams() + svp.len() > OTGS
}

/// DPMM's minimums (calculate_system_active_minimums and its kin) for one
/// set of `[dcfclk, fclk, dram]` derate percents: the urgent ones (none
/// for calculate_idle_minimums) and the average ones, at least the latency
/// state's clocks, `dml_round_up`.
fn minimums(
    sup: &Support,
    lat: &Level,
    channels: u32,
    urgent: Option<[i64; 3]>,
    average: [i64; 3],
) -> [f64; 3] {
    let tick = f64::from(channels) * CHANNEL_BYTES as f64 * TRANSACTIONS_PER_CLOCK as f64;
    let pct = |p: i64| p as f64 / 100.0;
    // dram_bw_kbps_to_uclk_khz of the derated bandwidth's integer kbps.
    let dram = |kbps: u64, d: i64| ((kbps as f64 / pct(d)) as u64) as f64 / tick;
    let sdp = |kbps: u64, d: i64| kbps as f64 / RETURN_BUS_BYTES as f64 / pct(d);
    let mut uclk = dram(sup.average_dram_kbps, average[2]);
    let mut fclk = sdp(sup.average_sdp_kbps, average[1]);
    let mut dcfclk = sdp(sup.average_sdp_kbps, average[0]);
    if let Some(u) = urgent {
        uclk = max_f(dram(sup.urgent_dram_kbps, u[2]), uclk);
        fclk = max_f(sdp(sup.urgent_sdp_kbps, u[1]), fclk);
        dcfclk = max_f(sdp(sup.urgent_sdp_kbps, u[0]), dcfclk);
    }
    let round_up = |v: f64| {
        let w = v as u64;
        (if v - w as f64 > 0.0 { w + 1 } else { w }) as f64
    };
    let lat_uclk = lat.dram_bw_kbps as f64 / tick;
    [
        round_up(max_f(uclk, lat_uclk)),
        round_up(max_f(fclk, f64::from(lat.fclk_khz))),
        round_up(max_f(dcfclk, f64::from(lat.dcfclk_khz))),
    ]
}

/// dcn4x.system_idle_average derates (dcfclk, fclk, dram).
const IDLE_AVERAGE: [i64; 3] = [100, 83, 70];

/// round_up_to_next_dpm for a UCLK table: discrete levels round up to the
/// next, a two-entry (fine-grained) table takes any value up to its top.
fn uclk_dpm(uclk: &UclkLevels, khz: f64) -> Option<u32> {
    let l = uclk.levels();
    if l.len() > 2 {
        l.iter().copied().find(|&v| f64::from(v) >= khz)
    } else {
        (f64::from(*l.last()?) >= khz).then_some(khz as u32)
    }
}

/// Admit `modes` with UCLK P-state switching as Linux DML21 does on a board
/// whose UCLK DPM levels are `uclk` (`soc.uclk_khz` must be the highest,
/// as the pinned policy has it), with FAMS 2.1 firmware or not. The pinned
/// configuration must admit natively first.
pub fn admit(soc: &Soc, uclk: &UclkLevels, modes: &[Mode], fams2: bool) -> Result<Pstate, Error> {
    admit_traced(soc, uclk, modes, fams2, &mut Vec::new())
}

/// [`admit`], leaving PMO's candidate list in `candidates` (empty when the
/// search never starts).
pub(crate) fn admit_traced(
    soc: &Soc,
    uclk: &UclkLevels,
    modes: &[Mode],
    fams2: bool,
    candidates: &mut Vec<Strategy>,
) -> Result<Pstate, Error> {
    admit_config(soc, uclk, modes, fams2, [None; MAX_STREAMS], candidates)
}

/// Search with each live stream's hardware-admitted variable-refresh limits.
pub fn admit_with_drr(
    soc: &Soc,
    uclk: &UclkLevels,
    modes: &[Mode],
    fams2: bool,
    drr: [Option<crate::amdgpu_freesync::Drr>; MAX_STREAMS],
) -> Result<Pstate, Error> {
    admit_config(soc, uclk, modes, fams2, drr, &mut Vec::new())
}
fn admit_config(
    soc: &Soc,
    uclk: &UclkLevels,
    modes: &[Mode],
    fams2: bool,
    drr: [Option<crate::amdgpu_freesync::Drr>; MAX_STREAMS],
    candidates: &mut Vec<Strategy>,
) -> Result<Pstate, Error> {
    for (i, limits) in drr.iter().enumerate() {
        if let Some(limits) = limits {
            let Some(mode) = modes.get(i) else {
                return Err(Error::Invalid);
            };
            if limits.v_total_min < mode.timing.v_total
                || limits.v_total_min > limits.v_total_max
                || limits.v_total_max > crate::amdgpu_freesync::MAX_V_TOTAL
            {
                return Err(Error::Invalid);
            }
        }
    }
    if uclk.levels().last() != Some(&soc.uclk_khz) {
        return Err(Error::Invalid);
    }
    admit_native(soc, modes)?;
    let mut shapes = mcache_shapes(soc, modes, Policy::NATIVE)?;
    let mut p = prepare(soc, &mut shapes)?;
    let table = min_clock_table(soc, uclk);
    if table.is_empty() {
        return Ok(Pstate::Pinned(Pinned::Unsupported));
    }
    let top = table.len() - 1;
    let none = Overrides::NONE;
    // Speculative at the lowest entry, else the highest, then phase 1's
    // binary search for the lowest supported latency index.
    let mut stage1 = 0;
    let mut base = run(soc, &shapes, &p, &table, uclk, 0, &none);
    if base.is_err() {
        base = run(soc, &shapes, &p, &table, uclk, top, &none);
        if base.is_err() {
            return Ok(Pstate::Pinned(Pinned::Unsupported));
        }
        let (mut hi, mut lo) = (top, 0);
        while hi > lo {
            let cur = (hi + lo) / 2;
            match run(soc, &shapes, &p, &table, uclk, cur, &none) {
                Ok(r) => {
                    base = Ok(r);
                    hi = cur;
                }
                Err(_) => lo = cur + 1,
            }
        }
        stage1 = lo;
    }
    let (base_eval, base_sup) = base?;

    // pmo_dcn4_fams2_init_for_pstate_support.
    let n = modes.len();
    let mut planes = [0u8; MAX_STREAMS];
    for (k, s) in shapes.iter().enumerate() {
        planes[s.stream] |= 1 << k;
    }
    let mut metas = [Meta::default(); MAX_STREAMS];
    for (i, m) in modes.iter().enumerate() {
        // dml2_core_calcs_get_stream_support_info for the stream's first
        // plane: ceil(SubViewportLinesNeededInMALL / v_ratio) and its
        // VStartup.
        let k = planes[i].trailing_zeros() as usize;
        metas[i] = meta(&m.timing, n, shapes[k].phantom_lines(base_eval.lat.urgent));
        if let Some(drr) = drr[i] {
            metas[i].max_vtotal = drr.v_total_max as i32;
        }
    }
    let mut pmo = Pmo {
        modes,
        shapes: &shapes,
        fams2,
        drr,
        metas,
        planes,
        vactive_capable: 0,
        groups: Vec::new(),
    };
    for s in 0..n {
        if pmo.margin(&base_sup, s) >= MIN_VACTIVE_MARGIN_US as i32 {
            pmo.vactive_capable |= 1 << s;
        }
    }
    // build_synchronized_timing_groups (no DRR stream).
    let mut mapped = 0u8;
    for i in 0..n {
        if mapped & 1 << i != 0 {
            continue;
        }
        mapped |= 1 << i;
        let mut g = 1u8 << i;
        for j in i + 1..n {
            if drr[i].is_none() && drr[j].is_none() && same_timing(&modes[i], &modes[j]) {
                g |= 1 << j;
                mapped |= 1 << j;
            }
        }
        pmo.groups.push(g);
    }
    *candidates = strategies(n)
        .into_iter()
        .filter(|st| pmo.cofunctional(st))
        .take(CANDIDATES)
        .collect();
    let Some(last) = candidates.last_mut() else {
        return Ok(Pstate::Pinned(Pinned::Unsupported));
    };
    last.allow_state_increase = true;

    // dml2_top_optimization_perform_optimization_phase over the
    // candidates, all or nothing.
    let mut cur: isize = -1;
    let mut lat = stage1;
    let mut last_failed = false;
    let found = loop {
        if !(last_failed && candidates[cur as usize].allow_state_increase && lat < table.len() - 1)
        {
            lat = stage1;
            cur += 1;
            if cur as usize >= candidates.len() {
                break None;
            }
        } else {
            lat += 1;
        }
        let st = candidates[cur as usize];
        let Some(ov) = setup(&pmo, &st) else {
            break None;
        };
        if let Some(&m) = st.methods[..n]
            .iter()
            .find(|m| matches!(m, Method::FwSvp | Method::FwSvpDrr))
        {
            // Keep fixed-refresh source-vector ordering. Runtime DRR may
            // continue to a schedulable non-SubVP method without a phantom
            // owner; it never programs a SubVP candidate.
            if !svp_impossible(&pmo, &st) && drr.iter().all(Option::is_none) {
                return Ok(Pstate::Pinned(Pinned::Firmware(m)));
            }
            last_failed = true;
            continue;
        }
        match run(soc, &shapes, &p, &table, uclk, lat, &ov) {
            Err(_) => last_failed = true,
            Ok((_, sup)) => {
                last_failed = false;
                if test(&pmo, &st, &ov, &sup) {
                    break Some((st, ov, sup));
                }
            }
        }
    };
    let Some((st, mut ov, _)) = found else {
        return Ok(Pstate::Pinned(Pinned::Unsupported));
    };

    // Phase 4 follows the selected P-state candidate and retains its
    // latency index and overrides while trying each dynamic ODM factor.
    let stream_metas = pmo.metas;
    drop(pmo);
    shapes = optimize_vmin(soc, modes, shapes, |candidate| {
        prepare(soc, candidate)
            .is_ok_and(|next| run(soc, candidate, &next, &table, uclk, lat, &ov).is_ok())
    });
    p = prepare(soc, &mut shapes)?;
    let mut sup = run(soc, &shapes, &p, &table, uclk, lat, &ov)?.1;

    // Stutter phase: every plane at least the stutter latency, if every
    // blank allows it and mode support still passes.
    let reserved_ok =
        |ov: &Overrides| (0..shapes.len()).all(|k| ov.reserved_us[k] >= SR_ENTER_PLUS_EXIT_US);
    if stutter_allowed(&shapes) && !reserved_ok(&ov) {
        let mut next = ov;
        for r in &mut next.reserved_us[..shapes.len()] {
            *r = (*r).max(SR_ENTER_PLUS_EXIT_US);
        }
        if let Ok((_, s)) = run(soc, &shapes, &p, &table, uclk, lat, &next) {
            ov = next;
            sup = s;
        }
    }

    // dpmm_dcn4_map_mode_to_soc_dpm.
    let level = table[lat];
    let ch = soc.umc_channels;
    let active = minimums(&sup, &level, ch, Some(URGENT_ACTIVE), AVERAGE_ACTIVE);
    // The SVP-prefetch state (no MALL plane: the same bandwidth) with DF
    // throttling, whose minimums the active ones are boosted to.
    let svp = minimums(&sup, &level, ch, Some(URGENT_PREFETCH), AVERAGE_PREFETCH);
    let idle = minimums(&sup, &level, ch, None, IDLE_AVERAGE);
    let boosted = [
        max_f(active[0], svp[0]),
        max_f(active[1], svp[1]),
        max_f(active[2], svp[2]),
    ];
    let fine = |v: f64, max: u32| (v <= f64::from(max)).then_some(v as u32);
    let (Some(au), Some(af), Some(ad), Some(iu), Some(i_f), Some(id)) = (
        uclk_dpm(uclk, boosted[0]),
        fine(boosted[1], soc.fclk_khz[1]),
        fine(boosted[2], soc.dcfclk_khz[1]),
        uclk_dpm(uclk, idle[0]),
        fine(idle[1], soc.fclk_khz[1]),
        fine(idle[2], soc.dcfclk_khz[1]),
    ) else {
        return Ok(Pstate::Pinned(Pinned::Unsupported));
    };
    // The port plans only at the latency state's clocks.
    if au != level.uclk_khz || af != level.fclk_khz || ad != level.dcfclk_khz {
        return Ok(Pstate::Pinned(Pinned::Port));
    }
    // FCLK P-state: planes whose vactive cannot hide a zero FCLK blackout
    // must be synchronizable (each stream's reserved vblank at least zero).
    let hiding_short = (0..shapes.len())
        .filter(|&k| sup.active_hiding_us[k] < 0)
        .fold(0u8, |m, k| m | 1 << k);
    let fclk_pstate = hiding_short == 0 || {
        let idx: Vec<usize> = (0..n).filter(|&i| hiding_short & 1 << i != 0).collect();
        idx.len() <= 1
            || idx
                .windows(2)
                .all(|w| same_timing(&modes[w[0]], &modes[w[1]]))
    };
    let mut active = MinClocks {
        uclk_khz: au,
        fclk_khz: af,
        dcfclk_khz: ad,
    };
    let mut idle = MinClocks {
        uclk_khz: iu,
        fclk_khz: i_f,
        dcfclk_khz: id,
    };
    if !fclk_pstate {
        active.fclk_khz = soc.fclk_khz[1];
        idle.fclk_khz = soc.fclk_khz[1];
    }

    let ctx = ctx_at(&table, uclk, lat);
    let mut plans = Vec::with_capacity(n);
    let mut fams2_streams = [Fams2Stream::default(); MAX_STREAMS];
    let (programmed, usable) =
        program_with_ttu(soc, modes, &shapes, &p, &ctx, &ov, &st, uclk, fams2, drr)?;
    for (i, plan) in programmed.into_iter().enumerate() {
        fams2_streams[i] =
            fams2_stream(&modes[i].timing, &stream_metas[i], st.methods[i], usable[i]);
        fams2_streams[i].is_drr = drr[i].is_some();
        if st.methods[i] == Method::FwDrr {
            fams2_streams[i].allow_start_otg_vline = stream_metas[i].drr.allow_start as u16;
            fams2_streams[i].allow_end_otg_vline = stream_metas[i].drr.allow_end as u16;
            fams2_streams[i].clamp_vtotal_min = n == 1;
            fams2_streams[i].drr_state = Some(DrrSubstate {
                stretched_vtotal: (stream_metas[i].drr.allow_end + stream_metas[i].blackout) as u16,
                programming_delay: stream_metas[i].drr_programming as u8 as u16,
            });
        }
        plans.push(plan);
    }
    Ok(Pstate::Supported(Supported {
        plans,
        methods: st.methods,
        level: lat as u8,
        active,
        idle,
        fclk_pstate,
        fams2_required: st.methods[..n].iter().any(|m| m.firmware()),
        fams2_streams: alloc::boxed::Box::new(fams2_streams),
    }))
}

/// Mode programming of the chosen configuration, and per stream whether
/// every plane's MinTTUVBlank exceeds the DRAM clock change watermark
/// (FAMS2's min_ttu_vblank_usable).
#[allow(clippy::too_many_arguments)]
fn program_with_ttu(
    soc: &Soc,
    modes: &[Mode],
    shapes: &[Shape],
    p: &Prepared,
    ctx: &Ctx,
    ov: &Overrides,
    st: &Strategy,
    uclk: &UclkLevels,
    fams2: bool,
    drr: [Option<crate::amdgpu_freesync::Drr>; MAX_STREAMS],
) -> Result<(Vec<Plan>, [bool; MAX_STREAMS]), Error> {
    let mut plans = program(soc, modes, shapes, p, ctx, ov, None)?;
    let mut usable = [true; MAX_STREAMS];
    for (i, plan) in plans.iter_mut().enumerate() {
        plan.pstate = Some(PlanPstate {
            uclk: *uclk,
            fams2,
            method: st.methods[i],
            drr,
        });
        for q in plan.planes.iter().flatten() {
            if q.ttu.min_ttu_vblank <= plan.watermarks.uclk_pstate {
                usable[i] = false;
            }
        }
    }
    Ok((plans, usable))
}

/// dml2_core_calcs_get_stream_fams2_programming.
fn fams2_stream(t: &Timing, m: &Meta, method: Method, usable: bool) -> Fams2Stream {
    let vbs = m.nom_vtotal - t.v_front_porch as i32;
    let mut s = Fams2Stream {
        htotal: t.h_total as u16,
        vtotal: t.v_total as u16,
        vblank_start: vbs as u16,
        vblank_end: (vbs - t.v_active as i32) as u16,
        otg_vline_time_ns: (m.vline_us * 1000.0) as u32,
        scheduling_delay_otg_vlines: m.scheduling as u8 as u16,
        contention_delay_otg_vlines: m.contention as u8 as u16,
        vline_int_ack_delay_otg_vlines: m.vint_ack as u8 as u16,
        drr_keepout_otg_vline: (vbs - m.drr_programming) as u16,
        allow_to_target_delay_otg_vlines: m.allow_to_target as u8 as u16,
        max_vtotal: m.max_vtotal as u16,
        min_ttu_vblank_usable: usable,
        kind: method.fams2_type(),
        ..Fams2Stream::default()
    };
    match method {
        Method::Vactive | Method::FwVactiveDrr => {
            s.vactive_det_fill_delay_otg_vlines = m.vactive_fill_lines as u8 as u16;
            s.allow_start_otg_vline = m.vactive.allow_start as u16;
            s.allow_end_otg_vline = m.vactive.allow_end as u16;
            s.clamp_vtotal_min = true;
        }
        Method::Vblank | Method::FwVblankDrr => {
            s.allow_start_otg_vline = m.vblank.allow_start as u16;
            s.allow_end_otg_vline = m.vblank.allow_end as u16;
            s.clamp_vtotal_min = true;
        }
        _ => {}
    }
    s
}

impl Shape {
    /// dml2_core_calcs_get_stream_support_info's phantom_min_v_active
    /// (`math_ceil(SubViewportLinesNeededInMALL / v_ratio)`, no meta rows)
    /// and phantom_v_startup (MaxVStartupLines), from mode support's
    /// `urgent_us` latency.
    fn phantom_lines(&self, urgent_us: Fx) -> (i32, i32) {
        let line_us = f64::from(self.t.h_total) / f64::from(self.t.pixel_clock_khz) * 1000.0;
        let urgent = urgent_us.raw() as f64 / 16_777_216.0;
        // dst_y_pstate: the blackout and the urgent latency in lines.
        let dst = ((BLACKOUT_US + urgent) / line_us + 0.99999) as i32 as f64;
        let unity = i64::from(Plane::UNITY);
        let lines = |u: &Surf| {
            let h = f64::from(u.height.max(1));
            let src_pstate = ((dst * ratio_f(u.v_ratio) / h + 0.99999) as i32) as f64 * h;
            let det_lines =
                f64::from(u.det_bytes) * 3.0 / f64::from(u.det_bpp3) / f64::from(u.swath.max(1));
            // LBLatencyHidingSourceLines, as active_hiding counts it.
            let hr = i64::from(u.h_ratio).max(unity);
            let lb = (LINE_BUFFER_BITS / LB_BITS_PER_PIXEL * hr / (i64::from(u.swath) * unity))
                .min(MAX_LINE_BUFFER_LINES)
                - (i64::from(u.v_taps) - 1);
            let ahead = ((det_lines / h) as i32) as f64 * h + f64::from(lb as u32);
            src_pstate + ahead
        };
        let mut needed = lines(&self.y);
        if let Some(c) = &self.c {
            needed = max_f(needed, 2.0 * lines(c));
        }
        let min_vactive = ceil_int(needed / ratio_f(self.plane.v_ratio));
        (min_vactive, (self.vblank - 1).min(MAX_VSTARTUP) as i32)
    }
}

/// [`Plan::readmits`] for a P-state plan.
pub(super) fn readmits(plan: &Plan, p: &PlanPstate) -> bool {
    match admit_with_drr(&plan.soc, &p.uclk, &plan.joint_modes(), p.fams2, p.drr) {
        Ok(Pstate::Supported(s)) => s.plans.get(usize::from(plan.stream)) == Some(plan),
        _ => false,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_pstate_tests.rs"]
mod tests;
