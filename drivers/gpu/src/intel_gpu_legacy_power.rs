//! Gen9/Gen11 GT power for the execlists owner: software frequency requests
//! and RC6, without PM interrupts.
//!
//! MIT Linux i915 `gt/intel_rps.c` (`__gen6_rps_get_freq_caps`,
//! `gen9_rps_enable`, `rps_set`, `intel_rps_park`/`unpark`), `gt/intel_rc6.c`
//! (`gen9_rc6_enable`, `gen11_rc6_enable`, `intel_rc6_park`/`unpark`) and
//! `i915_drv.h` (`NEEDS_RC6_CTX_CORRUPTION_WA`,
//! `NEEDS_WaRsDisableCoarsePowerGating`).
//!
//! Linux steers the frequency from RPS up/down interrupts. This owner has no
//! PM interrupt handler, so the [`Governor`] follows the same shape from the
//! job queue instead: the efficient frequency on unpark, the boost frequency
//! once the GT has stayed busy for one up-evaluation interval, and the idle
//! frequency at park. RC6 needs forcewake released, so the owner parks only
//! when no job is queued or in flight.

use crate::intel_gpu_legacy_gt::LegacyGt;

/// `GEN6_RP_STATE_CAP` (`MCHBAR_MIRROR_BASE_SNB + 0x5998`): RP0 [7:0], RP1
/// [15:8], RPn [23:16], in 50 MHz units.
const RP_STATE_CAP: u64 = 0x145998;
/// `BXT_RP_STATE_CAP`, Gen9 LP's caps register.
const BXT_RP_STATE_CAP: u64 = 0x138170;
/// `GEN10_FREQ_INFO_REC`: RPe [15:8] (`RPE_MASK`), 50 MHz units; Gen11's RP1.
const FREQ_INFO_REC: u64 = 0x145ef0;
/// `GEN9_FREQ_SCALER`: requests are in 16.67 MHz units.
const FREQ_SCALER: u32 = 3;

const RPNSWREQ: u64 = 0xa008;
const RC_VIDEO_FREQ: u64 = 0xa00c;
const RP_CONTROL: u64 = 0xa024;
const RP_UP_THRESHOLD: u64 = 0xa02c;
const RP_DOWN_THRESHOLD: u64 = 0xa030;
const RP_UP_EI: u64 = 0xa068;
const RP_DOWN_EI: u64 = 0xa06c;
const RP_IDLE_HYSTERSIS: u64 = 0xa070;
const RC_CONTROL: u64 = 0xa090;
const RC_STATE: u64 = 0xa094;
const RC6_WAKE_RATE_LIMIT: u64 = 0xa09c;
const MEDIA_WAKE_RATE_LIMIT: u64 = 0xa0a0;
const RC_EVALUATION_INTERVAL: u64 = 0xa0a8;
const RC_IDLE_HYSTERSIS: u64 = 0xa0ac;
const RC_SLEEP: u64 = 0xa0b0;
const RC6_THRESHOLD: u64 = 0xa0b8;
const MEDIA_PG_IDLE_HYSTERESIS: u64 = 0xa0c4;
const RENDER_PG_IDLE_HYSTERESIS: u64 = 0xa0c8;
const PMINTRMSK: u64 = 0xa168;
const PG_ENABLE: u64 = 0xa210;
/// `GUC_MAX_IDLE_COUNT`.
const GUC_MAX_IDLE_COUNT: u64 = 0xc3e4;
/// `RING_MAX_IDLE(base)` (`PWRCTX_MAXCNT`), with `IDLE_TIME_MASK`.
const RING_MAX_IDLE: u64 = 0x54;
const IDLE_TIME_MASK: u32 = 0xf_ffff;

/// `RC6_LOCATION` (`RC6_CTX_IN_DRAM` bit 0) and `RC6_CTX_BASE`.
const RC6_LOCATION: u64 = 0xd40;
const RC6_CTX_BASE: u64 = 0xd48;
/// `GEN6_STOLEN_RESERVED`: enable [0], base [31:20], Gen8 size [8:7].
const STOLEN_RESERVED: u64 = 0x1082c0;
/// `GEN8_PUSHBUS_CONTROL`, `_ENABLE`, `_SHIFT`; `GEN6_GFXPAUSE`;
/// `GEN8_MISC_CTRL0`: BIOS power-management setup Gen9 LP RC6 relies on.
const BIOS_PM_SETUP: [u64; 5] = [0xa248, 0xa250, 0xa25c, 0xa000, 0xa180];
/// The render, video, copy and enhancement engines `bxt_check_bios_rc6_setup`
/// reads the idle counts of.
const LP_RC6_ENGINES: [u64; 4] = [0x2000, 0x12000, 0x22000, 0x1a000];

/// `GEN6_RC_CTL_RC6_ENABLE`, `GEN6_RC_CTL_EI_MODE(1)`, `GEN6_RC_CTL_HW_ENABLE`.
const RC_CTL_RC6_ENABLE: u32 = 1 << 18;
const RC_CTL_HW_RC6: u32 = 1 << 31 | 1 << 27 | RC_CTL_RC6_ENABLE;
/// `RC_SW_TARGET_STATE` for plain RC6 (no RC6p/RC6pp on Gen9/Gen11).
const RC_SW_TARGET_RC6: u32 = 4 << 16;

/// Linux's LOW_POWER evaluation intervals (`rps_set_power`), in µs, and the
/// default up/down thresholds (`intel_rps_init`), in percent.
const EI_UP_US: u64 = 16_000;
const EI_DOWN_US: u64 = 32_000;
const UP_THRESHOLD: u64 = 95;
const DOWN_THRESHOLD: u64 = 85;

/// Skylake GT3 and GT4 (`INTEL_SKL_GT3_IDS`, `INTEL_SKL_GT4_IDS`), which
/// take `WaRsDisableCoarsePowerGating`.
const SKL_GT3_GT4: [u16; 9] = [
    0x1923, 0x1926, 0x1927, 0x192b, 0x192d, 0x1932, 0x193a, 0x193b, 0x193d,
];

/// The frequency caps, in request units (16.67 MHz).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Caps {
    /// RP0: the maximum and boost frequency.
    pub rp0: u32,
    /// RP1 (Gen11: RPe): the efficient frequency.
    pub rp1: u32,
    /// RPn: the minimum and idle frequency.
    pub rpn: u32,
}

impl Caps {
    /// `__gen6_rps_get_freq_caps` for big-core Gen9 and Gen11. `None` when
    /// the caps are unreadable or inconsistent; the owner then requests
    /// nothing and the PCU keeps its own choice.
    pub(crate) fn read(gt: LegacyGt, mut read: impl FnMut(u64) -> u32) -> Option<Self> {
        if gt == LegacyGt::Gen9Lp {
            // BXT_RP_STATE_CAP: RP0 [23:16], RP1 [15:8], RPn [7:0], already
            // in 16.67 MHz units. RPe stays RP1 (no pcode DDCC read on LP).
            let cap = read(BXT_RP_STATE_CAP);
            let (rp0, rp1, rpn) = ((cap >> 16) & 0xff, (cap >> 8) & 0xff, cap & 0xff);
            if cap == u32::MAX || rpn == 0 || rp0 < rpn {
                return None;
            }
            return Some(Self {
                rp0,
                rp1: rp1.clamp(rpn, rp0),
                rpn,
            });
        }
        let cap = read(RP_STATE_CAP);
        if cap == u32::MAX {
            return None;
        }
        let rp0 = (cap & 0xff) * FREQ_SCALER;
        let rpn = ((cap >> 16) & 0xff) * FREQ_SCALER;
        let rp1 = match gt {
            LegacyGt::Gen9 | LegacyGt::Gen9Lp => ((cap >> 8) & 0xff) * FREQ_SCALER,
            LegacyGt::Gen11 => {
                let info = read(FREQ_INFO_REC);
                if info == u32::MAX {
                    return None;
                }
                ((info >> 8) & 0xff) * FREQ_SCALER
            }
        };
        if rpn == 0 || rp0 < rpn {
            return None;
        }
        Some(Self {
            rp0,
            rp1: rp1.clamp(rpn, rp0),
            rpn,
        })
    }

    /// `GEN9_FREQUENCY(freq)`, the `RPNSWREQ` word.
    pub(crate) const fn request(freq: u32) -> u32 {
        freq << 23
    }
}

/// `intel_gt_ns_to_pm_interval`: 16 GT clocks per unit, rounded up.
fn pm_interval(clock_hz: u64, ns: u64) -> u32 {
    let clocks = ns * clock_hz / 1_000_000_000;
    clocks.div_ceil(16) as u32
}

/// `gen9_rps_enable` without PM interrupts: the media video frequency (Gen9),
/// the idle hysteresis, every PM interrupt masked, then `rps_reset`'s request
/// at RPn with the LOW_POWER thresholds and `RP_CONTROL`. `clock_hz` is the
/// CS timestamp clock (`gt->clock_frequency`).
pub(crate) fn rps_enable(gt: LegacyGt, caps: Caps, clock_hz: u64, mut write: impl FnMut(u64, u32)) {
    if gt.graphics9() {
        write(RC_VIDEO_FREQ, Caps::request(caps.rp1));
    }
    write(RP_IDLE_HYSTERSIS, 0xa);
    // No PM interrupt handler: mask all of them, GuC redirection included.
    write(PMINTRMSK, u32::MAX);
    write(RPNSWREQ, Caps::request(caps.rpn));
    write(RP_UP_EI, pm_interval(clock_hz, EI_UP_US * 1000));
    write(
        RP_UP_THRESHOLD,
        pm_interval(clock_hz, EI_UP_US * UP_THRESHOLD * 10),
    );
    write(RP_DOWN_EI, pm_interval(clock_hz, EI_DOWN_US * 1000));
    write(
        RP_DOWN_THRESHOLD,
        pm_interval(clock_hz, EI_DOWN_US * DOWN_THRESHOLD * 10),
    );
    // MEDIA_TURBO (Gen9 only) | MEDIA_HW_NORMAL_MODE | MEDIA_IS_GFX |
    // ENABLE | UP_BUSY_AVG | DOWN_IDLE_AVG.
    let turbo = if gt.graphics9() { 1 << 11 } else { 0 };
    write(RP_CONTROL, turbo | 2 << 9 | 1 << 8 | 1 << 7 | 2 << 3 | 2);
}

/// A Gen9 part's data stolen memory from PCI config (`gen3_stolen_base`,
/// `gen9_stolen_size`): `INTEL_BSM` [31:20] and `SNB_GMCH_CTRL`'s GMS
/// [15:8], 32 MiB steps below 0xf0 and 4 MiB steps from 4 MiB above.
pub(crate) fn gen9_dsm(bsm: u32, gmch_ctrl: u32) -> Option<(u64, u64)> {
    if bsm == u32::MAX || gmch_ctrl == u32::MAX {
        return None;
    }
    let base = u64::from(bsm & 0xfff0_0000);
    let gms = u64::from((gmch_ctrl >> 8) & 0xff);
    let size = if gms < 0xf0 {
        gms * (32 << 20)
    } else {
        (gms - 0xf0) * (4 << 20) + (4 << 20)
    };
    (base != 0 && size != 0).then_some((base, size))
}

/// `init_reserved_stolen` with `chv_get_stolen_reserved`, Gen9 LP's decode:
/// the enable bit, the base and a 1, 2, 4 or 8 MiB size. Linux records no
/// reserved range when it is disabled, based at zero or outside the DSM.
fn lp_stolen_reserved(dsm: (u64, u64), reg: u32) -> Option<(u64, u64)> {
    let base = u64::from(reg & 0xfff0_0000);
    let size = 1u64 << (20 + ((reg >> 7) & 3));
    if reg & 1 == 0 || base == 0 {
        return None;
    }
    (base >= dsm.0 && base + size <= dsm.0 + dsm.1).then_some((base, size))
}

/// `rc6_supported`: every Gen9 big-core and Gen11 part; Gen9 LP only when
/// `bxt_check_bios_rc6_setup` finds the BIOS's RC6 setup: the RC6 context in
/// DRAM, a page of it inside the reserved stolen range of `dsm`, every
/// engine's idle count above one, and the push-bus, GFX pause and GPM
/// controls programmed. An unreadable register fails the check.
pub(crate) fn rc6_supported(
    gt: LegacyGt,
    dsm: Option<(u64, u64)>,
    mut read: impl FnMut(u64) -> u32,
) -> bool {
    if gt != LegacyGt::Gen9Lp {
        return true;
    }
    let mut read = |reg| Some(read(reg)).filter(|&v| v != u32::MAX);
    let Some(location) = read(RC6_LOCATION) else {
        return false;
    };
    let reserved = dsm.and_then(|dsm| lp_stolen_reserved(dsm, read(STOLEN_RESERVED)?));
    // The exact context size is unknown on BXT; Linux checks one page
    // against the inclusive end of the reserved resource.
    let context = read(RC6_CTX_BASE).map(|base| u64::from(base & 0xffff_fff0));
    let in_reserved = match (reserved, context) {
        (Some((start, size)), Some(base)) => base >= start && base + 4096 < start + size - 1,
        _ => false,
    };
    location & 1 != 0
        && in_reserved
        && LP_RC6_ENGINES
            .iter()
            .all(|base| read(base + RING_MAX_IDLE).is_some_and(|v| v & IDLE_TIME_MASK > 1))
        && BIOS_PM_SETUP
            .iter()
            .all(|&reg| read(reg).is_some_and(|v| v != 0))
}

/// `gen9_rc6_enable` / `gen11_rc6_enable`: the RC6 and power-gating timers,
/// with every engine's idle count (`engines`, the mmio bases). Returns
/// `ctl_enable`, the `RC_CONTROL` value [`rc6_unpark`] restores: zero on
/// Gen9, big core and LP, whose RC6 context-corruption workaround leaves
/// only the software entry at park (`NEEDS_RC6_CTX_CORRUPTION_WA`), and
/// hardware RC6 on Gen11. Callers enable only where [`rc6_supported`].
pub(crate) fn rc6_enable(
    gt: LegacyGt,
    device: u16,
    engines: &[u64],
    mut write: impl FnMut(u64, u32),
) -> u32 {
    match gt {
        LegacyGt::Gen9 | LegacyGt::Gen9Lp => {
            // WaRsDoubleRc6WrlWithCoarsePowerGating: Skylake doubles it.
            let skylake = crate::intel_gpu::DEVICE_TABLE
                .iter()
                .any(|entry| entry.did == device && entry.asic == "skylake");
            write(
                RC6_WAKE_RATE_LIMIT,
                if skylake { 108 << 16 } else { 54 << 16 },
            );
            write(RC_EVALUATION_INTERVAL, 125_000);
            write(RC_IDLE_HYSTERSIS, 25);
            for base in engines {
                write(base + RING_MAX_IDLE, 10);
            }
            write(GUC_MAX_IDLE_COUNT, 0xa);
            write(RC_SLEEP, 0);
            write(MEDIA_PG_IDLE_HYSTERESIS, 250);
            write(RENDER_PG_IDLE_HYSTERESIS, 250);
            write(RC6_THRESHOLD, 37_500);
            if !SKL_GT3_GT4.contains(&device) {
                write(PG_ENABLE, 0x3); // RENDER_PG | MEDIA_PG
            }
            0
        }
        LegacyGt::Gen11 => {
            write(RC6_WAKE_RATE_LIMIT, 54 << 16 | 85);
            write(MEDIA_WAKE_RATE_LIMIT, 150);
            write(RC_EVALUATION_INTERVAL, 125_000);
            write(RC_IDLE_HYSTERSIS, 25);
            for base in engines {
                write(base + RING_MAX_IDLE, 10);
            }
            write(GUC_MAX_IDLE_COUNT, 0xa);
            write(RC_SLEEP, 0);
            write(RC6_THRESHOLD, 50_000);
            write(MEDIA_PG_IDLE_HYSTERESIS, 60);
            write(RENDER_PG_IDLE_HYSTERESIS, 60);
            write(PG_ENABLE, 0x7); // RENDER_PG | MEDIA_PG | MEDIA_SAMPLER_PG
            RC_CTL_HW_RC6
        }
    }
}

/// `intel_rc6_park`: request RC6 by software; the GT enters it once
/// forcewake is released.
pub(crate) fn rc6_park(mut write: impl FnMut(u64, u32)) {
    write(RC_CONTROL, RC_CTL_RC6_ENABLE);
    write(RC_STATE, RC_SW_TARGET_RC6);
}

/// `intel_rc6_unpark`: restore the hardware RC6 timers (none on Gen9).
pub(crate) fn rc6_unpark(ctl_enable: u32, mut write: impl FnMut(u64, u32)) {
    write(RC_CONTROL, ctl_enable);
}

/// `__intel_rc6_disable`, before a reset or release.
pub(crate) fn rc6_disable(mut write: impl FnMut(u64, u32)) {
    write(PG_ENABLE, 0);
    write(RC_CONTROL, 0);
    write(RC_STATE, 0);
}

/// `intel_rps_disable` → `gen6_rps_disable`: `GEN6_RP_CONTROL` cleared,
/// before system sleep (`intel_gt_suspend_late`).
pub(crate) fn rps_disable(mut write: impl FnMut(u64, u32)) {
    write(RP_CONTROL, 0);
}

/// Request `freq` (`rps_set`'s `RPNSWREQ` write).
pub(crate) fn rps_request(freq: u32, mut write: impl FnMut(u64, u32)) {
    write(RPNSWREQ, Caps::request(freq));
}

/// Idle time before the owner parks: requests the idle frequency, enters RC6
/// and releases forcewake.
pub(crate) const PARK_DELAY_NS: u64 = 5_000_000;
/// Continuous busy time before the boost frequency: one LOW_POWER
/// up-evaluation interval.
pub(crate) const BOOST_DELAY_NS: u64 = EI_UP_US * 1000;

/// What the owner does next to the GT's power state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Request this frequency.
    Request(u32),
    /// Request the idle frequency, enter RC6 and release forcewake.
    Park(u32),
}

/// The busy/idle frequency policy standing in for RPS interrupts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Governor {
    caps: Option<Caps>,
    parked: bool,
    requested: Option<u32>,
    busy_since: Option<u64>,
    idle_since: Option<u64>,
}

impl Governor {
    /// After bring-up: awake, with the engine idle.
    pub(crate) const fn new(caps: Option<Caps>) -> Self {
        Self {
            caps,
            parked: false,
            requested: None,
            busy_since: None,
            idle_since: None,
        }
    }

    pub(crate) const fn parked(&self) -> bool {
        self.parked
    }

    /// `intel_rps_unpark`: the frequency to request once the owner holds
    /// forcewake again (the efficient frequency); `None` when awake already.
    pub(crate) fn unpark(&mut self) -> Option<Option<u32>> {
        if !self.parked {
            return None;
        }
        self.parked = false;
        self.idle_since = None;
        let freq = self.caps.map(|caps| caps.rp1);
        self.requested = freq;
        Some(freq)
    }

    /// One service pass at `now`, `busy` while any job is queued or running.
    pub(crate) fn tick(&mut self, now: u64, busy: bool) -> Option<Step> {
        if self.parked {
            return None;
        }
        if busy {
            self.idle_since = None;
            let since = *self.busy_since.get_or_insert(now);
            let caps = self.caps?;
            if now.saturating_sub(since) >= BOOST_DELAY_NS && self.requested != Some(caps.rp0) {
                self.requested = Some(caps.rp0);
                return Some(Step::Request(caps.rp0));
            }
            if self.requested.is_none() {
                self.requested = Some(caps.rp1);
                return Some(Step::Request(caps.rp1));
            }
            return None;
        }
        self.busy_since = None;
        let since = *self.idle_since.get_or_insert(now);
        if now.saturating_sub(since) < PARK_DELAY_NS {
            return None;
        }
        self.parked = true;
        let idle = self.caps.map_or(0, |caps| caps.rpn);
        self.requested = Some(idle);
        Some(Step::Park(idle))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

    const ENGINES: [u64; 4] = [0x2000, 0x12000, 0x22000, 0x1a000];

    /// The Gen9 DSM from PCI config, and bxt_check_bios_rc6_setup against
    /// it: one passing setup, then each check failing alone.
    fn smoke_legacy_power_lp_bios_rc6() -> TestResult {
        kt_assert_eq!(gen9_dsm(0x7c00_0001, 0x0200), Some((0x7c00_0000, 64 << 20)));
        kt_assert_eq!(gen9_dsm(0x7c00_0000, 0xf100), Some((0x7c00_0000, 8 << 20)));
        kt_assert_eq!(gen9_dsm(0x7c00_0000, 0), None);
        kt_assert_eq!(gen9_dsm(u32::MAX, 0x0200), None);
        let dsm = Some((0x7c00_0000, 64 << 20));
        // 8 MiB reserved at the top of the DSM, the context in it.
        let good: alloc::vec::Vec<(u64, u32)> = [
            (RC6_LOCATION, 1),
            (STOLEN_RESERVED, 0x7f80_0000 | 3 << 7 | 1),
            (RC6_CTX_BASE, 0x7fe0_0000),
        ]
        .into_iter()
        .chain(ENGINES.iter().map(|base| (base + RING_MAX_IDLE, 0x10)))
        .chain(BIOS_PM_SETUP.iter().map(|&reg| (reg, 1)))
        .collect();
        let supported = |changes: &[(u64, u32)], dsm| {
            rc6_supported(LegacyGt::Gen9Lp, dsm, |reg| {
                changes
                    .iter()
                    .chain(good.iter())
                    .find(|(r, _)| *r == reg)
                    .map_or(0, |(_, v)| *v)
            })
        };
        kt_assert!(supported(&[], dsm));
        kt_assert!(!supported(&[], None));
        kt_assert!(!supported(&[(RC6_LOCATION, 0)], dsm));
        kt_assert!(!supported(&[(RC6_CTX_BASE, 0x7fff_f000)], dsm));
        kt_assert!(!supported(&[(RC6_CTX_BASE, 0x7f00_0000)], dsm));
        kt_assert!(!supported(&[(STOLEN_RESERVED, 0x7f80_0000 | 3 << 7)], dsm));
        kt_assert!(!supported(&[(STOLEN_RESERVED, 0x8000_0000 | 1)], dsm));
        kt_assert!(!supported(&[(0x1a000 + RING_MAX_IDLE, 1)], dsm));
        kt_assert!(!supported(&[(0xa000, 0)], dsm));
        kt_assert!(!supported(&[(0xa25c, u32::MAX)], dsm));
        // Big-core Gen9 and Gen11 need no BIOS setup.
        kt_assert!(rc6_supported(LegacyGt::Gen9, None, |_| 0));
        kt_assert!(rc6_supported(LegacyGt::Gen11, None, |_| 0));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_power",
        smoke_legacy_power_lp_bios_rc6
    );

    /// RP_STATE_CAP 0x0009_1122 (RP0 0x22 = 1.7 GHz, RP1 0x11 = 850 MHz,
    /// RPn 9 = 450 MHz) in 16.67 MHz units; Gen11 takes RP1 from RPe.
    fn smoke_legacy_power_caps() -> TestResult {
        let caps = Caps::read(LegacyGt::Gen9, |r| {
            if r == RP_STATE_CAP {
                0x0009_1122
            } else {
                0
            }
        });
        kt_assert_eq!(
            caps,
            Some(Caps {
                rp0: 0x66,
                rp1: 0x33,
                rpn: 27
            })
        );
        // BXT_RP_STATE_CAP: RP0 [23:16], RP1 [15:8], RPn [7:0], unscaled.
        let lp = Caps::read(LegacyGt::Gen9Lp, |r| {
            if r == BXT_RP_STATE_CAP {
                0x0021_0f06
            } else {
                0
            }
        });
        kt_assert_eq!(
            lp,
            Some(Caps {
                rp0: 0x21,
                rp1: 0x0f,
                rpn: 6
            })
        );
        kt_assert_eq!(Caps::read(LegacyGt::Gen9Lp, |_| 0x0006_0f21), None);
        let gen11 = Caps::read(LegacyGt::Gen11, |r| match r {
            RP_STATE_CAP => 0x0009_1122,
            FREQ_INFO_REC => 0x1400,
            _ => 0,
        });
        kt_assert_eq!(gen11.map(|c| c.rp1), Some(60));
        kt_assert_eq!(Caps::read(LegacyGt::Gen9, |_| u32::MAX), None);
        kt_assert_eq!(Caps::read(LegacyGt::Gen9, |_| 0x0022_0011), None);
        kt_assert_eq!(Caps::request(0x66), 0x3300_0000);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_power",
        smoke_legacy_power_caps
    );

    /// gen9_rps_enable at a 12 MHz SKL clock: 16 ms up EI = 12000 units, 95%
    /// threshold 11400; 32 ms down EI 24000, 85% 20400; RP_CONTROL 0xd92
    /// (Gen9) or 0x592 (Gen11), RPn requested.
    fn smoke_legacy_power_rps_enable() -> TestResult {
        let caps = Caps {
            rp0: 0x66,
            rp1: 0x33,
            rpn: 27,
        };
        let mut writes = Vec::new();
        rps_enable(LegacyGt::Gen9, caps, 12_000_000, |r, v| writes.push((r, v)));
        kt_assert_eq!(
            writes,
            alloc::vec![
                (RC_VIDEO_FREQ, 0x33 << 23),
                (RP_IDLE_HYSTERSIS, 0xa),
                (PMINTRMSK, u32::MAX),
                (RPNSWREQ, 27 << 23),
                (RP_UP_EI, 12_000),
                (RP_UP_THRESHOLD, 11_400),
                (RP_DOWN_EI, 24_000),
                (RP_DOWN_THRESHOLD, 20_400),
                (RP_CONTROL, 0xd92),
            ]
        );
        let mut writes = Vec::new();
        rps_enable(LegacyGt::Gen11, caps, 12_000_000, |r, v| {
            writes.push((r, v))
        });
        kt_assert!(writes.iter().all(|(r, _)| *r != RC_VIDEO_FREQ));
        kt_assert_eq!(writes.last(), Some(&(RP_CONTROL, 0x592)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_power",
        smoke_legacy_power_rps_enable
    );

    /// gen9_rc6_enable leaves hardware RC6 off (ctx-corruption WA) and skips
    /// power gating on SKL GT3/GT4; Skylake doubles the wake rate limit.
    /// gen11_rc6_enable returns hardware RC6 with all three PG domains.
    fn smoke_legacy_power_rc6_enable() -> TestResult {
        let mut writes = Vec::new();
        kt_assert_eq!(
            rc6_enable(LegacyGt::Gen9, 0x1912, &ENGINES, |r, v| writes.push((r, v))),
            0
        );
        // for_each_engine: every engine's idle count.
        for base in ENGINES {
            kt_assert!(writes.contains(&(base + RING_MAX_IDLE, 10)));
        }
        kt_assert_eq!(writes.first(), Some(&(RC6_WAKE_RATE_LIMIT, 108 << 16)));
        kt_assert_eq!(writes.last(), Some(&(PG_ENABLE, 3)));
        kt_assert!(writes.contains(&(RC6_THRESHOLD, 37_500)));
        let mut writes = Vec::new();
        rc6_enable(LegacyGt::Gen9, 0x193b, &ENGINES, |r, v| writes.push((r, v)));
        kt_assert!(writes.iter().all(|(r, _)| *r != PG_ENABLE));
        let mut writes = Vec::new();
        rc6_enable(LegacyGt::Gen9, 0x5916, &ENGINES, |r, v| writes.push((r, v)));
        kt_assert_eq!(writes.first(), Some(&(RC6_WAKE_RATE_LIMIT, 54 << 16)));
        let mut writes = Vec::new();
        kt_assert_eq!(
            rc6_enable(LegacyGt::Gen11, 0x8a52, &ENGINES, |r, v| writes
                .push((r, v))),
            0x8804_0000
        );
        kt_assert_eq!(writes.last(), Some(&(PG_ENABLE, 7)));
        kt_assert!(writes.contains(&(RC6_WAKE_RATE_LIMIT, 0x0036_0055)));
        // Gen9 LP takes gen9_rc6_enable (not Skylake's wake rate limit).
        let mut writes = Vec::new();
        kt_assert_eq!(
            rc6_enable(LegacyGt::Gen9Lp, 0x3185, &ENGINES, |r, v| writes
                .push((r, v))),
            0
        );
        kt_assert_eq!(writes.first(), Some(&(RC6_WAKE_RATE_LIMIT, 54 << 16)));
        let mut writes = Vec::new();
        rc6_park(|r, v| writes.push((r, v)));
        kt_assert_eq!(
            writes,
            alloc::vec![(RC_CONTROL, 0x40000), (RC_STATE, 0x40000)]
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_power",
        smoke_legacy_power_rc6_enable
    );

    /// The governor: RP1 on the first busy pass, RP0 after one up EI of
    /// continuous work, park at RPn after 5 ms idle, and RP1 again on unpark.
    fn smoke_legacy_power_governor() -> TestResult {
        let caps = Caps {
            rp0: 0x66,
            rp1: 0x33,
            rpn: 27,
        };
        let mut g = Governor::new(Some(caps));
        kt_assert_eq!(g.tick(0, true), Some(Step::Request(0x33)));
        kt_assert_eq!(g.tick(1_000_000, true), None);
        kt_assert_eq!(g.tick(BOOST_DELAY_NS, true), Some(Step::Request(0x66)));
        kt_assert_eq!(g.tick(BOOST_DELAY_NS + 1, true), None);
        kt_assert_eq!(g.tick(20_000_000, false), None);
        kt_assert_eq!(g.tick(20_000_000 + PARK_DELAY_NS - 1, false), None);
        kt_assert_eq!(
            g.tick(20_000_000 + PARK_DELAY_NS, false),
            Some(Step::Park(27))
        );
        kt_assert!(g.parked());
        kt_assert_eq!(g.tick(40_000_000, true), None);
        kt_assert_eq!(g.unpark(), Some(Some(0x33)));
        kt_assert_eq!(g.unpark(), None);
        // A burst shorter than the boost delay never boosts.
        kt_assert_eq!(g.tick(50_000_000, true), None);
        kt_assert_eq!(g.tick(50_000_000 + BOOST_DELAY_NS - 1, false), None);
        // Without caps the owner still parks (RC6, forcewake) but requests no
        // frequency.
        let mut g = Governor::new(None);
        kt_assert_eq!(g.tick(0, true), None);
        kt_assert_eq!(g.tick(1, false), None);
        kt_assert_eq!(g.tick(1 + PARK_DELAY_NS, false), Some(Step::Park(0)));
        kt_assert_eq!(g.unpark(), Some(None));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_power",
        smoke_legacy_power_governor
    );
}
