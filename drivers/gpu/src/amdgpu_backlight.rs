//! AMD GPU backlight control via DCN BL_PWM.
//!
//! Modern AMD laptop iGPUs drive the panel backlight through a
//! PWM block inside the DCN display window. The host programs:
//!
//! - **BL_PWM_PERIOD_CNTL** — a sixteen-bit period plus a four-bit
//!   `BL_PWM_PERIOD_BITCNT` that scales it. VBIOS programs this;
//!   the driver reads it back and scales the duty against it.
//! - **BL_PWM_CNTL** — enable at bit 31, fractional enable at 30,
//!   and the sixteen-bit active duty count at 15:0. The duty and
//!   the enable share one register.
//! - **BL_PWM_GRP1_REG_LOCK** — lock at bit 0, update-pending at 8,
//!   master-lock bypass at 31. The host takes the lock, writes the
//!   duty, releases it, then waits for update-pending to clear.
//!
//! Linux references:
//! - `drivers/gpu/drm/amd/display/dc/dce/dce_panel_cntl.c`
//!   (`dce_panel_cntl_set_backlight_level`, `dce_panel_cntl_hw_init`)
//! - Register ids and fields from `dcn_3_1_4_offset.h` / `_sh_mask.h`.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_dcn::DcnWrite;

// ── BL_PWM registers (DCN 3.1.4) ─────────────────────────────────
//
// Absolute dword ids from `dcn_3_1_4_offset.h`, BASE_IDX 2. The block is
// `PWRSEQ`, one instance per panel, and the four registers are consecutive
// dwords. `dce_panel_cntl.c` is the sequencer.

/// `regPWRSEQ0_BL_PWM_CNTL`. Holds **both** the enable and the duty cycle:
/// `BL_ACTIVE_INT_FRAC_CNT` is the sixteen-bit active count, and
/// `BL_PWM_EN` is bit 31.
pub const BL_PWM_CNTL: u32 = 0x2f19;
/// `regPWRSEQ0_BL_PWM_CNTL2`, the override controls.
pub const BL_PWM_CNTL2: u32 = 0x2f1a;
/// `regPWRSEQ0_BL_PWM_PERIOD_CNTL`.
pub const BL_PWM_PERIOD_CNTL: u32 = 0x2f1b;
/// `regPWRSEQ0_BL_PWM_GRP1_REG_LOCK`.
pub const BL_PWM_GRP1_REG_LOCK: u32 = 0x2f1c;
/// `regPWRSEQ1_BL_PWM_CNTL` is 0x2f85, so the per-panel stride is 0x6c.
pub const PWRSEQ_STRIDE: u32 = 0x6c;
/// DCN 3.1.4 has two power sequencers.
pub const PWRSEQ_INSTANCES: u8 = 2;

/// LINUX-GAP: there is no `BL_PWM_USER_LEVEL` in this path. The duty cycle
/// goes into `BL_PWM_CNTL.BL_ACTIVE_INT_FRAC_CNT`.
/// `regABM0_BL1_PWM_USER_LEVEL` does exist, but it is 0x0e7b at **BASE_IDX 3**
/// in the ABM (adaptive backlight management) block — a different engine, not
/// a fifth register of this group. The old table placed a `USER_LEVEL` in the
/// middle of this run and wrote the duty there.
pub const ABM0_BL1_PWM_USER_LEVEL: u32 = 0x0e7b;

/// The dword id of `reg` for power sequencer `instance`.
pub const fn for_pwrseq(reg: u32, instance: u8) -> u32 {
    reg + (instance as u32) * PWRSEQ_STRIDE
}

// ── Field encodings (`dcn_3_1_4_sh_mask.h`) ───────────────────────

/// `BL_PWM_CNTL.BL_ACTIVE_INT_FRAC_CNT`, bits 15:0 — the active duty count.
pub const BL_ACTIVE_INT_FRAC_CNT_MASK: u32 = 0x0000_FFFF;
/// `BL_PWM_CNTL.BL_PWM_FRACTIONAL_EN`, bit **30**.
pub const BL_PWM_FRACTIONAL_EN: u32 = 1 << 30;
/// `BL_PWM_CNTL.BL_PWM_EN`, bit **31**. Bit 0 is the low bit of the duty
/// count, so the old `1 << 0` enable wrote a duty of one instead.
pub const BL_PWM_EN: u32 = 1 << 31;

/// `BL_PWM_PERIOD_CNTL.BL_PWM_PERIOD`, bits 15:0 — **sixteen** bits, not the
/// twenty-four the old guard allowed.
pub const BL_PWM_PERIOD_MASK: u32 = 0x0000_FFFF;
/// `BL_PWM_PERIOD_CNTL.BL_PWM_PERIOD_BITCNT`, bits 19:16. Zero means sixteen
/// (`dce_panel_cntl.c`: "if (pwm_period_bitcnt == 0) bit_count = 16").
pub const BL_PWM_PERIOD_BITCNT_SHIFT: u32 = 16;
pub const BL_PWM_PERIOD_BITCNT_MASK: u32 = 0x000F_0000;

/// `BL_PWM_GRP1_REG_LOCK.BL_PWM_GRP1_REG_LOCK`, bit **0** — the lock itself.
pub const BL_PWM_GRP1_REG_LOCK_BIT: u32 = 1 << 0;
/// `..._REG_UPDATE_PENDING`, bit 8: read-only, polled after unlock.
pub const BL_PWM_GRP1_REG_UPDATE_PENDING: u32 = 1 << 8;
/// `..._UPDATE_AT_FRAME_START`, bit 16.
pub const BL_PWM_GRP1_UPDATE_AT_FRAME_START: u32 = 1 << 16;
/// `..._IGNORE_MASTER_LOCK_EN`, bit **31**. The old `BL_PWM_GRP1_LOCK` was
/// this bit, so "lock" set the master-lock bypass and never took the lock.
pub const BL_PWM_GRP1_IGNORE_MASTER_LOCK_EN: u32 = 1 << 31;

/// A PWM period for roughly 200 Hz off a 100 MHz reference needs
/// 100_000_000 / 200 = 500_000 counts, which does **not** fit the sixteen-bit
/// field — the old `BL_PWM_PERIOD_200HZ_RENOIR` was eight times over, and the
/// guard let it through by checking twenty-four bits.
///
/// The hardware reaches low frequencies through `BL_PWM_PERIOD_BITCNT`
/// instead: the duty is shifted right by the bit count, so the period is
/// expressed in `2^bitcnt` units. Linux never computes a period at all — it
/// reads back whatever VBIOS programmed and scales the duty against it, which
/// is what [`active_duty_count`] now does.
pub const BL_PWM_PERIOD_MAX: u32 = BL_PWM_PERIOD_MASK;

// ── Errors ──────────────────────────────────────────────────────────

/// Errors building a backlight programming sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacklightError {
    /// PWM period would exceed the sixteen-bit field.
    PeriodOverflow,
    /// Power-sequencer instance beyond the two DCN 3.1.4 has.
    BadInstance,
}

// ── Sequence builders ──────────────────────────────────────────────

/// Convert a percentage (0–100) to the 16.16 fixed-point brightness Linux
/// passes as `backlight_pwm_u16_16`. Saturating: >100 clamps to full on.
pub fn user_level_for_percent(pct: u8) -> u16 {
    let p = pct.min(100) as u32;
    ((p * 0xFFFF) / 100) as u16
}

/// `dce_panel_cntl_set_backlight_level`'s duty-cycle arithmetic.
///
/// The register does not take a brightness: it takes an active count scaled
/// against the period VBIOS programmed. `period_cntl` is the raw
/// `BL_PWM_PERIOD_CNTL` read back.
///
///   bit_count       = BITCNT, or 16 when BITCNT is zero
///   masked_period   = PERIOD & ((1 << bit_count) - 1)
///   active          = brightness * masked_period
///   count           = ((active >> bit_count) & 0xFFFF)
///                     + ((active >> (bit_count - 1)) & 1)
///
/// The trailing term is the rounding bit taken from the MSB of the discarded
/// fraction. Writing the brightness straight into the register, as this
/// module used to, ignores the period entirely and lands at full scale for
/// any period below 0x10000.
pub fn active_duty_count(brightness_u16: u16, period_cntl: u32) -> u32 {
    let bitcnt = (period_cntl & BL_PWM_PERIOD_BITCNT_MASK) >> BL_PWM_PERIOD_BITCNT_SHIFT;
    let bit_count = if bitcnt == 0 { 16 } else { bitcnt };
    let period = period_cntl & BL_PWM_PERIOD_MASK;
    let masked_period = if bit_count >= 32 {
        period
    } else {
        period & ((1u32 << bit_count) - 1)
    };
    let active = brightness_u16 as u64 * masked_period as u64;
    let count = ((active >> bit_count) as u32) & BL_ACTIVE_INT_FRAC_CNT_MASK;
    count + ((active >> (bit_count - 1)) as u32 & 1)
}

/// Build the one-shot PWM init sequence for `instance`: program the period,
/// then enable the PWM.
///
/// LINUX-GAP: `dce_panel_cntl_hw_init` also drives `BL_PWM_CNTL2`'s override
/// bits and the panel power sequencer's own enables, and it does not program
/// a period — VBIOS owns that. This keeps the period parameter for callers
/// that genuinely need to set one, but bounds it to the real field.
pub fn build_backlight_init(
    instance: u8,
    period_units: u32,
    initial_brightness: u16,
) -> Result<Vec<DcnWrite>, BacklightError> {
    if instance >= PWRSEQ_INSTANCES {
        return Err(BacklightError::BadInstance);
    }
    if period_units & !BL_PWM_PERIOD_MASK != 0 {
        return Err(BacklightError::PeriodOverflow);
    }
    let period_cntl = period_units;
    let writes = alloc::vec![
        // Period first: the duty count is computed against it.
        DcnWrite {
            addr: for_pwrseq(BL_PWM_PERIOD_CNTL, instance),
            value: period_cntl,
        },
        // Enable, carrying the initial duty in the same register.
        DcnWrite {
            addr: for_pwrseq(BL_PWM_CNTL, instance),
            value: BL_PWM_EN | active_duty_count(initial_brightness, period_cntl),
        },
    ];
    Ok(writes)
}

/// Build the hot-path brightness update, as
/// `dce_panel_cntl_set_backlight_level` sequences it: take the group lock
/// *with* the master-lock bypass, write the duty into `BL_PWM_CNTL`, release
/// the lock. The caller then polls `BL_PWM_GRP1_REG_UPDATE_PENDING` for zero.
///
/// `period_cntl` is the value read back from `BL_PWM_PERIOD_CNTL`.
pub fn build_set_user_level(
    instance: u8,
    brightness: u16,
    period_cntl: u32,
) -> Result<Vec<DcnWrite>, BacklightError> {
    if instance >= PWRSEQ_INSTANCES {
        return Err(BacklightError::BadInstance);
    }
    Ok(alloc::vec![
        DcnWrite {
            addr: for_pwrseq(BL_PWM_GRP1_REG_LOCK, instance),
            value: BL_PWM_GRP1_IGNORE_MASTER_LOCK_EN | BL_PWM_GRP1_REG_LOCK_BIT,
        },
        DcnWrite {
            addr: for_pwrseq(BL_PWM_CNTL, instance),
            value: BL_PWM_EN | active_duty_count(brightness, period_cntl),
        },
        DcnWrite {
            addr: for_pwrseq(BL_PWM_GRP1_REG_LOCK, instance),
            value: BL_PWM_GRP1_IGNORE_MASTER_LOCK_EN,
        },
    ])
}

// ── eDP T1..T8 power sequence ─────────────────────────────────────
//
// The eDP panel-power sequence per VESA eDP spec section 5.4:
//
//   T1: VDD assert → black image valid    (5..100 ms; panel-specific)
//   T2: VDD valid → AUX channel valid     (≤ 50 ms)
//   T3: AUX valid → HPD high              (≤ 200 ms after VDD)
//   T4: video valid → BL_EN assert        (≥ 200 ms typical)
//   T5: BL_EN → BL_PWM valid              (≤ 10 ms)
//   T6: BL_EN deassert → video off        (≥ 200 ms typical)
//   T7: BL_PWM low → BL_EN deassert       (≤ 10 ms)
//   T8: BL_EN → VDD deassert              (≤ 500 ms)
//
// All eight phases have minimum + maximum bounds. The driver
// records the phase delays in the panel-config block and the
// hardware sequencer (DCN PANEL_PWRSEQ) waits each delay between
// transitions. The host kicks off the sequence + the sequencer
// pumps the delays in firmware.
//
// References (post 2026-05-20 GPL relicense):
//   - drivers/gpu/drm/amd/display/dc/link/protocols/link_edp_panel_control.c:398-447
//     (edp_panel_backlight_power_on / edp_set_panel_power /
//      edp_wait_for_t12)
//   - VESA eDP 1.5 spec, section 5.4 (panel power sequence)

/// Per-phase delay configuration. Units are milliseconds.
/// Defaults from the eDP 1.5 spec mid-points (most panels work
/// without driver-side overrides).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EdpPowerSeq {
    pub t1_vdd_to_video_ms: u16,
    pub t2_vdd_to_aux_ms: u16,
    pub t3_aux_to_hpd_ms: u16,
    pub t4_video_to_bl_ms: u16,
    pub t5_bl_en_to_pwm_ms: u16,
    pub t6_bl_off_to_video_off_ms: u16,
    pub t7_pwm_low_to_bl_off_ms: u16,
    pub t8_bl_off_to_vdd_off_ms: u16,
}

impl Default for EdpPowerSeq {
    fn default() -> Self {
        Self {
            t1_vdd_to_video_ms: 50,
            t2_vdd_to_aux_ms: 10,
            t3_aux_to_hpd_ms: 50,
            t4_video_to_bl_ms: 200,
            t5_bl_en_to_pwm_ms: 5,
            t6_bl_off_to_video_off_ms: 200,
            t7_pwm_low_to_bl_off_ms: 5,
            t8_bl_off_to_vdd_off_ms: 500,
        }
    }
}

/// Current state of the eDP panel power sequencer. Transitions
/// happen in a strict order: Off → VddOn (T1+T2) → AuxReady (T3)
/// → BlOn (T4+T5) → AwaitingBlOff → BlOff (T6+T7) → VddOff (T8).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdpPanelState {
    /// VDD off, BL off — fully powered down.
    Off,
    /// VDD asserted; AUX ready; video valid. Backlight still off.
    VideoValid,
    /// Backlight + PWM at programmed duty. Normal operating state.
    BacklightOn,
    /// Mid-transition: BL has been told to turn off; we're waiting
    /// for T6 + T7 to elapse before VDD goes down.
    BacklightOff,
}

/// Errors driving the panel-power state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PanelPowerError {
    /// Requested transition isn't legal from the current state.
    IllegalTransition,
}

/// Trait for the host driver's view of: program GPIOs (VDD_EN /
/// BL_EN) + program PWM (USER_LEVEL). Decoupling from MMIO lets
/// the state machine be tested without a real panel.
pub trait EdpPanelHw {
    /// Drive the VDD_EN GPIO. `true` = VDD on.
    fn set_vdd(&mut self, on: bool);
    /// Drive the BL_EN GPIO. `true` = backlight power on.
    fn set_backlight_enable(&mut self, on: bool);
    /// Set the PWM duty cycle. 0 = full off; 0xFFFF = full on.
    fn set_pwm(&mut self, user_level: u16);
    /// Caller's hook to sleep for at least `ms` milliseconds. The
    /// caller plumbs this into whichever timer the kernel exposes;
    /// the state-machine just calls it between phase transitions.
    fn delay_ms(&mut self, ms: u16);
}

/// The eDP panel-power sequencer. Holds the per-panel delay
/// configuration + current state.
#[derive(Clone, Debug)]
pub struct EdpPanelSequencer {
    pub seq: EdpPowerSeq,
    pub state: EdpPanelState,
    /// PWM USER_LEVEL to restore when the backlight transitions
    /// back to BacklightOn. Persisted across power-off so the
    /// brightness setting survives DPMS cycles.
    pub last_pwm_level: u16,
}

impl EdpPanelSequencer {
    pub fn new(seq: EdpPowerSeq) -> Self {
        Self {
            seq,
            state: EdpPanelState::Off,
            last_pwm_level: 0xFFFF,
        }
    }

    /// Drive the panel from Off → VideoValid. Programs:
    ///   VDD_EN on → wait T1 → wait T2 (AUX comes up) → wait T3
    /// before signalling AUX-ready upstream.
    pub fn power_on_video<H: EdpPanelHw>(&mut self, hw: &mut H) -> Result<(), PanelPowerError> {
        if !matches!(self.state, EdpPanelState::Off) {
            return Err(PanelPowerError::IllegalTransition);
        }
        hw.set_vdd(true);
        hw.delay_ms(self.seq.t1_vdd_to_video_ms);
        hw.delay_ms(self.seq.t2_vdd_to_aux_ms);
        hw.delay_ms(self.seq.t3_aux_to_hpd_ms);
        self.state = EdpPanelState::VideoValid;
        Ok(())
    }

    /// Drive VideoValid → BacklightOn. Programs:
    ///   wait T4 → BL_EN on → wait T5 → PWM USER_LEVEL.
    pub fn power_on_backlight<H: EdpPanelHw>(
        &mut self,
        hw: &mut H,
        user_level: u16,
    ) -> Result<(), PanelPowerError> {
        if !matches!(self.state, EdpPanelState::VideoValid) {
            return Err(PanelPowerError::IllegalTransition);
        }
        hw.delay_ms(self.seq.t4_video_to_bl_ms);
        hw.set_backlight_enable(true);
        hw.delay_ms(self.seq.t5_bl_en_to_pwm_ms);
        hw.set_pwm(user_level);
        self.last_pwm_level = user_level;
        self.state = EdpPanelState::BacklightOn;
        Ok(())
    }

    /// Drive BacklightOn → BacklightOff. Programs:
    ///   PWM → 0 (start fading) → wait T7 → BL_EN off.
    /// State stays in BacklightOff until power_off_vdd advances it.
    pub fn power_off_backlight<H: EdpPanelHw>(
        &mut self,
        hw: &mut H,
    ) -> Result<(), PanelPowerError> {
        if !matches!(self.state, EdpPanelState::BacklightOn) {
            return Err(PanelPowerError::IllegalTransition);
        }
        hw.set_pwm(0);
        hw.delay_ms(self.seq.t7_pwm_low_to_bl_off_ms);
        hw.set_backlight_enable(false);
        self.state = EdpPanelState::BacklightOff;
        Ok(())
    }

    /// Drive BacklightOff → Off. Programs:
    ///   wait T6 (BL → video valid) → wait T8 (BL → VDD off) → VDD off.
    pub fn power_off_vdd<H: EdpPanelHw>(&mut self, hw: &mut H) -> Result<(), PanelPowerError> {
        if !matches!(self.state, EdpPanelState::BacklightOff) {
            return Err(PanelPowerError::IllegalTransition);
        }
        hw.delay_ms(self.seq.t6_bl_off_to_video_off_ms);
        hw.delay_ms(self.seq.t8_bl_off_to_vdd_off_ms);
        hw.set_vdd(false);
        self.state = EdpPanelState::Off;
        Ok(())
    }
}

// ── Smoke tests ───────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_user_level_pct_round_trip() -> TestResult {
        if user_level_for_percent(0) != 0 {
            return TestResult::Fail("0% not 0");
        }
        if user_level_for_percent(100) != 0xFFFF {
            return TestResult::Fail("100% not 0xFFFF");
        }
        // Out-of-range clamps.
        if user_level_for_percent(200) != 0xFFFF {
            return TestResult::Fail("clamp wrong");
        }
        // 50% ≈ 0x7FFF.
        let mid = user_level_for_percent(50);
        if !(0x7F00..=0x8200).contains(&mid) {
            return TestResult::Fail("50% not midpoint");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_user_level_pct_round_trip);

    /// Mock eDP HW that records GPIO + PWM + delay calls.
    struct MockEdpHw {
        log: Vec<(&'static str, u32)>,
    }
    impl EdpPanelHw for MockEdpHw {
        fn set_vdd(&mut self, on: bool) {
            self.log.push(("vdd", if on { 1 } else { 0 }));
        }
        fn set_backlight_enable(&mut self, on: bool) {
            self.log.push(("bl_en", if on { 1 } else { 0 }));
        }
        fn set_pwm(&mut self, user_level: u16) {
            self.log.push(("pwm", user_level as u32));
        }
        fn delay_ms(&mut self, ms: u16) {
            self.log.push(("delay", ms as u32));
        }
    }

    fn smoke_edp_power_on_video_sequence() -> TestResult {
        let mut s = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = MockEdpHw { log: Vec::new() };
        s.power_on_video(&mut hw).expect("on");
        // Should be VDD on + 3 delays (T1, T2, T3).
        if hw.log[0] != ("vdd", 1) {
            return TestResult::Fail("VDD not first");
        }
        if hw.log.iter().filter(|e| e.0 == "delay").count() != 3 {
            return TestResult::Fail("expected 3 delays");
        }
        if s.state != EdpPanelState::VideoValid {
            return TestResult::Fail("state didn't advance");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_edp_power_on_video_sequence);

    fn smoke_edp_full_power_on_off_round_trip() -> TestResult {
        let mut s = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = MockEdpHw { log: Vec::new() };
        // Off → VideoValid → BacklightOn.
        s.power_on_video(&mut hw).expect("on video");
        s.power_on_backlight(&mut hw, 0xC000).expect("on bl");
        if s.state != EdpPanelState::BacklightOn {
            return TestResult::Fail("not BL on");
        }
        // BacklightOn → BacklightOff → Off.
        s.power_off_backlight(&mut hw).expect("off bl");
        if s.state != EdpPanelState::BacklightOff {
            return TestResult::Fail("not BL off");
        }
        s.power_off_vdd(&mut hw).expect("off vdd");
        if s.state != EdpPanelState::Off {
            return TestResult::Fail("not Off");
        }
        // Verify the recorded events have proper VDD on then off.
        let vdd_events: Vec<&(&'static str, u32)> =
            hw.log.iter().filter(|e| e.0 == "vdd").collect();
        if vdd_events.len() != 2 {
            return TestResult::Fail("expected 2 VDD events");
        }
        if vdd_events[0].1 != 1 || vdd_events[1].1 != 0 {
            return TestResult::Fail("VDD on/off order wrong");
        }
        // last_pwm_level cached.
        if s.last_pwm_level != 0xC000 {
            return TestResult::Fail("PWM level not cached");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_edp_full_power_on_off_round_trip);

    fn smoke_edp_rejects_illegal_transitions() -> TestResult {
        let mut s = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = MockEdpHw { log: Vec::new() };
        // Off → BL on (illegal — must go via VideoValid).
        match s.power_on_backlight(&mut hw, 0xFFFF) {
            Err(PanelPowerError::IllegalTransition) => {}
            _ => return TestResult::Fail("Off → BL_on must reject"),
        }
        // Off → power_off_vdd (already off — illegal).
        match s.power_off_vdd(&mut hw) {
            Err(PanelPowerError::IllegalTransition) => {}
            _ => return TestResult::Fail("Off → power_off_vdd must reject"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_edp_rejects_illegal_transitions);
}
