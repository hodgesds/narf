//! AMD GPU backlight control via DCN BL_PWM.
//!
//! Modern AMD laptop iGPUs drive the panel backlight through a
//! PWM block inside the DCN display window. The host programs:
//!
//! - **BL_PWM_PERIOD_CNTL** — PWM period (in 16-bit clock units).
//!   1 kHz is the typical panel-friendly frequency; the period
//!   register reads `(ref_clk_khz * 1000 / 1000) = ref_clk_khz`
//!   units for that frequency.
//! - **BL_PWM_CNTL** — PWM enable + grp1-source-select +
//!   override-enable bits.
//! - **BL_PWM_USER_LEVEL** — 16-bit duty-cycle target. 0 =
//!   fully off (panel dark); 0xFFFF = fully on. Linear scale
//!   per VESA EDID-DDC; the laptop's panel response is usually
//!   gamma-corrected by the SMU's per-panel calibration table.
//! - **BL_PWM_GRP1_REG_LOCK** — lock bit. The host clears this
//!   bit before writing PERIOD/USER_LEVEL and re-asserts it so
//!   the DCN treats the next vsync as a single atomic update.
//!
//! Linux references (post 2026-05-20 GPL relicense — direct
//! citation allowed):
//! - `drivers/gpu/drm/amd/display/dc/dce/dce_panel_cntl.c`
//! - `drivers/gpu/drm/amd/display/dc/dcn31/dcn31_panel_cntl.c`
//!   (Phoenix delta — same shape, different stride)

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_dcn::DcnWrite;

// ── BL_PWM register offsets (relative to PANEL_CNTL block) ────────
//
// On DCN 2.0 (Renoir) the BL_PWM regs live in the DCE-derived
// PANEL_CNTL block within the DCN MMIO window. Values from
// `dce_panel_cntl.c`'s register tables.

/// `BL_PWM_PERIOD_CNTL` — PWM frequency setting.
pub const BL_PWM_PERIOD_CNTL_REL: u32 = 0x4B6C;
/// `BL_PWM_CNTL` — enable + grp1 source.
pub const BL_PWM_CNTL_REL: u32 = 0x4B5C;
/// `BL_PWM_USER_LEVEL` — 16-bit duty-cycle target.
pub const BL_PWM_USER_LEVEL_REL: u32 = 0x4B64;
/// `BL_PWM_GRP1_REG_LOCK` — atomic-update lock bit.
pub const BL_PWM_GRP1_REG_LOCK_REL: u32 = 0x4B70;

// ── Field encodings ────────────────────────────────────────────────

/// `BL_PWM_CNTL` — enable the PWM output.
pub const BL_PWM_CNTL_EN: u32 = 1 << 0;
/// `BL_PWM_CNTL` — select group 1 as the PWM source (the path
/// PERIOD_CNTL + USER_LEVEL feed).
pub const BL_PWM_CNTL_GRP1_FRAC_BL_EN: u32 = 1 << 24;
/// `BL_PWM_CNTL` — disable PWM source override (let group 1 drive
/// the output without forcing 0/1 from the override path).
pub const BL_PWM_CNTL_OVERRIDE_DISABLE: u32 = 0;

/// `BL_PWM_GRP1_REG_LOCK` — lock asserted; pending writes
/// accumulate until clear.
pub const BL_PWM_GRP1_LOCK: u32 = 1 << 31;

/// Default PWM period in DCN ref-clock units for the canonical
/// 200 Hz panel-friendly frequency on Renoir's 100 MHz ref clock:
/// period = ref_clk_hz / target_hz = 100_000_000 / 200 = 500_000.
/// Stays inside the 24-bit period field.
pub const BL_PWM_PERIOD_200HZ_RENOIR: u32 = 500_000;

// ── Errors ──────────────────────────────────────────────────────────

/// Errors building a backlight programming sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacklightError {
    /// PWM period would exceed the 24-bit field.
    PeriodOverflow,
}

// ── Sequence builders ──────────────────────────────────────────────

/// Convert a percentage (0–100) to a 16-bit BL_PWM_USER_LEVEL.
/// Saturating: >100 clamps to 0xFFFF; 0 → 0 (panel dark, but most
/// panels won't fully extinguish — the SMU's brightness-floor
/// calibration table sits between).
pub fn user_level_for_percent(pct: u8) -> u16 {
    let p = pct.min(100) as u32;
    ((p * 0xFFFF) / 100) as u16
}

/// Build the one-shot PWM init sequence: lock → program period
/// + cntl + initial duty → unlock. Caller writes it via DCN's
/// `execute_modeset` (the same MMIO writer the modeset uses).
pub fn build_backlight_init(
    panel_cntl_base: u32,
    period_units: u32,
    initial_user_level: u16,
) -> Result<Vec<DcnWrite>, BacklightError> {
    if period_units & !0x00FF_FFFF != 0 {
        return Err(BacklightError::PeriodOverflow);
    }
    let mut writes = Vec::with_capacity(5);
    // Lock — pending writes won't take effect until unlock.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
        value: BL_PWM_GRP1_LOCK,
    });
    // Program period (sets PWM frequency).
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_PERIOD_CNTL_REL,
        value: period_units,
    });
    // Enable PWM with grp1 source, no override.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_CNTL_REL,
        value: BL_PWM_CNTL_EN | BL_PWM_CNTL_GRP1_FRAC_BL_EN,
    });
    // Initial duty cycle.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_USER_LEVEL_REL,
        value: initial_user_level as u32,
    });
    // Unlock — DCN latches the new period + duty on next vsync.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
        value: 0,
    });
    Ok(writes)
}

/// Build the hot-path "set brightness" sequence used after init:
/// just lock → write USER_LEVEL → unlock. Programs the next vsync.
pub fn build_set_user_level(panel_cntl_base: u32, user_level: u16) -> Vec<DcnWrite> {
    alloc::vec![
        DcnWrite {
            addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
            value: BL_PWM_GRP1_LOCK,
        },
        DcnWrite {
            addr: panel_cntl_base + BL_PWM_USER_LEVEL_REL,
            value: user_level as u32,
        },
        DcnWrite {
            addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
            value: 0,
        },
    ]
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
        if mid < 0x7F00 || mid > 0x8200 {
            return TestResult::Fail("50% not midpoint");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_user_level_pct_round_trip);

    fn smoke_backlight_init_sequence() -> TestResult {
        let writes = build_backlight_init(0x10000, 500_000, 0x8000).expect("init");
        if writes.len() != 5 {
            return TestResult::Fail("expected 5 writes");
        }
        // First + last are the lock + unlock around the body.
        if writes[0].addr != 0x10000 + BL_PWM_GRP1_REG_LOCK_REL || writes[0].value == 0 {
            return TestResult::Fail("first write not lock-on");
        }
        if writes[4].addr != 0x10000 + BL_PWM_GRP1_REG_LOCK_REL || writes[4].value != 0 {
            return TestResult::Fail("last write not lock-off");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_backlight_init_sequence);

    fn smoke_backlight_init_rejects_period_overflow() -> TestResult {
        let r = build_backlight_init(0x10000, 0x0100_0000, 0);
        if r != Err(BacklightError::PeriodOverflow) {
            return TestResult::Fail("overflow not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_backlight_init_rejects_period_overflow);

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
