//! Generic PWM panel backlight (`pwm_bl`-style device, issue #957).
//!
//! Binds a panel to a [`narf_pwm::PwmDevice`] channel: the brightness
//! level selects a PWM duty cycle, and the device registers into the
//! arbitrated backlight stack via [`install`], alongside the existing
//! native devices (`intel_bl`, the DPCD device in `drivers/gpu`).
//!
//! This is the generic-PWM half of #957. The DPCD half was delivered
//! separately (via #1220) and is untouched here.
//!
//! ## Linux reference semantics (pinned — see Sources)
//!
//! The duty-cycle and power rules below are Linux
//! `drivers/video/backlight/pwm_bl.c`, transcribed onto the in-tree
//! [`narf_pwm::PwmDevice`] interface (`set_config` programs period
//! + duty + polarity in one call; `enable`/`disable` are separate):
//!
//! * **Duty** (`compute_duty_cycle`): with a levels table the step
//!   is `levels[brightness]`; without one the step is the brightness
//!   itself. `duty_ns = step * (period_ns - lth_ns) / scale +
//!   lth_ns`, where `scale` is the largest step (`max(levels)`, or
//!   `max_brightness` for the linear scale) and `lth_ns` is the
//!   low-threshold floor converted to nanoseconds
//!   (`lth_units * (period_ns / scale)`, integer division first, as
//!   in the Linux probe).
//! * **Power** (`pwm_backlight_update_status` / `power_on` /
//!   `power_off`): a nonzero level programs the duty and then
//!   enables the channel (idempotently — the `enabled` flag makes a
//!   second set a config-only update); level 0 programs duty 0 and
//!   then disables the channel, and is a complete no-op while
//!   already disabled. The low-threshold floor never applies at
//!   level 0: off means duty 0.
//! * **Kind** is [`crate::BacklightKind::Raw`] (Linux
//!   `props.type = BACKLIGHT_RAW`).
//! * **Default level**: Linux applies `default-brightness-level` at
//!   probe. [`install`] does the same — but only when this device
//!   wins the panel: a deferred candidate must never drive hardware
//!   (see Arbitration), so the default is applied after
//!   registration, and only on an [`crate::Ownership::Owner`]
//!   standing. A caller that wants a dark start sets
//!   [`PwmBlConfig::default_brightness`] to 0.
//!
//! ## Arbitration
//!
//! Kind is Raw, so this device ties with the native Intel PWM and
//! DPCD devices: ties keep the earliest registration, so install
//! ordering against those devices decides which native device owns
//! a panel that offers several paths. A panel that offers only a
//! PWM channel has no competitor and this device owns it outright.
//! Promotion does not replay the default level: a candidate
//! promoted after the owner unregisters stays at its cached level
//! (0 unless it was driven while owner) until the next sysfs or
//! brightness-key dispatch, like every other deferred candidate.
//!
//! ## No read-back
//!
//! [`narf_pwm::PwmDevice`] has no duty read-back, so
//! `current_brightness` returns the last level this device was
//! asked to drive (the [`narf_drivers_leds::LedPwm`] precedent for PWM-backed
//! devices), not a hardware sample. A period of 0 makes the device
//! inert — no PWM traffic at all, like `IntelBacklightDevice` with
//! `max == 0` — while the cached level still tracks intent.
//!
//! ## Remainder
//!
//! No probe/DT wiring yet: `narf-pwm` has no controller registry
//! and no production `PwmDevice` implementor (see
//! `drivers/platform/src/fan.rs`), so there is no panel binding to
//! call [`install`] from. That wiring — a PWM controller plus the
//! panel's `brightness-levels` / period / polarity facts — is the
//! follow-up once a controller lands. The `enable-gpio` and
//! `power-supply` (regulator) sequencing from Linux `pwm_bl` is
//! likewise not modelled: the channel enable/disable is the whole
//! power story here until a panel-power consumer exists.
//!
//! ## Sources
//!
//! * Issue #957 (generic PWM backlight half).
//! * Linux `drivers/video/backlight/pwm_bl.c` — `compute_duty_cycle`,
//!   `pwm_backlight_update_status`, `pwm_backlight_power_on/off`,
//!   `pwm_backlight_parse_dt`, `pwm_backlight_probe` (GPL-2.0-or-later,
//!   direct citation allowed). The `num-interpolated-steps` linear
//!   interpolation extension is not implemented: callers pass the
//!   expanded levels table instead.
//! * In-tree interfaces: [`narf_pwm::PwmDevice`] (`pwm/src/lib.rs`)
//!   and the [`crate::BacklightDevice`] trait + arbitration in this
//!   crate. The single-poll sync shim for the async PWM calls
//!   follows the `drivers/leds/src/leds_pwm.rs` precedent.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_pwm::{Polarity, PwmConfig, PwmDevice, PwmError};

use crate::{register_backlight, BacklightDevice, BacklightKind, Ownership};

// ── Configuration ──────────────────────────────────────────────────

/// Panel facts for a generic PWM backlight.
///
/// Mirrors the Linux `platform_pwm_backlight_data` / DT properties:
/// `pwms` (channel + period), `brightness-levels`, `max_brightness`,
/// `low-threshold-brightness`, polarity, and
/// `default-brightness-level`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PwmBlConfig {
    /// PWM channel index within the [`PwmDevice`].
    ///
    /// Must be `< PwmDevice::channel_count()`; the controller
    /// rejects an out-of-range channel with `InvalidChannel`, which
    /// the best-effort shim drops (see [`PwmBacklightDevice`]).
    pub channel: u32,
    /// Full PWM period in nanoseconds (Linux `pwms` period /
    /// `pwm_period_ns`). 0 makes the device inert (no PWM traffic).
    pub period_ns: u64,
    /// Duty-cycle steps in brightness units, indexed by level
    /// (Linux `brightness-levels`). Empty means the linear scale:
    /// the step for level `b` is `b` itself and
    /// [`PwmBacklightDevice::max_brightness`] is
    /// [`PwmBlConfig::max_brightness`]. With a table, the maximum
    /// is `levels.len() - 1` (Linux DT rule: `max_brightness =
    /// count - 1`) and the scale is the largest entry.
    pub levels: Vec<u32>,
    /// Maximum brightness step for the linear scale (no levels
    /// table). Ignored when [`PwmBlConfig::levels`] is non-empty.
    pub max_brightness: u32,
    /// Low-threshold brightness in brightness units (Linux
    /// `low-threshold-brightness`): the lowest duty the panel
    /// tolerates. Converted to nanoseconds at construction exactly
    /// as the Linux probe converts it
    /// (`lth_units * (period_ns / scale)`). 0 disables the floor.
    pub lth_brightness: u32,
    /// PWM polarity for every programmed config.
    pub polarity: Polarity,
    /// Level applied by [`install`] when this device wins the
    /// panel (Linux `default-brightness-level`, clamped to max).
    pub default_brightness: u32,
}

impl PwmBlConfig {
    /// Linear-scale config: no levels table, no low-threshold
    /// floor, normal polarity, default level at maximum so a probed
    /// panel lights at install (a NARF deviation from Linux's
    /// default-off: Linux relies on firmware having lit the panel,
    /// NARF probe owns the panel from boot). Set
    /// `default_brightness` to 0 for a dark start.
    pub fn linear(channel: u32, period_ns: u64, max_brightness: u32) -> Self {
        Self {
            channel,
            period_ns,
            levels: Vec::new(),
            max_brightness,
            lth_brightness: 0,
            polarity: Polarity::Normal,
            default_brightness: max_brightness,
        }
    }
}

// ── Device ─────────────────────────────────────────────────────────

/// Generic PWM panel backlight device.
///
/// Drives one [`PwmDevice`] channel. `set_brightness(level)`
/// programs the Linux `compute_duty_cycle` duty for the level and
/// enables the channel; level 0 programs duty 0 and disables it.
/// PWM errors are best-effort and silent — the
/// [`BacklightDevice`] trait returns `()` and sysfs stores cannot
/// surface a PWM error — exactly the `leds_pwm.rs` precedent.
pub struct PwmBacklightDevice {
    name: String,
    pwm: Arc<dyn PwmDevice>,
    channel: u32,
    period_ns: u64,
    /// Empty for the linear scale, else the levels table.
    levels: Vec<u32>,
    /// Largest step: `max(levels)`, or `max_brightness` linear.
    /// Never 0 (clamped), so the duty division cannot trap.
    scale: u32,
    max: u32,
    /// Low-threshold floor in nanoseconds (Linux probe conversion),
    /// clamped to `period_ns`.
    lth_ns: u64,
    polarity: Polarity,
    /// Last level driven (the PWM trait has no read-back).
    cur: AtomicU32,
    /// Whether the channel is currently enabled (Linux `pb->enabled`).
    enabled: AtomicBool,
}

impl PwmBacklightDevice {
    /// Build a device. The caller supplies the panel facts
    /// ([`PwmBlConfig`]); the device applies no level until
    /// [`BacklightDevice::set_brightness`] or [`install`] drives it.
    pub fn new(name: &str, pwm: Arc<dyn PwmDevice>, config: PwmBlConfig) -> Self {
        let (max, scale) = if config.levels.is_empty() {
            (config.max_brightness, config.max_brightness.max(1))
        } else {
            let largest = config.levels.iter().max().copied().unwrap_or(0);
            ((config.levels.len() - 1) as u32, largest.max(1))
        };
        // Linux probe: lth_ns = lth_units * (period_ns / scale),
        // integer period/scale division first; clamp to the period
        // so a threshold above the scale cannot invert the duty.
        let lth_ns = (config.lth_brightness as u64)
            .saturating_mul(config.period_ns / (scale as u64))
            .min(config.period_ns);
        Self {
            name: String::from(name),
            pwm,
            channel: config.channel,
            period_ns: config.period_ns,
            levels: config.levels,
            scale,
            max,
            lth_ns,
            polarity: config.polarity,
            cur: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
        }
    }

    /// Duty cycle in nanoseconds for a level (Linux
    /// `compute_duty_cycle`, byte-identical shape):
    /// `step * (period_ns - lth_ns) / scale + lth_ns`, where the
    /// step is `levels[level]` with a table, else `level`. The
    /// `u128` intermediate keeps the multiply exact for any
    /// panel period; the result never exceeds `period_ns` because
    /// the step never exceeds the scale.
    pub fn duty_ns(&self, level: u32) -> u64 {
        let level = level.min(self.max);
        let step: u128 = if self.levels.is_empty() {
            level as u128
        } else {
            self.levels[level as usize] as u128
        };
        let duty = step * (self.period_ns - self.lth_ns) as u128 / (self.scale as u128)
            + self.lth_ns as u128;
        duty.min(self.period_ns as u128) as u64
    }

    /// Period as a frequency for [`PwmConfig`], rounded down (the
    /// `leds_pwm.rs` conversion). 0 when the period is 0.
    fn frequency_hz(&self) -> u32 {
        if self.period_ns == 0 {
            0
        } else {
            (1_000_000_000u64 / self.period_ns) as u32
        }
    }

    /// Program one duty cycle on the channel (best-effort).
    fn program(&self, duty_ns: u64) {
        let cfg = PwmConfig {
            frequency_hz: self.frequency_hz(),
            duty_cycle_ns: duty_ns,
            polarity: self.polarity,
        };
        let _ = poll_once(self.pwm.set_config(self.channel, &cfg));
    }

    /// Apply a clamped level to the channel, following Linux
    /// `pwm_backlight_update_status` exactly: nonzero programs the
    /// duty then enables (once); zero is a no-op while already
    /// disabled, else programs duty 0 then disables. Inert when
    /// `period_ns == 0`.
    fn apply(&self, level: u32) {
        if self.period_ns == 0 {
            return;
        }
        if level == 0 {
            if !self.enabled.load(Ordering::Acquire) {
                return;
            }
            self.program(0);
            if poll_once(self.pwm.disable(self.channel)).is_ok() {
                self.enabled.store(false, Ordering::Release);
            }
        } else {
            self.program(self.duty_ns(level));
            if !self.enabled.load(Ordering::Acquire)
                && poll_once(self.pwm.enable(self.channel)).is_ok()
            {
                self.enabled.store(true, Ordering::Release);
            }
        }
    }
}

impl BacklightDevice for PwmBacklightDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max
    }

    fn current_brightness(&self) -> u32 {
        // Cached: the PWM trait has no read-back.
        self.cur.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        let clamped = level.min(self.max);
        self.cur.store(clamped, Ordering::Release);
        self.apply(clamped);
    }

    fn kind(&self) -> BacklightKind {
        // Direct hardware PWM control (Linux BACKLIGHT_RAW).
        BacklightKind::Raw
    }
}

impl core::fmt::Debug for PwmBacklightDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PwmBacklightDevice")
            .field("name", &self.name)
            .field("channel", &self.channel)
            .field("period_ns", &self.period_ns)
            .field("max", &self.max)
            .field("cur", &self.cur.load(Ordering::Relaxed))
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ── Sync shim for the async PWM API ────────────────────────────────

/// Poll an async PWM operation once with a no-op waker, as in
/// `drivers/leds/src/leds_pwm.rs`: PWM hardware writes are
/// fire-and-forget register writes underneath the async facade, so
/// a single poll suffices, and a `Pending` outcome means the write
/// was already submitted. Returns the operation's result, or
/// `Ok(())` when the future is still pending.
fn poll_once<F>(fut: F) -> Result<(), PwmError>
where
    F: core::future::Future<Output = Result<(), PwmError>>,
{
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    static VTABLE: RawWakerVTable = RawWakerVTable::new(
        |p| RawWaker::new(p, &VTABLE), // clone
        |_| {},                        // wake
        |_| {},                        // wake_by_ref
        |_| {},                        // drop
    );

    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: VTABLE functions are no-ops; the waker is never stored
    // beyond this function call.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    let mut fut = core::pin::pin!(fut);
    match Pin::new(&mut fut).poll(&mut cx) {
        Poll::Ready(r) => r,
        Poll::Pending => Ok(()),
    }
}

// ── install ────────────────────────────────────────────────────────

/// Register a generic PWM backlight into the arbitrated stack.
///
/// This is the seam a panel/PWM probe calls once a `PwmDevice`
/// controller and the panel's facts exist. The device is named
/// `"pwm_bl0"`. The configured default level is applied only when
/// this device wins the panel — a deferred candidate never drives
/// its channel. Returns the device's standing after registration.
pub fn install(pwm: Arc<dyn PwmDevice>, config: PwmBlConfig) -> Ownership {
    let default = config.default_brightness;
    let dev = Arc::new(PwmBacklightDevice::new("pwm_bl0", pwm, config));
    let standing = register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
    if standing == Ownership::Owner {
        dev.set_brightness(default);
    }
    let _ = writeln!(
        narf_console::Writer,
        "  pwm-backlight: registered, channel={}, period_ns={}, max={}, standing={:?}",
        dev.channel,
        dev.period_ns,
        dev.max,
        standing
    );
    standing
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    //! PWM-conversation fixture: a channel-side PWM model.
    //!
    //! The fake is the PWM controller, not the panel: it records
    //! every `set_config` / `enable` / `disable` call as an ordered
    //! transcript, so a test asserts the exact conversation the
    //! device has with its channel — duty values pinned to the
    //! Linux `compute_duty_cycle` formula, enable/disable sequencing
    //! pinned to Linux `power_on` / `power_off` — rather than
    //! trusting a final-state snapshot a wrong conversation could
    //! also produce.

    extern crate alloc;

    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::boxed::Box;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    /// One recorded PWM operation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Op {
        Config {
            channel: u32,
            frequency_hz: u32,
            duty_ns: u64,
            polarity: Polarity,
        },
        Enable(u32),
        Disable(u32),
    }

    /// Channel-side PWM model: a transcript plus a channel bound.
    #[derive(Debug)]
    struct FakePwm {
        ops: IrqSafeSpinLock<Vec<Op>>,
        channels: u32,
    }

    impl FakePwm {
        fn new(channels: u32) -> Self {
            Self {
                ops: IrqSafeSpinLock::new(Vec::new()),
                channels,
            }
        }

        fn ops(&self) -> Vec<Op> {
            self.ops.lock().clone()
        }

        fn enables(&self) -> usize {
            self.ops()
                .iter()
                .filter(|op| matches!(op, Op::Enable(_)))
                .count()
        }

        fn disables(&self) -> usize {
            self.ops()
                .iter()
                .filter(|op| matches!(op, Op::Disable(_)))
                .count()
        }
    }

    #[async_trait::async_trait]
    impl PwmDevice for FakePwm {
        async fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            self.ops.lock().push(Op::Config {
                channel,
                frequency_hz: config.frequency_hz,
                duty_ns: config.duty_cycle_ns,
                polarity: config.polarity,
            });
            Ok(())
        }

        async fn enable(&self, channel: u32) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            self.ops.lock().push(Op::Enable(channel));
            Ok(())
        }

        async fn disable(&self, channel: u32) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            self.ops.lock().push(Op::Disable(channel));
            Ok(())
        }

        fn channel_count(&self) -> u32 {
            self.channels
        }
    }

    /// Minimal competing Raw candidate for arbitration fixtures.
    #[derive(Debug)]
    struct StubRaw {
        name: &'static str,
        level: AtomicU32,
    }

    impl BacklightDevice for StubRaw {
        fn name(&self) -> &str {
            self.name
        }
        fn max_brightness(&self) -> u32 {
            100
        }
        fn current_brightness(&self) -> u32 {
            self.level.load(Ordering::Acquire)
        }
        fn set_brightness(&self, level: u32) {
            self.level.store(level.min(100), Ordering::Release);
        }
        fn kind(&self) -> BacklightKind {
            BacklightKind::Raw
        }
    }

    fn linear_dev(period_ns: u64, max: u32) -> (PwmBacklightDevice, Arc<FakePwm>) {
        let pwm = Arc::new(FakePwm::new(4));
        let dev = PwmBacklightDevice::new(
            "pwm_bl0",
            pwm.clone(),
            PwmBlConfig::linear(0, period_ns, max),
        );
        (dev, pwm)
    }

    fn cfg(channel: u32, duty_ns: u64) -> Op {
        Op::Config {
            channel,
            frequency_hz: 40_000,
            duty_ns,
            polarity: Polarity::Normal,
        }
    }

    fn smoke_linear_duty_mapping() -> TestResult {
        // Period 25_000 ns, linear scale 0..=255, no threshold.
        // Linux: duty = level * 25_000 / 255.
        let (dev, pwm) = linear_dev(25_000, 255);
        if dev.max_brightness() != 255 || dev.kind() != BacklightKind::Raw {
            return TestResult::Fail("max/kind wrong for linear device");
        }
        dev.set_brightness(255);
        // 255 * 25_000 / 255 = 25_000, then the channel enables.
        dev.set_brightness(128);
        // 128 * 25_000 / 255 = 12_549 (truncated); no re-enable.
        dev.set_brightness(0);
        // Duty 0 first, then disable.
        let want = vec![
            cfg(0, 25_000),
            Op::Enable(0),
            cfg(0, 12_549),
            cfg(0, 0),
            Op::Disable(0),
        ];
        if pwm.ops() != want {
            return TestResult::Fail(
                "linear transcript != config+enable, config, config(0)+disable",
            );
        }
        if dev.current_brightness() != 0 {
            return TestResult::Fail("cached level must be 0 after set(0)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_linear_duty_mapping);

    fn smoke_levels_table_mapping() -> TestResult {
        // Linux DT example shape: levels are steps, scale is the
        // largest entry (255), max is count - 1 (7).
        let pwm = Arc::new(FakePwm::new(4));
        let dev = PwmBacklightDevice::new(
            "pwm_bl0",
            pwm.clone(),
            PwmBlConfig {
                channel: 0,
                period_ns: 25_000,
                levels: vec![0, 4, 8, 16, 32, 64, 128, 255],
                max_brightness: 0,
                lth_brightness: 0,
                polarity: Polarity::Normal,
                default_brightness: 0,
            },
        );
        if dev.max_brightness() != 7 {
            return TestResult::Fail("levels max must be count - 1 = 7");
        }
        dev.set_brightness(6);
        // Step 128: 128 * 25_000 / 255 = 12_549.
        dev.set_brightness(7);
        // Step 255: full period.
        dev.set_brightness(1);
        // Step 4: 4 * 25_000 / 255 = 392 (truncated).
        let want = vec![cfg(0, 12_549), Op::Enable(0), cfg(0, 25_000), cfg(0, 392)];
        if pwm.ops() != want {
            return TestResult::Fail("levels transcript != step-scaled duties");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_levels_table_mapping);

    fn smoke_low_threshold_floor() -> TestResult {
        // lth 51 of 255 (~20%): lth_ns = 51 * (25_000 / 255) =
        // 51 * 98 = 4_998. Duty = step * (25_000 - 4_998) / 255 + 4_998.
        let pwm = Arc::new(FakePwm::new(4));
        let mut config = PwmBlConfig::linear(0, 25_000, 255);
        config.lth_brightness = 51;
        config.default_brightness = 0;
        let dev = PwmBacklightDevice::new("pwm_bl0", pwm.clone(), config);
        dev.set_brightness(255);
        // 255 * 20_002 / 255 + 4_998 = 25_000 (full period at max).
        dev.set_brightness(1);
        // 1 * 20_002 / 255 + 4_998 = 78 + 4_998 = 5_076.
        dev.set_brightness(0);
        // Off means duty 0: the floor never applies at level 0.
        let want = vec![
            cfg(0, 25_000),
            Op::Enable(0),
            cfg(0, 5_076),
            cfg(0, 0),
            Op::Disable(0),
        ];
        if pwm.ops() != want {
            return TestResult::Fail("lth transcript != floored duties with duty-0 off");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_low_threshold_floor);

    fn smoke_enable_disable_idempotent() -> TestResult {
        // Linux power_on/power_off early-return on the enabled flag:
        // a second nonzero set re-programs the duty but does not
        // re-enable; a second set(0) is a complete no-op.
        let (dev, pwm) = linear_dev(25_000, 255);
        dev.set_brightness(100);
        // 100 * 25_000 / 255 = 9_803.
        dev.set_brightness(50);
        // 50 * 25_000 / 255 = 4_901; still one enable.
        dev.set_brightness(0);
        dev.set_brightness(0);
        // Re-light after off: the channel enables again.
        dev.set_brightness(30);
        // 30 * 25_000 / 255 = 2_941.
        let want = vec![
            cfg(0, 9_803),
            Op::Enable(0),
            cfg(0, 4_901),
            cfg(0, 0),
            Op::Disable(0),
            cfg(0, 2_941),
            Op::Enable(0),
        ];
        if pwm.ops() != want {
            return TestResult::Fail(
                "enable/disable transcript not idempotent per Linux power_on/off",
            );
        }
        if pwm.enables() != 2 || pwm.disables() != 1 {
            return TestResult::Fail("enable/disable counts wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_enable_disable_idempotent);

    fn smoke_clamp_and_step_defaults() -> TestResult {
        let (dev, pwm) = linear_dev(25_000, 255);
        dev.set_brightness(300);
        if dev.current_brightness() != 255 {
            return TestResult::Fail("set above max must clamp to 255");
        }
        if pwm.ops() != vec![cfg(0, 25_000), Op::Enable(0)] {
            return TestResult::Fail("clamped set must program full period");
        }
        // Default step is a tenth of the range: 255 -> 0 -> 25 -> 0.
        let (dev, _) = linear_dev(25_000, 255);
        dev.step_up();
        if dev.current_brightness() != 25 {
            return TestResult::Fail("step_up from 0 must reach 25");
        }
        dev.step_down();
        if dev.current_brightness() != 0 {
            return TestResult::Fail("step_down must return to 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_clamp_and_step_defaults);

    fn smoke_cached_readback_and_kind() -> TestResult {
        let (dev, _) = linear_dev(25_000, 255);
        if dev.name() != "pwm_bl0" || dev.kind() != BacklightKind::Raw {
            return TestResult::Fail("name/kind wrong");
        }
        if dev.current_brightness() != 0 {
            return TestResult::Fail("initial cached level must be 0");
        }
        // No read-back exists: the reported level is the last level
        // this device was asked to drive.
        dev.set_brightness(42);
        if dev.current_brightness() != 42 {
            return TestResult::Fail("cached level must track the last set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_cached_readback_and_kind);

    fn smoke_polarity_propagated() -> TestResult {
        let pwm = Arc::new(FakePwm::new(4));
        let mut config = PwmBlConfig::linear(0, 25_000, 255);
        config.polarity = Polarity::Inversed;
        config.default_brightness = 0;
        let dev = PwmBacklightDevice::new("pwm_bl0", pwm.clone(), config);
        dev.set_brightness(255);
        dev.set_brightness(0);
        for op in pwm.ops() {
            match op {
                Op::Config {
                    polarity: Polarity::Inversed,
                    ..
                } => {}
                Op::Config { .. } => {
                    return TestResult::Fail("config polarity must be Inversed");
                }
                _ => {}
            }
        }
        if pwm.ops().len() != 4 {
            return TestResult::Fail(
                "inversed transcript must be config+enable, config(0)+disable",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_polarity_propagated);

    fn smoke_zero_period_is_inert() -> TestResult {
        let (dev, pwm) = linear_dev(0, 255);
        dev.set_brightness(100);
        dev.set_brightness(0);
        if !pwm.ops().is_empty() {
            return TestResult::Fail("period-0 device must emit no PWM traffic");
        }
        // The cached level still tracks intent (the LedPwm precedent).
        if dev.current_brightness() != 0 {
            return TestResult::Fail("cached level must still track the last set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight/pwm_bl", smoke_zero_period_is_inert);

    fn smoke_install_applies_default_only_as_owner() -> TestResult {
        crate::__reset_all_for_test();
        // Alone: wins the panel, default level (128) is applied.
        let pwm = Arc::new(FakePwm::new(4));
        let mut config = PwmBlConfig::linear(0, 25_000, 255);
        config.default_brightness = 128;
        if install(pwm.clone(), config) != Ownership::Owner {
            crate::__reset_all_for_test();
            return TestResult::Fail("sole pwm_bl candidate must own the panel");
        }
        // 128 * 25_000 / 255 = 12_549.
        if pwm.ops() != vec![cfg(0, 12_549), Op::Enable(0)] {
            crate::__reset_all_for_test();
            return TestResult::Fail("owner install must apply the default level");
        }
        if crate::panel_owner().map(|o| o.name().to_owned()) != Some(String::from("pwm_bl0")) {
            crate::__reset_all_for_test();
            return TestResult::Fail("panel owner is not pwm_bl0 after install");
        }
        crate::__reset_all_for_test();

        // A Raw incumbent owns the panel: install defers and the
        // channel is never touched — the loser never drives hardware.
        let incumbent = Arc::new(StubRaw {
            name: "intel_backlight",
            level: AtomicU32::new(0),
        });
        crate::register_backlight(incumbent as Arc<dyn BacklightDevice>);
        let pwm2 = Arc::new(FakePwm::new(4));
        let mut config2 = PwmBlConfig::linear(0, 25_000, 255);
        config2.default_brightness = 128;
        if install(pwm2.clone(), config2) != Ownership::Deferred {
            crate::__reset_all_for_test();
            return TestResult::Fail("pwm_bl must defer to the Raw incumbent");
        }
        if !pwm2.ops().is_empty() {
            crate::__reset_all_for_test();
            return TestResult::Fail("deferred install must emit no PWM traffic");
        }
        crate::__reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight/pwm_bl",
        smoke_install_applies_default_only_as_owner
    );

    fn smoke_install_end_to_end_through_sysfs() -> TestResult {
        crate::__reset_all_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        // Install as owner with default 0, then drive it through
        // the public sysfs path end to end.
        let pwm = Arc::new(FakePwm::new(4));
        let mut config = PwmBlConfig::linear(0, 25_000, 255);
        config.default_brightness = 0;
        if install(pwm.clone(), config) != Ownership::Owner {
            crate::__reset_all_for_test();
            narf_filesystem::sysfs::__reset_for_test();
            return TestResult::Fail("sole pwm_bl candidate must own the panel");
        }
        crate::sysfs_bridge::populate_backlight_class();
        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("pwm_bl0") {
            Some(k) => k,
            None => {
                crate::__reset_all_for_test();
                narf_filesystem::sysfs::__reset_for_test();
                return TestResult::Fail("pwm_bl0 not published to /sys/class/backlight");
            }
        };
        if !matches!(kobj.attr_store("brightness", b"42\n"), Some(Ok(()))) {
            crate::__reset_all_for_test();
            narf_filesystem::sysfs::__reset_for_test();
            return TestResult::Fail("sysfs brightness store failed");
        }
        // 42 * 25_000 / 255 = 4_117, then enable (first nonzero set).
        let want = vec![cfg(0, 4_117), Op::Enable(0)];
        let got = pwm.ops();
        let shown = kobj.attr_show("brightness").unwrap_or_default();
        crate::__reset_all_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        if got != want {
            return TestResult::Fail("sysfs store did not reach the PWM channel");
        }
        if shown.trim() != "42" {
            return TestResult::Fail("brightness read-back wrong after sysfs store");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight/pwm_bl",
        smoke_install_end_to_end_through_sysfs
    );
}
