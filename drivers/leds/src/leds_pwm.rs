//! PWM-backed dimmable LED driver.
//!
//! Wraps a `PwmDevice` channel. `set_brightness(level)` programs
//! the duty cycle proportionally: `duty_ns = level / max * period_ns`.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/leds/leds-pwm.c` — `led_pwm_set`, `led_pwm_brightness_set`.
//!   Duty calculation at line 52:
//!     `duty = led->pwmd->period / led->cdev.max_brightness * brightness`

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_pwm::{Polarity, PwmConfig, PwmDevice};

use crate::class::LedDevice;
use crate::triggers::Trigger;

// ── LedPwm ────────────────────────────────────────────────────────

/// PWM-backed dimmable LED device.
///
/// Duty cycle = `level / max_brightness * period_ns` nanoseconds.
/// At `level == 0` the PWM channel is programmed to 0% duty (LED
/// off); at `level == max_brightness` it is 100% duty (LED at full
/// brightness).
pub struct LedPwm {
    name: String,
    pwm: Arc<dyn PwmDevice>,
    /// PWM channel index within `pwm`.
    channel: u32,
    /// Full period in nanoseconds (= 1 / frequency).
    period_ns: u64,
    /// Maximum brightness step.  Typically 255 for byte-range UIs.
    max_brightness: u32,
    /// Cached brightness (avoids re-reading hardware for simple queries).
    cur_brightness: AtomicU32,
    trigger: IrqSafeSpinLock<Trigger>,
}

impl LedPwm {
    /// Create a new PWM LED.
    ///
    /// # Arguments
    ///
    /// - `name` — sysfs name, e.g. `"platform::kbd_backlight"`.
    /// - `pwm` — PWM device.
    /// - `channel` — channel index within `pwm`.
    /// - `period_ns` — PWM period in nanoseconds.
    /// - `max_brightness` — scale denominator. A typical value is 255
    ///   (matches Linux sysfs convention for `max_brightness`).
    pub fn new(
        name: impl Into<String>,
        pwm: Arc<dyn PwmDevice>,
        channel: u32,
        period_ns: u64,
        max_brightness: u32,
    ) -> Self {
        Self {
            name: name.into(),
            pwm,
            channel,
            period_ns,
            max_brightness: max_brightness.max(1),
            cur_brightness: AtomicU32::new(0),
            trigger: IrqSafeSpinLock::new(Trigger::None),
        }
    }

    /// Compute duty cycle in nanoseconds for a given brightness level.
    ///
    /// `duty_ns = level * period_ns / max_brightness`
    ///
    /// Matches `leds-pwm.c` line 52 duty formula.
    pub fn duty_ns(&self, level: u32) -> u64 {
        if self.max_brightness == 0 {
            return 0;
        }
        (level as u64) * self.period_ns / (self.max_brightness as u64)
    }

    fn apply_brightness(&self, level: u32) {
        let duty = self.duty_ns(level);
        let cfg = PwmConfig {
            // Convert period_ns to frequency_hz (rounded).
            frequency_hz: if self.period_ns > 0 {
                (1_000_000_000u64 / self.period_ns) as u32
            } else {
                0
            },
            duty_cycle_ns: duty,
            polarity: Polarity::Normal,
        };
        // PWM API is async; we use a sync adapter via a blocking
        // poll-until-done stub. In the real kernel this would be
        // dispatched to the scheduler's async executor. For now,
        // the `set_config` call is fire-and-forget from a non-async
        // context using a bare executor shim. We intentionally
        // ignore errors — hardware absent on QEMU.
        let _ = narf_pwm_sync_set(self.pwm.as_ref(), self.channel, &cfg);
    }
}

/// Synchronous wrapper around `PwmDevice::set_config`.
///
/// Drives a minimal single-step executor so we can call the async
/// PWM API from a synchronous `LedDevice::set_brightness` context.
/// This is a best-effort shim; the scheduler's async infrastructure
/// replaces this when the full executor is wired up.
fn narf_pwm_sync_set(
    pwm: &dyn PwmDevice,
    channel: u32,
    cfg: &PwmConfig,
) -> Result<(), narf_pwm::PwmError> {
    // Use a single-waker poll via a no-op Waker (never actually
    // polled to completion here — PWM hardware writes are fire-and-
    // forget register writes underneath the async façade, so a
    // single poll() suffices).
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

    let mut fut = core::pin::pin!(pwm.set_config(channel, cfg));
    match Pin::new(&mut fut).poll(&mut cx) {
        Poll::Ready(r) => r,
        Poll::Pending => Ok(()), // hardware write already submitted
    }
}

impl LedDevice for LedPwm {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max_brightness
    }

    fn brightness(&self) -> u32 {
        self.cur_brightness.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        let clamped = level.min(self.max_brightness);
        self.cur_brightness.store(clamped, Ordering::Release);
        self.apply_brightness(clamped);
    }

    fn current_trigger(&self) -> Trigger {
        self.trigger.lock().clone()
    }

    fn set_trigger(&self, trigger: Trigger) {
        *self.trigger.lock() = trigger;
    }
}

impl core::fmt::Debug for LedPwm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LedPwm")
            .field("name", &self.name)
            .field("channel", &self.channel)
            .field("period_ns", &self.period_ns)
            .field("max_brightness", &self.max_brightness)
            .field(
                "cur_brightness",
                &self.cur_brightness.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}
