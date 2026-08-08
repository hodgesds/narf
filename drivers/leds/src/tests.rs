//! Smoke tests for `narf-drivers-leds`.
//!
//! Coverage:
//! - Registry add/lookup/remove.
//! - GPIO LED: active-high and active-low brightness → pin state.
//! - PWM LED: duty cycle calculation.
//! - Trigger engine: Heartbeat ramp, Timer duty, default trigger.
//! - HID kbd Caps Lock LED → SET_REPORT byte.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::class::{
    __reset_for_test, led_devices, lookup_led_by_name, register_led, unregister_led, LedDevice,
};
use crate::leds_gpio::{DefaultState, LedGpio};
use crate::leds_input_caps::{
    register_set_report, unregister_set_report, LedCapsLock, HID_LED_BYTE, HID_LED_CAPS_LOCK,
};
use crate::leds_pwm::LedPwm;
use crate::triggers::{Trigger, __compute_brightness_for_test};

// ── Mock GPIO controller ───────────────────────────────────────────

use narf_drivers_gpio::{GpioController, GpioError, GpioIrqConfig, GpioPull};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
struct MockGpio {
    pins: IrqSafeSpinLock<alloc::vec::Vec<bool>>,
}

impl MockGpio {
    fn new(count: u16) -> Self {
        Self {
            pins: IrqSafeSpinLock::new(alloc::vec![false; count as usize]),
        }
    }

    fn pin_state(&self, pin: u16) -> bool {
        self.pins.lock()[pin as usize]
    }
}

impl GpioController for MockGpio {
    fn name(&self) -> &str {
        "mock-gpio"
    }
    fn pin_count(&self) -> u16 {
        self.pins.lock().len() as u16
    }
    fn read_pin(&self, pin: u16) -> Result<bool, GpioError> {
        Ok(self.pins.lock()[pin as usize])
    }
    fn set_pin(&self, pin: u16, value: bool) -> Result<(), GpioError> {
        self.pins.lock()[pin as usize] = value;
        Ok(())
    }
    fn register_irq(
        &self,
        _pin: u16,
        _pull: GpioPull,
        _irq: GpioIrqConfig,
        _handler: narf_drivers_gpio::GpioIrqHandler,
    ) -> Result<(), GpioError> {
        Ok(())
    }
    fn unregister_irq(&self, _pin: u16) {}
}

// ── Mock PWM device ────────────────────────────────────────────────

use narf_pwm::{PwmConfig, PwmDevice, PwmError};

#[derive(Debug)]
struct MockPwm {
    last_duty: IrqSafeSpinLock<u64>,
}

impl MockPwm {
    fn new() -> Self {
        Self {
            last_duty: IrqSafeSpinLock::new(0),
        }
    }
    fn last_duty_ns(&self) -> u64 {
        *self.last_duty.lock()
    }
}

#[async_trait::async_trait]
impl PwmDevice for MockPwm {
    async fn set_config(&self, _channel: u32, config: &PwmConfig) -> Result<(), PwmError> {
        *self.last_duty.lock() = config.duty_cycle_ns;
        Ok(())
    }
    async fn enable(&self, _channel: u32) -> Result<(), PwmError> {
        Ok(())
    }
    async fn disable(&self, _channel: u32) -> Result<(), PwmError> {
        Ok(())
    }
    fn channel_count(&self) -> u32 {
        1
    }
}

// ── Test 1: registry add / lookup / remove ────────────────────────

fn smoke_led_registry_add_remove() -> TestResult {
    __reset_for_test();
    let gpio = Arc::new(MockGpio::new(4));
    let led = Arc::new(LedGpio::new(
        "test::power",
        gpio,
        0,
        false,
        DefaultState::Off,
    ));
    register_led(led);
    if lookup_led_by_name("test::power").is_none() {
        return TestResult::Fail("LED not found after register");
    }
    unregister_led("test::power");
    if lookup_led_by_name("test::power").is_some() {
        return TestResult::Fail("LED still present after unregister");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_led_registry_add_remove);

// ── Test 2: registry deduplication ───────────────────────────────

fn smoke_led_registry_dedup() -> TestResult {
    __reset_for_test();
    let gpio = Arc::new(MockGpio::new(4));
    let led_a = Arc::new(LedGpio::new(
        "test::dup",
        gpio.clone(),
        0,
        false,
        DefaultState::Off,
    ));
    let led_b = Arc::new(LedGpio::new("test::dup", gpio, 1, false, DefaultState::Off));
    register_led(led_a);
    register_led(led_b);
    let count = led_devices().len();
    if count != 1 {
        return TestResult::Fail("dedup failed: expected 1 device");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_led_registry_dedup);

// ── Test 3: GPIO LED active-high set_brightness(1) → pin high ────

fn smoke_gpio_led_active_high_on() -> TestResult {
    let gpio = Arc::new(MockGpio::new(4));
    let led = LedGpio::new("test::ah", gpio.clone(), 0, false, DefaultState::Off);
    if gpio.pin_state(0) {
        return TestResult::Fail("pin should be low initially (active-high, off)");
    }
    led.set_brightness(1);
    if !gpio.pin_state(0) {
        return TestResult::Fail("set_brightness(1) on active-high LED should drive pin high");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_gpio_led_active_high_on);

// ── Test 4: GPIO LED active-low set_brightness(1) → pin low ──────

fn smoke_gpio_led_active_low_on() -> TestResult {
    let gpio = Arc::new(MockGpio::new(4));
    // Active-low: DefaultState::Off drives pin high (inactive).
    let led = LedGpio::new("test::al", gpio.clone(), 1, true, DefaultState::Off);
    // Off → active-low → pin driven high.
    if !gpio.pin_state(1) {
        return TestResult::Fail("active-low off should drive pin high");
    }
    led.set_brightness(1);
    // On → active-low → pin driven low.
    if gpio.pin_state(1) {
        return TestResult::Fail("set_brightness(1) on active-low LED should drive pin low");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_gpio_led_active_low_on);

// ── Test 5: PWM LED set_brightness(50) → 50% duty (max=100) ──────

fn smoke_pwm_led_50pct_duty() -> TestResult {
    let pwm = Arc::new(MockPwm::new());
    let period_ns = 1_000_000u64; // 1 ms = 1 kHz
    let led = LedPwm::new("test::pwm", pwm.clone(), 0, period_ns, 100);
    // duty for level=50 = 50 * 1_000_000 / 100 = 500_000 ns
    let expected_duty = 500_000u64;
    let computed = led.duty_ns(50);
    if computed != expected_duty {
        return TestResult::Fail("duty_ns(50) wrong for max=100 period=1ms");
    }
    led.set_brightness(50);
    let actual_duty = pwm.last_duty_ns();
    if actual_duty != expected_duty {
        return TestResult::Fail("PWM device did not receive 50% duty cycle");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_pwm_led_50pct_duty);

// ── Test 6: Trigger::Heartbeat ramp values over time ─────────────

fn smoke_trigger_heartbeat_ramp() -> TestResult {
    let max = 255u32;
    // At tick 0 the first pulse should be max.
    let t0 = __compute_brightness_for_test(&Trigger::Heartbeat, 0, max);
    if t0 != max {
        return TestResult::Fail("heartbeat tick 0 should be max brightness");
    }
    // At tick 2 the second pulse should be max.
    let t2 = __compute_brightness_for_test(&Trigger::Heartbeat, 2, max);
    if t2 != max {
        return TestResult::Fail("heartbeat tick 2 should be max brightness");
    }
    // At tick 5 (middle of off phase) brightness should be 0.
    let t5 = __compute_brightness_for_test(&Trigger::Heartbeat, 5, max);
    if t5 != 0 {
        return TestResult::Fail("heartbeat tick 5 should be 0");
    }
    // Pattern repeats at tick 10.
    let t10 = __compute_brightness_for_test(&Trigger::Heartbeat, 10, max);
    if t10 != max {
        return TestResult::Fail("heartbeat should repeat at tick 10");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_trigger_heartbeat_ramp);

// ── Test 7: Trigger::Timer on=200ms off=800ms → 20% duty ─────────

fn smoke_trigger_timer_duty() -> TestResult {
    let max = 1u32;
    let t = Trigger::Timer {
        on_ms: 200,
        off_ms: 800,
    };
    // period = 1000 ms = 10 ticks; on = 2 ticks.
    // tick 0 → on, tick 1 → on, tick 2 → off … tick 9 → off.
    let on_count = (0u32..10)
        .filter(|&i| __compute_brightness_for_test(&t, i, max) > 0)
        .count();
    if on_count != 2 {
        return TestResult::Fail("timer 200/800 should be on for 2 of 10 ticks (20%)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_trigger_timer_duty);

// ── Test 8: default trigger is None ──────────────────────────────

fn smoke_led_default_trigger_is_none() -> TestResult {
    let gpio = Arc::new(MockGpio::new(4));
    let led = LedGpio::new("test::def", gpio, 0, false, DefaultState::Off);
    if led.current_trigger() != Trigger::None {
        return TestResult::Fail("default trigger should be None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_led_default_trigger_is_none);

// ── Test 9: HID Caps Lock LED → SET_REPORT 0x02 byte ─────────────

fn smoke_hid_capslock_set_report() -> TestResult {
    // Reset shared HID LED byte.
    HID_LED_BYTE.store(0, Ordering::SeqCst);

    // Capture the byte that gets sent.
    static CAPTURED: AtomicU8 = AtomicU8::new(0);
    fn capture_report(byte: u8) {
        CAPTURED.store(byte, Ordering::SeqCst);
    }

    register_set_report(capture_report);

    let led = LedCapsLock::new("input0::capslock");
    led.set_brightness(1);

    unregister_set_report();

    let got = CAPTURED.load(Ordering::SeqCst);
    if got & HID_LED_CAPS_LOCK == 0 {
        return TestResult::Fail("SET_REPORT byte should have bit 1 (Caps Lock) set");
    }
    // Verify the exact bit value matches the standard.
    if HID_LED_CAPS_LOCK != 0x02 {
        return TestResult::Fail("HID_LED_CAPS_LOCK constant should be 0x02");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_hid_capslock_set_report);

// ── Test 10: multiple LEDs coexist in registry ───────────────────

fn smoke_led_registry_multi() -> TestResult {
    __reset_for_test();
    for i in 0u16..4 {
        let gpio = Arc::new(MockGpio::new(8));
        let name = alloc::format!("test::led{i}");
        let led = Arc::new(LedGpio::new(name, gpio, i, false, DefaultState::Off));
        register_led(led);
    }
    let all = led_devices();
    if all.len() != 4 {
        return TestResult::Fail("expected 4 LEDs in registry");
    }
    for i in 0u16..4 {
        let name = alloc::format!("test::led{i}");
        if lookup_led_by_name(&name).is_none() {
            return TestResult::Fail("LED not found by name after multi-register");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_led_registry_multi);

// ── engine worker: the BPF command mailbox ─────────────────────────

fn smoke_led_worker_applies_brightness_blink_off() -> TestResult {
    use crate::class::SimpleLed;
    use crate::worker::{drain, submit_command, ACTION_BLINK, ACTION_OFF, ACTION_SET_BRIGHTNESS};
    crate::__reset_all_for_test();
    register_led(Arc::new(SimpleLed::brightness_led("bpf-lvl")));
    let idx = led_devices()
        .iter()
        .position(|d| d.name() == "bpf-lvl")
        .expect("registered") as u32;

    // Brightness.
    if !submit_command(idx, ACTION_SET_BRIGHTNESS, 200) {
        return TestResult::Fail("mailbox rejected a brightness command");
    }
    drain();
    if led_devices()[idx as usize].brightness() != 200 {
        return TestResult::Fail("brightness command did not reach the LED");
    }

    // Blink → Timer trigger (on 250 ms, off 100 ms).
    let _ = submit_command(idx, ACTION_BLINK, (250u32 << 16) | 100);
    drain();
    match led_devices()[idx as usize].current_trigger() {
        Trigger::Timer {
            on_ms: 250,
            off_ms: 100,
        } => {}
        _ => return TestResult::Fail("blink command did not set a Timer trigger"),
    }

    // Off → trigger cleared + brightness 0.
    let _ = submit_command(idx, ACTION_OFF, 0);
    drain();
    if led_devices()[idx as usize].brightness() != 0
        || led_devices()[idx as usize].current_trigger() != Trigger::None
    {
        return TestResult::Fail("off command did not clear the LED");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/leds",
    smoke_led_worker_applies_brightness_blink_off
);

fn smoke_led_worker_sets_rgb_color() -> TestResult {
    use crate::multicolor::{register_rgb_led, rgb_led_devices, SimpleRgbLed};
    use crate::worker::{drain, submit_command, ACTION_SET_COLOR};
    crate::__reset_all_for_test();
    register_rgb_led(Arc::new(SimpleRgbLed::new("bpf-rgb")));

    // 0xFF8000 = (255, 128, 0).
    if !submit_command(0, ACTION_SET_COLOR, 0x00FF_8000) {
        return TestResult::Fail("mailbox rejected a color command");
    }
    drain();
    let devs = rgb_led_devices();
    match devs.first() {
        Some(dev) if dev.color() == (0xFF, 0x80, 0x00) => TestResult::Pass,
        Some(_) => TestResult::Fail("color command did not reach the RGB LED"),
        None => TestResult::Fail("RGB LED vanished"),
    }
}
kernel_test_in!("drivers/leds", smoke_led_worker_sets_rgb_color);

fn smoke_led_worker_mailbox_bounds_and_frees() -> TestResult {
    use crate::class::SimpleLed;
    use crate::worker::{drain, submit_command, ACTION_SET_BRIGHTNESS};
    crate::__reset_all_for_test();
    register_led(Arc::new(SimpleLed::onoff("bpf-full")));

    // A lossy ring must eventually refuse rather than allocate or block —
    // that is what makes the kfunc atomic-context safe.
    while submit_command(0, ACTION_SET_BRIGHTNESS, 1) {}
    if submit_command(0, ACTION_SET_BRIGHTNESS, 1) {
        return TestResult::Fail("mailbox accepted past its capacity");
    }
    // Draining frees the slots.
    drain();
    if !submit_command(0, ACTION_SET_BRIGHTNESS, 1) {
        return TestResult::Fail("mailbox did not free slots after a drain");
    }
    drain();
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_led_worker_mailbox_bounds_and_frees);

fn smoke_led_worker_preserves_full_device_index() -> TestResult {
    use crate::class::SimpleLed;
    use crate::worker::{drain, submit_command, ACTION_SET_BRIGHTNESS};
    crate::__reset_all_for_test();
    register_led(Arc::new(SimpleLed::brightness_led("bpf-index-width")));

    // The old packed mailbox silently truncated idx to 16 bits, turning 65536
    // into device 0. A bad full-width index must remain bad at drain time.
    if !submit_command(1 << 16, ACTION_SET_BRIGHTNESS, 99) {
        return TestResult::Fail("mailbox rejected a representable u32 index");
    }
    drain();
    if led_devices()[0].brightness() != 0 {
        return TestResult::Fail("mailbox truncated a u32 device index");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds", smoke_led_worker_preserves_full_device_index);
