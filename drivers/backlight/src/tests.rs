//! Smoke tests for the backlight subsystem (≥10 required).
//!
//! All tests are pure (no hardware, no AML live evaluation) — they
//! use synthetic devices registered via the `__test_install*` helpers.
//! The global registries are cleared before each test via
//! `__reset_all_for_test()` / module-local `__reset_for_test()`.

#[cfg(any(test, feature = "kernel-test"))]
mod smokes {
    extern crate alloc;

    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::Ordering;

    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::acpi_video::{AcpiVideoDevice, __reset_for_test as av_reset, __test_install};
    use crate::amdgpu_bl::{
        build_set_level_writes, AmdgpuBacklightDevice, MockAmdgpuBlExecutor,
    };
    use crate::brightness_keys::{handle_notify, NOTIFY_BRIGHTNESS_DOWN, NOTIFY_BRIGHTNESS_UP};
    use crate::kbd_backlight::dell_encode_kbd_level;
    use crate::leds::{led_device, register_led, unregister_led, LedDevice, SimpleLed, Trigger};
    use crate::{
        backlight_device, backlight_devices, register_backlight, unregister_backlight,
        BacklightDevice, BacklightKind, __reset_all_for_test,
    };

    // ── 1. BacklightDevice registry add / remove ───────────────────

    fn smoke_backlight_registry_add_remove() -> TestResult {
        __reset_all_for_test();

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD1F", vec![0, 50, 100]);
        // Device must be visible in the global registry.
        if backlight_device("acpi_video0").is_none() {
            return TestResult::Fail("device not found after register");
        }
        if backlight_devices().len() != 1 {
            return TestResult::Fail("unexpected device count after register");
        }
        // Remove it.
        unregister_backlight("acpi_video0");
        if backlight_device("acpi_video0").is_some() {
            return TestResult::Fail("device still present after unregister");
        }
        if !backlight_devices().is_empty() {
            return TestResult::Fail("device count not zero after unregister");
        }

        // Clean up AML-video registry too.
        av_reset();
        let _ = dev;
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_backlight_registry_add_remove);

    // ── 2. ACPI video _BCL parse: [80,100, 0,10,…,100] → max=100 ──

    fn smoke_acpi_video_bcl_parse() -> TestResult {
        __reset_all_for_test();
        av_reset();

        // _BCL: element 0 = AC default, 1 = battery default, 2..N = ladder.
        // Driver strips first two → sorted ladder 0..=100 in steps of 10.
        let raw: Vec<u32> = vec![80, 100, 0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", raw);

        if dev.max_brightness() != 100 {
            return TestResult::Fail("max != 100");
        }
        if dev.levels.len() != 11 {
            return TestResult::Fail("ladder len != 11");
        }
        if dev.levels[0] != 0 || dev.levels[10] != 100 {
            return TestResult::Fail("ladder boundaries wrong");
        }

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_acpi_video_bcl_parse);

    // ── 3. ACPI video _BCM snap + dispatch ────────────────────────

    fn smoke_acpi_video_bcm_snap() -> TestResult {
        __reset_all_for_test();
        av_reset();

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 25, 50, 75, 100]);
        // Snap 30 → nearest is 25.
        let snapped = dev.snap(30);
        if snapped != 25 {
            return TestResult::Fail("snap(30) != 25");
        }
        // Snap 60 → ties 50 and 75 → 75 (tie-break toward brighter).
        let snapped = dev.snap(62);
        // 62 is 12 above 50, 13 below 75 → nearest = 50.
        if snapped != 50 {
            return TestResult::Fail("snap(62) != 50");
        }
        // Snap 65 → 12 above 50, 10 below 75 → nearest = 75.
        let snapped2 = dev.snap(65);
        if snapped2 != 75 {
            return TestResult::Fail("snap(65) != 75");
        }

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_acpi_video_bcm_snap);

    // ── 4. AMDGPU backlight PWM level write (stub interface) ───────

    fn smoke_amdgpu_bl_pwm_level_write() -> TestResult {
        __reset_all_for_test();

        let exec = Arc::new(MockAmdgpuBlExecutor::new(0x8000));
        let dev = Arc::new(AmdgpuBacklightDevice::new(
            "amdgpu_bl0",
            exec.clone(),
            0x8000,
        ));

        // Initial state from constructor.
        if dev.current_brightness() != 0x8000 {
            return TestResult::Fail("initial brightness wrong");
        }
        // set_brightness must call the executor.
        dev.set_brightness(0xC000);
        if exec.level.load(Ordering::Acquire) != 0xC000 {
            return TestResult::Fail("executor level not updated");
        }
        if exec.set_count.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("set_count not 1");
        }
        if dev.current_brightness() != 0xC000 {
            return TestResult::Fail("cached brightness not updated");
        }
        // Clamp above max.
        dev.set_brightness(0xFFFF + 1);
        if exec.level.load(Ordering::Acquire) != 0xFFFF {
            return TestResult::Fail("clamp above max failed");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_amdgpu_bl_pwm_level_write);

    // ── 5. AMDGPU build_set_level_writes sequence ─────────────────

    fn smoke_amdgpu_build_set_level_writes() -> TestResult {
        let base: u32 = 0x0001_0000;
        let level: u16 = 0xBEEF;
        let writes = build_set_level_writes(base, level);
        if writes.len() != 3 {
            return TestResult::Fail("expected 3 writes: lock, level, unlock");
        }
        // First write: lock assert.
        let (lock_addr, lock_val) = writes[0];
        if lock_addr != base + 0x4B70 {
            return TestResult::Fail("lock addr wrong");
        }
        if lock_val != 1 << 31 {
            return TestResult::Fail("lock value wrong");
        }
        // Second write: user level.
        let (level_addr, level_val) = writes[1];
        if level_addr != base + 0x4B64 {
            return TestResult::Fail("level addr wrong");
        }
        if level_val != level as u32 {
            return TestResult::Fail("level value wrong");
        }
        // Third write: lock release.
        let (unlock_addr, unlock_val) = writes[2];
        if unlock_addr != base + 0x4B70 {
            return TestResult::Fail("unlock addr wrong");
        }
        if unlock_val != 0 {
            return TestResult::Fail("unlock value != 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_amdgpu_build_set_level_writes
    );

    // ── 6. LED class registry ─────────────────────────────────────

    fn smoke_led_registry() -> TestResult {
        __reset_all_for_test();

        let led = Arc::new(SimpleLed::onoff("platform::power"));
        register_led(led as Arc<dyn LedDevice>);

        if led_device("platform::power").is_none() {
            return TestResult::Fail("LED not found after register");
        }
        // Update (replace) with a new device of same name.
        let led2 = Arc::new(SimpleLed::brightness_led("platform::power"));
        register_led(led2.clone() as Arc<dyn LedDevice>);
        // Still only one entry.
        let count = crate::leds::led_devices().len();
        if count != 1 {
            return TestResult::Fail("duplicate name should replace, not duplicate");
        }
        // Unregister.
        unregister_led("platform::power");
        if led_device("platform::power").is_some() {
            return TestResult::Fail("LED still present after unregister");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_led_registry);

    // ── 7. LED Trigger::Heartbeat — trigger get/set round-trip ──────

    fn smoke_led_trigger_heartbeat() -> TestResult {
        __reset_all_for_test();

        let led = Arc::new(SimpleLed::brightness_led("test::heartbeat"));
        register_led(led.clone() as Arc<dyn LedDevice>);

        let d = led_device("test::heartbeat").unwrap();
        // No trigger → default is None.
        if d.current_trigger() != Trigger::None {
            return TestResult::Fail("default trigger should be None");
        }
        // Direct write works.
        d.set_brightness(100);
        if d.brightness() != 100 {
            return TestResult::Fail("initial set_brightness failed");
        }
        // Attach heartbeat trigger.
        d.set_trigger(Trigger::Heartbeat);
        if d.current_trigger() != Trigger::Heartbeat {
            return TestResult::Fail("current_trigger() not Heartbeat");
        }
        // Clear trigger → direct write works again.
        d.set_trigger(Trigger::None);
        d.set_brightness(50);
        if d.brightness() != 50 {
            return TestResult::Fail("set_brightness failed after trigger cleared");
        }

        unregister_led("test::heartbeat");
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_led_trigger_heartbeat);

    // ── 8. Brightness key Notify(0x87) → step down ───────────────

    fn smoke_brightness_key_notify_down() -> TestResult {
        __reset_all_for_test();
        av_reset();

        // Install a 5-step ladder panel at level 50 (index 2 of 0).
        let dev = __test_install(
            "acpi_video0",
            r"\_SB.GFX0.DD0",
            vec![0, 25, 50, 75, 100],
        );
        // Prime the cached level to 50.
        dev.last.store(50, Ordering::Release);

        // Inject brightness-down notify.
        let consumed = handle_notify(NOTIFY_BRIGHTNESS_DOWN);
        if !consumed {
            return TestResult::Fail("NOTIFY_BRIGHTNESS_DOWN not consumed");
        }
        // After step_down from level 50 (index 2), new level should be 25.
        let new_level = dev.last.load(Ordering::Acquire);
        if new_level != 25 {
            return TestResult::Fail("step_down did not advance to 25");
        }

        // Key event must have fired (BrightnessDown press + release).
        // We can't directly inspect the ring without the input crate's
        // test helpers, so we just verify handle_notify returned true.

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_brightness_key_notify_down);

    // ── 9. Brightness key Notify(0x86) → step up ─────────────────

    fn smoke_brightness_key_notify_up() -> TestResult {
        __reset_all_for_test();
        av_reset();

        let dev = __test_install(
            "acpi_video0",
            r"\_SB.GFX0.DD0",
            vec![0, 25, 50, 75, 100],
        );
        // Prime the cached level to 50.
        dev.last.store(50, Ordering::Release);

        let consumed = handle_notify(NOTIFY_BRIGHTNESS_UP);
        if !consumed {
            return TestResult::Fail("NOTIFY_BRIGHTNESS_UP not consumed");
        }
        // After step_up from 50 (index 2), new level should be 75.
        let new_level = dev.last.load(Ordering::Acquire);
        if new_level != 75 {
            return TestResult::Fail("step_up did not advance to 75");
        }

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_brightness_key_notify_up);

    // ── 10. Dell WMI keyboard backlight level encode ──────────────

    fn smoke_dell_kbd_backlight_wmi_encode() -> TestResult {
        // off = 0, low = 1, high = 2.
        let off = dell_encode_kbd_level(0);
        let low = dell_encode_kbd_level(1);
        let high = dell_encode_kbd_level(2);
        // Clamp above max (2) → 2.
        let clamped = dell_encode_kbd_level(5);

        if off != [0u8, 0, 0, 0] {
            return TestResult::Fail("off level encode wrong");
        }
        if low != [1u8, 0, 0, 0] {
            return TestResult::Fail("low level encode wrong");
        }
        if high != [2u8, 0, 0, 0] {
            return TestResult::Fail("high level encode wrong");
        }
        if clamped != [2u8, 0, 0, 0] {
            return TestResult::Fail("clamp encode wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_dell_kbd_backlight_wmi_encode);

    // ── 11. Brightness key at top of ladder → stays at max ────────

    fn smoke_brightness_key_clamp_at_max() -> TestResult {
        __reset_all_for_test();
        av_reset();

        let dev = __test_install(
            "acpi_video0",
            r"\_SB.GFX0.DD0",
            vec![0, 50, 100],
        );
        // Start at max.
        dev.last.store(100, Ordering::Release);

        handle_notify(NOTIFY_BRIGHTNESS_UP);
        // Should remain at 100.
        let new_level = dev.last.load(Ordering::Acquire);
        if new_level != 100 {
            return TestResult::Fail("step_up above max did not stay at 100");
        }

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_brightness_key_clamp_at_max);

    // ── 12. Brightness key at bottom of ladder → stays at min ─────

    fn smoke_brightness_key_clamp_at_min() -> TestResult {
        __reset_all_for_test();
        av_reset();

        let dev = __test_install(
            "acpi_video0",
            r"\_SB.GFX0.DD0",
            vec![0, 50, 100],
        );
        // Start at min.
        dev.last.store(0, Ordering::Release);

        handle_notify(NOTIFY_BRIGHTNESS_DOWN);
        let new_level = dev.last.load(Ordering::Acquire);
        if new_level != 0 {
            return TestResult::Fail("step_down below min did not stay at 0");
        }

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_brightness_key_clamp_at_min);

    // ── 13. handle_notify ignores unknown codes ────────────────────

    fn smoke_brightness_key_ignores_unknown() -> TestResult {
        // Non-brightness codes must not be consumed.
        if handle_notify(0x80) {
            return TestResult::Fail("0x80 (power-source) should not be consumed");
        }
        if handle_notify(0x00) {
            return TestResult::Fail("0x00 (bus-check) should not be consumed");
        }
        if handle_notify(0xFF) {
            return TestResult::Fail("0xFF should not be consumed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_brightness_key_ignores_unknown);

    // ── 14. ACPI video BacklightKind is Firmware ──────────────────

    fn smoke_backlight_kind_acpi_video() -> TestResult {
        __reset_all_for_test();
        av_reset();

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 50, 100]);
        let kind = dev.kind();
        if kind != BacklightKind::Firmware {
            return TestResult::Fail("ACPI video device should be Firmware kind");
        }

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_backlight_kind_acpi_video);
}
