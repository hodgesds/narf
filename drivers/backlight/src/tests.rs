//! Smoke tests for the backlight subsystem (≥10 required).
//!
#![allow(clippy::undocumented_unsafe_blocks)]
//! Most tests are pure (no hardware, no AML live evaluation) —
//! they use synthetic devices registered via the
//! `__test_install*` helpers. Smokes 27–30 instead parse the
//! fixture DSDT (`fixture_dsdt::dsdt_bytes`) into the real AML
//! namespace and drive the production discovery + dispatch paths.
//! The global registries are cleared before each test via
//! `__reset_all_for_test()` / module-local `__reset_for_test()`.

#[cfg(any(test, feature = "kernel-test"))]
mod smokes {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;
    use narf_input::KeyCode;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::acpi_video::{__reset_for_test as av_reset, __test_install};
    use crate::brightness_keys::{
        __reset_for_test as bk_reset, handle_notify, register_video_notify, NOTIFY_BRIGHTNESS_DOWN,
        NOTIFY_BRIGHTNESS_UP,
    };
    use crate::fixture_dsdt::{dsdt_bytes, BCL_LADDER, DD0_PATH};
    use crate::kbd_backlight::{dell_encode_kbd_level, install, KbdBacklightDevice, KbdBlVendor};
    use crate::leds::{led_device, register_led, unregister_led, LedDevice, SimpleLed, Trigger};
    use crate::sysfs_bridge::populate_backlight_class;
    use crate::{
        __reset_all_for_test, backlight_device, backlight_devices, panel_owner, register_backlight,
        unregister_backlight, BacklightDevice, BacklightKind, Ownership,
    };
    use narf_aml::eval::evaluate_method;

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
        let raw: Vec<u32> = vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
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

    // ── 4/5 retired with the amdgpu_bl bridge (#951) ──────────────
    // The bridge module and its two smokes were deleted: one smoke
    // asserted the pre-fix BL_PWM write sequence verbatim (lock
    // `1 << 31` at base+0x4B70, USER_LEVEL at base+0x4B64) — a
    // fixture pinning the bug. The production AMD owner is
    // `AmdgpuPanelBacklight` in drivers/gpu, covered by that crate's
    // contract smoke and the arbitration fixtures below.

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
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 25, 50, 75, 100]);
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

        // Ring delivery of the key pair is asserted end-to-end in
        // smoke_notify_dispatch_steps_owner_and_emits_key; here only
        // the step is checked.

        av_reset();
        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_brightness_key_notify_down);

    // ── 9. Brightness key Notify(0x86) → step up ─────────────────

    fn smoke_brightness_key_notify_up() -> TestResult {
        __reset_all_for_test();
        av_reset();

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 25, 50, 75, 100]);
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

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 50, 100]);
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

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 50, 100]);
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

    // ── 15. Intel backlight PWM round-trip ─────────────────────────

    fn smoke_intel_backlight_pwm_roundtrip() -> TestResult {
        __reset_all_for_test();

        // Fake BAR0 large enough to actually cover the BXT PWM registers at
        // ~0xC8254/0xC8258 (the old 1 KiB buffer put every access out of
        // bounds — it happened to land on adjacent heap in debug but not in
        // release). Heap-allocated (boxed slice, not a stack array) to avoid a
        // ~800 KiB stack frame.
        let buf: Box<[u8]> = alloc::vec![0u8; 0xC9000].into_boxed_slice();
        let raw = Box::leak(buf);
        let bar_len = raw.len() as u64;
        let phys = narf_memory::PhysAddr::new(raw.as_ptr() as u64);
        let mmio = narf_driver_runtime::MmioRegion {
            phys,
            virt: phys.raw(),
            len: bar_len,
            kind: narf_driver_runtime::BarKind::Mmio32 {
                prefetchable: false,
            },
        };

        // Seed BXT_BLC_PWM_FREQ1 (offset 0xC8254) with a period.
        // 0xC8254 is byte offset; u32 index is 0xC8254 / 4.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_volatile((raw.as_ptr() as *mut u32).add(0xC8254 / 4), 0x1000);
        }

        // SAFETY: Valid MMIO bounds or trusted driver environment
        let dev = unsafe { crate::intel_bl::IntelBacklightDevice::new("intel_bl0", mmio) };

        // 50% → duty 0x800.
        dev.set_brightness(50);
        let duty =
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { core::ptr::read_volatile((raw.as_ptr() as *const u32).add(0xC8258 / 4)) };
        if duty != 0x800 {
            return TestResult::Fail("50% did not yield duty 0x800");
        }

        if dev.current_brightness() != 50 {
            return TestResult::Fail("read-back percentage != 50");
        }

        // 0% → 0.
        dev.set_brightness(0);
        if dev.current_brightness() != 0 {
            return TestResult::Fail("0% read-back != 0");
        }

        // 100% → 0x1000.
        dev.set_brightness(100);
        if dev.current_brightness() != 100 {
            return TestResult::Fail("100% read-back != 100");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_intel_backlight_pwm_roundtrip);

    // ── 16. Lenovo keyboard backlight ACPI operations ───────────────

    fn smoke_lenovo_kbd_backlight_acpi_operations() -> TestResult {
        __reset_all_for_test();

        let dev = crate::kbd_backlight::KbdBacklightDevice::new_acpi(
            crate::kbd_backlight::KbdBlVendor::Lenovo,
            alloc::string::String::from("\\_SB.PCI0.LPCB.EC.HKEY"),
        );

        if dev.name() != "tpacpi::kbd_backlight" {
            return TestResult::Fail("incorrect LED name for Lenovo kbd backlight");
        }

        if dev.max_brightness() != 2 {
            return TestResult::Fail("incorrect max brightness for Lenovo");
        }

        // Initially 0.
        if dev.brightness() != 0 {
            return TestResult::Fail("initial brightness should be 0");
        }

        // Set to 2.
        dev.set_brightness(2);
        if dev.brightness() != 2 {
            return TestResult::Fail("brightness did not update to 2");
        }

        // Clamp to max.
        dev.set_brightness(5);
        if dev.brightness() != 2 {
            return TestResult::Fail("brightness clamping to max failed");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_lenovo_kbd_backlight_acpi_operations
    );

    // ── 17+. Single-owner arbitration fixtures ─────────────────────

    /// Mock panel candidate whose "hardware" is a level cell plus a
    /// dispatch counter, so a fixture can prove a deferred candidate
    /// is never driven by any subsystem path.
    #[derive(Debug)]
    struct MockPanel {
        name: &'static str,
        kind: BacklightKind,
        max: u32,
        level: AtomicU32,
        set_count: AtomicU32,
    }

    impl MockPanel {
        fn new(name: &'static str, kind: BacklightKind, max: u32) -> Arc<Self> {
            Arc::new(Self {
                name,
                kind,
                max,
                level: AtomicU32::new(0),
                set_count: AtomicU32::new(0),
            })
        }
        fn sets(&self) -> u32 {
            self.set_count.load(Ordering::Acquire)
        }
        fn level(&self) -> u32 {
            self.level.load(Ordering::Acquire)
        }
    }

    impl BacklightDevice for MockPanel {
        fn name(&self) -> &str {
            self.name
        }
        fn max_brightness(&self) -> u32 {
            self.max
        }
        fn current_brightness(&self) -> u32 {
            self.level.load(Ordering::Acquire)
        }
        fn set_brightness(&self, level: u32) {
            self.level.store(level.min(self.max), Ordering::Release);
            self.set_count.fetch_add(1, Ordering::Release);
        }
        fn kind(&self) -> BacklightKind {
            self.kind
        }
    }

    // ── 17. Racing candidates elect exactly one owner ─────────────

    fn smoke_arbitration_race_single_owner() -> TestResult {
        __reset_all_for_test();

        // Firmware candidate registers first (the initcall order on
        // a real boot) and owns the panel while it is alone.
        let fw = MockPanel::new("acpi_video0", BacklightKind::Firmware, 100);
        if register_backlight(fw.clone() as Arc<dyn BacklightDevice>) != Ownership::Owner {
            return TestResult::Fail("sole firmware candidate should own the panel");
        }
        // The native (Raw) candidate arrives later (PCI probe) and
        // preempts: still exactly one owner, now the raw device.
        let raw = MockPanel::new("amdgpu_bl0", BacklightKind::Raw, 100);
        if register_backlight(raw.clone() as Arc<dyn BacklightDevice>) != Ownership::Owner {
            return TestResult::Fail("raw candidate should preempt the firmware candidate");
        }
        match panel_owner() {
            Some(o) if o.name() == "amdgpu_bl0" => {}
            _ => return TestResult::Fail("panel owner is not the raw candidate"),
        }
        // A platform candidate defers to the raw owner.
        let plat = MockPanel::new("platform_bl", BacklightKind::Platform, 100);
        if register_backlight(plat as Arc<dyn BacklightDevice>) != Ownership::Deferred {
            return TestResult::Fail("platform candidate should defer to the raw owner");
        }
        // A second raw candidate also defers: ties keep the
        // incumbent, so ownership never flaps on probe order.
        let raw2 = MockPanel::new("intel_backlight", BacklightKind::Raw, 100);
        if register_backlight(raw2 as Arc<dyn BacklightDevice>) != Ownership::Deferred {
            return TestResult::Fail("tied raw candidate should defer to the incumbent");
        }
        match panel_owner() {
            Some(o) if o.name() == "amdgpu_bl0" => {}
            _ => return TestResult::Fail("owner changed after tied registrations"),
        }
        // Deferral is not deletion: all four candidates stay
        // registered for diagnostics and failover.
        if backlight_devices().len() != 4 {
            return TestResult::Fail("deferred candidates were dropped from the registry");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_arbitration_race_single_owner);

    // ── 18. The loser never touches hardware ──────────────────────

    fn smoke_arbitration_loser_never_drives_hardware() -> TestResult {
        __reset_all_for_test();
        sysfs_reset();

        let fw = MockPanel::new("acpi_video0", BacklightKind::Firmware, 100);
        let raw = MockPanel::new("amdgpu_bl0", BacklightKind::Raw, 100);
        register_backlight(fw.clone() as Arc<dyn BacklightDevice>);
        register_backlight(raw.clone() as Arc<dyn BacklightDevice>);

        // Publication: only the owner gets a sysfs directory, so no
        // userspace write can reach the loser either.
        populate_backlight_class();
        let class = narf_filesystem::sysfs::class_register("backlight");
        if class.get_child("amdgpu_bl0").is_none() {
            return TestResult::Fail("owner missing from /sys/class/backlight");
        }
        if class.get_child("acpi_video0").is_some() {
            return TestResult::Fail("deferred candidate was published to sysfs");
        }

        // Dispatch through the public sysfs path: a brightness store
        // on the owner's kobject moves only the winner's hardware.
        let kobj = match class.get_child("amdgpu_bl0") {
            Some(k) => k,
            None => return TestResult::Fail("owner kobj missing"),
        };
        if !matches!(kobj.attr_store("brightness", b"40\n"), Some(Ok(()))) {
            return TestResult::Fail("brightness store failed");
        }
        if raw.sets() != 1 || raw.level() != 40 {
            return TestResult::Fail("owner did not receive the dispatch");
        }
        if fw.sets() != 0 || fw.level() != 0 {
            return TestResult::Fail("deferred candidate was dispatched");
        }

        __reset_all_for_test();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_arbitration_loser_never_drives_hardware
    );

    // ── 19. Owner drives brightness end to end through sysfs ──────

    fn smoke_arbitration_owner_end_to_end_sysfs() -> TestResult {
        __reset_all_for_test();
        sysfs_reset();

        // The production AMD shape: one raw owner, registered alone
        // through arbitration.
        let raw = MockPanel::new("amdgpu_bl0", BacklightKind::Raw, 100);
        if register_backlight(raw.clone() as Arc<dyn BacklightDevice>) != Ownership::Owner {
            return TestResult::Fail("sole raw candidate should own the panel");
        }
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("amdgpu_bl0") {
            Some(k) => k,
            None => return TestResult::Fail("owner kobj missing"),
        };
        let max = kobj.attr_show("max_brightness").unwrap_or_default();
        if max.trim() != "100" {
            return TestResult::Fail("max_brightness did not read through the owner");
        }
        // A sysfs store reaches the owner's hardware cell…
        if !matches!(kobj.attr_store("brightness", b"42\n"), Some(Ok(()))) {
            return TestResult::Fail("brightness store failed");
        }
        if raw.level() != 42 {
            return TestResult::Fail("sysfs store did not reach the owner's hardware");
        }
        // …and reads back through the same path.
        let shown = kobj.attr_show("brightness").unwrap_or_default();
        if shown.trim() != "42" {
            return TestResult::Fail("brightness read-back wrong after store");
        }

        __reset_all_for_test();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_arbitration_owner_end_to_end_sysfs
    );

    // ── 20. Owner unregister promotes the next candidate ──────────

    fn smoke_arbitration_failover_on_owner_unregister() -> TestResult {
        __reset_all_for_test();

        let fw = MockPanel::new("acpi_video0", BacklightKind::Firmware, 100);
        let raw = MockPanel::new("amdgpu_bl0", BacklightKind::Raw, 100);
        register_backlight(fw.clone() as Arc<dyn BacklightDevice>);
        register_backlight(raw.clone() as Arc<dyn BacklightDevice>);

        // Owner goes away (GPU unbind): the firmware candidate is
        // promoted and becomes dispatchable — the panel is never
        // left ownerless while a candidate remains.
        unregister_backlight("amdgpu_bl0");
        match panel_owner() {
            Some(o) if o.name() == "acpi_video0" => {}
            _ => return TestResult::Fail("firmware candidate not promoted after owner left"),
        }
        let owner = panel_owner().unwrap();
        owner.set_brightness(30);
        if fw.sets() != 1 || fw.level() != 30 {
            return TestResult::Fail("promoted candidate did not receive the dispatch");
        }

        unregister_backlight("acpi_video0");
        if panel_owner().is_some() {
            return TestResult::Fail("owner present after all candidates unregistered");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_arbitration_failover_on_owner_unregister
    );

    // ── 21. Brightness keys step the owner, never a loser ─────────

    fn smoke_arbitration_keys_step_owner_only() -> TestResult {
        __reset_all_for_test();

        let fw = MockPanel::new("acpi_video0", BacklightKind::Firmware, 100);
        let raw = MockPanel::new("amdgpu_bl0", BacklightKind::Raw, 100);
        register_backlight(fw.clone() as Arc<dyn BacklightDevice>);
        register_backlight(raw.clone() as Arc<dyn BacklightDevice>);
        raw.level.store(50, Ordering::Release);

        // Notify 0x86 steps the owner (50 + tenth-of-range 10 = 60)…
        if !handle_notify(NOTIFY_BRIGHTNESS_UP) {
            return TestResult::Fail("brightness-up notify not consumed");
        }
        if raw.level() != 60 {
            return TestResult::Fail("owner not stepped by the key handler");
        }
        // …and the deferred firmware candidate is untouched: the
        // keys must not fight the owner through the _BCM path.
        if fw.sets() != 0 || fw.level() != 0 {
            return TestResult::Fail("key handler stepped a deferred candidate");
        }
        // Notify 0x87 steps the owner back down.
        if !handle_notify(NOTIFY_BRIGHTNESS_DOWN) {
            return TestResult::Fail("brightness-down notify not consumed");
        }
        if raw.level() != 50 {
            return TestResult::Fail("owner not stepped down by the key handler");
        }

        __reset_all_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_arbitration_keys_step_owner_only);

    // ── 22. Composition: initcalls registered in a composed boot ──

    fn smoke_backlight_composition_registers_initcalls() -> TestResult {
        // #947: the frame composition root must call this crate's
        // register_initcalls(), so a composed boot carries the
        // backlight Stage::Device initcalls. Before the fix the list
        // contained no backlight entries at all and none of the
        // subsystem ever ran in production.
        let names = narf_init::registered_names(narf_init::Stage::Device);
        for want in [
            "backlight/acpi-video",
            "backlight/intel",
            "backlight/leds",
            "backlight/kbd",
            "backlight/brightness-keys",
            "backlight/sysfs",
        ] {
            if !names.contains(&want) {
                return TestResult::Fail("backlight initcall missing from composed boot");
            }
        }
        // The sysfs initcall's body guarantees the class directory
        // exists even on a panel-less machine. Run it, then verify
        // through the non-creating child lookup so the assertion
        // cannot create the class itself.
        populate_backlight_class();
        let root = narf_filesystem::sysfs::sysfs_root();
        let class_dir = match root.get_child("class") {
            Some(c) => c,
            None => return TestResult::Fail("/sys/class missing"),
        };
        if class_dir.get_child("backlight").is_none() {
            return TestResult::Fail("/sys/class/backlight missing after populate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_backlight_composition_registers_initcalls
    );

    // ── 23. AML Notify dispatch → owner step + input event ────────

    /// Drain all pending key events as (code, pressed) pairs.
    fn drain_key_pairs() -> Vec<(KeyCode, bool)> {
        let mut out = Vec::new();
        while let Some(ev) = narf_input::pop_key() {
            out.push((ev.code, ev.pressed));
        }
        out
    }

    fn smoke_notify_dispatch_steps_owner_and_emits_key() -> TestResult {
        __reset_all_for_test();
        av_reset();
        narf_aml::sync::__reset_for_test();
        bk_reset();
        narf_input::init_global_ring(64);
        narf_input::__reset_global_ring_for_test();

        // Synthetic panel: 5-rung ladder, primed at 50.
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 25, 50, 75, 100]);
        dev.last.store(50, Ordering::Release);
        // Production wiring: the handler is registered on the video
        // device's AML path (what acpi_video::init does per device).
        register_video_notify(r"\_SB.GFX0.DD0");

        // Notify 0x86 through the REAL AML dispatch table.
        narf_aml::sync::dispatch_notify(r"\_SB.GFX0.DD0", 0x86);
        if dev.last.load(Ordering::Acquire) != 75 {
            return TestResult::Fail("Notify 0x86 did not step the panel to 75");
        }
        if drain_key_pairs()
            != [
                (KeyCode::BrightnessUp, true),
                (KeyCode::BrightnessUp, false),
            ]
        {
            return TestResult::Fail("Notify 0x86 did not emit BrightnessUp press+release");
        }

        // Notify 0x87 steps back down and emits BrightnessDown.
        narf_aml::sync::dispatch_notify(r"\_SB.GFX0.DD0", 0x87);
        if dev.last.load(Ordering::Acquire) != 50 {
            return TestResult::Fail("Notify 0x87 did not step the panel to 50");
        }
        if drain_key_pairs()
            != [
                (KeyCode::BrightnessDown, true),
                (KeyCode::BrightnessDown, false),
            ]
        {
            return TestResult::Fail("Notify 0x87 did not emit BrightnessDown press+release");
        }

        // A non-brightness code on the same path is ignored end to
        // end: no step, no key event.
        narf_aml::sync::dispatch_notify(r"\_SB.GFX0.DD0", 0x80);
        if dev.last.load(Ordering::Acquire) != 50 {
            return TestResult::Fail("Notify 0x80 stepped the panel");
        }
        if !drain_key_pairs().is_empty() {
            return TestResult::Fail("Notify 0x80 emitted a key event");
        }

        // A Notify on an unregistered path reaches no handler at all.
        narf_aml::sync::dispatch_notify(r"\_SB.GFX0.DD9", 0x86);
        if dev.last.load(Ordering::Acquire) != 50 {
            return TestResult::Fail("Notify on an unregistered path stepped the panel");
        }
        if !drain_key_pairs().is_empty() {
            return TestResult::Fail("Notify on an unregistered path emitted a key event");
        }

        narf_aml::sync::__reset_for_test();
        bk_reset();
        av_reset();
        __reset_all_for_test();
        narf_input::__reset_global_ring_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_notify_dispatch_steps_owner_and_emits_key
    );

    // ── 24. Double registration steps the panel once ──────────────

    fn smoke_notify_double_registration_steps_once() -> TestResult {
        __reset_all_for_test();
        av_reset();
        narf_aml::sync::__reset_for_test();
        bk_reset();
        narf_input::init_global_ring(64);
        narf_input::__reset_global_ring_for_test();

        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", vec![0, 25, 50, 75, 100]);
        dev.last.store(50, Ordering::Release);
        // A re-run of discovery must not double-register: one Notify
        // moves the panel exactly one rung and emits one key pair.
        register_video_notify(r"\_SB.GFX0.DD0");
        register_video_notify(r"\_SB.GFX0.DD0");
        narf_aml::sync::dispatch_notify(r"\_SB.GFX0.DD0", 0x86);
        if dev.last.load(Ordering::Acquire) != 75 {
            return TestResult::Fail("double registration stepped twice (or not at all)");
        }
        if drain_key_pairs().len() != 2 {
            return TestResult::Fail("double registration emitted a duplicate key pair");
        }

        narf_aml::sync::__reset_for_test();
        bk_reset();
        av_reset();
        __reset_all_for_test();
        narf_input::__reset_global_ring_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_notify_double_registration_steps_once
    );

    // ── 25. Notify with no panel owner still emits the key ────────

    fn smoke_notify_without_owner_still_emits_key() -> TestResult {
        __reset_all_for_test();
        av_reset();
        narf_aml::sync::__reset_for_test();
        bk_reset();
        narf_input::init_global_ring(64);
        narf_input::__reset_global_ring_for_test();

        // No panel device registered at all: the step is a no-op, but
        // the key event must still reach userspace.
        if panel_owner().is_some() {
            return TestResult::Fail("panel owner present before any registration");
        }
        register_video_notify(r"\_SB.GFX0.DD0");
        narf_aml::sync::dispatch_notify(r"\_SB.GFX0.DD0", 0x86);
        if drain_key_pairs()
            != [
                (KeyCode::BrightnessUp, true),
                (KeyCode::BrightnessUp, false),
            ]
        {
            return TestResult::Fail("Notify without an owner did not emit BrightnessUp");
        }

        narf_aml::sync::__reset_for_test();
        bk_reset();
        av_reset();
        __reset_all_for_test();
        narf_input::__reset_global_ring_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_notify_without_owner_still_emits_key
    );

    // ── 26. Kbd backlight install publishes to /sys/class/leds (#956) ──

    fn smoke_kbd_backlight_install_publishes_led() -> TestResult {
        __reset_all_for_test();
        sysfs_reset();
        // The production Dell device, minus the WMI transport: with
        // no GUID the set path is cache-only, so the fixture drives
        // install → register_led → dynamic publication → sysfs
        // store without touching firmware.
        let dev = KbdBacklightDevice::new(KbdBlVendor::Dell, None);
        install(dev.clone());
        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("dell::kbd_backlight") {
            Some(k) => k,
            None => {
                __reset_all_for_test();
                sysfs_reset();
                return TestResult::Fail("dell::kbd_backlight not published on install");
            }
        };
        if !matches!(kobj.attr_store("brightness", b"2"), Some(Ok(()))) {
            __reset_all_for_test();
            sysfs_reset();
            return TestResult::Fail("brightness store(2) failed");
        }
        let got = dev.brightness();
        // Unregister removes the publication again.
        unregister_led("dell::kbd_backlight");
        let gone = class.get_child("dell::kbd_backlight").is_none();
        __reset_all_for_test();
        sysfs_reset();
        if got != 2 {
            return TestResult::Fail("store did not reach the kbd device");
        }
        if !gone {
            return TestResult::Fail("kbd device still published after unregister");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_kbd_backlight_install_publishes_led
    );

    // ── 27–30. Fixture DSDT (#958) ─────────────────────────────────
    //
    // The smokes above install pre-parsed ladders via
    // `__test_install` and never touch AML. These four parse the
    // fixture DSDT (`fixture_dsdt::dsdt_bytes`) into the real AML
    // namespace and drive the production discovery + dispatch
    // paths: `_BCL` evaluation → registry → sysfs → `_BCM`.

    /// Reset every registry the fixture smokes touch: the backlight
    /// registries, sysfs, the AML namespace + notify table, and the
    /// brightness-key handler.
    fn reset_fixture_state() {
        __reset_all_for_test();
        sysfs_reset();
        av_reset();
        bk_reset();
        narf_aml::sync::__reset_for_test();
        narf_aml::__reset_for_test();
    }

    /// Parse the fixture DSDT into the AML namespace. Expects
    /// exactly the 7 nodes the fixture declares (Scope `\_SB`,
    /// Devices `GFX0` + `DD0`, Name `LEVL`, Methods `_BCL` / `_BCM`
    /// / `_BQC`).
    fn install_fixture_dsdt() -> Result<(), &'static str> {
        let parsed = narf_aml::__parse_body_for_test(&dsdt_bytes(), "\\")
            .map_err(|_| "fixture DSDT parse failed")?;
        if parsed != 7 {
            return Err("fixture DSDT parsed an unexpected node count");
        }
        if narf_aml::find_node(DD0_PATH).is_none() {
            return Err("fixture DD0 device missing from the namespace");
        }
        Ok(())
    }

    /// Read the fixture's firmware-side current level straight out
    /// of AML (`_BQC`), bypassing the driver's `last` cache — the
    /// proof that a dispatched `_BCM` argument actually landed in
    /// firmware state.
    fn fixture_level() -> Option<u32> {
        match evaluate_method(&alloc::format!("{}._BQC", DD0_PATH), &[]) {
            Ok(narf_aml::Value::Integer(v)) => Some(v as u32),
            _ => None,
        }
    }

    // ── 27. Fixture DSDT _BCL parse end to end (AML→registry) ──────

    fn smoke_fixture_dsdt_bcl_parse_end_to_end() -> TestResult {
        reset_fixture_state();
        if let Err(e) = install_fixture_dsdt() {
            reset_fixture_state();
            return TestResult::Fail(e);
        }

        // Production discovery: walk the AML namespace, evaluate
        // _BCL per device, register what answers.
        crate::acpi_video::init();

        let devs = crate::acpi_video::acpi_video_devices();
        if devs.len() != 1 {
            reset_fixture_state();
            return TestResult::Fail("discovery found != 1 ACPI video device");
        }
        let dev = &devs[0];
        if dev.name != "acpi_video0" {
            reset_fixture_state();
            return TestResult::Fail("discovered device is not acpi_video0");
        }
        if dev.acpi_path != DD0_PATH {
            reset_fixture_state();
            return TestResult::Fail("discovered device has the wrong AML path");
        }
        // _BCL [80, 100, 0, 10, …, 100] → first two stripped, the
        // ladder is 0..=100 in steps of 10.
        if dev.levels.len() != 11 {
            reset_fixture_state();
            return TestResult::Fail("ladder len != 11");
        }
        if dev.levels.as_slice() != BCL_LADDER {
            reset_fixture_state();
            return TestResult::Fail("ladder != fixture ladder");
        }
        if dev.levels[0] != 0 || dev.levels[5] != 50 || dev.levels[10] != 100 {
            reset_fixture_state();
            return TestResult::Fail("ladder values wrong");
        }
        if dev.max_brightness() != 100 {
            reset_fixture_state();
            return TestResult::Fail("max != 100");
        }
        // _BQC read-back through the driver: firmware starts at 50.
        if dev.current_brightness() != 50 {
            reset_fixture_state();
            return TestResult::Fail("initial _BQC read-back != 50");
        }
        // The discovered device is the elected panel owner.
        match panel_owner() {
            Some(o) if o.name() == "acpi_video0" => {}
            _ => {
                reset_fixture_state();
                return TestResult::Fail("fixture device is not the panel owner");
            }
        }

        reset_fixture_state();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_fixture_dsdt_bcl_parse_end_to_end);

    // ── 28. Fixture DSDT _BCM captures the dispatched argument ─────

    fn smoke_fixture_dsdt_bcm_captures_argument() -> TestResult {
        reset_fixture_state();
        if let Err(e) = install_fixture_dsdt() {
            reset_fixture_state();
            return TestResult::Fail(e);
        }
        crate::acpi_video::init();

        let devs = crate::acpi_video::acpi_video_devices();
        if devs.len() != 1 {
            reset_fixture_state();
            return TestResult::Fail("discovery found != 1 ACPI video device");
        }
        let dev = &devs[0];

        // Firmware starts at 50.
        if fixture_level() != Some(50) {
            reset_fixture_state();
            return TestResult::Fail("initial firmware level != 50");
        }
        // 63 is not a ladder rung: the driver snaps to 60 and _BCM
        // must receive exactly 60 — read it back out of AML, not
        // out of the driver's cache.
        dev.set_brightness(63);
        if fixture_level() != Some(60) {
            reset_fixture_state();
            return TestResult::Fail("_BCM did not capture the snapped level 60");
        }
        // Prove the live query path too: drop the driver's cache and
        // re-read through _BQC.
        dev.last.store(-1, Ordering::Release);
        if dev.current_brightness() != 60 {
            reset_fixture_state();
            return TestResult::Fail("_BQC re-query did not return 60");
        }
        dev.set_brightness(100);
        if fixture_level() != Some(100) {
            reset_fixture_state();
            return TestResult::Fail("_BCM did not capture 100");
        }
        dev.set_brightness(0);
        if fixture_level() != Some(0) {
            reset_fixture_state();
            return TestResult::Fail("_BCM did not capture 0");
        }
        // Out-of-range clamps through the ladder: 1000 snaps to 100.
        dev.set_brightness(1000);
        if fixture_level() != Some(100) {
            reset_fixture_state();
            return TestResult::Fail("_BCM did not capture the clamped level 100");
        }

        reset_fixture_state();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_fixture_dsdt_bcm_captures_argument
    );

    // ── 29. Fixture DSDT sysfs end to end ──────────────────────────

    fn smoke_fixture_dsdt_sysfs_end_to_end() -> TestResult {
        reset_fixture_state();
        sysfs_reset();
        if let Err(e) = install_fixture_dsdt() {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail(e);
        }
        crate::acpi_video::init();
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => {
                reset_fixture_state();
                sysfs_reset();
                return TestResult::Fail("acpi_video0 not published to /sys/class/backlight");
            }
        };
        if kobj.attr_show("max_brightness").unwrap_or_default().trim() != "100" {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("max_brightness did not read 100 through sysfs");
        }
        if kobj.attr_show("brightness").unwrap_or_default().trim() != "50" {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("brightness did not read the initial 50 through sysfs");
        }
        // A sysfs store travels brightness → snap → _BCM(70).
        if !matches!(kobj.attr_store("brightness", b"70\n"), Some(Ok(()))) {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("brightness store(70) failed");
        }
        if fixture_level() != Some(70) {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("sysfs store(70) did not reach _BCM");
        }
        if kobj.attr_show("brightness").unwrap_or_default().trim() != "70" {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("brightness read-back wrong after store(70)");
        }
        // Off-ladder store snaps: 63 → _BCM(60).
        if !matches!(kobj.attr_store("brightness", b"63\n"), Some(Ok(()))) {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("brightness store(63) failed");
        }
        if fixture_level() != Some(60) {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("sysfs store(63) did not snap to _BCM(60)");
        }

        reset_fixture_state();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_fixture_dsdt_sysfs_end_to_end);

    // ── 30. Composition: fixture panel is populated by the composed boot path ──

    fn smoke_fixture_dsdt_composition_populates_panel() -> TestResult {
        reset_fixture_state();
        sysfs_reset();
        if let Err(e) = install_fixture_dsdt() {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail(e);
        }

        // The composed boot path (#947): the Stage::Device initcalls
        // run acpi-video discovery, then the sysfs initcall
        // populates the class. (Dynamic publication would publish
        // on registration anyway; this smoke pins the composed
        // sequence itself.)
        crate::acpi_video::init();
        populate_backlight_class();

        // /sys/class/backlight/<panel> is populated — looked up
        // through the non-creating child accessors so the assertion
        // cannot create the entries it checks.
        let root = narf_filesystem::sysfs::sysfs_root();
        let class_dir = match root.get_child("class") {
            Some(c) => c,
            None => {
                reset_fixture_state();
                sysfs_reset();
                return TestResult::Fail("/sys/class missing");
            }
        };
        let backlight_dir = match class_dir.get_child("backlight") {
            Some(c) => c,
            None => {
                reset_fixture_state();
                sysfs_reset();
                return TestResult::Fail("/sys/class/backlight missing after populate");
            }
        };
        let panel = match backlight_dir.get_child("acpi_video0") {
            Some(k) => k,
            None => {
                reset_fixture_state();
                sysfs_reset();
                return TestResult::Fail("/sys/class/backlight/acpi_video0 missing");
            }
        };
        if panel.attr_show("type").unwrap_or_default().trim() != "firmware" {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("panel type is not firmware");
        }
        if panel.attr_show("max_brightness").unwrap_or_default().trim() != "100" {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("panel max_brightness is not 100");
        }
        if panel.attr_show("brightness").unwrap_or_default().trim() != "50" {
            reset_fixture_state();
            sysfs_reset();
            return TestResult::Fail("panel brightness is not the initial 50");
        }
        // And the published panel is the elected owner.
        match panel_owner() {
            Some(o) if o.name() == "acpi_video0" => {}
            _ => {
                reset_fixture_state();
                sysfs_reset();
                return TestResult::Fail("published panel is not the panel owner");
            }
        }

        reset_fixture_state();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_fixture_dsdt_composition_populates_panel
    );
}
