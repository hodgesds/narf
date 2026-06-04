//! Sysfs bridge: `/sys/class/leds/<name>/` per registered LED device.
//!
//! Wires every [`crate::LedDevice`] in the global registry into the
//! kobject tree so that userspace can read/write LED brightness and
//! set/query triggers through the standard sysfs interface.
//!
//! # Attributes exposed
//!
//! Per device directory `/sys/class/leds/<name>/`:
//!
//! | file           | access | semantics                                        |
//! |----------------|--------|--------------------------------------------------|
//! | `brightness`   | rw     | current brightness 0..max; calls set_brightness  |
//! | `max_brightness` | ro   | maximum brightness level                         |
//! | `trigger`      | rw     | trigger name: "none", "heartbeat", "timer", …    |
//! | `delay_on`     | rw     | on-time ms (only meaningful when trigger=timer)   |
//! | `delay_off`    | rw     | off-time ms (only meaningful when trigger=timer)  |
//!
//! # Trigger naming
//!
//! Trigger names follow Linux convention (`drivers/leds/led-triggers.c`):
//! - `"none"` — `Trigger::None`
//! - `"default-on"` — `Trigger::DefaultOn`
//! - `"heartbeat"` — `Trigger::Heartbeat`
//! - `"timer"` — `Trigger::Timer { .. }`
//! - `"disk-activity"` — `Trigger::DiskActivity`
//! - `"netdev"` — `Trigger::NetworkActivity { .. }`
//! - `"ac-online"` — `Trigger::AcOnline`
//! - `"charging"` — `Trigger::BatteryCharging`
//!
//! `delay_on` / `delay_off` are read/write at all times; they only
//! take effect when the trigger is `timer` (written before or after).
//! Linux: `drivers/leds/trigger/ledtrig-timer.c`.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/leds/led-class.c:brightness_show` (line 30)
//! - `drivers/leds/led-class.c:brightness_store` (line 44)
//! - `drivers/leds/led-class.c:max_brightness_show` (line 73)
//! - `drivers/leds/led-triggers.c:led_trigger_write` (line 36)
//! - `drivers/leds/led-triggers.c:led_trigger_read` (line 133)
//! - `drivers/leds/trigger/ledtrig-timer.c:led_delay_on_show` (line 18)
//! - `drivers/leds/trigger/ledtrig-timer.c:led_delay_on_store` (line 26)

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
};
use narf_filesystem::FsError;

use crate::class::{led_devices, LedDevice};
use crate::triggers::Trigger;

// ── Trigger ↔ name conversion ─────────────────────────────────────────

/// Convert a `Trigger` to its Linux sysfs name string.
/// Linux ref: `drivers/leds/led-triggers.c` trigger list.
fn trigger_name(t: &Trigger) -> &'static str {
    match t {
        Trigger::None => "none",
        Trigger::DefaultOn => "default-on",
        Trigger::Heartbeat => "heartbeat",
        Trigger::Timer { .. } => "timer",
        Trigger::OneShot { .. } => "oneshot",
        Trigger::DiskActivity => "disk-activity",
        Trigger::NetworkActivity { .. } => "netdev",
        Trigger::KeyboardCapsLock => "capslock",
        Trigger::KeyboardNumLock => "numlock",
        Trigger::KeyboardScrollLock => "scrolllock",
        Trigger::AcOnline => "ac-online",
        Trigger::BatteryCharging => "charging",
    }
}

/// Parse a trigger name into a `Trigger` value.
/// Returns `None` for unrecognised names.
/// Linux ref: `led_trigger_write` (led-triggers.c:52) string comparison.
fn parse_trigger(name: &str) -> Option<Trigger> {
    match name {
        "none" => Some(Trigger::None),
        "default-on" => Some(Trigger::DefaultOn),
        "heartbeat" => Some(Trigger::Heartbeat),
        "timer" => Some(Trigger::Timer {
            on_ms: 500,
            off_ms: 500,
        }),
        "oneshot" => Some(Trigger::OneShot {
            delay_ms: 0,
            on_ms: 100,
            off_ms: 100,
        }),
        "disk-activity" => Some(Trigger::DiskActivity),
        "netdev" | "network-activity" => Some(Trigger::NetworkActivity { iface: "eth0" }),
        "ac-online" => Some(Trigger::AcOnline),
        "charging" => Some(Trigger::BatteryCharging),
        _ => None,
    }
}

// ── Per-device timer delay state ──────────────────────────────────────

/// Timer delay atoms for `delay_on` / `delay_off` sysfs attrs.
/// Separate from the `Trigger` so userspace can write delays before
/// setting the trigger, matching Linux behaviour.
///
/// Linux ref: `drivers/leds/trigger/ledtrig-timer.c` — `delay_on` /
/// `delay_off` stored in `trig->private_data`.
#[derive(Debug)]
struct TimerDelays {
    on_ms: AtomicU32,
    off_ms: AtomicU32,
}

impl TimerDelays {
    const fn new() -> Self {
        Self {
            on_ms: AtomicU32::new(500),
            off_ms: AtomicU32::new(500),
        }
    }
}

// ── populate ─────────────────────────────────────────────────────────

/// Register `/sys/class/leds/<name>/` for every device in the LED
/// registry.
///
/// Called once from the `leds/sysfs` initcall (Stage::Device).
///
/// Linux ref: `led_classdev_register` calls `device_create_with_groups`
/// which runs `sysfs_create_group` for each `led_groups` entry
/// (`drivers/leds/led-class.c`).
pub fn populate_leds_class() {
    let class = class_register("leds");

    for dev in led_devices() {
        register_one(class.clone(), dev);
    }
}

fn register_one(class: Arc<narf_filesystem::sysfs::Kobject>, dev: Arc<dyn LedDevice>) {
    let name = dev.name();
    let kobj = class_device_register(class, name);

    // ── brightness (rw) ───────────────────────────────────────────
    // Linux ref: `brightness_show` (led-class.c:30), `brightness_store` (44).
    {
        let d = dev.clone();
        let d2 = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "brightness",
            move || format!("{}\n", d.brightness()),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                d2.set_brightness(v);
                Ok(())
            },
        );
    }

    // ── max_brightness (ro) ───────────────────────────────────────
    // Linux ref: `max_brightness_show` (led-class.c:73).
    {
        let d = dev.clone();
        kobject_add_attr(&kobj, "max_brightness", move || {
            format!("{}\n", d.max_brightness())
        });
    }

    // ── trigger (rw) ─────────────────────────────────────────────
    // Linux ref: `led_trigger_read` (led-triggers.c:133),
    //            `led_trigger_write` (led-triggers.c:36).
    {
        let d = dev.clone();
        let d2 = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "trigger",
            move || format!("{}\n", trigger_name(&d.current_trigger())),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                match parse_trigger(s) {
                    Some(t) => {
                        d2.set_trigger(t);
                        Ok(())
                    }
                    None => Err(FsError::InvalidData),
                }
            },
        );
    }

    // ── delay_on (rw) ────────────────────────────────────────────
    // Linux ref: `led_delay_on_show` / `led_delay_on_store`
    //            (`drivers/leds/trigger/ledtrig-timer.c:18,26`).
    {
        let delays = Arc::new(TimerDelays::new());
        let dr = delays.clone();
        let dw = delays.clone();
        let dev_dw = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "delay_on",
            move || format!("{}\n", dr.on_ms.load(Ordering::Acquire)),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                dw.on_ms.store(v, Ordering::Release);
                // Re-arm the timer trigger with new delays if currently active.
                if matches!(dev_dw.current_trigger(), Trigger::Timer { .. }) {
                    let off = dw.off_ms.load(Ordering::Acquire);
                    dev_dw.set_trigger(Trigger::Timer {
                        on_ms: v,
                        off_ms: off,
                    });
                }
                Ok(())
            },
        );
    }

    // ── delay_off (rw) ───────────────────────────────────────────
    // Linux ref: `led_delay_off_show` / `led_delay_off_store`
    //            (`drivers/leds/trigger/ledtrig-timer.c:43,51`).
    {
        let delays2 = Arc::new(TimerDelays::new());
        let dr2 = delays2.clone();
        let dw2 = delays2.clone();
        let dev_dw2 = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "delay_off",
            move || format!("{}\n", dr2.off_ms.load(Ordering::Acquire)),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                dw2.off_ms.store(v, Ordering::Release);
                // Re-arm the timer trigger with new delays if currently active.
                if matches!(dev_dw2.current_trigger(), Trigger::Timer { .. }) {
                    let on = dw2.on_ms.load(Ordering::Acquire);
                    dev_dw2.set_trigger(Trigger::Timer {
                        on_ms: on,
                        off_ms: v,
                    });
                }
                Ok(())
            },
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    extern crate alloc;

    use alloc::string::ToString;
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::populate_leds_class;
    use crate::class::{__reset_for_test as led_reset, register_led, LedDevice, SimpleLed};

    fn read_attr(kobj: &narf_filesystem::sysfs::Kobject, attr: &str) -> alloc::string::String {
        kobj.attr_show(attr).unwrap_or_default()
    }

    fn reset() {
        led_reset();
        sysfs_reset();
    }

    // ── smoke 1: LED brightness write "1" → set_brightness(1) ──────

    fn smoke_led_brightness_write() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::onoff("input0::capslock"));
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("input0::capslock") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("input0::capslock kobj missing");
            }
        };

        match kobj.attr_store("brightness", b"1") {
            Some(Ok(())) => {}
            _ => {
                reset();
                return TestResult::Fail("brightness store(1) failed");
            }
        }
        // SimpleLed.brightness uses AtomicU32.
        let got = led.brightness();
        reset();
        if got != 1 {
            return TestResult::Fail("LED brightness not 1 after store");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_brightness_write);

    // ── smoke 2: max_brightness == 1 for onoff LED ──────────────────

    fn smoke_led_max_brightness_one() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::onoff("input0::capslock"));
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("input0::capslock") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        let got = read_attr(&kobj, "max_brightness").trim().to_string();
        reset();
        if got != "1" {
            return TestResult::Fail("max_brightness should be 1 for onoff LED");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_max_brightness_one);

    // ── smoke 3: trigger write "heartbeat" → Trigger::Heartbeat ────

    fn smoke_led_trigger_write_heartbeat() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::brightness_led("platform::power"));
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("platform::power") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        match kobj.attr_store("trigger", b"heartbeat") {
            Some(Ok(())) => {}
            _ => {
                reset();
                return TestResult::Fail("trigger store failed");
            }
        }
        use crate::triggers::Trigger;
        let got = (led as Arc<dyn LedDevice>).current_trigger();
        reset();
        if got != Trigger::Heartbeat {
            return TestResult::Fail("trigger not Heartbeat after store");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_trigger_write_heartbeat);

    // ── smoke 4: trigger read returns "none" initially ──────────────

    fn smoke_led_trigger_read_none() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::onoff("input0::numlock"));
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("input0::numlock") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        let got = read_attr(&kobj, "trigger").trim().to_string();
        reset();
        if got != "none" {
            return TestResult::Fail("default trigger should be none");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_trigger_read_none);

    // ── smoke 5: enumerate /sys/class/leds → ≥4 entries ────────────

    fn smoke_led_class_enumerate_min4() -> TestResult {
        reset();
        for name in &[
            "input0::capslock",
            "input0::numlock",
            "input0::scrolllock",
            "platform::power",
        ] {
            let led = Arc::new(SimpleLed::onoff(name));
            register_led(led as Arc<dyn LedDevice>);
        }
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let names = class.child_names();
        reset();
        if names.len() < 4 {
            return TestResult::Fail("expected ≥4 LED entries in /sys/class/leds/");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_class_enumerate_min4);

    // ── smoke 6: brightness read returns current value ───────────────

    fn smoke_led_brightness_read() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::brightness_led("test::kbd"));
        led.set_brightness(77);
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("test::kbd") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        let got = read_attr(&kobj, "brightness").trim().to_string();
        reset();
        if got != "77" {
            return TestResult::Fail("brightness read wrong value");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_brightness_read);

    // ── smoke 7: delay_on write updates and re-arms timer trigger ───

    fn smoke_led_delay_on_write() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::brightness_led("test::timer"));
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("test::timer") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };

        // First set trigger to timer.
        let _ = kobj.attr_store("trigger", b"timer");
        // Now write delay_on.
        match kobj.attr_store("delay_on", b"200") {
            Some(Ok(())) => {}
            _ => {
                reset();
                return TestResult::Fail("delay_on store failed");
            }
        }
        let got = read_attr(&kobj, "delay_on").trim().to_string();
        reset();
        if got != "200" {
            return TestResult::Fail("delay_on read wrong after write");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_delay_on_write);

    // ── smoke 8: invalid trigger name → InvalidData ─────────────────

    fn smoke_led_trigger_invalid_name() -> TestResult {
        reset();
        let led = Arc::new(SimpleLed::onoff("test::bad"));
        register_led(led.clone() as Arc<dyn LedDevice>);
        populate_leds_class();

        let class = narf_filesystem::sysfs::class_register("leds");
        let kobj = match class.get_child("test::bad") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        let r = kobj.attr_store("trigger", b"not-a-real-trigger");
        reset();
        if !matches!(r, Some(Err(narf_filesystem::FsError::InvalidData))) {
            return TestResult::Fail("expected InvalidData for unknown trigger");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/leds", smoke_led_trigger_invalid_name);
}
