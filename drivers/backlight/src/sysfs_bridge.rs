//! Sysfs bridge: `/sys/class/backlight/<name>/` per registered device.
//!
//! Wires every [`crate::BacklightDevice`] in the global registry into
//! the kobject tree so that userspace (and the boot diagnostics) can
//! read and set panel brightness through the standard sysfs interface.
//!
//! # Attributes exposed
//!
//! Per device directory `/sys/class/backlight/<name>/`:
//!
//! | file              | access | semantics                                      |
//! |-------------------|--------|------------------------------------------------|
//! | `brightness`      | rw     | current brightness; store clamps to [0, max]   |
//! | `max_brightness`  | ro     | maximum brightness level                       |
//! | `actual_brightness` | ro   | same as `brightness` (no hw readback in v1)   |
//! | `bl_power`        | rw     | 0 = on, 4 = off (FB_BLANK_* values)           |
//! | `type`            | ro     | "raw", "firmware", or "platform"               |
//!
//! # Design
//!
//! Each attribute closure captures an `Arc<dyn BacklightDevice>` so it
//! holds a live reference without any global lookup per read/write.
//!
//! The `bl_power` state is held in a per-device `AtomicU32`; Linux uses
//! `backlight_device.props.power` for the same purpose.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/video/backlight/backlight.c:brightness_show` (line 178)
//! - `drivers/video/backlight/backlight.c:brightness_store` (line 209)
//! - `drivers/video/backlight/backlight.c:bl_power_show` (line 137)
//! - `drivers/video/backlight/backlight.c:bl_power_store` (line 145)
//! - `drivers/video/backlight/backlight.c:max_brightness_show` (line 235)
//! - `drivers/video/backlight/backlight.c:actual_brightness_show` (line 244)
//! - `drivers/video/backlight/backlight.c:type_show` (line 226)

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
};
use narf_filesystem::FsError;

use crate::{backlight_devices, BacklightDevice, BacklightKind};

// ── bl_power per-device state ─────────────────────────────────────────

/// Power-state atom for one backlight device.
///
/// Linux: `backlight_device.props.power` (`include/linux/backlight.h`).
/// Values: 0 = FB_BLANK_UNBLANK (on), 4 = FB_BLANK_POWERDOWN (off).
#[derive(Debug)]
struct BlPowerState(AtomicU32);

impl BlPowerState {
    const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
    fn get(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }
    fn set(&self, v: u32) {
        self.0.store(v, Ordering::Release);
    }
}

// ── populate ─────────────────────────────────────────────────────────

/// Register `/sys/class/backlight/<name>/` for every device in the
/// backlight registry.
///
/// Called once from the `backlight/sysfs` initcall (Stage::Device,
/// after all hardware drivers have run their own initcalls).
///
/// Linux ref: `backlight_register_attrs` called from
/// `backlight_device_register` (`drivers/video/backlight/backlight.c`).
pub fn populate_backlight_class() {
    let class = class_register("backlight");

    for dev in backlight_devices() {
        register_one(class.clone(), dev);
    }
}

fn register_one(
    class: Arc<narf_filesystem::sysfs::Kobject>,
    dev: Arc<dyn BacklightDevice>,
) {
    let name = dev.name();
    let kobj = class_device_register(class, name);

    // ── brightness (rw) ───────────────────────────────────────────
    // Linux ref: `brightness_show` (backlight.c:178), `brightness_store` (209).
    {
        let d = dev.clone();
        let d2 = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "brightness",
            move || format!("{}\n", d.current_brightness()),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                let clamped = v.min(d2.max_brightness());
                d2.set_brightness(clamped);
                Ok(())
            },
        );
    }

    // ── max_brightness (ro) ───────────────────────────────────────
    // Linux ref: `max_brightness_show` (backlight.c:235).
    {
        let d = dev.clone();
        kobject_add_attr(&kobj, "max_brightness", move || {
            format!("{}\n", d.max_brightness())
        });
    }

    // ── actual_brightness (ro) ────────────────────────────────────
    // Linux ref: `actual_brightness_show` (backlight.c:244).
    // v1: no get_brightness op; mirrors brightness.
    {
        let d = dev.clone();
        kobject_add_attr(&kobj, "actual_brightness", move || {
            format!("{}\n", d.current_brightness())
        });
    }

    // ── bl_power (rw) ─────────────────────────────────────────────
    // Linux ref: `bl_power_show` (backlight.c:137), `bl_power_store` (145).
    // Values: 0 = FB_BLANK_UNBLANK (on), 4 = FB_BLANK_POWERDOWN (off).
    {
        let power = Arc::new(BlPowerState::new());
        let pr = power.clone();
        let pw = power.clone();
        let dev_pw = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "bl_power",
            move || format!("{}\n", pr.get()),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                // Only 0 and 4 are valid per Linux `FB_BLANK_*`.
                if v != 0 && v != 4 {
                    return Err(FsError::InvalidData);
                }
                pw.set(v);
                if v == 4 {
                    // Blank: drive brightness to 0.
                    dev_pw.set_brightness(0);
                }
                Ok(())
            },
        );
    }

    // ── type (ro) ─────────────────────────────────────────────────
    // Linux ref: `type_show` (backlight.c:226).
    {
        let kind = dev.kind();
        kobject_add_attr(&kobj, "type", move || {
            let s = match kind {
                BacklightKind::Raw => "raw",
                BacklightKind::Firmware => "firmware",
                BacklightKind::Platform => "platform",
            };
            format!("{}\n", s)
        });
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use alloc::string::ToString;
    use core::sync::atomic::Ordering;

    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;

    use crate::acpi_video::__test_install;
    use crate::acpi_video::__reset_for_test as av_reset;
    use crate::{__reset_all_for_test, BacklightDevice};
    use super::populate_backlight_class;

    fn read_attr(kobj: &narf_filesystem::sysfs::Kobject, attr: &str) -> alloc::string::String {
        kobj.attr_show(attr).unwrap_or_default()
    }

    fn reset() {
        __reset_all_for_test();
        av_reset();
        sysfs_reset();
    }

    // ── smoke 1: brightness read ────────────────────────────────────

    fn smoke_bl_brightness_read() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        dev.last.store(50, Ordering::Release);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => { reset(); return TestResult::Fail("acpi_video0 kobj missing"); }
        };
        let got = read_attr(&kobj, "brightness").trim().to_string();
        reset();
        if got != "50" {
            return TestResult::Fail("brightness read wrong value");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_brightness_read);

    // ── smoke 2: brightness write → set_brightness called ──────────

    fn smoke_bl_brightness_write() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        dev.last.store(0, Ordering::Release);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => { reset(); return TestResult::Fail("kobj missing"); }
        };
        match kobj.attr_store("brightness", b"50\n") {
            Some(Ok(())) => {}
            _ => { reset(); return TestResult::Fail("brightness store failed"); }
        }
        let new_level = dev.last.load(Ordering::Acquire);
        reset();
        if new_level != 50 {
            return TestResult::Fail("device brightness not updated after store");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_brightness_write);

    // ── smoke 3: max_brightness read ────────────────────────────────

    fn smoke_bl_max_brightness_read() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => { reset(); return TestResult::Fail("kobj missing"); }
        };
        let got = read_attr(&kobj, "max_brightness").trim().to_string();
        reset();
        if got != "100" {
            return TestResult::Fail("max_brightness wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_max_brightness_read);

    // ── smoke 4: type attr returns "firmware" for ACPI video ────────

    fn smoke_bl_type_attr() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => { reset(); return TestResult::Fail("kobj missing"); }
        };
        let got = read_attr(&kobj, "type").trim().to_string();
        reset();
        if got != "firmware" {
            return TestResult::Fail("type attr wrong (expected firmware)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_type_attr);

    // ── smoke 5: bl_power toggle ─────────────────────────────────────

    fn smoke_bl_power_write() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        dev.last.store(80, Ordering::Release);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => { reset(); return TestResult::Fail("kobj missing"); }
        };

        if !matches!(kobj.attr_store("bl_power", b"4"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(4) failed");
        }
        let got = read_attr(&kobj, "bl_power").trim().to_string();
        if got != "4" {
            reset();
            return TestResult::Fail("bl_power read after store(4) wrong");
        }
        if !matches!(kobj.attr_store("bl_power", b"0"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(0) failed");
        }
        let got2 = read_attr(&kobj, "bl_power").trim().to_string();
        reset();
        if got2 != "0" {
            return TestResult::Fail("bl_power read after store(0) wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_power_write);

    // ── smoke 6: brightness clamped at max ──────────────────────────

    fn smoke_bl_brightness_clamp() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => { reset(); return TestResult::Fail("kobj missing"); }
        };
        if !matches!(kobj.attr_store("brightness", b"9999"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("brightness store(9999) error");
        }
        // AcpiVideoDevice.last is AtomicI32; max is 100, so 9999 clamps to 100.
        let new_level = dev.last.load(Ordering::Acquire);
        reset();
        if new_level != 100 {
            return TestResult::Fail("brightness not clamped to max");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_brightness_clamp);
}
