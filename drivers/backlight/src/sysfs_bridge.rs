//! Sysfs bridge: `/sys/class/backlight/<name>/` for the panel owner.
//!
//! Wires the panel owner elected by the subsystem's single-owner
//! arbitration ([`crate::panel_owner`]) into the kobject tree so
//! that userspace (and the boot diagnostics) can read and set panel
//! brightness through the standard sysfs interface. Deferred
//! candidates are deliberately NOT published: a sysfs directory for
//! a loser would give userspace a path that drives hardware the
//! subsystem has decided another device owns.
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
//! The per-device properties are held in a [`BlProps`] atom pair —
//! Linux's `backlight_device.props.power` + `props.brightness`.
//! Blanking changes only the power atom and drives the applied level
//! to 0; the level atom is never written by blanking, so the user's
//! level survives a blank/unblank cycle and is re-applied on unblank
//! (`backlight_update_status` semantics, #953).
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
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
};
use narf_filesystem::FsError;

use crate::{panel_owner, BacklightDevice, BacklightKind};

// ── per-device props (power + requested level) ────────────────────────

/// Per-device backlight properties held by the bridge.
///
/// Linux: `backlight_device.props` (`include/linux/backlight.h`) —
/// `power` is the FB_BLANK_* state (0 = FB_BLANK_UNBLANK, on;
/// 4 = FB_BLANK_POWERDOWN, off) and `level` is the user's requested
/// brightness (`props.brightness`). The two are independent: the
/// level applied to the device is `level` while unblanked and 0
/// while blanked (`backlight_update_status`,
/// `drivers/video/backlight/backlight.c`), and blanking must never
/// destroy `level`. The pre-#953 handler kept only the power atom
/// and routed blanking through `set_brightness(0)`, which on devices
/// that cache their level (ACPI video) destroyed the user's level;
/// unblank then restored nothing and the panel stayed dark.
#[derive(Debug)]
struct BlProps {
    power: AtomicU32,
    level: AtomicU32,
}

impl BlProps {
    fn new(level: u32) -> Self {
        Self {
            power: AtomicU32::new(0),
            level: AtomicU32::new(level),
        }
    }
    fn power(&self) -> u32 {
        self.power.load(Ordering::Acquire)
    }
    fn set_power(&self, v: u32) {
        self.power.store(v, Ordering::Release);
    }
    fn level(&self) -> u32 {
        self.level.load(Ordering::Acquire)
    }
    fn set_level(&self, v: u32) {
        self.level.store(v, Ordering::Release);
    }
}

// ── populate ─────────────────────────────────────────────────────────

/// Register `/sys/class/backlight/<name>/` for the panel owner.
///
/// Only the owner elected by the single-owner arbitration is
/// published; deferred candidates get no directory. Publication is
/// still a snapshot taken when this runs (dynamic publication on
/// register/unregister is the #952 follow-up); arbitration decides
/// *which* device the snapshot may contain.
///
/// Called once from the `backlight/sysfs` initcall (Stage::Device,
/// after all hardware drivers have run their own initcalls).
///
/// Linux ref: `backlight_register_attrs` called from
/// `backlight_device_register` (`drivers/video/backlight/backlight.c`).
pub fn populate_backlight_class() {
    let class = class_register("backlight");

    if let Some(owner) = panel_owner() {
        register_one(class, owner);
    }
}

fn register_one(class: Arc<narf_filesystem::sysfs::Kobject>, dev: Arc<dyn BacklightDevice>) {
    let name = dev.name();
    let kobj = class_device_register(class, name);

    // Per-device props shared by the `brightness` and `bl_power`
    // closures; the level atom starts at the device's live level.
    let props = Arc::new(BlProps::new(dev.current_brightness()));

    // ── brightness (rw) ───────────────────────────────────────────
    // Linux ref: `brightness_show` (backlight.c:178), `brightness_store` (209).
    {
        let d = dev.clone();
        let d2 = dev.clone();
        let pb = props.clone();
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
                // Always record the requested level in props (Linux
                // `props.brightness`); drive the device only while
                // unblanked — a store while blanked takes effect at
                // unblank and must not light the panel now (#953).
                pb.set_level(clamped);
                if pb.power() == 0 {
                    d2.set_brightness(clamped);
                }
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
        let pr = props.clone();
        let pw = props.clone();
        let dev_pw = dev.clone();
        kobject_add_writable_attr(
            &kobj,
            "bl_power",
            move || format!("{}\n", pr.power()),
            move |buf| {
                let s = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                // Only 0 and 4 are valid per Linux `FB_BLANK_*`.
                if v != 0 && v != 4 {
                    return Err(FsError::InvalidData);
                }
                let prev = pw.power();
                pw.set_power(v);
                if v == 4 && prev != 4 {
                    // Blank (FB_BLANK_POWERDOWN): capture the live
                    // level into props, then drive the applied level
                    // to 0. The capture is the record unblank
                    // restores from; the level atom itself is never
                    // zeroed (#953). A repeated store(4) while
                    // already blanked must NOT re-capture — the live
                    // level is 0 by then and capturing it would
                    // destroy the saved level.
                    pw.set_level(dev_pw.current_brightness());
                    dev_pw.set_brightness(0);
                } else if v == 0 && prev != 0 {
                    // Unblank (FB_BLANK_UNBLANK): re-apply the level
                    // held in props (Linux `backlight_update_status`
                    // re-applies `props.brightness` on unblank).
                    dev_pw.set_brightness(pw.level());
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

    use alloc::string::ToString;
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::populate_backlight_class;
    use crate::acpi_video::__reset_for_test as av_reset;
    use crate::acpi_video::__test_install;
    use crate::{BacklightDevice, __reset_all_for_test};

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
            None => {
                reset();
                return TestResult::Fail("acpi_video0 kobj missing");
            }
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
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        match kobj.attr_store("brightness", b"50\n") {
            Some(Ok(())) => {}
            _ => {
                reset();
                return TestResult::Fail("brightness store failed");
            }
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
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
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
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
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
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
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
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
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

    // ── smoke 7: blank → unblank restores the level (#953) ────────
    //
    // Linux semantics (backlight.c `backlight_update_status`):
    // blanking applies 0 but leaves `props.brightness` intact;
    // unblanking re-applies it. Pre-fix, blanking routed through
    // `set_brightness(0)` — destroying the ACPI device's cached
    // level — and unblank restored nothing.

    fn smoke_bl_power_unblank_restores_level() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        if !matches!(kobj.attr_store("brightness", b"50\n"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("brightness store(50) failed");
        }
        if dev.last.load(Ordering::Acquire) != 50 {
            reset();
            return TestResult::Fail("level not applied before blank");
        }
        if !matches!(kobj.attr_store("bl_power", b"4"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(4) failed");
        }
        if dev.last.load(Ordering::Acquire) != 0 {
            reset();
            return TestResult::Fail("blank did not drive the level to 0");
        }
        if !matches!(kobj.attr_store("bl_power", b"0"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(0) failed");
        }
        let restored = dev.last.load(Ordering::Acquire);
        reset();
        if restored != 50 {
            return TestResult::Fail("unblank did not restore the pre-blank level");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_power_unblank_restores_level);

    // ── smoke 8: blank at level 0, unblank restores 0 (#953) ──────

    fn smoke_bl_power_blank_at_zero() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        dev.last.store(0, Ordering::Release);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        if !matches!(kobj.attr_store("bl_power", b"4"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(4) failed");
        }
        if dev.last.load(Ordering::Acquire) != 0 {
            reset();
            return TestResult::Fail("blank-at-zero changed the level");
        }
        if !matches!(kobj.attr_store("bl_power", b"0"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(0) failed");
        }
        let lvl = dev.last.load(Ordering::Acquire);
        let pwr = read_attr(&kobj, "bl_power").trim().to_string();
        reset();
        if lvl != 0 {
            return TestResult::Fail("unblank after blank-at-zero changed the level");
        }
        if pwr != "0" {
            return TestResult::Fail("bl_power not back to 0 after unblank");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_power_blank_at_zero);

    // ── smoke 9: double blank must not destroy the saved level ────
    //
    // A second store(4) while already blanked sees a live level of
    // 0; an implementation that re-captures on every blank would
    // save 0 and the unblank below would restore darkness (#953).

    fn smoke_bl_power_double_blank_keeps_level() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        if !matches!(kobj.attr_store("brightness", b"50\n"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("brightness store(50) failed");
        }
        if !matches!(kobj.attr_store("bl_power", b"4"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("first bl_power store(4) failed");
        }
        if !matches!(kobj.attr_store("bl_power", b"4"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("second bl_power store(4) failed");
        }
        if !matches!(kobj.attr_store("bl_power", b"0"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(0) failed");
        }
        let restored = dev.last.load(Ordering::Acquire);
        reset();
        if restored != 50 {
            return TestResult::Fail("double blank destroyed the saved level");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_power_double_blank_keeps_level);

    // ── smoke 10: brightness store while blanked applies at unblank ──
    //
    // Linux: a `brightness` store updates `props.brightness` even
    // while blanked; the panel stays dark until unblank, which then
    // applies the NEW level, not the pre-blank one (#953).

    fn smoke_bl_brightness_store_while_blanked() -> TestResult {
        reset();
        let dev = __test_install("acpi_video0", r"\_SB.GFX0.DD0", alloc::vec![0, 50, 100]);
        crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
        populate_backlight_class();

        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("acpi_video0") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("kobj missing");
            }
        };
        if !matches!(kobj.attr_store("brightness", b"50\n"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("brightness store(50) failed");
        }
        if !matches!(kobj.attr_store("bl_power", b"4"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(4) failed");
        }
        if !matches!(kobj.attr_store("brightness", b"100\n"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("brightness store(100) while blanked failed");
        }
        if dev.last.load(Ordering::Acquire) != 0 {
            reset();
            return TestResult::Fail("brightness store lit the panel while blanked");
        }
        if !matches!(kobj.attr_store("bl_power", b"0"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("bl_power store(0) failed");
        }
        let restored = dev.last.load(Ordering::Acquire);
        reset();
        if restored != 100 {
            return TestResult::Fail("unblank did not apply the level stored while blanked");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/backlight", smoke_bl_brightness_store_while_blanked);
}
