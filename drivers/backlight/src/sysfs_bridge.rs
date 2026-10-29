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
//! Publication is **dynamic** (#952): [`sync_publication`] runs
//! after every registry change (register, unregister, test reset),
//! so the class always mirrors the current election — a device
//! registered from a PCI probe appears immediately, a preempted
//! owner disappears, and a promoted candidate takes its place. The
//! earlier one-shot snapshot taken by a Stage::Device initcall
//! could never publish probe-registered devices, because crate
//! Device initcalls run before `probe_all_pci` within the stage.
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
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
};
use narf_filesystem::FsError;

use crate::{panel_owner, BacklightDevice, BacklightKind};

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

// ── publication ──────────────────────────────────────────────────────

/// Reconcile `/sys/class/backlight` with the elected panel owner.
///
/// The class directory is created if absent (so it exists even on
/// a panel-less machine), any published child that is not the
/// current owner is removed, and the owner is published if it is
/// not already. The reconciliation is derived from the kobject
/// tree itself rather than shadow state, so it converges to the
/// current election regardless of the order registrations,
/// unregistrations, and test resets interleave.
///
/// Called from [`crate::register_backlight`] and
/// [`crate::unregister_backlight`] after the registry lock is
/// dropped; concurrent reconciliations are idempotent and the last
/// one to run observes the final election.
///
/// Linux ref: `backlight_register_attrs` / `backlight_device_unregister`
/// driven from `backlight_device_register`
/// (`drivers/video/backlight/backlight.c`).
pub fn sync_publication() {
    let class = class_register("backlight");
    let owner = panel_owner();
    let owner_name = owner.as_ref().map(|d| d.name());
    for child in class.child_names() {
        if Some(child.as_str()) != owner_name {
            class.remove_child(&child);
        }
    }
    if let Some(owner) = owner {
        if class.get_child(owner.name()).is_none() {
            register_one(class, owner);
        }
    }
}

/// Remove `name`'s sysfs directory if it is published.
///
/// Used when a same-name registration replaces the device object:
/// the published attribute closures capture the superseded `Arc`,
/// so the directory is dropped and the following
/// [`sync_publication`] rebuilds it against the replacement.
pub fn unpublish(name: &str) {
    let class = class_register("backlight");
    class.remove_child(name);
}

/// Populate `/sys/class/backlight` for the current panel owner.
///
/// Kept as the body of the `backlight/sysfs` initcall (Stage::Device):
/// it guarantees the class directory exists from boot even before
/// any device registers, and reconciles publication with whatever
/// the initcalls registered. Probe-time registrations afterwards
/// publish themselves via [`sync_publication`].
pub fn populate_backlight_class() {
    sync_publication();
}

fn register_one(class: Arc<narf_filesystem::sysfs::Kobject>, dev: Arc<dyn BacklightDevice>) {
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

    use alloc::string::ToString;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

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

    // ── dynamic publication fixtures (#952) ────────────────────────

    /// Minimal panel stub for the publication fixtures: the ACPI
    /// test device is always Firmware-kind, so exercising
    /// preemption needs a stub that can present a Raw candidate.
    #[derive(Debug)]
    struct StubPanel {
        name: &'static str,
        kind: crate::BacklightKind,
        level: AtomicU32,
    }

    impl StubPanel {
        fn new(name: &'static str, kind: crate::BacklightKind) -> Arc<Self> {
            Arc::new(Self {
                name,
                kind,
                level: AtomicU32::new(0),
            })
        }
    }

    impl BacklightDevice for StubPanel {
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
        fn kind(&self) -> crate::BacklightKind {
            self.kind
        }
    }

    // ── smoke 7: publication follows registration (probe order) ───

    fn smoke_bl_dynamic_publication_on_register() -> TestResult {
        reset();
        // A firmware candidate registers (its Stage::Device initcall
        // on a real boot) and is published immediately — no populate
        // call anywhere in this fixture.
        let fw = StubPanel::new("acpi_video0", crate::BacklightKind::Firmware);
        crate::register_backlight(fw as Arc<dyn BacklightDevice>);
        let class = narf_filesystem::sysfs::class_register("backlight");
        if class.get_child("acpi_video0").is_none() {
            reset();
            return TestResult::Fail("owner not published on register");
        }
        // A raw candidate arriving later (the PCI-probe order that
        // defeated the old one-shot snapshot) preempts, and the
        // publication swaps with the election.
        let raw = StubPanel::new("amdgpu_bl0", crate::BacklightKind::Raw);
        crate::register_backlight(raw.clone() as Arc<dyn BacklightDevice>);
        if class.get_child("acpi_video0").is_some() {
            reset();
            return TestResult::Fail("preempted owner still published");
        }
        let kobj = match class.get_child("amdgpu_bl0") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("preempting owner not published");
            }
        };
        // The swapped-in directory is live, not a tombstone.
        if !matches!(kobj.attr_store("brightness", b"33\n"), Some(Ok(()))) {
            reset();
            return TestResult::Fail("brightness store on swapped owner failed");
        }
        let lvl = raw.level.load(Ordering::Acquire);
        reset();
        if lvl != 33 {
            return TestResult::Fail("store did not reach the swapped owner");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_bl_dynamic_publication_on_register
    );

    // ── smoke 8: publication follows unregistration / promotion ───

    fn smoke_bl_dynamic_publication_on_unregister() -> TestResult {
        reset();
        let fw = StubPanel::new("acpi_video0", crate::BacklightKind::Firmware);
        let raw = StubPanel::new("amdgpu_bl0", crate::BacklightKind::Raw);
        crate::register_backlight(fw as Arc<dyn BacklightDevice>);
        crate::register_backlight(raw as Arc<dyn BacklightDevice>);
        let class = narf_filesystem::sysfs::class_register("backlight");
        // The owner unregisters (GPU unbind): the promoted
        // candidate is published in its place, again with no
        // populate call.
        crate::unregister_backlight("amdgpu_bl0");
        if class.get_child("amdgpu_bl0").is_some() {
            reset();
            return TestResult::Fail("unregistered owner still published");
        }
        if class.get_child("acpi_video0").is_none() {
            reset();
            return TestResult::Fail("promoted candidate not published");
        }
        // The last candidate leaves: no children remain, but the
        // class directory itself persists.
        crate::unregister_backlight("acpi_video0");
        let empty = class.child_names().is_empty();
        reset();
        if !empty {
            return TestResult::Fail("class not empty after last unregister");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_bl_dynamic_publication_on_unregister
    );

    // ── smoke 9: Intel install publishes through arbitration (#1021)

    fn smoke_bl_intel_install_publishes_via_arbitration() -> TestResult {
        reset();
        // Fake BAR0 covering the BXT PWM registers (the same
        // heap-buffer pattern as the Intel PWM round-trip smoke in
        // crate::tests — a stack array this size would overflow).
        let buf: alloc::boxed::Box<[u8]> = alloc::vec![0u8; 0xC9000].into_boxed_slice();
        let raw = alloc::boxed::Box::leak(buf);
        let phys = narf_memory::PhysAddr::new(raw.as_ptr() as u64);
        let mmio = narf_driver_runtime::MmioRegion {
            phys,
            virt: phys.raw(),
            len: raw.len() as u64,
            kind: narf_driver_runtime::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // Seed BXT_BLC_PWM_FREQ1 (byte offset 0xC8254) with a period.
        // SAFETY: the buffer backs the whole register window the
        // install path touches (SOUTH_CHICKEN1 + the BXT PWM block).
        unsafe {
            core::ptr::write_volatile((raw.as_ptr() as *mut u32).add(0xC8254 / 4), 0x1000);
        }
        // The production caller: the Intel GPU probe's install hook.
        crate::intel_bl::install(mmio);
        // Exactly one arbitrated path: the device is the panel
        // owner and is published with no populate call.
        match crate::panel_owner() {
            Some(o) if o.name() == "intel_backlight" => {}
            _ => {
                reset();
                return TestResult::Fail("intel device is not the panel owner");
            }
        }
        let class = narf_filesystem::sysfs::class_register("backlight");
        let kobj = match class.get_child("intel_backlight") {
            Some(k) => k,
            None => {
                reset();
                return TestResult::Fail("intel_backlight not published on install");
            }
        };
        let got = read_attr(&kobj, "type").trim().to_string();
        reset();
        if got != "raw" {
            return TestResult::Fail("intel_backlight type != raw");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/backlight",
        smoke_bl_intel_install_publishes_via_arbitration
    );
}
