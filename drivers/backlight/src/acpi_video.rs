//! ACPI video backlight — `_BCL` / `_BCM` / `_BQC` methods.
//!
//! Every modern laptop DSDT exposes a video-output device (typically
//! at `\_SB.PCI0.GFX0.DD1F` or similar) with three child methods:
//!
//! - `_BCL` — returns a `Package` of integers. Element 0 = "AC full
//!   power" default, element 1 = "battery" default, remaining elements
//!   are the supported brightness ladder (e.g. 0, 10, 20, …, 100).
//! - `_BCM(level)` — sets the panel brightness; `level` must be one of
//!   the ladder values from `_BCL`.
//! - `_BQC` — queries current brightness. Returns an integer.
//!
//! This module walks the AML namespace for every Device node that
//! carries a `_BCL` child, creates an [`AcpiVideoDevice`], and
//! registers it into the global [`crate::backlight_device`] registry
//! as `"acpi_video0"` (incrementing the index for multiple panels).
//!
//! ACPI Notify codes 0x86 (brightness up) and 0x87 (brightness down)
//! are delivered to the brightness-key handler in
//! [`crate::brightness_keys`]; that module queries this registry to
//! find the correct `AcpiVideoDevice` and calls `step_up` / `step_down`.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/acpi/acpi_video.c` — `acpi_video_init_brightness`,
//!   `acpi_video_device_brightness_set`, `acpi_video_device_brightness_get`.
//! - `drivers/acpi/video_detect.c` — `acpi_backlight_udev` probe order.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicI32, Ordering};

use narf_aml::eval::evaluate_method;
use narf_aml::{for_each_device, Value};

use crate::{BacklightDevice, BacklightKind};

// ── AcpiVideoDevice ────────────────────────────────────────────────

/// One ACPI video output device that exposes a brightness ladder.
///
/// Naming follows Linux: first device = `acpi_video0`, second =
/// `acpi_video1`, etc. The device is `Debug + Send + Sync` because
/// it lives behind `Arc<dyn BacklightDevice>`.
#[derive(Debug)]
pub struct AcpiVideoDevice {
    /// Backlight device name (`acpi_video0`, …).
    pub name: String,
    /// AML path of the video output device (e.g. `\_SB.PCI0.GFX0.DD1F`).
    pub acpi_path: String,
    /// Sorted, deduped brightness ladder (0..=max).
    ///
    /// From `_BCL` per ACPI 6.5 §B.6.2: first two entries (AC and
    /// battery defaults) are stripped; remainder is sorted ascending.
    pub levels: Vec<u32>,
    /// Last written brightness (snapped). `-1` = never written.
    last: AtomicI32,
}

impl AcpiVideoDevice {
    /// Find the closest level on the ladder to `requested`.
    /// Ties break toward brighter. Returns the first ladder entry
    /// on an empty ladder.
    fn snap(&self, requested: u32) -> u32 {
        if self.levels.is_empty() {
            return 0;
        }
        let mut best = self.levels[0];
        let mut best_dist = (best as i64 - requested as i64).abs();
        for &l in &self.levels[1..] {
            let d = (l as i64 - requested as i64).abs();
            if d <= best_dist {
                best = l;
                best_dist = d;
            }
        }
        best
    }

    /// Step down one level on the brightness ladder. Returns the new
    /// level, or the minimum if already at the bottom.
    ///
    /// Called by the brightness-key handler on ACPI Notify(0x87).
    pub fn step_down(&self) -> u32 {
        if self.levels.is_empty() {
            return 0;
        }
        let cur = self.current_brightness();
        // Find index of current level (or nearest), go one lower.
        let idx = self.levels.iter().position(|&l| l >= cur).unwrap_or(0);
        let new_level = if idx == 0 {
            self.levels[0]
        } else {
            self.levels[idx - 1]
        };
        self.set_brightness(new_level);
        new_level
    }

    /// Step up one level on the brightness ladder. Returns the new
    /// level, or the maximum if already at the top.
    ///
    /// Called by the brightness-key handler on ACPI Notify(0x86).
    pub fn step_up(&self) -> u32 {
        if self.levels.is_empty() {
            return 0;
        }
        let cur = self.current_brightness();
        let last_idx = self.levels.len() - 1;
        // Find position just above current.
        let idx = self
            .levels
            .iter()
            .rposition(|&l| l <= cur)
            .unwrap_or(0);
        let new_level = if idx >= last_idx {
            self.levels[last_idx]
        } else {
            self.levels[idx + 1]
        };
        self.set_brightness(new_level);
        new_level
    }

    /// Parse an AML Device node at `path` that has a `_BCL` child.
    /// Returns `None` if `_BCL` is absent, returns no ladder entries,
    /// or the AML evaluation fails.
    ///
    /// Reference: Linux `acpi_video_init_brightness` — strips first two
    /// entries and sorts.
    fn from_path(path: &str, index: usize) -> Option<Arc<Self>> {
        let bcl_path = format!("{}._BCL", path);
        let val = evaluate_method(&bcl_path, &[]).ok()?;
        let pkg = match val {
            Value::Package(p) => p,
            _ => return None,
        };
        // Drop AC + battery defaults (first 2 entries per ACPI spec §B.6.2).
        if pkg.len() < 3 {
            return None;
        }
        let mut levels: Vec<u32> = pkg[2..]
            .iter()
            .map(|v| v.as_integer() as u32)
            .collect();
        if levels.is_empty() {
            return None;
        }
        levels.sort_unstable();
        levels.dedup();

        Some(Arc::new(Self {
            name: format!("acpi_video{}", index),
            acpi_path: String::from(path),
            levels,
            last: AtomicI32::new(-1),
        }))
    }
}

impl BacklightDevice for AcpiVideoDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        *self.levels.last().unwrap_or(&0)
    }

    fn current_brightness(&self) -> u32 {
        let cached = self.last.load(Ordering::Acquire);
        if cached >= 0 {
            return cached as u32;
        }
        // Query live via _BQC.
        let path = format!("{}._BQC", self.acpi_path);
        match evaluate_method(&path, &[]) {
            Ok(v) => {
                let level = v.as_integer() as u32;
                self.last.store(level as i32, Ordering::Release);
                level
            }
            Err(_) => 0,
        }
    }

    fn set_brightness(&self, level: u32) {
        let snapped = self.snap(level);
        let path = format!("{}._BCM", self.acpi_path);
        let _ = evaluate_method(&path, &[Value::Integer(snapped as u64)]);
        self.last.store(snapped as i32, Ordering::Release);
    }

    fn kind(&self) -> BacklightKind {
        BacklightKind::Firmware
    }
}

// ── ACPI_VIDEO_DEVICES registry ────────────────────────────────────

/// All discovered ACPI video backlight devices. The `brightness_keys`
/// module iterates this to find which panel to step on a hotkey.
static ACPI_VIDEO_DEVS: narf_lib::sync::IrqSafeSpinLock<Vec<Arc<AcpiVideoDevice>>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

/// Return all registered ACPI video backlight devices.
pub fn acpi_video_devices() -> Vec<Arc<AcpiVideoDevice>> {
    ACPI_VIDEO_DEVS.lock().clone()
}

// ── init ───────────────────────────────────────────────────────────

/// Walk the AML namespace and register every Device node that has a
/// `_BCL` child method. Called from the Stage::Device initcall in
/// [`crate::register_initcalls`].
///
/// Each discovered device is registered in both the global
/// [`crate::BACKLIGHT_DEVS`] registry and the module-local
/// `ACPI_VIDEO_DEVS` registry (so `brightness_keys` can reach it
/// directly without going through the trait object).
pub fn init() {
    let mut index = 0usize;
    for_each_device(|node| {
        if let Some(dev) = AcpiVideoDevice::from_path(&node.path, index) {
            let _ = writeln!(
                narf_console::Writer,
                "  acpi-video-backlight: {} ({} levels, max={})",
                dev.name,
                dev.levels.len(),
                dev.max_brightness()
            );
            ACPI_VIDEO_DEVS.lock().push(dev.clone());
            crate::register_backlight(dev as Arc<dyn BacklightDevice>);
            index += 1;
        }
    });
}

/// Test helper: drain the module-local registry.
#[doc(hidden)]
pub fn __reset_for_test() {
    ACPI_VIDEO_DEVS.lock().clear();
}

/// Test helper: install a synthetic device without going through AML.
#[doc(hidden)]
pub fn __test_install(name: &str, path: &str, levels: Vec<u32>) -> Arc<AcpiVideoDevice> {
    let dev = Arc::new(AcpiVideoDevice {
        name: alloc::string::String::from(name),
        acpi_path: alloc::string::String::from(path),
        levels,
        last: AtomicI32::new(-1),
    });
    ACPI_VIDEO_DEVS.lock().push(dev.clone());
    crate::register_backlight(dev.clone() as Arc<dyn BacklightDevice>);
    dev
}
