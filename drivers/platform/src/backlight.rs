//! ACPI Display Backlight driver — clean-room.
//!
//! Spec: ACPI 6.5 §B.6 (Output Device-specific methods, video extensions).
//!
//! Three methods on each video-output device:
//! - `_BCL` — *Brightness Control Levels*. Returns a `Package` of
//!   integers. Element 0 is the "level on AC", element 1 the "level
//!   on battery", and the remainder is the supported-level ladder
//!   (typically 8–10 entries from 0..=100).
//! - `_BCM(level)` — set brightness to `level` (must be one of the
//!   ladder values returned by `_BCL`).
//! - `_BQC` — query the current brightness.
//!
//! `_BCL` is attached to a video output (LCD panel) as a child of an
//! ACPI graphics-adapter device. We discover backlight devices by
//! walking every Device node and probing for `_BCL` rather than
//! filtering on `_HID`, since the parent adapter's HID varies by
//! firmware (PNP0A08 / PNP0A03 / vendor-specific) but a `_BCL`-bearing
//! child is unambiguous.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicI32, Ordering};

use narf_aml::eval::evaluate_method;
use narf_aml::{for_each_device, Value};
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for the backlight surface. `Cap<Backlight, Grant>`
/// authorises every brightness change.
#[derive(Copy, Clone, Debug)]
pub struct Backlight;

impl CapType for Backlight {
    const KIND: CapKind = CapKind::Power;
}

/// Errors from the backlight surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacklightError {
    AuthorityRevoked,
    UnknownDevice,
    UnsupportedLevel,
    AmlFailure,
}

impl From<CapError> for BacklightError {
    fn from(_: CapError) -> Self {
        BacklightError::AuthorityRevoked
    }
}

/// One discovered backlight panel.
#[derive(Debug)]
pub struct BacklightPanel {
    pub path: String,
    /// Sorted-ascending ladder of supported levels (typically 0..=100
    /// in 10-step increments). The first two `_BCL` package
    /// entries (AC default, battery default) are stripped.
    pub levels: Vec<i32>,
    /// Last level we wrote. -1 means "never written" — call `query`
    /// to populate from `_BQC`.
    last: AtomicI32,
}

impl BacklightPanel {
    fn parse(path: &str) -> Option<Arc<Self>> {
        let bcl_path = format!("{}._BCL", path);
        let result = evaluate_method(&bcl_path, &[]).ok()?;
        let pkg = match result {
            Value::Package(p) => p,
            _ => return None,
        };
        // §B.6.2: package element 0 = "level for full power" (AC),
        // element 1 = "level for battery", element 2..N = supported
        // levels. Drop the two prefix entries; require at least one
        // ladder entry to be a usable backlight.
        if pkg.len() < 3 {
            return None;
        }
        let mut levels: Vec<i32> = pkg
            .iter()
            .skip(2)
            .map(|v| v.as_integer() as i32)
            .filter(|n| *n >= 0)
            .collect();
        if levels.is_empty() {
            return None;
        }
        levels.sort_unstable();
        levels.dedup();
        Some(Arc::new(Self {
            path: String::from(path),
            levels,
            last: AtomicI32::new(-1),
        }))
    }

    /// Maximum level on this panel. For laptops this is almost always
    /// 100, but some firmwares (notably Lenovo Yoga) ship 0..=10 or
    /// 0..=255 ladders.
    pub fn max(&self) -> i32 {
        *self.levels.last().unwrap_or(&0)
    }

    /// Snap `requested` to the nearest level on the ladder. Falls back
    /// to the closest neighbour when the request lies between two.
    /// Public so tests can exercise the snap algorithm without
    /// touching AML.
    #[doc(hidden)]
    pub fn snap(&self, requested: i32) -> i32 {
        let mut best = self.levels[0];
        let mut best_dist = (best - requested).abs();
        for l in &self.levels[1..] {
            let d = (l - requested).abs();
            if d < best_dist {
                best = *l;
                best_dist = d;
            }
        }
        best
    }

    /// Set the panel to a specific (snapped) level. Returns the level
    /// that was actually written.
    pub fn set_level(&self, requested: i32) -> Result<i32, BacklightError> {
        let level = self.snap(requested);
        let path = format!("{}._BCM", self.path);
        if evaluate_method(&path, &[Value::Integer(level as u64)]).is_err() {
            return Err(BacklightError::AmlFailure);
        }
        self.last.store(level, Ordering::Release);
        Ok(level)
    }

    /// Read the current level via `_BQC`.
    pub fn query(&self) -> Result<i32, BacklightError> {
        let path = format!("{}._BQC", self.path);
        match evaluate_method(&path, &[]) {
            Ok(v) => {
                let level = v.as_integer() as i32;
                self.last.store(level, Ordering::Release);
                Ok(level)
            }
            Err(_) => Err(BacklightError::AmlFailure),
        }
    }

    /// Last written / queried level. -1 if neither has run.
    pub fn last(&self) -> i32 {
        self.last.load(Ordering::Acquire)
    }
}

static PANELS: IrqSafeSpinLock<Vec<Arc<BacklightPanel>>> = IrqSafeSpinLock::new(Vec::new());

/// All discovered backlight panels.
pub fn panels() -> Vec<Arc<BacklightPanel>> {
    PANELS.lock().clone()
}

/// Convenience: set brightness on every panel as a 0..=100 percentage.
/// Useful for the platform-wide "user pressed Fn+F5" hotkey path.
pub fn set_percent(cap: &Cap<Backlight, Grant>, pct: u8) -> Result<(), BacklightError> {
    cap.invoke(NoopOp)?;
    let pct = pct.min(100) as i32;
    let panels = PANELS.lock().clone();
    for p in panels {
        let target = (p.max() * pct) / 100;
        let _ = p.set_level(target)?;
    }
    Ok(())
}

/// TCB-only entry path. Mints a fresh `Cap<Backlight, Grant>` for the
/// init code that owns brightness policy.
pub fn bootstrap_backlight_authority() -> Cap<Backlight, Grant> {
    Cap::<Backlight, Grant>::bootstrap()
}

/// Walk every Device node and register any that exposes a `_BCL`
/// method as a backlight panel.
pub fn init() {
    let mut found = 0u32;
    for_each_device(|node| {
        if let Some(panel) = BacklightPanel::parse(&node.path) {
            let _ = writeln!(
                narf_console::Writer,
                "  acpi-backlight: registered {} ({} levels, max={})",
                panel.path,
                panel.levels.len(),
                panel.max()
            );
            PANELS.lock().push(panel);
            found += 1;
        }
    });
    if found == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-backlight: no panels with _BCL discovered"
        );
    }
}

/// Test helper: drain registry.
#[doc(hidden)]
pub fn __test_reset() {
    PANELS.lock().clear();
}

/// Test-only: install a synthetic panel without going through AML.
/// Used by the smoke tests so we can exercise the snap / level-set
/// logic without a live `_BCL` table.
#[doc(hidden)]
pub fn __test_install_panel(path: &str, levels: Vec<i32>) -> Arc<BacklightPanel> {
    let panel = Arc::new(BacklightPanel {
        path: String::from(path),
        levels,
        last: AtomicI32::new(-1),
    });
    PANELS.lock().push(panel.clone());
    panel
}
