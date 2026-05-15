//! ACPI AC Adapter driver — clean-room.
//!
//! Spec: ACPI 6.5 §10.3 AC Adapters and Power Source Objects.
//!   <https://uefi.org/specs/ACPI/>
//!
//! Walks the AML namespace for `ACPI0003` (AC Adapter) devices
//! and registers one `AcAdapter` per device. `_PSR` returns
//! `Integer(0)` (off-line / running on battery) or `Integer(1)`
//! (on-line / mains attached); we re-evaluate the method per
//! `is_charging()` query so the answer reflects the live state
//! when the user yanks the cable.

use alloc::string::String;
use alloc::sync::Arc;

use narf_aml::eval::evaluate_method;
use narf_aml::find_all_devices_by_hid;
use narf_power::{register_source, PowerSource, PowerSourceType};

#[derive(Debug)]
pub struct AcAdapter {
    /// Fully-qualified namespace path of the adapter device, e.g.
    /// `"\\_SB.AC"`. `_PSR` is evaluated against `<path>._PSR`.
    path: String,
    name: &'static str,
}

impl AcAdapter {
    fn new(path: String, name: &'static str) -> Self {
        Self { path, name }
    }

    fn read_psr(&self) -> Option<u64> {
        let mut method = self.path.clone();
        method.push_str("._PSR");
        let v = evaluate_method(&method, &[]).ok()?;
        Some(v.as_integer())
    }
}

impl PowerSource for AcAdapter {
    fn source_type(&self) -> PowerSourceType {
        PowerSourceType::AcAdaptor
    }

    /// AC adapter has no capacity; the value is meaningful only
    /// for batteries. Reports 100 when on-line, 0 when off-line —
    /// matches the convention `power::list_sources` consumers
    /// already use for "is the wall power present?".
    fn capacity_percent(&self) -> u8 {
        match self.read_psr() {
            Some(1) => 100,
            _ => 0,
        }
    }

    /// True iff the adapter reports on-line (mains attached).
    /// Naming is "is_charging" because that's the trait shape;
    /// for an AC adapter "online" is the equivalent state and is
    /// what `power-monitor` should display as `(charging)` when
    /// reporting any battery.
    fn is_charging(&self) -> bool {
        matches!(self.read_psr(), Some(1))
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Stage::Subsys init. No-op when no `ACPI0003` device is present
/// (desktop / virtual host without AC adapter telemetry).
pub fn init() {
    const NAMES: &[&str] = &["AC0", "AC1", "AC2", "AC3"];
    let devices = find_all_devices_by_hid("ACPI0003");
    for (i, dev) in devices.iter().enumerate() {
        let name: &'static str = NAMES.get(i).copied().unwrap_or("ACX");
        let ac = Arc::new(AcAdapter::new(dev.path.clone(), name));
        register_source(ac);
    }
}
