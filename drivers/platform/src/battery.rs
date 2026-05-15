//! ACPI Control Method Battery driver — clean-room.
//!
//! Spec: ACPI 6.5 §10.2 Control Method Batteries.
//!   <https://uefi.org/specs/ACPI/>
//!
//! Walks the AML namespace for `PNP0C0A` (Control Method Battery)
//! devices and registers one `AcpiBattery` per device. Live state
//! (charge level, charging flag) is sourced from the AML
//! `_BST` method on each call; a one-shot `_BIF` evaluation at
//! init caches LastFullChargeCapacity so `capacity_percent()` can
//! produce a ratio without re-evaluating _BIF every poll.
//!
//! `_BST` returns `Package(4)` of integers (ACPI 6.5 §10.2.2.6):
//!     0  Battery State           bit0=discharging, bit1=charging,
//!                                 bit2=critical
//!     1  Present Rate            mA or mW
//!     2  Remaining Capacity      mAh or mWh
//!     3  Present Voltage         mV
//!
//! `_BIF` returns `Package(13)` (ACPI 6.5 §10.2.2.1) — fields 0..2
//! are PowerUnit / DesignCapacity / LastFullChargeCapacity, which
//! is all we need today.

use alloc::string::String;
use alloc::sync::Arc;

use narf_aml::eval::evaluate_method;
use narf_aml::{find_all_devices_by_hid, Value};
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::{register_source, PowerSource, PowerSourceType};

/// Per-battery state pulled at init time. The full-charge capacity
/// is the denominator for `capacity_percent`; we cache it in a
/// `IrqSafeSpinLock` rather than `AtomicU64` because a future
/// resample (post charge cycle) wants to refresh it without
/// reordering vs the path string.
#[derive(Debug)]
pub struct AcpiBattery {
    /// Fully-qualified namespace path of the battery device, e.g.
    /// `"\\_SB.PCI0.LPCB.EC0.BAT0"`. `_BST` / `_BIF` are evaluated
    /// against `<path>._BST` / `<path>._BIF`.
    path: String,
    /// `LastFullChargeCapacity` from `_BIF` field 2; the units (mAh
    /// vs mWh) are determined by `_BIF` field 0 (PowerUnit) but
    /// cancel in the percentage ratio so we don't need to keep them.
    /// `0` means "_BIF unavailable / 0 — fall back to design
    /// capacity-based heuristic" (which we don't have either, so
    /// we just report 100% if charging / 50% otherwise).
    full_capacity: IrqSafeSpinLock<u64>,
    /// Static name leaked once per battery so the `&'static str`
    /// PowerSource API is honoured. `BAT0`, `BAT1`, ... per device
    /// index — readable enough for the boot log without needing
    /// per-instance namespace inspection.
    name: &'static str,
}

impl AcpiBattery {
    fn new(path: String, name: &'static str) -> Self {
        Self {
            path,
            full_capacity: IrqSafeSpinLock::new(0),
            name,
        }
    }

    /// Evaluate `<path>._BST` and return the raw 4-tuple. `None` if
    /// the method is missing or returned the wrong shape.
    fn read_bst(&self) -> Option<[u64; 4]> {
        let mut method = self.path.clone();
        method.push_str("._BST");
        let v = evaluate_method(&method, &[]).ok()?;
        let pkg = match v {
            Value::Package(p) => p,
            _ => return None,
        };
        if pkg.len() < 4 {
            return None;
        }
        Some([
            pkg[0].as_integer(),
            pkg[1].as_integer(),
            pkg[2].as_integer(),
            pkg[3].as_integer(),
        ])
    }

    /// Evaluate `<path>._BIF` and return field 2 (LastFullCharge).
    fn read_full_capacity(&self) -> Option<u64> {
        let mut method = self.path.clone();
        method.push_str("._BIF");
        let v = evaluate_method(&method, &[]).ok()?;
        let pkg = match v {
            Value::Package(p) => p,
            _ => return None,
        };
        // _BIF field 2 = LastFullChargeCapacity. Some firmware
        // returns 0xFFFF_FFFF for "unknown" — treat as missing.
        if pkg.len() < 3 {
            return None;
        }
        let v = pkg[2].as_integer();
        if v == 0 || v == 0xFFFF_FFFF {
            None
        } else {
            Some(v)
        }
    }

    /// Refresh `full_capacity` from `_BIF`. Called at init; any
    /// caller can re-invoke after a known charge-cycle event.
    pub fn refresh_full_capacity(&self) {
        if let Some(fc) = self.read_full_capacity() {
            *self.full_capacity.lock() = fc;
        }
    }
}

impl PowerSource for AcpiBattery {
    fn source_type(&self) -> PowerSourceType {
        PowerSourceType::Battery
    }

    fn capacity_percent(&self) -> u8 {
        let bst = match self.read_bst() {
            Some(b) => b,
            None => return 0,
        };
        let remaining = bst[2];
        let full = *self.full_capacity.lock();
        if full == 0 {
            // No _BIF data; signal "present but unknown" with 100
            // when charging, 50 otherwise. Better than reporting
            // 0% on a healthy battery just because firmware hid
            // _BIF behind a region we don't decode.
            return if (bst[0] & 0x02) != 0 { 100 } else { 50 };
        }
        let pct = remaining.saturating_mul(100) / full;
        pct.min(100) as u8
    }

    fn is_charging(&self) -> bool {
        match self.read_bst() {
            Some(bst) => (bst[0] & 0x02) != 0, // bit 1 = charging
            None => false,
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Stage::Subsys init. Scans the AML namespace for PNP0C0A
/// (Control Method Battery) devices and registers a `PowerSource`
/// for each. No-op when no batteries are present (desktop /
/// virtual host without battery).
pub fn init() {
    // The static-name set lets us keep `PowerSource::name -> &'static
    // str` while still exposing one slot per detected battery. Most
    // laptops have one battery; bumping past 4 is unheard-of so the
    // small fixed table is fine.
    const NAMES: &[&str] = &["BAT0", "BAT1", "BAT2", "BAT3"];
    let devices = find_all_devices_by_hid("PNP0C0A");
    for (i, dev) in devices.iter().enumerate() {
        let name: &'static str = NAMES.get(i).copied().unwrap_or("BATX");
        let bat = Arc::new(AcpiBattery::new(dev.path.clone(), name));
        bat.refresh_full_capacity();
        register_source(bat);
    }
}
