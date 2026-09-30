//! Intel DTT — Dynamic Tuning Technology processor thermal device.
//!
//! ## Reference
//!
//! Linux v7.3-rc4
//! `drivers/thermal/intel/int340x_thermal/` (GPL-2.0; NARF is
//! GPL-2.0-or-later so adaptation is permitted):
//!
//! - `processor_thermal_device.h`     — PCI device IDs, feature bits.
//! - `processor_thermal_device_pci.c` — the `proc_thermal_mmio_info`
//!   table (register / shift / mask per field), `sys_get_curr_temp`,
//!   `sys_set_trip_temp`, and the PCI id table with per-SKU features.
//! - `processor_thermal_rapl.c`       — the MMIO RAPL register map.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** exposes the DTT device at PCI `00:04.0`
//! (`8086:b01d`, "Panther Lake"), which Linux binds with
//! `proc_thermal_pci`.
//!
//! ## What the device is
//!
//! DTT is the package's thermal and power-limit control surface,
//! presented as a PCI function rather than an MSR. BAR0 is a large
//! MMIO window; the fields this driver reads are scattered through it
//! and each is a `(register, shift, mask)` triple rather than a whole
//! register — `PROC_THERMAL_MMIO_TJMAX`, for instance, is bits 23:16
//! of the dword at 0x599c. [`MmioField`] encodes that shape directly
//! so a transcription slip shows up as a wrong constant rather than
//! as a plausible-looking temperature.
//!
//! Package temperature is reported as an **offset below TjMax**, not
//! as degrees: `T = TjMax - PKG_TEMP`. Reading `PKG_TEMP` as an
//! absolute value would give a number that looks sane and is wrong by
//! ~100 °C, so [`ProcThermal::package_temp_c`] does the subtraction.
//!
//! ## Scope
//!
//! Read-only telemetry: TjMax, package / PP0 / PP1 temperature, and
//! the RAPL power-limit registers. Writing trip points, the DLVR /
//! FIVR RF-interference-mitigation mailboxes, workload hints and the
//! MSI plumbing Linux wires up are **not** implemented — those change
//! how the part clocks and throttles, and belong behind the `power/`
//! subsystem's policy rather than in a probe path.

extern crate alloc;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `processor_thermal_device.h`. Only the generations whose
// feature masks are listed in `proc_thermal_pci_ids[]` are claimed.

/// Intel.
pub const DTT_VENDOR: u16 = 0x8086;

/// Alder Lake — `PCI_DEVICE_ID_INTEL_ADL_THERMAL`.
pub const DTT_DEV_ADL: u16 = 0x461D;
/// Raptor Lake — `PCI_DEVICE_ID_INTEL_RPL_THERMAL`.
pub const DTT_DEV_RPL: u16 = 0xA71D;
/// Meteor Lake-P — `PCI_DEVICE_ID_INTEL_MTLP_THERMAL`.
pub const DTT_DEV_MTL_P: u16 = 0x7D03;
/// Arrow Lake-S — `PCI_DEVICE_ID_INTEL_ARL_S_THERMAL`.
pub const DTT_DEV_ARL_S: u16 = 0xAD03;
/// Lunar Lake-M — `PCI_DEVICE_ID_INTEL_LNLM_THERMAL`.
pub const DTT_DEV_LNL_M: u16 = 0x641D;
/// Panther Lake — `PCI_DEVICE_ID_INTEL_PTL_THERMAL`. The MS-03's
/// `00:04.0`.
pub const DTT_DEV_PTL: u16 = 0xB01D;
/// Wildcat Lake — `PCI_DEVICE_ID_INTEL_WCL_THERMAL`.
pub const DTT_DEV_WCL: u16 = 0xFD1D;
/// Nova Lake-H — `PCI_DEVICE_ID_INTEL_NVL_H_THERMAL`.
pub const DTT_DEV_NVL_H: u16 = 0xD703;

/// Every device ID this driver claims, in one `const` so
/// `register_pci_driver` and the match-table smoke cannot drift.
///
/// `PCI_DEVICE_ID_INTEL_NVL_S_THERMAL` is deliberately absent: Linux
/// defines it as the same `0xAD03` as Arrow Lake-S, so listing both
/// would register two match entries for one device.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    DTT_DEV_ADL,
    DTT_DEV_RPL,
    DTT_DEV_MTL_P,
    DTT_DEV_ARL_S,
    DTT_DEV_LNL_M,
    DTT_DEV_PTL,
    DTT_DEV_WCL,
    DTT_DEV_NVL_H,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

// ── Feature mask ────────────────────────────────────────────────────
//
// `PROC_THERMAL_FEATURE_*` in `processor_thermal_device.h`. The mask
// is per-SKU driver data in Linux's PCI table; here it is looked up
// from the device id.

/// MMIO RAPL power limits are present.
pub const FEATURE_RAPL: u32 = 0x001;
/// FIVR (fully-integrated voltage regulator) RFIM mailbox.
pub const FEATURE_FIVR: u32 = 0x002;
/// DVFS RFIM mailbox.
pub const FEATURE_DVFS: u32 = 0x004;
/// Workload-type request mailbox.
pub const FEATURE_WT_REQ: u32 = 0x008;
/// DLVR (digital linear voltage regulator) RFIM mailbox.
pub const FEATURE_DLVR: u32 = 0x010;
/// Workload-type hint interface.
pub const FEATURE_WT_HINT: u32 = 0x020;
/// Power-floor notification.
pub const FEATURE_POWER_FLOOR: u32 = 0x040;
/// Device delivers thermal events by MSI rather than polling.
pub const FEATURE_MSI_SUPPORT: u32 = 0x080;
/// Platform temperature control.
pub const FEATURE_PTC: u32 = 0x100;
/// SoC power slider.
pub const FEATURE_SOC_POWER_SLIDER: u32 = 0x200;

/// Feature mask for `did`, matching Linux's `proc_thermal_pci_ids[]`
/// driver data. Returns 0 for an id this driver does not claim.
pub const fn features_for(did: u16) -> u32 {
    match did {
        DTT_DEV_ADL | DTT_DEV_RPL => FEATURE_RAPL | FEATURE_FIVR | FEATURE_DVFS | FEATURE_WT_REQ,
        DTT_DEV_MTL_P => {
            FEATURE_RAPL
                | FEATURE_FIVR
                | FEATURE_DVFS
                | FEATURE_DLVR
                | FEATURE_WT_HINT
                | FEATURE_POWER_FLOOR
        }
        DTT_DEV_ARL_S => FEATURE_RAPL | FEATURE_DVFS | FEATURE_DLVR | FEATURE_WT_HINT,
        DTT_DEV_LNL_M => {
            FEATURE_MSI_SUPPORT
                | FEATURE_RAPL
                | FEATURE_DLVR
                | FEATURE_DVFS
                | FEATURE_WT_HINT
                | FEATURE_POWER_FLOOR
                | FEATURE_PTC
        }
        DTT_DEV_PTL | DTT_DEV_NVL_H => {
            FEATURE_RAPL
                | FEATURE_DLVR
                | FEATURE_DVFS
                | FEATURE_MSI_SUPPORT
                | FEATURE_WT_HINT
                | FEATURE_POWER_FLOOR
                | FEATURE_PTC
                | FEATURE_SOC_POWER_SLIDER
        }
        DTT_DEV_WCL => {
            FEATURE_MSI_SUPPORT
                | FEATURE_RAPL
                | FEATURE_DLVR
                | FEATURE_DVFS
                | FEATURE_WT_HINT
                | FEATURE_POWER_FLOOR
                | FEATURE_PTC
                | FEATURE_SOC_POWER_SLIDER
        }
        _ => 0,
    }
}

// ── MMIO fields ─────────────────────────────────────────────────────

/// BAR carrying the thermal register window.
pub const DTT_BAR: u8 = 0;

/// One `(register, shift, mask)` triple out of Linux's
/// `proc_thermal_mmio_info[]`. Several fields share a register —
/// `THRES_0`, `THRES_1`, `INT_ENABLE_0` and `INT_ENABLE_1` are all
/// different bit ranges of the dword at 0x5820 — so the register
/// offset alone is not enough to name a field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MmioField {
    /// Byte offset of the containing dword within BAR0.
    pub reg: u64,
    /// Right-shift applied after the read.
    pub shift: u32,
    /// Mask applied after the shift.
    pub mask: u32,
}

impl MmioField {
    /// Extract this field from a dword already read from `reg`.
    pub const fn extract(self, dword: u32) -> u32 {
        (dword >> self.shift) & self.mask
    }
}

/// TjMax, the junction temperature the package throttles at, in °C.
pub const FIELD_TJMAX: MmioField = MmioField {
    reg: 0x599C,
    shift: 16,
    mask: 0xFF,
};
/// Core (PP0) temperature, as an offset below TjMax.
pub const FIELD_PP0_TEMP: MmioField = MmioField {
    reg: 0x597C,
    shift: 0,
    mask: 0xFF,
};
/// Graphics (PP1) temperature, as an offset below TjMax.
pub const FIELD_PP1_TEMP: MmioField = MmioField {
    reg: 0x5980,
    shift: 0,
    mask: 0xFF,
};
/// Package temperature, as an offset below TjMax.
pub const FIELD_PKG_TEMP: MmioField = MmioField {
    reg: 0x5978,
    shift: 0,
    mask: 0xFF,
};
/// Thermal threshold 0, as an offset below TjMax.
pub const FIELD_THRES_0: MmioField = MmioField {
    reg: 0x5820,
    shift: 8,
    mask: 0x7F,
};
/// Thermal threshold 1.
pub const FIELD_THRES_1: MmioField = MmioField {
    reg: 0x5820,
    shift: 16,
    mask: 0x7F,
};
/// Threshold-0 interrupt enable.
pub const FIELD_INT_ENABLE_0: MmioField = MmioField {
    reg: 0x5820,
    shift: 15,
    mask: 0x01,
};
/// Threshold-1 interrupt enable.
pub const FIELD_INT_ENABLE_1: MmioField = MmioField {
    reg: 0x5820,
    shift: 23,
    mask: 0x01,
};
/// Threshold-0 interrupt status.
pub const FIELD_INT_STATUS_0: MmioField = MmioField {
    reg: 0x7200,
    shift: 6,
    mask: 0x01,
};
/// Threshold-1 interrupt status.
pub const FIELD_INT_STATUS_1: MmioField = MmioField {
    reg: 0x7200,
    shift: 8,
    mask: 0x01,
};

// ── MMIO RAPL registers ─────────────────────────────────────────────
//
// `rapl_mmio_default` in `processor_thermal_rapl.c`.

/// `reg_unit` — the power / energy / time unit register. Its fields
/// say how to scale every other RAPL value.
pub const RAPL_REG_UNIT: u64 = 0x5938;
/// Package power limit (PL1 / PL2).
pub const RAPL_PKG_POWER_LIMIT: u64 = 0x59A0;
/// Package energy status (a free-running counter).
pub const RAPL_PKG_ENERGY_STATUS: u64 = 0x593C;
/// Package perf status.
pub const RAPL_PKG_PERF_STATUS: u64 = 0x58F0;
/// Package power info (TDP, min / max power).
pub const RAPL_PKG_POWER_INFO: u64 = 0x5930;
/// Package policy.
pub const RAPL_PKG_POLICY: u64 = 0x59B0;
/// DRAM power limit.
pub const RAPL_DRAM_POWER_LIMIT: u64 = 0x58E0;
/// DRAM energy status.
pub const RAPL_DRAM_ENERGY_STATUS: u64 = 0x58E8;
/// DRAM perf status.
pub const RAPL_DRAM_PERF_STATUS: u64 = 0x58EC;

/// Highest byte offset this driver reads. The BAR must cover it or
/// the device is not a DTT function.
const HIGHEST_OFFSET: u64 = 0x7200;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DttError {
    BarMapFailed,
    /// BAR0 does not cover the thermal register window.
    BarTooSmall,
    /// Registers read back all-ones — the device is not responding.
    DeviceGone,
    /// TjMax read back as 0, which no real part reports. Treating it
    /// as valid would make every temperature come out negative.
    BadTjMax,
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed DTT processor-thermal function.
pub struct ProcThermal {
    mmio: MmioRegion,
    /// PCI device id.
    pub device_id: u16,
    /// `PROC_THERMAL_FEATURE_*` mask for this SKU.
    pub features: u32,
    /// TjMax in °C, latched at probe. Does not change at runtime.
    pub tjmax_c: u32,
}

// SAFETY: `ProcThermal` has no interior mutability; `mmio` describes
// an identity-mapped MMIO window this driver owns exclusively and
// every other field is plain data written once at bring-up.
unsafe impl Send for ProcThermal {}
// SAFETY: every accessor is a read of an independent MMIO register,
// so concurrent `&ProcThermal` use from several CPUs is sound.
unsafe impl Sync for ProcThermal {}

impl core::fmt::Debug for ProcThermal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcThermal")
            .field("device_id", &self.device_id)
            .field("features", &self.features)
            .field("tjmax_c", &self.tjmax_c)
            .finish_non_exhaustive()
    }
}

impl ProcThermal {
    /// Map BAR0 and latch TjMax.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, DttError> {
        // SAFETY: forwarded — caller owns BAR0.
        let mmio = unsafe { map_bar(device, DTT_BAR) }.map_err(|_| DttError::BarMapFailed)?;
        if mmio.len < HIGHEST_OFFSET + 4 {
            return Err(DttError::BarTooSmall);
        }

        // SAFETY: `mmio` is the mapped window and `FIELD_TJMAX.reg` is
        // in range per the check above.
        let raw = unsafe { mmio.read32(FIELD_TJMAX.reg) };
        if raw == 0xFFFF_FFFF {
            return Err(DttError::DeviceGone);
        }
        let tjmax_c = FIELD_TJMAX.extract(raw);
        if tjmax_c == 0 {
            return Err(DttError::BadTjMax);
        }

        Ok(Self {
            mmio,
            device_id: device.id.device,
            features: features_for(device.id.device),
            tjmax_c,
        })
    }

    /// Read one [`MmioField`].
    pub fn read_field(&self, f: MmioField) -> u32 {
        // SAFETY: `self.mmio` is the mapped window; every `MmioField`
        // in this module has an offset below `HIGHEST_OFFSET`, which
        // `bring_up` verified the BAR covers.
        let raw = unsafe { self.mmio.read32(f.reg) };
        f.extract(raw)
    }

    /// Read one raw 32-bit register. `offset` must be inside the BAR.
    pub fn read_reg(&self, offset: u64) -> Option<u32> {
        if offset + 4 > self.mmio.len {
            return None;
        }
        // SAFETY: bounds-checked against the mapped BAR length.
        Some(unsafe { self.mmio.read32(offset) })
    }

    /// Package temperature in °C.
    ///
    /// The register reports an offset *below* TjMax, so this is
    /// `TjMax - PKG_TEMP`. A reading at or above TjMax saturates at
    /// TjMax rather than wrapping.
    pub fn package_temp_c(&self) -> u32 {
        self.tjmax_c.saturating_sub(self.read_field(FIELD_PKG_TEMP))
    }

    /// Core (PP0) temperature in °C.
    pub fn core_temp_c(&self) -> u32 {
        self.tjmax_c.saturating_sub(self.read_field(FIELD_PP0_TEMP))
    }

    /// Graphics (PP1) temperature in °C.
    pub fn graphics_temp_c(&self) -> u32 {
        self.tjmax_c.saturating_sub(self.read_field(FIELD_PP1_TEMP))
    }

    /// `true` if this SKU advertises `feature`.
    pub const fn has_feature(&self, feature: u32) -> bool {
        self.features & feature == feature
    }

    /// Package RAPL power-limit register, when the SKU has MMIO RAPL.
    pub fn rapl_package_power_limit(&self) -> Option<u32> {
        if !self.has_feature(FEATURE_RAPL) {
            return None;
        }
        self.read_reg(RAPL_PKG_POWER_LIMIT)
    }

    /// Package RAPL energy counter, when the SKU has MMIO RAPL.
    pub fn rapl_package_energy(&self) -> Option<u32> {
        if !self.has_feature(FEATURE_RAPL) {
            return None;
        }
        self.read_reg(RAPL_PKG_ENERGY_STATUS)
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<alloc::sync::Arc<ProcThermal>>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != DTT_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let dev = match unsafe { ProcThermal::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  proc_thermal: bring-up failed on {:04x}: {:?}",
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  proc_thermal: DTT {:04x} TjMax={}C pkg={}C features={:#05x}",
            dev.device_id,
            dev.tjmax_c,
            dev.package_temp_c(),
            dev.features,
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("proc_thermal"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    *CONTROLLER.lock() = Some(alloc::sync::Arc::new(dev));
    Ok(())
}

/// Register the DTT PCI driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "proc_thermal",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: DTT_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once a DTT function has been brought up.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed DTT function, if any.
pub fn with_device<R>(f: impl FnOnce(&ProcThermal) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: forget the probed device so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
