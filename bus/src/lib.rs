//! narf-bus — boot-time device enumeration.
//!
//! Spec: `bus/specification/spec.md` §3.1, §3.2, §5. Stage 2 baseline
//! per STAGE3.md side track B: PCIe ECAM walk on x86_64 + devicetree
//! virtio-mmio walk on aarch64, both feeding a unified read-only
//! `BusDevice` registry keyed by `BusAddr`. Hot-plug, MSI-X, IOMMU
//! grouping, and the `Cap<BusRegistry, Claim>` → `Cap<BusDevice, _>`
//! flow are Stage-3-proper / Wave-2 work and live behind a placeholder
//! here (see `claim_device`).
//!
//! Non-goals (deferred, flagged to the coordinator):
//! - `Cap<_>`-typed claim API — blocked on Wave 2 cap table.
//! - MSI-X vector allocation — blocked on `interrupts/` Stage 3.
//! - Hot-plug event stream — Stage 3 proper.
//! - ACS / IOMMU-group coordination — Stage 3 proper.
//! - ACPI MCFG parsing — Stage 1/2 does not expose MCFG via BootInfo;
//!   we fall back to the QEMU `q35` ECAM default (`0xb000_0000`, 256
//!   buses × 4 KiB / function). Real MCFG parsing lands with boot/
//!   ACPI work.
//! - Full FDT property walk on aarch64 — we scan the flattened-devicetree
//!   structure for the minimum set of nodes (`virtio_mmio@...`) needed to
//!   produce the registry; a generic property getter is out of scope.
//!
//! The registry is populated once by `init` and is read-only thereafter.
//! Wave 2 will swap the backing store for an RCU-protected list so
//! hot-plug can append without blocking `devices()`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod acpi_notify;
pub mod addr;
pub mod bar;
pub mod device;
pub mod driver_match;
pub mod hotplug;
pub mod msix;
pub mod pci;
pub mod pcie;
pub mod registry;

pub use acpi_notify::{AcpiNotify, NotifyEvent, NotifyKind};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub use addr::{BusAddr, PcieAddr};
pub use bar::{map_bar, read_bar, Bar, BarError, BarKind, MmioRegion, NUM_BARS};
pub use driver_match::{
    probe_all as probe_all_pci, register as register_pci_driver,
    registered as registered_pci_drivers, MatchKind, PciMatch, PciProbeFn,
    ProbeError,
};
pub use device::{BusDevice, BusKind, DeviceId};
pub use hotplug::{
    dispatch_event, register_listener, HotplugError, HotplugEvent, HotplugListener,
};
pub use msix::{enable_msix, MsixError, MsixTable, MsixVector};
pub use registry::{
    bootstrap_registry_authority, claim_device, claim_device_cap, devices, init, snapshot,
    BusDeviceCap, BusDeviceHandle, BusRegistryCap, ClaimError,
};

/// IOMMU group id for a given device. Stage-3 stub: QEMU's default
/// virtio transport (MMIO on aarch64, PCIe without vIOMMU on x86_64)
/// puts every device in group 0. Real ACS-walked grouping — where the
/// bus crate walks every bridge in a PCIe path looking for Access
/// Control Services, and assigns one group per isolation domain — is
/// Stage-4 per `bus/` §5 x86_64 ACS check. The signature stays stable
/// across the rewire: callers that already treat the return value as
/// opaque don't need to change.
pub fn iommu_group_for(_dev: &BusDevice) -> u32 {
    // Stage-3 invariant: no vIOMMU on the default xtask QEMU line, so
    // every device lives in a single shared group. This mirrors the
    // `acs_clean: bool = false` placeholder documented in `bus/` §5.
    0
}
