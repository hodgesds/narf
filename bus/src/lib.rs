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

mod tests;

pub mod acpi_notify;
pub mod addr;
pub mod bar;
pub mod cxl;
pub mod device;
pub mod driver_match;
pub mod dt_match;
pub mod ecam;
pub mod hotplug;
pub mod msi;
pub mod msix;
pub mod pci;
pub mod pci_cap;
pub mod pci_cap_ext;
pub mod pci_doe;
pub mod pci_express;
pub mod pci_ide;
pub mod pcie;
pub mod pcie_aer;
pub mod pcie_dpc;
pub mod pcie_recovery;
pub mod registry;
pub mod vmd_domain;
pub mod vmd_irq;

pub use acpi_notify::{AcpiNotify, NotifyEvent, NotifyKind};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub use addr::{BusAddr, PcieAddr};
pub use bar::{
    allocate_pci_mmio, assign_unprogrammed_bars, init_mmio_pool, map_bar, map_bar_control,
    read_bar, AssignError, Bar, BarError, BarKind, MmioRegion, NUM_BARS,
};
pub use device::{BusDevice, BusKind, DeviceId};
pub use driver_match::{
    bound_count as bound_pci_devices, detach as detach_pci_device, module_bar_map, module_dma_addr,
    module_dma_alloc, module_dma_free, module_dma_read, module_dma_wait8, module_dma_write,
    module_irq_set_handler, module_mmio_read32, module_mmio_wait32, module_mmio_write32,
    module_msix_claim, module_msix_enable, module_netif_register, module_netif_rx,
    module_pci_enable, module_spawn_poller, probe_all as probe_all_pci,
    register as register_pci_driver, register_module_pci_driver,
    register_remove as register_pci_remove, registered as registered_pci_drivers,
    set_module_callback_call_gate, set_module_probe_call_gate, set_module_tx_call_gate,
    set_probe_log, set_probe_log_hook, unregister_module_pci_drivers, MatchKind,
    ModuleCallbackCallGate, ModuleCallbackFn, ModuleProbeCallGate, ModuleProbeFn, ModuleTxCallGate,
    ModuleTxFn, PciMatch, PciProbeFn, PciRemoveFn, ProbeError,
};
pub use dt_match::{
    bound as bound_dt_nodes, probe_all as probe_all_dt, probe_blob as probe_dt_blob,
    register as register_dt_driver, registered as registered_dt_drivers,
    unregister as unregister_dt_driver, DtMatch, DtProbeFn,
};
pub use hotplug::{dispatch_event, register_listener, HotplugError, HotplugEvent, HotplugListener};
pub use msix::{enable_msix, MsixError, MsixTable, MsixVector};
pub use registry::{
    append_devices, boot_dtb, bootstrap_registry_authority, claim_device, claim_device_cap,
    devices, init, snapshot, BusDeviceCap, BusDeviceHandle, BusRegistryCap, ClaimError,
};
pub use vmd_domain::{
    allocate_domain_mmio as allocate_vmd_mmio, domain_for_device as vmd_domain_for_device,
    domain_info as vmd_domain_info, membar_window_of, register_domain as register_vmd_domain,
    unregister_domain as unregister_vmd_domain, MembarWindow, VmdDomainError, VmdDomainInfo,
};
pub use vmd_irq::{
    assign_child_vector as vmd_assign_child_vector, bridge_vector as vmd_bridge_vector,
    entry_for_child as vmd_entry_for_child, register_bridge_domain as register_vmd_irq_domain,
    release_device as vmd_release_device, remap_entry_words as vmd_remap_entry_words,
    remap_message as vmd_remap_message, unregister_bridge_domain as unregister_vmd_irq_domain,
    VmdIrqError,
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
