//! Chelsio T4/T5/T6 (cxgb4) Network Driver — EXPLICITLY NOT IMPLEMENTED.
//!
//! Decision (issue #799, peripherals program #746): the Chelsio
//! Terminator 10/40GbE datapath is out of this program's desktop
//! scope — T4–T6 are server parts — so no datapath is implemented
//! and none is planned in this lane. This crate exists only so the
//! decision is recorded where a reader finds it and so a Chelsio
//! device is refused explicitly instead of silently looking like a
//! present-but-inert driver (the old code only logged a
//! registration line and matched no PCI device at all).
//!
//! What this crate does: [`register_pci_driver`] registers one
//! vendor-wide [`narf_bus::MatchKind::Vendor`] match for Chelsio
//! (`0x1425`); [`probe`] declines every match with
//! [`narf_bus::ProbeError::NotForThisDriver`], which returns the
//! device to the candidate list so another claimant can bind it
//! (bus spec §9.3). It never touches the hardware, never claims
//! the device, and never allocates.
//!
//! References: `linux/drivers/net/ethernet/chelsio/cxgb4/`

extern crate alloc;

use core::fmt::Write as _;
use narf_bus::{BusDevice, BusDeviceCap, ProbeError};
use narf_capabilities::{Cap, Write};
use narf_console::Writer;

/// Chelsio PCI vendor id (Linux `PCI_VENDOR_ID_CHELSIO`).
pub const CHELSIO_VENDOR: u16 = 0x1425;

/// Probe entry — installed via `register_pci_driver`.
///
/// Refusal-only: cxgb4 is explicitly not implemented (#799), so
/// every Chelsio device is declined with
/// [`ProbeError::NotForThisDriver`]. The dispatcher then offers
/// the device to the next candidate (bus spec §9.3); the device
/// stays unbound and available to other claimants. Never returns
/// any other error: any other variant would end the walk for this
/// device instead of falling through.
pub fn probe(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    let _ = writeln!(
        Writer,
        "  net: cxgb4: Chelsio [{:04x}:{:04x}] explicitly not implemented (#799), declining probe",
        device.id.vendor, device.id.device
    );
    Err(ProbeError::NotForThisDriver)
}

/// Register the cxgb4 PCI driver — a refusal-only match.
///
/// One vendor-wide match, not a per-device table: there is no
/// datapath to key off device ids, and a vendor match (lowest
/// specificity) lets any more-specific claimant win first while
/// still catching every Chelsio device for an explicit refusal.
pub fn register_pci_driver() {
    let _ = writeln!(
        Writer,
        "  net: cxgb4 explicitly not implemented (#799): Chelsio T4/T5/T6 datapath out of desktop scope; probe declines Chelsio devices"
    );
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "cxgb4",
        kind: narf_bus::MatchKind::Vendor {
            vendor: CHELSIO_VENDOR,
        },
        probe,
    });
}

mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::{register_pci_driver, CHELSIO_VENDOR};

    fn smoke_cxgb4_registers_vendor_refusal_match() -> TestResult {
        use narf_bus::driver_match::__reset_for_test;
        use narf_bus::{registered_pci_drivers, MatchKind};
        __reset_for_test();
        register_pci_driver();
        let registered = registered_pci_drivers();
        let matched = registered.iter().any(|m| {
            m.name == "cxgb4"
                && matches!(m.kind, MatchKind::Vendor { vendor } if vendor == CHELSIO_VENDOR)
        });
        if !matched {
            return TestResult::Fail("cxgb4 did not register a vendor match for Chelsio");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/cxgb4",
        smoke_cxgb4_registers_vendor_refusal_match
    );

    /// A synthetic Chelsio T4 device (device `0x4401`, the id the
    /// module build already registers). Network class; the config
    /// address is never dereferenced — both probes in the
    /// fall-through smoke are pure.
    fn fake_chelsio_device() -> narf_bus::BusDevice {
        use narf_bus::{BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
        let addr = PcieAddr::new(0, 0x7f, 0, 0);
        BusDevice {
            addr: BusAddr::Pcie(addr),
            id: DeviceId {
                vendor: CHELSIO_VENDOR,
                device: 0x4401,
                class: 0x020000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        }
    }

    /// Stand-in for a later claimant: binds anything it is offered
    /// and records that it was attempted.
    static FALLBACK_ATTEMPTED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    fn fallback_probe(
        _device: narf_bus::BusDevice,
        _cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<(), narf_bus::ProbeError> {
        FALLBACK_ATTEMPTED.store(true, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Restores the device registry on drop so the smoke leaves no
    /// synthetic device behind, even on an early `Fail` return.
    struct RegistryRestore(alloc::vec::Vec<narf_bus::BusDevice>);

    impl Drop for RegistryRestore {
        fn drop(&mut self) {
            narf_bus::registry::install(core::mem::take(&mut self.0));
        }
    }

    fn smoke_cxgb4_probe_refuses_and_falls_through() -> TestResult {
        use core::sync::atomic::Ordering;
        use narf_bus::driver_match::__reset_for_test;
        use narf_bus::{bootstrap_registry_authority, bound_pci_devices, probe_all_pci};

        let _restore = RegistryRestore(narf_bus::snapshot());
        __reset_for_test();
        register_pci_driver();
        narf_bus::registry::install(alloc::vec![fake_chelsio_device()]);
        let authority = bootstrap_registry_authority();

        // Phase A: only the refusal is registered — the Chelsio
        // device must stay unbound.
        let bound = match probe_all_pci(&authority) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("probe_all lost the bootstrap authority"),
        };
        if bound != 0 || bound_pci_devices() != 0 {
            return TestResult::Fail("cxgb4 bound a Chelsio device it must refuse");
        }

        // Phase B: a second claimant for the same vendor, registered
        // after cxgb4 (same specificity, so attempted second) — the
        // refused device must fall through to it. If cxgb4 had
        // returned any error other than `NotForThisDriver`, the walk
        // would have ended and this bind would never happen.
        FALLBACK_ATTEMPTED.store(false, Ordering::SeqCst);
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "cxgb4-fallback-test",
            kind: narf_bus::MatchKind::Vendor {
                vendor: CHELSIO_VENDOR,
            },
            probe: fallback_probe,
        });
        let bound = match probe_all_pci(&authority) {
            Ok(n) => n,
            Err(_) => {
                return TestResult::Fail("probe_all lost the bootstrap authority (fall-through)");
            }
        };
        if bound != 1 {
            return TestResult::Fail(
                "refused Chelsio device did not fall through to the next claimant",
            );
        }
        if !FALLBACK_ATTEMPTED.load(Ordering::SeqCst) {
            return TestResult::Fail("fallback claimant was never attempted after cxgb4 declined");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/cxgb4",
        smoke_cxgb4_probe_refuses_and_falls_through
    );
}
