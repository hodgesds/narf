//! Smokes for the SDHCI DT binding (DT programme step 6).
//!
//! QEMU virt exposes no MMC host, so the fixtures pin what is
//! provable without one: the DtMatch registration, and the
//! shared bring-up sequence reaching its real first failure
//! against a dead register file — a RAM window never self-clears
//! SRST_ALL, so `bring_up_mmio` must surface `ResetTimeout`
//! from the production reset poll, proving the DT entry runs
//! the same sequence the PCI path proves on hardware.

extern crate alloc;

use alloc::boxed::Box;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::sdhci::{register_dt_driver, Sdhci, SdhciError};

fn smoke_sdhci_dt_match_registered() -> TestResult {
    register_dt_driver();
    let found = narf_bus::registered_dt()
        .iter()
        .any(|m| m.compatible == "xlnx,zynqmp-8.9a");
    if !found {
        return TestResult::Fail("SDHCI DT match (xlnx,zynqmp-8.9a) not registered");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-storage-sdhci", smoke_sdhci_dt_match_registered);

fn smoke_sdhci_dt_bring_up_reaches_reset() -> TestResult {
    // A 4 KiB dead register file: reads return what was written,
    // nothing self-clears. The production bring-up must run its
    // reset step and time out honestly rather than sailing on
    // into the card sequence.
    let buf: Box<[u8; 4096]> = Box::new([0u8; 4096]);
    let raw = Box::leak(buf);
    let base = raw.as_ptr() as u64;
    let mmio = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(base),
        virt: base,
        len: 0x1000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: the leaked RAM window outlives the call; bring_up
    // fails before any controller state is published.
    let result = unsafe { Sdhci::bring_up_mmio(mmio) };
    match result {
        Err(SdhciError::ResetTimeout) => TestResult::Pass,
        Err(e) => TestResult::Fail(match e {
            SdhciError::BarMapFailed => "DT bring-up failed at a BAR step it should not have",
            SdhciError::NoCard => "DT bring-up skipped the reset poll (reached card check)",
            _ => "DT bring-up failed with an unexpected error",
        }),
        Ok(_) => TestResult::Fail("DT bring-up succeeded against a dead register file"),
    }
}
kernel_test_in!(
    "drivers-storage-sdhci",
    smoke_sdhci_dt_bring_up_reaches_reset
);
