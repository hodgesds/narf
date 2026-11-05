use super::pci_park::invoke;
use core::cell::Cell;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_realtek_revoked_pci_authority_never_enters_control_operation() -> TestResult {
    // A fresh append-only object leaves every existing test/device identity
    // intact. The callback is the exact seam used for map/power/EFUSE and
    // each native firmware read/write, with no hardware in this fixture.
    // Fresh live BusDevice/Write fixture cap, minted via the safe
    // `Cap::bootstrap` path (SEC-B5, #1293: `Cap::mint` is
    // crate-private to `capabilities/`).
    let cap: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    let calls = Cell::new(0);
    if invoke(&cap, || calls.set(calls.get() + 1)).is_err() || calls.get() != 1 {
        return TestResult::Fail("live PCI control operation not executed");
    }
    cap.revoke();
    if !matches!(
        invoke(&cap, || calls.set(calls.get() + 1)),
        Err(CapError::Revoked)
    ) || calls.get() != 1
    {
        return TestResult::Fail("revoked PCI authority entered map/register operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/authority",
    smoke_realtek_revoked_pci_authority_never_enters_control_operation
);
