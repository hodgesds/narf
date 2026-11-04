use super::{fake_pcie, FakeWindow};
use crate::pci::pme::{self, PmeError, WakeState};
use narf_capabilities::{Cap, Read, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

fn native_pme_words_preserve_power_and_current_endpoint_authority() -> TestResult {
    let cfg = FakeWindow::new(4096);
    // SAFETY: the owned page remains live until this mapping guard drops.
    let _mapping = unsafe {
        crate::ecam::__test_windows(&[(narf_memory::PhysAddr::new(cfg.phys), cfg.ptr, 4096)])
    };
    let endpoint = fake_pcie(0x7f31, 1, 0x14c3, 0x7922, 0x028000, cfg.phys);
    cfg.write32(0x04, 0x0010_0000); // PCI Status.CAP_LIST
    cfg.write32(0x34, 0x80);
    cfg.write32(0x80, 0x4803_0001); // PM version3, PME D0+D3hot, capID1
    cfg.write32(0x84, 0xa55a_5c03); // D3hot plus unrelated PMCSR and data word
    let write = Cap::<crate::BusDeviceCap, Write>::bootstrap();
    let read: Cap<crate::BusDeviceCap, Read> = match write.derive() {
        Ok(cap) => cap,
        Err(_) => return TestResult::Fail("could not derive current endpoint Read authority"),
    };
    let before = match pme::status(&read, &endpoint) {
        Ok(status) => status,
        Err(_) => return TestResult::Fail("literal PM capability could not be read"),
    };
    if !before.supports(WakeState::D0)
        || !before.supports(WakeState::D3Hot)
        || before.supports(WakeState::D1)
        || before.supports(WakeState::D3Cold)
        || before.enabled
        || before.pending
    {
        return TestResult::Fail("native PME support bits were reinterpreted");
    }
    if pme::arm(&write, &endpoint, WakeState::D1) != Err(PmeError::Unsupported)
        || cfg.read32(0x84) != 0xa55a_5c03
    {
        return TestResult::Fail("unsupported PME state changed endpoint configuration");
    }
    if pme::arm(&write, &endpoint, WakeState::D3Hot) != Ok(()) || cfg.read32(0x84) != 0xa55a_dd03 {
        return TestResult::Fail("PME arm changed power/data fields or omitted W1C status");
    }
    // This fixture is RAM, not a W1C hardware emulator. The literal one
    // written to bit15 above proves the native acknowledgement intent.
    if pme::arm(&write, &endpoint, WakeState::D0) != Err(PmeError::AlreadyEnabled)
        || cfg.read32(0x84) != 0xa55a_dd03
    {
        return TestResult::Fail("a second PME owner erased the first owner's status");
    }
    if pme::disarm(&write, &endpoint) != Ok(true) || cfg.read32(0x84) != 0xa55a_dc03 {
        return TestResult::Fail("PME terminal cleanup lost status or unrelated PMCSR fields");
    }
    write.revoke();
    cfg.write32(0x84, 0xa55a_5c03);
    let revoked = PmeError::Pci(crate::pci::PciError::AuthorityRevoked);
    if pme::arm(&write, &endpoint, WakeState::D0) != Err(revoked)
        || pme::disarm(&write, &endpoint) != Err(revoked)
        || pme::status(&read, &endpoint) != Err(revoked)
        || cfg.read32(0x84) != 0xa55a_5c03
    {
        return TestResult::Fail("revoked endpoint retained PME register access");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/pme",
    native_pme_words_preserve_power_and_current_endpoint_authority
);

fn malformed_or_unavailable_native_pm_capabilities_never_arm() -> TestResult {
    let cfg = FakeWindow::new(4096);
    // SAFETY: this fixture owns the exact config page for the guard's life.
    let _mapping = unsafe {
        crate::ecam::__test_windows(&[(narf_memory::PhysAddr::new(cfg.phys), cfg.ptr, 4096)])
    };
    let endpoint = fake_pcie(0x7f31, 2, 0x14c3, 0x7922, 0x028000, cfg.phys);
    cfg.write32(0x04, 0x0010_0000);
    cfg.write32(0x34, 0x80);
    cfg.write32(0x80, 0xffff_0001);
    cfg.write32(0x84, 0);
    let cap = Cap::<crate::BusDeviceCap, Write>::bootstrap();
    if pme::arm(&cap, &endpoint, WakeState::D0) != Err(PmeError::Unavailable)
        || cfg.read32(0x84) != 0
    {
        return TestResult::Fail("malformed PM version created a PME source");
    }
    cfg.write32(0x80, 0x4803_0001);
    cfg.write32(0x84, u32::MAX);
    if pme::arm(&cap, &endpoint, WakeState::D0) != Err(PmeError::Unavailable) {
        return TestResult::Fail("an unavailable function was accepted as PME-enabled");
    }
    cfg.write32(0x34, 0xfc);
    cfg.write32(0xfc, 0x4803_0001);
    if pme::arm(&cap, &endpoint, WakeState::D0) != Err(PmeError::Unavailable) {
        return TestResult::Fail("truncated conventional PM capability crossed its boundary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/pme",
    malformed_or_unavailable_native_pm_capabilities_never_arm
);
