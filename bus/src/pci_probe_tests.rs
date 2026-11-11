use super::{fake_pcie, FakeWindow};
use crate::pci::{self, PciError, PciPowerState};
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

fn pci_probe_parks_inherited_dma_and_preserves_config() -> TestResult {
    let cfg = FakeWindow::new(4096);
    // SAFETY: the owned page outlives this scoped ECAM registration.
    let _mapping = unsafe {
        crate::ecam::__test_windows(&[(narf_memory::PhysAddr::new(cfg.phys), cfg.ptr, 4096)])
    };
    let device = fake_pcie(0x7f32, 1, 0x8086, 0x15f3, 0x020000, cfg.phys);
    cfg.write32(0x04, 0x0010_0007);
    cfg.write32(0x34, 0x80);
    cfg.write32(0x80, 0x4803_0001);
    cfg.write32(0x84, 0xa55a_0100); // D0, PME enabled, unrelated upper word.
    cfg.write32(0x10, 0xdf10_0000);
    let cap = Cap::<crate::BusDeviceCap, Write>::bootstrap();
    if pci::prepare_memory_probe(&cap, &device) != Ok(Some(PciPowerState::D0))
        || cfg.read32(0x04) != 0x0010_0401
        || cfg.read32(0x84) != 0xa55a_0100
        || cfg.read32(0x10) != 0xdf10_0000
        || pci::prepare_memory_probe(&cap, &device) != Ok(Some(PciPowerState::D0))
    {
        return TestResult::Fail("probe did not park mastering/decode while preserving D0 config");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/pci-probe",
    pci_probe_parks_inherited_dma_and_preserves_config
);

fn pci_probe_d3_exit_waits_and_restores_bars_without_mastering() -> TestResult {
    let cfg = FakeWindow::new(4096);
    // SAFETY: owned fixture remains live until the real ECAM map is restored.
    let _mapping = unsafe {
        crate::ecam::__test_windows(&[(narf_memory::PhysAddr::new(cfg.phys), cfg.ptr, 4096)])
    };
    let device = fake_pcie(0x7f32, 2, 0x14c3, 0x0616, 0x028000, cfg.phys);
    cfg.write32(0x04, 0x0010_0006);
    cfg.write32(0x34, 0x80);
    cfg.write32(0x80, 0x4803_0001);
    cfg.write32(0x84, 0xa55a_8103);
    cfg.write32(0x10, 0x3030_000c);
    cfg.write32(0x14, 0xfc);
    cfg.write32(0x30, 0xdf00_0000);
    let cap = Cap::<crate::BusDeviceCap, Write>::bootstrap();
    let started = narf_time::wall::monotonic_ns();
    let result = pci::prepare_memory_probe(&cap, &device);
    if result != Ok(Some(PciPowerState::D3Hot))
        || narf_time::wall::monotonic_ns().saturating_sub(started) < 10_000_000
        || cfg.read16(0x04) != 0x0400
        || cfg.read32(0x84) != 0xa55a_0100
        || cfg.read32(0x10) != 0x3030_000c
        || cfg.read32(0x14) != 0xfc
        || cfg.read32(0x30) != 0xdf00_0000
    {
        return TestResult::Fail("D3 exit lost BAR/config or enabled DMA before ring ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/pci-probe",
    pci_probe_d3_exit_waits_and_restores_bars_without_mastering
);

fn pci_probe_refuses_missing_or_revoked_functions() -> TestResult {
    let cfg = FakeWindow::new(4096);
    // SAFETY: this one owned configuration page outlives the mapping guard.
    let _mapping = unsafe {
        crate::ecam::__test_windows(&[(narf_memory::PhysAddr::new(cfg.phys), cfg.ptr, 4096)])
    };
    let device = fake_pcie(0x7f32, 3, 0x8086, 0x15f3, 0x020000, cfg.phys);
    let cap = Cap::<crate::BusDeviceCap, Write>::bootstrap();
    cfg.write32(0x04, u32::MAX);
    if pci::prepare_memory_probe(&cap, &device) != Err(PciError::NotReady)
        || cfg.read32(0x04) != u32::MAX
    {
        return TestResult::Fail("absent function was accepted or written");
    }
    cfg.write32(0x04, 7); // No PM capability: conventional always-on function.
    if pci::prepare_memory_probe(&cap, &device) != Ok(None) || cfg.read16(0x04) != 0x0401 {
        return TestResult::Fail("function without PM could not be parked");
    }
    cfg.write32(0x04, 7);
    cap.revoke();
    if pci::prepare_memory_probe(&cap, &device) != Err(PciError::AuthorityRevoked)
        || cfg.read32(0x04) != 7
    {
        return TestResult::Fail("revoked probe authority changed configuration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/pci-probe",
    pci_probe_refuses_missing_or_revoked_functions
);
