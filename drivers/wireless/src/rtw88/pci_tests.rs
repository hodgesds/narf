//! Exercise the runtime BAR selection without modifying global PCI state.

use narf_bus::{
    Bar, BarError, BarKind, BusAddr, BusDevice, BusKind, DeviceId, MmioRegion, PcieAddr,
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

use super::fw::{download_firmware, FwError};
use super::pci::{map_registers_with, ProbeError};
use super::regs::*;

fn device(did: u16) -> BusDevice {
    let addr = PcieAddr::new(0, 1, 0, 0);
    BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: REALTEK_VENDOR,
            device: did,
            class: 0x028000,
            subsystem_vendor: REALTEK_VENDOR,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    }
}

fn register_fixture(len: u64) -> MmioRegion {
    MmioRegion {
        phys: PhysAddr::new(0x2000_0000),
        // Mapping-only fixture; no test dereferences this address.
        virt: 0,
        len,
        kind: BarKind::Mmio64 {
            prefetchable: false,
        },
    }
}

fn smoke_rtw88_pci_selects_bar2_control_window() -> TestResult {
    for &did in ALL_DEV_IDS {
        let device = device(did);
        let mut selected = None;
        let expected = register_fixture(0x4000);
        let bars = [
            Bar {
                idx: 0,
                kind: BarKind::Io,
                phys: PhysAddr::new(0x1000),
                size: 0x100,
            },
            Bar {
                idx: 2,
                kind: expected.kind,
                phys: expected.phys,
                size: expected.len,
            },
        ];
        let mapped = map_registers_with(&device, |passed_device, index| {
            selected = Some(index);
            if !core::ptr::eq(passed_device, &device) {
                return Err(BarError::Unimplemented);
            }
            let bar = bars
                .iter()
                .find(|bar| bar.idx == index)
                .ok_or(BarError::Unimplemented)?;
            if matches!(bar.kind, BarKind::Io) {
                return Err(BarError::NotPcie);
            }
            Ok(MmioRegion {
                phys: bar.phys,
                virt: 0,
                len: bar.size,
                kind: bar.kind,
            })
        });
        match mapped {
            Ok(region) if selected == Some(2) && region.phys == expected.phys => {}
            _ => {
                return TestResult::Fail(
                    "rtw88 did not map the matched PCI function's BAR2 registers",
                )
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_pci_selects_bar2_control_window
);

fn smoke_rtw88_pci_missing_or_short_register_bar_fails() -> TestResult {
    let device = device(RTL_DEV_8822CE);
    if !matches!(
        map_registers_with(&device, |_, _| Err(BarError::Unimplemented)),
        Err(ProbeError::RegisterBarMapFailed)
    ) {
        return TestResult::Fail("rtw88 accepted absent BAR2 or attempted a fallback register BAR");
    }
    if !matches!(
        map_registers_with(&device, |_, _| Ok(register_fixture(
            super::power::REGISTER_WINDOW_MIN - 1
        ))),
        Err(ProbeError::RegisterBarTooSmall)
    ) {
        return TestResult::Fail("rtw88 accepted a register BAR too short for power-on");
    }
    if map_registers_with(&device, |_, _| {
        Ok(register_fixture(super::power::REGISTER_WINDOW_MIN))
    })
    .is_err()
    {
        return TestResult::Fail("rtw88 rejected the minimum complete register extent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_pci_missing_or_short_register_bar_fails
);

fn smoke_rtw88_firmware_unsupported_without_mmio() -> TestResult {
    // An unavailable loader needs neither a firmware capability nor valid
    // MMIO. It must reject all chips before any device/register access.
    let registers = register_fixture(0);
    for did in [RTL_DEV_8821CE, RTL_DEV_8822BE, RTL_DEV_8822CE, 0xffff] {
        if download_firmware(&registers, did) != Err(FwError::Unsupported) {
            return TestResult::Fail("rtw88 reported firmware success without a real loader");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_firmware_unsupported_without_mmio
);
