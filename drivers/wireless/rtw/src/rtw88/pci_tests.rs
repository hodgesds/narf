//! Exercise the runtime BAR selection without modifying global PCI state.

use narf_bus::{
    Bar, BarError, BarKind, BusAddr, BusDevice, BusKind, DeviceId, MmioRegion, PcieAddr,
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

use super::fw::{download_firmware, FwError};
use super::pci::{map_registers_with, register_window_min, ProbeError};
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
            register_window_min(device.id.device) - 1
        ))),
        Err(ProbeError::RegisterBarTooSmall)
    ) {
        return TestResult::Fail("rtw88 accepted a register BAR too short for power-on");
    }
    if map_registers_with(&device, |_, _| {
        Ok(register_fixture(register_window_min(device.id.device)))
    })
    .is_err()
    {
        return TestResult::Fail("rtw88 rejected the minimum complete register extent");
    }
    TestResult::Pass
}
fn smoke_rtw8821ce_native_register_window_covers_dma_lte_and_chip_mac() -> TestResult {
    let device = device(RTL_DEV_8821CE);
    for len in [0x1104, 0x1334, 0x144f, 0x170b] {
        if !matches!(
            map_registers_with(&device, |_, _| Ok(register_fixture(len))),
            Err(ProbeError::RegisterBarTooSmall)
        ) {
            return TestResult::Fail(
                "8821C accepted an identification-only BAR for native firmware/MAC",
            );
        }
    }
    if map_registers_with(&device, |_, _| Ok(register_fixture(0x170c))).is_err() {
        return TestResult::Fail("8821C rejected complete native register window");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_native_register_window_covers_dma_lte_and_chip_mac
);
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

fn smoke_rtw88_drive_scheduled_retries_and_terminates() -> TestResult {
    let attempts = core::cell::Cell::new(0);
    let waits = core::cell::Cell::new(0);
    let retryable = core::cell::Cell::new(true);

    // Case 1: retries while retryable and succeeds
    let result = narf_scheduler::block_on(super::pci::drive_scheduled(
        5,
        || retryable.get(),
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move {
                if n < 2 {
                    Err(super::FirmwareError::State)
                } else {
                    Ok(())
                }
            }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result.is_err() || attempts.get() != 3 || waits.get() != 2 {
        return TestResult::Fail("rtw88 drive_scheduled failed to retry");
    }

    // Case 2: stops early when retryable returns false
    attempts.set(0);
    waits.set(0);
    retryable.set(false);
    let result = narf_scheduler::block_on(super::pci::drive_scheduled(
        10,
        || retryable.get(),
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move { Err(super::FirmwareError::State) }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result != Err(super::FirmwareError::State) || attempts.get() != 1 || waits.get() != 0 {
        return TestResult::Fail("rtw88 drive_scheduled did not exit early when unretryable");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_drive_scheduled_retries_and_terminates
);
