// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual native restrictive park over scoped original RAM ECAM/BAR.
//! Active/link observations are synthetic; no physical activation, NASR
//! grant, RF stop, reset or DMA terminal receipt is fabricated.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_ae_native_terminal_park_withdraws_link_even_after_mac_failure() -> TestResult {
    for failure in 0..4 {
        let address = narf_bus::PcieAddr::new(0x7f23, 0, 0, 0);
        let mut config = vec![0u32; 1024].into_boxed_slice();
        config[0] = 0x8723_10ec;
        config[1] = u32::from(
            narf_bus::pci::cmd::MEM_SPACE
                | narf_bus::pci::cmd::BUS_MASTER
                | narf_bus::pci::cmd::INTX_DISABLE,
        ) | 1 << 20;
        config[0x18 / 4] = 0x7420_0000;
        config[0x2c / 4] = 0x2233_10ec;
        config[0x34 / 4] = 0x40;
        config[0x40 / 4] = 0x10;
        config[0x4c / 4] = 0xc00 | 1 << 18;
        config[0x50 / 4] = 0x0143;
        let physical = narf_memory::PhysAddr::new(0x7421_0000);
        // SAFETY: this private original RAM config page outlives its ECAM
        // guard and the native adapter. It is never registered as hardware.
        let _ecam = unsafe {
            narf_bus::ecam::__test_windows(&[(physical, config.as_mut_ptr().cast(), 4096)])
        };
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0x8723,
                class: 0x028000,
                subsystem_vendor: 0x10ec,
                subsystem_id: 0x2233,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: physical,
            },
        };
        let mut registers = vec![0u32; 0x2000 / 4].into_boxed_slice();
        registers[0x100 / 4] = if failure == 2 { 0xffff } else { 0x02ff };
        registers[0x3a8 / 4] = 0x1122_3344;
        registers[0x3ac / 4] = 0x5566_7788;
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0x7420_0000),
            virt: registers.as_mut_ptr() as u64,
            len: 0x2000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        // SAFETY: exact private RAM mappings above stay exclusively owned
        // for this native adapter's lifetime; no actual endpoint is claimed.
        let io = unsafe { PciIo::new(device, cap, region) };
        io.packet_mode.store(true, Ordering::Release);
        if failure == 1 {
            cap.revoke();
        }
        if failure == 3 {
            config[0] ^= 1;
        }
        let result = io.restrict_ae_packets();
        if result.is_ok() != (failure == 0) {
            return TestResult::Fail("AE terminal park invented complete receipts");
        }
        if matches!(failure, 0 | 2) {
            if config[1] & u32::from(narf_bus::pci::cmd::BUS_MASTER) != 0
                || config[0x50 / 4] != 0x40
                || registers[0x3a8 / 4] != 0
                || registers[0x3ac / 4] != 0
                || registers[0x100 / 4] != if failure == 2 { 0xffff } else { 0x0230 }
            {
                return TestResult::Fail(
                    "AE independent restrictive link/IRQ/BME gate was skipped",
                );
            }
        } else if config[0x50 / 4] != 0x0143
            || config[1] & u32::from(narf_bus::pci::cmd::BUS_MASTER) == 0
            || registers[0x3a8 / 4] != 0x1122_3344
            || registers[0x3ac / 4] != 0x5566_7788
            || registers[0x100 / 4] != 0x02ff
        {
            return TestResult::Fail(
                "AE revoked/replaced original PCI reached restrictive effects",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_ae_native_terminal_park_withdraws_link_even_after_mac_failure
);
