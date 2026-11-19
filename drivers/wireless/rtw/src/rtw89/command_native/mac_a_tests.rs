// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
fn smoke_rtw8852a_native_mac_port_encloses_each_actual_access_in_original_grants() -> TestResult {
    for revoke in [false, true] {
        let mut words = vec![0u32; 0x10000 / 4];
        let bus =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: words.as_mut_ptr() as u64,
            len: 0x10000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: independently owned aligned inert BAR, no physical device.
        let mut native = unsafe { NativeIo::new(region, bus, ChipId::Rtl8852A, 1) }.unwrap();
        let (grant, record) = crate::rtw89::mac_a_policy::tests::model();
        let mut port = Port {
            io: &mut native,
            grant: &grant,
            error: None,
        };
        if port.write32(0x2f0, 0x1234_8282).is_err() || port.read32(0x2f0) != Ok(0x1234_8282) {
            return TestResult::Fail("A actual MAC Port did not retain signed/Bus scope");
        }
        let address = narf_bus::PcieAddr::new(0, 0, 7, 0);
        let device = narf_bus::BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0x8852,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let mut rx = RxPort {
            io: port,
            device: &device,
            authority: &bus,
        };
        let mut config_effects = 0;
        // Invalid extent refuses before ECAM mapping/dereference; no positive
        // configuration or LTR permission is fabricated in this native case.
        if rx
            .config(4095, 2, |_| {
                config_effects += 1;
                0u16
            })
            .is_ok()
            || config_effects != 0
        {
            return TestResult::Fail("A RX config extent reached an unowned access");
        }
        if revoke {
            record.revoke();
        } else {
            bus.revoke();
        }
        if rx.write32(0x2f0, 0).is_ok()
            || rx.read32(0x2f0).is_ok()
            || rx
                .config(0x28, 2, |_| {
                    config_effects += 1;
                    0u16
                })
                .is_ok()
            || config_effects != 0
            || words[0x2f0 / 4] != 0x1234_8282
        {
            return TestResult::Fail("A revoked MAC/Bus grant permitted actual BAR effect");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_mac_port_encloses_each_actual_access_in_original_grants
);
