// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual NativeMmio + current PCI config under original publication gates.
//! RAM ECAM/BAR are owned fixtures, not boolean source validators.
use super::*;
use crate::pio::Registers;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_sdhci_native_mmio_publication_scope_preserves_actual_cap_and_terminal_latch() -> TestResult
{
    for late_cap in [false, true] {
        let mut config = alloc::vec![0u32; 1024].into_boxed_slice();
        let mut registers = alloc::vec![0u32; 64].into_boxed_slice();
        config[0] = 0x12341abc;
        config[1] = u32::from(narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE);
        let physical = narf_memory::PhysAddr::new(0x7f31_0000);
        // SAFETY: both owned pages outlive the scoped mapping and NativeMmio.
        let _ecam = unsafe {
            narf_bus::ecam::__test_windows(&[(physical, config.as_mut_ptr().cast(), 4096)])
        };
        let address = narf_bus::PcieAddr::new(0x7f31, 0, 0, 0);
        let identity = crate::pio::HostIdentity {
            address: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x1abc,
                device: 0x1234,
                class: 0x080500,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
        };
        let device = BusDevice {
            addr: identity.address,
            id: identity.id,
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: physical,
            },
        };
        let authority = Cap::<BusDeviceCap, Write>::bootstrap();
        let mut io = Mmio {
            region: MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: registers.as_mut_ptr() as u64,
                len: 256,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            },
            authority,
            device,
            gone: false,
            identity,
            intx: false,
            source_live: crate::source::Lifetime::new(),
            source_intx: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
        };
        let original = io
            .source()
            .unwrap()
            .retain_controller(&crate::source::Lifetime::new())
            .unwrap()
            .retain_card(&crate::source::Lifetime::new())
            .unwrap();
        // This actual MMIO action re-enters native current checking while
        // the original native gate is held. It must neither deadlock nor
        // skip original PCI identity/BME/INTx validity.
        if original
            .invoke(|| io.write16(crate::sdhci::regs::COMMAND, 0x1234))
            .is_err()
            || registers[3] >> 16 != 0x1234
            || io.gone
        {
            return TestResult::Fail("valid actual NativeMmio under source scope failed");
        }
        let mut attempted = false;
        let result = if late_cap {
            authority.revoke();
            original.invoke(|| {
                attempted = true;
                io.write16(crate::sdhci::regs::COMMAND, 0x5678);
            })
        } else {
            original.invoke(|| {
                attempted = true;
                // Actual BME violation occurs inside the original action,
                // after its entry proof. Native per-MMIO checks must still
                // deny the write and latch failure without recursive locks.
                config[1] |= u32::from(narf_bus::pci::cmd::BUS_MASTER);
                io.write16(crate::sdhci::regs::COMMAND, 0x5678);
            })
        };
        if result.is_ok()
            || attempted == late_cap
            || registers[3] >> 16 != 0x1234
            || original.current().is_ok()
            || io.source().is_some()
        {
            return TestResult::Fail("late native source loss wrote COMMAND or revived old owner");
        }
        config[1] &= !u32::from(narf_bus::pci::cmd::BUS_MASTER);
        if original.current().is_ok() {
            return TestResult::Fail("restored command bits revived terminal native latch");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/native",
    smoke_sdhci_native_mmio_publication_scope_preserves_actual_cap_and_terminal_latch
);
