//! No global bus mutation: exercise the exact policy used by all three PCI
//! family entry points against inherited command state and config failures.
use super::pci_park::{park_with, Error};
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_realtek_diagnostic_pci_parks_inherited_dma() -> TestResult {
    for initial in [0, BUS_MASTER, 0x5555, 0xffff] {
        let state = RefCell::new((initial, Vec::new()));
        let result = park_with(
            |bits| {
                let mut g = state.borrow_mut();
                g.1.push((0, bits));
                g.0 &= !bits;
                Ok(g.0)
            },
            |bits| {
                let mut g = state.borrow_mut();
                g.1.push((1, bits));
                if g.0 & BUS_MASTER != 0 {
                    return Err(());
                }
                g.0 |= bits;
                Ok(g.0)
            },
            || {
                let mut g = state.borrow_mut();
                g.1.push((2, 0));
                Ok(g.0)
            },
        );
        let g = state.borrow();
        if result != Ok(())
            || g.0 != (initial & !BUS_MASTER) | MEM_SPACE | INTX_DISABLE
            || g.1.as_slice() != [(0, BUS_MASTER), (1, MEM_SPACE | INTX_DISABLE), (2, 0)]
        {
            return TestResult::Fail(
                "Realtek probe did not clear BME before memory decode/readback",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_realtek_diagnostic_pci_parks_inherited_dma
);

fn smoke_realtek_diagnostic_pci_requires_park_readback() -> TestResult {
    for readback in [BUS_MASTER | MEM_SPACE | INTX_DISABLE, 0xffff, 0, MEM_SPACE] {
        if park_with(|_| Ok(0), |_| Ok(MEM_SPACE | INTX_DISABLE), || Ok(readback))
            != Err(Error::NotParked)
        {
            return TestResult::Fail("Realtek probe accepted active DMA/missing memory decode");
        }
    }
    for failed_step in 0..3 {
        let calls = RefCell::new(Vec::new());
        let result = park_with(
            |_| {
                calls.borrow_mut().push(0);
                if failed_step == 0 {
                    Err(())
                } else {
                    Ok(0)
                }
            },
            |_| {
                calls.borrow_mut().push(1);
                if failed_step == 1 {
                    Err(())
                } else {
                    Ok(MEM_SPACE | INTX_DISABLE)
                }
            },
            || {
                calls.borrow_mut().push(2);
                Err(())
            },
        );
        if result != Err(Error::Access) || calls.borrow().as_slice() != &([0, 1, 2][..=failed_step])
        {
            return TestResult::Fail("Realtek probe continued after config access failure");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_realtek_diagnostic_pci_requires_park_readback
);

fn smoke_realtek_repeat_probe_preserves_bound_function() -> TestResult {
    use super::pci_park::{admission, Admission};
    use narf_bus::{BusAddr, PcieAddr};
    let bound = BusAddr::Pcie(PcieAddr::new(0, 2, 0, 0));
    let extra = BusAddr::Pcie(PcieAddr::new(0, 3, 0, 0));
    let other_segment = BusAddr::Pcie(PcieAddr::new(1, 2, 0, 0));
    if admission(None, bound) != Admission::Initialize
        || admission(Some(bound), bound) != Admission::Bound
        || admission(Some(bound), extra) != Admission::ParkExtra
        || admission(Some(bound), other_segment) != Admission::ParkExtra
    {
        return TestResult::Fail("repeat probe could re-park an existing Realtek owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_realtek_repeat_probe_preserves_bound_function
);
