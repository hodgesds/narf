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

struct MappingModel {
    command: u16,
    sticky: u16,
    ignored: u16,
    failed: Option<usize>,
    calls: usize,
    trace: Vec<(u8, u16)>,
}
impl MappingModel {
    fn new(command: u16) -> Self {
        Self {
            command,
            sticky: 0,
            ignored: 0,
            failed: None,
            calls: 0,
            trace: Vec::new(),
        }
    }
    fn operation(&mut self, kind: u8, bits: u16) -> Result<u16, ()> {
        self.trace.push((kind, bits));
        let call = self.calls;
        self.calls += 1;
        if self.failed == Some(call) {
            return Err(());
        }
        match kind {
            0 => self.command &= !(bits & !self.sticky),
            1 => self.command |= bits & !self.ignored,
            _ => {}
        }
        Ok(self.command)
    }
}
fn mapping(state: &RefCell<MappingModel>, failure: bool) -> Result<u8, narf_bus::BarError> {
    super::pci_park::map_with(
        |bits| state.borrow_mut().operation(0, bits),
        |bits| state.borrow_mut().operation(1, bits),
        || state.borrow_mut().operation(2, 0),
        || {
            let mut g = state.borrow_mut();
            let command = g.command;
            g.trace.push((3, command));
            if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != INTX_DISABLE {
                return Err(narf_bus::BarError::MappingFailed);
            }
            if failure {
                Err(narf_bus::BarError::Unimplemented)
            } else {
                Ok(7)
            }
        },
    )
}
fn smoke_realtek_bar_sizing_requires_disabled_decode() -> TestResult {
    for initial in [0, BUS_MASTER | MEM_SPACE, 0xffff] {
        let state = RefCell::new(MappingModel::new(initial));
        if mapping(&state, false) != Ok(7) {
            return TestResult::Fail("valid Realtek BAR sizing policy rejected");
        }
        let g = state.borrow();
        let parked = (initial & !(BUS_MASTER | MEM_SPACE)) | INTX_DISABLE;
        if g.command != parked | MEM_SPACE
            || g.trace.as_slice()
                != [
                    (0, BUS_MASTER | MEM_SPACE),
                    (1, INTX_DISABLE),
                    (2, 0),
                    (3, parked),
                    (1, MEM_SPACE),
                    (2, 0),
                ]
        {
            return TestResult::Fail("Realtek BAR sizing ran with decode/DMA enabled");
        }
    }
    let state = RefCell::new(MappingModel::new(BUS_MASTER | MEM_SPACE));
    if mapping(&state, true) != Err(narf_bus::BarError::Unimplemented)
        || state.borrow().command != INTX_DISABLE
        || state.borrow().trace.len() != 4
    {
        return TestResult::Fail("failed Realtek mapping enabled decode or discarded BAR error");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_realtek_bar_sizing_requires_disabled_decode
);

fn smoke_realtek_bar_mapping_requires_each_config_transition() -> TestResult {
    // Five native command operations: clear both, mask IRQ, read parked,
    // enable decode after restored sizing, read final parked-DMA policy.
    for failed in 0..5 {
        let state = RefCell::new(MappingModel::new(BUS_MASTER | MEM_SPACE));
        state.borrow_mut().failed = Some(failed);
        if mapping(&state, false) != Err(narf_bus::BarError::MappingFailed)
            || state.borrow().calls != failed + 1
        {
            return TestResult::Fail("Realtek mapping continued after configuration failure");
        }
        if failed < 3 && state.borrow().trace.iter().any(|e| e.0 == 3) {
            return TestResult::Fail("Realtek BAR sizing preceded verified parking");
        }
    }
    for (sticky, ignored) in [
        (BUS_MASTER, 0),
        (MEM_SPACE, 0),
        (0, INTX_DISABLE),
        (0, MEM_SPACE),
    ] {
        let state = RefCell::new(MappingModel::new(BUS_MASTER | MEM_SPACE));
        state.borrow_mut().sticky = sticky;
        state.borrow_mut().ignored = ignored;
        if mapping(&state, false) != Err(narf_bus::BarError::MappingFailed)
            || ((sticky != 0 || ignored == INTX_DISABLE)
                && state.borrow().trace.iter().any(|e| e.0 == 3))
        {
            return TestResult::Fail("Realtek BAR mapping accepted computed writes as readback");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_realtek_bar_mapping_requires_each_config_transition
);

fn smoke_realtek_revocation_prevents_bar_sizing_and_decode_changes() -> TestResult {
    use narf_bus::BusDeviceCap;
    use narf_capabilities::{object_table, Cap, CapError, CapKind, CapSlot, Rights, Write};
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: the fixture owns the newly registered BusDevice object and
    // mints only its declared type, current generation and Write rights.
    let cap: Cap<BusDeviceCap, Write> = unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    };
    let state = RefCell::new(MappingModel::new(BUS_MASTER | MEM_SPACE));
    if super::pci_park::invoke(&cap, || mapping(&state, false)) != Ok(Ok(7)) {
        return TestResult::Fail("current Realtek mapping invocation rejected");
    }
    cap.revoke();
    state.borrow_mut().trace.clear();
    state.borrow_mut().command = BUS_MASTER | MEM_SPACE;
    if super::pci_park::invoke(&cap, || mapping(&state, false)) != Err(CapError::Revoked)
        || !state.borrow().trace.is_empty()
        || state.borrow().command != BUS_MASTER | MEM_SPACE
    {
        return TestResult::Fail("revoked Realtek authority entered config/BAR sizing operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_realtek_revocation_prevents_bar_sizing_and_decode_changes
);
