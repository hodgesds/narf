//! Verified PCI parking before Qualcomm/Atheros MMIO, including rejected
//! software profiles and additional radios the singleton cannot own.
use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

trait Config {
    fn clear(&mut self, bits: u16) -> Result<(), ()>;
    fn set(&mut self, bits: u16) -> Result<(), ()>;
    fn read(&mut self) -> Result<u16, ()>;
}
fn prepare(config: &mut impl Config, memory: bool) -> Result<(), ()> {
    config.clear(BUS_MASTER | MEM_SPACE)?;
    config.set(INTX_DISABLE)?;
    let policy = BUS_MASTER | MEM_SPACE | INTX_DISABLE;
    if config.read()? & policy != INTX_DISABLE {
        return Err(());
    }
    if memory {
        config.set(MEM_SPACE)?;
        if config.read()? & policy != (MEM_SPACE | INTX_DISABLE) {
            return Err(());
        }
    }
    Ok(())
}
fn prepare_for_probe(config: &mut impl Config, memory: bool, same_owner: bool) -> Result<(), ()> {
    if same_owner {
        // Repeated dispatch of the live function is not inherited DMA.
        // It must not park or reset rings still owned by the current runtime.
        return Err(());
    }
    prepare(config, memory)
}
struct Function<'a> {
    cap: &'a Cap<BusDeviceCap, Write>,
    device: &'a BusDevice,
}
impl Config for Function<'_> {
    fn clear(&mut self, bits: u16) -> Result<(), ()> {
        narf_bus::pci::clear_command(self.cap, self.device, bits)
            .map(|_| ())
            .map_err(|_| ())
    }
    fn set(&mut self, bits: u16) -> Result<(), ()> {
        narf_bus::pci::set_command(self.cap, self.device, bits)
            .map(|_| ())
            .map_err(|_| ())
    }
    fn read(&mut self) -> Result<u16, ()> {
        narf_bus::pci::read_command(self.cap, self.device).map_err(|_| ())
    }
}
pub(crate) fn park(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    memory: bool,
    owner: Option<narf_bus::BusAddr>,
) -> Result<(), narf_bus::ProbeError> {
    invoke(cap, || {
        prepare_for_probe(
            &mut Function { cap, device },
            memory,
            owner == Some(device.addr),
        )
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?
    .map_err(|_| narf_bus::ProbeError::BadDevice)
}

/// BAR sizing performs all-ones PCI BAR writes. Keep decode and inherited
/// DMA parked until every sizing write is restored, then enable memory.
fn map_prepared<T>(config: &mut impl Config, map: impl FnOnce() -> Result<T, ()>) -> Result<T, ()> {
    prepare(config, false)?;
    let region = map()?;
    prepare(config, true)?;
    Ok(region)
}
pub(crate) fn invoke<T>(
    cap: &Cap<BusDeviceCap, Write>,
    operation: impl FnOnce() -> T,
) -> Result<T, CapError> {
    struct Access<F>(F);
    impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Access<F> {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(Access(operation))
}
pub(crate) fn map_bar_control(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    index: u8,
) -> Result<MmioRegion, narf_bus::ProbeError> {
    invoke(cap, || {
        map_prepared(&mut Function { cap, device }, || {
            // SAFETY: exclusive current PCI authority; map_prepared verifies
            // BME/MEM disabled before BAR sizing, restores decode only after.
            unsafe { narf_bus::map_bar_control(device, index) }.map_err(|_| ())
        })
    })
    .map_err(|_| narf_bus::ProbeError::BadDevice)?
    .map_err(|_| narf_bus::ProbeError::BadDevice)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, TestResult};
    #[derive(Debug, PartialEq)]
    enum Op {
        Clear(u16),
        Set(u16),
        Read,
    }
    struct Fake {
        command: u16,
        sticky: u16,
        ignored: u16,
        trace: Vec<Op>,
    }
    impl Config for Fake {
        fn clear(&mut self, bits: u16) -> Result<(), ()> {
            self.trace.push(Op::Clear(bits));
            self.command &= !(bits & !self.sticky);
            Ok(())
        }
        fn set(&mut self, bits: u16) -> Result<(), ()> {
            self.trace.push(Op::Set(bits));
            self.command |= bits & !self.ignored;
            Ok(())
        }
        fn read(&mut self) -> Result<u16, ()> {
            self.trace.push(Op::Read);
            Ok(self.command)
        }
    }
    fn smoke_qualcomm_pci_readback_precedes_memory_decode() -> TestResult {
        for memory in [false, true] {
            let mut config = Fake {
                command: 0x47,
                sticky: 0,
                ignored: 0,
                trace: vec![],
            };
            if prepare(&mut config, memory).is_err() {
                return TestResult::Fail("valid PCI parking rejected");
            }
            let mut expected = vec![
                Op::Clear(BUS_MASTER | MEM_SPACE),
                Op::Set(INTX_DISABLE),
                Op::Read,
            ];
            if memory {
                expected.extend([Op::Set(MEM_SPACE), Op::Read]);
            }
            if config.trace != expected
                || config.command != (0x441 | if memory { MEM_SPACE } else { 0 })
            {
                return TestResult::Fail(
                    "PCI decode activated before parked readback or unrelated bits clobbered",
                );
            }
        }
        for (sticky, ignored) in [
            (BUS_MASTER, 0),
            (MEM_SPACE, 0),
            (0, INTX_DISABLE),
            (0, MEM_SPACE),
        ] {
            let mut config = Fake {
                command: 0x47,
                sticky,
                ignored,
                trace: vec![],
            };
            if prepare(&mut config, true).is_ok()
                || sticky != 0 && config.trace.contains(&Op::Set(MEM_SPACE))
            {
                return TestResult::Fail("computed PCI write mistaken for verified parking");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/qualcomm",
        smoke_qualcomm_pci_readback_precedes_memory_decode
    );

    fn smoke_qualcomm_pci_repeat_owner_is_not_parked() -> TestResult {
        let mut config = Fake {
            command: BUS_MASTER | MEM_SPACE,
            sticky: 0,
            ignored: 0,
            trace: vec![],
        };
        if prepare_for_probe(&mut config, false, true).is_ok()
            || !config.trace.is_empty()
            || config.command != BUS_MASTER | MEM_SPACE
        {
            return TestResult::Fail("repeated dispatch stopped the live owner's DMA");
        }
        if prepare_for_probe(&mut config, false, false).is_err()
            || config.command != INTX_DISABLE
            || config.trace.is_empty()
        {
            return TestResult::Fail("unclaimed additional radio was not parked");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/qualcomm",
        smoke_qualcomm_pci_repeat_owner_is_not_parked
    );

    fn smoke_qualcomm_bar_sizing_is_decode_parked_and_capability_scoped() -> TestResult {
        use alloc::rc::Rc;
        use core::cell::{Cell, RefCell};
        struct Timed {
            state: Rc<Cell<u16>>,
            events: Rc<RefCell<Vec<(u8, u16)>>>,
        }
        impl Config for Timed {
            fn clear(&mut self, bits: u16) -> Result<(), ()> {
                self.state.set(self.state.get() & !bits);
                self.events.borrow_mut().push((0, self.state.get()));
                Ok(())
            }
            fn set(&mut self, bits: u16) -> Result<(), ()> {
                self.state.set(self.state.get() | bits);
                self.events.borrow_mut().push((1, self.state.get()));
                Ok(())
            }
            fn read(&mut self) -> Result<u16, ()> {
                self.events.borrow_mut().push((2, self.state.get()));
                Ok(self.state.get())
            }
        }
        let state = Rc::new(Cell::new(BUS_MASTER | MEM_SPACE));
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut config = Timed {
            state: state.clone(),
            events: events.clone(),
        };
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        let result = invoke(&cap, || {
            map_prepared(&mut config, || {
                events.borrow_mut().push((3, state.get()));
                if state.get() & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != INTX_DISABLE {
                    return Err(());
                }
                Ok(17)
            })
        });
        if result != Ok(Ok(17))
            || state.get() != MEM_SPACE | INTX_DISABLE
            || events.borrow().as_slice()
                != [
                    (0, 0),
                    (1, INTX_DISABLE),
                    (2, INTX_DISABLE),
                    (3, INTX_DISABLE),
                    (0, INTX_DISABLE),
                    (1, INTX_DISABLE),
                    (2, INTX_DISABLE),
                    (1, MEM_SPACE | INTX_DISABLE),
                    (2, MEM_SPACE | INTX_DISABLE),
                ]
        {
            return TestResult::Fail(
                "BAR sizing ran with decode/DMA enabled or decode opened before restored sizing",
            );
        }
        cap.revoke();
        events.borrow_mut().clear();
        if invoke(&cap, || {
            map_prepared(&mut config, || {
                events.borrow_mut().push((3, 0));
                Ok(0)
            })
        }) != Err(CapError::Revoked)
            || !events.borrow().is_empty()
        {
            return TestResult::Fail("revoked mapping operation touched config space or BARs");
        }
        let mut sticky = Fake {
            command: MEM_SPACE | BUS_MASTER,
            sticky: MEM_SPACE,
            ignored: 0,
            trace: vec![],
        };
        let mapped = Cell::new(false);
        if map_prepared(&mut sticky, || {
            mapped.set(true);
            Ok(())
        })
        .is_ok()
            || mapped.get()
        {
            return TestResult::Fail("unverified decode parking admitted BAR sizing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/qualcomm",
        smoke_qualcomm_bar_sizing_is_decode_parked_and_capability_scoped
    );
}
