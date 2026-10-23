//! Verified PCI parking before Qualcomm/Atheros MMIO, including rejected
//! software profiles and additional radios the singleton cannot own.
use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

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
) -> Result<(), narf_bus::ProbeError> {
    prepare(&mut Function { cap, device }, memory).map_err(|_| narf_bus::ProbeError::BadDevice)
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
}
