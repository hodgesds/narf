use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Scratch(u32),
    SetConfig(u16, u32),
    Pmfw,
    Memsize,
}
#[derive(Default)]
struct Fake {
    scratch: Option<u32>,
    config: BTreeMap<u16, u32>,
    log: Vec<Step>,
    pmfw: Option<Error>,
    /// MEMSIZE reads that return all-ones before the real value.
    dead_reads: u32,
}
impl Io for Fake {
    fn scratch3(&mut self) -> Option<u32> {
        self.scratch
    }
    fn set_scratch3(&mut self, value: u32) {
        self.scratch = Some(value);
        self.log.push(Step::Scratch(value));
    }
    fn config(&mut self, offset: u16) -> Result<u32, Error> {
        Ok(*self.config.get(&offset).unwrap_or(&0))
    }
    fn set_config(&mut self, offset: u16, value: u32) -> Result<(), Error> {
        self.config.insert(offset, value);
        self.log.push(Step::SetConfig(offset, value));
        Ok(())
    }
    async fn pmfw_mode2(&mut self) -> Result<(), Error> {
        self.log.push(Step::Pmfw);
        // The reset clears bus mastering and a BAR, as the cached state covers.
        self.config.insert(PCI_BASE_ADDRESS_0, 0);
        self.pmfw.map_or(Ok(()), Err)
    }
    fn memsize(&mut self) -> Result<u32, Error> {
        self.log.push(Step::Memsize);
        if self.dead_reads > 0 {
            self.dead_reads -= 1;
            return Ok(u32::MAX);
        }
        Ok(0x200)
    }
    async fn sleep_ms(&mut self, _: u64) {}
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

/// nv_asic_mode2_reset's order: engine-hung scratch, bus mastering off with
/// the command register and BARs cached, PMFW mode 2, the cached state
/// restored, MEMSIZE alive, the scratch bit cleared. A refused message is
/// reported after the restore; MEMSIZE that stays all-ones is the device
/// gone.
fn raphael_mode2_follows_nv_asic_mode2_reset() -> TestResult {
    let fake = || Fake {
        scratch: Some(0x11),
        config: [(PCI_COMMAND, 0x0007), (PCI_BASE_ADDRESS_0, 0xd000_000c)]
            .into_iter()
            .collect(),
        dead_reads: 2,
        ..Fake::default()
    };
    let mut io = fake();
    if run(sequence(&mut io)) != Ok(()) {
        return TestResult::Fail("mode 2 sequence failed");
    }
    let pmfw = io.log.iter().position(|s| *s == Step::Pmfw).unwrap();
    let restored = io
        .log
        .iter()
        .position(|s| *s == Step::SetConfig(PCI_BASE_ADDRESS_0, 0xd000_000c))
        .unwrap();
    if io.log.first() != Some(&Step::Scratch(0x2000_0011))
        || io.log.get(1) != Some(&Step::SetConfig(PCI_COMMAND, 0x0003))
        || pmfw != 2
        || restored <= pmfw
        || io.config[&PCI_COMMAND] != 0x0007
        || io.log.iter().filter(|s| **s == Step::Memsize).count() != 3
        || io.log.last() != Some(&Step::Scratch(0x11))
    {
        return TestResult::Fail("mode 2 steps out of nv_asic_mode2_reset's order");
    }
    let mut refused = fake();
    refused.pmfw = Some(Error::Smu(smu::Error::Rejected(0xff)));
    let mut gone = fake();
    gone.dead_reads = u32::MAX;
    if run(sequence(&mut refused)) != Err(Error::Smu(smu::Error::Rejected(0xff)))
        || refused.config[&PCI_COMMAND] != 0x0007
        || refused.scratch != Some(0x11)
        || run(sequence(&mut gone)) != Err(Error::Timeout)
    {
        return TestResult::Fail("a failed mode 2 left the device half-restored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/raphael-reset",
    raphael_mode2_follows_nv_asic_mode2_reset
);
