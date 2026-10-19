//! SMUIO 14.0.2's free-running GPU clock counter — Linux
//! smuio_v14_0_2_get_gpu_clock_counter, what `AMDGPU_INFO_TIMESTAMP`
//! returns on Navi48. It ticks at the VBIOS reference clock DEV_INFO
//! reports as `gpu_counter_freq`.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// `regGOLDEN_TSC_COUNT_UPPER` / `_LOWER`, SMUIO bank 1.
const UPPER: u64 = 0x2d;
const LOWER: u64 = 0x2e;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
}

/// Reads the counter with its own capability; reads only, so any number
/// may run concurrently with each other and with the device's owner.
#[derive(Clone, Copy, Debug)]
pub struct ClockReader {
    regs: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    base: u64,
}

trait Io {
    fn read(&mut self, at: u64) -> u32;
}
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: `ClockReader::new` bounds both registers inside the
        // discovered SMUIO bank of this mapping; reads have no side effect.
        unsafe { self.0.read32(at) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

/// The 64-bit counter from its halves: the upper half before and after the
/// lower, and the lower again if the upper moved meanwhile. All-ones reads
/// mean the device is gone.
fn sample(io: &mut impl Io, base: u64) -> Option<u64> {
    let read = |io: &mut dyn FnMut(u64) -> u32, reg: u64| {
        let v = io(base + reg * 4);
        (v != u32::MAX).then_some(u64::from(v))
    };
    let mut io = |at| io.read(at);
    let before = read(&mut io, UPPER)?;
    let mut lower = read(&mut io, LOWER)?;
    let after = read(&mut io, UPPER)?;
    if before != after {
        lower = read(&mut io, LOWER)?;
    }
    Some(after << 32 | lower)
}

impl ClockReader {
    /// A reader for `gpu`'s SMUIO 14.0.2 counter.
    pub fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let base = bank(gpu, ip::HW_ID_SMUIO, &[(14, 0, 2)], 1, LOWER as u32)
            .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            regs: gpu.regs,
            authority,
            base,
        })
    }
    /// The counter now; None once the device or the capability is gone.
    pub fn read(&self) -> Option<u64> {
        let (regs, base) = (self.regs, self.base);
        self.authority
            .invoke(Op(|| sample(&mut Mmio(regs), base)))
            .ok()
            .flatten()
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fake(Vec<u32>, usize);
    impl Io for Fake {
        fn read(&mut self, at: u64) -> u32 {
            assert!(at == 0x100 + UPPER * 4 || at == 0x100 + LOWER * 4);
            self.1 += 1;
            self.0.remove(0)
        }
    }
    /// The halves combine high-low-high, re-reading the low half when the
    /// high one moved; an all-ones read is a vanished device.
    fn smuio14_clock_reads_both_halves_consistently() -> TestResult {
        let mut steady = Fake(alloc::vec![2, 0x10, 2], 0);
        let mut carried = Fake(alloc::vec![2, 0xffff_fff0, 3, 0x4], 0);
        let mut gone = Fake(alloc::vec![u32::MAX], 0);
        if sample(&mut steady, 0x100) != Some(0x2_0000_0010)
            || steady.1 != 3
            || sample(&mut carried, 0x100) != Some(0x3_0000_0004)
            || carried.1 != 4
            || sample(&mut gone, 0x100).is_some()
        {
            return TestResult::Fail("GOLDEN_TSC sampling");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/gfx12",
        smuio14_clock_reads_both_halves_consistently
    );
}
