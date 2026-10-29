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
// HDP6 removed HDP5's READ_CACHE_INVALIDATE register. HOST_PATH_CNTL is
// readable, has reserved zero bits, and shares this offset on HDP6 revisions.
const HDP_LIVE: u32 = 0xcc; // regHDP_HOST_PATH_CNTL, HDP6 base 0

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
    live: u64,
}

trait Io {
    fn read(&mut self, at: u64) -> u32;
}
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: `ClockReader::new` bounds the SMUIO halves and HDP probe
        // inside this permanent mapping; reads have no side effect.
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
/// lower, and the lower again if the upper moved meanwhile. HDP probes
/// detect loss independently; every counter bit pattern is valid.
fn sample(io: &mut impl Io, base: u64, live: u64) -> Option<u64> {
    if io.read(live) == u32::MAX {
        return None;
    }
    let before = io.read(base + UPPER * 4);
    let mut lower = io.read(base + LOWER * 4);
    let after = io.read(base + UPPER * 4);
    if before != after {
        lower = io.read(base + LOWER * 4);
    }
    (io.read(live) != u32::MAX).then_some(u64::from(after) << 32 | u64::from(lower))
}

impl ClockReader {
    /// A reader for `gpu`'s SMUIO 14.0.2 counter.
    pub fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let base = bank(gpu, ip::HW_ID_SMUIO, &[(14, 0, 2)], 1, LOWER as u32)
            .map_err(|_| Error::Unsupported)?;
        let live = bank(
            gpu,
            ip::HW_ID_HDP,
            &[(6, 0, 0), (6, 0, 1), (6, 1, 0), (6, 1, 1), (6, 4, 0)],
            0,
            HDP_LIVE,
        )
        .map_err(|_| Error::Unsupported)?
            + u64::from(HDP_LIVE) * 4;
        Ok(Self {
            regs: gpu.regs,
            authority,
            base,
            live,
        })
    }
    /// The counter now; None once the device or the capability is gone.
    pub fn read(&self) -> Option<u64> {
        let (regs, base, live) = (self.regs, self.base, self.live);
        self.authority
            .invoke(Op(|| {
                narf_lib::sync::without_interrupts(|| sample(&mut Mmio(regs), base, live))
            }))
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
            assert!(at == 0x100 + UPPER * 4 || at == 0x100 + LOWER * 4 || at == 0x80);
            self.1 += 1;
            self.0.remove(0)
        }
    }
    /// The halves combine high-low-high, re-reading the low half when the
    /// high one moved; an all-ones HDP probe is a vanished device.
    fn smuio14_clock_reads_both_halves_consistently() -> TestResult {
        let mut steady = Fake(alloc::vec![0, 2, 0x10, 2, 0], 0);
        let mut carried = Fake(alloc::vec![0, 2, 0xffff_fff0, 3, 0x4, 0], 0);
        let mut gone = Fake(alloc::vec![u32::MAX], 0);
        let mut max = Fake(alloc::vec![0, u32::MAX, u32::MAX, u32::MAX, 0], 0);
        let mut late_loss = Fake(alloc::vec![0, 2, 0x10, 2, u32::MAX], 0);
        if sample(&mut steady, 0x100, 0x80) != Some(0x2_0000_0010)
            || steady.1 != 5
            || sample(&mut carried, 0x100, 0x80) != Some(0x3_0000_0004)
            || carried.1 != 6
            || sample(&mut gone, 0x100, 0x80).is_some()
            || sample(&mut max, 0x100, 0x80) != Some(u64::MAX)
            || sample(&mut late_loss, 0x100, 0x80).is_some()
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
