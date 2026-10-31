//! Correlated RCS0/BCS0 RING_TIMESTAMP samples. MIT Linux xe_query.c at
//! b90c984d615e8ce2af96f5b1411a962d83fed2ad.
use crate::intel_gpu_aux::MmioWindow;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EngineCycles {
    pub width: u32,
    pub engine_cycles: u64,
    pub cpu_timestamp: u64,
    pub cpu_delta: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SampleError {
    Unavailable,
    Unstable,
}

/// The caller owns current render forcewake and PCI D0. Three bounded
/// high/low/high observations avoid publishing a counter spanning rollover.
/// CPU time brackets the lower register, matching the Xe wire contract.
pub(crate) fn sample(
    window: &impl MmioWindow,
    engine: crate::intel_gpu_engine::Engine,
    width: u32,
    mut clock: impl FnMut() -> u64,
    mut monotonic: impl FnMut() -> u64,
) -> Result<EngineCycles, SampleError> {
    let (low, high) = (
        u64::from(engine.base()) + 0x358,
        u64::from(engine.base()) + 0x35c,
    );
    let mut upper = window.read32(high);
    for _ in 0..3 {
        let before = monotonic();
        let cpu_timestamp = clock();
        let lower = window.read32(low);
        let after = monotonic();
        let next = window.read32(high);
        if upper == next {
            if (upper == u32::MAX && lower == u32::MAX) || (width == 36 && upper & !0xf != 0) {
                return Err(SampleError::Unavailable);
            }
            return Ok(EngineCycles {
                width,
                engine_cycles: u64::from(upper) << 32 | u64::from(lower),
                cpu_timestamp,
                cpu_delta: after.checked_sub(before).ok_or(SampleError::Unstable)?,
            });
        }
        upper = next;
    }
    Err(SampleError::Unstable)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::intel_gpu_engine::Engine;
    use alloc::collections::VecDeque;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Registers(RefCell<VecDeque<(u64, u32)>>);
    impl MmioWindow for Registers {
        fn read32(&self, address: u64) -> u32 {
            let (expected, value) = self.0.borrow_mut().pop_front().expect("extra MMIO read");
            assert_eq!(address, expected);
            value
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("timestamp query must not write registers");
        }
    }
    fn fixed(sequence: &[(u64, u32)]) -> Registers {
        Registers(RefCell::new(sequence.iter().copied().collect()))
    }

    fn smoke_xe_engine_timestamp_rollover_and_full_width() -> TestResult {
        let registers = fixed(&[
            (0x235c, 1),
            (0x2358, u32::MAX),
            (0x235c, 2),
            (0x2358, 3),
            (0x235c, 2),
        ]);
        let cpu = Cell::new(100);
        let mono = Cell::new(10);
        let stamp = sample(
            &registers,
            Engine::Rcs0,
            36,
            || {
                let value = cpu.get();
                cpu.set(value + 1);
                value
            },
            || {
                let value = mono.get();
                mono.set(value + 5);
                value
            },
        )
        .unwrap();
        assert_eq!(
            stamp,
            EngineCycles {
                width: 36,
                engine_cycles: 0x2_0000_0003,
                cpu_timestamp: 101,
                cpu_delta: 5,
            }
        );
        assert!(registers.0.borrow().is_empty());
        let registers = fixed(&[
            (0x235c, 0x12345678),
            (0x2358, 0x90abcdef),
            (0x235c, 0x12345678),
        ]);
        let stamp = sample(&registers, Engine::Rcs0, 64, || 200, || 300).unwrap();
        assert_eq!(stamp.engine_cycles, 0x1234567890abcdef);
        assert_eq!(stamp.width, 64);
        assert_eq!(stamp.cpu_delta, 0);
        let registers = fixed(&[(0x235c, 0), (0x2358, 0), (0x235c, 0)]);
        assert_eq!(
            sample(&registers, Engine::Rcs0, 36, || 0, || 0)
                .unwrap()
                .engine_cycles,
            0
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe",
        smoke_xe_engine_timestamp_rollover_and_full_width
    );

    fn smoke_xe_engine_timestamp_unavailable_and_unstable() -> TestResult {
        let registers = fixed(&[
            (0x235c, 1),
            (0x2358, 0),
            (0x235c, 2),
            (0x2358, 0),
            (0x235c, 3),
            (0x2358, 0),
            (0x235c, 4),
        ]);
        assert_eq!(
            sample(&registers, Engine::Rcs0, 36, || 0, || 0),
            Err(SampleError::Unstable)
        );
        assert!(registers.0.borrow().is_empty());
        for (width, upper, lower) in [(64, u32::MAX, u32::MAX), (36, 16, 0)] {
            let registers = fixed(&[(0x235c, upper), (0x2358, lower), (0x235c, upper)]);
            assert_eq!(
                sample(&registers, Engine::Rcs0, width, || 0, || 0),
                Err(SampleError::Unavailable)
            );
        }
        let registers = fixed(&[(0x235c, 0), (0x2358, 1), (0x235c, 0)]);
        let mono = Cell::new(10);
        assert_eq!(
            sample(&registers, Engine::Rcs0, 36, || 0, || mono.replace(9)),
            Err(SampleError::Unstable)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe",
        smoke_xe_engine_timestamp_unavailable_and_unstable
    );
}
