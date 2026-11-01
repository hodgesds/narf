//! User-job GPU time, following MIT Linux b90c984d xe_lrc.c
//! setup_utilization_wa/xe_lrc_timestamp and xe_guc_submit.c::check_timeout.
//! CTX_TIMESTAMP counts only while this context executes. A restore batch
//! marks the saved timestamp active; context save replaces that marker.

use super::{SchedulingError, TIMEOUT};
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_engine::{Engine, REGS},
    intel_gpu_gt::GtPlatform,
    intel_gpu_rcs::GpuBacking,
};
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

const START: u64 = 0x808;
const JOB_TIMESTAMP: u64 = 0x810;
const TIMESTAMP: u64 = REGS + 0x23 * 4;
/// Private, cache-line-aligned PPHWSP space outside the breadcrumbs.
const RESTORE_BATCH: u64 = 0x900;
const ACTIVE: u32 = 1;

/// Install a trusted per-context batch, run after every restore. These are
/// MI_STORE_DATA_IMM GGTT stores followed by MI_BATCH_BUFFER_END. Unlike a
/// ring-only marker, this stays correct when GuC preempts and resumes a job.
pub(super) fn setup(image: &impl GpuBacking, platform: GtPlatform) {
    let address = image.ggtt_offset();
    let mut words = alloc::vec![0x10400002, address + TIMESTAMP as u32, 0, ACTIVE];
    if platform == GtPlatform::Battlemage {
        words.extend_from_slice(&[0x10400002, address + (REGS + 0x25 * 4) as u32, 0, 0]);
    }
    words.push(0x05000000);
    for (i, word) in words.into_iter().enumerate() {
        image.write32(RESTORE_BATCH + i as u64 * 4, word);
    }
    image.write32(REGS + 0x13 * 4, address + RESTORE_BATCH as u32 + 1);
}

/// Sample CTX_TIMESTAMP before publishing the start stamp. Both writes are
/// GGTT, outside the untrusted PPGTT address space, as in emit_copy_timestamp.
pub(super) fn prefix(image: u32, stamp: u32, engine: Engine, words: &mut Vec<u32>) {
    let mut start = alloc::vec![0x12480002, 0x3a8, image + JOB_TIMESTAMP as u32, 0];
    // BCS already has a TLB-invalidating MI_FLUSH_DW start stamp.
    if engine != Engine::Bcs0 {
        start.extend_from_slice(&[0x10400002, image + START as u32, 0, stamp]);
    }
    words.splice(0..0, start);
}

#[derive(Default)]
pub(super) struct Runtime {
    previous_active: Option<u32>,
    previous_timestamp: Option<u32>,
}

impl Runtime {
    /// Called at a wall-clock watchdog interval, after CPU cache visibility
    /// has been established. Queuing/preemption costs no job runtime. A live
    /// timestamp stuck across two watchdog observations still identifies a
    /// hardware hang, even when its counter stopped below the runtime limit.
    pub(super) fn expired(
        &mut self,
        image: &impl GpuBacking,
        stamp: u32,
        engine: Engine,
        window: &impl MmioWindow,
    ) -> Result<(bool, bool), SchedulingError> {
        fence(Ordering::Acquire);
        match image.read32(START) {
            0 => {
                self.previous_active = None;
                return Ok((false, false));
            }
            found if found != stamp => return Err(SchedulingError::Protocol),
            _ => {}
        }
        let rpm = window.read32(0xd00);
        if rpm == u32::MAX || rpm != window.read32(0xd00) {
            return Err(SchedulingError::Protocol);
        }
        let crystal = match (rpm >> 3) & 7 {
            0 => 24_000_000u64,
            1 => 19_200_000,
            2 => 38_400_000,
            3 => 25_000_000,
            _ => return Err(SchedulingError::Protocol),
        };
        let frequency = crystal >> (3 - ((rpm >> 1) & 3));
        let mut saved = image.read32(TIMESTAMP);
        let mut current = saved;
        let mut active = false;
        if saved == ACTIVE {
            let base = u64::from(engine.base());
            let before = window.read32(base + 0x240); // RING_CURRENT_LRCA
            current = window.read32(base + 0x3a8);
            let after = window.read32(base + 0x240);
            if before == u32::MAX || after == u32::MAX {
                return Err(SchedulingError::Protocol);
            }
            // A context can switch out between the saved-state and MMIO
            // reads. In that case its new saved value wins over the other
            // context's live counter (xe_lrc_timestamp's read-again rule).
            fence(Ordering::Acquire);
            saved = image.read32(TIMESTAMP);
            if saved == ACTIVE {
                // A saved counter can itself equal the active sentinel.
                // Validate ownership before charging live MMIO to this job.
                if before & !0xfff != image.ggtt_offset() || after & !0xfff != image.ggtt_offset() {
                    // This can also be a restore/save transition. The
                    // sentinel is not a counter and must never participate
                    // in wrapping subtraction against the job timestamp.
                    self.previous_active = None;
                    return Ok((false, false));
                } else if current == u32::MAX {
                    return Err(SchedulingError::Protocol);
                } else {
                    active = true;
                }
            } else {
                current = saved;
            }
        }
        let stuck = active && self.previous_active == Some(current);
        self.previous_active = active.then_some(current);
        let progressed = self.previous_timestamp != Some(current);
        self.previous_timestamp = Some(current);
        let ticks = current.wrapping_sub(image.read32(JOB_TIMESTAMP));
        // Five seconds is far below the shortest supported 32-bit wrap
        // interval (112 s). Match Linux's 5% GuC scheduling tolerance.
        let running_ns = u64::from(ticks) * 1_000_000_000 / frequency;
        Ok((stuck || running_ns * 105 / 100 >= TIMEOUT, progressed))
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::intel_gpu_engine::tests::Image;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Window<'a> {
        current: u32,
        lrca: u32,
        clock: u32,
        switched: Option<&'a Image>,
    }
    impl MmioWindow for Window<'_> {
        fn read32(&self, address: u64) -> u32 {
            match address {
                0xd00 => self.clock,
                0x2240 => self.lrca,
                0x23a8 => {
                    if let Some(image) = self.switched {
                        image.write32(TIMESTAMP, 3_000_000);
                    }
                    self.current
                }
                _ => panic!("unexpected timeout MMIO"),
            }
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("watchdog must not write MMIO");
        }
    }
    fn image() -> Image {
        Image(RefCell::new(alloc::vec![0; 2048]))
    }
    fn window(image: &Image, current: u32) -> Window<'_> {
        Window {
            current,
            lrca: image.ggtt_offset(),
            clock: 0,
            switched: None,
        }
    }

    fn smoke_guc_runtime_restore_and_ring_vectors() -> TestResult {
        for platform in [GtPlatform::Alchemist, GtPlatform::Battlemage] {
            let image = image();
            setup(&image, platform);
            assert_eq!(image.read32(REGS + 0x13 * 4), 0x01000901);
            assert_eq!(
                &image.0.borrow()[0x900 / 4..0x910 / 4],
                &[0x10400002, 0x0100108c, 0, 1]
            );
            if platform == GtPlatform::Battlemage {
                assert_eq!(
                    &image.0.borrow()[0x910 / 4..0x924 / 4],
                    &[0x10400002, 0x01001094, 0, 0, 0x05000000]
                );
            } else {
                assert_eq!(image.read32(0x910), 0x05000000);
            }
            for engine in Engine::ALL {
                let mut words = alloc::vec![0x04000001];
                prefix(image.ggtt_offset(), 7, engine, &mut words);
                assert_eq!(&words[..4], &[0x12480002, 0x3a8, 0x01000810, 0]);
                if engine == Engine::Bcs0 {
                    assert_eq!(&words[4..], &[0x04000001]);
                } else {
                    assert_eq!(&words[4..], &[0x10400002, 0x01000808, 0, 7, 0x04000001]);
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_user",
        smoke_guc_runtime_restore_and_ring_vectors
    );

    fn smoke_guc_runtime_queued_preempted_and_stuck() -> TestResult {
        let image = image();
        let mut runtime = Runtime::default();
        // An unstarted job reads no MMIO, even an inaccessible BAR.
        let unavailable = Window {
            current: u32::MAX,
            lrca: u32::MAX,
            clock: u32::MAX,
            switched: None,
        };
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &unavailable),
            Ok((false, false))
        );
        image.write32(START, 7);
        image.write32(TIMESTAMP, 3_000_000);
        let other = window(&image, 900_000_000);
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &other),
            Ok((false, true))
        );
        // Frozen inactive LRC time is preemption, not a guilty hang.
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &other),
            Ok((false, false))
        );
        image.write32(TIMESTAMP, ACTIVE);
        let active = window(&image, 4_000_000);
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &active),
            Ok((false, true))
        );
        // Two unchanged active samples identify a stopped hardware counter.
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &active),
            Ok((true, false))
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_user",
        smoke_guc_runtime_queued_preempted_and_stuck
    );

    fn smoke_guc_runtime_wrap_switch_race_and_bad_reads() -> TestResult {
        let image = image();
        image.write32(START, 7);
        image.write32(JOB_TIMESTAMP, u32::MAX - 2_999_999);
        image.write32(TIMESTAMP, 3_000_000);
        let mut runtime = Runtime::default();
        // Counter wrap represents two seconds at the actual 3 MHz clock.
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &window(&image, 0)),
            Ok((false, true))
        );
        image.write32(TIMESTAMP, 12_000_000);
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &window(&image, 0)),
            Ok((true, true))
        );
        image.write32(JOB_TIMESTAMP, 0);
        image.write32(TIMESTAMP, ACTIVE);
        let switched = Window {
            current: 900_000_000,
            lrca: image.ggtt_offset(),
            clock: 0,
            switched: Some(&image),
        };
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &switched),
            Ok((false, true))
        );
        // An actual saved timestamp of one must not borrow another LRC's time.
        image.write32(TIMESTAMP, ACTIVE);
        let other = Window {
            current: 900_000_000,
            lrca: image.ggtt_offset() + 4096,
            clock: 0,
            switched: None,
        };
        image.write32(JOB_TIMESTAMP, 100);
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &other),
            Ok((false, false))
        );
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &window(&image, u32::MAX)),
            Err(SchedulingError::Protocol)
        );
        let bad_clock = Window {
            current: 0,
            lrca: image.ggtt_offset(),
            clock: 4 << 3,
            switched: None,
        };
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &bad_clock),
            Err(SchedulingError::Protocol)
        );
        image.write32(START, 8);
        assert_eq!(
            runtime.expired(&image, 7, Engine::Rcs0, &window(&image, 0)),
            Err(SchedulingError::Protocol)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_user",
        smoke_guc_runtime_wrap_switch_race_and_bad_reads
    );
}
