//! User-job GPU time, following MIT Linux b90c984d xe_lrc.c
//! setup_utilization_wa/xe_lrc_timestamp and xe_guc_submit.c::check_timeout.
//! CTX_TIMESTAMP counts only while this context executes. A restore batch
//! marks the saved timestamp active; context save replaces that marker.

use super::{SchedulingError, TIMEOUT};
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_engine::{Engine, EngineSet, REGS},
    intel_gpu_gt::GtPlatform,
    intel_gpu_rcs::GpuBacking,
};
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

const START: u64 = 0x808;
const JOB_TIMESTAMP: u64 = 0x810;
const ENGINE_RECEIPT: u64 = 0x818;
const TIMESTAMP: u64 = REGS + 0x23 * 4;
/// Private, cache-line-aligned PPHWSP space outside the breadcrumbs.
const RESTORE_BATCH: u64 = 0x900;
const ACTIVE: u32 = 1;

/// Install a trusted per-context batch, run after every restore. Its private
/// GGTT stores are followed by MI_BATCH_BUFFER_END. Unlike a
/// ring-only marker, this stays correct when GuC preempts and resumes a job.
pub(super) fn setup(image: &impl GpuBacking, platform: GtPlatform) {
    setup_inner(image, platform, false);
}

pub(super) fn setup_virtual(image: &impl GpuBacking, platform: GtPlatform) {
    setup_inner(image, platform, true);
}

fn setup_inner(image: &impl GpuBacking, platform: GtPlatform, virtual_engine: bool) {
    let address = image.ggtt_offset();
    let mut words = Vec::new();
    if virtual_engine {
        // xe_lrc.c::setup_utilization_wa: CS-relative ENGINE_ID captured
        // before marking this restore active, outside every user mapping.
        words.extend_from_slice(&[0x12480002, 0x8c, address + ENGINE_RECEIPT as u32, 0]);
    }
    words.extend_from_slice(&[0x10400002, address + TIMESTAMP as u32, 0, ACTIVE]);
    if platform == GtPlatform::Battlemage {
        words.extend_from_slice(&[0x10400002, address + (REGS + 0x25 * 4) as u32, 0, 0]);
    }
    words.push(0x05000000);
    for (i, word) in words.into_iter().enumerate() {
        image.write32(RESTORE_BATCH + i as u64 * 4, word);
    }
    image.write32(REGS + 0x13 * 4, address + RESTORE_BATCH as u32 + 1);
}

pub(super) fn observed_engine(
    image: &impl GpuBacking,
    stamp: u32,
    placements: EngineSet,
) -> Result<Option<Engine>, SchedulingError> {
    let first = placements.iter().next().ok_or(SchedulingError::State)?;
    if placements.iter().count() == 1 {
        return Ok(Some(first));
    }
    match image.read32(START) {
        0 => return Ok(None),
        found if found != stamp => return Err(SchedulingError::Protocol),
        _ => {}
    }
    let receipt = image.read32(ENGINE_RECEIPT);
    placements
        .decode_hardware_id(receipt)
        .map(Some)
        .ok_or(SchedulingError::Protocol)
}

/// Sample CTX_TIMESTAMP before publishing the start stamp. Both writes are
/// GGTT, outside the untrusted PPGTT address space, as in emit_copy_timestamp.
pub(super) fn prefix(image: u32, stamp: u32, engine: Engine, words: &mut Vec<u32>) {
    let mut start = alloc::vec![0x12480002, 0x3a8, image + JOB_TIMESTAMP as u32, 0];
    // BCS already has a TLB-invalidating MI_FLUSH_DW start stamp.
    if !engine.is_copy() {
        start.extend_from_slice(&[0x10400002, image + START as u32, 0, stamp]);
    }
    words.splice(0..0, start);
}

#[derive(Default)]
pub(super) struct Runtime {
    previous_active: Option<(Engine, u32)>,
    previous_timestamp: Option<u32>,
    last_running_ticks: Option<u32>,
}

impl Runtime {
    pub(super) fn diagnostic_ticks(&self) -> Option<u32> {
        self.last_running_ticks
    }

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
        self.expired_on(image, stamp, EngineSet::of(&[engine]), window)
    }

    pub(super) fn expired_on(
        &mut self,
        image: &impl GpuBacking,
        stamp: u32,
        placements: EngineSet,
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
        let engine = observed_engine(image, stamp, placements)?.ok_or(SchedulingError::Protocol)?;
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
            if observed_engine(image, stamp, placements)? != Some(engine) {
                // GuC migrated between the receipt and MMIO observations.
                self.previous_active = None;
                return Ok((false, false));
            }
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
        let stuck = active && self.previous_active == Some((engine, current));
        self.previous_active = active.then_some((engine, current));
        let progressed = self.previous_timestamp != Some(current);
        self.previous_timestamp = Some(current);
        let ticks = current.wrapping_sub(image.read32(JOB_TIMESTAMP));
        self.last_running_ticks = Some(ticks);
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
                if engine.is_copy() {
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

    struct VirtualWindow<'a> {
        image: &'a Image,
        engine: Engine,
        migrate: Option<u32>,
    }
    impl MmioWindow for VirtualWindow<'_> {
        fn read32(&self, address: u64) -> u32 {
            if address == 0xd00 {
                return 0;
            }
            let base = u64::from(self.engine.base());
            if address == base + 0x240 {
                return self.image.ggtt_offset();
            }
            assert_eq!(address, base + 0x3a8, "wrong physical timestamp bank");
            if let Some(receipt) = self.migrate {
                self.image.write32(ENGINE_RECEIPT, receipt);
            }
            3_000_000
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("virtual watchdog must not write MMIO");
        }
    }

    fn smoke_virtual_runtime_physical_receipt_each_restore_and_migration() -> TestResult {
        for placements in [
            EngineSet::of(&[Engine::Bcs0, Engine::Bcs8]),
            EngineSet::of(&[Engine::Ccs0, Engine::Ccs1, Engine::Ccs2, Engine::Ccs3]),
        ] {
            let image = image();
            let mut runtime = Runtime::default();
            assert_eq!(observed_engine(&image, 7, placements), Ok(None));
            for engine in placements.iter() {
                image.write32(START, 7);
                image.write32(TIMESTAMP, ACTIVE);
                let receipt =
                    engine.physical_instance() << 4 | if engine.is_compute() { 5 } else { 3 };
                image.write32(ENGINE_RECEIPT, receipt);
                assert_eq!(observed_engine(&image, 7, placements), Ok(Some(engine)));
                let window = VirtualWindow {
                    image: &image,
                    engine,
                    migrate: None,
                };
                // Equal timestamps on different engines are not a stuck
                // context: the physical receipt is part of the observation.
                assert!(
                    !runtime
                        .expired_on(&image, 7, placements, &window)
                        .unwrap()
                        .0
                );
                assert!(
                    runtime
                        .expired_on(&image, 7, placements, &window)
                        .unwrap()
                        .0
                );
            }
        }
        let placements = EngineSet::of(&[Engine::Ccs1, Engine::Ccs3]);
        let image = image();
        image.write32(START, 7);
        image.write32(TIMESTAMP, ACTIVE);
        image.write32(ENGINE_RECEIPT, 0x15);
        let racing = VirtualWindow {
            image: &image,
            engine: Engine::Ccs1,
            migrate: Some(0x35),
        };
        assert_eq!(
            Runtime::default().expired_on(&image, 7, placements, &racing),
            Ok((false, false))
        );
        for bad in [0, 3, 5, 0x25, 0x83, u32::MAX] {
            image.write32(ENGINE_RECEIPT, bad);
            assert_eq!(
                observed_engine(&image, 7, placements),
                Err(SchedulingError::Protocol)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_virtual_queues",
        smoke_virtual_runtime_physical_receipt_each_restore_and_migration
    );
}
