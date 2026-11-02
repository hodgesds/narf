use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Device {
    regs: RefCell<BTreeMap<u64, u32>>,
    log: RefCell<Vec<(bool, u64, u32)>>,
    idle: Cell<bool>,
    wake_ack: Cell<bool>,
    release_ack: Cell<bool>,
    lost: Cell<Option<u64>>,
}
impl Device {
    fn new(fuse: u32) -> Self {
        let mut regs = BTreeMap::from([
            (0xa188, 1),
            (0x130044, 1),
            (0xa278, 1),
            (0xd84, 1),
            (0x9140, fuse),
            (0xa2a0, 31),
            (0x941c, 0),
            (0xc000, 1),
            (0xc314, 0),
        ]);
        for engine in ENGINES {
            regs.insert(engine.base + 0x9c, 0x0040);
            regs.insert(engine.base + 0x29c, 0x0080);
            regs.insert(engine.msg, 0);
            if engine.request != 0 {
                regs.insert(engine.request, 0x40);
                regs.insert(engine.ack, 0x80);
            }
        }
        Self {
            regs: RefCell::new(regs),
            log: RefCell::new(Vec::new()),
            idle: Cell::new(true),
            wake_ack: Cell::new(true),
            release_ack: Cell::new(true),
            lost: Cell::new(None),
        }
    }
    fn set(&self, reg: u64, value: u32) {
        self.regs.borrow_mut().insert(reg, value);
    }
    fn prepare(&self, reset: &mut Reset, start: u64) -> u64 {
        for step in 0..32 {
            let now = start + step * 1000;
            match reset.poll_prepare(self, now, || true) {
                Poll::Pending => {}
                Poll::Ready(Ok(())) => return now,
                Poll::Ready(Err(error)) => panic!("reset preparation: {error:?}"),
            }
        }
        panic!("reset preparation never completed")
    }
    fn release(&self, reset: &mut Reset, now: u64) {
        // SAFETY: this exclusive native model has completed its full reset,
        // records GuC held in reset and has no firmware/engine DMA activity.
        unsafe {
            reset
                .begin_release_after_full_reset(self, now, || true)
                .unwrap();
        }
        assert_eq!(
            reset.poll_release(self, now + 1, || true),
            Poll::Ready(Ok(()))
        );
        assert!(reset.released());
    }
}
impl MmioWindow for Device {
    fn read32(&self, reg: u64) -> u32 {
        let mut value = if self.lost.get() == Some(reg) {
            u32::MAX
        } else {
            *self.regs.borrow().get(&reg).unwrap_or(&0)
        };
        if value != u32::MAX
            && self.idle.get()
            && ENGINES.iter().any(|engine| engine.base + 0x9c == reg)
            && value & 0x100 != 0
        {
            value |= 0x200;
        }
        self.log.borrow_mut().push((false, reg, value));
        value
    }
    fn write32(&self, reg: u64, value: u32) {
        self.log.borrow_mut().push((true, reg, value));
        let masked = reg == 0xa278
            || ENGINES.iter().any(|engine| {
                reg == engine.base + 0x9c
                    || reg == engine.base + 0x29c
                    || (engine.request != 0 && reg == engine.request)
            });
        let old = *self.regs.borrow().get(&reg).unwrap_or(&0);
        self.set(
            reg,
            if masked {
                (old & !(value >> 16)) | (value & (value >> 16))
            } else {
                value
            },
        );
        if reg == 0xa278 {
            self.set(0xd84, value & 1);
        }
        if let Some(engine) = ENGINES
            .iter()
            .find(|engine| engine.request != 0 && engine.request == reg)
        {
            let ack = *self.regs.borrow().get(&engine.ack).unwrap();
            if value & 1 != 0 && self.wake_ack.get() {
                self.set(engine.ack, ack | 1);
            }
            if value & 1 == 0 && self.release_ack.get() {
                self.set(engine.ack, ack & !1);
            }
        }
    }
}

fn smoke_gen12_reset_sparse_media_stop_gpm_settles_and_fused_register_exclusion() -> TestResult {
    // Actual physical VCS2 and VECS1, plus RCS/BCS. Other domains are fused off.
    let dev = Device::new(0x000f00ff & !(1 << 2 | 1 << 17));
    let mut reset = Reset::new(0).unwrap();
    dev.set(0x80c0, 3 << 9 | 3 << 25);
    dev.set(0x80d8, 4 << 9 | 4 << 25);
    dev.set(0xa2a0, 3);
    assert!(reset.poll_prepare(&dev, 0, || true).is_pending());
    assert!(reset.poll_prepare(&dev, 1, || true).is_pending());
    assert!(reset.poll_prepare(&dev, 2, || true).is_pending());
    let before = dev.log.borrow().len();
    assert!(reset.poll_prepare(&dev, 1001, || true).is_pending());
    assert!(
        dev.log.borrow()[before..]
            .iter()
            .all(|(write, reg, _)| !write && !ENGINES.iter().any(|engine| engine.msg == *reg)),
        "GPM receive settle was skipped"
    );
    assert!(reset.poll_prepare(&dev, 1002, || true).is_pending());
    assert!(reset.poll_prepare(&dev, 1003, || true).is_pending());
    assert_eq!(reset.pending, 7);
    dev.set(0xa2a0, 7);
    assert!(reset.poll_prepare(&dev, 1004, || true).is_pending());
    let before = dev.log.borrow().len();
    assert!(reset.poll_prepare(&dev, 2003, || true).is_pending());
    assert!(
        dev.log.borrow()[before..]
            .iter()
            .all(|(write, reg, _)| !write
                && !ENGINES.iter().any(|engine| engine.base + 0x9c == *reg)),
        "CS acknowledge settle was skipped"
    );
    assert_eq!(reset.poll_prepare(&dev, 2004, || true), Poll::Ready(Ok(())));
    assert_eq!(reset.owned, 1 << 4 | 1 << 11);
    for (index, engine) in ENGINES.iter().enumerate() {
        let present = [0, 1, 4, 11].contains(&index);
        let log = dev.log.borrow();
        for reg in [engine.base + 0x9c, engine.base + 0x29c, engine.msg] {
            assert_eq!(log.iter().any(|(_, target, _)| *target == reg), present);
        }
        if index >= 2 {
            for reg in [engine.request, engine.ack] {
                assert_eq!(log.iter().any(|(_, target, _)| *target == reg), present);
            }
        }
    }
    assert!(!dev
        .log
        .borrow()
        .iter()
        .any(|(write, reg, _)| *write && *reg == 0x941c));
    dev.release(&mut reset, 3000);
    assert_eq!(dev.read32(0xa548), 0x40);
    assert_eq!(dev.read32(0xa564), 0x40);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_reset_sparse_media_stop_gpm_settles_and_fused_register_exclusion
);

fn smoke_gen12_reset_fresh_idle_and_pending_wake_deadlines_retain_owner() -> TestResult {
    for stuck in [0, 1, 2] {
        let dev = Device::new(0x000f00fe); // VCS0 only.
        dev.idle.set(stuck != 0);
        dev.wake_ack.set(stuck != 1);
        dev.set(0x8000, 0x02000200); // Only the overlapping masked FW bit counts.
        dev.set(0xa2a0, if stuck == 2 { 0 } else { 31 });
        let mut reset = Reset::new(0).unwrap();
        for step in 0..5 {
            assert!(reset.poll_prepare(&dev, step * 1000, || true).is_pending());
        }
        assert_eq!(
            reset.poll_prepare(&dev, 200_000_000, || true),
            Poll::Ready(Err(HardwareError::Timeout))
        );
        assert_eq!(reset.owned, 1 << 2);
        assert_eq!(dev.read32(0xa540) & 1, 1);
        let writes = dev.log.borrow().len();
        assert_eq!(
            reset.poll_prepare(&dev, 200_000_001, || true),
            Poll::Ready(Err(HardwareError::Timeout))
        );
        assert_eq!(
            dev.log.borrow().len(),
            writes,
            "failed proof resumed without restart"
        );
        dev.idle.set(true);
        dev.wake_ack.set(true);
        dev.set(0xa2a0, 31);
        reset.restart(300_000_000).unwrap();
        let now = dev.prepare(&mut reset, 300_000_000);
        dev.release(&mut reset, now + 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_reset_fresh_idle_and_pending_wake_deadlines_retain_owner
);

fn smoke_gen12_reset_current_loss_and_foreign_media_wake_never_fake_proof() -> TestResult {
    let dev = Device::new(0x000f00fe);
    let mut reset = Reset::new(0).unwrap();
    {
        let _borrow = dev.regs.borrow_mut();
        assert_eq!(
            reset.poll_prepare(&dev, 0, || false),
            Poll::Ready(Err(HardwareError::Unavailable))
        );
    }
    assert!(dev.log.borrow().is_empty());
    reset.restart(1).unwrap();
    dev.set(0xa540, 0x41);
    assert_eq!(
        reset.poll_prepare(&dev, 1, || true),
        Poll::Ready(Err(HardwareError::Busy))
    );
    assert_eq!(reset.owned, 0);
    assert!(dev.log.borrow().iter().all(|(write, _, _)| !write));
    dev.set(0xa540, 0x40);
    reset.restart(2).unwrap();
    assert!(reset.poll_prepare(&dev, 2, || true).is_pending());
    dev.lost.set(Some(0xd50));
    let writes = dev
        .log
        .borrow()
        .iter()
        .filter(|(write, _, _)| *write)
        .count();
    assert_eq!(
        reset.poll_prepare(&dev, 3, || true),
        Poll::Ready(Err(HardwareError::Unavailable))
    );
    assert_eq!(
        dev.log
            .borrow()
            .iter()
            .filter(|(write, _, _)| *write)
            .count(),
        writes
    );
    assert_eq!(reset.owned, 1 << 2);
    dev.lost.set(None);
    reset.restart(10).unwrap();
    let now = dev.prepare(&mut reset, 10);
    dev.release(&mut reset, now + 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_reset_current_loss_and_foreign_media_wake_never_fake_proof
);

fn smoke_gen12_reset_media_release_needs_full_idle_and_ack_before_outer_wake() -> TestResult {
    for contradiction in [false, true] {
        let dev = Device::new(0x000f00fe);
        let mut reset = Reset::new(0).unwrap();
        let now = dev.prepare(&mut reset, 0);
        dev.release_ack.set(false);
        // SAFETY: the model's GuC/full-reset/DMA idle proof is set in new().
        unsafe {
            reset
                .begin_release_after_full_reset(&dev, now + 1, || true)
                .unwrap();
        }
        assert!(reset.poll_release(&dev, now + 2, || true).is_pending());
        if contradiction {
            dev.set(0xc314, 1);
        }
        assert_eq!(
            reset.poll_release(&dev, now + WAKE_NS + 1, || true),
            Poll::Ready(Err(if contradiction {
                HardwareError::Unavailable
            } else {
                HardwareError::Timeout
            }))
        );
        assert!(!reset.released());
        assert_eq!(reset.owned, 1 << 2);
        assert_eq!(dev.read32(0xa278) & 1, 1);
        assert_eq!(dev.read32(0xa188) & 1, 1);
        dev.set(0xc314, 0);
        dev.release_ack.set(true);
        reset.restart(now + WAKE_NS + 2).unwrap();
        let now = dev.prepare(&mut reset, now + WAKE_NS + 2);
        dev.release(&mut reset, now + 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_reset_media_release_needs_full_idle_and_ack_before_outer_wake
);

fn smoke_gen12_hardware_inherited_reset_orders_stop_before_full_and_cache() -> TestResult {
    use crate::{
        intel_gpu_gt::{Gen12Platform, GtPlatform},
        intel_gpu_gt_hw::HardwareInit,
    };
    let dev = Device::new(0x000f00ff); // No inherited media engine is present.
    dev.set(0xa278, 0);
    dev.set(0xd84, 0);
    let mut hardware = HardwareInit::new(GtPlatform::Gen12(Gen12Platform::TigerLake)).unwrap();
    hardware.begin(&dev, 0).unwrap();
    let mut done = false;
    for step in 0..32 {
        match hardware.poll_with_access(&dev, step * 1000, || true) {
            Poll::Ready(Ok(_)) => {
                done = true;
                break;
            }
            Poll::Pending => {}
            Poll::Ready(Err(error)) => panic!("inherited reset: {error:?}"),
        }
        // Hardware reset completion is independent of the stop-bit writes.
        if dev.read32(0x941c) != 0 {
            dev.set(0x941c, 0);
            dev.set(0xc000, 1);
            dev.set(0xc314, 0);
        }
    }
    assert!(done);
    let log = dev.log.borrow();
    let guc = log
        .iter()
        .position(|entry| *entry == (true, 0x941c, 8))
        .unwrap();
    let stop = log
        .iter()
        .position(|entry| *entry == (true, 0x209c, 0x01000100))
        .unwrap();
    let full = log
        .iter()
        .position(|entry| *entry == (true, 0x941c, 1))
        .unwrap();
    let cache = log
        .iter()
        .position(|entry| *entry == (true, 0x4800, 3))
        .unwrap();
    assert!(guc < stop && stop < full && full < cache);
    assert!(hardware.take_gen12_reset().unwrap().released());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_hardware_inherited_reset_orders_stop_before_full_and_cache
);

fn smoke_gen12_hardware_outer_budget_allows_source_cs_wait_without_extending_pending() -> TestResult
{
    use crate::{
        intel_gpu_gt::{Gen12Platform, GtPlatform},
        intel_gpu_gt_hw::HardwareInit,
    };
    let dev = Device::new(0x000f00ff);
    dev.set(0xa278, 0);
    dev.set(0xd84, 0);
    dev.idle.set(false);
    let mut hardware = HardwareInit::new(GtPlatform::Gen12(Gen12Platform::AlderLakeP)).unwrap();
    hardware.begin(&dev, 0).unwrap();
    assert!(hardware.poll_with_access(&dev, 0, || true).is_pending());
    dev.set(0x941c, 0);
    for now in [1000, 2000, 3000] {
        assert!(hardware.poll_with_access(&dev, now, || true).is_pending());
    }
    // CS stopping has its own100ms bound, independent of the completed
    // initial5ms GuC reset. A99ms wait must not inherit the old deadline.
    dev.idle.set(true);
    assert!(hardware
        .poll_with_access(&dev, 99_002_000, || true)
        .is_pending());
    let mut complete = false;
    for step in 1..16 {
        match hardware.poll_with_access(&dev, 99_002_000 + step * 1000, || true) {
            Poll::Pending => {}
            Poll::Ready(Ok(_)) => {
                complete = true;
                break;
            }
            Poll::Ready(Err(error)) => panic!("bounded outer reset: {error:?}"),
        }
        if dev.read32(0x941c) != 0 {
            dev.set(0x941c, 0);
        }
    }
    assert!(complete);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_hardware_outer_budget_allows_source_cs_wait_without_extending_pending
);

fn smoke_gen12_reset_partial_boot_must_prove_inherited_guc_stopped_before_any_write() -> TestResult
{
    for (status, dma, reset_value) in [(0, 0, 0), (1, 1, 0), (1, 0, 8)] {
        let dev = Device::new(0x000f00fe);
        dev.set(0xc000, status);
        dev.set(0xc314, dma);
        dev.set(0x941c, reset_value);
        let mut reset = Reset::new(0).unwrap();
        assert_eq!(
            reset.poll_prepare(&dev, 0, || true),
            Poll::Ready(Err(HardwareError::Unavailable))
        );
        assert!(dev.log.borrow().iter().all(|(write, _, _)| !write));
        assert_eq!(reset.owned, 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt",
    smoke_gen12_reset_partial_boot_must_prove_inherited_guc_stopped_before_any_write
);
