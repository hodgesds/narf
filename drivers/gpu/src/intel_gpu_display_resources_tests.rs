//! Native production modeset/resource conversations. Linux register literals
//! are repeated independently here; the model supplies only ACK/power mirrors.
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Debug)]
struct Registers {
    mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake,
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    drop_write: Cell<u64>,
    lost_read: Cell<u64>,
    ack: Cell<bool>,
}
impl Registers {
    fn new() -> Self {
        Self {
            mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake::new(
                crate::intel_gpu_xelpg::XeLpgPort::A,
            ),
            values: RefCell::new(
                [
                    (0x510a0, 14 << 22),
                    (0x45780, 6 | (8 << 16)),
                    (0x45784, 10 | (12 << 16)),
                    (0x45788, 14 | (16 << 16)),
                ]
                .into_iter()
                .collect(),
            ),
            writes: RefCell::new(Vec::new()),
            drop_write: Cell::new(u64::MAX),
            lost_read: Cell::new(u64::MAX),
            ack: Cell::new(true),
        }
    }
    fn resource(r: u64) -> bool {
        matches!(
            r,
            0x510a0
                | 0x45230
                | 0x45234
                | 0x46440
                | 0x46438
                | 0x4438c
                | 0x7003c
                | 0x44464
                | 0x44468
                | 0x4446c
                | 0x45780
                | 0x45784
                | 0x45788
                | 0x45008
                | 0x44fe8
                | 0x44300
                | 0x44304
                | 0x45004
                | 0x71008
                | 0x72008
                | 0x73008
        ) || ((0x70000..0x75000).contains(&r)
            && r & 0xfff >= 0x140
            && r & 0xfff <= 0x87c
            && r & 0xff < 0x80)
    }
    fn run(&self) -> Result<Mode, crate::intel_gpu_modeset::ModesetError> {
        crate::intel_gpu_modeset::modeset_display(
            self,
            crate::intel_gpu::Generation::MeteorLake,
            &crate::intel_gpu_modeset::Framebuffer {
                phys_addr: 0x1000000,
                stride_bytes: 4096,
                format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
            },
            Some(&Mode::VESA_1024X768_60),
        )
    }
}
impl MmioWindow for Registers {
    fn read32(&self, r: u64) -> u32 {
        if self.lost_read.get() == r {
            return u32::MAX;
        }
        if Self::resource(r) {
            *self.values.borrow().get(&r).unwrap_or(&0)
        } else {
            self.mode.read32(r)
        }
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if self.drop_write.get() == r {
            return;
        }
        if Self::resource(r) {
            let mut value = v;
            if r == 0x45234 && v & (1 << 31) != 0 && self.ack.get() {
                value &= !(1 << 31)
            }
            if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) && v & (1 << 31) != 0 {
                value |= 1 << 30
            }
            self.values.borrow_mut().insert(r, value);
        } else {
            self.mode.write32(r, v)
        }
    }
}
fn smoke_mtl_cursor_resources_real_modeset_ack_joined_ddb_and_watermarks() -> TestResult {
    let io = Registers::new();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    let profile = Profile::capture(&io, &Mode::VESA_1024X768_60).unwrap();
    assert_eq!(io.read32(0x45230) >> 16, 0xffff);
    assert_eq!(io.read32(0x45230) & 0xf7, 0x71);
    assert_eq!(io.read32(0x45234) & (1 << 31), 0);
    assert_eq!((io.read32(0x45234) >> 8) & 2047, 810);
    assert_eq!(io.read32(0x46438) & (1 << 19), 1 << 19);
    assert_eq!(io.read32(0x4438c) & 0xdc000000, 0xdc000000);
    assert_eq!(io.read32(0x7003c), 0x0103ca4c);
    assert_eq!(io.read32(0x45004) & (1 << 3), 1 << 3);
    for r in [0x45008, 0x44fe8, 0x44300, 0x44304] {
        assert_eq!(io.read32(r) & 0xc0ff0000, 0xc0430000)
    }
    assert_eq!(
        io.read32(0x7027c),
        (u32::from(profile.cursor_start) - 1) << 16
    );
    assert_eq!(
        io.read32(0x7017c),
        (4095 << 16) | u32::from(profile.cursor_start)
    );
    assert!(profile.cursor_start <= 4064);
    assert!(profile.primary.levels[0].enable && profile.cursor.levels[0].enable);
    assert_eq!(
        io.read32(0x70140),
        0,
        "hidden cursor keeps reserved DDB with disabled WMs"
    );
    assert!(
        io.writes
            .borrow()
            .iter()
            .position(|&(r, v)| r == 0x45234 && v >> 31 != 0)
            .unwrap()
            < io.writes
                .borrow()
                .iter()
                .position(|&(r, _)| r == 0x4438c)
                .unwrap()
    );
    let before = io.writes.borrow().len();
    for pipe in 1..4 {
        // A blank enabled pipe invalidates the global single-pipe owner too.
        let register = 0x70008 + pipe * 0x1000;
        io.values.borrow_mut().insert(register, 1 << 31);
        assert!(matches!(
            Profile::capture(&io, &Mode::VESA_1024X768_60),
            Err(FsError::Unsupported)
        ));
        io.values.borrow_mut().insert(register, 0);
    }
    assert_eq!(io.writes.borrow().len(), before);
    io.values.borrow_mut().insert(0x45004, 0);
    assert!(matches!(
        Profile::capture(&io, &Mode::VESA_1024X768_60),
        Err(FsError::Unsupported)
    ));
    assert_eq!(io.writes.borrow().len(), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_mtl_cursor_resources_real_modeset_ack_joined_ddb_and_watermarks
);
fn smoke_mtl_cursor_resources_prewrite_foreign_and_bad_profiles_refused() -> TestResult {
    for (r, v) in [
        (0x71008, 3 << 30),
        (0x70080, 0x27),
        (0x70b08, 1 << 31),
        (0x43248, 1 << 31),
    ] {
        let io = Registers::new();
        io.values.borrow_mut().insert(r, v);
        // Use the generic model overlay for the full register surface here.
        struct Overlay<'a>(&'a Registers, u64, u32);
        impl MmioWindow for Overlay<'_> {
            fn read32(&self, r: u64) -> u32 {
                if r == self.1 {
                    self.2
                } else {
                    self.0.read32(r)
                }
            }
            fn write32(&self, r: u64, v: u32) {
                self.0.write32(r, v)
            }
        }
        assert!(
            initialize(&Overlay(&io, r, v), &Mode::VESA_1024X768_60, 307200)
                .unwrap()
                .is_none()
        );
        assert!(io.writes.borrow().is_empty());
    }
    let io = Registers::new();
    io.values
        .borrow_mut()
        .insert(0x510a0, (14 << 22) | (1 << 14));
    assert!(initialize(&io, &Mode::VESA_1024X768_60, 307200)
        .unwrap()
        .is_none());
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_mtl_cursor_resources_prewrite_foreign_and_bad_profiles_refused
);
fn smoke_mtl_cursor_resources_partial_failures_keep_pipe_off_then_fresh_retry() -> TestResult {
    for fault in [0x45230, 0x4438c, 0x7027c] {
        let io = Registers::new();
        io.drop_write.set(fault);
        assert_eq!(
            io.run(),
            Err(crate::intel_gpu_modeset::ModesetError::DisplayResourceUnavailable)
        );
        assert_eq!(io.read32(0x70008) & 0xc0000000, 0);
        assert_eq!(io.read32(0x70180) & (1 << 31), 0);
        assert!(Profile::capture(&io, &Mode::VESA_1024X768_60).is_err());
        io.drop_write.set(u64::MAX);
        assert!(io.run().is_ok());
    }
    let io = Registers::new();
    io.lost_read.set(0x45230);
    assert!(io.run().is_err());
    assert_eq!(io.read32(0x70008) & 0xc0000000, 0);
    let io = Registers::new();
    io.ack.set(false);
    assert!(io.run().is_err());
    assert_ne!(io.read32(0x45234) & (1 << 31), 0);
    assert_eq!(io.read32(0x70008) & 0xc0000000, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_mtl_cursor_resources_partial_failures_keep_pipe_off_then_fresh_retry
);
