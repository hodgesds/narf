//! Actual stopped-pipe resource programming, qualified against PCODE replies.
use super::*;
use crate::intel_gpu_kms::tests::MockPlatform;
use narf_kernel_test::{kernel_test_in, TestResult};
fn mode() -> Mode {
    Mode {
        pixel_clock_khz: 1034,
        h_active: 64,
        h_total: 224,
        v_active: 32,
        v_total: 77,
        ..Mode::VESA_1024X768_60
    }
}
fn stopped() -> MockPlatform {
    let io = MockPlatform::new();
    io.set(0x70008, 0);
    io.set(0x70180, 0);
    io
}
fn smoke_gen12_cursor_stopped_partition_pcode_sagv_and_copy_down() -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ] {
        let io = stopped();
        io.set(0x45004, 1 << 3);
        io.pcode_values([0, 5, 0, 99, 99, 99, 0, 0], 10, 0);
        let p = setup(&io, &mode(), family).unwrap().unwrap();
        assert_eq!(p.latencies, [3, 8, 0, 0, 0, 0]);
        assert_eq!(io.read32(0x7027c), 2015 << 16);
        assert_eq!(io.read32(0x7017c), 2047 << 16 | 2016);
        assert_ne!(io.read32(0x70258) & (1 << 31), 0, "real SAGV WM");
        assert_eq!(io.read32(0x70248), io.read32(0x70244) & !(1 << 31));
        assert_eq!(io.read32(0x70254), io.read32(0x70248));
        assert_eq!(io.read32(0x70140), 0, "cursor still off");
        assert_eq!(io.read32(0x700a0), 0);
        p.check(&io, family).unwrap();
        p.check_cursor(&io, false).unwrap();
        assert!(p
            .cursor_registers(true)
            .iter()
            .any(|&(r, v)| r == 0x70158 && v & (1 << 31) != 0));
        io.set(0x7027c, 2047 << 16);
        assert_eq!(p.check(&io, family), Err(FsError::NoDevice));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_stopped_partition_pcode_sagv_and_copy_down
);
fn smoke_gen12_cursor_resource_refusals_precede_partition_and_partial_writes_abort() -> TestResult {
    let family = Gen12Platform::AlderLakeP;
    for (register, value) in [
        (0x70008, 1 << 31),
        (0x71080, 0x27),
        (0x70280, 1 << 31),
        (0x70b08, 1 << 31),
        (0x43208, 1 << 31),
        (0x4438c, 1 << 31),
        (0x44fe8, 0),
        (crate::intel_gpu_pcode::PCODE_MAILBOX, 1 << 31),
    ] {
        let io = stopped();
        io.set(register, value);
        assert!(setup(&io, &mode(), family).unwrap().is_none());
        assert!(io
            .writes()
            .iter()
            .all(|&(r, _)| !(0x70080..0x70300).contains(&r)));
    }
    for (block, status) in [(0, 0), (65536, 0), (10, 1)] {
        let io = stopped();
        io.pcode_values([6, 8, 10, 12, 14, 16, 0, 0], block, status);
        assert!(setup(&io, &mode(), family).unwrap().is_none());
        assert_eq!(io.read32(0x7027c), 2047 << 16);
    }
    let io = stopped();
    io.set(0x44fe8, u32::MAX);
    assert!(matches!(
        setup(&io, &mode(), family),
        Err(FsError::NoDevice)
    ));
    let io = stopped();
    io.refuse_layout(0x70244);
    assert!(matches!(
        setup(&io, &mode(), family),
        Err(FsError::NoDevice)
    ));
    assert_ne!(io.read32(0x70240), 0);
    assert_eq!(
        io.read32(0x70180),
        0,
        "partial resource image never enables fetch"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_cursor",
    smoke_gen12_cursor_resource_refusals_precede_partition_and_partial_writes_abort
);
