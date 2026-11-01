use super::*;
use alloc::{collections::BTreeMap, sync::Arc};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone)]
struct Registers(Arc<IrqSafeSpinLock<BTreeMap<u64, u32>>>);
impl MmioWindow for Registers {
    fn read32(&self, r: u64) -> u32 {
        self.0.lock().get(&r).copied().unwrap_or(0)
    }
    fn write32(&self, r: u64, v: u32) {
        self.0.lock().insert(r, v);
    }
}
fn registers() -> Registers {
    let io = Registers(Arc::new(IrqSafeSpinLock::new(BTreeMap::new())));
    io.write32(0x70180, 0x84000000);
    io.write32(0x701cc, 1 << 13);
    io.write32(FRAME, 10);
    io
}
fn identity() -> [u64; 9] {
    [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32]
}
fn smoke_intel_ctm_coefficient_encoding_follows_linux_rounding_and_clamp() -> TestResult {
    for (input, expected) in [
        (0, 0x3000),
        (1 << 63, 0xb000),
        ((1 << 29) - 1, 0x3ff8),
        (1 << 29, 0x2800),
        ((1 << 30) - 1, 0x2ff8),
        (1 << 30, 0x1800),
        ((1 << 31) - 1, 0x1ff8),
        (1 << 31, 0x0800),
        ((1 << 32) - 1, 0x0ff8),
        (1 << 32, 0x7800),
        ((2 << 32) - 1, 0x7ff8),
        (2 << 32, 0x6800),
        ((4 << 32) - 1, 0x6ff8),
        (u64::MAX, 0xeff8),
        ((1 << 63) | (1 << 32), 0xf800),
        ((1 << 29) + (1 << 20), 0x2808),
    ] {
        assert_eq!(coefficient(input), expected, "coefficient {input:#x}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_ctm_coefficient_encoding_follows_linux_rounding_and_clamp
);
fn smoke_intel_ctm_original_snapshot_and_real_vblank_readback() -> TestResult {
    let io = registers();
    for (i, r) in REGISTERS.into_iter().enumerate() {
        io.write32(r, i as u32 + 1);
    }
    let mut owner = Owner::capture(&io, Generation::MeteorLake).unwrap();
    owner.arm(&io, Some(identity()), 100).unwrap();
    assert_eq!(io.read32(MODE), CSC_ENABLE);
    assert_eq!(io.read32(0x49010), 0x78003000);
    assert!(owner.poll(&io, 101).unwrap().is_none());
    io.write32(FRAME, 11);
    assert_eq!(
        owner.poll(&io, 123).unwrap(),
        Some(FlipStamp {
            ns: 123,
            sequence: 11
        })
    );
    owner.arm(&io, None, 124).unwrap();
    assert!(owner.poll(&io, 125).unwrap().is_none());
    io.write32(FRAME, 12);
    assert!(owner.poll(&io, 126).unwrap().is_some());
    assert_eq!(io.read32(MODE), 0);
    for (i, r) in REGISTERS.into_iter().enumerate() {
        assert_eq!(io.read32(r), i as u32 + 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_ctm_original_snapshot_and_real_vblank_readback
);
fn smoke_intel_ctm_inherited_color_paths_refuse_without_writes() -> TestResult {
    for (r, v) in [
        (MODE, 1 << 31),
        (MODE, 1 << 30),
        (GAMMA, 1 << 31),
        (GAMMA, 1 << 30),
        (0x701cc, 0),
        (0x701cc, (1 << 13) | (1 << 21)),
        (0x701cc, (1 << 13) | (1 << 20)),
        (0x701cc, (1 << 13) | (1 << 17)),
        (0x701cc, (1 << 13) | (1 << 15)),
        (0x701cc, (1 << 13) | (1 << 14)),
        (0x701cc, (1 << 13) | (3 << 4)),
        (0x701c8, 1 << 31),
        (0x701c8, 1 << 12),
        (0x70034, 1),
        (0x70180, 0x86000000),
    ] {
        let io = registers();
        io.write32(r, v);
        let before = io.0.lock().clone();
        assert!(matches!(
            Owner::capture(&io, Generation::MeteorLake),
            Err(FsError::Unsupported)
        ));
        assert_eq!(*io.0.lock(), before);
    }
    assert!(matches!(
        Owner::capture(&registers(), Generation::TigerLake),
        Err(FsError::Unsupported)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_ctm_inherited_color_paths_refuse_without_writes
);
fn smoke_intel_ctm_failed_readback_timeout_and_fresh_original_recovery() -> TestResult {
    for timeout in [false, true] {
        let io = registers();
        let mut owner = Owner::capture(&io, Generation::MeteorLake).unwrap();
        owner.arm(&io, Some(identity()), 100).unwrap();
        if !timeout {
            io.write32(0x49010, 0);
        }
        assert_eq!(
            owner.poll(&io, 1_000_000_100),
            Err(if timeout {
                FsError::TimedOut
            } else {
                FsError::NoDevice
            })
        );
        assert!(owner.pending());
        // Recovery independently re-arms baseline; an old changed frame cannot
        // satisfy it. No old color readback is accepted as restoration.
        io.write32(FRAME, 99);
        owner.recover_original(&io, 2_000_000_000).unwrap();
        assert!(owner.poll(&io, 2_000_000_001).unwrap().is_none());
        io.write32(FRAME, 100);
        assert!(owner.poll(&io, 2_000_000_002).unwrap().is_some());
        assert_eq!(io.read32(MODE), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_ctm_failed_readback_timeout_and_fresh_original_recovery
);
