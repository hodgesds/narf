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
    // PantherLake is admitted since eb930b194 (Display 30, same MTL color
    // profile: 129 degamma / 1024 gamma entries), so clean registers capture
    // successfully and the owner reports double-buffered LUT support.
    let panther = Owner::capture(&registers(), Generation::PantherLake).unwrap();
    assert!(panther.double_buffered_lut());
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

fn lut_bytes(reverse: bool) -> alloc::vec::Vec<u8> {
    (0..LUT_SIZE)
        .flat_map(|i| {
            let value = ((if reverse { LUT_SIZE - 1 - i } else { i }) * 65535 / 1023) as u16;
            [
                value.to_le_bytes(),
                (65535 - value).to_le_bytes(),
                value.to_le_bytes(),
                [0xff, 0xff],
            ]
            .concat()
        })
        .collect()
}

fn smoke_intel_gen12_ctm_owner_refuses_lut_and_dsb_without_register_writes() -> TestResult {
    for generation in [Generation::TigerLake, Generation::AlderLake] {
        let io = registers();
        let mut owner = if generation == Generation::AlderLake {
            Owner::capture_gen12(&io, crate::intel_gpu_gt::Gen12Platform::AlderLakeS)
        } else {
            Owner::capture(&io, generation)
        }
        .unwrap();
        let lut = Lut::decode(&lut_bytes(false)).unwrap();
        let before = io.0.lock().clone();
        assert_eq!(
            owner.arm_color(&io, Some(identity()), Some(lut.clone()), 100),
            Err(FsError::Unsupported)
        );
        assert!(matches!(
            owner.prepare_stages(&io, Some(identity()), None, None),
            Err(FsError::Unsupported)
        ));
        assert_eq!(*io.0.lock(), before);
        assert!(!owner.pending());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_gen12_ctm_owner_refuses_lut_and_dsb_without_register_writes
);
fn smoke_intel_gamma_native_size_rounding_channels_and_reserved_word() -> TestResult {
    let pre: Vec<u8> = (0..129)
        .flat_map(|i| {
            let v: u16 = match i {
                0 => 0,
                1 => 1,
                2 => 128,
                3 => 32768,
                _ => 65535,
            };
            [
                v.to_le_bytes(),
                v.to_le_bytes(),
                v.to_le_bytes(),
                [0xaa, 0x55],
            ]
            .concat()
        })
        .collect();
    let pre = DegammaLut::decode(&pre).unwrap();
    assert_eq!(&pre.entries[..5], &[0, 0x100, 0x8000, 0x800080, 0xffffff]);
    assert_eq!(pre.entries.len(), 131);
    assert_eq!(&pre.entries[129..], &[1 << 24, 1 << 24]);
    let bytes = lut_bytes(false);
    let lut = Lut::decode(&bytes).unwrap();
    assert_eq!(lut.entries[0], 1023 << 10);
    assert_eq!(lut.entries[1023], (1023 << 20) | 1023);
    assert!(lut.entries.iter().any(|v| (v >> 20) != ((v >> 10) & 1023)));
    let mut bytes = bytes;
    bytes[0..8].copy_from_slice(&[0, 128, 32, 0, 224, 255, 0, 0]);
    let lut = Lut::decode(&bytes).unwrap();
    assert_eq!(lut.entries[0], (512 << 20) | 1023);
    for size in [0, 255 * 8, 257 * 8, 1023 * 8, 1024 * 8 + 1, 1025 * 8] {
        assert!(matches!(
            Lut::decode(&alloc::vec![0; size]),
            Err(FsError::InvalidData)
        ));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_gamma_native_size_rounding_channels_and_reserved_word
);

fn smoke_intel_gamma_inactive_preload_disable_replacement_and_original_restore() -> TestResult {
    let io = crate::intel_gpu_kms::tests::MockPlatform::new();
    for (i, r) in MAX_REGS.into_iter().enumerate() {
        io.set(r, i as u32 + 17);
    }
    let lut = Lut::decode(&lut_bytes(false)).unwrap();
    let other = Lut::decode(&lut_bytes(true)).unwrap();
    let mut owner = Owner::capture(&io, Generation::MeteorLake).unwrap();
    owner
        .arm_color(&io, Some(identity()), Some(lut.clone()), 100)
        .unwrap();
    assert_eq!(io.palette_writes(), LUT_SIZE);
    assert_eq!(io.read32(GAMMA), POST_ENABLE | 1);
    assert!(owner.poll(&io, 101).unwrap().is_none());
    io.set(FRAME, 41);
    assert!(owner.poll(&io, 102).unwrap().is_some());
    owner.arm_color(&io, None, Some(lut), 103).unwrap();
    assert_eq!(
        io.palette_writes(),
        LUT_SIZE,
        "same LUT CTM update must not rewrite palette"
    );
    io.set(FRAME, 42);
    owner.poll(&io, 104).unwrap().unwrap();
    assert_eq!(
        owner.arm_color(&io, None, Some(other.clone()), 105),
        Err(FsError::Unsupported)
    );
    assert_eq!(io.palette_writes(), LUT_SIZE);
    owner.arm_color(&io, Some(identity()), None, 106).unwrap();
    assert_eq!(
        io.palette_writes(),
        LUT_SIZE,
        "restore cannot rewrite while gamma disable is unlatched"
    );
    assert!(owner.poll(&io, 107).unwrap().is_none());
    io.set(FRAME, 43);
    owner.poll(&io, 108).unwrap().unwrap();
    assert_eq!(io.palette_writes(), LUT_SIZE * 2);
    for i in 0..LUT_SIZE {
        io.write32(INDEX, i as u32);
        assert_eq!(io.read32(DATA), i as u32);
    }
    io.write32(INDEX, 0);
    for (i, r) in MAX_REGS.into_iter().enumerate() {
        assert_eq!(io.read32(r), i as u32 + 17);
    }
    owner.arm_color(&io, None, Some(other), 109).unwrap();
    io.set(FRAME, 44);
    owner.poll(&io, 110).unwrap().unwrap();
    let writes = io.palette_writes();
    owner.recover_original(&io, 111).unwrap();
    assert_eq!(io.palette_writes(), writes);
    io.set(FRAME, 45);
    owner.poll(&io, 112).unwrap().unwrap();
    assert_eq!(io.palette_writes(), writes + LUT_SIZE);
    assert_eq!(io.read32(GAMMA), 0);
    assert_eq!(io.read32(MODE), 0);
    // Retaining the original snapshot is not a pending restoration. Later
    // CTM-only commits keep this already-restored RAM untouched.
    let restored_writes = io.palette_writes();
    owner.arm_color(&io, Some(identity()), None, 113).unwrap();
    io.set(FRAME, 46);
    owner.poll(&io, 114).unwrap().unwrap();
    owner.arm_color(&io, None, None, 115).unwrap();
    io.set(FRAME, 47);
    owner.poll(&io, 116).unwrap().unwrap();
    assert_eq!(io.palette_writes(), restored_writes);
    assert!(!owner.palette_dirty);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_gamma_inactive_preload_disable_replacement_and_original_restore
);

fn smoke_intel_gamma_failed_preload_retains_original_for_fresh_recovery() -> TestResult {
    let io = crate::intel_gpu_kms::tests::MockPlatform::new();
    let mut owner = Owner::capture(&io, Generation::MeteorLake).unwrap();
    io.refuse_palette(true);
    assert_eq!(
        owner.arm_color(&io, None, Some(Lut::decode(&lut_bytes(true)).unwrap()), 100),
        Err(FsError::NoDevice)
    );
    assert!(owner.original_palette.is_some());
    assert!(owner.palette_dirty);
    assert!(owner.failed);
    assert_eq!(io.read32(GAMMA), 0);
    io.refuse_palette(false);
    owner.recover_original(&io, 101).unwrap();
    let writes = io.palette_writes();
    assert!(owner.poll(&io, 102).unwrap().is_none());
    io.set(FRAME, 41);
    assert!(owner.poll(&io, 103).unwrap().is_some());
    assert_eq!(io.palette_writes(), writes + LUT_SIZE);
    assert!(!owner.palette_dirty);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_gamma_failed_preload_retains_original_for_fresh_recovery
);

fn smoke_intel_gamma_control_arm_crossing_frame_fails_and_retains_owner() -> TestResult {
    struct FrameRace(Registers);
    impl MmioWindow for FrameRace {
        fn read32(&self, register: u64) -> u32 {
            self.0.read32(register)
        }
        fn write32(&self, register: u64, value: u32) {
            self.0.write32(register, value);
            if register == MODE {
                self.0.write32(FRAME, self.0.read32(FRAME) + 1);
            }
        }
    }
    for generation in [
        Generation::TigerLake,
        Generation::AlderLake,
        Generation::MeteorLake,
    ] {
        let io = FrameRace(registers());
        let mut owner = if generation == Generation::AlderLake {
            Owner::capture_gen12(&io, crate::intel_gpu_gt::Gen12Platform::AlderLakeS)
        } else {
            Owner::capture(&io, generation)
        }
        .unwrap();
        assert_eq!(
            owner.arm(&io, Some(identity()), 100),
            Err(FsError::NoDevice)
        );
        assert!(owner.pending());
        assert_eq!(owner.poll(&io, 101), Err(FsError::NoDevice));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_intel_gamma_control_arm_crossing_frame_fails_and_retains_owner
);

fn smoke_gen12_lut_profile_codec_literal_boundaries_and_endpoint_padding() -> TestResult {
    for profile in [Profile::Display12, Profile::Display13, Profile::Mtl] {
        let count = profile.sizes().1;
        let mut bytes = alloc::vec![0;count*8];
        for i in 0..count {
            let v = if i == 0 { 1u16 } else { 65535 };
            for c in 0..3 {
                bytes[i * 8 + c * 2..i * 8 + c * 2 + 2].copy_from_slice(&v.to_le_bytes());
            }
        }
        let lut = DegammaLut::decode_profile(&bytes, profile).unwrap();
        assert_eq!(
            lut.entries.len(),
            if profile == Profile::Display12 {
                35
            } else {
                131
            }
        );
        assert_eq!(
            lut.entries[0],
            if profile == Profile::Mtl { 256 } else { 1 }
        );
        assert_eq!(
            lut.entries[count - 1],
            if profile == Profile::Mtl {
                0xffffff
            } else {
                65535
            }
        );
        assert_eq!(
            &lut.entries[count..],
            &[if profile == Profile::Mtl {
                1 << 24
            } else {
                1 << 16
            }; 2]
        );
    }
    assert_eq!(Profile::Display12.sizes(), (262145, 33));
    assert_eq!(Profile::Display13.sizes(), (1024, 129));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_gen12_lut_profile_codec_literal_boundaries_and_endpoint_padding
);

// Wa_22012358565 must remain immutable through CTM/LUT/profile operations.
fn smoke_color_gen12_arb_slots_capture_retention_and_profile_refusal() -> TestResult {
    use crate::intel_gpu_gt::Gen12Platform;
    for (family, expected) in [
        (Gen12Platform::TigerLake, 0x84000000),
        (Gen12Platform::AlderLakeS, 0x84000000),
        (Gen12Platform::AlderLakeP, 0x94000000),
        (Gen12Platform::AlderLakeN, 0x94000000),
    ] {
        let io = registers();
        io.write32(0x70180, expected);
        let mut owner = Owner::capture_gen12(&io, family).unwrap();
        let wrong_profile = if expected == 0x94000000 {
            Profile::Display12
        } else {
            Profile::Display13
        };
        assert_eq!(
            owner.qualify_gen12(wrong_profile),
            Err(FsError::Unsupported)
        );
        owner.qualify_gen12(Profile::gen12(family)).unwrap();
        owner.arm(&io, Some(identity()), 100).unwrap();
        assert_eq!(io.read32(0x70180), expected);
        // A dropped/replaced arbitration image is not an acceptable source
        // family switch, including after the color arm was already exposed.
        io.write32(0x70180, expected ^ 0x10000000);
        io.write32(FRAME, 11);
        assert_eq!(owner.poll(&io, 101), Err(FsError::NoDevice));
        assert!(owner.pending());
        assert_eq!(owner.recover_original(&io, 102), Err(FsError::NoDevice));
        for wrong in [
            expected ^ 0x10000000,
            expected | 0x20000000,
            expected | 0x40000000,
        ] {
            let bad = registers();
            bad.write32(0x70180, wrong);
            let before = bad.0.lock().clone();
            assert!(matches!(
                Owner::capture_gen12(&bad, family),
                Err(FsError::Unsupported)
            ));
            assert_eq!(*bad.0.lock(), before);
        }
    }
    let io = registers();
    assert!(matches!(
        Owner::capture(&io, Generation::AlderLake),
        Err(FsError::Unsupported)
    ));
    io.write32(0x70180, 0x94000000);
    assert!(matches!(
        Owner::capture(&io, Generation::MeteorLake),
        Err(FsError::Unsupported)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_color",
    smoke_color_gen12_arb_slots_capture_retention_and_profile_refusal
);
