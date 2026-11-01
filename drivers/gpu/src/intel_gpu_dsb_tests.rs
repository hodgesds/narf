//! Production WC/GGTT transport conversations using the native display model.
use super::*;
use crate::intel_gpu_kms::{tests::MockPlatform, Platform};
use narf_kernel_test::{kernel_test_in, TestResult};

fn transport(platform: &MockPlatform) -> Option<Owner<MockPlatform>> {
    match Owner::reserve(platform.clone(), 0x1000000) {
        Ok(owner) => Some(owner),
        Err(FsError::NotImplemented) => {
            assert!(cfg!(target_arch = "aarch64"));
            None
        }
        Err(error) => panic!("DSB transport reserve failed: {error:?}"),
    }
}
fn smoke_dsb_ggtt_ledger_exclusive_fixed_idempotent_and_per_bar() -> TestResult {
    use crate::intel_gpu_ggtt_ranges::Kind;
    let p = MockPlatform::new();
    let q = MockPlatform::new();
    let a = Ledger::for_bar(p.ggtt_key().unwrap(), 0x1000000).unwrap();
    let again = Ledger::for_bar(p.ggtt_key().unwrap(), 0x1000000).unwrap();
    assert!(Arc::ptr_eq(&a, &again));
    for _ in 0..2 {
        assert!(a.allows(Kind::Console(0), 16 * 1024 * 1024, 32 * 1024 * 1024));
        assert!(a.allows(Kind::Console(3), 112 * 1024 * 1024, 32 * 1024 * 1024));
        assert!(a.allows(Kind::Primary, 160 * 1024 * 1024, 96 * 1024 * 1024));
        assert!(a.allows(Kind::Gt, 256 * 1024 * 1024, 16 * 1024 * 1024));
    }
    assert!(!a.allows(Kind::Console(3), 112 * 1024 * 1024, 32 * 1024 * 1024 + 1));
    assert!(!a.allows(Kind::Primary, 144 * 1024 * 1024, 4096));
    assert!(!a.allows(Kind::Gt, 160 * 1024 * 1024, 4096));
    assert!(matches!(
        Ledger::for_bar(p.ggtt_key().unwrap(), 0x900000),
        Err(FsError::Busy)
    ));
    let b = Ledger::for_bar(q.ggtt_key().unwrap(), 0x1000000).unwrap();
    let full = a.reserve_dsb(16 * 1024 * 1024).unwrap();
    assert!(matches!(again.reserve_dsb(4096), Err(FsError::OutOfMemory)));
    let other = b.reserve_dsb(4096).unwrap();
    assert_eq!(full.start, other.start);
    drop(full);
    let free = a.reserve_dsb(4096).unwrap();
    assert_eq!(free.start, other.start);
    assert!(matches!(
        Ledger::for_bar(u64::MAX, GGTT_ARRAY_BASE),
        Err(FsError::NoDevice)
    ));
    let small = Ledger::for_bar(u64::MAX - 1, GGTT_ARRAY_BASE + 8).unwrap();
    assert!(!small.allows(Kind::Gt, 256 * 1024 * 1024, 4096));
    assert!(matches!(small.reserve_dsb(4096), Err(FsError::Unsupported)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_dsb_ggtt_ledger_exclusive_fixed_idempotent_and_per_bar
);

fn smoke_dsb_inherited_stream_and_pte_refusal_precede_command_exposure() -> TestResult {
    for (register, value) in [
        (reg(0, 8), ENABLE),
        (reg(1, 8), BUSY),
        (reg(0, 4), 64),
        (reg(1, 0x3c), 1 << 23),
        (GGTT_ARRAY_BASE + 144 * 1024 * 1024 / 4096 * 8, 1),
    ] {
        let p = MockPlatform::new();
        p.set(register, value);
        assert!(matches!(
            Owner::reserve(p.clone(), 0x1000000),
            Err(FsError::Unsupported)
        ));
        assert!(p.dsb_writes().is_empty());
        assert_eq!(p.palette_writes(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_dsb_inherited_stream_and_pte_refusal_precede_command_exposure
);

fn smoke_dsb_native_chain_leaf_completion_preserves_irqs_and_reuses_same_pages() -> TestResult {
    let p = MockPlatform::new();
    let t = p.dsb_timing();
    p.set(IER, 8 | (1 << 5));
    p.set(IMR, u32::MAX & !8);
    p.set(IIR, 8 | (1 << 7));
    let Some(mut owner) = transport(&p) else {
        return TestResult::Pass;
    };
    let lut: Vec<u32> = (0..1024).map(|v| v * 1024).collect();
    owner
        .arm(
            t,
            &[(0x4a480, (1 << 30) | 1), (0x49028, 1 << 31)],
            Some(&lut),
            p.now(),
        )
        .unwrap();
    let mapping = p.dsb_mappings();
    assert_eq!(mapping.len(), 8);
    assert!(!owner.poll(p.now()).unwrap());
    p.step();
    assert_eq!(
        p.read32(reg(0, 0x28)) & PROG,
        0,
        "chained source emits no PROG"
    );
    assert!(!owner.poll(p.now()).unwrap());
    assert_eq!(p.palette_writes(), 0);
    p.step();
    assert_eq!(p.palette_writes(), 1024);
    assert!(
        !owner.poll(p.now()).unwrap(),
        "frame change and palette writes are insufficient before leaf PROG"
    );
    p.step();
    assert!(owner.poll(p.now()).unwrap());
    let stops: Vec<_> = p
        .dsb_writes()
        .into_iter()
        .filter(|&(r, v)| v == 0 && (r == reg(0, 8) || r == reg(1, 8)))
        .collect();
    assert_eq!(stops, [(reg(0, 8), 0), (reg(1, 8), 0)]);
    owner.shutdown().unwrap();
    assert_eq!(p.read32(IER), 8 | (1 << 5));
    assert_eq!(p.read32(IMR), u32::MAX & !8);
    assert_eq!(p.read32(IIR) & (8 | (1 << 7)), 8 | (1 << 7));
    assert_eq!(
        p.dsb_mappings(),
        mapping,
        "retirement never rebinds or frees cached command VA"
    );
    owner.arm(t, &[(0x49028, 0)], None, p.now()).unwrap();
    for _ in 0..4 {
        if owner.poll(p.now()).unwrap() {
            break;
        }
        p.step();
    }
    assert!(owner.poll(p.now()).unwrap());
    owner.shutdown().unwrap();
    assert_eq!(p.dsb_mappings(), mapping);
    assert_eq!(p.palette_writes(), 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_dsb_native_chain_leaf_completion_preserves_irqs_and_reuses_same_pages
);

fn smoke_dsb_timing_psr_and_latency_refuse_before_mapping_or_controls() -> TestResult {
    for (register, value) in [
        (0x60800, ENABLE),
        (0x60900, ENABLE),
        (0x60420, ENABLE),
        (0x60420, 1 << 28),
        (0x60420, 1 << 27),
        (0x70008, 3 << 30 | 1 << 21),
        (0x60010, 0),
        (0x45780, u32::MAX),
        (0x45788, 8191 | (8191 << 16)),
    ] {
        let p = MockPlatform::new();
        let t = p.dsb_timing();
        let Some(mut owner) = transport(&p) else {
            return TestResult::Pass;
        };
        p.set(register, value);
        assert!(owner.arm(t, &[(0x49028, 0)], None, p.now()).is_err());
        assert!(!owner.exposed());
        assert!(p.dsb_writes().is_empty());
        assert!(p.dsb_mappings().is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_dsb_timing_psr_and_latency_refuse_before_mapping_or_controls
);

fn smoke_dsb_timeout_drop_retains_real_dma_pages_and_exclusive_lease() -> TestResult {
    let p = MockPlatform::new();
    let t = p.dsb_timing();
    let Some(mut owner) = transport(&p) else {
        return TestResult::Pass;
    };
    let object = Arc::downgrade(owner.object.as_ref().unwrap());
    let ledger = Ledger::for_bar(p.ggtt_key().unwrap(), 0x1000000).unwrap();
    let start = owner.lease.as_ref().unwrap().start;
    p.stall_dsb(0, true);
    owner.arm(t, &[(0x49028, 0)], None, p.now()).unwrap();
    let mapping = p.dsb_mappings();
    assert_eq!(owner.poll(p.now() + 1_000_000_000), Err(FsError::TimedOut));
    assert_eq!(owner.shutdown(), Err(FsError::Busy));
    drop(owner);
    assert!(object.upgrade().is_some());
    assert_eq!(p.dsb_mappings(), mapping);
    assert!(ledger.reserve_dsb(BYTES).unwrap().start >= start + BYTES);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dsb",
    smoke_dsb_timeout_drop_retains_real_dma_pages_and_exclusive_lease
);
