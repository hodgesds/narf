use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

static A: AtomicUsize = AtomicUsize::new(0);
static B: AtomicUsize = AtomicUsize::new(0);
fn retain_a(phys: u64) -> bool {
    if phys != 0xa000 {
        return false;
    }
    A.fetch_add(1, Ordering::AcqRel);
    true
}
fn release_a(phys: u64) -> bool {
    if phys != 0xa000 {
        return false;
    }
    assert_ne!(A.fetch_sub(1, Ordering::AcqRel), 0);
    true
}
fn retain_b(phys: u64) -> bool {
    if phys != 0xb000 {
        return false;
    }
    B.fetch_add(1, Ordering::AcqRel);
    true
}
fn release_b(phys: u64) -> bool {
    if phys != 0xb000 {
        return false;
    }
    assert_ne!(B.fetch_sub(1, Ordering::AcqRel), 0);
    true
}
fn unused(_: u64) -> bool {
    false
}

fn smoke_device_alias_providers_are_bounded_immutable_and_disjoint() -> TestResult {
    let mut registry = AliasRegistry::new();
    registry.register(retain_a, release_a).unwrap();
    registry.register(retain_b, release_b).unwrap();
    registry.register(retain_a, release_a).unwrap();
    assert_eq!(registry.hooks.iter().flatten().count(), 2);
    assert_eq!(
        registry.register(retain_a, release_b),
        Err(FsError::InvalidData)
    );
    A.store(0, Ordering::Release);
    B.store(0, Ordering::Release);
    for phys in [0xa000, 0xb000, 0xa000] {
        assert!(registry
            .hooks
            .into_iter()
            .flatten()
            .any(|(retain, _)| retain(phys)));
    }
    assert!(!registry
        .hooks
        .into_iter()
        .flatten()
        .any(|(retain, _)| retain(0xc000)));
    assert_eq!(
        (A.load(Ordering::Acquire), B.load(Ordering::Acquire)),
        (2, 1)
    );
    for phys in [0xb000, 0xa000, 0xa000] {
        assert!(registry
            .hooks
            .into_iter()
            .flatten()
            .any(|(_, release)| release(phys)));
    }
    assert_eq!(
        (A.load(Ordering::Acquire), B.load(Ordering::Acquire)),
        (0, 0)
    );
    // Exercise the production fixed-capacity branch without consuming global
    // card-lifetime slots or registering a provider which claims fake frames.
    registry.hooks.fill(Some((unused, unused)));
    assert_eq!(registry.register(unused, unused), Ok(()));
    assert_eq!(
        registry.register(retain_a, release_a),
        Err(FsError::NoSpace)
    );
    assert_eq!(registry.hooks.iter().flatten().count(), MAX_ALIAS_PROVIDERS);
    TestResult::Pass
}
kernel_test_in!(
    "filesystem",
    smoke_device_alias_providers_are_bounded_immutable_and_disjoint
);
