//! Shared-GGTT GuC TLB invalidation: the tracker and request protocol on
//! their own, then the production `SharedArena` over a RAM-backed 16 MiB BAR0
//! with current capability authority. Register and wire values follow MIT
//! Linux b90c984d: regs/xe_guc_regs.h, abi/guc_actions_abi.h,
//! xe_tlb_inval_types.h, xe_guc_tlb_inval.c and xe_guc_ct.c.

use super::*;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_rcs::{FrameBacking, GgttArena, GpuAllocator, GpuBacking, SharedArena};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, kt_assert_ne, TestResult};

const MTL: GtPlatform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
const SENTINEL: u32 = 0x5a5a_5a5a;
const INV_REGS: [u64; 4] = [0xcee8, 0xcf7c, 0xcf80, 0x38cee8];

fn done(seqno: u32) -> GuCMessage {
    GuCMessage {
        fence: 0,
        kind: 1,
        auxiliary: DONE,
        payload: alloc::vec![seqno],
    }
}

fn smoke_ggtt_tlb_wire_constants_follow_linux() -> TestResult {
    // XE_GUC_ACTION_TLB_INVALIDATION / _DONE and MAKE_INVAL_OP(GUC):
    // XE_GUC_TLB_INVAL_GUC 3 in bits 7:0, XE_GUC_TLB_INVAL_MODE_HEAVY (0) in
    // bits 15:8 and XE_GUC_TLB_INVAL_FLUSH_CACHE in bit 31.
    kt_assert_eq!(ACTION, 0x7000);
    kt_assert_eq!(DONE, 0x7001);
    kt_assert_eq!(OP_GUC & 0xff, 3);
    kt_assert_eq!((OP_GUC >> 8) & 0xff, 0);
    kt_assert_eq!(OP_GUC & !0xffff, 1 << 31);
    kt_assert_eq!(SEQNO_MAX, 0x100000);
    // HZ/4 + 2 * (SZ_4K / SZ_4K) * HZ.
    kt_assert_eq!(TIMEOUT_NS, 2_250_000_000);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_wire_constants_follow_linux
);

fn smoke_ggtt_tlb_tracker_modes_cover_and_release_in_order() -> TestResult {
    let mut tlb: Tracker<u32> = Tracker::new();
    // No GuC yet: nothing to invalidate, removals release at once.
    kt_assert_eq!(tlb.publish(), [false, false]);
    kt_assert_eq!(tlb.remove(tlb.generation(), 1), Some(1));
    // GT0 by MMIO: every update is invalidated and completes at once.
    kt_assert!(tlb.set_mode(GuCTlb::Primary, Mode::Mmio).is_empty());
    kt_assert_eq!(tlb.publish(), [true, false]);
    kt_assert_eq!(tlb.remove(tlb.generation(), 2), Some(2));
    kt_assert_eq!(tlb.pending(GuCTlb::Primary), None);
    // GT1 registers before firmware DMA: no stale entry to wait for.
    kt_assert!(tlb.set_mode(GuCTlb::Media, Mode::Mmio).is_empty());
    kt_assert_eq!(tlb.publish(), [true, true]);
    // GT0 over CT: removals wait for a covering completion.
    kt_assert!(tlb.set_mode(GuCTlb::Primary, Mode::Ct).is_empty());
    kt_assert_eq!(tlb.publish(), [false, true]);
    let first = tlb.generation();
    kt_assert_eq!(tlb.remove(first, 3), None);
    kt_assert_eq!(tlb.pending(GuCTlb::Primary), Some(first));
    kt_assert_eq!(tlb.pending(GuCTlb::Media), None);
    tlb.publish();
    let second = tlb.generation();
    kt_assert_eq!(tlb.remove(second, 4), None);
    kt_assert_eq!(tlb.retained(), 2);
    // A completion covers exactly what was published before it was sent.
    kt_assert_eq!(tlb.complete(GuCTlb::Primary, first), alloc::vec![3]);
    kt_assert_eq!(tlb.pending(GuCTlb::Primary), Some(second));
    // A completion for an unpublished generation proves nothing.
    kt_assert!(tlb.complete(GuCTlb::Primary, second + 7).is_empty());
    kt_assert_eq!(tlb.retained(), 1);
    // Another GuC's completion does not cover GT0.
    kt_assert!(tlb.complete(GuCTlb::Media, second).is_empty());
    kt_assert_eq!(tlb.complete(GuCTlb::Primary, second), alloc::vec![4]);
    kt_assert_eq!(tlb.pending(GuCTlb::Primary), None);
    kt_assert_eq!(tlb.retained(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_tracker_modes_cover_and_release_in_order
);

fn smoke_ggtt_tlb_tracker_leaving_ct_keeps_debt_until_reset() -> TestResult {
    let mut tlb: Tracker<u32> = Tracker::new();
    kt_assert!(tlb.set_mode(GuCTlb::Primary, Mode::Ct).is_empty());
    tlb.publish();
    kt_assert_eq!(tlb.remove(tlb.generation(), 10), None);
    // Submission stops: MMIO again, but the CT-era debt is not discharged by
    // MMIO writes made after the switch.
    kt_assert!(tlb.set_mode(GuCTlb::Primary, Mode::Mmio).is_empty());
    kt_assert_eq!(tlb.publish(), [true, false]);
    kt_assert_eq!(tlb.remove(tlb.generation(), 11), None);
    kt_assert_eq!(tlb.pending(GuCTlb::Primary), None, "MMIO mode sends no CT");
    kt_assert_eq!(tlb.retained(), 2);
    // Proven GuC reset (xe_tlb_inval_reset) releases everything, in order,
    // and the stopped GuC leaves the client set: no MMIO without its wake.
    kt_assert_eq!(tlb.reset(GuCTlb::Primary), alloc::vec![10, 11]);
    kt_assert_eq!(tlb.mode(GuCTlb::Primary), Mode::Off);
    kt_assert_eq!(tlb.publish(), [false, false]);
    kt_assert_eq!(tlb.remove(tlb.generation(), 12), Some(12));
    // A new boot registers again, caught up.
    kt_assert!(tlb.set_mode(GuCTlb::Primary, Mode::Mmio).is_empty());
    kt_assert_eq!(tlb.publish(), [true, false]);
    kt_assert_eq!(tlb.remove(tlb.generation(), 14), Some(14));
    // Unregistration after a proven stop releases what only GT1 owed.
    kt_assert!(tlb.set_mode(GuCTlb::Media, Mode::Mmio).is_empty());
    kt_assert!(tlb.set_mode(GuCTlb::Media, Mode::Ct).is_empty());
    tlb.publish();
    kt_assert_eq!(tlb.remove(tlb.generation(), 13), None);
    kt_assert_eq!(tlb.set_mode(GuCTlb::Media, Mode::Off), alloc::vec![13]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_tracker_leaving_ct_keeps_debt_until_reset
);

fn smoke_ggtt_tlb_request_seqno_done_and_timeout() -> TestResult {
    let mut inval = Inval::new();
    // xe_gt_tlb_inval_init_early: the first seqno is 1.
    kt_assert_eq!(inval.candidate(|_| false), 1);
    // A live per-context stamp is never reused as a GGTT seqno.
    kt_assert_eq!(inval.candidate(|s| s == 1 || s == 2), 3);
    kt_assert!(inval.issued(1, 5, 100).is_ok());
    kt_assert_eq!(inval.inflight_seqno(), Some(1));
    // One request in flight per GuC.
    kt_assert!(inval.issued(2, 6, 100).is_err());
    // Only an exact DONE event for the in-flight seqno matches.
    let mut wrong_kind = done(1);
    wrong_kind.kind = 0;
    let mut long = done(1);
    long.payload.push(0);
    let mut data0 = done(1);
    data0.auxiliary |= 1 << 16;
    for message in [done(2), wrong_kind, long, data0] {
        kt_assert_eq!(inval.done(&message), None);
    }
    kt_assert_eq!(inval.inflight_seqno(), Some(1));
    // tlb_inval_timeout_delay counts from issue, inclusive at the bound.
    kt_assert!(!inval.expired(100 + TIMEOUT_NS - 1));
    kt_assert!(inval.expired(100 + TIMEOUT_NS));
    kt_assert_eq!(inval.done(&done(1)), Some(5));
    kt_assert_eq!(inval.inflight_seqno(), None);
    kt_assert!(!inval.expired(u64::MAX));
    // A repeated DONE has no owner.
    kt_assert_eq!(inval.done(&done(1)), None);
    // xe_tlb_inval_fence_prep: wrap at TLB_INVALIDATION_SEQNO_MAX, skip 0.
    kt_assert_eq!(inval.candidate(|_| false), 2);
    kt_assert!(inval.issued(SEQNO_MAX - 1, 7, 0).is_ok());
    kt_assert_eq!(inval.done(&done(SEQNO_MAX - 1)), Some(7));
    kt_assert_eq!(inval.candidate(|_| false), 1);
    // Refusals leave no request behind.
    kt_assert!(inval.issued(0, 8, 0).is_err());
    kt_assert!(inval.issued(SEQNO_MAX, 8, 0).is_err());
    kt_assert!(inval.issued(1, 8, u64::MAX).is_err());
    kt_assert_eq!(inval.inflight_seqno(), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_request_seqno_done_and_timeout
);

/// A RAM-backed 16 MiB BAR0. `key` is a fixture-unique GGTT ledger key;
/// no real device sits there.
struct RamBar {
    /// Owns the memory `region` points at; only reached through `region`.
    _words: alloc::vec::Vec<u32>,
    region: narf_bus::bar::MmioRegion,
}

impl RamBar {
    fn new(key: u64) -> Self {
        let mut words = alloc::vec![0u32; 4 * 1024 * 1024];
        let region = narf_bus::bar::MmioRegion {
            phys: narf_memory::PhysAddr::new(key),
            virt: words.as_mut_ptr() as u64,
            len: 16 << 20,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        };
        let bar = Self {
            _words: words,
            region,
        };
        for reg in INV_REGS {
            bar.store(reg, SENTINEL);
        }
        bar
    }
    fn load(&self, reg: u64) -> u32 {
        // SAFETY: `_words` backs the whole fixture BAR and outlives every
        // arena built over it. The aligned offset selects an in-bounds dword.
        unsafe { core::ptr::read_volatile((self.region.virt + reg) as *const u32) }
    }
    fn store(&self, reg: u64, value: u32) {
        // SAFETY: as `load`; no arena operation runs concurrently.
        unsafe { core::ptr::write_volatile((self.region.virt + reg) as *mut u32, value) }
    }
    fn rearm(&self) {
        for reg in INV_REGS {
            self.store(reg, SENTINEL);
        }
    }
    /// The invalidation registers written since the last rearm.
    fn written(&self) -> alloc::vec::Vec<(u64, u32)> {
        INV_REGS
            .into_iter()
            .map(|reg| (reg, self.load(reg)))
            .filter(|(_, value)| *value != SENTINEL)
            .collect()
    }
}

fn pte(backing: &FrameBacking) -> u64 {
    crate::intel_gpu_gtt::GGTT_ARRAY_BASE + u64::from(backing.ggtt_offset()) / 4096 * 8
}

/// An authorized GT arena whose cache policy is configured on a one-page seed,
/// as GT0's hardware owner does before firmware DMA.
fn configured(bar: &RamBar, platform: GtPlatform) -> (SharedArena, FrameBacking) {
    let cap =
        narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    let arena = SharedArena::new(GgttArena::for_gt(bar.region, cap, platform));
    let mut seed = arena.clone().alloc(1).expect("fixture seed page");
    let policy = crate::intel_gpu_gt_hw::CachePolicy {
        platform,
        ggtt_pat: 3,
        media: None,
    };
    arena
        .configure_cache(&mut seed, policy)
        .expect("fixture cache policy");
    (arena, seed)
}

/// Option-off GT0 behaviour: every authorized GuC arena now invalidates GT0's
/// GuC TLB after each PTE publication and clear, as xe_ggtt_invalidate does,
/// by GUC_TLB_INV_CR before Xe2 and PVC_GUC_TLB_INV_DESC1/DESC0 from Xe2.
/// The legacy execlist arena drives no GuC and writes neither register.
fn smoke_ggtt_tlb_arena_gt0_mmio_every_update_per_platform() -> TestResult {
    let cases: [(GtPlatform, u64, &[(u64, u32)]); 4] = [
        (MTL, 0x6_e000_0000, &[(0xcee8, 1)]),
        (GtPlatform::Alchemist, 0x6_e100_0000, &[(0xcee8, 1)]),
        (
            GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
            0x6_e200_0000,
            &[(0xcee8, 1)],
        ),
        (
            GtPlatform::Battlemage,
            0x6_e300_0000,
            &[(0xcf7c, 1), (0xcf80, 1 << 6)],
        ),
    ];
    for (platform, key, expected) in cases {
        let bar = RamBar::new(key);
        let cap =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let arena = SharedArena::new(GgttArena::for_gt(bar.region, cap, platform));
        let mut alloc = arena.clone();
        kt_assert_eq!(arena.guc_tlb_mode(GuCTlb::Primary), Mode::Mmio);
        kt_assert_eq!(arena.guc_tlb_mode(GuCTlb::Media), Mode::Off);
        // Before the cache policy nothing is published, so nothing is
        // invalidated.
        let Ok(mut seed) = alloc.alloc(1) else {
            return TestResult::Fail("fixture arena refused its seed page");
        };
        kt_assert_eq!(bar.load(pte(&seed)), 0);
        kt_assert!(bar.written().is_empty());
        let policy = crate::intel_gpu_gt_hw::CachePolicy {
            platform,
            ggtt_pat: 3,
            media: None,
        };
        kt_assert!(arena.configure_cache(&mut seed, policy).is_ok());
        kt_assert_ne!(bar.load(pte(&seed)), 0);
        kt_assert_eq!(bar.written().as_slice(), expected);
        bar.rearm();
        let Ok(second) = alloc.alloc(2) else {
            return TestResult::Fail("fixture arena refused a mapped allocation");
        };
        kt_assert_eq!(bar.written().as_slice(), expected);
        bar.rearm();
        let cleared = pte(&second);
        alloc.free(second);
        kt_assert_eq!(bar.load(cleared), 0);
        kt_assert_eq!(bar.written().as_slice(), expected);
        // MMIO invalidation completes at once: nothing is retained.
        kt_assert!(arena.guc_tlb_retained().is_empty());
        kt_assert_eq!(arena.guc_tlb_pending(GuCTlb::Primary), None);
        alloc.free(seed);
        kt_assert_eq!(arena.live_allocations(), 0);
        drop((arena, alloc));
        drop(bar);
    }
    // The legacy execlist arena (no authority) has no GuC client.
    let bar = RamBar::new(0x6_e400_0000);
    let mut legacy = SharedArena::new(GgttArena::new(bar.region));
    kt_assert_eq!(legacy.guc_tlb_mode(GuCTlb::Primary), Mode::Off);
    let Ok(page) = legacy.alloc(1) else {
        return TestResult::Fail("legacy arena refused a page");
    };
    kt_assert_ne!(bar.load(pte(&page)), 0);
    legacy.free(page);
    kt_assert!(bar.written().is_empty());
    kt_assert!(legacy.set_guc_tlb_ct(GuCTlb::Primary, true).is_err());
    kt_assert_eq!(legacy.live_allocations(), 0);
    drop(legacy);
    drop(bar);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_arena_gt0_mmio_every_update_per_platform
);

/// GT0 in CT mode: a cleared range keeps its frames and stays out of the
/// first-fit free list until the covering TLB_INVALIDATION_DONE.
fn smoke_ggtt_tlb_arena_gt0_ct_removal_blocks_reuse_until_done() -> TestResult {
    let bar = RamBar::new(0x6_e500_0000);
    let (arena, seed) = configured(&bar, MTL);
    let mut alloc = arena.clone();
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Primary, true).is_ok());
    kt_assert_eq!(arena.guc_tlb_mode(GuCTlb::Primary), Mode::Ct);
    let Ok(first) = alloc.alloc(2) else {
        return TestResult::Fail("fixture arena refused the first range");
    };
    let range = (first.ggtt_offset(), 2);
    let cleared = pte(&first);
    let live = arena.live_allocations();
    bar.rearm();
    alloc.free(first);
    // PTEs are cleared at once, but no MMIO invalidation in CT mode and the
    // range is retained with its frames.
    kt_assert_eq!(bar.load(cleared), 0);
    kt_assert!(bar.written().is_empty());
    kt_assert_eq!(arena.guc_tlb_retained(), alloc::vec![range]);
    kt_assert_eq!(arena.live_allocations(), live);
    let Some(removal) = arena.guc_tlb_pending(GuCTlb::Primary) else {
        return TestResult::Fail("a CT-mode removal must leave an invalidation pending");
    };
    // First fit cannot hand the retained range out again.
    let Ok(other) = alloc.alloc(2) else {
        return TestResult::Fail("fixture arena refused a second range");
    };
    kt_assert_ne!(other.ggtt_offset(), range.0);
    kt_assert!(arena.guc_tlb_pending(GuCTlb::Primary) > Some(removal));
    // A completion issued before the removal proves nothing about it.
    arena.guc_tlb_complete(GuCTlb::Primary, removal - 1);
    kt_assert_eq!(arena.guc_tlb_retained(), alloc::vec![range]);
    // The covering completion releases it, and first fit reuses it.
    arena.guc_tlb_complete(GuCTlb::Primary, removal);
    kt_assert!(arena.guc_tlb_retained().is_empty());
    kt_assert_eq!(arena.live_allocations(), live);
    let Ok(again) = alloc.alloc(2) else {
        return TestResult::Fail("released range was not reusable");
    };
    kt_assert_eq!(again.ggtt_offset(), range.0);
    // Back to MMIO with nothing outstanding: removal completes at once.
    let newest = arena.guc_tlb_pending(GuCTlb::Primary).unwrap_or(0);
    arena.guc_tlb_complete(GuCTlb::Primary, newest);
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Primary, false).is_ok());
    for backing in [again, other, seed] {
        alloc.free(backing);
    }
    kt_assert!(arena.guc_tlb_retained().is_empty());
    kt_assert_eq!(bar.written().as_slice(), &[(0xcee8, 1)]);
    kt_assert_eq!(arena.live_allocations(), 0);
    drop((arena, alloc));
    drop(bar);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_arena_gt0_ct_removal_blocks_reuse_until_done
);

/// A CT invalidation that never completes (timeout, lost GT, stop that
/// cannot be proven) keeps every range it covers. Returning to MMIO does not
/// discharge that debt. Only the proven GuC reset releases it.
fn smoke_ggtt_tlb_arena_unproven_stop_retains_until_reset_proof() -> TestResult {
    let bar = RamBar::new(0x6_e600_0000);
    let (arena, seed) = configured(&bar, MTL);
    let mut alloc = arena.clone();
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Primary, true).is_ok());
    let (Ok(first), Ok(second)) = (alloc.alloc(1), alloc.alloc(3)) else {
        return TestResult::Fail("fixture arena refused its ranges");
    };
    let ranges = alloc::vec![(first.ggtt_offset(), 1), (second.ggtt_offset(), 3)];
    alloc.free(first);
    kt_assert_eq!(arena.guc_tlb_retained().len(), 1);
    // Begin stop: submission off, MMIO again.
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Primary, false).is_ok());
    bar.rearm();
    alloc.free(second);
    kt_assert_eq!(bar.written().as_slice(), &[(0xcee8, 1)]);
    kt_assert_eq!(arena.guc_tlb_retained(), ranges);
    kt_assert_eq!(arena.guc_tlb_pending(GuCTlb::Primary), None);
    // A late completion for an older generation still proves nothing new.
    arena.guc_tlb_complete(GuCTlb::Primary, 1);
    kt_assert_eq!(arena.guc_tlb_retained(), ranges);
    // GuC reset proven (MIA in reset, DMA idle): xe_tlb_inval_reset. The
    // stopped GuC leaves the client set, so later updates write no register.
    arena.guc_tlb_reset(GuCTlb::Primary);
    kt_assert!(arena.guc_tlb_retained().is_empty());
    kt_assert_eq!(arena.guc_tlb_mode(GuCTlb::Primary), Mode::Off);
    let Ok(reused) = alloc.alloc(1) else {
        return TestResult::Fail("released range was not reusable");
    };
    kt_assert_eq!(reused.ggtt_offset(), ranges[0].0);
    bar.rearm();
    alloc.free(reused);
    alloc.free(seed);
    kt_assert!(bar.written().is_empty());
    kt_assert!(arena.guc_tlb_retained().is_empty());
    kt_assert_eq!(arena.live_allocations(), 0);
    drop((arena, alloc));
    drop(bar);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_arena_unproven_stop_retains_until_reset_proof
);

/// MTL with the media GuC registered: xe_ggtt_invalidate reaches both GTs.
/// A removal is released only when every GuC that may cache it has
/// invalidated, whichever transport each uses.
fn smoke_ggtt_tlb_arena_gt0_and_media_both_cover_before_release() -> TestResult {
    let bar = RamBar::new(0x6_e700_0000);
    let (arena, seed) = configured(&bar, MTL);
    let mut alloc = arena.clone();
    kt_assert!(arena.set_media_guc_tlb(true).is_ok());
    // Both MMIO: both registers, immediate release.
    let Ok(both_mmio) = alloc.alloc(1) else {
        return TestResult::Fail("fixture arena refused a page");
    };
    bar.rearm();
    alloc.free(both_mmio);
    kt_assert_eq!(bar.written().as_slice(), &[(0xcee8, 1), (0x38cee8, 1)]);
    kt_assert!(arena.guc_tlb_retained().is_empty());
    // Media over CT, GT0 by MMIO: GT0's register only, held for GT1.
    kt_assert!(arena.set_media_guc_submission(true).is_ok());
    let Ok(media_ct) = alloc.alloc(1) else {
        return TestResult::Fail("fixture arena refused a page");
    };
    let held = (media_ct.ggtt_offset(), 1);
    bar.rearm();
    alloc.free(media_ct);
    kt_assert_eq!(bar.written().as_slice(), &[(0xcee8, 1)]);
    kt_assert_eq!(arena.guc_tlb_retained(), alloc::vec![held]);
    kt_assert_eq!(arena.guc_tlb_pending(GuCTlb::Primary), None);
    let Some(media_gen) = arena.guc_tlb_pending(GuCTlb::Media) else {
        return TestResult::Fail("media CT removal left nothing pending");
    };
    arena.guc_tlb_complete(GuCTlb::Primary, media_gen);
    kt_assert_eq!(arena.guc_tlb_retained(), alloc::vec![held]);
    arena.guc_tlb_complete(GuCTlb::Media, media_gen);
    kt_assert!(arena.guc_tlb_retained().is_empty());
    // Both over CT: either completion alone is not enough.
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Primary, true).is_ok());
    let Ok(both_ct) = alloc.alloc(2) else {
        return TestResult::Fail("fixture arena refused a range");
    };
    let held = (both_ct.ggtt_offset(), 2);
    bar.rearm();
    alloc.free(both_ct);
    kt_assert!(bar.written().is_empty());
    let (Some(gt0), Some(gt1)) = (
        arena.guc_tlb_pending(GuCTlb::Primary),
        arena.guc_tlb_pending(GuCTlb::Media),
    ) else {
        return TestResult::Fail("both CT GuCs must owe the removal");
    };
    arena.guc_tlb_complete(GuCTlb::Media, gt1);
    kt_assert_eq!(arena.guc_tlb_retained(), alloc::vec![held]);
    arena.guc_tlb_complete(GuCTlb::Primary, gt0);
    kt_assert!(arena.guc_tlb_retained().is_empty());
    // GT0 back to MMIO with nothing owed. GT1 then owes a removal, and its
    // proven stop unregisters it.
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Primary, false).is_ok());
    let Ok(last) = alloc.alloc(1) else {
        return TestResult::Fail("fixture arena refused a page");
    };
    alloc.free(last);
    kt_assert_eq!(arena.guc_tlb_pending(GuCTlb::Primary), None);
    kt_assert_eq!(arena.guc_tlb_retained().len(), 1);
    kt_assert!(arena.set_media_guc_tlb(false).is_ok());
    kt_assert!(arena.guc_tlb_retained().is_empty());
    kt_assert_eq!(arena.guc_tlb_mode(GuCTlb::Media), Mode::Off);
    // An unregistered GuC has no transport to switch.
    kt_assert!(arena.set_guc_tlb_ct(GuCTlb::Media, true).is_err());
    alloc.free(seed);
    kt_assert_eq!(arena.live_allocations(), 0);
    drop((arena, alloc));
    drop(bar);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_ggtt_tlb",
    smoke_ggtt_tlb_arena_gt0_and_media_both_cover_before_release
);
