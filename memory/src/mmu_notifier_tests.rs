//! Interval-notifier smokes (`crate::mmu_notifier`): registration and range
//! filtering, the read_begin/read_retry protocol, every firing address-space
//! operation, invalidation before frame release, fork/COW, exit, migration,
//! and the reader interleavings the sequence protocol must catch.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::address_space::{AddressSpace, MremapLimits, Region, RegionPerms, ZapOutcome};
use crate::frame::cow;
use crate::mmu_notifier::{
    registered_intervals, MmuInterval, MmuIntervalNotifier, MmuIntervalNotifierOps,
    MmuNotifierError, MmuNotifierEvent, MmuNotifierRange,
};
use crate::{PhysAddr, VirtAddr};

const PAGE: u64 = 0x1000;
const LOG: usize = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Seen {
    event: MmuNotifierEvent,
    start: u64,
    end: u64,
    cur_seq: u64,
    /// The interval's sequence observed inside the callback.
    stored_seq: u64,
    blockable: bool,
    /// `cow::count` of the sampled frame inside the callback.
    frame_refs: u32,
}

/// Records invalidations without allocating: the callback runs with the
/// address space's IRQ-masked locks held. Its own lock is a leaf lock.
struct Recorder {
    calls: AtomicUsize,
    seen: IrqSafeSpinLock<[Option<Seen>; LOG]>,
    sample: AtomicU64,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: IrqSafeSpinLock::new([None; LOG]),
            sample: AtomicU64::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn nth(&self, index: usize) -> Option<Seen> {
        self.seen.lock().get(index).copied().flatten()
    }

    fn last(&self) -> Option<Seen> {
        self.calls()
            .checked_sub(1)
            .and_then(|index| self.nth(index))
    }
}

impl MmuIntervalNotifierOps for Recorder {
    fn invalidate(&self, interval: &MmuInterval, range: &MmuNotifierRange, cur_seq: u64) {
        let frame = self.sample.load(Ordering::SeqCst);
        let seen = Seen {
            event: range.event,
            start: range.start,
            end: range.end,
            cur_seq,
            stored_seq: interval.read_begin(),
            blockable: range.blockable(),
            frame_refs: if frame == 0 {
                0
            } else {
                cow::count(PhysAddr::new(frame))
            },
        };
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        if index < LOG {
            self.seen.lock()[index] = Some(seen);
        }
    }
}

fn lazy(base: u64, pages: u64, perms: RegionPerms) -> Region {
    Region {
        base: VirtAddr::new(base),
        len: pages * PAGE,
        perms,
        phys: alloc::vec![PhysAddr::new(0); pages as usize].into(),
    }
}

fn va(base: u64, page: u64) -> VirtAddr {
    VirtAddr::new(base + page * PAGE)
}

fn watch(
    space: &AddressSpace,
    start: u64,
    len: u64,
    recorder: &Arc<Recorder>,
) -> MmuIntervalNotifier {
    MmuIntervalNotifier::insert(space, start, len, recorder.clone()).expect("interval insert")
}

/// The callback saw `event` over `[start, end)` with the sequence already
/// published and in non-blocking context.
fn saw(seen: Option<Seen>, event: MmuNotifierEvent, start: u64, end: u64) -> bool {
    seen.is_some_and(|seen| {
        seen.event == event
            && seen.start == start
            && seen.end == end
            && seen.cur_seq & 1 == 1
            && seen.stored_seq == seen.cur_seq
            && !seen.blockable
    })
}

fn smoke_mmu_notifier_registration_range_filter_and_removal() -> TestResult {
    const BASE: u64 = 0x0000_0080_6e00_0000;
    let baseline = registered_intervals();
    let a = AddressSpace::empty();
    let b = AddressSpace::empty();
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    if a.map_region(lazy(BASE, 8, rw)).is_err() || b.map_region(lazy(BASE, 8, rw)).is_err() {
        return TestResult::Fail("fixture regions");
    }
    for (start, len) in [
        (BASE, 0),
        (u64::MAX - PAGE + 1, 2 * PAGE),
        (AddressSpace::USER_HALF_END - PAGE, 2 * PAGE),
    ] {
        if !matches!(
            MmuIntervalNotifier::insert(&a, start, len, Recorder::new()),
            Err(MmuNotifierError::InvalidRange)
        ) {
            return TestResult::Fail("empty/overflowing/kernel-half interval was accepted");
        }
    }
    if registered_intervals() != baseline {
        return TestResult::Fail("a refused insert left a registration");
    }
    let (first, second, other) = (Recorder::new(), Recorder::new(), Recorder::new());
    let n1 = watch(&a, BASE + 2 * PAGE, 2 * PAGE, &first);
    let n2 = watch(&a, BASE + 6 * PAGE, PAGE, &second);
    let nb = watch(&b, BASE, 8 * PAGE, &other);
    if registered_intervals() != baseline + 3
        || n2.start() != BASE + 6 * PAGE
        || n2.end() != BASE + 7 * PAGE
        || n2.address_space_id() != a.identity()
        || nb.address_space_id() != b.identity()
        || n1.is_released()
    {
        return TestResult::Fail("interval accessors or registry census");
    }
    // A punch outside both intervals fires nothing; one inside the first
    // fires it alone, with the operation's range, and never the other space.
    if a.punch_fixed(va(BASE, 0), PAGE).is_err() {
        return TestResult::Fail("disjoint punch");
    }
    if first.calls() + second.calls() + other.calls() != 0 {
        return TestResult::Fail("a disjoint unmap fired an interval");
    }
    if a.punch_fixed(va(BASE, 3), PAGE).is_err() {
        return TestResult::Fail("overlapping punch");
    }
    if first.calls() != 1
        || !saw(
            first.last(),
            MmuNotifierEvent::Unmap,
            BASE + 3 * PAGE,
            BASE + 4 * PAGE,
        )
        || second.calls() != 0
        || other.calls() != 0
    {
        return TestResult::Fail("overlap filter or address-space filter");
    }
    // Removal: no callback for the dropped interval afterwards.
    drop(n1);
    if a.punch_fixed(va(BASE, 2), PAGE).is_err() || first.calls() != 1 {
        return TestResult::Fail("a removed interval was still invalidated");
    }
    drop(n2);
    drop(nb);
    if registered_intervals() != baseline {
        return TestResult::Fail("removal leaked a registration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_mmu_notifier_registration_range_filter_and_removal
);

/// Intervals inserted out of order are all found by a range that overlaps
/// them and only them, and one address space cannot register more than
/// `MAX_INTERVALS_PER_SPACE` while another still can.
fn smoke_mmu_notifier_sorted_scan_and_per_space_cap() -> TestResult {
    use crate::mmu_notifier::MAX_INTERVALS_PER_SPACE;
    const BASE: u64 = 0x0000_0080_6f00_0000;
    let baseline = registered_intervals();
    let a = AddressSpace::empty();
    let b = AddressSpace::empty();
    if a.map_region(lazy(BASE, 16, RegionPerms::READ)).is_err() {
        return TestResult::Fail("fixture region");
    }
    let recorders = [Recorder::new(), Recorder::new(), Recorder::new()];
    // Starts 8, 2 and 5 pages, inserted in that order.
    let watched: alloc::vec::Vec<_> = [8u64, 2, 5]
        .iter()
        .zip(&recorders)
        .map(|(&page, recorder)| watch(&a, BASE + page * PAGE, 2 * PAGE, recorder))
        .collect();
    // [4, 7) overlaps only the interval at [5, 7).
    if a.madvise_dontneed(va(BASE, 4), 3 * PAGE).is_err()
        || recorders[0].calls() != 0
        || recorders[1].calls() != 0
        || recorders[2].calls() != 1
    {
        return TestResult::Fail("the sorted scan missed or over-matched an interval");
    }
    // [3, 9) overlaps [2, 4), [5, 7) and [8, 10).
    if a.madvise_dontneed(va(BASE, 3), 6 * PAGE).is_err()
        || recorders[0].calls() != 1
        || recorders[1].calls() != 1
        || recorders[2].calls() != 2
    {
        return TestResult::Fail("an overlapping interval was skipped");
    }
    drop(watched);
    let filler = Recorder::new();
    let mut held = alloc::vec::Vec::new();
    if held.try_reserve_exact(MAX_INTERVALS_PER_SPACE).is_err() {
        return TestResult::Skip("census vector allocation");
    }
    for index in 0..MAX_INTERVALS_PER_SPACE as u64 {
        match MmuIntervalNotifier::insert(&a, BASE + (index % 64) * PAGE, PAGE, filler.clone()) {
            Ok(notifier) => held.push(notifier),
            Err(_) => return TestResult::Skip("registry growth under memory pressure"),
        }
    }
    let over = MmuIntervalNotifier::insert(&a, BASE, PAGE, filler.clone());
    let other = MmuIntervalNotifier::insert(&b, BASE, PAGE, filler.clone());
    if !matches!(over, Err(MmuNotifierError::OutOfMemory)) || other.is_err() {
        return TestResult::Fail("the per-space cap did not hold or leaked to another space");
    }
    drop(other);
    drop(held);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_mmu_notifier_sorted_scan_and_per_space_cap);

fn smoke_mmu_notifier_seq_read_begin_retry_protocol() -> TestResult {
    const BASE: u64 = 0x0000_0080_6e10_0000;
    let baseline = registered_intervals();
    let a = AddressSpace::empty();
    if a.map_region(lazy(BASE, 4, RegionPerms::READ | RegionPerms::WRITE))
        .is_err()
    {
        return TestResult::Fail("fixture region");
    }
    let recorder = Recorder::new();
    let n = watch(&a, BASE, 4 * PAGE, &recorder);
    let s0 = n.read_begin();
    if n.read_retry(s0) || n.check_retry(s0) {
        return TestResult::Fail("retry without an invalidation");
    }
    if a.madvise_dontneed(va(BASE, 1), PAGE).is_err() {
        return TestResult::Fail("MADV_DONTNEED");
    }
    let Some(first) = recorder.last() else {
        return TestResult::Fail("MADV_DONTNEED did not fire");
    };
    if !n.read_retry(s0) || !n.check_retry(s0) {
        return TestResult::Fail("a section spanning an invalidation did not retry");
    }
    let s1 = n.read_begin();
    if s1 != first.cur_seq || n.read_retry(s1) {
        return TestResult::Fail("read_begin after the invalidation is not current");
    }
    // set_seq is the Linux-shaped consumer store; repeating the registry's
    // value is idempotent.
    n.set_seq(s1);
    if n.read_retry(s1) {
        return TestResult::Fail("set_seq of the current sequence forced a retry");
    }
    if a.madvise_dontneed(va(BASE, 2), PAGE).is_err() {
        return TestResult::Fail("second MADV_DONTNEED");
    }
    let Some(second) = recorder.last() else {
        return TestResult::Fail("second invalidation missing");
    };
    if recorder.calls() != 2
        || second.cur_seq <= first.cur_seq
        || !n.read_retry(s1)
        || !saw(
            Some(second),
            MmuNotifierEvent::Clear,
            BASE + 2 * PAGE,
            BASE + 3 * PAGE,
        )
    {
        return TestResult::Fail("each invalidation must publish a fresh sequence");
    }
    drop(n);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_mmu_notifier_seq_read_begin_retry_protocol);

/// Region-table operations of `munmap`, `mprotect`, `MADV_DONTNEED`, the
/// truncate zap, `MADV_GUARD_INSTALL`, `mremap` and `MREMAP_DONTUNMAP` each
/// fire with their Linux event; upgrades and operations outside the interval
/// do not fire.
fn smoke_mmu_notifier_fires_for_each_mapping_operation() -> TestResult {
    use MmuNotifierEvent::{Clear, ProtectionVma, Unmap};
    const BASE: u64 = 0x0000_0080_6e20_0000;
    const MOVED: u64 = BASE + 0x40 * PAGE;
    const KEPT: u64 = BASE + 0x80 * PAGE;
    let baseline = registered_intervals();
    let a = AddressSpace::empty();
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    if a.map_region(lazy(BASE, 16, rw)).is_err() {
        return TestResult::Fail("fixture region");
    }
    let r = Recorder::new();
    let n = watch(&a, BASE, 16 * PAGE, &r);
    let step = |calls: usize, event, start: u64, end: u64| {
        r.calls() == calls && saw(r.last(), event, start, end)
    };

    // munmap splitting the VMA.
    if a.punch_fixed(va(BASE, 15), PAGE).is_err()
        || !step(1, Unmap, BASE + 15 * PAGE, BASE + 16 * PAGE)
    {
        return TestResult::Fail("munmap split");
    }
    // mprotect: removing WRITE fires; restoring it does not.
    if a.mprotect_range(va(BASE, 0), 2 * PAGE, RegionPerms::READ)
        .is_err()
        || !step(2, ProtectionVma, BASE, BASE + 2 * PAGE)
    {
        return TestResult::Fail("mprotect downgrade");
    }
    if a.mprotect_range(va(BASE, 0), 2 * PAGE, rw).is_err() || r.calls() != 2 {
        return TestResult::Fail("mprotect upgrade fired");
    }
    if a.mprotect_range(va(BASE, 0), 2 * PAGE, RegionPerms::READ)
        .is_err()
        || !step(3, ProtectionVma, BASE, BASE + 2 * PAGE)
    {
        return TestResult::Fail("second mprotect downgrade");
    }
    // Whole-VMA change_perms_range: same rule.
    if a.change_perms_range(va(BASE, 2), 13 * PAGE, RegionPerms::READ)
        .is_err()
        || !step(4, ProtectionVma, BASE + 2 * PAGE, BASE + 15 * PAGE)
    {
        return TestResult::Fail("change_perms_range downgrade");
    }
    if a.change_perms_range(va(BASE, 2), 13 * PAGE, rw).is_err() || r.calls() != 4 {
        return TestResult::Fail("change_perms_range upgrade fired");
    }
    // MADV_DONTNEED and the truncate zap keep the VMA and clear pages.
    if a.madvise_dontneed(va(BASE, 3), 2 * PAGE).is_err()
        || !step(5, Clear, BASE + 3 * PAGE, BASE + 5 * PAGE)
    {
        return TestResult::Fail("MADV_DONTNEED");
    }
    let zapped = a.with_vma_transaction(|| {
        // SAFETY: the enclosing transaction is the zap's documented lock.
        unsafe { a.zap_mapping_range_locked_for_syscall_with_shared(va(BASE, 5), 2 * PAGE, false) }
    });
    if zapped != Ok(ZapOutcome::Retained) || !step(6, Clear, BASE + 5 * PAGE, BASE + 7 * PAGE) {
        return TestResult::Fail("truncate zap");
    }
    // MADV_GUARD_INSTALL fires when the markers go in, then again as its
    // private pages are released through MADV_DONTNEED.
    if a.madvise_guard_install(va(BASE, 7), PAGE).is_err()
        || r.calls() != 8
        || !saw(r.nth(6), Clear, BASE + 7 * PAGE, BASE + 8 * PAGE)
        || !saw(r.nth(7), Clear, BASE + 7 * PAGE, BASE + 8 * PAGE)
    {
        return TestResult::Fail("MADV_GUARD_INSTALL");
    }
    // mremap move: the source range is unmapped; the destination is outside
    // the interval and fires nothing more.
    // SAFETY: root-less fixture; no page table is touched.
    if unsafe { a.relocate_region(va(BASE, 8), 2 * PAGE, VirtAddr::new(MOVED), 2 * PAGE) }.is_err()
        || r.calls() != 9
    {
        return TestResult::Fail("mremap move did not fire once");
    }
    // The log holds the first eight; check the ninth through the sequence.
    let moved_seq = n.read_begin();
    if a.punch_fixed(VirtAddr::new(MOVED), 2 * PAGE).is_err()
        || r.calls() != 9
        || n.read_begin() != moved_seq
    {
        return TestResult::Fail("an unmap outside the interval fired it");
    }
    // MREMAP_DONTUNMAP keeps the (now empty) source VMA and fires on it.
    let kept = a.with_vma_transaction(|| {
        // SAFETY: root-less fixture under its VMA transaction.
        unsafe {
            a.dontunmap_region_locked_limited(
                va(BASE, 0),
                2 * PAGE,
                VirtAddr::new(KEPT),
                MremapLimits::UNLIMITED,
            )
        }
    });
    if kept.is_err() || r.calls() != 10 || n.read_begin() == moved_seq {
        return TestResult::Fail("MREMAP_DONTUNMAP");
    }
    // Whole-VMA unmap of the retained source.
    let before = n.read_begin();
    if a.unmap_region(va(BASE, 0)).is_err() || r.calls() != 11 || n.read_begin() == before {
        return TestResult::Fail("unmap_region");
    }
    drop(n);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_mmu_notifier_fires_for_each_mapping_operation
);

/// A fresh user address space with `frames` mapped read/write at `base`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn resident_space(base: u64, frames: &[PhysAddr]) -> Result<AddressSpace, TestResult> {
    // SAFETY: a fresh, inactive user address space owned by this test.
    let space = unsafe { AddressSpace::new_for_user() }
        .map_err(|_| TestResult::Skip("new_for_user unavailable"))?;
    space
        .map_region(Region {
            base: VirtAddr::new(base),
            len: frames.len() as u64 * PAGE,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: frames.to_vec().into(),
        })
        .map_err(|_| TestResult::Fail("resident fixture mapping"))?;
    // SAFETY: the inactive root is live and owns the region just mapped.
    unsafe { space.materialize() }.map_err(|_| TestResult::Fail("materialize"))?;
    Ok(space)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn frame() -> Result<PhysAddr, TestResult> {
    crate::alloc_frame()
        .map(|frame| frame.start_address())
        .map_err(|_| TestResult::Skip("frame allocator drained"))
}

/// The callback runs while the unmapped page's frame is still owned by the
/// mapping (and, when pinned, the pin): invalidation precedes release, and a
/// pinned frame is never returned to the allocator under its consumer.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_mmu_notifier_invalidates_before_frame_release() -> TestResult {
    const BASE: u64 = 0x0000_0080_6e40_0000;
    let baseline = registered_intervals();
    for pinned in [false, true] {
        let phys = match frame() {
            Ok(phys) => phys,
            Err(result) => return result,
        };
        let space = match resident_space(BASE, &[phys]) {
            Ok(space) => space,
            Err(result) => return result,
        };
        let pin = if pinned {
            match space.pin_user_page(VirtAddr::new(BASE)) {
                Some(pin) => Some(pin),
                None => return TestResult::Fail("ordinary RAM pin refused"),
            }
        } else {
            None
        };
        let recorder = Recorder::new();
        recorder.sample.store(phys.raw(), Ordering::SeqCst);
        let n = watch(&space, BASE, PAGE, &recorder);
        let mapped_refs = cow::count(phys);
        if space.punch_fixed(VirtAddr::new(BASE), PAGE).is_err() {
            return TestResult::Fail("munmap");
        }
        // Retire the deferred-unmap quarantine so the release has happened.
        space.flush_deferred();
        let Some(seen) = recorder.last() else {
            return TestResult::Fail("munmap did not fire");
        };
        if recorder.calls() != 1
            || seen.event != MmuNotifierEvent::Unmap
            || seen.frame_refs != mapped_refs
            || seen.frame_refs != 1 + u32::from(pinned)
        {
            return TestResult::Fail("the callback did not precede the frame release");
        }
        if let Some(pin) = pin {
            if cow::count(phys) != 1 || !cow::is_pinned(phys) {
                return TestResult::Fail("munmap released a pinned frame");
            }
            drop(pin);
            if cow::is_pinned(phys) {
                return TestResult::Fail("pin marker leaked");
            }
        }
        if cow::count(phys) != 0 {
            return TestResult::Fail("the unmapped frame was not released");
        }
        drop(n);
        drop(space);
    }
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_mmu_notifier_invalidates_before_frame_release
);

/// Fork neither fires nor copies the parent's intervals. A COW break in the
/// parent fires `Clear` on exactly that page; the child's COW and teardown
/// never reach the parent's interval.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_mmu_notifier_fork_cow_break_and_child_isolation() -> TestResult {
    const BASE: u64 = 0x0000_0080_6e60_0000;
    let baseline = registered_intervals();
    let (f0, f1) = match (frame(), frame()) {
        (Ok(f0), Ok(f1)) => (f0, f1),
        _ => return TestResult::Skip("frame allocator drained"),
    };
    let parent = match resident_space(BASE, &[f0, f1]) {
        Ok(space) => space,
        Err(result) => return result,
    };
    // Page 0 is pinned (fork copies it for the child); page 1 is shared COW.
    let Some(pin) = parent.pin_user_page(VirtAddr::new(BASE)) else {
        return TestResult::Fail("pin refused");
    };
    let recorder = Recorder::new();
    let n = watch(&parent, BASE, 2 * PAGE, &recorder);
    // SAFETY: the inactive parent is exclusively owned by this test.
    let child = match unsafe { parent.clone_for_fork() } {
        Ok(child) => child,
        Err(_) => return TestResult::Fail("clone_for_fork"),
    };
    if recorder.calls() != 0 || registered_intervals() != baseline + 1 {
        return TestResult::Fail("fork fired or copied an interval");
    }
    if child
        .page_backing(VirtAddr::new(BASE))
        .map(|(_, phys)| phys)
        == Some(f0)
        || parent.page_backing(va(BASE, 1)).map(|(_, phys)| phys) != Some(f1)
        || cow::count(f1) != 2
    {
        return TestResult::Fail("fork fixture shape");
    }
    // Mirror the write fault: split, then rewrite the leaf to the copy.
    // SAFETY: test-owned present COW page of the inactive parent.
    if unsafe { parent.cow_split_on_write(va(BASE, 1)) }.is_err()
        // SAFETY: same live-root contract; the split just repointed the page.
        || unsafe { parent.remap_page(va(BASE, 1)) }.is_err()
        || parent.page_backing(va(BASE, 1)).map(|(_, phys)| phys) == Some(f1)
    {
        return TestResult::Fail("parent COW break");
    }
    if recorder.calls() != 1
        || !saw(
            recorder.last(),
            MmuNotifierEvent::Clear,
            BASE + PAGE,
            BASE + 2 * PAGE,
        )
    {
        return TestResult::Fail("COW break did not fire Clear on its page");
    }
    // SAFETY: the child's page is now its sole copy; the split is a no-op.
    if unsafe { child.cow_split_on_write(va(BASE, 1)) }.is_err()
        || child.punch_fixed(VirtAddr::new(BASE), 2 * PAGE).is_err()
        || recorder.calls() != 1
    {
        return TestResult::Fail("child operations reached the parent's interval");
    }
    drop(child);
    drop(n);
    drop(pin);
    drop(parent);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_mmu_notifier_fork_cow_break_and_child_isolation
);

/// Exit (`reclaim_unshared_on_exit`) and final drop each release every
/// interval once, before the space's frames are freed.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_mmu_notifier_exit_and_drop_release_intervals() -> TestResult {
    const BASE: u64 = 0x0000_0080_6e80_0000;
    let baseline = registered_intervals();
    let phys = match frame() {
        Ok(phys) => phys,
        Err(result) => return result,
    };
    let space = match resident_space(BASE, &[phys]) {
        Ok(space) => space,
        Err(result) => return result,
    };
    let recorder = Recorder::new();
    recorder.sample.store(phys.raw(), Ordering::SeqCst);
    let n = watch(&space, BASE, PAGE, &recorder);
    // SAFETY: no task executes through this private test address space.
    if unsafe { space.reclaim_unshared_on_exit() } != 1 {
        return TestResult::Fail("exit reclaim");
    }
    if recorder.calls() != 1
        || !saw(
            recorder.last(),
            MmuNotifierEvent::Release,
            BASE,
            BASE + PAGE,
        )
        || recorder.last().is_some_and(|seen| seen.frame_refs != 1)
        || !n.is_released()
        || registered_intervals() != baseline
    {
        return TestResult::Fail("exit did not release the interval before the frame");
    }
    drop(space);
    if recorder.calls() != 1 {
        return TestResult::Fail("final drop released an interval twice");
    }
    drop(n);

    // Drop alone (exec replacement, a never-scheduled space) also releases.
    let empty = AddressSpace::empty();
    if empty
        .map_region(lazy(BASE, 1, RegionPerms::READ | RegionPerms::WRITE))
        .is_err()
    {
        return TestResult::Fail("fixture region");
    }
    let dropped = Recorder::new();
    let n = watch(&empty, BASE, PAGE, &dropped);
    drop(empty);
    if dropped.calls() != 1
        || !saw(dropped.last(), MmuNotifierEvent::Release, BASE, BASE + PAGE)
        || !n.is_released()
    {
        return TestResult::Fail("drop did not release the interval");
    }
    drop(n);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!("memory", smoke_mmu_notifier_exit_and_drop_release_intervals);

/// A reader collects two pages between `read_begin` and `read_retry` while a
/// writer unmaps the second one. Every placement of the writer relative to
/// the reader's steps either makes the reader retry or lets it observe the
/// post-unmap state; none lets a stale collection pass the retry check.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_mmu_notifier_racing_reader_every_interleaving() -> TestResult {
    const BASE: u64 = 0x0000_0080_6ea0_0000;
    let baseline = registered_intervals();
    // Writer position: 0 before read_begin, 1 after it, 2 between the two
    // pins, 3 after both pins, 4 after the retry check.
    for writer_at in 0..5u32 {
        let (f0, f1) = match (frame(), frame()) {
            (Ok(f0), Ok(f1)) => (f0, f1),
            _ => return TestResult::Skip("frame allocator drained"),
        };
        let space = match resident_space(BASE, &[f0, f1]) {
            Ok(space) => space,
            Err(result) => return result,
        };
        let recorder = Recorder::new();
        let n = watch(&space, BASE, 2 * PAGE, &recorder);
        let writer = |at: u32| {
            if at == writer_at && space.punch_fixed(va(BASE, 1), PAGE).is_err() {
                return Err(TestResult::Fail("writer munmap"));
            }
            Ok(())
        };
        let run = || -> Result<(bool, bool, u64), TestResult> {
            writer(0)?;
            let seq = n.read_begin();
            writer(1)?;
            let first = space.pin_user_page(VirtAddr::new(BASE));
            writer(2)?;
            let second = space.pin_user_page(va(BASE, 1));
            writer(3)?;
            let retry = n.read_retry(seq);
            writer(4)?;
            if first.is_none() {
                return Err(TestResult::Fail("the untouched page lost its pin"));
            }
            Ok((second.is_some(), retry, seq))
        };
        let (second_pinned, retry, seq) = match run() {
            Ok(outcome) => outcome,
            Err(result) => return result,
        };
        let ok = match writer_at {
            // Unmapped before the section: the reader sees the hole.
            0 => !second_pinned && !retry,
            // Unmapped inside the section: the reader must retry, whatever
            // it collected.
            1 | 2 => !second_pinned && retry,
            3 => second_pinned && retry,
            // After the check the collection was current when published, and
            // the consumer's next check sees the later invalidation.
            _ => second_pinned && !retry && n.read_retry(seq),
        };
        if !ok || recorder.calls() != 1 {
            return TestResult::Fail("a stale collection passed read_retry");
        }
        drop(n);
        drop(space);
    }
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "memory",
    smoke_mmu_notifier_racing_reader_every_interleaving
);

/// Migration never moves a pinned page, so a pinned consumer view is never
/// invalidated by it; an unpinned move fires `Migrate` on its page.
#[cfg(target_arch = "x86_64")]
fn smoke_mmu_notifier_migration_refuses_pins_and_fires_on_move() -> TestResult {
    const BASE: u64 = 0x0000_0080_6ec0_0000;
    let baseline = registered_intervals();
    let phys = match frame() {
        Ok(phys) => phys,
        Err(result) => return result,
    };
    let space = match resident_space(BASE, &[phys]) {
        Ok(space) => space,
        Err(result) => return result,
    };
    let recorder = Recorder::new();
    let n = watch(&space, BASE, PAGE, &recorder);
    let Some(pin) = space.pin_user_page(VirtAddr::new(BASE)) else {
        return TestResult::Fail("pin refused");
    };
    let seq = n.read_begin();
    // SAFETY: live inactive root; the page is the test's private resident page.
    if unsafe { space.relocate_page(VirtAddr::new(BASE)) }.is_ok()
        || recorder.calls() != 0
        || n.read_retry(seq)
    {
        return TestResult::Fail("a pinned page was migrated or invalidated");
    }
    drop(pin);
    // SAFETY: as above; the page is now unpinned and solely owned.
    let moved = match unsafe { space.relocate_page(VirtAddr::new(BASE)) } {
        Ok(moved) => moved,
        Err(_) => return TestResult::Fail("unpinned relocation"),
    };
    if moved == phys
        || recorder.calls() != 1
        || !saw(
            recorder.last(),
            MmuNotifierEvent::Migrate,
            BASE,
            BASE + PAGE,
        )
        || !n.read_retry(seq)
    {
        return TestResult::Fail("migration did not fire Migrate on its page");
    }
    drop(n);
    drop(space);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory",
    smoke_mmu_notifier_migration_refuses_pins_and_fires_on_move
);

/// A clean `MADV_FREE` page discarded by reclaim leaves the translation:
/// `Clear` fires on it before its frame is freed.
#[cfg(target_arch = "x86_64")]
fn smoke_mmu_notifier_lazyfree_discard_fires_clear() -> TestResult {
    const BASE: u64 = 0x0000_0080_6ee0_0000;
    let baseline = registered_intervals();
    let phys = match frame() {
        Ok(phys) => phys,
        Err(result) => return result,
    };
    let space = match resident_space(BASE, &[phys]) {
        Ok(space) => space,
        Err(result) => return result,
    };
    let recorder = Recorder::new();
    recorder.sample.store(phys.raw(), Ordering::SeqCst);
    let n = watch(&space, BASE, PAGE, &recorder);
    if space.madvise_free(VirtAddr::new(BASE), PAGE).is_err() || recorder.calls() != 0 {
        return TestResult::Fail("MADV_FREE itself must not fire");
    }
    if space.discard_lazyfree_pages(8) != 1 {
        return TestResult::Skip("the clean lazy-free page was not discarded");
    }
    if recorder.calls() != 1
        || !saw(recorder.last(), MmuNotifierEvent::Clear, BASE, BASE + PAGE)
        || recorder.last().is_some_and(|seen| seen.frame_refs != 1)
    {
        return TestResult::Fail("lazy-free discard did not fire before the free");
    }
    drop(n);
    drop(space);
    if registered_intervals() != baseline {
        return TestResult::Fail("registry census");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_mmu_notifier_lazyfree_discard_fires_clear);
