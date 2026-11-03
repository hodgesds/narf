//! Swap-out snapshots a victim only after no CPU can store to it, and never
//! frees a frame holding a store the snapshot may have missed.
//!
//! The order under test is Linux's (`mm/vmscan.c` `shrink_folio_list`:
//! `try_to_unmap`, `try_to_unmap_flush_dirty`, `pageout`, free): the batch
//! commits its swap entries and completes the TLB shootdown before the
//! backend write, a fault in that window waits for the in-flight batch, a
//! failed write puts every exact leaf back, and a pin or kernel write that
//! reaches a frame through the region table while its batch is in flight
//! makes the batch keep the page. A kernel-test seam
//! (`swap::__test_after_swap_commit`) runs between the unmap and the backend
//! write; a wrapping backend runs a hook after the write.
//!
//! The fixtures are inactive address spaces, so a store "through a stale
//! translation" is modelled as a store to the frame's kernel alias after the
//! leaf has been replaced: any CPU store that raced the unmap lands in the
//! frame exactly like that before the shootdown completes.

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::address_space::{AddressSpace, Region, RegionPerms, RemoteAccess, RemoteBuf};
    use crate::mmu_notifier::{
        MmuInterval, MmuIntervalNotifier, MmuIntervalNotifierOps, MmuNotifierRange,
    };
    use crate::swap::{SwapBackend, SwapError, SwapSlot};
    use crate::x86_64::paging::{flags_at, translate};
    use crate::zpool::ZPAGE_SIZE;
    use crate::{AddressSpaceError, PhysAddr, VirtAddr, ZramBackend};

    const PAGE: u64 = 0x1000;

    fn va(base: u64, page: u64) -> VirtAddr {
        VirtAddr::new(base + page * PAGE)
    }

    /// Fresh frames filled with `patterns`, mapped READ|WRITE private at
    /// `base` in a fresh inactive user address space.
    fn filled_space(
        base: u64,
        patterns: &[u8],
    ) -> Result<(Arc<AddressSpace>, Vec<PhysAddr>), TestResult> {
        let mut frames = Vec::new();
        for &pattern in patterns {
            let phys = crate::alloc_frame()
                .map_err(|_| TestResult::Skip("frame allocator drained"))?
                .start_address();
            fill(phys, pattern);
            frames.push(phys);
        }
        // SAFETY: paging and the frame allocator are live in the kernel suite.
        let space = unsafe { AddressSpace::new_for_user() }
            .map_err(|_| TestResult::Skip("new_for_user unavailable"))?;
        space
            .map_region(Region {
                base: VirtAddr::new(base),
                len: frames.len() as u64 * PAGE,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: frames.clone().into(),
            })
            .map_err(|_| TestResult::Fail("fixture mapping"))?;
        // SAFETY: the inactive root is live and owns the region just mapped.
        unsafe { space.materialize() }.map_err(|_| TestResult::Fail("materialize"))?;
        Ok((Arc::new(space), frames))
    }

    /// Store `byte` over a whole frame through its kernel alias.
    fn fill(phys: PhysAddr, byte: u8) {
        // SAFETY: the callers' frames stay allocated for the store (a fresh
        // fixture frame, or a victim its swap batch has not freed yet); no
        // Rust reference is formed over them.
        unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), byte, PAGE as usize) };
    }

    /// Every byte of the page the mapping at `at` shows equals `byte`.
    fn shows(space: &AddressSpace, at: VirtAddr, byte: u8) -> bool {
        let mut page = [0u8; PAGE as usize];
        space.copy_user_bytes_nofault(at, &mut page) == page.len()
            && page.iter().all(|b| *b == byte)
    }

    fn backing(space: &AddressSpace, base: u64) -> Vec<PhysAddr> {
        space
            .regions_snapshot()
            .into_iter()
            .find(|region| region.base.as_u64() == base)
            .map(|region| region.phys.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Slots handed out and not yet returned, across every area.
    fn live_slots() -> u64 {
        let stats = crate::swap_stats();
        stats.slots_high_water - stats.slots_free as u64
    }

    fn swap_ready() -> Result<(), TestResult> {
        if crate::swap_stats().resident != 0 {
            return Err(TestResult::Skip("another swap lifecycle is active"));
        }
        crate::install_swap_backend(ZramBackend::new());
        Ok(())
    }

    /// Counts invalidations; allocation-free, as callbacks must be.
    struct Count(AtomicUsize);
    impl MmuIntervalNotifierOps for Count {
        fn invalidate(&self, _: &MmuInterval, _: &MmuNotifierRange, _: u64) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The address space, region base and frames a hook acts on. The frames
    /// are a fixed array: `race()` clones this under an IRQ-masked lock,
    /// where the heap must not be used.
    #[derive(Clone)]
    struct Race {
        space: Arc<AddressSpace>,
        base: u64,
        frames: [PhysAddr; 3],
    }

    /// Up to three fixture frames, zero-padded, for [`Race`].
    fn fixed(frames: &[PhysAddr]) -> [PhysAddr; 3] {
        let mut out = [PhysAddr::new(0); 3];
        for (slot, phys) in out.iter_mut().zip(frames) {
            *slot = *phys;
        }
        out
    }

    static RACE: IrqSafeSpinLock<Option<Race>> = IrqSafeSpinLock::new(None);
    /// Set by a hook when it ran; its first failed check, if any.
    static HOOK_RAN: AtomicUsize = AtomicUsize::new(0);
    static HOOK_FAILURE: IrqSafeSpinLock<Option<&'static str>> = IrqSafeSpinLock::new(None);

    fn arm(race: Race) {
        HOOK_RAN.store(0, Ordering::SeqCst);
        *HOOK_FAILURE.lock() = None;
        *RACE.lock() = Some(race);
    }

    /// The armed fixture, cloned out so no static lock is held while the
    /// hook calls into the address space.
    fn race() -> Option<Race> {
        let race = RACE.lock().clone();
        if race.is_some() {
            HOOK_RAN.fetch_add(1, Ordering::SeqCst);
        }
        race
    }

    fn hook_fail(why: &'static str) {
        let mut failure = HOOK_FAILURE.lock();
        if failure.is_none() {
            *failure = Some(why);
        }
    }

    /// Disarm and report the hook's verdict.
    fn disarm() -> Result<(), TestResult> {
        crate::swap::__test_after_swap_commit(None);
        *AFTER_WRITE.lock() = None;
        *RACE.lock() = None;
        if HOOK_RAN.load(Ordering::SeqCst) != 1 {
            return Err(TestResult::Fail("the race hook did not run exactly once"));
        }
        match HOOK_FAILURE.lock().take() {
            Some(why) => Err(TestResult::Fail(why)),
            None => Ok(()),
        }
    }

    /// The leaf at `at` no longer maps a frame (the unmap has happened).
    fn unmapped(space: &AddressSpace, at: VirtAddr) -> bool {
        // SAFETY: the fixture's live inactive root.
        unsafe { translate(space.root, at) }.is_none()
    }

    /// A backend whose every write fails, as zram does when its pool is full.
    struct FailingBackend;
    impl SwapBackend for FailingBackend {
        fn name(&self) -> &'static str {
            "test-failing"
        }
        fn write_batch(&self, _: &[SwapSlot], _: &[PhysAddr]) -> Result<(), SwapError> {
            Err(SwapError::BackendFull)
        }
        fn read(&self, _: SwapSlot, _: &mut [u8; ZPAGE_SIZE]) -> Result<(), SwapError> {
            Err(SwapError::SlotNotFound)
        }
        fn discard(&self, _: SwapSlot) {}
    }

    /// One-shot hook a [`AfterWriteBackend`] runs once its write succeeded,
    /// with no swap lock held: the snapshot of every victim is taken.
    static AFTER_WRITE: IrqSafeSpinLock<Option<fn()>> = IrqSafeSpinLock::new(None);

    /// zram, plus [`AFTER_WRITE`] between its write and the batch's
    /// publication.
    struct AfterWriteBackend(ZramBackend);
    impl SwapBackend for AfterWriteBackend {
        fn name(&self) -> &'static str {
            "test-after-write"
        }
        fn write_batch(&self, slots: &[SwapSlot], pages: &[PhysAddr]) -> Result<(), SwapError> {
            self.0.write_batch(slots, pages)?;
            let hook = AFTER_WRITE.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            Ok(())
        }
        fn read(&self, slot: SwapSlot, out: &mut [u8; ZPAGE_SIZE]) -> Result<(), SwapError> {
            self.0.read(slot, out)
        }
        fn read_batch_into(&self, slots: &[SwapSlot], pages: &[PhysAddr]) -> Result<(), SwapError> {
            self.0.read_batch_into(slots, pages)
        }
        fn discard(&self, slot: SwapSlot) {
            self.0.discard(slot)
        }
        fn discard_batch(&self, slots: &[SwapSlot]) {
            self.0.discard_batch(slots)
        }
    }

    /// Fault every page of the fixture back in through the swap fault path.
    fn fault_all(space: &AddressSpace, base: u64, pages: u64) -> bool {
        (0..pages).all(|page| {
            // SAFETY: the fixture's live root; the swap fault path.
            unsafe { space.demand_alloc_page(va(base, page)) }.is_ok()
        })
    }

    fn cleanup(space: &AddressSpace, base: u64) -> TestResult {
        let unmapped = space.unmap_region(VirtAddr::new(base)).is_ok();
        crate::install_swap_backend(ZramBackend::new());
        if !unmapped || crate::swap_stats().resident != 0 {
            return TestResult::Fail("cleanup left swap slots");
        }
        TestResult::Pass
    }

    // ── A store that raced the unmap is in the swapped copy ──────────────

    /// Runs between the unmap and the backend write.
    fn store_after_unmap() {
        let Some(race) = race() else {
            return;
        };
        if !unmapped(&race.space, va(race.base, 1)) {
            hook_fail("the seam ran before the victim's leaf was replaced");
        }
        // A store through a translation cached before the commit.
        fill(race.frames[1], 0x99);
    }

    /// A store that lands in a victim after its leaf became a swap entry,
    /// before the shootdown retired the storing CPU's translation, is in the
    /// swapped copy: the backend snapshot is taken after the shootdown, not
    /// before the unmap. Before this order the store was read by nobody and
    /// freed with the frame.
    fn smoke_swap_out_store_racing_unmap_lands_in_swapped_copy() -> TestResult {
        const BASE: u64 = 0x0000_0080_7100_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0x61, 0x62]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        arm(Race {
            space: space.clone(),
            base: BASE,
            frames: fixed(&frames),
        });
        crate::swap::__test_after_swap_commit(Some(store_after_unmap));
        // SAFETY: the fixture's live root and private resident run.
        let swapped = unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 2) };
        if let Err(result) = disarm() {
            return result;
        }
        if swapped != Ok(2) {
            return TestResult::Fail("the batch did not swap both pages");
        }
        if backing(&space, BASE).iter().any(|phys| phys.raw() != 0) {
            return TestResult::Fail("a swapped page kept its backing");
        }
        if !fault_all(&space, BASE, 2) {
            return TestResult::Fail("swap-in");
        }
        if !shows(&space, va(BASE, 0), 0x61) {
            return TestResult::Fail("the untouched page changed");
        }
        if !shows(&space, va(BASE, 1), 0x99) {
            return TestResult::Fail("the store that raced the unmap was lost");
        }
        cleanup(&space, BASE)
    }
    kernel_test_in!(
        "memory/swap",
        smoke_swap_out_store_racing_unmap_lands_in_swapped_copy
    );

    // ── A fault during the pending write waits for the batch ─────────────

    static PAGES_IN_BEFORE: AtomicU64 = AtomicU64::new(0);

    /// Runs between the unmap and the backend write.
    fn fault_during_pending_write() {
        let Some(race) = race() else {
            return;
        };
        let at = va(race.base, 0);
        // SAFETY: the fixture's live root; the hardware fault path.
        if unsafe { race.space.demand_alloc_page(at) } != Ok(()) {
            hook_fail("a fault on an in-flight victim did not wait for the batch");
        }
        if !unmapped(&race.space, at) {
            hook_fail("a fault during the pending write mapped the page");
        }
        if crate::swap_stats().pages_in != PAGES_IN_BEFORE.load(Ordering::SeqCst) {
            hook_fail("a fault during the pending write read the unwritten slot");
        }
        let held = backing(&race.space, race.base);
        if held.first() != race.frames.first() {
            hook_fail("a fault during the pending write took the region's backing");
        }
        // A remote read sees the still-allocated frame and does not make the
        // batch keep the page.
        let mut word = [0u8; 8];
        // SAFETY: the fixture's live address space.
        let read = unsafe {
            race.space.access_remote(
                at.as_u64(),
                RemoteBuf::Read(&mut word),
                RemoteAccess {
                    write: false,
                    force: false,
                    expand_stack: None,
                },
            )
        };
        if read != word.len() || word != [0x71; 8] {
            hook_fail("a remote read during the pending write saw the wrong bytes");
        }
    }

    /// A fault on a page whose swap entry is committed but whose backend
    /// write is still pending neither reads the unwritten slot nor maps the
    /// page: it returns for a retry and leaves the batch alone, which then
    /// completes. The retried fault after publication reads the written slot
    /// back. A remote read in the window does not keep the page.
    fn smoke_swap_out_fault_during_pending_write_waits() -> TestResult {
        const BASE: u64 = 0x0000_0080_7120_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0x71, 0x72]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        PAGES_IN_BEFORE.store(crate::swap_stats().pages_in, Ordering::SeqCst);
        arm(Race {
            space: space.clone(),
            base: BASE,
            frames: fixed(&frames),
        });
        crate::swap::__test_after_swap_commit(Some(fault_during_pending_write));
        // SAFETY: the fixture's live root and private resident run.
        let swapped = unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 2) };
        if let Err(result) = disarm() {
            return result;
        }
        if swapped != Ok(2) {
            return TestResult::Fail("the waiting fault or remote read disturbed the batch");
        }
        // SAFETY: the fixture's live root; the retried fault.
        if unsafe { space.demand_alloc_page(VirtAddr::new(BASE)) }.is_err()
            || !shows(&space, VirtAddr::new(BASE), 0x71)
        {
            return TestResult::Fail("the retried fault did not read the written slot");
        }
        if crate::swap_stats().pages_in <= PAGES_IN_BEFORE.load(Ordering::SeqCst) {
            return TestResult::Fail("the retried fault did not page in");
        }
        if !fault_all(&space, BASE, 2) || !shows(&space, va(BASE, 1), 0x72) {
            return TestResult::Fail("the other page did not fault back");
        }
        cleanup(&space, BASE)
    }
    kernel_test_in!(
        "memory/swap",
        smoke_swap_out_fault_during_pending_write_waits
    );

    // ── Paths that free or move a frame leave an in-flight victim alone ──

    /// Runs between the unmap and the backend write.
    fn reap_migrate_remap_during_pending_write() {
        let Some(race) = race() else {
            return;
        };
        // The fixture runs no task, so only the in-flight batch can block.
        if race.space.reap_anonymous_owned() != crate::oom::ReapOutcome::Blocked {
            hook_fail("the OOM reaper freed frames a swap batch still held");
        }
        // SAFETY: the fixture frame is live and direct-mapped.
        let node = unsafe { crate::frame::narf_phys_node(race.frames[1].raw()) };
        let other = (node + 1) % crate::frame::MAX_NUMA_NODES;
        // SAFETY: the fixture's live root.
        let moved = unsafe { race.space.migrate_page_to_node(va(race.base, 1), other) };
        if moved != Err(AddressSpaceError::Pinned) {
            hook_fail("NUMA migration moved a page a swap batch held");
        }
        // A NUMA hint fault's restore (and a COW break's) rebuilds the leaf
        // from Region::phys; over a swap entry that would map the frame the
        // batch is about to free.
        // SAFETY: the fixture's live root.
        if unsafe { race.space.remap_page(va(race.base, 0)) }
            != Err(AddressSpaceError::NotImplemented)
            || !unmapped(&race.space, va(race.base, 0))
        {
            hook_fail("remap_page reinstalled a leaf over an in-flight swap entry");
        }
    }

    /// While a batch holds its victims, the OOM reaper reports `Blocked`
    /// instead of freeing their frames under it, NUMA migration reports the
    /// page busy instead of moving it (Linux cannot isolate a folio reclaim
    /// holds), and `remap_page` refuses to rebuild a leaf over the swap
    /// entry. The batch then completes and both pages round-trip.
    fn smoke_swap_out_inflight_victim_refuses_reap_migrate_remap() -> TestResult {
        const BASE: u64 = 0x0000_0080_7180_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0xa1, 0xa2]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        arm(Race {
            space: space.clone(),
            base: BASE,
            frames: fixed(&frames),
        });
        crate::swap::__test_after_swap_commit(Some(reap_migrate_remap_during_pending_write));
        // SAFETY: the fixture's live root and private resident run.
        let swapped = unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 2) };
        if let Err(result) = disarm() {
            return result;
        }
        if swapped != Ok(2) {
            return TestResult::Fail("the refused reaper or migration disturbed the batch");
        }
        if !fault_all(&space, BASE, 2)
            || !shows(&space, va(BASE, 0), 0xa1)
            || !shows(&space, va(BASE, 1), 0xa2)
        {
            return TestResult::Fail("the pages did not round-trip");
        }
        cleanup(&space, BASE)
    }
    kernel_test_in!(
        "memory/swap",
        smoke_swap_out_inflight_victim_refuses_reap_migrate_remap
    );

    // ── A failed write restores every exact leaf ─────────────────────────

    /// Runs between the unmap and the (failing) backend write.
    fn store_and_mprotect_before_failed_write() {
        let Some(race) = race() else {
            return;
        };
        fill(race.frames[1], 0xc3);
        // The batch holds the old leaf it may restore, so a permission change
        // must not slip in underneath it.
        if race.space.mprotect_range(
            VirtAddr::new(race.base),
            2 * PAGE,
            RegionPerms::READ | RegionPerms::WRITE,
        ) != Err(AddressSpaceError::NotImplemented)
        {
            hook_fail("mprotect changed a page whose swap-out was in flight");
        }
    }

    /// A backend write failure after the unmap puts every victim's exact
    /// leaf back and frees no frame, so a store that raced the unmap is still
    /// in the mapping. Every slot of the run is released, nothing is
    /// resident in swap, no invalidation fires, and mprotect, refused while
    /// the batch held the pages, works again; a later swap round-trips.
    fn smoke_swap_out_write_failure_restores_leaves() -> TestResult {
        const BASE: u64 = 0x0000_0080_7140_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0x81, 0x82]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let interval = match MmuIntervalNotifier::insert(&space, BASE, 2 * PAGE, count.clone()) {
            Ok(interval) => interval,
            Err(_) => return TestResult::Fail("interval insert"),
        };
        // SAFETY: the fixture's live root.
        let leaves_before = [0, 1].map(|page| unsafe { flags_at(space.root, va(BASE, page)) });
        crate::install_swap_backend(FailingBackend);
        let live_before = live_slots();
        arm(Race {
            space: space.clone(),
            base: BASE,
            frames: fixed(&frames),
        });
        crate::swap::__test_after_swap_commit(Some(store_and_mprotect_before_failed_write));
        // SAFETY: the fixture's live root and private resident run.
        let swapped = unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 2) };
        let hook = disarm();
        let live_after = live_slots();
        crate::install_swap_backend(ZramBackend::new());
        if let Err(result) = hook {
            return result;
        }
        if swapped != Err(SwapError::BackendFull) {
            return TestResult::Fail("the backend failure was not reported");
        }
        if backing(&space, BASE) != frames {
            return TestResult::Fail("a failed write changed the region's backing");
        }
        for page in 0..2u64 {
            // SAFETY: the fixture's live root.
            if unsafe { translate(space.root, va(BASE, page)) } != Some(frames[page as usize])
                // SAFETY: as above.
                || unsafe { flags_at(space.root, va(BASE, page)) } != leaves_before[page as usize]
            {
                return TestResult::Fail("a failed write did not restore the exact leaf");
            }
        }
        if live_after != live_before || crate::swap_stats().resident != 0 {
            return TestResult::Fail("a failed write kept swap slots");
        }
        if count.0.load(Ordering::SeqCst) != 0 || interval.read_retry(0) {
            return TestResult::Fail("a failed write invalidated the range");
        }
        if !shows(&space, va(BASE, 0), 0x81) || !shows(&space, va(BASE, 1), 0xc3) {
            return TestResult::Fail("a failed write lost the page contents");
        }
        drop(interval);
        if space
            .mprotect_range(
                VirtAddr::new(BASE),
                2 * PAGE,
                RegionPerms::READ | RegionPerms::WRITE,
            )
            .is_err()
        {
            return TestResult::Fail("mprotect stayed refused after the batch");
        }
        // SAFETY: the fixture's live root; no transition record survived.
        if unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 2) } != Ok(2)
            || !fault_all(&space, BASE, 2)
            || !shows(&space, va(BASE, 0), 0x81)
            || !shows(&space, va(BASE, 1), 0xc3)
        {
            return TestResult::Fail("the pages did not swap after the failure");
        }
        cleanup(&space, BASE)
    }
    kernel_test_in!("memory/swap", smoke_swap_out_write_failure_restores_leaves);

    // ── A pin or kernel write after the snapshot keeps the page ──────────

    /// Runs after the backend write, before publication: a remote write
    /// (ptrace POKEDATA, process_vm_writev) to page 1 and a pin of page 2
    /// that a device writes through and drops again.
    fn reach_frames_after_snapshot() {
        let Some(race) = race() else {
            return;
        };
        let poke = [0xe5u8; PAGE as usize];
        // SAFETY: the fixture's live address space.
        let wrote = unsafe {
            race.space.access_remote(
                va(race.base, 1).as_u64(),
                RemoteBuf::Write(&poke),
                RemoteAccess {
                    write: true,
                    force: false,
                    expand_stack: None,
                },
            )
        };
        if wrote != poke.len() {
            hook_fail("the remote write during the pending batch was refused");
        }
        let Some(pin) = race.space.pin_user_page(va(race.base, 2)) else {
            hook_fail("pinning an in-flight victim was refused");
            return;
        };
        fill(pin.phys(), 0xd7);
        drop(pin);
    }

    /// A kernel write and a pin reach a victim's frame through the region
    /// table after the backend snapshot was taken; the pin is even dropped
    /// again before the batch publishes. The batch keeps both pages
    /// resident with their exact leaves (the snapshot misses those bytes),
    /// releases their slots, and swaps only the untouched page.
    fn smoke_swap_out_keeps_page_reached_after_snapshot() -> TestResult {
        const BASE: u64 = 0x0000_0080_7160_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0x91, 0x92, 0x93]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        // SAFETY: the fixture's live root.
        let leaves_before = [1, 2].map(|page| unsafe { flags_at(space.root, va(BASE, page)) });
        crate::install_swap_backend(AfterWriteBackend(ZramBackend::new()));
        arm(Race {
            space: space.clone(),
            base: BASE,
            frames: fixed(&frames),
        });
        *AFTER_WRITE.lock() = Some(reach_frames_after_snapshot);
        // SAFETY: the fixture's live root and private resident run.
        let swapped = unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 3) };
        if let Err(result) = disarm() {
            return result;
        }
        if swapped != Ok(1) {
            return TestResult::Fail("the batch did not keep exactly the two reached pages");
        }
        let after = backing(&space, BASE);
        if after.len() != 3 || after[0].raw() != 0 || after[1] != frames[1] || after[2] != frames[2]
        {
            return TestResult::Fail("a reached page lost its backing");
        }
        for page in 1..3u64 {
            // SAFETY: the fixture's live root.
            if unsafe { translate(space.root, va(BASE, page)) } != Some(frames[page as usize])
                // SAFETY: as above.
                || unsafe { flags_at(space.root, va(BASE, page)) }
                    != leaves_before[page as usize - 1]
            {
                return TestResult::Fail("a reached page's leaf was not restored");
            }
        }
        if crate::swap_stats().resident != 1 {
            return TestResult::Fail("a reached page kept its swap slot");
        }
        if !shows(&space, va(BASE, 1), 0xe5) {
            return TestResult::Fail("the remote write was lost");
        }
        if !shows(&space, va(BASE, 2), 0xd7) {
            return TestResult::Fail("the device's write through the dropped pin was lost");
        }
        // SAFETY: the fixture's live root; the swap fault path.
        if unsafe { space.demand_alloc_page(VirtAddr::new(BASE)) }.is_err()
            || !shows(&space, VirtAddr::new(BASE), 0x91)
        {
            return TestResult::Fail("the swapped page did not fault back");
        }
        cleanup(&space, BASE)
    }
    kernel_test_in!(
        "memory/swap",
        smoke_swap_out_keeps_page_reached_after_snapshot
    );
}
