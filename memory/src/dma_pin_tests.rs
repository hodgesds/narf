//! Reclaim never moves or drops a page pinned for device access
//! (`UserPagePin`): swap-out skips it, including a pin that lands between the
//! swap commit and its publication, and lazy-free discard keeps it, whether
//! the pin predates `MADV_FREE`, follows it, or holds at discard time. Each
//! test writes through the pin as a device would and proves the mapping
//! still shows those bytes. Multi-owner migration is covered beside its
//! resolver fixtures in `migrate.rs`.
//!
//! Linux: `mm/vmscan.c` `shrink_folio_list` (`folio_maybe_dma_pinned`),
//! `mm/rmap.c` `try_to_unmap_one` (anon-exclusive share and the MADV_FREE
//! reference test), `mm/gup.c` `follow_page_pte` (`FOLL_TOUCH` dirtying).

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    // The racing-pin test drives `swap::__test_after_swap_commit`, which
    // exists only with the kernel-test feature, so it and the items only it
    // uses are built only with that feature.
    #[cfg(feature = "kernel-test")]
    use core::sync::atomic::{AtomicUsize, Ordering};

    use narf_kernel_test::{kernel_test_in, TestResult};
    #[cfg(feature = "kernel-test")]
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::address_space::{AddressSpace, Region, RegionPerms, UserPagePin};
    #[cfg(feature = "kernel-test")]
    use crate::mmu_notifier::{
        MmuInterval, MmuIntervalNotifier, MmuIntervalNotifierOps, MmuNotifierRange,
    };
    use crate::x86_64::paging::{flags_at, translate, PtFlags};
    use crate::{PhysAddr, VirtAddr};

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
            // SAFETY: a fresh allocator frame owned by this test until the
            // region below takes it.
            unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), pattern, PAGE as usize) };
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

    /// Write a whole page through a pin, as a device would: through the
    /// physical frame, never through the user mapping.
    fn device_write(pin: &UserPagePin, byte: u8) {
        // SAFETY: the pin retains the frame; this test is its only writer and
        // forms no Rust reference over it.
        unsafe { core::ptr::write_bytes(pin.phys().kernel_mut_ptr::<u8>(), byte, PAGE as usize) };
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

    fn lazyfree(space: &AddressSpace, at: VirtAddr) -> bool {
        // SAFETY: the test's live inactive root.
        unsafe { flags_at(space.root, at) }.is_some_and(|flags| flags.contains(PtFlags::LAZYFREE))
    }

    /// Counts invalidations; allocation-free, as callbacks must be.
    #[cfg(feature = "kernel-test")]
    struct Count(AtomicUsize);
    #[cfg(feature = "kernel-test")]
    impl MmuIntervalNotifierOps for Count {
        fn invalidate(&self, _: &MmuInterval, _: &MmuNotifierRange, _: u64) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn swap_ready() -> Result<(), TestResult> {
        if crate::swap_stats().resident != 0 {
            return Err(TestResult::Skip("another swap lifecycle is active"));
        }
        crate::install_swap_backend(crate::ZramBackend::new());
        Ok(())
    }

    /// A pinned page is neither offered by the reclaim scan nor swapped by a
    /// batch that names it; the rest of the batch is swapped. The device's
    /// writes through the pin stay visible in the mapping. Once unpinned the
    /// page swaps and faults back with those bytes.
    fn smoke_dma_pin_swap_out_skips_pinned_page() -> TestResult {
        const BASE: u64 = 0x0000_0080_6f00_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0x31, 0x32, 0x33]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        let Some(pin) = space.pin_user_page(va(BASE, 1)) else {
            return TestResult::Fail("ordinary RAM pin refused");
        };
        let mut candidates = Vec::new();
        space.collect_anon_reclaim_candidates(&mut candidates, 16);
        if candidates.iter().any(|run| {
            let lo = run.base.as_u64();
            (lo..lo + run.pages as u64 * PAGE).contains(&va(BASE, 1).as_u64())
        }) {
            return TestResult::Fail("the reclaim scan offered a pinned page");
        }
        // SAFETY: the test's live root and private resident run.
        if unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 3) } != Ok(2) {
            return TestResult::Fail("the batch did not swap exactly the two unpinned pages");
        }
        let after = backing(&space, BASE);
        if after.len() != 3
            || after[0].raw() != 0
            || after[2].raw() != 0
            || after[1] != frames[1]
            // SAFETY: the test's live root.
            || unsafe { translate(space.root, va(BASE, 1)) } != Some(frames[1])
        {
            return TestResult::Fail("the pinned page lost its backing or leaf");
        }
        if crate::swap_stats().resident != 2 {
            return TestResult::Fail("swap slots charged for a skipped page");
        }
        device_write(&pin, 0x77);
        if !shows(&space, va(BASE, 1), 0x77) {
            return TestResult::Fail("the mapping does not show the device's writes");
        }
        drop(pin);
        // SAFETY: as above; the page is now unpinned.
        if unsafe { space.swap_out_private_batch(va(BASE, 1), 1) } != Ok(1) {
            return TestResult::Fail("an unpinned page was not swapped");
        }
        for page in 0..3 {
            // SAFETY: the test's live root; the swap fault path.
            if unsafe { space.demand_alloc_page(va(BASE, page)) }.is_err() {
                return TestResult::Fail("swap-in");
            }
        }
        if !shows(&space, va(BASE, 0), 0x31)
            || !shows(&space, va(BASE, 1), 0x77)
            || !shows(&space, va(BASE, 2), 0x33)
        {
            return TestResult::Fail("swapped contents changed");
        }
        if space.unmap_region(VirtAddr::new(BASE)).is_err() || crate::swap_stats().resident != 0 {
            return TestResult::Fail("cleanup left swap slots");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory", smoke_dma_pin_swap_out_skips_pinned_page);

    #[cfg(feature = "kernel-test")]
    static RACE_TARGET: IrqSafeSpinLock<Option<(Arc<AddressSpace>, u64)>> =
        IrqSafeSpinLock::new(None);
    #[cfg(feature = "kernel-test")]
    static RACE_PIN: IrqSafeSpinLock<Option<UserPagePin>> = IrqSafeSpinLock::new(None);

    /// Runs inside the swap batch after its PTE commit, with no lock held.
    #[cfg(feature = "kernel-test")]
    fn pin_after_swap_commit() {
        let target = RACE_TARGET.lock().clone();
        if let Some((space, at)) = target {
            let pin = space.pin_user_page(VirtAddr::new(at));
            *RACE_PIN.lock() = pin;
        }
    }

    /// A pin that lands after the swap batch committed its swap entries but
    /// before it published them refuses that page: its exact leaf comes back,
    /// its slot is released, no invalidation fires for it, and the device's
    /// writes stay visible. The other page of the batch is swapped.
    #[cfg(feature = "kernel-test")]
    fn smoke_dma_pin_swap_commit_refuses_racing_pin() -> TestResult {
        const BASE: u64 = 0x0000_0080_6f20_0000;
        if let Err(result) = swap_ready() {
            return result;
        }
        let (space, frames) = match filled_space(BASE, &[0x41, 0x42]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let interval =
            match MmuIntervalNotifier::insert(&space, va(BASE, 1).as_u64(), PAGE, count.clone()) {
                Ok(interval) => interval,
                Err(_) => return TestResult::Fail("interval insert"),
            };
        // SAFETY: the test's live root.
        let leaf_before = unsafe { flags_at(space.root, va(BASE, 1)) };
        *RACE_TARGET.lock() = Some((space.clone(), va(BASE, 1).as_u64()));
        crate::swap::__test_after_swap_commit(Some(pin_after_swap_commit));
        // SAFETY: the test's live root and private resident run.
        let swapped = unsafe { space.swap_out_private_batch(VirtAddr::new(BASE), 2) };
        crate::swap::__test_after_swap_commit(None);
        *RACE_TARGET.lock() = None;
        let Some(pin) = RACE_PIN.lock().take() else {
            return TestResult::Fail("the racing pin was not taken");
        };
        if swapped != Ok(1) {
            return TestResult::Fail("the racing pin did not refuse exactly its page");
        }
        let after = backing(&space, BASE);
        if after.len() != 2
            || after[0].raw() != 0
            || after[1] != frames[1]
            // SAFETY: the test's live root.
            || unsafe { translate(space.root, va(BASE, 1)) } != Some(frames[1])
            // SAFETY: as above.
            || unsafe { flags_at(space.root, va(BASE, 1)) } != leaf_before
        {
            return TestResult::Fail("the refused page's leaf or backing was not restored");
        }
        if crate::swap_stats().resident != 1 {
            return TestResult::Fail("the refused page kept its swap slot");
        }
        if count.0.load(Ordering::SeqCst) != 0 || interval.read_retry(0) {
            return TestResult::Fail("the refused page was invalidated");
        }
        device_write(&pin, 0x88);
        if !shows(&space, va(BASE, 1), 0x88) {
            return TestResult::Fail("the mapping does not show the device's writes");
        }
        drop(pin);
        drop(interval);
        // SAFETY: the test's live root; the swap fault path.
        if unsafe { space.demand_alloc_page(VirtAddr::new(BASE)) }.is_err()
            || !shows(&space, VirtAddr::new(BASE), 0x41)
        {
            return TestResult::Fail("the swapped page did not fault back");
        }
        if space.unmap_region(VirtAddr::new(BASE)).is_err() || crate::swap_stats().resident != 0 {
            return TestResult::Fail("cleanup left swap slots");
        }
        TestResult::Pass
    }
    #[cfg(feature = "kernel-test")]
    kernel_test_in!("memory", smoke_dma_pin_swap_commit_refuses_racing_pin);

    /// Lazy-free never discards a page a device may have written through a
    /// pin. A: pinned before MADV_FREE, which does not mark it. B: marked,
    /// then pinned, which drops the mark. D: pinned and carrying a mark set
    /// behind MADV_FREE's back, which the discard pass refuses and clears.
    /// C: the unpinned control, discarded. After the pins are released no
    /// mark survives, so a later pass keeps the device's bytes.
    fn smoke_dma_pin_lazyfree_never_discards_pinned_page() -> TestResult {
        const BASE: u64 = 0x0000_0080_6f40_0000;
        let (space, frames) = match filled_space(BASE, &[0x51, 0x52, 0x53, 0x54]) {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        let Some(pin_a) = space.pin_user_page(va(BASE, 0)) else {
            return TestResult::Fail("pin A refused");
        };
        if space.madvise_free(VirtAddr::new(BASE), 4 * PAGE).is_err() {
            return TestResult::Fail("MADV_FREE");
        }
        if lazyfree(&space, va(BASE, 0))
            || !lazyfree(&space, va(BASE, 1))
            || !lazyfree(&space, va(BASE, 2))
            || !lazyfree(&space, va(BASE, 3))
        {
            return TestResult::Fail("MADV_FREE marked a pinned page or skipped an unpinned one");
        }
        let Some(pin_b) = space.pin_user_page(va(BASE, 1)) else {
            return TestResult::Fail("pin B refused");
        };
        if lazyfree(&space, va(BASE, 1)) {
            return TestResult::Fail("pinning did not drop the MADV_FREE mark");
        }
        let Some(pin_d) = space.pin_user_page(va(BASE, 3)) else {
            return TestResult::Fail("pin D refused");
        };
        // SAFETY: the test's live root; the page lies in its bookkept region.
        let remarked = unsafe {
            crate::x86_64::paging::lazyfree_mark_4kb_local_range(space.root, va(BASE, 3), 1, |_| {
                true
            })
        };
        if remarked != Ok(1) || !lazyfree(&space, va(BASE, 3)) {
            return TestResult::Fail("fixture re-mark of the pinned page");
        }
        device_write(&pin_a, 0xa1);
        device_write(&pin_b, 0xb2);
        device_write(&pin_d, 0xd4);
        if space.discard_lazyfree_pages(16) != 1 {
            return TestResult::Fail("discard did not take exactly the unpinned page");
        }
        let after = backing(&space, BASE);
        if after.len() != 4
            || after[0] != frames[0]
            || after[1] != frames[1]
            || after[2].raw() != 0
            || after[3] != frames[3]
        {
            return TestResult::Fail("a pinned page lost its backing");
        }
        if lazyfree(&space, va(BASE, 3)) {
            return TestResult::Fail("the refused pinned page kept its mark");
        }
        drop((pin_a, pin_b, pin_d));
        if space.discard_lazyfree_pages(16) != 0 {
            return TestResult::Fail("a once-pinned page was discarded after its release");
        }
        if !shows(&space, va(BASE, 0), 0xa1)
            || !shows(&space, va(BASE, 1), 0xb2)
            || !shows(&space, va(BASE, 3), 0xd4)
        {
            return TestResult::Fail("the device's writes were lost");
        }
        // SAFETY: the test's live root; a demand-zero refault of the hole.
        if unsafe { space.demand_alloc_page(va(BASE, 2)) }.is_err()
            || !shows(&space, va(BASE, 2), 0)
        {
            return TestResult::Fail("the discarded page did not refault as zero");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory", smoke_dma_pin_lazyfree_never_discards_pinned_page);
}
