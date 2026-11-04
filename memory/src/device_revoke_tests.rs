//! Device-frame revocation (`address_space::revoke_device_frames`): every
//! leaf of the range goes from every named address space while VMAs, slots
//! and metadata-only aliases stay; census refusals change nothing; no leaf
//! installer (materialize for mmap and fork, mprotect, shared-frame rebind)
//! maps a revoked frame; and a fault waits for the driver's refault, then
//! repairs the same frame with exactly one reverse-map owner.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod both {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::paging::translate;
    use crate::address_space::{
        install_refault_wait, is_device_frame_revoked, revoke_device_frames,
        with_revoked_shared_frames, AddressSpace, AddressSpaceError, DeviceFrameRefault,
        DeviceFrameRevocation, DeviceRefaultError, DeviceRefaultFuture, Region, RegionPerms,
    };
    use crate::mmu_notifier::{
        MmuInterval, MmuIntervalNotifier, MmuIntervalNotifierOps, MmuNotifierEvent,
        MmuNotifierRange,
    };
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::paging::translate;
    use crate::{PhysAddr, VirtAddr};

    const PAGE: u64 = 0x1000;

    fn leaf(space: &AddressSpace, va: VirtAddr) -> Option<PhysAddr> {
        // SAFETY: a test-owned live root, not concurrently mutated.
        unsafe { translate(space.root, va) }
    }

    fn slot(space: &AddressSpace, base: VirtAddr, page: usize) -> PhysAddr {
        space
            .regions_snapshot()
            .into_iter()
            .find(|region| region.base == base)
            .map_or(PhysAddr::new(0), |region| region.backing_at(page))
    }

    fn map(space: &AddressSpace, base: VirtAddr, perms: RegionPerms, frames: &[PhysAddr]) -> bool {
        space
            .map_region(Region {
                base,
                len: frames.len() as u64 * PAGE,
                perms,
                phys: frames.to_vec().into(),
            })
            .is_ok()
    }

    /// The device provider's metadata-alias census for these tests.
    static ALIASES: IrqSafeSpinLock<Vec<(u64, usize)>> = IrqSafeSpinLock::new(Vec::new());

    fn aliases(phys: u64) -> usize {
        ALIASES
            .lock()
            .iter()
            .find(|(frame, _)| *frame == phys)
            .map_or(0, |(_, count)| *count)
    }

    fn set_aliases(counts: &[(PhysAddr, usize)]) {
        *ALIASES.lock() = counts.iter().map(|(phys, n)| (phys.raw(), *n)).collect();
    }

    /// The same census in the enumerating form revocation takes.
    fn census(start: u64, end: u64, report: &mut dyn FnMut(u64, usize)) {
        for &(frame, count) in ALIASES.lock().iter() {
            if (start..end).contains(&frame) && count != 0 {
                report(frame, count);
            }
        }
    }

    /// The live test revocation; the refault future ends it, as a driver
    /// does once its device is accessible again.
    static REVOCATION: IrqSafeSpinLock<Option<DeviceFrameRevocation>> = IrqSafeSpinLock::new(None);

    struct Refault {
        calls: AtomicUsize,
        last: AtomicU64,
        fail: AtomicBool,
    }

    impl Refault {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                last: AtomicU64::new(0),
                fail: AtomicBool::new(false),
            })
        }
    }

    impl DeviceFrameRefault for Refault {
        fn refault(&self, phys: PhysAddr) -> DeviceRefaultFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.last.store(phys.raw(), Ordering::SeqCst);
            let fail = self.fail.load(Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    return Err(DeviceRefaultError::Bus);
                }
                // "Resumed": end the revocation before completing.
                let ended = REVOCATION.lock().take();
                drop(ended);
                Ok(())
            })
        }
    }

    /// Counts invalidations without allocating.
    struct Count(AtomicUsize, IrqSafeSpinLock<Option<MmuNotifierEvent>>);
    impl MmuIntervalNotifierOps for Count {
        fn invalidate(&self, _: &MmuInterval, range: &MmuNotifierRange, _: u64) {
            self.0.fetch_add(1, Ordering::SeqCst);
            *self.1.lock() = Some(range.event);
        }
    }

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &NOOP)
    }
    unsafe fn noop(_: *const ()) {}
    static NOOP: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    static WAITS: AtomicUsize = AtomicUsize::new(0);

    /// A waiter for futures that complete when polled, standing in for the
    /// syscall layer's task-parking waiter.
    fn poll_ready(mut future: DeviceRefaultFuture) -> Option<Result<(), DeviceRefaultError>> {
        WAITS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: NOOP never dereferences its null data pointer.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &NOOP)) };
        match future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        }
    }

    /// Four contiguous frames standing in for a device aperture.
    fn aperture() -> Result<(crate::frame::PhysFrame, [PhysAddr; 4]), TestResult> {
        let block = crate::frame::alloc_pages_below(2, u64::MAX)
            .map_err(|_| TestResult::Skip("no contiguous block"))?;
        let base = block.start_address().raw();
        Ok((
            block,
            core::array::from_fn(|i| PhysAddr::new(base + i as u64 * PAGE)),
        ))
    }

    /// Revocation across two spaces: a read-write alias run, a second
    /// read-only alias, a reordered alias in the other space and a PROT_NONE
    /// metadata-only alias. Census refusals leave every leaf; success removes
    /// every leaf and its owner, keeps every slot, fires `Clear`, and refuses
    /// an overlapping revocation. While it lives, a new mapping, a fork
    /// child, a PROT_NONE -> RW mprotect and a shared-frame rebind all leave
    /// the frames unmapped, and a nofault copy stops at them. After it ends a
    /// fault repairs the same frame.
    fn smoke_device_revoke_removes_leaves_and_masks_installers() -> TestResult {
        let (block, f) = match aperture() {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        let spare = match crate::alloc_frame() {
            Ok(frame) => frame,
            Err(_) => {
                crate::frame::free_pages(block, 2);
                return TestResult::Skip("frame allocator drained");
            }
        };
        let result = run_revoke_fixture(f, spare.start_address());
        crate::free_frame(spare);
        crate::frame::free_pages(block, 2);
        result
    }

    fn run_revoke_fixture(f: [PhysAddr; 4], spare: PhysAddr) -> TestResult {
        // SAFETY: fresh user roots owned by this test.
        let (a, b, c) = match unsafe {
            (
                AddressSpace::new_for_user(),
                AddressSpace::new_for_user(),
                AddressSpace::new_for_user(),
            )
        } {
            (Ok(a), Ok(b), Ok(c)) => (Arc::new(a), Arc::new(b), Arc::new(c)),
            _ => return TestResult::Skip("root allocation failed"),
        };
        let rw = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED;
        let va1 = VirtAddr::new(0x0000_40b0_0000_0000);
        let va2 = VirtAddr::new(0x0000_40b1_0000_0000);
        let va3 = VirtAddr::new(0x0000_40b2_0000_0000);
        let va4 = VirtAddr::new(0x0000_40b3_0000_0000);
        let va5 = VirtAddr::new(0x0000_40b4_0000_0000);
        if !map(&a, va1, rw, &[f[0], f[1]])
            || !map(&a, va2, RegionPerms::READ | RegionPerms::SHARED, &[f[1]])
            || !map(&b, va3, rw, &[f[2], f[0]])
            || !map(&b, va4, RegionPerms::SHARED, &[f[3]])
        {
            return TestResult::Fail("alias registration");
        }
        // SAFETY: live test roots with registered frames.
        if unsafe { a.materialize().and_then(|()| b.materialize()) }.is_err() {
            return TestResult::Fail("alias materialization");
        }
        let present = [
            (&a, va1, f[0]),
            (&a, VirtAddr::new(va1.raw() + PAGE), f[1]),
            (&a, va2, f[1]),
            (&b, va3, f[2]),
            (&b, VirtAddr::new(va3.raw() + PAGE), f[0]),
        ];
        if present.iter().any(|(s, va, p)| leaf(s, *va) != Some(*p)) || leaf(&b, va4).is_some() {
            return TestResult::Fail("fixture did not materialize as laid out");
        }
        let owners = |n: [usize; 4]| (0..4).all(|i| crate::rmap::owner_count(f[i]) == n[i]);
        if !owners([2, 2, 1, 0]) {
            return TestResult::Fail("fixture reverse map");
        }
        let count = Arc::new(Count(AtomicUsize::new(0), IrqSafeSpinLock::new(None)));
        let interval = match MmuIntervalNotifier::insert(&a, va1.raw(), 2 * PAGE, count.clone()) {
            Ok(interval) => interval,
            Err(_) => return TestResult::Fail("interval insert"),
        };
        let both = [a.clone(), b.clone()];
        let refault = Refault::new();
        let untouched = |label| {
            if present.iter().any(|(s, va, p)| leaf(s, *va) != Some(*p))
                || !owners([2, 2, 1, 0])
                || f.iter().any(|p| is_device_frame_revoked(*p))
                || count.0.load(Ordering::SeqCst) != 0
            {
                Err(TestResult::Fail(label))
            } else {
                Ok(())
            }
        };
        let counts = [(f[0], 2), (f[1], 2), (f[2], 1), (f[3], 1)];
        // 1. The provider counts an alias the snapshot lacks.
        set_aliases(&[(f[0], 3), (f[1], 2), (f[2], 1), (f[3], 1)]);
        // SAFETY: the test owns the aperture; both roots are live.
        let refused =
            unsafe { revoke_device_frames(&both, f[0], 4 * PAGE, census, refault.clone()) };
        if refused.err() != Some(AddressSpaceError::Pinned) {
            return TestResult::Fail("census shortfall was not refused");
        }
        if let Err(result) = untouched("census refusal changed a leaf") {
            return result;
        }
        // 2. A space missing from the snapshot.
        set_aliases(&counts);
        // SAFETY: as above.
        let refused =
            unsafe { revoke_device_frames(&both[..1], f[0], 4 * PAGE, census, refault.clone()) };
        if refused.err() != Some(AddressSpaceError::Pinned) {
            return TestResult::Fail("missing space was not refused");
        }
        if let Err(result) = untouched("missing-space refusal changed a leaf") {
            return result;
        }
        // 3. An alias the provider does not own (f[3] unreported).
        set_aliases(&counts[..3]);
        // SAFETY: as above.
        let refused =
            unsafe { revoke_device_frames(&both, f[0], 4 * PAGE, census, refault.clone()) };
        if refused.err() != Some(AddressSpaceError::Pinned) {
            return TestResult::Fail("an unowned alias was not refused");
        }
        if let Err(result) = untouched("unowned-alias refusal changed a leaf") {
            return result;
        }
        set_aliases(&counts);
        // 4. Success.
        // SAFETY: as above.
        let revocation =
            match unsafe { revoke_device_frames(&both, f[0], 4 * PAGE, census, refault.clone()) } {
                Ok(revocation) => revocation,
                Err(_) => return TestResult::Fail("revocation refused"),
            };
        if present.iter().any(|(s, va, _)| leaf(s, *va).is_some())
            || slot(&a, va1, 0) != f[0]
            || slot(&a, va1, 1) != f[1]
            || slot(&a, va2, 0) != f[1]
            || slot(&b, va3, 0) != f[2]
            || slot(&b, va3, 1) != f[0]
            || slot(&b, va4, 0) != f[3]
            || !owners([0, 0, 0, 0])
            || !f.iter().all(|p| is_device_frame_revoked(*p))
            || is_device_frame_revoked(spare)
        {
            return TestResult::Fail("revocation left a leaf or changed a VMA");
        }
        if count.0.load(Ordering::SeqCst) != 1 || *count.1.lock() != Some(MmuNotifierEvent::Clear) {
            return TestResult::Fail("revocation did not fire Clear");
        }
        // SAFETY: as above.
        let overlap = unsafe { revoke_device_frames(&both, f[1], PAGE, census, refault.clone()) };
        if overlap.err() != Some(AddressSpaceError::Overlap) {
            return TestResult::Fail("an overlapping revocation was admitted");
        }
        // Installers leave revoked frames unmapped.
        if !map(&c, va5, rw, &[f[1]]) {
            return TestResult::Fail("new mapping of a revoked frame");
        }
        // SAFETY: live test roots.
        let installed = unsafe { c.materialize() };
        // SAFETY: fork's documented contract on a test root.
        let child = match unsafe { a.clone_for_fork() } {
            Ok(child) => child,
            Err(_) => return TestResult::Fail("fork"),
        };
        // SAFETY: the child owns a fresh live root.
        let child_installed = unsafe { child.materialize() };
        let reprotected = b.mprotect_range(va4, PAGE, RegionPerms::READ | RegionPerms::WRITE);
        if installed.is_err()
            || child_installed.is_err()
            || reprotected.is_err()
            || leaf(&c, va5).is_some()
            || leaf(&child, va1).is_some()
            || leaf(&b, va4).is_some()
        {
            return TestResult::Fail("an installer mapped a revoked frame");
        }
        let mut byte = [0u8; 1];
        if a.copy_user_bytes_nofault(va1, &mut byte) != 0 {
            return TestResult::Fail("a nofault copy read a revoked frame");
        }
        set_aliases(&[(f[2], 1)]);
        // SAFETY: both frames live for the call; roots are live.
        let rebound = unsafe {
            with_revoked_shared_frames(
                core::slice::from_ref(&b),
                &[f[2]],
                &[spare],
                aliases,
                || Ok(()),
            )
        };
        if rebound != Err(AddressSpaceError::Pinned) || slot(&b, va3, 0) != f[2] {
            return TestResult::Fail("a revoked frame was rebound");
        }
        // 5. End it: the next fault repairs the same frame, owner once.
        drop(revocation);
        if f.iter().any(|p| is_device_frame_revoked(*p)) {
            return TestResult::Fail("dropping the revocation did not end it");
        }
        // SAFETY: the test's live root; the ordinary fault path.
        if unsafe { a.demand_alloc_page(va1) }.is_err()
            || leaf(&a, va1) != Some(f[0])
            || !crate::rmap::contains_owner(f[0], a.root, va1)
            || crate::rmap::owner_count(f[0]) != 1
            || refault.calls.load(Ordering::SeqCst) != 0
        {
            return TestResult::Fail("the fault did not repair the same frame");
        }
        drop(interval);
        drop(child);
        TestResult::Pass
    }
    kernel_test_in!(
        "memory",
        smoke_device_revoke_removes_leaves_and_masks_installers
    );

    /// A fault on a revoked frame calls the revocation's refault hook with no
    /// lock held and waits through the installed waiter. Without a waiter, or
    /// when the refault fails, it is `Bus` and the frame stays revoked. When
    /// the refault ends the revocation the access retries, and the retry
    /// installs the same frame with one reverse-map owner.
    fn smoke_device_refault_waits_then_reinstalls_same_frame() -> TestResult {
        let (block, f) = match aperture() {
            Ok(fixture) => fixture,
            Err(result) => return result,
        };
        let previous = install_refault_wait(None);
        let result = run_refault_fixture(f[0]);
        install_refault_wait(previous);
        drop(REVOCATION.lock().take());
        crate::frame::free_pages(block, 2);
        result
    }

    fn run_refault_fixture(frame: PhysAddr) -> TestResult {
        // SAFETY: a fresh user root owned by this test.
        let space = match unsafe { AddressSpace::new_for_user() } {
            Ok(space) => Arc::new(space),
            Err(_) => return TestResult::Skip("root allocation failed"),
        };
        let va = VirtAddr::new(0x0000_40b8_0000_0000);
        let rw = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED;
        if !map(&space, va, rw, &[frame]) {
            return TestResult::Fail("mapping");
        }
        // SAFETY: the test's live root.
        if unsafe { space.materialize() }.is_err() || leaf(&space, va) != Some(frame) {
            return TestResult::Fail("materialize");
        }
        set_aliases(&[(frame, 1)]);
        let refault = Refault::new();
        // SAFETY: the test owns the frame; the root is live.
        match unsafe {
            revoke_device_frames(
                core::slice::from_ref(&space),
                frame,
                PAGE,
                census,
                refault.clone(),
            )
        } {
            Ok(revocation) => *REVOCATION.lock() = Some(revocation),
            Err(_) => return TestResult::Fail("revocation refused"),
        }
        let waits = WAITS.load(Ordering::SeqCst);
        // No waiter: the fault cannot wait and is Bus.
        // SAFETY: the test's live root; the ordinary fault path.
        if unsafe { space.demand_alloc_page(va) } != Err(AddressSpaceError::Bus)
            || !is_device_frame_revoked(frame)
            || leaf(&space, va).is_some()
        {
            return TestResult::Fail("a fault without a waiter was not Bus");
        }
        install_refault_wait(Some(poll_ready));
        refault.fail.store(true, Ordering::SeqCst);
        // SAFETY: as above.
        if unsafe { space.demand_alloc_page(va) } != Err(AddressSpaceError::Bus)
            || refault.calls.load(Ordering::SeqCst) != 1
            || refault.last.load(Ordering::SeqCst) != frame.raw()
            || WAITS.load(Ordering::SeqCst) != waits + 1
            || !is_device_frame_revoked(frame)
            || leaf(&space, va).is_some()
        {
            return TestResult::Fail("a failed refault was not Bus");
        }
        refault.fail.store(false, Ordering::SeqCst);
        // SAFETY: as above. The refault ends the revocation and the access
        // retries; the retry is the fault below.
        if unsafe { space.demand_alloc_page(va) } != Ok(())
            || is_device_frame_revoked(frame)
            || leaf(&space, va).is_some()
        {
            return TestResult::Fail("the refault did not end the revocation");
        }
        // SAFETY: as above.
        if unsafe { space.demand_alloc_page(va) } != Ok(())
            || leaf(&space, va) != Some(frame)
            || crate::rmap::owner_count(frame) != 1
            || !crate::rmap::contains_owner(frame, space.root, va)
        {
            return TestResult::Fail("the retry did not reinstall the same frame");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory",
        smoke_device_refault_waits_then_reinstalls_same_frame
    );
}
