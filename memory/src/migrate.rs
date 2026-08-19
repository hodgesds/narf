//! Physical-frame migration — the compaction primitive that relocates a frame
//! and repoints every mapping of it.
//!
//! It composes two pieces this crate now has: the reverse map ([`crate::rmap`],
//! frame → owner `(root, va)`) and — because `memory` cannot enumerate address
//! spaces without a dependency cycle — a pluggable **resolver** that maps a
//! page-table `root` back to its live `Arc<AddressSpace>`. The task/scheduler
//! layer implements [`AddressSpaceResolver`] and installs it at boot, exactly
//! like the [`oom::OomKiller`](crate::oom::OomKiller) and
//! [`reclaim::AnonReclaimer`](crate::reclaim::AnonReclaimer) seams.
//!
//! `migrate_frame` (a later change) walks a frame's rmap owners, resolves each
//! owning address space through this seam, and relocates via
//! [`AddressSpace::relocate_page`](crate::address_space::AddressSpace::relocate_page).

use alloc::sync::Arc;

use narf_lib::sync::IrqSafeSpinLock;

use crate::address_space::AddressSpace;
use crate::PhysAddr;

/// Resolve a page-table root (`pml4` phys) to its live address space. Implemented
/// by the layer that owns the `Arc<AddressSpace>`es (the task/scheduler layer)
/// and installed with [`register_address_space_resolver`]. Returns `None` for a
/// root with no live address space (already torn down, or a kernel-only root).
pub trait AddressSpaceResolver: Sync {
    fn resolve(&self, root: PhysAddr) -> Option<Arc<AddressSpace>>;
}

static RESOLVER: IrqSafeSpinLock<Option<&'static dyn AddressSpaceResolver>> =
    IrqSafeSpinLock::new(None);

/// Install the root→AddressSpace resolver. Intended to be called once at boot;
/// last registration wins.
pub fn register_address_space_resolver(resolver: &'static dyn AddressSpaceResolver) {
    *RESOLVER.lock() = Some(resolver);
}

/// True once a resolver is installed.
pub fn resolver_armed() -> bool {
    RESOLVER.lock().is_some()
}

/// Resolve `root` to its live address space, or `None` if no resolver is
/// installed or the root is unknown (already torn down).
pub fn resolve_address_space(root: PhysAddr) -> Option<Arc<AddressSpace>> {
    // `&'static dyn` is Copy, so drop the registry lock before calling the
    // (task-enumerating, possibly allocating) resolver.
    let resolver = (*RESOLVER.lock())?;
    resolver.resolve(root)
}

/// Why a physical-frame migration could not proceed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MigrateError {
    /// The frame has no recorded mapping (untracked, or already free).
    NotMapped,
    /// Retained for API compatibility; no longer returned. COW-shared frames are
    /// now migrated by walking every rmap owner ([`migrate_frame_multi`]).
    MultiOwner,
    /// No live address space owns the frame's root (torn down, or no resolver
    /// installed).
    NoAddressSpace,
    /// The frame moved out from under us between the rmap read and the
    /// relocation (a concurrent fault/unmap/COW) — a no-op; a caller should
    /// re-scan and retry.
    Raced,
    /// The relocation itself failed (frame allocation or page-table install).
    Failed,
}

/// Relocate physical frame `src` to a fresh frame, repointing every mapping of
/// it, and return the new frame — the compaction primitive that evacuates a
/// specific frame so its buddy block can coalesce.
///
/// Single-owner frames take the fast path ([`AddressSpace::relocate_frame_at`],
/// which re-checks under the region lock that `src` is still mapped where rmap
/// named it → [`MigrateError::Raced`] rather than moving the wrong page). A
/// COW-shared frame (more than one rmap owner) is migrated by
/// [`migrate_frame_multi`]. [`MigrateError::MultiOwner`] is retained in the API
/// but no longer returned here.
#[cfg(target_arch = "x86_64")]
pub fn migrate_frame(src: PhysAddr) -> Result<PhysAddr, MigrateError> {
    match crate::rmap::owner_count(src) {
        0 => Err(MigrateError::NotMapped),
        1 => {
            let mut owner = None;
            crate::rmap::for_each_owner(src, |o| owner = Some(o));
            let owner = owner.ok_or(MigrateError::NotMapped)?;
            let aspace = resolve_address_space(owner.root).ok_or(MigrateError::NoAddressSpace)?;
            // SAFETY: `aspace` is a live, Arc-pinned root; `relocate_frame_at`
            // re-validates the page under the region lock and only moves it if it
            // still maps `src`.
            match unsafe { aspace.relocate_frame_at(owner.va, src) } {
                Ok(new) => Ok(new),
                Err(crate::address_space::AddressSpaceError::Unmapped) => Err(MigrateError::Raced),
                Err(_) => Err(MigrateError::Failed),
            }
        }
        _ => migrate_frame_multi(src),
    }
}

/// Migrate a COW-shared frame (`> 1` rmap owner) to a fresh shared frame.
///
/// Copies `src` into a new `dst`, pre-counts `dst`'s COW refcount to the owner
/// count BEFORE any owner can reach it — so a write during migration faults into
/// a proper COW split against `dst` rather than corrupting a co-owner — then
/// repoints each owner atomically under its own region lock with a READ-ONLY
/// leaf ([`AddressSpace::repoint_shared_page`]). An owner that raced (COW-split /
/// unmapped `src` first) fails its repoint; its pre-counted `dst` reference is
/// dropped and it keeps its own copy. `src`'s refcount is then released once per
/// moved owner, and the physical frame is freed by whichever caller drops its
/// last reference (the atomic `dec_ref` 1→0 transition, so never double-freed).
#[cfg(target_arch = "x86_64")]
fn migrate_frame_multi(src: PhysAddr) -> Result<PhysAddr, MigrateError> {
    let mut owners: alloc::vec::Vec<crate::rmap::Owner> = alloc::vec::Vec::new();
    crate::rmap::for_each_owner(src, |o| owners.push(o));
    let n = owners.len();
    if n < 2 {
        // The count changed under us between the gate and the snapshot.
        return Err(MigrateError::Raced);
    }

    // Allocate `dst` on `src`'s node and copy the contents.
    // SAFETY: `src` is a live frame naming its node.
    let node = unsafe { crate::frame::narf_phys_node(src.raw()) };
    let dst_frame =
        crate::frame::alloc_user_frame_on_strict(node).map_err(|_| MigrateError::Failed)?;
    let dst = dst_frame.start_address();
    // SAFETY: both frames are live, distinct 4 KiB direct-map ranges.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src.kernel_ptr::<u8>(),
            dst.kernel_mut_ptr::<u8>(),
            crate::frame::PAGE_SIZE as usize,
        );
    }

    // Pre-count `dst` to `n` BEFORE installing any leaf, so a write during the
    // migration faults into cow_split against a shared `dst`.
    for _ in 1..n {
        crate::frame::cow::inc_ref(dst);
    }

    // Repoint each owner atomically under its region lock.
    let mut moved = 0usize;
    for owner in &owners {
        let ok = match resolve_address_space(owner.root) {
            // SAFETY: `dst` holds a copy of `src`; the AS is a live pinned root.
            Some(aspace) => unsafe { aspace.repoint_shared_page(owner.va, src, dst) }.is_ok(),
            None => false,
        };
        if ok {
            moved += 1;
        } else {
            // This owner did not move (raced / AS gone) → drop its pre-counted
            // `dst` reference.
            crate::frame::cow::dec_ref(dst);
        }
    }

    if moved == 0 {
        // Nobody moved; `dst` (now refcount 0) is unused.
        crate::frame::free_frame(dst_frame);
        return Err(MigrateError::Raced);
    }

    // Release `src`: one `free_frame` per owner we moved off it (repoint did not
    // touch the refcount). `free_frame` dec_refs and returns the physical frame
    // only from the caller that wins the atomic 1→0 transition, so it composes
    // with a racing owner's own COW-split/unmap `free_frame` — exactly one caller
    // frees the physical frame, and it is never double-freed or leaked.
    for _ in 0..moved {
        crate::frame::free_frame(crate::frame::PhysFrame::new(src));
    }
    Ok(dst)
}

/// Why a compaction attempt on a physical block could not free it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompactError {
    /// The block holds an allocated frame that is not a migratable user page
    /// (kernel / slab / DMA — no rmap owner), so it can't be fully freed.
    Unmovable,
    /// A movable page could not be migrated out (relocation failed, raced, or
    /// COW-shared / multi-owner).
    MigrateFailed,
    /// A frame was taken by a concurrent allocation before it could be reserved;
    /// the attempt is abandoned cleanly, leaving the block as found.
    Raced,
}

/// Compact the naturally-aligned order-`order` physical block based at `base` (a
/// run of `2^order` frames): migrate every movable user page out of it so the
/// whole block becomes free and the buddy coalesces it back to order `order`.
/// Returns the number of pages migrated.
///
/// [`crate::rmap`] is the movability oracle — a frame with an rmap owner is a
/// migratable user page; an allocated frame WITHOUT one is unmovable
/// (kernel/slab/DMA) → [`CompactError::Unmovable`]. Free frames in the block are
/// reserved up front, and each migrated frame is re-reserved the moment it
/// frees, so every migration destination lands OUTSIDE the block. On any failure
/// the reservations are released, leaving the block as it was found; on success
/// the whole run is released as one coalescing free.
#[cfg(target_arch = "x86_64")]
pub fn compact_block(base: PhysAddr, order: usize) -> Result<usize, CompactError> {
    let count = 1u64 << order;
    let node = crate::frame::node_for_phys(base.raw());

    fn release(reserved: &[PhysAddr]) {
        for r in reserved {
            crate::frame::free_movable_range(*r, 1);
        }
    }

    // Under a cache drain + bypass so the block's currently-free frames are
    // visible in the zone free lists (reservable), and every alloc/free below
    // routes straight to the zone rather than a per-CPU cache — so a just-
    // migrated frame is immediately reservable and no destination allocation
    // comes from the block.
    crate::frame::with_node_cache_bypassed(node, || {
        // Frames pulled out of the free lists (released at the end / on failure).
        let mut reserved: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();
        // Allocated user pages to evacuate.
        let mut movable: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();

        // Pass 1: classify each frame; reserve the free ones.
        for i in 0..count {
            let phys = PhysAddr::new(base.raw() + i * 4096);
            if crate::rmap::owner_count(phys) >= 1 {
                movable.push(phys);
            } else if crate::frame::reserve_frame_range(phys, 1) {
                reserved.push(phys); // was free, now held
            } else {
                // Allocated but not an rmap-owned user page → unmovable.
                release(&reserved);
                return Err(CompactError::Unmovable);
            }
        }

        // Pass 2: migrate movable pages out. Destinations can be neither our
        // reserved frames (out of the free lists) nor the not-yet-migrated
        // movable frames (still allocated), so they land outside the block.
        // Re-reserve each frame the instant migration frees it.
        let mut migrated = 0usize;
        for phys in &movable {
            match migrate_frame(*phys) {
                Ok(_new) => {
                    if crate::frame::reserve_frame_range(*phys, 1) {
                        reserved.push(*phys);
                        migrated += 1;
                    } else {
                        release(&reserved);
                        return Err(CompactError::Raced);
                    }
                }
                Err(_) => {
                    release(&reserved);
                    return Err(CompactError::MigrateFailed);
                }
            }
        }

        // Pass 3: the whole block is now reserved → release it, coalescing to
        // order.
        release(&reserved);
        Ok(migrated)
    })
}

/// Proactive compaction driver: consolidate free memory by compacting up to
/// `max_blocks` order-`order` blocks that currently hold movable (user-mapped)
/// pages, returning the number of pages migrated. Candidate blocks are the
/// order-`order` blocks containing rmap-tracked frames, so the scan is directed
/// at movable memory instead of walking all of RAM.
///
/// Bounded by `max_blocks` so a background caller (kswapd) does a little gentle
/// consolidation per pass rather than a full sweep. This is a first-cut policy:
/// it does not yet order candidates by yield or use Linux's dual (free/migrate)
/// scanner, so it can migrate a page more than once across passes; the sound
/// per-block mechanism is [`compact_block`].
#[cfg(target_arch = "x86_64")]
pub fn compact_scan(order: usize, max_blocks: usize) -> usize {
    if order == 0 || max_blocks == 0 {
        return 0;
    }
    let block_bytes = (1u64 << order) << 12;
    let block_mask = !(block_bytes - 1);
    // Distinct order-`order` block bases covering the tracked (movable) frames.
    let mut candidates: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    crate::rmap::for_each_tracked_frame(|phys| {
        let base = phys.raw() & block_mask;
        if candidates.len() < max_blocks && !candidates.contains(&base) {
            candidates.push(base);
        }
    });
    let mut migrated = 0usize;
    for base in candidates {
        if let Ok(n) = compact_block(PhysAddr::new(base), order) {
            migrated = migrated.saturating_add(n);
        }
    }
    migrated
}

/// Test-only: clear the installed resolver so a test's mock never leaks.
#[doc(hidden)]
pub fn __reset_resolver_for_test() {
    *RESOLVER.lock() = None;
}

// ── Tests ────────────────────────────────────────────────────────
// Always compiled so they register + run under `cargo xtask test`.
mod tests {
    use super::{
        __reset_resolver_for_test, register_address_space_resolver, resolve_address_space,
        resolver_armed, AddressSpaceResolver,
    };
    use crate::address_space::AddressSpace;
    use crate::PhysAddr;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static ASKED_ROOT: AtomicU64 = AtomicU64::new(0);

    /// Records the root it was asked to resolve and returns `None` (a real AS is
    /// not needed to prove the dispatch forwards the query).
    struct RecordingResolver;
    impl AddressSpaceResolver for RecordingResolver {
        fn resolve(&self, root: PhysAddr) -> Option<Arc<AddressSpace>> {
            ASKED_ROOT.store(root.raw(), Ordering::Relaxed);
            None
        }
    }
    static RECORDING_RESOLVER: RecordingResolver = RecordingResolver;

    fn smoke_migrate_resolver_dispatch() -> TestResult {
        __reset_resolver_for_test();
        let result = (|| {
            // Unregistered: resolve is a no-op returning None.
            if resolver_armed() || resolve_address_space(PhysAddr::new(0x1000)).is_some() {
                return TestResult::Fail("unregistered resolver should yield None");
            }
            register_address_space_resolver(&RECORDING_RESOLVER);
            if !resolver_armed() {
                return TestResult::Fail("register_address_space_resolver did not arm the seam");
            }
            // The queried root is forwarded to the installed resolver.
            ASKED_ROOT.store(0, Ordering::Relaxed);
            let _ = resolve_address_space(PhysAddr::new(0x00AB_C000));
            if ASKED_ROOT.load(Ordering::Relaxed) != 0x00AB_C000 {
                return TestResult::Fail("resolve did not forward the root to the resolver");
            }
            TestResult::Pass
        })();
        __reset_resolver_for_test();
        result
    }
    kernel_test_in!("memory/migrate", smoke_migrate_resolver_dispatch);

    // A resolver backed by a single test-owned address space (stored in a static
    // so the `&'static dyn` resolver can reach it).
    #[cfg(target_arch = "x86_64")]
    static TEST_AS: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);

    #[cfg(target_arch = "x86_64")]
    struct SingleAsResolver;
    #[cfg(target_arch = "x86_64")]
    impl AddressSpaceResolver for SingleAsResolver {
        fn resolve(&self, root: PhysAddr) -> Option<Arc<AddressSpace>> {
            TEST_AS.lock().as_ref().filter(|a| a.root == root).cloned()
        }
    }
    #[cfg(target_arch = "x86_64")]
    static SINGLE_AS_RESOLVER: SingleAsResolver = SingleAsResolver;

    #[cfg(target_arch = "x86_64")]
    fn smoke_migrate_frame_relocates() -> TestResult {
        use super::{migrate_frame, MigrateError};
        use crate::{Region, RegionPerms, VirtAddr};

        __reset_resolver_for_test();
        crate::rmap::__reset_for_test();
        // SAFETY: paging + frame allocator live in the kernel suite.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => Arc::new(a),
            Err(_) => return TestResult::Skip("new_for_user failed"),
        };
        let p = match crate::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        // SAFETY: identity-mapped fresh frame, sole owner.
        unsafe { *(p.kernel_mut_ptr::<u32>()) = 0x5EED_1111 };
        let va = VirtAddr::new(0x0000_0080_0090_0000);
        if aspace
            .map_region(Region {
                base: va,
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![p],
            })
            .is_err()
        {
            return TestResult::Fail("map_region failed");
        }
        // SAFETY: aspace owns a live root and the validated region.
        if unsafe { aspace.materialize() }.is_err() {
            return TestResult::Fail("materialize failed");
        }
        *TEST_AS.lock() = Some(aspace.clone());
        register_address_space_resolver(&SINGLE_AS_RESOLVER);

        let result = (|| {
            // Phys-driven migration finds the owner via rmap, resolves the AS,
            // and relocates the frame.
            let new_p = match migrate_frame(p) {
                Ok(x) => x,
                Err(e) => {
                    let _ = e;
                    return TestResult::Fail("migrate_frame failed for a live single-owner frame");
                }
            };
            if new_p == p {
                return TestResult::Fail("migrate_frame must move to a different frame");
            }
            // SAFETY: new_p is the live frame; identity-mapped.
            if unsafe { *(new_p.kernel_ptr::<u32>()) } != 0x5EED_1111 {
                return TestResult::Fail("migrate_frame did not preserve contents");
            }
            if aspace.regions_snapshot()[0].phys[0] != new_p {
                return TestResult::Fail("migrate_frame did not update Region.phys");
            }
            if crate::rmap::owner_count(p) != 0 || crate::rmap::owner_count(new_p) != 1 {
                return TestResult::Fail("migrate_frame did not move the rmap entry");
            }
            // An untracked frame is a clean NotMapped (never a wrong-page move).
            if migrate_frame(PhysAddr::new(0x0099_0000)) != Err(MigrateError::NotMapped) {
                return TestResult::Fail("untracked frame should yield NotMapped");
            }
            TestResult::Pass
        })();

        *TEST_AS.lock() = None;
        __reset_resolver_for_test();
        crate::rmap::__reset_for_test();
        result
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("memory/migrate", smoke_migrate_frame_relocates);

    // A resolver backed by several test-owned address spaces, so a fork-shared
    // frame's owners (parent + child) both resolve.
    #[cfg(target_arch = "x86_64")]
    static TEST_AS_LIST: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

    #[cfg(target_arch = "x86_64")]
    struct ListAsResolver;
    #[cfg(target_arch = "x86_64")]
    impl AddressSpaceResolver for ListAsResolver {
        fn resolve(&self, root: PhysAddr) -> Option<Arc<AddressSpace>> {
            TEST_AS_LIST.lock().iter().find(|a| a.root == root).cloned()
        }
    }
    #[cfg(target_arch = "x86_64")]
    static LIST_AS_RESOLVER: ListAsResolver = ListAsResolver;

    /// Multi-owner (COW) migration: a fork-shared frame must move to a fresh
    /// shared frame carried by BOTH owners, preserving contents, freeing the
    /// source, and keeping the copy COW so a later write still splits privately.
    #[cfg(target_arch = "x86_64")]
    fn smoke_migrate_frame_multi_owner() -> TestResult {
        use super::migrate_frame;
        use crate::frame::cow;
        use crate::{Region, RegionPerms, VirtAddr};

        __reset_resolver_for_test();
        crate::rmap::__reset_for_test();
        cow::__test_clear();
        TEST_AS_LIST.lock().clear();

        // SAFETY: paging + frame allocator live in the kernel suite.
        let parent = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => Arc::new(a),
            Err(_) => return TestResult::Skip("new_for_user failed"),
        };
        let p = match crate::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        // SAFETY: identity-mapped fresh frame, sole owner.
        unsafe { *(p.kernel_mut_ptr::<u32>()) = 0xC0FE_D00D };
        let va = VirtAddr::new(0x0000_0080_00B0_0000);
        if parent
            .map_region(Region {
                base: va,
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![p],
            })
            .is_err()
        {
            return TestResult::Fail("map_region parent failed");
        }
        // SAFETY: aspace owns a live root and the validated region.
        if unsafe { parent.materialize() }.is_err() {
            return TestResult::Fail("materialize parent failed");
        }
        // SAFETY: fork's documented contract; paging is live.
        let child = match unsafe { parent.clone_for_fork() } {
            Ok(c) => Arc::new(c),
            Err(_) => return TestResult::Fail("clone_for_fork failed"),
        };
        // SAFETY: child owns a fresh root; materialize maps its COW-shared page.
        if unsafe { child.materialize() }.is_err() {
            return TestResult::Fail("materialize child failed");
        }
        *TEST_AS_LIST.lock() = alloc::vec![parent.clone(), child.clone()];
        register_address_space_resolver(&LIST_AS_RESOLVER);

        let result = (|| {
            if crate::rmap::owner_count(p) != 2 || cow::count(p) != 2 {
                return TestResult::Fail("setup: fork-shared frame should have 2 owners/refs");
            }
            // Phys-driven migration walks BOTH owners and repoints them.
            let new = match migrate_frame(p) {
                Ok(x) => x,
                Err(e) => {
                    let _ = e;
                    return TestResult::Fail("migrate_frame failed for a live COW-shared frame");
                }
            };
            if new == p {
                return TestResult::Fail("migrate must move to a different frame");
            }
            // SAFETY: new is the live frame; identity-mapped.
            if unsafe { *(new.kernel_ptr::<u32>()) } != 0xC0FE_D00D {
                return TestResult::Fail("migrate did not preserve the shared page contents");
            }
            // Both owners now carry `new`; the source is fully released.
            if crate::rmap::owner_count(new) != 2 || cow::count(new) != 2 {
                return TestResult::Fail("migrated frame should be shared by both owners");
            }
            if crate::rmap::owner_count(p) != 0 || cow::count(p) != 0 {
                return TestResult::Fail("source frame should be fully released after migration");
            }
            if parent.regions_snapshot()[0].phys[0] != new
                || child.regions_snapshot()[0].phys[0] != new
            {
                return TestResult::Fail("both owners' Region.phys must point at the new frame");
            }
            // The copy is still COW: a child write must split to a private frame,
            // leaving the parent as the lone owner of `new`.
            // SAFETY: `va` names the child's present COW mapping of `new`.
            if unsafe { child.cow_split_on_write(va) }.is_err() {
                return TestResult::Fail("post-migrate cow_split_on_write failed");
            }
            // SAFETY: pairs with the split to rewrite the leaf PTE.
            if unsafe { child.remap_page(va) }.is_err() {
                return TestResult::Fail("post-migrate remap_page failed");
            }
            let c_priv = child.regions_snapshot()[0].phys[0];
            if c_priv == new {
                return TestResult::Fail("post-migrate write should split to a private frame");
            }
            if crate::rmap::owner_count(new) != 1 || cow::count(new) > 1 {
                return TestResult::Fail("after the split, only the parent should own `new`");
            }
            TestResult::Pass
        })();

        TEST_AS_LIST.lock().clear();
        __reset_resolver_for_test();
        crate::rmap::__reset_for_test();
        cow::__test_clear();
        result
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("memory/migrate", smoke_migrate_frame_multi_owner);

    #[cfg(target_arch = "x86_64")]
    fn smoke_compact_block_evacuates_movable() -> TestResult {
        use super::{compact_block, CompactError};
        use crate::{Region, RegionPerms, VirtAddr};

        __reset_resolver_for_test();
        crate::rmap::__reset_for_test();
        // SAFETY: paging + frame allocator live in the kernel suite.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => Arc::new(a),
            Err(_) => return TestResult::Skip("new_for_user failed"),
        };
        let f = match crate::alloc_frame() {
            Ok(x) => x.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let va = VirtAddr::new(0x0000_0080_00A0_0000);
        if aspace
            .map_region(Region {
                base: va,
                len: 4096,
                perms: RegionPerms::READ | RegionPerms::WRITE,
                phys: alloc::vec![f],
            })
            .is_err()
        {
            return TestResult::Fail("map_region failed");
        }
        // SAFETY: aspace owns a live root and the validated region.
        if unsafe { aspace.materialize() }.is_err() {
            return TestResult::Fail("materialize failed");
        }
        *TEST_AS.lock() = Some(aspace.clone());
        register_address_space_resolver(&SINGLE_AS_RESOLVER);

        let result = (|| {
            // The order-0 "block" is the single movable frame: compaction must
            // migrate it out (dest from elsewhere) and free the frame.
            match compact_block(f, 0) {
                Ok(1) => {}
                other => {
                    let _ = other;
                    return TestResult::Fail("compact_block should migrate the one movable frame");
                }
            }
            if aspace.regions_snapshot()[0].phys[0] == f {
                return TestResult::Fail("compaction did not move the page off its frame");
            }
            if crate::rmap::owner_count(f) != 0 {
                return TestResult::Fail("compaction left an rmap entry on the evacuated frame");
            }
            // An unmovable allocated frame (raw alloc, no rmap owner) cannot be
            // compacted and must not be touched.
            let g = match crate::alloc_frame() {
                Ok(x) => x.start_address(),
                Err(_) => return TestResult::Skip("frame allocator drained"),
            };
            let verdict = compact_block(g, 0);
            crate::frame::free_frame(crate::frame::PhysFrame::new(g));
            if verdict != Err(CompactError::Unmovable) {
                return TestResult::Fail("an unmovable allocated frame must yield Unmovable");
            }
            TestResult::Pass
        })();

        *TEST_AS.lock() = None;
        __reset_resolver_for_test();
        crate::rmap::__reset_for_test();
        result
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("memory/migrate", smoke_compact_block_evacuates_movable);

    #[cfg(target_arch = "x86_64")]
    fn smoke_compact_scan_guards_and_runs() -> TestResult {
        use super::compact_scan;
        // Degenerate arguments do nothing.
        if compact_scan(0, 4) != 0 || compact_scan(3, 0) != 0 {
            return TestResult::Fail("compact_scan must no-op on order 0 / max_blocks 0");
        }
        // With no resolver installed, any candidate blocks fail to migrate, so a
        // scan is a safe no-op returning 0 rather than panicking.
        __reset_resolver_for_test();
        if compact_scan(3, 4) != 0 {
            return TestResult::Fail("compact_scan with no resolver should migrate nothing");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("memory/migrate", smoke_compact_scan_guards_and_runs);
}
