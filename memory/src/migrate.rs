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
    /// The frame has more than one owner (COW-shared). Rewriting every owner's
    /// PTE via [`crate::rmap::for_each_owner`] under a cross-AS lock order is the
    /// multi-owner migration follow-up.
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

/// Relocate physical frame `src` to a fresh frame, repointing its owner's
/// mapping, and return the new frame — the compaction primitive that evacuates a
/// specific frame so its buddy block can coalesce.
///
/// SINGLE-OWNER only for now: a COW-shared frame (more than one rmap owner) is
/// refused with [`MigrateError::MultiOwner`]; walking every owner and rewriting
/// its PTE is the multi-owner follow-up. The relocation re-checks under the
/// region lock that `src` is still mapped where rmap named it
/// ([`AddressSpace::relocate_frame_at`]), so a concurrent fault/unmap yields
/// [`MigrateError::Raced`] rather than moving the wrong page.
#[cfg(target_arch = "x86_64")]
pub fn migrate_frame(src: PhysAddr) -> Result<PhysAddr, MigrateError> {
    match crate::rmap::owner_count(src) {
        0 => return Err(MigrateError::NotMapped),
        1 => {}
        _ => return Err(MigrateError::MultiOwner),
    }
    let mut owner = None;
    crate::rmap::for_each_owner(src, |o| owner = Some(o));
    let owner = owner.ok_or(MigrateError::NotMapped)?;
    let aspace = resolve_address_space(owner.root).ok_or(MigrateError::NoAddressSpace)?;
    // SAFETY: `aspace` is a live, Arc-pinned root; `relocate_frame_at`
    // re-validates the page under the region lock and only moves it if it still
    // maps `src`.
    match unsafe { aspace.relocate_frame_at(owner.va, src) } {
        Ok(new) => Ok(new),
        Err(crate::address_space::AddressSpaceError::Unmapped) => Err(MigrateError::Raced),
        Err(_) => Err(MigrateError::Failed),
    }
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
}
