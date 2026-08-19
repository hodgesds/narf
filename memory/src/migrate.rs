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
}
