//! Scoped namespace/register-table ownership for serialized kernel smokes.

use core::sync::atomic::{AtomicBool, Ordering};

use super::{Namespace, NAMESPACE};

static ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct TestNamespace {
    namespace: Namespace,
    _regions: super::oregion::TestRegions,
}

/// Isolate a test's namespace and OpRegion tables; restore both at Drop.
///
/// # Safety
/// The caller must serialize all namespace/OpRegion parsing and evaluation
/// against this scope. No running production AML transaction may retain a
/// node, method-body offset or region reference into the replaced tables.
pub unsafe fn __test_namespace_scope() -> TestNamespace {
    assert!(
        !ACTIVE.swap(true, Ordering::AcqRel),
        "nested AML test namespace"
    );
    let namespace = {
        let mut namespace = NAMESPACE.lock();
        let saved = core::mem::take(&mut *namespace);
        // Explicit synthetic AML2+ profile confined to this unsafe test
        // scope; production derives the width only from the actual DSDT.
        namespace.integer_width = Some(64);
        saved
    };
    TestNamespace {
        namespace,
        _regions: super::oregion::TestRegions::capture(),
    }
}

impl Drop for TestNamespace {
    fn drop(&mut self) {
        core::mem::swap(&mut *NAMESPACE.lock(), &mut self.namespace);
        ACTIVE.store(false, Ordering::Release);
    }
}
