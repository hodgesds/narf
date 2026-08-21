//! Architecture-neutral task-context domain-rights state.
//!
//! The hardware state is per CPU, but scheduling treats it as task state.
//! Callers capture immediately after a task stops executing and restore the
//! executor's saved state before touching scheduler-owned data.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_arch::DomainPrimitive;
use narf_lib::id::DomainId;

#[cfg(target_arch = "aarch64")]
type ArchSavedState = narf_arch::aarch64::mte::SavedMteState;
#[cfg(target_arch = "x86_64")]
type ArchSavedState = narf_arch::x86_64::pks::SavedPkrs;

/// Complete domain state that follows a task across CPU switches.
///
/// The architecture value stays opaque outside `memory`; scheduler policy
/// receives neither this object nor a way to restore it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DomainSavedState {
    arch: ArchSavedState,
    current_domain: DomainId,
    active: bool,
}

impl DomainSavedState {
    /// Logical domain captured with the architecture rights state.
    #[inline]
    pub const fn current_domain(self) -> DomainId {
        self.current_domain
    }

    /// Whether the architecture backend was live at capture time.
    #[inline]
    pub const fn is_active(self) -> bool {
        self.active
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn backend_active() -> bool {
    // The x86 Domain implementation safely handles both live PKS and the
    // pre-init/inactive PCID sentinel path.
    true
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn backend_active() -> bool {
    // GCR_EL1 is architected only for MTE level >= 2. The boot path uses the
    // same feature gate before enabling tagged-access control.
    // SAFETY: ID_AA64PFR1_EL1 is readable at EL1 on every aarch64 CPU.
    unsafe { narf_arch::aarch64::Features::probe() }.mte >= 2
}

#[cfg(target_arch = "x86_64")]
const fn inactive_arch_state() -> ArchSavedState {
    narf_arch::x86_64::pks::SavedPkrs(0)
}

#[cfg(target_arch = "aarch64")]
const fn inactive_arch_state() -> ArchSavedState {
    narf_arch::aarch64::mte::SavedMteState { sctlr: 0, gcr: 0 }
}

/// Capture the current CPU's domain state into a task-portable value.
///
/// The wrapper supplies an additional compiler-fence pair around the HAL
/// operation. Individual register accessors are fenced as well; retaining the
/// outer pair makes the scheduling boundary explicit under fat LTO.
#[inline]
pub fn save_domain_state() -> DomainSavedState {
    let active = backend_active();
    compiler_fence(Ordering::SeqCst);
    let arch = if active {
        // SAFETY: `backend_active` establishes the architecture precondition;
        // the kernel is executing at ring 0 / EL1.
        unsafe { <narf_arch::Domain as DomainPrimitive>::save() }
    } else {
        inactive_arch_state()
    };
    compiler_fence(Ordering::SeqCst);
    DomainSavedState {
        arch,
        current_domain: DomainId::new(narf_arch::narf_arch_current_domain()),
        active,
    }
}

/// Restore a state previously returned by [`save_domain_state`].
#[inline]
pub fn restore_domain_state(saved: &DomainSavedState) {
    if !saved.active {
        return;
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the value was captured from this architecture's Domain backend.
    // Scheduler migration is restricted to homogeneous CPUs using that same
    // backend selection.
    unsafe {
        <narf_arch::Domain as DomainPrimitive>::restore(saved.arch);
    }
    compiler_fence(Ordering::SeqCst);
}
