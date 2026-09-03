//! Domain placement for loaded modules.
//!
//! Every NARF module declares a `target_domain=<name>` in its
//! manifest. The loader maps the module's text + rodata into that
//! domain's PKS-protected region (read-execute from in-domain,
//! no-access from out-of-domain) and the data + bss into the same
//! domain's RW region.
//!
//! Concretely, the kernel maintains a `name -> DomainId` table that
//! drivers populate at boot. The loader consults the table to pick
//! the runtime DomainId; if the module asks for a domain that doesn't
//! exist, load fails.
//!
//! This is a NARF-only mechanism — Linux has no equivalent because
//! it has no driver isolation.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// Errors from domain resolution.
#[derive(Debug, PartialEq, Eq)]
pub enum DomainError {
    /// `target_domain` references an unregistered name.
    Unknown(String),
}

/// One registered driver domain. The kernel boot path registers all
/// driver-domain names; modules subsequently target one of these.
#[derive(Clone, Debug)]
struct DomainEntry {
    name: String,
    id: DomainId,
}

static REGISTRY: IrqSafeSpinLock<Vec<DomainEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver-domain name -> id mapping. Idempotent on name.
pub fn register_domain(name: &str, id: DomainId) {
    let mut g = REGISTRY.lock();
    if let Some(e) = g.iter_mut().find(|e| e.name == name) {
        e.id = id;
    } else {
        g.push(DomainEntry {
            name: name.to_string(),
            id,
        });
    }
}

/// Look up a domain by name. None if not registered.
pub fn lookup_domain(name: &str) -> Option<DomainId> {
    let g = REGISTRY.lock();
    g.iter().find(|e| e.name == name).map(|e| e.id)
}

/// Number of registered domains. For tests.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Reset registry (test helper).
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}

/// Pre-populate with the standard driver-domain slots from
/// `narf_lib::id::DomainId::DRIVER_0..=DRIVER_4`, plus the BPF runtime's
/// own domain. Bring-up code can also pass concrete names ("net",
/// "block", "graphics") so module authors don't have to memorise
/// numbers. Idempotent.
pub fn install_standard_domains() {
    register_domain("driver0", DomainId::DRIVER_0);
    register_domain("driver1", DomainId::DRIVER_1);
    register_domain("driver2", DomainId::DRIVER_2);
    register_domain("driver3", DomainId::DRIVER_3);
    register_domain("driver4", DomainId::DRIVER_4);
    register_domain("bpf", DomainId::BPF);
    register_domain("scratch", DomainId::SCRATCH);
    // Named aliases for the common driver subsystems.
    register_domain("net", DomainId::DRIVER_0);
    register_domain("block", DomainId::DRIVER_1);
    register_domain("graphics", DomainId::DRIVER_2);
    register_domain("input", DomainId::DRIVER_3);
    register_domain("crypto", DomainId::DRIVER_4);
}

/// Resolve a domain name (from a manifest) to a DomainId, returning
/// `DomainError::Unknown` if it isn't registered. The empty string
/// (no `target_domain` declared) falls back to `SCRATCH`.
pub fn resolve(name: &str) -> Result<DomainId, DomainError> {
    if name.is_empty() {
        return Ok(DomainId::SCRATCH);
    }
    lookup_domain(name).ok_or_else(|| DomainError::Unknown(name.to_string()))
}

// ── Running module code inside its domain ──────────────────────────────

/// A narrowed PKS rights state, to be handed back to [`exit`].
///
/// Opaque and arch-neutral: on x86_64 it carries the saved `IA32_PKRS`, and
/// on every other target it carries nothing, because no backend there tags
/// pages by domain yet.
#[derive(Debug)]
pub struct DomainScope {
    #[cfg(target_arch = "x86_64")]
    saved: narf_arch::x86_64::pks::SavedPkrs,
}

/// Enter `domain` — deny every PKS domain except the kernel's and this one.
///
/// Called around each entry into module code (`narf_module_init`,
/// `narf_module_exit`). While the scope is open a module can reach its own
/// image and the kernel, and faults on the other fourteen domains. That is
/// the isolation DESIGN.md §2 describes: a buggy module cannot corrupt
/// another driver's memory.
///
/// The kernel's domain deliberately stays reachable. A module that could not
/// call an exported function or read a kernel global could not do anything,
/// and closing that direction instead would mean an MSR write on every
/// crossing — worth measuring before it is anyone's default.
///
/// Dispatches to whichever x86 backend is live. `Pks::enter_domain` is the
/// `DomainPrimitive` impl, which switches `IA32_PKRS` under PKS and swaps to
/// the domain's PCID-tagged CR3 under PCID -- this used to call
/// `pks::enter_domain` directly and gate on `pks::is_active()` alone, so a
/// module on an AMD or pre-SPR Intel part ran with the pages still carrying
/// their protection key and nothing consulting it. `bpf::domain::enter` has
/// dispatched for both backends all along; this is the same call.
///
/// Still a no-op when neither backend can enforce -- no PKS and no usable
/// CR4.PCIDE, or another architecture. `enter_domain` itself declines in that
/// case, and the boot log says so.
pub fn enter(domain: DomainId) -> DomainScope {
    #[cfg(target_arch = "x86_64")]
    {
        if narf_arch::x86_64::pks::is_active() || narf_arch::x86_64::pcid::is_active() {
            // SAFETY: one backend is live; both ids are 0..=15 (`DomainId` is
            // constructed from that range). Under PCID this swaps CR3 to the
            // domain's PML4 clone; under PKS it narrows IA32_PKRS.
            let saved = unsafe {
                <narf_arch::x86_64::Pks as narf_arch::DomainPrimitive>::enter_domain(
                    DomainId::FRAME.raw(),
                    domain.raw(),
                )
            };
            return DomainScope { saved };
        }
        // Inactive: capture the current value so `exit` restores exactly
        // what was there rather than assuming all-allow.
        DomainScope {
            saved: narf_arch::x86_64::pks::SavedPkrs(0),
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = domain;
        DomainScope {}
    }
}

/// Leave a scope opened by [`enter`], restoring the previous rights.
///
/// Must run even when the module's entry point returned an error: leaving
/// PKRS narrowed would deny the rest of the kernel access to every domain
/// but two, and the fault would land arbitrarily far from here.
pub fn exit(scope: DomainScope) {
    #[cfg(target_arch = "x86_64")]
    {
        if narf_arch::x86_64::pks::is_active() || narf_arch::x86_64::pcid::is_active() {
            // SAFETY: `scope.saved` came from the matching `enter_domain`, and
            // exit dispatches to the same backend that produced it. Unbalanced
            // here would leave PKRS narrowed or CR3 on a domain clone, and the
            // fault would land arbitrarily far away.
            unsafe {
                <narf_arch::x86_64::Pks as narf_arch::DomainPrimitive>::exit_domain(scope.saved)
            };
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = scope;
    }
}
