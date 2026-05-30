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
/// `narf_lib::id::DomainId::DRIVER_0..=DRIVER_5`. Bring-up code can
/// also pass concrete names ("net", "block", "graphics") so module
/// authors don't have to memorise numbers. Idempotent.
pub fn install_standard_domains() {
    register_domain("driver0", DomainId::DRIVER_0);
    register_domain("driver1", DomainId::DRIVER_1);
    register_domain("driver2", DomainId::DRIVER_2);
    register_domain("driver3", DomainId::DRIVER_3);
    register_domain("driver4", DomainId::DRIVER_4);
    register_domain("driver5", DomainId::DRIVER_5);
    register_domain("scratch", DomainId::SCRATCH);
    // Named aliases for the common driver subsystems.
    register_domain("net", DomainId::DRIVER_0);
    register_domain("block", DomainId::DRIVER_1);
    register_domain("graphics", DomainId::DRIVER_2);
    register_domain("input", DomainId::DRIVER_3);
    register_domain("crypto", DomainId::DRIVER_4);
    register_domain("misc", DomainId::DRIVER_5);
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
