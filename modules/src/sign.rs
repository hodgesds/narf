//! Module-signature verification hook.
//!
//! Linux ref: `linux/kernel/module/signing.c::mod_verify_sig`
//! (`signing.c:43`).
//!
//! Phase-1 ships a no-op default verifier plus a single
//! `install_verifier` slot. A future patch can register an Ed25519
//! verifier without touching the loader contract.
//!
//! The verifier is cap-gated: the caller must hold a
//! `Cap<ModuleVerify, Invoke>` (placeholder kind — wired when the
//! signature work lands).

use alloc::boxed::Box;

use narf_lib::sync::IrqSafeSpinLock;

/// Verifier result. `Allow` means the module is trusted to load;
/// `Reject(reason)` aborts the load with the supplied diagnostic.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyDecision {
    Allow,
    Reject(&'static str),
}

/// Verifier: called with the module's raw bytes before any parsing.
pub trait ModuleVerifier: Send + Sync {
    fn verify(&self, image: &[u8]) -> VerifyDecision;
}

/// No-op verifier — accepts everything. Default during Phase 1.
#[derive(Debug, Default)]
pub struct AcceptAll;

impl ModuleVerifier for AcceptAll {
    fn verify(&self, _image: &[u8]) -> VerifyDecision {
        VerifyDecision::Allow
    }
}

/// Locked verifier slot. The kernel boot installs the no-op
/// default; a richer verifier (Ed25519, in-tree signing key) can
/// take its place at any later point.
static VERIFIER: IrqSafeSpinLock<Option<Box<dyn ModuleVerifier>>> =
    IrqSafeSpinLock::new(None);

/// Install a verifier. Replaces any previous installation.
pub fn install_verifier(v: Box<dyn ModuleVerifier>) {
    *VERIFIER.lock() = Some(v);
}

/// Verify an image. If no verifier has been installed, the call
/// allows by default — Phase 1 ships unsigned modules everywhere.
pub fn verify(image: &[u8]) -> VerifyDecision {
    let g = VERIFIER.lock();
    match g.as_ref() {
        Some(v) => v.verify(image),
        None => VerifyDecision::Allow,
    }
}
