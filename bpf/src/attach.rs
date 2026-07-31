//! Attach adapters. Attach #1: tracing / dynamic probes.
//!
//! `ProbeArgs([u64; 4])` is already the BPF ctx-array shape, so
//! `ProbeHandler::fire` *is* the ABI boundary and there is no trampoline.
//! Linux needs one (`bpf_jit_comp.c:3150-3210` spills the target function's
//! native arguments into a stack array and passes that as the ctx) precisely
//! because its probe ABI is the target's real C signature; NARF's probe ABI is
//! the array already.
//!
//! ## The lock rule
//!
//! `bpf/specification/spec.md` §4.7: **no BPF-reachable path may re-enter
//! `narf_tracing::dispatch::*`**. Until this series, `dispatch::fire()`
//! invoked handlers *while holding* `TABLE.inner` with IRQs masked, so a
//! `probe!` inside a running program — or any kfunc that fired one —
//! self-deadlocked on a non-reentrant `IrqSafeSpinLock`. The recursion guard
//! `dispatch.rs`'s header contemplates would not have fixed it, because the
//! deadlock is on the lock, not on the recursion. The Stage-4 rework named at
//! `dispatch.rs:19` (drop the lock before invoking) landed with this attach
//! type as its prerequisite, not as a follow-up.
//!
//! Registration goes through `HandlerTable::register`, **not**
//! `install_probe_observer`: that is a single `AtomicUsize` slot already
//! claimed by `userspace::perf_event::ensure_trace_observers()`, and taking it
//! would silently break `perf record` on tracepoints.

use alloc::sync::Arc;

use narf_capabilities::{Cap, Grant};
use narf_tracing::dispatch::{HandlerTable, ProbeArgs, ProbeHandler, ProbeHandlerInstall};

use crate::interp::{Outcome, MAX_CTX_WORDS};
use crate::prog::{BpfAttach, BpfProg};

/// Why an attach failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    /// The `Cap<BpfAttach, Grant>` was revoked.
    AuthorityRevoked,
    /// The program was verified for a context this hook does not provide.
    ///
    /// Probe sites run with IRQs masked, so they provide
    /// `Context::Atomic` and nothing else — spec §4.5 makes this a type
    /// error at attach rather than a runtime flag check.
    ContextMismatch,
    /// `HandlerTable::register` refused: duplicate probe id, table full, or a
    /// revoked install cap.
    Register(narf_tracing::dispatch::RegisterError),
}

/// A verified program attached to a dynamic probe site.
#[derive(Debug)]
pub struct ProbeProgram {
    prog: Arc<BpfProg>,
}

impl ProbeProgram {
    /// The attached program.
    #[must_use]
    pub fn prog(&self) -> &Arc<BpfProg> {
        &self.prog
    }
}

impl ProbeHandler for ProbeProgram {
    fn fire(&self, args: ProbeArgs) {
        // Runs in the firing task's context with IRQs masked. Everything
        // reachable from here obeys invariant §4.6: no allocation, no lock a
        // caller might hold, and nothing that re-enters `dispatch::*`.
        //
        // `run_atomic` returning `None` means the per-CPU stack provider
        // declined — a nested fire, per §1.5's depth counter. Dropping the
        // invocation is the designed behaviour; corrupting the frame below it
        // is not.
        let ctx: [u64; MAX_CTX_WORDS] = args.0;
        match self.prog.run_atomic(ctx, MAX_CTX_WORDS) {
            Some(Outcome::Returned(_)) | None => {}
            Some(Outcome::Trapped(_)) => {
                // The trap is already counted on the program (`prog.traps()`).
                // Printing here would take the console lock from inside a
                // probe site, which is exactly the class of re-entrancy §4.7
                // forbids — so the diagnostic is *pulled* by whoever reads the
                // counters, never pushed from here.
            }
        }
    }
}

/// Attach `prog` to dynamic probe id `probe_id`.
///
/// # Errors
///
/// See [`AttachError`].
pub fn attach_probe(
    attach: &Cap<BpfAttach, Grant>,
    install: &Cap<ProbeHandlerInstall, Grant>,
    probe_id: u32,
    prog: Arc<BpfProg>,
) -> Result<(), AttachError> {
    attach
        .check_live()
        .map_err(|_| AttachError::AuthorityRevoked)?;
    if prog.context() != narf_bpf_verifier::kfunc::Context::Atomic {
        return Err(AttachError::ContextMismatch);
    }
    narf_tracing::dispatch::table()
        .register(install, probe_id, ProbeProgram { prog })
        .map_err(AttachError::Register)
}

/// Detach whatever handler is installed for `probe_id`.
///
/// # Errors
///
/// [`AttachError::AuthorityRevoked`] if the install cap was revoked.
pub fn detach_probe(
    install: &Cap<ProbeHandlerInstall, Grant>,
    probe_id: u32,
) -> Result<(), AttachError> {
    HandlerTable::unregister(narf_tracing::dispatch::table(), install, probe_id)
        .map_err(|_| AttachError::AuthorityRevoked)
}
