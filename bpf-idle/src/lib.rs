//! `narf-bpf-idle` — the BPF idle governor.
//!
//! The first real `struct_ops` consumer: it binds a verified BPF program set to
//! `narf-power`'s pluggable idle-state selector, so a program supplied at
//! runtime chooses the CPU C-state that `power::select_idle_state` resolves.
//!
//! The shape is the reference the `struct_ops!` macro was written for. The macro
//! emits the [`BpfIdleGovernor`] trait, the `BpfIdleGovernorOps` adapter (which
//! runs the bound program), and the cap-gated `install_bpf_idle_governor` entry.
//! A small bridge `impl` maps the adapter onto `power`'s own hand-written
//! [`narf_power::IdleGovernor`] trait, and the `#[commit(...)]` committer moves
//! that adapter into `power`'s live `IDLE_GOVERNOR` slot — so `power` needs to
//! know nothing about BPF, and BPF needs to know nothing about `power`. This
//! crate is the only place the two meet.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::boxed::Box;

use narf_capabilities::{Cap, CapType, Grant};

narf_bpf_structops::struct_ops! {
    /// A BPF-supplied idle-state selection policy.
    ///
    /// Dispatched as [`narf_power::IdleGovernor`] through the bridge below, so
    /// `power`'s existing selection path resolves whatever C-state index the
    /// program returns against the live C-state table.
    #[cap(IdleGovernor)]
    #[install(install_bpf_idle_governor)]
    #[desc(BPF_IDLE_GOVERNOR_OPS)]
    #[adapter(BpfIdleGovernorOps)]
    #[commit(commit_bpf_idle_governor)]
    pub trait BpfIdleGovernor {
        /// Pick a C-state index for the given latency budget and predicted idle
        /// duration (both microseconds), exactly the arguments
        /// [`narf_power::IdleGovernor::select_idle_state`] receives.
        fn select_state(&self, latency_budget_us: u64, predicted_idle_us: u64) -> u32;
    }
}

/// Bridge the generated adapter onto `power`'s hand-written trait.
///
/// This is the whole point of the struct_ops shape: `power` dispatches through
/// `Box<dyn narf_power::IdleGovernor>` and cannot tell a BPF program set from a
/// native `LinearScan`. The C-state id fits a `u8`; a program returning a wider
/// value is truncated by the cast, and `power::select_idle_state` already
/// handles an index that names no registered state.
impl narf_power::IdleGovernor for BpfIdleGovernorOps {
    fn name(&self) -> &'static str {
        "bpf"
    }
    fn select_idle_state(
        &self,
        latency_budget_us: u64,
        predicted_idle_us: u64,
    ) -> narf_power::CStateIdx {
        narf_power::CStateIdx(BpfIdleGovernor::select_state(
            self,
            latency_budget_us,
            predicted_idle_us,
        ) as u8)
    }
}

/// The committer named by `#[commit(...)]`: move the verified adapter into
/// `power`'s live `IDLE_GOVERNOR` slot.
///
/// Generic over the cap marker because the generated install fn is; the
/// struct_ops layer has already proved the cap's kind is `IdleGovernor` before
/// this runs, and [`narf_power::install_idle_governor_boxed`] re-checks it. A
/// `power` refusal maps to [`StructOpsError::CommitFailed`], which the framework
/// only ever surfaces after the set is validated — so a malformed set never
/// reaches the slot.
fn commit_bpf_idle_governor<M: CapType>(
    cap: &Cap<M, Grant>,
    adapter: BpfIdleGovernorOps,
) -> Result<(), narf_bpf_structops::StructOpsError> {
    narf_power::install_idle_governor_boxed(cap, Box::new(adapter)).map_err(|_| {
        narf_bpf_structops::StructOpsError::CommitFailed("power rejected the governor")
    })
}

/// Force-link anchor.
///
/// Nothing is installed at boot — a BPF program installs the governor at runtime
/// via [`install_bpf_idle_governor`]. This entry exists so `frame` (under the
/// `bpf-idle` feature) and `verification` can reference the crate, keeping its
/// `narf.structops` descriptor and its smokes from being dropped at link
/// (`codegen-units > 1`).
pub fn register_initcalls() {
    // Touch the descriptor so the `#[used]` `narf.structops` entry the macro
    // emitted rides in with this referenced object.
    let _ = &BPF_IDLE_GOVERNOR_OPS;
}

#[cfg(feature = "kernel-test")]
mod tests;
