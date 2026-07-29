//! # `narf-bpf` — the BPF kernel runtime
//!
//! Program lifecycle, the `kfunc!` / `struct_ops!` extension macros and their
//! link-section registries, the fuel-metered interpreter, and the attach
//! adapters. The pure crates sit below: `narf-bpf-isa` owns the encoding,
//! `narf-bpf-verifier` owns verification, and both are host-testable because
//! they have no kernel dependencies.
//!
//! This crate must **not** depend on `narf-userspace` — userspace already
//! depends on `narf-tracing`, so that would be a cycle. `bpf(2)` lives in
//! `narf-userspace`, which depends on this.
//!
//! ## What Phase 1 is
//!
//! Everything here runs interpreted, and the interpreter never dereferences a
//! program-supplied address: pointers index synthetic regions and every access
//! is bounds-checked (see [`interp`]). That is what makes it safe to run
//! programs before the abstract interpreter lands, and it is what the JIT will
//! trade away for the extable and the arena guard slots — so the JIT must not
//! be enabled before the real verifier is. [`provisional`] is the reminder.
//!
//! Not here yet: maps and arenas (Phase 3), the JIT and the RX allocator
//! (Phase 4), struct_ops trampolines (Phase 5), and the net/perf attach
//! surfaces (Phase 6).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod attach;
pub mod interp;
pub mod kfunc;
pub mod kfuncs;
pub mod mem;
pub mod prog;
pub mod provisional;
pub mod structops;
pub mod types;

#[cfg(feature = "kernel-test")]
mod tests;

/// Types the `kfunc!` and `struct_ops!` macros name in their expansions.
///
/// Re-exported so a crate that invokes them needs no direct dependency on
/// `narf-bpf-verifier` or `narf-capabilities` — the same courtesy
/// `kernel_test!` extends by naming everything through `$crate`.
pub mod reexport {
    pub use narf_bpf_verifier::kfunc::{ArgDesc, ArgFlags, Context, PtrKind, TypeKey, TypeKind};
    pub use narf_capabilities::{Cap, CapKind, CapType, Grant};
}

pub use attach::{attach_probe, detach_probe, AttachError, ProbeProgram};
pub use interp::{Outcome, Trap, Vm};
pub use kfunc::{KfuncEntry, KfuncShim, Registry, RegistryError};
pub use prog::{BpfAttach, BpfProg, BpfProgLoad, LoadError, LoadRequest};
pub use structops::{ProgSet, StructOpsDesc, StructOpsError};
pub use types::{ArenaPtr, BpfObject, BpfType, Const, Guard, Owned, Rcu, SleepableRcu, Trusted};

/// Boot-time bring-up.
///
/// One `Subsys`-stage initcall: collect and validate the `narf.kfuncs` link
/// section. Everything else in this crate is lazy — a program cannot load
/// before the registry exists, and [`prog::BpfProg::load`] says so with
/// [`LoadError::NoRegistry`] rather than papering over the ordering.
///
/// The `Subsys` stage rather than `Early` because collection allocates (the
/// registry is a `Vec`), so the heap must be up. That is not the boot-order
/// constraint that matters for BPF, though: `bpf/specification/spec.md` §4.1's
/// kernel-VA slot reservation must happen *before the first user address
/// space* and is a direct call from `bare_main`, not an initcall. It arrives
/// with Stream B's arena work.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(
        Stage::Subsys,
        "bpf-kfunc-registry",
        || match kfunc::install() {
            Ok(_) => InitResult::Ok,
            // A malformed descriptor is a build-time bug in a `kfunc!`
            // invocation. Reporting it as an initcall error names the stage in the
            // boot log rather than panicking the kernel over a subsystem that
            // nothing has asked to use yet.
            Err(_) => InitResult::Error("malformed kfunc descriptor"),
        },
    );
}

/// A short one-line summary of the subsystem's state, for the boot log and
/// for the smokes.
#[must_use]
pub fn summary() -> (usize, usize) {
    (
        kfunc::registry().map_or(0, kfunc::Registry::len),
        structops::descriptors().len(),
    )
}
