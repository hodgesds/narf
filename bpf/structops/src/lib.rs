//! `narf-bpf-structops` — the `struct_ops!` extension mechanism.
//!
//! Runtime-supplied implementations of pluggable traits: the `struct_ops!`
//! macro, the [`StructOpsDesc`] descriptors it emits into the `narf.structops`
//! link section, generated target-specific builders, and owning
//! [`StructOpsLink`] attachments. Programs are loaded against one exact method
//! contract rather than attached from the generic BPF program pool.
//!
//! This lives in its own crate — separate from `narf-bpf` — so a subsystem that
//! wants a BPF-supplied policy (e.g. `narf-power`'s idle governor via
//! `narf-bpf-idle`) depends on the *seam* rather than the whole BPF runtime,
//! and so `narf-bpf` stays ignorant of the subsystems it plugs into. The macro
//! needs a few `narf-bpf` types at expansion time; the [`interp`], [`types`],
//! and [`reexport`] modules below re-export exactly those so the macro's
//! `$crate::…` paths resolve here.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod structops;

/// The `narf-bpf` runtime pieces the `struct_ops!` adapter runs a program
/// through. Re-exported so the macro's `$crate::interp::…` paths resolve in
/// this crate.
pub mod interp {
    pub use narf_bpf::interp::{Outcome, MAX_CTX_WORDS};
}

/// The return descriptor trait used by generated method contracts.
pub mod types {
    pub use narf_bpf::types::BpfRet;
}

/// Program-loading types used by generated target-specific builders.
#[doc(hidden)]
pub mod runtime {
    pub use alloc::sync::Arc;
    pub use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadError, LoadRequest};
}

/// Verifier enums used in generated descriptors.
#[doc(hidden)]
pub mod verifier {
    pub use narf_bpf_verifier::kfunc::Context;
}

/// The capability primitives the generated install fn is cap-gated on.
/// Re-exported so the macro's `$crate::reexport::…` paths resolve here.
pub mod reexport {
    pub use narf_capabilities::{Cap, CapKind, CapType, Grant};
}

pub use structops::{
    descriptors, installed_count, is_installed, validate, Binding, BpfCtxArg, MethodDesc, ProgSet,
    StructOpsDesc, StructOpsError, StructOpsLink,
};

/// Force-link anchor + boot-log stat: how many `struct_ops!` traits are
/// compiled into the image.
///
/// This crate carries the only writers of the `narf.structops` link section, so
/// `verification` anchors it with a `#[used]` static referencing this fn —
/// otherwise the rlib unit is dropped at link (`codegen-units > 1`) and the
/// descriptor table comes up empty.
#[must_use]
pub fn summary() -> usize {
    structops::descriptors().len()
}

#[cfg(feature = "kernel-test")]
mod tests;
