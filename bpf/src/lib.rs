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
//! The [`ringbuf`] map kind is complete: a program produces to it through
//! kfuncs (`bpf_ringbuf_output`, and reserve/submit/discard), and a consumer
//! drains it either in-kernel or by `mmap`ing the fd's shared frames and
//! `poll`ing it (both on [`map::MapFile`]). The four keyed kinds and arenas are
//! in [`map`] and [`arena`].

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod arena;
pub mod attach;
pub mod attach_xdp;
#[cfg(feature = "bench")]
pub mod bench;
pub mod domain;
pub mod idreg;
pub mod interp;
pub mod jit_glue;
pub mod kfunc;
pub mod kfuncs;
pub mod link;
pub mod map;
pub mod mem;
pub mod prog;
pub mod provisional;
pub mod ringbuf;
pub mod stats;
pub mod types;

#[cfg(feature = "kernel-test")]
mod kfunc_tests;
#[cfg(feature = "kernel-test")]
mod tests;

/// Types the `kfunc!` macro names in its expansion.
///
/// Re-exported so a crate that invokes it needs no direct dependency on
/// `narf-bpf-verifier` or `narf-capabilities` — the same courtesy
/// `kernel_test!` extends by naming everything through `$crate`. The
/// `struct_ops!` macro lives in `narf-bpf-structops`, which carries its own.
pub mod reexport {
    pub use narf_bpf_verifier::kfunc::{ArgDesc, ArgFlags, Context, PtrKind, TypeKey, TypeKind};
    pub use narf_capabilities::{Cap, CapKind, CapType, Grant};
}

pub use attach::{attach_probe, detach_probe, AttachError, ProbeProgram};
pub use interp::{Outcome, Trap, Vm};
pub use kfunc::{KfuncEntry, KfuncShim, Registry, RegistryError};
pub use link::{BpfLink, LinkCaps, LinkError, LinkFile, LinkTarget};
pub use map::{ArrayMap, BpfMap, BpfMapCap, BpfMapOps, HashMap, MapAttr, MapError, MapKind};
pub use prog::{BpfAttach, BpfProg, BpfProgLoad, LoadError, LoadRequest};
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
    // The per-CPU BPF stack region. `memory::bpf_stack` allocates and maps it,
    // but nothing was calling `init`, so the region existed and had no users
    // and every atomic program ran on the interpreter-only stub instead. This
    // is the seam that connects the two halves of the subsystem.
    //
    // `Subsys` and after `bpf-kfunc-registry` because it needs
    // `bpf_text::slots_reserved()`, which `bare_main` establishes before any
    // initcall runs.
    narf_init::register(Stage::Subsys, "bpf-percpu-stack", || {
        let cpus = narf_lib::smp::cpu_count().max(1) as usize;
        match narf_memory::bpf_stack::init(cpus) {
            Ok(()) => InitResult::Ok,
            // Not fatal: `run_atomic` falls back to the stub, which declines
            // any program needing more than its much smaller frame. Degraded
            // rather than unsafe.
            Err(_) => InitResult::Error("bpf per-CPU stack region unavailable"),
        }
    });
    // Program-text reclamation. `narf-memory` cannot depend on `narf-rcu`
    // (the graph already runs rcu -> time -> console -> memory), so freeing
    // JIT text quarantines it and defers the actual reclaim through this hook.
    // Without it, freed text is quarantined forever.
    narf_memory::bpf_text::install_reclaim_hook(|alloc| {
        // `retire_box` frees the box after a grace period, so wrapping the
        // allocation in a type whose `Drop` reclaims it is how a *deferred
        // action* is expressed with the RCU API this tree has. A CPU may still
        // be executing the text when `free` is called; only the grace period
        // establishes that none is.
        narf_rcu::retire_box(alloc::boxed::Box::new(ReclaimOnGracePeriod(Some(alloc))));
    });
    // The benchmark suite, when built with it. Registers a `Late` initcall
    // that is a cmdline check and nothing else unless `bpf_bench` was asked
    // for — benchmarks are not tests and must not run as a side effect of
    // booting.
    #[cfg(feature = "bench")]
    bench::register();
}

/// Recover a loaded program from an `Arc<dyn FileOps>`'s `as_any`.
///
/// Lives here rather than in `narf-userspace` because the concrete fd type is
/// `narf-bpf`'s: the caller has an `Arc<dyn FileOps>` and no way to name what it
/// might downcast to. The same shape `setns(2)` uses to pull a namespace back
/// out of a file.
///
/// Returns `None` for any fd that is not a BPF program, which is what makes
/// `PERF_EVENT_IOC_SET_BPF` on the wrong fd an `EINVAL` rather than a
/// misinterpretation.
#[must_use]
pub fn prog_from_file_ops(any: &dyn core::any::Any) -> Option<alloc::sync::Arc<prog::BpfProg>> {
    any.downcast_ref::<prog::ProgFile>()
        .map(prog::ProgFile::prog)
}

/// Reclaims a text allocation when dropped, which `narf_rcu::retire_box`
/// arranges to happen after a grace period.
struct ReclaimOnGracePeriod(Option<narf_memory::bpf_text::TextAlloc>);

impl Drop for ReclaimOnGracePeriod {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            // Release the exception-table registration here, not in
            // `JitImage::drop`: `bpf_extable` requires unregistering only after
            // the grace period, and the fault handler may still be consulting
            // it until then. Leaving it registered leaks — and worse than
            // leaks, since `register_image` rejects overlapping ranges while
            // `bpf_text` reuses VAs, so a stale entry permanently blocks every
            // later program that lands on the same address.
            narf_memory::bpf_extable::unregister_image(a.va);
            narf_memory::bpf_text::reclaim(a);
        }
    }
}

/// A short one-line summary of the subsystem's state, for the boot log and
/// for the smokes.
#[must_use]
pub fn summary() -> (usize, usize) {
    (
        kfunc::registry().map_or(0, kfunc::Registry::len),
        idreg::progs().len(),
    )
}
