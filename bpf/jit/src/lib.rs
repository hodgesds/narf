//! # `narf-bpf-jit` — native code generation for verified BPF programs
//!
//! Takes a [`VerifiedProgram`] and emits machine code into a buffer the caller
//! provides. Deliberately knows nothing about *where* that buffer lives: the
//! executable-text allocator, the RW→RX seal, and the exception-table
//! registration are `narf-bpf`'s and `narf-memory`'s business. That keeps this
//! crate dependency-free of the kernel and testable on the host against golden
//! encodings.
//!
//! ## The order that matters
//!
//! Codegen produces both the bytes and a [`FaultTable`]. The caller must
//! register the fault table **before** sealing the text as executable — spec
//! §4.3, enforced by `memory::bpf_text::seal` returning `ExtableMissing`
//! rather than trusted. This crate makes that hard to get wrong by returning
//! the two together from one call: there is no way to obtain the code without
//! also obtaining the table it requires.
//!
//! ## No sizing fixpoint, and no fuel — read this before enabling anything
//!
//! Two things this crate does **not** do, both of which an earlier version of
//! these docs claimed it did:
//!
//! * **There is no sizing fixpoint.** Every branch is `rel32`, so nothing
//!   shrinks and nothing needs re-measuring. The convergence loop and the
//!   123-byte short-branch cap borrowed from
//!   `arch/x86/net/bpf_jit_comp.c:70-113` were removed: the emitter never
//!   selected a short form, so the machinery guarded a hazard it was not
//!   exposed to. It comes back with `rel8` selection, if that ever lands.
//! * **No fuel is emitted.** The verifier deliberately does not prove
//!   termination — `bpf/verifier/src/lib.rs` says so, and
//!   `an_unbounded_loop_verifies` is a passing test — so fuel is the *only*
//!   thing bounding a program's work (spec §4.9). Native code that omits it
//!   turns `loop: r0 += 1; goto loop` into an unterminated loop on a hook that
//!   may run with IRQs masked.
//!
//!   Until per-block fuel accounting exists, `narf_bpf::jit_glue` refuses any
//!   program containing a back-edge. That gate is what makes this crate safe to
//!   use at all, and it lives there rather than here because it is a statement
//!   about what the emitter lacks.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;

pub mod x86_64;

#[cfg(test)]
mod tests;

use narf_bpf_verifier::VerifiedProgram;

/// One instruction that may fault, and what to do about it.
///
/// The native counterpart of [`narf_bpf_verifier::FaultSite`]: the verifier
/// says *which BPF instruction*, codegen says *which native address*.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FaultEntry {
    /// Byte offset from the start of the emitted image to the faulting
    /// instruction. The caller adds the image's base address — codegen does
    /// not know it, which is what lets the same bytes be sized before they are
    /// placed.
    pub fault_off: u32,
    /// Byte offset to resume at: the instruction after the faulting one.
    pub fixup_off: u32,
    /// Host register to zero on fault, or `None` for a store.
    ///
    /// A host register number, not a BPF one — the trap handler writes the
    /// trap frame directly, so no translation table exists to drift out of
    /// step with the register allocation.
    pub dst_host_reg: Option<u8>,
    /// Whether this is an arena access, which reports differently.
    pub arena: bool,
}

/// Every faulting site in an emitted image, sorted by `fault_off`.
#[derive(Clone, Debug, Default)]
pub struct FaultTable(pub Vec<FaultEntry>);

/// A completed compilation.
#[derive(Clone, Debug)]
pub struct Compiled {
    /// The machine code.
    pub code: Vec<u8>,
    /// Faulting sites, which must be registered before the code is sealed.
    pub faults: FaultTable,
    /// Byte offset of the program's entry point within `code`.
    ///
    /// Non-zero once a CFI or endbr preamble is emitted; zero today. Returned
    /// explicitly rather than assumed, because Linux's equivalent assumption
    /// broke when FineIBT started placing its hash *before* the entry
    /// (`bpf_jit_comp.c:3902`).
    pub entry_off: u32,
}

/// Why compilation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JitError {
    /// An instruction this backend does not emit yet. Falls back to the
    /// interpreter rather than refusing the program.
    Unsupported { at: u32, what: &'static str },
    /// A jump or call target outside the program.
    BadTarget { at: u32 },
    /// The instruction stream could not be decoded. Should be unreachable —
    /// the verifier decoded it already — so it means the image changed
    /// underneath us.
    Decode { at: u32 },
}

/// Compile a verified program for the host architecture.
///
/// # Errors
///
/// [`JitError`]. `Unsupported` is not fatal to the caller — the interpreter
/// remains a complete implementation, so an un-emittable instruction means
/// "run this one interpreted", not "reject the program".
pub fn compile(prog: &VerifiedProgram) -> Result<Compiled, JitError> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::compile(prog)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // aarch64 runs interpreted until its emitter lands (spec §5). Reported
        // as `Unsupported` at instruction 0 so the caller's existing fallback
        // path handles it with no special case.
        let _ = prog;
        Err(JitError::Unsupported {
            at: 0,
            what: "no native backend for this architecture",
        })
    }
}
