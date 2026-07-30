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
//! ## Two-pass sizing, and why it needs care
//!
//! Branch displacements shrink as the image shrinks, so the emitter runs to a
//! fixpoint and then emits once more into the real buffer. That loop does not
//! converge for free. `arch/x86/net/bpf_jit_comp.c:70-113` documents a real
//! oscillation between a 2-byte and a 6-byte `je` paired with a 5-byte and a
//! 2-byte `jmp`, fixed by capping positive 8-bit jump offsets at 123 rather
//! than 127. [`is_imm8_branch`] does the same thing for the same reason —
//! this is the one part of Linux's JIT worth copying behaviour-for-behaviour,
//! because the bug is invisible until a program of exactly the wrong shape
//! appears.
//!
//! ## Fuel
//!
//! The interpreter burns fuel per instruction. Native code burns it **per
//! basic block**, decrementing by the block's instruction count on entry:
//! the same bound at coarser granularity, and one `sub`/`jz` pair instead of
//! one per instruction. A block that would take the counter below zero exits
//! with [`EXIT_OUT_OF_FUEL`].

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;

pub mod x86_64;

#[cfg(test)]
mod tests;

use narf_bpf_verifier::VerifiedProgram;

/// Return value a program's native code produces when its fuel runs out.
///
/// Distinct from any value a program can return itself, so the caller can
/// report exhaustion as the diagnostic §4.9 requires rather than as a result.
pub const EXIT_OUT_OF_FUEL: u64 = u64::MAX;

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
    /// The two-pass sizing loop did not reach a fixpoint.
    ///
    /// Should be impossible given [`is_imm8_branch`]'s cap; reported rather
    /// than looped on, because the alternative is a kernel hang at load time
    /// and this crate has no fuel of its own.
    SizingDiverged,
    /// The instruction stream could not be decoded. Should be unreachable —
    /// the verifier decoded it already — so it means the image changed
    /// underneath us.
    Decode { at: u32 },
}

/// Whether a branch displacement fits the short form.
///
/// **Capped at 123, not 127.** The five bytes of headroom stop the sizing
/// fixpoint oscillating: at exactly 127 a displacement can flip between the
/// short and long encodings on alternate passes, each choice making the other
/// correct. `arch/x86/net/bpf_jit_comp.c:70-113` carries the post-mortem of
/// exactly this bug, and the fix is this constant.
#[inline]
#[must_use]
pub const fn is_imm8_branch(disp: i64) -> bool {
    disp <= 123 && disp >= -128
}

/// Maximum sizing passes before declaring divergence.
pub const MAX_SIZING_PASSES: usize = 20;

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
