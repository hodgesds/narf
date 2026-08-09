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
//! ## No sizing fixpoint on either backend
//!
//! Neither emitter runs a convergence loop, and each gets there a different
//! way:
//!
//! * **x86-64**: every branch is `rel32`, so nothing shrinks and nothing needs
//!   re-measuring. The convergence loop and the 123-byte short-branch cap
//!   borrowed from `arch/x86/net/bpf_jit_comp.c:70-113` were removed: the
//!   emitter never selected a short form, so the machinery guarded a hazard it
//!   was not exposed to. It comes back with `rel8` selection, if that ever
//!   lands.
//! * **aarch64**: fixed-size branch *shapes* rather than one branch width.
//!   `B` reaches ±128 MiB but `B.cond` only ±1 MiB, so a conditional jump
//!   always lowers to an inverted-condition `B.cond` over a `B` — two
//!   instructions whatever the distance. See [`aarch64`] for why a
//!   distance-dependent choice is what oscillates.
//!
//! ## Fuel, and how exhaustion is reported
//!
//! The verifier deliberately does not prove termination — fuel is the *only*
//! thing bounding a program's work (spec §4.9) — so native code must burn it or
//! `loop: r0 += 1; goto loop` runs forever on a hook that may have IRQs masked.
//!
//! Fuel is burned **per basic block**, decrementing by the block's instruction
//! count on entry: the same *total* as the interpreter's per-instruction burn,
//! at one subtract-and-branch per block instead of per instruction. Equal
//! totals is a correctness property, not an optimisation — a program that
//! completes JITed and exhausts fuel interpreted is a program whose verdict
//! depends on whether it happened to clear `jit_glue`'s gates. Both backends
//! compute the charge from the same `blocks` module so the two cannot drift.
//!
//! Exhaustion is reported **out of band**, in the second return register. An
//! in-band sentinel was tried and removed: the obvious choice, `u64::MAX`, is
//! exactly what `r0 = -1; exit` returns, so "ran out of fuel" and "returned -1"
//! would be the same answer. Both ABIs return a 128-bit value in a register
//! pair — SysV `rax:rdx`, AAPCS64 `x0:x1` — so the entry point is declared
//! `-> u128` and the high half carries the flag. The value and the verdict
//! travel together with no extra memory traffic and nothing to confuse.
//!
//! That flag is now a **status code** rather than a boolean ([`Status`]), for
//! the same reason it was out of band to begin with: the arena lowering below
//! needs a third way to stop, and squeezing it in band would repeat the mistake
//! the sentinel made.
//!
//! ## The arena lowering
//!
//! An in-program arena pointer is a slot-relative handle, so an arena access is
//! `slot_base + handle + off16` — Linux's `[r12 + reg + off]` shape. The slot
//! base is a **fourth entry argument**, because the same image must run against
//! whatever slot the program was given; each backend parks it in the one 8-byte
//! pad slot its prologue already claims for stack alignment and reloads it per
//! access, because neither register file has a callee-saved register spare.
//!
//! Two properties of the emitted sequence are load-bearing and are asserted by
//! golden tests rather than argued:
//!
//! * The handle is **zero-extended from 32 bits** into the index register. That
//!   is what makes the reachable set
//!   `[slot_base - 32768, slot_base + 2^32 + 32767)` a property of the emitted
//!   bytes rather than an inherited verifier invariant — it lands inside
//!   `memory::bpf_arena`'s
//!   `[slot_base - ARENA_MAX_UNDERSHOOT_BYTES, slot_base + ARENA_SLOT_STRIDE)`
//!   whatever the register happens to hold. No *legitimate* handle is affected:
//!   every byte any arena can occupy is below `ARENA_USABLE_BYTES`, which is
//!   4 GiB.
//! * The displacement is folded into the index register rather than left in the
//!   instruction, so at the moment of the fault that register holds exactly the
//!   handle the interpreter would have computed. The arena-fault epilogue moves
//!   it into the value half of the return, which is what lets the trap *name*
//!   the offending handle instead of reporting a zero.
//!
//! An arena access is identified by [`arena_access_map`] — the verifier already
//! records one as a fault site — and `narf_bpf::jit_glue`'s gate 5 consults the
//! *same* function, so the emitter and the gate cannot disagree about which
//! accesses get the arena shape.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;

pub mod aarch64;
mod blocks;
pub mod x86_64;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_aarch64;

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
    ///
    /// Always `None` when [`arena`](Self::arena) is set: an arena fault does not
    /// resume into the program at all, so there is no destination whose value
    /// would ever be read.
    pub dst_host_reg: Option<u8>,
    /// Whether this is an arena access, which reports differently.
    ///
    /// A probe read zeroes its destination and carries on, which is Linux's
    /// `ex_handler_bpf`. An arena access must not: the interpreter stops the
    /// program with `Trap::ArenaOutOfBounds`, and a JIT that returned a value
    /// instead would make the same program produce two verdicts depending on
    /// whether it happened to clear `jit_glue`'s gates. So `fixup_off` for an
    /// arena entry names the **arena-fault epilogue**, not the next
    /// instruction, and the program stops.
    pub arena: bool,
}

/// The out-of-band verdict a compiled program returns in the high half of its
/// `u128`.
///
/// A code rather than a boolean since the arena lowering landed: "ran out of
/// fuel" and "walked out of its arena" are different diagnoses, and the low
/// half is not available to distinguish them — it is the program's return
/// value on the one path where there is one.
pub mod status {
    /// Ran to `exit`; the low half is R0.
    pub const OK: u64 = 0;
    /// Fuel ran out. The low half is meaningless.
    pub const OUT_OF_FUEL: u64 = 1;
    /// An arena access faulted and was recovered by the exception table. The
    /// low half carries the offending **handle**, so the trap can name it.
    pub const ARENA_FAULT: u64 = 2;
    /// An arena atomic's effective address was not naturally aligned. The low
    /// half carries the offending handle, as it does for [`ARENA_FAULT`].
    pub const ARENA_UNALIGNED: u64 = 3;
}

/// Which instructions are arena accesses, indexed by instruction.
///
/// The verifier records an arena access as a [`narf_bpf_verifier::FaultSite`]
/// with `arena` set, which is the only signal either the emitter or
/// `narf_bpf::jit_glue`'s gate 5 has for "this dereference is slot-relative and
/// must not be lowered as a bare one". Both call *this* function, so the two
/// cannot drift: a site the emitter would lower as an arena access is exactly a
/// site the gate stops demanding a certified base register for.
///
/// Deliberately a scan and not a binary search over `fault_sites`. That slice
/// happens to be sorted, but `VerifiedProgram` is a public struct any caller can
/// build by literal, and the failure mode of a missed lookup is the one that
/// matters: an arena access lowered as a bare dereference of a small integer.
/// A linear build cannot miss one.
#[must_use]
pub fn arena_access_map(prog: &VerifiedProgram) -> Vec<bool> {
    let mut map = alloc::vec![false; prog.insns.len()];
    for f in &prog.fault_sites {
        if f.arena {
            if let Some(slot) = map.get_mut(f.insn_index as usize) {
                *slot = true;
            }
        }
    }
    map
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

/// Whether this build has a native backend at all.
///
/// True on both supported architectures now that [`aarch64`] emits — spec §5's
/// "aarch64 runs interpreted" no longer holds. Kept as a predicate rather than
/// deleted: it is what lets a test tell "no backend on this architecture" — a
/// legitimate skip — from "there is a backend and this program did not
/// compile", which must stay a failure. Conflating the two is how a
/// differential test starts passing vacuously, and a third architecture would
/// bring the distinction straight back.
#[must_use]
pub const fn has_backend() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

/// Compile a verified program for the host architecture.
///
/// # Errors
///
/// [`JitError`]. `Unsupported` is not fatal to the caller — the interpreter
/// remains a complete implementation, so an un-emittable instruction means
/// "run this one interpreted", not "reject the program".
pub fn compile(prog: &VerifiedProgram) -> Result<Compiled, JitError> {
    compile_resolved(prog, &[])
}

/// As [`compile`], but with the loader-resolved addresses for map pseudo-form
/// `LD_IMM64`s — `(instruction index, address)` pairs, sorted by index. The
/// verifier does not have these (an `Arc` pointer is a runtime value), so the
/// loader supplies them; a map form whose index is absent runs interpreted, as
/// every one did before.
pub fn compile_resolved(
    prog: &VerifiedProgram,
    map_imm64: &[(u32, u64)],
) -> Result<Compiled, JitError> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::compile_resolved(prog, map_imm64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::compile_resolved(prog, map_imm64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // Reported as `Unsupported` at instruction 0 so the caller's existing
        // fallback path handles it with no special case.
        let _ = (prog, map_imm64);
        Err(JitError::Unsupported {
            at: 0,
            what: "no native backend for this architecture",
        })
    }
}
