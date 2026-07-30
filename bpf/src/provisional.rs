//! Phase-1 provisional acceptance. **Delete when Stream A's abstract
//! interpreter lands.**
//!
//! `narf_bpf_verifier::verify` currently decodes the image, checks it cannot
//! run off the end, and then returns `VerifyError::NotImplemented` — it fails
//! closed, deliberately, so nothing accidentally ships on a half-verifier.
//! That leaves Phase 1 needing *some* acceptance rule to be able to run a
//! program at all.
//!
//! ## Why this is not fail-open
//!
//! The check below is structural: it proves nothing about values. What makes
//! Phase 1 safe is that the **interpreter never dereferences a
//! program-supplied address** (`crate::interp`). Every pointer a program can
//! hold indexes a synthetic region, every access is bounds-checked, and a
//! violation is a [`crate::interp::Trap`] that terminates the program. So the
//! worst a hostile program can do here is waste its own fuel.
//!
//! That property is exactly what the JIT gives up: JITed code accesses memory
//! directly and relies on the verifier plus the extable plus the arena guard
//! slots. So the ordering is not negotiable — **the JIT must not be enabled
//! until the real verifier is** — and this module existing is the reminder.
//!
//! What is checked here is what the interpreter cannot check cheaply at
//! runtime: that every branch and call target is in range, and that every
//! kfunc a program names exists and is callable from its context. Those are
//! load-time facts, and reporting them at load is worth far more to the
//! program author than a trap at fire time.

use narf_bpf_isa::{decode, CallTarget, Decoded, Imm64, Insn};
use narf_bpf_verifier::kfunc::Context;
use narf_bpf_verifier::VerifyError;

use crate::kfunc::Registry;

/// Structurally check a program.
///
/// # Errors
///
/// The first problem found, with the instruction index.
pub fn accept(insns: &[Insn], context: Context, registry: &Registry) -> Result<(), VerifyError> {
    if insns.is_empty() {
        return Err(VerifyError::Empty);
    }

    let mut i = 0usize;
    let mut saw_exit = false;
    while i < insns.len() {
        let at = i as u32;
        let (d, width) = decode(insns, i).map_err(|err| VerifyError::Decode { at, err })?;
        let next = i + width;

        match d {
            Decoded::Exit => saw_exit = true,

            Decoded::Jump { off } => check_target(at, next, i64::from(off), insns.len())?,
            Decoded::JumpCond { off, .. } | Decoded::MayGoto { off } => {
                check_target(at, next, i64::from(off), insns.len())?;
            }

            Decoded::Call(CallTarget::Subprog(rel)) => {
                check_target(at, next, i64::from(rel), insns.len())?;
            }
            Decoded::Call(CallTarget::Kfunc(id)) => {
                let entry = registry
                    .by_id(id)
                    .ok_or(VerifyError::UnknownKfunc { at, id })?;
                // Sleepability is a property of the hook (§4.5), so this is a
                // type error at load, not a runtime flag check.
                if !context.permits(entry.context) {
                    return Err(VerifyError::ContextMismatch {
                        at,
                        required: entry.context,
                        actual: context,
                    });
                }
            }

            // A map reference must go through the *real* verifier, never this
            // structural check.
            //
            // `narf_bpf_verifier` now resolves `LD_IMM64`'s map pseudo-forms
            // against `Program::maps`, and that resolution is load-bearing in
            // both directions: it is what bounds a map-value pointer to
            // `value_size`, and it is what requires a map *handle* to reach a
            // kfunc at offset zero. This function proves neither, so admitting
            // a map form here would hand a kfunc a `NonNull<BpfMap>` at a
            // program-chosen address. Rejecting is not "maps are unimplemented"
            // — it is that this path cannot discharge their obligations.
            Decoded::LoadImm64 {
                value: Imm64::Value(_),
                ..
            } => {}
            Decoded::LoadImm64 { .. } => {
                return Err(VerifyError::NotImplemented(
                    "a map or BTF reference needs the abstract interpreter, not the \
                     structural check",
                ))
            }
            Decoded::AddrSpaceCast { .. } => {
                return Err(VerifyError::NotImplemented("arenas land in Phase 3"))
            }

            // Writes to R10 are rejected up front for the same reason: the
            // interpreter would trap, but the author would rather know now.
            Decoded::Alu { dst, .. }
            | Decoded::Neg { dst, .. }
            | Decoded::Mov { dst, .. }
            | Decoded::Div { dst, .. }
            | Decoded::Mod { dst, .. }
            | Decoded::End { dst, .. }
            | Decoded::Load { dst, .. } => {
                if dst.is_frame_ptr() {
                    return Err(VerifyError::WriteToFramePointer { at });
                }
            }

            Decoded::Store { .. } | Decoded::Atomic { .. } => {}
        }

        i = next;
    }

    if !saw_exit {
        return Err(VerifyError::FallsOffEnd {
            at: (insns.len() - 1) as u32,
        });
    }
    Ok(())
}

fn check_target(at: u32, next: usize, off: i64, len: usize) -> Result<(), VerifyError> {
    let target = next as i64 + off;
    if target < 0 || target as usize >= len {
        return Err(VerifyError::BadTarget { at, target });
    }
    Ok(())
}
