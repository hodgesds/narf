//! Basic-block boundaries and per-block instruction counts.
//!
//! Shared by every backend on purpose. The fuel bound is a *cross-backend*
//! contract: the interpreter burns one unit per instruction retired
//! (`bpf/src/interp.rs`), and a JIT that charges a different total for the same
//! program makes fuel exhaustion depend on whether the program happened to
//! clear `jit_glue`'s gates. Two copies of this computation could drift into
//! exactly that; one copy cannot.
//!
//! It is deliberately not a CFG. All per-block fuel needs is "how many
//! instructions run once this block is entered", and because a block ends at
//! every branch, every branch target, and every `exit`, entering a block
//! commits to retiring all of its instructions — which is what makes the
//! block-sized charge equal to the interpreter's per-instruction charge.

use alloc::vec;
use alloc::vec::Vec;

use narf_bpf_isa::{decode, Decoded};
use narf_bpf_verifier::VerifiedProgram;

use crate::JitError;

/// Instruction indices that begin a basic block.
///
/// Index 0, every branch target, and the instruction after every branch or
/// `exit`. The returned vector has `insns.len() + 1` entries: the trailing one
/// is the "one past the end" position a jump may legally target.
pub fn block_starts(prog: &VerifiedProgram) -> Result<Vec<bool>, JitError> {
    let n = prog.insns.len();
    let mut starts = vec![false; n + 1];
    if n == 0 {
        return Ok(starts);
    }
    starts[0] = true;
    let mut i = 0usize;
    while i < n {
        let (d, width) = decode(&prog.insns, i).map_err(|_| JitError::Decode { at: i as u32 })?;
        let next = i + width;
        let mut mark_target = |off: i64| -> Result<(), JitError> {
            let t = i as i64 + 1 + off;
            if t < 0 || t as usize > n {
                return Err(JitError::BadTarget { at: i as u32 });
            }
            starts[t as usize] = true;
            Ok(())
        };
        match d {
            Decoded::Jump { off } => {
                mark_target(i64::from(off))?;
                if next <= n {
                    starts[next] = true;
                }
            }
            Decoded::JumpCond { off, .. } => {
                mark_target(i64::from(off))?;
                if next <= n {
                    starts[next] = true;
                }
            }
            // `exit` ends a block; whatever follows begins one.
            Decoded::Exit => {
                if next <= n {
                    starts[next] = true;
                }
            }
            _ => {}
        }
        i = next;
    }
    Ok(starts)
}

/// Instructions in the block beginning at `i`.
///
/// The charge a backend must pay on entry to that block. `max(1)` because a
/// zero charge would let a block run for free, and the interpreter never
/// retires an instruction for nothing.
pub fn block_len(prog: &VerifiedProgram, starts: &[bool], i: usize) -> u32 {
    let mut count = 0u32;
    let mut k = i;
    while k < prog.insns.len() {
        if k != i && starts[k] {
            break;
        }
        let width = decode(&prog.insns, k).map(|(_, w)| w).unwrap_or(1);
        count += 1;
        k += width;
    }
    count.max(1)
}
