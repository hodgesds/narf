//! Turning a [`VerifiedProgram`] into executable text.
//!
//! The three components this joins — the emitter, `memory::bpf_text`, and
//! `memory::bpf_extable` — had never executed together before this module, so
//! it is deliberately the narrowest thing that can work rather than the most
//! capable. Native code gives up the interpreter's per-access bounds checks in
//! exchange for the verifier's proofs plus the exception table plus the arena
//! guard slots, and that trade is only sound where all three are actually in
//! place.
//!
//! ## The gates, and why each one exists
//!
//! A program is compiled only if **all** of these hold. Each corresponds to a
//! capability the emitter does not yet have, so each is a statement about this
//! backend rather than about BPF:
//!
//! 1. **The verifier returned `Ok`.** Never the `crate::provisional`
//!    fallthrough — provisional acceptance is *defined* as leaning on the
//!    interpreter's runtime bounds checks, which JITed code does not perform.
//!    This is the load-bearing gate; the other two are narrower.
//! 2. **No arena use.** The emitter does not pin a base register for the arena
//!    window, so an arena access would lower to a bare dereference of a
//!    32-bit-ish offset.
//! 3. **No fault sites.** The emitter does not record any, so a program with
//!    faulting accesses would have them unregistered — and `seal` requires a
//!    registered image, so this would fail closed anyway. Checked explicitly
//!    so the reason is visible rather than inferred from an error.
//! 4. ~~No back-edge.~~ **Lifted.** This gate stood in for missing fuel
//!    emission: the verifier deliberately does not prove termination
//!    (`an_unbounded_loop_verifies` is a passing test) because fuel bounds work
//!    at runtime, and native code that omitted fuel would have run
//!    `loop: r0 += 1; goto loop` forever. The emitter now burns fuel per basic
//!    block, so loops compile — which matters, because a loop is the only shape
//!    where native code is meaningfully faster than interpreting.
//! 5. **Only stack and context pointers are dereferenced.** Checked
//!    positively, by walking the program, rather than inferred from the set of
//!    instructions the emitter happens to refuse. Today gates 1–3 already
//!    imply it — every pointer-producing instruction is `Unsupported`, so only
//!    R10 and R1 can be a load base — but that is an emergent property, and
//!    the day someone teaches the emitter to emit `Call` it silently stops
//!    holding. An explicit check fails closed instead.
//!
//! Anything gated out runs interpreted, which is a complete implementation.

use narf_bpf_verifier::VerifiedProgram;
use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::bpf_text::{self, Jit, TextAlloc};

/// The ABI of a compiled program.
///
/// `(frame_top, ctx_ptr, fuel) -> (value, exhausted)`.
///
/// The prologue moves `frame_top` into the host register R10 maps to and
/// `ctx_ptr` into R1's, so the same image runs on the per-CPU region and on a
/// sleepable program's heap stack with no recompilation.
///
/// The `u128` return is SysV's `rax:rdx` pair: the low half is R0, the high half
/// is non-zero if the program ran out of fuel. Out of band deliberately — an
/// in-band sentinel was tried and removed, because the obvious choice
/// (`u64::MAX`) is exactly what `r0 = -1; exit` returns, so "exhausted" and
/// "returned -1" would have been the same answer.
pub type JitEntry = unsafe extern "C" fn(u64, u64, u64) -> u128;

/// A compiled program's text, freed on drop.
#[derive(Debug)]
pub struct JitImage {
    alloc: Option<TextAlloc>,
    entry: u64,
}

impl JitImage {
    /// The entry point.
    #[inline]
    #[must_use]
    pub fn entry(&self) -> JitEntry {
        // SAFETY: `entry` is the start of a sealed, executable image emitted by
        // `narf_bpf_jit` for a program the verifier accepted. The signature
        // matches the prologue the emitter generates — see [`JitEntry`].
        unsafe { core::mem::transmute::<u64, JitEntry>(self.entry) }
    }
}

impl Drop for JitImage {
    fn drop(&mut self) {
        if let Some(a) = self.alloc.take() {
            // Quarantines and defers through the RCU reclaim hook: a CPU may
            // still be executing this text.
            //
            // The extable registration is *not* released here. `bpf_extable`
            // requires unregistering only after the grace period, and the same
            // hook that reclaims the text does it — see
            // `crate::register_initcalls`. Dropping it here instead would have
            // been wrong twice over: too early for the fault handler, and
            // `register_image` rejects overlapping ranges while `bpf_text`
            // reuses VAs, so leaving it registered at all progressively bricks
            // the JIT — every later program landing on that VA fails to
            // register, permanently.
            bpf_text::free(a);
        }
    }
}

/// The kernel's own JIT authority.
///
/// Minted once at first use. Distinct from the privilege check on `bpf(2)` —
/// that one gates *userspace*, on credentials; this is the kernel's own
/// authority to make its own text executable, and there is no user on whose
/// behalf it could be checked.
fn jit_cap() -> &'static Cap<Jit, Grant> {
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<Jit, Grant>>> = IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        // `Cap::bootstrap()` allocates an object-table slot per call, so it is
        // minted once and leaked rather than called per program load.
        let c: &'static _ =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<Jit, Grant>::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

/// Why a program was not compiled. Never fatal — it runs interpreted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JitSkip {
    /// The verifier could not prove the program; `crate::provisional` accepted
    /// it structurally instead, and that acceptance depends on the
    /// interpreter's bounds checks.
    NotFullyVerified,
    /// Uses an arena; the emitter does not pin the window base.
    UsesArena,
    /// Has faulting accesses; the emitter does not record fault sites.
    HasFaultSites,
    /// The emitter declined an instruction.
    Unsupported,
    /// Text allocation, writing, registration, or sealing failed.
    TextUnavailable,
    /// Contains a back-edge, and no fuel is emitted to bound it.
    Unbounded,
    /// Dereferences something other than the frame or the context.
    UncheckedPointerBase,
}

/// Gates 4 and 5, as a single walk.
///
/// Deliberately a positive check. Both properties currently hold as a
/// consequence of which instructions the emitter refuses, and both would stop
/// holding silently the first time that set grows.
fn scan_program(insns: &[narf_bpf_isa::Insn]) -> Result<(), JitSkip> {
    use narf_bpf_isa::{Decoded, Reg};
    let mut i = 0usize;
    while i < insns.len() {
        // Undecodable is impossible here — the verifier decoded it — so treat
        // it as a reason not to compile rather than a reason to panic.
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Err(JitSkip::Unsupported);
        };
        match d {
            // `may_goto` still declines: it carries a hidden counter the
            // emitter does not model, which is separate from fuel.
            Decoded::MayGoto { .. } => return Err(JitSkip::Unbounded),
            // A load or store base must be the frame pointer or the context.
            // Any other register could hold a class the emitter would lower to
            // a bare dereference.
            Decoded::Load { src, .. } if src != Reg::R10 && src != Reg::R1 => {
                return Err(JitSkip::UncheckedPointerBase)
            }
            Decoded::Store { dst, .. } if dst != Reg::R10 && dst != Reg::R1 => {
                return Err(JitSkip::UncheckedPointerBase)
            }
            _ => {}
        }
        i += width;
    }
    Ok(())
}

/// Compile `v` and publish it as executable text.
///
/// `fully_verified` must be `false` when the program reached
/// `crate::provisional` rather than a clean `verify()` — see gate 1.
///
/// # Errors
///
/// [`JitSkip`], all of which mean "run this interpreted".
pub fn try_compile(v: &VerifiedProgram, fully_verified: bool) -> Result<JitImage, JitSkip> {
    if !fully_verified {
        return Err(JitSkip::NotFullyVerified);
    }
    if v.uses_arena {
        return Err(JitSkip::UsesArena);
    }
    if !v.fault_sites.is_empty() {
        return Err(JitSkip::HasFaultSites);
    }
    scan_program(&v.insns)?;

    let compiled = narf_bpf_jit::compile(v).map_err(|_| JitSkip::Unsupported)?;
    let cap = jit_cap();
    let a = bpf_text::alloc(cap, compiled.code.len(), 0).map_err(|_| JitSkip::TextUnavailable)?;
    if bpf_text::write(&a, 0, &compiled.code).is_err() {
        bpf_text::free(a);
        return Err(JitSkip::TextUnavailable);
    }

    // Register before sealing, in that order, because `seal` requires it —
    // spec §4.3 as a mechanism. The table is empty by gate 3; registering it
    // anyway is the point, since `seal` cannot tell an image with no faulting
    // instructions from one whose producer forgot.
    let lo = a.va;
    let hi = a.va + a.len as u64;
    // Gate 3 guarantees there is nothing to register, but registering anyway is
    // the point: `seal` cannot distinguish an image with no faulting
    // instructions from one whose producer forgot. The assertion catches the
    // day `record_fault` gains a caller and this silently starts discarding a
    // real table.
    debug_assert!(
        compiled.faults.0.is_empty(),
        "codegen produced fault entries that this path would discard"
    );
    if narf_memory::bpf_extable::register_image(lo, lo, hi, alloc::vec::Vec::new()).is_err() {
        bpf_text::free(a);
        return Err(JitSkip::TextUnavailable);
    }
    if bpf_text::seal(cap, &a).is_err() {
        narf_memory::bpf_extable::unregister_image(lo);
        bpf_text::free(a);
        return Err(JitSkip::TextUnavailable);
    }

    let entry = a.va + u64::from(compiled.entry_off);
    Ok(JitImage {
        alloc: Some(a),
        entry,
    })
}
