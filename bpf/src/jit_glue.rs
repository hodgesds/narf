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
//! 2. ~~No arena use.~~ **Relaxed to "at most one arena".** The emitter now
//!    lowers an arena access to `slot_base + handle + off16` with the base
//!    supplied at entry, so the gate is no longer about a missing capability —
//!    it is about the *one* place the JIT's reachable set and the interpreter's
//!    admitted set differ. See "Lifting gate 2" below, and
//!    [`JitSkip::UsesArena`], which now means "more than one arena".
//! 3. **No non-arena fault sites.** Relaxed rather than lifted: the verifier
//!    records an arena access *as* a fault site, so the original gate refused
//!    every arena program by itself. Probe reads still have no lowering, so a
//!    fault site that is not an arena access is still a refusal — checked
//!    explicitly so the reason is visible rather than inferred from an error.
//! 4. ~~No back-edge.~~ **Lifted.** This gate stood in for missing fuel
//!    emission: the verifier deliberately does not prove termination
//!    (`an_unbounded_loop_verifies` is a passing test) because fuel bounds work
//!    at runtime, and native code that omitted fuel would have run
//!    `loop: r0 += 1; goto loop` forever. The emitter now burns fuel per basic
//!    block, so loops compile — which matters, because a loop is the only shape
//!    where native code is meaningfully faster than interpreting.
//! 5. **Only pointers the emitter can certify are dereferenced.** Checked
//!    positively, by walking the program, rather than inferred from the set of
//!    instructions the emitter happens to refuse. That distinction stopped
//!    being academic the day the emitter learned `Call`, which is exactly the
//!    day this gate's own doc-comment predicted:
//!
//!    * In a program with **no call**, R10 and R1 are both safe bases. R10 is
//!      the frame and cannot be written at all (the verifier rejects it), and
//!      with no call there is no producer of any pointer class other than the
//!      entry ones — so R1 is the context, or an offset from the frame copied
//!      into it, and either lowers correctly to a bare `[base + disp]`.
//!    * In a program **with** a call, only R10 is. A kfunc return can put an
//!      arena handle or a map-value pointer in R0, `r1 = r0` is an ordinary
//!      move, and the verifier will happily prove the resulting access
//!      in-bounds *for that class* — while native code would dereference the
//!      register verbatim. Nothing catches that, so R1 stops being admissible
//!      wholesale.
//!    * **An arena access is exempt**, whatever its base, because it does not
//!      lower to a bare dereference at all — it lowers to the slot-relative
//!      shape, whose reachable set is the slot's guards. "Which accesses are
//!      arena accesses" is
//!      [`narf_bpf_jit::arena_access_map`](narf_bpf_jit::arena_access_map), the
//!      same function the emitter uses, so the gate and the lowering cannot
//!      disagree about a single instruction.
//!
//!    That last exemption is where this gate stops being merely conservative
//!    and starts being a **second, independent brace** on the arena lowering.
//!    The dangerous direction is an arena access the fault-site map *misses*,
//!    which would lower as a bare dereference of a small integer. It cannot
//!    happen, and not because the map is trusted: a missed site is subject to
//!    the ordinary rule, so its base would have to be R10 — and R10 is the frame
//!    pointer, which the verifier refuses to let a program write, so it can
//!    never hold an arena handle. (R1 is not a way out either: `PtrClass::Arena`
//!    has only a kfunc return as a producer, so an arena program always contains
//!    a call, and a call is what withdraws R1.)
//!
//!    This is otherwise deliberately conservative: it also refuses programs that
//!    read their context before calling anything, which is sound but slower than
//!    it needs to be. Making it precise means the verifier publishing the
//!    pointer *class* at each access, which it does not today — and until it
//!    does, "refuse and interpret" is the only answer that cannot be wrong.
//!
//! Anything gated out runs interpreted, which is a complete implementation.
//!
//! ## Lifting gate 2 — **landed**
//!
//! Written down here because the analysis is most of the work and the
//! conclusion was counter-intuitive: **gate 2 was never what stopped arena
//! programs being compiled.** The prerequisite it was waiting on — call
//! emission — landed first, and the lowering this section specifies has now
//! landed too. What follows is kept in the present tense because every clause
//! of it is a property the code must still have; each subsection names what
//! discharges it.
//!
//! ### The blocker was `Decoded::Call`, not the arena — and it has gone
//!
//! `PtrClass::Arena` has exactly one producer in the verifier — a kfunc's
//! return descriptor, through `fixpoint.rs`'s `value_of`. Arithmetic and
//! `addr_space_cast` propagate the class but cannot create it, and no context
//! field or map value carries it. So *every* program that touches an arena
//! contains a `call`; while no backend emitted `Decoded::Call`, an arena
//! program was refused as `Unsupported` at the call, before any arena-specific
//! lowering was reached, and lifting gate 2 alone would have compiled nothing.
//!
//! Both backends emit kfunc calls now. Each of the pieces that made it a
//! feature in its own right is in place: the R4/R5 shuffle on x86-64 and the
//! whole-argument-list rotation on aarch64, the `x30` save the aarch64
//! prologue did not do, the SysV alignment step (the six pushes move `rsp` by
//! 48, which is `0 mod 16` and therefore changes nothing — the residue is what
//! was wrong), the kfunc-address table now on
//! [`VerifiedProgram::kfunc_calls`](narf_bpf_verifier::VerifiedProgram::kfunc_calls),
//! and the callee-context check. `an_arena_program_reaches_its_arena_access_once_the_call_is_emitted`
//! is what used to pin the old claim and now pins the new one, in bytes: an
//! arena program walks past its call into a **bare dereference of the handle**.
//!
//! So gate 2 went from the second of two refusals to the only one, which made
//! it *more* load-bearing than it was, not less. A differential test written
//! against a lifted gate 2 now finds its subject genuinely compiled — which is
//! what removed the vacuity hazard and made the work below testable.
//!
//! ### What the lowering has to be
//!
//! An in-program arena pointer is a slot-relative handle (`crate::arena`), so
//! the access is `slot_base + handle + off16` — Linux's `[r12 + reg + off]`
//! shape, with the base pinned for the program's whole body and supplied at
//! entry, since the same image must run against whatever slot the program was
//! given. That is a fourth entry argument on [`JitEntry`].
//!
//! Discharged by `narf_bpf_jit`'s `emit_arena_addr` on both backends. Neither
//! *pins* a register — x86-64 has no callee-saved one spare and aarch64 would
//! have had to grow every program's frame — so the base is parked in the
//! prologue's existing alignment padding and reloaded per access. That is
//! observationally the same thing: the base is available at every access in the
//! body, which is all "pinned" was ever asking for.
//!
//! Every address such an access can compute lies in
//! `[slot_base - ARENA_MAX_UNDERSHOOT_BYTES, slot_base + ARENA_SLOT_STRIDE)` —
//! see that constant in `memory::bpf_arena`, which is asserted against the
//! guards rather than argued. So no verified arena access can reach another
//! program's arenas, whatever it computes. Cross-program isolation is
//! structural and needs no per-access check, which is the whole bargain.
//!
//! The emitted sequence strengthens that from "no *verified* access" to "no
//! access": it zero-extends the handle from 32 bits, so the index is in
//! `[0, 2^32)` by construction and the reachable set is a property of the bytes
//! rather than of the verifier's bounds. No legitimate handle is affected —
//! every byte an arena can occupy is below `ARENA_USABLE_BYTES`, which is 4 GiB.
//!
//! ### The extable is mandatory, not an option
//!
//! Gate 3 cannot simply be kept: the verifier records an arena access *as* a
//! fault site (`fixpoint.rs`'s `access`), so gate 3 refuses every arena program
//! by itself. Nor can "require the arena fully populated" replace the extable.
//! Full population is already the default (`ProgArena::new` makes live equal
//! reserved) and it is not sufficient, because the verifier bounds a
//! displacement against a fixed 4 GiB window and not against the arena's
//! extent: the slot's null guard, the space past the last arena, and any gap
//! are all inside a verified access's reach and all unmapped. A JITed arena
//! access can therefore fault no matter how the arena is populated, so it
//! needs an `ExEntry` — which also means gate 3 must relax to "no *non-arena*
//! fault sites" rather than lift outright, since probe reads have no lowering
//! either.
//!
//! Discharged by [`try_compile`]'s `fault_sites.iter().any(|f| !f.arena)` test,
//! and by the `ExEntry` vector it now builds from `compiled.faults` — where it
//! used to register an empty one and assert that codegen had produced nothing.
//!
//! ### Where the fixup must resume, and why not "zero and continue"
//!
//! `bpf_extable`'s fixup zeroes a register and resumes at the next instruction,
//! which is what Linux's `ex_handler_bpf` does. Taking that shape verbatim
//! would make an out-of-bounds arena access *return a value* under the JIT and
//! `Trap::ArenaOutOfBounds` under the interpreter — the same program, two
//! verdicts, decided by whether it happened to clear these gates. That is
//! precisely the divergence class `crate::jit_glue`'s fuel accounting and
//! `run_atomic_native`'s ctx zero-fill were both fixed to avoid, and the
//! differential harness compares trap discriminants specifically to catch it.
//!
//! So the fixup should resume at a dedicated arena-fault epilogue that returns
//! with a distinct out-of-band status, and `run_atomic_native` should turn that
//! into `Trap::ArenaOutOfBounds`. This costs nothing in the extable — the entry
//! already carries an arbitrary `fixup_pc` — and satisfies the acceptance
//! criterion that a wild arena access be a diagnostic rather than a panic:
//! recovered by the extable, so not fatal, and stopped with a named trap, so
//! not silent.
//!
//! Discharged by `emit_arena_epilogue` on both backends, by `emit_pass`
//! rewriting every arena entry's `fixup_off` to it unconditionally, and by
//! `crate::prog::run_atomic_native` mapping `narf_bpf_jit::status::ARENA_FAULT`
//! to `Trap::ArenaOutOfBounds`. The epilogue also returns the offending
//! **handle** in the value half — the emitter folds the displacement into the
//! index register precisely so that it can — because
//! [`Trap::ArenaOutOfBounds`](crate::interp::Trap::ArenaOutOfBounds) exists to
//! name the value rather than leave it inferred. `at` and `len` are not
//! recoverable without a side table and are reported as zero, the same
//! concession `Trap::OutOfFuel { at: 0 }` already makes.
//!
//! ### One arena, or the two paths still disagree
//!
//! With that fixup, the JIT's reachable-and-mapped set is the slot's mapped
//! pages and the interpreter's is `arena::resolve_in`'s admitted set. They are
//! equal for a program with **one** arena and not otherwise: `ArenaSlot::carve`
//! places arenas contiguously, so with two adjacent arenas an 8-byte access
//! straddling the boundary succeeds natively and traps interpreted
//! (`resolve_in` admits a range only if it lies inside a single arena — see
//! `smoke_bpf_arena_straddling_two_arenas_is_refused`, which asserts the two
//! arenas are VA-contiguous first, so the refusal is the bound and not an
//! unmapped page). One arena is also the
//! only program-visible shape, since `narf_arena_base()` names the first and
//! nothing publishes the rest, so requiring it costs no capability. It does
//! mean the arena count has to reach this function.
//!
//! Discharged by [`try_compile`]'s `arena_count` parameter, which
//! `crate::prog::BpfProg::load_with_arena` fills from the [`ArenaGroup`] it was
//! handed — the same group the program will run against, so the number cannot
//! describe a different one. A program that touches an arena and has anything
//! other than exactly one is [`JitSkip::UsesArena`] and runs interpreted.

use narf_bpf_verifier::VerifiedProgram;
use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::bpf_text::{self, Jit, TextAlloc};

/// The ABI of a compiled program.
///
/// `(frame_top, ctx_ptr, fuel, arena_slot_base) -> (value, status)`.
///
/// The prologue moves `frame_top` into the host register R10 maps to and
/// `ctx_ptr` into R1's, so the same image runs on the per-CPU region and on a
/// sleepable program's heap stack with no recompilation. `arena_slot_base` is
/// the fourth argument for the same reason: the image must run against whatever
/// slot the program was given, so the base is passed rather than baked in. It is
/// parked in the prologue's alignment padding and read back at each arena
/// access; a program with no arena access never reads it, and passing zero for
/// one is harmless.
///
/// The `u128` return is SysV's `rax:rdx` pair: the low half is R0, the high half
/// is a [`narf_bpf_jit::status`] code. Out of band deliberately — an in-band
/// sentinel was tried and removed, because the obvious choice (`u64::MAX`) is
/// exactly what `r0 = -1; exit` returns, so "exhausted" and "returned -1" would
/// have been the same answer. A code rather than a boolean since the arena
/// lowering landed: on `ARENA_FAULT` the low half carries the offending handle,
/// which is the one case where it means something other than R0.
pub type JitEntry = unsafe extern "C" fn(u64, u64, u64, u64) -> u128;

/// A compiled program's text, freed on drop.
#[derive(Debug)]
pub struct JitImage {
    alloc: Option<TextAlloc>,
    entry: u64,
    /// Whether the image contains any arena access.
    ///
    /// Read by `crate::prog::run_atomic` as the belt to gate 2's brace: an image
    /// that dereferences the slot base must never be entered with a slot base it
    /// was not compiled against. Derived from the emitted fault table rather than
    /// from `VerifiedProgram::uses_arena`, because it is the *emitted code* that
    /// will do the dereferencing.
    arena: bool,
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

    /// Bytes of emitted text — what `bpf_prog_info.jited_prog_len` reports.
    ///
    /// The requested length, not the rounded-up chunk span, because that is
    /// what Linux reports for `prog->jited_len` and what a disassembler would
    /// need to bound its read.
    #[inline]
    #[must_use]
    pub fn text_len(&self) -> usize {
        self.alloc.as_ref().map_or(0, |a| a.len)
    }

    /// Whether the emitted code dereferences the arena slot base.
    #[inline]
    #[must_use]
    pub fn uses_arena(&self) -> bool {
        self.arena
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
    /// Touches an arena and does not have exactly one.
    ///
    /// Not "uses an arena" any more — that is compiled. With two arenas the
    /// JIT's reachable-and-mapped set stops equalling the interpreter's, because
    /// `ArenaSlot::carve` places them contiguously and an access straddling the
    /// boundary succeeds natively while `arena::resolve_in` refuses it. Zero
    /// arenas is refused for the mirror-image reason: there would be no slot base
    /// to enter the image with.
    UsesArena,
    /// Has faulting accesses that are not arena accesses — a probe read, which
    /// has no lowering on either backend.
    HasFaultSites,
    /// The emitter declined an instruction.
    Unsupported,
    /// Text allocation, writing, registration, or sealing failed.
    TextUnavailable,
    /// Contains a back-edge, and no fuel is emitted to bound it.
    Unbounded,
    /// Dereferences a register whose pointer class the emitter cannot certify:
    /// anything but the frame, or — in a program with no `call` — the context.
    UncheckedPointerBase,
}

/// Whether the program contains any `call`.
///
/// Load and store bases are admitted differently either side of this, because
/// a kfunc return is the only way a *new* pointer class enters a register —
/// see gate 5 in the module docs.
fn contains_a_call(insns: &[narf_bpf_isa::Insn]) -> Result<bool, JitSkip> {
    let mut i = 0usize;
    while i < insns.len() {
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Err(JitSkip::Unsupported);
        };
        if matches!(d, narf_bpf_isa::Decoded::Call(_)) {
            return Ok(true);
        }
        i += width;
    }
    Ok(false)
}

/// Gates 4 and 5, as a single walk.
///
/// Deliberately a positive check. Both properties currently hold as a
/// consequence of which instructions the emitter refuses, and both would stop
/// holding silently the first time that set grows.
fn scan_program(v: &VerifiedProgram) -> Result<(), JitSkip> {
    use narf_bpf_isa::{Decoded, Reg};

    let insns = &v.insns;
    // Whether R1 is still admissible as a dereference base. It is the context
    // pointer on entry and stays so as long as nothing can produce another
    // pointer class — and a kfunc return is exactly that. Whole-program rather
    // than flow-sensitive: a back-edge can route a call around to an
    // earlier-indexed access, so "no call *before* this instruction" is not a
    // property the instruction order can establish.
    let ctx_base_ok = !contains_a_call(insns)?;
    let base_ok = |r: Reg| r == Reg::R10 || (r == Reg::R1 && ctx_base_ok);
    // Which accesses the emitter will give the slot-relative shape. The *same*
    // function the emitter calls, so an instruction cannot be exempt here and
    // lowered as a bare dereference there.
    let arena = narf_bpf_jit::arena_access_map(v);

    let mut i = 0usize;
    while i < insns.len() {
        // Undecodable is impossible here — the verifier decoded it — so treat
        // it as a reason not to compile rather than a reason to panic.
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Err(JitSkip::Unsupported);
        };
        // An arena access needs no certified base: it is not lowered to
        // `[base + disp]` at all, and its reachable set is the slot's guards
        // whatever the register holds. See the gate-5 note in the module docs
        // for why a *missed* arena site cannot slip through this exemption.
        let arena_here = arena[i];
        match d {
            // `may_goto` still declines: it carries a hidden counter the
            // emitter does not model, which is separate from fuel.
            Decoded::MayGoto { .. } => return Err(JitSkip::Unbounded),
            // A load or store base must be one the emitter can certify. Any
            // other register could hold a class it would lower to a bare
            // dereference.
            Decoded::Load { src, .. } if !arena_here && !base_ok(src) => {
                return Err(JitSkip::UncheckedPointerBase)
            }
            Decoded::Store { dst, .. } if !arena_here && !base_ok(dst) => {
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
/// `arena_count` is how many arenas the program will actually run against — the
/// length of its [`ArenaGroup`](crate::arena::ArenaGroup), or zero if it has
/// none. Gate 2 needs it and the verifier does not have it: `narf-bpf-verifier`
/// bounds an arena displacement against a fixed window, never against a
/// particular program's extent, so the count can only come from the loader.
///
/// # Errors
///
/// [`JitSkip`], all of which mean "run this interpreted".
pub fn try_compile(
    v: &VerifiedProgram,
    fully_verified: bool,
    arena_count: usize,
) -> Result<JitImage, JitSkip> {
    if !fully_verified {
        return Err(JitSkip::NotFullyVerified);
    }
    // Gate 2, relaxed: exactly one arena, or none of the program's business.
    // See "One arena, or the two paths still disagree" in the module docs —
    // with two, an access straddling the boundary between two contiguously
    // placed arenas succeeds natively and traps interpreted.
    if v.uses_arena && arena_count != 1 {
        return Err(JitSkip::UsesArena);
    }
    // Gate 3, relaxed: an arena access *is* a fault site, so refusing all of
    // them refuses every arena program. A probe read still has no lowering.
    if v.fault_sites.iter().any(|f| !f.arena) {
        return Err(JitSkip::HasFaultSites);
    }
    scan_program(v)?;

    let compiled = narf_bpf_jit::compile(v).map_err(|_| JitSkip::Unsupported)?;
    let cap = jit_cap();
    let a = bpf_text::alloc(cap, compiled.code.len(), 0).map_err(|_| JitSkip::TextUnavailable)?;

    // Register **before writing**, not merely before sealing — spec §4.3 as a
    // mechanism rather than a convention.
    //
    // The order used to be write → register → seal, on the reasoning that `seal`
    // is the gate and it checks registration. That was wrong for every
    // allocation after the first in a pack: `alloc` first-fits into already
    // sealed packs, permissions are whole-pack, so the VA handed back is
    // *already executable*. `write` therefore laid fully-formed instructions
    // into executable memory with no extable coverage, and `seal` refusing
    // afterwards could not take that back. `bpf_text::write` now refuses in
    // that situation, so this order is enforced rather than merely documented.
    //
    // The table is registered even when it is empty, since neither `write` nor
    // `seal` can tell an image with no faulting instructions from one whose
    // producer forgot.
    let lo = a.va;
    let hi = a.va + a.len as u64;
    // Gate 3 admits only arena fault sites, so anything else here means the two
    // have drifted — and the consequence would be a probe fault recovering into
    // the arena epilogue, which is a wrong answer rather than a crash and so is
    // exactly the kind that goes unnoticed.
    debug_assert!(
        compiled.faults.0.iter().all(|f| f.arena),
        "codegen produced a non-arena fault entry that gate 3 should have refused"
    );
    // An arena entry resumes at the arena epilogue and zeroes nothing: the
    // program stops. `GpReg::NONE` is what says so — see `emit_arena_epilogue`
    // and the "why not zero and continue" note in the module docs.
    let entries: alloc::vec::Vec<_> = compiled
        .faults
        .0
        .iter()
        .map(|f| narf_memory::bpf_extable::ExEntry {
            fault_pc: lo + u64::from(f.fault_off),
            fixup_pc: lo + u64::from(f.fixup_off),
            dst: f
                .dst_host_reg
                .map_or(narf_memory::bpf_extable::GpReg::NONE, |r| {
                    narf_memory::bpf_extable::GpReg(r)
                }),
        })
        .collect();
    let arena = compiled.faults.0.iter().any(|f| f.arena);
    if narf_memory::bpf_extable::register_image(lo, lo, hi, entries).is_err() {
        bpf_text::free(a);
        return Err(JitSkip::TextUnavailable);
    }
    if bpf_text::write(&a, 0, &compiled.code).is_err() {
        narf_memory::bpf_extable::unregister_image(lo);
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
        arena,
    })
}
