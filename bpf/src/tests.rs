//! In-kernel smokes for the BPF runtime.
//!
//! Positive *and* negative per behaviour, per `feedback_tests_are_the_value`.
//! These run inside the kernel because everything they exercise — the link
//! section, the per-CPU stack, the probe dispatcher — has no host analogue;
//! the pure logic is tested on the host in `narf-bpf-isa` and
//! `narf-bpf-verifier`.

use alloc::vec::Vec;

use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CallTarget, CondOp, Decoded, Insn, Reg, Size, Source};
use narf_bpf_verifier::kfunc::Context;
use narf_capabilities::{Cap, Grant};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::interp::{Outcome, Trap};
use crate::prog::{BpfProg, BpfProgLoad, LoadRequest};

// Minted once, at first use, and cached — `Cap::bootstrap()` allocates an
// object-table slot per call, so calling it per test would leak a slot per
// smoke run.
fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfProgLoad,
            Grant,
        >::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

/// Assemble a straight list of decoded instructions.
fn asm(items: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for d in items {
        out.extend_from_slice(encode(*d).slots());
    }
    out
}

fn mov_imm(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}
fn mov_reg(dst: u8, src: u8) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Reg(r(src)),
        sign_extend: None,
    }
}
fn ldx(dst: u8, src: u8, off: i16) -> Decoded {
    Decoded::Load {
        size: Size::Dw,
        sign_extend: false,
        dst: r(dst),
        src: r(src),
        off,
    }
}
fn ldx_size(size: Size, dst: u8, src: u8, off: i16) -> Decoded {
    Decoded::Load {
        size,
        sign_extend: false,
        dst: r(dst),
        src: r(src),
        off,
    }
}
fn st_imm(dst: u8, off: i16, v: i32) -> Decoded {
    Decoded::Store {
        size: Size::Dw,
        dst: r(dst),
        off,
        src: Source::Imm(v),
    }
}
fn alu_imm(op: AluOp, dst: u8, v: i32) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Imm(v),
    }
}
fn alu_reg(op: AluOp, dst: u8, src: u8) -> Decoded {
    Decoded::Alu {
        wide: true,
        op,
        dst: r(dst),
        src: Source::Reg(r(src)),
    }
}
fn jne_imm(dst: u8, v: i32, off: i16) -> Decoded {
    Decoded::JumpCond {
        wide: true,
        op: CondOp::Ne,
        dst: r(dst),
        src: Source::Imm(v),
        off,
    }
}
fn ja(off: i32) -> Decoded {
    Decoded::Jump { off }
}
fn call(name: &str) -> Decoded {
    Decoded::Call(CallTarget::Kfunc(crate::kfunc::id_for(name)))
}
fn call_id(id: i32) -> Decoded {
    Decoded::Call(CallTarget::Kfunc(id))
}
const EXIT: Decoded = Decoded::Exit;

fn load(
    name: &str,
    insns: Vec<Insn>,
    ctx: Context,
) -> Result<alloc::sync::Arc<BpfProg>, &'static str> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: alloc::string::String::from(name),
            insns,
            context: ctx,
        },
    )
    .map_err(|_| "load rejected")
}

// ── registry ────────────────────────────────────────────────────────

fn smoke_bpf_kfunc_registry_populated() -> TestResult {
    let Some(reg) = crate::kfunc::registry() else {
        return TestResult::Fail("kfunc registry not installed (initcall did not run)");
    };
    if reg.is_empty() {
        return TestResult::Fail("kfunc registry is empty — narf.kfuncs section was dropped");
    }
    if reg.by_name("narf_counter_add").is_none() {
        return TestResult::Fail("narf_counter_add missing from the registry");
    }
    if reg.by_name("narf_yield").is_none() {
        return TestResult::Fail("narf_yield missing from the registry");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_kfunc_registry_populated);

fn smoke_bpf_kfunc_id_matches_name_hash() -> TestResult {
    let Some(reg) = crate::kfunc::registry() else {
        return TestResult::Fail("kfunc registry not installed");
    };
    let Some(e) = reg.by_name("narf_counter_read") else {
        return TestResult::Fail("narf_counter_read missing");
    };
    // The id a `call` immediate carries must be computable from the name
    // alone, so a loader never has to read BTF to resolve a kfunc.
    if e.id() != crate::kfunc::id_for("narf_counter_read") {
        return TestResult::Fail("kfunc id is not the name hash");
    }
    if reg.by_id(crate::kfunc::id_for("no_such_kfunc")).is_some() {
        return TestResult::Fail("registry resolved a name that was never declared");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_kfunc_id_matches_name_hash);

fn smoke_bpf_kfunc_descriptors_validate() -> TestResult {
    let Some(reg) = crate::kfunc::registry() else {
        return TestResult::Fail("kfunc registry not installed");
    };
    for e in reg.all() {
        if e.desc().validate().is_err() {
            return TestResult::Fail("a registered kfunc descriptor failed validate()");
        }
        if e.shim as usize == 0 {
            return TestResult::Fail("a registered kfunc has a null shim");
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_kfunc_descriptors_validate);

// ── interpreter: positive ───────────────────────────────────────────

fn smoke_bpf_interp_returns_immediate() -> TestResult {
    // r0 = 42; exit
    let insns = asm(&[mov_imm(0, 42), EXIT]);
    let Ok(p) = load("ret42", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a trivial program");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(42)) => TestResult::Pass,
        Some(Outcome::Returned(v)) => {
            if v == 42 {
                TestResult::Pass
            } else {
                TestResult::Fail("wrong return value")
            }
        }
        Some(Outcome::Trapped(_)) => TestResult::Fail("trivial program trapped"),
        None => TestResult::Fail("per-CPU stack declined the first invocation"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_returns_immediate);

fn smoke_bpf_interp_reads_context() -> TestResult {
    // r0 = *(u64 *)(r1 + 8); exit   — the second context word.
    let insns = asm(&[ldx(0, 1, 8), EXIT]);
    let Ok(p) = load("ctxread", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a context read");
    };
    match p.run_atomic([11, 22, 33, 44], 4) {
        Some(Outcome::Returned(22)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("read the wrong context word"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("context read trapped"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_reads_context);

fn smoke_bpf_interp_stack_roundtrip() -> TestResult {
    // *(u64 *)(r10 - 8) = 0x1234; r0 = *(u64 *)(r10 - 8); exit
    let insns = asm(&[st_imm(10, -8, 0x1234), ldx(0, 10, -8), EXIT]);
    let Ok(p) = load("stack", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a stack round-trip");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(0x1234)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("stack read back the wrong value"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("stack round-trip trapped"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_stack_roundtrip);

fn smoke_bpf_interp_loop_terminates() -> TestResult {
    // r0 = 0; r1 = 10; loop { r0 += 1; r1 -= 1; if r1 != 0 goto loop } exit
    let insns = asm(&[
        mov_imm(0, 0),
        mov_imm(1, 10),
        alu_imm(AluOp::Add, 0, 1),
        alu_imm(AluOp::Sub, 1, 1),
        jne_imm(1, 0, -3),
        EXIT,
    ]);
    let Ok(p) = load("loop", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a loop — arbitrary loops are legal here");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(10)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("loop produced the wrong count"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("bounded loop trapped"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_loop_terminates);

fn smoke_bpf_interp_calls_kfunc() -> TestResult {
    const SLOT: u32 = 3;
    crate::kfuncs::reset_counter(SLOT as usize);
    // r1 = SLOT; r2 = 7; call narf_counter_add; exit  (r0 = pre-add value)
    let insns = asm(&[
        mov_imm(1, SLOT as i32),
        mov_imm(2, 7),
        call("narf_counter_add"),
        EXIT,
    ]);
    let Ok(p) = load("kfunc", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a kfunc call");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(0)) => {}
        Some(Outcome::Returned(_)) => {
            return TestResult::Fail("kfunc returned a stale pre-add value")
        }
        Some(Outcome::Trapped(_)) => return TestResult::Fail("kfunc call trapped"),
        None => return TestResult::Fail("per-CPU stack declined"),
    }
    if crate::kfuncs::counter(SLOT as usize) != 7 {
        return TestResult::Fail("kfunc did not take effect on the counter");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_interp_calls_kfunc);

/// The clobber program: `r3 = 0x55; r6 = 0x66; r1 = 0; call; r0 = r3 + r6`.
///
/// R1..R5 are caller-saved, so the read of `r3` after the call is a read of an
/// uninitialised register. That makes this program both a good verifier
/// negative *and* a good interpreter fixture, so the two tests below share it.
fn clobber_program() -> Vec<Insn> {
    asm(&[
        mov_imm(3, 0x55),
        mov_imm(6, 0x66),
        mov_imm(1, 0),
        call("narf_counter_read"),
        alu_reg(AluOp::Add, 3, 6),
        mov_reg(0, 3),
        EXIT,
    ])
}

/// `r1 = 0; r0 = *(u64 *)(r1 + 0); exit` — a null dereference.
fn wild_load_program() -> Vec<Insn> {
    asm(&[mov_imm(1, 0), ldx(0, 1, 0), EXIT])
}

/// Run an **unverified** instruction image straight through the interpreter.
///
/// Deliberately bypasses [`BpfProg::load`]. The interpreter's bounds checks
/// are defence in depth *behind* verification, and `crate::provisional`'s
/// safety argument leans on them directly — so they have to stay covered even
/// for programs the verifier now rejects outright. A test that can only reach
/// the interpreter through a passing `verify()` silently stops exercising this
/// layer the moment the verifier gets stricter, which is exactly what happened
/// when the real abstract interpreter landed.
fn run_unverified(insns: &[Insn], fuel: u64) -> Option<Outcome> {
    use crate::mem::BpfStack;
    let provider = crate::mem::PerCpuStackStub;
    let frame = provider.acquire(64)?;
    let registry = crate::kfunc::registry()?;
    let mut vm = crate::interp::Vm::new(
        crate::interp::VmProgram {
            insns,
            // No subprograms: `run_unverified` bypasses the verifier, so
            // there is no table to honour and a call falls back to
            // FRAME_BYTES.
            subprogs: &[],
            context: Context::Atomic,
            fuel,
        },
        [0; crate::interp::MAX_CTX_WORDS],
        4,
        frame,
        registry,
    );
    Some(crate::interp::drive(vm.run()))
}

fn smoke_bpf_verify_rejects_read_of_clobbered_arg_reg() -> TestResult {
    // The primary guarantee: because R1..R5 are caller-saved, reading r3 after
    // a call reads an uninitialised register, and the verifier must refuse the
    // program rather than leave the JIT free to miscompile it. Catching this
    // at load is strictly stronger than catching it at run time.
    match load("clobber", clobber_program(), Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("verifier accepted a read of a caller-saved register"),
    }
}
kernel_test_in!("bpf", smoke_bpf_verify_rejects_read_of_clobbered_arg_reg);

fn smoke_bpf_interp_call_clobbers_arg_regs() -> TestResult {
    // Defence in depth, with verification bypassed: the interpreter must model
    // the BPF ABI's caller-saved R1..R5 faithfully on its own. An interpreter
    // that quietly preserved them would disagree with the JIT, and the
    // disagreement would only surface once the JIT was enabled.
    match run_unverified(&clobber_program(), 64) {
        // r3 was clobbered to 0, r6 survived: 0 + 0x66.
        Some(Outcome::Returned(0x66)) => TestResult::Pass,
        Some(Outcome::Returned(0xBB)) => {
            TestResult::Fail("R1..R5 survived a call — they are caller-saved")
        }
        Some(Outcome::Returned(_)) => TestResult::Fail("unexpected value after a call"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("clobber program trapped"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_call_clobbers_arg_regs);

// ── interpreter: negative ───────────────────────────────────────────

fn smoke_bpf_verify_rejects_wild_load() -> TestResult {
    // The primary guarantee: a scalar is not a pointer, so a null dereference
    // must be rejected at load time.
    match load("wild", wild_load_program(), Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("verifier accepted a null dereference"),
    }
}
kernel_test_in!("bpf", smoke_bpf_verify_rejects_wild_load);

fn smoke_bpf_interp_wild_load_traps_not_faults() -> TestResult {
    // Defence in depth, with verification bypassed. This is the property
    // `crate::provisional` names as the reason the runtime is safe while the
    // verifier matures: a bad program must produce a diagnostic, never a
    // kernel page fault — whatever the verifier did or did not catch.
    match run_unverified(&wild_load_program(), 64) {
        Some(Outcome::Trapped(Trap::BadAccess { .. })) => TestResult::Pass,
        Some(Outcome::Trapped(_)) => TestResult::Fail("wrong trap for a wild access"),
        Some(Outcome::Returned(_)) => TestResult::Fail("wild access was not caught"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_wild_load_traps_not_faults);

fn smoke_bpf_interp_fuel_bounds_infinite_loop() -> TestResult {
    // goto -1 — an unconditional infinite loop, which the verifier is
    // *supposed* to accept (spec §1.1: termination is a runtime property).
    // Fuel is what stops it.
    let insns = asm(&[ja(-1), EXIT]);
    let Ok(p) = load("spin", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected an unbounded loop — fuel makes it legal");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => TestResult::Pass,
        Some(Outcome::Trapped(_)) => TestResult::Fail("infinite loop produced the wrong trap"),
        Some(Outcome::Returned(_)) => TestResult::Fail("infinite loop returned"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_fuel_bounds_infinite_loop);

fn smoke_bpf_load_rejects_unknown_kfunc() -> TestResult {
    let insns = asm(&[call_id(0x7FFF_FFFF), EXIT]);
    match load("badkfunc", insns, Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("load accepted a call to an unregistered kfunc"),
    }
}
kernel_test_in!("bpf", smoke_bpf_load_rejects_unknown_kfunc);

fn smoke_bpf_load_rejects_sleepable_kfunc_in_atomic() -> TestResult {
    // `narf_yield` declares `Context::Sleepable`. Attaching it to an atomic
    // program must fail at load, by type — not at fire time, by flag check.
    let insns = asm(&[call("narf_yield"), EXIT]);
    if load("yield-atomic", insns.clone(), Context::Atomic).is_ok() {
        return TestResult::Fail("atomic program accepted a sleepable kfunc");
    }
    // …and the same program is fine in a sleepable context.
    if load("yield-sleepable", insns, Context::Sleepable).is_err() {
        return TestResult::Fail("sleepable program rejected a sleepable kfunc");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_load_rejects_sleepable_kfunc_in_atomic);

fn smoke_bpf_load_rejects_out_of_range_jump() -> TestResult {
    let insns = asm(&[ja(9999), EXIT]);
    match load("badjump", insns, Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("load accepted a jump past the end of the program"),
    }
}
kernel_test_in!("bpf", smoke_bpf_load_rejects_out_of_range_jump);

fn smoke_bpf_load_rejects_empty_program() -> TestResult {
    match load("empty", Vec::new(), Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("load accepted an empty program"),
    }
}
kernel_test_in!("bpf", smoke_bpf_load_rejects_empty_program);

// ── sleepable path ──────────────────────────────────────────────────

fn smoke_bpf_sleepable_yield_completes() -> TestResult {
    // call narf_yield; r0 = 5; exit. The yield parks the future once, so this
    // exercises the async interpreter's resume path — not just its fast path.
    let insns = asm(&[call("narf_yield"), mov_imm(0, 5), EXIT]);
    let Ok(p) = load("yield", insns, Context::Sleepable) else {
        return TestResult::Fail("load rejected a sleepable program");
    };
    match crate::interp::drive(p.run_sleepable([0; 4], 4)) {
        Some(Outcome::Returned(5)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => {
            TestResult::Fail("sleepable program returned the wrong value")
        }
        Some(Outcome::Trapped(_)) => TestResult::Fail("sleepable program trapped"),
        None => TestResult::Fail("heap stack allocation failed"),
    }
}
kernel_test_in!("bpf", smoke_bpf_sleepable_yield_completes);

fn smoke_bpf_yield_does_not_refill_fuel() -> TestResult {
    // Spec §4.9: yielding lets other tasks interleave; it does not restore
    // fuel. A yield inside an unbounded loop must therefore still run out.
    let insns = asm(&[call("narf_yield"), ja(-2), EXIT]);
    let Ok(p) = load("yieldspin", insns, Context::Sleepable) else {
        return TestResult::Fail("load rejected the yield-loop program");
    };
    match crate::interp::drive(p.run_sleepable([0; 4], 4)) {
        Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => TestResult::Pass,
        Some(Outcome::Trapped(_)) => TestResult::Fail("wrong trap for a yielding infinite loop"),
        Some(Outcome::Returned(_)) => TestResult::Fail("yielding infinite loop returned"),
        None => TestResult::Fail("heap stack allocation failed"),
    }
}
kernel_test_in!("bpf", smoke_bpf_yield_does_not_refill_fuel);

// ── attach ──────────────────────────────────────────────────────────

fn smoke_bpf_probe_attach_fires() -> TestResult {
    use narf_tracing::dispatch::{self, ProbeArgs, ProbeHandlerInstall};

    const SLOT: u32 = 5;
    crate::kfuncs::reset_counter(SLOT as usize);

    //   r6 = *(u64 *)(r1 + 0)     ; ctx word 0, stashed callee-saved
    //   r1 = SLOT
    //   r2 = r6
    //   call narf_counter_add
    //   r0 = r6
    //   exit
    //
    // The stash must be R6..R9: the BPF ABI makes R1..R5 caller-saved, so a
    // call clobbers them. Reading the ctx into R3 and expecting it to survive
    // `call` is the classic version of this bug, and the interpreter models
    // the clobber faithfully rather than quietly preserving the register.
    let insns = asm(&[
        ldx(6, 1, 0),
        mov_imm(1, SLOT as i32),
        mov_reg(2, 6),
        call("narf_counter_add"),
        mov_reg(0, 6),
        EXIT,
    ]);
    let Ok(prog) = load("probe", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the probe program");
    };

    let attach_cap = Cap::<crate::prog::BpfAttach, Grant>::bootstrap();
    let install_cap = Cap::<ProbeHandlerInstall, Grant>::bootstrap();
    let probe_id = dispatch::reserve_probe_id();

    if crate::attach::attach_probe(&attach_cap, &install_cap, probe_id, prog.clone()).is_err() {
        return TestResult::Fail("attach_probe failed");
    }

    // Firing goes through the real dispatcher, so this also proves the
    // Stage-4 lock rework: under the old shape the handler ran with
    // `TABLE.inner` held.
    dispatch::fire(probe_id, ProbeArgs::two(6, 0));
    dispatch::fire(probe_id, ProbeArgs::two(7, 0));

    let _ = crate::attach::detach_probe(&install_cap, probe_id);

    if prog.runs() != 2 {
        return TestResult::Fail("probe fired but the program did not run twice");
    }
    if prog.traps() != 0 {
        return TestResult::Fail("attached program trapped");
    }
    if crate::kfuncs::counter(SLOT as usize) != 13 {
        return TestResult::Fail("counter did not accumulate 6 + 7 from the probe fires");
    }
    if prog.accumulated() != 13 {
        return TestResult::Fail("return values did not accumulate");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_probe_attach_fires);

fn smoke_bpf_probe_attach_rejects_sleepable_program() -> TestResult {
    use narf_tracing::dispatch::{self, ProbeHandlerInstall};

    let insns = asm(&[mov_imm(0, 1), EXIT]);
    let Ok(prog) = load("sleepy", insns, Context::Sleepable) else {
        return TestResult::Fail("load rejected a sleepable program");
    };
    let attach_cap = Cap::<crate::prog::BpfAttach, Grant>::bootstrap();
    let install_cap = Cap::<ProbeHandlerInstall, Grant>::bootstrap();
    let probe_id = dispatch::reserve_probe_id();
    // A probe site runs with IRQs masked, so it provides `Atomic` and only
    // `Atomic`. The mismatch is a type error at attach (spec §4.5).
    match crate::attach::attach_probe(&attach_cap, &install_cap, probe_id, prog) {
        Err(crate::AttachError::ContextMismatch) => TestResult::Pass,
        Err(_) => TestResult::Fail("attach failed for the wrong reason"),
        Ok(()) => {
            let _ = crate::attach::detach_probe(&install_cap, probe_id);
            TestResult::Fail("a sleepable program attached to an atomic hook")
        }
    }
}
kernel_test_in!("bpf", smoke_bpf_probe_attach_rejects_sleepable_program);

// ── struct_ops ──────────────────────────────────────────────────────

crate::struct_ops! {
    /// A minimal pluggable trait, declared here so the `struct_ops!` macro,
    /// the `narf.structops` section, and the cap-gated install path are all
    /// exercised without waiting for Phase 5's trampolines.
    #[cap(IdleGovernor)]
    #[install(install_bpf_demo_governor)]
    #[desc(DEMO_GOVERNOR_OPS)]
    #[optional(init)]
    pub trait DemoGovernor {
        /// Pick an idle state for an expected idle duration.
        fn select_state(&self, expected_idle_ns: u64) -> u32;
        /// Optional one-time setup.
        fn init(&self) -> i32;
    }
}

/// A native in-tree implementation.
///
/// The point of the whole `struct_ops!` design is that the trait comes out of
/// the macro *unchanged*, so a Rust impl needs to know nothing about BPF. This
/// is that claim, compiled.
struct NativeDemoGovernor;

impl DemoGovernor for NativeDemoGovernor {
    fn select_state(&self, expected_idle_ns: u64) -> u32 {
        if expected_idle_ns > 1_000_000 {
            2
        } else {
            0
        }
    }
    fn init(&self) -> i32 {
        0
    }
}

fn smoke_bpf_structops_native_impl_still_works() -> TestResult {
    let g = NativeDemoGovernor;
    if g.select_state(10) != 0 || g.select_state(2_000_000) != 2 || g.init() != 0 {
        return TestResult::Fail("native impl of a struct_ops trait misbehaved");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_structops_native_impl_still_works);

fn smoke_bpf_structops_descriptor_registered() -> TestResult {
    let all = crate::structops::descriptors();
    let Some(d) = all.iter().find(|d| d.name == "DemoGovernor") else {
        return TestResult::Fail("narf.structops section did not carry DemoGovernor");
    };
    if d.cap != narf_capabilities::CapKind::IdleGovernor {
        return TestResult::Fail("struct_ops descriptor carried the wrong CapKind");
    }
    if d.methods.len() != 2 {
        return TestResult::Fail("struct_ops descriptor has the wrong method count");
    }
    // `#[optional(init)]` must reach the descriptor, or a program set could
    // omit a required method and be installed anyway.
    if d.methods[0].optional || !d.methods[1].optional {
        return TestResult::Fail("#[optional] did not reach the method descriptors");
    }
    // The ctx tuple is the method's real argument list — one u64 here.
    if d.methods[0].ctx.len() != 1 {
        return TestResult::Fail("method ctx tuple was not derived from the signature");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_structops_descriptor_registered);

/// The install authority for the demo trait.
///
/// `power::IdleGov` is the real marker for `CapKind::IdleGovernor`; declaring
/// a local one keeps this crate off a `narf-power` dependency it otherwise has
/// no use for. `CapType::KIND` is what `structops::install` compares, and both
/// markers name the same kind.
#[derive(Copy, Clone, Debug)]
struct IdleGovInstall;
impl narf_capabilities::CapType for IdleGovInstall {
    const KIND: narf_capabilities::CapKind = narf_capabilities::CapKind::IdleGovernor;
}

fn smoke_bpf_structops_install_requires_matching_cap() -> TestResult {
    use crate::structops::{ProgSet, StructOpsError};

    let insns = asm(&[mov_imm(0, 1), EXIT]);
    let Ok(prog) = load("gov", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the governor program");
    };

    // Negative: the right shape, the wrong authority.
    let wrong = Cap::<BpfProgLoad, Grant>::bootstrap();
    let set = ProgSet::new().with("select_state", prog.clone());
    match crate::structops::install(&DEMO_GOVERNOR_OPS, &wrong, set) {
        Err(StructOpsError::WrongCapability { .. }) => {}
        _ => return TestResult::Fail("install accepted a capability of the wrong kind"),
    }

    // Negative: right authority, missing a required method.
    let right = Cap::<IdleGovInstall, Grant>::bootstrap();
    match install_bpf_demo_governor(&right, ProgSet::new()) {
        Err(StructOpsError::MissingMethod("select_state")) => {}
        _ => return TestResult::Fail("install accepted a set missing a required method"),
    }

    // Positive: the optional method may be omitted.
    let set = ProgSet::new().with("select_state", prog);
    if install_bpf_demo_governor(&right, set).is_err() {
        return TestResult::Fail("install rejected a complete program set");
    }
    if !crate::structops::is_installed("DemoGovernor") {
        return TestResult::Fail("installed set was not recorded");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_structops_install_requires_matching_cap);

fn smoke_bpf_interp_wrapping_ctx_access_traps() -> TestResult {
    // r0 = -1; r1 = *(u8 *)(r0 + 0)
    //
    // The ctx path computed `addr + len` unchecked. At `u64::MAX` that wraps
    // to 0, so `addr >= CTX_REGION` and `addr + len <= ctx_limit` were *both*
    // true and the load indexed a `[u64; 4]` far out of bounds — a kernel
    // panic, in the very layer `crate::provisional` nominates as the reason
    // the runtime is safe when the verifier is wrong. The stack path had used
    // `checked_add` all along, which is what made the asymmetry easy to miss.
    let insns = asm(&[mov_imm(0, -1), ldx_size(Size::B, 1, 0, 0), EXIT]);
    match run_unverified(&insns, 64) {
        Some(Outcome::Trapped(Trap::BadAccess { .. })) => TestResult::Pass,
        Some(Outcome::Trapped(_)) => TestResult::Fail("wrong trap for a wrapping access"),
        Some(Outcome::Returned(_)) => TestResult::Fail("wrapping access was not caught"),
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_interp_wrapping_ctx_access_traps);

fn smoke_bpf_percpu_frame_is_released_to_its_own_cpu() -> TestResult {
    // The per-CPU slot must be reusable after a program finishes. The bug
    // this guards: `release` used to re-read `current_cpu()` at drop, so a
    // task that migrated between acquire and drop cleared the *wrong* CPU's
    // flag — the original CPU's cell then stayed claimed forever and declined
    // every later program, while another CPU's live cell was handed out
    // twice. `StackFrame` is now `!Send` and carries its CPU index.
    //
    // A migration cannot be provoked from a smoke, so this checks the
    // observable consequence: repeated acquire/release cycles keep working
    // and nothing is declined.
    let before = crate::mem::declined_count();
    for _ in 0..64 {
        let insns = asm(&[mov_imm(0, 1), EXIT]);
        let Ok(p) = load("reuse", insns, Context::Atomic) else {
            return TestResult::Fail("load rejected a trivial program");
        };
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Returned(1)) => {}
            Some(_) => return TestResult::Fail("trivial program did not return 1"),
            None => return TestResult::Fail("per-CPU frame was not released"),
        }
    }
    if crate::mem::declined_count() != before {
        return TestResult::Fail("a frame leaked — a later acquire was declined");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_percpu_frame_is_released_to_its_own_cpu);

// ── subprogram calls ────────────────────────────────────────────────

fn subprog_call(rel: i32) -> Decoded {
    Decoded::Call(narf_bpf_isa::CallTarget::Subprog(rel))
}

fn smoke_bpf_subprog_frames_do_not_overlap() -> TestResult {
    // main:  *(u64*)(r10-8) = 0x11; call sub; r0 = *(u64*)(r10-8); exit
    // sub:   *(u64*)(r10-8) = 0x22; r0 = 0; exit
    //
    // The callee writes its own frame at the same *relative* offset. If the
    // frames overlap, main reads back 0x22.
    //
    // There was no subprogram-call test at all, which is how the frame sizing
    // came to disagree with the verifier in both directions: every frame got a
    // fixed 512 bytes regardless of what the verifier had modelled, so eight
    // tiny subprograms verified with a 64-byte budget and then exhausted the
    // region on the *first* call, while a single oversized callee verified and
    // then wrote below the region.
    let insns = asm(&[
        st_imm(10, -8, 0x11),
        subprog_call(2),
        ldx(0, 10, -8),
        EXIT,
        st_imm(10, -8, 0x22),
        mov_imm(0, 0),
        EXIT,
    ]);
    let Ok(p) = load("subcall", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a subprogram call");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(0x11)) => TestResult::Pass,
        Some(Outcome::Returned(0x22)) => TestResult::Fail("callee frame overlapped the caller's"),
        Some(Outcome::Returned(_)) => TestResult::Fail("unexpected value after a subprogram call"),
        Some(Outcome::Trapped(t)) => match t {
            Trap::StackExhausted { .. } => {
                TestResult::Fail("frame sizing exhausted the region on a two-frame program")
            }
            _ => TestResult::Fail("subprogram call trapped"),
        },
        None => TestResult::Fail("per-CPU stack declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_subprog_frames_do_not_overlap);

fn smoke_bpf_verify_rejects_excessive_call_depth() -> TestResult {
    // A chain deeper than the runtime's frame limit must be refused at load.
    // The verifier had no depth limit while the interpreter enforced one, so
    // such a program verified and then trapped — accepted-but-unrunnable is a
    // contract break even though it is not a safety hole.
    //
    // Nine frames: main plus eight callees, each calling the next.
    let mut items: Vec<Decoded> = Vec::new();
    let depth = 9usize;
    for _ in 0..depth - 1 {
        // Each level: call the next subprogram, then return 0.
        items.push(subprog_call(2));
        items.push(mov_imm(0, 0));
        items.push(EXIT);
    }
    items.push(mov_imm(0, 0));
    items.push(EXIT);
    match load("deep", asm(&items), Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("a call chain deeper than the frame limit was accepted"),
    }
}
kernel_test_in!("bpf", smoke_bpf_verify_rejects_excessive_call_depth);
