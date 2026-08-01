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
            maps: alloc::vec::Vec::new(),
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
        if e.shim.addr() == 0 {
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
            maps: &[],
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
    /// A minimal pluggable trait, exercising the `struct_ops!` macro, the
    /// `narf.structops` section, the cap-gated install path, and the generated
    /// adapter that dispatches through BPF programs.
    #[cap(IdleGovernor)]
    #[install(install_bpf_demo_governor)]
    #[desc(DEMO_GOVERNOR_OPS)]
    #[adapter(BpfDemoGovernor)]
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

// ── integration: the runtime uses the real memory subsystem ─────────

fn smoke_bpf_uses_the_real_percpu_region() -> TestResult {
    // The two halves of this subsystem were built in parallel and, for a
    // while, never connected: `memory::bpf_stack` allocated and mapped a
    // 64 KiB-per-CPU region at boot, nothing called `init`, and every atomic
    // program ran on a 4 KiB interpreter-only stub instead — while the
    // verifier was proving programs against a 16 KiB ceiling. A program
    // needing more than 4 KiB was accepted and then declined at every
    // invocation.
    //
    // `StackFrame::cpu()` is `Some` only for a frame that came from the real
    // region, so it distinguishes "integrated" from "still on the stub"
    // without inspecting private state.
    if !crate::mem::region_ready() {
        return TestResult::Fail("bpf-percpu-stack initcall did not run");
    }
    use crate::mem::BpfStack;
    let Some(frame) = crate::mem::PerCpuRegion.acquire(64) else {
        return TestResult::Fail("the real per-CPU region declined a 64-byte frame");
    };
    if frame.cpu().is_none() {
        return TestResult::Fail("frame did not come from the per-CPU region");
    }
    if frame.len() != 64 {
        return TestResult::Fail("wrong frame length");
    }
    drop(frame);

    // And a program actually runs on it.
    let insns = asm(&[st_imm(10, -8, 0x5A), ldx(0, 10, -8), EXIT]);
    let Ok(p) = load("region", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a stack round-trip");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(0x5A)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("stack round-trip returned wrong value"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("program trapped on the real region"),
        None => TestResult::Fail("the real region declined the program"),
    }
}
kernel_test_in!("bpf", smoke_bpf_uses_the_real_percpu_region);

fn smoke_bpf_verified_ceiling_fits_the_real_region() -> TestResult {
    // The sizing agreement that was silently broken: whatever the verifier
    // accepts must fit in a real per-CPU frame, or a verified program is
    // declined at run time rather than rejected at load.
    let per_level = narf_memory::bpf_stack::bytes_per_level();
    if per_level < u64::from(narf_bpf_verifier::MAX_STACK_BYTES) {
        return TestResult::Fail("per-CPU frame is smaller than the verifier's ceiling");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_verified_ceiling_fits_the_real_region);

fn smoke_bpf_fresh_frame_is_zeroed() -> TestResult {
    // Pins a cross-crate obligation. The verifier deliberately loses per-byte
    // initialisation tracking for a caller frame passed to a callee, which is
    // only sound because those bytes belong to the same program — and that in
    // turn is only true because the runtime clears a frame before handing it
    // out. The per-CPU region is reused, so an unzeroed level would hand a
    // program the previous one's spills.
    //
    // Written dirty, released, re-acquired: the bytes must be zero again.
    use crate::mem::BpfStack;
    for provider_is_region in [false, true] {
        if provider_is_region && !crate::mem::region_ready() {
            continue;
        }
        let dirty: u8 = 0xA5;
        {
            let acquired = if provider_is_region {
                crate::mem::PerCpuRegion.acquire(128)
            } else {
                crate::mem::PerCpuStackStub.acquire(128)
            };
            let Some(mut f) = acquired else {
                return TestResult::Fail("provider declined a 128-byte frame");
            };
            f.bytes_mut().fill(dirty);
        }
        let again = if provider_is_region {
            crate::mem::PerCpuRegion.acquire(128)
        } else {
            crate::mem::PerCpuStackStub.acquire(128)
        };
        let Some(mut f) = again else {
            return TestResult::Fail("provider declined the second acquire");
        };
        if f.bytes_mut().iter().any(|&b| b != 0) {
            return TestResult::Fail("a reused frame still held the previous contents");
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_fresh_frame_is_zeroed);

fn smoke_bpf_fuel_bounds_straight_line_work() -> TestResult {
    // Fuel must bound *work*, not iterations. It used to burn only on
    // back-edges and calls, so a straight-line program cost one unit however
    // long it was — the default 2^20 tank permitted on the order of 7e10
    // instructions per invocation, which is no bound at all in an atomic probe
    // running with IRQs masked on someone else's timeslice.
    //
    // A straight line longer than the tank must therefore run out. Built with
    // a tiny tank so the test stays cheap.
    let mut items: Vec<Decoded> = Vec::new();
    for _ in 0..64 {
        items.push(alu_imm(AluOp::Add, 0, 1));
    }
    items.push(EXIT);
    let insns = asm(&items);
    match run_unverified(&insns, 8) {
        Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => {}
        Some(Outcome::Returned(_)) => {
            return TestResult::Fail("a straight line longer than the tank did not run out of fuel")
        }
        Some(Outcome::Trapped(_)) => return TestResult::Fail("wrong trap"),
        None => return TestResult::Fail("per-CPU stack declined"),
    }
    // And with enough fuel the same program completes, so the bound is a
    // bound and not a blanket refusal.
    match run_unverified(&insns, 1024) {
        Some(Outcome::Returned(_)) => TestResult::Pass,
        _ => TestResult::Fail("the program did not complete with ample fuel"),
    }
}
kernel_test_in!("bpf", smoke_bpf_fuel_bounds_straight_line_work);

// ── the sleepable kfunc ABI ─────────────────────────────────────────

fn smoke_bpf_sleepable_kfunc_suspends_and_resumes() -> TestResult {
    // r1 = 5; call narf_yield_n; exit  — in a Sleepable program.
    //
    // The uniform `extern "C" fn(u64x5) -> u64` shim had nowhere to put a
    // suspension, so `narf_yield()` was an interpreter intrinsic with a dead
    // body and *no* kfunc could actually sleep — "sleepable" bought yielding
    // and nothing else. `narf_yield_n` suspends an argument-dependent number of
    // times, which only a real future can do, and is the shape a blocking
    // kfunc (a filesystem walk, an iterator drain) would take.
    let insns = asm(&[mov_imm(1, 5), call("narf_yield_n"), EXIT]);
    let Ok(p) = load("sleepy", insns, Context::Sleepable) else {
        return TestResult::Fail("load rejected a sleepable program");
    };
    match crate::interp::drive(p.run_sleepable([0; 4], 4)) {
        Some(Outcome::Returned(5)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("wrong yield count"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("sleepable kfunc trapped"),
        None => TestResult::Fail("sleepable run declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_sleepable_kfunc_suspends_and_resumes);

fn smoke_bpf_atomic_program_cannot_call_a_sleepable_kfunc() -> TestResult {
    // The context rule, enforced by type rather than by a flag: an `async fn`
    // kfunc is Sleepable because it is `async`, so an atomic program calling it
    // must be refused at load. Nothing in the declaration could have said
    // otherwise.
    let insns = asm(&[mov_imm(1, 1), call("narf_yield_n"), mov_imm(0, 0), EXIT]);
    match load("atomic-sleeps", insns, Context::Atomic) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("an atomic program was allowed to call a sleepable kfunc"),
    }
}
kernel_test_in!(
    "bpf",
    smoke_bpf_atomic_program_cannot_call_a_sleepable_kfunc
);

// ── JIT ↔ interpreter differential ──────────────────────────────────

/// A corpus of programs that pass every `jit_glue` gate.
///
/// No back-edges, only R10/R1 dereferences, no arena, no faulting accesses —
/// so each of these actually compiles rather than silently falling back, which
/// a differential test must guarantee or it compares the interpreter with
/// itself and passes vacuously.
fn jit_corpus() -> Vec<(&'static str, Vec<Insn>)> {
    alloc::vec![
        ("ret_imm", asm(&[mov_imm(0, 42), EXIT])),
        (
            "add_imm",
            asm(&[mov_imm(0, 100), alu_imm(AluOp::Add, 0, 23), EXIT])
        ),
        (
            "sub_and_or_xor",
            asm(&[
                mov_imm(0, 0xFF),
                alu_imm(AluOp::Sub, 0, 0x0F),
                alu_imm(AluOp::And, 0, 0xF0),
                alu_imm(AluOp::Or, 0, 0x03),
                alu_imm(AluOp::Xor, 0, 0x01),
                EXIT,
            ])
        ),
        (
            "reg_to_reg",
            asm(&[
                mov_imm(6, 7),
                mov_imm(7, 6),
                mov_reg(0, 6),
                alu_reg(AluOp::Mul, 0, 7),
                EXIT,
            ])
        ),
        (
            "shift_imm",
            asm(&[mov_imm(0, 1), alu_imm(AluOp::Lsh, 0, 20), EXIT])
        ),
        (
            "shift_reg",
            asm(&[
                mov_imm(0, 1),
                mov_imm(1, 8),
                alu_reg(AluOp::Lsh, 0, 1),
                EXIT,
            ])
        ),
        (
            "arsh_negative",
            asm(&[mov_imm(0, -256), alu_imm(AluOp::Arsh, 0, 4), EXIT])
        ),
        (
            "stack_roundtrip",
            asm(&[
                mov_imm(0, 0x5EED),
                st_imm(10, -8, 0x1234),
                ldx(0, 10, -8),
                EXIT,
            ])
        ),
        (
            "stack_two_slots",
            asm(&[
                mov_imm(1, 11),
                mov_imm(2, 22),
                Decoded::Store {
                    size: Size::Dw,
                    dst: r(10),
                    off: -8,
                    src: Source::Reg(r(1)),
                },
                Decoded::Store {
                    size: Size::Dw,
                    dst: r(10),
                    off: -16,
                    src: Source::Reg(r(2)),
                },
                ldx(0, 10, -16),
                alu_reg(AluOp::Add, 0, 1),
                EXIT,
            ])
        ),
        ("ctx_read", asm(&[ldx(0, 1, 8), EXIT])),
        (
            "forward_branch_taken",
            asm(&[mov_imm(0, 1), jne_imm(0, 1, 1), mov_imm(0, 99), EXIT,])
        ),
        (
            "forward_branch_not_taken",
            asm(&[mov_imm(0, 5), jne_imm(0, 1, 1), mov_imm(0, 99), EXIT,])
        ),
        (
            "signed_compare",
            asm(&[
                mov_imm(0, -1),
                Decoded::JumpCond {
                    wide: true,
                    op: CondOp::Slt,
                    dst: r(0),
                    src: Source::Imm(0),
                    off: 1,
                },
                mov_imm(0, 7),
                EXIT,
            ])
        ),
        (
            "unsigned_compare",
            asm(&[
                mov_imm(0, -1),
                Decoded::JumpCond {
                    wide: true,
                    op: CondOp::Gt,
                    dst: r(0),
                    src: Source::Imm(0),
                    off: 1,
                },
                mov_imm(0, 7),
                EXIT,
            ])
        ),
    ]
}

fn smoke_bpf_jit_matches_the_interpreter() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // The only test that checks the emitter's *semantics*. Golden encodings
    // prove it emitted what was intended; the interpreter is the oracle for
    // whether the intent was right — and three of the four defects the JIT
    // review found were about what the code did not do rather than what it
    // encoded wrongly, which is exactly the class byte-level tests cannot see.
    let ctxs: [[u64; 4]; 3] = [[0; 4], [1, 2, 3, 4], [u64::MAX, 0, 0x5A5A, 1]];
    let mut compiled = 0usize;
    for (name, insns) in jit_corpus() {
        let Ok(p) = load(name, insns, Context::Atomic) else {
            return TestResult::Fail("load rejected a corpus program");
        };
        if !p.is_jited() {
            // A gate rejected it. Not a pass: a corpus entry that silently
            // falls back would make this test compare the interpreter against
            // itself.
            return TestResult::Fail("a corpus program was not compiled");
        }
        compiled += 1;
        for ctx in ctxs {
            let native = p.run_atomic(ctx, 4);
            let interp = p.run_atomic_interpreted(ctx, 4);
            match (native, interp) {
                (Some(Outcome::Returned(a)), Some(Outcome::Returned(b))) if a == b => {}
                (Some(Outcome::Returned(_)), Some(Outcome::Returned(_))) => {
                    return TestResult::Fail("native and interpreted results differ")
                }
                (None, _) | (_, None) => return TestResult::Fail("a run was declined"),
                _ => return TestResult::Fail("one path trapped and the other did not"),
            }
        }
    }
    if compiled == 0 {
        return TestResult::Fail("nothing in the corpus compiled");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_matches_the_interpreter);

fn smoke_bpf_jit_compiles_a_loop_and_runs_out_of_fuel() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // This test previously asserted the *opposite*: that a back-edge must never
    // reach the JIT, because no fuel was emitted and native code would have run
    // `loop: r0 += 1; goto loop` forever with IRQs masked. The emitter now burns
    // fuel per basic block, so the gate is lifted and the assertion inverts —
    // a loop must compile, and must still terminate.
    //
    // Loops are the only shape where native code is meaningfully faster than
    // interpreting, so this is the gate whose removal the whole JIT was for.
    let insns = asm(&[mov_imm(0, 0), alu_imm(AluOp::Add, 0, 1), ja(-2)]);
    let Ok(p) = load("spin-jit", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected an unbounded loop — fuel makes it legal");
    };
    if !p.is_jited() {
        return TestResult::Fail("a loop did not compile even though fuel is now emitted");
    }
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => {}
        Some(Outcome::Returned(_)) => {
            return TestResult::Fail("the native loop returned — it should have exhausted fuel")
        }
        Some(Outcome::Trapped(_)) => return TestResult::Fail("wrong trap"),
        None => return TestResult::Fail("run declined"),
    }
    // Interpreted, the same program must reach the same verdict. That is the
    // property fuel emission has to preserve: the two paths agree on
    // termination, not merely on results.
    match p.run_atomic_interpreted([0; 4], 4) {
        Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => TestResult::Pass,
        _ => TestResult::Fail("interpreted and native disagreed on exhaustion"),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_compiles_a_loop_and_runs_out_of_fuel);

fn smoke_bpf_jit_bounded_loop_completes() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // The other half: fuel must not fire on a loop that legitimately finishes.
    // Without this, "everything runs out of fuel" would pass the test above.
    //
    // r0 = 0; r1 = 8;  L: r0 += 3; r1 -= 1; if r1 != 0 goto L;  exit
    let insns = asm(&[
        mov_imm(0, 0),
        mov_imm(1, 8),
        alu_imm(AluOp::Add, 0, 3),
        alu_imm(AluOp::Sub, 1, 1),
        jne_imm(1, 0, -3),
        EXIT,
    ]);
    let Ok(p) = load("bounded", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a bounded loop");
    };
    if !p.is_jited() {
        return TestResult::Fail("bounded loop did not compile");
    }
    let native = p.run_atomic([0; 4], 4);
    let interp = p.run_atomic_interpreted([0; 4], 4);
    match (native, interp) {
        (Some(Outcome::Returned(a)), Some(Outcome::Returned(b))) if a == b && a == 24 => {
            TestResult::Pass
        }
        (Some(Outcome::Returned(a)), Some(Outcome::Returned(b))) if a == b => {
            TestResult::Fail("both paths agree but the value is wrong")
        }
        (Some(Outcome::Returned(_)), Some(Outcome::Returned(_))) => {
            TestResult::Fail("native and interpreted results differ")
        }
        _ => TestResult::Fail("a bounded loop did not complete on one of the paths"),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_bounded_loop_completes);

// ── heavy differential coverage ─────────────────────────────────────
//
// Combinatorial sweeps rather than more hand-written cases. The dimensions
// below are the ones that actually break a code generator:
//
//   * operand width — a 32-bit BPF op must zero-extend to 64, and the emitter
//     relies on x86's 32-bit-write rule to do it;
//   * register number — r8..r15 need REX.R/REX.B, and rbp/r13 need a forced
//     displacement byte, so a bug can hide in half the register file;
//   * boundary immediates — sign-extension of imm32 to 64 bits;
//   * shift counts above the operand width, which hardware masks and the
//     interpreter masks separately;
//   * both edges of every predicate, signed and unsigned.
//
// Every case asserts `is_jited()` before comparing. Without that a case that
// falls back compares the interpreter against itself and passes for free —
// which is how the missing `ST`-immediate encoding was found.

/// Sentinel meaning "this architecture has no native backend", so the caller
/// skips rather than failing. Compared by pointer-equal `&'static str`.
const NO_BACKEND: &str = "no native backend on this architecture";

/// Load, require compilation, run both ways, compare.
fn diff_case(name: &str, items: &[Decoded], ctx: [u64; 4]) -> Result<(), &'static str> {
    let p = load(name, asm(items), Context::Atomic).map_err(|_| "load rejected")?;
    diff_run(&p, ctx)
}

/// Run an already-loaded program both ways and compare, requiring that it
/// actually compiled.
///
/// Split out of [`diff_case`] so the arena cases — which need
/// `BpfProg::load_with_arena` and therefore cannot go through `load` — compare
/// by exactly the same rule, including the `is_jited` assertion. A second copy
/// of this comparison is how one of the two would quietly stop checking trap
/// discriminants.
fn diff_run(p: &BpfProg, ctx: [u64; 4]) -> Result<(), &'static str> {
    if !p.is_jited() {
        // On an architecture with a backend this is a real failure: a
        // differential test whose subject fell back compares the interpreter
        // with itself. Where there is no backend at all there is nothing to
        // compare, and the caller skips.
        return Err(if narf_bpf_jit::has_backend() {
            "not compiled — the comparison would be vacuous"
        } else {
            NO_BACKEND
        });
    }
    match (p.run_atomic(ctx, 4), p.run_atomic_interpreted(ctx, 4)) {
        (Some(Outcome::Returned(a)), Some(Outcome::Returned(b))) => {
            if a == b {
                Ok(())
            } else {
                Err("native and interpreted results differ")
            }
        }
        // Two traps agree only if they are the *same kind* of trap.
        //
        // This arm used to be `(Trapped(_), Trapped(_)) => Ok(())`, which made
        // the differential nearly vacuous for every failing program: `Trap` has
        // eight variants, and collapsing them meant a native run that exhausted
        // fuel matched an interpreted run that took a bad access. That is
        // exactly the divergence class this sweep exists to catch — a review
        // had already found the interpreter and JIT charging different fuel for
        // an unconditional back-edge, and this harness would not have noticed.
        //
        // Compared by discriminant rather than by value because the payloads
        // legitimately differ between backends: `at:` is a BPF instruction index
        // the JIT does not always have to hand, and native fuel exhaustion
        // synthesises `at: 0`. The *kind* is the part both must agree on.
        (Some(Outcome::Trapped(a)), Some(Outcome::Trapped(b))) => {
            if core::mem::discriminant(&a) == core::mem::discriminant(&b) {
                Ok(())
            } else {
                Err("native and interpreted trapped differently")
            }
        }
        (None, _) | (_, None) => Err("a run was declined"),
        _ => Err("one path trapped and the other did not"),
    }
}

// ── differential: arena programs ────────────────────────────────────
//
// `jit_glue` gate 2 used to refuse every arena program, so the sweep above has
// never covered the one lowering that has no bounds check in it at all. These
// are that coverage.
//
// Two things make them worth more than the ALU sweep per case. The subject is
// asserted `is_jited()` like every other differential case, and for an arena
// program that assertion is the *gate* under test — if gate 2 ever closes again
// these fail rather than silently comparing the interpreter with itself. And
// the comparison includes the trap discriminant, which is what catches the
// tempting-but-wrong fixup: Linux's `ex_handler_bpf` zeroes the destination and
// resumes, which would make an out-of-bounds arena access *return a value*
// natively and `Trap::ArenaOutOfBounds` interpreted.

use crate::arena::{kernel_arena_cap, ArenaGroup, ARENA_BASE_HANDLE};

/// `call narf_arena_base` — the only producer of an in-program arena handle.
fn call_arena_base() -> Decoded {
    call("narf_arena_base")
}

/// Build a group of `pages`-page arenas, one per entry, and load `items`
/// against it.
fn arena_prog(
    name: &str,
    items: &[Decoded],
    pages: &[usize],
) -> Result<alloc::sync::Arc<BpfProg>, &'static str> {
    let cap = kernel_arena_cap();
    let mut g = ArenaGroup::new(cap).map_err(|_| "ArenaGroup::new failed")?;
    for &p in pages {
        g.add(cap, p).map_err(|_| "adding an arena failed")?;
    }
    BpfProg::load_with_arena(
        load_cap(),
        LoadRequest {
            name: alloc::string::String::from(name),
            insns: asm(items),
            context: Context::Atomic,
            maps: alloc::vec::Vec::new(),
        },
        Some(alloc::sync::Arc::new(g)),
    )
    .map_err(|_| "load rejected")
}

fn smoke_bpf_jit_diff_arena_store_then_load() -> TestResult {
    // The positive case: a store and a load back through the same handle, at
    // three displacements including zero — zero being the one the emitter
    // shortens by skipping the fold into the index register.
    //
    // `r0` is the handle; the program writes 0x5A5A at `off`, reads it back and
    // returns it, so a lowering that addressed the wrong place would return
    // something other than the value it just wrote *and* disagree with the
    // interpreter.
    for off in [0i16, 8, 4088] {
        let items = [
            call_arena_base(),
            mov_reg(6, 0),
            st_imm(6, off, 0x5A5A),
            ldx(0, 6, off),
            EXIT,
        ];
        let p = match arena_prog("arena_diff_rw", &items, &[1]) {
            Ok(p) => p,
            Err(e) => return TestResult::Fail(e),
        };
        match diff_run(&p, [0; 4]) {
            Ok(()) => {}
            Err(e) if core::ptr::eq(e, NO_BACKEND) => return TestResult::Skip(NO_BACKEND),
            Err(e) => return TestResult::Fail(e),
        }
        // …and the value is the one written, so "both agree" is not two paths
        // agreeing on a wrong answer.
        if p.run_atomic([0; 4], 4) != Some(Outcome::Returned(0x5A5A)) {
            return TestResult::Fail("the arena round trip did not return what it wrote");
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_arena_store_then_load);

fn smoke_bpf_jit_diff_arena_out_of_bounds_traps_like_the_interpreter() -> TestResult {
    // **The acceptance criterion.** A wild arena access must produce a
    // diagnostic and not a kernel panic: recovered by the exception table so it
    // is not fatal, and stopped with a named trap so it is not silent.
    //
    // Every case here is *accepted by the verifier* — it bounds a displacement
    // against a fixed 4 GiB window, never against this program's extent — so
    // reaching the runtime is the premise and not an accident.
    //
    // Mutation: make the fixup zero-and-continue (resume at the next
    // instruction, zero the destination) and the native run returns instead of
    // trapping, which `diff_run`'s discriminant comparison catches here.
    let cases: [(&str, i16, i32); 4] = [
        // Just past the end of a one-page arena.
        ("one page past", 4096, 0),
        // Two pages past — well clear of any rounding.
        ("two pages past", 8192, 0),
        // The far end of the `off16` reach, still inside the slot.
        ("off16 maximum", 32760, 0),
        // Far past the arena by *arithmetic* rather than by displacement: one
        // gibibyte up the slot, which the verifier accepts and nothing maps.
        // This is the wildest address a verified program can name, and it is
        // the one that shows the recovery is not a property of being near the
        // arena.
        ("a gibibyte up the slot", 0, 1 << 30),
    ];
    for (what, off, bump) in cases {
        let mut items = alloc::vec![call_arena_base()];
        if bump != 0 {
            items.push(alu_imm(AluOp::Add, 0, bump));
        }
        items.push(st_imm(0, off, 0xBAD));
        items.push(mov_imm(0, 1));
        items.push(EXIT);
        let p =
            match arena_prog("arena_diff_oob", &items, &[1]) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail(
                    "the verifier rejected the program, so this no longer tests the runtime bound",
                ),
            };
        match diff_run(&p, [0; 4]) {
            Ok(()) => {}
            Err(e) if core::ptr::eq(e, NO_BACKEND) => return TestResult::Skip(NO_BACKEND),
            Err(_) => return TestResult::Fail(what),
        }
        // Not merely "the same kind of trap": the *right* kind, and naming the
        // handle. Without this the case would pass if both paths happened to
        // report, say, `BadAccess`.
        let want = ARENA_BASE_HANDLE
            .wrapping_add(bump as u64)
            .wrapping_add(off as u64);
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Trapped(Trap::ArenaOutOfBounds { handle, .. })) => {
                if handle != want {
                    return TestResult::Fail("the native trap named the wrong handle");
                }
            }
            Some(Outcome::Returned(_)) => {
                return TestResult::Fail("an out-of-bounds arena write was allowed natively")
            }
            _ => {
                return TestResult::Fail(
                    "the native out-of-bounds write trapped for the wrong reason",
                )
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf",
    smoke_bpf_jit_diff_arena_out_of_bounds_traps_like_the_interpreter
);

fn smoke_bpf_jit_arena_recovers_and_keeps_running() -> TestResult {
    // The "not fatal" half of the acceptance criterion, stated so that only
    // recovery can satisfy it: the program is run twice and a *third* program
    // runs afterwards. A fixup that did not actually return through the
    // epilogue — a wrong resume address, an unbalanced stack — would take the
    // kernel down here rather than producing a trap, and a leaked extable
    // registration would stop the later program compiling at all.
    let items = [
        call_arena_base(),
        st_imm(0, 8192, 0xBAD),
        mov_imm(0, 1),
        EXIT,
    ];
    let p = match arena_prog("arena_recover", &items, &[1]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    if !p.is_jited() {
        return if narf_bpf_jit::has_backend() {
            TestResult::Fail("the arena program did not compile, so nothing was recovered")
        } else {
            TestResult::Skip(NO_BACKEND)
        };
    }
    for _ in 0..2 {
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Trapped(Trap::ArenaOutOfBounds { .. })) => {}
            _ => return TestResult::Fail("the recovered fault did not surface as a trap"),
        }
    }
    // Something ordinary still works afterwards, which is what says the kernel
    // survived rather than that this test was simply not reached.
    let after = match arena_prog(
        "arena_after",
        &[call_arena_base(), st_imm(0, 0, 7), ldx(0, 0, 0), EXIT],
        &[1],
    ) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    if after.run_atomic([0; 4], 4) != Some(Outcome::Returned(7)) {
        return TestResult::Fail("a later arena program did not run after a recovered fault");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_arena_recovers_and_keeps_running);

fn smoke_bpf_jit_arena_unpopulated_pages_trap_natively() -> TestResult {
    // The extable's own reason for existing, isolated: an address inside the
    // program's *reserved* arena that is not *live*. The interpreter refuses it
    // by comparing against `live_bytes`; native code has no such comparison and
    // reaches the same verdict only because the page is unmapped and the fixup
    // catches the fault.
    //
    // "Require the arena fully populated" was the alternative to an extable, and
    // this is the case that shows it would not have been enough on its own —
    // though here it is arranged deliberately, since `ProgArena::new` makes live
    // equal reserved.
    let cap = kernel_arena_cap();
    let mut g = match ArenaGroup::new(cap) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("ArenaGroup::new failed"),
    };
    // One live page, four reserved: handles into pages 1..4 are inside the
    // arena's declared extent and are not backed.
    if g.add_reserved(cap, 1, 4).is_err() {
        return TestResult::Fail("add_reserved failed");
    }
    let p = match BpfProg::load_with_arena(
        load_cap(),
        LoadRequest {
            name: alloc::string::String::from("arena_unpopulated"),
            insns: asm(&[
                call_arena_base(),
                st_imm(0, 4096, 0xBAD),
                mov_imm(0, 1),
                EXIT,
            ]),
            context: Context::Atomic,
            maps: alloc::vec::Vec::new(),
        },
        Some(alloc::sync::Arc::new(g)),
    ) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load rejected"),
    };
    match diff_run(&p, [0; 4]) {
        Ok(()) => TestResult::Pass,
        Err(e) if core::ptr::eq(e, NO_BACKEND) => TestResult::Skip(NO_BACKEND),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_arena_unpopulated_pages_trap_natively);

fn smoke_bpf_jit_refuses_a_program_with_two_arenas() -> TestResult {
    // Gate 2 in its relaxed form. With two arenas the JIT's reachable-and-mapped
    // set stops equalling the interpreter's admitted set: `ArenaSlot::carve`
    // places them contiguously, so an 8-byte access straddling the boundary is
    // entirely inside mapped, writable, program-owned memory and would *succeed*
    // natively while `arena::resolve_in` refuses it — one program, two verdicts.
    //
    // Mutation: drop the `arena_count != 1` test in `try_compile` and this goes
    // red, because the straddling store below completes and returns 1.
    //
    // See `smoke_bpf_arena_straddling_two_arenas_is_refused`, which asserts the
    // two arenas really are VA-contiguous first — without that premise the
    // refusal could be an unmapped page and the JIT would agree after all.
    let items = [
        call_arena_base(),
        st_imm(0, 4092, 0xBAD),
        mov_imm(0, 1),
        EXIT,
    ];
    let p = match arena_prog("two_arena_straddle", &items, &[1, 1]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    if p.is_jited() {
        return TestResult::Fail("a two-arena program was compiled; the straddling case diverges");
    }
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Trapped(Trap::ArenaOutOfBounds { handle, .. })) => {
            if handle != ARENA_BASE_HANDLE + 4092 {
                return TestResult::Fail("the trap named the wrong handle");
            }
        }
        Some(Outcome::Returned(_)) => {
            return TestResult::Fail("a store straddling two arenas was allowed")
        }
        _ => return TestResult::Fail("the straddling store trapped for the wrong reason"),
    }
    // The single-arena form of the *same* program does compile, so the refusal
    // is about the count and not about arena programs in general. A gate that
    // refuses everything is not a gate.
    let one = match arena_prog("one_arena_straddle", &items, &[2]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    if !one.is_jited() && narf_bpf_jit::has_backend() {
        return TestResult::Fail("the one-arena form must still compile");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_refuses_a_program_with_two_arenas);

fn smoke_bpf_jit_arena_reachable_set_is_inside_the_slot_guards() -> TestResult {
    // The boundary arithmetic, at the layer where it is expressible.
    //
    // Two of the three boundaries — the slot's null guard, and
    // `ARENA_MAX_UNDERSHOOT_BYTES` below the slot base — are **not reachable by
    // a verified program**: the verifier refuses an arena access whose offset
    // domain can go negative (`fixpoint.rs`'s `addr.min < 0`), and both require
    // exactly that. So they cannot be tested by running a program, and are
    // tested here as what they actually are: an arithmetic property of the
    // address the emitter computes, checked against the guards the memory layer
    // asserts, plus the agreement of the two paths' admitted sets.
    //
    // The third — past the last arena — *is* reachable, and
    // `smoke_bpf_jit_diff_arena_out_of_bounds_traps_like_the_interpreter` runs
    // it.
    use narf_memory::bpf_arena::{
        ARENA_MAX_UNDERSHOOT_BYTES, ARENA_SLOT_STRIDE, ARENA_USABLE_BYTES,
    };
    let cap = kernel_arena_cap();
    let g = match ArenaGroup::with_one(cap, 1) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("ArenaGroup::with_one failed"),
    };
    let base = g.slot_base();

    // The emitted sequence is `slot_base + zx32(handle) + sext(off16)`, with the
    // displacement folded into the index. Modelled here exactly as the emitter
    // computes it, over the extremes of both fields.
    let addr = |handle: u64, off: i16| -> u64 {
        base.wrapping_add((handle as u32 as u64).wrapping_add(off as i64 as u64))
    };
    let lo = base - ARENA_MAX_UNDERSHOOT_BYTES;
    let hi = base + ARENA_SLOT_STRIDE;
    for &handle in &[0u64, 1, ARENA_BASE_HANDLE, ARENA_USABLE_BYTES - 8, u64::MAX] {
        for &off in &[i16::MIN, -1, 0, 1, i16::MAX] {
            let a = addr(handle, off);
            if a < lo || a >= hi {
                return TestResult::Fail(
                    "an address the emitted sequence can compute escapes the slot's guards",
                );
            }
        }
    }
    // The zero-extension is what makes that hold for `u64::MAX`, and it is not
    // free: without it the address would be `base - 1 + off`, which is `lo` only
    // by luck. Stated as its own check so the case above cannot pass by an
    // accident of the chosen constants.
    if addr(u64::MAX, 0) != base + u64::from(u32::MAX) {
        return TestResult::Fail("the handle is not zero-extended to 32 bits");
    }

    // And the two paths' *admitted* sets agree at the boundaries that are
    // reachable: `resolve_in` refuses exactly what the guards leave unmapped.
    let arenas = g.arenas();
    for &h in &[0u64, 1, ARENA_BASE_HANDLE - 8, ARENA_BASE_HANDLE + 4096] {
        if crate::arena::resolve_in(arenas, h, 8).is_some() {
            return TestResult::Fail("a handle outside the arena resolved");
        }
    }
    if crate::arena::resolve_in(arenas, ARENA_BASE_HANDLE, 8).is_none() {
        return TestResult::Fail("the arena's first doubleword did not resolve");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf",
    smoke_bpf_jit_arena_reachable_set_is_inside_the_slot_guards
);

/// Immediates chosen for sign-extension and shift-count boundaries.
const SWEEP_IMMS: [i32; 10] = [0, 1, -1, 2, -2, 7, 31, 32, 63, 64];
/// Wider boundaries, for the operands rather than the counts.
const SWEEP_VALS: [i32; 8] = [0, 1, -1, i32::MAX, i32::MIN, 0x7FFF, -0x8000, 0x5A5A_5A5A];

const ALL_ALU: [AluOp; 9] = [
    AluOp::Add,
    AluOp::Sub,
    AluOp::Mul,
    AluOp::Or,
    AluOp::And,
    AluOp::Xor,
    AluOp::Lsh,
    AluOp::Rsh,
    AluOp::Arsh,
];

const ALL_COND: [CondOp; 11] = [
    CondOp::Eq,
    CondOp::Ne,
    CondOp::Gt,
    CondOp::Ge,
    CondOp::Lt,
    CondOp::Le,
    CondOp::Sgt,
    CondOp::Sge,
    CondOp::Slt,
    CondOp::Sle,
    CondOp::Set,
];

fn smoke_bpf_jit_diff_alu_sweep() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // Every operation × both widths × immediate and register source × boundary
    // operands. ~1150 cases.
    for &op in &ALL_ALU {
        for wide in [false, true] {
            for &a in &SWEEP_VALS {
                for &b in &SWEEP_IMMS {
                    // Immediate source.
                    let prog = [
                        mov_imm(0, a),
                        Decoded::Alu {
                            wide,
                            op,
                            dst: r(0),
                            src: Source::Imm(b),
                        },
                        EXIT,
                    ];
                    if diff_case("alu_i", &prog, [0; 4]).is_err() {
                        return TestResult::Fail("ALU immediate sweep diverged");
                    }
                    // Register source.
                    let prog = [
                        mov_imm(0, a),
                        mov_imm(1, b),
                        Decoded::Alu {
                            wide,
                            op,
                            dst: r(0),
                            src: Source::Reg(r(1)),
                        },
                        EXIT,
                    ];
                    if diff_case("alu_r", &prog, [0; 4]).is_err() {
                        return TestResult::Fail("ALU register sweep diverged");
                    }
                }
            }
        }
    }
    // Negate, both widths.
    for wide in [false, true] {
        for &a in &SWEEP_VALS {
            let prog = [mov_imm(0, a), Decoded::Neg { wide, dst: r(0) }, EXIT];
            if diff_case("neg", &prog, [0; 4]).is_err() {
                return TestResult::Fail("negate sweep diverged");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_alu_sweep);

fn smoke_bpf_jit_diff_branch_sweep() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // Every predicate × both widths × immediate and register source, with
    // operands chosen so each predicate is exercised on both edges. Signed and
    // unsigned matter here: BPF's `Gt` is unsigned, so -1 > 0 must be *true*
    // natively and interpreted alike, and a JA/JG mix-up shows up only on a
    // case like that.
    let pairs: [(i32, i32); 7] = [
        (0, 0),
        (1, 0),
        (0, 1),
        (-1, 0),
        (0, -1),
        (i32::MIN, i32::MAX),
        (0x5A5A, 0x5A5A),
    ];
    for &op in &ALL_COND {
        for wide in [false, true] {
            for &(a, b) in &pairs {
                // `r0 = a; if r0 <op> b goto +1; r0 = 0xBAD; exit`
                // The return value distinguishes taken from not-taken, so a
                // wrong condition code changes the result rather than being
                // invisible.
                let prog = [
                    mov_imm(0, a),
                    Decoded::JumpCond {
                        wide,
                        op,
                        dst: r(0),
                        src: Source::Imm(b),
                        off: 1,
                    },
                    mov_imm(0, 0x0BAD),
                    EXIT,
                ];
                if diff_case("br_i", &prog, [0; 4]).is_err() {
                    return TestResult::Fail("branch immediate sweep diverged");
                }
                let prog = [
                    mov_imm(0, a),
                    mov_imm(2, b),
                    Decoded::JumpCond {
                        wide,
                        op,
                        dst: r(0),
                        src: Source::Reg(r(2)),
                        off: 1,
                    },
                    mov_imm(0, 0x0BAD),
                    EXIT,
                ];
                if diff_case("br_r", &prog, [0; 4]).is_err() {
                    return TestResult::Fail("branch register sweep diverged");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_branch_sweep);

fn smoke_bpf_jit_diff_register_sweep() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // Every general register as destination and as source. R6..R9 map to
    // rbx/r13/r14/r15 — callee-saved and, for three of them, needing REX.B —
    // so a prefix bug hides in half the register file. R10 is excluded: it is
    // the read-only frame pointer and the verifier rejects writing it.
    for d in 0..10u8 {
        for sr in 0..10u8 {
            let prog = [
                mov_imm(d, 0x1234),
                mov_imm(sr, 0x5678),
                Decoded::Alu {
                    wide: true,
                    op: AluOp::Add,
                    dst: r(d),
                    src: Source::Reg(r(sr)),
                },
                mov_reg(0, d),
                EXIT,
            ];
            if diff_case("regs", &prog, [0; 4]).is_err() {
                return TestResult::Fail("register sweep diverged");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_register_sweep);

fn smoke_bpf_jit_diff_stack_and_ctx_sweep() -> TestResult {
    // Wholesale skip where there is no backend: every case would compare the
    // interpreter with itself. Stated as a Skip with a reason rather than a
    // Pass, so "the JIT is untested on this architecture" stays visible.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // Frame offsets across the whole slot range, and every context word.
    // rbp-relative addressing needs a forced displacement byte, and the
    // disp8/disp32 boundary at -128 is where `modrm_mem` switches encodings —
    // so both sides of it are swept.
    for slot in 1..=24i16 {
        let off = -8 * slot;
        let prog = [
            mov_imm(1, 0x4321),
            Decoded::Store {
                size: Size::Dw,
                dst: r(10),
                off,
                src: Source::Reg(r(1)),
            },
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(0),
                src: r(10),
                off,
            },
            EXIT,
        ];
        if diff_case("stack", &prog, [0; 4]).is_err() {
            return TestResult::Fail("stack offset sweep diverged");
        }
        // And an immediate store at the same offset.
        let prog = [
            Decoded::Store {
                size: Size::Dw,
                dst: r(10),
                off,
                src: Source::Imm(-99),
            },
            Decoded::Load {
                size: Size::Dw,
                sign_extend: false,
                dst: r(0),
                src: r(10),
                off,
            },
            EXIT,
        ];
        if diff_case("stack_i", &prog, [0; 4]).is_err() {
            return TestResult::Fail("immediate store sweep diverged");
        }
    }
    for word in 0..4i16 {
        let prog = [ldx(0, 1, word * 8), EXIT];
        for ctx in [[0u64; 4], [1, 2, 3, 4], [u64::MAX, 0, 0x5A5A, 1]] {
            match diff_case("ctx", &prog, ctx) {
                Ok(()) => {}
                Err(e) if e == NO_BACKEND => return TestResult::Skip(NO_BACKEND),
                Err(_) => return TestResult::Fail("context sweep diverged"),
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_stack_and_ctx_sweep);

fn smoke_bpf_structops_adapter_dispatches() -> TestResult {
    // The generated adapter is what Linux spends a code generator on. Linux
    // needs `arch_prepare_bpf_trampoline` (306 lines of assembly emission)
    // because it patches into an arbitrary function's `__fentry__` nop, where
    // there is no host language to interpose. NARF's struct_ops targets are
    // trait slots with a Rust-level install point, so the adapter is an
    // ordinary `impl` — this test is that claim, executed.
    //
    // The program returns its first context word doubled, so the result proves
    // the argument reached it as ctx[0] rather than being zero or stale.
    let insns = asm(&[ldx(0, 1, 0), alu_reg(AluOp::Add, 0, 0), EXIT]);
    let Ok(prog) = load("gov", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the governor program");
    };
    let set = crate::structops::ProgSet::new().with("select_state", prog);
    let gov = BpfDemoGovernor::new(set);

    if gov.select_state(21) != 42 {
        return TestResult::Fail("adapter did not pass the argument as ctx[0]");
    }
    if gov.select_state(0) != 0 {
        return TestResult::Fail("adapter returned a stale value");
    }
    // `init` is `#[optional]` and unbound, so it must fall back rather than
    // fabricate. Returning nonsense from a policy hook is worse than returning
    // the default.
    if gov.init() != 0 {
        return TestResult::Fail("unbound optional method did not fall back");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_structops_adapter_dispatches);

fn smoke_bpf_structops_adapter_is_the_trait() -> TestResult {
    // The adapter must be usable anywhere the trait is — that is the whole
    // point of the trait coming out of the macro unchanged. Exercised through a
    // `&dyn` so nothing can be specialised away.
    let insns = asm(&[mov_imm(0, 7), EXIT]);
    let Ok(prog) = load("gov7", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    let bpf = BpfDemoGovernor::new(crate::structops::ProgSet::new().with("select_state", prog));
    let native = NativeDemoGovernor;
    let both: [&dyn DemoGovernor; 2] = [&bpf, &native];
    if both[0].select_state(1) != 7 {
        return TestResult::Fail("BPF impl did not dispatch through &dyn");
    }
    // The native impl still works and still has no idea BPF exists.
    let _ = both[1].select_state(1);
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_structops_adapter_is_the_trait);

// ── XDP attach ──────────────────────────────────────────────────────

fn smoke_bpf_xdp_program_decides() -> TestResult {
    // The seam `net/src/bypass/classifier.rs` has named since it was written.
    //
    // The frame is *summarised* into the context tuple — length, then the first
    // 24 bytes as three words — because the verifier has no packet-pointer
    // class, so a program cannot dereference the frame. This checks that the
    // summary is real: the program returns DROP only when the EtherType word
    // matches, so a zeroed or misaligned context would show up as the wrong
    // verdict rather than passing quietly.
    use narf_net::bypass::classifier::{XdpAction, XdpProgram};

    // ctx[2] holds frame bytes 8..16, which for an Ethernet frame spans the
    // last 4 bytes of the source MAC and the EtherType. `if ctx[2] == K` then
    // drop (1), else pass (2).
    let insns = asm(&[
        ldx(1, 1, 16), // r1 = ctx[2]
        mov_imm(0, 2), // default: XDP_PASS
        jne_imm(1, 0x11, 1),
        mov_imm(0, 1), // XDP_DROP
        EXIT,
    ]);
    let Ok(prog) = load("xdp", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected the XDP program");
    };
    let x = crate::attach_xdp::BpfXdp::for_test(prog, "test0");

    // A frame whose bytes 8..16 are 0x11 followed by zeroes → matches → DROP.
    let mut frame = [0u8; 64];
    frame[8] = 0x11;
    if x.run("test0", &frame) != XdpAction::Drop {
        return TestResult::Fail("program did not see the frame summary");
    }
    // Change the matched byte → PASS. If the context were zeroed, both frames
    // would take the same branch and this would be the failure.
    frame[8] = 0x22;
    if x.run("test0", &frame) != XdpAction::Pass {
        return TestResult::Fail("verdict did not follow the frame contents");
    }
    // A short frame must not panic and must still be summarised — the tail is
    // zero-padded, and ctx[0] stays the authority on how much is real.
    if x.run("test0", &[0u8; 3]) != XdpAction::Pass {
        return TestResult::Fail("a short frame was mishandled");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_xdp_program_decides);

fn smoke_bpf_xdp_unknown_action_aborts() -> TestResult {
    // Linux treats an unrecognised XDP return as XDP_ABORTED. So does this: a
    // program returning nonsense drops the frame *and is counted*, rather than
    // being read as PASS — a broken filter that silently passes everything is
    // the worst outcome available.
    use narf_net::bypass::classifier::{XdpAction, XdpProgram};
    let insns = asm(&[mov_imm(0, 99), EXIT]);
    let Ok(prog) = load("xdp-bad", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    let x = crate::attach_xdp::BpfXdp::for_test(prog, "test1");
    if x.run("test1", &[0u8; 64]) != XdpAction::Aborted {
        return TestResult::Fail("an unknown action was not treated as aborted");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_xdp_unknown_action_aborts);

fn smoke_bpf_jit_fuel_covers_every_path() -> TestResult {
    // The risk fuel emission actually has: if a back-edge target is not a block
    // start, the loop bypasses the burn and runs forever. `block_starts` marks
    // every branch target, so it should hold — this exercises the shapes where
    // it would not.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }

    // (a) A back-edge into the *middle* of the program, not to instruction 0.
    //     r0=0; r1=0; L: r0+=1; r1+=1; goto L   — target is index 2.
    let mid = asm(&[
        mov_imm(0, 0),
        mov_imm(1, 0),
        alu_imm(AluOp::Add, 0, 1),
        alu_imm(AluOp::Add, 1, 1),
        ja(-3),
    ]);

    // (b) A loop whose body contains a conditional, so the body spans several
    //     blocks and only one of them is the back-edge target. A burn on the
    //     loop head alone would not bound this.
    //     L: r0+=1; if r0 == 0 goto skip; r1+=1; skip: goto L
    let multi = asm(&[
        mov_imm(0, 0),
        mov_imm(1, 0),
        alu_imm(AluOp::Add, 0, 1),
        Decoded::JumpCond {
            wide: true,
            op: CondOp::Eq,
            dst: r(0),
            src: Source::Imm(0),
            off: 1,
        },
        alu_imm(AluOp::Add, 1, 1),
        ja(-4),
    ]);

    // (c) Two back-edges to the same target.
    //     L: r0+=1; if r0==7 goto L; if r0==9 goto L; goto L
    let two = asm(&[
        mov_imm(0, 0),
        alu_imm(AluOp::Add, 0, 1),
        jne_imm(0, 7, -2),
        jne_imm(0, 9, -3),
        ja(-4),
    ]);

    for (name, insns) in [("mid", mid), ("multi", multi), ("two", two)] {
        let Ok(p) = load(name, insns, Context::Atomic) else {
            return TestResult::Fail("load rejected an unbounded loop — fuel makes it legal");
        };
        if !p.is_jited() {
            return TestResult::Fail("a loop shape did not compile");
        }
        // The whole point: it must stop. A missing burn on any path shows up
        // here as a hang rather than a wrong answer, which is why this runs
        // the program instead of inspecting bytes.
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => {}
            Some(Outcome::Returned(_)) => {
                return TestResult::Fail("an unbounded loop returned — a path skipped the burn")
            }
            Some(Outcome::Trapped(_)) => return TestResult::Fail("wrong trap"),
            None => return TestResult::Fail("run declined"),
        }
        // And the interpreter agrees, which is what makes the native verdict
        // trustworthy rather than merely plausible.
        match p.run_atomic_interpreted([0; 4], 4) {
            Some(Outcome::Trapped(Trap::OutOfFuel { .. })) => {}
            _ => return TestResult::Fail("interpreted and native disagreed on exhaustion"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_fuel_covers_every_path);

/// Asymmetric frame sizes: a big caller and a small callee.
///
/// The existing overlap test uses 8 bytes on *both* sides, which is the one
/// arrangement where subtracting the callee's frame size and subtracting the
/// caller's give the same answer — so it passed while `push_frame` used the
/// wrong one.
///
/// Here main uses 512 bytes and the callee 8. With the callee's size subtracted,
/// its base landed 8 bytes below main's top, i.e. *inside* main's frame, and its
/// store silently overwrote a slot the verifier had proved untouched. Main then
/// read back the callee's value.
fn smoke_bpf_big_caller_small_callee_frames_disjoint() -> TestResult {
    // main:  *(u64*)(r10-16) = 0x11; *(u64*)(r10-512) = 0x33; call sub;
    //        r0 = *(u64*)(r10-16); exit
    // sub:   *(u64*)(r10-8) = 0x22; r0 = 0; exit
    //
    // The sentinel sits at -16 deliberately. Subtracting the *callee's* 8 bytes
    // puts its base at `top - 8`, so its own `r10-8` resolves to `top - 16` —
    // exactly main's `r10-16`. A sentinel at -8 would sit one slot clear of the
    // collision and the test would pass under the bug it exists to catch.
    let insns = asm(&[
        st_imm(10, -16, 0x11),
        st_imm(10, -512, 0x33),
        subprog_call(2),
        ldx(0, 10, -16),
        EXIT,
        st_imm(10, -8, 0x22),
        mov_imm(0, 0),
        EXIT,
    ]);
    let Ok(p) = load("bigsmall", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected an asymmetric subprogram call");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(0x11)) => TestResult::Pass,
        Some(Outcome::Returned(0x22)) => {
            TestResult::Fail("callee frame landed inside the caller's frame")
        }
        Some(Outcome::Returned(_)) => TestResult::Fail("unexpected value after a subprogram call"),
        Some(Outcome::Trapped(_)) => TestResult::Fail("asymmetric subprogram call trapped"),
        None => TestResult::Fail("run declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_big_caller_small_callee_frames_disjoint);

/// The mirror case: a small caller and a big callee.
///
/// With the callee's size subtracted, `max_stack_bytes` was 520 while the
/// callee's base was placed at `top - 512`, so its own `r10-512` addressed
/// *below* the region and trapped `BadAccess` — a program the verifier had
/// proved fits, failing at runtime.
fn smoke_bpf_small_caller_big_callee_fits() -> TestResult {
    // main:  *(u64*)(r10-8) = 0x11; call sub; r0 = *(u64*)(r10-8); exit
    // sub:   *(u64*)(r10-512) = 0x22; r0 = 0; exit
    let insns = asm(&[
        st_imm(10, -8, 0x11),
        subprog_call(2),
        ldx(0, 10, -8),
        EXIT,
        st_imm(10, -512, 0x22),
        mov_imm(0, 0),
        EXIT,
    ]);
    let Ok(p) = load("smallbig", insns, Context::Atomic) else {
        return TestResult::Fail("load rejected a small-caller/big-callee call");
    };
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(0x11)) => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("caller slot was clobbered"),
        Some(Outcome::Trapped(Trap::BadAccess { .. })) => {
            TestResult::Fail("callee addressed below the stack region — frame sizing is wrong")
        }
        Some(Outcome::Trapped(Trap::StackExhausted { .. })) => {
            TestResult::Fail("frame sizing exhausted a region the verifier proved sufficient")
        }
        Some(Outcome::Trapped(_)) => TestResult::Fail("call trapped"),
        None => TestResult::Fail("run declined"),
    }
}
kernel_test_in!("bpf", smoke_bpf_small_caller_big_callee_fits);

/// A program that traps on **both** paths must trap the *same way*.
///
/// The differential harness compares two traps by kind, and until this test
/// existed nothing exercised that arm: every sweep case returned a value, so
/// inverting the comparison to `!=` left the suite green. A check no test can
/// reach is the "defensive machinery guarding a case that cannot arise" shape
/// this design has already been burned by once (spec §9, the sizing fixpoint),
/// so the arm gets a case rather than a rewrite.
///
/// An unbounded loop is the natural subject: the verifier accepts it by design
/// (termination is a runtime property under fuel, §1.1), and both backends must
/// stop it with `OutOfFuel` rather than one running out of fuel while the other
/// takes a bad access. That is exactly the divergence class a review already
/// found on the interpreter side, where an unconditional back-edge was charged
/// twice interpreted and once natively.
fn smoke_bpf_jit_diff_trapping_program_agrees() -> TestResult {
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }
    // r0 = 0; loop { r0 += 1 }  — never exits, so fuel decides.
    let prog = [mov_imm(0, 0), alu_imm(AluOp::Add, 0, 1), ja(-2)];
    match diff_case("difftrap", &prog, [0; 4]) {
        Ok(()) => TestResult::Pass,
        Err(e) if core::ptr::eq(e, NO_BACKEND) => TestResult::Skip(NO_BACKEND),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_trapping_program_agrees);

// ── kfunc calls, natively ───────────────────────────────────────────
//
// The only place the emitted call sequence is *executed* against the
// interpreter. The golden tests in `narf-bpf-jit` prove the bytes are the ones
// intended; only this proves the intention was right — and only in-kernel,
// because the subject is a real kfunc shim at a real address.
//
// Every case goes through `diff_case`, which refuses to compare unless the
// subject actually compiled. That is not boilerplate here: before call emission
// landed, *every* program below fell back to the interpreter, so a version of
// these tests without that assertion would have passed on unmodified `main`.

/// `r1..r5 = args; call narf_test_arg_mix; exit`.
///
/// Distinct values per register, because the failure mode being hunted is a
/// *permutation* — R4 and R5 land in the two host registers that do not line up
/// between the BPF and C ABIs on either architecture.
fn arg_mix_prog(args: [i32; 5]) -> Vec<Decoded> {
    let mut p: Vec<Decoded> = Vec::new();
    for (k, v) in args.iter().enumerate() {
        p.push(mov_imm((k + 1) as u8, *v));
    }
    p.push(call("narf_test_arg_mix"));
    p.push(EXIT);
    p
}

fn smoke_bpf_jit_diff_kfunc_argument_registers() -> TestResult {
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }
    for args in [
        [1, 2, 3, 4, 5],
        [5, 4, 3, 2, 1],
        [0, -1, i32::MAX, i32::MIN, 0x5A5A_5A5A],
        [11, 13, 17, 19, 23],
        [-7, -11, -13, -17, -19],
    ] {
        match diff_case("kfunc_args", &arg_mix_prog(args), [0; 4]) {
            Ok(()) => {}
            Err(e) if core::ptr::eq(e, NO_BACKEND) => return TestResult::Skip(NO_BACKEND),
            Err(e) => return TestResult::Fail(e),
        }
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_diff_kfunc_argument_registers);

fn smoke_bpf_jit_kfunc_call_returns_the_shims_own_answer() -> TestResult {
    // "Both paths agree" cannot distinguish "both are right" from "both call
    // the same wrong kfunc", so this one pins the absolute value. The multipliers
    // are `narf_test_arg_mix`'s, restated here on purpose: if that kfunc's body
    // changes, this should go red and be re-derived rather than silently follow.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }
    let args = [3i32, 5, 7, 11, 13];
    let want = 3u64 + 5 * 3 + 7 * 5 + 11 * 7 + 13 * 11;
    let Ok(p) = load("kfunc_val", asm(&arg_mix_prog(args)), Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    if !p.is_jited() {
        return TestResult::Fail("the call did not compile; this would test nothing");
    }
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(v)) if v == want => TestResult::Pass,
        Some(Outcome::Returned(_)) => TestResult::Fail("native call returned the wrong value"),
        _ => TestResult::Fail("native call did not return"),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_kfunc_call_returns_the_shims_own_answer);

fn smoke_bpf_jit_kfunc_call_keeps_the_c_stack_aligned() -> TestResult {
    // SysV wants `rsp % 16 == 0` at the call and AAPCS64 wants `sp % 16 == 0`
    // always. Neither is observable from BPF directly, so `narf_test_stack_residue`
    // reports the shim's own stack residue and the two callers are compared:
    // the interpreter enters it from ordinary Rust, where the rule holds by
    // construction.
    //
    // This is the test that fails if the prologue's alignment step is removed —
    // a misaligned SysV call otherwise shows up as a fault on an aligned SSE
    // spill inside some unrelated callee, arbitrarily far away.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }
    let prog = [call("narf_test_stack_residue"), EXIT];
    match diff_case("kfunc_align", &prog, [0; 4]) {
        Ok(()) => TestResult::Pass,
        Err(e) if core::ptr::eq(e, NO_BACKEND) => TestResult::Skip(NO_BACKEND),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_kfunc_call_keeps_the_c_stack_aligned);

fn smoke_bpf_jit_diff_kfunc_call_preserves_callee_saved_state() -> TestResult {
    // R6..R9 and R10 must survive a call — that is the BPF ABI, and it is what
    // the register maps buy by putting them in callee-saved host registers.
    // Checked by *observing* them afterwards rather than by reading the map:
    // values go into R6..R9 and the frame, a call happens, and everything is
    // summed into R0. A backend that mapped one of them to a caller-saved
    // register passes every other test here and fails this one.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }
    let mut p: Vec<Decoded> = alloc::vec![
        mov_imm(6, 0x0011),
        mov_imm(7, 0x0220),
        mov_imm(8, 0x4400),
        mov_imm(9, 0x8000),
        st_imm(10, -8, 0x1234),
    ];
    p.extend_from_slice(&arg_mix_prog([1, 2, 3, 4, 5])[..6]); // args + the call
    p.extend_from_slice(&[
        alu_reg(AluOp::Add, 0, 6),
        alu_reg(AluOp::Add, 0, 7),
        alu_reg(AluOp::Add, 0, 8),
        alu_reg(AluOp::Add, 0, 9),
        ldx(1, 10, -8),
        alu_reg(AluOp::Add, 0, 1),
        EXIT,
    ]);
    match diff_case("kfunc_saved", &p, [0; 4]) {
        Ok(()) => TestResult::Pass,
        Err(e) if core::ptr::eq(e, NO_BACKEND) => TestResult::Skip(NO_BACKEND),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "bpf",
    smoke_bpf_jit_diff_kfunc_call_preserves_callee_saved_state
);

fn smoke_bpf_jit_diff_kfunc_call_in_a_loop_agrees_on_fuel() -> TestResult {
    // The JIT charges fuel per basic block and the interpreter per instruction,
    // and a call sits inside a block on one side and is its own charge on the
    // other. A loop whose body contains a call is where those two accountings
    // would diverge, and the harness compares the *kind* of stop, so
    // "completed" versus "OutOfFuel" is a failure and not a near-miss.
    if !narf_bpf_jit::has_backend() {
        return TestResult::Skip(NO_BACKEND);
    }
    for (name, trips) in [("kfunc_loop_short", 64i32), ("kfunc_loop_long", 1_000_000)] {
        let mut p: Vec<Decoded> = alloc::vec![mov_imm(6, 0)];
        p.extend_from_slice(&arg_mix_prog([1, 2, 3, 4, 5])[..6]);
        p.extend_from_slice(&[
            alu_imm(AluOp::Add, 6, 1),
            jne_imm(6, trips, -8),
            mov_reg(0, 6),
            EXIT,
        ]);
        match diff_case(name, &p, [0; 4]) {
            Ok(()) => {}
            Err(e) if core::ptr::eq(e, NO_BACKEND) => return TestResult::Skip(NO_BACKEND),
            Err(e) => return TestResult::Fail(e),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf",
    smoke_bpf_jit_diff_kfunc_call_in_a_loop_agrees_on_fuel
);

// ── negatives: what must *not* be compiled ──────────────────────────

fn smoke_bpf_jit_refuses_a_sleepable_kfunc_call() -> TestResult {
    // `narf_yield`'s shim is `fn(..) -> Pin<Box<dyn Future>>`, not
    // `extern "C" fn(..) -> u64`. Entering it through the uniform ABI would
    // reinterpret a boxed future as R0 and leak it, so the emitter must refuse
    // on the *callee's* context — not on the program's, which here is
    // `Sleepable` and permits the call perfectly legally.
    let Ok(p) = load(
        "sleepy_call",
        asm(&[call("narf_yield"), EXIT]),
        Context::Sleepable,
    ) else {
        return TestResult::Fail("load rejected");
    };
    if p.is_jited() {
        return TestResult::Fail("a sleepable kfunc's shim was compiled into native code");
    }
    TestResult::Pass
}
kernel_test_in!("bpf", smoke_bpf_jit_refuses_a_sleepable_kfunc_call);

fn smoke_bpf_jit_refuses_a_context_dereference_in_a_calling_program() -> TestResult {
    // `jit_glue` gate 5. R1 is the context on entry and stays so as long as
    // nothing can produce another pointer class — but a kfunc return can, and
    // `r1 = r0` is an ordinary move the verifier will type-check happily
    // against whatever class R0 holds. Native code would dereference R1
    // verbatim, so a program containing *any* call loses R1 as a base.
    //
    // Both halves, because a gate that refuses everything is not a gate: the
    // same load must still compile when there is no call to worry about.
    let with_ctx_load = [ldx(0, 1, 0), EXIT];
    let Ok(a) = load("ctx_nocall", asm(&with_ctx_load), Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    if !a.is_jited() && narf_bpf_jit::has_backend() {
        return TestResult::Fail("a context load with no call must still compile");
    }

    let mut b_prog: Vec<Decoded> = alloc::vec![ldx(6, 1, 0)];
    b_prog.extend_from_slice(&arg_mix_prog([1, 2, 3, 4, 5]));
    let Ok(b) = load("ctx_call", asm(&b_prog), Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    if b.is_jited() {
        return TestResult::Fail("a context dereference survived into a calling program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bpf",
    smoke_bpf_jit_refuses_a_context_dereference_in_a_calling_program
);

fn smoke_bpf_jit_refuses_a_subprogram_call() -> TestResult {
    // Kfunc calls landing does not make BPF-to-BPF calls land: a subprogram
    // call needs the frame push the interpreter does in `push_frame`, and a
    // bare native `call` would run the callee on the caller's BPF frame.
    let prog = [subprog_call(1), EXIT, mov_imm(0, 7), EXIT];
    let Ok(p) = load("subcall", asm(&prog), Context::Atomic) else {
        return TestResult::Fail("load rejected");
    };
    if p.is_jited() {
        return TestResult::Fail("a subprogram call was compiled");
    }
    // …and it still runs, interpreted, which is the whole reason refusing is
    // safe.
    match p.run_atomic([0; 4], 4) {
        Some(Outcome::Returned(7)) => TestResult::Pass,
        _ => TestResult::Fail("the refused program did not run interpreted"),
    }
}
kernel_test_in!("bpf", smoke_bpf_jit_refuses_a_subprogram_call);
// ════════════════════════════════════════════════════════════════════
// Maps (`crate::map`).
//
// In-kernel rather than host tests because a map's width comes from
// `narf_lib::smp::cpu_count()`, its storage sits behind an `IrqSafeSpinLock`,
// and the per-CPU kinds are indexed by `current_cpu()` — none of which has a
// host analogue. The Linux-ABI errno mapping is pinned separately from
// userspace in `userspace/src/abi_bpf_tests.rs`.
// ════════════════════════════════════════════════════════════════════

use alloc::string::String;
use alloc::sync::Arc;

use crate::map::{
    BpfMap, BpfMapCap, MapAttr, MapError, MapKind, BPF_ANY, BPF_EXIST, BPF_F_LOCK, BPF_NOEXIST,
};

/// Cached for the same reason [`load_cap`] is: `Cap::bootstrap()` allocates an
/// object-table slot per call.
fn map_cap() -> &'static Cap<BpfMapCap, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfMapCap, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<BpfMapCap, Grant>::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

fn mk(
    kind: MapKind,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> Result<Arc<BpfMap>, MapError> {
    BpfMap::create(
        map_cap(),
        MapAttr {
            kind,
            key_size,
            value_size,
            max_entries,
        },
        String::from("smoke"),
    )
}

fn k32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// `?`-style bodies, so a test reads as a list of assertions rather than a
/// staircase of `match`.
fn checked(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}

// ── Array ───────────────────────────────────────────────────────────

fn smoke_bpf_map_array_roundtrip() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        let ops = m.ops();
        let mut out = [0u8; 8];
        // Every array slot exists from creation and reads as zero. A program
        // may load a slot nothing has written, so the bytes must not be a
        // previous map's.
        ops.lookup(&k32(2), &mut out)
            .map_err(|_| "a fresh Array slot was not readable")?;
        if out != [0u8; 8] {
            return Err("a fresh Array slot was not zeroed");
        }
        ops.update(&k32(2), &0xDEAD_BEEF_u64.to_le_bytes(), BPF_ANY)
            .map_err(|_| "Array update rejected")?;
        ops.lookup(&k32(2), &mut out)
            .map_err(|_| "Array lookup after update failed")?;
        if u64::from_le_bytes(out) != 0xDEAD_BEEF {
            return Err("Array lookup returned the wrong value");
        }
        // Sentinels on *both* sides of the written slot, because an off-by-one
        // in `slot_range` shifts in one direction only and a single neighbour
        // would miss half of them.
        for neighbour in [1u32, 3] {
            ops.lookup(&k32(neighbour), &mut out)
                .map_err(|_| "Array neighbour lookup failed")?;
            if out != [0u8; 8] {
                return Err("Array update wrote outside its own slot");
            }
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_array_roundtrip);

fn smoke_bpf_map_array_errnos() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        let ops = m.ops();
        let mut out = [0u8; 8];
        // A key past `max_entries` is a *missing* key on lookup and an
        // oversized one on update. Linux splits them exactly here
        // (`array_map_lookup_elem` returns NULL ⇒ ENOENT;
        // `array_map_update_elem` returns -E2BIG) and a loader that probes
        // capacity depends on the difference.
        if ops.lookup(&k32(4), &mut out) != Err(MapError::NotFound) {
            return Err("Array lookup past max_entries was not NotFound");
        }
        if ops.update(&k32(4), &out, BPF_ANY) != Err(MapError::TooBig) {
            return Err("Array update past max_entries was not TooBig");
        }
        // Every slot already exists, so "create only" can never be satisfied.
        if ops.update(&k32(0), &out, BPF_NOEXIST) != Err(MapError::Exists) {
            return Err("Array update with BPF_NOEXIST was not Exists");
        }
        // ...but "overwrite only" always can.
        if ops.update(&k32(0), &out, BPF_EXIST).is_err() {
            return Err("Array update with BPF_EXIST was refused");
        }
        // An array slot cannot stop existing: `array_map_delete_elem` is
        // -EINVAL, not -ENOENT.
        if ops.delete(&k32(0)) != Err(MapError::Invalid) {
            return Err("Array delete was not Invalid");
        }
        // Widths are part of the contract; a short buffer would otherwise be a
        // panicking slice copy.
        if ops.lookup(&k32(0), &mut [0u8; 4]) != Err(MapError::Invalid) {
            return Err("Array lookup into a short buffer was not Invalid");
        }
        if ops.update(&k32(0), &[0u8; 4], BPF_ANY) != Err(MapError::Invalid) {
            return Err("Array update from a short buffer was not Invalid");
        }
        if ops.lookup(&[0u8; 2], &mut out) != Err(MapError::Invalid) {
            return Err("Array lookup with a 2-byte key was not Invalid");
        }
        // No map value can carry a `bpf_spin_lock`: there is no BTF to say
        // where it would live, so `BPF_F_LOCK` is EINVAL exactly as it is on
        // Linux for a map with no lock field.
        if ops.update(&k32(0), &out, BPF_F_LOCK) != Err(MapError::Invalid) {
            return Err("BPF_F_LOCK was not rejected");
        }
        // `BPF_NOEXIST | BPF_EXIST` is not a flag combination.
        if ops.update(&k32(0), &out, BPF_NOEXIST | BPF_EXIST) != Err(MapError::Invalid) {
            return Err("a nonsense flag word was not rejected");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_array_errnos);

fn smoke_bpf_map_array_next_key() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Array, 4, 8, 3).map_err(|_| "Array create failed")?;
        let ops = m.ops();
        let mut out = [0u8; 4];
        // `array_map_get_next_key`: NULL starts at 0, index i yields i+1, and
        // the last index terminates the walk.
        ops.next_key(None, &mut out)
            .map_err(|_| "Array next_key(None) failed")?;
        if out != k32(0) {
            return Err("Array next_key(None) did not start at 0");
        }
        ops.next_key(Some(&k32(0)), &mut out)
            .map_err(|_| "Array next_key(0) failed")?;
        if out != k32(1) {
            return Err("Array next_key(0) was not 1");
        }
        ops.next_key(Some(&k32(1)), &mut out)
            .map_err(|_| "Array next_key(1) failed")?;
        if out != k32(2) {
            return Err("Array next_key(1) was not 2");
        }
        if ops.next_key(Some(&k32(2)), &mut out) != Err(MapError::NotFound) {
            return Err("Array next_key past the last index was not NotFound");
        }
        // An out-of-range key restarts the walk rather than failing — Linux's
        // `if (index >= max_entries) { *next = 0; return 0; }`.
        ops.next_key(Some(&k32(99)), &mut out)
            .map_err(|_| "Array next_key with an out-of-range key failed")?;
        if out != k32(0) {
            return Err("Array next_key with an out-of-range key did not restart at 0");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_array_next_key);

// ── Hash ────────────────────────────────────────────────────────────

fn smoke_bpf_map_hash_roundtrip() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Hash, 4, 8, 8).map_err(|_| "Hash create failed")?;
        let ops = m.ops();
        let mut out = [0u8; 8];
        // Absent until written — unlike an array, a hash slot does not exist
        // until something creates it.
        if ops.lookup(&k32(7), &mut out) != Err(MapError::NotFound) {
            return Err("a fresh Hash reported a key it does not hold");
        }
        for i in 0..8u32 {
            ops.update(&k32(i), &(u64::from(i) * 1000 + 1).to_le_bytes(), BPF_ANY)
                .map_err(|_| "Hash update rejected")?;
        }
        // Every key, read back after every other key was written: a bucket
        // chain that drops a node shows up here and nowhere in a single
        // insert/lookup pair.
        for i in 0..8u32 {
            ops.lookup(&k32(i), &mut out)
                .map_err(|_| "Hash lost a key that was inserted")?;
            if u64::from_le_bytes(out) != u64::from(i) * 1000 + 1 {
                return Err("Hash returned another key's value");
            }
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_hash_roundtrip);

fn smoke_bpf_map_hash_flag_policy() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Hash, 4, 8, 4).map_err(|_| "Hash create failed")?;
        let ops = m.ops();
        let v = 1u64.to_le_bytes();
        // "Overwrite only" against an absent key is ENOENT, and must not
        // create it.
        if ops.update(&k32(1), &v, BPF_EXIST) != Err(MapError::NotFound) {
            return Err("Hash update with BPF_EXIST on an absent key was not NotFound");
        }
        if ops.lookup(&k32(1), &mut [0u8; 8]) != Err(MapError::NotFound) {
            return Err("a refused BPF_EXIST update created the key anyway");
        }
        // "Create only" against an absent key succeeds...
        ops.update(&k32(1), &v, BPF_NOEXIST)
            .map_err(|_| "Hash update with BPF_NOEXIST on an absent key was refused")?;
        // ...and against a present one is EEXIST, without overwriting.
        if ops.update(&k32(1), &2u64.to_le_bytes(), BPF_NOEXIST) != Err(MapError::Exists) {
            return Err("Hash update with BPF_NOEXIST on a present key was not Exists");
        }
        let mut out = [0u8; 8];
        ops.lookup(&k32(1), &mut out)
            .map_err(|_| "Hash lookup failed")?;
        if u64::from_le_bytes(out) != 1 {
            return Err("a refused BPF_NOEXIST update overwrote the value");
        }
        // Now BPF_EXIST does overwrite.
        ops.update(&k32(1), &3u64.to_le_bytes(), BPF_EXIST)
            .map_err(|_| "Hash update with BPF_EXIST on a present key was refused")?;
        ops.lookup(&k32(1), &mut out)
            .map_err(|_| "Hash lookup failed")?;
        if u64::from_le_bytes(out) != 3 {
            return Err("BPF_EXIST did not overwrite");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_hash_flag_policy);

fn smoke_bpf_map_hash_delete_and_reuse() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Hash, 4, 8, 3).map_err(|_| "Hash create failed")?;
        let ops = m.ops();
        let v = 9u64.to_le_bytes();
        if ops.delete(&k32(0)) != Err(MapError::NotFound) {
            return Err("Hash delete of an absent key was not NotFound");
        }
        for i in 0..3u32 {
            ops.update(&k32(i), &v, BPF_ANY)
                .map_err(|_| "Hash update rejected")?;
        }
        // Full: a fourth key has no node to take.
        if ops.update(&k32(3), &v, BPF_ANY) != Err(MapError::TooBig) {
            return Err("insertion into a full Hash was not TooBig");
        }
        ops.delete(&k32(1)).map_err(|_| "Hash delete failed")?;
        if ops.lookup(&k32(1), &mut [0u8; 8]) != Err(MapError::NotFound) {
            return Err("a deleted key is still present");
        }
        // Unlinking must return the node to the free list; if it only cleared
        // `live`, capacity would leak one node per delete and this insert would
        // be TooBig.
        ops.update(&k32(3), &v, BPF_ANY)
            .map_err(|_| "a deleted node's capacity was not reclaimed")?;
        // The two survivors are still reachable — a mis-unlinked chain drops
        // the node that followed the removed one.
        for i in [0u32, 2, 3] {
            if ops.lookup(&k32(i), &mut [0u8; 8]).is_err() {
                return Err("deleting a key unlinked a different key too");
            }
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_hash_delete_and_reuse);

/// A recycled hash node must not hand a new key the previous occupant's bytes.
///
/// This has to go through a *per-CPU* kind and reinsert with `update_local`,
/// because that is the only combination where the reinsert does not itself
/// overwrite the stale bytes. A plain `Hash` reinserted through the
/// syscall-view `update` writes the whole value, so the previous occupant's
/// bytes are gone whether or not `unlink_node` zeroed them — a test written
/// that way passes with the zeroing deleted, which is to say it tests nothing.
/// `update_local` writes one CPU's slot and leaves the rest, so the syscall
/// view below reads exactly the bytes the free path was supposed to clear.
///
/// Skipped rather than run on a single-CPU boot for the same reason
/// [`smoke_bpf_map_percpu_rejects_program_width_buffer`] is: there
/// `update_local` covers the whole value, nothing distinguishes a cleared slot
/// from an overwritten one, and a Pass would claim a gate that was never
/// exercised.
fn smoke_bpf_map_hash_recycled_node_is_zeroed() -> TestResult {
    let cpus = narf_lib::smp::cpu_count().max(1) as usize;
    if cpus < 2 {
        return TestResult::Skip("single CPU: update_local covers the whole value");
    }
    checked(|| {
        let m = mk(MapKind::PerCpuHash, 4, 8, 1).map_err(|_| "PerCpuHash create failed")?;
        let ops = m.ops();
        let width = ops.syscall_value_bytes();
        // Fill every CPU's slot with the sentinel.
        let poison = alloc::vec![0x55u8; width];
        ops.update(&k32(1), &poison, BPF_ANY)
            .map_err(|_| "PerCpuHash update rejected")?;
        // Pin that the sentinel really landed, so a future change that stopped
        // the poison taking would show up here rather than as a pass below.
        let mut seeded = alloc::vec![0u8; width];
        ops.lookup(&k32(1), &mut seeded)
            .map_err(|_| "PerCpuHash lookup of the seeded key failed")?;
        if seeded.iter().any(|b| *b != 0x55) {
            return Err("the per-CPU sentinel did not reach every slot");
        }
        ops.delete(&k32(1))
            .map_err(|_| "PerCpuHash delete failed")?;
        // The only node is now free, so key 2 must land on it. `update_local`
        // touches this CPU's slot alone.
        ops.update_local(&k32(2), &0u64.to_le_bytes(), BPF_ANY)
            .map_err(|_| "PerCpuHash local reinsert rejected")?;
        let mut out = alloc::vec![0u8; width];
        ops.lookup(&k32(2), &mut out)
            .map_err(|_| "PerCpuHash lookup failed")?;
        if out.iter().any(|b| *b != 0) {
            return Err("a recycled hash node leaked the previous key's value");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_hash_recycled_node_is_zeroed);

fn smoke_bpf_map_hash_next_key_walk() -> TestResult {
    checked(|| {
        const N: u32 = 6;
        let m = mk(MapKind::Hash, 4, 8, N).map_err(|_| "Hash create failed")?;
        let ops = m.ops();
        for i in 0..N {
            ops.update(&k32(i * 7), &u64::from(i).to_le_bytes(), BPF_ANY)
                .map_err(|_| "Hash update rejected")?;
        }
        // A full walk must visit every key exactly once and then terminate.
        let mut seen = [false; N as usize];
        let mut key: Option<[u8; 4]> = None;
        let mut out = [0u8; 4];
        for _ in 0..=N {
            match ops.next_key(key.as_ref().map(|k| &k[..]), &mut out) {
                Ok(()) => {}
                Err(MapError::NotFound) => {
                    key = None;
                    break;
                }
                Err(_) => return Err("Hash next_key failed for a reason other than NotFound"),
            }
            let raw = u32::from_le_bytes(out);
            if raw % 7 != 0 || raw / 7 >= N {
                return Err("Hash next_key produced a key that was never inserted");
            }
            let slot = (raw / 7) as usize;
            if seen[slot] {
                return Err("Hash next_key revisited a key inside one walk");
            }
            seen[slot] = true;
            key = Some(out);
        }
        if key.is_some() {
            return Err("Hash next_key walk did not terminate after max_entries steps");
        }
        if seen.iter().any(|s| !*s) {
            return Err("Hash next_key walk skipped a key");
        }
        // A key the map does not hold restarts the walk rather than failing —
        // the quirk `htab_map_get_next_key`'s `goto find_first_elem` produces,
        // and what lets a delete-while-iterating loop keep going.
        ops.next_key(Some(&k32(12345)), &mut out)
            .map_err(|_| "Hash next_key with an absent key did not restart the walk")?;
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_hash_next_key_walk);

fn smoke_bpf_map_hash_next_key_empty() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Hash, 4, 8, 4).map_err(|_| "Hash create failed")?;
        let mut out = [0u8; 4];
        // An empty map terminates immediately; anything else would make
        // `BPF_MAP_GET_NEXT_KEY` on a fresh map return an uninitialised key.
        if m.ops().next_key(None, &mut out) != Err(MapError::NotFound) {
            return Err("next_key on an empty Hash was not NotFound");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_hash_next_key_empty);

// ── per-CPU kinds ───────────────────────────────────────────────────

fn smoke_bpf_map_percpu_array_views() -> TestResult {
    checked(|| {
        let m = mk(MapKind::PerCpuArray, 4, 8, 2).map_err(|_| "PerCpuArray create failed")?;
        let ops = m.ops();
        let cpus = narf_lib::smp::cpu_count().max(1) as usize;
        // The syscall view spans every CPU at an 8-byte stride, exactly as
        // Linux's `bpf_percpu_array_copy` lays it out.
        if ops.syscall_value_bytes() != cpus * 8 {
            return Err("PerCpuArray syscall_value_bytes is not cpus * stride");
        }
        // Syscall update writes every CPU.
        let all: alloc::vec::Vec<u8> = (0..cpus).flat_map(|_| 0x11u64.to_le_bytes()).collect();
        ops.update(&k32(0), &all, BPF_ANY)
            .map_err(|_| "PerCpuArray syscall update rejected")?;
        // The program view sees this CPU's slot, which the all-CPU write set.
        let mut local = [0u8; 8];
        ops.lookup_local(&k32(0), &mut local)
            .map_err(|_| "PerCpuArray lookup_local failed")?;
        if u64::from_le_bytes(local) != 0x11 {
            return Err("PerCpuArray lookup_local did not see the all-CPU write");
        }
        // The program view writes only this CPU's slot.
        ops.update_local(&k32(0), &0x22u64.to_le_bytes(), BPF_ANY)
            .map_err(|_| "PerCpuArray update_local rejected")?;
        let mut read_all = alloc::vec![0u8; cpus * 8];
        ops.lookup(&k32(0), &mut read_all)
            .map_err(|_| "PerCpuArray syscall lookup failed")?;
        let mut changed = 0usize;
        for c in 0..cpus {
            let mut w = [0u8; 8];
            w.copy_from_slice(&read_all[c * 8..c * 8 + 8]);
            match u64::from_le_bytes(w) {
                0x22 => changed += 1,
                0x11 => {}
                _ => return Err("PerCpuArray slot holds neither value written to it"),
            }
        }
        if changed != 1 {
            // `changed == cpus` means `update_local` wrote every slot;
            // `changed == 0` means it wrote none of the ones the syscall view
            // reads, i.e. the two views disagree about the stride.
            return Err("PerCpuArray update_local did not write exactly one CPU's slot");
        }
        // Entry 1 must be untouched: the per-CPU stride multiplies the index,
        // so an off-by-one there lands on the next entry.
        ops.lookup(&k32(1), &mut read_all)
            .map_err(|_| "PerCpuArray syscall lookup failed")?;
        if read_all.iter().any(|b| *b != 0) {
            return Err("a PerCpuArray write reached the next entry");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_percpu_array_views);

/// The syscall view of a per-CPU map is `cpus * stride` wide, and must reject a
/// buffer of the *program* width.
///
/// Separate from the test above because on a single-CPU boot the two widths
/// coincide, so there is nothing to distinguish and a Pass would claim a gate
/// that was never exercised.
fn smoke_bpf_map_percpu_rejects_program_width_buffer() -> TestResult {
    let cpus = narf_lib::smp::cpu_count().max(1) as usize;
    if cpus < 2 {
        return TestResult::Skip("single CPU: the syscall and program value widths coincide");
    }
    checked(|| {
        for kind in [MapKind::PerCpuArray, MapKind::PerCpuHash] {
            let m = mk(kind, 4, 8, 2).map_err(|_| "per-CPU create failed")?;
            let ops = m.ops();
            if ops.update(&k32(0), &[0u8; 8], BPF_ANY) != Err(MapError::Invalid) {
                return Err("a per-CPU syscall update accepted a program-width buffer");
            }
            // Width is checked before the key is resolved, so this is `Invalid`
            // and not `NotFound` even for a key the map does not hold.
            if ops.lookup(&k32(0), &mut [0u8; 8]) != Err(MapError::Invalid) {
                return Err("a per-CPU syscall lookup accepted a program-width buffer");
            }
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_percpu_rejects_program_width_buffer);

fn smoke_bpf_map_percpu_hash_views() -> TestResult {
    checked(|| {
        let m = mk(MapKind::PerCpuHash, 4, 8, 4).map_err(|_| "PerCpuHash create failed")?;
        let ops = m.ops();
        let cpus = narf_lib::smp::cpu_count().max(1) as usize;
        if ops.syscall_value_bytes() != cpus * 8 {
            return Err("PerCpuHash syscall_value_bytes is not cpus * stride");
        }
        // `update_local` creates the entry when absent — a per-CPU counter map
        // is written by programs, never by the syscall side, so this is the
        // only path that populates it.
        ops.update_local(&k32(5), &0x33u64.to_le_bytes(), BPF_ANY)
            .map_err(|_| "PerCpuHash update_local could not create an entry")?;
        let mut local = [0u8; 8];
        ops.lookup_local(&k32(5), &mut local)
            .map_err(|_| "PerCpuHash lookup_local failed")?;
        if u64::from_le_bytes(local) != 0x33 {
            return Err("PerCpuHash lookup_local returned the wrong value");
        }
        let mut all = alloc::vec![0u8; cpus * 8];
        ops.lookup(&k32(5), &mut all)
            .map_err(|_| "PerCpuHash syscall lookup failed")?;
        let mut nonzero = 0usize;
        for c in 0..cpus {
            let mut w = [0u8; 8];
            w.copy_from_slice(&all[c * 8..c * 8 + 8]);
            if u64::from_le_bytes(w) != 0 {
                nonzero += 1;
            }
        }
        if nonzero != 1 {
            return Err("PerCpuHash update_local did not write exactly one CPU's slot");
        }
        // Flag policy still applies to the program view.
        if ops.update_local(&k32(5), &local, BPF_NOEXIST) != Err(MapError::Exists) {
            return Err("PerCpuHash update_local ignored BPF_NOEXIST");
        }
        if ops.update_local(&k32(6), &local, BPF_EXIST) != Err(MapError::NotFound) {
            return Err("PerCpuHash update_local ignored BPF_EXIST");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_percpu_hash_views);

// ── creation gates ──────────────────────────────────────────────────

fn smoke_bpf_map_create_rejects_bad_shapes() -> TestResult {
    checked(|| {
        // `max_entries == 0` and `value_size == 0` are EINVAL for every kind:
        // a zero-capacity map has no reachable key and a zero-width value has
        // nothing to store.
        for kind in [
            MapKind::Array,
            MapKind::Hash,
            MapKind::PerCpuArray,
            MapKind::PerCpuHash,
        ] {
            if mk(kind, 4, 8, 0).err() != Some(MapError::Invalid) {
                return Err("max_entries == 0 was accepted");
            }
            if mk(kind, 4, 0, 4).err() != Some(MapError::Invalid) {
                return Err("value_size == 0 was accepted");
            }
            if mk(kind, 0, 8, 4).err() != Some(MapError::Invalid) {
                return Err("key_size == 0 was accepted");
            }
        }
        // The array kinds *are* their index, so the key is exactly 4 bytes.
        for kind in [MapKind::Array, MapKind::PerCpuArray] {
            if mk(kind, 8, 8, 4).err() != Some(MapError::Invalid) {
                return Err("an array kind accepted a key_size other than 4");
            }
        }
        // A hash key may be any width up to the cap.
        if mk(MapKind::Hash, 16, 8, 4).is_err() {
            return Err("Hash refused a 16-byte key");
        }
        if mk(MapKind::Hash, crate::map::MAX_KEY_SIZE + 1, 8, 4).err() != Some(MapError::Invalid) {
            return Err("a key past MAX_KEY_SIZE was accepted");
        }
        if mk(MapKind::Hash, 4, crate::map::MAX_VALUE_SIZE + 1, 4).err() != Some(MapError::TooBig) {
            return Err("a value past MAX_VALUE_SIZE was not TooBig");
        }
        // The *product* is what gets allocated. Both factors below are legal on
        // their own; without a bound on the product this asks for 4 GiB.
        if mk(MapKind::Array, 4, 4096, 1 << 20).err() != Some(MapError::TooBig) {
            return Err("a map whose footprint exceeds MAX_MAP_BYTES was accepted");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_create_rejects_bad_shapes);

fn smoke_bpf_map_create_needs_live_cap() -> TestResult {
    checked(|| {
        // Possession is not authority: the cap is checked live at every entry,
        // so a revoked one fails even though the caller still holds it.
        let cap = Cap::<BpfMapCap, Grant>::bootstrap();
        let attr = MapAttr {
            kind: MapKind::Array,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        };
        if BpfMap::create(&cap, attr, String::new()).is_err() {
            return Err("create with a live cap failed");
        }
        cap.revoke();
        match BpfMap::create(&cap, attr, String::new()) {
            Err(MapError::AuthorityRevoked) => Ok(()),
            Err(_) => Err("create with a revoked cap failed for the wrong reason"),
            Ok(_) => Err("create with a revoked cap succeeded"),
        }
    })
}
kernel_test_in!("bpf", smoke_bpf_map_create_needs_live_cap);

fn smoke_bpf_map_file_is_a_handle() -> TestResult {
    checked(|| {
        use narf_filesystem::FileOps;
        let m = mk(MapKind::Array, 4, 8, 1).map_err(|_| "Array create failed")?;
        let id = m.id;
        let f = crate::map::MapFile::new(m);
        // The downcast every fd-to-map recovery goes through.
        let any = f.as_any().ok_or("MapFile does not expose as_any")?;
        let back = any
            .downcast_ref::<crate::map::MapFile>()
            .ok_or("MapFile did not downcast back to itself")?;
        if back.map().id != id {
            return Err("the recovered map is a different map");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_file_is_a_handle);

// ── map access from a program ───────────────────────────────────────

/// The fd a smoke's `LD_IMM64` immediates name.
///
/// Arbitrary: these tests hand `LoadRequest::maps` the pair directly rather
/// than going through an fd table, so the number only has to agree between the
/// instruction and the list. Deliberately not 0..2, so a resolver that treated
/// the immediate as an *index* would miss.
const SMOKE_MAP_FD: i32 = 7;

fn ld_map_fd(dst: u8, fd: i32) -> Decoded {
    Decoded::LoadImm64 {
        dst: r(dst),
        value: narf_bpf_isa::Imm64::MapFd(fd),
    }
}

fn load_with_map(
    name: &str,
    insns: Vec<Insn>,
    map: &Arc<BpfMap>,
) -> Result<Arc<BpfProg>, crate::prog::LoadError> {
    BpfProg::load(
        load_cap(),
        crate::prog::LoadRequest {
            name: String::from(name),
            insns,
            context: Context::Atomic,
            maps: alloc::vec![(SMOKE_MAP_FD, Arc::clone(map))],
        },
    )
}

/// `r1 = map; r2 = key; r3 = r10 - 8; r4 = 8` — the four registers every map
/// kfunc below starts from.
fn map_call_prelude(key: i32) -> alloc::vec::Vec<Decoded> {
    alloc::vec![
        ld_map_fd(1, SMOKE_MAP_FD),
        mov_imm(2, key),
        mov_reg(3, 10),
        alu_imm(AluOp::Add, 3, -8),
        mov_imm(4, 8),
    ]
}

fn smoke_bpf_map_kfunc_update_then_lookup() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;

        // *(u64*)(r10-8) = 0x5A5A; narf_map_update(map, 1, r10-8, 8, BPF_ANY);
        // exit with the kfunc's return value.
        let mut prog = alloc::vec![st_imm(10, -8, 0x5A5A)];
        prog.extend(map_call_prelude(1));
        prog.extend([mov_imm(5, 0), call("narf_map_update"), EXIT]);
        let p = load_with_map("mapupd", asm(&prog), &m)
            .map_err(|_| "load rejected a program calling narf_map_update")?;
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Returned(0)) => {}
            Some(Outcome::Returned(v)) => {
                // The kfunc reports failure as a negative errno in R0.
                let _ = v;
                return Err("narf_map_update returned an error");
            }
            Some(Outcome::Trapped(_)) => return Err("narf_map_update trapped"),
            None => return Err("run declined"),
        }
        // The kernel side must see it.
        let mut out = [0u8; 8];
        m.ops()
            .lookup(&k32(1), &mut out)
            .map_err(|_| "the map has no entry the program wrote")?;
        if u64::from_le_bytes(out) != 0x5A5A {
            return Err("narf_map_update wrote the wrong value");
        }
        // ...and a neighbouring slot must not have been touched.
        m.ops()
            .lookup(&k32(2), &mut out)
            .map_err(|_| "neighbour lookup failed")?;
        if out != [0u8; 8] {
            return Err("narf_map_update reached the neighbouring slot");
        }

        // Now read it back *from a program*: narf_map_lookup(map, 1, r10-8, 8);
        // r0 = *(u64*)(r10-8); exit.
        let mut prog = map_call_prelude(1);
        prog.extend([call("narf_map_lookup"), ldx(0, 10, -8), EXIT]);
        let p = load_with_map("maplkp", asm(&prog), &m)
            .map_err(|_| "load rejected a program calling narf_map_lookup")?;
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Returned(0x5A5A)) => Ok(()),
            Some(Outcome::Returned(0)) => {
                Err("narf_map_lookup did not write the program's output buffer")
            }
            Some(Outcome::Returned(_)) => Err("narf_map_lookup returned the wrong value"),
            Some(Outcome::Trapped(_)) => Err("narf_map_lookup trapped"),
            None => Err("run declined"),
        }
    })
}
kernel_test_in!("bpf", smoke_bpf_map_kfunc_update_then_lookup);

fn smoke_bpf_map_kfunc_reports_errnos() -> TestResult {
    checked(|| {
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        // A key past `max_entries`: `-ENOENT` from a lookup, and the program
        // gets it as a value rather than as a trap — spec's rule that a kfunc
        // reports failure through R0, because trapping would make every map
        // access a termination point.
        let mut prog = map_call_prelude(9);
        prog.extend([call("narf_map_lookup"), EXIT]);
        let p = load_with_map("maperr", asm(&prog), &m).map_err(|_| "load rejected")?;
        match p.run_atomic([0; 4], 4) {
            // -ENOENT sign-extended into R0.
            Some(Outcome::Returned(v)) if v as i64 == -2 => {}
            Some(Outcome::Returned(0)) => {
                return Err("narf_map_lookup reported success for a missing key")
            }
            Some(Outcome::Returned(_)) => return Err("narf_map_lookup returned the wrong errno"),
            Some(Outcome::Trapped(_)) => {
                return Err("a missing key trapped the program instead of returning an errno")
            }
            None => return Err("run declined"),
        }
        // `delete` is not defined on an array kind: `-EINVAL`.
        let prog = alloc::vec![
            ld_map_fd(1, SMOKE_MAP_FD),
            mov_imm(2, 0),
            call("narf_map_delete"),
            EXIT,
        ];
        let p = load_with_map("mapdel", asm(&prog), &m).map_err(|_| "load rejected")?;
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Returned(v)) if v as i64 == -22 => {}
            Some(Outcome::Returned(_)) => {
                return Err("narf_map_delete on an array was not -EINVAL")
            }
            Some(Outcome::Trapped(_)) => return Err("narf_map_delete trapped"),
            None => return Err("run declined"),
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_kfunc_reports_errnos);

fn smoke_bpf_map_kfunc_wrong_buffer_width_is_einval() -> TestResult {
    checked(|| {
        // The map's value is 8 bytes and the program offers 4. The verifier
        // proves the *region* in bounds — 4 bytes at r10-8 is fine — so nothing
        // upstream catches the mismatch, and without the width check in the
        // kfunc `lookup_local` would be handed a short buffer.
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        let prog = alloc::vec![
            ld_map_fd(1, SMOKE_MAP_FD),
            mov_imm(2, 0),
            mov_reg(3, 10),
            alu_imm(AluOp::Add, 3, -8),
            mov_imm(4, 4),
            call("narf_map_lookup"),
            EXIT,
        ];
        let p = load_with_map("mapwid", asm(&prog), &m).map_err(|_| "load rejected")?;
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Returned(v)) if v as i64 == -22 => Ok(()),
            Some(Outcome::Returned(0)) => {
                Err("narf_map_lookup accepted a buffer narrower than the map value")
            }
            Some(Outcome::Returned(_)) => Err("narf_map_lookup returned the wrong errno"),
            Some(Outcome::Trapped(_)) => Err("narf_map_lookup trapped"),
            None => Err("run declined"),
        }
    })
}
kernel_test_in!("bpf", smoke_bpf_map_kfunc_wrong_buffer_width_is_einval);

fn smoke_bpf_map_kfunc_per_cpu_hash_counter() -> TestResult {
    checked(|| {
        // What a per-CPU map is for: a program aggregating into its own CPU's
        // slot, read back across every CPU from the syscall side.
        let m = mk(MapKind::PerCpuHash, 4, 8, 4).map_err(|_| "PerCpuHash create failed")?;
        let mut prog = alloc::vec![st_imm(10, -8, 0x77)];
        prog.extend(map_call_prelude(3));
        prog.extend([mov_imm(5, 0), call("narf_map_update"), EXIT]);
        let p = load_with_map("pcupd", asm(&prog), &m).map_err(|_| "load rejected")?;
        match p.run_atomic([0; 4], 4) {
            Some(Outcome::Returned(0)) => {}
            Some(Outcome::Returned(_)) => return Err("narf_map_update on a PerCpuHash failed"),
            Some(Outcome::Trapped(_)) => return Err("narf_map_update trapped"),
            None => return Err("run declined"),
        }
        // The syscall view sees exactly one CPU's slot written. A kfunc that
        // took the all-CPU path would show `cpus` of them.
        let cpus = narf_lib::smp::cpu_count().max(1) as usize;
        let mut all = alloc::vec![0u8; cpus * 8];
        m.ops()
            .lookup(&k32(3), &mut all)
            .map_err(|_| "the program's PerCpuHash entry does not exist")?;
        let written = (0..cpus)
            .filter(|c| {
                let mut w = [0u8; 8];
                w.copy_from_slice(&all[c * 8..c * 8 + 8]);
                u64::from_le_bytes(w) == 0x77
            })
            .count();
        if written != 1 {
            return Err("a program's PerCpuHash update did not write exactly one CPU's slot");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_map_kfunc_per_cpu_hash_counter);

fn smoke_bpf_map_handle_may_not_be_dereferenced() -> TestResult {
    checked(|| {
        // The runtime half of the host test `a_map_handle_may_not_be_dereferenced`.
        // A map handle is a *real kernel address* in a program-visible register,
        // which is the one exception to "the interpreter never dereferences a
        // program-supplied address" — so the load through it has to be refused
        // at verification, not left to the interpreter's region check.
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        let prog = alloc::vec![ld_map_fd(1, SMOKE_MAP_FD), ldx(0, 1, 0), EXIT];
        match load_with_map("mapderef", asm(&prog), &m) {
            Err(crate::prog::LoadError::Rejected(
                narf_bpf_verifier::VerifyError::OpaqueDeref { .. },
            )) => Ok(()),
            Err(_) => Err("dereferencing a map handle was rejected for the wrong reason"),
            Ok(_) => Err("a program dereferencing a map handle was accepted"),
        }
    })
}
kernel_test_in!("bpf", smoke_bpf_map_handle_may_not_be_dereferenced);

fn smoke_bpf_map_reference_needs_the_real_verifier() -> TestResult {
    checked(|| {
        // `crate::provisional` cannot prove a map handle reaches a kfunc at
        // offset zero, so it refuses every map form. Without that, a program the
        // real verifier could not prove would still get a raw `Arc<BpfMap>`
        // pointer in a register it may do arithmetic on.
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        // `run_unverified` is the only way to reach the interpreter without a
        // passing `verify()`, and it is what the provisional path used to feed.
        // Here the point is the *load* gate: a map form plus something the real
        // verifier rejects must not fall through to `provisional` and be
        // accepted.
        let prog = alloc::vec![
            ld_map_fd(1, SMOKE_MAP_FD),
            // Returning a pointer is rejected by the real verifier, so this
            // program cannot pass it; if it fell through to `provisional`
            // instead, that path would have to reject it too.
            mov_reg(0, 1),
            EXIT,
        ];
        match load_with_map("mapprov", asm(&prog), &m) {
            Err(crate::prog::LoadError::Rejected(_)) => Ok(()),
            Err(_) => Err("rejected for the wrong reason"),
            Ok(_) => Err("a program returning a map handle was accepted"),
        }
    })
}
kernel_test_in!("bpf", smoke_bpf_map_reference_needs_the_real_verifier);

fn smoke_bpf_map_value_pseudo_form_is_refused_at_load() -> TestResult {
    checked(|| {
        // The verifier resolves and bounds `BPF_PSEUDO_MAP_VALUE`; no backend
        // can produce the address. A program the verifier accepts and the
        // runtime cannot execute is a contract break, so it is refused at load
        // rather than trapping at fire time.
        let m = mk(MapKind::Array, 4, 8, 4).map_err(|_| "Array create failed")?;
        let prog = alloc::vec![
            Decoded::LoadImm64 {
                dst: r(1),
                value: narf_bpf_isa::Imm64::MapValue {
                    fd: SMOKE_MAP_FD,
                    value_offset: 0,
                },
            },
            mov_imm(0, 0),
            EXIT,
        ];
        match load_with_map("mapval", asm(&prog), &m) {
            Err(crate::prog::LoadError::Rejected(
                narf_bpf_verifier::VerifyError::NotImplemented(_),
            )) => Ok(()),
            Err(_) => Err("the map-value pseudo-form was refused for the wrong reason"),
            Ok(_) => Err("a program the interpreter cannot run was accepted"),
        }
    })
}
kernel_test_in!("bpf", smoke_bpf_map_value_pseudo_form_is_refused_at_load);
