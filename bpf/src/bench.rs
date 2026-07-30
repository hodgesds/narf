//! Benchmark cases for the BPF runtime.
//!
//! Declared against `narf-bpf-bench`, which owns the sampling discipline; this
//! module owns only *what* is measured. Compiled under the `bench` feature and
//! run only when the kernel cmdline carries `bpf_bench`, so a production build
//! neither links nor pays for it.
//!
//! ## What is measured, and what is deliberately not
//!
//! **Interpreter throughput, per fuel policy.** `interp.rs` burns one unit of
//! fuel per instruction retired, which adds a decrement and a conditional
//! branch to the hot loop. That change landed with the justification that "the
//! interpreter is already paying a decode and a match per instruction, so the
//! marginal cost is noise" — an assertion, not a measurement. Each shape below
//! is therefore declared twice, once per policy, as an A/B pair the host
//! compares directly. If the cost is material, `bpf/specification/spec.md`
//! §8 item 7 is not as resolved as it says.
//!
//! **Load-time latency, decomposed.** `BpfProg::load` runs inside `sys_bpf`
//! with no yield point, so what matters is latency, not throughput. It is
//! measured whole and also split into verify / codegen / publish, which makes
//! the three parts add up to the whole — a consistency check on the
//! decomposition, and the only way to tell which of the three a future
//! regression landed in.
//!
//! **Not measured: JIT versus interpreter.** `jit_glue`'s five gates exclude
//! back-edges, so no JIT-able program contains a loop, and a straight-line
//! handful of instructions measures call overhead rather than codegen quality.
//! A number there would satisfy the protocol and mean nothing. It becomes
//! measurable when per-block fuel emission lifts gate 4.
//!
//! ## Why the interpreter cases drive `Vm` directly
//!
//! They construct a `Vm` rather than calling `BpfProg::run_atomic`, because
//! `run_atomic` adds a per-CPU stack claim, a registry lookup, and two atomic
//! counter updates per invocation — real costs, but per *invocation*, and these
//! cases measure cost per *instruction*. Each program is a loop retiring tens
//! of thousands of instructions per run precisely so that setup lands in the
//! noise; measuring the invocation path is a separate benchmark that does not
//! exist yet because nothing has asked what it costs.

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_bpf_bench::{measure, observe, Benchmark, Sample};
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{AluOp, CallTarget, CondOp, Decoded, Insn, Reg, Size, Source};
use narf_bpf_verifier::kfunc::Context;
use narf_bpf_verifier::{ArgDesc, VerifiedProgram};
use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::interp::{drive, Vm, VmProgram, MAX_CTX_WORDS};
use crate::mem::{BpfStack, HeapStack};
use crate::prog::{BpfProg, BpfProgLoad, LoadRequest};

// ── program construction ────────────────────────────────────────────

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

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

const EXIT: Decoded = Decoded::Exit;

/// Instruction mixes the interpreter is measured on.
///
/// Four shapes rather than one because the per-instruction fuel burn is a
/// fixed cost added to a *variable* one: it is a larger fraction of a cheap
/// ALU dispatch than of a bounds-checked store, so one shape could hide the
/// answer either way.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Shape {
    /// Register-to-register arithmetic — the cheapest dispatch there is, so
    /// the fuel burn's largest relative share.
    Alu,
    /// Stack stores and loads, each bounds-checked against the synthetic
    /// region (`interp.rs`'s address model).
    Mem,
    /// Not-taken conditional branches, which exercise `cond()` and the
    /// interpreter's own branch predictor rather than the ALU.
    Branch,
    /// A subprogram call per iteration: frame push, callee-saved spill,
    /// frame pop.
    Call,
}

impl Shape {
    /// Loop iterations, chosen so every shape retires ≈30 000 instructions
    /// per run. Equal *work* per sample rather than equal *iterations*: a
    /// sample is only comparable across shapes if the amount of interpreting
    /// it did is comparable, and the shapes have different body lengths.
    const fn iterations(self) -> i32 {
        match self {
            // 10 instructions per iteration (8 body + counter + back-edge).
            Shape::Alu | Shape::Mem | Shape::Branch => 3_000,
            // 5 per iteration: call, two in the callee, counter, back-edge.
            Shape::Call => 6_000,
        }
    }
}

/// Build a counted loop around `body`.
///
/// R6 is the counter: it is callee-saved under the BPF ABI, so the `Call`
/// shape's subprogram cannot clobber it, and the loop therefore measures the
/// call rather than a corrupted trip count.
fn counted_loop(body: &[Decoded], trips: i32) -> Vec<Insn> {
    let mut prog: Vec<Decoded> = Vec::new();
    prog.push(mov_imm(6, trips));
    let loop_top = prog.len();
    prog.extend_from_slice(body);
    prog.push(alu_imm(AluOp::Sub, 6, 1));
    // The back-edge is relative to the *next* instruction, so from the jump at
    // index `i` the offset to `loop_top` is `loop_top - (i + 1)`.
    let jump_at = prog.len();
    let off = loop_top as i32 - (jump_at as i32 + 1);
    prog.push(Decoded::JumpCond {
        wide: true,
        op: CondOp::Ne,
        dst: r(6),
        src: Source::Imm(0),
        off: off as i16,
    });
    prog.push(mov_imm(0, 0));
    prog.push(EXIT);
    // Every shape is one slot per instruction (no LD_IMM64), so the decoded
    // indices above are also slot indices and the offsets survive encoding.
    // A shape that grows an `LD_IMM64` must switch to building offsets from
    // encoded lengths instead.
    asm(&prog)
}

fn shape_program(shape: Shape) -> Vec<Insn> {
    let trips = shape.iterations();
    match shape {
        Shape::Alu => counted_loop(
            &[
                alu_reg(AluOp::Add, 1, 2),
                alu_reg(AluOp::Xor, 3, 1),
                alu_imm(AluOp::Mul, 1, 3),
                alu_reg(AluOp::Sub, 2, 1),
                alu_reg(AluOp::Or, 4, 1),
                alu_reg(AluOp::And, 5, 1),
                alu_imm(AluOp::Lsh, 1, 1),
                alu_imm(AluOp::Rsh, 1, 1),
            ],
            trips,
        ),
        Shape::Mem => {
            let mut body: Vec<Decoded> = Vec::new();
            for i in 0..4i16 {
                let off = -8 * (i + 1);
                body.push(Decoded::Store {
                    size: Size::Dw,
                    dst: r(10),
                    off,
                    src: Source::Reg(r(1)),
                });
                body.push(Decoded::Load {
                    size: Size::Dw,
                    sign_extend: false,
                    dst: r(2),
                    src: r(10),
                    off,
                });
            }
            counted_loop(&body, trips)
        }
        Shape::Branch => {
            let mut body: Vec<Decoded> = Vec::new();
            for _ in 0..4 {
                // Never taken: R1 is 0 on entry and the body leaves it alone,
                // so this is a predictable not-taken branch plus a filler.
                body.push(Decoded::JumpCond {
                    wide: true,
                    op: CondOp::Eq,
                    dst: r(1),
                    src: Source::Imm(0x7FFF),
                    off: 1,
                });
                body.push(alu_imm(AluOp::Add, 2, 1));
            }
            counted_loop(&body, trips)
        }
        Shape::Call => {
            // Hand-laid rather than built through `counted_loop`, because the
            // callee has to sit past the `exit` and the call offset has to know
            // where.
            //
            //   0: r6 = trips
            //   1: call +4          → 6
            //   2: r6 -= 1
            //   3: if r6 != 0 goto -3   → 1
            //   4: r0 = 0
            //   5: exit
            //   6: r0 = 1
            //   7: exit
            asm(&[
                mov_imm(6, trips),
                Decoded::Call(CallTarget::Subprog(4)),
                alu_imm(AluOp::Sub, 6, 1),
                Decoded::JumpCond {
                    wide: true,
                    op: CondOp::Ne,
                    dst: r(6),
                    src: Source::Imm(0),
                    off: -3,
                },
                mov_imm(0, 0),
                EXIT,
                mov_imm(0, 1),
                EXIT,
            ])
        }
    }
}

/// Straight-line ALU program of `n` instructions plus `exit`, for the
/// load-time cases.
///
/// Straight-line because the JIT's gate 4 rejects back-edges, and the point of
/// the codegen and publish cases is to measure the path a program that *is*
/// compiled takes.
fn straight_line(n: usize) -> Vec<Insn> {
    let mut prog: Vec<Decoded> = Vec::with_capacity(n + 1);
    prog.push(mov_imm(0, 1));
    for i in 1..n {
        prog.push(alu_imm(AluOp::Add, 0, (i % 7) as i32 + 1));
    }
    prog.push(EXIT);
    asm(&prog)
}

/// Forward-branching program of roughly `n` instructions.
///
/// Each `if` is a fork the abstract interpreter must explore, so this is the
/// shape whose verification cost is not linear in instruction count. It is
/// here because the verifier's fixpoint is the part of load most likely to
/// surprise, and a straight line cannot show it.
fn branchy(pairs: usize) -> Vec<Insn> {
    let mut prog: Vec<Decoded> = Vec::new();
    // R0 first. Without it the verifier rejects the whole image with
    // `UninitRegister { at: 5, reg: 0 }` — correctly, since the body's `r0 += 1`
    // reads a register nothing wrote. It is worth noting how this failed: the
    // first run of this suite skipped *every* case, because one rejected image
    // took the shared cache down with it. Both halves of that are fixed.
    prog.push(mov_imm(0, 0));
    prog.push(mov_imm(1, 0));
    for i in 0..pairs {
        prog.push(Decoded::JumpCond {
            wide: true,
            op: CondOp::Eq,
            dst: r(1),
            src: Source::Imm(i as i32),
            off: 2,
        });
        prog.push(alu_imm(AluOp::Add, 0, 1));
        prog.push(alu_imm(AluOp::Add, 0, 2));
    }
    prog.push(EXIT);
    asm(&prog)
}

// ── cached state ────────────────────────────────────────────────────

/// The programs, built once.
///
/// Built on first sample and leaked, not rebuilt per sample: assembling a
/// 6 000-instruction image allocates, and an allocation inside a timing window
/// measures the slab.
struct Cache {
    /// Indexed by `Shape as usize`, so the array's order and the enum's
    /// declaration order are the same fact stated twice. `cache()` builds it
    /// in that order.
    shapes: [Vec<Insn>; 4],
    /// Verified forms of [`Cache::load_images`], positionally.
    ///
    /// `Option` per entry, not a single `Option` over the lot: a shape the
    /// verifier declines must cost only its own cases their samples. The first
    /// run of this suite had one rejected image return `None` from `cache()`,
    /// which skipped all seventeen benchmarks including every interpreter one —
    /// a shared cache turning one bad fixture into total silence.
    verified: Vec<Option<VerifiedProgram>>,
    /// Un-verified images for the load-path cases, cloned per iteration.
    load_images: Vec<Vec<Insn>>,
}

static CACHE: IrqSafeSpinLock<Option<&'static Cache>> = IrqSafeSpinLock::new(None);

/// Straight-line instruction counts the verifier is measured at. Powers of
/// four so a superlinear fixpoint shows up as a rising cycles-per-instruction
/// figure across three points rather than having to be inferred from one.
const VERIFY_SIZES: [usize; 3] = [16, 64, 256];

/// Forward-branch forks in the branchy verification shape.
///
/// 64 forks is 194 instruction slots (two prologue movs, three per fork, one
/// `exit`), which is where the `branchy194` benchmark's name comes from — named
/// for its size rather than its fork count so it is directly comparable with
/// `straight256`.
const BRANCHY_PAIRS: usize = 64;

/// The four scalar words of the probe context tuple, as `prog.rs` declares
/// them. Duplicated rather than shared because `prog.rs`'s copy is private and
/// a benchmark is not a reason to widen a module's surface.
static CTX_SCALARS: [ArgDesc; MAX_CTX_WORDS] = [ArgDesc::SCALAR64; MAX_CTX_WORDS];

fn verifier_program<'a>(
    insns: &'a [Insn],
    descs: &'a [narf_bpf_verifier::KfuncDesc],
) -> narf_bpf_verifier::Program<'a> {
    narf_bpf_verifier::Program {
        insns,
        context: Context::Atomic,
        ctx_fields: &CTX_SCALARS,
        kfuncs: descs,
    }
}

fn cache() -> Option<&'static Cache> {
    let mut slot = CACHE.lock();
    if let Some(c) = *slot {
        return Some(c);
    }
    let registry = crate::kfunc::registry()?;
    let descs: Vec<_> = registry.all().iter().map(|e| e.desc()).collect();

    let shapes = [
        shape_program(Shape::Alu),
        shape_program(Shape::Mem),
        shape_program(Shape::Branch),
        shape_program(Shape::Call),
    ];

    let mut load_images = Vec::new();
    for n in VERIFY_SIZES {
        load_images.push(straight_line(n));
    }
    load_images.push(branchy(BRANCHY_PAIRS));

    // A `None` here means the verifier declined a shape this module built,
    // which is a bug in the shape rather than a result — the cases that need
    // that shape skip with a reason instead of timing a rejection.
    let verified: Vec<Option<VerifiedProgram>> = load_images
        .iter()
        .map(|img| narf_bpf_verifier::verify(&verifier_program(img, &descs)).ok())
        .collect();

    let c: &'static Cache = Box::leak(Box::new(Cache {
        shapes,
        verified,
        load_images,
    }));
    *slot = Some(c);
    Some(c)
}

/// The load authority, minted once.
///
/// `Cap::bootstrap()` allocates an object-table slot per call, so minting one
/// per sample would leak a slot per sample — and 50 samples across a suite is
/// exactly the loop that rule exists for.
fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Box::leak(Box::new(Cap::<BpfProgLoad, Grant>::bootstrap())));
    }
    g.expect("just installed")
}

/// The JIT authority, minted once, for the same reason.
///
/// Distinct from `jit_glue`'s own cap only because that one is private. Both
/// are the kernel's authority over its own text; there is no user on whose
/// behalf either could be checked.
fn jit_cap() -> &'static Cap<narf_memory::bpf_text::Jit, Grant> {
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<narf_memory::bpf_text::Jit, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Box::leak(Box::new(
            Cap::<narf_memory::bpf_text::Jit, Grant>::bootstrap(),
        )));
    }
    g.expect("just installed")
}

// ── interpreter cases ───────────────────────────────────────────────

/// Bytes of BPF stack the shapes are run on.
///
/// 2 KiB rather than the 512 the `Mem` shape needs, because the `Call` shape
/// pushes a frame and `push_frame` falls back to `FRAME_BYTES` when the
/// subprogram table is empty — which it is here, since these images are run
/// directly rather than loaded.
const BENCH_STACK_BYTES: usize = 2048;

/// Which arm of the fuel experiment a sample runs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Arm {
    /// The production policy: `Vm::run`.
    PerInsn,
    /// The policy it replaced.
    Hoisted,
    /// The production policy again, through a second monomorphisation. See
    /// `interp::FUEL_PER_INSN_CONTROL` — this is the A/A control that says how
    /// much of any A/B difference is code placement rather than fuel.
    PerInsnControl,
}

fn sample_interp(shape: Shape, arm: Arm, iters: u32) -> Option<Sample> {
    let cache = cache()?;
    let registry = crate::kfunc::registry()?;
    let insns = &cache.shapes[shape as usize];
    // Allocated outside the timing window: a sleepable program's heap stack is
    // allocated before its first instruction too (`mem.rs` says why), so this
    // is not sleight of hand — it is where the allocation belongs.
    let stack = HeapStack::new(BENCH_STACK_BYTES);

    let mut steps = 0u64;
    let mut cycles = 0u64;
    for _ in 0..iters {
        let frame = stack.acquire(BENCH_STACK_BYTES)?;
        let mut vm = Vm::new(
            VmProgram {
                insns,
                subprogs: &[],
                context: Context::Atomic,
                fuel: narf_bpf_verifier::DEFAULT_FUEL,
            },
            [0; MAX_CTX_WORDS],
            0,
            frame,
            registry,
        );
        let (c, outcome) = measure(|| match arm {
            Arm::PerInsn => drive(vm.run()),
            Arm::Hoisted => drive(vm.run_fuel_hoisted()),
            Arm::PerInsnControl => drive(vm.run_fuel_per_insn_control()),
        });
        // A trap means the shape ran out of fuel or escaped its region, which
        // makes the sample a measurement of the failure path. Decline rather
        // than report it: the two fuel arms would then be timing different
        // amounts of work, which is the one thing an A/B may not do.
        if !observe(outcome).is_ok() {
            return None;
        }
        cycles = cycles.wrapping_add(c);
        steps = steps.wrapping_add(vm.steps());
    }
    Some(Sample {
        value: cycles,
        work: steps,
    })
}

// ── load-path cases ─────────────────────────────────────────────────

fn sample_verify(idx: usize, iters: u32) -> Option<Sample> {
    let cache = cache()?;
    let registry = crate::kfunc::registry()?;
    let descs: Vec<_> = registry.all().iter().map(|e| e.desc()).collect();
    let insns = cache.load_images.get(idx)?;
    let prog = verifier_program(insns, &descs);
    let (cycles, ok) = measure(|| {
        let mut all_ok = true;
        for _ in 0..iters {
            all_ok &= observe(narf_bpf_verifier::verify(&prog)).is_ok();
        }
        all_ok
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: u64::from(iters),
    })
}

fn sample_codegen(idx: usize, iters: u32) -> Option<Sample> {
    let cache = cache()?;
    let v = cache.verified.get(idx)?.as_ref()?;
    // Probe once outside the window: on aarch64 there is no emitter, so this
    // case must skip rather than time a `Err(Unsupported)` return.
    narf_bpf_jit::compile(v).ok()?;
    let (cycles, ok) = measure(|| {
        let mut all_ok = true;
        for _ in 0..iters {
            all_ok &= observe(narf_bpf_jit::compile(v)).is_ok();
        }
        all_ok
    });
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: u64::from(iters),
    })
}

/// Text allocation, write, extable registration, and the RW→RX seal.
///
/// The three steps are timed together because §4.3 makes their *order* load
/// bearing — register before seal — and a benchmark that timed them apart
/// would be measuring a sequence the kernel is not allowed to perform.
fn sample_publish(idx: usize, iters: u32) -> Option<Sample> {
    use narf_memory::{bpf_extable, bpf_text};

    let cache = cache()?;
    let v = cache.verified.get(idx)?.as_ref()?;
    let compiled = narf_bpf_jit::compile(v).ok()?;
    let cap = jit_cap();

    let mut allocs = Vec::with_capacity(iters as usize);
    let (cycles, ok) = measure(|| {
        for _ in 0..iters {
            let Ok(a) = bpf_text::alloc(cap, compiled.code.len(), 0) else {
                return false;
            };
            if bpf_text::write(&a, 0, &compiled.code).is_err() {
                allocs.push(a);
                return false;
            }
            let (lo, hi) = (a.va, a.va + a.len as u64);
            if bpf_extable::register_image(lo, lo, hi, Vec::new()).is_err() {
                allocs.push(a);
                return false;
            }
            let sealed = bpf_text::seal(cap, &a).is_ok();
            allocs.push(a);
            if !sealed {
                return false;
            }
        }
        true
    });

    // Teardown outside the window, through the production path: `free` routes
    // to the RCU reclaim hook `register_initcalls` installed, which is what
    // unregisters the extable entry after a grace period. Freeing here without
    // it would leave a stale registration on a VA `bpf_text` reuses, and
    // `register_image` rejects overlaps — which would brick every later
    // sample.
    for a in allocs {
        bpf_text::free(a);
    }
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: u64::from(iters),
    })
}

/// End-to-end `BpfProg::load`: verify, then compile and publish if the gates
/// allow it.
///
/// Should equal verify + codegen + publish for the same image, which is the
/// point: a decomposition nothing checks is a decomposition that drifts.
fn sample_load_total(idx: usize, iters: u32) -> Option<Sample> {
    let cache = cache()?;
    let insns = cache.load_images.get(idx)?;
    let cap = load_cap();
    // Requests built outside the window: `LoadRequest` owns its image, and
    // cloning a 256-instruction `Vec` inside would time the allocator.
    let mut reqs: Vec<LoadRequest> = (0..iters)
        .map(|i| LoadRequest {
            name: alloc::format!("bench{i}"),
            insns: insns.clone(),
            context: Context::Atomic,
        })
        .collect();

    let mut progs = Vec::with_capacity(iters as usize);
    let (cycles, ok) = measure(|| {
        let mut all_ok = true;
        for req in reqs.drain(..) {
            match BpfProg::load(cap, req) {
                Ok(p) => progs.push(p),
                Err(_) => all_ok = false,
            }
        }
        all_ok
    });
    // Dropped outside the window: the `Arc` drop frees any JIT image, which
    // quarantines text and defers through RCU — teardown cost, not load cost.
    drop(progs);
    if !ok {
        return None;
    }
    Some(Sample {
        value: cycles,
        work: u64::from(iters),
    })
}

// ── declarations ────────────────────────────────────────────────────

/// Inner iterations for the interpreter shapes.
///
/// One: each run already retires ≈30 000 instructions, which is four orders of
/// magnitude more than the `rdtsc` pair costs. Raising it would only lengthen
/// the interrupt-masked window.
const INTERP_ITERS: u32 = 1;

/// Inner iterations for the load cases. Eight, because a single verify of a
/// 16-instruction program is short enough for timer granularity to matter.
const LOAD_ITERS: u32 = 8;

/// δ for every case here: 3%.
///
/// Not a target, a threshold — §8.6.6 makes a significant difference smaller
/// than δ recorded rather than blocking. 3% is roughly twice the run-to-run
/// spread seen on a KVM guest with the host's noise controls unverified, so a
/// difference that clears it is a difference in the code rather than in the
/// machine.
const DELTA_PCT: f64 = 3.0;

/// N. Above §8.3's floor of 30 because the bootstrap CI on a skewed latency
/// distribution tightens noticeably between 30 and 60, and a sample costs
/// ≈100 µs.
const TARGET_N: u32 = 60;

macro_rules! interp_case {
    ($name:literal, $pair:literal, $shape:expr, $arm:expr) => {
        Benchmark {
            name: $name,
            subsystem: "bpf",
            unit: "cycles",
            lower_is_better: true,
            warmup: 3,
            iters: INTERP_ITERS,
            target_n: TARGET_N,
            delta_pct: DELTA_PCT,
            compare_with: Some($pair),
            sample: |iters| sample_interp($shape, $arm, iters),
            skip_reason: "kfunc registry or BPF stack unavailable, or the shape trapped",
        }
    };
}

/// Declare one shape's three arms: the A/B pair and the A/A control.
///
/// A macro over the whole triple rather than three `interp_case!`s, because the
/// cross-links have to agree — the control must name the production arm and the
/// pair must name each other, and writing twelve of those by hand is twelve
/// chances to point a benchmark at the wrong peer and get a meaningless
/// comparison that still looks like a result.
macro_rules! interp_triple {
    ($shape:expr, $per_insn:literal, $hoisted:literal, $control:literal) => {
        [
            interp_case!($per_insn, $hoisted, $shape, Arm::PerInsn),
            interp_case!($hoisted, $per_insn, $shape, Arm::Hoisted),
            interp_case!($control, $per_insn, $shape, Arm::PerInsnControl),
        ]
    };
}

macro_rules! load_case {
    ($name:literal, $f:expr, $reason:literal) => {
        Benchmark {
            name: $name,
            subsystem: "bpf",
            unit: "cycles",
            lower_is_better: true,
            warmup: 3,
            iters: LOAD_ITERS,
            target_n: TARGET_N,
            delta_pct: DELTA_PCT,
            compare_with: None,
            sample: $f,
            skip_reason: $reason,
        }
    };
}

/// The fuel-granularity experiment, one group per instruction mix.
///
/// Grouped per shape rather than flattened because the harness takes groups and
/// the shape is the unit that has to stay internally consistent: three arms,
/// two comparisons, all four names sharing a prefix.
static ALU_FUEL: [Benchmark; 3] = interp_triple!(
    Shape::Alu,
    "bpf.interp.alu.fuel_per_insn",
    "bpf.interp.alu.fuel_hoisted",
    "bpf.interp.alu.fuel_per_insn_ctl"
);
static MEM_FUEL: [Benchmark; 3] = interp_triple!(
    Shape::Mem,
    "bpf.interp.mem.fuel_per_insn",
    "bpf.interp.mem.fuel_hoisted",
    "bpf.interp.mem.fuel_per_insn_ctl"
);
static BRANCH_FUEL: [Benchmark; 3] = interp_triple!(
    Shape::Branch,
    "bpf.interp.branch.fuel_per_insn",
    "bpf.interp.branch.fuel_hoisted",
    "bpf.interp.branch.fuel_per_insn_ctl"
);
static CALL_FUEL: [Benchmark; 3] = interp_triple!(
    Shape::Call,
    "bpf.interp.call.fuel_per_insn",
    "bpf.interp.call.fuel_hoisted",
    "bpf.interp.call.fuel_per_insn_ctl"
);

/// Load-time latency, whole and decomposed.
static LOAD_BENCHES: &[Benchmark] = &[
    load_case!(
        "bpf.load.verify.straight16",
        |i| sample_verify(0, i),
        "verifier declined the benchmark's own image"
    ),
    load_case!(
        "bpf.load.verify.straight64",
        |i| sample_verify(1, i),
        "verifier declined the benchmark's own image"
    ),
    load_case!(
        "bpf.load.verify.straight256",
        |i| sample_verify(2, i),
        "verifier declined the benchmark's own image"
    ),
    load_case!(
        "bpf.load.verify.branchy194",
        |i| sample_verify(3, i),
        "verifier declined the benchmark's own image"
    ),
    load_case!(
        "bpf.load.codegen.straight64",
        |i| sample_codegen(1, i),
        "no native emitter for this architecture"
    ),
    load_case!(
        "bpf.load.publish.straight64",
        |i| sample_publish(1, i),
        "no native emitter, or executable text unavailable"
    ),
    load_case!(
        "bpf.load.total.straight64",
        |i| sample_load_total(1, i),
        "load rejected the benchmark's own image"
    ),
    load_case!(
        "bpf.load.total.branchy194",
        |i| sample_load_total(3, i),
        "load rejected the benchmark's own image"
    ),
];

/// The harness's own noise floor.
///
/// Times an empty window, so its median is the cost of the `rdtsc` pair plus
/// the interrupt mask/unmask, and its spread is the environment's. A run whose
/// benchmark CVs are indistinguishable from this one's is measuring the
/// machine, not the code — which is a thing worth being able to see rather
/// than infer.
static NOISE: &[Benchmark] = &[Benchmark {
    name: "bpf.harness.noise_floor",
    subsystem: "bpf",
    unit: "cycles",
    lower_is_better: true,
    warmup: 3,
    iters: 1,
    target_n: TARGET_N,
    delta_pct: DELTA_PCT,
    compare_with: None,
    sample: |_| {
        let (cycles, ()) = measure(|| {});
        Some(Sample {
            value: cycles,
            work: 1,
        })
    },
    skip_reason: "unreachable",
}];

/// Contribute the suite. Called from `crate::register_initcalls`.
pub fn register() {
    narf_bpf_bench::register_group(NOISE);
    narf_bpf_bench::register_group(&ALU_FUEL);
    narf_bpf_bench::register_group(&MEM_FUEL);
    narf_bpf_bench::register_group(&BRANCH_FUEL);
    narf_bpf_bench::register_group(&CALL_FUEL);
    narf_bpf_bench::register_group(LOAD_BENCHES);
    narf_bpf_bench::register_initcalls();
}
