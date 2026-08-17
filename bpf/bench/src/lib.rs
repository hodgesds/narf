//! # `narf-bpf-bench` — the sampling half of the perf protocol
//!
//! `verification/specification/spec.md` §8 splits a performance number into
//! two jobs: collecting samples under stated conditions, and deciding what the
//! samples mean. This crate does only the first. It emits every raw sample to
//! the console; `cargo xtask bpf-bench` computes the median, the 95% bootstrap
//! CI, Welch's t, Mann-Whitney U, and the Benjamini-Hochberg correction.
//!
//! The split is not squeamishness about `f64` in a kernel. It is that §8.5
//! forbids silent trimming and §8.8 archives the whole sample vector, so the
//! samples must leave the kernel regardless — and once they have, 10 000
//! bootstrap resamples belong somewhere with a heap, a debugger, and unit
//! tests rather than in an initcall.
//!
//! ## This is not a test
//!
//! Benchmarks are deliberately *not* registered through `narf-kernel-test`. A
//! `kernel_test!` entry answers pass/fail, and a benchmark that answers
//! pass/fail has already thrown away the number. Nothing here can fail a
//! build; the suite runs only when the kernel cmdline asks for it
//! (`bpf_bench`), and a case that cannot run reports `skip` with a reason
//! instead of contributing a zero.
//!
//! ## What the harness guarantees, and what it cannot
//!
//! Guaranteed, because the harness controls it:
//!
//! * Warmup iterations are discarded (§8.1).
//! * Each sample brackets `iters` measured inner iterations, so the two
//!   `rdtsc` reads amortise away instead of dominating (§8.1).
//! * Samples are collected **round-robin across the whole suite** rather than
//!   benchmark-by-benchmark. Any drift over the run — thermal, host-side
//!   scheduling under a VM, another vCPU waking up — then lands on every
//!   benchmark equally, which is what makes an A/B pair a *paired* comparison
//!   rather than two independent ones separated in time.
//! * Interrupts are masked for the duration of each individual sample, and
//!   only for that duration. See [`measure`].
//!
//! Not guaranteed, and reported rather than papered over: every §8.2
//! noise-control precondition (governor, turbo, SMT, ASLR, thermal
//! tripwires) is a property of the machine outside the kernel. The harness
//! emits what it can observe into the `narf.bench.env:` line and the host
//! side refuses to call a run publishable unless it verified the rest.
//!
//! ## Output grammar
//!
//! One `narf.bench.env:` line, then per benchmark one `narf.bench.rec:` line
//! followed by `narf.bench.val:` chunks carrying the samples, then one
//! `narf.bench.end:` line. Line-oriented `key=value` rather than JSON because
//! the emitter is `core::fmt` and the parser is a `split_whitespace` in xtask;
//! the §8.8 JSON record is assembled host-side, where the statistics it
//! carries are computed.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_lib::sync::{without_interrupts, IrqSafeSpinLock};

/// One observation of one benchmark's metric.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    /// The metric, in the benchmark's declared unit.
    pub value: u64,
    /// Work units the sample covered — interpreted BPF instructions retired,
    /// program loads performed, whatever the benchmark's unit is *per*.
    ///
    /// Kept per sample rather than declared once because it is the check on
    /// the declaration: if two samples of the same benchmark disagree about
    /// how much work they did, then the samples are not comparable and any
    /// per-work figure derived from them is fiction. The runner emits
    /// `work_varied=1` when that happens.
    pub work: u64,
}

/// A benchmark, per §8.1: a deterministic routine returning one sample of one
/// scalar metric, plus the declarations that make the sample interpretable.
#[derive(Copy, Clone)]
pub struct Benchmark {
    /// Dotted metric name, e.g. `bpf.interp.loop.fuel_per_insn`. The host
    /// keys baselines off this, so it is an interface: renaming one orphans
    /// its history.
    pub name: &'static str,
    /// Owning subsystem, for grouping output.
    pub subsystem: &'static str,
    /// Metric unit, e.g. `cycles`.
    pub unit: &'static str,
    /// Direction of goodness.
    pub lower_is_better: bool,
    /// Warmup iterations, discarded (§8.1).
    pub warmup: u32,
    /// Measured inner iterations per sample (§8.1). Chosen so a sample is
    /// long enough to swamp the timer pair and short enough that masking
    /// interrupts across it is harmless.
    pub iters: u32,
    /// Target sample count. §8.3 sets the floor at 30 and asks for 100 when
    /// the observed CV exceeds 5%; the host reports CV so the next run can
    /// raise this.
    pub target_n: u32,
    /// Declared δ, in percent: the smallest change worth blocking a merge on
    /// (§8.6.6). A significant difference smaller than this is recorded, not
    /// blocking.
    pub delta_pct: f64,
    /// Name of the benchmark this one is the A/B counterpart of, if any.
    ///
    /// Two benchmarks naming each other form a pair the host compares
    /// directly instead of against a stored baseline. That is the shape a
    /// "does this implementation choice cost anything" question has, and it
    /// needs no baseline archive to answer.
    pub compare_with: Option<&'static str>,
    /// Collect one sample over `iters` inner iterations.
    ///
    /// `None` means the case cannot run here — a missing registry, an
    /// unavailable per-CPU region — and is reported as a skip with the
    /// benchmark's `skip_reason`. Returning a zero instead would put a
    /// fabricated sample into a statistical test.
    pub sample: fn(u32) -> Option<Sample>,
    /// Why `sample` might return `None`, for the skip line.
    pub skip_reason: &'static str,
}

impl core::fmt::Debug for Benchmark {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Benchmark")
            .field("name", &self.name)
            .field("unit", &self.unit)
            .field("iters", &self.iters)
            .field("target_n", &self.target_n)
            .finish_non_exhaustive()
    }
}

// ── measurement primitives ──────────────────────────────────────────

/// Read the cycle counter with the compiler pinned on both sides.
///
/// `narf_time::now_cycles()` is `lfence; rdtsc`, which orders the read against
/// the *CPU's* out-of-order engine — but its `asm!` carries `options(nomem)`,
/// which tells LLVM the instruction touches no memory and may therefore be
/// hoisted or sunk across the loads and stores it is supposed to bracket.
/// Under fat LTO that is not theoretical. A `compiler_fence` on each side is
/// what keeps the timing window closed; it is the same discipline the domain
/// intrinsics use (AGENTS.md invariant 4) and for the same reason.
#[inline]
fn cycles_fenced() -> u64 {
    compiler_fence(Ordering::SeqCst);
    let c = narf_time::now_cycles();
    compiler_fence(Ordering::SeqCst);
    c
}

/// Time `f`, in cycles, with interrupts masked for exactly that window.
///
/// Masked because a timer tick or a device IRQ landing inside a window
/// measured in microseconds is a multi-microsecond outlier, and §8.5 forbids
/// trimming it back out afterwards — so it must not be admitted in the first
/// place. Masking is also faithful rather than artificial: the path these
/// benchmarks exercise is `BpfProg::run_atomic`, which a probe enters with
/// interrupts already off.
///
/// Masked *per sample*, never across the run: the suite would otherwise stall
/// the timer for its whole duration. That is the constraint that caps how
/// large `iters` may be.
pub fn measure<R>(f: impl FnOnce() -> R) -> (u64, R) {
    without_interrupts(|| {
        let t0 = cycles_fenced();
        let r = f();
        let t1 = cycles_fenced();
        // Wrapping rather than saturating: the TSC is 64-bit and monotone, so
        // the only way to get a negative delta is a wrap, and a wrapped delta
        // is still the right number.
        (t1.wrapping_sub(t0), r)
    })
}

/// Keep a value the optimiser would otherwise prove dead.
///
/// `core::hint::black_box` is the real thing; this wrapper exists so a
/// benchmark case reads as "the result is observed" rather than as a hint
/// call, and so there is one place to change if the hint's guarantees do.
#[inline]
pub fn observe<T>(v: T) -> T {
    core::hint::black_box(v)
}

// ── registry ────────────────────────────────────────────────────────

/// Registered benchmark groups.
///
/// Runtime registration rather than a `narf.benches` link section (the shape
/// `narf-kernel-test` uses) because a link section needs start/end symbols in
/// both architectures' linker scripts, and this needs no such reach: the only
/// consumer runs from an initcall, after every registering crate has had its
/// chance to call [`register_group`].
static GROUPS: IrqSafeSpinLock<Vec<&'static [Benchmark]>> = IrqSafeSpinLock::new(Vec::new());

/// Contribute a group of benchmarks. Call before the `Late` stage.
pub fn register_group(group: &'static [Benchmark]) {
    GROUPS.lock().push(group);
}

/// How many benchmarks are registered.
#[must_use]
pub fn registered() -> usize {
    GROUPS.lock().iter().map(|g| g.len()).sum()
}

// ── the runner ──────────────────────────────────────────────────────

/// Per-benchmark accumulation while the rounds run.
struct Collected {
    bench: &'static Benchmark,
    samples: Vec<u64>,
    work: u64,
    work_varied: bool,
    declined: bool,
}

/// Run every registered benchmark and write the record stream to `out`.
///
/// `n_override` replaces each benchmark's `target_n` when non-zero, so a
/// cmdline can trade run time for tightness without a rebuild. It is clamped
/// up to 30:
/// §8.3's floor is not a suggestion, and a harness that will happily emit
/// `n=5` invites exactly the report the protocol exists to prevent.
pub fn run(out: &mut impl Write, n_override: u32) {
    // Cloned out from under the lock before anything runs: a sample masks
    // interrupts, and holding an `IrqSafeSpinLock` across the whole suite
    // would keep them masked for its duration.
    let groups: Vec<&'static [Benchmark]> = (*GROUPS.lock()).clone();
    let mut cases: Vec<Collected> = Vec::new();
    for g in &groups {
        for b in *g {
            cases.push(Collected {
                bench: b,
                samples: Vec::new(),
                work: 0,
                work_varied: false,
                declined: false,
            });
        }
    }

    emit_env(out, cases.len());
    if cases.is_empty() {
        let _ = writeln!(out, "narf.bench.end: recs=0 skipped=0");
        return;
    }

    // Warmup, once per case, before any sample is kept. Discarded per §8.1:
    // the first pass through an interpreter loop pays for cold i-cache, an
    // unprimed branch predictor, and a cold per-CPU stack page.
    for c in &mut cases {
        for _ in 0..c.bench.warmup {
            if (c.bench.sample)(c.bench.iters).is_none() {
                c.declined = true;
                break;
            }
        }
    }

    // Round-robin. See the module docs: this is what makes an A/B pair paired.
    let rounds = cases
        .iter()
        .map(|c| effective_n(c.bench, n_override))
        .max()
        .unwrap_or(0);
    for round in 0..rounds {
        for c in &mut cases {
            if c.declined || round >= effective_n(c.bench, n_override) {
                continue;
            }
            match (c.bench.sample)(c.bench.iters) {
                None => c.declined = true,
                Some(s) => {
                    if c.samples.is_empty() {
                        c.work = s.work;
                    } else if s.work != c.work {
                        c.work_varied = true;
                    }
                    c.samples.push(s.value);
                }
            }
        }
    }

    let mut recs = 0usize;
    let mut skipped = 0usize;
    for c in &cases {
        if c.declined || c.samples.is_empty() {
            skipped += 1;
            let _ = writeln!(
                out,
                "narf.bench.skip: name={} reason={}",
                c.bench.name, c.bench.skip_reason
            );
            continue;
        }
        recs += 1;
        emit_record(out, c);
    }
    let _ = writeln!(out, "narf.bench.end: recs={recs} skipped={skipped}");
}

fn effective_n(b: &Benchmark, n_override: u32) -> u32 {
    // 30 is §8.3's floor; the override may raise the count but never lower it
    // below the floor, and never below what the benchmark itself declared it
    // needs to resolve its δ.
    if n_override == 0 {
        b.target_n.max(30)
    } else {
        n_override.max(30)
    }
}

fn emit_env(out: &mut impl Write, cases: usize) {
    let (mult, shift) = narf_time::cyc_to_ns_mult_shift();
    // `cycles_per_ns` is the truncated integer form and is here only so a
    // reader can sanity-check the mult/shift pair against it; the host uses
    // mult/shift, because truncation is what made userspace's monotonic clock
    // run 10-20% fast on a non-integer-GHz TSC.
    let _ = writeln!(
        out,
        "narf.bench.env: version=1 arch={} cases={} cpus={} cycles_per_ns={} \
         tsc_mult={} tsc_shift={} irq_masked=1 tick_reliable={}",
        if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "aarch64"
        },
        cases,
        narf_lib::smp::cpu_count(),
        narf_time::cycles_per_ns(),
        mult,
        shift,
        u8::from(narf_time::tick_reliable()),
    );
}

fn emit_record(out: &mut impl Write, c: &Collected) {
    let b = c.bench;
    let _ = writeln!(
        out,
        "narf.bench.rec: name={} subsystem={} unit={} lower_is_better={} n={} \
         iters={} warmup={} work={} work_varied={} delta_pct={} pair={}",
        b.name,
        b.subsystem,
        b.unit,
        u8::from(b.lower_is_better),
        c.samples.len(),
        b.iters,
        b.warmup,
        c.work,
        u8::from(c.work_varied),
        b.delta_pct,
        b.compare_with.unwrap_or("-"),
    );
    // Chunked because a 100-sample vector on one line is a ~1 KB line, and
    // both the FB console and a human reading raw serial handle 16 values at
    // a time better than they handle one enormous one.
    for (chunk, vals) in c.samples.chunks(VALS_PER_LINE).enumerate() {
        let _ = write!(
            out,
            "narf.bench.val: name={} i={} v=",
            b.name,
            chunk * VALS_PER_LINE
        );
        for (i, v) in vals.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "{v}");
        }
        let _ = writeln!(out);
    }
}

const VALS_PER_LINE: usize = 16;

// ── cmdline gating + initcall ───────────────────────────────────────

/// Whether the cmdline asked for a bench run (`bpf_bench`).
#[must_use]
pub fn requested() -> bool {
    narf_boot::args().has_flag("bpf_bench")
}

/// `bpf_bench_n=<N>` from the cmdline, or 0 for "use each declaration".
#[must_use]
pub fn requested_n() -> u32 {
    narf_boot::args()
        .parse_value::<u32>("bpf_bench_n")
        .unwrap_or(0)
}

/// Register the `Late`-stage runner.
///
/// `Late` because the run needs everything the cases touch to be up (the
/// kfunc registry and the per-CPU BPF stack are both `Subsys`), and because
/// a benchmark has no business delaying the boot of a kernel that was not
/// asked to benchmark anything — with no `bpf_bench` on the cmdline this
/// initcall reports `NotPresent` and costs a string scan.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "bpf-bench", || {
        if !requested() {
            return InitResult::NotPresent;
        }
        run(&mut narf_console::Writer, requested_n());
        InitResult::Ok
    });
}
