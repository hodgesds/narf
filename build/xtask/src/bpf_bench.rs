//! `cargo xtask bpf-bench` — boot the BPF benchmark suite, harvest the raw
//! samples, and apply `verification/specification/spec.md` §8 to them.
//!
//! The kernel side (`bpf/bench`) collects samples and emits them; everything
//! judgemental happens here. That boundary is deliberate — see
//! [`crate::bench_stats`] for why — and it makes this subcommand the only place
//! that can say the word "regression".
//!
//! ## The precondition gate
//!
//! §8.2 requires the harness to *verify* its noise-control preconditions at run
//! start and to abort with a structured failure rather than emit a polluted
//! record. That is implemented literally: [`check_preconditions`] inspects the
//! host, and a failure aborts unless `--allow-unverified-runner` is passed. With
//! that flag every record carries `noise_control: "unverified"` and every
//! comparison is labelled advisory, because a number collected on a laptop with
//! a `powersave` governor and SMT on is a development measurement and must never
//! be quoted as a release one.
//!
//! The flag exists because refusing outright would mean no measurement can be
//! taken until a perf runner exists, which is how "we never measured it" becomes
//! permanent. What it does not do is let an unverified run look verified.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use wait_timeout::ChildExt;

use crate::bench_stats::{
    benjamini_hochberg, delta_pct_ci, mann_whitney_u, summarize, welch_t_test, Comparison,
    Decision, Series, Summary,
};
use crate::{cargo_build, ensure_feature, workspace_root, Arch, BuildArgs};

#[derive(clap::Parser, Clone)]
pub struct BpfBenchArgs {
    #[command(flatten)]
    pub build: BuildArgs,

    /// Samples per benchmark. 0 uses each benchmark's own declared target.
    /// The kernel clamps this up to §8.3's floor of 30 regardless.
    #[arg(long, default_value_t = 0)]
    pub n: u32,

    /// Bootstrap resamples. §8.4 specifies 10 000.
    #[arg(long, default_value_t = 10_000)]
    pub resamples: usize,

    /// Proceed even though §8.2's noise-control preconditions could not be
    /// verified. Every emitted record is then marked `unverified` and no
    /// comparison may be quoted as a release number.
    #[arg(long)]
    pub allow_unverified_runner: bool,

    /// Where to write the §8.8 JSON records.
    #[arg(long, default_value = "target/bench/bpf-bench.json")]
    pub json: String,

    /// Seconds to wait for the boot + suite + clean exit.
    #[arg(long, default_value_t = 300)]
    pub timeout_secs: u64,
}

// ── §8.2 preconditions ──────────────────────────────────────────────

/// One precondition and what the host actually reported.
struct Precondition {
    what: &'static str,
    ok: bool,
    detail: String,
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn glob_cpu_governors() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path().join("cpufreq/scaling_governor");
        if let Some(g) = p.to_str().and_then(read_trim) {
            out.push(g);
        }
    }
    out
}

fn max_thermal_millicelsius() -> Option<i64> {
    let entries = std::fs::read_dir("/sys/class/thermal").ok()?;
    let mut max = None;
    for e in entries.flatten() {
        let p = e.path().join("temp");
        if let Some(v) = p
            .to_str()
            .and_then(read_trim)
            .and_then(|s| s.parse::<i64>().ok())
        {
            max = Some(max.map_or(v, |m: i64| m.max(v)));
        }
    }
    max
}

/// Inspect every §8.2 precondition this side of the VM boundary can see.
///
/// The ones inside the guest — that interrupts were masked per sample, that
/// warmup was discarded — are the kernel harness's job and it reports them on
/// its `narf.bench.env:` line. Neither side can verify the other's, which is
/// why both halves report rather than assert.
fn check_preconditions(accel: &str) -> Vec<Precondition> {
    let mut out = Vec::new();

    let govs = glob_cpu_governors();
    let all_perf = !govs.is_empty() && govs.iter().all(|g| g == "performance");
    let mut distinct: Vec<&str> = govs.iter().map(String::as_str).collect();
    distinct.sort_unstable();
    distinct.dedup();
    out.push(Precondition {
        what: "cpu governor is performance",
        ok: all_perf,
        detail: if govs.is_empty() {
            "no cpufreq sysfs".into()
        } else {
            distinct.join(",")
        },
    });

    // Boost/turbo. `cpufreq/boost` is the generic knob; amd_pstate exposes the
    // same thing through its own status file, and a machine in `active` mode
    // has the firmware choosing frequencies, which is turbo by another name.
    let boost = read_trim("/sys/devices/system/cpu/cpufreq/boost");
    let pstate = read_trim("/sys/devices/system/cpu/amd_pstate/status");
    let boost_off = boost.as_deref() == Some("0");
    out.push(Precondition {
        what: "turbo/boost disabled",
        ok: boost_off,
        detail: match (&boost, &pstate) {
            (Some(b), Some(p)) => format!("boost={b} amd_pstate={p}"),
            (Some(b), None) => format!("boost={b}"),
            (None, Some(p)) => format!("no boost knob, amd_pstate={p}"),
            (None, None) => "no boost knob".into(),
        },
    });

    let smt_active = read_trim("/sys/devices/system/cpu/smt/active");
    let smt_control = read_trim("/sys/devices/system/cpu/smt/control");
    out.push(Precondition {
        what: "SMT disabled",
        ok: smt_active.as_deref() == Some("0"),
        detail: format!(
            "active={} control={}",
            smt_active.as_deref().unwrap_or("?"),
            smt_control.as_deref().unwrap_or("?")
        ),
    });

    let aslr = read_trim("/proc/sys/kernel/randomize_va_space");
    out.push(Precondition {
        what: "ASLR disabled",
        ok: aslr.as_deref() == Some("0"),
        detail: format!("randomize_va_space={}", aslr.as_deref().unwrap_or("?")),
    });

    // §8.2's "no sibling CPU on the same LLC has a load average > 0.05". The
    // 1-minute figure over the whole machine is a coarser check than that and a
    // strictly stronger one, which is the right direction to err.
    let load1 = read_trim("/proc/loadavg")
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .and_then(|s| s.parse::<f64>().ok());
    out.push(Precondition {
        what: "machine idle (1-min load < 0.05)",
        ok: load1.is_some_and(|l| l < 0.05),
        detail: format!(
            "loadavg1={}",
            load1.map_or("?".to_string(), |l| format!("{l:.2}"))
        ),
    });

    let temp = max_thermal_millicelsius();
    out.push(Precondition {
        what: "not near thermal throttle",
        ok: temp.is_some_and(|t| t < 85_000),
        detail: temp.map_or("no thermal sysfs".into(), |t| {
            format!("max_zone={:.1}C", t as f64 / 1000.0)
        }),
    });

    // Not a §8.2 clause, but load-bearing for interpretation: under TCG a
    // "cycle" is host time spent *emulating*, and TCG's relative cost model is
    // not silicon's — a per-instruction branch is nearly free in a translation
    // block. A fuel-granularity answer measured under TCG would be an answer
    // about QEMU.
    out.push(Precondition {
        what: "hardware virtualisation (KVM)",
        ok: accel == "kvm",
        detail: format!("accel={accel}"),
    });

    out
}

// ── parsing the serial record stream ────────────────────────────────

#[derive(Clone, Debug, Default)]
struct Env {
    version: u32,
    arch: String,
    cpus: u32,
    tsc_mult: u64,
    tsc_shift: u32,
    /// The guest's truncated integer `cycles/ns`. Parsed and archived rather
    /// than used: it is the lossy form of the mult/shift pair above, and the
    /// only reason to carry it is that a reader comparing a record against a
    /// boot log will find it there.
    #[allow(dead_code)]
    cycles_per_ns: u64,
    irq_masked: bool,
    tick_reliable: bool,
}

impl Env {
    /// TSC frequency implied by the guest's published `cyc → ns` pair.
    ///
    /// The mult/shift pair rather than `cycles_per_ns`, because that one is an
    /// integer truncation — the same truncation that made userspace's monotonic
    /// clock run 10-20% fast on a non-integer-GHz TSC, and a 10% error here
    /// would land directly in every instructions-per-second figure.
    fn tsc_hz(&self) -> Option<f64> {
        if self.tsc_mult == 0 {
            return None;
        }
        Some(1e9 * (1u64 << self.tsc_shift) as f64 / self.tsc_mult as f64)
    }
}

/// Measure the host's TSC frequency directly.
///
/// Needed because the guest cannot supply it: QEMU `-cpu max` reports
/// `invariant_tsc=false`, NARF's calibration therefore declines, and
/// `cyc_to_ns_mult_shift()` stays at its 1-cycle-per-ns default — which would
/// turn every derived instructions-per-second figure into a number that is
/// wrong by the ratio of the real clock to 1 GHz.
///
/// Sound only under KVM, where the guest TSC *is* the host TSC (no scaling on
/// this path), and used only for the derived throughput line. The primary
/// metric stays in cycles, which is what the guest actually measured.
#[cfg(target_arch = "x86_64")]
fn host_tsc_hz() -> Option<f64> {
    use std::time::Instant;
    // 200 ms is long enough that scheduler jitter is a small fraction and short
    // enough not to be noticed. Two reads bracketing a wall-clock interval; no
    // fencing, because at this duration a few hundred cycles of reorder is
    // nine significant figures down.
    let t0 = Instant::now();
    // SAFETY: `_rdtsc` reads the time-stamp counter. It is unprivileged on
    // every x86_64 that runs this tool and has no memory operand.
    let c0 = unsafe { std::arch::x86_64::_rdtsc() };
    std::thread::sleep(Duration::from_millis(200));
    // SAFETY: as above — `_rdtsc` is unprivileged and has no memory operand.
    let c1 = unsafe { std::arch::x86_64::_rdtsc() };
    let elapsed = t0.elapsed().as_secs_f64();
    if elapsed <= 0.0 || c1 <= c0 {
        return None;
    }
    Some((c1 - c0) as f64 / elapsed)
}

#[cfg(not(target_arch = "x86_64"))]
fn host_tsc_hz() -> Option<f64> {
    None
}

fn kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key).filter(|_| tok.len() > key.len()))
}

fn parse_env(line: &str) -> Env {
    let num = |k: &str| kv(line, k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    Env {
        version: num("version=") as u32,
        arch: kv(line, "arch=").unwrap_or("?").to_string(),
        cpus: num("cpus=") as u32,
        tsc_mult: num("tsc_mult="),
        tsc_shift: num("tsc_shift=") as u32,
        cycles_per_ns: num("cycles_per_ns="),
        irq_masked: num("irq_masked=") == 1,
        tick_reliable: num("tick_reliable=") == 1,
    }
}

/// Accumulate `narf.bench.*` lines into series.
///
/// Tolerant of interleaved kernel log lines, because the console is shared: a
/// benchmark record and a driver's boot chatter can and do arrive in the same
/// stream. Anything that is not a `narf.bench.` line is ignored here and echoed
/// by the caller.
#[derive(Default)]
struct Harvest {
    env: Option<Env>,
    order: Vec<String>,
    series: BTreeMap<String, Series>,
    skips: Vec<(String, String)>,
    end: Option<(usize, usize)>,
}

impl Harvest {
    fn line(&mut self, line: &str) {
        let Some(rest) = line.split("narf.bench").nth(1) else {
            return;
        };
        let rest = format!("narf.bench{rest}");
        if let Some(body) = rest.strip_prefix("narf.bench.env:") {
            self.env = Some(parse_env(body));
        } else if let Some(body) = rest.strip_prefix("narf.bench.rec:") {
            if let Some(s) = parse_rec(body) {
                self.order.push(s.name.clone());
                self.series.insert(s.name.clone(), s);
            }
        } else if let Some(body) = rest.strip_prefix("narf.bench.val:") {
            let Some(name) = kv(body, "name=") else {
                return;
            };
            let Some(vals) = kv(body, "v=") else { return };
            if let Some(s) = self.series.get_mut(name) {
                for v in vals.split(',') {
                    if let Ok(x) = v.parse::<f64>() {
                        s.samples.push(x);
                    }
                }
            }
        } else if let Some(body) = rest.strip_prefix("narf.bench.skip:") {
            let name = kv(body, "name=").unwrap_or("?").to_string();
            let reason = body
                .split_once("reason=")
                .map_or("?".to_string(), |(_, r)| r.trim().to_string());
            self.skips.push((name, reason));
        } else if let Some(body) = rest.strip_prefix("narf.bench.end:") {
            let n = |k: &str| {
                kv(body, k)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0)
            };
            self.end = Some((n("recs="), n("skipped=")));
        }
    }
}

fn parse_rec(body: &str) -> Option<Series> {
    let name = kv(body, "name=")?.to_string();
    let num = |k: &str| kv(body, k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let pair = kv(body, "pair=").filter(|p| *p != "-").map(str::to_string);
    Some(Series {
        name,
        subsystem: kv(body, "subsystem=").unwrap_or("?").to_string(),
        unit: kv(body, "unit=").unwrap_or("?").to_string(),
        lower_is_better: num("lower_is_better=") == 1,
        iters: num("iters="),
        warmup: num("warmup="),
        work: num("work="),
        work_varied: num("work_varied=") == 1,
        delta_pct: kv(body, "delta_pct=")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0),
        pair,
        samples: Vec::new(),
    })
}

// ── the subcommand ──────────────────────────────────────────────────

pub fn bpf_bench_cmd(args: &BpfBenchArgs) -> Result<()> {
    if !matches!(args.build.arch, Arch::X86_64) {
        // Nothing here is x86-only in principle, but the JIT codegen and
        // publish cases have no aarch64 emitter to measure and would skip,
        // and RDTSC-versus-CNTPCT changes what a "cycle" means. Refuse rather
        // than silently report a different metric under the same name.
        bail!("xtask bpf-bench: only x86_64 is wired (no aarch64 emitter to measure)");
    }

    // Accelerator first: the precondition report needs to know, and the guest
    // needs it set before `qemu_args` runs.
    let accel = match std::env::var("XTASK_QEMU_ACCEL") {
        Ok(a) if !a.is_empty() => a,
        _ => {
            // Default to KVM when the host has it. Under TCG this measures
            // QEMU's cost model rather than the machine's; see the
            // precondition note.
            let a = if Path::new("/dev/kvm").exists() {
                "kvm"
            } else {
                "tcg"
            };
            std::env::set_var("XTASK_QEMU_ACCEL", a);
            a.to_string()
        }
    };

    let pre = check_preconditions(&accel);
    println!("── §8.2 noise-control preconditions ─────────────────────");
    for p in &pre {
        println!(
            "  [{}] {:<38} {}",
            if p.ok { "ok" } else { "FAIL" },
            p.what,
            p.detail
        );
    }
    let failed: Vec<&str> = pre.iter().filter(|p| !p.ok).map(|p| p.what).collect();
    let verified = failed.is_empty();
    if !verified {
        if !args.allow_unverified_runner {
            bail!(
                "PreconditionFailed: {} of {} §8.2 checks failed ({}). \
                 §8.2 requires the run be discarded rather than averaged in. \
                 Re-run with --allow-unverified-runner to take a development \
                 measurement, which must not be published as a perf number.",
                failed.len(),
                pre.len(),
                failed.join("; ")
            );
        }
        println!(
            "  → {} check(s) failed; proceeding under --allow-unverified-runner. \
             Records are marked noise_control=unverified.",
            failed.len()
        );
    }

    // A single vCPU: the suite is single-threaded, and every extra vCPU is
    // another host thread competing for the core the samples are taken on.
    // Not a correctness workaround (SMP>1 works) — a noise control.
    if std::env::var_os("NARF_QEMU_SMP").is_none() {
        std::env::set_var("NARF_QEMU_SMP", "1");
    }

    let mut build = args.build.clone();
    // `boot-smoke` gives the run a clean, natural QEMU exit after the initcalls
    // drain, so there is no kill-after-timeout race between the reader and the
    // last record line. `narf-bpf/bench` compiles the suite in.
    ensure_feature(&mut build.features, "boot-smoke");
    ensure_feature(&mut build.features, "narf-bpf/bench");

    let prior_append = std::env::var_os("XTASK_QEMU_APPEND");
    let mut append = prior_append
        .as_ref()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !append.is_empty() {
        append.push(' ');
    }
    append.push_str("bpf_bench");
    if args.n > 0 {
        append.push_str(&format!(" bpf_bench_n={}", args.n));
    }
    std::env::set_var("XTASK_QEMU_APPEND", append);

    let result = run_and_report(args, &build, &accel, verified);

    match prior_append {
        Some(v) => std::env::set_var("XTASK_QEMU_APPEND", v),
        None => std::env::remove_var("XTASK_QEMU_APPEND"),
    }
    result
}

fn run_and_report(
    args: &BpfBenchArgs,
    build: &BuildArgs,
    accel: &str,
    verified: bool,
) -> Result<()> {
    let root = workspace_root()?;
    let out_dir = cargo_build(build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!("expected kernel binary at {}", kernel.display());
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile, build.gpu_backend),
    );
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    println!("xtask bpf-bench: launching {qemu} {}", kernel.display());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let reader = std::thread::spawn(move || -> (Harvest, Option<String>, bool) {
        let panic_markers: &[&str] = &[
            "*** KERNEL PANIC ***",
            "panicked at",
            "double fault",
            "general protection",
            "kernel page fault",
        ];
        let mut harvest = Harvest::default();
        let mut panic_line = None;
        let mut clean = false;
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            println!("{line}");
            clean |= line.contains("boot-smoke: clean exit");
            if panic_line.is_none() && panic_markers.iter().any(|m| line.contains(m)) {
                panic_line = Some(line.clone());
            }
            harvest.line(&line);
        }
        (harvest, panic_line, clean)
    });

    let exit = child.wait_timeout(Duration::from_secs(args.timeout_secs))?;
    let timed_out = exit.is_none();
    if timed_out {
        child.kill()?;
        child.wait()?;
    }
    let (harvest, panic_line, clean) = reader
        .join()
        .map_err(|_| anyhow!("xtask bpf-bench: serial-reader thread panicked"))?;

    if let Some(p) = panic_line {
        bail!("xtask bpf-bench: kernel panic during the run — '{p}'");
    }
    if timed_out {
        bail!(
            "xtask bpf-bench: no clean exit within {}s",
            args.timeout_secs
        );
    }
    if !clean {
        bail!("xtask bpf-bench: QEMU exited without the kernel clean-exit marker");
    }
    report(args, &harvest, accel, verified, &root)
}

/// One benchmark's parsed samples plus everything §8.4 asks be reported.
struct Row {
    series: Series,
    summary: Summary,
}

fn report(
    args: &BpfBenchArgs,
    harvest: &Harvest,
    accel: &str,
    verified: bool,
    root: &Path,
) -> Result<()> {
    let env = harvest
        .env
        .clone()
        .ok_or_else(|| anyhow!("no narf.bench.env line — did the suite run?"))?;
    // The guest declares its output grammar's version. Refuse a mismatch rather
    // than parse an unknown shape into plausible-looking numbers: this parser
    // and that emitter are one interface, and a silent skew between them would
    // show up as a benchmark that quietly lost half its samples.
    if env.version != 1 {
        bail!(
            "narf.bench.env reports grammar version {} but this parser speaks 1",
            env.version
        );
    }
    if harvest.series.is_empty() {
        bail!(
            "the suite emitted no records (skipped: {})",
            harvest.skips.len()
        );
    }

    let mut rows: Vec<Row> = Vec::new();
    for name in &harvest.order {
        let Some(s) = harvest.series.get(name) else {
            continue;
        };
        if s.samples.is_empty() {
            continue;
        }
        // A short series is reported as short. §8.3's floor is not negotiable,
        // and quietly reporting n=12 as though it met the bar is exactly the
        // failure the protocol exists to prevent.
        let summary = summarize(&s.samples, args.resamples, hash_name(name));
        rows.push(Row {
            series: s.clone(),
            summary,
        });
    }

    // The guest's own timebase where it has one, else the host's — see
    // `host_tsc_hz`. `(1, 0)` is the uncalibrated default, not a 1 GHz clock,
    // and taking it at face value would scale every throughput figure by the
    // ratio of the real clock to 1 GHz.
    let guest_calibrated = !(env.tsc_mult == 1 && env.tsc_shift == 0);
    let (tsc_hz, tsc_from) = if guest_calibrated {
        (env.tsc_hz(), "guest")
    } else if accel == "kvm" {
        (
            host_tsc_hz(),
            "host (guest TSC uncalibrated, KVM passthrough)",
        )
    } else {
        (None, "unknown (guest uncalibrated, not KVM)")
    };
    println!();
    println!("── §8.4 summary ─────────────────────────────────────────");
    println!(
        "  guest: arch={} cpus={} accel={} irq_masked={} tick_reliable={}",
        env.arch, env.cpus, accel, env.irq_masked, env.tick_reliable,
    );
    println!(
        "  timebase: {} via {}",
        tsc_hz.map_or("unavailable".into(), |h| format!("{:.3} GHz", h / 1e9)),
        tsc_from,
    );
    println!(
        "  {:<36} {:>3} {:>10} {:>19} {:>9} {:>9} {:>6} {:>12}",
        "benchmark", "n", "median", "median 95% CI", "p95", "p99", "CV%", "per work"
    );
    for r in &rows {
        let per_work = if r.series.work > 0 && !r.series.work_varied {
            format!("{:.3}", r.summary.median / r.series.work as f64)
        } else {
            "—".into()
        };
        println!(
            "  {:<36} {:>3} {:>10.0} [{:>8.0},{:>8.0}] {:>9.0} {:>9.0} {:>6.2} {:>12}",
            r.series.name,
            r.summary.n,
            r.summary.median,
            r.summary.median_ci.0,
            r.summary.median_ci.1,
            r.summary.p95,
            r.summary.p99,
            r.summary.cv * 100.0,
            per_work,
        );
    }

    // Derived throughput, for the cases that declared work in instructions.
    // Reported separately because it is a transformation of the median above,
    // not an independently measured quantity — the CI belongs to the median.
    if let Some(hz) = tsc_hz {
        println!();
        println!("── derived throughput (from the medians above, timebase: {tsc_from}) ──");
        for r in &rows {
            if r.series.work <= 1 || r.series.work_varied {
                continue;
            }
            let per = r.summary.median / r.series.work as f64;
            println!(
                "  {:<36} {:>9.2} cycles/unit  {:>12.2} M units/s",
                r.series.name,
                per,
                hz / per / 1e6
            );
        }
    }

    for (name, reason) in &harvest.skips {
        println!("  [skip] {name}: {reason}");
    }

    // ── §8.6 comparisons ────────────────────────────────────────────
    let comparisons = compare_pairs(args, &rows);
    if !comparisons.is_empty() {
        println!();
        println!("── §8.6 A/B comparisons (BH-corrected, q=0.05) ──────────");
        for c in &comparisons {
            let (shared, base, cand) = split_pair(&c.baseline, &c.candidate);
            println!("  {shared}{base} → {cand}");
            println!(
                "      delta {:+.2}% [{:+.2}%, {:+.2}%]   welch p={}{}   mwu p={}   delta={}%",
                c.delta_pct,
                c.delta_ci.0,
                c.delta_ci.1,
                fmt_p(c.welch_p),
                if c.welch_logged { " (log)" } else { "" },
                fmt_p(c.mwu_p),
                c.delta_threshold,
            );
            println!(
                "      → {}{}",
                c.decision().label(),
                if verified {
                    ""
                } else {
                    "  [advisory: runner unverified]"
                }
            );
        }
    }

    write_json(args, harvest, &rows, &comparisons, accel, verified, root)?;
    Ok(())
}

/// Split a pair's two names into their shared prefix and their differing tails.
///
/// The prefix is *kept* and printed once: it carries which shape the pair
/// measured, and dropping it made all four fuel comparisons print as the
/// identical line `fuel_hoisted → fuel_per_insn`.
fn split_pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str, &'a str) {
    let common = a
        .char_indices()
        .zip(b.chars())
        .take_while(|((_, x), y)| x == y)
        .map(|((i, _), _)| i)
        .last()
        .map_or(0, |i| a[..=i].rfind('.').map_or(0, |d| d + 1));
    (&a[..common], &a[common..], &b[common..])
}

/// Format a p-value, distinguishing "vanishingly small" from "exactly zero".
///
/// The Mann-Whitney normal approximation's tail underflows `f64` for a
/// well-separated pair, and printing `0.000e0` invites reading a limit of
/// double precision as a claim of certainty.
fn fmt_p(p: f64) -> String {
    if p == 0.0 {
        "<1e-308".into()
    } else {
        format!("{p:.3e}")
    }
}

/// Build one comparison per A/B pair, then apply Benjamini-Hochberg across the
/// whole set — separately to the Welch family and the Mann-Whitney family, so
/// "both tests must agree" (§8.6.3) is judged after each has been corrected for
/// the size of the suite rather than before.
fn compare_pairs(args: &BpfBenchArgs, rows: &[Row]) -> Vec<Comparison> {
    let by_name: BTreeMap<&str, &Row> = rows.iter().map(|r| (r.series.name.as_str(), r)).collect();
    let mut out: Vec<Comparison> = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();
    for r in rows {
        let Some(peer) = r.series.pair.as_deref() else {
            continue;
        };
        let Some(other) = by_name.get(peer) else {
            continue;
        };
        // Lexicographic order picks the baseline, deterministically and without
        // a second declaration to keep in sync. For the fuel pairs this makes
        // `fuel_hoisted` the baseline and `fuel_per_insn` the candidate, which
        // is the direction the question is asked in: what does the policy that
        // replaced it cost?
        let (base, cand) = if r.series.name < other.series.name {
            (r, *other)
        } else {
            (*other, r)
        };
        let key = (base.series.name.clone(), cand.series.name.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);

        let (welch_p, welch_logged) = welch_t_test(&base.series.samples, &cand.series.samples);
        let mwu_p = mann_whitney_u(&base.series.samples, &cand.series.samples);
        let (delta_pct, delta_ci) = delta_pct_ci(
            &base.series.samples,
            &cand.series.samples,
            args.resamples,
            hash_name(&cand.series.name) ^ 0xABCD,
        );
        out.push(Comparison {
            baseline: base.series.name.clone(),
            candidate: cand.series.name.clone(),
            delta_pct,
            delta_ci,
            welch_p,
            welch_logged,
            mwu_p,
            delta_threshold: cand.series.delta_pct,
            welch_significant: false,
            mwu_significant: false,
        });
    }

    let welch: Vec<f64> = out.iter().map(|c| c.welch_p).collect();
    let mwu: Vec<f64> = out.iter().map(|c| c.mwu_p).collect();
    let welch_rej = benjamini_hochberg(&welch, 0.05);
    let mwu_rej = benjamini_hochberg(&mwu, 0.05);
    for (i, c) in out.iter_mut().enumerate() {
        c.welch_significant = welch_rej[i];
        c.mwu_significant = mwu_rej[i];
    }
    out
}

/// Deterministic per-benchmark bootstrap seed. Derived from the name so a
/// re-run of the same suite reproduces the same intervals from the same
/// samples, which is what makes an archived §8.8 record checkable.
fn hash_name(name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in name.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

fn write_json(
    args: &BpfBenchArgs,
    harvest: &Harvest,
    rows: &[Row],
    comparisons: &[Comparison],
    accel: &str,
    verified: bool,
    root: &Path,
) -> Result<()> {
    let path = root.join(&args.json);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    }
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or("unknown".to_string(), |s| s.trim().to_string());
    let env = harvest.env.clone().unwrap_or_default();

    let mut f =
        std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    // Hand-formatted because xtask has no serde dependency and one record shape
    // is not worth adding one. §8.8's field names are reproduced exactly so an
    // archived record from this harness is comparable with one from any other.
    writeln!(f, "{{")?;
    writeln!(f, "  \"schema\": 1,")?;
    writeln!(f, "  \"commit\": \"{commit}\",")?;
    writeln!(f, "  \"runner\": \"{}\",", hostname())?;
    writeln!(f, "  \"accel\": \"{accel}\",")?;
    writeln!(
        f,
        "  \"noise_control\": \"{}\",",
        if verified { "verified" } else { "unverified" }
    )?;
    writeln!(f, "  \"guest\": {{ \"arch\": \"{}\", \"cpus\": {}, \"tsc_mult\": {}, \"tsc_shift\": {}, \"irq_masked\": {} }},",
        env.arch, env.cpus, env.tsc_mult, env.tsc_shift, env.irq_masked)?;
    writeln!(f, "  \"benchmarks\": [")?;
    for (i, r) in rows.iter().enumerate() {
        let s = &r.summary;
        let samples: Vec<String> = r.series.samples.iter().map(|v| format!("{v:.0}")).collect();
        writeln!(f, "    {{")?;
        writeln!(f, "      \"benchmark\": \"{}\",", r.series.name)?;
        writeln!(f, "      \"unit\": \"{}\",", r.series.unit)?;
        writeln!(
            f,
            "      \"lower_is_better\": {},",
            r.series.lower_is_better
        )?;
        writeln!(f, "      \"n\": {},", s.n)?;
        writeln!(f, "      \"iters\": {},", r.series.iters)?;
        writeln!(f, "      \"warmup\": {},", r.series.warmup)?;
        writeln!(f, "      \"work_per_sample\": {},", r.series.work)?;
        writeln!(f, "      \"median\": {:.2},", s.median)?;
        writeln!(
            f,
            "      \"median_ci95\": [{:.2}, {:.2}],",
            s.median_ci.0, s.median_ci.1
        )?;
        writeln!(f, "      \"mean\": {:.2},", s.mean)?;
        writeln!(
            f,
            "      \"mean_ci95\": [{:.2}, {:.2}],",
            s.mean_ci.0, s.mean_ci.1
        )?;
        writeln!(f, "      \"p50\": {:.2},", s.p50)?;
        writeln!(f, "      \"p95\": {:.2},", s.p95)?;
        writeln!(f, "      \"p99\": {:.2},", s.p99)?;
        writeln!(f, "      \"p999\": {:.2},", s.p999)?;
        writeln!(f, "      \"cv\": {:.5},", s.cv)?;
        writeln!(f, "      \"skew\": {:.4},", s.skew)?;
        writeln!(f, "      \"min\": {:.2}, \"max\": {:.2},", s.min, s.max)?;
        writeln!(f, "      \"samples\": [{}]", samples.join(", "))?;
        writeln!(f, "    }}{}", if i + 1 == rows.len() { "" } else { "," })?;
    }
    writeln!(f, "  ],")?;
    writeln!(f, "  \"comparisons\": [")?;
    for (i, c) in comparisons.iter().enumerate() {
        writeln!(f, "    {{")?;
        writeln!(f, "      \"baseline\": \"{}\",", c.baseline)?;
        writeln!(f, "      \"candidate\": \"{}\",", c.candidate)?;
        writeln!(f, "      \"delta_pct\": {:.4},", c.delta_pct)?;
        writeln!(
            f,
            "      \"delta_ci95\": [{:.4}, {:.4}],",
            c.delta_ci.0, c.delta_ci.1
        )?;
        writeln!(f, "      \"welch_p\": {:.6e},", c.welch_p)?;
        writeln!(f, "      \"welch_log_transformed\": {},", c.welch_logged)?;
        writeln!(f, "      \"mwu_p\": {:.6e},", c.mwu_p)?;
        writeln!(
            f,
            "      \"delta_threshold_pct\": {:.2},",
            c.delta_threshold
        )?;
        writeln!(f, "      \"bh_q\": 0.05,")?;
        writeln!(
            f,
            "      \"welch_significant\": {}, \"mwu_significant\": {},",
            c.welch_significant, c.mwu_significant
        )?;
        writeln!(
            f,
            "      \"decision\": \"{}\"",
            match c.decision() {
                Decision::Inconclusive => "inconclusive",
                Decision::NotSignificant => "not-significant",
                Decision::SignificantWithinDelta => "significant-within-delta",
                Decision::SignificantBeyondDelta => "significant-beyond-delta",
            }
        )?;
        writeln!(
            f,
            "    }}{}",
            if i + 1 == comparisons.len() { "" } else { "," }
        )?;
    }
    writeln!(f, "  ]")?;
    writeln!(f, "}}")?;
    println!();
    println!("xtask bpf-bench: wrote {}", path.display());
    Ok(())
}

fn hostname() -> String {
    read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into())
}
