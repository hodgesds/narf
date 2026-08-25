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
//! that flag comparisons are printed as advisory diagnostics, but no JSON
//! performance record is emitted: a number collected on a laptop with a
//! `powersave` governor and SMT on must never be quoted as a release one.
//! Records also capture whether the source tree is dirty. An uncommitted build
//! cannot produce a publishable comparison under the identity of `HEAD`.
//!
//! The flag exists because refusing outright would mean no measurement can be
//! taken until a perf runner exists, which is how "we never measured it" becomes
//! permanent. What it does not do is let an unverified run look verified.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use wait_timeout::ChildExt;

use crate::bench_stats::{
    benjamini_hochberg, delta_pct_ci, mann_whitney_u, mean, stddev, summarize, welch_t_test,
    Comparison, Decision, Series, Summary,
};
use crate::{cargo_build, ensure_feature, workspace_root, Arch, BuildArgs};

#[derive(clap::Parser, Clone)]
pub struct BpfBenchArgs {
    #[command(flatten)]
    pub build: BuildArgs,

    /// Samples per benchmark. 0 uses each benchmark's own declared target.
    /// The kernel clamps this up to §8.3's floor of 30 and each benchmark's
    /// declared target regardless.
    #[arg(long, default_value_t = 0)]
    pub n: u32,

    /// Bootstrap resamples. §8.4 specifies 10 000.
    #[arg(long, default_value_t = 10_000)]
    pub resamples: usize,

    /// Proceed even though §8.2's noise-control preconditions could not be
    /// verified. Advisory statistics are printed, but no JSON performance
    /// record is emitted and no comparison may be quoted as a release number.
    #[arg(long)]
    pub allow_unverified_runner: bool,

    /// Where to write the §8.8 JSON records.
    #[arg(long, default_value = "target/bench/bpf-bench.json")]
    pub json: String,

    /// Previous green main record to compare against under §8.6.
    #[arg(long)]
    pub baseline: Option<String>,

    /// Most recent release record for §8.7's slow-cooking regression check.
    #[arg(long)]
    pub release_baseline: Option<String>,

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

fn thermal_throttle_count() -> Option<u64> {
    let entries = std::fs::read_dir("/sys/devices/system/cpu").ok()?;
    let mut total = 0u64;
    let mut found = false;
    for entry in entries.flatten() {
        for counter in ["core_throttle_count", "package_throttle_count"] {
            let path = entry.path().join("thermal_throttle").join(counter);
            if let Some(value) = path
                .to_str()
                .and_then(read_trim)
                .and_then(|value| value.parse::<u64>().ok())
            {
                total = total.saturating_add(value);
                found = true;
            }
        }
    }
    found.then_some(total)
}

struct ThermalWindow {
    max_millicelsius: Option<i64>,
    throttle_delta: Option<u64>,
    throttle_end: Option<u64>,
}

fn monitor_thermal_window() -> ThermalWindow {
    let before = thermal_throttle_count();
    let started = Instant::now();
    let mut max = None;
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(current) = max_thermal_millicelsius() {
            max = Some(max.map_or(current, |seen: i64| seen.max(current)));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let after = thermal_throttle_count();
    ThermalWindow {
        max_millicelsius: max,
        throttle_delta: before
            .zip(after)
            .map(|(start, end)| end.saturating_sub(start)),
        throttle_end: after,
    }
}

/// Inspect every §8.2 precondition this side of the VM boundary can see.
///
/// The ones inside the guest — that interrupts were masked per sample, that
/// warmup was discarded — are the kernel harness's job and it reports them on
/// its `narf.bench.env:` line. Neither side can verify the other's, which is
/// why both halves report rather than assert.
fn check_preconditions(accel: &str, thermal: &ThermalWindow) -> Vec<Precondition> {
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

    out.push(Precondition {
        what: "30s thermal window stayed clean",
        ok: thermal.max_millicelsius.is_some_and(|t| t < 85_000)
            && thermal.throttle_delta == Some(0),
        detail: format!(
            "max_zone={} throttle_delta={}",
            thermal
                .max_millicelsius
                .map_or("?".into(), |t| format!("{:.1}C", t as f64 / 1000.0)),
            thermal
                .throttle_delta
                .map_or("?".into(), |delta| delta.to_string()),
        ),
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
    cases: usize,
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

fn required_token<'a>(line: &'a str, key: &str) -> Result<&'a str> {
    kv(line, key).ok_or_else(|| anyhow!("missing `{key}` token"))
}

fn token_u64(line: &str, key: &str) -> Result<u64> {
    required_token(line, key)?
        .parse::<u64>()
        .with_context(|| format!("invalid integer `{key}` token"))
}

fn token_bool(line: &str, key: &str) -> Result<bool> {
    match token_u64(line, key)? {
        0 => Ok(false),
        1 => Ok(true),
        value => bail!("invalid boolean `{key}{value}` (expected 0 or 1)"),
    }
}

fn parse_env(line: &str) -> Result<Env> {
    let env = Env {
        version: token_u64(line, "version=")?.try_into()?,
        arch: required_token(line, "arch=")?.to_string(),
        cases: token_u64(line, "cases=")?.try_into()?,
        cpus: token_u64(line, "cpus=")?.try_into()?,
        tsc_mult: token_u64(line, "tsc_mult=")?,
        tsc_shift: token_u64(line, "tsc_shift=")?.try_into()?,
        cycles_per_ns: token_u64(line, "cycles_per_ns=")?,
        irq_masked: token_bool(line, "irq_masked=")?,
        tick_reliable: token_bool(line, "tick_reliable=")?,
    };
    if env.arch.is_empty() || env.cpus == 0 || env.tsc_shift >= 64 {
        bail!("invalid arch/cpus/tsc_shift environment declaration");
    }
    Ok(env)
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
    errors: Vec<String>,
}

impl Harvest {
    fn line(&mut self, line: &str) {
        let Some(rest) = line.split("narf.bench").nth(1) else {
            return;
        };
        let rest = format!("narf.bench{rest}");
        if self.end.is_some() {
            self.errors
                .push("benchmark record appeared after narf.bench.end".into());
            return;
        }
        if let Some(body) = rest.strip_prefix("narf.bench.env:") {
            if self.env.is_some() {
                self.errors.push("duplicate narf.bench.env line".into());
            } else {
                match parse_env(body) {
                    Ok(env) => self.env = Some(env),
                    Err(error) => self.errors.push(format!("malformed env line: {error}")),
                }
            }
        } else if let Some(body) = rest.strip_prefix("narf.bench.rec:") {
            match parse_rec(body) {
                Ok(series) => {
                    if self.series.contains_key(&series.name)
                        || self.skips.iter().any(|(name, _)| name == &series.name)
                    {
                        self.errors
                            .push(format!("duplicate benchmark record `{}`", series.name));
                    } else {
                        self.order.push(series.name.clone());
                        self.series.insert(series.name.clone(), series);
                    }
                }
                Err(error) => self.errors.push(format!("malformed record line: {error}")),
            }
        } else if let Some(body) = rest.strip_prefix("narf.bench.val:") {
            if let Err(error) = self.values(body) {
                self.errors.push(format!("malformed value line: {error}"));
            }
        } else if let Some(body) = rest.strip_prefix("narf.bench.skip:") {
            match (
                required_token(body, "name="),
                body.split_once("reason=").map(|(_, reason)| reason.trim()),
            ) {
                (Ok(name), Some(reason)) if !reason.is_empty() => {
                    if self.series.contains_key(name)
                        || self.skips.iter().any(|(skipped, _)| skipped == name)
                    {
                        self.errors
                            .push(format!("duplicate benchmark case `{name}`"));
                    } else {
                        self.skips.push((name.to_string(), reason.to_string()));
                    }
                }
                _ => self.errors.push("malformed skip line".into()),
            }
        } else if let Some(body) = rest.strip_prefix("narf.bench.end:") {
            let parsed = token_u64(body, "recs=")
                .and_then(|value| usize::try_from(value).map_err(Into::into))
                .and_then(|records| {
                    token_u64(body, "skipped=")
                        .and_then(|value| usize::try_from(value).map_err(Into::into))
                        .map(|skips| (records, skips))
                });
            match parsed {
                Ok(end) => self.end = Some(end),
                Err(error) => self.errors.push(format!("malformed end line: {error}")),
            }
        }
    }

    fn values(&mut self, body: &str) -> Result<()> {
        let name = required_token(body, "name=")?.to_string();
        let index: usize = token_u64(body, "i=")?.try_into()?;
        let values = required_token(body, "v=")?
            .split(',')
            .map(|value| {
                value
                    .parse::<f64>()
                    .ok()
                    .filter(|parsed| parsed.is_finite())
                    .ok_or_else(|| {
                        anyhow!("`{name}` contains non-finite or invalid sample `{value}`")
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        if values.is_empty() {
            bail!("`{name}` contains an empty value chunk");
        }
        let series = self
            .series
            .get_mut(&name)
            .ok_or_else(|| anyhow!("values precede record for `{name}`"))?;
        if index != series.samples.len() {
            bail!(
                "`{name}` chunk starts at i={index}, expected i={}",
                series.samples.len(),
            );
        }
        series.samples.extend(values);
        Ok(())
    }
}

fn parse_rec(body: &str) -> Result<Series> {
    let pair = required_token(body, "pair=")?;
    let delta_pct = required_token(body, "delta_pct=")?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| anyhow!("invalid `delta_pct` token"))?;
    Ok(Series {
        name: required_token(body, "name=")?.to_string(),
        subsystem: required_token(body, "subsystem=")?.to_string(),
        unit: required_token(body, "unit=")?.to_string(),
        lower_is_better: token_bool(body, "lower_is_better=")?,
        iters: token_u64(body, "iters=")?,
        warmup: token_u64(body, "warmup=")?,
        work: token_u64(body, "work=")?,
        work_varied: token_bool(body, "work_varied=")?,
        delta_pct,
        pair: (pair != "-").then(|| pair.to_string()),
        declared_n: token_u64(body, "n=")?.try_into()?,
        target_n: token_u64(body, "target_n=")?.try_into()?,
        samples: Vec::new(),
    })
}

fn validate_harvest(harvest: &Harvest) -> Result<()> {
    if !harvest.errors.is_empty() {
        bail!(
            "invalid benchmark serial stream: {}",
            harvest.errors.join("; ")
        );
    }
    let (expected_records, expected_skips) = harvest
        .end
        .ok_or_else(|| anyhow!("no narf.bench.end line — serial benchmark output is incomplete"))?;
    if expected_records != harvest.order.len()
        || expected_records != harvest.series.len()
        || expected_skips != harvest.skips.len()
    {
        bail!(
            "narf.bench.end declares recs={expected_records} skipped={expected_skips}, \
             but harvested {} record lines, {} unique records, and {} skips",
            harvest.order.len(),
            harvest.series.len(),
            harvest.skips.len(),
        );
    }
    if let Some(env) = &harvest.env {
        if expected_records + expected_skips != env.cases {
            bail!(
                "guest declared {} cases but ended with {} records and {} skips",
                env.cases,
                expected_records,
                expected_skips,
            );
        }
    }
    for name in &harvest.order {
        let series = harvest
            .series
            .get(name)
            .ok_or_else(|| anyhow!("benchmark record `{name}` disappeared during harvest"))?;
        if series.declared_n != series.samples.len() {
            bail!(
                "benchmark `{name}` declares n={} but harvested {} samples",
                series.declared_n,
                series.samples.len(),
            );
        }
        if series.samples.len() < 30 {
            bail!(
                "benchmark `{name}` has {} samples; §8.3 requires at least 30",
                series.samples.len(),
            );
        }
        if series.samples.len() < series.target_n {
            bail!(
                "benchmark `{name}` has {} samples, below its declared target {}",
                series.samples.len(),
                series.target_n,
            );
        }
    }
    Ok(())
}

fn validate_adaptive_sample_count(name: &str, n: usize, cv: f64) -> Result<()> {
    if cv > 0.05 && n < 100 {
        bail!(
            "benchmark `{name}` has CV {:.2}% with n={n}; §8.3 requires N=100. \
             Re-run with --n 100",
            cv * 100.0,
        );
    }
    Ok(())
}

const REQUIRED_BOOTSTRAP_RESAMPLES: usize = 10_000;

fn resamples_publishable(resamples: usize) -> Result<bool> {
    if resamples == 0 {
        bail!("--resamples must be greater than zero");
    }
    Ok(resamples == REQUIRED_BOOTSTRAP_RESAMPLES)
}

fn verify_protocol_preconditions(args: &BpfBenchArgs, accel: &str) -> Result<(bool, Option<u64>)> {
    println!("xtask bpf-bench: observing the required 30s pre-run thermal window...");
    let thermal = monitor_thermal_window();
    let pre = check_preconditions(accel, &thermal);
    println!("── §8.2 noise-control preconditions ─────────────────────");
    for p in &pre {
        println!(
            "  [{}] {:<38} {}",
            if p.ok { "ok" } else { "FAIL" },
            p.what,
            p.detail
        );
    }
    let resamples_verified = resamples_publishable(args.resamples)?;
    let mut failed: Vec<String> = pre
        .iter()
        .filter(|p| !p.ok)
        .map(|p| p.what.to_string())
        .collect();
    println!(
        "  [{}] {:<38} resamples={}",
        if resamples_verified { "ok" } else { "FAIL" },
        "bootstrap resamples = 10000",
        args.resamples,
    );
    if !resamples_verified {
        failed.push("bootstrap resamples differ from §8.4 requirement".into());
    }
    let verified = failed.is_empty();
    if !verified {
        if !args.allow_unverified_runner {
            bail!(
                "PreconditionFailed: {} benchmark protocol check(s) failed ({}). \
                 The run must be discarded rather than averaged in. \
                 Re-run with --allow-unverified-runner to take a development \
                 measurement, which must not be published as a perf number.",
                failed.len(),
                failed.join("; ")
            );
        }
        println!(
            "  → {} check(s) failed; proceeding under --allow-unverified-runner. \
             No performance record will be emitted.",
            failed.len()
        );
    }
    Ok((verified, thermal.throttle_end))
}

// ── the subcommand ──────────────────────────────────────────────────

pub fn bpf_bench_cmd(args: &BpfBenchArgs) -> Result<()> {
    resamples_publishable(args.resamples)?;
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

    let result = run_and_report(args, &build, &accel);

    match prior_append {
        Some(v) => std::env::set_var("XTASK_QEMU_APPEND", v),
        None => std::env::remove_var("XTASK_QEMU_APPEND"),
    }
    result
}

fn run_and_report(args: &BpfBenchArgs, build: &BuildArgs, accel: &str) -> Result<()> {
    let root = workspace_root()?;
    let out_dir = cargo_build(build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!("expected kernel binary at {}", kernel.display());
    }
    // Check immediately before QEMU launch: compilation can heat the CPU or
    // create host load, so a gate taken before the build would not describe
    // the benchmark's actual prior 30-second window.
    let (verified, throttle_before_run) = verify_protocol_preconditions(args, accel)?;

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
    let throttle_after_run = thermal_throttle_count();
    let runtime_thermal_clean = throttle_before_run
        .zip(throttle_after_run)
        .is_some_and(|(before, after)| before == after)
        && max_thermal_millicelsius().is_some_and(|temperature| temperature < 85_000);
    if !runtime_thermal_clean && !args.allow_unverified_runner {
        bail!("PreconditionFailed: thermal throttle tripwire changed during benchmark run");
    }
    if !runtime_thermal_clean {
        println!("  [advisory] runtime thermal tripwire failed; no JSON record will be emitted");
    }
    report(
        args,
        &harvest,
        accel,
        verified && runtime_thermal_clean,
        &root,
    )
}

/// One benchmark's parsed samples plus everything §8.4 asks be reported.
struct Row {
    series: Series,
    summary: Summary,
}

/// The subset of a §8.8 record needed for a cross-build comparison.
#[derive(Clone, Debug)]
struct ArchivedRecord {
    commit: String,
    dirty: bool,
    runner: String,
    accel: String,
    noise_control: String,
    guest_timing_verified: bool,
    guest_arch: String,
    benchmarks: BTreeMap<String, ArchivedSeries>,
}

#[derive(Clone, Debug)]
struct ArchivedSeries {
    unit: String,
    lower_is_better: bool,
    iters: u64,
    warmup: u64,
    work: u64,
    target_n: usize,
    samples: Vec<f64>,
}

#[derive(Clone, Debug)]
struct BaselineComparison {
    kind: &'static str,
    benchmark: String,
    baseline_commit: String,
    comparison: Comparison,
    decision: BaselineDecision,
    publishable: bool,
}

#[derive(Clone, Copy, Debug)]
struct ReportComparisons<'a> {
    pairs: &'a [Comparison],
    baselines: &'a [BaselineComparison],
}

#[derive(Clone, Copy, Debug)]
struct ReportProvenance<'a> {
    accel: &'a str,
    noise_verified: bool,
    source_dirty: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaselineDecision {
    Inconclusive,
    NotSignificant,
    Improvement,
    RegressionWithinDelta,
    RegressionBeyondDelta,
}

impl BaselineDecision {
    fn label(self) -> &'static str {
        match self {
            Self::Inconclusive => "inconclusive (tests disagree)",
            Self::NotSignificant => "no difference established",
            Self::Improvement => "significant improvement",
            Self::RegressionWithinDelta => "significant regression, within delta (tracked)",
            Self::RegressionBeyondDelta => "significant regression, beyond delta",
        }
    }

    fn record_value(self) -> &'static str {
        match self {
            Self::Inconclusive => "inconclusive",
            Self::NotSignificant => "not-significant",
            Self::Improvement => "improvement",
            Self::RegressionWithinDelta => "regression-within-delta",
            Self::RegressionBeyondDelta => "regression-beyond-delta",
        }
    }
}

fn required_string<'a>(value: &'a Value, key: &str, path: &Path) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{}: missing string field `{key}`", path.display()))
}

fn required_u64(value: &Value, key: &str, path: &Path) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("{}: missing integer field `{key}`", path.display()))
}

fn load_archived_record(path: &Path) -> Result<ArchivedRecord> {
    let bytes = std::fs::read(path).with_context(|| format!("read baseline {}", path.display()))?;
    parse_archived_record(&bytes, path)
}

fn parse_archived_record(bytes: &[u8], path: &Path) -> Result<ArchivedRecord> {
    let root: Value = serde_json::from_slice(bytes)
        .with_context(|| format!("parse baseline {}", path.display()))?;
    let schema = required_u64(&root, "schema", path)?;
    if !matches!(schema, 1..=3) {
        bail!(
            "{}: unsupported benchmark-record schema {schema} (expected 1, 2, or 3)",
            path.display()
        );
    }

    let guest = root
        .get("guest")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("{}: missing object field `guest`", path.display()))?;
    let guest_arch = guest
        .get("arch")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{}: missing string field `guest.arch`", path.display()))?;
    let entries = root
        .get("benchmarks")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{}: missing array field `benchmarks`", path.display()))?;
    let mut benchmarks = BTreeMap::new();
    for entry in entries {
        let name = required_string(entry, "benchmark", path)?.to_string();
        let sample_values = entry
            .get("samples")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("{}: `{name}` has no sample array", path.display()))?;
        let samples: Vec<f64> = sample_values
            .iter()
            .map(|sample| {
                sample.as_f64().filter(|v| v.is_finite()).ok_or_else(|| {
                    anyhow!("{}: `{name}` contains a non-finite sample", path.display())
                })
            })
            .collect::<Result<_>>()?;
        let declared_n = required_u64(entry, "n", path)? as usize;
        if declared_n != samples.len() {
            bail!(
                "{}: `{name}` declares n={declared_n} but contains {} samples",
                path.display(),
                samples.len()
            );
        }
        if samples.len() < 30 {
            bail!(
                "{}: `{name}` has {} samples; §8.3 requires at least 30",
                path.display(),
                samples.len()
            );
        }
        let target_n = if schema >= 3 {
            required_u64(entry, "target_n", path)?.try_into()?
        } else {
            declared_n
        };
        if samples.len() < target_n {
            bail!(
                "{}: `{name}` has {} samples, below its declared target {target_n}",
                path.display(),
                samples.len(),
            );
        }
        let sample_mean = mean(&samples);
        let sample_cv = if sample_mean == 0.0 {
            0.0
        } else {
            stddev(&samples) / sample_mean
        };
        validate_adaptive_sample_count(&name, samples.len(), sample_cv)
            .with_context(|| format!("{}: invalid archived sample count", path.display()))?;
        let archived = ArchivedSeries {
            unit: required_string(entry, "unit", path)?.to_string(),
            lower_is_better: entry
                .get("lower_is_better")
                .and_then(Value::as_bool)
                .ok_or_else(|| anyhow!("{}: `{name}` has no boolean direction", path.display()))?,
            iters: required_u64(entry, "iters", path)?,
            warmup: required_u64(entry, "warmup", path)?,
            work: required_u64(entry, "work_per_sample", path)?,
            target_n,
            samples,
        };
        if benchmarks.insert(name.clone(), archived).is_some() {
            bail!("{}: duplicate benchmark `{name}`", path.display());
        }
    }
    if benchmarks.is_empty() {
        bail!("{}: baseline contains no benchmarks", path.display());
    }

    let noise_control = required_string(&root, "noise_control", path)?.to_string();
    if !matches!(noise_control.as_str(), "verified" | "unverified") {
        bail!(
            "{}: unknown noise_control value `{noise_control}`",
            path.display()
        );
    }

    // Schema 1 predates source-state provenance. Treat it conservatively as
    // dirty: it remains usable for development comparisons, but cannot make a
    // result publishable merely because both machines passed the noise gate.
    let dirty = if schema == 1 {
        true
    } else {
        root.get("dirty")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("{}: missing boolean field `dirty`", path.display()))?
    };
    // Schemas 1 and 2 predate guest timing provenance. They remain readable
    // for advisory comparisons but cannot establish a publishable baseline.
    let guest_timing_verified = if schema >= 3 {
        guest
            .get("irq_masked")
            .and_then(Value::as_bool)
            .zip(guest.get("tick_reliable").and_then(Value::as_bool))
            .is_some_and(|(irq_masked, tick_reliable)| irq_masked && tick_reliable)
    } else {
        false
    };

    Ok(ArchivedRecord {
        commit: required_string(&root, "commit", path)?.to_string(),
        dirty,
        runner: required_string(&root, "runner", path)?.to_string(),
        accel: required_string(&root, "accel", path)?.to_string(),
        noise_control,
        guest_timing_verified,
        guest_arch: guest_arch.to_string(),
        benchmarks,
    })
}

fn report(
    args: &BpfBenchArgs,
    harvest: &Harvest,
    accel: &str,
    host_verified: bool,
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
    if env.version != 2 {
        bail!(
            "narf.bench.env reports grammar version {} but this parser speaks 2",
            env.version
        );
    }
    validate_harvest(harvest)?;
    if harvest.series.is_empty() {
        bail!(
            "the suite emitted no records (skipped: {})",
            harvest.skips.len()
        );
    }

    let guest_verified = env.irq_masked && env.tick_reliable;
    if !guest_verified && !args.allow_unverified_runner {
        bail!(
            "PreconditionFailed: guest reports irq_masked={} tick_reliable={}. \
             Re-run with --allow-unverified-runner only for an advisory development record",
            env.irq_masked,
            env.tick_reliable,
        );
    }
    let verified = host_verified && guest_verified;
    if !guest_verified {
        println!("  [advisory] guest timing preconditions failed; the record is not publishable");
    }

    let source_dirty = source_tree_dirty(root)?;
    if source_dirty {
        println!("  [advisory] source tree has uncommitted changes; the record is not publishable");
    }

    let mut rows: Vec<Row> = Vec::new();
    for name in &harvest.order {
        let Some(s) = harvest.series.get(name) else {
            continue;
        };
        let summary = summarize(&s.samples, args.resamples, hash_name(name));
        validate_adaptive_sample_count(name, summary.n, summary.cv)?;
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
    let comparisons = compare_pairs(args, &rows)?;
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

    let mut baseline_comparisons = Vec::new();
    for (kind, configured) in [
        ("main", args.baseline.as_deref()),
        ("release", args.release_baseline.as_deref()),
    ] {
        let Some(configured) = configured else {
            continue;
        };
        let configured_path = Path::new(configured);
        let path = if configured_path.is_absolute() {
            configured_path.to_path_buf()
        } else {
            root.join(configured_path)
        };
        let archived = load_archived_record(&path)?;
        let compared = compare_archived(
            args,
            &rows,
            &archived,
            kind,
            &env.arch,
            accel,
            verified && !source_dirty,
        )?;
        println!();
        println!(
            "── §8.6 {kind} baseline {} (BH-corrected, q=0.05) ──",
            archived.commit
        );
        for item in &compared {
            let c = &item.comparison;
            println!("  {}", item.benchmark);
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
                item.decision.label(),
                if item.publishable {
                    ""
                } else {
                    "  [advisory: runner unverified or source tree dirty]"
                }
            );
        }
        baseline_comparisons.extend(compared);
    }

    if verified {
        write_json(
            args,
            harvest,
            &rows,
            ReportComparisons {
                pairs: &comparisons,
                baselines: &baseline_comparisons,
            },
            ReportProvenance {
                accel,
                noise_verified: true,
                source_dirty,
            },
            root,
        )?;
    } else {
        println!("  [advisory] no JSON record emitted because protocol checks failed");
    }
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
fn validate_pair_declarations(rows: &[Row]) -> Result<()> {
    let by_name: BTreeMap<&str, &Row> = rows.iter().map(|r| (r.series.name.as_str(), r)).collect();
    for r in rows {
        let Some(peer) = r.series.pair.as_deref() else {
            continue;
        };
        let other = by_name
            .get(peer)
            .ok_or_else(|| anyhow!("A/B peer `{peer}` for `{}` is missing", r.series.name))?;
        if peer == r.series.name
            || other.series.pair.as_deref() != Some(r.series.name.as_str())
            || other.series.subsystem != r.series.subsystem
            || other.series.unit != r.series.unit
            || other.series.lower_is_better != r.series.lower_is_better
            || other.series.iters != r.series.iters
            || other.series.warmup != r.series.warmup
            || other.series.work != r.series.work
            || other.series.work_varied != r.series.work_varied
            || other.series.delta_pct != r.series.delta_pct
            || other.series.target_n != r.series.target_n
            || other.series.samples.len() != r.series.samples.len()
        {
            bail!(
                "A/B declaration for `{}` is not reciprocal and compatible with `{peer}`",
                r.series.name
            );
        }
    }
    Ok(())
}

fn compare_pairs(args: &BpfBenchArgs, rows: &[Row]) -> Result<Vec<Comparison>> {
    validate_pair_declarations(rows)?;
    let by_name: BTreeMap<&str, &Row> = rows.iter().map(|r| (r.series.name.as_str(), r)).collect();
    let mut out: Vec<Comparison> = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();
    for r in rows {
        let Some(peer) = r.series.pair.as_deref() else {
            continue;
        };
        let other = by_name
            .get(peer)
            .expect("pair declarations were validated before comparison");
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
    Ok(out)
}

fn baseline_decision(comparison: &Comparison, lower_is_better: bool) -> BaselineDecision {
    if comparison.welch_significant != comparison.mwu_significant {
        return BaselineDecision::Inconclusive;
    }
    if !comparison.welch_significant {
        return BaselineDecision::NotSignificant;
    }

    let regressed = if lower_is_better {
        comparison.delta_pct > 0.0
    } else {
        comparison.delta_pct < 0.0
    };
    if !regressed {
        return BaselineDecision::Improvement;
    }

    let beyond_delta = if lower_is_better {
        comparison.delta_ci.0 > comparison.delta_threshold
    } else {
        comparison.delta_ci.1 < -comparison.delta_threshold
    };
    if beyond_delta {
        BaselineDecision::RegressionBeyondDelta
    } else {
        BaselineDecision::RegressionWithinDelta
    }
}

/// Compare the current suite with an archived main or release record.
///
/// §8.6 requires the same runner. The declaration checks are equally strict:
/// changing the timer unit, inner-iteration count, or work per sample while
/// retaining a benchmark name makes the two raw vectors different metrics.
fn compare_archived(
    args: &BpfBenchArgs,
    rows: &[Row],
    archived: &ArchivedRecord,
    kind: &'static str,
    current_arch: &str,
    accel: &str,
    current_publishable: bool,
) -> Result<Vec<BaselineComparison>> {
    let runner = hostname();
    if archived.runner != runner {
        bail!(
            "{kind} baseline runner is `{}`, current runner is `{runner}`; §8.6 requires the same runner",
            archived.runner
        );
    }
    if archived.accel != accel {
        bail!(
            "{kind} baseline accelerator is `{}`, current accelerator is `{accel}`",
            archived.accel
        );
    }
    if archived.guest_arch != current_arch {
        bail!(
            "{kind} baseline guest arch is `{}`, current guest arch is `{current_arch}`",
            archived.guest_arch
        );
    }

    let mut out = Vec::new();
    for row in rows {
        let Some(base) = archived.benchmarks.get(&row.series.name) else {
            continue;
        };
        if base.unit != row.series.unit
            || base.lower_is_better != row.series.lower_is_better
            || base.iters != row.series.iters
            || base.warmup != row.series.warmup
            || base.work != row.series.work
            || base.target_n != row.series.target_n
        {
            bail!(
                "{kind} baseline declaration for `{}` is incompatible with the current benchmark",
                row.series.name
            );
        }
        let (welch_p, welch_logged) = welch_t_test(&base.samples, &row.series.samples);
        let mwu_p = mann_whitney_u(&base.samples, &row.series.samples);
        let (delta_pct, delta_ci) = delta_pct_ci(
            &base.samples,
            &row.series.samples,
            args.resamples,
            hash_name(&row.series.name) ^ hash_name(kind),
        );
        out.push(BaselineComparison {
            kind,
            benchmark: row.series.name.clone(),
            baseline_commit: archived.commit.clone(),
            comparison: Comparison {
                baseline: format!("{}@{}", row.series.name, archived.commit),
                candidate: row.series.name.clone(),
                delta_pct,
                delta_ci,
                welch_p,
                welch_logged,
                mwu_p,
                delta_threshold: row.series.delta_pct,
                welch_significant: false,
                mwu_significant: false,
            },
            decision: BaselineDecision::NotSignificant,
            publishable: current_publishable
                && archived.noise_control == "verified"
                && archived.guest_timing_verified
                && !archived.dirty,
        });
    }

    if out.is_empty() {
        bail!("{kind} baseline has no benchmark names in common with the current suite");
    }
    let welch: Vec<f64> = out.iter().map(|c| c.comparison.welch_p).collect();
    let mwu: Vec<f64> = out.iter().map(|c| c.comparison.mwu_p).collect();
    let welch_rej = benjamini_hochberg(&welch, 0.05);
    let mwu_rej = benjamini_hochberg(&mwu, 0.05);
    for (i, item) in out.iter_mut().enumerate() {
        item.comparison.welch_significant = welch_rej[i];
        item.comparison.mwu_significant = mwu_rej[i];
        let lower_is_better = rows
            .iter()
            .find(|row| row.series.name == item.benchmark)
            .expect("comparison came from current rows")
            .series
            .lower_is_better;
        item.decision = baseline_decision(&item.comparison, lower_is_better);
    }
    Ok(out)
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

fn source_tree_dirty(root: &Path) -> Result<bool> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .current_dir(root)
        .output()
        .context("inspect source-tree state for benchmark provenance")?;
    if !output.status.success() {
        bail!(
            "git status failed while recording benchmark provenance: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(!output.stdout.is_empty())
}

fn write_json(
    args: &BpfBenchArgs,
    harvest: &Harvest,
    rows: &[Row],
    comparisons: ReportComparisons<'_>,
    provenance: ReportProvenance<'_>,
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
    writeln!(f, "  \"schema\": 3,")?;
    writeln!(f, "  \"commit\": \"{commit}\",")?;
    writeln!(f, "  \"dirty\": {},", provenance.source_dirty)?;
    writeln!(f, "  \"runner\": \"{}\",", hostname())?;
    writeln!(f, "  \"accel\": \"{}\",", provenance.accel)?;
    writeln!(
        f,
        "  \"noise_control\": \"{}\",",
        if provenance.noise_verified {
            "verified"
        } else {
            "unverified"
        }
    )?;
    writeln!(f, "  \"guest\": {{ \"arch\": \"{}\", \"cpus\": {}, \"tsc_mult\": {}, \"tsc_shift\": {}, \"irq_masked\": {}, \"tick_reliable\": {} }},",
        env.arch, env.cpus, env.tsc_mult, env.tsc_shift, env.irq_masked, env.tick_reliable)?;
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
        writeln!(f, "      \"target_n\": {},", r.series.target_n)?;
        writeln!(f, "      \"iters\": {},", r.series.iters)?;
        writeln!(f, "      \"warmup\": {},", r.series.warmup)?;
        writeln!(f, "      \"work_per_sample\": {},", r.series.work)?;
        writeln!(
            f,
            "      \"delta_threshold_pct\": {:.2},",
            r.series.delta_pct
        )?;
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
    for (i, c) in comparisons.pairs.iter().enumerate() {
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
            if i + 1 == comparisons.pairs.len() {
                ""
            } else {
                ","
            }
        )?;
    }
    writeln!(f, "  ],")?;
    writeln!(f, "  \"baseline_comparisons\": [")?;
    for (i, item) in comparisons.baselines.iter().enumerate() {
        let c = &item.comparison;
        writeln!(f, "    {{")?;
        writeln!(f, "      \"kind\": \"{}\",", item.kind)?;
        writeln!(f, "      \"benchmark\": \"{}\",", item.benchmark)?;
        writeln!(
            f,
            "      \"baseline_commit\": \"{}\",",
            item.baseline_commit
        )?;
        writeln!(f, "      \"candidate_commit\": \"{commit}\",")?;
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
        writeln!(f, "      \"publishable\": {},", item.publishable)?;
        writeln!(
            f,
            "      \"decision\": \"{}\"",
            item.decision.record_value()
        )?;
        writeln!(
            f,
            "    }}{}",
            if i + 1 == comparisons.baselines.len() {
                ""
            } else {
                ","
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn harvested_series(declared_n: usize, actual_n: usize, with_end: bool) -> Harvest {
        let mut harvest = Harvest::default();
        harvest.line(
            "narf.bench.env: version=2 arch=x86_64 cases=1 cpus=1 cycles_per_ns=1 \
             tsc_mult=1 tsc_shift=0 irq_masked=1 tick_reliable=1",
        );
        harvest.line(&format!(
            "narf.bench.rec: name=bpf.test subsystem=bpf unit=cycles \
             lower_is_better=1 n={declared_n} target_n=30 iters=8 warmup=3 work=8 \
             work_varied=0 delta_pct=3 pair=-"
        ));
        let values = (1..=actual_n)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        harvest.line(&format!("narf.bench.val: name=bpf.test i=0 v={values}"));
        if with_end {
            harvest.line("narf.bench.end: recs=1 skipped=0");
        }
        harvest
    }

    #[test]
    fn live_harvest_requires_complete_declared_sample_vector() {
        let valid = harvested_series(30, 30, true);
        validate_harvest(&valid).expect("complete stream should validate");

        let missing_end = harvested_series(30, 30, false);
        assert!(validate_harvest(&missing_end)
            .expect_err("missing end marker must fail")
            .to_string()
            .contains("no narf.bench.end"));

        let short = harvested_series(30, 29, true);
        assert!(validate_harvest(&short)
            .expect_err("truncated values must fail")
            .to_string()
            .contains("declares n=30"));

        let below_floor = harvested_series(29, 29, true);
        assert!(validate_harvest(&below_floor)
            .expect_err("N below 30 must fail")
            .to_string()
            .contains("requires at least 30"));
    }

    #[test]
    fn live_harvest_rejects_chunk_corruption_and_post_end_data() {
        let mut duplicate_chunk = harvested_series(30, 30, false);
        duplicate_chunk.line("narf.bench.val: name=bpf.test i=0 v=100");
        duplicate_chunk.line("narf.bench.end: recs=1 skipped=0");
        assert!(validate_harvest(&duplicate_chunk)
            .expect_err("duplicate chunk must fail")
            .to_string()
            .contains("expected i=30"));

        let mut nonfinite = harvested_series(30, 30, false);
        nonfinite.line("narf.bench.val: name=bpf.test i=30 v=NaN");
        nonfinite.line("narf.bench.end: recs=1 skipped=0");
        assert!(validate_harvest(&nonfinite)
            .expect_err("non-finite sample must fail")
            .to_string()
            .contains("non-finite"));

        let mut post_end = harvested_series(30, 30, true);
        post_end.line("narf.bench.skip: name=late reason=too-late");
        assert!(validate_harvest(&post_end)
            .expect_err("post-end record must fail")
            .to_string()
            .contains("after narf.bench.end"));

        assert!(parse_env(
            "version=2 arch=x86_64 cases=1 cpus=1 cycles_per_ns=1 \
             tsc_mult=1 tsc_shift=64 irq_masked=1 tick_reliable=1"
        )
        .is_err());
    }

    #[test]
    fn high_cv_requires_one_hundred_samples() {
        assert!(validate_adaptive_sample_count("bpf.test", 30, 0.051).is_err());
        assert!(validate_adaptive_sample_count("bpf.test", 100, 0.051).is_ok());
        assert!(validate_adaptive_sample_count("bpf.test", 30, 0.05).is_ok());
        assert_eq!(REQUIRED_BOOTSTRAP_RESAMPLES, 10_000);
        assert!(resamples_publishable(0).is_err());
        assert!(resamples_publishable(10_000).unwrap());
        assert!(!resamples_publishable(1_000).unwrap());
    }

    fn pair_row(name: &str, peer: Option<&str>, unit: &str) -> Row {
        let samples = vec![100.0; 30];
        Row {
            summary: summarize(&samples, 10, hash_name(name)),
            series: Series {
                name: name.into(),
                subsystem: "bpf".into(),
                unit: unit.into(),
                lower_is_better: true,
                iters: 8,
                warmup: 3,
                work: 8,
                work_varied: false,
                delta_pct: 3.0,
                pair: peer.map(str::to_string),
                declared_n: 30,
                target_n: 30,
                samples,
            },
        }
    }

    #[test]
    fn ab_pairs_must_be_reciprocal_and_compatible() {
        let valid = vec![
            pair_row("a", Some("b"), "cycles"),
            pair_row("b", Some("a"), "cycles"),
        ];
        validate_pair_declarations(&valid).expect("reciprocal compatible pair");

        let missing = vec![pair_row("a", Some("b"), "cycles")];
        assert!(validate_pair_declarations(&missing).is_err());

        let unlike = vec![
            pair_row("a", Some("b"), "cycles"),
            pair_row("b", Some("a"), "ns"),
        ];
        assert!(validate_pair_declarations(&unlike).is_err());
    }

    fn comparison(delta_pct: f64, delta_ci: (f64, f64), welch: bool, mwu: bool) -> Comparison {
        Comparison {
            baseline: "base".into(),
            candidate: "candidate".into(),
            delta_pct,
            delta_ci,
            welch_p: 0.001,
            welch_logged: false,
            mwu_p: 0.001,
            delta_threshold: 3.0,
            welch_significant: welch,
            mwu_significant: mwu,
        }
    }

    #[test]
    fn baseline_direction_distinguishes_improvements_from_regressions() {
        assert_eq!(
            baseline_decision(&comparison(5.0, (4.0, 6.0), true, true), true),
            BaselineDecision::RegressionBeyondDelta
        );
        assert_eq!(
            baseline_decision(&comparison(-5.0, (-6.0, -4.0), true, true), true),
            BaselineDecision::Improvement
        );
        assert_eq!(
            baseline_decision(&comparison(-5.0, (-6.0, -4.0), true, true), false),
            BaselineDecision::RegressionBeyondDelta
        );
        assert_eq!(
            baseline_decision(&comparison(5.0, (4.0, 6.0), true, true), false),
            BaselineDecision::Improvement
        );
    }

    #[test]
    fn baseline_disagreement_remains_inconclusive() {
        assert_eq!(
            baseline_decision(&comparison(20.0, (19.0, 21.0), true, false), true),
            BaselineDecision::Inconclusive
        );
    }

    #[test]
    fn archived_schema_one_record_remains_readable() {
        let samples = (0..30)
            .map(|_| "100".to_string())
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
                "schema": 1,
                "commit": "abc123",
                "runner": "runner-1",
                "accel": "kvm",
                "noise_control": "verified",
                "guest": {{ "arch": "x86_64" }},
                "benchmarks": [{{
                    "benchmark": "bpf.test",
                    "unit": "cycles",
                    "lower_is_better": true,
                    "n": 30,
                    "iters": 8,
                    "warmup": 3,
                    "work_per_sample": 8,
                    "samples": [{samples}]
                }}]
            }}"#
        );
        let record = parse_archived_record(json.as_bytes(), Path::new("record.json"))
            .expect("valid archived record");
        assert_eq!(record.commit, "abc123");
        assert!(record.dirty, "schema 1 has no clean-tree provenance");
        assert!(!record.guest_timing_verified);
        assert_eq!(record.benchmarks["bpf.test"].samples.len(), 30);
    }

    #[test]
    fn archived_schema_two_preserves_clean_tree_provenance() {
        let samples = (0..30)
            .map(|_| "100".to_string())
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
                "schema": 2,
                "commit": "abc123",
                "dirty": false,
                "runner": "runner-1",
                "accel": "kvm",
                "noise_control": "verified",
                "guest": {{ "arch": "x86_64" }},
                "benchmarks": [{{
                    "benchmark": "bpf.test",
                    "unit": "cycles",
                    "lower_is_better": true,
                    "n": 30,
                    "iters": 8,
                    "warmup": 3,
                    "work_per_sample": 8,
                    "samples": [{samples}]
                }}]
            }}"#
        );
        let record = parse_archived_record(json.as_bytes(), Path::new("record.json"))
            .expect("valid archived record");
        assert!(!record.dirty);
        assert!(!record.guest_timing_verified);
    }

    #[test]
    fn archived_schema_three_carries_guest_timing_provenance() {
        let samples = (0..30)
            .map(|_| "100".to_string())
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
                "schema": 3,
                "commit": "abc123",
                "dirty": false,
                "runner": "runner-1",
                "accel": "kvm",
                "noise_control": "verified",
                "guest": {{
                    "arch": "x86_64",
                    "irq_masked": true,
                    "tick_reliable": true
                }},
                "benchmarks": [{{
                    "benchmark": "bpf.test",
                    "unit": "cycles",
                    "lower_is_better": true,
                    "n": 30,
                    "target_n": 30,
                    "iters": 8,
                    "warmup": 3,
                    "work_per_sample": 8,
                    "samples": [{samples}]
                }}]
            }}"#
        );
        let record = parse_archived_record(json.as_bytes(), Path::new("record.json"))
            .expect("valid schema-3 record");
        assert!(record.guest_timing_verified);
        assert_eq!(record.benchmarks["bpf.test"].target_n, 30);

        let underpowered = json.replace("\"target_n\": 30", "\"target_n\": 60");
        assert!(
            parse_archived_record(underpowered.as_bytes(), Path::new("record.json"))
                .expect_err("archive below its target N must fail")
                .to_string()
                .contains("below its declared target 60")
        );
    }

    #[test]
    fn archived_high_cv_series_requires_one_hundred_samples() {
        let samples = (1..=30)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
                "schema": 2,
                "commit": "abc123",
                "dirty": false,
                "runner": "runner-1",
                "accel": "kvm",
                "noise_control": "verified",
                "guest": {{ "arch": "x86_64" }},
                "benchmarks": [{{
                    "benchmark": "bpf.test",
                    "unit": "cycles",
                    "lower_is_better": true,
                    "n": 30,
                    "iters": 8,
                    "warmup": 3,
                    "work_per_sample": 8,
                    "samples": [{samples}]
                }}]
            }}"#
        );
        assert!(
            parse_archived_record(json.as_bytes(), Path::new("record.json"))
                .expect_err("noisy N=30 archive must fail")
                .to_string()
                .contains("invalid archived sample count")
        );
    }

    #[test]
    fn archived_record_rejects_declared_sample_count_mismatch() {
        let samples = (1..=30)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
                "schema": 2,
                "commit": "abc123",
                "dirty": false,
                "runner": "runner-1",
                "accel": "kvm",
                "noise_control": "unverified",
                "guest": {{ "arch": "x86_64" }},
                "benchmarks": [{{
                    "benchmark": "bpf.test",
                    "unit": "cycles",
                    "lower_is_better": true,
                    "n": 31,
                    "iters": 8,
                    "warmup": 3,
                    "work_per_sample": 8,
                    "samples": [{samples}]
                }}]
            }}"#
        );
        let error = parse_archived_record(json.as_bytes(), Path::new("record.json"))
            .expect_err("mismatched n must fail");
        assert!(error.to_string().contains("declares n=31"));
    }
}
