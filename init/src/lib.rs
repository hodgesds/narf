//! narf-init — staged initcall registry.
//!
//! Mirrors Linux's `*_initcall` ordering without the ELF-section
//! plumbing (linker scripts + per-stage `__initcall_start_N` symbols
//! + `do_initcalls` walker). Subsystems and drivers express
//! initialisation order by tagging each call with a `Stage`; the
//! kernel runs every stage in `Stage::ALL` order, calling each
//! registered function exactly once.
//!
//! ## Stages
//!
//! | Stage      | Linux equivalent       | Typical content                                 |
//! |------------|------------------------|-------------------------------------------------|
//! | Early      | `early_initcall`       | runs before the heap; arch-required setup       |
//! | Core       | `core_initcall`        | RCU, scheduler, IRQ dispatch                    |
//! | PostCore   | `postcore_initcall`    | structures depending on Core                    |
//! | Arch       | `arch_initcall`        | per-CPU bring-up, arch-specific MSRs            |
//! | Subsys     | `subsys_initcall`      | per-subsystem one-time setup (registries, hooks)|
//! | Fs         | `fs_initcall`          | filesystem registration                         |
//! | Device     | `device_initcall`      | driver probes (default for ordinary drivers)    |
//! | Late       | `late_initcall`        | post-driver glue, splash, boot summary          |
//!
//! Stages are policy, not enforced — an Early initcall that touches
//! the heap is still a bug. The contract is: when stage N runs,
//! every initcall in stages 0..N has already returned.
//!
//! ## Failure semantics
//!
//! Initcalls return `InitResult`:
//!   * `Ok`           — completed successfully.
//!   * `NotPresent`   — feature/device absent (silent skip;
//!                      counted in stage stats but not a failure).
//!   * `Error(&str)`  — non-fatal failure; logged via the optional
//!                      log-hook, kernel continues to the next
//!                      initcall.
//!
//! Fatal init (paging on, console early-init, frame allocator
//! online) stays outside the registry. The registry is for
//! soft-fail subsystems and drivers that the kernel must be
//! resilient to losing.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Initcall return value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InitResult {
    Ok,
    NotPresent,
    Error(&'static str),
}

/// Initcall function pointer + a static name for diagnostics.
pub type InitFn = fn() -> InitResult;

/// Linux-style staging hierarchy. Higher stages run later.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Stage {
    Early    = 0,
    Core     = 1,
    PostCore = 2,
    Arch     = 3,
    Subsys   = 4,
    Fs       = 5,
    Device   = 6,
    Late     = 7,
}

impl Stage {
    /// Iteration order. Used by `run_all_through`.
    pub const ALL: [Stage; 8] = [
        Stage::Early, Stage::Core, Stage::PostCore, Stage::Arch,
        Stage::Subsys, Stage::Fs, Stage::Device, Stage::Late,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Stage::Early    => "early",
            Stage::Core     => "core",
            Stage::PostCore => "postcore",
            Stage::Arch     => "arch",
            Stage::Subsys   => "subsys",
            Stage::Fs       => "fs",
            Stage::Device   => "device",
            Stage::Late     => "late",
        }
    }
}

/// One registered initcall.
#[derive(Copy, Clone)]
pub struct Initcall {
    pub stage: Stage,
    pub name:  &'static str,
    pub func:  InitFn,
}

impl core::fmt::Debug for Initcall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Initcall")
            .field("stage", &self.stage)
            .field("name",  &self.name)
            .finish_non_exhaustive()
    }
}

/// Per-stage statistics filled in by `run_stage`. Cleared by
/// `__reset_for_test`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StageStats {
    pub total:        u32,
    pub ok:           u32,
    pub not_present:  u32,
    pub error:        u32,
    /// Sum of `cycles_since` deltas across every initcall in the
    /// stage. Stays 0 when the cycle counter isn't available
    /// (fallback time backend).
    pub total_cycles: u64,
    /// Cycles spent in the slowest single initcall of this stage.
    pub max_cycles:   u64,
    /// Name of the slowest single initcall, for diagnostics.
    pub max_name:     &'static str,
}

/// Optional hook for emitting "init: stage X / call Y -> Z" lines.
/// Frame installs this after the console is up; before then,
/// failures are silently counted in the stats.
pub type LogHook = fn(&str);
static LOG_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn set_log_hook(h: LogHook) {
    LOG_HOOK.store(h as usize, Ordering::Release);
}

fn log(line: &str) {
    let h = LOG_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: LOG_HOOK is only written via `set_log_hook` which
        // stores `LogHook as usize`.
        let f: LogHook = unsafe { core::mem::transmute(h) };
        f(line);
    }
}

/// Process-wide registry: one `Vec<Initcall>` per stage. Each
/// stage's vec is held behind an IrqSafeSpinLock so registration
/// can happen from any context (typically BSP boot).
struct Registry {
    stages: [IrqSafeSpinLock<Vec<Initcall>>; 8],
    stats:  IrqSafeSpinLock<[StageStats; 8]>,
}

const EMPTY_STATS: StageStats = StageStats {
    total: 0, ok: 0, not_present: 0, error: 0,
    total_cycles: 0, max_cycles: 0, max_name: "",
};

static REGISTRY: Registry = Registry {
    stages: [
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
        IrqSafeSpinLock::new(Vec::new()),
    ],
    stats: IrqSafeSpinLock::new([EMPTY_STATS; 8]),
};

/// Register an initcall under the given stage. The function will
/// run when `run_stage(stage)` is invoked. Subsequent registrations
/// to the same stage append; order within a stage is the
/// registration order.
pub fn register(stage: Stage, name: &'static str, func: InitFn) {
    let i = stage as usize;
    REGISTRY.stages[i].lock().push(Initcall { stage, name, func });
}

/// Run every initcall registered under `stage`. Each call's result
/// is logged + counted. Returns the stage's stats post-run.
pub fn run_stage(stage: Stage) -> StageStats {
    let i = stage as usize;
    // Take a snapshot — registrations during a stage's run are
    // possible (a Subsys initcall might Stage::Device-register a
    // probe), but they should land in the *target* stage's vec for
    // its later run, not this one's.
    let calls = REGISTRY.stages[i].lock().clone();
    let mut stats = StageStats::default();
    for ic in &calls {
        stats.total += 1;
        let t0 = narf_time::now_cycles();
        let result = (ic.func)();
        let dt = narf_time::now_cycles().saturating_sub(t0);
        stats.total_cycles = stats.total_cycles.saturating_add(dt);
        if dt > stats.max_cycles {
            stats.max_cycles = dt;
            stats.max_name   = ic.name;
        }
        match result {
            InitResult::Ok         => stats.ok += 1,
            InitResult::NotPresent => stats.not_present += 1,
            InitResult::Error(msg) => {
                stats.error += 1;
                let mut buf = [0u8; 256];
                let mut w = TruncatingWriter::new(&mut buf);
                use core::fmt::Write;
                let _ = write!(&mut w, "init: {} / {} -> error: {}",
                               stage.name(), ic.name, msg);
                log(w.as_str());
            }
        }
    }
    REGISTRY.stats.lock()[i] = stats;
    stats
}

/// Convenience: run every stage from `Early` through and including
/// `last_stage`. Returns the accumulated stats per stage.
pub fn run_all_through(last_stage: Stage) -> [StageStats; 8] {
    let mut out = [StageStats::default(); 8];
    for s in Stage::ALL {
        if (s as u8) > (last_stage as u8) { break; }
        out[s as usize] = run_stage(s);
    }
    out
}

/// Read the most-recent stats for a stage without re-running it.
pub fn stats(stage: Stage) -> StageStats {
    REGISTRY.stats.lock()[stage as usize]
}

/// Number of initcalls currently registered under `stage`. Useful
/// for tests that want to assert the registry is non-empty before
/// firing `run_stage`.
pub fn registered_count(stage: Stage) -> usize {
    REGISTRY.stages[stage as usize].lock().len()
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    for v in REGISTRY.stages.iter() { v.lock().clear(); }
    *REGISTRY.stats.lock() = [EMPTY_STATS; 8];
}

/// Print a formatted boot summary table through the supplied
/// writer (typically `console::Writer`). One row per stage; the
/// caller can compute its own time-conversion (the stats hold
/// raw cycles).
pub fn print_summary(w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    use core::fmt::Write as _;
    writeln!(w, "  init summary:")?;
    writeln!(w, "    stage       calls  ok  skip  err  total_cyc      slowest")?;
    for stage in Stage::ALL {
        let s = stats(stage);
        if s.total == 0 { continue; }
        writeln!(
            w,
            "    {:8}    {:5}  {:>2}  {:>4}  {:>3}  {:>11}  {} ({} cyc)",
            stage.name(),
            s.total, s.ok, s.not_present, s.error,
            s.total_cycles,
            if s.max_name.is_empty() { "-" } else { s.max_name },
            s.max_cycles,
        )?;
    }
    Ok(())
}

// ── tiny formatter helper to avoid an alloc::format!() in the hot path ──

struct TruncatingWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> TruncatingWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self { Self { buf, len: 0 } }
    fn as_str(&self) -> &str {
        // SAFETY: we only ever push valid UTF-8 via fmt::Write, and
        // truncate at byte boundaries that are also char boundaries
        // for the chars we write (ASCII subset of stage names + the
        // formatted name string).
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<'a> core::fmt::Write for TruncatingWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let avail = self.buf.len().saturating_sub(self.len);
        let n = avail.min(s.len());
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

// Per-crate smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite.
mod tests;
