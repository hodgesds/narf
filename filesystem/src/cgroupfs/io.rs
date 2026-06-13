//! `io` controller — block-I/O weight + per-device accounting.
//!
//! Presents the cgroup-v2 io interface:
//!   * `io.stat`   (ro) — per-device `rbytes/wbytes/rios/wios`, charged
//!     from real block-layer traffic via the `narf-block` cgroup hook.
//!   * `io.weight` (rw) — default per-cgroup weight (1..=10000).
//!   * `io.max`    (rw) — per-device `rbps/wbps/riops/wiops` limits.
//!
//! ## Accounting (REAL)
//!
//! `new_state` lazily installs a fn-pointer hook into `narf-block`
//! (`install_cgroup_io_hook`, guarded by an `AtomicBool` so it runs
//! exactly once, no boot wiring needed). The block layer invokes the
//! hook on every *accounted* submit with `(pid, dev, bytes,
//! is_write)`; the hook walks `pid`'s cgroup chain via
//! `with_chain_states(pid, "io", …)` and adds the bytes/ios to each
//! level's `IoState`, downcasting through `as_any`. So `io.stat`
//! reflects real charged traffic for every request that reaches the
//! accounted submit seam (`BlockDevice::submit_accounted`).
//!
//! ## Throttling (ACCOUNTING-ONLY)
//!
//! `io.max` limits are parsed, stored, and reported, but NOT enforced.
//! The `narf-block` I/O scheduler exposes no rate-limit / token-bucket
//! seam to delay or reject a request by bps/iops, so there is nowhere
//! to apply a limit without fabricating throttling behaviour. The
//! limits are kept so that (a) `io.max` round-trips correctly and (b)
//! a future block-layer rate-limit hook can read them. Until that
//! seam exists, setting `io.max` changes reporting only — it does not
//! slow or cap I/O.
//!
//! Linux ref: `block/blk-cgroup.c`, `block/blk-throttle.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"IO".

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &["io.stat", "io.max", "io.weight"];

/// Default `io.weight` for a fresh cgroup (cgroup-v2 default is 100).
const DEFAULT_WEIGHT: u64 = 100;

/// Installs the `narf-block` accounting hook exactly once, the first
/// time any `IoState` is created. No boot ordering required.
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Per-device I/O counters (`io.stat` fields).
#[derive(Clone, Copy, Debug, Default)]
struct DevStats {
    rbytes: u64,
    wbytes: u64,
    rios: u64,
    wios: u64,
}

/// Per-device `io.max` limits. `None` = `"max"` (unlimited) for that
/// field. ACCOUNTING-ONLY (see module docs): stored + reported, never
/// enforced.
#[derive(Clone, Copy, Debug, Default)]
struct DevLimits {
    rbps: Option<u64>,
    wbps: Option<u64>,
    riops: Option<u64>,
    wiops: Option<u64>,
}

impl DevLimits {
    /// A limit row with every field `"max"` carries no information and
    /// is dropped rather than printed.
    fn is_empty(&self) -> bool {
        self.rbps.is_none() && self.wbps.is_none() && self.riops.is_none() && self.wiops.is_none()
    }
}

#[derive(Debug)]
pub struct IoController;

impl Controller for IoController {
    fn name(&self) -> &'static str {
        "io"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        install_hook_once();
        Arc::new(IoState {
            weight: IrqSafeSpinLock::new(DEFAULT_WEIGHT),
            stats: IrqSafeSpinLock::new(BTreeMap::new()),
            limits: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }
}

#[derive(Debug)]
pub struct IoState {
    /// `io.weight` default (1..=10000).
    weight: IrqSafeSpinLock<u64>,
    /// Per-device charged counters, keyed by `dev` (MAJ:MIN packed).
    stats: IrqSafeSpinLock<BTreeMap<u64, DevStats>>,
    /// Per-device `io.max` limits (accounting-only).
    limits: IrqSafeSpinLock<BTreeMap<u64, DevLimits>>,
}

impl IoState {
    /// Charge one accounted block request into this cgroup level.
    /// Called (per level) by the block-layer hook.
    fn charge(&self, dev: u64, bytes: u64, is_write: bool) {
        let mut stats = self.stats.lock();
        let e = stats.entry(dev).or_default();
        if is_write {
            e.wbytes = e.wbytes.saturating_add(bytes);
            e.wios = e.wios.saturating_add(1);
        } else {
            e.rbytes = e.rbytes.saturating_add(bytes);
            e.rios = e.rios.saturating_add(1);
        }
    }
}

impl ControllerState for IoState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "io.stat" => render_stat(&self.stats.lock()),
            "io.max" => render_max(&self.limits.lock()),
            "io.weight" => format!("default {}\n", *self.weight.lock()),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        match file {
            "io.weight" => {
                // Accept "default <n>" or bare "<n>".
                let n = text
                    .split_whitespace()
                    .next_back()
                    .ok_or(FsError::InvalidData)?
                    .parse::<u64>()
                    .map_err(|_| FsError::InvalidData)?;
                if !(1..=10000).contains(&n) {
                    return Err(FsError::InvalidData);
                }
                *self.weight.lock() = n;
                Ok(())
            }
            "io.max" => {
                let (dev, limits) = parse_max_line(text)?;
                let mut map = self.limits.lock();
                if limits.is_empty() {
                    map.remove(&dev);
                } else {
                    // Merge: a write updates only the named fields,
                    // leaving previously-set ones intact (v2 semantics).
                    let cur = map.entry(dev).or_default();
                    if limits.rbps.is_some() {
                        cur.rbps = limits.rbps;
                    }
                    if limits.wbps.is_some() {
                        cur.wbps = limits.wbps;
                    }
                    if limits.riops.is_some() {
                        cur.riops = limits.riops;
                    }
                    if limits.wiops.is_some() {
                        cur.wiops = limits.wiops;
                    }
                }
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(file, "io.max" | "io.weight")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Decompose a packed `dev` id into `(major, minor)` for display.
/// Mirrors Linux `dev_t` packing: `MAJOR = dev >> 20`,
/// `MINOR = dev & 0xfffff`.
fn split_dev(dev: u64) -> (u64, u64) {
    (dev >> 20, dev & 0xf_ffff)
}

fn render_stat(stats: &BTreeMap<u64, DevStats>) -> String {
    let mut out = String::new();
    for (&dev, s) in stats {
        let (maj, min) = split_dev(dev);
        // `write!` to a String is infallible.
        let _ = writeln!(
            out,
            "{maj}:{min} rbytes={} wbytes={} rios={} wios={}",
            s.rbytes, s.wbytes, s.rios, s.wios
        );
    }
    out
}

fn render_max(limits: &BTreeMap<u64, DevLimits>) -> String {
    let mut out = String::new();
    for (&dev, l) in limits {
        if l.is_empty() {
            continue;
        }
        let (maj, min) = split_dev(dev);
        let _ = write!(out, "{maj}:{min}");
        write_limit(&mut out, "rbps", l.rbps);
        write_limit(&mut out, "wbps", l.wbps);
        write_limit(&mut out, "riops", l.riops);
        write_limit(&mut out, "wiops", l.wiops);
        out.push('\n');
    }
    out
}

/// Render one `key=value` limit field; `None` prints `key=max`.
fn write_limit(out: &mut String, key: &str, v: Option<u64>) {
    match v {
        Some(n) => {
            let _ = write!(out, " {key}={n}");
        }
        None => {
            let _ = write!(out, " {key}=max");
        }
    }
}

// ── Parsing ─────────────────────────────────────────────────────────

/// Parse `MAJ:MIN [rbps=..] [wbps=..] [riops=..] [wiops=..]`.
///
/// Each value is either a `u64` or the literal `max` (→ `None`, clears
/// that field). Unknown keys and malformed numbers are
/// `FsError::InvalidData`.
fn parse_max_line(text: &str) -> Result<(u64, DevLimits), FsError> {
    let mut it = text.split_whitespace();
    let dev = it.next().ok_or(FsError::InvalidData)?;
    let dev = parse_dev(dev)?;

    let mut limits = DevLimits::default();
    for tok in it {
        let (key, val) = tok.split_once('=').ok_or(FsError::InvalidData)?;
        let parsed = parse_limit_val(val)?;
        match key {
            "rbps" => limits.rbps = parsed,
            "wbps" => limits.wbps = parsed,
            "riops" => limits.riops = parsed,
            "wiops" => limits.wiops = parsed,
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok((dev, limits))
}

/// Parse a `MAJ:MIN` pair into the packed `dev` id.
fn parse_dev(s: &str) -> Result<u64, FsError> {
    let (maj, min) = s.split_once(':').ok_or(FsError::InvalidData)?;
    let maj: u64 = maj.parse().map_err(|_| FsError::InvalidData)?;
    let min: u64 = min.parse().map_err(|_| FsError::InvalidData)?;
    if maj > 0xfff || min > 0xf_ffff {
        return Err(FsError::InvalidData);
    }
    Ok((maj << 20) | min)
}

/// Parse a limit value: `"max"` → `None` (clear), else `Some(u64)`.
fn parse_limit_val(val: &str) -> Result<Option<u64>, FsError> {
    if val == "max" {
        Ok(None)
    } else {
        Ok(Some(val.parse::<u64>().map_err(|_| FsError::InvalidData)?))
    }
}

// ── Block-layer hook ────────────────────────────────────────────────

/// Install the `narf-block` accounting hook on first use.
fn install_hook_once() {
    // Acquire-release CAS: exactly one installer wins; others skip.
    if HOOK_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        narf_block::install_cgroup_io_hook(io_charge_hook);
    }
}

/// Block-layer hook: charge `bytes`/one-io to every active `io` state
/// on `pid`'s cgroup chain. Runs in the submitting task's context
/// (synchronous submit prologue), so the chain walk attributes the
/// I/O to the correct cgroup.
fn io_charge_hook(pid: u64, dev: u64, bytes: u64, is_write: bool) {
    super::with_chain_states(pid, "io", |s| {
        if let Some(io) = s.as_any().downcast_ref::<IoState>() {
            io.charge(dev, bytes, is_write);
        }
    });
}
