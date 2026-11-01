//! Bounded, redacted Intel GT first-error diagnostics.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_devcoredump.c::{devcoredump_snapshot,xe_devcoredump},
//! xe_guc_capture.c::COMMON_BASE_ENGINE_INSTANCE and regs/xe_engine_regs.h.
//! This is NARF's small read-only error report, not the Linux devcoredump ABI.
//! Address, instruction, ring-buffer, LRC-body and user-memory dumps are never
//! captured. CPU scalar context facts and a fixed status-register whitelist
//! are retained before reset; report reads never touch the hardware.

use alloc::{string::String, sync::Arc};
use core::fmt::{self, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    intel_gpu_engine::{Engine, EngineSet},
    intel_gpu_gt::GtPlatform,
    intel_gpu_guc_gt::GtState,
};

pub(crate) const MAX_CONTEXTS: usize = 8;
pub(crate) const MAX_CARDS: usize = 64;
pub(crate) const MAX_REPORT_BYTES: usize = 4096;
const GLOBAL: [(&str, u64); 4] = [
    ("guc_status", 0xc000),
    ("guc_dma_control", 0xc314),
    ("gt_reset", 0x941c),
    ("gt_interrupt", 0x190018),
];
// RING_HEAD/TAIL expose only ring-relative offsets. Never export RING_START,
// ACTHD, CURRENT_LRCA, HWS_PGA, BBADDR, DMA_FADD or instruction words.
const ENGINE: [(&str, u64, u32); 6] = [
    ("head_offset", 0x34, 0x001ffffc),
    ("tail_offset", 0x30, 0x001ffff8),
    ("mi_mode", 0x9c, u32::MAX),
    ("esr", 0xb8, u32::MAX),
    ("instdone", 0x6c, u32::MAX),
    ("ctx_timestamp", 0x3a8, u32::MAX),
];
const REGISTERS: usize = 4 + Engine::COUNT * 6;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    Timeout,
    EngineReset,
    Protocol,
    Transport,
    WakeLost,
    Unavailable,
    Boot,
    State,
    Recovery,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ContextPhase {
    Invalidate,
    Invalidating,
    Register,
    Policy,
    Enable,
    Enabling,
    Running,
    Disable,
    Disabling,
    Deregister,
    Deregistering,
    RetireInvalidate,
    RetireInvalidating,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContextInfo {
    pub engine: Engine,
    pub id: u16,
    pub request_stamp: u32,
    pub phase: ContextPhase,
    pub timed_out: bool,
    pub reset: bool,
    /// Most recent watchdog observation, not a claim of a fresh MMIO sample.
    pub observed_runtime_ticks: Option<u32>,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Contexts {
    entries: [Option<ContextInfo>; MAX_CONTEXTS],
    total: usize,
}
impl Contexts {
    pub(crate) fn new(total: usize) -> Self {
        Self {
            entries: [None; MAX_CONTEXTS],
            total,
        }
    }
    pub(crate) fn push(&mut self, context: ContextInfo) {
        if let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(context);
        }
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = &ContextInfo> {
        self.entries.iter().flatten()
    }
    pub(crate) fn total(&self) -> usize {
        self.total
    }
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Capture {
    pub platform: GtPlatform,
    pub reason: Reason,
    pub epoch: u64,
    pub now_ns: u64,
    pub state: GtState,
    pub engines: EngineSet,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RegisterAccess {
    Complete,
    Unavailable,
    Partial,
}

/// Entire capture is fixed-size and allocation-free, suitable for an actual
/// failure path. It contains no references to a live GT or mutable backing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Report {
    generation: u64,
    capture: Capture,
    contexts: Contexts,
    registers: [Option<u32>; REGISTERS],
    access: RegisterAccess,
}
impl Report {
    /// The closure supplies a currently authorized status read under the
    /// caller's D0/wake/reset ownership. None closes capture immediately;
    /// registers captured earlier remain observations, never an atomic GPU
    /// freeze. No retry, wake request, register write or hardware wait occurs.
    pub(crate) fn capture(
        capture: Capture,
        contexts: Contexts,
        mut read: impl FnMut(u64) -> Option<u32>,
    ) -> Self {
        let mut report = Self {
            generation: 0,
            capture,
            contexts,
            registers: [None; REGISTERS],
            access: RegisterAccess::Unavailable,
        };
        if capture.platform.guc().is_none() {
            return report;
        }
        let mut read_count = 0;
        for (index, (_, offset)) in GLOBAL.iter().enumerate() {
            let Some(value) = read(*offset).filter(|value| *value != u32::MAX) else {
                return report;
            };
            report.registers[index] = Some(value);
            read_count += 1;
            report.access = RegisterAccess::Partial;
        }
        for engine in capture.engines.iter() {
            for (index, (_, offset, mask)) in ENGINE.iter().enumerate() {
                let Some(value) =
                    read(u64::from(engine.base()) + offset).filter(|value| *value != u32::MAX)
                else {
                    return report;
                };
                report.registers[4 + engine.index() * 6 + index] = Some(value & mask);
                read_count += 1;
            }
        }
        if read_count == 4 + capture.engines.iter().count() * 6 {
            report.access = RegisterAccess::Complete;
        }
        report
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Copy, Clone)]
struct Slot {
    generation: u64,
    report: Option<Report>,
    suppressed: u64,
}
impl Slot {
    const fn new() -> Self {
        Self {
            generation: 0,
            report: None,
            suppressed: 0,
        }
    }
}
static ERRORS: IrqSafeSpinLock<[Slot; MAX_CARDS]> = IrqSafeSpinLock::new([Slot::new(); MAX_CARDS]);

/// Immutable reader-owned copy. Clearing/reusing the slot cannot alter any
/// existing reader, nor can capture during a partial read splice this body.
#[derive(Debug)]
pub(crate) struct Snapshot {
    pub report: Report,
    pub suppressed: u64,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecordResult {
    Stored(u64),
    Retained(u64),
    OutOfRange,
    Exhausted,
}

/// First error survives recovery/repeated failure until an explicit internal
/// generation-matched clear. No allocations occur while recording a failure.
pub(crate) fn record(index: u32, mut report: Report) -> RecordResult {
    let mut slots = ERRORS.lock();
    let Some(slot) = slots.get_mut(index as usize) else {
        return RecordResult::OutOfRange;
    };
    if slot.report.is_some() {
        slot.suppressed = slot.suppressed.saturating_add(1);
        return RecordResult::Retained(slot.generation);
    }
    let Some(generation) = slot.generation.checked_add(1) else {
        return RecordResult::Exhausted;
    };
    report.generation = generation;
    slot.generation = generation;
    slot.report = Some(report);
    slot.suppressed = 0;
    RecordResult::Stored(generation)
}
pub(crate) fn snapshot(index: u32) -> Option<Arc<Snapshot>> {
    let (report, suppressed) = {
        let slots = ERRORS.lock();
        let slot = slots.get(index as usize)?;
        (slot.report?, slot.suppressed)
    };
    Some(Arc::new(Snapshot { report, suppressed }))
}
/// Reserved for explicit owner lifecycle operations; the sysfs file is
/// read-only and deliberately cannot acknowledge a newer failure by accident.
#[allow(dead_code)]
pub(crate) fn clear(index: u32, generation: u64) -> bool {
    let mut slots = ERRORS.lock();
    let Some(slot) = slots.get_mut(index as usize) else {
        return false;
    };
    if slot.report.is_none() || slot.generation != generation {
        return false;
    }
    slot.report = None;
    slot.suppressed = 0;
    true
}

struct Text {
    data: String,
    full: bool,
}
impl Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.full || self.data.len() + text.len() > MAX_REPORT_BYTES - 32 {
            self.full = true;
            return Err(fmt::Error);
        }
        self.data.push_str(text);
        Ok(())
    }
}
fn engine_name(engine: Engine) -> &'static str {
    match engine {
        Engine::Rcs0 => "rcs0",
        Engine::Bcs0 => "bcs0",
        Engine::Bcs8 => "bcs8",
        Engine::Ccs0 => "ccs0",
        Engine::Ccs1 => "ccs1",
        Engine::Ccs2 => "ccs2",
        Engine::Ccs3 => "ccs3",
    }
}
impl Snapshot {
    pub(crate) fn text(&self) -> String {
        let report = &self.report;
        let capture = report.capture;
        let mut out = Text {
            data: String::with_capacity(MAX_REPORT_BYTES),
            full: false,
        };
        let _ = writeln!(out, "narf-intel-error-v1\ngeneration={}\nreason={:?}\nepoch={}\nmonotonic_ns={}\nplatform={:?}\ngt_state={:?}\nregister_access={:?}\nsuppressed_errors={}",
            report.generation(), capture.reason, capture.epoch, capture.now_ns, capture.platform,
            capture.state, report.access, self.suppressed);
        let retained = report.contexts.entries().count();
        let _ = writeln!(
            out,
            "contexts={}\ncontexts_truncated={}",
            retained,
            report.contexts.total().saturating_sub(retained)
        );
        for context in report.contexts.entries() {
            let _ = write!(
                out,
                "context {} id={} request={} phase={:?} timed_out={} reset={} runtime_ticks=",
                engine_name(context.engine),
                context.id,
                context.request_stamp,
                context.phase,
                u8::from(context.timed_out),
                u8::from(context.reset)
            );
            if let Some(ticks) = context.observed_runtime_ticks {
                let _ = writeln!(out, "{ticks}");
            } else {
                let _ = writeln!(out, "unavailable");
            }
        }
        for (index, (name, _)) in GLOBAL.iter().enumerate() {
            if let Some(value) = report.registers[index] {
                let _ = writeln!(out, "{name}=0x{value:08x}");
            } else {
                let _ = writeln!(out, "{name}=unavailable");
            }
        }
        for engine in capture.engines.iter() {
            for (index, (name, _, _)) in ENGINE.iter().enumerate() {
                if let Some(value) = report.registers[4 + engine.index() * 6 + index] {
                    let _ = writeln!(out, "{}.{}=0x{value:08x}", engine_name(engine), name);
                } else {
                    let _ = writeln!(out, "{}.{}=unavailable", engine_name(engine), name);
                }
            }
        }
        if out.full {
            out.data.push_str("\noutput_truncated=1\n");
        }
        out.data
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn read(&self, offset: u64, output: &mut [u8]) -> usize {
        let text = self.text();
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        let Some(rest) = text.as_bytes().get(start..) else {
            return 0;
        };
        let bytes = rest.len().min(output.len());
        output[..bytes].copy_from_slice(&rest[..bytes]);
        bytes
    }
}
pub(crate) fn show(index: u32) -> String {
    snapshot(index).map_or_else(
        || String::from("narf-intel-error-v1\nstate=none\n"),
        |report| report.text(),
    )
}
pub(crate) fn populate_card(index: u32, node: &narf_filesystem::sysfs::Kobject) {
    narf_filesystem::sysfs::kobject_add_attr(node, "error", move || show(index));
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_error_tests.rs"]
mod tests;
