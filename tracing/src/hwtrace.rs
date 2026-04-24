//! Hardware trace integration — Intel PT + ARM CoreSight ETM.
//!
//! Spec: `tracing/specification/spec.md` (Stage-4 HW trace
//! integration). Both platforms expose CPU-driven execution-trace
//! recording — Intel Processor Trace (PT) on x86_64 and CoreSight
//! Embedded Trace Macrocell (ETM) on aarch64. The kernel's job is
//! small and similar on both:
//!
//! - Allocate a per-CPU trace buffer (large, contiguous,
//!   DMA-addressable).
//! - Program the CPU's trace-config MSRs / CoreSight registers.
//! - Expose a cap-gated enable/disable surface.
//!
//! What lands here: the shared configuration + status shapes so
//! both platforms agree on what a "trace session" looks like. The
//! arch-specific MSR pokes live behind `arch/` primitives
//! (`arch::x86_64::ipt::configure`, `arch::aarch64::etm::configure`)
//! that don't yet exist; `start`/`stop` return
//! `HwTraceError::NotImplemented` until they do.

use narf_capabilities::{Cap, CapError, CapKind, CapType, Invoke, NoopOp};

/// Cap-type marker for the HW-trace control surface.
/// `Cap<HwTraceMarker, Invoke>` authorises `start` / `stop` /
/// `capture` — different from the existing
/// `observability::Debugger` cap so operators can enable HW trace
/// without granting GDB-stub authority.
#[derive(Copy, Clone, Debug)]
pub struct HwTraceMarker;

impl CapType for HwTraceMarker {
    const KIND: CapKind = CapKind::HwTrace;
}

/// Trace-session configuration. Shared between Intel PT and
/// CoreSight ETM — the fields map onto each platform's register
/// subset in the per-arch backend.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HwTraceConfig {
    /// Physical ring-buffer backing the trace output. 0 = driver
    /// supplies its own.
    pub buffer_phys:    u64,
    pub buffer_size:    u64,
    /// Trace this CPU only (`None` = every online CPU).
    pub cpu_filter:     Option<u32>,
    /// Record user-ring execution (CPL=3 / EL0).
    pub trace_user:     bool,
    /// Record kernel-ring execution (CPL=0 / EL1).
    pub trace_kernel:   bool,
    /// Record indirect branches.
    pub trace_indirect: bool,
    /// Record timestamp packets at `timestamp_period` cycles.
    pub timestamp_period: u16,
}

impl Default for HwTraceConfig {
    fn default() -> Self {
        Self {
            buffer_phys: 0, buffer_size: 0,
            cpu_filter: None,
            trace_user: true, trace_kernel: true, trace_indirect: true,
            timestamp_period: 1024,
        }
    }
}

/// Session status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwTraceStatus {
    Idle,
    Running,
    Overflow,
    Error,
}

/// Errors from the HW-trace surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwTraceError {
    AuthorityRevoked,
    NotImplemented,
    InvalidBuffer,
}

impl From<CapError> for HwTraceError {
    fn from(_: CapError) -> Self { HwTraceError::AuthorityRevoked }
}

/// Start a new trace session. Returns `NotImplemented` until `arch/`
/// exposes the Intel PT / CoreSight ETM programming primitives.
pub fn start(
    cap: &Cap<HwTraceMarker, Invoke>,
    cfg: &HwTraceConfig,
) -> Result<(), HwTraceError> {
    cap.invoke(NoopOp)?;
    if cfg.buffer_size != 0 && cfg.buffer_phys == 0 {
        return Err(HwTraceError::InvalidBuffer);
    }
    Err(HwTraceError::NotImplemented)
}

/// Stop an active trace session.
pub fn stop(cap: &Cap<HwTraceMarker, Invoke>) -> Result<(), HwTraceError> {
    cap.invoke(NoopOp)?;
    Err(HwTraceError::NotImplemented)
}

/// Query the current session's status.
pub fn status(cap: &Cap<HwTraceMarker, Invoke>) -> Result<HwTraceStatus, HwTraceError> {
    cap.invoke(NoopOp)?;
    Ok(HwTraceStatus::Idle)
}
