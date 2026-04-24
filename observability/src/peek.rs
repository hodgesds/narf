//! Live-peek API — Stage-4 read-only inspection.
//!
//! Spec: `observability/specification/spec.md` §3.4. A live-peek
//! caller holds `Cap<Diagnostics, Read>` and can sample kernel
//! counters / structures without stopping the kernel. The real
//! implementation enumerates per-subsystem providers (e.g.
//! `scheduler/`'s task list, `rcu/`'s queue depths, `tracing/`'s
//! FnTime aggregates) behind a uniform key/value surface. This
//! Stage-4 structural pass lands the wire shape plus a registry
//! placeholder so every subsystem can register its own provider
//! as it comes online.

use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapError, NoopOp, Read};
use narf_lib::sync::IrqSafeSpinLock;

use crate::Diagnostics;

/// A peek-able metric. Values are u64 for simplicity; Stage-4's
/// second pass will widen the enum to cover strings, byte-ranges,
/// and nested records for rich provider output.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MetricValue {
    U64(u64),
    Bool(bool),
}

/// A named metric reading. `provider` identifies the subsystem
/// (`"scheduler"`, `"rcu"`, ...); `name` is the metric.
#[derive(Clone, Debug)]
pub struct MetricSample {
    pub provider: String,
    pub name:     String,
    pub value:    MetricValue,
}

/// A provider exposes zero or more metrics on demand.
pub trait Provider: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn sample(&self, out: &mut Vec<MetricSample>);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeekError {
    AuthorityRevoked,
    NotRegistered,
}

impl From<CapError> for PeekError {
    fn from(_: CapError) -> Self { PeekError::AuthorityRevoked }
}

type ProviderBox = alloc::boxed::Box<dyn Provider>;

struct Registry { providers: Vec<ProviderBox> }

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry").field("providers", &self.providers.len()).finish()
    }
}

static REG: IrqSafeSpinLock<Option<Registry>> = IrqSafeSpinLock::new(None);

/// Register a provider. Not cap-gated here — providers are always
/// kernel-internal code; the consumer of samples is cap-gated.
pub fn register<P: Provider>(p: P) {
    let mut r = REG.lock();
    let reg = r.get_or_insert_with(|| Registry { providers: Vec::new() });
    reg.providers.push(alloc::boxed::Box::new(p));
}

/// Number of installed providers.
pub fn provider_count() -> usize {
    REG.lock().as_ref().map(|r| r.providers.len()).unwrap_or(0)
}

/// Sample every provider into `out`, cap-gated on
/// `Cap<Diagnostics, Read>`. Replaces `out` with the fresh samples.
pub fn sample_all(cap: &Cap<Diagnostics, Read>, out: &mut Vec<MetricSample>) -> Result<(), PeekError> {
    cap.invoke(NoopOp)?;
    out.clear();
    if let Some(ref r) = *REG.lock() {
        for p in &r.providers {
            p.sample(out);
        }
    }
    Ok(())
}

/// Test helper: wipe the registry so independent kernel_tests don't
/// leak providers across boots.
#[doc(hidden)]
pub fn __test_reset() { *REG.lock() = None; }
