//! Dynamic probe dispatch.
//!
//! Spec: `tracing/specification/spec.md` §3.2. Armed probe sites
//! invoke `fire(probe_id, args)` which looks up a registered handler
//! and dispatches. No handler → no-op. The lookup is a bounded-size
//! `probe_id → handler` table: probe IDs are stable `u32`s assigned
//! at register time.
//!
//! Stage-3 scope:
//! - Linear-scan handler table (N ≤ 256) under a single `IrqSafeSpinLock`.
//!   Stage 4 swaps in a per-probe-id slot array backed by `rcu/`'s
//!   hazard pointers so the hot path is wait-free.
//! - Up to 4 u64 args per fire — matches the `abi/` Submission inline
//!   slot width and covers every built-in probe site. Variadic
//!   arg-lists are Stage 4.
//! - Handlers run in the firing task's context; re-entrancy is the
//!   caller's concern. A handler that itself fires a probe will
//!   currently recurse through the same dispatcher; Stage 4 adds a
//!   per-CPU "in-dispatch" bit to short-circuit.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for the dynamic-probe installation surface.
/// Distinct from `ProbeArming` (the patch-word gate) — arming flips
/// the site's enable bit; *registering a handler* for a probe_id is
/// the separate authority gated here.
#[derive(Debug)]
pub struct ProbeHandlerInstall;
impl CapType for ProbeHandlerInstall {
    const KIND: CapKind = CapKind::Probe;
}

/// Monotonic source of probe IDs. `0` is reserved as "unassigned".
static NEXT_PROBE_ID: AtomicU32 = AtomicU32::new(1);

/// Reserve a fresh probe ID. Every compiled probe site calls this
/// once at first fire (lazy assignment) so the ID is stable across
/// the life of the kernel.
#[inline]
pub fn reserve_probe_id() -> u32 {
    NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Handler trait. Kept narrow: four `u64` args cover every
/// currently-spec'd probe shape.
pub trait ProbeHandler: Send + Sync + 'static {
    fn fire(&self, args: ProbeArgs);
}

/// Four-u64 argument bundle. Unused slots are `0`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeArgs(pub [u64; 4]);

impl ProbeArgs {
    #[inline]
    pub const fn none() -> Self {
        Self([0; 4])
    }
    #[inline]
    pub const fn one(a: u64) -> Self {
        Self([a, 0, 0, 0])
    }
    #[inline]
    pub const fn two(a: u64, b: u64) -> Self {
        Self([a, b, 0, 0])
    }
}

struct Entry {
    probe_id: u32,
    handler: Box<dyn ProbeHandler>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("probe_id", &self.probe_id)
            .finish_non_exhaustive()
    }
}

/// Bound on concurrently-installed handlers. Stage 4 removes when the
/// hazard-pointer-backed table lands.
const MAX_HANDLERS: usize = 256;

#[derive(Debug)]
pub struct HandlerTable {
    inner: IrqSafeSpinLock<Vec<Entry>>,
}

static TABLE: HandlerTable = HandlerTable {
    inner: IrqSafeSpinLock::new(Vec::new()),
};

#[inline]
pub fn table() -> &'static HandlerTable {
    &TABLE
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegisterError {
    AuthorityRevoked,
    DuplicateProbeId,
    TableFull,
}

impl From<CapError> for RegisterError {
    fn from(_: CapError) -> Self {
        RegisterError::AuthorityRevoked
    }
}

impl HandlerTable {
    /// Install a handler for `probe_id`. Cap-gated.
    pub fn register<H: ProbeHandler + 'static>(
        &self,
        cap: &Cap<ProbeHandlerInstall, Grant>,
        probe_id: u32,
        handler: H,
    ) -> Result<(), RegisterError> {
        cap.check_live()?;
        let mut q = self.inner.lock();
        if q.iter().any(|e| e.probe_id == probe_id) {
            return Err(RegisterError::DuplicateProbeId);
        }
        if q.len() >= MAX_HANDLERS {
            return Err(RegisterError::TableFull);
        }
        q.push(Entry {
            probe_id,
            handler: Box::new(handler),
        });
        Ok(())
    }

    /// Remove the handler for `probe_id` (no-op if not installed).
    pub fn unregister(
        &self,
        cap: &Cap<ProbeHandlerInstall, Grant>,
        probe_id: u32,
    ) -> Result<(), CapError> {
        cap.check_live()?;
        let mut q = self.inner.lock();
        q.retain(|e| e.probe_id != probe_id);
        Ok(())
    }

    /// Handler count.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

/// Fire a probe. No-op if no handler installed for `probe_id`.
/// Called from armed probe sites and from tests.
#[inline]
pub fn fire(probe_id: u32, args: ProbeArgs) {
    // Take a short-lived reference to the handler by first locking,
    // cloning the Box pointer via a trait-object reference, and
    // releasing the lock before invoking — so a handler that blocks
    // doesn't hold the registry lock. Each Entry.handler is behind a
    // Box<dyn _>; we invoke through the trait pointer directly while
    // the lock is held in Stage 3 (handler must be non-blocking).
    // Stage 4 replaces with a hazard-pointer-backed lookup that drops
    // the lock before the call.
    let q = TABLE.inner.lock();
    if let Some(e) = q.iter().find(|e| e.probe_id == probe_id) {
        e.handler.fire(args);
    }
}
