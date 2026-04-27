//! Typed driver-parameter surface.
//!
//! NARF's answer to Linux's sysfs: a cap-gated **typed** read/write
//! channel into a driver's tunables. Each driver picks a `Snapshot`
//! type for read-side observability and an `Update` type for the
//! parameters callers can change. Both are plain Rust structs — no
//! string parsing, no path namespace, no implicit "uid+path" gating.
//!
//! Authority is `Cap<DriverHandle, Write>` (the per-driver handle
//! returned by `DriverRegistry::register`). Stage-3 collapses the
//! Read/Write split into a single cap because the rights-system's
//! `SubsetOf` bound only derives into `Grant` today; a follow-up can
//! introduce a true read-only path once `SubsetOf<Write> for Read`
//! lands.

use core::marker::PhantomData;

use narf_capabilities::{Cap, CapError, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::DriverHandle;

/// What can go wrong reading or writing a parameter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParamError {
    /// `Cap<DriverHandle, Write>` was revoked since it was minted.
    AuthorityRevoked,
    /// Driver hasn't installed its parameter slot yet (probe didn't
    /// run, or this slot is for a not-yet-bound driver).
    NotInstalled,
    /// `Update` carried a value the driver rejected (out-of-range,
    /// not a power of two, beyond the device's reported capability).
    OutOfRange,
    /// The requested change can't apply right now (e.g. queue depth
    /// while I/O is outstanding). Retry once the driver quiesces.
    Busy,
    /// The driver doesn't expose this parameter (used when a single
    /// `Update` enum has variants only some drivers handle).
    Unsupported,
}

impl From<CapError> for ParamError {
    fn from(_: CapError) -> Self { ParamError::AuthorityRevoked }
}

/// A driver's typed parameter contract. Implementors define what
/// readers see (`Snapshot`) and what writers can change (`Update`).
///
/// Both types must be `Copy + Send + Sync + 'static` so they can
/// cross IPC boundaries without lifetime gymnastics.
pub trait DriverParams: Send + Sync + 'static {
    /// Read-side view. A driver typically derives `Debug` here and
    /// returns the latest counters / config snapshot.
    type Snapshot: Copy + Send + Sync + 'static;
    /// Write-side request. An enum is the conventional shape — one
    /// variant per knob — so callers don't have to write every field
    /// when they only want to twiddle one.
    type Update:   Copy + Send + Sync + 'static;

    /// Take a fresh snapshot. Called under the slot's lock.
    fn snapshot(&self) -> Self::Snapshot;

    /// Apply an update. Called under the slot's lock with `&mut self`.
    fn apply(&mut self, update: Self::Update) -> Result<(), ParamError>;
}

/// Per-driver storage for a typed `DriverParams` instance.
///
/// Drivers declare a `static NAME: ParamSlot<Foo> = ParamSlot::new();`
/// at module scope and call `NAME.install(...)` from their probe.
/// Readers / writers then go through `NAME.read(&cap)` /
/// `NAME.write(&cap, update)`.
pub struct ParamSlot<T: DriverParams> {
    inner: IrqSafeSpinLock<Option<T>>,
    _t:    PhantomData<fn() -> T>,
}

impl<T: DriverParams> ParamSlot<T> {
    /// Construct an empty slot. `const`-friendly so a driver can
    /// declare it as a `static`.
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(None),
            _t:    PhantomData,
        }
    }

    /// Install the live params instance. Replaces any previous
    /// installation — drivers typically call this once at probe
    /// time. The previous value (if any) is dropped under the lock.
    pub fn install(&self, t: T) {
        *self.inner.lock() = Some(t);
    }

    /// Take a typed snapshot. Cap-gated.
    pub fn read(
        &self,
        cap: &Cap<DriverHandle, Write>,
    ) -> Result<T::Snapshot, ParamError> {
        cap.check_live()?;
        let g = self.inner.lock();
        let p = g.as_ref().ok_or(ParamError::NotInstalled)?;
        Ok(p.snapshot())
    }

    /// Apply a typed update. Cap-gated. The driver's `apply` body
    /// runs under the slot lock; for fast updates that's fine, for
    /// long-running reconfigurations the driver can take a
    /// short critical section and post the actual work to its
    /// scheduler task.
    pub fn write(
        &self,
        cap:    &Cap<DriverHandle, Write>,
        update: T::Update,
    ) -> Result<(), ParamError> {
        cap.check_live()?;
        let mut g = self.inner.lock();
        let p = g.as_mut().ok_or(ParamError::NotInstalled)?;
        p.apply(update)
    }

    /// `true` once `install` has populated the slot.
    pub fn is_installed(&self) -> bool { self.inner.lock().is_some() }

    /// Drop the installed instance without any cap check. Test-only
    /// reset path that lets the kernel-test harness re-install the
    /// slot between smokes.
    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        *self.inner.lock() = None;
    }
}

impl<T: DriverParams> core::fmt::Debug for ParamSlot<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParamSlot")
            .field("installed", &self.is_installed())
            .finish_non_exhaustive()
    }
}
