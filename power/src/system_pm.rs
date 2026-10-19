//! Async pre/post hooks for system suspend.
//!
//! [`crate::device_pm`] deliberately runs synchronously with interrupts
//! gated, which is the right environment for PCI configuration save/restore
//! but cannot carry an interrupt-driven firmware exchange.  This registry is
//! the preceding/following phase: prepare hooks run while the scheduler and
//! device interrupts still service futures; resume hooks run only after the
//! synchronous device fan-out has restored them.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use narf_lib::sync::IrqSafeSpinLock;

use crate::device_pm::DevicePmError;

/// Object-safe future returned by an asynchronous system-PM driver hook.
pub type SystemPmFuture<'a> = Pin<Box<dyn Future<Output = Result<(), DevicePmError>> + Send + 'a>>;

/// A driver phase that must run outside the interrupt-gated
/// [`crate::device_pm::DevicePmOps`] fan-out.
///
/// Registration order follows [`crate::device_pm`]: parents register before
/// children.  Preparation runs in reverse order and resume runs forward.
/// A failing `prepare` must leave its own device usable; the coordinator
/// resumes every earlier successful hook before returning to the caller.
pub trait AsyncSystemPm: Send + Sync {
    /// Complete asynchronous protocol/firmware work before synchronous
    /// device quiesce gates the corresponding interrupt sources.
    fn prepare_suspend<'a>(&'a self) -> SystemPmFuture<'a>;
    /// Undo [`Self::prepare_suspend`] after synchronous device resume has
    /// restored the transport and its interrupt sources.
    fn resume_from_suspend<'a>(&'a self) -> SystemPmFuture<'a>;
}

#[derive(Clone)]
struct Entry {
    name: String,
    ops: Arc<dyn AsyncSystemPm>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncSystemPmEntry")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Register or replace a named asynchronous system-PM hook.  Replacing by
/// name makes driver re-probe idempotent without perturbing parent/child
/// ordering.
pub fn register_async_system_pm(name: &str, ops: Arc<dyn AsyncSystemPm>) {
    let mut registry = REGISTRY.lock();
    let entry = Entry {
        name: String::from(name),
        ops,
    };
    if let Some(slot) = registry.iter_mut().find(|slot| slot.name == name) {
        *slot = entry;
    } else {
        registry.push(entry);
    }
}

/// Number of registered asynchronous system-PM hooks.
pub fn async_system_pm_count() -> usize {
    REGISTRY.lock().len()
}

/// A failed prepare hook, retained for diagnostics after the successful
/// preceding hooks have been unwound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncPrepareFailure {
    pub name: String,
    pub error: DevicePmError,
}

/// The successfully prepared portion of a system-PM transition.  It is kept
/// by the suspend coordinator across the synchronous platform phase so its
/// exact paired resume order cannot be confused with a later registration.
#[derive(Debug)]
pub struct AsyncSystemPmTransition {
    // Stored in the order preparation ran: leaf → root.  Resume reverses it
    // to restore root → leaf.
    prepared: Vec<Entry>,
    failure: Option<AsyncPrepareFailure>,
}

impl AsyncSystemPmTransition {
    /// Whether every registered asynchronous prepare hook completed.
    pub fn succeeded(&self) -> bool {
        self.failure.is_none()
    }

    /// The first failed prepare, if any.
    pub fn failure(&self) -> Option<&AsyncPrepareFailure> {
        self.failure.as_ref()
    }

    /// Resume exactly the hooks whose prepare completed.  It is best-effort:
    /// all hooks receive their paired resume even if an earlier one fails.
    pub async fn resume(&self) -> Vec<AsyncPrepareFailure> {
        let mut failures = Vec::new();
        for entry in self.prepared.iter().rev() {
            if let Err(error) = entry.ops.resume_from_suspend().await {
                failures.push(AsyncPrepareFailure {
                    name: entry.name.clone(),
                    error,
                });
            }
        }
        failures
    }
}

/// Run asynchronous system-PM preparation in reverse registration order.
/// The registry lock is released before every await.  Call
/// [`AsyncSystemPmTransition::resume`] even when this returns a failed
/// transition so all earlier hooks are rolled back.
pub async fn prepare_async_system_pm() -> AsyncSystemPmTransition {
    let snapshot = REGISTRY.lock().clone();
    let mut prepared = Vec::with_capacity(snapshot.len());
    for entry in snapshot.iter().rev() {
        match entry.ops.prepare_suspend().await {
            Ok(()) => prepared.push(entry.clone()),
            Err(error) => {
                return AsyncSystemPmTransition {
                    prepared,
                    failure: Some(AsyncPrepareFailure {
                        name: entry.name.clone(),
                        error,
                    }),
                };
            }
        }
    }
    AsyncSystemPmTransition {
        prepared,
        failure: None,
    }
}

/// Test-only registry reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}
