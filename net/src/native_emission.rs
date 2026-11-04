//! Concrete provider lifetimes for native emission fences. These observations
//! contain no capability and can only deny an otherwise authorized operation.
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    task::Waker,
};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
struct State {
    live: AtomicBool,
    waiters: IrqSafeSpinLock<Vec<Waker>>,
}

/// Owned by the actual registration/socket provider. Cloning shares that
/// same registration; replacing it always creates a different identity.
#[derive(Clone, Debug)]
pub struct ProviderLifetime(Arc<State>);
/// A weak, non-revivable observation. It never keeps its provider alive.
#[derive(Clone, Debug)]
pub struct Lifetime(Weak<State>);
/// Wake only after releasing provider/registry/publication locks. Retiring
/// closes the fence synchronously even when notification has not run yet.
#[must_use = "notify the retained native owner after releasing provider locks"]
pub struct Retirement(Vec<Waker>);
impl core::fmt::Debug for Retirement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Retirement")
            .field("wake_count", &self.0.len())
            .finish()
    }
}
impl Retirement {
    pub fn notify(self) {
        for waker in self.0 {
            waker.wake();
        }
    }
}
impl Default for ProviderLifetime {
    fn default() -> Self {
        Self::new()
    }
}
impl ProviderLifetime {
    pub fn new() -> Self {
        Self(Arc::new(State {
            live: AtomicBool::new(true),
            waiters: IrqSafeSpinLock::new(Vec::new()),
        }))
    }
    pub fn observe(&self) -> Lifetime {
        Lifetime(Arc::downgrade(&self.0))
    }
    /// No virtual/provider callback runs here. The owner must call notify
    /// after releasing its metadata locks, including for removal/last close.
    pub fn retire(&self) -> Retirement {
        self.0.live.store(false, Ordering::Release);
        Retirement(core::mem::take(&mut *self.0.waiters.lock()))
    }
}
impl Lifetime {
    /// Fixed atomic observation only: safe at a native queue publication
    /// boundary. Actual capability invocation remains independently required.
    pub fn current(&self) -> bool {
        self.0
            .upgrade()
            .is_some_and(|state| state.live.load(Ordering::Acquire))
    }
    /// Arm outside the native State/provider locks. The caller must recheck
    /// current after arming and drive terminal cleanup if this returns false.
    /// A source may control several physical interfaces. The bounded list
    /// retains each distinct native owner; exhaustion refuses new watches.
    pub fn watch(&self, waker: Waker) -> bool {
        let Some(state) = self.0.upgrade() else {
            return false;
        };
        {
            let mut waiters = state.waiters.lock();
            if !state.live.load(Ordering::Acquire) {
                return false;
            }
            if !waiters.iter().any(|old| old.will_wake(&waker)) {
                if waiters.len() == 64 {
                    return false;
                }
                waiters.push(waker);
            }
        }
        state.live.load(Ordering::Acquire)
    }
}
