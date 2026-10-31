//! Private periodic-scan publication ordering; no firmware or RF authority.
use narf_lib::sync::IrqSafeSpinLock;

pub(super) struct Epoch(IrqSafeSpinLock<u64>);
impl Epoch {
    pub fn new() -> Self {
        Self(IrqSafeSpinLock::new(0))
    }
    /// Reserve a start and its mandatory later retirement without wrapping.
    pub fn begin(&self) -> Result<u64, &'static str> {
        let mut epoch = self.0.lock();
        epoch
            .checked_add(2)
            .ok_or("Intel scheduled generation exhausted")?;
        *epoch += 1;
        Ok(*epoch)
    }
    pub fn retire(&self) -> Result<u64, &'static str> {
        let mut epoch = self.0.lock();
        *epoch = epoch
            .checked_add(1)
            .ok_or("Intel scheduled retirement exhausted")?;
        Ok(*epoch)
    }
    /// Linearize the entire synchronous cache/event callback with native
    /// retirement and successor START. The callback runs outside native
    /// state/control locks, never awaits, and may inspect only the existing
    /// current-source/registry/atomic interface identity. It must not reenter
    /// native control. Epoch advancement never calls any external code.
    pub fn publish<T>(
        &self,
        expected: u64,
        callback: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let epoch = self.0.lock();
        if *epoch != expected {
            return Err("Intel scheduled copied publication retired");
        }
        let result = callback();
        drop(epoch);
        result
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn publication_locked(&self) -> bool {
        self.0.try_lock().is_none()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) struct Audit {
    epoch: alloc::sync::Arc<Epoch>,
    owner_unlocked: alloc::boxed::Box<dyn Fn() -> bool + Send + Sync>,
    calls: core::sync::atomic::AtomicU64,
    failed: core::sync::atomic::AtomicBool,
}
#[cfg(any(test, feature = "kernel-test"))]
impl Audit {
    pub fn new(
        epoch: alloc::sync::Arc<Epoch>,
        owner_unlocked: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            epoch,
            owner_unlocked: alloc::boxed::Box::new(owner_unlocked),
            calls: core::sync::atomic::AtomicU64::new(0),
            failed: core::sync::atomic::AtomicBool::new(false),
        }
    }
    /// Called by the fixture's actual shared control-source check, including
    /// the check made with the GET_SCAN cache locked. No production hook.
    pub fn observe(&self) {
        use core::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::AcqRel);
        if !self.epoch.publication_locked() || !(self.owner_unlocked)() {
            self.failed.store(true, Ordering::Release);
        }
    }
    pub fn calls(&self) -> u64 {
        self.calls.load(core::sync::atomic::Ordering::Acquire)
    }
    pub fn valid(&self) -> bool {
        !self.failed.load(core::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
impl core::fmt::Debug for Audit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScheduledPublicationAudit")
            .field("calls", &self.calls())
            .field("valid", &self.valid())
            .finish()
    }
}
