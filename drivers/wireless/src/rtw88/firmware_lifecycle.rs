//! Retain the exact native firmware owner before its first device publication.
use super::firmware_transport::{Error, Info, Io, Owner};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Detected,
    Allocating,
    Loading,
    Ready,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub stage: Stage,
    pub info: Option<Info>,
    pub error: Option<Error>,
}
pub(super) struct Lifecycle<I: Io> {
    started: AtomicBool,
    retained: Mutex<Option<Owner<I>>>,
    status: IrqSafeSpinLock<Status>,
    did: u16,
}
impl<I: Io> core::fmt::Debug for Lifecycle<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88FirmwareLifecycle")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}
enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Bytes(alloc::vec::Vec<u8>),
}
struct Attempt<'a, I: Io>(&'a Lifecycle<I>);
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        let mut status = self.0.status.lock();
        if !matches!(status.stage, Stage::Ready | Stage::Failed) {
            *status = Status {
                stage: Stage::Failed,
                info: None,
                error: Some(Error::Cancelled),
            };
        }
    }
}
impl<I: Io> Lifecycle<I> {
    pub(super) fn new(did: u16) -> Self {
        Self {
            started: AtomicBool::new(false),
            retained: Mutex::new(None),
            status: IrqSafeSpinLock::new(Status {
                stage: Stage::Detected,
                info: None,
                error: None,
            }),
            did,
        }
    }
    pub(super) fn status(&self) -> Status {
        *self.status.lock()
    }
    pub(super) async fn initialize_registered(
        &self,
        allocate: impl FnOnce() -> Result<I, Error> + Send,
    ) -> Result<Info, Error> {
        self.initialize(allocate, Source::Registered).await
    }
    async fn initialize(
        &self,
        allocate: impl FnOnce() -> Result<I, Error> + Send,
        source: Source,
    ) -> Result<Info, Error> {
        self.started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::State)?;
        *self.status.lock() = Status {
            stage: Stage::Allocating,
            info: None,
            error: None,
        };
        let _attempt = Attempt(self);
        let result = async {
            let owner = Owner::new(allocate()?, self.did);
            let mut retained = self.retained.lock().await;
            if retained.is_some() {
                return Err(Error::State);
            }
            *retained = Some(owner); // before registry/MMIO/DMA claim can run
            *self.status.lock() = Status {
                stage: Stage::Loading,
                info: None,
                error: None,
            };
            let owner = retained.as_mut().ok_or(Error::State)?;
            match source {
                Source::Registered => owner.initialize_registered().await,
                #[cfg(any(test, feature = "kernel-test"))]
                Source::Bytes(bytes) => owner.download(&bytes).await,
            }
        }
        .await;
        *self.status.lock() = match result {
            Ok(info) => Status {
                stage: Stage::Ready,
                info: Some(info),
                error: None,
            },
            Err(error) => Status {
                stage: Stage::Failed,
                info: None,
                error: Some(error),
            },
        };
        result
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_lifecycle_tests.rs"]
mod tests;
