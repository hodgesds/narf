//! Retain the exact native firmware owner before its first device publication.
use super::firmware_transport::{Error, Info, Io, Owner};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Detected,
    Allocating,
    Loading,
    Ready,
    PreparingMac,
    MacPrepared,
    PreparingPhy,
    PhyTablesPrepared,
    Calibrating,
    Calibrated,
    StationPreparation,
    StationReady,
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
    pub(super) retained: Mutex<Option<Owner<I>>>,
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
    Prepared(super::firmware_transport::PreparedImage),
    #[cfg(any(test, feature = "kernel-test"))]
    Bytes(alloc::vec::Vec<u8>),
}
struct Attempt<'a, I: Io>(&'a Lifecycle<I>);
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        let mut status = self.0.status.lock();
        if !matches!(
            status.stage,
            Stage::Ready
                | Stage::MacPrepared
                | Stage::PhyTablesPrepared
                | Stage::Calibrated
                | Stage::StationReady
                | Stage::Failed
        ) {
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
        self.initialize_registered_with(allocate, || {
            super::firmware_transport::registered_image(self.did)
        })
        .await
    }
    async fn initialize_registered_with(
        &self,
        allocate: impl FnOnce() -> Result<I, Error> + Send,
        load: impl FnOnce() -> Result<super::firmware_transport::PreparedImage, Error> + Send,
    ) -> Result<Info, Error> {
        if self.started.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        let image = match load() {
            Ok(image) => image,
            Err(error) => {
                let mut status = self.status.lock();
                if !self.started.load(Ordering::Acquire) && status.stage == Stage::Detected {
                    status.error = Some(error);
                }
                return Err(error);
            }
        };
        self.initialize(allocate, Source::Prepared(image)).await
    }
    pub(super) async fn start_station(
        &self,
        environment: Arc<dyn super::station::Environment>,
        admission: super::station_control::Admission,
    ) -> Result<(), super::station::Error> {
        admission.check()?;
        let mut retained = self.retained.lock().await;
        admission.check()?;
        if self.status().stage != Stage::Calibrated {
            return Err(super::station::Error::State);
        }
        self.status.lock().stage = Stage::StationPreparation;
        let _attempt = Attempt(self);
        let result = retained
            .as_mut()
            .ok_or(super::station::Error::State)?
            .start_station(environment, admission)
            .await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::StationReady,
            Err(_) => {
                *status = Status {
                    stage: Stage::Failed,
                    info: None,
                    error: Some(Error::Prerequisite),
                }
            }
        }
        result.map(|_| ())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn initialize_bytes(
        &self,
        allocate: impl FnOnce() -> Result<I, Error> + Send,
        bytes: alloc::vec::Vec<u8>,
    ) -> Result<Info, Error> {
        self.initialize(allocate, Source::Bytes(bytes)).await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn qualify_board_with_source(
        &self,
        factory: &super::efuse::Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        source: super::power_policy::Source,
    ) -> Result<super::power_policy::Permission, Error> {
        if self.status().stage != Stage::PhyTablesPrepared {
            return Err(Error::State);
        }
        self.retained
            .lock()
            .await
            .as_mut()
            .ok_or(Error::State)?
            .qualify_with(factory, domain, source)
    }
    pub(super) async fn prepare_radio_with_policy<F>(
        &self,
        factory: &super::efuse::Factory,
        permission: super::power_policy::Permission,
        policy: F,
    ) -> Result<super::radio::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::PhyTablesPrepared {
            return Err(Error::State);
        }
        let owner = retained.as_mut().ok_or(Error::State)?;
        // Complete pure current-policy/board/permission validation before the
        // one-shot calibration attempt or any hardware register transition.
        let plan = owner.preflight_radio(factory, permission, &policy()?)?;
        self.status.lock().stage = Stage::Calibrating;
        let _attempt = Attempt(self);
        let result = owner.prepare_radio_prepared(factory, plan, policy).await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::Calibrated,
            Err(error) => {
                *status = Status {
                    stage: Stage::Failed,
                    info: None,
                    error: Some(error),
                }
            }
        }
        result
    }
    pub(super) async fn prepare_mac(&self) -> Result<super::mac::Info, Error> {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::Ready {
            return Err(Error::State);
        }
        self.status.lock().stage = Stage::PreparingMac;
        let _attempt = Attempt(self);
        let owner = retained.as_mut().ok_or(Error::State)?;
        let result = owner.prepare_mac().await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::MacPrepared,
            Err(error) => {
                *status = Status {
                    stage: Stage::Failed,
                    info: None,
                    error: Some(error),
                }
            }
        }
        result
    }
    pub(super) async fn prepare_phy_tables(
        &self,
        factory: &super::efuse::Factory,
    ) -> Result<super::phy::Info, Error> {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::MacPrepared {
            return Err(Error::State);
        }
        self.status.lock().stage = Stage::PreparingPhy;
        let _attempt = Attempt(self);
        let owner = retained.as_mut().ok_or(Error::State)?;
        let result = owner.prepare_phy_tables(factory).await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::PhyTablesPrepared,
            Err(error) => {
                *status = Status {
                    stage: Stage::Failed,
                    info: None,
                    error: Some(error),
                }
            }
        }
        result
    }
    pub(super) async fn prepare_phy8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::phy8821c::Info, Error> {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::MacPrepared {
            return Err(Error::State);
        }
        self.status.lock().stage = Stage::PreparingPhy;
        let _attempt = Attempt(self);
        let owner = retained.as_mut().ok_or(Error::State)?;
        let result = owner.prepare_phy8821c(factory).await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::PhyTablesPrepared,
            Err(error) => {
                *status = Status {
                    stage: Stage::Failed,
                    info: None,
                    error: Some(error),
                }
            }
        }
        result
    }
    pub(super) async fn qualify_board(
        &self,
        factory: &super::efuse::Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<super::power_policy::Permission, Error> {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::PhyTablesPrepared {
            return Err(Error::State);
        }
        retained
            .as_mut()
            .ok_or(Error::State)?
            .qualify_board(factory, domain)
    }
    pub(super) async fn prepare_radio(
        &self,
        factory: &super::efuse::Factory,
        permission: super::power_policy::Permission,
    ) -> Result<super::radio::Info, Error> {
        self.prepare_radio_with_policy(factory, permission, || {
            narf_wireless::reg::db::ensure_domain()
                .map_err(|_| Error::Power(super::power_policy::Error::Policy))
        })
        .await
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
                Source::Prepared(image) => owner.initialize_prepared(image).await,
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
