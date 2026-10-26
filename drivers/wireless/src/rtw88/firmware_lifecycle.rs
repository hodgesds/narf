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
    PreparingCalibration8821c,
    Calibration8821cPrepared,
    PreparingOperating8821c,
    Operating8821cPrepared,
    PreparingRadio8821c,
    Radio8821cPrepared,
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
                | Stage::Calibration8821cPrepared
                | Stage::Operating8821cPrepared
                | Stage::Radio8821cPrepared
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
    pub(super) fn device_id(&self) -> u16 {
        self.did
    }
    pub(super) async fn legacy_wmm_request(
        &self,
    ) -> Result<super::station_profile::Request, Error> {
        self.retained
            .lock()
            .await
            .as_ref()
            .ok_or(Error::State)?
            .legacy_wmm_request()
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
        if !matches!(
            self.status().stage,
            Stage::Calibrated | Stage::Radio8821cPrepared
        ) {
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
    pub(super) async fn operating_request8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::operating8821c::Request, Error> {
        self.retained
            .lock()
            .await
            .as_ref()
            .ok_or(Error::State)?
            .operating_request8821c(factory)
    }
    pub(super) async fn operating_info8821c(&self) -> Option<super::operating8821c::Info> {
        self.retained
            .lock()
            .await
            .as_ref()
            .and_then(Owner::operating_info8821c)
    }
    pub(super) async fn prepare_operating8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::operating8821c::Info, Error> {
        self.prepare_operating8821c_with(factory, super::operating8821c::Source::Registered, || {
            narf_wireless::reg::db::get_domain().ok_or(Error::Calibration8821c(
                super::calibration8821c::Error::Policy,
            ))
        })
        .await
    }
    pub(super) async fn prepare_operating8821c_with<F>(
        &self,
        factory: &super::efuse::Factory8821c,
        source: super::operating8821c::Source,
        policy: F,
    ) -> Result<super::operating8821c::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::Calibration8821cPrepared {
            return Err(Error::State);
        }
        let owner = retained.as_mut().ok_or(Error::State)?;
        let envelope = owner.preflight_operating8821c(factory, source, &policy()?)?;
        self.status.lock().stage = Stage::PreparingOperating8821c;
        let _attempt = Attempt(self);
        let result = owner
            .prepare_operating8821c(factory, envelope, policy)
            .await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::Operating8821cPrepared,
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
    pub(super) async fn station_request8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::station_power8821c::Request, Error> {
        self.retained
            .lock()
            .await
            .as_ref()
            .ok_or(Error::State)?
            .station_request8821c(factory)
    }
    pub(super) async fn station_radio_info8821c(&self) -> Option<super::radio8821c::StationInfo> {
        self.retained
            .lock()
            .await
            .as_ref()
            .and_then(Owner::station_radio_info8821c)
    }
    pub(super) async fn prepare_station8821c(
        &self,
        factory: &super::efuse::Factory8821c,
        source: super::station_power8821c::Source,
    ) -> Result<super::radio8821c::StationInfo, Error> {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::Operating8821cPrepared {
            return Err(Error::State);
        }
        let owner = retained.as_mut().ok_or(Error::State)?;
        // Missing, mismatched, revoked or policy-denied qualification is
        // retryable before the first register write or ownership transition.
        let grant = owner.preflight_station8821c(factory, source)?;
        self.status.lock().stage = Stage::PreparingRadio8821c;
        let _attempt = Attempt(self);
        let result = owner.prepare_station8821c(factory, grant).await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::Radio8821cPrepared,
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
    pub(super) async fn calibration_request8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::calibration8821c::Request, Error> {
        self.retained
            .lock()
            .await
            .as_ref()
            .ok_or(Error::State)?
            .calibration_request8821c(factory)
    }
    pub(super) async fn calibration_info8821c(&self) -> Option<super::radio8821c::Info> {
        self.retained
            .lock()
            .await
            .as_ref()
            .and_then(Owner::calibration_info8821c)
    }
    pub(super) async fn prepare_calibration8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::radio8821c::Info, Error> {
        // Bootstrap may run only before admission. A live policy clear never
        // reloads policy from inside an active command/register continuation.
        narf_wireless::reg::db::ensure_domain()
            .map_err(|_| Error::Calibration8821c(super::calibration8821c::Error::Policy))?;
        self.prepare_calibration8821c_with(
            factory,
            super::calibration8821c::Source::Registered,
            || {
                narf_wireless::reg::db::get_domain().ok_or(Error::Calibration8821c(
                    super::calibration8821c::Error::Policy,
                ))
            },
        )
        .await
    }
    pub(super) async fn prepare_calibration8821c_with<F>(
        &self,
        factory: &super::efuse::Factory8821c,
        source: super::calibration8821c::Source,
        policy: F,
    ) -> Result<super::radio8821c::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        let mut retained = self.retained.lock().await;
        if self.status().stage != Stage::PhyTablesPrepared {
            return Err(Error::State);
        }
        let owner = retained.as_mut().ok_or(Error::State)?;
        // Exact immutable data, signer/current source and policy all qualify
        // before the stage changes or any register/command can be published.
        let envelope = owner.preflight_calibration8821c(factory, source, &policy()?)?;
        self.status.lock().stage = Stage::PreparingCalibration8821c;
        let _attempt = Attempt(self);
        let result = owner
            .prepare_calibration8821c(factory, envelope, policy)
            .await;
        let mut status = self.status.lock();
        match result {
            Ok(_) => status.stage = Stage::Calibration8821cPrepared,
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
