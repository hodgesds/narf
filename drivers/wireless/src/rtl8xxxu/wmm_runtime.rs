//! RTL8188EU WMM admission: source conf_tx/set_aifs, fixed BE/TID0 only.
use super::{
    device_init::Factory,
    power_policy::{Calibration, Permission},
    receive_runtime::Error,
};
use alloc::sync::Arc;
use core::{future::Future, task::Poll};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareBlob;
#[cfg(any(test, feature = "kernel-test"))]
use narf_wireless::reg::RegulatoryDomain;
use narf_wireless::wmm::Parameters;

pub(super) fn words(p: Parameters, short: bool) -> Result<[u32; 4], Error> {
    words_profile(p, short, false)
}
pub(super) fn words_profile(p: Parameters, short: bool, ht: bool) -> Result<[u32; 4], Error> {
    if p.ac[0].admission_control
        || p.ac.iter().any(|a| {
            a.ecw_min == 0
                || a.ecw_min > 15
                || a.ecw_max > 15
                || a.ecw_min > a.ecw_max
                || a.aifsn < 2
                || a.aifsn > 15
        })
    {
        return Err(Error::State);
    }
    let mut result = [0; 4];
    for (i, a) in p.ac.iter().enumerate() {
        let aifs = u32::from(if i == 0 { a.aifsn.max(3) } else { a.aifsn })
            * if short { 9 } else { 20 }
            + if ht { 16 } else { 10 };
        if aifs > 255 {
            return Err(Error::State);
        }
        result[i] = u32::from(if i == 0 { 0 } else { a.txop }) << 16
            | u32::from(if i == 0 { a.ecw_max.max(10) } else { a.ecw_max }) << 12
            | u32::from(if i == 0 { a.ecw_min.max(5) } else { a.ecw_min }) << 8
            | aifs;
    }
    Ok(result)
}
pub(super) struct Proof {
    calibration: Calibration,
    permission: Permission,
    cap: Cap<FirmwareBlob, Read>,
    country: [u8; 2],
    #[cfg(any(test, feature = "kernel-test"))]
    model: Option<Arc<narf_lib::sync::IrqSafeSpinLock<RegulatoryDomain>>>,
}
impl Proof {
    pub(super) fn calibration(&self) -> &Calibration {
        &self.calibration
    }
    pub(super) fn permission(&self) -> Permission {
        self.permission
    }
    pub(super) fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(model) = &self.model {
            return Ok(model.lock().clone());
        }
        narf_wireless::reg::db::get_domain().ok_or(Error::Policy)
    }
    pub(super) fn registered(
        factory: Factory,
        vid: u16,
        pid: u16,
        permission: Permission,
    ) -> Result<Arc<Self>, Error> {
        let calibration = Calibration::load_registered(factory, vid, pid).map_err(Error::Power)?;
        let cap = calibration.authority().ok_or(Error::State)?;
        // Only this explicit pre-attempt boundary may bootstrap policy.
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Policy)?;
        if calibration.permission(&domain, 1).map_err(Error::Power)? != permission {
            return Err(Error::Policy);
        }
        Ok(Arc::new(Self {
            calibration,
            permission,
            cap,
            country: domain.country_code,
            #[cfg(any(test, feature = "kernel-test"))]
            model: None,
        }))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn model(
        calibration: Calibration,
        permission: Permission,
        cap: Cap<FirmwareBlob, Read>,
        domain: Arc<narf_lib::sync::IrqSafeSpinLock<RegulatoryDomain>>,
    ) -> Arc<Self> {
        let country = domain.lock().country_code;
        Arc::new(Self {
            calibration,
            permission,
            cap,
            country,
            model: Some(domain),
        })
    }
    fn policy(&self) -> Result<(), Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        let domain = if let Some(model) = &self.model {
            Some(model.lock().clone())
        } else {
            narf_wireless::reg::db::get_domain()
        };
        #[cfg(not(any(test, feature = "kernel-test")))]
        let domain = narf_wireless::reg::db::get_domain();
        let domain = domain.ok_or(Error::Policy)?;
        if domain.country_code != self.country
            || self
                .calibration
                .permission(&domain, 1)
                .map_err(Error::Power)?
                != self.permission
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
    pub(super) fn invoke<T>(&self, operation: impl FnOnce() -> T) -> Result<T, Error> {
        struct Invoke<'a, F> {
            proof: &'a Proof,
            operation: F,
        }
        impl<T, F: FnOnce() -> T> CapOp<FirmwareBlob, Read> for Invoke<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok(self.proof.policy().map(|()| (self.operation)()))
            }
        }
        self.cap
            .invoke(Invoke {
                proof: self,
                operation,
            })
            .map_err(|_| {
                Error::Power(super::power_policy::Error::Firmware(
                    narf_firmware::FirmwareError::AuthorityRevoked,
                ))
            })?
    }
    pub(super) async fn fence<T, E, F: Future<Output = Result<T, E>>>(
        &self,
        operation: F,
        map: fn(Error) -> E,
    ) -> Result<T, E> {
        let mut operation = core::pin::pin!(operation);
        core::future::poll_fn(|cx| match self.invoke(|| operation.as_mut().poll(cx)) {
            Ok(poll) => poll,
            Err(error) => Poll::Ready(Err(map(error))),
        })
        .await
    }
}
