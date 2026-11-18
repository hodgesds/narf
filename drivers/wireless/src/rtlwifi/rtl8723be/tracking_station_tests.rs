// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-only shared NBTH station/publication cases. The real original
//! RF/Prepared actor supplies inert radio/peer metadata; no physical boot,
//! over-air association or measured qualification is claimed.
use super::*;
use crate::rtlwifi::{
    prepare::packet::{be8723::shared_station_fixture, Publication as PciPublication},
    rtl8723be,
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
struct Joint {
    grant: Option<Arc<thermal::Grant>>,
}
impl Environment for Joint {
    async fn pause(&self) {}
    fn now_ms(&self) -> u64 {
        0
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        None
    }
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        Ok(rtl8723be::tests::be_us_domain())
    }
    fn rtl8723be_tracking(
        &self,
        base: Arc<rtl8723be::envelope::Calibration>,
        facts: thermal::Facts,
    ) -> Result<Option<Arc<thermal::Grant>>, Error> {
        if let Some(grant) = &self.grant {
            if !Arc::ptr_eq(&base, grant.base()) || facts != grant.facts() {
                return Err(Error::Profile);
            }
            grant.with_current(|| Ok(()))?;
        }
        Ok(self.grant.clone())
    }
}
fn run<F: core::future::Future>(f: F) -> F::Output {
    narf_scheduler::block_on(f)
}
fn capture<I: Port<Buffer = M> + 'static, M: Memory>(
    owner: &Prepared<I, M>,
    pci: PciPublication,
) -> Publication {
    Publication {
        pci,
        base: owner.station.calibration.clone().unwrap(),
        ht: None,
        protection: None,
        tracking: None,
        antenna: None,
        permission: owner.station_grant().unwrap(),
        indices: [0; 8],
        epoch: owner.station.epoch.clone(),
        expected: owner.station.epoch.load(Ordering::Acquire),
        failed: owner.station.failed.clone(),
    }
}
fn smoke_be_joint_station_install_retires_old_publication_and_restore_keeps_new_cap() -> TestResult
{
    let mut h = match shared_station_fixture() {
        Ok(h) => h,
        Err(error) => return TestResult::Fail(error),
    };
    // Existing actor supplied no shared MLME. Bind its already-authenticated
    // NAPC/radio into inert Passive metadata before exercising actual APIs.
    h.owner.packet.be8723.tracking.take();
    h.owner.station.calibration = Some(Base::Rtl8723be(h.base.clone()));
    h.owner.station.phase = Phase::Passive;
    let environment = Joint {
        grant: Some(h.grant.clone()),
    };
    let request = h
        .owner
        .be_tracking_request(h.firmware, &environment)
        .unwrap();
    kt_assert!(request.name.starts_with("rtlwifi/rtl8723be-thermal-v1-"));
    let model = h.model.clone();
    let old = capture(
        &h.owner,
        PciPublication::model(Arc::new(move || model.authority(true, || Ok(())))),
    );
    let expected = old.expected;
    let selected = h.owner.be_tracking_prepare(&environment).unwrap().unwrap();
    kt_assert!(Arc::ptr_eq(&selected, &h.grant));
    kt_assert_eq!(h.owner.be_tracking_retire_publications(), Ok(()));
    kt_assert!(h.owner.station.epoch.load(Ordering::Acquire) > expected);
    kt_assert_eq!(h.owner.be_tracking_install(selected, &environment), Ok(()));
    let counter = core::sync::atomic::AtomicUsize::new(0);
    kt_assert_eq!(
        old.invoke(&rtl8723be::tests::be_us_domain(), || {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }),
        Ok(None)
    );
    kt_assert_eq!(run(h.owner.be_tracking_restore(&environment)), Ok(()));
    let joint = h
        .owner
        .station
        .calibration
        .as_ref()
        .and_then(Base::rtl8723be_tracking)
        .unwrap();
    kt_assert!(Arc::ptr_eq(joint, &h.grant));
    let model = h.model.clone();
    let after = capture(
        &h.owner,
        PciPublication::model(Arc::new(move || model.authority(true, || Ok(())))),
    );
    h.cap.revoke();
    kt_assert!(after
        .invoke(&rtl8723be::tests::be_us_domain(), || {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .is_err());
    kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
fn smoke_be_joint_station_optional_absence_and_different_op_refuse_without_promotion() -> TestResult
{
    let mut h = match shared_station_fixture() {
        Ok(h) => h,
        Err(error) => return TestResult::Fail(error),
    };
    h.owner.packet.be8723.tracking.take();
    h.owner.station.calibration = Some(Base::Rtl8723be(h.base.clone()));
    h.owner.station.phase = Phase::Passive;
    let absent = Joint { grant: None };
    kt_assert!(h.owner.be_tracking_prepare(&absent).unwrap().is_none());
    kt_assert!(!h.owner.be_tracking_bound());
    kt_assert!(h
        .owner
        .station
        .calibration
        .as_ref()
        .unwrap()
        .rtl8723be_tracking()
        .is_none());
    let environment = Joint {
        grant: Some(h.grant.clone()),
    };
    let selected = h.owner.be_tracking_prepare(&environment).unwrap().unwrap();
    kt_assert_eq!(h.owner.be_tracking_retire_publications(), Ok(()));
    kt_assert_eq!(h.owner.be_tracking_install(selected, &environment), Ok(()));
    kt_assert!(h
        .owner
        .be_tracking_allows_op(
            Operating {
                channel: 6,
                width: rtl8723be::envelope::Width::W40Above
            },
            &environment
        )
        .is_err());
    kt_assert_eq!(
        h.owner
            .be_tracking_allows_op(Operating::twenty(6), &environment),
        Ok(())
    );
    let base = h.owner.station.calibration.as_ref().unwrap().clone();
    h.cap.revoke();
    kt_assert!(base
        .regrant(
            &rtl8723be::tests::be_us_domain(),
            h.owner.station_grant().unwrap()
        )
        .is_err());
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723be",smoke_be_joint_station_install_retires_old_publication_and_restore_keeps_new_cap}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723be",smoke_be_joint_station_optional_absence_and_different_op_refuse_without_promotion}
