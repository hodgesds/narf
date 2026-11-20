// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit native lifecycle cases over the existing inert original RF/DMA
//! actor. Published metadata bypasses real registries/over-air boot only;
//! original/joint caps, lease drain, actual install/restore are production code.
use super::*;
use crate::rtlwifi::{firmware_transport::Io, rtl8723be::h2c};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
struct Joint {
    grant: Arc<thermal::Grant>,
    admission: Arc<station::Admission>,
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
        Ok(crate::rtlwifi::rtl8723be::tests::be_us_domain())
    }
    fn admission(&self) -> Option<&Arc<station::Admission>> {
        Some(&self.admission)
    }
    fn rtl8723be_tracking(
        &self,
        base: Arc<crate::rtlwifi::rtl8723be::envelope::Calibration>,
        facts: thermal::Facts,
    ) -> Result<Option<Arc<thermal::Grant>>, Error> {
        if !Arc::ptr_eq(&base, self.grant.base()) || facts != self.grant.facts() {
            return Err(Error::Profile);
        }
        self.grant.with_current(|| Ok(()))?;
        Ok(Some(self.grant.clone()))
    }
}
fn run<F: Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}
fn smoke_be_native_thermal_enable_waits_old_lease_and_retains_joint_after_restore() -> TestResult {
    let h = match station::be_tracking_native_fixture() {
        Ok(h) => h,
        Err(error) => return TestResult::Fail(error),
    };
    let old = station::be_tracking_fixture_publication(&h);
    let model = h.model.clone();
    let cap = h.cap;
    let grant = h.grant.clone();
    let storage = Arc::new(Mutex::new(Some(*h.owner)));
    let admission = Arc::new(station::Admission::new());
    let device = Device::new(
        "be-thermal-inert",
        storage.clone(),
        Arc::new(crate::rtlwifi::rtl8723be::tests::be_factory()),
        Joint {
            grant: grant.clone(),
            admission: admission.clone(),
        },
        6,
    );
    // No real net/wiphy registry or physical boot receipt is fabricated.
    device.published.store(true, Ordering::Release);
    let old_generation = device.lifecycle.generation();
    let lease = device.lifecycle.lease(&admission, old_generation).unwrap();
    let mut enable = core::pin::pin!(device.enable_be_thermal_tracking());
    kt_assert!(enable
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    kt_assert!(admission.closed.load(Ordering::Acquire));
    kt_assert!(device.lifecycle.generation() > old_generation);
    kt_assert!(storage.try_lock().is_none());
    drop(lease);
    kt_assert_eq!(run(enable), Ok(true));
    kt_assert!(!admission.closed.load(Ordering::Acquire));
    let counter = core::sync::atomic::AtomicUsize::new(0);
    kt_assert_eq!(
        old.invoke(&crate::rtlwifi::rtl8723be::tests::be_us_domain(), || {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }),
        Ok(None)
    );
    {
        let mut saved = run(storage.lock());
        let owner = saved.as_mut().unwrap();
        kt_assert_eq!(
            run(owner.be_tracking_leisure(true, &device.environment)),
            Ok(())
        );
        kt_assert!(owner.leisure());
        kt_assert_eq!(model.read8(h2c::REG_PCIE_HRPWM), Ok(h2c::FW_PS_TOGGLE));
    }
    kt_assert_eq!(run(device.restore_be_thermal_tracking()), Ok(()));
    let saved = run(storage.lock());
    let owner = saved.as_ref().unwrap();
    kt_assert!(!owner.leisure());
    kt_assert_eq!(model.read8(h2c::REG_PCIE_HRPWM), Ok(0));
    kt_assert_eq!(
        thermal::Snapshot::read(&model),
        Ok(grant.facts().original())
    );
    let (base, permission) = owner.be_tracking_authority().unwrap();
    kt_assert!(Arc::ptr_eq(&base, &grant));
    cap.revoke();
    kt_assert!(base
        .with_current(|| {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .is_err());
    kt_assert!(base
        .permission_for(
            &crate::rtlwifi::rtl8723be::tests::be_us_domain(),
            permission.operating()
        )
        .is_err());
    kt_assert_eq!(counter.load(Ordering::Relaxed), 0);
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723be",smoke_be_native_thermal_enable_waits_old_lease_and_retains_joint_after_restore}

fn smoke_be_native_lifecycle_wakes_bound_lps_before_original_bb_restore() -> TestResult {
    let h = match station::be_tracking_native_fixture() {
        Ok(h) => h,
        Err(error) => return TestResult::Fail(error),
    };
    let model = h.model.clone();
    let grant = h.grant.clone();
    let storage = Arc::new(Mutex::new(Some(*h.owner)));
    let admission = Arc::new(station::Admission::new());
    let device = Device::new(
        "be-thermal-lps-lifecycle",
        storage.clone(),
        Arc::new(crate::rtlwifi::rtl8723be::tests::be_factory()),
        Joint {
            grant: grant.clone(),
            admission: admission.clone(),
        },
        6,
    );
    device.published.store(true, Ordering::Release);
    kt_assert_eq!(run(device.enable_be_thermal_tracking()), Ok(true));
    let _control = run(device.lifecycle.control.lock());
    let mut saved = run(storage.lock());
    let owner = saved.as_mut().unwrap();
    // Initial peer metadata is synthetic; actual H2C entry/wake and the
    // native closed-admission lifecycle/BB restore are production paths.
    kt_assert_eq!(
        run(owner.be_tracking_leisure(true, &device.environment)),
        Ok(())
    );
    kt_assert!(owner.leisure());
    kt_assert_eq!(model.read8(h2c::REG_PCIE_HRPWM), Ok(h2c::FW_PS_TOGGLE));
    device.close();
    kt_assert!(admission.closed.load(Ordering::Acquire));
    kt_assert_eq!(run(device.be_restore_for_lifecycle(owner)), Ok(()));
    kt_assert!(!owner.leisure());
    kt_assert_eq!(owner.station_phase(), station::Phase::Passive);
    kt_assert_eq!(model.read8(h2c::REG_PCIE_HRPWM), Ok(0));
    kt_assert_eq!(
        thermal::Snapshot::read(&model),
        Ok(grant.facts().original())
    );
    kt_assert!(admission.closed.load(Ordering::Acquire));
    let (retained, _) = owner.be_tracking_authority().unwrap();
    kt_assert!(Arc::ptr_eq(&retained, &grant));
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723be",smoke_be_native_lifecycle_wakes_bound_lps_before_original_bb_restore}

fn smoke_be_native_lps_restore_cancellation_or_source_loss_stays_terminal() -> TestResult {
    for loss in 0..3 {
        let h = match station::be_tracking_native_fixture() {
            Ok(h) => h,
            Err(error) => return TestResult::Fail(error),
        };
        let model = h.model.clone();
        let cap = h.cap;
        let grant = h.grant.clone();
        let storage = Arc::new(Mutex::new(Some(*h.owner)));
        let admission = Arc::new(station::Admission::new());
        let device = Device::new(
            "be-thermal-lps-loss",
            storage.clone(),
            Arc::new(crate::rtlwifi::rtl8723be::tests::be_factory()),
            Joint {
                grant: grant.clone(),
                admission: admission.clone(),
            },
            6,
        );
        device.published.store(true, Ordering::Release);
        kt_assert_eq!(run(device.enable_be_thermal_tracking()), Ok(true));
        let _control = run(device.lifecycle.control.lock());
        let mut saved = run(storage.lock());
        let owner = saved.as_mut().unwrap();
        kt_assert_eq!(
            run(owner.be_tracking_leisure(true, &device.environment)),
            Ok(())
        );
        kt_assert!(owner.leisure());
        device.close();
        model.hold_delays(true);
        {
            let mut restoring = core::pin::pin!(device.be_restore_for_lifecycle(owner));
            // The real fwlps_leave is waiting before its RPWM write.
            kt_assert!(restoring
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            if loss == 1 {
                cap.revoke();
                kt_assert!(run(restoring).is_err());
            } else if loss == 2 {
                device.removed.store(true, Ordering::Release);
                kt_assert!(run(restoring).is_err());
            }
            // loss=0 drops the pending production wake future here.
        }
        kt_assert_eq!(owner.station_phase(), station::Phase::Failed);
        if loss == 0 {
            kt_assert!(owner.leisure());
        }
        kt_assert!(admission.closed.load(Ordering::Acquire));
        kt_assert_eq!(model.read8(h2c::REG_PCIE_HRPWM), Ok(h2c::FW_PS_TOGGLE));
        let (retained, _) = owner.be_tracking_authority().unwrap();
        kt_assert!(Arc::ptr_eq(&retained, &grant));
        kt_assert!(run(device.be_restore_for_lifecycle(owner)).is_err());
    }
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723be",smoke_be_native_lps_restore_cancellation_or_source_loss_stays_terminal}
