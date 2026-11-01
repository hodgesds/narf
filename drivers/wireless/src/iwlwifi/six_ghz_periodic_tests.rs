//! Actual retained UID/event/epoch ownership with mixed periodic6GHz.
use super::super::six_ghz_tests as six;
use super::*;

fn smoke_iwl_six_ghz_periodic_psc_passive_typed_results_and_retirement() -> TestResult {
    check(|| {
        for associated in [false, true] {
            let model = six::model();
            let guard = six::setup(six::Native::Sc, model, Fault::None)?;
            let mut domain = six::policy();
            domain.rules.push(narf_wireless::reg::RegRule {
                freq_start_mhz: 2400,
                freq_end_mhz: 2500,
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: narf_wireless::reg::RegFlags::empty(),
            });
            guard.policy_db.install(domain);
            if associated {
                six::join(&guard, model)?;
            }
            let mut request = configured(true);
            // Same numeric channel5 on two physical bands, plus nonPSC1
            // which Linux removes before emitting the native periodic job.
            request.frequencies_mhz = vec![2432, 5955, 5975];
            let control = Control::with_guard(request, *guard)?;
            control.start()?;
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let beacon = wire.ap.beacon();
                wire.mpdu_at(&beacon, false, 1, 5);
                let mut beacon = wire.ap.beacon();
                six::complete_ap_frame(&mut beacon, model)?;
                wire.mpdu(&beacon, false);
                wire.firmware.inject(0xd9, 0, 0x8000, &[]);
            }
            until(|| {
                control.device().state.try_lock().is_some_and(|s| {
                    s.beacons.iter().any(|b| {
                        b.bssid == AP
                            && b.band == super::super::super::super::native_band::Band::Six
                    }) && s.beacons.iter().any(|b| {
                        b.bssid == AP
                            && b.band == super::super::super::super::native_band::Band::Two
                    })
                })
            })?;
            let source = control.source.1.lock();
            require(
                !source.is_empty(),
                "periodic6GHz never published a current result event",
            )?;
            drop(source);
            let state = control
                .device()
                .state
                .try_lock()
                .ok_or("periodic6GHz current owner")?;
            require(
                !state.hardware.is_failed() && state.scheduled.is_some(),
                "periodic6GHz closed before its owned UID terminal",
            )?;
            drop(state);
            control.stop()?;
            require(
                control
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none() && !s.hardware.is_failed()),
                "periodic6GHz stop lost native UID or transport ownership",
            )?;
            if associated {
                six::close(control.fixture.as_ref().unwrap())?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_periodic_psc_passive_typed_results_and_retirement
);
