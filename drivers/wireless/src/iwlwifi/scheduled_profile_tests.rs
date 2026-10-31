//! Exact API89 and Bz idle periodic producers over the real retained owner.
//! Parent helpers use actual delegated Admin/radio leases and GET_SCAN cache.
use super::super::super::super::{bz_fixture, gen3_fixture};
use super::*;

#[derive(Clone, Copy)]
enum Profile {
    Api89(gen3_fixture::Case),
    Bz(bz_fixture::Case),
}
const PROFILES: [Profile; 10] = [
    Profile::Api89(gen3_fixture::Case::Ty),
    Profile::Api89(gen3_fixture::Case::So),
    Profile::Api89(gen3_fixture::Case::SoLong),
    Profile::Api89(gen3_fixture::Case::SoImr),
    Profile::Api89(gen3_fixture::Case::SoCdb),
    Profile::Api89(gen3_fixture::Case::Ma),
    Profile::Bz(bz_fixture::Case::FmDiscrete),
    Profile::Bz(bz_fixture::Case::WhDiscrete),
    Profile::Bz(bz_fixture::Case::FmIntegrated),
    Profile::Bz(bz_fixture::Case::WhIntegrated),
];
#[inline(never)]
fn control(profile: Profile, active: bool) -> R<Control> {
    let (api89, bz) = match profile {
        Profile::Api89(c) => (Some(c), None),
        Profile::Bz(c) => (None, Some(c)),
    };
    let model = NativeModel {
        receive_model: if api89.is_some() {
            ReceiveModel::ExplicitV1
        } else {
            ReceiveModel::NativeSc
        },
        tx_model: None,
        api89,
        bz,
    };
    Control::with_guard(
        configured(active),
        Guard::build_native_profile(false, Fault::None, None, None, None, model)?,
    )
}
fn smoke_native_api89_bz_idle_periodic_profiles_actual_results_and_terminal_stop() -> TestResult {
    check(|| {
        for profile in PROFILES {
            for active in [false, true] {
                let control = control(profile, active)?;
                control.start()?;
                let transcript = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    let scan = wire
                        .commands
                        .iter()
                        .position(|(g, c, b)| (*g, *c) == (1, 0xd) && word(b, 0) == 1)
                        .ok_or("native profile PNO request absent")?;
                    let profiles = wire
                        .commands
                        .iter()
                        .position(|(g, c, _)| (*g, *c) == (1, 0x6e))
                        .ok_or("native source periodic profile absent")?;
                    profiles < scan
                        && wire.queues.is_empty()
                        && wire.rx_queues.len() == 2
                        && (!active
                            || wire
                                .commands
                                .iter()
                                .position(|(g, c, b)| (*g, *c) == (1, 0x9f) && word(b, 0) == 1)
                                .is_some_and(|power| power < profiles))
                };
                require(
                    transcript,
                    "profile-specific PNO omitted native power/order or created station queues",
                )?;
                inject_result();
                until(|| control.device().scan_information_elements(AP).is_some())?;
                let replies = dispatch(&control, 32, 0x7e01)?;
                require(
                    replies
                        .iter()
                        .any(|reply| reply.windows(SSID.len()).any(|v| v == SSID)),
                    "native profile PNO failed actual GET_SCAN copy",
                )?;
                control.stop()?;
                let stopped = control.device().state.try_lock().is_some_and(|s| {
                    s.scheduled.is_none()
                        && !s.needs_reset
                        && !s.hardware.is_failed()
                        && s.hardware.receive_queue_count() == 3
                });
                require(
                    stopped
                        && !HARNESS
                            .lock()
                            .as_ref()
                            .unwrap()
                            .1
                            .scheduled
                            .as_ref()
                            .unwrap()
                            .live,
                    "native profile PNO terminal stop left emitter or reset healthy transport",
                )?;
                let found = run(control.device().scan(scan_request()), service)?
                    .map_err(|_| "ordinary scan after native profile PNO retirement")?;
                require(
                    found.len() == 1 && found[0].bssid == AP,
                    "retired PNO did not return healthy native scan owner",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/scheduled_profiles",
    smoke_native_api89_bz_idle_periodic_profiles_actual_results_and_terminal_stop
);

fn smoke_native_api89_bz_periodic_stop_waiter_drop_keeps_exact_uid_owner() -> TestResult {
    check(|| {
        for profile in [
            Profile::Api89(gen3_fixture::Case::SoCdb),
            Profile::Bz(bz_fixture::Case::WhIntegrated),
        ] {
            let control = control(profile, true)?;
            control.start()?;
            HARNESS
                .lock()
                .as_mut()
                .unwrap()
                .1
                .scheduled
                .as_mut()
                .unwrap()
                .hold_stop = true;
            let authority = control.authority()?;
            let mut stop = Box::pin(control.device().stop_sched_scan_async(&authority));
            let mut cx = Context::from_waker(Waker::noop());
            until(|| {
                let _ = stop.as_mut().poll(&mut cx);
                HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .commands
                    .iter()
                    .any(|(g, c, _)| (*g, *c) == (1, 0xe))
            })?;
            require(
                stop.as_mut().poll(&mut cx).is_pending(),
                "profile PNO ACK incorrectly proved firmware absence",
            )?;
            drop(stop);
            drop(authority);
            {
                let mut h = HARNESS.lock();
                let wire = &mut h.as_mut().unwrap().1;
                let mut done = [0; 16];
                done[6] = 2;
                wire.firmware.inject(0xf, 0, 0x8000, &done);
            }
            drain();
            require(
                control.device().state.try_lock().is_none(),
                "foreign profile UID retired retained autonomous owner",
            )?;
            {
                let mut h = HARNESS.lock();
                let wire = &mut h.as_mut().unwrap().1;
                let mut done = [0; 16];
                done[..4].copy_from_slice(&1u32.to_le_bytes());
                done[6] = 2;
                wire.firmware.inject(0xf, 0, 0x8000, &done);
                wire.scheduled.as_mut().unwrap().live = false;
            }
            until(|| {
                control
                    .device()
                    .control
                    .try_lock()
                    .is_some_and(|c| c.is_none())
            })?;
            require(
                control.device().state.try_lock().is_some_and(|s| {
                    s.scheduled.is_none() && !s.needs_reset && !s.hardware.is_failed()
                }),
                "profile PNO dropped STOP released or lost terminal owner",
            )?;
            HARNESS
                .lock()
                .as_mut()
                .unwrap()
                .1
                .scheduled
                .as_mut()
                .unwrap()
                .hold_stop = false;
            control.start()?;
            control.stop()?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/scheduled_profiles",
    smoke_native_api89_bz_periodic_stop_waiter_drop_keeps_exact_uid_owner
);
