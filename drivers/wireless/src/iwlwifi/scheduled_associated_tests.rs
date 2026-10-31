//! Associated MLD periodic scans retain the actual serving-link/key/port
//! owner. Firmware execution is modeled; native TFH/RFH/leases are real.
use super::super::super::super::{bz_fixture, gen3_fixture};
use super::*;

#[derive(Clone, Copy)]
enum Profile {
    Sc,
    Bz(bz_fixture::Case),
    Mvm,
}
#[inline(never)]
fn control(profile: Profile, active: bool, phy: Option<PhyModel>) -> R<Control> {
    let (api89, bz) = match profile {
        Profile::Sc => (None, None),
        Profile::Bz(case) => (None, Some(case)),
        Profile::Mvm => (Some(gen3_fixture::Case::Ty), None),
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
        Guard::build_native_profile(true, Fault::None, None, None, phy, model)?,
    )
}
fn join(control: &Control, phy: Option<PhyModel>) -> R {
    let device = control.device();
    let mut scan_request = scan_request();
    let mut join_request = request(true);
    if let Some(phy) = phy {
        scan_request.channels = vec![u32::from(phy.channel())];
        join_request.channel = u32::from(phy.channel());
        scan_request.frequencies_mhz =
            vec![if phy.channel() <= 14 { 2407 } else { 5000 } + 5 * u32::from(phy.channel())];
        join_request.frequency_mhz =
            if phy.channel() <= 14 { 2407 } else { 5000 } + 5 * u32::from(phy.channel());
    }
    let bss =
        run(device.scan(scan_request), service)?.map_err(|_| "associated PNO actual discovery")?;
    require(
        bss.len() == 1 && bss[0].bssid == AP,
        "associated PNO native BSS identity",
    )?;
    let domain = control
        .fixture
        .as_ref()
        .unwrap()
        .policy_db
        .snapshot()
        .ok_or("associated PNO fixture current policy")?;
    run(device.associate_in_domain(join_request, &domain), service)?
        .map_err(|_| "associated PNO actual WPA2 join")?;
    carrier(device, true)
}
fn original(control: &Control) -> R<(u64, usize, usize)> {
    let state = control
        .device()
        .state
        .try_lock()
        .ok_or("associated PNO actual state")?;
    let capture = state
        .hardware
        .receive_capture_epoch()
        .ok_or("associated PNO original capture")?;
    let wire = HARNESS.lock();
    let wire = &wire.as_ref().unwrap().1;
    Ok((
        capture,
        wire.keys,
        wire.queues.iter().filter(|q| q.2).count(),
    ))
}
fn same_home(control: &Control, original: (u64, usize, usize)) -> R {
    carrier(control.device(), true)?;
    let state = control
        .device()
        .state
        .try_lock()
        .ok_or("associated PNO retained home state")?;
    let wire = HARNESS.lock();
    let wire = &wire.as_ref().unwrap().1;
    require(
        !state.needs_reset
            && !state.hardware.is_failed()
            && state.hardware.receive_capture_epoch() == Some(original.0)
            && state.hardware.receive_queue_count() == 3
            && state.connection.as_ref().is_some_and(|c| c.authorized)
            && wire.keys == original.1
            && wire.queues.iter().filter(|q| q.2).count() == original.2,
        "associated PNO replaced original home key/port/capture/rings",
    )
}
fn data(control: &Control, payload: &[u8]) -> R {
    let uplink = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        payload,
    );
    narf_net::iface::send_on(control.device().name(), &uplink)
        .map_err(|_| "associated PNO real IP transmit")?;
    flush()?;
    let sent = {
        let slot = HARNESS.lock();
        slot.as_ref()
            .unwrap()
            .1
            .data
            .iter()
            .any(|(frame, protected)| frame == &uplink && *protected)
    };
    require(sent, "associated PNO exact protected uplink bytes")?;
    let downlink = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        12345,
        54321,
        payload,
    );
    HARNESS.lock().as_mut().unwrap().1.ethernet(&downlink);
    flush()?;
    let received = HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .received
        .iter()
        .any(|f| f == &downlink);
    require(received, "associated PNO exact protected RFH downlink")
}
fn held_data(control: &Control) -> R<Delivery> {
    let frame = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        12345,
        54321,
        b"associated-pno-held-home",
    );
    HARNESS.lock().as_mut().unwrap().1.ethernet(&frame);
    service()?;
    control
        .device()
        .step(None)
        .into_iter()
        .find(|d| d.bytes == frame)
        .ok_or("associated PNO actual held station delivery")
}
fn timing() -> R {
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    let body = &wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, b)| (*g, *c) == (1, 0xd) && word(b, 0) == 1)
        .ok_or("associated PNO native request absent")?
        .2;
    require(
        body[11] == 0
            && word(body, 20) == 120
            && word(body, 24) == 0
            && word(body, 28) == 30
            && word(body, 32) == 0,
        "associated PNO actual serving link/WILD low-load timing literal",
    )
}
fn smoke_mld_associated_periodic_sc_bz_live_wpa2_dhcp_data_and_exact_home_stop() -> TestResult {
    check(|| {
        for profile in [
            Profile::Sc,
            Profile::Bz(bz_fixture::Case::FmDiscrete),
            Profile::Bz(bz_fixture::Case::WhIntegrated),
        ] {
            for active in [false, true] {
                let control = control(profile, active, None)?;
                join(&control, None)?;
                let before = original(&control)?;
                control.start()?;
                timing()?;
                let lease = narf_net::dhcp::dhcp_acquire(control.device().name(), 0)
                    .map_err(|_| "associated periodic scan blocked native DORA")?;
                require(
                    NETWORK.matches_lease(&lease),
                    "associated PNO actual DHCP terms",
                )?;
                let native_dora = {
                    let slot = HARNESS.lock();
                    let seen = slot.as_ref().unwrap().1.server.observations();
                    seen.discovers == 1 && seen.requests == 1
                };
                require(
                    native_dora,
                    "associated PNO skipped actual native DORA packets",
                )?;
                data(&control, b"associated-pno-live")?;
                inject_result();
                until(|| {
                    control
                        .source
                        .1
                        .lock()
                        .iter()
                        .any(|m| m.get(16) == Some(&77))
                })?;
                let replies = dispatch(&control, 32, 0x7e91)?;
                require(
                    replies
                        .iter()
                        .any(|reply| reply.windows(SSID.len()).any(|s| s == SSID)),
                    "associated PNO actual GET_SCAN result",
                )?;
                same_home(&control, before)?;
                let held = held_data(&control)?;
                held.invoke(|| Ok(()))?;
                control.stop()?;
                same_home(&control, before)?;
                held.invoke(|| Ok(()))?;
                data(&control, b"associated-pno-stopped")?;
                run(control.device().disassociate(), service)?
                    .map_err(|_| "associated PNO orderly home teardown")?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled_associated",
    smoke_mld_associated_periodic_sc_bz_live_wpa2_dhcp_data_and_exact_home_stop
);

fn smoke_mld_periodic_actual_mcc_refresh_preserves_or_stickily_retires_held_home() -> TestResult {
    check(|| {
        for profile in [Profile::Sc, Profile::Bz(bz_fixture::Case::WhIntegrated)] {
            // An actual wider response cannot change the issued home width.
            {
                let phy = PhyModel {
                    width: 0,
                    streams: 1,
                    rates: 3,
                    mcc_he: true,
                    response_he: true,
                };
                let control = control(profile, true, Some(phy))?;
                HARNESS.lock().as_mut().unwrap().1.mcc_caps_override = Some(0);
                join(&control, Some(phy))?;
                let held = held_data(&control)?;
                let before = original(&control)?;
                HARNESS.lock().as_mut().unwrap().1.mcc_caps_override = Some(0x18);
                control.start()?;
                held.invoke(|| Ok(()))?;
                same_home(&control, before)?;
                let still_narrow = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    wire.commands
                        .iter()
                        .rev()
                        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
                        .is_some_and(|(_, _, b)| b[8] == 0 && b[9] == 3)
                };
                require(
                    still_narrow,
                    "looser periodic MCC enlarged original home TLC",
                )?;
                let lease = narf_net::dhcp::dhcp_acquire(control.device().name(), 0)
                    .map_err(|_| "benign actual MCC refresh blocked home DHCP")?;
                require(NETWORK.matches_lease(&lease), "benign MCC refresh lease")?;
                control.stop()?;
                held.invoke(|| Ok(()))?;
            }
            // Both width and HE prohibitions come from the actual correlated
            // command response, and retire old policy proofs before SCAN_REQ.
            for he in [false, true] {
                let phy = PhyModel {
                    width: if he { 0 } else { 2 },
                    streams: 1,
                    rates: 3,
                    mcc_he: true,
                    response_he: true,
                };
                let control = control(profile, true, Some(phy))?;
                join(&control, Some(phy))?;
                let held = held_data(&control)?;
                held.policy.check()?;
                let before = HARNESS.lock().as_ref().unwrap().1.commands.len();
                HARNESS.lock().as_mut().unwrap().1.mcc_caps_override =
                    Some(if he { 0x18 | (1 << 13) } else { 8 });
                require(
                    control.start().is_err(),
                    "forbidden actual MCC admitted associated periodic emitter",
                )?;
                require(
                    held.policy.check().is_err() && held.invoke(|| Ok(())).is_err(),
                    "fresh MCC did not invalidate held original home policy",
                )?;
                let no_request = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    !wire.commands[before..]
                        .iter()
                        .any(|(g, c, b)| (*g, *c) == (1, 0xd) && word(b, 0) == 1)
                };
                require(
                    no_request,
                    "forbidden home MCC published periodic native request",
                )?;
                let state = control
                    .device()
                    .state
                    .try_lock()
                    .ok_or("forbidden MCC physical retirement")?;
                require(
                    state.needs_reset
                        && state.stop_completed
                        && state.hardware.receive_capture_epoch().is_none()
                        && !state.connection.as_ref().is_some_and(|c| c.authorized),
                    "forbidden home MCC left authorized RF/capture owner",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled_associated",
    smoke_mld_periodic_actual_mcc_refresh_preserves_or_stickily_retires_held_home
);

fn smoke_mld_periodic_live_group_rekey_keeps_scan_and_all_ring_epochs_owned() -> TestResult {
    check(|| {
        for profile in [Profile::Sc, Profile::Bz(bz_fixture::Case::WhIntegrated)] {
            let control = control(profile, true, None)?;
            join(&control, None)?;
            let before = original(&control)?;
            control.start()?;
            let old = held_data(&control)?;
            security_tests::acknowledged_rotation((2, [0x88; 16]), None, 3)?;
            let after = original(&control)?;
            require(
                after.0 != before.0
                    && after.1 == before.1 + 1
                    && after.2 == before.2
                    && old.invoke(|| Ok(())).is_err(),
                "associated PNO rekey bypassed original all-ring key epoch",
            )?;
            let live = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                wire.scheduled.as_ref().is_some_and(|s| s.live)
                    && wire.group_reply
                    && wire.held_markers.is_empty()
                    && wire.rx_queues.len() == 2
            };
            require(
                live,
                "actual group rotation lost live periodic scanner or RX marker owner",
            )?;
            inject_result();
            until(|| {
                control
                    .source
                    .1
                    .lock()
                    .iter()
                    .any(|m| m.get(16) == Some(&77))
            })?;
            let lease = narf_net::dhcp::dhcp_acquire(control.device().name(), 0)
                .map_err(|_| "PNO rekey blocked original DHCP port")?;
            require(NETWORK.matches_lease(&lease), "PNO rekey native lease")?;
            data(&control, b"associated-pno-new-key")?;
            control.stop()?;
            same_home(&control, after)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled_associated",
    smoke_mld_periodic_live_group_rekey_keeps_scan_and_all_ring_epochs_owned
);

fn smoke_mld_periodic_source_close_and_dropped_stop_wait_for_exact_uid_keep_home() -> TestResult {
    check(|| {
        for drop_stop in [false, true] {
            let control = control(Profile::Bz(bz_fixture::Case::WhIntegrated), true, None)?;
            join(&control, None)?;
            control.start()?;
            let before = original(&control)?;
            let copies = copied_result(&control, [2, 0x7b, 2, 3, 4, 6])?;
            require(
                copies.len() == 1,
                "associated PNO actual held result missing",
            )?;
            let copy_epoch = copies[0].epoch_for_test();
            if drop_stop {
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
                    "associated PNO command ACK became emitter absence proof",
                )?;
                drop(stop);
                drop(authority);
                {
                    let mut slot = HARNESS.lock();
                    let wire = &mut slot.as_mut().unwrap().1;
                    let mut done = [0; 16];
                    done[6] = 2;
                    wire.firmware.inject(0xf, 0, 0x8000, &done);
                }
                for _ in 0..8 {
                    service()?;
                    drain();
                }
                require(
                    control.device().state.try_lock().is_none(),
                    "associated PNO foreign UID retired retained stop owner",
                )?;
                {
                    let mut slot = HARNESS.lock();
                    let wire = &mut slot.as_mut().unwrap().1;
                    let mut done = [0; 16];
                    done[0] = 1;
                    done[6] = 2;
                    wire.firmware.inject(0xf, 0, 0x8000, &done);
                    wire.scheduled.as_mut().unwrap().live = false;
                }
            } else {
                control.source.0.store(false, Ordering::Release);
            }
            until(|| {
                control
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none())
            })?;
            same_home(&control, before)?;
            require(
                control
                    .device()
                    .scan_generation
                    .publish(copy_epoch, || Ok(()))
                    .is_err(),
                "retired associated periodic copy retained publication permission",
            )?;
            for publication in copies {
                publication.publish();
            }
            let lease = narf_net::dhcp::dhcp_acquire(control.device().name(), 0)
                .map_err(|_| "healthy associated periodic retirement lost home DHCP")?;
            require(
                NETWORK.matches_lease(&lease),
                "healthy associated retirement lease",
            )?;
            data(&control, b"associated-pno-independent-home")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled_associated",
    smoke_mld_periodic_source_close_and_dropped_stop_wait_for_exact_uid_keep_home
);

fn smoke_mld_periodic_live_mcc_or_ambiguous_abort_closes_both_but_mvm_stays_idle_only() -> TestResult
{
    check(|| {
        for boundary in 0..4 {
            let control = control(Profile::Sc, boundary != 3, None)?;
            join(&control, None)?;
            control.start()?;
            let old = held_data(&control)?;
            let mut copies = copied_result(&control, [2, 0x7c, 2, 3, 4, 6])?;
            require(
                copies.len() == 1,
                "associated failure actual held result absent",
            )?;
            match boundary {
                0 => {
                    HARNESS
                        .lock()
                        .as_mut()
                        .unwrap()
                        .1
                        .firmware
                        .inject(0xc9, 0, 0x8000, &[]);
                }
                1 => {
                    HARNESS
                        .lock()
                        .as_mut()
                        .unwrap()
                        .1
                        .scheduled
                        .as_mut()
                        .unwrap()
                        .malformed_abort = true;
                    require(
                        control.stop().is_err(),
                        "associated PNO malformed abort became absence proof",
                    )?;
                }
                2 => {
                    HARNESS.lock().as_mut().unwrap().1.fault = Fault::HoldGroupReply;
                    security_tests::rotation((2, [0x88; 16]), None, 3)?;
                    until(|| HARNESS.lock().as_ref().unwrap().1.held_tx.is_some())?;
                    // This source loss occurs while the real maintenance future
                    // retains State and pending native TX: no steady-state
                    // currentness snapshot can obtain that lock to hide it.
                    control.source.0.store(false, Ordering::Release);
                }
                _ => {
                    // A real peer deauthentication is a later home receive
                    // error, not a revoked caller/firmware grant. The copied
                    // periodic result must close before physical work polls.
                    let old_epoch = copies[0].epoch_for_test();
                    control
                        .device()
                        .scan_generation
                        .publish(old_epoch, || Ok(()))?;
                    let mut deauth = vec![0; 24];
                    deauth[0] = 0xc0;
                    deauth[4..10].copy_from_slice(&OWN);
                    deauth[10..16].copy_from_slice(&AP);
                    deauth[16..22].copy_from_slice(&AP);
                    deauth.extend_from_slice(&3u16.to_le_bytes());
                    HARNESS.lock().as_mut().unwrap().1.mpdu(&deauth, false);
                    let _ = control.device().step(None);
                    let before_stop = control.device().state.try_lock().is_some_and(|s| {
                        s.needs_reset && !s.stop_completed && s.scheduled.is_none()
                    });
                    require(
                        before_stop,
                        "home receive error deferred periodic cancellation to physical stop",
                    )?;
                    control.device().source.invoke(|| Ok(()))?;
                    let authority = control.authority()?;
                    authority
                        .check_for(control.device().as_ref())
                        .map_err(|_| "home receive error masked private epoch via caller revoke")?;
                    authority
                        .require_link()
                        .map_err(|_| "home receive error changed administrative UP")?;
                    drop(authority);
                    require(
                        control
                            .device()
                            .scan_generation
                            .publish(old_epoch, || Ok(()))
                            .is_err(),
                        "home repair admission kept copied periodic publication epoch",
                    )?;
                    let events_before = control.source.1.lock().len();
                    for publication in core::mem::take(&mut copies) {
                        publication.publish();
                    }
                    require(
                        control.source.1.lock().len() == events_before,
                        "held passive result published before physical repair ran",
                    )?;
                }
            }
            until(|| {
                control
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|s| s.stop_completed)
            })?;
            carrier(control.device(), false)?;
            require(
                old.invoke(|| Ok(())).is_err(),
                "failed associated periodic owner kept old data grant",
            )?;
            for publication in copies {
                publication.publish();
            }
            let state = control
                .device()
                .state
                .try_lock()
                .ok_or("associated PNO failed retained owner")?;
            require(
                state.needs_reset
                    && state.hardware.is_failed()
                    && state.hardware.receive_capture_epoch().is_none()
                    && state.scheduled.is_none()
                    && !state.connection.as_ref().is_some_and(|c| c.authorized),
                "ambiguous associated scanner failed to stop both RF owners",
            )?;
            if boundary == 2 {
                require(
                    model::retained(&state.hardware).1 != 0,
                    "uncertain native rekey TX lost DMA owner after source revoke",
                )?;
            }
        }
        for active in [false, true] {
            let control = control(Profile::Mvm, active, None)?;
            join(&control, None)?;
            let before = original(&control)?;
            let commands = HARNESS.lock().as_ref().unwrap().1.commands.len();
            let authority = control.authority()?;
            let result = run(
                control
                    .device()
                    .start_sched_scan_async(&authority, control.request()),
                service,
            )?;
            drop(authority);
            require(
                result == Err(16),
                "MVM associated periodic scan ignored Linux cfg.idle EBUSY",
            )?;
            require(
                HARNESS.lock().as_ref().unwrap().1.commands.len() == commands,
                "MVM associated periodic refusal mutated native firmware",
            )?;
            same_home(&control, before)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled_associated",
    smoke_mld_periodic_live_mcc_or_ambiguous_abort_closes_both_but_mvm_stays_idle_only
);

fn smoke_mld_periodic_bounded_scan_pass_preserves_data_prefix_and_later_uid_terminal() -> TestResult
{
    check(|| {
        let control = control(Profile::Sc, false, None)?;
        join(&control, None)?;
        control.start()?;
        let before = original(&control)?;
        let held = copied_result(&control, [2, 0x7d, 2, 3, 4, 6])?;
        require(
            held.len() == 1,
            "bounded associated scan actual old result absent",
        )?;
        let copy_epoch = held[0].epoch_for_test();
        // The borrowed scan BSS remains an ordinary station notification;
        // retire that unrelated prefix before measuring exactly64 data MPDUs.
        let _ = control.device().step(None);
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            for n in 0..63 {
                let frame = udp_ipv4(
                    OWN,
                    AP,
                    NETWORK.server_ip,
                    NETWORK.lease_ip,
                    12345,
                    54321,
                    &[b'p', n],
                );
                wire.ethernet(&frame);
            }
            let mut done = [0; 16];
            done[0] = 1;
            done[6] = 1;
            // The last actual RFH buffer contains BOTH the64th data MPDU
            // and UID terminal, each64-byte aligned. Hardware's independent
            // 64-buffer drain therefore copies65 notifications in one poll.
            // Literal native descriptor/MAC/CCMP fields follow this legacy
            // WPA2 fixture; production still validates its real key/epoch.
            wire.next_pn += 1;
            let pn = wire.next_pn.to_le_bytes();
            let ethernet = udp_ipv4(
                OWN,
                AP,
                NETWORK.server_ip,
                NETWORK.lease_ip,
                12345,
                54321,
                &[b'p', 63],
            );
            let mut mpdu = vec![0; 24];
            mpdu[0] = 8;
            mpdu[1] = 0x42;
            mpdu[4..10].copy_from_slice(&OWN);
            mpdu[10..16].copy_from_slice(&AP);
            mpdu[16..22].copy_from_slice(&AP);
            mpdu.extend_from_slice(&[pn[0], pn[1], 0, 0x20, pn[2], pn[3], pn[4], pn[5]]);
            mpdu.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            mpdu.extend_from_slice(&ethernet[12..]);
            let mut native = vec![0; 64];
            native[..2].copy_from_slice(&(mpdu.len() as u16).to_le_bytes());
            native[12..16].copy_from_slice(&0x243u32.to_le_bytes());
            native[40] = 50;
            native[41] = 60;
            native[42] = 6;
            native.extend_from_slice(&mpdu);
            wire.firmware
                .inject_packed(&[(0xc1, 0, 0x8000, &native), (0xf, 0, 0x8000, &done)]);
            wire.scheduled.as_mut().unwrap().live = false;
        }
        service()?;
        let frames = control.device().step(None);
        require(
            frames.len() == 64 && frames.iter().all(|d| d.invoke(|| Ok(())).is_ok()),
            "bounded scan pass discarded or reordered its inspected station prefix",
        )?;
        require(
            control.device().state.try_lock().is_some_and(|s| {
                s.scheduled.is_some()
                    && s.hardware
                        .notifications
                        .front()
                        .is_some_and(|p| p.header.cmd == 0xf)
            }),
            "scan pass inspected past its native fairness budget",
        )?;
        let later = control.device().step(None);
        require(
            later.is_empty()
                && control
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|s| s.scheduled.is_none()),
            "station decoder swallowed later native periodic UID completion",
        )?;
        same_home(&control, before)?;
        require(
            control
                .source
                .1
                .lock()
                .iter()
                .any(|m| m.get(16) == Some(&78))
                && control
                    .device()
                    .scan_generation
                    .publish(copy_epoch, || Ok(()))
                    .is_err(),
            "natural periodic terminal omitted exact STOP or retained old publication",
        )?;
        for publication in held {
            publication.publish();
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/scheduled_associated",
    smoke_mld_periodic_bounded_scan_pass_preserves_data_prefix_and_later_uid_terminal
);
