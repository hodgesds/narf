//! Exact extra-RFH/RSS command receipts and real per-ring DMA captures use
//! the public Sc station worker, current keys, IPC and kernel network path.
use super::*;

fn setup() -> R<Guard> {
    setup_profile(ReceiveModel::ExplicitV1)
}
fn setup_profile(profile: ReceiveModel) -> R<Guard> {
    let phy = PhyModel {
        width: 0,
        streams: 1,
        rates: 3,
        mcc_he: false,
        response_he: false,
    };
    Guard::build_features(true, Fault::None, None, None, Some(phy), profile, None)
}
fn ready(guard: &Guard) -> R {
    scan(guard.device())?;
    run(
        guard
            .device()
            .associate_in_domain(request(true), &he_tests::policy()),
        service,
    )?
    .map_err(|_| "Sc RSS actual WPA2 association failed")?;
    carrier(guard.device(), true)?;
    let state = guard
        .device()
        .state
        .try_lock()
        .ok_or("Sc RSS retained association")?;
    require(
        state.hardware.receive_queue_count() == 3,
        "Sc RSS native extra queues absent",
    )
}
fn progress_until(mut done: impl FnMut() -> R<bool>) -> R {
    let deadline = narf_time::Deadline::after_ms(1500);
    loop {
        service()?;
        drain();
        if done()? {
            return Ok(());
        }
        if deadline.expired() {
            return Err("Sc RSS native progress bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
}
fn terminal(guard: &Guard) -> R {
    progress_until(|| {
        Ok(guard
            .device()
            .control
            .try_lock()
            .is_some_and(|control| control.is_none()))
    })
}
fn ethernet(marker: u8) -> Vec<u8> {
    udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        1000 + u16::from(marker),
        45000,
        &[marker],
    )
}
fn payload(ethernet: &[u8], sn: u16, nssn: u16, pn: u64, baid: u8) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[..2].copy_from_slice(&[0x88, 0x42]);
    frame[4..10].copy_from_slice(&ethernet[..6]);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&ethernet[6..12]);
    frame[22..24].copy_from_slice(&(sn << 4).to_le_bytes());
    frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&ethernet[12..]);
    let mut out = vec![0; 64];
    out[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    out[12..16].copy_from_slice(&0x243u32.to_le_bytes());
    out[16..20].copy_from_slice(
        &((u32::from(baid) << 24) | (u32::from(sn) << 12) | u32::from(nssn)).to_le_bytes(),
    );
    out[40] = 50;
    out[42] = 6;
    out.extend_from_slice(&frame);
    out
}
fn inject(queue: u8, command: u8, group: u8, body: &[u8]) -> R {
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    if queue == 0 {
        wire.firmware.inject(command, group, 0x8000, body);
    } else {
        wire.rx_queues
            .iter_mut()
            .find(|rx| rx.queue == queue)
            .ok_or("Sc RSS missing physical ring")?
            .inject(command, group, 0x8000, body);
    }
    Ok(())
}
fn seen(frame: &[u8]) -> bool {
    HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .received
        .iter()
        .any(|old| old == frame)
}
fn release_markers() -> R {
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    wire.hold_rx_queue = None;
    for (queue, marker) in core::mem::take(&mut wire.held_markers) {
        wire.rx_queues
            .iter_mut()
            .find(|rx| rx.queue == queue)
            .ok_or("Sc held marker ring absent")?
            .inject(0xff, 5, 0x8000, &marker);
    }
    Ok(())
}
fn smoke_sc_rss_native_three_queues_keep_pairwise_pn_and_fallback_control_separate() -> TestResult {
    check(|| {
        for profile in [ReceiveModel::ExplicitV1, ReceiveModel::NativeSc] {
            let guard = setup_profile(profile)?;
            ready(&guard)?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "Sc RSS actual kernel DORA")?;
            require(NETWORK.matches_lease(&lease), "Sc RSS DHCP lease terms")?;
            for (queue, sn, pn, marker, accept) in [
                (1, 10, 100, 1, true),
                (2, 20, 5, 2, true),
                (2, 21, 5, 3, false),
                (1, 11, 99, 4, false),
                (2, 22, 6, 5, true),
            ] {
                let frame = ethernet(marker);
                inject(queue, 0xc1, 0, &payload(&frame, sn, 0, pn, 127))?;
                flush()?;
                require(
                    seen(&frame) == accept,
                    "Sc RSS cross-queue or same-queue PN admission",
                )?;
            }
            let mut eapol = ethernet(6);
            eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
            inject(1, 0xc1, 0, &payload(&eapol, 12, 0, 1000, 127))?;
            let fresh = ethernet(7);
            inject(1, 0xc1, 0, &payload(&fresh, 13, 0, 101, 127))?;
            flush()?;
            require(
                !seen(&eapol) && seen(&fresh),
                "Sc RSS misplaced EAPOL poisoned native PN",
            )?;
            carrier(guard.device(), true)?;
            run(guard.device().disassociate(), service)?.map_err(|_| "Sc RSS native teardown")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/rx_queues",
    smoke_sc_rss_native_three_queues_keep_pairwise_pn_and_fallback_control_separate
);

fn smoke_sc_rss_native_open_port_waits_all_real_ring_markers_and_drops_closed_copies() -> TestResult
{
    check(|| {
        let guard = setup()?;
        scan(guard.device())?;
        HARNESS.lock().as_mut().unwrap().1.hold_rx_queue = Some(2);
        let req = request(true);
        let domain = he_tests::policy();
        let mut waiter = Box::pin(guard.device().associate_in_domain(req, &domain));
        let mut cx = Context::from_waker(Waker::noop());
        progress_until(|| {
            require(
                waiter.as_mut().poll(&mut cx).is_pending(),
                "Sc RSS opened port before final RFH marker",
            )?;
            Ok(!HARNESS.lock().as_ref().unwrap().1.held_markers.is_empty())
        })?;
        carrier(guard.device(), false).map_err(|_| "Sc RSS carrier opened at held final marker")?;
        let closed = ethernet(8);
        inject(1, 0xc1, 0, &payload(&closed, 20, 0, 5, 127))?;
        for _ in 0..4 {
            require(
                waiter.as_mut().poll(&mut cx).is_pending(),
                "Sc RSS completed before final marker",
            )?;
            service()?;
        }
        carrier(guard.device(), false)
            .map_err(|_| "Sc RSS carrier opened while closed copies were pending")?;
        require(
            !seen(&closed),
            "Sc RSS closed-prefix data entered successor epoch",
        )?;
        release_markers()?;
        run(waiter, service)?
            .map_err(|_| "Sc RSS association did not complete after every marker")?;
        carrier(guard.device(), true)
            .map_err(|_| "Sc RSS carrier stayed closed after every marker")?;
        let fresh = ethernet(9);
        inject(1, 0xc1, 0, &payload(&fresh, 21, 0, 5, 127))?;
        flush()?;
        require(
            !seen(&closed) && seen(&fresh),
            "Sc RSS closed copy acquired new epoch or consumed PN",
        )?;
        run(guard.device().disassociate(), service)?.map_err(|_| "Sc RSS fenced teardown")?;
        drop(guard);

        // Public association cancellation has a different terminal outcome:
        // the before-await reset sentinel makes the persistent worker stop
        // and retain the native owner; a late marker cannot finish that join.
        let guard = setup()?;
        scan(guard.device())?;
        HARNESS.lock().as_mut().unwrap().1.hold_rx_queue = Some(2);
        let domain = he_tests::policy();
        let mut waiter = Box::pin(guard.device().associate_in_domain(request(true), &domain));
        progress_until(|| {
            require(
                waiter.as_mut().poll(&mut cx).is_pending(),
                "Sc cancelled RSS join passed held marker",
            )?;
            Ok(!HARNESS.lock().as_ref().unwrap().1.held_markers.is_empty())
        })?;
        drop(waiter);
        terminal(&guard)?;
        carrier(guard.device(), false).map_err(|_| "Sc cancelled RSS join left carrier open")?;
        {
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("Sc cancelled RSS stop retained state")?;
            require(
                state.needs_reset
                    && state.stop_completed
                    && state.hardware.is_failed()
                    && state.hardware.receive_queue_count() == 3
                    && state.hardware.receive_capture_epoch().is_none()
                    && model::retained(&state.hardware).1 != 0,
                "Sc cancelled RSS join failed bounded stop or released native rings",
            )?;
        }
        release_markers()?;
        let stale = ethernet(17);
        inject(1, 0xc1, 0, &payload(&stale, 22, 0, 100, 127))?;
        for _ in 0..4 {
            service()?;
            drain();
        }
        carrier(guard.device(), false)
            .map_err(|_| "Sc late RSS marker revived a cancelled join")?;
        require(!seen(&stale), "Sc cancelled RSS join delivered late data")?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/rx_queues",
    smoke_sc_rss_native_open_port_waits_all_real_ring_markers_and_drops_closed_copies
);

fn action(body: &[u8]) -> R {
    let mut frame = vec![0; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(body);
    HARNESS.lock().as_mut().unwrap().1.mpdu(&frame, false);
    Ok(())
}
fn smoke_sc_rss_native_baid_windows_are_per_ring_and_retire_after_all_prefixes() -> TestResult {
    check(|| {
        let guard = setup()?;
        ready(&guard)?;
        action(&[3, 0, 1, 2, 8, 0, 0, 0x40, 6])?; // immediate TID0/window32/SSN100
        progress_until(|| Ok(HARNESS.lock().as_ref().unwrap().1.baid_live))?;
        terminal(&guard)?;
        for (queue, sn, pn, marker) in [
            (1, 102, 12, 10),
            (2, 100, 5, 11),
            (1, 100, 10, 12),
            (1, 101, 11, 13),
            (2, 101, 6, 14),
        ] {
            let frame = ethernet(marker);
            inject(queue, 0xc1, 0, &payload(&frame, sn, 100, pn, 3))?;
            flush()?;
        }
        let delivered = {
            let slot = HARNESS.lock();
            slot.as_ref()
                .unwrap()
                .1
                .received
                .iter()
                .filter_map(|frame| {
                    (10..=14).find(|marker| frame.as_slice() == ethernet(*marker).as_slice())
                })
                .collect::<Vec<_>>()
        };
        require(
            delivered == [11, 12, 13, 10, 14],
            "Sc RSS BAID reorder/NSSN/PN crossed physical queues",
        )?;
        HARNESS.lock().as_mut().unwrap().1.hold_rx_queue = Some(2);
        action(&[3, 2, 0, 8, 0, 0])?; // originator DELBA TID0
        progress_until(|| Ok(!HARNESS.lock().as_ref().unwrap().1.held_markers.is_empty()))?;
        require(
            guard
                .device()
                .control
                .try_lock()
                .is_some_and(|control| control.is_some()),
            "Sc BAID retirement escaped final queue marker",
        )?;
        release_markers()?;
        terminal(&guard)?;
        // A retired BAID cannot deliver even a higher PN; a new native
        // allocation can reuse that identity only after the all-ring proof.
        let stale = ethernet(15);
        inject(2, 0xc1, 0, &payload(&stale, 102, 103, 100, 3))?;
        flush()?;
        require(!seen(&stale), "Sc retired RSS BAID delivered after remove")?;
        action(&[3, 0, 1, 2, 8, 0, 0, 0x40, 6])?;
        progress_until(|| Ok(HARNESS.lock().as_ref().unwrap().1.baid_live))?;
        terminal(&guard)?;
        let fresh = ethernet(16);
        inject(2, 0xc1, 0, &payload(&fresh, 100, 100, 7, 3))?;
        flush()?;
        require(seen(&fresh), "Sc RSS BAID identity failed safe reuse")?;
        run(guard.device().disassociate(), service)?.map_err(|_| "Sc RSS BAID teardown")?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/rx_queues",
    smoke_sc_rss_native_baid_windows_are_per_ring_and_retire_after_all_prefixes
);

fn inputs(
    profile: ReceiveModel,
) -> R<(crate::firmware_asset::Asset, crate::firmware_asset::Asset)> {
    let (write, read) = narf_firmware::bootstrap_authority();
    let mut bytes = super::super::super::firmware_parser_tests::mld_image();
    let mut table = super::super::super::firmware_parser_tests::mld_commands();
    he_tests::versions(&mut table);
    profile.commands(&mut table);
    require(
        word(&bytes, 88) == 48,
        "Sc RSS authored executable table tag",
    )?;
    let old = word(&bytes, 92) as usize;
    bytes.splice(96..96 + old.next_multiple_of(4), table.iter().copied());
    bytes[92..96].copy_from_slice(&(table.len() as u32).to_le_bytes());
    profile.capability(&mut bytes);
    for (name, payload) in [
        ("narf-test/iwl-rss/executable", bytes.as_slice()),
        ("narf-test/iwl-rss/pnvm", &[0x35u8; 32][..]),
    ] {
        crate::firmware_asset::tests::install(&write, name, payload, true)
            .map_err(|_| "Sc RSS source fixture install")?;
    }
    Ok((
        crate::firmware_asset::load(
            &read,
            "narf-test/iwl-rss/executable",
            16 * 1024 * 1024,
            true,
        )
        .map_err(|_| "Sc RSS executable source")?,
        crate::firmware_asset::load(&read, "narf-test/iwl-rss/pnvm", 64, true)
            .map_err(|_| "Sc RSS PNVM source")?,
    ))
}
fn smoke_sc_rss_native_dropped_waiter_and_revoked_config_receipt_pin_every_ring() -> TestResult {
    check(|| {
        for profile in [ReceiveModel::ExplicitV1, ReceiveModel::NativeSc] {
            let (executable, pnvm) = inputs(profile)?;
            let phy = PhyModel {
                width: 0,
                streams: 1,
                rates: 3,
                mcc_he: false,
                response_he: false,
            };
            let guard = Guard::build_features(
                true,
                Fault::HoldRfh,
                None,
                Some((&executable, &pnvm)),
                Some(phy),
                profile,
                None,
            )?;
            scan(guard.device())?;
            let domain = he_tests::policy();
            let mut waiter = Box::pin(guard.device().associate_in_domain(request(true), &domain));
            let mut cx = Context::from_waker(Waker::noop());
            progress_until(|| {
                require(
                    waiter.as_mut().poll(&mut cx).is_pending(),
                    "Sc RSS escaped held RFH config",
                )?;
                Ok(HARNESS.lock().as_ref().unwrap().1.held.is_some())
            })?;
            drop(waiter);
            executable.cap.revoke();
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let (cmd, group, sequence) =
                    wire.held.take().ok_or("Sc held RFH config missing")?;
                require(
                    (group, cmd) == (5, 0x0d),
                    "Sc RSS held another native command",
                )?;
                wire.fault = Fault::None;
                wire.firmware.inject(cmd, group, sequence, &[]);
            }
            terminal(&guard)?;
            carrier(guard.device(), false)?;
            let safe = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                !wire.m4
                    && wire.keys == 0
                    && wire.data.is_empty()
                    && !wire.commands.iter().any(|(g, c, _)| (*g, *c) == (1, 0xb3))
            };
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("Sc RSS failed owner retained state")?;
            require(
                safe && state.needs_reset
                    && state.hardware.is_failed()
                    && state.hardware.receive_queue_count() == 3
                    && state.hardware.receive_capture_epoch().is_none()
                    && model::retained(&state.hardware).0 != 0,
                "Sc RSS source loss released uncertain rings or programmed RSS/keys",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/rx_queues",
    smoke_sc_rss_native_dropped_waiter_and_revoked_config_receipt_pin_every_ring
);

fn smoke_sc_rss_native_actual_profile_unknown_version_and_malformed_receipt_stay_bounded(
) -> TestResult {
    check(|| {
        {
            let guard = setup_profile(ReceiveModel::Unsupported)?;
            scan(guard.device())?;
            run(
                guard
                    .device()
                    .associate_in_domain(request(true), &he_tests::policy()),
                service,
            )?
            .map_err(|_| "Sc unknown RX optimization blocked actual station")?;
            carrier(guard.device(), true)?;
            let single = {
                let state = guard
                    .device()
                    .state
                    .try_lock()
                    .ok_or("Sc unknown RX retained state")?;
                state.hardware.receive_queue_count() == 1
            };
            let quiet = {
                let slot = HARNESS.lock();
                !slot
                    .as_ref()
                    .unwrap()
                    .1
                    .commands
                    .iter()
                    .any(|(g, c, _)| matches!((*g, *c), (5, 0x0d) | (1, 0xb3)))
            };
            require(
                single && quiet,
                "Sc unsupported RX version published assumed RFH/RSS geometry",
            )?;
            run(guard.device().disassociate(), service)?
                .map_err(|_| "Sc unknown RX profile teardown")?;
        }
        for profile in [ReceiveModel::ExplicitV1, ReceiveModel::NativeSc] {
            let phy = PhyModel {
                width: 0,
                streams: 1,
                rates: 3,
                mcc_he: false,
                response_he: false,
            };
            let guard = Guard::build_features(
                true,
                Fault::MalformedRfh,
                None,
                None,
                Some(phy),
                profile,
                None,
            )?;
            scan(guard.device())?;
            require(
                run(
                    guard
                        .device()
                        .associate_in_domain(request(true), &he_tests::policy()),
                    service,
                )?
                .is_err(),
                "Sc malformed actual RFH receipt enabled station",
            )?;
            terminal(&guard)?;
            carrier(guard.device(), false)?;
            let safe = {
                let state = guard
                    .device()
                    .state
                    .try_lock()
                    .ok_or("Sc malformed RFH retained state")?;
                state.needs_reset
                    && state.hardware.is_failed()
                    && state.hardware.receive_queue_count() == 3
            };
            let stopped = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                !wire.m4
                    && wire.keys == 0
                    && wire.data.is_empty()
                    && !wire.commands.iter().any(|(g, c, _)| (*g, *c) == (1, 0xb3))
            };
            require(
                safe && stopped,
                "Sc malformed RFH freed published rings or continued to RSS/keys",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/rx_queues",
    smoke_sc_rss_native_actual_profile_unknown_version_and_malformed_receipt_stay_bounded
);
