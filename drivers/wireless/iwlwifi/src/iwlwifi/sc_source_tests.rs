//! Source/epoch boundaries through the real retained Sc DHCP/IP path. Only
//! the RAM fixture supplies post-INIT state; capabilities are real registry
//! objects and final publication executes the production source enclosure.
use super::*;
fn inputs() -> R<(crate::firmware_asset::Asset, crate::firmware_asset::Asset)> {
    super::super::super::runtime::source::tests::inputs()
}
fn setup(
    secured: bool,
    fault: Fault,
    firmware: &crate::firmware_asset::Asset,
    pnvm: &crate::firmware_asset::Asset,
) -> R<Guard> {
    let guard = Guard::build_named(secured, fault, None, Some((firmware, pnvm)))?;
    scan(guard.device())?;
    Ok(guard)
}
fn join(guard: &Guard, secured: bool) -> R {
    run(
        guard
            .device()
            .associate_in_domain(request(secured), &policy()),
        service,
    )?
    .map_err(|_| "Sc sourced native association")
}
fn downlink() -> Vec<u8> {
    udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        7,
        49152,
        b"Sc source boundary",
    )
}
fn held_join(
    guard: &Guard,
) -> R<core::pin::Pin<Box<impl Future<Output = Result<(), WirelessError>> + '_>>> {
    // The future borrows the explicit private policy below in ordinary code;
    // return only an owned future whose policy is retained inside it.
    let device = guard.device();
    let mut future = Box::pin(async move {
        let domain = policy();
        device.associate_in_domain(request(true), &domain).await
    });
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("sourced Sc M4 did not wait native receipt");
        }
        service()?;
        let held = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            wire.held_tx.is_some() || wire.held_rx.is_some()
        };
        if held {
            return Ok(future);
        }
        if deadline.expired() {
            return Err("sourced Sc held M4 setup bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
}
fn release_m4() -> R {
    let mut h = HARNESS.lock();
    let wire = &mut h.as_mut().ok_or("Sc source harness absent")?.1;
    let (queue, pointer) = wire.held_tx.take().ok_or("Sc held native M4 absent")?;
    wire.fault = Fault::None;
    wire.firmware.tx_complete(queue, pointer);
    Ok(())
}
fn smoke_iwl_sc_sourced_open_wpa2_native_dhcp_and_bidirectional_ip() -> TestResult {
    check(|| {
        for secured in [false, true] {
            let (firmware, pnvm) = inputs()?;
            let guard = setup(secured, Fault::None, &firmware, &pnvm)?;
            join(&guard, secured)?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "Sc sourced kernel DHCP")?;
            require(NETWORK.matches_lease(&lease), "Sc sourced lease terms")?;
            let frame = downlink();
            HARNESS.lock().as_mut().unwrap().1.ethernet(&frame);
            flush()?;
            require(
                HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                "Sc sourced IP callback absent",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_sourced_open_wpa2_native_dhcp_and_bidirectional_ip
);
fn smoke_iwl_sc_executable_pnvm_or_pci_revoke_after_m4_post_never_publishes() -> TestResult {
    check(|| {
        for which in 0..3 {
            let (firmware, pnvm) = inputs()?;
            let guard = setup(true, Fault::HoldM4, &firmware, &pnvm)?;
            let mut future = held_join(&guard)?;
            if which == 0 {
                firmware.cap.revoke();
            } else if which == 1 {
                pnvm.cap.revoke();
            } else {
                // Association owns state; capture the exact model PCI grant from
                // the independently retained publication fence through its test API.
                guard.device().source.revoke_model_pci();
            }
            release_m4()?;
            require(
                run(future.as_mut(), service)?.is_err(),
                "revoked sourced M4 reopened carrier",
            )?;
            drop(future);
            guard.device().step(None);
            let _new = inputs()?;
            guard.device().step(None);
            require(
                !guard.device().link_up() && guard.device().quarantined.load(Ordering::Acquire),
                "source reinstall revived closed Sc owner",
            )?;
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("sourced failed M4 state retained")?;
            require(
                model::retained(&state.hardware).1 == 2,
                "sourced failed M4 reclaimed uncertain DMA",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_executable_pnvm_or_pci_revoke_after_m4_post_never_publishes
);
fn smoke_iwl_sc_original_rx_delivery_is_fenced_again_at_actual_stack_callback() -> TestResult {
    check(|| {
        for which in 0..2 {
            let (firmware, pnvm) = inputs()?;
            let guard = setup(true, Fault::None, &firmware, &pnvm)?;
            join(&guard, true)?;
            HARNESS.lock().as_mut().unwrap().1.ethernet(&downlink());
            let output = guard.device().step(None);
            require(output.len() == 1, "sourced original RX packet missing")?;
            if which == 0 {
                firmware.cap.revoke();
            } else {
                pnvm.cap.revoke();
            }
            let mut called = false;
            require(
                output[0]
                    .invoke(|| {
                        called = true;
                        Ok(())
                    })
                    .is_err()
                    && !called,
                "stale source delivery callback invoked",
            )?;
            guard.device().dispatch(output);
            require(
                !guard.device().link_up() && guard.device().quarantined.load(Ordering::Acquire),
                "final callback failed to quarantine revoked source",
            )?;
            require(
                matches!(
                    guard.device().rx.lock().as_mut().unwrap().try_recv(),
                    Ok(None)
                ),
                "source close left old RX IPC frames",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_original_rx_delivery_is_fenced_again_at_actual_stack_callback
);
fn smoke_iwl_sc_original_delivery_after_close_cannot_retire_successor_epoch() -> TestResult {
    check(|| {
        let (firmware, pnvm) = inputs()?;
        let guard = setup(false, Fault::None, &firmware, &pnvm)?;
        join(&guard, false)?;
        HARNESS.lock().as_mut().unwrap().1.ethernet(&downlink());
        let output = guard.device().step(None);
        require(output.len() == 1, "old Sc delivery setup absent")?;
        let old = output[0].epoch;
        guard.device().set_link(false);
        let successor = guard.device().generation.load(Ordering::Acquire);
        // This republishes only the already completed native connection; it does
        // not synthesize another authentication/key or hardware authority.
        guard.device().publish_link(AP, successor)?;
        require(successor != old, "close did not retire publication epoch")?;
        guard.device().dispatch(output);
        require(
            guard.device().link_up() && !guard.device().quarantined.load(Ordering::Acquire),
            "old delivery downed successor publication",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_original_delivery_after_close_cannot_retire_successor_epoch
);
fn smoke_iwl_sc_callback_has_no_owner_ring_or_admission_guards_and_tx_full_retries() -> TestResult {
    check(|| {
        let (firmware, pnvm) = inputs()?;
        let guard = setup(false, Fault::None, &firmware, &pnvm)?;
        join(&guard, false)?;
        HARNESS.lock().as_mut().unwrap().1.ethernet(&downlink());
        let output = guard.device().step(None);
        require(output.len() == 1, "Sc reentrant callback setup absent")?;
        let uplink = udp_ipv4(
            AP,
            OWN,
            NETWORK.lease_ip,
            NETWORK.server_ip,
            49152,
            7,
            b"Sc reentrant reply",
        );
        output[0].invoke(|| {
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("callback retained owner lock")?;
            drop(state);
            let ring = guard
                .device()
                .rx
                .try_lock()
                .ok_or("callback retained RX ring lock")?;
            drop(ring);
            let admission = guard
                .device()
                .admission
                .try_lock()
                .ok_or("callback retained admission lock")?;
            drop(admission);
            guard
                .device()
                .enqueue(&uplink, narf_net::TxMeta::plain())
                .map_err(|_| "reentrant callback TX enqueue")
        })?;
        flush()?;
        require(
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .data
                .iter()
                .any(|(bytes, _)| bytes == &uplink),
            "reentrant native reply missing",
        )?;
        for _ in 0..TX_RING_N {
            guard
                .device()
                .enqueue(&uplink, narf_net::TxMeta::plain())
                .map_err(|_| "Sc ring capacity fixture")?;
        }
        require(
            guard
                .device()
                .enqueue(&uplink, narf_net::TxMeta::plain())
                .is_err()
                && guard.device().link_up()
                && !guard.device().quarantined.load(Ordering::Acquire),
            "ring-full confused with source revocation",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_callback_has_no_owner_ring_or_admission_guards_and_tx_full_retries
);

fn smoke_iwl_sc_native_m4_and_empty_marker_closed_copies_never_consume_successor_pn() -> TestResult
{
    check(|| {
        for fault in [Fault::HoldM4, Fault::HoldRxFence] {
            let (firmware, pnvm) = inputs()?;
            let guard = setup(true, fault, &firmware, &pnvm)?;
            let mut future = held_join(&guard)?;
            let frame = downlink();
            let pn_before = {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let before = wire.next_pn;
                wire.ethernet(&frame);
                before
            };
            // Exercise the retained native TX/fence waiter; the packet is
            // copied while admission is closed, before either terminal proof.
            for _ in 0..2 {
                narf_scheduler::block_on_spin(narf_time::sleep_cycles(
                    narf_time::wall::ns_to_cycles(2_000_000),
                ));
                require(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending(),
                    "closed native receive fixture unexpectedly finished",
                )?;
                service()?;
            }
            if fault == Fault::HoldM4 {
                release_m4()?;
            } else {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let cookie = wire
                    .held_rx
                    .take()
                    .ok_or("actual held EMPTY marker absent")?;
                let mut marker = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                marker[8..].copy_from_slice(&cookie.to_le_bytes());
                wire.fault = Fault::None;
                wire.firmware.inject(0xff, 5, 0x8000, &marker);
                // The suffix of this same DMA batch was also copied closed.
                wire.ethernet(&frame);
            }
            run(future.as_mut(), service)?.map_err(|_| "closed-copy native association failed")?;
            drop(future);
            flush()?;
            require(
                HARNESS.lock().as_ref().unwrap().1.received.is_empty(),
                "closed native packet escaped after M4/key receipts",
            )?;
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                wire.next_pn = pn_before;
                wire.ethernet(&frame);
            }
            flush()?;
            require(
                HARNESS.lock().as_ref().unwrap().1.received.as_slice() == [frame],
                "closed capture consumed successor PN or fresh native data was lost",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_native_m4_and_empty_marker_closed_copies_never_consume_successor_pn
);

fn group_challenge(fault: Fault) -> R {
    use narf_wireless::eapol::KeyFrame;
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().ok_or("Sc group harness absent")?.1;
    let ptk = wire
        .ptk
        .as_ref()
        .ok_or("Sc actual authenticator PTK absent")?;
    let mut clear = vec![221, 22, 0, 15, 172, 1, 2, 0];
    clear.extend_from_slice(&[0x88; 16]);
    let mut request = KeyFrame::empty(16);
    request.key_information = 0x1382; // ver2|ACK|MIC|SECURE|ENCRYPTED_KEY_DATA
    request.key_length = 16;
    request.replay_counter = 3;
    request.key_data = narf_crypto::aes_kw::aes_wrap(
        ptk.kek
            .as_slice()
            .try_into()
            .map_err(|_| "Sc actual group KEK extent")?,
        &clear,
    )
    .ok_or("Sc group authenticator AES wrap")?;
    super::super::super::handshake::install_mic(&mut request, &ptk.kck);
    let mut ethernet = OWN.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&request.into_eapol());
    wire.group_rekey = true;
    wire.fault = fault;
    wire.ethernet(&ethernet);
    Ok(())
}

fn smoke_iwl_sc_native_rekey_retires_actual_queued_ipc_before_wait_and_callback_successor(
) -> TestResult {
    check(|| {
        for fault in [Fault::None, Fault::HoldGroupReply] {
            let (firmware, pnvm) = inputs()?;
            let guard = setup(true, Fault::None, &firmware, &pnvm)?;
            join(&guard, true)?;
            let frame = downlink();
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                wire.ethernet(&frame);
                wire.ethernet(&frame);
            }
            let output = guard.device().step(None);
            require(output.len() == 2, "Sc queued native IPC setup absent")?;
            {
                let mut rx = guard.device().rx.lock();
                let first = rx
                    .as_mut()
                    .ok_or("Sc actual RX consumer absent")?
                    .try_recv()
                    .map_err(|_| "Sc original RX consumer closed")?
                    .ok_or("Sc original native IPC missing")?;
                require(first.payload() == frame, "Sc original native IPC identity")?;
                // The second genuine native packet stays queued until key work
                // retires this actual consumer, not merely Delivery callbacks.
            }
            let mut callbacks = 0;
            let mut failure = None;
            guard.device().dispatch_with(output, |_| {
                callbacks += 1;
                let result = (|| {
                    group_challenge(fault)?;
                    require(
                        guard.device().step(None).is_empty(),
                        "Sc rekey delivered ordinary control input",
                    )?;
                    require(
                        guard.device().rx.lock().is_none(),
                        "closed native key work left old IPC consumer",
                    )?;
                    if fault == Fault::HoldGroupReply {
                        let mut waiter = Box::pin(guard.device().finish_control());
                        let deadline = narf_time::Deadline::after_ms(3000);
                        loop {
                            require(
                                waiter
                                    .as_mut()
                                    .poll(&mut Context::from_waker(Waker::noop()))
                                    .is_pending(),
                                "held group reply skipped native terminal receipt",
                            )?;
                            service()?;
                            if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
                                break;
                            }
                            if deadline.expired() {
                                return Err("Sc native group reply setup bound");
                            }
                            narf_scheduler::sleep_pumps::run();
                        }
                        drop(waiter);
                        require(
                            guard
                                .device()
                                .control
                                .try_lock()
                                .is_some_and(|s| s.is_some())
                                && guard.device().state.try_lock().is_none()
                                && guard.device().rx.lock().is_none(),
                            "cancelled rekey waiter released owner/DMA or reopened old IPC",
                        )?;
                        release_m4()?; // releases only the observed native queue/pointer
                    }
                    run(guard.device().finish_control(), service)?;
                    require(
                        guard.device().link_up()
                            && !guard.device().quarantined.load(Ordering::Acquire),
                        "native GTK replacement did not retain current carrier",
                    )?;
                    let mut rx = guard.device().rx.lock();
                    require(
                        matches!(
                            rx.as_mut()
                                .ok_or("native successor RX consumer absent")?
                                .try_recv(),
                            Ok(None)
                        ),
                        "old queued native IPC packet escaped after actual key replacement",
                    )?;
                    Ok(())
                })();
                if let Err(error) = result {
                    failure = Some(error);
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
            require(
                callbacks == 1,
                "old receive batch invoked callback after replacement epoch",
            )?;
            {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                require(
                    wire.group_reply && wire.keys == 3,
                    "actual GTK native reply/key receipts missing",
                )?;
            }
            HARNESS.lock().as_mut().unwrap().1.ethernet(&frame);
            let fresh = guard.device().step(None);
            require(
                fresh.len() == 1,
                "successor native packet failed current source/PN",
            )?;
            let mut rx = guard.device().rx.lock();
            let actual = rx
                .as_mut()
                .ok_or("successor native IPC missing")?
                .try_recv()
                .map_err(|_| "successor RX IPC closed")?
                .ok_or("successor native IPC empty")?;
            require(actual.payload() == frame, "successor native IPC identity")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/source",
    smoke_iwl_sc_native_rekey_retires_actual_queued_ipc_before_wait_and_callback_successor
);
