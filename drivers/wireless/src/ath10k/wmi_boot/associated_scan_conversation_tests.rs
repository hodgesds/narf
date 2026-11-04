//! Associated dwell through the actual retained netdev, CE, HTT and RSNA.
//! The scan future is deliberately parked while DHCP/IP use the normal drain.
use super::super::super::associated_scan_tests as firmware_scan;
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

fn request(active: bool, frequencies: &[u16]) -> ScanRequest {
    ScanRequest {
        ssids: vec![b"narf".to_vec()],
        frequencies_mhz: frequencies.iter().copied().map(u32::from).collect(),
        channels: Vec::new(),
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn arm(h: &Harness, dialect: Dialect, width: u8, active: bool, frequencies: &[u16]) {
    let receive = h
        .device
        .radio
        .try_lock()
        .unwrap()
        .configured_channels()
        .to_vec();
    h.model(|m| {
        m.associated = Some(firmware_scan::Fixture::new(
            dialect,
            &receive,
            h.frequency,
            width,
            frequencies,
            active,
        ))
    });
}
fn hold<F: Future>(h: &Harness, mut operation: Pin<&mut F>) -> Result<(), &'static str> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("scan completed before native terminal");
        }
        if let Some(radio) = h.device.radio.try_lock() {
            if radio
                .htt
                .wmi
                .htc
                .transport
                .associated
                .as_ref()
                .is_some_and(|f| f.started)
            {
                return Ok(());
            }
        }
    }
    Err("associated scan did not release owner during dwell")
}
fn finish<F: Future<Output = Result<Vec<narf_wireless::BssInfo>, WirelessError>>>(
    h: &Harness,
    operation: Pin<&mut F>,
) -> Result<(), &'static str> {
    h.model(firmware_scan::complete);
    if !matches!(drive(operation), Poll::Ready(Ok(_)))
        || !h.model(|m| m.associated.as_ref().unwrap().done)
        || h.device.radio.try_lock().unwrap().scan_in_progress()
        || !h.device.link_up()
    {
        return Err("matched scan completion/home restore lost retained station");
    }
    Ok(())
}
fn offchannel_beacon(h: &Harness) {
    h.model(|m| {
        let mut frame = m.data.as_ref().unwrap().beacon();
        frame[10] = 4;
        frame[16] = 4;
        let mut at = 36;
        while at + 2 <= frame.len() {
            let len = usize::from(frame[at + 1]);
            if frame[at] == 3 {
                frame[at + 2] = 6;
            }
            at += 2 + len;
        }
        let previous = m.frequency;
        m.frequency = 2437;
        super::super::super::management_frame(m, frame);
        m.frequency = previous;
    });
}
fn traffic(h: &Harness) -> Result<(), &'static str> {
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0)
        .map_err(|_| "DHCP stalled behind associated scan owner")?;
    if !network().matches_lease(&lease) {
        return Err("associated scan DHCP lease changed");
    }
    let (up, down) = packets();
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "associated scan host TX enqueue")?;
    h.pump();
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&down);
        f.queue.push_back(frame);
    });
    h.pump();
    if !h.received(&down)
        || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up))
        || !h.device.link_up()
    {
        return Err("associated dwell did not deliver both native IP directions");
    }
    Ok(())
}
fn smoke_ath10k_associated_scan_six_dialects_open_wpa2_dhcp_ip_and_home_cache() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for secured in [false, true] {
            for active in [false, true] {
                let result = (|| {
                    let h = Harness::new_scan(version, dialect, secured, true);
                    h.join()?;
                    arm(&h, dialect, 0, active, &[2412, 2437]);
                    let mut operation = Box::pin(h.device.scan(request(active, &[2412, 2437])));
                    hold(&h, operation.as_mut())?;
                    offchannel_beacon(&h);
                    traffic(&h)?;
                    if !matches!(
                        drive(h.device.scan(request(active, &[2412]))),
                        Poll::Ready(Err(WirelessError::Busy | WirelessError::HardwareError))
                    ) {
                        return Err("concurrent scan reused native request owner");
                    }
                    finish(&h, operation.as_mut())?;
                    if h.device
                        .radio
                        .try_lock()
                        .unwrap()
                        .information_elements(AP)
                        .is_none()
                    {
                        return Err("off-channel report erased associated home beacon identity");
                    }
                    Ok(())
                })();
                if let Err(e) = result {
                    return TestResult::Fail(e);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_six_dialects_open_wpa2_dhcp_ip_and_home_cache
);

fn smoke_ath10k_associated_scan_drop_retains_exact_stop_and_native_peer_teardown() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let result = (|| {
            let h = Harness::new_scan(version, dialect, true, true);
            h.join()?;
            arm(&h, dialect, 0, true, &[2412, 2437]);
            let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
            hold(&h, operation.as_mut())?;
            drop(operation);
            h.model(|m| teardown_tests::arm_data_disconnect(m, false));
            if !h.closed()
                || !matches!(drive(h.device.cleanup_failed_scan()), Poll::Ready(Ok(true)))
                || !h.model(|m| {
                    m.associated.as_ref().unwrap().stopped
                        && teardown_tests::data_disconnect_completed(m)
                        && m.ce.as_ref().unwrap().retained()
                })
                || h.device.link_up()
            {
                return Err("dropped scan lost exact firmware STOP/delete/unmap/vdev receipts");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_drop_retains_exact_stop_and_native_peer_teardown
);

fn smoke_ath10k_associated_scan_disassociate_defers_delete_to_retained_worker() -> TestResult {
    let result = (|| {
        let h = Harness::new_scan(4, Dialect::Tlv, true, true);
        h.join()?;
        arm(&h, Dialect::Tlv, 0, true, &[2412, 2437]);
        let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
        hold(&h, operation.as_mut())?;
        let before = h.model(|m| m.sent.len());
        if !matches!(
            drive(h.device.disassociate()),
            Poll::Ready(Err(WirelessError::Busy))
        ) || !h.closed()
            || h.model(|m| m.sent.len()) != before
        {
            return Err("disassociate submitted native DELETE before scan terminal");
        }
        if !matches!(drive(operation.as_mut()), Poll::Ready(Err(_))) {
            return Err("closed host scan retained a public result");
        }
        drop(operation);
        h.model(|m| teardown_tests::arm_data_disconnect(m, false));
        if !matches!(drive(h.device.cleanup_failed_scan()), Poll::Ready(Ok(true)))
            || !matches!(drive(h.device.disassociate()), Poll::Ready(Ok(())))
        {
            return Err("retained scan stop failed to finish pending disassociation");
        }
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_disassociate_defers_delete_to_retained_worker
);

fn smoke_ath10k_associated_scan_retired_generation_cannot_continue_cleanup() -> TestResult {
    for during_stop in [false, true] {
        let result = (|| {
            let h = Harness::new_scan(4, Dialect::Tlv, true, true);
            h.join()?;
            arm(&h, Dialect::Tlv, 0, true, &[2412, 2437]);
            let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
            hold(&h, operation.as_mut())?;
            drop(operation);
            let before = h.model(|m| m.sent.len());
            if during_stop {
                h.model(|m| m.associated.as_mut().unwrap().stall = Some(4));
                let mut cleanup = Box::pin(h.device.cleanup_failed_scan());
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..16 {
                    if cleanup.as_mut().poll(&mut cx).is_ready() {
                        return Err("retirement fixture failed to hold native STOP source");
                    }
                }
                h.device.retire_host();
                if !matches!(
                    drive(cleanup.as_mut()),
                    Poll::Ready(Err(radio::Error::Failed))
                ) {
                    return Err("retired generation continued its pending source waiter");
                }
                drop(cleanup);
            } else {
                h.device.retire_host();
            }
            let after = h.model(|m| m.sent.len());
            if after != before + usize::from(during_stop)
                || !matches!(
                    drive(h.device.cleanup_failed_scan()),
                    Poll::Ready(Ok(false))
                )
                || h.model(|m| m.sent.len()) != after
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
            {
                return Err("late cleanup touched retired hardware or released uncertain DMA");
            }
            Ok(())
        })();
        if let Err(error) = result {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_retired_generation_cannot_continue_cleanup
);

fn smoke_ath10k_associated_scan_final_callback_rechecks_probe_permission() -> TestResult {
    let result = (|| {
        let mut h = Harness::new_scan(4, Dialect::Tlv, true, true);
        let remaining = Arc::new(AtomicUsize::new(usize::MAX));
        let scripted = remaining.clone();
        let policy = h.policy.clone();
        let device = Arc::new(Device::for_test(
            &h.name,
            OWN,
            h.device.radio.clone(),
            move || {
                let mut domain = policy.lock().clone()?;
                let count = scripted.load(Ordering::Acquire);
                if count == 0 {
                    domain.rules.push(narf_wireless::reg::RegRule {
                        freq_start_mhz: 2427,
                        freq_end_mhz: 2447,
                        max_bandwidth_mhz: 20,
                        max_power_dbm: 17,
                        flags: narf_wireless::reg::RegFlags::NO_IR,
                    });
                } else if count != usize::MAX {
                    scripted.fetch_sub(1, Ordering::AcqRel);
                }
                Some(domain)
            },
        ));
        narf_net::iface::register_with_context(&h.name, OWN, device.generation_for_test(), send);
        *ACTIVE_TEST.lock() = Some(device.clone());
        h.device = device;
        h.join()?;
        arm(&h, Dialect::Tlv, 0, true, &[2437]);
        let mut operation = Box::pin(h.device.scan(request(true, &[2437])));
        hold(&h, operation.as_mut())?;
        let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
        h.device.set_receive_hook_for_test(move |point| {
            if point == crate::ath10k::interface::ReceivePoint::BeforeCallbackAdmission {
                // The Radio admission sees the old policy; only the final
                // copied callback read loses the off-channel probe grant.
                remaining.store(1, Ordering::Release);
            }
        });
        let (_, down) = packets();
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let frame = f.downlink(&down);
            f.queue.push_back(frame);
        });
        h.pump();
        if !h.closed() || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before {
            return Err(
                "final callback ignored revoked probe permission while home remained allowed",
            );
        }
        drop(operation);
        h.model(|m| teardown_tests::arm_data_disconnect(m, false));
        if !matches!(drive(h.device.cleanup_failed_scan()), Poll::Ready(Ok(true))) {
            return Err("final callback policy loss did not retain native scan STOP");
        }
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_final_callback_rechecks_probe_permission
);

fn smoke_ath10k_associated_scan_cpu_poll_count_cannot_expire_valid_dwell() -> TestResult {
    let result = (|| {
        let h = Harness::new_scan(4, Dialect::Tlv, false, true);
        h.join()?;
        arm(&h, Dialect::Tlv, 0, true, &[2437]);
        let mut operation = Box::pin(h.device.scan(request(true, &[2437])));
        hold(&h, operation.as_mut())?;
        let started = narf_time::wall::monotonic_ns();
        let mut cx = Context::from_waker(Waker::noop());
        for poll in 0..70_000 {
            if poll % 128 == 0 {
                h.model(|m| {
                    let frame = m.data.as_ref().unwrap().beacon();
                    super::super::super::management_frame(m, frame);
                });
            }
            if operation.as_mut().poll(&mut cx).is_ready() {
                if narf_time::wall::monotonic_ns().saturating_sub(started) >= 24_000_000_000 {
                    return Ok(false); // Environment cannot exercise the early CPU-count boundary.
                }
                return Err("CPU polling exhausted a valid scan before its actual deadline");
            }
        }
        finish(&h, operation.as_mut())?;
        Ok(true)
    })();
    match result {
        Ok(true) => TestResult::Pass,
        Ok(false) => TestResult::Skip("emulated polling reached the actual scan deadline"),
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_cpu_poll_count_cannot_expire_valid_dwell
);

fn smoke_ath10k_registered_unassociated_scan_drop_preserves_wmi_stop_owner() -> TestResult {
    let result = (|| {
        let h = Harness::new_scan(4, Dialect::Tlv, false, true);
        h.model(|m| {
            let scan = m.active.as_mut().unwrap();
            scan.extra_ies.clear();
            scan.hold_terminal = true;
            scan.hold_start_source();
        });
        let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("unassociated scan did not hold its actual START CE receipt");
            }
        }
        drop(operation);
        if !h.never_opened() || !h.model(|m| m.active.as_ref().unwrap().is_started()) {
            return Err("unassociated cancellation fixture did not publish START");
        }
        h.model(|m| m.ce.as_mut().unwrap().hold_source(false));
        if !matches!(drive(h.device.cleanup_failed_scan()), Poll::Ready(Ok(true)))
            || !h.model(|m| {
                m.active.as_ref().unwrap().is_stopped() && m.ce.as_ref().unwrap().retained()
            })
        {
            return Err("unassociated public drop poisoned away retained native STOP");
        }
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_registered_unassociated_scan_drop_preserves_wmi_stop_owner
);

fn smoke_ath10k_associated_scan_missing_terminal_does_not_delete_or_reclaim() -> TestResult {
    let h = Harness::new_scan(4, Dialect::Tlv, true, true);
    if let Err(e) = h.join() {
        return TestResult::Fail(e);
    }
    arm(&h, Dialect::Tlv, 0, true, &[2412, 2437]);
    h.model(|m| m.associated.as_mut().unwrap().stop_receipt = false);
    let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
    if let Err(e) = hold(&h, operation.as_mut()) {
        return TestResult::Fail(e);
    }
    drop(operation);
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    let mut cleanup = Box::pin(h.device.cleanup_failed_scan());
    let mut result = drive(cleanup.as_mut());
    if result.is_pending() {
        result = drive(cleanup.as_mut());
    }
    if !matches!(result, Poll::Ready(Err(radio::Error::Timeout)))
        || !h.closed()
        || !h.model(|m| {
            m.associated.as_ref().unwrap().stopped
                && !teardown_tests::data_disconnect_completed(m)
                && m.ce.as_ref().unwrap().retained()
        })
    {
        return TestResult::Fail(
            "STOP publication or foreign terminal was treated as idle/DMA receipt",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_missing_terminal_does_not_delete_or_reclaim
);

fn smoke_ath10k_associated_scan_live_probe_or_home_restriction_quiesces_without_restore(
) -> TestResult {
    for fault in 0..4 {
        let result = (|| {
            let h = Harness::new_scan(4, Dialect::Tlv, true, true);
            h.join()?;
            arm(&h, Dialect::Tlv, 0, true, &[2437]);
            let mut operation = Box::pin(h.device.scan(request(true, &[2437])));
            hold(&h, operation.as_mut())?;
            {
                let mut policy = h.policy.lock();
                let domain = policy.as_mut().unwrap();
                match fault {
                    0 => domain.rules.push(narf_wireless::reg::RegRule {
                        freq_start_mhz: 2427,
                        freq_end_mhz: 2447,
                        max_bandwidth_mhz: 20,
                        max_power_dbm: 9,
                        flags: narf_wireless::reg::RegFlags::empty(),
                    }),
                    1 => domain.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR,
                    2 => domain.country_code = *b"CA",
                    _ => domain.rules.clear(),
                }
            }
            let before = h.model(|m| m.sent.len());
            h.pump();
            if !h.closed() || !matches!(drive(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("changed scan probe/home policy kept autonomous owner live");
            }
            drop(operation);
            h.model(|m| teardown_tests::arm_data_disconnect(m, false));
            if !matches!(drive(h.device.cleanup_failed_scan()), Poll::Ready(Ok(true)))
                || h.model(|m| m.sent.len()) != before + 4
            {
                return Err("policy loss restored obsolete power/inventory instead of STOP/DOWN/DELETE/STOP");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_live_probe_or_home_restriction_quiesces_without_restore
);

fn smoke_ath10k_associated_scan_each_setup_drop_and_restore_drop_retains_owner() -> TestResult {
    for publication in 0..=4 {
        let result = (|| {
            let h = Harness::new_scan(4, Dialect::Tlv, true, true);
            h.join()?;
            arm(&h, Dialect::Tlv, 0, true, &[2412, 2437]);
            h.model(|m| m.associated.as_mut().unwrap().stall = Some(publication));
            let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
            if publication == 4 {
                hold(&h, operation.as_mut())?;
                h.model(firmware_scan::complete);
            }
            if !drive(operation.as_mut()).is_pending() {
                return Err("native publication cancellation fixture did not hold");
            }
            drop(operation);
            let before = h.model(|m| m.sent.len());
            // STOP must first wait for the old source's actual device CE
            // receipt. The model checks every byte of that owned bounce on
            // three waiting polls before advancing native CURRENT_SRRI.
            h.model(|m| {
                let bytes = m.ce.as_ref().unwrap().source_bytes(3);
                m.associated.as_mut().unwrap().release_after_ready = Some((3, bytes));
            });
            h.model(|m| teardown_tests::arm_data_disconnect(m, false));
            if !h.closed()
                || !matches!(drive(h.device.cleanup_failed_scan()), Poll::Ready(Ok(true)))
                || !h.model(|m| {
                    teardown_tests::data_disconnect_completed(m)
                        && m.ce.as_ref().unwrap().retained()
                })
                || h.model(|m| m.sent.len()) != before + if publication == 4 { 3 } else { 4 }
            {
                return Err(
                    "cancelled setup/restore reused firmware owner or forgot terminal proof",
                );
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_each_setup_drop_and_restore_drop_retains_owner
);

fn smoke_ath10k_associated_scan_rekey_keeps_native_reply_gate_and_carrier() -> TestResult {
    let result = (|| {
        let h = Harness::new_scan(4, Dialect::Tlv, true, true);
        h.join()?;
        arm(&h, Dialect::Tlv, 0, true, &[2412, 2437]);
        let mut operation = Box::pin(h.device.scan(request(true, &[2412, 2437])));
        hold(&h, operation.as_mut())?;
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.hold_data = true;
            let group = f.group_rekey();
            f.queue.push_back(group);
        });
        h.pump();
        let before = h.model(|m| m.data.as_ref().unwrap().uplink.len());
        let (up, _) = packets();
        narf_net::iface::send_on(&h.name, &up).map_err(|_| "scan rekey host enqueue")?;
        h.pump();
        if !h.device.link_up()
            || h.device
                .radio
                .try_lock()
                .unwrap()
                .data_permission()
                .is_some()
            || h.model(|m| m.data.as_ref().unwrap().uplink.len()) != before
        {
            return Err("scan dwell bypassed rekey receipt gate or flapped carrier");
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.hold_data = false;
            let id = f.held.pop_front().unwrap();
            complete(m, id, 0);
        });
        h.pump();
        if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
            return Err("scan rekey receipt did not release queued host data");
        }
        finish(&h, operation.as_mut())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_rekey_keeps_native_reply_gate_and_carrier
);

fn smoke_ath10k_associated_scan_ht40_vht80_inventory_and_ba_survive_dwell() -> TestResult {
    for width in [40, 80] {
        let result = (|| {
            let h = Harness::new_on(4, Dialect::Tlv, true, false, 5180, 0x8348);
            if width == 40 {
                ht40_conversation_tests::enable(&h)?;
            } else {
                vht_conversation_tests::enable(&h, 2)?;
            }
            h.join()?;
            arm(&h, Dialect::Tlv, width, true, &[2412]);
            let mut operation = Box::pin(h.device.scan(request(true, &[2412])));
            hold(&h, operation.as_mut())?;
            h.model(|m| m.data.as_mut().unwrap().receive_sequence = Some(0));
            h.model(|m| {
                m.inner
                    .inner
                    .rx
                    .push_back((m.inner.receive_pipe, header(1, &[5, 8, 0x80, 0x70])))
            }); // peer1800/TID0
            h.pump();
            if h.device.radio.try_lock().unwrap().receive_ba_for_test(0) != Some((1800, 8, 0, None))
            {
                return Err("scan dwell bypassed exact native HTT BA owner");
            }
            traffic(&h)?;
            finish(&h, operation.as_mut())?;
            if h.device
                .radio
                .try_lock()
                .unwrap()
                .receive_ba_for_test(0)
                .is_none()
            {
                return Err("scan restore erased native BA agreement");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/associated-scan",
    smoke_ath10k_associated_scan_ht40_vht80_inventory_and_ba_survive_dwell
);
