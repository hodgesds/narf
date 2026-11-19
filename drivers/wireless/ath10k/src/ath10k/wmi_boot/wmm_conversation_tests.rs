//! Native WMI/CE/HTT WMM conversations, with literal IEEE/native reference data.
use super::*;
use narf_wireless::reg::RegFlags;

fn enable(h: &Harness) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
        f.wmm_response = Some(WMM_PARAMETERS.to_vec());
    });
}

fn retained(h: &Harness) -> bool {
    let radio = h.device.radio.try_lock().unwrap();
    radio.associated_station().is_none()
        && !radio.has_station_data()
        && radio.htt.wmi.htc.transport.inner.inner.retained.is_some()
        && radio
            .htt
            .wmi
            .htc
            .transport
            .inner
            .storage
            .as_ref()
            .unwrap()
            .filled
            == 1023
}

fn smoke_ath10k_wmm_native_six_dialects_open_wpa2_dhcp_ip() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for frequency in [2412, 5180] {
            for secured in [false, true] {
                if let Err(error) =
                    composition_profile(version, dialect, secured, false, true, frequency, true)
                {
                    return TestResult::Fail(error);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_native_six_dialects_open_wpa2_dhcp_ip
);

fn smoke_ath10k_wmm_uses_actual_association_contention() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        enable(&h);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let response = f.wmm_response.as_mut().unwrap();
            response[8] = 1; // New parameter set in the actual association response.
            response[10] = 4;
            response[11] = 0x93; // CWmin7, CWmax511, not beacon15/1023.
            f.wmm_words[0] = 7;
            f.wmm_words[1] = 511;
            f.wmm_words[2] = 4;
        });
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (uplink, _) = packets();
        if narf_net::iface::send_on(&h.name, &uplink).is_err() {
            return TestResult::Fail("response-bound QoS DATA did not enqueue");
        }
        h.pump();
        if !h.model(|m| {
            let f = m.data.as_ref().unwrap();
            f.wmm_sent == 1 && f.qos_frames == 1 && f.uplink.contains(&uplink)
        }) {
            return TestResult::Fail("native WMM ignored response or QoS HTT metadata");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_uses_actual_association_contention
);

fn smoke_ath10k_wmm_malformed_offer_and_sme_cannot_emit_management() -> TestResult {
    for case in 0..5 {
        let h = Harness::new(4, Dialect::Tlv, false);
        enable(&h);
        let mut request = h.request();
        h.model(|m| {
            let offer = m.data.as_mut().unwrap().wmm_offer.as_mut().unwrap();
            match case {
                0 => offer[10] |= 0x10, // BE requires TSPEC admission.
                1 => offer.extend_from_slice(&WMM_PARAMETERS),
                2 => offer[9] = 1,
                _ => {}
            }
        });
        if case == 3 {
            request.ie = vec![221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];
        } else if case == 4 {
            request.ie = WMM_PARAMETERS.to_vec();
        }
        if let Err(error) = h.scan() {
            return TestResult::Fail(error);
        }
        if !matches!(
            drive(h.device.associate_for_test(request, [0x73; 32])),
            Poll::Ready(Err(_))
        ) || !h.never_opened()
            || !h
                .model(|m| m.native_management.is_empty() && m.data.as_ref().unwrap().wmm_sent == 0)
        {
            return TestResult::Fail("malformed/caller-owned WMM emitted management or carrier");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_malformed_offer_and_sme_cannot_emit_management
);

fn smoke_ath10k_wmm_response_refusal_keeps_native_peer_and_dma_closed() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for case in 0..4 {
            let h = Harness::new(version, dialect, true);
            enable(&h);
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                match case {
                    0 => f.wmm_response = None,
                    1 => f.wmm_response.as_mut().unwrap()[10] |= 0x10,
                    2 => f
                        .wmm_response
                        .as_mut()
                        .unwrap()
                        .extend_from_slice(&WMM_PARAMETERS),
                    _ => f.wmm_response = Some(vec![221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0]),
                }
            });
            if let Err(error) = h.scan() {
                return TestResult::Fail(error);
            }
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || !retained(&h)
                || !h.model(|m| {
                    let f = m.data.as_ref().unwrap();
                    f.control_phase == 2 && f.wmm_sent == 0 && m.native_management.len() == 2
                })
            {
                return TestResult::Fail(
                    "unnegotiated WMM response enabled peer/port or released DMA",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_response_refusal_keeps_native_peer_and_dma_closed
);

fn smoke_ath10k_wmm_publication_cancel_failure_and_policy_loss_are_terminal() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for case in 0..4 {
            let h = Harness::new(version, dialect, true);
            enable(&h);
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.wmm_hold = case < 2;
                f.wmm_fail = case == 2;
                if case == 3 {
                    f.wmm_policy = Some(h.policy.clone());
                }
            });
            if let Err(error) = h.scan() {
                return TestResult::Fail(error);
            }
            {
                let mut future =
                    core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
                let result = drive(future.as_mut());
                if case >= 2 {
                    if !matches!(result, Poll::Ready(Err(_))) {
                        return TestResult::Fail("native WMM failure was ignored");
                    }
                } else {
                    if !result.is_pending() {
                        return TestResult::Fail("WMM publication did not hold the actual owner");
                    }
                    if case == 1 {
                        h.policy.lock().as_mut().unwrap().rules[0].flags = RegFlags::INDOOR_ONLY;
                        if !matches!(drive(future.as_mut()), Poll::Ready(Err(_))) {
                            return TestResult::Fail(
                                "policy loss during WMM credit wait was ignored",
                            );
                        }
                    }
                }
            }
            let before = h.model(|m| m.sent.len());
            *h.policy.lock() = Some(station_tests::policy());
            if !h.never_opened()
                || !retained(&h)
                || !h.model(|m| {
                    let f = m.data.as_ref().unwrap();
                    f.control_phase == 3 && f.wmm_sent == 1
                })
                || !matches!(
                    drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                    Poll::Ready(Err(_))
                )
                || h.model(|m| m.sent.len()) != before
            {
                return TestResult::Fail("failed/dropped WMM owner reopened or reused native DMA");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_publication_cancel_failure_and_policy_loss_are_terminal
);

fn smoke_ath10k_station_indoor_unknown_restrictions_cannot_emit_or_reopen() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for flags in [RegFlags::INDOOR_ONLY, RegFlags::from_bits_retain(1 << 31)] {
            let h = Harness::new(version, dialect, true);
            if let Err(error) = h.scan() {
                return TestResult::Fail(error);
            }
            h.policy.lock().as_mut().unwrap().rules[0].flags = flags;
            let before = h.model(|m| m.sent.len());
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || h.model(|m| m.sent.len()) != before
            {
                return TestResult::Fail("unqualified2GHz station rule emitted native TX");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_station_indoor_unknown_restrictions_cannot_emit_or_reopen
);

fn smoke_ath10k_live_indoor_restriction_discards_queued_data_before_native_tx() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        enable(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (uplink, _) = packets();
        if h.device
            .enqueue(&uplink, narf_net::TxMeta::plain())
            .is_err()
        {
            return TestResult::Fail("live-restriction fixture failed to queue DATA");
        }
        h.policy.lock().as_mut().unwrap().rules[0].flags = RegFlags::INDOOR_ONLY;
        let before = h.model(|m| m.sent.len());
        h.pump();
        *h.policy.lock() = Some(station_tests::policy());
        if !h.closed()
            || h.model(|m| m.sent.len()) != before
            || h.device.request_power_save(false) != Err(-19)
        {
            return TestResult::Fail(
                "live indoor restriction emitted QoS DATA or reopened carrier",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_live_indoor_restriction_discards_queued_data_before_native_tx
);

fn smoke_ath10k_wmm_native_qos_rx_binding_preserves_ccmp_pn() -> TestResult {
    for case in 0..2 {
        let h = Harness::new(4, Dialect::Tlv, true);
        enable(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (_, downlink) = packets();
        let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
        let wire = h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let wire = f.downlink(&downlink);
            let mut malformed = wire.clone();
            if case == 0 {
                f.next_tid = Some(7); // Native metadata does not match QoS TID0.
            } else {
                malformed[24] |= 0x80; // A-MSDU is not negotiated by this profile.
            }
            f.queue.push_back(malformed);
            wire
        });
        h.pump();
        if !h.device.link_up()
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before
        {
            return TestResult::Fail(
                "invalid native QoS binding delivered Ethernet or closed peer",
            );
        }
        h.model(|m| m.data.as_mut().unwrap().queue.push_back(wire));
        h.pump();
        if !h.received(&downlink)
            || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before + 1
        {
            return TestResult::Fail("rejected native QoS binding consumed a valid CCMP PN");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_native_qos_rx_binding_preserves_ccmp_pn
);

fn smoke_ath10k_wmm_held_m4_policy_loss_cannot_commit_keys_or_carrier() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    enable(&h);
    h.model(|m| m.data.as_mut().unwrap().hold_m4 = true);
    if let Err(error) = h.scan() {
        return TestResult::Fail(error);
    }
    {
        let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
        if !drive(future.as_mut()).is_pending() {
            return TestResult::Fail("native M4 was not awaiting its terminal receipt");
        }
        h.policy.lock().as_mut().unwrap().rules[0].flags = RegFlags::INDOOR_ONLY;
        if !matches!(drive(future.as_mut()), Poll::Ready(Err(_))) {
            return TestResult::Fail("held M4 waiter ignored current policy restriction");
        }
    }
    let before = h.model(|m| m.sent.len());
    if !h.model(|m| {
        m.inner.storage.as_ref().unwrap().tx.pending() == 1
            && m.inner.storage.as_ref().unwrap().filled == 1023
    }) {
        return TestResult::Fail("failed M4 waiter released uncertain native DMA");
    }
    *h.policy.lock() = Some(station_tests::policy());
    h.model(|m| {
        let id = m.data.as_mut().unwrap().held.pop_front().unwrap();
        complete(m, id, 0); // A late success cannot resurrect host authorization.
    });
    h.pump();
    if !h.never_opened()
        || h.model(|m| m.sent.len()) != before
        || h.device.request_power_save(false) != Err(-19)
    {
        return TestResult::Fail("late M4 receipt reopened restricted QoS keys or carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_held_m4_policy_loss_cannot_commit_keys_or_carrier
);

/// One Device worker pass: the synchronous drain, then its await point.
fn service(h: &Harness) {
    h.pump();
    let _ = drive(h.device.flush_management());
}

fn smoke_ath10k_wmm_beacon_parameter_set_change_reprograms_contention() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new(version, dialect, true);
        enable(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        // mac80211 ieee80211_sta_wmm_params: a new Parameter Set Count in a
        // beacon reaches ath10k_conf_tx for every AC.
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let offer = f.wmm_offer.as_mut().unwrap();
            offer[8] = 1;
            offer[10] = 4;
            offer[11] = 0x93; // BE CWmin7, CWmax511, AIFSN4.
            f.wmm_words[0] = 7;
            f.wmm_words[1] = 511;
            f.wmm_words[2] = 4;
            let beacon = f.beacon();
            management_frame(m, beacon);
        });
        service(&h);
        if h.closed() || !h.model(|m| m.data.as_ref().unwrap().wmm_sent == 2) {
            return TestResult::Fail("beacon WMM parameter-set change was not reprogrammed");
        }
        // The same count again is not a change.
        h.model(|m| {
            let beacon = m.data.as_ref().unwrap().beacon();
            management_frame(m, beacon);
        });
        service(&h);
        if h.closed() || !h.model(|m| m.data.as_ref().unwrap().wmm_sent == 2) {
            return TestResult::Fail("unchanged WMM parameter-set count was resent");
        }
        // A new set requiring BE admission control is refused like the
        // association response: the owner closes instead of programming it.
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let offer = f.wmm_offer.as_mut().unwrap();
            offer[8] = 2;
            offer[10] |= 0x10;
            let beacon = f.beacon();
            management_frame(m, beacon);
        });
        service(&h);
        if !h.closed() || !h.model(|m| m.data.as_ref().unwrap().wmm_sent == 2) {
            return TestResult::Fail("BE-ACM beacon parameter set was programmed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmm",
    smoke_ath10k_wmm_beacon_parameter_set_change_reprograms_contention
);
