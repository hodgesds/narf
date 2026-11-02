//! Existing Device/CE/HTT/RSNA paths under an explicit deployment assertion.
use super::*;
use narf_wireless::reg::RegFlags;

pub(super) fn install(h: &Harness) {
    let mut policy = h.policy.lock();
    for rule in &mut policy.as_mut().unwrap().rules {
        if rule.freq_start_mhz < u32::from(h.frequency) + 10
            && rule.freq_end_mhz > u32::from(h.frequency) - 10
        {
            rule.flags |= RegFlags::INDOOR_ONLY | RegFlags::DEPLOYMENT_INDOOR;
        }
    }
}

fn remove_fact(h: &Harness) {
    let mut policy = h.policy.lock();
    for rule in &mut policy.as_mut().unwrap().rules {
        rule.flags.remove(RegFlags::DEPLOYMENT_INDOOR);
    }
}

fn smoke_ath10k_indoor_native_six_dialects_active_passive_open_wpa2_dhcp_ip() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for frequency in [2412, 5180] {
            for secured in [false, true] {
                for active in [false, true] {
                    if let Err(error) = composition_radio(
                        version,
                        dialect,
                        secured,
                        active,
                        false,
                        frequency,
                        TestPhy::Indoor,
                    ) {
                        return TestResult::Fail(error);
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/indoor",
    smoke_ath10k_indoor_native_six_dialects_active_passive_open_wpa2_dhcp_ip
);

fn smoke_ath10k_indoor_actual_vht80_keeps_native_center_power_and_crypto() -> TestResult {
    for primary in [5180, 5240] {
        let h = Harness::new_on(4, Dialect::Tlv, true, false, primary, 0x8348);
        if let Err(error) = vht_conversation_tests::enable(&h, 2) {
            return TestResult::Fail(error);
        }
        install(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let prepared = h.device.radio.try_lock().unwrap().prepared_peer().unwrap();
        if prepared.frequency != primary
            || prepared.center_frequency != 5210
            || prepared.bandwidth_mhz != 80
        {
            return TestResult::Fail("indoor fact changed actual native80 center/width");
        }
        let lease = match narf_net::dhcp::dhcp_acquire(&h.name, 0) {
            Ok(lease) => lease,
            Err(_) => return TestResult::Fail("indoor80 native RSNA/DHCP failed"),
        };
        if !network().matches_lease(&lease) {
            return TestResult::Fail("indoor80 lease terms changed");
        }
        let (up, down) = packets();
        if narf_net::iface::send_on(&h.name, &up).is_err() {
            return TestResult::Fail("indoor80 native uplink enqueue failed");
        }
        h.pump();
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            let frame = f.downlink(&down);
            f.queue.push_back(frame);
        });
        h.pump();
        if !h.received(&down) || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
            return TestResult::Fail("indoor80 native encrypted DATA lost original ownership");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/indoor",
    smoke_ath10k_indoor_actual_vht80_keeps_native_center_power_and_crypto
);

fn smoke_ath10k_indoor_fact_loss_discards_actual_queued_data_and_stays_terminal() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new_on(version, dialect, true, false, 5180, 0x8348);
        install(&h);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let (up, _) = packets();
        if h.device.enqueue(&up, narf_net::TxMeta::plain()).is_err() {
            return TestResult::Fail("indoor live-policy fixture did not own queued DATA");
        }
        let before = h.model(|m| m.sent.len());
        remove_fact(&h);
        h.pump();
        install(&h);
        if !h.closed()
            || h.model(|m| m.sent.len()) != before
            || h.device.request_power_save(false) != Err(-19)
        {
            return TestResult::Fail("lost indoor fact emitted DATA or revived old native owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/indoor",
    smoke_ath10k_indoor_fact_loss_discards_actual_queued_data_and_stays_terminal
);

fn smoke_ath10k_indoor_fact_loss_during_native_credit_wait_cannot_publish_port() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let h = Harness::new_on(version, dialect, true, false, 5180, 0x8348);
        install(&h);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
            f.wmm_response = Some(WMM_PARAMETERS.to_vec());
            f.wmm_hold = true;
        });
        if let Err(error) = h.scan() {
            return TestResult::Fail(error);
        }
        {
            let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
            if !drive(future.as_mut()).is_pending() {
                return TestResult::Fail("indoor publication did not retain credit-wait owner");
            }
            remove_fact(&h);
            if !matches!(drive(future.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("indoor fact loss across actual credit wait was ignored");
            }
        }
        let before = h.model(|m| m.sent.len());
        install(&h);
        if !h.never_opened()
            || !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            )
            || h.model(|m| m.sent.len()) != before
        {
            return TestResult::Fail("failed indoor association resurrected original carrier");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/indoor",
    smoke_ath10k_indoor_fact_loss_during_native_credit_wait_cannot_publish_port
);
