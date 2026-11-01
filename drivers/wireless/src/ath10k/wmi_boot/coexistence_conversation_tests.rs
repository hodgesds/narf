//! Real retained CE/HTT/RSNA/netdev conversations for 2.4GHz20/40 SME.
use super::super::super::coexistence_native;
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::Ordering;
fn elements(primary: u8, above: bool) -> Vec<u8> {
    let mut ie = vec![45, 26, 0x6e, 0, 0x1b, 255];
    ie.extend_from_slice(&[0; 11]);
    ie.push(1);
    ie.extend_from_slice(&[0; 10]);
    ie.extend_from_slice(&[61, 22, primary, if above { 5 } else { 7 }]);
    ie.extend_from_slice(&[0; 20]);
    ie.extend_from_slice(&[74, 14, 20, 0, 10, 0, 10, 0, 200, 0, 20, 0, 5, 0, 25, 0]);
    ie
}
fn harness(
    version: u32,
    dialect: Dialect,
    protected: bool,
    primary: u16,
    secondary: u16,
) -> Harness {
    let h = Harness::new_on_inventory(
        version,
        dialect,
        protected,
        false,
        primary,
        0x64,
        (Some(0x803), 2, true),
    );
    let channels = h
        .device
        .radio
        .try_lock()
        .unwrap()
        .configured_channels()
        .to_vec();
    h.policy.lock().as_mut().unwrap().rules[0].max_bandwidth_mhz = 40;
    h.policy.lock().as_mut().unwrap().rules[0].freq_end_mhz = 2482;
    let ies = elements(((primary - 2407) / 5) as u8, secondary > primary);
    h.model(|m| {
        m.coexistence = Some(coexistence_native::Fixture::new(
            primary, secondary, channels,
        ));
        let f = m.data.as_mut().unwrap();
        f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
        f.wmm_response = Some(WMM_PARAMETERS.to_vec());
        f.ht_offer = Some(ies.clone());
        f.ht_response = Some(ies);
        f.ht_expected = true;
        f.ht_secondary = Some(secondary);
        f.ht_capabilities = 0x6e;
        f.ht_request_sgi40 = true;
        f.rx_phy = Some((8, 0x87, 0));
    });
    h
}
fn traffic(h: &Harness) -> Result<(), &'static str> {
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "2.4HT40 actual DORA")?;
    if !network().matches_lease(&lease) {
        return Err("2.4HT40 lease changed");
    }
    let (up, down) = packets();
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "2.4HT40 native enqueue")?;
    h.pump();
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&down);
        f.queue.push_back(frame);
    });
    h.pump();
    if !h.received(&down) || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
        return Err("2.4HT40 real native bidirectional IP");
    }
    Ok(())
}
fn trigger(h: &Harness) {
    h.model(|m| {
        m.coexistence.as_mut().unwrap().narrow = true;
        let mut frame = vec![0xd0, 0, 0, 0];
        frame.extend_from_slice(&OWN);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&[0, 0, 4, 0, 72, 1, 4]);
        super::super::super::management_frame(m, frame);
    });
    h.pump();
}
fn service(h: &Harness) -> Result<(), &'static str> {
    if !matches!(drive(h.device.flush_management()), Poll::Ready(Ok(()))) {
        return Err("coexistence management worker/native terminal");
    }
    Ok(())
}
fn smoke_ath10k_2ghz_ht40_native_six_dialects_both_extensions_rsn_dhcp_ip() -> TestResult {
    for (v, d) in BAND_DIALECTS {
        for (p, s) in [(2412, 2432), (2432, 2412)] {
            for protected in [false, true] {
                let result = (|| {
                    let h = harness(v, d, protected, p, s);
                    h.join()?;
                    service(&h)?;
                    let actual = h
                        .device
                        .radio
                        .try_lock()
                        .unwrap()
                        .prepared_peer()
                        .ok_or("2.4HT40 native peer missing")?;
                    if actual.bandwidth_mhz != 40
                        || actual.center_frequency != (p + s) / 2
                        || !h.model(|m| {
                            m.coexistence.as_ref().unwrap().scans == 1
                                && m.data
                                    .as_ref()
                                    .unwrap()
                                    .management_tx
                                    .iter()
                                    .any(|f| f.get(24..) == Some(&[4, 0, 72, 1, 0]))
                        })
                    {
                        return Err("40MHz clear OBSS did not precede actual native width/report");
                    }
                    traffic(&h)?;
                    h.model(|m| m.coexistence.as_mut().unwrap().periodic = true);
                    h.device
                        .radio
                        .try_lock()
                        .unwrap()
                        .expire_coexistence_for_test();
                    service(&h)?;
                    h.pump();
                    service(&h)?;
                    if !h.model(|m| {
                        m.coexistence.as_ref().unwrap().scans == 2
                            && !m.coexistence.as_ref().unwrap().periodic
                    }) || !h.device.link_up()
                    {
                        return Err("timed OBSS scan lacked matching terminal/home40 restore");
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
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_2ghz_ht40_native_six_dialects_both_extensions_rsn_dhcp_ip
);
fn smoke_ath10k_obss_preflight_legacy_selects_actual20_before_association() -> TestResult {
    for (v, d) in BAND_DIALECTS {
        let result = (|| {
            let h = harness(v, d, true, 2412, 2432);
            h.model(|m| m.coexistence.as_mut().unwrap().legacy = true);
            h.join()?;
            service(&h)?;
            let width = h
                .device
                .radio
                .try_lock()
                .unwrap()
                .prepared_peer()
                .ok_or("OBSS20 peer missing")?
                .bandwidth_mhz;
            if width != 20
                || h.model(|m| {
                    m.coexistence.as_ref().unwrap().restart
                        || m.data.as_ref().unwrap().ht_inventory != 0
                })
            {
                return Err("overlap fallback relabeled40 or restarted a never-wide owner");
            }
            traffic(&h)
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_obss_preflight_legacy_selects_actual20_before_association
);
fn smoke_ath10k_obss_native_one_way_restart_bounds_width_before_same_pn() -> TestResult {
    for (v, d) in BAND_DIALECTS {
        let result = (|| {
            let h = harness(v, d, true, 2412, 2432);
            h.join()?;
            service(&h)?;
            trigger(&h);
            service(&h)?;
            let p = h
                .device
                .radio
                .try_lock()
                .unwrap()
                .prepared_peer()
                .ok_or("narrowed actual native peer")?;
            if p.bandwidth_mhz != 20
                || p.center_frequency != 2412
                || !h.model(|m| {
                    m.coexistence.as_ref().unwrap().step == 5
                        && m.coexistence.as_ref().unwrap().restart
                })
            {
                return Err("coex width metadata preceded real20 RESTART/source words");
            }
            let (_, down) = packets();
            let wire = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.rx_phy = Some((8, 0x87, 0));
                f.queue.push_back(wire.clone());
            });
            h.pump();
            if h.received(&down) {
                return Err("old40 PPDU admitted after actual20 restart");
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.rx_phy = Some((8, 7, 0));
                f.queue.push_back(wire);
            });
            h.pump();
            if !h.received(&down) {
                return Err("rejected old40 PPDU burned valid20 same PN");
            }
            trigger(&h);
            service(&h)?;
            if h.model(|m| m.coexistence.as_ref().unwrap().step) != 5 {
                return Err("second trigger reused ambiguous unversioned RESTART");
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
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_obss_native_one_way_restart_bounds_width_before_same_pn
);
fn smoke_ath10k_obss_restart_old_start_and_drop_never_reopen_retained_owner() -> TestResult {
    for (v, d) in BAND_DIALECTS {
        let result = (|| {
            let h = harness(v, d, true, 2412, 2432);
            h.join()?;
            service(&h)?;
            h.model(|m| m.coexistence.as_mut().unwrap().hold_restart = true);
            let entered = h.model(|m| m.coexistence.as_ref().unwrap().entered.clone());
            let observed_steps =
                h.model(|m| m.coexistence.as_ref().unwrap().observed_steps.clone());
            trigger(&h);
            let mut future = Box::pin(h.device.flush_management());
            if drive(future.as_mut()).is_ready()
                || !entered.load(Ordering::Acquire)
                || observed_steps.load(Ordering::Acquire) != 4
            {
                return Err("old START/foreign RESTART satisfied held native type1");
            }
            drop(future);
            let link = h.device.radio.try_lock().unwrap().station_link();
            if !h.closed()
                || h.device.link_up()
                || link.is_some()
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
            {
                return Err("cancelled RESTART released/reopened native data/key/DMA");
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
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_obss_restart_old_start_and_drop_never_reopen_retained_owner
);
