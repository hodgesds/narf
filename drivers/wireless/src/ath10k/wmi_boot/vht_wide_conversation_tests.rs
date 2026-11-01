//! Actual READY/INIT/CE/HTT/RSNA/netdev80+80 fixtures. Native expected words
//! are authored from Linux core/mac/WMI, not the driver's new geometry helper.
use super::*;
use alloc::boxed::Box;
const SOURCE: u32 = 0x0180_0068; // actual VHT-SGI80/160, widthSet2, exponent3.
fn pair(f: u16) -> u16 {
    if matches!(f, 5180 | 5220 | 5745 | 5785) {
        f + 20
    } else {
        f - 20
    }
}
fn centers(primary: u16) -> (u16, u16) {
    if primary < 5500 {
        (5210, 5775)
    } else {
        (5775, 5210)
    }
}
fn elements(primary: u16, deprecated: bool) -> Vec<u8> {
    let mut v = vec![45, 26, 0x6e, 0, 0x1b];
    v.extend_from_slice(&[255; 4]);
    v.extend_from_slice(&[0; 8]);
    v.push(1);
    v.extend_from_slice(&[0; 10]);
    v.extend_from_slice(&[
        61,
        22,
        ((primary - 5000) / 5) as u8,
        if pair(primary) > primary { 5 } else { 7 },
    ]);
    v.extend_from_slice(&[0; 20]);
    v.extend_from_slice(&[191, 12]);
    v.extend_from_slice(&SOURCE.to_le_bytes());
    v.extend_from_slice(&[0xaa, 0xff, 0x18, 6, 0xaa, 0xff, 0x18, 6]);
    let (first, second) = centers(primary);
    v.extend_from_slice(&[
        192,
        5,
        if deprecated { 3 } else { 1 },
        ((first - 5000) / 5) as u8,
        ((second - 5000) / 5) as u8,
        0xfc,
        0xff,
    ]);
    v
}
fn expected(h: &Harness, wide: bool, source: u32, hardware: HwRev) {
    let chains = if matches!(hardware, HwRev::Qca9984 | HwRev::Qca99x0) {
        4
    } else {
        2
    };
    let nss = if wide {
        if hardware == HwRev::Qca9888 {
            1
        } else {
            2
        }
    } else {
        chains
    };
    let map = (0..nss).fold(0xffffu16, |m, i| (m & !(3 << (i * 2))) | (2 << (i * 2)));
    let mut request = [0; 12];
    request[..4].copy_from_slice(&(if wide { source } else { source & !0x4c }).to_le_bytes());
    request[4..6].copy_from_slice(&map.to_le_bytes());
    request[8..10].copy_from_slice(&map.to_le_bytes());
    let (_, second) = centers(h.frequency);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.ht_request_nss = chains;
        f.ht_mcs_more = if chains == 4 { [255; 3] } else { [255, 0, 0] };
        f.ht_capabilities = 0x6e;
        f.ht_request_sgi40 = true;
        f.ht_peer_nss = u32::from(nss);
        f.ht_rate_caps = if chains == 4 { 0x200 } else { 1 };
        f.vht = Some(Box::new(VhtExpect {
            width: if wide { 3 } else { 2 },
            center2: wide.then_some(second),
            wide_override: if wide {
                0x8000_0000 | u32::from(nss - 1) | (u32::from(nss - 1) << 3)
            } else {
                0
            },
            half_dbm: 54,
            request,
            capabilities: if wide { source } else { source & !0x4c },
            rates: [1560, u32::from(map), 1560, u32::from(map)],
            max_mpdu: 65535,
        }));
        f.rx_phy = Some((
            12,
            (if wide { 3 } else { 2 }) | (u32::from(nss - 1) << 10),
            0x90 | u32::from(!wide || source & 64 != 0),
        ));
    });
}
fn harness(
    hardware: HwRev,
    primary: u16,
    deprecated: bool,
    protected: bool,
    source: u32,
) -> Harness {
    let chains = if matches!(hardware, HwRev::Qca9984 | HwRev::Qca99x0) {
        4
    } else {
        2
    };
    let h = Harness::new_on_source(
        6,
        Dialect::TenFour,
        protected,
        false,
        primary,
        0x8348,
        (
            Some(0x803),
            RadioSource {
                hardware,
                rf_chains: chains,
                vht: Some((source, if chains == 4 { 0xffaa } else { 0xfffa })),
            },
            true,
        ),
    );
    for rule in &mut h.policy.lock().as_mut().unwrap().rules {
        if rule.freq_start_mhz > 3000 {
            rule.max_bandwidth_mhz = 80;
        }
    }
    let ie = elements(primary, deprecated);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
        f.wmm_response = Some(WMM_PARAMETERS.to_vec());
        f.ht_offer = Some(ie.clone());
        f.ht_response = Some(ie);
        f.ht_expected = true;
        f.ht_secondary = Some(pair(primary));
    });
    expected(
        &h,
        hardware != HwRev::Qca99x0 && source & 12 == 8,
        source,
        hardware,
    );
    h
}
fn traffic(h: &Harness) -> Result<(), &'static str> {
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "80+80 actual native DORA")?;
    if !network().matches_lease(&lease) {
        return Err("80+80 DHCP identity");
    }
    let (up, down) = packets();
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "80+80 TX enqueue")?;
    h.pump();
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let wire = f.downlink(&down);
        f.queue.push_back(wire);
    });
    h.pump();
    if !h.received(&down) || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
        return Err("80+80 native bidirectional IP");
    }
    Ok(())
}
fn smoke_ath10k_80p80_actual_chip_nss_two_spans_open_wpa2_dhcp_ip() -> TestResult {
    for hardware in [HwRev::Qca9984, HwRev::Qca9888] {
        for primary in [5180, 5745] {
            for deprecated in [false, true] {
                for protected in [false, true] {
                    let result = (|| {
                        let h = harness(hardware, primary, deprecated, protected, SOURCE);
                        if primary == 5745 {
                            for rule in &mut h.policy.lock().as_mut().unwrap().rules {
                                if (3000..5500).contains(&rule.freq_start_mhz) {
                                    rule.max_power_dbm = 9;
                                }
                            }
                            h.model(|m| {
                                m.data.as_mut().unwrap().vht.as_mut().unwrap().half_dbm = 18
                            });
                        }
                        let (raw_caps, raw_mcs, service) = {
                            let radio = h.device.radio.try_lock().unwrap();
                            let caps = radio.htt.wmi.caps.as_ref().unwrap();
                            (caps.vht, caps.vht_mcs, caps.service(Dialect::TenFour, 8))
                        };
                        if !service
                            || raw_caps != SOURCE
                            || raw_mcs
                                != if hardware == HwRev::Qca9984 {
                                    0xffaa
                                } else {
                                    0xfffa
                                }
                        {
                            return Err(
                                "wide capability did not originate in actual native SERVICE_READY",
                            );
                        }
                        h.join()?;
                        let actual = h
                            .device
                            .radio
                            .try_lock()
                            .unwrap()
                            .prepared_peer()
                            .ok_or("80+80 prepared receipt")?;
                        let (first, second) = centers(primary);
                        if actual.bandwidth_mhz != 160
                            || actual.center_frequency != first
                            || actual.second_center_frequency != Some(second)
                            || actual.maximum_power_dbm != if primary == 5745 { 9 } else { 27 }
                            || !h.model(|m| m.data.as_ref().unwrap().ht_inventory == 1)
                        {
                            return Err("80+80 source native centers/8-row inventory/NSS override");
                        }
                        let cap = h
                            .device
                            .radio
                            .try_lock()
                            .unwrap()
                            .vht_capabilities()
                            .ok_or("80+80 hardware cap")?;
                        let highest = u16::from_le_bytes([cap[6], cap[7]]);
                        if cap[0] & 0x4c != 0x48
                            || highest
                                != if hardware == HwRev::Qca9984 {
                                    1560
                                } else {
                                    780
                                }
                        {
                            return Err("actual chip wide-NSS highest-rate hint");
                        }
                        traffic(&h)
                    })();
                    if let Err(e) = result {
                        return TestResult::Fail(e);
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht80p80",
    smoke_ath10k_80p80_actual_chip_nss_two_spans_open_wpa2_dhcp_ip
);
fn smoke_ath10k_80p80_second_span_and_chip_limits_fall_back_real_primary80() -> TestResult {
    for fault in 0..3 {
        let result = (|| {
            let hardware = if fault == 1 {
                HwRev::Qca99x0
            } else {
                HwRev::Qca9984
            };
            let source = if fault == 2 { SOURCE & !12 | 4 } else { SOURCE };
            let h = harness(hardware, 5180, false, true, source);
            if fault == 0 {
                h.policy
                    .lock()
                    .as_mut()
                    .unwrap()
                    .rules
                    .push(narf_wireless::reg::RegRule {
                        freq_start_mhz: 5740,
                        freq_end_mhz: 5750,
                        max_bandwidth_mhz: 80,
                        max_power_dbm: 27,
                        flags: narf_wireless::reg::RegFlags::NO_IR,
                    });
            }
            expected(&h, false, source, hardware);
            h.join()?;
            let actual = h
                .device
                .radio
                .try_lock()
                .unwrap()
                .prepared_peer()
                .ok_or("primary80 fallback owner")?;
            if actual.bandwidth_mhz != 80
                || actual.center_frequency != 5210
                || actual.second_center_frequency.is_some()
            {
                return Err("denied second span/hardware relabeled80+80 instead of actual80");
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
    "drivers/wireless/ath10k/vht80p80",
    smoke_ath10k_80p80_second_span_and_chip_limits_fall_back_real_primary80
);
fn smoke_ath10k_80p80_gi_nss_before_same_pn_and_second_span_copy_revocation() -> TestResult {
    for hardware in [HwRev::Qca9984, HwRev::Qca9888] {
        for sgi in [false, true] {
            let result = (|| {
                let source = SOURCE & !64 | if sgi { 64 } else { 0 };
                let h = harness(hardware, 5180, true, true, source);
                h.join()?;
                let (_, down) = packets();
                let wire = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
                let nss = if hardware == HwRev::Qca9984 { 2u32 } else { 1 };
                h.model(|m| {
                    let f = m.data.as_mut().unwrap();
                    f.rx_phy = Some((12, 3 | (nss << 10), 0x90));
                    f.queue.push_back(wire.clone());
                });
                h.pump();
                if h.received(&down) {
                    return Err("wide NSS exceeded actual chip limit before PN");
                }
                if !sgi {
                    h.model(|m| {
                        let f = m.data.as_mut().unwrap();
                        f.rx_phy = Some((12, 3 | ((nss - 1) << 10), 0x91));
                        f.queue.push_back(wire.clone());
                    });
                    h.pump();
                    if h.received(&down) {
                        return Err("SGI80 source bit lent an absent SGI160 promise");
                    }
                }
                h.model(|m| {
                    let f = m.data.as_mut().unwrap();
                    f.rx_phy = Some((12, 3 | ((nss - 1) << 10), 0x90 | u32::from(sgi)));
                    f.queue.push_back(wire);
                });
                h.pump();
                if !h.received(&down) {
                    return Err("invalid wide PPDU burned valid same PN");
                }
                let policy = h.policy.clone();
                h.device.set_receive_hook_for_test(move |point| {
                    if point == crate::ath10k::interface::ReceivePoint::AfterFrameAllocation {
                        policy.lock().as_mut().unwrap().rules[2].flags =
                            narf_wireless::reg::RegFlags::NO_IR;
                    }
                });
                h.model(|m| {
                    let f = m.data.as_mut().unwrap();
                    let wire = f.downlink(&down);
                    f.queue.push_back(wire);
                });
                h.pump();
                if h.received(&down) || !h.closed() {
                    return Err("second80 authority loss crossed copied packet publication");
                }
                Ok(())
            })();
            if let Err(e) = result {
                return TestResult::Fail(e);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht80p80",
    smoke_ath10k_80p80_gi_nss_before_same_pn_and_second_span_copy_revocation
);
fn smoke_ath10k_80p80_response_second_center_cannot_rebind_prepared_native_owner() -> TestResult {
    for hardware in [HwRev::Qca9984, HwRev::Qca9888] {
        let h = harness(hardware, 5180, false, true, SOURCE);
        h.model(|m| {
            let ies = m.data.as_mut().unwrap().ht_response.as_mut().unwrap();
            let mut at = 0;
            while at < ies.len() {
                if ies[at] == 192 {
                    ies[at + 4] = 106;
                    break;
                }
                at += 2 + usize::from(ies[at + 1]);
            }
        });
        if h.join().is_ok() || !h.never_opened() {
            return TestResult::Fail(
                "association response replaced source-selected second80 center",
            );
        }
        let before_port = h.model(|m| {
            let f = m.data.as_ref().unwrap();
            f.control_phase == 2 && f.ptk.is_none() && f.uplink.is_empty()
        });
        if !before_port {
            return TestResult::Fail("foreign second80 reached native PEER_ASSOC/M2/DATA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht80p80",
    smoke_ath10k_80p80_response_second_center_cannot_rebind_prepared_native_owner
);
fn smoke_ath10k_80p80_peer_highest_rate_hint_has_directional_nss_bounds() -> TestResult {
    for known in [false, true] {
        let result = (|| {
            let h = harness(HwRev::Qca9984, 5180, false, true, SOURCE);
            let hint = if known { 780u16 } else { 0 };
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                for ies in [&mut f.ht_offer, &mut f.ht_response] {
                    let ie = ies.as_mut().unwrap();
                    let mut at = 0;
                    while at < ie.len() {
                        if ie[at] == 191 {
                            ie[at + 8..at + 10].copy_from_slice(&hint.to_le_bytes());
                            ie[at + 12..at + 14].copy_from_slice(&hint.to_le_bytes());
                            break;
                        }
                        at += 2 + usize::from(ie[at + 1]);
                    }
                }
                let expected = f.vht.as_mut().unwrap();
                expected.rates[0] = u32::from(hint);
                expected.rates[2] = u32::from(hint);
                expected.wide_override = 0x8000_0000;
                f.rx_phy = Some((12, 3 | if known { 0 } else { 1 << 10 }, 0x91));
            });
            h.join()?;
            let (_, down) = packets();
            let wire = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            let valid = if known { 1u32 } else { 2 };
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.rx_phy = Some((12, 3 | (valid << 10), 0x91));
                f.queue.push_back(wire.clone());
            });
            h.pump();
            if h.received(&down) {
                return Err("peer TX wide-NSS hint/map ignored before PN");
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.rx_phy = Some((12, 3 | ((valid - 1) << 10), 0x91));
                f.queue.push_back(wire);
            });
            h.pump();
            if !h.received(&down) {
                return Err("directional peer hint rejection burned valid same PN");
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
    "drivers/wireless/ath10k/vht80p80",
    smoke_ath10k_80p80_peer_highest_rate_hint_has_directional_nss_bounds
);
