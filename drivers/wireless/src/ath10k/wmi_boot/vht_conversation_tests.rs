//! Actual CE/HTT/RSNA/netdev VHT conversations. The device model's expected
//! VHT element, PEER_ASSOC words and VDEV_START channel are authored from
//! Linux v7.2 ath10k mac.c/wmi.c and mac80211 vht.c, not the encoder.
use super::*;
use alloc::boxed::Box;

/// SERVICE_READY `vht_cap_info`: SGI80 (0x20) and A-MPDU exponent3.
const LOCAL_VHT: u32 = 0x0180_0020;
/// Association-request VHT Capabilities body (ath10k_create_vht_cap):
/// the info word above and one-stream MCS0-9 RX/TX maps.
const REQUEST: [u8; 12] = [0x20, 0, 0x80, 0x01, 0xfe, 0xff, 0, 0, 0xfe, 0xff, 0, 0];
/// AP VHT Capabilities: RX LDPC, SGI80, TX STBC, RX STBC1, exponent7, a
/// two-stream MCS0-9 RX/TX map and780 Mb/s highest rates.
const AP_VHT: [u8; 12] = [0xb0, 0x01, 0x80, 0x03, 0xfa, 0xff, 0x0c, 0x03, 0xfa, 0xff, 0x0c, 0x03];

fn pair(f: u16) -> u16 {
    match f {
        5180 | 5220 | 5745 | 5785 => f + 20,
        _ => f - 20,
    }
}
/// HT Capabilities/Operation (HT40, plus/minus by the pair) followed by VHT
/// Capabilities and a VHT Operation of `width` (0 = 20/40, 1 = 80).
fn elements(primary: u16, forty: bool, width: u8) -> Vec<u8> {
    let channel = ((primary - 5000) / 5) as u8;
    let mut v = vec![45, 26, 0x6e, 0, 0x1b, 0xff];
    v.extend_from_slice(&[0; 11]);
    v.push(1);
    v.extend_from_slice(&[0; 10]);
    let offset = if !forty {
        0
    } else if pair(primary) > primary {
        5
    } else {
        7
    };
    v.extend_from_slice(&[61, 22, channel, offset]);
    v.extend_from_slice(&[0; 20]);
    v.extend_from_slice(&[191, 12]);
    v.extend_from_slice(&AP_VHT);
    let center = if primary < 5500 { 42 } else { 155 };
    v.extend_from_slice(&[192, 5, width, if width == 1 { center } else { 0 }, 0, 0xfc, 0xff]);
    v
}
/// `width`: 0 = VHT20, 1 = VHT40, 2 = VHT80 selected by the AP.
pub(super) fn enable(h: &Harness, width: u8) -> Result<(), &'static str> {
    if !matches!(h.frequency, 5180..=5240 | 5745..=5805) {
        return Err("VHT test primary");
    }
    ht_conversation_tests::enable(h);
    h.device
        .radio
        .try_lock()
        .unwrap()
        .htt
        .wmi
        .caps
        .as_mut()
        .unwrap()
        .vht = LOCAL_VHT;
    for rule in &mut h.policy.lock().as_mut().unwrap().rules {
        if rule.freq_start_mhz > 3000 {
            rule.max_bandwidth_mhz = 80;
        }
    }
    let ies = elements(h.frequency, width > 0, u8::from(width == 2));
    let secondary = (width > 0).then(|| pair(h.frequency));
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.ht_offer = Some(ies.clone());
        f.ht_response = Some(ies);
        f.ht_secondary = secondary;
        // HT facts match the HT40 local profile (no SGI40, SGI20 kept).
        f.ht_capabilities = if width > 0 { 0x002e } else { 0x002c };
        f.ht_sgi = true;
        f.vht = Some(Box::new(VhtExpect {
            width,
            request: REQUEST,
            // mac80211 masking: RX LDPC, exponent7 kept; SGI80 symmetric;
            // the AP's TX STBC needs our (absent) RX STBC promise.
            capabilities: 0x0380_0030,
            // rx: AP RX map ∩ our TX (1SS MCS0-9); tx: AP TX ∩ our RX.
            rates: [780, 0xfffe, 780, 0xfffe],
            max_mpdu: (1 << 20) - 1,
        }));
        f.rx_phy = Some((12, u32::from(width), 0x90));
    });
    Ok(())
}
fn harness(f: u16, width: u8) -> Result<Harness, &'static str> {
    let h = Harness::new_on(4, Dialect::Tlv, true, false, f, 0x8348);
    enable(&h, width)?;
    Ok(h)
}
fn rx(h: &Harness, bytes: Vec<u8>, preamble: u8, a1: u32, a2: u32) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.rx_phy = Some((preamble, a1, a2));
        f.queue.push_back(bytes);
    });
    h.pump();
}
fn prepared(h: &Harness) -> Result<radio::PeerPrepared, &'static str> {
    h.device
        .radio
        .try_lock()
        .unwrap()
        .prepared_peer()
        .ok_or("VHT native peer absent")
}

fn smoke_ath10k_vht80_native_six_dialects_open_wpa2_dhcp_ip_and_retirement() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        for frequency in [5180, 5765] {
            for secured in [false, true] {
                if let Err(e) = composition_radio(
                    version,
                    dialect,
                    secured,
                    false,
                    false,
                    frequency,
                    TestPhy::Vht80,
                ) {
                    return TestResult::Fail(e);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht80_native_six_dialects_open_wpa2_dhcp_ip_and_retirement
);

fn smoke_ath10k_vht80_every_primary_binds_segment_center_and_occupied_80() -> TestResult {
    for primary in [5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805] {
        let result = (|| {
            let h = harness(primary, 2)?;
            h.join()?;
            let p = prepared(&h)?;
            let center = if primary < 5500 { 5210 } else { 5775 };
            if p.frequency != primary || p.center_frequency != center || p.bandwidth_mhz != 80 {
                return Err("VHT80 primary/segment center/occupied width mismatch");
            }
            let (up, down) = packets();
            narf_net::iface::send_on(&h.name, &up).map_err(|_| "VHT80 uplink")?;
            h.pump();
            let bytes = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, bytes, 12, 2, 0x90);
            if !h.received(&down) || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
                return Err("VHT80 native Ethernet");
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
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht80_every_primary_binds_segment_center_and_occupied_80
);

fn smoke_ath10k_vht_narrow_bss_uses_vht20_vht40_peer_mode_and_ht_start() -> TestResult {
    for (dialect, version) in [(Dialect::Tlv, 4), (Dialect::TenFour, 6), (Dialect::Main, 1)] {
        for width in [0u8, 1] {
            let result = (|| {
                let h = Harness::new_on(version, dialect, true, false, 5200, 0x8348);
                enable(&h, width)?;
                h.join()?;
                let p = prepared(&h)?;
                if p.bandwidth_mhz != if width == 1 { 40 } else { 20 }
                    || p.center_frequency != if width == 1 { 5190 } else { 5200 }
                {
                    return Err("narrow VHT BSS occupied geometry");
                }
                let (_, down) = packets();
                let bytes = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
                rx(&h, bytes.clone(), 12, 2, 0x90);
                if h.received(&down) {
                    return Err("narrow VHT profile accepted an 80 MHz PPDU");
                }
                rx(&h, bytes, 12, u32::from(width), 0x90);
                if !h.received(&down) {
                    return Err("narrow VHT profile refused its own bandwidth");
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
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht_narrow_bss_uses_vht20_vht40_peer_mode_and_ht_start
);

fn smoke_ath10k_vht_denied_segment_or_no_vht_fact_falls_back_without_vht_element() -> TestResult {
    for fault in 0..3 {
        let result = (|| {
            let h = harness(5180, 2)?;
            match fault {
                // Host ceiling 40 MHz: the 80 MHz segment is not granted.
                0 => {
                    for rule in &mut h.policy.lock().as_mut().unwrap().rules {
                        if rule.freq_start_mhz > 3000 {
                            rule.max_bandwidth_mhz = 40;
                        }
                    }
                }
                // Firmware reported no vht_cap_info.
                1 => {
                    h.device
                        .radio
                        .try_lock()
                        .unwrap()
                        .htt
                        .wmi
                        .caps
                        .as_mut()
                        .unwrap()
                        .vht = 0
                }
                // The upper half of the segment is out of the firmware band.
                _ => {
                    h.device
                        .radio
                        .try_lock()
                        .unwrap()
                        .htt
                        .wmi
                        .caps
                        .as_mut()
                        .unwrap()
                        .high_5ghz = 5200
                }
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.vht = None;
                f.rx_phy = Some((8, 0x87, 0));
            });
            h.join()?;
            let p = prepared(&h)?;
            if p.bandwidth_mhz != 40 || p.center_frequency != 5190 {
                return Err("VHT fallback did not select the real HT40 profile");
            }
            let (_, down) = packets();
            let bytes = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            rx(&h, bytes.clone(), 12, 1, 0x90);
            if h.received(&down) {
                return Err("HT40 fallback accepted a VHT PPDU");
            }
            rx(&h, bytes, 8, 0x87, 0);
            if !h.received(&down) {
                return Err("HT40 fallback refused HT40 PPDU");
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
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht_denied_segment_or_no_vht_fact_falls_back_without_vht_element
);

fn smoke_ath10k_vht80_ppdu_admits_only_promised_bandwidth_stream_coding_and_mcs() -> TestResult {
    // (preamble, VHT-SIG-A1, VHT-SIG-A2): TXBF, MU group, two streams,
    // STBC without our RX STBC, LDPC without our RX LDPC, bw160, MCS10.
    let refused: [(u8, u32, u32); 7] = [
        (13, 2, 0x90),
        (12, 2 | 5 << 4, 0x90),
        (12, 2 | 1 << 10, 0x90),
        (12, 2 | 8 | 1 << 10, 0x90),
        (12, 2, 0x94),
        (12, 3, 0x90),
        (12, 2, 0xa0),
    ];
    let result = (|| {
        let h = harness(5180, 2)?;
        h.join()?;
        let (_, down) = packets();
        let bytes = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
        for (preamble, a1, a2) in refused {
            rx(&h, bytes.clone(), preamble, a1, a2);
            if h.received(&down) {
                return Err("unpromised VHT PPDU escaped");
            }
        }
        // SGI80 is promised; the refused PPDUs consumed no CCMP PN.
        rx(&h, bytes.clone(), 12, 2, 0x91);
        if !h.received(&down) {
            return Err("promised VHT80 SGI PPDU refused or PN consumed");
        }
        rx(&h, bytes, 12, 0, 0x90);
        if h.received(&down) {
            return Err("replayed VHT20 PPDU inherited a fresh PN");
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht80_ppdu_admits_only_promised_bandwidth_stream_coding_and_mcs
);

fn smoke_ath10k_vht80_response_without_vht_or_changed_width_never_publishes_peer() -> TestResult {
    for fault in 0..3 {
        let result = (|| {
            let h = harness(5180, 2)?;
            h.model(|m| {
                let v = m.data.as_mut().unwrap().ht_response.as_mut().unwrap();
                let vht = v.len() - 21;
                match fault {
                    0 => v.truncate(vht),
                    // VHT Operation narrowed to 20/40 after an 80 MHz offer.
                    1 => {
                        let op = v.len() - 5;
                        v[op] = 0;
                        v[op + 1] = 0;
                    }
                    // Basic VHT-MCS set requiring two streams.
                    _ => {
                        let basic = v.len() - 2;
                        v[basic] = 0xf0;
                    }
                }
            });
            h.scan()?;
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || h.model(|m| m.data.as_ref().unwrap().control_phase) > 2
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
            {
                return Err("VHT response changed width/VHT presence or opened the port");
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
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht80_response_without_vht_or_changed_width_never_publishes_peer
);

fn smoke_ath10k_vht80_changed_ap_vht_operation_closes_without_relabel() -> TestResult {
    let result = (|| {
        let h = harness(5180, 2)?;
        h.join()?;
        h.model(|m| {
            let v = m.data.as_mut().unwrap().ht_offer.as_mut().unwrap();
            let op = v.len() - 5;
            v[op] = 0;
            v[op + 1] = 0;
            let beacon = m.data.as_ref().unwrap().beacon();
            management_frame(m, beacon);
        });
        h.pump();
        if !h.closed() || !h.model(|m| m.ce.as_ref().unwrap().retained()) {
            return Err("AP VHT Operation changed without a retained native channel transition");
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht",
    smoke_ath10k_vht80_changed_ap_vht_operation_closes_without_relabel
);
