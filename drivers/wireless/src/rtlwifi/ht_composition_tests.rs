//! Composed retained RTL8188EE HT20/LGI native station regressions.
use super::super::super::super::super::super::ht;
use super::*;
use core::sync::atomic::AtomicUsize;
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn packet(h: &Harness, n: u8, uplink: bool) -> Vec<u8> {
    let p = h.peer.lock().plan;
    udp_ipv4(
        if uplink { PEER } else { p.station },
        if uplink { p.station } else { PEER },
        if uplink { p.lease_ip } else { p.server_ip },
        if uplink { p.server_ip } else { p.lease_ip },
        49152,
        7,
        &[n; 40],
    )
}
fn aggregate(h: &Harness, frames: &[Vec<u8>], pn: u64) -> Result<Vec<u8>, &'static str> {
    let mut p = h.peer.lock();
    p.pn = p.pn.max(pn.saturating_add(1));
    let mut header = vec![0x88, if p.ap.protected() { 0x42 } else { 2 }, 0, 0];
    header.extend_from_slice(&p.plan.station);
    header.extend_from_slice(&PEER);
    header.extend_from_slice(&PEER);
    header.extend_from_slice(&[0, 0, 0x80, 0]);
    let mut body = Vec::new();
    for (i, e) in frames.iter().enumerate() {
        body.extend_from_slice(&e[..12]);
        body.extend_from_slice(&((e.len() - 6) as u16).to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        body.extend_from_slice(&e[12..]);
        if i + 1 != frames.len() {
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
    }
    if p.ap.protected() {
        let key = p
            .ptk
            .as_ref()
            .ok_or("HT AP key absent")?
            .tk
            .as_slice()
            .try_into()
            .map_err(|_| "HT TK extent")?;
        let mut clear = body;
        body = narf_wireless::ccmp::protect(&Ccm, &header, key, pn, 0, 0, false, &mut clear)
            .map_err(|_| "HT aggregate CCMP")?;
    }
    header.extend_from_slice(&body);
    Ok(header)
}
fn retained(h: &Harness) -> usize {
    h.packet.live_regions().len()
}
fn ht_join(h: &Harness) -> Result<(), &'static str> {
    h.scan();
    complete(h.device.associate(h.request())).map_err(|_| "HT native MLME/RSNA failed")?;
    if !h.device.link_up()
        || !h.device.get_wireless_info().hw_caps.ht_supported
        || h.device.phy_capabilities(2400).is_none()
    {
        return Err("HT profile was not publicly admitted");
    }
    if h.packet.radio.word(0xe10) != 0x1e1e1e1e
        || h.packet.radio.word(0xe14) != 0x17191c1d
        || h.packet.radio.word(0x508) != 0xa52b
        || h.packet.radio.word(0x50c) != 0xa44f
        || h.packet.radio.word(0x504) != 0x005e4322
        || h.packet.radio.word(0x500) != 0x002f3222
        || [0x515, 0x517, 0x429, 0x63b]
            .into_iter()
            .any(|r| h.packet.radio.hardware_read8(r) != 14)
    {
        return Err("HT native gain/SIFS readbacks changed");
    }
    Ok(())
}
fn composition(protected: bool) -> Result<(), &'static str> {
    let h = Harness::new_profile(protected, true);
    ht_join(&h)?;
    let count = retained(&h);
    let plan = h.peer.lock().plan;
    let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
        .map_err(|_| "HT real kernel DHCP failed")?;
    if !plan.matches_lease(&lease) || h.peer.lock().server.observations().requests != 1 {
        return Err("HT native DORA terms/publications changed");
    }
    let up = packet(&h, 1, true);
    h.device
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "HT enqueue")?;
    h.pump();
    if h.peer.lock().uplink.last() != Some(&up) {
        return Err("HT actual software-CCMP uplink mismatch");
    }
    let d = h.packet.model.lock().descriptors.last().unwrap().clone();
    // RA mask (NGB, RATE_ID 0) installed: USE_RATE kept, DISDATAFB clear.
    if word(&d, 20) & 127 != 19
        || word(&d, 16) & ((1 << 6) | (1 << 8) | (1 << 10)) != 0x140
        || (word(&d, 4) >> 16) & 15 != 0
        || word(&d, 16) & ((1 << 25) | (3 << 20)) != 0
        || word(&d, 8) & (1 << 12) != 0
    {
        return Err("HT native MCS7/LGI/QoS/nonBA descriptor changed");
    }
    let down = packet(&h, 2, false);
    let raw = h.peer.lock().downlink(&down)?;
    h.packet
        .emit_native(&raw, 0x53, 0, None)
        .map_err(|_| "HT RX injection")?;
    h.pump();
    if !h.received().contains(&down) || retained(&h) != count {
        return Err("HT native RX exact IP/retained DMA changed");
    }
    complete(h.device.disassociate()).map_err(|_| "HT native close")?;
    if !h.closed() || h.packet.model.lock().master {
        return Err("HT terminal close retained admission");
    }
    Ok(())
}
fn smoke_rtl8188ee_ht20_open_native_kernel_dhcp_and_ip() -> TestResult {
    check(|| composition(false))
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_open_native_kernel_dhcp_and_ip
);
fn smoke_rtl8188ee_ht20_wpa2_native_kernel_dhcp_and_ip() -> TestResult {
    check(|| composition(true))
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_wpa2_native_kernel_dhcp_and_ip
);
fn smoke_rtl8188ee_ht20_all_mcs_bound_actual_response_and_lgi_descriptors() -> TestResult {
    check(|| {
        for m in 0..8 {
            let h = Harness::new_profile(true, true);
            h.peer.lock().ht = Some(ht::tests::ap_elements(1 << m));
            ht_join(&h)?;
            let up = packet(&h, m, true);
            h.device
                .enqueue(&up, TxMeta::default())
                .map_err(|_| "selected MCS enqueue")?;
            h.pump();
            let model = h.packet.model.lock();
            let d = model.descriptors.last().unwrap();
            if word(d, 20) & 127 != u32::from(12 + m) || model.observed.last().unwrap()[0] != 0x88 {
                return Err("response MCS intersection lost actual native rate/LGI");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_all_mcs_bound_actual_response_and_lgi_descriptors
);
fn smoke_rtl8188ee_ht20_default3839_whole_amsdu_and_atomic_pn() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = Harness::new_profile(protected, true);
            ht_join(&h)?;
            let mut e = packet(&h, 3, false);
            e.resize(1271, 0x55);
            let frames = vec![e.clone(), e.clone(), e];
            let raw = aggregate(&h, &frames, 101)?;
            h.packet
                .emit_native(&raw, 0x53, 0, None)
                .map_err(|_| "3839 native DMA")?;
            h.pump();
            if h.received() != frames {
                return Err("mandatory3839 original A-MSDU not delivered completely");
            }
            if protected {
                h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
                h.pump();
                if !h.received().is_empty() {
                    return Err("aggregate replay admitted");
                }
            }
            let good = vec![packet(&h, 4, false), packet(&h, 5, false)];
            let mut bad = good.clone();
            bad[1][12..14].copy_from_slice(&[0x88, 0x8e]);
            let malformed = aggregate(&h, &bad, 102)?;
            h.packet.emit_native(&malformed, 0x53, 0, None).unwrap();
            h.pump();
            if !h.received().is_empty() {
                return Err("invalid suffix exposed aggregate prefix");
            }
            let valid = aggregate(&h, &good, 102)?;
            h.packet.emit_native(&valid, 0x53, 0, None).unwrap();
            h.pump();
            if h.received() != good {
                return Err("invalid aggregate consumed original PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_default3839_whole_amsdu_and_atomic_pn
);
fn smoke_rtl8188ee_ht20_native_rx_phy_width_rate_aggregate_before_pn() -> TestResult {
    check(|| {
        let h = Harness::new_profile(true, true);
        ht_join(&h)?;
        for fault in 0..9 {
            let e = packet(&h, fault, false);
            let raw = h.peer.lock().downlink(&e)?;
            let (report, extra, phy) = match fault {
                0 => (0x253, 0, None),
                1 => (0x153, 0, None),
                2 => (0xd3, 0, None),
                3 => (0x54, 0, None),
                4 => (19, 0, None),
                5 => (0x53, 1 << 14, None),
                6 => (
                    0x53,
                    0,
                    Some({
                        let mut p = [0; 28];
                        p[27] = 2;
                        p
                    }),
                ),
                7 => (0x53, 1 << 15, None),
                _ => (0x53, 0, None),
            };
            h.packet
                .emit_native(&raw, report, extra, phy.as_ref().map(|p| p.as_slice()))
                .unwrap();
            if fault == 8 {
                let slot = (h.packet.model.lock().rx_next + 3) % 4;
                let ring = h
                    .packet
                    .region(u64::from(h.packet.radio.word(LINUX_RX_BASE)));
                let mut d = ring.bytes.lock();
                let status = word(&d, slot * 32);
                put(&mut d, slot * 32, status & !(1 << 23));
            }
            h.pump();
            if !h.received().is_empty() || !h.device.link_up() {
                return Err("unsupported native HT metadata reached crypto/publication");
            }
            h.packet.emit_native(&raw, 0x53, 0, Some(&[0; 28])).unwrap();
            h.pump();
            if h.received() != vec![e] {
                return Err("rejected native PHY/AMPDU consumed CCMP PN");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_native_rx_phy_width_rate_aggregate_before_pn
);
fn addba(h: &Harness, tid: u8) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&h.peer.lock().plan.station);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&[0, 0, 3, 0, 71]);
    f.extend_from_slice(&(3u16 | (u16::from(tid) << 2) | (32 << 6)).to_le_bytes());
    f.extend_from_slice(&[0, 0, 0x30, 0x12]);
    f
}
fn smoke_rtl8188ee_ht20_real_addba_response_terminal_receipt_and_cancelled_dma() -> TestResult {
    check(|| {
        for fault in 0..3 {
            let h = Harness::new_profile(true, true);
            ht_join(&h)?;
            if fault != 0 {
                h.peer.lock().hold_control = true;
            }
            let count = retained(&h);
            for tid in 0..8 {
                h.packet.emit(&addba(&h, tid)).unwrap();
                h.pump();
                let peer = h.peer.lock();
                let response = peer
                    .controls
                    .last()
                    .ok_or("native ADDBA response not delivered to peer")?;
                // mac80211 accepts (status0); rtlwifi's SUPPORTS_AMSDU_IN_AMPDU
                // sets the response A-MSDU bit.
                if response.len() != 33
                    || response[26] != 71
                    || response[27..29] != [0, 0]
                    || u16::from_le_bytes([response[29], response[30]])
                        != 3 | (u16::from(tid) << 2) | (32 << 6)
                {
                    return Err("native ADDBA response lost token/TID/status/A-MSDU/window");
                }
                drop(peer);
                let d = h.packet.model.lock().descriptors.last().unwrap().clone();
                if word(&d, 20) & 127 != 0
                    || word(&d, 16) & (1 << 6) != 0
                    || word(&d, 8) & (1 << 12) != 0
                {
                    return Err("BA response used MCS/QoS/AGG instead of native legacy management");
                }
                if fault != 0 {
                    break;
                }
            }
            if fault == 1 {
                h.env.now.fetch_add(1001, Ordering::AcqRel);
                h.pump();
                if !h.closed() {
                    return Err("missing native Action OWN receipt reopened station");
                }
            } else if fault == 2 {
                complete(h.device.disassociate()).map_err(|_| "held decline native close")?;
                h.packet.release_held();
                h.pump();
                if !h.closed() {
                    return Err("late decline receipt reopened cancelled owner");
                }
            } else if !h.device.link_up() {
                return Err("successful BA response changed station admission");
            }
            if retained(&h) < count {
                return Err("uncertain ADDBA control released native DMA");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_real_addba_response_terminal_receipt_and_cancelled_dma
);
/// One non-A-MSDU QoS DATA MPDU on `tid`, sequence `seq`, CCMP PN `pn`.
fn qos(h: &Harness, seq: u16, tid: u8, pn: u64, n: u8) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let e = packet(h, n, false);
    let mut p = h.peer.lock();
    p.pn = p.pn.max(pn.saturating_add(1));
    let mut header = vec![0x88, if p.ap.protected() { 0x42 } else { 2 }, 0, 0];
    header.extend_from_slice(&p.plan.station);
    header.extend_from_slice(&PEER);
    header.extend_from_slice(&PEER);
    header.extend_from_slice(&(seq << 4).to_le_bytes());
    header.extend_from_slice(&[tid, 0]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
    body.extend_from_slice(&e[12..]);
    if p.ap.protected() {
        let key = p
            .ptk
            .as_ref()
            .ok_or("BA AP key absent")?
            .tk
            .as_slice()
            .try_into()
            .map_err(|_| "BA TK extent")?;
        let mut clear = body;
        body = narf_wireless::ccmp::protect(&Ccm, &header, key, pn, 0, tid, false, &mut clear)
            .map_err(|_| "BA CCMP")?;
    }
    header.extend_from_slice(&body);
    Ok((header, e))
}
fn addba_with(h: &Harness, token: u8, params: u16, timeout: u16, ssn: u16) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&h.peer.lock().plan.station);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&[0, 0, 3, 0, token]);
    f.extend_from_slice(&params.to_le_bytes());
    f.extend_from_slice(&timeout.to_le_bytes());
    f.extend_from_slice(&(ssn << 4).to_le_bytes());
    f
}
fn bar(h: &Harness, tid: u16, ssn: u16) -> Vec<u8> {
    let mut f = vec![0x84, 0, 0, 0];
    f.extend_from_slice(&h.peer.lock().plan.station);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&(tid << 12 | 4).to_le_bytes());
    f.extend_from_slice(&(ssn << 4).to_le_bytes());
    f
}
fn originator_delba(h: &Harness, tid: u16) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&h.peer.lock().plan.station);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&[0, 0, 3, 2]);
    f.extend_from_slice(&(tid << 12 | 1 << 11).to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f
}
const PAGGR: u32 = 1 << 14;
fn smoke_rtl8188ee_ht20_rx_ba_reorders_ampdu_and_bar_before_pn() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = Harness::new_profile(protected, true);
            ht_join(&h)?;
            // Window16 TID6 session at SSN200; A-MSDU permitted in A-MPDU.
            let params = 3u16 | 6 << 2 | 16 << 6;
            h.packet.emit(&addba_with(&h, 9, params, 0, 200)).unwrap();
            h.pump();
            {
                let peer = h.peer.lock();
                let r = peer.controls.last().ok_or("EE ADDBA response missing")?;
                if r.len() != 33
                    || r[26] != 9
                    || r[27..29] != [0, 0]
                    || r[29..31] != params.to_le_bytes()
                    || r[31..33] != [0, 0]
                {
                    return Err("EE ADDBA acceptance status/params/A-MSDU");
                }
            }
            let (f200, e200) = qos(&h, 200, 6, 200, 20)?;
            let (f201, e201) = qos(&h, 201, 6, 201, 21)?;
            let (f202, e202) = qos(&h, 202, 6, 202, 22)?;
            h.packet
                .emit_native(&f200, 0x53, PAGGR | 1 << 15, None)
                .unwrap();
            h.pump();
            if h.received() != vec![e200] {
                return Err("EE BA head MPDU");
            }
            h.packet.emit_native(&f202, 0x53, PAGGR, None).unwrap();
            h.pump();
            if !h.received().is_empty() {
                return Err("EE BA delivered across a hole");
            }
            h.packet.emit_native(&f201, 0x53, PAGGR, None).unwrap();
            h.pump();
            if h.received() != vec![e201, e202] {
                return Err("EE BA hole fill order");
            }
            // BAR moves the window past a missing SN204 and releases SN205.
            let (f205, e205) = qos(&h, 205, 6, 205, 25)?;
            h.packet.emit_native(&f205, 0x53, PAGGR, None).unwrap();
            h.pump();
            if !h.received().is_empty() {
                return Err("EE BA delivered before BAR");
            }
            h.packet.emit(&bar(&h, 6, 205)).unwrap();
            h.pump();
            if h.received() != vec![e205] {
                return Err("EE BlockAckReq did not release up to its SSN");
            }
            // Reorder hole timeout (100ms).
            let (f208, e208) = qos(&h, 208, 6, 208, 28)?;
            h.packet.emit_native(&f208, 0x53, PAGGR, None).unwrap();
            h.pump();
            if !h.received().is_empty() {
                return Err("EE BA delivered before reorder timeout");
            }
            h.env.now.fetch_add(101, Ordering::AcqRel);
            h.pump();
            if h.received() != vec![e208] {
                return Err("EE BA reorder timeout release");
            }
            // A-MPDU without a session is refused before PN; BAR for such a
            // TID sends one DELBA QSTA_REQUIRE_SETUP.
            let (f0, _) = qos(&h, 0, 0, 300, 30)?;
            h.packet.emit_native(&f0, 0x53, PAGGR, None).unwrap();
            h.pump();
            if !h.received().is_empty() || !h.device.link_up() {
                return Err("EE A-MPDU accepted without session");
            }
            for _ in 0..2 {
                h.packet.emit(&bar(&h, 2, 0)).unwrap();
                h.pump();
            }
            {
                let peer = h.peer.lock();
                let delbas: Vec<_> = peer
                    .controls
                    .iter()
                    .filter(|c| c.len() == 30 && c[24..26] == [3, 2])
                    .collect();
                if delbas.len() != 1
                    || delbas[0][26..28] != (2u16 << 12).to_le_bytes()
                    || delbas[0][28..30] != [38, 0]
                {
                    return Err("EE unexpected BAR DELBA");
                }
            }
            // Originator DELBA ends the session.
            h.packet.emit(&originator_delba(&h, 6)).unwrap();
            h.pump();
            let (f209, _) = qos(&h, 209, 6, 309, 31)?;
            h.packet.emit_native(&f209, 0x53, PAGGR, None).unwrap();
            h.pump();
            if !h.received().is_empty() || !h.device.link_up() {
                return Err("EE A-MPDU accepted after originator DELBA");
            }
            let (f210, e210) = qos(&h, 210, 6, 310, 32)?;
            h.packet.emit_native(&f210, 0x53, 0, None).unwrap();
            h.pump();
            if h.received() != vec![e210] {
                return Err("EE ordinary QoS after DELBA");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_rx_ba_reorders_ampdu_and_bar_before_pn
);
fn smoke_rtl8188ee_ht20_rx_ba_policy_and_inactivity_delba() -> TestResult {
    check(|| {
        let h = Harness::new_profile(false, true);
        ht_join(&h)?;
        let status = |request: Vec<u8>| -> Result<[u8; 4], &'static str> {
            let before = h.peer.lock().controls.len();
            h.packet.emit(&request).unwrap();
            h.pump();
            let peer = h.peer.lock();
            if peer.controls.len() != before + 1 {
                return Err("EE ADDBA response missing");
            }
            let r = peer.controls.last().unwrap();
            Ok([r[27], r[28], r[29], r[30]])
        };
        let tid9 = status(addba_with(&h, 1, 2 | 9 << 2 | 8 << 6, 0, 0))?;
        let delayed = status(addba_with(&h, 2, 3 << 2 | 8 << 6, 0, 0))?;
        let wide = status(addba_with(&h, 3, 2 | 3 << 2 | 65 << 6, 0, 0))?;
        let zero = status(addba_with(&h, 4, 2 | 3 << 2, 100, 0))?;
        if tid9[..2] != [37, 0]
            || delayed[..2] != [38, 0]
            || wide[..2] != [38, 0]
            || zero != [0, 0, 0x0f, 0x10]
        {
            return Err("EE ADDBA status/window differs from mac80211");
        }
        let same = status(addba_with(&h, 4, 2 | 3 << 2, 100, 0))?;
        let changed = status(addba_with(&h, 4, 2 | 3 << 2, 200, 0))?;
        if same[..2] != [0, 0] || changed[..2] != [37, 0] {
            return Err("EE ADDBA same-token update policy");
        }
        let before = h.peer.lock().controls.len();
        h.env.now.fetch_add(103, Ordering::AcqRel);
        h.pump();
        let peer = h.peer.lock();
        let d = peer.controls.last().ok_or("EE DELBA missing")?;
        if peer.controls.len() != before + 1
            || d.len() != 30
            || d[24..26] != [3, 2]
            || d[26..28] != (3u16 << 12).to_le_bytes()
            || d[28..30] != [39, 0]
            || !h.device.link_up()
        {
            return Err("EE BA inactivity DELBA");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_rx_ba_policy_and_inactivity_delba
);
fn smoke_rtl8188ee_ht20_bad_assets_retry_before_writes_and_live_legacy_no_upgrade() -> TestResult {
    check(|| {
        for field in [0, 16, 80, 112, 118, 121, 128] {
            let h = Harness::new_profile(false, true);
            let (record, _, _) = h.ht_source.as_ref().unwrap();
            let saved = record.lock().clone();
            record.lock()[field] ^= 1;
            if complete(h.device.scan(ScanRequest {
                ssids: vec![SSID.to_vec()],
                frequencies_mhz: vec![2412],
                channels: vec![1],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: Some(1),
                duration_mandatory: false,
                extra_ies: Vec::new(),
            }))
            .is_ok()
                || h.packet.model.lock().master
                || h.packet.radio.word(0xe10) != 0
                || h.device
                    .prepared
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .phase()
                    != Phase::MacConfigured
            {
                return Err("invalid optional HT program wrote gains or consumed the parked owner");
            }
            *record.lock() = saved;
            ht_join(&h)?;
        }
        let h = Harness::new(false);
        {
            let mut p = h.peer.lock();
            p.wmm = Some(WMM.to_vec());
            p.ht = Some(ht::tests::ap_elements(255));
        }
        h.join();
        let mut owner = h.device.prepared.try_lock().unwrap();
        let owner = owner.as_mut().unwrap();
        if owner.prepare_station_ht(h.env.as_ref()) != Err(StationError::State)
            || h.packet.radio.word(0xe10) != 0
            || h.device.get_wireless_info().hw_caps.ht_supported
        {
            return Err("running legacy owner silently upgraded to HT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_bad_assets_retry_before_writes_and_live_legacy_no_upgrade
);
fn smoke_rtl8188ee_ht20_native_gain_timing_and_current_sources_fail_closed() -> TestResult {
    check(|| {
        for reg in [0xe10, 0x515] {
            let h = Harness::new_profile(true, true);
            h.packet.radio.ignore(reg);
            let request = ScanRequest {
                ssids: vec![SSID.to_vec()],
                frequencies_mhz: vec![2412],
                channels: vec![1],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: Some(1),
                duration_mandatory: false,
                extra_ies: Vec::new(),
            };
            let scan = complete(h.device.scan(request));
            let denied = scan.is_err() || complete(h.device.associate(h.request())).is_err();
            if !denied
                || !h.closed()
                || h.device
                    .prepared
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .station_phase()
                    != Logical::Failed
            {
                return Err("ignored MCS gain/SIFS write admitted the HT owner");
            }
            let count = retained(&h);
            h.pump();
            if retained(&h) != count {
                return Err("failed HT readback released retained DMA");
            }
        }
        for source in 0..6 {
            let db = Arc::new(narf_wireless::reg::db::Database::new());
            db.install(power::domain(17));
            let h = Harness::with_policy(true, true, (source == 4).then(|| db.clone()));
            ht_join(&h)?;
            let down = packet(&h, 8, false);
            let raw = h.peer.lock().downlink(&down)?;
            h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
            match source {
                0 => {
                    h.ht_source.as_ref().unwrap().1.revoke();
                }
                1 => {
                    h.base_cap.unwrap().revoke();
                }
                2 => {
                    h.packet.model.lock().live = false;
                }
                3 => {
                    h.env.power.store(1, Ordering::Release);
                }
                4 => {
                    db.clear();
                }
                _ => {
                    if !h.firmware.identity().unwrap().revoke_source() {
                        return Err("HT native executable source was not retained");
                    }
                }
            }
            h.pump();
            if !h.closed() || !h.received().is_empty() {
                return Err("changed signed/PCI/policy authority published HT RX");
            }
            h.env.power.store(17, Ordering::Release);
            db.install(power::domain(17));
            h.packet.model.lock().live = true;
            h.pump();
            if !h.closed() {
                return Err("reinstalled authority revived failed HT owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_native_gain_timing_and_current_sources_fail_closed
);
fn smoke_rtl8188ee_ht20_held_m4_discards_closed_capture_without_committing_pn() -> TestResult {
    check(|| {
        let h = Harness::new_profile(true, true);
        h.scan();
        h.peer.lock().hold_m4 = true;
        // async_trait already returns the owned pinned Box. Drop this actual
        // waiter below, rather than another Pin borrowing a hidden temporary.
        let mut join = h.device.associate(h.request());
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..100 {
            if join.as_mut().poll(&mut cx).is_ready() {
                return Err("HT M4 did not retain native wait");
            }
            if h.packet.model.lock().held.is_some() {
                break;
            }
        }
        if h.packet.model.lock().held.is_none() || h.device.link_up() {
            return Err("HT fixture lacks actual held M4");
        }
        let frames = vec![packet(&h, 11, false), packet(&h, 12, false)];
        let raw = aggregate(&h, &frames, 201)?;
        h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
        h.peer.lock().hold_m4 = false;
        h.packet.release_held();
        let mut completed = false;
        for _ in 0..1000 {
            if let Poll::Ready(result) = join.as_mut().poll(&mut cx) {
                result.map_err(|_| "HT native M4 completion")?;
                completed = true;
                break;
            }
        }
        if !completed {
            return Err("HT M4 future did not complete");
        }
        drop(join);
        h.pump();
        if !h.received().is_empty() {
            return Err("pre-M4 original A-MSDU received retrospective authority");
        }
        h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
        h.pump();
        if h.received() != frames {
            return Err("closed aggregate consumed successor PTK PN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_held_m4_discards_closed_capture_without_committing_pn
);
type RxHook = dyn Fn(&str, &mut [u8]) + Send + Sync;
static RX_HOOK: IrqSafeSpinLock<Option<Arc<RxHook>>> = IrqSafeSpinLock::new(None);
fn intercepted(name: &str, bytes: &mut [u8]) {
    let hook = RX_HOOK.lock().clone();
    if let Some(hook) = hook {
        hook(name, bytes);
    }
}
struct RestoreRx;
impl Drop for RestoreRx {
    fn drop(&mut self) {
        *RX_HOOK.lock() = None;
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    }
}
fn group_rekey(h: &Harness) -> Result<Vec<u8>, &'static str> {
    let pdu = {
        let p = h.peer.lock();
        let ptk = p.ptk.as_ref().ok_or("group rekey PTK absent")?;
        let mut clear = vec![48, 20];
        clear.extend_from_slice(&narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body());
        clear.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
        clear.extend_from_slice(&[0x66; 16]);
        if clear.len() % 8 != 0 {
            clear.push(0xdd);
        }
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
        let mut key = KeyFrame::empty(16);
        key.key_information = 0x1382;
        key.key_length = 16;
        key.replay_counter = 3;
        key.key_data = narf_crypto::aes_kw::aes_wrap(
            ptk.kek.as_slice().try_into().map_err(|_| "group KEK")?,
            &clear,
        )
        .ok_or("group KDE wrap")?;
        let mut pdu = key.into_eapol();
        pdu[0] = 2;
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &pdu);
        pdu[81..97].copy_from_slice(&mic[..16]);
        pdu
    };
    let mut e = h.peer.lock().plan.station.to_vec();
    e.extend_from_slice(&PEER);
    e.extend_from_slice(&[0x88, 0x8e]);
    e.extend_from_slice(&pdu);
    h.peer.lock().downlink(&e)
}
fn smoke_rtl8188ee_ht20_reentrant_amsdu_key_epoch_reopen_and_tx_credit() -> TestResult {
    check(|| {
        for mode in 0..4 {
            let h = Arc::new(Harness::new_profile(true, true));
            ht_join(&h)?;
            let count = retained(&h);
            let frames = vec![packet(&h, 30, false), packet(&h, 31, false)];
            let raw = aggregate(&h, &frames, 301)?;
            let rekey = group_rekey(&h)?;
            let seen = Arc::new(IrqSafeSpinLock::new(Vec::<Vec<u8>>::new()));
            let okay = Arc::new(AtomicBool::new(true));
            let calls = Arc::new(AtomicUsize::new(0));
            let target = h.clone();
            let log = seen.clone();
            let valid = okay.clone();
            let called = calls.clone();
            *RX_HOOK.lock() = Some(Arc::new(move |name, bytes| {
                if name != target.device.name() {
                    return;
                }
                log.lock().push(bytes.to_vec());
                if called.fetch_add(1, Ordering::AcqRel) != 0 {
                    return;
                }
                if mode == 3 {
                    target.ht_source.as_ref().unwrap().1.revoke();
                    return;
                }
                target.peer.lock().hold_data = true;
                if mode == 0 {
                    if target
                        .device
                        .enqueue(&packet(&target, 32, true), TxMeta::default())
                        .is_err()
                    {
                        valid.store(false, Ordering::Release);
                    }
                } else {
                    target.packet.emit_native(&rekey, 0x53, 0, None).unwrap();
                }
                target.pump();
                if target.packet.model.lock().held.is_none() {
                    valid.store(false, Ordering::Release);
                }
                let open = target
                    .device
                    .prepared
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .station_receive_open();
                if open != (mode == 0) {
                    valid.store(false, Ordering::Release);
                }
                if mode != 0 && !target.received().is_empty() {
                    valid.store(false, Ordering::Release);
                }
                if mode == 2 {
                    target.peer.lock().hold_data = false;
                    target.packet.release_held();
                    target.pump();
                    if !target
                        .device
                        .prepared
                        .try_lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .station_receive_open()
                    {
                        valid.store(false, Ordering::Release);
                    }
                }
            }));
            let restore = RestoreRx;
            narf_net::iface::install_rx_handler(intercepted);
            h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
            h.pump();
            let expected = if mode == 0 {
                frames
            } else {
                vec![frames[0].clone()]
            };
            if *seen.lock() != expected
                || !okay.load(Ordering::Acquire)
                || h.device.link_up() != (mode != 3)
                || retained(&h) < count
            {
                return Err(
                    "reentrant A-MSDU batch crossed key epoch or mistook ordinary TX credit for closure",
                );
            }
            if mode == 3 {
                drop(restore);
                continue;
            }
            h.peer.lock().hold_data = false;
            if h.packet.model.lock().held.is_some() {
                h.packet.release_held();
            }
            h.pump();
            let fresh = vec![packet(&h, 33, false)];
            let raw = aggregate(&h, &fresh, 303)?;
            h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
            h.pump();
            if seen.lock().last() != fresh.last() {
                return Err("new receive epoch did not admit actual successor aggregate");
            }
            drop(restore);
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_reentrant_amsdu_key_epoch_reopen_and_tx_credit
);
fn smoke_rtl8188ee_ht20_native_mailbox_cancel_and_per_poll_source_fence() -> TestResult {
    check(|| {
        for revoke in [false, true] {
            let h = Harness::new_profile(true, true);
            {
                let mut model = h.packet.model.lock();
                model.hold_command = Some(0x20);
                model.wait = true;
            }
            let count = retained(&h);
            {
                let request = ScanRequest {
                    ssids: vec![SSID.to_vec()],
                    frequencies_mhz: vec![2412],
                    channels: vec![1],
                    active: false,
                    random_mac: None,
                    colocated_6ghz: false,
                    duration_tu: Some(1),
                    duration_mandatory: false,
                    extra_ies: Vec::new(),
                };
                let mut future = core::pin::pin!(h.device.scan(request));
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..20 {
                    if future.as_mut().poll(&mut cx).is_ready() {
                        return Err("HT native awake mailbox did not hold actual owner");
                    }
                    if h.packet
                        .model
                        .lock()
                        .commands
                        .iter()
                        .any(|(id, _)| *id == 0x20)
                    {
                        break;
                    }
                }
                if !h
                    .packet
                    .model
                    .lock()
                    .commands
                    .iter()
                    .any(|(id, _)| *id == 0x20)
                {
                    return Err("HT cancellation missed the native command publication");
                }
                if revoke {
                    h.ht_source.as_ref().unwrap().1.revoke();
                    let before = h.packet.model.lock().commands.len();
                    h.packet.model.lock().hold_command = None;
                    if !matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(_)))
                        || h.packet.model.lock().commands.len() != before
                    {
                        return Err(
                            "resumed mailbox future published after observed HT-source denial",
                        );
                    }
                }
            }
            h.pump();
            if h.device.link_up()
                || h.packet.model.lock().master
                || retained(&h) != count
                || h.device
                    .prepared
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .station_phase()
                    != Logical::Failed
            {
                return Err("cancelled or revoked HT native command reused/released owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_native_mailbox_cancel_and_per_poll_source_fence
);
fn smoke_rtl8188ee_ht20_bound_ht_wmm_response_gates_native_port() -> TestResult {
    check(|| {
        for fault in 0..6 {
            let h = Harness::new_profile(true, true);
            h.scan();
            let count = retained(&h);
            {
                let mut p = h.peer.lock();
                let b = p.ht.as_mut().unwrap();
                match fault {
                    0 => b[30] = 6,
                    1 => {
                        let duplicate = b.clone();
                        b.extend_from_slice(&duplicate);
                    }
                    2 => b[5] = 0,
                    3 => b[32] = 3,
                    4 => b.truncate(28),
                    _ => {
                        p.wmm = None;
                    }
                }
            }
            if complete(h.device.associate(h.request())).is_ok()
                || !h.closed()
                || !h.received().is_empty()
                || retained(&h) < count
            {
                return Err(
                    "unbound/unsupported response admitted native HT or released uncertain DMA",
                );
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_bound_ht_wmm_response_gates_native_port
);
fn smoke_rtl8188ee_ht20_cancelled_native_m4_retains_closed_dma_owner() -> TestResult {
    check(|| {
        let h = Harness::new_profile(true, true);
        h.scan();
        h.peer.lock().hold_m4 = true;
        {
            let mut join = core::pin::pin!(h.device.associate(h.request()));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..100 {
                if join.as_mut().poll(&mut cx).is_ready() {
                    return Err("cancelled HT M4 missed native wait");
                }
                if h.packet.model.lock().held.is_some() {
                    break;
                }
            }
            if h.packet.model.lock().held.is_none() {
                return Err("cancelled HT M4 lacked immutable native payload");
            }
        }
        let count = retained(&h);
        h.packet.release_held();
        h.pump();
        if !h.closed()
            || h.packet.model.lock().master
            || !h.received().is_empty()
            || retained(&h) != count
            || complete(h.device.associate(h.request())).is_ok()
        {
            return Err("cancelled HT M4 late receipt reopened/released/reconstructed owner");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_cancelled_native_m4_retains_closed_dma_owner
);
fn addba_response(h: &Harness, token: u8, status: u16, params: u16, timeout: u16) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&h.peer.lock().plan.station);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&[0, 0, 3, 1, token]);
    f.extend_from_slice(&status.to_le_bytes());
    f.extend_from_slice(&params.to_le_bytes());
    f.extend_from_slice(&timeout.to_le_bytes());
    f
}
/// Advance `ms` in 2 s steps, each refreshed by one downlink so the 5 s
/// peer-loss bound never fires.
fn settle(h: &Harness, ms: u64, n: &mut u8) -> Result<(), &'static str> {
    let mut left = ms;
    while left != 0 {
        let step = left.min(2000);
        h.env.now.fetch_add(step, Ordering::AcqRel);
        left -= step;
        *n = n.wrapping_add(1);
        let down = packet(h, *n, false);
        let raw = h.peer.lock().downlink(&down)?;
        h.packet
            .emit_native(&raw, 0x53, 0, None)
            .map_err(|_| "keepalive RX injection")?;
        h.pump();
        h.received();
    }
    Ok(())
}
/// One uplink; returns (TXD of the QoS DATA, its 802.11 sequence number).
fn uplink(h: &Harness, n: u8) -> Result<(Vec<u8>, u16), &'static str> {
    h.device
        .enqueue(&packet(h, n, true), TxMeta::default())
        .map_err(|_| "originator enqueue")?;
    h.pump();
    let model = h.packet.model.lock();
    let i = model
        .observed
        .iter()
        .rposition(|f| f[0] == 0x88)
        .ok_or("no QoS DATA emitted")?;
    let f = &model.observed[i];
    Ok((
        model.descriptors[i].clone(),
        u16::from_le_bytes([f[22], f[23]]) >> 4,
    ))
}
fn agg(d: &[u8]) -> (bool, u32, u32) {
    (
        word(d, 8) & (1 << 12) != 0,
        (word(d, 8) >> 20) & 7,
        (word(d, 24) >> 11) & 31,
    )
}
fn last_control(h: &Harness) -> Vec<u8> {
    h.peer.lock().controls.last().cloned().unwrap_or_default()
}
fn originator(protected: bool) -> Result<(), &'static str> {
    let h = Harness::new_profile(protected, true);
    {
        let mut e = ht::tests::ap_elements(255);
        e[4] = 5 << 2 | 3;
        h.peer.lock().ht = Some(e);
    }
    ht_join(&h)?;
    let mut n = 10u8;
    let controls = |h: &Harness| h.peer.lock().controls.len();
    // Before `cnt_after_linked` reaches 3 no session starts; the TXD
    // already carries the peer density without AGG_EN.
    let (d, _) = uplink(&h, 1)?;
    if agg(&d) != (false, 5, 0) || controls(&h) != 0 {
        return Err("pre-settle QoS DATA lost density or started a session");
    }
    settle(&h, 6000, &mut n)?;
    let (d, seq) = uplink(&h, 2)?;
    if agg(&d).0 {
        return Err("AGG_EN before the ADDBA exchange");
    }
    let tid = *h.peer.lock().tids.last().ok_or("no uplink TID")?;
    let request = last_control(&h);
    if request.len() != 33 || request[24..27] != [3, 0, 1] {
        return Err("ADDBA Request shape/token");
    }
    if u16::from_le_bytes([request[27], request[28]]) != 3 | u16::from(tid) << 2 | 64 << 6
        || u16::from_le_bytes([request[29], request[30]]) != 5000
    {
        return Err("ADDBA Request A-MSDU/policy/TID/window/timeout");
    }
    if u16::from_le_bytes([request[31], request[32]]) >> 4 != (seq + 1) & 4095 {
        return Err("ADDBA Request SSN");
    }
    let params = 2 | u16::from(tid) << 2 | 64 << 6;
    // A stale token is ignored; the outstanding one makes the TID operational.
    for token in [9, 1] {
        h.packet
            .emit_native(&addba_response(&h, token, 0, params, 0), 0x53, 0, None)
            .map_err(|_| "ADDBA Response injection")?;
        h.pump();
    }
    let (d, _) = uplink(&h, 3)?;
    if agg(&d) != (true, 5, 0x14) {
        return Err("operational TID lost AGG_EN/density/MAX_AGG_NUM");
    }
    // Recipient DELBA: silent stop, next delivery restarts with token 2.
    let before = controls(&h);
    let mut delba = vec![0xd0, 0, 0, 0];
    delba.extend_from_slice(&h.peer.lock().plan.station);
    delba.extend_from_slice(&PEER);
    delba.extend_from_slice(&PEER);
    delba.extend_from_slice(&[0, 0, 3, 2]);
    delba.extend_from_slice(&(u16::from(tid) << 12).to_le_bytes());
    delba.extend_from_slice(&1u16.to_le_bytes());
    h.packet
        .emit_native(&delba, 0x53, 0, None)
        .map_err(|_| "DELBA injection")?;
    h.pump();
    if controls(&h) != before {
        return Err("peer DELBA answered with a DELBA");
    }
    let (d, _) = uplink(&h, 4)?;
    let last = last_control(&h);
    if agg(&d).0 || controls(&h) != before + 1 || last.get(24..27) != Some(&[3, 0, 2][..]) {
        return Err("stopped TID kept AGG_EN or did not restart");
    }
    // No response within ADDBA_RESP_INTERVAL: initiator DELBA QSTA_NOT_USE.
    settle(&h, 1000, &mut n)?;
    let last = last_control(&h);
    if last.len() != 30
        || last[24..26] != [3, 2]
        || u16::from_le_bytes([last[26], last[27]]) != u16::from(tid) << 12 | 1 << 11
        || last[28..30] != 37u16.to_le_bytes()
    {
        return Err("response timeout did not send the initiator DELBA");
    }
    // Declines stop silently; beyond HT_AGG_BURST_RETRIES in 15 s mac80211
    // refuses the start and rtlwifi leaves the TID at RTL_AGG_PROGRESS.
    for token in 3..=5u8 {
        let before = controls(&h);
        uplink(&h, 2 + token)?;
        let last = last_control(&h);
        if controls(&h) != before + 1 || last.get(24..27) != Some(&[3, 0, token][..]) {
            return Err("declined TID did not retry");
        }
        h.packet
            .emit_native(&addba_response(&h, token, 37, params, 0), 0x53, 0, None)
            .map_err(|_| "decline injection")?;
        h.pump();
        if controls(&h) != before + 1 {
            return Err("decline answered with a DELBA");
        }
    }
    let before = controls(&h);
    let (d, _) = uplink(&h, 9)?;
    if controls(&h) != before || agg(&d).0 {
        return Err("burst retry limit did not park the TID");
    }
    complete(h.device.disassociate()).map_err(|_| "originator close")?;
    if !h.closed() {
        return Err("originator teardown retained admission");
    }
    Ok(())
}
fn smoke_rtl8188ee_ht20_originator_ba_and_tx_ampdu() -> TestResult {
    check(|| originator(false).and_then(|()| originator(true)))
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht20",
    smoke_rtl8188ee_ht20_originator_ba_and_tx_ampdu
);
