// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Host AP PS/U-APSD owner against mac80211 sta_info.c/rx.c/tx.c rules.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const STA: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const STA2: [u8; 6] = [0x02, 0, 0, 0, 0, 3];

fn peer(aid: u16, addr: [u8; 6], uapsd_queues: u8, max_sp: u8) -> PeerConfig {
    PeerConfig {
        aid,
        addr,
        wme: true,
        uapsd_queues,
        max_sp,
        listen_interval: 10,
    }
}
/// FromDS QoS data with `tid`, 4-byte body tagged `tag`.
fn qos_data(tid: u8, tag: u8) -> Vec<u8> {
    let mut f = vec![0x88, 0x02, 0, 0];
    f.extend_from_slice(&STA);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&[0, 0, tid, 0, tag, tag, tag, tag]);
    f
}
/// ToDS (QoS) Null / data header from the peer with PM.
fn uplink(qos: bool, null: bool, tid: u8, pm: bool) -> Vec<u8> {
    let subtype: u8 = match (qos, null) {
        (true, true) => 0xc,
        (true, false) => 0x8,
        (false, true) => 0x4,
        (false, false) => 0x0,
    };
    let mut f = vec![
        0x08 | (subtype << 4),
        0x01 | if pm { 0x10 } else { 0 },
        0,
        0,
    ];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&STA);
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&[0, 0]);
    if qos {
        f.extend_from_slice(&[tid, 0]);
    }
    f
}
fn pspoll() -> Vec<u8> {
    let mut f = vec![0xa4, 0x10, 1, 0xc0];
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&STA);
    f
}
fn doze(ps: &mut ApPs, aid: u16) -> bool {
    ps.receive(aid, &uplink(true, true, 0, true), false)
        .is_ok_and(|r| r.transition == Some(true))
}
fn eosp(r: &Response) -> bool {
    r.mpdu.get(24).is_some_and(|q| q & 0x10 != 0)
}
fn more_data(r: &Response) -> bool {
    r.mpdu[1] & 0x20 != 0
}

fn smoke_rtw89_ap_ps_buffers_dozing_peer_sets_tim_and_wakeup_flushes() -> TestResult {
    let mut ps = ApPs::new(OWN, 100);
    if ps.add_peer(peer(1, STA, 0, 0)).is_err() {
        return TestResult::Fail("legacy-PS WME peer refused");
    }
    if ps.transmit(1, qos_data(0, 1), 0, 0) != Ok(Transmit::Send(qos_data(0, 1))) {
        return TestResult::Fail("awake peer frame was buffered");
    }
    if !doze(&mut ps, 1) || ps.dozing(1) != Some(true) {
        return TestResult::Fail("PM=1 data did not enter power save");
    }
    if ps.transmit(1, qos_data(0, 2), 0, 0) != Ok(Transmit::Buffered { tim_changed: true })
        || !ps.tim_bit(1)
    {
        return TestResult::Fail("dozing peer frame not buffered with TIM");
    }
    if ps.transmit(1, qos_data(6, 3), 6, 0) != Ok(Transmit::Buffered { tim_changed: false }) {
        return TestResult::Fail("second buffered frame re-flipped TIM");
    }
    let tim = ps.tim_element(0, 2);
    // AID1: N1=0, bitmap control 0, one PVB octet with bit1.
    if tim != vec![5, 4, 0, 2, 0, 0x02] {
        return TestResult::Fail("TIM element differs from ieee80211_beacon_add_tim_pvb");
    }
    let out = match ps.receive(1, &uplink(true, true, 0, false), false) {
        Ok(out) => out,
        Err(_) => return TestResult::Fail("wake frame refused"),
    };
    if out.transition != Some(false)
        || !out.tim_changed
        || ps.tim_bit(1)
        || out.responses.len() != 2
        || out.responses[0].tid != 6
        || out.responses[1].tid != 0
        || out.responses.iter().any(|r| r.ends_period || more_data(r))
        || ps.total_buffered() != 0
    {
        return TestResult::Fail("wakeup did not flush VO..BK unchanged and clear TIM");
    }
    if ps.tim_element(1, 2) != vec![5, 4, 1, 2, 0, 0] {
        return TestResult::Fail("empty TIM element");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_ps_buffers_dozing_peer_sets_tim_and_wakeup_flushes
);

fn smoke_rtw89_ap_ps_pspoll_releases_one_with_more_data_and_eosp_status() -> TestResult {
    let mut ps = ApPs::new(OWN, 100);
    let _ = ps.add_peer(peer(1, STA, 0, 0));
    doze(&mut ps, 1);
    for tag in 0..2 {
        let _ = ps.transmit(1, qos_data(0, tag), 0, 0);
    }
    let first = match ps.receive(1, &pspoll(), false) {
        Ok(out) => out,
        Err(_) => return TestResult::Fail("PS-Poll refused"),
    };
    if !first.consumed
        || first.responses.len() != 1
        || !more_data(&first.responses[0])
        || !first.responses[0].ends_period
        || eosp(&first.responses[0])
        || ps.in_service_period(1) != Some(true)
    {
        return TestResult::Fail("PS-Poll response must be one MoreData frame ending the poll");
    }
    // A second poll inside the open period is ignored (WLAN_STA_SP).
    if ps.receive(1, &pspoll(), false).map(|r| r.responses.len()) != Ok(0) {
        return TestResult::Fail("PS-Poll during an open period released frames");
    }
    ps.tx_status(1, &first.responses[0]);
    let second = ps.receive(1, &pspoll(), false).unwrap_or_default();
    if second.responses.len() != 1 || more_data(&second.responses[0]) || !second.tim_changed {
        return TestResult::Fail("last PS-Poll frame kept MoreData or TIM");
    }
    ps.tx_status(1, &second.responses[0]);
    // Nothing left: a QoS Null without EOSP answers the race.
    let third = ps.receive(1, &pspoll(), false).unwrap_or_default();
    if third.responses.len() != 1
        || !third.responses[0].null
        || eosp(&third.responses[0])
        || third.responses[0].mpdu[0] != 0xc8
        || third.responses[0].mpdu[1] != 0x02
    {
        return TestResult::Fail("empty PS-Poll did not answer with FromDS QoS Null");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_ps_pspoll_releases_one_with_more_data_and_eosp_status
);

fn smoke_rtw89_ap_ps_uapsd_trigger_delivers_max_sp_with_eosp() -> TestResult {
    let mut ps = ApPs::new(OWN, 100);
    // VO+VI delivery/trigger-enabled, Max SP 1 => two frames.
    if ps.add_peer(peer(1, STA, 0x3, 1)).is_err() {
        return TestResult::Fail("U-APSD peer refused");
    }
    doze(&mut ps, 1);
    let mut changed = false;
    for tag in 0..3 {
        if let Ok(Transmit::Buffered { tim_changed }) = ps.transmit(1, qos_data(6, tag), 6, 0) {
            changed |= tim_changed;
        }
    }
    if changed || ps.tim_bit(1) {
        return TestResult::Fail("delivery-enabled AC indicated in TIM");
    }
    let _ = ps.transmit(1, qos_data(0, 9), 0, 0);
    if !ps.tim_bit(1) {
        return TestResult::Fail("legacy BE frame missing from TIM");
    }
    // BE trigger is not trigger-enabled: no delivery.
    let be = ps
        .receive(1, &uplink(true, true, 0, true), false)
        .unwrap_or_default();
    if !be.responses.is_empty() {
        return TestResult::Fail("non-trigger-enabled AC started a service period");
    }
    let sp = ps
        .receive(1, &uplink(true, false, 6, true), false)
        .unwrap_or_default();
    if sp.responses.len() != 2
        || !more_data(&sp.responses[0])
        || eosp(&sp.responses[0])
        || !more_data(&sp.responses[1])
        || !eosp(&sp.responses[1])
        || !sp.responses[1].ends_period
        || sp.transition.is_some()
        || ps.buffered(1) != 2
    {
        return TestResult::Fail("Max SP 2 frames with EOSP on last and MoreData remaining");
    }
    // Trigger inside the period is ignored.
    if !ps
        .receive(1, &uplink(true, true, 5, true), false)
        .is_ok_and(|r| r.responses.is_empty())
    {
        return TestResult::Fail("trigger during service period delivered");
    }
    ps.tx_status(1, &sp.responses[1]);
    let last = ps
        .receive(1, &uplink(true, true, 5, true), false)
        .unwrap_or_default();
    if last.responses.len() != 1 || more_data(&last.responses[0]) || !eosp(&last.responses[0]) {
        return TestResult::Fail("final VO frame must clear MoreData (BE is not delivery-enabled)");
    }
    ps.tx_status(1, &last.responses[0]);
    // Empty delivery-enabled ACs: QoS Null with EOSP on TID 7 (VO).
    let empty = ps
        .receive(1, &uplink(true, true, 7, true), false)
        .unwrap_or_default();
    if empty.responses.len() != 1
        || !empty.responses[0].null
        || empty.responses[0].tid != 7
        || empty.responses[0].mpdu[24] != 0x17
    {
        return TestResult::Fail("empty U-APSD period must send EOSP QoS Null TID7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_ps_uapsd_trigger_delivers_max_sp_with_eosp
);

fn smoke_rtw89_ap_ps_all_acs_delivery_enabled_tim_and_mmpdu_null() -> TestResult {
    let mut ps = ApPs::new(OWN, 100);
    let _ = ps.add_peer(peer(1, STA, 0xf, 0));
    doze(&mut ps, 1);
    // Bufferable deauth (stype 0xC) as the only unit.
    let mut deauth = vec![0xc0, 0, 0, 0];
    deauth.extend_from_slice(&STA);
    deauth.extend_from_slice(&OWN);
    deauth.extend_from_slice(&OWN);
    deauth.extend_from_slice(&[0, 0, 3, 0]);
    if ps.transmit(1, deauth.clone(), 7, 0) != Ok(Transmit::Buffered { tim_changed: true }) {
        return TestResult::Fail("all-ACs-delivery-enabled peer must still indicate TIM");
    }
    // Probe Response is not bufferable.
    let mut probe = deauth.clone();
    probe[0] = 0x50;
    if !matches!(ps.transmit(1, probe, 7, 0), Ok(Transmit::Send(_))) {
        return TestResult::Fail("non-bufferable MMPDU was buffered");
    }
    let sp = ps
        .receive(1, &uplink(true, true, 1, true), false)
        .unwrap_or_default();
    if sp.responses.len() != 2
        || sp.responses[0].ends_period
        || !more_data(&sp.responses[0])
        || !sp.responses[1].null
        || sp.responses[1].tid != 7
        || !eosp(&sp.responses[1])
    {
        return TestResult::Fail("MMPDU-terminated period needs MoreData then EOSP QoS Null");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_ps_all_acs_delivery_enabled_tim_and_mmpdu_null
);

fn smoke_rtw89_ap_ps_limits_expiry_and_peer_validation() -> TestResult {
    let mut ps = ApPs::new(OWN, 100);
    let mut bad = peer(1, STA, 0x10, 0);
    if ps.add_peer(bad) != Err(Error::Invalid) {
        return TestResult::Fail("U-APSD mask beyond four ACs admitted");
    }
    bad = peer(1, STA, 1, 0);
    bad.wme = false;
    if ps.add_peer(bad) != Err(Error::Invalid) {
        return TestResult::Fail("non-WME U-APSD admitted");
    }
    if ps.add_peer(peer(0, STA, 0, 0)) != Err(Error::Invalid)
        || ps.add_peer(peer(MAX_AID + 1, STA, 0, 0)) != Err(Error::Invalid)
    {
        return TestResult::Fail("AID outside 1..2007 admitted");
    }
    let _ = ps.add_peer(peer(1, STA, 0, 0));
    if ps.add_peer(peer(2, STA, 0, 0)) != Err(Error::Duplicate) {
        return TestResult::Fail("duplicate address admitted");
    }
    let _ = ps.add_peer(peer(1000, STA2, 0, 0));
    doze(&mut ps, 1);
    for tag in 0..(STA_MAX_TX_BUFFER as u8 + 3) {
        let _ = ps.transmit(1, qos_data(0, tag), 0, 0);
    }
    if ps.buffered(1) != STA_MAX_TX_BUFFER || ps.total_buffered() != STA_MAX_TX_BUFFER {
        return TestResult::Fail("per-AC buffer exceeded STA_MAX_TX_BUFFER");
    }
    // Group frame goes after DTIM while any peer dozes.
    if !group_after_dtim(&ps, 0x0208) || group_after_dtim(&ps, 0x0040) {
        return TestResult::Fail("SEND_AFTER_DTIM rule");
    }
    // Group-addressed PM=0 frame does not wake the peer.
    let group = ps
        .receive(1, &uplink(false, false, 0, false), true)
        .unwrap_or_default();
    if group.transition.is_some() || ps.dozing(1) != Some(true) {
        return TestResult::Fail("group-addressed frame changed PS state");
    }
    // Expiry: listen 10 * 100 TU * 32/15625 = 2 s < 10 s floor.
    if !ps.expire(10_000).is_empty() || ps.buffered(1) == 0 {
        return TestResult::Fail("expired before 10 s floor");
    }
    if ps.expire(10_001) != vec![1] || ps.buffered(1) != 0 || ps.tim_bit(1) {
        return TestResult::Fail("expiry did not drop and clear TIM");
    }
    // A high AID TIM uses an even N1 offset.
    let mut far = ApPs::new(OWN, 100);
    let _ = far.add_peer(peer(1000, STA2, 0, 0));
    let mut doze_far = uplink(true, true, 0, true);
    doze_far[10..16].copy_from_slice(&STA2);
    let _ = far.receive(1000, &doze_far, false);
    let _ = far.transmit(1000, qos_data(0, 1), 0, 0);
    // AID 1000 = octet 125 bit 0; N1 = 124.
    if far.tim_element(0, 1) != vec![5, 5, 0, 1, 124, 0, 1] {
        return TestResult::Fail("partial virtual bitmap offset");
    }
    if far.remove_peer(1000) != Ok(true) || far.total_buffered() != 0 {
        return TestResult::Fail("removal kept buffers or TIM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_ps_limits_expiry_and_peer_validation
);
