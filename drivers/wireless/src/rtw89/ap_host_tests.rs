// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AP host session against mac80211 tx.c/rx.c AP rules (unexecuted).
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const STA: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const OTHER: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
const TK: [u8; 16] = [0x5a; 16];

fn config(privacy: bool) -> ApConfig {
    let mut head = vec![0x80, 0, 0, 0];
    head.extend_from_slice(&[0xff; 6]);
    head.extend_from_slice(&OWN);
    head.extend_from_slice(&OWN);
    head.extend_from_slice(&[0, 0]);
    head.extend_from_slice(&[0; 8]);
    head.extend_from_slice(&[100, 0, 0x11, 0x04]);
    head.extend_from_slice(&[0, 4, b'n', b'a', b'r', b'f']);
    ApConfig {
        ssid: b"narf".to_vec(),
        beacon_head: head,
        beacon_tail: vec![3, 1, 6],
        probe_resp: None,
        beacon_interval: 100,
        dtim_period: 2,
        frequency_mhz: 2437,
        channel_width: 1,
        center_freq1_mhz: Some(2437),
        center_freq2_mhz: None,
        hidden_ssid: 0,
        privacy,
        mbssid: None,
        mbssid_elems: Vec::new(),
        ema_rnr_elems: Vec::new(),
        fils_discovery: None,
        unsol_bcast_probe_resp: None,
        ftm_responder: None,
        twt_responder: false,
        he_obss_pd: None,
        he_bss_color: None,
    }
}
fn station(aid: u16, authorized: Option<bool>) -> StationConfig {
    StationConfig {
        mac: STA,
        aid,
        listen_interval: 10,
        supported_rates: vec![0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36],
        wme: Some(false),
        uapsd_queues: None,
        uapsd_max_sp: None,
        mfp: None,
        capability: None,
        ext_capability: None,
        ht_capability: None,
        vht_capability: None,
        he_capability: None,
        he_6ghz_capability: None,
        authorized,
        station_tx_power: None,
    }
}
/// A started host with one associated, authorized peer on MACID 1.
fn started(privacy: bool) -> Option<Host> {
    let mut host = Host::default();
    let plan = Plan::new(OWN, &config(privacy), &ApStartSettings::default(), 6).ok()?;
    host.start(OWN, plan, ApStartSettings::default());
    host.add_peer(&station(0, None), 1).ok()?;
    host.associate(STA, 1).ok()?;
    host.update_peer(&station(1, Some(true))).ok()?;
    if privacy {
        let install = Install::from_params(&narf_wireless::KeyParams {
            idx: 0,
            pairwise: true,
            peer: Some(STA),
            cipher: CCMP,
            key: TK.to_vec(),
            seq: Vec::new(),
            default_mgmt: false,
        })
        .ok()?;
        host.install_key(&install).ok()?;
    }
    Some(host)
}
/// ToDS data from the peer, optionally CCMP-protected with PN `pn`.
fn uplink(da: [u8; 6], ethertype: u16, payload: &[u8], pn: Option<u64>, pm: bool) -> Vec<u8> {
    let mut header = vec![0x08, 0x01 | if pm { 0x10 } else { 0 }, 0, 0];
    header.extend_from_slice(&OWN);
    header.extend_from_slice(&STA);
    header.extend_from_slice(&da);
    header.extend_from_slice(&[0x10, 0]);
    let mut body = LLC.to_vec();
    body.extend_from_slice(&ethertype.to_be_bytes());
    body.extend_from_slice(payload);
    match pn {
        Some(pn) => {
            header[1] |= 0x40;
            let protected = narf_wireless::ccmp::protect(
                &ap_crypto::Ccm,
                &header,
                &TK,
                pn,
                0,
                0,
                false,
                &mut body,
            )
            .unwrap_or_default();
            header.extend_from_slice(&protected);
        }
        None => header.extend_from_slice(&body),
    }
    header
}

fn smoke_rtw89_ap_host_plan_admits_only_the_20mhz_ccmp_profile() -> TestResult {
    let settings = ApStartSettings::default();
    if Plan::new(OWN, &config(true), &settings, 6).is_err() {
        return TestResult::Fail("plain 20 MHz CCMP AP refused");
    }
    let mut wide = config(true);
    wide.channel_width = 2;
    let mut twt = config(true);
    twt.twt_responder = true;
    let mut tim_in_head = config(true);
    tim_in_head
        .beacon_head
        .extend_from_slice(&[5, 4, 0, 2, 0, 0]);
    let mut foreign = config(true);
    foreign.beacon_head[10..16].copy_from_slice(&OTHER);
    let tkip = ApStartSettings {
        pairwise_ciphers: Some(vec![0x000f_ac02]),
        ..ApStartSettings::default()
    };
    if Plan::new(OWN, &wide, &settings, 6) != Err(Error::Unsupported)
        || Plan::new(OWN, &twt, &settings, 6) != Err(Error::Unsupported)
        || Plan::new(OWN, &config(true), &tkip, 6) != Err(Error::Unsupported)
        || Plan::new(OWN, &tim_in_head, &settings, 6) != Err(Error::Invalid)
        || Plan::new(OWN, &foreign, &settings, 6) != Err(Error::Invalid)
    {
        return TestResult::Fail("richer START_AP must be refused, not dropped");
    }
    // CCK 1/2/5.5/11 -> bits 0..3, OFDM 6 -> bit 4, OFDM 54 -> bit 11
    // (the 2 GHz sband bitrate order `rtw89_phy_ra_sta_update` indexes).
    if legacy_rates(&[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x6c], false) != 0x81f
        || legacy_rates(&[0x82, 0x0c, 0x6c], true) != 0x810
    {
        return TestResult::Fail("RA legacy bitmap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_host_plan_admits_only_the_20mhz_ccmp_profile
);

fn smoke_rtw89_ap_host_ccmp_fromds_tx_and_macid_bound_rx() -> TestResult {
    let Some(mut host) = started(true) else {
        return TestResult::Fail("fixture");
    };
    let mut eth = STA.to_vec();
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 20]);
    if host.transmit_ethernet(&eth, 0).is_err() {
        return TestResult::Fail("authorized unicast refused");
    }
    let Some(out) = host.next_outbound().cloned() else {
        return TestResult::Fail("no outbound MPDU");
    };
    // Non-WME peer: FromDS protected data, A1 DA, A2 BSSID, A3 SA, PN 1.
    if out.mpdu[..2] != [0x08, 0x42]
        || out.mpdu[4..10] != STA
        || out.mpdu[10..16] != OWN
        || out.mpdu[16..22] != OWN
        || out.mpdu[24..32] != [1, 0, 0, 0x20, 0, 0, 0, 0]
        || out.after_dtim
    {
        return TestResult::Fail("FromDS CCMP header");
    }
    host.consume_outbound(7);
    let frame = uplink(OTHER, 0x0800, &[0x45, 1, 2, 3], Some(1), false);
    if !host.receive(Some(2), &frame, 0).is_empty() {
        return TestResult::Fail("frame accepted under another MACID");
    }
    let inbound = host.receive(Some(1), &frame, 0);
    let ok = matches!(inbound.as_slice(), [Inbound::Ethernet(eth)]
        if eth[..6] == OTHER && eth[6..12] == STA && eth[12..] == [0x08, 0, 0x45, 1, 2, 3]);
    if !ok {
        return TestResult::Fail("decrypted 802.3 delivery");
    }
    if !host.receive(Some(1), &frame, 0).is_empty() {
        return TestResult::Fail("CCMP replay accepted");
    }
    if host.key_sequence(Target::Pairwise(STA)) != Ok([1, 0, 0, 0, 0, 0]) {
        return TestResult::Fail("GET_KEY must report the consumed TX PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_host_ccmp_fromds_tx_and_macid_bound_rx
);

fn smoke_rtw89_ap_host_control_port_and_unencrypted_drop() -> TestResult {
    let Some(mut host) = started(true) else {
        return TestResult::Fail("fixture");
    };
    let eapol = uplink(OWN, 0x888e, &[1, 3, 0, 4], None, false);
    let ok = matches!(host.receive(Some(1), &eapol, 0).as_slice(),
        [Inbound::Control { peer, ethertype: 0x888e, unencrypted: true, .. }] if *peer == STA);
    if !ok {
        return TestResult::Fail("clear EAPOL must reach the control port");
    }
    let clear = uplink(OWN, 0x0800, &[0x45], None, false);
    if !host.receive(Some(1), &clear, 0).is_empty() {
        return TestResult::Fail("ieee80211_drop_unencrypted");
    }
    let mut eapol_eth = STA.to_vec();
    eapol_eth.extend_from_slice(&OWN);
    eapol_eth.extend_from_slice(&[0x88, 0x8e, 1]);
    if host.transmit_ethernet(&eapol_eth, 0) != Err(Error::Invalid) {
        return TestResult::Fail("EAPOL must not use the netdev path");
    }
    match host.control_frame(STA, 0x888e, &[1, 3, 0, 0], true) {
        Ok(mpdu) if mpdu[1] == 0x02 && mpdu[30..32] == [0x88, 0x8e] => {}
        _ => return TestResult::Fail("no_encrypt control-port frame"),
    }
    match host.control_frame(STA, 0x888e, &[1, 3, 0, 0], false) {
        Ok(mpdu) if mpdu[1] == 0x42 => {}
        _ => return TestResult::Fail("installed PTK must protect control port"),
    }
    if host.control_frame(OTHER, 0x888e, &[1], true).is_ok() {
        return TestResult::Fail("control port to an unknown peer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_host_control_port_and_unencrypted_drop
);

fn smoke_rtw89_ap_host_dozing_peer_tim_and_pspoll_release() -> TestResult {
    let Some(mut host) = started(false) else {
        return TestResult::Fail("fixture");
    };
    // Null data with PM: the peer dozes (rx.c sta_ps_start).
    let mut null = uplink(OWN, 0, &[], None, true);
    null[0] = 0x48;
    null.truncate(24);
    let _ = host.receive(Some(1), &null, 0);
    let mut eth = STA.to_vec();
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x08, 0x00, 0x45]);
    if host.transmit_ethernet(&eth, 0).is_err() || host.next_outbound().is_some() {
        return TestResult::Fail("dozing peer frame must be buffered");
    }
    if !host.beacon_dirty() {
        return TestResult::Fail("TIM change must refresh the beacon");
    }
    let Ok((beacon, at)) = host.beacon() else {
        return TestResult::Fail("beacon");
    };
    // TIM: DTIM period 2, partial virtual bitmap with AID 1.
    if beacon.get(at..at + 6) != Some(&[5, 4, 0, 2, 0, 0x02][..]) || host.beacon_dirty() {
        return TestResult::Fail("TIM element");
    }
    let mut pspoll = vec![0xa4, 0x10, 1, 0xc0];
    pspoll.extend_from_slice(&OWN);
    pspoll.extend_from_slice(&STA);
    if !host.receive(Some(1), &pspoll, 1).is_empty() {
        return TestResult::Fail("PS-Poll is consumed");
    }
    let Some(out) = host.next_outbound().cloned() else {
        return TestResult::Fail("PS-Poll released nothing");
    };
    if out.mpdu[4..10] != STA || out.mpdu[1] & 0x20 != 0 || out.release.is_none() {
        return TestResult::Fail("single release without MoreData, period-ending");
    }
    // AP no-ack still ends the period (status.c EOSP).
    host.consume_outbound(11);
    host.report(11, false);
    if host.take_report(11).is_some() {
        return TestResult::Fail("release reports have no waiter");
    }
    // Group frames go after DTIM while any peer dozes.
    let mut group = vec![0xff; 6];
    group.extend_from_slice(&OWN);
    group.extend_from_slice(&[0x08, 0x00, 0x45]);
    if host.transmit_ethernet(&group, 2).is_err()
        || !host.next_outbound().is_some_and(|out| out.after_dtim)
    {
        return TestResult::Fail("SEND_AFTER_DTIM group frame");
    }
    if host.remove_peer(STA).is_none() || host.peer(STA).is_some() {
        return TestResult::Fail("DEL_STATION");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_host_dozing_peer_tim_and_pspoll_release
);

/// Sweep F3: `mgmt_tx` honors the PS decision (`ieee80211_tx_h_unicast_ps_buf`).
/// Awake: a deauthentication sends now. Dozing: a probe response
/// (non-bufferable MMPDU) still sends now, but a deauthentication
/// (bufferable) is held with TIM set and released by PS-Poll.
fn smoke_rtw89_ap_host_mgmt_tx_to_dozing_peer_buffers() -> TestResult {
    let Some(mut host) = started(false) else {
        return TestResult::Fail("fixture");
    };
    fn mgmt(subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![subtype << 4, 0, 0, 0];
        frame.extend_from_slice(&STA);
        frame.extend_from_slice(&OWN);
        frame.extend_from_slice(&OWN);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(body);
        frame
    }
    // Awake peer: deauthentication sends now.
    if !matches!(
        host.ps_decide(mgmt(0xc, &[7, 0]), 1, 0),
        Ok(Transmit::Send(_))
    ) {
        return TestResult::Fail("awake peer deauthentication was buffered");
    }
    // Null data with PM: the peer dozes (rx.c sta_ps_start).
    let mut null = uplink(OWN, 0, &[], None, true);
    null[0] = 0x48;
    null.truncate(24);
    let _ = host.receive(Some(1), &null, 0);
    // Non-bufferable MMPDU to a dozing peer still sends now.
    if !matches!(
        host.ps_decide(mgmt(0x5, &[0; 8]), 1, 1),
        Ok(Transmit::Send(_))
    ) {
        return TestResult::Fail("probe response to dozing peer was buffered");
    }
    // Bufferable MMPDU to a dozing peer is held with TIM set.
    if !matches!(
        host.ps_decide(mgmt(0xc, &[7, 0]), 1, 2),
        Ok(Transmit::Buffered { tim_changed: true })
    ) || !host.beacon_dirty()
    {
        return TestResult::Fail("deauthentication to dozing peer not buffered with TIM");
    }
    // PS-Poll releases the held deauthentication, period-ending.
    let mut pspoll = vec![0xa4, 0x10, 1, 0xc0];
    pspoll.extend_from_slice(&OWN);
    pspoll.extend_from_slice(&STA);
    if !host.receive(Some(1), &pspoll, 1).is_empty() {
        return TestResult::Fail("PS-Poll is consumed");
    }
    let Some(out) = host.next_outbound().cloned() else {
        return TestResult::Fail("PS-Poll released nothing");
    };
    if out.mpdu[4..10] != STA || out.mpdu[0] != 0xc0 || out.release.is_none() {
        return TestResult::Fail("PS-Poll did not release the buffered deauthentication");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/uapsd",
    smoke_rtw89_ap_host_mgmt_tx_to_dozing_peer_buffers
);
