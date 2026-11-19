//! EMLSR policy vectors authored from Linux mld/mlo.c semantics; they
//! exercise decisions only and claim no firmware or RF behaviour.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn link(spec: u8, band: Band, primary: u32, width: u32, grade: u16) -> Candidate {
    Candidate {
        spec_link: spec,
        band,
        primary_mhz: primary,
        center_mhz: primary,
        width_mhz: width,
        signal_dbm: -50,
        csa_active: false,
        grade,
        chan_load: 128,
        active: true,
        load_not_by_us: 60,
    }
}

fn smoke_iwl_emlsr_pair_state_and_link_selection() -> TestResult {
    let five = link(1, Band::Five, 5180, 20, 100);
    let six = link(2, Band::Six, 6115, 20, 90);
    let two = link(0, Band::Two, 2437, 20, 80);
    if pair_state(&five, &six, false, false) != 0 {
        return TestResult::Fail("5/6GHz pair refused");
    }
    if pair_state(&two, &six, true, false) & exit::BT_COEX == 0 {
        return TestResult::Fail("2.4GHz link with active BT allowed");
    }
    let mut weak = six;
    weak.signal_dbm = -70;
    if pair_state(&five, &weak, false, false) & exit::LOW_RSSI == 0 {
        return TestResult::Fail("low-RSSI secondary allowed");
    }
    // Same 5GHz band: 36 (5180) vs 149 (5745) is separated; 36 vs 52 not.
    let high = link(3, Band::Five, 5745, 20, 90);
    let near = link(4, Band::Five, 5260, 20, 90);
    if pair_state(&five, &high, false, false) & exit::EQUAL_BAND != 0
        || pair_state(&five, &near, false, false) & exit::EQUAL_BAND == 0
    {
        return TestResult::Fail("5GHz equal-band separation rule differs from Linux");
    }
    let mut idle = five;
    idle.load_not_by_us = 5;
    if pair_state(&idle, &six, false, false) & exit::CHAN_LOAD == 0 {
        return TestResult::Fail("unloaded primary entered EMLSR");
    }
    let mut wide = five;
    wide.width_mhz = 80;
    wide.center_mhz = 5210;
    wide.load_not_by_us = 30;
    if channel_load_allows(&wide, &six, false) || !channel_load_allows(&wide, &six, true) {
        return TestResult::Fail("bandwidth-ratio channel load rule differs from Linux");
    }
    if rssi_threshold(80, false) != Some(-61) || rssi_threshold(60, false).is_some() {
        return TestResult::Fail("EMLSR RSSI thresholds differ from constants.h");
    }
    let mut state = Emlsr::default();
    let chosen = state.select(&[five, six], true, false, false);
    if chosen
        != Some(Selection {
            active: 0b110,
            primary: 1,
        })
    {
        return TestResult::Fail("EMLSR pair not preferred over single best link");
    }
    let single = state.select(&[five, six], false, false, false);
    if single.map(|s| s.active) != Some(0b10) {
        return TestResult::Fail("EMLSR pair selected without capability");
    }
    state.blocked = blocked::TPT;
    if state
        .select(&[five, six], true, false, false)
        .map(|s| s.active)
        != Some(0b10)
    {
        return TestResult::Fail("blocked EMLSR selected a pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_emlsr_pair_state_and_link_selection
);

fn smoke_iwl_emlsr_block_exit_prevention_and_notifications() -> TestResult {
    let mut state = Emlsr {
        selected: 0b110,
        selected_primary: 2,
        ..Emlsr::default()
    };
    state.links_activated(0b110, 0);
    if !state.emlsr_active() || state.primary_link() != 2 {
        return TestResult::Fail("selected EMLSR primary not retained");
    }
    // Block keeps the requested link and installs no prevention.
    if state.block(blocked::ROC, 1, true, 1_000) != Some(0b10)
        || state.blocked != blocked::ROC
        || state.block(blocked::ROC, 1, true, 1_001).is_some()
    {
        return TestResult::Fail("EMLSR block did not exit once to the kept link");
    }
    if !state.unblock(blocked::ROC, true) || state.unblock(blocked::ROC, true) {
        return TestResult::Fail("EMLSR unblock did not report a single full unblock");
    }
    // FW recommend-leave exits to the primary and prevents for 30s.
    let leave = [0u8; 8];
    if state.mode_notification(&leave, true, 2_000) != Ok(Some(0b100))
        || state.blocked & blocked::PREVENTION == 0
    {
        return TestResult::Fail("FW recommend-leave did not exit with prevention");
    }
    if state.mode_notification(&leave[..4], true, 2_000).is_ok() {
        return TestResult::Fail("ESR mode notification v1 size accepted as v2");
    }
    if state.prevention_tick(true, 31_000) || !state.prevention_tick(true, 32_000) {
        return TestResult::Fail("EMLSR prevention timing differs from 30s");
    }
    // Second FW-request exit inside 400s gets the 300s prevention.
    state.links_activated(0b110, 0);
    let _ = state.mode_notification(&leave, true, 40_000);
    if state.prevention_tick(true, 339_000) || !state.prevention_tick(true, 340_000) {
        return TestResult::Fail("repeated FW-request exit lacks short prevention");
    }
    // Transition failure: unknown fw link or failed deactivation disconnects.
    let mut fail = [0u8; 12];
    fail[4] = 1;
    state.links_activated(0b110, 0);
    let spec = |fw: u32| match fw {
        0 => Some(1),
        1 => Some(2),
        _ => None,
    };
    if state.transition_failure(&fail, spec, 400_000) != Ok(TransitionFailure::Keep(0b10)) {
        return TestResult::Fail("EMLSR entry failure did not keep firmware-named link");
    }
    fail[0] = 3;
    if state.transition_failure(&fail, spec, 400_001) != Ok(TransitionFailure::Disconnect) {
        return TestResult::Fail("EMLSR failure on unowned fw link did not disconnect");
    }
    fail[0] = 0;
    fail[4] = 0;
    if state.transition_failure(&fail, spec, 400_002) != Ok(TransitionFailure::Disconnect) {
        return TestResult::Fail("EMLSR deactivation failure did not disconnect");
    }
    if state.transition_failure(&fail[..8], spec, 400_003).is_ok() {
        return TestResult::Fail("short EMLSR transition failure accepted");
    }
    let ap = Some(EmlCapabilities(1 | (15 << 11)));
    if client_mld_fields(ap, Some(9)) != (10, 9)
        || client_mld_fields(None, None) != (0, MED_SYNC_DELAY_DEFAULT)
    {
        return TestResult::Fail("MAC client EMLSR timeout clamp differs from mld/iface.c");
    }
    if !capable(true, true, true, ap, false) || capable(true, true, true, ap, true) {
        return TestResult::Fail("EMLSR capability ignored CDB dual-radio exclusion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_emlsr_block_exit_prevention_and_notifications
);

fn smoke_iwl_mld_fw_link_station_ids_bounded_by_tlvs() -> TestResult {
    use super::super::sc_mlo::FwIds;
    if FwIds::new(None, Some(16)).is_ok() || FwIds::new(Some(5), Some(16)).is_ok() {
        return TestResult::Fail("FW link ids admitted without valid NUM_LINKS TLV");
    }
    let Ok(mut ids) = FwIds::new(Some(2), Some(2)) else {
        return TestResult::Fail("valid FW link/station counts refused");
    };
    if ids.claim(0, 0).is_err() || ids.claim(0, 1).is_ok() {
        return TestResult::Fail("association FW link0/STA0 claim not exclusive");
    }
    if ids.allocate() != Ok((1, 1)) || ids.allocate().is_ok() {
        return TestResult::Fail("second link FW ids exceeded firmware counts");
    }
    ids.release(1, 1);
    if ids.allocate() != Ok((1, 1)) {
        return TestResult::Fail("released second-link FW ids not reusable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_fw_link_station_ids_bounded_by_tlvs
);

fn missed(
    link: u32,
    since_rx: u32,
    missed: u32,
    other: u32,
    other_missed: u32,
) -> alloc::vec::Vec<u8> {
    [link, since_rx, missed, other, other_missed]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

/// link.c iwl_mld_handle_missed_beacon_notif thresholds (constants.h).
fn smoke_iwl_mld_missed_beacons_exit_emlsr_and_connection_loss() -> TestResult {
    // FW link 0 = spec link 1 (primary), FW link 1 = spec link 2.
    let spec = |fw: u32| match fw {
        0 => Some(1),
        1 => Some(2),
        _ => None,
    };
    let mut emlsr = Emlsr {
        selected: 0b110,
        selected_primary: 1,
        ..Emlsr::default()
    };
    emlsr.links_activated(0b110, 0);
    // Long loss without RX is a connection loss even in EMLSR.
    if emlsr.missed_beacons(&missed(0, 6, 19, 1, 0), spec, 0) != Ok(MissedBeacons::Disconnect) {
        return TestResult::Fail("long missed-beacon run did not lose the connection");
    }
    // Long loss while data is still received stays connected.
    if emlsr.missed_beacons(&missed(0, 5, 19, 1, 0), spec, 0) != Ok(MissedBeacons::Ignored) {
        return TestResult::Fail("long missed-beacon run with RX disconnected");
    }
    // Below every threshold, or before the other link is activated.
    if emlsr.missed_beacons(&missed(1, 0, 14, 0, 4), spec, 0) != Ok(MissedBeacons::Ignored)
        || emlsr.missed_beacons(&missed(1, 0, 15, u32::MAX, 0), spec, 0)
            != Ok(MissedBeacons::Ignored)
    {
        return TestResult::Fail("EMLSR left below the missed-beacon thresholds");
    }
    // Only the further link is sick: keep the other (association) link.
    if emlsr.missed_beacons(&missed(1, 0, 15, 0, 0), spec, 0) != Ok(MissedBeacons::Keep(0b10)) {
        return TestResult::Fail("sick link was kept");
    }
    // Both links lose beacons: keep the primary.
    let mut both = Emlsr {
        selected: 0b110,
        selected_primary: 2,
        ..Emlsr::default()
    };
    both.links_activated(0b110, 0);
    if both.missed_beacons(&missed(0, 0, 5, 1, 5), spec, 0) != Ok(MissedBeacons::Keep(0b100)) {
        return TestResult::Fail("symmetric loss did not keep the primary link");
    }
    if both.missed_beacons(&[0; 16], spec, 0).is_ok() {
        return TestResult::Fail("short v5 notification accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_missed_beacons_exit_emlsr_and_connection_loss
);

fn smoke_iwl_mld_link_grade_tables_chan_load_and_puncturing() -> TestResult {
    let idle = 0;
    // link.c tables: 5GHz uses the high-band RSSI column, 2.4GHz the low.
    if link_grade(Band::Five, 20, -60, chan_load(Band::Five, None, 0), 0) != Some(219) {
        return TestResult::Fail("5GHz 20MHz grade or default load wrong");
    }
    if link_grade(Band::Two, 20, -60, chan_load(Band::Two, None, 0), 0) != Some(181) {
        return TestResult::Fail("2.4GHz 20MHz grade or default load wrong");
    }
    if link_grade(Band::Five, 20, -40, idle, 0) != Some(345) {
        return TestResult::Fail("RSSI above the table did not keep the top grade");
    }
    if link_grade(Band::Five, 20, 0, idle, 0) != Some(9) {
        return TestResult::Fail("missing RSSI did not take the lowest line");
    }
    if link_grade(Band::Five, 80, -61, idle, 0) != Some(824)
        || link_grade(Band::Five, 80, -61, idle, 0b1) != Some(618)
        || link_grade(Band::Five, 40, -61, idle, 0b1) != link_grade(Band::Five, 40, -61, idle, 0)
    {
        return TestResult::Fail("80MHz grade or puncturing penalty wrong");
    }
    if link_grade(Band::Six, 20, -60, idle, 0).is_some()
        || link_grade(Band::Five, 60, -60, idle, 0).is_some()
    {
        return TestResult::Fail("ungraded band or width produced a grade");
    }
    if chan_load(Band::Five, Some(100), 10) != 75 || chan_load(Band::Five, Some(10), 10) != 10 {
        return TestResult::Fail("channel load by others wrong");
    }
    if bss_load_channel_util(&[0, 0, 11, 5, 1, 0, 77, 0, 0]) != Some(77)
        || bss_load_channel_util(&[11, 4, 1, 0, 77, 0]).is_some()
    {
        return TestResult::Fail("BSS Load element parse wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_link_grade_tables_chan_load_and_puncturing
);

fn smoke_iwl_mld_stats_tpt_and_internal_mlo_scan_selection() -> TestResult {
    if stats_command(true, false) != [2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0]
        || stats_command(false, true) != [0, 0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0]
        || stats_command(false, false) != [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("SYSTEM_STATISTICS_CMD bodies wrong");
    }
    for (size, stride) in [(492usize, 104usize), (444, 88)] {
        let mut notif = alloc::vec![0u8; size];
        let at = 4 + 112 + stride;
        notif[at + 4] = 7;
        notif[at + 8] = 40;
        if per_phy_loads(&notif).map(|l| l[1]) != Ok((7, 40)) {
            return TestResult::Fail("per-PHY channel load offsets wrong");
        }
    }
    if per_phy_loads(&[0; 400]).is_ok() {
        return TestResult::Fail("odd statistics size accepted");
    }
    let mut measure = Measurements::default();
    measure.update_phys(&[(0, 0), (5, 40), (0, 0)], &[1]);
    measure.update_phys(&[(0, 0), (6, 40), (0, 0)], &[1]);
    measure.update_phys(&[(0, 0), (9, 101), (0, 0)], &[1]);
    measure.update_phys(&[(0, 0), (8, 0xffff_ffff), (0, 0)], &[1]);
    if measure.avg_not_by_us[1] != 30 || measure.load_by_us[1] != 8 {
        return TestResult::Fail("PHY load averaging wrong");
    }
    for n in 1..=401u32 {
        let crossed = measure.count_mpdus(0, 1, 1, false, true, 100);
        if crossed != (n == 400) {
            return TestResult::Fail("TPT threshold crossing wrong");
        }
    }
    if measure.count_mpdus(0, 1, 1, false, true, 5_200) {
        return TestResult::Fail("expired TPT window not cleared");
    }
    let mut emlsr = Emlsr::default();
    emlsr.links_activated(0b11, 0);
    if emlsr.check_tpt(&mut Measurements::default(), Some(1), true, 10_000) != TptCheck::Block(0b1)
    {
        return TestResult::Fail("idle EMLSR not blocked for TPT");
    }
    let channels = [
        super::super::native_band::Channel {
            band: Band::Five,
            number: 36,
        },
        super::super::native_band::Channel {
            band: Band::Two,
            number: 6,
        },
    ];
    let body = match Selector::scan_body(17, &channels, 2) {
        Ok(body) => body,
        Err(_) => return TestResult::Fail("internal MLO scan body refused"),
    };
    if body[..4] != MLO_SCAN_UID.to_le_bytes()
        || u16::from_le_bytes([body[8], body[9]]) & (1 << 9) == 0
        || body[11] != 2
        || body[36..40] != 4u32.to_le_bytes()
    {
        return TestResult::Fail("internal MLO scan body fields wrong");
    }
    let mut selector = Selector {
        scan_requested: true,
        last_activation_ms: Some(1_000),
        ..Selector::default()
    };
    if selector.may_start_scan(5_999) || !selector.may_start_scan(6_000) {
        return TestResult::Fail("MLO scan blockout wrong");
    }
    selector.scan_running = true;
    let seen = Seen {
        spec_link: 1,
        signal_dbm: -60,
        util: None,
    };
    selector.observe(seen);
    if !selector.seen.is_empty()
        || selector.scan_started(&[1, 0, 0, 0, 0, 0, 0, 0], 7_000)
        || !selector.scan_started(&[0; 8], 7_000)
    {
        return TestResult::Fail("scan start gating wrong");
    }
    selector.observe(seen);
    if selector.seen != [seen] || !selector.scan_completed(&[0; 16]) || selector.scan_running {
        return TestResult::Fail("scan completion or observation wrong");
    }
    if !selector.fresh(12_000) || selector.fresh(12_001) {
        return TestResult::Fail("link-selection freshness wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_stats_tpt_and_internal_mlo_scan_selection
);

/// A beacon's Basic MLE (link id, BSS Parameters Change Count, AP MLD ID)
/// and one RNR TBTT entry (ieee80211_tbtt_info_ge_11) naming `rnr_link`.
fn mld_beacon(link: u8, count: u8, mld_id: u8, rnr: (u8, u8, u8)) -> Vec<u8> {
    let mut ies = alloc::vec![255, 13, 107, 0x30, 0x02, 10, 2, 0, 0, 0, 0, 0x20];
    ies.extend_from_slice(&[link, count, mld_id]);
    let (rnr_mld, rnr_link, rnr_count) = rnr;
    let params = u16::from(rnr_link) | u16::from(rnr_count) << 4;
    ies.extend_from_slice(&[201, 20, 0x00, 16, 115, 36]);
    ies.extend_from_slice(&[0, 2, 0, 0, 0, 0, 0x21, 0, 0, 0, 0, 0, 0, rnr_mld]);
    ies.extend_from_slice(&params.to_le_bytes());
    ies
}

/// link.c iwl_mld_handle_missed_beacon_notif beacon-loss CQM, single-link
/// rescan and the BSS-parameters-changed EMLSR exit, with mlme.c
/// ieee80211_mgd_update_bss_param_ch_cnt reporter tracking.
fn smoke_iwl_mld_missed_beacons_cqm_rescan_and_bss_param_changed() -> TestResult {
    let spec = |fw: u32| match fw {
        0 => Some(1),
        1 => Some(2),
        _ => None,
    };
    // Single active link: more than 8 missed since RX notifies CQM and
    // requests the internal MLO scan; exactly 8 does neither.
    let mut single = Emlsr::default();
    single.links_activated(0b10, 0);
    if single.missed_beacons(&missed(0, 8, 8, 0, 0), spec, 0) != Ok(MissedBeacons::Ignored)
        || single.cqm_beacon_loss
    {
        return TestResult::Fail("beacon loss raised at the threshold");
    }
    if single.missed_beacons(&missed(0, 9, 9, u32::MAX, 0), spec, 0) != Ok(MissedBeacons::Rescan)
        || !single.cqm_beacon_loss
    {
        return TestResult::Fail("single-link beacon loss did not rescan/notify");
    }
    // Reporter tracking: link 2's own beacon records itself; link 1's
    // beacon reporting a changed count for link 2 makes link 1 its reporter;
    // an unchanged count, another AP MLD or count 255 does not.
    let mut emlsr = Emlsr {
        selected: 0b110,
        selected_primary: 1,
        ..Emlsr::default()
    };
    emlsr.links_activated(0b110, 0);
    emlsr.update_bss_param(2, &mld_beacon(2, 4, 0, (0, 1, 7)), 0b110);
    if emlsr.bss_param_reporter(2) != 2 || emlsr.bss_param[1] != Some((7, 2)) {
        return TestResult::Fail("own/RNR BSS parameter counts not recorded");
    }
    emlsr.update_bss_param(1, &mld_beacon(1, 7, 0, (0, 2, 4)), 0b110);
    if emlsr.bss_param_reporter(2) != 2 {
        return TestResult::Fail("unchanged count changed the reporter");
    }
    emlsr.update_bss_param(1, &mld_beacon(1, 7, 0, (3, 2, 5)), 0b110);
    emlsr.update_bss_param(1, &mld_beacon(1, 7, 0, (0, 2, 255)), 0b110);
    if emlsr.bss_param_reporter(2) != 2 {
        return TestResult::Fail("another AP MLD or count 255 changed the reporter");
    }
    emlsr.update_bss_param(1, &mld_beacon(1, 7, 0, (0, 2, 5)), 0b110);
    if emlsr.bss_param_reporter(2) != 1 || emlsr.bss_param[2] != Some((5, 1)) {
        return TestResult::Fail("changed RNR count did not move the reporter");
    }
    // Link 2 (FW 1) misses 11 while its change was reported elsewhere:
    // leave EMLSR keeping link 1. Link 1 (own reporter) needs 15.
    if emlsr.missed_beacons(&missed(0, 0, 11, 1, 0), spec, 0) != Ok(MissedBeacons::Ignored) {
        return TestResult::Fail("own-reported link left EMLSR below 15");
    }
    if emlsr.missed_beacons(&missed(1, 0, 11, 0, 0), spec, 0) != Ok(MissedBeacons::Keep(0b10)) {
        return TestResult::Fail("BSS-parameters-changed threshold not applied");
    }
    // In EMLSR the CQM event fires without a rescan request.
    let mut both = emlsr;
    both.cqm_beacon_loss = false;
    if both.missed_beacons(&missed(0, 9, 9, 1, 0), spec, 0) == Ok(MissedBeacons::Rescan)
        || !both.cqm_beacon_loss
    {
        return TestResult::Fail("EMLSR beacon loss requested a single-link rescan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_missed_beacons_cqm_rescan_and_bss_param_changed
);

/// One advertised TTLM element (ext 109): both directions, a presence
/// indicator for all TIDs and two-octet maps, optionally a switch time.
fn ttlm(switch_time: Option<u16>, maps: [u16; 8]) -> Vec<u8> {
    let mut body = alloc::vec![109, 2 | if switch_time.is_some() { 0x08 } else { 0 }, 0xff];
    if let Some(at) = switch_time {
        body.extend_from_slice(&at.to_le_bytes());
    }
    for map in maps {
        body.extend_from_slice(&map.to_le_bytes());
    }
    let mut ies = alloc::vec![255, body.len() as u8];
    ies.extend_from_slice(&body);
    ies
}

/// mlme.c ieee80211_parse_adv_t2l, ieee80211_assoc_success's response
/// mapping, ieee80211_process_adv_ttlm and ieee80211_tid_to_link_map_work.
fn smoke_iwl_mld_advertised_ttlm_dormant_links_and_switch() -> TestResult {
    // Valid links 1 and 2. A response mapping link 1 only: link 2 dormant.
    let response = ttlm(None, [0b10; 8]);
    if response_dormant(&response, 0b110)
        != Ok((
            0b100,
            Some(AdvTtlm {
                switch_time: 0,
                duration: 0,
                map: 0b10,
            }),
        ))
    {
        return TestResult::Fail("response TTLM dormant links wrong");
    }
    // A switch time, an unmapped valid set, uneven TIDs, a one-direction
    // mapping or two elements are refused in a response.
    let mut uneven = [0b10; 8];
    uneven[7] = 0b110;
    let mut one_way = ttlm(None, [0b10; 8]);
    one_way[3] = 1;
    let mut two = response.clone();
    two.extend_from_slice(&response);
    if response_dormant(&ttlm(Some(5), [0b10; 8]), 0b110).is_ok()
        || response_dormant(&ttlm(None, [0b1000; 8]), 0b110).is_ok()
        || response_dormant(&ttlm(None, uneven), 0b110).is_ok()
        || response_dormant(&one_way, 0b110).is_ok()
        || response_dormant(&two, 0b110).is_ok()
        || response_dormant(&[], 0b110) != Ok((0, None))
    {
        return TestResult::Fail("invalid response TTLM accepted");
    }
    // A beacon announcing a switch at TSF TU 0x0100 seen at TU 0x0080:
    // 128 TU = 131072us, minus the 100ms buffer -> due after 31ms.
    let mut state = TtlmState::default();
    state.associated(0, None);
    let tsf = 0x80u64 << 10;
    if state.process(&ttlm(Some(0x100), [0b100; 8]), tsf, 1000) != TtlmAction::None
        || state.switch_at_ms != Some(1031)
        || state.due(1030, 0b110).is_some()
    {
        return TestResult::Fail("TTLM switch time not scheduled");
    }
    if state.due(1031, 0b110) != Some((0b100, 0b010)) || !state.active || state.dormant != 0b010 {
        return TestResult::Fail("TTLM switch did not make the unmapped link dormant");
    }
    // A switch time far in the future (underflow) is ignored.
    let mut late = TtlmState::default();
    if late.process(&ttlm(Some(0x10), [0b100; 8]), 0x20 << 10, 0) != TtlmAction::None
        || late.switch_at_ms.is_some()
    {
        return TestResult::Fail("previous switch announcement scheduled");
    }
    // An active mapping withdrawn from the beacon returns to the default.
    if state.process(&[], tsf, 2000) != TtlmAction::Default || state.dormant != 0 || state.active {
        return TestResult::Fail("withdrawn TTLM kept dormant links");
    }
    // A planned switch cancelled by its element's removal never fires.
    state.process(&ttlm(Some(0x100), [0b100; 8]), tsf, 3000);
    if state.process(&[], tsf, 3001) != TtlmAction::None || state.due(9999, 0b110).is_some() {
        return TestResult::Fail("cancelled TTLM switch still fired");
    }
    // An invalid advertised mapping disconnects.
    if state.process(&ttlm(None, uneven), tsf, 4000) != TtlmAction::Disconnect {
        return TestResult::Fail("invalid advertised TTLM kept the connection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_advertised_ttlm_dormant_links_and_switch
);
