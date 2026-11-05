//! TLV WoWLAN wire, program and wake-event cases (Linux `wow.c`,
//! `wmi-tlv.c`); unexecuted until the coordinated native run.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::WowlanPattern;

fn word(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}

/// `ath10k_wmi_tlv_op_gen_wow_{enable,add_wakeup_event,del_pattern}` and
/// `ath10k_wmi_tlv_gen_wow_host_wakeup_ind`: WMI_TLV_GRP_WOW identities,
/// struct tags/lengths and PCI's `link_can_suspend` pause value 0.
fn smoke_ath10k_wow_fixed_command_layouts() -> TestResult {
    let (Ok(e), Ok(a), Ok(d), Ok(h), Ok(p)) = (
        enable(),
        wakeup_event(0, 3, true),
        wakeup_event(0, 23, false),
        host_wakeup(),
        del_pattern(0, 21),
    ) else {
        return TestResult::Fail("fixed WoW command refused");
    };
    if e != [0x13004, (119 << 16) | 12, 1, 0, 0]
        .iter()
        .flat_map(|v: &u32| v.to_le_bytes())
        .collect::<Vec<_>>()
    {
        return TestResult::Fail("WOW_ENABLE layout");
    }
    if a.len() != 20
        || word(&a, 0) != 0x13003
        || word(&a, 4) != (137 << 16) | 12
        || word(&a, 8) != 0
        || word(&a, 12) != 1
        || word(&a, 16) != 1 << 3
        || word(&d, 12) != 0
        || word(&d, 16) != 1 << 23
    {
        return TestResult::Fail("WOW_ENABLE_DISABLE_WAKE_EVENT layout");
    }
    if h.len() != 12 || word(&h, 0) != 0x13005 || word(&h, 4) != (120 << 16) | 4 {
        return TestResult::Fail("WOW_HOSTWAKEUP_FROM_SLEEP layout");
    }
    if p.len() != 20
        || word(&p, 0) != 0x13002
        || word(&p, 4) != (136 << 16) | 12
        || word(&p, 12) != 21
        || word(&p, 16) != 0
    {
        return TestResult::Fail("WOW_DEL_WAKE_PATTERN layout");
    }
    if wakeup_event(0, EVENT_MAX, true).is_ok() {
        return TestResult::Fail("event beyond WOW_EVENT_MAX encoded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_fixed_command_layouts
);

/// `ath10k_wmi_tlv_op_gen_wow_add_pattern`: the 148+148 bitmap struct inside
/// an ARRAY_STRUCT, four empty arrays and the declared one-word ratelimit.
fn smoke_ath10k_wow_add_pattern_layout() -> TestResult {
    let pattern = Pattern {
        bytes: vec![1, 2, 3],
        mask: vec![0xff, 0, 0xff],
        offset: 30,
    };
    let Ok(c) = add_pattern(0, 4, &pattern) else {
        return TestResult::Fail("ADD_WAKE_PATTERN refused");
    };
    let bitmap = 2 * 148 + 16;
    let at = 4 + 16 + 4 + 4 + bitmap;
    if c.len() != at + 16 + 8
        || word(&c, 0) != 0x13001
        || word(&c, 4) != (179 << 16) | 12
        || word(&c, 12) != 4
        || word(&c, 16) != 0
        || word(&c, 20) != (18 << 16) | (4 + bitmap as u32)
        || word(&c, 24) != (180 << 16) | bitmap as u32
        || c[28..31] != [1, 2, 3]
        || c[31..28 + 148].iter().any(|b| *b != 0)
        || c[28 + 148..28 + 151] != [0xff, 0, 0xff]
        || word(&c, 28 + 296) != 30
        || word(&c, 28 + 300) != 3
        || word(&c, 28 + 304) != 3
        || word(&c, 28 + 308) != 4
        || word(&c, at) != 18 << 16
        || word(&c, at + 4) != 18 << 16
        || word(&c, at + 8) != 18 << 16
        || word(&c, at + 12) != 16 << 16
        || word(&c, at + 16) != (16 << 16) | 4
        || word(&c, at + 20) != 0
    {
        return TestResult::Fail("ADD_WAKE_PATTERN layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_add_pattern_layout
);

/// `ath10k_vif_wow_set_wakeups` (STA): disconnect -> DEAUTH/DISASSOC/BMISS/
/// CSA_IE, magic -> MAGIC_PKT; RAW decap advertises no patterns, GTK is
/// refused, ND is refused without NLO; native-WiFi converts 802.3 offsets
/// like `ath10k_wow_convert_8023_to_80211`.
fn smoke_ath10k_wow_program_and_conversion() -> TestResult {
    let raw = support(Decap::Raw, false);
    if !raw.disconnect
        || !raw.magic_packet
        || raw.max_patterns != 0
        || raw.gtk_rekey
        || raw.net_detect_max_match_sets != 0
        || raw.net_detect_random_mac
    {
        return TestResult::Fail("RAW advertisement");
    }
    let native = support(Decap::NativeWifi, true);
    if native.max_patterns != 22
        || native.max_pattern_len != 134
        || native.max_packet_offset != 114
        || native.net_detect_max_match_sets != 16
        || !native.net_detect_random_mac
    {
        return TestResult::Fail("native-WiFi WOW_MAX_REDUCE limits");
    }
    let config = WowlanConfig {
        disconnect: true,
        magic_packet: true,
        ..WowlanConfig::default()
    };
    match Program::new(&config, Decap::Raw, false) {
        Ok(p) if p.events == 0b101_0000_1101 && p.patterns.is_empty() => {}
        _ => return TestResult::Fail("disconnect+magic event mask"),
    }
    let with_pattern = |offset: u32, bytes: Vec<u8>| WowlanConfig {
        patterns: vec![WowlanPattern {
            mask: vec![0xff; bytes.len().div_ceil(8)],
            pattern: bytes,
            offset,
        }],
        ..WowlanConfig::default()
    };
    if Program::new(&with_pattern(0, vec![1]), Decap::Raw, false).is_ok()
        || Program::new(
            &WowlanConfig {
                gtk_rekey_failure: true,
                ..WowlanConfig::default()
            },
            Decap::NativeWifi,
            false,
        )
        .is_ok()
    {
        return TestResult::Fail("unadvertised trigger accepted");
    }
    // Destination MAC + ethertype + two body bytes from offset 0.
    let mut eth = vec![0xaa; 6];
    eth.extend_from_slice(&[0xbb; 6]);
    eth.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    let Ok(p) = Program::new(&with_pattern(0, eth), Decap::NativeWifi, false) else {
        return TestResult::Fail("native pattern refused");
    };
    let q = &p.patterns[0];
    let mut expected = vec![0xaa; 6];
    expected.extend_from_slice(&[0; 6]); // addr2
    expected.extend_from_slice(&[0xbb; 6]); // addr3
    expected.extend_from_slice(&[0; 8]); // seq + LLC/OUI
    expected.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    if p.events != 1 << 9 || q.offset != 4 || q.bytes != expected || q.mask.len() != 30 {
        return TestResult::Fail("802.3 header conversion");
    }
    // A body-only pattern only shifts by WOW_HDR_LEN - ETH_HLEN.
    let Ok(p) = Program::new(&with_pattern(20, vec![7, 8]), Decap::NativeWifi, false) else {
        return TestResult::Fail("body pattern refused");
    };
    if p.patterns[0].offset != 38 || p.patterns[0].bytes != [7, 8] {
        return TestResult::Fail("body offset conversion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_program_and_conversion
);

/// `ath10k_wmi_tlv_op_pull_wow_ev`: WOW_EVENT_INFO is mandatory; the
/// optional ARRAY_BYTE buffer is bounded by `data_len`.
fn smoke_ath10k_wow_wakeup_event_decode() -> TestResult {
    let mut body = Vec::new();
    for v in [(49u32 << 16) | 16, 0, 0, 10, 3] {
        body.extend_from_slice(&v.to_le_bytes());
    }
    body.extend_from_slice(&((17u32 << 16) | 4).to_le_bytes());
    body.extend_from_slice(&[9, 8, 7, 6]);
    match wake_event(&body) {
        Ok(r) if r.magic_packet() && !r.connection_lost() && r.packet == [9, 8, 7] => {}
        _ => return TestResult::Fail("magic wake decode"),
    }
    let mut lost = body[..20].to_vec();
    lost[12..16].copy_from_slice(&3u32.to_le_bytes());
    match wake_event(&lost) {
        Ok(r) if r.disconnect() && r.connection_lost() && r.packet.is_empty() => {}
        _ => return TestResult::Fail("deauth wake decode"),
    }
    if wake_event(&body[20..]).is_ok() || wake_event(&body[..12]).is_ok() {
        return TestResult::Fail("event without WOW_EVENT_INFO accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_wakeup_event_decode
);

/// `ath10k_wmi_tlv_op_gen_config_pno_start/stop`: NLO command id, TLV
/// 144 fixed header, dwell pair, plan periods, SSID records (rssi + hidden
/// broadcast type) and channel array; passive + random-MAC flag forms;
/// validation bounds; `Program` gates net-detect on the NLO service and
/// sets the NLO_DETECTED event bit.
fn smoke_ath10k_wow_nlo_config_layout() -> TestResult {
    use crate::ath11k::wmi::{NloConfig, NloNetwork};
    let nlo = |probe_ssids: Vec<Vec<u8>>,
               random_mac: Option<narf_wireless::ScanRandomMac>|
     -> NloConfig {
        NloConfig {
            probe_ssids,
            channels_mhz: vec![2412, 2437],
            probe_ies: Vec::new(),
            networks: vec![
                NloNetwork {
                    ssid: b"TestNet".to_vec(),
                    rssi_threshold_dbm: Some(-70),
                    hidden: false,
                },
                NloNetwork {
                    ssid: b"Hidden".to_vec(),
                    rssi_threshold_dbm: None,
                    hidden: true,
                },
            ],
            plans: vec![(30, Some(3)), (300, None)],
            delay_secs: 5,
            random_mac,
        }
    };
    let config = nlo(vec![b"TestNet".to_vec()], None);
    let Ok(c) = nlo_config_start(2, &config) else {
        return TestResult::Fail("NLO start refused");
    };
    // 4 WMI header + 4 TLV + 112 fixed + 4 array + 2*76 records + 4 chan
    // TLV + 2*4 channels.
    if c.len() != 128 + 2 * 76 + 8
        || word(&c, 0) != 0x18001
        || word(&c, 4) != (144 << 16) | 112
        || word(&c, 8) != (1 << 1) | (1 << 6)
        || word(&c, 12) != 2
        || word(&c, 16) != 3
        || word(&c, 20) != 40
        || word(&c, 24) != 110
        || word(&c, 44) != 30000
        || word(&c, 48) != 300000
        || word(&c, 52) != 2
        || word(&c, 56) != 2
        || word(&c, 60) != 5
        || word(&c, 120) != (18 << 16) | 152
        || word(&c, 124) != (17 << 16) | 72
        || word(&c, 128) != 1
        || word(&c, 132) != 7
        || c[136..143] != *b"TestNet"
        || word(&c, 184) != 1
        || word(&c, 188) != (-70i32) as u32
        || word(&c, 192) != 1
        || word(&c, 196) != 0
        || word(&c, 200) != (17 << 16) | 72
        || word(&c, 204) != 1
        || word(&c, 208) != 6
        || c[212..218] != *b"Hidden"
        || word(&c, 260) != 0
        || word(&c, 268) != 1
        || word(&c, 272) != 2
        || word(&c, 276) != (16 << 16) | 8
        || word(&c, 280) != 2412
        || word(&c, 284) != 2437
    {
        return TestResult::Fail("NLO start layout");
    }
    // Empty probe SSIDs -> passive scan; random MAC -> spoof + seq flags
    // and the address/mask unions (6 bytes + 2 pad each).
    let passive = nlo(Vec::new(), None);
    let Ok(p) = nlo_config_start(0, &passive) else {
        return TestResult::Fail("passive NLO start refused");
    };
    if word(&p, 8) != (1 << 1) | (1 << 6) | (1 << 8) {
        return TestResult::Fail("NLO passive flag");
    }
    let random = nlo(
        vec![b"TestNet".to_vec()],
        Some(narf_wireless::ScanRandomMac {
            addr: [1, 2, 3, 4, 5, 6],
            mask: [0xff; 6],
        }),
    );
    let Ok(r) = nlo_config_start(0, &random) else {
        return TestResult::Fail("random-MAC NLO start refused");
    };
    if word(&r, 8) != (1 << 1) | (1 << 6) | (1 << 10) | (1 << 11)
        || r[64..70] != [1, 2, 3, 4, 5, 6]
        || r[72..78] != [0xff; 6]
    {
        return TestResult::Fail("NLO random-MAC flag/address");
    }
    // Stop: fixed header only, STOP bit + vdev.
    let Ok(s) = nlo_config_stop(2) else {
        return TestResult::Fail("NLO stop refused");
    };
    if s.len() != 120
        || word(&s, 0) != 0x18001
        || word(&s, 4) != (144 << 16) | 112
        || word(&s, 8) != 1
        || word(&s, 12) != 2
        || word(&s, 16) != 0
        || word(&s, 116) != 0
    {
        return TestResult::Fail("NLO stop layout");
    }
    // Validation bounds: empty/overfull networks, channels, plans.
    let mut bad = nlo(vec![b"TestNet".to_vec()], None);
    bad.networks.clear();
    let mut many = nlo(vec![b"TestNet".to_vec()], None);
    many.networks = (0..17)
        .map(|_| NloNetwork {
            ssid: b"x".to_vec(),
            rssi_threshold_dbm: None,
            hidden: false,
        })
        .collect();
    let mut chans = nlo(vec![b"TestNet".to_vec()], None);
    chans.channels_mhz = (0..61).map(|i| 2412 + i).collect();
    let mut noplan = nlo(vec![b"TestNet".to_vec()], None);
    noplan.plans.clear();
    let mut final_iter = nlo(vec![b"TestNet".to_vec()], None);
    final_iter.plans = vec![(30, Some(3)), (300, Some(2))];
    if nlo_config_start(0, &bad).is_ok()
        || nlo_config_start(0, &many).is_ok()
        || nlo_config_start(0, &chans).is_ok()
        || nlo_config_start(0, &noplan).is_ok()
        || nlo_config_start(0, &final_iter).is_ok()
    {
        return TestResult::Fail("invalid NLO configuration accepted");
    }
    // Program gates net-detect on the NLO service and sets bit 7.
    let with_nd = WowlanConfig {
        net_detect: Some(config.clone()),
        ..WowlanConfig::default()
    };
    if Program::new(&with_nd, Decap::Raw, false).is_ok() {
        return TestResult::Fail("net-detect accepted without NLO service");
    }
    match Program::new(&with_nd, Decap::Raw, true) {
        Ok(p) if p.events == 1 << 7 && p.nlo.is_some() => {}
        _ => return TestResult::Fail("net-detect program"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_nlo_config_layout
);
