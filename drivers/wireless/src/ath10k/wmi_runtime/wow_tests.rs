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
/// CSA_IE, magic -> MAGIC_PKT; RAW decap advertises no patterns, GTK/ND are
/// refused; native-WiFi converts 802.3 offsets like
/// `ath10k_wow_convert_8023_to_80211`.
fn smoke_ath10k_wow_program_and_conversion() -> TestResult {
    let raw = support(Decap::Raw);
    if !raw.disconnect || !raw.magic_packet || raw.max_patterns != 0 || raw.gtk_rekey {
        return TestResult::Fail("RAW advertisement");
    }
    let native = support(Decap::NativeWifi);
    if native.max_patterns != 22 || native.max_pattern_len != 134 || native.max_packet_offset != 114
    {
        return TestResult::Fail("native-WiFi WOW_MAX_REDUCE limits");
    }
    let config = WowlanConfig {
        disconnect: true,
        magic_packet: true,
        ..WowlanConfig::default()
    };
    match Program::new(&config, Decap::Raw) {
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
    if Program::new(&with_pattern(0, vec![1]), Decap::Raw).is_ok()
        || Program::new(
            &WowlanConfig {
                gtk_rekey_failure: true,
                ..WowlanConfig::default()
            },
            Decap::NativeWifi,
        )
        .is_ok()
    {
        return TestResult::Fail("unadvertised trigger accepted");
    }
    // Destination MAC + ethertype + two body bytes from offset 0.
    let mut eth = vec![0xaa; 6];
    eth.extend_from_slice(&[0xbb; 6]);
    eth.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    let Ok(p) = Program::new(&with_pattern(0, eth), Decap::NativeWifi) else {
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
    let Ok(p) = Program::new(&with_pattern(20, vec![7, 8]), Decap::NativeWifi) else {
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
