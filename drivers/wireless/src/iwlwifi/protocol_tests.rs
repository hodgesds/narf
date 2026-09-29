use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_tx_power_command_versions_and_units() -> TestResult {
    for (version, length) in [(10, 108), (11, 116)] {
        let command = station_api::tx_power(version, 17).unwrap();
        if command.len() != length
            || command[..8] != [0; 8]
            || command[8..10] != [136, 0]
            || command[10..].iter().any(|&b| b != 0)
        {
            return TestResult::Fail("TX power wire layout/units");
        }
        let negative = station_api::tx_power(version, -3).unwrap();
        if negative[8..10] != (-24i16).to_le_bytes() {
            return TestResult::Fail("negative TX power signed encoding");
        }
    }
    if station_api::tx_power(9, 17).is_ok() {
        return TestResult::Fail("unknown TX power layout accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_tx_power_command_versions_and_units
);

fn tlv(bytes: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize((bytes.len() + 3) & !3, 0);
}

fn image() -> Vec<u8> {
    let mut bytes = alloc::vec![0;88];
    bytes[4..8].copy_from_slice(&IWL_TLV_UCODE_MAGIC.to_le_bytes());
    tlv(&mut bytes, 52, &[1, 2, 3, 4]);
    tlv(&mut bytes, 48, &[1, 0, 99, 8, 0xd, 1, 18, 0]);
    tlv(&mut bytes, 30, &[1, 0, 0, 0, 1, 0, 0, 0]);
    tlv(&mut bytes, 23, &[0x11, 0x22, 0x33, 0x44]);
    tlv(&mut bytes, 22, &[0, 0, 0, 0, 0x12, 0, 0, 0, 0x34, 0, 0, 0]);
    tlv(&mut bytes, 24, &[0, 0x10, 0, 0, 1, 2, 3, 4]);
    tlv(&mut bytes, 24, &CPU1_CPU2_SEPARATOR.to_le_bytes());
    tlv(&mut bytes, 19, &[0, 0x20, 0, 0, 5, 6, 7, 8]);
    tlv(&mut bytes, 19, &PAGING_SEPARATOR.to_le_bytes());
    tlv(&mut bytes, 19, &[0, 0x30, 0, 0, 9, 10, 11, 12]);
    bytes
}

fn smoke_modern_firmware_metadata_and_sections() -> TestResult {
    let bytes = image();
    let fw = parse_ucode(&bytes).unwrap();
    if fw.api.iml != Some([1, 2, 3, 4].as_slice())
        || fw.api.versions(1, 0xd) != Some((18, 0))
        || !fw.api.has_capability(32)
        || fw.api.has_capability(256)
        || fw.api.phy_config != 0x44332211
        || fw.api.calibration != [0x12, 0x34]
    {
        return TestResult::Fail("firmware metadata was lost or misdecoded");
    }
    let map = boot_context::section_map(&fw).unwrap();
    if map != [(0, 636), (2, 124), (4, 1148)] {
        return TestResult::Fail("LMAC/UMAC/paging DMA map order");
    }
    let mut bad = fw.clone();
    bad.rt_sections.swap(0, 1);
    if boot_context::section_map(&bad).is_ok() {
        return TestResult::Fail("accepted leading CPU separator");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_modern_firmware_metadata_and_sections
);

fn smoke_modern_tlv_truncation_rejected() -> TestResult {
    let mut bytes = image();
    bytes.push(1);
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("short trailing TLV accepted");
    }
    let mut bytes = image();
    tlv(&mut bytes, 52, &[1]);
    bytes.pop();
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("missing TLV padding accepted");
    }
    let mut bytes = image();
    tlv(&mut bytes, 48, &[1, 2, 3]);
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("partial command version accepted");
    }
    let mut bytes = image();
    tlv(&mut bytes, 30, &[0; 7]);
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("partial capability accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_modern_tlv_truncation_rejected
);

fn smoke_boot_context_wire_units() -> TestResult {
    let q = boot_context::BootQueues {
        free: 0x123456789000,
        used: 0x23456789a000,
        status: 0x3456789ab000,
        command: 0x456789abc000,
        rx_depth: 512,
        command_depth: 128,
    };
    let out = boot_context::context(q, 0x56789abcd000, 0x6789abcde000).unwrap();
    if out.len() != 104
        || out[52..60] != q.command.to_le_bytes()
        || out[60..68] != q.used.to_le_bytes()
        || out[68..72] != [4, 0, 9, 0]
        || out[96..100] != 1660u32.to_le_bytes()
        || out[24..32] != 0x56789abcd800u64.to_le_bytes()
        || out[32..40] != 0x56789abcdc00u64.to_le_bytes()
    {
        return TestResult::Fail("context address/size units mismatch");
    }
    let scratch = boot_context::scratch(0x1234, q.free);
    if scratch.len() != 1724
        || scratch[4..6] != 431u16.to_le_bytes()
        || scratch[8..12] != 0x000f0000u32.to_le_bytes()
        || scratch[48..56] != q.free.to_le_bytes()
    {
        return TestResult::Fail("scratch header/RX free pointer mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_boot_context_wire_units
);

fn smoke_pnvm_selection_and_lengths() -> TestResult {
    let mut bytes = Vec::new();
    tlv(&mut bytes, 64, &[9; 12]);
    tlv(&mut bytes, 19, &[0, 0, 0, 0, 99]);
    tlv(&mut bytes, 64, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    tlv(&mut bytes, 58, &[0x23, 1, 0x56, 4]);
    tlv(&mut bytes, 19, &[0, 0, 0, 0, 42]);
    tlv(&mut bytes, 19, &0xddddeeeeu32.to_le_bytes());
    tlv(&mut bytes, 7, &[0, 0, 0, 0, 2, 0, 0, 0, 43, 44]);
    let chunks = match pnvm::select(&bytes, [1, 2, 3], 0x123, 0x456) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("valid PNVM selection failed"),
    };
    if chunks != [vec![42].as_slice(), vec![43, 44].as_slice()] {
        return TestResult::Fail("PNVM mixed SKUs or consumed deprecated marker");
    }
    if pnvm::select(&bytes, [1, 2, 4], 0x123, 0x456).is_ok()
        || pnvm::select(&bytes, [1, 2, 3], 0x123, 0x457).is_ok()
    {
        return TestResult::Fail("PNVM accepted mismatched SKU/hardware");
    }
    bytes.pop();
    if pnvm::select(&bytes, [1, 2, 3], 0x123, 0x456).is_ok() {
        return TestResult::Fail("truncated PNVM accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_pnvm_selection_and_lengths
);

fn smoke_scan_nvm_and_band_numbering() -> TestResult {
    let mut nvm = vec![0; 468];
    nvm[12] = 3;
    nvm[16] = 3;
    nvm[24] = 110;
    nvm[28] = 1;
    nvm[28 + 14 * 4] = 1;
    let info = station_api::Nvm::parse(4, &nvm).unwrap();
    if info.channels != [1, 36] {
        return TestResult::Fail("NVM profile channel mapping");
    }
    let scan = scan_api::passive(18, 0, &info.channels).unwrap();
    if scan.len() != 1948
        || scan[45] != 2
        || scan[48..52] != (1u32 << 30).to_le_bytes()
        || scan[56..60] != [0; 4]
        || scan[52] != 1
        || scan[60] != 36
        || scan[594] != 1
    {
        return TestResult::Fail("scan v18 channel band/count/periodic encoding");
    }
    nvm[24] = 111;
    if station_api::Nvm::parse(4, &nvm).is_ok() || scan_api::passive(13, 0, &[1]).is_ok() {
        return TestResult::Fail("unsupported NVM/scan geometry accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_scan_nvm_and_band_numbering
);

fn smoke_frame_receive_padding_mic_and_replay() -> TestResult {
    let local = [2, 1, 2, 3, 4, 5];
    let ap = [2, 6, 7, 8, 9, 10];
    let mut bytes = vec![0; 64 + 50];
    bytes[0] = 50;
    bytes[2] = 0x20;
    bytes[3] = 0x20; // 4-byte trailer, 2-byte pad
    boot_context::put32(&mut bytes, 12, 0x243); // good CRC/overrun + CCM + MIC
    bytes[64] = 8;
    bytes[65] = 0x42; // data FromDS, protected
    bytes[68..74].copy_from_slice(&local);
    bytes[74..80].copy_from_slice(&ap);
    bytes[80..86].fill(0x12);
    bytes[88..96].copy_from_slice(&narf_wireless::ccmp::build_ccmp_header(5, 0));
    bytes[98..110].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4]);
    let mut replay = frame_api::Replay::default();
    let mut bad = bytes.clone();
    bad[12] &= !0x40;
    if frame_api::receive(&scan_api::mpdu(&bad).unwrap(), local, ap, true, &mut replay).is_some()
        || replay.pairwise[16] != 0
    {
        return TestResult::Fail("bad MIC advanced replay state");
    }
    let mpdu = scan_api::mpdu(&bytes).unwrap();
    let frame = frame_api::receive(&mpdu, local, ap, true, &mut replay).unwrap();
    if frame[..6] != local
        || frame[6..12] != [0x12; 6]
        || frame[12..] != [8, 0, 1, 2, 3, 4]
        || replay.pairwise[16] != 5
    {
        return TestResult::Fail("RX padding/IV/trailer or Ethernet conversion");
    }
    if frame_api::receive(&mpdu, local, ap, true, &mut replay).is_some() {
        return TestResult::Fail("CCMP replay accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_frame_receive_padding_mic_and_replay
);

fn smoke_frame_transmit_address_mapping() -> TestResult {
    let local = [2, 1, 2, 3, 4, 5];
    let ap = [2, 6, 7, 8, 9, 10];
    let mut ethernet = vec![0; 18];
    ethernet[..6].fill(0xff);
    ethernet[6..12].copy_from_slice(&local);
    ethernet[12..].copy_from_slice(&[8, 0, 1, 2, 3, 4]);
    let frame = frame_api::transmit(local, ap, 0x1234, &ethernet, true).unwrap();
    if frame[..2] != [8, 0x41]
        || frame[4..10] != ap
        || frame[10..16] != local
        || frame[16..22] != [0xff; 6]
        || frame[22..24] != [0x40, 0x23]
        || frame[24..] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4]
    {
        return TestResult::Fail("TX 802.11 mapping");
    }
    ethernet[6] ^= 1;
    if frame_api::transmit(local, ap, 0, &ethernet, false).is_some() {
        return TestResult::Fail("foreign Ethernet source accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_frame_transmit_address_mapping
);

fn smoke_active_scan_segments_and_channel_permissions() -> TestResult {
    let local = [2, 1, 2, 3, 4, 5];
    for (version, capacity) in [(14, 67), (17, 67), (18, 68)] {
        let ssids = vec![b"hidden".to_vec(), Vec::new()];
        let command = scan_api::active(
            version,
            7,
            &[1, 36, 52],
            &[true, true, false],
            local,
            &ssids,
        )
        .unwrap();
        let probe = 48 + capacity * 8 + 12;
        let data = probe + 20;
        if command[8..10] != [2, 0]
            || command[48..52] != ((1u32 << 30) | 3).to_le_bytes()
            || command[56..60] != 3u32.to_le_bytes()
            || command[64..68] != [0; 4]
            || command[probe..probe + 4] != [0, 0, 26, 0]
            || command[data..data + 2] != [0x40, 0]
            || command[data + 4..data + 10] != [0xff; 6]
            || command[data + 10..data + 16] != local
            || command[data + 16..data + 22] != [0xff; 6]
            || command[data + 24..data + 26] != [0, 0]
            || command[probe + 536..probe + 544] != *b"\0\x06hidden"
        {
            return TestResult::Fail("active scan firmware layout or passive-channel isolation");
        }
        let passive = scan_api::active(version, 7, &[52], &[false], local, &ssids).unwrap();
        if passive != scan_api::passive(version, 7, &[52]).unwrap() {
            return TestResult::Fail("denied active scan emitted a probe");
        }
    }
    if scan_api::active(18, 0, &[1], &[true], local, &[vec![0; 33]]).is_ok()
        || scan_api::active(18, 0, &[1], &[], local, &[]).is_ok()
    {
        return TestResult::Fail("invalid probe request accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_active_scan_segments_and_channel_permissions
);

fn smoke_probe_regulatory_intersection() -> TestResult {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let mut domain = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5330,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    };
    let mut flags = vec![0; 51];
    let i = station_api::channel_index(36).unwrap();
    flags[i] = 13; // VALID + 20MHz activity + ACTIVE
    if connection::channel_power(&domain, 36, &flags, true) != Some(17) {
        return TestResult::Fail("authorized probe channel denied");
    }
    flags[i] = 5; // association allowed, initiating a probe is not
    if connection::channel_power(&domain, 36, &flags, true).is_some()
        || connection::channel_power(&domain, 36, &flags, false) != Some(17)
    {
        return TestResult::Fail("active scan ignored MCC ACTIVE restriction");
    }
    flags[i] = 13 | 16;
    if connection::channel_power(&domain, 36, &flags, true).is_some() {
        return TestResult::Fail("probe on firmware DFS channel");
    }
    flags[i] = 13;
    domain.rules[0].flags = RegFlags::DFS;
    if connection::channel_power(&domain, 36, &flags, true).is_some() {
        return TestResult::Fail("probe on host DFS channel");
    }
    domain.rules[0].flags = RegFlags::empty();
    let mut lower = domain.rules[0].clone();
    lower.max_power_dbm = 9;
    domain.rules.push(lower);
    if connection::channel_power(&domain, 36, &flags, true) != Some(9)
        || connection::channel_power(&domain, 1, &flags, true).is_some()
    {
        return TestResult::Fail("host channel/power intersection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_probe_regulatory_intersection
);

fn smoke_wmm_edca_and_admission_control() -> TestResult {
    // Hostapd-style WMM parameters in wire ACI order BE, BK, VI, VO.
    let mut ie = vec![
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 0x03, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94,
        0, 0x62, 0x32, 47, 0,
    ];
    let mut qos = qos::Parameters::parse(&ie).unwrap().unwrap();
    let mut link = station_api::link(2, [2; 6], true, 36, 100, 1);
    qos.apply(&mut link);
    if link[56..60] != 1u32.to_le_bytes()
        || link[60..68] != [15, 0, 255, 3, 7, 0, 0, 0]
        || link[76..84] != [7, 0, 15, 0, 2, 0, 0xc0, 0xb]
        || link[84..92] != [3, 0, 7, 0, 2, 0, 0xe0, 5]
    {
        return TestResult::Fail("WMM ACI to firmware AC or TXOP units mismatch");
    }
    let mut ethernet = vec![0; 54];
    ethernet[12..14].copy_from_slice(&[8, 0]);
    ethernet[14] = 0x45;
    for (dscp, ac) in [(0, 1), (8, 0), (34, 2), (46, 3)] {
        ethernet[15] = dscp << 2;
        if qos.classify(&ethernet) != Some(ac) {
            return TestResult::Fail("IPv4 DSCP classification");
        }
    }
    qos.ac[3].admission = true;
    if qos.classify(&ethernet) != Some(2) {
        return TestResult::Fail("ACM bypassed instead of downgraded");
    }
    ethernet[12..14].copy_from_slice(&[0x86, 0xdd]);
    ethernet[14] = 0x6b;
    ethernet[15] = 0x80; // IPv6 EF traffic class
    if qos.classify(&ethernet) != Some(2) {
        return TestResult::Fail("IPv6 DSCP classification");
    }
    for ac in &mut qos.ac {
        ac.admission = true;
    }
    if qos.classify(&ethernet).is_some() {
        return TestResult::Fail("all ACM categories admitted");
    }
    ie[14] = 3; // duplicate BE, missing BK
    if qos::Parameters::parse(&ie).is_ok() {
        return TestResult::Fail("duplicate WMM ACI accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_wmm_edca_and_admission_control
);

fn smoke_qos_transmit_header_and_tid() -> TestResult {
    let local = [2, 1, 2, 3, 4, 5];
    let ap = [2, 6, 7, 8, 9, 10];
    let mut ethernet = vec![0; 18];
    ethernet[..6].fill(0xff);
    ethernet[6..12].copy_from_slice(&local);
    ethernet[12..].copy_from_slice(&[8, 0, 1, 2, 3, 4]);
    for tid in qos::TIDS {
        let frame = frame_api::transmit_qos(local, ap, 3, &ethernet, true, tid).unwrap();
        if frame[..2] != [0x88, 0x41]
            || frame[24..26] != [tid, 0]
            || frame[26..] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4]
        {
            return TestResult::Fail("QoS MAC header/LLC geometry");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_qos_transmit_header_and_tid
);

fn smoke_negotiated_legacy_rates_and_tlc() -> TestResult {
    // OFDM-only 2.4GHz BSS: management must not use the old fixed 1M CCK.
    let rates = rates::Rates::parse(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108], 6).unwrap();
    if rates.supported != 0xff0 || rates.basic != 0x150 || rates.management_rate(1) != 0x4100 {
        return TestResult::Fail("AP basic/supported rate intersection");
    }
    let command = rates.tlc(6, 3).unwrap();
    if command[..4] != [1, 0, 0, 0]
        || command[8..12] != [0, 0, 3, 0]
        || command[14..16] != [0xf0, 0xf]
        || command[16..40] != [0; 24]
        || command[40..44] != [0xff, 0xf, 0, 0]
    {
        return TestResult::Fail("TLC v6 station/rate/MPDU configuration");
    }
    if rates::Rates::parse(&[1, 1, 0xff], 6).is_ok()
        || rates::Rates::parse(&[1, 1, 0x82], 36).is_ok()
        || rates::Rates::parse(&[1, 2, 0x8c], 36).is_ok()
    {
        return TestResult::Fail("unsupported required PHY/band or truncated rates accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_negotiated_legacy_rates_and_tlc
);
