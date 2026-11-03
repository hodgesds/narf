//! Authored API77 D3 command/notification layouts (`fw/api/d3.h`). No vendor
//! image or device; native suspend/resume conversations live with the Gen2
//! recovery smokes.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The installed 22000/API77 WoWLAN inventory: opcode, group, command
/// version, notification version.
const API77_D3: &[[u8; 4]] = &[
    [0xe1, 1, 6, 0],
    [0xe0, 1, 3, 0],
    [0xe2, 1, 5, 0],
    [0xe4, 1, 4, 0],
    [0xd4, 1, 4, 0],
    [0xd3, 1, 4, 0],
    [0xfd, 0xb, 99, 1],
    [0xfc, 0xb, 99, 1],
    [0xfe, 0xb, 99, 1],
];

fn api(commands: &[u8]) -> FirmwareApi<'_> {
    let mut api = FirmwareApi {
        commands,
        flags: 1 << 16,
        ..FirmwareApi::default()
    };
    api.capabilities[0] = 1 << 17;
    api.api_changes[1] = 1 << (53 - 32);
    api
}

fn check(test: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match test() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}

fn flat(rows: &[[u8; 4]]) -> Vec<u8> {
    rows.iter().flatten().copied().collect()
}

fn smoke_mvm_d3_admits_only_exact_api77_unified_versions() -> TestResult {
    check(|| {
        let commands = flat(API77_D3);
        let admitted = D3Api::admit(&api(&commands))?;
        if admitted.btm {
            return Err("BTM offload without capability 113");
        }
        let mut btm = api(&commands);
        btm.capabilities[3] = 1 << (113 - 96);
        if !D3Api::admit(&btm)?.btm {
            return Err("BTM capability ignored");
        }
        let mut split = api(&commands);
        split.capabilities[0] = 0;
        if D3Api::admit(&split).is_ok() {
            return Err("non-unified image admitted without a D3 image");
        }
        let mut first = api(&commands);
        first.capabilities[1] = 1 << (41 - 32);
        if D3Api::admit(&first).is_ok() {
            return Err("D0I3_END_FIRST resume admitted");
        }
        let mut small = api(&commands);
        small.flags |= 1 << 15;
        if D3Api::admit(&small).is_ok() {
            return Err("small NS offload layout admitted");
        }
        let mut no_syn = api(&commands);
        no_syn.api_changes[1] = 0;
        if D3Api::admit(&no_syn).is_ok() {
            return Err("pattern v1 layout admitted");
        }
        // Every row is load-bearing: a different or missing version fails.
        for row in 0..API77_D3.len() {
            for version in [None, Some(7u8)] {
                let mut rows = API77_D3.to_vec();
                match version {
                    None => {
                        rows.remove(row);
                    }
                    Some(v) if rows[row][1] == 0xb => rows[row][3] = v,
                    Some(v) => rows[row][2] = v,
                }
                // KEK/KCK is not used by the admitted trigger set.
                if API77_D3[row][0] == 0xe4 {
                    continue;
                }
                let bytes = flat(&rows);
                if D3Api::admit(&api(&bytes)).is_ok() {
                    return Err("unadvertised D3 command version admitted");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_d3_admits_only_exact_api77_unified_versions
);

fn pattern(len: usize, offset: u32) -> narf_wireless::WowlanPattern {
    narf_wireless::WowlanPattern {
        mask: vec![0xff; len.div_ceil(8)],
        pattern: (0..len as u8).collect(),
        offset,
    }
}

fn smoke_mvm_d3_wake_limits_and_configuration_v6_layout() -> TestResult {
    check(|| {
        let support = support();
        if !support.disconnect
            || !support.magic_packet
            || support.gtk_rekey
            || support.gtk_rekey_failure
            || support.max_patterns != 20
            || support.min_pattern_len != 16
            || support.max_pattern_len != 128
            || support.max_packet_offset != 0
            || support.net_detect_max_match_sets != 0
        {
            return Err("WoWLAN support differs from the admitted trigger set");
        }
        let mut config = WowlanConfig {
            disconnect: true,
            magic_packet: true,
            patterns: vec![pattern(16, 0), pattern(128, 0)],
            ..WowlanConfig::default()
        };
        let wake = Wake::from_config(&config)?;
        for bad in [pattern(15, 0), pattern(129, 0), pattern(16, 1)] {
            config.patterns = vec![bad];
            if Wake::from_config(&config).is_ok() {
                return Err("pattern outside firmware limits admitted");
            }
        }
        config.patterns = (0..21).map(|_| pattern(16, 0)).collect();
        if Wake::from_config(&config).is_ok() {
            return Err("21 patterns admitted");
        }
        if Wake::from_config(&WowlanConfig::default()).is_ok() {
            return Err("empty trigger set admitted");
        }
        let rekey = WowlanConfig {
            gtk_rekey_failure: true,
            ..WowlanConfig::default()
        };
        if Wake::from_config(&rekey).is_ok() {
            return Err("unadvertised GTK failure trigger admitted");
        }
        let station = Station {
            sta_id: 1,
            ht: true,
            mfp: true,
            next_qos_seq: [0x20, 0x10, 0, 0x30, 0x40, 0x50, 0x60, 0x70],
        };
        let bytes = configuration_v6(&wake, &station);
        if bytes[..4]
            != (filter::MAGIC_PACKET
                | filter::PATTERN_MATCH
                | filter::BEACON_MISS
                | filter::LINK_CHANGE)
                .to_le_bytes()
            || bytes[4..6] != [0, 0]
            || bytes[6..8] != [0x10, 0]
            || bytes[8..10] != [0, 0]
            || bytes[10..12] != [0xf0, 0xff]
            || bytes[20..22] != [0x60, 0]
            || bytes[22..28] != [0, 1, 0, 0x0f, 1, 0]
        {
            return Err("WOWLAN_CONFIGURATION v6 layout differs");
        }
        let patterns = patterns_v3(1, &wake.patterns).ok_or("pattern command missing")?;
        if patterns.len() != 4 + 2 * 152
            || patterns[..4] != [2, 1, 0, 0]
            || patterns[4] != 0
            || patterns[8..10] != [0xff, 0xff]
            || patterns[8 + 16..8 + 18] != [0, 1]
            || patterns[8 + 144..8 + 146] != [2, 16]
            || patterns[156 + 4 + 144..156 + 4 + 146] != [16, 128]
        {
            return Err("WOWLAN_PATTERNS v3 layout differs");
        }
        if patterns_v3(1, &[]).is_some() {
            return Err("empty pattern command emitted");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_d3_wake_limits_and_configuration_v6_layout
);

fn smoke_mvm_d3_rsc_offload_and_d3_config_layouts() -> TestResult {
    check(|| {
        if rsc_tsc_v5(1, &Counters::default())?.is_some() {
            return Err("RSC command without keys");
        }
        let counters = Counters {
            ptk: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            gtks: vec![(2, [9; 8]), (1, [10; 8])],
        };
        let bytes = rsc_tsc_v5(3, &counters)?.ok_or("RSC command missing")?;
        if bytes[..8] != 1u64.to_le_bytes()
            || bytes[56..64] != 8u64.to_le_bytes()
            || bytes[64..72] != 9u64.to_le_bytes()
            || bytes[128..136] != 10u64.to_le_bytes()
            || bytes[192..196] != [3, 0, 0, 0]
            || bytes[196..200] != [0xff, 1, 0, 0xff]
        {
            return Err("WOWLAN_TSC_RSC_PARAM v5 layout differs");
        }
        let three = Counters {
            ptk: None,
            gtks: vec![(1, [0; 8]), (2, [0; 8]), (3, [0; 8])],
        };
        let duplicate = Counters {
            ptk: None,
            gtks: vec![(1, [0; 8]), (1, [0; 8])],
        };
        if rsc_tsc_v5(1, &three).is_ok() || rsc_tsc_v5(1, &duplicate).is_ok() {
            return Err("invalid GTK set admitted");
        }
        let offload = proto_offload_v4(1, &D3Api { btm: true });
        if offload.len() != 428
            || offload[..8] != [1, 0, 0, 0, 0x10, 0, 0, 0]
            || offload[8..].iter().any(|&b| b != 0)
        {
            return Err("PROT_OFFLOAD_CONFIG v4 layout differs");
        }
        if proto_offload_v4(1, &D3Api { btm: false })[4..8] != [0; 4] {
            return Err("BTM enabled without capability");
        }
        if d3_config() != [0x80, 0x96, 0x98, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
            return Err("D3_CONFIG_CMD layout differs");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_d3_rsc_offload_and_d3_config_layouts
);

fn info(reasons: u32, rekeys: u32) -> Vec<u8> {
    let mut bytes = vec![0; INFO_V1_LEN];
    // gtk[0]: key index 1, current, 16-byte key; counters in its sc.
    bytes[..16].copy_from_slice(&[0x55; 16]);
    bytes[32] = 16;
    bytes[33] = 0x81;
    for tid in 0..8 {
        put64(&mut bytes, 48 + tid * 8, 100 + tid as u64);
        put64(&mut bytes, 48 + 64 + 64 + tid * 8, 200 + tid as u64);
    }
    bytes[48 + 196..48 + 200].copy_from_slice(&[0xff, 1, 0xff, 0xff]);
    put64(&mut bytes, 568, 0x0102030405060708);
    put16(&mut bytes, 576, 3);
    put16(&mut bytes, 580, 0x120);
    put32(&mut bytes, 596, reasons);
    put32(&mut bytes, 600, rekeys);
    put32(&mut bytes, 608, 77);
    put32(&mut bytes, 612, 60);
    bytes[621] = 1;
    bytes
}

fn smoke_mvm_d3_info_v1_wake_packet_and_d3_end() -> TestResult {
    check(|| {
        if parse_info_v1(&[0; INFO_V1_LEN - 1]).is_ok() {
            return Err("short WoWLAN info admitted");
        }
        let status = parse_info_v1(&info(reason::MAGIC_PACKET, 0))?;
        if status.ptk_rx != [100, 101, 102, 103, 104, 105, 106, 107]
            || status.gtk_rx != vec![(1, [200, 201, 202, 203, 204, 205, 206, 207])]
            || status.gtks.len() != 1
            || status.gtks[0].id != 1
            || status.gtks[0].len != 16
            || status.replay_counter != 0x0102030405060708
            || status.pattern_number != 3
            || status.qos_seq[0] != 0x120
            || status.received_beacons != 77
            || status.wake_packet_length != 60
            || status.station_id != 1
        {
            return Err("WOWLAN_INFO v1 conversion differs");
        }
        if !keeps_connection(&status) {
            return Err("magic-packet wake dropped the connection");
        }
        for (reasons, rekeys) in [
            (reason::DEAUTH, 0),
            (reason::MISSED_BEACON, 0),
            (reason::UCODE_ERROR, 0),
            (0, 1),
        ] {
            if keeps_connection(&parse_info_v1(&info(reasons, rekeys))?) {
                return Err("disconnect/error/rekey wake kept the connection");
            }
        }
        let mut packet = vec![0; 8];
        put32(&mut packet, 0, 4);
        packet.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        if parse_wake_packet(&packet)? != [1, 2, 3, 4] || parse_wake_packet(&[0; 7]).is_ok() {
            return Err("wake packet bounds differ");
        }
        let report = report(&status, vec![9]);
        if !report.magic_packet || report.disconnect || report.packet != [9] {
            return Err("magic-packet wake report differs");
        }
        let idle = parse_info_v1(&info(0, 0))?;
        if !super::report(&idle, vec![9]).non_wireless {
            return Err("non-wireless wake not reported");
        }
        let pattern = parse_info_v1(&info(reason::PATTERN | reason::UNPROTECTED_DEAUTH, 0))?;
        let pattern = super::report(&pattern, Vec::new());
        if pattern.pattern_index != Some(3)
            || !pattern.unprotected_deauth_disassoc
            || pattern.disconnect
        {
            return Err("pattern wake report differs");
        }
        if parse_d3_end(&[1, 0, 0, 0])? != true
            || parse_d3_end(&[0; 4])?
            || parse_d3_end(&[0; 3]).is_ok()
        {
            return Err("D3_END reset flag differs");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/wowlan",
    smoke_mvm_d3_info_v1_wake_packet_and_d3_end
);
