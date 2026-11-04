//! Literal Linux CONNAC2 NLO layout regressions.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::{NetDetectMatch, NetDetectScanPlan, ScanRandomMac};

fn config() -> NetDetectConfig {
    NetDetectConfig {
        probe_ssids: vec![b"one".to_vec(), b"two".to_vec()],
        frequencies_mhz: vec![2437, 5180, 5975],
        probe_ies: vec![221, 3, 0x12, 0x34, 0x56],
        matches: vec![
            NetDetectMatch {
                ssid: b"one".to_vec(),
                rssi_threshold_dbm: Some(-67),
            },
            NetDetectMatch {
                ssid: b"two".to_vec(),
                rssi_threshold_dbm: None,
            },
        ],
        plans: vec![NetDetectScanPlan {
            interval_secs: 65535,
            iterations: None,
        }],
        delay_secs: 0x1234_5678,
        random_mac: Some(ScanRandomMac {
            addr: [2, 0xa0, 0, 0, 0, 0],
            mask: [0xff, 0xf0, 0, 0, 0, 0],
        }),
    }
}

fn literal() -> Result<(), &'static str> {
    let config = config();
    let channels = [
        (channel::Band::Ghz2, 6),
        (channel::Band::Ghz5, 36),
        (channel::Band::Ghz6, 5),
    ];
    let random = [2, 0xa7, 0x41, 0x82, 0x32, 0x11];
    let body = request(&config, 127, &channels, Some(random)).map_err(|_| "NLO native encoding")?;
    if body.len() != 1229
        || body[..8] != [1, 127, 0, 2, 2, 0, 5, 0]
        || body[8..15] != [3, 0, 0, 0, b'o', b'n', b'e']
        || body[44..51] != [3, 0, 0, 0, b't', b'w', b'o']
        || body[368..372] != (-67i32).to_le_bytes()
        || &body[372..375] != b"one"
        || body[404] != 3
        || body[408..412] != (-300i32).to_le_bytes()
        || &body[412..415] != b"two"
        || body[444] != 3
        || body[1008..1018] != [4, 3, 1, 1, 1, 6, 2, 36, 3, 5]
        || body[1140..1142] != [0xff, 0xff]
        || body[1160..1168] != [0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]
        || body[1180..1186] != random
        || body[1224..] != config.probe_ies
        || enable(true) != [0, 0, 0, 0]
        || enable(false) != [1, 0, 0, 0]
    {
        return Err("NLO literal packed layout lost a native field or alias-separated channel");
    }
    Ok(())
}

fn mt76_nlo_literal_packed_ssids_matches_intervals_channels_and_random_address() -> TestResult {
    literal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wowlan",
    mt76_nlo_literal_packed_ssids_matches_intervals_channels_and_random_address
);

fn refusal() -> Result<(), &'static str> {
    let original = config();
    for fault in 0..9 {
        let mut config = original.clone();
        match fault {
            0 => config.probe_ssids.resize(11, b"overflow".to_vec()),
            1 => config.matches.resize(11, config.matches[0].clone()),
            2 => config.plans[0].interval_secs = 65536,
            3 => config.plans[0].iterations = Some(1),
            4 => config.plans.push(config.plans[0].clone()),
            5 => config.probe_ies = vec![221; 513],
            6 => config.matches[0].ssid.clear(),
            7 => config.frequencies_mhz.resize(65, 2412),
            _ => config.random_mac.as_mut().unwrap().mask[0] = 0,
        }
        if validate(&config) != Err(Error::Bounds) {
            return Err("NLO accepted unsupported plan/count/IE/address metadata");
        }
    }
    let channels = [(channel::Band::Ghz2, 6)];
    for address in [
        None,
        Some([3, 0xa7, 1, 2, 3, 4]),
        Some([2, 0x07, 1, 2, 3, 4]),
    ] {
        if request(&original, 1, &channels, address) != Err(Error::Bounds) {
            return Err("NLO synthesized an absent/invalid host-resolved random MAC");
        }
    }
    let mut passive = original;
    passive.probe_ssids.clear();
    passive.random_mac = None;
    if request(&passive, 1, &channels, None).map(|body| body[3] == 0 && body[1011] == 0) != Ok(true)
    {
        return Err("NLO passive request fabricated probes or random-source metadata");
    }
    Ok(())
}

fn mt76_nlo_rejects_unsupported_counts_plans_and_unresolved_random_metadata() -> TestResult {
    refusal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wowlan",
    mt76_nlo_rejects_unsupported_counts_plans_and_unresolved_random_metadata
);
