//! Host scheduled scan through the retained native owner (Linux
//! mt7921_start_sched_scan / mt7921_stop_sched_scan and the
//! MCU_EVENT_SCHED_SCAN_DONE cycle report).
use super::*;
use narf_wireless::{NetDetectConfig, NetDetectMatch, NetDetectScanPlan};

fn config(probe: bool) -> NetDetectConfig {
    NetDetectConfig {
        probe_ssids: if probe {
            vec![b"narf".to_vec()]
        } else {
            Vec::new()
        },
        frequencies_mhz: vec![2412, 2437],
        probe_ies: Vec::new(),
        matches: vec![NetDetectMatch {
            ssid: b"narf".to_vec(),
            rssi_threshold_dbm: None,
        }],
        plans: vec![NetDetectScanPlan {
            interval_secs: 30,
            iterations: None,
        }],
        delay_secs: 0,
        random_mac: None,
    }
}

fn policy(power: i8) -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 40,
            max_power_dbm: power,
            flags: RegFlags::empty(),
        }],
    }
}

fn ce(frame: &[u8], id: u8) -> Option<&[u8]> {
    (frame.len() > 64 && frame[43] != 7 && frame[36] == id).then(|| &frame[64..])
}

fn done() -> Vec<u8> {
    runtime_event(0x23, 0, 0, &[0; 4])
}

/// Every channel of a CE 0x0f domain is NO_IR (passive).
fn passive(domain: &[u8]) -> bool {
    domain[12..]
        .chunks_exact(8)
        .all(|entry| u32::from_le_bytes(entry[4..8].try_into().unwrap()) & 2 != 0)
}

fn lifecycle() -> Result<(), &'static str> {
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).map_err(|_| "firmware fixture")?;
    run(session.initialize_radio()).map_err(|_| "radio fixture")?;
    let start = session.backend.frames.len();
    run(session.start_sched_scan(&config(false))).map_err(|_| "passive sched scan start")?;
    let frames = &session.backend.frames[start..];
    let request = frames
        .iter()
        .position(|(_, frame)| ce(frame, 0x62).is_some())
        .ok_or("no NLO request")?;
    let enable = frames
        .iter()
        .position(|(_, frame)| ce(frame, 0x61) == Some(&[0, 0, 0, 0][..]))
        .ok_or("no NLO enable")?;
    let body = ce(&frames[request].1, 0x62).ok_or("NLO body")?;
    if request > enable
        || body[3] != 0
        || body[4] != 1
        || body[368..372] != (-300i32).to_le_bytes()
        || body[372..376] != *b"narf"
        || body[404] != 4
        || body[1008..1016] != [4, 2, 1, 0, 1, 1, 1, 6]
        || body[1140..1142] != [30, 0]
        || frames.iter().any(|(_, frame)| ce(frame, 3).is_some())
        || !matches!(session.state, State::ScanReady(_))
        || !session.sched_scan_running()
    {
        return Err("scheduled scan request fields, order or state");
    }
    if !frames
        .iter()
        .filter_map(|(_, frame)| ce(frame, 0x0f))
        .all(passive)
    {
        return Err("a passive scheduled scan obtained probe permission");
    }
    if run(session.start_sched_scan(&config(false))) != Err(Error::Busy)
        || !matches!(run(session.scan_passive(&[1, 6])), Err(Error::Busy))
    {
        return Err("a second request or a one-shot scan ran beside it");
    }
    if !matches!(session.step_sched_scan(), Ok(None)) {
        return Err("an idle step reported a cycle");
    }
    session.backend.packets.push_back(scan_beacon(6, b"narf"));
    session.backend.packets.push_back(scan_beacon(1, &[]));
    session
        .backend
        .packets
        .push_back(scan_beacon(11, b"elsewhere"));
    if !matches!(session.step_sched_scan(), Ok(None)) {
        return Err("results before the cycle finished");
    }
    session.backend.replies.push_back(done());
    let report = session
        .step_sched_scan()
        .map_err(|_| "cycle step")?
        .ok_or("SCHED_SCAN_DONE did not finish the cycle")?;
    let mut channels: Vec<_> = report.bss.iter().map(|bss| bss.channel).collect();
    channels.sort_unstable();
    if channels != [1, 6]
        || !report
            .bss
            .iter()
            .any(|bss| bss.channel == 6 && bss.ssid == b"narf")
        || !report.beaconed.iter().any(|&(_, channel)| channel == 6)
    {
        return Err("cycle results: request channels, SSIDs and beacons");
    }
    session.backend.replies.push_back(done());
    match session.step_sched_scan() {
        Ok(Some(next)) if next.bss.is_empty() => {}
        _ => return Err("the next cycle inherited the previous one's results"),
    }
    let stop = session.backend.frames.len();
    run(session.stop_sched_scan()).map_err(|_| "sched scan stop")?;
    let frames = &session.backend.frames[stop..];
    let disable = frames
        .iter()
        .position(|(_, frame)| ce(frame, 0x61) == Some(&[1, 0, 0, 0][..]))
        .ok_or("no NLO disable")?;
    let domain = frames
        .iter()
        .position(|(_, frame)| ce(frame, 0x0f).is_some_and(passive))
        .ok_or("idle domain not restored")?;
    if disable > domain
        || session.sched_scan_running()
        || !matches!(session.step_sched_scan(), Err(Error::Cancelled))
        || run(session.stop_sched_scan()) != Err(Error::Cancelled)
    {
        return Err("stop order or retained request");
    }
    run(session.scan_passive(&[1, 6])).map_err(|_| "one-shot scan after stop")?;
    Ok(())
}
fn mt76_sched_scan_programs_nlo_reports_cycles_and_stops() -> TestResult {
    lifecycle().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_sched_scan_programs_nlo_reports_cycles_and_stops
);

/// Directed probes need a regulatory grant on every requested channel; the
/// grant is rechecked each step, and stopping returns the idle VIF to NO_IR.
fn probes() -> Result<(), &'static str> {
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).map_err(|_| "firmware fixture")?;
    run(session.initialize_radio()).map_err(|_| "radio fixture")?;
    let current = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: AtomicBool::new(false),
    });
    current.database.install(policy(17));
    session.backend.tx_policy = Some(current.clone());
    let mut outside = config(true);
    outside.frequencies_mhz = vec![5180];
    let before = session.backend.frames.len();
    if run(session.start_sched_scan(&outside)).is_ok()
        || session.backend.frames.len() != before
        || session.sched_scan_running()
    {
        return Err("probing outside the regulatory domain was programmed");
    }
    run(session.start_sched_scan(&config(true))).map_err(|_| "active sched scan start")?;
    let body = session
        .backend
        .frames
        .iter()
        .rev()
        .find_map(|(_, frame)| ce(frame, 0x62))
        .ok_or("NLO body")?;
    let domain = session
        .backend
        .frames
        .iter()
        .rev()
        .find_map(|(_, frame)| ce(frame, 0x0f))
        .ok_or("probe domain")?;
    if body[3] != 1
        || body[8..12] != 4u32.to_le_bytes()
        || body[12..16] != *b"narf"
        || passive(domain)
    {
        return Err("directed probe SSID or its channel grant");
    }
    current.database.install(policy(9));
    if session.step_sched_scan().is_ok() {
        return Err("a replaced regulatory grant kept the probing scan");
    }
    run(session.stop_sched_scan()).map_err(|_| "stop after policy change")?;
    let domain = session
        .backend
        .frames
        .iter()
        .rev()
        .find_map(|(_, frame)| ce(frame, 0x0f))
        .ok_or("idle domain")?;
    if !passive(domain) {
        return Err("probe permission outlived the scheduled scan");
    }
    Ok(())
}
fn mt76_sched_scan_probes_only_under_current_regulatory_grant() -> TestResult {
    probes().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mt76_sched_scan_probes_only_under_current_regulatory_grant
);
