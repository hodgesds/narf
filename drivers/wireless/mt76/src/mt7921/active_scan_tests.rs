//! Active scan conversations through the retained firmware/DMA owner.
use super::*;
use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

fn policy() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2472,
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5895,
                max_bandwidth_mhz: 20,
                max_power_dbm: 14,
                flags: RegFlags::empty(),
            },
        ],
    }
}
fn ready_radio() -> Result<Session<Model>, &'static str> {
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).map_err(|_| "MT76 firmware fixture initialization")?;
    run(session.initialize_radio()).map_err(|_| "MT76 radio fixture initialization")?;
    Ok(session)
}
fn originals() -> Result<(), &'static str> {
    const ORIGINAL: &[u8; 4 * 1186] = include_bytes!("scan_reference.bytes");
    let channels = crate::mt7921::channel::channels(3);
    let fixtures = [
        scan::scan_request(1, &[1, 6, 36]),
        scan::active_scan_request(127, &[1, 6, 11], &[Vec::new()]),
        scan::active_scan_request(
            7,
            &[36, 1, 177],
            &[
                b"narf\0one".to_vec(),
                (0u8..32).collect(),
                b"x".to_vec(),
                b"four".to_vec(),
            ],
        ),
        scan::active_scan_request(
            2,
            &channels,
            &[Vec::new(), b"hidden".to_vec(), Vec::new(), b"z".to_vec()],
        ),
    ];
    for (index, generated) in fixtures.into_iter().enumerate() {
        if generated.map_err(|_| "scan encoder rejected original fixture")?
            != ORIGINAL[index * 1186..(index + 1) * 1186]
        {
            return Err("whole CONNAC2 scan body differs from original Linux encoder");
        }
    }
    Ok(())
}
fn mcu_active_scan_whole_request_matches_frozen_reference() -> TestResult {
    originals().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_active_scan_whole_request_matches_frozen_reference
);

fn native() -> Result<(), &'static str> {
    for channels in [[36, 6], [6, 36]] {
        native_order(&channels)?;
    }
    Ok(())
}
fn native_order(channels: &[u8]) -> Result<(), &'static str> {
    const BAND_ORDER: &[u8; 2] = include_bytes!("power_order.bytes");
    let mut session = ready_radio()?;
    let mut probe = scan_beacon(6, b"hidden");
    probe[32] = 0x50; // Native Probe Response, not a fabricated cache record.
    session.backend.packets.push_back(probe);
    let before = session.backend.frames.len();
    let report =
        run(session.scan_active_with_policy(channels, &[b"hidden".to_vec()], || Ok(policy())))
            .map_err(|_| "retained active scan conversation")?;
    if report.received != 1
        || report.bss.len() != 1
        || report.bss[0].ssid != b"hidden"
        || !matches!(session.state, State::ScanReady(_))
        || session.security.is_some()
    {
        return Err("active scan observations or unauthorized station publication");
    }
    let frames = &session.backend.frames[before..];
    if frames.len() != 12
        || frames[5].1[36] != 0x5d
        || frames[6].1[36] != 0xc0
        || frames[7].1[36] != 0x5d
        || frames[8].1[36] != 0xc0
        || frames[9].1[36] != 0x0f
        || frames[10].1[36] != 3
        || frames[11].1[36] != 0x0f
    {
        return Err("active scan bypassed VIF/power/PSE/domain/start/close sequencing");
    }
    for (row, (index, power, channel, last)) in
        [(5, 34, 6, 0), (7, 28, 36, 1)].into_iter().enumerate()
    {
        let limits = &frames[index].1[64..];
        if limits.len() != 206
            || limits[4] != 1
            || limits[5] != BAND_ORDER[row]
            || limits[6] != last
            || &limits[8..10] != b"US"
            || limits[44] != channel
            || limits[45..].iter().any(|&entry| entry != power)
        {
            return Err("active scan lost its per-channel signed half-dBm ceiling");
        }
    }
    for index in [6, 8] {
        let query = &frames[index].1;
        if query[38] != 0 || query[64..] != [0, 0x80, 0x0c, 0x82, 0, 0, 0, 0] {
            return Err("source PSE query was not a correlated register read");
        }
    }
    let domain = &frames[9].1[64..];
    if domain.len() != 28
        || &domain[..2] != b"US"
        || domain[8..10] != [1, 1]
        || domain[12..14] != [6, 0]
        || domain[20..22] != [36, 0]
        || domain[16..20] != [0; 4]
        || domain[24..28] != [0; 4]
    {
        return Err("scan TX permission widened or failed band partitioning");
    }
    if frames[11].1[76..]
        .chunks_exact(8)
        .any(|ch| ch[4..] != [2, 0, 0, 0])
    {
        return Err("completed active scan left an idle TX-enabled domain");
    }
    if frames[10].1[66] != 1 || frames[10].1[69] != 2 {
        return Err("native START_HW_SCAN did not enable two directed probes");
    }
    let before = session.backend.frames.len();
    run(session.scan_passive(&[6])).map_err(|_| "passive continuation after active scan")?;
    if session.backend.frames.len() != before + 1 || session.backend.frames[before].1[66] != 0 {
        return Err("passive continuation repeated setup or retained active probes");
    }
    Ok(())
}
fn mcu_active_scan_native_policy_power_barriers_and_passive_continuation() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_active_scan_native_policy_power_barriers_and_passive_continuation
);

fn invalid() -> Result<(), &'static str> {
    let mut session = ready_radio()?;
    let before = session.backend.frames.len();
    for (channels, ssids) in [
        (vec![6], Vec::new()),
        (vec![6, 6], vec![b"ssid".to_vec()]),
        (vec![0], vec![b"ssid".to_vec()]),
        (vec![6], vec![vec![1; 33]]),
        (vec![6], vec![Vec::new(); 5]),
    ] {
        if run(session.scan_active_with_policy(&channels, &ssids, || Ok(policy()))).err()
            != Some(Error::Bounds)
            || session.backend.frames.len() != before
        {
            return Err("invalid active scan published hardware commands");
        }
    }
    for flags in [RegFlags::DFS, RegFlags::NO_IR] {
        let mut domain = policy();
        // A partial restrictive overlap cannot be bypassed by the wide rule.
        domain.rules.push(RegRule {
            freq_start_mhz: 2435,
            freq_end_mhz: 2439,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags,
        });
        if run(session.scan_active_with_policy(&[6], &[Vec::new()], || Ok(domain.clone()))).err()
            != Some(Error::Authority)
            || session.backend.frames.len() != before
        {
            return Err("restrictive policy overlap was ignored before active TX");
        }
    }
    if run(session.scan_active_with_policy(&[6], &[Vec::new()], || Err(Error::Authority))).err()
        != Some(Error::Authority)
        || session.backend.frames.len() != before
        || !matches!(session.state, State::RadioReady(_))
    {
        return Err("missing policy consumed the parked radio");
    }
    Ok(())
}
fn mcu_active_scan_denied_and_malformed_preflight_has_no_writes() -> TestResult {
    invalid().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_active_scan_denied_and_malformed_preflight_has_no_writes
);

fn changed() -> Result<(), &'static str> {
    for deny_after in [2, 4] {
        let mut session = ready_radio()?;
        let before = session.backend.frames.len();
        let calls = Cell::new(0);
        let error = run(session.scan_active_with_policy(&[6], &[Vec::new()], || {
            let call = calls.get();
            calls.set(call + 1);
            if call >= deny_after {
                Err(Error::Authority)
            } else {
                Ok(policy())
            }
        }))
        .err();
        let frames = &session.backend.frames[before..];
        let starts = frames
            .iter()
            .filter(|(_, f)| f[36] == 3 && f[43] != 7)
            .count();
        if error != Some(Error::Authority)
            || starts != usize::from(deny_after == 4)
            || !frames.iter().any(|(_, frame)| frame[36] == 0x1b)
            || !matches!(
                session.state,
                State::Failed {
                    error: Error::Authority,
                    ..
                }
            )
            || !session.backend.owner.published
        {
            return Err(
                "changed active-scan policy authorized TX/reuse or lost cancellation ownership",
            );
        }
        if run(session.scan_active_with_policy(&[6], &[Vec::new()], || Ok(policy()))).err()
            != Some(Error::Busy)
        {
            return Err("failed active scan reused a stale completion");
        }
    }
    Ok(())
}
fn mcu_active_scan_policy_change_before_probe_and_during_wait_is_terminal() -> TestResult {
    changed().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_active_scan_policy_change_before_probe_and_during_wait_is_terminal
);

fn failed_receipts() -> Result<(), &'static str> {
    for fault in [1, 2, 3] {
        let mut session = ready_radio()?;
        run(session.scan_passive(&[6])).map_err(|_| "PSE fixture passive setup")?;
        session.backend.reg_reply_fault = fault;
        let before = session.backend.frames.len();
        if run(session.scan_active_with_policy(&[6], &[Vec::new()], || Ok(policy()))).err()
            != Some(Error::MalformedEvent)
            || session.backend.frames[before..]
                .iter()
                .any(|(_, frame)| frame[36] == 3)
            || !session.backend.owner.published
        {
            return Err("invalid PSE query response admitted a probe or retired DMA");
        }
    }
    let mut session = ready_radio()?;
    run(session.scan_passive(&[6])).map_err(|_| "revocation fixture passive setup")?;
    session.backend.revoke_on_submit = true;
    let before = session.backend.frames.len();
    if run(session.scan_active_with_policy(&[6], &[Vec::new()], || Ok(policy()))).err()
        != Some(Error::Authority)
        || session.backend.frames[before..]
            .iter()
            .any(|(_, frame)| frame[36] == 3)
        || !session.backend.owner.published
    {
        return Err("revoked hardware authority reached active probe admission");
    }
    Ok(())
}
fn mcu_active_scan_requires_exact_pse_receipt_and_live_hardware_authority() -> TestResult {
    failed_receipts().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_active_scan_requires_exact_pse_receipt_and_live_hardware_authority
);

fn cancelled() -> Result<(), &'static str> {
    for publication in 1..=5 {
        let mut session = ready_radio()?;
        run(session.scan_passive(&[6])).map_err(|_| "cancellation fixture passive setup")?;
        let before = session.backend.frames.len();
        session.backend.tx_stall_after = Some(before + publication);
        let ssids = [Vec::new()];
        {
            let mut future = pin!(session.scan_active_with_policy(&[6], &ssids, || Ok(policy())));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return Err("active scan skipped a held power/PSE/domain/scan/close DMA receipt");
            }
        }
        if !matches!(session.state, State::Running(_))
            || session.backend.frames.len() != before + publication
            || run(session.scan_active_with_policy(&[6], &ssids, || Ok(policy()))).err()
                != Some(Error::Busy)
            || !session.backend.owner.published
        {
            return Err("cancelled active scan prelude/completion replayed from an idle state");
        }
    }
    let mut session = ready_radio()?;
    session.backend.scan_stall = true;
    if run(session.scan_active_with_policy(&[6], &[Vec::new()], || Ok(policy()))).err()
        != Some(Error::Timeout)
        || !session.backend.owner.published
        || !matches!(session.state, State::Failed { .. })
    {
        return Err("active scan timeout lost terminal state or DMA ownership");
    }
    let mut cancelled = ready_radio()?;
    cancelled.backend.scan_stall = true;
    {
        let ssids = [Vec::new()];
        let mut future = pin!(cancelled.scan_active_with_policy(&[6], &ssids, || Ok(policy())));
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("active scan did not await the actual completion");
        }
    }
    if !matches!(cancelled.state, State::Running(Stage::ScanWait))
        || run(cancelled.scan_active_with_policy(&[6], &[Vec::new()], || Ok(policy()))).err()
            != Some(Error::Busy)
        || !cancelled.backend.owner.published
    {
        return Err("cancelled active scan was replayed or released published DMA");
    }
    Ok(())
}
fn mcu_active_scan_timeout_and_dropped_waiter_require_verified_recovery() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/scan",
    mcu_active_scan_timeout_and_dropped_waiter_require_verified_recovery
);
