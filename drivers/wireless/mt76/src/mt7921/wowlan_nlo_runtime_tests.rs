//! Genuine station/unassociated NLO handoffs and current RF-policy refusal.
use super::*;
use narf_wireless::{NetDetectConfig, NetDetectMatch, NetDetectScanPlan, ScanRandomMac};

fn config(active: bool) -> WowlanConfig {
    WowlanConfig {
        net_detect: Some(NetDetectConfig {
            probe_ssids: if active {
                vec![b"narf".to_vec()]
            } else {
                Vec::new()
            },
            frequencies_mhz: vec![2412, 5180],
            probe_ies: vec![221, 3, 0x12, 0x34, 0x56],
            matches: vec![NetDetectMatch {
                ssid: b"narf".to_vec(),
                rssi_threshold_dbm: Some(-65),
            }],
            plans: vec![NetDetectScanPlan {
                interval_secs: 30,
                iterations: None,
            }],
            delay_secs: 3,
            random_mac: Some(ScanRandomMac {
                addr: [2, 0xaa, 0, 0, 0, 0],
                mask: [255, 255, 0, 0, 0, 0],
            }),
        }),
        ..WowlanConfig::default()
    }
}

fn policy(power: i8) -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2472,
                max_bandwidth_mhz: 40,
                max_power_dbm: power,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5895,
                max_bandwidth_mhz: 40,
                max_power_dbm: power,
                flags: RegFlags::empty(),
            },
        ],
    }
}

fn current() -> Arc<CurrentPolicy> {
    let current = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: AtomicBool::new(false),
    });
    current.database.install(policy(17));
    current
}

fn radio(associated: bool, secure: bool) -> Result<Session<Model>, &'static str> {
    let mut session = if associated {
        joined(secure)?
    } else {
        let mut session = Session::new(Model::new(), firmware(32));
        run(session.run()).map_err(|_| "NLO firmware fixture")?;
        run(session.initialize_radio()).map_err(|_| "NLO actual radio identity")?;
        session.backend.pm.dma_enabled = true;
        session
    };
    session.backend.pm.wow.route_available = true;
    session.backend.tx_policy = Some(current());
    Ok(session)
}

fn ce(frame: &[u8], id: u8) -> Option<&[u8]> {
    (frame.len() > 64 && frame[43] != 7 && frame[36] == id).then(|| &frame[64..])
}

fn handoffs() -> Result<(), &'static str> {
    for associated in [false, true] {
        for secure in [false, true] {
            for active in [false, true] {
                let mut session = radio(associated, secure)?;
                let start = session.backend.frames.len();
                run(Box::pin(
                    session.suspend_wowlan(&config(active), SystemSleepState::S0Idle),
                ))
                .map_err(|_| "native associated/unassociated NLO handoff")?;
                let State::WowSuspended {
                    info, association, ..
                } = session.state
                else {
                    return Err("NLO did not retain its suspended owner");
                };
                let frames = &session.backend.frames[start..];
                let request = frames
                    .iter()
                    .position(|(_, frame)| ce(frame, 0x62).is_some())
                    .ok_or("NLO request absent")?;
                let enable = frames
                    .iter()
                    .position(|(_, frame)| ce(frame, 0x61) == Some(&[0, 0, 0, 0][..]))
                    .ok_or("NLO enable absent")?;
                let control = frames
                    .iter()
                    .position(|(_, frame)| {
                        uni(frame, 5)
                            .is_some_and(|body| body.len() == 32 && body[8..11] == [1, 0x20, 2])
                    })
                    .ok_or("NLO wake trigger absent")?;
                let hif = frames
                    .iter()
                    .position(|(_, frame)| uni(frame, 7).is_some())
                    .ok_or("NLO HIF receipt absent")?;
                let body = ce(&frames[request].1, 0x62).ok_or("NLO native body")?;
                if !(request < enable && enable < control && control < hif)
                    || body.len() != 1229
                    || body[3] != u8::from(active)
                    || body[4] != 1
                    || body[368..372] != (-65i32).to_le_bytes()
                    || body[1008..1016] != [4, 2, 1, 1, 1, 1, 2, 36]
                    || body[1140..1142] != [30, 0]
                    || body[1164..1168] != [3, 0, 0, 0]
                    || body[1180..1186] != [2, 0xaa, 0x73, 0x73, 0x73, 0x73]
                    || body[1224..] != [221, 3, 0x12, 0x34, 0x56]
                    || association.is_some() != associated
                    || session.backend.receive_open
                    || !session.backend.pm.wow.armed
                    || frames.iter().any(|(_, frame)| ce(frame, 3).is_some())
                {
                    return Err(
                        "NLO lost source fields/order, fabricated a peer/scan or opened host RX",
                    );
                }
                let domain = frames
                    .iter()
                    .filter_map(|(_, frame)| ce(frame, 0x0f))
                    .next_back()
                    .ok_or("NLO domain absent")?;
                for entry in domain[12..].chunks_exact(8) {
                    let flags = u32::from_le_bytes(entry[4..8].try_into().unwrap());
                    if !active && !associated && flags & 2 == 0 {
                        return Err(
                            "passive unassociated NLO obtained active radiation permission",
                        );
                    }
                }
                run(Box::pin(session.resume_wowlan(info.capabilities.mac)))
                    .map_err(|_| "NLO D0/reset resume")?;
                if session.state != State::RadioReady(info)
                    || session.wow_nlo.is_some()
                    || session.security.is_some()
                    || session.backend.pm.wow.armed
                {
                    return Err("NLO resume reused an old peer/key/scan owner");
                }
            }
        }
    }
    Ok(())
}

fn mt76_native_nlo_uses_real_associated_or_unassociated_owner_and_ordered_commands() -> TestResult {
    handoffs().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wowlan",
    mt76_native_nlo_uses_real_associated_or_unassociated_owner_and_ordered_commands
);

fn revoked_policy() -> Result<(), &'static str> {
    let mut session = radio(false, false)?;
    let current = session
        .backend
        .tx_policy
        .as_ref()
        .ok_or("NLO current policy")?
        .clone();
    let hold = session.backend.pm.wow.hold_offload_ack.clone();
    hold.store(true, Ordering::Release);
    let configuration = config(true);
    let result = {
        let mut future = Box::pin(session.suspend_wowlan(&configuration, SystemSleepState::S0Idle));
        let mut context = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut context).is_ready() {
            return Err("NLO offload ACK was not held");
        }
        current.database.install(policy(9));
        hold.store(false, Ordering::Release);
        run(future)
    };
    if result != Err(Error::Authority)
        || session
            .backend
            .frames
            .iter()
            .any(|(_, frame)| ce(frame, 0x62).is_some() || ce(frame, 0x61).is_some())
        || session.backend.pm.trace.contains(&"pme-arm")
        || session.backend.receive_open
        || !matches!(session.state, State::RadioReady(_))
        || session.wow_nlo.is_some()
    {
        return Err("a lower current RF policy survived a held native command into autonomous NLO");
    }
    Ok(())
}

fn mt76_nlo_refuses_policy_replacement_across_native_ack_wait_before_autonomous_scan() -> TestResult
{
    revoked_policy().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wowlan",
    mt76_nlo_refuses_policy_replacement_across_native_ack_wait_before_autonomous_scan
);
