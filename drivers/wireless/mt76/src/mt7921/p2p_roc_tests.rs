//! Actual CNM MCU events under a registered DOWN P2P wdev grant.
//! RX-only dwell is distinct from active action/probe TX permission.
use super::*;
use crate::mt7921::p2p_cnm::Phase;
#[path = "p2p_cancel_tests.rs"]
mod cancel;

fn started(cnm: bool) -> Result<(NativeSession, Fixture, Arc<RocModel>), &'static str> {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let (mut session, fixture) = device(cnm, 10)?;
    let policy = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: AtomicBool::new(false),
    });
    policy.database.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::NO_IR | RegFlags::DFS | RegFlags::INDOOR_ONLY,
        }],
    });
    session.backend.tx_policy = Some(policy);
    let model = Arc::new(RocModel::default());
    session.backend.roc = Some(model.clone());
    let authority = reserved(&fixture)?;
    run(Box::pin(session.start_p2p_device(authority.clone())))
        .map_err(|_| "actual P2P wdev before ROC")?;
    session
        .commit_p2p_device(&authority)
        .map_err(|_| "actual P2P device publication before ROC")?;
    Ok((session, fixture, model))
}
fn expiry(session: &Session<Model>) -> Result<u64, &'static str> {
    let lease = session
        .p2p_owner
        .as_ref()
        .and_then(|owner| owner.cnm.lease())
        .ok_or("actual retained CNM lease")?;
    match lease.phase {
        Phase::Granted { expires_ns, .. } => Ok(expires_ns),
        _ => Err("no actual native CNM grant"),
    }
}
fn complete() -> Result<(), &'static str> {
    let (mut session, fixture, model) = started(true)?;
    model.hold.store(true, Ordering::Release);
    model.interval_ms.store(250, Ordering::Release);
    model.fault.store(1, Ordering::Release); // late old token, then exact grant
    let authority = reserved(&fixture)?;
    let mut native = Box::pin(session.acquire_p2p_roc(authority.clone(), 71, 2437, 500));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..8192 {
        if native.as_mut().poll(&mut cx).is_ready() {
            return Err("ROC ACK/DMA fabricated an on-channel grant");
        }
        if model.seen.load(Ordering::Acquire) {
            break;
        }
    }
    if !model.seen.load(Ordering::Acquire) || !fixture.source.1.lock().is_empty() {
        return Err("ROC did not retain actual unsolicited grant wait");
    }
    model.hold.store(false, Ordering::Release);
    if run(native) != Ok(250) || session.p2p_roc_current(71, 2437) != Ok(false) {
        return Err("ROC used requested duration or published before terminal commit");
    }
    let receipt = session
        .commit_p2p_roc(&authority)
        .map_err(|_| "actual ROC terminal commit")?;
    if receipt.cookie != 71
        || receipt.frequency_mhz != 2437
        || receipt.duration_ms != 250
        || session.p2p_roc_current(71, 2437) != Ok(true)
        || session.p2p_roc_current(72, 2437) != Ok(false)
        || session.p2p_roc_current(71, 2412) != Ok(false)
        || session.backend.receive_open
        || !session.backend.data_headers.is_empty()
        || !session.backend.management_rates.is_empty()
        || narf_net::iface::lookup(fixture.radio.name())
            .is_none_or(|link| link.link_up || link.carrier)
    {
        return Err("receive-only ROC invented frame/UP/key/port authority");
    }
    drop(authority);
    if run(Box::pin(session.expire_p2p_roc())) != Ok(false) {
        return Err("ROC expired before native grant interval");
    }
    session.backend.ticks.set(expiry(&session)?);
    if run(Box::pin(session.expire_p2p_roc())) != Ok(true)
        || session
            .p2p_owner
            .as_ref()
            .is_none_or(|owner| owner.cnm.pending())
        || session.p2p_roc_current(71, 2437) != Ok(false)
        || !matches!(session.state, State::P2pDevice(_))
    {
        return Err("finite ROC failed native abort/progress and lease retirement");
    }
    let messages = fixture.source.1.lock();
    if messages.len() != 2 || messages[0].get(16) != Some(&55) || messages[1].get(16) != Some(&56) {
        return Err("ROC exact source missed actual ready/expiry or saw duplicate old-token grant");
    }
    Ok(())
}
fn mt76_p2p_roc_requires_actual_unsolicited_grant_and_retains_rx_only_interval() -> TestResult {
    complete().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_requires_actual_unsolicited_grant_and_retains_rx_only_interval
);

fn unsupported_and_malformed() -> Result<(), &'static str> {
    let (mut legacy, fixture, _) = started(false)?;
    let authority = reserved(&fixture)?;
    let before = legacy.backend.frames.len();
    if run(Box::pin(legacy.acquire_p2p_roc(authority, 1, 2437, 500)))
        != Err(Error::UnsupportedFirmware)
        || legacy.backend.frames.len() != before
        || !matches!(legacy.state, State::P2pDevice(_))
    {
        return Err("legacy device BSS incorrectly promoted to optional CNM ROC ABI");
    }
    for fault in [2, 3, 4, 5] {
        let (mut session, fixture, model) = started(true)?;
        model.fault.store(fault, Ordering::Release);
        let authority = reserved(&fixture)?;
        let expected = if fault == 5 {
            Error::Timeout
        } else {
            Error::MalformedEvent
        };
        if run(Box::pin(session.acquire_p2p_roc(authority, 2, 2437, 500))) != Err(expected)
            || session.p2p_owner.is_some()
            || !matches!(session.state, State::RadioReady(_))
            || !fixture.source.1.lock().is_empty()
        {
            return Err("malformed/missing native ROC grant published success or escaped reset");
        }
    }
    Ok(())
}
fn mt76_p2p_roc_legacy_capability_and_malformed_event_never_create_native_grant() -> TestResult {
    unsupported_and_malformed().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_legacy_capability_and_malformed_event_never_create_native_grant
);

fn pending() -> Result<(), &'static str> {
    for failure in 0..4 {
        let (mut session, fixture, model) = started(true)?;
        model.hold.store(true, Ordering::Release);
        let authority = reserved(&fixture)?;
        let policy = session
            .backend
            .tx_policy
            .as_ref()
            .ok_or("actual ROC policy owner")?
            .clone();
        let mut native = Box::pin(session.acquire_p2p_roc(authority, 9, 2437, 500));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..8192 {
            if native.as_mut().poll(&mut cx).is_ready() {
                return Err("pending ROC completed before native grant");
            }
            if model.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !model.seen.load(Ordering::Acquire) {
            return Err("actual ROC grant hold not reached");
        }
        if failure == 0 {
            drop(native);
            if radio(&fixture)
                .and_then(RadioControlAuthority::reserve)
                .err()
                != Some(WirelessError::Busy)
                || session.state != State::Running(Stage::P2pRocAcquire)
                || !session
                    .p2p_owner
                    .as_ref()
                    .is_some_and(|owner| owner.cnm.pending())
            {
                return Err("cancelled ROC waiter released uncertain native command/token");
            }
            model.hold.store(false, Ordering::Release);
            run(Box::pin(session.shutdown())).map_err(|_| "abandoned ROC shutdown")?;
            if session.p2p_owner.is_some()
                || session.state != State::Stopped
                || radio(&fixture)
                    .and_then(RadioControlAuthority::reserve)
                    .is_err()
            {
                return Err("ROC shutdown missed actual reset/terminal reservation release");
            }
        } else {
            match failure {
                1 => fixture.source.0.store(false, Ordering::Release),
                2 => fixture.daemon.revoke(),
                _ => policy.database.clear(),
            }
            if run(native) != Err(Error::Authority)
                || session.p2p_owner.is_some()
                || !matches!(session.state, State::RadioReady(_))
                || !fixture.source.1.lock().is_empty()
            {
                return Err("ROC pending native wait ignored current source/grant/RF policy");
            }
        }
    }
    Ok(())
}
fn mt76_p2p_roc_cancel_close_revoke_and_policy_loss_retire_native_owner() -> TestResult {
    pending().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_cancel_close_revoke_and_policy_loss_retire_native_owner
);

fn completed_source() -> Result<(), &'static str> {
    for loss in 0..3 {
        let (mut session, fixture, _) = started(true)?;
        let authority = reserved(&fixture)?;
        run(Box::pin(session.acquire_p2p_roc(
            authority.clone(),
            2,
            2437,
            500,
        )))
        .map_err(|_| "ROC before completed-source/policy/identity loss")?;
        session
            .commit_p2p_roc(&authority)
            .map_err(|_| "ROC publication before completed-source loss")?;
        drop(authority);
        match loss {
            0 => fixture.source.0.store(false, Ordering::Release),
            1 => session
                .backend
                .tx_policy
                .as_ref()
                .ok_or("actual ROC policy")?
                .database
                .clear(),
            _ => fixture
                .admin
                .move_to_net_ns(0x7627)
                .map_err(|_| "actual completed ROC namespace transfer")?,
        }
        if session.p2p_roc_current(2, 2437).unwrap_or(false)
            || run(Box::pin(session.expire_p2p_roc())) != Ok(true)
            || session.p2p_owner.is_some()
            || !matches!(session.state, State::RadioReady(_))
            || fixture.source.1.lock().len() != if loss == 1 { 2 } else { 1 }
        {
            return Err("completed ROC loss retained RF use, retargeted events or bypassed native retirement");
        }
    }
    Ok(())
}
fn mt76_p2p_roc_completed_source_closure_fences_use_and_resets_before_reuse() -> TestResult {
    completed_source().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_completed_source_closure_fences_use_and_resets_before_reuse
);

fn token_reuse() -> Result<(), &'static str> {
    let (mut session, fixture, model) = started(true)?;
    let before = session
        .backend
        .recovery_trace
        .iter()
        .filter(|(stage, _)| *stage == "assert")
        .count();
    for cookie in 1..=512 {
        model.fault.store(1, Ordering::Release); // foreign old grant precedes exact current terminal
        let authority = reserved(&fixture)?;
        run(Box::pin(session.acquire_p2p_roc(
            authority.clone(),
            cookie,
            2437,
            50,
        )))
        .map_err(|_| "ROC failed source-correct successful opaque token reuse")?;
        session
            .commit_p2p_roc(&authority)
            .map_err(|_| "actual ROC publication across successful token reuse")?;
        drop(authority);
        session.backend.ticks.set(expiry(&session)?);
        if run(Box::pin(session.expire_p2p_roc())) != Ok(true) {
            return Err("actual ROC finite expiry before token reuse");
        }
    }
    let after = session
        .backend
        .recovery_trace
        .iter()
        .filter(|(stage, _)| *stage == "assert")
        .count();
    if after != before
        || !matches!(session.state, State::P2pDevice(_))
        || session
            .p2p_owner
            .as_ref()
            .is_none_or(|owner| !owner.activated || owner.cnm.pending())
    {
        return Err(
            "successful terminal ROC reuse reset the physical radio or lost native wdev ownership",
        );
    }
    Ok(())
}
fn mt76_p2p_roc_successful_terminal_token_reuse_never_periodically_resets_the_radio() -> TestResult
{
    token_reuse().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_successful_terminal_token_reuse_never_periodically_resets_the_radio
);
