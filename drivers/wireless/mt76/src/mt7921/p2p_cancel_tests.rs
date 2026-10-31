//! Exact-cookie cancel is terminal only after real native retirement and
//! DEV/BSS reinitialization, with the same current request throughout.
use super::*;
fn native() -> Result<(), &'static str> {
    let (mut session, fixture, _) = started(true)?;
    let first = reserved(&fixture)?;
    run(Box::pin(session.acquire_p2p_roc(
        first.clone(),
        31,
        2437,
        500,
    )))
    .map_err(|_| "actual ROC before cancel")?;
    session
        .commit_p2p_roc(&first)
        .map_err(|_| "actual ready before cancel")?;
    drop(first);
    let authority = reserved(&fixture)?;
    let frames = session.backend.frames.len();
    if run(Box::pin(session.cancel_p2p_roc(authority.clone(), 99))) != Err(Error::Bounds)
        || session.backend.frames.len() != frames
        || session.p2p_roc_current(31, 2437) != Ok(true)
    {
        return Err("foreign ROC cookie changed native channel owner");
    }
    let resets = session
        .backend
        .recovery_trace
        .iter()
        .filter(|(stage, _)| *stage == "assert")
        .count();
    run(Box::pin(session.cancel_p2p_roc(authority, 31)))
        .map_err(|_| "native cancel terminal reset/rebuild")?;
    if !matches!(session.state, State::P2pDevice(_))
        || session.p2p_roc_current(31, 2437) != Ok(false)
        || session
            .p2p_owner
            .as_ref()
            .is_none_or(|owner| !owner.activated || owner.cnm.pending())
        || session
            .backend
            .recovery_trace
            .iter()
            .filter(|(stage, _)| *stage == "assert")
            .count()
            <= resets
    {
        return Err("ROC cancel completed from abort progress without real native wdev retirement");
    }
    let messages = fixture.source.1.lock();
    if messages.len() != 2 || messages[0].get(16) != Some(&55) || messages[1].get(16) != Some(&56) {
        return Err("native cancel missed exact owned ready/terminal expiry pairing");
    }
    Ok(())
}
fn mt76_p2p_roc_cancel_exact_cookie_requires_real_reset_and_started_wdev_rebuild() -> TestResult {
    native().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_cancel_exact_cookie_requires_real_reset_and_started_wdev_rebuild
);
fn pending() -> Result<(), &'static str> {
    for failure in 0..3 {
        let (mut session, fixture, _) = started(true)?;
        let first = reserved(&fixture)?;
        run(Box::pin(session.acquire_p2p_roc(
            first.clone(),
            31,
            2437,
            500,
        )))
        .map_err(|_| "native ROC before pending cancel")?;
        session
            .commit_p2p_roc(&first)
            .map_err(|_| "actual native ROC before pending cancel")?;
        drop(first);
        let authority = reserved(&fixture)?;
        let hold = Arc::new(Hold::default());
        session.backend.p2p_hold = Some(hold.clone());
        let mut native = Box::pin(session.cancel_p2p_roc(authority, 31));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..8192 {
            if native.as_mut().poll(&mut cx).is_ready() {
                return Err("ROC cancel ACKed while old BSS retirement remained pending");
            }
            if hold.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !hold.seen.load(Ordering::Acquire) {
            return Err("native cancel did not reach owned BSS stop receipt");
        }
        if failure == 0 {
            drop(native);
            if radio(&fixture)
                .and_then(RadioControlAuthority::reserve)
                .err()
                != Some(WirelessError::Busy)
                || session.p2p_roc_current(31, 2437) != Ok(false)
            {
                return Err(
                    "cancelled ROC cancel waiter released native owner or reopened channel use",
                );
            }
            hold.release.store(true, Ordering::Release);
            run(Box::pin(session.shutdown())).map_err(|_| "native pending cancel shutdown")?;
            if session.p2p_owner.is_some()
                || session.state != State::Stopped
                || radio(&fixture)
                    .and_then(RadioControlAuthority::reserve)
                    .is_err()
            {
                return Err("cancelled ROC stop did not retain ownership through verified reset");
            }
        } else {
            if failure == 1 {
                fixture.source.0.store(false, Ordering::Release);
            } else {
                fixture.daemon.revoke();
            }
            hold.release.store(true, Ordering::Release);
            if run(native) != Err(Error::Authority)
                || session.p2p_owner.is_some()
                || !matches!(session.state, State::RadioReady(_))
                || fixture.source.1.lock().len() != 1
            {
                return Err(
                    "ROC cancel reused revoked source or published a replacement wdev/event",
                );
            }
        }
    }
    Ok(())
}
fn mt76_p2p_roc_cancel_drop_close_and_revoke_keep_old_owner_until_native_retirement() -> TestResult
{
    pending().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_cancel_drop_close_and_revoke_keep_old_owner_until_native_retirement
);
