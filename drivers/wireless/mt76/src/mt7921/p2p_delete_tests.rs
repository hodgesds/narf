//! Actual native BSS stop/WTBL receipt before exact control withdrawal.
use super::*;
fn held() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    execute(&mut session, &concrete, P2pRequest::Start).map_err(|_| "native START before DEL")?;
    let admin = concrete
        .source
        .control_admin(concrete.child.name(), 0)
        .ok_or("actual live child admin")?;
    let wdev = narf_wireless::registry::control_for(concrete.child.as_ref())
        .ok_or("actual WDEV before native DEL")?;
    let authority = concrete.authority()?;
    let hold = Arc::new(Hold::default());
    session.backend.p2p_hold = Some(hold.clone());
    let before = session.backend.frames.len();
    // Use the actual generic retained owner. Its native future can finish
    // while BOOT_OWNER's equivalent publication mutex remains unavailable.
    let result = Arc::new(IrqSafeSpinLock::new(None));
    let target = result.clone();
    let iface = Arc::downgrade(&concrete.child);
    let original = authority.clone();
    let expected_mac = concrete.binding.iface.mac();
    let owner = narf_lib::mutex::Mutex::new(None::<NativeSession>);
    let publication_hold = owner
        .try_lock()
        .ok_or("actual retained owner handoff gate")?;
    let mut owned = KeyWork {
        future: Some(Box::pin(async move {
            let completed = boot_p2p::delete_session(
                &mut session,
                iface,
                authority,
                Arc::new(AtomicBool::new(true)),
                expected_mac,
            )
            .await;
            let status = completed.as_ref().map(|_| ()).map_err(|error| *error);
            *target.lock() = Some(completed);
            (session, status)
        })),
        completed: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if owned.poll(&mut cx).is_ready() {
            return Err("DEL completed without actual BSS stop receipt");
        }
        if hold.seen.load(Ordering::Acquire) {
            break;
        }
    }
    if !hold.seen.load(Ordering::Acquire)
        || admin.authorize_interface(concrete.child.name(), 0).is_err()
        || narf_wireless::registry::control_by_id(wdev.id(), 0).is_none()
    {
        return Err("pending native DEL withdrew its current registration or missed BSS ACK");
    }
    hold.release.store(true, Ordering::Release);
    run(core::future::poll_fn(|cx| owned.poll(cx)));
    if owner.try_lock().is_some() || owned.completed.is_none() || original.current().is_ok() {
        return Err("retained native completion bypassed the busy publication gate or revived normal authority");
    }
    let retired = result
        .lock()
        .take()
        .ok_or("actual retained terminal result while owner publication remains pending")?
        .map_err(|_| "actual stop/WTBL progress and retirement receipt")?;
    if !retired.current() || owned.poll(&mut cx).is_pending() {
        return Err("pending owner republication lost or replaced the native retirement receipt");
    }
    drop(original);
    drop(publication_hold);
    let (session, status) = owned
        .completed
        .take()
        .ok_or("actual completed owner handoff")?;
    status.map_err(|_| "actual native DEL status at owner republication")?;
    *owner
        .try_lock()
        .ok_or("terminal owner publication after gate release")? = Some(session);
    let session = owner
        .try_lock()
        .ok_or("actual republished owner read")?
        .take()
        .ok_or("actual republished native Session")?;
    if !retired.current()
        || admin.check_live().is_ok()
        || concrete.child.started_current()
        || session.p2p_owner.is_some()
        || !matches!(session.state, State::RadioReady(_))
        || narf_wireless::registry::control_by_id(wdev.id(), 0).is_some()
        || !session.backend.frames[before..]
            .iter()
            .filter_map(|(_, frame)| uni(frame, 2))
            .any(|body| {
                body.len() == 36
                    && body[0] == 1
                    && body[8] == 0
                    && body[24..26] == 18u16.to_le_bytes()
            })
        || session.backend.wtbl_clears.last() != Some(&18)
    {
        return Err(
            "DEL invented retirement, disabled home BSS or restored live child administration",
        );
    }
    let parent: Arc<dyn WirelessNetIface> = concrete.binding.iface.clone();
    let index = narf_net::iface::lookup(parent.name())
        .ok_or("actual parent during terminal ACK")?
        .ifindex;
    if RadioControlAuthority::bind(
        concrete.binding.admin.clone(),
        &parent,
        0,
        index,
        concrete.source.clone(),
    )
    .and_then(RadioControlAuthority::reserve)
    .err()
        != Some(WirelessError::Busy)
    {
        return Err("hidden terminal receipt released the native/interface serialization early");
    }
    drop(retired);
    if narf_wireless::registry::control_for(concrete.child.as_ref()).is_some()
        || concrete
            .source
            .control_admin(concrete.child.name(), 0)
            .is_some()
    {
        return Err("terminal retirement retained old metadata/admin");
    }
    let create = RadioControlAuthority::bind(
        concrete.binding.admin.clone(),
        &parent,
        0,
        index,
        concrete.source.clone(),
    )
    .and_then(RadioControlAuthority::reserve)
    .map_err(|_| "fresh parent after terminal ACK")?;
    let successor = concrete
        .binding
        .iface
        .create_p2p_device(
            &create,
            &narf_net::bootstrap_authority(),
            0,
            concrete.child.name(),
            None,
        )
        .map_err(|_| "same-name child after actual complete native DEL")?;
    let next =
        narf_wireless::registry::control_for(successor.as_ref()).ok_or("fresh successor WDEV")?;
    if next == wdev
        || admin.authorize_interface(successor.name(), 0).is_ok()
        || successor.started_current()
    {
        return Err("retired child identity/grant/native started state retargeted successor");
    }
    successor.release_retired_metadata();
    Ok(())
}
fn mt76_p2p_delete_keeps_current_metadata_until_native_stop_then_exact_terminal_retirement(
) -> TestResult {
    held().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_delete_keeps_current_metadata_until_native_stop_then_exact_terminal_retirement
);

fn cancelled() -> Result<(), &'static str> {
    for cause in 0..2 {
        let (mut session, concrete) = setup()?;
        execute(&mut session, &concrete, P2pRequest::Start)
            .map_err(|_| "native START before lost DEL caller")?;
        let authority = concrete.authority()?;
        let alive = Arc::new(AtomicBool::new(true));
        let hold = Arc::new(Hold::default());
        session.backend.p2p_hold = Some(hold.clone());
        let mut owned = Box::pin(boot_p2p::delete_session(
            &mut session,
            Arc::downgrade(&concrete.child),
            authority,
            alive.clone(),
            concrete.binding.iface.mac(),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if owned.as_mut().poll(&mut cx).is_ready() {
                return Err("lost-caller DEL skipped held native stop");
            }
            if hold.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !hold.seen.load(Ordering::Acquire) {
            return Err("lost-caller DEL never entered native stop receipt wait");
        }
        if cause == 0 {
            alive.store(false, Ordering::Release);
        } else {
            concrete.source.live.store(false, Ordering::Release);
        }
        hold.release.store(true, Ordering::Release);
        let result = run(owned);
        if !matches!(result, Err(Error::Cancelled | Error::Authority))
            || session.p2p_owner.is_some()
            || !matches!(session.state, State::RadioReady(_))
            || concrete.child.started_current()
            || narf_wireless::registry::control_for(concrete.child.as_ref()).is_some()
            || session
                .backend
                .recovery_trace
                .iter()
                .all(|(stage, _)| *stage != "assert")
        {
            return Err(
                "cancelled/closed DEL dropped uncertain native ownership or stranded its metadata",
            );
        }
    }
    Ok(())
}
fn mt76_p2p_delete_lost_waiter_or_socket_keeps_owned_native_cleanup_through_verified_reset(
) -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_delete_lost_waiter_or_socket_keeps_owned_native_cleanup_through_verified_reset
);

fn idle() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    let count = session.backend.frames.len();
    let authority = concrete.authority()?;
    let retired = run(Box::pin(boot_p2p::delete_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        authority,
        Arc::new(AtomicBool::new(true)),
        concrete.binding.iface.mac(),
    )))
    .map_err(|_| "never-started actual metadata DEL")?;
    if !retired.current()
        || session.backend.frames.len() != count
        || session.p2p_owner.is_some()
        || concrete.child.started_current()
        || narf_wireless::registry::control_by_id(
            narf_wireless::registry::control_for(concrete.child.as_ref())
                .ok_or("hidden exact idle WDEV")?
                .id(),
            0,
        )
        .is_some()
    {
        return Err(
            "idle DEL manufactured native START/stop or left an externally selectable WDEV",
        );
    }
    drop(retired);
    if narf_wireless::registry::control_for(concrete.child.as_ref()).is_some() {
        return Err("idle exact retirement did not finish metadata release");
    }
    Ok(())
}
fn mt76_p2p_never_started_delete_needs_no_invented_native_or_up_receipt() -> TestResult {
    idle().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_never_started_delete_needs_no_invented_native_or_up_receipt
);
