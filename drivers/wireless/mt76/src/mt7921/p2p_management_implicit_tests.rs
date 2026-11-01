//! Concrete FRAME owner obtains real private CNM grants and retires them.
use super::*;

fn started(secure: Option<bool>) -> Result<(NativeSession, Concrete), &'static str> {
    let (mut session, concrete) = setup()?;
    if let Some(secure) = secure {
        join_home(&mut session, &concrete, secure)?;
    } else {
        session
            .backend
            .tx_policy
            .as_ref()
            .unwrap()
            .database
            .install(active_policy());
    }
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "actual independent device before implicit FRAME")?;
    Ok((session, concrete))
}
fn no_public_roc(concrete: &Concrete) -> bool {
    !concrete
        .source
        .messages
        .lock()
        .iter()
        .any(|message| matches!(message.get(16), Some(55 | 56)))
}
fn held_grant(operation: &mut Operation<'_>, model: &RocModel) -> Result<(), &'static str> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..256 {
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("implicit FRAME completed before actual unsolicited CNM grant");
        }
        if model.seen.load(Ordering::Acquire) {
            return Ok(());
        }
    }
    Err("implicit native acquisition grant hold not reached")
}
fn granted_and_terminal() -> Result<(), &'static str> {
    for secure in [None, Some(false), Some(true)] {
        for shorter in [false, true] {
            let (mut session, concrete) = started(secure)?;
            boot_p2p::management::register_session(
                &mut session,
                Arc::downgrade(&concrete.child),
                concrete.authority()?,
                0xd0,
                &[4, 9],
                concrete.binding.iface.mac(),
            )
            .map_err(|_| "actual private FRAME response subscription")?;
            // Inert hardware-model clock: a real10ms zero-wait grant must
            // leave enough polls to observe independent TXS/packet edges.
            session.backend.tick_step_ns = 1_000;
            let model = session.backend.roc.as_ref().unwrap().clone();
            model.hold.store(true, Ordering::Release);
            if shorter {
                model.interval_ms.store(2, Ordering::Release);
            }
            let home = session.state;
            let epoch = session.receive_epoch;
            let began = session.backend.ticks.get();
            let resets = session.backend.recovery_trace.len();
            let first_command = session.backend.frames.len();
            let observer = Arc::new(Observer::default());
            session.backend.p2p_tx = Some(observer.clone());
            let mut request = request(&concrete, false);
            if shorter {
                request.duration = 100;
            }
            request.no_cck = shorter;
            let mut operation = tx(
                &mut session,
                &concrete,
                request,
                Arc::new(AtomicBool::new(true)),
            )?;
            held_grant(&mut operation, &model)?;
            if !observer.published.lock().is_empty()
                || !no_public_roc(&concrete)
                || concrete.authority().is_ok()
            {
                return Err("acquire publication/ACK invented RF grant, public ROC event or released FRAME owner");
            }
            model.hold.store(false, Ordering::Release);
            let pid = published(&mut operation, &observer)?;
            let rate = observer
                .published
                .lock()
                .last()
                .map(|(header, _)| u32::from_le_bytes(header[24..28].try_into().unwrap()))
                .ok_or("actual private FRAME fixed-rate descriptor")?;
            if rate != if shorter { 0x004b0004 } else { 4 } {
                return Err(
                    "private2.4GHz FRAME ignored NO_CCK OFDM6 or changed unflagged1Mbps fallback",
                );
            }
            observer.reports.lock().push_back(report(pid, !shorter));
            observer.terminal.store(true, Ordering::Release);
            let mut response = vec![0; 30];
            response[0] = 0xd0;
            response[4..10].copy_from_slice(&concrete.child.mac());
            response[10..16].copy_from_slice(&[2, 0, 0, 0, 0x79, 9]);
            response[16..22].fill(0xff);
            response[24..].copy_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9]);
            let mut descriptor = vec![0; 32 + response.len()];
            descriptor[..4].copy_from_slice(&(2u32 << 27 | 62).to_le_bytes());
            descriptor[4..8].copy_from_slice(&(1u32 << 13 | 0x3ff).to_le_bytes());
            descriptor[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
            descriptor[12..16].copy_from_slice(&(1u32 << 8 | 1 << 16).to_le_bytes());
            descriptor[28..32].copy_from_slice(&0x6464u32.to_le_bytes());
            descriptor[32..].copy_from_slice(&response);
            observer.received.lock().push_back(descriptor);
            let mut cx = Context::from_waker(Waker::noop());
            if operation.as_mut().poll(&mut cx).is_ready() || concrete.authority().is_ok() {
                return Err(
                    "packet ACK released private CNM ownership before finite lease retirement",
                );
            }
            if !concrete.source.messages.lock().iter().any(|message| {
                message.get(16) == Some(&59)
                    && message
                        .windows(response.len())
                        .any(|bytes| bytes == response)
            }) {
                return Err("private FRAME aborted or closed native response capture at TXS before finite wait expired");
            }
            if run(operation) != Ok(!shorter) {
                return Err("private native lease lost actual positive/negative ACK");
            }
            let interval = if shorter { 2_000_000 } else { 10_000_000 };
            let preserved = secure.map_or(session.state == home, |secure| {
                home_current(&session, home, epoch, secure)
            });
            if !preserved
                || session.receive_epoch != epoch
                || session.p2p_rf_busy()
                || session.backend.ticks.get() < began + interval
                || shorter && session.backend.ticks.get() >= began + 100_000_000
                || session.backend.recovery_trace.len() != resets
                || !no_public_roc(&concrete)
                || concrete.authority().is_err()
                || session.p2p_owner.as_ref().is_none_or(|owner| {
                    owner.management.implicit.is_some()
                        || owner.management.tx.is_some()
                        || owner.management.worker_cleanup.is_some()
                        || owner.pending.is_some()
                })
            {
                return Err("private FRAME altered home/keys/capture or failed exact native interval/owner retirement");
            }
            let frames = &session.backend.frames[first_command..];
            let acquired = frames
                .iter()
                .find(|(_, frame)| frame.len() == 76 && frame[34..36] == [0x27, 0])
                .ok_or("actual private native acquisition bytes")?;
            let aborted = frames
                .iter()
                .find(|(_, frame)| frame.len() == 64 && frame[34..36] == [0x27, 0])
                .ok_or("exact private native abort bytes")?;
            if acquired.1[56] != 1
                || acquired.1[67] != 1
                || acquired.1[57] != aborted.1[57]
                || aborted.1[56] != 1
                || u32::from_le_bytes(acquired.1[68..72].try_into().unwrap())
                    != if shorter { 100 } else { 10 }
            {
                return Err(
                    "implicit FRAME changed native BSS/token/ROC-kind or zero-wait interval ABI",
                );
            }
            if let Some(secure) = secure {
                run(Box::pin(session.send_ethernet(&ethernet(0x66))))
                    .map_err(|_| "same home station resumes after private FRAME retirement")?;
                if session.backend.data_protection.last() != Some(&secure) {
                    return Err("private FRAME changed original home controlled-port protection");
                }
            }
        }
    }
    Ok(())
}
fn mt76_p2p_frame_acquires_real_private_roc_and_retires_exact_finite_native_owner() -> TestResult {
    granted_and_terminal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_frame_acquires_real_private_roc_and_retires_exact_finite_native_owner
);

fn pending_grant_loss() -> Result<(), &'static str> {
    for cause in 0..7 {
        let (mut session, concrete) = started(Some(true))?;
        let model = session.backend.roc.as_ref().unwrap().clone();
        let policy = session.backend.tx_policy.as_ref().unwrap().clone();
        let resets = session.backend.recovery_trace.len();
        let observer = Arc::new(Observer::default());
        session.backend.p2p_tx = Some(observer.clone());
        let alive = Arc::new(AtomicBool::new(true));
        if cause < 4 {
            model.hold.store(true, Ordering::Release);
        } else {
            model.fault.store(
                if cause == 4 {
                    5
                } else if cause == 5 {
                    2
                } else {
                    4
                },
                Ordering::Release,
            );
        }
        let mut request = request(&concrete, false);
        request.duration = 500;
        let mut operation = tx(&mut session, &concrete, request, alive.clone())?;
        if cause < 4 {
            held_grant(&mut operation, &model)?;
            match cause {
                0 => alive.store(false, Ordering::Release),
                1 => concrete.source.live.store(false, Ordering::Release),
                2 => concrete.binding.daemon.revoke(),
                _ => {
                    let mut domain = active_policy();
                    domain.rules[0].flags = narf_wireless::reg::RegFlags::NO_P2P;
                    policy.database.install(domain);
                }
            }
        }
        if run(operation).is_ok()
            || !observer.published.lock().is_empty()
            || !no_public_roc(&concrete)
            || session.p2p_owner.is_some()
            || concrete.child.started_current()
            || !matches!(session.state, State::RadioReady(_))
            || session.backend.recovery_trace.len() <= resets
        {
            return Err("lost/missing/malformed private CNM grant transmitted or escaped actual reset/retirement");
        }
    }
    Ok(())
}
fn mt76_p2p_private_frame_never_transmits_on_missing_grant_or_lost_source_policy() -> TestResult {
    pending_grant_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_private_frame_never_transmits_on_missing_grant_or_lost_source_policy
);

fn terminal_cleanup_loss() -> Result<(), &'static str> {
    for source_loss in [false, true] {
        let (mut session, concrete) = started(Some(true))?;
        boot_p2p::management::register_session(
            &mut session,
            Arc::downgrade(&concrete.child),
            concrete.authority()?,
            0xd0,
            &[4, 9],
            concrete.binding.iface.mac(),
        )
        .map_err(|_| "actual source-bound tail response subscription")?;
        session.backend.tick_step_ns = 1_000;
        let home = session.state;
        let epoch = session.receive_epoch;
        let resets = session.backend.recovery_trace.len();
        let began = session.backend.ticks.get();
        let observer = Arc::new(Observer::default());
        session.backend.p2p_tx = Some(observer.clone());
        let alive = Arc::new(AtomicBool::new(true));
        let mut operation = tx(
            &mut session,
            &concrete,
            request(&concrete, false),
            alive.clone(),
        )?;
        let pid = published(&mut operation, &observer)?;
        observer.reports.lock().push_back(report(pid, true));
        observer.terminal.store(true, Ordering::Release);
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("private native lease cleanup was not retained after packet terminal");
        }
        if source_loss {
            concrete.source.live.store(false, Ordering::Release);
        } else {
            alive.store(false, Ordering::Release);
        }
        // Inject only after the terminal tail has begun and its borrower or
        // source has disappeared. A live independent subscription can still
        // receive; a revoked source must never inherit this later raw copy.
        let mut response = vec![0; 30];
        response[0] = 0xd0;
        response[4..10].copy_from_slice(&concrete.child.mac());
        response[10..16].copy_from_slice(&[2, 0, 0, 0, 0x79, 9]);
        response[16..22].fill(0xff);
        response[24..].copy_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9]);
        let mut descriptor = vec![0; 32 + response.len()];
        descriptor[..4].copy_from_slice(&(2u32 << 27 | 62).to_le_bytes());
        descriptor[4..8].copy_from_slice(&(1u32 << 13 | 0x3ff).to_le_bytes());
        descriptor[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
        descriptor[12..16].copy_from_slice(&(1u32 << 8 | 1 << 16).to_le_bytes());
        descriptor[28..32].copy_from_slice(&0x6464u32.to_le_bytes());
        descriptor[32..].copy_from_slice(&response);
        observer.received.lock().push_back(descriptor);
        if run(operation).is_ok()
            || !home_current(&session, home, epoch, true)
            || session.backend.ticks.get() < began + 10_000_000
            || session.p2p_rf_busy()
            || session.backend.recovery_trace.len() != resets
            || !no_public_roc(&concrete)
        {
            return Err("lost borrower dropped finite native cleanup, reset healthy home or published stale ACK");
        }
        let responses = concrete
            .source
            .messages
            .lock()
            .iter()
            .filter(|message| {
                message.get(16) == Some(&59)
                    && message
                        .windows(response.len())
                        .any(|bytes| bytes == response)
            })
            .count();
        if responses != usize::from(!source_loss) {
            return Err("tail raw response reached a revoked source or lost its still-live independent subscription");
        }
    }
    Ok(())
}
fn mt76_p2p_private_frame_keeps_finite_cleanup_after_packet_terminal_and_borrower_loss(
) -> TestResult {
    terminal_cleanup_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_private_frame_keeps_finite_cleanup_after_packet_terminal_and_borrower_loss
);

fn admission_and_packet_loss() -> Result<(), &'static str> {
    let (mut session, concrete) = started(None)?;
    let policy = session.backend.tx_policy.as_ref().unwrap().clone();
    for cause in 0..7 {
        policy.database.install(active_policy());
        let mut request = request(&concrete, false);
        match cause {
            0 => request.frequency_mhz = 0,
            1 => request.offchannel_ok = false,
            2 => request.duration = 5001,
            3 => request.frame[10] ^= 4,
            4 => request.frame[1] |= 0x40,
            _ => {
                let mut domain = active_policy();
                domain.rules[0].flags = if cause == 5 {
                    narf_wireless::reg::RegFlags::NO_IR
                } else {
                    narf_wireless::reg::RegFlags::NO_P2P
                };
                policy.database.install(domain);
            }
        }
        let count = session.backend.frames.len();
        if run(tx(
            &mut session,
            &concrete,
            request,
            Arc::new(AtomicBool::new(true)),
        )?)
        .is_ok()
            || session.backend.frames.len() != count
            || session.p2p_rf_busy()
            || !concrete.child.started_current()
        {
            return Err(
                "invalid implicit FRAME reached native acquisition or changed actual device",
            );
        }
    }
    policy.database.install(active_policy());
    session
        .backend
        .sequence
        .arm(0)
        .map_err(|_| "old native report before private FRAME")?;
    let old = session
        .backend
        .sequence
        .pid(0)
        .map_err(|_| "old native private FRAME PID")?;
    let count = session.backend.frames.len();
    if run(tx(
        &mut session,
        &concrete,
        request(&concrete, false),
        Arc::new(AtomicBool::new(true)),
    )?) != Err(Error::Busy)
        || session.backend.frames.len() != count
        || session
            .backend
            .sequence
            .pid(0)
            .map_err(|_| "retained old native PID")?
            != old
        || session.backend.sequence.published(0)
    {
        return Err("implicit unicast acquisition reset/borrowed an old native report owner");
    }
    session.backend.tick_step_ns = 1_000;
    let observer = Arc::new(Observer::default());
    observer.terminal.store(true, Ordering::Release);
    session.backend.p2p_tx = Some(observer.clone());
    if run(tx(
        &mut session,
        &concrete,
        request(&concrete, true),
        Arc::new(AtomicBool::new(true)),
    )?) != Ok(false)
        || session
            .backend
            .sequence
            .pid(0)
            .map_err(|_| "retained old multicast PID")?
            != old
        || session.backend.sequence.published(0)
        || observer
            .published
            .lock()
            .last()
            .is_none_or(|(header, _)| header[21] & 4 != 0)
        || session.p2p_rf_busy()
        || !no_public_roc(&concrete)
    {
        return Err(
            "private multicast borrowed an old PID, fabricated ACK or missed finite retirement",
        );
    }
    session.backend.sequence.cancel();
    let (mut legacy, concrete) = setup_features(0)?;
    legacy
        .backend
        .tx_policy
        .as_ref()
        .unwrap()
        .database
        .install(active_policy());
    execute(&mut legacy, &concrete, P2pRequest::Start)
        .map_err(|_| "actual legacy P2P device before private FRAME")?;
    let count = legacy.backend.frames.len();
    if run(tx(
        &mut legacy,
        &concrete,
        request(&concrete, false),
        Arc::new(AtomicBool::new(true)),
    )?) != Err(Error::UnsupportedFirmware)
        || legacy.backend.frames.len() != count
        || !concrete.child.started_current()
    {
        return Err("private FRAME inferred optional CNM ABI from legacy native device metadata");
    }
    for cause in 0..4 {
        let (mut session, concrete) = started(Some(true))?;
        let policy = session.backend.tx_policy.as_ref().unwrap().clone();
        let resets = session.backend.recovery_trace.len();
        let observer = Arc::new(Observer::default());
        session.backend.p2p_tx = Some(observer.clone());
        let alive = Arc::new(AtomicBool::new(true));
        let mut request = request(&concrete, false);
        request.duration = 500;
        let mut operation = tx(&mut session, &concrete, request, alive.clone())?;
        published(&mut operation, &observer)?;
        match cause {
            0 => alive.store(false, Ordering::Release),
            1 => concrete.source.live.store(false, Ordering::Release),
            2 => {
                let mut domain = active_policy();
                domain.rules[0].flags = narf_wireless::reg::RegFlags::NO_P2P;
                policy.database.install(domain);
            }
            _ => observer.terminal.store(true, Ordering::Release), // No native TXS; finite grant expires.
        }
        if run(operation).is_ok()
            || session.p2p_owner.is_some()
            || concrete.child.started_current()
            || !matches!(session.state, State::RadioReady(_))
            || session.backend.recovery_trace.len() <= resets
            || !no_public_roc(&concrete)
        {
            return Err("private packet without source/policy/status escaped finite native reset/retirement");
        }
    }
    Ok(())
}
fn mt76_p2p_private_frame_admits_before_acquire_and_retains_uncertain_native_packet() -> TestResult
{
    admission_and_packet_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_private_frame_admits_before_acquire_and_retains_uncertain_native_packet
);
