//! Real concrete WDEV grants + retained native Session TX body. Peer TXS
//! and terminal packet observations are injected independently at hardware.
use super::*;
use crate::mt7921::firmware_transport::{
    boot_p2p::management_tx, tests::p2p_management_model::Observer,
};

fn request(concrete: &Concrete, multicast: bool) -> narf_wireless::MgmtTxRequest {
    let mut frame = vec![0; 30];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&if multicast {
        [0xff; 6]
    } else {
        [2, 0, 0, 0, 0x79, 9]
    });
    frame[10..16].copy_from_slice(&concrete.child.mac());
    frame[16..22].fill(0xff);
    frame[24..].copy_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9]);
    narf_wireless::MgmtTxRequest {
        frequency_mhz: 2412,
        frame,
        offchannel_ok: true,
        duration: 0,
    }
}
fn report(pid: u8, ack: bool) -> Vec<u8> {
    [
        1u32 << 27 | 40,
        0,
        if ack { 0 } else { 1 << 16 },
        0,
        18 << 16,
        u32::from(pid) << 24,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}
type Operation<'a> = core::pin::Pin<Box<dyn Future<Output = Result<bool, Error>> + 'a>>;
fn tx<'a>(
    session: &'a mut Session<Model>,
    concrete: &Concrete,
    request: narf_wireless::MgmtTxRequest,
    alive: Arc<AtomicBool>,
) -> Result<Operation<'a>, &'static str> {
    Ok(Box::pin(management_tx::run_session(
        session,
        Arc::downgrade(&concrete.child),
        concrete.authority()?,
        request,
        alive,
        concrete.binding.iface.mac(),
    )))
}
fn start_roc(session: &mut Session<Model>, concrete: &Concrete) -> Result<(), &'static str> {
    execute(session, concrete, P2pRequest::Start)
        .map_err(|_| "native device before management TX")?;
    execute(
        session,
        concrete,
        P2pRequest::Roc {
            cookie: 0x7654,
            frequency_mhz: 2412,
            duration_ms: 1000,
        },
    )
    .map_err(|_| "actual finite management TX channel grant")
}
fn published(operation: &mut Operation<'_>, observer: &Observer) -> Result<u8, &'static str> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..256 {
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("management TX returned before held actual native packet receipt");
        }
        let records = observer.published.lock();
        if let Some((header, frame)) = records.last() {
            if header[4..8] != 0x81026012u32.to_le_bytes()
                || header[12..16] != 0x10007800u32.to_le_bytes()
                || header[20] < 3
                || header[21] & 4 == 0
                || frame[0] != 0xd0
                || frame[24..] != [4, 9, 0x50, 0x6f, 0x9a, 9]
            {
                return Err("actual management publication lost native BMC18/OMAC1/HOST-PID bytes");
            }
            return Ok(header[20]);
        }
    }
    Err("actual native management publication bound")
}
fn home_and_ack() -> Result<(), &'static str> {
    for secure in [false, true] {
        for ack in [false, true] {
            let (mut session, concrete) = setup()?;
            join_home(&mut session, &concrete, secure)?;
            start_roc(&mut session, &concrete)?;
            let home = session.state;
            let epoch = session.receive_epoch;
            let resets = session.backend.recovery_trace.len();
            let observer = Arc::new(Observer::default());
            session.backend.p2p_tx = Some(observer.clone());
            let mut operation = tx(
                &mut session,
                &concrete,
                request(&concrete, false),
                Arc::new(AtomicBool::new(true)),
            )?;
            let pid = published(&mut operation, &observer)?;
            observer.reports.lock().push_back(report(pid, ack));
            let mut cx = Context::from_waker(Waker::noop());
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("TXS alone supplied a native device ACK before packet retirement");
            }
            observer.terminal.store(true, Ordering::Release);
            if run(operation) != Ok(ack)
                || !home_current(&session, home, epoch, secure)
                || session.backend.recovery_trace.len() != resets
                || !concrete.child.started_current()
                || session
                    .p2p_owner
                    .as_ref()
                    .is_none_or(|owner| owner.management.tx.is_some() || owner.pending.is_some())
            {
                return Err("actual management ACK/negative status replaced home keys/BA/capture or reset the station");
            }
            let domain = session
                .backend
                .frames
                .iter()
                .rev()
                .find(|(_, frame)| frame.len() > 64 && frame[36] == 0x0f)
                .ok_or("actual restored home management domain")?;
            for row in domain.1[76..].chunks_exact(8) {
                let channel = u16::from_le_bytes([row[0], row[1]]);
                if channel == 6 && row[4..8] != [0; 4] || channel == 1 && row[4..8] == [0; 4] {
                    return Err("management TX left away emission enabled or failed original home-domain restore");
                }
            }
            execute(&mut session, &concrete, P2pRequest::Cancel(0x7654))
                .map_err(|_| "real finite management ROC cancellation")?;
            run(Box::pin(session.send_ethernet(&ethernet(0x65))))
                .map_err(|_| "same home station data after management and finite ROC")?;
            if session.backend.data_protection.last() != Some(&secure)
                || session.backend.recovery_trace.len() != resets
            {
                return Err("management TX changed original home data protection or lifetime");
            }
        }
    }
    let (mut session, concrete) = setup()?;
    session
        .backend
        .tx_policy
        .as_ref()
        .unwrap()
        .database
        .install(active_policy());
    start_roc(&mut session, &concrete)?;
    session
        .backend
        .sequence
        .arm(0)
        .map_err(|_| "existing native report identity before multicast")?;
    let old_pid = session
        .backend
        .sequence
        .pid(0)
        .map_err(|_| "retained old report PID")?;
    let observer = Arc::new(Observer::default());
    observer.terminal.store(true, Ordering::Release);
    session.backend.p2p_tx = Some(observer.clone());
    if run(tx(
        &mut session,
        &concrete,
        request(&concrete, true),
        Arc::new(AtomicBool::new(true)),
    )?) != Ok(false)
    {
        return Err(
            "multicast management fabricated a peer ACK or required a nonexistent unicast TXS",
        );
    }
    if session
        .backend
        .sequence
        .pid(0)
        .map_err(|_| "old PID after multicast")?
        != old_pid
        || session.backend.sequence.published(0)
        || observer.published.lock()[0].0[21] & 4 != 0
    {
        return Err("multicast management borrowed an unrelated native report identity");
    }
    session.backend.sequence.cancel();
    Ok(())
}
fn mt76_p2p_management_tx_keeps_real_home_keys_ba_capture_and_reports_only_native_ack() -> TestResult
{
    home_and_ack().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_tx_keeps_real_home_keys_ba_capture_and_reports_only_native_ack
);

fn admission() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    let policy = session.backend.tx_policy.as_ref().unwrap().clone();
    policy.database.install(active_policy());
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "native device before pure TX admission")?;
    let count = session.backend.frames.len();
    if run(tx(
        &mut session,
        &concrete,
        request(&concrete, false),
        Arc::new(AtomicBool::new(true)),
    )?) != Err(Error::Busy)
        || session.backend.frames.len() != count
    {
        return Err("started host metadata fabricated an actual management channel lease");
    }
    execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 0x7654,
            frequency_mhz: 2412,
            duration_ms: 1000,
        },
    )
    .map_err(|_| "pure management request actual channel owner")?;
    for cause in 0..6 {
        policy.database.install(active_policy());
        let mut request = request(&concrete, false);
        match cause {
            0 => request.frequency_mhz = 2437,
            1 => request.offchannel_ok = false,
            2 => request.frame[10] ^= 4,
            3 => request.frame[1] |= 0x40,
            _ => {
                let mut domain = active_policy();
                domain.rules[0].flags = if cause == 4 {
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
            || !concrete.child.started_current()
        {
            return Err(
                "invalid source/channel/occupied-policy management request reached native I/O",
            );
        }
    }
    policy.database.install(active_policy());
    session
        .backend
        .sequence
        .arm(0)
        .map_err(|_| "existing report owner before unicast admission")?;
    let old_pid = session
        .backend
        .sequence
        .pid(0)
        .map_err(|_| "existing unicast report PID")?;
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
            .map_err(|_| "unmodified prior report owner")?
            != old_pid
        || session.backend.sequence.published(0)
    {
        return Err("management contention reset or borrowed an existing report owner after hardware mutation");
    }
    session.backend.sequence.cancel();
    let info = session.p2p_owner.as_ref().unwrap().info;
    let mut old = active_policy();
    old.rules[0].freq_end_mhz = 2482;
    old.rules[0].max_bandwidth_mhz = 40;
    old.rules[0].max_power_dbm = 10;
    let home =
        TxPermission::from_domain40(&old, 6, 10).ok_or("real issued40MHz management home bound")?;
    let mut looser = old;
    looser.rules[0].max_power_dbm = 17;
    let plan = crate::mt7921::firmware_transport::p2p_management_power::Plan::prepare(
        info,
        &looser,
        2437,
        Some(home),
        false,
    )
    .map_err(|_| "actual clipped management power plan")?;
    let rows = plan
        .rows(info)
        .map_err(|_| "actual management native SKU rows")?;
    let expected = 20
        - if info.capabilities.phy.spatial_streams == 2 {
            6
        } else {
            0
        };
    if plan.emit.power_dbm != 10
        || rows.len() != 2
        || rows[0][4] != 2
        || rows[1][4] != 1
        || rows[0][6] != 0
        || rows[1][6] != 1
        || rows.iter().any(|row| {
            row[44..]
                .chunks_exact(162)
                .any(|channel| channel[1..].iter().any(|value| *value != expected))
        })
    {
        return Err("20MHz management row raised an issued wide home bound or omitted native path headroom/batch terminal");
    }
    let mut five = looser;
    five.rules[0].freq_start_mhz = 5170;
    five.rules[0].freq_end_mhz = 5190;
    five.rules[0].max_bandwidth_mhz = 20;
    let five = crate::mt7921::firmware_transport::p2p_management_power::Plan::prepare(
        info, &five, 5180, None, false,
    )
    .map_err(|_| "actual5GHz management occupied plan")?;
    if five.rate.hardware() != 75 || five.rows(info).map_err(|_| "native5GHz power row")?[0][5] != 2
    {
        return Err("5GHz management selected CCK or the wrong native band/rate namespace");
    }
    Ok(())
}
fn mt76_p2p_management_tx_requires_actual_roc_and_occupied_power_before_native_publication(
) -> TestResult {
    admission().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_tx_requires_actual_roc_and_occupied_power_before_native_publication
);

fn held() -> Result<(), &'static str> {
    for cause in 0..6 {
        let (mut session, concrete) = setup()?;
        let policy = session.backend.tx_policy.as_ref().unwrap().clone();
        policy.database.install(active_policy());
        start_roc(&mut session, &concrete)?;
        let resets = session.backend.recovery_trace.len();
        let observer = Arc::new(Observer::default());
        session.backend.p2p_tx = Some(observer.clone());
        let alive = Arc::new(AtomicBool::new(true));
        let mut operation = tx(
            &mut session,
            &concrete,
            request(&concrete, false),
            alive.clone(),
        )?;
        let _pid = published(&mut operation, &observer)?;
        if concrete.authority().is_ok() {
            return Err("actual held management packet released the native mutation reservation");
        }
        match cause {
            0 => alive.store(false, Ordering::Release),
            1 => concrete.source.live.store(false, Ordering::Release),
            2 => concrete.binding.daemon.revoke(),
            3 => {
                let mut domain = active_policy();
                domain.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
                policy.database.install(domain);
            }
            4 => {} // A held real packet outlives the actual finite CNM interval.
            _ => observer.terminal.store(true, Ordering::Release), // TX_FREE/DMA alone, no TXS.
        }
        if run(operation).is_ok()
            || concrete.child.started_current()
            || session.p2p_owner.is_some()
            || !matches!(session.state, State::RadioReady(_))
            || session.backend.recovery_trace.len() <= resets
        {
            return Err("cancelled/revoked/expired or status-less management packet returned ACK or escaped actual native retirement");
        }
        if cause == 0 && concrete.authority().is_err() {
            return Err(
                "verified native management retirement retained an obsolete mutation reservation",
            );
        }
    }
    Ok(())
}
fn mt76_p2p_management_tx_retains_packet_status_and_source_through_cancel_revoke_and_expiry(
) -> TestResult {
    held().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_tx_retains_packet_status_and_source_through_cancel_revoke_and_expiry
);
