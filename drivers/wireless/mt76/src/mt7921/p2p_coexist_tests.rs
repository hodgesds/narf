//! Real separate DEV/BSS contexts while the production home station keeps
//! its native peer/key/BA/copy-time epoch. Hardware observations are modeled;
//! parent/child/daemon/source grants are the actual concrete registration.
use super::*;
use crate::mt7921::association::{Security, TxPermission};
use narf_wifi_fixtures::FakeAp;
#[path = "p2p_management_tests.rs"]
mod management;

fn active_policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}
#[inline(never)]
fn join_home(
    session: &mut Session<Model>,
    concrete: &Concrete,
    secure: bool,
) -> Result<(), &'static str> {
    concrete
        .binding
        .iface
        .set_iftype(2)
        .map_err(|_| "actual home station mode")?;
    let policy = session
        .backend
        .tx_policy
        .as_ref()
        .ok_or("actual current native policy")?;
    policy.database.install(active_policy());
    let network = super::super::super::wmm_tests::NETWORK;
    let ap = if secure {
        FakeAp::wpa2(network, b"narf", 6, 42, [0x55; 32], [0xaa; 32])
    } else {
        FakeAp::open(network, b"narf", 6, 42)
    }
    .map_err(|_| "actual home AP fixture")?;
    let beacon = ap.beacon();
    let mut bss = ScanBss {
        bssid: network.bssid,
        ssid: b"narf".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-45),
        capability: u16::from_le_bytes([beacon[34], beacon[35]]),
        beacon_interval: 100,
        information_elements: beacon[36..].to_vec(),
    };
    let wmm = super::super::super::wmm_tests::PARAMETERS.to_vec();
    let ht = super::super::super::ht20_tests::elements(6);
    bss.information_elements.extend_from_slice(&wmm);
    bss.information_elements.extend_from_slice(&ht);
    session.backend.wmm_reply = Some(wmm);
    session.backend.ht_reply = Some(ht);
    session.backend.access_point = Some(ap);
    let State::RadioReady(info) = session.state else {
        return Err("separate device did not leave actual home radio ready");
    };
    let permission =
        TxPermission::from_ap(&active_policy(), info, &bss).ok_or("actual AP/policy home grant")?;
    run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        if secure {
            Security::Wpa2Psk { psk: [0x55; 32] }
        } else {
            Security::Open
        },
        permission,
        &[],
    )))
    .map_err(|_| "actual home MLME/RSNA")?;
    session.backend.tx_ba_offer = Some((64, 0));
    if run(Box::pin(session.negotiate_transmit_ba())) != Ok(true) || !session.tx_ba.active() {
        return Err("actual native home TX BA");
    }
    Ok(())
}
fn ethernet(value: u8) -> Vec<u8> {
    let network = super::super::super::wmm_tests::NETWORK;
    let mut frame = vec![value; 60];
    frame[..6].copy_from_slice(&network.bssid);
    frame[6..12].copy_from_slice(&network.station);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame
}
fn home_current(session: &Session<Model>, state: State, epoch: u64, secure: bool) -> bool {
    session.state == state
        && session.receive_epoch == epoch
        && session.receive_current(epoch) == Ok(true)
        && session.security.is_some() == secure
        && session.tx_ba.active()
        && session.backend.receive_open
}
fn coexist() -> Result<(), &'static str> {
    for secure in [false, true] {
        for start_first in [false, true] {
            let (mut session, concrete) = setup()?;
            let resets = session.backend.recovery_trace.len();
            if start_first {
                execute(&mut session, &concrete, P2pRequest::Start)
                    .map_err(|_| "device before home association")?;
            }
            join_home(&mut session, &concrete, secure)?;
            let state = session.state;
            let epoch = session.receive_epoch;
            let clears = session.backend.wtbl_clears.len();
            if !start_first {
                execute(&mut session, &concrete, P2pRequest::Start)
                    .map_err(|_| "device alongside live home")?;
                if session.backend.wtbl_clears[clears..] != [18] {
                    return Err("separate device cleared the live peer/BMC WTBL");
                }
            }
            if !concrete.child.started_current() || !home_current(&session, state, epoch, secure) {
                return Err("separate native START reset or replaced home keys/BA/capture");
            }
            run(Box::pin(session.send_ethernet(&ethernet(0x31))))
                .map_err(|_| "home TX while P2P device stays started")?;
            if session.backend.data_protection.last() != Some(&secure) {
                return Err("sidecar changed actual home data protection");
            }
            let before = session.backend.frames.len();
            execute(&mut session, &concrete, P2pRequest::Stop)
                .map_err(|_| "independent native device STOP")?;
            if !home_current(&session, state, epoch, secure)
                || session.backend.recovery_trace.len() != resets
                || session.backend.frames[before..]
                    .iter()
                    .filter_map(|(_, f)| uni(f, 2))
                    .any(|body| body.first() != Some(&1))
            {
                return Err("normal independent STOP reset/disabled the home owner");
            }
            run(Box::pin(session.send_ethernet(&ethernet(0x32))))
                .map_err(|_| "home data after independent STOP")?;
        }
    }
    Ok(())
}
fn mt76_p2p_separate_bss_preserves_real_home_mlme_keys_ba_and_capture_in_both_start_orders(
) -> TestResult {
    coexist().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_separate_bss_preserves_real_home_mlme_keys_ba_and_capture_in_both_start_orders
);

fn off_channel() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    join_home(&mut session, &concrete, true)?;
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "independent device before off-channel")?;
    let state = session.state;
    let epoch = session.receive_epoch;
    let resets = session.backend.recovery_trace.len();
    let native = session
        .backend
        .roc
        .clone()
        .ok_or("actual native ROC model")?;
    native.interval_ms.store(500, Ordering::Release);
    let packet = Arc::new(Hold::default());
    session.backend.packet_hold = Some(packet.clone());
    session
        .start_ethernet(&ethernet(0x41))
        .map_err(|_| "actual pending home packet before ROC")?;
    let authority = concrete.authority()?;
    let mut operation = Box::pin(boot_p2p::run_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        authority,
        P2pRequest::Roc {
            cookie: 91,
            frequency_mhz: 2412,
            duration_ms: 1000,
        },
        Arc::new(AtomicBool::new(true)),
        concrete.binding.iface.mac(),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if operation.as_mut().poll(&mut cx).is_ready()
        || !packet.seen.load(Ordering::Acquire)
        || native.seen.load(Ordering::Acquire)
    {
        return Err("CNM publication preceded actual old home packet retirement");
    }
    packet.release.store(true, Ordering::Release);
    run(operation).map_err(|_| "actual home-retired off-channel grant")?;
    if !home_current(&session, state, epoch, true)
        || !session.data_pending.is_empty()
        || session.start_ethernet(&ethernet(0x42)) != Err(Error::Busy)
        || !home_current(&session, state, epoch, true)
    {
        return Err("off-channel pause revoked home security or reused packet ownership");
    }
    // The temporary listen domain keeps the real home channel active while
    // channel1 remains NO_IR. Listening never becomes an active probe grant.
    let frame = session
        .backend
        .frames
        .iter()
        .rev()
        .find(|(_, f)| f.len() > 64 && f[36] == 0x0f)
        .ok_or("actual coexistence domain")?;
    let domain = &frame.1[64..];
    for entry in domain[12..].chunks_exact(8) {
        let channel = u16::from_le_bytes([entry[0], entry[1]]);
        if (channel == 6 && entry[4..8] != [0; 4]) || (channel == 1 && entry[4..8] == [0; 4]) {
            return Err("listen grant overwrote home channel or permitted off-channel TX");
        }
    }
    let deadline = match session
        .p2p_owner
        .as_ref()
        .and_then(|o| o.cnm.lease())
        .map(|l| l.phase)
    {
        Some(crate::mt7921::p2p_cnm::Phase::Granted { expires_ns, .. }) => expires_ns,
        _ => return Err("actual finite coexistence lease"),
    };
    let authority = concrete.authority()?;
    let mut cancel = Box::pin(boot_p2p::run_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        authority,
        P2pRequest::Cancel(91),
        Arc::new(AtomicBool::new(true)),
        concrete.binding.iface.mac(),
    ));
    if cancel.as_mut().poll(&mut cx).is_ready() {
        return Err("queued abort acknowledged cancellation before finite retirement");
    }
    run(cancel).map_err(|_| "owned finite cancellation alongside home")?;
    if session.backend.ticks.get() < deadline
        || !home_current(&session, state, epoch, true)
        || session.backend.recovery_trace.len() != resets
        || session.p2p_rf_busy()
    {
        return Err("normal CNM cancellation reset home or retired before actual finite end");
    }
    run(Box::pin(session.send_ethernet(&ethernet(0x43))))
        .map_err(|_| "resumed home TX after real cancel")?;
    execute(&mut session, &concrete, P2pRequest::Stop)
        .map_err(|_| "independent stop after cancel")?;
    if session.backend.recovery_trace.len() != resets {
        return Err("stop after cancel reset live station");
    }
    Ok(())
}
fn mt76_p2p_roc_drains_real_home_packets_pauses_tx_and_cancels_after_finite_retirement(
) -> TestResult {
    off_channel().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_roc_drains_real_home_packets_pauses_tx_and_cancels_after_finite_retirement
);

fn source_loss() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    join_home(&mut session, &concrete, true)?;
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "independent start before source loss")?;
    let state = session.state;
    let epoch = session.receive_epoch;
    let resets = session.backend.recovery_trace.len();
    execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 92,
            frequency_mhz: 2412,
            duration_ms: 500,
        },
    )
    .map_err(|_| "actual grant before source loss")?;
    concrete.source.live.store(false, Ordering::Release);
    let events = concrete.source.messages.lock().len();
    run(Box::pin(boot_p2p::maintain_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        concrete.binding.iface.mac(),
    )))
    .map_err(|_| "owned source-loss finite cleanup")?;
    if !home_current(&session, state, epoch, true)
        || session.backend.recovery_trace.len() != resets
        || session.p2p_owner.is_some()
        || concrete.child.started_current()
        || concrete.source.messages.lock().len() != events
    {
        return Err("retired P2P source retargeted an event or reset the unrelated home");
    }
    run(Box::pin(session.send_ethernet(&ethernet(0x44))))
        .map_err(|_| "home data survives control-source loss")?;
    Ok(())
}
fn mt76_p2p_closed_source_retires_only_owned_native_context_without_resetting_home() -> TestResult {
    source_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_closed_source_retires_only_owned_native_context_without_resetting_home
);

fn mt76_native_vif_geometry_and_retired_allocation_do_not_alias_live_or_reused_contexts(
) -> TestResult {
    use crate::mt7921::vif_slots::{mac_candidates, Slots, Vif};
    let mut slots = Slots::default();
    let first = slots.reserve().unwrap();
    let second = slots.reserve().unwrap();
    let third = slots.reserve().unwrap();
    if [
        first.vif().index(),
        second.vif().index(),
        third.vif().index(),
    ] != [1, 2, 3]
        || slots.reserve() != Err(Error::Busy)
        || !slots.release_retired(second)
    {
        return TestResult::Fail("native four-BSS inventory displaced the physical or live child");
    }
    let successor = slots.reserve().unwrap();
    if successor.vif().index() != 2
        || successor == second
        || slots.current(second)
        || slots.release_retired(second)
        || !slots.current(successor)
        || !slots.current(first)
        || !slots.current(third)
    {
        return TestResult::Fail(
            "retired native allocation freed a current successor or another BSS",
        );
    }
    for index in 0..4 {
        let vif = Vif::new(index).unwrap();
        let (dev, bss) = vif
            .device_payloads([2, 1, 2, 3, 4, 5], false, true)
            .unwrap();
        if dev[0] != index
            || bss[0] != index
            || bss[9] != index
            || bss[10] != index
            || bss[17] != index
            || vif.bmc() != 19 - index
            || bss[24..26] != u16::from(19 - index).to_le_bytes()
        {
            return TestResult::Fail(
                "native BSS/OMAC/WMM/BMC does not follow actual add-interface geometry",
            );
        }
    }
    if Vif::new(4).is_ok()
        || mac_candidates([0, 1, 2, 3, 4, 5])
            != [
                [0, 1, 2, 3, 4, 5],
                [2, 1, 2, 3, 4, 5],
                [6, 1, 2, 3, 4, 5],
                [10, 1, 2, 3, 4, 5],
            ]
    {
        return TestResult::Fail("native slot bound or Linux default MAC candidates differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_native_vif_geometry_and_retired_allocation_do_not_alias_live_or_reused_contexts
);

fn retired_home() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    join_home(&mut session, &concrete, true)?;
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "sidecar before home disconnect")?;
    run(Box::pin(session.disassociate_station()))
        .map_err(|_| "actual home disconnect while device idle")?;
    let idle = session.state;
    let epoch = session.receive_epoch;
    let resets = session.backend.recovery_trace.len();
    if !matches!(idle, State::ScanReady(_))
        || session.security.is_some()
        || !concrete.child.started_current()
    {
        return Err("home disconnect lost independent device or retained old key owner");
    }
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "idempotent device after home disconnect")?;
    execute(&mut session, &concrete, P2pRequest::Stop)
        .map_err(|_| "independent stop after home disconnect")?;
    if session.state != idle
        || session.receive_epoch != epoch
        || session.security.is_some()
        || session.receive_current(epoch) != Ok(false)
        || session.backend.recovery_trace.len() != resets
    {
        return Err("device operation resurrected a stale saved home association/key/epoch");
    }
    Ok(())
}
fn mt76_p2p_operations_cannot_restore_a_home_association_retired_while_device_is_idle() -> TestResult
{
    retired_home().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_operations_cannot_restore_a_home_association_retired_while_device_is_idle
);

fn publication_loss() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    join_home(&mut session, &concrete, true)?;
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "sidecar before publication loss")?;
    let home = session.state;
    let epoch = session.receive_epoch;
    let resets = session.backend.recovery_trace.len();
    concrete
        .source
        .close_on_ready
        .store(true, Ordering::Release);
    if execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 93,
            frequency_mhz: 2412,
            duration_ms: 500,
        },
    ) != Err(Error::Authority)
        || !home_current(&session, home, epoch, true)
        || session.p2p_owner.is_some()
        || concrete.child.started_current()
        || session.backend.recovery_trace.len() != resets
    {
        return Err("lost terminal ready source reset home or leaked actual finite ROC/device");
    }
    if concrete
        .source
        .messages
        .lock()
        .iter()
        .filter(|event| event.get(16) == Some(&55))
        .count()
        != 1
        || concrete
            .source
            .messages
            .lock()
            .iter()
            .any(|event| event.get(16) == Some(&56))
    {
        return Err("terminal publication loss retargeted or duplicated a native event");
    }
    run(Box::pin(session.send_ethernet(&ethernet(0x45))))
        .map_err(|_| "home TX after terminal source loss")?;
    Ok(())
}
fn mt76_p2p_terminal_publication_loss_retires_only_completed_independent_native_owner() -> TestResult
{
    publication_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_terminal_publication_loss_retires_only_completed_independent_native_owner
);

fn ap_request(
    session: &mut Session<Model>,
    concrete: &Concrete,
    request: crate::mt7921::firmware_transport::boot_ap::Request,
) -> Result<crate::mt7921::firmware_transport::boot_ap::Reply, Error> {
    use narf_wireless::ap_control::ApControlAuthority;
    let iface: Arc<dyn WirelessNetIface> = concrete.binding.iface.clone();
    let index = narf_net::iface::lookup(iface.name())
        .ok_or(Error::Authority)?
        .ifindex;
    let authority = ApControlAuthority::bind(
        concrete.binding.admin.clone(),
        &iface,
        0,
        index,
        concrete.source.clone(),
    )
    .and_then(ApControlAuthority::reserve)
    .map(Arc::new)
    .map_err(|_| Error::Authority)?;
    concrete.binding.iface.ap_work_started();
    run(Box::pin(
        crate::mt7921::firmware_transport::boot_ap::run_session(
            session,
            Arc::downgrade(&concrete.binding.iface),
            authority,
            request,
            Arc::new(AtomicBool::new(true)),
            concrete.binding.iface.mac(),
        ),
    ))
}
fn ap_home() -> Result<(), &'static str> {
    use crate::mt7921::firmware_transport::boot_ap::{Reply, Request};
    use narf_wireless::ap_control::ApControlAuthority;
    let (mut session, concrete) = setup()?;
    session
        .backend
        .tx_policy
        .as_ref()
        .ok_or("actual AP policy")?
        .database
        .install(active_policy());
    concrete
        .binding
        .admin
        .set_link(true)
        .map_err(|_| "actual delegated AP administrative UP")?;
    let config = super::super::config(concrete.binding.iface.mac());
    if ap_request(
        &mut session,
        &concrete,
        Request::Start(Box::new((
            config,
            narf_wireless::ApStartSettings::default(),
        ))),
    ) != Ok(Reply::Done)
    {
        return Err("actual retained AP home native start/host publication");
    }
    let state = session.state;
    let epoch = session.receive_epoch;
    let plan = session
        .ap_owner
        .as_ref()
        .ok_or("actual home AP owner")?
        .plan
        .clone();
    let resets = session.backend.recovery_trace.len();
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "independent device alongside real AP")?;
    execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 94,
            frequency_mhz: 2412,
            duration_ms: 500,
        },
    )
    .map_err(|_| "actual AP/device native off-channel grant")?;
    if !matches!(session.step_ap_network(None), Err(Error::Busy))
        || session.state != state
        || session.ap_receive_current(epoch) != Ok(true)
    {
        return Err("off-channel AP data pause revoked current AP owner/epoch");
    }
    let iface: Arc<dyn WirelessNetIface> = concrete.binding.iface.clone();
    let index = narf_net::iface::lookup(iface.name())
        .ok_or("actual AP index")?
        .ifindex;
    let authority = ApControlAuthority::bind(
        concrete.binding.admin.clone(),
        &iface,
        0,
        index,
        concrete.source.clone(),
    )
    .and_then(ApControlAuthority::reserve)
    .map(Arc::new)
    .map_err(|_| "actual AP control during device ROC")?;
    let mut action = vec![0; 24];
    action[0] = 0xd0;
    action[4..10].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    action[10..16].copy_from_slice(&iface.mac());
    action[16..22].copy_from_slice(&iface.mac());
    let frames = session.backend.frames.len();
    if run(Box::pin(session.ap_send_management(authority, &action))) != Err(Error::Busy)
        || session.backend.frames.len() != frames
    {
        return Err("AP control transmitted across another BSS's off-channel RF owner");
    }
    execute(&mut session, &concrete, P2pRequest::Cancel(94))
        .map_err(|_| "independent AP/device finite cancel")?;
    execute(&mut session, &concrete, P2pRequest::Stop).map_err(|_| "independent AP/device stop")?;
    if session.state != state
        || session.receive_epoch != epoch
        || session.ap_receive_current(epoch) != Ok(true)
        || session
            .ap_owner
            .as_ref()
            .is_none_or(|owner| !owner.activated || !Arc::ptr_eq(&owner.plan, &plan))
        || session.backend.recovery_trace.len() != resets
        || !concrete.binding.iface.link_up()
    {
        return Err("independent device stop/reset replaced AP beacon/capture/carrier ownership");
    }
    session
        .step_ap_network(None)
        .map_err(|_| "resumed actual AP packet service")?;
    if ap_request(&mut session, &concrete, Request::Stop) != Ok(Reply::Done) {
        return Err("actual home AP native cleanup");
    }
    Ok(())
}
fn mt76_p2p_independent_context_preserves_actual_ap_beacon_owner_and_pauses_home_control_tx(
) -> TestResult {
    ap_home().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_independent_context_preserves_actual_ap_beacon_owner_and_pauses_home_control_tx
);

fn suspend_owners() -> Result<(), &'static str> {
    for wow in [false, true] {
        let (mut session, concrete) = setup()?;
        join_home(&mut session, &concrete, true)?;
        execute(&mut session, &concrete, P2pRequest::Start)
            .map_err(|_| "separate device before system suspend")?;
        execute(
            &mut session,
            &concrete,
            P2pRequest::Roc {
                cookie: 95,
                frequency_mhz: 2412,
                duration_ms: 500,
            },
        )
        .map_err(|_| "actual finite ROC before sleep")?;
        session.backend.pm.dma_enabled = true;
        let before = session.backend.frames.len();
        if wow {
            session.backend.pm.wow.route_available = true;
            let config = narf_wireless::WowlanConfig {
                magic_packet: true,
                ..Default::default()
            };
            run(Box::pin(session.suspend_wowlan(
                &config,
                narf_power::system_pm::SystemSleepState::S3,
            )))
            .map_err(|_| "actual bounded WoW handoff after control retirement")?;
            if !matches!(
                session.state,
                State::WowSuspended {
                    association: Some(_),
                    ..
                }
            ) {
                return Err("independent control cleanup discarded retained WoW association");
            }
        } else {
            run(Box::pin(session.suspend()))
                .map_err(|_| "actual non-WoW system suspend after control retirement")?;
            if !matches!(session.state, State::Suspended(_)) {
                return Err("ordinary suspend did not complete actual low-power handoff");
            }
        }
        let frames = &session.backend.frames[before..];
        let child_off = frames.iter().position(|(_, frame)| {
            uni(frame, 2).is_some_and(|body| body.len() == 36 && body[0] == 1 && body[8] == 0)
        });
        let hif_suspend = frames
            .iter()
            .position(|(_, frame)| uni(frame, 7).is_some_and(|body| body.get(8) == Some(&1)));
        if session.p2p_owner.is_some()
            || session.p2p_rf_busy()
            || !matches!((child_off, hif_suspend), (Some(child), Some(hif)) if child < hif)
        {
            return Err(
                "system sleep retained a control BSS/RF lease or disabled it after HIF handoff",
            );
        }
        concrete.child.commit_stopped();
        if concrete.child.started_current() {
            return Err("completed system sleep retained a started host control identity");
        }
    }
    Ok(())
}
fn mt76_p2p_system_sleep_retires_actual_control_bss_before_ordinary_or_wow_hif_handoff(
) -> TestResult {
    suspend_owners().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_system_sleep_retires_actual_control_bss_before_ordinary_or_wow_hif_handoff
);
