//! Same native subscription/copy/ROC/session body used by the concrete
//! Hardware owner; the model supplies MCU events and owned RX descriptors.
use super::*;
use crate::mt7921::firmware_transport::boot_p2p::management;
fn action(local: [u8; 6], tag: u8) -> Vec<u8> {
    let mut frame = vec![0; 30];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&local);
    frame[10..16].copy_from_slice(&[2, 0, 0, 0, 0x79, 0xe1]);
    frame[16..22].fill(0xff);
    frame[24..].copy_from_slice(&[4, tag, 0x50, 0x6f, 0x9a, 9]);
    frame
}
fn packet(frame: &[u8], channel: u8) -> Vec<u8> {
    let mut bytes = vec![0; 32 + frame.len()];
    let length = bytes.len();
    bytes[..4].copy_from_slice(&(2u32 << 27 | length as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&(1u32 << 13 | 0x3ff).to_le_bytes()); // unassociated peer is no data WCID.
    bytes[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    bytes[12..16].copy_from_slice(&(u32::from(channel) << 8 | 1 << 16).to_le_bytes()); // actual CH_FREQ +U2M.
    bytes[28..32].copy_from_slice(&0x6464u32.to_le_bytes());
    bytes[32..].copy_from_slice(frame);
    bytes
}
fn attr(mut bytes: &[u8], kind: u16) -> Option<&[u8]> {
    while bytes.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 4 || length > bytes.len() {
            return None;
        }
        if u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff == kind {
            return Some(&bytes[4..length]);
        }
        bytes = bytes.get((length + 3) & !3..)?;
    }
    None
}
fn events(source: &Source) -> Vec<Vec<u8>> {
    source
        .messages
        .lock()
        .iter()
        .filter(|message| message.get(16) == Some(&59))
        .cloned()
        .collect()
}
fn register(
    session: &mut Session<Model>,
    concrete: &Concrete,
    frame_type: u16,
    prefix: &[u8],
) -> Result<(), i32> {
    management::register_session(
        session,
        Arc::downgrade(&concrete.child),
        concrete.authority().map_err(|_| 1)?,
        frame_type,
        prefix,
        concrete.binding.iface.mac(),
    )
}
fn source() -> Arc<Source> {
    Arc::new(Source {
        live: AtomicBool::new(true),
        close_on_ready: AtomicBool::new(false),
        messages: IrqSafeSpinLock::new(Vec::new()),
        controls: IrqSafeSpinLock::new(Vec::new()),
    })
}
fn authority_as(
    concrete: &Concrete,
    source: Arc<Source>,
) -> Result<Arc<RadioControlAuthority>, &'static str> {
    let wdev = narf_wireless::registry::control_for(concrete.child.as_ref())
        .ok_or("actual management WDEV")?;
    let admin = source
        .control_admin(concrete.child.name(), 0)
        .ok_or("explicit current management child grant")?;
    RadioControlAuthority::bind_wdev(admin, &concrete.iface, 0, wdev.id(), source)
        .and_then(RadioControlAuthority::reserve)
        .map(Arc::new)
        .map_err(|_| "current exact management source reservation")
}
fn execute_as(
    session: &mut Session<Model>,
    concrete: &Concrete,
    source: Arc<Source>,
    operation: P2pRequest,
) -> Result<(), Error> {
    run(Box::pin(boot_p2p::run_session(
        session,
        Arc::downgrade(&concrete.child),
        authority_as(concrete, source).map_err(|_| Error::Authority)?,
        operation,
        Arc::new(AtomicBool::new(true)),
        concrete.binding.iface.mac(),
    )))
}
fn start_roc(
    session: &mut Session<Model>,
    concrete: &Concrete,
    cookie: u64,
) -> Result<(), &'static str> {
    execute(session, concrete, P2pRequest::Start)
        .map_err(|_| "actual started management device")?;
    execute(
        session,
        concrete,
        P2pRequest::Roc {
            cookie,
            frequency_mhz: 2412,
            duration_ms: 1000,
        },
    )
    .map_err(|_| "matching native management listen grant")
}
fn prestart() -> Result<(), &'static str> {
    for features in [0, 0x80] {
        let (mut session, concrete) = setup_features(features)?;
        let count = session.backend.frames.len();
        register(&mut session, &concrete, 0xd0, &[4, 9])
            .map_err(|_| "pre-START actual host subscription")?;
        if session.backend.frames.len() != count
            || session.p2p_owner.is_some()
            || concrete.child.started_current()
            || session.backend.receive_open
            || session.security.is_some()
            || concrete.child.link_up()
        {
            return Err(
                "management registration fabricated CNM/native START/key/port/UP authority",
            );
        }
        if register(&mut session, &concrete, 0xd0, &[4]) != Err(114)
            || register(&mut session, &concrete, 0xc0, &[]) != Err(22)
            || register(&mut session, &concrete, 0xd1, &[]) != Err(22)
        {
            return Err("overlapping/unsupported management filter lost cfg80211 admission");
        }
        let old = packet(&action(concrete.child.mac(), 9), 1);
        session.backend.packets.push_back(old.clone());
        execute(&mut session, &concrete, P2pRequest::Start)
            .map_err(|_| "actual native START after host registration")?;
        session
            .service_p2p_management_receive()
            .map_err(|_| "started device without RF grant")?;
        if !events(&concrete.source).is_empty() {
            return Err("host registration/started metadata invented an RX channel grant");
        }
        if features == 0x80 {
            execute(
                &mut session,
                &concrete,
                P2pRequest::Roc {
                    cookie: 401,
                    frequency_mhz: 2412,
                    duration_ms: 1000,
                },
            )
            .map_err(|_| "real ROC after pre-START subscription")?;
            session
                .service_p2p_management_receive()
                .map_err(|_| "pre-grant completed-prefix cut")?;
            if !events(&concrete.source).is_empty() {
                return Err("old pre-START descriptor inherited a later RF/source capture");
            }
            let frame = action(concrete.child.mac(), 9);
            session.backend.packets.push_back(packet(&frame, 1));
            session
                .service_p2p_management_receive()
                .map_err(|_| "actual captured public action")?;
            let messages = events(&concrete.source);
            let wdev = narf_wireless::registry::control_for(concrete.child.as_ref())
                .ok_or("actual captured WDEV")?;
            if messages.len() != 1
                || attr(&messages[0][20..], 51) != Some(&frame)
                || attr(&messages[0][20..], 153) != Some(&wdev.id().to_ne_bytes())
                || attr(&messages[0][20..], 3).is_some()
                || attr(&messages[0][20..], 38) != Some(&2412u32.to_ne_bytes())
                || attr(&messages[0][20..], 151) != Some(&(-60i32).to_ne_bytes())
                || session.backend.receive_open
                || session.security.is_some()
            {
                return Err("native management event invented identity/frequency/signal/port or lost real frame bytes");
            }
        }
        execute(&mut session, &concrete, P2pRequest::Stop)
            .map_err(|_| "native management device cleanup")?;
    }
    Ok(())
}
fn mt76_p2p_management_subscription_precedes_start_without_inventing_cnm_or_packet_authority(
) -> TestResult {
    prestart().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_subscription_precedes_start_without_inventing_cnm_or_packet_authority
);

fn cut() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    join_home(&mut session, &concrete, true)?;
    let state = session.state;
    let epoch = session.receive_epoch;
    register(&mut session, &concrete, 0xd0, &[4, 1])
        .map_err(|_| "first actual management filter")?;
    start_roc(&mut session, &concrete, 402)?;
    let before = session.backend.recovery_trace.len();
    let old = packet(&action(concrete.child.mac(), 2), 1);
    session.backend.packets.push_back(old.clone());
    let copy = session
        .backend
        .receive_data_captured()
        .map_err(|_| "actual old native descriptor copy")?
        .ok_or("old copied descriptor")?;
    if copy.epoch != epoch || !copy.port_open {
        return Err("independent management capture changed home copy-time facts");
    }
    session.backend.captured_packets.push_back(copy);
    session.backend.packets.push_back(old.clone()); // another completed prefix, not yet copied.
    register(&mut session, &concrete, 0xd0, &[4, 2])
        .map_err(|_| "new disjoint filter and native completed-prefix cut")?;
    session
        .service_p2p_management_receive()
        .map_err(|_| "old queue/native prefix after filter replacement")?;
    if !events(&concrete.source).is_empty()
        || !home_current(&session, state, epoch, true)
        || !session
            .backend
            .captured_packets
            .iter()
            .any(|packet| packet.bytes == old && packet.epoch == epoch && packet.port_open)
    {
        return Err("new filter grafted an old copy/prefix or damaged real home security/capture");
    }
    let fresh = action(concrete.child.mac(), 2);
    session.backend.packets.push_back(packet(&fresh, 1));
    session
        .service_p2p_management_receive()
        .map_err(|_| "fresh copy under new filter generation")?;
    let messages = events(&concrete.source);
    if messages.len() != 1 || attr(&messages[0][20..], 51) != Some(&fresh) {
        return Err("fresh new-generation management delivery missing");
    }
    execute(&mut session, &concrete, P2pRequest::Cancel(402))
        .map_err(|_| "actual finite ROC retirement after capture")?;
    if !home_current(&session, state, epoch, true) || session.backend.recovery_trace.len() != before
    {
        return Err("management filter/ROC retirement reset or replaced the home owner");
    }
    run(Box::pin(session.send_ethernet(&ethernet(0x67))))
        .map_err(|_| "real protected home data after management capture")?;
    execute(&mut session, &concrete, P2pRequest::Stop)
        .map_err(|_| "management device stop after home data")?;
    Ok(())
}
fn mt76_p2p_management_filter_epoch_cuts_old_copies_and_native_prefix_preserving_home_rsna(
) -> TestResult {
    cut().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_filter_epoch_cuts_old_copies_and_native_prefix_preserving_home_rsna
);

fn lost() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    join_home(&mut session, &concrete, true)?;
    let state = session.state;
    let epoch = session.receive_epoch;
    register(&mut session, &concrete, 0xd0, &[4, 3])
        .map_err(|_| "first current management source")?;
    start_roc(&mut session, &concrete, 403)?;
    let admin = concrete
        .source
        .control_admin(concrete.child.name(), 0)
        .ok_or("explicit child grant before socket transfer")?;
    let old = packet(&action(concrete.child.mac(), 3), 1);
    session.backend.packets.push_back(old);
    let _ = session
        .backend
        .receive_data_captured()
        .map_err(|_| "native pending control copy before socket close")?;
    concrete.source.live.store(false, Ordering::Release);
    session
        .service_p2p_management_receive()
        .map_err(|_| "closed registered source capture fence")?;
    run(Box::pin(boot_p2p::maintain_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        concrete.binding.iface.mac(),
    )))
    .map_err(|_| "native owned ROC/device cleanup after source close")?;
    if !events(&concrete.source).is_empty()
        || concrete.child.started_current()
        || !home_current(&session, state, epoch, true)
    {
        return Err("closed source received old management or cleanup damaged home RSNA");
    }
    let next = source();
    next.retain_control_admin(admin)
        .map_err(|_| "explicit actual child grant retained on replacement source")?;
    management::register_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        authority_as(&concrete, next.clone())?,
        0xd0,
        &[4, 3],
        concrete.binding.iface.mac(),
    )
    .map_err(|_| "closed old registration released overlapping prefix for fresh source")?;
    execute_as(&mut session, &concrete, next.clone(), P2pRequest::Start)
        .map_err(|_| "actual fresh-source native START")?;
    execute_as(
        &mut session,
        &concrete,
        next.clone(),
        P2pRequest::Roc {
            cookie: 404,
            frequency_mhz: 2412,
            duration_ms: 1000,
        },
    )
    .map_err(|_| "actual fresh-source native grant")?;
    session
        .service_p2p_management_receive()
        .map_err(|_| "old pending copy after new source/grant")?;
    if !events(&next).is_empty() {
        return Err("new source inherited an old descriptor/ROC capture");
    }
    session
        .backend
        .packets
        .push_back(packet(&action(concrete.child.mac(), 3), 1));
    session
        .service_p2p_management_receive()
        .map_err(|_| "fresh source own management copy")?;
    if events(&next).len() != 1 || !events(&concrete.source).is_empty() {
        return Err("management event retargeted a closed original socket");
    }
    execute_as(&mut session, &concrete, next, P2pRequest::Stop)
        .map_err(|_| "fresh management native owner cleanup")?;
    Ok(())
}
fn mt76_p2p_management_closed_socket_cannot_retarget_old_capture_into_a_fresh_source() -> TestResult
{
    lost().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_closed_socket_cannot_retarget_old_capture_into_a_fresh_source
);

fn malformed() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    register(&mut session, &concrete, 0xd0, &[4])
        .map_err(|_| "actual raw management subscription")?;
    start_roc(&mut session, &concrete, 405)?;
    let frame = action(concrete.child.mac(), 7);
    let valid = packet(&frame, 1);
    for fault in 0..10 {
        let mut packet = valid.clone();
        match fault {
            0 => packet[12..16].copy_from_slice(&(6u32 << 8 | 1 << 16).to_le_bytes()),
            1 => packet[7] |= 8, // FCS error, not valid management.
            2 => packet[8..12].copy_from_slice(&(1u32 << 13 | 1 << 30).to_le_bytes()),
            3 => packet[16] = 1,     // partial hardware A-MSDU.
            4 => packet[33] |= 0x40, // raw protected data cannot authenticate an unkeyed device.
            5 => packet[32] = 0x08,
            6 => packet[36..42].copy_from_slice(&[2, 0, 0, 0, 0x79, 0xe2]),
            7 => packet[56] = 3, // non-public action does not enter DEVICE RX.
            8 => packet[54] |= 1,
            _ => packet.truncate(30),
        }
        session.backend.packets.push_back(packet);
    }
    session
        .service_p2p_management_receive()
        .map_err(|_| "malformed raw descriptors remain rejected")?;
    session
        .service_p2p_management_receive()
        .map_err(|_| "bounded remainder malformed descriptors")?;
    if !events(&concrete.source).is_empty() {
        return Err("malformed/cross-channel/keyed/data RX manufactured a valid management event");
    }
    session.backend.packets.push_back(valid);
    session
        .service_p2p_management_receive()
        .map_err(|_| "valid raw descriptor after malformed batch")?;
    if events(&concrete.source).len() != 1 {
        return Err("malformed batch revoked valid native raw management owner");
    }
    execute(&mut session, &concrete, P2pRequest::Stop)
        .map_err(|_| "malformed batch native cleanup")?;
    Ok(())
}
fn mt76_p2p_management_requires_real_channel_unkeyed_fcs_header_and_public_action_metadata(
) -> TestResult {
    malformed().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_requires_real_channel_unkeyed_fcs_header_and_public_action_metadata
);
