//! Production Mt76Iface and native Session composed under actual registry
//! grants. No test edits mode/generation, opens a port, or fakes a receipt.
use super::super::super::boot_ap::{self, Reply, Request};
use super::*;
use crate::iface::ap_tests::Binding as Concrete;

fn concrete() -> Result<(NativeSession, Concrete, Arc<Source>), &'static str> {
    let (session, fixture, authority) = idle()?;
    let State::RadioReady(info) = session.state else {
        return Err("concrete native radio receipt");
    };
    drop(authority);
    drop(fixture);
    let binding = crate::iface::ap_tests::bind(info)?;
    Ok((session, binding, Arc::new(Source::new())))
}
fn bound(
    binding: &Concrete,
    source: &Arc<Source>,
) -> Result<Arc<ApControlAuthority>, &'static str> {
    let iface: Arc<dyn WirelessNetIface> = binding.iface.clone();
    let index = narf_net::iface::lookup(binding.iface.name())
        .ok_or("concrete link registration")?
        .ifindex;
    ApControlAuthority::bind(binding.admin.clone(), &iface, 0, index, source.clone())
        .and_then(ApControlAuthority::reserve)
        .map(Arc::new)
        .map_err(|_| "concrete current AP authority")
}
fn execute(
    session: &mut Session<Model>,
    binding: &Concrete,
    authority: Arc<ApControlAuthority>,
    request: Request,
) -> Result<Reply, Error> {
    binding.iface.ap_work_started();
    run(Box::pin(boot_ap::run_session(
        session,
        Arc::downgrade(&binding.iface),
        authority,
        request,
        Arc::new(AtomicBool::new(true)),
        binding.iface.mac(),
    )))
}
fn bootstrap() -> Result<(), &'static str> {
    let (mut session, binding, source) = concrete()?;
    let own = binding.iface.mac();
    let authority = bound(&binding, &source)?;
    // Normal Linux REGISTER_FRAME is permitted before IFF_UP. It gives no
    // native RX or association receipt and holds no native transport.
    run(binding
        .iface
        .register_mgmt_frame_ap_async(&authority, 0xb0, vec![0, 0]))
    .map_err(|_| "concrete pre-UP management registration")?;
    drop(authority);
    if binding.iface.link_up() || binding.iface.rx_ring().lock().is_some() {
        return Err("pre-UP registration published carrier or Ethernet RX");
    }
    narf_net::iface::set_link_state(binding.iface.name(), true);
    let authority = bound(&binding, &source)?;
    if execute(
        &mut session,
        &binding,
        authority,
        Request::Start(Box::new((
            config(own),
            narf_wireless::ApStartSettings::default(),
        ))),
    ) != Ok(Reply::Done)
    {
        return Err("concrete retained START/native host commit");
    }
    if !binding.iface.link_up()
        || binding.iface.rx_ring().lock().is_none()
        || binding.iface.tx_ring().lock().is_none()
        || narf_net::iface::lookup(binding.iface.name())
            .is_none_or(|link| !link.link_up || !link.carrier)
        || !session.backend.receive_open
        || session
            .ap_owner
            .as_ref()
            .is_none_or(|owner| !owner.activated)
        || !session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .addresses()
            .is_empty()
    {
        return Err("native START receipt did not bind exact concrete carrier/rings");
    }
    // A completed configured AP is independent of the former CLI socket;
    // frame notifications still require the original current source.
    source.0.store(false, Ordering::Release);
    if !binding.iface.link_up() {
        return Err("completed AP lifetime depended on CLI socket");
    }
    narf_net::iface::set_link_state(binding.iface.name(), false);
    if binding.iface.link_up()
        || session.ap_receive_current(session.receive_epoch) != Err(Error::Authority)
        || binding.iface.set_iftype(2) != Err(WirelessError::Busy)
    {
        return Err("DOWN admitted old data or released autonomous BSS role ownership");
    }
    let fresh = Arc::new(Source::new());
    let authority = bound(&binding, &fresh)?;
    if execute(&mut session, &binding, authority, Request::Stop) != Ok(Reply::Done)
        || session.ap_owner.is_some()
        || !matches!(session.state, State::RadioReady(_))
        || binding.iface.rx_ring().lock().is_some()
        || binding.iface.tx_ring().lock().is_some()
        || narf_net::iface::lookup(binding.iface.name()).is_none_or(|link| link.carrier)
    {
        return Err("concrete STOP did not retire native BSS and old ring ownership");
    }
    binding
        .iface
        .set_iftype(2)
        .map_err(|_| "native STOP did not release role transition")?;
    Ok(())
}
fn observed(result: Result<(), &'static str>) -> TestResult {
    match result {
        Ok(()) => TestResult::Pass,
        Err(
            reason @ ("active physical radio cannot be displaced"
            | "physical probe won concrete fixture admission"),
        ) => TestResult::Skip(reason),
        Err(reason) => TestResult::Fail(reason),
    }
}
fn mt76_ap_concrete_start_registration_down_stop_and_role_publication() -> TestResult {
    observed(bootstrap())
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_concrete_start_registration_down_stop_and_role_publication
);

fn cancelled() -> Result<(), &'static str> {
    for reason in 0..3 {
        let (mut session, binding, source) = concrete()?;
        narf_net::iface::set_link_state(binding.iface.name(), true);
        let authority = bound(&binding, &source)?;
        let own = binding.iface.mac();
        let alive = Arc::new(AtomicBool::new(true));
        let hold = Arc::new(Hold::default());
        session.backend.ap_hold = Some(hold.clone());
        binding.iface.ap_work_started();
        let mut operation = Box::pin(boot_ap::run_session(
            &mut *session,
            Arc::downgrade(&binding.iface),
            authority.clone(),
            Request::Start(Box::new((
                config(own),
                narf_wireless::ApStartSettings::default(),
            ))),
            alive.clone(),
            own,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..8192 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("concrete AP completed before actual beacon receipt");
            }
            if hold.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !hold.seen.load(Ordering::Acquire)
            || binding.iface.link_up()
            || narf_net::iface::lookup(binding.iface.name()).is_none_or(|link| link.carrier)
        {
            return Err("held native START published concrete success");
        }
        match reason {
            0 => alive.store(false, Ordering::Release),
            1 => source.0.store(false, Ordering::Release),
            _ => {
                binding.daemon.revoke();
            }
        }
        let expected = if reason == 0 {
            Error::Cancelled
        } else {
            Error::Authority
        };
        if run(operation) != Err(expected)
            || session.ap_owner.is_some()
            || !matches!(session.state, State::RadioReady(_))
            || session.backend.receive_open
            || binding.iface.link_up()
            || binding.iface.rx_ring().lock().is_some()
        {
            return Err(
                "cancelled/source-closed/revoked native START stranded BSS or host publication",
            );
        }
        drop(authority);
        narf_net::iface::set_link_state(binding.iface.name(), false);
        binding
            .iface
            .set_iftype(2)
            .map_err(|_| "verified cancellation retained dead mode ownership")?;
    }
    Ok(())
}
fn mt76_ap_concrete_pending_start_waiter_source_and_cap_cancellation_reset_before_reuse(
) -> TestResult {
    observed(cancelled())
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_concrete_pending_start_waiter_source_and_cap_cancellation_reset_before_reuse
);

fn emit_management(
    session: &mut Session<Model>,
    binding: &Concrete,
    frame: &[u8],
) -> Result<(), &'static str> {
    session
        .backend
        .packets
        .push_back(receive::packet(frame, 1023, true));
    if !session
        .step_ap_network(None)
        .map_err(|_| "concrete native management capture")?
        .received
        .is_empty()
    {
        return Err("concrete management escaped into ordinary Ethernet");
    }
    let event = session
        .pop_ap_event()
        .map_err(|_| "concrete captured event")?
        .ok_or("concrete native event missing")?;
    binding
        .iface
        .deliver_ap_event_with(event, |epoch| {
            session
                .ap_receive_current(epoch)
                .map_err(|_| WirelessError::HardwareError)
        })
        .map_err(|_| "concrete registered management delivery")
}
fn keys_and_events() -> Result<(), &'static str> {
    let (mut session, binding, source) = concrete()?;
    let own = binding.iface.mac();
    let authority = bound(&binding, &source)?;
    run(binding
        .iface
        .register_mgmt_frame_ap_async(&authority, 0xb0, vec![0, 0]))
    .map_err(|_| "concrete secure pre-UP management registration")?;
    drop(authority);
    narf_net::iface::set_link_state(binding.iface.name(), true);
    let settings = narf_wireless::ApStartSettings {
        control_port: narf_wireless::ControlPort {
            enabled: true,
            over_nl80211: true,
            ..narf_wireless::ControlPort::default()
        },
        ..narf_wireless::ApStartSettings::default()
    };
    execute(
        &mut session,
        &binding,
        bound(&binding, &source)?,
        Request::Start(Box::new((secure_config(own), settings))),
    )
    .map_err(|_| "concrete secure START")?;
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&own);
    auth[10..16].copy_from_slice(&[2, 0, 0, 0, 0x44, 1]);
    auth[16..22].copy_from_slice(&own);
    auth[26] = 1;
    emit_management(&mut session, &binding, &auth)?;
    if source.1.lock().len() != 1 {
        return Err("concrete pre-UP filter did not deliver its real native RX");
    }
    let peer_cfg = peer_config(1);
    let peer = peer_cfg.mac;
    execute(
        &mut session,
        &binding,
        bound(&binding, &source)?,
        Request::AddStation(peer_cfg.clone()),
    )
    .map_err(|_| "concrete native peer")?;
    let old_epoch = session.receive_epoch;
    let mut old_tx = binding
        .iface
        .tx_ring()
        .lock()
        .take()
        .ok_or("concrete old TX ring")?;
    let key = narf_wireless::OwnedKey::new(narf_wireless::KeyParams {
        idx: 0,
        pairwise: true,
        peer: Some(peer),
        cipher: 0x000fac04,
        key: vec![91; 16],
        seq: vec![0; 6],
        default_mgmt: false,
    });
    execute(
        &mut session,
        &binding,
        bound(&binding, &source)?,
        Request::AddKey(key),
    )
    .map_err(|_| "concrete current PTK commit")?;
    let buffer = narf_io::alloc_coherent(60, narf_lib::id::DomainId::DRIVER_0)
        .map_err(|_| "concrete old-ring buffer")?;
    if session.receive_epoch == old_epoch
        || session.ap_receive_current(old_epoch) != Ok(false)
        || old_tx.try_send(Frame::new(buffer, 60)).is_ok()
        || session
            .ap_owner
            .as_ref()
            .unwrap()
            .peers
            .get(peer)
            .unwrap()
            .authorized
    {
        return Err("key commit revived an old ring/copy or granted a peer port");
    }
    let mut authorized = peer_cfg;
    authorized.authorized = Some(true);
    execute(
        &mut session,
        &binding,
        bound(&binding, &source)?,
        Request::SetStation(authorized),
    )
    .map_err(|_| "concrete explicit peer authorization")?;
    source.0.store(false, Ordering::Release);
    emit_management(&mut session, &binding, &auth)?;
    if source.1.lock().len() != 1 || !binding.iface.link_up() {
        return Err("closed RX source got a native event or destroyed completed BSS");
    }
    let successor = Arc::new(Source::new());
    let authority = bound(&binding, &successor)?;
    run(binding
        .iface
        .register_mgmt_frame_ap_async(&authority, 0xb0, vec![0, 0]))
    .map_err(|_| "closed registration blocked actual successor source")?;
    drop(authority);
    emit_management(&mut session, &binding, &auth)?;
    if successor.1.lock().len() != 1 || source.1.lock().len() != 1 {
        return Err("management event retargeted an old source or bypassed current filter");
    }
    execute(
        &mut session,
        &binding,
        bound(&binding, &successor)?,
        Request::Stop,
    )
    .map_err(|_| "concrete secure STOP")?;
    Ok(())
}
fn mt76_ap_concrete_key_epoch_rings_and_exact_source_management_delivery() -> TestResult {
    observed(keys_and_events())
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_concrete_key_epoch_rings_and_exact_source_management_delivery
);
#[path = "p2p_group_tests.rs"]
mod p2p_group;
