//! Real delegated grants and registry generations for native radio control.
//! Native started-wdev/CNM/RF receipts are separate driver preconditions.
use super::super::{RadioControlAuthority, RadioInterfaceIdentity};
use super::*;
fn radio(fixture: &Fixture) -> Result<RadioControlAuthority, WirelessError> {
    RadioControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    )
}
fn p2p_device_identity() -> Result<(), &'static str> {
    let fixture = fixture()?;
    narf_net::iface::set_link_state(fixture.radio.name(), false);
    fixture.radio.mode.store(10, Ordering::Release);
    fixture.radio.generation.store(2, Ordering::Release);
    let authority = radio(&fixture).map_err(|_| "actual P2P-device radio source")?;
    let identity: RadioInterfaceIdentity = authority
        .identity()
        .map_err(|_| "P2P wdev identity without synthetic UP")?;
    let source = authority
        .event_authority()
        .map_err(|_| "actual radio source capture")?;
    if authority.check_for(fixture.radio.as_ref()).is_err()
        || identity.check_for(fixture.radio.as_ref()).is_err()
        || source.current().is_err()
        || narf_net::iface::lookup(fixture.radio.name())
            .is_none_or(|link| link.link_up || link.carrier)
        || ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .is_ok()
    {
        return Err("radio identity invented UP or relaxed AP-only admission");
    }
    // Capturing a wdev/source observation supplies no START_P2P_DEVICE,
    // CNM channel grant, frame or carrier. This test emits none of those.
    fixture.source.0.store(false, Ordering::Release);
    if authority.current() != Err(WirelessError::Denied)
        || source.current() != Err(WirelessError::Denied)
        || identity.current().is_err()
    {
        return Err("exact-source revocation confused with completed identity observation");
    }
    fixture
        .admin
        .move_to_net_ns(0x7661)
        .map_err(|_| "actual radio namespace transfer")?;
    fixture
        .admin
        .move_to_net_ns(0)
        .map_err(|_| "actual radio namespace return")?;
    if identity.current() != Err(WirelessError::Denied) {
        return Err("namespace away/back revived a P2P wdev identity");
    }
    Ok(())
}
fn typed_radio_p2p_device_identity_preserves_actual_down_and_ap_only_scope() -> TestResult {
    p2p_device_identity().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    typed_radio_p2p_device_identity_preserves_actual_down_and_ap_only_scope
);
fn station_and_lease() -> Result<(), &'static str> {
    let fixture = fixture()?;
    fixture.radio.mode.store(8, Ordering::Release);
    fixture.radio.generation.store(2, Ordering::Release);
    narf_net::iface::set_link_state(fixture.radio.name(), false);
    let authority = radio(&fixture).map_err(|_| "native client source bind")?;
    if authority.current().is_err()
        || authority.require_link() != Err(WirelessError::Denied)
        || authority.identity().is_ok()
    {
        return Err("station/client borrowed the no-UP P2P-device exception");
    }
    narf_net::iface::set_link_state(fixture.radio.name(), true);
    if authority.require_link().is_err() {
        return Err("current native client UP refused");
    }
    drop(authority);
    fixture.radio.mode.store(3, Ordering::Release);
    fixture.radio.generation.store(3, Ordering::Release);
    let authority = radio(&fixture)
        .map_err(|_| "native radio/AP common control bind")?
        .reserve()
        .map_err(|_| "native radio reservation")?;
    let retained = authority.clone();
    drop(authority);
    let competing = || {
        ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .and_then(ApControlAuthority::reserve)
    };
    if competing().err() != Some(WirelessError::Busy) {
        return Err("radio cancellation released a retained AP mutation reservation");
    }
    drop(retained);
    let _successor =
        competing().map_err(|_| "terminal radio lease did not release AP successor")?;
    Ok(())
}
fn typed_radio_client_up_and_shared_native_serialization_are_current() -> TestResult {
    station_and_lease().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    typed_radio_client_up_and_shared_native_serialization_are_current
);
fn revocation() -> Result<(), &'static str> {
    let fixture = fixture()?;
    let authority = radio(&fixture).map_err(|_| "native radio current AP bind")?;
    let source = authority
        .event_authority()
        .map_err(|_| "native radio typed event source")?;
    let other = super::fixture()?;
    let identity = authority
        .identity()
        .map_err(|_| "actual retained radio identity")?;
    let other_identity = radio(&other)
        .and_then(|source| source.identity())
        .map_err(|_| "other actual radio identity")?;
    if authority.check_for(other.radio.as_ref()) != Err(WirelessError::Denied)
        || authority.check_identity(&identity).is_err()
        || authority.check_identity(&other_identity) != Err(WirelessError::Denied)
        || authority.require_mode(10) != Err(WirelessError::Denied)
    {
        return Err("radio authority retargeted another registered concrete receiver");
    }
    fixture.daemon.revoke();
    if authority.current() != Err(WirelessError::Denied)
        || source.current() != Err(WirelessError::Denied)
    {
        return Err("native radio/event source survived actual delegated grant revocation");
    }
    Ok(())
}
fn typed_radio_and_event_sources_refuse_foreign_receiver_and_revoked_grants() -> TestResult {
    revocation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    typed_radio_and_event_sources_refuse_foreign_receiver_and_revoked_grants
);
fn namesake_fresh_bind() -> Result<(), &'static str> {
    let fixture = fixture()?;
    let name = String::from(fixture.radio.name());
    crate::registry::unregister(&name);
    narf_net::registry().unregister(&name);
    narf_net::iface::unregister(&name);
    let name = narf_net::iface::register(&name, fixture.radio.mac(), reject);
    let replacement = Arc::new(Radio::new(name.clone()));
    let net_cap = narf_net::registry()
        .register(
            &narf_net::bootstrap_authority(),
            Registered(replacement.clone()),
        )
        .map_err(|_| "fresh namesake typed device")?;
    let iface: Arc<dyn WirelessNetIface> = replacement;
    crate::registry::register(iface.clone());
    narf_net::iface::set_link_state(&name, true);
    let index = narf_net::iface::lookup(&name)
        .ok_or("fresh namesake legacy device")?
        .ifindex;
    if RadioControlAuthority::bind(
        fixture.admin.clone(),
        &iface,
        0,
        index,
        fixture.source.clone(),
    )
    .is_ok()
        || ApControlAuthority::bind(
            fixture.admin.clone(),
            &iface,
            0,
            index,
            fixture.source.clone(),
        )
        .is_ok()
    {
        return Err("old delegated admin freshly bound a new same-name radio/AP");
    }
    let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
        iface: net_cap,
        daemon: fixture.daemon,
    })
    .map_err(|_| "fresh namesake actual delegation")?
    .admin;
    if RadioControlAuthority::bind(admin.clone(), &iface, 0, index, fixture.source.clone()).is_err()
        || ApControlAuthority::bind(admin, &iface, 0, index, fixture.source.clone()).is_err()
    {
        return Err("fresh namesake source grant could not bind its actual radio/AP");
    }
    Ok(())
}
fn typed_radio_and_ap_fresh_bind_cannot_retarget_old_delegated_admin_to_namesake() -> TestResult {
    namesake_fresh_bind().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    typed_radio_and_ap_fresh_bind_cannot_retarget_old_delegated_admin_to_namesake
);
