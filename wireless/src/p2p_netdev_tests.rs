//! Public CLIENT/GO opt-ins retain the original netdev and deferred owner.
use super::*;

fn go(fixture: &Fixture) {
    fixture.radio.mode.store(9, Ordering::Release);
    fixture.radio.p2p_roles.store(true, Ordering::Release);
    fixture.radio.go_power.store(true, Ordering::Release);
}
fn send(fixture: &Fixture, bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let _ = crate::nl80211::register();
    build_replies_with_endpoint(
        bytes,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&fixture.admin),
            portid: 77,
            ..RequestContext::default()
        },
        fixture.source.clone(),
    )
    .map_err(|_| "P2P netdev public request framing")
}
fn power_request(fixture: &Fixture, attrs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut raw = Vec::new();
    attr(&mut raw, 3, &fixture.ifindex.to_ne_bytes());
    for (id, bytes) in attrs {
        attr(&mut raw, *id, bytes);
    }
    message(fixture, 25, &raw)
}
fn rejected_power() -> Result<(), &'static str> {
    for variant in 0..10 {
        let fixture = fixture()?;
        go(&fixture);
        let mut attrs: Vec<(u16, &[u8])> = alloc::vec![(162, &[0])];
        let errno: i32 = match variant {
            0 => {
                attrs = alloc::vec![(162, &[128])];
                22
            }
            1 => {
                attrs = alloc::vec![(163, &[2])];
                22
            }
            2 => {
                attrs = alloc::vec![(162, &[0, 0])];
                22
            }
            3 => {
                attrs.push((162, &[1]));
                22
            }
            4 => {
                fixture.radio.mode.store(3, Ordering::Release);
                22
            }
            5 => {
                fixture.radio.mode.store(8, Ordering::Release);
                22
            }
            6 => {
                fixture.radio.go_power.store(false, Ordering::Release);
                95
            }
            7 => {
                fixture.radio.p2p_roles.store(false, Ordering::Release);
                95
            }
            8 => {
                attrs.clear();
                95
            }
            _ => {
                fixture
                    .admin
                    .set_link(false)
                    .map_err(|_| "GO initially DOWN")?;
                100
            }
        };
        let replies = send(&fixture, &power_request(&fixture, &attrs))?;
        if replies.len() != 1
            || replies[0][16..20] != (-errno).to_ne_bytes()
            || fixture.radio.start_polls.load(Ordering::Acquire) != 0
            || fixture.radio.go_seen.lock().is_some()
        {
            return Err("GO malformed/unsupported setting reached native callback");
        }
    }
    Ok(())
}
fn smoke_nl80211_go_power_bounds_and_explicit_role_optin() -> TestResult {
    rejected_power().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/p2p_netdev",
    smoke_nl80211_go_power_bounds_and_explicit_role_optin
);

fn power_lifecycle() -> Result<(), &'static str> {
    // START carries both actual initial values without granting a live owner
    // before the native callback has completed.
    {
        let fixture = fixture()?;
        go(&fixture);
        let mut start = request(&fixture);
        attr(&mut start, 162, &[127]);
        attr(&mut start, 163, &[1]);
        let len = start.len() as u32;
        start[..4].copy_from_slice(&len.to_ne_bytes());
        if !send(&fixture, &start)?.is_empty() {
            return Err("GO START early ACK");
        }
        narf_scheduler::poll_one_round();
        if fixture.radio.start_polls.load(Ordering::Acquire) == 0
            || fixture.radio.starts.load(Ordering::Acquire) != 0
            || fixture.radio.go_seen.lock().is_some()
        {
            return Err("GO START settings promoted before actual receipt");
        }
        finish(&fixture);
        check(&fixture, 0, 1)?;
        if *fixture.radio.go_seen.lock()
            != Some(crate::P2pGoPowerSave {
                ctwindow_tu: Some(127),
                opportunistic: Some(true),
            })
        {
            return Err("GO START lost actual CTWindow/OPPPS settings");
        }
    }
    for boundary in 0..6 {
        let fixture = fixture()?;
        go(&fixture);
        // Explicit zero/false resets differ from omitted values. Each update
        // supplies one field so the other remains None in the native request.
        let (attrs, expected): (Vec<(u16, &[u8])>, _) = if boundary % 2 == 0 {
            (
                alloc::vec![(162, &[0])],
                crate::P2pGoPowerSave {
                    ctwindow_tu: Some(0),
                    opportunistic: None,
                },
            )
        } else {
            (
                alloc::vec![(163, &[0])],
                crate::P2pGoPowerSave {
                    ctwindow_tu: None,
                    opportunistic: Some(false),
                },
            )
        };
        if !send(&fixture, &power_request(&fixture, &attrs))?.is_empty() {
            return Err("GO SET_BSS early ACK");
        }
        narf_scheduler::poll_one_round();
        if fixture.radio.start_polls.load(Ordering::Acquire) == 0
            || !fixture.source.1.lock().is_empty()
            || fixture.radio.go_seen.lock().is_some()
        {
            return Err("GO SET_BSS escaped held native receipt");
        }
        match boundary {
            1 => fixture.daemon.revoke(),
            2 => {
                fixture.radio.mode.store(2, Ordering::Release);
                fixture.radio.generation.store(2, Ordering::Release);
                fixture.radio.mode.store(9, Ordering::Release);
                fixture.radio.generation.store(3, Ordering::Release);
            }
            3 => fixture.source.0.store(false, Ordering::Release),
            4 => {
                fixture.admin.set_link(false).map_err(|_| "GO DOWN")?;
                fixture.admin.set_link(true).map_err(|_| "GO UP")?;
            }
            _ => (),
        }
        finish(&fixture);
        let success = matches!(boundary, 0 | 5);
        if boundary == 3 {
            if !fixture.source.1.lock().is_empty()
                || fixture.radio.start_drops.load(Ordering::Acquire) != 1
            {
                return Err("GO closed source published terminal ACK or leaked waiter");
            }
        } else {
            check(&fixture, if success { 0 } else { 1 }, u32::from(success))?;
        }
        if *fixture.radio.go_seen.lock() != success.then_some(expected) {
            return Err("GO old source/role/link promoted power-save state");
        }
    }
    Ok(())
}
fn smoke_nl80211_go_initial_and_live_power_wait_for_current_terminal_owner() -> TestResult {
    power_lifecycle().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/p2p_netdev",
    smoke_nl80211_go_initial_and_live_power_wait_for_current_terminal_owner
);

fn management() -> Result<(), &'static str> {
    for mode in [8, 9] {
        for register in [false, true] {
            for boundary in 0..4 {
                let fixture = fixture()?;
                fixture.radio.mode.store(mode, Ordering::Release);
                fixture.radio.p2p_roles.store(true, Ordering::Release);
                fixture.radio.p2p_mgmt.store(true, Ordering::Release);
                // The independent managed2 marker stays false.
                if fixture.radio.async_radio_management_tx_control()
                    || fixture.radio.async_radio_management_rx_control()
                {
                    return Err("P2P fixture inherited managed marker");
                }
                let bytes = if register {
                    let mut attrs = Vec::new();
                    attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
                    attr(&mut attrs, 101, &0xd0u16.to_ne_bytes());
                    attr(&mut attrs, 91, &[4, 9, 0x50, 0x6f, 0x9a, 9]);
                    message(&fixture, 58, &attrs)
                } else {
                    management_request(&fixture)
                };
                if !send(&fixture, &bytes)?.is_empty() {
                    return Err("P2P management early reply");
                }
                narf_scheduler::poll_one_round();
                if fixture.radio.start_polls.load(Ordering::Acquire) == 0
                    || !fixture.source.1.lock().is_empty()
                    || fixture.radio.management_registration.lock().is_some()
                    || fixture.radio.mgmt_cookie.load(Ordering::Acquire) != 0
                {
                    return Err("P2P management skipped retained native callback");
                }
                match boundary {
                    1 => {
                        fixture.radio.generation.store(2, Ordering::Release);
                    }
                    2 => fixture.daemon.revoke(),
                    3 => {
                        fixture.admin.set_link(false).map_err(|_| "P2P DOWN")?;
                        fixture.admin.set_link(true).map_err(|_| "P2P UP")?;
                    }
                    _ => (),
                }
                // Radio fixture's scheduled callback has a separate owner;
                // both types retain the same actual source/mode generation.
                fixture.radio.start_ready.store(true, Ordering::Release);
                for _ in 0..16 {
                    narf_scheduler::poll_one_round();
                }
                let registered = fixture.radio.management_registration.lock().clone();
                let sent = fixture.radio.mgmt_cookie.load(Ordering::Acquire);
                if boundary == 0 {
                    if register {
                        if registered != Some((0xd0, alloc::vec![4, 9, 0x50, 0x6f, 0x9a, 9])) {
                            return Err("P2P registration lost exact management filter");
                        }
                    } else if sent == 0 {
                        return Err("P2P FRAME lacked actual terminal callback");
                    }
                    if fixture.source.1.lock().is_empty() {
                        return Err("P2P terminal reply absent");
                    }
                } else if registered.is_some() || sent != 0 {
                    return Err("P2P management survived source or role ABA");
                }
            }
        }
    }
    Ok(())
}
fn smoke_nl80211_client_go_management_uses_explicit_mode_and_native_receipt() -> TestResult {
    management().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/p2p_netdev",
    smoke_nl80211_client_go_management_uses_explicit_mode_and_native_receipt
);
