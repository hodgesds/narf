//! Actual nl80211 parse/authority/dispatcher plus an explicitly held
//! interface callback. Native MT76 MCU and DMA receipts have separate tests.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};

fn attr(out: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    out.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(bytes);
    out.resize((out.len() + 3) & !3, 0);
}
fn request(fixture: &Fixture) -> Vec<u8> {
    let mut attrs = Vec::new();
    let index = narf_net::iface::lookup(fixture.radio.name())
        .unwrap()
        .ifindex;
    attr(&mut attrs, 3, &index.to_ne_bytes());
    attr(&mut attrs, 12, &100u32.to_ne_bytes());
    attr(&mut attrs, 13, &1u32.to_ne_bytes());
    attr(&mut attrs, 38, &2412u32.to_ne_bytes());
    attr(&mut attrs, 52, b"actual-async-ap");
    let mut head = alloc::vec![0; 36];
    head[0] = 0x80;
    head[4..10].fill(0xff);
    head[10..16].copy_from_slice(&fixture.radio.mac());
    head[16..22].copy_from_slice(&fixture.radio.mac());
    head[32..34].copy_from_slice(&100u16.to_le_bytes());
    attr(&mut attrs, 14, &head);
    let mut message = Vec::new();
    message.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message.extend_from_slice(&5u16.to_ne_bytes());
    message.extend_from_slice(&0x76ab_1234u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&[15, 1, 0, 0]);
    message.extend_from_slice(&attrs);
    message
}
fn start(fixture: &Fixture) -> Result<(), &'static str> {
    let _ = crate::nl80211::register();
    let replies = build_replies_with_endpoint(
        &request(fixture),
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&fixture.admin),
            portid: 77,
            ..RequestContext::default()
        },
        fixture.source.clone(),
    )
    .map_err(|_| "async AP native request framing")?;
    if !replies.is_empty() || fixture.radio.start_polls.load(Ordering::Acquire) != 0 {
        return Err("AP request acknowledged or polled before deferred admission");
    }
    narf_scheduler::poll_one_round();
    if fixture.radio.start_polls.load(Ordering::Acquire) == 0
        || fixture.radio.starts.load(Ordering::Acquire) != 0
        || !fixture.source.1.lock().is_empty()
    {
        return Err("AP callback did not remain pending without a native terminal ACK");
    }
    Ok(())
}
fn finish(fixture: &Fixture) {
    fixture.radio.start_ready.store(true, Ordering::Release);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if fixture.radio.start_drops.load(Ordering::Acquire) != 0 {
            break;
        }
    }
}
fn check(fixture: &Fixture, errno: i32, starts: u32) -> Result<(), &'static str> {
    if fixture.radio.start_drops.load(Ordering::Acquire) != 1
        || fixture.radio.starts.load(Ordering::Acquire) != starts
    {
        return Err("AP callback ownership did not retire in the expected generation");
    }
    let messages = fixture.source.1.lock();
    if messages.len() != 1
        || messages[0][16..20] != (-errno).to_ne_bytes()
        || messages[0][8..12] != 0x76ab_1234u32.to_ne_bytes()
    {
        return Err("AP terminal result lost its original errno, sequence or exact source");
    }
    Ok(())
}

fn nl80211_ap_ack_waits_for_the_actual_async_callback() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    finish(&fixture);
    check(&fixture, 0, 1).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_ack_waits_for_the_actual_async_callback
);

fn nl80211_ap_pending_callback_rechecks_delegated_capability() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    fixture.daemon.revoke();
    finish(&fixture);
    check(&fixture, 1, 0).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_pending_callback_rechecks_delegated_capability
);

fn nl80211_ap_pending_callback_cannot_survive_mode_aba() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    fixture.radio.mode.store(2, Ordering::Release);
    fixture.radio.generation.store(2, Ordering::Release);
    fixture.radio.mode.store(3, Ordering::Release);
    fixture.radio.generation.store(3, Ordering::Release);
    finish(&fixture);
    check(&fixture, 1, 0).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_pending_callback_cannot_survive_mode_aba
);

fn nl80211_ap_closed_source_cancels_its_borrowed_callback_without_success() -> TestResult {
    let fixture = match fixture() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    if let Err(error) = start(&fixture) {
        return TestResult::Fail(error);
    }
    fixture.source.0.store(false, Ordering::Release);
    finish(&fixture);
    if fixture.radio.starts.load(Ordering::Acquire) != 0
        || fixture.radio.start_drops.load(Ordering::Acquire) != 1
        || !fixture.source.1.lock().is_empty()
    {
        return TestResult::Fail(
            "closed source published AP state or retained its callback waiter",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_ap_closed_source_cancels_its_borrowed_callback_without_success
);

fn management_request(fixture: &Fixture) -> Vec<u8> {
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
    attr(&mut attrs, 38, &2412u32.to_ne_bytes());
    let mut frame = alloc::vec![0;30];
    frame[0] = 0xb0;
    frame[4..10].copy_from_slice(&[2, 0, 0, 0, 0x77, 1]);
    frame[10..16].copy_from_slice(&fixture.radio.mac());
    frame[16..22].copy_from_slice(&fixture.radio.mac());
    frame[26] = 2;
    attr(&mut attrs, 51, &frame);
    let mut message = request(fixture);
    message.truncate(20);
    message[16] = 59;
    message.extend_from_slice(&attrs);
    let len = message.len() as u32;
    message[..4].copy_from_slice(&len.to_ne_bytes());
    message
}
fn management_dispatch() -> Result<(), &'static str> {
    for boundary in 0..5 {
        let fixture = fixture()?;
        let _ = crate::nl80211::register();
        fixture
            .radio
            .mgmt_acked
            .store(boundary != 1, Ordering::Release);
        let replies = build_replies_with_endpoint(
            &management_request(&fixture),
            ReplyOptions::default(),
            RequestContext {
                admin: Some(&fixture.admin),
                portid: 77,
                ..RequestContext::default()
            },
            fixture.source.clone(),
        )
        .map_err(|_| "native AP FRAME dispatch")?;
        if !replies.is_empty() || fixture.radio.start_polls.load(Ordering::Acquire) != 0 {
            return Err("AP FRAME returned a cookie/ACK before native execution");
        }
        narf_scheduler::poll_one_round();
        if fixture.radio.start_polls.load(Ordering::Acquire) == 0
            || !fixture.source.1.lock().is_empty()
        {
            return Err("AP FRAME did not await its native TXS callback");
        }
        match boundary {
            2 => fixture.daemon.revoke(),
            3 => {
                fixture.radio.generation.store(2, Ordering::Release);
            }
            4 => fixture.source.0.store(false, Ordering::Release),
            _ => (),
        }
        finish(&fixture);
        let messages = fixture.source.1.lock();
        if boundary < 2 {
            let cookie = fixture.radio.mgmt_cookie.load(Ordering::Acquire);
            if cookie == 0
                || messages.len() != 2
                || messages[0][4..6] != crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes()
                || messages[0][16] != 59
                || messages[0][20..24] != [12, 0, 88, 0]
                || messages[0][24..32] != cookie.to_ne_bytes()
                || messages[1][16..20] != [0; 4]
                || fixture.radio.starts.load(Ordering::Acquire) != 1
            {
                return Err("AP FRAME terminal cookie/ACK lost native source/sequence/result");
            }
        } else if boundary == 4 {
            if !messages.is_empty() || fixture.radio.starts.load(Ordering::Acquire) != 0 {
                return Err("closed AP FRAME source received old output");
            }
        } else if messages.len() != 1
            || messages[0][4..6] != 2u16.to_ne_bytes()
            || messages[0][16..20] != (-1i32).to_ne_bytes()
            || fixture.radio.starts.load(Ordering::Acquire) != 0
        {
            return Err("revoked/replaced AP FRAME emitted a terminal cookie");
        }
        if fixture.radio.start_drops.load(Ordering::Acquire) != 1 {
            return Err("AP FRAME native waiter cancellation was not retired");
        }
    }
    Ok(())
}
fn nl80211_native_ap_frame_cookie_waits_for_current_terminal_callback() -> TestResult {
    management_dispatch().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_native_ap_frame_cookie_waits_for_current_terminal_callback
);

fn key_request(fixture: &Fixture, command: u8, index: u8, default: bool) -> Vec<u8> {
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
    attr(&mut attrs, 8, &[index]);
    if command == 11 {
        attr(&mut attrs, 9, &0x000fac04u32.to_ne_bytes());
        attr(&mut attrs, 7, &[0x5a; 16]);
        attr(&mut attrs, 10, &[0; 6]);
    }
    if default {
        attr(&mut attrs, 11, &[]);
    }
    let mut message = request(fixture);
    message.truncate(20);
    message[16] = command;
    message.extend_from_slice(&attrs);
    let len = message.len() as u32;
    message[..4].copy_from_slice(&len.to_ne_bytes());
    message
}
fn key_dispatch() -> Result<(), &'static str> {
    for boundary in 0..4 {
        let fixture = fixture()?;
        let _ = crate::nl80211::register();
        if boundary == 3 {
            fixture.radio.key_errno.store(2, Ordering::Release);
        }
        let replies = build_replies_with_endpoint(
            &key_request(&fixture, 11, 1, true),
            ReplyOptions::default(),
            RequestContext {
                admin: Some(&fixture.admin),
                portid: 77,
                ..RequestContext::default()
            },
            fixture.source.clone(),
        )
        .map_err(|_| "native AP key dispatch")?;
        if !replies.is_empty() || fixture.radio.start_polls.load(Ordering::Acquire) != 0 {
            return Err("AP key install acknowledged or ran at queue admission");
        }
        narf_scheduler::poll_one_round();
        if fixture.radio.start_polls.load(Ordering::Acquire) == 0
            || !fixture.source.1.lock().is_empty()
        {
            return Err("AP key did not await native installation receipt");
        }
        match boundary {
            1 => fixture.daemon.revoke(),
            2 => fixture.source.0.store(false, Ordering::Release),
            _ => (),
        }
        finish(&fixture);
        let messages = fixture.source.1.lock();
        if fixture.radio.start_drops.load(Ordering::Acquire) != 1 {
            return Err("native AP key future staging was not retired");
        }
        match boundary {
            0 => {
                if messages.len() != 1
                    || messages[0].len() != 36
                    || messages[0][16..20] != [0; 4]
                    || fixture.radio.key_installs.load(Ordering::Acquire) != 1
                    || fixture.radio.default_key.load(Ordering::Acquire) != 1
                {
                    return Err(
                        "native AP install/default-key ordering or secret-free terminal ACK",
                    );
                }
            }
            1 => {
                if messages.len() != 1
                    || messages[0][16..20] != (-1i32).to_ne_bytes()
                    || fixture.radio.key_installs.load(Ordering::Acquire) != 0
                {
                    return Err("revoked AP key request mutated native state");
                }
            }
            2 => {
                if !messages.is_empty() || fixture.radio.key_installs.load(Ordering::Acquire) != 0 {
                    return Err("closed AP key source received a stale completion");
                }
            }
            _ => {
                if messages.len() != 1
                    || messages[0][16..20] != (-2i32).to_ne_bytes()
                    || fixture.radio.default_key.load(Ordering::Acquire) != u32::MAX
                {
                    return Err("native key errno was rewritten or failed install selected a GTK");
                }
            }
        }
    }
    Ok(())
}
fn nl80211_native_ap_key_install_default_and_exact_errno_wait_for_receipt() -> TestResult {
    key_dispatch().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_native_ap_key_install_default_and_exact_errno_wait_for_receipt
);

fn message(fixture: &Fixture, command: u8, attrs: &[u8]) -> Vec<u8> {
    let mut m = request(fixture);
    m.truncate(20);
    m[16] = command;
    m.extend_from_slice(attrs);
    let len = m.len() as u32;
    m[..4].copy_from_slice(&len.to_ne_bytes());
    m
}
fn security_start(fixture: &Fixture, owner: bool) -> Vec<u8> {
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
    attr(&mut attrs, 12, &100u32.to_ne_bytes());
    attr(&mut attrs, 13, &1u32.to_ne_bytes());
    attr(&mut attrs, 38, &2412u32.to_ne_bytes());
    attr(&mut attrs, 159, &0u32.to_ne_bytes());
    attr(&mut attrs, 52, b"narf");
    let mut head = alloc::vec![0;36];
    head[0] = 0x80;
    head[4..10].fill(0xff);
    head[10..16].copy_from_slice(&fixture.radio.mac());
    head[16..22].copy_from_slice(&fixture.radio.mac());
    head[32] = 100;
    head[34] = 17;
    head.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    attr(&mut attrs, 14, &head);
    attr(
        &mut attrs,
        15,
        &[
            48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
        ],
    );
    attr(&mut attrs, 70, &[]);
    attr(&mut attrs, 53, &0u32.to_ne_bytes());
    attr(&mut attrs, 73, &0x000fac04u32.to_ne_bytes());
    attr(&mut attrs, 74, &0x000fac04u32.to_ne_bytes());
    attr(&mut attrs, 75, &2u32.to_ne_bytes());
    attr(&mut attrs, 76, &0x000fac02u32.to_ne_bytes());
    attr(&mut attrs, 68, &[]);
    attr(&mut attrs, 264, &[]);
    if owner {
        attr(&mut attrs, 204, &[]);
    }
    message(fixture, 15, &attrs)
}
fn settings_dispatch() -> Result<(), &'static str> {
    for owner in [false, true] {
        let fixture = fixture()?;
        let _ = crate::nl80211::register();
        let replies = build_replies_with_endpoint(
            &security_start(&fixture, owner),
            ReplyOptions::default(),
            RequestContext {
                admin: Some(&fixture.admin),
                portid: 77,
                ..RequestContext::default()
            },
            fixture.source.clone(),
        )
        .map_err(|_| "native secure START framing")?;
        if !owner {
            if replies.len() != 1
                || replies[0][16..20] != (-22i32).to_ne_bytes()
                || fixture.radio.start_polls.load(Ordering::Acquire) != 0
            {
                return Err("START_AP control port ignored required actual SOCKET_OWNER");
            }
            continue;
        }
        if !replies.is_empty() {
            return Err("secure START acknowledged before native callback");
        }
        narf_scheduler::poll_one_round();
        if !fixture.radio.settings_seen.load(Ordering::Acquire)
            || fixture.radio.start_polls.load(Ordering::Acquire) == 0
            || !fixture.source.1.lock().is_empty()
        {
            return Err(
                "secure START lost actual crypto/control metadata or emitted queued success",
            );
        }
        finish(&fixture);
        check(&fixture, 0, 1)?;
    }
    Ok(())
}
fn nl80211_native_ap_start_retains_crypto_and_actual_control_socket_settings() -> TestResult {
    settings_dispatch().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_native_ap_start_retains_crypto_and_actual_control_socket_settings
);

fn control_dispatch() -> Result<(), &'static str> {
    for boundary in 0..4 {
        let fixture = fixture()?;
        let _ = crate::nl80211::register();
        let mut attrs = Vec::new();
        attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
        attr(&mut attrs, 6, &[2, 0, 0, 0, 0x77, 1]);
        attr(&mut attrs, 102, &0x888eu16.to_ne_bytes());
        attr(&mut attrs, 51, &[2, 3, 0, 4, 1, 2, 3, 4]);
        attr(&mut attrs, 103, &[]);
        if boundary == 1 {
            attr(&mut attrs, 142, &[]);
        }
        let replies = build_replies_with_endpoint(
            &message(&fixture, 129, &attrs),
            ReplyOptions {
                cap_ack: true,
                ext_ack: true,
            },
            RequestContext {
                admin: Some(&fixture.admin),
                portid: 77,
                ..RequestContext::default()
            },
            fixture.source.clone(),
        )
        .map_err(|_| "native AP control dispatch")?;
        if !replies.is_empty() {
            return Err("AP control reported queued TX as completion");
        }
        narf_scheduler::poll_one_round();
        if fixture.radio.start_polls.load(Ordering::Acquire) == 0
            || !fixture.source.1.lock().is_empty()
        {
            return Err("AP control did not await native packet/status callback");
        }
        if boundary == 2 {
            fixture.daemon.revoke();
        } else if boundary == 3 {
            fixture.source.0.store(false, Ordering::Release);
        }
        finish(&fixture);
        let messages = fixture.source.1.lock();
        if fixture.radio.start_drops.load(Ordering::Acquire) != 1 {
            return Err("AP control callback cancellation did not retire staging");
        }
        match boundary {
            0 => {
                if messages.len() != 1
                    || messages[0][16..20] != [0; 4]
                    || messages[0].len() != 48
                    || messages[0][36..40] != [12, 0, 4, 0]
                    || messages[0][40..48] == [0; 8]
                    || fixture.radio.control_sends.load(Ordering::Acquire) != 1
                {
                    return Err(
                        "native control terminal extended-ACK cookie lost actual completion",
                    );
                }
            }
            1 => {
                if messages.len() != 1
                    || messages[0][16..20] != [0; 4]
                    || messages[0].len() != 36
                    || fixture.radio.control_sends.load(Ordering::Acquire) != 1
                {
                    return Err("DONT_WAIT AP control fabricated a status cookie");
                }
            }
            2 => {
                if messages.len() != 1
                    || messages[0][16..20] != (-1i32).to_ne_bytes()
                    || fixture.radio.control_sends.load(Ordering::Acquire) != 0
                {
                    return Err("revoked AP control request transmitted or acknowledged success");
                }
            }
            _ => {
                if !messages.is_empty() || fixture.radio.control_sends.load(Ordering::Acquire) != 0
                {
                    return Err("closed AP control source received old transmission results");
                }
            }
        }
    }
    Ok(())
}
fn nl80211_native_ap_control_port_terminal_cookie_and_cancellation_match_native_receipt(
) -> TestResult {
    control_dispatch().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_native_ap_control_port_terminal_cookie_and_cancellation_match_native_receipt
);

fn response_attr(message: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut rest = message.get(20..)?;
    while !rest.is_empty() {
        let head = rest.get(..4)?;
        let length = u16::from_ne_bytes(head[..2].try_into().ok()?) as usize;
        if length < 4 {
            return None;
        }
        let kind = u16::from_ne_bytes(head[2..4].try_into().ok()?) & 0x3fff;
        let value = rest.get(4..length)?;
        if kind == wanted {
            return Some(value);
        }
        rest = rest.get((length + 3) & !3..)?;
    }
    None
}
fn physical_ap_caps() -> Result<(), &'static str> {
    let fixture = fixture()?;
    let _ = crate::nl80211::register();
    fixture.radio.mode.store(2, Ordering::Release);
    fixture
        .radio
        .station_external
        .store(false, Ordering::Release);
    fixture.radio.station_sme.store(false, Ordering::Release);
    fixture
        .radio
        .station_handshake
        .store(true, Ordering::Release);
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
    let replies = build_replies_with_endpoint(
        &message(&fixture, 1, &attrs),
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&fixture.admin),
            portid: 77,
            ..RequestContext::default()
        },
        fixture.source.clone(),
    )
    .map_err(|_| "physical AP/STA GET_WIPHY")?;
    let reply = replies
        .iter()
        .find(|m| m.get(16) == Some(&crate::nl80211::NL80211_CMD_NEW_WIPHY))
        .ok_or("physical mode capabilities absent")?;
    let ext = response_attr(reply, 217).ok_or("physical mode ext features")?;
    let bit = |n: usize| ext.get(n / 8).is_some_and(|b| b & (1 << (n % 8)) != 0);
    let commands = response_attr(reply, 50).ok_or("physical commands")?;
    let have = |command: u32| {
        commands
            .chunks_exact(8)
            .any(|a| a[4..8] == command.to_ne_bytes())
    };
    if !bit(15)
        || !bit(26)
        || bit(42)
        || !bit(48)
        || !have(11)
        || !have(58)
        || !have(59)
        || have(37)
        || have(38)
    {
        return Err("AP authenticator capability replaced station SME/offload or invented no-preauth routing");
    }
    let mut connect = attrs;
    attr(&mut connect, 52, b"narf");
    attr(&mut connect, 68, &[]);
    attr(&mut connect, 264, &[]);
    attr(&mut connect, 204, &[]);
    let replies = build_replies_with_endpoint(
        &message(&fixture, 46, &connect),
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&fixture.admin),
            portid: 77,
            ..RequestContext::default()
        },
        fixture.source.clone(),
    )
    .map_err(|_| "station external admission")?;
    if replies.len() != 1 || replies[0][16..20] != (-95i32).to_ne_bytes() {
        return Err("physical AP control support admitted unsupported station external join");
    }
    Ok(())
}
fn nl80211_physical_ap_authenticator_preserves_station_offload_and_external_admission() -> TestResult
{
    physical_ap_caps().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    nl80211_physical_ap_authenticator_preserves_station_offload_and_external_admission
);
