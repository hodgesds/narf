//! Original generic-netlink source/admin/AP authority and deferred callback.
//! The fixture counter is explicit protocol state, never a hardware PN claim.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};

const SEQUENCE: u32 = 0x4b53_4551;
fn attr(out: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    out.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(bytes);
    out.resize((out.len() + 3) & !3, 0);
}
fn raw(f: &Fixture, command: u8) -> Result<Vec<Vec<u8>>, &'static str> {
    let _ = crate::nl80211::register();
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &f.ifindex.to_ne_bytes());
    if command == 9 {
        attr(&mut attrs, 8, &[1]);
    }
    let mut request = Vec::new();
    request.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    request.extend_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    request.extend_from_slice(&5u16.to_ne_bytes());
    request.extend_from_slice(&SEQUENCE.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(&[command, 1, 0, 0]);
    request.extend_from_slice(&attrs);
    build_replies_with_endpoint(
        &request,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&f.admin),
            portid: 77,
            ..RequestContext::default()
        },
        f.source.clone(),
    )
    .map_err(|_| "GET_KEY dispatcher framing")
}
fn issue(f: &Fixture) -> Result<(), &'static str> {
    let replies = raw(f, 9)?;
    if !replies.is_empty() || f.radio.key_sequence_polls.load(Ordering::Acquire) != 0 {
        return Err("GET_KEY returned or polled before deferred admission");
    }
    narf_scheduler::poll_one_round();
    if f.radio.key_sequence_polls.load(Ordering::Acquire) == 0 || !f.source.1.lock().is_empty() {
        return Err("GET_KEY callback did not retain its original pending result");
    }
    Ok(())
}
fn pump(f: &Fixture) {
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if f.radio.key_sequence_drops.load(Ordering::Acquire) != 0 {
            break;
        }
    }
}
fn find(bytes: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = usize::from(u16::from_ne_bytes(bytes[at..at + 2].try_into().ok()?));
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into().ok()?);
        if len < 4 || at + len > bytes.len() {
            return None;
        }
        if kind & 0x3fff == wanted {
            return Some(&bytes[at + 4..at + len]);
        }
        at += (len + 3) & !3;
    }
    None
}
fn ap_get_key_defers_and_reports_only_actual_allocated_transmit_sequence() -> TestResult {
    for pn in [0, 0x0605_0403_0201, (1u64 << 48) - 1] {
        let f = match fixture() {
            Ok(f) => f,
            Err(error) => return TestResult::Fail(error),
        };
        f.radio
            .key_sequence_supported
            .store(true, Ordering::Release);
        let expected_wdev = (u64::from(crate::registry::wiphy_index(f.radio.wiphy_id()).unwrap())
            << 32)
            | u64::from(f.ifindex);
        if let Err(error) = issue(&f) {
            return TestResult::Fail(error);
        }
        // Allocation can advance while the source-bound callback awaits its
        // native lock. The reply snapshots this actual counter, not an RSC
        // cached at request admission or an unconditional zero.
        f.radio.key_sequence_pn.store(pn, Ordering::Release);
        f.radio.key_sequence_ready.store(true, Ordering::Release);
        pump(&f);
        let messages = f.source.1.lock();
        let reports: Vec<_> = messages
            .iter()
            .filter(|m| m.len() >= 20 && m[4..6] == crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes())
            .collect();
        if reports.len() != 1
            || reports[0][16] != 11
            || reports[0][8..12] != SEQUENCE.to_ne_bytes()
            || f.radio.key_sequence_drops.load(Ordering::Acquire) != 1
        {
            return TestResult::Fail("GET_KEY lost its exact source, sequence or native result");
        }
        let attrs = &reports[0][20..];
        let expected = pn.to_le_bytes();
        let Some(key) = find(attrs, 80) else {
            return TestResult::Fail("GET_KEY lacks Linux key nest");
        };
        if find(attrs, 10) != Some(&expected[..6])
            || find(attrs, 153) != Some(&expected_wdev.to_ne_bytes()[..])
            || find(key, 4) != Some(&expected[..6])
            || find(attrs, 7).is_some()
            || find(key, 1).is_some()
        {
            return TestResult::Fail("GET_KEY PN changed or a temporal key was exported");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211/ap-key",
    ap_get_key_defers_and_reports_only_actual_allocated_transmit_sequence
);

fn ap_get_key_pending_reply_cannot_survive_original_authority_or_role_loss() -> TestResult {
    for change in 0..6 {
        let f = match fixture() {
            Ok(f) => f,
            Err(error) => return TestResult::Fail(error),
        };
        f.radio
            .key_sequence_supported
            .store(true, Ordering::Release);
        if let Err(error) = issue(&f) {
            return TestResult::Fail(error);
        }
        match change {
            0 => f.cap.revoke(),
            1 => f.daemon.revoke(),
            2 => {
                f.radio.generation.fetch_add(1, Ordering::AcqRel);
            }
            3 => f.radio.mode.store(2, Ordering::Release),
            4 => {
                narf_net::iface::set_link_state(f.radio.name(), false);
            }
            _ => f.source.0.store(false, Ordering::Release),
        }
        f.radio.key_sequence_ready.store(true, Ordering::Release);
        pump(&f);
        if f.radio.key_sequence_drops.load(Ordering::Acquire) != 1 {
            return TestResult::Fail("GET_KEY pending owner was not cancelled on authority loss");
        }
        let messages = f.source.1.lock();
        if messages
            .iter()
            .any(|m| m.len() >= 20 && m[4..6] == crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes())
            || change == 5 && !messages.is_empty()
        {
            return TestResult::Fail("GET_KEY disclosed a stale result or rebound source reply");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211/ap-key",
    ap_get_key_pending_reply_cannot_survive_original_authority_or_role_loss
);

fn ap_get_key_raw_advertisement_and_dispatch_require_the_native_opt_in() -> TestResult {
    for supported in [false, true] {
        let f = match fixture() {
            Ok(f) => f,
            Err(error) => return TestResult::Fail(error),
        };
        f.radio
            .key_sequence_supported
            .store(supported, Ordering::Release);
        let replies = match raw(&f, 1) {
            Ok(replies) => replies,
            Err(error) => return TestResult::Fail(error),
        };
        let wiphy = replies.iter().find(|reply| {
            reply.len() >= 20 && reply[4..6] == crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes()
        });
        let Some(commands) = wiphy.and_then(|reply| find(&reply[20..], 50)) else {
            return TestResult::Fail("raw GET_WIPHY lacks supported command inventory");
        };
        let advertises = commands
            .chunks_exact(8)
            .any(|command| command[4..8] == 9u32.to_ne_bytes());
        if advertises != supported {
            return TestResult::Fail("raw GET_WIPHY bypassed the key-sequence capability opt-in");
        }
        if supported {
            f.radio.mode.store(2, Ordering::Release);
        }
        let replies = match raw(&f, 9) {
            Ok(replies) => replies,
            Err(error) => return TestResult::Fail(error),
        };
        if replies.len() != 1
            || replies[0].len() < 20
            || replies[0][16..20] != (-95i32).to_ne_bytes()
            || f.radio.key_sequence_polls.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("GET_KEY entered a non-opted-in or non-AP native getter");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211/ap-key",
    ap_get_key_raw_advertisement_and_dispatch_require_the_native_opt_in
);
