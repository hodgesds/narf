//! Actual generic-netlink permission/namespace/WDEV resolution and deferred
//! callback boundaries. Native BSS/CNM receipts have separate MT76 tests.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};

pub(super) fn attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize((out.len() + 3) & !3, 0);
}
fn send(
    child: &Child,
    source: Arc<dyn narf_net::netlink_generic::DeferredReplySink>,
    command: u8,
    extra: &[(u16, &[u8])],
) -> Result<Vec<Vec<u8>>, &'static str> {
    send_with_admin(child, source, command, extra, &child.admin)
}
pub(super) fn send_with_admin(
    child: &Child,
    source: Arc<dyn narf_net::netlink_generic::DeferredReplySink>,
    command: u8,
    extra: &[(u16, &[u8])],
    admin: &AdminHandle,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let _ = crate::nl80211::register();
    let mut attrs = Vec::new();
    attr(&mut attrs, 153, &child.registration.id().to_ne_bytes());
    for (kind, value) in extra {
        attr(&mut attrs, *kind, value);
    }
    let mut message = alloc::vec![0;20];
    message[..4].copy_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message[6..8].copy_from_slice(&5u16.to_ne_bytes());
    message[8..12].copy_from_slice(&0x7610_cafeu32.to_ne_bytes());
    message[16] = command;
    message[17] = 1;
    message.extend_from_slice(&attrs);
    build_replies_with_endpoint(
        &message,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(admin),
            net_ns_id: child.registration.namespace(),
            portid: 77,
            ..RequestContext::default()
        },
        source,
    )
    .map_err(|_| "actual P2P netlink framing")
}
fn source() -> Arc<Source> {
    Arc::new(Source(
        AtomicBool::new(true),
        IrqSafeSpinLock::new(Vec::new()),
    ))
}
pub(super) fn complete(child: &Child) {
    child.radio.inner.start_ready.store(true, Ordering::Release);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
    }
}
fn receipt() -> Result<(), &'static str> {
    for command in [89, 90, 55, 56] {
        let parent = fixture()?;
        let child = child(&parent, None, 27)?;
        let source = source();
        let frequency = 2412u32.to_ne_bytes();
        let duration = 30u32.to_ne_bytes();
        let cookie = 1u64.to_ne_bytes();
        let extras = match command {
            55 => alloc::vec![(38, &frequency[..]), (87, &duration[..])],
            56 => alloc::vec![(88, &cookie[..])],
            _ => Vec::new(),
        };
        if !send(&child, source.clone(), command, &extras)?.is_empty() {
            return Err("P2P callback acknowledged before native terminal completion");
        }
        narf_scheduler::poll_one_round();
        if child.radio.inner.start_polls.load(Ordering::Acquire) == 0
            || child.radio.inner.starts.load(Ordering::Acquire) != 0
            || !source.1.lock().is_empty()
            || child.radio.link_up()
            || narf_net::iface::lookup(child.radio.name()).is_some()
        {
            return Err(
                "control-only P2P pending callback invented a terminal receipt or netdev UP",
            );
        }
        complete(&child);
        if child.radio.inner.starts.load(Ordering::Acquire) != 1
            || child.radio.inner.start_drops.load(Ordering::Acquire) != 1
        {
            return Err("P2P borrowed callback was not retired exactly once");
        }
        let messages = source.1.lock();
        let ack = messages
            .iter()
            .find(|m| m.len() >= 20 && m[4..6] == 2u16.to_ne_bytes())
            .ok_or("P2P terminal ACK missing")?;
        if ack[16..20] != 0i32.to_ne_bytes() || ack[8..12] != 0x7610_cafeu32.to_ne_bytes() {
            return Err("P2P terminal ACK lost original sequence/result");
        }
        if command == 55 {
            let reply = messages
                .iter()
                .find(|m| m.len() >= 20 && m[16] == 55)
                .ok_or("native ROC terminal cookie reply missing")?;
            if value(&reply[20..], 88).is_none_or(|cookie| cookie == 0u64.to_ne_bytes()) {
                return Err("native ROC replied without its nonzero admitted cookie");
            }
        }
    }
    Ok(())
}
fn control_only_p2p_start_stop_and_roc_wait_for_terminal_callbacks() -> TestResult {
    receipt().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_p2p_start_stop_and_roc_wait_for_terminal_callbacks
);

fn lost() -> Result<(), &'static str> {
    for cause in 0..4 {
        let parent = fixture()?;
        let child = child(&parent, None, 27)?;
        let source = source();
        if !send(&child, source.clone(), 89, &[])?.is_empty() {
            return Err("P2P lost-source admission");
        }
        narf_scheduler::poll_one_round();
        match cause {
            0 => parent.daemon.revoke(),
            1 => source.0.store(false, Ordering::Release),
            2 => {
                crate::registry::unregister_control(child.registration, child.radio.as_ref());
            }
            _ => {
                child.radio.inner.generation.fetch_add(1, Ordering::AcqRel);
            }
        }
        complete(&child);
        if child.radio.inner.starts.load(Ordering::Acquire) != 0
            || child.radio.inner.start_drops.load(Ordering::Acquire) != 1
            || source
                .1
                .lock()
                .iter()
                .any(|message| message.len() >= 20 && message[16..20] == 0i32.to_ne_bytes())
        {
            return Err("stale source/grant/WDEV generation completed a P2P operation");
        }
    }
    Ok(())
}
fn control_only_p2p_pending_operations_refuse_source_grant_and_registration_loss() -> TestResult {
    lost().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_p2p_pending_operations_refuse_source_grant_and_registration_loss
);

fn selector() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = child(&parent, None, 27)?;
    for (command, extras) in [
        (89, alloc::vec![(3, 1u32.to_ne_bytes().to_vec())]),
        (56, alloc::vec![(88, 0u64.to_ne_bytes().to_vec())]),
    ] {
        let refs: Vec<_> = extras
            .iter()
            .map(|(kind, value)| (*kind, value.as_slice()))
            .collect();
        let replies = send(&child, source(), command, &refs)?;
        if replies.len() != 1
            || replies[0].len() < 20
            || replies[0][16..20] != (-22i32).to_ne_bytes()
        {
            return Err("P2P accepted fabricated IFINDEX or invalid native cookie");
        }
    }
    if child.radio.inner.start_polls.load(Ordering::Acquire) != 0 {
        return Err("invalid P2P selector reached native callback");
    }
    let first = source();
    if !send(&child, first.clone(), 89, &[])?.is_empty() {
        return Err("P2P exclusive start admission");
    }
    let competing = send(&child, source(), 90, &[])?;
    if competing.len() != 1 || competing[0][16..20] != (-16i32).to_ne_bytes() {
        return Err("P2P competing stop bypassed retained native serialization");
    }
    complete(&child);
    let second = source();
    if !send(&child, second.clone(), 90, &[])?.is_empty() {
        return Err("P2P terminal lease not released");
    }
    complete(&child);
    if child.radio.inner.starts.load(Ordering::Acquire) != 2 || second.1.lock().is_empty() {
        return Err("P2P successor could not use the actually retired lease");
    }
    Ok(())
}
fn control_only_p2p_selector_and_exclusive_native_lease_are_enforced() -> TestResult {
    selector().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_p2p_selector_and_exclusive_native_lease_are_enforced
);
