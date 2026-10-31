//! Actual delegated grants, netlink parser and exact-source deferred ACKs.
//! The held callback models only the driver boundary; native Sc firmware
//! scheduling, cancellation and DMA ownership have separate driver fixtures.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};

impl Radio {
    pub(super) async fn scheduled_callback(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), i32> {
        struct Waiter<'a>(&'a AtomicU32);
        impl Drop for Waiter<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let _waiter = Waiter(&self.start_drops);
        core::future::poll_fn(|cx| {
            authority.check_for(self).map_err(|_| 1)?;
            authority.require_link().map_err(|_| 1)?;
            self.start_polls.fetch_add(1, Ordering::AcqRel);
            if self.start_ready.load(Ordering::Acquire) {
                core::task::Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        })
        .await
    }
}
static CAPTURING: AtomicBool = AtomicBool::new(false);
static EVENTS: IrqSafeSpinLock<Vec<(u64, u32, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
fn event(namespace: u64, group: u32, message: &[u8]) {
    if CAPTURING.load(Ordering::Acquire)
        && group == 18
        && message
            .get(16)
            .is_some_and(|cmd| matches!(cmd, 75 | 77 | 78))
    {
        EVENTS.lock().push((namespace, group, message.to_vec()));
    }
}
struct Events(Option<fn(u64, u32, &[u8])>);
impl Events {
    fn install() -> Self {
        EVENTS.lock().clear();
        CAPTURING.store(true, Ordering::Release);
        Self(narf_net::netlink_generic::install_event_sink(event))
    }
}
impl Drop for Events {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::Release);
        if let Some(sink) = self.0 {
            narf_net::netlink_generic::install_event_sink(sink);
        }
        EVENTS.lock().clear();
    }
}
fn fixture_scheduled(native: bool) -> Result<Fixture, &'static str> {
    let fixture = fixture()?;
    fixture.radio.mode.store(2, Ordering::Release);
    fixture.radio.generation.store(2, Ordering::Release);
    fixture.radio.sched_supported.store(true, Ordering::Release);
    fixture.radio.sched_native.store(native, Ordering::Release);
    Ok(fixture)
}
fn attr(bytes: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    bytes.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
fn request(fixture: &Fixture, command: u8, sequence: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    attr(&mut attrs, 3, &fixture.ifindex.to_ne_bytes());
    if command == 75 {
        let mut one = Vec::new();
        attr(&mut one, 1, b"scheduled-proof");
        let mut matches = Vec::new();
        attr(&mut matches, 0x8001, &one);
        attr(&mut attrs, 0x8084, &matches); // SCHED_SCAN_MATCH132
        let mut one = Vec::new();
        attr(&mut one, 1, &30u32.to_ne_bytes());
        let mut plans = Vec::new();
        attr(&mut plans, 0x8001, &one);
        attr(&mut attrs, 0x80e1, &plans); // SCHED_SCAN_PLANS225
    }
    let mut message = Vec::new();
    message.extend_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message.extend_from_slice(&5u16.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&77u32.to_ne_bytes());
    message.extend_from_slice(&[command, 1, 0, 0]);
    message.extend_from_slice(&attrs);
    message
}
fn dispatch(fixture: &Fixture, command: u8, sequence: u32) -> Result<Vec<Vec<u8>>, &'static str> {
    let _ = crate::nl80211::register();
    build_replies_with_endpoint(
        &request(fixture, command, sequence),
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&fixture.admin),
            portid: 77,
            ..RequestContext::default()
        },
        fixture.source.clone(),
    )
    .map_err(|_| "scheduled async actual generic-netlink request")
}
fn pending(fixture: &Fixture, command: u8, sequence: u32) -> Result<(), &'static str> {
    let before = fixture.radio.start_polls.load(Ordering::Acquire);
    if !dispatch(fixture, command, sequence)?.is_empty()
        || fixture.radio.start_polls.load(Ordering::Acquire) != before
    {
        return Err("scheduled request polled or acknowledged before deferred admission");
    }
    narf_scheduler::poll_one_round();
    if fixture.radio.start_polls.load(Ordering::Acquire) == before
        || !fixture.source.1.lock().is_empty()
        || !EVENTS.lock().is_empty()
    {
        return Err("scheduled queued callback published premature ACK/event");
    }
    Ok(())
}
fn finish(fixture: &Fixture, drops: u32) {
    fixture.radio.start_ready.store(true, Ordering::Release);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if fixture.radio.start_drops.load(Ordering::Acquire) == drops {
            break;
        }
    }
}
fn terminal(fixture: &Fixture, sequence: u32, errno: i32) -> Result<(), &'static str> {
    let messages = fixture.source.1.lock();
    if messages.len() != 1
        || messages[0].get(16..20) != Some(&(-errno).to_ne_bytes())
        || messages[0].get(8..12) != Some(&sequence.to_ne_bytes())
    {
        return Err("scheduled terminal ACK lost exact sequence/source/errno");
    }
    Ok(())
}
fn completion() -> Result<(), &'static str> {
    let _events = Events::install();
    let fixture = fixture_scheduled(true)?;
    pending(&fixture, 75, 0x5301)?;
    let competing = dispatch(&fixture, 76, 0x5302)?;
    if competing.len() != 1 || competing[0].get(16..20) != Some(&(-16i32).to_ne_bytes()) {
        return Err("scheduled native lease failed synchronous competing admission");
    }
    finish(&fixture, 1);
    terminal(&fixture, 0x5301, 0)?;
    let parsed = fixture
        .radio
        .sched_request
        .lock()
        .clone()
        .ok_or("scheduled native parsed request absent")?;
    if parsed.matches.len() != 1
        || parsed.matches[0].ssid != b"scheduled-proof"
        || parsed.plans.len() != 1
        || parsed.plans[0].interval_secs != 30
        || fixture.radio.sched_started.load(Ordering::Acquire) != 1
        || EVENTS
            .lock()
            .as_slice()
            .iter()
            .map(|entry| entry.2[16])
            .collect::<Vec<_>>()
            != [75]
    {
        return Err("scheduled native start event/parsed callback completion mismatch");
    }
    fixture.source.1.lock().clear();
    EVENTS.lock().clear();
    fixture.radio.start_ready.store(false, Ordering::Release);
    pending(&fixture, 76, 0x5303)?;
    finish(&fixture, 2);
    terminal(&fixture, 0x5303, 0)?;
    if fixture.radio.sched_stopped.load(Ordering::Acquire) != 1
        || EVENTS
            .lock()
            .as_slice()
            .iter()
            .map(|entry| entry.2[16])
            .collect::<Vec<_>>()
            != [78]
    {
        return Err("scheduled stop event preceded or lost native terminal callback");
    }
    Ok(())
}
fn scheduled_native_start_stop_ack_and_events_wait_for_callback_and_real_lease() -> TestResult {
    completion().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/sched_scan_control",
    scheduled_native_start_stop_ack_and_events_wait_for_callback_and_real_lease
);

fn revocation() -> Result<(), &'static str> {
    let _events = Events::install();
    for boundary in 0..5 {
        let fixture = fixture_scheduled(true)?;
        pending(&fixture, 75, 0x5310 + boundary)?;
        match boundary {
            0 => fixture.daemon.revoke(),
            1 => {
                fixture
                    .admin
                    .move_to_net_ns(0x5301)
                    .map_err(|_| "scheduled actual namespace away")?;
                fixture
                    .admin
                    .move_to_net_ns(0)
                    .map_err(|_| "scheduled actual namespace return")?;
            }
            2 => {
                fixture.radio.mode.store(8, Ordering::Release);
                fixture.radio.generation.store(3, Ordering::Release);
                fixture.radio.mode.store(2, Ordering::Release);
                fixture.radio.generation.store(4, Ordering::Release);
            }
            3 => {
                narf_net::iface::set_link_state(fixture.radio.name(), false);
            }
            _ => fixture.source.0.store(false, Ordering::Release),
        }
        finish(&fixture, 1);
        if fixture.radio.sched_started.load(Ordering::Acquire) != 0
            || fixture.radio.start_drops.load(Ordering::Acquire) != 1
            || !EVENTS.lock().is_empty()
        {
            return Err(
                "scheduled pending callback survived revoked grant/source/mode/namespace/UP",
            );
        }
        if boundary != 4 {
            terminal(&fixture, 0x5310 + boundary, 1)?;
        } else if !fixture.source.1.lock().is_empty() {
            return Err("scheduled ACK reached closed original source");
        }
    }
    Ok(())
}
fn scheduled_native_pending_callback_keeps_actual_authority_and_source_current() -> TestResult {
    revocation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/sched_scan_control",
    scheduled_native_pending_callback_keeps_actual_authority_and_source_current
);

fn compatibility() -> Result<(), &'static str> {
    let _events = Events::install();
    let fixture = fixture_scheduled(false)?;
    let start = dispatch(&fixture, 75, 0x5321)?;
    let stop = dispatch(&fixture, 76, 0x5322)?;
    if start.len() != 1
        || stop.len() != 1
        || start[0].get(16..20) != Some(&0i32.to_ne_bytes())
        || stop[0].get(16..20) != Some(&0i32.to_ne_bytes())
        || fixture.radio.sched_started.load(Ordering::Acquire) != 1
        || fixture.radio.sched_stopped.load(Ordering::Acquire) != 1
        || fixture.radio.start_polls.load(Ordering::Acquire) != 0
        || fixture.radio.start_drops.load(Ordering::Acquire) != 0
    {
        return Err("scheduled async addition changed legacy synchronous callbacks/ACKs");
    }
    Ok(())
}
fn scheduled_legacy_sync_callbacks_keep_existing_admission_contract() -> TestResult {
    compatibility().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/sched_scan_control",
    scheduled_legacy_sync_callbacks_keep_existing_admission_contract
);
