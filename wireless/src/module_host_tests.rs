//! Tests for the native wireless family host: wire decoding, operation
//! lifecycle, session flow through the real `submit` / `poll` / `cancel` /
//! `close` entry points, wiphy publication, and event delivery through a
//! test-installed call gate.
//!
//! Sessions are built through the same `new_session` + `insert_session`
//! helpers `open` uses (a fabricated probe `BusDevice` would need a
//! `PhysAddr` this crate does not depend on); the broker-level open path
//! — owner/token/session validation and the publish gate — is covered by
//! the bus broker tests with their own host.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);
/// One fresh (owner, token, session id, MAC) per session test, so tests
/// never share a session or a shell name.
fn fresh_identity() -> (u64, u64, u64, [u8; 6]) {
    let n = NEXT_TEST.fetch_add(1, Ordering::AcqRel);
    (
        0xffff_ffff_7700 + n * 2,
        0xffff_ffff_7701 + n * 2,
        0x7700_0000 + n,
        [0x02, 0x00, 0x5e, 0x00, 0x53, 0x41 + (n as u8 & 0x3f)],
    )
}

fn insert_test_session(event: Option<ModuleWirelessEventFn>) -> Option<(u64, u64, u64, [u8; 6])> {
    let identity = fresh_identity();
    let (owner, token, id, _) = identity;
    let cap: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    if insert_session(new_session(id, owner, token, cap, event)).is_err() {
        return None;
    }
    Some(identity)
}

/// Closes the session on drop (and drains the cleanup task `close`
/// spawns) so a failing test cannot leak a session or a wiphy shell into
/// the next test.
struct SessionGuard(u64);
impl Drop for SessionGuard {
    fn drop(&mut self) {
        close(self.0);
        narf_scheduler::run_until_empty();
    }
}

fn register_request(
    mac: [u8; 6],
    modes: u32,
    hw_caps: u8,
    ciphers: &[u32],
    bands: &[(u32, &[u8])],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&mac);
    request.extend_from_slice(&modes.to_le_bytes());
    request.push(hw_caps);
    request.push(ciphers.len() as u8);
    request.push(bands.len() as u8);
    request.push(0);
    for cipher in ciphers {
        request.extend_from_slice(&cipher.to_le_bytes());
    }
    for (freq_mhz, channels) in bands {
        request.extend_from_slice(&freq_mhz.to_le_bytes());
        request.push(channels.len() as u8);
        request.push(0);
        request.extend_from_slice(channels);
    }
    request
}

fn valid_request(mac: [u8; 6]) -> Vec<u8> {
    register_request(
        mac,
        0x1 | 0x2,
        0x1 | 0x4,
        &[crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC],
        &[(2412, &[1, 6, 11]), (5180, &[36, 40])],
    )
}

/// Poll once with a caller-owned reply buffer, mirroring the broker's
/// final copy gate.
fn poll_with(id: u64, operation: u64, reply: &mut [u8]) -> (i32, usize, usize) {
    let mut len = 0usize;
    let capacity = reply.len();
    let mut publish = |bytes: &[u8]| -> Result<(), i32> {
        if bytes.len() > capacity {
            return Err(-105);
        }
        reply[..bytes.len()].copy_from_slice(bytes);
        len = bytes.len();
        Ok(())
    };
    let (status, required) = poll(id, operation, capacity, &mut publish);
    (status, required, len)
}

fn smoke_module_host_register_wiphy_decode_valid() -> TestResult {
    let mac = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
    let Ok(decoded) = decode_register_wiphy(&valid_request(mac)) else {
        return TestResult::Fail("valid REGISTER_WIPHY request failed to decode");
    };
    if decoded.mac != mac
        || decoded.modes != (WirelessModes::STATION | WirelessModes::AP)
        || !decoded.hw_caps.ht_supported
        || decoded.hw_caps.vht_supported
        || !decoded.hw_caps.he_supported
        || decoded.hw_caps.eht_supported
        || decoded.ciphers != [crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC]
        || decoded.bands.len() != 2
        || decoded.bands[0].freq_mhz != 2412
        || decoded.bands[0].channels != [1, 6, 11]
        || decoded.bands[1].freq_mhz != 5180
        || decoded.bands[1].channels != [36, 40]
    {
        return TestResult::Fail("valid REGISTER_WIPHY decoded to wrong advertisement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_register_wiphy_decode_valid
);

fn smoke_module_host_register_wiphy_decode_rejects_malformed() -> TestResult {
    let mac = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x02];
    let valid = valid_request(mac);
    // Each case mutates exactly one wire rule; all must fail with -EINVAL.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    cases.push(valid[..10].to_vec()); // truncated header
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing); // trailing bytes
    let mut reserved = valid.clone();
    reserved[13] = 1;
    cases.push(reserved); // reserved header byte
    let mut band_reserved = valid.clone();
    // First band's reserved byte: header 14 + 2 ciphers * 4 = 22, freq 4,
    // channel count 1, then reserved at 27.
    band_reserved[27] = 1;
    cases.push(band_reserved); // reserved band byte
    cases.push(register_request(mac, 0, 0x1, &[], &[(2412, &[1])])); // zero modes
    cases.push(register_request(mac, 0x10, 0x1, &[], &[(2412, &[1])])); // unknown mode bit
    cases.push(register_request(mac, 0x1, 0x10, &[], &[(2412, &[1])])); // unknown hw-cap bit
    cases.push(register_request(
        mac,
        0x1,
        0x1,
        &[0x000f_ac99],
        &[(2412, &[1])],
    )); // unknown cipher
    cases.push(register_request(
        mac,
        0x1,
        0x1,
        &[crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_CCMP],
        &[(2412, &[1])],
    )); // duplicate cipher
    cases.push(register_request(mac, 0x1, 0x1, &[], &[])); // zero bands
    cases.push(register_request(
        mac,
        0x1,
        0x1,
        &[],
        &[(2412, &[1]), (2437, &[6]), (5180, &[36]), (5240, &[48])],
    )); // too many bands
    cases.push(register_request(mac, 0x1, 0x1, &[], &[(3000, &[1])])); // unmapped band
    cases.push(register_request(
        mac,
        0x1,
        0x1,
        &[],
        &[(2412, &[1]), (2437, &[6])],
    )); // duplicate band
    cases.push(register_request(mac, 0x1, 0x1, &[], &[(2412, &[])])); // zero channels
    cases.push(register_request(mac, 0x1, 0x1, &[], &[(2412, &[0])])); // channel 0
    cases.push(register_request(mac, 0x1, 0x1, &[], &[(2412, &[234])])); // channel 234
    cases.push(register_request(mac, 0x1, 0x1, &[], &[(2412, &[1, 1])])); // duplicate channel
    for case in cases.iter() {
        if decode_register_wiphy(case) != Err(-22) {
            return TestResult::Fail("malformed REGISTER_WIPHY was accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_register_wiphy_decode_rejects_malformed
);

fn smoke_module_host_validate_stage4_and_unknown() -> TestResult {
    let mac = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x03];
    if validate(OP_REGISTER_WIPHY, &valid_request(mac)).is_err()
        || validate(OP_SCAN_RESULT, &[]) != Err(-95)
        || validate(OP_CONNECT_RESULT, &[]) != Err(-95)
        || validate(OP_DISCONNECT, &[]) != Err(-95)
        || validate(OP_SET_STATE, &[]) != Err(-95)
        || validate(0x99, &[]) != Err(-95)
    {
        return TestResult::Fail("opcode validation misclassified a Stage 4 or unknown opcode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_validate_stage4_and_unknown
);

struct Held {
    ready: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
}
impl Future for Held {
    type Output = Result<Vec<u8>, i32>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::AcqRel);
        if self.ready.load(Ordering::Acquire) {
            Poll::Ready(Ok(alloc::vec![7, 9]))
        } else {
            Poll::Pending
        }
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

fn smoke_module_host_operation_cancel_retains_started_work() -> TestResult {
    // Same contract as the mt76 host: cancel never drops started native
    // work, and a cancelled-but-successful operation reports EALREADY.
    let ready = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let mut operation = Operation {
        id: 9,
        started: false,
        cancelled: false,
        future: Some(Box::pin(Held {
            ready: ready.clone(),
            dropped: dropped.clone(),
            polls: polls.clone(),
        })),
        result: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    operation.advance(&mut cx);
    operation.request_cancel();
    operation.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 0
        || operation.result.is_some()
        || polls.load(Ordering::Acquire) != 2
        || !operation.started
    {
        return TestResult::Fail("cancel dropped or completed held native module work");
    }
    ready.store(true, Ordering::Release);
    operation.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 1
        || operation.future.is_some()
        || !matches!(operation.result, Some(Err(-114)))
    {
        return TestResult::Fail("started module cancellation invented cancelled success");
    }
    let mut unstarted = Operation {
        id: 10,
        started: false,
        cancelled: false,
        future: Some(Box::pin(Held {
            ready: ready.clone(),
            dropped: dropped.clone(),
            polls: polls.clone(),
        })),
        result: None,
    };
    unstarted.request_cancel();
    unstarted.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 2
        || polls.load(Ordering::Acquire) != 2
        || !matches!(unstarted.result, Some(Err(-125)))
    {
        return TestResult::Fail("unstarted module cancellation entered native work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_operation_cancel_retains_started_work
);

fn find_shell(mac: [u8; 6]) -> Option<Arc<dyn WirelessNetIface>> {
    registry::list()
        .into_iter()
        .find(|iface| iface.get_wireless_info().base_mac == mac)
}

fn smoke_module_host_session_register_wiphy_round_trip() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some((owner, token, id, mac)) = insert_test_session(None) else {
        return TestResult::Fail("test session insert failed");
    };
    let _guard = SessionGuard(id);
    // A second session for the same probe device is refused.
    let cap2: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    if insert_session(new_session(id + 1, owner, token, cap2, None)) != Err(-16) {
        return TestResult::Fail("duplicate wireless session for one probe device was accepted");
    }
    let Ok(operation) = submit(id, OP_REGISTER_WIPHY, &valid_request(mac)) else {
        return TestResult::Fail("REGISTER_WIPHY submit failed");
    };
    // A second submit while one operation is in flight is refused...
    if submit(id, OP_REGISTER_WIPHY, &valid_request(mac)) != Err(-16) {
        return TestResult::Fail("second in-flight wireless operation was accepted");
    }
    // ...but the terminal reply is retained across an undersized poll.
    let mut small = [0x77u8; 2];
    let (status, required, len) = poll_with(id, operation, &mut small);
    if (status, required, len) != (-105, 4, 0) || small != [0x77, 0x77] {
        return TestResult::Fail("undersized REGISTER_WIPHY poll consumed or corrupted the reply");
    }
    let mut reply = [0x77u8; 4];
    let (status, required, len) = poll_with(id, operation, &mut reply);
    if (status, required, len) != (0, 4, 4) {
        return TestResult::Fail("REGISTER_WIPHY poll did not publish the wiphy index");
    }
    let index = u32::from_le_bytes(reply);
    let Some(shell) = find_shell(mac) else {
        return TestResult::Fail("REGISTER_WIPHY published no wiphy shell");
    };
    if registry::wiphy_index(shell.wiphy_id()) != Some(index) {
        return TestResult::Fail("REGISTER_WIPHY reply index does not resolve to the shell");
    }
    let info = shell.get_wireless_info();
    if info.base_mac != mac
        || info.bands.len() != 2
        || info.bands[0].channels != [1, 6, 11]
        || shell.cipher_suites() != [crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC]
    {
        return TestResult::Fail("published wiphy shell does not carry the advertised caps");
    }
    // The terminal reply is consumed: a second poll finds no operation.
    let mut again = [0u8; 4];
    if poll_with(id, operation, &mut again).0 != -22 {
        return TestResult::Fail("consumed wireless operation stayed pollable");
    }
    // A second REGISTER_WIPHY on the same session is refused at execution.
    let Ok(second) = submit(id, OP_REGISTER_WIPHY, &valid_request(mac)) else {
        return TestResult::Fail("second REGISTER_WIPHY submit failed");
    };
    let mut second_reply = [0u8; 4];
    if poll_with(id, second, &mut second_reply).0 != -16 {
        return TestResult::Fail("second REGISTER_WIPHY did not fail with EBUSY");
    }
    // Unknown operation ids and foreign sessions never enter the host.
    if cancel(id, operation) != -22
        || submit(
            id.wrapping_add(0x1000_0000),
            OP_REGISTER_WIPHY,
            &valid_request(mac),
        ) != Err(-19)
    {
        return TestResult::Fail("foreign wireless handle entered the host");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_session_register_wiphy_round_trip
);

fn smoke_module_host_close_unpublishes_wiphy_and_ends_session() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some((_owner, _token, id, mac)) = insert_test_session(None) else {
        return TestResult::Fail("test session insert failed");
    };
    let Ok(operation) = submit(id, OP_REGISTER_WIPHY, &valid_request(mac)) else {
        return TestResult::Fail("REGISTER_WIPHY submit failed");
    };
    let mut reply = [0u8; 4];
    if poll_with(id, operation, &mut reply).0 != 0 || find_shell(mac).is_none() {
        return TestResult::Fail("REGISTER_WIPHY did not publish before close");
    }
    close(id);
    narf_scheduler::run_until_empty();
    if find_shell(mac).is_some() {
        return TestResult::Fail("closed wireless session kept its wiphy published");
    }
    if submit(id, OP_REGISTER_WIPHY, &valid_request(mac)) != Err(-19)
        || cancel(id, operation) != -19
    {
        return TestResult::Fail("closed wireless session stayed usable");
    }
    // Closing twice is a no-op, and the session id is never reused.
    close(id);
    let Some((_owner2, _token2, id2, mac2)) = insert_test_session(None) else {
        return TestResult::Fail("test session insert failed");
    };
    let _guard = SessionGuard(id2);
    if id2 == id {
        return TestResult::Fail("wireless session id reused after close");
    }
    let Ok(operation2) = submit(id2, OP_REGISTER_WIPHY, &valid_request(mac2)) else {
        return TestResult::Fail("reopened wireless session could not register a wiphy");
    };
    let mut reply2 = [0u8; 4];
    if poll_with(id2, operation2, &mut reply2).0 != 0 {
        return TestResult::Fail("reopened wireless session could not publish");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_close_unpublishes_wiphy_and_ends_session
);

fn smoke_module_host_revoked_cap_ends_session() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let (owner, token, id, mac) = fresh_identity();
    let cap: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    if insert_session(new_session(id, owner, token, cap, None)).is_err() {
        return TestResult::Fail("test session insert failed");
    }
    let _guard = SessionGuard(id);
    cap.revoke();
    if submit(id, OP_REGISTER_WIPHY, &valid_request(mac)) != Err(-19) {
        return TestResult::Fail("revoked wireless cap kept the session usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_revoked_cap_ends_session
);

static GATE_ENABLED: AtomicBool = AtomicBool::new(false);
static GATE_CALLS: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_TOKEN: AtomicU64 = AtomicU64::new(0);
static CALLBACK_EVENT: AtomicU64 = AtomicU64::new(0);
static CALLBACK_LEN: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn test_event_callback(token: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    CALLBACK_TOKEN.store(token, Ordering::Release);
    CALLBACK_EVENT.store(u64::from(event), Ordering::Release);
    CALLBACK_LEN.store(len, Ordering::Release);
    CALLBACK_CALLS.fetch_add(1, Ordering::AcqRel);
    if len > 0 {
        // SAFETY: the gate passes a live payload borrow for the call duration.
        let _ = unsafe { *payload };
    }
    7
}

fn test_event_gate(
    owner: u64,
    callback: ModuleWirelessEventFn,
    token: u64,
    event: u32,
    payload: &[u8],
) -> i32 {
    let _ = owner;
    GATE_CALLS.fetch_add(1, Ordering::AcqRel);
    if !GATE_ENABLED.load(Ordering::Acquire) {
        return -19;
    }
    callback(token, event, payload.as_ptr(), payload.len())
}

fn smoke_module_host_event_delivery() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    // Install the test gate once; it stays installed for later tests, so
    // the enabled/disabled flag (not install order) selects the path.
    narf_bus::set_module_wireless_event_call_gate(test_event_gate);
    let Some((_owner, token, id, _mac)) = insert_test_session(Some(test_event_callback)) else {
        return TestResult::Fail("test session insert failed");
    };
    let _guard = SessionGuard(id);
    // Gate disabled: delivery fails without invoking the callback.
    GATE_ENABLED.store(false, Ordering::Release);
    CALLBACK_CALLS.store(0, Ordering::Release);
    if deliver_event(id, EVENT_SCAN_REQUEST, &[1, 2, 3]) != -19
        || CALLBACK_CALLS.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("wireless event entered a module with no call gate");
    }
    // Gate enabled: the callback runs in the module's domain with the
    // session's device token, event id and payload; its return passes back.
    GATE_ENABLED.store(true, Ordering::Release);
    GATE_CALLS.store(0, Ordering::Release);
    if deliver_event(id, EVENT_SCAN_REQUEST, &[1, 2, 3]) != 7
        || GATE_CALLS.load(Ordering::Acquire) != 1
        || CALLBACK_CALLS.load(Ordering::Acquire) != 1
        || CALLBACK_TOKEN.load(Ordering::Acquire) != token
        || CALLBACK_EVENT.load(Ordering::Acquire) != u64::from(EVENT_SCAN_REQUEST)
        || CALLBACK_LEN.load(Ordering::Acquire) != 3
    {
        return TestResult::Fail("wireless event did not reach the session callback");
    }
    // Unknown events and over-bounded payloads never reach the callback.
    CALLBACK_CALLS.store(0, Ordering::Release);
    if deliver_event(id, 0x99, &[]) != -95
        || deliver_event(id, EVENT_CONNECT, &[0u8; 4097]) != -90
        || CALLBACK_CALLS.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("invalid wireless event reached the session callback");
    }
    // A plain-open session has no event channel.
    let Some((_owner2, _token2, id2, _mac2)) = insert_test_session(None) else {
        return TestResult::Fail("test session insert failed");
    };
    let _guard2 = SessionGuard(id2);
    if deliver_event(id2, EVENT_SCAN_REQUEST, &[]) != -19 {
        return TestResult::Fail("wireless event reached a session with no callback");
    }
    // A closed session's callback is forgotten.
    close(id);
    narf_scheduler::run_until_empty();
    if deliver_event(id, EVENT_SCAN_REQUEST, &[]) != -19 {
        return TestResult::Fail("wireless event reached a closed session");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/module-host", smoke_module_host_event_delivery);
