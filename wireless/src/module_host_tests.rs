//! Tests for the native wireless family host (version 2): wire decoding,
//! operation lifecycle, session flow through the real `submit` / `poll` /
//! `cancel` / `close` entry points, wiphy publication bound to the module's
//! netdev, event delivery through a test-installed call gate, and the shell's
//! scan / connect / disconnect round trips against a scripted module.
//!
//! Sessions are built through the same `new_session` + `insert_session`
//! helpers `open` uses; the broker-level open path is covered by the bus
//! broker tests. The module's netdev comes from the bus test helper, which
//! registers it exactly as `narf_netif_register_with_context` does.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);
/// One fresh (owner, token, session id, MAC) per session test.
fn fresh_identity() -> (u64, u64, u64, [u8; 6]) {
    let n = NEXT_TEST.fetch_add(1, Ordering::AcqRel);
    (
        0xffff_ffff_7700 + n * 2,
        0xffff_ffff_7701 + n * 2,
        0x7700_0000 + n,
        [0x02, 0x00, 0x5e, 0x00, 0x53, 0x41 + (n as u8 & 0x3f)],
    )
}

/// A session plus the module netdev its wiphy binds to.
struct Fixture {
    owner: u64,
    token: u64,
    id: u64,
    mac: [u8; 6],
    netdev: String,
    ifindex: u32,
}

/// Closes the session (draining the cleanup task `close` spawns) and removes
/// the netdev's device context on drop, so a failing test leaks nothing.
impl Drop for Fixture {
    fn drop(&mut self) {
        close(self.id);
        narf_scheduler::run_until_empty();
        narf_bus::driver_match::__remove_module_device_for_test(self.token);
    }
}

fn fixture(event: Option<ModuleWirelessEventFn>) -> Option<Fixture> {
    let (owner, token, id, mac) = fresh_identity();
    let (netdev, ifindex) =
        narf_bus::driver_match::__install_module_netif_for_test(owner, token, mac)?;
    let cap: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    if insert_session(new_session(id, owner, token, cap, event)).is_err() {
        narf_bus::driver_match::__remove_module_device_for_test(token);
        return None;
    }
    Some(Fixture {
        owner,
        token,
        id,
        mac,
        netdev,
        ifindex,
    })
}

#[allow(clippy::too_many_arguments)]
fn register_request(
    ifindex: u32,
    mac: [u8; 6],
    modes: u32,
    hw_caps: u8,
    flags: u8,
    max_scan_ssids: u8,
    ciphers: &[u32],
    bands: &[(u32, &[u8])],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&ifindex.to_le_bytes());
    request.extend_from_slice(&mac);
    request.extend_from_slice(&modes.to_le_bytes());
    request.push(hw_caps);
    request.push(ciphers.len() as u8);
    request.push(bands.len() as u8);
    request.push(flags);
    request.push(max_scan_ssids);
    request.push(0);
    request.extend_from_slice(&512u16.to_le_bytes());
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

fn valid_request(ifindex: u32, mac: [u8; 6]) -> Vec<u8> {
    register_request(
        ifindex,
        mac,
        0x1,
        0x1 | 0x4,
        FLAG_PSK_OFFLOAD | FLAG_SAE_OFFLOAD | FLAG_REPORTS_DISCONNECT,
        4,
        &[crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC],
        &[(2412, &[1, 6, 11]), (5180, &[36, 40])],
    )
}

/// Poll once with a caller-owned reply buffer, mirroring the broker's final
/// copy gate.
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

/// Submit `opcode` and collect its status the way a module does.
fn report(id: u64, opcode: u32, request: &[u8]) -> i32 {
    match submit(id, opcode, request) {
        Ok(operation) => {
            let mut reply = [0u8; 8];
            poll_with(id, operation, &mut reply).0
        }
        Err(error) => error,
    }
}

fn register(f: &Fixture) -> Option<Arc<dyn WirelessNetIface>> {
    if report(f.id, OP_REGISTER_WIPHY, &valid_request(f.ifindex, f.mac)) != 0 {
        return None;
    }
    find_shell(f.mac)
}

fn find_shell(mac: [u8; 6]) -> Option<Arc<dyn WirelessNetIface>> {
    registry::list()
        .into_iter()
        .find(|iface| iface.get_wireless_info().base_mac == mac)
}

fn scan_result(bssid: [u8; 6], ssid: &[u8], freq: u32, channel: u8, ies: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&bssid);
    out.push(channel);
    out.push(3); // WPA2
    out.extend_from_slice(&freq.to_le_bytes());
    out.push((-50i8) as u8);
    out.push(0);
    out.push(ssid.len() as u8);
    out.push(0);
    out.extend_from_slice(&(ies.len() as u16).to_le_bytes());
    out.extend_from_slice(ssid);
    out.extend_from_slice(ies);
    out
}

fn connect_result(status: u16, bssid: [u8; 6], freq: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&bssid);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&freq.to_le_bytes());
    out
}

fn disconnected(reason: u16, local: bool) -> Vec<u8> {
    let mut out = reason.to_le_bytes().to_vec();
    out.push(u8::from(local));
    out.push(0);
    out
}

// ── wire decoding ───────────────────────────────────────────────────

fn smoke_module_host_register_wiphy_decode_valid() -> TestResult {
    let mac = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
    let Ok(decoded) = decode_register_wiphy(&valid_request(7, mac)) else {
        return TestResult::Fail("valid REGISTER_WIPHY request failed to decode");
    };
    if decoded.ifindex != 7
        || decoded.mac != mac
        || decoded.modes != WirelessModes::STATION
        || !decoded.hw_caps.ht_supported
        || decoded.hw_caps.vht_supported
        || !decoded.hw_caps.he_supported
        || decoded.flags != FLAG_PSK_OFFLOAD | FLAG_SAE_OFFLOAD | FLAG_REPORTS_DISCONNECT
        || decoded.max_scan_ssids != 4
        || decoded.max_scan_ie_len != 512
        || decoded.ciphers != [crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC]
        || decoded.bands.len() != 2
        || decoded.bands[0].channels != [1, 6, 11]
        || decoded.bands[1].freq_mhz != 5180
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
    let valid = valid_request(7, mac);
    let r = |modes, hw, flags, ssids, ciphers: &[u32], bands: &[(u32, &[u8])]| {
        register_request(7, mac, modes, hw, flags, ssids, ciphers, bands)
    };
    // Each case breaks exactly one wire rule; all must fail with -EINVAL.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    cases.push(valid[..21].to_vec()); // truncated header
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut reserved = valid.clone();
    reserved[19] = 1; // header reserved byte
    cases.push(reserved);
    let mut ie_len = valid.clone();
    ie_len[20..22].copy_from_slice(&2049u16.to_le_bytes());
    cases.push(ie_len);
    let mut band_reserved = valid.clone();
    // header 22 + 2 ciphers * 4 = 30; freq 4, count 1, reserved at 35.
    band_reserved[35] = 1;
    cases.push(band_reserved);
    cases.push(register_request(0, mac, 1, 1, 0, 0, &[], &[(2412, &[1])])); // ifindex 0
    cases.push(r(0, 0x1, 0, 0, &[], &[(2412, &[1])])); // zero modes
    cases.push(r(0x10, 0x1, 0, 0, &[], &[(2412, &[1])])); // unknown mode bit
    cases.push(r(0x1, 0x10, 0, 0, &[], &[(2412, &[1])])); // unknown hw-cap bit
    cases.push(r(0x1, 0x1, 0x08, 0, &[], &[(2412, &[1])])); // unknown flag
    cases.push(r(0x1, 0x1, 0, 17, &[], &[(2412, &[1])])); // too many scan SSIDs
    cases.push(r(0x1, 0x1, 0, 0, &[0x000f_ac99], &[(2412, &[1])])); // unknown cipher
    cases.push(r(0x1, 0x1, 0, 0, &[], &[])); // zero bands
    cases.push(r(0x1, 0x1, 0, 0, &[], &[(3000, &[1])])); // unmapped band
    cases.push(r(0x1, 0x1, 0, 0, &[], &[(2412, &[1]), (2437, &[6])])); // duplicate band
    cases.push(r(0x1, 0x1, 0, 0, &[], &[(2412, &[0])])); // channel 0
    cases.push(r(0x1, 0x1, 0, 0, &[], &[(2412, &[1, 1])])); // duplicate channel
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

fn smoke_module_host_report_decoders_enforce_the_wire() -> TestResult {
    let bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let good = scan_result(bssid, b"narf", 2437, 6, &[0x30, 0x02, 0x01, 0x00]);
    let Ok(bss) = decode_scan_result(&good) else {
        return TestResult::Fail("valid SCAN_RESULT rejected");
    };
    if bss.info.bssid != bssid
        || bss.info.ssid != b"narf"
        || bss.info.frequency_mhz != 2437
        || bss.info.rssi != -50
        || bss.ies != [0x30, 0x02, 0x01, 0x00]
    {
        return TestResult::Fail("SCAN_RESULT decoded to the wrong BSS");
    }
    let mut long_ssid = scan_result(bssid, &[b'x'; 33], 2437, 6, &[]);
    let mut bad_freq = scan_result(bssid, b"narf", 3000, 6, &[]);
    let mut bad_security = good.clone();
    bad_security[7] = 5;
    let mut short = good.clone();
    short.pop();
    for case in [&mut long_ssid, &mut bad_freq, &mut bad_security, &mut short] {
        if decode_scan_result(case).is_ok() {
            return TestResult::Fail("malformed SCAN_RESULT accepted");
        }
    }
    if decode_connect_result(&connect_result(0, bssid, 2437)) != Ok((0, bssid, 2437))
        || decode_connect_result(&connect_result(0, [0; 6], 2437)).is_ok()
        || decode_connect_result(&connect_result(17, [0; 6], 0)) != Ok((17, [0; 6], 0))
        || decode_disconnected(&disconnected(7, true)) != Ok((7, true))
        || decode_disconnected(&[7, 0, 2, 0]).is_ok()
        || decode_scan_done(&0i32.to_le_bytes()) != Ok(0)
        || decode_scan_done(&1i32.to_le_bytes()).is_ok()
        || validate(0x99, &[]) != Err(-95)
    {
        return TestResult::Fail("a report decoder misjudged its wire format");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_report_decoders_enforce_the_wire
);

fn smoke_module_host_connect_encoding_follows_the_offloads() -> TestResult {
    let req = |security| AssociateRequest {
        bssid: [0x02, 1, 2, 3, 4, 5],
        ssid: b"narf".to_vec(),
        frequency_mhz: 5180,
        channel: 36,
        security,
        ie: alloc::vec![0xdd, 0x01, 0x00],
    };
    let all = FLAG_PSK_OFFLOAD | FLAG_SAE_OFFLOAD;
    let Ok(psk) = encode_connect(&req(SecurityConfig::Wpa2 { psk: [0x5a; 32] }), all) else {
        return TestResult::Fail("PSK CONNECT refused with the offload advertised");
    };
    // bssid 6 | security | reserved | freq 4 | ssid_len | reserved | ie_len 2
    // | secret_len 2 | reserved 2 = 20, then ssid 4, ie 3, secret 32.
    if psk.len() != 20 + 4 + 3 + 32
        || psk[6] != SECURITY_PSK
        || psk[8..12] != 5180u32.to_le_bytes()
        || psk[14..16] != 3u16.to_le_bytes()
        || psk[16..18] != 32u16.to_le_bytes()
        || psk[20..24] != *b"narf"
        || psk[27..] != [0x5a; 32]
    {
        return TestResult::Fail("PSK CONNECT encoded the wrong record");
    }
    let sae = SecurityConfig::Wpa3 {
        password: b"correct horse".to_vec(),
    };
    let ext = SecurityConfig::External(crate::ExternalSecurity::default());
    if encode_connect(
        &req(SecurityConfig::Wpa2 { psk: [0; 32] }),
        FLAG_SAE_OFFLOAD,
    )
    .is_ok()
        || encode_connect(&req(sae), FLAG_PSK_OFFLOAD).is_ok()
        || encode_connect(&req(ext), all).is_ok()
        || !matches!(encode_connect(&req(SecurityConfig::Open), 0), Ok(ref v) if v[6] == SECURITY_OPEN)
    {
        return TestResult::Fail("CONNECT ignored the advertised SME offloads");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_connect_encoding_follows_the_offloads
);

// ── operation lifecycle ─────────────────────────────────────────────

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
    // Cancel never drops started native work, and a cancelled-but-successful
    // operation reports EALREADY.
    let ready = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let held = || {
        Some(Box::pin(Held {
            ready: ready.clone(),
            dropped: dropped.clone(),
            polls: polls.clone(),
        }) as NativeWork)
    };
    let mut operation = Operation {
        id: 9,
        started: false,
        cancelled: false,
        future: held(),
        result: None,
    };
    let mut cx = Context::from_waker(Waker::noop());
    operation.advance(&mut cx);
    operation.request_cancel();
    operation.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 0 || operation.result.is_some() || !operation.started {
        return TestResult::Fail("cancel dropped or completed held native module work");
    }
    ready.store(true, Ordering::Release);
    operation.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 1 || !matches!(operation.result, Some(Err(-114))) {
        return TestResult::Fail("started module cancellation invented cancelled success");
    }
    let mut unstarted = Operation {
        id: 10,
        started: false,
        cancelled: false,
        future: held(),
        result: None,
    };
    unstarted.request_cancel();
    unstarted.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 2
        || polls.load(Ordering::Acquire) != 3
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

// ── sessions and wiphy publication ──────────────────────────────────

fn smoke_module_host_register_wiphy_binds_to_the_module_netdev() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some(f) = fixture(None) else {
        return TestResult::Fail("test fixture install failed");
    };
    // A second session for the same probe device is refused.
    let cap2: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    if insert_session(new_session(f.id + 1, f.owner, f.token, cap2, None)) != Err(-16) {
        return TestResult::Fail("duplicate wireless session for one probe device was accepted");
    }
    // A netdev this module does not own (wrong ifindex) is refused, and no
    // report is accepted before a wiphy exists.
    if report(
        f.id,
        OP_REGISTER_WIPHY,
        &valid_request(f.ifindex + 1000, f.mac),
    ) != -19
        || report(f.id, OP_SCAN_DONE, &0i32.to_le_bytes()) != -22
    {
        return TestResult::Fail("wiphy bound to a foreign netdev or report without a wiphy");
    }
    let Ok(operation) = submit(f.id, OP_REGISTER_WIPHY, &valid_request(f.ifindex, f.mac)) else {
        return TestResult::Fail("REGISTER_WIPHY submit failed");
    };
    if submit(f.id, OP_SCAN_DONE, &0i32.to_le_bytes()) != Err(-16) {
        return TestResult::Fail("second in-flight wireless operation was accepted");
    }
    let mut small = [0x77u8; 2];
    if poll_with(f.id, operation, &mut small) != (-105, 4, 0) || small != [0x77, 0x77] {
        return TestResult::Fail("undersized REGISTER_WIPHY poll consumed or corrupted the reply");
    }
    let mut reply = [0u8; 4];
    if poll_with(f.id, operation, &mut reply) != (0, 4, 4) {
        return TestResult::Fail("REGISTER_WIPHY poll did not publish the wiphy index");
    }
    let Some(shell) = find_shell(f.mac) else {
        return TestResult::Fail("REGISTER_WIPHY published no wiphy shell");
    };
    if registry::wiphy_index(shell.wiphy_id()) != Some(u32::from_le_bytes(reply))
        || shell.name() != f.netdev
        || !shell.supports_handshake_offload()
        || !shell.supports_sae_offload()
        || !shell.reports_disconnect_events()
        || shell.max_scan_ssids() != 4
        || shell.cipher_suites() != [crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC]
    {
        return TestResult::Fail("wiphy shell is not the module netdev's, or lost its caps");
    }
    if report(f.id, OP_REGISTER_WIPHY, &valid_request(f.ifindex, f.mac)) != -16 {
        return TestResult::Fail("second REGISTER_WIPHY did not fail with EBUSY");
    }
    if submit(
        f.id.wrapping_add(0x1000_0000),
        OP_SCAN_DONE,
        &0i32.to_le_bytes(),
    ) != Err(-19)
    {
        return TestResult::Fail("foreign wireless handle entered the host");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_register_wiphy_binds_to_the_module_netdev
);

fn smoke_module_host_close_unpublishes_wiphy_and_ends_session() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some(f) = fixture(None) else {
        return TestResult::Fail("test fixture install failed");
    };
    if register(&f).is_none() {
        return TestResult::Fail("REGISTER_WIPHY did not publish before close");
    }
    close(f.id);
    narf_scheduler::run_until_empty();
    if find_shell(f.mac).is_some()
        || report(f.id, OP_SCAN_DONE, &0i32.to_le_bytes()) != -19
        || cancel(f.id, 1) != -19
    {
        return TestResult::Fail("closed wireless session stayed published or usable");
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
    cap.revoke();
    let refused = submit(id, OP_REGISTER_WIPHY, &valid_request(1, mac)) == Err(-19);
    close(id);
    narf_scheduler::run_until_empty();
    if !refused {
        return TestResult::Fail("revoked wireless cap kept the session usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_revoked_cap_ends_session
);

// ── events and the shell's station operations ───────────────────────

static GATE_ENABLED: AtomicBool = AtomicBool::new(false);
static GATE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Scripted module: what the callback does with each event.
static SCRIPT_SESSION: AtomicU64 = AtomicU64::new(0);
/// 0 = record only; 1 = report a scan and a success; 2 = refuse the connect
/// (status 17); 3 = report nothing (timeouts).
static SCRIPT_MODE: AtomicUsize = AtomicUsize::new(0);
static LAST_EVENT: AtomicU64 = AtomicU64::new(0);
static LAST_LEN: AtomicUsize = AtomicUsize::new(0);
static LAST_BYTE6: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_TOKEN: AtomicU64 = AtomicU64::new(0);
static CALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);

const AP: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP2: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x66];

extern "C" fn scripted_module(token: u64, event: u32, payload: *const u8, len: usize) -> i32 {
    CALLBACK_TOKEN.store(token, Ordering::Release);
    CALLBACK_CALLS.fetch_add(1, Ordering::AcqRel);
    LAST_EVENT.store(u64::from(event), Ordering::Release);
    LAST_LEN.store(len, Ordering::Release);
    // SAFETY: the gate passes a live payload borrow for the call duration.
    let bytes = unsafe { core::slice::from_raw_parts(payload, len) };
    LAST_BYTE6.store(
        bytes.get(6).copied().unwrap_or(0) as usize,
        Ordering::Release,
    );
    let id = SCRIPT_SESSION.load(Ordering::Acquire);
    let mode = SCRIPT_MODE.load(Ordering::Acquire);
    if mode == 0 {
        return 7;
    }
    if mode == 3 {
        return 0;
    }
    match event {
        EVENT_SCAN_REQUEST => {
            let _ = report(
                id,
                OP_SCAN_RESULT,
                &scan_result(AP, b"narf", 2437, 6, &[0x30, 0]),
            );
            let _ = report(id, OP_SCAN_RESULT, &scan_result(AP2, b"lab", 5180, 36, &[]));
            let _ = report(id, OP_SCAN_DONE, &0i32.to_le_bytes());
        }
        EVENT_CONNECT => {
            let status = if mode == 2 { 17 } else { 0 };
            let _ = report(id, OP_CONNECT_RESULT, &connect_result(status, AP, 2437));
        }
        EVENT_DISCONNECT => {
            let _ = report(id, OP_DISCONNECTED, &disconnected(3, true));
        }
        _ => {}
    }
    0
}

fn test_event_gate(
    _owner: u64,
    callback: ModuleWirelessEventFn,
    token: u64,
    event: u32,
    payload: &[u8],
) -> i32 {
    GATE_CALLS.fetch_add(1, Ordering::AcqRel);
    if !GATE_ENABLED.load(Ordering::Acquire) {
        return -19;
    }
    callback(token, event, payload.as_ptr(), payload.len())
}

fn scripted_fixture(mode: usize) -> Option<Fixture> {
    narf_bus::set_module_wireless_event_call_gate(test_event_gate);
    GATE_ENABLED.store(true, Ordering::Release);
    SCRIPT_MODE.store(mode, Ordering::Release);
    let f = fixture(Some(scripted_module))?;
    SCRIPT_SESSION.store(f.id, Ordering::Release);
    Some(f)
}

fn smoke_module_host_event_delivery() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some(f) = scripted_fixture(0) else {
        return TestResult::Fail("test fixture install failed");
    };
    GATE_ENABLED.store(false, Ordering::Release);
    CALLBACK_CALLS.store(0, Ordering::Release);
    if deliver_event(f.id, EVENT_SCAN_REQUEST, &[1, 2, 3]) != -19
        || CALLBACK_CALLS.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("wireless event entered a module with no call gate");
    }
    GATE_ENABLED.store(true, Ordering::Release);
    GATE_CALLS.store(0, Ordering::Release);
    if deliver_event(f.id, EVENT_DISCONNECT, &[1, 2, 3]) != 7
        || GATE_CALLS.load(Ordering::Acquire) != 1
        || CALLBACK_CALLS.load(Ordering::Acquire) != 1
        || CALLBACK_TOKEN.load(Ordering::Acquire) != f.token
        || LAST_EVENT.load(Ordering::Acquire) != u64::from(EVENT_DISCONNECT)
        || LAST_LEN.load(Ordering::Acquire) != 3
    {
        return TestResult::Fail("wireless event did not reach the session callback");
    }
    CALLBACK_CALLS.store(0, Ordering::Release);
    if deliver_event(f.id, 0x99, &[]) != -95
        || deliver_event(f.id, EVENT_CONNECT, &[0u8; 4097]) != -90
        || CALLBACK_CALLS.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("invalid wireless event reached the session callback");
    }
    let Some(plain) = fixture(None) else {
        return TestResult::Fail("test fixture install failed");
    };
    if deliver_event(plain.id, EVENT_SCAN_REQUEST, &[]) != -19 {
        return TestResult::Fail("wireless event reached a session with no callback");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/module-host", smoke_module_host_event_delivery);

fn smoke_module_host_shell_scan_and_connect_round_trip() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some(f) = scripted_fixture(1) else {
        return TestResult::Fail("test fixture install failed");
    };
    let Some(shell) = register(&f) else {
        return TestResult::Fail("REGISTER_WIPHY failed");
    };
    let scan = ScanRequest {
        ssids: alloc::vec![b"narf".to_vec()],
        frequencies_mhz: alloc::vec![2437, 5180],
        channels: Vec::new(),
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let results = match narf_scheduler::block_on_spin(shell.scan(scan)) {
        Ok(results) => results,
        Err(_) => return TestResult::Fail("shell scan failed against a reporting module"),
    };
    // flags 1 | 2 freqs | 1 ssid | reserved | ie_len 2 | reserved 2
    // | 2 * u32 | len 1 + "narf" = 8 + 8 + 5.
    if LAST_EVENT.load(Ordering::Acquire) != u64::from(EVENT_SCAN_REQUEST)
        || LAST_LEN.load(Ordering::Acquire) != 21
        || results.len() != 2
        || !results.iter().any(|b| b.bssid == AP && b.ssid == b"narf")
        || shell.scan_information_elements(AP) != Some(alloc::vec![0x30, 0])
    {
        return TestResult::Fail("shell scan lost results, IEs, or sent the wrong request");
    }
    let req = AssociateRequest {
        bssid: AP,
        ssid: b"narf".to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: SecurityConfig::Wpa2 { psk: [0x42; 32] },
        ie: Vec::new(),
    };
    if narf_scheduler::block_on_spin(shell.associate(req)).is_err()
        || LAST_BYTE6.load(Ordering::Acquire) != usize::from(SECURITY_PSK)
        || shell.connected_bssid() != Some(AP)
        || !shell.link_up()
        || !narf_net::iface::lookup(&f.netdev).is_some_and(|i| i.carrier)
    {
        return TestResult::Fail("shell connect did not reach the module or raise carrier");
    }
    // The module reports link loss on its own: carrier drops.
    if report(f.id, OP_DISCONNECTED, &disconnected(4, false)) != 0
        || shell.link_up()
        || shell.connected_bssid().is_some()
        || narf_net::iface::lookup(&f.netdev).is_none_or(|i| i.carrier)
    {
        return TestResult::Fail("module link loss did not clear the association and carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_shell_scan_and_connect_round_trip
);

fn smoke_module_host_shell_refusal_disconnect_and_unsupported() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let Some(f) = scripted_fixture(2) else {
        return TestResult::Fail("test fixture install failed");
    };
    let Some(shell) = register(&f) else {
        return TestResult::Fail("REGISTER_WIPHY failed");
    };
    let req = |security| AssociateRequest {
        bssid: AP,
        ssid: b"narf".to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security,
        ie: Vec::new(),
    };
    if !matches!(
        narf_scheduler::block_on_spin(shell.associate(req(SecurityConfig::Open))),
        Err(WirelessError::Denied)
    ) || shell.link_up()
    {
        return TestResult::Fail("a refused association was reported as connected");
    }
    CALLBACK_CALLS.store(0, Ordering::Release);
    let external = SecurityConfig::External(crate::ExternalSecurity::default());
    if !matches!(
        narf_scheduler::block_on_spin(shell.associate(req(external))),
        Err(WirelessError::NotSupported)
    ) || CALLBACK_CALLS.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("an external-supplicant connect reached the module");
    }
    // Requested disconnect: the module's DISCONNECTED completes it.
    SCRIPT_MODE.store(1, Ordering::Release);
    if narf_scheduler::block_on_spin(shell.associate(req(SecurityConfig::Open))).is_err() {
        return TestResult::Fail("open association failed against a reporting module");
    }
    if narf_scheduler::block_on_spin(shell.disassociate()).is_err()
        || LAST_EVENT.load(Ordering::Acquire) != u64::from(EVENT_DISCONNECT)
        || shell.link_up()
    {
        return TestResult::Fail("shell disconnect did not reach the module or drop carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/module-host",
    smoke_module_host_shell_refusal_disconnect_and_unsupported
);
