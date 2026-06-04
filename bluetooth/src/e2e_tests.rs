//! Wave-31 end-to-end smokes for the Bluetooth stack.
//!
//! Wave 17 shipped HCI / L2CAP / SMP / GATT (client + server) /
//! profile state machines; Wave 19 wired the devfs + sysfs bridges.
//! Each layer has unit smokes in [`crate::tests`] (154 passing), but
//! none of them walks the full path from a raw HCI controller probe,
//! through SMP pairing, into GATT service discovery and a
//! characteristic read.
//!
//! This module fills that gap with synthetic-peer driven smokes.
//! There is no real radio; each test pushes pre-canned HCI events
//! and L2CAP/ATT/SMP PDUs into the right code path and asserts the
//! stack reacts the way the spec requires.
//!
//! Spec references throughout the file refer to Bluetooth Core
//! Specification 5.3 (`Vol N Part X §S` notation) and the HID 1.0,
//! A2DP 1.4, BAS 1.1, DIS 1.1 profile specs. GPL Linux sources
//! consulted per the 2026-05-20 NARF relicense:
//!   - `linux/net/bluetooth/hci_event.c` (HCI event dispatch).
//!   - `linux/net/bluetooth/smp.c`        (LE-SC f5/f6 derivation).
//!   - `linux/net/bluetooth/att.c`        (ATT request dispatch).

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::att;
use crate::controller::{BringupPhase, Controller};
use crate::event::{EventCode, LeConnectionComplete, LeSubevent};
use crate::gatt;
use crate::gatt_server::{GattServer, Permissions};
use crate::hci::{Command, Event};
use crate::l2cap;
use crate::opcode as op;
use crate::services;
use crate::smp;
use crate::transport::LoopbackTransport;

// ── helpers ────────────────────────────────────────────────────────

/// Build a Command Complete event for `opcode` with `status` (LE) and
/// the trailing return-parameter bytes. Mirrors the helper in
/// `tests.rs` but kept private here so this module stands alone.
fn cc(opcode: u16, status: u8, ret: &[u8]) -> Event {
    let mut params = vec![0x01u8];
    params.extend_from_slice(&opcode.to_le_bytes());
    params.push(status);
    params.extend_from_slice(ret);
    Event {
        code: EventCode::CommandComplete as u8,
        params,
    }
}

/// Build a Command Status event for `opcode` with `status` (LE).
/// Used for commands like `HCI_LE_Create_Connection` that emit
/// Command Status, not Command Complete.
#[allow(dead_code)]
fn cs(opcode: u16, status: u8) -> Event {
    let mut params = vec![status, 0x01u8];
    params.extend_from_slice(&opcode.to_le_bytes());
    Event {
        code: EventCode::CommandStatus as u8,
        params,
    }
}

/// Build an LE Meta event by prepending the subevent code to `payload`.
fn le_meta(subev: LeSubevent, payload: &[u8]) -> Event {
    let mut params = vec![subev as u8];
    params.extend_from_slice(payload);
    Event {
        code: EventCode::LeMeta as u8,
        params,
    }
}

// ── 1. HCI mandatory bring-up — opcode order + LE encoding ─────────

fn smoke_e2e_hci_mandatory_sequence_order() -> TestResult {
    use crate::bootstrap_bluetooth_authority;

    // §3 (Vol 4 Part E) mandates Reset → Read Local Version →
    // Read BD_ADDR → Read Buffer Size → Set Event Mask before any
    // higher-layer traffic. Verify our controller fires exactly that
    // chain in order.
    let lt = Arc::new(LoopbackTransport::new("e2e-mandatory"));
    lt.enqueue_event(cc(op::HCI_RESET, 0x00, &[]));
    lt.enqueue_event(cc(
        op::HCI_READ_LOCAL_VERSION,
        0x00,
        &[0x0C, 0x10, 0x00, 0x0C, 0xAA, 0xBB, 0x01, 0x00],
    ));
    let bd_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    lt.enqueue_event(cc(op::HCI_READ_BD_ADDR, 0x00, &bd_addr));
    lt.enqueue_event(cc(
        op::HCI_READ_BUFFER_SIZE,
        0x00,
        &[0x40, 0x01, 0x40, 0x10, 0x00, 0x08, 0x00],
    ));
    lt.enqueue_event(cc(op::HCI_SET_EVENT_MASK, 0x00, &[]));

    let controller = Controller::new(lt.clone());
    let cap = bootstrap_bluetooth_authority();
    let info = match controller.bring_up(&cap) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("bring_up failed"),
    };

    if controller.phase() != BringupPhase::Ready {
        return TestResult::Fail("phase != Ready");
    }
    if info.bd_addr != bd_addr {
        return TestResult::Fail("BD_ADDR not captured");
    }
    let sent = lt.sent_commands();
    let want = [
        op::HCI_RESET,
        op::HCI_READ_LOCAL_VERSION,
        op::HCI_READ_BD_ADDR,
        op::HCI_READ_BUFFER_SIZE,
        op::HCI_SET_EVENT_MASK,
    ];
    if sent.len() != want.len() {
        return TestResult::Fail("wrong command count");
    }
    for (i, (s, w)) in sent.iter().zip(want.iter()).enumerate() {
        if s.opcode != *w {
            let _ = i;
            return TestResult::Fail("command order drift");
        }
        // Also verify LE wire encoding of each opcode is consistent.
        let enc = s.encode();
        if enc.len() < 3 {
            return TestResult::Fail("command encoding too short");
        }
        if u16::from_le_bytes([enc[0], enc[1]]) != s.opcode {
            return TestResult::Fail("opcode LE encoding wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_hci_mandatory_sequence_order);

// ── 2. HCI Set Event Mask carries NARF's chosen 8-byte bitmap ──────

fn smoke_e2e_hci_set_event_mask_payload() -> TestResult {
    use crate::bootstrap_bluetooth_authority;

    let lt = Arc::new(LoopbackTransport::new("e2e-evmask"));
    lt.enqueue_event(cc(op::HCI_RESET, 0x00, &[]));
    lt.enqueue_event(cc(op::HCI_READ_LOCAL_VERSION, 0x00, &[0; 8]));
    lt.enqueue_event(cc(op::HCI_READ_BD_ADDR, 0x00, &[0; 6]));
    lt.enqueue_event(cc(op::HCI_READ_BUFFER_SIZE, 0x00, &[0; 7]));
    lt.enqueue_event(cc(op::HCI_SET_EVENT_MASK, 0x00, &[]));

    let controller = Controller::new(lt.clone());
    let cap = bootstrap_bluetooth_authority();
    if controller.bring_up(&cap).is_err() {
        return TestResult::Fail("bring_up failed");
    }
    // Pick the Set Event Mask command out of the trace and verify the
    // mask is the 8-byte default the controller bring-up picks
    // (§7.3.1, default mask 0x0000_1FFF_FFFF_FFFF on the wire = LE
    // [FF FF FF FF FF 1F 00 00]).
    let sent = lt.sent_commands();
    let mask_cmd = sent.iter().find(|c| c.opcode == op::HCI_SET_EVENT_MASK);
    let mask_cmd = match mask_cmd {
        Some(c) => c,
        None => return TestResult::Fail("Set_Event_Mask not emitted"),
    };
    if mask_cmd.params.len() != 8 {
        return TestResult::Fail("event mask must be 8 bytes");
    }
    let want: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x00, 0x00];
    if mask_cmd.params[..] != want[..] {
        return TestResult::Fail("event mask payload mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_hci_set_event_mask_payload);

// ── 3. HCI LE Set Scan Parameters + Enable opcode encoding ─────────

fn smoke_e2e_hci_le_scan_enable_opcode_encoding() -> TestResult {
    // §7.8.10 LE_Set_Scan_Parameters opcode = 0x200B; §7.8.11
    // LE_Set_Scan_Enable = 0x200C. Build the wire payloads and verify
    // every byte against the spec layout.
    let params = vec![
        0x00, // scan_type = passive
        0x12, 0x00, // scan_interval = 0x0012 LE (≈ 11.25 ms)
        0x12, 0x00, // scan_window
        0x00, // own_address_type = public
        0x00, // filter_policy = accept all
    ];
    let cmd = Command::with_params(op::HCI_LE_SET_SCAN_PARAMETERS, &params);
    let bytes = cmd.encode();
    if u16::from_le_bytes([bytes[0], bytes[1]]) != 0x200B {
        return TestResult::Fail("LE_Set_Scan_Parameters opcode wrong");
    }
    if bytes[2] != 7 {
        return TestResult::Fail("LE_Set_Scan_Parameters length != 7");
    }
    if bytes[3] != 0x00 {
        return TestResult::Fail("scan_type should be passive");
    }

    let enable = Command::with_params(op::HCI_LE_SET_SCAN_ENABLE, &[0x01, 0x00]);
    let eb = enable.encode();
    if u16::from_le_bytes([eb[0], eb[1]]) != 0x200C {
        return TestResult::Fail("LE_Set_Scan_Enable opcode wrong");
    }
    if eb[2] != 2 || eb[3] != 0x01 || eb[4] != 0x00 {
        return TestResult::Fail("LE_Set_Scan_Enable payload wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/e2e",
    smoke_e2e_hci_le_scan_enable_opcode_encoding
);

// ── 4. LE Advertising Report decodes to (addr, name) ───────────────

fn smoke_e2e_le_advertising_report_decode() -> TestResult {
    // §7.7.65.2 LE Advertising Report. Single report from peer
    // 11:22:33:44:55:66 carrying AD: Complete Local Name "TestBLE".
    // ad: len(8)=0x08, type(1)=0x09 (Complete Local Name), value=7 bytes.
    let ad = [0x08, 0x09, b'T', b'e', b's', b't', b'B', b'L', b'E'];
    let mut payload = vec![
        0x01, // num_reports
        0x00, // event_type = ADV_IND
        0x00, // address_type = public
        // address LE order — first byte is the low byte.
        0x66,
        0x55,
        0x44,
        0x33,
        0x22,
        0x11,
        ad.len() as u8,
    ];
    payload.extend_from_slice(&ad);
    payload.push(0xC0u8); // rssi = -64 dBm (signed)

    let event = le_meta(LeSubevent::AdvertisingReport, &payload);
    let reports = match crate::event::parse_le_advertising_reports(&event) {
        Some(r) => r,
        None => return TestResult::Fail("parse_le_advertising_reports returned None"),
    };
    if reports.len() != 1 {
        return TestResult::Fail("expected exactly one report");
    }
    let rep = &reports[0];
    if rep.address != [0x66, 0x55, 0x44, 0x33, 0x22, 0x11] {
        return TestResult::Fail("peer address mismatch");
    }
    if rep.rssi != -64 {
        return TestResult::Fail("RSSI sign decode wrong");
    }
    // AD type 0x09 = Complete Local Name; the encoded slice carries
    // the AD record verbatim, so just check the bytes match.
    if &rep.data[..] != &ad[..] {
        return TestResult::Fail("AD payload mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_le_advertising_report_decode);

// ── 5. LE Create Connection → LE Connection Complete decoded ──────

fn smoke_e2e_le_connection_complete_decode() -> TestResult {
    // §7.7.65.1 LE Connection Complete: status(1) + handle(2 LE) +
    // role(1) + peer_addr_type(1) + peer_addr(6 LE) + interval(2 LE)
    // + latency(2 LE) + timeout(2 LE) + accuracy(1).
    let payload = [
        0x00, // status = success
        0x40, 0x00, // connection_handle = 0x0040
        0x00, // role = central
        0x00, // peer_address_type = public
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // peer BD_ADDR
        0x18, 0x00, // interval = 0x0018 (30 ms @ 1.25 ms)
        0x00, 0x00, // peripheral_latency = 0
        0xF4, 0x01, // supervision_timeout = 500 (5 s @ 10 ms)
        0x00, // central_clock_accuracy
    ];
    let ev = le_meta(LeSubevent::ConnectionComplete, &payload);
    let cc = match LeConnectionComplete::parse(&ev) {
        Some(p) => p,
        None => return TestResult::Fail("LeConnectionComplete::parse None"),
    };
    if cc.status != 0 {
        return TestResult::Fail("status not zero");
    }
    if cc.handle != 0x0040 {
        return TestResult::Fail("connection_handle mismatch");
    }
    if cc.peer_address != [0x66, 0x55, 0x44, 0x33, 0x22, 0x11] {
        return TestResult::Fail("peer_address mismatch");
    }
    if cc.connection_interval != 0x0018 {
        return TestResult::Fail("interval mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_le_connection_complete_decode);

// ── 6. L2CAP Connect Request → pending + success response shapes ───

fn smoke_e2e_l2cap_signalling_connect_pending_then_success() -> TestResult {
    use l2cap::{
        build_connection_response, iter_signalling, SignallingCode, CONN_RESULT_PENDING,
        CONN_RESULT_SUCCESS, CONN_STATUS_AUTHENTICATION_PENDING, CONN_STATUS_NO_INFORMATION,
    };

    // Peer drives the inbound Connect Request on PSM 0x0003 (RFCOMM)
    // with identifier 0x05 and source CID 0x0040.
    let inbound = l2cap::build_connection_request(0x05, l2cap::PSM_RFCOMM, 0x0040);
    let mut wire = Vec::new();
    inbound.encode(&mut wire);
    // Walk it back out of the iter_signalling decoder to verify the
    // round-trip.
    let mut parsed = iter_signalling(&wire);
    let cmd = match parsed.next() {
        Some(c) => c,
        None => return TestResult::Fail("iter_signalling returned None"),
    };
    if cmd.code != SignallingCode::ConnectionRequest as u8 {
        return TestResult::Fail("not a Connection Request");
    }
    if cmd.identifier != 0x05 {
        return TestResult::Fail("identifier round-trip wrong");
    }
    // psm = LE u16 at [0..2], source_cid at [2..4].
    if u16::from_le_bytes([cmd.data[0], cmd.data[1]]) != l2cap::PSM_RFCOMM {
        return TestResult::Fail("PSM round-trip wrong");
    }

    // First response: Pending with Authentication Pending status.
    let pending = build_connection_response(
        cmd.identifier,
        0x0041,
        0x0040,
        CONN_RESULT_PENDING,
        CONN_STATUS_AUTHENTICATION_PENDING,
    );
    if pending.identifier != 0x05 {
        return TestResult::Fail("response should echo identifier");
    }
    // Second response: Success.
    let success = build_connection_response(
        cmd.identifier,
        0x0041,
        0x0040,
        CONN_RESULT_SUCCESS,
        CONN_STATUS_NO_INFORMATION,
    );
    let want_result = u16::from_le_bytes([success.data[4], success.data[5]]);
    if want_result != CONN_RESULT_SUCCESS {
        return TestResult::Fail("success result code wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/e2e",
    smoke_e2e_l2cap_signalling_connect_pending_then_success
);

// ── 7. SMP Pairing Request + Response with SC bit ──────────────────

struct E2eCrypto;
impl smp::SmpCrypto for E2eCrypto {
    fn p256_keygen(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([0x11; 32], [0x22; 32], [0x33; 32])
    }
    fn p256_dh(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 32]) -> [u8; 32] {
        [0x44; 32]
    }
    fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16] {
        // Deterministic — not a real MAC, but stable for state-machine
        // testing.
        let mut out = [0u8; 16];
        for (i, b) in key.iter().enumerate() {
            out[i] ^= *b;
        }
        for (i, b) in data.iter().enumerate() {
            out[i % 16] ^= *b;
        }
        out
    }
    fn rand128(&self) -> [u8; 16] {
        [0x55; 16]
    }
}

fn smoke_e2e_smp_pairing_request_response_sc_flag() -> TestResult {
    use smp::{
        IoCapability, PairingFeatureExchange, Pdu, Responder, ResponderState, AUTH_BONDING,
        AUTH_SC, SMP_PAIRING_REQUEST,
    };

    // Peer drives a Pairing Request with IO=NoInputNoOutput, OOB=No,
    // AuthReq = SC | Bonding. Verify the Responder mirrors it and
    // keeps the SC bit set on the way out.
    let mut r = Responder::new(E2eCrypto, [0u8; 7], [0u8; 7]);
    let req = PairingFeatureExchange {
        io_capability: IoCapability::NoInputNoOutput as u8,
        oob_data_flag: 0,
        auth_req: AUTH_BONDING | AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0,
        responder_key_distribution: 0,
    }
    .encode(SMP_PAIRING_REQUEST);
    let rsp: Pdu = match r.feed(&req) {
        Ok(Some(p)) => p,
        _ => return TestResult::Fail("responder did not emit Pairing Response"),
    };
    let decoded = match PairingFeatureExchange::decode(&rsp) {
        Some(d) => d,
        None => return TestResult::Fail("Pairing Response did not decode"),
    };
    if decoded.auth_req & AUTH_SC == 0 {
        return TestResult::Fail("Responder must keep SC bit set");
    }
    if r.state != ResponderState::GotRequest {
        return TestResult::Fail("state did not advance to GotRequest");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/e2e",
    smoke_e2e_smp_pairing_request_response_sc_flag
);

// ── 8. SMP Public Key exchange (64-byte EC P-256) ──────────────────

fn smoke_e2e_smp_public_key_exchange() -> TestResult {
    use smp::{
        IoCapability, PairingFeatureExchange, Pdu, Responder, ResponderState, AUTH_BONDING,
        AUTH_SC, SMP_PAIRING_PUBLIC_KEY, SMP_PAIRING_REQUEST,
    };

    let mut r = Responder::new(E2eCrypto, [0u8; 7], [0u8; 7]);
    let req = PairingFeatureExchange {
        io_capability: IoCapability::NoInputNoOutput as u8,
        oob_data_flag: 0,
        auth_req: AUTH_BONDING | AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0,
        responder_key_distribution: 0,
    }
    .encode(SMP_PAIRING_REQUEST);
    let _ = r.feed(&req);

    // Peer sends a 64-byte ECDH P-256 public key (X || Y).
    let mut pk_payload = Vec::with_capacity(64);
    pk_payload.extend(core::iter::repeat(0xAAu8).take(32));
    pk_payload.extend(core::iter::repeat(0xBBu8).take(32));
    let pk = Pdu {
        code: SMP_PAIRING_PUBLIC_KEY,
        payload: pk_payload,
    };
    let our_pk: Pdu = match r.feed(&pk) {
        Ok(Some(p)) => p,
        _ => return TestResult::Fail("responder did not emit own Public Key"),
    };
    if our_pk.code != SMP_PAIRING_PUBLIC_KEY {
        return TestResult::Fail("expected Pairing_Public_Key opcode");
    }
    if our_pk.payload.len() != 64 {
        return TestResult::Fail("public key must be 64 bytes (X||Y)");
    }
    if r.state != ResponderState::SentPublicKey {
        return TestResult::Fail("state did not advance to SentPublicKey");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_smp_public_key_exchange);

// ── 9. SMP Phase-2 random + LTK derivation ─────────────────────────

fn smoke_e2e_smp_phase2_ltk_derivation() -> TestResult {
    use smp::{
        IoCapability, PairingFeatureExchange, Pdu, Responder, ResponderState, AUTH_BONDING,
        AUTH_SC, SMP_PAIRING_DHKEY_CHECK, SMP_PAIRING_PUBLIC_KEY, SMP_PAIRING_RANDOM,
        SMP_PAIRING_REQUEST,
    };

    let mut r = Responder::new(E2eCrypto, [0u8; 7], [0u8; 7]);
    // 1) Pairing_Request.
    let req = PairingFeatureExchange {
        io_capability: IoCapability::NoInputNoOutput as u8,
        oob_data_flag: 0,
        auth_req: AUTH_BONDING | AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0,
        responder_key_distribution: 0,
    }
    .encode(SMP_PAIRING_REQUEST);
    let _ = r.feed(&req);

    // 2) Peer Public Key.
    let mut pk_payload = vec![0xAAu8; 64];
    for v in pk_payload.iter_mut().take(32) {
        *v = 0xAA;
    }
    for v in pk_payload.iter_mut().skip(32) {
        *v = 0xBB;
    }
    let _ = r.feed(&Pdu {
        code: SMP_PAIRING_PUBLIC_KEY,
        payload: pk_payload,
    });

    // 3) Peer Pairing Random (Na). Drives Nb out + LTK via f5.
    let nb: Pdu = match r.feed(&Pdu {
        code: SMP_PAIRING_RANDOM,
        payload: vec![0x77u8; 16],
    }) {
        Ok(Some(p)) => p,
        _ => return TestResult::Fail("responder did not emit Pairing_Random"),
    };
    if nb.code != SMP_PAIRING_RANDOM || nb.payload.len() != 16 {
        return TestResult::Fail("Pairing_Random shape wrong");
    }
    if r.ltk == [0u8; 16] {
        return TestResult::Fail("LTK should be derived (non-zero) by f5");
    }
    if r.state != ResponderState::SentRandom {
        return TestResult::Fail("state did not advance to SentRandom");
    }

    // 4) Peer DHKey Check.
    let our_check: Pdu = match r.feed(&Pdu {
        code: SMP_PAIRING_DHKEY_CHECK,
        payload: vec![0x99u8; 16],
    }) {
        Ok(Some(p)) => p,
        _ => return TestResult::Fail("responder did not emit DHKey check"),
    };
    if our_check.code != SMP_PAIRING_DHKEY_CHECK || our_check.payload.len() != 16 {
        return TestResult::Fail("DHKey check shape wrong");
    }
    if r.state != ResponderState::Done {
        return TestResult::Fail("state did not advance to Done");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_smp_phase2_ltk_derivation);

// ── 10. ATT MTU exchange — server picks min(client, server) ≥ 23 ───

fn smoke_e2e_att_exchange_mtu_round_trip() -> TestResult {
    let mut srv = GattServer::new();
    srv.mtu = 247;
    let req = att::build_exchange_mtu_request(517);
    let rsp = srv.handle_request(&req);
    if rsp.opcode != att::ATT_EXCHANGE_MTU_RSP {
        return TestResult::Fail("expected Exchange MTU Response opcode");
    }
    let server_mtu = match att::decode_exchange_mtu(&rsp) {
        Some(m) => m,
        None => return TestResult::Fail("MTU response did not decode"),
    };
    if server_mtu != 247 {
        return TestResult::Fail("MTU should clamp to min(client=517, server=247)");
    }
    if srv.mtu != 247 {
        return TestResult::Fail("server MTU state should be 247");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_att_exchange_mtu_round_trip);

// ── 11. GATT Primary Service Discovery ──────────────────────────────

fn smoke_e2e_gatt_discover_primary_services() -> TestResult {
    let mut srv = GattServer::new();
    services::mount_gap_service(
        &mut srv.db,
        "narf-be",
        services::APPEARANCE_GENERIC_COMPUTER,
    );
    services::mount_gatt_service(&mut srv.db);
    services::mount_device_information_service(
        &mut srv.db,
        &services::DeviceInformation {
            manufacturer: Some("NARF"),
            ..Default::default()
        },
    );
    services::mount_battery_service(&mut srv.db, 85);

    let req = gatt::build_discover_primary_services(0x0001, 0xFFFF);
    let rsp = srv.handle_request(&req);
    if rsp.opcode != att::ATT_READ_BY_GROUP_TYPE_RSP {
        return TestResult::Fail("expected Read By Group Type Response");
    }
    let services_found = gatt::parse_primary_services(&rsp.params);
    // The four services we mounted may not all be returned in a
    // single tuple if their value sizes differ — but GAP / GATT /
    // DIS / Battery all use 16-bit UUIDs so one frame should hold
    // every record. Verify the expected four service UUIDs land.
    let mut found_gap = false;
    let mut found_gatt = false;
    let mut found_dis = false;
    let mut found_bat = false;
    for rec in &services_found {
        if let gatt::Uuid::U16(u) = rec.uuid {
            match u {
                gatt::UUID_SERVICE_GAP => found_gap = true,
                gatt::UUID_SERVICE_GATT => found_gatt = true,
                gatt::UUID_SERVICE_DEVICE_INFORMATION => found_dis = true,
                gatt::UUID_SERVICE_BATTERY => found_bat = true,
                _ => {}
            }
        }
    }
    if !(found_gap && found_gatt && found_dis && found_bat) {
        return TestResult::Fail("not all four well-known services discovered");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_gatt_discover_primary_services);

// ── 12. GATT Read Characteristic — read the Device Name ─────────────

fn smoke_e2e_gatt_read_device_name_characteristic() -> TestResult {
    let mut srv = GattServer::new();
    services::mount_gap_service(
        &mut srv.db,
        "narf-test",
        services::APPEARANCE_GENERIC_COMPUTER,
    );

    // Find the Device Name attribute (UUID 0x2A00) by walking the DB.
    let mut name_handle: Option<u16> = None;
    for a in srv.db.attrs() {
        if a.uuid == gatt::Uuid::U16(services::UUID_DEVICE_NAME) {
            name_handle = Some(a.handle);
            break;
        }
    }
    let h = match name_handle {
        Some(h) => h,
        None => return TestResult::Fail("Device Name attribute not in DB"),
    };
    let rsp = srv.handle_request(&att::build_read_request(h));
    if rsp.opcode != att::ATT_READ_RSP {
        return TestResult::Fail("expected Read Response opcode");
    }
    if &rsp.params[..] != b"narf-test" {
        return TestResult::Fail("Device Name value mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/e2e",
    smoke_e2e_gatt_read_device_name_characteristic
);

// ── 13. GATT Battery Level subscribe via CCCD + notification PDU ────

fn smoke_e2e_gatt_battery_level_cccd_subscribe_and_notify() -> TestResult {
    let mut srv = GattServer::new();
    services::mount_gatt_service(&mut srv.db);
    let (_svc, level_handle, cccd_handle) = services::mount_battery_service(&mut srv.db, 85);

    // Peer writes the CCCD with the "enable notifications" bit set
    // (§3.3.3.3 / Vol 3 Part G — bit 0 of the 16-bit CCCD value).
    let write = att::build_write_request(cccd_handle, &services::cccd_value(true, false));
    let wrsp = srv.handle_request(&write);
    if wrsp.opcode != att::ATT_WRITE_RSP {
        return TestResult::Fail("CCCD write did not return Write Response");
    }
    // Verify the CCCD attribute now holds the subscription bits.
    let cccd_attr = match srv.db.attr_by_handle(cccd_handle) {
        Some(a) => a,
        None => return TestResult::Fail("CCCD attribute missing post-write"),
    };
    if cccd_attr.value[..] != [0x01, 0x00] {
        return TestResult::Fail("CCCD did not record notification subscription");
    }

    // Build the notification PDU NARF would emit on a battery change.
    let ntf = att::build_handle_value_notification(level_handle, &[85u8]);
    if ntf.opcode != att::ATT_HANDLE_VALUE_NTF {
        return TestResult::Fail("notification opcode wrong");
    }
    let (h, val) = match att::decode_handle_value(&ntf) {
        Some(v) => v,
        None => return TestResult::Fail("notification did not decode"),
    };
    if h != level_handle {
        return TestResult::Fail("notification handle mismatch");
    }
    if val != [85u8] {
        return TestResult::Fail("notification value mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/e2e",
    smoke_e2e_gatt_battery_level_cccd_subscribe_and_notify
);

// ── 14. HID-over-BT: Control + Interrupt PSMs + Data packet encode ──

fn smoke_e2e_hid_over_bt_data_round_trip() -> TestResult {
    use crate::hid_profile::{
        build_data, build_get_report, decode_header, parse_input_data, ReportType, TransactionType,
        PSM_HID_CONTROL, PSM_HID_INTERRUPT,
    };

    // §5.2 of the HID Profile spec fixes the L2CAP PSMs at 0x0011 +
    // 0x0013. Verify our constants agree (catches accidental swaps).
    if PSM_HID_CONTROL != 0x0011 {
        return TestResult::Fail("PSM_HID_CONTROL must be 0x0011");
    }
    if PSM_HID_INTERRUPT != 0x0013 {
        return TestResult::Fail("PSM_HID_INTERRUPT must be 0x0013");
    }
    // Round-trip: build a GET_REPORT command, ensure header parses.
    let req = build_get_report(ReportType::Input, Some(0x01), None);
    let hdr = match decode_header(&req) {
        Some(h) => h,
        None => return TestResult::Fail("decode_header None"),
    };
    if hdr.transaction != TransactionType::GetReport {
        return TestResult::Fail("transaction type round-trip wrong");
    }

    // Synthesise a DATA packet carrying a 3-byte input report
    // (Report ID + 2 data bytes). Verify parse_input_data peels the
    // header off correctly.
    let body = [0x01, 0x55, 0xAA];
    let pkt = build_data(ReportType::Input, &body);
    let parsed = match parse_input_data(&pkt) {
        Some(p) => p,
        None => return TestResult::Fail("parse_input_data None"),
    };
    if parsed != body {
        return TestResult::Fail("DATA payload round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_hid_over_bt_data_round_trip);

// ── 15. /dev/rfcomm<N> lifecycle ───────────────────────────────────

fn smoke_e2e_devfs_rfcomm_lifecycle() -> TestResult {
    use crate::devfs_bridge::{
        __reset_for_test, enumerate_rfcomm_devices, lookup_rfcomm_file, rfcomm_bind_loopback,
        rfcomm_release,
    };

    __reset_for_test();
    let minor = rfcomm_bind_loopback(1);
    if minor != 0 {
        return TestResult::Fail("first bind should yield minor=0");
    }
    if lookup_rfcomm_file("rfcomm0").is_none() {
        return TestResult::Fail("/dev/rfcomm0 should appear after bind");
    }
    let listed = enumerate_rfcomm_devices(0, usize::MAX);
    if !listed.iter().any(|(n, _)| n == "rfcomm0") {
        return TestResult::Fail("enumerate must include rfcomm0");
    }
    rfcomm_release(minor);
    if lookup_rfcomm_file("rfcomm0").is_some() {
        return TestResult::Fail("/dev/rfcomm0 should disappear after release");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_devfs_rfcomm_lifecycle);

// ── 16. /sys/class/bluetooth/hci0/address from synthetic BD_ADDR ────

fn smoke_e2e_sysfs_hci_address_after_bringup() -> TestResult {
    use crate::bootstrap_bluetooth_authority;
    use crate::sysfs_bridge::register_hci_controller;
    use narf_filesystem::sysfs::__reset_for_test;

    __reset_for_test();

    // Drive a full bring-up against a loopback transport with a known
    // BD_ADDR, then register the resulting ControllerInfo into sysfs
    // and verify the address attribute reads back in the expected
    // "XX:XX:XX:XX:XX:XX" form (MSB first).
    let lt = Arc::new(LoopbackTransport::new("e2e-sysfs"));
    lt.enqueue_event(cc(op::HCI_RESET, 0x00, &[]));
    lt.enqueue_event(cc(op::HCI_READ_LOCAL_VERSION, 0x00, &[0; 8]));
    let want = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    lt.enqueue_event(cc(op::HCI_READ_BD_ADDR, 0x00, &want));
    lt.enqueue_event(cc(op::HCI_READ_BUFFER_SIZE, 0x00, &[0; 7]));
    lt.enqueue_event(cc(op::HCI_SET_EVENT_MASK, 0x00, &[]));
    let controller = Controller::new(lt.clone());
    let cap = bootstrap_bluetooth_authority();
    let info = match controller.bring_up(&cap) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("bring_up failed"),
    };
    let kobj = register_hci_controller(0, info, &[]);
    let addr = match kobj.attr_show("address") {
        Some(s) => s,
        None => return TestResult::Fail("address attr missing"),
    };
    // wire bytes [DE AD BE EF CA FE] (LE-order on the wire) → display
    // MSB first → "FE:CA:EF:BE:AD:DE".
    if !addr.contains("FE:CA:EF:BE:AD:DE") {
        return TestResult::Fail("sysfs address format mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_sysfs_hci_address_after_bringup);

// ── 17. A2DP source — SBC encode + sync word at frame start ────────

fn smoke_e2e_a2dp_sbc_encode_sync_word() -> TestResult {
    // Build the narrowest legal SBC config and encode a single block
    // of silence. A2DP §12.4 specifies every SBC frame on the wire
    // begins with the 0x9C sync byte; verify it.
    let header = narf_audio::sbc::Header {
        sampling_frequency: 2, // 44.1 kHz
        blocks: 0,             // 4 blocks
        channel_mode: 0,       // mono
        allocation_method: 0,  // loudness
        subbands: 0,           // 4 subbands
        bitpool: 16,
        crc: 0,
    };
    let mut enc = narf_audio::sbc::Sbc::new(header);
    let pcm_len = enc.pcm_frame_len();
    let pcm = alloc::vec![0i16; pcm_len];
    let mut buf = alloc::vec![0u8; enc.frame_bytes()];
    if enc.encode(&pcm, &mut buf).is_err() {
        return TestResult::Fail("SBC encode failed");
    }
    if buf.is_empty() {
        return TestResult::Fail("SBC frame empty");
    }
    if buf[0] != narf_audio::sbc::SBC_SYNCWORD {
        return TestResult::Fail("SBC frame must start with 0x9C sync");
    }
    // Sanity: encoded frame length matches the spec computation.
    if buf.len() != enc.frame_bytes() {
        return TestResult::Fail("encoded length != frame_bytes()");
    }
    TestResult::Pass
}
kernel_test_in!("bluetooth/e2e", smoke_e2e_a2dp_sbc_encode_sync_word);

// ── 18. GATT server: Permissions::read passes correct flags ────────
//
// Cross-layer cleanup smoke — confirms a Permissions::read attribute
// declines writes (server emits Write Not Permitted) even though the
// rest of the stack is willing to relay the request. Catches the
// "anything ATT relays gets written" regression once.

fn smoke_e2e_gatt_write_rejected_on_readonly_attribute() -> TestResult {
    let mut srv = GattServer::new();
    let _ = srv
        .db
        .add_primary_service(gatt::Uuid::U16(gatt::UUID_SERVICE_GAP));
    let (_, val_h) = srv.db.add_characteristic(
        gatt::Uuid::U16(services::UUID_DEVICE_NAME),
        gatt::CHAR_PROP_READ,
        Permissions::read(),
        b"locked".to_vec(),
    );
    let write = att::build_write_request(val_h, b"unwanted");
    let rsp = srv.handle_request(&write);
    if rsp.opcode != att::ATT_ERROR_RSP {
        return TestResult::Fail("write to read-only attr should error");
    }
    let err = match att::decode_error_response(&rsp) {
        Some(e) => e,
        None => return TestResult::Fail("error response did not decode"),
    };
    if err.error_code != att::ATT_ECODE_WRITE_NOT_PERMITTED {
        return TestResult::Fail("wrong error code (want Write Not Permitted)");
    }
    // And the attribute value is unchanged.
    let attr = match srv.db.attr_by_handle(val_h) {
        Some(a) => a,
        None => return TestResult::Fail("attr disappeared"),
    };
    if attr.value != b"locked" {
        return TestResult::Fail("read-only attr was mutated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/e2e",
    smoke_e2e_gatt_write_rejected_on_readonly_attribute
);
