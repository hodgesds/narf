//! XDomain fixtures: two production engines wired back-to-back
//! over an in-memory channel pair.
//!
//! The peer in every fixture is a second instance of the engine
//! under test (plus, for the malformed cases, a scripted responder
//! built from hand-written dword literals). That is the honest end
//! of "two connection managers talking": both sides run the real
//! state machines, and the wire bytes they exchange are pinned
//! byte-for-byte against hand-computed vectors from the protocol
//! sources in `xdomain_protocol_vectors` and
//! `xdomain_property_block_byte_for_byte`, so the pair cannot agree
//! on a wrong framing and pass.
//!
//! Global-state hygiene: the published peer registry and the
//! netdev registry are shared with the other fixtures in the boot
//! (notably `pm_tests`, whose first phase requires an idle world),
//! so every fixture here unregisters and forgets its domains and
//! leaves `live_link_count() == 0` behind.

use super::*;
use crate::tbnet::{fragment, DataLink, Reassembler, MAX_PAYLOAD};
use crate::topology::{Domain, Router};
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::Interface as _;

fn uuid_a() -> Uuid {
    Uuid::from_fields(
        0x1111_1111,
        0x2222,
        0x3333,
        [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44],
    )
}

fn uuid_b() -> Uuid {
    Uuid::from_fields(
        0x5555_5555,
        0x6666,
        0x7777,
        [0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88],
    )
}

/// A two-router domain as one host sees it: itself at route 0 and
/// the peer host's router as its depth-1 child at route 1.
fn fixture_domain(id: u32) -> Domain {
    let router = |route: u64, device: u16| Router {
        route,
        upstream: if route == 0 { 0 } else { 1 },
        vendor: 0x8086,
        device,
        ports: Vec::new(),
    };
    Domain {
        id,
        routers: alloc::vec![router(0, 0x1000 + id as u16), router(1, 0x2000 + id as u16)],
    }
}

struct Side {
    engine: Rc<RefCell<Engine>>,
    inbox: Rc<RefCell<Vec<(u8, Vec<u32>)>>>,
    domain: Domain,
}

impl Side {
    fn new(domain_id: u32, uuid: Uuid, root: PropDir) -> Self {
        let mut engine = Engine::new(domain_id, crate::firmware::CONTROL_XDOMAIN);
        engine.set_identity(uuid, root);
        Self {
            engine: Rc::new(RefCell::new(engine)),
            inbox: Rc::new(RefCell::new(Vec::new())),
            domain: fixture_domain(domain_id),
        }
    }

    fn channel(&self, peer: &Side) -> TestChannel {
        TestChannel {
            mine: self.inbox.clone(),
            peer_inbox: peer.inbox.clone(),
            peer_engine: peer.engine.clone(),
        }
    }

    fn peer_info(&self) -> Option<PeerInfo> {
        peers().into_iter().find(|p| p.domain == self.domain.id)
    }
}

/// The fixture channel: delivering a frame to the peer runs the
/// peer engine's packet handler synchronously (the CM loop would
/// do it on its next pass; the outcome is identical because the
/// handler is a pure state-machine step), and an exchange completes
/// with the first queued frame matching the reference match rule
/// (kind 7, masked route equal, protocol UUID equal).
struct TestChannel {
    mine: Rc<RefCell<Vec<(u8, Vec<u32>)>>>,
    peer_inbox: Rc<RefCell<Vec<(u8, Vec<u32>)>>>,
    peer_engine: Rc<RefCell<Engine>>,
}

fn wire_route(words: &[u32]) -> u64 {
    ((words[0] as u64) << 32) | words[1] as u64
}

impl XdChannel for TestChannel {
    async fn exchange(&mut self, kind: u8, words: &[u32]) -> Result<Vec<u32>, Error> {
        self.peer_inbox.borrow_mut().push((kind, words.to_vec()));
        let queued: Vec<(u8, Vec<u32>)> = self.peer_inbox.borrow_mut().drain(..).collect();
        let mut engine = self.peer_engine.borrow_mut();
        for (k, w) in queued {
            for out in engine.handle_packet(k, &w) {
                self.mine.borrow_mut().push(out);
            }
        }
        drop(engine);
        let want_route = wire_route(words) & !ROUTE_REPLY_BIT;
        let mut inbox = self.mine.borrow_mut();
        let pos = inbox.iter().position(|(k, w)| {
            *k == PKG_XDOMAIN_RESP
                && w.len() >= 7
                && wire_route(w) & !ROUTE_REPLY_BIT == want_route
                && w[3..7] == words[3..7]
        });
        match pos {
            Some(pos) => Ok(inbox.remove(pos).1),
            None => Err(Error::Timeout),
        }
    }

    async fn send(&mut self, kind: u8, words: &[u32]) -> Result<(), Error> {
        self.peer_inbox.borrow_mut().push((kind, words.to_vec()));
        Ok(())
    }

    fn drain(&mut self) -> Vec<(u8, Vec<u32>)> {
        self.mine.borrow_mut().drain(..).collect()
    }
}

/// An in-memory data transport pair endpoint.
struct MemLink {
    out: Arc<narf_lib::sync::IrqSafeSpinLock<Vec<(u8, Vec<u8>)>>>,
    inc: Arc<narf_lib::sync::IrqSafeSpinLock<Vec<(u8, Vec<u8>)>>>,
}

impl DataLink for MemLink {
    fn send_frame(&mut self, pdf: u8, frame: &[u8]) {
        self.out.lock().push((pdf, frame.to_vec()));
    }
    fn poll_frames(&mut self) -> Vec<(u8, Vec<u8>)> {
        core::mem::take(&mut *self.inc.lock())
    }
}

/// Run both engines' service passes alternately.
fn drive(a: &Side, b: &Side, rounds: usize) {
    for _ in 0..rounds {
        {
            let mut chan = a.channel(b);
            let mut engine = a.engine.borrow_mut();
            narf_scheduler::block_on_spin(engine.service(&mut chan, &a.domain));
        }
        {
            let mut chan = b.channel(a);
            let mut engine = b.engine.borrow_mut();
            narf_scheduler::block_on_spin(engine.service(&mut chan, &b.domain));
        }
    }
}

fn stack_frame(payload: &[u8]) -> Option<narf_net::Frame> {
    let buf =
        narf_io::alloc_coherent(payload.len().max(1), narf_lib::id::DomainId::DRIVER_0).ok()?;
    // SAFETY: the buffer was just allocated for at least
    // `payload.len()` bytes and is exclusively owned here.
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), buf.cpu_mut_ptr::<u8>(), payload.len());
    }
    Some(narf_net::Frame::new(buf, payload.len() as u32))
}

fn push_tx(side: &Side, payload: &[u8]) -> bool {
    let engine = side.engine.borrow();
    let Some(peer) = engine.peers.iter().find(|p| p.route == 1) else {
        return false;
    };
    let Some(net) = &peer.net else {
        return false;
    };
    let mut ring = net.interface().tx_ring().lock();
    let Some(producer) = ring.as_mut() else {
        return false;
    };
    let Some(frame) = stack_frame(payload) else {
        return false;
    };
    producer.try_send(frame).is_ok()
}

fn pop_rx(side: &Side) -> Option<Vec<u8>> {
    let engine = side.engine.borrow();
    let peer = engine.peers.iter().find(|p| p.route == 1)?;
    let net = peer.net.as_ref()?;
    let mut ring = net.interface().rx_ring().lock();
    let consumer = ring.as_mut()?;
    consumer
        .try_recv()
        .ok()
        .flatten()
        .map(|f| f.payload().to_vec())
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
}

// -----------------------------------------------------------------
// Byte-for-byte protocol vectors (hand-computed from tb_msgs.h /
// thunderbolt.c layouts; see the per-vector notes).
// -----------------------------------------------------------------

fn xdomain_protocol_vectors() -> TestResult {
    // PROPERTIES_REQUEST: route 1, sequence 2, src = uuid_a,
    // dst = uuid_b, offset 0x1234. Payload dwords after the
    // 3-dword XDomain header: protocol UUID (4) + type (1) +
    // src (4) + dst (4) + offset/reserved (1) = 14, so
    // length_sn = 14 | (2 << 27).
    let request = encode_xdp(
        1,
        2,
        &XdpMessage::PropertiesRequest {
            src: uuid_a(),
            dst: uuid_b(),
            offset: 0x1234,
        },
    );
    let expected: Vec<u32> = alloc::vec![
        0x0000_0000,
        0x0000_0001,
        0x1000_000e,
        // XDP protocol UUID b638d70e-42ff-40bb-97c2-90e2c0b2ff07
        0xb638_d70e,
        0x40bb_42ff,
        0xe290_c297,
        0x07ff_b2c0,
        3, // PROPERTIES_REQUEST
        0x1111_1111,
        0x3333_2222,
        0x4444_4444,
        0x4444_4444,
        0x5555_5555,
        0x7777_6666,
        0x8888_8888,
        0x8888_8888,
        0x0000_1234,
    ];
    if request != expected {
        return TestResult::Fail("properties request encoding differs from the spec vector");
    }
    match decode_xdp(&expected) {
        Some((head, XdpMessage::PropertiesRequest { src, dst, offset }))
            if head.route == 1
                && head.sequence == 2
                && src == uuid_a()
                && dst == uuid_b()
                && offset == 0x1234 => {}
        _ => return TestResult::Fail("properties request vector did not decode to its fields"),
    }

    // ThunderboltIP LOGIN: route 1, sequence 1, command_id 7,
    // initiator uuid_a, target uuid_b, proto_version 1,
    // transmit_path 0xf. Total 23 dwords; payload 20, so
    // length_sn = 20 | (1 << 27).
    let login = encode_ip(
        1,
        1,
        7,
        uuid_a(),
        uuid_b(),
        &IpMessage::Login {
            initiator: uuid_a(),
            target: uuid_b(),
            proto_version: 1,
            transmit_path: 0xf,
        },
    );
    let expected_login: Vec<u32> = alloc::vec![
        0x0000_0000,
        0x0000_0001,
        0x0800_0014,
        // ThunderboltIP UUID 798f589e-3616-8a47-97c6-5664a920c8dd
        0x798f_589e,
        0x8a47_3616,
        0x6456_c697,
        0xddc8_20a9,
        0x1111_1111,
        0x3333_2222,
        0x4444_4444,
        0x4444_4444,
        0x5555_5555,
        0x7777_6666,
        0x8888_8888,
        0x8888_8888,
        0,   // TBIP_LOGIN
        7,   // command_id
        1,   // proto_version
        0xf, // transmit_path
        0,
        0,
        0,
        0, // reserved[4]
    ];
    if login != expected_login {
        return TestResult::Fail("login frame encoding differs from the spec vector");
    }
    match decode_ip(&expected_login) {
        Some((
            head,
            7,
            IpMessage::Login {
                proto_version,
                transmit_path,
                ..
            },
        )) if head.route == 1 && proto_version == 1 && transmit_path == 0xf => {}
        _ => return TestResult::Fail("login vector did not decode to its fields"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/xdomain", xdomain_protocol_vectors);

fn xdomain_property_block_byte_for_byte() -> TestResult {
    // The local root for (vendorid 0x8086 "Intel Corp.",
    // deviceid 0x1111 "host-a") formatted by hand from the
    // property.c layout: root header (magic + entry dwords = 24),
    // six entries, then the leaf data region (vendor text 3
    // dwords at 26, device text 2 dwords at 29, one padding dword
    // at 31), then the network directory at 32 (UUID + 4 entries).
    // Keys and text/data payloads are big-endian per dword; entry
    // headers and the root header are native (little-endian).
    let expected: Vec<u32> = alloc::vec![
        0x5558_4401,
        24, // root magic, entry dwords
        // vendorid VALUE 0x8086
        0x7665_6e64,
        0x6f72_6964,
        0x0400_0001,
        0x0000_8086,
        // vendorid TEXT, 3 dwords at offset 26
        0x7665_6e64,
        0x6f72_6964,
        0x0300_0003,
        26,
        // deviceid VALUE 0x1111
        0x6465_7669,
        0x6365_6964,
        0x0400_0001,
        0x0000_1111,
        // deviceid TEXT, 2 dwords at offset 29
        0x6465_7669,
        0x6365_6964,
        0x0300_0002,
        29,
        // devicerv VALUE 0x80000100
        0x6465_7669,
        0x6365_7276,
        0x0400_0001,
        0x8000_0100,
        // network DIRECTORY: length 20 (uuid + entries), at 32
        0x6e65_7477,
        0x6f72_6b00,
        0x0100_0014,
        32,
        // leaf data region
        0x496e_7465,
        0x6c20_436f,
        0x7270_2e00, // "Intel Corp."
        0x686f_7374,
        0x2d61_0000, // "host-a"
        0x0000_0000, // padding dword before the child directory
        // network directory: UUID c66189ca-1cce-4195-bdb8-49592e5f5a4f
        0xc661_89ca,
        0x4195_1cce,
        0x5949_b8bd,
        0x4f5a_5f2e,
        // prtcid VALUE 1
        0x7072_7463,
        0x6964_0000,
        0x0400_0001,
        1,
        // prtcvers VALUE 1
        0x7072_7463,
        0x7665_7273,
        0x0400_0001,
        1,
        // prtcrevs VALUE 1
        0x7072_7463,
        0x7265_7673,
        0x0400_0001,
        1,
        // prtcstns VALUE 2 (MATCH_FRAGS_ID)
        0x7072_7463,
        0x7374_6e73,
        0x0400_0001,
        2,
    ];
    let root = local_root(0x8086, "Intel Corp.", 0x1111, "host-a");
    if format_block(&root) != expected {
        return TestResult::Fail("formatted property block differs from the hand-computed block");
    }
    // The other direction: parsing the hand-computed block must
    // recover the identity and the networking service.
    let parsed = match parse_block(&expected) {
        Ok(dir) => dir,
        Err(_) => return TestResult::Fail("hand-computed block did not parse"),
    };
    let identity = host_identity(&parsed);
    if identity
        != Some(HostIdentity {
            vendor_id: 0x8086,
            vendor_name: "Intel Corp.".into(),
            device_id: 0x1111,
            device_name: "host-a".into(),
            device_revision: 0x8000_0100,
        })
    {
        return TestResult::Fail("identity recovered from the block is wrong");
    }
    let svc = network_service(&parsed);
    if svc
        != Some(ServiceInfo {
            key: "network".into(),
            dir_uuid: NETWORK_DIR_UUID,
            protocol_id: 1,
            protocol_version: 1,
            protocol_revision: 1,
            protocol_instances: MATCH_FRAGS_ID,
        })
    {
        return TestResult::Fail("network service recovered from the block is wrong");
    }
    // Fail-closed parsing: bad magic, a VALUE entry whose length
    // is not 1, and an entry pointing past the block all reject.
    let mut bad = expected.clone();
    bad[0] = 0x5558_4402;
    if parse_block(&bad).is_ok() {
        return TestResult::Fail("bad-magic block parsed");
    }
    let mut bad = expected.clone();
    bad[4] = 0x0400_0002; // vendorid VALUE with length 2
    if parse_block(&bad) != Err(PropError::BadValueLength) {
        return TestResult::Fail("VALUE entry with length 2 parsed");
    }
    let mut bad = expected.clone();
    bad[9] = 500; // vendorid TEXT payload offset beyond the block
    if parse_block(&bad) != Err(PropError::OutOfBounds) {
        return TestResult::Fail("out-of-bounds payload offset parsed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/xdomain",
    xdomain_property_block_byte_for_byte
);

// -----------------------------------------------------------------
// Two-engine end-to-end: discovery, login, data, logout, reconnect.
// -----------------------------------------------------------------

fn xdomain_two_hosts_end_to_end() -> TestResult {
    let a = Side::new(
        90,
        uuid_a(),
        local_root(0x8086, "Intel Corp.", 0x1111, "host-a"),
    );
    let b = Side::new(91, uuid_b(), local_root(0x1022, "AMD", 0x2222, "host-b"));

    // Discovery + property fetch (the 52-dword block needs two
    // chunks at 45 dwords per response, so this also exercises
    // chunked fetch on both sides).
    drive(&a, &b, 6);
    let (info_a, info_b) = match (a.peer_info(), b.peer_info()) {
        (Some(x), Some(y)) => (x, y),
        _ => return TestResult::Fail("peers did not discover each other"),
    };
    if info_a.uuid != uuid_b()
        || info_a.identity.vendor_id != 0x1022
        || info_a.identity.device_name != "host-b"
        || info_b.uuid != uuid_a()
        || info_b.identity.vendor_id != 0x8086
        || network_service_present(&info_a) != Some(MATCH_FRAGS_ID)
        || network_service_present(&info_b) != Some(MATCH_FRAGS_ID)
    {
        return TestResult::Fail("discovered peer identity/services are wrong");
    }

    // Bind the data transports, then log in both ways.
    let ab = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    let ba = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    a.engine.borrow_mut().bind_data_link(
        1,
        Box::new(MemLink {
            out: ab.clone(),
            inc: ba.clone(),
        }),
    );
    b.engine.borrow_mut().bind_data_link(
        1,
        Box::new(MemLink {
            out: ba.clone(),
            inc: ab.clone(),
        }),
    );
    drive(&a, &b, 6);
    let (info_a, info_b) = match (a.peer_info(), b.peer_info()) {
        (Some(x), Some(y)) => (x, y),
        _ => return TestResult::Fail("peers vanished after login phase"),
    };
    if !info_a.login_connected || !info_b.login_connected || !info_a.link_up || !info_b.link_up {
        return TestResult::Fail("mutual ThunderboltIP login did not complete");
    }
    if live_link_count() != 2 {
        return TestResult::Fail("live link count does not reflect both sessions");
    }

    // Ethernet frames across, both directions: a small frame and a
    // multi-frame packet (9000 bytes = 3 ThunderboltIP frames).
    let small = pattern(60, 0x10);
    let big = pattern(9000, 0x40);
    if !push_tx(&a, &small) || !push_tx(&a, &big) {
        return TestResult::Fail("could not queue TX frames on A");
    }
    drive(&a, &b, 3);
    if pop_rx(&b) != Some(small.clone()) || pop_rx(&b) != Some(big.clone()) {
        return TestResult::Fail("frames A->B did not arrive intact");
    }
    if !push_tx(&b, &small) {
        return TestResult::Fail("could not queue TX frame on B");
    }
    drive(&a, &b, 3);
    if pop_rx(&a) != Some(small) {
        return TestResult::Fail("frame B->A did not arrive intact");
    }

    // A properties-changed from B revalidates A's view without
    // dropping the session (same generation: stale rule).
    {
        let mut engine = a.engine.borrow_mut();
        let out = engine.handle_packet(
            PKG_XDOMAIN_REQ,
            &encode_xdp(
                1,
                0,
                &XdpMessage::PropertiesChangedRequest { src: uuid_b() },
            ),
        );
        let answered = out.len() == 1
            && matches!(
                decode_xdp(&out[0].1),
                Some((_, XdpMessage::PropertiesChangedResponse))
            );
        if !answered {
            return TestResult::Fail("properties-changed was not answered");
        }
    }
    drive(&a, &b, 4);
    match a.peer_info() {
        Some(info) if info.login_connected => {}
        _ => return TestResult::Fail("session dropped across a properties re-read"),
    }

    // Logout from A: one A pass performs the LOGOUT exchange and
    // B's handler clears its session synchronously, so both
    // engines observe the link down (B's engines re-login on
    // their own passes, so the down state is asserted here, before
    // any further driving).
    a.engine.borrow_mut().initiate_logout(1);
    {
        let mut chan = a.channel(&b);
        let mut engine = a.engine.borrow_mut();
        narf_scheduler::block_on_spin(engine.service(&mut chan, &a.domain));
    }
    let session_down = |side: &Side| {
        side.engine
            .borrow()
            .peers
            .iter()
            .find(|p| p.route == 1)
            .map(|p| !p.connected())
            == Some(true)
    };
    if !session_down(&a)
        || !session_down(&b)
        || a.peer_info().map(|i| i.login_connected) != Some(false)
    {
        return TestResult::Fail("logout did not tear down both sides");
    }

    // Reconnect happens on its own (the engines re-login against
    // the standing properties).
    drive(&a, &b, 6);
    let back_a = a.peer_info().map(|i| i.login_connected) == Some(true);
    let back_b = b.peer_info().map(|i| i.login_connected) == Some(true);
    if !back_a || !back_b || live_link_count() != 2 {
        return TestResult::Fail("sessions did not reconnect after logout");
    }

    // Hygiene: dropping the engines unregisters the netdevs; the
    // published peers are forgotten explicitly.
    drop(a);
    drop(b);
    forget_domain(90);
    forget_domain(91);
    if live_link_count() != 0 || peers().iter().any(|p| p.domain == 90 || p.domain == 91) {
        return TestResult::Fail("fixture left published XDomain state behind");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/xdomain", xdomain_two_hosts_end_to_end);

fn network_service_present(info: &PeerInfo) -> Option<u32> {
    info.services
        .iter()
        .find(|s| s.key == "network" && s.dir_uuid == NETWORK_DIR_UUID)
        .map(|s| s.protocol_instances)
}

// -----------------------------------------------------------------
// Data plane validation (tbnet fragment/reassembly rules).
// -----------------------------------------------------------------

fn xdomain_tbnet_reassembly_rules() -> TestResult {
    // Fragmentation of a 9000-byte packet: 3 frames of
    // 4084 + 4084 + 832 payload bytes, header pinned on frame 0.
    let packet = pattern(9000, 0x21);
    let frames = fragment(&packet, 7);
    if frames.len() != 3 {
        return TestResult::Fail("9000-byte packet did not split into 3 frames");
    }
    let (pdf, first) = &frames[0];
    if *pdf != 3
        || first[0..4] != (MAX_PAYLOAD as u32).to_le_bytes()
        || first[4..6] != 0u16.to_le_bytes()
        || first[6..8] != 7u16.to_le_bytes()
        || first[8..12] != 3u32.to_le_bytes()
    {
        return TestResult::Fail("first fragment header is wrong");
    }
    if frames[2].1.len() != 12 + 832 {
        return TestResult::Fail("last fragment size is wrong");
    }
    // In-order reassembly reproduces the packet.
    let mut rx = Reassembler::default();
    let mut out = None;
    for (_, frame) in &frames {
        out = rx.push(frame).or(out);
    }
    if out != Some(packet.clone()) {
        return TestResult::Fail("reassembly did not reproduce the packet");
    }
    // A skipped index drops the packet in progress; the next
    // well-formed first fragment starts cleanly.
    let mut rx = Reassembler::default();
    if rx.push(&frames[0].1).is_some() || rx.push(&frames[2].1).is_some() {
        return TestResult::Fail("out-of-order fragment was accepted");
    }
    let mut out = None;
    for (_, frame) in &frames {
        out = rx.push(frame).or(out);
    }
    if out != Some(packet.clone()) {
        return TestResult::Fail("reassembler did not recover after a dropped packet");
    }
    // A frame_id change mid-packet is a missed-frame error.
    let mut rx = Reassembler::default();
    let mut wrong_id = frames[1].1.clone();
    wrong_id[6..8].copy_from_slice(&8u16.to_le_bytes());
    if rx.push(&frames[0].1).is_some() || rx.push(&wrong_id).is_some() || rx.errors != 1 {
        return TestResult::Fail("frame_id change mid-packet was accepted");
    }
    // First-fragment validation: frame_count 0 and 65 are both
    // out of range; a header-only frame carries no data.
    let mut rx = Reassembler::default();
    let mut bad = frames[0].1.clone();
    bad[8..12].copy_from_slice(&65u32.to_le_bytes());
    if rx.push(&bad).is_some() {
        return TestResult::Fail("frame_count 65 was accepted");
    }
    bad[8..12].copy_from_slice(&0u32.to_le_bytes());
    if rx.push(&bad).is_some() {
        return TestResult::Fail("frame_count 0 was accepted");
    }
    if rx.push(&frames[0].1[..12]).is_some() {
        return TestResult::Fail("header-only frame was accepted");
    }
    // frame_size beyond the delivered bytes is a length error.
    let mut bad = frames[0].1.clone();
    bad[0..4].copy_from_slice(&9999u32.to_le_bytes());
    if rx.push(&bad).is_some() {
        return TestResult::Fail("oversized frame_size was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/xdomain",
    xdomain_tbnet_reassembly_rules
);

// -----------------------------------------------------------------
// Fail-closed packet handling against one live engine.
// -----------------------------------------------------------------

fn xdomain_fail_closed_packets() -> TestResult {
    let a = Side::new(
        94,
        uuid_a(),
        local_root(0x8086, "Intel Corp.", 0x1111, "host-a"),
    );
    let mut engine = a.engine.borrow_mut();

    // Properties request addressed to a different domain UUID:
    // exactly one ERROR_UNKNOWN_DOMAIN response.
    let out = engine.handle_packet(
        PKG_XDOMAIN_REQ,
        &encode_xdp(
            1,
            0,
            &XdpMessage::PropertiesRequest {
                src: uuid_b(),
                dst: Uuid::from_fields(0xdead, 0xbeef, 0xcafe, [1; 8]),
                offset: 0,
            },
        ),
    );
    let answered = out.len() == 1
        && matches!(
            decode_xdp(&out[0].1),
            Some((
                _,
                XdpMessage::ErrorResponse {
                    error: XdpError::UnknownDomain
                }
            ))
        );
    if !answered {
        return TestResult::Fail("wrong-domain properties request not refused with UNKNOWN_DOMAIN");
    }

    // Offset at the end of our block: invalid, silently dropped.
    let out = engine.handle_packet(
        PKG_XDOMAIN_REQ,
        &encode_xdp(
            1,
            0,
            &XdpMessage::PropertiesRequest {
                src: uuid_b(),
                dst: uuid_a(),
                offset: 52,
            },
        ),
    );
    if !out.is_empty() {
        return TestResult::Fail("out-of-range properties offset was answered");
    }

    // Length field disagreeing with the frame size: dropped.
    let mut tampered = encode_xdp(1, 0, &XdpMessage::UuidRequest);
    tampered[2] = 0x3f;
    if !engine.handle_packet(PKG_XDOMAIN_REQ, &tampered).is_empty() {
        return TestResult::Fail("length-tampered packet was answered");
    }

    // A request arriving on the response kind is not a request.
    if !engine
        .handle_packet(
            PKG_XDOMAIN_RESP,
            &encode_xdp(1, 0, &XdpMessage::UuidRequest),
        )
        .is_empty()
    {
        return TestResult::Fail("response-kind XDP frame was treated as a request");
    }

    // ThunderboltIP LOGIN from an initiator that is not the peer
    // at that route: ignored, no session state created.
    let stranger = Uuid::from_fields(0x9999, 0x8888, 0x7777, [0x66; 8]);
    let out = engine.handle_packet(
        PKG_XDOMAIN_RESP,
        &encode_ip(
            1,
            0,
            1,
            stranger,
            uuid_a(),
            &IpMessage::Login {
                initiator: stranger,
                target: uuid_a(),
                proto_version: 1,
                transmit_path: 0xf,
            },
        ),
    );
    if !out.is_empty() || !engine.peers.is_empty() {
        return TestResult::Fail("stranger LOGIN created state");
    }
    drop(engine);
    drop(a);
    forget_domain(94);
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/xdomain", xdomain_fail_closed_packets);

// -----------------------------------------------------------------
// A scripted peer serving a corrupt property block: the fetch
// completes at the transport level and the peer is still refused.
// The script answers from hand-written dword literals.
// -----------------------------------------------------------------

struct ScriptChannel {
    uuid_response: Vec<u32>,
    props_response: Vec<u32>,
    inbox: Vec<(u8, Vec<u32>)>,
}

impl XdChannel for ScriptChannel {
    async fn exchange(&mut self, _kind: u8, words: &[u32]) -> Result<Vec<u32>, Error> {
        match words.get(7) {
            Some(&XDP_UUID_REQUEST) => Ok(self.uuid_response.clone()),
            Some(&XDP_PROPERTIES_REQUEST) => Ok(self.props_response.clone()),
            _ => Err(Error::Timeout),
        }
    }
    async fn send(&mut self, _kind: u8, _words: &[u32]) -> Result<(), Error> {
        Ok(())
    }
    fn drain(&mut self) -> Vec<(u8, Vec<u32>)> {
        core::mem::take(&mut self.inbox)
    }
}

fn xdomain_bad_property_block_rejected() -> TestResult {
    // Scripted peer UUID: 99999999-8888-7777-6666-666666666666.
    let script_uuid = Uuid::from_fields(0x9999_9999, 0x8888, 0x7777, [0x66; 8]);
    let uuid_response: Vec<u32> = alloc::vec![
        0x8000_0000,
        1,
        9, // route (reply bit set), payload 9
        0xb638_d70e,
        0x40bb_42ff,
        0xe290_c297,
        0x07ff_b2c0, // XDP UUID
        2,           // UUID_RESPONSE
        0x9999_9999,
        0x7777_8888,
        0x6666_6666,
        0x6666_6666,
    ];
    // Properties response carrying a 6-dword block whose root
    // magic is wrong (0xdeadbeef instead of 0x55584401).
    let props_response: Vec<u32> = alloc::vec![
        0x8000_0000,
        1,
        21, // payload 15 + 6 data
        0xb638_d70e,
        0x40bb_42ff,
        0xe290_c297,
        0x07ff_b2c0,
        4, // PROPERTIES_RESPONSE
        0x9999_9999,
        0x7777_8888,
        0x6666_6666,
        0x6666_6666, // src
        0x1111_1111,
        0x3333_2222,
        0x4444_4444,
        0x4444_4444, // dst = uuid_a
        0x0006_0000, // offset 0, data_length 6
        1,           // generation
        0xdead_beef,
        4,
        0,
        0,
        0,
        0, // the corrupt block
    ];
    let mut engine = Engine::new(95, crate::firmware::CONTROL_XDOMAIN);
    engine.set_identity(
        uuid_a(),
        local_root(0x8086, "Intel Corp.", 0x1111, "host-a"),
    );
    let mut script = ScriptChannel {
        uuid_response,
        props_response,
        inbox: Vec::new(),
    };
    let domain = fixture_domain(95);
    for _ in 0..3 {
        narf_scheduler::block_on_spin(engine.service(&mut script, &domain));
    }
    let rejected = engine
        .peers
        .iter()
        .find(|p| p.route == 1)
        .map(|p| p.state == PeerState::Rejected && p.uuid == Some(script_uuid))
        == Some(true);
    drop(engine);
    forget_domain(95);
    if !rejected || peers().iter().any(|p| p.domain == 95) {
        return TestResult::Fail("peer with a corrupt property block was not rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/xdomain",
    xdomain_bad_property_block_rejected
);

// -----------------------------------------------------------------
// Service matching: a network directory with the wrong protocol id
// and a peer with only unknown services both stay unbound — the
// peer is Ready, no netdev, no login, no live link.
// -----------------------------------------------------------------

fn root_with_prtcid(prtcid: u32) -> PropDir {
    let mut root = local_root(0x8086, "Intel Corp.", 0x3333, "host-c");
    for entry in &mut root.entries {
        if let PropKind::Dir(child) = &mut entry.kind {
            for sub in &mut child.entries {
                if sub.key == prop_key("prtcid") {
                    sub.kind = PropKind::Value(prtcid);
                }
            }
        }
    }
    root
}

fn xdomain_service_matching() -> TestResult {
    // Wrong ThunderboltIP protocol id (2 instead of 1).
    let a = Side::new(
        96,
        uuid_a(),
        local_root(0x8086, "Intel Corp.", 0x1111, "host-a"),
    );
    let d = Side::new(97, uuid_b(), root_with_prtcid(2));
    drive(&a, &d, 6);
    let ready_but_unbound = match (a.peer_info(), d.peer_info()) {
        (Some(x), Some(y)) => {
            !x.login_connected
                && !y.login_connected
                && a.engine.borrow().peers.iter().all(|p| p.net.is_none())
        }
        _ => false,
    };
    drop(a);
    drop(d);
    forget_domain(96);
    forget_domain(97);
    if !ready_but_unbound {
        return TestResult::Fail("peer with prtcid 2 was bound as a network service");
    }
    if live_link_count() != 0 {
        return TestResult::Fail("service-matching fixture left a live link behind");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/xdomain", xdomain_service_matching);
