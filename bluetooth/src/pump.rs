//! HCI event/ACL pump — the driver task that composes the host stack.
//!
//! Until this module landed, the Bluetooth host stack (L2CAP, ATT /
//! GATT server, SMP, GAP) existed as fixture-tested libraries with no
//! production caller: after `controller::Controller::bring_up` (or a
//! driver's own async bring-up) nothing continuously drained
//! `HciTransport::recv_event` / `recv_acl`, so no in-kernel Bluetooth
//! use was possible at all. The pump is that missing task.
//!
//! ## Shape
//!
//! - One [`PumpCore`] per ready controller, registered by
//!   [`notify_controller_ready`] (called from
//!   `controller::register_ready_transport` and from
//!   `controller::bring_up_all`'s success path).
//! - [`pump_once`] performs one bounded, synchronous step: drain
//!   pending HCI events, dispatch them, drain pending ACL packets,
//!   route reassembled L2CAP frames, flush queued outbound ACL.
//!   It is deliberately synchronous and fixture-drivable — tests run
//!   it against a scripted fake controller with no task involved.
//! - The production driver task is a stackful kernel thread spawned
//!   by [`start_pump_task`] once spawning is enabled from the
//!   Stage::Late `bluetooth-pump` initcall. A stackful thread is
//!   required, not optional: `UsbHciTransport` bridges through
//!   `narf_scheduler::block_on`, which panics inside an executor poll.
//! - Event fan-out: every drained event is also encoded for the raw
//!   HCI socket layer (`hci_sock::drain_event` reads this queue once
//!   a pump is active for the controller, instead of racing the pump
//!   for the transport).
//!
//! ## Dispatch table (inbound)
//!
//! - LE / BR-EDR Connection Complete → connection table entry.
//! - Disconnection Complete → entry removed (L2CAP state dropped).
//! - LE Long Term Key Request → LTK Request Negative Reply. There is
//!   no bonding store yet, so no LTK can ever match; replying with a
//!   stored key we do not have would be worse than refusing.
//! - Number Of Completed Packets → ACL flow-control credits.
//! - ACL → per-connection `l2cap::Dispatcher` → CID routing:
//!   ATT → the per-controller `gatt_server::GattServer` (default GAP /
//!   GATT / Device Information / Battery services mounted);
//!   SMP → a per-connection `smp::Responder` driven by the production
//!   [`NarfSmpCrypto`]; LE signalling → Connection Parameter Update
//!   accepted, LE credit-based connections refused (no COC servers
//!   yet); BR/EDR signalling → Echo answered, Information answered,
//!   Connection Requests refused (no BR/EDR profile servers wired
//!   yet), Configure / Disconnection answered so peers do not wedge.
//!   Dynamic CIDs are dropped and counted — SDP / RFCOMM channel
//!   servers are follow-up work, as is initiating pairing
//!   (`smp::Initiator` needs an application policy trigger that does
//!   not exist yet).
//!
//! ## Lifecycle
//!
//! [`stop_pump`] asks the task to exit at its next iteration. It does
//! not unregister the controller: full detach composition (registry
//! removal, sysfs teardown, mgmt INDEX_REMOVED) is the detach work
//! tracked separately; the pump is the piece that must stop first so
//! the transport is quiescent when that lands.
//!
//! Spec: Bluetooth Core 5.3 Vol 3 Part A (L2CAP), Part F (ATT),
//! Part G (GATT), Part H (SMP); Vol 4 Part E (HCI).

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::att;
use crate::controller::ControllerInfo;
use crate::event::{
    DisconnectionComplete, EventCode, LeConnectionComplete, LeLongTermKeyRequest,
    NumberOfCompletedPackets,
};
use crate::gatt_server::GattServer;
use crate::hci::{AclData, Command, Event};
use crate::l2cap::{
    self, BFrame, CidClass, SignallingCode, CID_ATT, CID_LE_SIGNALLING, CID_SIGNALLING, CID_SMP,
};
use crate::opcode as op;
use crate::services;
use crate::smp::{self, PairingError, Responder};
use crate::transport::{HciTransport, TransportError};

// ── Production SMP crypto ───────────────────────────────────────────

/// Production [`smp::SmpCrypto`] backed by `narf-crypto`: P-256 ECDH
/// (RFC 5903 vectors in `crypto/src/p256`), AES-CMAC
/// (`narf_crypto::cmac_aes128`), and the hardware-seeded entropy
/// adapter (`narf_crypto::try_fill_random_bytes`, RDSEED/RNDR only —
/// no timing fallback).
///
/// Byte-order contract: the SMP state machine copies public-key
/// coordinates verbatim into the Pairing Public Key PDU, whose wire
/// format is little-endian (Vol 3 Part H §2.3.5.6). `narf-crypto`
/// works in FIPS big-endian, so this adapter reverses coordinates at
/// the boundary; the DHKey is likewise returned little-endian.
///
/// Failure discipline: entropy failure is retried a bounded number of
/// times and then yields zero bytes. A zero private scalar maps to
/// the point at infinity, whose encoding is all-zero; the peer's f4
/// confirm check then fails and pairing aborts — fail-closed, never a
/// fabricated key.
#[derive(Copy, Clone, Debug, Default)]
pub struct NarfSmpCrypto;

impl NarfSmpCrypto {
    fn fill_random(out: &mut [u8]) {
        for _ in 0..8 {
            if narf_crypto::try_fill_random_bytes(out).is_ok() {
                return;
            }
        }
        out.fill(0);
    }

    fn reverse32(input: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = input[31 - i];
        }
        out
    }
}

impl smp::SmpCrypto for NarfSmpCrypto {
    fn p256_keygen(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut raw = [0u8; 32];
        Self::fill_random(&mut raw);
        let scalar = narf_crypto::p256::Scalar::from_bytes_be_reduce(&raw);
        let priv_be = scalar.to_bytes_be();
        let point = narf_crypto::p256::point::scalar_mul_base(&scalar);
        match point.to_encoded() {
            Some(enc) => {
                let mut x_be = [0u8; 32];
                let mut y_be = [0u8; 32];
                x_be.copy_from_slice(&enc[0..32]);
                y_be.copy_from_slice(&enc[32..64]);
                (priv_be, Self::reverse32(&x_be), Self::reverse32(&y_be))
            }
            // Point at infinity (zero scalar after an entropy
            // failure): all-zero public key, pairing fails closed at
            // the peer's confirm check.
            None => (priv_be, [0u8; 32], [0u8; 32]),
        }
    }

    fn p256_dh(
        &self,
        private: &[u8; 32],
        peer_pub_x: &[u8; 32],
        peer_pub_y: &[u8; 32],
    ) -> [u8; 32] {
        let scalar = match narf_crypto::p256::Scalar::from_bytes_be(private) {
            Some(s) if !s.is_zero() => s,
            _ => return [0u8; 32],
        };
        let mut enc = [0u8; 64];
        enc[0..32].copy_from_slice(&Self::reverse32(peer_pub_x));
        enc[32..64].copy_from_slice(&Self::reverse32(peer_pub_y));
        let Some(peer) = narf_crypto::p256::AffinePoint::from_encoded(&enc) else {
            return [0u8; 32];
        };
        let shared = narf_crypto::p256::point::scalar_mul(&scalar, &peer);
        match shared.to_encoded() {
            Some(enc) => {
                let mut x_be = [0u8; 32];
                x_be.copy_from_slice(&enc[0..32]);
                Self::reverse32(&x_be)
            }
            None => [0u8; 32],
        }
    }

    fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16] {
        narf_crypto::cmac_aes128::cmac_aes128(key, data)
    }

    fn rand128(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        Self::fill_random(&mut out);
        out
    }
}

// ── Pump statistics ─────────────────────────────────────────────────

/// Cumulative pump counters for one controller.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PumpStats {
    pub events_seen: u64,
    pub acl_received: u64,
    pub acl_sent: u64,
    pub commands_sent: u64,
    pub frames_dropped_unknown_handle: u64,
    pub frames_dropped_unrouted_cid: u64,
    pub socket_events_dropped: u64,
    pub transport_errors: u64,
}

/// Work performed by one [`pump_once`] step.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PumpStep {
    pub events: u32,
    pub acl_received: u32,
    pub acl_sent: u32,
    pub commands_sent: u32,
}

impl PumpStep {
    pub fn is_idle(&self) -> bool {
        self.events == 0 && self.acl_received == 0 && self.acl_sent == 0 && self.commands_sent == 0
    }
}

// ── Per-connection state ────────────────────────────────────────────

/// One ACL connection tracked by the pump.
#[derive(Debug)]
struct Connection {
    handle: u16,
    le: bool,
    /// `[address_type, bd_addr(wire order, 6)]` of the peer.
    peer_addr: [u8; 7],
    dispatcher: l2cap::Dispatcher,
    smp: Option<Responder<NarfSmpCrypto>>,
    /// LTK from a completed pairing (in-memory only; no bond store).
    ltk: Option<[u8; 16]>,
    encrypted: bool,
}

impl Connection {
    fn new(handle: u16, le: bool, peer_addr: [u8; 7]) -> Self {
        Self {
            handle,
            le,
            peer_addr,
            dispatcher: l2cap::Dispatcher::new(),
            smp: None,
            ltk: None,
            encrypted: false,
        }
    }
}

// ── Pump core ───────────────────────────────────────────────────────

/// The dispatch state for one controller. Owned by the registry slot
/// but taken out for the duration of a [`pump_once`] step so no
/// `IrqSafeSpinLock` is ever held across transport I/O (the USB
/// transport bridges through `block_on`, which deadlocks with an
/// IRQ-safe lock held).
pub struct PumpCore {
    index: usize,
    transport: Arc<dyn HciTransport>,
    info: ControllerInfo,
    connections: Vec<Connection>,
    gatt: GattServer,
    /// Encoded outbound ACL packets awaiting flow-control credits.
    pending_acl: VecDeque<Vec<u8>>,
    /// Controller-wide ACL packets currently with the controller.
    acl_in_flight: u32,
    stats: PumpStats,
}

impl fmt::Debug for PumpCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PumpCore")
            .field("index", &self.index)
            .field("info", &self.info)
            .field("connections", &self.connections.len())
            .field("pending_acl", &self.pending_acl.len())
            .field("acl_in_flight", &self.acl_in_flight)
            .finish_non_exhaustive()
    }
}

impl PumpCore {
    pub fn new(index: usize, transport: Arc<dyn HciTransport>, info: ControllerInfo) -> Self {
        let mut gatt = GattServer::new();
        services::mount_gap_service(&mut gatt.db, "NARF", services::APPEARANCE_GENERIC_COMPUTER);
        services::mount_gatt_service(&mut gatt.db);
        services::mount_device_information_service(
            &mut gatt.db,
            &services::DeviceInformation {
                manufacturer: Some("NARF"),
                model: Some("narf-bluetooth"),
                firmware_revision: Some("1.0"),
                ..Default::default()
            },
        );
        services::mount_battery_service(&mut gatt.db, 100);
        Self {
            index,
            transport,
            info,
            connections: Vec::new(),
            gatt,
            pending_acl: VecDeque::new(),
            acl_in_flight: 0,
            stats: PumpStats::default(),
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn stats(&self) -> PumpStats {
        self.stats
    }

    fn acl_mtu(&self) -> u16 {
        if self.info.acl_data_mtu >= 27 {
            self.info.acl_data_mtu
        } else {
            // Vol 4 Part E §5.4.2: every controller accepts at least a
            // 27-byte ACL payload (BR/EDR DH1 / LE minimum). Used only
            // when bring-up left the MTU unset.
            27
        }
    }

    fn local_addr(&self) -> [u8; 7] {
        let mut out = [0u8; 7];
        out[0] = 0; // public address
        out[1..7].copy_from_slice(&self.info.bd_addr);
        out
    }

    fn connection_mut(&mut self, handle: u16) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| c.handle == handle)
    }

    fn send_command(&mut self, opcode: u16, params: &[u8]) -> Result<(), TransportError> {
        let cmd = Command::with_params(opcode, params);
        self.transport.send_command(&cmd)?;
        self.stats.commands_sent += 1;
        Ok(())
    }

    /// Queue one L2CAP B-frame for transmission on `handle`, wrapped
    /// into ACL packets sized to the controller's ACL MTU.
    fn queue_frame(&mut self, handle: u16, le: bool, frame: &BFrame) {
        for packet in l2cap::wrap_frame_into_acl(handle, frame, self.acl_mtu(), le) {
            self.pending_acl.push_back(packet.encode());
        }
    }

    /// Transmit queued ACL packets while flow-control credits last.
    /// Returns the number of packets sent.
    fn flush_acl(&mut self) -> u32 {
        let mut sent = 0;
        loop {
            if self.info.acl_total_num != 0
                && self.acl_in_flight >= u32::from(self.info.acl_total_num)
            {
                break;
            }
            let Some(packet) = self.pending_acl.pop_front() else {
                break;
            };
            match self.transport.send_acl(&packet) {
                Ok(()) => {
                    self.acl_in_flight += 1;
                    self.stats.acl_sent += 1;
                    sent += 1;
                }
                Err(_) => {
                    self.stats.transport_errors += 1;
                    self.pending_acl.push_front(packet);
                    break;
                }
            }
        }
        sent
    }
}

// ── Event dispatch ──────────────────────────────────────────────────

impl PumpCore {
    /// Handle one HCI event. Socket fan-out happens in `pump_once`;
    /// this is only the host-stack dispatch.
    fn dispatch_event(&mut self, event: &Event) {
        match event.code {
            code if code == EventCode::LeMeta as u8 => {
                if let Some(cc) = LeConnectionComplete::parse(event) {
                    if cc.status == 0 {
                        let mut peer = [0u8; 7];
                        peer[0] = cc.peer_address_type;
                        peer[1..7].copy_from_slice(&cc.peer_address);
                        self.connections.retain(|c| c.handle != cc.handle);
                        self.connections
                            .push(Connection::new(cc.handle, true, peer));
                    }
                    return;
                }
                if let Some(req) = LeLongTermKeyRequest::parse(event) {
                    // No bonding store: no LTK can match (rand, ediv),
                    // so refuse explicitly (Vol 4 Part E §7.8.25).
                    let _ = self.send_command(
                        op::HCI_LE_LTK_REQUEST_NEGATIVE_REPLY,
                        &req.handle.to_le_bytes(),
                    );
                }
            }
            code if code == EventCode::ConnectionComplete as u8 => {
                // §7.7.3: Status(1) Handle(2) BD_ADDR(6) Link_Type(1)
                // Encryption_Enabled(1).
                let p = &event.params;
                if p.len() >= 11 && p[0] == 0 {
                    let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0FFF;
                    let mut peer = [0u8; 7];
                    peer[0] = 0; // BR/EDR addresses are public.
                    peer[1..7].copy_from_slice(&p[3..9]);
                    self.connections.retain(|c| c.handle != handle);
                    self.connections.push(Connection::new(handle, false, peer));
                }
            }
            code if code == EventCode::DisconnectionComplete as u8 => {
                if let Some(dc) = DisconnectionComplete::parse(event) {
                    self.connections.retain(|c| c.handle != dc.handle);
                }
            }
            code if code == EventCode::NumberOfCompletedPackets as u8 => {
                if let Some(nocp) = NumberOfCompletedPackets::parse(event) {
                    for (_handle, count) in nocp.entries {
                        self.acl_in_flight = self.acl_in_flight.saturating_sub(u32::from(count));
                    }
                }
            }
            code if code == EventCode::EncryptionChange as u8 => {
                // §7.7.8: Status(1) Handle(2) Encryption_Enabled(1).
                let p = &event.params;
                if p.len() >= 4 && p[0] == 0 {
                    let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0FFF;
                    if let Some(conn) = self.connection_mut(handle) {
                        conn.encrypted = p[3] != 0;
                    }
                }
            }
            _ => {}
        }
    }
}

// ── ACL / L2CAP dispatch ────────────────────────────────────────────

impl PumpCore {
    fn route_acl(&mut self, acl: &AclData) {
        let Some(conn_idx) = self.connections.iter().position(|c| c.handle == acl.handle) else {
            self.stats.frames_dropped_unknown_handle += 1;
            return;
        };
        let frames = self.connections[conn_idx]
            .dispatcher
            .feed_acl(acl.pb_flag, &acl.data);
        for frame in frames {
            self.route_frame(conn_idx, &frame);
        }
    }

    fn route_frame(&mut self, conn_idx: usize, frame: &BFrame) {
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        match l2cap::Dispatcher::classify_cid(frame.cid) {
            CidClass::Att => {
                let Some(req) = att::Pdu::decode(&frame.payload) else {
                    return;
                };
                if req.expects_response() {
                    let rsp = self.gatt.handle_request(&req);
                    self.queue_frame(handle, le, &BFrame::new(CID_ATT, rsp.encode()));
                }
            }
            CidClass::Smp => {
                let Some(pdu) = smp::Pdu::decode(&frame.payload) else {
                    return;
                };
                self.route_smp(conn_idx, &pdu);
            }
            CidClass::LeSignalling => {
                let mut out = Vec::new();
                for cmd in l2cap::iter_signalling(&frame.payload) {
                    self.answer_le_signalling(&cmd, &mut out);
                }
                if !out.is_empty() {
                    self.queue_frame(handle, le, &BFrame::new(CID_LE_SIGNALLING, out));
                }
            }
            CidClass::BrEdrSignalling => {
                let mut out = Vec::new();
                for cmd in l2cap::iter_signalling(&frame.payload) {
                    self.answer_bredr_signalling(&cmd, &mut out);
                }
                if !out.is_empty() {
                    self.queue_frame(handle, le, &BFrame::new(CID_SIGNALLING, out));
                }
            }
            _ => {
                self.stats.frames_dropped_unrouted_cid += 1;
            }
        }
    }

    fn route_smp(&mut self, conn_idx: usize, pdu: &smp::Pdu) {
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        if self.connections[conn_idx].smp.is_none() {
            let peer = self.connections[conn_idx].peer_addr;
            let local = self.local_addr();
            self.connections[conn_idx].smp = Some(Responder::new(NarfSmpCrypto, peer, local));
        }
        let responder = self.connections[conn_idx].smp.as_mut().unwrap();
        match responder.feed(pdu) {
            Ok(out) => {
                if responder.state == smp::ResponderState::Done {
                    self.connections[conn_idx].ltk = Some(responder.ltk);
                }
                if let Some(out) = out {
                    self.queue_frame(handle, le, &BFrame::new(CID_SMP, out.encode()));
                }
            }
            Err(PairingError::PeerFailed(_)) => {
                self.connections[conn_idx].smp = None;
            }
            Err(err) => {
                // SMP failure reasons (Vol 3 Part H §3.5.5):
                // 0x04 Confirm Value Failed, 0x08 Unspecified.
                let reason = match err {
                    PairingError::BadConfirm => 0x04,
                    _ => 0x08,
                };
                self.connections[conn_idx].smp = None;
                let failed = smp::Pdu {
                    code: smp::SMP_PAIRING_FAILED,
                    payload: alloc::vec![reason],
                };
                self.queue_frame(handle, le, &BFrame::new(CID_SMP, failed.encode()));
            }
        }
    }

    /// LE signalling answers (Vol 3 Part A §4). Only Connection
    /// Parameter Update is accepted; LE credit-based channels are
    /// refused until a COC server registers.
    fn answer_le_signalling(&self, cmd: &l2cap::SignallingCommand, out: &mut Vec<u8>) {
        match SignallingCode::from_u8(cmd.code) {
            Some(SignallingCode::ConnectionParameterUpdateRequest) => {
                // §4.20 response: Result(2 LE). 0x0000 = accepted.
                l2cap::SignallingCommand {
                    code: SignallingCode::ConnectionParameterUpdateResponse as u8,
                    identifier: cmd.identifier,
                    data: 0x0000u16.to_le_bytes().to_vec(),
                }
                .encode(out);
            }
            Some(SignallingCode::LeCreditBasedConnectionRequest) => {
                // §4.22 response: Dest_CID(2) Source_CID(2) Result(2)
                // MTU(2) MPS(2) Initial_Credits(2). Result 0x0002 =
                // LE_PSM not supported (no COC server registered).
                let source_cid = if cmd.data.len() >= 4 {
                    u16::from_le_bytes([cmd.data[2], cmd.data[3]])
                } else {
                    0
                };
                let mut data = Vec::with_capacity(10);
                data.extend_from_slice(&0u16.to_le_bytes());
                data.extend_from_slice(&source_cid.to_le_bytes());
                data.extend_from_slice(&0x0002u16.to_le_bytes());
                data.extend_from_slice(&0u16.to_le_bytes());
                data.extend_from_slice(&0u16.to_le_bytes());
                data.extend_from_slice(&0u16.to_le_bytes());
                l2cap::SignallingCommand {
                    code: SignallingCode::LeCreditBasedConnectionResponse as u8,
                    identifier: cmd.identifier,
                    data,
                }
                .encode(out);
            }
            _ => {
                // §4.1 Command Reject, reason 0x0000 (not understood).
                l2cap::SignallingCommand {
                    code: SignallingCode::CommandReject as u8,
                    identifier: cmd.identifier,
                    data: 0x0000u16.to_le_bytes().to_vec(),
                }
                .encode(out);
            }
        }
    }

    /// BR/EDR signalling answers (Vol 3 Part A §4). No BR/EDR profile
    /// servers (SDP / RFCOMM channels) are wired yet, so Connection
    /// Requests are refused with PSM-not-supported instead of being
    /// left to time out; Echo and Information are answered from the
    /// fixed-channel set this pump actually serves.
    fn answer_bredr_signalling(&mut self, cmd: &l2cap::SignallingCommand, out: &mut Vec<u8>) {
        match SignallingCode::from_u8(cmd.code) {
            Some(SignallingCode::EchoRequest) => {
                l2cap::SignallingCommand {
                    code: SignallingCode::EchoResponse as u8,
                    identifier: cmd.identifier,
                    data: cmd.data.clone(),
                }
                .encode(out);
            }
            Some(SignallingCode::InformationRequest) => {
                let info_type = if cmd.data.len() >= 2 {
                    u16::from_le_bytes([cmd.data[0], cmd.data[1]])
                } else {
                    0
                };
                let mut data = Vec::new();
                data.extend_from_slice(&info_type.to_le_bytes());
                match info_type {
                    l2cap::INFO_TYPE_EXTENDED_FEATURES => {
                        data.extend_from_slice(&0x0000u16.to_le_bytes()); // success
                        data.extend_from_slice(&0u32.to_le_bytes()); // no features
                    }
                    l2cap::INFO_TYPE_FIXED_CHANNELS => {
                        data.extend_from_slice(&0x0000u16.to_le_bytes()); // success
                                                                          // Fixed channels served: 0x0001 signalling,
                                                                          // 0x0004 ATT, 0x0005 LE signalling, 0x0006 SMP.
                        let mask: u64 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6);
                        data.extend_from_slice(&mask.to_le_bytes());
                    }
                    _ => {
                        data.extend_from_slice(&0x0001u16.to_le_bytes()); // not supported
                    }
                }
                l2cap::SignallingCommand {
                    code: SignallingCode::InformationResponse as u8,
                    identifier: cmd.identifier,
                    data,
                }
                .encode(out);
            }
            Some(SignallingCode::ConnectionRequest) => {
                let source_cid = if cmd.data.len() >= 4 {
                    u16::from_le_bytes([cmd.data[2], cmd.data[3]])
                } else {
                    0
                };
                l2cap::build_connection_response(
                    cmd.identifier,
                    0,
                    source_cid,
                    l2cap::CONN_RESULT_REFUSED_PSM_NOT_SUPPORTED,
                    l2cap::CONN_STATUS_NO_INFORMATION,
                )
                .encode(out);
            }
            Some(SignallingCode::ConfigureRequest) => {
                // §4.5 response: Source_CID(2) Flags(2) Result(2)
                // options(0). Accept with no options.
                let dest_cid = if cmd.data.len() >= 2 {
                    u16::from_le_bytes([cmd.data[0], cmd.data[1]])
                } else {
                    0
                };
                let mut data = Vec::with_capacity(6);
                data.extend_from_slice(&dest_cid.to_le_bytes());
                data.extend_from_slice(&0u16.to_le_bytes());
                data.extend_from_slice(&0u16.to_le_bytes());
                l2cap::SignallingCommand {
                    code: SignallingCode::ConfigureResponse as u8,
                    identifier: cmd.identifier,
                    data,
                }
                .encode(out);
            }
            Some(SignallingCode::DisconnectionRequest) => {
                l2cap::SignallingCommand {
                    code: SignallingCode::DisconnectionResponse as u8,
                    identifier: cmd.identifier,
                    data: cmd.data.clone(),
                }
                .encode(out);
            }
            _ => {
                l2cap::SignallingCommand {
                    code: SignallingCode::CommandReject as u8,
                    identifier: cmd.identifier,
                    data: 0x0000u16.to_le_bytes().to_vec(),
                }
                .encode(out);
            }
        }
    }
}

// ── Registry + lifecycle ────────────────────────────────────────────

/// Max events / ACL packets drained per `pump_once` step, so one
/// chatty controller cannot starve the task's other controllers.
const MAX_PACKETS_PER_STEP: usize = 64;
/// Cap on queued raw-socket event frames per controller; the oldest
/// are dropped (counted) when a socket consumer falls behind.
const SOCKET_EVENT_QUEUE_CAP: usize = 128;
/// HCI packet-type indicator for Event packets on the raw socket
/// wire (mirrors `hci_sock`'s private constant of the same name).
const HCI_EVENT_PKT: u8 = 0x04;

#[derive(Debug)]
struct PumpSlot {
    index: usize,
    core: Option<PumpCore>,
    socket_events: VecDeque<Vec<u8>>,
    stats: PumpStats,
    stop: bool,
    task_running: bool,
    /// Set once a task is running or a step has run; tells
    /// `hci_sock::drain_event` the pump owns this controller's event
    /// stream (before that, sockets keep today's direct-transport
    /// behaviour and tests see no behaviour change).
    active: bool,
}

static PUMPS: IrqSafeSpinLock<Vec<PumpSlot>> = IrqSafeSpinLock::new(Vec::new());
static SPAWN_ENABLED: AtomicBool = AtomicBool::new(false);

fn encode_socket_event(event: &Event) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + event.params.len());
    out.push(HCI_EVENT_PKT);
    out.push(event.code);
    out.push(event.params.len() as u8);
    out.extend_from_slice(&event.params);
    out
}

/// Register a pump for controller `index` if one does not exist yet,
/// and start its driver task when spawning is enabled. Called from
/// the controller registry whenever a controller becomes ready.
/// Idempotent.
pub fn notify_controller_ready(index: usize) {
    {
        let mut pumps = PUMPS.lock();
        if pumps.iter().any(|s| s.index == index) {
            drop(pumps);
            start_task_if_enabled(index);
            return;
        }
        let Some(controller) = crate::controller::controllers().get(index).cloned() else {
            return;
        };
        pumps.push(PumpSlot {
            index,
            core: Some(PumpCore::new(
                index,
                controller.transport(),
                controller.info(),
            )),
            socket_events: VecDeque::new(),
            stats: PumpStats::default(),
            stop: false,
            task_running: false,
            active: false,
        });
    }
    start_task_if_enabled(index);
}

fn find_slot_mut(pumps: &mut [PumpSlot], index: usize) -> Option<&mut PumpSlot> {
    pumps.iter_mut().find(|s| s.index == index)
}

/// Enable pump task spawning (Stage::Late `bluetooth-pump` initcall)
/// and adopt every controller that is already ready.
pub fn enable_spawning() {
    SPAWN_ENABLED.store(true, Ordering::Release);
    for index in 0..crate::controller::controller_count() {
        notify_controller_ready(index);
    }
}

fn start_task_if_enabled(index: usize) {
    if !SPAWN_ENABLED.load(Ordering::Acquire) {
        return;
    }
    {
        let mut pumps = PUMPS.lock();
        let Some(slot) = find_slot_mut(&mut pumps, index) else {
            return;
        };
        if slot.task_running || slot.stop {
            return;
        }
        slot.task_running = true;
        slot.active = true;
    }
    narf_scheduler::spawn_stackful(async move {
        pump_task(index);
    });
}

fn stop_requested(index: usize) -> bool {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)
        .map(|s| s.stop)
        .unwrap_or(true)
}

/// The driver task: step the pump until [`stop_pump`] is requested.
///
/// Stackful (kernel thread) rather than an executor task because the
/// USB transport's `HciTransport` methods bridge through `block_on`.
fn pump_task(index: usize) {
    loop {
        if stop_requested(index) {
            break;
        }
        let step = pump_once(index);
        if stop_requested(index) {
            break;
        }
        if step.is_idle() {
            let _ = narf_scheduler::responsive_spin_until(
                || stop_requested(index),
                narf_time::Deadline::after_ms(2),
            );
        }
    }
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.task_running = false;
    }
}

/// Ask controller `index`'s pump task to stop at its next iteration.
/// The controller stays registered; this is the quiesce step a future
/// detach path performs before unregistering anything.
pub fn stop_pump(index: usize) {
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.stop = true;
    }
}

/// Whether a pump is actively draining controller `index`'s events.
pub fn is_attached(index: usize) -> bool {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)
        .map(|s| s.active)
        .unwrap_or(false)
}

/// Pop the next raw-socket event frame queued for controller `index`.
pub fn take_socket_event(index: usize) -> Option<Vec<u8>> {
    let mut pumps = PUMPS.lock();
    let slot = find_slot_mut(&mut pumps, index)?;
    slot.socket_events.pop_front()
}

/// Live connection count for controller `index`, if it has a pump.
pub fn connection_count(index: usize) -> Option<usize> {
    let pumps = PUMPS.lock();
    let slot = pumps.iter().find(|s| s.index == index)?;
    slot.core.as_ref().map(|c| c.connection_count())
}

/// Cumulative pump statistics for controller `index`.
pub fn stats(index: usize) -> Option<PumpStats> {
    let pumps = PUMPS.lock();
    let slot = pumps.iter().find(|s| s.index == index)?;
    Some(slot.stats)
}

// ── The step ────────────────────────────────────────────────────────

/// Run one bounded pump step for controller `index`: drain events
/// (fanning them out to the raw-socket queue), dispatch them, drain
/// ACL, route L2CAP frames, and flush outbound ACL subject to flow
/// control. Returns zeros when no pump exists for `index`.
pub fn pump_once(index: usize) -> PumpStep {
    let mut core = {
        let mut pumps = PUMPS.lock();
        let Some(slot) = find_slot_mut(&mut pumps, index) else {
            return PumpStep::default();
        };
        slot.active = true;
        match slot.core.take() {
            Some(core) => core,
            // A step is already running for this controller (only
            // possible if a second caller drives it concurrently).
            None => return PumpStep::default(),
        }
    };

    let commands_before = core.stats.commands_sent;
    let mut step = PumpStep::default();
    let mut socket_frames: Vec<Vec<u8>> = Vec::new();

    for _ in 0..MAX_PACKETS_PER_STEP {
        match core.transport.recv_event() {
            Ok(Some(event)) => {
                step.events += 1;
                core.stats.events_seen += 1;
                socket_frames.push(encode_socket_event(&event));
                core.dispatch_event(&event);
            }
            Ok(None) => break,
            Err(_) => {
                core.stats.transport_errors += 1;
                break;
            }
        }
    }
    step.acl_sent += core.flush_acl();

    for _ in 0..MAX_PACKETS_PER_STEP {
        match core.transport.recv_acl() {
            Ok(Some(bytes)) => {
                step.acl_received += 1;
                core.stats.acl_received += 1;
                if let Some(acl) = AclData::decode(&bytes) {
                    core.route_acl(&acl);
                }
            }
            Ok(None) => break,
            Err(_) => {
                core.stats.transport_errors += 1;
                break;
            }
        }
    }
    step.acl_sent += core.flush_acl();
    step.commands_sent = (core.stats.commands_sent - commands_before) as u32;

    let final_stats = core.stats;
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.core = Some(core);
        slot.stats = final_stats;
        for frame in socket_frames {
            if slot.socket_events.len() >= SOCKET_EVENT_QUEUE_CAP {
                slot.socket_events.pop_front();
                slot.stats.socket_events_dropped += 1;
            }
            slot.socket_events.push_back(frame);
        }
    }
    step
}

#[doc(hidden)]
pub fn __test_reset() {
    PUMPS.lock().clear();
    SPAWN_ENABLED.store(false, Ordering::Release);
}

// ── Fixtures: fake HCI controller conversations ─────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted fake HCI controller: the fixture half of #822. The
    /// test plays the controller — queuing Command Complete events
    /// for bring-up, connection events, and inbound ACL — and reads
    /// back every command / ACL packet the host stack emitted.
    #[derive(Debug)]
    struct ScriptedTransport {
        events: IrqSafeSpinLock<VecDeque<Event>>,
        acl_inbox: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        sent_commands: IrqSafeSpinLock<Vec<Command>>,
        sent_acl: IrqSafeSpinLock<Vec<Vec<u8>>>,
    }

    impl ScriptedTransport {
        fn new() -> Self {
            Self {
                events: IrqSafeSpinLock::new(VecDeque::new()),
                acl_inbox: IrqSafeSpinLock::new(VecDeque::new()),
                sent_commands: IrqSafeSpinLock::new(Vec::new()),
                sent_acl: IrqSafeSpinLock::new(Vec::new()),
            }
        }
    }

    impl ScriptedTransport {
        fn enqueue_event(&self, e: Event) {
            self.events.lock().push_back(e);
        }
        fn enqueue_acl(&self, bytes: Vec<u8>) {
            self.acl_inbox.lock().push_back(bytes);
        }
        fn sent_opcodes(&self) -> Vec<u16> {
            self.sent_commands.lock().iter().map(|c| c.opcode).collect()
        }
        fn sent_acl_frames(&self) -> Vec<(u16, BFrame)> {
            self.sent_acl
                .lock()
                .iter()
                .filter_map(|bytes| AclData::decode(bytes))
                .filter_map(|acl| BFrame::decode(&acl.data).map(|f| (acl.handle, f)))
                .collect()
        }
    }

    impl HciTransport for ScriptedTransport {
        fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
            self.sent_commands.lock().push(cmd.clone());
            Ok(())
        }
        fn recv_event(&self) -> Result<Option<Event>, TransportError> {
            Ok(self.events.lock().pop_front())
        }
        fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
            self.sent_acl.lock().push(data.to_vec());
            Ok(())
        }
        fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
            Ok(self.acl_inbox.lock().pop_front())
        }
        fn name(&self) -> &'static str {
            "fake-hci"
        }
    }

    /// Command Complete event for `opcode`; `ret` starts with the
    /// HCI status byte, as on the wire.
    fn cc(opcode: u16, ret: &[u8]) -> Event {
        let mut params = alloc::vec![1, (opcode & 0xFF) as u8, (opcode >> 8) as u8];
        params.extend_from_slice(ret);
        Event {
            code: EventCode::CommandComplete as u8,
            params,
        }
    }

    fn reset_all() {
        crate::transport::__test_reset();
        crate::controller::__test_reset_controllers();
        __test_reset();
    }

    fn script_successful_bringup(fake: &ScriptedTransport) {
        fake.enqueue_event(cc(op::HCI_RESET, &[0]));
        // Status, HCI v5.3 (0x0B), rev 0x1234, LMP v5.3, mfr 0x0002
        // (Intel), subver 0x5678.
        fake.enqueue_event(cc(
            op::HCI_READ_LOCAL_VERSION,
            &[0, 0x0B, 0x34, 0x12, 0x0B, 0x02, 0x00, 0x78, 0x56],
        ));
        fake.enqueue_event(cc(
            op::HCI_READ_BD_ADDR,
            &[0, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
        ));
        // Status, ACL MTU 1022, SCO MTU 64, ACL total 8, SCO total 4.
        fake.enqueue_event(cc(
            op::HCI_READ_BUFFER_SIZE,
            &[0, 0xFE, 0x03, 64, 0x08, 0x00, 0x04, 0x00],
        ));
        fake.enqueue_event(cc(op::HCI_SET_EVENT_MASK, &[0]));
    }

    fn le_connection_complete(handle: u16, peer: [u8; 6]) -> Event {
        let mut params = alloc::vec![0x01, 0x00];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(0x01); // role: Peripheral (we accepted)
        params.push(0x00); // peer address type: public
        params.extend_from_slice(&peer);
        params.extend_from_slice(&0x0028u16.to_le_bytes()); // interval 50 ms
        params.extend_from_slice(&0u16.to_le_bytes()); // latency
        params.extend_from_slice(&0x01F4u16.to_le_bytes()); // timeout 5 s
        params.push(0x00); // central clock accuracy
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    fn acl_packet(handle: u16, frame: &BFrame) -> Vec<u8> {
        AclData {
            handle,
            pb_flag: l2cap::PB_COMPLETE_LE,
            bc_flag: 0,
            data: frame.encode(),
        }
        .encode()
    }

    /// The #822 conversation at the HCI seam: bring-up command order,
    /// then a connection whose ATT and SMP traffic the pump answers,
    /// with the raw-socket fan-out intact, then disconnect.
    fn smoke_pump_fake_controller_conversation() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport);
        script_successful_bringup(&fake);

        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        if outcomes.len() != 1 || outcomes[0].result.is_err() {
            reset_all();
            return TestResult::Fail("bring-up against fake controller failed");
        }
        // Exact mandatory command order (Vol 4 Part E §3).
        let expected = [
            op::HCI_RESET,
            op::HCI_READ_LOCAL_VERSION,
            op::HCI_READ_BD_ADDR,
            op::HCI_READ_BUFFER_SIZE,
            op::HCI_SET_EVENT_MASK,
        ];
        if fake.sent_opcodes() != expected {
            reset_all();
            return TestResult::Fail("bring-up command order mismatch");
        }

        // Peer connects (LE), then speaks ATT and SMP.
        let handle = 0x0040;
        fake.enqueue_event(le_connection_complete(
            handle,
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ));
        // ATT Exchange MTU Request, client MTU 512.
        let mtu_req = att::Pdu {
            opcode: att::ATT_EXCHANGE_MTU_REQ,
            params: 512u16.to_le_bytes().to_vec(),
        };
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, mtu_req.encode())));
        // SMP Pairing Request (LE SC, bonding, NoInputNoOutput).
        let pairing_req = smp::PairingFeatureExchange {
            io_capability: smp::IoCapability::NoInputNoOutput as u8,
            oob_data_flag: 0,
            auth_req: smp::AUTH_BONDING | smp::AUTH_SC,
            max_encryption_key_size: 16,
            initiator_key_distribution: 0,
            responder_key_distribution: 0,
        }
        .encode(smp::SMP_PAIRING_REQUEST);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_SMP, pairing_req.encode()),
        ));

        let step = pump_once(0);
        if step.events != 1 || step.acl_received != 2 || step.acl_sent != 2 {
            reset_all();
            return TestResult::Fail("pump step counts mismatch");
        }
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("pump did not track the LE connection");
        }
        // Raw-socket fan-out carries the connection event verbatim.
        match crate::hci_sock::drain_event(0) {
            Some(pkt) if pkt.len() > 3 && pkt[0] == HCI_EVENT_PKT && pkt[1] == 0x3E => {}
            _ => {
                reset_all();
                return TestResult::Fail("socket fan-out lost the connection event");
            }
        }
        // Host -> controller bytes: ATT MTU response then SMP Pairing
        // Response, both on the connection's handle.
        let frames = fake.sent_acl_frames();
        let ok = frames.len() == 2
            && frames[0].0 == handle
            && frames[0].1.cid == CID_ATT
            && frames[0].1.payload.first() == Some(&att::ATT_EXCHANGE_MTU_RSP)
            && frames[1].0 == handle
            && frames[1].1.cid == CID_SMP
            && frames[1].1.payload.first() == Some(&smp::SMP_PAIRING_RESPONSE);
        if !ok {
            reset_all();
            return TestResult::Fail("pump responses missing or misrouted");
        }

        // Disconnect tears the connection state down.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x40, 0x00, 0x13],
        });
        let _ = pump_once(0);
        let gone = connection_count(0) == Some(0);
        reset_all();
        if !gone {
            return TestResult::Fail("connection state survived disconnect");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_fake_controller_conversation);

    /// Init failure: the controller NAKs HCI_Reset (status 0x0C,
    /// Command Disallowed). Bring-up must fail closed, no controller
    /// is registered, and no pump ever attaches.
    fn smoke_pump_reset_nak_fails_closed() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport);
        fake.enqueue_event(cc(op::HCI_RESET, &[0x0C]));

        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        let failed = outcomes.len() == 1
            && matches!(
                outcomes[0].result,
                Err(crate::controller::BringupError::BadStatus { status: 0x0C, .. })
            );
        let no_controller = crate::controller::controller_count() == 0;
        let no_pump = !is_attached(0) && pump_once(0).is_idle();
        reset_all();
        if !failed || !no_controller || !no_pump {
            return TestResult::Fail("reset NAK did not fail closed");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_reset_nak_fails_closed);
}
