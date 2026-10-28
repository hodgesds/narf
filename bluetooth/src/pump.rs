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
            if Self::fill_once(out).is_ok() {
                return;
            }
        }
        out.fill(0);
    }

    fn fill_once(out: &mut [u8]) -> Result<(), narf_crypto::CryptoError> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(result) = test_entropy::fill(out) {
            return result;
        }
        narf_crypto::try_fill_random_bytes(out)
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

/// Test-only entropy seam for [`NarfSmpCrypto`], compiled only for
/// test / kernel-test builds (same pattern as [`__test_reset`]).
///
/// The production SMP fixtures need two entropy regimes the
/// hardware source cannot be asked for on demand: a deterministic
/// nonzero stream (so a fixture exchange runs the real keygen /
/// ECDH path rather than the degenerate zero-key one, whatever the
/// host CPU advertises) and a hard failure (to pin the fail-closed
/// zero-fill in `fill_random`). Installing a mode replaces
/// `narf_crypto::try_fill_random_bytes` for this adapter only;
/// clearing restores the hardware source. Fixtures must clear what
/// they install — `__test_reset` also clears, so a leaked install
/// cannot poison a later fixture that resets first.
#[cfg(any(test, feature = "kernel-test"))]
pub mod test_entropy {
    use narf_lib::sync::IrqSafeSpinLock;

    #[derive(Copy, Clone, Debug)]
    enum Mode {
        /// Every fill fails, as a dead hardware source does.
        Fail,
        /// Deterministic xorshift64* stream (state must be nonzero).
        Stream(u64),
    }

    static STATE: IrqSafeSpinLock<Option<Mode>> = IrqSafeSpinLock::new(None);

    /// Make every subsequent fill fail with `EntropyUnavailable`.
    pub fn install_fail() {
        *STATE.lock() = Some(Mode::Fail);
    }

    /// Make subsequent fills serve a deterministic nonzero stream.
    pub fn install_stream(seed: u64) {
        *STATE.lock() = Some(Mode::Stream(seed | 1));
    }

    /// Restore the hardware entropy source.
    pub fn clear() {
        *STATE.lock() = None;
    }

    /// `Some` when a test mode is installed: the fill result to use
    /// in place of the hardware source.
    pub(super) fn fill(out: &mut [u8]) -> Option<Result<(), narf_crypto::CryptoError>> {
        let mut state = STATE.lock();
        match &mut *state {
            None => None,
            Some(Mode::Fail) => Some(Err(narf_crypto::CryptoError::EntropyUnavailable)),
            Some(Mode::Stream(s)) => {
                for b in out.iter_mut() {
                    *s ^= *s >> 12;
                    *s ^= *s << 25;
                    *s ^= *s >> 27;
                    *b = (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
                }
                Some(Ok(()))
            }
        }
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
            Ok(outs) => {
                if responder.state == smp::ResponderState::Done {
                    self.connections[conn_idx].ltk = Some(responder.ltk);
                }
                for out in outs {
                    self.queue_frame(handle, le, &BFrame::new(CID_SMP, out.encode()));
                }
            }
            Err(PairingError::PeerFailed(_)) => {
                self.connections[conn_idx].smp = None;
            }
            Err(err) => {
                // SMP failure reasons (Vol 3 Part H §3.5.5):
                // 0x04 Confirm Value Failed, 0x0B DHKey Check
                // Failed, 0x08 Unspecified otherwise.
                let reason = match err {
                    PairingError::BadConfirm => smp::SMP_FAILED_CONFIRM_VALUE,
                    PairingError::BadDhKeyCheck => smp::SMP_FAILED_DHKEY_CHECK_FAILED,
                    _ => smp::SMP_FAILED_UNSPECIFIED,
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
        // Merge this step's fan-out drops into the cumulative total
        // before publishing the slot stats. `final_stats` comes from
        // the core, which never observes fan-out drops (the core's
        // own `socket_events_dropped` is always 0), so assigning it
        // after counting — or without carrying the slot's running
        // total over — would reset the counter on every step.
        let mut merged = final_stats;
        merged.socket_events_dropped = slot.stats.socket_events_dropped;
        for frame in socket_frames {
            if slot.socket_events.len() >= SOCKET_EVENT_QUEUE_CAP {
                slot.socket_events.pop_front();
                merged.socket_events_dropped += 1;
            }
            slot.socket_events.push_back(frame);
        }
        slot.stats = merged;
    }
    step
}

#[doc(hidden)]
pub fn __test_reset() {
    PUMPS.lock().clear();
    SPAWN_ENABLED.store(false, Ordering::Release);
    #[cfg(any(test, feature = "kernel-test"))]
    test_entropy::clear();
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

    // ── Independent peer model for the production SMP crypto ─────
    //
    // The fixtures below drive the PRODUCTION construction
    // `Responder<NarfSmpCrypto>` through complete LE Secure
    // Connections exchanges and assert the cryptographic results
    // byte-for-byte. The expected values are computed by this peer
    // model, which re-implements — from the public specifications
    // only — everything a real peer performs: P-256 field/curve
    // arithmetic (FIPS 186-4 / SEC 2), AES-128 (FIPS 197), AES-CMAC
    // (RFC 4493), and the SMP f4 / f5 / f6 / g2 derivations (Core
    // 5.3 Vol 3 Part H §2.2), all in SMP wire (little-endian) order.
    //
    // INDEPENDENCE: the model shares no code with narf-crypto, with
    // the `NarfSmpCrypto` adapter, or with the SMP state machine —
    // nothing is fed back. If the adapter's LE↔BE reversal (or its
    // CMAC passthrough) is wrong, the model's DHKey / LTK / g2
    // values disagree with the responder's and the assertions fail;
    // the error cannot cancel out. The model anchors itself with
    // self-checks against universally published constants (the
    // P-256 generator and group order, the FIPS-197 AES vector, the
    // RFC 4493 CMAC vectors) and reports those failures with a
    // distinct message, so a model bug cannot masquerade as a
    // production failure.
    //
    // NOTE: the Just-Works flow runs the full §2.3.5.6 sequence —
    // Pairing Confirm values (f4, §2.2.6) are committed in stage 1
    // and verified when the nonces are revealed, and the DHKey
    // Check values (f6, §2.2.8) are computed from the f5 MacKey
    // and verified in stage 2 before the exchange completes. A
    // mismatch aborts with BadConfirm / BadDhKeyCheck (Pairing
    // Failed 0x04 / 0x0B on the wire — see route_smp). The
    // byte-exact assertions therefore cover the ECDH DHKey, the
    // f5 MacKey + LTK, the responder's confirm Cb, its DHKey
    // check Eb, and the g2 numeric-comparison value; the f4/f5/f6
    // helpers are additionally pinned against the published
    // Appendix D sample data (smoke_pump_smp_spec_appendix_vectors),
    // and the tampered-value fixtures prove the verifications
    // actually reject.

    /// Field element mod the P-256 prime, little-endian limbs.
    type Fe = [u64; 4];

    const FE_P: Fe = [
        0xFFFF_FFFF_FFFF_FFFF,
        0x0000_0000_FFFF_FFFF,
        0x0000_0000_0000_0000,
        0xFFFF_FFFF_0000_0001,
    ];
    const FE_P_MINUS_2: Fe = [
        0xFFFF_FFFF_FFFF_FFFD,
        0x0000_0000_FFFF_FFFF,
        0x0000_0000_0000_0000,
        0xFFFF_FFFF_0000_0001,
    ];
    const FE_B: Fe = [
        0x3BCE_3C3E_27D2_604B,
        0x651D_06B0_CC53_B0F6,
        0xB3EB_BD55_7698_86BC,
        0x5AC6_35D8_AA3A_93E7,
    ];
    const ORDER_N: Fe = [
        0xF3B9_CAC2_FC63_2551,
        0xBCE6_FAAD_A717_9E84,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
    ];
    const GEN_X: Fe = [
        0xF4A1_3945_D898_C296,
        0x7703_7D81_2DEB_33A0,
        0xF8BC_E6E5_63A4_40F2,
        0x6B17_D1F2_E12C_4247,
    ];
    const GEN_Y: Fe = [
        0xCBB6_4068_37BF_51F5,
        0x2BCE_3357_6B31_5ECE,
        0x8EE7_EB4A_7C0F_9E16,
        0x4FE3_42E2_FE1A_7F9B,
    ];

    fn fe_adc(a: &Fe, b: &Fe) -> (Fe, u64) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
            let t = u128::from(*x) + u128::from(*y) + carry;
            *o = t as u64;
            carry = t >> 64;
        }
        (out, carry as u64)
    }

    fn fe_sbb(a: &Fe, b: &Fe) -> (Fe, u64) {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
            let (d1, b1) = x.overflowing_sub(*y);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *o = d2;
            borrow = u64::from(b1 || b2);
        }
        (out, borrow)
    }

    fn fe_add(a: &Fe, b: &Fe) -> Fe {
        let (s, carry) = fe_adc(a, b);
        let (d, borrow) = fe_sbb(&s, &FE_P);
        // a + b < 2p always; subtract p exactly when the sum
        // reached it (borrow == 0) or overflowed 256 bits (carry).
        if carry == 1 || borrow == 0 {
            d
        } else {
            s
        }
    }

    fn fe_sub(a: &Fe, b: &Fe) -> Fe {
        let (d, borrow) = fe_sbb(a, b);
        if borrow == 1 {
            fe_adc(&d, &FE_P).0
        } else {
            d
        }
    }

    fn fe_is_zero(a: &Fe) -> bool {
        a.iter().all(|x| *x == 0)
    }

    /// Bit-serial double-and-add multiply: slow, and correct by
    /// construction — the right trade for a fixture model.
    fn fe_mul(a: &Fe, b: &Fe) -> Fe {
        let mut r: Fe = [0; 4];
        for i in (0..256).rev() {
            r = fe_add(&r, &r);
            if (b[i >> 6] >> (i & 63)) & 1 == 1 {
                r = fe_add(&r, a);
            }
        }
        r
    }

    /// Fermat inversion: a^(p-2) mod p.
    fn fe_inv(a: &Fe) -> Fe {
        let mut r: Fe = [1, 0, 0, 0];
        for i in (0..256).rev() {
            r = fe_mul(&r, &r);
            if (FE_P_MINUS_2[i >> 6] >> (i & 63)) & 1 == 1 {
                r = fe_mul(&r, a);
            }
        }
        r
    }

    fn fe_from_be(bytes: &[u8; 32]) -> Fe {
        let mut out = [0u64; 4];
        for (i, limb) in out.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&bytes[8 * (3 - i)..8 * (3 - i) + 8]);
            *limb = u64::from_be_bytes(w);
        }
        out
    }

    fn fe_to_be(a: &Fe) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in a.iter().enumerate() {
            out[8 * (3 - i)..8 * (3 - i) + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// SMP wire order is little-endian: reverse the FIPS form.
    fn fe_from_wire(wire: &[u8; 32]) -> Fe {
        let mut be = *wire;
        be.reverse();
        fe_from_be(&be)
    }

    fn fe_to_wire(a: &Fe) -> [u8; 32] {
        let mut b = fe_to_be(a);
        b.reverse();
        b
    }

    /// Jacobian point; the point at infinity is any with z == 0.
    #[derive(Copy, Clone, Debug)]
    struct Jac {
        x: Fe,
        y: Fe,
        z: Fe,
    }

    const JAC_INF: Jac = Jac {
        x: [0; 4],
        y: [0; 4],
        z: [0; 4],
    };

    /// Doubling for a = -3 (the "dbl-2001-b" shape).
    fn jac_double(p: &Jac) -> Jac {
        let delta = fe_mul(&p.z, &p.z);
        let gamma = fe_mul(&p.y, &p.y);
        let beta = fe_mul(&p.x, &gamma);
        let t = fe_mul(&fe_sub(&p.x, &delta), &fe_add(&p.x, &delta));
        let alpha = fe_add(&fe_add(&t, &t), &t);
        let beta2 = fe_add(&beta, &beta);
        let beta4 = fe_add(&beta2, &beta2);
        let beta8 = fe_add(&beta4, &beta4);
        let x3 = fe_sub(&fe_mul(&alpha, &alpha), &beta8);
        let yz = fe_add(&p.y, &p.z);
        let z3 = fe_sub(&fe_sub(&fe_mul(&yz, &yz), &gamma), &delta);
        let gamma2 = fe_mul(&gamma, &gamma);
        let g2x = fe_add(&gamma2, &gamma2);
        let g4x = fe_add(&g2x, &g2x);
        let g8x = fe_add(&g4x, &g4x);
        let y3 = fe_sub(&fe_mul(&alpha, &fe_sub(&beta4, &x3)), &g8x);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// General addition ("add-2007-bl" shape).
    fn jac_add(p: &Jac, q: &Jac) -> Jac {
        if fe_is_zero(&p.z) {
            return *q;
        }
        if fe_is_zero(&q.z) {
            return *p;
        }
        let z1z1 = fe_mul(&p.z, &p.z);
        let z2z2 = fe_mul(&q.z, &q.z);
        let u1 = fe_mul(&p.x, &z2z2);
        let u2 = fe_mul(&q.x, &z1z1);
        let s1 = fe_mul(&fe_mul(&p.y, &q.z), &z2z2);
        let s2 = fe_mul(&fe_mul(&q.y, &p.z), &z1z1);
        if u1 == u2 {
            if s1 != s2 {
                return JAC_INF;
            }
            return jac_double(p);
        }
        let h = fe_sub(&u2, &u1);
        let hh = fe_add(&h, &h);
        let i = fe_mul(&hh, &hh);
        let j = fe_mul(&h, &i);
        let r0 = fe_sub(&s2, &s1);
        let r = fe_add(&r0, &r0);
        let v = fe_mul(&u1, &i);
        let x3 = fe_sub(&fe_sub(&fe_mul(&r, &r), &j), &fe_add(&v, &v));
        let s1j = fe_mul(&s1, &j);
        let y3 = fe_sub(&fe_mul(&r, &fe_sub(&v, &x3)), &fe_add(&s1j, &s1j));
        let zz = fe_add(&p.z, &q.z);
        let z3 = fe_mul(&fe_sub(&fe_sub(&fe_mul(&zz, &zz), &z1z1), &z2z2), &h);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn jac_to_affine(p: &Jac) -> Option<(Fe, Fe)> {
        if fe_is_zero(&p.z) {
            return None;
        }
        let zinv = fe_inv(&p.z);
        let zinv2 = fe_mul(&zinv, &zinv);
        let zinv3 = fe_mul(&zinv2, &zinv);
        Some((fe_mul(&p.x, &zinv2), fe_mul(&p.y, &zinv3)))
    }

    fn jac_scalar_mul(k: &Fe, px: &Fe, py: &Fe) -> Jac {
        let base = Jac {
            x: *px,
            y: *py,
            z: [1, 0, 0, 0],
        };
        let mut top = 256usize;
        while top > 0 && (k[(top - 1) >> 6] >> ((top - 1) & 63)) & 1 == 0 {
            top -= 1;
        }
        let mut r = JAC_INF;
        for i in (0..top).rev() {
            r = jac_double(&r);
            if (k[i >> 6] >> (i & 63)) & 1 == 1 {
                r = jac_add(&r, &base);
            }
        }
        r
    }

    fn peer_on_curve(x: &Fe, y: &Fe) -> bool {
        let lhs = fe_mul(y, y);
        let x2 = fe_mul(x, x);
        let x3 = fe_mul(&x2, x);
        let three_x = fe_add(&fe_add(x, x), x);
        let rhs = fe_add(&fe_sub(&x3, &three_x), &FE_B);
        lhs == rhs
    }

    fn peer_public(priv_scalar: &Fe) -> (Fe, Fe) {
        jac_to_affine(&jac_scalar_mul(priv_scalar, &GEN_X, &GEN_Y))
            .expect("a nonzero scalar yields a point")
    }

    /// The peer's DHKey, in SMP wire order, from its own scalar and
    /// the responder's wire public key.
    fn peer_dhkey_wire(priv_scalar: &Fe, pub_wire_x: &[u8; 32], pub_wire_y: &[u8; 32]) -> [u8; 32] {
        let x = fe_from_wire(pub_wire_x);
        let y = fe_from_wire(pub_wire_y);
        let shared = jac_scalar_mul(priv_scalar, &x, &y);
        let (sx, _) = jac_to_affine(&shared).expect("ECDH yields a point");
        fe_to_wire(&sx)
    }

    // ── Fixture AES-128 (FIPS 197) ───────────────────────────────

    fn gf_mul8(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    /// The S-box is generated, not tabulated: affine transform of
    /// the GF(2^8) inverse, so no 256-entry table can be mistyped.
    fn build_sbox() -> [u8; 256] {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            let x = i as u8;
            let inv = if x == 0 {
                0
            } else {
                let mut r = 1u8;
                let mut base = x;
                let mut e = 254u16;
                while e > 0 {
                    if e & 1 == 1 {
                        r = gf_mul8(r, base);
                    }
                    base = gf_mul8(base, base);
                    e >>= 1;
                }
                r
            };
            *v = inv
                ^ inv.rotate_left(1)
                ^ inv.rotate_left(2)
                ^ inv.rotate_left(3)
                ^ inv.rotate_left(4)
                ^ 0x63;
        }
        s
    }

    fn aes_sub_bytes(sbox: &[u8; 256], state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = sbox[usize::from(*b)];
        }
    }

    fn aes_shift_rows(state: &mut [u8; 16]) {
        let old = *state;
        for r in 0..4 {
            for c in 0..4 {
                state[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
            }
        }
    }

    fn aes_mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let a0 = state[4 * c];
            let a1 = state[4 * c + 1];
            let a2 = state[4 * c + 2];
            let a3 = state[4 * c + 3];
            state[4 * c] = gf_mul8(a0, 2) ^ gf_mul8(a1, 3) ^ a2 ^ a3;
            state[4 * c + 1] = a0 ^ gf_mul8(a1, 2) ^ gf_mul8(a2, 3) ^ a3;
            state[4 * c + 2] = a0 ^ a1 ^ gf_mul8(a2, 2) ^ gf_mul8(a3, 3);
            state[4 * c + 3] = gf_mul8(a0, 3) ^ a1 ^ a2 ^ gf_mul8(a3, 2);
        }
    }

    fn aes128_encrypt(sbox: &[u8; 256], key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
        // Key expansion (FIPS 197 §5.2), 11 round keys.
        let mut w = [0u8; 176];
        w[..16].copy_from_slice(key);
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = [
                w[4 * (i - 1)],
                w[4 * (i - 1) + 1],
                w[4 * (i - 1) + 2],
                w[4 * (i - 1) + 3],
            ];
            if i % 4 == 0 {
                t = [
                    sbox[usize::from(t[1])] ^ rcon,
                    sbox[usize::from(t[2])],
                    sbox[usize::from(t[3])],
                    sbox[usize::from(t[0])],
                ];
                rcon = gf_mul8(rcon, 2);
            }
            for j in 0..4 {
                w[4 * i + j] = w[4 * (i - 4) + j] ^ t[j];
            }
        }
        let mut state = *input;
        for i in 0..16 {
            state[i] ^= w[i];
        }
        for round in 1..10 {
            aes_sub_bytes(sbox, &mut state);
            aes_shift_rows(&mut state);
            aes_mix_columns(&mut state);
            for i in 0..16 {
                state[i] ^= w[16 * round + i];
            }
        }
        aes_sub_bytes(sbox, &mut state);
        aes_shift_rows(&mut state);
        for i in 0..16 {
            state[i] ^= w[160 + i];
        }
        state
    }

    // ── Fixture AES-CMAC (RFC 4493) ──────────────────────────────

    fn cmac_dbl(b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut carry = 0u8;
        for i in (0..16).rev() {
            let c = b[i] >> 7;
            out[i] = (b[i] << 1) | carry;
            carry = c;
        }
        if b[0] >> 7 == 1 {
            out[15] ^= 0x87;
        }
        out
    }

    fn peer_cmac(sbox: &[u8; 256], key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
        let l = aes128_encrypt(sbox, key, &[0u8; 16]);
        let k1 = cmac_dbl(&l);
        let k2 = cmac_dbl(&k1);
        let block_count = if msg.is_empty() {
            1
        } else {
            msg.len().div_ceil(16)
        };
        let complete = !msg.is_empty() && msg.len() % 16 == 0;
        let mut last = [0u8; 16];
        if complete {
            last.copy_from_slice(&msg[16 * (block_count - 1)..16 * block_count]);
            for (lb, kb) in last.iter_mut().zip(k1.iter()) {
                *lb ^= kb;
            }
        } else {
            let rem: &[u8] = if msg.is_empty() {
                &[]
            } else {
                &msg[16 * (block_count - 1)..]
            };
            last[..rem.len()].copy_from_slice(rem);
            last[rem.len()] = 0x80;
            for (lb, kb) in last.iter_mut().zip(k2.iter()) {
                *lb ^= kb;
            }
        }
        let mut x = [0u8; 16];
        for n in 0..block_count - 1 {
            for (xb, mb) in x.iter_mut().zip(msg[16 * n..16 * n + 16].iter()) {
                *xb ^= mb;
            }
            x = aes128_encrypt(sbox, key, &x);
        }
        for (xb, lb) in x.iter_mut().zip(last.iter()) {
            *xb ^= lb;
        }
        aes128_encrypt(sbox, key, &x)
    }

    /// f4 (Core 5.3 Vol 3 Part H §2.2.6): AES-CMAC keyed on the
    /// nonce `x` over `u ‖ v ‖ z`, computed with the fixture
    /// CMAC. The caller supplies u/v in the table 2.1 orientation
    /// for the side being modelled (each side's own key first).
    fn peer_f4(sbox: &[u8; 256], u: &[u8; 32], v: &[u8; 32], x: &[u8; 16], z: u8) -> [u8; 16] {
        let mut msg = [0u8; 65];
        msg[0..32].copy_from_slice(u);
        msg[32..64].copy_from_slice(v);
        msg[64] = z;
        peer_cmac(sbox, x, &msg)
    }

    /// f5 (Core 5.3 Vol 3 Part H §2.2.7) at one counter value:
    /// counter 0 yields the MacKey, counter 1 the LTK. Keyed on
    /// the DHKey in SMP wire order, exactly as the machine
    /// derives it — but computed with the fixture CMAC.
    fn peer_f5_half(
        sbox: &[u8; 256],
        dhkey_wire: &[u8; 32],
        counter: u8,
        na: &[u8; 16],
        nb: &[u8; 16],
        a1: &[u8; 7],
        a2: &[u8; 7],
    ) -> [u8; 16] {
        const SALT: [u8; 16] = [
            0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60,
            0x83, 0xBE,
        ];
        let t = peer_cmac(sbox, &SALT, dhkey_wire);
        let mut buf = [0u8; 53];
        buf[0] = counter;
        buf[1..5].copy_from_slice(b"btle");
        buf[5..21].copy_from_slice(na);
        buf[21..37].copy_from_slice(nb);
        buf[37..44].copy_from_slice(a1);
        buf[44..51].copy_from_slice(a2);
        buf[51] = 0x01;
        buf[52] = 0x00;
        peer_cmac(sbox, &t, &buf)
    }

    /// f5 MacKey half (counter 0).
    fn peer_f5_mac_key(
        sbox: &[u8; 256],
        dhkey_wire: &[u8; 32],
        na: &[u8; 16],
        nb: &[u8; 16],
        a1: &[u8; 7],
        a2: &[u8; 7],
    ) -> [u8; 16] {
        peer_f5_half(sbox, dhkey_wire, 0, na, nb, a1, a2)
    }

    /// f5 LTK half (counter 1).
    fn peer_f5_ltk(
        sbox: &[u8; 256],
        dhkey_wire: &[u8; 32],
        na: &[u8; 16],
        nb: &[u8; 16],
        a1: &[u8; 7],
        a2: &[u8; 7],
    ) -> [u8; 16] {
        peer_f5_half(sbox, dhkey_wire, 1, na, nb, a1, a2)
    }

    /// f6 (Core 5.3 Vol 3 Part H §2.2.8): AES-CMAC keyed on the
    /// MacKey over `n1 ‖ n2 ‖ r ‖ iocap ‖ a1 ‖ a2`, computed with
    /// the fixture CMAC. The caller supplies the table 2.2
    /// orientation for the side being modelled — the responder's
    /// check swaps both the nonce order and the address order.
    fn peer_f6(
        sbox: &[u8; 256],
        mac_key: &[u8; 16],
        n1: &[u8; 16],
        n2: &[u8; 16],
        r: &[u8; 16],
        iocap: &[u8; 3],
        a1: &[u8; 7],
        a2: &[u8; 7],
    ) -> [u8; 16] {
        let mut msg = [0u8; 65];
        msg[0..16].copy_from_slice(n1);
        msg[16..32].copy_from_slice(n2);
        msg[32..48].copy_from_slice(r);
        msg[48..51].copy_from_slice(iocap);
        msg[51..58].copy_from_slice(a1);
        msg[58..65].copy_from_slice(a2);
        peer_cmac(sbox, mac_key, &msg)
    }

    /// g2 (Core 5.3 Vol 3 Part H §2.2.9), mirroring the formula the
    /// state machine's `numeric_comparison_value` documents, with
    /// the fixture CMAC.
    fn peer_g2(
        sbox: &[u8; 256],
        initiator_pk_x_wire: &[u8; 32],
        responder_pk_x_wire: &[u8; 32],
        na: &[u8; 16],
        nb: &[u8; 16],
    ) -> u32 {
        let mut data = [0u8; 80];
        data[0..32].copy_from_slice(initiator_pk_x_wire);
        data[32..64].copy_from_slice(responder_pk_x_wire);
        data[64..80].copy_from_slice(nb);
        let mac = peer_cmac(sbox, na, &data);
        u32::from_be_bytes([mac[12], mac[13], mac[14], mac[15]]) % 1_000_000
    }

    /// Anchor the model against published constants. A failure
    /// here indicts the fixture, never the production code — the
    /// messages say so.
    fn peer_model_self_check(sbox: &[u8; 256]) -> Result<(), &'static str> {
        // AES-128: FIPS 197 worked example.
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let want: [u8; 16] = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4,
            0xC5, 0x5A,
        ];
        if aes128_encrypt(sbox, &key, &pt) != want {
            return Err("peer model self-check failed: AES-128 FIPS-197 vector");
        }
        // AES-CMAC: RFC 4493 examples 1 (empty) and 2 (one block).
        let ck: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        if peer_cmac(sbox, &ck, &[])
            != [
                0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75,
                0x67, 0x46,
            ]
        {
            return Err("peer model self-check failed: CMAC RFC 4493 empty-message vector");
        }
        let m2: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        if peer_cmac(sbox, &ck, &m2)
            != [
                0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A,
                0x28, 0x7C,
            ]
        {
            return Err("peer model self-check failed: CMAC RFC 4493 one-block vector");
        }
        // P-256 anchors. G on the curve comes first: a wrong
        // field prime fails this one check and names the modulus
        // as the defect, instead of surfacing later as an n·G
        // scalar failure.
        if !peer_on_curve(&GEN_X, &GEN_Y) {
            return Err("peer model self-check failed: generator is not on the curve");
        }
        // 1·G = G, n·G = O, (n−1)·G = −G.
        let one: Fe = [1, 0, 0, 0];
        if jac_to_affine(&jac_scalar_mul(&one, &GEN_X, &GEN_Y)) != Some((GEN_X, GEN_Y)) {
            return Err("peer model self-check failed: 1*G is not the generator");
        }
        if jac_to_affine(&jac_scalar_mul(&ORDER_N, &GEN_X, &GEN_Y)).is_some() {
            return Err("peer model self-check failed: n*G is not infinity");
        }
        let n_minus_1: Fe = [ORDER_N[0] - 1, ORDER_N[1], ORDER_N[2], ORDER_N[3]];
        let neg_g = (GEN_X, fe_sub(&[0, 0, 0, 0], &GEN_Y));
        if jac_to_affine(&jac_scalar_mul(&n_minus_1, &GEN_X, &GEN_Y)) != Some(neg_g) {
            return Err("peer model self-check failed: (n-1)*G is not -G");
        }
        Ok(())
    }

    const SMP_IAT: [u8; 7] = [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const SMP_RAT: [u8; 7] = [0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const SMP_NA: [u8; 16] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];

    /// What one driven exchange produced: the responder (DHKey,
    /// MacKey and LTK already asserted against the peer model
    /// inside `run_production_exchange`), the two public-key X
    /// coordinates as they crossed the wire, the responder's
    /// nonce, and the peer-model MacKey (for the stage-2 f6
    /// values the fixtures compute).
    struct ExchangeOutcome {
        responder: Responder<NarfSmpCrypto>,
        peer_pk_x: [u8; 32],
        resp_pk_x: [u8; 32],
        nb: [u8; 16],
        mac_key: [u8; 16],
    }

    /// Drive the production responder through the feature
    /// exchange and the public-key exchange, asserting the ECDH
    /// DHKey against the peer model. Returns the responder in
    /// SentPublicKey plus the two wire public-key X coordinates.
    /// Negative fixtures take the exchange off-script from here.
    fn drive_to_public_key(
        initiator_io: u8,
        initiator_auth: u8,
        peer_priv: &Fe,
    ) -> Result<(Responder<NarfSmpCrypto>, [u8; 32], [u8; 32]), &'static str> {
        let mut r = Responder::new(NarfSmpCrypto, SMP_IAT, SMP_RAT);
        let req = smp::PairingFeatureExchange {
            io_capability: initiator_io,
            oob_data_flag: 0,
            auth_req: initiator_auth,
            max_encryption_key_size: 16,
            initiator_key_distribution: 0,
            responder_key_distribution: 0,
        }
        .encode(smp::SMP_PAIRING_REQUEST);
        let out = r
            .feed(&req)
            .map_err(|_| "responder rejected the pairing request")?;
        if out.len() != 1
            || out[0].code != smp::SMP_PAIRING_RESPONSE
            || out[0].payload != [0x01, 0x00, 0x0D, 16, 0, 0]
        {
            return Err("pairing response payload is not the responder feature set");
        }
        // Public Key exchange: the peer's key comes from the
        // independent model; the responder's must be a real point
        // whose ECDH agrees with the model bit-for-bit.
        let (ppx, ppy) = peer_public(peer_priv);
        let peer_pk_x_wire = fe_to_wire(&ppx);
        let mut pk_payload = Vec::with_capacity(64);
        pk_payload.extend_from_slice(&peer_pk_x_wire);
        pk_payload.extend_from_slice(&fe_to_wire(&ppy));
        let out = r
            .feed(&smp::Pdu {
                code: smp::SMP_PAIRING_PUBLIC_KEY,
                payload: pk_payload,
            })
            .map_err(|_| "responder rejected the peer public key")?;
        if out.len() != 1
            || out[0].code != smp::SMP_PAIRING_PUBLIC_KEY
            || out[0].payload.len() != 64
        {
            return Err("responder public key PDU shape wrong");
        }
        let our_pk = &out[0];
        let mut resp_pk_x = [0u8; 32];
        let mut resp_pk_y = [0u8; 32];
        resp_pk_x.copy_from_slice(&our_pk.payload[0..32]);
        resp_pk_y.copy_from_slice(&our_pk.payload[32..64]);
        if resp_pk_x == [0u8; 32] && resp_pk_y == [0u8; 32] {
            return Err("responder emitted a zero public key (entropy seam not live)");
        }
        if resp_pk_x != r.pub_x || resp_pk_y != r.pub_y {
            return Err("public key PDU does not carry the responder keypair");
        }
        if !peer_on_curve(&fe_from_wire(&resp_pk_x), &fe_from_wire(&resp_pk_y)) {
            return Err("responder public key is not a P-256 point");
        }
        let peer_dh = peer_dhkey_wire(peer_priv, &resp_pk_x, &resp_pk_y);
        if r.dh_key != peer_dh {
            return Err("DHKey mismatch: production ECDH disagrees with the independent peer");
        }
        if r.state != smp::ResponderState::SentPublicKey {
            return Err("responder did not advance to SentPublicKey");
        }
        Ok((r, peer_pk_x_wire, resp_pk_x))
    }

    /// Drive one full exchange against `Responder<NarfSmpCrypto>`
    /// (the production construction `route_smp` uses) with the
    /// deterministic entropy stream installed: feature exchange,
    /// public keys, the f4 confirm commitment (Cb pinned
    /// byte-for-byte), and the nonce reveal that verifies Ca and
    /// derives MacKey + LTK. Returns the responder in
    /// WaitDhKeyCheck plus the wire values each fixture asserts
    /// its own phase against.
    fn run_production_exchange(
        sbox: &[u8; 256],
        initiator_io: u8,
        initiator_auth: u8,
        peer_priv: &Fe,
    ) -> Result<ExchangeOutcome, &'static str> {
        let (mut r, peer_pk_x_wire, resp_pk_x) =
            drive_to_public_key(initiator_io, initiator_auth, peer_priv)?;
        // Authentication stage 1 (§2.3.5.6.2): the peer commits
        // Ca = f4(PKax, PKbx, Na, 0) (§2.2.6 table 2.1 — the
        // committing side's own key first). The responder answers
        // with its own commitment Cb plus Nb. Cb is pinned
        // byte-for-byte against the model — note the table 2.1
        // orientation: Cb takes the responder's key first.
        let ca = peer_f4(sbox, &peer_pk_x_wire, &resp_pk_x, &SMP_NA, 0);
        let out = r
            .feed(&smp::Pdu {
                code: smp::SMP_PAIRING_CONFIRM,
                payload: ca.to_vec(),
            })
            .map_err(|_| "responder rejected the pairing confirm")?;
        if out.len() != 2
            || out[0].code != smp::SMP_PAIRING_CONFIRM
            || out[1].code != smp::SMP_PAIRING_RANDOM
            || out[1].payload.len() != 16
        {
            return Err("responder did not answer Confirm with [Confirm, Random]");
        }
        let mut nb = [0u8; 16];
        nb.copy_from_slice(&out[1].payload);
        if nb != r.nb {
            return Err("pairing random PDU does not carry the responder nonce");
        }
        if nb == [0u8; 16] {
            return Err("responder nonce is zero (entropy seam not live)");
        }
        let want_cb = peer_f4(sbox, &resp_pk_x, &peer_pk_x_wire, &nb, 0);
        if out[0].payload != want_cb {
            return Err("Cb mismatch: production f4 disagrees with the independent peer");
        }
        if r.state != smp::ResponderState::SentRandom {
            return Err("responder did not advance to SentRandom");
        }
        // Pairing Random: Na is revealed; the responder verifies
        // Ca against it and derives MacKey + LTK via f5.
        let out = r
            .feed(&smp::Pdu {
                code: smp::SMP_PAIRING_RANDOM,
                payload: SMP_NA.to_vec(),
            })
            .map_err(|_| "responder rejected the pairing random")?;
        if !out.is_empty() {
            return Err("responder emitted a PDU on the Na step");
        }
        let peer_dh = r.dh_key;
        let mac_key = peer_f5_mac_key(sbox, &peer_dh, &SMP_NA, &nb, &SMP_IAT, &SMP_RAT);
        if r.mac_key != mac_key {
            return Err("MacKey mismatch: production f5 disagrees with the independent peer");
        }
        let want_ltk = peer_f5_ltk(sbox, &peer_dh, &SMP_NA, &nb, &SMP_IAT, &SMP_RAT);
        if r.ltk != want_ltk {
            return Err("LTK mismatch: production f5/CMAC disagrees with the independent peer");
        }
        if r.ltk == [0u8; 16] {
            return Err("derived LTK is zero");
        }
        if r.state != smp::ResponderState::WaitDhKeyCheck {
            return Err("responder did not advance to WaitDhKeyCheck");
        }
        Ok(ExchangeOutcome {
            responder: r,
            peer_pk_x: peer_pk_x_wire,
            resp_pk_x,
            nb,
            mac_key,
        })
    }

    /// Complete Just-Works exchange against the production SMP
    /// crypto, byte-exact on the DHKey and the f5 LTK via the
    /// independent peer model.
    fn smoke_pump_smp_production_crypto_full_exchange() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let result = run_production_exchange(
            &sbox,
            smp::IoCapability::NoInputNoOutput as u8,
            smp::AUTH_BONDING | smp::AUTH_SC,
            &[0x5A5A_5A5A_5A5A_5A5A; 4],
        )
        .and_then(|mut out| {
            let mac_key = out.mac_key;
            let nb = out.nb;
            let r = &mut out.responder;
            if r.method != smp::PairingMethod::JustWorks {
                return Err("negotiated method is not Just Works");
            }
            // Authentication stage 2 (§2.3.5.6.5): the peer's
            // DHKey Check Ea = f6(MacKey, Na, Nb, 0, IOcapA, A, B)
            // (§2.2.8 table 2.2), with IOcapA in §2.2.8 octet
            // order [AuthReq, OOB, IO capability] taken from this
            // fixture's Pairing Request.
            let iocap_a: [u8; 3] = [
                smp::AUTH_BONDING | smp::AUTH_SC,
                0,
                smp::IoCapability::NoInputNoOutput as u8,
            ];
            let ea = peer_f6(
                &sbox, &mac_key, &SMP_NA, &nb, &[0u8; 16], &iocap_a, &SMP_IAT, &SMP_RAT,
            );
            let check = r
                .feed(&smp::Pdu {
                    code: smp::SMP_PAIRING_DHKEY_CHECK,
                    payload: ea.to_vec(),
                })
                .map_err(|_| "responder rejected the DHKey check")?;
            if check.len() != 1 || check[0].code != smp::SMP_PAIRING_DHKEY_CHECK {
                return Err("responder did not answer with its DHKey check");
            }
            // Eb pinned byte-for-byte: the table 2.2 responder
            // form swaps the nonce order and the address order
            // and uses IOcapB (the responder's own feature set:
            // AuthReq 0x0D, OOB 0, DisplayYesNo).
            let iocap_b: [u8; 3] = [0x0D, 0, smp::IoCapability::DisplayYesNo as u8];
            let want_eb = peer_f6(
                &sbox, &mac_key, &nb, &SMP_NA, &[0u8; 16], &iocap_b, &SMP_RAT, &SMP_IAT,
            );
            if check[0].payload != want_eb {
                return Err("Eb mismatch: production f6 disagrees with the independent peer");
            }
            if r.state != smp::ResponderState::Done {
                return Err("responder did not reach Done");
            }
            Ok(())
        });
        test_entropy::clear();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_production_crypto_full_exchange
    );

    /// Published sample data (Core 5.4 Vol 3 Part H Appendix D):
    /// the production f4/f5/f6 helpers and the independent peer
    /// model must both reproduce D.2 / D.3 / D.4 byte-for-byte.
    /// This pins the helpers against the specification itself,
    /// not merely against each other — including the f6 IOcap
    /// octet order (D.4's IOcap is 01 01 02 = AuthReq ‖ OOB ‖ IO
    /// capability, §2.2.8).
    fn smoke_pump_smp_spec_appendix_vectors() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        // D.2 — f4(U, V, X, Z = 0).
        let u: [u8; 32] = [
            0x20, 0xB0, 0x03, 0xD2, 0xF2, 0x97, 0xBE, 0x2C, 0x5E, 0x2C, 0x83, 0xA7, 0xE9, 0xF9,
            0xA5, 0xB9, 0xEF, 0xF4, 0x91, 0x11, 0xAC, 0xF4, 0xFD, 0xDB, 0xCC, 0x03, 0x01, 0x48,
            0x0E, 0x35, 0x9D, 0xE6,
        ];
        let v: [u8; 32] = [
            0x55, 0x18, 0x8B, 0x3D, 0x32, 0xF6, 0xBB, 0x9A, 0x90, 0x0A, 0xFC, 0xFB, 0xEE, 0xD4,
            0xE7, 0x2A, 0x59, 0xCB, 0x9A, 0xC2, 0xF1, 0x9D, 0x7C, 0xFB, 0x6B, 0x4F, 0xDD, 0x49,
            0xF4, 0x7F, 0xC5, 0xFD,
        ];
        let n1: [u8; 16] = [
            0xD5, 0xCB, 0x84, 0x54, 0xD1, 0x77, 0x73, 0x3E, 0xFF, 0xFF, 0xB2, 0xEC, 0x71, 0x2B,
            0xAE, 0xAB,
        ];
        let want_f4: [u8; 16] = [
            0xF2, 0xC9, 0x16, 0xF1, 0x07, 0xA9, 0xBD, 0x1C, 0xF1, 0xED, 0xA1, 0xBE, 0xA9, 0x74,
            0x87, 0x2D,
        ];
        if peer_f4(&sbox, &u, &v, &n1, 0) != want_f4 {
            return TestResult::Fail("peer model f4 disagrees with Appendix D.2");
        }
        if smp::confirm_value(&NarfSmpCrypto, &u, &v, &n1, 0) != want_f4 {
            return TestResult::Fail("production f4 disagrees with Appendix D.2");
        }
        // D.3 — f5(W = DHKey, N1, N2, A1, A2) → MacKey ‖ LTK.
        let w: [u8; 32] = [
            0xEC, 0x02, 0x34, 0xA3, 0x57, 0xC8, 0xAD, 0x05, 0x34, 0x10, 0x10, 0xA6, 0x0A, 0x39,
            0x7D, 0x9B, 0x99, 0x79, 0x6B, 0x13, 0xB4, 0xF8, 0x66, 0xF1, 0x86, 0x8D, 0x34, 0xF3,
            0x73, 0xBF, 0xA6, 0x98,
        ];
        let n2: [u8; 16] = [
            0xA6, 0xE8, 0xE7, 0xCC, 0x25, 0xA7, 0x5F, 0x6E, 0x21, 0x65, 0x83, 0xF7, 0xFF, 0x3D,
            0xC4, 0xCF,
        ];
        let a1: [u8; 7] = [0x00, 0x56, 0x12, 0x37, 0x37, 0xBF, 0xCE];
        let a2: [u8; 7] = [0x00, 0xA7, 0x13, 0x70, 0x2D, 0xCF, 0xC1];
        let want_mac_key: [u8; 16] = [
            0x29, 0x65, 0xF1, 0x76, 0xA1, 0x08, 0x4A, 0x02, 0xFD, 0x3F, 0x6A, 0x20, 0xCE, 0x63,
            0x6E, 0x20,
        ];
        let want_ltk: [u8; 16] = [
            0x69, 0x86, 0x79, 0x11, 0x69, 0xD7, 0xCD, 0x23, 0x98, 0x05, 0x22, 0xB5, 0x94, 0x75,
            0x0A, 0x38,
        ];
        let (mac_key, ltk) = smp::derive_mac_key_and_ltk(&NarfSmpCrypto, &w, &n1, &n2, &a1, &a2);
        if mac_key != want_mac_key || ltk != want_ltk {
            return TestResult::Fail("production f5 disagrees with Appendix D.3");
        }
        if peer_f5_mac_key(&sbox, &w, &n1, &n2, &a1, &a2) != want_mac_key
            || peer_f5_ltk(&sbox, &w, &n1, &n2, &a1, &a2) != want_ltk
        {
            return TestResult::Fail("peer model f5 disagrees with Appendix D.3");
        }
        // D.4 — f6(MacKey, N1, N2, R, IOcap, A1, A2).
        let r: [u8; 16] = [
            0x12, 0xA3, 0x34, 0x3B, 0xB4, 0x53, 0xBB, 0x54, 0x08, 0xDA, 0x42, 0xD2, 0x0C, 0x2D,
            0x0F, 0xC8,
        ];
        let iocap: [u8; 3] = [0x01, 0x01, 0x02];
        let want_f6: [u8; 16] = [
            0xE3, 0xC4, 0x73, 0x98, 0x9C, 0xD0, 0xE8, 0xC5, 0xD2, 0x6C, 0x0B, 0x09, 0xDA, 0x95,
            0x8F, 0x61,
        ];
        if peer_f6(&sbox, &want_mac_key, &n1, &n2, &r, &iocap, &a1, &a2) != want_f6 {
            return TestResult::Fail("peer model f6 disagrees with Appendix D.4");
        }
        if smp::dhkey_check_value(
            &NarfSmpCrypto,
            &want_mac_key,
            &n1,
            &n2,
            &r,
            &iocap,
            &a1,
            &a2,
        ) != want_f6
        {
            return TestResult::Fail("production f6 disagrees with Appendix D.4");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_smp_spec_appendix_vectors);

    /// Tampered confirm: one flipped bit in Ca must abort the
    /// exchange with BadConfirm when Na is revealed. The
    /// commitment is verified, not merely carried — a build that
    /// accepts any confirm value fails this fixture.
    fn smoke_pump_smp_tampered_confirm_rejected() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x1111_2222_3333_4444);
        let result = drive_to_public_key(
            smp::IoCapability::NoInputNoOutput as u8,
            smp::AUTH_BONDING | smp::AUTH_SC,
            &[0x5A5A_5A5A_5A5A_5A5A; 4],
        )
        .and_then(|(mut r, peer_pk_x, resp_pk_x)| {
            let mut ca = peer_f4(&sbox, &peer_pk_x, &resp_pk_x, &SMP_NA, 0);
            ca[0] ^= 0x01;
            // The responder cannot reject yet — it commits Cb and
            // reveals Nb first; rejection lands at the Na reveal.
            let out = r
                .feed(&smp::Pdu {
                    code: smp::SMP_PAIRING_CONFIRM,
                    payload: ca.to_vec(),
                })
                .map_err(|_| "responder failed before the Na reveal")?;
            if out.len() != 2 {
                return Err("responder did not commit Cb + Nb");
            }
            match r.feed(&smp::Pdu {
                code: smp::SMP_PAIRING_RANDOM,
                payload: SMP_NA.to_vec(),
            }) {
                Err(PairingError::BadConfirm) => {}
                _ => return Err("tampered Ca was not rejected with BadConfirm"),
            }
            if r.state != smp::ResponderState::Failed {
                return Err("responder not in Failed after a bad confirm");
            }
            Ok(())
        });
        test_entropy::clear();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_smp_tampered_confirm_rejected);

    /// Wrong-nonce confirm: a Ca honestly computed over a
    /// *different* nonce than the Na the peer then reveals must
    /// fail verification — the confirm binds the exact nonce.
    fn smoke_pump_smp_wrong_nonce_confirm_rejected() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x2222_3333_4444_5555);
        let wrong_na: [u8; 16] = [
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
            0xBE, 0xBF,
        ];
        let result = drive_to_public_key(
            smp::IoCapability::NoInputNoOutput as u8,
            smp::AUTH_BONDING | smp::AUTH_SC,
            &[0x5A5A_5A5A_5A5A_5A5A; 4],
        )
        .and_then(|(mut r, peer_pk_x, resp_pk_x)| {
            let ca = peer_f4(&sbox, &peer_pk_x, &resp_pk_x, &wrong_na, 0);
            let out = r
                .feed(&smp::Pdu {
                    code: smp::SMP_PAIRING_CONFIRM,
                    payload: ca.to_vec(),
                })
                .map_err(|_| "responder failed before the Na reveal")?;
            if out.len() != 2 {
                return Err("responder did not commit Cb + Nb");
            }
            match r.feed(&smp::Pdu {
                code: smp::SMP_PAIRING_RANDOM,
                payload: SMP_NA.to_vec(),
            }) {
                Err(PairingError::BadConfirm) => {}
                _ => return Err("wrong-nonce Ca was not rejected with BadConfirm"),
            }
            if r.state != smp::ResponderState::Failed {
                return Err("responder not in Failed after a wrong-nonce confirm");
            }
            Ok(())
        });
        test_entropy::clear();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_wrong_nonce_confirm_rejected
    );

    /// Tampered DHKey check: one flipped bit in Ea must abort
    /// the completed stage-1 exchange with BadDhKeyCheck — the
    /// responder emits no Eb and never reaches Done.
    fn smoke_pump_smp_tampered_dhkey_check_rejected() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x3333_4444_5555_6666);
        let result = run_production_exchange(
            &sbox,
            smp::IoCapability::NoInputNoOutput as u8,
            smp::AUTH_BONDING | smp::AUTH_SC,
            &[0x5A5A_5A5A_5A5A_5A5A; 4],
        )
        .and_then(|mut out| {
            let iocap_a: [u8; 3] = [
                smp::AUTH_BONDING | smp::AUTH_SC,
                0,
                smp::IoCapability::NoInputNoOutput as u8,
            ];
            let mut ea = peer_f6(
                &sbox,
                &out.mac_key,
                &SMP_NA,
                &out.nb,
                &[0u8; 16],
                &iocap_a,
                &SMP_IAT,
                &SMP_RAT,
            );
            ea[15] ^= 0x80;
            match out.responder.feed(&smp::Pdu {
                code: smp::SMP_PAIRING_DHKEY_CHECK,
                payload: ea.to_vec(),
            }) {
                Err(PairingError::BadDhKeyCheck) => {}
                _ => return Err("tampered Ea was not rejected with BadDhKeyCheck"),
            }
            if out.responder.state != smp::ResponderState::Failed {
                return Err("responder not in Failed after a bad DHKey check");
            }
            Ok(())
        });
        test_entropy::clear();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_tampered_dhkey_check_rejected
    );

    /// Numeric Comparison run: the responder computes the g2 value
    /// with the production CMAC during the random exchange; assert
    /// it byte-exact against the independent model.
    fn smoke_pump_smp_production_crypto_numeric_comparison() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0FED_CBA9_8765_4321);
        let result = run_production_exchange(
            &sbox,
            smp::IoCapability::KeyboardDisplay as u8,
            smp::AUTH_BONDING | smp::AUTH_SC | smp::AUTH_MITM,
            &[0x3C3C_3C3C_3C3C_3C3C; 4],
        )
        .and_then(|out| {
            let r = &out.responder;
            if r.method != smp::PairingMethod::NumericComparison {
                return Err("negotiated method is not Numeric Comparison");
            }
            let want = peer_g2(&sbox, &out.peer_pk_x, &out.resp_pk_x, &SMP_NA, &out.nb);
            if r.numeric_comparison != Some(want) {
                return Err("g2 mismatch: production CMAC disagrees with the independent peer");
            }
            Ok(())
        });
        test_entropy::clear();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_production_crypto_numeric_comparison
    );

    /// Fail-closed entropy: with the source dead, the adapter must
    /// emit NO key material — keygen collapses to the all-zero
    /// point-at-infinity encoding, the nonce is zero, and a
    /// responder built on it puts zero key material on the wire,
    /// so no peer could ever accept the pairing. Nothing is
    /// fabricated.
    fn smoke_pump_smp_entropy_failure_emits_no_key_material() -> TestResult {
        reset_all();
        test_entropy::install_fail();
        let result = run_entropy_failure();
        test_entropy::clear();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_entropy_failure_emits_no_key_material
    );

    fn run_entropy_failure() -> Result<(), &'static str> {
        let crypto = NarfSmpCrypto;
        let (priv_k, pub_x, pub_y) = <NarfSmpCrypto as smp::SmpCrypto>::p256_keygen(&crypto);
        if priv_k != [0u8; 32] || pub_x != [0u8; 32] || pub_y != [0u8; 32] {
            return Err("dead entropy produced non-zero key material");
        }
        if <NarfSmpCrypto as smp::SmpCrypto>::rand128(&crypto) != [0u8; 16] {
            return Err("dead entropy produced a non-zero nonce");
        }
        // A responder on the dead source: feature exchange still
        // works (it needs no secrets), but everything secret it
        // would emit is zero.
        let mut r = Responder::new(NarfSmpCrypto, SMP_IAT, SMP_RAT);
        let req = smp::PairingFeatureExchange {
            io_capability: smp::IoCapability::NoInputNoOutput as u8,
            oob_data_flag: 0,
            auth_req: smp::AUTH_BONDING | smp::AUTH_SC,
            max_encryption_key_size: 16,
            initiator_key_distribution: 0,
            responder_key_distribution: 0,
        }
        .encode(smp::SMP_PAIRING_REQUEST);
        if r.feed(&req).is_err() {
            return Err("responder rejected the pairing request");
        }
        let mut pk_payload = Vec::with_capacity(64);
        pk_payload.extend_from_slice(&fe_to_wire(&GEN_X));
        pk_payload.extend_from_slice(&fe_to_wire(&GEN_Y));
        let out = r
            .feed(&smp::Pdu {
                code: smp::SMP_PAIRING_PUBLIC_KEY,
                payload: pk_payload,
            })
            .map_err(|_| "responder rejected the peer public key")?;
        if out.len() != 1 {
            return Err("responder emitted no public key");
        }
        if out[0].payload != [0u8; 64] {
            return Err("responder emitted key material with a dead entropy source");
        }
        if r.dh_key != [0u8; 32] {
            return Err("DHKey is non-zero with a dead entropy source");
        }
        // The confirm step answers [Cb, Nb]: Cb is a deterministic
        // commitment over public (here all-zero) values, but Nb —
        // the secret nonce — must be zero with a dead source.
        let out = r
            .feed(&smp::Pdu {
                code: smp::SMP_PAIRING_CONFIRM,
                payload: alloc::vec![0u8; 16],
            })
            .map_err(|_| "responder rejected the pairing confirm")?;
        if out.len() != 2 || out[1].code != smp::SMP_PAIRING_RANDOM {
            return Err("responder did not answer Confirm with [Confirm, Random]");
        }
        if out[1].payload != [0u8; 16] {
            return Err("responder emitted a non-zero nonce with a dead entropy source");
        }
        Ok(())
    }

    /// `socket_events_dropped` must accumulate across steps: four
    /// undrained steps of 64 events fill the 128-deep fan-out queue
    /// in two steps, then drop 64 per step — 128 total, held
    /// cumulatively in the published stats (not last-step-only).
    /// Kept separate from the conversation smoke because that one
    /// pins its exact step counts and drains the queue.
    fn smoke_pump_socket_event_drops_accumulate() -> TestResult {
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
        let peer = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        for _ in 0..4 {
            for _ in 0..64 {
                fake.enqueue_event(le_connection_complete(0x0040, peer));
            }
            if pump_once(0).events != 64 {
                reset_all();
                return TestResult::Fail("pump step did not drain its 64 events");
            }
        }
        let st = stats(0);
        let totals_ok = st.map(|s| s.events_seen) == Some(256)
            && st.map(|s| s.socket_events_dropped) == Some(128);
        let mut drained = 0usize;
        while take_socket_event(0).is_some() {
            drained += 1;
        }
        reset_all();
        if !totals_ok {
            return TestResult::Fail("socket_events_dropped did not accumulate across steps");
        }
        if drained != SOCKET_EVENT_QUEUE_CAP {
            return TestResult::Fail("socket queue did not hold exactly the cap");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_socket_event_drops_accumulate);
}
