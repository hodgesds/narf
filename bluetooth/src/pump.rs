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
//! - LE Long Term Key Request → answered from the in-progress
//!   AuthComplete session or the bond store when peer address +
//!   EDIV/Rand match exactly, else LTK Request Negative Reply.
//! - Number Of Completed Packets → ACL flow-control credits.
//! - ACL → per-connection `l2cap::Dispatcher` → CID routing:
//!   ATT → the per-controller `gatt_server::GattServer` (default GAP /
//!   GATT / Device Information / Battery services mounted);
//!   SMP → a per-connection SMP session: `smp::Responder` for
//!   peer-initiated pairings, `smp::Initiator` when the peer sends a
//!   Security Request or the application calls
//!   [`smp_initiate_pairing`]; a completed bonded pairing persists in
//!   the bond store, and an encrypted link starts Phase 3 key
//!   distribution; LE signalling → Connection Parameter Update
//!   accepted, LE credit-based connections answered from the
//!   `l2cap_server::ServerRegistry` (open/credit/disconnect flow,
//!   SDU reassembly, staged receive queues); BR/EDR signalling →
//!   Echo answered, Information answered, Connection Requests
//!   answered from the registry (SDP on PSM 0x0001, RFCOMM on PSM
//!   0x0003, refused otherwise), Configure / Disconnection answered
//!   so peers do not wedge. Dynamic CIDs route to their channel's
//!   service (SDP server, RFCOMM session, or staged generic queue);
//!   frames on unknown dynamic CIDs are dropped and counted.
//!   initiating pairing (`smp::Initiator` needs an application policy
//!   trigger that does not exist yet).
//! - LE Advertising Report (while scanning) → the central peer table.
//! - Inquiry Result (while inquiring) → the classic peer table;
//!   Inquiry Complete → the classic phase machine, issuing a
//!   deferred page when one is waiting. Inquiry Result with RSSI
//!   (0x22) and Extended Inquiry Result / EIR (0x2F) feed the
//!   same table with RSSI and the EIR local name; Remote Name
//!   Request Complete (0x07) delivers a requested peer name into
//!   the table.
//! - BR/EDR Connection Complete (while paging) → the classic phase
//!   machine + connection table entry.
//! - Command Complete / Command Status for the scan/connect opcodes
//!   → the central phase machine: parameters accepted enables the
//!   scan, disable accepted issues a deferred Create Connection, a
//!   refused command drops the phase back to Idle. The same arms
//!   drive the classic phase machine: a refused Inquiry or Create
//!   Connection drops it to Idle, a refused Inquiry Cancel returns
//!   it to Inquiring, an accepted Write Scan Enable records the mode,
//!   an accepted Write Inquiry Mode records the result format, and
//!   a refused Remote Name Request frees the pending name slot.
//!
//! ## Central initiation (issue #1312)
//!
//! [`central_start_scan`] / [`central_stop_scan`] /
//! [`central_connect`] issue the LE scan + Create Connection commands
//! through the pump's own send path, sequenced on the controller's
//! completions, never on host assumption. [`central_phase`] /
//! [`central_peers`] expose the state for a future mgmt/userspace
//! trigger lane. What this deliberately does NOT do: ATT/GATT client
//! traffic after connect (#1313), pairing initiation (#888), or a
//! host-initiated disconnect — the connection is tracked like any
//! other pump connection and torn down on Disconnection Complete.
//!
//! ## Extended advertising / scanning (issue #823)
//!
//! [`ext_central_start_scan`] / [`ext_central_stop_scan`] issue the
//! LE Set Extended Scan Parameters / Enable commands (§7.8.64/65)
//! through the same sequenced send path; LE Extended Advertising
//! Reports (§7.7.65.13) received while scanning feed the
//! [`gap::ExtendedScanner`] peer table with fragment reassembly, and
//! LE Scan Timeout (§7.7.65.17) ends the scan on its own.
//! [`ext_adv_start`] / [`ext_adv_stop`] drive one advertising set
//! through parameters → data → (scan response) → enable (§7.8.53..56),
//! chained on Command Completes; LE Advertising Set Terminated
//! (§7.7.65.18) and LE Scan Request Received (§7.7.65.19) land on
//! the set's host-side state. [`ext_central_phase`] /
//! [`ext_central_peers`] / [`ext_adv_phase`] /
//! [`ext_adv_selected_tx_power`] expose the state for a future
//! mgmt/userspace trigger lane. What this deliberately does NOT do:
//! periodic advertising (§7.8.61..63) or LE Extended Create
//! Connection (§7.8.66) — both are follow-ups to #823.
//!
//! ## Classic initiation (issue #1315)
//!
//! [`classic_start_inquiry`] / [`classic_cancel_inquiry`] /
//! [`classic_connect`] / [`classic_write_scan_enable`] /
//! [`classic_write_inquiry_mode`] / [`classic_request_remote_name`]
//! issue the BR/EDR inquiry + paging + name commands through the
//! pump's own send path, sequenced on the controller's completions
//! exactly like the LE central above (copied pattern: phase machine
//! in [`classic::ClassicCentral`], deferred connect while the inquiry
//! is cancelled, fail-closed refusal handling). [`classic_phase`] /
//! [`classic_peers`] / [`classic_scan_mode`] /
//! [`classic_inquiry_mode`] expose the state for a future
//! mgmt/userspace trigger lane. What this deliberately does
//! NOT do: SSP pairing initiation on the paged link (#888 covers
//! pairing). SCO setup after connect is the AF_BLUETOOTH SCO socket
//! path (issue #814): [`sco_connect`] pages when needed and issues
//! `HCI_Setup_Synchronous_Connection` (§7.1.26) on the ACL handle,
//! completing on Synchronous Connection Complete (§7.7.35); SCO
//! frames ride the transport's `send_sco` / `recv_sco` (#817) and
//! are staged per link for [`drain_sco_rx`].
//!
//! ## Lifecycle
//!
//! [`stop_pump`] asks the task to exit at its next iteration. It does
//! not unregister the controller: full detach composition (registry
//! removal, sysfs teardown, mgmt INDEX_REMOVED) is
//! [`crate::controller::unregister_controller`], which calls [`stop_pump`]
//! and then [`remove_pump`] so the transport is quiescent before
//! anything else is torn down.
//!
//! Spec: Bluetooth Core 5.3 Vol 3 Part A (L2CAP), Part F (ATT),
//! Part G (GATT), Part H (SMP); Vol 4 Part E (HCI).

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_filesystem::bluetooth::{
    BtConnectStatus, BtRegisterStatus, BtScoConnectResult, BtSendError,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::att;
use crate::bond_store::{Bond, BondStore};
use crate::classic::{self, ClassicPhase};
use crate::controller::ControllerInfo;
use crate::event::{
    parse_ext_adv_selected_tx_power, parse_extended_inquiry_results, parse_inquiry_results,
    parse_inquiry_results_with_rssi, parse_le_advertising_reports,
    parse_le_extended_advertising_reports, ClassicConnectionComplete, CommandComplete,
    CommandStatus, DisconnectionComplete, EventCode, LeAdvertisingSetTerminated,
    LeChannelSelectionAlgorithm, LeConnectionComplete, LeEnhancedConnectionComplete,
    LeLongTermKeyRequest, LePeriodicAdvReport, LePeriodicAdvSyncEstablished, LePeriodicAdvSyncLost,
    LePeriodicAdvSyncTransferReceived, LeScanRequestReceived, LeScanTimeout,
    NumberOfCompletedPackets, RemoteNameRequestComplete, SyncConnectionComplete,
};
use crate::gap::{
    self, AdvertisingSetPhase, CentralPhase, ExtendedScannerPhase, PeriodicAdvertiserPhase,
    PeriodicSyncPhase,
};
use crate::gatt_client::{self, GattClientError};
use crate::gatt_server::GattServer;
use crate::hci::{AclData, Command, Event, ScoData};
use crate::hogp::HidInformation;
use crate::hogp_client::{HogpClient, HogpHandles};
use crate::l2cap::{
    self, BFrame, CidAllocator, CidClass, SignallingCode, CID_ATT, CID_LE_SIGNALLING,
    CID_SIGNALLING, CID_SMP,
};
use crate::l2cap_server::{
    BrEdrChannel, Channel, ChannelService, LeCocChannel, LeReceiveOutcome, ServerKind,
    ServerRegistry, LE_COC_INITIAL_CREDITS, LE_COC_MPS, LE_COC_MTU,
};
use crate::opcode as op;
use crate::sdp_server::SdpServer;
use crate::services;
use crate::smp::{self, Initiator, PairingError, Responder, SmpCrypto};
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
    pub frames_dropped_no_credit: u64,
    pub socket_events_dropped: u64,
    pub transport_errors: u64,
    /// SCO frames received from the transport and staged on a link.
    pub sco_received: u64,
}

/// Work performed by one [`pump_once`] step.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PumpStep {
    pub events: u32,
    pub acl_received: u32,
    pub acl_sent: u32,
    pub commands_sent: u32,
    /// SCO frames received from the transport and staged on a link.
    pub sco_received: u32,
}

impl PumpStep {
    pub fn is_idle(&self) -> bool {
        self.events == 0
            && self.acl_received == 0
            && self.acl_sent == 0
            && self.commands_sent == 0
            && self.sco_received == 0
    }
}

/// What an outbound channel-open (#1532) is opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboundKind {
    /// LE credit-based channel to `psm`.
    LeCoc { psm: u16 },
    /// BR/EDR generic channel to `psm`.
    BrEdr { psm: u16 },
    /// RFCOMM DLC to server `channel` (mux open + SABM exchange).
    Rfcomm { channel: u8 },
}

/// Progress of one outbound channel-open (#1532). The record lives
/// in `PumpCore::outbound` from the socket's first `connect()` call
/// until the socket takes the completed (or refused) outcome; the
/// pump drives it from HCI events and signalling responses. A
/// record in `Open` owns its channel (already socket-claimed, so
/// `accept` can never steal it); a record in `Refused`/`Failed`
/// carries the terminal outcome for one poll, then is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboundState {
    /// No ACL link yet; the HCI connection is being established.
    AclPending,
    /// Channel-open request sent; awaiting the peer's response.
    RequestSent,
    /// BR/EDR Connection Response accepted; Configure Request sent.
    Configuring,
    /// RFCOMM mux channel open; SABM on DLCI 0 sent.
    MuxSabmSent,
    /// Mux open; SABM on the target DLCI sent.
    DlcSabmSent,
    /// Channel/DLC open and socket-claimed; takeable by `connect`.
    Open,
    /// Peer refused the open; the value is the L2CAP result code.
    Refused(u16),
    /// Failed below L2CAP (link failure, DM, Command Reject).
    Failed,
}

/// One in-flight outbound channel-open (#1532).
#[derive(Clone, Copy, Debug)]
struct OutboundOpen {
    /// Peer address: `[address type, bdaddr...]`.
    peer: [u8; 7],
    kind: OutboundKind,
    state: OutboundState,
    /// Signalling identifier of the outstanding request (0 = none).
    ident: u8,
    /// Second identifier (BR/EDR Configure Request).
    ident2: u8,
    /// ACL handle once the link exists (0 while waiting for it).
    handle: u16,
    /// Our local CID once allocated.
    local_cid: u16,
    /// The peer's CID once the open succeeds.
    peer_cid: u16,
    /// RFCOMM DLCI once the DLC opens (0 for L2CAP).
    dlci: u8,
}

impl OutboundOpen {
    fn new(peer: [u8; 7], kind: OutboundKind) -> Self {
        Self {
            peer,
            kind,
            state: OutboundState::AclPending,
            ident: 0,
            ident2: 0,
            handle: 0,
            local_cid: 0,
            peer_cid: 0,
            dlci: 0,
        }
    }

    /// Whether this record is the open the socket is polling for
    /// (`psm` is the PSM, or the RFCOMM server channel).
    fn matches(&self, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
        if self.peer != peer {
            return false;
        }
        match (self.kind, rfcomm) {
            (OutboundKind::LeCoc { psm: p }, false) => le && p == psm,
            (OutboundKind::BrEdr { psm: p }, false) => !le && p == psm,
            (OutboundKind::Rfcomm { channel }, true) => !le && channel as u16 == psm,
            _ => false,
        }
    }
}

// ── Per-connection state ────────────────────────────────────────────

/// One side of a pairing: the pump drives a responder for
/// peer-initiated pairings and an initiator for peer Security
/// Requests and application triggers. Exactly one session per
/// connection — a second pairing attempt while one is in flight is
/// refused by the initiator API and routed into the live session
/// for inbound PDUs.
#[derive(Debug)]
enum SmpSession {
    Responder(Responder<NarfSmpCrypto>),
    Initiator(Initiator<NarfSmpCrypto>),
}

/// One ACL connection tracked by the pump.
#[derive(Debug)]
struct Connection {
    handle: u16,
    le: bool,
    /// `[address_type, bd_addr(wire order, 6)]` of the peer.
    peer_addr: [u8; 7],
    dispatcher: l2cap::Dispatcher,
    smp: Option<SmpSession>,
    /// GATT client record, present only on central-role
    /// connections (issue #1313). Peripheral-role connections
    /// keep server-only dispatch.
    client: Option<gatt_client::Client>,
    /// HOGP client record, present only once a central-role
    /// connection's peer has been attached as a HID device
    /// (issue #1314, via `hogp_attach`).
    hogp: Option<HogpClient>,
    /// Channel Selection Algorithm (§7.7.65.20) reported for this
    /// connection, if the controller has sent one: 0x00 = #1,
    /// 0x01 = #2. Extended-create connections always get one
    /// immediately after Enhanced Connection Complete (§7.8.66).
    channel_selection_algorithm: Option<u8>,
    /// LTK from a completed pairing. When the pairing was bonded
    /// the same LTK also lives in the pump's bond store, which is
    /// what answers reconnects; this field is the live
    /// connection's copy.
    ltk: Option<[u8; 16]>,
    encrypted: bool,
    /// Dynamic-CID allocator for this connection's channels.
    cid_alloc: CidAllocator,
    /// Open L2CAP channel servers (LE COC + BR/EDR), in open order.
    channels: Vec<Channel>,
}

impl Connection {
    fn new(handle: u16, le: bool, peer_addr: [u8; 7]) -> Self {
        Self {
            handle,
            le,
            peer_addr,
            dispatcher: l2cap::Dispatcher::new(),
            smp: None,
            client: None,
            hogp: None,
            channel_selection_algorithm: None,
            ltk: None,
            encrypted: false,
            cid_alloc: CidAllocator::new(),
            channels: Vec::new(),
        }
    }

    /// Position of the open channel with `local_cid`, if any.
    fn channel_pos(&self, local_cid: u16) -> Option<usize> {
        self.channels
            .iter()
            .position(|c| c.local_cid() == local_cid)
    }
}

// ── SCO link state (issue #814) ─────────────────────────────────────

/// One established SCO/eSCO link: the Synchronous Connection
/// Complete's handle + negotiated lengths, the ACL handle it rides
/// on, and staged inbound frames.
///
/// Negotiated link state (`voice_setting`, `tx_packet_length`,
/// `rx_packet_length`) is recorded for future SCO_CONNINFO
/// reporting; no reader exists yet.
#[allow(dead_code)]
#[derive(Debug)]
struct ScoLink {
    /// SCO connection handle (from Synchronous Connection Complete).
    handle: u16,
    /// ACL connection handle this SCO link rides on.
    acl_handle: u16,
    /// Peer bdaddr (wire order).
    peer: [u8; 6],
    /// Voice setting the link was opened with (socket BT_VOICE).
    voice_setting: u16,
    /// Negotiated packet lengths from Synchronous Connection Complete.
    tx_packet_length: u16,
    rx_packet_length: u16,
    /// SCO MTU for send (controller Read Buffer Size SCO MTU, 60
    /// when unset — Linux `sco_conn_add`).
    mtu: u16,
    /// Peer class of device (SCO_CONNINFO; zeros when unknown).
    dev_class: [u8; 3],
    /// Staged inbound SCO payloads awaiting `drain_sco_rx`.
    rx: VecDeque<Vec<u8>>,
    /// Claimed by a socket's `sco_connect_status` poll. A link is
    /// claimed at most once: a second socket connecting to the same
    /// peer gets AlreadyConnected until the link goes away.
    claimed: bool,
}

/// Outbound SCO setup in flight (at most one per controller — the
/// classic phase machine pages one peer at a time).
#[derive(Debug)]
struct PendingSco {
    /// Peer bdaddr (wire order).
    peer: [u8; 6],
    /// Voice setting the socket asked for.
    voice_setting: u16,
    /// ACL handle once the peer's ACL connection is up; None while paging.
    acl_handle: Option<u16>,
    /// Setup Synchronous Connection already issued; awaiting
    /// Synchronous Connection Complete.
    setup_sent: bool,
    /// Terminal outcome recorded once the setup can no longer
    /// complete (refused Setup Sync, failed page, dead ACL, dead
    /// transport). Consumed by `sco_connect_status` / a re-entered
    /// `sco_connect`, which report it verbatim.
    failed: Option<BtScoConnectResult>,
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
    /// PSM → channel-server registry (SDP + RFCOMM pre-registered
    /// on BR/EDR; LE services register explicitly).
    servers: ServerRegistry,
    /// SDP record database, shared by all connections.
    sdp: SdpServer,
    /// GAP central initiator state (issue #1312): scan discovery +
    /// outbound connection setup. Driven by `dispatch_event` for
    /// inbound reports/completions and by the `central_*` API for
    /// outbound issuance.
    central: gap::Central,
    /// Connection parameters waiting on scan-disable completion:
    /// Connection parameters waiting on scan-disable completion:
    /// `central_connect` / `central_connect_ext` from Scanning
    /// issue Set_Scan_Enable(0) first and only issue the create
    /// command once the disable completes, so the controller is
    /// never asked to initiate while it is still scanning.
    pending_connect: Option<PendingConnect>,
    /// GAP extended scanner state (issue #823): extended scan
    /// discovery. Mirrors the legacy `central` field; driven by
    /// `dispatch_event` for inbound extended reports / scan timeout
    /// and by the `ext_central_*` API for outbound issuance.
    ext_central: gap::ExtendedScanner,
    /// Advertising sets owned by this controller (issue #823), keyed
    /// by handle. Driven by `dispatch_event` (Advertising Set
    /// Terminated, Scan Request Received) and the `ext_adv_*` API.
    ext_adv_sets: Vec<gap::AdvertisingSet>,
    /// Advertising payloads waiting on the parameters completion of
    /// an `ext_adv_start` chain: `ext_adv_start` issues parameters
    /// first and the data / scan-response / enable commands follow
    /// on successive Command Completes. Only one chain runs at a
    /// time — a second `ext_adv_start` while one is in flight is
    /// refused — so the completion arms can find their set by phase.
    pending_ext_adv: Option<PendingExtAdv>,
    /// Classic BR/EDR central initiator state (issue #1315): inquiry
    /// discovery + outbound paging. Mirrors the LE `central` field;
    /// driven by `dispatch_event` and the `classic_*` API.
    classic: classic::ClassicCentral,
    /// LE periodic advertising broadcaster state (issue #1560):
    /// which advertising handle carries a periodic train and
    /// whether it is enabled. Driven by `dispatch_event` (command
    /// completions) and the `periodic_adv_*` API.
    periodic_adv: gap::PeriodicAdvertiser,
    /// LE periodic advertising sync receiver state (issue #1560):
    /// creating / synced / lost. Driven by `dispatch_event` (sync
    /// subevents + command completions) and the `periodic_adv_*` API.
    periodic_sync: gap::PeriodicSync,
    /// Outcome of the most recent §7.8.89..92 sync-transfer
    /// command (issue #1654), from its Command Complete. The
    /// transfer commands change no phase — the sync stays Synced
    /// and the train stays Enabled — so the completion is recorded
    /// here rather than in either state machine; the pump API /
    /// fixtures read it via `periodic_sync_transfer_last_outcome`.
    last_sync_transfer: Option<gap::SyncTransferOutcome>,
    /// Page deferred while an inquiry is being cancelled:
    /// `classic_connect` from Inquiring issues Inquiry_Cancel first
    /// and only issues Create_Connection once Inquiry Complete
    /// arrives, so the controller is never asked to page while it
    /// is still inquiring.
    pending_page: Option<classic::PageRequest>,
    /// Write_Scan_Enable mode awaiting its Command Complete; applied
    /// to `classic.scan_mode` only on success.
    pending_scan_mode: Option<u8>,
    /// BD_ADDR of the in-flight HCI_Remote_Name_Request, if any.
    /// Only one name request may be outstanding (the controller
    /// rejects a second with Command Disallowed); cleared on its
    /// Remote Name Request Complete, or on a refused Command
    /// Status (no Complete follows a refusal).
    pending_name: Option<[u8; 6]>,
    /// Handles with a host-initiated HCI Disconnect in flight, in
    /// issue order (issue #1527): [`PumpCore::disconnect`] sends
    /// HCI_Disconnect and records the handle here; the
    /// Disconnection Complete removes it, or a refused Command
    /// Status does (no Complete follows a refusal — same
    /// discipline as `pending_name`). Command Status events arrive
    /// in issue order (Vol 4 Part E §7.7.15: one status per
    /// command, in order), so a refused status belongs to the
    /// oldest entry. A second disconnect for a handle already
    /// queued here is refused as already-disconnecting instead of
    /// sending the controller a duplicate Disconnect.
    disconnecting: VecDeque<u16>,
    /// Write_Inquiry_Mode mode awaiting its Command Complete;
    /// applied to `classic.inquiry_mode` only on success.
    pending_inquiry_mode: Option<u8>,
    /// Bonds from completed pairings (driver-domain state, never a
    /// global, never exposed to userspace). Survives disconnects;
    /// lost on controller removal or reboot.
    bonds: BondStore,
    /// Provisioned sealing key for the on-disk bond image
    /// (#818). `None` until a key service provisions one — with
    /// no key, sealing is disabled and `sealed_bonds` stays
    /// `None`; bonds are in-memory only. The key is never derived
    /// here: key custody belongs to the suspend programme's
    /// KEYS domain (#996–#1008), and this slot is the hookup
    /// point, not a key service.
    bond_sealing_key: Option<[u8; 32]>,
    /// Latest sealed bond image (`nonce ‖ ciphertext ‖ tag`,
    /// ChaCha20-Poly1305 over the versioned store encoding).
    /// Refreshed after every store mutation while a key is
    /// provisioned; the future disk layer reads it via
    /// `sealed_bonds_image` and restores via
    /// `restore_sealed_bonds`. `None` while sealing is disabled.
    sealed_bonds: Option<Vec<u8>>,
    /// Channels claimed by AF_BLUETOOTH sockets via `accept`, as
    /// (ACL handle, local CID, DLCI). DLCI is 0 for L2CAP channels;
    /// for RFCOMM it names the claimed DLC, so one mux can serve
    /// several server channels at once. A claimed channel/DLC is
    /// owned by its socket: a later `accept` never returns it twice,
    /// and the pump's own services never route to it. Service
    /// channels (SDP/RFCOMM) are never claimed as L2CAP channels.
    /// Released when the socket disconnects it, the peer
    /// disconnects it, or its connection goes away — every
    /// channel-removal site releases, so a reused CID is never
    /// shadowed by a stale claim.
    claimed: Vec<(u16, u16, u8)>,
    /// In-flight outbound channel-opens (issue #1532), driven by
    /// HCI events and signalling responses; see [`OutboundOpen`].
    outbound: Vec<OutboundOpen>,
    /// Next L2CAP signalling identifier for outbound requests.
    /// 0 is never issued (it marks commands that expect no
    /// response); the counter cycles 1..=255.
    next_signal_ident: u8,
    /// Encoded outbound ACL packets awaiting flow-control credits.
    pending_acl: VecDeque<Vec<u8>>,
    /// Controller-wide ACL packets currently with the controller.
    acl_in_flight: u32,
    /// Established SCO links (issue #814): one per peer, owned by
    /// the AF_BLUETOOTH SCO socket that connected it. A link's SCO
    /// handle dies with its ACL connection (Disconnection Complete
    /// removes both).
    sco_links: Vec<ScoLink>,
    /// Outbound SCO setup in flight.
    pending_sco: Option<PendingSco>,
    stats: PumpStats,
}

impl fmt::Debug for PumpCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PumpCore")
            .field("index", &self.index)
            .field("info", &self.info)
            .field("connections", &self.connections.len())
            .field("central_phase", &self.central.phase)
            .field("ext_central_phase", &self.ext_central.phase)
            .field("ext_adv_sets", &self.ext_adv_sets.len())
            .field("classic_phase", &self.classic.phase)
            .field("periodic_adv_phase", &self.periodic_adv.phase)
            .field("periodic_sync_phase", &self.periodic_sync.phase)
            .field("last_sync_transfer", &self.last_sync_transfer)
            .field("bonds", &self.bonds.len())
            .field("claimed", &self.claimed.len())
            .field("outbound", &self.outbound.len())
            .field("pending_acl", &self.pending_acl.len())
            .field("acl_in_flight", &self.acl_in_flight)
            .field("sco_links", &self.sco_links.len())
            .field("pending_sco", &self.pending_sco.is_some())
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
        // HID service mount (#1314): always mounted like
        // GAP/GATT/DIS/Battery. Mounting alone does not
        // advertise, and the server cannot emit notifications
        // yet — a central can read the map and flip Protocol
        // Mode, but receives no input reports from this mount.
        services::mount_hid_service(&mut gatt.db);
        Self {
            index,
            transport,
            info,
            connections: Vec::new(),
            gatt,
            servers: ServerRegistry::new(),
            sdp: SdpServer::new(),
            central: gap::Central::new(),
            pending_connect: None,
            ext_central: gap::ExtendedScanner::new(),
            ext_adv_sets: Vec::new(),
            pending_ext_adv: None,
            classic: classic::ClassicCentral::new(),
            periodic_adv: gap::PeriodicAdvertiser::new(),
            periodic_sync: gap::PeriodicSync::new(),
            last_sync_transfer: None,
            pending_page: None,
            pending_scan_mode: None,
            pending_name: None,
            disconnecting: VecDeque::new(),
            pending_inquiry_mode: None,
            bonds: BondStore::new(),
            bond_sealing_key: None,
            sealed_bonds: None,
            claimed: Vec::new(),
            outbound: Vec::new(),
            next_signal_ident: 0,
            pending_acl: VecDeque::new(),
            acl_in_flight: 0,
            sco_links: Vec::new(),
            pending_sco: None,
            stats: PumpStats::default(),
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Channel Selection Algorithm recorded for `handle`
    /// (§7.7.65.20): outer `None` = no such connection; inner
    /// `None` = no CSA event received yet for it.
    pub fn connection_channel_selection(&self, handle: u16) -> Option<Option<u8>> {
        self.connections
            .iter()
            .find(|c| c.handle == handle)
            .map(|c| c.channel_selection_algorithm)
    }

    pub fn stats(&self) -> PumpStats {
        self.stats
    }

    /// Register an LE PSM served by the generic staging server
    /// (SDUs staged for [`drain_channel_rx`]). The registry is the
    /// extension point future LE profiles register against.
    /// `false` when the PSM is already registered (a previous
    /// listener owns it); the socket layer reports that as
    /// EADDRINUSE.
    pub fn register_le_psm(&mut self, le_psm: u16) -> bool {
        if self.servers.lookup_le(le_psm).is_some() {
            return false;
        }
        self.servers.register_le(le_psm, ServerKind::Generic);
        true
    }

    /// Register a BR/EDR PSM served by the generic staging server.
    /// `false` when the PSM is owned by an in-kernel service (SDP on
    /// 0x0001, RFCOMM on 0x0003) or already registered by a previous
    /// listener.
    pub fn register_bredr_psm(&mut self, psm: u16) -> bool {
        match self.servers.lookup_bredr(psm) {
            Some(_) => false,
            None => {
                self.servers.register_bredr(psm, ServerKind::Generic);
                true
            }
        }
    }

    /// Release a socket-listener LE PSM registration. Service
    /// entries are never removed (see `ServerRegistry::unregister_le`).
    pub fn unregister_le_psm(&mut self, le_psm: u16) {
        self.servers.unregister_le(le_psm);
    }

    /// Release a socket-listener BR/EDR PSM registration.
    pub fn unregister_bredr_psm(&mut self, psm: u16) {
        self.servers.unregister_bredr(psm);
    }

    /// Whether `handle`/`local_cid`/`dlci` is claimed by a socket
    /// (DLCI 0 for L2CAP channels).
    fn is_claimed(&self, handle: u16, local_cid: u16, dlci: u8) -> bool {
        self.claimed.contains(&(handle, local_cid, dlci))
    }

    /// Release every socket claim on (`handle`, `local_cid`) — all
    /// DLCIs. Call whenever the channel goes away.
    fn release_claims(&mut self, handle: u16, local_cid: u16) {
        self.claimed
            .retain(|(h, c, _)| !(*h == handle && *c == local_cid));
    }

    /// Release every socket claim on a connection (connection gone).
    fn release_handle_claims(&mut self, handle: u16) {
        self.claimed.retain(|(h, _, _)| *h != handle);
    }

    /// Release one RFCOMM DLC claim (DLCI closed, mux survives).
    fn release_dlc_claim(&mut self, handle: u16, local_cid: u16, dlci: u8) {
        self.claimed
            .retain(|(h, c, d)| !(*h == handle && *c == local_cid && *d == dlci));
    }

    /// Claim the oldest unclaimed socket-claimable channel opened by
    /// a peer to `psm`: LE CoC channels for an LE listener, generic
    /// BR/EDR channels otherwise. Service channels (SDP/RFCOMM) are
    /// never claimable — they belong to the pump's own services.
    /// Returns (ACL handle, local CID, peer CID, peer address).
    pub fn take_pending_channel(&mut self, psm: u16, le: bool) -> Option<(u16, u16, u16, [u8; 7])> {
        for conn in self.connections.iter() {
            for ch in conn.channels.iter() {
                let (matches, local_cid, peer_cid) = match ch {
                    Channel::Le(lech) if le && lech.le_psm == psm => {
                        (true, lech.local_cid, lech.peer_cid)
                    }
                    Channel::BrEdr(brch)
                        if !le
                            && brch.psm == psm
                            && matches!(brch.service, ChannelService::Generic { .. }) =>
                    {
                        (true, brch.local_cid, brch.peer_cid)
                    }
                    _ => (false, 0, 0),
                };
                if matches && !self.is_claimed(conn.handle, local_cid, 0) {
                    self.claimed.push((conn.handle, local_cid, 0));
                    return Some((conn.handle, local_cid, peer_cid, conn.peer_addr));
                }
            }
        }
        None
    }

    /// Whether an unclaimed socket-claimable channel to `psm` is
    /// pending (non-consuming peek for poll/accept readiness).
    pub fn pending_channel(&self, psm: u16, le: bool) -> bool {
        for conn in self.connections.iter() {
            for ch in conn.channels.iter() {
                let matches = match ch {
                    Channel::Le(lech) => le && lech.le_psm == psm,
                    Channel::BrEdr(brch) => {
                        !le && brch.psm == psm
                            && matches!(brch.service, ChannelService::Generic { .. })
                    }
                };
                if matches && !self.is_claimed(conn.handle, ch.local_cid(), 0) {
                    return true;
                }
            }
        }
        false
    }

    /// Send one SDU on the open channel (`handle`, `local_cid`).
    /// LE CoC: segmented into K-frames against the peer's MPS and
    /// credit budget (all-or-nothing — see
    /// `LeCocChannel::take_send_frames`). BR/EDR generic: one
    /// B-frame. Returns the bytes sent. Frames are flushed to the
    /// transport here, so a caller outside a pump step still moves
    /// the bytes.
    pub fn send_channel(
        &mut self,
        handle: u16,
        local_cid: u16,
        payload: &[u8],
    ) -> Result<usize, BtSendError> {
        if payload.is_empty() {
            return Ok(0);
        }
        let conn_idx = match self.connections.iter().position(|c| c.handle == handle) {
            Some(i) => i,
            None => return Err(BtSendError::NoChannel),
        };
        let le = self.connections[conn_idx].le;
        let pos = match self.connections[conn_idx].channel_pos(local_cid) {
            Some(p) => p,
            None => return Err(BtSendError::NoChannel),
        };
        match &mut self.connections[conn_idx].channels[pos] {
            Channel::Le(ch) => {
                let peer_cid = ch.peer_cid;
                let frames = match ch.take_send_frames(payload) {
                    Some(f) => f,
                    None => {
                        // Distinguish the two refusals without
                        // re-deriving the budget: an oversize SDU
                        // is TooBig, anything else is credit.
                        if payload.len() > ch.peer_mtu as usize {
                            return Err(BtSendError::TooBig);
                        }
                        return Err(BtSendError::NoCredits);
                    }
                };
                for frame in frames {
                    self.queue_frame(handle, le, &BFrame::new(peer_cid, frame));
                }
            }
            Channel::BrEdr(ch) => match &ch.service {
                ChannelService::Generic { .. } => {
                    let peer_cid = ch.peer_cid;
                    self.queue_frame(handle, le, &BFrame::new(peer_cid, payload.to_vec()));
                }
                // Service channels are never socket-held; a stale
                // socket that kept one must not inject into the
                // service's stream.
                ChannelService::Sdp | ChannelService::Rfcomm(_) => {
                    return Err(BtSendError::WrongService);
                }
            },
        }
        self.flush_acl();
        Ok(payload.len())
    }

    /// Whether staged inbound data awaits on the open channel
    /// (`handle`, `local_cid`) — non-consuming peek for poll.
    pub fn channel_rx_pending(&self, handle: u16, local_cid: u16) -> bool {
        let Some(conn) = self.connections.iter().find(|c| c.handle == handle) else {
            return false;
        };
        let Some(pos) = conn.channel_pos(local_cid) else {
            return false;
        };
        match &conn.channels[pos] {
            Channel::Le(ch) => !ch.rx.is_empty(),
            Channel::BrEdr(ch) => match &ch.service {
                ChannelService::Generic { rx } => !rx.is_empty(),
                // SDP traffic is synchronous request/response and
                // RFCOMM DLCs have their own peek; neither stages
                // on the channel itself.
                ChannelService::Sdp | ChannelService::Rfcomm(_) => false,
            },
        }
    }

    /// Tear down the open channel (`handle`, `local_cid`): release
    /// the socket claim, remove the channel, and send the peer a
    /// Disconnection Request on the connection's signalling CID.
    /// `false` when no such channel exists. The peer's own
    /// Disconnection Request takes the same path through
    /// `answer_*_signalling`, which also releases the claim.
    pub fn disconnect_channel(&mut self, handle: u16, local_cid: u16) -> bool {
        let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) else {
            return false;
        };
        let Some(pos) = self.connections[conn_idx].channel_pos(local_cid) else {
            return false;
        };
        let (peer_cid, le) = {
            let ch = &self.connections[conn_idx].channels[pos];
            (ch.peer_cid(), self.connections[conn_idx].le)
        };
        self.connections[conn_idx].channels.remove(pos);
        self.release_claims(handle, local_cid);
        let cmd = l2cap::build_disconnection_request(0, peer_cid, local_cid);
        let mut payload = Vec::new();
        cmd.encode(&mut payload);
        let cid = if le {
            CID_LE_SIGNALLING
        } else {
            CID_SIGNALLING
        };
        self.queue_frame(handle, le, &BFrame::new(cid, payload));
        self.flush_acl();
        true
    }

    /// Claim the oldest unclaimed RFCOMM DLC opened by a peer to
    /// server `channel`: the peer (mux initiator) opens DLCI
    /// `2*channel+1` per TS 07.10 §5.4; the match is lenient on the
    /// direction bit (`dlci >> 1 == channel`) because the session
    /// mirrors any DLCI and the DLCI space partitions by server
    /// channel either way. Returns (ACL handle, local CID, peer
    /// CID, DLCI, peer address).
    pub fn take_pending_rfcomm(&mut self, channel: u8) -> Option<(u16, u16, u16, u8, [u8; 7])> {
        for conn in self.connections.iter() {
            for ch in conn.channels.iter() {
                let Channel::BrEdr(brch) = ch else {
                    continue;
                };
                let ChannelService::Rfcomm(session) = &brch.service else {
                    continue;
                };
                for dlci in session.open_dlcs() {
                    if dlci >> 1 == channel && !self.is_claimed(conn.handle, brch.local_cid, dlci) {
                        // The claim names the DLC, not the channel:
                        // the mux is shared, so a second server
                        // channel on the same L2CAP channel claims
                        // its own DLCI independently.
                        self.claimed.push((conn.handle, brch.local_cid, dlci));
                        return Some((
                            conn.handle,
                            brch.local_cid,
                            brch.peer_cid,
                            dlci,
                            conn.peer_addr,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Whether an unclaimed RFCOMM DLC to server `channel` is
    /// pending (non-consuming peek for poll/accept readiness).
    pub fn pending_rfcomm(&self, channel: u8) -> bool {
        for conn in self.connections.iter() {
            for ch in conn.channels.iter() {
                let Channel::BrEdr(brch) = ch else {
                    continue;
                };
                let ChannelService::Rfcomm(session) = &brch.service else {
                    continue;
                };
                if session
                    .open_dlcs()
                    .iter()
                    .any(|d| d >> 1 == channel && !self.is_claimed(conn.handle, brch.local_cid, *d))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Send one UIH frame on the open RFCOMM DLC (`handle`,
    /// `local_cid`, `dlci`). C/R follows the DLC's side (TS 07.10
    /// §5.1.1): initiator-opened DLCs (#1532) send C/R=1,
    /// responder-side DLCs C/R=0. Returns the bytes sent.
    pub fn send_rfcomm(
        &mut self,
        handle: u16,
        local_cid: u16,
        dlci: u8,
        payload: &[u8],
    ) -> Result<usize, BtSendError> {
        if payload.is_empty() {
            return Ok(0);
        }
        let conn_idx = match self.connections.iter().position(|c| c.handle == handle) {
            Some(i) => i,
            None => return Err(BtSendError::NoChannel),
        };
        let le = self.connections[conn_idx].le;
        let pos = match self.connections[conn_idx].channel_pos(local_cid) {
            Some(p) => p,
            None => return Err(BtSendError::NoChannel),
        };
        let (peer_cid, open, initiator) = match &self.connections[conn_idx].channels[pos] {
            Channel::BrEdr(ch) => match &ch.service {
                ChannelService::Rfcomm(session) => (
                    ch.peer_cid,
                    session.is_dlc_open(dlci),
                    session.is_dlc_initiator(dlci),
                ),
                _ => return Err(BtSendError::WrongService),
            },
            Channel::Le(_) => return Err(BtSendError::WrongService),
        };
        if !open {
            return Err(BtSendError::NoChannel);
        }
        let frame = crate::rfcomm::Frame::uih(dlci, initiator, payload.to_vec());
        self.queue_frame(handle, le, &BFrame::new(peer_cid, frame.encode()));
        self.flush_acl();
        Ok(payload.len())
    }

    /// Whether staged inbound data awaits on the open RFCOMM DLC
    /// (`handle`, `local_cid`, `dlci`) — non-consuming peek for poll.
    pub fn rfcomm_rx_pending(&self, handle: u16, local_cid: u16, dlci: u8) -> bool {
        let Some(conn) = self.connections.iter().find(|c| c.handle == handle) else {
            return false;
        };
        let Some(pos) = conn.channel_pos(local_cid) else {
            return false;
        };
        match &conn.channels[pos] {
            Channel::BrEdr(ch) => match &ch.service {
                ChannelService::Rfcomm(session) => session.rx_pending(dlci),
                _ => false,
            },
            Channel::Le(_) => false,
        }
    }

    /// Close the open RFCOMM DLC (`handle`, `local_cid`, `dlci`)
    /// from our side: forget the DLC in the session and send the
    /// peer a DISC (C/R follows the DLC's side — 1 for
    /// initiator-opened DLCs, 0 for responder-side ones). The L2CAP
    /// channel (shared mux) survives, as do its other DLCs. `false`
    /// when no such channel/DLC exists.
    pub fn close_rfcomm_dlc(&mut self, handle: u16, local_cid: u16, dlci: u8) -> bool {
        let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) else {
            return false;
        };
        let Some(pos) = self.connections[conn_idx].channel_pos(local_cid) else {
            return false;
        };
        let (peer_cid, le, was_open, initiator) =
            match &mut self.connections[conn_idx].channels[pos] {
                Channel::BrEdr(ch) => match &mut ch.service {
                    ChannelService::Rfcomm(session) => {
                        let was_open = session.is_dlc_open(dlci);
                        let initiator = session.is_dlc_initiator(dlci);
                        session.close_dlc(dlci);
                        (
                            ch.peer_cid,
                            self.connections[conn_idx].le,
                            was_open,
                            initiator,
                        )
                    }
                    _ => return false,
                },
                Channel::Le(_) => return false,
            };
        if !was_open {
            return false;
        }
        self.release_dlc_claim(handle, local_cid, dlci);
        let frame = crate::rfcomm::Frame::disc(dlci, initiator);
        self.queue_frame(handle, le, &BFrame::new(peer_cid, frame.encode()));
        self.flush_acl();
        true
    }

    /// Drain staged SDUs/payloads for an LE COC or generic BR/EDR
    /// channel. Returns None when no such connection/channel
    /// exists; an SDP channel drains as an empty vec (its traffic
    /// is synchronous request/response, never staged), as does an
    /// RFCOMM channel (use [`drain_rfcomm_rx`] for its DLCs).
    pub fn drain_channel_rx(&mut self, handle: u16, cid: u16) -> Option<Vec<Vec<u8>>> {
        let conn = self.connection_mut(handle)?;
        let pos = conn.channel_pos(cid)?;
        match &mut conn.channels[pos] {
            Channel::Le(ch) => Some(ch.take_rx()),
            Channel::BrEdr(ch) => match &mut ch.service {
                ChannelService::Generic { rx } => Some(core::mem::take(rx)),
                ChannelService::Sdp | ChannelService::Rfcomm(_) => Some(Vec::new()),
            },
        }
    }

    /// Drain staged UIH payloads for one RFCOMM DLCI on a channel.
    /// Returns None when no such connection/channel exists.
    pub fn drain_rfcomm_rx(&mut self, handle: u16, cid: u16, dlci: u8) -> Option<Vec<Vec<u8>>> {
        let conn = self.connection_mut(handle)?;
        let pos = conn.channel_pos(cid)?;
        match &mut conn.channels[pos] {
            Channel::BrEdr(ch) => match &mut ch.service {
                ChannelService::Rfcomm(session) => Some(session.drain_rx(dlci)),
                _ => Some(Vec::new()),
            },
            _ => Some(Vec::new()),
        }
    }

    // ── Outbound channel-open client (issue #1532) ───────────────
    //
    // `connect()` from our side: LE credit-based Connection Request
    // initiation (+ credit flow), BR/EDR Connection Request
    // initiation, and RFCOMM session/DLC establishment initiated by
    // us (SABM on DLCI 0, then DLC open). The socket layer polls
    // `connect_outbound` until the open completes or fails; the
    // pump drives the record from HCI events (ACL establishment)
    // and signalling responses. SCO connect is NOT here (#817).

    /// Next signalling identifier for an outbound request. 0 is
    /// never issued (it marks commands that expect no response);
    /// the counter cycles 1..=255.
    fn next_signal_ident(&mut self) -> u8 {
        self.next_signal_ident = self.next_signal_ident.wrapping_add(1);
        if self.next_signal_ident == 0 {
            self.next_signal_ident = 1;
        }
        self.next_signal_ident
    }

    /// Start (or poll) an outbound open to `peer` (`psm` is the
    /// LE/BR-EDR PSM, or the RFCOMM server channel when `rfcomm`).
    /// The first call starts the open and reports `Pending`; later
    /// calls report the live state, and `Open`/`Refused`/`Failed`
    /// consume the record — a second poll after one finds nothing
    /// pending. `Busy` means nothing was started (retry the call).
    pub fn connect_outbound(
        &mut self,
        peer: [u8; 7],
        psm: u16,
        le: bool,
        rfcomm: bool,
    ) -> BtConnectStatus {
        // A connect() retry while one is in flight (or after it
        // finished) polls the live record.
        if let Some(pos) = self
            .outbound
            .iter()
            .position(|o| o.matches(peer, psm, le, rfcomm))
        {
            // A record whose link is gone can never complete: the
            // Disconnection Complete hook marks these Failed, but a
            // handle-reuse race is closed here as well.
            let stale = {
                let rec = &self.outbound[pos];
                rec.handle != 0 && !self.connections.iter().any(|c| c.handle == rec.handle)
            };
            if stale {
                self.outbound[pos].state = OutboundState::Failed;
            }
            return self.take_outbound_status(pos, rfcomm);
        }
        // Validate before starting anything: RFCOMM is BR/EDR-only
        // on server channels 1..=30; L2CAP needs a non-zero PSM.
        let kind = if rfcomm {
            if le || psm == 0 || psm > 30 {
                return BtConnectStatus::Failed;
            }
            OutboundKind::Rfcomm { channel: psm as u8 }
        } else if psm == 0 {
            return BtConnectStatus::Failed;
        } else if le {
            OutboundKind::LeCoc { psm }
        } else {
            OutboundKind::BrEdr { psm }
        };
        // A live ACL to the peer takes the channel-open exchange
        // straight away; otherwise the HCI link is established
        // first and the exchange follows on Connection Complete.
        if let Some(handle) = self
            .connections
            .iter()
            .find(|c| c.peer_addr == peer && c.le == le)
            .map(|c| c.handle)
        {
            self.outbound.push(OutboundOpen::new(peer, kind));
            let pos = self.outbound.len() - 1;
            self.outbound[pos].handle = handle;
            self.advance_outbound(pos);
            return self.take_outbound_status(pos, rfcomm);
        }
        let mut addr6 = [0u8; 6];
        addr6.copy_from_slice(&peer[1..7]);
        if le {
            let peer_type = if peer[0] == 2 {
                gap::PeerAddressType::Random
            } else {
                gap::PeerAddressType::Public
            };
            match self.central_connect(peer_type, addr6) {
                Ok(()) => {}
                Err(CentralError::WrongPhase) | Err(CentralError::Transport) => {
                    return BtConnectStatus::Busy;
                }
                Err(_) => return BtConnectStatus::Failed,
            }
        } else {
            match self.classic_connect(addr6) {
                Ok(()) => {}
                Err(ClassicError::UnknownPeer) => {
                    return BtConnectStatus::UnknownPeer;
                }
                Err(ClassicError::WrongPhase) | Err(ClassicError::Transport) => {
                    return BtConnectStatus::Busy;
                }
                Err(_) => return BtConnectStatus::Failed,
            }
        }
        self.outbound.push(OutboundOpen::new(peer, kind));
        BtConnectStatus::Pending
    }

    /// Whether an outbound open to `peer` has completed and is
    /// ready to take (non-consuming peek for poll writability).
    pub fn connect_outbound_ready(&self, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
        self.outbound
            .iter()
            .any(|o| o.matches(peer, psm, le, rfcomm) && o.state == OutboundState::Open)
    }

    /// Abandon an in-flight outbound open to `peer` (socket close):
    /// drop the record and tear down any half-opened channel, so no
    /// half-open channel survives the socket that asked for it.
    /// `false` when nothing is in flight.
    pub fn cancel_outbound(&mut self, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
        let Some(pos) = self
            .outbound
            .iter()
            .position(|o| o.matches(peer, psm, le, rfcomm))
        else {
            return false;
        };
        let rec = self.outbound.remove(pos);
        if rec.local_cid == 0 || rec.handle == 0 {
            return true;
        }
        if rfcomm && rec.dlci != 0 {
            // DLC open: close it; the shared mux survives.
            self.close_rfcomm_dlc(rec.handle, rec.local_cid, rec.dlci);
        } else if rfcomm {
            // Mux channel, no DLC yet: drop it only when nothing
            // uses it — a peer-opened mux (or one serving peer
            // DLCs) stays for its owner.
            let drop_mux = match self
                .connections
                .iter()
                .find(|c| c.handle == rec.handle)
                .and_then(|c| c.channels.iter().find(|ch| ch.local_cid() == rec.local_cid))
            {
                Some(Channel::BrEdr(ch)) => match &ch.service {
                    ChannelService::Rfcomm(session) => {
                        session.open_dlcs().is_empty() && !session.is_mux_open()
                    }
                    _ => false,
                },
                _ => false,
            };
            if drop_mux {
                self.disconnect_channel(rec.handle, rec.local_cid);
            }
        } else {
            // A client-opened L2CAP channel is ours alone.
            self.disconnect_channel(rec.handle, rec.local_cid);
        }
        true
    }

    /// Report (and consume, when terminal) one outbound record's
    /// state. `Open`/`Refused`/`Failed` remove the record; any
    /// other state reports `Pending` and keeps it.
    fn take_outbound_status(&mut self, pos: usize, rfcomm: bool) -> BtConnectStatus {
        match self.outbound[pos].state {
            OutboundState::Open => {
                let rec = self.outbound.remove(pos);
                if rfcomm {
                    BtConnectStatus::OpenRfcomm((
                        rec.handle,
                        rec.local_cid,
                        rec.peer_cid,
                        rec.dlci,
                        rec.peer,
                    ))
                } else {
                    BtConnectStatus::Open((rec.handle, rec.local_cid, rec.peer_cid, rec.peer))
                }
            }
            OutboundState::Refused(result) => {
                self.outbound.remove(pos);
                BtConnectStatus::Refused(result)
            }
            OutboundState::Failed => {
                self.outbound.remove(pos);
                BtConnectStatus::Failed
            }
            _ => BtConnectStatus::Pending,
        }
    }

    /// Drive one outbound record whose ACL link exists: send the
    /// channel-open request (or the RFCOMM SABM, reusing a live mux
    /// when one exists). Called from `connect_outbound` and from
    /// the Connection Complete hooks.
    fn advance_outbound(&mut self, pos: usize) {
        let (kind, handle) = {
            let rec = &self.outbound[pos];
            (rec.kind, rec.handle)
        };
        let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) else {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        };
        let le = self.connections[conn_idx].le;
        match kind {
            OutboundKind::LeCoc { psm } => {
                let Some(local_cid) = self.connections[conn_idx].cid_alloc.alloc_le() else {
                    self.outbound[pos].state = OutboundState::Failed;
                    return;
                };
                let ident = self.next_signal_ident();
                let cmd = l2cap::build_le_credit_based_connection_request(
                    ident,
                    psm,
                    local_cid,
                    LE_COC_MTU,
                    LE_COC_MPS,
                    LE_COC_INITIAL_CREDITS,
                );
                let mut payload = Vec::new();
                cmd.encode(&mut payload);
                self.queue_frame(handle, le, &BFrame::new(CID_LE_SIGNALLING, payload));
                let rec = &mut self.outbound[pos];
                rec.ident = ident;
                rec.local_cid = local_cid;
                rec.state = OutboundState::RequestSent;
            }
            OutboundKind::BrEdr { psm } => {
                let Some(local_cid) = self.connections[conn_idx].cid_alloc.alloc_bredr() else {
                    self.outbound[pos].state = OutboundState::Failed;
                    return;
                };
                // The BR/EDR allocator wraps without tracking the
                // open set: refuse rather than alias an open channel.
                if self.connections[conn_idx].channel_pos(local_cid).is_some() {
                    self.outbound[pos].state = OutboundState::Failed;
                    return;
                }
                let ident = self.next_signal_ident();
                let cmd = l2cap::build_connection_request(ident, psm, local_cid);
                let mut payload = Vec::new();
                cmd.encode(&mut payload);
                self.queue_frame(handle, le, &BFrame::new(CID_SIGNALLING, payload));
                let rec = &mut self.outbound[pos];
                rec.ident = ident;
                rec.local_cid = local_cid;
                rec.state = OutboundState::RequestSent;
            }
            OutboundKind::Rfcomm { .. } => {
                self.advance_outbound_rfcomm(pos, conn_idx);
            }
        }
    }

    /// RFCOMM leg of [`Self::advance_outbound`]: reuse a live mux
    /// channel on this link when one exists (SABM on DLCI 0), or
    /// open the mux (BR/EDR Connection Request to PSM 0x0003)
    /// first and SABM once it opens.
    fn advance_outbound_rfcomm(&mut self, pos: usize, conn_idx: usize) {
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        let mux = self.connections[conn_idx]
            .channels
            .iter()
            .find_map(|c| match c {
                Channel::BrEdr(ch)
                    if ch.psm == l2cap::PSM_RFCOMM
                        && matches!(ch.service, ChannelService::Rfcomm(_)) =>
                {
                    Some((ch.local_cid, ch.peer_cid))
                }
                _ => None,
            });
        match mux {
            Some((local_cid, peer_cid)) => {
                // Initiator SABM on DLCI 0 (C/R=1, TS 07.10 §5.1.1).
                let frame = crate::rfcomm::Frame::sabm(0, true);
                self.queue_frame(handle, le, &BFrame::new(peer_cid, frame.encode()));
                let rec = &mut self.outbound[pos];
                rec.local_cid = local_cid;
                rec.peer_cid = peer_cid;
                rec.state = OutboundState::MuxSabmSent;
            }
            None => {
                let Some(local_cid) = self.connections[conn_idx].cid_alloc.alloc_bredr() else {
                    self.outbound[pos].state = OutboundState::Failed;
                    return;
                };
                if self.connections[conn_idx].channel_pos(local_cid).is_some() {
                    self.outbound[pos].state = OutboundState::Failed;
                    return;
                }
                let ident = self.next_signal_ident();
                let cmd = l2cap::build_connection_request(ident, l2cap::PSM_RFCOMM, local_cid);
                let mut payload = Vec::new();
                cmd.encode(&mut payload);
                self.queue_frame(handle, le, &BFrame::new(CID_SIGNALLING, payload));
                let rec = &mut self.outbound[pos];
                rec.ident = ident;
                rec.local_cid = local_cid;
                rec.state = OutboundState::RequestSent;
            }
        }
    }

    /// Drive outbound opens waiting on the ACL link `handle` to
    /// `peer`: a fresh link replaces any stale record for the
    /// handle (its channel died with the old link), then
    /// `AclPending` records for the peer send their open request.
    fn advance_outbound_on_acl(&mut self, handle: u16, peer: [u8; 7], le: bool) {
        for rec in self.outbound.iter_mut() {
            if rec.handle == handle && rec.state != OutboundState::AclPending {
                rec.state = OutboundState::Failed;
            }
        }
        let mut pos = 0;
        while pos < self.outbound.len() {
            let (pending, is_le, rec_peer) = {
                let rec = &self.outbound[pos];
                (
                    rec.state == OutboundState::AclPending,
                    matches!(rec.kind, OutboundKind::LeCoc { .. }),
                    rec.peer,
                )
            };
            if pending && is_le == le && rec_peer == peer {
                self.outbound[pos].handle = handle;
                self.advance_outbound(pos);
            }
            pos += 1;
        }
    }

    /// Fail every outbound open still waiting on an ACL link of
    /// this transport: the HCI initiation was refused (Command
    /// Status or a failed deferred issue), so no link — and no
    /// channel request — will ever arrive for them.
    fn fail_outbound_acl_pending(&mut self, le: bool) {
        for rec in self.outbound.iter_mut() {
            if rec.state == OutboundState::AclPending {
                let is_le = matches!(rec.kind, OutboundKind::LeCoc { .. });
                if is_le == le {
                    rec.state = OutboundState::Failed;
                }
            }
        }
    }

    /// Fail every outbound record on `handle`: the link is gone, so
    /// a pending open can never complete and a completed one lost
    /// its channel. The socket polls the failure once.
    fn fail_outbound_for_handle(&mut self, handle: u16) {
        for rec in self.outbound.iter_mut() {
            if rec.handle == handle {
                rec.state = OutboundState::Failed;
            }
        }
    }

    /// Fail an outbound open that already created its channel
    /// (BR/EDR `Configuring`, or an RFCOMM mux open): remove the
    /// channel, tell the peer with a Disconnection Request, and
    /// mark the record with the terminal state.
    fn fail_outbound_open(&mut self, pos: usize, terminal: OutboundState) {
        let (handle, local_cid, peer_cid) = {
            let rec = &self.outbound[pos];
            (rec.handle, rec.local_cid, rec.peer_cid)
        };
        let le = self
            .connections
            .iter()
            .find(|c| c.handle == handle)
            .map(|c| c.le);
        if local_cid != 0 {
            if let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) {
                if let Some(ch_pos) = self.connections[conn_idx].channel_pos(local_cid) {
                    self.connections[conn_idx].channels.remove(ch_pos);
                }
            }
            self.release_claims(handle, local_cid);
            if peer_cid != 0 {
                if let Some(le) = le {
                    let cmd = l2cap::build_disconnection_request(0, peer_cid, local_cid);
                    let mut payload = Vec::new();
                    cmd.encode(&mut payload);
                    self.queue_frame(handle, le, &BFrame::new(CID_SIGNALLING, payload));
                }
            }
        }
        self.outbound[pos].state = terminal;
    }

    /// Answer one LE Credit-Based Connection Response (§4.23) to our
    /// request: success creates the channel (claimed for the
    /// connecting socket); any other result is the peer's refusal.
    fn answer_le_coc_response(&mut self, conn_idx: usize, cmd: &l2cap::SignallingCommand) {
        let handle = self.connections[conn_idx].handle;
        let Some(pos) = self.outbound.iter().position(|o| {
            o.handle == handle
                && o.ident == cmd.identifier
                && o.state == OutboundState::RequestSent
                && matches!(o.kind, OutboundKind::LeCoc { .. })
        }) else {
            return;
        };
        // §4.23 response: Dest_CID + Source_CID + Result + MTU +
        // MPS + Initial_Credits = 12 bytes.
        let (dest_cid, source_cid, result, mtu, mps, credits) = if cmd.data.len() >= 12 {
            (
                u16::from_le_bytes([cmd.data[0], cmd.data[1]]),
                u16::from_le_bytes([cmd.data[2], cmd.data[3]]),
                u16::from_le_bytes([cmd.data[4], cmd.data[5]]),
                u16::from_le_bytes([cmd.data[6], cmd.data[7]]),
                u16::from_le_bytes([cmd.data[8], cmd.data[9]]),
                u16::from_le_bytes([cmd.data[10], cmd.data[11]]),
            )
        } else {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        };
        let (kind, local_cid) = {
            let rec = &self.outbound[pos];
            (rec.kind, rec.local_cid)
        };
        let OutboundKind::LeCoc { psm } = kind else {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        };
        // The response echoes our Source_CID; a mismatch is not
        // our open.
        if source_cid != local_cid {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        }
        if result != l2cap::LE_COC_RESULT_SUCCESS {
            self.outbound[pos].state = OutboundState::Refused(result);
            return;
        }
        // A success with unusable parameters cannot carry data.
        if mtu == 0 || mps == 0 {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        }
        self.connections[conn_idx]
            .channels
            .push(Channel::Le(LeCocChannel::new(
                local_cid, dest_cid, psm, mtu, mps, credits,
            )));
        // The channel is the connecting socket's from here: claim
        // it so accept can never steal it, and wake parked waiters.
        self.claimed.push((handle, local_cid, 0));
        let rec = &mut self.outbound[pos];
        rec.peer_cid = dest_cid;
        rec.state = OutboundState::Open;
        narf_filesystem::bluetooth::publish_bt_channel_event();
    }

    /// Answer one BR/EDR Connection Response (§4.3) to our
    /// request. Result 1 (pending) is not terminal — a second
    /// response with the same identifier follows. On success a
    /// plain channel goes to configuration, while an RFCOMM mux
    /// open goes straight to SABM on DLCI 0.
    fn answer_bredr_conn_response(&mut self, conn_idx: usize, cmd: &l2cap::SignallingCommand) {
        let handle = self.connections[conn_idx].handle;
        let Some(pos) = self.outbound.iter().position(|o| {
            o.handle == handle
                && o.ident == cmd.identifier
                && o.state == OutboundState::RequestSent
                && matches!(
                    o.kind,
                    OutboundKind::BrEdr { .. } | OutboundKind::Rfcomm { .. }
                )
        }) else {
            return;
        };
        // §4.3 response: Dest_CID + Source_CID + Result + Status
        // = 8 bytes.
        let (dest_cid, source_cid, result) = if cmd.data.len() >= 8 {
            (
                u16::from_le_bytes([cmd.data[0], cmd.data[1]]),
                u16::from_le_bytes([cmd.data[2], cmd.data[3]]),
                u16::from_le_bytes([cmd.data[4], cmd.data[5]]),
            )
        } else {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        };
        let (kind, local_cid) = {
            let rec = &self.outbound[pos];
            (rec.kind, rec.local_cid)
        };
        if source_cid != local_cid {
            self.outbound[pos].state = OutboundState::Failed;
            return;
        }
        if result == l2cap::CONN_RESULT_PENDING {
            return;
        }
        if result != l2cap::CONN_RESULT_SUCCESS {
            self.outbound[pos].state = OutboundState::Refused(result);
            return;
        }
        let le = self.connections[conn_idx].le;
        match kind {
            OutboundKind::BrEdr { psm } => {
                self.connections[conn_idx]
                    .channels
                    .push(Channel::BrEdr(BrEdrChannel::new(
                        local_cid,
                        dest_cid,
                        psm,
                        ServerKind::Generic,
                    )));
                // Configuration follows the connection (§4.4): the
                // channel opens once the peer accepts it.
                let ident2 = self.next_signal_ident();
                let cmd = l2cap::build_configure_request(ident2, dest_cid, false, &[]);
                let mut payload = Vec::new();
                cmd.encode(&mut payload);
                self.queue_frame(handle, le, &BFrame::new(CID_SIGNALLING, payload));
                let rec = &mut self.outbound[pos];
                rec.peer_cid = dest_cid;
                rec.ident2 = ident2;
                rec.state = OutboundState::Configuring;
            }
            OutboundKind::Rfcomm { .. } => {
                self.connections[conn_idx]
                    .channels
                    .push(Channel::BrEdr(BrEdrChannel::new(
                        local_cid,
                        dest_cid,
                        l2cap::PSM_RFCOMM,
                        ServerKind::Rfcomm,
                    )));
                // The mux is open: SABM on DLCI 0 (initiator,
                // C/R=1) starts the RFCOMM session.
                let frame = crate::rfcomm::Frame::sabm(0, true);
                self.queue_frame(handle, le, &BFrame::new(dest_cid, frame.encode()));
                let rec = &mut self.outbound[pos];
                rec.peer_cid = dest_cid;
                rec.state = OutboundState::MuxSabmSent;
            }
            OutboundKind::LeCoc { .. } => {
                self.outbound[pos].state = OutboundState::Failed;
            }
        }
    }

    /// Answer one BR/EDR Configure Response (§4.5) to our
    /// Configure Request: success opens the channel (claimed for
    /// the connecting socket); a refusal tears the channel down
    /// and reports the peer's result code.
    fn answer_bredr_config_response(&mut self, conn_idx: usize, cmd: &l2cap::SignallingCommand) {
        let handle = self.connections[conn_idx].handle;
        let Some(pos) = self.outbound.iter().position(|o| {
            o.handle == handle
                && o.ident2 == cmd.identifier
                && o.state == OutboundState::Configuring
                && matches!(o.kind, OutboundKind::BrEdr { .. })
        }) else {
            return;
        };
        // §4.5 response: Source_CID(2) Flags(2) Result(2). The
        // source is the CID the request named — the peer's CID.
        let (source_cid, result) = if cmd.data.len() >= 6 {
            (
                u16::from_le_bytes([cmd.data[0], cmd.data[1]]),
                u16::from_le_bytes([cmd.data[4], cmd.data[5]]),
            )
        } else {
            self.fail_outbound_open(pos, OutboundState::Failed);
            return;
        };
        let (local_cid, peer_cid) = {
            let rec = &self.outbound[pos];
            (rec.local_cid, rec.peer_cid)
        };
        if source_cid != peer_cid {
            self.fail_outbound_open(pos, OutboundState::Failed);
            return;
        }
        if result != 0 {
            self.fail_outbound_open(pos, OutboundState::Refused(result));
            return;
        }
        if let Some(ch_pos) = self.connections[conn_idx].channel_pos(local_cid) {
            if let Channel::BrEdr(ch) = &mut self.connections[conn_idx].channels[ch_pos] {
                ch.configured = true;
            }
        }
        self.claimed.push((handle, local_cid, 0));
        self.outbound[pos].state = OutboundState::Open;
        narf_filesystem::bluetooth::publish_bt_channel_event();
    }

    /// Drive one intercepted RFCOMM UA/DM (#1532): the peer's
    /// answer to our SABM. UA on DLCI 0 opens the mux and sends
    /// the DLC SABM; UA on the target DLCI opens the DLC; DM
    /// refuses either leg.
    fn answer_outbound_rfcomm_frame(&mut self, handle: u16, le: bool, fr: crate::rfcomm::Frame) {
        use crate::rfcomm::{FRAME_DM, FRAME_UA};
        let Some(pos) = self.outbound.iter().position(|o| {
            o.handle == handle
                && match o.state {
                    OutboundState::MuxSabmSent => fr.dlci == 0,
                    OutboundState::DlcSabmSent => fr.dlci == o.dlci,
                    _ => false,
                }
        }) else {
            return;
        };
        let (state, kind, local_cid, peer_cid) = {
            let rec = &self.outbound[pos];
            (rec.state, rec.kind, rec.local_cid, rec.peer_cid)
        };
        match (state, fr.frame_type) {
            (OutboundState::MuxSabmSent, FRAME_UA) => {
                let OutboundKind::Rfcomm { channel } = kind else {
                    self.outbound[pos].state = OutboundState::Failed;
                    return;
                };
                // Mark the mux open in the session, then SABM the
                // target DLCI (initiator DLCI 2*channel+1, C/R=1).
                if let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) {
                    if let Some(ch_pos) = self.connections[conn_idx].channel_pos(local_cid) {
                        if let Channel::BrEdr(ch) = &mut self.connections[conn_idx].channels[ch_pos]
                        {
                            if let ChannelService::Rfcomm(session) = &mut ch.service {
                                session.mux_opened();
                            }
                        }
                    }
                }
                let dlci = 2 * channel + 1;
                let sabm = crate::rfcomm::Frame::sabm(dlci, true);
                self.queue_frame(handle, le, &BFrame::new(peer_cid, sabm.encode()));
                let rec = &mut self.outbound[pos];
                rec.dlci = dlci;
                rec.state = OutboundState::DlcSabmSent;
            }
            (OutboundState::MuxSabmSent, FRAME_DM) => {
                self.outbound[pos].state = OutboundState::Failed;
            }
            (OutboundState::DlcSabmSent, FRAME_UA) => {
                if let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) {
                    if let Some(ch_pos) = self.connections[conn_idx].channel_pos(local_cid) {
                        if let Channel::BrEdr(ch) = &mut self.connections[conn_idx].channels[ch_pos]
                        {
                            if let ChannelService::Rfcomm(session) = &mut ch.service {
                                session.dlc_opened(fr.dlci);
                            }
                        }
                    }
                }
                self.claimed.push((handle, local_cid, fr.dlci));
                self.outbound[pos].state = OutboundState::Open;
                narf_filesystem::bluetooth::publish_bt_channel_event();
            }
            (OutboundState::DlcSabmSent, FRAME_DM) => {
                self.outbound[pos].state = OutboundState::Failed;
            }
            _ => {}
        }
    }

    // ── SCO socket backend (issue #814) ─────────────────────────────

    /// SCO MTU for send: the controller's Read Buffer Size SCO MTU,
    /// 60 when bring-up left it unset (Linux `sco_conn_add`).
    fn sco_mtu(&self) -> u16 {
        if self.info.sco_data_mtu > 0 {
            u16::from(self.info.sco_data_mtu)
        } else {
            60
        }
    }

    /// Peer class of device from the classic peer table (inquiry
    /// result); zeros when the peer was never discovered.
    fn sco_peer_class(&self, peer: &[u8; 6]) -> [u8; 3] {
        self.classic
            .peer(peer)
            .map(|p| p.class_of_device)
            .unwrap_or([0; 3])
    }

    /// ACL handle of the live BR/EDR connection to `peer`, if any.
    fn acl_handle_for_peer(&self, peer: &[u8; 6]) -> Option<u16> {
        self.connections
            .iter()
            .find(|c| !c.le && c.peer_addr[1..7] == *peer)
            .map(|c| c.handle)
    }

    /// Issue HCI_Setup_Synchronous_Connection (§7.1.26) on `handle`
    /// with the socket's voice setting. Bandwidth 8 kHz both ways,
    /// latency don't-care, retransmission effort 0x02 (HFP CVSD
    /// preferred), all SCO+eSCO packet types
    /// (`ESCO_PACKET_TYPES_ALL` — the in-tree generic default).
    fn issue_setup_sync(&mut self, handle: u16, voice_setting: u16) -> Result<(), TransportError> {
        let cmd = classic::build_setup_synchronous_connection(
            handle,
            classic::SCO_BANDWIDTH_8KHZ,
            classic::SCO_BANDWIDTH_8KHZ,
            0xFFFF,
            voice_setting,
            0x02,
            classic::ESCO_PACKET_TYPES_ALL,
        );
        self.send_command_obj(&cmd)
    }

    /// Consume a recorded terminal failure for `peer`'s pending
    /// setup, clearing the pending slot. `None` when no failed
    /// setup for this peer exists.
    fn take_pending_sco_failure(&mut self, peer: [u8; 6]) -> Option<BtScoConnectResult> {
        if self
            .pending_sco
            .as_ref()
            .is_some_and(|p| p.peer == peer && p.failed.is_some())
        {
            let pending = self.pending_sco.take().unwrap();
            return pending.failed;
        }
        None
    }

    /// Record a terminal failure on the in-flight SCO setup (at most
    /// one setup runs per controller) and publish a channel event so
    /// a parked connect(2) wakes and re-polls. No-op when no setup
    /// is in flight or one already failed.
    fn fail_pending_sco(&mut self, result: BtScoConnectResult) {
        if let Some(pending) = self.pending_sco.as_mut() {
            if pending.failed.is_none() {
                pending.failed = Some(result);
                narf_filesystem::bluetooth::publish_bt_channel_event();
            }
        }
    }

    /// Record a terminal HCI-status failure on the in-flight setup.
    fn fail_pending_sco_status(&mut self, status: u8) {
        self.fail_pending_sco(BtScoConnectResult::Refused(status));
    }

    /// The ACL to `peer` just came up: if an outbound SCO setup is
    /// waiting on its page, issue Setup Synchronous Connection on
    /// the new handle. A refused command fails the setup.
    fn maybe_issue_pending_sco_setup(&mut self, peer: &[u8; 6], handle: u16) {
        let Some(pending) = &self.pending_sco else {
            return;
        };
        if pending.peer != *peer || pending.setup_sent || pending.failed.is_some() {
            return;
        }
        let voice_setting = pending.voice_setting;
        match self.issue_setup_sync(handle, voice_setting) {
            Ok(()) => {
                if let Some(pending) = self.pending_sco.as_mut() {
                    pending.acl_handle = Some(handle);
                    pending.setup_sent = true;
                }
            }
            Err(_) => self.fail_pending_sco(BtScoConnectResult::Transport),
        }
    }

    /// Complete an outbound SCO setup on Synchronous Connection
    /// Complete (§7.7.35). Status 0 with a matching pending setup
    /// records the link (claimed by the socket's status poll); a
    /// refusal fails the pending setup. A completion with no
    /// matching pending setup (the socket cancelled mid-flight, or
    /// a peer-initiated link) still records an unclaimed link — a
    /// later `sco_connect` to that peer claims it.
    fn on_sync_connection_complete(&mut self, sc: SyncConnectionComplete) {
        let pending_matches = self
            .pending_sco
            .as_ref()
            .is_some_and(|p| p.peer == sc.bd_addr && p.setup_sent && p.failed.is_none());
        if sc.status != 0 {
            if self
                .pending_sco
                .as_ref()
                .is_some_and(|p| p.peer == sc.bd_addr && p.setup_sent)
            {
                self.fail_pending_sco_status(sc.status);
            }
            return;
        }
        let Some(acl_handle) = self.acl_handle_for_peer(&sc.bd_addr) else {
            // No ACL to attribute it to (it died between the setup
            // and the completion) — nothing to stage it on.
            return;
        };
        // Voice setting the link was opened with: the pending setup's
        // BT_VOICE when this completion answers our outbound setup.
        // Synchronous Connection Complete carries no voice setting,
        // so a peer-initiated link (no matching pending setup)
        // records the CVSD default — the same default a socket
        // starts with.
        let voice_setting = self
            .pending_sco
            .as_ref()
            .filter(|_| pending_matches)
            .map_or(classic::SCO_VOICE_SETTING_CVSD, |p| p.voice_setting);
        if pending_matches {
            self.pending_sco = None;
        }
        if self.sco_links.iter().any(|l| l.handle == sc.handle) {
            return;
        }
        self.sco_links.push(ScoLink {
            handle: sc.handle,
            acl_handle,
            peer: sc.bd_addr,
            voice_setting,
            tx_packet_length: sc.tx_packet_length,
            rx_packet_length: sc.rx_packet_length,
            mtu: self.sco_mtu(),
            dev_class: self.sco_peer_class(&sc.bd_addr),
            rx: VecDeque::new(),
            claimed: false,
        });
        narf_filesystem::bluetooth::publish_bt_channel_event();
    }

    /// Drop every SCO link riding ACL `handle`, and the link whose
    /// own SCO handle is `handle` (a peer-torn-down synchronous
    /// link). The socket layer learns on its next send/recv
    /// (NotConnected) — the same staleness the L2CAP channel path
    /// has for a dead channel.
    fn drop_sco_links_for_handle(&mut self, handle: u16) {
        self.sco_links
            .retain(|l| l.handle != handle && l.acl_handle != handle);
    }

    /// Route one decoded SCO frame to its link's staging, dropping
    /// frames for unknown handles (stale controller frames after a
    /// link went away). The packet-status flag (§5.4.3) is not
    /// staged: Linux delivers it as ancillary data
    /// (`BT_SCM_PKT_STATUS`), never as payload, and NARF has no BT
    /// ancillary-data path yet — a frame with a nonzero status
    /// still delivers its payload.
    fn route_sco(&mut self, frame: ScoData) -> bool {
        let Some(link) = self.sco_links.iter_mut().find(|l| l.handle == frame.handle) else {
            return false;
        };
        link.rx.push_back(frame.data);
        true
    }

    /// Start an outbound SCO setup to `peer` (issue #814). When an
    /// ACL connection to the peer already exists the Setup Sync
    /// command goes out immediately; otherwise the peer is paged
    /// first (it must have been discovered — `classic_connect`
    /// refuses an unknown peer rather than paging blind) and the
    /// setup follows on Connection Complete. `Connected` only when
    /// a link to this peer already exists and is unclaimed.
    pub fn sco_connect(&mut self, peer: [u8; 6], voice_setting: u16) -> BtScoConnectResult {
        if let Some(failed) = self.take_pending_sco_failure(peer) {
            return failed;
        }
        if let Some(link) = self.sco_links.iter_mut().find(|l| l.peer == peer) {
            if link.claimed {
                return BtScoConnectResult::AlreadyConnected;
            }
            link.claimed = true;
            return BtScoConnectResult::Connected {
                handle: link.handle,
                mtu: link.mtu,
                dev_class: link.dev_class,
            };
        }
        if let Some(pending) = &self.pending_sco {
            if pending.peer == peer {
                return BtScoConnectResult::Pending;
            }
            return BtScoConnectResult::Busy;
        }
        if let Some(handle) = self.acl_handle_for_peer(&peer) {
            if self.issue_setup_sync(handle, voice_setting).is_err() {
                return BtScoConnectResult::Busy;
            }
            self.pending_sco = Some(PendingSco {
                peer,
                voice_setting,
                acl_handle: Some(handle),
                setup_sent: true,
                failed: None,
            });
            return BtScoConnectResult::Pending;
        }
        match self.classic_connect(peer) {
            Ok(()) => {
                self.pending_sco = Some(PendingSco {
                    peer,
                    voice_setting,
                    acl_handle: None,
                    setup_sent: false,
                    failed: None,
                });
                BtScoConnectResult::Pending
            }
            Err(ClassicError::UnknownPeer) => BtScoConnectResult::UnknownPeer,
            Err(_) => BtScoConnectResult::Busy,
        }
    }

    /// Poll the outcome of an outbound SCO setup to `peer`:
    /// `Connected` claims the established link, `Pending` means
    /// still in flight, `Refused`/`Transport`/`Aborted` are
    /// terminal.
    pub fn sco_connect_status(&mut self, peer: [u8; 6]) -> BtScoConnectResult {
        if let Some(failed) = self.take_pending_sco_failure(peer) {
            return failed;
        }
        if let Some(link) = self
            .sco_links
            .iter_mut()
            .find(|l| l.peer == peer && !l.claimed)
        {
            link.claimed = true;
            return BtScoConnectResult::Connected {
                handle: link.handle,
                mtu: link.mtu,
                dev_class: link.dev_class,
            };
        }
        if self.sco_links.iter().any(|l| l.peer == peer) {
            return BtScoConnectResult::AlreadyConnected;
        }
        if self.pending_sco.as_ref().is_some_and(|p| p.peer == peer) {
            return BtScoConnectResult::Pending;
        }
        BtScoConnectResult::Aborted
    }

    /// Send one SCO frame on the open link (`handle`). A payload
    /// larger than the link MTU is TooBig (the socket layer reports
    /// EINVAL, per Linux `sco_send_frame`); a transport that cannot
    /// carry SCO data is Unsupported (EOPNOTSUPP, fail-closed).
    /// Frames go straight to the transport — SCO has no ACL-style
    /// flow control or queueing.
    pub fn send_sco(&mut self, handle: u16, payload: &[u8]) -> Result<usize, BtSendError> {
        if payload.is_empty() {
            return Ok(0);
        }
        let Some(link) = self.sco_links.iter().find(|l| l.handle == handle) else {
            return Err(BtSendError::NoChannel);
        };
        if payload.len() > link.mtu as usize {
            return Err(BtSendError::TooBig);
        }
        let frame = ScoData {
            handle,
            packet_status: 0,
            data: payload.to_vec(),
        };
        match self.transport.send_sco(&frame.encode()) {
            Ok(()) => Ok(payload.len()),
            Err(TransportError::Unsupported) => Err(BtSendError::Unsupported),
            Err(_) => Err(BtSendError::Busy),
        }
    }

    /// Drain staged inbound SCO payloads for the open link
    /// (`handle`). `None` when no such link exists.
    pub fn drain_sco_rx(&mut self, handle: u16) -> Option<Vec<Vec<u8>>> {
        let link = self.sco_links.iter_mut().find(|l| l.handle == handle)?;
        Some(link.rx.drain(..).collect())
    }

    /// Whether staged inbound SCO frames await on the open link
    /// (`handle`) — non-consuming peek for poll.
    pub fn sco_rx_pending(&self, handle: u16) -> bool {
        self.sco_links
            .iter()
            .find(|l| l.handle == handle)
            .is_some_and(|l| !l.rx.is_empty())
    }

    /// Tear down the open SCO link (`handle`): remove it and send
    /// the controller HCI_Disconnect on the SCO handle (reason 0x13
    /// Remote User Terminated Connection). `false` when no such
    /// link exists. The ACL connection itself survives — only the
    /// synchronous link goes away. (A shared host-initiated
    /// disconnect backend, #1527, may subsume this direct command
    /// later.)
    pub fn disconnect_sco(&mut self, handle: u16) -> bool {
        let Some(pos) = self.sco_links.iter().position(|l| l.handle == handle) else {
            return false;
        };
        self.sco_links.remove(pos);
        let params = gap::build_disconnect(handle, gap::DISCONNECT_REASON_REMOTE_USER);
        let _ = self.send_command(op::HCI_DISCONNECT, &params);
        true
    }

    /// Cancel an in-flight outbound SCO setup to `peer` (shutdown /
    /// Drop of a socket whose connect never completed). A page
    /// already in flight is left running; its Connection Complete
    /// lands a plain ACL connection and issues no SCO setup.
    pub fn cancel_sco_connect(&mut self, peer: [u8; 6]) {
        if self.pending_sco.as_ref().is_some_and(|p| p.peer == peer) {
            self.pending_sco = None;
        }
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

    /// Send a pre-built [`Command`] (the Classic builders return
    /// one) and count it like [`send_command`].
    fn send_command_obj(&mut self, cmd: &Command) -> Result<(), TransportError> {
        self.transport.send_command(cmd)?;
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

/// A deferred connection initiation, waiting on scan-disable
/// completion. The legacy (§7.8.12) and extended (§7.8.66) forms
/// share the same phase discipline; the enum keeps every site
/// that issues a deferred connect honest about both forms.
#[derive(Clone, Debug)]
enum PendingConnect {
    /// Legacy LE Create Connection (§7.8.12).
    Legacy(gap::CreateConnection),
    /// Extended LE Create Connection (§7.8.66).
    Extended(gap::ExtendedCreateConnection),
}

/// Errors from the GAP central initiator API (issue #1312).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CentralError {
    /// No pump registered for this controller index.
    NoPump,
    /// A pump step currently owns the core; retry after the step.
    Busy,
    /// The central state machine is in a phase that forbids this call.
    WrongPhase,
    /// The transport rejected the HCI command.
    Transport,
    /// The extended-create request cannot be encoded: no scanning
    /// PHY, an unsupported PHY bit, a missing per-PHY block, or an
    /// inverted interval / connection-event-length range (§7.8.66).
    BadParams,
    /// Advertising data or scan-response data exceeds the 251-byte
    /// extended maximum (§7.8.54).
    BadData,
}

impl PumpCore {
    /// Begin LE discovery: issue LE Set Scan Parameters (Vol 4 Part E
    /// §7.8.10). The follow-up LE Set Scan Enable(1) is issued from
    /// `dispatch_event` once the parameters complete successfully,
    /// so the controller never receives Enable before its parameters
    /// are accepted. Only from Idle.
    pub fn central_start_scan(&mut self, params: gap::ScanParameters) -> Result<(), CentralError> {
        if self.central.phase != CentralPhase::Idle {
            return Err(CentralError::WrongPhase);
        }
        self.send_command(op::HCI_LE_SET_SCAN_PARAMETERS, &params.encode())
            .map_err(|_| CentralError::Transport)?;
        self.central.note_parameters_sent();
        Ok(())
    }

    /// Stop LE discovery: issue LE Set Scan Enable(0) (§7.8.11).
    /// Only from Scanning; completion returns the phase to Idle.
    pub fn central_stop_scan(&mut self) -> Result<(), CentralError> {
        if self.central.phase != CentralPhase::Scanning {
            return Err(CentralError::WrongPhase);
        }
        self.send_command(
            op::HCI_LE_SET_SCAN_ENABLE,
            &gap::ScanEnable {
                enable: false,
                filter_duplicates: false,
            }
            .encode(),
        )
        .map_err(|_| CentralError::Transport)?;
        self.central.note_scan_stopping();
        self.pending_connect = None;
        Ok(())
    }

    /// Connect to a peer (§7.8.12). From Scanning this first issues
    /// Set_Scan_Enable(0) and defers LE_Create_Connection until the
    /// disable completes; from Idle it issues LE_Create_Connection
    /// directly. Forbidden while a setup is already in flight or a
    /// central connection is established.
    pub fn central_connect(
        &mut self,
        peer_address_type: gap::PeerAddressType,
        peer_address: [u8; 6],
    ) -> Result<(), CentralError> {
        match self.central.phase {
            CentralPhase::Scanning => {
                self.send_command(
                    op::HCI_LE_SET_SCAN_ENABLE,
                    &gap::ScanEnable {
                        enable: false,
                        filter_duplicates: false,
                    }
                    .encode(),
                )
                .map_err(|_| CentralError::Transport)?;
                self.pending_connect = Some(PendingConnect::Legacy(
                    gap::CreateConnection::to_peer(peer_address_type, peer_address),
                ));
                self.central.note_scan_stopping();
                Ok(())
            }
            CentralPhase::Idle => {
                let cc = gap::CreateConnection::to_peer(peer_address_type, peer_address);
                self.send_command(op::HCI_LE_CREATE_CONNECTION, &cc.encode())
                    .map_err(|_| CentralError::Transport)?;
                self.central.note_connecting();
                Ok(())
            }
            _ => Err(CentralError::WrongPhase),
        }
    }

    /// Connect to a peer with LE Extended Create Connection
    /// (§7.8.66). Same phase discipline as [`Self::central_connect`]:
    /// from Scanning the scan is disabled first and the extended
    /// create follows on the disable completion; from Idle it is
    /// issued directly. Forbidden while a setup is already in
    /// flight or a central connection is established. `BadParams`
    /// when the request cannot be encoded — the parameters are
    /// validated before anything is sent, so a malformed request
    /// never disables a scan in progress.
    pub fn central_connect_ext(
        &mut self,
        params: gap::ExtendedCreateConnection,
    ) -> Result<(), CentralError> {
        let encoded = params.encode().ok_or(CentralError::BadParams)?;
        match self.central.phase {
            CentralPhase::Scanning => {
                self.send_command(
                    op::HCI_LE_SET_SCAN_ENABLE,
                    &gap::ScanEnable {
                        enable: false,
                        filter_duplicates: false,
                    }
                    .encode(),
                )
                .map_err(|_| CentralError::Transport)?;
                self.pending_connect = Some(PendingConnect::Extended(params));
                self.central.note_scan_stopping();
                Ok(())
            }
            CentralPhase::Idle => {
                self.send_command(op::HCI_LE_EXTENDED_CREATE_CONNECTION, &encoded)
                    .map_err(|_| CentralError::Transport)?;
                self.central.note_connecting();
                Ok(())
            }
            _ => Err(CentralError::WrongPhase),
        }
    }

    /// Issue a deferred connection command taken from
    /// `pending_connect`; on any failure the phase returns to Idle
    /// rather than leaving a half-issued initiation behind.
    fn issue_pending_connect(&mut self, pending: PendingConnect) {
        let issued = match &pending {
            PendingConnect::Legacy(cc) => self
                .send_command(op::HCI_LE_CREATE_CONNECTION, &cc.encode())
                .is_ok(),
            PendingConnect::Extended(ecc) => match ecc.encode() {
                Some(params) => self
                    .send_command(op::HCI_LE_EXTENDED_CREATE_CONNECTION, &params)
                    .is_ok(),
                None => false,
            },
        };
        if issued {
            self.central.note_connecting();
        } else {
            self.central.phase = CentralPhase::Idle;
            // The deferred create never went out: any outbound
            // open waiting on it can never complete.
            self.fail_outbound_acl_pending(true);
        }
    }

    /// Advance the central state machine on a completed scan/connect
    /// command. Shared by the Command Complete and Command Status
    /// arms: scan commands return Complete, while Create Connection
    /// returns Status first and completes later via LE Connection
    /// Complete.
    fn on_central_command_done(&mut self, opcode: u16, status: u8) {
        match opcode {
            op::HCI_LE_SET_SCAN_PARAMETERS => {
                if self.central.phase == CentralPhase::ParametersSent {
                    if status == 0 {
                        // Parameters accepted: enable scanning now.
                        if self
                            .send_command(
                                op::HCI_LE_SET_SCAN_ENABLE,
                                &gap::ScanEnable {
                                    enable: true,
                                    filter_duplicates: false,
                                }
                                .encode(),
                            )
                            .is_ok()
                        {
                            self.central.note_scanning();
                        } else {
                            self.central.phase = CentralPhase::Idle;
                        }
                    } else {
                        self.central.phase = CentralPhase::Idle;
                    }
                }
            }
            op::HCI_LE_SET_SCAN_ENABLE => {
                if self.central.phase == CentralPhase::ScanStopping {
                    if status == 0 {
                        match self.pending_connect.take() {
                            Some(pending) => self.issue_pending_connect(pending),
                            None => self.central.phase = CentralPhase::Idle,
                        }
                    } else {
                        // Disable refused: drop the deferred connect
                        // rather than issue it against a controller
                        // that may still be scanning.
                        self.pending_connect = None;
                        self.central.phase = CentralPhase::Idle;
                    }
                }
            }
            // Legacy (§7.8.12) and extended (§7.8.66) creates both
            // return Command Status first and complete later via an
            // LE (Enhanced) Connection Complete subevent; a refused
            // status returns the phase to Idle in either case.
            op::HCI_LE_CREATE_CONNECTION | op::HCI_LE_EXTENDED_CREATE_CONNECTION => {
                if self.central.phase == CentralPhase::Connecting && status != 0 {
                    self.central.phase = CentralPhase::Idle;
                    // The controller refused the create: the link
                    // — and any outbound open waiting on it — is dead.
                    self.fail_outbound_acl_pending(true);
                }
            }
            _ => {}
        }
    }
}

// ── LE Periodic Advertising API (issue #1560) ───────────────────────

/// Errors from the periodic advertising API.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeriodicError {
    /// No pump registered for this controller index.
    NoPump,
    /// A pump step currently owns the core; retry after the step.
    Busy,
    /// The periodic advertiser / sync state machine is in a phase
    /// that forbids this call.
    WrongPhase,
    /// The transport rejected the HCI command.
    Transport,
    /// A parameter is outside its spec range (interval, data
    /// length, skip, timeout, CTE type).
    BadParameter,
}

impl PumpCore {
    /// Set periodic advertising parameters for a handle (§7.8.61).
    /// Callable any time; the handle becomes Configured only once
    /// the controller accepts the parameters (Command Complete).
    pub fn periodic_adv_set_parameters(
        &mut self,
        params: gap::PeriodicAdvertisingParameters,
    ) -> Result<(), PeriodicError> {
        if !params.is_valid() {
            return Err(PeriodicError::BadParameter);
        }
        self.send_command(
            op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS,
            &params.encode(),
        )
        .map_err(|_| PeriodicError::Transport)?;
        self.periodic_adv
            .note_parameters_sent(params.advertising_handle);
        Ok(())
    }

    /// Set periodic advertising data for a handle (§7.8.62). Only
    /// for the configured handle (Configured or Enabled); the
    /// controller rejects data for any other handle, so the pump
    /// refuses first. `data.len()` must be <= 251 and empty for the
    /// Unchanged operation.
    pub fn periodic_adv_set_data(
        &mut self,
        advertising_handle: u8,
        operation: gap::PeriodicAdvDataOperation,
        data: &[u8],
    ) -> Result<(), PeriodicError> {
        if self.periodic_adv.advertising_handle != Some(advertising_handle)
            || (self.periodic_adv.phase != PeriodicAdvertiserPhase::Configured
                && self.periodic_adv.phase != PeriodicAdvertiserPhase::Enabled)
        {
            return Err(PeriodicError::WrongPhase);
        }
        if data.len() > gap::PER_ADV_DATA_MAX_LEN
            || (operation == gap::PeriodicAdvDataOperation::Unchanged && !data.is_empty())
        {
            return Err(PeriodicError::BadParameter);
        }
        let params = gap::encode_periodic_adv_data(advertising_handle, operation, data);
        self.send_command(op::HCI_LE_SET_PERIODIC_ADVERTISING_DATA, &params)
            .map_err(|_| PeriodicError::Transport)?;
        Ok(())
    }

    /// Enable or disable the periodic advertising train (§7.8.63).
    /// Enable only from Configured, disable only from Enabled; the
    /// phase follows only once the controller accepts the command.
    pub fn periodic_adv_set_enable(&mut self, enable: bool) -> Result<(), PeriodicError> {
        let handle = match (enable, self.periodic_adv.phase) {
            (true, PeriodicAdvertiserPhase::Configured) => self.periodic_adv.advertising_handle,
            (false, PeriodicAdvertiserPhase::Enabled) => self.periodic_adv.advertising_handle,
            _ => return Err(PeriodicError::WrongPhase),
        };
        let handle = match handle {
            Some(h) => h,
            None => return Err(PeriodicError::WrongPhase),
        };
        self.send_command(
            op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE,
            &gap::PeriodicAdvertisingEnable {
                enable,
                advertising_handle: handle,
            }
            .encode(),
        )
        .map_err(|_| PeriodicError::Transport)?;
        self.periodic_adv.note_enable_sent(handle, enable);
        Ok(())
    }

    /// Synchronise to a periodic advertising train (§7.8.67). Only
    /// from Idle — the spec allows a single pending Create Sync at
    /// a time. The command returns Command Status; the outcome is
    /// signalled by Sync Established (§7.7.65.15) or a rejection.
    pub fn periodic_adv_create_sync(
        &mut self,
        req: gap::PeriodicAdvertisingCreateSync,
    ) -> Result<(), PeriodicError> {
        if self.periodic_sync.phase != PeriodicSyncPhase::Idle {
            return Err(PeriodicError::WrongPhase);
        }
        if !req.is_valid() {
            return Err(PeriodicError::BadParameter);
        }
        self.send_command(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, &req.encode())
            .map_err(|_| PeriodicError::Transport)?;
        self.periodic_sync.note_create_sync_sent();
        Ok(())
    }

    /// Cancel a pending Create Sync (§7.8.68). Only from Creating.
    pub fn periodic_adv_cancel_create_sync(&mut self) -> Result<(), PeriodicError> {
        if self.periodic_sync.phase != PeriodicSyncPhase::Creating {
            return Err(PeriodicError::WrongPhase);
        }
        self.send_command(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL, &[])
            .map_err(|_| PeriodicError::Transport)?;
        Ok(())
    }

    /// Terminate an established sync (§7.8.69). Only from Synced;
    /// the sync is gone only once the controller accepts the
    /// command (Command Complete).
    pub fn periodic_adv_terminate_sync(&mut self) -> Result<(), PeriodicError> {
        if self.periodic_sync.phase != PeriodicSyncPhase::Synced {
            return Err(PeriodicError::WrongPhase);
        }
        let handle = match self.periodic_sync.sync_handle {
            Some(h) => h,
            None => return Err(PeriodicError::WrongPhase),
        };
        self.send_command(
            op::HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC,
            &gap::build_periodic_adv_terminate_sync(handle),
        )
        .map_err(|_| PeriodicError::Transport)?;
        self.periodic_sync.note_terminate_sent();
        Ok(())
    }

    /// Transfer our established sync to a connected device
    /// (§7.8.89, issue #1654). Only from Synced, and only for the
    /// sync we actually hold — transferring a handle we do not hold
    /// would draw Unknown Advertising Identifier (0x42) from the
    /// controller, so the pump refuses first. The peer connection
    /// must exist in the connection table (otherwise the controller
    /// would return Unknown Connection Identifier, 0x02). State is
    /// checked before the handle ranges, matching Create Sync. The
    /// command completes once the information is queued, before it
    /// is actually sent; the outcome lands in `last_sync_transfer`
    /// and the sync stays Synced either way.
    pub fn periodic_adv_sync_transfer(
        &mut self,
        connection_handle: u16,
        service_data: u16,
        sync_handle: u16,
    ) -> Result<(), PeriodicError> {
        if self.periodic_sync.phase != PeriodicSyncPhase::Synced
            || self.periodic_sync.sync_handle != Some(sync_handle)
        {
            return Err(PeriodicError::WrongPhase);
        }
        if self.connection(connection_handle).is_none() {
            return Err(PeriodicError::WrongPhase);
        }
        if connection_handle > gap::PA_SYNC_HANDLE_MAX || sync_handle > gap::PA_SYNC_HANDLE_MAX {
            return Err(PeriodicError::BadParameter);
        }
        self.send_command(
            op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
            &gap::build_periodic_adv_sync_transfer(connection_handle, service_data, sync_handle),
        )
        .map_err(|_| PeriodicError::Transport)?;
        Ok(())
    }

    /// Transfer our own periodic advertising set's sync information
    /// to a connected device (§7.8.90, issue #1654). Only while the
    /// train is Enabled for `advertising_handle` — the controller
    /// returns Command Disallowed (0x0C) for a train that is not in
    /// progress and Unknown Advertising Identifier (0x42) for a
    /// handle with no set, so the pump refuses first. The peer
    /// connection must exist in the connection table. The outcome
    /// lands in `last_sync_transfer`; the train stays Enabled
    /// either way.
    pub fn periodic_adv_set_info_transfer(
        &mut self,
        connection_handle: u16,
        service_data: u16,
        advertising_handle: u8,
    ) -> Result<(), PeriodicError> {
        if self.periodic_adv.phase != PeriodicAdvertiserPhase::Enabled
            || self.periodic_adv.advertising_handle != Some(advertising_handle)
        {
            return Err(PeriodicError::WrongPhase);
        }
        if self.connection(connection_handle).is_none() {
            return Err(PeriodicError::WrongPhase);
        }
        if connection_handle > gap::PA_SYNC_HANDLE_MAX
            || advertising_handle > gap::PA_ADV_HANDLE_MAX
        {
            return Err(PeriodicError::BadParameter);
        }
        self.send_command(
            op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
            &gap::build_periodic_adv_set_info_transfer(
                connection_handle,
                service_data,
                advertising_handle,
            ),
        )
        .map_err(|_| PeriodicError::Transport)?;
        Ok(())
    }

    /// Set how the controller processes periodic advertising sync
    /// information received over a connection (§7.8.91, issue
    /// #1654). Only for a connection in the table; the mode / skip
    /// / timeout / CTE ranges are validated host-side. The values
    /// override the §7.8.92 defaults (and any earlier §7.8.91
    /// values) for this connection; they do not affect sync
    /// information already received. The outcome lands in
    /// `last_sync_transfer`.
    pub fn periodic_adv_set_sync_transfer_parameters(
        &mut self,
        params: gap::PeriodicAdvertisingSyncTransferParameters,
    ) -> Result<(), PeriodicError> {
        if self.connection(params.connection_handle).is_none() {
            return Err(PeriodicError::WrongPhase);
        }
        if !params.is_valid() {
            return Err(PeriodicError::BadParameter);
        }
        self.send_command(
            op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
            &params.encode(),
        )
        .map_err(|_| PeriodicError::Transport)?;
        Ok(())
    }

    /// Set the default transfer parameters for all subsequent LE
    /// connections (§7.8.92, issue #1654). No connection or phase
    /// requirement: the values are the initial mode / skip /
    /// timeout / CTE type for connections made after this command,
    /// and the command does not affect existing connections. Only
    /// the parameter ranges are validated host-side. The outcome
    /// lands in `last_sync_transfer`.
    pub fn periodic_adv_set_default_sync_transfer_parameters(
        &mut self,
        params: gap::PeriodicAdvertisingDefaultSyncTransferParameters,
    ) -> Result<(), PeriodicError> {
        if !params.is_valid() {
            return Err(PeriodicError::BadParameter);
        }
        self.send_command(
            op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
            &params.encode(),
        )
        .map_err(|_| PeriodicError::Transport)?;
        Ok(())
    }

    /// Advance the periodic state machines on a completed periodic
    /// command. Shared by the Command Complete and Command Status
    /// arms: the §7.8.61..63 broadcaster commands and Terminate
    /// Sync return Complete, while Create Sync returns Status
    /// first and completes later via Sync Established.
    ///
    /// `return_params` is `Some` for a Command Complete (the
    /// return parameters after the opcode, starting with the status
    /// byte) and `None` for a Command Status. Only a Command
    /// Complete records a §7.8.89..92 transfer outcome: those
    /// commands never return Command Status, so a Status event for
    /// one of them is not its completion.
    fn on_periodic_command_done(&mut self, opcode: u16, status: u8, return_params: Option<&[u8]>) {
        match opcode {
            op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS => {
                self.periodic_adv.note_parameters_set(status);
            }
            op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE => {
                self.periodic_adv.note_enable_done(status);
            }
            op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC => {
                // A non-zero Command Status means the controller
                // refused the attempt outright; no Sync Established
                // will ever follow it.
                if status != 0 {
                    self.periodic_sync.note_create_sync_rejected();
                }
            }
            op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL => {
                self.periodic_sync.note_create_sync_cancelled(status);
            }
            op::HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC => {
                self.periodic_sync.note_terminated(status);
            }
            op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER
            | op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER
            | op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS => {
                // §7.8.89..91 return Status + Connection_Handle.
                // The transfer changes no phase, so the outcome is
                // recorded for the API / fixtures.
                if let Some(ret) = return_params {
                    self.last_sync_transfer = Some(gap::SyncTransferOutcome {
                        opcode,
                        status,
                        connection_handle: ret.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])),
                    });
                }
            }
            op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS => {
                // §7.8.92 returns Status only.
                if return_params.is_some() {
                    self.last_sync_transfer = Some(gap::SyncTransferOutcome {
                        opcode,
                        status,
                        connection_handle: None,
                    });
                }
            }
            _ => {}
        }
    }
}

// ── GAP extended advertising / scanning (issue #823) ───────────────

/// Advertising payloads waiting on the parameters completion of an
/// `ext_adv_start` chain.
#[derive(Clone, Debug)]
struct PendingExtAdv {
    handle: u8,
    data: Vec<u8>,
    scan_response: Option<Vec<u8>>,
}

impl PumpCore {
    /// Begin extended LE discovery: issue LE Set Extended Scan
    /// Parameters (Vol 4 Part E §7.8.64). The follow-up LE Set
    /// Extended Scan Enable(1) is issued from `dispatch_event` once
    /// the parameters complete successfully, so the controller never
    /// receives Enable before its parameters are accepted. Only from
    /// Idle. At least one PHY must be set in `params` — an empty
    /// mask is rejected by the controller and the phase returns to
    /// Idle on the failed completion.
    pub fn ext_central_start_scan(
        &mut self,
        params: gap::ExtendedScanParameters,
    ) -> Result<(), CentralError> {
        if self.ext_central.phase != ExtendedScannerPhase::Idle {
            return Err(CentralError::WrongPhase);
        }
        self.send_command(op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS, &params.encode())
            .map_err(|_| CentralError::Transport)?;
        self.ext_central.note_parameters_sent();
        Ok(())
    }

    /// Stop extended LE discovery: issue LE Set Extended Scan
    /// Enable(0) (§7.8.65). Only from Scanning; completion returns
    /// the phase to Idle. A scan whose duration expired ends on its
    /// own via LE Scan Timeout (§7.7.65.17) instead.
    pub fn ext_central_stop_scan(&mut self) -> Result<(), CentralError> {
        if self.ext_central.phase != ExtendedScannerPhase::Scanning {
            return Err(CentralError::WrongPhase);
        }
        self.send_command(
            op::HCI_LE_SET_EXTENDED_SCAN_ENABLE,
            &gap::ExtendedScanEnable {
                enable: false,
                filter_duplicates: gap::ExtendedDuplicateFilter::Disabled,
                duration: 0,
                period: 0,
            }
            .encode(),
        )
        .map_err(|_| CentralError::Transport)?;
        self.ext_central.note_scan_stopping();
        Ok(())
    }

    /// Begin advertising set `params.handle`: issue LE Set Extended
    /// Advertising Parameters (§7.8.53). On the parameters'
    /// Command Complete the pump issues Set Extended Advertising
    /// Data (§7.8.54) with `data`, then — if `scan_response` is
    /// given — Set Extended Scan Response Data (§7.8.55), then Set
    /// Extended Advertising Enable(enable=1) (§7.8.56), each step
    /// only on the previous step's success. Any failed step drops
    /// the set to Idle and clears the chain. Only from Idle, and
    /// only one set may be mid-chain at a time.
    pub fn ext_adv_start(
        &mut self,
        params: gap::ExtendedAdvertisingParameters,
        data: &[u8],
        scan_response: Option<&[u8]>,
    ) -> Result<(), CentralError> {
        if data.len() > gap::EXT_ADV_DATA_MAX_LEN
            || scan_response.is_some_and(|s| s.len() > gap::EXT_ADV_DATA_MAX_LEN)
        {
            return Err(CentralError::BadData);
        }
        // One configuration chain at a time: a second start while a
        // set is mid-chain would make the completion arms ambiguous.
        if self.pending_ext_adv.is_some()
            || self.ext_adv_sets.iter().any(|s| {
                s.phase == AdvertisingSetPhase::ParametersSent
                    || s.phase == AdvertisingSetPhase::Configuring
                    || s.phase == AdvertisingSetPhase::Enabling
            })
        {
            return Err(CentralError::WrongPhase);
        }
        let handle = params.handle;
        if self.ext_adv_set(handle).phase != AdvertisingSetPhase::Idle {
            return Err(CentralError::WrongPhase);
        }
        self.send_command(
            op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
            &params.encode(),
        )
        .map_err(|_| CentralError::Transport)?;
        self.pending_ext_adv = Some(PendingExtAdv {
            handle,
            data: data.to_vec(),
            scan_response: scan_response.map(|s| s.to_vec()),
        });
        self.ext_adv_set_mut(handle).note_parameters_sent();
        Ok(())
    }

    /// Stop advertising set `handle`: issue LE Set Extended
    /// Advertising Enable(enable=0) for that set (§7.8.56). Only
    /// from Advertising; completion returns the set to Idle. A set
    /// whose duration / max-events expired ends on its own via LE
    /// Advertising Set Terminated (§7.7.65.18) instead.
    pub fn ext_adv_stop(&mut self, handle: u8) -> Result<(), CentralError> {
        let phase = self
            .ext_adv_sets
            .iter()
            .find(|s| s.handle == handle)
            .map(|s| s.phase);
        if phase != Some(AdvertisingSetPhase::Advertising) {
            return Err(CentralError::WrongPhase);
        }
        self.send_command(
            op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE,
            &gap::ExtendedAdvertisingEnable::disable_one(handle),
        )
        .map_err(|_| CentralError::Transport)?;
        self.ext_adv_set_mut(handle).note_disabling();
        Ok(())
    }

    /// Host-side state for advertising set `handle`, creating it in
    /// Idle when this controller has never configured the set.
    fn ext_adv_set(&mut self, handle: u8) -> &gap::AdvertisingSet {
        if self.ext_adv_sets.iter().all(|s| s.handle != handle) {
            self.ext_adv_sets.push(gap::AdvertisingSet::new(handle));
        }
        self.ext_adv_sets
            .iter()
            .find(|s| s.handle == handle)
            .expect("set just created")
    }

    /// Mutable host-side state for advertising set `handle`,
    /// creating it in Idle when this controller has never configured
    /// the set.
    fn ext_adv_set_mut(&mut self, handle: u8) -> &mut gap::AdvertisingSet {
        if self.ext_adv_sets.iter().all(|s| s.handle != handle) {
            self.ext_adv_sets.push(gap::AdvertisingSet::new(handle));
        }
        self.ext_adv_sets
            .iter_mut()
            .find(|s| s.handle == handle)
            .expect("set just created")
    }

    /// Advance the extended scanner on a completed extended scan
    /// command. Shared by the Command Complete and Command Status
    /// arms: scan commands return Complete.
    fn on_ext_central_command_done(&mut self, opcode: u16, status: u8) {
        match opcode {
            op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS => {
                if self.ext_central.phase == ExtendedScannerPhase::ParametersSent {
                    if status == 0 {
                        // Parameters accepted: enable scanning now.
                        if self
                            .send_command(
                                op::HCI_LE_SET_EXTENDED_SCAN_ENABLE,
                                &gap::ExtendedScanEnable {
                                    enable: true,
                                    filter_duplicates: gap::ExtendedDuplicateFilter::Disabled,
                                    duration: 0,
                                    period: 0,
                                }
                                .encode(),
                            )
                            .is_ok()
                        {
                            self.ext_central.note_scanning();
                        } else {
                            self.ext_central.phase = ExtendedScannerPhase::Idle;
                        }
                    } else {
                        self.ext_central.phase = ExtendedScannerPhase::Idle;
                    }
                }
            }
            op::HCI_LE_SET_EXTENDED_SCAN_ENABLE => {
                // The enable(1) completion while Scanning changes
                // nothing on success; the disable completion while
                // ScanStopping ends the scan. A rejected enable
                // leaves the phase where the controller actually is:
                // enable rejected while Scanning means scanning never
                // started (back to Idle); disable rejected while
                // ScanStopping means the controller is still scanning.
                if status != 0 {
                    match self.ext_central.phase {
                        ExtendedScannerPhase::ScanStopping => {
                            self.ext_central.phase = ExtendedScannerPhase::Scanning;
                        }
                        ExtendedScannerPhase::Scanning => {
                            self.ext_central.phase = ExtendedScannerPhase::Idle;
                        }
                        _ => {}
                    }
                } else if self.ext_central.phase == ExtendedScannerPhase::ScanStopping {
                    self.ext_central.phase = ExtendedScannerPhase::Idle;
                }
            }
            _ => {}
        }
    }

    /// Issue the enable step of an advertising-set chain for
    /// `handle`: Set Extended Advertising Enable(enable=1) with no
    /// duration limit and no event cap (§7.8.56).
    fn send_ext_adv_enable(&mut self, handle: u8) -> Result<(), TransportError> {
        self.send_command(
            op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE,
            &gap::ExtendedAdvertisingEnable::enable_one(handle),
        )
    }

    /// Advance the advertising-set chain on a completed extended
    /// advertising command. `selected_tx_power` is the §7.8.53
    /// return parameter, present only on the parameters' Command
    /// Complete; Command Status completions pass `None`.
    fn on_ext_adv_command_done(&mut self, opcode: u16, status: u8, selected_tx_power: Option<i8>) {
        match opcode {
            op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS => {
                let Some(handle) = self
                    .ext_adv_sets
                    .iter()
                    .find(|s| s.phase == AdvertisingSetPhase::ParametersSent)
                    .map(|s| s.handle)
                else {
                    return;
                };
                if status != 0 {
                    self.ext_adv_set_mut(handle).note_failed();
                    self.pending_ext_adv = None;
                    return;
                }
                let tx = selected_tx_power.unwrap_or(gap::EXT_ADV_TX_POWER_NO_PREFERENCE);
                self.ext_adv_set_mut(handle)
                    .note_parameters_complete(status, tx);
                let Some(pending) = self.pending_ext_adv.clone() else {
                    self.ext_adv_set_mut(handle).note_failed();
                    return;
                };
                let data = gap::ExtendedAdvertisingData {
                    handle: pending.handle,
                    operation: gap::AdvertisingDataOperation::Complete,
                    fragment_preference: gap::FragmentPreference::MinimizeFragmentation,
                    data: &pending.data,
                };
                if self
                    .send_command(op::HCI_LE_SET_EXTENDED_ADVERTISING_DATA, &data.encode())
                    .is_err()
                {
                    self.ext_adv_set_mut(handle).note_failed();
                    self.pending_ext_adv = None;
                }
            }
            op::HCI_LE_SET_EXTENDED_ADVERTISING_DATA => {
                let Some(handle) = self
                    .ext_adv_sets
                    .iter()
                    .find(|s| s.phase == AdvertisingSetPhase::Configuring)
                    .map(|s| s.handle)
                else {
                    return;
                };
                if status != 0 {
                    self.ext_adv_set_mut(handle).note_failed();
                    self.pending_ext_adv = None;
                    return;
                }
                let Some(pending) = self.pending_ext_adv.clone() else {
                    self.ext_adv_set_mut(handle).note_failed();
                    return;
                };
                match &pending.scan_response {
                    Some(sr) => {
                        let sr_data = gap::ExtendedAdvertisingData {
                            handle: pending.handle,
                            operation: gap::AdvertisingDataOperation::Complete,
                            fragment_preference: gap::FragmentPreference::MinimizeFragmentation,
                            data: sr,
                        };
                        if self
                            .send_command(
                                op::HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA,
                                &sr_data.encode(),
                            )
                            .is_err()
                        {
                            self.ext_adv_set_mut(handle).note_failed();
                            self.pending_ext_adv = None;
                        }
                    }
                    None => {
                        if self.send_ext_adv_enable(pending.handle).is_err() {
                            self.ext_adv_set_mut(handle).note_failed();
                            self.pending_ext_adv = None;
                        } else {
                            self.ext_adv_set_mut(handle).note_enabling();
                        }
                    }
                }
            }
            op::HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA => {
                let Some(handle) = self
                    .ext_adv_sets
                    .iter()
                    .find(|s| s.phase == AdvertisingSetPhase::Configuring)
                    .map(|s| s.handle)
                else {
                    return;
                };
                if status != 0 {
                    self.ext_adv_set_mut(handle).note_failed();
                    self.pending_ext_adv = None;
                    return;
                }
                let Some(pending) = self.pending_ext_adv.clone() else {
                    self.ext_adv_set_mut(handle).note_failed();
                    return;
                };
                if self.send_ext_adv_enable(pending.handle).is_err() {
                    self.ext_adv_set_mut(handle).note_failed();
                    self.pending_ext_adv = None;
                } else {
                    self.ext_adv_set_mut(handle).note_enabling();
                }
            }
            op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE => {
                if let Some(handle) = self
                    .ext_adv_sets
                    .iter()
                    .find(|s| s.phase == AdvertisingSetPhase::Enabling)
                    .map(|s| s.handle)
                {
                    // Enable step of a configuration chain.
                    self.ext_adv_set_mut(handle).note_enable_complete(status);
                    self.pending_ext_adv = None;
                } else if let Some(handle) = self
                    .ext_adv_sets
                    .iter()
                    .find(|s| s.phase == AdvertisingSetPhase::Disabling)
                    .map(|s| s.handle)
                {
                    self.ext_adv_set_mut(handle).note_disable_complete(status);
                }
            }
            _ => {}
        }
    }
}

// ── Classic BR/EDR central initiator API (issue #1315) ─────────────

/// Errors from the Classic BR/EDR central initiator API (issue #1315).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClassicError {
    /// No pump registered for this controller index.
    NoPump,
    /// A pump step currently owns the core; retry after the step.
    Busy,
    /// The classic state machine is in a phase that forbids this call.
    WrongPhase,
    /// The transport rejected the HCI command.
    Transport,
    /// `classic_connect` for an address no inquiry ever reported.
    /// Paging blind would use guessed PSRM/clock-offset values;
    /// discover first.
    UnknownPeer,
    /// `classic_write_scan_enable` mode outside 0..=3 (§7.3.18).
    BadScanMode,
    /// `classic_write_inquiry_mode` mode outside 0..=2 (§7.3.45).
    BadInquiryMode,
    /// `classic_request_remote_name` while another name request is
    /// already in flight — the controller allows only one.
    NameRequestPending,
    /// Extended advertising data passed through a classic entry
    /// point exceeds the 251-byte maximum (§7.8.54). Only reachable
    /// via the shared `with_pump_core` error conversion.
    BadData,
}

impl From<CentralError> for ClassicError {
    /// `with_pump_core` only ever fails as NoPump/Busy (its own
    /// slot errors); WrongPhase/Transport map identically so the
    /// module-level `classic_*` API can use `?` on it.
    fn from(e: CentralError) -> Self {
        match e {
            CentralError::NoPump => ClassicError::NoPump,
            CentralError::Busy => ClassicError::Busy,
            CentralError::WrongPhase => ClassicError::WrongPhase,
            CentralError::Transport => ClassicError::Transport,
            // Unreachable through this conversion: BadParams is
            // only produced by `central_connect_ext`, which never
            // flows into the classic API. Mapped to WrongPhase to
            // keep the match exhaustive.
            CentralError::BadParams => ClassicError::WrongPhase,
            CentralError::BadData => ClassicError::BadData,
        }
    }
}

impl PumpCore {
    /// Begin BR/EDR discovery: issue HCI_Inquiry (§7.1.1). Only
    /// from Idle. Results arrive as Inquiry Result events; Inquiry
    /// Complete ends the scan.
    pub fn classic_start_inquiry(
        &mut self,
        lap: [u8; 3],
        inquiry_length: u8,
        num_responses: u8,
    ) -> Result<(), ClassicError> {
        if self.classic.phase != ClassicPhase::Idle {
            return Err(ClassicError::WrongPhase);
        }
        let cmd = classic::build_inquiry(lap, inquiry_length, num_responses);
        self.send_command_obj(&cmd)
            .map_err(|_| ClassicError::Transport)?;
        self.classic.note_inquiry_started();
        Ok(())
    }

    /// Stop BR/EDR discovery early: issue HCI_Inquiry_Cancel
    /// (§7.1.2). Only from Inquiring; the phase reaches Idle on
    /// Inquiry Complete.
    pub fn classic_cancel_inquiry(&mut self) -> Result<(), ClassicError> {
        if self.classic.phase != ClassicPhase::Inquiring {
            return Err(ClassicError::WrongPhase);
        }
        self.send_command_obj(&classic::build_inquiry_cancel())
            .map_err(|_| ClassicError::Transport)?;
        self.pending_page = None;
        self.classic.note_inquiry_stopping();
        Ok(())
    }

    /// Page a discovered peer (§7.1.5). From Inquiring this first
    /// issues Inquiry_Cancel and defers Create_Connection until
    /// Inquiry Complete arrives; from Idle it issues
    /// Create_Connection directly. Forbidden while a page is
    /// already in flight or a classic connection is established.
    /// The PSRM + clock offset come from the peer's inquiry
    /// result — never guessed.
    pub fn classic_connect(&mut self, bd_addr: [u8; 6]) -> Result<(), ClassicError> {
        let peer = self
            .classic
            .peer(&bd_addr)
            .ok_or(ClassicError::UnknownPeer)?;
        let page = classic::PageRequest {
            bd_addr,
            page_scan_repetition_mode: peer.page_scan_repetition_mode,
            clock_offset: peer.clock_offset,
        };
        match self.classic.phase {
            ClassicPhase::Inquiring => {
                self.send_command_obj(&classic::build_inquiry_cancel())
                    .map_err(|_| ClassicError::Transport)?;
                self.pending_page = Some(page);
                self.classic.note_inquiry_stopping();
                Ok(())
            }
            ClassicPhase::Idle => self.issue_page(page),
            _ => Err(ClassicError::WrongPhase),
        }
    }

    /// Issue HCI_Create_Connection for a captured page request
    /// (§7.1.5) and enter Paging. Shared by the direct and deferred
    /// paths; the caller has already phase-checked.
    fn issue_page(&mut self, page: classic::PageRequest) -> Result<(), ClassicError> {
        let cmd = classic::build_create_connection(
            page.bd_addr,
            classic::ACL_PACKET_TYPES_DEFAULT,
            page.page_scan_repetition_mode,
            page.clock_offset,
            1, // allow role switch
        );
        self.send_command_obj(&cmd)
            .map_err(|_| ClassicError::Transport)?;
        self.classic.note_paging();
        Ok(())
    }

    /// Make this controller discoverable/connectable: issue
    /// HCI_Write_Scan_Enable (§7.3.18). No phase gate — host
    /// configuration, callable any time. The mode is recorded only
    /// once the controller accepts it (see `on_classic_command_done`).
    pub fn classic_write_scan_enable(&mut self, mode: u8) -> Result<(), ClassicError> {
        if mode > 3 {
            return Err(ClassicError::BadScanMode);
        }
        let cmd = classic::build_write_scan_enable(mode);
        self.send_command_obj(&cmd)
            .map_err(|_| ClassicError::Transport)?;
        self.pending_scan_mode = Some(mode);
        Ok(())
    }

    /// Select the inquiry-result format: issue HCI_Write_Inquiry_Mode
    /// (§7.3.45). No phase gate — host configuration, callable any
    /// time. The mode is recorded only once the controller accepts
    /// it (see `on_classic_command_done`). Mode 1 arms Inquiry
    /// Result with RSSI (0x22); mode 2 additionally arms Extended
    /// Inquiry Result / EIR (0x2F). Until a mode is accepted the
    /// controller sends standard results (0x02) only.
    pub fn classic_write_inquiry_mode(&mut self, mode: u8) -> Result<(), ClassicError> {
        if mode > 2 {
            return Err(ClassicError::BadInquiryMode);
        }
        let cmd = classic::build_write_inquiry_mode(mode);
        self.send_command_obj(&cmd)
            .map_err(|_| ClassicError::Transport)?;
        self.pending_inquiry_mode = Some(mode);
        Ok(())
    }

    /// Ask a discovered peer for its user-friendly name: issue
    /// HCI_Remote_Name_Request (§7.1.19) with the PSRM + clock
    /// offset from its inquiry result — never guessed. Only from
    /// Idle or Connected: the controller rejects a name request
    /// issued while inquiring (Command Disallowed, 0x0C — the
    /// radio is busy; Android/Floss starts RNR only after
    /// Inquiry Complete, and BTstack serialises inquiry, name
    /// request and page), and a page in flight (Paging) or being
    /// set up (InquiryStopping) is the same refusal. Only one
    /// name request may be outstanding at a time. The name lands
    /// in the peer table on Remote Name Request Complete (§7.7.7).
    pub fn classic_request_remote_name(&mut self, bd_addr: [u8; 6]) -> Result<(), ClassicError> {
        let peer = self
            .classic
            .peer(&bd_addr)
            .ok_or(ClassicError::UnknownPeer)?;
        if self.pending_name.is_some() {
            return Err(ClassicError::NameRequestPending);
        }
        match self.classic.phase {
            ClassicPhase::Idle | ClassicPhase::Connected => {}
            _ => return Err(ClassicError::WrongPhase),
        }
        let cmd = classic::build_remote_name_request(
            bd_addr,
            peer.page_scan_repetition_mode,
            peer.clock_offset,
        );
        self.send_command_obj(&cmd)
            .map_err(|_| ClassicError::Transport)?;
        self.pending_name = Some(bd_addr);
        Ok(())
    }

    /// Advance the classic state machine on a completed
    /// inquiry/page/scan/name command. Shared by the Command Complete
    /// and Command Status arms: Inquiry, Create Connection and
    /// Remote Name Request return Status first; Inquiry Cancel,
    /// Write Scan Enable and Write Inquiry Mode return Complete.
    fn on_classic_command_done(&mut self, opcode: u16, status: u8) {
        match opcode {
            op::HCI_INQUIRY => {
                // Refused inquiry: back to Idle, nothing to wait for.
                if self.classic.phase == ClassicPhase::Inquiring && status != 0 {
                    self.classic.note_idle();
                }
            }
            op::HCI_INQUIRY_CANCEL => {
                if self.classic.phase == ClassicPhase::InquiryStopping {
                    if status == 0 {
                        // Cancel accepted: Inquiry Complete still
                        // follows; the deferred page (if any) is
                        // issued there, never here — the controller
                        // is inquiring until that event arrives.
                    } else {
                        // Cancel refused: the inquiry is still
                        // running; drop the deferred page rather
                        // than page against a controller that may
                        // still be inquiring.
                        let dropped_peer = self.pending_page.take().map(|p| p.bd_addr);
                        self.classic.note_inquiry_started();
                        if dropped_peer.is_some_and(|peer| {
                            self.pending_sco.as_ref().is_some_and(|p| p.peer == peer)
                        }) {
                            self.fail_pending_sco_status(status);
                        }
                    }
                }
            }
            op::HCI_CREATE_CONNECTION => {
                if self.classic.phase == ClassicPhase::Paging && status != 0 {
                    self.classic.note_idle();
                    // The controller refused the page: the link —
                    // and any outbound open waiting on it — is dead.
                    self.fail_outbound_acl_pending(false);
                    // A refused page kills the SCO setup waiting on it.
                    if self
                        .pending_sco
                        .as_ref()
                        .is_some_and(|p| p.acl_handle.is_none())
                    {
                        self.fail_pending_sco_status(status);
                    }
                }
            }
            op::HCI_SETUP_SYNCHRONOUS_CONNECTION => {
                // Refused Setup Sync: no Synchronous Connection
                // Complete follows, so the pending setup fails here.
                // An accepted command keeps it until the Complete
                // event arrives (see dispatch_event).
                if status != 0 {
                    self.fail_pending_sco_status(status);
                }
            }
            op::HCI_WRITE_SCAN_ENABLE => {
                if status == 0 {
                    if let Some(mode) = self.pending_scan_mode.take() {
                        self.classic.note_scan_enable(mode);
                    }
                } else {
                    self.pending_scan_mode = None;
                }
            }
            op::HCI_WRITE_INQUIRY_MODE => {
                if status == 0 {
                    if let Some(mode) = self.pending_inquiry_mode.take() {
                        self.classic.note_inquiry_mode(mode);
                    }
                } else {
                    self.pending_inquiry_mode = None;
                }
            }
            op::HCI_REMOTE_NAME_REQUEST => {
                // Refused name request: no Remote Name Request
                // Complete follows, so the pending slot is freed
                // here. An accepted request keeps it until the
                // Complete event arrives (see dispatch_event).
                if status != 0 {
                    self.pending_name = None;
                }
            }
            _ => {}
        }
    }
}
// ── SMP initiator + bonding ─────────────────────────────────────────

/// Errors starting an initiator pairing on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpInitiateError {
    /// No connection with this handle.
    UnknownHandle,
    /// A pairing session is already in flight on this connection.
    AlreadyPairing,
    /// SMP initiation here is LE-only; BR/EDR cross-transport
    /// pairing is out of scope.
    NotLe,
    /// `smp_initiate_pairing_with_io` was given an IO capability
    /// byte outside the §3.5.1 set (0..=4).
    InvalidIoCap,
}

/// Errors starting encryption from a stored bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpEncryptError {
    /// No connection with this handle.
    UnknownHandle,
    /// A pairing session is in flight; re-encrypting from an old
    /// bond mid-pairing would leave the new session parked at
    /// AuthComplete with no EncryptionChange left to trigger it.
    PairingInProgress,
    /// No bond for this connection's peer.
    NoBond,
    /// The HCI command itself failed to send.
    Transport,
}

/// Outcome of feeding one SMP PDU, captured before acting so the
/// session borrow ends before any `queue_frame` / bond-store call.
struct SmpFeedOutcome {
    outs: Vec<smp::Pdu>,
    /// LTK to record on the connection when the session completed.
    done_ltk: Option<[u8; 16]>,
    /// Bond to store when the session completed bonded.
    bond: Option<Bond>,
    /// Pairing Failed reason to send when the session errored
    /// (`None` on the silent PeerFailed path).
    fail_reason: Option<u8>,
    /// True when the session must be cleared (Done, or any error).
    clear: bool,
    /// LTK to start encryption with when an initiator session just
    /// entered AuthComplete: the Central starts encryption (the
    /// Peripheral cannot), and Phase 3 needs the encrypted link.
    /// `None` for every other outcome.
    auto_encrypt: Option<[u8; 16]>,
    /// Terminal state of a mgmt-initiated pairing: `Some(true)`
    /// when an initiator session just completed (Done),
    /// `Some(false)` when one just failed; `None` for responder
    /// sessions and non-terminal initiator outcomes. The pump
    /// reports it to mgmt ([`crate::mgmt::pairing_complete`]),
    /// which only acts when a PAIR_DEVICE started the pairing
    /// (issue #815).
    initiator_terminal: Option<bool>,
    /// User attention the session raised while feeding this PDU
    /// (Numeric Comparison value to confirm, passkey to type in
    /// or to display). Drained once via `take_attention` and
    /// published by the pump as the matching mgmt event — the
    /// session raises it exactly once, so a dropped drain would
    /// strand the pairing at its park.
    attention: Option<smp::SmpAttention>,
}

/// Map a state-machine error to its Pairing Failed reason byte
/// (Vol 3 Part H §3.5.5).
fn smp_fail_reason(err: &PairingError) -> u8 {
    match err {
        PairingError::BadConfirm => smp::SMP_FAILED_CONFIRM_VALUE,
        PairingError::BadDhKeyCheck => smp::SMP_FAILED_DHKEY_CHECK_FAILED,
        PairingError::NumericComparisonRejected => smp::SMP_FAILED_NUMERIC_COMPARISON_FAILED,
        PairingError::PasskeyEntryFailed => smp::SMP_FAILED_PASSKEY_ENTRY,
        PairingError::OobNotAvailable => smp::SMP_FAILED_OOB_NOT_AVAILABLE,
        _ => smp::SMP_FAILED_UNSPECIFIED,
    }
}

/// Errors starting a host-initiated disconnect (issue #1527).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectError {
    /// No connection with this handle.
    UnknownHandle,
    /// An HCI Disconnect is already in flight for this handle.
    AlreadyDisconnecting,
    /// The transport rejected the HCI Disconnect.
    Transport,
}

impl PumpCore {
    /// Disconnect a connection by handle: issue HCI_Disconnect
    /// (§7.1.6, reason Remote User Terminated Connection 0x13)
    /// and record the handle as disconnecting until the
    /// Disconnection Complete (§7.7.5) — or a refused Command
    /// Status — resolves it. The mgmt DISCONNECT completion is
    /// reported from the event handlers, not here: this only
    /// proves the command was issued.
    pub fn disconnect(&mut self, handle: u16) -> Result<(), DisconnectError> {
        if self.connection(handle).is_none() {
            return Err(DisconnectError::UnknownHandle);
        }
        if self.disconnecting.contains(&handle) {
            return Err(DisconnectError::AlreadyDisconnecting);
        }
        self.send_command(
            op::HCI_DISCONNECT,
            &gap::build_disconnect(handle, gap::DISCONNECT_REASON_REMOTE_USER),
        )
        .map_err(|_| DisconnectError::Transport)?;
        self.disconnecting.push_back(handle);
        Ok(())
    }

    /// Resolve a refused HCI Disconnect Command Status: no
    /// Disconnection Complete follows a refusal, so the oldest
    /// in-flight disconnect completes as FAILED here instead of
    /// hanging until the link dies another way. A successful
    /// status is a no-op — the Disconnection Complete is the
    /// completion. Only a mgmt DISCONNECT that is pending gets a
    /// Command Complete ([`crate::mgmt::disconnect_complete`]
    /// ignores anything else, e.g. an UNPAIR-driven disconnect).
    fn on_disconnect_command_done(&mut self, opcode: u16, status: u8) {
        if opcode != op::HCI_DISCONNECT || status == 0 {
            return;
        }
        if let Some(handle) = self.disconnecting.pop_front() {
            crate::mgmt::disconnect_complete(self.index, handle, crate::mgmt::STATUS_FAILED);
        }
    }

    /// Start an initiator pairing on an LE connection: emit the
    /// Pairing Request and park the new session on the connection.
    /// This is the application trigger — the kernel side of pairing
    /// initiation. There is no ATT-triggered path yet: no
    /// auth-gated attribute exists to produce an
    /// Insufficient-Authentication error, so nothing today calls
    /// this from the ATT path. The IO capability comes from
    /// mgmt's SET_IO_CAPABILITY store (default NoInputNoOutput);
    /// PAIR_DEVICE pairings use [`smp_initiate_pairing_with_io`]
    /// instead, so their per-pairing io_cap is what the peer
    /// sees.
    pub fn smp_initiate_pairing(&mut self, handle: u16) -> Result<(), SmpInitiateError> {
        let io = smp::IoCapability::from_u8(crate::mgmt::io_capability(self.index as u16))
            .unwrap_or(smp::IoCapability::NoInputNoOutput);
        self.smp_initiate_pairing_with_io(handle, io as u8)
    }

    /// Start an initiator pairing advertising `io_cap` (a §3.5.1
    /// IO capability byte; invalid values are refused with
    /// [`SmpInitiateError::InvalidIoCap`]). The MITM bit follows
    /// the capability — any capability other than NoInputNoOutput
    /// asks for MITM, so Numeric Comparison / Passkey Entry are
    /// reachable (#818).
    pub fn smp_initiate_pairing_with_io(
        &mut self,
        handle: u16,
        io_cap: u8,
    ) -> Result<(), SmpInitiateError> {
        let io = smp::IoCapability::from_u8(io_cap).ok_or(SmpInitiateError::InvalidIoCap)?;
        let local = self.local_addr();
        let peer = {
            let conn = self
                .connections
                .iter()
                .find(|c| c.handle == handle)
                .ok_or(SmpInitiateError::UnknownHandle)?;
            if !conn.le {
                return Err(SmpInitiateError::NotLe);
            }
            if conn.smp.is_some() {
                return Err(SmpInitiateError::AlreadyPairing);
            }
            conn.peer_addr
        };
        let mut initiator = Initiator::with_io_capability(NarfSmpCrypto, local, peer, io);
        if let Some(oob) = crate::mgmt::remote_oob(self.index as u16, &peer) {
            initiator.set_peer_oob(oob);
        }
        let req = initiator.start();
        let conn = self
            .connection_mut(handle)
            .ok_or(SmpInitiateError::UnknownHandle)?;
        conn.smp = Some(SmpSession::Initiator(initiator));
        let le = conn.le;
        self.queue_frame(handle, le, &BFrame::new(CID_SMP, req.encode()));
        Ok(())
    }

    /// Re-encrypt a connection from its stored bond: issue HCI LE
    /// Start Encryption with the bond's EDIV/Rand/LTK (Vol 4 Part E
    /// §7.8.24). The peer's controller answers with an LE LTK
    /// Request event, which the pump answers from the same bond.
    /// Refused while a pairing session is in flight (see
    /// [`SmpEncryptError::PairingInProgress`]).
    pub fn smp_start_encryption(&mut self, handle: u16) -> Result<(), SmpEncryptError> {
        let peer = {
            let conn = self
                .connections
                .iter()
                .find(|c| c.handle == handle)
                .ok_or(SmpEncryptError::UnknownHandle)?;
            if conn.smp.is_some() {
                return Err(SmpEncryptError::PairingInProgress);
            }
            conn.peer_addr
        };
        let bond = self.bonds.lookup(&peer).ok_or(SmpEncryptError::NoBond)?;
        let (ediv, rand, ltk) = (bond.ediv, bond.rand, bond.ltk);
        let mut params = Vec::with_capacity(26);
        params.extend_from_slice(&handle.to_le_bytes());
        params.extend_from_slice(&rand);
        params.extend_from_slice(&ediv.to_le_bytes());
        params.extend_from_slice(&ltk);
        self.send_command(op::HCI_LE_START_ENCRYPTION, &params)
            .map_err(|_| SmpEncryptError::Transport)
    }
}

/// Errors cancelling an in-flight pairing on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpCancelError {
    /// No connection with this handle.
    UnknownHandle,
    /// No pairing session is in flight on this connection.
    NotPairing,
}

impl PumpCore {
    /// Abort an in-flight pairing on an LE connection (issue
    /// #1528): clear the session — initiator or responder — and
    /// send the peer a Pairing Failed PDU, Unspecified Reason
    /// (Vol 3 Part H §3.5.5), so the peer also abandons the
    /// exchange instead of waiting on a dead session. A
    /// mgmt-started pairing completes as CANCELLED
    /// ([`crate::mgmt::pairing_complete`], which no-ops for
    /// responder pairings and direct `smp_initiate_pairing` calls
    /// that never created a pending entry). No bond forms and no
    /// LTK is recorded: cancellation happens before Done, so
    /// there is nothing to forget. The link itself is untouched
    /// — cancelling a pairing is not a disconnect.
    pub fn smp_cancel_pairing(&mut self, handle: u16) -> Result<(), SmpCancelError> {
        let (peer, le) = {
            let conn = self
                .connections
                .iter()
                .find(|c| c.handle == handle)
                .ok_or(SmpCancelError::UnknownHandle)?;
            if conn.smp.is_none() {
                return Err(SmpCancelError::NotPairing);
            }
            (conn.peer_addr, conn.le)
        };
        let conn = self
            .connection_mut(handle)
            .ok_or(SmpCancelError::UnknownHandle)?;
        conn.smp = None;
        let failed = smp::Pdu {
            code: smp::SMP_PAIRING_FAILED,
            payload: alloc::vec![smp::SMP_FAILED_UNSPECIFIED],
        };
        self.queue_frame(handle, le, &BFrame::new(CID_SMP, failed.encode()));
        crate::mgmt::pairing_complete(self.index, peer, crate::mgmt::STATUS_CANCELLED);
        Ok(())
    }

    /// Forget a peer's bond. Returns true when one was removed.
    /// The sealed image is refreshed so a forgotten bond does
    /// not survive a reload.
    pub fn forget_bond(&mut self, peer_addr: &[u8; 7]) -> bool {
        let removed = self.bonds.forget(peer_addr);
        if removed {
            self.refresh_sealed_bonds();
        }
        removed
    }

    /// Number of bonds held for this controller.
    pub fn bond_count(&self) -> usize {
        self.bonds.len()
    }

    /// Answer a parked Numeric Comparison for `peer` (mgmt
    /// USER_CONFIRM_REPLY / NEG_REPLY). Returns false when no
    /// session for the peer is parked at the confirm — the mgmt
    /// layer reports that as NOT_CONNECTED. On acceptance the
    /// session resumes (the initiator's Random + DHKey Check go
    /// out); on rejection the session is cleared and a Pairing
    /// Failed 0x0C (Numeric Comparison Failed) is queued, and a
    /// mgmt-initiated initiator pairing completes AUTH_FAILED.
    pub fn smp_user_confirm(&mut self, peer: &[u8; 7], accepted: bool) -> bool {
        let Some(conn_idx) = self.connections.iter().position(|c| &c.peer_addr == peer) else {
            return false;
        };
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        // Capture the outcome first so the session borrow ends
        // before any queue/store call.
        struct ConfirmOutcome {
            outs: Vec<smp::Pdu>,
            fail_reason: Option<u8>,
            clear: bool,
            initiator_terminal: Option<bool>,
        }
        let outcome = {
            let conn = &mut self.connections[conn_idx];
            let Some(session) = conn.smp.as_mut() else {
                return false;
            };
            let (is_initiator, result) = match session {
                SmpSession::Initiator(i) => (true, i.confirm_numeric_comparison(accepted)),
                SmpSession::Responder(r) => (false, r.confirm_numeric_comparison(accepted)),
            };
            match result {
                Ok(outs) => ConfirmOutcome {
                    outs,
                    fail_reason: None,
                    clear: false,
                    initiator_terminal: None,
                },
                Err(PairingError::NumericComparisonRejected) => ConfirmOutcome {
                    outs: Vec::new(),
                    fail_reason: Some(smp::SMP_FAILED_NUMERIC_COMPARISON_FAILED),
                    clear: true,
                    initiator_terminal: if is_initiator { Some(false) } else { None },
                },
                Err(_) => return false,
            }
        };
        if outcome.clear {
            self.connections[conn_idx].smp = None;
        }
        if let Some(done) = outcome.initiator_terminal {
            let status = if done {
                crate::mgmt::STATUS_SUCCESS
            } else {
                crate::mgmt::STATUS_AUTH_FAILED
            };
            crate::mgmt::pairing_complete(self.index, *peer, status);
        }
        for out in outcome.outs {
            self.queue_frame(handle, le, &BFrame::new(CID_SMP, out.encode()));
        }
        if let Some(reason) = outcome.fail_reason {
            let failed = smp::Pdu {
                code: smp::SMP_PAIRING_FAILED,
                payload: alloc::vec![reason],
            };
            self.queue_frame(handle, le, &BFrame::new(CID_SMP, failed.encode()));
        }
        true
    }

    /// Supply the typed-in passkey for a session parked at
    /// Passkey Entry (mgmt USER_PASSKEY_REPLY). Returns false
    /// when no session for the peer is parked for a passkey.
    /// The initiator's first round confirm goes out on success;
    /// the responder simply resumes its rounds.
    pub fn smp_user_passkey(&mut self, peer: &[u8; 7], passkey: u32) -> bool {
        let Some(conn_idx) = self.connections.iter().position(|c| &c.peer_addr == peer) else {
            return false;
        };
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        let outs = {
            let conn = &mut self.connections[conn_idx];
            let Some(session) = conn.smp.as_mut() else {
                return false;
            };
            match session {
                SmpSession::Initiator(i) => i.provide_passkey(passkey),
                SmpSession::Responder(r) => r.provide_passkey(passkey),
            }
        };
        match outs {
            Ok(outs) => {
                for out in outs {
                    self.queue_frame(handle, le, &BFrame::new(CID_SMP, out.encode()));
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Cancel a parked passkey entry for `peer` (mgmt
    /// USER_PASSKEY_NEG_REPLY). Only a session still waiting for
    /// the passkey can be cancelled — once the rounds are running
    /// the entry is committed. Returns false when nothing was
    /// parked. On success the session is cleared and a Pairing
    /// Failed 0x01 (Passkey Entry Failed) is queued.
    pub fn smp_user_passkey_cancel(&mut self, peer: &[u8; 7]) -> bool {
        let Some(conn_idx) = self.connections.iter().position(|c| &c.peer_addr == peer) else {
            return false;
        };
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        let (parked, is_initiator) = {
            let conn = &self.connections[conn_idx];
            match &conn.smp {
                Some(SmpSession::Initiator(i)) => (i.state == smp::PairingState::WaitPasskey, true),
                Some(SmpSession::Responder(r)) => {
                    (r.state == smp::ResponderState::WaitPasskey, false)
                }
                None => (false, false),
            }
        };
        if !parked {
            return false;
        }
        self.connections[conn_idx].smp = None;
        if is_initiator {
            crate::mgmt::pairing_complete(self.index, *peer, crate::mgmt::STATUS_AUTH_FAILED);
        }
        let failed = smp::Pdu {
            code: smp::SMP_PAIRING_FAILED,
            payload: alloc::vec![smp::SMP_FAILED_PASSKEY_ENTRY],
        };
        self.queue_frame(handle, le, &BFrame::new(CID_SMP, failed.encode()));
        true
    }

    /// Provision the bond sealing key (32 bytes). Until a key is
    /// set, sealing is disabled: `sealed_bonds_image` returns
    /// `None` and bonds stay in-memory only. The key must come
    /// from a key service — this slot is the hookup point, not a
    /// key service (key custody is the suspend programme's KEYS
    /// domain, #996–#1008). Provisioning re-seals the current
    /// store immediately.
    pub fn set_bond_sealing_key(&mut self, key: [u8; 32]) {
        self.bond_sealing_key = Some(key);
        self.refresh_sealed_bonds();
    }

    /// Latest sealed bond image, if sealing is enabled. The
    /// future disk layer persists this blob; it is
    /// `nonce ‖ ciphertext ‖ tag` over the versioned store
    /// encoding.
    pub fn sealed_bonds_image(&self) -> Option<Vec<u8>> {
        self.sealed_bonds.clone()
    }

    /// Restore bonds from a sealed image produced by
    /// `sealed_bonds_image` (same key + AAD). Returns false on a
    /// bad tag or a malformed image, leaving the store untouched
    /// — a tampered image never yields bonds. On success the
    /// sealed image is re-sealed under a fresh nonce.
    pub fn restore_sealed_bonds(&mut self, blob: &[u8]) -> bool {
        let Some(key) = self.bond_sealing_key else {
            return false;
        };
        match BondStore::unseal(&key, &self.bond_seal_aad(), blob) {
            Some(store) => {
                self.bonds = store;
                self.refresh_sealed_bonds();
                true
            }
            None => false,
        }
    }

    /// AAD for the sealed bond image: format tag + controller
    /// index, so an image sealed for one controller cannot be
    /// replayed onto another (and a future format bumps the tag).
    fn bond_seal_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16);
        aad.extend_from_slice(b"narf-bond-v1:");
        aad.extend_from_slice(&(self.index as u32).to_le_bytes());
        aad
    }

    /// Re-seal the current store into `sealed_bonds` when a key
    /// is provisioned, with a fresh nonce per seal; otherwise
    /// clear the image. Called after every store mutation, so
    /// the image always matches the in-memory store.
    fn refresh_sealed_bonds(&mut self) {
        self.sealed_bonds = self.bond_sealing_key.map(|key| {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&NarfSmpCrypto.rand128()[..12]);
            self.bonds.seal(&key, &nonce, &self.bond_seal_aad())
        });
    }
}

// ── Event dispatch ──────────────────────────────────────────────────

/// GATT client issuance (issue #1313): ATT requests over a
/// central-role connection's outbound ACL path. The pump owns the
/// role check — a connection only has a client record when it was
/// initiated by this host — so these methods fail with
/// [`GattClientError::NotCentral`] on any other connection.
impl PumpCore {
    fn connection(&self, handle: u16) -> Option<&Connection> {
        self.connections.iter().find(|c| c.handle == handle)
    }

    /// Issue one client PDU on a central-role connection: resolve
    /// the connection, enforce the central role, run the client's
    /// lock-step issue, and queue the request for the next flush.
    /// The two lookups are sequential (never overlapping borrows);
    /// the second cannot miss because nothing mutates the table
    /// between them.
    fn gatt_client_issue(
        &mut self,
        handle: u16,
        f: impl FnOnce(&mut gatt_client::Client) -> Result<att::Pdu, GattClientError>,
    ) -> Result<(), GattClientError> {
        let Some(le) = self.connection(handle).map(|c| c.le) else {
            return Err(GattClientError::NoConnection);
        };
        if self.central.connected_handle != Some(handle) {
            return Err(GattClientError::NotCentral);
        }
        let pdu = {
            let conn = self.connection_mut(handle).unwrap();
            match conn.client.as_mut() {
                Some(client) => f(client)?,
                None => return Err(GattClientError::NotCentral),
            }
        };
        self.queue_frame(handle, le, &BFrame::new(CID_ATT, pdu.encode()));
        Ok(())
    }

    /// Discover all primary services in `[start, end]` on a
    /// central-role connection.
    pub fn gatt_client_discover_services(
        &mut self,
        handle: u16,
        start: u16,
        end: u16,
    ) -> Result<(), GattClientError> {
        self.gatt_client_issue(handle, |client| client.discover_services(start, end))
    }

    /// Discover all characteristics in `[start, end]` on a
    /// central-role connection.
    pub fn gatt_client_discover_characteristics(
        &mut self,
        handle: u16,
        start: u16,
        end: u16,
    ) -> Result<(), GattClientError> {
        self.gatt_client_issue(handle, |client| client.discover_characteristics(start, end))
    }

    /// Discover all descriptors in `[start, end]` on a
    /// central-role connection.
    pub fn gatt_client_discover_descriptors(
        &mut self,
        handle: u16,
        start: u16,
        end: u16,
    ) -> Result<(), GattClientError> {
        self.gatt_client_issue(handle, |client| client.discover_descriptors(start, end))
    }

    /// Read one characteristic value by handle on a central-role
    /// connection.
    pub fn gatt_client_read(
        &mut self,
        handle: u16,
        value_handle: u16,
    ) -> Result<(), GattClientError> {
        self.gatt_client_issue(handle, |client| client.read(value_handle))
    }

    /// Write one characteristic value by handle (Write Request,
    /// with response) on a central-role connection.
    pub fn gatt_client_write(
        &mut self,
        handle: u16,
        value_handle: u16,
        value: &[u8],
    ) -> Result<(), GattClientError> {
        self.gatt_client_issue(handle, |client| client.write(value_handle, value))
    }

    /// Subscribe to notifications (`notify == true`) or indications
    /// on a characteristic via its CCCD, on a central-role
    /// connection.
    pub fn gatt_client_subscribe(
        &mut self,
        handle: u16,
        cccd_handle: u16,
        notify: bool,
    ) -> Result<(), GattClientError> {
        self.gatt_client_issue(handle, |client| client.subscribe(cccd_handle, notify))
    }
}

impl PumpCore {
    /// Mirror a new connection into sysfs under this controller's
    /// `hci<N>` node (Linux `hci_conn_add_sysfs`). No-op when no
    /// controller kobject is published at this ordinal.
    fn sysfs_track_connect(&self, handle: u16, le: bool, peer: &[u8; 7]) {
        let mut bd_addr = [0u8; 6];
        bd_addr.copy_from_slice(&peer[1..7]);
        crate::sysfs_bridge::add_connection_for(
            self.index,
            &crate::sysfs_bridge::ConnInfo {
                handle,
                bd_addr,
                is_le: le,
                state: "connected",
            },
        );
    }

    /// Drop a connection's sysfs child on disconnect (Linux
    /// `hci_conn_del_sysfs`). No-op when nothing is published.
    fn sysfs_track_disconnect(&self, handle: u16) {
        let _ = crate::sysfs_bridge::remove_connection_for(self.index, handle);
    }

    /// Apply an LE (Enhanced) Connection Complete to the central
    /// state machine and the connection table. Shared by the legacy
    /// (§7.7.65.1) and enhanced (§7.7.65.10) subevents: the enhanced
    /// form is what an LE Extended Create Connection (§7.8.66)
    /// completes with.
    fn handle_le_connection_complete(
        &mut self,
        status: u8,
        handle: u16,
        peer_address_type: u8,
        peer_address: &[u8; 6],
    ) {
        // Initiator-role completions drive the central state
        // machine; inbound (peripheral-role) connections while Idle
        // leave it alone. The role is captured before the state
        // machine advances: it is the only sound test for whether
        // THIS completion is central-role (connected_handle alone
        // could match a stale handle reused by a peripheral
        // connection).
        let central_completed = self.central.phase == CentralPhase::Connecting;
        if central_completed {
            self.central.note_connection_complete(status, handle);
        }
        if status == 0 {
            let mut peer = [0u8; 7];
            peer[0] = peer_address_type;
            peer[1..7].copy_from_slice(peer_address);
            // New-main (detach lane) behaviour: drop any stale
            // handle claims before recording the connection.
            self.release_handle_claims(handle);
            self.connections.retain(|c| c.handle != handle);
            self.connections.push(Connection::new(handle, true, peer));
            // Central-role connections gain a GATT client record
            // (#1313); peripheral-role connections keep
            // server-only dispatch.
            if central_completed {
                if let Some(conn) = self.connections.last_mut() {
                    conn.client = Some(gatt_client::Client::new());
                }
            }
            self.sysfs_track_connect(handle, true, &peer);
            // An outbound open waiting on this link sends its
            // channel-open request now (#1532).
            self.advance_outbound_on_acl(handle, peer, true);
        } else if central_completed {
            // The central initiation failed: no link, no channel open.
            self.fail_outbound_acl_pending(true);
        }
    }

    /// Handle one HCI event. Socket fan-out happens in `pump_once`;
    /// this is only the host-stack dispatch.
    fn dispatch_event(&mut self, event: &Event) {
        match event.code {
            code if code == EventCode::LeMeta as u8 => {
                if let Some(cc) = LeConnectionComplete::parse(event) {
                    self.handle_le_connection_complete(
                        cc.status,
                        cc.handle,
                        cc.peer_address_type,
                        &cc.peer_address,
                    );
                    return;
                }
                if let Some(cc) = LeEnhancedConnectionComplete::parse(event) {
                    self.handle_le_connection_complete(
                        cc.status,
                        cc.handle,
                        cc.peer_address_type,
                        &cc.peer_address,
                    );
                    return;
                }
                if let Some(csa) = LeChannelSelectionAlgorithm::parse(event) {
                    // §7.7.65.20: recorded on the connection it
                    // names. An event for an unknown handle (or a
                    // stale one) is dropped, never recorded
                    // against the wrong link.
                    if let Some(conn) = self.connections.iter_mut().find(|c| c.handle == csa.handle)
                    {
                        conn.channel_selection_algorithm = Some(csa.algorithm);
                    }
                }
                if let Some(req) = LeLongTermKeyRequest::parse(event) {
                    // Answer order (Vol 4 Part E §7.8.25, Part H
                    // §3.6): first an in-progress AuthComplete
                    // session on this connection — the peer is
                    // encrypting with the just-derived LTK, and the
                    // bond is not stored until distribution
                    // finishes. SC sessions store EDIV 0 / Rand 0,
                    // so a non-zero event pair cannot match one.
                    // Then a stored bond matching peer address +
                    // EDIV/Rand exactly. Anything else gets an
                    // explicit negative reply — never a guessed key.
                    let reply = {
                        let conn = self.connections.iter().find(|c| c.handle == req.handle);
                        match conn {
                            Some(conn) => {
                                let session_ltk = match &conn.smp {
                                    Some(SmpSession::Responder(r))
                                        if r.state == smp::ResponderState::AuthComplete =>
                                    {
                                        Some(r.ltk)
                                    }
                                    Some(SmpSession::Initiator(i))
                                        if i.state == smp::PairingState::AuthComplete =>
                                    {
                                        Some(i.ltk)
                                    }
                                    _ => None,
                                };
                                if let Some(ltk) =
                                    session_ltk.filter(|_| req.ediv == 0 && req.random_number == 0)
                                {
                                    Some(ltk)
                                } else {
                                    self.bonds
                                        .lookup_for_ltk_request(
                                            &conn.peer_addr,
                                            req.ediv,
                                            req.random_number,
                                        )
                                        .map(|b| b.ltk)
                                }
                            }
                            None => None,
                        }
                    };
                    match reply {
                        Some(ltk) => {
                            let mut params = Vec::with_capacity(18);
                            params.extend_from_slice(&req.handle.to_le_bytes());
                            params.extend_from_slice(&ltk);
                            let _ = self.send_command(op::HCI_LE_LTK_REQUEST_REPLY, &params);
                        }
                        None => {
                            let _ = self.send_command(
                                op::HCI_LE_LTK_REQUEST_NEGATIVE_REPLY,
                                &req.handle.to_le_bytes(),
                            );
                        }
                    }
                }
                // Discovery reports feed the central peer table while
                // scanning (§7.7.65.2). Malformed reports parse to
                // None and are dropped, never recorded.
                if self.central.phase == CentralPhase::Scanning {
                    if let Some(reports) = parse_le_advertising_reports(event) {
                        for r in reports {
                            self.central.report_advertisement(
                                r.address_type,
                                r.address,
                                r.event_type,
                                &r.data,
                                r.rssi,
                            );
                            // mgmt DEVICE_FOUND, one per report
                            // (issue #815): published only while a
                            // mgmt discovery is active — the mgmt
                            // layer drops it otherwise.
                            crate::mgmt::publish_device_found(
                                self.index,
                                r.address_type,
                                r.address,
                                r.rssi,
                                r.event_type,
                                &r.data,
                            );
                        }
                    }
                }
                // Periodic advertising sync subevents (§7.7.65.14..16,
                // .21, issues #1560 / #1575). Malformed subevents parse to None
                // and are dropped; the state machine itself ignores
                // reports for other handles and stale subevents, so
                // a residual report racing a Sync Lost / Terminate
                // can neither resurrect state nor panic.
                if let Some(est) = LePeriodicAdvSyncEstablished::parse(event) {
                    self.periodic_sync.note_sync_established(&est);
                }
                if let Some(report) = LePeriodicAdvReport::parse(event) {
                    self.periodic_sync.note_report(&report);
                }
                if let Some(lost) = LePeriodicAdvSyncLost::parse(event) {
                    self.periodic_sync.note_sync_lost(&lost);
                }
                // Periodic Advertising Sync Transfer Received
                // (§7.7.65.21, issue #1575): a sync that arrives
                // by transfer adopts into PeriodicSync with no
                // pending Create Sync; malformed transfers parse
                // to None and are dropped, and the state machine
                // ignores failed transfers and transfers racing a
                // pending Create Sync or an existing sync.
                if let Some(xfer) = LePeriodicAdvSyncTransferReceived::parse(event) {
                    self.periodic_sync.note_sync_transfer_received(&xfer);
                }
                // Extended discovery reports feed the extended scanner
                // peer table while extended scanning (§7.7.65.13),
                // with fragment reassembly in `gap::ExtendedScanner`.
                // Malformed reports parse to None and are dropped.
                if self.ext_central.phase == ExtendedScannerPhase::Scanning {
                    if let Some(reports) = parse_le_extended_advertising_reports(event) {
                        for r in reports {
                            self.ext_central.report(&r);
                        }
                    }
                }
                // LE Scan Timeout (§7.7.65.17): the scan duration
                // expired, so the controller stopped scanning on its
                // own.
                if LeScanTimeout::parse(event).is_some() {
                    self.ext_central.note_scan_timeout();
                }
                // LE Advertising Set Terminated (§7.7.65.18): the
                // controller ended the set (duration / max-events
                // reached, or a connection was created from it).
                if let Some(term) = LeAdvertisingSetTerminated::parse(event) {
                    if let Some(set) = self
                        .ext_adv_sets
                        .iter_mut()
                        .find(|s| s.handle == term.handle)
                    {
                        set.note_terminated(
                            term.status,
                            term.connection_handle,
                            term.num_completed_events,
                        );
                    }
                }
                // LE Scan Request Received (§7.7.65.19): a scanner
                // asked this set for a scan response. Recorded on
                // the set; the phase is unchanged.
                if let Some(req) = LeScanRequestReceived::parse(event) {
                    if let Some(set) = self
                        .ext_adv_sets
                        .iter_mut()
                        .find(|s| s.handle == req.handle)
                    {
                        set.note_scan_request_received(
                            req.scanner_address_type,
                            req.scanner_address,
                        );
                    }
                }
            }
            code if code == EventCode::InquiryResult as u8 => {
                // §7.7.2: results feed the classic peer table while
                // the inquiry window is open (Inquiring, or
                // InquiryStopping until Inquiry Complete lands).
                // Malformed results parse to None and are dropped,
                // never recorded.
                if self.classic.phase == ClassicPhase::Inquiring
                    || self.classic.phase == ClassicPhase::InquiryStopping
                {
                    if let Some(results) = parse_inquiry_results(event) {
                        for r in results {
                            self.classic.report_inquiry_result(&r);
                        }
                    }
                }
            }
            code if code == EventCode::InquiryResultWithRssi as u8 => {
                // §7.7.33: same window and fail-closed discipline
                // as the standard result, plus the RSSI lands on
                // the peer entry.
                if self.classic.phase == ClassicPhase::Inquiring
                    || self.classic.phase == ClassicPhase::InquiryStopping
                {
                    if let Some(results) = parse_inquiry_results_with_rssi(event) {
                        for r in results {
                            self.classic.report_inquiry_result_with_rssi(&r);
                        }
                    }
                }
            }
            code if code == EventCode::ExtendedInquiryResult as u8 => {
                // §7.7.38: same window and fail-closed discipline
                // as the standard result, plus RSSI and the EIR
                // local name (if the 240-byte block carries one)
                // land on the peer entry.
                if self.classic.phase == ClassicPhase::Inquiring
                    || self.classic.phase == ClassicPhase::InquiryStopping
                {
                    if let Some(results) = parse_extended_inquiry_results(event) {
                        for r in results {
                            self.classic.report_extended_inquiry_result(&r);
                        }
                    }
                }
            }
            code if code == EventCode::InquiryComplete as u8 => {
                // §7.7.1: Status(1). Ends the inquiry window: from
                // InquiryStopping a deferred page is issued on
                // success and dropped on failure; from Inquiring the
                // phase simply returns to Idle.
                let status = event.params.first().copied().unwrap_or(0xFF);
                match self.classic.phase {
                    ClassicPhase::InquiryStopping => match (status, self.pending_page.take()) {
                        (0, Some(page)) => {
                            if self.issue_page(page).is_err() {
                                self.classic.note_idle();
                                // The deferred page never went out:
                                // any outbound open waiting on it
                                // can never complete.
                                self.fail_outbound_acl_pending(false);
                            }
                        }
                        _ => {
                            self.classic.note_idle();
                            // The deferred page was dropped with the
                            // failed inquiry cancel/complete.
                            self.fail_outbound_acl_pending(false);
                        }
                    },
                    ClassicPhase::Inquiring => self.classic.note_idle(),
                    _ => {}
                }
            }
            code if code == EventCode::SyncConnectionComplete as u8 => {
                // §7.7.35: Status(1) Handle(2) BD_ADDR(6)
                // Link_Type(1) TX_Interval(1) ReTx_Window(1)
                // Rx_Len(2) Tx_Len(2) Air_Mode(1).
                if let Some(sc) = SyncConnectionComplete::parse(event) {
                    self.on_sync_connection_complete(sc);
                }
            }
            code if code == EventCode::ConnectionComplete as u8 => {
                // §7.7.3: Status(1) Handle(2) BD_ADDR(6) Link_Type(1)
                // Encryption_Enabled(1).
                if let Some(cc) = ClassicConnectionComplete::parse(event) {
                    // Paging-role completions drive the classic
                    // state machine; inbound connections while Idle
                    // leave it alone. The role is captured before
                    // the state machine advances: it is the only
                    // sound test for whether THIS completion is
                    // classic-central-role (a stale handle reused
                    // by a peripheral connection must not flip it).
                    let classic_completed = self.classic.phase == ClassicPhase::Paging;
                    if classic_completed {
                        self.classic.note_connection_complete(cc.status, cc.handle);
                    }
                    if cc.status == 0 {
                        let mut peer = [0u8; 7];
                        peer[0] = 0; // BR/EDR addresses are public.
                        peer[1..7].copy_from_slice(&cc.bd_addr);
                        self.release_handle_claims(cc.handle);
                        self.connections.retain(|c| c.handle != cc.handle);
                        self.connections
                            .push(Connection::new(cc.handle, false, peer));
                        self.sysfs_track_connect(cc.handle, false, &peer);
                        // An outbound open waiting on this link
                        // sends its channel-open request now (#1532).
                        self.advance_outbound_on_acl(cc.handle, peer, false);
                        // SCO setup waiting on this page: the ACL is
                        // up — issue Setup Synchronous Connection now.
                        self.maybe_issue_pending_sco_setup(&cc.bd_addr, cc.handle);
                    } else if classic_completed {
                        // The page failed: no link, no channel open.
                        self.fail_outbound_acl_pending(false);
                    }
                }
            }
            code if code == EventCode::DisconnectionComplete as u8 => {
                if let Some(dc) = DisconnectionComplete::parse(event) {
                    self.release_handle_claims(dc.handle);
                    // A pending outbound open on this link can never
                    // complete, and a completed one lost its
                    // channel (#1532).
                    self.fail_outbound_for_handle(dc.handle);
                    // A mgmt-initiated pairing dies with the link:
                    // complete it as DISCONNECTED before the
                    // connection (and its session) is dropped
                    // (issue #815). mgmt ignores it when no
                    // PAIR_DEVICE started the pairing.
                    let dropped_peer = self
                        .connections
                        .iter()
                        .find(|c| c.handle == dc.handle)
                        .and_then(|c| {
                            if matches!(c.smp, Some(SmpSession::Initiator(_))) {
                                Some(c.peer_addr)
                            } else {
                                None
                            }
                        });
                    // A host-initiated disconnect resolves here
                    // (issue #1527): drop the in-flight record
                    // wherever it sits in issue order and complete
                    // the mgmt DISCONNECT — SUCCESS when the
                    // controller tore the link down, FAILED when
                    // the event itself reports the disconnect
                    // failed. An UNPAIR-driven disconnect has no
                    // pending mgmt record and completes nothing.
                    let disconnecting = self
                        .disconnecting
                        .iter()
                        .position(|h| *h == dc.handle)
                        .and_then(|i| self.disconnecting.remove(i));
                    self.connections.retain(|c| c.handle != dc.handle);
                    // SCO links ride the ACL: a dead ACL takes its
                    // SCO links with it, and a setup waiting on
                    // this ACL fails with the disconnect reason.
                    self.drop_sco_links_for_handle(dc.handle);
                    if self
                        .pending_sco
                        .as_ref()
                        .is_some_and(|p| p.acl_handle == Some(dc.handle))
                    {
                        self.fail_pending_sco_status(dc.reason);
                    }
                    self.sysfs_track_disconnect(dc.handle);
                    if self.central.connected_handle == Some(dc.handle) {
                        self.central.note_disconnected();
                    }
                    if self.classic.connected_handle == Some(dc.handle) {
                        self.classic.note_disconnected();
                    }
                    if let Some(peer) = dropped_peer {
                        crate::mgmt::pairing_complete(
                            self.index,
                            peer,
                            crate::mgmt::STATUS_DISCONNECTED,
                        );
                    }
                    if disconnecting.is_some() {
                        crate::mgmt::disconnect_complete(
                            self.index,
                            dc.handle,
                            if dc.status == 0 {
                                crate::mgmt::STATUS_SUCCESS
                            } else {
                                crate::mgmt::STATUS_FAILED
                            },
                        );
                    }
                }
            }
            code if code == EventCode::RemoteNameRequestComplete as u8 => {
                // §7.7.7: completes the one outstanding Remote Name
                // Request. A Complete for any other address is
                // ignored — the pending request is still owed its
                // own Complete. A failed Complete (non-zero status)
                // frees the slot but records no name.
                if let Some(rn) = RemoteNameRequestComplete::parse(event) {
                    if self.pending_name == Some(rn.bd_addr) {
                        self.pending_name = None;
                        if rn.status == 0 {
                            self.classic.note_remote_name(&rn.bd_addr, rn.name_bytes());
                        }
                    }
                }
            }
            code if code == EventCode::NumberOfCompletedPackets as u8 => {
                if let Some(nocp) = NumberOfCompletedPackets::parse(event) {
                    for (_handle, count) in nocp.entries {
                        self.acl_in_flight = self.acl_in_flight.saturating_sub(u32::from(count));
                    }
                }
            }
            code if code == EventCode::CommandComplete as u8 => {
                // Scan/connect sequencing lives here: the central
                // state machine advances only on the controller's
                // own completion, never on host assumption.
                if let Some(cc) = CommandComplete::parse(event) {
                    if let Some(status) = cc.status() {
                        self.on_central_command_done(cc.opcode, status);
                        self.on_classic_command_done(cc.opcode, status);
                        self.on_periodic_command_done(cc.opcode, status, Some(cc.return_params));
                        self.on_ext_central_command_done(cc.opcode, status);
                        self.on_ext_adv_command_done(
                            cc.opcode,
                            status,
                            parse_ext_adv_selected_tx_power(&cc),
                        );
                    }
                }
            }
            code if code == EventCode::CommandStatus as u8 => {
                if let Some(cs) = CommandStatus::parse(event) {
                    self.on_central_command_done(cs.opcode, cs.status);
                    self.on_classic_command_done(cs.opcode, cs.status);
                    self.on_periodic_command_done(cs.opcode, cs.status, None);
                    self.on_ext_central_command_done(cs.opcode, cs.status);
                    self.on_ext_adv_command_done(cs.opcode, cs.status, None);
                    self.on_disconnect_command_done(cs.opcode, cs.status);
                }
            }
            code if code == EventCode::EncryptionChange as u8 => {
                // §7.7.8: Status(1) Handle(2) Encryption_Enabled(1).
                let p = &event.params;
                if p.len() >= 4 {
                    let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0FFF;
                    let ok = p[0] == 0;
                    let enabled = p[3] != 0;
                    // Capture distribution output before acting
                    // (the session borrow must end first). The
                    // third element is the terminal outcome of a
                    // mgmt-initiated pairing, if this event ended
                    // one: `Some(true)` when an initiator session
                    // just completed (Done), `Some(false)` when
                    // one just failed.
                    let (outs, bond, initiator_done) = match self.connection_mut(handle) {
                        None => (Vec::new(), None, None),
                        Some(conn) => {
                            if ok {
                                conn.encrypted = enabled;
                            }
                            let is_auth_complete = match &conn.smp {
                                Some(SmpSession::Responder(r)) => {
                                    r.state == smp::ResponderState::AuthComplete
                                }
                                Some(SmpSession::Initiator(i)) => {
                                    i.state == smp::PairingState::AuthComplete
                                }
                                None => false,
                            };
                            if !is_auth_complete {
                                (Vec::new(), None, None)
                            } else if ok && enabled {
                                // The link is encrypted: Phase 3
                                // may start. On completion the bond
                                // is stored and the session cleared.
                                let (outs, bond, initiator_done) = match conn.smp.as_mut().unwrap()
                                {
                                    SmpSession::Responder(r) => {
                                        let outs = r.begin_distribution();
                                        let bond =
                                            if r.state == smp::ResponderState::Done && r.bonded {
                                                Some(Bond {
                                                    peer_addr: conn.peer_addr,
                                                    ltk: r.ltk,
                                                    ediv: 0,
                                                    rand: [0; 8],
                                                    authenticated: r.method
                                                        != smp::PairingMethod::JustWorks,
                                                    peer_irk: r.peer_irk,
                                                    peer_identity_addr: r.peer_identity_addr,
                                                    peer_csrk: r.peer_csrk,
                                                })
                                            } else {
                                                None
                                            };
                                        (outs, bond, None)
                                    }
                                    SmpSession::Initiator(i) => {
                                        let outs = i.begin_distribution();
                                        let bond = if i.state == smp::PairingState::Done && i.bonded
                                        {
                                            Some(Bond {
                                                peer_addr: conn.peer_addr,
                                                ltk: i.ltk,
                                                ediv: 0,
                                                rand: [0; 8],
                                                authenticated: i.method
                                                    != smp::PairingMethod::JustWorks,
                                                peer_irk: i.peer_irk,
                                                peer_identity_addr: i.peer_identity_addr,
                                                peer_csrk: i.peer_csrk,
                                            })
                                        } else {
                                            None
                                        };
                                        // Done here is terminal
                                        // (nothing was expected
                                        // from the peer); a
                                        // non-bonded Done
                                        // lingers in the
                                        // session table, but
                                        // the pairing itself
                                        // completed.
                                        (outs, bond, Some(i.state == smp::PairingState::Done))
                                    }
                                };
                                if bond.is_some() {
                                    conn.smp = None;
                                }
                                (outs, bond, initiator_done)
                            } else {
                                // Encryption failed or was switched
                                // off mid-pairing: no bond forms. The
                                // pairing already authenticated, so
                                // this is a silent clear, not a
                                // Pairing Failed — there is nothing
                                // left to fail.
                                let was_initiator =
                                    matches!(conn.smp, Some(SmpSession::Initiator(_)));
                                conn.smp = None;
                                (
                                    Vec::new(),
                                    None,
                                    if was_initiator { Some(false) } else { None },
                                )
                            }
                        }
                    };
                    if let Some(bond) = bond {
                        self.bonds.store(bond);
                        self.refresh_sealed_bonds();
                    }
                    // Terminal initiator outcome: complete a
                    // mgmt-initiated pairing (issue #815). mgmt
                    // ignores it when no PAIR_DEVICE started this
                    // pairing; a second fire is a no-op (the
                    // pending entry is already gone).
                    if let Some(done) = initiator_done {
                        if let Some(conn) = self.connections.iter().find(|c| c.handle == handle) {
                            let peer = conn.peer_addr;
                            let status = if done {
                                crate::mgmt::STATUS_SUCCESS
                            } else {
                                crate::mgmt::STATUS_AUTH_FAILED
                            };
                            crate::mgmt::pairing_complete(self.index, peer, status);
                        }
                    }
                    let le = self
                        .connections
                        .iter()
                        .find(|c| c.handle == handle)
                        .map(|c| c.le)
                        .unwrap_or(false);
                    for out in outs {
                        self.queue_frame(handle, le, &BFrame::new(CID_SMP, out.encode()));
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
                let Some(pdu) = att::Pdu::decode(&frame.payload) else {
                    return;
                };
                if self.central.connected_handle == Some(handle) {
                    // Central-role connection: inbound ATT PDUs are
                    // responses to this client's requests (or
                    // server-initiated notifications/indications).
                    // They must never reach the GATT server: a
                    // response opcode like Read By Group Type Rsp
                    // (0x11) has expects_response() == true, so the
                    // server arm below would answer it with a bogus
                    // response. A central connection without a
                    // client record drops the PDU instead of
                    // falling through to the server.
                    let outs = match self.connections[conn_idx].client.as_mut() {
                        Some(client) => client.feed(&pdu),
                        None => Vec::new(),
                    };
                    for out in outs {
                        self.queue_frame(handle, le, &BFrame::new(CID_ATT, out.encode()));
                    }
                } else if pdu.expects_response() {
                    let rsp = self.gatt.handle_request(&pdu);
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
                    self.answer_le_signalling(conn_idx, &cmd, &mut out);
                }
                if !out.is_empty() {
                    self.queue_frame(handle, le, &BFrame::new(CID_LE_SIGNALLING, out));
                }
            }
            CidClass::BrEdrSignalling => {
                let mut out = Vec::new();
                for cmd in l2cap::iter_signalling(&frame.payload) {
                    self.answer_bredr_signalling(conn_idx, &cmd, &mut out);
                }
                if !out.is_empty() {
                    self.queue_frame(handle, le, &BFrame::new(CID_SIGNALLING, out));
                }
            }
            CidClass::Dynamic => {
                self.route_dynamic(conn_idx, frame);
            }
            _ => {
                self.stats.frames_dropped_unrouted_cid += 1;
            }
        }
    }

    /// Route one reassembled frame on a dynamic CID to its channel's
    /// service. Responses are collected first, then queued, so no
    /// borrow of the connection outlives the service call.
    fn route_dynamic(&mut self, conn_idx: usize, frame: &BFrame) {
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        let Some(pos) = self.connections[conn_idx].channel_pos(frame.cid) else {
            self.stats.frames_dropped_unrouted_cid += 1;
            return;
        };
        // SDP's record database lives on the pump, not the
        // connection: answer it without holding the connection
        // borrow, then return.
        let is_sdp = matches!(
            &self.connections[conn_idx].channels[pos],
            Channel::BrEdr(ch) if matches!(ch.service, ChannelService::Sdp)
        );
        if is_sdp {
            let rsp = self.sdp.handle(&frame.payload);
            self.queue_frame(handle, le, &BFrame::new(frame.cid, rsp));
            return;
        }
        let mut responses: Vec<crate::rfcomm::Frame> = Vec::new();
        let mut top_up = 0u16;
        let mut no_credit = false;
        let mut drop_channel = false;
        // Set when the frame staged data (or opened a DLC) a socket
        // may be waiting on: the pump publishes a channel event so
        // parked poll/accept waiters re-run their readiness scan.
        let mut staged = false;
        // RFCOMM initiator interception (#1532): decode the payload
        // once, before the session borrow, and pull out any UA/DM
        // answering our SABM — the responder feed would swallow
        // them, and the outbound state machine needs them. The feed
        // loop below reuses the decoded remainder.
        let is_rfcomm = matches!(
            &self.connections[conn_idx].channels[pos],
            Channel::BrEdr(ch) if matches!(ch.service, ChannelService::Rfcomm(_))
        );
        let mut rfcomm_frames: Vec<crate::rfcomm::Frame> = Vec::new();
        let mut intercepted: Vec<crate::rfcomm::Frame> = Vec::new();
        if is_rfcomm {
            let mut buf = &frame.payload[..];
            while !buf.is_empty() {
                match crate::rfcomm::Frame::decode(buf) {
                    Ok((decoded, n)) => {
                        buf = &buf[n..];
                        // A UA/DM for a DLCI our outbound SABM
                        // named is the peer's answer to us, not
                        // responder traffic: intercept it.
                        let ours = (decoded.frame_type == crate::rfcomm::FRAME_UA
                            || decoded.frame_type == crate::rfcomm::FRAME_DM)
                            && self.outbound.iter().any(|o| {
                                o.handle == handle
                                    && o.local_cid == frame.cid
                                    && match o.state {
                                        OutboundState::MuxSabmSent => decoded.dlci == 0,
                                        OutboundState::DlcSabmSent => decoded.dlci == o.dlci,
                                        _ => false,
                                    }
                            });
                        if ours {
                            intercepted.push(decoded);
                        } else {
                            rfcomm_frames.push(decoded);
                        }
                    }
                    // Corrupt tail: drop the rest of this B-frame's
                    // payload.
                    Err(_) => break,
                }
            }
        }
        {
            let conn = &mut self.connections[conn_idx];
            match &mut conn.channels[pos] {
                Channel::Le(ch) => {
                    match ch.receive(&frame.payload) {
                        LeReceiveOutcome::Consumed => {}
                        LeReceiveOutcome::ConsumedSdu => staged = true,
                        LeReceiveOutcome::DroppedNoCredit => no_credit = true,
                        LeReceiveOutcome::Violation => drop_channel = true,
                    }
                    top_up = ch.take_top_up();
                }
                Channel::BrEdr(ch) => match &mut ch.service {
                    ChannelService::Rfcomm(session) => {
                        for decoded in &rfcomm_frames {
                            responses.extend(session.feed(decoded));
                        }
                        // A fed frame may have opened a DLC (accept
                        // wake) or staged UIH data (recv wake); the
                        // waiter re-checks, so a spurious publish on
                        // a mux-only frame is harmless.
                        staged = true;
                    }
                    ChannelService::Generic { rx } => {
                        rx.push(frame.payload.clone());
                        staged = true;
                    }
                    ChannelService::Sdp => {} // handled above
                },
            }
        }
        if staged {
            narf_filesystem::bluetooth::publish_bt_channel_event();
        }
        if no_credit {
            self.stats.frames_dropped_no_credit += 1;
        }
        if top_up > 0 && !drop_channel {
            // Flow Control Credit: identifier 0 (no response is
            // defined for this command); CID is our local CID, the
            // channel the peer may now send to. Suppressed when the
            // channel is being dropped below.
            let cmd = l2cap::build_le_flow_control_credit(0, frame.cid, top_up);
            let mut payload = Vec::new();
            cmd.encode(&mut payload);
            self.queue_frame(handle, le, &BFrame::new(CID_LE_SIGNALLING, payload));
        }
        if drop_channel {
            let (local_cid, peer_cid) = {
                let ch = &self.connections[conn_idx].channels[pos];
                (ch.local_cid(), ch.peer_cid())
            };
            self.connections[conn_idx].channels.remove(pos);
            self.release_claims(handle, local_cid);
            // Disconnection Request: Dest = the peer's CID for the
            // channel, Source = our local CID.
            let cmd = l2cap::build_disconnection_request(0, peer_cid, local_cid);
            let mut payload = Vec::new();
            cmd.encode(&mut payload);
            self.queue_frame(handle, le, &BFrame::new(CID_LE_SIGNALLING, payload));
        }
        for rsp in responses {
            self.queue_frame(handle, le, &BFrame::new(frame.cid, rsp.encode()));
        }
        // Intercepted RFCOMM answers to our SABM (#1532): drive the
        // outbound state machine now that the session borrow ended.
        for fr in intercepted {
            self.answer_outbound_rfcomm_frame(handle, le, fr);
        }
    }

    /// Parse a (Dest_CID, Source_CID) pair from signalling data;
    /// short data yields zeros (callers treat CID 0 as no match).
    fn parse_cid_pair(data: &[u8]) -> (u16, u16) {
        let a = if data.len() >= 2 {
            u16::from_le_bytes([data[0], data[1]])
        } else {
            0
        };
        let b = if data.len() >= 4 {
            u16::from_le_bytes([data[2], data[3]])
        } else {
            0
        };
        (a, b)
    }

    fn route_smp(&mut self, conn_idx: usize, pdu: &smp::Pdu) {
        let handle = self.connections[conn_idx].handle;
        let le = self.connections[conn_idx].le;
        if self.connections[conn_idx].smp.is_none() {
            let peer = self.connections[conn_idx].peer_addr;
            let local = self.local_addr();
            if le && pdu.code == smp::SMP_SECURITY_REQUEST {
                // Part H §3.6.7: the Peripheral asks the Central to
                // initiate security. The Security Request itself is
                // consumed by starting the initiator — it is not
                // fed into the new machine. The initiator
                // advertises the controller's SET_IO_CAPABILITY
                // value (not a hardcoded Just Works) and applies
                // any remote OOB data held for this peer (#818).
                let io = smp::IoCapability::from_u8(crate::mgmt::io_capability(self.index as u16))
                    .unwrap_or(smp::IoCapability::NoInputNoOutput);
                let mut initiator = Initiator::with_io_capability(NarfSmpCrypto, local, peer, io);
                if let Some(oob) = crate::mgmt::remote_oob(self.index as u16, &peer) {
                    initiator.set_peer_oob(oob);
                }
                let req = initiator.start();
                self.connections[conn_idx].smp = Some(SmpSession::Initiator(initiator));
                self.queue_frame(handle, le, &BFrame::new(CID_SMP, req.encode()));
                return;
            }
            // A fresh responder advertises the controller's
            // SET_IO_CAPABILITY value and applies any remote OOB
            // data held for this peer (#818).
            let io = smp::IoCapability::from_u8(crate::mgmt::io_capability(self.index as u16))
                .unwrap_or(smp::IoCapability::NoInputNoOutput);
            let mut responder = Responder::with_io_capability(NarfSmpCrypto, peer, local, io);
            if let Some(oob) = crate::mgmt::remote_oob(self.index as u16, &peer) {
                responder.set_peer_oob(oob);
            }
            self.connections[conn_idx].smp = Some(SmpSession::Responder(responder));
        }
        // Feed the session; capture the outcome first so the
        // session borrow ends before any queue/store call.
        let outcome = {
            let conn = &mut self.connections[conn_idx];
            let session = conn.smp.as_mut().unwrap();
            match session {
                SmpSession::Responder(r) => match r.feed(pdu) {
                    Ok(outs) => {
                        let done = r.state == smp::ResponderState::Done;
                        let attention = r.take_attention();
                        SmpFeedOutcome {
                            outs,
                            done_ltk: if done { Some(r.ltk) } else { None },
                            bond: if done && r.bonded {
                                Some(Bond {
                                    peer_addr: conn.peer_addr,
                                    ltk: r.ltk,
                                    ediv: 0,
                                    rand: [0; 8],
                                    authenticated: r.method != smp::PairingMethod::JustWorks,
                                    peer_irk: r.peer_irk,
                                    peer_identity_addr: r.peer_identity_addr,
                                    peer_csrk: r.peer_csrk,
                                })
                            } else {
                                None
                            },
                            fail_reason: None,
                            clear: done,
                            auto_encrypt: None,
                            initiator_terminal: None,
                            attention,
                        }
                    }
                    Err(PairingError::PeerFailed(_)) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: None,
                        clear: true,
                        auto_encrypt: None,
                        initiator_terminal: None,
                        attention: None,
                    },
                    Err(err) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: Some(smp_fail_reason(&err)),
                        clear: true,
                        auto_encrypt: None,
                        initiator_terminal: None,
                        attention: None,
                    },
                },
                SmpSession::Initiator(i) => match i.feed(pdu) {
                    Ok(outs) => {
                        let done = i.state == smp::PairingState::Done;
                        let attention = i.take_attention();
                        SmpFeedOutcome {
                            outs,
                            done_ltk: if done { Some(i.ltk) } else { None },
                            bond: if done && i.bonded {
                                Some(Bond {
                                    peer_addr: conn.peer_addr,
                                    ltk: i.ltk,
                                    ediv: 0,
                                    rand: [0; 8],
                                    authenticated: i.method != smp::PairingMethod::JustWorks,
                                    peer_irk: i.peer_irk,
                                    peer_identity_addr: i.peer_identity_addr,
                                    peer_csrk: i.peer_csrk,
                                })
                            } else {
                                None
                            },
                            fail_reason: None,
                            clear: done,
                            // The Central starts encryption: an
                            // initiator parked at AuthComplete
                            // issues Start Encryption with the
                            // just-derived LTK (SC: EDIV/Rand 0)
                            // so Phase 3 can proceed.
                            auto_encrypt: if i.state == smp::PairingState::AuthComplete {
                                Some(i.ltk)
                            } else {
                                None
                            },
                            // Done here is terminal: the peer's
                            // distribution completed the pairing
                            // (the other terminal path is
                            // begin_distribution in the
                            // EncryptionChange arm, when nothing
                            // was expected from the peer).
                            initiator_terminal: if done { Some(true) } else { None },
                            attention,
                        }
                    }
                    Err(PairingError::PeerFailed(_)) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: None,
                        clear: true,
                        auto_encrypt: None,
                        initiator_terminal: Some(false),
                        attention: None,
                    },
                    Err(err) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: Some(smp_fail_reason(&err)),
                        clear: true,
                        auto_encrypt: None,
                        initiator_terminal: Some(false),
                        attention: None,
                    },
                },
            }
        };
        if outcome.clear {
            self.connections[conn_idx].smp = None;
        }
        if let Some(ltk) = outcome.done_ltk {
            self.connections[conn_idx].ltk = Some(ltk);
        }
        if let Some(bond) = outcome.bond {
            self.bonds.store(bond);
            self.refresh_sealed_bonds();
        }
        // User attention raised while feeding this PDU: publish
        // the matching mgmt event so userspace can answer it
        // (USER_CONFIRM_REPLY / USER_PASSKEY_REPLY). The session
        // raises it exactly once — the drain here is the only
        // path out of the park.
        if let Some(attention) = outcome.attention {
            let peer = self.connections[conn_idx].peer_addr;
            match attention {
                smp::SmpAttention::UserConfirm(value) => {
                    crate::mgmt::user_confirm_request(self.index, peer, value)
                }
                smp::SmpAttention::PasskeyRequest => {
                    crate::mgmt::user_passkey_request(self.index, peer)
                }
                smp::SmpAttention::PasskeyNotify(passkey) => {
                    crate::mgmt::passkey_notify(self.index, peer, passkey)
                }
            }
        }
        // Terminal initiator outcome: complete a mgmt-initiated
        // pairing (issue #815). mgmt ignores it when no
        // PAIR_DEVICE started this pairing.
        if let Some(done) = outcome.initiator_terminal {
            let peer = self.connections[conn_idx].peer_addr;
            let status = if done {
                crate::mgmt::STATUS_SUCCESS
            } else {
                crate::mgmt::STATUS_AUTH_FAILED
            };
            crate::mgmt::pairing_complete(self.index, peer, status);
        }
        for out in outcome.outs {
            self.queue_frame(handle, le, &BFrame::new(CID_SMP, out.encode()));
        }
        if let Some(ltk) = outcome.auto_encrypt {
            // SC values: EDIV 0, Rand 0 (Part H §2.4.3.1). A
            // transport failure here leaves the session parked at
            // AuthComplete until disconnect — same swallow
            // discipline as the event-dispatch sends.
            let mut params = Vec::with_capacity(26);
            params.extend_from_slice(&handle.to_le_bytes());
            params.extend_from_slice(&[0u8; 8]);
            params.extend_from_slice(&0u16.to_le_bytes());
            params.extend_from_slice(&ltk);
            let _ = self.send_command(op::HCI_LE_START_ENCRYPTION, &params);
        }
        if let Some(reason) = outcome.fail_reason {
            let failed = smp::Pdu {
                code: smp::SMP_PAIRING_FAILED,
                payload: alloc::vec![reason],
            };
            self.queue_frame(handle, le, &BFrame::new(CID_SMP, failed.encode()));
        }
    }

    /// LE signalling answers (Vol 3 Part A §4). Connection
    /// Parameter Update is accepted; LE credit-based opens are
    /// answered from the server registry; Flow Control Credits add
    /// to our send budget; disconnections free the channel.
    fn answer_le_signalling(
        &mut self,
        conn_idx: usize,
        cmd: &l2cap::SignallingCommand,
        out: &mut Vec<u8>,
    ) {
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
                self.answer_le_coc_request(conn_idx, cmd, out);
            }
            Some(SignallingCode::LeCreditBasedConnectionResponse) => {
                // Our outbound CoC request's answer (#1532); an
                // unmatched response is ignored, never answered.
                self.answer_le_coc_response(conn_idx, cmd);
            }
            Some(SignallingCode::ConnectionParameterUpdateResponse) => {
                // We never send update requests; ignore.
            }
            Some(SignallingCode::CommandReject) => {
                // A rejected outbound request fails the open; any
                // other reject is ignored (never answer a response
                // with a reject).
                let handle = self.connections[conn_idx].handle;
                if let Some(pos) = self.outbound.iter().position(|o| {
                    o.handle == handle
                        && o.ident == cmd.identifier
                        && o.state == OutboundState::RequestSent
                        && matches!(o.kind, OutboundKind::LeCoc { .. })
                }) {
                    self.outbound[pos].state = OutboundState::Failed;
                }
            }
            Some(SignallingCode::FlowControlCredit) => {
                if cmd.data.len() >= 4 {
                    let cid = u16::from_le_bytes([cmd.data[0], cmd.data[1]]);
                    let credits = u16::from_le_bytes([cmd.data[2], cmd.data[3]]);
                    // CID is the sender's local CID (see the
                    // l2cap_server credit convention): the peer's
                    // local CID, i.e. the CID we send data on.
                    let conn = &mut self.connections[conn_idx];
                    for ch in conn.channels.iter_mut() {
                        if let Channel::Le(lech) = ch {
                            if lech.peer_cid == cid {
                                lech.grant_credits(credits);
                            }
                        }
                    }
                }
                // No response is defined for Flow Control Credit.
            }
            Some(SignallingCode::DisconnectionRequest) => {
                let (dest, _source) = Self::parse_cid_pair(&cmd.data);
                let handle = self.connections[conn_idx].handle;
                self.connections[conn_idx]
                    .channels
                    .retain(|c| c.local_cid() != dest);
                // A socket-claimed channel the peer tore down must
                // not shadow a later channel reusing the CID.
                self.release_claims(handle, dest);
                l2cap::SignallingCommand {
                    code: SignallingCode::DisconnectionResponse as u8,
                    identifier: cmd.identifier,
                    data: cmd.data.clone(),
                }
                .encode(out);
            }
            Some(SignallingCode::DisconnectionResponse) => {
                let (dest, _source) = Self::parse_cid_pair(&cmd.data);
                let handle = self.connections[conn_idx].handle;
                self.connections[conn_idx]
                    .channels
                    .retain(|c| c.local_cid() != dest);
                self.release_claims(handle, dest);
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

    /// Answer one LE Credit-Based Connection Request (§4.22/§4.23).
    /// Check order: source-CID validity, duplicate source CID,
    /// parameters, registry, allocation. Every refusal carries the
    /// §4.23 result code for the first failing check; the refusal
    /// shape (Dest 0, peer Source, result, zeros) matches the
    /// pre-server behaviour for unregistered PSMs.
    fn answer_le_coc_request(
        &mut self,
        conn_idx: usize,
        cmd: &l2cap::SignallingCommand,
        out: &mut Vec<u8>,
    ) {
        let (le_psm, source_cid, mtu, mps, initial_credits) = if cmd.data.len() >= 10 {
            (
                u16::from_le_bytes([cmd.data[0], cmd.data[1]]),
                u16::from_le_bytes([cmd.data[2], cmd.data[3]]),
                u16::from_le_bytes([cmd.data[4], cmd.data[5]]),
                u16::from_le_bytes([cmd.data[6], cmd.data[7]]),
                u16::from_le_bytes([cmd.data[8], cmd.data[9]]),
            )
        } else {
            (0, 0, 0, 0, 0)
        };
        let mut result = l2cap::LE_COC_RESULT_SUCCESS;
        let mut local_cid = 0u16;
        if !(l2cap::CID_DYNAMIC_LE_FIRST..=l2cap::CID_DYNAMIC_LE_LAST).contains(&source_cid) {
            result = l2cap::LE_COC_RESULT_INVALID_SOURCE_CID;
        } else if self.connections[conn_idx]
            .channels
            .iter()
            .any(|c| c.peer_cid() == source_cid)
        {
            result = l2cap::LE_COC_RESULT_SOURCE_CID_ALREADY_ALLOCATED;
        } else if mtu == 0 || mps == 0 {
            result = l2cap::LE_COC_RESULT_UNACCEPTABLE_PARAMETERS;
        } else {
            match self.servers.lookup_le(le_psm) {
                None => result = l2cap::LE_COC_RESULT_PSM_NOT_SUPPORTED,
                // LE channels stage SDUs regardless of kind today;
                // kinds exist so future LE profiles can attach
                // handlers to the registry.
                Some(kind) => match self.connections[conn_idx].cid_alloc.alloc_le() {
                    None => result = l2cap::LE_COC_RESULT_NO_RESOURCES,
                    Some(cid) => {
                        local_cid = cid;
                        self.connections[conn_idx]
                            .channels
                            .push(Channel::Le(LeCocChannel::new(
                                cid,
                                source_cid,
                                le_psm,
                                mtu,
                                mps,
                                initial_credits,
                            )));
                        // A Generic channel is socket-claimable: wake
                        // a listener parked in accept.
                        if kind == ServerKind::Generic {
                            narf_filesystem::bluetooth::publish_bt_channel_event();
                        }
                    }
                },
            }
        }
        let (dest, src, rmtu, rmps, rcredits) = if result == l2cap::LE_COC_RESULT_SUCCESS {
            (
                source_cid,
                local_cid,
                LE_COC_MTU,
                LE_COC_MPS,
                LE_COC_INITIAL_CREDITS,
            )
        } else {
            (0, source_cid, 0, 0, 0)
        };
        l2cap::build_le_credit_based_connection_response(
            cmd.identifier,
            dest,
            src,
            result,
            rmtu,
            rmps,
            rcredits,
        )
        .encode(out);
    }

    /// BR/EDR signalling answers (Vol 3 Part A §4). Connection
    /// Requests are answered from the server registry (SDP on PSM
    /// 0x0001, RFCOMM on PSM 0x0003, refused otherwise); Echo and
    /// Information are answered from the fixed-channel set this pump
    /// actually serves; Configure / Disconnection are answered so
    /// peers do not wedge.
    fn answer_bredr_signalling(
        &mut self,
        conn_idx: usize,
        cmd: &l2cap::SignallingCommand,
        out: &mut Vec<u8>,
    ) {
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
                let (psm, source_cid) = Self::parse_cid_pair(&cmd.data);
                // A peer must not reuse the source CID of an open
                // channel; refuse with no-resources (no classic
                // result code names this case).
                let duplicate = self.connections[conn_idx]
                    .channels
                    .iter()
                    .any(|c| c.peer_cid() == source_cid);
                let kind = if duplicate {
                    None
                } else {
                    self.servers.lookup_bredr(psm)
                };
                match kind {
                    None => {
                        let result = if duplicate {
                            l2cap::CONN_RESULT_REFUSED_NO_RESOURCES
                        } else {
                            l2cap::CONN_RESULT_REFUSED_PSM_NOT_SUPPORTED
                        };
                        l2cap::build_connection_response(
                            cmd.identifier,
                            0,
                            source_cid,
                            result,
                            l2cap::CONN_STATUS_NO_INFORMATION,
                        )
                        .encode(out);
                    }
                    Some(kind) => match self.connections[conn_idx].cid_alloc.alloc_bredr() {
                        // The BR/EDR allocator wraps and reuses CIDs
                        // without tracking the open set: refuse
                        // rather than aliasing an open channel.
                        Some(local_cid)
                            if self.connections[conn_idx].channel_pos(local_cid).is_none() =>
                        {
                            self.connections[conn_idx].channels.push(Channel::BrEdr(
                                BrEdrChannel::new(local_cid, source_cid, psm, kind),
                            ));
                            // A Generic channel is socket-claimable:
                            // wake a listener parked in accept.
                            if kind == ServerKind::Generic {
                                narf_filesystem::bluetooth::publish_bt_channel_event();
                            }
                            l2cap::build_connection_response(
                                cmd.identifier,
                                local_cid,
                                source_cid,
                                l2cap::CONN_RESULT_SUCCESS,
                                l2cap::CONN_STATUS_NO_INFORMATION,
                            )
                            .encode(out);
                        }
                        _ => {
                            l2cap::build_connection_response(
                                cmd.identifier,
                                0,
                                source_cid,
                                l2cap::CONN_RESULT_REFUSED_NO_RESOURCES,
                                l2cap::CONN_STATUS_NO_INFORMATION,
                            )
                            .encode(out);
                        }
                    },
                }
            }
            Some(SignallingCode::ConnectionResponse) => {
                // Our outbound Connection Request's answer (#1532);
                // an unmatched response is ignored, never answered.
                self.answer_bredr_conn_response(conn_idx, cmd);
            }
            Some(SignallingCode::ConfigureResponse) => {
                // Our outbound Configure Request's answer (#1532);
                // an unmatched response is ignored, never answered.
                self.answer_bredr_config_response(conn_idx, cmd);
            }
            Some(SignallingCode::CommandReject) => {
                // A rejected outbound request (or configure) fails
                // the open and tears its channel down; any other
                // reject is ignored (never answer a response with
                // a reject).
                let handle = self.connections[conn_idx].handle;
                if let Some(pos) = self.outbound.iter().position(|o| {
                    o.handle == handle
                        && (o.ident == cmd.identifier || o.ident2 == cmd.identifier)
                        && matches!(
                            o.state,
                            OutboundState::RequestSent | OutboundState::Configuring
                        )
                        && matches!(
                            o.kind,
                            OutboundKind::BrEdr { .. } | OutboundKind::Rfcomm { .. }
                        )
                }) {
                    self.fail_outbound_open(pos, OutboundState::Failed);
                }
            }
            Some(SignallingCode::ConfigureRequest) => {
                // §4.5 response: Source_CID(2) Flags(2) Result(2)
                // options(0). Accept with no options; record the
                // configuration on the channel when it is ours.
                let dest_cid = if cmd.data.len() >= 2 {
                    u16::from_le_bytes([cmd.data[0], cmd.data[1]])
                } else {
                    0
                };
                if let Some(pos) = self.connections[conn_idx].channel_pos(dest_cid) {
                    if let Channel::BrEdr(ch) = &mut self.connections[conn_idx].channels[pos] {
                        ch.configured = true;
                    }
                }
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
                let (dest, _source) = Self::parse_cid_pair(&cmd.data);
                let handle = self.connections[conn_idx].handle;
                self.connections[conn_idx]
                    .channels
                    .retain(|c| c.local_cid() != dest);
                // A socket-claimed channel the peer tore down must
                // not shadow a later channel reusing the CID.
                self.release_claims(handle, dest);
                l2cap::SignallingCommand {
                    code: SignallingCode::DisconnectionResponse as u8,
                    identifier: cmd.identifier,
                    data: cmd.data.clone(),
                }
                .encode(out);
            }
            Some(SignallingCode::DisconnectionResponse) => {
                let (dest, _source) = Self::parse_cid_pair(&cmd.data);
                let handle = self.connections[conn_idx].handle;
                self.connections[conn_idx]
                    .channels
                    .retain(|c| c.local_cid() != dest);
                self.release_claims(handle, dest);
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
        let Some(controller) = crate::controller::get_live(index) else {
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
    for index in crate::controller::live_indices() {
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
/// The controller stays registered; this is the quiesce step the
/// detach path (`controller::unregister_controller`) performs
/// before unregistering anything.
pub fn stop_pump(index: usize) {
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.stop = true;
    }
}

/// Remove controller `index`'s pump slot outright, dropping its core
/// (connection table, bonds, queued ACL) and its raw-socket fan-out
/// queue. The driver task, if running, observes the missing slot —
/// [`stop_requested`] is true when no slot exists — and exits at
/// its next iteration boundary; a step already in flight finishes
/// against the detached core and drops it when the slot is gone
/// (see [`pump_once`]'s restore), so no step can run on after this
/// returns. Returns `true` when a slot was removed.
///
/// Called by [`crate::controller::unregister_controller`] after
/// [`stop_pump`]; the flag is set again here so a task that reads
/// the slot between the two calls still sees the stop request.
pub fn remove_pump(index: usize) -> bool {
    let mut pumps = PUMPS.lock();
    let Some(pos) = pumps.iter().position(|s| s.index == index) else {
        return false;
    };
    pumps[pos].stop = true;
    pumps.swap_remove(pos);
    true
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

/// Register an LE PSM on controller `index`'s pump (see
/// `PumpCore::register_le_psm`). No-op when no pump exists.
pub fn register_le_psm(index: usize, le_psm: u16) {
    let _ = register_psm(index as u16, le_psm, true);
}

// ── AF_BLUETOOTH channel-socket API (issue #814) ─────────────────────
//
// The socket layer reaches these through the filesystem broker
// (`narf_filesystem::bluetooth`), which the `bluetooth-mgmt`
// initcall wires up. `dev` is the controller index. Read-only calls
// hold the slot lock (no transport I/O); calls that flush ACL frames
// take the core out via `with_core`, so a transiently-busy pump
// reports `Busy` (retryable) instead of stalling the caller.

/// Register `psm` on controller `dev`'s pump for a listening socket
/// (`le`: LE CoC PSM vs BR/EDR PSM). See
/// `PumpCore::register_le_psm` / `register_bredr_psm`.
pub fn register_psm(dev: u16, psm: u16, le: bool) -> BtRegisterStatus {
    let mut pumps = PUMPS.lock();
    let Some(slot) = find_slot_mut(&mut pumps, dev as usize) else {
        return BtRegisterStatus::NoPump;
    };
    let Some(core) = slot.core.as_mut() else {
        return BtRegisterStatus::NoPump;
    };
    let ok = if le {
        core.register_le_psm(psm)
    } else {
        core.register_bredr_psm(psm)
    };
    if ok {
        BtRegisterStatus::Registered
    } else {
        BtRegisterStatus::InUse
    }
}

/// Release a socket-listener PSM registration. No-op when no pump
/// exists or the PSM is service-owned.
pub fn unregister_psm(dev: u16, psm: u16, le: bool) {
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, dev as usize) {
        if let Some(core) = slot.core.as_mut() {
            if le {
                core.unregister_le_psm(psm);
            } else {
                core.unregister_bredr_psm(psm);
            }
        }
    }
}

/// Claim the oldest unclaimed channel opened by a peer to `psm` on
/// controller `dev`. `None` when nothing is pending or no pump
/// exists. See `PumpCore::take_pending_channel`.
pub fn take_pending_channel(dev: u16, psm: u16, le: bool) -> Option<(u16, u16, u16, [u8; 7])> {
    let mut pumps = PUMPS.lock();
    let slot = find_slot_mut(&mut pumps, dev as usize)?;
    slot.core.as_mut()?.take_pending_channel(psm, le)
}

/// Whether an unclaimed channel to `psm` is pending on controller
/// `dev` (non-consuming peek for poll/accept readiness).
pub fn pending_channel(dev: u16, psm: u16, le: bool) -> bool {
    let pumps = PUMPS.lock();
    let Some(slot) = pumps.iter().find(|s| s.index == dev as usize) else {
        return false;
    };
    slot.core
        .as_ref()
        .map(|c| c.pending_channel(psm, le))
        .unwrap_or(false)
}

/// Send one SDU on the open channel (`handle`, `cid`) of controller
/// `dev`. See `PumpCore::send_channel`.
pub fn send_channel(dev: u16, handle: u16, cid: u16, payload: &[u8]) -> Result<usize, BtSendError> {
    with_core(dev as usize, |core| core.send_channel(handle, cid, payload))
        .unwrap_or(Err(BtSendError::Busy))
}

/// Whether staged inbound data awaits on the open channel
/// (`handle`, `cid`) — non-consuming peek for poll.
pub fn channel_rx_pending(dev: u16, handle: u16, cid: u16) -> bool {
    let pumps = PUMPS.lock();
    let Some(slot) = pumps.iter().find(|s| s.index == dev as usize) else {
        return false;
    };
    slot.core
        .as_ref()
        .map(|c| c.channel_rx_pending(handle, cid))
        .unwrap_or(false)
}

/// Tear down the open channel (`handle`, `cid`) on controller `dev`
/// (see `PumpCore::disconnect_channel`). `false` when no such
/// channel exists, or the core is busy with a pump step (the claim
/// then survives until the peer or the connection releases it).
pub fn disconnect_channel(dev: u16, handle: u16, cid: u16) -> bool {
    with_core(dev as usize, |core| core.disconnect_channel(handle, cid)).unwrap_or(false)
}

// ── SCO socket backend (issue #814) ──────────────────────────────────

/// Start an outbound SCO setup to `peer` on controller `dev`
/// (see `PumpCore::sco_connect`). `NoPump` when no pump exists
/// for this controller index, `Busy` when a pump step currently
/// owns the core.
pub fn sco_connect(dev: u16, peer: [u8; 6], voice_setting: u16) -> BtScoConnectResult {
    match with_pump_core(dev as usize, |core| core.sco_connect(peer, voice_setting)) {
        Ok(r) => r,
        Err(CentralError::NoPump) => BtScoConnectResult::NoPump,
        Err(_) => BtScoConnectResult::Busy,
    }
}

/// Poll the outcome of an outbound SCO setup to `peer` started by
/// [`sco_connect`] (see `PumpCore::sco_connect_status`).
pub fn sco_connect_status(dev: u16, peer: [u8; 6]) -> BtScoConnectResult {
    match with_pump_core(dev as usize, |core| core.sco_connect_status(peer)) {
        Ok(r) => r,
        Err(CentralError::NoPump) => BtScoConnectResult::NoPump,
        Err(_) => BtScoConnectResult::Busy,
    }
}

/// Send one SCO frame on the open link (`handle`) of controller
/// `dev` (see `PumpCore::send_sco`).
pub fn send_sco(dev: u16, handle: u16, payload: &[u8]) -> Result<usize, BtSendError> {
    with_core(dev as usize, |core| core.send_sco(handle, payload)).unwrap_or(Err(BtSendError::Busy))
}

/// Drain staged inbound SCO payloads for the open link (`handle`)
/// (see `PumpCore::drain_sco_rx`).
pub fn drain_sco_rx(dev: u16, handle: u16) -> Option<Vec<Vec<u8>>> {
    let mut pumps = PUMPS.lock();
    let slot = find_slot_mut(&mut pumps, dev as usize)?;
    slot.core.as_mut()?.drain_sco_rx(handle)
}

/// Whether staged inbound SCO frames await on the open link
/// (`handle`) — non-consuming peek for poll.
pub fn sco_rx_pending(dev: u16, handle: u16) -> bool {
    let pumps = PUMPS.lock();
    let Some(slot) = pumps.iter().find(|s| s.index == dev as usize) else {
        return false;
    };
    slot.core
        .as_ref()
        .map(|c| c.sco_rx_pending(handle))
        .unwrap_or(false)
}

/// Tear down the open SCO link (`handle`) on controller `dev`
/// (see `PumpCore::disconnect_sco`). `false` when no such link
/// exists, or the core is busy with a pump step.
pub fn disconnect_sco(dev: u16, handle: u16) -> bool {
    with_core(dev as usize, |core| core.disconnect_sco(handle)).unwrap_or(false)
}

/// Cancel an in-flight outbound SCO setup to `peer` (see
/// `PumpCore::cancel_sco_connect`). No-op when no pump exists or
/// no setup is in flight for this peer.
pub fn cancel_sco_connect(dev: u16, peer: [u8; 6]) {
    let _ = with_core(dev as usize, |core| core.cancel_sco_connect(peer));
}

/// Claim the oldest unclaimed RFCOMM DLC opened by a peer to server
/// `channel` on controller `dev`. `None` when nothing is pending or
/// no pump exists. See `PumpCore::take_pending_rfcomm`.
pub fn take_pending_rfcomm(dev: u16, channel: u8) -> Option<(u16, u16, u16, u8, [u8; 7])> {
    let mut pumps = PUMPS.lock();
    let slot = find_slot_mut(&mut pumps, dev as usize)?;
    slot.core.as_mut()?.take_pending_rfcomm(channel)
}

/// Whether an unclaimed RFCOMM DLC to server `channel` is pending on
/// controller `dev` (non-consuming peek for poll/accept readiness).
pub fn pending_rfcomm(dev: u16, channel: u8) -> bool {
    let pumps = PUMPS.lock();
    let Some(slot) = pumps.iter().find(|s| s.index == dev as usize) else {
        return false;
    };
    slot.core
        .as_ref()
        .map(|c| c.pending_rfcomm(channel))
        .unwrap_or(false)
}

/// Send one UIH frame on the open RFCOMM DLC (`handle`, `cid`,
/// `dlci`) of controller `dev`. See `PumpCore::send_rfcomm`.
pub fn send_rfcomm(
    dev: u16,
    handle: u16,
    cid: u16,
    dlci: u8,
    payload: &[u8],
) -> Result<usize, BtSendError> {
    with_core(dev as usize, |core| {
        core.send_rfcomm(handle, cid, dlci, payload)
    })
    .unwrap_or(Err(BtSendError::Busy))
}

/// Whether staged inbound data awaits on the open RFCOMM DLC
/// (`handle`, `cid`, `dlci`) — non-consuming peek for poll.
pub fn rfcomm_rx_pending(dev: u16, handle: u16, cid: u16, dlci: u8) -> bool {
    let pumps = PUMPS.lock();
    let Some(slot) = pumps.iter().find(|s| s.index == dev as usize) else {
        return false;
    };
    slot.core
        .as_ref()
        .map(|c| c.rfcomm_rx_pending(handle, cid, dlci))
        .unwrap_or(false)
}

/// Close the open RFCOMM DLC (`handle`, `cid`, `dlci`) on controller
/// `dev` (see `PumpCore::close_rfcomm_dlc`). `false` when no such
/// DLC exists, or the core is busy with a pump step.
pub fn close_rfcomm_dlc(dev: u16, handle: u16, cid: u16, dlci: u8) -> bool {
    with_core(dev as usize, |core| {
        core.close_rfcomm_dlc(handle, cid, dlci)
    })
    .unwrap_or(false)
}

/// Drain staged channel payloads (see `PumpCore::drain_channel_rx`).
pub fn drain_channel_rx(dev: u16, handle: u16, cid: u16) -> Option<Vec<Vec<u8>>> {
    let mut pumps = PUMPS.lock();
    let slot = find_slot_mut(&mut pumps, dev as usize)?;
    slot.core.as_mut()?.drain_channel_rx(handle, cid)
}

/// Drain staged RFCOMM DLC payloads (see `PumpCore::drain_rfcomm_rx`).
pub fn drain_rfcomm_rx(dev: u16, handle: u16, cid: u16, dlci: u8) -> Option<Vec<Vec<u8>>> {
    let mut pumps = PUMPS.lock();
    let slot = find_slot_mut(&mut pumps, dev as usize)?;
    slot.core.as_mut()?.drain_rfcomm_rx(handle, cid, dlci)
}

// ── AF_BLUETOOTH outbound-connect API (issue #1532) ─────────────────
//
// The socket layer's `connect()` reaches the pump's outbound client
// through these, via the filesystem broker. `psm` is the LE/BR-EDR
// PSM, or the RFCOMM server channel when `rfcomm` is true.

/// Start (or poll) an outbound L2CAP/RFCOMM channel open on
/// controller `dev`. See [`PumpCore::connect_outbound`]. `NoPump`
/// when no pump is registered for the controller; a core busy with
/// a pump step reports `Busy`.
pub fn connect(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> BtConnectStatus {
    if !pump_registered(dev) {
        return BtConnectStatus::NoPump;
    }
    with_core(dev as usize, |core| {
        core.connect_outbound(peer, psm, le, rfcomm)
    })
    .unwrap_or(BtConnectStatus::Busy)
}

/// Whether an outbound open to `peer` has completed and is ready
/// to take (non-consuming peek for poll writability).
pub fn connect_ready(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
    let pumps = PUMPS.lock();
    let Some(slot) = pumps.iter().find(|s| s.index == dev as usize) else {
        return false;
    };
    slot.core
        .as_ref()
        .map(|c| c.connect_outbound_ready(peer, psm, le, rfcomm))
        .unwrap_or(false)
}

/// Abandon an in-flight outbound open to `peer` (socket close).
/// See [`PumpCore::cancel_outbound`].
pub fn cancel_connect(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
    with_core(dev as usize, |core| {
        core.cancel_outbound(peer, psm, le, rfcomm)
    })
    .unwrap_or(false)
}

/// Whether a pump slot is registered for controller `dev` (a slot
/// with its core temporarily taken out by a pump step still
/// counts — it is registered, just busy).
fn pump_registered(dev: u16) -> bool {
    let pumps = PUMPS.lock();
    pumps.iter().any(|s| s.index == dev as usize)
}

/// Cumulative pump statistics for controller `index`.
pub fn stats(index: usize) -> Option<PumpStats> {
    let pumps = PUMPS.lock();
    let slot = pumps.iter().find(|s| s.index == index)?;
    Some(slot.stats)
}

// ── GAP central initiator API (issue #1312) ─────────────────────────

/// Run `f` against controller `index`'s core with the slot lock
/// released — the same take-out pattern as [`pump_once`], so no
/// `IrqSafeSpinLock` is ever held across transport I/O. The core is
/// restored even when `f` reports an error.
fn with_pump_core<T>(index: usize, f: impl FnOnce(&mut PumpCore) -> T) -> Result<T, CentralError> {
    let mut core = {
        let mut pumps = PUMPS.lock();
        let Some(slot) = find_slot_mut(&mut pumps, index) else {
            return Err(CentralError::NoPump);
        };
        match slot.core.take() {
            Some(core) => core,
            None => return Err(CentralError::Busy),
        }
    };
    let out = f(&mut core);
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.core = Some(core);
    }
    Ok(out)
}

/// Begin LE discovery on controller `index`: issue LE Set Scan
/// Parameters; Set Scan Enable(1) follows on completion. Only from
/// Idle. This is the trigger mgmt START_DISCOVERY calls (issue
/// #815); it is also fixture-driven.
pub fn central_start_scan(index: usize, params: gap::ScanParameters) -> Result<(), CentralError> {
    with_pump_core(index, |core| core.central_start_scan(params))?
}

/// Stop LE discovery on controller `index`. Only from Scanning.
pub fn central_stop_scan(index: usize) -> Result<(), CentralError> {
    with_pump_core(index, |core| core.central_stop_scan())?
}

/// Connect to a discovered peer from controller `index`. From
/// Scanning the scan is disabled first and LE_Create_Connection
/// follows on the disable completion; from Idle the connection is
/// issued directly.
pub fn central_connect(
    index: usize,
    peer_address_type: gap::PeerAddressType,
    peer_address: [u8; 6],
) -> Result<(), CentralError> {
    with_pump_core(index, |core| {
        core.central_connect(peer_address_type, peer_address)
    })?
}

/// Connect to a discovered peer from controller `index` with LE
/// Extended Create Connection (§7.8.66). From Scanning the scan is
/// disabled first and the extended create follows on the disable
/// completion; from Idle it is issued directly. This is the trigger
/// surface a future mgmt/userspace lane will call; today it is
/// fixture-driven.
pub fn central_connect_ext(
    index: usize,
    params: gap::ExtendedCreateConnection,
) -> Result<(), CentralError> {
    with_pump_core(index, |core| core.central_connect_ext(params))?
}

/// Current GAP central phase for controller `index`, if its core is
/// not currently owned by a pump step.
pub fn central_phase(index: usize) -> Option<CentralPhase> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.central.phase)
}

/// Peers discovered by controller `index`'s scan, if its core is not
/// currently owned by a pump step.
pub fn central_peers(index: usize) -> Option<Vec<gap::DiscoveredPeer>> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.central.peers.clone())
}

// ── LE Periodic Advertising API (issue #1560) ───────────────────────

/// Run `f` against controller `index`'s core with the slot lock
/// released — the periodic counterpart of [`with_pump_core`].
fn with_pump_core_periodic<T>(
    index: usize,
    f: impl FnOnce(&mut PumpCore) -> T,
) -> Result<T, PeriodicError> {
    let mut core = {
        let mut pumps = PUMPS.lock();
        let Some(slot) = find_slot_mut(&mut pumps, index) else {
            return Err(PeriodicError::NoPump);
        };
        match slot.core.take() {
            Some(core) => core,
            None => return Err(PeriodicError::Busy),
        }
    };
    let out = f(&mut core);
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.core = Some(core);
    }
    Ok(out)
}

/// Set periodic advertising parameters on controller `index`
/// (§7.8.61). This is the trigger surface a future mgmt/userspace
/// lane will call; today it is fixture-driven.
pub fn periodic_adv_set_parameters(
    index: usize,
    params: gap::PeriodicAdvertisingParameters,
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| core.periodic_adv_set_parameters(params))?
}

/// Set periodic advertising data on controller `index` (§7.8.62).
pub fn periodic_adv_set_data(
    index: usize,
    advertising_handle: u8,
    operation: gap::PeriodicAdvDataOperation,
    data: &[u8],
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| {
        core.periodic_adv_set_data(advertising_handle, operation, data)
    })?
}

/// Enable or disable the periodic advertising train on controller
/// `index` (§7.8.63).
pub fn periodic_adv_set_enable(index: usize, enable: bool) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| core.periodic_adv_set_enable(enable))?
}

/// Synchronise to a periodic advertising train from controller
/// `index` (§7.8.67).
pub fn periodic_adv_create_sync(
    index: usize,
    req: gap::PeriodicAdvertisingCreateSync,
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| core.periodic_adv_create_sync(req))?
}

/// Cancel a pending Create Sync on controller `index` (§7.8.68).
pub fn periodic_adv_cancel_create_sync(index: usize) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| core.periodic_adv_cancel_create_sync())?
}

/// Terminate an established sync on controller `index` (§7.8.69).
pub fn periodic_adv_terminate_sync(index: usize) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| core.periodic_adv_terminate_sync())?
}

/// Transfer the established sync to a connected device on
/// controller `index` (§7.8.89, #1654). This is the trigger surface
/// a future mgmt/userspace lane will call; today it is
/// fixture-driven.
pub fn periodic_adv_sync_transfer(
    index: usize,
    connection_handle: u16,
    service_data: u16,
    sync_handle: u16,
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| {
        core.periodic_adv_sync_transfer(connection_handle, service_data, sync_handle)
    })?
}

/// Transfer our own periodic advertising set's sync information to
/// a connected device on controller `index` (§7.8.90, #1654).
pub fn periodic_adv_set_info_transfer(
    index: usize,
    connection_handle: u16,
    service_data: u16,
    advertising_handle: u8,
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| {
        core.periodic_adv_set_info_transfer(connection_handle, service_data, advertising_handle)
    })?
}

/// Set the per-connection transfer parameters on controller `index`
/// (§7.8.91, #1654).
pub fn periodic_adv_set_sync_transfer_parameters(
    index: usize,
    params: gap::PeriodicAdvertisingSyncTransferParameters,
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| {
        core.periodic_adv_set_sync_transfer_parameters(params)
    })?
}

/// Set the default transfer parameters on controller `index`
/// (§7.8.92, #1654).
pub fn periodic_adv_set_default_sync_transfer_parameters(
    index: usize,
    params: gap::PeriodicAdvertisingDefaultSyncTransferParameters,
) -> Result<(), PeriodicError> {
    with_pump_core_periodic(index, |core| {
        core.periodic_adv_set_default_sync_transfer_parameters(params)
    })?
}

/// Outcome of the most recent §7.8.89..92 sync-transfer command on
/// controller `index`, if its core is not currently owned by a pump
/// step.
pub fn periodic_sync_transfer_last_outcome(index: usize) -> Option<gap::SyncTransferOutcome> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .and_then(|c| c.last_sync_transfer)
}

/// Current periodic advertiser phase for controller `index`, if its
/// core is not currently owned by a pump step.
pub fn periodic_adv_phase(index: usize) -> Option<PeriodicAdvertiserPhase> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.periodic_adv.phase)
}

/// Current periodic-sync state for controller `index`, if its core
/// is not currently owned by a pump step.
pub fn periodic_sync_snapshot(index: usize) -> Option<gap::PeriodicSyncSnapshot> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.periodic_sync.snapshot())
}

/// Channel Selection Algorithm recorded for `handle` on controller
/// `index` (see `PumpCore::connection_channel_selection`).
pub fn connection_channel_selection(index: usize, handle: u16) -> Option<Option<u8>> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .and_then(|c| c.connection_channel_selection(handle))
}

// ── GAP extended advertising / scanning API (issue #823) ────────────

/// Begin extended LE discovery on controller `index`: issue LE Set
/// Extended Scan Parameters; Set Extended Scan Enable(1) follows on
/// completion. Only from Idle. This is the trigger surface a future
/// mgmt/userspace lane will call; today it is fixture-driven.
pub fn ext_central_start_scan(
    index: usize,
    params: gap::ExtendedScanParameters,
) -> Result<(), CentralError> {
    with_pump_core(index, |core| core.ext_central_start_scan(params))?
}

/// Stop extended LE discovery on controller `index`. Only from
/// Scanning.
pub fn ext_central_stop_scan(index: usize) -> Result<(), CentralError> {
    with_pump_core(index, |core| core.ext_central_stop_scan())?
}

/// Current GAP extended scanner phase for controller `index`, if its
/// core is not currently owned by a pump step.
pub fn ext_central_phase(index: usize) -> Option<gap::ExtendedScannerPhase> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.ext_central.phase)
}

/// Peers discovered by controller `index`'s extended scan, if its
/// core is not currently owned by a pump step.
pub fn ext_central_peers(index: usize) -> Option<Vec<gap::ExtendedDiscoveredPeer>> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.ext_central.peers.clone())
}

/// Begin advertising set `params.handle` on controller `index`:
/// parameters → data → (scan response) → enable, chained on Command
/// Completes. Only from Idle, and only one set may be mid-chain at a
/// time. This is the trigger surface a future mgmt/userspace lane
/// will call; today it is fixture-driven.
pub fn ext_adv_start(
    index: usize,
    params: gap::ExtendedAdvertisingParameters,
    data: &[u8],
    scan_response: Option<&[u8]>,
) -> Result<(), CentralError> {
    with_pump_core(index, |core| {
        core.ext_adv_start(params, data, scan_response)
    })?
}

/// Stop advertising set `handle` on controller `index`. Only from
/// Advertising.
pub fn ext_adv_stop(index: usize, handle: u8) -> Result<(), CentralError> {
    with_pump_core(index, |core| core.ext_adv_stop(handle))?
}

/// Current phase of advertising set `handle` on controller `index`,
/// if its core is not currently owned by a pump step.
pub fn ext_adv_phase(index: usize, handle: u8) -> Option<gap::AdvertisingSetPhase> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()?
        .ext_adv_sets
        .iter()
        .find(|s| s.handle == handle)
        .map(|s| s.phase)
}

/// Tx power the controller selected for advertising set `handle` on
/// controller `index` (§7.8.53 return params), once parameters
/// complete; `None` before that.
pub fn ext_adv_selected_tx_power(index: usize, handle: u8) -> Option<i8> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()?
        .ext_adv_sets
        .iter()
        .find(|s| s.handle == handle)?
        .selected_tx_power
}

// ── Classic BR/EDR central initiator API (issue #1315) ─────────────

/// Begin BR/EDR discovery on controller `index`: issue HCI_Inquiry
/// with `lap` (usually [`classic::GIAC`]). Only from Idle. This is
/// the trigger surface a future mgmt/userspace lane will call; today
/// it is fixture-driven.
pub fn classic_start_inquiry(
    index: usize,
    lap: [u8; 3],
    inquiry_length: u8,
    num_responses: u8,
) -> Result<(), ClassicError> {
    with_pump_core(index, |core| {
        core.classic_start_inquiry(lap, inquiry_length, num_responses)
    })?
}

/// Stop BR/EDR discovery early on controller `index`. Only from
/// Inquiring.
pub fn classic_cancel_inquiry(index: usize) -> Result<(), ClassicError> {
    with_pump_core(index, |core| core.classic_cancel_inquiry())?
}

/// Page a discovered peer from controller `index`. From Inquiring
/// the inquiry is cancelled first and Create_Connection follows on
/// Inquiry Complete; from Idle the page is issued directly.
pub fn classic_connect(index: usize, bd_addr: [u8; 6]) -> Result<(), ClassicError> {
    with_pump_core(index, |core| core.classic_connect(bd_addr))?
}

/// Set controller `index`'s scan mode (0 = off, 1 = inquiry,
/// 2 = page, 3 = both). Callable any time; the mode is recorded
/// only once the controller accepts it.
pub fn classic_write_scan_enable(index: usize, mode: u8) -> Result<(), ClassicError> {
    with_pump_core(index, |core| core.classic_write_scan_enable(mode))?
}

/// Select controller `index`'s inquiry-result format (0 =
/// standard, 1 = with RSSI, 2 = with RSSI or EIR). Callable any
/// time; the mode is recorded only once the controller accepts
/// it.
pub fn classic_write_inquiry_mode(index: usize, mode: u8) -> Result<(), ClassicError> {
    with_pump_core(index, |core| core.classic_write_inquiry_mode(mode))?
}

/// Ask discovered peer `bd_addr` for its user-friendly name from
/// controller `index`. Only from Idle or Connected, and only one
/// name request at a time; the name lands in the peer table on
/// Remote Name Request Complete.
pub fn classic_request_remote_name(index: usize, bd_addr: [u8; 6]) -> Result<(), ClassicError> {
    with_pump_core(index, |core| core.classic_request_remote_name(bd_addr))?
}

/// Current Classic central phase for controller `index`, if its core
/// is not currently owned by a pump step.
pub fn classic_phase(index: usize) -> Option<ClassicPhase> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.classic.phase)
}

/// Peers discovered by controller `index`'s inquiry, if its core is
/// not currently owned by a pump step.
pub fn classic_peers(index: usize) -> Option<Vec<classic::ClassicPeer>> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.classic.peers.clone())
}

/// Last Write_Scan_Enable mode controller `index` accepted, if its
/// core is not currently owned by a pump step.
pub fn classic_scan_mode(index: usize) -> Option<u8> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.classic.scan_mode)
}

/// Last Write_Inquiry_Mode mode controller `index` accepted, if its
/// core is not currently owned by a pump step.
pub fn classic_inquiry_mode(index: usize) -> Option<u8> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| c.classic.inquiry_mode)
}
/// Run `f` against controller `index`'s core, taken out of its slot
/// for the call (same discipline as [`pump_once`]: no
/// `IrqSafeSpinLock` held across transport I/O). Returns `None`
/// when no pump exists for `index` or a step is currently running.
fn with_core<R>(index: usize, f: impl FnOnce(&mut PumpCore) -> R) -> Option<R> {
    let mut core = {
        let mut pumps = PUMPS.lock();
        let slot = find_slot_mut(&mut pumps, index)?;
        slot.core.take()?
    };
    let r = f(&mut core);
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.core = Some(core);
    }
    Some(r)
}

/// Start an initiator pairing on controller `index`'s connection
/// `handle`. See [`PumpCore::smp_initiate_pairing`].
pub fn smp_initiate_pairing(index: usize, handle: u16) -> Option<Result<(), SmpInitiateError>> {
    with_core(index, |core| core.smp_initiate_pairing(handle))
}

/// Start an initiator pairing advertising `io_cap` (a §3.5.1 IO
/// capability byte). See
/// [`PumpCore::smp_initiate_pairing_with_io`].
pub fn smp_initiate_pairing_with_io(
    index: usize,
    handle: u16,
    io_cap: u8,
) -> Option<Result<(), SmpInitiateError>> {
    with_core(index, |core| {
        core.smp_initiate_pairing_with_io(handle, io_cap)
    })
}

/// Answer a parked Numeric Comparison for `peer` on controller
/// `index` (mgmt USER_CONFIRM_REPLY / NEG_REPLY). `None` when
/// there is no pump; `Some(false)` when no session for the peer
/// is parked at the confirm. See
/// [`PumpCore::smp_user_confirm`].
pub fn smp_user_confirm(index: usize, peer: &[u8; 7], accepted: bool) -> Option<bool> {
    with_core(index, |core| core.smp_user_confirm(peer, accepted))
}

/// Supply the typed-in passkey for a session parked at Passkey
/// Entry on controller `index` (mgmt USER_PASSKEY_REPLY).
/// `None` when there is no pump; `Some(false)` when no session
/// for the peer is parked for a passkey. See
/// [`PumpCore::smp_user_passkey`].
pub fn smp_user_passkey(index: usize, peer: &[u8; 7], passkey: u32) -> Option<bool> {
    with_core(index, |core| core.smp_user_passkey(peer, passkey))
}

/// Cancel a parked passkey entry for `peer` on controller
/// `index` (mgmt USER_PASSKEY_NEG_REPLY). `None` when there is
/// no pump; `Some(false)` when nothing was parked. See
/// [`PumpCore::smp_user_passkey_cancel`].
pub fn smp_user_passkey_cancel(index: usize, peer: &[u8; 7]) -> Option<bool> {
    with_core(index, |core| core.smp_user_passkey_cancel(peer))
}

/// Provision controller `index`'s bond sealing key. `None` when
/// there is no pump. See [`PumpCore::set_bond_sealing_key`].
pub fn set_bond_sealing_key(index: usize, key: [u8; 32]) -> Option<()> {
    with_core(index, |core| core.set_bond_sealing_key(key))
}

/// Latest sealed bond image for controller `index`, if sealing
/// is enabled. See [`PumpCore::sealed_bonds_image`].
pub fn sealed_bonds_image(index: usize) -> Option<Option<Vec<u8>>> {
    with_core(index, |core| core.sealed_bonds_image())
}

/// Restore controller `index`'s bonds from a sealed image.
/// `None` when there is no pump; `Some(false)` on a bad tag or
/// a malformed image. See [`PumpCore::restore_sealed_bonds`].
pub fn restore_sealed_bonds(index: usize, blob: &[u8]) -> Option<bool> {
    with_core(index, |core| core.restore_sealed_bonds(blob))
}

/// Re-encrypt controller `index`'s connection `handle` from its
/// stored bond. See [`PumpCore::smp_start_encryption`].
pub fn smp_start_encryption(index: usize, handle: u16) -> Option<Result<(), SmpEncryptError>> {
    with_core(index, |core| core.smp_start_encryption(handle))
}

/// Cancel an in-flight pairing on controller `index`'s connection
/// `handle`. See [`PumpCore::smp_cancel_pairing`].
pub fn smp_cancel_pairing(index: usize, handle: u16) -> Option<Result<(), SmpCancelError>> {
    with_core(index, |core| core.smp_cancel_pairing(handle))
}

/// Disconnect controller `index`'s connection `handle` by
/// issuing HCI Disconnect (issue #1527). See
/// [`PumpCore::disconnect`].
pub fn disconnect(index: usize, handle: u16) -> Option<Result<(), DisconnectError>> {
    with_core(index, |core| core.disconnect(handle))
}

/// Forget controller `index`'s bond for `peer_addr`.
pub fn forget_bond(index: usize, peer_addr: &[u8; 7]) -> Option<bool> {
    with_core(index, |core| core.forget_bond(peer_addr))
}

/// Store a bond for controller `index`, replacing any bond for
/// the same peer (mgmt LOAD_LONG_TERM_KEYS, issue #815). Returns
/// `None` when the controller has no pump.
pub fn store_bond(index: usize, bond: Bond) -> Option<()> {
    with_core(index, |core| core.bonds.store(bond))
}

/// Record the peer IRK for controller `index`'s existing bond
/// (mgmt LOAD_IRKS, issue #815). Returns `None` when the
/// controller has no pump, `Some(false)` when no bond exists
/// for the peer.
pub fn set_peer_irk(index: usize, peer_addr: &[u8; 7], irk: [u8; 16]) -> Option<bool> {
    with_core(index, |core| core.bonds.set_peer_irk(peer_addr, irk))
}

/// Bond count for controller `index`, if it has a pump.
pub fn bond_count(index: usize) -> Option<usize> {
    let pumps = PUMPS.lock();
    let slot = pumps.iter().find(|s| s.index == index)?;
    slot.core.as_ref().map(|c| c.bond_count())
}

/// One live ACL connection, as mgmt GET_CONNECTIONS reports it
/// (issue #815). `peer_addr` is `[address_type, bd_addr]`;
/// `le` distinguishes LE from BR/EDR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PumpConnectionInfo {
    pub handle: u16,
    pub peer_addr: [u8; 7],
    pub le: bool,
}

/// Live connections on controller `index`, if it has a pump.
/// Read-only snapshot (same discipline as [`central_peers`]).
pub fn connections(index: usize) -> Option<Vec<PumpConnectionInfo>> {
    let pumps = PUMPS.lock();
    pumps
        .iter()
        .find(|s| s.index == index)?
        .core
        .as_ref()
        .map(|c| {
            c.connections
                .iter()
                .map(|conn| PumpConnectionInfo {
                    handle: conn.handle,
                    peer_addr: conn.peer_addr,
                    le: conn.le,
                })
                .collect()
        })
}

/// Whether controller `index` holds a bond for `peer_addr`, if it
/// has a pump.
pub fn has_bond(index: usize, peer_addr: &[u8; 7]) -> Option<bool> {
    with_core(index, |core| core.bonds.lookup(peer_addr).is_some())
}

/// Whether controller `index`'s bond for `peer_addr` is
/// MITM-authenticated (Numeric Comparison / Passkey Entry / OOB
/// rather than Just Works), if it has a pump and holds the bond.
pub fn bond_authenticated(index: usize, peer_addr: &[u8; 7]) -> Option<bool> {
    with_core(index, |core| {
        core.bonds.lookup(peer_addr).map(|b| b.authenticated)
    })
    .flatten()
}

// ── The step ────────────────────────────────────────────────────────

/// Slot-level core access for the GATT client free API. Mirrors
/// [`with_pump_core`] exactly, but reports
/// [`GattClientError`] instead of [`CentralError`]; keep the two
/// in sync.
fn with_client_core<T>(
    index: usize,
    f: impl FnOnce(&mut PumpCore) -> T,
) -> Result<T, GattClientError> {
    let mut core = {
        let mut pumps = PUMPS.lock();
        let Some(slot) = find_slot_mut(&mut pumps, index) else {
            return Err(GattClientError::NoPump);
        };
        match slot.core.take() {
            Some(core) => core,
            None => return Err(GattClientError::Busy),
        }
    };
    let out = f(&mut core);
    let mut pumps = PUMPS.lock();
    if let Some(slot) = find_slot_mut(&mut pumps, index) {
        slot.core = Some(core);
    }
    Ok(out)
}

/// Discover all primary services in `[start, end]` on controller
/// `index`'s central-role connection `handle`.
pub fn gatt_client_discover_services(
    index: usize,
    handle: u16,
    start: u16,
    end: u16,
) -> Result<(), GattClientError> {
    with_client_core(index, |core| {
        core.gatt_client_discover_services(handle, start, end)
    })?
}

/// Discover all characteristics in `[start, end]` on controller
/// `index`'s central-role connection `handle`.
pub fn gatt_client_discover_characteristics(
    index: usize,
    handle: u16,
    start: u16,
    end: u16,
) -> Result<(), GattClientError> {
    with_client_core(index, |core| {
        core.gatt_client_discover_characteristics(handle, start, end)
    })?
}

/// Discover all descriptors in `[start, end]` on controller
/// `index`'s central-role connection `handle`.
pub fn gatt_client_discover_descriptors(
    index: usize,
    handle: u16,
    start: u16,
    end: u16,
) -> Result<(), GattClientError> {
    with_client_core(index, |core| {
        core.gatt_client_discover_descriptors(handle, start, end)
    })?
}

/// Read one characteristic value by handle on controller `index`'s
/// central-role connection `handle`.
pub fn gatt_client_read(
    index: usize,
    handle: u16,
    value_handle: u16,
) -> Result<(), GattClientError> {
    with_client_core(index, |core| core.gatt_client_read(handle, value_handle))?
}

/// Write one characteristic value by handle (Write Request, with
/// response) on controller `index`'s central-role connection
/// `handle`.
pub fn gatt_client_write(
    index: usize,
    handle: u16,
    value_handle: u16,
    value: &[u8],
) -> Result<(), GattClientError> {
    with_client_core(index, |core| {
        core.gatt_client_write(handle, value_handle, value)
    })?
}

/// Subscribe to notifications (`notify == true`) or indications
/// on a characteristic via its CCCD, on controller `index`'s
/// central-role connection `handle`.
pub fn gatt_client_subscribe(
    index: usize,
    handle: u16,
    cccd_handle: u16,
    notify: bool,
) -> Result<(), GattClientError> {
    with_client_core(index, |core| {
        core.gatt_client_subscribe(handle, cccd_handle, notify)
    })?
}

fn gatt_client_records<T: Clone>(
    index: usize,
    handle: u16,
    f: impl FnOnce(&gatt_client::Client) -> &[T],
) -> Option<Vec<T>> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.client.as_ref())
            .map(|client| f(client).to_vec())
    })
    .ok()
    .flatten()
}

/// Services from the last completed primary-service discovery on
/// controller `index`'s central-role connection `handle`.
pub fn gatt_client_services(index: usize, handle: u16) -> Option<Vec<crate::gatt::ServiceRecord>> {
    gatt_client_records(index, handle, |client| client.services())
}

/// Characteristics accumulated across completed characteristic
/// discoveries on controller `index`'s central-role connection
/// `handle`.
pub fn gatt_client_characteristics(
    index: usize,
    handle: u16,
) -> Option<Vec<crate::gatt::CharacteristicRecord>> {
    gatt_client_records(index, handle, |client| client.characteristics())
}

/// Descriptors accumulated across completed descriptor discoveries
/// on controller `index`'s central-role connection `handle`.
pub fn gatt_client_descriptors(
    index: usize,
    handle: u16,
) -> Option<Vec<crate::gatt::DescriptorRecord>> {
    gatt_client_records(index, handle, |client| client.descriptors())
}

/// CCCD handles with a live subscription from controller `index`'s
/// central-role connection `handle`.
pub fn gatt_client_subscribed(index: usize, handle: u16) -> Option<Vec<u16>> {
    gatt_client_records(index, handle, |client| client.subscribed())
}

/// Value from the last completed read on controller `index`'s
/// central-role connection `handle`, if any.
pub fn gatt_client_last_read(index: usize, handle: u16) -> Option<(u16, Vec<u8>)> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.client.as_ref())
            .and_then(|client| client.last_read())
    })
    .ok()
    .flatten()
}

/// Failure that terminated the last client operation on controller
/// `index`'s central-role connection `handle`, if any.
pub fn gatt_client_last_error(index: usize, handle: u16) -> Option<gatt_client::ClientFailure> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.client.as_ref())
            .and_then(|client| client.last_error())
    })
    .ok()
    .flatten()
}

/// Drain queued notifications (handle, value) on controller
/// `index`'s central-role connection `handle`.
pub fn gatt_client_take_notifications(index: usize, handle: u16) -> Option<Vec<(u16, Vec<u8>)>> {
    with_client_core(index, |core| {
        core.connection_mut(handle)
            .and_then(|c| c.client.as_mut())
            .map(|client| client.take_notifications())
    })
    .ok()
    .flatten()
}

// ── HOGP client free API (issue #1314) ─────────────────────────────
//
// Caller flow on a central-role connection, after GATT discovery:
// 1. `hogp_attach` builds the client from discovery records.
// 2. `gatt_client_read` the HID Information / Report Map / Report
//    Reference handles, then `hogp_note_last_read` after each.
// 3. `hogp_protocol_mode_write` + `gatt_client_write` to select
//    boot protocol (when Protocol Mode exists), then
//    `hogp_note_boot_mode` on the Write Response.
// 4. One `gatt_client_subscribe` per `hogp_subscribe_targets` entry.
// 5. `hogp_route_drained` whenever notifications arrive: it drains
//    the client queue and routes each payload to the input rings.
// 6. `hogp_take_undecoded` drains staged report-protocol payloads.
// All return `None` when the pump, connection, client, or HOGP
// record is absent; attach additionally returns `None` when the
// peer exposes no usable HID service.

/// Attach a HOGP client to controller `index`'s central-role
/// connection `handle`, from the GATT client's discovery records.
/// Returns the discovered handle layout.
pub fn hogp_attach(index: usize, handle: u16) -> Option<HogpHandles> {
    with_client_core(index, |core| {
        let conn = core.connection_mut(handle)?;
        let client = conn.client.as_ref()?;
        let hogp = HogpClient::from_records(
            client.services(),
            client.characteristics(),
            client.descriptors(),
        )?;
        conn.hogp = Some(hogp);
        conn.hogp.as_ref().map(|h| h.handles().clone())
    })
    .ok()
    .flatten()
}

/// Discovered HOGP handle layout for an attached connection.
pub fn hogp_handles(index: usize, handle: u16) -> Option<HogpHandles> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.hogp.as_ref())
            .map(|h| h.handles().clone())
    })
    .ok()
    .flatten()
}

/// Feed the GATT client's last read into the HOGP record (HID
/// Information, Report Map, or a Report Reference descriptor).
/// Returns whether the value was consumed by the HOGP record.
pub fn hogp_note_last_read(index: usize, handle: u16) -> Option<bool> {
    with_client_core(index, |core| {
        let conn = core.connection_mut(handle)?;
        let (h, v) = conn.client.as_ref()?.last_read()?;
        conn.hogp.as_mut().map(|hogp| hogp.note_read(h, &v))
    })
    .ok()
    .flatten()
}

/// The Protocol Mode write selecting boot protocol, if the peer
/// exposes Protocol Mode: (value handle, `[BOOT 0x00]`).
pub fn hogp_protocol_mode_write(index: usize, handle: u16) -> Option<(u16, [u8; 1])> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.hogp.as_ref())
            .and_then(|h| h.protocol_mode_write())
    })
    .ok()
    .flatten()
}

/// Record that the Protocol Mode write completed (boot protocol
/// selected).
pub fn hogp_note_boot_mode(index: usize, handle: u16) -> Option<()> {
    with_client_core(index, |core| {
        core.connection_mut(handle)
            .and_then(|c| c.hogp.as_mut())
            .map(|h| h.note_boot_mode())
    })
    .ok()
    .flatten()
}

/// CCCD subscription targets: (cccd handle, notify?).
pub fn hogp_subscribe_targets(index: usize, handle: u16) -> Option<Vec<(u16, bool)>> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.hogp.as_ref())
            .map(|h| h.subscribe_targets().to_vec())
    })
    .ok()
    .flatten()
}

/// Drain the GATT client's notification queue and route each
/// payload through the HOGP record into the input rings.
/// Returns the number of input events pushed.
pub fn hogp_route_drained(index: usize, handle: u16) -> Option<usize> {
    with_client_core(index, |core| {
        let conn = core.connection_mut(handle)?;
        let notifs = conn.client.as_mut()?.take_notifications();
        let hogp = conn.hogp.as_mut()?;
        Some(notifs.iter().map(|(h, v)| hogp.route(*h, v)).sum())
    })
    .ok()
    .flatten()
}

/// Drain staged report-protocol input Reports: (report ID, raw value).
pub fn hogp_take_undecoded(index: usize, handle: u16) -> Option<Vec<(u8, Vec<u8>)>> {
    with_client_core(index, |core| {
        core.connection_mut(handle)
            .and_then(|c| c.hogp.as_mut())
            .map(|h| h.take_undecoded())
    })
    .ok()
    .flatten()
}

/// Last Report Map bytes read from the peer, if attached.
pub fn hogp_report_map(index: usize, handle: u16) -> Option<Vec<u8>> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.hogp.as_ref())
            .map(|h| h.report_map().to_vec())
    })
    .ok()
    .flatten()
}

/// Last decoded HID Information value, once read.
pub fn hogp_hid_info(index: usize, handle: u16) -> Option<HidInformation> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.hogp.as_ref())
            .and_then(|h| h.hid_info())
    })
    .ok()
    .flatten()
}

/// Whether boot protocol was selected on this connection.
pub fn hogp_boot_mode(index: usize, handle: u16) -> Option<bool> {
    with_client_core(index, |core| {
        core.connection(handle)
            .and_then(|c| c.hogp.as_ref())
            .map(|h| h.boot_mode())
    })
    .ok()
    .flatten()
}

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

    // Parked (mgmt power-off, system suspend, or USB autosuspend):
    // do not poll the transport — a gated USB port fails every
    // poll and the pump would spin on transport errors. The
    // outbound flush below still runs: an empty queue returns
    // without touching the transport, and a queued packet wakes
    // the port through the transport's TX-demand resume instead
    // of stalling until a remote-wakeup edge (#820).
    let parked = crate::pm::is_parked(index);

    for _ in 0..MAX_PACKETS_PER_STEP {
        if parked {
            break;
        }
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
        if parked {
            break;
        }
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

    // SCO: drain Synchronous Data frames into their links' staging.
    // A transport without SCO (no isoch endpoints) reports
    // Unsupported on every poll — that is an expected "no data",
    // not a transport error.
    for _ in 0..MAX_PACKETS_PER_STEP {
        if parked {
            break;
        }
        match core.transport.recv_sco() {
            Ok(Some(bytes)) => {
                if let Some(frame) = ScoData::decode(&bytes) {
                    if core.route_sco(frame) {
                        step.sco_received += 1;
                        core.stats.sco_received += 1;
                        narf_filesystem::bluetooth::publish_bt_channel_event();
                    }
                }
            }
            Ok(None) => break,
            Err(TransportError::Unsupported) => break,
            Err(_) => {
                core.stats.transport_errors += 1;
                break;
            }
        }
    }

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
        /// Raw SCO packets the scripted peer delivers.
        sco_inbox: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        /// Raw SCO packets the host sent.
        sent_sco: IrqSafeSpinLock<Vec<Vec<u8>>>,
        /// When set, `send_sco` / `recv_sco` fail closed with
        /// `Unsupported` (a controller with no isoch endpoints).
        sco_unsupported: IrqSafeSpinLock<bool>,
    }

    impl ScriptedTransport {
        fn new() -> Self {
            Self {
                events: IrqSafeSpinLock::new(VecDeque::new()),
                acl_inbox: IrqSafeSpinLock::new(VecDeque::new()),
                sent_commands: IrqSafeSpinLock::new(Vec::new()),
                sent_acl: IrqSafeSpinLock::new(Vec::new()),
                sco_inbox: IrqSafeSpinLock::new(VecDeque::new()),
                sent_sco: IrqSafeSpinLock::new(Vec::new()),
                sco_unsupported: IrqSafeSpinLock::new(false),
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
        fn enqueue_sco(&self, bytes: Vec<u8>) {
            self.sco_inbox.lock().push_back(bytes);
        }
        /// Fail closed on SCO I/O, like a controller with no isoch
        /// endpoints (#817).
        fn set_sco_unsupported(&self, unsupported: bool) {
            *self.sco_unsupported.lock() = unsupported;
        }
        fn sent_opcodes(&self) -> Vec<u16> {
            self.sent_commands.lock().iter().map(|c| c.opcode).collect()
        }
        fn sent_command_params(&self) -> Vec<(u16, Vec<u8>)> {
            self.sent_commands
                .lock()
                .iter()
                .map(|c| (c.opcode, c.params.clone()))
                .collect()
        }
        fn sent_commands(&self) -> Vec<Command> {
            self.sent_commands.lock().clone()
        }
        fn sent_acl_frames(&self) -> Vec<(u16, BFrame)> {
            self.sent_acl
                .lock()
                .iter()
                .filter_map(|bytes| AclData::decode(bytes))
                .filter_map(|acl| BFrame::decode(&acl.data).map(|f| (acl.handle, f)))
                .collect()
        }
        fn sent_sco_frames(&self) -> Vec<ScoData> {
            self.sent_sco
                .lock()
                .iter()
                .filter_map(|bytes| ScoData::decode(bytes))
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
        fn send_sco(&self, data: &[u8]) -> Result<(), TransportError> {
            if *self.sco_unsupported.lock() {
                return Err(TransportError::Unsupported);
            }
            self.sent_sco.lock().push(data.to_vec());
            Ok(())
        }
        fn recv_sco(&self) -> Result<Option<Vec<u8>>, TransportError> {
            if *self.sco_unsupported.lock() {
                return Err(TransportError::Unsupported);
            }
            Ok(self.sco_inbox.lock().pop_front())
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
        // Identity reads (§7.4.14/§7.4.23): the name/class mgmt
        // READ_INFO reports (issue #815). `cc`'s `ret` starts with
        // the status byte, so the name payload is 1 + 248 bytes.
        let mut name_ret = alloc::vec![0u8; 249];
        name_ret[1..10].copy_from_slice(b"narf-pump");
        fake.enqueue_event(cc(op::HCI_READ_LOCAL_NAME, &name_ret));
        fake.enqueue_event(cc(op::HCI_READ_CLASS_OF_DEVICE, &[0, 0x04, 0x0C, 0x02]));
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
        // Exact mandatory command order (Vol 4 Part E §3), plus the
        // identity reads (issue #815).
        let expected = [
            op::HCI_RESET,
            op::HCI_READ_LOCAL_VERSION,
            op::HCI_READ_BD_ADDR,
            op::HCI_READ_BUFFER_SIZE,
            op::HCI_SET_EVENT_MASK,
            op::HCI_READ_LOCAL_NAME,
            op::HCI_READ_CLASS_OF_DEVICE,
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

    /// #820: a parked controller's pump step does not poll the
    /// transport — queued events/ACL sit untouched until the park
    /// clears, then flow on the next step. Covers the mgmt-off
    /// and autosuspend parks through the same gate.
    fn smoke_pump_parked_step_skips_transport() -> TestResult {
        reset_all();
        crate::pm::__reset_for_test();
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            crate::pm::__reset_for_test();
            TestResult::Fail(msg)
        };

        let fake = Arc::new(ScriptedTransport::new());
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport);
        script_successful_bringup(&fake);

        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        if outcomes.len() != 1 || outcomes[0].result.is_err() {
            return fail("bring-up against fake controller failed");
        }

        // Queue one event + one ACL blob, then park (autosuspend).
        fake.enqueue_event(le_connection_complete(
            0x0040,
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ));
        // Minimal ACL blob (handle 0x0040, 4 payload bytes); the
        // pump counts it on receipt even though no connection
        // exists to route it to.
        fake.enqueue_acl(alloc::vec![0x40, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03]);
        crate::pm::park_autosuspend(0);

        let step = pump_once(0);
        if !step.is_idle() || step.events != 0 || step.acl_received != 0 {
            return fail("parked pump step polled the transport");
        }
        if connection_count(0) != Some(0) {
            return fail("parked pump step dispatched the queued event");
        }
        // Unpark: the queued event + ACL flow on the next step.
        crate::pm::unpark_autosuspend(0);
        let step = pump_once(0);
        if step.events != 1 || step.acl_received != 1 {
            return fail("unparked pump step did not drain the queued traffic");
        }
        if connection_count(0) != Some(1) {
            return fail("pump did not track the connection after unpark");
        }
        reset_all();
        crate::pm::__reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_parked_step_skips_transport);

    /// #891: the pump mirrors its connection table into sysfs — LE
    /// connect gains the `hci<N>:<handle>` child, disconnect removes
    /// it again.
    fn smoke_pump_sysfs_connection_child_lifecycle() -> TestResult {
        use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;
        sysfs_reset();
        reset_all();
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            sysfs_reset();
            TestResult::Fail(msg)
        };

        let fake = Arc::new(ScriptedTransport::new());
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport);
        script_successful_bringup(&fake);

        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        if outcomes.len() != 1 || outcomes[0].result.is_err() {
            return fail("bring-up against fake controller failed");
        }

        // LE connect on handle 0x0040 (decimal 64 in the child name).
        let handle = 0x0040;
        fake.enqueue_event(le_connection_complete(
            handle,
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            return fail("pump did not track the LE connection");
        }
        let hci_kobj = match crate::sysfs_bridge::hci_kobject(0) {
            Some(k) => k,
            None => return fail("no controller kobject published for hci0"),
        };
        let child = match hci_kobj.get_child("hci0:64") {
            Some(c) => c,
            None => return fail("hci0:64 child missing after LE connect"),
        };
        match child.attr_show("address") {
            Some(v) if v.contains("B5:B4:B3:B2:B1:B0") => {}
            _ => return fail("conn address attr missing or mismatched"),
        }
        match child.attr_show("type") {
            Some(v) if v.contains("LE") => {}
            _ => return fail("conn type attr should be LE"),
        }

        // Disconnect removes the child again.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x40, 0x00, 0x13],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(0) {
            return fail("connection state survived disconnect");
        }
        if hci_kobj.get_child("hci0:64").is_some() {
            return fail("sysfs child survived disconnect");
        }
        reset_all();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_sysfs_connection_child_lifecycle
    );

    /// #890: detach composition — attach → bring-up → pump → USB
    /// removal tears everything down: the pump slot is gone, the
    /// controller is unregistered, the transport is unregistered,
    /// the sysfs `hci<N>` node is gone, mgmt `INDEX_REMOVED` is
    /// published, and `READ_INDEX_LIST` is empty. A Disconnection
    /// Complete arriving during teardown must not resurrect the
    /// controller, and re-registering the same transport afterwards
    /// is a fresh controller reusing the ordinal — never the
    /// detached state coming back.
    fn smoke_pump_detach_teardown_publishes_index_removed() -> TestResult {
        use narf_filesystem::sysfs::__reset_for_test as sysfs_reset;

        // mgmt event opcodes (mgmt.h MGMT_EV_*); the constants are
        // private to the mgmt module.
        const EV_INDEX_ADDED: u16 = 0x0004;
        const EV_INDEX_REMOVED: u16 = 0x0005;
        const OP_READ_INDEX_LIST: u16 = 0x0003;
        const MGMT_INDEX_NONE: u16 = 0xffff;

        static CAPTURED: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());
        fn capture_sink(event: &[u8]) {
            CAPTURED.lock().push(event.to_vec());
        }
        fn is_mgmt_event(frame: &[u8], opcode: u16, index: u16) -> bool {
            frame.len() >= 6
                && u16::from_le_bytes([frame[0], frame[1]]) == opcode
                && u16::from_le_bytes([frame[2], frame[3]]) == index
        }

        sysfs_reset();
        reset_all();
        CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        let fail = |msg: &'static str| -> TestResult {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            sysfs_reset();
            TestResult::Fail(msg)
        };

        let fake = Arc::new(ScriptedTransport::new());
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport.clone());
        script_successful_bringup(&fake);

        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        if outcomes.len() != 1 || outcomes[0].result.is_err() {
            return fail("bring-up against fake controller failed");
        }
        // Attach published the sysfs node and INDEX_ADDED.
        if crate::sysfs_bridge::hci_kobject(0).is_none() {
            return fail("no controller kobject published for hci0");
        }
        if !CAPTURED
            .lock()
            .iter()
            .any(|e| is_mgmt_event(e, EV_INDEX_ADDED, 0))
        {
            return fail("INDEX_ADDED was not published on registration");
        }

        // Pump a live LE connection, mirrored into sysfs.
        let handle = 0x0040;
        fake.enqueue_event(le_connection_complete(
            handle,
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            return fail("pump did not track the LE connection");
        }
        let hci_kobj = match crate::sysfs_bridge::hci_kobject(0) {
            Some(k) => k,
            None => return fail("controller kobject vanished before detach"),
        };
        if hci_kobj.get_child("hci0:64").is_none() {
            return fail("hci0:64 child missing before detach");
        }

        // ── USB removal ──────────────────────────────────────────
        CAPTURED.lock().clear();
        if !crate::controller::unregister_controller(0) {
            return fail("unregister_controller refused a live controller");
        }
        if crate::controller::controller_count() != 0 {
            return fail("controller registry not empty after detach");
        }
        if crate::transport::transport_count() != 0 {
            return fail("transport registry not empty after detach");
        }
        if crate::controller::is_live(0) {
            return fail("detached controller still reports live");
        }
        if connection_count(0).is_some() || !pump_once(0).is_idle() {
            return fail("pump slot survived detach");
        }
        if crate::sysfs_bridge::hci_kobject(0).is_some() {
            return fail("sysfs hci0 node survived detach");
        }
        // INDEX_REMOVED exactly once, and no INDEX_ADDED after the
        // removal point.
        let removed = CAPTURED
            .lock()
            .iter()
            .filter(|e| is_mgmt_event(e, EV_INDEX_REMOVED, 0))
            .count();
        if removed != 1 {
            return fail("INDEX_REMOVED was not published exactly once");
        }
        if CAPTURED
            .lock()
            .iter()
            .any(|e| is_mgmt_event(e, EV_INDEX_ADDED, 0))
        {
            return fail("INDEX_ADDED published after detach");
        }
        // READ_INDEX_LIST is empty now.
        let list = crate::mgmt::handle(&[
            (OP_READ_INDEX_LIST & 0xFF) as u8,
            (OP_READ_INDEX_LIST >> 8) as u8,
            (MGMT_INDEX_NONE & 0xFF) as u8,
            (MGMT_INDEX_NONE >> 8) as u8,
            0,
            0,
        ]);
        let count = list
            .first()
            .filter(|r| r.len() >= 11)
            .map(|r| u16::from_le_bytes([r[9], r[10]]));
        if count != Some(0) {
            return fail("READ_INDEX_LIST not empty after detach");
        }
        // Detaching again is an idempotent no-op.
        if crate::controller::unregister_controller(0) {
            return fail("second detach reported success");
        }

        // ── Race: disconnect arriving during teardown ───────────
        // The event sits in the dead transport's queue; nothing
        // drains it into a resurrected controller.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x40, 0x00, 0x13],
        });
        if !pump_once(0).is_idle() {
            return fail("pump step ran on a detached controller");
        }
        if crate::controller::controller_count() != 0
            || crate::transport::transport_count() != 0
            || crate::sysfs_bridge::hci_kobject(0).is_some()
        {
            return fail("late disconnect resurrected detached state");
        }
        if CAPTURED
            .lock()
            .iter()
            .any(|e| is_mgmt_event(e, EV_INDEX_ADDED, 0))
        {
            return fail("late disconnect published INDEX_ADDED");
        }

        // ── Replug: same transport, fresh controller ─────────────
        // The detached slot is reused (ordinal 0 again) with fresh
        // state: no connections, no stale pump core.
        let index = crate::controller::register_ready_transport(
            transport,
            crate::controller::ControllerInfo::default(),
        );
        if index != 0 || crate::controller::controller_count() != 1 {
            return fail("re-registration did not reuse the detached slot");
        }
        if !crate::controller::is_live(0) || connection_count(0) != Some(0) {
            return fail("re-registered controller is not fresh and live");
        }
        if crate::sysfs_bridge::hci_kobject(0).is_none() {
            return fail("re-registered controller published no sysfs node");
        }

        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        sysfs_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_detach_teardown_publishes_index_removed
    );

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

    /// The §2.2.8 f6 message block, in formula order — the
    /// peer-model mirror of production's DhKeyCheckInputs.
    /// Deliberately a separate type, not the production struct:
    /// the peer model shares no code with the SMP state machine,
    /// so a production-side field change cannot silently move
    /// the model's message layout. The caller picks the table
    /// 2.2 orientation by which values it places in `n1`/`n2`
    /// and `a1`/`a2`.
    #[derive(Debug)]
    struct F6Inputs<'a> {
        /// First nonce (Na for Ea, Nb for Eb).
        n1: &'a [u8; 16],
        /// Second nonce (Nb for Ea, Na for Eb).
        n2: &'a [u8; 16],
        /// The 128-bit random (zero for Just Works / Numeric
        /// Comparison).
        r: &'a [u8; 16],
        /// IO capabilities.
        iocap: &'a [u8; 3],
        /// First address (A for Ea, B for Eb): type byte + BD_ADDR.
        a1: &'a [u8; 7],
        /// Second address (B for Ea, A for Eb).
        a2: &'a [u8; 7],
    }

    /// f6 (Core 5.3 Vol 3 Part H §2.2.8): AES-CMAC keyed on the
    /// MacKey over `n1 ‖ n2 ‖ r ‖ iocap ‖ a1 ‖ a2`, computed with
    /// the fixture CMAC. `inputs` carries the message block in
    /// formula order; the caller supplies the table 2.2
    /// orientation for the side being modelled — the responder's
    /// check swaps both the nonce order and the address order.
    fn peer_f6(sbox: &[u8; 256], mac_key: &[u8; 16], inputs: &F6Inputs<'_>) -> [u8; 16] {
        let mut msg = [0u8; 65];
        msg[0..16].copy_from_slice(inputs.n1);
        msg[16..32].copy_from_slice(inputs.n2);
        msg[32..48].copy_from_slice(inputs.r);
        msg[48..51].copy_from_slice(inputs.iocap);
        msg[51..58].copy_from_slice(inputs.a1);
        msg[58..65].copy_from_slice(inputs.a2);
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

    /// (responder, initiator wire X, responder wire X): the
    /// drive_to_public_key outcome, aliased so the return type
    /// stays under clippy's type-complexity threshold.
    type PublicKeyOutcome = (Responder<NarfSmpCrypto>, [u8; 32], [u8; 32]);

    /// Drive the production responder through the feature
    /// exchange and the public-key exchange, asserting the ECDH
    /// DHKey against the peer model. Returns the responder in
    /// SentPublicKey plus the two wire public-key X coordinates.
    /// Negative fixtures take the exchange off-script from here.
    fn drive_to_public_key(
        initiator_io: u8,
        initiator_auth: u8,
        peer_priv: &Fe,
    ) -> Result<PublicKeyOutcome, &'static str> {
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
            || out[0].payload != [0x01, 0x00, 0x0D, 16, 0x06, 0x06]
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
        // Numeric Comparison parks here (§2.3.5.6.2 steps 7–8):
        // the user confirms the g2 value before the DHKey Check
        // is answered. Every other method proceeds straight to
        // WaitDhKeyCheck.
        if r.method == smp::PairingMethod::NumericComparison {
            if r.state != smp::ResponderState::WaitUserConfirm {
                return Err("responder did not park at WaitUserConfirm");
            }
            if r.take_attention()
                != Some(smp::SmpAttention::UserConfirm(
                    r.numeric_comparison.unwrap_or(0),
                ))
            {
                return Err("responder did not raise the UserConfirm attention");
            }
        } else if r.state != smp::ResponderState::WaitDhKeyCheck {
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
                &sbox,
                &mac_key,
                &F6Inputs {
                    n1: &SMP_NA,
                    n2: &nb,
                    r: &[0u8; 16],
                    iocap: &iocap_a,
                    a1: &SMP_IAT,
                    a2: &SMP_RAT,
                },
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
                &sbox,
                &mac_key,
                &F6Inputs {
                    n1: &nb,
                    n2: &SMP_NA,
                    r: &[0u8; 16],
                    iocap: &iocap_b,
                    a1: &SMP_RAT,
                    a2: &SMP_IAT,
                },
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
        if peer_f6(
            &sbox,
            &want_mac_key,
            &F6Inputs {
                n1: &n1,
                n2: &n2,
                r: &r,
                iocap: &iocap,
                a1: &a1,
                a2: &a2,
            },
        ) != want_f6
        {
            return TestResult::Fail("peer model f6 disagrees with Appendix D.4");
        }
        if smp::dhkey_check_value(
            &NarfSmpCrypto,
            &want_mac_key,
            &smp::DhKeyCheckInputs {
                n1: &n1,
                n2: &n2,
                r: &r,
                iocap: &iocap,
                a1: &a1,
                a2: &a2,
            },
        ) != want_f6
        {
            return TestResult::Fail("production f6 disagrees with Appendix D.4");
        }
        // D.5 — g2(U, V, X, Y) = AES-CMAC_X(U ‖ V ‖ Y) mod 2^32,
        // displayed mod 10^6 (§2.2.9). The D.5 inputs reuse the
        // D.2 public keys and nonces: U = initiator PKx, V =
        // responder PKx, X = Na, Y = Nb; the published g2 is
        // 0x2f9ed5ba = 798938554, so the compare value is 938554.
        if peer_g2(&sbox, &u, &v, &n1, &n2) != 938_554 {
            return TestResult::Fail("peer model g2 disagrees with Appendix D.5");
        }
        if smp::numeric_comparison_value(&NarfSmpCrypto, &u, &v, &n1, &n2) != 938_554 {
            return TestResult::Fail("production g2 disagrees with Appendix D.5");
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
                &F6Inputs {
                    n1: &SMP_NA,
                    n2: &out.nb,
                    r: &[0u8; 16],
                    iocap: &iocap_a,
                    a1: &SMP_IAT,
                    a2: &SMP_RAT,
                },
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
        .and_then(|mut out| {
            let r = &mut out.responder;
            if r.method != smp::PairingMethod::NumericComparison {
                return Err("negotiated method is not Numeric Comparison");
            }
            let want = peer_g2(&sbox, &out.peer_pk_x, &out.resp_pk_x, &SMP_NA, &out.nb);
            if r.numeric_comparison != Some(want) {
                return Err("g2 mismatch: production CMAC disagrees with the independent peer");
            }
            // The user confirms the values match: the responder
            // resumes to WaitDhKeyCheck with no PDU out, and
            // stage 2 (§2.3.5.6.5) completes exactly as Just
            // Works does.
            if r.confirm_numeric_comparison(true).is_err() {
                return Err("responder rejected the numeric comparison confirm");
            }
            if r.state != smp::ResponderState::WaitDhKeyCheck {
                return Err("responder did not resume to WaitDhKeyCheck after confirm");
            }
            let mac_key = out.mac_key;
            let nb = out.nb;
            // Ea = f6(MacKey, Na, Nb, 0, IOcapA, A, B) (§2.2.8
            // table 2.2), with IOcapA in §2.2.8 octet order
            // [AuthReq, OOB, IO capability] taken from this
            // fixture's Pairing Request (KeyboardDisplay + MITM).
            let iocap_a: [u8; 3] = [
                smp::AUTH_BONDING | smp::AUTH_SC | smp::AUTH_MITM,
                0,
                smp::IoCapability::KeyboardDisplay as u8,
            ];
            let ea = peer_f6(
                &sbox,
                &mac_key,
                &F6Inputs {
                    n1: &SMP_NA,
                    n2: &nb,
                    r: &[0u8; 16],
                    iocap: &iocap_a,
                    a1: &SMP_IAT,
                    a2: &SMP_RAT,
                },
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
            let iocap_b: [u8; 3] = [0x0D, 0, smp::IoCapability::DisplayYesNo as u8];
            let want_eb = peer_f6(
                &sbox,
                &mac_key,
                &F6Inputs {
                    n1: &nb,
                    n2: &SMP_NA,
                    r: &[0u8; 16],
                    iocap: &iocap_b,
                    a1: &SMP_RAT,
                    a2: &SMP_IAT,
                },
            );
            if check[0].payload != want_eb {
                return Err("Eb mismatch: production f6 disagrees with the independent peer");
            }
            if r.state != smp::ResponderState::Done {
                return Err("responder did not reach Done after the confirmed exchange");
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

    /// #889 LE fixture: open → data → disconnect on a credit-based
    /// channel, against the scripted-controller harness. The test LE
    /// PSM 0x0080 is an arbitrary fixture value, not an assigned
    /// SPSM — the registry is value-agnostic and both sides are
    /// fixtures.
    fn smoke_pump_le_coc_open_data_disconnect() -> TestResult {
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
        let handle = 0x0040;
        fake.enqueue_event(le_connection_complete(
            handle,
            [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("LE connection not tracked");
        }
        register_le_psm(0, 0x0080);

        // Open: COC Request (id 0x07, PSM 0x0080, peer CID 0x0041,
        // MTU 1024, MPS 256, 8 initial credits).
        let open =
            l2cap::build_le_credit_based_connection_request(0x07, 0x0080, 0x0041, 1024, 256, 8);
        let mut payload = Vec::new();
        open.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_LE_SIGNALLING, payload)));
        let _ = pump_once(0);
        // Exact response bytes: code 0x15, id 0x07, len 12, Dest
        // 0x0041 (peer CID), Source 0x0040 (first LE alloc), result
        // 0, MTU 1024, MPS 256, credits 16.
        let expected_rsp: Vec<u8> = alloc::vec![
            0x15, 0x07, 0x0C, 0x00, 0x41, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01,
            0x10, 0x00,
        ];
        let frames = fake.sent_acl_frames();
        let rsp_ok = frames
            .iter()
            .any(|(_, f)| f.cid == CID_LE_SIGNALLING && f.payload == expected_rsp);
        if !rsp_ok {
            reset_all();
            return TestResult::Fail("LE COC open response bytes mismatch");
        }

        // Data: single-K-frame SDU "hi" on our local CID 0x0040.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![0x02, 0x00, b'h', b'i']),
        ));
        let _ = pump_once(0);
        if drain_channel_rx(0, handle, 0x0040) != Some(alloc::vec![alloc::vec![b'h', b'i']]) {
            reset_all();
            return TestResult::Fail("LE COC SDU not staged");
        }
        // Spend the grant down to the top-up threshold: 11 more
        // single-K-frame SDUs (12 spent of 16 -> 4 left -> top-up).
        for _ in 0..11 {
            fake.enqueue_acl(acl_packet(
                handle,
                &BFrame::new(0x0040, alloc::vec![0x01, 0x00, b'x']),
            ));
        }
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let credit_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_LE_SIGNALLING
                && f.payload == alloc::vec![0x16, 0x00, 0x04, 0x00, 0x40, 0x00, 0x0C, 0x00]
        });
        if !credit_ok {
            reset_all();
            return TestResult::Fail("LE COC top-up Flow Control Credit missing");
        }
        if drain_channel_rx(0, handle, 0x0040).map(|v| v.len()) != Some(11) {
            reset_all();
            return TestResult::Fail("LE COC staged SDU count mismatch");
        }

        // Disconnect: request on LE signalling, Dest = our CID.
        let disc = l2cap::build_disconnection_request(0x09, 0x0040, 0x0041);
        let mut payload = Vec::new();
        disc.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_LE_SIGNALLING, payload)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_LE_SIGNALLING
                && f.payload == alloc::vec![0x07, 0x09, 0x04, 0x00, 0x40, 0x00, 0x41, 0x00]
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("LE COC disconnection response missing");
        }
        if drain_channel_rx(0, handle, 0x0040).is_some() {
            reset_all();
            return TestResult::Fail("LE COC channel survived disconnect");
        }
        // Data on the freed CID is dropped and counted.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![0x01, 0x00, b'z']),
        ));
        let _ = pump_once(0);
        let dropped = stats(0).map(|s| s.frames_dropped_unrouted_cid) == Some(1);
        reset_all();
        if !dropped {
            return TestResult::Fail("data on freed CID not counted as dropped");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_le_coc_open_data_disconnect);

    /// #814: the AF_BLUETOOTH socket path over a scripted LE CoC
    /// conversation — register → peer open → accept-claim → recv →
    /// send → disconnect, all through the top-level pump API the
    /// socket layer calls via the filesystem broker.
    fn smoke_pump_bt_socket_le_coc_path() -> TestResult {
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
        let handle = 0x0040;
        let peer = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        fake.enqueue_event(le_connection_complete(handle, peer));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("LE connection not tracked");
        }
        // Register: first call wins, second reports InUse.
        if register_psm(0, 0x0080, true) != BtRegisterStatus::Registered {
            reset_all();
            return TestResult::Fail("LE PSM registration should succeed");
        }
        if register_psm(0, 0x0080, true) != BtRegisterStatus::InUse {
            reset_all();
            return TestResult::Fail("second LE PSM registration should report InUse");
        }
        if pending_channel(0, 0x0080, true) {
            reset_all();
            return TestResult::Fail("no channel should be pending before the peer opens");
        }
        // Peer opens the CoC (id 0x07, PSM 0x0080, peer CID 0x0041,
        // MTU 1024, MPS 256, 8 initial credits).
        let open =
            l2cap::build_le_credit_based_connection_request(0x07, 0x0080, 0x0041, 1024, 256, 8);
        let mut payload = Vec::new();
        open.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_LE_SIGNALLING, payload)));
        let _ = pump_once(0);
        if !pending_channel(0, 0x0080, true) {
            reset_all();
            return TestResult::Fail("opened channel should be pending for accept");
        }
        let claimed = match take_pending_channel(0, 0x0080, true) {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("accept-claim should return the opened channel");
            }
        };
        if claimed.0 != handle || claimed.1 != 0x0040 || claimed.2 != 0x0041 {
            reset_all();
            return TestResult::Fail("claimed channel handle/CID mismatch");
        }
        if claimed.3[1..7] != peer {
            reset_all();
            return TestResult::Fail("claimed channel peer address mismatch");
        }
        // A claim is single-use: the same channel never accepts twice.
        if take_pending_channel(0, 0x0080, true).is_some() || pending_channel(0, 0x0080, true) {
            reset_all();
            return TestResult::Fail("claimed channel must not be pending again");
        }
        // Peer data: single-K-frame SDU "hi" on our local CID.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![0x02, 0x00, b'h', b'i']),
        ));
        let _ = pump_once(0);
        if !channel_rx_pending(0, handle, 0x0040) {
            reset_all();
            return TestResult::Fail("staged SDU should read pending");
        }
        if drain_channel_rx(0, handle, 0x0040) != Some(alloc::vec![alloc::vec![b'h', b'i']]) {
            reset_all();
            return TestResult::Fail("LE COC SDU not staged for the socket");
        }
        if channel_rx_pending(0, handle, 0x0040) {
            reset_all();
            return TestResult::Fail("drained channel should not read pending");
        }
        // Socket send: one K-frame ("pong" + length prefix) on the
        // peer CID 0x0041, credits deducted (8 granted - 1 spent).
        match send_channel(0, handle, 0x0040, b"pong") {
            Ok(4) => {}
            _ => {
                reset_all();
                return TestResult::Fail("LE COC send should report 4 bytes");
            }
        }
        let frames = fake.sent_acl_frames();
        let send_ok = frames.iter().any(|(h, f)| {
            *h == handle
                && f.cid == 0x0041
                && f.payload == alloc::vec![0x04, 0x00, b'p', b'o', b'n', b'g']
        });
        if !send_ok {
            reset_all();
            return TestResult::Fail("LE COC send K-frame missing from the wire");
        }
        // Socket close: Disconnection Request on LE signalling, then
        // the channel is gone for good.
        if !disconnect_channel(0, handle, 0x0040) {
            reset_all();
            return TestResult::Fail("disconnect should tear the channel down");
        }
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_LE_SIGNALLING
                && f.payload == alloc::vec![0x06, 0x00, 0x04, 0x00, 0x41, 0x00, 0x40, 0x00]
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("disconnect request missing from the wire");
        }
        if drain_channel_rx(0, handle, 0x0040).is_some()
            || channel_rx_pending(0, handle, 0x0040)
            || send_channel(0, handle, 0x0040, b"x").is_ok()
        {
            reset_all();
            return TestResult::Fail("disconnected channel must be gone");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_socket_le_coc_path);

    /// #1532: outbound LE CoC connect — HCI create, CoC Request,
    /// peer response, data round-trip, disconnect — against the
    /// scripted-controller harness. Fixture PSM 0x0080 is an
    /// arbitrary value, not an assigned SPSM.
    fn smoke_pump_bt_connect_le_coc() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 1; // LE public
        peer[1..7].copy_from_slice(&peer6);
        // Start: LE_Create_Connection goes out, open is pending.
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("first connect should report Pending");
        }
        if !fake.sent_opcodes().contains(&op::HCI_LE_CREATE_CONNECTION) {
            reset_all();
            return TestResult::Fail("LE_Create_Connection not issued");
        }
        // Command Status (accepted) + LE Connection Complete
        // (central role).
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0x00));
        fake.enqueue_event(le_connection_complete_central(handle, peer6));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("LE connection not tracked");
        }
        // Exact CoC Request bytes: code 0x14, id 0x01, len 10, PSM
        // 0x0080, source CID 0x0040 (first LE alloc), MTU 1024,
        // MPS 256, 16 initial credits.
        let expected_req: Vec<u8> = alloc::vec![
            0x14, 0x01, 0x0A, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x04, 0x00, 0x01, 0x10, 0x00,
        ];
        let frames = fake.sent_acl_frames();
        let req_ok = frames
            .iter()
            .any(|(_, f)| f.cid == CID_LE_SIGNALLING && f.payload == expected_req);
        if !req_ok {
            reset_all();
            return TestResult::Fail("LE CoC request bytes mismatch");
        }
        // Still pending until the peer answers.
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("connect should stay Pending before the response");
        }
        // Peer answers: success, peer CID 0x0041, MTU 1024, MPS
        // 256, 8 credits.
        let rsp =
            l2cap::build_le_credit_based_connection_response(0x01, 0x0040, 0x0041, 0, 1024, 256, 8);
        let mut payload = Vec::new();
        rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_LE_SIGNALLING, payload)));
        let _ = pump_once(0);
        if !connect_ready(0, peer, 0x0080, true, false) {
            reset_all();
            return TestResult::Fail("completed open should read ready");
        }
        match connect(0, peer, 0x0080, true, false) {
            BtConnectStatus::Open((h, local, peer_cid, addr)) => {
                if h != handle || local != 0x0040 || peer_cid != 0x0041 || addr != peer {
                    reset_all();
                    return TestResult::Fail("opened channel handle/CID/peer mismatch");
                }
            }
            _ => {
                reset_all();
                return TestResult::Fail("connect should report Open after the response");
            }
        }
        // The open is consumed: the readiness peek clears.
        if connect_ready(0, peer, 0x0080, true, false) {
            reset_all();
            return TestResult::Fail("taken open must not read ready again");
        }
        // Socket send: one K-frame ("pong" + length prefix) on the
        // peer CID 0x0041, credits deducted (8 granted - 1 spent).
        match send_channel(0, handle, 0x0040, b"pong") {
            Ok(4) => {}
            _ => {
                reset_all();
                return TestResult::Fail("LE COC send should report 4 bytes");
            }
        }
        let frames = fake.sent_acl_frames();
        let send_ok = frames.iter().any(|(h, f)| {
            *h == handle
                && f.cid == 0x0041
                && f.payload == alloc::vec![0x04, 0x00, b'p', b'o', b'n', b'g']
        });
        if !send_ok {
            reset_all();
            return TestResult::Fail("LE COC send K-frame missing from the wire");
        }
        // Peer data: single-K-frame SDU "hi" on our local CID.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![0x02, 0x00, b'h', b'i']),
        ));
        let _ = pump_once(0);
        if drain_channel_rx(0, handle, 0x0040) != Some(alloc::vec![alloc::vec![b'h', b'i']]) {
            reset_all();
            return TestResult::Fail("LE COC SDU not staged for the socket");
        }
        // Socket close: Disconnection Request on LE signalling,
        // then the channel is gone for good.
        if !disconnect_channel(0, handle, 0x0040) {
            reset_all();
            return TestResult::Fail("disconnect should tear the channel down");
        }
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_LE_SIGNALLING
                && f.payload == alloc::vec![0x06, 0x00, 0x04, 0x00, 0x41, 0x00, 0x40, 0x00]
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("disconnect request missing from the wire");
        }
        if drain_channel_rx(0, handle, 0x0040).is_some() {
            reset_all();
            return TestResult::Fail("disconnected channel must be gone");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_le_coc);

    /// #1532: outbound LE CoC connect against a link that already
    /// exists (peripheral-role ACL) — no HCI create is issued and
    /// the CoC Request goes out on the first call.
    fn smoke_pump_bt_connect_le_coc_existing_acl() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 1;
        peer[1..7].copy_from_slice(&peer6);
        // Peripheral-role link already up (peer connected to us).
        fake.enqueue_event(le_connection_complete(handle, peer6));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("LE connection not tracked");
        }
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("connect on a live ACL should report Pending");
        }
        // No HCI create: the link already exists.
        if fake.sent_opcodes().contains(&op::HCI_LE_CREATE_CONNECTION) {
            reset_all();
            return TestResult::Fail("connect on a live ACL must not create a link");
        }
        // The CoC Request went out synchronously with the call
        // (queue_frame + the pump's own flush in send paths is not
        // involved — check via a pump step's flush).
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let req_ok = frames
            .iter()
            .any(|(_, f)| f.cid == CID_LE_SIGNALLING && f.payload.first() == Some(&0x14));
        if !req_ok {
            reset_all();
            return TestResult::Fail("CoC Request missing on a live ACL");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_le_coc_existing_acl);

    /// #1532: outbound LE CoC refusal + link failure. A peer
    /// refusal carries its §4.23 result code; a failed HCI link
    /// reports Failed.
    fn smoke_pump_bt_connect_le_coc_refused_and_failed() -> TestResult {
        // Refusal: peer answers PSM-not-supported (0x0002).
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 1;
        peer[1..7].copy_from_slice(&peer6);
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("first connect should report Pending");
        }
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0x00));
        fake.enqueue_event(le_connection_complete_central(handle, peer6));
        let _ = pump_once(0);
        let rsp = l2cap::build_le_credit_based_connection_response(
            0x01,
            0,
            0x0040,
            l2cap::LE_COC_RESULT_PSM_NOT_SUPPORTED,
            0,
            0,
            0,
        );
        let mut payload = Vec::new();
        rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_LE_SIGNALLING, payload)));
        let _ = pump_once(0);
        if connect(0, peer, 0x0080, true, false)
            != BtConnectStatus::Refused(l2cap::LE_COC_RESULT_PSM_NOT_SUPPORTED)
        {
            reset_all();
            return TestResult::Fail("refused CoC should report Refused(0x0002)");
        }
        // Link failure: the create completes with status 0x3C
        // (Connection Failed to be Established).
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
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("first connect should report Pending");
        }
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0x00));
        let mut params = alloc::vec![0x01, 0x3C];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(0x00); // role: Central
        params.push(0x00); // peer address type: public
        params.extend_from_slice(&peer6);
        params.extend_from_slice(&0x0028u16.to_le_bytes());
        params.extend_from_slice(&0u16.to_le_bytes());
        params.extend_from_slice(&0x01F4u16.to_le_bytes());
        params.push(0x00);
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params,
        });
        let _ = pump_once(0);
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Failed {
            reset_all();
            return TestResult::Fail("failed LE link should report Failed");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_bt_connect_le_coc_refused_and_failed
    );

    /// #1532: cancelling an in-flight LE connect drops the record
    /// — the link still comes up, but no CoC Request is ever sent
    /// on it.
    fn smoke_pump_bt_connect_cancel() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 1;
        peer[1..7].copy_from_slice(&peer6);
        if connect(0, peer, 0x0080, true, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("first connect should report Pending");
        }
        if !cancel_connect(0, peer, 0x0080, true, false) {
            reset_all();
            return TestResult::Fail("cancel should drop the in-flight open");
        }
        if cancel_connect(0, peer, 0x0080, true, false) {
            reset_all();
            return TestResult::Fail("second cancel should find nothing in flight");
        }
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0x00));
        fake.enqueue_event(le_connection_complete_central(handle, peer6));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("LE connection not tracked");
        }
        let frames = fake.sent_acl_frames();
        if frames.iter().any(|(_, f)| f.cid == CID_LE_SIGNALLING) {
            reset_all();
            return TestResult::Fail("cancelled connect must send no CoC Request");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_cancel);

    /// #1532: outbound BR/EDR connect — inquiry, page, Connection
    /// Request (with a pending-then-success response), Configure
    /// Request/Response, data round-trip, disconnect — against the
    /// scripted-controller harness. Fixture PSM 0x1001 is an
    /// arbitrary dynamic PSM (odd, >= 0x1001).
    fn smoke_pump_bt_connect_bredr() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 0; // BR/EDR public
        peer[1..7].copy_from_slice(&peer6);
        // Undiscovered peer: no paging parameters, honest refusal.
        if connect(0, peer, 0x1001, false, false) != BtConnectStatus::UnknownPeer {
            reset_all();
            return TestResult::Fail("undiscovered BR/EDR peer should report UnknownPeer");
        }
        // Discover the peer: GIAC inquiry, one result, complete.
        if classic_start_inquiry(0, [0x33, 0x8B, 0x9E], 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("inquiry start failed");
        }
        fake.enqueue_event(inquiry_result_event(peer6, 1, [0x04, 0x0C, 0x02], 0x1234));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        // Start: HCI_Create_Connection goes out, open is pending.
        if connect(0, peer, 0x1001, false, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("first connect should report Pending");
        }
        if !fake.sent_opcodes().contains(&op::HCI_CREATE_CONNECTION) {
            reset_all();
            return TestResult::Fail("HCI_Create_Connection not issued");
        }
        fake.enqueue_event(cs(op::HCI_CREATE_CONNECTION, 0x00));
        fake.enqueue_event(classic_connection_complete(handle, peer6));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("BR/EDR connection not tracked");
        }
        // Exact Connection Request bytes: code 0x02, id 0x01, len
        // 4, PSM 0x1001, source CID 0x0040 (first BR/EDR alloc).
        let expected_req: Vec<u8> = alloc::vec![0x02, 0x01, 0x04, 0x00, 0x01, 0x10, 0x40, 0x00];
        let frames = fake.sent_acl_frames();
        let req_ok = frames
            .iter()
            .any(|(_, f)| f.cid == CID_SIGNALLING && f.payload == expected_req);
        if !req_ok {
            reset_all();
            return TestResult::Fail("BR/EDR Connection Request bytes mismatch");
        }
        // Peer answers pending first (§4.3 result 1): still
        // pending, no Configure Request yet.
        let pending =
            l2cap::build_connection_response(0x01, 0x0040, 0x0041, l2cap::CONN_RESULT_PENDING, 0);
        let mut payload = Vec::new();
        pending.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        if connect(0, peer, 0x1001, false, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("pending response should keep the open Pending");
        }
        let frames = fake.sent_acl_frames();
        if frames
            .iter()
            .any(|(_, f)| f.cid == CID_SIGNALLING && f.payload.first() == Some(&0x04))
        {
            reset_all();
            return TestResult::Fail("Configure Request must wait for the final response");
        }
        // Final response: success, peer CID 0x0041.
        let rsp = l2cap::build_connection_response(
            0x01,
            0x0040,
            0x0041,
            l2cap::CONN_RESULT_SUCCESS,
            l2cap::CONN_STATUS_NO_INFORMATION,
        );
        let mut payload = Vec::new();
        rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        // Exact Configure Request bytes: code 0x04, id 0x02, len
        // 4, dest CID 0x0041, flags 0, no options.
        let expected_cfg: Vec<u8> = alloc::vec![0x04, 0x02, 0x04, 0x00, 0x41, 0x00, 0x00, 0x00];
        let frames = fake.sent_acl_frames();
        let cfg_ok = frames
            .iter()
            .any(|(_, f)| f.cid == CID_SIGNALLING && f.payload == expected_cfg);
        if !cfg_ok {
            reset_all();
            return TestResult::Fail("Configure Request bytes mismatch");
        }
        // Still pending until the peer accepts the configuration.
        if connect(0, peer, 0x1001, false, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("connect should stay Pending before Configure Response");
        }
        // Peer accepts: source 0x0041, flags 0, result 0.
        let cfg_rsp = l2cap::SignallingCommand {
            code: l2cap::SignallingCode::ConfigureResponse as u8,
            identifier: 0x02,
            data: alloc::vec![0x41, 0x00, 0x00, 0x00, 0x00, 0x00],
        };
        let mut payload = Vec::new();
        cfg_rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        match connect(0, peer, 0x1001, false, false) {
            BtConnectStatus::Open((h, local, peer_cid, addr)) => {
                if h != handle || local != 0x0040 || peer_cid != 0x0041 || addr != peer {
                    reset_all();
                    return TestResult::Fail("opened channel handle/CID/peer mismatch");
                }
            }
            _ => {
                reset_all();
                return TestResult::Fail("connect should report Open after Configure Response");
            }
        }
        // Data round-trip on the generic channel.
        match send_channel(0, handle, 0x0040, b"ping") {
            Ok(4) => {}
            _ => {
                reset_all();
                return TestResult::Fail("BR/EDR send should report 4 bytes");
            }
        }
        let frames = fake.sent_acl_frames();
        let send_ok = frames.iter().any(|(h, f)| {
            *h == handle && f.cid == 0x0041 && f.payload == alloc::vec![b'p', b'i', b'n', b'g']
        });
        if !send_ok {
            reset_all();
            return TestResult::Fail("BR/EDR send B-frame missing from the wire");
        }
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![b'p', b'o', b'n', b'g']),
        ));
        let _ = pump_once(0);
        if drain_channel_rx(0, handle, 0x0040)
            != Some(alloc::vec![alloc::vec![b'p', b'o', b'n', b'g']])
        {
            reset_all();
            return TestResult::Fail("BR/EDR SDU not staged for the socket");
        }
        // Socket close: Disconnection Request on signalling, then
        // the channel is gone for good.
        if !disconnect_channel(0, handle, 0x0040) {
            reset_all();
            return TestResult::Fail("disconnect should tear the channel down");
        }
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_SIGNALLING
                && f.payload == alloc::vec![0x06, 0x00, 0x04, 0x00, 0x41, 0x00, 0x40, 0x00]
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("disconnect request missing from the wire");
        }
        if drain_channel_rx(0, handle, 0x0040).is_some() {
            reset_all();
            return TestResult::Fail("disconnected channel must be gone");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_bredr);

    /// #1532: outbound BR/EDR refusal — the peer refuses the PSM
    /// and the open reports its §4.3 result code.
    fn smoke_pump_bt_connect_bredr_refused() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 0;
        peer[1..7].copy_from_slice(&peer6);
        // Live ACL (peripheral-role link) so no paging is needed.
        fake.enqueue_event(classic_connection_complete(handle, peer6));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("BR/EDR connection not tracked");
        }
        if connect(0, peer, 0x1001, false, false) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("connect on a live ACL should report Pending");
        }
        let rsp = l2cap::build_connection_response(
            0x01,
            0,
            0x0040,
            l2cap::CONN_RESULT_REFUSED_PSM_NOT_SUPPORTED,
            l2cap::CONN_STATUS_NO_INFORMATION,
        );
        let mut payload = Vec::new();
        rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        if connect(0, peer, 0x1001, false, false)
            != BtConnectStatus::Refused(l2cap::CONN_RESULT_REFUSED_PSM_NOT_SUPPORTED)
        {
            reset_all();
            return TestResult::Fail("refused BR/EDR open should report Refused(0x0002)");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_bredr_refused);

    /// #1532: outbound RFCOMM connect — page, mux open, SABM on
    /// DLCI 0, SABM on the target DLCI, data round-trip with
    /// initiator C/R=1, DISC — against the scripted-controller
    /// harness. Fixture server channel 5 → DLCI 11 (2*5+1).
    fn smoke_pump_bt_connect_rfcomm() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 0; // BR/EDR public
        peer[1..7].copy_from_slice(&peer6);
        // Discover the peer first (paging needs inquiry data).
        if classic_start_inquiry(0, [0x33, 0x8B, 0x9E], 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("inquiry start failed");
        }
        fake.enqueue_event(inquiry_result_event(peer6, 1, [0x04, 0x0C, 0x02], 0x1234));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        if connect(0, peer, 5, false, true) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("first connect should report Pending");
        }
        fake.enqueue_event(cs(op::HCI_CREATE_CONNECTION, 0x00));
        fake.enqueue_event(classic_connection_complete(handle, peer6));
        let _ = pump_once(0);
        // Exact mux Connection Request bytes: code 0x02, id 0x01,
        // len 4, PSM 0x0003 (RFCOMM), source CID 0x0040.
        let expected_req: Vec<u8> = alloc::vec![0x02, 0x01, 0x04, 0x00, 0x03, 0x00, 0x40, 0x00];
        let frames = fake.sent_acl_frames();
        let req_ok = frames
            .iter()
            .any(|(_, f)| f.cid == CID_SIGNALLING && f.payload == expected_req);
        if !req_ok {
            reset_all();
            return TestResult::Fail("RFCOMM mux Connection Request bytes mismatch");
        }
        // Peer accepts the mux.
        let rsp = l2cap::build_connection_response(
            0x01,
            0x0040,
            0x0041,
            l2cap::CONN_RESULT_SUCCESS,
            l2cap::CONN_STATUS_NO_INFORMATION,
        );
        let mut payload = Vec::new();
        rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        // SABM on DLCI 0, initiator C/R=1, on the peer CID.
        let frames = fake.sent_acl_frames();
        let sabm0_ok = frames.iter().any(|(_, f)| {
            f.cid == 0x0041
                && crate::rfcomm::Frame::decode(&f.payload)
                    .map(|(fr, _)| {
                        fr.dlci == 0 && fr.frame_type == crate::rfcomm::FRAME_SABM && fr.cr
                    })
                    .unwrap_or(false)
        });
        if !sabm0_ok {
            reset_all();
            return TestResult::Fail("mux SABM(DLCI 0, C/R=1) missing from the wire");
        }
        if connect(0, peer, 5, false, true) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("connect should stay Pending before the mux UA");
        }
        // Peer answers the mux SABM with UA.
        let ua0 = crate::rfcomm::Frame::ua(0, false);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, ua0.encode())));
        let _ = pump_once(0);
        // SABM on DLCI 11 (2*5+1), initiator C/R=1.
        let frames = fake.sent_acl_frames();
        let sabm_ok = frames.iter().any(|(_, f)| {
            f.cid == 0x0041
                && crate::rfcomm::Frame::decode(&f.payload)
                    .map(|(fr, _)| {
                        fr.dlci == 11 && fr.frame_type == crate::rfcomm::FRAME_SABM && fr.cr
                    })
                    .unwrap_or(false)
        });
        if !sabm_ok {
            reset_all();
            return TestResult::Fail("DLC SABM(DLCI 11, C/R=1) missing from the wire");
        }
        // Peer answers the DLC SABM with UA: the DLC is open.
        let ua = crate::rfcomm::Frame::ua(11, false);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, ua.encode())));
        let _ = pump_once(0);
        if !connect_ready(0, peer, 5, false, true) {
            reset_all();
            return TestResult::Fail("completed RFCOMM open should read ready");
        }
        match connect(0, peer, 5, false, true) {
            BtConnectStatus::OpenRfcomm((h, local, peer_cid, dlci, addr)) => {
                if h != handle
                    || local != 0x0040
                    || peer_cid != 0x0041
                    || dlci != 11
                    || addr != peer
                {
                    reset_all();
                    return TestResult::Fail("opened DLC handle/CID/DLCI/peer mismatch");
                }
            }
            _ => {
                reset_all();
                return TestResult::Fail("connect should report OpenRfcomm after the DLC UA");
            }
        }
        // Data: our UIH carries C/R=1 (initiator).
        match send_rfcomm(0, handle, 0x0040, 11, b"hi") {
            Ok(2) => {}
            _ => {
                reset_all();
                return TestResult::Fail("RFCOMM send should report 2 bytes");
            }
        }
        let frames = fake.sent_acl_frames();
        let uih_ok = frames.iter().any(|(_, f)| {
            f.cid == 0x0041
                && crate::rfcomm::Frame::decode(&f.payload)
                    .map(|(fr, _)| {
                        fr.dlci == 11
                            && fr.frame_type == crate::rfcomm::FRAME_UIH
                            && fr.cr
                            && fr.info == alloc::vec![b'h', b'i']
                    })
                    .unwrap_or(false)
        });
        if !uih_ok {
            reset_all();
            return TestResult::Fail("RFCOMM UIH(DLCI 11, C/R=1, 'hi') missing");
        }
        // Peer data stages on the DLC.
        let peer_uih = crate::rfcomm::Frame::uih(11, false, alloc::vec![b'y', b'o']);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, peer_uih.encode())));
        let _ = pump_once(0);
        if drain_rfcomm_rx(0, handle, 0x0040, 11) != Some(alloc::vec![alloc::vec![b'y', b'o']]) {
            reset_all();
            return TestResult::Fail("RFCOMM payload not staged for the socket");
        }
        // Socket close: DISC on DLCI 11 with C/R=1 (initiator).
        if !close_rfcomm_dlc(0, handle, 0x0040, 11) {
            reset_all();
            return TestResult::Fail("RFCOMM close should succeed");
        }
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == 0x0041
                && crate::rfcomm::Frame::decode(&f.payload)
                    .map(|(fr, _)| {
                        fr.dlci == 11 && fr.frame_type == crate::rfcomm::FRAME_DISC && fr.cr
                    })
                    .unwrap_or(false)
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("RFCOMM DISC(DLCI 11, C/R=1) missing");
        }
        if drain_rfcomm_rx(0, handle, 0x0040, 11) != Some(alloc::vec![]) {
            reset_all();
            return TestResult::Fail("closed DLC must drain empty");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_rfcomm);

    /// #1532: outbound RFCOMM refusal — the peer answers DM to the
    /// mux SABM and the open reports Failed.
    fn smoke_pump_bt_connect_rfcomm_dm() -> TestResult {
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
        let handle = 0x0040;
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[0] = 0;
        peer[1..7].copy_from_slice(&peer6);
        // Live ACL so no paging is needed.
        fake.enqueue_event(classic_connection_complete(handle, peer6));
        let _ = pump_once(0);
        if connect(0, peer, 5, false, true) != BtConnectStatus::Pending {
            reset_all();
            return TestResult::Fail("connect on a live ACL should report Pending");
        }
        let rsp = l2cap::build_connection_response(
            0x01,
            0x0040,
            0x0041,
            l2cap::CONN_RESULT_SUCCESS,
            l2cap::CONN_STATUS_NO_INFORMATION,
        );
        let mut payload = Vec::new();
        rsp.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        // Peer refuses the mux with DM.
        let dm = crate::rfcomm::Frame::dm(0, false);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, dm.encode())));
        let _ = pump_once(0);
        if connect(0, peer, 5, false, true) != BtConnectStatus::Failed {
            reset_all();
            return TestResult::Fail("DM to the mux SABM should report Failed");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_connect_rfcomm_dm);

    /// #814: the AF_BLUETOOTH socket path over a scripted BR/EDR
    /// generic-PSM conversation — service PSMs refuse registration,
    /// a peer open to a listener PSM claims, data round-trips, and
    /// disconnect tears down.
    fn smoke_pump_bt_socket_bredr_generic_path() -> TestResult {
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
        let handle = 0x0041;
        let peer = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        fake.enqueue_event(Event {
            code: EventCode::ConnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0x01, 0x00],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("BR/EDR connection not tracked");
        }
        // Service PSMs are owned by the pump's own services.
        if register_psm(0, l2cap::PSM_SDP, false) != BtRegisterStatus::InUse {
            reset_all();
            return TestResult::Fail("SDP PSM registration should report InUse");
        }
        if register_psm(0, l2cap::PSM_RFCOMM, false) != BtRegisterStatus::InUse {
            reset_all();
            return TestResult::Fail("RFCOMM PSM registration should report InUse");
        }
        if register_psm(0, 0x0101, false) != BtRegisterStatus::Registered {
            reset_all();
            return TestResult::Fail("generic BR/EDR PSM registration should succeed");
        }
        // Peer opens PSM 0x0101 (peer CID 0x0040) -> local CID 0x0040.
        let open = l2cap::build_connection_request(0x05, 0x0101, 0x0040);
        let mut payload = Vec::new();
        open.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        let claimed = match take_pending_channel(0, 0x0101, false) {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("accept-claim should return the BR/EDR channel");
            }
        };
        if claimed.0 != handle || claimed.1 != 0x0040 || claimed.2 != 0x0040 {
            reset_all();
            return TestResult::Fail("claimed BR/EDR channel handle/CID mismatch");
        }
        if claimed.3[1..7] != peer {
            reset_all();
            return TestResult::Fail("claimed BR/EDR channel peer address mismatch");
        }
        // Peer data on our local CID stages for the socket.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![b'h', b'i']),
        ));
        let _ = pump_once(0);
        if drain_channel_rx(0, handle, 0x0040) != Some(alloc::vec![alloc::vec![b'h', b'i']]) {
            reset_all();
            return TestResult::Fail("BR/EDR payload not staged for the socket");
        }
        // Socket send: one B-frame on the peer CID.
        match send_channel(0, handle, 0x0040, b"yo") {
            Ok(2) => {}
            _ => {
                reset_all();
                return TestResult::Fail("BR/EDR send should report 2 bytes");
            }
        }
        let frames = fake.sent_acl_frames();
        let send_ok = frames
            .iter()
            .any(|(h, f)| *h == handle && f.cid == 0x0040 && f.payload == alloc::vec![b'y', b'o']);
        if !send_ok {
            reset_all();
            return TestResult::Fail("BR/EDR send B-frame missing from the wire");
        }
        // Unregister releases the PSM; a later listener can claim it.
        unregister_psm(0, 0x0101, false);
        if register_psm(0, 0x0101, false) != BtRegisterStatus::Registered {
            reset_all();
            return TestResult::Fail("unregistered PSM should be claimable again");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_socket_bredr_generic_path);

    /// #814: the AF_BLUETOOTH RFCOMM socket path over a scripted
    /// conversation — peer opens the PSM 0x0003 mux + DLCI 3 (server
    /// channel 1), accept claims the DLC, UIH data round-trips, and
    /// close sends DISC.
    fn smoke_pump_bt_socket_rfcomm_path() -> TestResult {
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
        let handle = 0x0041;
        let peer = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        fake.enqueue_event(Event {
            code: EventCode::ConnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0x01, 0x00],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("BR/EDR connection not tracked");
        }
        if pending_rfcomm(0, 1) {
            reset_all();
            return TestResult::Fail("no DLC should be pending before the peer opens");
        }
        // Peer opens PSM 0x0003 (peer CID 0x0040) -> local CID 0x0040.
        let open = l2cap::build_connection_request(0x05, l2cap::PSM_RFCOMM, 0x0040);
        let mut payload = Vec::new();
        open.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        // Mux SABM (DLCI 0, C/R 1) then DLC SABM (DLCI 3 = server
        // channel 1, C/R 1) on the new channel.
        let mux_sabm = crate::rfcomm::Frame::sabm(0, true);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, mux_sabm.encode())));
        let dlc_sabm = crate::rfcomm::Frame::sabm(3, true);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, dlc_sabm.encode())));
        let _ = pump_once(0);
        if !pending_rfcomm(0, 1) {
            reset_all();
            return TestResult::Fail("opened DLC should be pending for accept");
        }
        let claimed = match take_pending_rfcomm(0, 1) {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("accept-claim should return the opened DLC");
            }
        };
        if claimed.0 != handle || claimed.1 != 0x0040 || claimed.2 != 0x0040 || claimed.3 != 3 {
            reset_all();
            return TestResult::Fail("claimed DLC handle/CID/DLCI mismatch");
        }
        if claimed.4[1..7] != peer {
            reset_all();
            return TestResult::Fail("claimed DLC peer address mismatch");
        }
        if take_pending_rfcomm(0, 1).is_some() || pending_rfcomm(0, 1) {
            reset_all();
            return TestResult::Fail("claimed DLC must not be pending again");
        }
        // Peer UIH data on DLCI 3 stages for the socket.
        let data = crate::rfcomm::Frame::uih(3, true, alloc::vec![b'h', b'i']);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, data.encode())));
        let _ = pump_once(0);
        if !rfcomm_rx_pending(0, handle, 0x0040, 3) {
            reset_all();
            return TestResult::Fail("staged UIH should read pending");
        }
        if drain_rfcomm_rx(0, handle, 0x0040, 3) != Some(alloc::vec![alloc::vec![b'h', b'i']]) {
            reset_all();
            return TestResult::Fail("UIH payload not staged for the socket");
        }
        // Socket send: one UIH frame on DLCI 3, C/R 0 (responder).
        match send_rfcomm(0, handle, 0x0040, 3, b"yo") {
            Ok(2) => {}
            _ => {
                reset_all();
                return TestResult::Fail("RFCOMM send should report 2 bytes");
            }
        }
        let frames = fake.sent_acl_frames();
        let expected_uih = crate::rfcomm::Frame::uih(3, false, alloc::vec![b'y', b'o']).encode();
        let send_ok = frames
            .iter()
            .any(|(h, f)| *h == handle && f.cid == 0x0040 && f.payload == expected_uih);
        if !send_ok {
            reset_all();
            return TestResult::Fail("RFCOMM send UIH frame missing from the wire");
        }
        // Socket close: DISC on DLCI 3, C/R 0; the DLC is forgotten.
        if !close_rfcomm_dlc(0, handle, 0x0040, 3) {
            reset_all();
            return TestResult::Fail("RFCOMM close should send DISC");
        }
        let frames = fake.sent_acl_frames();
        let expected_disc = crate::rfcomm::Frame::disc(3, false).encode();
        let disc_ok = frames
            .iter()
            .any(|(h, f)| *h == handle && f.cid == 0x0040 && f.payload == expected_disc);
        if !disc_ok {
            reset_all();
            return TestResult::Fail("RFCOMM DISC missing from the wire");
        }
        if drain_rfcomm_rx(0, handle, 0x0040, 3).map(|v| v.len()) != Some(0)
            || send_rfcomm(0, handle, 0x0040, 3, b"x").is_ok()
        {
            reset_all();
            return TestResult::Fail("closed DLC must be gone");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_bt_socket_rfcomm_path);

    /// #889 BR/EDR fixture: open → SDP search/attribute → disconnect.
    fn smoke_pump_sdp_open_search_disconnect() -> TestResult {
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
        let handle = 0x0041;
        fake.enqueue_event(Event {
            code: EventCode::ConnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0x01, 0x00],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("BR/EDR connection not tracked");
        }

        // Open: Connection Request (id 0x05, PSM 0x0001 SDP, peer
        // CID 0x0040) -> success, local CID 0x0040 (first BR/EDR
        // alloc).
        let open = l2cap::build_connection_request(0x05, 0x0001, 0x0040);
        let mut payload = Vec::new();
        open.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let open_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_SIGNALLING
                && f.payload
                    == alloc::vec![
                        0x03, 0x05, 0x08, 0x00, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00
                    ]
        });
        if !open_ok {
            reset_all();
            return TestResult::Fail("SDP channel open response mismatch");
        }
        // Configure -> accept.
        let cfg = l2cap::build_configure_request(0x06, 0x0040, false, &[]);
        let mut payload = Vec::new();
        cfg.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let cfg_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_SIGNALLING
                && f.payload
                    == alloc::vec![0x05, 0x06, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]
        });
        if !cfg_ok {
            reset_all();
            return TestResult::Fail("SDP channel configure response mismatch");
        }

        // SDP Service Search for Serial Port (0x1101) -> exact
        // response bytes (total 1, current 1, handle 0x00010000).
        let spp_uuid = 0x1101u16.to_be_bytes();
        let search = crate::sdp::build_service_search_request(0x1234, &[&spp_uuid], 0xFFFF);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, search)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let search_ok = frames.iter().any(|(_, f)| {
            f.cid == 0x0040
                && f.payload
                    == alloc::vec![
                        0x03, 0x12, 0x34, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
                        0x00, 0x00,
                    ]
        });
        if !search_ok {
            reset_all();
            return TestResult::Fail("SDP search response bytes mismatch");
        }
        // SDP Service Attribute for the service name.
        let attr = crate::sdp::build_service_attribute_request(
            0x0007,
            0x00010000,
            0xFFFF,
            &[0x0100],
            false,
        );
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(0x0040, attr)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let attr_ok = frames.iter().any(|(_, f)| {
            f.cid == 0x0040
                && f.payload.len() >= 6
                && f.payload[0] == 0x05
                && f.payload[1..3] == [0x00, 0x07]
                && f.payload.windows(8).any(|w| w == b"NARF SPP")
                && f.payload.last() == Some(&0)
        });
        if !attr_ok {
            reset_all();
            return TestResult::Fail("SDP attribute response missing service name");
        }

        // Disconnect -> response, then data on the freed CID drops.
        let disc = l2cap::build_disconnection_request(0x08, 0x0040, 0x0040);
        let mut payload = Vec::new();
        disc.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_SIGNALLING
                && f.payload == alloc::vec![0x07, 0x08, 0x04, 0x00, 0x40, 0x00, 0x40, 0x00]
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("SDP channel disconnection response missing");
        }
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![0x01, 0x02, 0x03]),
        ));
        let _ = pump_once(0);
        let dropped = stats(0).map(|s| s.frames_dropped_unrouted_cid) == Some(1);
        reset_all();
        if !dropped {
            return TestResult::Fail("data on freed SDP CID not counted as dropped");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_sdp_open_search_disconnect);

    /// #889 BR/EDR fixture: open → RFCOMM mux + DLC → data →
    /// disconnect. The peer's DLCIs (mux 0, DLC 2) are the peer's
    /// choice, mirrored by the session — no server-channel → DLCI
    /// mapping is computed here.
    fn smoke_pump_rfcomm_open_data_disconnect() -> TestResult {
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
        let handle = 0x0041;
        fake.enqueue_event(Event {
            code: EventCode::ConnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0x01, 0x00],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("BR/EDR connection not tracked");
        }

        // Open: Connection Request (id 0x05, PSM 0x0003 RFCOMM,
        // peer CID 0x0040) -> success, local CID 0x0040.
        let open = l2cap::build_connection_request(0x05, 0x0003, 0x0040);
        let mut payload = Vec::new();
        open.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let open_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_SIGNALLING
                && f.payload
                    == alloc::vec![
                        0x03, 0x05, 0x08, 0x00, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00
                    ]
        });
        if !open_ok {
            reset_all();
            return TestResult::Fail("RFCOMM channel open response mismatch");
        }
        // Configure -> accept.
        let cfg = l2cap::build_configure_request(0x06, 0x0040, false, &[]);
        let mut payload = Vec::new();
        cfg.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);

        // Helper: last payload sent on a CID.
        let last_on = |frames: &Vec<(u16, BFrame)>, cid: u16| -> Option<Vec<u8>> {
            frames
                .iter()
                .rev()
                .find(|(_, f)| f.cid == cid)
                .map(|(_, f)| f.payload.clone())
        };

        // Mux SABM -> UA, pinned bytes (address 0x01, control
        // 0x73, length 0x01, FCS 0xB6).
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, crate::rfcomm::Frame::sabm(0, true).encode()),
        ));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        if last_on(&frames, 0x0040) != Some(alloc::vec![0x01, 0x73, 0x01, 0xB6]) {
            reset_all();
            return TestResult::Fail("RFCOMM mux SABM response bytes mismatch");
        }
        // DLC SABM -> UA, pinned bytes.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, crate::rfcomm::Frame::sabm(2, true).encode()),
        ));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        if last_on(&frames, 0x0040) != Some(alloc::vec![0x09, 0x73, 0x01, 0xF3]) {
            reset_all();
            return TestResult::Fail("RFCOMM DLC SABM response bytes mismatch");
        }
        // UIH data -> staged, no response frame.
        let before = fake
            .sent_acl_frames()
            .iter()
            .filter(|(_, f)| f.cid == 0x0040)
            .count();
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(
                0x0040,
                crate::rfcomm::Frame::uih(2, true, alloc::vec![b'h', b'e', b'l', b'l', b'o'])
                    .encode(),
            ),
        ));
        let _ = pump_once(0);
        let after = fake
            .sent_acl_frames()
            .iter()
            .filter(|(_, f)| f.cid == 0x0040)
            .count();
        if before != after {
            reset_all();
            return TestResult::Fail("RFCOMM UIH data must not be answered");
        }
        if drain_rfcomm_rx(0, handle, 0x0040, 2)
            != Some(alloc::vec![alloc::vec![b'h', b'e', b'l', b'l', b'o']])
        {
            reset_all();
            return TestResult::Fail("RFCOMM UIH payload not staged");
        }
        // DLC DISC -> UA; UIH after close -> DM, pinned bytes.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, crate::rfcomm::Frame::disc(2, true).encode()),
        ));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        if last_on(&frames, 0x0040) != Some(alloc::vec![0x09, 0x73, 0x01, 0xF3]) {
            reset_all();
            return TestResult::Fail("RFCOMM DLC DISC response bytes mismatch");
        }
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(
                0x0040,
                crate::rfcomm::Frame::uih(2, true, alloc::vec![b'x']).encode(),
            ),
        ));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        if last_on(&frames, 0x0040) != Some(alloc::vec![0x09, 0x1F, 0x01, 0x12]) {
            reset_all();
            return TestResult::Fail("RFCOMM UIH on closed DLC should get DM");
        }

        // L2CAP disconnect -> response, then data on the freed CID
        // drops.
        let disc = l2cap::build_disconnection_request(0x08, 0x0040, 0x0040);
        let mut payload = Vec::new();
        disc.encode(&mut payload);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_SIGNALLING, payload)));
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let disc_ok = frames.iter().any(|(_, f)| {
            f.cid == CID_SIGNALLING
                && f.payload == alloc::vec![0x07, 0x08, 0x04, 0x00, 0x40, 0x00, 0x40, 0x00]
        });
        if !disc_ok {
            reset_all();
            return TestResult::Fail("RFCOMM channel disconnection response missing");
        }
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(0x0040, alloc::vec![0x01, 0x02, 0x03]),
        ));
        let _ = pump_once(0);
        let dropped = stats(0).map(|s| s.frames_dropped_unrouted_cid) == Some(1);
        reset_all();
        if !dropped {
            return TestResult::Fail("data on freed RFCOMM CID not counted as dropped");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_rfcomm_open_data_disconnect);

    /// Command Status event for `opcode` with `status` (§7.7.15).
    fn cs(opcode: u16, status: u8) -> Event {
        Event {
            code: EventCode::CommandStatus as u8,
            params: alloc::vec![status, 1, (opcode & 0xFF) as u8, (opcode >> 8) as u8],
        }
    }

    /// One LE Advertising Report subevent (§7.7.65.2): subevent,
    /// Num_Reports=1, event type, address type, address, data, RSSI.
    fn le_advertising_report(
        event_type: u8,
        address_type: u8,
        address: [u8; 6],
        data: &[u8],
        rssi: i8,
    ) -> Event {
        let mut params = alloc::vec![0x02, 0x01, event_type, address_type];
        params.extend_from_slice(&address);
        params.push(data.len() as u8);
        params.extend_from_slice(data);
        params.push(rssi as u8);
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// One LE Extended Advertising Report subevent (§7.7.65.13) with a
    /// single report: subevent, Num_Reports=1, then the 24-byte fixed
    /// header + data. Bytes pinned against the spec layout, not
    /// against `parse_le_extended_advertising_reports`.
    #[allow(clippy::too_many_arguments)]
    fn le_ext_advertising_report(
        event_type: u16,
        address_type: u8,
        address: [u8; 6],
        primary_phy: u8,
        secondary_phy: u8,
        sid: u8,
        tx_power: i8,
        rssi: i8,
        data: &[u8],
    ) -> Event {
        let mut params = alloc::vec![0x0D, 0x01];
        params.extend_from_slice(&event_type.to_le_bytes());
        params.push(address_type);
        params.extend_from_slice(&address);
        params.push(primary_phy);
        params.push(secondary_phy);
        params.push(sid);
        params.push(tx_power as u8);
        params.push(rssi as u8);
        params.extend_from_slice(&0x0000u16.to_le_bytes()); // periodic interval: none
        params.push(0xFF); // direct address type: none
        params.extend_from_slice(&[0x00; 6]); // direct address
        params.push(data.len() as u8);
        params.extend_from_slice(data);
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// LE Connection Complete as seen by the Central role (§7.7.65.1):
    /// same layout as the peripheral helper, but role byte 0x00.
    fn le_connection_complete_central(handle: u16, peer: [u8; 6]) -> Event {
        let mut params = alloc::vec![0x01, 0x00];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(0x00); // role: Central (we initiated)
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

    /// One HCI_Inquiry_Result event (§7.7.2) with a single entry:
    /// Num_Responses, BD_ADDR, PSRM, 2 reserved bytes, Class of
    /// Device, Clock Offset. Bytes pinned against the spec layout,
    /// not against `parse_inquiry_results`.
    fn inquiry_result_event(bd_addr: [u8; 6], psrm: u8, cod: [u8; 3], clock_offset: u16) -> Event {
        let mut params = alloc::vec![0x01];
        params.extend_from_slice(&bd_addr);
        params.push(psrm);
        params.extend_from_slice(&[0x00, 0x00]); // reserved
        params.extend_from_slice(&cod);
        params.extend_from_slice(&clock_offset.to_le_bytes());
        Event {
            code: EventCode::InquiryResult as u8,
            params,
        }
    }

    /// HCI_Inquiry_Complete event (§7.7.1): Status(1).
    fn inquiry_complete_event(status: u8) -> Event {
        Event {
            code: EventCode::InquiryComplete as u8,
            params: alloc::vec![status],
        }
    }

    /// HCI_Connection_Complete event (§7.7.3) for a BR/EDR ACL link:
    /// Status, Handle, BD_ADDR, Link_Type 0x01 (ACL),
    /// Encryption_Enabled 0.
    fn classic_connection_complete(handle: u16, bd_addr: [u8; 6]) -> Event {
        let mut params = alloc::vec![0x00];
        params.extend_from_slice(&handle.to_le_bytes());
        params.extend_from_slice(&bd_addr);
        params.extend_from_slice(&[0x01, 0x00]);
        Event {
            code: EventCode::ConnectionComplete as u8,
            params,
        }
    }

    // ── #888: SMP initiator + bonding fixtures ────────────────────

    const SMP888_HANDLE: u16 = 0x0040;
    const SMP888_PEER6: [u8; 6] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    const SMP888_PEER_ADDR: [u8; 7] = [0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    const SMP888_LOCAL_ADDR: [u8; 7] = [0x00, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    const SMP888_PEER_PRIV: &Fe = &[0x5A5A_5A5A_5A5A_5A5A; 4];

    /// One SMP PDU wrapped as a single LE ACL packet.
    fn smp888_acl(handle: u16, code: u8, payload: &[u8]) -> Vec<u8> {
        acl_packet(
            handle,
            &BFrame::new(
                CID_SMP,
                smp::Pdu {
                    code,
                    payload: payload.to_vec(),
                }
                .encode(),
            ),
        )
    }

    /// Peer Pairing Request (NoInputNoOutput, bonding|SC) as one
    /// LE ACL packet, with the given distribution bytes.
    fn smp888_request_acl(handle: u16, dist_init: u8, dist_resp: u8) -> Vec<u8> {
        acl_packet(
            handle,
            &BFrame::new(
                CID_SMP,
                smp::PairingFeatureExchange {
                    io_capability: smp::IoCapability::NoInputNoOutput as u8,
                    oob_data_flag: 0,
                    auth_req: smp::AUTH_BONDING | smp::AUTH_SC,
                    max_encryption_key_size: 16,
                    initiator_key_distribution: dist_init,
                    responder_key_distribution: dist_resp,
                }
                .encode(smp::SMP_PAIRING_REQUEST)
                .encode(),
            ),
        )
    }

    /// LE LTK Request event (LeMeta subevent 0x05).
    fn smp888_ltk_request_event(handle: u16, rand: u64, ediv: u16) -> Event {
        let mut params = alloc::vec![0x05u8];
        params.extend_from_slice(&handle.to_le_bytes());
        params.extend_from_slice(&rand.to_le_bytes());
        params.extend_from_slice(&ediv.to_le_bytes());
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    fn central_bring_up(fake: Arc<ScriptedTransport>) -> Result<(), &'static str> {
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport);
        script_successful_bringup(&fake);
        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        if outcomes.len() != 1 || outcomes[0].result.is_err() {
            return Err("bring-up against fake controller failed");
        }
        Ok(())
    }
    /// Encryption Change event (§7.7.8: Status, Handle, Enabled).
    fn smp888_encryption_change_event(handle: u16, status: u8, enabled: u8) -> Event {
        Event {
            code: EventCode::EncryptionChange as u8,
            params: alloc::vec![status, (handle & 0xFF) as u8, (handle >> 8) as u8, enabled],
        }
    }

    /// Credit back 8 ACL packets (the bring-up MTU total) so a
    /// later flush is never credit-starved mid-fixture.
    fn smp888_replenish(fake: &ScriptedTransport, handle: u16) {
        fake.enqueue_event(Event {
            code: EventCode::NumberOfCompletedPackets as u8,
            params: alloc::vec![1, (handle & 0xFF) as u8, (handle >> 8) as u8, 8, 0],
        });
    }

    /// Enqueue `acls`, run one pump step, return the new SMP
    /// payloads sent on `handle`.
    fn smp888_step_acls(fake: &ScriptedTransport, acls: &[Vec<u8>], handle: u16) -> Vec<Vec<u8>> {
        let before = fake.sent_acl_frames().len();
        for a in acls {
            fake.enqueue_acl(a.clone());
        }
        let _ = pump_once(0);
        fake.sent_acl_frames()
            .into_iter()
            .skip(before)
            .filter(|(h, f)| *h == handle && f.cid == CID_SMP)
            .map(|(_, f)| f.payload)
            .collect()
    }

    /// Enqueue one event, run one pump step, return the new SMP
    /// payloads sent on `handle`.
    fn smp888_step_event(fake: &ScriptedTransport, ev: Event, handle: u16) -> Vec<Vec<u8>> {
        let before = fake.sent_acl_frames().len();
        fake.enqueue_event(ev);
        let _ = pump_once(0);
        fake.sent_acl_frames()
            .into_iter()
            .skip(before)
            .filter(|(h, f)| *h == handle && f.cid == CID_SMP)
            .map(|(_, f)| f.payload)
            .collect()
    }

    /// Bring up the fake controller and open one LE connection.
    fn smp888_bring_up_connect(fake: &Arc<ScriptedTransport>) -> Result<(), &'static str> {
        let transport: Arc<dyn HciTransport> = fake.clone();
        crate::transport::register(transport);
        script_successful_bringup(fake);
        let cap = crate::bootstrap_bluetooth_authority();
        let outcomes = crate::controller::bring_up_all(&cap);
        if outcomes.len() != 1 || outcomes[0].result.is_err() {
            return Err("bring-up against fake controller failed");
        }
        fake.enqueue_event(le_connection_complete(SMP888_HANDLE, SMP888_PEER6));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            return Err("pump did not track the LE connection");
        }
        Ok(())
    }

    /// #1312: the full central sequence against a scripted
    /// controller — scan parameters → enable → reports → disable →
    /// create connection → complete → disconnect — with the outbound
    /// command bytes pinned against the Core Specification field
    /// order, not against the encoders under test.
    fn smoke_pump_central_scan_connect_sequence() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // 1. Start scan: LE Set Scan Parameters, pinned byte-for-byte
        // against Vol 4 Part E §7.8.10 (passive, 30 ms / 30 ms,
        // public address, accept-all).
        if central_start_scan(0, crate::gap::ScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("central_start_scan rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_params: [u8; 7] = [0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00];
        if sent.len() != 6
            || sent[5].0 != op::HCI_LE_SET_SCAN_PARAMETERS
            || sent[5].1 != expect_params
        {
            reset_all();
            return TestResult::Fail("Set Scan Parameters bytes mismatch");
        }
        if central_phase(0) != Some(crate::gap::CentralPhase::ParametersSent) {
            reset_all();
            return TestResult::Fail("phase not ParametersSent after start_scan");
        }
        // 2. Parameters complete -> Enable(1) issued by the pump.
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_PARAMETERS, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        if sent.len() != 7 || sent[6].0 != op::HCI_LE_SET_SCAN_ENABLE || sent[6].1 != [0x01, 0x00] {
            reset_all();
            return TestResult::Fail("Set Scan Enable(1) not issued on parameters complete");
        }
        if central_phase(0) != Some(crate::gap::CentralPhase::Scanning) {
            reset_all();
            return TestResult::Fail("phase not Scanning after enable");
        }
        // Enable complete itself changes nothing.
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Scanning) {
            reset_all();
            return TestResult::Fail("enable complete moved phase out of Scanning");
        }
        // 3. Advertising reports: peer recorded, refresh dedups.
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        let ad: [u8; 3] = [0x02, 0x01, 0x06]; // Flags: LE General Discoverable + BR/EDR not supported
        fake.enqueue_event(le_advertising_report(0x00, 0x00, peer, &ad, -60));
        let _ = pump_once(0);
        let peers = central_peers(0).unwrap_or_default();
        if peers.len() != 1
            || peers[0].address != peer
            || peers[0].last_rssi != -60
            || peers[0].ad_data != ad
        {
            reset_all();
            return TestResult::Fail("advertising report not recorded as peer");
        }
        // Same peer, stronger signal: refresh, not duplicate. A
        // count-only assertion would pass a duplicate bug, so the
        // length check here is load-bearing.
        fake.enqueue_event(le_advertising_report(0x00, 0x00, peer, &ad, -50));
        let _ = pump_once(0);
        let peers = central_peers(0).unwrap_or_default();
        if peers.len() != 1 || peers[0].last_rssi != -50 {
            reset_all();
            return TestResult::Fail("peer refresh duplicated instead of updating RSSI");
        }
        // Same address, random address type: a distinct peer.
        fake.enqueue_event(le_advertising_report(0x00, 0x01, peer, &ad, -70));
        let _ = pump_once(0);
        if central_peers(0).map(|p| p.len()) != Some(2) {
            reset_all();
            return TestResult::Fail("same address with random type not a distinct peer");
        }
        // 4. Connect: scan disabled first, create follows on completion.
        if central_connect(0, crate::gap::PeerAddressType::Public, peer).is_err() {
            reset_all();
            return TestResult::Fail("central_connect rejected from Scanning");
        }
        let sent = fake.sent_command_params();
        if sent.len() != 8 || sent[7].0 != op::HCI_LE_SET_SCAN_ENABLE || sent[7].1 != [0x00, 0x00] {
            reset_all();
            return TestResult::Fail("connect did not disable scan first");
        }
        if central_phase(0) != Some(crate::gap::CentralPhase::ScanStopping) {
            reset_all();
            return TestResult::Fail("phase not ScanStopping after connect");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        // LE Create Connection, pinned byte-for-byte against Vol 4
        // Part E §7.8.12: scan interval/window 30 ms, peer-address
        // policy, public peer, 30..50 ms interval, 4 s timeout.
        let expect_create: [u8; 25] = [
            0x30, 0x00, 0x30, 0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x00, 0x18,
            0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        if sent.len() != 9
            || sent[8].0 != op::HCI_LE_CREATE_CONNECTION
            || sent[8].1 != expect_create
        {
            reset_all();
            return TestResult::Fail("LE Create Connection bytes mismatch");
        }
        if central_phase(0) != Some(crate::gap::CentralPhase::Connecting) {
            reset_all();
            return TestResult::Fail("phase not Connecting after create");
        }
        // 5. Command Status (accepted) keeps Connecting; Connection
        // Complete lands the connection.
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Connecting) {
            reset_all();
            return TestResult::Fail("accepted Command Status moved phase out of Connecting");
        }
        let handle = 0x0041;
        fake.enqueue_event(le_connection_complete_central(handle, peer));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Connected)
            || connection_count(0) != Some(1)
        {
            reset_all();
            return TestResult::Fail("connection complete did not land central connection");
        }
        // 6. Disconnect returns to Idle.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0x13],
        });
        let _ = pump_once(0);
        let ok = connection_count(0) == Some(0)
            && central_phase(0) == Some(crate::gap::CentralPhase::Idle);
        reset_all();
        if !ok {
            return TestResult::Fail("disconnect did not return central to Idle");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_central_scan_connect_sequence);

    /// #1312: failure paths fail closed — a refused scan command
    /// returns to Idle without issuing Enable (and a retry works),
    /// malformed reports record nothing, stop-then-connect from Idle
    /// issues Create directly, and a rejected Create returns to
    /// Idle with no connection.
    fn smoke_pump_central_failure_and_malformed() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        if central_start_scan(0, crate::gap::ScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("central_start_scan rejected from Idle");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_PARAMETERS, &[0x0C]));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Idle) {
            reset_all();
            return TestResult::Fail("refused scan parameters did not return to Idle");
        }
        if fake
            .sent_command_params()
            .iter()
            .any(|(o, _)| *o == op::HCI_LE_SET_SCAN_ENABLE)
        {
            reset_all();
            return TestResult::Fail("Enable issued after refused scan parameters");
        }
        // Retry works: no wedge from the failure.
        if central_start_scan(0, crate::gap::ScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("retry start_scan rejected after failure");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Scanning) {
            reset_all();
            return TestResult::Fail("retry scan did not reach Scanning");
        }
        // Malformed report (claims 1 report, truncated) records
        // nothing and panics nothing.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x02, 0x01, 0x00, 0x00],
        });
        let _ = pump_once(0);
        if central_peers(0).map(|p| p.len()) != Some(0) {
            reset_all();
            return TestResult::Fail("malformed advertising report recorded a peer");
        }
        // Zero-report subevent likewise records nothing.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x02, 0x00],
        });
        let _ = pump_once(0);
        if central_peers(0).map(|p| p.len()) != Some(0) {
            reset_all();
            return TestResult::Fail("zero-report subevent recorded a peer");
        }
        // Stop the scan, then connect from Idle: Create directly.
        if central_stop_scan(0).is_err() {
            reset_all();
            return TestResult::Fail("central_stop_scan rejected from Scanning");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Idle) {
            reset_all();
            return TestResult::Fail("scan disable did not return to Idle");
        }
        let peer = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5];
        if central_connect(0, crate::gap::PeerAddressType::Public, peer).is_err() {
            reset_all();
            return TestResult::Fail("central_connect rejected from Idle");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, _)| *o) != Some(op::HCI_LE_CREATE_CONNECTION)
            || central_phase(0) != Some(crate::gap::CentralPhase::Connecting)
        {
            reset_all();
            return TestResult::Fail("connect from Idle did not issue Create directly");
        }
        // Create rejected by Command Status: Idle, no connection.
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0x0C));
        let _ = pump_once(0);
        let ok = central_phase(0) == Some(crate::gap::CentralPhase::Idle)
            && connection_count(0) == Some(0);
        reset_all();
        if !ok {
            return TestResult::Fail("rejected Create did not return to Idle");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_central_failure_and_malformed);

    /// LE Enhanced Connection Complete as seen by the Central role
    /// (§7.7.65.10, v1 subevent 0x0A): Status, Handle, Role 0x00,
    /// Peer_Address_Type, Peer_Address, Local_RPA, Peer_RPA,
    /// Connection_Interval, Peripheral_Latency,
    /// Supervision_Timeout, Central_Clock_Accuracy.
    fn le_enhanced_connection_complete_central(status: u8, handle: u16, peer: [u8; 6]) -> Event {
        let mut params = alloc::vec![0x0A, status];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(0x00); // role: Central (we initiated)
        params.push(0x00); // peer address type: public
        params.extend_from_slice(&peer);
        params.extend_from_slice(&[0u8; 6]); // local RPA (public own address)
        params.extend_from_slice(&[0u8; 6]); // peer RPA
        params.extend_from_slice(&0x0028u16.to_le_bytes()); // interval 50 ms
        params.extend_from_slice(&0u16.to_le_bytes()); // latency
        params.extend_from_slice(&0x01F4u16.to_le_bytes()); // timeout 5 s
        params.push(0x00); // central clock accuracy
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// LE Channel Selection Algorithm event (§7.7.65.20, subevent
    /// 0x14): Handle + algorithm (0x00 = #1, 0x01 = #2).
    fn le_channel_selection_event(handle: u16, algorithm: u8) -> Event {
        let mut params = alloc::vec![0x14];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(algorithm);
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// #1561: the extended-create encoder and the two new event
    /// parsers, pinned byte-for-byte against Vol 4 Part E §7.8.66 /
    /// §7.7.65.10 / §7.7.65.20. Malformed variants are rejected:
    /// no scanning PHY, a 2M/reserved PHY bit, a missing per-PHY
    /// block, inverted interval/CE ranges, truncated events, and a
    /// reserved channel-selection algorithm.
    fn smoke_gap_ext_create_connection_encode() -> TestResult {
        // Opcode: OGF 0x08, OCF 0x0043 → 0x2043.
        if op::HCI_LE_EXTENDED_CREATE_CONNECTION != 0x2043 {
            return TestResult::Fail("LE Extended Create Connection opcode is not 0x2043");
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        // 1M only: 10-byte header + one 16-byte PHY block = 26.
        let expect_1m: [u8; 26] = [
            0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x01, 0x30, 0x00, 0x30, 0x00,
            0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let one_m = crate::gap::ExtendedCreateConnection::to_peer(
            crate::gap::PeerAddressType::Public,
            peer,
        );
        if one_m.encode().as_deref() != Some(&expect_1m[..]) {
            return TestResult::Fail("1M extended-create bytes mismatch");
        }
        // Coded only: same block, phys 0x04.
        let mut expect_coded = expect_1m;
        expect_coded[9] = 0x04;
        let coded = crate::gap::ExtendedCreateConnection::to_peer_coded(
            crate::gap::PeerAddressType::Public,
            peer,
        );
        if coded.encode().as_deref() != Some(&expect_coded[..]) {
            return TestResult::Fail("Coded extended-create bytes mismatch");
        }
        // Dual PHY with distinct Coded parameters: the 1M block
        // comes first (§7.8.66: blocks in ascending bit order).
        let mut dual = crate::gap::ExtendedCreateConnection::to_peer_dual_phy(
            crate::gap::PeerAddressType::Public,
            peer,
        );
        dual.phy_coded = Some(crate::gap::ExtConnPhyParams {
            scan_interval: 0x0040,
            scan_window: 0x0020,
            conn_interval_min: 0x0020,
            conn_interval_max: 0x0030,
            max_latency: 0x0001,
            supervision_timeout: 0x0200,
            min_ce_length: 0x0010,
            max_ce_length: 0x0020,
        });
        let expect_dual: [u8; 42] = [
            0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x05, 0x30, 0x00, 0x30, 0x00,
            0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x20, 0x00, 0x20, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x02, 0x10, 0x00, 0x20, 0x00,
        ];
        if dual.encode().as_deref() != Some(&expect_dual[..]) {
            return TestResult::Fail("dual-PHY extended-create bytes mismatch");
        }
        // Malformed encoder inputs are all rejected.
        let mut bad = one_m.clone();
        bad.phys = 0x00;
        if bad.encode().is_some() {
            return TestResult::Fail("phys=0 accepted");
        }
        bad = one_m.clone();
        bad.phys = 0x02; // LE 2M: parameters only, no scanning PHY
        if bad.encode().is_some() {
            return TestResult::Fail("phys=0x02 (LE 2M) accepted");
        }
        bad = one_m.clone();
        bad.phys = 0x08; // reserved bit
        if bad.encode().is_some() {
            return TestResult::Fail("phys with reserved bit accepted");
        }
        bad = one_m.clone();
        bad.phys = 0x05;
        bad.phy_coded = None;
        if bad.encode().is_some() {
            return TestResult::Fail("dual PHY with missing Coded block accepted");
        }
        bad = one_m.clone();
        bad.phy_1m = None;
        if bad.encode().is_some() {
            return TestResult::Fail("1M PHY with missing block accepted");
        }
        bad = one_m.clone();
        bad.phy_1m = Some(crate::gap::ExtConnPhyParams {
            conn_interval_min: 0x0028,
            conn_interval_max: 0x0018,
            ..crate::gap::ExtConnPhyParams::default()
        });
        if bad.encode().is_some() {
            return TestResult::Fail("inverted connection interval accepted");
        }
        bad = one_m.clone();
        bad.phy_1m = Some(crate::gap::ExtConnPhyParams {
            min_ce_length: 0x0010,
            max_ce_length: 0x0000,
            ..crate::gap::ExtConnPhyParams::default()
        });
        if bad.encode().is_some() {
            return TestResult::Fail("inverted CE length accepted");
        }
        // Enhanced Connection Complete: full field decode.
        let ev = le_enhanced_connection_complete_central(0x00, 0x0041, peer);
        let Some(cc) = LeEnhancedConnectionComplete::parse(&ev) else {
            return TestResult::Fail("valid Enhanced Connection Complete did not parse");
        };
        if cc.status != 0x00
            || cc.handle != 0x0041
            || cc.role != 0x00
            || cc.peer_address_type != 0x00
            || cc.peer_address != peer
            || cc.local_rpa != [0u8; 6]
            || cc.peer_rpa != [0u8; 6]
            || cc.connection_interval != 0x0028
            || cc.peripheral_latency != 0x0000
            || cc.supervision_timeout != 0x01F4
            || cc.central_clock_accuracy != 0x00
        {
            return TestResult::Fail("Enhanced Connection Complete fields mismatch");
        }
        // Truncated enhanced event (30 bytes) is rejected.
        let mut truncated = ev.clone();
        truncated.params.truncate(30);
        if LeEnhancedConnectionComplete::parse(&truncated).is_some() {
            return TestResult::Fail("truncated Enhanced Connection Complete parsed");
        }
        // Legacy subevent byte in a 31-byte body is not enhanced.
        let mut wrong = ev.clone();
        wrong.params[0] = 0x01;
        if LeEnhancedConnectionComplete::parse(&wrong).is_some() {
            return TestResult::Fail("legacy subevent parsed as Enhanced Complete");
        }
        // Channel Selection Algorithm: valid, truncated, reserved.
        let csa = le_channel_selection_event(0x0041, 0x01);
        let Some(parsed) = LeChannelSelectionAlgorithm::parse(&csa) else {
            return TestResult::Fail("valid Channel Selection Algorithm did not parse");
        };
        if parsed.handle != 0x0041 || parsed.algorithm != 0x01 {
            return TestResult::Fail("Channel Selection Algorithm fields mismatch");
        }
        let mut short = csa.clone();
        short.params.truncate(3);
        if LeChannelSelectionAlgorithm::parse(&short).is_some() {
            return TestResult::Fail("truncated Channel Selection Algorithm parsed");
        }
        let reserved = le_channel_selection_event(0x0041, 0x02);
        if LeChannelSelectionAlgorithm::parse(&reserved).is_some() {
            return TestResult::Fail("reserved CSA algorithm value parsed");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_gap_ext_create_connection_encode);

    /// #1561: end-to-end extended connect on the LE 1M PHY from
    /// Idle — opcode + 26-byte parameters pinned, Command Status
    /// accepted, LE Enhanced Connection Complete lands the
    /// connection, and the immediately-following Channel Selection
    /// Algorithm event (§7.8.66) is recorded on the link.
    fn smoke_pump_ext_create_connection_1m() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        if central_connect_ext(
            0,
            crate::gap::ExtendedCreateConnection::to_peer(
                crate::gap::PeerAddressType::Public,
                peer,
            ),
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("central_connect_ext rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_params: [u8; 26] = [
            0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x01, 0x30, 0x00, 0x30, 0x00,
            0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        if sent.len() != 6
            || sent[5].0 != op::HCI_LE_EXTENDED_CREATE_CONNECTION
            || sent[5].1 != expect_params
        {
            reset_all();
            return TestResult::Fail("LE Extended Create Connection bytes mismatch");
        }
        if central_phase(0) != Some(crate::gap::CentralPhase::Connecting) {
            reset_all();
            return TestResult::Fail("phase not Connecting after extended create");
        }
        // Command Status (accepted) keeps Connecting; the Enhanced
        // Connection Complete lands the connection.
        fake.enqueue_event(cs(op::HCI_LE_EXTENDED_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Connecting) {
            reset_all();
            return TestResult::Fail("accepted Command Status moved phase out of Connecting");
        }
        let handle = 0x0041;
        fake.enqueue_event(le_enhanced_connection_complete_central(0x00, handle, peer));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Connected)
            || connection_count(0) != Some(1)
        {
            reset_all();
            return TestResult::Fail("Enhanced Connection Complete did not land connection");
        }
        // No CSA event yet: nothing recorded for the handle.
        if connection_channel_selection(0, handle) != Some(None) {
            reset_all();
            return TestResult::Fail("CSA recorded before any CSA event");
        }
        // CSA #2 follows the completion (§7.8.66); a CSA for an
        // unknown handle is dropped, never mis-recorded.
        fake.enqueue_event(le_channel_selection_event(handle, 0x01));
        let _ = pump_once(0);
        fake.enqueue_event(le_channel_selection_event(0x0042, 0x00));
        let _ = pump_once(0);
        if connection_channel_selection(0, handle) != Some(Some(0x01))
            || connection_channel_selection(0, 0x0042).is_some()
        {
            reset_all();
            return TestResult::Fail("Channel Selection Algorithm not recorded correctly");
        }
        // Disconnect returns to Idle.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0x13],
        });
        let _ = pump_once(0);
        let ok = connection_count(0) == Some(0)
            && central_phase(0) == Some(crate::gap::CentralPhase::Idle);
        reset_all();
        if !ok {
            return TestResult::Fail("disconnect did not return central to Idle");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_ext_create_connection_1m);

    /// #1561: deferred extended connect from Scanning (scan
    /// disabled first, dual-PHY create follows on completion),
    /// Command Status refusal and Enhanced Complete failure
    /// (0x3E) both fail closed with a working retry, and the
    /// Coded-PHY retry completes with CSA #1 recorded.
    fn smoke_pump_ext_create_connection_deferred_coded() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // A malformed request is rejected before anything is sent.
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        let mut bad = crate::gap::ExtendedCreateConnection::to_peer(
            crate::gap::PeerAddressType::Public,
            peer,
        );
        bad.phys = 0x02;
        let sent_before = fake.sent_command_params().len();
        if central_connect_ext(0, bad) != Err(CentralError::BadParams)
            || central_phase(0) != Some(crate::gap::CentralPhase::Idle)
            || fake.sent_command_params().len() != sent_before
        {
            reset_all();
            return TestResult::Fail("malformed extended create not rejected cleanly");
        }
        // Scan, discover the peer, then connect dual-PHY.
        if central_start_scan(0, crate::gap::ScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("central_start_scan rejected from Idle");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Scanning) {
            reset_all();
            return TestResult::Fail("phase not Scanning after enable");
        }
        let ad: [u8; 3] = [0x02, 0x01, 0x06];
        fake.enqueue_event(le_advertising_report(0x00, 0x00, peer, &ad, -60));
        let _ = pump_once(0);
        if central_peers(0).map(|p| p.len()) != Some(1) {
            reset_all();
            return TestResult::Fail("peer not recorded before extended connect");
        }
        if central_connect_ext(
            0,
            crate::gap::ExtendedCreateConnection::to_peer_dual_phy(
                crate::gap::PeerAddressType::Public,
                peer,
            ),
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("central_connect_ext rejected from Scanning");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, _)| *o) != Some(op::HCI_LE_SET_SCAN_ENABLE)
            || central_phase(0) != Some(crate::gap::CentralPhase::ScanStopping)
        {
            reset_all();
            return TestResult::Fail("extended connect did not disable scan first");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        // Dual-PHY create: 10-byte header + two identical default
        // 16-byte blocks = 42 bytes, phys 0x05.
        let expect_dual: [u8; 42] = [
            0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x05, 0x30, 0x00, 0x30, 0x00,
            0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00,
            0x30, 0x00, 0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        if sent.last().map(|(o, _)| *o) != Some(op::HCI_LE_EXTENDED_CREATE_CONNECTION)
            || sent.last().map(|(_, p)| p.as_slice()) != Some(&expect_dual[..])
            || central_phase(0) != Some(crate::gap::CentralPhase::Connecting)
        {
            reset_all();
            return TestResult::Fail("dual-PHY extended create bytes mismatch");
        }
        // A second initiation while Connecting is a phase error.
        if central_connect_ext(
            0,
            crate::gap::ExtendedCreateConnection::to_peer_coded(
                crate::gap::PeerAddressType::Public,
                peer,
            ),
        ) != Err(CentralError::WrongPhase)
        {
            reset_all();
            return TestResult::Fail("second extended connect accepted while Connecting");
        }
        // Command Status refusal (0x0C) returns to Idle, no link.
        fake.enqueue_event(cs(op::HCI_LE_EXTENDED_CREATE_CONNECTION, 0x0C));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Idle)
            || connection_count(0) != Some(0)
        {
            reset_all();
            return TestResult::Fail("refused extended create did not return to Idle");
        }
        // Retry on Coded only, from Idle: 26 bytes, phys 0x04.
        if central_connect_ext(
            0,
            crate::gap::ExtendedCreateConnection::to_peer_coded(
                crate::gap::PeerAddressType::Public,
                peer,
            ),
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("Coded retry rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_coded: [u8; 26] = [
            0x00, 0x00, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x04, 0x30, 0x00, 0x30, 0x00,
            0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        if sent.last().map(|(o, _)| *o) != Some(op::HCI_LE_EXTENDED_CREATE_CONNECTION)
            || sent.last().map(|(_, p)| p.as_slice()) != Some(&expect_coded[..])
        {
            reset_all();
            return TestResult::Fail("Coded extended-create bytes mismatch");
        }
        // Enhanced Complete failure (0x3E, Connection Failed to
        // be Established) returns to Idle with no connection.
        fake.enqueue_event(cs(op::HCI_LE_EXTENDED_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        let handle = 0x0041;
        fake.enqueue_event(le_enhanced_connection_complete_central(0x3E, handle, peer));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Idle)
            || connection_count(0) != Some(0)
        {
            reset_all();
            return TestResult::Fail("failed Enhanced Complete did not return to Idle");
        }
        // Retry again: success, CSA #1 recorded.
        if central_connect_ext(
            0,
            crate::gap::ExtendedCreateConnection::to_peer_coded(
                crate::gap::PeerAddressType::Public,
                peer,
            ),
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("second Coded retry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_LE_EXTENDED_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        fake.enqueue_event(le_enhanced_connection_complete_central(0x00, handle, peer));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Connected)
            || connection_count(0) != Some(1)
        {
            reset_all();
            return TestResult::Fail("Coded retry Enhanced Complete did not land connection");
        }
        fake.enqueue_event(le_channel_selection_event(handle, 0x00));
        let _ = pump_once(0);
        let ok = connection_channel_selection(0, handle) == Some(Some(0x00));
        reset_all();
        if !ok {
            return TestResult::Fail("CSA #1 not recorded on Coded connection");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_ext_create_connection_deferred_coded
    );

    /// #1312: phase guards reject out-of-order API calls instead of
    /// issuing commands the controller cannot honour.
    fn smoke_pump_central_wrong_phase() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let mut ok = central_stop_scan(0) == Err(CentralError::WrongPhase);
        let peer = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5];
        ok &= central_connect(0, crate::gap::PeerAddressType::Public, peer).is_ok();
        ok &= central_phase(0) == Some(crate::gap::CentralPhase::Connecting);
        ok &= central_start_scan(0, crate::gap::ScanParameters::default())
            == Err(CentralError::WrongPhase);
        ok &= central_connect(0, crate::gap::PeerAddressType::Public, peer)
            == Err(CentralError::WrongPhase);
        ok &= central_stop_scan(0) == Err(CentralError::WrongPhase);
        ok &= central_phase(99).is_none() && central_peers(99).is_none();
        // No extra commands beyond bring-up + the one direct Create.
        ok &= fake.sent_command_params().len() == 6;
        reset_all();
        if !ok {
            return TestResult::Fail("wrong-phase call issued a command or wrong error");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_central_wrong_phase);

    /// #823: the full extended-scan sequence against a scripted
    /// controller — parameters → enable → fragmented extended
    /// reports (reassembled) → second peer → scan timeout → stop —
    /// with the outbound command bytes pinned against the Core
    /// Specification field order, not against the encoders under test.
    fn smoke_pump_ext_central_scan_reports() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // 1. Start extended scan: LE Set Extended Scan Parameters,
        // pinned byte-for-byte against Vol 4 Part E §7.8.64 (1M
        // only, passive, 30 ms / 30 ms, public, accept-all).
        if ext_central_start_scan(0, crate::gap::ExtendedScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("ext_central_start_scan rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_params: [u8; 8] = [0x00, 0x00, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00];
        if sent.len() != 6
            || sent[5].0 != op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS
            || sent[5].1 != expect_params
        {
            reset_all();
            return TestResult::Fail("Set Extended Scan Parameters bytes mismatch");
        }
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::ParametersSent) {
            reset_all();
            return TestResult::Fail("phase not ParametersSent after ext start_scan");
        }
        // 2. Parameters complete -> Enable(1) issued by the pump.
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        if sent.len() != 7
            || sent[6].0 != op::HCI_LE_SET_EXTENDED_SCAN_ENABLE
            || sent[6].1 != [0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
        {
            reset_all();
            return TestResult::Fail(
                "Set Extended Scan Enable(1) not issued on parameters complete",
            );
        }
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Scanning) {
            reset_all();
            return TestResult::Fail("phase not Scanning after ext enable");
        }
        // Enable complete itself changes nothing.
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Scanning) {
            reset_all();
            return TestResult::Fail("ext enable complete moved phase out of Scanning");
        }
        // 3. Fragmented extended report: first fragment (more to
        // come) pends, second (complete) publishes reassembled data.
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        fake.enqueue_event(le_ext_advertising_report(
            0x0021,
            0x00,
            peer,
            0x01,
            0x02,
            0x03,
            -10,
            -60,
            &[0x02, 0x01, 0x06],
        ));
        let _ = pump_once(0);
        let peers = ext_central_peers(0).unwrap_or_default();
        if peers.len() != 1 || !peers[0].ad_data.is_empty() || !peers[0].reassembling {
            reset_all();
            return TestResult::Fail("first fragment should pend, not publish");
        }
        fake.enqueue_event(le_ext_advertising_report(
            0x0001,
            0x00,
            peer,
            0x01,
            0x02,
            0x03,
            -10,
            -55,
            &[0x05, 0x09, b'N', b'A', b'R', b'F'],
        ));
        let _ = pump_once(0);
        let peers = ext_central_peers(0).unwrap_or_default();
        if peers.len() != 1
            || peers[0].ad_data != [0x02, 0x01, 0x06, 0x05, 0x09, b'N', b'A', b'R', b'F']
            || peers[0].last_rssi != -55
            || peers[0].primary_phy != 0x01
            || peers[0].secondary_phy != 0x02
            || peers[0].sid != 0x03
            || peers[0].tx_power != -10
            || peers[0].reassembling
        {
            reset_all();
            return TestResult::Fail("complete fragment did not publish reassembled peer");
        }
        // Second peer (legacy extended report, SID 0xFF): distinct.
        fake.enqueue_event(le_ext_advertising_report(
            0x0010,
            0x01,
            [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5],
            0x01,
            0x00,
            0xFF,
            0x7F,
            -70,
            &[0x02, 0x01, 0x06],
        ));
        let _ = pump_once(0);
        if ext_central_peers(0).map(|p| p.len()) != Some(2) {
            reset_all();
            return TestResult::Fail("second extended peer not recorded");
        }
        // 4. Scan timeout ends the scan on its own.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x11],
        });
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Idle) {
            reset_all();
            return TestResult::Fail("scan timeout should return to Idle");
        }
        // 5. Restart, then stop: disable issued, completion to Idle.
        if ext_central_start_scan(0, crate::gap::ExtendedScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("ext restart rejected from Idle");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Scanning) {
            reset_all();
            return TestResult::Fail("ext restart did not reach Scanning");
        }
        if ext_central_stop_scan(0).is_err() {
            reset_all();
            return TestResult::Fail("ext_central_stop_scan rejected from Scanning");
        }
        let sent = fake.sent_command_params();
        let last = sent.last().cloned();
        if last
            != Some((
                op::HCI_LE_SET_EXTENDED_SCAN_ENABLE,
                alloc::vec![0, 0, 0, 0, 0, 0],
            ))
        {
            reset_all();
            return TestResult::Fail("stop did not issue Set Extended Scan Enable(0)");
        }
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::ScanStopping) {
            reset_all();
            return TestResult::Fail("phase not ScanStopping after ext stop");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Idle) {
            reset_all();
            return TestResult::Fail("disable complete should return to Idle");
        }
        // 6. A rejected enable(1) leaves the scanner Idle — scanning
        // never started — instead of stranding it in Scanning.
        if ext_central_start_scan(0, crate::gap::ExtendedScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("ext restart rejected from Idle");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Scanning) {
            reset_all();
            return TestResult::Fail("ext restart did not reach Scanning");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_ENABLE, &[0x0C]));
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Idle) {
            reset_all();
            return TestResult::Fail("rejected ext enable should return to Idle");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_ext_central_scan_reports);

    /// #823: the full advertising-set chain against a scripted
    /// controller — parameters → data → scan response → enable →
    /// terminated → restart (no scan response) → stop — with the
    /// outbound command bytes pinned against the Core Specification
    /// field order, not against the encoders under test.
    fn smoke_pump_ext_adv_start_chain() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let data: [u8; 9] = [0x02, 0x01, 0x06, 0x05, 0x09, b'N', b'A', b'R', b'F'];
        let scan_rsp: [u8; 3] = [0x02, 0x01, 0x06];
        // 1. Start set 0: LE Set Extended Advertising Parameters,
        // pinned byte-for-byte against Vol 4 Part E §7.8.53
        // (default: legacy connectable, 100 ms, all channels,
        // controller-chosen Tx power).
        if ext_adv_start(
            0,
            crate::gap::ExtendedAdvertisingParameters::default(),
            &data,
            Some(&scan_rsp),
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("ext_adv_start rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_params: [u8; 25] = [
            0x00, 0x13, 0x00, 0xA0, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x01, 0x00, 0x01, 0x00, 0x00,
        ];
        if sent.len() != 6
            || sent[5].0 != op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS
            || sent[5].1 != expect_params
        {
            reset_all();
            return TestResult::Fail("Set Extended Advertising Parameters bytes mismatch");
        }
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::ParametersSent) {
            reset_all();
            return TestResult::Fail("phase not ParametersSent after ext_adv_start");
        }
        if ext_adv_selected_tx_power(0, 0).is_some() {
            reset_all();
            return TestResult::Fail("Tx power must be None before parameters complete");
        }
        // 2. Parameters complete (selected Tx power -10) -> data.
        fake.enqueue_event(cc(
            op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
            &[0, 0xF6],
        ));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        let expect_data: [u8; 13] = [
            0x00, 0x03, 0x01, 0x09, 0x02, 0x01, 0x06, 0x05, 0x09, b'N', b'A', b'R', b'F',
        ];
        if sent.len() != 7
            || sent[6].0 != op::HCI_LE_SET_EXTENDED_ADVERTISING_DATA
            || sent[6].1 != expect_data
        {
            reset_all();
            return TestResult::Fail(
                "Set Extended Advertising Data not issued on parameters complete",
            );
        }
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Configuring)
            || ext_adv_selected_tx_power(0, 0) != Some(-10)
        {
            reset_all();
            return TestResult::Fail("phase not Configuring / Tx power not recorded");
        }
        // 3. Data complete -> scan response data.
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_DATA, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        if sent.len() != 8
            || sent[7].0 != op::HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA
            || sent[7].1 != [0x00, 0x03, 0x01, 0x03, 0x02, 0x01, 0x06]
        {
            reset_all();
            return TestResult::Fail("Set Extended Scan Response Data not issued on data complete");
        }
        // 4. Scan response complete -> enable.
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        if sent.len() != 9
            || sent[8].0 != op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE
            || sent[8].1 != [0x01, 0x01, 0x00, 0x00, 0x00, 0x00]
        {
            reset_all();
            return TestResult::Fail(
                "Set Extended Advertising Enable not issued on scan-response complete",
            );
        }
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Enabling) {
            reset_all();
            return TestResult::Fail("phase not Enabling after enable issued");
        }
        // 5. Enable complete -> Advertising. A scan request received
        // while advertising leaves the phase alone.
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Advertising) {
            reset_all();
            return TestResult::Fail("enable complete should reach Advertising");
        }
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x13, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        });
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Advertising) {
            reset_all();
            return TestResult::Fail("scan request must not move the advertising phase");
        }
        // 6. Set terminated (duration/max-events reached) -> Idle.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x12, 0x00, 0x00, 0x00, 0x00, 0x03],
        });
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Idle) {
            reset_all();
            return TestResult::Fail("set terminated should return to Idle");
        }
        // 7. Restart without scan response: data complete goes
        // straight to enable.
        if ext_adv_start(
            0,
            crate::gap::ExtendedAdvertisingParameters::default(),
            &data,
            None,
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("ext_adv_start restart rejected from Idle");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
            &[0, 0x00],
        ));
        let _ = pump_once(0);
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_DATA, &[0]));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        let last = sent.last().cloned();
        if last
            != Some((
                op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE,
                alloc::vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x00],
            ))
        {
            reset_all();
            return TestResult::Fail("restart without scan response should enable after data");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Advertising) {
            reset_all();
            return TestResult::Fail("restart enable complete should reach Advertising");
        }
        // 8. Stop: disable issued, completion to Idle.
        if ext_adv_stop(0, 0).is_err() {
            reset_all();
            return TestResult::Fail("ext_adv_stop rejected from Advertising");
        }
        let sent = fake.sent_command_params();
        let last = sent.last().cloned();
        if last
            != Some((
                op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE,
                alloc::vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ))
        {
            reset_all();
            return TestResult::Fail("stop did not issue disable-one for the set");
        }
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Disabling) {
            reset_all();
            return TestResult::Fail("phase not Disabling after ext_adv_stop");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Idle) {
            reset_all();
            return TestResult::Fail("disable complete should return to Idle");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_ext_adv_start_chain);

    /// #823: extended failure + wrong-phase handling — oversize data
    /// is refused before any command, a second start mid-chain is
    /// refused, and a failed parameters completion drops the set so
    /// a later start can retry.
    fn smoke_pump_ext_adv_failure_and_wrong_phase() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        if ext_central_stop_scan(0) != Err(CentralError::WrongPhase) {
            reset_all();
            return TestResult::Fail("ext stop from Idle must be WrongPhase");
        }
        if ext_adv_stop(0, 0) != Err(CentralError::WrongPhase) {
            reset_all();
            return TestResult::Fail("ext_adv_stop with no set must be WrongPhase");
        }
        // 252-byte payload exceeds the 251-byte extended maximum.
        let big = [0u8; 252];
        if ext_adv_start(
            0,
            crate::gap::ExtendedAdvertisingParameters::default(),
            &big,
            None,
        ) != Err(CentralError::BadData)
        {
            reset_all();
            return TestResult::Fail("oversize advertising data must be BadData");
        }
        if fake.sent_command_params().len() != 5 {
            reset_all();
            return TestResult::Fail("BadData start must not issue a command");
        }
        // Start set 0; a second start (any handle) mid-chain is
        // refused, as is a stop while still configuring.
        let data: [u8; 3] = [0x02, 0x01, 0x06];
        if ext_adv_start(
            0,
            crate::gap::ExtendedAdvertisingParameters::default(),
            &data,
            None,
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("ext_adv_start rejected from Idle");
        }
        let mut params1 = crate::gap::ExtendedAdvertisingParameters::default();
        params1.handle = 0x01;
        if ext_adv_start(0, params1, &data, None) != Err(CentralError::WrongPhase) {
            reset_all();
            return TestResult::Fail("second start mid-chain must be WrongPhase");
        }
        if ext_adv_stop(0, 0) != Err(CentralError::WrongPhase) {
            reset_all();
            return TestResult::Fail("stop while configuring must be WrongPhase");
        }
        // Failed parameters completion drops the set to Idle and
        // clears the chain, so a retry works.
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS, &[0x05]));
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Idle) {
            reset_all();
            return TestResult::Fail("failed parameters should return to Idle");
        }
        if ext_adv_start(
            0,
            crate::gap::ExtendedAdvertisingParameters::default(),
            &data,
            None,
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("retry after failed parameters rejected");
        }
        // Extended scan failure: refused parameters drop to Idle.
        fake.enqueue_event(cc(
            op::HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
            &[0, 0x00],
        ));
        let _ = pump_once(0);
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_DATA, &[0]));
        let _ = pump_once(0);
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        if ext_adv_phase(0, 0) != Some(crate::gap::AdvertisingSetPhase::Advertising) {
            reset_all();
            return TestResult::Fail("retry chain should reach Advertising");
        }
        if ext_central_start_scan(0, crate::gap::ExtendedScanParameters::default()).is_err() {
            reset_all();
            return TestResult::Fail("ext scan start rejected from Idle");
        }
        if ext_central_start_scan(0, crate::gap::ExtendedScanParameters::default())
            != Err(CentralError::WrongPhase)
        {
            reset_all();
            return TestResult::Fail("second ext scan start must be WrongPhase");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_EXTENDED_SCAN_PARAMETERS, &[0x0C]));
        let _ = pump_once(0);
        if ext_central_phase(0) != Some(crate::gap::ExtendedScannerPhase::Idle) {
            reset_all();
            return TestResult::Fail("failed ext scan parameters should return to Idle");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_ext_adv_failure_and_wrong_phase);

    /// #1315: the full Classic sequence against a scripted
    /// controller — inquiry → result → complete → scan-enable →
    /// page/create-connection → complete → disconnect — with the
    /// outbound command bytes pinned against the Core Specification
    /// field order, not against the builders under test.
    fn smoke_pump_classic_inquiry_page_sequence() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // 1. Start inquiry: HCI_Inquiry, pinned byte-for-byte
        // against Vol 4 Part E §7.1.1 (GIAC, 8 x 1.28 s, unlimited
        // responses).
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_inquiry: [u8; 5] = [0x33, 0x8B, 0x9E, 0x08, 0x00];
        if sent.len() != 6 || sent[5].0 != op::HCI_INQUIRY || sent[5].1 != expect_inquiry {
            reset_all();
            return TestResult::Fail("HCI_Inquiry bytes mismatch");
        }
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Inquiring) {
            reset_all();
            return TestResult::Fail("phase not Inquiring after start_inquiry");
        }
        // Command Status (accepted) keeps Inquiring.
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Inquiring) {
            reset_all();
            return TestResult::Fail("accepted Command Status moved phase out of Inquiring");
        }
        // 2. Inquiry Result: peer recorded with its paging
        // parameters; a re-report refreshes instead of duplicating.
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        let cod = [0x10, 0x01, 0x00];
        fake.enqueue_event(inquiry_result_event(peer, 0x01, cod, 0x1234));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers.len() != 1
            || peers[0].bd_addr != peer
            || peers[0].page_scan_repetition_mode != 0x01
            || peers[0].class_of_device != cod
            || peers[0].clock_offset != 0x1234
        {
            reset_all();
            return TestResult::Fail("inquiry result not recorded as peer");
        }
        fake.enqueue_event(inquiry_result_event(peer, 0x02, cod, 0x5678));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers.len() != 1
            || peers[0].page_scan_repetition_mode != 0x02
            || peers[0].clock_offset != 0x5678
        {
            reset_all();
            return TestResult::Fail("peer re-report duplicated instead of refreshing");
        }
        // 3. Inquiry Complete ends the scan.
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Idle) {
            reset_all();
            return TestResult::Fail("inquiry complete did not return to Idle");
        }
        // 4. Scan enable (both): accepted on Command Complete.
        if classic_write_scan_enable(0, 3).is_err() {
            reset_all();
            return TestResult::Fail("classic_write_scan_enable rejected");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, p)| (*o, p.as_slice()))
            != Some((op::HCI_WRITE_SCAN_ENABLE, [0x03].as_slice()))
        {
            reset_all();
            return TestResult::Fail("Write Scan Enable bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_WRITE_SCAN_ENABLE, &[0]));
        let _ = pump_once(0);
        if classic_scan_mode(0) != Some(3) {
            reset_all();
            return TestResult::Fail("accepted scan enable did not record mode 3");
        }
        // 5. Page the discovered peer: Create Connection, pinned
        // byte-for-byte against Vol 4 Part E §7.1.5 (BD_ADDR,
        // packet types 0xCC18, PSRM 0x02, reserved 0, clock offset
        // 0x5678, allow role switch).
        if classic_connect(0, peer).is_err() {
            reset_all();
            return TestResult::Fail("classic_connect rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_create: [u8; 13] = [
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x18, 0xCC, 0x02, 0x00, 0x78, 0x56, 0x01,
        ];
        if sent.last().map(|(o, p)| (*o, p.as_slice()))
            != Some((op::HCI_CREATE_CONNECTION, expect_create.as_slice()))
        {
            reset_all();
            return TestResult::Fail("HCI_Create_Connection bytes mismatch");
        }
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Paging) {
            reset_all();
            return TestResult::Fail("phase not Paging after connect");
        }
        // Command Status (accepted) keeps Paging; Connection
        // Complete lands the connection.
        fake.enqueue_event(cs(op::HCI_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Paging) {
            reset_all();
            return TestResult::Fail("accepted Command Status moved phase out of Paging");
        }
        let handle = 0x0042;
        fake.enqueue_event(classic_connection_complete(handle, peer));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Connected)
            || connection_count(0) != Some(1)
        {
            reset_all();
            return TestResult::Fail("connection complete did not land classic connection");
        }
        // 6. Disconnect returns to Idle.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x42, 0x00, 0x13],
        });
        let _ = pump_once(0);
        let ok = connection_count(0) == Some(0)
            && classic_phase(0) == Some(crate::classic::ClassicPhase::Idle);
        reset_all();
        if !ok {
            return TestResult::Fail("disconnect did not return classic to Idle");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_classic_inquiry_page_sequence);

    /// #1315: connecting while inquiring cancels the inquiry and
    /// defers the page until Inquiry Complete — the controller is
    /// never asked to page while it is still inquiring. A rejected
    /// page returns to Idle with no connection, and paging an
    /// undiscovered address is refused without issuing a command.
    fn smoke_pump_classic_inquiry_cancel_deferred_page() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        let peer = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5];
        fake.enqueue_event(inquiry_result_event(peer, 0x01, [0x10, 0x01, 0x00], 0x0ABC));
        let _ = pump_once(0);
        // Connect from Inquiring: Inquiry_Cancel issued, page deferred.
        if classic_connect(0, peer).is_err() {
            reset_all();
            return TestResult::Fail("classic_connect rejected from Inquiring");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, _)| *o) != Some(op::HCI_INQUIRY_CANCEL)
            || classic_phase(0) != Some(crate::classic::ClassicPhase::InquiryStopping)
        {
            reset_all();
            return TestResult::Fail("connect did not cancel inquiry first");
        }
        // Cancel accepted: still InquiryStopping, no Create yet.
        fake.enqueue_event(cc(op::HCI_INQUIRY_CANCEL, &[0]));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::InquiryStopping)
            || fake
                .sent_command_params()
                .iter()
                .any(|(o, _)| *o == op::HCI_CREATE_CONNECTION)
        {
            reset_all();
            return TestResult::Fail("Create issued before Inquiry Complete");
        }
        // Inquiry Complete issues the deferred page with the
        // discovered paging parameters.
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        let expect_create: [u8; 13] = [
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0x18, 0xCC, 0x01, 0x00, 0xBC, 0x0A, 0x01,
        ];
        if sent.last().map(|(o, p)| (*o, p.as_slice()))
            != Some((op::HCI_CREATE_CONNECTION, expect_create.as_slice()))
            || classic_phase(0) != Some(crate::classic::ClassicPhase::Paging)
        {
            reset_all();
            return TestResult::Fail("deferred page not issued on Inquiry Complete");
        }
        // Page rejected by Command Status: Idle, no connection.
        fake.enqueue_event(cs(op::HCI_CREATE_CONNECTION, 0x0C));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Idle)
            || connection_count(0) != Some(0)
        {
            reset_all();
            return TestResult::Fail("rejected page did not return to Idle");
        }
        // Undiscovered address: refused, no command issued.
        let unknown = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5];
        let before = fake.sent_command_params().len();
        if classic_connect(0, unknown) != Err(ClassicError::UnknownPeer) {
            reset_all();
            return TestResult::Fail("connect to undiscovered peer did not fail UnknownPeer");
        }
        if fake.sent_command_params().len() != before {
            reset_all();
            return TestResult::Fail("unknown-peer connect issued a command");
        }
        // Cancel from Idle is a wrong-phase call.
        let ok = classic_cancel_inquiry(0) == Err(ClassicError::WrongPhase);
        reset_all();
        if !ok {
            return TestResult::Fail("cancel from Idle did not fail WrongPhase");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_classic_inquiry_cancel_deferred_page
    );

    /// #1315: failure paths fail closed — a refused inquiry returns
    /// to Idle without recording anything (and a retry works),
    /// malformed inquiry results record nothing, a failed inquiry
    /// drops a deferred page, a refused scan enable records no
    /// mode, and an out-of-range scan mode is rejected outright.
    fn smoke_pump_classic_failure_and_malformed() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0x0C));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Idle) {
            reset_all();
            return TestResult::Fail("refused inquiry did not return to Idle");
        }
        // Retry works: no wedge from the failure.
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("retry start_inquiry rejected after failure");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Inquiring) {
            reset_all();
            return TestResult::Fail("retry inquiry did not reach Inquiring");
        }
        // Malformed result (claims 2 entries, carries 1) records
        // nothing and panics nothing.
        let mut bad = alloc::vec![0x02];
        bad.extend_from_slice(&[0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5]);
        bad.extend_from_slice(&[0x01, 0x00, 0x00, 0x10, 0x01, 0x00, 0x34, 0x12]);
        fake.enqueue_event(Event {
            code: EventCode::InquiryResult as u8,
            params: bad,
        });
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(0) {
            reset_all();
            return TestResult::Fail("malformed inquiry result recorded a peer");
        }
        // Zero-response result likewise records nothing.
        fake.enqueue_event(Event {
            code: EventCode::InquiryResult as u8,
            params: alloc::vec![0x00],
        });
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(0) {
            reset_all();
            return TestResult::Fail("zero-response result recorded a peer");
        }
        // Deferred page dropped when the inquiry itself fails.
        let peer = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5];
        fake.enqueue_event(inquiry_result_event(peer, 0x01, [0x10, 0x01, 0x00], 0x0ABC));
        let _ = pump_once(0);
        if classic_connect(0, peer).is_err() {
            reset_all();
            return TestResult::Fail("classic_connect rejected from Inquiring");
        }
        fake.enqueue_event(cc(op::HCI_INQUIRY_CANCEL, &[0]));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_complete_event(0x0C));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Idle)
            || fake
                .sent_command_params()
                .iter()
                .any(|(o, _)| *o == op::HCI_CREATE_CONNECTION)
        {
            reset_all();
            return TestResult::Fail("failed inquiry issued the deferred page");
        }
        // Refused scan enable records no mode.
        if classic_write_scan_enable(0, 2).is_err() {
            reset_all();
            return TestResult::Fail("classic_write_scan_enable rejected");
        }
        fake.enqueue_event(cc(op::HCI_WRITE_SCAN_ENABLE, &[0x0C]));
        let _ = pump_once(0);
        if classic_scan_mode(0) != Some(0) {
            reset_all();
            return TestResult::Fail("refused scan enable recorded a mode");
        }
        // Out-of-range mode rejected without issuing a command.
        let before = fake.sent_command_params().len();
        let ok = classic_write_scan_enable(0, 4) == Err(ClassicError::BadScanMode)
            && fake.sent_command_params().len() == before;
        reset_all();
        if !ok {
            return TestResult::Fail("scan mode 4 did not fail BadScanMode");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_classic_failure_and_malformed);

    /// HCI_Inquiry_Result_with_RSSI event (§7.7.33): Num_Responses
    /// + one 14-byte entry (BD_ADDR, PSRM, Reserved, CoD,
    /// Clock_Offset, RSSI).
    fn inquiry_result_with_rssi_event(
        bd_addr: [u8; 6],
        psrm: u8,
        cod: [u8; 3],
        clock_offset: u16,
        rssi: i8,
    ) -> Event {
        let mut params = alloc::vec![0x01];
        params.extend_from_slice(&bd_addr);
        params.push(psrm);
        params.push(0x00); // reserved
        params.extend_from_slice(&cod);
        params.extend_from_slice(&clock_offset.to_le_bytes());
        params.push(rssi as u8);
        Event {
            code: EventCode::InquiryResultWithRssi as u8,
            params,
        }
    }

    /// HCI_Extended_Inquiry_Result event (§7.7.38):
    /// Num_Responses + one 254-byte entry (14-byte RSSI entry +
    /// 240-byte EIR).
    fn extended_inquiry_result_event(
        bd_addr: [u8; 6],
        psrm: u8,
        cod: [u8; 3],
        clock_offset: u16,
        rssi: i8,
        eir: &[u8; 240],
    ) -> Event {
        let mut params = alloc::vec![0x01];
        params.extend_from_slice(&bd_addr);
        params.push(psrm);
        params.push(0x00); // reserved
        params.extend_from_slice(&cod);
        params.extend_from_slice(&clock_offset.to_le_bytes());
        params.push(rssi as u8);
        params.extend_from_slice(eir);
        Event {
            code: EventCode::ExtendedInquiryResult as u8,
            params,
        }
    }

    /// HCI_Remote_Name_Request_Complete event (§7.7.7): Status(1)
    /// + BD_ADDR(6) + Remote_Name(248, NUL-padded).
    fn remote_name_complete_event(status: u8, bd_addr: [u8; 6], name: &[u8]) -> Event {
        let mut params = alloc::vec![status];
        params.extend_from_slice(&bd_addr);
        let mut field = [0u8; 248];
        let n = name.len().min(248);
        field[..n].copy_from_slice(&name[..n]);
        params.extend_from_slice(&field);
        Event {
            code: EventCode::RemoteNameRequestComplete as u8,
            params,
        }
    }

    /// Build a 240-byte EIR block from (AD type, payload) records,
    /// zero-padded like a controller that sends no further records.
    fn eir_block(records: &[(u8, &[u8])]) -> [u8; 240] {
        let mut buf = alloc::vec::Vec::new();
        for (ad_type, payload) in records {
            crate::gap::append_record(&mut buf, *ad_type, payload);
        }
        let mut eir = [0u8; 240];
        eir[..buf.len()].copy_from_slice(&buf);
        eir
    }

    /// #1315 remainder: EIR + RSSI + Remote Name Request. Inquiry
    /// mode 2 arms the 0x22/0x2F results; an RSSI result records
    /// the signal strength, an EIR result records RSSI + the local
    /// name (Complete wins over Shortened, a nameless re-report
    /// keeps the old name, a malformed EIR records the peer but no
    /// name, and a standard re-report keeps the RSSI); the name
    /// request is pinned byte-for-byte against §7.1.19, is
    /// single-flight, and delivers the name on Complete.
    fn smoke_pump_classic_eir_rssi_remote_name() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // 1. Write Inquiry Mode 2 (RSSI or EIR): accepted on
        // Command Complete.
        if classic_write_inquiry_mode(0, 2).is_err() {
            reset_all();
            return TestResult::Fail("classic_write_inquiry_mode rejected");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, p)| (*o, p.as_slice()))
            != Some((op::HCI_WRITE_INQUIRY_MODE, [0x02].as_slice()))
        {
            reset_all();
            return TestResult::Fail("Write Inquiry Mode bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_WRITE_INQUIRY_MODE, &[0]));
        let _ = pump_once(0);
        if classic_inquiry_mode(0) != Some(2) {
            reset_all();
            return TestResult::Fail("accepted inquiry mode did not record mode 2");
        }
        // 2. Start inquiry.
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        // 3. RSSI result: peer A recorded with its signal strength
        // and no name yet.
        let peer_a = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
        let cod = [0x10, 0x01, 0x00];
        fake.enqueue_event(inquiry_result_with_rssi_event(
            peer_a, 0x01, cod, 0x1234, -52,
        ));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers.len() != 1
            || peers[0].bd_addr != peer_a
            || peers[0].rssi != Some(-52)
            || peers[0].name_len != 0
        {
            reset_all();
            return TestResult::Fail("RSSI result not recorded with RSSI");
        }
        // 4. EIR result: peer B recorded with RSSI + the Complete
        // Local Name (a TX Power record in the same block is
        // skipped by the AD walker).
        let peer_b = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let eir = eir_block(&[
            (crate::gap::AD_COMPLETE_LOCAL_NAME, b"Headset-X"),
            (crate::gap::AD_TX_POWER_LEVEL, &[17]),
        ]);
        fake.enqueue_event(extended_inquiry_result_event(
            peer_b, 0x02, cod, 0x5678, -70, &eir,
        ));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers.len() != 2
            || peers[1].bd_addr != peer_b
            || peers[1].rssi != Some(-70)
            || peers[1].name_bytes() != b"Headset-X"
        {
            reset_all();
            return TestResult::Fail("EIR result not recorded with RSSI + name");
        }
        // 5. EIR re-report with a Shortened name refreshes the
        // name and RSSI; a nameless re-report keeps the name.
        let eir_short = eir_block(&[(crate::gap::AD_SHORTENED_LOCAL_NAME, b"HS-X")]);
        fake.enqueue_event(extended_inquiry_result_event(
            peer_b, 0x02, cod, 0x5678, -65, &eir_short,
        ));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers[1].rssi != Some(-65) || peers[1].name_bytes() != b"HS-X" {
            reset_all();
            return TestResult::Fail("EIR re-report did not refresh name + RSSI");
        }
        let eir_noname = eir_block(&[(crate::gap::AD_TX_POWER_LEVEL, &[12])]);
        fake.enqueue_event(extended_inquiry_result_event(
            peer_b,
            0x02,
            cod,
            0x5678,
            -60,
            &eir_noname,
        ));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers[1].rssi != Some(-60) || peers[1].name_bytes() != b"HS-X" {
            reset_all();
            return TestResult::Fail("nameless EIR re-report cleared the name");
        }
        // 6. Malformed EIR (first record claims 255 bytes in a
        // 240-byte block): peer recorded with RSSI, no name.
        let peer_c = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        let mut bad_eir = [0u8; 240];
        bad_eir[0] = 0xFF;
        bad_eir[1] = crate::gap::AD_COMPLETE_LOCAL_NAME;
        fake.enqueue_event(extended_inquiry_result_event(
            peer_c, 0x01, cod, 0x1111, -80, &bad_eir,
        ));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers.len() != 3
            || peers[2].bd_addr != peer_c
            || peers[2].rssi != Some(-80)
            || peers[2].name_len != 0
        {
            reset_all();
            return TestResult::Fail("malformed EIR recorded a name or dropped the peer");
        }
        // 7. Standard re-report of peer A keeps its RSSI.
        fake.enqueue_event(inquiry_result_event(peer_a, 0x03, cod, 0x4321));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers[0].page_scan_repetition_mode != 0x03
            || peers[0].clock_offset != 0x4321
            || peers[0].rssi != Some(-52)
        {
            reset_all();
            return TestResult::Fail("standard re-report cleared the RSSI");
        }
        // 8. Inquiry Complete ends the scan.
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        if classic_phase(0) != Some(crate::classic::ClassicPhase::Idle) {
            reset_all();
            return TestResult::Fail("inquiry complete did not return to Idle");
        }
        // 9. Remote Name Request for peer A: pinned byte-for-byte
        // against Vol 4 Part E §7.1.19 (BD_ADDR, PSRM 0x03,
        // reserved 0, clock offset 0x4321).
        if classic_request_remote_name(0, peer_a).is_err() {
            reset_all();
            return TestResult::Fail("classic_request_remote_name rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let expect_name_req: [u8; 10] =
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x03, 0x00, 0x21, 0x43];
        if sent.last().map(|(o, p)| (*o, p.as_slice()))
            != Some((op::HCI_REMOTE_NAME_REQUEST, expect_name_req.as_slice()))
        {
            reset_all();
            return TestResult::Fail("HCI_Remote_Name_Request bytes mismatch");
        }
        // Accepted Command Status keeps the request in flight: a
        // second request is refused without issuing a command.
        fake.enqueue_event(cs(op::HCI_REMOTE_NAME_REQUEST, 0));
        let _ = pump_once(0);
        let before = fake.sent_command_params().len();
        if classic_request_remote_name(0, peer_b) != Err(ClassicError::NameRequestPending)
            || fake.sent_command_params().len() != before
        {
            reset_all();
            return TestResult::Fail("second name request did not fail NameRequestPending");
        }
        // 10. Remote Name Request Complete delivers the name.
        fake.enqueue_event(remote_name_complete_event(0, peer_a, b"Speaker One"));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        if peers[0].name_bytes() != b"Speaker One" {
            reset_all();
            return TestResult::Fail("remote name not delivered to peer table");
        }
        // 11. A refused name request frees the slot (retry works),
        // and a failed Complete records no name.
        if classic_request_remote_name(0, peer_b).is_err() {
            reset_all();
            return TestResult::Fail("name request rejected after previous completed");
        }
        fake.enqueue_event(cs(op::HCI_REMOTE_NAME_REQUEST, 0x0C));
        let _ = pump_once(0);
        if classic_request_remote_name(0, peer_b).is_err() {
            reset_all();
            return TestResult::Fail("refused name request did not free the slot");
        }
        fake.enqueue_event(cs(op::HCI_REMOTE_NAME_REQUEST, 0));
        let _ = pump_once(0);
        fake.enqueue_event(remote_name_complete_event(0x04, peer_b, b"Should Not Land"));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        let ok = peers[1].name_bytes() == b"HS-X";
        reset_all();
        if !ok {
            return TestResult::Fail("failed name complete overwrote the EIR name");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_classic_eir_rssi_remote_name);

    /// #1315 remainder: name-request guards fail closed — an
    /// out-of-range inquiry mode is rejected, a refused inquiry
    /// mode records nothing, an undiscovered peer is refused, a
    /// request during inquiry is refused, malformed/zero-response
    /// RSSI/EIR results record nothing, and a Remote Name Request
    /// Complete for any address other than the pending one is
    /// ignored without freeing the slot.
    fn smoke_pump_classic_remote_name_guards() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // Out-of-range inquiry mode rejected without a command.
        let before = fake.sent_command_params().len();
        let ok = classic_write_inquiry_mode(0, 3) == Err(ClassicError::BadInquiryMode)
            && fake.sent_command_params().len() == before;
        if !ok {
            reset_all();
            return TestResult::Fail("inquiry mode 3 did not fail BadInquiryMode");
        }
        // Refused inquiry mode records nothing.
        if classic_write_inquiry_mode(0, 1).is_err() {
            reset_all();
            return TestResult::Fail("classic_write_inquiry_mode rejected");
        }
        fake.enqueue_event(cc(op::HCI_WRITE_INQUIRY_MODE, &[0x0C]));
        let _ = pump_once(0);
        if classic_inquiry_mode(0) != Some(0) {
            reset_all();
            return TestResult::Fail("refused inquiry mode recorded a mode");
        }
        // Undiscovered peer: refused, no command issued.
        let peer = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5];
        let before = fake.sent_command_params().len();
        if classic_request_remote_name(0, peer) != Err(ClassicError::UnknownPeer)
            || fake.sent_command_params().len() != before
        {
            reset_all();
            return TestResult::Fail("name request for undiscovered peer did not fail UnknownPeer");
        }
        // Start inquiry and discover the peer.
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        let cod = [0x10, 0x01, 0x00];
        fake.enqueue_event(inquiry_result_with_rssi_event(peer, 0x01, cod, 0x0ABC, -40));
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(1) {
            reset_all();
            return TestResult::Fail("RSSI result did not record the peer");
        }
        // Name request during inquiry: refused, no command issued.
        let before = fake.sent_command_params().len();
        if classic_request_remote_name(0, peer) != Err(ClassicError::WrongPhase)
            || fake.sent_command_params().len() != before
        {
            reset_all();
            return TestResult::Fail("name request during inquiry did not fail WrongPhase");
        }
        // Malformed RSSI result (claims 2 entries, carries 1)
        // records nothing new.
        let mut bad = alloc::vec![0x02];
        bad.extend_from_slice(&[0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5]);
        bad.extend_from_slice(&[0x01, 0x00, 0x10, 0x01, 0x00, 0x34, 0x12, 0xD0]);
        fake.enqueue_event(Event {
            code: EventCode::InquiryResultWithRssi as u8,
            params: bad,
        });
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(1) {
            reset_all();
            return TestResult::Fail("malformed RSSI result recorded a peer");
        }
        // Malformed EIR result (claims 1 entry, carries 100 bytes
        // of one) records nothing new.
        let mut bad_eir = alloc::vec![0x01];
        bad_eir.extend_from_slice(&[0u8; 100]);
        fake.enqueue_event(Event {
            code: EventCode::ExtendedInquiryResult as u8,
            params: bad_eir,
        });
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(1) {
            reset_all();
            return TestResult::Fail("malformed EIR result recorded a peer");
        }
        // Zero-response RSSI/EIR results record nothing.
        fake.enqueue_event(Event {
            code: EventCode::InquiryResultWithRssi as u8,
            params: alloc::vec![0x00],
        });
        let _ = pump_once(0);
        fake.enqueue_event(Event {
            code: EventCode::ExtendedInquiryResult as u8,
            params: alloc::vec![0x00],
        });
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(1) {
            reset_all();
            return TestResult::Fail("zero-response RSSI/EIR result recorded a peer");
        }
        // Inquiry Complete ends the scan.
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        // A Complete for an address nobody requested is ignored.
        let stranger = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5];
        fake.enqueue_event(remote_name_complete_event(0, stranger, b"Stranger"));
        let _ = pump_once(0);
        if classic_peers(0).map(|p| p.len()) != Some(1) {
            reset_all();
            return TestResult::Fail("stray name complete recorded a peer");
        }
        // Request the real peer's name; a Complete for a different
        // address is ignored and does NOT free the slot.
        if classic_request_remote_name(0, peer).is_err() {
            reset_all();
            return TestResult::Fail("classic_request_remote_name rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_REMOTE_NAME_REQUEST, 0));
        let _ = pump_once(0);
        fake.enqueue_event(remote_name_complete_event(0, stranger, b"Stranger"));
        let _ = pump_once(0);
        if classic_request_remote_name(0, peer) != Err(ClassicError::NameRequestPending) {
            reset_all();
            return TestResult::Fail("stray name complete freed the pending slot");
        }
        // The matching Complete delivers the name.
        fake.enqueue_event(remote_name_complete_event(0, peer, b"Guard Peer"));
        let _ = pump_once(0);
        let peers = classic_peers(0).unwrap_or_default();
        let ok = peers.len() == 1 && peers[0].name_bytes() == b"Guard Peer";
        reset_all();
        if !ok {
            return TestResult::Fail("matching name complete did not deliver the name");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_classic_remote_name_guards);

    // ── #814: SCO socket backend fixtures ────────────────────────

    /// HCI_Synchronous_Connection_Complete event (§7.7.35): Status,
    /// Handle, BD_ADDR, Link_Type, TX_Interval, ReTx_Window,
    /// Rx_Len, Tx_Len, Air_Mode. Bytes pinned against the spec
    /// layout, not against `SyncConnectionComplete::parse`.
    fn sync_connection_complete_event(
        status: u8,
        handle: u16,
        bd_addr: [u8; 6],
        rx_len: u16,
        tx_len: u16,
    ) -> Event {
        let mut params = alloc::vec![status];
        params.extend_from_slice(&handle.to_le_bytes());
        params.extend_from_slice(&bd_addr);
        params.extend_from_slice(&[0x00, 0x07, 0x00]); // SCO link, TX interval 7, retx window 0
        params.extend_from_slice(&rx_len.to_le_bytes());
        params.extend_from_slice(&tx_len.to_le_bytes());
        params.push(0x02); // air mode CVSD
        Event {
            code: EventCode::SyncConnectionComplete as u8,
            params,
        }
    }

    /// Expected Setup Synchronous Connection params for `handle`
    /// with the socket's CVSD defaults (§7.1.26): 8 kHz TX/RX,
    /// 0xFFFF max latency, voice 0x0060, retransmission effort
    /// 0x02, all eSCO packet types 0x003F.
    fn expected_setup_sync_params(handle: u16) -> Vec<u8> {
        alloc::vec![
            (handle & 0xFF) as u8,
            (handle >> 8) as u8,
            0x40,
            0x1F,
            0x00,
            0x00, // TX 8000
            0x40,
            0x1F,
            0x00,
            0x00, // RX 8000
            0xFF,
            0xFF, // max latency
            0x60,
            0x00, // voice CVSD
            0x02, // retransmission effort
            0x3F,
            0x00, // packet types
        ]
    }

    /// #814: SCO connect over a live ACL — Setup Sync with the
    /// pinned CVSD params, Synchronous Connection Complete lands
    /// the link, then send/recv move SCO frames through the
    /// scripted peer and disconnect tears the link down.
    fn smoke_pump_sco_connect_send_recv() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        let acl_handle = 0x0042;
        let sco_handle = 0x0043;
        // 1. Seed the ACL link directly (the paging half is covered
        // by the classic fixtures).
        fake.enqueue_event(classic_connection_complete(acl_handle, peer));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("ACL seed did not land a connection");
        }
        // 2. SCO connect over the live ACL issues Setup Synchronous
        // Connection with the pinned CVSD params.
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::Pending
        {
            reset_all();
            return TestResult::Fail("sco_connect over live ACL did not go Pending");
        }
        let sent = fake.sent_command_params();
        if sent.last()
            != Some(&(
                op::HCI_SETUP_SYNCHRONOUS_CONNECTION,
                expected_setup_sync_params(acl_handle),
            ))
        {
            reset_all();
            return TestResult::Fail("sco_connect did not issue the pinned Setup Sync command");
        }
        if sco_connect_status(0, peer) != BtScoConnectResult::Pending {
            reset_all();
            return TestResult::Fail("sco_connect_status did not stay Pending before completion");
        }
        // 3. Synchronous Connection Complete lands the link with
        // the controller's SCO MTU (64 from the scripted bring-up).
        fake.enqueue_event(sync_connection_complete_event(0, sco_handle, peer, 60, 60));
        let _ = pump_once(0);
        match sco_connect_status(0, peer) {
            BtScoConnectResult::Connected {
                handle,
                mtu,
                dev_class,
            } if handle == sco_handle && mtu == 64 && dev_class == [0, 0, 0] => {}
            _ => {
                reset_all();
                return TestResult::Fail("sync complete did not land the link");
            }
        }
        // 4. Send one SCO frame; the scripted peer sees the exact
        // §5.4.3 packet.
        if send_sco(0, sco_handle, b"hello") != Ok(5) {
            reset_all();
            return TestResult::Fail("send_sco rejected a frame on the live link");
        }
        let frames = fake.sent_sco_frames();
        if frames.len() != 1
            || frames[0].handle != sco_handle
            || frames[0].packet_status != 0
            || frames[0].data != b"hello"
        {
            reset_all();
            return TestResult::Fail("sent SCO frame bytes mismatch");
        }
        // 5. An inbound SCO frame is staged by the pump drain and
        // comes back out of drain_sco_rx.
        fake.enqueue_sco(
            ScoData {
                handle: sco_handle,
                packet_status: 0,
                data: b"world".to_vec(),
            }
            .encode(),
        );
        let _ = pump_once(0);
        if !sco_rx_pending(0, sco_handle) {
            reset_all();
            return TestResult::Fail("inbound SCO frame did not stage");
        }
        if drain_sco_rx(0, sco_handle) != Some(alloc::vec![b"world".to_vec()]) {
            reset_all();
            return TestResult::Fail("drain_sco_rx did not return the staged frame");
        }
        if sco_rx_pending(0, sco_handle) {
            reset_all();
            return TestResult::Fail("drain_sco_rx left the link pending");
        }
        // 6. Disconnect issues HCI_Disconnect (reason 0x13) and the
        // link is gone: send and drain both refuse.
        if !disconnect_sco(0, sco_handle) {
            reset_all();
            return TestResult::Fail("disconnect_sco rejected the live link");
        }
        let sent = fake.sent_command_params();
        if sent.last() != Some(&(op::HCI_DISCONNECT, alloc::vec![0x43, 0x00, 0x13])) {
            reset_all();
            return TestResult::Fail("disconnect_sco did not issue HCI_Disconnect(0x13)");
        }
        if send_sco(0, sco_handle, b"x") != Err(BtSendError::NoChannel) {
            reset_all();
            return TestResult::Fail("send_sco accepted a frame after disconnect");
        }
        if drain_sco_rx(0, sco_handle).is_some() {
            reset_all();
            return TestResult::Fail("drain_sco_rx returned frames after disconnect");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_sco_connect_send_recv);

    /// #814: SCO connect with no live ACL pages first — inquiry,
    /// Create Connection, Connection Complete, then Setup Sync —
    /// and a second connect to the live link is AlreadyConnected.
    fn smoke_pump_sco_connect_pages_first() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5];
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_result_event(peer, 0x01, [0x10, 0x01, 0x00], 0x0ABC));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        // 1. No ACL yet: the page goes out first.
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::Pending
        {
            reset_all();
            return TestResult::Fail("sco_connect without an ACL did not go Pending");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, _)| *o) != Some(op::HCI_CREATE_CONNECTION) {
            reset_all();
            return TestResult::Fail("sco_connect without an ACL did not page first");
        }
        fake.enqueue_event(cs(op::HCI_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        if sco_connect_status(0, peer) != BtScoConnectResult::Pending {
            reset_all();
            return TestResult::Fail("sco_connect_status did not stay Pending while paging");
        }
        // 2. The page lands the ACL; Setup Sync follows at once.
        fake.enqueue_event(classic_connection_complete(0x0042, peer));
        let _ = pump_once(0);
        let sent = fake.sent_command_params();
        if sent.last()
            != Some(&(
                op::HCI_SETUP_SYNCHRONOUS_CONNECTION,
                expected_setup_sync_params(0x0042),
            ))
        {
            reset_all();
            return TestResult::Fail("page complete did not issue the pinned Setup Sync command");
        }
        // 3. Synchronous Connection Complete lands the link with
        // the peer's class from the inquiry record.
        fake.enqueue_event(sync_connection_complete_event(0, 0x0043, peer, 60, 60));
        let _ = pump_once(0);
        match sco_connect_status(0, peer) {
            BtScoConnectResult::Connected {
                handle,
                mtu,
                dev_class,
            } if handle == 0x0043 && mtu == 64 && dev_class == [0x10, 0x01, 0x00] => {}
            _ => {
                reset_all();
                return TestResult::Fail("paged SCO setup did not land the link");
            }
        }
        // 4. A second connect to the live link is refused outright.
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::AlreadyConnected
        {
            reset_all();
            return TestResult::Fail("second sco_connect did not report AlreadyConnected");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_sco_connect_pages_first);

    /// #814: SCO connect refusals — no pump, undiscovered peer,
    /// controller-refused setup (Page Timeout surfaces as
    /// Refused(0x04) and a retry re-issues the setup) — and a
    /// transport with no isoch endpoints fails SCO send closed.
    fn smoke_pump_sco_connect_refusals() -> TestResult {
        reset_all();
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        // 1. No pump for this controller index.
        if sco_connect(7, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::NoPump
        {
            reset_all();
            return TestResult::Fail("sco_connect without a pump did not report NoPump");
        }
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        // 2. Undiscovered peer: refused without issuing a command.
        let before = fake.sent_command_params().len();
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::UnknownPeer
        {
            reset_all();
            return TestResult::Fail(
                "sco_connect to an undiscovered peer did not report UnknownPeer",
            );
        }
        if fake.sent_command_params().len() != before {
            reset_all();
            return TestResult::Fail("sco_connect to an undiscovered peer issued a command");
        }
        // 3. Controller refuses the setup: Page Timeout surfaces.
        fake.enqueue_event(classic_connection_complete(0x0042, peer));
        let _ = pump_once(0);
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::Pending
        {
            reset_all();
            return TestResult::Fail("sco_connect over live ACL did not go Pending");
        }
        fake.enqueue_event(sync_connection_complete_event(0x04, 0x0043, peer, 60, 60));
        let _ = pump_once(0);
        if sco_connect_status(0, peer) != BtScoConnectResult::Refused(0x04) {
            reset_all();
            return TestResult::Fail("refused setup did not surface Refused(0x04)");
        }
        // 4. A retry after the refusal re-issues the setup and lands.
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::Pending
        {
            reset_all();
            return TestResult::Fail("sco_connect retry after refusal did not go Pending");
        }
        fake.enqueue_event(sync_connection_complete_event(0, 0x0043, peer, 60, 60));
        let _ = pump_once(0);
        if !matches!(
            sco_connect_status(0, peer),
            BtScoConnectResult::Connected { handle: 0x0043, .. }
        ) {
            reset_all();
            return TestResult::Fail("sco_connect retry did not land the link");
        }
        // 5. A transport with no isoch endpoints fails SCO send
        // closed and stages nothing on receive.
        fake.set_sco_unsupported(true);
        if send_sco(0, 0x0043, b"x") != Err(BtSendError::Unsupported) {
            reset_all();
            return TestResult::Fail("send_sco did not fail closed on an isoch-less transport");
        }
        fake.enqueue_sco(
            ScoData {
                handle: 0x0043,
                packet_status: 0,
                data: b"y".to_vec(),
            }
            .encode(),
        );
        let _ = pump_once(0);
        if sco_rx_pending(0, 0x0043) || drain_sco_rx(0, 0x0043).is_some() {
            reset_all();
            return TestResult::Fail("isoch-less transport staged an inbound SCO frame");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_sco_connect_refusals);

    /// #814: death of the ACL drops the SCO link riding on it —
    /// send and drain refuse, and no link survives for a later
    /// connect poll.
    fn smoke_pump_sco_acl_disconnect_drops_link() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        fake.enqueue_event(classic_connection_complete(0x0042, peer));
        let _ = pump_once(0);
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::Pending
        {
            reset_all();
            return TestResult::Fail("sco_connect over live ACL did not go Pending");
        }
        fake.enqueue_event(sync_connection_complete_event(0, 0x0043, peer, 60, 60));
        let _ = pump_once(0);
        if !matches!(
            sco_connect_status(0, peer),
            BtScoConnectResult::Connected { handle: 0x0043, .. }
        ) {
            reset_all();
            return TestResult::Fail("SCO setup did not land the link");
        }
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x42, 0x00, 0x13],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(0) {
            reset_all();
            return TestResult::Fail("ACL disconnect did not drop the connection");
        }
        if send_sco(0, 0x0043, b"x") != Err(BtSendError::NoChannel) {
            reset_all();
            return TestResult::Fail("send_sco accepted a frame after its ACL died");
        }
        if drain_sco_rx(0, 0x0043).is_some() {
            reset_all();
            return TestResult::Fail("drain_sco_rx returned frames after its ACL died");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_sco_acl_disconnect_drops_link);

    /// #814: cancelling a SCO setup while it pages leaves the page
    /// running but issues no SCO setup when the ACL lands; the
    /// poll reports Aborted.
    fn smoke_pump_sco_cancel_connect() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5];
        if classic_start_inquiry(0, crate::classic::GIAC, 8, 0).is_err() {
            reset_all();
            return TestResult::Fail("classic_start_inquiry rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_INQUIRY, 0));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_result_event(peer, 0x01, [0x10, 0x01, 0x00], 0x0ABC));
        let _ = pump_once(0);
        fake.enqueue_event(inquiry_complete_event(0));
        let _ = pump_once(0);
        if sco_connect(0, peer, crate::classic::SCO_VOICE_SETTING_CVSD)
            != BtScoConnectResult::Pending
        {
            reset_all();
            return TestResult::Fail("sco_connect without an ACL did not go Pending");
        }
        cancel_sco_connect(0, peer);
        if sco_connect_status(0, peer) != BtScoConnectResult::Aborted {
            reset_all();
            return TestResult::Fail("cancelled SCO setup did not report Aborted");
        }
        // The page still lands a plain ACL connection — and no SCO
        // setup follows it.
        fake.enqueue_event(cs(op::HCI_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        fake.enqueue_event(classic_connection_complete(0x0042, peer));
        let _ = pump_once(0);
        if connection_count(0) != Some(1) {
            reset_all();
            return TestResult::Fail("cancelled page did not land the ACL");
        }
        if fake
            .sent_command_params()
            .iter()
            .any(|(o, _)| *o == op::HCI_SETUP_SYNCHRONOUS_CONNECTION)
        {
            reset_all();
            return TestResult::Fail("cancelled SCO setup issued Setup Sync after the page landed");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_sco_cancel_connect);

    /// #1313: bring up the fake controller and land a central-role
    /// connection from Idle (Create issued directly, no scan
    /// dance), returning its handle.
    fn gatt_client_bring_up_connected(fake: Arc<ScriptedTransport>) -> Result<u16, &'static str> {
        central_bring_up(fake.clone())?;
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        if central_connect(0, crate::gap::PeerAddressType::Public, peer).is_err() {
            return Err("central_connect rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_LE_CREATE_CONNECTION, 0));
        let _ = pump_once(0);
        let handle = 0x0041;
        fake.enqueue_event(le_connection_complete_central(handle, peer));
        let _ = pump_once(0);
        if central_phase(0) != Some(crate::gap::CentralPhase::Connected)
            || connection_count(0) != Some(1)
        {
            return Err("central connection did not land");
        }
        Ok(handle)
    }

    /// Outbound ATT payloads on `handle`, in send order, from the
    /// fake's sent ACL frames.
    fn sent_att_payloads(fake: &ScriptedTransport, handle: u16) -> Vec<Vec<u8>> {
        fake.sent_acl_frames()
            .into_iter()
            .filter(|(h, f)| *h == handle && f.cid == CID_ATT)
            .map(|(_, f)| f.payload)
            .collect()
    }

    /// #1313: service discovery end-to-end — request bytes pinned
    /// against Vol 3 Part F §3.4.4.10 / Part G §4.4, continuation
    /// from the last end handle, Attribute Not Found termination,
    /// and exactly the two outbound requests (a wrong-demux server
    /// answer would add frames and fail the count).
    fn smoke_pump_gatt_client_discovery() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        let handle = match gatt_client_bring_up_connected(fake.clone()) {
            Ok(h) => h,
            Err(e) => {
                reset_all();
                return TestResult::Fail(e);
            }
        };
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("discover_services rejected on central connection");
        }
        let _ = pump_once(0);
        // Read By Group Type Request, pinned byte-for-byte: opcode
        // 0x10, start 0x0001, end 0xFFFF, group type 0x2800.
        let expect_req: [u8; 7] = [0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28];
        let sent = sent_att_payloads(&fake, handle);
        if sent.len() != 1 || sent[0] != expect_req {
            reset_all();
            return TestResult::Fail("discover services request bytes mismatch");
        }
        // Peer answers two services (GAP 0x1800, Battery 0x180F);
        // the client must continue from the last end handle + 1.
        let rsp: [u8; 14] = [
            0x11, 0x06, // Read By Group Type Rsp, length 6
            0x01, 0x00, 0x09, 0x00, 0x00, 0x18, // 0x0001-0x0009 GAP
            0x0A, 0x00, 0x0F, 0x00, 0x0F, 0x18, // 0x000A-0x000F Battery
        ];
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, rsp.to_vec())));
        let _ = pump_once(0);
        let expect_cont: [u8; 7] = [0x10, 0x10, 0x00, 0xFF, 0xFF, 0x00, 0x28];
        let sent = sent_att_payloads(&fake, handle);
        if sent.len() != 2 || sent[1] != expect_cont {
            reset_all();
            return TestResult::Fail("discovery continuation bytes mismatch");
        }
        // Attribute Not Found terminates discovery.
        let err: [u8; 5] = [0x01, 0x10, 0x10, 0x00, 0x0A];
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, err.to_vec())));
        let _ = pump_once(0);
        let services = gatt_client_services(0, handle).unwrap_or_default();
        let ok = services.len() == 2
            && services[0].start_handle == 0x0001
            && services[0].end_handle == 0x0009
            && services[0].uuid == crate::gatt::Uuid::U16(0x1800)
            && services[1].start_handle == 0x000A
            && services[1].end_handle == 0x000F
            && services[1].uuid == crate::gatt::Uuid::U16(0x180F)
            && sent_att_payloads(&fake, handle).len() == 2;
        reset_all();
        if !ok {
            return TestResult::Fail("discovered services mismatch or stray frames");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_gatt_client_discovery);

    /// #1313: read, lock-step write, CCCD subscription, and
    /// notification/indication intake (indications confirm).
    fn smoke_pump_gatt_client_read_write_subscribe() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        let handle = match gatt_client_bring_up_connected(fake.clone()) {
            Ok(h) => h,
            Err(e) => {
                reset_all();
                return TestResult::Fail(e);
            }
        };
        // Read: request pinned, value returned verbatim.
        if gatt_client_read(0, handle, 0x0003).is_err() {
            reset_all();
            return TestResult::Fail("read rejected on central connection");
        }
        let _ = pump_once(0);
        let sent = sent_att_payloads(&fake, handle);
        if sent.len() != 1 || sent[0] != [0x0A, 0x03, 0x00] {
            reset_all();
            return TestResult::Fail("read request bytes mismatch");
        }
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x0B, 0x4E, 0x41, 0x52, 0x46]),
        )); // "NARF"
        let _ = pump_once(0);
        if gatt_client_last_read(0, handle) != Some((0x0003, alloc::vec![0x4E, 0x41, 0x52, 0x46])) {
            reset_all();
            return TestResult::Fail("read value mismatch");
        }
        // Lock-step: a second request while the write is pending
        // fails, and the write completes on its Write Response.
        if gatt_client_write(0, handle, 0x0005, &[0x01, 0x02]).is_err() {
            reset_all();
            return TestResult::Fail("write rejected on central connection");
        }
        if gatt_client_read(0, handle, 0x0003) != Err(GattClientError::RequestPending) {
            reset_all();
            return TestResult::Fail("second request while pending did not fail lock-step");
        }
        let _ = pump_once(0);
        let sent = sent_att_payloads(&fake, handle);
        if sent.len() != 2 || sent[1] != [0x12, 0x05, 0x00, 0x01, 0x02] {
            reset_all();
            return TestResult::Fail("write request bytes mismatch");
        }
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x13])));
        let _ = pump_once(0);
        // Subscribe: CCCD write 0x0001 (notifications).
        if gatt_client_subscribe(0, handle, 0x0008, true).is_err() {
            reset_all();
            return TestResult::Fail("subscribe rejected on central connection");
        }
        let _ = pump_once(0);
        let sent = sent_att_payloads(&fake, handle);
        if sent.len() != 3 || sent[2] != [0x12, 0x08, 0x00, 0x01, 0x00] {
            reset_all();
            return TestResult::Fail("subscribe request bytes mismatch");
        }
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x13])));
        let _ = pump_once(0);
        if gatt_client_subscribed(0, handle) != Some(alloc::vec![0x0008]) {
            reset_all();
            return TestResult::Fail("subscription not recorded");
        }
        // Notification queues with no outbound traffic; indication
        // queues and confirms.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x1B, 0x05, 0x00, 0xAA]),
        ));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x1D, 0x05, 0x00, 0xBB]),
        ));
        let _ = pump_once(0);
        let sent = sent_att_payloads(&fake, handle);
        let notes = gatt_client_take_notifications(0, handle).unwrap_or_default();
        let ok = sent.len() == 4
            && sent[3] == [0x1E]
            && notes.len() == 2
            && notes[0] == (0x0005, alloc::vec![0xAA])
            && notes[1] == (0x0005, alloc::vec![0xBB]);
        reset_all();
        if !ok {
            return TestResult::Fail("notification/indication intake mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_gatt_client_read_write_subscribe
    );

    /// #1313: failure paths fail closed — non-terminator errors
    /// and malformed/mismatched responses fail the operation
    /// (pending cleared, retry works), client ops on a
    /// peripheral-role connection are refused, and peripheral ATT
    /// still reaches the GATT server.
    fn smoke_pump_gatt_client_errors_and_roles() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        let handle = match gatt_client_bring_up_connected(fake.clone()) {
            Ok(h) => h,
            Err(e) => {
                reset_all();
                return TestResult::Fail(e);
            }
        };
        // Non-terminator error fails the operation and records it.
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("discover rejected on central connection");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x10, 0x01, 0x00, 0x01]),
        ));
        let _ = pump_once(0);
        let err_ok = matches!(
            gatt_client_last_error(0, handle),
            Some(gatt_client::ClientFailure::ErrorResponse(e))
                if e.request_opcode == 0x10 && e.attribute_handle == 0x0001 && e.error_code == 0x01
        ) && gatt_client_services(0, handle) == Some(alloc::vec![]);
        if !err_ok {
            reset_all();
            return TestResult::Fail("non-terminator error not recorded");
        }
        // Retry works after failure: an immediate terminator
        // completes an empty discovery.
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("rediscover rejected after failure");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x10, 0x01, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        if gatt_client_services(0, handle) != Some(alloc::vec![]) {
            reset_all();
            return TestResult::Fail("terminator did not complete empty discovery");
        }
        // Malformed (truncated) and mismatched responses fail.
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("discover rejected for malformed case");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x11])));
        let _ = pump_once(0);
        if gatt_client_last_error(0, handle)
            != Some(gatt_client::ClientFailure::Malformed { opcode: 0x11 })
        {
            reset_all();
            return TestResult::Fail("truncated discovery response did not fail malformed");
        }
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("discover rejected for mismatch case");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x0B, 0x00]),
        ));
        let _ = pump_once(0);
        if gatt_client_last_error(0, handle)
            != Some(gatt_client::ClientFailure::Malformed { opcode: 0x0B })
        {
            reset_all();
            return TestResult::Fail("mismatched response did not fail malformed");
        }
        // Wrong role: disconnect the central link, then accept a
        // peripheral connection on a fresh handle. Client ops on
        // it are refused, and its ATT still reaches the server.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x41, 0x00, 0x13],
        });
        let _ = pump_once(0);
        let peri = 0x0042;
        fake.enqueue_event(le_connection_complete(
            peri,
            [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5],
        ));
        let _ = pump_once(0);
        if connection_count(0) != Some(1)
            || gatt_client_read(0, peri, 0x0003) != Err(GattClientError::NotCentral)
        {
            reset_all();
            return TestResult::Fail("peripheral connection accepted client traffic");
        }
        // A read of an unknown handle on the peripheral connection
        // is answered by the server with Invalid Handle — proving
        // the route_frame change did not break server dispatch.
        let before = sent_att_payloads(&fake, peri).len();
        fake.enqueue_acl(acl_packet(
            peri,
            &BFrame::new(CID_ATT, alloc::vec![0x0A, 0xFF, 0xFF]),
        ));
        let _ = pump_once(0);
        let sent = sent_att_payloads(&fake, peri);
        let ok = sent.len() == before + 1 && sent[before] == [0x01, 0x0A, 0xFF, 0xFF, 0x01];
        reset_all();
        if !ok {
            return TestResult::Fail("peripheral ATT did not reach the server");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_gatt_client_errors_and_roles);

    /// #1314: the pump's GATT server mounts the HID service as a
    /// boot keyboard, and its stored values answer reads/writes
    /// through the generic server path (Protocol Mode flips and
    /// sticks; Control Point accepts writes).
    fn smoke_pump_hogp_server_mount() -> TestResult {
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let probe = with_pump_core(0, |core| {
            let attrs = core.gatt.db.attrs();
            let find = |uuid: u16| {
                attrs
                    .iter()
                    .find(|a| a.uuid == crate::gatt::Uuid::U16(uuid))
            };
            let svc = attrs.iter().find(|a| {
                a.uuid == crate::gatt::Uuid::U16(0x2800) && a.value == alloc::vec![0x12, 0x18]
            });
            let info = find(0x2A4A).filter(|a| a.value == alloc::vec![0x11, 0x01, 0x00, 0x02]);
            let map =
                find(0x2A4B).filter(|a| a.value == crate::hogp::BOOT_KEYBOARD_REPORT_MAP.to_vec());
            let pm = find(0x2A4E).filter(|a| a.value == alloc::vec![0x01]);
            let kbd_in = find(0x2A22).map(|a| a.handle);
            let cccd = attrs.iter().find(|a| {
                a.uuid == crate::gatt::Uuid::U16(0x2902)
                    && a.value == alloc::vec![0x00, 0x00]
                    && kbd_in.map(|k| a.handle > k).unwrap_or(false)
            });
            let pm_handle = pm.map(|a| a.handle);
            let cp_handle = find(0x2A4C).map(|a| a.handle);
            (
                svc.is_some(),
                info.is_some(),
                map.is_some(),
                pm.is_some(),
                cccd.is_some(),
                pm_handle,
                cp_handle,
            )
        });
        let Ok((svc_ok, info_ok, map_ok, pm_ok, cccd_ok, pm_handle, cp_handle)) = probe else {
            reset_all();
            return TestResult::Fail("pump core unavailable for HID mount probe");
        };
        if !(svc_ok && info_ok && map_ok && pm_ok && cccd_ok) {
            reset_all();
            return TestResult::Fail("HID service mount mismatch");
        }
        let (Some(pm_h), Some(cp_h)) = (pm_handle, cp_handle) else {
            reset_all();
            return TestResult::Fail("HID mount handles missing");
        };
        // Protocol Mode reads back REPORT, flips to BOOT on write,
        // and sticks; Control Point accepts a write.
        let driven = with_pump_core(0, |core| {
            let read = |core: &mut PumpCore, h: u16| {
                core.gatt.handle_request(&att::Pdu {
                    opcode: att::ATT_READ_REQ,
                    params: h.to_le_bytes().to_vec(),
                })
            };
            let write = |core: &mut PumpCore, h: u16, v: &[u8]| {
                let mut params = h.to_le_bytes().to_vec();
                params.extend_from_slice(v);
                core.gatt.handle_request(&att::Pdu {
                    opcode: att::ATT_WRITE_REQ,
                    params,
                })
            };
            let r0 = read(core, pm_h);
            let w = write(core, pm_h, &[0x00]);
            let r1 = read(core, pm_h);
            let c = write(core, cp_h, &[0x01]);
            (r0, w, r1, c)
        });
        let Ok((r0, w, r1, c)) = driven else {
            reset_all();
            return TestResult::Fail("pump core unavailable for HID drive");
        };
        let ok = r0.opcode == att::ATT_READ_RSP
            && r0.params == alloc::vec![0x01]
            && w.opcode == att::ATT_WRITE_RSP
            && r1.opcode == att::ATT_READ_RSP
            && r1.params == alloc::vec![0x00]
            && c.opcode == att::ATT_WRITE_RSP;
        reset_all();
        if !ok {
            return TestResult::Fail("HID Protocol Mode / Control Point drive mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_hogp_server_mount);

    /// #1314: central HOGP flow for a boot keyboard — discover the
    /// HID service, attach, read map + info, select boot protocol,
    /// subscribe the boot input CCCD, then route notifications into
    /// the input rings (press, release, rollover-suppressed,
    /// truncated-ignored, valid-again).
    fn smoke_pump_hogp_client_boot_keyboard() -> TestResult {
        use narf_input::{__reset_modifiers_for_test, init_global_ring, pop_key, KeyCode};
        reset_all();
        init_global_ring(64);
        __reset_modifiers_for_test();
        let fake = Arc::new(ScriptedTransport::new());
        let handle = match gatt_client_bring_up_connected(fake.clone()) {
            Ok(h) => h,
            Err(e) => {
                reset_all();
                return TestResult::Fail(e);
            }
        };
        // Services: GAP + HID.
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("discover_services rejected");
        }
        let _ = pump_once(0);
        let rsp: [u8; 14] = [
            0x11, 0x06, // Read By Group Type Rsp, length 6
            0x01, 0x00, 0x09, 0x00, 0x00, 0x18, // 0x0001-0x0009 GAP
            0x10, 0x00, 0x20, 0x00, 0x12, 0x18, // 0x0010-0x0020 HID
        ];
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, rsp.to_vec())));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x10, 0x21, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        let services = gatt_client_services(0, handle).unwrap_or_default();
        if services.len() != 2 || services[1].uuid != crate::gatt::Uuid::U16(0x1812) {
            reset_all();
            return TestResult::Fail("HID service discovery mismatch");
        }
        // Characteristics in the HID range, pinned as Read By Type
        // Rsp tuples (decl, properties, value handle, UUID).
        if gatt_client_discover_characteristics(0, handle, 0x0010, 0x0020).is_err() {
            reset_all();
            return TestResult::Fail("discover_characteristics rejected");
        }
        let _ = pump_once(0);
        let chars_rsp: [u8; 44] = [
            0x09, 0x07, // Read By Type Rsp, unit 7
            0x11, 0x00, 0x02, 0x12, 0x00, 0x4A, 0x2A, // info
            0x13, 0x00, 0x02, 0x14, 0x00, 0x4B, 0x2A, // map
            0x15, 0x00, 0x04, 0x16, 0x00, 0x4C, 0x2A, // control point
            0x17, 0x00, 0x06, 0x18, 0x00, 0x4E, 0x2A, // protocol mode
            0x19, 0x00, 0x12, 0x1A, 0x00, 0x22, 0x2A, // boot kbd in
            0x1C, 0x00, 0x0E, 0x1D, 0x00, 0x32, 0x2A, // boot kbd out
        ];
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, chars_rsp.to_vec()),
        ));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x08, 0x1D, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        // Descriptors: CCCDs for the two boot characteristics.
        if gatt_client_discover_descriptors(0, handle, 0x0010, 0x0020).is_err() {
            reset_all();
            return TestResult::Fail("discover_descriptors rejected");
        }
        let _ = pump_once(0);
        let desc_rsp: [u8; 10] = [
            0x05, 0x01, // Find Information Rsp, 16-bit UUIDs
            0x1B, 0x00, 0x02, 0x29, // boot kbd in CCCD
            0x1E, 0x00, 0x02, 0x29, // boot kbd out CCCD
        ];
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, desc_rsp.to_vec())));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x04, 0x1F, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        let handles = match hogp_attach(0, handle) {
            Some(h) => h,
            None => {
                reset_all();
                return TestResult::Fail("hogp_attach rejected HID peer");
            }
        };
        if handles.boot_keyboard_input != Some(0x001A)
            || handles.protocol_mode != Some(0x0018)
            || handles.subscribe_targets != alloc::vec![(0x001B, true)]
        {
            reset_all();
            return TestResult::Fail("hogp_attach handle layout mismatch");
        }
        // Read map + info, feeding each back through note_last_read.
        if gatt_client_read(0, handle, 0x0014).is_err() {
            reset_all();
            return TestResult::Fail("report map read rejected");
        }
        let _ = pump_once(0);
        let mut map_rsp = alloc::vec![0x0B];
        map_rsp.extend_from_slice(&crate::hogp::BOOT_KEYBOARD_REPORT_MAP);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, map_rsp)));
        let _ = pump_once(0);
        if hogp_note_last_read(0, handle) != Some(true)
            || hogp_report_map(0, handle) != Some(crate::hogp::BOOT_KEYBOARD_REPORT_MAP.to_vec())
        {
            reset_all();
            return TestResult::Fail("report map readback mismatch");
        }
        if gatt_client_read(0, handle, 0x0012).is_err() {
            reset_all();
            return TestResult::Fail("hid info read rejected");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x0B, 0x11, 0x01, 0x00, 0x02]),
        ));
        let _ = pump_once(0);
        if hogp_note_last_read(0, handle) != Some(true)
            || hogp_hid_info(0, handle)
                != Some(crate::hogp::HidInformation {
                    bcd_hid: 0x0111,
                    country_code: 0,
                    flags: 0x02,
                })
        {
            reset_all();
            return TestResult::Fail("hid info readback mismatch");
        }
        // Boot protocol selection: write [0x00] to Protocol Mode.
        if hogp_protocol_mode_write(0, handle) != Some((0x0018, [0x00])) {
            reset_all();
            return TestResult::Fail("protocol mode write target mismatch");
        }
        if gatt_client_write(0, handle, 0x0018, &[0x00]).is_err() {
            reset_all();
            return TestResult::Fail("protocol mode write rejected");
        }
        let _ = pump_once(0);
        let sent = sent_att_payloads(&fake, handle);
        if !sent
            .iter()
            .any(|p| *p == alloc::vec![0x12, 0x18, 0x00, 0x00])
        {
            reset_all();
            return TestResult::Fail("protocol mode write bytes mismatch");
        }
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x13])));
        let _ = pump_once(0);
        if hogp_note_boot_mode(0, handle) != Some(()) || hogp_boot_mode(0, handle) != Some(true) {
            reset_all();
            return TestResult::Fail("boot mode not recorded");
        }
        // Subscribe the boot input CCCD.
        if gatt_client_subscribe(0, handle, 0x001B, true).is_err() {
            reset_all();
            return TestResult::Fail("subscribe rejected");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x13])));
        let _ = pump_once(0);
        // Press: LShift + A.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(
                CID_ATT,
                alloc::vec![0x1B, 0x1A, 0x00, 0x02, 0x00, 0x04, 0, 0, 0, 0, 0],
            ),
        ));
        let _ = pump_once(0);
        let n = hogp_route_drained(0, handle);
        let k0 = pop_key();
        let k1 = pop_key();
        if n != Some(2)
            || k0.map(|k| (k.code, k.pressed)) != Some((KeyCode::LeftShift, true))
            || k1.map(|k| (k.code, k.pressed)) != Some((KeyCode::A, true))
        {
            reset_all();
            return TestResult::Fail("boot keyboard press routing mismatch");
        }
        // Release: empty report.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(
                CID_ATT,
                alloc::vec![0x1B, 0x1A, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
        ));
        let _ = pump_once(0);
        let n = hogp_route_drained(0, handle);
        let k0 = pop_key();
        let k1 = pop_key();
        if n != Some(2)
            || k0.map(|k| (k.code, k.pressed)) != Some((KeyCode::LeftShift, false))
            || k1.map(|k| (k.code, k.pressed)) != Some((KeyCode::A, false))
        {
            reset_all();
            return TestResult::Fail("boot keyboard release routing mismatch");
        }
        // Rollover: all six slots 0x01 — phantom, no events.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(
                CID_ATT,
                alloc::vec![0x1B, 0x1A, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
            ),
        ));
        let _ = pump_once(0);
        if hogp_route_drained(0, handle) != Some(0) || pop_key().is_some() {
            reset_all();
            return TestResult::Fail("rollover report produced events");
        }
        // Truncated: 6 bytes, not 8 — ignored.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x1B, 0x1A, 0x00, 0x02, 0x00, 0x04]),
        ));
        let _ = pump_once(0);
        if hogp_route_drained(0, handle) != Some(0) || pop_key().is_some() {
            reset_all();
            return TestResult::Fail("truncated report produced events");
        }
        // Valid again after rollover: B press only (rollover did
        // not corrupt the previous-key state).
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(
                CID_ATT,
                alloc::vec![0x1B, 0x1A, 0x00, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0],
            ),
        ));
        let _ = pump_once(0);
        let n = hogp_route_drained(0, handle);
        let k0 = pop_key();
        let ok = n == Some(1)
            && k0.map(|k| (k.code, k.pressed)) == Some((KeyCode::B, true))
            && pop_key().is_none();
        reset_all();
        if !ok {
            return TestResult::Fail("post-rollover key routing mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_hogp_client_boot_keyboard);

    /// #1314: central HOGP flow for a boot mouse + a report-protocol
    /// input Report — mouse motion/buttons route to Pointer/Button
    /// events, and the Report payload stages undecoded only once
    /// its Report Reference has been read (unresolved payloads do
    /// not stage).
    fn smoke_pump_hogp_client_boot_mouse_and_undecoded() -> TestResult {
        use narf_input::{init_global_ring, pop_button, pop_pointer, PointerButtons};
        reset_all();
        init_global_ring(64);
        let fake = Arc::new(ScriptedTransport::new());
        let handle = match gatt_client_bring_up_connected(fake.clone()) {
            Ok(h) => h,
            Err(e) => {
                reset_all();
                return TestResult::Fail(e);
            }
        };
        // Services: GAP + HID (0x0010-0x0030).
        if gatt_client_discover_services(0, handle, 0x0001, 0xFFFF).is_err() {
            reset_all();
            return TestResult::Fail("discover_services rejected");
        }
        let _ = pump_once(0);
        let rsp: [u8; 14] = [
            0x11, 0x06, 0x01, 0x00, 0x09, 0x00, 0x00, 0x18, 0x10, 0x00, 0x30, 0x00, 0x12, 0x18,
        ];
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, rsp.to_vec())));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x10, 0x31, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        // Characteristics: info, map, control, protocol, boot kbd
        // in, boot mouse in, Report.
        if gatt_client_discover_characteristics(0, handle, 0x0010, 0x0030).is_err() {
            reset_all();
            return TestResult::Fail("discover_characteristics rejected");
        }
        let _ = pump_once(0);
        let chars_rsp: [u8; 51] = [
            0x09, 0x07, 0x11, 0x00, 0x02, 0x12, 0x00, 0x4A, 0x2A, 0x13, 0x00, 0x02, 0x14, 0x00,
            0x4B, 0x2A, 0x15, 0x00, 0x04, 0x16, 0x00, 0x4C, 0x2A, 0x17, 0x00, 0x06, 0x18, 0x00,
            0x4E, 0x2A, 0x19, 0x00, 0x12, 0x1A, 0x00, 0x22, 0x2A, 0x1C, 0x00, 0x12, 0x1D, 0x00,
            0x33, 0x2A, 0x1F, 0x00, 0x12, 0x20, 0x00, 0x4D, 0x2A,
        ];
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, chars_rsp.to_vec()),
        ));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x08, 0x20, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        // Descriptors: CCCDs + the Report Reference.
        if gatt_client_discover_descriptors(0, handle, 0x0010, 0x0030).is_err() {
            reset_all();
            return TestResult::Fail("discover_descriptors rejected");
        }
        let _ = pump_once(0);
        let desc_rsp: [u8; 18] = [
            0x05, 0x01, 0x1B, 0x00, 0x02, 0x29, 0x1E, 0x00, 0x02, 0x29, 0x21, 0x00, 0x02, 0x29,
            0x22, 0x00, 0x08, 0x29,
        ];
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, desc_rsp.to_vec())));
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x01, 0x04, 0x23, 0x00, 0x0A]),
        ));
        let _ = pump_once(0);
        let handles = match hogp_attach(0, handle) {
            Some(h) => h,
            None => {
                reset_all();
                return TestResult::Fail("hogp_attach rejected HID peer");
            }
        };
        if handles.boot_mouse_input != Some(0x001D)
            || handles.reports.len() != 1
            || handles.reports[0].value_handle != 0x0020
            || handles.reports[0].report_reference_handle != Some(0x0022)
            || handles.subscribe_targets
                != alloc::vec![(0x001B, true), (0x001E, true), (0x0021, true)]
        {
            reset_all();
            return TestResult::Fail("hogp_attach mouse/report layout mismatch");
        }
        // Unresolved Report payload does NOT stage.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x1B, 0x20, 0x00, 0xAA, 0xBB]),
        ));
        let _ = pump_once(0);
        if hogp_route_drained(0, handle) != Some(0)
            || hogp_take_undecoded(0, handle) != Some(alloc::vec![])
        {
            reset_all();
            return TestResult::Fail("unresolved report payload staged");
        }
        // Resolve the reference: read 0x0022 -> [id 1, input].
        if gatt_client_read(0, handle, 0x0022).is_err() {
            reset_all();
            return TestResult::Fail("report reference read rejected");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x0B, 0x01, 0x01]),
        ));
        let _ = pump_once(0);
        if hogp_note_last_read(0, handle) != Some(true) {
            reset_all();
            return TestResult::Fail("report reference readback not consumed");
        }
        // Subscribe mouse + report CCCDs (lock-step: one at a time).
        if gatt_client_subscribe(0, handle, 0x001E, true).is_err() {
            reset_all();
            return TestResult::Fail("mouse subscribe rejected");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x13])));
        let _ = pump_once(0);
        if gatt_client_subscribe(0, handle, 0x0021, true).is_err() {
            reset_all();
            return TestResult::Fail("report subscribe rejected");
        }
        let _ = pump_once(0);
        fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, alloc::vec![0x13])));
        let _ = pump_once(0);
        // Mouse: left button down, dx +5, dy -3.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x1B, 0x1D, 0x00, 0x01, 0x05, 0xFD]),
        ));
        let _ = pump_once(0);
        let n = hogp_route_drained(0, handle);
        let btn = pop_button();
        let ptr = pop_pointer();
        if n != Some(2)
            || btn.map(|b| (b.code, b.pressed)) != Some((narf_input::btn::BTN_LEFT, true))
            || ptr.map(|p| (p.dx, p.dy, p.buttons)) != Some((5, -3, PointerButtons::LEFT))
        {
            reset_all();
            return TestResult::Fail("boot mouse routing mismatch");
        }
        // Report payload now stages with its resolved ID.
        fake.enqueue_acl(acl_packet(
            handle,
            &BFrame::new(CID_ATT, alloc::vec![0x1B, 0x20, 0x00, 0xAA, 0xBB]),
        ));
        let _ = pump_once(0);
        let n = hogp_route_drained(0, handle);
        let staged = hogp_take_undecoded(0, handle);
        let ok = n == Some(0) && staged == Some(alloc::vec![(1u8, alloc::vec![0xAA, 0xBB])]);
        reset_all();
        if !ok {
            return TestResult::Fail("resolved report payload staging mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_hogp_client_boot_mouse_and_undecoded
    );
    /// #888: the pump initiates pairing, completes a Just Works LE
    /// SC exchange against the independent peer model, auto-starts
    /// encryption, distributes keys in §3.6.1 order (peer first,
    /// then host), stores the bond, and answers a reconnect LTK
    /// Request from the store. The peer-model f5 LTK is pinned
    /// byte-for-byte in the Start Encryption command and the LTK
    /// Request reply.
    fn smoke_pump_smp_initiator_bonding_full_exchange() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = smp888_bring_up_connect(&fake) {
            return fail(m);
        }
        // API guards: unknown handle, then the real trigger, then
        // AlreadyPairing while the session is in flight.
        if smp_initiate_pairing(0, 0x0001) != Some(Err(SmpInitiateError::UnknownHandle)) {
            return fail("initiate on unknown handle did not fail UnknownHandle");
        }
        if smp_initiate_pairing(0, SMP888_HANDLE) != Some(Ok(())) {
            return fail("initiate pairing failed");
        }
        if smp_initiate_pairing(0, SMP888_HANDLE) != Some(Err(SmpInitiateError::AlreadyPairing)) {
            return fail("second initiate did not fail AlreadyPairing");
        }
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let req = frames
            .iter()
            .find(|(h, f)| *h == SMP888_HANDLE && f.cid == CID_SMP)
            .map(|(_, f)| f.payload.clone());
        // Byte-exact Pairing Request: NoInputNoOutput (0x03 per
        // Part H §3.5.1 — NOT 0x00, which is DisplayOnly),
        // bonding|SC, IdKey|Sign offered and requested.
        if req
            != Some(alloc::vec![
                0x01,
                smp::IoCapability::NoInputNoOutput as u8,
                0x00,
                0x09,
                16,
                0x06,
                0x06
            ])
        {
            return fail("initiator Pairing Request bytes wrong");
        }
        // Peer (responder) answers: NoInputNoOutput (0x03 per
        // Part H §3.5.1), bonding|SC, IdKey|Sign both directions.
        let rsp = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_RESPONSE,
                &[
                    smp::IoCapability::NoInputNoOutput as u8,
                    0x00,
                    0x09,
                    16,
                    0x06,
                    0x06,
                ],
            )],
            SMP888_HANDLE,
        );
        if rsp.len() != 1 || rsp[0].len() != 65 || rsp[0][0] != smp::SMP_PAIRING_PUBLIC_KEY {
            return fail("initiator did not answer Response with a public key");
        }
        let mut pump_pk_x = [0u8; 32];
        let mut pump_pk_y = [0u8; 32];
        pump_pk_x.copy_from_slice(&rsp[0][1..33]);
        pump_pk_y.copy_from_slice(&rsp[0][33..65]);
        if pump_pk_x == [0u8; 32] {
            return fail("initiator public key is zero (entropy seam not live)");
        }
        let peer_dh = peer_dhkey_wire(SMP888_PEER_PRIV, &pump_pk_x, &pump_pk_y);
        let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
        let peer_pk_x = fe_to_wire(&peer_px);
        let peer_pk_y = fe_to_wire(&peer_py);
        let mut peer_pk_payload = Vec::with_capacity(64);
        peer_pk_payload.extend_from_slice(&peer_pk_x);
        peer_pk_payload.extend_from_slice(&peer_pk_y);
        let ca_frames = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_PUBLIC_KEY,
                &peer_pk_payload,
            )],
            SMP888_HANDLE,
        );
        if ca_frames.len() != 1
            || ca_frames[0].len() != 17
            || ca_frames[0][0] != smp::SMP_PAIRING_CONFIRM
        {
            return fail("initiator did not answer public key with Confirm");
        }
        let ca = &ca_frames[0][1..17];
        // Peer commits Cb and reveals Nb.
        let nb: [u8; 16] = [0xBB; 16];
        let cb = peer_f4(&sbox, &peer_pk_x, &pump_pk_x, &nb, 0);
        let na_ea = smp888_step_acls(
            &fake,
            &[
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &cb),
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &nb),
            ],
            SMP888_HANDLE,
        );
        if na_ea.len() != 2
            || na_ea[0].len() != 17
            || na_ea[0][0] != smp::SMP_PAIRING_RANDOM
            || na_ea[1].len() != 17
            || na_ea[1][0] != smp::SMP_PAIRING_DHKEY_CHECK
        {
            return fail("initiator did not answer Random with [Random, DHKey Check]");
        }
        let mut na = [0u8; 16];
        na.copy_from_slice(&na_ea[0][1..17]);
        if na == [0u8; 16] {
            return fail("initiator nonce is zero (entropy seam not live)");
        }
        // Peer verifies Ca and Ea against the independent model —
        // a wrong production f4/f6 fails the fixture here, not in
        // a later byte comparison.
        let want_ca = peer_f4(&sbox, &pump_pk_x, &peer_pk_x, &na, 0);
        if ca != &want_ca[..] {
            return fail("Ca mismatch: production f4 disagrees with the peer model");
        }
        let mac_key = peer_f5_mac_key(
            &sbox,
            &peer_dh,
            &na,
            &nb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &peer_dh,
            &na,
            &nb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let iocap_a: [u8; 3] = [
            smp::AUTH_BONDING | smp::AUTH_SC,
            0x00,
            smp::IoCapability::NoInputNoOutput as u8,
        ];
        let want_ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &na,
                n2: &nb,
                r: &[0u8; 16],
                iocap: &iocap_a,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if na_ea[1][1..17] != want_ea[..] {
            return fail("Ea mismatch: production f6 disagrees with the peer model");
        }
        // Peer answers with Eb. The initiator parks at
        // AuthComplete and auto-starts encryption — no bond yet.
        let iocap_b: [u8; 3] = [
            smp::AUTH_BONDING | smp::AUTH_SC,
            0x00,
            smp::IoCapability::NoInputNoOutput as u8,
        ];
        let eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &nb,
                n2: &na,
                r: &[0u8; 16],
                iocap: &iocap_b,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let cmds_before = fake.sent_commands().len();
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &eb)],
            SMP888_HANDLE,
        );
        if !eb_out.is_empty() {
            return fail("initiator sent SMP PDUs at AuthComplete (must wait for encryption)");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        let new_cmds = &fake.sent_commands()[cmds_before..];
        let start_enc = new_cmds
            .iter()
            .find(|c| c.opcode == op::HCI_LE_START_ENCRYPTION);
        let mut want_start_enc = Vec::with_capacity(26);
        want_start_enc.extend_from_slice(&SMP888_HANDLE.to_le_bytes());
        want_start_enc.extend_from_slice(&[0u8; 8]);
        want_start_enc.extend_from_slice(&0u16.to_le_bytes());
        want_start_enc.extend_from_slice(&want_ltk);
        match start_enc {
            Some(cmd) if cmd.params == want_start_enc => {}
            _ => return fail("initiator did not auto-start encryption with the f5 LTK"),
        }
        // Encryption reported: the initiator still sends nothing —
        // the Peripheral (peer) distributes first (§3.6.1).
        let after_enc = smp888_step_event(
            &fake,
            smp888_encryption_change_event(SMP888_HANDLE, 0, 1),
            SMP888_HANDLE,
        );
        if !after_enc.is_empty() {
            return fail("initiator distributed before the responder (order is Peripheral first)");
        }
        smp888_replenish(&fake, SMP888_HANDLE);
        // Peer distributes IRK, identity address, CSRK in order;
        // the first two steps emit nothing, the third releases
        // the host's own distribution PDUs.
        let irk_pin: [u8; 16] = [0xC0; 16];
        let csrk_pin: [u8; 16] = [0xD0; 16];
        let step1 = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_INFORMATION,
                &irk_pin,
            )],
            SMP888_HANDLE,
        );
        if !step1.is_empty() {
            return fail("initiator answered Identity Information early");
        }
        let step2 = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_ADDRESS_INFORMATION,
                &SMP888_PEER_ADDR,
            )],
            SMP888_HANDLE,
        );
        if !step2.is_empty() {
            return fail("initiator answered Identity Address early");
        }
        let step3 = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_SIGNING_INFORMATION,
                &csrk_pin,
            )],
            SMP888_HANDLE,
        );
        if step3.len() != 3
            || step3[0].len() != 17
            || step3[0][0] != smp::SMP_IDENTITY_INFORMATION
            || step3[0][1..17] == [0u8; 16]
            || step3[1].len() != 8
            || step3[1][0] != smp::SMP_IDENTITY_ADDRESS_INFORMATION
            || step3[1][1..8] != SMP888_LOCAL_ADDR
            || step3[2].len() != 17
            || step3[2][0] != smp::SMP_SIGNING_INFORMATION
            || step3[2][1..17] == [0u8; 16]
        {
            return fail("initiator distribution PDUs wrong (order/length/address/randomness)");
        }
        if bond_count(0) != Some(1) {
            return fail("bond not stored after distribution completed");
        }
        // The stored bond answers a reconnect LTK Request.
        let cmds_before = fake.sent_commands().len();
        let _ = smp888_step_event(
            &fake,
            smp888_ltk_request_event(SMP888_HANDLE, 0, 0),
            SMP888_HANDLE,
        );
        let new_cmds = &fake.sent_commands()[cmds_before..];
        let reply = new_cmds
            .iter()
            .find(|c| c.opcode == op::HCI_LE_LTK_REQUEST_REPLY);
        let mut want_reply = Vec::with_capacity(18);
        want_reply.extend_from_slice(&SMP888_HANDLE.to_le_bytes());
        want_reply.extend_from_slice(&want_ltk);
        match reply {
            Some(cmd) if cmd.params == want_reply => {}
            _ => return fail("stored bond did not answer LTK Request with the f5 LTK"),
        }
        if forget_bond(0, &SMP888_PEER_ADDR) != Some(true) {
            return fail("forget_bond did not remove the bond");
        }
        let cmds_before = fake.sent_commands().len();
        let _ = smp888_step_event(
            &fake,
            smp888_ltk_request_event(SMP888_HANDLE, 0, 0),
            SMP888_HANDLE,
        );
        let new_cmds = &fake.sent_commands()[cmds_before..];
        if !new_cmds
            .iter()
            .any(|c| c.opcode == op::HCI_LE_LTK_REQUEST_NEGATIVE_REPLY)
        {
            return fail("forgotten bond still answered LTK Request");
        }
        if forget_bond(0, &SMP888_PEER_ADDR) != Some(false) {
            return fail("forget_bond on unknown peer did not return false");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_initiator_bonding_full_exchange
    );

    /// mgmt opcodes/events used by the mgmt-driven pairing fixture
    /// (bluetooth/src/mgmt.rs; kept local so the pump fixture does
    /// not depend on mgmt's private consts).
    const MGMT_OP_SET_POWERED: u16 = 0x0005;
    const MGMT_OP_PAIR_DEVICE: u16 = 0x0019;
    const MGMT_OP_USER_CONFIRM_REPLY: u16 = 0x001c;
    const MGMT_OP_USER_CONFIRM_NEG_REPLY: u16 = 0x001d;
    const MGMT_OP_USER_PASSKEY_REPLY: u16 = 0x001e;
    const MGMT_OP_USER_PASSKEY_NEG_REPLY: u16 = 0x001f;
    const MGMT_OP_ADD_REMOTE_OOB_DATA: u16 = 0x0021;
    const MGMT_EV_CMD_COMPLETE: u16 = 0x0001;
    const MGMT_EV_CMD_STATUS: u16 = 0x0002;
    const MGMT_EV_USER_CONFIRM_REQUEST: u16 = 0x000f;
    const MGMT_EV_USER_PASSKEY_REQUEST: u16 = 0x0010;
    const MGMT_EV_PASSKEY_NOTIFY: u16 = 0x0017;

    /// One mgmt command frame: header (opcode/index/len) + params.
    fn mgmt_frame(opcode: u16, index: u16, params: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(6 + params.len());
        f.extend_from_slice(&opcode.to_le_bytes());
        f.extend_from_slice(&index.to_le_bytes());
        f.extend_from_slice(&(params.len() as u16).to_le_bytes());
        f.extend_from_slice(params);
        f
    }

    /// mgmt event capture for the pairing fixture.
    static MGMT_CAPTURED: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());
    fn mgmt_capture_sink(event: &[u8]) {
        MGMT_CAPTURED.lock().push(event.to_vec());
    }

    /// Enqueue the Command Completes a mgmt power-on consumes on
    /// the scripted transport. The identity re-reads return the
    /// bring-up values ("narf-pump" / 0x040C02), so the refresh is
    /// a no-op and no change event fires.
    fn enqueue_mgmt_power_on_ccs(fake: &ScriptedTransport) {
        fake.enqueue_event(cc(op::HCI_RESET, &[0]));
        fake.enqueue_event(cc(op::HCI_SET_EVENT_MASK, &[0]));
        let mut name_ret = alloc::vec![0u8; 249];
        name_ret[1..10].copy_from_slice(b"narf-pump");
        fake.enqueue_event(cc(op::HCI_READ_LOCAL_NAME, &name_ret));
        fake.enqueue_event(cc(op::HCI_READ_CLASS_OF_DEVICE, &[0, 0x04, 0x0C, 0x02]));
        fake.enqueue_event(cc(op::HCI_WRITE_SCAN_ENABLE, &[0]));
        fake.enqueue_event(cc(op::HCI_WRITE_AUTHENTICATION_ENABLE, &[0]));
        fake.enqueue_event(cc(op::HCI_WRITE_SIMPLE_PAIRING_MODE, &[0]));
        fake.enqueue_event(cc(op::HCI_WRITE_LE_HOST_SUPPORT, &[0]));
        fake.enqueue_event(cc(op::HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT, &[0]));
        fake.enqueue_event(cc(op::HCI_WRITE_PAGE_SCAN_TYPE, &[0]));
    }

    /// #815: the mgmt end of initiator pairing. PAIR_DEVICE via
    /// `mgmt::handle` returns Command Status now, and the full SMP
    /// exchange — the same scripted peer as
    /// `smoke_pump_smp_initiator_bonding_full_exchange`, initiated
    /// via mgmt instead of the pump API — ends with a Command
    /// Complete (PAIR_DEVICE, SUCCESS) on the mgmt event sink.
    fn smoke_mgmt_pair_device_full_exchange() -> TestResult {
        reset_all();
        crate::mgmt::__test_reset();
        MGMT_CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(mgmt_capture_sink);
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        // `previous` is Option<fn> (Copy), so the `move` closure
        // copies it and the outer binding stays usable for the
        // success-path restore below.
        let fail = move |msg: &'static str| -> TestResult {
            test_entropy::clear();
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            crate::mgmt::__test_reset();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = smp888_bring_up_connect(&fake) {
            return fail(m);
        }
        // Power the controller on through mgmt: the power-on CCs
        // are scripted first (identity re-reads return the
        // bring-up values).
        enqueue_mgmt_power_on_ccs(&fake);
        let on = crate::mgmt::handle(&mgmt_frame(MGMT_OP_SET_POWERED, 0, &[1]));
        if on.len() != 1
            || u16::from_le_bytes([on[0][0], on[0][1]]) != MGMT_EV_CMD_COMPLETE
            || u16::from_le_bytes([on[0][6], on[0][7]]) != MGMT_OP_SET_POWERED
            || on[0][8] != 0
        {
            return fail("mgmt power-on failed");
        }
        // PAIR_DEVICE via mgmt: Command Status (SUCCESS) now — the
        // pairing runs async and completes on the event sink.
        let mut pair_params = [0u8; 8];
        pair_params[..6].copy_from_slice(&SMP888_PEER6);
        pair_params[6] = 0x01; // LE public
        pair_params[7] = 0x03; // NoInputNoOutput
        let pair = crate::mgmt::handle(&mgmt_frame(MGMT_OP_PAIR_DEVICE, 0, &pair_params));
        if pair.len() != 1
            || u16::from_le_bytes([pair[0][0], pair[0][1]]) != MGMT_EV_CMD_STATUS
            || u16::from_le_bytes([pair[0][6], pair[0][7]]) != MGMT_OP_PAIR_DEVICE
            || pair[0][8] != 0
        {
            return fail("mgmt PAIR_DEVICE did not return Command Status SUCCESS");
        }
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let req = frames
            .iter()
            .find(|(h, f)| *h == SMP888_HANDLE && f.cid == CID_SMP)
            .map(|(_, f)| f.payload.clone());
        // Byte-exact Pairing Request: NoInputNoOutput (0x03 per
        // Part H §3.5.1 — NOT 0x00, which is DisplayOnly),
        // bonding|SC, IdKey|Sign offered and requested.
        if req
            != Some(alloc::vec![
                0x01,
                smp::IoCapability::NoInputNoOutput as u8,
                0x00,
                0x09,
                16,
                0x06,
                0x06
            ])
        {
            return fail("mgmt-initiated Pairing Request bytes wrong");
        }
        // Peer (responder) answers: NoInputNoOutput (0x03 per
        // Part H §3.5.1), bonding|SC, IdKey|Sign both directions.
        let rsp = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_RESPONSE,
                &[
                    smp::IoCapability::NoInputNoOutput as u8,
                    0x00,
                    0x09,
                    16,
                    0x06,
                    0x06,
                ],
            )],
            SMP888_HANDLE,
        );
        if rsp.len() != 1 || rsp[0].len() != 65 || rsp[0][0] != smp::SMP_PAIRING_PUBLIC_KEY {
            return fail("initiator did not answer Response with a public key");
        }
        let mut pump_pk_x = [0u8; 32];
        let mut pump_pk_y = [0u8; 32];
        pump_pk_x.copy_from_slice(&rsp[0][1..33]);
        pump_pk_y.copy_from_slice(&rsp[0][33..65]);
        if pump_pk_x == [0u8; 32] {
            return fail("initiator public key is zero (entropy seam not live)");
        }
        let peer_dh = peer_dhkey_wire(SMP888_PEER_PRIV, &pump_pk_x, &pump_pk_y);
        let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
        let peer_pk_x = fe_to_wire(&peer_px);
        let peer_pk_y = fe_to_wire(&peer_py);
        let mut peer_pk_payload = Vec::with_capacity(64);
        peer_pk_payload.extend_from_slice(&peer_pk_x);
        peer_pk_payload.extend_from_slice(&peer_pk_y);
        let ca_frames = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_PUBLIC_KEY,
                &peer_pk_payload,
            )],
            SMP888_HANDLE,
        );
        if ca_frames.len() != 1
            || ca_frames[0].len() != 17
            || ca_frames[0][0] != smp::SMP_PAIRING_CONFIRM
        {
            return fail("initiator did not answer public key with Confirm");
        }
        let ca = &ca_frames[0][1..17];
        // Peer commits Cb and reveals Nb.
        let nb: [u8; 16] = [0xBB; 16];
        let cb = peer_f4(&sbox, &peer_pk_x, &pump_pk_x, &nb, 0);
        let na_ea = smp888_step_acls(
            &fake,
            &[
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &cb),
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &nb),
            ],
            SMP888_HANDLE,
        );
        if na_ea.len() != 2
            || na_ea[0].len() != 17
            || na_ea[0][0] != smp::SMP_PAIRING_RANDOM
            || na_ea[1].len() != 17
            || na_ea[1][0] != smp::SMP_PAIRING_DHKEY_CHECK
        {
            return fail("initiator did not answer Random with [Random, DHKey Check]");
        }
        let mut na = [0u8; 16];
        na.copy_from_slice(&na_ea[0][1..17]);
        if na == [0u8; 16] {
            return fail("initiator nonce is zero (entropy seam not live)");
        }
        // Peer verifies Ca and Ea against the independent model —
        // a wrong production f4/f6 fails the fixture here, not in
        // a later byte comparison.
        let want_ca = peer_f4(&sbox, &pump_pk_x, &peer_pk_x, &na, 0);
        if ca != &want_ca[..] {
            return fail("Ca mismatch: production f4 disagrees with the peer model");
        }
        let mac_key = peer_f5_mac_key(
            &sbox,
            &peer_dh,
            &na,
            &nb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &peer_dh,
            &na,
            &nb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let iocap_a: [u8; 3] = [
            smp::AUTH_BONDING | smp::AUTH_SC,
            0x00,
            smp::IoCapability::NoInputNoOutput as u8,
        ];
        let want_ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &na,
                n2: &nb,
                r: &[0u8; 16],
                iocap: &iocap_a,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if na_ea[1][1..17] != want_ea[..] {
            return fail("Ea mismatch: production f6 disagrees with the peer model");
        }
        // Peer answers with Eb. The initiator parks at
        // AuthComplete and auto-starts encryption — no bond yet.
        let iocap_b: [u8; 3] = [
            smp::AUTH_BONDING | smp::AUTH_SC,
            0x00,
            smp::IoCapability::NoInputNoOutput as u8,
        ];
        let eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &nb,
                n2: &na,
                r: &[0u8; 16],
                iocap: &iocap_b,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let cmds_before = fake.sent_commands().len();
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &eb)],
            SMP888_HANDLE,
        );
        if !eb_out.is_empty() {
            return fail("initiator sent SMP PDUs at AuthComplete (must wait for encryption)");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        let new_cmds = &fake.sent_commands()[cmds_before..];
        let start_enc = new_cmds
            .iter()
            .find(|c| c.opcode == op::HCI_LE_START_ENCRYPTION);
        let mut want_start_enc = Vec::with_capacity(26);
        want_start_enc.extend_from_slice(&SMP888_HANDLE.to_le_bytes());
        want_start_enc.extend_from_slice(&[0u8; 8]);
        want_start_enc.extend_from_slice(&0u16.to_le_bytes());
        want_start_enc.extend_from_slice(&want_ltk);
        match start_enc {
            Some(cmd) if cmd.params == want_start_enc => {}
            _ => return fail("initiator did not auto-start encryption with the f5 LTK"),
        }
        // Encryption reported: the initiator still sends nothing —
        // the Peripheral (peer) distributes first (§3.6.1).
        let after_enc = smp888_step_event(
            &fake,
            smp888_encryption_change_event(SMP888_HANDLE, 0, 1),
            SMP888_HANDLE,
        );
        if !after_enc.is_empty() {
            return fail("initiator distributed before the responder (order is Peripheral first)");
        }
        smp888_replenish(&fake, SMP888_HANDLE);
        // Peer distributes IRK, identity address, CSRK in order;
        // the first two steps emit nothing, the third releases
        // the host's own distribution PDUs — and the initiator
        // reaches Done, completing the mgmt pairing.
        let irk_pin: [u8; 16] = [0xC0; 16];
        let csrk_pin: [u8; 16] = [0xD0; 16];
        let step1 = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_INFORMATION,
                &irk_pin,
            )],
            SMP888_HANDLE,
        );
        if !step1.is_empty() {
            return fail("initiator answered Identity Information early");
        }
        let step2 = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_ADDRESS_INFORMATION,
                &SMP888_PEER_ADDR,
            )],
            SMP888_HANDLE,
        );
        if !step2.is_empty() {
            return fail("initiator answered Identity Address early");
        }
        let step3 = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_SIGNING_INFORMATION,
                &csrk_pin,
            )],
            SMP888_HANDLE,
        );
        if step3.len() != 3
            || step3[0].len() != 17
            || step3[0][0] != smp::SMP_IDENTITY_INFORMATION
            || step3[0][1..17] == [0u8; 16]
            || step3[1].len() != 8
            || step3[1][0] != smp::SMP_IDENTITY_ADDRESS_INFORMATION
            || step3[1][1..8] != SMP888_LOCAL_ADDR
            || step3[2].len() != 17
            || step3[2][0] != smp::SMP_SIGNING_INFORMATION
            || step3[2][1..17] == [0u8; 16]
        {
            return fail("initiator distribution PDUs wrong (order/length/address/randomness)");
        }
        if bond_count(0) != Some(1) {
            return fail("bond not stored after distribution completed");
        }
        // The mgmt sink must have received the async completion:
        // Command Complete (PAIR_DEVICE, SUCCESS) echoing the peer.
        let completed = MGMT_CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == MGMT_EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == MGMT_OP_PAIR_DEVICE
                && e[8] == 0
                && e[9..15] == SMP888_PEER6[..]
                && e[15] == 0x01
        });
        test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        crate::mgmt::__test_reset();
        if !completed {
            return TestResult::Fail("mgmt sink never got PAIR_DEVICE Command Complete SUCCESS");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_mgmt_pair_device_full_exchange);

    /// Bring up the scripted controller + connection and power it
    /// on through mgmt: the shared prologue for the
    /// mgmt-driven MITM fixtures below.
    fn mgmt_pair_bring_up(fake: &Arc<ScriptedTransport>) -> Result<(), &'static str> {
        smp888_bring_up_connect(fake)?;
        enqueue_mgmt_power_on_ccs(fake);
        let on = crate::mgmt::handle(&mgmt_frame(MGMT_OP_SET_POWERED, 0, &[1]));
        if on.len() != 1
            || u16::from_le_bytes([on[0][0], on[0][1]]) != MGMT_EV_CMD_COMPLETE
            || u16::from_le_bytes([on[0][6], on[0][7]]) != MGMT_OP_SET_POWERED
            || on[0][8] != 0
        {
            return Err("mgmt power-on failed");
        }
        Ok(())
    }

    /// PAIR_DEVICE via mgmt with `io_cap`; expects Command Status
    /// SUCCESS (the pairing itself completes asynchronously).
    fn mgmt_pair_start(io_cap: u8) -> Result<(), &'static str> {
        let mut pair_params = [0u8; 8];
        pair_params[..6].copy_from_slice(&SMP888_PEER6);
        pair_params[6] = 0x01; // LE public
        pair_params[7] = io_cap;
        let pair = crate::mgmt::handle(&mgmt_frame(MGMT_OP_PAIR_DEVICE, 0, &pair_params));
        if pair.len() != 1
            || u16::from_le_bytes([pair[0][0], pair[0][1]]) != MGMT_EV_CMD_STATUS
            || u16::from_le_bytes([pair[0][6], pair[0][7]]) != MGMT_OP_PAIR_DEVICE
            || pair[0][8] != 0
        {
            return Err("mgmt PAIR_DEVICE did not return Command Status SUCCESS");
        }
        Ok(())
    }

    /// Keys of an mgmt-initiated pairing once the public keys are
    /// exchanged: both sides' public keys (wire order), the
    /// peer-side DHKey, and the initiator's stage-1 commitment
    /// Ca (verified by the peer once Na is revealed).
    struct MgmtPairKeys {
        pump_pk_x: [u8; 32],
        pump_pk_y: [u8; 32],
        peer_pk_x: [u8; 32],
        peer_pk_y: [u8; 32],
        peer_dh: [u8; 32],
        ca: [u8; 16],
    }

    /// Drive an mgmt-initiated pairing through the feature
    /// exchange and the public-key exchange against the scripted
    /// peer. `want_req` is the byte-exact Pairing Request the
    /// initiator must emit; `peer_rsp` is the peer's Pairing
    /// Response payload. Returns the exchanged keys plus the
    /// initiator's stage-1 commitment.
    fn mgmt_pair_to_public_key(
        fake: &ScriptedTransport,
        want_req: &[u8; 7],
        peer_rsp: &[u8; 6],
    ) -> Result<MgmtPairKeys, &'static str> {
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let req = frames
            .iter()
            .find(|(h, f)| *h == SMP888_HANDLE && f.cid == CID_SMP)
            .map(|(_, f)| f.payload.clone());
        if req != Some(want_req.to_vec()) {
            return Err("mgmt-initiated Pairing Request bytes wrong");
        }
        let rsp = smp888_step_acls(
            fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_RESPONSE,
                peer_rsp,
            )],
            SMP888_HANDLE,
        );
        if rsp.len() != 1 || rsp[0].len() != 65 || rsp[0][0] != smp::SMP_PAIRING_PUBLIC_KEY {
            return Err("initiator did not answer Response with a public key");
        }
        let mut pump_pk_x = [0u8; 32];
        let mut pump_pk_y = [0u8; 32];
        pump_pk_x.copy_from_slice(&rsp[0][1..33]);
        pump_pk_y.copy_from_slice(&rsp[0][33..65]);
        if pump_pk_x == [0u8; 32] {
            return Err("initiator public key is zero (entropy seam not live)");
        }
        let peer_dh = peer_dhkey_wire(SMP888_PEER_PRIV, &pump_pk_x, &pump_pk_y);
        let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
        let peer_pk_x = fe_to_wire(&peer_px);
        let peer_pk_y = fe_to_wire(&peer_py);
        let mut peer_pk_payload = Vec::with_capacity(64);
        peer_pk_payload.extend_from_slice(&peer_pk_x);
        peer_pk_payload.extend_from_slice(&peer_pk_y);
        let first = smp888_step_acls(
            fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_PUBLIC_KEY,
                &peer_pk_payload,
            )],
            SMP888_HANDLE,
        );
        if first.len() != 1 || first[0].len() != 17 || first[0][0] != smp::SMP_PAIRING_CONFIRM {
            return Err("initiator did not answer public key with Confirm");
        }
        let mut ca = [0u8; 16];
        ca.copy_from_slice(&first[0][1..17]);
        Ok(MgmtPairKeys {
            pump_pk_x,
            pump_pk_y,
            peer_pk_x,
            peer_pk_y,
            peer_dh,
            ca,
        })
    }

    /// Drive all 20 passkey rounds (§2.3.5.6.3) against the
    /// scripted peer, which uses `passkey` for every round.
    /// `first_cai` is the initiator's round-0 Confirm (returned
    /// by the step that delivered the peer's public key, or by
    /// the USER_PASSKEY_REPLY flush for the input case). Each
    /// round the peer verifies Cai once Nai is revealed; the
    /// initiator verifies Cbi once Nbi is revealed — a wrong
    /// production f4 fails the fixture here. Returns the round-19
    /// nonces (Na20, Nb20) and the initiator's DHKey Check.
    fn mgmt_pair_passkey_rounds(
        fake: &ScriptedTransport,
        sbox: &[u8; 256],
        keys: &MgmtPairKeys,
        passkey: u32,
        first_cai: [u8; 16],
    ) -> Result<([u8; 16], [u8; 16], [u8; 16]), &'static str> {
        let mut cai = first_cai;
        for round in 0..20u8 {
            let z = smp::passkey_bit_z(passkey, round);
            // Deterministic distinct peer nonce per round (the
            // peer's real nonce is random; the fixture pins the
            // value so both sides' f4/f6 inputs are checkable).
            let nbi = [0xC0u8.wrapping_add(round); 16];
            let cbi = peer_f4(sbox, &keys.peer_pk_x, &keys.pump_pk_x, &nbi, z);
            let out = smp888_step_acls(
                fake,
                &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &cbi)],
                SMP888_HANDLE,
            );
            if out.len() != 1 || out[0].len() != 17 || out[0][0] != smp::SMP_PAIRING_RANDOM {
                return Err("initiator did not answer round Confirm with its round Random");
            }
            let mut nai = [0u8; 16];
            nai.copy_from_slice(&out[0][1..17]);
            // The peer verifies Cai now that Nai is revealed.
            let want_cai = peer_f4(sbox, &keys.pump_pk_x, &keys.peer_pk_x, &nai, z);
            if cai != want_cai {
                return Err("Cai mismatch: production f4 disagrees with the peer model");
            }
            let out = smp888_step_acls(
                fake,
                &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &nbi)],
                SMP888_HANDLE,
            );
            if round < 19 {
                if out.len() != 1 || out[0].len() != 17 || out[0][0] != smp::SMP_PAIRING_CONFIRM {
                    return Err("initiator did not advance to the next passkey round");
                }
                cai.copy_from_slice(&out[0][1..17]);
            } else {
                if out.len() != 1 || out[0].len() != 17 || out[0][0] != smp::SMP_PAIRING_DHKEY_CHECK
                {
                    return Err("initiator did not finish the passkey rounds with a DHKey Check");
                }
                let mut ea = [0u8; 16];
                ea.copy_from_slice(&out[0][1..17]);
                return Ok((nai, nbi, ea));
            }
        }
        Err("passkey rounds did not terminate")
    }

    /// From AuthComplete (Eb accepted, encryption auto-started):
    /// check the Start Encryption command carries the f5 LTK,
    /// report encryption, drive the peer's Phase 3 distribution,
    /// and check the initiator's distribution PDUs, the stored
    /// bond, and the mgmt PAIR_DEVICE Command Complete.
    fn mgmt_pair_finish_distribution(
        fake: &ScriptedTransport,
        want_ltk: &[u8; 16],
    ) -> Result<(), &'static str> {
        let sent = fake.sent_commands();
        let start_enc = sent
            .iter()
            .find(|c| c.opcode == op::HCI_LE_START_ENCRYPTION);
        let mut want_start_enc = Vec::with_capacity(26);
        want_start_enc.extend_from_slice(&SMP888_HANDLE.to_le_bytes());
        want_start_enc.extend_from_slice(&[0u8; 8]);
        want_start_enc.extend_from_slice(&0u16.to_le_bytes());
        want_start_enc.extend_from_slice(want_ltk);
        match start_enc {
            Some(cmd) if cmd.params == want_start_enc => {}
            _ => return Err("initiator did not auto-start encryption with the f5 LTK"),
        }
        let after_enc = smp888_step_event(
            fake,
            smp888_encryption_change_event(SMP888_HANDLE, 0, 1),
            SMP888_HANDLE,
        );
        if !after_enc.is_empty() {
            return Err("initiator distributed before the responder (order is Peripheral first)");
        }
        smp888_replenish(fake, SMP888_HANDLE);
        let irk_pin: [u8; 16] = [0xC0; 16];
        let csrk_pin: [u8; 16] = [0xD0; 16];
        let step1 = smp888_step_acls(
            fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_INFORMATION,
                &irk_pin,
            )],
            SMP888_HANDLE,
        );
        if !step1.is_empty() {
            return Err("initiator answered Identity Information early");
        }
        let step2 = smp888_step_acls(
            fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_ADDRESS_INFORMATION,
                &SMP888_PEER_ADDR,
            )],
            SMP888_HANDLE,
        );
        if !step2.is_empty() {
            return Err("initiator answered Identity Address early");
        }
        let step3 = smp888_step_acls(
            fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_SIGNING_INFORMATION,
                &csrk_pin,
            )],
            SMP888_HANDLE,
        );
        if step3.len() != 3
            || step3[0].len() != 17
            || step3[0][0] != smp::SMP_IDENTITY_INFORMATION
            || step3[0][1..17] == [0u8; 16]
            || step3[1].len() != 8
            || step3[1][0] != smp::SMP_IDENTITY_ADDRESS_INFORMATION
            || step3[1][1..8] != SMP888_LOCAL_ADDR
            || step3[2].len() != 17
            || step3[2][0] != smp::SMP_SIGNING_INFORMATION
            || step3[2][1..17] == [0u8; 16]
        {
            return Err("initiator distribution PDUs wrong (order/length/address/randomness)");
        }
        if bond_count(0) != Some(1) {
            return Err("bond not stored after distribution completed");
        }
        let completed = MGMT_CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == MGMT_EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == MGMT_OP_PAIR_DEVICE
                && e[8] == 0
                && e[9..15] == SMP888_PEER6[..]
                && e[15] == 0x01
        });
        if !completed {
            return Err("mgmt sink never got PAIR_DEVICE Command Complete SUCCESS");
        }
        Ok(())
    }

    /// #818: Numeric Comparison end-to-end through mgmt.
    /// PAIR_DEVICE with KeyboardDisplay io_cap negotiates
    /// Numeric Comparison against a DisplayYesNo + MITM peer;
    /// the initiator parks after the peer's Random (no Random /
    /// DHKey Check leaves before the user confirms), the mgmt
    /// sink gets USER_CONFIRM_REQUEST with the g2 value, the
    /// USER_CONFIRM_REPLY resumes the exchange, and the pairing
    /// completes to an authenticated bond.
    fn smoke_mgmt_pair_device_numeric_comparison_full_exchange() -> TestResult {
        reset_all();
        crate::mgmt::__test_reset();
        MGMT_CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(mgmt_capture_sink);
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = move |msg: &'static str| -> TestResult {
            test_entropy::clear();
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            crate::mgmt::__test_reset();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = mgmt_pair_bring_up(&fake) {
            return fail(m);
        }
        if let Err(m) = mgmt_pair_start(smp::IoCapability::KeyboardDisplay as u8) {
            return fail(m);
        }
        // Pairing Request: KeyboardDisplay (0x04), bonding|SC|
        // MITM (0x0D), IdKey|Sign both directions.
        let keys = match mgmt_pair_to_public_key(
            &fake,
            &[0x01, 0x04, 0x00, 0x0D, 16, 0x06, 0x06],
            &[0x01, 0x00, 0x0D, 16, 0x06, 0x06],
        ) {
            Ok(keys) => keys,
            Err(m) => return fail(m),
        };
        // Peer commits Cb and reveals Nb. The initiator must
        // park: NO PDU leaves before the user confirms.
        let nb: [u8; 16] = [0xBB; 16];
        let cb = peer_f4(&sbox, &keys.peer_pk_x, &keys.pump_pk_x, &nb, 0);
        let parked = smp888_step_acls(
            &fake,
            &[
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &cb),
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &nb),
            ],
            SMP888_HANDLE,
        );
        if !parked.is_empty() {
            return fail("initiator sent PDUs while parked at Numeric Comparison");
        }
        // The mgmt sink must have the USER_CONFIRM_REQUEST event
        // (addr + type + hint 0 + value).
        let shown = match MGMT_CAPTURED.lock().iter().find(|e| {
            e.len() >= 18 && u16::from_le_bytes([e[0], e[1]]) == MGMT_EV_USER_CONFIRM_REQUEST
        }) {
            Some(e) => {
                if e[6..12] != SMP888_PEER6[..] || e[12] != 0x01 || e[13] != 0 {
                    return fail("USER_CONFIRM_REQUEST address/hint wrong");
                }
                u32::from_le_bytes([e[14], e[15], e[16], e[17]])
            }
            None => return fail("no USER_CONFIRM_REQUEST event on the mgmt sink"),
        };
        // Answer via mgmt: USER_CONFIRM_REPLY completes SUCCESS
        // echoing the peer.
        let mut confirm_params = [0u8; 7];
        confirm_params[..6].copy_from_slice(&SMP888_PEER6);
        confirm_params[6] = 0x01;
        let reply =
            crate::mgmt::handle(&mgmt_frame(MGMT_OP_USER_CONFIRM_REPLY, 0, &confirm_params));
        if reply.len() != 1
            || u16::from_le_bytes([reply[0][0], reply[0][1]]) != MGMT_EV_CMD_COMPLETE
            || u16::from_le_bytes([reply[0][6], reply[0][7]]) != MGMT_OP_USER_CONFIRM_REPLY
            || reply[0][8] != 0
            || reply[0][9..15] != SMP888_PEER6[..]
            || reply[0][15] != 0x01
        {
            return fail("USER_CONFIRM_REPLY did not complete SUCCESS");
        }
        // The confirm releases [Random, DHKeyCheck].
        let na_ea = smp888_step_acls(&fake, &[], SMP888_HANDLE);
        if na_ea.len() != 2
            || na_ea[0].len() != 17
            || na_ea[0][0] != smp::SMP_PAIRING_RANDOM
            || na_ea[1].len() != 17
            || na_ea[1][0] != smp::SMP_PAIRING_DHKEY_CHECK
        {
            return fail("initiator did not answer confirm with [Random, DHKey Check]");
        }
        let mut na = [0u8; 16];
        na.copy_from_slice(&na_ea[0][1..17]);
        if na == [0u8; 16] {
            return fail("initiator nonce is zero (entropy seam not live)");
        }
        // The displayed value is the g2 of the revealed nonces.
        if shown != peer_g2(&sbox, &keys.pump_pk_x, &keys.peer_pk_x, &na, &nb) {
            return fail("USER_CONFIRM_REQUEST value is not the g2 of the exchange");
        }
        // Peer verifies Ca and Ea against the independent model.
        let want_ca = peer_f4(&sbox, &keys.pump_pk_x, &keys.peer_pk_x, &na, 0);
        if keys.ca != want_ca {
            return fail("Ca mismatch: production f4 disagrees with the peer model");
        }
        let mac_key = peer_f5_mac_key(
            &sbox,
            &keys.peer_dh,
            &na,
            &nb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &keys.peer_dh,
            &na,
            &nb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let iocap_a: [u8; 3] = [0x0D, 0x00, smp::IoCapability::KeyboardDisplay as u8];
        let want_ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &na,
                n2: &nb,
                r: &[0u8; 16],
                iocap: &iocap_a,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if na_ea[1][1..17] != want_ea[..] {
            return fail("Ea mismatch: production f6 disagrees with the peer model");
        }
        // Peer answers with Eb. The initiator parks at
        // AuthComplete and auto-starts encryption — no bond yet.
        let iocap_b: [u8; 3] = [0x0D, 0x00, smp::IoCapability::DisplayYesNo as u8];
        let eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &nb,
                n2: &na,
                r: &[0u8; 16],
                iocap: &iocap_b,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &eb)],
            SMP888_HANDLE,
        );
        if !eb_out.is_empty() {
            return fail("initiator sent SMP PDUs at AuthComplete (must wait for encryption)");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        if let Err(m) = mgmt_pair_finish_distribution(&fake, &want_ltk) {
            return fail(m);
        }
        if bond_authenticated(0, &SMP888_PEER_ADDR) != Some(true) {
            return fail("bond is not authenticated after Numeric Comparison");
        }
        test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        crate::mgmt::__test_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_mgmt_pair_device_numeric_comparison_full_exchange
    );

    /// #818: a rejected Numeric Comparison aborts the pairing.
    /// Same setup as the confirmed exchange, but the mgmt reply
    /// is USER_CONFIRM_NEG_REPLY: the initiator queues Pairing
    /// Failed 0x0C (Numeric Comparison Failed), stores no bond,
    /// and the mgmt pairing completes AUTH_FAILED.
    fn smoke_mgmt_pair_device_numeric_comparison_rejected() -> TestResult {
        reset_all();
        crate::mgmt::__test_reset();
        MGMT_CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(mgmt_capture_sink);
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = move |msg: &'static str| -> TestResult {
            test_entropy::clear();
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            crate::mgmt::__test_reset();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = mgmt_pair_bring_up(&fake) {
            return fail(m);
        }
        if let Err(m) = mgmt_pair_start(smp::IoCapability::KeyboardDisplay as u8) {
            return fail(m);
        }
        let keys = match mgmt_pair_to_public_key(
            &fake,
            &[0x01, 0x04, 0x00, 0x0D, 16, 0x06, 0x06],
            &[0x01, 0x00, 0x0D, 16, 0x06, 0x06],
        ) {
            Ok(keys) => keys,
            Err(m) => return fail(m),
        };
        let nb: [u8; 16] = [0xBB; 16];
        let cb = peer_f4(&sbox, &keys.peer_pk_x, &keys.pump_pk_x, &nb, 0);
        let parked = smp888_step_acls(
            &fake,
            &[
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &cb),
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &nb),
            ],
            SMP888_HANDLE,
        );
        if !parked.is_empty() {
            return fail("initiator sent PDUs while parked at Numeric Comparison");
        }
        let mut neg_params = [0u8; 7];
        neg_params[..6].copy_from_slice(&SMP888_PEER6);
        neg_params[6] = 0x01;
        let reply =
            crate::mgmt::handle(&mgmt_frame(MGMT_OP_USER_CONFIRM_NEG_REPLY, 0, &neg_params));
        if reply.len() != 1
            || u16::from_le_bytes([reply[0][0], reply[0][1]]) != MGMT_EV_CMD_COMPLETE
            || u16::from_le_bytes([reply[0][6], reply[0][7]]) != MGMT_OP_USER_CONFIRM_NEG_REPLY
            || reply[0][8] != 0
        {
            return fail("USER_CONFIRM_NEG_REPLY did not complete SUCCESS");
        }
        let failed = smp888_step_acls(&fake, &[], SMP888_HANDLE);
        if failed.len() != 1
            || failed[0].len() != 2
            || failed[0][0] != smp::SMP_PAIRING_FAILED
            || failed[0][1] != smp::SMP_FAILED_NUMERIC_COMPARISON_FAILED
        {
            return fail("rejected Numeric Comparison did not queue Pairing Failed 0x0C");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored after a rejected Numeric Comparison");
        }
        let completed = MGMT_CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == MGMT_EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == MGMT_OP_PAIR_DEVICE
                && e[8] == crate::mgmt::STATUS_AUTH_FAILED
                && e[9..15] == SMP888_PEER6[..]
                && e[15] == 0x01
        });
        test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        crate::mgmt::__test_reset();
        if !completed {
            return TestResult::Fail(
                "mgmt sink never got PAIR_DEVICE Command Complete AUTH_FAILED",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_mgmt_pair_device_numeric_comparison_rejected
    );

    /// #818: Passkey Entry, initiator displays. PAIR_DEVICE with
    /// DisplayOnly io_cap against a KeyboardOnly + MITM peer
    /// negotiates PasskeyEntryInitiatorDisplays (Table 2.8: the
    /// initiator is the only side with a display). The initiator
    /// generates the passkey, notifies it via PASSKEY_NOTIFY on
    /// the mgmt sink, and the 20 rounds complete against the
    /// scripted peer typing that passkey in — ending in an
    /// authenticated bond.
    fn smoke_mgmt_pair_device_passkey_display_full_exchange() -> TestResult {
        reset_all();
        crate::mgmt::__test_reset();
        MGMT_CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(mgmt_capture_sink);
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = move |msg: &'static str| -> TestResult {
            test_entropy::clear();
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            crate::mgmt::__test_reset();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = mgmt_pair_bring_up(&fake) {
            return fail(m);
        }
        if let Err(m) = mgmt_pair_start(smp::IoCapability::DisplayOnly as u8) {
            return fail(m);
        }
        // Pairing Request: DisplayOnly (0x00), bonding|SC|MITM.
        let keys = match mgmt_pair_to_public_key(
            &fake,
            &[0x01, 0x00, 0x00, 0x0D, 16, 0x06, 0x06],
            &[0x02, 0x00, 0x0D, 16, 0x06, 0x06],
        ) {
            Ok(keys) => keys,
            Err(m) => return fail(m),
        };
        // The first Confirm out of the public-key step is round
        // 0's Cai — the rounds started when the key arrived.
        // The mgmt sink must have the PASSKEY_NOTIFY event with
        // the passkey the peer will type in.
        let passkey =
            match MGMT_CAPTURED.lock().iter().find(|e| {
                e.len() >= 18 && u16::from_le_bytes([e[0], e[1]]) == MGMT_EV_PASSKEY_NOTIFY
            }) {
                Some(e) => {
                    if e[6..12] != SMP888_PEER6[..] || e[12] != 0x01 || e[17] != 0 {
                        return fail("PASSKEY_NOTIFY address/entered wrong");
                    }
                    u32::from_le_bytes([e[13], e[14], e[15], e[16]])
                }
                None => return fail("no PASSKEY_NOTIFY event on the mgmt sink"),
            };
        if passkey > 999_999 {
            return fail("displayed passkey is not six digits");
        }
        let (na20, nb20, ea) = match mgmt_pair_passkey_rounds(&fake, &sbox, &keys, passkey, keys.ca)
        {
            Ok(r) => r,
            Err(m) => return fail(m),
        };
        // Stage 2 with the passkey as f6 R (§2.2.8 table 2.2).
        let r128 = smp::passkey_as_128(passkey);
        let mac_key = peer_f5_mac_key(
            &sbox,
            &keys.peer_dh,
            &na20,
            &nb20,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &keys.peer_dh,
            &na20,
            &nb20,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let iocap_a: [u8; 3] = [0x0D, 0x00, smp::IoCapability::DisplayOnly as u8];
        let want_ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &na20,
                n2: &nb20,
                r: &r128,
                iocap: &iocap_a,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if ea != want_ea {
            return fail("Ea mismatch: production f6 disagrees with the peer model");
        }
        let iocap_b: [u8; 3] = [0x0D, 0x00, smp::IoCapability::KeyboardOnly as u8];
        let eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &nb20,
                n2: &na20,
                r: &r128,
                iocap: &iocap_b,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &eb)],
            SMP888_HANDLE,
        );
        if !eb_out.is_empty() {
            return fail("initiator sent SMP PDUs at AuthComplete (must wait for encryption)");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        if let Err(m) = mgmt_pair_finish_distribution(&fake, &want_ltk) {
            return fail(m);
        }
        if bond_authenticated(0, &SMP888_PEER_ADDR) != Some(true) {
            return fail("bond is not authenticated after Passkey Entry");
        }
        test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        crate::mgmt::__test_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_mgmt_pair_device_passkey_display_full_exchange
    );

    /// #818: Passkey Entry, initiator inputs. PAIR_DEVICE with
    /// KeyboardOnly io_cap against a DisplayOnly + MITM peer
    /// negotiates PasskeyEntryResponderDisplays (Table 2.8: the
    /// responder is the only side with a display). The initiator
    /// parks for the passkey, the mgmt sink gets
    /// USER_PASSKEY_REQUEST, the USER_PASSKEY_REPLY (123456)
    /// resumes the rounds, and the exchange completes to an
    /// authenticated bond.
    fn smoke_mgmt_pair_device_passkey_input_full_exchange() -> TestResult {
        reset_all();
        crate::mgmt::__test_reset();
        MGMT_CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(mgmt_capture_sink);
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = move |msg: &'static str| -> TestResult {
            test_entropy::clear();
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            crate::mgmt::__test_reset();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = mgmt_pair_bring_up(&fake) {
            return fail(m);
        }
        if let Err(m) = mgmt_pair_start(smp::IoCapability::KeyboardOnly as u8) {
            return fail(m);
        }
        // Pairing Request: KeyboardOnly (0x02), bonding|SC|MITM.
        // The public-key step answers with NO Confirm — the
        // initiator parks for the passkey instead of starting
        // the rounds.
        let _ = pump_once(0);
        let frames = fake.sent_acl_frames();
        let req = frames
            .iter()
            .find(|(h, f)| *h == SMP888_HANDLE && f.cid == CID_SMP)
            .map(|(_, f)| f.payload.clone());
        if req != Some(alloc::vec![0x01, 0x02, 0x00, 0x0D, 16, 0x06, 0x06]) {
            return fail("mgmt-initiated Pairing Request bytes wrong");
        }
        let rsp = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_RESPONSE,
                &[0x00, 0x00, 0x0D, 16, 0x06, 0x06],
            )],
            SMP888_HANDLE,
        );
        if rsp.len() != 1 || rsp[0].len() != 65 || rsp[0][0] != smp::SMP_PAIRING_PUBLIC_KEY {
            return fail("initiator did not answer Response with a public key");
        }
        let mut pump_pk_x = [0u8; 32];
        let mut pump_pk_y = [0u8; 32];
        pump_pk_x.copy_from_slice(&rsp[0][1..33]);
        pump_pk_y.copy_from_slice(&rsp[0][33..65]);
        if pump_pk_x == [0u8; 32] {
            return fail("initiator public key is zero (entropy seam not live)");
        }
        let peer_dh = peer_dhkey_wire(SMP888_PEER_PRIV, &pump_pk_x, &pump_pk_y);
        let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
        let peer_pk_x = fe_to_wire(&peer_px);
        let peer_pk_y = fe_to_wire(&peer_py);
        let mut peer_pk_payload = Vec::with_capacity(64);
        peer_pk_payload.extend_from_slice(&peer_pk_x);
        peer_pk_payload.extend_from_slice(&peer_pk_y);
        let parked = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_PUBLIC_KEY,
                &peer_pk_payload,
            )],
            SMP888_HANDLE,
        );
        if !parked.is_empty() {
            return fail("initiator started the rounds before the passkey was supplied");
        }
        let asked = MGMT_CAPTURED.lock().iter().any(|e| {
            e.len() >= 13
                && u16::from_le_bytes([e[0], e[1]]) == MGMT_EV_USER_PASSKEY_REQUEST
                && e[6..12] == SMP888_PEER6[..]
                && e[12] == 0x01
        });
        if !asked {
            return fail("no USER_PASSKEY_REQUEST event on the mgmt sink");
        }
        // Answer via mgmt: USER_PASSKEY_REPLY 123456 — the
        // responder displays that value, the initiator types it.
        let mut passkey_params = [0u8; 11];
        passkey_params[..6].copy_from_slice(&SMP888_PEER6);
        passkey_params[6] = 0x01;
        passkey_params[7..11].copy_from_slice(&123456u32.to_le_bytes());
        let reply =
            crate::mgmt::handle(&mgmt_frame(MGMT_OP_USER_PASSKEY_REPLY, 0, &passkey_params));
        if reply.len() != 1
            || u16::from_le_bytes([reply[0][0], reply[0][1]]) != MGMT_EV_CMD_COMPLETE
            || u16::from_le_bytes([reply[0][6], reply[0][7]]) != MGMT_OP_USER_PASSKEY_REPLY
            || reply[0][8] != 0
            || reply[0][9..15] != SMP888_PEER6[..]
            || reply[0][15] != 0x01
        {
            return fail("USER_PASSKEY_REPLY did not complete SUCCESS");
        }
        // The reply releases round 0's Confirm.
        let first = smp888_step_acls(&fake, &[], SMP888_HANDLE);
        if first.len() != 1 || first[0].len() != 17 || first[0][0] != smp::SMP_PAIRING_CONFIRM {
            return fail("initiator did not start the passkey rounds after the reply");
        }
        let mut cai0 = [0u8; 16];
        cai0.copy_from_slice(&first[0][1..17]);
        let keys = MgmtPairKeys {
            pump_pk_x,
            pump_pk_y,
            peer_pk_x,
            peer_pk_y,
            peer_dh,
            ca: cai0,
        };
        let (na20, nb20, ea) = match mgmt_pair_passkey_rounds(&fake, &sbox, &keys, 123456, cai0) {
            Ok(r) => r,
            Err(m) => return fail(m),
        };
        let r128 = smp::passkey_as_128(123456);
        let mac_key = peer_f5_mac_key(
            &sbox,
            &keys.peer_dh,
            &na20,
            &nb20,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &keys.peer_dh,
            &na20,
            &nb20,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let iocap_a: [u8; 3] = [0x0D, 0x00, smp::IoCapability::KeyboardOnly as u8];
        let want_ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &na20,
                n2: &nb20,
                r: &r128,
                iocap: &iocap_a,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if ea != want_ea {
            return fail("Ea mismatch: production f6 disagrees with the peer model");
        }
        let iocap_b: [u8; 3] = [0x0D, 0x00, smp::IoCapability::DisplayOnly as u8];
        let eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &nb20,
                n2: &na20,
                r: &r128,
                iocap: &iocap_b,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &eb)],
            SMP888_HANDLE,
        );
        if !eb_out.is_empty() {
            return fail("initiator sent SMP PDUs at AuthComplete (must wait for encryption)");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        if let Err(m) = mgmt_pair_finish_distribution(&fake, &want_ltk) {
            return fail(m);
        }
        if bond_authenticated(0, &SMP888_PEER_ADDR) != Some(true) {
            return fail("bond is not authenticated after Passkey Entry");
        }
        test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        crate::mgmt::__test_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_mgmt_pair_device_passkey_input_full_exchange
    );

    /// #818: Out of Band, one direction. ADD_REMOTE_OOB_DATA
    /// holds the peer's P-256 hash + randomizer; PAIR_DEVICE
    /// with NoInputNoOutput negotiates OOB (Table 2.7: OOB when
    /// one OR both sides have OOB data — the peer's response
    /// carries flag 0, we carry flag 1). The peer's confirm is
    /// its OOB hash itself; stage 2 uses the OOB randoms as the
    /// f6 R values. Ends in an authenticated bond.
    fn smoke_mgmt_pair_device_oob_full_exchange() -> TestResult {
        reset_all();
        crate::mgmt::__test_reset();
        MGMT_CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(mgmt_capture_sink);
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = move |msg: &'static str| -> TestResult {
            test_entropy::clear();
            if let Some(prev) = previous {
                narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
            }
            reset_all();
            crate::mgmt::__test_reset();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = mgmt_pair_bring_up(&fake) {
            return fail(m);
        }
        // The peer's OOB data: rb is the randomizer, the hash is
        // f4(PKbx, PKbx, rb, 0) over the peer's known keypair.
        let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
        let peer_pk_x = fe_to_wire(&peer_px);
        let rb: [u8; 16] = [0xCC; 16];
        let hash = peer_f4(&sbox, &peer_pk_x, &peer_pk_x, &rb, 0);
        let mut oob_params = [0u8; 71];
        oob_params[..6].copy_from_slice(&SMP888_PEER6);
        oob_params[6] = 0x01; // LE public
                              // P-192 fields stay zero for LE.
        oob_params[39..55].copy_from_slice(&hash);
        oob_params[55..71].copy_from_slice(&rb);
        let added = crate::mgmt::handle(&mgmt_frame(MGMT_OP_ADD_REMOTE_OOB_DATA, 0, &oob_params));
        if added.len() != 1
            || u16::from_le_bytes([added[0][0], added[0][1]]) != MGMT_EV_CMD_COMPLETE
            || u16::from_le_bytes([added[0][6], added[0][7]]) != MGMT_OP_ADD_REMOTE_OOB_DATA
            || added[0][8] != 0
        {
            return fail("ADD_REMOTE_OOB_DATA did not complete SUCCESS");
        }
        if let Err(m) = mgmt_pair_start(smp::IoCapability::NoInputNoOutput as u8) {
            return fail(m);
        }
        // Pairing Request: NoInputNoOutput, OOB flag SET (we
        // hold the peer's OOB data), bonding|SC.
        let keys = match mgmt_pair_to_public_key(
            &fake,
            &[0x01, 0x03, 0x01, 0x09, 16, 0x06, 0x06],
            &[0x03, 0x00, 0x09, 16, 0x06, 0x06],
        ) {
            Ok(keys) => keys,
            Err(m) => return fail(m),
        };
        // The initiator's Ca commits its own key to r=0
        // (§2.3.5.6.4 rule 3: the peer holds no OOB data for us,
        // so our r is zero).
        let want_ca = peer_f4(&sbox, &keys.pump_pk_x, &keys.pump_pk_x, &[0u8; 16], 0);
        if keys.ca != want_ca {
            return fail("OOB Ca mismatch: production f4 disagrees with the peer model");
        }
        // Peer commits Cb — which IS the OOB hash — and reveals
        // Nb = rb.
        let cb = hash;
        let na_ea = smp888_step_acls(
            &fake,
            &[
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &cb),
                smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &rb),
            ],
            SMP888_HANDLE,
        );
        if na_ea.len() != 2
            || na_ea[0].len() != 17
            || na_ea[0][0] != smp::SMP_PAIRING_RANDOM
            || na_ea[1].len() != 17
            || na_ea[1][0] != smp::SMP_PAIRING_DHKEY_CHECK
        {
            return fail("initiator did not answer OOB Random with [Random, DHKey Check]");
        }
        // The initiator's Random is its r = 0.
        if na_ea[0][1..17] != [0u8; 16] {
            return fail("OOB initiator Random is not its zero r");
        }
        // Stage 2 with the OOB randoms as f6 R: ours is 0, the
        // peer's is rb (§2.2.8 table 2.2).
        let zero16 = [0u8; 16];
        let mac_key = peer_f5_mac_key(
            &sbox,
            &keys.peer_dh,
            &zero16,
            &rb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &keys.peer_dh,
            &zero16,
            &rb,
            &SMP888_LOCAL_ADDR,
            &SMP888_PEER_ADDR,
        );
        let iocap_a: [u8; 3] = [0x09, 0x01, smp::IoCapability::NoInputNoOutput as u8];
        let want_ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &zero16,
                n2: &rb,
                r: &rb,
                iocap: &iocap_a,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if na_ea[1][1..17] != want_ea[..] {
            return fail("OOB Ea mismatch: production f6 disagrees with the peer model");
        }
        let iocap_b: [u8; 3] = [0x09, 0x00, smp::IoCapability::NoInputNoOutput as u8];
        let eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &rb,
                n2: &zero16,
                r: &[0u8; 16],
                iocap: &iocap_b,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &eb)],
            SMP888_HANDLE,
        );
        if !eb_out.is_empty() {
            return fail("initiator sent SMP PDUs at AuthComplete (must wait for encryption)");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        if let Err(m) = mgmt_pair_finish_distribution(&fake, &want_ltk) {
            return fail(m);
        }
        if bond_authenticated(0, &SMP888_PEER_ADDR) != Some(true) {
            return fail("bond is not authenticated after Out of Band pairing");
        }
        test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        reset_all();
        crate::mgmt::__test_reset();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_mgmt_pair_device_oob_full_exchange);

    /// #818: sealed bond storage round-trips. A store seals to
    /// `nonce ‖ ciphertext ‖ tag`, unseals back to the same
    /// bonds, and refuses a tampered tag, a wrong key, a wrong
    /// AAD, a truncation, and a malformed image — a bad image
    /// never yields a partial store.
    fn smoke_bond_store_seal_reload_round_trip() -> TestResult {
        let mut store = BondStore::new();
        store.store(Bond {
            peer_addr: [0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
            ltk: [0x11; 16],
            ediv: 0x1234,
            rand: [0x22; 8],
            authenticated: true,
            peer_irk: Some([0x33; 16]),
            peer_identity_addr: Some([0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5]),
            peer_csrk: Some([0x44; 16]),
        });
        store.store(Bond {
            peer_addr: [0x01, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5],
            ltk: [0x55; 16],
            ediv: 0,
            rand: [0; 8],
            authenticated: false,
            peer_irk: None,
            peer_identity_addr: None,
            peer_csrk: None,
        });
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let aad = b"narf-bond-v1:test";
        let blob = store.seal(&key, &nonce, aad);
        if blob.len() < 12 + 16 || blob[..12] != nonce[..] {
            return TestResult::Fail("sealed blob is not nonce || ciphertext || tag");
        }
        let back = match BondStore::unseal(&key, aad, &blob) {
            Some(store) => store,
            None => return TestResult::Fail("sealed store did not unseal"),
        };
        if back.len() != 2 {
            return TestResult::Fail("unsealed store lost bonds");
        }
        let first = match back.lookup(&[0x00, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5]) {
            Some(bond) => bond,
            None => return TestResult::Fail("unsealed store lost the first bond"),
        };
        if first.ltk != [0x11; 16]
            || first.ediv != 0x1234
            || first.rand != [0x22; 8]
            || !first.authenticated
            || first.peer_irk != Some([0x33; 16])
            || first.peer_csrk != Some([0x44; 16])
        {
            return TestResult::Fail("unsealed bond fields drifted");
        }
        if back
            .lookup(&[0x01, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5])
            .map(|b| b.authenticated)
            != Some(false)
        {
            return TestResult::Fail("unsealed second bond drifted");
        }
        // Tampered tag.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        if BondStore::unseal(&key, aad, &bad).is_some() {
            return TestResult::Fail("tampered sealed image unsealed");
        }
        // Wrong key, wrong AAD, truncated blob.
        if BondStore::unseal(&[0x43u8; 32], aad, &blob).is_some() {
            return TestResult::Fail("sealed image unsealed under the wrong key");
        }
        if BondStore::unseal(&key, b"narf-bond-v1:other", &blob).is_some() {
            return TestResult::Fail("sealed image unsealed under the wrong AAD");
        }
        if BondStore::unseal(&key, aad, &blob[..blob.len() - 1]).is_some() {
            return TestResult::Fail("truncated sealed image unsealed");
        }
        // Malformed images: bad magic, unknown version, trailing
        // bytes, count mismatch.
        let image = store.encode();
        let mut bad_magic = image.clone();
        bad_magic[0] ^= 1;
        if BondStore::decode(&bad_magic).is_some() {
            return TestResult::Fail("bad-magic image decoded");
        }
        let mut bad_version = image.clone();
        bad_version[8] = 99;
        if BondStore::decode(&bad_version).is_some() {
            return TestResult::Fail("unknown-version image decoded");
        }
        let mut trailing = image.clone();
        trailing.push(0);
        if BondStore::decode(&trailing).is_some() {
            return TestResult::Fail("trailing-bytes image decoded");
        }
        if BondStore::decode(&image[..image.len() - 1]).is_some() {
            return TestResult::Fail("truncated image decoded");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_bond_store_seal_reload_round_trip);
    /// #1528: the pump cancel API. Cancelling an in-flight
    /// initiator or responder session clears it (a fresh pairing
    /// can start on the same connection) and sends the peer a
    /// Pairing Failed PDU, Unspecified Reason (Vol 3 Part H
    /// §3.5.5: code 0x05, reason 0x08 — the bytes are pinned
    /// here from the spec, not from the encoder under test).
    /// Cancelling with no session, or no connection, is a clean
    /// error, not a silent no-op.
    fn smoke_pump_smp_cancel_pairing() -> TestResult {
        reset_all();
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = |msg: &'static str| -> TestResult {
            test_entropy::clear();
            reset_all();
            TestResult::Fail(msg)
        };
        // No pump at all → None, not an error.
        if smp_cancel_pairing(0, SMP888_HANDLE).is_some() {
            return fail("cancel with no pump was not None");
        }
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = smp888_bring_up_connect(&fake) {
            return fail(m);
        }
        if smp_cancel_pairing(0, 0x1234) != Some(Err(SmpCancelError::UnknownHandle)) {
            return fail("cancel on an unknown handle was not UnknownHandle");
        }
        if smp_cancel_pairing(0, SMP888_HANDLE) != Some(Err(SmpCancelError::NotPairing)) {
            return fail("cancel with no session was not NotPairing");
        }
        let failed_sent = |fake: &ScriptedTransport| {
            fake.sent_acl_frames().iter().any(|(h, f)| {
                *h == SMP888_HANDLE
                    && f.cid == CID_SMP
                    && f.payload
                        == alloc::vec![smp::SMP_PAIRING_FAILED, smp::SMP_FAILED_UNSPECIFIED]
            })
        };
        // Initiator: start, cancel, Pairing Failed goes out, and
        // the session is gone (a second cancel is NotPairing, a
        // fresh start works).
        if smp_initiate_pairing(0, SMP888_HANDLE) != Some(Ok(())) {
            return fail("initiator start failed");
        }
        if smp_cancel_pairing(0, SMP888_HANDLE) != Some(Ok(())) {
            return fail("initiator cancel failed");
        }
        let _ = pump_once(0);
        if !failed_sent(&fake) {
            return fail("initiator cancel sent no Pairing Failed (0x05, 0x08)");
        }
        if smp_cancel_pairing(0, SMP888_HANDLE) != Some(Err(SmpCancelError::NotPairing)) {
            return fail("second initiator cancel was not NotPairing");
        }
        if smp_initiate_pairing(0, SMP888_HANDLE) != Some(Ok(())) {
            return fail("pairing did not restart after cancel");
        }
        if smp_cancel_pairing(0, SMP888_HANDLE) != Some(Ok(())) {
            return fail("second initiator cancel failed");
        }
        let _ = pump_once(0);
        // Responder: a peer Pairing Request opens the session;
        // cancelling it also sends Pairing Failed and clears it.
        let rsp = smp888_step_acls(
            &fake,
            &[smp888_request_acl(SMP888_HANDLE, 0x06, 0x06)],
            SMP888_HANDLE,
        );
        if rsp.len() != 1 || rsp[0][0] != smp::SMP_PAIRING_RESPONSE {
            return fail("peer Pairing Request did not open a responder session");
        }
        if smp_cancel_pairing(0, SMP888_HANDLE) != Some(Ok(())) {
            return fail("responder cancel failed");
        }
        let _ = pump_once(0);
        if !failed_sent(&fake) {
            return fail("responder cancel sent no Pairing Failed (0x05, 0x08)");
        }
        if smp_cancel_pairing(0, SMP888_HANDLE) != Some(Err(SmpCancelError::NotPairing)) {
            return fail("second responder cancel was not NotPairing");
        }
        test_entropy::clear();
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_smp_cancel_pairing);

    /// #888: responder pairing with distribution. The LTK Request
    /// that arrives while the session is AuthComplete is answered
    /// from the session (before any bond exists); after encryption
    /// the responder distributes first, the peer's keys complete
    /// the bond, and the bond survives disconnect and answers a
    /// fresh connection's re-encryption.
    fn smoke_pump_smp_responder_distribution_and_reencrypt() -> TestResult {
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = smp888_bring_up_connect(&fake) {
            return fail(m);
        }
        // Peer requests pairing with IdKey|Sign both directions.
        let rsp = smp888_step_acls(
            &fake,
            &[smp888_request_acl(SMP888_HANDLE, 0x06, 0x06)],
            SMP888_HANDLE,
        );
        // Byte-exact Pairing Response: DisplayYesNo, bonding|SC|
        // MITM, IdKey|Sign both directions.
        if rsp.len() != 1 || rsp[0] != alloc::vec![0x02, 0x01, 0x00, 0x0D, 16, 0x06, 0x06] {
            return fail("responder Pairing Response bytes wrong");
        }
        let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
        let peer_pk_x = fe_to_wire(&peer_px);
        let peer_pk_y = fe_to_wire(&peer_py);
        let mut peer_pk_payload = Vec::with_capacity(64);
        peer_pk_payload.extend_from_slice(&peer_pk_x);
        peer_pk_payload.extend_from_slice(&peer_pk_y);
        let pk_out = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_PAIRING_PUBLIC_KEY,
                &peer_pk_payload,
            )],
            SMP888_HANDLE,
        );
        if pk_out.len() != 1 || pk_out[0].len() != 65 || pk_out[0][0] != smp::SMP_PAIRING_PUBLIC_KEY
        {
            return fail("responder did not answer public key with its public key");
        }
        let mut pump_pk_x = [0u8; 32];
        let mut pump_pk_y = [0u8; 32];
        pump_pk_x.copy_from_slice(&pk_out[0][1..33]);
        pump_pk_y.copy_from_slice(&pk_out[0][33..65]);
        let peer_dh = peer_dhkey_wire(SMP888_PEER_PRIV, &pump_pk_x, &pump_pk_y);
        // Peer commits Ca and the pump answers [Cb, Nb].
        let na: [u8; 16] = [0xAA; 16];
        let ca = peer_f4(&sbox, &peer_pk_x, &pump_pk_x, &na, 0);
        let cb_nb = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &ca)],
            SMP888_HANDLE,
        );
        if cb_nb.len() != 2
            || cb_nb[0].len() != 17
            || cb_nb[0][0] != smp::SMP_PAIRING_CONFIRM
            || cb_nb[1].len() != 17
            || cb_nb[1][0] != smp::SMP_PAIRING_RANDOM
        {
            return fail("responder did not answer Confirm with [Confirm, Random]");
        }
        let mut nb = [0u8; 16];
        nb.copy_from_slice(&cb_nb[1][1..17]);
        let want_cb = peer_f4(&sbox, &pump_pk_x, &peer_pk_x, &nb, 0);
        if cb_nb[0][1..17] != want_cb[..] {
            return fail("Cb mismatch: production f4 disagrees with the peer model");
        }
        // Peer reveals Na; the responder emits nothing yet.
        let none = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &na)],
            SMP888_HANDLE,
        );
        if !none.is_empty() {
            return fail("responder emitted PDUs on the Na step");
        }
        let mac_key = peer_f5_mac_key(
            &sbox,
            &peer_dh,
            &na,
            &nb,
            &SMP888_PEER_ADDR,
            &SMP888_LOCAL_ADDR,
        );
        let want_ltk = peer_f5_ltk(
            &sbox,
            &peer_dh,
            &na,
            &nb,
            &SMP888_PEER_ADDR,
            &SMP888_LOCAL_ADDR,
        );
        let iocap_a: [u8; 3] = [
            smp::AUTH_BONDING | smp::AUTH_SC,
            0x00,
            smp::IoCapability::NoInputNoOutput as u8,
        ];
        let ea = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &na,
                n2: &nb,
                r: &[0u8; 16],
                iocap: &iocap_a,
                a1: &SMP888_PEER_ADDR,
                a2: &SMP888_LOCAL_ADDR,
            },
        );
        let eb_out = smp888_step_acls(
            &fake,
            &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &ea)],
            SMP888_HANDLE,
        );
        if eb_out.len() != 1
            || eb_out[0].len() != 17
            || eb_out[0][0] != smp::SMP_PAIRING_DHKEY_CHECK
        {
            return fail("responder did not answer DHKey Check with Eb");
        }
        let iocap_b: [u8; 3] = [0x0D, 0x00, 0x01];
        let want_eb = peer_f6(
            &sbox,
            &mac_key,
            &F6Inputs {
                n1: &nb,
                n2: &na,
                r: &[0u8; 16],
                iocap: &iocap_b,
                a1: &SMP888_LOCAL_ADDR,
                a2: &SMP888_PEER_ADDR,
            },
        );
        if eb_out[0][1..17] != want_eb[..] {
            return fail("Eb mismatch: production f6 disagrees with the peer model");
        }
        // AuthComplete: no bond yet, but the session answers the
        // peer's LTK Request with the just-derived LTK.
        if bond_count(0) != Some(0) {
            return fail("bond stored before distribution (must wait for Phase 3)");
        }
        let cmds_before = fake.sent_commands().len();
        let _ = smp888_step_event(
            &fake,
            smp888_ltk_request_event(SMP888_HANDLE, 0, 0),
            SMP888_HANDLE,
        );
        let new_cmds = &fake.sent_commands()[cmds_before..];
        let reply = new_cmds
            .iter()
            .find(|c| c.opcode == op::HCI_LE_LTK_REQUEST_REPLY);
        let mut want_reply = Vec::with_capacity(18);
        want_reply.extend_from_slice(&SMP888_HANDLE.to_le_bytes());
        want_reply.extend_from_slice(&want_ltk);
        match reply {
            Some(cmd) if cmd.params == want_reply => {}
            _ => return fail("AuthComplete session did not answer LTK Request with the f5 LTK"),
        }
        // Encryption reported: the responder (Peripheral)
        // distributes first.
        smp888_replenish(&fake, SMP888_HANDLE);
        let dist = smp888_step_event(
            &fake,
            smp888_encryption_change_event(SMP888_HANDLE, 0, 1),
            SMP888_HANDLE,
        );
        if dist.len() != 3
            || dist[0].len() != 17
            || dist[0][0] != smp::SMP_IDENTITY_INFORMATION
            || dist[0][1..17] == [0u8; 16]
            || dist[1].len() != 8
            || dist[1][0] != smp::SMP_IDENTITY_ADDRESS_INFORMATION
            || dist[1][1..8] != SMP888_LOCAL_ADDR
            || dist[2].len() != 17
            || dist[2][0] != smp::SMP_SIGNING_INFORMATION
            || dist[2][1..17] == [0u8; 16]
        {
            return fail("responder distribution PDUs wrong (order/length/address/randomness)");
        }
        // Peer distributes; the responder completes and stores.
        let irk_pin: [u8; 16] = [0xC0; 16];
        let csrk_pin: [u8; 16] = [0xD0; 16];
        let done = smp888_step_acls(
            &fake,
            &[
                smp888_acl(SMP888_HANDLE, smp::SMP_IDENTITY_INFORMATION, &irk_pin),
                smp888_acl(
                    SMP888_HANDLE,
                    smp::SMP_IDENTITY_ADDRESS_INFORMATION,
                    &SMP888_PEER_ADDR,
                ),
                smp888_acl(SMP888_HANDLE, smp::SMP_SIGNING_INFORMATION, &csrk_pin),
            ],
            SMP888_HANDLE,
        );
        if !done.is_empty() {
            return fail("responder sent PDUs after distribution completed");
        }
        if bond_count(0) != Some(1) {
            return fail("bond not stored after responder distribution completed");
        }
        // Mismatched diversifier must not match the SC bond.
        let cmds_before = fake.sent_commands().len();
        let _ = smp888_step_event(
            &fake,
            smp888_ltk_request_event(SMP888_HANDLE, 0, 0x1234),
            SMP888_HANDLE,
        );
        let new_cmds = &fake.sent_commands()[cmds_before..];
        if !new_cmds
            .iter()
            .any(|c| c.opcode == op::HCI_LE_LTK_REQUEST_NEGATIVE_REPLY)
        {
            return fail("mismatched EDIV answered with an LTK");
        }
        // Disconnect: the bond survives. Reconnect on a fresh
        // handle and re-encrypt from the store.
        fake.enqueue_event(Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, 0x40, 0x00, 0x13],
        });
        let _ = pump_once(0);
        if connection_count(0) != Some(0) || bond_count(0) != Some(1) {
            return fail("bond did not survive disconnect");
        }
        let handle2: u16 = 0x0041;
        fake.enqueue_event(le_connection_complete(handle2, SMP888_PEER6));
        let _ = pump_once(0);
        if smp_start_encryption(0, handle2) != Some(Ok(())) {
            return fail("re-encrypt from stored bond failed");
        }
        let cmds = fake.sent_commands();
        let start_enc = cmds
            .iter()
            .rev()
            .find(|c| c.opcode == op::HCI_LE_START_ENCRYPTION);
        let mut want_start_enc = Vec::with_capacity(26);
        want_start_enc.extend_from_slice(&handle2.to_le_bytes());
        want_start_enc.extend_from_slice(&[0u8; 8]);
        want_start_enc.extend_from_slice(&0u16.to_le_bytes());
        want_start_enc.extend_from_slice(&want_ltk);
        match start_enc {
            Some(cmd) if cmd.params == want_start_enc => {}
            _ => return fail("re-encrypt did not issue Start Encryption with the stored LTK"),
        }
        // Unknown handle / unknown peer guards.
        if smp_start_encryption(0, 0x0001) != Some(Err(SmpEncryptError::UnknownHandle)) {
            return fail("re-encrypt on unknown handle did not fail UnknownHandle");
        }
        let handle3: u16 = 0x0042;
        fake.enqueue_event(le_connection_complete(
            handle3,
            [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5],
        ));
        let _ = pump_once(0);
        if smp_start_encryption(0, handle3) != Some(Err(SmpEncryptError::NoBond)) {
            return fail("re-encrypt for unbonded peer did not fail NoBond");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_responder_distribution_and_reencrypt
    );

    /// #888: a peer Security Request starts an initiator pairing
    /// (Part H §3.6.7), and the live session refuses a second
    /// application trigger.
    fn smoke_pump_smp_security_request_starts_initiator() -> TestResult {
        reset_all();
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = smp888_bring_up_connect(&fake) {
            return fail(m);
        }
        let out = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_SECURITY_REQUEST,
                &[0x09],
            )],
            SMP888_HANDLE,
        );
        if out.len() != 1
            || out[0]
                != alloc::vec![
                    0x01,
                    smp::IoCapability::NoInputNoOutput as u8,
                    0x00,
                    0x09,
                    16,
                    0x06,
                    0x06
                ]
        {
            return fail("Security Request did not produce the initiator Pairing Request");
        }
        if smp_initiate_pairing(0, SMP888_HANDLE) != Some(Err(SmpInitiateError::AlreadyPairing)) {
            return fail("initiate during Security-Request session did not fail AlreadyPairing");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_smp_security_request_starts_initiator
    );

    /// #888, state-machine level: production Initiator against
    /// production Responder with distribution negotiated both
    /// ways. The responder distributes first; each side's stored
    /// peer keys must equal the exact PDU bytes the other side
    /// emitted (captured bytes, not self-agreement); both sides
    /// reach Done bonded with identical LTKs.
    fn smoke_smp_distribution_initiator_responder_exchange() -> TestResult {
        reset_all();
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            TestResult::Fail(msg)
        };
        let mut initiator = Initiator::new(NarfSmpCrypto, SMP_IAT, SMP_RAT);
        let mut responder = Responder::new(NarfSmpCrypto, SMP_IAT, SMP_RAT);
        let req = initiator.start();
        let out = match responder.feed(&req) {
            Ok(out) => out,
            Err(_) => return fail("responder rejected the pairing request"),
        };
        if out.len() != 1 || out[0].code != smp::SMP_PAIRING_RESPONSE {
            return fail("responder did not answer with Pairing Response");
        }
        let out = match initiator.feed(&out[0]) {
            Ok(out) => out,
            Err(_) => return fail("initiator rejected the pairing response"),
        };
        if out.len() != 1 || out[0].code != smp::SMP_PAIRING_PUBLIC_KEY {
            return fail("initiator did not answer with its public key");
        }
        let out = match responder.feed(&out[0]) {
            Ok(out) => out,
            Err(_) => return fail("responder rejected the initiator public key"),
        };
        if out.len() != 1 || out[0].code != smp::SMP_PAIRING_PUBLIC_KEY {
            return fail("responder did not answer with its public key");
        }
        let out = match initiator.feed(&out[0]) {
            Ok(out) => out,
            Err(_) => return fail("initiator rejected the responder public key"),
        };
        if out.len() != 1 || out[0].code != smp::SMP_PAIRING_CONFIRM {
            return fail("initiator did not answer with Confirm");
        }
        let cb_nb = match responder.feed(&out[0]) {
            Ok(out) => out,
            Err(_) => return fail("responder rejected the initiator confirm"),
        };
        if cb_nb.len() != 2
            || cb_nb[0].code != smp::SMP_PAIRING_CONFIRM
            || cb_nb[1].code != smp::SMP_PAIRING_RANDOM
        {
            return fail("responder did not answer Confirm with [Confirm, Random]");
        }
        let out = match initiator.feed(&cb_nb[0]) {
            Ok(out) => out,
            Err(_) => return fail("initiator rejected the responder confirm"),
        };
        if !out.is_empty() {
            return fail("initiator emitted PDUs on the confirm step");
        }
        let na_ea = match initiator.feed(&cb_nb[1]) {
            Ok(out) => out,
            Err(_) => return fail("initiator rejected the responder random"),
        };
        if na_ea.len() != 2
            || na_ea[0].code != smp::SMP_PAIRING_RANDOM
            || na_ea[1].code != smp::SMP_PAIRING_DHKEY_CHECK
        {
            return fail("initiator did not answer Random with [Random, DHKey Check]");
        }
        let out = match responder.feed(&na_ea[0]) {
            Ok(out) => out,
            Err(_) => return fail("responder rejected the initiator random"),
        };
        if !out.is_empty() {
            return fail("responder emitted PDUs on the random step");
        }
        let eb = match responder.feed(&na_ea[1]) {
            Ok(out) => out,
            Err(_) => return fail("responder rejected the initiator DHKey Check"),
        };
        if eb.len() != 1 || eb[0].code != smp::SMP_PAIRING_DHKEY_CHECK {
            return fail("responder did not answer with Eb");
        }
        let out = match initiator.feed(&eb[0]) {
            Ok(out) => out,
            Err(_) => return fail("initiator rejected Eb"),
        };
        if !out.is_empty() {
            return fail("initiator emitted PDUs on the Eb step");
        }
        if initiator.state != smp::PairingState::AuthComplete
            || responder.state != smp::ResponderState::AuthComplete
        {
            return fail("both sides did not park at AuthComplete with distribution pending");
        }
        // Responder distributes first.
        let r_dist = responder.begin_distribution();
        if r_dist.len() != 3
            || r_dist[0].code != smp::SMP_IDENTITY_INFORMATION
            || r_dist[0].payload.len() != 16
            || r_dist[1].code != smp::SMP_IDENTITY_ADDRESS_INFORMATION
            || r_dist[1].payload.len() != 7
            || r_dist[2].code != smp::SMP_SIGNING_INFORMATION
            || r_dist[2].payload.len() != 16
        {
            return fail("responder distribution PDUs wrong");
        }
        if responder.state != smp::ResponderState::WaitDistribution {
            return fail("responder did not park in WaitDistribution");
        }
        // Initiator waits while expecting responder keys.
        if !initiator.begin_distribution().is_empty()
            || initiator.state != smp::PairingState::WaitDistribution
        {
            return fail("initiator did not wait for responder keys");
        }
        let mut i_out = Vec::new();
        for pdu in &r_dist {
            match initiator.feed(pdu) {
                Ok(out) => i_out = out,
                Err(_) => return fail("initiator rejected a responder distribution PDU"),
            }
        }
        if initiator.state != smp::PairingState::Done || i_out.len() != 3 {
            return fail("initiator did not complete with its own distribution PDUs");
        }
        // Captured-byte checks: stored peer keys equal the PDUs
        // the responder actually emitted.
        if initiator.peer_irk
            != Some({
                let mut b = [0u8; 16];
                b.copy_from_slice(&r_dist[0].payload);
                b
            })
            || initiator.peer_identity_addr
                != Some({
                    let mut b = [0u8; 7];
                    b.copy_from_slice(&r_dist[1].payload);
                    b
                })
            || initiator.peer_csrk
                != Some({
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&r_dist[2].payload);
                    b
                })
        {
            return fail("initiator stored peer keys differ from the emitted PDUs");
        }
        // Responder consumes the initiator's PDUs the same way.
        for pdu in &i_out {
            match responder.feed(pdu) {
                Ok(out) => {
                    if !out.is_empty() {
                        return fail("responder emitted PDUs on distribution intake");
                    }
                }
                Err(_) => return fail("responder rejected an initiator distribution PDU"),
            }
        }
        if responder.state != smp::ResponderState::Done {
            return fail("responder did not complete after initiator distribution");
        }
        if responder.peer_irk
            != Some({
                let mut b = [0u8; 16];
                b.copy_from_slice(&i_out[0].payload);
                b
            })
            || responder.peer_identity_addr
                != Some({
                    let mut b = [0u8; 7];
                    b.copy_from_slice(&i_out[1].payload);
                    b
                })
            || responder.peer_csrk
                != Some({
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&i_out[2].payload);
                    b
                })
        {
            return fail("responder stored peer keys differ from the emitted PDUs");
        }
        if !initiator.bonded || !responder.bonded || initiator.ltk != responder.ltk {
            return fail("bonded LTKs disagree between the two sides");
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_smp_distribution_initiator_responder_exchange
    );

    /// #888: distribution before encryption fails the pairing, and
    /// a failed encryption clears an AuthComplete session — both
    /// proven by a fresh Pairing Request starting a new pairing
    /// afterwards (a live session would answer Protocol instead).
    fn smoke_pump_smp_authcomplete_failure_paths() -> TestResult {
        // Abbreviated responder drive to AuthComplete: only step
        // shapes are asserted here; the full byte-verified
        // exchange is the previous fixture's job. Split so a
        // fresh request can double as the "session cleared" proof
        // and the rest of the drive continues from it.
        fn drive_request(fake: &ScriptedTransport) -> Result<(), &'static str> {
            smp888_replenish(fake, SMP888_HANDLE);
            let rsp = smp888_step_acls(
                fake,
                &[smp888_request_acl(SMP888_HANDLE, 0x06, 0x06)],
                SMP888_HANDLE,
            );
            if rsp.len() != 1 || rsp[0][0] != smp::SMP_PAIRING_RESPONSE {
                return Err("responder did not answer Pairing Request");
            }
            Ok(())
        }
        fn drive_rest(fake: &ScriptedTransport, sbox: &[u8; 256]) -> Result<(), &'static str> {
            smp888_replenish(fake, SMP888_HANDLE);
            let (peer_px, peer_py) = peer_public(SMP888_PEER_PRIV);
            let peer_pk_x = fe_to_wire(&peer_px);
            let peer_pk_y = fe_to_wire(&peer_py);
            let mut peer_pk_payload = Vec::with_capacity(64);
            peer_pk_payload.extend_from_slice(&peer_pk_x);
            peer_pk_payload.extend_from_slice(&peer_pk_y);
            let pk_out = smp888_step_acls(
                fake,
                &[smp888_acl(
                    SMP888_HANDLE,
                    smp::SMP_PAIRING_PUBLIC_KEY,
                    &peer_pk_payload,
                )],
                SMP888_HANDLE,
            );
            if pk_out.len() != 1 || pk_out[0].len() != 65 {
                return Err("responder public key step wrong");
            }
            let mut pump_pk_x = [0u8; 32];
            let mut pump_pk_y = [0u8; 32];
            pump_pk_x.copy_from_slice(&pk_out[0][1..33]);
            pump_pk_y.copy_from_slice(&pk_out[0][33..65]);
            let peer_dh = peer_dhkey_wire(SMP888_PEER_PRIV, &pump_pk_x, &pump_pk_y);
            let na: [u8; 16] = [0xAA; 16];
            let ca = peer_f4(sbox, &peer_pk_x, &pump_pk_x, &na, 0);
            let cb_nb = smp888_step_acls(
                fake,
                &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_CONFIRM, &ca)],
                SMP888_HANDLE,
            );
            if cb_nb.len() != 2 {
                return Err("responder Confirm step wrong");
            }
            let mut nb = [0u8; 16];
            nb.copy_from_slice(&cb_nb[1][1..17]);
            let _ = smp888_step_acls(
                fake,
                &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_RANDOM, &na)],
                SMP888_HANDLE,
            );
            let mac_key = peer_f5_mac_key(
                sbox,
                &peer_dh,
                &na,
                &nb,
                &SMP888_PEER_ADDR,
                &SMP888_LOCAL_ADDR,
            );
            let iocap_a: [u8; 3] = [
                smp::AUTH_BONDING | smp::AUTH_SC,
                0x00,
                smp::IoCapability::NoInputNoOutput as u8,
            ];
            let ea = peer_f6(
                sbox,
                &mac_key,
                &F6Inputs {
                    n1: &na,
                    n2: &nb,
                    r: &[0u8; 16],
                    iocap: &iocap_a,
                    a1: &SMP888_PEER_ADDR,
                    a2: &SMP888_LOCAL_ADDR,
                },
            );
            let eb_out = smp888_step_acls(
                fake,
                &[smp888_acl(SMP888_HANDLE, smp::SMP_PAIRING_DHKEY_CHECK, &ea)],
                SMP888_HANDLE,
            );
            if eb_out.len() != 1 || eb_out[0][0] != smp::SMP_PAIRING_DHKEY_CHECK {
                return Err("responder Eb step wrong");
            }
            Ok(())
        }
        reset_all();
        let sbox = build_sbox();
        if let Err(m) = peer_model_self_check(&sbox) {
            return TestResult::Fail(m);
        }
        test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let fail = |msg: &'static str| -> TestResult {
            reset_all();
            TestResult::Fail(msg)
        };
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(m) = smp888_bring_up_connect(&fake) {
            return fail(m);
        }
        if let Err(m) = drive_request(&fake).and_then(|_| drive_rest(&fake, &sbox)) {
            return fail(m);
        }
        // Early distribution PDU: Pairing Failed 0x08.
        let early = smp888_step_acls(
            &fake,
            &[smp888_acl(
                SMP888_HANDLE,
                smp::SMP_IDENTITY_INFORMATION,
                &[0xC0; 16],
            )],
            SMP888_HANDLE,
        );
        if early.len() != 1
            || early[0] != alloc::vec![smp::SMP_PAIRING_FAILED, smp::SMP_FAILED_UNSPECIFIED]
        {
            return fail("early distribution PDU did not fail the pairing with 0x08");
        }
        if bond_count(0) != Some(0) {
            return fail("bond stored after failed pairing");
        }
        // Fresh request starts a new pairing (session cleared),
        // and the rest of the drive reaches AuthComplete again.
        if let Err(m) = drive_request(&fake).and_then(|_| drive_rest(&fake, &sbox)) {
            return fail(m);
        }
        // Failed encryption clears the session silently.
        let cleared = smp888_step_event(
            &fake,
            smp888_encryption_change_event(SMP888_HANDLE, 0x01, 1),
            SMP888_HANDLE,
        );
        if !cleared.is_empty() || bond_count(0) != Some(0) {
            return fail("failed encryption produced PDUs or a bond");
        }
        if let Err(m) = drive_request(&fake) {
            return fail(m);
        }
        reset_all();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_smp_authcomplete_failure_paths);

    /// LE Periodic Advertising Sync Established subevent (§7.7.65.15):
    /// subevent, status, sync handle, SID, address type, address,
    /// PHY, interval, clock accuracy.
    fn le_periodic_adv_sync_established(status: u8, handle: u16, sid: u8, peer: [u8; 6]) -> Event {
        let mut params = alloc::vec![0x0E, status];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(sid);
        params.push(0x00); // advertiser address type: public
        params.extend_from_slice(&peer);
        params.push(0x01); // advertiser PHY: 1M
        params.extend_from_slice(&0x0050u16.to_le_bytes()); // interval 100 ms
        params.push(0x00); // advertiser clock accuracy
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// LE Periodic Advertising Report subevent (§7.7.65.14): subevent,
    /// sync handle, Tx Power, RSSI, CTE type (0xFF = none),
    /// data status, data length, data.
    fn le_periodic_adv_report(
        handle: u16,
        tx_power: i8,
        rssi: i8,
        data_status: u8,
        data: &[u8],
    ) -> Event {
        let mut params = alloc::vec![0x0F];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(tx_power as u8);
        params.push(rssi as u8);
        params.push(0xFF); // CTE type: none
        params.push(data_status);
        params.push(data.len() as u8);
        params.extend_from_slice(data);
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// LE Periodic Advertising Sync Lost subevent (§7.7.65.16):
    /// subevent, sync handle.
    fn le_periodic_adv_sync_lost(handle: u16) -> Event {
        let mut params = alloc::vec![0x10];
        params.extend_from_slice(&handle.to_le_bytes());
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// LE Periodic Advertising Sync Transfer Received subevent [v1]
    /// (§7.7.65.21): subevent, status, connection handle, service
    /// data, sync handle, SID, address type, address, PHY,
    /// interval, clock accuracy.
    fn le_periodic_adv_sync_transfer_received(
        status: u8,
        connection_handle: u16,
        service_data: u16,
        sync_handle: u16,
        sid: u8,
        peer: [u8; 6],
    ) -> Event {
        let mut params = alloc::vec![0x18, status];
        params.extend_from_slice(&connection_handle.to_le_bytes());
        params.extend_from_slice(&service_data.to_le_bytes());
        params.extend_from_slice(&sync_handle.to_le_bytes());
        params.push(sid);
        params.push(0x00); // advertiser address type: public
        params.extend_from_slice(&peer);
        params.push(0x01); // advertiser PHY: 1M
        params.extend_from_slice(&0x0050u16.to_le_bytes()); // interval 100 ms
        params.push(0x00); // advertiser clock accuracy
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// #1560: the full periodic advertising conversation against the
    /// scripted controller — broadcaster parameters / data / enable,
    /// then receiver Create Sync → Sync Established → complete +
    /// fragmented + truncated reports → Sync Lost → disable.
    fn smoke_pump_periodic_adv_sync_flow() -> TestResult {
        use crate::event::{LE_PA_DATA_COMPLETE, LE_PA_DATA_MORE_TO_COME, LE_PA_DATA_TRUNCATED};
        use crate::gap::{
            PeerAddressType, PeriodicAdvDataOperation, PeriodicAdvertisingCreateSync,
            PeriodicAdvertisingParameters,
        };
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        // 1. Broadcaster: Set Parameters, pinned byte-for-byte
        // against §7.8.61 (handle 0x00, 100 ms, Tx Power included).
        let params = PeriodicAdvertisingParameters::for_handle(0x00);
        if periodic_adv_set_parameters(0, params).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_set_parameters rejected");
        }
        let sent = fake.sent_command_params();
        if sent.len() != 6
            || sent[5].0 != op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS
            || sent[5].1 != [0x00, 0x50, 0x00, 0x50, 0x00, 0x01, 0x00]
        {
            reset_all();
            return TestResult::Fail("Set Periodic Adv Parameters bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Configured) {
            reset_all();
            return TestResult::Fail("phase not Configured after parameters complete");
        }
        // 2. Set Data (Complete, Flags 0x06), then Enable.
        if periodic_adv_set_data(
            0,
            0x00,
            PeriodicAdvDataOperation::Complete,
            &[0x02, 0x01, 0x06],
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("periodic_adv_set_data rejected from Configured");
        }
        let sent = fake.sent_command_params();
        if sent.len() != 7
            || sent[6].0 != op::HCI_LE_SET_PERIODIC_ADVERTISING_DATA
            || sent[6].1 != [0x00, 0x03, 0x03, 0x02, 0x01, 0x06]
        {
            reset_all();
            return TestResult::Fail("Set Periodic Adv Data bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_DATA, &[0]));
        let _ = pump_once(0);
        if periodic_adv_set_enable(0, true).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_set_enable rejected from Configured");
        }
        let sent = fake.sent_command_params();
        if sent.len() != 8
            || sent[7].0 != op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE
            || sent[7].1 != [0x01, 0x00]
        {
            reset_all();
            return TestResult::Fail("Set Periodic Adv Enable bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        if periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Enabled) {
            reset_all();
            return TestResult::Fail("phase not Enabled after enable complete");
        }
        // 3. Receiver: Create Sync, pinned byte-for-byte against
        // §7.8.67 (reporting on, SID 0x01, public peer, 10 s
        // timeout, no CTE sync).
        let req = PeriodicAdvertisingCreateSync::to_advertiser(0x01, PeerAddressType::Public, peer);
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_create_sync rejected from Idle");
        }
        let sent = fake.sent_command_params();
        let want_create: [u8; 14] = [
            0x02, 0x01, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x00, 0x00, 0xE8, 0x03, 0xFF,
        ];
        if sent.len() != 9
            || sent[8].0 != op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC
            || sent[8].1 != want_create
        {
            reset_all();
            return TestResult::Fail("Create Sync bytes mismatch");
        }
        if periodic_sync_snapshot(0).map(|s| s.phase)
            != Some(crate::gap::PeriodicSyncPhase::Creating)
        {
            reset_all();
            return TestResult::Fail("phase not Creating after create sync");
        }
        // Command Status (accepted) keeps Creating; Sync Established
        // lands the sync.
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase)
            != Some(crate::gap::PeriodicSyncPhase::Creating)
        {
            reset_all();
            return TestResult::Fail("accepted Command Status moved phase out of Creating");
        }
        fake.enqueue_event(le_periodic_adv_sync_established(0x00, 0x0007, 0x01, peer));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0);
        if snap.as_ref().map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Synced)
            || snap.as_ref().and_then(|s| s.sync_handle) != Some(0x0007)
            || snap.as_ref().map(|s| s.periodic_interval) != Some(0x0050)
        {
            reset_all();
            return TestResult::Fail("Sync Established did not land the sync");
        }
        // 4. Reports: one complete, one fragmented across two
        // subevents, one truncated then re-delivered.
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_COMPLETE,
            &[0x02, 0x01, 0x06],
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.reports_received != 1 || snap.last_report != [0x02, 0x01, 0x06] {
            reset_all();
            return TestResult::Fail("complete report not delivered");
        }
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_MORE_TO_COME,
            &[0x02, 0x01],
        ));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.reports_received) != Some(1) {
            reset_all();
            return TestResult::Fail("partial fragment delivered early");
        }
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_COMPLETE,
            &[0x06],
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.reports_received != 2 || snap.last_report != [0x02, 0x01, 0x06] {
            reset_all();
            return TestResult::Fail("fragmented report not reassembled");
        }
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_MORE_TO_COME,
            &[0x02, 0x01],
        ));
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_TRUNCATED,
            &[0x06],
        ));
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_COMPLETE,
            &[0x09],
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.reports_received != 3 || snap.last_report != [0x09] {
            reset_all();
            return TestResult::Fail("truncated fragment poisoned reassembly");
        }
        // 5. Malformed report (Data_Length overruns the event) and
        // a report for another handle: both ignored, no panic, no
        // state change.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x0F, 0x07, 0x00, 0x04, 0xC4, 0xFF, 0x00, 0x09, 0x02, 0x01, 0x06],
        });
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_report(
            0x0009,
            4,
            -60,
            LE_PA_DATA_COMPLETE,
            &[0xAA],
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.reports_received != 3 || snap.phase != crate::gap::PeriodicSyncPhase::Synced {
            reset_all();
            return TestResult::Fail("malformed / foreign report moved sync state");
        }
        // 6. Sync Lost ends the sync; the train is then disabled.
        fake.enqueue_event(le_periodic_adv_sync_lost(0x0007));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.phase != crate::gap::PeriodicSyncPhase::Idle || snap.sync_handle.is_some() {
            reset_all();
            return TestResult::Fail("Sync Lost did not return to Idle");
        }
        if periodic_adv_set_enable(0, false).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_set_enable(false) rejected from Enabled");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        let ok = periodic_adv_phase(0) == Some(crate::gap::PeriodicAdvertiserPhase::Configured);
        reset_all();
        if !ok {
            return TestResult::Fail("disable did not return advertiser to Configured");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_periodic_adv_sync_flow);

    /// #1654: the sender-side sync-transfer conversation against
    /// the scripted controller — transfer our sync (§7.8.89) and
    /// our advertising set's info (§7.8.90) to a connected device,
    /// per-connection (§7.8.91) and default (§7.8.92) transfer
    /// parameters, each byte-pinned against its spec section, with
    /// Command Complete outcomes (success, 0x42 / 0x02 / 0x11
    /// rejections, short return) recorded and the sync / train
    /// phases unchanged by every transfer.
    ///
    /// Counts are relative to the bring-up baseline: #1560's
    /// absolute counts went stale when #815 added the Read Local
    /// Name + Read Class of Device bring-up phases, so this test
    /// records the baseline instead of assuming it.
    fn smoke_pump_periodic_adv_sync_transfer_flow() -> TestResult {
        use crate::gap::{
            PeerAddressType, PeriodicAdvDataOperation, PeriodicAdvertisingCreateSync,
            PeriodicAdvertisingDefaultSyncTransferParameters, PeriodicAdvertisingParameters,
            PeriodicAdvertisingSyncTransferParameters, SyncTransferOutcome,
        };
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        // Commands sent so far are exactly the bring-up sequence;
        // every assertion below counts from this baseline.
        let base = fake.sent_command_params().len();
        let sent_is = |want: &[(u16, &[u8])]| -> bool {
            let sent = fake.sent_command_params();
            if sent.len() != base + want.len() {
                return false;
            }
            want.iter().enumerate().all(|(i, (opcode, params))| {
                sent[base + i].0 == *opcode && sent[base + i].1 == *params
            })
        };
        // 1. Rejections before anything exists: no sync to
        // transfer, no train enabled, no connection, and the
        // default-parameters struct refuses a reserved mode.
        if periodic_adv_sync_transfer(0, 0x0001, 0xBEEF, 0x0007) != Err(PeriodicError::WrongPhase) {
            reset_all();
            return TestResult::Fail("sync transfer accepted with no sync");
        }
        if periodic_adv_set_info_transfer(0, 0x0001, 0xBEEF, 0x00) != Err(PeriodicError::WrongPhase)
        {
            reset_all();
            return TestResult::Fail("set info transfer accepted with no train");
        }
        if periodic_adv_set_sync_transfer_parameters(
            0,
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x02,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
        ) != Err(PeriodicError::WrongPhase)
        {
            reset_all();
            return TestResult::Fail("transfer parameters accepted with no connection");
        }
        if periodic_adv_set_default_sync_transfer_parameters(
            0,
            PeriodicAdvertisingDefaultSyncTransferParameters {
                mode: 0x04,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
        ) != Err(PeriodicError::BadParameter)
        {
            reset_all();
            return TestResult::Fail("default transfer parameters accepted mode 0x04");
        }
        if !sent_is(&[]) {
            reset_all();
            return TestResult::Fail("rejected transfer commands reached the controller");
        }
        if periodic_sync_transfer_last_outcome(0).is_some() {
            reset_all();
            return TestResult::Fail("transfer outcome recorded before any transfer");
        }
        // 2. Establish the peer connection, the broadcaster train,
        // and the receiver sync (same pinned bytes as #1560).
        fake.enqueue_event(le_connection_complete(0x0001, peer));
        let _ = pump_once(0);
        let params = PeriodicAdvertisingParameters::for_handle(0x00);
        if periodic_adv_set_parameters(0, params).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_set_parameters rejected");
        }
        if !sent_is(&[(
            op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS,
            &[0x00, 0x50, 0x00, 0x50, 0x00, 0x01, 0x00],
        )]) {
            reset_all();
            return TestResult::Fail("Set Periodic Adv Parameters bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if periodic_adv_set_data(
            0,
            0x00,
            PeriodicAdvDataOperation::Complete,
            &[0x02, 0x01, 0x06],
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("periodic_adv_set_data rejected from Configured");
        }
        if !sent_is(&[
            (
                op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS,
                &[0x00, 0x50, 0x00, 0x50, 0x00, 0x01, 0x00],
            ),
            (
                op::HCI_LE_SET_PERIODIC_ADVERTISING_DATA,
                &[0x00, 0x03, 0x03, 0x02, 0x01, 0x06],
            ),
        ]) {
            reset_all();
            return TestResult::Fail("Set Periodic Adv Data bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_DATA, &[0]));
        let _ = pump_once(0);
        if periodic_adv_set_enable(0, true).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_set_enable rejected from Configured");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE, &[0]));
        let _ = pump_once(0);
        if periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Enabled) {
            reset_all();
            return TestResult::Fail("phase not Enabled after enable complete");
        }
        let req = PeriodicAdvertisingCreateSync::to_advertiser(0x01, PeerAddressType::Public, peer);
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_create_sync rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0));
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_sync_established(0x00, 0x0007, 0x01, peer));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0);
        if snap.as_ref().map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Synced)
            || snap.as_ref().and_then(|s| s.sync_handle) != Some(0x0007)
        {
            reset_all();
            return TestResult::Fail("Sync Established did not land the sync");
        }
        // 3. Rejections with state present: a sync handle we do not
        // hold, an unknown connection, and out-of-range transfer
        // parameters for the live connection.
        if periodic_adv_sync_transfer(0, 0x0001, 0xBEEF, 0x0009) != Err(PeriodicError::WrongPhase) {
            reset_all();
            return TestResult::Fail("sync transfer accepted for a foreign sync handle");
        }
        if periodic_adv_sync_transfer(0, 0x0002, 0xBEEF, 0x0007) != Err(PeriodicError::WrongPhase) {
            reset_all();
            return TestResult::Fail("sync transfer accepted for an unknown connection");
        }
        if periodic_adv_set_info_transfer(0, 0x0002, 0xBEEF, 0x00) != Err(PeriodicError::WrongPhase)
        {
            reset_all();
            return TestResult::Fail("set info transfer accepted for an unknown connection");
        }
        let bad_params: [PeriodicAdvertisingSyncTransferParameters; 5] = [
            // Mode 0x04 is reserved (§7.8.91).
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x04,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
            // Skip above 0x01F3.
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x02,
                skip: 0x01F4,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
            // Timeout below 0x000A.
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x02,
                skip: 0,
                sync_timeout: 0x0009,
                cte_type: 0x00,
            },
            // Reserved CTE_Type bit 3.
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x02,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x08,
            },
            // All non-reserved CTE_Type bits set (0x17): the
            // controller refuses with Command Disallowed.
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x02,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x17,
            },
        ];
        for params in bad_params {
            if periodic_adv_set_sync_transfer_parameters(0, params)
                != Err(PeriodicError::BadParameter)
            {
                reset_all();
                return TestResult::Fail("out-of-range transfer parameters accepted");
            }
        }
        if !sent_is(&[
            (
                op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS,
                &[0x00, 0x50, 0x00, 0x50, 0x00, 0x01, 0x00],
            ),
            (
                op::HCI_LE_SET_PERIODIC_ADVERTISING_DATA,
                &[0x00, 0x03, 0x03, 0x02, 0x01, 0x06],
            ),
            (op::HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE, &[0x01, 0x00]),
            (
                op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC,
                &[
                    0x02, 0x01, 0x00, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x00, 0x00, 0xE8, 0x03,
                    0xFF,
                ],
            ),
        ]) {
            reset_all();
            return TestResult::Fail("rejected transfer commands reached the controller");
        }
        // 4. §7.8.89 happy path: connection 0x0001, service data
        // 0xBEEF, sync 0x0007 — 6 bytes, little-endian handles.
        if periodic_adv_sync_transfer(0, 0x0001, 0xBEEF, 0x0007).is_err() {
            reset_all();
            return TestResult::Fail("sync transfer rejected from Synced");
        }
        let sent = fake.sent_command_params();
        let last = match sent.last() {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("no command sent for sync transfer");
            }
        };
        if last.0 != op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER
            || last.1 != [0x01, 0x00, 0xEF, 0xBE, 0x07, 0x00]
        {
            reset_all();
            return TestResult::Fail("Sync Transfer bytes mismatch");
        }
        // Command Complete (status 0 + echoed connection handle):
        // the outcome is recorded and the sync stays Synced.
        fake.enqueue_event(cc(
            op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
            &[0, 0x01, 0x00],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
                status: 0,
                connection_handle: Some(0x0001),
            })
            || periodic_sync_snapshot(0).map(|s| s.phase)
                != Some(crate::gap::PeriodicSyncPhase::Synced)
        {
            reset_all();
            return TestResult::Fail("Sync Transfer success outcome wrong");
        }
        // A Command Status for this opcode is not its completion:
        // it records nothing.
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER, 0));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
                status: 0,
                connection_handle: Some(0x0001),
            })
        {
            reset_all();
            return TestResult::Fail("Command Status overwrote the transfer outcome");
        }
        // 5. §7.8.89 error path: Unknown Advertising Identifier
        // (0x42) — the transfer failed, the sync is untouched.
        if periodic_adv_sync_transfer(0, 0x0001, 0xBEEF, 0x0007).is_err() {
            reset_all();
            return TestResult::Fail("sync transfer rejected before its 0x42 complete");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
            &[0x42, 0x01, 0x00],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
                status: 0x42,
                connection_handle: Some(0x0001),
            })
            || periodic_sync_snapshot(0).map(|s| s.phase)
                != Some(crate::gap::PeriodicSyncPhase::Synced)
        {
            reset_all();
            return TestResult::Fail("Sync Transfer 0x42 outcome wrong");
        }
        // 6. §7.8.90 happy path: our train (handle 0x00) to the
        // same connection — 5 bytes.
        if periodic_adv_set_info_transfer(0, 0x0001, 0xBEEF, 0x00).is_err() {
            reset_all();
            return TestResult::Fail("set info transfer rejected from Enabled");
        }
        let sent = fake.sent_command_params();
        let last = match sent.last() {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("no command sent for set info transfer");
            }
        };
        if last.0 != op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER
            || last.1 != [0x01, 0x00, 0xEF, 0xBE, 0x00]
        {
            reset_all();
            return TestResult::Fail("Set Info Transfer bytes mismatch");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
            &[0, 0x01, 0x00],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
                status: 0,
                connection_handle: Some(0x0001),
            })
            || periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Enabled)
        {
            reset_all();
            return TestResult::Fail("Set Info Transfer success outcome wrong");
        }
        // 7. §7.8.90 error path: Unknown Connection Identifier
        // (0x02) — the train stays Enabled.
        if periodic_adv_set_info_transfer(0, 0x0001, 0xBEEF, 0x00).is_err() {
            reset_all();
            return TestResult::Fail("set info transfer rejected before its 0x02 complete");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
            &[0x02, 0x01, 0x00],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
                status: 0x02,
                connection_handle: Some(0x0001),
            })
            || periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Enabled)
        {
            reset_all();
            return TestResult::Fail("Set Info Transfer 0x02 outcome wrong");
        }
        // 8. §7.8.91 happy path: mode 0x02 (reports on, no
        // duplicate filtering), skip 0, 10 s timeout, CTE 0x00 —
        // 8 bytes.
        if periodic_adv_set_sync_transfer_parameters(
            0,
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x02,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("set transfer parameters rejected for a live connection");
        }
        let sent = fake.sent_command_params();
        let last = match sent.last() {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("no command sent for set transfer parameters");
            }
        };
        if last.0 != op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS
            || last.1 != [0x01, 0x00, 0x02, 0x00, 0x00, 0xE8, 0x03, 0x00]
        {
            reset_all();
            return TestResult::Fail("Set Transfer Parameters bytes mismatch");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
            &[0, 0x01, 0x00],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                status: 0,
                connection_handle: Some(0x0001),
            })
        {
            reset_all();
            return TestResult::Fail("Set Transfer Parameters success outcome wrong");
        }
        // 9. §7.8.91 short return: status only, no echoed handle.
        if periodic_adv_set_sync_transfer_parameters(
            0,
            PeriodicAdvertisingSyncTransferParameters {
                connection_handle: 0x0001,
                mode: 0x01,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("set transfer parameters rejected before short complete");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
            &[0],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                status: 0,
                connection_handle: None,
            })
        {
            reset_all();
            return TestResult::Fail("short Set Transfer Parameters complete misread");
        }
        // 10. §7.8.92 happy path: mode 0x01, skip 0, 10 s timeout,
        // CTE 0x00 — 6 bytes, no connection handle, and the return
        // carries Status only.
        if periodic_adv_set_default_sync_transfer_parameters(
            0,
            PeriodicAdvertisingDefaultSyncTransferParameters {
                mode: 0x01,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("set default transfer parameters rejected");
        }
        let sent = fake.sent_command_params();
        let last = match sent.last() {
            Some(c) => c,
            None => {
                reset_all();
                return TestResult::Fail("no command sent for set default transfer parameters");
            }
        };
        if last.0 != op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS
            || last.1 != [0x01, 0x00, 0x00, 0xE8, 0x03, 0x00]
        {
            reset_all();
            return TestResult::Fail("Set Default Transfer Parameters bytes mismatch");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
            &[0],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                status: 0,
                connection_handle: None,
            })
        {
            reset_all();
            return TestResult::Fail("Set Default Transfer Parameters success outcome wrong");
        }
        // 11. §7.8.92 error path: Unsupported Feature or Parameter
        // Value (0x11, e.g. mode 0x03 without ADI support).
        if periodic_adv_set_default_sync_transfer_parameters(
            0,
            PeriodicAdvertisingDefaultSyncTransferParameters {
                mode: 0x03,
                skip: 0,
                sync_timeout: 0x03E8,
                cte_type: 0x00,
            },
        )
        .is_err()
        {
            reset_all();
            return TestResult::Fail("set default transfer parameters rejected before 0x11");
        }
        fake.enqueue_event(cc(
            op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
            &[0x11],
        ));
        let _ = pump_once(0);
        if periodic_sync_transfer_last_outcome(0)
            != Some(SyncTransferOutcome {
                opcode: op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                status: 0x11,
                connection_handle: None,
            })
        {
            reset_all();
            return TestResult::Fail("Set Default Transfer Parameters 0x11 outcome wrong");
        }
        // 12. §7.8.89 BadParameter: a held sync handle above
        // 0x0EFF is refused even though the sync, the connection,
        // and the service data are all otherwise valid.
        fake.enqueue_event(le_periodic_adv_sync_lost(0x0007));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Idle) {
            reset_all();
            return TestResult::Fail("Sync Lost did not return to Idle");
        }
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_create_sync rejected for the second sync");
        }
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0));
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_sync_established(0x00, 0x0F00, 0x01, peer));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).and_then(|s| s.sync_handle) != Some(0x0F00) {
            reset_all();
            return TestResult::Fail("out-of-range sync handle not adopted for the probe");
        }
        let before = fake.sent_command_params().len();
        if periodic_adv_sync_transfer(0, 0x0001, 0xBEEF, 0x0F00) != Err(PeriodicError::BadParameter)
        {
            reset_all();
            return TestResult::Fail("sync transfer accepted an out-of-range sync handle");
        }
        if fake.sent_command_params().len() != before {
            reset_all();
            return TestResult::Fail("out-of-range sync transfer reached the controller");
        }
        // The refused command recorded no outcome: the last one is
        // still the §7.8.92 0x11 rejection.
        let ok = periodic_sync_transfer_last_outcome(0)
            == Some(SyncTransferOutcome {
                opcode: op::HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                status: 0x11,
                connection_handle: None,
            });
        reset_all();
        if !ok {
            return TestResult::Fail("refused transfer overwrote the last outcome");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/pump", smoke_pump_periodic_adv_sync_transfer_flow);

    /// #1575: a transferred sync adopts into PeriodicSync with no
    /// (named `..._received_flow` on rebase: #1654's sender-side test
    /// on main already owns `smoke_pump_periodic_adv_sync_transfer_flow`.)
    /// pending Create Sync — the scripted controller sends the
    /// 0x18 subevent, reports then deliver on the transferred
    /// handle, and Sync Lost ends it. Failed, truncated, and
    /// racing transfers are ignored.
    fn smoke_pump_periodic_adv_sync_transfer_received_flow() -> TestResult {
        use crate::event::LE_PA_DATA_COMPLETE;
        use crate::gap::{PeerAddressType, PeriodicAdvertisingCreateSync};
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        // 1. Failed transfer (status 0x3E): nothing is adopted.
        fake.enqueue_event(le_periodic_adv_sync_transfer_received(
            0x3E, 0x0001, 0xBEEF, 0x0007, 0x01, peer,
        ));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Idle) {
            reset_all();
            return TestResult::Fail("failed transfer adopted a sync");
        }
        // 2. Truncated transfer (19 of 20 params bytes): ignored.
        let mut truncated =
            le_periodic_adv_sync_transfer_received(0x00, 0x0001, 0xBEEF, 0x0007, 0x01, peer);
        truncated.params.truncate(19);
        fake.enqueue_event(truncated);
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Idle) {
            reset_all();
            return TestResult::Fail("truncated transfer adopted a sync");
        }
        // 3. Good transfer, no pending Create Sync: adopts.
        fake.enqueue_event(le_periodic_adv_sync_transfer_received(
            0x00, 0x0001, 0xBEEF, 0x0007, 0x01, peer,
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0);
        if snap.as_ref().map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Synced)
            || snap.as_ref().and_then(|s| s.sync_handle) != Some(0x0007)
            || snap.as_ref().map(|s| s.periodic_interval) != Some(0x0050)
            || snap.as_ref().and_then(|s| s.transfer_connection_handle) != Some(0x0001)
            || snap.as_ref().map(|s| s.service_data) != Some(0xBEEF)
        {
            reset_all();
            return TestResult::Fail("transfer did not adopt the sync");
        }
        // 4. A report on the transferred handle delivers.
        fake.enqueue_event(le_periodic_adv_report(
            0x0007,
            4,
            -60,
            LE_PA_DATA_COMPLETE,
            &[0x02, 0x01, 0x06],
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.reports_received != 1 || snap.last_report != [0x02, 0x01, 0x06] {
            reset_all();
            return TestResult::Fail("report on transferred sync not delivered");
        }
        // 5. A second transfer while Synced is ignored (existing
        // sync wins; no hijack to handle 0x0009).
        fake.enqueue_event(le_periodic_adv_sync_transfer_received(
            0x00, 0x0002, 0x1234, 0x0009, 0x02, peer,
        ));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.sync_handle != Some(0x0007) || snap.transfer_connection_handle != Some(0x0001) {
            reset_all();
            return TestResult::Fail("transfer while Synced hijacked the sync");
        }
        // 6. Sync Lost ends the transferred sync.
        fake.enqueue_event(le_periodic_adv_sync_lost(0x0007));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        if snap.phase != crate::gap::PeriodicSyncPhase::Idle
            || snap.sync_handle.is_some()
            || snap.transfer_connection_handle.is_some()
        {
            reset_all();
            return TestResult::Fail("Sync Lost did not end the transferred sync");
        }
        // 7. A transfer racing a pending Create Sync is ignored;
        // the local attempt then lands normally, with no transfer
        // provenance.
        let req = PeriodicAdvertisingCreateSync::to_advertiser(0x01, PeerAddressType::Public, peer);
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("periodic_adv_create_sync rejected from Idle");
        }
        fake.enqueue_event(le_periodic_adv_sync_transfer_received(
            0x00, 0x0001, 0xBEEF, 0x0009, 0x01, peer,
        ));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase)
            != Some(crate::gap::PeriodicSyncPhase::Creating)
        {
            reset_all();
            return TestResult::Fail("transfer racing Create Sync moved phase out of Creating");
        }
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0));
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_sync_established(0x00, 0x0007, 0x01, peer));
        let _ = pump_once(0);
        let snap = periodic_sync_snapshot(0).unwrap();
        let ok = snap.phase == crate::gap::PeriodicSyncPhase::Synced
            && snap.sync_handle == Some(0x0007)
            && snap.transfer_connection_handle.is_none();
        reset_all();
        if !ok {
            return TestResult::Fail("local Create Sync did not land after racing transfer");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_periodic_adv_sync_transfer_received_flow
    );

    /// #1560: failure paths fail closed — out-of-order API calls are
    /// rejected, out-of-range parameters never reach the controller,
    /// refused commands return to Idle without wedging the machine,
    /// and malformed sync subevents change nothing.
    fn smoke_pump_periodic_adv_failure_and_malformed() -> TestResult {
        use crate::gap::{
            PeerAddressType, PeriodicAdvDataOperation, PeriodicAdvertisingCreateSync,
            PeriodicAdvertisingParameters,
        };
        reset_all();
        let fake = Arc::new(ScriptedTransport::new());
        if let Err(e) = central_bring_up(fake.clone()) {
            reset_all();
            return TestResult::Fail(e);
        }
        let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
        // Data / enable before any parameters: WrongPhase, and no
        // command reaches the controller.
        if periodic_adv_set_data(0, 0x00, PeriodicAdvDataOperation::Complete, &[0x02]).is_ok() {
            reset_all();
            return TestResult::Fail("set_data accepted before configure");
        }
        if periodic_adv_set_enable(0, true).is_ok() {
            reset_all();
            return TestResult::Fail("set_enable accepted before configure");
        }
        if periodic_adv_terminate_sync(0).is_ok() || periodic_adv_cancel_create_sync(0).is_ok() {
            reset_all();
            return TestResult::Fail("terminate/cancel accepted from Idle");
        }
        if fake.sent_command_params().len() != 5 {
            reset_all();
            return TestResult::Fail("rejected calls emitted commands");
        }
        // Out-of-range parameters never reach the controller.
        let bad_params = PeriodicAdvertisingParameters {
            advertising_handle: 0x00,
            interval_min: 0x0005,
            interval_max: 0x0050,
            include_tx_power: false,
            include_adi: false,
        };
        if periodic_adv_set_parameters(0, bad_params).is_ok() {
            reset_all();
            return TestResult::Fail("out-of-range parameters accepted");
        }
        let mut bad_req =
            PeriodicAdvertisingCreateSync::to_advertiser(0x01, PeerAddressType::Public, peer);
        bad_req.sync_timeout = 0x0009;
        if periodic_adv_create_sync(0, bad_req).is_ok() {
            reset_all();
            return TestResult::Fail("out-of-range Create Sync accepted");
        }
        if fake.sent_command_params().len() != 5 {
            reset_all();
            return TestResult::Fail("bad parameters emitted commands");
        }
        // Refused parameters change nothing; retry works.
        if periodic_adv_set_parameters(0, PeriodicAdvertisingParameters::for_handle(0x00)).is_err()
        {
            reset_all();
            return TestResult::Fail("set_parameters rejected");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS, &[0x0C]));
        let _ = pump_once(0);
        if periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Idle) {
            reset_all();
            return TestResult::Fail("refused parameters left Idle");
        }
        if periodic_adv_set_parameters(0, PeriodicAdvertisingParameters::for_handle(0x00)).is_err()
        {
            reset_all();
            return TestResult::Fail("retry set_parameters rejected");
        }
        fake.enqueue_event(cc(op::HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS, &[0]));
        let _ = pump_once(0);
        if periodic_adv_phase(0) != Some(crate::gap::PeriodicAdvertiserPhase::Configured) {
            reset_all();
            return TestResult::Fail("retry parameters did not configure");
        }
        // Create Sync rejected by Command Status: Idle, no sync.
        let req = PeriodicAdvertisingCreateSync::to_advertiser(0x01, PeerAddressType::Public, peer);
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("create_sync rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0x0C));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Idle) {
            reset_all();
            return TestResult::Fail("rejected Create Sync did not return to Idle");
        }
        // Failed establishment (status != 0): Idle.
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("retry create_sync rejected");
        }
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0));
        let _ = pump_once(0);
        // Malformed Sync Established (truncated) while Creating:
        // ignored, still Creating.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x0E, 0x00, 0x07, 0x00, 0x01, 0x00, 0xC0, 0xC1],
        });
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase)
            != Some(crate::gap::PeriodicSyncPhase::Creating)
        {
            reset_all();
            return TestResult::Fail("malformed Sync Established moved phase out of Creating");
        }
        fake.enqueue_event(le_periodic_adv_sync_established(0x3E, 0x0007, 0x01, peer));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Idle) {
            reset_all();
            return TestResult::Fail("failed establishment did not return to Idle");
        }
        // Establish, then phase guards: no second create, no
        // cancel while Synced; refused terminate stays Synced.
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("create_sync rejected from Idle");
        }
        fake.enqueue_event(cs(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC, 0));
        let _ = pump_once(0);
        fake.enqueue_event(le_periodic_adv_sync_established(0x00, 0x0007, 0x01, peer));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Synced)
        {
            reset_all();
            return TestResult::Fail("establishment did not reach Synced");
        }
        if periodic_adv_create_sync(0, req).is_ok() || periodic_adv_cancel_create_sync(0).is_ok() {
            reset_all();
            return TestResult::Fail("create/cancel accepted while Synced");
        }
        // Malformed Sync Lost (truncated) while Synced: ignored.
        fake.enqueue_event(Event {
            code: EventCode::LeMeta as u8,
            params: alloc::vec![0x10, 0x07],
        });
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Synced)
        {
            reset_all();
            return TestResult::Fail("malformed Sync Lost moved phase out of Synced");
        }
        if periodic_adv_terminate_sync(0).is_err() {
            reset_all();
            return TestResult::Fail("terminate_sync rejected from Synced");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, p)| (*o, p.clone()))
            != Some((
                op::HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC,
                alloc::vec![0x07, 0x00],
            ))
        {
            reset_all();
            return TestResult::Fail("Terminate Sync bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC, &[0x0C]));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Synced)
        {
            reset_all();
            return TestResult::Fail("refused terminate did not stay Synced");
        }
        if periodic_adv_terminate_sync(0).is_err() {
            reset_all();
            return TestResult::Fail("retry terminate_sync rejected");
        }
        fake.enqueue_event(cc(op::HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC, &[0]));
        let _ = pump_once(0);
        if periodic_sync_snapshot(0).map(|s| s.phase) != Some(crate::gap::PeriodicSyncPhase::Idle) {
            reset_all();
            return TestResult::Fail("accepted terminate did not return to Idle");
        }
        // Cancel flow: Create → Cancel command → complete → Idle.
        if periodic_adv_create_sync(0, req).is_err() {
            reset_all();
            return TestResult::Fail("create_sync rejected from Idle");
        }
        if periodic_adv_cancel_create_sync(0).is_err() {
            reset_all();
            return TestResult::Fail("cancel_create_sync rejected from Creating");
        }
        let sent = fake.sent_command_params();
        if sent.last().map(|(o, p)| (*o, p.clone()))
            != Some((
                op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL,
                alloc::vec![],
            ))
        {
            reset_all();
            return TestResult::Fail("Create Sync Cancel bytes mismatch");
        }
        fake.enqueue_event(cc(op::HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL, &[0]));
        let _ = pump_once(0);
        let ok =
            periodic_sync_snapshot(0).map(|s| s.phase) == Some(crate::gap::PeriodicSyncPhase::Idle);
        reset_all();
        if !ok {
            return TestResult::Fail("accepted cancel did not return to Idle");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/pump",
        smoke_pump_periodic_adv_failure_and_malformed
    );
}
