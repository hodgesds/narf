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
//!   deferred page when one is waiting.
//! - BR/EDR Connection Complete (while paging) → the classic phase
//!   machine + connection table entry.
//! - Command Complete / Command Status for the scan/connect opcodes
//!   → the central phase machine: parameters accepted enables the
//!   scan, disable accepted issues a deferred Create Connection, a
//!   refused command drops the phase back to Idle. The same arms
//!   drive the classic phase machine: a refused Inquiry or Create
//!   Connection drops it to Idle, a refused Inquiry Cancel returns
//!   it to Inquiring, an accepted Write Scan Enable records the mode.
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
//! ## Classic initiation (issue #1315)
//!
//! [`classic_start_inquiry`] / [`classic_cancel_inquiry`] /
//! [`classic_connect`] / [`classic_write_scan_enable`] issue the
//! BR/EDR inquiry + paging commands through the pump's own send
//! path, sequenced on the controller's completions exactly like the
//! LE central above (copied pattern: phase machine in
//! [`classic::ClassicCentral`], deferred connect while the inquiry
//! is cancelled, fail-closed refusal handling). [`classic_phase`] /
//! [`classic_peers`] / [`classic_scan_mode`] expose the state for a
//! future mgmt/userspace trigger lane. What this deliberately does
//! NOT do: extended inquiry results / EIR + RSSI, Remote Name
//! Request, SSP pairing initiation on the paged link (#888 covers
//! pairing), or SCO setup after connect (#817) — the connection is
//! tracked like any other pump connection and torn down on
//! Disconnection Complete.
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

use narf_filesystem::bluetooth::{BtRegisterStatus, BtSendError};
use narf_lib::sync::IrqSafeSpinLock;

use crate::att;
use crate::bond_store::{Bond, BondStore};
use crate::classic::{self, ClassicPhase};
use crate::controller::ControllerInfo;
use crate::event::{
    parse_inquiry_results, parse_le_advertising_reports, ClassicConnectionComplete,
    CommandComplete, CommandStatus, DisconnectionComplete, EventCode, LeConnectionComplete,
    LeLongTermKeyRequest, LePeriodicAdvReport, LePeriodicAdvSyncEstablished, LePeriodicAdvSyncLost,
    NumberOfCompletedPackets,
};
use crate::gap::{self, CentralPhase, PeriodicAdvertiserPhase, PeriodicSyncPhase};
use crate::gatt_client::{self, GattClientError};
use crate::gatt_server::GattServer;
use crate::hci::{AclData, Command, Event};
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
use crate::smp::{self, Initiator, PairingError, Responder};
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
    /// `central_connect` from Scanning issues Set_Scan_Enable(0)
    /// first and only issues LE_Create_Connection once the disable
    /// completes, so the controller is never asked to initiate
    /// while it is still scanning.
    pending_connect: Option<gap::CreateConnection>,
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
    /// Page deferred while an inquiry is being cancelled:
    /// `classic_connect` from Inquiring issues Inquiry_Cancel first
    /// and only issues Create_Connection once Inquiry Complete
    /// arrives, so the controller is never asked to page while it
    /// is still inquiring.
    pending_page: Option<classic::PageRequest>,
    /// Write_Scan_Enable mode awaiting its Command Complete; applied
    /// to `classic.scan_mode` only on success.
    pending_scan_mode: Option<u8>,
    /// Bonds from completed pairings (driver-domain state, never a
    /// global, never exposed to userspace). Survives disconnects;
    /// lost on controller removal or reboot.
    bonds: BondStore,
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
            .field("central_phase", &self.central.phase)
            .field("classic_phase", &self.classic.phase)
            .field("periodic_adv_phase", &self.periodic_adv.phase)
            .field("periodic_sync_phase", &self.periodic_sync.phase)
            .field("bonds", &self.bonds.len())
            .field("claimed", &self.claimed.len())
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
            classic: classic::ClassicCentral::new(),
            periodic_adv: gap::PeriodicAdvertiser::new(),
            periodic_sync: gap::PeriodicSync::new(),
            pending_page: None,
            pending_scan_mode: None,
            bonds: BondStore::new(),
            claimed: Vec::new(),
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
    /// `local_cid`, `dlci`). We are the responder, so C/R is 0
    /// (TS 07.10 §5.1.1: the initiator sets C/R=1, the responder
    /// 0). Returns the bytes sent.
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
        let (peer_cid, open) = match &self.connections[conn_idx].channels[pos] {
            Channel::BrEdr(ch) => match &ch.service {
                ChannelService::Rfcomm(session) => (ch.peer_cid, session.is_dlc_open(dlci)),
                _ => return Err(BtSendError::WrongService),
            },
            Channel::Le(_) => return Err(BtSendError::WrongService),
        };
        if !open {
            return Err(BtSendError::NoChannel);
        }
        let frame = crate::rfcomm::Frame::uih(dlci, false, payload.to_vec());
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
    /// peer a DISC (C/R 0 — responder). The L2CAP channel (shared
    /// mux) survives, as do its other DLCs. `false` when no such
    /// channel/DLC exists.
    pub fn close_rfcomm_dlc(&mut self, handle: u16, local_cid: u16, dlci: u8) -> bool {
        let Some(conn_idx) = self.connections.iter().position(|c| c.handle == handle) else {
            return false;
        };
        let Some(pos) = self.connections[conn_idx].channel_pos(local_cid) else {
            return false;
        };
        let (peer_cid, le, was_open) = match &mut self.connections[conn_idx].channels[pos] {
            Channel::BrEdr(ch) => match &mut ch.service {
                ChannelService::Rfcomm(session) => {
                    let was_open = session.is_dlc_open(dlci);
                    session.close_dlc(dlci);
                    (ch.peer_cid, self.connections[conn_idx].le, was_open)
                }
                _ => return false,
            },
            Channel::Le(_) => return false,
        };
        if !was_open {
            return false;
        }
        self.release_dlc_claim(handle, local_cid, dlci);
        let frame = crate::rfcomm::Frame::disc(dlci, false);
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
                self.pending_connect = Some(gap::CreateConnection::to_peer(
                    peer_address_type,
                    peer_address,
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
                            Some(cc) => {
                                if self
                                    .send_command(op::HCI_LE_CREATE_CONNECTION, &cc.encode())
                                    .is_ok()
                                {
                                    self.central.note_connecting();
                                } else {
                                    self.central.phase = CentralPhase::Idle;
                                }
                            }
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
            op::HCI_LE_CREATE_CONNECTION => {
                if self.central.phase == CentralPhase::Connecting && status != 0 {
                    self.central.phase = CentralPhase::Idle;
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

    /// Advance the periodic state machines on a completed periodic
    /// command. Shared by the Command Complete and Command Status
    /// arms: the §7.8.61..63 broadcaster commands and Terminate
    /// Sync return Complete, while Create Sync returns Status
    /// first and completes later via Sync Established.
    fn on_periodic_command_done(&mut self, opcode: u16, status: u8) {
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

    /// Advance the classic state machine on a completed
    /// inquiry/page/scan command. Shared by the Command Complete
    /// and Command Status arms: Inquiry and Create Connection
    /// return Status first, Inquiry Cancel and Write Scan Enable
    /// return Complete.
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
                        self.pending_page = None;
                        self.classic.note_inquiry_started();
                    }
                }
            }
            op::HCI_CREATE_CONNECTION => {
                if self.classic.phase == ClassicPhase::Paging && status != 0 {
                    self.classic.note_idle();
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
}

/// Map a state-machine error to its Pairing Failed reason byte
/// (Vol 3 Part H §3.5.5).
fn smp_fail_reason(err: &PairingError) -> u8 {
    match err {
        PairingError::BadConfirm => smp::SMP_FAILED_CONFIRM_VALUE,
        PairingError::BadDhKeyCheck => smp::SMP_FAILED_DHKEY_CHECK_FAILED,
        _ => smp::SMP_FAILED_UNSPECIFIED,
    }
}

impl PumpCore {
    /// Start an initiator pairing on an LE connection: emit the
    /// Pairing Request and park the new session on the connection.
    /// This is the application trigger — the kernel side of pairing
    /// initiation. There is no ATT-triggered path yet: no
    /// auth-gated attribute exists to produce an
    /// Insufficient-Authentication error, so nothing today calls
    /// this from the ATT path.
    pub fn smp_initiate_pairing(&mut self, handle: u16) -> Result<(), SmpInitiateError> {
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
        let mut initiator = Initiator::new(NarfSmpCrypto, local, peer);
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

    /// Forget a peer's bond. Returns true when one was removed.
    pub fn forget_bond(&mut self, peer_addr: &[u8; 7]) -> bool {
        self.bonds.forget(peer_addr)
    }

    /// Number of bonds held for this controller.
    pub fn bond_count(&self) -> usize {
        self.bonds.len()
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

    /// Handle one HCI event. Socket fan-out happens in `pump_once`;
    /// this is only the host-stack dispatch.
    fn dispatch_event(&mut self, event: &Event) {
        match event.code {
            code if code == EventCode::LeMeta as u8 => {
                if let Some(cc) = LeConnectionComplete::parse(event) {
                    // Initiator-role completions drive the central
                    // state machine; inbound (peripheral-role)
                    // connections while Idle leave it alone. The
                    // role is captured before the state machine
                    // advances: it is the only sound test for
                    // whether THIS completion is central-role
                    // (connected_handle alone could match a stale
                    // handle reused by a peripheral connection).
                    let central_completed = self.central.phase == CentralPhase::Connecting;
                    if central_completed {
                        self.central.note_connection_complete(cc.status, cc.handle);
                    }
                    if cc.status == 0 {
                        let mut peer = [0u8; 7];
                        peer[0] = cc.peer_address_type;
                        peer[1..7].copy_from_slice(&cc.peer_address);
                        self.release_handle_claims(cc.handle);
                        self.connections.retain(|c| c.handle != cc.handle);
                        self.connections
                            .push(Connection::new(cc.handle, true, peer));
                        // Central-role connections gain a GATT
                        // client record (#1313); peripheral-role
                        // connections keep server-only dispatch.
                        if central_completed {
                            if let Some(conn) = self.connections.last_mut() {
                                conn.client = Some(gatt_client::Client::new());
                            }
                        }
                        self.sysfs_track_connect(cc.handle, true, &peer);
                    }
                    return;
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
                        }
                    }
                }
                // Periodic advertising sync subevents (§7.7.65.14..16,
                // issue #1560). Malformed subevents parse to None
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
                            }
                        }
                        _ => self.classic.note_idle(),
                    },
                    ClassicPhase::Inquiring => self.classic.note_idle(),
                    _ => {}
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
                    }
                }
            }
            code if code == EventCode::DisconnectionComplete as u8 => {
                if let Some(dc) = DisconnectionComplete::parse(event) {
                    self.release_handle_claims(dc.handle);
                    self.connections.retain(|c| c.handle != dc.handle);
                    self.sysfs_track_disconnect(dc.handle);
                    if self.central.connected_handle == Some(dc.handle) {
                        self.central.note_disconnected();
                    }
                    if self.classic.connected_handle == Some(dc.handle) {
                        self.classic.note_disconnected();
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
                        self.on_periodic_command_done(cc.opcode, status);
                    }
                }
            }
            code if code == EventCode::CommandStatus as u8 => {
                if let Some(cs) = CommandStatus::parse(event) {
                    self.on_central_command_done(cs.opcode, cs.status);
                    self.on_classic_command_done(cs.opcode, cs.status);
                    self.on_periodic_command_done(cs.opcode, cs.status);
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
                    // (the session borrow must end first).
                    let (outs, bond) = match self.connection_mut(handle) {
                        None => (Vec::new(), None),
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
                                (Vec::new(), None)
                            } else if ok && enabled {
                                // The link is encrypted: Phase 3
                                // may start. On completion the bond
                                // is stored and the session cleared.
                                let (outs, bond) = match conn.smp.as_mut().unwrap() {
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
                                        (outs, bond)
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
                                        (outs, bond)
                                    }
                                };
                                if bond.is_some() {
                                    conn.smp = None;
                                }
                                (outs, bond)
                            } else {
                                // Encryption failed or was switched
                                // off mid-pairing: no bond forms. The
                                // pairing already authenticated, so
                                // this is a silent clear, not a
                                // Pairing Failed — there is nothing
                                // left to fail.
                                conn.smp = None;
                                (Vec::new(), None)
                            }
                        }
                    };
                    if let Some(bond) = bond {
                        self.bonds.store(bond);
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
                        let mut buf = &frame.payload[..];
                        while !buf.is_empty() {
                            match crate::rfcomm::Frame::decode(buf) {
                                Ok((decoded, n)) => {
                                    responses.extend(session.feed(&decoded));
                                    buf = &buf[n..];
                                }
                                // Corrupt tail: drop the rest of
                                // this B-frame's payload.
                                Err(_) => break,
                            }
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
                // fed into the new machine.
                let mut initiator = Initiator::new(NarfSmpCrypto, local, peer);
                let req = initiator.start();
                self.connections[conn_idx].smp = Some(SmpSession::Initiator(initiator));
                self.queue_frame(handle, le, &BFrame::new(CID_SMP, req.encode()));
                return;
            }
            self.connections[conn_idx].smp = Some(SmpSession::Responder(Responder::new(
                NarfSmpCrypto,
                peer,
                local,
            )));
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
                        }
                    }
                    Err(PairingError::PeerFailed(_)) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: None,
                        clear: true,
                        auto_encrypt: None,
                    },
                    Err(err) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: Some(smp_fail_reason(&err)),
                        clear: true,
                        auto_encrypt: None,
                    },
                },
                SmpSession::Initiator(i) => match i.feed(pdu) {
                    Ok(outs) => {
                        let done = i.state == smp::PairingState::Done;
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
                        }
                    }
                    Err(PairingError::PeerFailed(_)) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: None,
                        clear: true,
                        auto_encrypt: None,
                    },
                    Err(err) => SmpFeedOutcome {
                        outs: Vec::new(),
                        done_ltk: None,
                        bond: None,
                        fail_reason: Some(smp_fail_reason(&err)),
                        clear: true,
                        auto_encrypt: None,
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
/// Idle. This is the trigger surface a future mgmt/userspace lane
/// will call; today it is fixture-driven.
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

/// Re-encrypt controller `index`'s connection `handle` from its
/// stored bond. See [`PumpCore::smp_start_encryption`].
pub fn smp_start_encryption(index: usize, handle: u16) -> Option<Result<(), SmpEncryptError>> {
    with_core(index, |core| core.smp_start_encryption(handle))
}

/// Forget controller `index`'s bond for `peer_addr`.
pub fn forget_bond(index: usize, peer_addr: &[u8; 7]) -> Option<bool> {
    with_core(index, |core| core.forget_bond(peer_addr))
}

/// Bond count for controller `index`, if it has a pump.
pub fn bond_count(index: usize) -> Option<usize> {
    let pumps = PUMPS.lock();
    let slot = pumps.iter().find(|s| s.index == index)?;
    slot.core.as_ref().map(|c| c.bond_count())
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
