//! Cross-crate broker for the Bluetooth management (mgmt) handler.
//!
//! `narf-bluetooth` owns the mgmt (`HCI_CHANNEL_CONTROL`) protocol logic, but
//! it cannot be a dependency of the userspace socket layer (that would cycle
//! through `narf-audio`). This crate sits below both, so — like the uevent
//! wake hook — `narf-bluetooth` installs its handler here at boot and the
//! socket layer calls it through a function pointer.

use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;
use alloc::vec::Vec;

/// Handler shape: one mgmt command frame in, zero or more reply frames out.
pub type MgmtHandler = fn(&[u8]) -> Vec<Vec<u8>>;

// Stored as `MgmtHandler as usize`; 0 means "not installed".
static MGMT_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Install the mgmt command handler (`narf_bluetooth::mgmt::handle`). Called
/// once during Bluetooth bring-up.
pub fn install_mgmt_handler(f: MgmtHandler) {
    MGMT_HANDLER.store(f as usize, Ordering::Release);
}

/// Dispatch a mgmt command frame to the installed handler, returning its
/// reply frames. `None` if no Bluetooth stack has registered a handler.
pub fn mgmt_handle(command: &[u8]) -> Option<Vec<Vec<u8>>> {
    let h = MGMT_HANDLER.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `MgmtHandler as usize` by install_mgmt_handler.
    let f: MgmtHandler = unsafe { core::mem::transmute::<usize, MgmtHandler>(h) };
    Some(f(command))
}

/// Raw/user HCI channel hooks: send a type-prefixed HCI packet to a
/// controller, and drain the next HCI event from it.
pub type HciSendHandler = fn(dev: u16, packet: &[u8]) -> bool;
pub type HciDrainHandler = fn(dev: u16) -> Option<Vec<u8>>;

static HCI_SEND: AtomicUsize = AtomicUsize::new(0);
static HCI_DRAIN: AtomicUsize = AtomicUsize::new(0);

/// Install the raw-HCI send/drain handlers (narf_bluetooth::hci_sock).
pub fn install_hci_handlers(send: HciSendHandler, drain: HciDrainHandler) {
    HCI_SEND.store(send as usize, Ordering::Release);
    HCI_DRAIN.store(drain as usize, Ordering::Release);
}

/// Forward a type-prefixed HCI packet to controller `dev`. Returns false if
/// no handler is installed or the stack rejected it.
pub fn hci_send(dev: u16, packet: &[u8]) -> bool {
    let h = HCI_SEND.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `HciSendHandler as usize`.
    let f: HciSendHandler = unsafe { core::mem::transmute::<usize, HciSendHandler>(h) };
    f(dev, packet)
}

/// Drain the next HCI event packet from controller `dev`, or `None`.
pub fn hci_drain(dev: u16) -> Option<Vec<u8>> {
    let h = HCI_DRAIN.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `HciDrainHandler as usize`.
    let f: HciDrainHandler = unsafe { core::mem::transmute::<usize, HciDrainHandler>(h) };
    f(dev)
}

// Legacy HCI ioctl providers (HCIGETDEVLIST / HCIGETDEVINFO / HCIDEVUP/DOWN).
pub type HciDevCountHandler = fn() -> usize;
pub type HciDevInfoHandler = fn(dev: u16) -> Option<Vec<u8>>;
pub type HciDevPowerHandler = fn(dev: u16, on: bool) -> bool;

static HCI_DEV_COUNT: AtomicUsize = AtomicUsize::new(0);
static HCI_DEV_INFO: AtomicUsize = AtomicUsize::new(0);
static HCI_DEV_POWER: AtomicUsize = AtomicUsize::new(0);

/// Install the legacy-ioctl providers (narf_bluetooth::hci_sock).
pub fn install_hci_ioctl_handlers(
    count: HciDevCountHandler,
    info: HciDevInfoHandler,
    power: HciDevPowerHandler,
) {
    HCI_DEV_COUNT.store(count as usize, Ordering::Release);
    HCI_DEV_INFO.store(info as usize, Ordering::Release);
    HCI_DEV_POWER.store(power as usize, Ordering::Release);
}

/// Registered controller count (0 if no stack installed).
pub fn hci_dev_count() -> usize {
    let h = HCI_DEV_COUNT.load(Ordering::Acquire);
    if h == 0 {
        return 0;
    }
    // SAFETY: only ever stored as `HciDevCountHandler as usize`.
    let f: HciDevCountHandler = unsafe { core::mem::transmute::<usize, HciDevCountHandler>(h) };
    f()
}

/// Packed `struct hci_dev_info` bytes for controller `dev`, or `None`.
pub fn hci_dev_info(dev: u16) -> Option<Vec<u8>> {
    let h = HCI_DEV_INFO.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `HciDevInfoHandler as usize`.
    let f: HciDevInfoHandler = unsafe { core::mem::transmute::<usize, HciDevInfoHandler>(h) };
    f(dev)
}

/// HCI_CHANNEL_MONITOR bind-time replay provider (per-controller NEW_INDEX).
pub type HciMonitorReplayHandler = fn() -> Vec<Vec<u8>>;
static HCI_MONITOR_REPLAY: AtomicUsize = AtomicUsize::new(0);

/// Install the monitor-replay provider (narf_bluetooth::hci_sock::monitor_replay).
pub fn install_hci_monitor_replay(replay: HciMonitorReplayHandler) {
    HCI_MONITOR_REPLAY.store(replay as usize, Ordering::Release);
}

/// The monitor replay packets to deliver when a socket binds HCI_CHANNEL_MONITOR.
pub fn hci_monitor_replay() -> Vec<Vec<u8>> {
    let h = HCI_MONITOR_REPLAY.load(Ordering::Acquire);
    if h == 0 {
        return Vec::new();
    }
    // SAFETY: only ever stored as `HciMonitorReplayHandler as usize`.
    let f: HciMonitorReplayHandler =
        unsafe { core::mem::transmute::<usize, HciMonitorReplayHandler>(h) };
    f()
}

/// Power controller `dev` on/off; false for an unknown index/no stack.
pub fn hci_dev_power(dev: u16, on: bool) -> bool {
    let h = HCI_DEV_POWER.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `HciDevPowerHandler as usize`.
    let f: HciDevPowerHandler = unsafe { core::mem::transmute::<usize, HciDevPowerHandler>(h) };
    f(dev, on)
}

/// Asynchronous mgmt event sink. The native stack calls `publish_mgmt_event`
/// (e.g. on controller registration or a settings change); the socket layer
/// installs a sink that fans the event out to subscribed mgmt sockets.
pub type MgmtEventSink = fn(&[u8]);
static MGMT_EVENT_SINK: AtomicUsize = AtomicUsize::new(0);

/// Install the mgmt-event fan-out (the socket layer's broadcaster), returning
/// the previously installed one so a test can restore it afterward.
pub fn install_mgmt_event_sink(sink: MgmtEventSink) -> Option<MgmtEventSink> {
    let prev = MGMT_EVENT_SINK.swap(sink as usize, Ordering::AcqRel);
    if prev == 0 {
        None
    } else {
        // SAFETY: only ever stored as `MgmtEventSink as usize`.
        Some(unsafe { core::mem::transmute::<usize, MgmtEventSink>(prev) })
    }
}

/// Deliver an already-framed mgmt event to every subscribed mgmt socket.
/// A no-op until the socket layer has installed its sink.
pub fn publish_mgmt_event(event: &[u8]) {
    let h = MGMT_EVENT_SINK.load(Ordering::Acquire);
    if h == 0 {
        return;
    }
    // SAFETY: only ever stored as `MgmtEventSink as usize`.
    let f: MgmtEventSink = unsafe { core::mem::transmute::<usize, MgmtEventSink>(h) };
    f(event);
}

// ── L2CAP / RFCOMM channel-socket bridge (issue #814) ───────────────
//
// The socket layer (narf-userspace) cannot depend on narf-bluetooth
// (that would cycle through narf-audio), so the channel operations
// the pump owns are exposed here as fn pointers installed by
// narf-bluetooth at bring-up, in the same shape as the mgmt/HCI
// handlers above. Every forward returns the "no stack" value when
// nothing is installed, so a socket op on a stack-less boot fails
// closed instead of touching an absent pump.

/// Outcome of registering a PSM for a listening L2CAP socket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtRegisterStatus {
    /// The PSM is now served by the generic staging server.
    Registered,
    /// An in-kernel service (SDP/RFCOMM) or another listener already
    /// owns this PSM.
    InUse,
    /// No pump exists for this controller index.
    NoPump,
}

/// Errors sending on an L2CAP/RFCOMM channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtSendError {
    /// No pump exists for this controller index.
    NoPump,
    /// A pump step currently owns the core; retry after the step.
    Busy,
    /// No such open channel (closed by the peer, or never opened).
    NoChannel,
    /// LE CoC peer-credit budget exhausted; retry after the peer
    /// grants Flow Control Credit.
    NoCredits,
    /// SDU larger than the peer's MTU (LE CoC).
    TooBig,
    /// Channel belongs to an in-kernel service (SDP/RFCOMM), not a
    /// socket — use the service path, not `send`.
    WrongService,
}

/// One pending channel, as claimed by `accept`: ACL handle, our local
/// CID, the peer's CID, and the peer address (`[type, bdaddr...]`).
pub type BtPendingChannel = (u16, u16, u16, [u8; 7]);
/// One pending RFCOMM DLC, as claimed by `accept`: ACL handle, our
/// local CID, the peer's CID, the DLCI, and the peer address.
pub type BtPendingRfcomm = (u16, u16, u16, u8, [u8; 7]);

pub type BtRegisterPsmHandler = fn(dev: u16, psm: u16, le: bool) -> BtRegisterStatus;
pub type BtUnregisterPsmHandler = fn(dev: u16, psm: u16, le: bool);
pub type BtTakePendingChannelHandler = fn(dev: u16, psm: u16, le: bool) -> Option<BtPendingChannel>;
pub type BtPendingChannelHandler = fn(dev: u16, psm: u16, le: bool) -> bool;
pub type BtSendChannelHandler =
    fn(dev: u16, handle: u16, cid: u16, payload: &[u8]) -> Result<usize, BtSendError>;
pub type BtDrainChannelHandler = fn(dev: u16, handle: u16, cid: u16) -> Option<Vec<Vec<u8>>>;
pub type BtChannelRxPendingHandler = fn(dev: u16, handle: u16, cid: u16) -> bool;
pub type BtDisconnectChannelHandler = fn(dev: u16, handle: u16, cid: u16) -> bool;
pub type BtTakePendingRfcommHandler = fn(dev: u16, channel: u8) -> Option<BtPendingRfcomm>;
pub type BtPendingRfcommHandler = fn(dev: u16, channel: u8) -> bool;
pub type BtSendRfcommHandler =
    fn(dev: u16, handle: u16, cid: u16, dlci: u8, payload: &[u8]) -> Result<usize, BtSendError>;
pub type BtDrainRfcommHandler =
    fn(dev: u16, handle: u16, cid: u16, dlci: u8) -> Option<Vec<Vec<u8>>>;
pub type BtRfcommRxPendingHandler = fn(dev: u16, handle: u16, cid: u16, dlci: u8) -> bool;
pub type BtCloseRfcommHandler = fn(dev: u16, handle: u16, cid: u16, dlci: u8) -> bool;

static BT_REGISTER_PSM: AtomicUsize = AtomicUsize::new(0);
static BT_UNREGISTER_PSM: AtomicUsize = AtomicUsize::new(0);
static BT_TAKE_PENDING_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static BT_PENDING_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static BT_SEND_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static BT_DRAIN_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static BT_CHANNEL_RX_PENDING: AtomicUsize = AtomicUsize::new(0);
static BT_DISCONNECT_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static BT_TAKE_PENDING_RFCOMM: AtomicUsize = AtomicUsize::new(0);
static BT_PENDING_RFCOMM: AtomicUsize = AtomicUsize::new(0);
static BT_SEND_RFCOMM: AtomicUsize = AtomicUsize::new(0);
static BT_DRAIN_RFCOMM: AtomicUsize = AtomicUsize::new(0);
static BT_RFCOMM_RX_PENDING: AtomicUsize = AtomicUsize::new(0);
static BT_CLOSE_RFCOMM: AtomicUsize = AtomicUsize::new(0);

/// Install the L2CAP channel handlers (narf_bluetooth::pump).
/// Each handler type is distinct, so a swapped argument is a
/// compile error, not a silent misroute.
#[allow(clippy::too_many_arguments)]
pub fn install_bt_l2cap_handlers(
    register: BtRegisterPsmHandler,
    unregister: BtUnregisterPsmHandler,
    take_pending: BtTakePendingChannelHandler,
    pending: BtPendingChannelHandler,
    send: BtSendChannelHandler,
    drain: BtDrainChannelHandler,
    rx_pending: BtChannelRxPendingHandler,
    disconnect: BtDisconnectChannelHandler,
) {
    BT_REGISTER_PSM.store(register as usize, Ordering::Release);
    BT_UNREGISTER_PSM.store(unregister as usize, Ordering::Release);
    BT_TAKE_PENDING_CHANNEL.store(take_pending as usize, Ordering::Release);
    BT_PENDING_CHANNEL.store(pending as usize, Ordering::Release);
    BT_SEND_CHANNEL.store(send as usize, Ordering::Release);
    BT_DRAIN_CHANNEL.store(drain as usize, Ordering::Release);
    BT_CHANNEL_RX_PENDING.store(rx_pending as usize, Ordering::Release);
    BT_DISCONNECT_CHANNEL.store(disconnect as usize, Ordering::Release);
}

/// Install the RFCOMM channel handlers (narf_bluetooth::pump).
pub fn install_bt_rfcomm_handlers(
    take_pending: BtTakePendingRfcommHandler,
    pending: BtPendingRfcommHandler,
    send: BtSendRfcommHandler,
    drain: BtDrainRfcommHandler,
    rx_pending: BtRfcommRxPendingHandler,
    close: BtCloseRfcommHandler,
) {
    BT_TAKE_PENDING_RFCOMM.store(take_pending as usize, Ordering::Release);
    BT_PENDING_RFCOMM.store(pending as usize, Ordering::Release);
    BT_SEND_RFCOMM.store(send as usize, Ordering::Release);
    BT_DRAIN_RFCOMM.store(drain as usize, Ordering::Release);
    BT_RFCOMM_RX_PENDING.store(rx_pending as usize, Ordering::Release);
    BT_CLOSE_RFCOMM.store(close as usize, Ordering::Release);
}

// ── L2CAP / RFCOMM outbound-connect bridge (issue #1532) ───────────
//
// The socket layer's `connect()` reaches the pump's outbound
// channel-open client through these handlers, installed by
// narf-bluetooth at bring-up like the server-side handlers above.
// `psm` is the LE/BR-EDR PSM for L2CAP, or the RFCOMM server
// channel (1..=30) when `rfcomm` is true; `le` is false for
// RFCOMM. `peer` is `[address type, bdaddr...]` (type 0 BR/EDR,
// 1 LE public, 2 LE random).

/// Outcome of one outbound-open poll. `connect` is start-or-poll:
/// the first call starts the open (ACL establishment when needed,
/// then the channel-open exchange) and reports `Pending`; later
/// calls report the live state. `Open` consumes the completed
/// record — a second poll after `Open` finds nothing pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtConnectStatus {
    /// The open is in flight (ACL establishment and/or the
    /// channel-open exchange awaiting the peer's answer).
    Pending,
    /// L2CAP channel open: (ACL handle, local CID, peer CID, peer
    /// address).
    Open(BtPendingChannel),
    /// RFCOMM DLC open: (ACL handle, local CID, peer CID, DLCI,
    /// peer address).
    OpenRfcomm(BtPendingRfcomm),
    /// The peer refused the channel open; the value is the L2CAP
    /// result code (BR/EDR §4.3 / LE CoC §4.23) when the peer sent
    /// one.
    Refused(u16),
    /// The open failed below L2CAP: the ACL link failed, the peer
    /// answered DM to an RFCOMM SABM, or the peer rejected a
    /// signalling command outright (Command Reject).
    Failed,
    /// No pump exists for this controller index.
    NoPump,
    /// A pump step currently owns the core, or the controller's
    /// initiator is busy with another link setup; retry after the
    /// step / link completes. Nothing was started.
    Busy,
    /// BR/EDR only: the peer was never discovered by inquiry, so
    /// the pump has no paging parameters for it (it never guesses
    /// them). Discover the peer first.
    UnknownPeer,
}

pub type BtConnectHandler =
    fn(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> BtConnectStatus;
pub type BtConnectReadyHandler =
    fn(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool;
/// Cancel handler: `true` when an in-flight outbound open was
/// dropped, `false` when nothing was in flight. Matches
/// `narf_bluetooth::pump::cancel_connect`; the other connect handlers
/// carry their results the same way (`BtDisconnectChannelHandler`,
/// `BtCloseRfcommHandler`).
pub type BtCancelConnectHandler =
    fn(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool;

static BT_CONNECT: AtomicUsize = AtomicUsize::new(0);
static BT_CONNECT_READY: AtomicUsize = AtomicUsize::new(0);
static BT_CANCEL_CONNECT: AtomicUsize = AtomicUsize::new(0);

/// Install the outbound-connect handlers (narf_bluetooth::pump).
pub fn install_bt_connect_handlers(
    connect: BtConnectHandler,
    ready: BtConnectReadyHandler,
    cancel: BtCancelConnectHandler,
) {
    BT_CONNECT.store(connect as usize, Ordering::Release);
    BT_CONNECT_READY.store(ready as usize, Ordering::Release);
    BT_CANCEL_CONNECT.store(cancel as usize, Ordering::Release);
}

/// Start (or poll) an outbound L2CAP/RFCOMM channel open to `peer`
/// on controller `dev`. See [`BtConnectStatus`].
pub fn bt_connect(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> BtConnectStatus {
    let h = BT_CONNECT.load(Ordering::Acquire);
    if h == 0 {
        return BtConnectStatus::NoPump;
    }
    // SAFETY: only ever stored as `BtConnectHandler as usize`.
    let f: BtConnectHandler = unsafe { core::mem::transmute::<usize, BtConnectHandler>(h) };
    f(dev, peer, psm, le, rfcomm)
}

/// Whether an outbound open to `peer` has completed and is ready
/// to take (non-consuming peek for poll writability).
pub fn bt_connect_ready(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
    let h = BT_CONNECT_READY.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtConnectReadyHandler as usize`.
    let f: BtConnectReadyHandler =
        unsafe { core::mem::transmute::<usize, BtConnectReadyHandler>(h) };
    f(dev, peer, psm, le, rfcomm)
}

/// Abandon an in-flight outbound open to `peer` (socket close):
/// drop the record and tear down any half-opened channel. No-op
/// when no stack is installed or nothing is in flight. The
/// handler's "anything dropped" result is fire-and-forget here;
/// socket close does not act on it.
pub fn bt_cancel_connect(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) {
    let h = BT_CANCEL_CONNECT.load(Ordering::Acquire);
    if h == 0 {
        return;
    }
    // SAFETY: only ever stored as `BtCancelConnectHandler as usize`.
    let f: BtCancelConnectHandler =
        unsafe { core::mem::transmute::<usize, BtCancelConnectHandler>(h) };
    let _ = f(dev, peer, psm, le, rfcomm);
}

/// Register `psm` on controller `dev`'s pump for a listening socket
/// (`le`: LE CoC PSM vs BR/EDR PSM). `NoPump` when no stack is
/// installed.
pub fn bt_register_psm(dev: u16, psm: u16, le: bool) -> BtRegisterStatus {
    let h = BT_REGISTER_PSM.load(Ordering::Acquire);
    if h == 0 {
        return BtRegisterStatus::NoPump;
    }
    // SAFETY: only ever stored as `BtRegisterPsmHandler as usize`.
    let f: BtRegisterPsmHandler = unsafe { core::mem::transmute::<usize, BtRegisterPsmHandler>(h) };
    f(dev, psm, le)
}

/// Release a PSM registered by [`bt_register_psm`]. No-op when no
/// stack is installed or the PSM is service-owned.
pub fn bt_unregister_psm(dev: u16, psm: u16, le: bool) {
    let h = BT_UNREGISTER_PSM.load(Ordering::Acquire);
    if h == 0 {
        return;
    }
    // SAFETY: only ever stored as `BtUnregisterPsmHandler as usize`.
    let f: BtUnregisterPsmHandler =
        unsafe { core::mem::transmute::<usize, BtUnregisterPsmHandler>(h) };
    f(dev, psm, le)
}

/// Claim the oldest unclaimed channel opened by a peer to `psm` on
/// controller `dev` (`le`: LE CoC vs BR/EDR). `None` when nothing is
/// pending or no stack is installed.
pub fn bt_take_pending_channel(dev: u16, psm: u16, le: bool) -> Option<BtPendingChannel> {
    let h = BT_TAKE_PENDING_CHANNEL.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `BtTakePendingChannelHandler as usize`.
    let f: BtTakePendingChannelHandler =
        unsafe { core::mem::transmute::<usize, BtTakePendingChannelHandler>(h) };
    f(dev, psm, le)
}

/// Whether an unclaimed channel to `psm` is pending on controller
/// `dev` (non-consuming peek for poll/accept readiness).
pub fn bt_pending_channel(dev: u16, psm: u16, le: bool) -> bool {
    let h = BT_PENDING_CHANNEL.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtPendingChannelHandler as usize`.
    let f: BtPendingChannelHandler =
        unsafe { core::mem::transmute::<usize, BtPendingChannelHandler>(h) };
    f(dev, psm, le)
}

/// Send `payload` as one SDU on the open channel (`handle`, `cid`)
/// of controller `dev`. Returns the bytes sent.
pub fn bt_send_channel(
    dev: u16,
    handle: u16,
    cid: u16,
    payload: &[u8],
) -> Result<usize, BtSendError> {
    let h = BT_SEND_CHANNEL.load(Ordering::Acquire);
    if h == 0 {
        return Err(BtSendError::NoPump);
    }
    // SAFETY: only ever stored as `BtSendChannelHandler as usize`.
    let f: BtSendChannelHandler = unsafe { core::mem::transmute::<usize, BtSendChannelHandler>(h) };
    f(dev, handle, cid, payload)
}

/// Drain staged inbound SDUs for the open channel (`handle`, `cid`).
/// `None` when no such channel exists or no stack is installed.
pub fn bt_drain_channel(dev: u16, handle: u16, cid: u16) -> Option<Vec<Vec<u8>>> {
    let h = BT_DRAIN_CHANNEL.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `BtDrainChannelHandler as usize`.
    let f: BtDrainChannelHandler =
        unsafe { core::mem::transmute::<usize, BtDrainChannelHandler>(h) };
    f(dev, handle, cid)
}

/// Whether staged inbound data awaits on the open channel
/// (`handle`, `cid`) — non-consuming peek for poll readability.
pub fn bt_channel_rx_pending(dev: u16, handle: u16, cid: u16) -> bool {
    let h = BT_CHANNEL_RX_PENDING.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtChannelRxPendingHandler as usize`.
    let f: BtChannelRxPendingHandler =
        unsafe { core::mem::transmute::<usize, BtChannelRxPendingHandler>(h) };
    f(dev, handle, cid)
}

/// Tear down the open channel (`handle`, `cid`) on controller `dev`:
/// remove it and send the peer a Disconnection Request. `false` when
/// no stack is installed or no such channel exists.
pub fn bt_disconnect_channel(dev: u16, handle: u16, cid: u16) -> bool {
    let h = BT_DISCONNECT_CHANNEL.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtDisconnectChannelHandler as usize`.
    let f: BtDisconnectChannelHandler =
        unsafe { core::mem::transmute::<usize, BtDisconnectChannelHandler>(h) };
    f(dev, handle, cid)
}

/// Claim the oldest unclaimed RFCOMM DLC opened by a peer to server
/// `channel` on controller `dev`. `None` when nothing is pending or
/// no stack is installed.
pub fn bt_take_pending_rfcomm(dev: u16, channel: u8) -> Option<BtPendingRfcomm> {
    let h = BT_TAKE_PENDING_RFCOMM.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `BtTakePendingRfcommHandler as usize`.
    let f: BtTakePendingRfcommHandler =
        unsafe { core::mem::transmute::<usize, BtTakePendingRfcommHandler>(h) };
    f(dev, channel)
}

/// Whether an unclaimed RFCOMM DLC to server `channel` is pending on
/// controller `dev` (non-consuming peek for poll/accept readiness).
pub fn bt_pending_rfcomm(dev: u16, channel: u8) -> bool {
    let h = BT_PENDING_RFCOMM.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtPendingRfcommHandler as usize`.
    let f: BtPendingRfcommHandler =
        unsafe { core::mem::transmute::<usize, BtPendingRfcommHandler>(h) };
    f(dev, channel)
}

/// Send `payload` as one UIH frame on the open RFCOMM DLC
/// (`handle`, `cid`, `dlci`) of controller `dev`.
pub fn bt_send_rfcomm(
    dev: u16,
    handle: u16,
    cid: u16,
    dlci: u8,
    payload: &[u8],
) -> Result<usize, BtSendError> {
    let h = BT_SEND_RFCOMM.load(Ordering::Acquire);
    if h == 0 {
        return Err(BtSendError::NoPump);
    }
    // SAFETY: only ever stored as `BtSendRfcommHandler as usize`.
    let f: BtSendRfcommHandler = unsafe { core::mem::transmute::<usize, BtSendRfcommHandler>(h) };
    f(dev, handle, cid, dlci, payload)
}

/// Drain staged inbound UIH payloads for the open RFCOMM DLC
/// (`handle`, `cid`, `dlci`). `None` when no such DLC exists or no
/// stack is installed.
pub fn bt_drain_rfcomm(dev: u16, handle: u16, cid: u16, dlci: u8) -> Option<Vec<Vec<u8>>> {
    let h = BT_DRAIN_RFCOMM.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `BtDrainRfcommHandler as usize`.
    let f: BtDrainRfcommHandler = unsafe { core::mem::transmute::<usize, BtDrainRfcommHandler>(h) };
    f(dev, handle, cid, dlci)
}

/// Whether staged inbound data awaits on the open RFCOMM DLC
/// (`handle`, `cid`, `dlci`) — non-consuming peek for poll.
pub fn bt_rfcomm_rx_pending(dev: u16, handle: u16, cid: u16, dlci: u8) -> bool {
    let h = BT_RFCOMM_RX_PENDING.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtRfcommRxPendingHandler as usize`.
    let f: BtRfcommRxPendingHandler =
        unsafe { core::mem::transmute::<usize, BtRfcommRxPendingHandler>(h) };
    f(dev, handle, cid, dlci)
}

/// Close the open RFCOMM DLC (`handle`, `cid`, `dlci`) on controller
/// `dev`: send the peer a DISC and forget the DLC. The L2CAP
/// channel (shared mux) survives. `false` when no stack is installed
/// or no such DLC exists.
pub fn bt_close_rfcomm(dev: u16, handle: u16, cid: u16, dlci: u8) -> bool {
    let h = BT_CLOSE_RFCOMM.load(Ordering::Acquire);
    if h == 0 {
        return false;
    }
    // SAFETY: only ever stored as `BtCloseRfcommHandler as usize`.
    let f: BtCloseRfcommHandler = unsafe { core::mem::transmute::<usize, BtCloseRfcommHandler>(h) };
    f(dev, handle, cid, dlci)
}

/// Channel-event wake sink. The pump publishes whenever a peer opens
/// a socket-claimable channel or stages data on one; the socket
/// layer installs a sink that wakes parked poll/accept waiters
/// (a bare readiness-generation bump — waiters re-run their
/// readiness scan, which peeks the pump). A no-op until installed.
pub type BtChannelEventSink = fn();
static BT_CHANNEL_EVENT_SINK: AtomicUsize = AtomicUsize::new(0);

/// Install the channel-event sink (the socket layer's waker),
/// returning the previously installed one.
pub fn install_bt_channel_sink(sink: BtChannelEventSink) -> Option<BtChannelEventSink> {
    let prev = BT_CHANNEL_EVENT_SINK.swap(sink as usize, Ordering::AcqRel);
    if prev == 0 {
        None
    } else {
        // SAFETY: only ever stored as `BtChannelEventSink as usize`.
        Some(unsafe { core::mem::transmute::<usize, BtChannelEventSink>(prev) })
    }
}

/// Publish a channel event to the installed sink. No-op until the
/// socket layer has installed one.
pub fn publish_bt_channel_event() {
    let h = BT_CHANNEL_EVENT_SINK.load(Ordering::Acquire);
    if h == 0 {
        return;
    }
    // SAFETY: only ever stored as `BtChannelEventSink as usize`.
    let f: BtChannelEventSink = unsafe { core::mem::transmute::<usize, BtChannelEventSink>(h) };
    f()
}
