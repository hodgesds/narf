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
