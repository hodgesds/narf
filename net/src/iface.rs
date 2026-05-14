//! Lightweight per-interface registry used by the kernel-side TCP
//! stack. NIC drivers register a `(mac, send_fn)` pair at probe
//! time; the stack uses the registered iface to push outbound
//! Ethernet frames and to learn the local MAC for ARP.
//!
//! Stage-1: single global iface keyed by name. Multi-NIC routing
//! lands when a real consumer needs it.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Function pointer the driver supplies to send a single Ethernet
/// frame. Returns Ok on enqueue, Err on driver failure.
pub type SendFn = fn(&[u8]) -> Result<(), ()>;

#[derive(Debug)]
pub struct NetIfaceEntry {
    pub name: String,
    pub mac: [u8; 6],
    pub send: SendFn,
    /// IPv4 address assigned to the interface (host byte order in
    /// [u8; 4]). Populated by the static config at boot — no DHCP
    /// today.
    pub ipv4: [u8; 4],
    /// Default gateway. Used for any non-on-link destination.
    pub gateway: [u8; 4],
}

static IFACES: IrqSafeSpinLock<Option<Vec<NetIfaceEntry>>> = IrqSafeSpinLock::new(None);

/// Default IP / gateway for the QEMU user-net topology — Stage-1
/// hard-codes these so a freshly-booted NARF can talk out without
/// DHCP. Override at boot via `set_default_ipv4` if the actual
/// network differs.
pub const QEMU_DEFAULT_IP: [u8; 4] = [10, 0, 2, 15];
pub const QEMU_DEFAULT_GW: [u8; 4] = [10, 0, 2, 2];

/// Register a NIC driver as a network interface. Called from the
/// driver's probe path.
pub fn register(name: &str, mac: [u8; 6], send: SendFn) {
    let mut g = IFACES.lock();
    let v = g.get_or_insert_with(Vec::new);
    // De-dup: if a same-named iface exists, replace it.
    v.retain(|i| i.name != name);
    v.push(NetIfaceEntry {
        name: alloc::string::String::from(name),
        mac,
        send,
        ipv4: QEMU_DEFAULT_IP,
        gateway: QEMU_DEFAULT_GW,
    });
}

/// Number of registered interfaces.
pub fn count() -> usize {
    IFACES.lock().as_ref().map(|v| v.len()).unwrap_or(0)
}

/// Find the first registered interface (Stage-1: there's at most
/// one; multi-iface routing wants the destination IP to pick).
pub fn primary() -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = g.as_ref()?;
    let e = v.first()?;
    Some(NetIfaceSnapshot {
        name: e.name.clone(),
        mac: e.mac,
        send: e.send,
        ipv4: e.ipv4,
        gateway: e.gateway,
    })
}

/// Send a complete Ethernet frame through the primary iface.
/// Returns Err if no iface is registered or the driver failed.
pub fn send(frame: &[u8]) -> Result<(), ()> {
    let send_fn = {
        let g = IFACES.lock();
        let v = g.as_ref().ok_or(())?;
        let e = v.first().ok_or(())?;
        e.send
    };
    send_fn(frame)
}

/// Owned-by-value snapshot of a NetIfaceEntry. Used to avoid
/// holding the IFACES lock while rendering / sending.
#[derive(Clone, Debug)]
pub struct NetIfaceSnapshot {
    pub name: String,
    pub mac: [u8; 6],
    pub send: SendFn,
    pub ipv4: [u8; 4],
    pub gateway: [u8; 4],
}

/// Replace the IPv4 / gateway pair on the primary iface (boot-time
/// static config). No-op if no iface is registered.
pub fn set_default_ipv4(ipv4: [u8; 4], gateway: [u8; 4]) {
    let mut g = IFACES.lock();
    if let Some(v) = g.as_mut() {
        if let Some(e) = v.first_mut() {
            e.ipv4 = ipv4;
            e.gateway = gateway;
        }
    }
}

// ── RX dispatch hook ────────────────────────────────────────────
//
// Drivers call `on_rx_frame(bytes)` from their RX-pump task; we
// route by ethertype to the registered handler. Initial handlers
// (ARP, IPv4) are wired by `tcp_stack::init`; the registry uses
// fn-pointer slots so the dep direction stays one-way (drivers →
// net → stack).

type RxHandler = fn(&[u8]);

static RX_HANDLER: AtomicUsize = AtomicUsize::new(0);

pub fn install_rx_handler(h: RxHandler) {
    RX_HANDLER.store(h as usize, Ordering::Release);
}

pub fn on_rx_frame(frame: &[u8]) {
    let v = RX_HANDLER.load(Ordering::Acquire);
    if v == 0 {
        return;
    }
    let h: RxHandler = unsafe { core::mem::transmute(v) };
    h(frame);
}

// ── RX drain hook ───────────────────────────────────────────────
//
// Kernel busy-wait paths in `tcp_stack::arp_resolve` / `connect`
// run inside a syscall handler (i.e. inside `UserTaskFuture::poll`).
// While they're spinning, the executor cannot poll any other
// task, so the spawned RX-pump task is frozen. This hook lets the
// busy-waiter pull frames out of the NIC ring directly each
// iteration so inbound replies actually reach the dispatch.

type DrainFn = fn() -> bool;

static DRAIN_FN: AtomicUsize = AtomicUsize::new(0);

pub fn install_rx_drain(f: DrainFn) {
    DRAIN_FN.store(f as usize, Ordering::Release);
}

/// Drain-one-frame step. Returns true iff a frame was processed.
pub fn drain_pump() -> bool {
    let v = DRAIN_FN.load(Ordering::Acquire);
    if v == 0 {
        return false;
    }
    let f: DrainFn = unsafe { core::mem::transmute(v) };
    f()
}
