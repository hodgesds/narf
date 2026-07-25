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
    pub mtu: u32,
    pub link_up: bool,
    /// Owning network namespace. Zero is the initial namespace.
    pub net_ns_id: u64,
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
        mtu: 1500,
        link_up: true,
        net_ns_id: 0,
    });
}

/// Number of registered interfaces.
pub fn count() -> usize {
    IFACES.lock().as_ref().map(|v| v.len()).unwrap_or(0)
}

/// Per-interface counter snapshot for `/proc/net/dev`. NARF
/// drivers don't yet report their RX/TX statistics into a central
/// counter table — when they do, this snapshot will pick them up.
/// Until then we emit zeros for every counter so unmodified
/// `ifconfig` / `ip -s link` parsers still print a coherent row.
#[derive(Clone, Debug)]
pub struct IfaceCounterSnapshot {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub rx_fifo: u64,
    pub rx_frame: u64,
    pub rx_compressed: u64,
    pub rx_multicast: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
    pub tx_fifo: u64,
    pub tx_colls: u64,
    pub tx_carrier: u64,
    pub tx_compressed: u64,
}

/// Snapshot every registered interface's name + counters.
pub fn snapshot_counters() -> Vec<IfaceCounterSnapshot> {
    let g = IFACES.lock();
    let v = match g.as_ref() {
        Some(v) => v,
        None => return Vec::new(),
    };
    v.iter()
        .map(|e| IfaceCounterSnapshot {
            name: e.name.clone(),
            rx_bytes: 0,
            rx_packets: 0,
            rx_errs: 0,
            rx_drop: 0,
            rx_fifo: 0,
            rx_frame: 0,
            rx_compressed: 0,
            rx_multicast: 0,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errs: 0,
            tx_drop: 0,
            tx_fifo: 0,
            tx_colls: 0,
            tx_carrier: 0,
            tx_compressed: 0,
        })
        .collect()
}

/// Snapshot EVERY registered interface, by value. Used by the rtnetlink
/// dump responder (RTM_GETLINK / RTM_GETADDR) to enumerate the NICs it
/// describes to systemd-udevd / `ip link`. Order matches registration
/// order, which the dump maps to synthetic ifindex 2, 3, … (ifindex 1 is
/// the synthetic loopback the responder always prepends).
pub fn snapshot_all() -> Vec<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = match g.as_ref() {
        Some(v) => v,
        None => return Vec::new(),
    };
    v.iter()
        .map(|e| NetIfaceSnapshot {
            name: e.name.clone(),
            mac: e.mac,
            send: e.send,
            ipv4: e.ipv4,
            gateway: e.gateway,
            mtu: e.mtu,
            link_up: e.link_up,
            net_ns_id: e.net_ns_id,
        })
        .collect()
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
        mtu: e.mtu,
        link_up: e.link_up,
        net_ns_id: e.net_ns_id,
    })
}

/// Look up a registered interface by name. Returns `None` if the
/// registry is empty or no entry matches. Used by tests + admin
/// callers that need to address a specific NIC; the routing layer
/// still picks via `primary` for outbound frames today.
pub fn lookup(name: &str) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = g.as_ref()?;
    let e = v.iter().find(|e| e.name == name)?;
    Some(NetIfaceSnapshot {
        name: e.name.clone(),
        mac: e.mac,
        send: e.send,
        ipv4: e.ipv4,
        gateway: e.gateway,
        mtu: e.mtu,
        link_up: e.link_up,
        net_ns_id: e.net_ns_id,
    })
}

/// Find the registered interface that OWNS the given IPv4 address (its
/// primary `ipv4`). Used by the ARP responder so a request for a NIC's
/// address is answered by THAT NIC's MAC — not always `primary()`,
/// which is merely the first-registered iface and may carry no / a
/// different address (e.g. when a second NIC registered ahead of the
/// configured one).
pub fn for_local_addr(ip: [u8; 4]) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = g.as_ref()?;
    let e = v.iter().find(|e| e.ipv4 == ip)?;
    Some(NetIfaceSnapshot {
        name: e.name.clone(),
        mac: e.mac,
        send: e.send,
        ipv4: e.ipv4,
        gateway: e.gateway,
        mtu: e.mtu,
        link_up: e.link_up,
        net_ns_id: e.net_ns_id,
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

/// First interface visible in `net_ns_id`.
pub fn primary_in(net_ns_id: u64) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let entry = g
        .as_ref()?
        .iter()
        .find(|entry| entry.net_ns_id == net_ns_id)?;
    Some(snapshot(entry))
}

/// Look up an interface only when it belongs to `net_ns_id`.
pub fn lookup_in(net_ns_id: u64, name: &str) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let entry = g
        .as_ref()?
        .iter()
        .find(|entry| entry.net_ns_id == net_ns_id && entry.name == name)?;
    Some(snapshot(entry))
}

/// Move an interface between network namespaces. Callers must gate this with
/// the interface's live `AdminHandle`; this primitive only changes ownership.
pub(crate) fn set_net_ns(name: &str, net_ns_id: u64) -> bool {
    let mut g = IFACES.lock();
    let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|entry| entry.name == name))
    else {
        return false;
    };
    entry.net_ns_id = net_ns_id;
    crate::route::move_iface_routes(name, net_ns_id);
    true
}

/// Pick the egress iface for a destination IPv4 address by consulting
/// the FIB and falling back to `primary()`. The returned snapshot is
/// what TCP / UDP / ICMP send paths use to stamp the source MAC and
/// dispatch the frame so each flow exits on the correct NIC instead
/// of always the first-registered one.
pub fn for_dst(dst: [u8; 4]) -> Option<NetIfaceSnapshot> {
    for_dst_in(0, dst)
}

pub fn for_dst_in(net_ns_id: u64, dst: [u8; 4]) -> Option<NetIfaceSnapshot> {
    if let Some(r) = crate::route::route_lookup_in(net_ns_id, crate::ipv4::Ipv4Addr(dst)) {
        if let Some(s) = lookup_in(net_ns_id, &r.iface) {
            return Some(s);
        }
    }
    primary_in(net_ns_id)
}

/// Send a complete Ethernet frame through the iface chosen by
/// `for_dst(dst_ip)`. Returns Err if no iface is registered or the
/// driver failed.
pub fn send_for_dst(dst: [u8; 4], frame: &[u8]) -> Result<(), ()> {
    let send_fn = for_dst(dst).ok_or(())?.send;
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
    pub mtu: u32,
    pub link_up: bool,
    pub net_ns_id: u64,
}

fn snapshot(entry: &NetIfaceEntry) -> NetIfaceSnapshot {
    NetIfaceSnapshot {
        name: entry.name.clone(),
        mac: entry.mac,
        send: entry.send,
        ipv4: entry.ipv4,
        gateway: entry.gateway,
        mtu: entry.mtu,
        link_up: entry.link_up,
        net_ns_id: entry.net_ns_id,
    }
}

pub fn set_link_state(name: &str, up: bool) -> bool {
    let mut g = IFACES.lock();
    let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|iface| iface.name == name))
    else {
        return false;
    };
    entry.link_up = up;
    true
}

pub fn set_mtu(name: &str, mtu: u32) -> bool {
    let mut g = IFACES.lock();
    let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|iface| iface.name == name))
    else {
        return false;
    };
    entry.mtu = mtu;
    true
}

pub fn set_mac(name: &str, mac: [u8; 6]) -> bool {
    let mut g = IFACES.lock();
    let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|iface| iface.name == name))
    else {
        return false;
    };
    entry.mac = mac;
    true
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

/// Replace the IPv4 / gateway pair on a named iface. Wave-47: the
/// per-flow `for_dst` path stamps src-IP from `NetIfaceSnapshot::ipv4`,
/// so multi-iface tests (and any future multi-NIC bring-up) need a
/// per-iface setter rather than `set_default_ipv4`, which only touches
/// the first-registered entry.
pub fn set_iface_ipv4(name: &str, ipv4: [u8; 4], gateway: [u8; 4]) {
    let mut g = IFACES.lock();
    if let Some(v) = g.as_mut() {
        if let Some(e) = v.iter_mut().find(|e| e.name == name) {
            e.ipv4 = ipv4;
            e.gateway = gateway;
        }
    }
}

// ── Per-interface address management ───────────────────────────────────
//
// These functions forward to `ifaddr` and `route` to keep iface.rs as
// the single external API entry point for NIC-level configuration.

/// Add an IPv4 address (with CIDR prefix length) to the named interface.
/// Automatically installs a connected subnet route. Idempotent.
pub fn add_addr(iface_name: &str, addr: [u8; 4], prefix_len: u8) {
    crate::ifaddr::iface_add_addr(iface_name, crate::ipv4::Ipv4Addr(addr), prefix_len);
}

/// Remove an IPv4 address from the named interface.
pub fn del_addr(iface_name: &str, addr: [u8; 4], prefix_len: u8) {
    crate::ifaddr::iface_del_addr(iface_name, crate::ipv4::Ipv4Addr(addr), prefix_len);
}

/// Return all IPv4 addresses assigned to the named interface as a
/// `Vec<(Ipv4Addr, prefix_len)>`.
pub fn get_addrs(iface_name: &str) -> alloc::vec::Vec<(crate::ipv4::Ipv4Addr, u8)> {
    crate::ifaddr::iface_addrs(iface_name)
        .into_iter()
        .map(|ia| (ia.addr, ia.prefix_len))
        .collect()
}

/// Install the iface's default gateway as a route (0.0.0.0/0 via
/// gateway). Called by boot-time static config or DHCP ACK.
pub fn set_gateway(iface_name: &str, gateway: [u8; 4]) {
    use crate::ipv4::Ipv4Addr;
    use crate::route::{Ipv4Net, Route, Scope, TABLE_MAIN};
    crate::route::route_add(Route {
        net_ns_id: lookup(iface_name).map_or(0, |iface| iface.net_ns_id),
        dst: Ipv4Net {
            addr: Ipv4Addr([0, 0, 0, 0]),
            prefix_len: 0,
        },
        gateway: Some(Ipv4Addr(gateway)),
        iface: alloc::string::String::from(iface_name),
        src_hint: None,
        metric: 100,
        scope: Scope::Universe,
        table: TABLE_MAIN,
    });
}

// ── RX dispatch hook ────────────────────────────────────────────
//
// Drivers call `on_rx_frame(bytes)` from their RX-pump task; we
// route by ethertype to the registered handler. Initial handlers
// (ARP, IPv4) are wired by `tcp_stack::init`; the registry uses
// fn-pointer slots so the dep direction stays one-way (drivers →
// net → stack).

// The RX handler carries the INGRESS iface name so the dispatch can
// answer ARP / route replies out the NIC a frame actually arrived on —
// essential with multiple NICs on overlapping subnets (e.g. two QEMU
// user-mode NICs both at 10.0.2.0/24), where a global address lookup
// would otherwise reply out the wrong NIC. `""` means "ingress unknown".
type RxHandler = fn(&str, &[u8]);

static RX_HANDLER: AtomicUsize = AtomicUsize::new(0);

pub fn install_rx_handler(h: RxHandler) {
    RX_HANDLER.store(h as usize, Ordering::Release);
}

/// Dispatch a frame received on a known ingress interface.
pub fn on_rx_frame_from(iface_name: &str, frame: &[u8]) {
    let v = RX_HANDLER.load(Ordering::Acquire);
    if v == 0 {
        return;
    }
    // SAFETY: `v` is non-zero (checked above) and was produced by
    // `install_rx_handler`, which stores exactly `h as usize` for a live
    // `RxHandler` fn pointer (pointer-sized), so reconstituting it from that
    // same `usize` yields the original valid, callable function pointer. The
    // `Acquire`/`Release` pairing guarantees we observe the written pointer.
    // SAFETY: Valid memory or trusted environment
    let h: RxHandler = unsafe { core::mem::transmute::<usize, RxHandler>(v) };
    h(iface_name, frame);
}

/// Dispatch a frame whose ingress iface is unknown (legacy callers).
pub fn on_rx_frame(frame: &[u8]) {
    on_rx_frame_from("", frame);
}

// ── RX drain hook ───────────────────────────────────────────────
//
// Kernel busy-wait paths in `tcp_stack::arp_resolve` / `connect`
// run inside a syscall handler (i.e. inside `UserTaskFuture::poll`).
// While they're spinning, the executor cannot poll any other
// task, so the spawned RX-pump task is frozen. This hook lets the
// busy-waiter pull frames out of the NIC ring directly each
// iteration so inbound replies actually reach the dispatch.
//
// Why a Vec instead of a single AtomicUsize slot: with both
// virtio-net and e1000 attached (the standard test profile), each
// driver registers its own drain at probe. A single-slot store
// silently overwrites the earlier registration, so the busy-wait
// drains only one NIC and replies arriving on the other ring
// stall until the async forwarder gets CPU again — which never
// happens while the syscall is parked. Fan-out per tick keeps
// every NIC's ring serviced regardless of probe order.

type DrainFn = fn() -> bool;

static DRAIN_FNS: IrqSafeSpinLock<Vec<DrainFn>> = IrqSafeSpinLock::new(Vec::new());

pub fn install_rx_drain(f: DrainFn) {
    let mut g = DRAIN_FNS.lock();
    // De-dup: a driver re-probing shouldn't double-register and
    // double-poll the same ring.
    if !g.iter().any(|&existing| existing as usize == f as usize) {
        g.push(f);
    }
}

/// Drain-one-frame step across every registered NIC. Returns true
/// iff any drain produced a frame. We snapshot the fn list under
/// the lock and release before invoking so a drain callback can
/// safely re-enter the registry (e.g. to register another iface).
pub fn drain_pump() -> bool {
    let fns: Vec<DrainFn> = DRAIN_FNS.lock().clone();
    let mut any = false;
    for f in fns {
        if f() {
            any = true;
        }
    }
    any
}
