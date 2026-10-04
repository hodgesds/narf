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

/// Duplex state reported by a physical driver. `None` in snapshots means the
/// driver has no authoritative link-mode sample.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkDuplex {
    Half,
    Full,
}

#[derive(Clone, Debug)]
pub struct NetIfaceEntry {
    pub name: String,
    pub mac: [u8; 6],
    pub send: SendFn,
    /// The interface's primary IPv4 address (the stack's source address),
    /// `0.0.0.0` while it has none. [`add_addr`] / [`del_addr`] keep it on
    /// the first address configured, as Linux's primary `ifa_list` entry.
    pub ipv4: [u8; 4],
    /// Default gateway recorded by the in-kernel DHCP client / static config.
    pub gateway: [u8; 4],
    pub mtu: u32,
    /// Administratively up (IFF_UP). Physical carrier is tracked separately.
    pub link_up: bool,
    /// Owning network namespace. Zero is the initial namespace.
    pub net_ns_id: u64,
    /// Linux ifindex, fixed at registration (`dev_new_index`): `lo` is 1, the
    /// rest take the next unused number and keep it for their lifetime, so
    /// unregistering one device never renumbers another.
    pub ifindex: u32,
    /// What `ETHTOOL_GDRVINFO` reports: the driver's Linux name (`e1000`,
    /// `virtio_net`), its version string if it sets one (else the kernel
    /// release is reported), and the parent device's name (the PCI address).
    /// Empty `driver` = no driver info (Linux answers -EOPNOTSUPP).
    pub driver: &'static str,
    pub driver_version: Option<&'static str>,
    pub bus_info: String,
    /// `dev->promiscuity`: references taken by `dev_set_promiscuity`.
    pub promiscuity: u32,
    /// `dev->allmulti`: references taken by `dev_set_allmulti`.
    pub allmulti: u32,
    /// `dev->mc` / `dev->uc`: hardware addresses added by `dev_mc_add` /
    /// `dev_uc_add`, each with its reference count.
    pub hw_addrs: Vec<HwAddr>,
    /// Linux net-device metadata owned by the control plane rather than by
    /// sysfs.  Values are initialized with `register_netdevice` semantics and
    /// snapshots render this state verbatim.
    pub name_assign_type: u8,
    pub addr_assign_type: u8,
    pub dev_id: u32,
    pub dev_port: u32,
    pub link_mode: u8,
    pub netdev_group: u32,
    pub dormant: bool,
    pub testing: bool,
    pub ifalias: String,
    pub tx_queue_len: u32,
    pub gro_flush_timeout_ns: u64,
    pub napi_defer_hard_irqs: u32,
    pub proto_down: bool,
    pub threaded: bool,
    /// Physical carrier/link-mode state, distinct from administrative
    /// `link_up` (IFF_UP). Drivers update it from hardware observations.
    pub carrier: bool,
    pub carrier_changes: u32,
    pub carrier_up_count: u32,
    pub carrier_down_count: u32,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<LinkDuplex>,
    /// Authoritative software-path counters shared by sysfs, procfs, and
    /// rtnetlink. Driver-specific error paths can add to these through the
    /// accounting helpers below as they gain detailed hardware reporting.
    pub stats: IfaceCounterSnapshot,
}

/// One `netdev_hw_addr` on a device's multicast or unicast list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwAddr {
    pub addr: [u8; 6],
    pub unicast: bool,
    pub refcount: u32,
}

/// Record `ETHTOOL_GDRVINFO` data for interface `name` (see
/// [`NetIfaceEntry::driver`]). Drivers call this right after [`register`].
pub fn set_driver_info(
    name: &str,
    driver: &'static str,
    driver_version: Option<&'static str>,
    bus_info: String,
) {
    if let Some(entry) = IFACES
        .lock()
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|entry| entry.name == name))
    {
        entry.driver = driver;
        entry.driver_version = driver_version;
        entry.bus_info = bus_info;
    }
}

/// `ETHTOOL_GDRVINFO` data for `name`: `(driver, version, bus_info)`, or
/// `None` when the device has none (`lo`).
pub fn driver_info(name: &str) -> Option<(&'static str, Option<&'static str>, String)> {
    let g = IFACES.lock();
    let entry = g.as_ref()?.iter().find(|entry| entry.name == name)?;
    (!entry.driver.is_empty()).then(|| (entry.driver, entry.driver_version, entry.bus_info.clone()))
}

/// Next ifindex to hand out (`dev_new_index`). 1 is reserved for `lo`.
static NEXT_IFINDEX: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);

/// Ifindexes of devices that exist only in the frame-ring registry (they
/// never call [`register`]), allocated from the same counter on first sight.
static REGISTRY_IFINDEX: IrqSafeSpinLock<alloc::collections::BTreeMap<String, u32>> =
    IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

/// The ifindex of a device known only by name to the frame-ring registry:
/// its registered ifindex if it has one, else one allocated once and kept.
pub fn stable_ifindex(name: &str) -> u32 {
    if let Some(ifindex) = ifindex_of(name) {
        return ifindex;
    }
    *REGISTRY_IFINDEX
        .lock()
        .entry(String::from(name))
        .or_insert_with(|| NEXT_IFINDEX.fetch_add(1, Ordering::Relaxed))
}

/// Names handed out by [`reserve_name`] that are not registered yet. They
/// count as taken for [`alloc_name`].
static RESERVED: IrqSafeSpinLock<Vec<String>> = IrqSafeSpinLock::new(Vec::new());

/// Linux `dev_alloc_name`: a name containing `%d` takes the lowest number not
/// already used by a registered or reserved device; any other name is used
/// as-is.
fn alloc_name(ifaces: &[NetIfaceEntry], reserved: &[String], pattern: &str) -> String {
    let Some((prefix, suffix)) = pattern.split_once("%d") else {
        return String::from(pattern);
    };
    (0u32..)
        .map(|n| alloc::format!("{prefix}{n}{suffix}"))
        .find(|candidate| {
            ifaces.iter().all(|entry| entry.name != *candidate)
                && reserved.iter().all(|name| name != candidate)
        })
        .unwrap_or_default()
}

/// Allocate a device name (`dev_alloc_name`) for a driver that needs it
/// before it calls [`register`] — Linux names a `net_device` when it is set
/// up, before `register_netdevice`. The name is held until registered.
pub fn reserve_name(pattern: &str) -> &'static str {
    let g = IFACES.lock();
    let mut reserved = RESERVED.lock();
    let name = alloc_name(g.as_deref().unwrap_or(&[]), &reserved, pattern);
    reserved.push(name.clone());
    alloc::boxed::Box::leak(name.into_boxed_str())
}

/// [`register`] for a driver that keeps its device name for the kernel's
/// lifetime: returns it as a `&'static str`.
pub fn register_static(pattern: &str, mac: [u8; 6], send: SendFn) -> &'static str {
    alloc::boxed::Box::leak(register(pattern, mac, send).into_boxed_str())
}

/// Hook into procfs for publishing an interface's `net.ipv4.conf.<dev>.*`
/// keys. Installed by `frame::cross_crate_init`, because `narf-net` cannot
/// see `narf-filesystem` — the same seam the `/proc/net/*` renderers use,
/// pointing the other way: here the net stack notifies procfs rather than
/// procfs pulling a snapshot.
///
/// Zero means nothing is installed, which is the normal state in unit tests
/// and before procfs is up. Registration is then simply skipped; the
/// per-interface values still live in `narf_lib::sysctl` and the datapath
/// still honours them, so only the /proc files are missing.
/// There is no companion unregister hook because NARF has no interface
/// removal path — `register` replaces a same-named entry in place, and
/// re-registering refreshes rather than duplicates.
static DEV_CONF_HOOK: AtomicUsize = AtomicUsize::new(0);

/// `fn(iface_name)` — publish an interface's conf keys.
pub type DevConfFn = fn(&str);

/// Install the procfs registration hook. Idempotent.
pub fn install_dev_conf_hook(register: DevConfFn) {
    DEV_CONF_HOOK.store(register as usize, Ordering::Release);
}

fn dev_conf_register(iface_name: &str) {
    let v = DEV_CONF_HOOK.load(Ordering::Acquire);
    if v == 0 {
        // No procfs yet — still seed the value so the datapath has one.
        narf_lib::sysctl::ipv4::init_device_conf(iface_name);
        return;
    }
    // SAFETY: v was stored by install_dev_conf_hooks as a DevConfFn
    // fn-pointer; non-zero confirms it.
    let f: DevConfFn = unsafe { core::mem::transmute(v) };
    f(iface_name);
}

static IFACES: IrqSafeSpinLock<Option<Vec<NetIfaceEntry>>> = IrqSafeSpinLock::new(None);

/// Loopback transmit: a frame sent on "lo" is immediately received on
/// "lo". Linux does the same thing — `loopback_xmit` hands the skb straight
/// to `netif_rx` rather than to any hardware.
///
/// The reentrancy guard is the part that is not optional. `rx_handler` can
/// answer a frame with another frame (a TCP ACK, an ICMP reply), and that
/// answer routes back to lo and re-enters here. Linux breaks the chain by
/// queueing to a softirq; NARF delivers inline, so without a guard a
/// request/reply exchange recurses until the kernel stack is gone. One level
/// in flight is enough for the deliver-and-reply pattern; anything deeper is
/// a loop, and dropping is what Linux's backlog overflow does too.
///
/// The guard is PER-CPU. Recursion is a property of one call stack, so a
/// single global flag would make two CPUs transmitting on lo at the same
/// time drop each other's frames — turning an unrelated peer's traffic into
/// loss that looks like a network fault. Same shape as the per-CPU staging
/// in `bypass::classifier`.
///
/// The CPU index is read ONCE and used for both the claim and the release:
/// if this task migrates mid-delivery, the release must still clear the flag
/// it actually set, or that CPU is left permanently guarded and silently
/// drops every later loopback frame.
fn lo_send_fn(frame: &[u8]) -> Result<(), ()> {
    use core::sync::atomic::{AtomicBool, Ordering};
    const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;
    static IN_LOOPBACK: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

    let cpu = narf_lib::percpu::current_cpu().min(MAX_CPUS - 1);
    if IN_LOOPBACK[cpu].swap(true, Ordering::AcqRel) {
        return Err(());
    }
    let mut buf = frame.to_vec();
    record_rx_frame("lo", &buf);
    crate::tcp_stack::rx_handler("lo", &mut buf);
    IN_LOOPBACK[cpu].store(false, Ordering::Release);
    Ok(())
}

/// Register the loopback interface in the routing/dispatch registry.
///
/// `narf_net::register_loopback` builds the cap-gated `Loopback` device, but
/// `for_dst` / `lookup_in` — the path TCP, UDP and ICMP use to pick an egress
/// interface — read THIS registry, the one NIC drivers call into. Without an
/// entry here a route to 127.0.0.0/8 resolves to an interface that dispatch
/// cannot find, `for_dst` falls back to `primary_in()`, and a datagram
/// addressed to 127.0.0.1 goes out the physical NIC.
///
/// Idempotent: `register` replaces a same-named entry.
pub fn register_loopback_iface() {
    register("lo", [0u8; 6], lo_send_fn);
    set_iface_ipv4("lo", [127, 0, 0, 1], [0, 0, 0, 0]);
}

/// Register a NIC driver as a network interface. Called from the
/// driver's probe path.
/// Returns the registered name: `name` itself, or for an `eth%d`-style
/// pattern the name `dev_alloc_name` chose. Drivers address their device by
/// the returned name afterwards.
pub fn register(name: &str, mac: [u8; 6], send: SendFn) -> String {
    let enumerated_name = name.contains("%d");
    let mut g = IFACES.lock();
    let v = g.get_or_insert_with(Vec::new);
    let name = {
        let mut reserved = RESERVED.lock();
        let name = alloc_name(v, &reserved, name);
        // Registering a reserved name consumes the reservation.
        reserved.retain(|held| *held != name);
        name
    };
    // De-dup: a same-named iface is replaced, keeping its ifindex and the
    // configuration userspace gave it (admin state, addresses).
    let old = v.iter().find(|i| i.name == name).cloned();
    let ifindex = if name == "lo" {
        1
    } else if let Some(old) = old.as_ref() {
        old.ifindex
    } else {
        NEXT_IFINDEX.fetch_add(1, Ordering::Relaxed)
    };
    // `register_netdevice`: a new device is down (no IFF_UP) and has no
    // address; userspace (NetworkManager, `ip`) or the boot-time IP
    // autoconfiguration brings it up and configures it. NARF's `lo` is the
    // exception: its datapath is permanently up (see `AdminHandle::set_link`).
    let (ipv4, gateway, link_up) = match old.as_ref() {
        Some(old) => (old.ipv4, old.gateway, old.link_up),
        None => ([0; 4], [0; 4], name == "lo"),
    };
    let mtu = old.as_ref().map_or(1500, |old| old.mtu);
    let net_ns_id = old.as_ref().map_or(0, |old| old.net_ns_id);
    let name_assign_type = old.as_ref().map_or_else(
        || {
            if name == "lo" {
                2 // NET_NAME_PREDICTABLE
            } else if enumerated_name {
                1 // NET_NAME_ENUM
            } else {
                0 // NET_NAME_UNKNOWN
            }
        },
        |old| old.name_assign_type,
    );
    let addr_assign_type = old.as_ref().map_or(0, |old| old.addr_assign_type);
    let dev_id = old.as_ref().map_or(0, |old| old.dev_id);
    let dev_port = old.as_ref().map_or(0, |old| old.dev_port);
    let link_mode = old.as_ref().map_or(0, |old| old.link_mode);
    let netdev_group = old.as_ref().map_or(0, |old| old.netdev_group);
    let dormant = old.as_ref().is_some_and(|old| old.dormant);
    let testing = old.as_ref().is_some_and(|old| old.testing);
    let ifalias = old
        .as_ref()
        .map_or_else(String::new, |old| old.ifalias.clone());
    let tx_queue_len = old.as_ref().map_or(1000, |old| old.tx_queue_len);
    let gro_flush_timeout_ns = old.as_ref().map_or(0, |old| old.gro_flush_timeout_ns);
    let napi_defer_hard_irqs = old.as_ref().map_or(0, |old| old.napi_defer_hard_irqs);
    let proto_down = old.as_ref().is_some_and(|old| old.proto_down);
    let threaded = old.as_ref().is_some_and(|old| old.threaded);
    let carrier = old.as_ref().is_some_and(|old| old.carrier) || name == "lo";
    let carrier_changes = old.as_ref().map_or(0, |old| old.carrier_changes);
    let carrier_up_count = old.as_ref().map_or(0, |old| old.carrier_up_count);
    let carrier_down_count = old.as_ref().map_or(0, |old| old.carrier_down_count);
    let speed_mbps = old.as_ref().and_then(|old| old.speed_mbps);
    let duplex = old.as_ref().and_then(|old| old.duplex);
    let stats = old.as_ref().map_or_else(
        || IfaceCounterSnapshot::empty(&name),
        |old| old.stats.clone(),
    );
    let promiscuity = old.as_ref().map_or(0, |old| old.promiscuity);
    let allmulti = old.as_ref().map_or(0, |old| old.allmulti);
    let hw_addrs = old
        .as_ref()
        .map_or_else(Vec::new, |old| old.hw_addrs.clone());
    v.retain(|i| i.name != name);
    v.push(NetIfaceEntry {
        name: name.clone(),
        mac,
        send,
        ipv4,
        gateway,
        mtu,
        link_up,
        net_ns_id,
        ifindex,
        driver: "",
        driver_version: None,
        bus_info: String::new(),
        promiscuity,
        allmulti,
        hw_addrs,
        name_assign_type,
        addr_assign_type,
        dev_id,
        dev_port,
        link_mode,
        netdev_group,
        dormant,
        testing,
        ifalias,
        tx_queue_len,
        gro_flush_timeout_ns,
        napi_defer_hard_irqs,
        proto_down,
        threaded,
        carrier,
        carrier_changes,
        carrier_up_count,
        carrier_down_count,
        speed_mbps,
        duplex,
        stats,
    });
    drop(g);
    // Publish this interface's `net.ipv4.conf.<dev>.*` keys and seed its
    // forwarding value from `conf.default`. Done with IFACES released: the
    // hook reaches into the procfs registry, which must not be entered under
    // this lock.
    dev_conf_register(&name);
    name
}

/// Number of registered interfaces.
pub fn count() -> usize {
    IFACES.lock().as_ref().map(|v| v.len()).unwrap_or(0)
}

/// Per-interface counter snapshot shared by `/proc/net/dev`, net sysfs, and
/// rtnetlink. The common ingress/egress paths update packet and byte totals;
/// detailed driver error counters remain zero until an actual error is
/// reported, rather than being synthesized by a compatibility renderer.
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
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_missed_errors: u64,
    pub tx_aborted_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    pub rx_nohandler: u64,
    pub rx_otherhost_dropped: u64,
}

impl IfaceCounterSnapshot {
    fn empty(name: &str) -> Self {
        Self {
            name: String::from(name),
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
            rx_length_errors: 0,
            rx_over_errors: 0,
            rx_crc_errors: 0,
            rx_missed_errors: 0,
            tx_aborted_errors: 0,
            tx_heartbeat_errors: 0,
            tx_window_errors: 0,
            rx_nohandler: 0,
            rx_otherhost_dropped: 0,
        }
    }
}

/// Snapshot every registered interface's name + counters.
pub fn snapshot_counters() -> Vec<IfaceCounterSnapshot> {
    snapshot_counters_in(0)
}

pub fn snapshot_counters_in(net_ns_id: u64) -> Vec<IfaceCounterSnapshot> {
    let g = IFACES.lock();
    let v = match g.as_ref() {
        Some(v) => v,
        None => return Vec::new(),
    };
    v.iter()
        .filter(|e| e.net_ns_id == net_ns_id)
        .map(|e| e.stats.clone())
        .collect()
}

/// Snapshot EVERY registered interface, by value. Used by the rtnetlink
/// dump responder (RTM_GETLINK / RTM_GETADDR) to enumerate the NICs it
/// describes to systemd-udevd / `ip link`. Order matches registration
/// order, which the dump maps to synthetic ifindex 2, 3, … (ifindex 1 is
/// the synthetic loopback the responder always prepends).
pub fn snapshot_all() -> Vec<NetIfaceSnapshot> {
    snapshot_all_in(0)
}

pub fn snapshot_all_in(net_ns_id: u64) -> Vec<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = match g.as_ref() {
        Some(v) => v,
        None => return Vec::new(),
    };
    v.iter()
        .filter(|e| e.net_ns_id == net_ns_id)
        .map(snapshot)
        .collect()
}

/// Find the first registered interface (Stage-1: there's at most
/// one; multi-iface routing wants the destination IP to pick).
pub fn primary() -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = g.as_ref()?;
    let e = v.first()?;
    Some(snapshot(e))
}

/// Look up a registered interface by name. Returns `None` if the
/// registry is empty or no entry matches. Used by tests + admin
/// callers that need to address a specific NIC; the routing layer
/// still picks via `primary` for outbound frames today.
pub fn lookup(name: &str) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = g.as_ref()?;
    let e = v.iter().find(|e| e.name == name)?;
    Some(snapshot(e))
}

/// Find the registered interface that OWNS the given IPv4 address (its
/// primary `ipv4`). Used by the ARP responder so a request for a NIC's
/// address is answered by THAT NIC's MAC — not always `primary()`,
/// which is merely the first-registered iface and may carry no / a
/// different address (e.g. when a second NIC registered ahead of the
/// configured one).
pub fn for_local_addr(ip: [u8; 4]) -> Option<NetIfaceSnapshot> {
    for_local_addr_in(0, ip)
}

/// Find an interface in `net_ns_id` that owns `ip`.
pub fn for_local_addr_in(net_ns_id: u64, ip: [u8; 4]) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let v = g.as_ref()?;
    let e = v
        .iter()
        .find(|e| e.net_ns_id == net_ns_id && e.ipv4 == ip)?;
    Some(snapshot(e))
}

/// Send a complete Ethernet frame through the primary iface.
/// Returns Err if no iface is registered or the driver failed.
pub fn send(frame: &[u8]) -> Result<(), ()> {
    primary().ok_or(())?.xmit(frame)
}

fn with_stats_mut(name: &str, update: impl FnOnce(&mut IfaceCounterSnapshot)) {
    let mut guard = IFACES.lock();
    if let Some(entry) = guard
        .as_mut()
        .and_then(|entries| entries.iter_mut().find(|entry| entry.name == name))
    {
        update(&mut entry.stats);
    }
}

fn record_tx_result(name: &str, bytes: usize, success: bool) {
    with_stats_mut(name, |stats| {
        if success {
            stats.tx_packets = stats.tx_packets.saturating_add(1);
            stats.tx_bytes = stats.tx_bytes.saturating_add(bytes as u64);
        } else {
            stats.tx_errs = stats.tx_errs.saturating_add(1);
            stats.tx_drop = stats.tx_drop.saturating_add(1);
        }
    });
}

fn record_rx_frame(name: &str, frame: &[u8]) {
    with_stats_mut(name, |stats| {
        stats.rx_packets = stats.rx_packets.saturating_add(1);
        stats.rx_bytes = stats.rx_bytes.saturating_add(frame.len() as u64);
        // Linux's multicast counter excludes the all-ones broadcast address.
        if frame.len() >= 6 && frame[0] & 1 != 0 && frame[..6] != [0xff; 6] {
            stats.rx_multicast = stats.rx_multicast.saturating_add(1);
        }
    });
}

fn record_rx_nohandler(name: &str) {
    with_stats_mut(name, |stats| {
        stats.rx_nohandler = stats.rx_nohandler.saturating_add(1);
    });
}

/// Send a complete Ethernet frame out the interface named `iface_name`.
/// Returns `Err` if no such iface is registered or the driver failed.
///
/// The retransmit primitive behind XDP `XDP_TX` (reflect out the ingress
/// iface) and `XDP_REDIRECT` (send out a target iface). We look the send fn up
/// under the lock and release it before calling — the driver's send path may
/// re-enter the registry, and holding the `IrqSafeSpinLock` across it would
/// deadlock. The classifier is the sole XDP caller and invokes this only after
/// its own `XDP_PROGS` lock is released, so no BPF-side lock is held here.
pub fn send_on(iface_name: &str, frame: &[u8]) -> Result<(), ()> {
    let (send_fn, name) = {
        let g = IFACES.lock();
        let v = g.as_ref().ok_or(())?;
        let e = v.iter().find(|e| e.name == iface_name).ok_or(())?;
        (e.send, e.name.clone())
    };
    let result = send_fn(frame);
    record_tx_result(&name, frame.len(), result.is_ok());
    result
}

/// Send a frame out the interface at synthetic `ifindex`.
///
/// The ifindex space matches the rtnetlink dump responder's: index 1 is the
/// synthetic loopback (nothing to transmit onto — treated as `Err`), and
/// 2, 3, … map to registered interfaces in registration order (the same order
/// [`snapshot_all`] returns). This is the resolution XDP `XDP_REDIRECT` uses to
/// turn a program's `bpf_redirect(ifindex)` into an egress NIC. Returns `Err`
/// if the ifindex names no registered iface or the driver failed.
pub fn send_on_ifindex(ifindex: u32, frame: &[u8]) -> Result<(), ()> {
    let (send_fn, name) = {
        let g = IFACES.lock();
        let v = g.as_ref().ok_or(())?;
        let entry = v.iter().find(|e| e.ifindex == ifindex).ok_or(())?;
        (entry.send, entry.name.clone())
    };
    let result = send_fn(frame);
    record_tx_result(&name, frame.len(), result.is_ok());
    result
}

/// The synthetic ifindex of `iface_name`, in the same space
/// [`send_on_ifindex`] resolves: index 1 is loopback and 2, 3, … are the
/// registered interfaces in registration order. `None` if no interface has that
/// name. Used by XDP `BPF_F_EXCLUDE_INGRESS` to skip the ingress iface in a
/// broadcast fan-out.
#[must_use]
pub fn ifindex_of(iface_name: &str) -> Option<u32> {
    if iface_name == "lo" {
        return Some(1);
    }
    let g = IFACES.lock();
    g.as_ref()?
        .iter()
        .find(|e| e.name == iface_name)
        .map(|e| e.ifindex)
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
    let old_ns = entry.net_ns_id;
    entry.net_ns_id = net_ns_id;
    let moved = snapshot(entry);
    drop(g);
    crate::route::move_iface_routes(name, net_ns_id);
    // `dev_change_net_namespace` unregisters the device from its old
    // namespace (NETDEV_UNREGISTER there).
    if old_ns != net_ns_id {
        crate::raw_sock::netdev_unregister_moved(old_ns, &moved);
    }
    true
}

pub(crate) fn release_namespace(net_ns_id: u64) {
    let names: Vec<String> = {
        let mut interfaces = IFACES.lock();
        let Some(entries) = interfaces.as_mut() else {
            return;
        };
        entries
            .iter_mut()
            .filter(|entry| entry.net_ns_id == net_ns_id)
            .map(|entry| {
                entry.net_ns_id = 0;
                entry.name.clone()
            })
            .collect()
    };
    for name in names {
        crate::route::move_iface_routes(&name, 0);
    }
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
    for_dst(dst).ok_or(())?.xmit(frame)
}

/// Owned-by-value snapshot of a NetIfaceEntry. Used to avoid
/// holding the IFACES lock while rendering / sending.
#[derive(Clone, Debug)]
pub struct NetIfaceSnapshot {
    pub name: String,
    pub mac: [u8; 6],
    /// The driver's transmit hook. Private: every kernel transmit goes
    /// through [`NetIfaceSnapshot::xmit`] so packet taps see it.
    driver_send: SendFn,
    pub ipv4: [u8; 4],
    pub gateway: [u8; 4],
    pub mtu: u32,
    pub link_up: bool,
    pub net_ns_id: u64,
    pub ifindex: u32,
    /// `dev->promiscuity != 0` (`IFF_PROMISC` in `dev->flags`).
    pub promisc: bool,
    /// `dev->allmulti != 0` (`IFF_ALLMULTI` in `dev->flags`).
    pub allmulti: bool,
    pub name_assign_type: u8,
    pub addr_assign_type: u8,
    pub dev_id: u32,
    pub dev_port: u32,
    pub link_mode: u8,
    pub netdev_group: u32,
    pub dormant: bool,
    pub testing: bool,
    pub ifalias: String,
    pub tx_queue_len: u32,
    pub gro_flush_timeout_ns: u64,
    pub napi_defer_hard_irqs: u32,
    pub proto_down: bool,
    pub threaded: bool,
    pub carrier: bool,
    pub carrier_changes: u32,
    pub carrier_up_count: u32,
    pub carrier_down_count: u32,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<LinkDuplex>,
    pub stats: IfaceCounterSnapshot,
}

impl NetIfaceSnapshot {
    /// `dev->type`: `ARPHRD_LOOPBACK` for `lo`, `ARPHRD_ETHER` otherwise.
    #[must_use]
    pub fn hatype(&self) -> u16 {
        if self.ifindex == 1 || self.name == "lo" {
            crate::raw_sock::ARPHRD_LOOPBACK
        } else {
            crate::raw_sock::ARPHRD_ETHER
        }
    }

    /// `dev_queue_xmit`: transmit a complete Ethernet frame the kernel
    /// stack built. `ETH_P_ALL` packet sockets see it first
    /// (`dev_queue_xmit_nit`, `PACKET_OUTGOING`), then the driver sends it.
    pub fn xmit(&self, frame: &[u8]) -> Result<(), ()> {
        crate::raw_sock::dev_queue_xmit_nit(self, frame, crate::raw_sock::tx_protocol(frame), None);
        let result = (self.driver_send)(frame);
        record_tx_result(&self.name, frame.len(), result.is_ok());
        result
    }

    /// `dev_queue_xmit` for a frame a packet socket built: `protocol` is
    /// the `skb->protocol` it set and `origin` the sender, which its own
    /// tap skips (`skb_loop_sk`). A driver refusal models `NET_XMIT_DROP`;
    /// packet_snd translates it to ENOBUFS.
    pub fn xmit_from(
        &self,
        frame: &[u8],
        protocol: u16,
        origin: Option<&crate::raw_sock::PacketSock>,
    ) -> Result<(), ()> {
        crate::raw_sock::dev_queue_xmit_nit(self, frame, protocol, origin);
        let result = (self.driver_send)(frame);
        record_tx_result(&self.name, frame.len(), result.is_ok());
        result
    }

    /// `dev_direct_xmit`: hand the frame straight to the driver, with no
    /// packet taps (`PACKET_QDISC_BYPASS`).
    pub fn xmit_direct(&self, frame: &[u8]) -> Result<(), ()> {
        let result = (self.driver_send)(frame);
        record_tx_result(&self.name, frame.len(), result.is_ok());
        result
    }
}

fn snapshot(entry: &NetIfaceEntry) -> NetIfaceSnapshot {
    NetIfaceSnapshot {
        name: entry.name.clone(),
        mac: entry.mac,
        driver_send: entry.send,
        ipv4: entry.ipv4,
        gateway: entry.gateway,
        mtu: entry.mtu,
        link_up: entry.link_up,
        net_ns_id: entry.net_ns_id,
        ifindex: entry.ifindex,
        promisc: entry.promiscuity != 0,
        allmulti: entry.allmulti != 0,
        name_assign_type: entry.name_assign_type,
        addr_assign_type: entry.addr_assign_type,
        dev_id: entry.dev_id,
        dev_port: entry.dev_port,
        link_mode: entry.link_mode,
        netdev_group: entry.netdev_group,
        dormant: entry.dormant,
        testing: entry.testing,
        ifalias: entry.ifalias.clone(),
        tx_queue_len: entry.tx_queue_len,
        gro_flush_timeout_ns: entry.gro_flush_timeout_ns,
        napi_defer_hard_irqs: entry.napi_defer_hard_irqs,
        proto_down: entry.proto_down,
        threaded: entry.threaded,
        carrier: entry.carrier,
        carrier_changes: entry.carrier_changes,
        carrier_up_count: entry.carrier_up_count,
        carrier_down_count: entry.carrier_down_count,
        speed_mbps: entry.speed_mbps,
        duplex: entry.duplex,
        stats: entry.stats.clone(),
    }
}

/// The interface with `ifindex` in `net_ns_id` (`dev_get_by_index`).
#[must_use]
pub fn by_index_in(net_ns_id: u64, ifindex: u32) -> Option<NetIfaceSnapshot> {
    let g = IFACES.lock();
    let entry = g
        .as_ref()?
        .iter()
        .find(|entry| entry.net_ns_id == net_ns_id && entry.ifindex == ifindex)?;
    Some(snapshot(entry))
}

fn with_dev<R>(net_ns_id: u64, ifindex: u32, f: impl FnOnce(&mut NetIfaceEntry) -> R) -> Option<R> {
    let mut g = IFACES.lock();
    let entry = g
        .as_mut()?
        .iter_mut()
        .find(|entry| entry.net_ns_id == net_ns_id && entry.ifindex == ifindex)?;
    Some(f(entry))
}

/// `dev_set_promiscuity(dev, inc)`. Errors are Linux errnos (positive).
///
/// LINUX-GAP: `__dev_set_rx_mode` / `ndo_set_rx_mode` — NARF NIC drivers do
/// not reprogram their receive filters from this count; only the reference
/// count and `IFF_PROMISC` in `dev->flags` (sysfs `flags`) change.
pub fn dev_set_promiscuity(net_ns_id: u64, ifindex: u32, inc: i32) -> Result<(), i32> {
    with_dev(net_ns_id, ifindex, |e| {
        let next = e.promiscuity.wrapping_add_signed(inc);
        if next == 0 && inc > 0 {
            // "promiscuity touches roof".
            return Err(crate::raw_sock::errno::EOVERFLOW);
        }
        e.promiscuity = next;
        Ok(())
    })
    .unwrap_or(Err(crate::raw_sock::errno::ENODEV))
}

/// `dev_set_allmulti(dev, inc)`; see [`dev_set_promiscuity`] for the
/// driver-programming gap.
pub fn dev_set_allmulti(net_ns_id: u64, ifindex: u32, inc: i32) -> Result<(), i32> {
    with_dev(net_ns_id, ifindex, |e| {
        let next = e.allmulti.wrapping_add_signed(inc);
        if next == 0 && inc > 0 {
            return Err(crate::raw_sock::errno::EOVERFLOW);
        }
        e.allmulti = next;
        Ok(())
    })
    .unwrap_or(Err(crate::raw_sock::errno::ENODEV))
}

/// `dev_mc_add` / `dev_uc_add`: take a reference on a hardware address.
pub fn dev_hw_addr_add(
    net_ns_id: u64,
    ifindex: u32,
    addr: [u8; 6],
    unicast: bool,
) -> Result<(), i32> {
    with_dev(net_ns_id, ifindex, |e| {
        match e
            .hw_addrs
            .iter_mut()
            .find(|h| h.addr == addr && h.unicast == unicast)
        {
            Some(h) => h.refcount += 1,
            None => e.hw_addrs.push(HwAddr {
                addr,
                unicast,
                refcount: 1,
            }),
        }
        Ok(())
    })
    .unwrap_or(Err(crate::raw_sock::errno::ENODEV))
}

/// `dev_mc_del` / `dev_uc_del`: drop a reference; `-ENOENT` when absent.
pub fn dev_hw_addr_del(
    net_ns_id: u64,
    ifindex: u32,
    addr: [u8; 6],
    unicast: bool,
) -> Result<(), i32> {
    with_dev(net_ns_id, ifindex, |e| {
        let Some(pos) = e
            .hw_addrs
            .iter()
            .position(|h| h.addr == addr && h.unicast == unicast)
        else {
            return Err(crate::raw_sock::errno::ENOENT);
        };
        e.hw_addrs[pos].refcount -= 1;
        if e.hw_addrs[pos].refcount == 0 {
            e.hw_addrs.remove(pos);
        }
        Ok(())
    })
    .unwrap_or(Err(crate::raw_sock::errno::ENODEV))
}

/// The hardware addresses on a device's lists (tests and diagnostics).
#[must_use]
pub fn dev_hw_addrs(net_ns_id: u64, ifindex: u32) -> Vec<HwAddr> {
    with_dev(net_ns_id, ifindex, |e| e.hw_addrs.clone()).unwrap_or_default()
}

/// `dev->promiscuity` / `dev->allmulti` reference counts.
#[must_use]
pub fn dev_promisc_counts(net_ns_id: u64, ifindex: u32) -> Option<(u32, u32)> {
    with_dev(net_ns_id, ifindex, |e| (e.promiscuity, e.allmulti))
}

pub fn set_link_state(name: &str, up: bool) -> bool {
    let mut g = IFACES.lock();
    let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|iface| iface.name == name))
    else {
        return false;
    };
    let changed = entry.link_up != up;
    entry.link_up = up;
    let (net_ns_id, ifindex) = (entry.net_ns_id, entry.ifindex);
    drop(g);
    // `dev_open` / `dev_close` raise NETDEV_UP / NETDEV_DOWN only on a real
    // transition. Delivered with IFACES released: the notifier reads it.
    if changed {
        crate::raw_sock::netdev_event(
            net_ns_id,
            ifindex,
            if up {
                crate::raw_sock::NetdevEvent::Up
            } else {
                crate::raw_sock::NetdevEvent::Down
            },
        );
    }
    true
}

/// Publish a driver's latest physical-link sample. Administrative IFF_UP is
/// deliberately independent: NetworkManager may open/close a device without
/// changing whether the PHY has carrier.
pub fn set_link_metadata(
    name: &str,
    carrier: bool,
    speed_mbps: Option<u32>,
    duplex: Option<LinkDuplex>,
) -> bool {
    let mut guard = IFACES.lock();
    let Some(entry) = guard
        .as_mut()
        .and_then(|entries| entries.iter_mut().find(|entry| entry.name == name))
    else {
        return false;
    };
    if entry.carrier != carrier {
        entry.carrier = carrier;
        entry.carrier_changes = entry.carrier_changes.saturating_add(1);
        if carrier {
            entry.carrier_up_count = entry.carrier_up_count.saturating_add(1);
        } else {
            entry.carrier_down_count = entry.carrier_down_count.saturating_add(1);
        }
    }
    entry.speed_mbps = carrier.then_some(speed_mbps).flatten();
    entry.duplex = carrier.then_some(duplex).flatten();
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
    entry.addr_assign_type = 3; // NET_ADDR_SET
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
    // Deliberately does NOT publish a 0.0.0.0/0 route, unlike
    // `set_iface_ipv4`. This applies to whatever happens to be FIRST in the
    // registry, which is not necessarily the interface the caller means —
    // adequate for stamping a field, far too vague to hang a default route
    // on, since the wrong one silently captures all off-link traffic.
    // Callers that know the interface name (the DHCP ACK does) call
    // `set_gateway` themselves.
}

/// Stamp a named iface's IPv4 / gateway FIELDS ONLY — like
/// [`set_default_ipv4`] (no `0.0.0.0/0` route published), but targeting the
/// entry by name instead of whatever is first in the registry. `for_dst` reads
/// `ipv4` for the src-IP and `connect` reads `gateway` for the next-hop ARP, so
/// a test harness needs these correct on ITS interface — while relying on the
/// connected route from `add_addr` (and any explicit `set_gateway`) for routing,
/// so a synthetic default route does not mask "no route" behaviour.
pub fn set_iface_ipv4_fields(name: &str, ipv4: [u8; 4], gateway: [u8; 4]) {
    let mut g = IFACES.lock();
    if let Some(v) = g.as_mut() {
        if let Some(e) = v.iter_mut().find(|e| e.name == name) {
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
    {
        let mut g = IFACES.lock();
        if let Some(v) = g.as_mut() {
            if let Some(e) = v.iter_mut().find(|e| e.name == name) {
                e.ipv4 = ipv4;
                e.gateway = gateway;
            }
        }
    }
    // As in `set_default_ipv4`: the gateway becomes a FIB entry, and the
    // IFACES lock is dropped before `set_gateway` re-takes it.
    if gateway != [0u8; 4] {
        set_gateway(name, gateway);
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
    // The first address a device gets is its primary: the source address
    // the stack sends from (Linux `inet_select_addr` picks the primary).
    let mut g = IFACES.lock();
    if let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|entry| entry.name == iface_name))
    {
        if entry.ipv4 == [0; 4] {
            entry.ipv4 = addr;
        }
    }
}

/// Remove an IPv4 address from the named interface. Removing the address
/// the stack sends from moves it to the next remaining address, or leaves
/// the device with none.
pub fn del_addr(iface_name: &str, addr: [u8; 4], prefix_len: u8) {
    crate::ifaddr::iface_del_addr(iface_name, crate::ipv4::Ipv4Addr(addr), prefix_len);
    let next = crate::ifaddr::iface_primary_addr(iface_name).map_or([0; 4], |next| next.addr.0);
    let mut g = IFACES.lock();
    if let Some(entry) = g
        .as_mut()
        .and_then(|ifaces| ifaces.iter_mut().find(|entry| entry.name == iface_name))
    {
        if entry.ipv4 == addr {
            entry.ipv4 = next;
        }
    }
}

/// Return all IPv4 addresses assigned to the named interface as a
/// `Vec<(Ipv4Addr, prefix_len)>`.
pub fn get_addrs(iface_name: &str) -> alloc::vec::Vec<(crate::ipv4::Ipv4Addr, u8)> {
    crate::ifaddr::iface_addrs(iface_name)
        .into_iter()
        .map(|ia| (ia.addr, ia.prefix_len))
        .collect()
}

/// True if `ip` is one of `net_ns_id`'s own IPv4 addresses: an interface's
/// primary address, any address added with [`add_addr`], or anything in
/// 127.0.0.0/8 (Linux installs `local 127.0.0.0/8 dev lo` in the local
/// table, so the whole block is `RTN_LOCAL`).
///
/// This is the `inet_addr_type_table() == RTN_LOCAL` test that `__inet_bind`
/// (`net/ipv4/af_inet.c:494`) and the loopback-delivery decision need.
pub fn is_local_addr_in(net_ns_id: u64, ip: [u8; 4]) -> bool {
    if ip[0] == 127 {
        return true;
    }
    snapshot_all_in(net_ns_id).iter().any(|i| {
        i.ipv4 == ip
            || crate::ifaddr::iface_addrs(&i.name)
                .iter()
                .any(|a| a.addr.0 == ip)
    })
}

/// True if a datagram to `ip` would be a broadcast (`RTCF_BROADCAST`).
///
/// Two cases, both from Linux:
/// - the limited broadcast 255.255.255.255 (`ipv4_is_lbcast`,
///   `ip_route_output_key_hash_rcu`);
/// - a local subnet's directed broadcast, `prefix | ~mask`, which
///   `fib_add_ifaddr` (`net/ipv4/fib_frontend.c:1147`) installs as an
///   `RTN_BROADCAST` route only when `ifa_prefixlen < 31`.
///
/// A host address that merely ends in `.255` (e.g. 10.0.1.255 in a /16) is
/// NOT a broadcast.
pub fn is_broadcast_in(net_ns_id: u64, ip: [u8; 4]) -> bool {
    if ip == [255, 255, 255, 255] {
        return true;
    }
    let dst = u32::from_be_bytes(ip);
    snapshot_all_in(net_ns_id).iter().any(|i| {
        crate::ifaddr::iface_addrs(&i.name).iter().any(|a| {
            if a.prefix_len >= 31 {
                return false;
            }
            let mask = if a.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - a.prefix_len)
            };
            let prefix = u32::from_be_bytes(a.addr.0) & mask;
            prefix != 0 && dst == prefix | !mask
        })
    })
}

/// Install the iface's default gateway as a route (0.0.0.0/0 via
/// gateway).
///
/// Called from `set_iface_ipv4` / `set_default_ipv4`, the two places a
/// gateway is ever configured (static boot config and the DHCP ACK). It
/// used to have no caller at all: both of those recorded the gateway as an
/// interface FIELD and nothing published it to the FIB, so no IPv4 default
/// route existed. Outbound still worked, because `ipv4::send` does its own
/// subnet comparison and falls back to `binding.gateway` — but the routing
/// table did not describe what the stack actually did, which shows up as a
/// missing default in `ip route` / `/proc/net/route`, and as `for_dst`
/// picking an egress by `primary_in()` fallback rather than by route.
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
//
// The frame is `&mut`: an attached XDP program may rewrite header bytes in
// place before the stack parses or the driver reflects the frame. The buffer
// is the driver's own DMA/scratch buffer, mutated before anything downstream
// copies it out, so an in-place write is sound (see `on_rx_frame_from`).
type RxHandler = fn(&str, &mut [u8]);

static RX_HANDLER: AtomicUsize = AtomicUsize::new(0);

pub fn install_rx_handler(h: RxHandler) {
    RX_HANDLER.store(h as usize, Ordering::Release);
}

/// Dispatch a frame received on a known ingress interface.
///
/// `frame` is the driver's own RX buffer, passed `&mut` so an attached XDP
/// program can rewrite it in place. The driver retains ownership and recycles
/// the buffer afterwards; mutating it before the stack copies the payload out
/// (or the driver reflects it for `XDP_TX`) is the whole point of a writable
/// XDP surface.
pub fn on_rx_frame_from(iface_name: &str, frame: &mut [u8]) {
    if !iface_name.is_empty() {
        record_rx_frame(iface_name, frame);
    }
    let v = RX_HANDLER.load(Ordering::Acquire);
    if v == 0 {
        if !iface_name.is_empty() {
            record_rx_nohandler(iface_name);
        }
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
pub fn on_rx_frame(frame: &mut [u8]) {
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
