//! narf-net — frame-ring contract, interface registry, loopback.
//!
//! Spec: `net/specification/spec.md` §3 (frame-ring contract, interface
//! trait, registry) and §4 (invariants). Stage-3 subset: enough of the
//! contract to register a `Loopback` interface, push a `Frame` through
//! the cap-gated registry, and round-trip it via the real `narf_ipc`
//! Narf-Ring SPSC. The kernel never parses L3+ — frames are opaque
//! `DmaBuffer`s whose ownership transfers through the rings.
//!
//! What lands in Stage 3:
//! - `Frame`: owned `DmaBuffer` + used-byte length, move-only across
//!   rings — the spec's "zero-copy" invariant.
//! - `Direction`: `Rx` / `Tx` enum (used by drivers/test harnesses to
//!   describe frame intent at trace points).
//! - `Interface` trait: `name`/`mac`/`mtu`/`link_up` plus a pair of
//!   `IrqSafeSpinLock<Option<…>>`-wrapped ring halves. The lock holds
//!   `Option<_>` so the consumer/producer can be `take()`n by exactly
//!   one owner (mirrors `narf_ipc` SPSC's single-owner invariant).
//! - `NetIface` cap-type marker (→ `CapKind::NetIface`).
//! - `Registry`: global, cap-gated `register(authority, iface)`. On a
//!   revoked authority returns `RegisterError::AuthorityRevoked` —
//!   mirrors the drivers/ framework pattern.
//! - `Loopback`: in-kernel reference implementation. Backed by two
//!   real `narf_ipc::channel`s; the forwarder task is spawned at
//!   registration time and pumps tx → rx with no copy.
//! - `virtio_net::VirtioNet`: skeleton implementing `Interface` with
//!   `unimplemented!()` ring slots — a placeholder so Stage 4 can wire
//!   `drivers/virtio/` without churning the crate's public surface.
//!
//! Non-goals for Stage 3:
//! - `IfaceFeatures` / multi-queue / hash steering. The spec's §3.2
//!   `queue: u16` field is collapsed to a single queue per direction.
//! - Admin-rights flow (`set_link` / `set_mtu` / `set_mac`) — the trait
//!   exposes read-only `link_up` / `mtu`; control-plane is Stage 4.
//! - Stack-daemon attach protocol (Stage 4).
//! - aarch64 MTE retag on Frame publish — `narf_ipc::retag::retag_on_publish`
//!   is the existing stub; nothing extra is needed at this layer.
//! - `IfaceStats` / per-ring `rx_dropped` counters (drop-newest is
//!   internal to drivers; the contract here is the rings themselves).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

/// Reclaim kernel networking state after the final reference to a non-initial
/// network namespace disappears.
pub fn release_network_namespace(net_ns_id: u64) {
    if net_ns_id == 0 {
        return;
    }
    tcp::core::remove_namespace(net_ns_id);
    udp_sock::remove_namespace(net_ns_id);
    raw_sock::remove_namespace(net_ns_id);
    icmp_sock::remove_namespace(net_ns_id);
    tcp_stack::remove_namespace(net_ns_id);
    dhcp::remove_namespace(net_ns_id);
    route::remove_namespace(net_ns_id);
    netfilter::namespace::remove(net_ns_id);
    iface::release_namespace(net_ns_id);
}

pub mod arp;
pub mod arp_cache;
pub mod bypass;
pub mod dhcp;
pub mod dns;
pub mod http;
pub mod http2;
pub mod icmp_sock;
pub mod iface;
pub mod ifaddr;
pub mod ipv4;
pub mod ipv6;
pub mod ipv6_stack;
pub mod mqtt;
pub mod netfilter;
pub mod netlink_audit;
pub mod netlink_diag;
pub mod netlink_generic;
pub mod netlink_netfilter;
pub mod netlink_route;
pub mod pkt;
pub mod pkt_coap;
pub mod pkt_dhcp;
pub mod pkt_dhcpv6;
pub mod pkt_dns;
pub mod pkt_gre;
pub mod pkt_icmp_extra;
pub mod pkt_ipv6;
pub mod pkt_l2;
pub mod pkt_mdns;
pub mod pkt_ntp;
pub mod pkt_sctp;
pub mod pkt_tcp;
pub mod pkt_tftp;
pub mod pkt_udp;
pub mod quic;
pub mod raw_sock;
pub mod readiness;
pub mod resolv_conf;
pub mod route;
pub mod stack;
pub mod stun;
pub mod tcp;
pub mod tcp_stack;
pub mod tls;
pub mod udp_sock;
pub mod wireguard;
pub mod ws;
pub use stack::{
    AdminCap, AdminError, AdminHandle, AdminIpv4Route, AdminIpv6Route, AttachError, StackAttach,
    StackAttachReply, StackDaemon,
};

mod dhcp_dns_e2e_tests;
mod e2e_tests;
mod ipv6_e2e_tests;
mod tcp_timer_e2e_tests;
mod tests;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, Rights, Write};
use narf_io::DmaBuffer;
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;

// ── Ring depths ─────────────────────────────────────────────────────
//
// Both rings are 64 deep. The spec doesn't fix a depth; 64 is a
// power-of-two (required by `narf_ipc::Ring`'s mask) and matches
// virtio-net's typical default split. `pub const` so tests and the
// Stage-4 virtio binding can refer to the same number.

/// RX ring depth (inbound frames from interface to consumer).
pub const RX_RING_N: usize = 64;
/// TX ring depth (outbound frames from consumer to interface).
pub const TX_RING_N: usize = 64;

// ── Frame ───────────────────────────────────────────────────────────

/// Owned network frame handle. `len` is the *used* bytes — always
/// `<= buf.len() - offset` (the underlying `DmaBuffer` is page-
/// rounded by `narf_io::alloc_coherent`). `offset` lets drivers
/// hand back a device-filled buffer that has device-protocol bytes
/// (e.g. the 12-byte virtio-net header) sitting at the front of
/// the page — the consumer slices from `offset..offset+len` and
/// never has to memmove the payload to the page start.
///
/// Move-semantics through rings preserves the spec's single-owner
/// invariant: a frame buffer is owned by exactly one holder at a
/// time.
pub struct Frame {
    buf: DmaBuffer,
    offset: u32,
    len: u32,
}

// `Frame` carries a `DmaBuffer` whose backing storage is referenced
// via a phys-address handle, not a raw pointer in the struct itself.
// MTE retag is therefore the trait's identity default.
impl narf_ipc::Retag for Frame {}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("len", &self.len)
            .field("cap", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl Frame {
    /// Wrap a `DmaBuffer` into a `Frame` whose payload starts at
    /// offset 0. `len` is clamped to the buffer's allocated
    /// capacity so a misuse can't create a frame claiming bytes
    /// the allocator never gave us.
    #[inline]
    pub fn new(buf: DmaBuffer, len: u32) -> Self {
        let cap = buf.len() as u32;
        Self {
            buf,
            offset: 0,
            len: if len > cap { cap } else { len },
        }
    }

    /// Wrap a `DmaBuffer` with the payload starting at `offset`
    /// bytes into the buffer. The driver uses this on the RX side
    /// when the device wrote a fixed-size protocol header at the
    /// front of the page (e.g. virtio-net's 12-byte hdr) — we'd
    /// rather not memmove the payload to offset 0 just to satisfy
    /// a no-offset Frame. `offset + len` is clamped to the
    /// buffer's allocated capacity.
    #[inline]
    pub fn with_offset(buf: DmaBuffer, offset: u32, len: u32) -> Self {
        let cap = buf.len() as u32;
        let off = offset.min(cap);
        let max_len = cap.saturating_sub(off);
        Self {
            buf,
            offset: off,
            len: if len > max_len { max_len } else { len },
        }
    }

    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn buf(&self) -> &DmaBuffer {
        &self.buf
    }

    /// Offset of the first payload byte within `buf`. Always 0 for
    /// frames built via [`Frame::new`]; can be non-zero for frames
    /// produced by a driver via [`Frame::with_offset`].
    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Borrow the payload bytes. Honors `offset` so the slice
    /// starts at the first payload byte rather than at the buffer
    /// origin.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let off = self.offset as usize;
        let end = off + self.len as usize;
        &self.buf.as_slice()[off..end]
    }

    /// Mutably borrow the payload bytes. Same slice as [`Self::payload`]
    /// but grants write access. Drivers use this on the RX path to
    /// copy received bytes into the frame before handing it to the
    /// IPC ring.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let off = self.offset as usize;
        let end = off + self.len as usize;
        &mut self.buf.as_mut_slice()[off..end]
    }

    /// Decompose into the underlying `DmaBuffer` + used length.
    /// The caller takes ownership of the buffer and `offset` is
    /// dropped — only use this when the consumer knows the
    /// payload starts at offset 0 in the returned buffer (true
    /// for frames built via [`Frame::new`]).
    #[inline]
    pub fn into_parts(self) -> (DmaBuffer, u32) {
        (self.buf, self.len)
    }

    /// Decompose into the underlying `DmaBuffer` + (offset, len).
    /// Use this when the consumer needs to honor `offset` —
    /// typically drivers handing the buffer back to the device
    /// for the next RX.
    #[inline]
    pub fn into_parts_with_offset(self) -> (DmaBuffer, u32, u32) {
        (self.buf, self.offset, self.len)
    }
}

// ── Direction ───────────────────────────────────────────────────────

/// RX vs TX intent. Trace-only at this layer; rings carry directional
/// information by virtue of which half (`rx_ring` / `tx_ring`) they
/// were taken from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Rx,
    Tx,
}

// ── Cap marker ──────────────────────────────────────────────────────

/// Cap-type marker for network interfaces.
///
/// - `Cap<NetIface, Grant>`: registry authority — who may register
///   interfaces. Bootstrapped once at boot by the TCB.
/// - `Cap<NetIface, Write>`: handle to a specific registered interface,
///   returned from `Registry::register`.
#[derive(Debug)]
pub struct NetIface;
impl CapType for NetIface {
    const KIND: CapKind = CapKind::NetIface;
}

// ── Interface trait ─────────────────────────────────────────────────

/// The frame-ring contract. An implementation owns its rings and
/// surfaces them as `IrqSafeSpinLock<Option<…>>` so exactly one caller
/// can `take()` each end (matching `narf_ipc`'s single-owner SPSC
/// invariant).
///
/// `Send + Sync` because the registry stores boxed implementations
/// behind a global lock and tasks running in different domains may
/// query them concurrently.
pub trait Interface: Send + Sync {
    /// Stable, human-readable name (e.g. "lo0", "eth0"). Used for
    /// diagnostics and (Stage 4) for cap-naming.
    fn name(&self) -> &str;
    /// 48-bit hardware address. Loopback returns a deterministic value;
    /// real NICs read it from device config space.
    fn mac(&self) -> [u8; 6];
    /// Maximum transmission unit in bytes. 1500 by convention.
    fn mtu(&self) -> u32;
    /// Link state. Loopback is always up; physical NICs sample PHY.
    fn link_up(&self) -> bool;
    /// RX consumer half. Caller `lock().take()`s the consumer to drain
    /// inbound frames. `None` after take, until the implementation
    /// hands ownership back (Stage-3 implementations don't).
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>;
    /// TX producer half. Caller `lock().take()`s the producer to push
    /// outbound frames.
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>;
}

// ── Registry ────────────────────────────────────────────────────────

/// Registry-side error codes. `From<CapError>` collapses every cap
/// failure into `AuthorityRevoked` because Stage-3 only checks one
/// thing on the authority cap (its epoch); a richer mapping lands when
/// the registry grows additional cap-gated ops.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The registration authority cap has been revoked.
    AuthorityRevoked,
    /// An interface with this `name` is already registered.
    DuplicateName,
}

impl From<CapError> for RegisterError {
    fn from(_: CapError) -> Self {
        RegisterError::AuthorityRevoked
    }
}

struct Entry {
    iface: Box<dyn Interface>,
    handle: Cap<NetIface, Write>,
}

/// Owned control-plane view of a driver-backed interface.
///
/// Frame-ring endpoints remain in the registry; inventory consumers receive
/// only immutable identity and link metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub link_up: bool,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.iface.name())
            .finish_non_exhaustive()
    }
}

/// Global interface registry. Stage-3 holds everything under one
/// `IrqSafeSpinLock` — registration is rare and the contention
/// argument from `drivers/` applies identically here.
#[derive(Debug)]
pub struct Registry {
    inner: IrqSafeSpinLock<Vec<Entry>>,
}

static REGISTRY: Registry = Registry {
    inner: IrqSafeSpinLock::new(Vec::new()),
};

/// Reference the global registry.
#[inline]
pub fn registry() -> &'static Registry {
    &REGISTRY
}

impl Registry {
    /// Register an interface. Cap-gated on a `Cap<NetIface, Grant>`
    /// authority (mirrors the drivers/ framework). On success returns
    /// a `Cap<NetIface, Write>` handle the caller can later use to
    /// reference its interface in (Stage-4) cap-gated operations.
    pub fn register<I: Interface + 'static>(
        &self,
        authority: &Cap<NetIface, Grant>,
        iface: I,
    ) -> Result<Cap<NetIface, Write>, RegisterError> {
        authority.check_live()?;

        let mut q = self.inner.lock();
        if q.iter().any(|e| e.iface.name() == iface.name()) {
            return Err(RegisterError::DuplicateName);
        }
        let handle: Cap<NetIface, Write> = Cap::<NetIface, Write>::bootstrap();
        q.push(Entry {
            iface: Box::new(iface),
            handle,
        });
        Ok(handle)
    }

    /// Number of registered interfaces.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff the registry holds zero interfaces.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Run `f` against the named interface's `&dyn Interface`. Returns
    /// `None` if no interface matches. The lock is held across `f`, so
    /// `f` should be short — read fields, not block.
    pub fn with_interface<R, F>(&self, name: &str, f: F) -> Option<R>
    where
        F: FnOnce(&dyn Interface) -> R,
    {
        let q = self.inner.lock();
        q.iter()
            .find(|e| e.iface.name() == name)
            .map(|e| f(&*e.iface))
    }

    /// Run `f` against the named entry's `Cap<NetIface, Write>` handle.
    /// Useful for tests and Stage-4 control-plane lookups.
    pub fn with_handle<R, F>(&self, name: &str, f: F) -> Option<R>
    where
        F: FnOnce(&Cap<NetIface, Write>) -> R,
    {
        let q = self.inner.lock();
        q.iter()
            .find(|e| e.iface.name() == name)
            .map(|e| f(&e.handle))
    }

    /// Run `f` against the exact interface named by a presented registry
    /// handle. A live handle minted for another entry does not match.
    pub fn with_interface_for_handle<R, F>(&self, handle: &Cap<NetIface, Write>, f: F) -> Option<R>
    where
        F: FnOnce(&dyn Interface) -> R,
    {
        let q = self.inner.lock();
        q.iter()
            .find(|entry| entry.handle.slot() == handle.slot())
            .map(|entry| f(&*entry.iface))
    }

    /// Snapshot every driver-backed interface without exposing its frame rings.
    pub fn snapshots(&self) -> Vec<InterfaceSnapshot> {
        self.inner
            .lock()
            .iter()
            .map(|entry| InterfaceSnapshot {
                name: String::from(entry.iface.name()),
                mac: entry.iface.mac(),
                mtu: entry.iface.mtu(),
                link_up: entry.iface.link_up(),
            })
            .collect()
    }
}

/// Bootstrap the registry authority cap. TCB-only path — the kernel
/// calls this at boot and hands the result to whatever subsystem
/// actually registers interfaces.
pub fn bootstrap_authority() -> Cap<NetIface, Grant> {
    Cap::<NetIface, Grant>::bootstrap()
}

/// Trusted network authority — a Grant cap minted once at boot and
/// stored here for the driver-registration path.
static TRUSTED_NET_AUTHORITY: IrqSafeSpinLock<Option<Cap<NetIface, Grant>>> =
    IrqSafeSpinLock::new(None);

/// Install the trusted network authority. TCB-only.
pub fn install_trusted_net_authority(cap: Cap<NetIface, Grant>) {
    let mut g = TRUSTED_NET_AUTHORITY.lock();
    if g.is_none() {
        *g = Some(cap);
    }
}

/// Retrieve the trusted network authority.
pub fn trusted_net_authority() -> Option<Cap<NetIface, Grant>> {
    TRUSTED_NET_AUTHORITY.lock().as_ref().cloned()
}

// ── Loopback ────────────────────────────────────────────────────────

/// In-kernel loopback interface. Backed by two real `narf_ipc`
/// channels: one for tx (caller → loopback) and one for rx (loopback
/// → caller). A dedicated forwarder task pumps tx-Consumer drain into
/// rx-Producer publish, exercising the full ownership-transfer path
/// of the IPC layer.
///
/// Construction order matters: `register_loopback` builds the
/// Loopback, registers it (cap-gated), then spawns the forwarder. The
/// forwarder owns the two "internal" halves (tx-Consumer + rx-Producer)
/// and is `'static` — it doesn't borrow the registry.
pub struct Loopback {
    name: &'static str,
    mac: [u8; 6],
    mtu: u32,
    /// Producer the *caller* uses to submit tx frames.
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    /// Consumer the *caller* uses to read rx frames.
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
}

impl fmt::Debug for Loopback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loopback")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl Loopback {
    /// Default loopback name. Registered interfaces must be uniquely
    /// named; tests that need parallel loopbacks should use
    /// `Loopback::with_name`.
    pub const DEFAULT_NAME: &'static str = "lo0";
    /// Loopback MAC. Locally-administered, individual address — the
    /// lowest-octet `0x02` bit is set so it can't collide with a real
    /// vendor-assigned address.
    pub const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    /// Default MTU. 1500 is the Ethernet convention; loopback could go
    /// higher but matching real NICs makes test code portable.
    pub const DEFAULT_MTU: u32 = 1500;
}

/// Build a loopback + its forwarder halves. The forwarder isn't
/// spawned here — `register_loopback` does that *after* the cap-gated
/// register call so a revoked authority doesn't leak a background
/// task.
fn build_loopback(
    name: &'static str,
    mac: [u8; 6],
    mtu: u32,
) -> (
    Loopback,
    Consumer<Frame, TX_RING_N>,
    Producer<Frame, RX_RING_N>,
) {
    let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
    let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let lo = Loopback {
        name,
        mac,
        mtu,
        tx: IrqSafeSpinLock::new(Some(tx_prod)),
        rx: IrqSafeSpinLock::new(Some(rx_cons)),
    };
    (lo, tx_cons, rx_prod)
}

impl Interface for Loopback {
    fn name(&self) -> &str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        self.mtu
    }
    fn link_up(&self) -> bool {
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}

/// Register a loopback interface and spawn its forwarder task. The
/// forwarder reads from the caller-fed `tx_ring`'s peer Consumer and
/// writes to the caller-fed `rx_ring`'s peer Producer — i.e. every
/// frame the caller sends comes back as an rx frame.
///
/// The forwarder is spawned via `narf_scheduler::spawn`, so the
/// scheduler must be initialised before this is called. The forwarder
/// terminates when the caller drops its tx Producer (the peer
/// Consumer observes `RecvError::Closed`).
pub fn register_loopback(
    authority: &Cap<NetIface, Grant>,
) -> Result<Cap<NetIface, Write>, RegisterError> {
    register_loopback_named(authority, Loopback::DEFAULT_NAME)
}

/// Register a loopback under a custom name. Useful for tests that
/// want multiple parallel loopbacks.
pub fn register_loopback_named(
    authority: &Cap<NetIface, Grant>,
    name: &'static str,
) -> Result<Cap<NetIface, Write>, RegisterError> {
    let (lo, mut tx_cons, mut rx_prod) =
        build_loopback(name, Loopback::DEFAULT_MAC, Loopback::DEFAULT_MTU);

    // Register first so a revoked authority short-circuits before we
    // spawn anything.
    let handle = registry().register(authority, lo)?;

    narf_scheduler::spawn(async move {
        // Forwarder loop: drain tx, publish to rx. The send is async —
        // if the rx ring fills, the forwarder parks until the consumer
        // drains. This matches the spec's TX-blocks-via-waker rule
        // (§4); RX drop-newest is a driver-level concern that doesn't
        // apply to loopback (no hardware racing the ring).
        // tx Producer dropped → recv resolves Err(Closed); we stop.
        while let Ok(frame) = tx_cons.recv().await {
            if rx_prod.send(frame).await.is_err() {
                // Consumer dropped the rx end — stop forwarding.
                break;
            }
        }
    });

    Ok(handle)
}

// ── virtio-net Interface impl ───────────────────────────────────────

/// virtio-net interface, bound to a probed `drivers/virtio/net_pci`
/// controller. The PCI driver constructs one of these after reading
/// MAC/MTU from device-cfg, building the SPSC ring halves via
/// `narf_ipc::channel`, registering with `net::registry()`, and
/// spawning RX/TX forwarder tasks.
///
/// Holds the *caller-facing* ring halves: a Producer for tx (the
/// stack pushes frames here, the forwarder drains them and sends
/// them to the device) and a Consumer for rx (the forwarder pushes
/// frames received from the device here, the stack drains them).
/// The peer halves live captured in the spawned forwarders.
pub mod virtio_net {
    use super::*;
    use alloc::string::String;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// virtio-net `Interface` implementation. Construct via
    /// `VirtioNet::new`; the PCI driver then calls
    /// `narf_net::registry().register()` to bind the interface and
    /// receives a `Cap<NetIface, Write>` handle for later admin
    /// operations.
    pub struct VirtioNet {
        name: String,
        mac: [u8; 6],
        mtu: u32,
        link_up: AtomicBool,
        rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
        tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    }

    impl fmt::Debug for VirtioNet {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("VirtioNet")
                .field("name", &self.name.as_str())
                .field("mac", &self.mac)
                .field("mtu", &self.mtu)
                .field("link_up", &self.link_up.load(Ordering::Acquire))
                .finish()
        }
    }

    impl VirtioNet {
        /// Build a `VirtioNet` from already-paired ring halves. The
        /// caller (the PCI driver) keeps the *peer* halves (rx
        /// Producer + tx Consumer) and spawns forwarder tasks that
        /// pump device → rx Producer and tx Consumer → device.
        pub fn new(
            name: String,
            mac: [u8; 6],
            mtu: u32,
            link_up: bool,
            tx: Producer<Frame, TX_RING_N>,
            rx: Consumer<Frame, RX_RING_N>,
        ) -> Self {
            Self {
                name,
                mac,
                mtu,
                link_up: AtomicBool::new(link_up),
                rx: IrqSafeSpinLock::new(Some(rx)),
                tx: IrqSafeSpinLock::new(Some(tx)),
            }
        }

        /// Update the link state. Drivers call this when a PHY-state
        /// IRQ or a periodic poll observes a transition; the
        /// stack's `link_up()` reflects the new value immediately.
        pub fn set_link_up(&self, up: bool) {
            self.link_up.store(up, Ordering::Release);
        }
    }

    impl Interface for VirtioNet {
        fn name(&self) -> &str {
            self.name.as_str()
        }
        fn mac(&self) -> [u8; 6] {
            self.mac
        }
        fn mtu(&self) -> u32 {
            self.mtu
        }
        fn link_up(&self) -> bool {
            self.link_up.load(Ordering::Acquire)
        }
        fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
            &self.rx
        }
        fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
            &self.tx
        }
    }
}

// ── Cap-rights helper ───────────────────────────────────────────────

/// Re-export so callers can satisfy the `R: Rights` bound on
/// `Cap<NetIface, R>` without separately importing
/// `narf_capabilities`. Stage 4 widens this to `Rx`/`Tx`/`Admin`
/// per spec §3.1.
pub fn rights_bits<R: Rights>() -> u32 {
    R::BITS
}

// ── TX/RX metadata ──────────────────────────────────────────────────

/// L4 checksum offload kind. Passed in `TxMeta::csum_l4` to tell the
/// driver which L4 checksum to compute in hardware.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum L4CsumKind {
    /// Compute a TCP checksum.
    Tcp,
    /// Compute a UDP checksum.
    Udp,
}

/// Per-frame transmit metadata. Drivers read this alongside the
/// `Frame` to know which hardware offloads to request.
///
/// All fields are `Option`; `None` means "no offload requested". The
/// driver applies whichever the hardware supports and ignores the rest.
#[derive(Copy, Clone, Debug, Default)]
pub struct TxMeta {
    /// L4 checksum offload. `None` = no offload.
    pub csum_l4: Option<L4CsumKind>,
    /// TCP Segmentation Offload: maximum segment size in bytes.
    /// When `Some`, implies L3 + L4 checksum offload as well.
    /// `None` = no TSO.
    pub tso_mss: Option<u16>,
    /// 802.1Q VLAN tag to insert (12-bit VID + 3-bit PCP + CFI).
    /// `None` = no VLAN insertion.
    pub vlan_tag: Option<u16>,
}

impl TxMeta {
    /// Convenience: a plain data frame with no offloads.
    pub const fn plain() -> Self {
        Self {
            csum_l4: None,
            tso_mss: None,
            vlan_tag: None,
        }
    }

    /// Convenience: request L4 checksum offload only.
    pub const fn with_csum(kind: L4CsumKind) -> Self {
        Self {
            csum_l4: Some(kind),
            tso_mss: None,
            vlan_tag: None,
        }
    }

    /// Convenience: request TSO (implies TCP checksum offload).
    pub const fn with_tso(mss: u16) -> Self {
        Self {
            csum_l4: Some(L4CsumKind::Tcp),
            tso_mss: Some(mss),
            vlan_tag: None,
        }
    }
}

/// Per-frame receive metadata. Drivers populate this from the
/// completion descriptor so consumers know which offloads the
/// hardware already verified.
#[derive(Copy, Clone, Debug, Default)]
pub struct RxMeta {
    /// `true` if the hardware verified the IP (L3) header checksum
    /// and found it valid.
    pub csum_l3: bool,
    /// `true` if the hardware verified the L4 (TCP/UDP) checksum
    /// and found it valid.
    pub csum_l4: bool,
}
