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

pub mod http;
pub mod http2;
pub mod mqtt;
pub mod pkt;
pub mod pkt_dhcp;
pub mod pkt_coap;
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
pub mod stack;
pub mod stun;
pub mod tls;
pub mod ws;
pub use stack::{AdminCap, AttachError, StackAttach, StackAttachReply, StackDaemon};

mod tests;

use alloc::boxed::Box;
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
/// `<= buf.len()` (the underlying `DmaBuffer` is page-rounded by
/// `narf_io::alloc_coherent`). Move-semantics through rings preserves
/// the spec's single-owner invariant: a frame buffer is owned by
/// exactly one holder at a time.
pub struct Frame {
    buf: DmaBuffer,
    len: u32,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("len", &self.len)
            .field("cap", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl Frame {
    /// Wrap a `DmaBuffer` into a `Frame`. `len` is clamped to the
    /// buffer's allocated capacity so a misuse can't create a frame
    /// claiming bytes the allocator never gave us.
    #[inline]
    pub fn new(buf: DmaBuffer, len: u32) -> Self {
        let cap = buf.len() as u32;
        Self {
            buf,
            len: if len > cap { cap } else { len },
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

    /// Decompose into the underlying `DmaBuffer` + used length. The
    /// caller takes ownership of the buffer; the frame is consumed.
    #[inline]
    pub fn into_parts(self) -> (DmaBuffer, u32) {
        (self.buf, self.len)
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
}

/// Bootstrap the registry authority cap. TCB-only path — the kernel
/// calls this at boot and hands the result to whatever subsystem
/// actually registers interfaces.
pub fn bootstrap_authority() -> Cap<NetIface, Grant> {
    Cap::<NetIface, Grant>::bootstrap()
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

// ── virtio-net skeleton (Stage 4 hand-off) ──────────────────────────

/// virtio-net placeholder.
///
/// Stage 4 binds this to `drivers/virtio/` proper:
/// - `mac` is read from virtio-net config space (`drivers/virtio/`
///   exposes the MMIO config region via `DriverEnv`).
/// - `mtu` defaults to 1500 unless `VIRTIO_NET_F_MTU` is negotiated;
///   then it comes from config space too.
/// - `rx_ring` / `tx_ring` are populated by the driver framework when
///   it sets up the device's virtqueues — the framework hands the
///   driver a pair of `narf_ipc` halves wired to the queue indices,
///   the driver stashes them in this struct's `Option<>` slots.
///
/// In Stage 3 every ring accessor is `unimplemented!()`. Tests must
/// not exercise this path; Stage 3 functional coverage uses
/// `Loopback`.
pub mod virtio_net {
    use super::*;

    /// virtio-net interface skeleton. The fields exist so the Stage-4
    /// implementation can fill them in without changing the public
    /// surface.
    #[allow(dead_code)] // rx/tx are placeholder slots for the Stage-4 binding.
    pub struct VirtioNet {
        name: &'static str,
        mac: [u8; 6],
        mtu: u32,
        // The actual rings are populated at driver-start time. Until
        // then the lock holds `None`, and the trait accessors panic
        // (any caller in Stage 3 is a bug — `Loopback` is the only
        // functioning impl).
        rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
        tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    }

    impl fmt::Debug for VirtioNet {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("VirtioNet")
                .field("name", &self.name)
                .field("mtu", &self.mtu)
                .finish_non_exhaustive()
        }
    }

    impl VirtioNet {
        /// Construct a placeholder with empty ring slots. Stage-4 will
        /// add a `from_device(env: &DriverEnv) -> Self` constructor
        /// that reads MAC/MTU from config space and wires the queues.
        pub fn new(name: &'static str, mac: [u8; 6], mtu: u32) -> Self {
            Self {
                name,
                mac,
                mtu,
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
            }
        }
    }

    impl Interface for VirtioNet {
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
            false
        } // Until Stage 4 binds the device.
        fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
            unimplemented!("virtio-net rx_ring: Stage 4 binds drivers/virtio/")
        }
        fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
            unimplemented!("virtio-net tx_ring: Stage 4 binds drivers/virtio/")
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
