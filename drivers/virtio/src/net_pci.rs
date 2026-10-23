//! virtio-net over modern virtio-PCI transport (VirtIO 1.2 §5.1).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-net's PCI device id is `0x1000 + 0x40 + 0x01`
//! = 0x1041 (`0x1040 + virtio_id`, virtio_id 1 = net).
//!
//! Queue layout (VirtIO 1.2 §5.1.2):
//!   - queue 2N     = receiveq[N]
//!   - queue 2N+1   = transmitq[N]
//!   - queue 2 * max_virtqueue_pairs = controlq (when F_CTRL_VQ
//!     negotiated; sits at fixed index 2 when F_MQ is *not*
//!     negotiated since max_virtqueue_pairs is implicitly 1).
//!
//! Multi-queue (VIRTIO_NET_F_MQ, §5.1.3.1 feature bit 22): the
//! device advertises `max_virtqueue_pairs` (§5.1.4 u16 at device-cfg
//! offset 8). After feature ack + DRIVER_OK we issue
//! `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` (§5.1.6.5.5: class 4, cmd 0,
//! 2-byte LE payload) to tell the device how many pairs to keep
//! active. Frames still funnel into a single `narf_net::Interface`
//! per device — MQ is a throughput optimisation, not a multi-iface
//! fan-out — but TX submissions round-robin across the pairs so
//! parallel callers don't serialise on a single virtqueue lock,
//! and each RX pair gets its own forwarder.

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

/// Latency policy for TX notification. EVENT_IDX suppression (default) lets the
/// device (QEMU/SLIRP) tell us when to skip a notify VM-exit — great for
/// concurrent throughput, but for a lone request-response frame it can defer the
/// frame until the host next polls the ring on its own timer (the redis PING p99
/// tail). When this is set the driver additionally kicks whenever a submission
/// leaves TX descriptors in flight the device hasn't reclaimed — i.e. a lone
/// frame after the ring had drained — mirroring Linux virtio-net, which kicks
/// every non-`xmit_more` frame. Boot param `tx_always_kick`.
static TX_ALWAYS_KICK: AtomicBool = AtomicBool::new(false);

/// Enable the latency-first TX kick policy (boot param `tx_always_kick`).
pub fn set_tx_always_kick(on: bool) {
    TX_ALWAYS_KICK.store(on, Ordering::Relaxed);
}

/// Is the latency-first TX kick policy enabled?
#[inline]
pub fn tx_always_kick() -> bool {
    TX_ALWAYS_KICK.load(Ordering::Relaxed)
}

/// NAPI RX interrupt suppression during sustained poll (boot param `rx_napi`).
/// When set, the forwarder disables the RX used-ring callback while a burst is
/// flowing (it polls the ring itself) and re-enables it before parking —
/// mirroring Linux NAPI `disable_cb`/`enable_cb`. Cuts an MSI-per-frame VM-exit
/// (and, under SLIRP, an irqfd crossing on the single-threaded host iothread).
static RX_NAPI: AtomicBool = AtomicBool::new(false);

/// Maximum number of consecutive fast RX polls before letting another
/// runnable task make progress. A fast poll is still immediate; this only
/// bounds how long a CPU-pinned forwarder can occupy one executor poll when a
/// device continuously has completions ready.
pub(crate) const FAST_POLL_QUANTUM: u32 = 32;

/// Enable NAPI RX interrupt suppression (boot param `rx_napi`).
pub fn set_rx_napi(on: bool) {
    RX_NAPI.store(on, Ordering::Relaxed);
}

/// Account one RX polling round and report whether the fast-poll quantum has
/// been consumed. An idle round resets the budget so the next burst gets a
/// full immediate-poll quantum.
#[inline]
pub(crate) fn fast_poll_quantum_expired(rounds: &mut u32, fast: bool) -> bool {
    if !fast {
        *rounds = 0;
        return false;
    }

    *rounds = rounds.saturating_add(1);
    if *rounds >= FAST_POLL_QUANTUM {
        *rounds = 0;
        true
    } else {
        false
    }
}

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::pool::DmaPool;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_DEVICE_FEATURE,
    CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF,
    CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

/// Modern virtio-net PCI ids.
pub const VIRTIO_NET_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_NET_PCI_DEVICE: u16 = 0x1041;

// virtio-net feature bits (VirtIO 1.2 §5.1.3). We negotiate the
// subset the kernel actually reads from device-cfg / drives via
// the control queue.
/// The device completes a partial transport checksum supplied by the driver.
const VIRTIO_NET_F_CSUM: u64 = 0;
const VIRTIO_NET_F_MTU: u64 = 3;
const VIRTIO_NET_F_MAC: u64 = 5;
/// The device can segment a driver-supplied IPv4/TCP GSO packet.
///
/// "HOST" is from the virtio specification's host/device viewpoint: this is
/// the feature a guest driver negotiates before placing a TCPv4 GSO packet on
/// its transmit queue.
const VIRTIO_NET_F_HOST_TSO4: u64 = 11;
const VIRTIO_NET_F_STATUS: u64 = 16;
const VIRTIO_NET_F_CTRL_VQ: u64 = 17;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_CTRL_MAC_ADDR (bit 23).
/// Required for `VIRTIO_NET_CTRL_MAC_ADDR_SET` to succeed.
const VIRTIO_NET_F_CTRL_MAC_ADDR: u64 = 23;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_MQ (bit 22). Device supports
/// multi-queue with auto receive-steering across `max_virtqueue_pairs`.
const VIRTIO_NET_F_MQ: u64 = 22;
/// VIRTIO_RING_F_EVENT_IDX (bit 29, transport). Enables the fine-grained
/// avail_event/used_event notification protocol — the driver suppresses a
/// TX-notify VM-exit unless the device's published `avail_event` says it wants
/// one. Under the SLIRP backend (single-threaded host NAT) each guest→host
/// notify crossing dominates the concurrent feed cost, so suppressing the
/// unnecessary ones is the lever.
const VIRTIO_RING_F_EVENT_IDX: u64 = 29;

// virtio-net control-queue command classes + sub-commands
// (VirtIO 1.2 §5.1.6.5). One class per logical operation group
// (RX filter, MAC, VLAN, …); each class has a numeric command
// space the driver fills in `virtio_net_ctrl_hdr::cmd`.
const VIRTIO_NET_CTRL_RX: u8 = 0;
const VIRTIO_NET_CTRL_RX_PROMISC: u8 = 0;
const VIRTIO_NET_CTRL_RX_ALLMULTI: u8 = 1;

/// VirtIO 1.2 §5.1.6.5.2 — VIRTIO_NET_CTRL_MAC class.
const VIRTIO_NET_CTRL_MAC: u8 = 1;
/// `VIRTIO_NET_CTRL_MAC_ADDR_SET` (§5.1.6.5.2). 6-byte MAC
/// payload. Only valid when the device negotiated
/// `VIRTIO_NET_F_CTRL_MAC_ADDR` (bit 23) — otherwise the device
/// will reject the command with `VIRTIO_NET_ERR`.
const VIRTIO_NET_CTRL_MAC_ADDR_SET: u8 = 1;

/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ class.
const VIRTIO_NET_CTRL_MQ: u8 = 4;
/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET.
/// Payload is a `__virtio16` (2-byte LE) count of pairs to enable.
const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u8 = 0;

const VIRTIO_NET_OK: u8 = 0;

// virtio-net config status bits.
const VIRTIO_NET_S_LINK_UP: u16 = 1 << 0;

// Offsets within the device-specific config region (VirtIO 1.2
// §5.1.4 — `struct virtio_net_config`).
const CFG_MAC: u64 = 0;
const CFG_STATUS: u64 = 6;
/// Per §5.1.4: u16 LE, only valid when VIRTIO_NET_F_MQ negotiated.
/// Reports the maximum number of TX/RX queue pairs the device
/// supports. Spec guarantees 1 ≤ value ≤ 0x8000.
const CFG_MAX_VIRTQUEUE_PAIRS: u64 = 8;
const CFG_MTU: u64 = 10;

/// Upper bound on how many queue pairs we'll actually bring up,
/// regardless of what `max_virtqueue_pairs` reports. Keeps DMA-page
/// + MSI-X-vector consumption bounded for absurd device-advertised
///   counts (some emulators advertise 0x8000). Four is enough to spread
///   TX submission across a typical small-core machine.
const MAX_QUEUE_PAIRS: u16 = 4;

/// virtio-net header (VirtIO 1.2 §5.1.6.1). 12 bytes when
/// VIRTIO_F_VERSION_1 is negotiated and VIRTIO_NET_F_MRG_RXBUF /
/// VIRTIO_NET_F_HASH_REPORT are *not* — the form we use.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

const VIRTIO_NET_HDR_LEN: usize = core::mem::size_of::<VirtioNetHdr>();
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_HDR_LEN: usize = 20;
const TCP_MIN_HDR_LEN: usize = 20;
const TCP_CSUM_OFFSET: usize = 16;
const IP_PROTO_TCP: u8 = 6;
const TCP_ECE_OR_CWR: u8 = 0xc0;

/// Maximum frame we'll accept on RX. Standard MTU + Ethernet header + the
/// virtio-net header. RX GSO is deliberately not negotiated yet.
pub const MAX_RX_FRAME: usize = 1518 + VIRTIO_NET_HDR_LEN;

/// Largest complete Ethernet frame accepted by the bounded virtio TX GSO
/// profile. It is deliberately the same 64 KiB order used by the TCP stack's
/// existing e1000 profile, while still fitting one contiguous DMA buffer.
const MAX_TX_TSO_FRAME: usize = 64 * 1024;
const TX_BUF_LEN: usize = VIRTIO_NET_HDR_LEN + MAX_TX_TSO_FRAME;

/// Per-pair RX/TX virtqueue + descriptor-id → buffer slot table.
/// With VIRTIO_NET_F_MQ the device exposes N of these as virtqueues
/// 2N (RX) + 2N+1 (TX). Each pair carries its own notify offset
/// (read once from `queue_notify_off` at bring_up) so the TX
/// round-robin selector can fire the right notify register without
/// re-walking the cfg space, and its own buffer slot table so RX
/// refills land back in the right pair.
#[derive(Debug)]
struct QueuePair {
    /// virtqueue index 2*N. Stored explicitly because `tx_dma` /
    /// `rx_take` need it for the device notify write, and a Vec
    /// position isn't necessarily the pair index after future
    /// hot-unplug paths land.
    rx_qidx: u16,
    /// virtqueue index 2*N + 1.
    tx_qidx: u16,
    rx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_queue: IrqSafeSpinLock<Option<Virtqueue>>,
    /// RX descriptor → buffer table for this pair only.
    rx_buffers: IrqSafeSpinLock<Vec<Option<DmaBuffer>>>,
    /// TX descriptor → in-flight buffer table for this pair only.
    /// With fire-and-forget TX the payload `DmaBuffer` must stay
    /// alive (the device DMAs from it) until its used-ring entry
    /// appears. On submit we move the buffer into `tx_buffers[head]`;
    /// on completion reclaim we `take()` it out and return it to this pair's
    /// pool. Sized to the TX queue size.
    tx_buffers: IrqSafeSpinLock<Vec<Option<DmaBuffer>>>,
    /// Recycled TX DMA buffers owned solely by this queue pair. A completion
    /// returns to the same pool its submission acquired from, so multi-queue
    /// traffic never serializes on an interface-wide recycler lock.
    tx_pool: Arc<DmaPool>,
    /// Recycled RX DMA buffers for this queue pair. A forwarder consumes and
    /// replenishes only its own pool, retaining queue/CPU locality.
    rx_pool: DmaPool,
    /// Holds DMA pages backing the desc/avail/used rings alive.
    _rx_q_buf: DmaBuffer,
    _tx_q_buf: DmaBuffer,
    rx_qsize: u16,
    tx_qsize: u16,
    rx_notify_off: u16,
    tx_notify_off: u16,
}

impl QueuePair {
    /// Caller holds this pair's queue lock followed by its buffer-table lock.
    /// Reclaim only device-completed descriptors, returning their buffers to
    /// this pair without allocating or waiting for outstanding DMA.
    fn reclaim_tx(&self, q: &mut Virtqueue, bufs: &mut [Option<DmaBuffer>]) -> bool {
        let mut freed_any = false;
        while let Some((head, _)) = q.poll_used() {
            q.free_chain(head as u16);
            if let Some(buf) = bufs.get_mut(head as usize).and_then(Option::take) {
                self.tx_pool.release(buf);
            }
            freed_any = true;
        }
        freed_any
    }
}

/// Cap on each queue pair's recycled TX DMA-buffer free-list. A 64 KiB GSO
/// buffer per entry bounds the per-pair reservation and maximum queued
/// super-frame payload at 2 MiB. This retains 32 descriptors worth of 64 KiB
/// frames without multiplying the original 4 KiB-pool footprint by sixteen
/// on multi-queue VMs. Overflow drops (frees) rather than growing
/// unbounded.
const TX_POOL_CAP: usize = 32;

/// Cap on each queue pair's recycled RX DMA-buffer free-list (the RX
/// `skb`/frame pool).
/// Sized to a full RX ring so steady-state RX never falls back to the global
/// buddy allocator + per-frame 4 KiB zero-fill (`alloc_coherent`): the device
/// overwrites every RX buffer, so recycled buffers need no re-zeroing. This
/// killed an ~880-in-200k (>128µs) `alloc_frame` lock-contention tail.
/// Overflow drops (frees) the buffer.
const RX_POOL_CAP: usize = 256;

pub struct VirtioNetPci {
    common: VirtioRegion,
    notify: VirtioRegion,
    /// Device-specific config region. `None` when the device didn't
    /// expose a Device cap (rare on modern QEMU); MAC defaults to
    /// `[0; 6]`, MTU to 1500, link assumed up in that case.
    device_cfg: Option<VirtioRegion>,
    notify_off_multiplier: u32,
    /// Active RX/TX queue pairs. Always non-empty post-bring_up;
    /// pair index 0 is the "primary" pair (still bound to MSI-X for
    /// RX-arrival wakeups). Pairs 1..N rely on the 16 ms polling
    /// fallback for now — per-queue MSI-X for MQ is a follow-up.
    pairs: Vec<QueuePair>,
    /// Round-robin TX-pair selector. `tx_dma` increments this then
    /// mods by `pairs.len()` to pick which TX virtqueue gets the
    /// next outbound frame. AtomicU64 to keep wraparound trivial
    /// (overflow ~ 5 × 10^11 years at 1 Gpps); Relaxed because we
    /// only need monotonic-ish, not coherence-with-data.
    tx_rr: AtomicU64,
    /// IDT vector bound to receiveq pair-0 (queue 0) when MSI-X is
    /// enabled. `None` means polled-only completion. Consumers wait
    /// via `narf_interrupts::wait_for_irq(v).await`.
    pub irq_vector: Option<u8>,
    /// Per-RX-pair MSI-X IDT vectors, indexed by pair (queue `2*K`).
    /// `rx_irq_vectors[K] == Some(v)` means pair K's forwarder parks on
    /// IRQ `v` (routed to pair K's CPU); `None` means it polls. Empty
    /// until `enable_rx_msix_all` runs; `rx_irq_vectors[0]` mirrors
    /// `irq_vector`. This is what makes a multi-queue NIC wake every
    /// forwarder on its own interrupt instead of pairs 1..N blind-sleeping.
    pub rx_irq_vectors: alloc::vec::Vec<Option<u8>>,
    /// Whether to use flow-affine (4-tuple-hashed) TX queue selection vs
    /// round-robin. Set true only when forwarders own dedicated cores
    /// (`partition`, set in `enable_rx_msix_all`): flow affinity makes a
    /// connection sticky to one queue → one forwarder CPU, which only helps
    /// when those CPUs are distinct from the workers. When forwarders share a
    /// core (single-vCPU / single-threaded server), the per-TX hash is pure
    /// overhead and round-robin's even packet spread is better — so we fall
    /// back to round-robin, matching pre-RSS behaviour exactly (zero cost).
    flow_affine: bool,
    /// Per-queue MSI-X vector for TX completions on pair 0. `None`
    /// = caller hasn't called `enable_tx_msix` yet, TX uses polled
    /// used-ring drain.
    pub tx_irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,
    pub ready: bool,
    /// 48-bit hardware address. Initial value read from device-cfg
    /// at bring-up (zero when `VIRTIO_NET_F_MAC` wasn't advertised).
    /// Subsequent `set_mac` calls overwrite the cache so `mac()`
    /// reflects the live value — useful for the rare case where
    /// the OS reassigns the address after probe.
    mac: IrqSafeSpinLock<[u8; 6]>,
    /// True when `VIRTIO_NET_F_CTRL_MAC_ADDR` was negotiated.
    /// `set_mac` short-circuits with NoQueues when this is false
    /// rather than firing a doomed CTRL_VQ command.
    has_ctrl_mac_addr: bool,
    /// Last-read MTU from device-cfg (when `VIRTIO_NET_F_MTU`
    /// negotiated). Default 1500 otherwise.
    mtu: u32,
    /// True when `VIRTIO_NET_F_STATUS` was negotiated. Without it
    /// the spec says treat link as always up.
    has_status: bool,
    /// TX offloads actually negotiated with this device. The legacy interface
    /// advertises exactly this profile to TCP after registration; no caller can
    /// request a partial checksum or GSO packet the transport did not accept.
    tx_checksum: bool,
    tx_tso4: bool,
    /// Runtime control-queue index (VirtIO 1.2 §5.1.2): with F_MQ
    /// negotiated and pairs > 1 the controlq sits at
    /// `2 * num_pairs`; without F_MQ it sits at fixed index 2.
    /// Stored so `submit_control` notifies the right queue.
    ctrl_qidx: u16,
    /// Control queue. `None` when the device didn't offer
    /// `F_CTRL_VQ`. Wrapped together with its scratch buffer +
    /// notify offset so callers can submit one command without
    /// trampolining through multiple locks.
    ctrl: Option<IrqSafeSpinLock<CtrlQueue>>,
    /// Phys address of the device's PCIe config space. Used by
    /// probe() as a per-device fingerprint so a second probe pass
    /// against the same device (e.g. tests that reset the bus
    /// driver-match registry + re-walk PCI) is idempotent — we
    /// recognise the device and don't push a duplicate controller.
    cfg_phys: u64,
}

/// Control-queue runtime state. `ctrl_buf` holds back-to-back
/// (hdr, payload, ack) byte regions used by `submit_control`;
/// 256 bytes is enough for a 2-byte hdr + ≤253 bytes of payload +
/// 1 byte ack, covering every RX/MAC/VLAN command we care about
/// today.
#[derive(Debug)]
struct CtrlQueue {
    q: Virtqueue,
    /// 4 KiB scratch page. The same page backs every submitted
    /// command (single-flight serialised by the outer lock); the
    /// device sees an [hdr|payload|ack] layout at fixed offsets
    /// 0 / 16 / 256 within the page.
    buf: DmaBuffer,
    notify_off: u16,
    /// Layout-buffer DMA backing the descriptor / avail / used
    /// rings — held so the page stays allocated for the device's
    /// lifetime.
    _layout_buf: DmaBuffer,
}

// Target depth of the RX buffer ring. Posted up front and kept full by
// the one-for-one refill in `rx_take_on`. Capped by the actual queue
// size (`rx_qsize`), so on a typical 128-descriptor virtio-net RX queue
// the whole ring is posted. A shallow ring (the old value was 8) is the
// burst-absorption limit: under concurrent off-box load, if the single
// forwarder falls briefly behind, an 8-deep ring empties and the host
// tap silently drops frames → TCP retransmit (a ~tens-of-ms p99 tail).
// Post the full ring so a momentary scheduling stall doesn't drop.
const RX_POOL_LEN: usize = 256;

impl core::fmt::Debug for VirtioNetPci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNetPci")
            .field("ready", &self.ready)
            .field("num_pairs", &self.pairs.len())
            .field(
                "rx_qsize",
                &self.pairs.first().map(|p| p.rx_qsize).unwrap_or(0),
            )
            .field(
                "tx_qsize",
                &self.pairs.first().map(|p| p.tx_qsize).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

/// The subset of the negotiated virtio-net feature word that changes the TX
/// packet format. Kept separate from [`VirtioNetPci`] so the header encoder is
/// directly testable without MMIO or DMA fixtures.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TxOffloadProfile {
    pub checksum: bool,
    pub tso4: bool,
}

impl TxOffloadProfile {
    /// Virtio's TCPv4 GSO format always carries a partial checksum. Keep this
    /// implication explicit even though probe constructs only valid profiles,
    /// so a future feature-negotiation refactor cannot advertise TSO alone.
    const fn tso4_enabled(self) -> bool {
        self.checksum && self.tso4
    }

    const fn advertised(self) -> narf_net::OffloadCapabilities {
        narf_net::OffloadCapabilities {
            tx_checksum: self.checksum,
            rx_checksum: false,
            max_tso_bytes: if self.tso4_enabled() {
                MAX_TX_TSO_FRAME as u32
            } else {
                0
            },
            vlan_insert: false,
        }
    }
}

/// Encode a native Rust representation of a virtio-net header into its packed
/// wire representation. The multi-byte fields are pre-converted to little
/// endian by [`tx_header_for_frame`]; `to_ne_bytes` therefore preserves the
/// intended byte sequence on both supported architectures without relying on
/// a packed-struct pointer cast.
fn write_tx_header(dst: &mut [u8], hdr: VirtioNetHdr) {
    debug_assert!(dst.len() >= VIRTIO_NET_HDR_LEN);
    dst[0] = hdr.flags;
    dst[1] = hdr.gso_type;
    dst[2..4].copy_from_slice(&hdr.hdr_len.to_ne_bytes());
    dst[4..6].copy_from_slice(&hdr.gso_size.to_ne_bytes());
    dst[6..8].copy_from_slice(&hdr.csum_start.to_ne_bytes());
    dst[8..10].copy_from_slice(&hdr.csum_offset.to_ne_bytes());
    dst[10..12].copy_from_slice(&hdr.num_buffers.to_ne_bytes());
}

fn malformed_tx() -> VirtioPciError {
    // The PCI transport has no packet-format error because this path used to
    // accept only plain MTU-sized frames. QueueTooSmall is its established
    // input-validation error and keeps the rejection local to this driver.
    VirtioPciError::QueueTooSmall
}

/// Validate an ordinary Ethernet/IP TCP or UDP frame and return the start of
/// its L4 header plus the checksum field offset within that header. Virtio's
/// checksum fields are packet-relative, so accepting arbitrary offsets here
/// would let a malformed `TxMeta` make the device write elsewhere in the DMA
/// buffer.
fn l4_checksum_layout(
    frame: &[u8],
    kind: narf_net::L4CsumKind,
) -> Result<(usize, usize), VirtioPciError> {
    if frame.len() < ETH_HDR_LEN + IPV4_MIN_HDR_LEN {
        return Err(malformed_tx());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => {
            let ip = ETH_HDR_LEN;
            if frame[ip] >> 4 != 4 {
                return Err(malformed_tx());
            }
            let ip_hlen = usize::from(frame[ip] & 0x0f) * 4;
            if !(IPV4_MIN_HDR_LEN..=60).contains(&ip_hlen)
                || frame.len() < ip + ip_hlen
                || u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]) & 0x3fff != 0
            {
                return Err(malformed_tx());
            }
            let ip_len = usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]));
            if ip_len < ip_hlen || ip + ip_len != frame.len() {
                return Err(malformed_tx());
            }
            let l4 = ip + ip_hlen;
            match kind {
                narf_net::L4CsumKind::Tcp
                    if frame[ip + 9] == IP_PROTO_TCP
                        && ip_len >= ip_hlen + TCP_MIN_HDR_LEN
                        && usize::from(frame[l4 + 12] >> 4) * 4 >= TCP_MIN_HDR_LEN
                        && l4 + usize::from(frame[l4 + 12] >> 4) * 4 <= frame.len() =>
                {
                    Ok((l4, TCP_CSUM_OFFSET))
                }
                narf_net::L4CsumKind::Udp
                    if frame[ip + 9] == 17
                        && ip_len >= ip_hlen + 8
                        && usize::from(u16::from_be_bytes([frame[l4 + 4], frame[l4 + 5]]))
                            == ip_len - ip_hlen =>
                {
                    Ok((l4, 6))
                }
                _ => Err(malformed_tx()),
            }
        }
        0x86dd => {
            const IPV6_HDR_LEN: usize = 40;
            if frame.len() < ETH_HDR_LEN + IPV6_HDR_LEN || frame[ETH_HDR_LEN] >> 4 != 6 {
                return Err(malformed_tx());
            }
            let payload_len = usize::from(u16::from_be_bytes([
                frame[ETH_HDR_LEN + 4],
                frame[ETH_HDR_LEN + 5],
            ]));
            if ETH_HDR_LEN + IPV6_HDR_LEN + payload_len != frame.len() {
                return Err(malformed_tx());
            }
            let l4 = ETH_HDR_LEN + IPV6_HDR_LEN;
            match kind {
                narf_net::L4CsumKind::Tcp
                    if frame[ETH_HDR_LEN + 6] == IP_PROTO_TCP
                        && payload_len >= TCP_MIN_HDR_LEN
                        && usize::from(frame[l4 + 12] >> 4) * 4 >= TCP_MIN_HDR_LEN
                        && l4 + usize::from(frame[l4 + 12] >> 4) * 4 <= frame.len() =>
                {
                    Ok((l4, TCP_CSUM_OFFSET))
                }
                narf_net::L4CsumKind::Udp
                    if frame[ETH_HDR_LEN + 6] == 17
                        && payload_len >= 8
                        && usize::from(u16::from_be_bytes([frame[l4 + 4], frame[l4 + 5]]))
                            == payload_len =>
                {
                    Ok((l4, 6))
                }
                _ => Err(malformed_tx()),
            }
        }
        _ => Err(malformed_tx()),
    }
}

/// Prepare the virtio-net header for one transmit. This is deliberately
/// feature-gated: a frame carrying partial checksum data or GSO metadata must
/// never reach a device that did not negotiate the matching virtio feature.
pub(crate) fn tx_header_for_frame(
    frame: &mut [u8],
    meta: narf_net::TxMeta,
    profile: TxOffloadProfile,
) -> Result<VirtioNetHdr, VirtioPciError> {
    if frame.is_empty() || meta.vlan_tag.is_some() {
        return Err(malformed_tx());
    }

    match (meta.tso_mss, meta.csum_l4) {
        (Some(_), Some(narf_net::L4CsumKind::Tcp)) => {
            if !profile.tso4_enabled() || frame.len() > MAX_TX_TSO_FRAME {
                return Err(malformed_tx());
            }
            let (l4, csum_offset) = l4_checksum_layout(frame, narf_net::L4CsumKind::Tcp)?;
            let ip = ETH_HDR_LEN;
            // ECN GSO needs the separately negotiated HOST_ECN feature. NARF
            // does not advertise ECN today, so reject instead of emitting an
            // invalid TCPv4 GSO header if a future caller requests it.
            if frame[l4 + 13] & TCP_ECE_OR_CWR != 0 {
                return Err(malformed_tx());
            }
            let tcp_hlen = usize::from(frame[l4 + 12] >> 4) * 4;
            let header_len = l4 + tcp_hlen;
            let mss = meta.tso_mss.expect("matched Some TCP TSO metadata");
            if mss == 0 || frame.len() <= header_len {
                return Err(malformed_tx());
            }
            // For TCP GSO the partial checksum is the pseudo-header with a
            // zero TCP length. The device fills each segment's length before
            // completing the checksum, matching the 8254x TSO preparation.
            let src = [
                frame[ip + 12],
                frame[ip + 13],
                frame[ip + 14],
                frame[ip + 15],
            ];
            let dst = [
                frame[ip + 16],
                frame[ip + 17],
                frame[ip + 18],
                frame[ip + 19],
            ];
            let seed = narf_net::pkt_tcp::ipv4_tcp_pseudo_seed(src, dst, 0);
            frame[l4 + csum_offset..l4 + csum_offset + 2].copy_from_slice(&seed.to_be_bytes());
            Ok(VirtioNetHdr {
                flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
                hdr_len: (header_len as u16).to_le(),
                gso_size: mss.to_le(),
                csum_start: (l4 as u16).to_le(),
                csum_offset: (csum_offset as u16).to_le(),
                num_buffers: 0,
            })
        }
        (Some(_), _) => Err(malformed_tx()),
        (None, Some(kind)) => {
            if !profile.checksum || frame.len() > MAX_RX_FRAME - VIRTIO_NET_HDR_LEN {
                return Err(malformed_tx());
            }
            let (l4, csum_offset) = l4_checksum_layout(frame, kind)?;
            Ok(VirtioNetHdr {
                flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type: VIRTIO_NET_HDR_GSO_NONE,
                csum_start: (l4 as u16).to_le(),
                csum_offset: (csum_offset as u16).to_le(),
                ..VirtioNetHdr::default()
            })
        }
        (None, None) if frame.len() <= MAX_RX_FRAME - VIRTIO_NET_HDR_LEN => {
            Ok(VirtioNetHdr::default())
        }
        (None, None) => Err(malformed_tx()),
    }
}

impl VirtioNetPci {
    /// Bring up the device with RX + TX virtqueues. RX is pre-
    /// populated with `RX_POOL_LEN` empty buffers.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        let cfg_phys = match device.kind {
            narf_bus::BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => 0,
        };
        // SAFETY: bounded walk over identity-mapped cfg.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned device.
        let common = unsafe { map_cap(device, &caps.common) }?;
        // SAFETY: same.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;

        // Reset + ACK + DRIVER.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }

        // Feature negotiation: we only ask for VERSION_1.
        // SAFETY: same.
        let feats_lo = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 0);
            common.read32(CC_DEVICE_FEATURE)
        };
        // SAFETY: same.
        let feats_hi = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 1);
            common.read32(CC_DEVICE_FEATURE)
        };
        let feats = (feats_hi as u64) << 32 | feats_lo as u64;
        if feats & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        // Opportunistic negotiation: take F_MAC / F_STATUS / F_MTU and the
        // checksum/GSO profile when the device offers it. HOST_TSO4 depends
        // on CSUM: a GSO packet must carry VIRTIO_NET_HDR_F_NEEDS_CSUM, and
        // accepting either feature means the matching TX header is emitted
        // below. Do not acknowledge an offload feature merely to inspect it;
        // that would permit a partial packet to reach a device that was never
        // told how to complete it.
        let want_mac = feats & (1u64 << VIRTIO_NET_F_MAC) != 0;
        let want_status = feats & (1u64 << VIRTIO_NET_F_STATUS) != 0;
        let want_mtu = feats & (1u64 << VIRTIO_NET_F_MTU) != 0;
        let want_csum = feats & (1u64 << VIRTIO_NET_F_CSUM) != 0;
        let want_tso4 = want_csum && feats & (1u64 << VIRTIO_NET_F_HOST_TSO4) != 0;
        let want_ctrl_vq = feats & (1u64 << VIRTIO_NET_F_CTRL_VQ) != 0;
        // F_MQ requires F_CTRL_VQ (we can only command the device to
        // enable a pair count through the control queue). Reject MQ
        // when the device skipped F_CTRL_VQ — keeps the pair vector
        // single-entry and avoids a control-queue-less code path.
        let want_mq = (feats & (1u64 << VIRTIO_NET_F_MQ) != 0) && want_ctrl_vq;
        // F_CTRL_MAC_ADDR gates MAC_ADDR_SET via the control queue.
        // Same dependency as F_MQ: needs F_CTRL_VQ first.
        let want_ctrl_mac_addr =
            (feats & (1u64 << VIRTIO_NET_F_CTRL_MAC_ADDR) != 0) && want_ctrl_vq;
        let want_event_idx = feats & (1u64 << VIRTIO_RING_F_EVENT_IDX) != 0;
        // virtio-net F_* bits we care about live in the low 32
        // (max is F_CTRL_MAC_ADDR = 23; RING_F_EVENT_IDX = 29); only
        // F_VERSION_1 = 32 is in the high half.
        let drv_lo = ((1u32 << VIRTIO_NET_F_MAC) * (want_mac as u32))
            | ((1u32 << VIRTIO_NET_F_MTU) * (want_mtu as u32))
            | ((1u32 << VIRTIO_NET_F_CSUM) * (want_csum as u32))
            | ((1u32 << VIRTIO_NET_F_HOST_TSO4) * (want_tso4 as u32))
            | ((1u32 << VIRTIO_NET_F_STATUS) * (want_status as u32))
            | ((1u32 << VIRTIO_NET_F_CTRL_VQ) * (want_ctrl_vq as u32))
            | ((1u32 << VIRTIO_NET_F_MQ) * (want_mq as u32))
            | ((1u32 << VIRTIO_RING_F_EVENT_IDX) * (want_event_idx as u32))
            | ((1u32 << VIRTIO_NET_F_CTRL_MAC_ADDR) * (want_ctrl_mac_addr as u32));
        let drv_hi = 1u32 << (VIRTIO_F_VERSION_1 - 32);
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, drv_lo);
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, drv_hi);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
                    as u8,
            );
        }
        // SAFETY: same.
        let post = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Per-queue setup. Helper to size + program one queue.
        let size_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer, u16, u16), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            // Deepen the ring (was capped at 32) so the RX path has more
            // burst headroom under concurrent off-box load — see
            // RX_POOL_LEN. Still halved from the device max for descriptor
            // headroom, and bounded by what the device actually supports.
            let qsize = qmax.min(256).next_power_of_two() / 2;
            let qsize = if qsize == 0 { 4 } else { qsize.min(qmax) };
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let phys = buf.dma_addr().raw();
            let layout = VirtqueueLayout::new(qsize, phys).ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC, layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
            }
            // SAFETY: same.
            let nof = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            Ok((layout, buf, qsize, nof))
        };
        // Map device-cfg now (pre-queue-setup) — we need it to
        // peek `max_virtqueue_pairs` (§5.1.4) when F_MQ was
        // negotiated. The same mapping is reused further down for
        // MAC / MTU / link-status reads, so map_cap fires once.
        let device_cfg = if let Some(cap) = caps.device_cfg.as_ref() {
            // SAFETY: caller-owned device.
            unsafe { crate::pci::map_cap(device, cap) }.ok()
        } else {
            None
        };
        let mut max_pairs: u16 = 1;
        if want_mq {
            if let Some(r) = device_cfg.as_ref() {
                // SAFETY: device-cfg region was just mapped; u16
                // at offset 8 per §5.1.4.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                let p = unsafe { r.read16(CFG_MAX_VIRTQUEUE_PAIRS) };
                if p >= 1 {
                    max_pairs = p.min(MAX_QUEUE_PAIRS);
                }
            }
        }
        let num_pairs: u16 = if want_mq { max_pairs.max(1) } else { 1 };

        // Bring up `num_pairs` RX/TX pairs at virtqueue indices
        // (0,1), (2,3), ..., (2N-2, 2N-1). The control queue (if
        // F_CTRL_VQ negotiated) sits at index 2*num_pairs.
        // Wide tuple: (rx_layout, rx_buf, rx_qsize, rx_noff, tx_layout, tx_buf, tx_qsize, tx_noff).
        #[allow(clippy::type_complexity)]
        let mut pair_setups: Vec<(
            VirtqueueLayout,
            DmaBuffer,
            u16,
            u16,
            VirtqueueLayout,
            DmaBuffer,
            u16,
            u16,
        )> = Vec::with_capacity(num_pairs as usize);
        for n in 0..num_pairs {
            let rxi = 2 * n;
            let txi = 2 * n + 1;
            let (rx_layout, rx_q_buf, rx_qsize, rx_notify_off) = size_q(rxi)?;
            let (tx_layout, tx_q_buf, tx_qsize, tx_notify_off) = size_q(txi)?;
            pair_setups.push((
                rx_layout,
                rx_q_buf,
                rx_qsize,
                rx_notify_off,
                tx_layout,
                tx_q_buf,
                tx_qsize,
                tx_notify_off,
            ));
        }
        // Control queue is queue `2 * num_pairs` when F_CTRL_VQ was
        // negotiated (§5.1.2). With F_MQ off, num_pairs == 1, so
        // that's queue 2 — matches the legacy single-queue layout.
        let ctrl_qidx: u16 = 2 * num_pairs;
        let ctrl_setup = if want_ctrl_vq {
            size_q(ctrl_qidx).ok()
        } else {
            None
        };

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }

        // Build the per-pair Virtqueue instances and pre-populate
        // each RX with RX_POOL_LEN empty buffers. Per-pair buffer
        // tables so refills in `rx_take` find the slot they came
        // from regardless of which pair handled the arrival.
        let mut pairs: Vec<QueuePair> = Vec::with_capacity(num_pairs as usize);
        for (
            n,
            (
                rx_layout,
                rx_q_buf,
                rx_qsize,
                rx_notify_off,
                tx_layout,
                tx_q_buf,
                tx_qsize,
                tx_notify_off,
            ),
        ) in pair_setups.into_iter().enumerate()
        {
            let rx_qidx = 2 * n as u16;
            let tx_qidx = 2 * n as u16 + 1;
            // SAFETY: Virtqueue::new wipes the layout regions; the
            // backing pages may be recycled (alloc_frame doesn't zero).
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let mut rx_q = unsafe { Virtqueue::new(rx_layout) };
            // SAFETY: same.
            let mut tx_q = unsafe { Virtqueue::new(tx_layout) };
            // Enable the EVENT_IDX notification protocol if negotiated (both
            // rings): TX gets avail_event-gated kick suppression, RX publishes
            // used_event so the device still interrupts on new frames.
            rx_q.set_event_idx(want_event_idx);
            tx_q.set_event_idx(want_event_idx);

            let mut rx_buffers: Vec<Option<DmaBuffer>> = (0..rx_qsize).map(|_| None).collect();
            let posted = RX_POOL_LEN.min(rx_qsize as usize);
            for _ in 0..posted {
                let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| VirtioPciError::BarMapFailed)?;
                let phys = buf.dma_addr().raw();
                let descs = [VirtqDesc {
                    addr: phys,
                    len: MAX_RX_FRAME as u32,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                }];
                if let Some(head) = rx_q.add_buffer(&descs) {
                    rx_buffers[head as usize] = Some(buf);
                }
            }

            // Kick the device about the freshly-posted RX buffers.
            let rx_off = (rx_notify_off as u64) * (notify_off_multiplier as u64);
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped notify region.
            unsafe {
                notify.write16(rx_off, rx_qidx);
            }

            // Per-descriptor in-flight TX buffer table, sized to the
            // TX queue. A submitted frame's `DmaBuffer` parks here at
            // its descriptor head until the device publishes the
            // completion (lazily reclaimed before the next transmit).
            let tx_buffers: Vec<Option<DmaBuffer>> = (0..tx_qsize).map(|_| None).collect();
            // One fixed-capacity recycler per hardware queue pair. Preparation
            // and allocation happen before the queues are exposed; RX/TX and
            // completion paths only pop/push their own queue-local pool.
            let tx_pool = Arc::new(DmaPool::new(TX_BUF_LEN, DomainId::DRIVER_0, TX_POOL_CAP));
            let rx_pool = DmaPool::new(4096, DomainId::DRIVER_0, RX_POOL_CAP);

            pairs.push(QueuePair {
                rx_qidx,
                tx_qidx,
                rx_queue: IrqSafeSpinLock::new(Some(rx_q)),
                tx_queue: IrqSafeSpinLock::new(Some(tx_q)),
                rx_buffers: IrqSafeSpinLock::new(rx_buffers),
                tx_buffers: IrqSafeSpinLock::new(tx_buffers),
                tx_pool,
                rx_pool,
                _rx_q_buf: rx_q_buf,
                _tx_q_buf: tx_q_buf,
                rx_qsize,
                tx_qsize,
                rx_notify_off,
                tx_notify_off,
            });
        }

        // Build the CtrlQueue handle now that we have the layout
        // tuple from the optional size_q call earlier.
        let ctrl = match ctrl_setup {
            Some((c_layout, c_layout_buf, _c_qsize, c_notify_off)) => {
                let ctrl_buf = alloc_coherent(4096, DomainId::DRIVER_0)
                    .map_err(|_| VirtioPciError::BarMapFailed)?;
                // SAFETY: Virtqueue::new zeros the layout regions.
                let mut q = unsafe { Virtqueue::new(c_layout) };
                q.set_event_idx(want_event_idx);
                Some(IrqSafeSpinLock::new(CtrlQueue {
                    q,
                    buf: ctrl_buf,
                    notify_off: c_notify_off,
                    _layout_buf: c_layout_buf,
                }))
            }
            None => None,
        };

        // Read MAC + MTU + status from device-cfg, gated on whether
        // the feature was negotiated. Spec: the corresponding field
        // is only valid when its feature was negotiated.
        let mut mac = [0u8; 6];
        let mut mtu: u32 = 1500;
        let mut link_up_init = true;
        if let Some(r) = device_cfg.as_ref() {
            if want_mac {
                for i in 0..6u64 {
                    // SAFETY: device-cfg region was just mapped; MAC field at offset 0..6.
                    mac[i as usize] = unsafe { r.read8(CFG_MAC + i) };
                }
            }
            if want_status {
                // SAFETY: same. Status at offset 6 (u16 LE).
                let s = unsafe { r.read16(CFG_STATUS) };
                link_up_init = s & VIRTIO_NET_S_LINK_UP != 0;
            }
            if want_mtu {
                // SAFETY: same. MTU at offset 10 (u16 LE).
                let m = unsafe { r.read16(CFG_MTU) };
                if m >= 64 {
                    mtu = m as u32;
                }
            }
        }
        // Stash an initial link-state guess on the controller so
        // accessors don't need to re-read MMIO on every poll.
        let _ = link_up_init;

        let mut this = Self {
            common,
            notify,
            device_cfg,
            notify_off_multiplier,
            pairs,
            tx_rr: AtomicU64::new(0),
            irq_vector: None,
            rx_irq_vectors: alloc::vec::Vec::new(),
            flow_affine: false,
            tx_irq_vector: None,
            msix: None,
            ready: true,
            mac: IrqSafeSpinLock::new(mac),
            has_ctrl_mac_addr: want_ctrl_mac_addr,
            mtu,
            has_status: want_status,
            tx_checksum: want_csum,
            tx_tso4: want_tso4,
            ctrl_qidx,
            ctrl,
            cfg_phys,
        };

        // Preparation is deliberately outside all packet/IRQ paths. A failed
        // prefill leaves only that queue backpressured rather than smuggling a
        // buddy allocation into its poll loop.
        for pair in &this.pairs {
            let _ = pair.tx_pool.prefill(TX_POOL_CAP);
            let _ = pair.rx_pool.prefill(RX_POOL_CAP);
        }

        // VirtIO 1.2 §5.1.6.5.5: after DRIVER_OK, tell the device
        // how many queue pairs to actually use. Without this command
        // the device defaults to a single pair even though we
        // brought up more — frames would silently disappear from
        // pairs 1..N. Best-effort: if the command fails (device
        // refused, or no ctrl queue despite F_MQ being set, which
        // shouldn't happen but isn't worth panicking over), fall
        // back to using just pair 0.
        if want_mq && num_pairs > 1 {
            match this.submit_control(
                VIRTIO_NET_CTRL_MQ,
                VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET,
                &num_pairs.to_le_bytes(),
            ) {
                Ok(VIRTIO_NET_OK) => {}
                _ => {
                    // Device rejected the MQ command. Truncate down
                    // to a single pair — the extra rings stay
                    // allocated but unused, which is fine for now.
                    this.pairs.truncate(1);
                }
            }
        }
        Ok(this)
    }

    /// Phys address of this controller's PCIe config space. Used by
    /// the probe-time dedupe check + diagnostics.
    pub fn cfg_phys(&self) -> u64 {
        self.cfg_phys
    }

    /// Bind the receiveq pair-0 (queue 0) to a fresh MSI-X vector.
    /// After this call, frame-arrival on the primary pair is
    /// observable via
    /// `narf_interrupts::wait_for_irq(self.irq_vector.unwrap())`.
    /// RX pairs 1..N rely on the 16 ms polling fallback in their
    /// forwarders — per-queue MSI-X for the MQ case is a follow-up.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-owns the device.
        let (v, table) = unsafe { crate::pci::enable_msix_queue(&self.common, cap, device, 0) }?;
        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Bind EVERY active RX queue pair to its own MSI-X vector, each routed
    /// to the CPU its forwarder will run on, so no forwarder has to fall
    /// back to a blind 2ms poll sleep between sparse frames. This is the
    /// multi-queue completion of [`Self::enable_msix`] (which wired only
    /// pair 0). The per-pair routing CPU mirrors the forwarder placement in
    /// the RX-forwarder spawn (`partition` ⇒ pair K → CPU K, else CPU 0) so
    /// the RX IRQ lands locally on the core that services the queue.
    ///
    /// Best-effort per pair: a pair that can't get a vector (MSI-X table
    /// full, IDT exhausted) keeps `None` and its forwarder polls — correct,
    /// just without the IRQ fast-path on that queue. `irq_vector` is kept
    /// pointing at pair 0 for back-compat.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively (probe, before
    /// the controller is shared into `CONTROLLERS`).
    pub unsafe fn enable_rx_msix_all(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(), VirtioPciError> {
        let num_pairs = self.pairs.len();
        // Mirror the forwarder placement decision (see the RX-forwarder
        // spawn): with enough cores, pair K's forwarder is pinned to CPU K;
        // otherwise all forwarders share the BSP. Route each queue's IRQ to
        // the same CPU so the wake is local.
        let online = narf_lib::smp::online_count() as usize;
        let partition = num_pairs >= 2 && online > num_pairs;
        // Gate flow-affine TX on the same condition (see the `flow_affine`
        // field): sticky-queue TX only helps when forwarders own distinct CPUs.
        self.flow_affine = partition;
        // Per-queue MSI-X only PAYS OFF when each forwarder owns a core
        // (`partition`): then pair K's RX IRQ lands on CPU K, a dedicated
        // forwarder core, waking it without disturbing any worker. When
        // forwarders SHARE a core with workers (`!partition` — a single-vCPU
        // guest, or a single-threaded server like redis), an extra queue's IRQ
        // instead INTERRUPTS the busy worker core on every burst (~5% redis
        // throughput at smp=1). So bind a vector for pairs 1..N only under
        // `partition`; pair 0 always keeps its (BSP) MSI-X. Ungated pairs fall
        // back to the polled cadence — exactly the pre-per-queue behaviour.
        let msix_pairs = if partition { num_pairs } else { 1 };
        let mut targets: alloc::vec::Vec<(u16, u32)> = alloc::vec::Vec::with_capacity(msix_pairs);
        for k in 0..msix_pairs {
            let cpu = if partition { k } else { 0 };
            // Fall back to the BSP's APIC id (cpu 0) if the topology lookup
            // fails — delivery still works, just not core-local.
            let apic = narf_interrupts::apic_id_at(cpu)
                .or_else(|| narf_interrupts::apic_id_at(0))
                .unwrap_or(0);
            targets.push((2 * k as u16, apic));
        }
        // SAFETY: caller owns the device exclusively.
        let (table, vectors) =
            unsafe { crate::pci::enable_msix_rx_queues(&self.common, cap, device, &targets) }?;
        self.irq_vector = vectors.first().copied().flatten();
        self.rx_irq_vectors = vectors;
        self.msix = Some(table);
        Ok(())
    }

    /// TX-queue MSI-X for pair 0 (queue index 1). Reuses the
    /// existing `MsixTable` if RX MSI-X is already enabled — both
    /// vectors land on the same MSI-X table.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively.
    pub unsafe fn enable_tx_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // SAFETY: caller-owns the device.
        let (v, table) = unsafe { crate::pci::enable_msix_queue(&self.common, cap, device, 1) }?;
        self.tx_irq_vector = Some(v);
        // Replace the MSI-X table handle with the latest one
        // (enable_msix_queue allocates a fresh slot in the
        // existing table; there's only one table per device,
        // and the new handle keeps both vectors live).
        self.msix = Some(table);
        Ok(v)
    }

    /// Number of active TX/RX queue pairs after `bring_up` (and
    /// after the optional `VQ_PAIRS_SET` ack). Always ≥ 1.
    pub fn num_pairs(&self) -> usize {
        self.pairs.len()
    }

    fn tx_offload_profile(&self) -> TxOffloadProfile {
        TxOffloadProfile {
            checksum: self.tx_checksum,
            tso4: self.tx_tso4,
        }
    }

    /// Round-robin TX-pair pick. `tx_dma` calls this to spread
    /// outbound frames across pairs without callers having to know
    /// the pair count. Wraps via modulo — safe on overflow because
    /// AtomicU64 wraps and modulo is unaffected by the wrap.
    fn next_tx_pair(&self) -> usize {
        // Relaxed: the only invariant is "two concurrent calls get
        // different-ish indices over time". No data is published
        // through this counter — the per-pair virtqueue lock is the
        // real synchroniser.
        let n = self.tx_rr.fetch_add(1, Ordering::Relaxed);
        (n as usize) % self.pairs.len()
    }

    /// Pick the TX pair for a frame by hashing its flow 4-tuple, so every
    /// segment of a connection leaves on the SAME virtio TX queue.
    ///
    /// Why this matters: the host tun driver (multi-queue tap) records a
    /// flow→queue map from the guest's TX (`tun_flow_update`) and replays it
    /// to steer that flow's RX (`tun_select_queue`). So the guest's TX queue
    /// choice *determines* RX stickiness. The old [`Self::next_tx_pair`]
    /// round-robin bumped a single global counter per TX, so a connection's
    /// segments fanned across queues 0,1,0,1… — the host re-steered its RX
    /// every round and the flow never settled on one forwarder/CPU. Hashing
    /// the 4-tuple keeps a flow pinned to one TX queue → one RX queue → one
    /// forwarder (pair K → CPU K), i.e. the connection becomes sticky to a
    /// core (Linux RSS+RFS). Falls back to round-robin for ARP / IPv6 /
    /// non-TCP-UDP, which are low-volume and don't need affinity.
    ///
    /// `frame` is the Ethernet frame (no virtio header). The hash is
    /// symmetric in (src,dst) so it composes with later worker co-location.
    fn tx_pair_for_frame(&self, frame: &[u8]) -> usize {
        let npairs = self.pairs.len();
        if npairs <= 1 {
            return 0;
        }
        flow_tx_pair(frame, npairs).unwrap_or_else(|| self.next_tx_pair())
    }

    /// Take a prepared 64 KiB TX DMA buffer from one queue pair, or return
    /// `None` for backpressure. Pairs with `tx_buf_release_on`; never
    /// allocates in the packet path.
    fn tx_buf_acquire_on(&self, pair_idx: usize) -> Option<DmaBuffer> {
        let pair = self.pairs.get(pair_idx)?;
        pair.tx_pool.try_acquire().or_else(|| {
            // Reclaim before requiring another buffer: once the fixed pool
            // empties, submit-time reclaim is otherwise unreachable (#704).
            let mut queue = pair.tx_queue.lock();
            let q = queue.as_mut()?;
            let mut bufs = pair.tx_buffers.lock();
            pair.reclaim_tx(q, &mut bufs);
            pair.tx_pool.try_acquire()
        })
    }

    /// Return a completed TX DMA buffer to its submitting queue's recycler, or
    /// drop it (freeing) when that bounded queue pool is already full.
    fn tx_buf_release_on(&self, pair_idx: usize, buf: DmaBuffer) {
        if let Some(pair) = self.pairs.get(pair_idx) {
            pair.tx_pool.release(buf);
        }
    }

    /// Take a prepared 4 KiB RX DMA buffer from a queue pair. The device
    /// overwrites the whole buffer on receive, so recycled (un-zeroed) storage
    /// is safe. `None` applies queue-local backpressure; it never falls back
    /// to allocation. Pairs with [`Self::rx_buf_release_on`].
    pub fn rx_buf_acquire_on(&self, pair_idx: usize) -> Option<DmaBuffer> {
        self.pairs.get(pair_idx)?.rx_pool.try_acquire()
    }

    /// Compatibility shorthand for pair zero. Multi-queue paths must use
    /// [`Self::rx_buf_acquire_on`] to preserve queue locality.
    pub fn rx_buf_acquire(&self) -> Option<DmaBuffer> {
        self.rx_buf_acquire_on(0)
    }

    /// Return a fully-consumed RX DMA buffer to the queue that supplied it,
    /// or drop it (freeing) when that bounded pool is already full.
    pub fn rx_buf_release_on(&self, pair_idx: usize, buf: DmaBuffer) {
        if let Some(pair) = self.pairs.get(pair_idx) {
            pair.rx_pool.release(buf);
        }
    }

    /// Compatibility shorthand for pair zero. Multi-queue paths must use
    /// [`Self::rx_buf_release_on`] to preserve queue locality.
    pub fn rx_buf_release(&self, buf: DmaBuffer) {
        self.rx_buf_release_on(0, buf);
    }

    /// Transmit a plain frame backed by a caller-owned `DmaBuffer`,
    /// fire-and-forget (Linux-style). The virtio-net header occupies
    /// `buf[..VIRTIO_NET_HDR_LEN]`; the frame starts immediately after it.
    /// The function takes the buffer by value and parks it in the selected
    /// queue's in-flight table until completion, so it never waits for device
    /// DMA and callers must not retain the buffer.
    pub fn tx_dma(&self, buf: DmaBuffer, frame_len: u32) -> Result<(), VirtioPciError> {
        // Flow-affine TX (hash the 4-tuple → sticky queue/forwarder/CPU, see
        // `tx_pair_for_frame`) ONLY when `flow_affine` (forwarders own
        // dedicated cores). Validated +19% over round-robin at Q=4 CONNS=64
        // with per-queue MSI-X. Otherwise round-robin: cheaper (no per-TX hash)
        // and better-balanced for shared-core / single-threaded servers —
        // exactly pre-RSS behaviour, zero added cost. Frame body begins just
        // after the virtio header.
        let pair_idx = if self.flow_affine {
            let end = (VIRTIO_NET_HDR_LEN + frame_len as usize).min(buf.len());
            let frame = buf.as_slice().get(VIRTIO_NET_HDR_LEN..end).unwrap_or(&[]);
            self.tx_pair_for_frame(frame)
        } else {
            self.next_tx_pair()
        };
        self.tx_dma_on(pair_idx, buf, frame_len)
    }

    /// Like `tx_dma` but submits on a specific pair. Used by the
    /// TX forwarder (already picks the pair, doesn't need to
    /// re-roll the round-robin) and by tests that want to exercise
    /// a particular queue.
    ///
    /// See [`Self::tx_dma`] for the buffer layout contract and the
    /// fire-and-forget / lazy-reclaim ownership model.
    pub fn tx_dma_on(
        &self,
        pair_idx: usize,
        buf: DmaBuffer,
        frame_len: u32,
    ) -> Result<(), VirtioPciError> {
        self.tx_dma_on_with_meta(pair_idx, buf, frame_len, narf_net::TxMeta::plain())
    }

    /// Submit one frame with the offload metadata supplied by the stack. The
    /// legacy public `tx_dma_on` wrapper above remains plain-frame-only for
    /// callers that do not participate in the frame-ring contract.
    fn tx_dma_on_with_meta(
        &self,
        pair_idx: usize,
        mut buf: DmaBuffer,
        frame_len: u32,
        meta: narf_net::TxMeta,
    ) -> Result<(), VirtioPciError> {
        let pair = self.pairs.get(pair_idx).ok_or(VirtioPciError::NoQueues)?;
        let frame_len = frame_len as usize;
        if frame_len == 0 || frame_len > MAX_TX_TSO_FRAME {
            return Err(VirtioPciError::QueueTooSmall);
        }
        // Total device-readable region: virtio header + frame body.
        let total_len = VIRTIO_NET_HDR_LEN + frame_len;
        if total_len > buf.len() {
            return Err(VirtioPciError::QueueTooSmall);
        }
        // Prepend a per-packet virtio-net header into the payload buffer
        // itself. No shared scratch → no header race even with many in-flight
        // transmits. `tx_header_for_frame` rejects unsupported metadata before
        // publishing anything to the device.
        {
            let slice = buf.as_mut_slice();
            let header = tx_header_for_frame(
                &mut slice[VIRTIO_NET_HDR_LEN..total_len],
                meta,
                self.tx_offload_profile(),
            )?;
            write_tx_header(&mut slice[..VIRTIO_NET_HDR_LEN], header);
        }
        let buf_phys = buf.dma_addr().raw();

        // Single device-readable descriptor over [hdr | frame].
        let submit = |q: &mut Virtqueue| -> Option<u16> {
            let descs = [VirtqDesc {
                addr: buf_phys,
                len: total_len as u32,
                flags: 0,
                next: 0,
            }];
            q.add_buffer(&descs)
        };

        // Serialize completion reclaim, descriptor submission, and DMA-buffer
        // publication under the same queue/buffer lock pair. The previous
        // split critical sections released `tx_queue` after `add_buffer()` and
        // recorded `buf` in `tx_buffers` only afterwards. A parallel sender
        // could reclaim a very fast completion in that window, find an empty
        // slot, and free the descriptor. The first sender then parked its
        // already-completed buffer under that re-usable head, permanently
        // starving the queue-local recycler under multi-flow traffic.
        //
        // The queue lock is always taken before `tx_buffers`, so publishing
        // the buffer before either lock is released closes that ownership hole
        // without changing lock order. If the ring stays full, return the
        // caller-owned recycler buffer before reporting backpressure; otherwise
        // every transient full ring also drains the fixed TX pool.
        let needs_kick = {
            let mut q = pair.tx_queue.lock();
            let q = q.as_mut().ok_or(VirtioPciError::NoQueues)?;
            let mut bufs = pair.tx_buffers.lock();

            // Lazy completion reclaim: drain every TX the device has finished
            // since the last transmit. A descriptor can be reused only after
            // its paired DMA buffer has been returned to this queue's pool.
            pair.reclaim_tx(q, &mut bufs);

            let head = match submit(q) {
                Some(h) => h,
                None => {
                    // Ring full. Bounded retry: re-drain completions a
                    // few times. Each pass can only free what the device
                    // has already finished — no spinning on un-finished
                    // work, no unbounded sync wait.
                    let mut retried = None;
                    for _ in 0..8 {
                        if !pair.reclaim_tx(q, &mut bufs) {
                            break;
                        }
                        if let Some(h) = submit(q) {
                            retried = Some(h);
                            break;
                        }
                    }
                    // Still full after draining everything the device
                    // finished → return the buffer and report backpressure.
                    match retried {
                        Some(h) => h,
                        None => {
                            self.tx_buf_release_on(pair_idx, buf);
                            return Err(VirtioPciError::QueueTooSmall);
                        }
                    }
                }
            };
            // `head` is produced by this pair's virtqueue and is therefore in
            // `0..tx_qsize`, exactly the range of `tx_buffers`. Publish before
            // another sender can reclaim the descriptor.
            bufs[head as usize] = Some(buf);
            // `TxMeta::more` is Linux's xmit_more hint: defer the expensive
            // notify VM-exit until the ordered burst ends. Flush at either
            // descriptor or buffer exhaustion: the 32-buffer pool can empty
            // well before the 128-entry ring fills, preventing a later frame
            // from delivering the burst's final notify (#704). Once a flush
            // is required, `needs_kick` remains the EVENT_IDX authority.
            let ring_full = q.diagnostic_snapshot().3 == 0;
            if !meta.more || ring_full || pair.tx_pool.available() == 0 {
                q.needs_kick() || (TX_ALWAYS_KICK.load(Ordering::Relaxed) && !meta.more)
            } else {
                false
            }
        };

        if needs_kick {
            let off = (pair.tx_notify_off as u64) * (self.notify_off_multiplier as u64);
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped. Fire-and-forget: kick the device
            // and return — completion is reclaimed lazily on the next TX.
            unsafe {
                self.notify.write16(off, pair.tx_qidx);
            }
        }
        Ok(())
    }

    /// Queue size for the primary RX pair (pair 0). Kept as a
    /// shorthand for tests that don't care about MQ specifics.
    pub fn rx_queue_size(&self) -> u16 {
        self.pairs.first().map(|p| p.rx_qsize).unwrap_or(0)
    }
    /// Queue size for the primary TX pair (pair 0).
    pub fn tx_queue_size(&self) -> u16 {
        self.pairs.first().map(|p| p.tx_qsize).unwrap_or(0)
    }

    /// 48-bit hardware address. Zero when `VIRTIO_NET_F_MAC` wasn't
    /// negotiated (rare; QEMU advertises a vendor-default MAC).
    /// Reflects the latest value committed via `set_mac` if the
    /// driver reassigned the address post-probe.
    pub fn mac(&self) -> [u8; 6] {
        *self.mac.lock()
    }

    /// Reassign the device's hardware address via
    /// `VIRTIO_NET_CTRL_MAC_ADDR_SET` (VirtIO 1.2 §5.1.6.5.2).
    /// Requires `VIRTIO_NET_F_CTRL_MAC_ADDR` to have been
    /// negotiated. Updates the cached MAC on success so `mac()`
    /// returns the new value immediately.
    pub fn set_mac(&self, mac: [u8; 6]) -> Result<(), VirtioPciError> {
        if !self.has_ctrl_mac_addr {
            return Err(VirtioPciError::NoQueues);
        }
        let ack = self.submit_control(VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET, &mac)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        *self.mac.lock() = mac;
        Ok(())
    }

    /// Negotiated MTU. Defaults to 1500 when `VIRTIO_NET_F_MTU`
    /// wasn't offered.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Live link state. Reads the status word from device-cfg every
    /// call when `VIRTIO_NET_F_STATUS` was negotiated; returns
    /// `true` unconditionally otherwise (spec: absence of the
    /// feature means assume link up).
    pub fn link_up(&self) -> bool {
        if !self.has_status {
            return true;
        }
        let r = match self.device_cfg.as_ref() {
            Some(r) => r,
            None => return true,
        };
        // SAFETY: device-cfg region was mapped at bring_up; field
        // at offset 6 stays valid for the controller's lifetime.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let s = unsafe { r.read16(CFG_STATUS) };
        s & VIRTIO_NET_S_LINK_UP != 0
    }

    /// `true` iff this controller negotiated F_CTRL_VQ and has a
    /// working control queue. Callers gate `set_promisc` /
    /// `set_allmulti` etc. on this.
    pub fn has_ctrl_vq(&self) -> bool {
        self.ctrl.is_some()
    }

    /// Submit one control command to virtqueue 2 and wait for the
    /// device's 1-byte ack. The chain is [hdr, payload, ack]
    /// (device-readable, device-readable, device-writable). Returns
    /// the ack byte — `VIRTIO_NET_OK` (0) on success, anything else
    /// is a device-side error.
    ///
    /// Single-flight per controller — the outer lock serialises
    /// callers, so concurrent set_promisc + set_allmulti pairs are
    /// fine but interleaving is sequential. Control commands are
    /// rare (PHY-driven events), so no contention concern.
    pub fn submit_control(&self, class: u8, cmd: u8, payload: &[u8]) -> Result<u8, VirtioPciError> {
        let ctrl = self.ctrl.as_ref().ok_or(VirtioPciError::NoQueues)?;
        let mut g = ctrl.lock();
        // Layout within `buf`:
        //   0..2     hdr  (class, cmd)         device-readable
        //   16..16+N payload                    device-readable
        //   256..257 ack                        device-writable
        // The 256-byte stride leaves slack for ≤240 byte payloads
        // — covers RX_MODE (1 byte) and MAC_ADDR_SET (6 bytes)
        // trivially. Larger payloads (MAC_TABLE_SET with many
        // entries) will need a per-call allocation later.
        if payload.len() > 240 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let phys = g.buf.dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; the offsets stay
        // within the 4 KiB page allocated above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            core::ptr::write_volatile(g.buf.cpu_mut_ptr::<u8>(), class);
            core::ptr::write_volatile(g.buf.cpu_mut_ptr_at::<u8>(1), cmd);
            for (i, b) in payload.iter().enumerate() {
                core::ptr::write_volatile(g.buf.cpu_mut_ptr_at::<u8>(16 + i as u64), *b);
            }
            // Seed the ack byte with a sentinel so we can spot
            // "device didn't write anything".
            core::ptr::write_volatile(g.buf.cpu_mut_ptr_at::<u8>(256), 0xFF);
        }
        let descs = [
            VirtqDesc {
                addr: phys,
                len: 2,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: phys + 16,
                len: payload.len() as u32,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: phys + 256,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head =
            g.q.add_buffer(&descs)
                .ok_or(VirtioPciError::QueueTooSmall)?;
        let notify_off = (g.notify_off as u64) * (self.notify_off_multiplier as u64);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region. Notify the runtime
        // controlq index — it shifts based on `num_pairs` when F_MQ
        // is negotiated (§5.1.2).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.notify.write16(notify_off, self.ctrl_qidx);
        }
        // Spin for completion while letting sleep_pumps tick.
        let done = narf_scheduler::responsive_spin_until(
            || matches!(g.q.poll_used(), Some((id, _)) if id == head as u32),
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            return Err(VirtioPciError::QueueTooSmall);
        }
        g.q.free_chain(head);
        // SAFETY: device wrote the ack byte before publishing the
        // used-ring entry; identity-mapped read.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let ack = unsafe { core::ptr::read_volatile(g.buf.cpu_ptr_at::<u8>(256)) };
        Ok(ack)
    }

    /// Convenience wrapper for `VIRTIO_NET_CTRL_RX_PROMISC`. Asks
    /// the device to enable / disable promiscuous mode (deliver
    /// every frame to RX, even those destined for other MACs).
    /// Returns `Err` if the device didn't negotiate F_CTRL_VQ or
    /// the ack wasn't `VIRTIO_NET_OK`.
    pub fn set_promisc(&self, on: bool) -> Result<(), VirtioPciError> {
        let payload = [u8::from(on)];
        let ack = self.submit_control(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, &payload)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Convenience wrapper for `VIRTIO_NET_CTRL_RX_ALLMULTI`.
    /// Requests delivery of every multicast frame regardless of the
    /// MAC-filter list — useful for IPv6 NDP / mDNS consumers
    /// without per-address filter setup.
    pub fn set_allmulti(&self, on: bool) -> Result<(), VirtioPciError> {
        let payload = [u8::from(on)];
        let ack = self.submit_control(VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_ALLMULTI, &payload)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Take ownership of one device-filled RX frame from pair 0.
    /// Shorthand for `rx_take_on(0)`; kept for tests that don't
    /// care about MQ specifics.
    pub fn rx_take(&self) -> Option<(DmaBuffer, u32)> {
        self.rx_take_on(0)
    }

    /// Take ownership of one device-filled RX frame from the given
    /// pair. Zero-copy: returns the actual `DmaBuffer` the device
    /// wrote into + total bytes (including the 12-byte virtio-net
    /// header). Allocates a replacement buffer and re-posts it in
    /// the avail ring before returning so the device always has a
    /// place to land the next frame.
    ///
    /// Returns `None` if the pair index is out of range, the used
    /// ring is empty, or the replacement allocation fails (in which
    /// case the original stays in place — the device-filled buffer
    /// is not surrendered until the refill is guaranteed).
    /// Arm this RX pair's used-ring interrupt and report whether a completion is
    /// ALREADY pending — the `virtqueue_enable_cb` re-check a forwarder runs
    /// right before it parks, so a suppressed/coalesced RX interrupt can't
    /// strand a frame in the ring until the poll backstop deadline. `false` for
    /// a missing pair/queue (nothing to wait on).
    pub fn rx_arm_and_pending(&self, pair_idx: usize) -> bool {
        let Some(pair) = self.pairs.get(pair_idx) else {
            return false;
        };
        let mut g = pair.rx_queue.lock();
        match g.as_mut() {
            Some(q) => q.enable_used_cb_and_pending(),
            None => false,
        }
    }

    /// NAPI: suppress RX used-ring interrupts while the forwarder sustained-polls
    /// this pair (see `Virtqueue::disable_used_cb`). Re-armed at park via
    /// `rx_arm_and_pending`.
    pub fn rx_disable_cb(&self, pair_idx: usize) {
        if let Some(pair) = self.pairs.get(pair_idx) {
            if let Some(q) = pair.rx_queue.lock().as_mut() {
                q.disable_used_cb();
            }
        }
    }

    pub fn rx_take_on(&self, pair_idx: usize) -> Option<(DmaBuffer, u32)> {
        let pair = self.pairs.get(pair_idx)?;
        let elem = {
            let mut g = pair.rx_queue.lock();
            let q = g.as_mut()?;
            q.poll_used()
        };
        let (id, len) = elem?;
        let head = id as u16;
        // Allocate the replacement up front. If we can't, we leave
        // the device-filled buffer parked in its slot and return
        // None — better than handing the stack a frame and losing
        // the refill slot.
        let replacement = self.rx_buf_acquire_on(pair_idx)?;
        let rep_phys = replacement.dma_addr().raw();
        // Now swap: take the original out of its slot, free the
        // descriptor chain, post the replacement, stash it under
        // its new head index.
        let original = {
            let mut bufs = pair.rx_buffers.lock();
            bufs.get_mut(head as usize).and_then(|s| s.take())?
        };
        let new_head = {
            let mut g = pair.rx_queue.lock();
            let q = match g.as_mut() {
                Some(q) => q,
                None => {
                    // Queue vanished — return the original to its
                    // slot so we don't lose it.
                    pair.rx_buffers.lock()[head as usize] = Some(original);
                    return None;
                }
            };
            q.free_chain(head);
            let descs = [VirtqDesc {
                addr: rep_phys,
                len: MAX_RX_FRAME as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            }];
            match q.add_buffer(&descs) {
                Some(h) => h,
                None => {
                    // Refill failed: device is one descriptor down
                    // until the next caller frees one. Return the
                    // original anyway — the stack already drained
                    // it logically.
                    drop(replacement);
                    return Some((original, len));
                }
            }
        };
        // Park the replacement in its slot for the next rx_take.
        pair.rx_buffers.lock()[new_head as usize] = Some(replacement);
        Some((original, len))
    }

    /// Notify the device that new RX buffers have been posted to the avail ring.
    /// This should be called *after* a batch of `rx_take`s to avoid kicking
    /// the device synchronously for every single frame (mimicking Linux NAPI).
    pub fn rx_notify(&self, pair_idx: usize) {
        if let Some(pair) = self.pairs.get(pair_idx) {
            let needs_kick = {
                pair.rx_queue
                    .lock()
                    .as_mut()
                    .is_some_and(|q| q.needs_kick())
            };
            if needs_kick {
                let off = (pair.rx_notify_off as u64) * (self.notify_off_multiplier as u64);
                compiler_fence(Ordering::SeqCst);
                // SAFETY: identity-mapped notify region.
                unsafe {
                    self.notify.write16(off, pair.rx_qidx);
                }
            }
        }
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Every bound virtio-net device. A modern host can attach more than
/// one virtio-net controller (separate vlans, separate netdevs); the
/// singleton-Option shape used to swallow the second probe — match
/// the virtio-input fix and keep all bound devices.
// Bound controllers held behind `Arc` so `with_at` / `with_controller` /
// `with_each` can clone the handle out under the lock and then DROP the
// lock before running the caller's closure. Holding this IrqSafeSpinLock
// across the closure deadlocks: `vnet0_send_fn` → `with_controller` (lock
// held) → `tx_dma` → `responsive_spin_until` runs `sleep_pumps`, which can
// re-enter `with_at`/`with_controller` → re-locks CONTROLLERS → spins
// forever with IRQs disabled on the single cooperative CPU (the lock
// holder never resumes to release it). Cloning the Arc out first means the
// closure — and any re-entrant net_pci call it makes via the sleep-pump
// spin — runs with the lock released. Controllers are append-only after
// probe, so a stale clone is never freed mid-use.
//
// `pub(crate)` so the e2e re-entrancy regression test can assert the lock
// is released while a `with_*` closure runs (`smoke_e2e_net_with_at_*`).
pub(crate) static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<VirtioNetPci>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Symmetric per-flow hash of an Ethernet frame → TX pair index in
/// `0..npairs`. Returns `None` for frames that aren't IPv4/TCP-UDP (ARP,
/// IPv6, IP options we don't parse) so the caller can fall back to
/// round-robin. See [`VirtioNetPci::tx_pair_for_frame`] for why a flow must
/// stay pinned to one queue.
///
/// Parses Ethernet (14-byte header) → IPv4 → TCP/UDP ports. The hash folds
/// (src⊕dst, sport⊕dport) so it's identical for both directions of a flow
/// (matching the host tun's `__skb_get_hash_symmetric`), then runs an
/// xorshift-multiply finaliser so the low bits (which `% npairs` selects)
/// depend on the whole tuple rather than just the port LSBs.
fn flow_tx_pair(frame: &[u8], npairs: usize) -> Option<usize> {
    if npairs <= 1 {
        return Some(0);
    }
    // TX HOT PATH — one call per transmitted frame, so it must be cheap. The
    // queue is a pure function of the 4-tuple (constant per connection), so we
    // only need a fast, consistent hash, not a parser. Fast path for the
    // overwhelming common case: IPv4 with a 20-byte header (no options).
    // ethertype 0x0800 at [12..14]; IPv4 version+IHL 0x45 at [14]. With
    // eth(14) + ip(20): src_ip [26..30], dst_ip [30..34], L4 ports [34..38].
    // After the single `len() < 38` check the compiler proves every fixed
    // index in-bounds and elides the per-field bounds checks. Anything else
    // (IPv6, IP options, runt, non-0x45) → None → caller round-robins (those
    // are low-volume; flow affinity doesn't matter for them).
    if frame.len() < 38 || frame[12] != 0x08 || frame[13] != 0x00 || frame[14] != 0x45 {
        return None;
    }
    // Endianness is irrelevant for a hash — only per-flow consistency matters.
    // `ports.rotate_left(16) ^ ports` and `src ^ dst` are symmetric in
    // (src,dst)/(sport,dport), so the hash is identical for either flow
    // direction (matches the host tun's symmetric steering). One
    // xorshift-multiply finaliser scatters the low bits `% npairs` selects.
    let src = [frame[26], frame[27], frame[28], frame[29]];
    let dst = [frame[30], frame[31], frame[32], frame[33]];
    let src_port = u16::from_be_bytes([frame[34], frame[35]]);
    let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
    Some(narf_net::ipv4_flow_queue(
        src, dst, src_port, dst_port, npairs,
    ))
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // Dedupe: tests that reset the bus driver-match registry and
    // re-walk PCI would otherwise push a second controller for
    // the same device. Match by config-space phys address — every
    // PCIe device has a unique one.
    let dev_cfg = match device.kind {
        narf_bus::BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
        _ => 0,
    };
    if dev_cfg != 0 {
        let already = {
            let g = CONTROLLERS.lock();
            g.iter().any(|c| c.cfg_phys() == dev_cfg)
        };
        if already {
            return Ok(());
        }
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device.
    let mut dev = match unsafe { VirtioNetPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // SAFETY: probe-time caller owns the device. Best-effort —
    // failure leaves the polled fallback in place inside the
    // forwarder. Bind a per-queue MSI-X vector to EVERY RX pair (routed
    // to each pair's forwarder CPU) so no forwarder blind-sleeps between
    // sparse frames; single-queue NICs just get pair 0 as before.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { dev.enable_rx_msix_all(&cap, &device) };
    let idx = {
        let mut g = CONTROLLERS.lock();
        let i = g.len();
        g.push(Arc::new(dev));
        i
    };
    let bound_name = alloc::format!("vnet{}", idx);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: bound_name.clone(),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(VIRTIO_NET_PCI_VENDOR),
        pci_did: Some(VIRTIO_NET_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    // Register this specific controller's interface and spawn its
    // forwarder pair.
    // `virtnet_get_drvinfo` reports `virtio_bus_name()`: virtio-pci's
    // `vp_bus_name` is the PCI function's name; a transport without a
    // `bus_name` op (virtio-mmio) reports "virtio".
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::from("virtio"),
    };
    register_net_interface(idx, bus_info);
    Ok(())
}

/// Build a `VirtioNet` from the controller at `idx`, register it
/// with `narf_net::registry()` under `name`, and spawn the RX/TX
/// forwarder tasks scoped to that controller's index.
///
/// Forwarder shape with VIRTIO_NET_F_MQ:
/// - One TX forwarder per device. Drains the iface tx_consumer once
///   and demuxes each frame to one of N TX virtqueues via the
///   controller's round-robin selector. Single-consumer of the
///   `narf_ipc::Consumer<Frame>`; no lock contention on the consumer
///   half (narf_ipc is SPSC and we hold the single S/C side).
/// - N RX forwarders, one per pair. Each pair has its own used-ring
///   to drain; pair 0 waits on MSI-X, pairs 1..N fall back to a
///   16 ms poll. All N RX forwarders push into the same shared
///   `Producer<Frame>`, behind an `Arc<IrqSafeSpinLock<...>>` —
///   `narf_ipc::Producer` is `!Sync` so the lock is required to
///   serialise the multiple producer halves. Push frequency is
///   low (one short critical section per frame, no awaits held
///   under the lock) so contention is bounded even on a 4-pair
///   line-rate workload.
fn register_net_interface(idx: usize, bus_info: alloc::string::String) {
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    let (mac, mtu, link_up, rx_irq_vectors, num_pairs, offloads) = match with_at(idx, |c| {
        (
            c.mac(),
            c.mtu(),
            c.link_up(),
            c.rx_irq_vectors.clone(),
            c.num_pairs(),
            c.tx_offload_profile().advertised(),
        )
    }) {
        Some(t) => t,
        None => return,
    };
    // One device name for both registries, `eth%d` as Linux
    // `dev_alloc_name` picks it. The primary controller is the legacy L3
    // registry's device (the TCP stack sends through `vnet0_send_fn`); the
    // others are frame-ring devices only and reserve their name.
    let name: alloc::string::String = if idx == 0 {
        let name = narf_net::iface::register_static("eth%d", mac, vnet0_send_fn);
        // `virtnet_get_drvinfo`: driver "virtio_net", VIRTNET_DRIVER_VERSION.
        narf_net::iface::set_driver_info(name, "virtio_net", Some("1.0.0"), bus_info);
        // Advertise only the feature-gated profile negotiated during probe.
        // TCP consults this snapshot before it creates partial checksums or a
        // GSO super-frame, and `tx_header_for_frame` validates it again at the
        // hardware boundary.
        narf_net::iface::set_offloads(name, offloads);
        // The primary RX forwarder drains complete bursts and calls
        // `gro_flush` before it parks, so this interface can safely opt into
        // the stack's per-interface software GRO path.
        let _ = narf_net::iface::set_software_gro(name, true);
        *PRIMARY_IFNAME.lock() = Some(name);
        // Opt into zero-copy TX with one recycler per TX pair. `tx_acquire`
        // records its selected queue in the frame, and the reaper returns the
        // buffer to that same pair. `VIRTIO_NET_HDR_LEN` bytes of head-room
        // are for the virtio-net header `tx_dma_on` writes in front.
        if let Some((pools, flow_affine)) = with_at(idx, |c| {
            (
                c.pairs
                    .iter()
                    .map(|pair| Arc::clone(&pair.tx_pool))
                    .collect(),
                c.flow_affine,
            )
        }) {
            narf_net::iface::enable_zero_copy_tx_pools_with_affinity(
                name,
                vnet0_send_frame_zc,
                pools,
                VIRTIO_NET_HDR_LEN,
                flow_affine,
            );
        }
        name.into()
    } else {
        narf_net::iface::reserve_name("eth%d").into()
    };
    let (tx_prod, mut tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
    let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
    // Keep the legacy L3 registry -- which is what rtnetlink and
    // NetworkManager consume -- in lockstep with the ring interface.  Without
    // this, `register_static` correctly creates eth0 administratively down,
    // but also leaves its physical carrier at the default false.  QEMU has
    // already told us its virtio-net link is up, so NetworkManager sees an
    // unavailable device and never starts DHCP.
    narf_net::iface::set_link_metadata(&name, link_up, None, None);
    let iface = narf_net::virtio_net::VirtioNet::new(name, mac, mtu, link_up, tx_prod, rx_cons);
    let authority = narf_net::bootstrap_authority();
    // Registration failure leaks the iface (returned by-value into
    // the registry would have moved it) — we constructed it above
    // and Registry::register consumes it on success. On failure
    // the Vec slot stays free and the forwarders below would talk
    // to nothing useful, so bail.
    if narf_net::registry().register(&authority, iface).is_err() {
        return;
    }
    // Wrap the rx_prod in an Arc<IrqSafeSpinLock> so all N RX
    // forwarders can push to it. Producer is !Sync (narf_ipc SPSC);
    // the lock serialises the N producer halves into one logical
    // producer feeding the iface's RX ring.
    let rx_prod = Arc::new(IrqSafeSpinLock::new(Some(rx_prod)));

    // Shared "the NIC saw RX traffic recently" timestamp (TSC cycles),
    // updated by EVERY per-pair forwarder when it drains a frame. The
    // poll-only pairs (1..N, no MSI-X) read it to decide whether to keep
    // fast-polling. Under concurrent off-box load the host RSS-spreads
    // flows across all queues, so any single queue idles for short
    // windows even while the NIC is busy. Without this, a poll-only pair
    // exhausted its fast rounds and backed off to the PUMP_CYCLES sleep
    // (~22 ms at a 2.3 GHz TSC) — and the next request steered to that
    // queue ate the whole deadline, a fixed ~22 ms p99 tail under load.
    // Staying hot while ANY queue is active keeps the tail sub-ms; the
    // device still parks (all pairs back off) once the whole NIC quiets.
    // Slow-poll cadence for the poll-only pairs (no MSI-X) once idle: 2 ms,
    // matching the MSI-X pair's IRQ-park backstop. The old fixed 53M-cycle
    // sleep was ~22 ms at the KVM TSC, so a packet landing on a backed-off
    // poll-only queue stalled up to ~22 ms — the p99.9 tail. 2 ms caps that
    // at the same bound as the IRQ pair; a truly idle NIC still parks (it
    // just wakes to poll every 2 ms — negligible CPU).
    let slow_poll_cycles = narf_time::ns_to_cycles(2_000_000);

    // Core-partitioned RX placement. Under multi-queue with enough cores,
    // give each per-queue forwarder its OWN low CPU (pair K → CPU K, pair
    // 0 on the BSP where its MSI-X lands) and reserve those cores so the
    // scheduler steers user-task workers to the REMAINING cores
    // (`reserve_rx_forwarder_cores`). This spreads RX dispatch across
    // cores WITHOUT the forwarders contending the AP-biased workers — the
    // failure mode of naive AP-pinning. The per-segment TCB lookup is off
    // the global lock (sharded CONN_INDEX), so the forwarders run truly
    // concurrently. Falls back to all-on-BSP (the prior behaviour) for
    // single-queue / nosmp / too-few-vCPUs, where partitioning can't help.
    let online = narf_lib::smp::online_count() as usize;
    let partition = num_pairs >= 2 && online > num_pairs;
    if partition {
        narf_scheduler::reserve_rx_forwarder_cores(num_pairs as u32);
    }

    // Spawn one RX forwarder per active pair.
    for pair_idx in 0..num_pairs {
        let rx_prod = Arc::clone(&rx_prod);
        // Each pair parks on its OWN MSI-X vector (`enable_rx_msix_all`
        // routed pair K's IRQ to CPU K). A `None` entry (MSI-X table/IDT
        // exhausted, or single-queue) falls back to the polled cadence
        // below — correct, just without the per-queue IRQ fast-path.
        let irq = rx_irq_vectors.get(pair_idx).copied().flatten();
        // Forwarder's home core (see the partition comment above).
        let target_cpu = if partition { pair_idx as u32 } else { 0 };
        // Stackful: virtio-net RX pump.
        narf_scheduler::spawn_stackful_pinned(
            async move {
                // Adaptive (NAPI-style) poll cadence. virtio-net MSI-X RX
                // completions don't always wake us promptly under SLIRP/TCG
                // (the device can leave the used-ring interrupt suppressed),
                // so a fixed 100 ms fallback gated every off-box round-trip
                // at ~tens of ms. Instead: while frames are flowing, re-poll
                // on a 1 ms deadline so request/response latency is sub-ms;
                // after a run of empty polls, back off to 100 ms so an idle
                // NIC parks instead of spinning the CPU. `idle_rounds`
                // counts consecutive empty wakes.
                const FAST_ROUNDS: u32 = 64;
                let mut idle_rounds: u32 = FAST_ROUNDS;
                let mut fast_rounds: u32 = 0;
                // `wake_race` diagnostic: register the primary RX forwarder as the
                // separately-tracked task so its own wake→dispatch tail (the
                // RX-side blind spot io_next/rxtx_hist can't see) is isolated.
                // No-op unless the instrument is on.
                if pair_idx == 0 {
                    narf_scheduler::wake_race_track(narf_scheduler::current_task_id().raw());
                }
                loop {
                    // Snapshot the IRQ generation BEFORE draining (Linux NAPI
                    // re-check pattern). A frame that lands during or after the
                    // drain below bumps the vector's `fire_count` past this
                    // baseline, so the wait at the bottom of the loop resolves
                    // immediately instead of sleeping out the deadline. In the
                    // old wait-then-drain order, a frame arriving in the window
                    // between a drain and the next `wait_for_irq` snapshot was
                    // absorbed into the new baseline and waited the full 1 ms
                    // deadline — that dragged off-box request latency to ~0.7 ms
                    // avg (vs ~0.15 ms when the IRQ edge was caught). Building
                    // the future just snapshots the count; its waker isn't
                    // installed until the first poll (in `timeout` below).
                    let irq_waiter = irq.map(narf_interrupts::wait_for_irq);
                    let mut processed_any = false;
                    // Buffer pending recycle into the RX frame pool, released on the
                    // NEXT take's `with_at` so recycling adds no extra CONTROLLERS
                    // lock on the per-frame hot path (flushed after the drain loop).
                    let mut to_recycle: Option<DmaBuffer> = None;
                    loop {
                        let taken = match with_at(idx, |c| {
                            if let Some(b) = to_recycle.take() {
                                c.rx_buf_release_on(pair_idx, b);
                            }
                            c.rx_take_on(pair_idx)
                        }) {
                            Some(t) => t,
                            None => return, // controller vanished
                        };
                        let (mut buf, total_len) = match taken {
                            Some(t) => t,
                            None => break,
                        };
                        // Saw a used-ring entry → the NIC is active; stay in
                        // fast-poll mode.
                        processed_any = true;
                        // virtio-net always prepends a 12-byte header to
                        // every RX frame. Strip it via Frame::with_offset
                        // — the bytes stay where the device wrote them.
                        let payload_len = total_len.saturating_sub(12);
                        if payload_len == 0 {
                            // Empty frame (just header): recycle the buffer (on the
                            // next take's with_at) and keep draining.
                            to_recycle = Some(buf);
                            continue;
                        }
                        // Tap: synchronously dispatch the payload through the iface
                        // RX handler. Only installed for the primary controller
                        // (idx 0) — the TCP stack hooked itself there at boot via
                        // `install_rx_drain` / `on_rx_frame_from`. virtio-net
                        // prepends a 12-byte header; dispatch the payload slice
                        // directly (no `Frame`) so the consumed DmaBuffer can be
                        // RECYCLED into the RX frame pool instead of freed — keeping
                        // the buddy allocator + per-frame 4 KiB zero-fill off the
                        // hot path.
                        if idx == 0 {
                            let end = (12 + payload_len as usize).min(buf.len());
                            // `&mut`: an attached XDP program may rewrite header
                            // bytes in place. `buf` is a DmaBuffer this pump owns
                            // for the duration (recycled into the RX pool on the
                            // next take); the device is not reading it back, so an
                            // in-place write before dispatch is sound.
                            narf_net::iface::on_rx_frame_from(
                                primary_iface_name(),
                                &mut buf.as_mut_slice()[12..end],
                            );
                            // The tap consumed the frame synchronously + completely.
                            // (The legacy rx_prod/rx_cons channel is NOT drained in
                            // production, so pushing there would wedge after 64
                            // frames.) Recycle the buffer on the next take's with_at.
                            to_recycle = Some(buf);
                            continue;
                        }
                        let frame =
                            Frame::with_offset_on_queue(buf, 12, payload_len, pair_idx as u16);
                        // Secondary controllers (idx != 0) have no
                        // synchronous tap, so the channel IS their delivery
                        // path. Push best-effort: on a full ring DROP the
                        // frame (TCP will retransmit) rather than spin the
                        // pump forever — an undrained/slow consumer must not
                        // wedge RX. Closed ⇒ consumer gone, bail.
                        {
                            let mut g = rx_prod.lock();
                            let prod = match g.as_mut() {
                                Some(p) => p,
                                None => return,
                            };
                            match prod.try_send(frame) {
                                Ok(()) => {}
                                Err(narf_ipc::TrySendError::Closed(_)) => {
                                    *g = None;
                                    return;
                                }
                                Err(narf_ipc::TrySendError::Full(_)) => {
                                    // The driver→stack ring is full: the stack
                                    // isn't draining fast enough. Frame is
                                    // dropped on scope exit — count it so the
                                    // loss is observable (rx_dropped) instead
                                    // of silent.
                                    narf_net::iface::note_rx_drop(primary_iface_name(), 1);
                                }
                            }
                        }
                    }
                    // Flush the last drained buffer's recycle: the per-frame recycle
                    // rides the next take's `with_at`, but the final frame of the
                    // round has no next take — release it here (≤1 with_at/round).
                    if let Some(b) = to_recycle.take() {
                        with_at(idx, |c| c.rx_buf_release_on(pair_idx, b));
                    }
                    // NAPI-complete for this pair: the RX ring drained this round,
                    // so flush any TCP segments GRO coalesced for the frames just
                    // delivered. Only pair/idx 0 feeds GRO (it owns the synchronous
                    // tap into the stack), so only it needs draining. This runs on
                    // the forwarder's own CPU — the same CPU the offers ran on — so
                    // it drains that CPU's per-CPU coalescer. No-op when that CPU
                    // holds no GRO flows.
                    if idx == 0 {
                        narf_net::tcp_stack::gro_flush();
                    }
                    // Adapt cadence: reset to fast-poll if this round drained
                    // anything (per-queue), else step toward the slow fallback.
                    if processed_any {
                        with_at(idx, |c| c.rx_notify(pair_idx));
                        idle_rounds = 0;
                        // NAPI: a burst is flowing and we'll keep polling the
                        // ring — suppress RX interrupts so the device stops
                        // firing an MSI per frame. Re-armed by rx_arm_and_pending
                        // before the park below once the burst drains.
                        if RX_NAPI.load(Ordering::Relaxed) {
                            with_at(idx, |c| c.rx_disable_cb(pair_idx));
                        }
                    } else {
                        idle_rounds = idle_rounds.saturating_add(1);
                    }
                    // Wait for an IRQ newer than the pre-drain baseline (a frame
                    // that arrived during the drain resolves this immediately),
                    // or fall back to the adaptive deadline. Non-MSI-X pairs
                    // (`irq == None`) poll on the sleep cadence.
                    //
                    // PER-QUEUE activity gating: fast-poll only while THIS queue
                    // is bursting (`idle_rounds` resets to 0 on every non-empty
                    // drain). The earlier NIC-WIDE `nic_active` gate kept EVERY
                    // poll-only pair hot whenever ANY queue saw traffic — but the
                    // host tap delivers all flows to RX queue 0 (no RSS spread),
                    // so the secondary queues NEVER receive yet busy-spun a whole
                    // core each forever (perf-dump: a poll-only forwarder core at
                    // ~100% kTk, 0 syscalls). Gating on this queue's own idleness
                    // lets a dead queue's forwarder park (IRQ-park / slow-poll)
                    // while the busy queue 0 stays hot (its `idle_rounds` stays
                    // low under load). If real RSS spreads later, an MSI-X pair
                    // re-wakes on its own RX IRQ; a poll-only pair re-checks on
                    // the 2 ms slow-poll — both per-queue, not NIC-wide.
                    let fast = idle_rounds < FAST_ROUNDS;
                    let yield_fast = fast_poll_quantum_expired(&mut fast_rounds, fast);
                    match irq_waiter {
                        Some(w) => {
                            if fast {
                                // NAPI sustained-poll: while frames are flowing
                                // (recent non-empty drain), do NOT park waiting for
                                // an RX IRQ. Re-poll immediately while the used
                                // ring has a burst pending, but yield once per
                                // bounded quantum: an unbounded `continue` here
                                // keeps this CPU-pinned stackful task inside one
                                // executor poll and starves system services.
                                // `yield_now` self-wakes, so the forwarder resumes
                                // without relying on a new RX interrupt.
                                drop(w);
                                if yield_fast {
                                    narf_scheduler::yield_now().await;
                                }
                                continue;
                            } else {
                                // Register-then-recheck (Linux
                                // virtqueue_enable_cb): arm the used-ring
                                // interrupt and re-read `used.idx` BEFORE
                                // committing to the park. If a completion is
                                // already pending the device suppressed or
                                // coalesced its interrupt (EVENT_IDX arm race /
                                // QEMU-SLIRP used-ring coalescing), so the
                                // `wait_for_irq` edge would never come and we'd
                                // sleep out the 2 ms backstop on a frame already
                                // sitting in the ring — the sequential off-box
                                // request/reply p99 tail. Drain it now instead.
                                // `w`'s pre-drain `fire_count` baseline still
                                // covers a frame that fires the IRQ AFTER this
                                // re-read, so the two together are lossless.
                                if with_at(idx, |c| c.rx_arm_and_pending(pair_idx)).unwrap_or(false)
                                {
                                    idle_rounds = 0;
                                    drop(w);
                                    continue;
                                }
                                // Idle: park on the IRQ. The edge resolves `w`
                                // immediately when caught; the 2 ms deadline only
                                // backstops a missed/late RX MSI-X so the executor
                                // can HLT and save power while no traffic flows.
                                // (A/B measured: extending this to 50 ms did NOT
                                // change the sequential-PING p99 tail and `max`
                                // never approached 50 ms, so the RX IRQ is
                                // reliable and the backstop cadence is not the
                                // tail — keep it tight for concurrent-load
                                // responsiveness.)
                                let dl = narf_time::Deadline::after_ms(2);
                                let _ = narf_time::timeout(dl, w).await;
                            }
                        }
                        None => {
                            if fast {
                                // Same bounded immediate poll for a queue without
                                // an IRQ vector. Its periodic cooperative yield
                                // requeues the forwarder without needing an IRQ.
                                if yield_fast {
                                    narf_scheduler::yield_now().await;
                                }
                                continue;
                            } else {
                                narf_time::sleep_cycles(slow_poll_cycles).await;
                            }
                        }
                    }
                }
            },
            target_cpu,
        );
    }

    // Single TX forwarder per device. Drains the tx_consumer once
    // and selects one of the N TX virtqueues before it acquires that
    // queue's recycler buffer, so completion returns to the same pool.
    //
    // tx_dma is fire-and-forget and requires the frame body after the
    // virtio header headroom at offset 0, taking the
    // DmaBuffer BY VALUE. Channel-pushed Frames carry their payload
    // at an arbitrary `offset` (0 for Frame::new), so we relocate
    // into a prepared recycler buffer with the required header room.
    // This is an alternate production ingress, not an allocator-per-packet
    // slow path: an empty TX pool is ordinary backpressure.
    // Stackful: TX forwarder.
    narf_scheduler::spawn_stackful(async move {
        while let Ok(frame) = tx_cons.recv().await {
            let payload = frame.payload();
            let plen = payload.len();
            let meta = frame.tx_meta();
            if plen == 0 || plen > MAX_TX_TSO_FRAME {
                continue; // bad frame; drop it
            }
            let (pair_idx, mut buf) = match with_at(idx, |c| {
                let pair_idx = c.tx_pair_for_frame(payload);
                c.tx_buf_acquire_on(pair_idx).map(|buf| (pair_idx, buf))
            })
            .flatten()
            {
                Some(pair) => pair,
                None => continue, // bounded TX pool empty; upper layers retry
            };
            {
                let slice = buf.as_mut_slice();
                if slice.len() < VIRTIO_NET_HDR_LEN + plen {
                    continue;
                }
                slice[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + plen].copy_from_slice(payload);
            }
            // tx_dma takes ownership of `buf` and keeps it alive until
            // the device completes; never wait, never drop early.
            let _ = with_at(idx, |c| {
                c.tx_dma_on_with_meta(pair_idx, buf, plen as u32, meta)
            });
            // `frame` (and its DmaBuffer) drops at end of scope.
        }
    });

    // The primary controller (registered in the legacy `narf_net::iface`
    // registry above, which the TCP stack consumes via `iface::send` /
    // `iface::on_rx_frame`) also feeds the stack's RX drain hook.
    if idx == 0 {
        narf_net::iface::install_rx_drain(vnet0_drain_fn);
    }
}

/// `iface::SendFn` for the primary virtio-net controller. The TCP
/// stack invokes this with a full Ethernet frame; we allocate a
/// fresh DmaBuffer, leave virtio-net-header headroom at the front, memcpy the
/// frame after it, and submit through
/// the fire-and-forget tx_dma path. tx_dma takes the buffer BY VALUE
/// and keeps it alive (in the per-pair in-flight table) until the
/// device completes the transmit, so we must NOT drop it here.
fn vnet0_send_fn(frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    if frame.is_empty() || frame.len() > MAX_TX_TSO_FRAME {
        return Err(());
    }
    // Take a prepared TX buffer. An empty pool is backpressure; the send fails
    // rather than allocating from the page allocator on the frame path.
    let (pair_idx, mut buf) = with_controller(|c| {
        let pair_idx = c.tx_pair_for_frame(frame);
        c.tx_buf_acquire_on(pair_idx).map(|buf| (pair_idx, buf))
    })
    .flatten()
    .ok_or(())?;
    {
        let slice = buf.as_mut_slice();
        if slice.len() < VIRTIO_NET_HDR_LEN + frame.len() {
            return Err(());
        }
        // Frame body follows the virtio header, which tx_dma writes here.
        slice[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + frame.len()].copy_from_slice(frame);
    }
    // Move `buf` into its selected queue — it owns the buffer until the device
    // finishes DMAing the frame out of it.
    let res = with_controller(|c| c.tx_dma_on_with_meta(pair_idx, buf, frame.len() as u32, meta));
    match res {
        Some(Ok(())) => Ok(()),
        // `tx_dma` consumed `buf` (the closure moved it in). On the
        // None branch (no controller) the closure never ran and `buf`
        // would have been dropped inside `with_controller`'s map.
        _ => Err(()),
    }
}

/// Zero-copy `iface::SendFrameFn` (P-F). The stack built the Ethernet frame
/// directly into a buffer drawn from one selected queue's TX pool, at the
/// virtio-header head-room `enable_zero_copy_tx_pools` requested — exactly
/// the layout `tx_dma_on` expects (body after the header space). So
/// hand the buffer straight to that queue with no copy; the TX reaper recycles
/// it back into the same queue-local pool on completion. Replaces the
/// slice-into-`buf[VIRTIO_NET_HDR_LEN..]` memcpy `vnet0_send_fn` does.
fn vnet0_send_frame_zc(frame: narf_net::Frame, meta: narf_net::TxMeta) -> Result<(), ()> {
    let len = frame.len() as usize;
    if len == 0 || len > MAX_TX_TSO_FRAME {
        return Err(());
    }
    // `tx_acquire` built this with `VIRTIO_NET_HDR_LEN` bytes of headroom, so
    // the body follows the header space at the front of `buf`.
    // Discard the offset/len view and give `tx_dma` the whole buffer.
    let (buf, _off, _len, queue) = frame.into_parts_with_offset_and_queue();
    match with_controller(|c| c.tx_dma_on_with_meta(queue as usize, buf, len as u32, meta)) {
        Some(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

/// Pair chosen first by the next synchronous RX drain. The TCP connect and ARP
/// waits call the drain hook in a tight loop, so advancing this cursor makes
/// those waits fair across the NIC's RSS / flow-steered receive queues.
static DRAIN_PAIR_RR: AtomicU64 = AtomicU64::new(0);

/// `iface::DrainFn` — synchronous one-frame drain used by the TCP stack's
/// in-kernel `connect_wait` busy-wait (kernel callers that cannot park). A caller can
/// be occupying its executor while it waits, so it cannot rely on the spawned
/// RX forwarders making progress. Drain one frame from every active queue pair
/// in rotating order: with F_MQ, a flow's SYN-ACK returns on the pair selected
/// for its outbound SYN, not necessarily pair 0.
///
/// The buffer stays zero-copy through `iface::on_rx_frame`; we return it to
/// exactly the pair that supplied it and notify that pair after replenishing.
/// Returns `true` iff a frame was actually processed.
fn vnet0_drain_fn() -> bool {
    let taken = with_controller(|c| {
        let pairs = c.num_pairs();
        if pairs == 0 {
            return None;
        }
        let start = (DRAIN_PAIR_RR.fetch_add(1, Ordering::Relaxed) as usize) % pairs;
        (0..pairs).find_map(|offset| {
            let pair_idx = (start + offset) % pairs;
            c.rx_take_on(pair_idx).map(|frame| (pair_idx, frame))
        })
    })
    .flatten();
    let (pair_idx, (mut buf, total_len)) = match taken {
        Some(t) => t,
        None => return false,
    };
    let payload_len = total_len.saturating_sub(12);
    let end = (12 + payload_len as usize).min(buf.len());
    if payload_len != 0 {
        // `&mut`: as in the async pump, the program may rewrite header bytes in
        // place. `buf` is owned here until it is recycled below.
        narf_net::iface::on_rx_frame_from(primary_iface_name(), &mut buf.as_mut_slice()[12..end]);
    }
    // Recycle the consumed buffer into the RX frame pool instead of freeing.
    with_controller(|c| {
        c.rx_buf_release_on(pair_idx, buf);
        c.rx_notify(pair_idx);
    });
    true
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-net-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_NET_PCI_VENDOR,
            device: VIRTIO_NET_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// Number of bound virtio-net devices.
pub fn count() -> usize {
    CONTROLLERS.lock().len()
}

/// Active virtio-net queue-pair count on the primary device (1 unless
/// VIRTIO_NET_F_MQ was negotiated and `VQ_PAIRS_SET` accepted N>1).
/// The interface name `iface::register` gave the primary controller
/// (`eth%d`, Linux `dev_alloc_name`). Set once at probe and leaked: the
/// device lives as long as the kernel.
static PRIMARY_IFNAME: narf_lib::sync::IrqSafeSpinLock<Option<&'static str>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The primary controller's interface name; empty until it has registered.
pub fn primary_iface_name() -> &'static str {
    PRIMARY_IFNAME.lock().unwrap_or("")
}

pub fn primary_num_pairs() -> usize {
    CONTROLLERS
        .lock()
        .first()
        .map(|c| c.num_pairs())
        .unwrap_or(0)
}

/// Run `f` against the first bound controller, if any. Use the
/// `with_each` iterator instead when behaviour should fan out over
/// every device.
pub fn with_controller<R>(f: impl FnOnce(&VirtioNetPci) -> R) -> Option<R> {
    // Clone the Arc out, then DROP the lock before calling `f` (see the
    // CONTROLLERS doc comment: `f` may re-enter net_pci via tx_dma's
    // sleep-pump spin, which re-locks CONTROLLERS).
    let ctrl = CONTROLLERS.lock().first().cloned();
    ctrl.as_deref().map(f)
}

/// Run `f` against every bound controller in probe order.
pub fn with_each(mut f: impl FnMut(&VirtioNetPci)) {
    // Snapshot the Arc handles, drop the lock, then run `f` (see the
    // CONTROLLERS doc comment).
    let ctrls: alloc::vec::Vec<Arc<VirtioNetPci>> = CONTROLLERS.lock().iter().cloned().collect();
    for c in &ctrls {
        f(c);
    }
}

/// Run `f` against the controller at `idx`, if any. Per-device
/// forwarder tasks call this every tick to drain/post on their own
/// queues without stepping on siblings.
pub fn with_at<R>(idx: usize, f: impl FnOnce(&VirtioNetPci) -> R) -> Option<R> {
    // Clone the Arc out, then DROP the lock before calling `f` (see the
    // CONTROLLERS doc comment).
    let ctrl = CONTROLLERS.lock().get(idx).cloned();
    ctrl.as_deref().map(f)
}

#[cfg(target_arch = "x86_64")]
mod tx_tests {
    use super::*;
    use crate::queue::VirtqUsedElem;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const QSIZE: u16 = 128;
    const FRAME_LEN: usize = 54 + 8192;

    // Real driver queues and DMA ownership, with RAM in place of the notify
    // register. The fake device completes only when the test tells it to, so
    // pool exhaustion and delayed completion do not depend on QEMU timing.
    struct TxFixture {
        dev: VirtioNetPci,
        _registers: DmaBuffer,
        layouts: Vec<VirtqueueLayout>,
    }

    impl TxFixture {
        fn new() -> Result<Self, &'static str> {
            let registers =
                alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "register page")?;
            let region = || VirtioRegion {
                region: narf_bus::MmioRegion {
                    phys: registers.phys_addr(),
                    virt: registers.cpu_ptr::<u8>() as u64,
                    len: 4096,
                    kind: narf_bus::BarKind::Mmio32 {
                        prefetchable: false,
                    },
                },
                virt: registers.cpu_ptr::<u8>() as u64,
                offset: 0,
                length: 4096,
            };
            let mut pairs = Vec::new();
            let mut layouts = Vec::new();
            for n in 0..2 {
                let rx = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "RX ring page")?;
                let tx = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "TX ring page")?;
                let layout =
                    VirtqueueLayout::new(QSIZE, tx.phys_addr().raw()).ok_or("TX layout")?;
                // SAFETY: tx owns a coherent page containing this entire layout.
                let mut queue = unsafe { Virtqueue::new(layout) };
                queue.set_event_idx(true);
                let pool = Arc::new(DmaPool::new(TX_BUF_LEN, DomainId::DRIVER_0, TX_POOL_CAP));
                if pool.prefill(TX_POOL_CAP) != TX_POOL_CAP {
                    return Err("TX pool prefill");
                }
                pairs.push(QueuePair {
                    rx_qidx: 2 * n,
                    tx_qidx: 2 * n + 1,
                    rx_queue: IrqSafeSpinLock::new(None),
                    tx_queue: IrqSafeSpinLock::new(Some(queue)),
                    rx_buffers: IrqSafeSpinLock::new(Vec::new()),
                    tx_buffers: IrqSafeSpinLock::new((0..QSIZE).map(|_| None).collect()),
                    tx_pool: pool,
                    rx_pool: DmaPool::new(4096, DomainId::DRIVER_0, 0),
                    _rx_q_buf: rx,
                    _tx_q_buf: tx,
                    rx_qsize: 0,
                    tx_qsize: QSIZE,
                    rx_notify_off: 2 * n,
                    tx_notify_off: 2 * n + 1,
                });
                layouts.push(layout);
            }
            let dev = VirtioNetPci {
                common: region(),
                notify: region(),
                device_cfg: None,
                notify_off_multiplier: 2,
                pairs,
                tx_rr: AtomicU64::new(0),
                irq_vector: None,
                rx_irq_vectors: Vec::new(),
                flow_affine: false,
                tx_irq_vector: None,
                msix: None,
                ready: true,
                mac: IrqSafeSpinLock::new([0; 6]),
                has_ctrl_mac_addr: false,
                mtu: 1500,
                has_status: false,
                tx_checksum: true,
                tx_tso4: true,
                ctrl_qidx: 4,
                ctrl: None,
                cfg_phys: 0,
            };
            Ok(Self {
                dev,
                _registers: registers,
                layouts,
            })
        }

        fn submit(&self, pair: usize, more: bool) -> Result<(), &'static str> {
            let mut buf = self.dev.tx_buf_acquire_on(pair).ok_or("TX pool starved")?;
            let frame = &mut buf.as_mut_slice()[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + FRAME_LEN];
            frame.fill(0);
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&((FRAME_LEN - 14) as u16).to_be_bytes());
            frame[23] = 6;
            frame[46] = 5 << 4;
            frame[47] = 0x18;
            self.dev
                .tx_dma_on_with_meta(
                    pair,
                    buf,
                    FRAME_LEN as u32,
                    narf_net::TxMeta::with_tso(1024).with_more(more),
                )
                .map_err(|_| "TSO submit rejected")
        }

        fn complete(&self, pair: usize) -> Result<(), &'static str> {
            let layout = self.layouts[pair];
            let avail = narf_memory::PhysAddr::new(layout.avail_ring).kernel_ptr::<u16>();
            let used = narf_memory::PhysAddr::new(layout.used_ring).kernel_mut_ptr::<u16>();
            let descs = narf_memory::PhysAddr::new(layout.desc_table).kernel_ptr::<VirtqDesc>();
            let buffers = self.dev.pairs[pair].tx_buffers.lock();
            // SAFETY: the fixture exclusively owns these aligned ring pages;
            // every index is masked to QSIZE, and no real device accesses them.
            unsafe {
                let end = core::ptr::read_volatile(avail.add(1));
                let mut idx = core::ptr::read_volatile(used.add(1));
                while idx != end {
                    let slot = usize::from(idx % QSIZE);
                    let head = core::ptr::read_volatile(avail.add(2 + slot));
                    let desc = core::ptr::read_volatile(descs.add(usize::from(head)));
                    let buf = buffers[usize::from(head)]
                        .as_ref()
                        .ok_or("missing TX owner")?;
                    if desc.addr != buf.dma_addr().raw()
                        || desc.len as usize != VIRTIO_NET_HDR_LEN + FRAME_LEN
                        || desc.flags != 0
                        || buf.as_slice()[..2] != [1, 1]
                    {
                        return Err("TSO descriptor/header ownership mismatch");
                    }
                    core::ptr::write_volatile(
                        used.add(2 + slot * 4).cast::<VirtqUsedElem>(),
                        VirtqUsedElem {
                            id: u32::from(head),
                            len: 0,
                        },
                    );
                    idx = idx.wrapping_add(1);
                }
                crate::queue::virtio_wmb();
                core::ptr::write_volatile(used.add(1), end);
            }
            Ok(())
        }
    }

    fn smoke_virtio_net_tso_burst_recovers_exhausted_pool() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            for pair in 0..2 {
                for _ in 0..3 {
                    for i in 0..TX_POOL_CAP {
                        fixture.submit(pair, i + 1 < TX_POOL_CAP)?;
                    }
                    if fixture.dev.tx_buf_acquire_on(pair).is_some() {
                        return Err("uncompleted DMA buffer was reused");
                    }
                    fixture.complete(pair)?;
                    let buf = fixture
                        .dev
                        .tx_buf_acquire_on(pair)
                        .ok_or("completed pool stayed empty")?;
                    let p = &fixture.dev.pairs[pair];
                    if p.tx_pool.available() != TX_POOL_CAP - 1
                        || p.tx_buffers.lock().iter().any(Option::is_some)
                        || p.tx_queue.lock().as_ref().unwrap().diagnostic_snapshot().3 != QSIZE
                        || fixture.dev.pairs[1 - pair].tx_pool.available() != TX_POOL_CAP
                    {
                        return Err("TSO burst leaked buffers/descriptors or crossed queue pools");
                    }
                    fixture.dev.tx_buf_release_on(pair, buf);
                }
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_tso_burst_recovers_exhausted_pool
    );

    fn smoke_virtio_net_tso_more_flushes_at_pool_limit() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            // SAFETY: RAM-backed notify register, owned by this fixture.
            unsafe {
                fixture.dev.notify.write16(2, u16::MAX);
            }
            for _ in 0..TX_POOL_CAP - 1 {
                fixture.submit(0, true)?;
            }
            // SAFETY: same RAM-backed notify register.
            if unsafe { fixture.dev.notify.read16(2) } != u16::MAX {
                return Err("TSO more hint was not batched");
            }
            fixture.submit(0, true)?;
            // SAFETY: same RAM-backed notify register.
            if unsafe { fixture.dev.notify.read16(2) } != 1 {
                return Err("TX pool exhausted without flushing a deferred TSO burst");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_tso_more_flushes_at_pool_limit
    );
}
