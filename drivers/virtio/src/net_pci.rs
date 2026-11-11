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

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, AtomicU64, Ordering};

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
    alloc_msix_config_vector, bind_config_msix_vector, bind_queue_msix_vector, discover, map_cap,
    MsixQueueBinding, VirtioCaps, VirtioPciError, VirtioRegion, CC_DEVICE_FEATURE,
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
/// The device validates RX transport checksums and reports
/// `VIRTIO_NET_HDR_F_DATA_VALID` on valid frames (VirtIO 1.2 §5.1.3).
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1;
const VIRTIO_NET_F_MTU: u64 = 3;
const VIRTIO_NET_F_MAC: u64 = 5;
/// The device can segment a driver-supplied IPv4/TCP GSO packet.
///
/// "HOST" is from the virtio specification's host/device viewpoint: this is
/// the feature a guest driver negotiates before placing a TCPv4 GSO packet on
/// its transmit queue.
const VIRTIO_NET_F_HOST_TSO4: u64 = 11;
/// The device can segment a driver-supplied IPv6/TCP GSO packet.
/// Linux `include/uapi/linux/virtio_net.h`: `VIRTIO_NET_F_HOST_TSO6 12`.
const VIRTIO_NET_F_HOST_TSO6: u64 = 12;
/// The device can segment a driver-supplied UDP GSO packet (USO): each
/// segment carries its own UDP header, unlike legacy UFO fragmentation.
/// Linux `include/uapi/linux/virtio_net.h`: `VIRTIO_NET_F_HOST_USO 56`.
/// Note the high half: unlike every other virtio-net bit negotiated here,
/// USO lives above bit 32, so it is acknowledged through the second
/// feature word (see `bring_up`). HOST_UFO (bit 14) is deliberately NOT
/// negotiated: UFO fragments one UDP datagram at the IP layer, while
/// `TxMeta`'s `(mss, Udp)` requests segmentation (one UDP header per
/// segment) — different application-visible behavior, and no meta kind
/// exists to express the fragmentation choice.
const VIRTIO_NET_F_HOST_USO: u64 = 56;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_MRG_RXBUF (bit 15, uapi
/// `linux/virtio_net.h:48`). The device may span one RX frame across
/// several posted buffers, reporting the count in the header's
/// `num_buffers` field; the driver reassembles before delivery.
const VIRTIO_NET_F_MRG_RXBUF: u64 = 15;
const VIRTIO_NET_F_STATUS: u64 = 16;
const VIRTIO_NET_F_CTRL_VQ: u64 = 17;
/// VirtIO 1.2 §5.1.3 — VIRTIO_NET_F_CTRL_RX (bit 18). Required for
/// `VIRTIO_NET_CTRL_MAC_TABLE_SET` (and the RX class) to succeed.
const VIRTIO_NET_F_CTRL_RX: u64 = 18;
/// VirtIO 1.2 §5.1.3 — VIRTIO_NET_F_CTRL_VLAN (bit 19). Required for
/// `VIRTIO_NET_CTRL_VLAN_ADD` / `VIRTIO_NET_CTRL_VLAN_DEL` to succeed.
const VIRTIO_NET_F_CTRL_VLAN: u64 = 19;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_GUEST_ANNOUNCE (bit 21). The
/// device may raise `VIRTIO_NET_S_ANNOUNCE` in the STATUS word to
/// ask the driver to announce itself (gratuitous ARP / unsolicited
/// ND) after link-up, migration, or failover; the driver acks with
/// `VIRTIO_NET_CTRL_ANNOUNCE_ACK`. Requires F_CTRL_VQ (Linux
/// `virtnet_validate_features` fails the feature otherwise).
const VIRTIO_NET_F_GUEST_ANNOUNCE: u64 = 21;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_CTRL_MAC_ADDR (bit 23).
/// Required for `VIRTIO_NET_CTRL_MAC_ADDR_SET` to succeed.
const VIRTIO_NET_F_CTRL_MAC_ADDR: u64 = 23;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_MQ (bit 22). Device supports
/// multi-queue with auto receive-steering across `max_virtqueue_pairs`.
const VIRTIO_NET_F_MQ: u64 = 22;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_HASH_REPORT (bit 57). Device
/// reports the RSS hash in the RX header (`virtio_net_hdr_v1_hash`:
/// the 12-byte header + hash_value + hash_report + padding = 20
/// bytes). Negotiated independently of F_RSS; the hash fields are
/// device-written on RX only, so the TX header stays 12 bytes.
const VIRTIO_NET_F_HASH_REPORT: u64 = 57;
/// VirtIO 1.2 §5.1.3.1 — VIRTIO_NET_F_RSS (bit 60). Device steers
/// RX flows to queues per the RSS config sent via
/// `VIRTIO_NET_CTRL_MQ_RSS_CONFIG`. Requires F_CTRL_VQ like F_MQ.
const VIRTIO_NET_F_RSS: u64 = 60;
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
/// `VIRTIO_NET_CTRL_MAC_TABLE_SET` (§5.1.6.5.2). Payload is
/// `[u32 LE unicast count][unicast MACs][u32 LE multicast count]
/// [multicast MACs]`. Linux `virtnet_set_rx_mode` sends the same
/// two tables as two scatterlist segments; one contiguous buffer
/// is byte-identical on the wire. Only valid when the device
/// negotiated `VIRTIO_NET_F_CTRL_RX` (bit 18).
const VIRTIO_NET_CTRL_MAC_TABLE_SET: u8 = 0;
/// `VIRTIO_NET_CTRL_MAC_ADDR_SET` (§5.1.6.5.2). 6-byte MAC
/// payload. Only valid when the device negotiated
/// `VIRTIO_NET_F_CTRL_MAC_ADDR` (bit 23) — otherwise the device
/// will reject the command with `VIRTIO_NET_ERR`.
const VIRTIO_NET_CTRL_MAC_ADDR_SET: u8 = 1;

/// VirtIO 1.2 §5.1.6.5.3 — VIRTIO_NET_CTRL_VLAN class.
const VIRTIO_NET_CTRL_VLAN: u8 = 2;
/// `VIRTIO_NET_CTRL_VLAN_ADD` (§5.1.6.5.3). 2-byte LE VID payload.
/// Only valid when the device negotiated `VIRTIO_NET_F_CTRL_VLAN`
/// (bit 19). Programs the device's VLAN filter table: incoming
/// frames whose tag VID is not in the table are dropped by the
/// device. The device filters; it does not strip — matching frames
/// arrive with the tag intact for the stack to parse (net spec:
/// RX stripping stays OFF, `Frame::rx_meta` has no VLAN-tag field).
const VIRTIO_NET_CTRL_VLAN_ADD: u8 = 0;
/// `VIRTIO_NET_CTRL_VLAN_DEL` (§5.1.6.5.3). 2-byte LE VID payload.
const VIRTIO_NET_CTRL_VLAN_DEL: u8 = 1;

/// VirtIO 1.2 §5.1.6.5.4 — VIRTIO_NET_CTRL_ANNOUNCE class.
/// `VIRTIO_NET_CTRL_ANNOUNCE_ACK` (cmd 0) tells the device the
/// driver received its announce request; the device clears
/// `VIRTIO_NET_S_ANNOUNCE` on receipt. No payload (Linux
/// `virtnet_ack_link_announce` sends NULL data) — the command is
/// just the 2-byte header + 1-byte ack.
const VIRTIO_NET_CTRL_ANNOUNCE: u8 = 3;
const VIRTIO_NET_CTRL_ANNOUNCE_ACK: u8 = 0;

/// 802.1Q tag protocol identifier, big-endian on the wire.
const ETHERTYPE_VLAN: u16 = 0x8100;
/// Bytes an 802.1Q tag adds to an Ethernet frame (TPID + TCI).
const VLAN_TAG_LEN: usize = 4;
/// Largest valid VLAN ID (12-bit VID space).
const MAX_VLAN_VID: u16 = 4095;
/// Largest control payload `submit_control` accepts. The 4 KiB
/// scratch page holds the 2-byte header at offset 0, the payload
/// at offset 16, and the 1-byte ack immediately after the payload,
/// so `16 + N + 1 <= 4096`.
const MAX_CTRL_PAYLOAD: usize = 4096 - 16 - 1;

/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ class.
const VIRTIO_NET_CTRL_MQ: u8 = 4;
/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET.
/// Payload is a `__virtio16` (2-byte LE) count of pairs to enable.
const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u8 = 0;
/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ_RSS_CONFIG.
/// Payload is a `virtio_net_rss_config`: hash_types, indirection
/// table mask + table, unclassified queue, max TX virtqueues,
/// hash key length + key. Has the same pair-count effect as
/// VQ_PAIRS_SET (via max_tx_vq) plus the steering config.
const VIRTIO_NET_CTRL_MQ_RSS_CONFIG: u8 = 1;
/// VirtIO 1.2 §5.1.6.5.5 — VIRTIO_NET_CTRL_MQ_HASH_CONFIG.
/// Payload is a `virtio_net_hash_config`: hash_types, reserved,
/// hash key length + key. Requests the device include the hash
/// value + report type in the RX header; requires F_HASH_REPORT
/// negotiated. Sent when HASH_REPORT is negotiated without RSS
/// (mirroring Linux's commit choice: RSS_CONFIG iff has_rss, else
/// HASH_CONFIG).
const VIRTIO_NET_CTRL_MQ_HASH_CONFIG: u8 = 2;

/// RSS hash-type bits (uapi `VIRTIO_NET_RSS_HASH_TYPE_*`, bits
/// 0–8). The `_EX` variants cover IPv6 extension headers.
const RSS_HASH_TYPE_IPV4: u32 = 1 << 0;
const RSS_HASH_TYPE_TCPV4: u32 = 1 << 1;
const RSS_HASH_TYPE_UDPV4: u32 = 1 << 2;
const RSS_HASH_TYPE_IPV6: u32 = 1 << 3;
const RSS_HASH_TYPE_TCPV6: u32 = 1 << 4;
const RSS_HASH_TYPE_UDPV6: u32 = 1 << 5;
const RSS_HASH_TYPE_IP_EX: u32 = 1 << 6;
const RSS_HASH_TYPE_TCP_EX: u32 = 1 << 7;
const RSS_HASH_TYPE_UDP_EX: u32 = 1 << 8;
/// All hash-type bits the driver knows how to interpret.
const RSS_HASH_TYPE_ALL_KNOWN: u32 = (1 << 9) - 1;
/// Extension-header variants, masked out of the programmed config
/// exactly as Linux does (`virtio_net.c` clears the `_EX` bits from
/// the device-advertised set): extension-header hashing is device
/// behavior we do not need to steer on.
const RSS_HASH_TYPE_EX_MASK: u32 =
    RSS_HASH_TYPE_IP_EX | RSS_HASH_TYPE_TCP_EX | RSS_HASH_TYPE_UDP_EX;
/// Fallback hash types when the device advertises none we know:
/// the base IPv4/IPv6 TCP/UDP set.
const RSS_HASH_TYPE_BASE: u32 = RSS_HASH_TYPE_IPV4
    | RSS_HASH_TYPE_TCPV4
    | RSS_HASH_TYPE_UDPV4
    | RSS_HASH_TYPE_IPV6
    | RSS_HASH_TYPE_TCPV6
    | RSS_HASH_TYPE_UDPV6;
/// Largest indirection table we will program. The control queue's
/// `submit_control` caps payloads at 240 bytes; a 64-entry table
/// with a 40-byte key is 11 + 128 + 40 = 179 bytes, comfortably
/// inside. A larger device-advertised max is simply not fully
/// used — the mask defines the table length, not the device max.
const RSS_MAX_INDIR_TABLE: u16 = 64;
/// Toeplitz key length programmed into the device. 40 bytes is the
/// minimum for full IPv6 Toeplitz (36-byte input + 32-bit output
/// window); a smaller device-advertised max clamps it down.
const RSS_KEY_LEN: usize = 40;

const VIRTIO_NET_OK: u8 = 0;

// virtio-net config status bits.
const VIRTIO_NET_S_LINK_UP: u16 = 1 << 0;
/// VirtIO 1.2 §5.1.4 — VIRTIO_NET_S_ANNOUNCE (bit 1): the device
/// wants the driver to announce (see `VIRTIO_NET_F_GUEST_ANNOUNCE`).
/// Cleared by the device once it receives
/// `VIRTIO_NET_CTRL_ANNOUNCE_ACK`.
const VIRTIO_NET_S_ANNOUNCE: u16 = 1 << 1;

// Offsets within the device-specific config region (VirtIO 1.2
// §5.1.4 — `struct virtio_net_config`).
const CFG_MAC: u64 = 0;
const CFG_STATUS: u64 = 6;
/// Per §5.1.4: u16 LE, only valid when VIRTIO_NET_F_MQ negotiated.
/// Reports the maximum number of TX/RX queue pairs the device
/// supports. Spec guarantees 1 ≤ value ≤ 0x8000.
const CFG_MAX_VIRTQUEUE_PAIRS: u64 = 8;
const CFG_MTU: u64 = 10;
/// RSS device-cfg fields (packed `virtio_net_config`, valid when
/// F_RSS or F_HASH_REPORT is offered): max key size (u8) at 17,
/// max indirection-table length (u16 LE) at 18, supported hash
/// types (u32 LE) at 20. Offsets follow the packed layout past
/// speed (u32, 12–15) and duplex (u8, 16).
const CFG_RSS_MAX_KEY_SIZE: u64 = 17;
const CFG_RSS_MAX_INDIR_LEN: u64 = 18;
const CFG_SUPPORTED_HASH_TYPES: u64 = 20;

/// Upper bound on how many queue pairs we'll actually bring up,
/// regardless of what `max_virtqueue_pairs` reports. Keeps DMA-page
/// + MSI-X-vector consumption bounded for absurd device-advertised
///   counts (some emulators advertise 0x8000). Four is enough to spread
///   TX submission across a typical small-core machine.
const MAX_QUEUE_PAIRS: u16 = 4;

/// virtio-net header (VirtIO 1.2 §5.1.6.1), 12 bytes: the
/// `virtio_net_hdr_mrg_rxbuf` form. `num_buffers` is live on RX when
/// VIRTIO_NET_F_MRG_RXBUF is negotiated (and ignored otherwise); on
/// TX it is always 0 (Linux `virtio_net.c:3335` likewise). The RX
/// header is 12 bytes, or 20 with HASH_REPORT
/// (`VIRTIO_NET_HDR_HASH_LEN`); see `rx_hdr_len`. The TX form is
/// always 12 bytes (the hash fields are device-written on RX only).
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

pub(crate) const VIRTIO_NET_HDR_LEN: usize = core::mem::size_of::<VirtioNetHdr>();
pub(crate) const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
/// RX header flag (VirtIO 1.2 §5.1.6.1): the device validated the
/// packet's checksum and it is valid. Mutually exclusive with
/// NEEDS_CSUM (a partial checksum is, by definition, not validated).
pub(crate) const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;
/// RX header length with VIRTIO_NET_F_HASH_REPORT negotiated
/// (`virtio_net_hdr_v1_hash`: the 12-byte header + hash_value
/// (u32) + hash_report (u16) + padding (u16)). The hash fields
/// are parsed-and-skipped: no stack consumer reads them yet (a
/// future RFS lane can read hash_value at offset 12 and
/// hash_report at offset 16 of the RX header).
pub(crate) const VIRTIO_NET_HDR_HASH_LEN: usize = VIRTIO_NET_HDR_LEN + 8;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// GSO type values from Linux `include/uapi/linux/virtio_net.h`
/// (`struct virtio_net_hdr_v1`): UDP here is 3, the legacy UFO
/// fragmentation type — deliberately unused (see `VIRTIO_NET_F_HOST_USO`
/// above). TCPv6 is 4; USO is 5 (`GSO_UDP_L4`, IPv4 and IPv6 UDP).
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const TCP_MIN_HDR_LEN: usize = 20;
const TCP_CSUM_OFFSET: usize = 16;
const UDP_HDR_LEN: usize = 8;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const TCP_ECE_OR_CWR: u8 = 0xc0;

/// Maximum frame we'll accept on RX. Standard MTU + Ethernet header + the
/// virtio-net header. RX GSO is deliberately not negotiated yet.
pub const MAX_RX_FRAME: usize = 1518 + VIRTIO_NET_HDR_LEN;
/// Largest Ethernet payload (frame minus virtio-net header) an RX
/// buffer must hold. RX descriptor lengths are `rx_hdr_len +
/// MAX_RX_FRAME_PAYLOAD` so a max-size frame still fits when the
/// RX header grows to 20 bytes with HASH_REPORT.
const MAX_RX_FRAME_PAYLOAD: usize = MAX_RX_FRAME - VIRTIO_NET_HDR_LEN;

/// Minimum runtime MTU (Linux `virtio_net.c`: `dev->min_mtu =
/// ETH_MIN_MTU` = 68). Probe keeps its own `>= 64` gate for
/// device-advertised values (below 64 falls back to 1500);
/// runtime changes enforce the Linux 68 floor instead.
const MIN_MTU: u32 = 68;
/// Largest MTU honestly advertisable without MRG_RXBUF: a standard
/// frame (1500 MTU + Ethernet header + VLAN tag). A device advertising
/// more while MRG is off gets clamped to this at probe — previously
/// the raw device MTU was published while the datapath capped at
/// 1518, a probe/datapath inconsistency (audit gap 4).
const RX_MTU_CAP_PLAIN: u32 = 1500;
/// Largest MTU honestly advertisable with MRG_RXBUF: the standard
/// jumbo MTU. The reassembly buffer for a cap-sized frame is
/// 9018 + 12 header bytes (3 pages) — bounded, not MTU-unbounded.
const RX_MTU_CAP_MRG: u32 = 9000;

/// Largest frame (header excluded) the datapath accepts for a given
/// advertised MTU: MTU + Ethernet header + VLAN tag headroom.
const fn max_frame_for_mtu(mtu: u32) -> usize {
    mtu as usize + ETH_HDR_LEN + VLAN_TAG_LEN
}

/// Maximum number of posted buffers one merged RX frame may span.
/// A cap-sized jumbo frame needs at most 6 (1518 first payload +
/// 1530 per continuation); 16 is generous headroom, and anything
/// above it is a pathological split (or a corrupt `num_buffers`)
/// dropped fail-closed.
const RX_MRG_MAX_BUFFERS: usize = 16;

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
    /// Active RX/TX queue pairs. Always non-empty post-bring_up.
    /// Each pair owns one MSI-X vector under `partition` (see
    /// `enable_rx_msix_all`): the pair's RX queue (2K) is bound to
    /// it, and its TX queue (2K+1) shares the same slot — one
    /// vector per pair, which VirtIO 1.2 §4.1.5.2 permits — so the
    /// pair's RX forwarder is the ISR consumer for both queues.
    /// Without `partition` only pair 0 gets a vector and pairs
    /// 1..N poll: a deliberate, measured perf gate (an extra
    /// queue's IRQ interrupts the busy worker core on a shared
    /// core), not a gap.
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
    /// IDT vector bound to the device-config-change MSI-X vector
    /// (`msix_config`, common-cfg 0x10). `None` = the table had no
    /// free slot (or the device rejected the binding) and link
    /// state stays poll-based via `link_up()`; `Some(v)` means the
    /// config-change watcher parks on `v` and republishes link
    /// metadata on every config-change interrupt. Routed to the
    /// BSP: config changes are rare, no per-pair affinity applies.
    pub config_irq_vector: Option<u8>,
    /// MSI-X table handle, retained across suspend so resume can
    /// re-enable the same programmed vectors without the probe-time
    /// `Cap` + `BusDevice`. Lock-guarded (rather than plain) because
    /// suspend/resume/detach run through `&self` accessors while the
    /// probe-time `enable_*` methods run through `&mut self`.
    msix: IrqSafeSpinLock<Option<narf_bus::MsixTable>>,
    pub ready: bool,
    /// Datapath gate: set by `detach_device`, never cleared. While
    /// set, every TX/RX entry point fails fast (TX → `NoQueues`,
    /// RX take → `None`, arm → `false`, notify → no-op) so a parked
    /// pump can no longer touch the device. See the power-management
    /// section below.
    detached: AtomicBool,
    /// Datapath gate: set by `suspend`, cleared by `resume` (LAST,
    /// after MSI-X is re-enabled). Same fail-fast shape as
    /// `detached`, but the queues stay live so resume is a re-arm
    /// rather than a rebuild — see the suspend doc comment for why
    /// no device reset happens here (detach owns the reset).
    suspended: AtomicBool,
    /// Interface name this controller registered as (`eth%d`), stashed
    /// at registration time so the detach path can publish link DOWN,
    /// clear the RX-mirror note, and unregister both registries
    /// without reaching back into the registry for the name.
    ifname: IrqSafeSpinLock<Option<alloc::string::String>>,
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
    /// True when `VIRTIO_NET_F_CTRL_RX` was negotiated.
    /// `set_mac_table` short-circuits with NoQueues when this is
    /// false rather than firing a doomed CTRL_VQ command.
    has_ctrl_rx: bool,
    /// True when `VIRTIO_NET_F_CTRL_VLAN` was negotiated.
    /// `vlan_add` / `vlan_del` short-circuit with NoQueues when
    /// this is false rather than firing a doomed CTRL_VQ command.
    has_ctrl_vlan: bool,
    /// Current MTU: probe-time device value clamped by
    /// `clamp_mtu`, retargetable at runtime via `set_mtu`.
    /// `AtomicU32` so the TX/RX paths read the live value per
    /// frame with no lock, and `DeviceControl::configure`
    /// (which takes `&self`) can commit a change.
    mtu: AtomicU32,
    /// Raw device-advertised MTU from device-cfg (1500 when
    /// `VIRTIO_NET_F_MTU` wasn't negotiated or the value was
    /// below 64). Immutable after probe; the runtime ceiling is
    /// `clamp_mtu(device_mtu, mrg_rxbuf)` — the device value is
    /// the ceiling (Linux `dev->max_mtu = mtu`), further capped
    /// by what the datapath can deliver.
    device_mtu: u32,
    /// True when `VIRTIO_NET_F_STATUS` was negotiated. Without it
    /// the spec says treat link as always up.
    has_status: bool,
    /// True when `VIRTIO_NET_F_GUEST_ANNOUNCE` was negotiated
    /// (requires F_CTRL_VQ). `ack_announce` short-circuits with
    /// NoQueues when this is false rather than firing a doomed
    /// CTRL_VQ command.
    has_guest_announce: bool,
    /// True when `VIRTIO_NET_F_RSS` was negotiated (requires
    /// F_CTRL_VQ; the steering config goes through the control
    /// queue). Device-side RX steering replaces the host-backend
    /// replay the software TX affinity relied on; the affinity
    /// itself stays as the fallback and still spreads TX.
    has_rss: bool,
    /// True when `VIRTIO_NET_F_HASH_REPORT` was negotiated
    /// (requires F_CTRL_VQ). The RX header is then 20 bytes, not
    /// 12 — see `rx_hdr_len`. The hash fields themselves are
    /// parsed-and-skipped: no stack consumer reads them yet.
    has_hash_report: bool,
    /// True when the RSS_CONFIG (or HASH_CONFIG, when only hash
    /// report was negotiated) command was accepted by the device.
    /// Diagnostic only: a refused config costs steering, never
    /// the device — all pairs still deliver to one Interface.
    rss_configured: bool,
    /// RX header length in bytes: 20 with HASH_REPORT, else 12.
    /// Drives RX descriptor lengths and both strip sites; the TX
    /// header is always 12 bytes.
    rx_hdr_len: usize,
    /// TX offloads actually negotiated with this device. The legacy interface
    /// advertises exactly this profile to TCP after registration; no caller can
    /// request a partial checksum or GSO packet the transport did not accept.
    tx_checksum: bool,
    tx_tso4: bool,
    tx_tso6: bool,
    tx_uso: bool,
    /// True when `VIRTIO_NET_F_GUEST_CSUM` was negotiated. The RX
    /// forwarder then enforces the DATA_VALID verdict (see
    /// `rx_csum_deliver`); when false the device never reports
    /// validity, so the forwarder delivers everything as before.
    rx_guest_csum: bool,
    /// True when `VIRTIO_NET_F_MRG_RXBUF` was negotiated. RX frames may
    /// then span several posted buffers (`num_buffers` in the header);
    /// `rx_take_on` reassembles them before delivery. False keeps the
    /// legacy one-buffer-per-frame path byte-identical.
    mrg_rxbuf: bool,
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
/// the 4 KiB page fits a 2-byte hdr + up to `MAX_CTRL_PAYLOAD`
/// bytes of payload + 1 byte ack, covering every RX/MAC/VLAN
/// command including a large MAC table.
#[derive(Debug)]
struct CtrlQueue {
    q: Virtqueue,
    /// 4 KiB scratch page. The same page backs every submitted
    /// command (single-flight serialised by the outer lock); the
    /// device sees an [hdr|payload|ack] layout at offsets
    /// 0 / 16 / (16 + payload length) within the page.
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
    pub tso6: bool,
    pub uso: bool,
}

impl TxOffloadProfile {
    /// Virtio's TCP GSO formats always carry a partial checksum. Keep these
    /// implications explicit even though probe constructs only valid
    /// profiles, so a future feature-negotiation refactor cannot advertise
    /// GSO alone.
    const fn tso4_enabled(self) -> bool {
        self.checksum && self.tso4
    }

    const fn tso6_enabled(self) -> bool {
        self.checksum && self.tso6
    }

    const fn uso_enabled(self) -> bool {
        self.checksum && self.uso
    }

    const fn advertised(self) -> narf_net::OffloadCapabilities {
        narf_net::OffloadCapabilities {
            tx_checksum: self.checksum,
            rx_checksum: false,
            // TCP TSO capability only. USO deliberately does not raise
            // this: the TCP stack gates TSO on it regardless of IP
            // version, and a USO-only device must not be promised TCP
            // segmentation. No UDP producer reads this value yet.
            max_tso_bytes: if self.tso4_enabled() || self.tso6_enabled() {
                MAX_TX_TSO_FRAME as u32
            } else {
                0
            },
            // Software insertion at copy time (the virtio-net header
            // has no VLAN field), not a negotiated device feature:
            // always available, and it composes with checksum/TSO
            // through the VLAN-aware header layout. The zero-copy
            // path falls back to a copy for tagged frames.
            vlan_insert: true,
        }
    }
}

/// One splitmix64 step (Stafford's constants). Used only to derive
/// the fixed RSS Toeplitz key below — not a security primitive.
const fn splitmix64_next(state: u64) -> (u64, u64) {
    let next = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = next;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (next, z ^ (z >> 31))
}

/// Fixed 40-byte Toeplitz key programmed into the device's RSS
/// config, derived at compile time from a splitmix64 stream.
/// Deliberately fixed, not random: the key travels in plaintext
/// over the control queue (the host sees it by design), so
/// randomness buys no secrecy — and a fixed key makes steering
/// reproducible across boots, which is what debugging wants.
/// The test pins the derived bytes so an accidental key change
/// (which would silently re-steer every flow) fails loudly.
const fn rss_key() -> [u8; RSS_KEY_LEN] {
    let mut key = [0u8; RSS_KEY_LEN];
    let mut state: u64 = 0x51AB_3C7D_9E2F_4601;
    let mut i = 0;
    while i < RSS_KEY_LEN {
        let (next, word) = splitmix64_next(state);
        state = next;
        let mut b = 0;
        while b < 8 && i + b < RSS_KEY_LEN {
            key[i + b] = (word >> (8 * b)) as u8;
            b += 1;
        }
        i += 8;
    }
    key
}
const RSS_KEY: [u8; RSS_KEY_LEN] = rss_key();

/// RX header length for a negotiated feature set: 20 bytes with
/// HASH_REPORT, else the 12-byte base header. Pure so the strip
/// math is testable without MMIO.
pub(crate) const fn rx_header_len(hash_report: bool) -> usize {
    if hash_report {
        VIRTIO_NET_HDR_HASH_LEN
    } else {
        VIRTIO_NET_HDR_LEN
    }
}

/// Hash types to program: the device-advertised set, restricted
/// to known bits, with extension-header variants masked out
/// (Linux's choice). Falls back to the base six when nothing
/// known remains — a device advertising zero usable types still
/// gets a valid config rather than a zero-type one.
fn rss_program_hash_types(supported: u32) -> u32 {
    let types = supported & RSS_HASH_TYPE_ALL_KNOWN & !RSS_HASH_TYPE_EX_MASK;
    if types == 0 {
        RSS_HASH_TYPE_BASE
    } else {
        types
    }
}

/// Build a `VIRTIO_NET_CTRL_MQ_RSS_CONFIG` payload
/// (`virtio_net_rss_config` wire layout): hash_types (LE32),
/// indirection_table_mask (LE16), unclassified_queue (LE16 =
/// 0, Linux's choice: unhashable frames land on pair 0),
/// indirection_table (LE16 per entry, `i % num_pairs` — the
/// `ethtool_rxfh_indir_default` rule), max_tx_vq (LE16 = live
/// pair count, Linux's rule), hash_key_length, hash_key_data.
/// Returns `None` (fail-closed: caller skips the command and
/// keeps software affinity) when no valid config exists: zero
/// pairs, zero key budget, or zero indirection budget from the
/// device. Table size is the largest power of two ≤ the device
/// max, capped at `RSS_MAX_INDIR_TABLE` by the control-queue
/// payload ceiling; the mask is size − 1.
pub(crate) fn build_rss_config(
    supported_hash_types: u32,
    num_pairs: u16,
    indir_max: u16,
    key_size: u8,
) -> Option<Vec<u8>> {
    if num_pairs == 0 || key_size == 0 || indir_max == 0 {
        return None;
    }
    let mut table_size: u16 = 1;
    let capped = indir_max.min(RSS_MAX_INDIR_TABLE);
    while table_size * 2 <= capped {
        table_size *= 2;
    }
    let key_len = (key_size as usize).min(RSS_KEY_LEN);
    let mut payload = Vec::with_capacity(11 + 2 * table_size as usize + key_len);
    payload.extend_from_slice(&rss_program_hash_types(supported_hash_types).to_le_bytes());
    payload.extend_from_slice(&(table_size - 1).to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    for i in 0..table_size {
        payload.extend_from_slice(&(i % num_pairs).to_le_bytes());
    }
    payload.extend_from_slice(&num_pairs.to_le_bytes());
    payload.push(key_len as u8);
    payload.extend_from_slice(&RSS_KEY[..key_len]);
    Some(payload)
}

/// Build a `VIRTIO_NET_CTRL_MQ_HASH_CONFIG` payload
/// (`virtio_net_hash_config` wire layout): hash_types (LE32),
/// reserved[4] (8 zero bytes, for compatibility with the RSS
/// config layout), hash_key_length, hash_key_data. Same
/// fail-closed `None` rule as `build_rss_config` (minus the
/// indirection table, which hash-only config does not have).
pub(crate) fn build_hash_config(supported_hash_types: u32, key_size: u8) -> Option<Vec<u8>> {
    if key_size == 0 {
        return None;
    }
    let key_len = (key_size as usize).min(RSS_KEY_LEN);
    let mut payload = Vec::with_capacity(13 + key_len);
    payload.extend_from_slice(&rss_program_hash_types(supported_hash_types).to_le_bytes());
    payload.extend_from_slice(&[0u8; 8]);
    payload.push(key_len as u8);
    payload.extend_from_slice(&RSS_KEY[..key_len]);
    Some(payload)
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
/// Locate the L4 header and its checksum field for one transmit.
/// Returns `(l4_offset, csum_offset_within_l4)`. VLAN-aware: a
/// frame carrying a single 802.1Q tag (TPID 0x8100 at bytes 12..14)
/// shifts the IP header by `VLAN_TAG_LEN`, so checksum/TSO layout
/// computed over an inserted tag stays correct. A second tag
/// (Q-in-Q) falls through to the rejection arm — one tag only.
fn l4_checksum_layout(
    frame: &[u8],
    kind: narf_net::L4CsumKind,
) -> Result<(usize, usize), VirtioPciError> {
    if frame.len() < ETH_HDR_LEN {
        return Err(malformed_tx());
    }
    let outer = u16::from_be_bytes([frame[12], frame[13]]);
    let (l2, ethertype) = if outer == ETHERTYPE_VLAN {
        if frame.len() < ETH_HDR_LEN + VLAN_TAG_LEN {
            return Err(malformed_tx());
        }
        (
            ETH_HDR_LEN + VLAN_TAG_LEN,
            u16::from_be_bytes([frame[16], frame[17]]),
        )
    } else {
        (ETH_HDR_LEN, outer)
    };
    if frame.len() < l2 + IPV4_MIN_HDR_LEN {
        return Err(malformed_tx());
    }
    match ethertype {
        0x0800 => {
            let ip = l2;
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
            if frame.len() < l2 + IPV6_HDR_LEN || frame[l2] >> 4 != 6 {
                return Err(malformed_tx());
            }
            let payload_len = usize::from(u16::from_be_bytes([frame[l2 + 4], frame[l2 + 5]]));
            if l2 + IPV6_HDR_LEN + payload_len != frame.len() {
                return Err(malformed_tx());
            }
            let l4 = l2 + IPV6_HDR_LEN;
            match kind {
                narf_net::L4CsumKind::Tcp
                    if frame[l2 + 6] == IP_PROTO_TCP
                        && payload_len >= TCP_MIN_HDR_LEN
                        && usize::from(frame[l4 + 12] >> 4) * 4 >= TCP_MIN_HDR_LEN
                        && l4 + usize::from(frame[l4 + 12] >> 4) * 4 <= frame.len() =>
                {
                    Ok((l4, TCP_CSUM_OFFSET))
                }
                narf_net::L4CsumKind::Udp
                    if frame[l2 + 6] == 17
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

/// Build a `VIRTIO_NET_CTRL_MAC_TABLE_SET` payload: `[u32 LE unicast
/// count][unicast MACs][u32 LE multicast count][multicast MACs]`.
/// Counts are little-endian under `VIRTIO_F_VERSION_1`, matching
/// Linux `virtnet_set_rx_mode`'s `cpu_to_virtio32` encoding.
pub(crate) fn mac_table_payload(unicast: &[[u8; 6]], multicast: &[[u8; 6]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 6 * (unicast.len() + multicast.len()));
    out.extend_from_slice(&(unicast.len() as u32).to_le_bytes());
    for mac in unicast {
        out.extend_from_slice(mac);
    }
    out.extend_from_slice(&(multicast.len() as u32).to_le_bytes());
    for mac in multicast {
        out.extend_from_slice(mac);
    }
    out
}

/// Copy `frame` into `dst` inserting an 802.1Q tag after the two
/// MAC addresses: `[dst | src | 0x8100 | TCI | EtherType |
/// payload]`. The tag is the full 16-bit TCI (PCP + CFI + VID) as
/// carried by `TxMeta::vlan_tag`. Returns the tagged length, or
/// `None` when the frame is too short to carry a tag (it needs
/// dst + src MAC + EtherType) or `dst` cannot hold the tagged
/// frame. The virtio-net header has no VLAN field, so software
/// insertion at copy time is the only insertion path — the device
/// just transmits the tagged bytes it is given.
pub(crate) fn copy_frame_with_vlan(dst: &mut [u8], frame: &[u8], tag: u16) -> Option<usize> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }
    let new_len = frame.len() + VLAN_TAG_LEN;
    if dst.len() < new_len {
        return None;
    }
    dst[..12].copy_from_slice(&frame[..12]);
    dst[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
    dst[14..16].copy_from_slice(&tag.to_be_bytes());
    dst[16..new_len].copy_from_slice(&frame[12..]);
    Some(new_len)
}

/// The IPv4 GSO checksum seed for any L4 protocol: the folded
/// one's-complement sum of the pseudo-header (src, dst, proto, zero length)
/// — the same convention as `narf_net::pkt_tcp::ipv4_tcp_pseudo_seed`
/// (which hardcodes TCP and returns the double-negated sum, i.e. the sum
/// itself). The device adds the per-segment length when it completes the
/// checksum, so the seed carries length zero. Used for USO; TCPv4 GSO keeps
/// calling the in-tree helper directly.
pub(crate) fn ipv4_pseudo_seed(src: [u8; 4], dst: [u8; 4], proto: u8) -> u16 {
    let mut sum: u32 = 0;
    for addr in [src, dst] {
        sum += u32::from(u16::from_be_bytes([addr[0], addr[1]]));
        sum += u32::from(u16::from_be_bytes([addr[2], addr[3]]));
    }
    sum += u32::from(proto);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The IPv6 GSO checksum seed (RFC 2460 §8.1): the folded
/// one's-complement sum of the pseudo-header (src, dst, zero 32-bit length,
/// next header) — the v6 analog of [`ipv4_pseudo_seed`]. The length word
/// contributes zero and is omitted. The device adds the per-segment length
/// when it completes the checksum.
pub(crate) fn ipv6_pseudo_seed(src: &[u8; 16], dst: &[u8; 16], next_header: u8) -> u16 {
    let mut sum: u32 = 0;
    for addr in [src, dst] {
        for pair in addr.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
    }
    sum += u32::from(next_header);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Prepare the virtio-net header for one transmit. This is deliberately
/// feature-gated: a frame carrying partial checksum data or GSO metadata must
/// never reach a device that did not negotiate the matching virtio feature.
/// `max_plain_frame` caps non-GSO frames (plain + checksum): the
/// advertised MTU + headers, so a jumbo-MTU device accepts jumbo plain
/// frames while a standard-MTU device keeps the old 1518 bound exactly
/// (1500 + 14 + 4). The GSO arm keeps its own `MAX_TX_TSO_FRAME` cap.
pub(crate) fn tx_header_for_frame(
    frame: &mut [u8],
    meta: narf_net::TxMeta,
    profile: TxOffloadProfile,
    max_plain_frame: usize,
) -> Result<VirtioNetHdr, VirtioPciError> {
    // A vlan_tag reaching this point is a caller error: insertion
    // happens at copy time in the send fns (`vnet0_send_fn` /
    // `vnet0_send_frame_zc`'s copy fallback), which clear the tag
    // before submitting. By the time a frame is laid out here, any
    // tag is already bytes in the frame, and the VLAN-aware layout
    // below handles it. Rejecting here keeps a direct caller from
    // silently dropping a tag it expected to be inserted.
    if frame.is_empty() || meta.vlan_tag.is_some() {
        return Err(malformed_tx());
    }

    match (meta.tso_mss, meta.csum_l4) {
        (Some(_), Some(narf_net::L4CsumKind::Tcp)) => {
            if frame.len() > MAX_TX_TSO_FRAME {
                return Err(malformed_tx());
            }
            let (l4, csum_offset) = l4_checksum_layout(frame, narf_net::L4CsumKind::Tcp)?;
            // ECN GSO needs the separately negotiated HOST_ECN feature. NARF
            // does not advertise ECN today, so reject instead of emitting an
            // invalid TCP GSO header if a future caller requests it.
            if frame[l4 + 13] & TCP_ECE_OR_CWR != 0 {
                return Err(malformed_tx());
            }
            let tcp_hlen = usize::from(frame[l4 + 12] >> 4) * 4;
            let header_len = l4 + tcp_hlen;
            let mss = meta.tso_mss.expect("matched Some TCP TSO metadata");
            if mss == 0 || frame.len() <= header_len {
                return Err(malformed_tx());
            }
            // The stack gates TSO only on `max_tso_bytes`, not on IP
            // version, so a v6 TCP flow can arrive here. Dispatch on
            // ethertype: previously every TCP GSO frame took the v4
            // path, mislabeling v6 super-frames as TCPV4 with a seed
            // read from the wrong offsets. A v6 frame with only TSO4
            // negotiated is now rejected instead of mis-emitted.
            let ip = ETH_HDR_LEN;
            match u16::from_be_bytes([frame[12], frame[13]]) {
                0x0800 => {
                    if !profile.tso4_enabled() {
                        return Err(malformed_tx());
                    }
                    // For TCP GSO the partial checksum is the pseudo-header
                    // with a zero TCP length. The device fills each
                    // segment's length before completing the checksum,
                    // matching the 8254x TSO preparation.
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
                    frame[l4 + csum_offset..l4 + csum_offset + 2]
                        .copy_from_slice(&seed.to_be_bytes());
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
                0x86dd => {
                    if !profile.tso6_enabled() {
                        return Err(malformed_tx());
                    }
                    // IPv6 header: 8 bytes of version/traffic/flow +
                    // payload-length + next-header + hop-limit, then the
                    // 16-byte source and destination addresses.
                    let mut src = [0u8; 16];
                    let mut dst = [0u8; 16];
                    src.copy_from_slice(&frame[ip + 8..ip + 24]);
                    dst.copy_from_slice(&frame[ip + 24..ip + IPV6_HDR_LEN]);
                    let seed = ipv6_pseudo_seed(&src, &dst, IP_PROTO_TCP);
                    frame[l4 + csum_offset..l4 + csum_offset + 2]
                        .copy_from_slice(&seed.to_be_bytes());
                    Ok(VirtioNetHdr {
                        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                        gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
                        hdr_len: (header_len as u16).to_le(),
                        gso_size: mss.to_le(),
                        csum_start: (l4 as u16).to_le(),
                        csum_offset: (csum_offset as u16).to_le(),
                        num_buffers: 0,
                    })
                }
                _ => Err(malformed_tx()),
            }
        }
        (Some(_), Some(narf_net::L4CsumKind::Udp)) => {
            // USO: the device segments one large UDP payload into
            // several datagrams, each carrying a UDP header
            // (`GSO_UDP_L4`), with `gso_size` payload bytes per
            // segment. Same partial-checksum contract as TCP GSO: the
            // checksum field carries the zero-length pseudo-header
            // seed and the device completes it per segment. No
            // in-tree producer emits USO metadata yet (the TCP stack
            // is the only GSO producer); this is the device side,
            // header-encoder- and burst-tested, awaiting a UDP GSO
            // producer. The template's UDP length field describes
            // the whole super-frame payload, as `l4_checksum_layout`
            // validates; the device rewrites it per segment.
            if !profile.uso_enabled() || frame.len() > MAX_TX_TSO_FRAME {
                return Err(malformed_tx());
            }
            let (l4, csum_offset) = l4_checksum_layout(frame, narf_net::L4CsumKind::Udp)?;
            let header_len = l4 + UDP_HDR_LEN;
            let mss = meta.tso_mss.expect("matched Some UDP USO metadata");
            if mss == 0 || frame.len() <= header_len {
                return Err(malformed_tx());
            }
            let ip = ETH_HDR_LEN;
            let seed = match u16::from_be_bytes([frame[12], frame[13]]) {
                0x0800 => ipv4_pseudo_seed(
                    [
                        frame[ip + 12],
                        frame[ip + 13],
                        frame[ip + 14],
                        frame[ip + 15],
                    ],
                    [
                        frame[ip + 16],
                        frame[ip + 17],
                        frame[ip + 18],
                        frame[ip + 19],
                    ],
                    IP_PROTO_UDP,
                ),
                0x86dd => {
                    let mut src = [0u8; 16];
                    let mut dst = [0u8; 16];
                    src.copy_from_slice(&frame[ip + 8..ip + 24]);
                    dst.copy_from_slice(&frame[ip + 24..ip + IPV6_HDR_LEN]);
                    ipv6_pseudo_seed(&src, &dst, IP_PROTO_UDP)
                }
                _ => return Err(malformed_tx()),
            };
            frame[l4 + csum_offset..l4 + csum_offset + 2].copy_from_slice(&seed.to_be_bytes());
            Ok(VirtioNetHdr {
                flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
                hdr_len: (header_len as u16).to_le(),
                gso_size: mss.to_le(),
                csum_start: (l4 as u16).to_le(),
                csum_offset: (csum_offset as u16).to_le(),
                num_buffers: 0,
            })
        }
        (Some(_), _) => Err(malformed_tx()),
        (None, Some(kind)) => {
            if !profile.checksum || frame.len() > max_plain_frame {
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
        (None, None) if frame.len() <= max_plain_frame => Ok(VirtioNetHdr::default()),
        (None, None) => Err(malformed_tx()),
    }
}

/// Decode the mergeable-buffer count from an RX header's `num_buffers`
/// field (bytes 10..12, little-endian under VIRTIO_F_VERSION_1).
/// `None` when the slice is shorter than the 12-byte header.
fn mrg_num_buffers(hdr: &[u8]) -> Option<u16> {
    let b = hdr.get(10..12)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Pure shape check for a merged RX frame (testable without hardware).
/// `first_len` is the first used entry's length including the
/// `rx_hdr_len`-byte virtio header (12, or 20 with HASH_REPORT);
/// `cont_lens` are the continuation used lengths (raw payload, no
/// header). Returns the frame payload length (header excluded) when
/// the shape is deliverable, else `None`:
/// - `num_buffers` in 1..=RX_MRG_MAX_BUFFERS and matching the collected
///   segment count (a short collection means the device published
///   fewer used entries than promised — fail closed, never deliver
///   a prefix as a frame);
/// - every segment within the posted descriptor length
///   (`rx_hdr_len + MAX_RX_FRAME_PAYLOAD` — the length the probe,
///   single-path, and MRG refills all post);
/// - the reassembled frame within the advertised MTU + headers.
fn mrg_frame_payload_len(
    first_len: usize,
    cont_lens: &[usize],
    num_buffers: usize,
    mtu: u32,
    rx_hdr_len: usize,
) -> Option<usize> {
    if num_buffers == 0 || num_buffers > RX_MRG_MAX_BUFFERS {
        return None;
    }
    if cont_lens.len() + 1 != num_buffers {
        return None;
    }
    let posted = rx_hdr_len + MAX_RX_FRAME_PAYLOAD;
    if first_len < rx_hdr_len || first_len > posted {
        return None;
    }
    if cont_lens.iter().any(|&l| l > posted) {
        return None;
    }
    let payload = first_len - rx_hdr_len + cont_lens.iter().sum::<usize>();
    if payload > max_frame_for_mtu(mtu) {
        return None;
    }
    Some(payload)
}

/// Pure MTU clamp (testable): never advertise an MTU the datapath
/// cannot deliver. Without MRG_RXBUF the datapath caps at a standard
/// frame; with it, at the jumbo cap.
fn clamp_mtu(device_mtu: u32, mrg: bool) -> u32 {
    device_mtu.min(if mrg {
        RX_MTU_CAP_MRG
    } else {
        RX_MTU_CAP_PLAIN
    })
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
        // checksum/GSO profile when the device offers it. Every HOST_* GSO
        // feature depends on CSUM: a GSO packet must carry
        // VIRTIO_NET_HDR_F_NEEDS_CSUM, and accepting any of them means the
        // matching TX header is emitted below. Do not acknowledge an
        // offload feature merely to inspect it; that would permit a
        // partial packet to reach a device that was never told how to
        // complete it. HOST_UFO is not taken (see
        // `VIRTIO_NET_F_HOST_USO`): its fragmentation semantics do not
        // match the segmentation `TxMeta` requests.
        let want_mac = feats & (1u64 << VIRTIO_NET_F_MAC) != 0;
        let want_mrg = feats & (1u64 << VIRTIO_NET_F_MRG_RXBUF) != 0;
        let want_status = feats & (1u64 << VIRTIO_NET_F_STATUS) != 0;
        let want_mtu = feats & (1u64 << VIRTIO_NET_F_MTU) != 0;
        let want_csum = feats & (1u64 << VIRTIO_NET_F_CSUM) != 0;
        let want_tso4 = want_csum && feats & (1u64 << VIRTIO_NET_F_HOST_TSO4) != 0;
        let want_tso6 = want_csum && feats & (1u64 << VIRTIO_NET_F_HOST_TSO6) != 0;
        let want_uso = want_csum && feats & (1u64 << VIRTIO_NET_F_HOST_USO) != 0;
        // GUEST_CSUM is independent of the TX profile: the device
        // validates RX checksums and reports DATA_VALID per frame.
        // Negotiating it never changes a TX header (the RX verdict
        // path below reads the device-supplied flag only).
        let want_guest_csum = feats & (1u64 << VIRTIO_NET_F_GUEST_CSUM) != 0;
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
        // F_CTRL_RX gates MAC_TABLE_SET; F_CTRL_VLAN gates VLAN_ADD /
        // VLAN_DEL. Same F_CTRL_VQ dependency.
        let want_ctrl_rx = (feats & (1u64 << VIRTIO_NET_F_CTRL_RX) != 0) && want_ctrl_vq;
        let want_ctrl_vlan = (feats & (1u64 << VIRTIO_NET_F_CTRL_VLAN) != 0) && want_ctrl_vq;
        // F_GUEST_ANNOUNCE gates the ANNOUNCE_ACK command; same
        // F_CTRL_VQ dependency as the other control-queue features
        // (Linux fails the feature without CTRL_VQ).
        let want_guest_announce =
            (feats & (1u64 << VIRTIO_NET_F_GUEST_ANNOUNCE) != 0) && want_ctrl_vq;
        // F_RSS / F_HASH_REPORT gate on the control queue too: the
        // steering + hash params travel via CTRL_MQ commands. Both
        // live in the high feature half (bits 57/60), unlike the
        // low-half bits above — see drv_hi.
        let want_rss = (feats & (1u64 << VIRTIO_NET_F_RSS) != 0) && want_ctrl_vq;
        let want_hash_report = (feats & (1u64 << VIRTIO_NET_F_HASH_REPORT) != 0) && want_ctrl_vq;
        let want_event_idx = feats & (1u64 << VIRTIO_RING_F_EVENT_IDX) != 0;
        // virtio-net F_* bits we care about live in the low 32
        // (max is F_CTRL_MAC_ADDR = 23; RING_F_EVENT_IDX = 29) except
        // the high half, which carries F_VERSION_1 = 32 (high-half
        // bit 0), F_HOST_USO = 56 (high-half bit 24),
        // F_HASH_REPORT = 57 and F_RSS = 60 — see drv_hi.
        let drv_lo = ((1u32 << VIRTIO_NET_F_MAC) * (want_mac as u32))
            | ((1u32 << VIRTIO_NET_F_MTU) * (want_mtu as u32))
            | ((1u32 << VIRTIO_NET_F_CSUM) * (want_csum as u32))
            | ((1u32 << VIRTIO_NET_F_GUEST_CSUM) * (want_guest_csum as u32))
            | ((1u32 << VIRTIO_NET_F_HOST_TSO4) * (want_tso4 as u32))
            | ((1u32 << VIRTIO_NET_F_HOST_TSO6) * (want_tso6 as u32))
            | ((1u32 << VIRTIO_NET_F_MRG_RXBUF) * (want_mrg as u32))
            | ((1u32 << VIRTIO_NET_F_STATUS) * (want_status as u32))
            | ((1u32 << VIRTIO_NET_F_CTRL_VQ) * (want_ctrl_vq as u32))
            | ((1u32 << VIRTIO_NET_F_MQ) * (want_mq as u32))
            | ((1u32 << VIRTIO_RING_F_EVENT_IDX) * (want_event_idx as u32))
            | ((1u32 << VIRTIO_NET_F_CTRL_RX) * (want_ctrl_rx as u32))
            | ((1u32 << VIRTIO_NET_F_CTRL_VLAN) * (want_ctrl_vlan as u32))
            | ((1u32 << VIRTIO_NET_F_GUEST_ANNOUNCE) * (want_guest_announce as u32))
            | ((1u32 << VIRTIO_NET_F_CTRL_MAC_ADDR) * (want_ctrl_mac_addr as u32));
        let drv_hi = (1u32 << (VIRTIO_F_VERSION_1 - 32))
            | ((1u32 << (VIRTIO_NET_F_HOST_USO - 32)) * (want_uso as u32))
            | ((1u32 << (VIRTIO_NET_F_HASH_REPORT - 32)) * (want_hash_report as u32))
            | ((1u32 << (VIRTIO_NET_F_RSS - 32)) * (want_rss as u32));
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

        // RX header length for this device: 20 bytes with
        // HASH_REPORT, else 12. RX descriptor lengths below are
        // `rx_hdr_len + MAX_RX_FRAME_PAYLOAD` so a max-size frame
        // still fits under the extended header.
        let rx_hdr_len = rx_header_len(want_hash_report);

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
                    len: (rx_hdr_len + MAX_RX_FRAME_PAYLOAD) as u32,
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
        // RSS device-cfg inputs (zero unless RSS/hash-report was
        // offered — the fields are only valid then).
        let mut rss_max_key_size: u8 = 0;
        let mut rss_max_indir_len: u16 = 0;
        let mut rss_supported_hash_types: u32 = 0;
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
            if want_rss || want_hash_report {
                // SAFETY: same. RSS fields at packed offsets 17
                // (u8), 18 (u16 LE), 20 (u32 LE); only valid when
                // the device offered RSS or HASH_REPORT.
                rss_max_key_size = unsafe { r.read8(CFG_RSS_MAX_KEY_SIZE) };
                // SAFETY: same. RSS max indir len at packed offset 18 (u16 LE);
                // only valid when RSS or HASH_REPORT was offered.
                rss_max_indir_len = unsafe { r.read16(CFG_RSS_MAX_INDIR_LEN) };
                // SAFETY: same. Supported hash types at packed offset 20 (u32 LE);
                // only valid when RSS or HASH_REPORT was offered.
                rss_supported_hash_types = unsafe { r.read32(CFG_SUPPORTED_HASH_TYPES) };
            }
        }
        // Clamp to what the datapath can actually deliver (audit
        // gap 4): without MRG_RXBUF a device advertising MTU 9000
        // previously got 9000 published while RX capped at 1518
        // and TX rejected past 1518 — the stack sized frames the
        // driver could never move. With MRG the jumbo cap applies.
        // A no-op at the QEMU default (1500) either way.
        // Keep the raw advertised value: it is the runtime ceiling
        // (Linux `dev->max_mtu`), while `mtu` is the clamped live
        // value `set_mtu` retargets within that ceiling.
        let device_mtu = mtu;
        mtu = clamp_mtu(mtu, want_mrg);
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
            config_irq_vector: None,
            msix: IrqSafeSpinLock::new(None),
            ready: true,
            detached: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            ifname: IrqSafeSpinLock::new(None),
            mac: IrqSafeSpinLock::new(mac),
            has_ctrl_mac_addr: want_ctrl_mac_addr,
            has_ctrl_rx: want_ctrl_rx,
            has_ctrl_vlan: want_ctrl_vlan,
            mtu: AtomicU32::new(mtu),
            device_mtu,
            has_status: want_status,
            has_guest_announce: want_guest_announce,
            has_rss: want_rss,
            has_hash_report: want_hash_report,
            rss_configured: false,
            rx_hdr_len,
            tx_checksum: want_csum,
            tx_tso4: want_tso4,
            tx_tso6: want_tso6,
            tx_uso: want_uso,
            rx_guest_csum: want_guest_csum,
            mrg_rxbuf: want_mrg,
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
        // VirtIO 1.2 §5.1.6.5.5: device RSS steering. RSS_CONFIG
        // also (re)sets the pair count via max_tx_vq, so it runs
        // AFTER VQ_PAIRS_SET — if the device refuses RSS, the pair
        // count from VQ_PAIRS_SET already stands and software
        // affinity keeps working. Best-effort like VQ_PAIRS_SET: a
        // refused config only costs steering, never the device
        // (all pairs still deliver to the same Interface, and
        // every pair of the primary controller feeds software
        // GRO through its synchronous tap — #1533: the audit's
        // gap-9 "pair-0-only GRO" reading misread the
        // controller-`idx` gate). The pair
        // count programmed is the LIVE count (`this.pairs.len()`),
        // not the pre-truncation request, so a refused pairs-set
        // that truncated to pair 0 cannot resurrect dead pairs
        // through the RSS command. With RSS negotiated, TX
        // affinity no longer implies RX queue correspondence
        // (the device, not the TX queue, picks the RX queue) — it
        // stays purely as TX-side spreading + the fallback when
        // RSS was not negotiated.
        if want_rss {
            if let Some(payload) = build_rss_config(
                rss_supported_hash_types,
                this.pairs.len() as u16,
                rss_max_indir_len,
                rss_max_key_size,
            ) {
                if let Ok(VIRTIO_NET_OK) =
                    this.submit_control(VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_RSS_CONFIG, &payload)
                {
                    this.rss_configured = true;
                }
            }
        } else if want_hash_report {
            if let Some(payload) = build_hash_config(rss_supported_hash_types, rss_max_key_size) {
                if let Ok(VIRTIO_NET_OK) = this.submit_control(
                    VIRTIO_NET_CTRL_MQ,
                    VIRTIO_NET_CTRL_MQ_HASH_CONFIG,
                    &payload,
                ) {
                    this.rss_configured = true;
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

    /// Bind EVERY active RX queue pair to its own MSI-X vector, each routed
    /// to the CPU its forwarder will run on, so no forwarder has to fall
    /// back to a blind 2ms poll sleep between sparse frames. This is the
    /// multi-queue completion of the old pair-0-only MSI-X setup.
    /// Each pair's TX queue (2K+1) shares its RX queue's (2K) table
    /// slot — one vector per pair, which VirtIO 1.2 §4.1.5.2
    /// permits — so the pair's RX forwarder is the ISR consumer for
    /// both queues (see `bind_tx_queue_shares`). The per-pair
    /// routing CPU mirrors the forwarder placement in the
    /// RX-forwarder spawn (`partition` ⇒ pair K → CPU K, else CPU 0) so
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
        let (table, bindings) =
            unsafe { crate::pci::enable_msix_rx_queues(&self.common, cap, device, &targets) }?;
        // Share each pair's vector with its TX queue (see
        // `bind_tx_queue_shares`): one vector per pair, not per queue.
        self.bind_tx_queue_shares(&bindings);
        self.irq_vector = bindings.first().and_then(|b| b.idt_vector);
        self.rx_irq_vectors = bindings.iter().map(|b| b.idt_vector).collect();
        *self.msix.lock() = Some(table);
        Ok(())
    }

    /// Point each pair's TX queue (2K+1) at the same MSI-X table
    /// slot as its RX queue (2K). VirtIO 1.2 §4.1.5.2 permits
    /// several queues sharing one vector, and one vector per pair
    /// (not per queue) is the point of this shape:
    /// - Table economy: the device needs N+1 slots (pairs +
    ///   config) instead of 2N+1, so the config vector survives
    ///   even on a short table (QEMU's MQ default is 2N+2, but a
    ///   stingy table still fits).
    /// - The pair's RX forwarder — already parking on the vector —
    ///   is the ISR consumer for both queues, so no vector is ever
    ///   programmed without a waiter. A separate TX vector would
    ///   only add host MSI traffic for a vector nobody parks on:
    ///   TX completions are reclaimed lazily at submit time (the §0
    ///   design — fire-and-forget + reclaim-before-backpressure),
    ///   and nothing in the driver blocks on a TX completion.
    ///   Cost, stated plainly: a TX completion also wakes the pair's
    ///   RX forwarder, which drains an (empty) RX ring and re-parks —
    ///   one cheap empty drain per TX batch while idle, a no-op while
    ///   the forwarder is fast-polling. Binding after the table is
    ///   enabled is safe: the TX queue was NO_VECTOR until this
    ///   write, so no TX interrupt can be in flight using the old
    ///   value. A rejected share leaves the TX queue unbound
    ///   (NO_VECTOR) — the pre-lane behaviour, not an error.
    fn bind_tx_queue_shares(&self, bindings: &[MsixQueueBinding]) {
        for (k, b) in bindings.iter().enumerate() {
            if let Some(slot) = b.slot {
                // SAFETY: caller owns the device exclusively; the
                // slot was just programmed by `enable_msix_rx_queues`.
                let _ = unsafe { bind_queue_msix_vector(&self.common, 2 * k as u16 + 1, slot) };
            }
        }
    }

    /// Bind the device-config-change MSI-X vector (`msix_config`,
    /// common-cfg 0x10, VirtIO 1.2 §4.1.5.2) to a fresh IDT vector
    /// routed to the BSP, so link/config changes arrive as an
    /// interrupt instead of waiting for a `link_up()` poll. Uses
    /// the table retained by `enable_rx_msix_all` — never
    /// re-discovers it (a fresh `enable_msix` resets the slot
    /// allocator to 0 and would reprogram slot 0 underneath the
    /// live pair bindings). If no table is retained yet (RX MSI-X
    /// never enabled), acquires one and enables it here. The
    /// config vector is allocated AFTER the pair vectors, so on a
    /// short table it is the config vector that degrades (link
    /// stays poll-based) while the pairs keep theirs. Best-effort
    /// at probe: `Err` leaves `config_irq_vector` unset.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg-space exclusively (probe,
    /// before the controller is shared into `CONTROLLERS`).
    pub unsafe fn enable_config_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, VirtioPciError> {
        // Config changes are rare; route to the BSP.
        let apic = narf_interrupts::apic_id_at(0).unwrap_or(0);
        let mut guard = self.msix.lock();
        if guard.is_none() {
            // SAFETY: caller owns the device.
            let table = narf_bus::msix::enable_msix(cap, device)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            *guard = Some(table);
        }
        let table = guard.as_mut().ok_or(VirtioPciError::BarMapFailed)?;
        // SAFETY: caller owns the device's BAR exclusively.
        let (v, slot) = unsafe { alloc_msix_config_vector(&mut *table, apic) }?;
        // SAFETY: caller owns the common-cfg region exclusively.
        if !unsafe { bind_config_msix_vector(&self.common, slot) } {
            return Err(VirtioPciError::BarMapFailed);
        }
        // Idempotent when the table is already enabled (the RX path
        // enabled it); required when this call acquired a fresh table.
        // SAFETY: caller owns the device's config space.
        unsafe { table.enable() }.map_err(|_| VirtioPciError::BarMapFailed)?;
        self.config_irq_vector = Some(v);
        Ok(v)
    }

    /// Number of active TX/RX queue pairs after `bring_up` (and
    /// after the optional `VQ_PAIRS_SET` ack). Always ≥ 1.
    pub fn num_pairs(&self) -> usize {
        self.pairs.len()
    }

    /// True when `VIRTIO_NET_F_GUEST_CSUM` was negotiated with this
    /// device. The negotiated set is immutable after probe, so the RX
    /// forwarder snapshots this once instead of consulting it per frame.
    pub fn rx_guest_csum(&self) -> bool {
        self.rx_guest_csum
    }

    fn tx_offload_profile(&self) -> TxOffloadProfile {
        TxOffloadProfile {
            checksum: self.tx_checksum,
            tso4: self.tx_tso4,
            tso6: self.tx_tso6,
            uso: self.tx_uso,
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
        if self.datapath_gated() {
            return None;
        }
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
    /// A buffer whose size differs from the pool's is also dropped, not
    /// pooled: reassembled merged frames are larger than the 4 KiB pool
    /// buffers, and pooling one would hand a wrong-sized buffer to a
    /// later refill (`DmaPool::release` drops only undersized buffers,
    /// so an oversized one would be retained — a latent pool wart this
    /// driver does not rely on). Jumbo frames are rare; the buddy free
    /// is cheap.
    pub fn rx_buf_release_on(&self, pair_idx: usize, buf: DmaBuffer) {
        if let Some(pair) = self.pairs.get(pair_idx) {
            if buf.len() != pair.rx_pool.buf_len() {
                drop(buf);
            } else {
                pair.rx_pool.release(buf);
            }
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
        // Gate FIRST, before any header write or ring touch: a
        // refused frame's caller-owned buffer goes back to its
        // queue-local pool (mirroring the ring-full path below) so
        // a gated device never drains the fixed TX pool.
        if self.datapath_gated() {
            self.tx_buf_release_on(pair_idx, buf);
            return Err(VirtioPciError::NoQueues);
        }
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
                max_frame_for_mtu(self.mtu()),
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
    /// wasn't offered. Always clamped to what the datapath can
    /// deliver (see the probe-time `clamp_mtu` call); retargeted
    /// at runtime by `set_mtu` within `max_mtu()`.
    pub fn mtu(&self) -> u32 {
        self.mtu.load(Ordering::Acquire)
    }

    /// Runtime MTU ceiling: the device-advertised MTU, capped by
    /// what the datapath can deliver (`clamp_mtu`). Linux sets
    /// `dev->max_mtu` to the device MTU when `VIRTIO_NET_F_MTU`
    /// is negotiated; NARF additionally caps at the no-MRG (1500)
    /// / MRG (9000) datapath bound, so `set_mtu` can never
    /// advertise a value the datapath would reject.
    pub fn max_mtu(&self) -> u32 {
        clamp_mtu(self.device_mtu, self.mrg_rxbuf)
    }

    /// Change the MTU at runtime (Linux `ndo_change_mtu` analog;
    /// virtio-net has no MTU-set control command — the device MTU
    /// is advisory and the guest stack value is what matters, so
    /// Linux's generic `eth_change_mtu` likewise just sets
    /// `dev->mtu`).
    ///
    /// Valid range is `MIN_MTU..=max_mtu()` (68..=device ceiling);
    /// anything else is `InvalidArgument` and the live MTU is
    /// untouched. No stop/reset dance (unlike igc): there is no
    /// MTU register to program — the TX plain-frame cap and the
    /// RX reassembly bound both read the live `mtu()` per frame,
    /// so the new value applies to subsequently submitted frames
    /// only and in-flight frames complete under the old bound.
    /// No control-queue command is issued.
    pub fn set_mtu(&self, mtu: u32) -> Result<(), VirtioPciError> {
        if !(MIN_MTU..=self.max_mtu()).contains(&mtu) {
            return Err(VirtioPciError::InvalidArgument);
        }
        self.mtu.store(mtu, Ordering::Release);
        Ok(())
    }
    /// True when `VIRTIO_NET_F_RSS` was negotiated.
    pub fn has_rss(&self) -> bool {
        self.has_rss
    }

    /// True when `VIRTIO_NET_F_HASH_REPORT` was negotiated.
    pub fn has_hash_report(&self) -> bool {
        self.has_hash_report
    }

    /// True when the device accepted the RSS_CONFIG (or
    /// HASH_CONFIG) command. Diagnostic: a refused config only
    /// costs steering, never the device.
    pub fn rss_configured(&self) -> bool {
        self.rss_configured
    }

    /// RX header length in bytes: 20 with HASH_REPORT, else 12.
    pub fn rx_hdr_len(&self) -> usize {
        self.rx_hdr_len
    }

    /// Whether mergeable RX buffers were negotiated with this device.
    pub fn mrg_rxbuf(&self) -> bool {
        self.mrg_rxbuf
    }

    /// Live link state. Reads the status word from device-cfg every
    /// call when `VIRTIO_NET_F_STATUS` was negotiated; returns
    /// `true` unconditionally otherwise (spec: absence of the
    /// feature means assume link up). Suspended or detached →
    /// `false` (e1000 parity: probe-time link AND NOT suspended).
    pub fn link_up(&self) -> bool {
        if self.datapath_gated() {
            return false;
        }
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

    /// Re-read live link state and republish it to the interface
    /// registry. The config-change watcher's per-fire action (and
    /// the resume path's shape): `link_up()` reads STATUS when
    /// F_STATUS was negotiated, else assumes up. Returns the link
    /// state. A controller with no registered name (probe never
    /// reached `register_net_interface`) still returns the state
    /// but publishes nothing.
    pub fn refresh_link_from_status(&self) -> bool {
        let link = self.link_up();
        if let Some(name) = self.ifname.lock().as_deref() {
            narf_net::iface::set_link_metadata(name, link, None, None);
        }
        link
    }

    /// Raw device-cfg STATUS word. `0` when F_STATUS wasn't
    /// negotiated or the device has no config region — the spec
    /// has no status word to read in either case, and no announce
    /// bit can be set.
    fn status_word(&self) -> u16 {
        if !self.has_status {
            return 0;
        }
        let r = match self.device_cfg.as_ref() {
            Some(r) => r,
            None => return 0,
        };
        // SAFETY: device-cfg region was mapped at bring_up; field
        // at offset 6 stays valid for the controller's lifetime.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { r.read16(CFG_STATUS) }
    }

    /// True when the device is asking for an announce: the
    /// `VIRTIO_NET_S_ANNOUNCE` status bit is set and
    /// `VIRTIO_NET_F_GUEST_ANNOUNCE` was negotiated. Without the
    /// feature the bit is meaningless (and without F_STATUS there
    /// is no word to read), so both gates apply.
    pub fn announce_pending(&self) -> bool {
        self.has_guest_announce && self.status_word() & VIRTIO_NET_S_ANNOUNCE != 0
    }

    /// Acknowledge a device announce request via
    /// `VIRTIO_NET_CTRL_ANNOUNCE_ACK` (VirtIO 1.2 §5.1.6.5.4).
    /// No payload — Linux `virtnet_ack_link_announce` sends NULL
    /// data. The device clears `VIRTIO_NET_S_ANNOUNCE` on receipt,
    /// so a successful ack is what stops the next config-change
    /// fire from re-announcing.
    pub fn ack_announce(&self) -> Result<(), VirtioPciError> {
        if !self.has_guest_announce {
            return Err(VirtioPciError::NoQueues);
        }
        let ack =
            self.submit_control(VIRTIO_NET_CTRL_ANNOUNCE, VIRTIO_NET_CTRL_ANNOUNCE_ACK, &[])?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Notify peers of our MAC location (Linux `netdev_notify_peers`):
    /// gratuitous ARP for the interface's primary IPv4 address, via
    /// the stack's existing `send_gratuitous_arp` surface, plus one
    /// unsolicited Neighbor Advertisement per usable IPv6 address
    /// (RFC 4861 §7.2.6), via the stack's `send_unsolicited_na`
    /// surface (#1536). No-op when the controller has no registered
    /// name; each half independently sends nothing when the
    /// interface has no address of that family.
    fn notify_peers(&self) {
        let name = match self.ifname.lock().as_deref() {
            Some(n) => alloc::string::String::from(n),
            None => return,
        };
        if let Some(addr) = narf_net::ifaddr::iface_primary_addr(&name) {
            narf_net::arp_cache::send_gratuitous_arp(&name, addr.addr.0);
        }
        let _ = narf_net::ipv6_stack::send_unsolicited_na(&name);
    }

    /// Config-change event handler — the config-change watcher's
    /// per-fire action: if the device raised
    /// `VIRTIO_NET_S_ANNOUNCE`, notify peers (gratuitous ARP +
    /// unsolicited NA) and ack the announce, then republish link
    /// Linux `virtnet_config_changed_work`: peers first, ack second,
    /// link state last. The ack is best-effort: a refused ack leaves
    /// S_ANNOUNCE set, so the next config-change fire retries; the
    /// link republish still runs. A spurious fire (no S_ANNOUNCE)
    /// costs only a STATUS read + the idempotent republish.
    pub fn handle_config_change(&self) {
        if self.announce_pending() {
            self.notify_peers();
            let _ = self.ack_announce();
        }
        let _ = self.refresh_link_from_status();
    }

    // ── Power management and detach ──────────────────────────────────
    //
    // igb pattern (`drivers/net/igb/src/igb.rs`, power-management
    // section) + the net spec §3 detach obligation (issue #789),
    // adapted to virtio: there is no per-queue DMA-stop register
    // (queue reset needs F_RING_RESET, which this driver does not
    // negotiate), so the two operations split by what they must
    // guarantee:
    //
    // - suspend() is LIGHT: gate the datapath, mask MSI-X at the
    //   retained table, publish link DOWN. No device reset, no queue
    //   teardown — the posted RX buffers stay valid DMA targets, so
    //   a device RX during suspend lands in a still-owned buffer
    //   and drains on resume instead of faulting. TX (the DMA this
    //   driver initiates) stops completely via the gates. Resume is
    //   therefore a re-arm (MSI-X re-enable + flag clear + link
    //   republish), not a rebuild. This is the virtio analog of
    //   igb's RCTL/TCTL suspend words: stop what the driver
    //   controls, keep what the device already owns valid.
    // - detach_device() is FULL: gate, mask MSI-X, DEVICE RESET
    //   (status 0 clears DRIVER_OK and resets every queue
    //   device-side — the real DMA stop), then take every queue
    //   `Option` to `None` so no datapath method can touch a ring
    //   again. The reset MUST precede the controller drop: after
    //   detach the `Arc` is released and the DMA buffers are freed,
    //   so any device still holding DRIVER_OK + posted buffers
    //   would DMA into freed pages. Linux `virtnet_remove`
    //   (virtio_net.c) does the same shape: unregister, then
    //   `remove_vq_common` (reset + delete queues).
    // The async pumps are NOT joined (igb parity): they hold no
    // controller `Arc` — RX forwarders exit when `with_at(idx)`
    // returns `None` after the tombstone, and the TX forwarder exits
    // when the registry unregister drops the iface's TX producer
    // (channel close). Every datapath entry point fails fast once
    // the gate is set, so a parked pump can no longer touch the
    // device in the meantime. The RX drain hook stays installed
    // (no uninstall API exists) but fails closed: it returns
    // `false` once the primary name is cleared.

    /// Whether the datapath may run: false while suspended or detached.
    /// Factored pure so the fixture pins the gate the live paths use.
    pub const fn datapath_allowed(detached: bool, suspended: bool) -> bool {
        !detached && !suspended
    }

    /// Current gate state (for the fixture + diagnostics).
    fn datapath_gated(&self) -> bool {
        !Self::datapath_allowed(
            self.detached.load(Ordering::Acquire),
            self.suspended.load(Ordering::Acquire),
        )
    }

    /// Stash the interface name at registration time (see the
    /// `ifname` field doc). Called once by `register_net_interface`.
    pub fn set_ifname(&self, name: alloc::string::String) {
        *self.ifname.lock() = Some(name);
    }

    /// Suspend the device (light contract, see the section header).
    /// Detached → `Err`; already-suspended → `Ok` no-op; else set
    /// the flag FIRST (datapath fails fast from here on), mask MSI-X
    /// at the retained table, publish link DOWN. Queues and posted
    /// RX buffers stay live and valid; `resume` re-arms them.
    pub fn suspend(&self) -> Result<(), VirtioPciError> {
        if self.detached.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if self.suspended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if let Some(table) = self.msix.lock().as_mut() {
            // SAFETY: caller owns the device's config space; datapath
            // sources are gated above, and the table entries + vectors
            // are retained (not freed), so an in-flight IRQ wake just
            // re-parks its forwarder.
            unsafe { table.disable() };
        }
        if let Some(name) = self.ifname.lock().as_deref() {
            narf_net::iface::set_link_metadata(name, false, None, None);
        }
        Ok(())
    }

    /// Resume a suspended device: re-enable MSI-X from the retained
    /// table, clear the flag LAST (datapath stays gated until the
    /// interrupts are back), republish link from live STATUS.
    /// Detached → `Err`; not-suspended → `Ok` no-op. No queue
    /// rebuild: suspend never tore the queues down.
    pub fn resume(&self) -> Result<(), VirtioPciError> {
        if self.detached.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(table) = self.msix.lock().as_mut() {
            // SAFETY: caller owns the device's config space; entries were
            // programmed at probe and retained, so re-enable restores
            // delivery on the same vectors.
            // Same conversion as the probe-time table.enable() sites
            // (pci.rs): MsixError folds into BarMapFailed.
            unsafe { table.enable() }.map_err(|_| VirtioPciError::BarMapFailed)?;
        }
        self.suspended.store(false, Ordering::Release);
        if let Some(name) = self.ifname.lock().as_deref() {
            let link = self.link_up();
            narf_net::iface::set_link_metadata(name, link, None, None);
        }
        Ok(())
    }

    /// Device half of detach (the registry half lives in
    /// `virtio_net_detach`): set the gate, mask MSI-X, DEVICE RESET,
    /// take every queue handle to `None`. Idempotent: a second call
    /// finds the gate already set and does nothing. Safe to call
    /// with the controller still in `CONTROLLERS` (the free fn
    /// tombstones first); the reset precedes any `Arc` drop, so the
    /// device can never DMA into freed buffers.
    pub fn detach_device(&self) {
        if self.detached.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(table) = self.msix.lock().as_mut() {
            // SAFETY: caller owns the device's config space; datapath
            // sources are gated above, table entries retained.
            unsafe { table.disable() };
        }
        // Device reset: writing 0 to device status clears DRIVER_OK
        // and resets every virtqueue device-side (VirtIO 1.2 §4.1).
        // This is the DMA stop — without it the device would keep
        // writing into RX buffers the controller drop is about to
        // free. Queues are taken to `None` below so no software path
        // can touch a ring after this point either.
        // SAFETY: identity-mapped MMIO; caller owns the device.
        unsafe {
            self.common.write8(CC_DEVICE_STATUS, 0);
        }
        for pair in &self.pairs {
            pair.rx_queue.lock().take();
            pair.tx_queue.lock().take();
        }
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
        // Fail fast while suspended or detached: no control commands
        // against a quiesced device (the queue is dead after detach
        // anyway — the device was reset — so a submit would only
        // burn the 1 s completion timeout).
        if self.datapath_gated() {
            return Err(VirtioPciError::NoQueues);
        }
        let ctrl = self.ctrl.as_ref().ok_or(VirtioPciError::NoQueues)?;
        let mut g = ctrl.lock();
        // Layout within `buf`:
        //   0..2         hdr  (class, cmd)         device-readable
        //   16..16+N     payload                    device-readable
        //   16+N..17+N   ack                        device-writable
        // The ack sits immediately after the payload instead of at
        // a fixed offset, so the 4 KiB scratch page holds payloads
        // up to `MAX_CTRL_PAYLOAD` — a MAC table with hundreds of
        // entries — with no per-call allocation. The device only
        // ever sees the three descriptor addresses, so the moving
        // ack offset is invisible to it.
        if payload.len() > MAX_CTRL_PAYLOAD {
            return Err(VirtioPciError::RequestTooLarge);
        }
        let ack_off = 16 + payload.len() as u64;
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
            core::ptr::write_volatile(g.buf.cpu_mut_ptr_at::<u8>(ack_off), 0xFF);
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
                addr: phys + ack_off,
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
        let ack = unsafe { core::ptr::read_volatile(g.buf.cpu_ptr_at::<u8>(ack_off)) };
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

    /// Program one VLAN ID into the device's VLAN filter table
    /// (`VIRTIO_NET_CTRL_VLAN_ADD`, VirtIO 1.2 §5.1.6.5.3).
    /// Requires `VIRTIO_NET_F_CTRL_VLAN` negotiated; returns
    /// `NoQueues` without touching the device otherwise. The VID
    /// is validated before any device access, so an out-of-range
    /// VID reports `InvalidArgument` even with no control queue.
    /// The device drops incoming frames whose tag VID is not in
    /// the table; matching frames arrive with the tag intact for
    /// the stack to parse (the device filters, it does not strip).
    pub fn vlan_add(&self, vid: u16) -> Result<(), VirtioPciError> {
        if vid > MAX_VLAN_VID {
            return Err(VirtioPciError::InvalidArgument);
        }
        if !self.has_ctrl_vlan {
            return Err(VirtioPciError::NoQueues);
        }
        let payload = vid.to_le_bytes();
        let ack = self.submit_control(VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_ADD, &payload)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Remove one VLAN ID from the device's VLAN filter table
    /// (`VIRTIO_NET_CTRL_VLAN_DEL`, VirtIO 1.2 §5.1.6.5.3).
    /// Same gating and validation as [`Self::vlan_add`].
    pub fn vlan_del(&self, vid: u16) -> Result<(), VirtioPciError> {
        if vid > MAX_VLAN_VID {
            return Err(VirtioPciError::InvalidArgument);
        }
        if !self.has_ctrl_vlan {
            return Err(VirtioPciError::NoQueues);
        }
        let payload = vid.to_le_bytes();
        let ack = self.submit_control(VIRTIO_NET_CTRL_VLAN, VIRTIO_NET_CTRL_VLAN_DEL, &payload)?;
        if ack != VIRTIO_NET_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Program the device's unicast + multicast filter tables
    /// (`VIRTIO_NET_CTRL_MAC_TABLE_SET`, VirtIO 1.2 §5.1.6.5.2;
    /// same shape as Linux `virtnet_set_rx_mode`). Requires
    /// `VIRTIO_NET_F_CTRL_RX` negotiated; returns `NoQueues`
    /// without touching the device otherwise. This is the
    /// selective alternative to `set_allmulti`: with a programmed
    /// table the device delivers only listed multicast groups
    /// instead of all of them, and unlisted multicast stays
    /// dropped (fail-closed — the table adds delivery, it never
    /// floods). The payload is built and bound-checked before
    /// any device access, so an over-large table reports
    /// `RequestTooLarge` even with no control queue.
    pub fn set_mac_table(
        &self,
        unicast: &[[u8; 6]],
        multicast: &[[u8; 6]],
    ) -> Result<(), VirtioPciError> {
        let payload = mac_table_payload(unicast, multicast);
        if payload.len() > MAX_CTRL_PAYLOAD {
            return Err(VirtioPciError::RequestTooLarge);
        }
        if !self.has_ctrl_rx {
            return Err(VirtioPciError::NoQueues);
        }
        let ack =
            self.submit_control(VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_TABLE_SET, &payload)?;
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
    /// wrote into + total bytes (including the virtio-net header:
    /// 12 bytes, or 20 with HASH_REPORT negotiated). Allocates a
    /// replacement buffer and re-posts it in the avail ring before
    /// returning so the device always has a place to land the next
    /// frame.
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
        if self.datapath_gated() {
            return false;
        }
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

    /// Take ownership of one device-filled RX frame from the given
    /// pair. When MRG_RXBUF was negotiated the frame may span several
    /// posted buffers; it is reassembled into one contiguous buffer
    /// before return so forwarders keep their one-frame-per-take
    /// contract. Otherwise the legacy single-buffer path, unchanged.
    ///
    /// Returns `None` if the pair index is out of range, the used
    /// ring is empty, a replacement allocation fails on the first
    /// segment, or a merged frame fails shape validation (dropped
    /// fail-closed after draining all its used entries so the ring
    /// stays in sync).
    pub fn rx_take_on(&self, pair_idx: usize) -> Option<(DmaBuffer, u32)> {
        if self.datapath_gated() {
            return None;
        }
        if self.mrg_rxbuf {
            self.rx_take_merged_on(pair_idx)
        } else {
            self.rx_take_single_on(pair_idx)
        }
    }

    /// Legacy single-buffer take (MRG_RXBUF not negotiated). The
    /// pre-merge body, unchanged except that the datapath gate now
    /// lives in the `rx_take_on` dispatcher above.
    fn rx_take_single_on(&self, pair_idx: usize) -> Option<(DmaBuffer, u32)> {
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
                len: (self.rx_hdr_len + MAX_RX_FRAME_PAYLOAD) as u32,
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

    /// Post `replacement` for the consumed descriptor `head` on `pair`
    /// and park it in the slot table. Returns false only when the
    /// queue vanished (detach); the caller restores its buffer and
    /// bails. A full ring (add_buffer None) drops the replacement
    /// and returns true — the ring is one descriptor down, like the
    /// single path's refill-failure arm, but the frame still stands.
    /// Lock order matches the single path: queue lock, then slot lock.
    fn rx_refill_segment(&self, pair: &QueuePair, head: u16, replacement: DmaBuffer) -> bool {
        let rep_phys = replacement.dma_addr().raw();
        let mut g = pair.rx_queue.lock();
        let Some(q) = g.as_mut() else {
            return false;
        };
        q.free_chain(head);
        // Same posted length as probe posting, the single-path
        // refill, and the RxFixture: the runtime header plus one
        // max payload. (Previously MAX_RX_FRAME, i.e. 12 + 1518,
        // which posted 8 bytes short with HASH_REPORT.)
        let descs = [VirtqDesc {
            addr: rep_phys,
            len: (self.rx_hdr_len + MAX_RX_FRAME_PAYLOAD) as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        }];
        match q.add_buffer(&descs) {
            Some(h) => {
                pair.rx_buffers.lock()[h as usize] = Some(replacement);
                true
            }
            None => {
                drop(replacement);
                true
            }
        }
    }

    /// Merged-buffer RX take (MRG_RXBUF negotiated). Linux
    /// `receive_mergeable` shape: the first used entry's header
    /// carries `num_buffers`; one used entry per buffer follows, in
    /// order. Segments are reassembled into one contiguous
    /// `[header | frame]` buffer (the forwarder contract); segment
    /// buffers return to the pair's RX pool and each consumed
    /// descriptor gets a fresh replacement posted, so the ring stays
    /// full. Any shape violation drops the frame fail-closed — after
    /// draining all its used entries, never delivering a prefix.
    ///
    /// Late-continuation caveat, shared with Linux's missing-buffer
    /// path: if a device publishes continuation used entries after
    /// the forwarder already polled a short merge, the partial frame
    /// is dropped and the late entries may later be misparsed as a
    /// new head. In practice a device completes a packet's buffers
    /// before the guest's poll observes them, and the shape check
    /// (buffer-count + frame caps) plus the stack's own L2 parse are
    /// the backstops; no retry loop here, since waiting on a
    /// genuinely broken device would wedge the forwarder.
    fn rx_take_merged_on(&self, pair_idx: usize) -> Option<(DmaBuffer, u32)> {
        let pair = self.pairs.get(pair_idx)?;
        // Segment 0: same swap discipline as the single path — poll,
        // acquire the replacement BEFORE surrendering the filled
        // buffer, so an empty pool parks the buffer (used entry
        // consumed) instead of losing the refill slot.
        let (head0, len0) = {
            let mut g = pair.rx_queue.lock();
            g.as_mut()?.poll_used()?
        };
        // `poll_used` reports the used-ring elem id (le32), but
        // descriptor indices are u16 — same conversion as the
        // single path (`let head = id as u16`).
        let head0 = head0 as u16;
        let replacement0 = self.rx_buf_acquire_on(pair_idx)?;
        let buf0 = {
            let mut bufs = pair.rx_buffers.lock();
            bufs.get_mut(head0 as usize).and_then(|s| s.take())?
        };
        // Parse num_buffers BEFORE posting the refill: a short or
        // corrupt header drops the frame, and the refill still goes
        // out below so the ring does not shrink on a device bug.
        let num_buffers = buf0
            .as_slice()
            .get(..VIRTIO_NET_HDR_LEN)
            .and_then(mrg_num_buffers)
            .unwrap_or(0) as usize;
        // Post segment 0's replacement now (mirrors the single path).
        if !self.rx_refill_segment(pair, head0, replacement0) {
            // Queue vanished mid-take: restore and bail (detach is
            // resetting the device; the ring is gone either way).
            pair.rx_buffers.lock()[head0 as usize] = Some(buf0);
            return None;
        }
        // Collect continuations, draining up to num_buffers - 1
        // further used entries. `short` marks any anomaly (poll
        // miss, empty slot, undersized buffer) that must fail the
        // frame even though draining continues for ring sync.
        // The drain is capped at RX_MRG_MAX_BUFFERS - 1: a corrupt
        // huge num_buffers must not eat a whole burst as
        // "continuations" (the shape check rejects > cap anyway, so
        // capping the drain changes no deliverable frame).
        let mut segments: Vec<(DmaBuffer, usize)> = Vec::new();
        let mut cont_lens: Vec<usize> = Vec::new();
        let mut short = false;
        for _ in 1..num_buffers.min(RX_MRG_MAX_BUFFERS) {
            let entry = {
                let mut g = pair.rx_queue.lock();
                g.as_mut().and_then(|q| q.poll_used())
            };
            let Some((head, len)) = entry else {
                short = true;
                break;
            };
            // See segment 0: used-ring ids are le32, indices are u16.
            let head = head as u16;
            let buf = {
                let mut bufs = pair.rx_buffers.lock();
                bufs.get_mut(head as usize).and_then(|s| s.take())
            };
            let Some(buf) = buf else {
                // Published entry with no parked buffer: free the
                // descriptor, mark short, keep draining for sync.
                let mut g = pair.rx_queue.lock();
                if let Some(q) = g.as_mut() {
                    q.free_chain(head);
                }
                short = true;
                continue;
            };
            if buf.len() < len as usize {
                // Used length exceeds its buffer: corrupt entry.
                // Still refill the descriptor, mark short, keep the
                // buffer for release at drop time.
                if let Some(rep) = self.rx_buf_acquire_on(pair_idx) {
                    let _ = self.rx_refill_segment(pair, head, rep);
                } else {
                    let mut g = pair.rx_queue.lock();
                    if let Some(q) = g.as_mut() {
                        q.free_chain(head);
                    }
                }
                segments.push((buf, 0));
                short = true;
                continue;
            }
            // Refill this segment (a failed acquire shrinks the ring
            // by one, like the single path's refill-failure arm —
            // the frame still delivers; the ring is not wedged).
            if let Some(rep) = self.rx_buf_acquire_on(pair_idx) {
                let _ = self.rx_refill_segment(pair, head, rep);
            } else {
                let mut g = pair.rx_queue.lock();
                if let Some(q) = g.as_mut() {
                    q.free_chain(head);
                }
            }
            cont_lens.push(len as usize);
            segments.push((buf, len as usize));
        }
        // Validate, then copy or drop. Segments are released to the
        // pool on both paths (no locks held during the copy).
        let payload_len = if short {
            None
        } else {
            mrg_frame_payload_len(
                len0 as usize,
                &cont_lens,
                num_buffers,
                self.mtu(),
                self.rx_hdr_len,
            )
        };
        let Some(payload_len) = payload_len else {
            for (buf, _) in segments {
                pair.rx_pool.release(buf);
            }
            pair.rx_pool.release(buf0);
            return None;
        };
        if num_buffers == 1 {
            // No split: the single buffer IS the frame (the common
            // case — a standard frame fits one posted descriptor).
            // The refill already went out above; return it directly
            // with no copy and no allocation.
            return Some((buf0, len0));
        }
        // Runtime header length, not the 12-byte base form: with
        // HASH_REPORT the header is 20 bytes, and the drain strips
        // `rx_hdr_len` from this total. (The copy below is a
        // contiguous copy of segment 0, so its bytes coincide either
        // way; threading the same length keeps total ==
        // rx_hdr_len + payload_len an explicit invariant rather
        // than an accident of cancelling errors.)
        let hdr = self.rx_hdr_len;
        let total = hdr + payload_len;
        let mut merged = match alloc_coherent(total, DomainId::DRIVER_0) {
            Ok(b) => b,
            Err(_) => {
                // Allocation failure must not strand the segments:
                // return them to the pool like every other drop path
                // (their replacements are already posted, so the ring
                // stays full).
                for (buf, _) in segments {
                    pair.rx_pool.release(buf);
                }
                pair.rx_pool.release(buf0);
                return None;
            }
        };
        if merged.len() < total {
            // Defensive: allocator rounded down (should not happen).
            for (buf, _) in segments {
                pair.rx_pool.release(buf);
            }
            pair.rx_pool.release(buf0);
            return None;
        }
        {
            let dst = merged.as_mut_slice();
            let src0 = buf0.as_slice();
            dst[..hdr].copy_from_slice(&src0[..hdr]);
            let mut off = hdr;
            let first_payload = len0 as usize - hdr;
            dst[off..off + first_payload].copy_from_slice(&src0[hdr..len0 as usize]);
            off += first_payload;
            for (buf, len) in &segments {
                let s = buf.as_slice();
                dst[off..off + *len].copy_from_slice(&s[..*len]);
                off += *len;
            }
            debug_assert_eq!(off, total);
        }
        for (buf, _) in segments {
            pair.rx_pool.release(buf);
        }
        pair.rx_pool.release(buf0);
        Some((merged, total as u32))
    }

    /// Notify the device that new RX buffers have been posted to the avail ring.
    /// This should be called *after* a batch of `rx_take`s to avoid kicking
    /// the device synchronously for every single frame (mimicking Linux NAPI).
    /// No-op while suspended or detached: no kicks to a masked/reset device.
    pub fn rx_notify(&self, pair_idx: usize) {
        if self.datapath_gated() {
            return;
        }
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

/// RX checksum verdict under `VIRTIO_NET_F_GUEST_CSUM` — pure, so the
/// smokes pin it without a device.
///
/// Returns true when the forwarder may deliver `payload` (the Ethernet
/// frame *after* the 12-byte virtio-net header), false when it must drop
/// it. `hdr_flags` is the header's flags byte.
///
/// Policy (drop-on-error interim, e1000 lane-2 precedent): Linux
/// delivers an unverified frame and lets the stack re-verify it in
/// software; NARF has no deliver-with-verdict channel yet (that is open
/// PR #1411's RxMeta work — deliberately NOT built here), so the driver
/// drops fail-closed instead. The end state is equivalent: no unverified
/// checksummed frame reaches the stack. When #1411 lands, this function
/// keeps its parse and the forwarder switches from drop to
/// deliver-with-verdict.
///
/// The rule, in order:
/// 1. Device-verified (`DATA_VALID` set, `NEEDS_CSUM` clear — the two
///    are mutually exclusive per Linux `virtio_net_handle_csum_offload`)
///    → deliver. A `NEEDS_CSUM` frame carries only a partial checksum
///    the stack would have to complete, so it is NOT verified.
/// 2. Otherwise the frame is unverified. Drop it ONLY when it is
///    identifiably a checksummed transport segment: unfragmented (or
///    first-fragment) IPv4/IPv6 TCP, or IPv4/IPv6 UDP with a nonzero
///    checksum field. Everything else delivers, because dropping it
///    would break traffic that has no checksum to verify:
///    - Non-IP frames (ARP, …) have no transport checksum.
///    - UDPv4 with a zero checksum field transmits no checksum
///      (RFC 768); UDPv6 checksums are mandatory, so no exception.
///    - Non-first IPv4 fragments carry no L4 header to verify, and
///      dropping them would wedge reassembly; IPv6 fragments hide
///      behind extension header 44 and take the same path.
///    - Other IPv4/IPv6 protocols (ICMP, …) are delivered unverified
///      exactly as before — their checksums are a follow-up, not
///      silently claimed here.
///    - Unparseable frames (runt, bad version/IHL, double VLAN tag)
///      deliver: the stack drops malformed frames, and this function
///      must not invent a verdict it cannot establish.
/// 3. A single 802.1Q tag is skipped (L3 starts at offset 18, inner
///    ethertype at [16..18]); double-tagged frames take the
///    unparseable path and deliver.
///
/// Payload slice for the RX pump's GUEST_CSUM check.
///
/// The virtio-net RX header is `rx_hdr_len` bytes (12, or 20 with
/// HASH_REPORT — see `rx_header_len`); the payload starts after it.
/// A hardcoded 12 here is fail-open under HASH_REPORT: the verdict
/// function would parse header-shifted bytes, misread the ethertype,
/// and deliver checksummed segments unverified. With `rx_hdr_len == 12`
/// this reproduces the pre-RSS slicing exactly.
pub(crate) fn rx_csum_payload(buf: &[u8], rx_hdr_len: usize, payload_len: u32) -> &[u8] {
    let end = (rx_hdr_len + payload_len as usize).min(buf.len());
    buf.get(rx_hdr_len..end).unwrap_or(&[])
}

pub(crate) fn rx_csum_deliver(hdr_flags: u8, payload: &[u8]) -> bool {
    const ETH_IPV4: u16 = 0x0800;
    const ETH_IPV6: u16 = 0x86dd;
    const ETH_VLAN: u16 = 0x8100;
    const IP_PROTO_TCP: u8 = 6;
    const IP_PROTO_UDP: u8 = 17;
    const IPV6_EXT_HOP: u8 = 0;
    const IPV6_EXT_ROUTE: u8 = 43;
    const IPV6_EXT_FRAG: u8 = 44;
    const IPV6_EXT_DEST: u8 = 60;
    const IPV6_EXT_AH: u8 = 51;
    const IPV6_EXT_ESP: u8 = 50;

    if hdr_flags & VIRTIO_NET_HDR_F_DATA_VALID != 0 && hdr_flags & VIRTIO_NET_HDR_F_NEEDS_CSUM == 0
    {
        return true;
    }
    // Ethernet header + ethertype, with one VLAN hop.
    let mut l3 = 14usize;
    let mut ethertype = match payload.get(12..14) {
        Some(b) => u16::from_be_bytes([b[0], b[1]]),
        None => return true,
    };
    if ethertype == ETH_VLAN {
        ethertype = match payload.get(16..18) {
            Some(b) => u16::from_be_bytes([b[0], b[1]]),
            None => return true,
        };
        l3 = 18;
    }
    match ethertype {
        ETH_IPV4 => {
            let Some(vihl) = payload.get(l3) else {
                return true;
            };
            if vihl >> 4 != 4 {
                return true;
            }
            let ihl = (vihl & 0x0f) as usize * 4;
            if ihl < 20 || payload.len() < l3 + ihl {
                return true;
            }
            // Fragmentation field (flags + offset), big-endian.
            let frag = u16::from_be_bytes([payload[l3 + 6], payload[l3 + 7]]);
            // Non-first fragment (offset != 0): no L4 header present.
            if frag & 0x1fff != 0 {
                return true;
            }
            let proto = payload[l3 + 9];
            match proto {
                IP_PROTO_TCP => false,
                IP_PROTO_UDP => {
                    // UDP header: checksum at +6, 8 bytes total.
                    let Some(csum) = payload.get(l3 + ihl + 6..l3 + ihl + 8) else {
                        return true;
                    };
                    // Zero UDPv4 checksum = no checksum transmitted.
                    u16::from_be_bytes([csum[0], csum[1]]) == 0
                }
                _ => true,
            }
        }
        ETH_IPV6 => {
            if payload.len() < l3 + 40 {
                return true;
            }
            if payload[l3] >> 4 != 6 {
                return true;
            }
            let nh = payload[l3 + 6];
            match nh {
                IP_PROTO_TCP => false,
                IP_PROTO_UDP => {
                    // UDPv6 checksum is mandatory: no zero exception,
                    // so a present UDP header drops. Only a truncated
                    // frame (unparseable) delivers.
                    payload.len() < l3 + 48
                }
                // Extension headers hide the L4 protocol (fragment
                // header 44 included): deliver, do not guess.
                IPV6_EXT_HOP | IPV6_EXT_ROUTE | IPV6_EXT_FRAG | IPV6_EXT_DEST | IPV6_EXT_AH
                | IPV6_EXT_ESP => true,
                _ => true,
            }
        }
        _ => true,
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
// spin — runs with the lock released. A stale clone is never freed
// mid-use: detach tombstones its slot (`None`) instead of removing it,
// so forwarder tasks that captured an index keep addressing their own
// (now-absent) controller rather than a shifted sibling, and a re-probe
// pushes a NEW slot rather than reusing a detached one. All `with_*`
// accessors skip tombstones.
//
// `pub(crate)` so the e2e re-entrancy regression test can assert the lock
// is released while a `with_*` closure runs (`smoke_e2e_net_with_at_*`).
pub(crate) static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Option<Arc<VirtioNetPci>>>> =
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
            g.iter().flatten().any(|c| c.cfg_phys() == dev_cfg)
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
    // Each pair's TX queue shares its RX vector (one vector per
    // pair — see `bind_tx_queue_shares`).
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { dev.enable_rx_msix_all(&cap, &device) };
    // SAFETY: probe-time caller owns the device. Best-effort —
    // failure leaves link state poll-based via `link_up()`, as
    // before. Allocated after the pair vectors so a short table
    // degrades config (not the pairs).
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { dev.enable_config_msix(&cap, &device) };
    let idx = {
        let mut g = CONTROLLERS.lock();
        let i = g.len();
        g.push(Some(Arc::new(dev)));
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

/// Stack MTU/MAC admin (`try_set_mtu` / `try_set_mac` /
/// `dev_set_promiscuity` / `dev_set_allmulti` all funnel here via
/// `configure_device`). Applies the MTU delta only: the device has
/// no MTU-set command and no other field has a driver-side apply
/// path in this lane. MAC / promisc / allmulti / addresses are
/// deliberately NOT applied here — `configure_device` still
/// commits them to the registry entry, exactly as the pre-hook
/// registry-only path did, so wiring this hook changes no
/// MAC/promisc behaviour. (MAC via the control queue exists as
/// `set_mac` but is not wired to the registry path; that is a
/// separate gap.)
impl narf_net::iface::DeviceControl for VirtioNetPci {
    fn configure(&self, desired: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        if desired.mtu != self.mtu() {
            self.set_mtu(desired.mtu).map_err(|_| 22)?;
        }
        Ok(())
    }
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
///   to drain; each pair parks on its own MSI-X vector under
///   `partition` (pairs without a vector fall back to the polled
///   cadence). All N RX forwarders push into the same shared
///   `Producer<Frame>`, behind an `Arc<IrqSafeSpinLock<...>>` —
///   `narf_ipc::Producer` is `!Sync` so the lock is required to
///   serialise the multiple producer halves. Push frequency is
///   low (one short critical section per frame, no awaits held
///   under the lock) so contention is bounded even on a 4-pair
///   line-rate workload.
/// - One config-change watcher per device (when the config vector
///   was bound): parks on the config MSI-X vector and republishes
///   link metadata on every config-change interrupt.
fn register_net_interface(idx: usize, bus_info: alloc::string::String) {
    use narf_net::{Frame, RX_RING_N, TX_RING_N};

    let (mac, mtu, link_up, rx_irq_vectors, config_irq_vector, num_pairs, offloads) =
        match with_at(idx, |c| {
            (
                c.mac(),
                c.mtu(),
                c.link_up(),
                c.rx_irq_vectors.clone(),
                c.config_irq_vector,
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
        // Every RX forwarder of the primary controller drains complete
        // bursts and calls `gro_flush` before it parks, so this interface
        // can safely opt into the stack's per-interface software GRO path.
        let _ = narf_net::iface::set_software_gro(name, true);
        // Publish the clamped probe MTU to the legacy registry so
        // the stack segments at the MTU the driver enforces (the
        // entry otherwise keeps its 1500 default even for a
        // 1400-MTU device, and the driver would reject the
        // stack's 1500-byte frames).
        let _ = narf_net::iface::set_mtu(name, mtu);
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
    // Stash the name on the controller BEFORE either registry call
    // consumes it, so `virtio_net_detach` can publish link DOWN,
    // clear the RX-mirror note, and unregister both registries even
    // if registration below fails midway.
    let _ = with_at(idx, |c| c.set_ifname(name.clone()));
    let (tx_prod, mut tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
    let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
    // Keep the legacy L3 registry -- which is what rtnetlink and
    // NetworkManager consume -- in lockstep with the ring interface.  Without
    // this, `register_static` correctly creates eth0 administratively down,
    // but also leaves its physical carrier at the default false.  QEMU has
    // already told us its virtio-net link is up, so NetworkManager sees an
    // unavailable device and never starts DHCP.
    narf_net::iface::set_link_metadata(&name, link_up, None, None);
    let iface =
        narf_net::virtio_net::VirtioNet::new(name.clone(), mac, mtu, link_up, tx_prod, rx_cons);
    let authority = narf_net::bootstrap_authority();
    // Registration failure leaks the iface (returned by-value into
    // the registry would have moved it) — we constructed it above
    // and Registry::register consumes it on success. On failure
    // the Vec slot stays free and the forwarders below would talk
    // to nothing useful, so bail.
    if narf_net::registry().register(&authority, iface).is_err() {
        return;
    }
    if idx == 0 {
        // Route stack MTU admin through the controller so a runtime
        // `try_set_mtu` retargets the driver's live MTU (and its
        // TX/RX caps) instead of only stamping the registry entry.
        // Clone the Arc out, then drop the lock before the call
        // (see the CONTROLLERS doc comment).
        let ctrl = CONTROLLERS.lock().get(idx).and_then(|o| o.clone());
        if let Some(ctrl) = ctrl {
            let ops: Arc<dyn narf_net::iface::DeviceControl> = ctrl;
            let _ = narf_net::iface::set_device_control(&name, ops);
        }
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
                // GUEST_CSUM is negotiated once at probe and never
                // re-negotiated, so snapshot it here instead of
                // consulting the controller per frame. A vanished
                // controller (None) disables enforcement — the drain
                // loop returns on the first take anyway.
                let rx_guest_csum = with_at(idx, |c| c.rx_guest_csum()).unwrap_or(false);
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
                            (c.rx_hdr_len(), c.rx_take_on(pair_idx))
                        }) {
                            Some(t) => t,
                            None => return, // controller vanished
                        };
                        let (rx_hdr_len, taken) = taken;
                        let (mut buf, total_len) = match taken {
                            Some(t) => t,
                            None => break,
                        };
                        // Saw a used-ring entry → the NIC is active; stay in
                        // fast-poll mode.
                        processed_any = true;
                        // virtio-net prepends a header to every RX frame
                        // (12 bytes, 20 with HASH_REPORT). Strip it via
                        // Frame::with_offset — the bytes stay where the
                        // device wrote them.
                        let payload_len = total_len.saturating_sub(rx_hdr_len as u32);
                        if payload_len == 0 {
                            // Empty frame (just header): recycle the buffer (on the
                            // next take's with_at) and keep draining.
                            to_recycle = Some(buf);
                            continue;
                        }
                        // GUEST_CSUM verdict (drop-on-error interim, see
                        // `rx_csum_deliver`): the header's flags byte sits
                        // at buf[0], the payload at [rx_hdr_len..end].
                        // The header length is runtime: 20 with
                        // HASH_REPORT, else 12 — a hardcoded 12 would
                        // parse header-shifted bytes under HASH_REPORT
                        // and deliver checksummed segments unverified
                        // (see `rx_csum_payload`). Only enforced when
                        // negotiated — without GUEST_CSUM the device
                        // never sets DATA_VALID, so enforcing would drop
                        // all checksummed traffic. Drops count via
                        // note_rx_drop like the ring-full path, and the
                        // buffer recycles exactly like an empty frame.
                        if rx_guest_csum {
                            let hdr_flags = buf.as_slice().first().copied().unwrap_or(0);
                            let payload = rx_csum_payload(buf.as_slice(), rx_hdr_len, payload_len);
                            if !rx_csum_deliver(hdr_flags, payload) {
                                narf_net::iface::note_rx_drop(primary_iface_name(), 1);
                                to_recycle = Some(buf);
                                continue;
                            }
                        }
                        // Tap: synchronously dispatch the payload through the iface
                        // RX handler. Only installed for the primary controller
                        // (idx 0) — the TCP stack hooked itself there at boot via
                        // `install_rx_drain` / `on_rx_frame_from`. virtio-net
                        // prepends a header (12 bytes, 20 with HASH_REPORT);
                        // dispatch the payload slice
                        // directly (no `Frame`) so the consumed DmaBuffer can be
                        // RECYCLED into the RX frame pool instead of freed — keeping
                        // the buddy allocator + per-frame 4 KiB zero-fill off the
                        // hot path.
                        if idx == 0 {
                            let end = (rx_hdr_len + payload_len as usize).min(buf.len());
                            // `&mut`: an attached XDP program may rewrite header
                            // bytes in place. `buf` is a DmaBuffer this pump owns
                            // for the duration (recycled into the RX pool on the
                            // next take); the device is not reading it back, so an
                            // in-place write before dispatch is sound.
                            narf_net::iface::on_rx_frame_from(
                                primary_iface_name(),
                                &mut buf.as_mut_slice()[rx_hdr_len..end],
                            );
                            // The tap consumed the frame synchronously + completely.
                            // (The legacy rx_prod/rx_cons channel is NOT drained in
                            // production, so pushing there would wedge after 64
                            // frames.) Recycle the buffer on the next take's with_at.
                            to_recycle = Some(buf);
                            continue;
                        }
                        let frame = Frame::with_offset_on_queue(
                            buf,
                            rx_hdr_len as u32,
                            payload_len,
                            pair_idx as u16,
                        );
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
                    // delivered. Every pair of the primary controller feeds GRO
                    // (each forwarder owns the synchronous tap into the stack),
                    // so every forwarder flushes its own CPU's table. `idx` here
                    // is the controller index, not the pair index (#1533: the
                    // audit's gap-9 "pair-0-only GRO" reading misread this gate).
                    // This runs on the forwarder's own CPU — the same CPU the
                    // offers ran on — so it drains that CPU's per-CPU coalescer.
                    // No-op when that CPU holds no GRO flows.
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

    // Config-change watcher: one task per device, parked on the
    // config MSI-X vector. A fire means the device changed its
    // configuration (VirtIO 1.2 §4.1.5.2 routes config-change
    // interrupts to `msix_config` exclusively, so the vector itself
    // is the discriminator — no ISR read needed, matching Linux's
    // `vp_config_changed`). Each fire runs `handle_config_change`:
    // announce (gratuitous ARP + unsolicited NA + ANNOUNCE_ACK) when the device
    // raised S_ANNOUNCE, then a link-metadata republish from live
    // STATUS; both are idempotent, so a spurious fire is harmless.
    // No vector (table exhausted at probe) → no watcher; link state
    // stays poll-based via `link_up()`, as before. Exits when the
    // controller vanishes (detach tombstone).
    if let Some(cfg_v) = config_irq_vector {
        narf_scheduler::spawn_stackful(async move {
            loop {
                let _ = narf_interrupts::wait_for_irq(cfg_v).await;
                if with_at(idx, |c| c.handle_config_change()).is_none() {
                    return;
                }
            }
        });
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
    // VLAN insertion happens here, at copy time: the tag goes into
    // the frame bytes before any header computation, so the
    // VLAN-aware checksum/TSO layout sees the tagged frame and
    // tagged offloads compose. Pair selection runs on the untagged
    // frame so the 4-tuple hash sees the untagged layout. A tagged
    // frame at exactly MAX_TX_TSO_FRAME cannot grow by the tag
    // inside the bounded TX pool buffer — fail closed rather than
    // truncate.
    let (out_len, tag) = match meta.vlan_tag {
        Some(tag) => {
            if frame.len() < ETH_HDR_LEN || frame.len() + VLAN_TAG_LEN > MAX_TX_TSO_FRAME {
                return Err(());
            }
            (frame.len() + VLAN_TAG_LEN, Some(tag))
        }
        None => (frame.len(), None),
    };
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
        if slice.len() < VIRTIO_NET_HDR_LEN + out_len {
            return Err(());
        }
        // Frame body follows the virtio header, which tx_dma writes here.
        let dst = &mut slice[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + out_len];
        match tag {
            Some(tag) => {
                copy_frame_with_vlan(dst, frame, tag).ok_or(())?;
            }
            None => dst.copy_from_slice(frame),
        }
    }
    // The tag is bytes in the frame now; clear it so the header
    // computation does not see a tag it would have to insert.
    let meta = narf_net::TxMeta {
        vlan_tag: None,
        ..meta
    };
    // Move `buf` into its selected queue — it owns the buffer until the device
    // finishes DMAing the frame out of it.
    let res = with_controller(|c| c.tx_dma_on_with_meta(pair_idx, buf, out_len as u32, meta));
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
    if meta.vlan_tag.is_none() {
        let (buf, _off, _len, queue) = frame.into_parts_with_offset_and_queue();
        return match with_controller(|c| {
            c.tx_dma_on_with_meta(queue as usize, buf, len as u32, meta)
        }) {
            Some(Ok(())) => Ok(()),
            _ => Err(()),
        };
    }
    // Tagged zero-copy frame: the stack-owned buffer has no room
    // to grow by the tag bytes in place, and mutating it would
    // break the zero-copy contract — so copy into a driver pool
    // buffer with the tag inserted (same shape as `vnet0_send_fn`)
    // and return the original buffer to its own queue-local pool.
    // The zc pools ARE the per-pair tx_pools (see registration),
    // so this release is the same recycler the TX reaper uses and
    // no pool accounting changes. There is no copy fallback in
    // the stack's zc dispatch — an Err here would drop the frame —
    // so the tagged path must succeed through this copy, not
    // refuse.
    let tag = meta.vlan_tag.expect("matched Some VLAN tag");
    if len < ETH_HDR_LEN || len + VLAN_TAG_LEN > MAX_TX_TSO_FRAME {
        return Err(());
    }
    let new_len = len + VLAN_TAG_LEN;
    let (orig, off, _flen, queue) = frame.into_parts_with_offset_and_queue();
    let queue = queue as usize;
    let copy = with_controller(|c| {
        let mut copy = c.tx_buf_acquire_on(queue)?;
        let done = (|| {
            let src = orig.as_slice().get((off as usize)..(off as usize + len))?;
            let slice = copy.as_mut_slice();
            if slice.len() < VIRTIO_NET_HDR_LEN + new_len {
                return None;
            }
            copy_frame_with_vlan(
                &mut slice[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + new_len],
                src,
                tag,
            )
        })();
        match done {
            Some(_) => Some(copy),
            // Copy failed after acquisition: return the copy to its
            // pool instead of leaking a recycler slot.
            None => {
                c.tx_buf_release_on(queue, copy);
                None
            }
        }
    })
    .flatten();
    let Some(copy) = copy else {
        with_controller(|c| c.tx_buf_release_on(queue, orig));
        return Err(());
    };
    let meta = narf_net::TxMeta {
        vlan_tag: None,
        ..meta
    };
    let res = with_controller(|c| c.tx_dma_on_with_meta(queue, copy, new_len as u32, meta));
    // The original buffer is consumed here in every outcome: it is
    // never submitted, so it must go back to its pool now rather
    // than leak when the submit fails.
    with_controller(|c| c.tx_buf_release_on(queue, orig));
    match res {
        Some(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

/// Pair chosen first by the next synchronous RX drain. The TCP connect and ARP
/// waits call the drain hook in a tight loop, so advancing this cursor makes
/// those waits fair across the NIC's RSS / flow-steered receive queues.
static DRAIN_PAIR_RR: AtomicU64 = AtomicU64::new(0);

impl VirtioNetPci {
    /// Drain one frame from `pair_idx` of this controller: take, apply
    /// the GUEST_CSUM verdict, deliver or drop-count, recycle, notify.
    /// Returns true iff a frame was consumed.
    ///
    /// This is the body of `vnet0_drain_fn` for a single pair, split out
    /// so the drain path is directly testable without a probed device
    /// (see `tx_tests::smoke_virtio_net_drain_enforces_guest_csum`).
    /// The verdict mirrors the async RX pump exactly: when GUEST_CSUM
    /// was negotiated, a checksummed segment the device did not verify
    /// is dropped fail-closed (e1000 drop-on-error precedent) and
    /// counted via `note_rx_drop`; without negotiation everything
    /// delivers as before. The payload slice uses the runtime
    /// `rx_hdr_len` (20 with HASH_REPORT, else 12) — a hardcoded 12
    /// would parse header-shifted bytes under HASH_REPORT and deliver
    /// checksummed segments unverified (see `rx_csum_payload`).
    /// A dropped frame still counts as consumed (returns true) so the
    /// connect_wait loop keeps draining instead of stalling behind a
    /// dropped head-of-queue frame, matching the pump's processed_any
    /// accounting. Recycling targets this controller (the frame's
    /// source) rather than re-resolving the first live controller.
    fn drain_one_on(&self, pair_idx: usize) -> bool {
        let (mut buf, total_len) = match self.rx_take_on(pair_idx) {
            Some(t) => t,
            None => return false,
        };
        let rx_hdr_len = self.rx_hdr_len();
        let payload_len = total_len.saturating_sub(rx_hdr_len as u32);
        let end = (rx_hdr_len + payload_len as usize).min(buf.len());
        if payload_len != 0 {
            let mut deliver = true;
            if self.rx_guest_csum() {
                let hdr_flags = buf.as_slice().first().copied().unwrap_or(0);
                let payload = rx_csum_payload(buf.as_slice(), rx_hdr_len, payload_len);
                if !rx_csum_deliver(hdr_flags, payload) {
                    narf_net::iface::note_rx_drop(primary_iface_name(), 1);
                    deliver = false;
                }
            }
            if deliver {
                // `&mut`: as in the async pump, the program may rewrite header bytes in
                // place. `buf` is owned here until it is recycled below.
                narf_net::iface::on_rx_frame_from(
                    primary_iface_name(),
                    &mut buf.as_mut_slice()[rx_hdr_len..end],
                );
            }
        }
        // Recycle the consumed buffer into the RX frame pool instead of freeing.
        self.rx_buf_release_on(pair_idx, buf);
        self.rx_notify(pair_idx);
        true
    }
}

/// `iface::DrainFn` — synchronous one-frame drain used by the TCP stack's
/// in-kernel `connect_wait` busy-wait (kernel callers that cannot park). A caller can
/// be occupying its executor while it waits, so it cannot rely on the spawned
/// RX forwarders making progress. Drain one frame from every active queue pair
/// in rotating order: with F_MQ, a flow's SYN-ACK returns on the pair selected
/// for its outbound SYN, not necessarily pair 0.
///
/// The buffer stays zero-copy through `iface::on_rx_frame`; we return it to
/// exactly the pair that supplied it and notify that pair after replenishing.
/// Each drained frame passes the same GUEST_CSUM verdict as the async RX
/// pump (see `VirtioNetPci::drain_one_on`); a dropped frame still counts
/// as processed.
/// Returns `true` iff a frame was actually processed.
fn vnet0_drain_fn() -> bool {
    // Fail closed after a primary detach: the hook stays installed
    // (no uninstall API exists) and `with_controller` would otherwise
    // resolve to the NEXT live controller after the primary slot is
    // tombstoned, draining its frames into a cleared primary name.
    if primary_iface_name().is_empty() {
        return false;
    }
    // Round-robin cursor advances once per call; pairs are tried in
    // order from it and the first pair with a frame wins — the same
    // shape as the previous inline take loop, now delegated to
    // `drain_one_on` (which also carries the GUEST_CSUM verdict).
    with_controller(|c| {
        let pairs = c.num_pairs();
        if pairs == 0 {
            return false;
        }
        let start = (DRAIN_PAIR_RR.fetch_add(1, Ordering::Relaxed) as usize) % pairs;
        (0..pairs).any(|offset| {
            let pair_idx = (start + offset) % pairs;
            c.drain_one_on(pair_idx)
        })
    })
    .unwrap_or(false)
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
    CONTROLLERS.lock().iter().any(|c| c.is_some())
}

/// Number of bound virtio-net devices.
pub fn count() -> usize {
    CONTROLLERS.lock().iter().flatten().count()
}

/// Active virtio-net queue-pair count on the primary device (1 unless
/// VIRTIO_NET_F_MQ was negotiated and `VQ_PAIRS_SET` accepted N>1).
/// The interface name `iface::register` gave the primary controller
/// (`eth%d`, Linux `dev_alloc_name`). Set once at probe; cleared by
/// `virtio_net_detach` for the primary slot (the drain hook reads it
/// to fail closed after detach).
static PRIMARY_IFNAME: narf_lib::sync::IrqSafeSpinLock<Option<&'static str>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The primary controller's interface name; empty until it has registered.
pub fn primary_iface_name() -> &'static str {
    PRIMARY_IFNAME.lock().unwrap_or("")
}

pub fn primary_num_pairs() -> usize {
    CONTROLLERS
        .lock()
        .iter()
        .flatten()
        .next()
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
    let ctrl = CONTROLLERS.lock().iter().flatten().next().cloned();
    ctrl.as_deref().map(f)
}

/// Run `f` against every bound controller in probe order.
pub fn with_each(mut f: impl FnMut(&VirtioNetPci)) {
    // Snapshot the Arc handles, drop the lock, then run `f` (see the
    // CONTROLLERS doc comment).
    let ctrls: alloc::vec::Vec<Arc<VirtioNetPci>> =
        CONTROLLERS.lock().iter().flatten().cloned().collect();
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
    let ctrl = CONTROLLERS.lock().get(idx).and_then(|o| o.clone());
    ctrl.as_deref().map(f)
}

/// Detach the bound virtio-net device at `idx`, if any: tombstone
/// the slot first (forwarders exit on their next tick — RX via
/// `with_at` → `None`, TX via the registry unregister dropping the
/// iface's TX producer — and no later probe reuses the index), then
/// the device half (`detach_device`: gate, MSI-X mask, device
/// reset, queue teardown), then the registry half the net spec §3
/// obliges — publish link DOWN, clear the RX-mirror attach note
/// for the interface name (`eth%d` names are lowest-free-allocated
/// and reused), and unregister from BOTH registries (legacy
/// `iface` + ring `registry`). Idempotent: a second call finds the
/// tombstone and does nothing. The async pumps are not joined
/// (they hold no controller `Arc`); every datapath entry point
/// fails fast once the gate is set.
/// The bound-driver diagnostic record (`record_bound` at probe) has
/// no removal API, so the entry is left in place — a remainder, not
/// a leak of device state.
pub fn virtio_net_detach(idx: usize) {
    let controller = CONTROLLERS.lock().get_mut(idx).and_then(Option::take);
    let Some(device) = controller else {
        return;
    };
    device.detach_device();
    let name: Option<alloc::string::String> = device.ifname.lock().as_ref().map(|s| s.clone());
    let Some(name) = name else {
        // Controller never reached registration (probe pushed it
        // but `register_net_interface` never stashed a name): the
        // device half above is still the correct teardown, there is
        // just no registry half to run.
        return;
    };
    narf_net::iface::set_link_metadata(&name, false, None, None);
    // virtio-net's `VirtioNet::rx_ring()` never calls
    // `note_rx_mirror_attached` (unlike atheros/igc), so no note
    // exists today — but the spec §3 obligation covers
    // dual-published families, and a future pump change could add
    // one, so clear unconditionally rather than reasoning about
    // the current pump.
    narf_drivers_net_core::publish::clear_rx_mirror_attached(&name);
    let _ = narf_net::iface::unregister(&name);
    let _ = narf_net::registry().unregister(&name);
    if idx == 0 || name == primary_iface_name() {
        *PRIMARY_IFNAME.lock() = None;
    }
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
                    // Retained cap (not prefilled — TX tests never touch
                    // the RX pool) so the recycle-guard test can observe
                    // retention; the old cap 0 made every release a drop.
                    rx_pool: DmaPool::new(4096, DomainId::DRIVER_0, RX_POOL_CAP),
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
                config_irq_vector: None,
                msix: IrqSafeSpinLock::new(None),
                ready: true,
                detached: AtomicBool::new(false),
                suspended: AtomicBool::new(false),
                ifname: IrqSafeSpinLock::new(None),
                mac: IrqSafeSpinLock::new([0; 6]),
                has_ctrl_mac_addr: false,
                has_ctrl_rx: false,
                has_ctrl_vlan: false,
                mtu: AtomicU32::new(1500),
                device_mtu: 1500,
                has_status: false,
                has_guest_announce: false,
                has_rss: false,
                has_hash_report: false,
                rss_configured: false,
                rx_hdr_len: VIRTIO_NET_HDR_LEN,
                tx_checksum: true,
                tx_tso4: true,
                tx_tso6: true,
                tx_uso: true,
                rx_guest_csum: false,
                mrg_rxbuf: false,
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

        fn submit_v6_tcp(&self, pair: usize, more: bool) -> Result<(), &'static str> {
            let mut buf = self.dev.tx_buf_acquire_on(pair).ok_or("TX pool starved")?;
            let frame = &mut buf.as_mut_slice()[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + FRAME_LEN];
            frame.fill(0);
            frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            frame[14] = 0x60;
            frame[16..18].copy_from_slice(&((FRAME_LEN - 54) as u16).to_be_bytes());
            frame[20] = 6;
            frame[22..38]
                .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            frame[38..54]
                .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            frame[66] = 5 << 4;
            frame[67] = 0x18;
            self.dev
                .tx_dma_on_with_meta(
                    pair,
                    buf,
                    FRAME_LEN as u32,
                    narf_net::TxMeta::with_tso(1024).with_more(more),
                )
                .map_err(|_| "TSO6 submit rejected")
        }

        fn submit_uso(&self, pair: usize, more: bool) -> Result<(), &'static str> {
            let mut buf = self.dev.tx_buf_acquire_on(pair).ok_or("TX pool starved")?;
            let frame = &mut buf.as_mut_slice()[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + FRAME_LEN];
            frame.fill(0);
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&((FRAME_LEN - 14) as u16).to_be_bytes());
            frame[23] = 17;
            frame[38..40].copy_from_slice(&((FRAME_LEN - 34) as u16).to_be_bytes());
            let meta = narf_net::TxMeta {
                csum_l4: Some(narf_net::L4CsumKind::Udp),
                tso_mss: Some(1024),
                ..Default::default()
            };
            self.dev
                .tx_dma_on_with_meta(pair, buf, FRAME_LEN as u32, meta.with_more(more))
                .map_err(|_| "USO submit rejected")
        }

        fn complete(&self, pair: usize) -> Result<(), &'static str> {
            self.complete_expected(pair, [1, 1])
        }

        fn complete_expected(&self, pair: usize, expected: [u8; 2]) -> Result<(), &'static str> {
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
                        || buf.as_slice()[..2] != expected
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

    /// §0 seam regression for the new GSO paths: a multi-frame IPv6
    /// TSO burst and a multi-frame UDP USO burst, each driven to pool
    /// exhaustion with delayed completions, must recover exactly like
    /// the TSO4 burst — no buffer reuse before completion, no
    /// descriptor leak, no buffer crossing queue pairs, and the
    /// emitted header's GSO type must be TCPV6 (4) / UDP_L4 (5).
    /// The `more`-hint flush behavior is path-independent (it lives
    /// in `tx_dma_on_with_meta`, shared by all GSO kinds), so the
    /// TSO4 more-flush test below continues to cover it.
    fn smoke_virtio_net_tso6_uso_burst_recovers_exhausted_pool() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            for pair in 0..2 {
                // IPv6 TSO burst to exhaustion, then delayed completion.
                for i in 0..TX_POOL_CAP {
                    fixture.submit_v6_tcp(pair, i + 1 < TX_POOL_CAP)?;
                }
                if fixture.dev.tx_buf_acquire_on(pair).is_some() {
                    return Err("uncompleted DMA buffer was reused (TSO6)");
                }
                fixture.complete_expected(pair, [1, 4])?;
                let buf = fixture
                    .dev
                    .tx_buf_acquire_on(pair)
                    .ok_or("completed pool stayed empty (TSO6)")?;
                let p = &fixture.dev.pairs[pair];
                if p.tx_pool.available() != TX_POOL_CAP - 1
                    || p.tx_buffers.lock().iter().any(Option::is_some)
                    || p.tx_queue.lock().as_ref().unwrap().diagnostic_snapshot().3 != QSIZE
                    || fixture.dev.pairs[1 - pair].tx_pool.available() != TX_POOL_CAP
                {
                    return Err("TSO6 burst leaked buffers/descriptors or crossed queue pools");
                }
                fixture.dev.tx_buf_release_on(pair, buf);
                // UDP USO burst to exhaustion, then delayed completion.
                for i in 0..TX_POOL_CAP {
                    fixture.submit_uso(pair, i + 1 < TX_POOL_CAP)?;
                }
                if fixture.dev.tx_buf_acquire_on(pair).is_some() {
                    return Err("uncompleted DMA buffer was reused (USO)");
                }
                fixture.complete_expected(pair, [1, 5])?;
                let buf = fixture
                    .dev
                    .tx_buf_acquire_on(pair)
                    .ok_or("completed pool stayed empty (USO)")?;
                let p = &fixture.dev.pairs[pair];
                if p.tx_pool.available() != TX_POOL_CAP - 1
                    || p.tx_buffers.lock().iter().any(Option::is_some)
                    || p.tx_queue.lock().as_ref().unwrap().diagnostic_snapshot().3 != QSIZE
                    || fixture.dev.pairs[1 - pair].tx_pool.available() != TX_POOL_CAP
                {
                    return Err("USO burst leaked buffers/descriptors or crossed queue pools");
                }
                fixture.dev.tx_buf_release_on(pair, buf);
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
        smoke_virtio_net_tso6_uso_burst_recovers_exhausted_pool
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

    fn smoke_virtio_net_datapath_gate_matrix() -> TestResult {
        // Pure predicate the live TX/RX/control paths gate on.
        let ok = VirtioNetPci::datapath_allowed(false, false)
            && !VirtioNetPci::datapath_allowed(true, false)
            && !VirtioNetPci::datapath_allowed(false, true)
            && !VirtioNetPci::datapath_allowed(true, true);
        if ok {
            TestResult::Pass
        } else {
            TestResult::Fail("datapath_allowed matrix wrong")
        }
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_datapath_gate_matrix
    );

    fn smoke_virtio_net_suspend_resume_gates() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            let dev = &fixture.dev;
            // Fixture has no F_STATUS, so live link reads true.
            if !dev.link_up() {
                return Err("fixture link_up not true pre-suspend");
            }
            // Acquire BEFORE suspending and hold the buffer, so the
            // post-suspend acquire-None is the gate, not starvation,
            // and the refused TX below has a buffer to return.
            let buf = dev.tx_buf_acquire_on(0).ok_or("pool empty pre-suspend")?;
            if dev.pairs[0].tx_pool.available() != TX_POOL_CAP - 1 {
                return Err("pool count wrong after pre-suspend acquire");
            }
            dev.suspend().map_err(|_| "suspend failed")?;
            // Second suspend is a no-op, not an error.
            dev.suspend().map_err(|_| "second suspend failed")?;
            if dev.link_up() {
                return Err("link_up still true while suspended");
            }
            if dev.tx_buf_acquire_on(0).is_some() {
                return Err("TX acquire succeeded while suspended");
            }
            // Gate fires before any header write or ring touch, and
            // the refused frame's buffer goes back to its pool
            // instead of draining the fixed recycler.
            if dev.tx_dma_on(0, buf, 1).is_ok() {
                return Err("TX accepted while suspended");
            }
            if dev.pairs[0].tx_pool.available() != TX_POOL_CAP {
                return Err("refused TX did not return its buffer to the pool");
            }
            dev.resume().map_err(|_| "resume failed")?;
            // Second resume is a no-op, not an error.
            dev.resume().map_err(|_| "resume-after-resume failed")?;
            if !dev.link_up() {
                return Err("link_up not true post-resume");
            }
            if dev.tx_buf_acquire_on(0).is_none() {
                return Err("TX acquire failed post-resume");
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
        smoke_virtio_net_suspend_resume_gates
    );

    fn smoke_virtio_net_detach_device_teardown() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            let dev = &fixture.dev;
            // Seed a nonzero device status so the reset write below
            // is pinned, not vacuous (coherent pages recycle).
            // SAFETY: RAM-backed fixture region, owned by this fixture.
            unsafe {
                dev.common.write8(CC_DEVICE_STATUS, 0xFF);
            }
            dev.detach_device();
            // SAFETY: same RAM-backed region.
            if unsafe { dev.common.read8(CC_DEVICE_STATUS) } != 0 {
                return Err("device status not reset by detach");
            }
            if dev.pairs[0].tx_queue.lock().is_some() {
                return Err("TX queue handle not taken by detach");
            }
            if dev.link_up() {
                return Err("link_up still true after detach");
            }
            if dev.tx_buf_acquire_on(0).is_some() {
                return Err("TX acquire succeeded after detach");
            }
            if dev.suspend().is_ok() {
                return Err("suspend accepted after detach");
            }
            if dev.resume().is_ok() {
                return Err("resume accepted after detach");
            }
            // Second detach is a no-op, not a panic or double-reset.
            dev.detach_device();
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_detach_device_teardown
    );

    fn smoke_virtio_net_vlan_insert_bytes() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let frame: [u8; 20] = [
                0x02, 0, 0, 0, 0, 0x01, // dst
                0x02, 0, 0, 0, 0, 0x02, // src
                0x08, 0x00, // EtherType IPv4
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // payload
            ];
            let mut dst = [0u8; 64];
            let len = copy_frame_with_vlan(&mut dst, &frame, 0x1234).ok_or("insert rejected")?;
            if len != 24 {
                return Err("inserted length wrong");
            }
            let expected: [u8; 24] = [
                0x02, 0, 0, 0, 0, 0x01, // dst
                0x02, 0, 0, 0, 0, 0x02, // src
                0x81, 0x00, // TPID
                0x12, 0x34, // TCI
                0x08, 0x00, // EtherType IPv4
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // payload
            ];
            if dst[..24] != expected {
                return Err("inserted bytes wrong");
            }
            // Too short to carry a tag (needs dst + src + EtherType).
            if copy_frame_with_vlan(&mut dst, &frame[..13], 0x1234).is_some() {
                return Err("short frame accepted");
            }
            // Destination too small for the tagged frame.
            if copy_frame_with_vlan(&mut dst[..23], &frame, 0x1234).is_some() {
                return Err("undersized destination accepted");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    fn smoke_virtio_net_mrg_header_decode() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let mut hdr = [0u8; 12];
            hdr[10] = 6;
            hdr[11] = 0;
            if mrg_num_buffers(&hdr) != Some(6) {
                return Err("num_buffers LE decode wrong");
            }
            hdr[10] = 0x34;
            hdr[11] = 0x12;
            if mrg_num_buffers(&hdr) != Some(0x1234) {
                return Err("num_buffers high byte ignored");
            }
            if mrg_num_buffers(&hdr[..11]).is_some() {
                return Err("short header decoded");
            }
            if mrg_num_buffers(&[]).is_some() {
                return Err("empty header decoded");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_vlan_insert_bytes);

    fn smoke_virtio_net_mac_table_payload() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let uc: [[u8; 6]; 1] = [[1, 2, 3, 4, 5, 6]];
            let mc: [[u8; 6]; 2] = [
                [0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
                [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb],
            ];
            let payload = mac_table_payload(&uc, &mc);
            let expected: [u8; 4 + 6 + 4 + 12] = [
                1, 0, 0, 0, // unicast count LE
                1, 2, 3, 4, 5, 6, // unicast MAC
                2, 0, 0, 0, // multicast count LE
                0xff, 0xff, 0xff, 0xff, 0xff, 0x01, // multicast MAC 1
                0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, // multicast MAC 2
            ];
            if payload.as_slice() != expected.as_slice() {
                return Err("MAC table payload layout wrong");
            }
            let empty = mac_table_payload(&[], &[]);
            if empty.as_slice() != [0u8; 8].as_slice() {
                return Err("empty MAC table payload wrong");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_mrg_header_decode);

    fn smoke_virtio_net_mrg_frame_shape() -> TestResult {
        let run = || -> Result<(), &'static str> {
            // Cap-sized jumbo frame: 1518 first payload + 5 x 1530
            // continuations + 1380 = 9018, exactly the 9000-MTU cap.
            let cont = [1530usize, 1530, 1530, 1530, 1380];
            if mrg_frame_payload_len(1530, &cont, 6, 9000, 12) != Some(9018) {
                return Err("cap-sized jumbo rejected");
            }
            // One byte over the cap.
            let cont = [1530usize, 1530, 1530, 1530, 1381];
            if mrg_frame_payload_len(1530, &cont, 6, 9000, 12).is_some() {
                return Err("over-cap jumbo accepted");
            }
            // Standard frame on a standard MTU, unsplit.
            if mrg_frame_payload_len(1530, &[], 1, 1500, 12) != Some(1518) {
                return Err("standard frame rejected");
            }
            // Same frame over a standard MTU with one continuation.
            if mrg_frame_payload_len(1530, &[100], 2, 1500, 12).is_some() {
                return Err("over-MTU split accepted");
            }
            // Degenerate counts.
            if mrg_frame_payload_len(1530, &[], 0, 9000, 12).is_some() {
                return Err("num_buffers 0 accepted");
            }
            if mrg_frame_payload_len(1530, &[1530; 16], 17, 9000, 12).is_some() {
                return Err("num_buffers over cap accepted");
            }
            // Count mismatch (device published fewer than promised).
            if mrg_frame_payload_len(1530, &[1530], 3, 9000, 12).is_some() {
                return Err("short collection accepted");
            }
            // Short first segment (no room for the header).
            if mrg_frame_payload_len(11, &[], 1, 9000, 12).is_some() {
                return Err("sub-header first segment accepted");
            }
            // Continuation longer than the posted descriptor.
            if mrg_frame_payload_len(1530, &[1531], 2, 9000, 12).is_some() {
                return Err("over-descriptor continuation accepted");
            }
            // HASH_REPORT form: 20-byte header. Every case below
            // fails under the old hardcoded-12 shape check, so each
            // pins the threading rather than the old behavior.
            // Full first segment on a probe-posted buffer
            // (20 + 1518 = 1538): old code rejected it (1538 > 1530).
            if mrg_frame_payload_len(1538, &[], 1, 1500, 20) != Some(1518) {
                return Err("hash full first segment rejected");
            }
            // Split frame with a 20-byte header.
            if mrg_frame_payload_len(1538, &[100], 2, 9000, 20) != Some(1618) {
                return Err("hash split frame rejected");
            }
            // First segment shorter than the 20-byte header: old
            // code accepted lengths 12..19 with a bogus payload.
            if mrg_frame_payload_len(15, &[], 1, 9000, 20).is_some() {
                return Err("hash sub-header first segment accepted");
            }
            if mrg_frame_payload_len(19, &[], 1, 9000, 20).is_some() {
                return Err("hash 19-byte first segment accepted");
            }
            // Header-only first segment is exactly at the floor.
            if mrg_frame_payload_len(20, &[], 1, 9000, 20) != Some(0) {
                return Err("hash header-only first segment rejected");
            }
            // Cap-sized jumbo with a 20-byte header: 1518 + 4 x 1538
            // + 1348 = 9018, exactly the 9000-MTU cap. Old code
            // overcounted the payload by 8 (9026) and rejected it.
            let cont = [1538usize, 1538, 1538, 1538, 1348];
            if mrg_frame_payload_len(1538, &cont, 6, 9000, 20) != Some(9018) {
                return Err("hash cap-sized jumbo rejected");
            }
            // One byte over the cap, 20-byte header form.
            let cont = [1538usize, 1538, 1538, 1538, 1349];
            if mrg_frame_payload_len(1538, &cont, 6, 9000, 20).is_some() {
                return Err("hash over-cap jumbo accepted");
            }
            // Continuation longer than the 20-byte-header posted
            // descriptor (20 + 1518 = 1538).
            if mrg_frame_payload_len(1538, &[1539], 2, 9000, 20).is_some() {
                return Err("hash over-descriptor continuation accepted");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_mac_table_payload);

    /// Queue-level pin for the MRG+HASH_REPORT threading: drives
    /// `rx_take` with a 20-byte RX header split across two posted
    /// buffers and checks the reassembled bytes exactly. The first
    /// segment is full (20 + 1518 = 1538 bytes, as on a
    /// probe-posted buffer), so the old hardcoded-12 shape check
    /// rejects this frame outright (1538 > 1530) while the threaded
    /// check delivers it — this smoke fails under the old code and
    /// passes under the new code, end to end through the take path:
    /// num_buffers decode, the 20-byte header intact at the head of
    /// the merged buffer, first payload then continuation in order,
    /// and total == rx_hdr_len + payload_len for the drain's strip
    /// math. Reuses the single-frame RxFixture and rewrites its
    /// posted buffer + used ring into a two-segment completion,
    /// using the same fake-device primitives `RxFixture::new` uses.
    fn smoke_virtio_net_mrg_hash_reassembly() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let mut fixture = RxFixture::new(20, false, 0)?;
            fixture.dev.mrg_rxbuf = true;
            // Jumbo-cap MTU so the 1518 + 50 payload fits the shape
            // check; the fixture's 1500 would reject it under both
            // old and new code.
            fixture.dev.mtu.store(9000, Ordering::Release);
            // Segment 0 is the fixture's posted buffer: find its
            // slot, then rewrite it as a 20-byte header (num_buffers
            // 2, distinctive hash fields) + 1518 bytes of payload.
            let head_a = {
                let bufs = fixture.dev.pairs[0].rx_buffers.lock();
                bufs.iter()
                    .position(|b| b.is_some())
                    .ok_or("no posted buffer")? as u16
            };
            {
                let mut bufs = fixture.dev.pairs[0].rx_buffers.lock();
                let buf = bufs[head_a as usize].as_mut().ok_or("posted buffer gone")?;
                let slice = buf.as_mut_slice();
                slice[..1538].fill(0);
                slice[10] = 2;
                slice[11] = 0;
                slice[12..16].copy_from_slice(&0x11223344u32.to_le_bytes());
                slice[16..18].copy_from_slice(&0x0007u16.to_le_bytes());
                for i in 0..1518 {
                    slice[20 + i] = (i as u8).wrapping_add(0x40);
                }
            }
            // Segment 1: a continuation buffer with 50 bytes of
            // payload, posted to the same queue and parked in the
            // slot table like any refill.
            let mut buf_b = fixture.dev.pairs[0]
                .rx_pool
                .try_acquire()
                .ok_or("RX pool starved")?;
            {
                let slice = buf_b.as_mut_slice();
                for (i, slot) in slice.iter_mut().enumerate().take(50) {
                    *slot = (i as u8).wrapping_add(0x80);
                }
            }
            let head_b = {
                let mut g = fixture.dev.pairs[0].rx_queue.lock();
                let q = g.as_mut().ok_or("no rx queue")?;
                q.add_buffer(&[VirtqDesc {
                    addr: buf_b.dma_addr().raw(),
                    len: (20 + MAX_RX_FRAME_PAYLOAD) as u32,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                }])
                .ok_or("RX post failed")?
            };
            fixture.dev.pairs[0].rx_buffers.lock()[head_b as usize] = Some(buf_b);
            // Fake device completion: rewrite used entry 0 (segment
            // 0, 1538 bytes) and append used entry 1 (continuation,
            // 50 bytes), then bump idx to 2. Element 1 sits 8 bytes
            // past element 0, i.e. 6 u16s past the ring base.
            let used = narf_memory::PhysAddr::new(fixture.rx_used).kernel_mut_ptr::<u16>();
            // SAFETY: the fixture exclusively owns this aligned ring page.
            unsafe {
                core::ptr::write_volatile(
                    used.add(2).cast::<VirtqUsedElem>(),
                    VirtqUsedElem {
                        id: u32::from(head_a),
                        len: 1538,
                    },
                );
                core::ptr::write_volatile(
                    used.add(6).cast::<VirtqUsedElem>(),
                    VirtqUsedElem {
                        id: u32::from(head_b),
                        len: 50,
                    },
                );
                crate::queue::virtio_wmb();
                core::ptr::write_volatile(used.add(1), 2);
            }
            let (merged, total) = fixture.dev.rx_take().ok_or("merged take failed")?;
            if total != 1588 {
                return Err("merged total wrong");
            }
            let got = merged.as_slice();
            if got.len() < 1588 {
                return Err("merged buffer short");
            }
            // Header: only the written fields are nonzero (the
            // segment was zero-filled first).
            let mut header = [0u8; 20];
            header[10] = 2;
            header[12..16].copy_from_slice(&0x11223344u32.to_le_bytes());
            header[16..18].copy_from_slice(&0x0007u16.to_le_bytes());
            if got[..20] != header[..] {
                return Err("merged header wrong");
            }
            for i in 0..1518 {
                if got[20 + i] != (i as u8).wrapping_add(0x40) {
                    return Err("merged first payload wrong");
                }
            }
            for i in 0..50 {
                if got[1538 + i] != (i as u8).wrapping_add(0x80) {
                    return Err("merged continuation wrong");
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
        smoke_virtio_net_mrg_hash_reassembly
    );

    fn smoke_virtio_net_vlan_filter_gating() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            // Validation runs before any device access, so an
            // out-of-range VID reports InvalidArgument even with
            // no control queue at all.
            if !matches!(
                fixture.dev.vlan_add(4096),
                Err(VirtioPciError::InvalidArgument)
            ) {
                return Err("vlan_add accepted VID 4096");
            }
            if !matches!(
                fixture.dev.vlan_del(4096),
                Err(VirtioPciError::InvalidArgument)
            ) {
                return Err("vlan_del accepted VID 4096");
            }
            // The fixture negotiates nothing and has no control
            // queue: in-range commands short-circuit with NoQueues.
            if !matches!(fixture.dev.vlan_add(100), Err(VirtioPciError::NoQueues)) {
                return Err("vlan_add without F_CTRL_VLAN did not report NoQueues");
            }
            if !matches!(fixture.dev.vlan_del(100), Err(VirtioPciError::NoQueues)) {
                return Err("vlan_del without F_CTRL_VLAN did not report NoQueues");
            }
            if !matches!(
                fixture.dev.set_mac_table(&[[1; 6]], &[[2; 6]]),
                Err(VirtioPciError::NoQueues)
            ) {
                return Err("set_mac_table without F_CTRL_RX did not report NoQueues");
            }
            // The payload is built and bound-checked before the
            // gate, so an over-large table reports RequestTooLarge
            // even with no control queue. 679 entries = 4082 bytes
            // of payload, past MAX_CTRL_PAYLOAD (4079).
            let big: Vec<[u8; 6]> = (0..679)
                .map(|i| [(i >> 8) as u8, i as u8, 0, 0, 0, 0])
                .collect();
            if !matches!(
                fixture.dev.set_mac_table(&big, &[]),
                Err(VirtioPciError::RequestTooLarge)
            ) {
                return Err("oversize MAC table did not report RequestTooLarge");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_mrg_frame_shape);

    fn smoke_virtio_net_mtu_clamp() -> TestResult {
        let run = || -> Result<(), &'static str> {
            if clamp_mtu(9000, true) != 9000 {
                return Err("jumbo MTU clamped with MRG");
            }
            if clamp_mtu(9000, false) != 1500 {
                return Err("jumbo MTU published without MRG");
            }
            if clamp_mtu(16000, true) != 9000 {
                return Err("oversize MTU published with MRG");
            }
            if clamp_mtu(1500, true) != 1500 || clamp_mtu(1500, false) != 1500 {
                return Err("standard MTU changed by clamp");
            }
            if clamp_mtu(64, false) != 64 {
                return Err("minimum MTU changed by clamp");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }

    /// Runtime `set_mtu` (audit gap 11): bounds, live-MTU
    /// retarget, and the TX plain-frame cap following the live
    /// value. Fixture: device MTU 1500, no MRG — ceiling 1500.
    /// The cap check goes through `tx_header_for_frame` with the
    /// same `max_frame_for_mtu(dev.mtu())` bound the submit path
    /// passes, so it pins the live TX boundary, not a copy of it.
    fn smoke_virtio_net_mtu_set_runtime() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            let dev = &fixture.dev;
            if dev.mtu() != 1500 || dev.max_mtu() != 1500 {
                return Err("fixture MTU/ceiling is not 1500");
            }
            if dev.set_mtu(1400).is_err() || dev.mtu() != 1400 {
                return Err("set_mtu(1400) did not take");
            }
            let profile = dev.tx_offload_profile();
            let mut frame = [0u8; 1419];
            if tx_header_for_frame(
                &mut frame[..1418],
                narf_net::TxMeta::plain(),
                profile,
                max_frame_for_mtu(dev.mtu()),
            )
            .is_err()
            {
                return Err("1418-byte frame rejected at MTU 1400");
            }
            if tx_header_for_frame(
                &mut frame,
                narf_net::TxMeta::plain(),
                profile,
                max_frame_for_mtu(dev.mtu()),
            )
            .is_ok()
            {
                return Err("1419-byte frame accepted at MTU 1400");
            }
            // Bounds: Linux floor 68; above the ceiling rejected;
            // a rejected change leaves the live MTU untouched.
            if dev.set_mtu(67).is_ok() || dev.mtu() != 1400 {
                return Err("MTU 67 accepted or clobbered live MTU");
            }
            if dev.set_mtu(1501).is_ok() || dev.mtu() != 1400 {
                return Err("MTU above ceiling accepted or clobbered live MTU");
            }
            if dev.set_mtu(68).is_err() || dev.mtu() != 68 {
                return Err("set_mtu(68) did not take");
            }
            if dev.set_mtu(1500).is_err() || dev.mtu() != 1500 {
                return Err("set_mtu(1500) restore did not take");
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
        smoke_virtio_net_vlan_filter_gating
    );

    fn smoke_virtio_net_vlan_tagged_tso_layout() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            // Same minimal IPv4/TCP frame the burst tests submit.
            let build_untagged = |dst: &mut [u8]| {
                dst.fill(0);
                dst[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                dst[14] = 0x45;
                dst[16..18].copy_from_slice(&((FRAME_LEN - 14) as u16).to_be_bytes());
                dst[23] = 6;
                dst[46] = 5 << 4;
                dst[47] = 0x18;
            };
            // Untagged TSO submit: baseline header.
            let mut buf = fixture.dev.tx_buf_acquire_on(0).ok_or("TX pool starved")?;
            {
                let slice = buf.as_mut_slice();
                build_untagged(&mut slice[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + FRAME_LEN]);
            }
            fixture
                .dev
                .tx_dma_on_with_meta(0, buf, FRAME_LEN as u32, narf_net::TxMeta::with_tso(1024))
                .map_err(|_| "untagged TSO submit rejected")?;
            // Tagged TSO submit: same frame with a tag inserted.
            let mut tagged = alloc::vec![0; FRAME_LEN + VLAN_TAG_LEN];
            {
                let mut plain = alloc::vec![0; FRAME_LEN];
                build_untagged(&mut plain);
                let len =
                    copy_frame_with_vlan(&mut tagged, &plain, 0x1234).ok_or("tag insert failed")?;
                if len != FRAME_LEN + VLAN_TAG_LEN {
                    return Err("tagged length wrong");
                }
            }
            let mut buf = fixture.dev.tx_buf_acquire_on(0).ok_or("TX pool starved")?;
            {
                let slice = buf.as_mut_slice();
                slice[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + tagged.len()]
                    .copy_from_slice(&tagged);
            }
            fixture
                .dev
                .tx_dma_on_with_meta(
                    0,
                    buf,
                    tagged.len() as u32,
                    narf_net::TxMeta::with_tso(1024),
                )
                .map_err(|_| "tagged TSO submit rejected")?;
            // Read back both submitted buffers and classify them by
            // their EtherType bytes: the tag shifts every L4 offset
            // by exactly VLAN_TAG_LEN, nothing else changes.
            let bufs = fixture.dev.pairs[0].tx_buffers.lock();
            let mut seen_untagged = false;
            let mut seen_tagged = false;
            for slot in bufs.iter().flatten() {
                let bytes = slot.as_slice();
                let hdr = &bytes[..VIRTIO_NET_HDR_LEN];
                let frame = &bytes[VIRTIO_NET_HDR_LEN..];
                let hdr_len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
                let csum_start = u16::from_le_bytes([hdr[6], hdr[7]]) as usize;
                let csum_offset = u16::from_le_bytes([hdr[8], hdr[9]]) as usize;
                if hdr[0] != 1 || hdr[1] != 1 || csum_offset != 16 {
                    return Err("virtio header flags/type/offset wrong");
                }
                if frame[12..14] == [0x08, 0x00] {
                    if hdr_len != 54 || csum_start != 34 {
                        return Err("untagged TSO layout wrong");
                    }
                    seen_untagged = true;
                } else if frame[12..16] == [0x81, 0x00, 0x12, 0x34] {
                    if hdr_len != 58 || csum_start != 38 {
                        return Err("tagged TSO layout not shifted by the tag");
                    }
                    if frame[16..18] != [0x08, 0x00] {
                        return Err("inner EtherType wrong after tag");
                    }
                    seen_tagged = true;
                } else {
                    return Err("submitted frame has neither layout");
                }
            }
            if !seen_untagged || !seen_tagged {
                return Err("missing submitted buffer");
            }
            drop(bufs);
            // Pool accounting: two buffers in flight on pair 0, pair
            // 1 untouched — the tag path moves no buffers across pairs.
            if fixture.dev.pairs[0].tx_pool.available() != TX_POOL_CAP - 2
                || fixture.dev.pairs[1].tx_pool.available() != TX_POOL_CAP
            {
                return Err("tagged TX leaked buffers or crossed queue pools");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_mtu_clamp);
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_mtu_set_runtime);

    fn smoke_virtio_net_tx_plain_cap_follows_mtu() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let profile = TxOffloadProfile {
                checksum: false,
                tso4: false,
                tso6: false,
                uso: false,
            };
            let mut buf = alloc_coherent(9018, DomainId::DRIVER_0).map_err(|_| "jumbo buf")?;
            let frame = &mut buf.as_mut_slice()[..9018];
            // Plain arm validates length only; zero-filled content is fine.
            if tx_header_for_frame(frame, narf_net::TxMeta::plain(), profile, 9018).is_err() {
                return Err("jumbo plain frame rejected at jumbo cap");
            }
            if tx_header_for_frame(frame, narf_net::TxMeta::plain(), profile, 1518).is_ok() {
                return Err("jumbo plain frame accepted at standard cap");
            }
            let frame = &mut buf.as_mut_slice()[..1518];
            if tx_header_for_frame(frame, narf_net::TxMeta::plain(), profile, 1518).is_err() {
                return Err("standard plain frame rejected at standard cap");
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
        smoke_virtio_net_vlan_tagged_tso_layout
    );

    // RX-capable fixture for the drain path: one queue pair whose RX
    // virtqueue the test drives directly (post a buffer, fake a device
    // completion), mirroring TxFixture's RAM-backed rings. The fake
    // device completes only when the test writes the used entry, so
    // drain behavior never depends on QEMU timing.
    const RX_POOL_CAP: usize = 4;

    struct RxFixture {
        dev: VirtioNetPci,
        _registers: DmaBuffer,
        /// Base of the RX used ring, so a merged-take smoke can fake
        /// a second device completion without rebuilding the fixture.
        rx_used: u64,
    }

    impl RxFixture {
        fn new(rx_hdr_len: usize, guest_csum: bool, hdr_flags: u8) -> Result<Self, &'static str> {
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
            let rx_page = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "RX ring page")?;
            let tx_page = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "TX ring page")?;
            let layout =
                VirtqueueLayout::new(QSIZE, rx_page.phys_addr().raw()).ok_or("RX layout")?;
            // SAFETY: rx_page owns a coherent page containing this entire layout.
            let mut rx_queue = unsafe { Virtqueue::new(layout) };
            let rx_pool = DmaPool::new(4096, DomainId::DRIVER_0, RX_POOL_CAP);
            if rx_pool.prefill(RX_POOL_CAP) != RX_POOL_CAP {
                return Err("RX pool prefill");
            }
            // Device-written buffer: virtio header (flags byte only) +
            // an IPv4/TCP frame (eth 14 + ip 20 + tcp 20), same field
            // writes as the tests.rs verdict builder.
            let mut frame_buf = rx_pool.try_acquire().ok_or("RX pool starved")?;
            let mut frame = [0u8; 54];
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame[14] = 0x45;
            frame[14 + 2..14 + 4].copy_from_slice(&40u16.to_be_bytes());
            frame[14 + 8] = 64;
            frame[14 + 9] = 6;
            frame[14 + 12..14 + 16].copy_from_slice(&[192, 0, 2, 10]);
            frame[14 + 16..14 + 20].copy_from_slice(&[198, 51, 100, 20]);
            frame[34..36].copy_from_slice(&1234u16.to_be_bytes());
            frame[36..38].copy_from_slice(&443u16.to_be_bytes());
            frame[34 + 12] = 5 << 4;
            frame[34 + 13] = 0x18;
            let total = (rx_hdr_len + 54) as u32;
            {
                let slice = frame_buf.as_mut_slice();
                slice[0] = hdr_flags;
                slice[rx_hdr_len..rx_hdr_len + 54].copy_from_slice(&frame);
            }
            let head = rx_queue
                .add_buffer(&[VirtqDesc {
                    addr: frame_buf.dma_addr().raw(),
                    len: (rx_hdr_len + MAX_RX_FRAME_PAYLOAD) as u32,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                }])
                .ok_or("RX post failed")?;
            let mut rx_buffers: Vec<Option<DmaBuffer>> = (0..QSIZE).map(|_| None).collect();
            rx_buffers[head as usize] = Some(frame_buf);
            // Fake device completion: one used entry, then bump idx.
            let used = narf_memory::PhysAddr::new(layout.used_ring).kernel_mut_ptr::<u16>();
            // SAFETY: the fixture exclusively owns this aligned ring page.
            unsafe {
                core::ptr::write_volatile(
                    used.add(2).cast::<VirtqUsedElem>(),
                    VirtqUsedElem {
                        id: u32::from(head),
                        len: total,
                    },
                );
                crate::queue::virtio_wmb();
                core::ptr::write_volatile(used.add(1), 1);
            }
            let pair = QueuePair {
                rx_qidx: 0,
                tx_qidx: 1,
                rx_queue: IrqSafeSpinLock::new(Some(rx_queue)),
                tx_queue: IrqSafeSpinLock::new(None),
                rx_buffers: IrqSafeSpinLock::new(rx_buffers),
                tx_buffers: IrqSafeSpinLock::new(Vec::new()),
                tx_pool: Arc::new(DmaPool::new(TX_BUF_LEN, DomainId::DRIVER_0, 0)),
                rx_pool,
                _rx_q_buf: rx_page,
                _tx_q_buf: tx_page,
                rx_qsize: QSIZE,
                tx_qsize: 0,
                rx_notify_off: 0,
                tx_notify_off: 1,
            };
            let pairs = alloc::vec![pair];
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
                config_irq_vector: None,
                msix: IrqSafeSpinLock::new(None),
                ready: true,
                detached: AtomicBool::new(false),
                suspended: AtomicBool::new(false),
                ifname: IrqSafeSpinLock::new(None),
                mac: IrqSafeSpinLock::new([0; 6]),
                has_ctrl_mac_addr: false,
                has_ctrl_rx: false,
                has_ctrl_vlan: false,
                mtu: AtomicU32::new(1500),
                device_mtu: 1500,
                has_status: false,
                has_guest_announce: false,
                tx_checksum: true,
                tx_tso4: true,
                tx_tso6: false,
                tx_uso: false,
                rx_guest_csum: guest_csum,
                mrg_rxbuf: false,
                has_rss: false,
                has_hash_report: rx_hdr_len == 20,
                rss_configured: false,
                rx_hdr_len,
                ctrl_qidx: 2,
                ctrl: None,
                cfg_phys: 0,
            };
            Ok(Self {
                dev,
                _registers: registers,
                rx_used: layout.used_ring,
            })
        }
    }

    /// Restores `PRIMARY_IFNAME` on scope exit so a drain test never
    /// leaks its fixture name into a later smoke, on any path.
    struct RestorePrimaryName(Option<&'static str>);

    impl Drop for RestorePrimaryName {
        fn drop(&mut self) {
            *super::PRIMARY_IFNAME.lock() = self.0;
        }
    }

    /// Regression pin for the drain-path GUEST_CSUM bypass: before the
    /// fix, `vnet0_drain_fn` delivered every taken frame via
    /// `on_rx_frame_from` with no verdict at all, so an unverified
    /// checksummed segment reached the stack through the connect_wait
    /// drain while the async pump dropped it. The cases below route a
    /// checksummed segment through the drain's own take → verdict →
    /// deliver/drop → recycle code (`drain_one_on`, the body of
    /// `vnet0_drain_fn`) and observe the outcome via the interface
    /// counters: delivered frames bump rx_packets, dropped frames bump
    /// rx_drop. The drain-namespace iface ("drain%d") keeps the test
    /// out of the live eth%d namespace; no controller is installed,
    /// so no forwarder or later smoke can observe the fixture.
    fn smoke_virtio_net_drain_enforces_guest_csum() -> TestResult {
        fn run_case(
            rx_hdr_len: usize,
            guest_csum: bool,
            hdr_flags: u8,
            expect_delivered: bool,
        ) -> Result<(), &'static str> {
            let fixture = RxFixture::new(rx_hdr_len, guest_csum, hdr_flags)?;
            let name = narf_net::iface::register_static(
                "drain%d",
                [0x02, 0, 0, 0, 0, 0x01],
                super::vnet0_send_fn,
            );
            let prev = {
                let mut g = super::PRIMARY_IFNAME.lock();
                let prev = *g;
                *g = Some(name);
                prev
            };
            let _restore = RestorePrimaryName(prev);
            let counters = |name: &str| {
                narf_net::iface::snapshot_counters()
                    .into_iter()
                    .find(|s| s.name.as_str() == name)
                    .ok_or("drain iface not registered")
            };
            let before = counters(name)?;
            let drained = fixture.dev.drain_one_on(0);
            let after = counters(name)?;
            if !drained {
                return Err("drain reported no frame");
            }
            let delivered =
                after.rx_packets == before.rx_packets + 1 && after.rx_drop == before.rx_drop;
            let dropped =
                after.rx_drop == before.rx_drop + 1 && after.rx_packets == before.rx_packets;
            if expect_delivered && !delivered {
                return Err("drain dropped a frame it must deliver");
            }
            if !expect_delivered && !dropped {
                return Err("drain delivered an unverified checksummed segment");
            }
            Ok(())
        }
        let run = || -> Result<(), &'static str> {
            // Unverified TCPv4, 12-byte header: the bypass itself.
            run_case(12, true, 0, false)?;
            // Unverified TCPv4, 20-byte HASH_REPORT header: pins the
            // runtime header length — a hardcoded 12 would slice the
            // header-shifted window (ethertype 0x0000 from the zeroed
            // dst-MAC bytes) and deliver.
            run_case(20, true, 0, false)?;
            // Device-verified TCPv4 under HASH_REPORT: delivers, proving
            // the harness observes delivery and the verdict does not
            // over-drop.
            run_case(20, true, VIRTIO_NET_HDR_F_DATA_VALID, true)?;
            // GUEST_CSUM not negotiated: the gate holds, everything
            // delivers as before.
            run_case(12, false, 0, true)?;
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_drain_enforces_guest_csum
    );
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_tx_plain_cap_follows_mtu
    );

    fn smoke_virtio_net_rx_recycle_drops_oversized() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fixture = TxFixture::new()?;
            let pool = &fixture.dev.pairs[0].rx_pool;
            if !pool.prepare() {
                return Err("rx pool prepare");
            }
            let small = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "pool buf")?;
            fixture.dev.rx_buf_release_on(0, small);
            if pool.available() != 1 {
                return Err("4 KiB buffer not retained");
            }
            let big = alloc_coherent(9030, DomainId::DRIVER_0).map_err(|_| "jumbo buf")?;
            fixture.dev.rx_buf_release_on(0, big);
            if pool.available() != 1 {
                return Err("oversized reassembled buffer pooled");
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
        smoke_virtio_net_rx_recycle_drops_oversized
    );

    /// Per-pair MSI-X, live-device readback (gap 10): on the real
    /// QEMU common cfg, every pair's TX queue (2K+1) must point at
    /// the same table slot as its RX queue (2K), and pairs with
    /// vectors must hold distinct slots. Read-only: QUEUE_SELECT
    /// writes are safe post-probe — the only writer in this driver
    /// is probe-time `size_q`, and every queue access sets SELECT
    /// first. Skips when no virtio-net controller is bound or
    /// MSI-X never came up at probe.
    fn smoke_virtio_net_msix_tx_shares_rx_slot() -> TestResult {
        let Some((num_pairs, rx_vecs)) = with_at(0, |c| (c.num_pairs(), c.rx_irq_vectors.clone()))
        else {
            return TestResult::Skip("no virtio-net controller");
        };
        if rx_vecs.iter().all(|v| v.is_none()) {
            return TestResult::Skip("MSI-X not enabled at probe");
        }
        let run = || -> Result<(), &'static str> {
            let mut slots: [Option<u16>; 4] = [None; 4];
            for (k, slot) in slots.iter_mut().enumerate().take(num_pairs) {
                if rx_vecs.get(k).copied().flatten().is_none() {
                    continue;
                }
                let rx = with_at(0, |c| {
                    // SAFETY: `c` is the live controller (the `Arc`
                    // keeps it alive for the closure); `common` is
                    // its mapped common-cfg MMIO region, and
                    // CC_QUEUE_SELECT (0x16) / CC_QUEUE_MSIX_VECTOR
                    // (0x1A) are in-bounds common-cfg registers.
                    // QUEUE_SELECT writes are safe post-probe: the
                    // only writer in this driver is probe-time
                    // `size_q`, and every queue access sets SELECT
                    // first.
                    unsafe {
                        c.common.write16(crate::pci::CC_QUEUE_SELECT, 2 * k as u16);
                        c.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR)
                    }
                })
                .ok_or("controller vanished")?;
                let tx = with_at(0, |c| {
                    // SAFETY: same as the RX readback above: `c` is
                    // the live controller, `common` is its mapped
                    // common-cfg MMIO region, and CC_QUEUE_SELECT
                    // (0x16) / CC_QUEUE_MSIX_VECTOR (0x1A) are
                    // in-bounds common-cfg registers. QUEUE_SELECT
                    // writes are safe post-probe: the only writer in
                    // this driver is probe-time `size_q`, and every
                    // queue access sets SELECT first.
                    unsafe {
                        c.common
                            .write16(crate::pci::CC_QUEUE_SELECT, 2 * k as u16 + 1);
                        c.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR)
                    }
                })
                .ok_or("controller vanished")?;
                if rx == 0xFFFF || tx == 0xFFFF {
                    return Err("pair queue left NO_VECTOR despite an IRQ vector");
                }
                if rx != tx {
                    return Err("TX queue does not share its pair RX slot");
                }
                *slot = Some(rx);
            }
            for a in 0..num_pairs {
                for b in a + 1..num_pairs {
                    if let (Some(x), Some(y)) = (slots[a], slots[b]) {
                        if x == y {
                            return Err("two pairs share one MSI-X slot");
                        }
                    }
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
        smoke_virtio_net_msix_tx_shares_rx_slot
    );

    /// Config MSI-X vector, live-device readback (gap 10): when a
    /// config vector was bound, `msix_config` must hold a slot
    /// inside the table, distinct from every pair slot, with an
    /// IDT vector distinct from every pair's. When none was bound,
    /// that is legitimate only if the table is full (every slot
    /// went to a pair). Same Skip conditions as the share smoke.
    fn smoke_virtio_net_msix_config_vector() -> TestResult {
        let Some((rx_vecs, cfg_v, table_size)) = with_at(0, |c| {
            (
                c.rx_irq_vectors.clone(),
                c.config_irq_vector,
                c.msix.lock().as_ref().map(|t| t.size()),
            )
        }) else {
            return TestResult::Skip("no virtio-net controller");
        };
        if rx_vecs.iter().all(|v| v.is_none()) {
            return TestResult::Skip("MSI-X not enabled at probe");
        }
        let run = || -> Result<(), &'static str> {
            let used = rx_vecs.iter().filter(|v| v.is_some()).count() as u16;
            let size = table_size.ok_or("MSI-X table not retained")?;
            match cfg_v {
                None => {
                    if size > used {
                        return Err("config vector missing despite free table slots");
                    }
                    Ok(())
                }
                Some(v) => {
                    let slot = with_at(0, |c| {
                        // SAFETY: `c` is the live controller (the
                        // `Arc` keeps it alive for the closure);
                        // `common` is its mapped common-cfg MMIO
                        // region, and CC_MSIX_CONFIG (0x10) is an
                        // in-bounds common-cfg register. Read-only.
                        unsafe { c.common.read16(crate::pci::CC_MSIX_CONFIG) }
                    })
                    .ok_or("controller vanished")?;
                    if slot == 0xFFFF {
                        return Err("msix_config reads NO_VECTOR despite a bound vector");
                    }
                    if slot >= size {
                        return Err("msix_config slot outside the table");
                    }
                    for (k, v) in rx_vecs.iter().enumerate() {
                        if v.is_none() {
                            continue;
                        }
                        let qslot = with_at(0, |c| {
                            // SAFETY: same as the share smoke above:
                            // `c` is the live controller, `common`
                            // is its mapped common-cfg MMIO region,
                            // and CC_QUEUE_SELECT (0x16) /
                            // CC_QUEUE_MSIX_VECTOR (0x1A) are
                            // in-bounds common-cfg registers.
                            // QUEUE_SELECT writes are safe post-probe:
                            // the only writer in this driver is
                            // probe-time `size_q`, and every queue
                            // access sets SELECT first.
                            unsafe {
                                c.common.write16(crate::pci::CC_QUEUE_SELECT, 2 * k as u16);
                                c.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR)
                            }
                        })
                        .ok_or("controller vanished")?;
                        if qslot == slot {
                            return Err("config vector shares a pair queue slot");
                        }
                    }
                    if rx_vecs.iter().flatten().any(|&rv| rv == v) {
                        return Err("config IDT vector collides with a pair vector");
                    }
                    Ok(())
                }
            }
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_msix_config_vector
    );

    /// MSI-X common-cfg bind writes on the RAM-backed fixture:
    /// the real production helpers (`bind_queue_msix_vector`,
    /// `bind_config_msix_vector`) must write the slot and read it
    /// back, and `bind_tx_queue_shares` must walk the pairs in
    /// order, binding TX queue 2K+1 per pair (pair 0 → queue 1,
    /// pair 1 → queue 3). Flat RAM cannot emulate per-queue SELECT
    /// semantics, so the per-queue mapping itself is pinned by
    /// the live-device smokes above; this pins the write path and
    /// the queue-index arithmetic.
    fn smoke_virtio_net_msix_bind_writes() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let fx = TxFixture::new()?;
            // SAFETY: `fx` is this test's own fixture; `fx.dev.common`
            // is the RAM-backed common-cfg region over the fixture's
            // own 4096-byte coherent page, exclusively owned here.
            // The bind writes queue 1 → slot 3 and reads it back.
            let ok = unsafe { crate::pci::bind_queue_msix_vector(&fx.dev.common, 1, 3) };
            if !ok {
                return Err("queue bind readback mismatch on RAM region");
            }
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // read-only read of the in-bounds CC_QUEUE_MSIX_VECTOR
            // register (0x1A).
            let at = unsafe { fx.dev.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR) };
            if at != 3 {
                return Err("queue bind did not write the slot");
            }
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // the bind writes the config slot and reads it back.
            let ok = unsafe { crate::pci::bind_config_msix_vector(&fx.dev.common, 4) };
            if !ok {
                return Err("config bind readback mismatch on RAM region");
            }
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // read-only read of the in-bounds CC_MSIX_CONFIG register
            // (0x10).
            let at = unsafe { fx.dev.common.read16(crate::pci::CC_MSIX_CONFIG) };
            if at != 4 {
                return Err("config bind did not write the slot");
            }
            // Pair 0 first: TX queue 1 → slot 0.
            let bindings = [
                crate::pci::MsixQueueBinding {
                    idt_vector: Some(40),
                    slot: Some(0),
                },
                crate::pci::MsixQueueBinding {
                    idt_vector: Some(41),
                    slot: Some(1),
                },
            ];
            fx.dev.bind_tx_queue_shares(&bindings[..1]);
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // read-only reads of the in-bounds CC_QUEUE_SELECT (0x16)
            // / CC_QUEUE_MSIX_VECTOR (0x1A) registers.
            let sel = unsafe { fx.dev.common.read16(crate::pci::CC_QUEUE_SELECT) };
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // read-only read of the in-bounds CC_QUEUE_MSIX_VECTOR
            // register (0x1A).
            let vec = unsafe { fx.dev.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR) };
            if sel != 1 || vec != 0 {
                return Err("TX-share loop did not bind pair 0 (queue 1, slot 0)");
            }
            // Then pair 1: TX queue 3 → slot 1.
            fx.dev.bind_tx_queue_shares(&bindings);
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // read-only reads of the in-bounds CC_QUEUE_SELECT (0x16)
            // / CC_QUEUE_MSIX_VECTOR (0x1A) registers.
            let sel = unsafe { fx.dev.common.read16(crate::pci::CC_QUEUE_SELECT) };
            // SAFETY: same fixture-owned RAM-backed common-cfg region;
            // read-only read of the in-bounds CC_QUEUE_MSIX_VECTOR
            // register (0x1A).
            let vec = unsafe { fx.dev.common.read16(crate::pci::CC_QUEUE_MSIX_VECTOR) };
            if sel != 3 || vec != 1 {
                return Err("TX-share loop did not bind pair 1 (queue 3, slot 1)");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_msix_bind_writes);

    /// MSI-X slot allocation order (gap 10): probe allocates pair
    /// slots first, in pair order, then the config slot — on a
    /// 5-slot table (4 pairs + config, the shared-per-pair shape)
    /// the slots come out 0..4 and a 6th allocation fails; on a
    /// 1-slot table pair 0 takes the only slot and the config
    /// allocation fails. Exercises the real `MsixTable` allocator
    /// via the synthetic table (no MMIO: `program_vector` is
    /// hardware-only, covered by the live-device smokes).
    fn smoke_virtio_net_msix_alloc_order() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let mut table = narf_bus::msix::__synth_msix_table(5);
            let mut slots = [0u16; 5];
            for slot in &mut slots {
                *slot = table.alloc_vector().ok_or("table exhausted early")?.vector;
            }
            if slots != [0, 1, 2, 3, 4] {
                return Err("MSI-X slots not allocated in probe order");
            }
            if table.alloc_vector().is_some() {
                return Err("MSI-X table over-allocated past its size");
            }
            let mut tiny = narf_bus::msix::__synth_msix_table(1);
            let _ = tiny.alloc_vector().ok_or("1-slot table gave nothing")?;
            if tiny.alloc_vector().is_some() {
                return Err("1-slot table gave a second vector");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_msix_alloc_order);

    /// Config-change link republish (gap 10 + gap 12 mechanism):
    /// `refresh_link_from_status` must follow the device-cfg
    /// STATUS word (VirtIO 1.2 §5.1.4: bit 0 = LINK_UP) on every
    /// call — up, down, up again. The fixture has no registered
    /// name, so nothing is published to the registry; only the
    /// STATUS decode the watcher relies on is pinned.
    fn smoke_virtio_net_config_change_republishes_link() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let mut fx = TxFixture::new()?;
            let page = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "cfg page")?;
            let region = VirtioRegion {
                region: narf_bus::MmioRegion {
                    phys: page.phys_addr(),
                    virt: page.cpu_ptr::<u8>() as u64,
                    len: 4096,
                    kind: narf_bus::BarKind::Mmio32 {
                        prefetchable: false,
                    },
                },
                virt: page.cpu_ptr::<u8>() as u64,
                offset: 0,
                length: 4096,
            };
            fx.dev.device_cfg = Some(region);
            fx.dev.has_status = true;
            // SAFETY: `device_cfg` is a region over a freshly
            // allocated 4096-byte coherent page, set up just above
            // in this test and exclusively owned by the fixture;
            // CFG_STATUS (6) is in-bounds (6 + 2 <= 4096), and the
            // write targets the STATUS word the link watcher decodes.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_LINK_UP);
            }
            if !fx.dev.refresh_link_from_status() {
                return Err("STATUS LINK_UP did not read as up");
            }
            // SAFETY: same fixture-owned 4096-byte device_cfg page as
            // above; CFG_STATUS (6) is in-bounds, and the write clears
            // the STATUS word the link watcher decodes.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, 0);
            }
            if fx.dev.refresh_link_from_status() {
                return Err("STATUS link-down did not read as down");
            }
            // SAFETY: same fixture-owned 4096-byte device_cfg page as
            // above; CFG_STATUS (6) is in-bounds, and the write
            // re-raises the STATUS word the link watcher decodes.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_LINK_UP);
            }
            if !fx.dev.refresh_link_from_status() {
                return Err("STATUS LINK_UP did not read as up on re-raise");
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
        smoke_virtio_net_config_change_republishes_link
    );

    /// Announce constants pinned byte-for-byte against the
    /// authoritative header (`include/uapi/linux/virtio_net.h`,
    /// torvalds/linux): class 3, ack cmd 0, feature bit 21, status
    /// bit 2 — never derived from the code under test.
    fn smoke_virtio_net_announce_constants() -> TestResult {
        let run = || -> Result<(), &'static str> {
            if VIRTIO_NET_CTRL_ANNOUNCE != 3 {
                return Err("CTRL_ANNOUNCE is not class 3");
            }
            if VIRTIO_NET_CTRL_ANNOUNCE_ACK != 0 {
                return Err("CTRL_ANNOUNCE_ACK is not cmd 0");
            }
            if VIRTIO_NET_F_GUEST_ANNOUNCE != 21 {
                return Err("F_GUEST_ANNOUNCE is not bit 21");
            }
            if VIRTIO_NET_S_ANNOUNCE != 2 {
                return Err("S_ANNOUNCE is not bit 1");
            }
            if VIRTIO_NET_S_LINK_UP != 1 {
                return Err("S_LINK_UP is not bit 0");
            }
            // The announce class sits between VLAN (2) and MQ (4)
            // in the §5.1.6.5 class space — a renumbering of either
            // neighbour would break this pin.
            if VIRTIO_NET_CTRL_VLAN != 2 || VIRTIO_NET_CTRL_MQ != 4 {
                return Err("announce neighbours moved in the class space");
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
        smoke_virtio_net_announce_constants
    );

    /// Announce gating + STATUS decode (gap 13): `ack_announce`
    /// short-circuits with NoQueues when F_GUEST_ANNOUNCE wasn't
    /// negotiated, and `announce_pending` follows the S_ANNOUNCE
    /// bit only when the feature AND F_STATUS are both negotiated.
    /// The fixture has no control queue and no registered name, so
    /// this pins the gates and the decode, not the wire command.
    fn smoke_virtio_net_announce_gating() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let mut fx = TxFixture::new()?;
            let page = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "cfg page")?;
            let region = VirtioRegion {
                region: narf_bus::MmioRegion {
                    phys: page.phys_addr(),
                    virt: page.cpu_ptr::<u8>() as u64,
                    len: 4096,
                    kind: narf_bus::BarKind::Mmio32 {
                        prefetchable: false,
                    },
                },
                virt: page.cpu_ptr::<u8>() as u64,
                offset: 0,
                length: 4096,
            };
            fx.dev.device_cfg = Some(region);
            // Fixture negotiates nothing: no ack, no pending, even
            // with S_ANNOUNCE raised in STATUS.
            // SAFETY: CFG_STATUS is a two-byte field within the live,
            // fixture-owned 4096-byte coherent page mapped above.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_ANNOUNCE);
            }
            if !matches!(fx.dev.ack_announce(), Err(VirtioPciError::NoQueues)) {
                return Err("ack_announce without F_GUEST_ANNOUNCE did not report NoQueues");
            }
            if fx.dev.announce_pending() {
                return Err("announce pending without negotiation");
            }
            // F_STATUS alone is not enough: the feature gate stays.
            fx.dev.has_status = true;
            if fx.dev.announce_pending() {
                return Err("announce pending with F_STATUS but no F_GUEST_ANNOUNCE");
            }
            // Both negotiated: the bit decodes.
            fx.dev.has_guest_announce = true;
            if !fx.dev.announce_pending() {
                return Err("S_ANNOUNCE did not read as pending");
            }
            // LINK_UP alone is not an announce request.
            // SAFETY: the fixture's coherent config page is still live;
            // CFG_STATUS is within its 4096-byte extent.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_LINK_UP);
            }
            if fx.dev.announce_pending() {
                return Err("LINK_UP alone read as announce pending");
            }
            // Both bits set: still pending.
            // SAFETY: the same fixture-owned config mapping remains valid
            // for this in-bounds two-byte status write.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
            }
            if !fx.dev.announce_pending() {
                return Err("S_ANNOUNCE|LINK_UP did not read as pending");
            }
            Ok(())
        };
        match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_announce_gating);

    /// `handle_config_change` (gap 13, watcher path): with
    /// S_ANNOUNCE raised and no control queue, the ack fails
    /// best-effort and is swallowed, the peer notification is a
    /// no-op (no registered name), and the link republish still
    /// runs — up, then down. A refused ack must never wedge
    /// the watcher or drop the link update.
    fn smoke_virtio_net_announce_handle_config_change() -> TestResult {
        let run = || -> Result<(), &'static str> {
            let mut fx = TxFixture::new()?;
            let page = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "cfg page")?;
            let region = VirtioRegion {
                region: narf_bus::MmioRegion {
                    phys: page.phys_addr(),
                    virt: page.cpu_ptr::<u8>() as u64,
                    len: 4096,
                    kind: narf_bus::BarKind::Mmio32 {
                        prefetchable: false,
                    },
                },
                virt: page.cpu_ptr::<u8>() as u64,
                offset: 0,
                length: 4096,
            };
            fx.dev.device_cfg = Some(region);
            fx.dev.has_status = true;
            fx.dev.has_guest_announce = true;
            // SAFETY: CFG_STATUS lies within the coherent page owned by
            // this fixture, which stays live through handle_config_change.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
            }
            fx.dev.handle_config_change();
            if !fx.dev.link_up() {
                return Err("link did not read up after announce handle");
            }
            // SAFETY: the fixture-owned page remains live and the same
            // two-byte status field remains within its mapped extent.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, 0);
            }
            fx.dev.handle_config_change();
            if fx.dev.link_up() {
                return Err("link did not read down after announce handle");
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
        smoke_virtio_net_announce_handle_config_change
    );

    // TX-capture cell for the announce test below: the fixture
    // registers the interface with this send fn, so every frame
    // `notify_peers` emits lands here instead of a device.
    static ANNOUNCE_TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

    fn announce_capture(frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
        ANNOUNCE_TX.lock().push(frame.to_vec());
        Ok(())
    }

    /// `notify_peers` via `handle_config_change` (gap 13, IPv6 half):
    /// with S_ANNOUNCE raised, a registered name, a primary IPv4
    /// address and usable IPv6 addresses, the announce emits the
    /// gratuitous ARP AND one unsolicited NA per usable IPv6 address
    /// (Solicited clear, Override set, dst ff02::1, target == src,
    /// TLLA option == our MAC), then the link republish still runs.
    /// A Tentative address gets no NA. Registry state is removed
    /// afterwards so the shared registries are left clean.
    fn smoke_virtio_net_announce_notify_peers_na() -> TestResult {
        const IFACE: &str = "vnet-na-1535";
        const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x53];
        const V4: [u8; 4] = [192, 168, 7, 5];
        const GLOBAL: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        const TENTATIVE: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        const ALL_NODES: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let ll = narf_net::ipv6::addrs::link_local_from_mac(MAC);

        let run = || -> Result<(), &'static str> {
            use narf_net::ipv6::addrs::{AddrScope, AddrState, Ipv6IfAddr};
            use narf_net::pkt_ipv6::{NA_FLAG_OVERRIDE, NA_FLAG_SOLICITED};

            let mut fx = TxFixture::new()?;
            let page = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| "cfg page")?;
            let region = VirtioRegion {
                region: narf_bus::MmioRegion {
                    phys: page.phys_addr(),
                    virt: page.cpu_ptr::<u8>() as u64,
                    len: 4096,
                    kind: narf_bus::BarKind::Mmio32 {
                        prefetchable: false,
                    },
                },
                virt: page.cpu_ptr::<u8>() as u64,
                offset: 0,
                length: 4096,
            };
            fx.dev.device_cfg = Some(region);
            fx.dev.has_status = true;
            fx.dev.has_guest_announce = true;

            // Register the fixture interface with the capture send fn
            // and give it one IPv4 + two usable IPv6 addresses, plus
            // a Tentative one that must not be announced.
            let registered = narf_net::iface::register(IFACE, MAC, announce_capture);
            if registered != IFACE {
                return Err("announce iface registered under a different name");
            }
            narf_net::ifaddr::iface_add_addr(IFACE, narf_net::ipv4::Ipv4Addr(V4), 24);
            for (addr, state, scope) in [
                (ll, AddrState::Preferred, AddrScope::LinkLocal),
                (GLOBAL, AddrState::Preferred, AddrScope::Global),
                (TENTATIVE, AddrState::Tentative, AddrScope::Global),
            ] {
                narf_net::ipv6::addrs::add(Ipv6IfAddr {
                    iface: alloc::string::String::from(IFACE),
                    addr,
                    prefix_len: 64,
                    state,
                    scope,
                    preferred_deadline_ns: u64::MAX,
                    valid_deadline_ns: u64::MAX,
                    temporary: false,
                });
            }
            fx.dev.set_ifname(alloc::string::String::from(IFACE));

            // SAFETY: CFG_STATUS lies within the coherent page owned by
            // this fixture, which stays live through handle_config_change.
            unsafe {
                fx.dev
                    .device_cfg
                    .as_ref()
                    .ok_or("no device_cfg")?
                    .write16(CFG_STATUS, VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
            }
            ANNOUNCE_TX.lock().clear();
            fx.dev.handle_config_change();
            if !fx.dev.link_up() {
                return Err("link did not read up after announce handle");
            }

            let frames = {
                let mut g = ANNOUNCE_TX.lock();
                let out = g.clone();
                g.clear();
                out
            };
            if frames.len() != 3 {
                return Err("announce did not emit exactly ARP + 2 NAs");
            }
            let mut saw_arp = false;
            let mut na_srcs: [bool; 2] = [false, false];
            for frame in &frames {
                if frame.len() < 14 {
                    return Err("announce emitted a runt frame");
                }
                let ethertype = [frame[12], frame[13]];
                if ethertype == [0x08, 0x06] {
                    // Gratuitous ARP: SPA == TPA == our IPv4 address.
                    if frame.len() < 42 || frame[28..32] != V4 || frame[38..42] != V4 {
                        return Err("gratuitous ARP SPA/TPA != our IPv4 address");
                    }
                    if saw_arp {
                        return Err("announce emitted two gratuitous ARPs");
                    }
                    saw_arp = true;
                } else if ethertype == [0x86, 0xdd] {
                    // Unsolicited NA: IPv6/ICMPv6 (58), type 136,
                    // code 0, Solicited clear, Override set, dst
                    // ff02::1, target == src, TLLA option == our MAC.
                    if frame.len() < 86 || frame[20] != 58 {
                        return Err("unsolicited NA is not ICMPv6 or is truncated");
                    }
                    if frame[54] != 136 || frame[55] != 0 {
                        return Err("unsolicited NA type/code != 136/0");
                    }
                    let flags = u32::from_be_bytes([frame[58], frame[59], frame[60], frame[61]]);
                    if flags & NA_FLAG_SOLICITED != 0 {
                        return Err("unsolicited NA Solicited flag must be clear");
                    }
                    if flags & NA_FLAG_OVERRIDE == 0 {
                        return Err("unsolicited NA Override flag must be set");
                    }
                    if frame[38..54] != ALL_NODES {
                        return Err("unsolicited NA dst != ff02::1");
                    }
                    let src: [u8; 16] = frame[22..38].try_into().map_err(|_| "NA src slice")?;
                    if frame[62..78] != src {
                        return Err("unsolicited NA target != src address");
                    }
                    if frame[78] != 2 || frame[79] != 1 || frame[80..86] != MAC {
                        return Err("unsolicited NA TLLA option != our MAC");
                    }
                    if src == ll {
                        na_srcs[0] = true;
                    } else if src == GLOBAL {
                        na_srcs[1] = true;
                    } else {
                        return Err("unsolicited NA src is not one of our usable addresses");
                    }
                } else {
                    return Err("announce emitted a frame that is neither ARP nor IPv6");
                }
            }
            if !saw_arp {
                return Err("announce emitted no gratuitous ARP");
            }
            if !na_srcs.iter().all(|s| *s) {
                return Err("announce missed an unsolicited NA for a usable address");
            }
            Ok(())
        };
        let result = match run() {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        };
        // Leave the shared registries clean whatever the outcome was.
        narf_net::iface::unregister(IFACE);
        for addr in [ll, GLOBAL, TENTATIVE] {
            narf_net::ipv6::addrs::remove(IFACE, &addr);
        }
        narf_net::ifaddr::iface_del_addr(IFACE, narf_net::ipv4::Ipv4Addr(V4), 24);
        ANNOUNCE_TX.lock().clear();
        result
    }
    kernel_test_in!(
        "drivers/virtio/net-pci",
        smoke_virtio_net_announce_notify_peers_na
    );
}
