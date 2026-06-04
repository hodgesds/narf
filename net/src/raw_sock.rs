//! AF_PACKET raw socket layer — receive all (or filtered) Ethernet
//! frames regardless of L3 protocol.
//!
//! References (clean-room):
//! - Linux Documentation/networking/packet_mmap.rst (interface concept).
//! - Linux net/packet/af_packet.c — `packet_rcv` dispatch, SOCK_RAW
//!   vs SOCK_DGRAM distinction, ETH_P_ALL fanout.
//!   <https://elixir.bootlin.com/linux/v6.8/source/net/packet/af_packet.c>
//! - IEEE 802.3 — Ethernet frame structure (ethertype field at offset 12).
//!
//! Two protocol selectors are provided:
//! - `ETH_P_ALL` (0x0003): receive every frame.
//! - Any other ethertype (e.g. `ETHERTYPE_IPV4 = 0x0800`): filter.
//!
//! Frames are delivered via `raw_pkt_deliver`, called from the top
//! of `tcp_stack::rx_handler` before any L3 dispatch.
//!
//! Optional `ifindex` filter: 0 = accept from any interface (the only
//! real iface in Stage-1 is always index 1; 0 or 1 both match).

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::pkt::ETH_HDR_LEN;

/// Accept every Ethernet frame regardless of ethertype.
pub const ETH_P_ALL: u16 = 0x0003;

/// A single captured Ethernet frame.
#[derive(Clone, Debug)]
pub struct RawFrame {
    /// Interface index the frame arrived on (1-based; 1 for the
    /// primary interface, matching Linux ARPHRD_ETHER convention).
    pub ifindex: u32,
    /// Full Ethernet frame bytes (including 14-byte header).
    pub frame: Vec<u8>,
}

/// Raw packet socket.  Receives Ethernet frames whose ethertype
/// matches `protocol` (or all frames if `protocol == ETH_P_ALL`).
#[derive(Debug)]
pub struct RawPacketSocket {
    /// `ETH_P_ALL` or a specific ethertype (network byte order on wire,
    /// stored in host byte order here for comparison convenience).
    pub protocol: u16,
    /// Interface index filter (0 = any).
    pub ifindex: u32,
    /// Receive queue.
    pub rx_queue: IrqSafeSpinLock<VecDeque<RawFrame>>,
    /// Maximum queue depth (configurable; default 128).
    pub max_depth: usize,
}

impl RawPacketSocket {
    fn new(protocol: u16, ifindex: u32) -> Self {
        Self {
            protocol,
            ifindex,
            rx_queue: IrqSafeSpinLock::new(VecDeque::new()),
            max_depth: 128,
        }
    }
}

// ── Global socket table ────────────────────────────────────────────

static RAW_PKT_SOCKETS: IrqSafeSpinLock<Vec<Arc<RawPacketSocket>>> =
    IrqSafeSpinLock::new(Vec::new());

// ── Public API ─────────────────────────────────────────────────────

/// Snapshot of one raw packet socket for `/proc/net/raw`. The raw
/// row format is the same as TCP/UDP — local/remote address,
/// queues — even though most fields are unused. We zero what
/// doesn't apply.
#[derive(Clone, Debug)]
pub struct RawSocketSnapshot {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    /// Convention: 7=CLOSE for raw (no L4 state).
    pub state_code: u8,
    pub protocol: u8,
}

/// Snapshot every raw packet socket. Cheap: only a few fields.
pub fn snapshot() -> Vec<RawSocketSnapshot> {
    let socks = RAW_PKT_SOCKETS.lock();
    socks
        .iter()
        .map(|s| RawSocketSnapshot {
            local_addr: [0u8; 4],
            local_port: 0,
            remote_addr: [0u8; 4],
            remote_port: 0,
            state_code: 0x07,
            // ETH_P_ALL → 0xFF sentinel since we don't have an L4
            // protocol number; ICMP raw sockets are handled by
            // `icmp_sock::snapshot_raw_protocols` separately.
            protocol: if s.protocol == ETH_P_ALL {
                0xFF
            } else {
                (s.protocol & 0xFF) as u8
            },
        })
        .collect()
}

/// Open a raw packet socket.
///
/// - `protocol`: `ETH_P_ALL` for all frames, or a specific ethertype
///   (e.g. `ETHERTYPE_IPV4 = 0x0800`) to filter.
/// - `ifindex`: 0 = any interface, non-zero = only from that interface.
pub fn raw_packet_open(protocol: u16, ifindex: u32) -> Arc<RawPacketSocket> {
    let sock = Arc::new(RawPacketSocket::new(protocol, ifindex));
    RAW_PKT_SOCKETS.lock().push(sock.clone());
    sock
}

/// Close a raw packet socket.
pub fn raw_packet_close(sock: &Arc<RawPacketSocket>) {
    RAW_PKT_SOCKETS.lock().retain(|s| !Arc::ptr_eq(s, sock));
}

/// Receive the next frame from a raw packet socket.
pub fn raw_packet_recv(sock: &Arc<RawPacketSocket>) -> Option<RawFrame> {
    sock.rx_queue.lock().pop_front()
}

/// Set the maximum receive queue depth.
pub fn raw_packet_set_depth(sock: &Arc<RawPacketSocket>, depth: usize) {
    // SAFETY: only modifies usize field; no race — callers hold Arc.
    // We rely on the IrqSafeSpinLock on rx_queue for queue ops; the
    // depth field is set before the socket receives any frames in
    // normal usage.  For correctness in tests, we guard under the
    // lock here.
    let q = sock.rx_queue.lock();
    // We have the lock so it's safe to mutate max_depth through the Arc.
    // Use a raw pointer to avoid requiring &mut Arc (the API takes &Arc).
    let ptr = sock.as_ref() as *const RawPacketSocket as *mut RawPacketSocket;
    // SAFETY: We hold the only lock that serialises queue writes; this
    // field is only mutated here and read under the same lock path.
    unsafe {
        (*ptr).max_depth = depth;
    }
    drop(q);
}

// ── RX deliver ─────────────────────────────────────────────────────
//
// Called from `tcp_stack::rx_handler` *before* L3 dispatch so that
// tcpdump-equivalent consumers see every frame, including malformed
// ones.

/// Deliver a raw Ethernet frame to all matching raw packet sockets.
/// `ifindex` is the receiving interface's index (1 for primary).
pub fn raw_pkt_deliver(frame: &[u8], ifindex: u32) {
    if frame.len() < ETH_HDR_LEN {
        return;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    // Snapshot the socket list under the lock, then release before
    // enqueuing to avoid holding the global lock while copying frames.
    let sockets: Vec<Arc<RawPacketSocket>> = RAW_PKT_SOCKETS.lock().clone();

    for sock in sockets {
        // Interface filter.
        if sock.ifindex != 0 && sock.ifindex != ifindex {
            continue;
        }
        // Protocol filter.
        if sock.protocol != ETH_P_ALL && sock.protocol != ethertype {
            continue;
        }
        let raw = RawFrame {
            ifindex,
            frame: frame.to_vec(),
        };
        let mut q = sock.rx_queue.lock();
        if q.len() < sock.max_depth {
            q.push_back(raw);
        }
        // Overflow: drop-newest (opposite of UDP drop-oldest).
        // Linux AF_PACKET drops newer frames when the ring is full
        // (af_packet.c:2388 tpacket_rcv → ring full → drop).
    }
}

// ── Tests ──────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_raw_eth_p_all_receives_all_frames() -> TestResult {
    let sock = raw_packet_open(ETH_P_ALL, 0);

    // Build a minimal 14-byte ARP-shaped frame (ethertype=0x0806).
    let mut frame = [0u8; 60];
    frame[0..6].copy_from_slice(&[0xFF; 6]); // dst MAC
    frame[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]); // src MAC
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ethertype

    raw_pkt_deliver(&frame, 1);

    let pkt = raw_packet_recv(&sock);
    raw_packet_close(&sock);

    match pkt {
        Some(p) => {
            if p.frame.len() < 14 || u16::from_be_bytes([p.frame[12], p.frame[13]]) != 0x0806 {
                return TestResult::Fail("frame ethertype wrong");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("ETH_P_ALL socket received nothing"),
    }
}
kernel_test_in!("net/raw", smoke_raw_eth_p_all_receives_all_frames);

fn smoke_raw_ethertype_filter_drops_non_ip() -> TestResult {
    use crate::pkt::ETHERTYPE_IPV4;

    // Open socket filtered to IPv4 only.
    let sock = raw_packet_open(ETHERTYPE_IPV4, 0);

    // Deliver an ARP frame (ethertype=0x0806) — should be filtered out.
    let mut arp_frame = [0u8; 60];
    arp_frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    raw_pkt_deliver(&arp_frame, 1);

    // Deliver an IPv4 frame — should be delivered.
    let mut ip_frame = [0u8; 60];
    ip_frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    raw_pkt_deliver(&ip_frame, 1);

    let pkt1 = raw_packet_recv(&sock);
    let pkt2 = raw_packet_recv(&sock);
    raw_packet_close(&sock);

    // Should have received exactly the IPv4 frame.
    match pkt1 {
        Some(p) => {
            if u16::from_be_bytes([p.frame[12], p.frame[13]]) != ETHERTYPE_IPV4 {
                return TestResult::Fail("filter let non-IP frame through");
            }
        }
        None => return TestResult::Fail("IPv4 frame not delivered to filtered socket"),
    }
    if pkt2.is_some() {
        return TestResult::Fail("extra frame in queue (ARP should have been filtered)");
    }
    TestResult::Pass
}
kernel_test_in!("net/raw", smoke_raw_ethertype_filter_drops_non_ip);
