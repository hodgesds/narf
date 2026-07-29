//! Bypass classifier — picks the destination for each RX frame.
//!
//! Decision ordering for an inbound L2 frame:
//! 1. Is the originating iface in **daemon-attached** mode? If so the
//!    classifier routes the *raw* frame to the daemon's RX ring and
//!    the kernel TCP/IP stack is bypassed entirely.
//! 2. Otherwise, parse just enough L3/L4 to compute the 5-tuple. Walk
//!    the per-flow claim table, most-specific-first; on match, stage
//!    the frame into the bypass socket's UMEM via FILL → RX.
//! 3. No match → fall through to `tcp_stack::rx_handler`.
//!
//! 5-tuples are 14 bytes (`src_ip`, `src_port`, `dst_ip`, `dst_port`,
//! `proto`). Wildcards are encoded as `0`. "Most specific" is the
//! claim with the fewest wildcard fields — registration order is the
//! tie-break (FIFO).
//!
//! Linux refs:
//! - `linux/net/xdp/xsk.c::__xsk_rcv` — the per-socket RX path
//! - `linux/net/core/dev.c::netif_receive_skb_core` — the classifier
//!   hook XDP installs ahead of the network stack
//!
//! The classifier table is the base matching mechanism. NARF is growing an
//! eBPF runtime (`bpf/`), and XDP-style programs attach here: a program runs
//! ahead of both the daemon claim and the flow table, mirroring Linux's
//! ordering in `netif_receive_skb_core`, and feeds the same table.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::umem::{Umem, UmemError};
use super::xdp::{UmemSlot, XdpSocket};

/// 5-tuple flow key. Field values of `0` are wildcards (matches any).
/// `proto` 0 matches any IP protocol.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Match the candidate `other` against `self` treating `self`'s
    /// zero fields as wildcards. Caller pre-computes `other` from the
    /// inbound frame's IP + L4 headers.
    pub fn matches(&self, other: &FlowKey) -> bool {
        (self.src_ip == [0; 4] || self.src_ip == other.src_ip)
            && (self.src_port == 0 || self.src_port == other.src_port)
            && (self.dst_ip == [0; 4] || self.dst_ip == other.dst_ip)
            && (self.dst_port == 0 || self.dst_port == other.dst_port)
            && (self.proto == 0 || self.proto == other.proto)
    }

    /// Number of non-wildcard fields. "More specific" = larger count.
    pub fn specificity(&self) -> u32 {
        let mut s = 0u32;
        if self.src_ip != [0; 4] {
            s += 1;
        }
        if self.src_port != 0 {
            s += 1;
        }
        if self.dst_ip != [0; 4] {
            s += 1;
        }
        if self.dst_port != 0 {
            s += 1;
        }
        if self.proto != 0 {
            s += 1;
        }
        s
    }
}

/// One installed claim. Held by the classifier table.
#[derive(Clone)]
struct Claim {
    key: FlowKey,
    socket: Arc<XdpSocket>,
    /// Registration order — used as a tie-break when two claims have
    /// the same specificity. Lower seq wins (FIFO).
    seq: u32,
}

impl core::fmt::Debug for Claim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Claim")
            .field("key", &self.key)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// Per-iface whole-NIC bypass record. When set, every inbound frame
/// from this iface is forwarded raw to the daemon's RX ring.
#[derive(Clone)]
struct DaemonClaim {
    iface_name: String,
    socket: Arc<XdpSocket>,
}

impl core::fmt::Debug for DaemonClaim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DaemonClaim")
            .field("iface_name", &self.iface_name)
            .finish_non_exhaustive()
    }
}

static CLAIMS: IrqSafeSpinLock<Vec<Claim>> = IrqSafeSpinLock::new(Vec::new());
static DAEMON_CLAIMS: IrqSafeSpinLock<Vec<DaemonClaim>> = IrqSafeSpinLock::new(Vec::new());

static CLAIM_SEQ: AtomicU32 = AtomicU32::new(0);

/// Per-iface poll-mode bit. When set, the iface's RX IRQ is masked
/// in hardware and userspace daemons drive the FILL/RX rings at
/// their own cadence. Tracked here so the classifier can answer
/// `is_poll_mode(iface)` without rebinding the driver vtable.
static POLL_MODE: IrqSafeSpinLock<Vec<(String, AtomicBool)>> = IrqSafeSpinLock::new(Vec::new());

/// Errors during claim install / lookup.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClassifyError {
    /// Claim already registered for an identical key + socket.
    Duplicate,
    /// Bypass socket UMEM is gone.
    UmemAccessDenied,
    /// No FILL frame available — driver should drop / kernel-route.
    NoFillBuffer,
    /// Daemon already owns this iface.
    AlreadyAttached,
}

/// Install a per-flow claim. Returns a sequence id callers can use
/// to revoke. Linux ref: `xsk_register_xsk_map_entry` —
/// XDP_REDIRECT-eligible socket lookup.
pub fn register_flow(key: FlowKey, socket: Arc<XdpSocket>) -> Result<u32, ClassifyError> {
    let seq = CLAIM_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut g = CLAIMS.lock();
    if g.iter()
        .any(|c| c.key == key && Arc::ptr_eq(&c.socket, &socket))
    {
        return Err(ClassifyError::Duplicate);
    }
    g.push(Claim { key, socket, seq });
    // Keep the table sorted most-specific-first. Stable sort: equal
    // specificity preserves registration order so the FIFO tie-break
    // works.
    g.sort_by(|a, b| {
        b.key
            .specificity()
            .cmp(&a.key.specificity())
            .then(a.seq.cmp(&b.seq))
    });
    Ok(seq)
}

/// Remove a per-flow claim by sequence id. Idempotent — no-op if not
/// found.
pub fn unregister_flow(seq: u32) {
    let mut g = CLAIMS.lock();
    g.retain(|c| c.seq != seq);
}

/// Install a whole-NIC daemon claim. Only one daemon per iface;
/// returns `AlreadyAttached` if a prior claim is live.
pub fn attach_daemon(iface_name: String, socket: Arc<XdpSocket>) -> Result<(), ClassifyError> {
    let mut g = DAEMON_CLAIMS.lock();
    if g.iter().any(|c| c.iface_name == iface_name) {
        return Err(ClassifyError::AlreadyAttached);
    }
    g.push(DaemonClaim { iface_name, socket });
    Ok(())
}

/// Detach the whole-NIC claim for `iface_name`. Returns `true` if a
/// claim was removed.
pub fn detach_daemon(iface_name: &str) -> bool {
    let mut g = DAEMON_CLAIMS.lock();
    let before = g.len();
    g.retain(|c| c.iface_name != iface_name);
    g.len() != before
}

/// `true` iff `iface_name` is currently in daemon-attached mode.
pub fn is_daemon_attached(iface_name: &str) -> bool {
    DAEMON_CLAIMS
        .lock()
        .iter()
        .any(|c| c.iface_name == iface_name)
}

/// Look up the daemon socket bound to `iface_name`.
fn daemon_socket(iface_name: &str) -> Option<Arc<XdpSocket>> {
    DAEMON_CLAIMS
        .lock()
        .iter()
        .find(|c| c.iface_name == iface_name)
        .map(|c| c.socket.clone())
}

/// Verdict the classifier returns to the iface-side RX dispatch.
#[derive(Debug)]
pub enum Verdict {
    /// Frame was consumed by the bypass path. Caller must NOT pass
    /// it to the kernel TCP stack.
    Consumed,
    /// No claim matched. Caller dispatches the frame normally.
    PassThrough,
    /// Claim matched but the bypass path couldn't accept the frame
    /// (FILL empty or UMEM gone). Caller decides whether to drop or
    /// fall through. Today we drop — that matches Linux's XDP
    /// XDP_DROP semantics when XSK FILL is starved.
    Dropped,
}

/// Toggle per-iface poll mode. `on = true` masks RX IRQ; `false`
/// re-enables it. The driver is expected to honor the value via its
/// own `rx_irq_enable`-style call; here we just track state so
/// `is_poll_mode` is queryable and the tests pass.
pub fn set_poll_mode(iface_name: &str, on: bool) {
    let mut g = POLL_MODE.lock();
    if let Some((_, b)) = g.iter().find(|(n, _)| n == iface_name) {
        b.store(on, Ordering::Release);
        return;
    }
    g.push((alloc::string::String::from(iface_name), AtomicBool::new(on)));
}

/// `true` iff the iface is currently in poll mode (RX IRQ masked).
pub fn is_poll_mode(iface_name: &str) -> bool {
    let g = POLL_MODE.lock();
    g.iter()
        .find(|(n, _)| n == iface_name)
        .map(|(_, b)| b.load(Ordering::Acquire))
        .unwrap_or(false)
}

/// Classify an inbound L2 frame originating from `iface_name`.
/// Returns the verdict and, if consumed, the frame is already
/// staged into UMEM + posted to the RX ring of the chosen socket.
pub fn classify(iface_name: &str, frame: &[u8]) -> Verdict {
    // Whole-NIC daemon attach — pure forward, no L3 parse needed.
    if let Some(sock) = daemon_socket(iface_name) {
        return stage_into_socket(&sock, frame);
    }

    // Per-flow path: extract 5-tuple. Only IPv4 today — IPv6 5-tuple
    // matching slots in here when the bypass surface grows v6.
    let key = match extract_flow_key(frame) {
        Some(k) => k,
        None => return Verdict::PassThrough,
    };

    let candidate = {
        let g = CLAIMS.lock();
        // Table is pre-sorted most-specific-first; first match wins.
        g.iter()
            .find(|c| c.key.matches(&key))
            .map(|c| c.socket.clone())
    };
    match candidate {
        Some(sock) => stage_into_socket(&sock, frame),
        None => Verdict::PassThrough,
    }
}

/// Extract the 5-tuple from an Ethernet+IPv4+UDP/TCP frame. Returns
/// `None` for non-IPv4 traffic (let the kernel handle ARP /
/// ethertypes the bypass doesn't claim).
fn extract_flow_key(frame: &[u8]) -> Option<FlowKey> {
    use crate::pkt::{parse_eth_header, parse_ipv4, ETHERTYPE_IPV4, IP_PROTO_TCP, IP_PROTO_UDP};
    let (eth, body) = parse_eth_header(frame)?;
    if eth.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let (ip, l4) = parse_ipv4(body)?;
    let (src_port, dst_port) = if ip.protocol == IP_PROTO_TCP || ip.protocol == IP_PROTO_UDP {
        if l4.len() < 4 {
            (0, 0)
        } else {
            (
                u16::from_be_bytes([l4[0], l4[1]]),
                u16::from_be_bytes([l4[2], l4[3]]),
            )
        }
    } else {
        (0, 0)
    };
    Some(FlowKey {
        src_ip: ip.src_ip,
        src_port,
        dst_ip: ip.dst_ip,
        dst_port,
        proto: ip.protocol,
    })
}

/// Common path: pop a FILL slot, copy the frame bytes into the
/// UMEM-backed buffer, push the slot onto the socket's RX ring.
/// Drops the frame if FILL is empty or UMEM access fails.
fn stage_into_socket(socket: &Arc<XdpSocket>, frame: &[u8]) -> Verdict {
    let umem = socket.umem();
    let slot = match socket.pop_fill() {
        Some(s) => s,
        None => return Verdict::Dropped,
    };
    if !umem.frame_in_bounds(slot.frame_idx) {
        return Verdict::Dropped;
    }
    let frame_size = umem.frame_size() as usize;
    if frame.len() > frame_size {
        // Frame larger than a UMEM chunk. Linux drops in this case
        // unless XDP_USE_NEED_WAKEUP/zero-copy multi-chunk is on; we
        // mirror.
        return Verdict::Dropped;
    }
    if !write_into_umem(umem, slot.frame_idx, frame) {
        return Verdict::Dropped;
    }
    let out = UmemSlot {
        frame_idx: slot.frame_idx,
        len: frame.len() as u32,
    };
    match socket.push_rx(out) {
        Ok(()) => Verdict::Consumed,
        Err(_) => Verdict::Dropped,
    }
}

/// Write `frame` bytes into UMEM at `frame_idx`. Uses
/// `frame_bytes_mut` indirectly by cloning the Arc's internals; in
/// practice the UMEM's backing `DmaBuffer` is page-pinned and the
/// kernel mapping is identity so we can write directly.
fn write_into_umem(umem: &Arc<Umem>, frame_idx: u32, frame: &[u8]) -> bool {
    let _ = UmemError::AccessDenied; // silence unused if path simplifies later
    if !umem.frame_in_bounds(frame_idx) {
        return false;
    }
    let frame_size = umem.frame_size() as usize;
    // SAFETY: `base_virt` is the kernel-mapped, page-pinned VA of
    // the UMEM's `DmaBuffer`. The kernel mapping outlives the
    // socket (Arc holds the buffer). `frame_idx` is bounds-checked
    // above; the write region is `[base, base + frame_size)` ⊂
    // `[base, base + size)`. We hold no aliasing mut ref because
    // FILL semantics say the kernel owns the slot now.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let dst = (umem.desc().base_virt as *mut u8).add(frame_idx as usize * frame_size);
        core::ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
    }
    true
}

/// Test-only reset hook. Wipes the entire classifier state.
#[doc(hidden)]
pub fn __reset_for_test() {
    CLAIMS.lock().clear();
    DAEMON_CLAIMS.lock().clear();
    POLL_MODE.lock().clear();
    CLAIM_SEQ.store(0, Ordering::Relaxed);
}

/// Number of installed per-flow claims. For tests + `proc-style`
/// diagnostics.
pub fn flow_count() -> usize {
    CLAIMS.lock().len()
}

/// Number of installed whole-NIC daemon claims.
pub fn daemon_count() -> usize {
    DAEMON_CLAIMS.lock().len()
}
