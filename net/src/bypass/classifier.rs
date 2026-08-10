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
//! The classifier table is the base matching mechanism, and XDP-style eBPF
//! programs attach ahead of it — see [`install_xdp`]. A program runs before both
//! the daemon claim and the flow table, mirroring Linux's ordering in
//! `netif_receive_skb_core`.
//!
//! The attached surface is **writable and resizable**. It offers `Pass`/`Drop`,
//! in-place **header rewrite** (a bounds-checked store through the packet's
//! `data` pointer), **frame resizing** (`bpf_xdp_adjust_head`/`_tail` move
//! `data`/`data_end` to trim or grow the packet), plus frame *retransmission* —
//! `XDP_TX` (reflect out the ingress iface) and `XDP_REDIRECT` (send out a named
//! iface) — of the **possibly-modified, possibly-resized** frame.
//! [`XdpProgram::run`] takes `&mut [u8]` and returns `(action, len)`: `len` is
//! the resulting `[data, data_end)` length, and the packet occupies
//! `frame[..len]`. The `&mut` slice is threaded from `iface::RxHandler` through
//! each driver's RX path (virtio-net / e1000 hand over a `&mut` borrow of their
//! DMA/scratch buffer); the resize is staged in `narf-bpf` and only the length
//! crosses this seam. That is a real bump-in-the-wire capability — inspect,
//! rewrite, resize, reflect, forward — reachable without a userspace daemon.
//!
//! `XDP_REDIRECT` also drives a devmap/cpumap (`bpf_redirect_map`): a single
//! interface, a CPU's local stack, or — with `BPF_F_BROADCAST` — a fan-out to
//! every live devmap port (optionally excluding the ingress iface).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_capabilities::{Cap, CapType, Grant};
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
    /// The capability presented for an XDP attach was revoked.
    CapRevoked,
    /// The capability presented for an XDP attach was of the wrong *kind*.
    ///
    /// Liveness and kind are independent questions, and checking only the first
    /// let any live grant of any kind install an XDP program.
    WrongCapKind,
    /// The program's execution context does not match what this hook provides.
    ///
    /// An XDP hook is `Atomic`; a program verified for `Sleepable` cannot run
    /// here, and installing one anyway made the interface fail open.
    WrongContext,
}

/// The capability kind an XDP attach/detach requires.
///
/// Split out so `install_xdp` and `remove_xdp` cannot disagree about it, and
/// checked *before* liveness because a wrong-kind capability is a programming
/// error rather than an expired authority.
///
/// This check was missing entirely: both entry points were generic over
/// `M: CapType` and only called `check_live()`, so **any** live grant of **any**
/// kind authorised replacing an interface's XDP program. `structops::install`
/// gets this right (`M::KIND != desc.cap`), one module over.
fn require_attach_cap<M: CapType>() -> Result<(), ClassifyError> {
    if M::KIND != narf_capabilities::CapKind::BpfAttach {
        return Err(ClassifyError::WrongCapKind);
    }
    Ok(())
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
#[derive(Debug, PartialEq, Eq)]
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
    /// `XDP_TX`: retransmit the (possibly-rewritten) frame back out the ingress
    /// interface. The caller sends after the `XDP_PROGS` lock is released —
    /// [`run_xdp`] deliberately does not transmit while it holds the lock with
    /// IRQs masked.
    Transmit,
    /// `XDP_REDIRECT`: send the (possibly-rewritten) frame out the interface
    /// named by `ifindex`. Same as [`Verdict::Transmit`] but out a
    /// program-chosen NIC; the caller resolves the ifindex and transmits after
    /// the lock is released.
    Redirect { ifindex: u32 },
    /// `XDP_REDIRECT` with `BPF_F_BROADCAST`: fan the (possibly-rewritten) frame
    /// out to every port a devmap named. Same as [`Verdict::Redirect`] but to a
    /// *set* of NICs; the caller drains the staged port list with
    /// [`take_xdp_broadcast`] and sends to each after the lock is released,
    /// skipping the ingress iface when the program asked to exclude it.
    Broadcast,
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

// ── XDP program attach ──────────────────────────────────────────────

/// An eBPF program attached ahead of the bypass table.
///
/// The seam this module's header has named since it was written. Implemented by
/// `narf-bpf`; declared here so `narf-net` keeps no dependency on the BPF
/// subsystem, which is the same shape `PLUGGABILITY.md` uses everywhere else.
///
/// **Writable and resizable.** [`Self::run`] takes `&mut [u8]`, so a program may
/// rewrite header bytes in place (a store through the packet's `data` pointer,
/// bounds-checked against `data_end` by the verifier and again by the
/// interpreter) and resize the frame (`bpf_xdp_adjust_head`/`_tail`). It returns
/// `(action, len)`: the resulting packet is `frame[..len]`, which `XDP_TX` and
/// `XDP_REDIRECT` retransmit — reflect out the ingress iface, forward out a
/// program-chosen one (`bpf_redirect`/devmap), or deliver to the local stack
/// (cpumap, see [`XdpAction::RedirectCpu`]). What is *not* yet supported is
/// `BPF_F_BROADCAST` fan-out (one frame to many ports), which is deferred.
pub trait XdpProgram: Send + Sync + 'static {
    /// A name, for diagnostics.
    fn name(&self) -> &str;
    /// Decide the frame's fate and report the resulting packet length. Must not
    /// block.
    ///
    /// `frame` is `&mut`: the program may rewrite header bytes in place
    /// (bounds-checked against `data_end` by the BPF verifier + runtime), and may
    /// *resize* the frame with `bpf_xdp_adjust_head`/`_tail`. The returned length
    /// is the effective `[data, data_end)` window after the run, and the packet
    /// bytes occupy `frame[..len]` — that is what an ensuing `XDP_TX`/
    /// `XDP_REDIRECT` retransmits and what the kernel stack sees on `Pass`. A
    /// program that only rewrites bytes (or does nothing) returns `frame.len()`.
    /// `len` never exceeds `frame.len()`.
    fn run(&self, iface: &str, frame: &mut [u8]) -> (XdpAction, usize);
}

/// What an [`XdpProgram`] decided.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XdpAction {
    /// Continue to the bypass table and then the kernel stack.
    Pass,
    /// Discard the frame.
    Drop,
    /// The program failed. Treated as [`XdpAction::Drop`] and counted
    /// separately, matching Linux's `XDP_ABORTED`, so a broken program is
    /// visible rather than merely quiet.
    Aborted,
    /// `XDP_TX`: reflect the (possibly-rewritten) frame back out the ingress
    /// iface.
    Tx,
    /// `XDP_REDIRECT`: send the (possibly-rewritten) frame out interface
    /// `ifindex`. The ifindex is the value a `bpf_redirect` kfunc stashed for
    /// this frame.
    Redirect { ifindex: u32 },
    /// `XDP_REDIRECT` into a cpumap: deliver the (possibly-rewritten) frame to
    /// CPU `cpu`'s network stack. NARF has one RX-processing context, so this
    /// resolves to *local* delivery — the frame continues up the local stack,
    /// exactly as `Pass` does — and `cpu` is carried for fidelity/diagnostics.
    /// Cross-CPU steering is the documented degradation.
    RedirectCpu { cpu: u32 },
    /// `XDP_REDIRECT` with `BPF_F_BROADCAST`: fan the (possibly-rewritten) frame
    /// out to every port a devmap named. The port list and the exclude-ingress
    /// flag were staged into this CPU's buffer by [`stage_xdp_broadcast`]; the
    /// caller drains them with [`take_xdp_broadcast`] and sends after the
    /// `XDP_PROGS` lock is released, like the other retransmit verdicts.
    Broadcast,
}

type XdpSlot = (alloc::string::String, alloc::boxed::Box<dyn XdpProgram>);
static XDP_PROGS: IrqSafeSpinLock<Vec<XdpSlot>> = IrqSafeSpinLock::new(Vec::new());
static XDP_ABORTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Whether *any* program is attached, so the RX path can skip the lock
/// entirely when none is. Relaxed: a frame racing an attach may take either
/// answer, which is the same latitude the daemon and flow tables already have.
static XDP_ANY: AtomicBool = AtomicBool::new(false);
static XDP_DROPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Frames a program asked to retransmit (`XDP_TX` + `XDP_REDIRECT`). Counted at
/// the *decision*, so a subsequent driver send failure does not un-count it —
/// the counter reflects program intent, and `XDP_TX_DROPS` records the send
/// failures separately.
static XDP_TXS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Retransmit requests (`XDP_TX`/`XDP_REDIRECT`) the caller could not send —
/// unknown target iface, or the driver's send returned `Err`. The frame is
/// dropped in that case, matching Linux, where a redirect to a down/absent
/// device is a drop.
static XDP_TX_DROPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Frames a program redirected into a cpumap. On NARF's single RX-processing
/// context these are delivered to the local stack (the target CPU is us), so
/// they are counted here rather than under `XDP_TXS`, which is retransmission
/// out a device.
static XDP_CPU_REDIRECTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Frames a program broadcast (`BPF_F_BROADCAST`) out a devmap's ports. Counted
/// once per broadcast *decision*, not once per port sent.
static XDP_BROADCASTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The most ports a single `BPF_F_BROADCAST` fans out to here — matches the
/// BPF side's `MAX_BROADCAST_PORTS`, which caps how many the staging call ever
/// passes. A fixed size keeps the per-CPU buffer allocation-free.
pub const MAX_XDP_BROADCAST_PORTS: usize = 16;

/// Per-CPU staging for a pending `BPF_F_BROADCAST`: the devmap ports and the
/// exclude-ingress flag. Written by [`stage_xdp_broadcast`] while the BPF side
/// holds `XDP_PROGS` (IRQs masked), drained by [`take_xdp_broadcast`] in the
/// same `rx_handler` call on the same CPU — the same discipline as the BPF-side
/// redirect slot, and safe because NARF drains RX one frame at a time in a
/// cooperative poll loop rather than by nested `rx_handler` re-entry.
static XDP_BCAST_PORTS: [[AtomicU32; MAX_XDP_BROADCAST_PORTS]; narf_lib::percpu::MAX_CPUS] =
    [const { [const { AtomicU32::new(0) }; MAX_XDP_BROADCAST_PORTS] }; narf_lib::percpu::MAX_CPUS];
/// Companion to [`XDP_BCAST_PORTS`]: the low 16 bits hold the staged port count,
/// bit 16 the exclude-ingress flag.
static XDP_BCAST_META: [AtomicU32; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; narf_lib::percpu::MAX_CPUS];
/// Bit in [`XDP_BCAST_META`] marking `BPF_F_EXCLUDE_INGRESS`.
const XDP_BCAST_EXCLUDE_INGRESS_BIT: u32 = 1 << 16;

/// Stage the ports a `BPF_F_BROADCAST` will fan out to on this CPU, plus whether
/// to skip the ingress iface. Called by the BPF `attach_xdp` bridge while it
/// holds `XDP_PROGS`; [`take_xdp_broadcast`] reads it back in the same
/// `rx_handler` call.
pub fn stage_xdp_broadcast(ports: &[u32], exclude_ingress: bool) {
    let cpu = narf_lib::percpu::current_cpu();
    let n = ports.len().min(MAX_XDP_BROADCAST_PORTS);
    for (slot, &ifindex) in XDP_BCAST_PORTS[cpu].iter().zip(&ports[..n]) {
        slot.store(ifindex, Ordering::Relaxed);
    }
    let mut meta = n as u32;
    if exclude_ingress {
        meta |= XDP_BCAST_EXCLUDE_INGRESS_BIT;
    }
    XDP_BCAST_META[cpu].store(meta, Ordering::Relaxed);
}

/// Drain this CPU's staged broadcast ports into `out`, returning
/// `(count, exclude_ingress)`. `count` is `min(staged, out.len())`. Read once,
/// right after a [`Verdict::Broadcast`], on the same CPU.
#[must_use]
pub fn take_xdp_broadcast(out: &mut [u32]) -> (usize, bool) {
    let cpu = narf_lib::percpu::current_cpu();
    let meta = XDP_BCAST_META[cpu].swap(0, Ordering::Relaxed);
    let staged = (meta & 0xFFFF) as usize;
    let n = staged.min(out.len()).min(MAX_XDP_BROADCAST_PORTS);
    for (dst, slot) in out[..n].iter_mut().zip(&XDP_BCAST_PORTS[cpu]) {
        *dst = slot.load(Ordering::Relaxed);
    }
    (n, meta & XDP_BCAST_EXCLUDE_INGRESS_BIT != 0)
}

/// Attach `prog` to `iface`, replacing any program already there.
///
/// # Errors
///
/// [`ClassifyError::CapRevoked`] if the capability is not live.
pub fn install_xdp<M: CapType>(
    cap: &Cap<M, Grant>,
    iface: alloc::string::String,
    prog: alloc::boxed::Box<dyn XdpProgram>,
) -> Result<(), ClassifyError> {
    require_attach_cap::<M>()?;
    cap.check_live().map_err(|_| ClassifyError::CapRevoked)?;
    let mut g = XDP_PROGS.lock();
    g.retain(|(n, _)| *n != iface);
    g.push((iface, prog));
    XDP_ANY.store(true, Ordering::Release);
    Ok(())
}

/// Detach any program on `iface`. Returns whether one was removed.
pub fn remove_xdp<M: CapType>(cap: &Cap<M, Grant>, iface: &str) -> Result<bool, ClassifyError> {
    require_attach_cap::<M>()?;
    cap.check_live().map_err(|_| ClassifyError::CapRevoked)?;
    let mut g = XDP_PROGS.lock();
    let before = g.len();
    g.retain(|(n, _)| n != iface);
    XDP_ANY.store(!g.is_empty(), Ordering::Release);
    Ok(g.len() != before)
}

/// (drops, aborts) attributed to XDP programs.
#[must_use]
pub fn xdp_stats() -> (u64, u64) {
    (
        XDP_DROPS.load(Ordering::Relaxed),
        XDP_ABORTS.load(Ordering::Relaxed),
    )
}

/// (retransmit requests, retransmit send failures) attributed to XDP programs.
/// The first counts `XDP_TX` + `XDP_REDIRECT` decisions; the second counts
/// those the caller could not actually send (unknown iface or driver `Err`).
#[must_use]
pub fn xdp_tx_stats() -> (u64, u64) {
    (
        XDP_TXS.load(Ordering::Relaxed),
        XDP_TX_DROPS.load(Ordering::Relaxed),
    )
}

/// Record that a retransmit verdict (`Transmit`/`Redirect`) could not be sent.
/// The `tcp_stack` RX path calls this after a failed `iface::send_on` so a
/// redirect to a down/absent device is visible as a drop rather than silent.
pub fn count_xdp_tx_drop() {
    XDP_TX_DROPS.fetch_add(1, Ordering::Relaxed);
}

/// Frames a program redirected into a cpumap, delivered to the local stack.
#[must_use]
pub fn xdp_cpu_redirects() -> u64 {
    XDP_CPU_REDIRECTS.load(Ordering::Relaxed)
}

/// Frames a program broadcast out a devmap's ports (`BPF_F_BROADCAST`).
#[must_use]
pub fn xdp_broadcasts() -> u64 {
    XDP_BROADCASTS.load(Ordering::Relaxed)
}

/// Run the attached program, if any.
///
/// **The program runs while `XDP_PROGS` is held**, and with interrupts masked
/// for that duration — `IrqSafeSpinLock` masks them for the guard's lifetime.
/// An earlier version of this doc claimed the opposite of the body three lines
/// below it, which is worse than no comment.
///
/// Two consequences, both real:
///
/// * A program that reached back into this module would deadlock on a
///   non-reentrant lock. Safe only because the kfunc set is closed and audited
///   and contains nothing that does — switch to `Arc` (the change
///   `tracing::dispatch::fire` made) *before* widening it, not after.
/// * Fuel bounds a program's *work*, not its *time*. With interrupts masked,
///   a frame can spend up to `DEFAULT_FUEL` interpreted instructions with IRQs
///   off. That is a latency characteristic of attaching a program at all, not
///   something this function can fix; recorded in `bpf/specification/spec.md`
///   §8 rather than left for someone to discover from a jitter graph.
fn run_xdp(iface: &str, frame: &mut [u8]) -> (XdpAction, usize) {
    // Fast path for the overwhelmingly common case: nothing attached. Without
    // this, every RX frame paid an IRQ-save, a `lock cmpxchg`, and a linear
    // `String == &str` scan before the existing daemon and flow-table locks —
    // roughly a third more locking on the bypass path for a feature that is
    // off. `POLL_MODE` next door already uses this shape.
    if !XDP_ANY.load(Ordering::Relaxed) {
        return (XdpAction::Pass, frame.len());
    }
    // The program runs while `XDP_PROGS` is held. That is a deliberate,
    // recorded limitation rather than an oversight: `Box<dyn XdpProgram>` is
    // not clonable, so releasing the lock first would need an `Arc` — exactly
    // the change `tracing::dispatch::fire` made for the same reason. It is safe
    // only because the kfunc set a program can reach is closed and audited and
    // contains nothing that re-enters this module. If that ever stops being
    // true, this deadlocks on a non-reentrant lock, so switch to `Arc` before
    // widening the kfunc set rather than after.
    let (action, len) = {
        let g = XDP_PROGS.lock();
        match g.iter().find(|(n, _)| n == iface) {
            Some((_, p)) => p.run(iface, frame),
            None => return (XdpAction::Pass, frame.len()),
        }
    };
    match action {
        XdpAction::Drop => {
            XDP_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        XdpAction::Aborted => {
            XDP_ABORTS.fetch_add(1, Ordering::Relaxed);
        }
        XdpAction::Tx | XdpAction::Redirect { .. } => {
            XDP_TXS.fetch_add(1, Ordering::Relaxed);
        }
        XdpAction::RedirectCpu { .. } => {
            XDP_CPU_REDIRECTS.fetch_add(1, Ordering::Relaxed);
        }
        XdpAction::Broadcast => {
            XDP_BROADCASTS.fetch_add(1, Ordering::Relaxed);
        }
        XdpAction::Pass => {}
    }
    // A resizing program can only deliver up to the caller frame's length; the
    // run path already bounds the copy-back, so this is belt to that brace.
    (action, len.min(frame.len()))
}

/// Classify an inbound L2 frame originating from `iface_name`.
///
/// Returns the verdict and the effective packet length after any XDP program
/// ran: an attached program may resize the frame (`bpf_xdp_adjust_head`/`_tail`),
/// so the live packet is `frame[..len]`, which is what every path below — the
/// daemon/flow bypass, and the caller's `Pass`/`Transmit`/`Redirect` handling —
/// must use. On a `Consumed` verdict the frame is already staged into UMEM +
/// posted to the RX ring of the chosen socket. `len` never exceeds `frame.len()`.
pub fn classify(iface_name: &str, frame: &mut [u8]) -> (Verdict, usize) {
    // An XDP program runs first — ahead of the daemon claim and the flow
    // table, mirroring Linux, where XDP sits in front of everything in
    // `netif_receive_skb_core`. It takes the frame `&mut` (in-place header
    // rewrite and/or resize); once it returns, every path below re-borrows
    // immutably over the resulting `frame[..len]` window and so sees the
    // possibly-modified, possibly-resized bytes.
    let len = match run_xdp(iface_name, &mut *frame) {
        (XdpAction::Drop | XdpAction::Aborted, _) => return (Verdict::Dropped, 0),
        // Retransmit verdicts return to the caller unconsumed by the bypass
        // table: the caller sends the frame after `XDP_PROGS` is released, so
        // no transmit happens with IRQs masked. The frame does NOT continue to
        // the daemon/flow table or the kernel stack.
        (XdpAction::Tx, len) => return (Verdict::Transmit, len),
        (XdpAction::Redirect { ifindex }, len) => return (Verdict::Redirect { ifindex }, len),
        // A devmap broadcast fans out to a set of NICs after the lock releases,
        // the same deferral `Transmit`/`Redirect` use; the ports are already
        // staged for the caller to drain.
        (XdpAction::Broadcast, len) => return (Verdict::Broadcast, len),
        // A cpumap redirect delivers to the local stack — the running CPU is the
        // only RX-processing context — so it continues down this function exactly
        // as `Pass` does, over the possibly-resized `frame[..len]`.
        (XdpAction::Pass | XdpAction::RedirectCpu { .. }, len) => len,
    };
    let packet = &frame[..len];

    // Whole-NIC daemon attach — pure forward, no L3 parse needed.
    if let Some(sock) = daemon_socket(iface_name) {
        return (stage_into_socket(&sock, packet), len);
    }

    // Per-flow path: extract 5-tuple. Only IPv4 today — IPv6 5-tuple
    // matching slots in here when the bypass surface grows v6.
    let key = match extract_flow_key(packet) {
        Some(k) => k,
        None => return (Verdict::PassThrough, len),
    };

    let candidate = {
        let g = CLAIMS.lock();
        // Table is pre-sorted most-specific-first; first match wins.
        g.iter()
            .find(|c| c.key.matches(&key))
            .map(|c| c.socket.clone())
    };
    let verdict = match candidate {
        Some(sock) => stage_into_socket(&sock, packet),
        None => Verdict::PassThrough,
    };
    (verdict, len)
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
