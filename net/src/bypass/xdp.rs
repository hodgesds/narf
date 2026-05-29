//! AF_XDP-equivalent bypass socket — UMEM + four SPSC rings per
//! socket.
//!
//! Linux AF_XDP shape (refs: `linux/net/xdp/xsk.c`,
//! `linux/net/xdp/xsk_queue.h`):
//!
//! ```text
//!  userspace                              kernel / driver
//!  ──────────                              ────────────────
//!  FILL ring (producer)        ─push idx→  driver writes RX into umem[idx]
//!                                          → RX ring (producer)
//!  RX ring (consumer)          ←pop idx─                 ↑
//!  process bytes, return idx                              │
//!  → FILL or recycle to TX                                │
//!                                                         │
//!  TX ring (producer)          ─push idx→  driver DMAs umem[idx]
//!                                          → COMPLETION ring (producer)
//!  COMPLETION (consumer)       ←pop idx─                 ↑
//!  reuse / recycle idx                                    │
//! ```
//!
//! Ownership direction:
//! - FILL: userspace writes, kernel reads.
//! - RX:   kernel writes, userspace reads.
//! - TX:   userspace writes, kernel reads.
//! - COMPLETION: kernel writes, userspace reads.
//!
//! All four are 64-deep SPSC rings — same `narf_ipc::Ring` primitive
//! the iface RX/TX rings use. The slot payload is a
//! [`UmemSlot`] (frame index + length) so a single 8-byte slot per
//! frame keeps the rings cache-friendly.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, CapKind, CapType, Invoke};
use narf_ipc::{channel, Consumer, Producer, Retag};
use narf_lib::sync::IrqSafeSpinLock;

use super::umem::{Umem, UmemRegion};

/// Cap-type marker for the FILL ring half handed to userspace.
#[derive(Debug)]
pub struct FillRing;
impl CapType for FillRing {
    const KIND: CapKind = CapKind::Ring;
}

/// Cap-type marker for the RX ring half handed to userspace.
#[derive(Debug)]
pub struct RxRing;
impl CapType for RxRing {
    const KIND: CapKind = CapKind::Ring;
}

/// Cap-type marker for the TX ring half handed to userspace.
#[derive(Debug)]
pub struct TxRing;
impl CapType for TxRing {
    const KIND: CapKind = CapKind::Ring;
}

/// Cap-type marker for the COMPLETION ring half handed to userspace.
#[derive(Debug)]
pub struct CompletionRing;
impl CapType for CompletionRing {
    const KIND: CapKind = CapKind::Ring;
}

/// SPSC slot payload: frame index into UMEM + used-byte length.
/// Pre-encoded into a single u64 so the ring slot is exactly 8 bytes
/// (matches Linux `xdp_desc` minus the per-driver flags field —
/// flags would land here when NARF grows TSO/checksum offload on the
/// bypass path).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct UmemSlot {
    /// Index of the frame in the UMEM pool.
    pub frame_idx: u32,
    /// Used bytes within the frame (0..frame_size).
    pub len: u32,
}

impl UmemSlot {
    /// Pack into a single 8-byte word.
    #[inline]
    pub const fn pack(self) -> u64 {
        ((self.frame_idx as u64) << 32) | (self.len as u64)
    }

    /// Unpack from a single 8-byte word.
    #[inline]
    pub const fn unpack(v: u64) -> Self {
        Self {
            frame_idx: (v >> 32) as u32,
            len: v as u32,
        }
    }
}

// `UmemSlot` is plain bytes; MTE retag is identity (no pointer
// inside). The default impl of `Retag` does the right thing.
impl Retag for UmemSlot {}

/// Default ring depth per bypass socket. 64 matches the iface
/// frame-ring depth and the typical AF_XDP default. Doubled per
/// direction lets userspace pipeline FILL → RX without immediately
/// stalling the driver. `pub const` so tests and the userspace
/// socket can refer to one symbol.
pub const XDP_RING_N: usize = 64;

/// XDP-socket-side bind error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XdpError {
    /// UMEM cap presented at bind/poll is revoked or wrong-region.
    UmemAccessDenied,
    /// Bind target iface name not found in the registry.
    InvalidIface,
    /// Queue id out of range for the iface.
    InvalidQueue,
    /// Socket already bound; rebind not supported.
    AlreadyBound,
    /// Frame index in the FILL/TX ring is out of range for UMEM.
    InvalidFrameIndex,
    /// Ring full / empty.
    RingFull,
    RingEmpty,
}

/// The kernel-side view of an AF_BYPASS socket. Owns the *kernel*
/// halves of all four SPSC rings; the *user* halves were handed to
/// the daemon at socket-create time wrapped in
/// `Cap<{Fill,Rx,Tx,Completion}Ring, Invoke>`.
///
/// Lock layout: each ring half lives behind its own
/// `IrqSafeSpinLock<Option<…>>` — the classifier uses the RX
/// producer in IRQ context, the TX path uses the TX consumer in the
/// driver's send pump, and the daemon may rebind at any time.
pub struct XdpSocket {
    umem: Arc<Umem>,
    iface_name: IrqSafeSpinLock<Option<alloc::string::String>>,
    queue_id: core::sync::atomic::AtomicU32,
    bound: AtomicBool,
    /// FILL ring consumer — kernel pops indices userspace posted.
    fill_cons: IrqSafeSpinLock<Option<Consumer<u64, XDP_RING_N>>>,
    /// RX ring producer — kernel pushes (frame_idx, len) for the
    /// daemon to read.
    rx_prod: IrqSafeSpinLock<Option<Producer<u64, XDP_RING_N>>>,
    /// TX ring consumer — kernel pops indices userspace queued for
    /// transmission.
    tx_cons: IrqSafeSpinLock<Option<Consumer<u64, XDP_RING_N>>>,
    /// COMPLETION ring producer — kernel pushes indices the driver
    /// finished DMAing.
    comp_prod: IrqSafeSpinLock<Option<Producer<u64, XDP_RING_N>>>,
}

/// What `XdpSocket::create` returns to the userspace daemon: the
/// kernel-side socket handle + the four user-side ring halves the
/// daemon will pull frames from / push frames to.
#[derive(Debug)]
pub struct XdpSocketParts {
    /// Kernel-side socket handle. Stored in the bypass socket
    /// registry; cap-gated.
    pub socket: Arc<XdpSocket>,
    pub fill_prod: Producer<u64, XDP_RING_N>,
    pub rx_cons: Consumer<u64, XDP_RING_N>,
    pub tx_prod: Producer<u64, XDP_RING_N>,
    pub comp_cons: Consumer<u64, XDP_RING_N>,
    /// User-side ring caps. The daemon's `setsockopt(XDP_*_RING)`
    /// returns the matching cap so the daemon can name the rings in
    /// later ops.
    pub fill_cap: Cap<FillRing, Invoke>,
    pub rx_cap: Cap<RxRing, Invoke>,
    pub tx_cap: Cap<TxRing, Invoke>,
    pub comp_cap: Cap<CompletionRing, Invoke>,
}

impl XdpSocket {
    /// Create a fresh bypass socket bound to `umem`. The four rings
    /// are paired here; the user halves are returned in
    /// `XdpSocketParts` for the daemon to drive directly through
    /// `narf_ipc` calls.
    ///
    /// Linux ref: `xsk_setsockopt(XDP_UMEM_REG)` +
    /// `XDP_{RX,TX,FILL,COMPLETION}_RING`.
    pub fn create(umem: Arc<Umem>) -> XdpSocketParts {
        let (fill_prod, fill_cons) = channel::<u64, XDP_RING_N>();
        let (rx_prod, rx_cons) = channel::<u64, XDP_RING_N>();
        let (tx_prod, tx_cons) = channel::<u64, XDP_RING_N>();
        let (comp_prod, comp_cons) = channel::<u64, XDP_RING_N>();
        let socket = Arc::new(Self {
            umem,
            iface_name: IrqSafeSpinLock::new(None),
            queue_id: core::sync::atomic::AtomicU32::new(0),
            bound: AtomicBool::new(false),
            fill_cons: IrqSafeSpinLock::new(Some(fill_cons)),
            rx_prod: IrqSafeSpinLock::new(Some(rx_prod)),
            tx_cons: IrqSafeSpinLock::new(Some(tx_cons)),
            comp_prod: IrqSafeSpinLock::new(Some(comp_prod)),
        });
        XdpSocketParts {
            socket,
            fill_prod,
            rx_cons,
            tx_prod,
            comp_cons,
            fill_cap: Cap::<FillRing, Invoke>::bootstrap(),
            rx_cap: Cap::<RxRing, Invoke>::bootstrap(),
            tx_cap: Cap::<TxRing, Invoke>::bootstrap(),
            comp_cap: Cap::<CompletionRing, Invoke>::bootstrap(),
        }
    }

    /// Borrow the UMEM the socket is registered against.
    #[inline]
    pub fn umem(&self) -> &Arc<Umem> {
        &self.umem
    }

    /// Mark the socket as bound to (iface, queue). The classifier
    /// will only route frames here once the bind is observed.
    pub fn bind(&self, iface_name: alloc::string::String, queue_id: u32) -> Result<(), XdpError> {
        if self.bound.load(Ordering::Acquire) {
            return Err(XdpError::AlreadyBound);
        }
        // Verify the iface exists. Per `iface.rs` the registry is
        // single-iface today; lookup by name covers the multi-iface
        // future without changing the bind API.
        crate::iface::lookup(&iface_name).ok_or(XdpError::InvalidIface)?;
        *self.iface_name.lock() = Some(iface_name);
        self.queue_id.store(queue_id, Ordering::Release);
        self.bound.store(true, Ordering::Release);
        Ok(())
    }

    /// Currently bound iface name, if any.
    pub fn bound_iface(&self) -> Option<alloc::string::String> {
        self.iface_name.lock().clone()
    }

    /// `true` after `bind` succeeds.
    pub fn is_bound(&self) -> bool {
        self.bound.load(Ordering::Acquire)
    }

    /// Queue id the socket is bound to (0 if not bound).
    pub fn queue_id(&self) -> u32 {
        self.queue_id.load(Ordering::Acquire)
    }

    /// Kernel-side: pop a free FILL slot the daemon posted. Used by
    /// the classifier to take a buffer before staging an RX frame
    /// into UMEM. Returns `None` if FILL is empty (driver should
    /// stash the frame elsewhere — in the kernel today that means
    /// drop).
    pub fn pop_fill(&self) -> Option<UmemSlot> {
        let mut g = self.fill_cons.lock();
        let cons = g.as_mut()?;
        match cons.try_recv() {
            Ok(Some(v)) => Some(UmemSlot::unpack(v)),
            _ => None,
        }
    }

    /// Kernel-side: push an RX entry to the daemon. Called by the
    /// classifier after staging the frame bytes into UMEM. Returns
    /// `Err(RingFull)` on backpressure — the caller is expected to
    /// recycle the slot back into FILL.
    pub fn push_rx(&self, slot: UmemSlot) -> Result<(), XdpError> {
        let mut g = self.rx_prod.lock();
        let prod = g.as_mut().ok_or(XdpError::RingFull)?;
        prod.try_send(slot.pack()).map_err(|_| XdpError::RingFull)
    }

    /// Kernel-side: pop a TX entry the daemon queued. Used by the
    /// driver's send pump.
    pub fn pop_tx(&self) -> Option<UmemSlot> {
        let mut g = self.tx_cons.lock();
        let cons = g.as_mut()?;
        match cons.try_recv() {
            Ok(Some(v)) => Some(UmemSlot::unpack(v)),
            _ => None,
        }
    }

    /// Kernel-side: push a COMPLETION entry for a TX frame the
    /// driver finished sending. Returns `Err(RingFull)` if the
    /// daemon's COMPLETION ring is full — caller should park /
    /// retry.
    pub fn push_completion(&self, slot: UmemSlot) -> Result<(), XdpError> {
        let mut g = self.comp_prod.lock();
        let prod = g.as_mut().ok_or(XdpError::RingFull)?;
        prod.try_send(slot.pack()).map_err(|_| XdpError::RingFull)
    }
}

impl core::fmt::Debug for XdpSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XdpSocket")
            .field("bound", &self.bound.load(Ordering::Relaxed))
            .field("queue_id", &self.queue_id.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Authority handle held by the userspace daemon — proves the
/// daemon owns this UMEM region. Returned alongside [`XdpSocketParts`]
/// so callers can plumb it back through later cap-gated ops.
#[derive(Copy, Clone, Debug)]
pub struct XdpAuthority {
    pub umem: Cap<UmemRegion, Invoke>,
    pub fill: Cap<FillRing, Invoke>,
    pub rx: Cap<RxRing, Invoke>,
    pub tx: Cap<TxRing, Invoke>,
    pub comp: Cap<CompletionRing, Invoke>,
}
