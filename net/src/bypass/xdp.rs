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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use narf_capabilities::{Cap, CapKind, CapType, Invoke};
use narf_io::DmaBuffer;
use narf_ipc::{channel, Consumer, Producer, Retag};
use narf_lib::id::DomainId;
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

/// Standard Linux `AF_XDP` `mmap(2)` page offsets (`include/uapi/linux/if_xdp.h`).
pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

/// Byte offsets within each 4096-byte shared AF_XDP ring page.
pub const XDP_RING_PRODUCER_OFF: usize = 0;
pub const XDP_RING_CONSUMER_OFF: usize = 128;
pub const XDP_RING_FLAGS_OFF: usize = 256;
pub const XDP_RING_DESC_OFF: usize = 384;

/// Linux `struct xdp_desc` layout for RX and TX rings (`include/uapi/linux/if_xdp.h`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// Linux `struct xdp_statistics` snapshot (`XDP_STATISTICS`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct XdpStatistics {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

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

/// The kernel-side view of an AF_BYPASS / AF_XDP socket. Owns the *kernel*
/// halves of all four SPSC rings plus 4096-byte shared ring pages for
/// Linux `AF_XDP` `mmap(2)` compatibility.
///
/// Lock layout: each ring half lives behind its own
/// `IrqSafeSpinLock<Option<…>>` — the classifier uses the RX
/// producer in IRQ context, the TX path uses the TX consumer in the
/// driver's send pump, and the daemon may rebind at any time.
pub struct XdpSocket {
    umem: Arc<Umem>,
    iface_name: IrqSafeSpinLock<Option<alloc::string::String>>,
    queue_id: AtomicU32,
    bound: AtomicBool,
    closed: AtomicBool,
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
    /// Shared mmap ring pages (4096 bytes each) for Linux AF_XDP ABI.
    rx_page: Option<DmaBuffer>,
    tx_page: Option<DmaBuffer>,
    fill_page: Option<DmaBuffer>,
    comp_page: Option<DmaBuffer>,
    rx_entries: AtomicU32,
    tx_entries: AtomicU32,
    fill_entries: AtomicU32,
    comp_entries: AtomicU32,
    mmap_active: AtomicBool,
    rx_dropped: AtomicU64,
    rx_invalid_descs: AtomicU64,
    tx_invalid_descs: AtomicU64,
    rx_ring_full: AtomicU64,
    rx_fill_ring_empty_descs: AtomicU64,
    tx_ring_empty_descs: AtomicU64,
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
        let alloc_ring_page = || {
            let mut page = narf_io::alloc_coherent(4096, DomainId::USERSPACE_K).ok()?;
            page.as_mut_slice().fill(0);
            Some(page)
        };
        let socket = Arc::new(Self {
            umem,
            iface_name: IrqSafeSpinLock::new(None),
            queue_id: AtomicU32::new(0),
            bound: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            fill_cons: IrqSafeSpinLock::new(Some(fill_cons)),
            rx_prod: IrqSafeSpinLock::new(Some(rx_prod)),
            tx_cons: IrqSafeSpinLock::new(Some(tx_cons)),
            comp_prod: IrqSafeSpinLock::new(Some(comp_prod)),
            rx_page: alloc_ring_page(),
            tx_page: alloc_ring_page(),
            fill_page: alloc_ring_page(),
            comp_page: alloc_ring_page(),
            rx_entries: AtomicU32::new(XDP_RING_N as u32),
            tx_entries: AtomicU32::new(XDP_RING_N as u32),
            fill_entries: AtomicU32::new(XDP_RING_N as u32),
            comp_entries: AtomicU32::new(XDP_RING_N as u32),
            mmap_active: AtomicBool::new(false),
            rx_dropped: AtomicU64::new(0),
            rx_invalid_descs: AtomicU64::new(0),
            tx_invalid_descs: AtomicU64::new(0),
            rx_ring_full: AtomicU64::new(0),
            rx_fill_ring_empty_descs: AtomicU64::new(0),
            tx_ring_empty_descs: AtomicU64::new(0),
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
        if self.is_closed() {
            return Err(XdpError::UmemAccessDenied);
        }
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

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
    /// Roll back a failed bind before any hardware queue was attached.
    pub fn unbind(&self) {
        self.bound.store(false, Ordering::Release);
        *self.iface_name.lock() = None;
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

    /// Configure the ring depth for one of `XDP_RX_RING` (2), `XDP_TX_RING` (3),
    /// `XDP_UMEM_FILL_RING` (5), or `XDP_UMEM_COMPLETION_RING` (6).
    pub fn set_ring_entries(&self, opt_name: u32, entries: u32) -> bool {
        if entries == 0 || entries > XDP_RING_N as u32 || !entries.is_power_of_two() {
            return false;
        }
        match opt_name {
            2 => self.rx_entries.store(entries, Ordering::Release),
            3 => self.tx_entries.store(entries, Ordering::Release),
            5 => self.fill_entries.store(entries, Ordering::Release),
            6 => self.comp_entries.store(entries, Ordering::Release),
            _ => return false,
        }
        true
    }

    /// Enable the shared `mmap` ring publication path.
    pub fn enable_mmap_rings(&self) {
        self.mmap_active.store(true, Ordering::Release);
    }

    #[inline]
    pub fn mmap_active(&self) -> bool {
        self.mmap_active.load(Ordering::Acquire)
    }

    /// Return the physical address of the shared 4096-byte ring page for the
    /// given `mmap(2)` byte offset (`XDP_PGOFF_*`).
    pub fn ring_phys_addr(&self, offset: u64) -> Option<u64> {
        let buf = match offset {
            XDP_PGOFF_RX_RING => self.rx_page.as_ref()?,
            XDP_PGOFF_TX_RING => self.tx_page.as_ref()?,
            XDP_UMEM_PGOFF_FILL_RING => self.fill_page.as_ref()?,
            XDP_UMEM_PGOFF_COMPLETION_RING => self.comp_page.as_ref()?,
            _ => return None,
        };
        Some(buf.dma_addr().raw())
    }

    /// Snapshot `struct xdp_statistics` counters.
    pub fn statistics(&self) -> XdpStatistics {
        XdpStatistics {
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            rx_invalid_descs: self.rx_invalid_descs.load(Ordering::Relaxed),
            tx_invalid_descs: self.tx_invalid_descs.load(Ordering::Relaxed),
            rx_ring_full: self.rx_ring_full.load(Ordering::Relaxed),
            rx_fill_ring_empty_descs: self.rx_fill_ring_empty_descs.load(Ordering::Relaxed),
            tx_ring_empty_descs: self.tx_ring_empty_descs.load(Ordering::Relaxed),
        }
    }

    fn ring_header(page: &DmaBuffer) -> (&AtomicU32, &AtomicU32, &AtomicU32, *mut u8) {
        let base = page.as_ptr();
        // SAFETY: `page` is a 4096-byte coherent page aligned to at least 4096;
        // offsets 0, 128, 256, and 384 are 4/8-byte aligned and disjoint.
        unsafe {
            let prod = &*(base.add(XDP_RING_PRODUCER_OFF) as *const AtomicU32);
            let cons = &*(base.add(XDP_RING_CONSUMER_OFF) as *const AtomicU32);
            let flags = &*(base.add(XDP_RING_FLAGS_OFF) as *const AtomicU32);
            let desc = (base as *mut u8).add(XDP_RING_DESC_OFF);
            (prod, cons, flags, desc)
        }
    }

    /// Kernel-side: pop a free FILL slot the daemon posted. Used by
    /// the classifier to take a buffer before staging an RX frame
    /// into UMEM. Returns `None` if FILL is empty (driver should
    /// stash the frame elsewhere — in the kernel today that means
    /// drop).
    pub fn pop_fill(&self) -> Option<UmemSlot> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        {
            let mut g = self.fill_cons.lock();
            if let Some(cons) = g.as_mut() {
                if let Ok(Some(v)) = cons.try_recv() {
                    return Some(UmemSlot::unpack(v));
                }
            }
        }
        if let Some(page) = self.fill_page.as_ref() {
            let (prod_atom, cons_atom, _flags, desc_base) = Self::ring_header(page);
            let entries = self.fill_entries.load(Ordering::Acquire).max(1);
            let mask = entries - 1;
            let frame_size = u64::from(self.umem.frame_size());
            loop {
                let prod = prod_atom.load(Ordering::Acquire);
                let cons = cons_atom.load(Ordering::Relaxed);
                if cons == prod {
                    break;
                }
                let idx = (cons & mask) as usize;
                // SAFETY: `idx < 64` and `384 + 64 * 8 <= 4096`.
                let addr = unsafe { core::ptr::read_volatile((desc_base as *const u64).add(idx)) };
                cons_atom.store(cons.wrapping_add(1), Ordering::Release);
                if frame_size == 0 || addr % frame_size != 0 {
                    self.rx_invalid_descs.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let frame_idx = (addr / frame_size) as u32;
                if !self.umem.frame_in_bounds(frame_idx) {
                    self.rx_invalid_descs.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                return Some(UmemSlot { frame_idx, len: 0 });
            }
        }
        self.rx_fill_ring_empty_descs
            .fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Kernel-side: push an RX entry to the daemon. Called by the
    /// classifier after staging the frame bytes into UMEM. Returns
    /// `Err(RingFull)` on backpressure — the caller is expected to
    /// recycle the slot back into FILL.
    pub fn push_rx(&self, slot: UmemSlot) -> Result<(), XdpError> {
        self.umem.sync_to_mirror(slot.frame_idx, slot.len);
        if self.mmap_active.load(Ordering::Acquire) {
            if let Some(page) = self.rx_page.as_ref() {
                let (prod_atom, cons_atom, _flags, desc_base) = Self::ring_header(page);
                let entries = self.rx_entries.load(Ordering::Acquire).max(1);
                let mask = entries - 1;
                let prod = prod_atom.load(Ordering::Relaxed);
                let cons = cons_atom.load(Ordering::Acquire);
                if prod.wrapping_sub(cons) >= entries {
                    self.rx_ring_full.fetch_add(1, Ordering::Relaxed);
                    self.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(XdpError::RingFull);
                }
                let idx = (prod & mask) as usize;
                let desc = XdpDesc {
                    addr: u64::from(slot.frame_idx) * u64::from(self.umem.frame_size()),
                    len: slot.len,
                    options: 0,
                };
                // SAFETY: `idx < 64` and `384 + 64 * 16 <= 4096`.
                unsafe {
                    core::ptr::write_volatile((desc_base as *mut XdpDesc).add(idx), desc);
                }
                prod_atom.store(prod.wrapping_add(1), Ordering::Release);
                return Ok(());
            }
        }
        let mut g = self.rx_prod.lock();
        let prod = g.as_mut().ok_or(XdpError::RingFull)?;
        prod.try_send(slot.pack()).map_err(|_| {
            self.rx_ring_full.fetch_add(1, Ordering::Relaxed);
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            XdpError::RingFull
        })
    }

    /// Pop one RX entry from the shared `mmap` RX ring (used when `recv` is
    /// called on an `mmap`-enabled socket).
    pub fn pop_rx_mmap(&self) -> Option<UmemSlot> {
        let page = self.rx_page.as_ref()?;
        let (prod_atom, cons_atom, _flags, desc_base) = Self::ring_header(page);
        let entries = self.rx_entries.load(Ordering::Acquire).max(1);
        let mask = entries - 1;
        let prod = prod_atom.load(Ordering::Acquire);
        let cons = cons_atom.load(Ordering::Relaxed);
        if cons == prod {
            return None;
        }
        let idx = (cons & mask) as usize;
        // SAFETY: `idx < 64` and `384 + 64 * 16 <= 4096`.
        let desc = unsafe { core::ptr::read_volatile((desc_base as *const XdpDesc).add(idx)) };
        cons_atom.store(cons.wrapping_add(1), Ordering::Release);
        let frame_idx = (desc.addr / u64::from(self.umem.frame_size())) as u32;
        Some(UmemSlot {
            frame_idx,
            len: desc.len,
        })
    }

    /// Kernel-side: pop a TX entry the daemon queued. Used by the
    /// driver's send pump.
    pub fn pop_tx(&self) -> Option<UmemSlot> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        {
            let mut g = self.tx_cons.lock();
            if let Some(cons) = g.as_mut() {
                if let Ok(Some(v)) = cons.try_recv() {
                    let slot = UmemSlot::unpack(v);
                    self.umem
                        .sync_from_mirror(slot.frame_idx, 0, slot.len as usize);
                    return Some(slot);
                }
            }
        }
        if let Some(page) = self.tx_page.as_ref() {
            let (prod_atom, cons_atom, _flags, desc_base) = Self::ring_header(page);
            let entries = self.tx_entries.load(Ordering::Acquire).max(1);
            let mask = entries - 1;
            let frame_size = u64::from(self.umem.frame_size());
            loop {
                let prod = prod_atom.load(Ordering::Acquire);
                let cons = cons_atom.load(Ordering::Relaxed);
                if cons == prod {
                    break;
                }
                let idx = (cons & mask) as usize;
                // SAFETY: `idx < 64` and `384 + 64 * 16 <= 4096`.
                let desc =
                    unsafe { core::ptr::read_volatile((desc_base as *const XdpDesc).add(idx)) };
                cons_atom.store(cons.wrapping_add(1), Ordering::Release);
                if frame_size == 0 || desc.options != 0 {
                    self.tx_invalid_descs.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let frame_idx = (desc.addr / frame_size) as u32;
                let in_frame_off = (desc.addr % frame_size) as usize;
                if !self.umem.frame_in_bounds(frame_idx)
                    || in_frame_off != 0
                    || desc.len == 0
                    || desc.len > self.umem.frame_size()
                {
                    self.tx_invalid_descs.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                self.umem
                    .sync_from_mirror(frame_idx, in_frame_off, desc.len as usize);
                return Some(UmemSlot {
                    frame_idx,
                    len: desc.len,
                });
            }
        }
        self.tx_ring_empty_descs.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Kernel-side: push a COMPLETION entry for a TX frame the
    /// driver finished sending. Returns `Err(RingFull)` if the
    /// daemon's COMPLETION ring is full — caller should park /
    /// retry.
    pub fn push_completion(&self, slot: UmemSlot) -> Result<(), XdpError> {
        if self.mmap_active.load(Ordering::Acquire) {
            if let Some(page) = self.comp_page.as_ref() {
                let (prod_atom, cons_atom, _flags, desc_base) = Self::ring_header(page);
                let entries = self.comp_entries.load(Ordering::Acquire).max(1);
                let mask = entries - 1;
                let prod = prod_atom.load(Ordering::Relaxed);
                let cons = cons_atom.load(Ordering::Acquire);
                if prod.wrapping_sub(cons) >= entries {
                    return Err(XdpError::RingFull);
                }
                let idx = (prod & mask) as usize;
                let addr = u64::from(slot.frame_idx) * u64::from(self.umem.frame_size());
                // SAFETY: `idx < 64` and `384 + 64 * 8 <= 4096`.
                unsafe {
                    core::ptr::write_volatile((desc_base as *mut u64).add(idx), addr);
                }
                prod_atom.store(prod.wrapping_add(1), Ordering::Release);
                return Ok(());
            }
        }
        let mut g = self.comp_prod.lock();
        let prod = g.as_mut().ok_or(XdpError::RingFull)?;
        prod.try_send(slot.pack()).map_err(|_| XdpError::RingFull)
    }

    /// Pop one COMPLETION entry from the shared `mmap` COMPLETION ring.
    pub fn pop_comp_mmap(&self) -> Option<UmemSlot> {
        let page = self.comp_page.as_ref()?;
        let (prod_atom, cons_atom, _flags, desc_base) = Self::ring_header(page);
        let entries = self.comp_entries.load(Ordering::Acquire).max(1);
        let mask = entries - 1;
        let prod = prod_atom.load(Ordering::Acquire);
        let cons = cons_atom.load(Ordering::Relaxed);
        if cons == prod {
            return None;
        }
        let idx = (cons & mask) as usize;
        // SAFETY: `idx < 64` and `384 + 64 * 8 <= 4096`.
        let addr = unsafe { core::ptr::read_volatile((desc_base as *const u64).add(idx)) };
        cons_atom.store(cons.wrapping_add(1), Ordering::Release);
        let frame_idx = (addr / u64::from(self.umem.frame_size())) as u32;
        Some(UmemSlot { frame_idx, len: 0 })
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
