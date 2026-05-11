//! narf-io — DMA buffers, IOMMU context, P2P DMA.
//!
//! Spec: `io/specification/spec.md`. Stage-3 Wave-3a subset: just enough
//! of the DMA-buffer lifecycle to hand a driver a `Cap<DmaBuffer, _>` and
//! let the driver framework thread it into `DriverEnv`. The full IOMMU
//! programming + P2P routing story is later waves.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod iommu;
mod tests;

use core::fmt;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_capabilities::{Cap, CapError, CapKind, CapOp, CapType};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{alloc_frame, free_frame, FrameAllocError, PhysAddr, PhysFrame, PAGE_SIZE};

// ── Operations ──────────────────────────────────────────────────────

/// Resolve a DmaBuffer's physical address.
#[derive(Copy, Clone, Debug, Default)]
pub struct GetPhysAddr;

impl<R: narf_capabilities::Rights> CapOp<DmaBuffer, R> for GetPhysAddr {
    type Output = PhysAddr;
    fn execute(self, cap: &Cap<DmaBuffer, R>) -> Result<Self::Output, CapError> {
        resolve(cap.slot().index)
            .map(|b| b.phys_addr())
            .ok_or(CapError::Revoked)
    }
}

// ── Registry ────────────────────────────────────────────────────────
//
// The registry is the cap → buffer indirection that makes
// `BlockRequest::buffer: Cap<DmaBuffer, _>` actually mean "this
// is the buffer to DMA against". A device's `submit()` does:
//
//   let buf = narf_io::resolve(req.buffer.slot().index)?;
//   // …copy into / out of buf.as_slice()…
//
// `register_with_cap(buf)` reserves an object-table slot for the
// buffer and returns a `Cap<DmaBuffer, Write>` whose `slot.index`
// is the registry index. The registry holds the only `Arc` to the
// buffer until either `unregister(cap)` is called explicitly or
// the cap is revoked (`cap.revoke()` bumps the epoch, which
// strictly invalidates all outstanding caps but does not free
// the registry slot — call `unregister` for that). Drop the cap
// without calling `unregister` and the buffer leaks; the API is
// explicit on this point because BlockRequest sometimes outlives
// the cap that authorised it (the device's queue still holds the
// completion in flight).

static REGISTRY: IrqSafeSpinLock<Vec<Option<Arc<DmaBuffer>>>> = IrqSafeSpinLock::new(Vec::new());

/// Register `buf` in the cap → buffer registry and mint a
/// `Cap<DmaBuffer, Write>` that points at it. The cap's
/// `slot.index` is the registry slot, so devices can `resolve()`
/// back to the buffer from a `BlockRequest::buffer` field.
pub fn register_with_cap(mut buf: DmaBuffer) -> Cap<DmaBuffer, narf_capabilities::Write> {
    let (index, _gen) = narf_capabilities::object_table::register(CapKind::DmaBuffer);
    buf.slot_index = Some(index);
    let mut r = REGISTRY.lock();
    if (index as usize) >= r.len() {
        r.resize(index as usize + 1, None);
    }
    r[index as usize] = Some(Arc::new(buf));
    drop(r);
    let slot = narf_capabilities::CapSlot::new(
        narf_capabilities::object_table::current_epoch(index).unwrap_or(1),
        index,
        <narf_capabilities::Write as narf_capabilities::Rights>::BITS,
        CapKind::DmaBuffer as u32,
    );
    // SAFETY: the slot we just synthesised is consistent with the
    // entry we wrote into REGISTRY a moment ago — same index, live
    // epoch, DmaBuffer kind. `Cap::mint` only requires that the
    // slot describe an authority the caller actually holds.
    unsafe { Cap::mint(slot) }
}

/// Revoke the cap and free the registry slot. After this call
/// every other cap referencing the same slot fails `check_live()`.
/// The buffer's frame is freed when the last `Arc<DmaBuffer>` ref
/// drops (typically immediately if no in-flight `resolve()` Arc is
/// held).
pub fn unregister<R: narf_capabilities::Rights>(cap: Cap<DmaBuffer, R>) {
    let index = cap.slot().index;
    let _ = narf_capabilities::object_table::bump_epoch(index);
    let mut r = REGISTRY.lock();
    if let Some(slot) = r.get_mut(index as usize) {
        *slot = None;
    }
}

/// Resolve a capability slot index to the underlying DmaBuffer.
/// Returns `None` if the index never existed or has been
/// `unregister`-ed.
pub fn resolve(index: u32) -> Option<Arc<DmaBuffer>> {
    let r = REGISTRY.lock();
    r.get(index as usize).and_then(|o| o.clone())
}

/// Cap-gated resolve: returns `None` if the cap is revoked, the
/// registry slot is empty, or the slot index is out of range.
pub fn resolve_cap<R: narf_capabilities::Rights>(
    cap: &Cap<DmaBuffer, R>,
) -> Option<Arc<DmaBuffer>> {
    cap.check_live().ok()?;
    resolve(cap.slot().index)
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why an `io/` call failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoError {
    NoMemory,
    DomainMismatch,
    OutOfIova,
    NotMapped,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::NoMemory => f.write_str("io: no contiguous DMA memory available"),
            IoError::DomainMismatch => f.write_str("io: buffer domain mismatch"),
            IoError::OutOfIova => f.write_str("io: no IOVA window available"),
            IoError::NotMapped => f.write_str("io: not mapped"),
        }
    }
}

impl From<FrameAllocError> for IoError {
    fn from(_e: FrameAllocError) -> Self {
        IoError::NoMemory
    }
}

// ── DmaBuffer ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Coherency {
    Coherent,
    Streaming,
}

pub struct DmaBuffer {
    phys: PhysAddr,
    len: usize,
    domain: DomainId,
    coherency: Coherency,
    freed: bool,
    /// Object-table slot index assigned by [`register_with_cap`].
    /// `None` until the buffer is registered. The `(slot_index,
    /// epoch)` pair is what a `Cap<DmaBuffer, _>` stores in its
    /// `slot` field — that's how a device's `submit()` can resolve
    /// the cap back to *this* buffer's `PhysAddr` + length.
    slot_index: Option<u32>,
}

impl fmt::Debug for DmaBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaBuffer")
            .field("phys", &self.phys)
            .field("len", &self.len)
            .field("domain", &self.domain)
            .field("coherency", &self.coherency)
            .finish_non_exhaustive()
    }
}

impl DmaBuffer {
    #[inline]
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn domain(&self) -> DomainId {
        self.domain
    }

    #[inline]
    pub fn coherency(&self) -> Coherency {
        self.coherency
    }

    /// Borrow the buffer's contents as bytes. Identity-mapped
    /// physical memory backs the slice — see `alloc_with` for the
    /// safety argument that the mapping is live.
    ///
    /// # Safety contract
    /// The slice's lifetime is tied to `&self`; the buffer's frame
    /// is freed in `Drop` so no caller can outlive the backing
    /// memory.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `kernel_ptr` resolves through the kernel's
        // identity map (x86_64) or TTBR1 high-half RAM window
        // (aarch64), so the slice stays valid across user-task
        // TTBR0/CR3 swaps. `len` is the buffer's true length and
        // `&self` keeps the buffer alive across this borrow.
        unsafe { core::slice::from_raw_parts(self.phys.kernel_ptr::<u8>(), self.len) }
    }

    /// Mutable byte view. Same kernel-mapping argument as
    /// [`Self::as_slice`].
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see `as_slice` — the unique-mut borrow comes from
        // `&mut self`, so no aliasing is possible.
        unsafe { core::slice::from_raw_parts_mut(self.phys.kernel_mut_ptr::<u8>(), self.len) }
    }

    /// Read this buffer's object-table slot index, if it has been
    /// registered via [`register_with_cap`]. Devices use this to
    /// resolve a `BlockRequest::buffer` cap back to the buffer.
    #[inline]
    pub fn slot_index(&self) -> Option<u32> {
        self.slot_index
    }

    /// Raw byte pointer into the kernel-mapped buffer region.
    /// Lifted to `&self` (not `&mut self`) because a `DmaBuffer`
    /// is normally accessed through an `Arc` from the registry —
    /// the device may DMA-write into it while a CPU-side observer
    /// only holds a shared reference. Resolves through the kernel
    /// identity map (x86_64) or TTBR1 high-half (aarch64), so the
    /// pointer stays valid across user-task page-table swaps.
    ///
    /// # Safety
    /// Callers must serialise CPU-side mutation against any
    /// concurrent device access. The cooperative single-CPU
    /// executor makes this trivial — copy in / out without
    /// yielding mid-borrow.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.phys.kernel_ptr::<u8>()
    }

    /// See [`Self::as_ptr`].
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.phys.kernel_mut_ptr::<u8>()
    }
}

impl CapType for DmaBuffer {
    const KIND: CapKind = CapKind::DmaBuffer;
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        if !self.freed {
            let frame = PhysFrame::new(self.phys);
            free_frame(frame);
            self.freed = true;
        }
    }
}

pub fn alloc_coherent(len: usize, domain: DomainId) -> Result<DmaBuffer, IoError> {
    alloc_with(len, domain, Coherency::Coherent)
}

pub fn free_coherent(mut buf: DmaBuffer) {
    if !buf.freed {
        let frame = PhysFrame::new(buf.phys);
        free_frame(frame);
        buf.freed = true;
    }
}

fn alloc_with(len: usize, domain: DomainId, coherency: Coherency) -> Result<DmaBuffer, IoError> {
    let page = PAGE_SIZE as usize;
    if len > page {
        return Err(IoError::NoMemory);
    }
    if len == 0 {
        return Err(IoError::NoMemory);
    }

    let frame = alloc_frame()?;
    let phys = frame.start_address();
    // Zero-fill the buffer. `alloc_frame` returns recycled frames
    // un-zeroed; drivers that build descriptor rings, completion
    // queues, or any phase-tagged structure on top of the buffer
    // rely on starting from a known-zero state. Without this,
    // stale phase bits / used-ring entries / status words from a
    // previous tenant cause non-deterministic init failures
    // (NVMe identify VID mismatch, virtio control-vq wedge, etc.)
    // depending on which test ran before.
    //
    // SAFETY: `phys` is a freshly allocated page; the kernel
    // accesses it through the per-arch kernel mapping
    // (`kernel_mut_ptr`) — identity on x86_64, TTBR1 high-half on
    // aarch64 — so the write stays valid even when the calling
    // thread is in a user-task TTBR0/CR3 context.
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, page);
    }
    Ok(DmaBuffer {
        phys,
        len: page,
        domain,
        coherency,
        freed: false,
        slot_index: None,
    })
}

pub struct IommuContext {
    domain: DomainId,
    mappings: AtomicUsize,
}

impl fmt::Debug for IommuContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IommuContext")
            .field("domain", &self.domain)
            .field("mappings", &self.mappings.load(Ordering::Relaxed))
            .finish()
    }
}

impl IommuContext {
    pub const fn new(domain: DomainId) -> Self {
        Self {
            domain,
            mappings: AtomicUsize::new(0),
        }
    }

    pub fn domain(&self) -> DomainId {
        self.domain
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.load(Ordering::Relaxed)
    }

    /// Translate a buffer's host-physical address into a device-
    /// usable IOVA via the active IOMMU backend. In identity
    /// mode (the only mode active right now) the IOVA equals
    /// the buffer's `phys`. The `fixed_iova` argument is
    /// retained as a hint for future per-domain modes that may
    /// honour caller-chosen virtual addresses; identity mode
    /// ignores it.
    pub fn map(&self, buf: &DmaBuffer, fixed_iova: u64) -> Result<u64, IoError> {
        if buf.domain() != self.domain {
            return Err(IoError::DomainMismatch);
        }
        let iova = match iommu::mode() {
            iommu::IommuMode::Disabled => fixed_iova.max(buf.phys.as_u64()),
            iommu::IommuMode::Identity => iommu::map_phys(buf.phys.as_u64())?,
            iommu::IommuMode::PerDomain => return Err(IoError::NotMapped),
        };
        self.mappings.fetch_add(1, Ordering::Relaxed);
        Ok(iova)
    }

    pub fn unmap(&self, iova: u64, _len: usize) -> Result<(), IoError> {
        let prev = self.mappings.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            self.mappings.fetch_add(1, Ordering::Relaxed); // restore
            return Err(IoError::NotMapped);
        }
        // Identity / disabled paths don't actually touch
        // hardware; per-domain mode walks the table.
        let _ = iommu::unmap_iova(iova)?;
        Ok(())
    }
}

pub fn p2p_map(_src: &DmaBuffer, _dst_device: DomainId) -> Result<u64, IoError> {
    Err(IoError::NotMapped)
}
