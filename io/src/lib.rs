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

static REGISTRY: IrqSafeSpinLock<Vec<Option<Arc<DmaBuffer>>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a DmaBuffer and return its assigned index.
pub fn register(buf: DmaBuffer) -> u32 {
    let mut r = REGISTRY.lock();
    let index = r.len() as u32;
    r.push(Some(Arc::new(buf)));
    index
}

/// Resolve a capability index to a DmaBuffer.
pub fn resolve(index: u32) -> Option<Arc<DmaBuffer>> {
    let r = REGISTRY.lock();
    r.get(index as usize).and_then(|o| o.clone())
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
    // SAFETY: `phys.raw()` is a freshly allocated page; identity-
    // mapped on x86_64 + the boot identity map on aarch64 (DMA
    // buffers must be reachable by the CPU on both arches).
    unsafe {
        core::ptr::write_bytes(phys.raw() as *mut u8, 0, page);
    }
    Ok(DmaBuffer {
        phys,
        len: page,
        domain,
        coherency,
        freed: false,
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

    pub fn map(&self, buf: &DmaBuffer, _fixed_iova: u64) -> Result<u64, IoError> {
        if buf.domain() != self.domain {
            return Err(IoError::DomainMismatch);
        }
        self.mappings.fetch_add(1, Ordering::Relaxed);
        Ok(_fixed_iova)
    }

    pub fn unmap(&self, _iova: u64, _len: usize) -> Result<(), IoError> {
        let prev = self.mappings.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            return Err(IoError::NotMapped);
        }
        Ok(())
    }
}

pub fn p2p_map(_src: &DmaBuffer, _dst_device: DomainId) -> Result<u64, IoError> {
    Err(IoError::NotMapped)
}
