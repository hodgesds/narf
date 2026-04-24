//! narf-io — DMA buffers, IOMMU context, P2P DMA.
//!
//! Spec: `io/specification/spec.md`. Stage-3 Wave-3a subset: just enough
//! of the DMA-buffer lifecycle to hand a driver a `Cap<DmaBuffer, _>` and
//! let the driver framework thread it into `DriverEnv`. The full IOMMU
//! programming + P2P routing story is later waves.
//!
//! What exists:
//! - `DmaBuffer`: owns a physically-contiguous region intended for DMA.
//!   Tracks owning domain, physical base, byte length, and a
//!   coherent-vs-streaming hint. Dropping the buffer returns storage to
//!   `narf_memory`.
//! - `alloc_coherent` / `free_coherent`: the Wave-3a allocator surface.
//!   Single 4 KiB `PhysFrame` backing per buffer. Requests bigger than
//!   one frame fail with `IoError::NoMemory` — contiguous multi-frame
//!   alloc is Wave-3b work (the spec requires physical contiguity for
//!   DMA, and `narf_memory` does not yet expose a buddy allocator).
//! - `DmaBuffer: CapType` — wiring into the Wave-2 cap table so a
//!   driver-facing `Cap<DmaBuffer, R>` is mintable via
//!   `Cap::<DmaBuffer, _>::bootstrap()`.
//! - `IommuContext`: stub type representing an IOMMU/SMMU context
//!   bound to a domain. `map` / `unmap` are no-ops on the QEMU default
//!   machine, which has no virtual IOMMU. Real programming of Intel
//!   VT-d / AMD-Vi / SMMUv3 context entries is Wave-4+.
//! - `p2p_map`: signature-only stub. Returns `Err(IoError::NotMapped)`
//!   until Wave-4 discovers the PCIe peer topology and can honour ACS.
//!
//! Non-goals for Wave 3a:
//! - Contiguous multi-frame DMA allocations (Wave 3b).
//! - Real IOMMU context-entry / StreamID programming (Wave 4+).
//! - Fault-handler registration (Wave 4+).
//! - P2P DMA routing and ACS enforcement (Wave 4+).
//! - `DmaBuffer` cache-maintenance ops on non-coherent aarch64 (Wave 4).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::fmt;

use narf_capabilities::{CapKind, CapType};
use narf_lib::id::DomainId;
use narf_memory::{
    alloc_frame, free_frame, FrameAllocError, PhysAddr, PhysFrame, PAGE_SIZE,
};

// ── Errors ──────────────────────────────────────────────────────────

/// Why an `io/` call failed.
///
/// Deliberately narrow: every surface here only has a handful of failure
/// modes, and drivers don't care about the distinction between
/// "allocator empty" and "allocator not initialised" — both collapse to
/// `NoMemory`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoError {
    /// No contiguous physical storage available. Wave-3a: also returned
    /// for any request larger than one page (multi-frame is Wave 3b).
    NoMemory,
    /// The buffer's owning domain does not match the caller's expected
    /// domain. Enforced at Wave-4+; Wave-3a has no domain-mismatch path
    /// because there's only ever one domain active per test.
    DomainMismatch,
    /// The IOMMU context has no free IOVA range large enough for the
    /// buffer. Wave-3a's stub mapper never returns this, but drivers
    /// can match on it today.
    OutOfIova,
    /// Operation referenced an IOVA / binding that was not previously
    /// mapped. Also the placeholder return for `p2p_map` until Wave 4.
    NotMapped,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::NoMemory       => f.write_str("io: no contiguous DMA memory available"),
            IoError::DomainMismatch => f.write_str("io: buffer domain mismatch"),
            IoError::OutOfIova      => f.write_str("io: no IOVA window available"),
            IoError::NotMapped      => f.write_str("io: not mapped"),
        }
    }
}

impl From<FrameAllocError> for IoError {
    fn from(_e: FrameAllocError) -> Self { IoError::NoMemory }
}

// ── DmaBuffer ───────────────────────────────────────────────────────

/// Coherency hint for a `DmaBuffer`. On x86_64 everything is cache-
/// coherent at the platform level, so the hint is informational. On
/// aarch64 `Streaming` means the driver must pair cache-maintenance ops
/// with device handoff — see `io/` spec §5 (aarch64). Wave-3a does not
/// emit those ops; Wave-4 wires them into `DmaBuffer` lifecycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Coherency {
    /// CPU and device see the same view without explicit maintenance.
    Coherent,
    /// Non-coherent; driver + `io/` cooperate on cache maintenance.
    Streaming,
}

/// A physically-contiguous region owned for device DMA.
///
/// Construction goes through `alloc_coherent`; dropping a `DmaBuffer`
/// returns the backing storage to `narf_memory`. The `phys_addr` is
/// page-aligned and the length is rounded up to a page multiple.
///
/// `DmaBuffer` is not `Copy` or `Clone` — it owns a physical allocation.
/// Drivers that need to share access go through
/// `Cap<DmaBuffer, R>::derive` on the cap-table side; the underlying
/// buffer stays here.
pub struct DmaBuffer {
    /// Physical base. Guaranteed page-aligned by construction.
    phys:      PhysAddr,
    /// Length in bytes (page-multiple after alloc rounding).
    len:       usize,
    /// Owning protection domain. On revoke of the corresponding
    /// `Cap<DmaBuffer, _>` the reclamation path compares this against
    /// the caller's domain.
    domain:    DomainId,
    /// Coherency hint — informs aarch64 cache maintenance in Wave 4.
    coherency: Coherency,
    /// Internal: set when the backing frame has been handed back to
    /// `narf_memory`. Guards against double-free on drop after explicit
    /// `free_coherent`.
    freed:     bool,
}

impl fmt::Debug for DmaBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaBuffer")
            .field("phys",      &self.phys)
            .field("len",       &self.len)
            .field("domain",    &self.domain)
            .field("coherency", &self.coherency)
            .finish_non_exhaustive()
    }
}

impl DmaBuffer {
    /// Physical base of the DMA region. Always page-aligned.
    #[inline]
    pub fn phys_addr(&self) -> PhysAddr { self.phys }

    /// Length in bytes. Always a multiple of `PAGE_SIZE`.
    #[inline]
    pub fn len(&self) -> usize { self.len }

    /// `true` iff `len() == 0`. Never true for a live buffer — alloc
    /// rejects zero-length requests — but present for parity with the
    /// slice-ish type surface.
    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Protection domain that owns this buffer.
    #[inline]
    pub fn domain(&self) -> DomainId { self.domain }

    /// Coherency hint (informational on x86_64; load-bearing on
    /// non-coherent aarch64 when Wave-4 cache-maintenance lands).
    #[inline]
    pub fn coherency(&self) -> Coherency { self.coherency }
}

impl CapType for DmaBuffer {
    const KIND: CapKind = CapKind::DmaBuffer;
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        if !self.freed {
            // Wave-3a single-frame backing. The allocation path only
            // hands out buffers of exactly `PAGE_SIZE`, so reconstructing
            // the frame from `phys` is unambiguous. When Wave-3b adds
            // multi-frame contiguous allocations, drop will iterate
            // frames from `phys` .. `phys + len`.
            let frame = PhysFrame::new(self.phys);
            free_frame(frame);
            self.freed = true;
        }
    }
}

/// Allocate a coherent (CPU-visible, device-coherent) DMA buffer of
/// at least `len` bytes, attached to `domain`.
///
/// Wave-3a limitation: only requests `<= PAGE_SIZE` succeed — the
/// Stage-1 frame allocator hands out one 4 KiB frame at a time and does
/// not guarantee contiguity across `alloc_frame` calls. Multi-frame
/// contiguous allocation is Wave-3b.
pub fn alloc_coherent(len: usize, domain: DomainId) -> Result<DmaBuffer, IoError> {
    alloc_with(len, domain, Coherency::Coherent)
}

/// Explicit free. Ordinarily the `Drop` impl does this at scope end;
/// the explicit form is here for drivers that need to tear down before
/// the binding drops (e.g. during quiesce).
pub fn free_coherent(mut buf: DmaBuffer) {
    if !buf.freed {
        let frame = PhysFrame::new(buf.phys);
        free_frame(frame);
        buf.freed = true;
    }
    // Drop runs next; sees `freed == true` and does nothing.
}

fn alloc_with(len: usize, domain: DomainId, coherency: Coherency) -> Result<DmaBuffer, IoError> {
    if len == 0 { return Err(IoError::NoMemory); }
    let page = PAGE_SIZE as usize;
    // Round up to page multiple. Wave-3a rejects anything bigger than
    // one page — see the crate-level doc for why.
    let rounded = (len + page - 1) & !(page - 1);
    if rounded > page { return Err(IoError::NoMemory); }

    let frame = alloc_frame()?;
    Ok(DmaBuffer {
        phys:      frame.start_address(),
        len:       rounded,
        domain,
        coherency,
        freed:     false,
    })
}

// ── IommuContext ────────────────────────────────────────────────────

/// One IOMMU / SMMU protection context bound to a CPU domain.
///
/// Wave-3a stub: `map` / `unmap` are no-ops because the QEMU default
/// machine (`q35` on x86_64, `virt` on aarch64) does not present a
/// virtual IOMMU unless explicitly requested (`intel-iommu=on`,
/// `iommu=smmuv3`). Without a real IOMMU to program, the correct
/// behaviour at this layer is "record the intent and move on." Wave-4+
/// replaces the stub with VT-d context-entry programming on x86_64 and
/// StreamID table programming on aarch64.
pub struct IommuContext {
    domain:   DomainId,
    // Simple tally used by the smoke test to observe that `map`
    // / `unmap` are at least dispatching. No semantic weight.
    mappings: usize,
}

impl fmt::Debug for IommuContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IommuContext")
            .field("domain",   &self.domain)
            .field("mappings", &self.mappings)
            .finish_non_exhaustive()
    }
}

impl IommuContext {
    /// Create a fresh IOMMU context bound to `domain`.
    pub fn new(domain: DomainId) -> Self {
        Self { domain, mappings: 0 }
    }

    /// Domain this context represents.
    #[inline]
    pub fn domain(&self) -> DomainId { self.domain }

    /// Current (stub) mapping count. Useful for the smoke test; not a
    /// stable API surface.
    #[inline]
    pub fn mapping_count(&self) -> usize { self.mappings }

    /// Map `dma` at device-visible IOVA `iova`. Wave-3a: no-op beyond
    /// the domain-correspondence check and the internal tally — the
    /// DMA is physically addressed under QEMU without a vIOMMU.
    pub fn map(&mut self, dma: &DmaBuffer, _iova: u64) -> Result<(), IoError> {
        if dma.domain() != self.domain {
            return Err(IoError::DomainMismatch);
        }
        self.mappings = self.mappings.saturating_add(1);
        Ok(())
    }

    /// Unmap the IOVA range previously installed by `map`. Wave-3a:
    /// symmetric no-op.
    pub fn unmap(&mut self, _iova: u64) -> Result<(), IoError> {
        if self.mappings == 0 {
            return Err(IoError::NotMapped);
        }
        self.mappings -= 1;
        Ok(())
    }
}

// ── P2P placeholder ─────────────────────────────────────────────────

/// Establish a P2P DMA path between two buffers. Wave-4 work — requires
/// PCIe peer discovery, ACS-chain verification, and (on systems that
/// support ATS) an ATS-invalidate protocol. Until then the signature
/// exists so drivers can reference it in their own Wave-3b wiring; the
/// body returns `Err(IoError::NotMapped)` unconditionally.
pub fn p2p_map(_src: &DmaBuffer, _dst: &DmaBuffer) -> Result<(), IoError> {
    Err(IoError::NotMapped)
}
