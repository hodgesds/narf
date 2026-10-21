//! amdgpu GEM buffer objects — `amdgpu_gem.c`.
//!
//! The four ioctls a Mesa client needs before it can put anything in memory:
//! `GEM_CREATE` allocates a buffer, `GEM_MMAP` hands back an offset the client
//! `mmap`s, `GEM_OP` reads a buffer's creation parameters back, and
//! `GEM_WAIT_IDLE` waits for the GPU to stop touching it. `GEM_CLOSE` (a
//! generic DRM ioctl) destroys one.
//!
//! ## Handles are per-open, and that is a security property
//!
//! Linux's GEM handles live in `struct drm_file`, so handle 3 in one client's
//! fd and handle 3 in another's are unrelated objects. That is what stops one
//! client reaching another's buffers by guessing a small integer, and it
//! matters here because the render node is opened by every GL client on the
//! system. The state therefore hangs off the per-open file object, not off the
//! card — unlike the KMS dumb-buffer table, which is card-global because a
//! dumb handle is shared deliberately between a compositor's own opens.
//!
//! Handles are allocated from [`HANDLE_BASE`] upward so they cannot collide
//! with the card-global dumb-buffer handles, which are small integers. Linux
//! has one handle space per file covering both kinds; NARF has two tables with
//! different lifetimes, and keeping their numbering disjoint is what lets
//! `GEM_CLOSE` tell which table a handle belongs to without a lookup in both.
//!
//! ## Placement
//!
//! A buffer allowed in VRAM, on a card that registered a [`VramHeap`], is a
//! reservation in that card's owned VRAM pool: its entries carry the
//! physical VRAM address (`gmc_v1x_0_get_vm_pde`'s translation) without
//! SYSTEM, and the CPU maps it through the BAR. Anything else — every APU
//! buffer, a GTT buffer, or VRAM falling back to GTT when the heap is full —
//! is system memory from the buddy allocator, which the GPU reaches as
//! SYSTEM pages (the IOMMU runs identity mappings): power-of-two chunks
//! covering exactly its pages, as TTM backs a GTT BO with scattered pages,
//! within a GTT limit of half of RAM (TTM's default page limit).
//!
//! A `NO_CPU_ACCESS` buffer goes first to the heap's VRAM past the BAR
//! ([`UnmappedHeap`]), when the card has some. The CPU cannot clear that, so
//! the card's engine does ([`VramClear`]), and the clear's fence becomes the
//! buffer's KERNEL fence: every job that may touch the buffer waits for it
//! (`amdgpu_cs`, `GEM_VA`), as Linux attaches amdgpu_fill_buffer's fence to
//! the new BO. Such a buffer has no CPU mapping at all.
//!
//! Visible VRAM buffers can be evicted to GTT under pressure and promoted
//! on validation. Shared handles and PRIME exports retain identity, while
//! address leases pin backing. The async move path waits for GPU jobs and
//! rebinds their VMs under card admission exclusion. CPU mappings, deferred
//! CPU fence writes and invisible VRAM still pin placement. Allocation or
//! copy failure preserves the source. GEM_SET_PLACEMENT records the normal-
//! domain preference; eligible buffers apply it on lookup or CS validation.
//! GEM_WAIT_IDLE is handled by amdgpu_cs::dispatch_async on running cards.
//!
//! `GEM_USERPTR` pins the caller's pages at creation (Linux faults them with
//! HMM and re-validates through an MMU interval notifier). LINUX-GAP: without
//! a notifier the pins are a snapshot: a later CPU remap, fork-COW split or
//! munmap leaves the GPU on the pinned frames, never on freed memory.
//! `GEM_LIST_HANDLES` is not implemented and returns EINVAL.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_uapi as uapi;
use crate::drm_ioctl_bridge::{copy_in, copy_out};
use crate::drm_uapi;
#[path = "amdgpu_cpu_mapping.rs"]
pub(crate) mod cpu_mapping;
pub use cpu_mapping::{release_cpu_frame, retain_cpu_frame};

/// First amdgpu GEM handle. Chosen above any plausible dumb-buffer handle so
/// the two spaces cannot overlap; see the module header.
const HANDLE_BASE: u32 = 0x4000_0000;

/// `DRM_IOCTL_GEM_CLOSE`'s command number — generic DRM, not amdgpu-private.
const DRM_GEM_CLOSE_NR: u32 = 0x09;

const PAGE_SIZE: u64 = 4096;

/// A discrete card's VRAM that client buffers may take: its owned pool, and
/// how a pool (GPU framebuffer) address becomes the physical VRAM address
/// page-table entries carry — `address - fb_base + fb_offset`, as
/// `gmc_v1x_0_get_vm_pde` subtracts `vram_start` and adds
/// `vram_base_offset`.
#[derive(Clone, Debug)]
pub struct VramHeap {
    pub pool: crate::amdgpu_vram::Pool,
    pub fb_base: u64,
    pub fb_offset: u64,
    /// The card's VRAM past the CPU-visible BAR, if it has some to give.
    pub unmapped: Option<UnmappedHeap>,
}

/// VRAM no CPU mapping reaches, for `NO_CPU_ACCESS` buffers, and the engine
/// that clears it.
#[derive(Clone, Debug)]
pub struct UnmappedHeap {
    pub pool: crate::amdgpu_vram::UnmappedPool,
    pub clear: Arc<dyn VramClear>,
    pub transfer: Option<Arc<dyn VramTransfer>>,
}

/// Copy an idle allocation between invisible VRAM and private System backing.
/// Success means every byte has landed. The caller retains card admission and
/// all source mappings until the copy finishes. Queued work must independently
/// retain its allocations and attach a KERNEL fence to `object` before yielding;
/// cancellation cannot release memory or permit writers still reached by DMA.
pub trait VramTransfer: Send + Sync + core::fmt::Debug {
    fn read<'a>(
        &'a self,
        object: Arc<GemObject>,
        source: Arc<GemPlacement>,
        destination: &'a mut GemPlacement,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), FsError>> + Send + 'a>,
    >;
    fn write<'a>(
        &'a self,
        _object: Arc<GemObject>,
        _source: Arc<GemPlacement>,
        _destination: Arc<GemPlacement>,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), FsError>> + Send + 'a>,
    > {
        alloc::boxed::Box::pin(async { Err(FsError::Unsupported) })
    }
}

pub(crate) async fn readback(
    gate: &PlacementGuard,
    object: &Arc<GemObject>,
    source: &Arc<GemPlacement>,
    destination: &mut GemPlacement,
) -> Result<(), FsError> {
    let reader = vram_heap(gate.card())
        .and_then(|heap| heap.unmapped)
        .and_then(|heap| heap.transfer)
        .ok_or(FsError::Unsupported)?;
    reader
        .read(object.clone(), source.clone(), destination)
        .await
}

pub(crate) async fn upload(
    gate: &PlacementGuard,
    object: &Arc<GemObject>,
    source: &Arc<GemPlacement>,
    destination: &Arc<GemPlacement>,
) -> Result<(), FsError> {
    let writer = vram_heap(gate.card())
        .and_then(|heap| heap.unmapped)
        .and_then(|heap| heap.transfer)
        .ok_or(FsError::Unsupported)?;
    writer
        .write(object.clone(), source.clone(), destination.clone())
        .await
}

pub(crate) fn hidden_destination(card: u32, object: &GemObject) -> Result<GemPlacement, FsError> {
    if object.flags & u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS) == 0 {
        return Err(FsError::Unsupported);
    }
    let heap = vram_heap(card).ok_or(FsError::NoDevice)?;
    let hidden = heap.unmapped.ok_or(FsError::Unsupported)?;
    if hidden.transfer.is_none() {
        return Err(FsError::Unsupported);
    }
    let align = object
        .alignment
        .max(PAGE_SIZE)
        .checked_next_power_of_two()
        .ok_or(FsError::InvalidData)?;
    let held = hidden
        .pool
        .reserve_aligned(object.byte_len, align)
        .map_err(|_| FsError::NoSpace)?;
    let gpu = held
        .address()
        .checked_sub(heap.fb_base)
        .and_then(|a| a.checked_add(heap.fb_offset))
        .ok_or(FsError::InvalidData)?;
    crate::amdgpu_vm::make_pte(gpu, 0)?;
    crate::amdgpu_vm::make_pte(gpu + object.byte_len - PAGE_SIZE, 0)?;
    Ok(GemPlacement {
        phys: 0,
        gpu,
        system: false,
        byte_len: object.byte_len,
        backing: Backing::Unmapped { _held: held },
    })
}

/// Clears VRAM the CPU cannot reach.
pub trait VramClear: Send + Sync + core::fmt::Debug {
    /// Queue zeroing `bytes` of VRAM at framebuffer-aperture address
    /// `address`. The fence signals once the zeros have landed; nothing
    /// may read the range before then. An error queued nothing.
    ///
    /// Clears complete in the order they were queued, so a range freed
    /// before its clear ran is safe to hand out again: its next clear, and
    /// so its next owner, comes after.
    fn clear(
        &self,
        address: u64,
        bytes: u64,
    ) -> Result<Arc<dyn narf_filesystem::DrmFence>, FsError>;
}

/// Each DRM card's client VRAM heap, by card index.
static HEAPS: IrqSafeSpinLock<Vec<(u32, VramHeap)>> = IrqSafeSpinLock::new(Vec::new());

/// Let clients of DRM card `card` place buffers in `heap`, replacing any
/// earlier heap. Buffers already created keep their placement.
pub fn register_vram_heap(card: u32, heap: VramHeap) {
    let mut heaps = HEAPS.lock();
    heaps.retain(|(c, _)| *c != card);
    heaps.push((card, heap));
}

/// Stop placing new buffers of DRM card `card` in VRAM.
pub fn unregister_vram_heap(card: u32) {
    HEAPS.lock().retain(|(c, _)| *c != card);
}

/// A card's client VRAM heap in bytes: `(size, used)` of its CPU-visible
/// pool and of its pool past the BAR (0, 0 without one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeapUsage {
    pub visible: (u64, u64),
    pub unmapped: (u64, u64),
}

/// What DRM card `card`'s client VRAM heap holds, if it has one.
pub fn vram_heap_usage(card: u32) -> Option<HeapUsage> {
    let heap = vram_heap(card)?;
    let visible = heap.pool.size();
    let unmapped = heap.unmapped.as_ref().map_or((0, 0), |u| {
        (u.pool.size(), u.pool.size() - u.pool.available())
    });
    Some(HeapUsage {
        visible: (visible, visible - heap.pool.available()),
        unmapped,
    })
}

fn vram_heap(card: u32) -> Option<VramHeap> {
    HEAPS
        .lock()
        .iter()
        .find(|(c, _)| *c == card)
        .map(|(_, h)| h.clone())
}

/// `AMDGPU_GEM_DOMAIN_MASK`, from the mirror — it was hand-composed here
/// until the mirror gained the composite the C header actually defines.
const DOMAIN_MASK: u64 = uapi::AMDGPU_GEM_DOMAIN_MASK as u64;

/// The CPU/GTT/VRAM domains, which may be combined freely.
const NORMAL_DOMAINS: u64 = (uapi::AMDGPU_GEM_DOMAIN_CPU
    | uapi::AMDGPU_GEM_DOMAIN_GTT
    | uapi::AMDGPU_GEM_DOMAIN_VRAM) as u64;

/// `AMDGPU_GEM_CREATE_SETTABLE_MASK` — the create flags userspace may set.
///
/// Spelled out rather than referenced because the mask is the ABI: a flag not
/// in it is EINVAL, and silently accepting one would let a client believe it
/// got a property (encryption, say) that it did not.
/// Transcribed from `amdgpu_gem.h`, not inferred from the flag list — the two
/// differ. `VRAM_CONTIGUOUS` looks settable and is not (the kernel sets it on
/// the caller's behalf), and four that are easy to overlook are:
/// `VRAM_WIPE_ON_RELEASE`, `COHERENT`, `UNCACHED` and `EXT_COHERENT`.
const SETTABLE_FLAGS: u64 = (uapi::AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED
    | uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS
    | uapi::AMDGPU_GEM_CREATE_CPU_GTT_USWC
    | uapi::AMDGPU_GEM_CREATE_VRAM_CLEARED
    | uapi::AMDGPU_GEM_CREATE_VM_ALWAYS_VALID
    | uapi::AMDGPU_GEM_CREATE_EXPLICIT_SYNC
    | uapi::AMDGPU_GEM_CREATE_VRAM_WIPE_ON_RELEASE
    | uapi::AMDGPU_GEM_CREATE_ENCRYPTED
    | uapi::AMDGPU_GEM_CREATE_GFX12_DCC
    | uapi::AMDGPU_GEM_CREATE_DISCARDABLE
    | uapi::AMDGPU_GEM_CREATE_COHERENT
    | uapi::AMDGPU_GEM_CREATE_UNCACHED
    | uapi::AMDGPU_GEM_CREATE_EXT_COHERENT) as u64;

/// amdgpu_bo_create permits GTT fallback for ordinary VRAM-preferred BOs.
fn initial_allowed_domains(preferred: u64, flags: u64) -> u64 {
    if preferred == u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM)
        && flags & u64::from(uapi::AMDGPU_GEM_CREATE_DISCARDABLE) == 0
    {
        preferred | u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT)
    } else {
        preferred
    }
}

/// `amdgpu_gem_are_domains_valid`: the special domains (GDS, GWS, OA,
/// DOORBELL) are each exclusive — one at a time, and never mixed with
/// CPU/GTT/VRAM.
fn domains_valid(domains: u64) -> bool {
    let special = domains & (DOMAIN_MASK & !NORMAL_DOMAINS);
    if special == 0 {
        return true;
    }
    if domains & NORMAL_DOMAINS != 0 {
        return false;
    }
    // Exactly one bit.
    special & (special - 1) == 0
}

/// Where a buffer's memory came from, which decides how it is returned.
#[derive(Debug)]
enum Backing {
    /// Buddy blocks `(address, order)`, in buffer order.
    System(Vec<(u64, u8)>),
    /// A VRAM pool reservation, held for its drop, which returns it to the
    /// pool.
    Vram {
        _held: crate::amdgpu_vram::Reservation,
    },
    /// VRAM past the BAR, which the CPU cannot reach; returned on drop.
    Unmapped {
        _held: crate::amdgpu_vram::UnmappedReservation,
    },
    /// `GEM_USERPTR`: the caller's pinned pages, one per buffer page.
    User(Vec<narf_memory::address_space::UserPagePin>),
    /// An imported foreign dma-buf's RAM pages, one per buffer page, kept
    /// alive by the exporter's lease (its placement or dumb backing).
    Foreign {
        frames: Vec<u64>,
        _lease: ForeignLease,
    },
}
/// What keeps a foreign dma-buf's pages allocated.
pub(crate) struct ForeignLease(
    #[allow(dead_code, reason = "held for its drop")] pub(crate) Arc<dyn Send + Sync>,
);
impl core::fmt::Debug for ForeignLease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ForeignLease")
    }
}
/// Internal BO flag (outside every AMDGPU_GEM_CREATE_* bit): GPU mappings
/// of a READONLY userptr drop WRITEABLE. Never reported to userspace.
pub(crate) const BO_GPU_READONLY: u64 = 1 << 63;

/// Shared buffer identity and placement policy, independent of backing addresses.
#[derive(Debug)]
pub struct GemObject {
    /// Address leases pin this storage, independently of shared handles.
    placement: IrqSafeSpinLock<Arc<GemPlacement>>,
    /// Rounded allocation size, invariant across moves.
    pub byte_len: u64,
    /// `alignment` as requested, reported back by `GEM_OP`.
    alignment: u64,
    preferred_domains: AtomicU64,
    allowed_domains: AtomicU64,
    pub flags: u64,
    /// `GEM_METADATA`: what a DRI client tells its peer about the buffer,
    /// kept with the buffer so every handle to it sees the same.
    metadata: IrqSafeSpinLock<Metadata>,
    /// The DRM card whose open created it (None outside a card).
    card: Option<u32>,
    /// The reservation and name every PRIME export of it shares, as Linux
    /// keeps one dma_buf per GEM object.
    dma_buf: Arc<narf_filesystem::dma_buf::DmaBufObject>,
    /// `tbo.pin_count`: live [`ScanoutPin`]s. A pinned buffer never moves
    /// (no eviction, demotion or suspend eviction) until the last unpin.
    pin_count: AtomicU32,
}

/// One address-stable backing generation. Retain an Arc while raw CPU frames,
/// GPU PTEs, or deferred CPU fence writes can still access its addresses.
/// Sharing a GEM object or dma-buf name does not itself acquire an address lease.
#[derive(Debug)]
pub struct GemPlacement {
    /// What the CPU maps at the start of the buffer: the first system
    /// chunk, or the buffer's BAR window (0 for a buffer past the BAR,
    /// which the CPU cannot map). [`frames`](Self::frames) gives the rest.
    pub phys: u64,
    /// What the GPU's page-table entries carry for the first page: the
    /// first system chunk's address, or the physical VRAM address.
    /// [`gpu_at`](Self::gpu_at) gives any page.
    pub gpu: u64,
    /// The GPU reaches it as system memory (SYSTEM/SNOOPED entries).
    pub system: bool,
    /// Rounded up to a page, as `bo_size` is reported back.
    pub byte_len: u64,
    backing: Backing,
}

/// A CPU mapping retains both GEM identity and its address-stable backing.
#[derive(Debug)]
pub struct GemMapping {
    _object: Arc<GemObject>,
    placement: Arc<GemPlacement>,
}

impl core::ops::Deref for GemMapping {
    type Target = GemPlacement;
    fn deref(&self) -> &Self::Target {
        &self.placement
    }
}

/// A buffer pinned for scanout (`GemObject::pin_scanout`): it holds the
/// buffer and its VRAM placement, which nothing moves, evicts or frees
/// while any pin lives (amdgpu_bo_unpin on drop, which
/// amdgpu_dm_plane_helper_cleanup_fb runs only after the flip that
/// replaced the framebuffer).
#[derive(Debug)]
pub struct ScanoutPin {
    object: Arc<GemObject>,
    placement: Arc<GemPlacement>,
    /// The placement's GPU (frame-buffer aperture) address, which display
    /// fetch takes: amdgpu_bo_gpu_offset.
    address: u64,
}
impl ScanoutPin {
    /// amdgpu_bo_gpu_offset: where display fetches byte 0.
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn object(&self) -> &Arc<GemObject> {
        &self.object
    }
    /// The pinned placement's size.
    pub fn byte_len(&self) -> u64 {
        self.placement.byte_len
    }
    /// The pinned placement, for CPU copies of a buffer the CPU reaches.
    pub fn placement(&self) -> &Arc<GemPlacement> {
        &self.placement
    }
}
impl Drop for ScanoutPin {
    fn drop(&mut self) {
        self.object.pin_count.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `amdgpu_bo_user`'s tiling flags and opaque metadata blob.
#[derive(Debug, Default)]
struct Metadata {
    tiling: u64,
    flags: u64,
    data: Vec<u8>,
}

impl GemObject {
    /// Refuse CPU/deferred/unregistered leases before asynchronous copying,
    /// not only at commit: a deferred CPU writer could race staging reads.
    pub(crate) fn check_transfer_source(
        &self,
        source: &Arc<GemPlacement>,
        gpu_leases: usize,
    ) -> Result<(), FsError> {
        let placement = self.placement.lock();
        if !Arc::ptr_eq(&placement, source)
            || Arc::strong_count(&placement) != gpu_leases.saturating_add(2)
            || Arc::weak_count(&placement) != 0
        {
            return Err(FsError::Busy);
        }
        Ok(())
    }
    pub(crate) fn allows_system(&self) -> bool {
        self.allowed_domains.load(Ordering::Acquire)
            & u64::from(uapi::AMDGPU_GEM_DOMAIN_CPU | uapi::AMDGPU_GEM_DOMAIN_GTT)
            != 0
    }
    pub(crate) fn commit_transfer(
        &self,
        source: &Arc<GemPlacement>,
        destination: Arc<GemPlacement>,
    ) -> Result<(), FsError> {
        let mut placement = self.placement.lock();
        let allowed = if destination.system {
            self.allows_system()
        } else {
            self.allowed_domains.load(Ordering::Acquire) & u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM)
                != 0
        };
        if !allowed
            || self.pinned()
            || !Arc::ptr_eq(&placement, source)
            || Arc::strong_count(&placement) != 2
            || Arc::weak_count(&placement) != 0
        {
            return Err(FsError::Busy);
        }
        let readback = source.hidden_address().is_some() && destination.system;
        let upload = source.system
            && destination.hidden_address().is_some()
            && self.flags & u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS) != 0;
        if (!readback && !upload) || destination.byte_len != self.byte_len {
            return Err(FsError::InvalidData);
        }
        if !self
            .dma_buf
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Bookkeep)
            .is_empty()
        {
            return Err(FsError::Busy);
        }
        *placement = destination;
        Ok(())
    }
    pub fn preferred_domains(&self) -> u64 {
        self.preferred_domains.load(Ordering::Acquire)
    }
    /// Whether a [`ScanoutPin`] holds the buffer where it is.
    pub fn pinned(&self) -> bool {
        self.pin_count.load(Ordering::Acquire) != 0
    }
    /// The tiling flags `GEM_METADATA` last set (amdgpu_bo_get_tiling_flags).
    pub fn tiling_flags(&self) -> u64 {
        self.metadata.lock().tiling
    }
    /// amdgpu_dm_plane_helper_prepare_fb's pin of a framebuffer's buffer:
    /// `amdgpu_bo_pin(rbo, amdgpu_display_supported_domains(...))` with
    /// AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS. On a dGPU (no gpu_vm_support) the
    /// display domain is VRAM alone, so a GFX12 DCC buffer, like any other,
    /// is scanned out of VRAM only: a buffer in system memory moves to VRAM
    /// first (amdgpu_bo_pin's validation), which needs it unshared by any
    /// other address lease and idle; a buffer VRAM is not allowed for, a
    /// userptr or a foreign dma-buf is refused (as amdgpu_bo_pin refuses a
    /// userptr). A VRAM placement is one reservation, so it is contiguous.
    /// The pin keeps the buffer, and that placement, until it drops.
    pub fn pin_scanout(self: &Arc<Self>) -> Result<ScanoutPin, FsError> {
        if self.allowed_domains.load(Ordering::Acquire) & u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM)
            == 0
        {
            return Err(FsError::InvalidData);
        }
        if self.system() && !self.pinned() {
            self.relocate(true)?;
        }
        let placement = self.placement.lock();
        let address = match &placement.backing {
            Backing::Vram { _held } => _held.address(),
            Backing::Unmapped { _held } => _held.address(),
            _ => return Err(FsError::Busy),
        };
        // Under the placement lock: no move can start between the check and
        // the count, and the pin's lease alone already stops one.
        self.pin_count.fetch_add(1, Ordering::AcqRel);
        Ok(ScanoutPin {
            object: Arc::clone(self),
            placement: Arc::clone(&placement),
            address,
        })
    }
    /// Acquire an address lease before exposing physical frames or PTEs.
    pub fn placement(&self) -> Arc<GemPlacement> {
        Arc::clone(&self.placement.lock())
    }

    pub fn mapping(self: &Arc<Self>) -> Arc<GemMapping> {
        Arc::new(GemMapping {
            _object: self.clone(),
            placement: self.placement(),
        })
    }

    pub(crate) fn relocate(&self, to_vram: bool) -> Result<(), FsError> {
        let target = if to_vram {
            u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM)
        } else {
            u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT | uapi::AMDGPU_GEM_DOMAIN_CPU)
        };
        let mut placement = self.placement.lock();
        if self.allowed_domains.load(Ordering::Acquire) & target == 0
            || self.pinned()
            || matches!(
                placement.backing,
                Backing::User(_) | Backing::Foreign { .. }
            )
        {
            return Err(FsError::Busy);
        }
        let backing = Arc::get_mut(&mut placement).ok_or(FsError::Busy)?;
        if !self
            .dma_buf
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Bookkeep)
            .is_empty()
        {
            return Err(FsError::Busy);
        }
        backing.relocate(to_vram, self.card, self.alignment)
    }

    pub fn phys(&self) -> u64 {
        self.placement().phys
    }
    pub fn gpu(&self) -> u64 {
        self.placement().gpu
    }
    pub fn system(&self) -> bool {
        self.placement().system
    }
    pub fn gpu_at(&self, offset: u64) -> Option<u64> {
        self.placement().gpu_at(offset)
    }
    pub fn load_u64(&self, offset: u64) -> Option<u64> {
        self.placement().load_u64(offset)
    }
    pub fn store_u64(&self, offset: u64, value: u64) -> Option<()> {
        self.placement().store_u64(offset, value)
    }
    pub fn cpu_visible(&self) -> bool {
        self.placement().cpu_visible()
    }
    /// Created by `GEM_USERPTR` (amdgpu_ttm_tt_get_usermm).
    pub fn is_userptr(&self) -> bool {
        matches!(self.placement().backing, Backing::User(_))
    }
    pub fn frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        self.placement().frames(offset, len)
    }
    pub fn domain(&self) -> u32 {
        self.placement().domain()
    }

    /// The DRM card whose open created the buffer.
    pub fn card(&self) -> Option<u32> {
        self.card
    }

    /// The reservation and name its PRIME exports share.
    pub fn dma_buf(&self) -> &Arc<narf_filesystem::dma_buf::DmaBufObject> {
        &self.dma_buf
    }
}

impl GemPlacement {
    pub(crate) fn hidden_address(&self) -> Option<u64> {
        match &self.backing {
            Backing::Unmapped { _held } => Some(_held.address()),
            _ => None,
        }
    }
    pub(crate) fn new_system(byte_len: u64) -> Result<Self, FsError> {
        if byte_len == 0 || byte_len % PAGE_SIZE != 0 {
            return Err(FsError::InvalidData);
        }
        let chunks = alloc_system(byte_len / PAGE_SIZE)?;
        let phys = chunks[0].0;
        let placement = Self {
            phys,
            gpu: phys,
            system: true,
            byte_len,
            backing: Backing::System(chunks),
        };
        if let Backing::System(chunks) = &placement.backing {
            for &(at, order) in chunks {
                crate::amdgpu_vm::make_pte(at + (PAGE_SIZE << order) - PAGE_SIZE, 0)?;
            }
        }
        Ok(placement)
    }
    /// # Safety
    /// `source` names `bytes` CPU-readable bytes in a live, exclusively held
    /// staging allocation. This newly allocated System backing is private.
    pub(crate) unsafe fn read_staging(
        &mut self,
        offset: u64,
        source: *const u8,
        bytes: usize,
    ) -> Result<(), FsError> {
        if !matches!(self.backing, Backing::System(_))
            || offset
                .checked_add(bytes as u64)
                .is_none_or(|end| end > self.byte_len)
        {
            return Err(FsError::InvalidData);
        }
        let mut copied = 0;
        while copied < bytes {
            let (phys, run) = self
                .locate(offset + copied as u64)
                .ok_or(FsError::InvalidData)?;
            let count = (run as usize).min(bytes - copied);
            // SAFETY: caller retains and bounds the source; locate bounds
            // each disjoint destination inside this private buddy backing.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.add(copied),
                    narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
                    count,
                );
            }
            copied += count;
        }
        Ok(())
    }
    /// # Safety
    /// The caller excludes CPU/GPU writers of this System source and owns
    /// `bytes` writable destination bytes in a private staging allocation.
    pub(crate) unsafe fn write_staging(
        &self,
        offset: u64,
        destination: *mut u8,
        bytes: usize,
    ) -> Result<(), FsError> {
        if !matches!(self.backing, Backing::System(_))
            || offset
                .checked_add(bytes as u64)
                .is_none_or(|end| end > self.byte_len)
        {
            return Err(FsError::InvalidData);
        }
        let mut copied = 0;
        while copied < bytes {
            let (phys, run) = self
                .locate(offset + copied as u64)
                .ok_or(FsError::InvalidData)?;
            let count = (run as usize).min(bytes - copied);
            // SAFETY: source ranges are retained buddy chunks and locate
            // bounds them; the caller bounds and exclusively owns staging.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
                    destination.add(copied),
                    count,
                );
            }
            copied += count;
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        Ok(())
    }
    /// Copy a uniquely leased backing; publish only after the copy succeeds.
    fn relocate(
        &mut self,
        to_vram: bool,
        card: Option<u32>,
        alignment: u64,
    ) -> Result<(), FsError> {
        if self.system != to_vram {
            return Ok(());
        }
        if to_vram {
            let Backing::System(chunks) = &self.backing else {
                return Err(FsError::Unsupported);
            };
            let heap = card.and_then(vram_heap).ok_or(FsError::NoDevice)?;
            let alignment = alignment
                .max(PAGE_SIZE)
                .checked_next_power_of_two()
                .ok_or(FsError::InvalidData)?;
            let reservation = heap
                .pool
                .reserve_aligned(self.byte_len, alignment)
                .map_err(|_| FsError::NoSpace)?;
            let gpu = reservation
                .address()
                .checked_sub(heap.fb_base)
                .and_then(|a| a.checked_add(heap.fb_offset))
                .ok_or(FsError::InvalidData)?;
            crate::amdgpu_vm::make_pte(gpu, 0)?;
            crate::amdgpu_vm::make_pte(gpu + self.byte_len - PAGE_SIZE, 0)?;
            let map = reservation.mapping();
            let mut offset = 0;
            for &(phys, order) in chunks {
                let bytes = PAGE_SIZE << order;
                // SAFETY: exclusive BO and new reservation, disjoint mappings;
                // chunks exactly cover byte_len and reservation bounds it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
                        (map.virt + offset) as *mut u8,
                        bytes as usize,
                    );
                }
                offset += bytes;
            }
            core::sync::atomic::fence(Ordering::SeqCst);
            let old = core::mem::replace(&mut self.backing, Backing::Vram { _held: reservation });
            self.phys = map.phys.raw();
            self.gpu = gpu;
            self.system = false;
            if let Backing::System(chunks) = old {
                free_chunks(&chunks);
                GTT_USED.fetch_sub(self.byte_len, Ordering::Relaxed);
            }
        } else {
            let Backing::Vram { _held } = &self.backing else {
                return Err(FsError::Unsupported);
            };
            let source = _held.mapping();
            let chunks = alloc_system(self.byte_len / PAGE_SIZE)?;
            if chunks.iter().any(|&(phys, order)| {
                crate::amdgpu_vm::make_pte(phys + (PAGE_SIZE << order) - PAGE_SIZE, 0).is_err()
            }) {
                free_chunks(&chunks);
                GTT_USED.fetch_sub(self.byte_len, Ordering::Relaxed);
                return Err(FsError::InvalidData);
            }
            let phys = chunks[0].0;
            let mut offset = 0;
            for &(at, order) in &chunks {
                let bytes = PAGE_SIZE << order;
                // SAFETY: exclusive BO and newly allocated system chunks;
                // source and destination cover precisely this BO's bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (source.virt + offset) as *const u8,
                        narf_memory::PhysAddr::new(at).kernel_mut_ptr::<u8>(),
                        bytes as usize,
                    );
                }
                offset += bytes;
            }
            core::sync::atomic::fence(Ordering::SeqCst);
            let old = core::mem::replace(&mut self.backing, Backing::System(chunks));
            self.phys = phys;
            self.gpu = phys;
            self.system = true;
            drop(old);
        }
        Ok(())
    }
    /// The physical address of byte `offset` (inside the buffer) and how
    /// many bytes from there lie in the same contiguous chunk.
    fn locate(&self, offset: u64) -> Option<(u64, u64)> {
        if offset >= self.byte_len {
            return None;
        }
        match &self.backing {
            Backing::System(chunks) => {
                let mut start = 0;
                for &(phys, order) in chunks {
                    let len = PAGE_SIZE << order;
                    if offset < start + len {
                        return Some((phys + offset - start, start + len - offset));
                    }
                    start += len;
                }
                None
            }
            Backing::User(pins) => {
                let page = pins.get((offset / PAGE_SIZE) as usize)?;
                let within = offset % PAGE_SIZE;
                Some((page.phys().raw() + within, PAGE_SIZE - within))
            }
            Backing::Foreign { frames, .. } => {
                let page = frames.get((offset / PAGE_SIZE) as usize)?;
                let within = offset % PAGE_SIZE;
                Some((page + within, PAGE_SIZE - within))
            }
            _ => Some((self.gpu + offset, self.byte_len - offset)),
        }
    }

    /// The address page-table entries carry for byte `offset` of the
    /// buffer, which must lie inside it.
    pub fn gpu_at(&self, offset: u64) -> Option<u64> {
        self.locate(offset).map(|(at, _)| at)
    }

    /// The CPU address of byte `offset` of the buffer, if 8 bytes from
    /// there lie inside it.
    fn cpu_ptr(&self, offset: u64) -> Option<*mut u8> {
        if offset.checked_add(8)? > self.byte_len {
            return None;
        }
        Some(match &self.backing {
            Backing::System(_) | Backing::User(_) | Backing::Foreign { .. } => {
                let (at, run) = self.locate(offset)?;
                if run < 8 {
                    return None;
                }
                narf_memory::PhysAddr::new(at).kernel_mut_ptr::<u8>()
            }
            Backing::Vram { _held } => (_held.mapping().virt + offset) as *mut u8,
            Backing::Unmapped { .. } => return None,
        })
    }

    /// Copy `out.len()` bytes from byte `offset` of a buffer the CPU
    /// reaches (system pages through the direct map, VRAM through its BAR
    /// window); None past its end or for VRAM beyond the BAR.
    pub fn read_bytes(&self, offset: u64, out: &mut [u8]) -> Option<()> {
        let end = offset.checked_add(out.len() as u64)?;
        if end > self.byte_len {
            return None;
        }
        match &self.backing {
            Backing::Unmapped { .. } => return None,
            Backing::Vram { _held } => {
                let at = _held.mapping().virt + offset;
                // SAFETY: the reservation's BAR window covers `byte_len`
                // bytes and lives while `self` does; bounds checked above.
                unsafe {
                    core::ptr::copy_nonoverlapping(at as *const u8, out.as_mut_ptr(), out.len())
                };
            }
            _ => {
                let mut done = 0;
                while done < out.len() {
                    let (phys, run) = self.locate(offset + done as u64)?;
                    let count = (run as usize).min(out.len() - done);
                    // SAFETY: locate bounds the run inside this buffer's
                    // retained frames, which the kernel maps.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
                            out.as_mut_ptr().add(done),
                            count,
                        );
                    }
                    done += count;
                }
            }
        }
        Some(())
    }

    /// The 64-bit value at byte `offset`, read by the CPU.
    pub fn load_u64(&self, offset: u64) -> Option<u64> {
        let at = self.cpu_ptr(offset)?;
        // SAFETY: `cpu_ptr` bounds 8 bytes inside this buffer's kernel
        // mapping (the direct map, or the reservation's BAR window), live
        // while `self` is.
        Some(u64::from_le_bytes(unsafe {
            core::ptr::read_volatile(at.cast::<[u8; 8]>())
        }))
    }

    /// Store `value` at byte `offset` from the CPU.
    pub fn store_u64(&self, offset: u64, value: u64) -> Option<()> {
        let at = self.cpu_ptr(offset)?;
        // SAFETY: as `load_u64`.
        unsafe { core::ptr::write_volatile(at.cast::<[u8; 8]>(), value.to_le_bytes()) };
        Some(())
    }

    /// Whether the CPU can map the buffer (it is not past the BAR).
    pub fn cpu_visible(&self) -> bool {
        !matches!(self.backing, Backing::Unmapped { .. })
    }

    /// The physical frames backing `len` bytes from byte `offset`, both
    /// page aligned and inside the buffer, for a CPU mapping.
    pub fn frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if !self.cpu_visible() {
            return Err(FsError::OperationNotPermitted);
        }
        let len = len as u64;
        if offset % PAGE_SIZE != 0
            || len == 0
            || len % PAGE_SIZE != 0
            || offset
                .checked_add(len)
                .is_none_or(|end| end > self.byte_len)
        {
            return Err(FsError::InvalidData);
        }
        (0..len / PAGE_SIZE)
            .map(|i| match self.backing {
                Backing::System(_) | Backing::User(_) | Backing::Foreign { .. } => self
                    .locate(offset + i * PAGE_SIZE)
                    .map(|(at, _)| at)
                    .ok_or(FsError::InvalidData),
                _ => Ok(self.phys + offset + i * PAGE_SIZE),
            })
            .collect()
    }

    /// Where the buffer lives: `AMDGPU_GEM_DOMAIN_VRAM` or `_GTT`.
    pub fn domain(&self) -> u32 {
        if self.system {
            uapi::AMDGPU_GEM_DOMAIN_GTT
        } else {
            uapi::AMDGPU_GEM_DOMAIN_VRAM
        }
    }
}

impl Drop for GemPlacement {
    fn drop(&mut self) {
        // Address leases outlive CPU/GPU mappings and deferred user-fence
        // writes; the last lease returns this backing to its allocator.
        if let Backing::System(chunks) = &self.backing {
            free_chunks(chunks);
            GTT_USED.fetch_sub(self.byte_len, Ordering::Relaxed);
        }
    }
}

type GemTable = IrqSafeSpinLock<BTreeMap<u32, Arc<GemObject>>>;
static GEM_TABLES: IrqSafeSpinLock<Vec<(u32, Weak<GemTable>)>> = IrqSafeSpinLock::new(Vec::new());

// Sharding bounds storage without imposing a lifetime requirement on card
// registration. Collisions only serialize unrelated cards.
static PLACEMENT_GATES: [narf_lib::mutex::Mutex<()>; 16] =
    [const { narf_lib::mutex::Mutex::new(()) }; 16];

/// Excludes new jobs and VA edits while a card's mappings are rebound.
pub(crate) struct PlacementGuard {
    card: u32,
    _held: narf_lib::mutex::MutexGuard<'static, ()>,
}
impl PlacementGuard {
    pub(crate) fn card(&self) -> u32 {
        self.card
    }
}
pub(crate) async fn lock_placement(card: u32) -> PlacementGuard {
    PlacementGuard {
        card,
        _held: PLACEMENT_GATES[card as usize % PLACEMENT_GATES.len()]
            .lock()
            .await,
    }
}
pub(crate) fn try_placement(card: u32) -> Option<PlacementGuard> {
    Some(PlacementGuard {
        card,
        _held: PLACEMENT_GATES[card as usize % PLACEMENT_GATES.len()].try_lock()?,
    })
}

/// Reclaim idle client VRAM; address leases and unsignalled fences pin it.
/// A shared handle or PRIME export alone does not pin placement.
fn evict_visible(card: u32, pool: &crate::amdgpu_vram::Pool, bytes: u64, alignment: u64) {
    let tables: Vec<_> = GEM_TABLES
        .lock()
        .iter()
        .filter(|(c, _)| *c == card)
        .filter_map(|(_, table)| table.upgrade())
        .collect();
    for table in tables {
        let objects: Vec<_> = table.lock().values().cloned().collect();
        for object in objects {
            if !object.system() && !object.pinned() {
                let _ = object.relocate(false);
                if pool.reserve_aligned(bytes, alignment).is_ok() {
                    return;
                }
            }
        }
    }
}

/// System suspend (`ttm_resource_manager_evict_all`): move every VRAM buffer
/// of `gate`'s card to system memory, waiting for its jobs, whatever its
/// allowed domains (each gains GTT for the move). A pinned buffer (a
/// framebuffer still scanned out) is not on TTM's LRU and stays where it
/// is, as `ttm_resource_manager_evict_all` leaves it. Returns every touched
/// buffer with its original allowed domains, which the caller restores on
/// resume or on failure ([`restore_domains`]); the first refusal stops the
/// eviction and is returned with the list so far.
pub(crate) async fn evict_all(
    gate: &PlacementGuard,
) -> (Vec<(Arc<GemObject>, u64)>, Result<(), FsError>) {
    let card = gate.card();
    let tables: Vec<_> = GEM_TABLES
        .lock()
        .iter()
        .filter(|(c, _)| *c == card)
        .filter_map(|(_, table)| table.upgrade())
        .collect();
    let mut touched = Vec::new();
    for table in tables {
        let objects: Vec<_> = table.lock().values().cloned().collect();
        for object in objects {
            if object.system()
                || object.pinned()
                || touched.iter().any(|(o, _)| Arc::ptr_eq(o, &object))
            {
                continue;
            }
            let original = object
                .allowed_domains
                .fetch_or(u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT), Ordering::AcqRel);
            touched.push((object.clone(), original));
            if let Err(error) = crate::amdgpu_vm::relocate(gate, &object, false).await {
                return (touched, Err(error));
            }
        }
    }
    (touched, Ok(()))
}
/// Put back the allowed domains [`evict_all`] widened. Buffers stay where
/// they are until validation promotes them.
pub(crate) fn restore_domains(touched: Vec<(Arc<GemObject>, u64)>) {
    for (object, original) in touched {
        object.allowed_domains.store(original, Ordering::Release);
    }
}

/// A strict VRAM allocation may park to reclaim buffers mapped by idle VMs.
/// The first create performs all ABI validation; a failure leaves its input
/// union untouched. Ordinary allocations retain their immediate GTT fallback.
pub async fn dispatch_async(
    cmd: u32,
    arg: usize,
    state: &GemState,
) -> Option<Result<u64, FsError>> {
    if drm_uapi::ioc_nr(cmd) != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_CREATE {
        return None;
    }
    let result = create(state, arg);
    if result != Err(FsError::NoSpace) {
        return Some(result);
    }
    let Some(card) = state.card else {
        return Some(result);
    };
    let Some(heap) = vram_heap(card) else {
        return Some(result);
    };
    // SAFETY: same validated ioctl pointer contract as create; copy_in bounds
    // and SMAP-brackets a fresh input snapshot. The retry validates it again.
    let bytes = match unsafe { copy_in(arg, 32) } {
        Ok(bytes) => bytes,
        Err(error) => return Some(Err(error)),
    };
    let domains = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    if domains & u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM) == 0 {
        return Some(result);
    }
    let Some(size) =
        u64::from_le_bytes(bytes[..8].try_into().unwrap()).checked_next_multiple_of(PAGE_SIZE)
    else {
        return Some(Err(FsError::InvalidData));
    };
    let Some(align) = u64::from_le_bytes(bytes[8..16].try_into().unwrap())
        .max(PAGE_SIZE)
        .checked_next_power_of_two()
    else {
        return Some(Err(FsError::InvalidData));
    };
    let gate = lock_placement(card).await;
    let tables: Vec<_> = GEM_TABLES
        .lock()
        .iter()
        .filter(|(c, _)| *c == card)
        .filter_map(|(_, table)| table.upgrade())
        .collect();
    for table in tables {
        let objects: Vec<_> = table.lock().values().cloned().collect();
        for object in objects {
            if object.system() {
                continue;
            }
            let _ = crate::amdgpu_vm::relocate(&gate, &object, false).await;
            let no_cpu = u64::from_le_bytes(bytes[24..32].try_into().unwrap())
                & u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS)
                != 0;
            if heap.pool.reserve_aligned(size, align).is_ok()
                || (no_cpu
                    && heap
                        .unmapped
                        .as_ref()
                        .is_some_and(|u| u.pool.reserve_aligned(size, align).is_ok()))
            {
                return Some(create(state, arg));
            }
        }
    }
    Some(result)
}

/// Per-open GEM state. One of these per `/dev/dri/*` open on an amdgpu card.
#[derive(Debug)]
pub struct GemState {
    objects: IrqSafeSpinLock<Option<Arc<GemTable>>>,
    next_handle: AtomicU32,
    /// The DRM card whose VRAM heap this open may place buffers in.
    card: Option<u32>,
}

impl Default for GemState {
    fn default() -> Self {
        Self::new()
    }
}

impl GemState {
    /// Acquire a revocable CPU mapping and its exact frame snapshot together.
    pub fn mmap_backing(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<narf_filesystem::MmapBacking, FsError> {
        let handle = u32::try_from(offset >> 12).map_err(|_| FsError::InvalidData)?;
        let object = self.get(handle).ok_or(FsError::InvalidData)?;
        cpu_mapping::backing(object, 0, len)
    }
    /// An open with no VRAM heap: every buffer is system memory.
    pub const fn new() -> Self {
        GemState {
            objects: IrqSafeSpinLock::new(None),
            next_handle: AtomicU32::new(HANDLE_BASE),
            card: None,
        }
    }

    /// An open of DRM card `index`, placing VRAM buffers in its heap once
    /// one is registered.
    pub const fn for_card(index: u32) -> Self {
        GemState {
            objects: IrqSafeSpinLock::new(None),
            next_handle: AtomicU32::new(HANDLE_BASE),
            card: Some(index),
        }
    }

    fn insert(&self, object: GemObject) -> Result<u32, FsError> {
        self.insert_shared(Arc::new(object))
    }

    fn insert_shared(&self, object: Arc<GemObject>) -> Result<u32, FsError> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        // Wrapping back into the dumb-handle space would make two different
        // objects answer to one number. Refuse instead.
        if handle < HANDLE_BASE {
            return Err(FsError::NoSpace);
        }
        self.table().lock().insert(handle, object);
        Ok(handle)
    }

    /// `drm_gem_prime_fd_to_handle` for a buffer another open of the same
    /// card exported: the handle this open already has for it, or a new
    /// one. A buffer of another card is refused (`InvalidData`), as is one
    /// not created on any card: Linux takes the native path only when
    /// `obj->dev == dev` (`amdgpu_gem_prime_import`; card indices are never
    /// reused, so the index is the device), and NARF has no attachment path
    /// for a foreign buffer.
    /// The DRM card this open belongs to.
    pub(crate) fn card(&self) -> Option<u32> {
        self.card
    }
    pub fn import(&self, object: &Arc<GemObject>) -> Result<u32, FsError> {
        if object.card.is_none() || object.card != self.card {
            return Err(FsError::InvalidData);
        }
        let existing = self
            .table()
            .lock()
            .iter()
            .find(|(_, o)| Arc::ptr_eq(o, object))
            .map(|(h, _)| *h);
        match existing {
            Some(handle) => Ok(handle),
            None => self.insert_shared(Arc::clone(object)),
        }
    }

    /// `amdgpu_gem_prime_import` of a foreign dma-buf (another device's,
    /// attached as GTT): a GTT-only buffer over the exporter's RAM `frames`
    /// (one per page), sharing its reservation for implicit sync and kept
    /// alive by `lease`. Its placement never moves.
    pub(crate) fn import_foreign(
        &self,
        frames: Vec<u64>,
        lease: ForeignLease,
        dma_buf: Arc<narf_filesystem::dma_buf::DmaBufObject>,
    ) -> Result<u32, FsError> {
        if self.card.is_none() || frames.is_empty() {
            return Err(FsError::InvalidData);
        }
        for &frame in &frames {
            if frame % PAGE_SIZE != 0 {
                return Err(FsError::InvalidData);
            }
            crate::amdgpu_vm::make_pte(frame, 0)?;
        }
        let byte_len = frames.len() as u64 * PAGE_SIZE;
        let first = frames[0];
        let gtt = u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT);
        self.insert(GemObject {
            placement: IrqSafeSpinLock::new(Arc::new(GemPlacement {
                phys: first,
                gpu: first,
                system: true,
                byte_len,
                backing: Backing::Foreign {
                    frames,
                    _lease: lease,
                },
            })),
            byte_len,
            alignment: PAGE_SIZE,
            preferred_domains: AtomicU64::new(gtt),
            allowed_domains: AtomicU64::new(gtt),
            flags: 0,
            metadata: IrqSafeSpinLock::new(Metadata::default()),
            card: self.card,
            dma_buf,
            pin_count: AtomicU32::new(0),
        })
    }

    fn table(&self) -> Arc<GemTable> {
        let mut table = self.objects.lock();
        Arc::clone(table.get_or_insert_with(|| {
            let table = Arc::new(IrqSafeSpinLock::new(BTreeMap::new()));
            if let Some(card) = self.card {
                let mut tables = GEM_TABLES.lock();
                tables.retain(|(_, t)| t.strong_count() != 0);
                tables.push((card, Arc::downgrade(&table)));
            }
            table
        }))
    }
    fn get(&self, handle: u32) -> Option<Arc<GemObject>> {
        self.table().lock().get(&handle).cloned()
    }
    fn validated(&self, handle: u32) -> Option<Arc<GemObject>> {
        let object = self.get(handle)?;
        let target_vram = object.preferred_domains() & u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM) != 0;
        if target_vram == object.system() {
            let _ = object.relocate(target_vram);
        }
        Some(object)
    }

    /// Drop this open's reference. The frames are freed when the last
    /// reference goes, which is not necessarily here — a buffer still mapped
    /// into a process stays alive until the mapping is torn down.
    fn remove(&self, handle: u32) -> bool {
        self.table().lock().remove(&handle).is_some()
    }

    /// The open's GEM table entry for `handle`, by its public name.
    pub(crate) fn lookup(&self, handle: u32) -> Option<Arc<GemObject>> {
        self.validated(handle)
    }

    /// The object named by `handle`, for the VM layer's range checks.
    pub fn object(&self, handle: u32) -> Option<Arc<GemObject>> {
        self.validated(handle)
    }

    /// Whether `handle` belongs to this table at all, so `GEM_CLOSE` can tell
    /// an amdgpu handle from a dumb one without consulting both.
    pub fn owns(&self, handle: u32) -> bool {
        handle >= HANDLE_BASE && self.get(handle).is_some()
    }

    /// The object an `mmap` of `len` bytes at `offset` maps, which the
    /// mapping holds until it is torn down (`FileOps::mmap_lifetime`), as
    /// Linux's VMA holds its GEM object.
    pub fn mapping_object(&self, offset: u64, len: usize) -> Option<Arc<GemMapping>> {
        let handle = u32::try_from(offset >> 12).ok()?;
        if self.get(handle)?.flags & u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS) != 0 {
            return None;
        }
        self.validated(handle)
            .filter(|o| len as u64 <= o.byte_len)
            .map(|o| o.mapping())
    }

    /// Resolve an `mmap` offset to the object's physical frames.
    ///
    /// The offset is the handle shifted by the page shift, which is how the
    /// dumb path encodes it too — there is no separate offset allocator, so an
    /// offset cannot name an object this open does not hold.
    pub fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        let handle = u32::try_from(offset >> 12).map_err(|_| FsError::InvalidData)?;
        let object = self.get(handle).ok_or(FsError::InvalidData)?;
        if object.flags & u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS) != 0 {
            return Err(FsError::OperationNotPermitted);
        }
        if len as u64 > object.byte_len {
            return Err(FsError::InvalidData);
        }
        if !object.cpu_visible() {
            return Err(FsError::OperationNotPermitted);
        }
        let rounded = (len as u64).div_ceil(PAGE_SIZE) * PAGE_SIZE;
        object.frames(0, rounded as usize)
    }
}

/// Bytes of system memory GEM buffers hold, against [`gtt_limit`].
static GTT_USED: AtomicU64 = AtomicU64::new(0);

/// How much system memory GEM buffers may hold in all: half of RAM, TTM's
/// default page limit (ttm_tt_pages_limit), which amdgpu also reports as
/// its GTT size.
pub fn gtt_limit() -> u64 {
    (narf_memory::frame::stats().total as u64 * PAGE_SIZE) / 2
}

/// Bytes of system memory GEM buffers hold now.
pub fn gtt_used() -> u64 {
    GTT_USED.load(Ordering::Relaxed)
}

/// Return buddy blocks to the allocator.
fn free_chunks(chunks: &[(u64, u8)]) {
    for &(phys, order) in chunks {
        let frame = narf_memory::PhysFrame::containing(narf_memory::PhysAddr::new(phys));
        narf_memory::frame::free_pages(frame, order);
    }
}

/// `pages` of zeroed system memory as buddy blocks in buffer order: the
/// binary decomposition of `pages`, each block split in two when the
/// allocator has none that large, within the GTT limit.
fn alloc_system(pages: u64) -> Result<Vec<(u64, u8)>, FsError> {
    let bytes = pages * PAGE_SIZE;
    let limit = gtt_limit();
    GTT_USED
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            used.checked_add(bytes).filter(|&total| total <= limit)
        })
        .map_err(|_| FsError::NoSpace)?;
    let mut chunks: Vec<(u64, u8)> = Vec::new();
    // Orders still to allocate, largest first; a failed one is retried as
    // two of the next order down.
    let mut wanted: Vec<u8> = Vec::new();
    for order in (0..=63u8).rev() {
        let order_pages = 1u64.checked_shl(u32::from(order)).unwrap_or(0);
        if pages & order_pages == 0 {
            continue;
        }
        // Blocks above the allocator's largest are several of its largest.
        let max = narf_memory::buddy::MAX_ORDER;
        if order > max {
            // The GTT limit, checked above, bounds the count.
            wanted.extend(core::iter::repeat_n(max, 1usize << (order - max)));
        } else {
            wanted.push(order);
        }
    }
    let result = (|| {
        let mut at = 0;
        while at < wanted.len() {
            let order = wanted[at];
            match narf_memory::frame::alloc_pages_on(0, order) {
                Ok(frame) => {
                    let phys = frame.start_address().raw();
                    chunks.try_reserve(1).map_err(|_| {
                        narf_memory::frame::free_pages(frame, order);
                        FsError::NoSpace
                    })?;
                    chunks.push((phys, order));
                    at += 1;
                }
                Err(_) if order > 0 => {
                    wanted.try_reserve(1).map_err(|_| FsError::NoSpace)?;
                    wanted[at] = order - 1;
                    wanted.insert(at + 1, order - 1);
                }
                Err(_) => return Err(FsError::NoSpace),
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        free_chunks(&chunks);
        GTT_USED.fetch_sub(bytes, Ordering::Relaxed);
        return Err(e);
    }
    // Zero before userspace or the GPU can see it. This is not optional:
    // the pages come from the kernel's own allocator and may hold anything.
    for &(phys, order) in &chunks {
        // SAFETY: the block covers `1 << order` pages at `phys`, which the
        // kernel maps at a fixed offset, and is this buffer's alone.
        unsafe {
            core::ptr::write_bytes(
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
                0,
                (PAGE_SIZE << order) as usize,
            );
        }
    }
    Ok(chunks)
}

/// `amdgpu_gem_create_ioctl`.
fn create(state: &GemState, arg: usize) -> Result<u64, FsError> {
    let size = core::mem::size_of::<uapi::DrmAmdgpuGemCreateIn>();
    // SAFETY: `arg` is the ioctl pointer the trap layer validated (or kernel-
    // owned on the test path); `copy_in` bounds-checks and SMAP-brackets.
    let bytes = unsafe { copy_in(arg, size)? };
    let bo_size = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let alignment = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let domains = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let flags = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

    // The three validations `amdgpu_gem_create_ioctl` runs before allocating.
    if flags & !SETTABLE_FLAGS != 0 {
        return Err(FsError::InvalidData);
    }
    if domains & !DOMAIN_MASK != 0 || !domains_valid(domains) {
        return Err(FsError::InvalidData);
    }
    // There is no TMZ engine, so encryption cannot be honoured. Linux refuses
    // the flag on a part without TMZ rather than ignoring it, and a client
    // that asked for an encrypted buffer must not be handed a plain one.
    if flags & uapi::AMDGPU_GEM_CREATE_ENCRYPTED as u64 != 0 {
        return Err(FsError::InvalidData);
    }
    // The special domains are register-file apertures, not memory: GDS, GWS
    // and OA live in the shader core and DOORBELL in the ring aperture.
    // Backing them with system pages would be meaningless.
    if domains & !NORMAL_DOMAINS != 0 {
        return Err(FsError::Unsupported);
    }
    if bo_size == 0 {
        return Err(FsError::InvalidData);
    }

    let byte_len = bo_size
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(FsError::InvalidData)?;
    let pages = byte_len / PAGE_SIZE;

    // VRAM first where the buffer may live there and the card has a heap —
    // past the BAR for a buffer the CPU never touches, where there is room
    // — then GTT if it is also allowed (Linux's placement order).
    let heap = (domains & uapi::AMDGPU_GEM_DOMAIN_VRAM as u64 != 0)
        .then(|| state.card.and_then(vram_heap))
        .flatten();
    let align = alignment
        .max(PAGE_SIZE)
        .checked_next_power_of_two()
        .ok_or(FsError::InvalidData)?;
    let unmapped = heap
        .as_ref()
        .filter(|_| flags & uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS as u64 != 0)
        .and_then(|heap| {
            let unmapped = heap.unmapped.as_ref()?;
            let reservation = unmapped.pool.reserve_aligned(byte_len, align).ok()?;
            Some((heap, unmapped, reservation))
        });
    if let Some((heap, unmapped, reservation)) = unmapped {
        let gpu = reservation
            .address()
            .checked_sub(heap.fb_base)
            .and_then(|a| a.checked_add(heap.fb_offset))
            .ok_or(FsError::InvalidData)?;
        // Zero it before any job can see it: the pool's previous owner may
        // have left anything, and only the engine reaches it.
        let cleared = unmapped
            .clear
            .clear(reservation.address(), reservation.size())?;
        let object = GemObject {
            placement: IrqSafeSpinLock::new(Arc::new(GemPlacement {
                phys: 0,
                gpu,
                system: false,
                byte_len,
                backing: Backing::Unmapped { _held: reservation },
            })),
            byte_len,
            alignment,
            preferred_domains: AtomicU64::new(domains),
            allowed_domains: AtomicU64::new(initial_allowed_domains(domains, flags)),
            flags,
            metadata: IrqSafeSpinLock::new(Metadata::default()),
            card: state.card,
            dma_buf: Arc::new(narf_filesystem::dma_buf::DmaBufObject::default()),
            pin_count: AtomicU32::new(0),
        };
        object
            .dma_buf
            .resv
            .add_fence(cleared, narf_filesystem::dma_buf::DmaResvUsage::Kernel);
        return finish_create(state, arg, object);
    }
    let vram = heap.and_then(|heap| {
        let reservation = heap
            .pool
            .reserve_aligned(byte_len, align)
            .or_else(|error| {
                if let Some(card) = state.card {
                    evict_visible(card, &heap.pool, byte_len, align);
                }
                heap.pool
                    .reserve_aligned(byte_len, align)
                    .map_err(|_| error)
            })
            .ok()?;
        Some((heap, reservation))
    });
    let object = match vram {
        Some((heap, reservation)) => {
            let map = reservation.mapping();
            // Zero through the BAR before userspace or the GPU can see it:
            // the pool's previous owner may have left anything.
            //
            // SAFETY: the reservation is this buffer's alone and its CPU
            // mapping covers `reservation.size()` bytes.
            unsafe { core::ptr::write_bytes(map.virt as *mut u8, 0, reservation.size() as usize) };
            let gpu = reservation
                .address()
                .checked_sub(heap.fb_base)
                .and_then(|a| a.checked_add(heap.fb_offset))
                .ok_or(FsError::InvalidData)?;
            GemObject {
                placement: IrqSafeSpinLock::new(Arc::new(GemPlacement {
                    phys: map.phys.raw(),
                    gpu,
                    system: false,
                    byte_len,
                    backing: Backing::Vram { _held: reservation },
                })),
                byte_len,
                alignment,
                preferred_domains: AtomicU64::new(domains),
                allowed_domains: AtomicU64::new(initial_allowed_domains(domains, flags)),
                flags,
                metadata: IrqSafeSpinLock::new(Metadata::default()),
                card: state.card,
                dma_buf: Arc::new(narf_filesystem::dma_buf::DmaBufObject::default()),
                pin_count: AtomicU32::new(0),
            }
        }
        None if domains == u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM)
            && flags & u64::from(uapi::AMDGPU_GEM_CREATE_DISCARDABLE) != 0
            && state.card.and_then(vram_heap).is_some() =>
        {
            // amdgpu_bo_create: ordinary VRAM-preferred BOs also allow
            // GTT fallback; DISCARDABLE VRAM-only BOs do not.
            return Err(FsError::NoSpace);
        }
        None => {
            let chunks = alloc_system(pages)?;
            let phys = chunks[0].0;
            GemObject {
                placement: IrqSafeSpinLock::new(Arc::new(GemPlacement {
                    phys,
                    gpu: phys,
                    system: true,
                    byte_len,
                    backing: Backing::System(chunks),
                })),
                byte_len,
                alignment,
                preferred_domains: AtomicU64::new(domains),
                allowed_domains: AtomicU64::new(initial_allowed_domains(domains, flags)),
                flags,
                metadata: IrqSafeSpinLock::new(Metadata::default()),
                card: state.card,
                dma_buf: Arc::new(narf_filesystem::dma_buf::DmaBufObject::default()),
                pin_count: AtomicU32::new(0),
            }
        }
    };
    finish_create(state, arg, object)
}

/// `amdgpu_gem_userptr_ioctl` on `drm_amdgpu_gem_userptr { addr, size,
/// flags, handle }`: page-aligned range, known flags, writable mappings
/// only with REGISTER (EACCES), ANONONLY refusing file/shared mappings
/// (EPERM). Every page is faulted in (resolving COW for a writable one) and
/// pinned now, VALIDATE or not; the GTT-only buffer cannot be CPU mapped,
/// exported or migrated.
fn userptr(state: &GemState, arg: usize) -> Result<u64, FsError> {
    use uapi::{
        AMDGPU_GEM_USERPTR_ANONONLY as ANONONLY, AMDGPU_GEM_USERPTR_READONLY as READONLY,
        AMDGPU_GEM_USERPTR_REGISTER as REGISTER, AMDGPU_GEM_USERPTR_VALIDATE as VALIDATE,
    };
    // SAFETY: `arg` is the ioctl pointer the trap layer validated; copy_in
    // bounds the read and SMAP-brackets it.
    let bytes = unsafe { copy_in(arg, 24)? };
    let addr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    if (addr | size) % PAGE_SIZE != 0
        || size == 0
        || flags & !(READONLY | ANONONLY | VALIDATE | REGISTER) != 0
        || addr.checked_add(size).is_none()
    {
        return Err(FsError::InvalidData);
    }
    if flags & READONLY == 0 && flags & REGISTER == 0 {
        return Err(FsError::PermissionDenied);
    }
    if size > gtt_limit() {
        return Err(FsError::NoSpace);
    }
    let space = narf_scheduler::current_address_space().ok_or(FsError::BadAddress)?;
    let pages = size / PAGE_SIZE;
    let mut pins = Vec::new();
    pins.try_reserve_exact(pages as usize)
        .map_err(|_| FsError::OutOfMemory)?;
    for page in 0..pages {
        let va = addr + page * PAGE_SIZE;
        let at = narf_memory::VirtAddr::new(va);
        if flags & ANONONLY != 0 {
            use narf_memory::address_space::RegionPerms as P;
            let region = space.lookup(at).ok_or(FsError::BadAddress)?;
            if region.perms.contains(P::FILE_DEMAND)
                || region.perms.contains(P::SHARED)
                || region.perms.contains(P::SYSV_SHM)
            {
                return Err(FsError::OperationNotPermitted);
            }
        }
        // Fault the page in through a guarded user access first.
        // SAFETY: copy_in range-checks and guards the one-byte read.
        unsafe { copy_in(va as usize, 1)? };
        // SAFETY: the kernel identity map and COW tables are live; the
        // address space belongs to the calling task.
        if flags & READONLY == 0 && !unsafe { space.user_page_writable_or_resolve(at) } {
            return Err(FsError::BadAddress);
        }
        let pin = space.pin_user_page(at).ok_or(FsError::BadAddress)?;
        crate::amdgpu_vm::make_pte(pin.phys().raw(), 0)?;
        pins.push(pin);
    }
    let first = pins[0].phys().raw();
    let gtt = u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT);
    let object = GemObject {
        placement: IrqSafeSpinLock::new(Arc::new(GemPlacement {
            phys: first,
            gpu: first,
            system: true,
            byte_len: size,
            backing: Backing::User(pins),
        })),
        byte_len: size,
        alignment: PAGE_SIZE,
        preferred_domains: AtomicU64::new(gtt),
        allowed_domains: AtomicU64::new(gtt),
        flags: if flags & READONLY != 0 {
            BO_GPU_READONLY
        } else {
            0
        },
        metadata: IrqSafeSpinLock::new(Metadata::default()),
        card: state.card,
        dma_buf: Arc::new(narf_filesystem::dma_buf::DmaBufObject::default()),
        pin_count: AtomicU32::new(0),
    };
    let handle = state.insert(object)?;
    // SAFETY: as above; `handle` is the struct's last field.
    unsafe { copy_out(arg + 20, &handle.to_le_bytes())? };
    Ok(0)
}

/// Give a new buffer a handle and report it.
fn finish_create(state: &GemState, arg: usize, object: GemObject) -> Result<u64, FsError> {
    // A failed insert drops the object, which returns its memory (a clear
    // still queued finishes before the range's next clear: `VramClear`).
    let handle = state.insert(object)?;

    // `drm_amdgpu_gem_create_out`: handle, _pad.
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&handle.to_le_bytes());
    // SAFETY: `arg` as above; the union's out arm is the same 8 bytes the in
    // arm occupied, which is how every amdgpu in/out union works.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// `amdgpu_gem_mmap_ioctl` — hand back the offset, nothing is mapped yet.
fn mmap(state: &GemState, arg: usize) -> Result<u64, FsError> {
    // `union drm_amdgpu_gem_mmap` is 8 bytes: in { handle, _pad } and
    // out { addr_ptr } both start at offset 0.
    // SAFETY: as above.
    let bytes = unsafe { copy_in(arg, 8)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let object = state.get(handle).ok_or(FsError::InvalidData)?;
    // Linux refuses a userptr or NO_CPU_ACCESS buffer outright.
    if object.is_userptr() || object.flags & uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS as u64 != 0 {
        return Err(FsError::OperationNotPermitted);
    }
    let mut out = [0u8; 8];
    out[0..8].copy_from_slice(&((handle as u64) << 12).to_le_bytes());
    // SAFETY: as above.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// `amdgpu_gem_wait_idle_ioctl`.
fn wait_idle(state: &GemState, arg: usize) -> Result<u64, FsError> {
    // SAFETY: as above.
    let bytes = unsafe { copy_in(arg, 16)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let object = state.get(handle).ok_or(FsError::InvalidData)?;
    // `drm_amdgpu_gem_wait_idle_out { status, domain }`: status 0 means idle
    // (1: timed out), domain the buffer's preferred domains. On a card that
    // runs jobs the `/dev/dri` route answers it from the engine
    // (`amdgpu_cs::dispatch_async`); here nothing can be busy.
    let mut out = [0u8; 8];
    out[4..8].copy_from_slice(&(object.preferred_domains() as u32).to_le_bytes());
    // SAFETY: as above.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// `amdgpu_gem_op_ioctl`.
fn op(state: &GemState, arg: usize) -> Result<u64, FsError> {
    // SAFETY: as above.
    let bytes = unsafe { copy_in(arg, 24)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let which = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let value = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let object = state.get(handle).ok_or(FsError::InvalidData)?;

    match which {
        // Report the creation parameters back, into the user pointer `value`
        // — note this writes to `value`, NOT to `arg`.
        uapi::AMDGPU_GEM_OP_GET_GEM_CREATE_INFO => {
            if value == 0 {
                return Err(FsError::BadAddress);
            }
            let mut info = [0u8; 32];
            info[0..8].copy_from_slice(&object.byte_len.to_le_bytes());
            info[8..16].copy_from_slice(&object.alignment.to_le_bytes());
            info[16..24].copy_from_slice(&object.preferred_domains().to_le_bytes());
            info[24..32].copy_from_slice(&(object.flags & !BO_GPU_READONLY).to_le_bytes());
            // SAFETY: `value` is the user out-pointer the caller supplied and
            // is non-zero here; exactly 32 bytes are written, which is
            // `sizeof(struct drm_amdgpu_gem_create_in)`.
            unsafe { copy_out(value as usize, &info)? };
            Ok(0)
        }
        // Linux records a preference here; validation applies it later.
        // Pinned objects retain their existing placement until unpinned.
        uapi::AMDGPU_GEM_OP_SET_PLACEMENT => {
            // Serialize policy changes with the allowed-domain check and
            // backing commit; logical sharing no longer pins a move.
            let _placement = object.placement.lock();
            object.allowed_domains.store(
                initial_allowed_domains(value & NORMAL_DOMAINS, 0),
                Ordering::Release,
            );
            object
                .preferred_domains
                .store(value & NORMAL_DOMAINS, Ordering::Release);
            Ok(0)
        }
        _ => Err(FsError::InvalidData),
    }
}

/// `drm_gem_close_ioctl` for a handle this table owns.
fn close(state: &GemState, arg: usize) -> Result<u64, FsError> {
    // SAFETY: as above.
    let bytes = unsafe { copy_in(arg, 8)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if !state.remove(handle) {
        return Err(FsError::InvalidData);
    }
    Ok(0)
}

/// `DRM_IOCTL_AMDGPU_GEM_*` and `DRM_IOCTL_GEM_CLOSE` for one open.
///
/// Returns `Unsupported` for anything else so the caller falls through to the
/// generic DRM path, as the virtio-gpu private dispatcher does.
pub fn dispatch(cmd: u32, arg: usize, state: &GemState) -> Result<u64, FsError> {
    let nr = drm_uapi::ioc_nr(cmd);
    // GEM_CLOSE is generic DRM, not amdgpu-private, and the card's dumb-buffer
    // table also answers it. Claim it only for a handle in THIS table; a dumb
    // handle falls through untouched, which the disjoint handle spaces make
    // decidable without a second lookup.
    if nr == DRM_GEM_CLOSE_NR {
        // SAFETY: as above.
        let bytes = unsafe { copy_in(arg, 8)? };
        let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if !state.owns(handle) {
            return Err(FsError::Unsupported);
        }
        return close(state, arg);
    }
    let base = drm_uapi::DRM_COMMAND_BASE;
    match nr.wrapping_sub(base) {
        uapi::DRM_AMDGPU_GEM_CREATE => create(state, arg),
        uapi::DRM_AMDGPU_GEM_MMAP => mmap(state, arg),
        uapi::DRM_AMDGPU_GEM_WAIT_IDLE => wait_idle(state, arg),
        uapi::DRM_AMDGPU_GEM_OP => op(state, arg),
        uapi::DRM_AMDGPU_GEM_METADATA => metadata(state, arg),
        uapi::DRM_AMDGPU_GEM_USERPTR => userptr(state, arg),
        _ => Err(FsError::Unsupported),
    }
}

/// `amdgpu_gem_metadata_ioctl` on `drm_amdgpu_gem_metadata` { handle, op,
/// data { flags, tiling_info, data_size_bytes, data[64] } } (288 bytes).
/// SET stores the tiling flags and up to 256 bytes of metadata (none
/// clears it); GET returns them, leaving the rest of `data` as passed. An
/// unknown op does nothing and succeeds, as in Linux.
fn metadata(state: &GemState, arg: usize) -> Result<u64, FsError> {
    const SIZE: usize = 288;
    // SAFETY: `arg` is the ioctl pointer the trap layer validated; copy_in
    // bounds the read and SMAP-brackets it.
    let mut bytes = unsafe { copy_in(arg, SIZE)? };
    let field = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let (handle, op) = (field(0), field(4));
    let object = state.lookup(handle).ok_or(FsError::NotFound)?;
    match op {
        uapi::AMDGPU_GEM_METADATA_OP_SET_METADATA => {
            let size = field(24) as usize;
            if size > 256 {
                return Err(FsError::InvalidData);
            }
            let mut m = object.metadata.lock();
            m.tiling = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
            // amdgpu_bo_set_metadata: an empty blob clears the blob but
            // keeps the old flags.
            if size == 0 {
                m.data.clear();
            } else {
                m.flags = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                m.data = bytes[28..28 + size].to_vec();
            }
            Ok(0)
        }
        uapi::AMDGPU_GEM_METADATA_OP_GET_METADATA => {
            {
                let m = object.metadata.lock();
                bytes[8..16].copy_from_slice(&m.flags.to_le_bytes());
                bytes[16..24].copy_from_slice(&m.tiling.to_le_bytes());
                bytes[24..28].copy_from_slice(&(m.data.len() as u32).to_le_bytes());
                bytes[28..28 + m.data.len()].copy_from_slice(&m.data);
            }
            // SAFETY: as above.
            unsafe { copy_out(arg, &bytes)? };
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_render_abi_tests.rs"]
mod render_abi_tests;
