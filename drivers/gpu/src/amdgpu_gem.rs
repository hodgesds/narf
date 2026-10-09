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
//! LINUX-GAP: the backing is always physically contiguous system memory from
//! the buddy allocator, whatever domain the caller asked for. There is no TTM:
//! no VRAM placement, no eviction, no migration between GTT and VRAM, and no
//! `GEM_CREATE_VRAM_CONTIGUOUS`/`NO_CPU_ACCESS` distinction. On these APUs
//! VRAM is carved out of system memory anyway, so the pages are of the right
//! kind; what is missing is the GPU-side placement a discrete part would need
//! and the pressure handling any part needs. `preferred_domains` is recorded
//! and reported back by `GEM_OP` so userspace sees its own request, not a
//! rewritten one.
//!
//! LINUX-GAP: `GEM_WAIT_IDLE` always reports idle immediately. That is
//! currently true — there is no submission path, so nothing can be busy — but
//! it will become a lie the moment `AMDGPU_CS` lands, and it is the one call
//! here that must be revisited then rather than extended.
//!
//! LINUX-GAP: `GEM_USERPTR` (pinning host pages into the GPU address space),
//! `GEM_METADATA` (the tiling descriptor a DRI client passes to its peer) and
//! `GEM_LIST_HANDLES` are not implemented and return EINVAL.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_uapi as uapi;
use crate::drm_ioctl_bridge::{copy_in, copy_out};
use crate::drm_uapi;

/// First amdgpu GEM handle. Chosen above any plausible dumb-buffer handle so
/// the two spaces cannot overlap; see the module header.
const HANDLE_BASE: u32 = 0x4000_0000;

/// `DRM_IOCTL_GEM_CLOSE`'s command number — generic DRM, not amdgpu-private.
const DRM_GEM_CLOSE_NR: u32 = 0x09;

const PAGE_SIZE: u64 = 4096;

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

/// One buffer object: a contiguous physical allocation plus what the client
/// asked for when it created it.
#[derive(Debug)]
pub struct GemObject {
    pub phys: u64,
    /// Rounded up to a page, as `bo_size` is reported back.
    pub byte_len: u64,
    /// Buddy order the allocation came from, needed to free it.
    order: u8,
    /// `alignment` as requested, reported back by `GEM_OP`.
    alignment: u64,
    pub preferred_domains: u64,
    pub flags: u64,
}

impl Drop for GemObject {
    fn drop(&mut self) {
        let frame = narf_memory::PhysFrame::containing(narf_memory::PhysAddr::new(self.phys));
        narf_memory::frame::free_pages(frame, self.order);
    }
}

/// Per-open GEM state. One of these per `/dev/dri/*` open on an amdgpu card.
#[derive(Debug)]
pub struct GemState {
    objects: IrqSafeSpinLock<Option<BTreeMap<u32, Arc<GemObject>>>>,
    next_handle: AtomicU32,
}

impl Default for GemState {
    fn default() -> Self {
        Self::new()
    }
}

impl GemState {
    pub const fn new() -> Self {
        GemState {
            objects: IrqSafeSpinLock::new(None),
            next_handle: AtomicU32::new(HANDLE_BASE),
        }
    }

    fn insert(&self, object: GemObject) -> Result<u32, FsError> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        // Wrapping back into the dumb-handle space would make two different
        // objects answer to one number. Refuse instead.
        if handle < HANDLE_BASE {
            return Err(FsError::NoSpace);
        }
        let mut g = self.objects.lock();
        g.get_or_insert_with(BTreeMap::new)
            .insert(handle, Arc::new(object));
        Ok(handle)
    }

    fn get(&self, handle: u32) -> Option<Arc<GemObject>> {
        self.objects
            .lock()
            .as_ref()
            .and_then(|m| m.get(&handle).cloned())
    }

    /// Drop this open's reference. The frames are freed when the last
    /// reference goes, which is not necessarily here — a buffer still mapped
    /// into a process stays alive until the mapping is torn down.
    fn remove(&self, handle: u32) -> bool {
        let mut g = self.objects.lock();
        g.as_mut().is_some_and(|m| m.remove(&handle).is_some())
    }

    /// The object named by `handle`, for the VM layer's range checks.
    pub fn object(&self, handle: u32) -> Option<Arc<GemObject>> {
        self.get(handle)
    }

    /// Whether `handle` belongs to this table at all, so `GEM_CLOSE` can tell
    /// an amdgpu handle from a dumb one without consulting both.
    pub fn owns(&self, handle: u32) -> bool {
        handle >= HANDLE_BASE && self.get(handle).is_some()
    }

    /// Resolve an `mmap` offset to the object's physical frames.
    ///
    /// The offset is the handle shifted by the page shift, which is how the
    /// dumb path encodes it too — there is no separate offset allocator, so an
    /// offset cannot name an object this open does not hold.
    pub fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        let handle = u32::try_from(offset >> 12).map_err(|_| FsError::InvalidData)?;
        let object = self.get(handle).ok_or(FsError::InvalidData)?;
        if len as u64 > object.byte_len {
            return Err(FsError::InvalidData);
        }
        let pages = (len as u64).div_ceil(PAGE_SIZE);
        Ok((0..pages).map(|i| object.phys + i * PAGE_SIZE).collect())
    }
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
    // The buddy allocator is power-of-two, and the request must also satisfy
    // `alignment`, which a contiguous power-of-two block of this size does for
    // any alignment up to its own size.
    let mut order = 0u8;
    while (1u64 << order) < pages {
        order += 1;
    }
    if alignment > (1u64 << order) * PAGE_SIZE {
        return Err(FsError::InvalidData);
    }

    let frame = narf_memory::frame::alloc_pages_on(0, order).map_err(|_| FsError::NoSpace)?;
    let phys = frame.start_address().raw();
    // Zero before userspace can see it. This is not optional: the pages come
    // from the kernel's own allocator and may hold anything.
    //
    // SAFETY: the allocation covers `(1 << order)` pages at `phys`, and phys
    // memory is kernel-mapped at a fixed offset.
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>(),
            0,
            ((1u64 << order) * PAGE_SIZE) as usize,
        );
    }

    let handle = match state.insert(GemObject {
        phys,
        byte_len,
        order,
        alignment,
        preferred_domains: domains,
        flags,
    }) {
        Ok(h) => h,
        Err(error) => {
            narf_memory::frame::free_pages(frame, order);
            return Err(error);
        }
    };

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
    // SAFETY: as above.
    let bytes = unsafe { copy_in(arg, 16)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if state.get(handle).is_none() {
        return Err(FsError::InvalidData);
    }
    let mut out = [0u8; 16];
    out[8..16].copy_from_slice(&((handle as u64) << 12).to_le_bytes());
    // SAFETY: as above.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// `amdgpu_gem_wait_idle_ioctl`.
fn wait_idle(state: &GemState, arg: usize) -> Result<u64, FsError> {
    // SAFETY: as above.
    let bytes = unsafe { copy_in(arg, 16)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if state.get(handle).is_none() {
        return Err(FsError::InvalidData);
    }
    // `drm_amdgpu_gem_wait_idle_out { status, domain }`: status 0 means the
    // wait completed rather than timed out. Nothing can be busy — see the
    // module LINUX-GAP.
    let out = [0u8; 8];
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
            info[16..24].copy_from_slice(&object.preferred_domains.to_le_bytes());
            info[24..32].copy_from_slice(&object.flags.to_le_bytes());
            // SAFETY: `value` is the user out-pointer the caller supplied and
            // is non-zero here; exactly 32 bytes are written, which is
            // `sizeof(struct drm_amdgpu_gem_create_in)`.
            unsafe { copy_out(value as usize, &info)? };
            Ok(0)
        }
        // Changing placement means moving the buffer between heaps, which
        // needs the migration path there isn't one of. Refusing is better
        // than accepting and leaving it where it was.
        uapi::AMDGPU_GEM_OP_SET_PLACEMENT => Err(FsError::Unsupported),
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
        _ => Err(FsError::Unsupported),
    }
}
