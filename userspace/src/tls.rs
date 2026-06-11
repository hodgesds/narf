//! Per-task TLS staging — initial-exec model on x86_64 SysV-AMD64.
//!
//! When a binary carries a `PT_TLS` segment we have to set up a
//! per-thread block before the first user-mode entry; otherwise
//! the (parsed-but-unused) `image.tls` template is wasted and any
//! `mov rax, fs:[N]` that the binary emits dereferences whatever
//! the previous CPU left in `IA32_FS_BASE`.
//!
//! ## SysV-AMD64 TLS layout (initial-exec)
//!
//! The thread pointer is `fs:[0]`; relibc and any TLS-using ELF
//! built against the SysV-AMD64 ABI assume:
//!
//! ```text
//!   low                                                      high
//!   ┌────────────────────────────┬──────────────────────────────┐
//!   │  TLS template image bytes  │  TCB (TCB[0] = self-pointer) │
//!   └────────────────────────────┴──────────────────────────────┘
//!   ↑                            ↑
//!   tls_image_base               fs_base  ← thread pointer
//! ```
//!
//! - `*(fs:0)` reads the TCB self-pointer (== `fs_base`); a
//!   handful of relibc startup paths verify this round-trip before
//!   they trust their own TCB.
//! - TLS variables live at *negative* offsets from `fs_base`:
//!   `mov rax, fs:[-8]` reads the last 8 bytes of the template,
//!   `mov rax, fs:[-(template.mem_size)]` reads the first.
//! - `fs_base` is therefore `tls_image_base + mem_size_aligned`.
//!
//! ## Why this lives outside `loader.rs`
//!
//! The TLS block is allocated *after* the program's PT_LOAD pages
//! are mapped + materialised — it lives in a dedicated user vaddr
//! region that the program itself never names. Coupling the TLS
//! plumbing to the ELF loader would force `LoadError` to grow a
//! TLS-specific variant; keeping the staging here lets
//! `process.rs` integrate the result independently and keeps
//! the loader pure-ELF.

use alloc::vec::Vec;

use narf_memory::{
    AddressSpace, AddressSpaceError, FrameAllocError, PhysAddr, Region, RegionPerms, VirtAddr,
};

use crate::ExecImage;

/// User vaddr at which per-task TLS blocks are staged. Disjoint from
/// `MMAP_CURSOR` (starts at `0x0000_4080_0000_0000`) and from the
/// interpreter bias (`0x0000_4000_0000_0000`) and the program load
/// region (low half) by design — picking a fresh /49-bit/ slot keeps
/// the kernel's "what's mapped where" mental model uncluttered.
///
/// SMP + multi-thread bring-up will swap this for a per-task allocator
/// (each thread needs its own non-aliasing TLS block); single-task
/// today is fine with a fixed slot.
pub const TLS_REGION_BASE: u64 = 0x0000_4090_0000_0000;

/// Slack appended past `mem_size` for the TCB self-pointer + a
/// little tail padding. The TCB only structurally needs one qword
/// (the self-pointer at `*(fs:0)`), but rounding up to 16 keeps
/// downstream relibc fields (`stack_canary`, the `errno` slot) on
/// natural alignment without us having to import their layout.
const TCB_RESERVE: u64 = 16;

/// Errors `stage_tls` can surface. None of these are recoverable
/// from the caller's perspective — a process can't run if its TLS
/// staging fails. Kept granular so the test harness can assert on
/// specific failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlsError {
    /// Frame allocator returned `Err` for a TLS-block page.
    Frames(FrameAllocError),
    /// `address_space.map_region` rejected the TLS region (overlap,
    /// alignment, …).
    Map(AddressSpaceError),
    /// `address_space.materialize` failed after the TLS region was
    /// pushed — the page tables couldn't pick up the new mapping.
    Materialize(AddressSpaceError),
    /// `paging::translate` couldn't resolve the TLS vaddr to its
    /// just-installed phys (a structural bug — the region was just
    /// mapped + materialised — but surfaced as an error rather
    /// than a panic so the test harness can assert).
    Translate,
    /// `template.mem_size` was so large that rounding up to the
    /// alignment overflowed `u64`. Defensive — a sane ELF would
    /// never hit this.
    AlignOverflow,
    /// `template.file_off + template.file_size` exceeded the input
    /// `bytes` length. The ELF parser already rejects this, but
    /// re-check here to keep `stage_tls` self-contained.
    ImageOutOfBounds,
}

impl From<FrameAllocError> for TlsError {
    fn from(e: FrameAllocError) -> Self {
        TlsError::Frames(e)
    }
}

/// Round `n` up to the next multiple of `align`. `align` must be a
/// power of two — `TlsTemplate::align` is normalised to that by the
/// ELF parser. Returns `None` on overflow.
#[inline]
fn align_up(n: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    n.checked_add(mask).map(|x| x & !mask)
}

/// Allocate + populate a per-task TLS block in `address_space` from
/// `image.tls`, copying the initial template image out of `bytes`,
/// and return the **fs_base user vaddr** the caller will plant into
/// `IA32_FS_BASE` on the next user-mode entry.
///
/// `image.tls` is expected to be `Some` on entry — callers that
/// want to skip TLS staging when a binary has no `PT_TLS` should do
/// the `image.tls.is_some()` gate at the integration site rather
/// than make `stage_tls` lie about success.
///
/// # Safety
/// - The low-4-GiB identity map must be live (we write the TLS
///   block via the kernel's identity view of each phys page).
/// - The frame allocator must be initialised.
/// - `address_space` must have been constructed via `new_for_user`
///   so its `materialize` is meaningful.
pub unsafe fn stage_tls(
    image: &ExecImage,
    bytes: &[u8],
    address_space: &AddressSpace,
) -> Result<u64, TlsError> {
    let template = image.tls.as_ref().expect("stage_tls called without PT_TLS");

    // Self-consistency check: file_off + file_size must lie within
    // the input ELF bytes. The parser already enforces this; we
    // re-check so a stage_tls call that's handed a mismatched
    // (image, bytes) pair still surfaces an error rather than
    // memcpying out of bounds.
    let file_end = (template.file_off as usize)
        .checked_add(template.file_size as usize)
        .ok_or(TlsError::ImageOutOfBounds)?;
    if file_end > bytes.len() {
        return Err(TlsError::ImageOutOfBounds);
    }

    // Round mem_size up to the template's required alignment so the
    // TCB sits at an aligned vaddr — relibc and gcc-emitted TLS
    // accessors assume `fs_base` is `template.align`-aligned.
    let mem_size_aligned =
        align_up(template.mem_size, template.align).ok_or(TlsError::AlignOverflow)?;
    let total_bytes = mem_size_aligned
        .checked_add(TCB_RESERVE)
        .ok_or(TlsError::AlignOverflow)?;
    // Page-round the mapping; sub-page TLS blocks are common (ours
    // is typically <128 bytes) but we map at page granularity.
    let mapped_bytes = align_up(total_bytes, 4096).ok_or(TlsError::AlignOverflow)?;
    let pages = mapped_bytes >> 12;

    // Allocate per-page phys frames. `alloc_frame` zeroes nothing,
    // so we walk each page and zero it via the identity map — that
    // also handles the `mem_size - file_size` BSS-style tail of the
    // TLS image without a separate zero-fill pass.
    let mut phys_list: Vec<PhysAddr> = Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        let f = narf_memory::alloc_frame()?;
        let p = f.start_address();
        // SAFETY: identity-mapped low 4 GiB; freshly allocated frame
        // is exclusively ours until we hand it to `map_region`.
        unsafe {
            core::ptr::write_bytes(p.raw() as *mut u8, 0, 4096);
        }
        phys_list.push(p);
    }

    let region_base = TLS_REGION_BASE;
    address_space
        .map_region(Region {
            base: VirtAddr::new(region_base),
            len: mapped_bytes,
            // TLS block is read+write; the dynamic-TLS code in relibc /
            // glibc patches the TCB at runtime, so we don't get away
            // with read-only here even if the initial image were const.
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .map_err(TlsError::Map)?;

    // SAFETY: AS came from `new_for_user`; map_region succeeded so
    // the regions list now includes our TLS span.
    unsafe { address_space.materialize() }.map_err(TlsError::Materialize)?;

    // Layout (low → high): `[ template image (mem_size_aligned) ][ TCB ]`.
    // fs_base sits at the TCB start; user-side TLS reads land at
    // negative offsets within the template region.
    let tls_image_base = region_base;
    let fs_base = tls_image_base + mem_size_aligned;

    // Copy `file_size` bytes from the ELF into the TLS image area.
    // The remaining `mem_size - file_size` bytes (BSS-style tail)
    // are already zero from the per-page write_bytes above.
    let root = address_space.root;
    let src = &bytes
        [template.file_off as usize..template.file_off as usize + template.file_size as usize];
    for (i, &b) in src.iter().enumerate() {
        let vaddr = tls_image_base + i as u64;
        let page = vaddr & !0xFFFu64;
        let off = vaddr & 0xFFFu64;
        // SAFETY: we just mapped + materialised the TLS region;
        // every vaddr in `[region_base, region_base + mapped_bytes)`
        // resolves to a phys that's identity-mapped in the low 4
        // GiB of the kernel's view.
        let phys = unsafe { narf_memory::x86_64::paging::translate(root, VirtAddr::new(page)) }
            .ok_or(TlsError::Translate)?;
        // SAFETY: identity-mapped phys; exclusive ownership through
        // the duration of staging (no other CPU is in this AS yet).
        unsafe {
            *((phys.as_u64() + off) as *mut u8) = b;
        }
    }

    // Write the TCB self-pointer at *(fs_base) = fs_base. relibc
    // reads `*(fs:0)` to validate / canonicalise its TCB on entry;
    // an uninitialised slot would either trip its sanity check or —
    // worse — silently land on the previous task's TCB.
    {
        let page = fs_base & !0xFFFu64;
        let off = fs_base & 0xFFFu64;
        // SAFETY: same reasoning as the image-copy loop above; the
        // TCB sits inside the just-mapped region by construction
        // (`fs_base + 8 <= region_base + mapped_bytes`).
        let phys = unsafe { narf_memory::x86_64::paging::translate(root, VirtAddr::new(page)) }
            .ok_or(TlsError::Translate)?;
        // The TCB self-pointer is 8 bytes; `fs_base` is `align`-
        // aligned (we rounded `mem_size` up to `align`, so the TCB
        // start is at least `align`-aligned, which the ELF parser
        // enforces is a power of two ≥ 1). For any `align ≥ 8` the
        // qword store stays within a single page; for the (rare)
        // `align < 8` case the TCB sits at `align`-aligned offset
        // and may straddle if `(off & 7) != 0`. We guard with a
        // per-byte fallback to keep the path correct without
        // assuming alignment we didn't enforce.
        let value = fs_base;
        if off + 8 <= 4096 {
            // SAFETY: dst lies within a single mapped phys page.
            unsafe {
                *((phys.as_u64() + off) as *mut u64) = value;
            }
        } else {
            // Slow path: byte-wise across the page boundary.
            for i in 0..8 {
                let v = fs_base + i;
                let p = v & !0xFFFu64;
                let o = v & 0xFFFu64;
                // SAFETY: both pages are mapped + materialised.
                let ph = unsafe { narf_memory::x86_64::paging::translate(root, VirtAddr::new(p)) }
                    .ok_or(TlsError::Translate)?;
                let byte = (value >> (i * 8)) as u8;
                // SAFETY: identity-mapped, exclusive.
                unsafe {
                    *((ph.as_u64() + o) as *mut u8) = byte;
                }
            }
        }
    }

    Ok(fs_base)
}
