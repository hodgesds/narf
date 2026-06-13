//! vDSO mapping + vvar publication.
//!
//! The kernel builds one shared copy of the `linux-vdso.so.1` image (from
//! `narf_verification::NARF_VDSO_ELF`) plus a single read-only "vvar" page,
//! and maps both into every user process. Layout in each address space:
//!
//! ```text
//!   VDSO_MAP_BASE        ┌──────────────┐  vvar  (RO, SHARED)
//!                        │ seq / cpns /  │
//!                        │ wall_offset   │
//!   VDSO_MAP_BASE+0x1000 ├──────────────┤  vdso ELF (RX, SHARED)  ← AT_SYSINFO_EHDR
//!                        │ linux-vdso.so │
//!                        └──────────────┘
//! ```
//!
//! The vDSO's `__ehdr_start - 4096` reference lands on the vvar page, so its
//! `clock_gettime` fast path reads `cycles_per_ns` + `wall_offset` straight
//! from there. The kernel publishes those under a seqlock so a concurrent
//! `clock_settime` update is observed atomically.
//!
//! The image frames are allocated once and mapped `SHARED`, so they are
//! neither double-freed on the second map nor released on process teardown.

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{alloc_frame, AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

/// Base of the [vvar][vdso] mapping in every process. Chosen well clear of
/// the program (0x0000_0080_…), interpreter (0x0000_4000_…) and stack
/// (0x7FFF_…) regions.
pub const VDSO_MAP_BASE: u64 = 0x0000_5000_0000_0000;
const VVAR_VADDR: u64 = VDSO_MAP_BASE;
/// The vDSO ELF base — the value placed in `AT_SYSINFO_EHDR`.
pub const VDSO_VADDR: u64 = VDSO_MAP_BASE + 0x1000;

// vvar field byte offsets (must match `struct vvar` in data/vdso/vdso.c).
const VVAR_SEQ: usize = 0; // u32
const VVAR_CPNS: usize = 4; // u32
const VVAR_OFF: usize = 8; // i64

struct VdsoImage {
    vvar_frame: PhysAddr,
    vdso_frames: Vec<PhysAddr>,
}

static VDSO: IrqSafeSpinLock<Option<VdsoImage>> = IrqSafeSpinLock::new(None);

/// Build the shared vDSO + vvar pages from the embedded image. A no-op when
/// the image is empty (the build host lacked clang/lld) — the kernel then
/// advertises no vDSO and libc falls back to syscalls. `cycles_per_ns` seeds
/// the vvar clock scale.
pub fn register_vdso_image(bytes: &[u8], cycles_per_ns: u32) {
    if bytes.is_empty() {
        return;
    }
    let mut g = VDSO.lock();
    if g.is_some() {
        return; // already built
    }
    // vvar page.
    let vvar = match alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return,
    };
    zero_frame(vvar);

    // vdso code pages (raw file image, contiguous; file offset == vaddr).
    let pages = bytes.len().div_ceil(4096);
    let mut frames = Vec::with_capacity(pages);
    for i in 0..pages {
        let frame = match alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => return,
        };
        zero_frame(frame);
        let off = i * 4096;
        let chunk = core::cmp::min(4096, bytes.len() - off);
        // SAFETY: freshly-allocated frame, identity-mapped in low RAM;
        // chunk <= 4096.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), frame.raw() as *mut u8, chunk);
        }
        frames.push(frame);
    }

    write_vvar(vvar, cycles_per_ns.max(1), 0);
    *g = Some(VdsoImage {
        vvar_frame: vvar,
        vdso_frames: frames,
    });
}

/// Publish a new realtime offset (called from `clock_settime`). Seqlock-
/// guarded so the vDSO never reads a torn value.
pub fn update_wall_offset(offset_ns: i64) {
    let g = VDSO.lock();
    if let Some(img) = g.as_ref() {
        let cpns = read_u32(img.vvar_frame, VVAR_CPNS);
        write_vvar(img.vvar_frame, cpns.max(1), offset_ns);
    }
}

/// Map the vvar + vdso pages into `addr_space`. Returns the vDSO base vaddr
/// for `AT_SYSINFO_EHDR`, or `None` if no vDSO is registered / mapping fails.
pub fn map_into(addr_space: &AddressSpace) -> Option<u64> {
    let g = VDSO.lock();
    let img = g.as_ref()?;
    addr_space
        .map_region(Region {
            base: VirtAddr::new(VVAR_VADDR),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::SHARED,
            phys: alloc::vec![img.vvar_frame],
        })
        .ok()?;
    let vdso_len = (img.vdso_frames.len() as u64) << 12;
    addr_space
        .map_region(Region {
            base: VirtAddr::new(VDSO_VADDR),
            len: vdso_len,
            perms: RegionPerms::READ | RegionPerms::EXEC | RegionPerms::SHARED,
            phys: img.vdso_frames.clone(),
        })
        .ok()?;
    Some(VDSO_VADDR)
}

fn zero_frame(frame: PhysAddr) {
    // SAFETY: identity-mapped freshly-allocated frame.
    unsafe {
        core::ptr::write_bytes(frame.raw() as *mut u8, 0, 4096);
    }
}

fn read_u32(frame: PhysAddr, off: usize) -> u32 {
    // SAFETY: identity-mapped vvar frame; off+4 <= 4096.
    unsafe { core::ptr::read_volatile((frame.raw() as *const u8).add(off) as *const u32) }
}

/// Write the vvar fields under a seqlock: bump seq to odd, store the
/// payload, bump to even. Readers retry while seq is odd or changes.
fn write_vvar(frame: PhysAddr, cycles_per_ns: u32, offset_ns: i64) {
    let base = frame.raw() as *mut u8;
    // SAFETY: identity-mapped vvar frame; all offsets within the page.
    unsafe {
        let seq_ptr = base.add(VVAR_SEQ) as *mut u32;
        let seq = core::ptr::read_volatile(seq_ptr);
        core::ptr::write_volatile(seq_ptr, seq | 1); // odd: writing
        fence(Ordering::Release);
        core::ptr::write_volatile(base.add(VVAR_CPNS) as *mut u32, cycles_per_ns);
        core::ptr::write_volatile(base.add(VVAR_OFF) as *mut i64, offset_ns);
        fence(Ordering::Release);
        core::ptr::write_volatile(seq_ptr, (seq | 1).wrapping_add(1)); // even
    }
}
