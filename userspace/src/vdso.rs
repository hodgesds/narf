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
/// the program (0x0000_0080_…), the brk arena (`[BRK_DEFAULT_BASE = 0x1000_…,
/// BRK_ARENA_TOP = 0x4000_…)`), the interpreter (0x0000_4000_…), the anonymous
/// mmap window (`[0x4080…, 0x7F00…)`) and the stack region (0x7FFF_FF…). An old
/// vdso base of 0x5000_0000_0000 collided with the (then) brk arena exactly:
/// glibc's `sbrk` grow at the default break failed `map_region` with `Overlap`
/// whenever the vdso was registered. Linux likewise parks the vdso just below
/// the stack.
pub const VDSO_MAP_BASE: u64 = 0x0000_7FFF_0000_0000;
const VVAR_VADDR: u64 = VDSO_MAP_BASE;
/// The vDSO ELF base — the value placed in `AT_SYSINFO_EHDR`.
pub const VDSO_VADDR: u64 = VDSO_MAP_BASE + 0x1000;

/// Perms for the vDSO code region (see `map_into`). WRITE|COW are load-bearing,
/// not decorative: `AddressSpace::cow_split_on_write` only recovers a present-RO
/// write fault — which is how glibc's ld.so patches the vDSO dynamic section in
/// place — when the region carries BOTH WRITE (logical write authority) and COW
/// (sharing exists). Dropping them (the pre-mmap-scalability `READ|EXEC`
/// mapping) makes the first vDSO write a fatal #PF that kills systemd PID 1 at
/// boot. Built from raw bits so it stays `const`.
pub(crate) const VDSO_CODE_PERMS: RegionPerms = RegionPerms(
    RegionPerms::READ.0 | RegionPerms::WRITE.0 | RegionPerms::EXEC.0 | RegionPerms::COW.0,
);

// vvar field byte offsets (must match `struct vvar` in data/vdso/vdso.c).
const VVAR_SEQ: usize = 0; // u32
const VVAR_CPNS: usize = 4; // u32
const VVAR_OFF: usize = 8; // i64
const VVAR_MULT: usize = 16; // u32 — cycles→ns fixed-point multiplier
const VVAR_SHIFT: usize = 20; // u32 — cycles→ns fixed-point shift

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
        // SAFETY: freshly-allocated frame, identity-mapped in low RAM; chunk <= 4096.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(off), frame.raw() as *mut u8, chunk);
        }
        frames.push(frame);
    }

    // Hold a PERMANENT COW reference on every master frame. The vDSO is
    // mapped into each process as a private copy-on-write region backed
    // by these masters (see `map_into`); this baseline ref keeps the
    // master count > 1 so a write-fault always SPLITS (giving the writer
    // a private page) instead of taking cow_split's sole-owner shortcut
    // that would write through to the shared master — and it guarantees
    // the global masters are never freed by a process teardown.
    for &f in &frames {
        let _ = narf_memory::frame::cow::inc_ref(f);
    }

    // Publish the wall-clock offset the kernel already anchored to the CMOS
    // RTC at boot (bare_main), NOT a hard 0 — otherwise the vDSO's
    // CLOCK_REALTIME fast path reports epoch 1970 until some process happens to
    // call clock_settime, even though the syscall path reads real wall time.
    write_vvar(
        vvar,
        cycles_per_ns.max(1),
        narf_scheduler::narf_time::wall_offset_ns(),
    );
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
    // Map the vDSO code+dynamic as a PRIVATE copy-on-write region backed
    // by the shared master frames — NOT MAP_SHARED. glibc's ld.so writes
    // the vDSO's dynamic section in-place (adjusting `d_un` by the load
    // bias); if that were shared, one process's write would corrupt every
    // other's (a later ld.so would double the bias into a non-canonical
    // pointer). As a COW region the write faults, cow_split hands the
    // writer a private page, and the master stays pristine (0-based
    // `d_un`) for the next process. `inc_ref` per mapping keeps the
    // master's refcount > 1 so the split path (not the sole-owner
    // shortcut) is taken; the teardown's `free_frame` dec_refs it back.
    //
    // WRITE|COW are REQUIRED, not decorative: `cow_split_on_write` only
    // recovers a present-RO write fault when the region carries BOTH
    // WRITE (logical write authority) and COW (sharing exists). It's the
    // permanent `inc_ref` above — NOT a WRITE-clear leaf — that keeps the
    // per-process leaf read-only until the write: `user_page_writable`
    // returns false while the master refcount stays > 1, so the vDSO
    // executes read-only and ld.so's store faults into the COW split. The
    // split then hands the writer a refcount-1 private frame whose leaf
    // becomes writable+executable (map_region/materialize do not apply the
    // syscall-level W^X gate). Omitting these flags — as the pre-
    // mmap-scalability `READ|EXEC` mapping did — makes cow_split decline
    // the fault and systemd's first vDSO write take a fatal #PF at boot.
    let vdso_len = (img.vdso_frames.len() as u64) << 12;
    for &f in &img.vdso_frames {
        let _ = narf_memory::frame::cow::inc_ref(f);
    }
    addr_space
        .map_region(Region {
            base: VirtAddr::new(VDSO_VADDR),
            len: vdso_len,
            perms: VDSO_CODE_PERMS,
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
///
/// `mult`/`shift` are the calibrated cycles→ns fixed-point pair (the vDSO
/// computes `ns = (cyc * mult) >> shift`, matching `monotonic_ns`); they are
/// pulled from the live clock calibration so a re-publish always reflects the
/// current scale.
fn write_vvar(frame: PhysAddr, cycles_per_ns: u32, offset_ns: i64) {
    let (mult, shift) = narf_scheduler::narf_time::cyc_to_ns_mult_shift();
    let base = frame.raw() as *mut u8;
    // SAFETY: identity-mapped vvar frame; all offsets within the page.
    unsafe {
        let seq_ptr = base.add(VVAR_SEQ) as *mut u32;
        let seq = core::ptr::read_volatile(seq_ptr);
        core::ptr::write_volatile(seq_ptr, seq | 1); // odd: writing
        fence(Ordering::Release);
        core::ptr::write_volatile(base.add(VVAR_CPNS) as *mut u32, cycles_per_ns);
        core::ptr::write_volatile(base.add(VVAR_OFF) as *mut i64, offset_ns);
        core::ptr::write_volatile(base.add(VVAR_MULT) as *mut u32, mult);
        core::ptr::write_volatile(base.add(VVAR_SHIFT) as *mut u32, shift);
        fence(Ordering::Release);
        core::ptr::write_volatile(seq_ptr, (seq | 1).wrapping_add(1)); // even
    }
}
