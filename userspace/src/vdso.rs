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
use core::sync::atomic::{fence, AtomicU32, Ordering};

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
    RegionPerms::READ.0
        | RegionPerms::WRITE.0
        | RegionPerms::EXEC.0
        | RegionPerms::COW.0
        | RegionPerms::LOCK_EXEMPT.0,
);

// vvar field byte offsets (must match `struct vvar` in data/vdso/vdso.c).
const VVAR_SEQ: usize = 0; // u32
const VVAR_CPNS: usize = 4; // u32
const VVAR_OFF: usize = 8; // i64
const VVAR_MULT: usize = 16; // u32 — cycles→ns fixed-point multiplier
const VVAR_SHIFT: usize = 20; // u32 — cycles→ns fixed-point shift
const VVAR_CLOCK_MODE: usize = 24; // u32 — VVAR_CLOCK_MODE_* in vdso.c

/// vDSO clock entry points read the counter (`VVAR_CLOCK_MODE_COUNTER`).
const CLOCK_MODE_COUNTER: u32 = 0;
/// vDSO clock entry points issue their syscall (`VVAR_CLOCK_MODE_SYSCALL`).
const CLOCK_MODE_SYSCALL: u32 = 1;

/// Mode published in the vvar page. Written only under [`VDSO`]'s lock so a
/// concurrent [`update_wall_offset`] republishes the current value.
static CLOCK_MODE: AtomicU32 = AtomicU32::new(CLOCK_MODE_COUNTER);

/// Why the clock entry points issue their syscall: a set of `ROUTE_*` bits,
/// changed only under [`VDSO`]'s lock together with [`CLOCK_MODE`]. The mode
/// is [`CLOCK_MODE_SYSCALL`] exactly while a reason is set, so a verification
/// reset of one installer cannot restore the counter under the other.
static ROUTE_REASONS: AtomicU32 = AtomicU32::new(0);
/// A timestamp instruction interceptor is installed.
const ROUTE_TIMESTAMP_TRAP: u32 = 1 << 0;
/// The published syscall table has a syscall interceptor.
const ROUTE_SYSCALL_INTERCEPTOR: u32 = 1 << 1;

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
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(off),
                frame.kernel_mut_ptr::<u8>(),
                chunk,
            );
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

/// Whether a vDSO image is registered, so that every process loaded from
/// now on maps it and gets `AT_SYSINFO_EHDR`.
pub fn vdso_registered() -> bool {
    VDSO.lock().is_some()
}

/// Undo [`register_vdso_image`] for a verification test that registered the
/// image in a kernel-test boot, which skips the boot-time registration.
/// While an image is registered, every process the loader builds maps the
/// vDSO and gets `AT_SYSINFO_EHDR`, so a registration left behind changes the
/// layout that every later loader test sees.
///
/// Refuses, leaving the image registered, unless no address space maps it:
/// each master frame must hold exactly the two references it held after
/// registration (its implicit owner and the permanent reference), and the
/// vvar frame none. Otherwise frees the masters and the vvar page.
#[cfg(feature = "verification-test-reset")]
#[doc(hidden)]
pub fn __verification_unregister_vdso_image() -> Result<(), &'static str> {
    use narf_memory::frame::cow;
    let mut g = VDSO.lock();
    let Some(img) = g.as_ref() else {
        return Ok(());
    };
    if img.vdso_frames.iter().any(|&f| cow::count(f) != 2) {
        return Err("a vDSO master frame is still mapped");
    }
    if cow::count(img.vvar_frame) != 0 {
        return Err("the vvar frame carries a COW reference");
    }
    let Some(img) = g.take() else {
        return Ok(());
    };
    drop(g);
    for f in img.vdso_frames {
        // Drop the permanent reference, then the implicit owner's.
        let _ = cow::dec_ref(f);
        narf_memory::free_frame(narf_memory::PhysFrame::new(f));
    }
    narf_memory::free_frame(narf_memory::PhysFrame::new(img.vvar_frame));
    Ok(())
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

/// Make every vDSO clock entry point, and `getcpu`, issue its syscall from
/// now on.
///
/// Installing a timestamp instruction interceptor calls this before arming
/// the trap, so a tool sees each guest clock read as a `clock_gettime`,
/// `gettimeofday` or `time` syscall rather than as a counter read that the
/// vDSO converts with the host scale, and each CPU query as `getcpu` rather
/// than an `RDTSCP` that reveals the physical CPU. The mode is sticky, like
/// the trap request, and is published under the vvar seqlock. Installation
/// runs only while no user task is runnable, so no vDSO call is in flight
/// across the switch; the vDSO also reads the counter inside its seqlock read
/// section, so a counter read that follows the publication belongs to a
/// snapshot that retries.
pub fn route_clocks_through_syscalls() {
    update_route_reasons(|reasons| reasons | ROUTE_TIMESTAMP_TRAP);
}

/// Make every vDSO clock entry point, and `getcpu`, issue its syscall because
/// the published syscall table has a syscall interceptor.
///
/// A syscall interceptor (the Reverie backend's among them) must see every
/// syscall the guest makes, and a guest reaches `clock_gettime`,
/// `gettimeofday`, `time` and `getcpu` through the vDSO without entering the
/// kernel. reverie-ptrace closes the same gap by patching each tracee's vDSO
/// entry points into syscalls (`reverie-ptrace/src/vdso.rs`,
/// `patch_current_vdso`); here the vvar clock mode does it for every process
/// at once. [`crate::syscall::try_install_global`] calls this when it
/// publishes a table whose interceptor asks for the guest's vDSO calls
/// ([`crate::syscall::SyscallInterceptor::intercepts_vdso_calls`]).
/// Publication happens once, at boot before the first user task
/// (verification harnesses republish only while no user task runs), so no
/// vDSO call is in flight across the switch. The mode is sticky in
/// production, like the table.
pub fn route_clocks_for_syscall_interceptor() {
    update_route_reasons(|reasons| reasons | ROUTE_SYSCALL_INTERCEPTOR);
}

/// Drop the syscall-interceptor reason for routing clocks through syscalls,
/// restoring the counter fast path unless a timestamp interceptor still needs
/// the syscalls. Only the test reset of the global syscall table calls this.
pub(crate) fn __test_release_syscall_interceptor_clocks() {
    update_route_reasons(|reasons| reasons & !ROUTE_SYSCALL_INTERCEPTOR);
}

/// Whether vDSO clock entry points currently issue their syscall.
pub fn clocks_route_through_syscalls() -> bool {
    CLOCK_MODE.load(Ordering::Acquire) == CLOCK_MODE_SYSCALL
}

/// Restore the counter fast path. Only the verification reset of the
/// instruction interceptor calls this.
#[cfg(feature = "verification-test-reset")]
pub(crate) fn __test_restore_counter_clocks() {
    update_route_reasons(|reasons| reasons & !ROUTE_TIMESTAMP_TRAP);
}

/// Drop the timestamp-trap reason while a timestamp interceptor stays
/// installed, so a verification smoke can trap the vDSO's own counter reads.
/// It clears only its own reason: a syscall interceptor's reason, if one is
/// still published, keeps the clocks on syscalls, and the smoke's own
/// counter-mode check then fails by name instead of the reset hiding the
/// other installer's state.
#[cfg(feature = "verification-test-reset")]
#[doc(hidden)]
pub fn __verification_restore_counter_clocks() {
    update_route_reasons(|reasons| reasons & !ROUTE_TIMESTAMP_TRAP);
}

/// Replace the routing reasons with `update(reasons)` and publish the clock
/// mode they imply.
fn update_route_reasons(update: impl FnOnce(u32) -> u32) {
    let g = VDSO.lock();
    let reasons = update(ROUTE_REASONS.load(Ordering::Acquire));
    ROUTE_REASONS.store(reasons, Ordering::Release);
    let mode = if reasons == 0 {
        CLOCK_MODE_COUNTER
    } else {
        CLOCK_MODE_SYSCALL
    };
    CLOCK_MODE.store(mode, Ordering::Release);
    if let Some(img) = g.as_ref() {
        let cpns = read_u32(img.vvar_frame, VVAR_CPNS);
        let offset = read_i64(img.vvar_frame, VVAR_OFF);
        write_vvar(img.vvar_frame, cpns.max(1), offset);
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
            perms: RegionPerms::READ | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT,
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
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
    }
}

fn read_u32(frame: PhysAddr, off: usize) -> u32 {
    // SAFETY: identity-mapped vvar frame; off+4 <= 4096.
    unsafe { core::ptr::read_volatile((frame.kernel_ptr::<u8>()).add(off) as *const u32) }
}

fn read_i64(frame: PhysAddr, off: usize) -> i64 {
    // SAFETY: identity-mapped vvar frame; off+8 <= 4096 and off is 8-aligned.
    unsafe { core::ptr::read_volatile((frame.kernel_ptr::<u8>()).add(off) as *const i64) }
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
    let base = frame.kernel_mut_ptr::<u8>();
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
        core::ptr::write_volatile(
            base.add(VVAR_CLOCK_MODE) as *mut u32,
            CLOCK_MODE.load(Ordering::Acquire),
        );
        fence(Ordering::Release);
        core::ptr::write_volatile(seq_ptr, (seq | 1).wrapping_add(1)); // even
    }
}
