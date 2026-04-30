//! Typed MMIO accessors with arch-correct ordering barriers.
//!
//! Replaces the open-coded
//! `compiler_fence(SeqCst); read_volatile(...); compiler_fence(SeqCst)`
//! pattern that drivers wrote at every BAR access. That pattern was
//! correct on x86_64 (TSO + volatile is enough for MMIO ordering) but
//! underconstrained on aarch64, where compiler_fence emits *no*
//! hardware barrier — only a load-load reorder hint to LLVM. A
//! seemingly fine `mmio_write(reg_a, x); mmio_read(reg_b)` could
//! observe the read complete before the write reached the device.
//!
//! Contract:
//! - **read32 / read16 / read8**: single naturally-aligned MMIO load.
//!   On aarch64 framed by `dmb ishld` so subsequent loads observe the
//!   value; on x86_64 the volatile load is sufficient.
//! - **write32 / write16 / write8**: single naturally-aligned MMIO
//!   store. On aarch64 framed by `dmb ishst` (before) and `dsb st`
//!   (after) so the write actually leaves the store buffer for the
//!   peripheral interconnect; on x86_64 volatile-store + the
//!   surrounding compiler_fence is enough.
//!
//! All accessors take a `va: u64` (kernel virtual address — typically
//! produced by `narf_memory::ioremap` or the boot identity map). The
//! caller's responsibility:
//! - The address must be naturally aligned for the access width.
//! - The mapping must permit the operation (RW for stores).
//! - The peripheral must tolerate the access at this offset (no
//!   read-side effects the caller didn't want, no atomicity violation
//!   on a partial-width register, etc.).

use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn dmb_ishld() {
    // SAFETY: dmb is always legal at any privilege level.
    unsafe { core::arch::asm!("dmb ishld", options(nostack, preserves_flags, nomem)); }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn dmb_ishst() {
    // SAFETY: same.
    unsafe { core::arch::asm!("dmb ishst", options(nostack, preserves_flags, nomem)); }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn dsb_st() {
    // SAFETY: same.
    unsafe { core::arch::asm!("dsb st", options(nostack, preserves_flags, nomem)); }
}

// ── reads ──────────────────────────────────────────────────────────

/// Read a naturally-aligned 32-bit MMIO register at `va`.
///
/// # Safety
/// `va` must be a writable kernel mapping covering [va, va+4); the
/// device must tolerate the read at this offset.
#[inline]
pub unsafe fn read32(va: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted; volatile defeats the load combiner.
    let v = unsafe { core::ptr::read_volatile(va as *const u32) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dmb_ishld(); }
    compiler_fence(Ordering::SeqCst);
    v
}

/// 16-bit MMIO read; same shape as [`read32`].
///
/// # Safety
/// See [`read32`].
#[inline]
pub unsafe fn read16(va: u64) -> u16 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted.
    let v = unsafe { core::ptr::read_volatile(va as *const u16) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dmb_ishld(); }
    compiler_fence(Ordering::SeqCst);
    v
}

/// 8-bit MMIO read; same shape as [`read32`].
///
/// # Safety
/// See [`read32`].
#[inline]
pub unsafe fn read8(va: u64) -> u8 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted.
    let v = unsafe { core::ptr::read_volatile(va as *const u8) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dmb_ishld(); }
    compiler_fence(Ordering::SeqCst);
    v
}

// ── writes ─────────────────────────────────────────────────────────

/// Write a naturally-aligned 32-bit MMIO register at `va`.
///
/// # Safety
/// `va` must be a writable kernel mapping covering [va, va+4); the
/// caller owns the device exclusively for the duration.
#[inline]
pub unsafe fn write32(va: u64, value: u32) {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dmb_ishst(); }
    // SAFETY: caller-asserted; volatile defeats the store combiner.
    unsafe { core::ptr::write_volatile(va as *mut u32, value); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal. dsb st pushes the store out of
    // the local CPU's buffer onto the interconnect, so the device
    // sees it before any subsequent CPU operation.
    unsafe { dsb_st(); }
    compiler_fence(Ordering::SeqCst);
}

/// 16-bit MMIO write; same shape as [`write32`].
///
/// # Safety
/// See [`write32`].
#[inline]
pub unsafe fn write16(va: u64, value: u16) {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dmb_ishst(); }
    // SAFETY: caller-asserted.
    unsafe { core::ptr::write_volatile(va as *mut u16, value); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dsb_st(); }
    compiler_fence(Ordering::SeqCst);
}

/// 8-bit MMIO write; same shape as [`write32`].
///
/// # Safety
/// See [`write32`].
#[inline]
pub unsafe fn write8(va: u64, value: u8) {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dmb_ishst(); }
    // SAFETY: caller-asserted.
    unsafe { core::ptr::write_volatile(va as *mut u8, value); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: barrier always legal.
    unsafe { dsb_st(); }
    compiler_fence(Ordering::SeqCst);
}
