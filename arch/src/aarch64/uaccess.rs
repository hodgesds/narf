//! aarch64 fault-guarded kernel↔user byte copy.
//!
//! This is the aarch64 analogue of `crate::x86_64::smap::copy_user_guarded`
//! (Linux analogue: `arch/arm64/lib/copy_from_user.S` /
//! `copy_to_user.S` plus their exception-table `_asm_extable` fixups).
//!
//! aarch64 has no SMAP/STAC window to open — PAN is the closest analogue
//! and NARF does not gate the kernel↔user channel on it — so this helper
//! is purely the fault-fixup half: it performs a byte-wise copy inside a
//! window where the per-CPU recoverable probe (`crate::aarch64::probe`)
//! is armed. Faults the EL1 data-abort handler can heal transparently —
//! demand-paging a fresh mmap page, stack growth, COW split — run FIRST
//! on the abort path and `eret` back to the faulting `ldrb`/`strb`, which
//! resumes cleanly (the loop's whole state lives in the loop registers);
//! the probe never fires for those. Only faults with no recovery reach
//! `probe::consume`, which redirects `ELR_EL1` to the local recovery
//! label past the copy — exactly the x86_64 shape.
//!
//! Returns `Ok(())` on a complete copy, `Err(bytes_remaining)` when a
//! fault was caught (`bytes_remaining` counts the not-copied tail of the
//! whole `len`; always > 0 on `Err`).
//!
//! The transfer is chunked (64 KiB) and each chunk runs with IRQs masked:
//! the probe slot is per-CPU and single-depth, so an IRQ-driven context
//! switch while armed would let another task on this CPU clobber the
//! armed probe. 64 KiB bounds each IRQ-off window; the 16 MiB
//! `MAX_USER_COPY` worst case is 256 short windows, not one blackout.
//! This mirrors the x86_64 constraint exactly.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use crate::aarch64::probe;

/// Per-CPU marker for the interval where [`copy_user_guarded`] owns the
/// recoverable-probe slot. A data abort in this interval may allocate a page
/// synchronously, but may not park for reclaim without leaking the probe into
/// another task (or another CPU after migration).
#[repr(C, align(64))]
struct GuardedCopyMarker {
    armed: AtomicBool,
    _pad: [u8; 63],
}

impl GuardedCopyMarker {
    const fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            _pad: [0; 63],
        }
    }
}

const _: () = assert!(core::mem::size_of::<GuardedCopyMarker>() == 64);

static GUARDED_COPY: [GuardedCopyMarker; narf_lib::percpu::MAX_CPUS] =
    [const { GuardedCopyMarker::new() }; narf_lib::percpu::MAX_CPUS];

#[inline]
fn guarded_copy_marker() -> &'static GuardedCopyMarker {
    let cpu = crate::current_cpu_id().raw() as usize;
    &GUARDED_COPY[cpu.min(narf_lib::percpu::MAX_CPUS - 1)]
}

/// Whether this CPU is inside [`copy_user_guarded`]'s probe window.
#[doc(hidden)]
#[inline]
pub fn guarded_copy_armed() -> bool {
    guarded_copy_marker().armed.load(Ordering::Acquire)
}

#[inline]
fn set_guarded_copy_armed(armed: bool) {
    let marker = guarded_copy_marker();
    let old = marker.armed.load(Ordering::Relaxed);
    debug_assert_ne!(old, armed, "nested or unbalanced guarded user copy");
    // This record has one writer: its own CPU with IRQs masked. A release
    // store is sufficient for the synchronous abort handler's acquire load.
    marker.armed.store(armed, Ordering::Release);
}

/// Fault-guarded byte copy from `src` to `dst` for `len` bytes.
///
/// # Safety
/// - EL1, not IRQ context.
/// - The *kernel* side (`dst` for a from-user copy, `src` for a to-user
///   copy) must be valid for `len` bytes. The *other* side may be an
///   arbitrary (even hostile) user pointer — surviving it is the point.
pub unsafe fn copy_user_guarded(dst: *mut u8, src: *const u8, len: usize) -> Result<(), usize> {
    const CHUNK: usize = 64 * 1024;
    let mut done = 0usize;
    while done < len {
        let n = core::cmp::min(CHUNK, len - done);

        // Save DAIF.I, then mask IRQs: no context switch may run while
        // the probe is armed (single per-CPU slot). `disable_interrupts`
        // is idempotent, so we read DAIF first to know whether to
        // re-enable afterwards.
        let daif: u64;
        // SAFETY: reading DAIF at EL1 is always defined.
        unsafe {
            asm!("mrs {d}, daif", d = out(reg) daif, options(nomem, nostack, preserves_flags));
        }
        let irqs_were_unmasked = (daif & (1 << 7)) == 0;
        // SAFETY: masking IRQs at EL1 is always legal.
        unsafe {
            crate::aarch64::asm::disable_interrupts();
        }

        // Compute the recovery PC (the address of the `99:` label below)
        // and arm the probe with it. On an unrecoverable data abort the
        // handler rewrites ELR_EL1 to this address; the loop's `count`
        // register (x-reg bound to `remaining`) then holds the bytes not
        // yet copied for this chunk.
        let recovery: u64;
        // SAFETY: ADR of a local label. `99f` resolves forward into the
        // copy block below.
        unsafe {
            asm!("adr {r}, 99f", r = out(reg) recovery, options(nostack, preserves_flags));
        }
        set_guarded_copy_armed(true);
        probe::arm(recovery);

        let remaining: usize;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: `dst`/`src` advanced by `done`; the kernel side is
        // valid for the whole `len` by contract, the user side may fault.
        // On an unrecoverable abort the handler sets ELR to `99:` with
        // `remaining` = bytes left in this chunk; on a healed abort the
        // `eret` re-executes the faulting `ldrb`/`strb` with the same
        // register state and the loop continues.
        unsafe {
            asm!(
                "1:",
                "cbz {cnt}, 99f",
                "ldrb {tmp:w}, [{s}]",
                "strb {tmp:w}, [{d}]",
                "add {s}, {s}, #1",
                "add {d}, {d}, #1",
                "sub {cnt}, {cnt}, #1",
                "b 1b",
                "99:",
                s = inout(reg) src.add(done) => _,
                d = inout(reg) dst.add(done) => _,
                cnt = inout(reg) n => remaining,
                tmp = out(reg) _,
                options(nostack),
            );
        }
        compiler_fence(Ordering::SeqCst);

        let caught = probe::disarm();
        set_guarded_copy_armed(false);

        // Restore IRQ mask exactly as found.
        if irqs_were_unmasked {
            // SAFETY: re-enabling interrupts we masked above.
            unsafe {
                crate::aarch64::asm::enable_interrupts();
            }
        }

        if caught.fired {
            // `remaining` is the count left in *this* chunk; the tail of
            // the whole `len` is the untouched later chunks plus that.
            return Err(len - done - (n - remaining));
        }
        done += n;
    }
    Ok(())
}
