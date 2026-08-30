//! Control-register access.
//!
//! Every entry point takes the compiler_fence(SeqCst) pair per
//! `arch/` §4: CR4 in particular gates PKS / UIPI / OSFXSR, and fat
//! LTO reordering across the write is specifically a correctness
//! hazard the spec names.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

/// Cached copy of CR4, maintained by [`write_cr4`]. The trap/syscall entry
/// prologue reads this from MEMORY instead of executing `mov rax, cr4` to test
/// CR4.PKS (bit 24) / CR4.PCIDE (bit 17) and decide whether to enter a FRAME
/// isolation domain. Under KVM/SVM a `mov from CR4` VMEXITs, so reading the
/// register on every syscall + trap cost ~248k VMEXITs/sec under a redis load
/// (the dominant exit reason, ~half of all exit time). Those two bits are set
/// once at boot and never change (the domain switch writes CR3, never CR4), so
/// the cached value is always correct for the branch. `#[no_mangle]` because
/// the entry assembly references it by symbol via RIP (a linker-private
/// architecture ABI, like `NARF_X86_FRAME_PML4`).
#[unsafe(no_mangle)]
pub static NARF_X86_CACHED_CR4: AtomicU64 = AtomicU64::new(0);

/// CR4 bit: PKS (bit 24). Enables supervisor protection keys
/// (IA32_PKRS-based domain rights).
pub const CR4_PKS: u64 = 1 << 24;
/// CR4 bit: PKE (bit 22). Enables user-mode protection keys.
pub const CR4_PKE: u64 = 1 << 22;
/// CR4 bit: PCIDE (bit 17). Enables Process-Context Identifiers; once set,
/// CR3 carries a 12-bit PCID in bits 0..=11 and bit 63 of a CR3 write
/// can preserve the previous PCID's TLB entries instead of flushing.
pub const CR4_PCIDE: u64 = 1 << 17;
/// CR4 bit: OSXSAVE (bit 18). Enables XSAVE and processor extended states.
pub const CR4_OSXSAVE: u64 = 1 << 18;

/// Read CR4.
///
/// # Safety
/// `MOV from CR4` is legal at CPL=0.
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MOV from CR4 at CPL=0 is always legal.
    unsafe {
        asm!("mov {out}, cr4", out = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write CR4.
///
/// # Safety
/// - Only bits documented as writable may be set.
/// - Enabling new features may require other setup first (e.g. CR4.PKS
///   requires CPUID.(07h:0).ECX:31=1, else `#GP`).
#[inline]
pub unsafe fn write_cr4(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller verified feature availability.
    unsafe {
        asm!("mov cr4, {v}", v = in(reg) value,
             options(nomem, nostack, preserves_flags));
    }
    // Keep the entry-prologue's cached copy in step with the register so the
    // trap/syscall path can test CR4.PKS/PCIDE from memory (no VMEXIT). Stored
    // AFTER the write so a concurrent entry reads either the old or new value,
    // never a torn one; feature bits change only during boot/AP bringup.
    NARF_X86_CACHED_CR4.store(value, Ordering::Release);
    compiler_fence(Ordering::SeqCst);
}

/// Read CR3 (page-table base + PCID, when CR4.PCIDE=1).
///
/// # Safety
/// `MOV from CR3` is legal at CPL=0.
#[inline]
pub unsafe fn read_cr3() -> u64 {
    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MOV from CR3 at CPL=0 is always legal.
    unsafe {
        asm!("mov {out}, cr3", out = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write CR3. When CR4.PCIDE=1, the low 12 bits encode a PCID and bit
/// 63 ("noflush") preserves the previous PCID's TLB entries.
///
/// # Safety
/// - The page-table base bits (PA bits, 12..=51) must point at a valid
///   4 KiB-aligned PML4 mapped writable in the current address space.
/// - When CR4.PCIDE=0, bits 0..=11 must encode legacy PWT/PCD and 0;
///   when CR4.PCIDE=1 they encode the PCID.
#[inline]
pub unsafe fn write_cr3(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller upholds the contract above.
    unsafe {
        asm!("mov cr3, {v}", v = in(reg) value,
             options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}
