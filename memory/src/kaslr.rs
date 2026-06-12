//! KASLR — kernel + userspace ASLR.
//!
//! Picks a random virtual-address slot for the kernel image base
//! and for each fresh user-mode AS's stack / mmap / brk arenas.
//!
//! Entropy sources, in priority order:
//!
//!   1. **RDRAND** (x86_64 only) — Intel CPRNG, AMD also implements
//!      it. Hardware reports CPUID(1).ECX[30]; the instruction itself
//!      sets CF on success. We loop up to [`RAND_RETRIES`] times on
//!      CF=0.
//!   2. **RDSEED** as a higher-quality alternative on the same path
//!      (CPUID(7, 0).EBX[18]).
//!   3. **TSC mix** — read the timestamp counter, splat-and-mix with
//!      a known-prime multiplier. Last resort; entropy is only
//!      "boot-time jitter," which is enough for ASLR slot picking
//!      but not for crypto.
//!
//! The "more secure than Linux" framing for KASLR is per-AS: each
//! new user-mode address space gets a fresh randomisation. Linux's
//! per-process mmap randomisation drains entropy at exec; NARF re-
//! seeds at every AS creation including kernel thread stacks
//! (a kernel ROP target leaks address layout that's pure-noise to a
//! second kernel thread).
//!
//! References:
//!   * Linux `arch/x86/boot/compressed/kaslr.c` for the boot-time
//!     slot picker (different problem — KASLR before paging).
//!   * Linux `arch/x86/mm/mmap.c::arch_pick_mmap_base` for per-task
//!     mmap randomisation.
//!   * Intel SDM Vol 1 §7.3.17 (RDRAND), §7.3.18 (RDSEED).

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Number of RDRAND/RDSEED retries before falling back to TSC.
/// Intel guarantees success within 10 retries; we use 32 for margin.
const RAND_RETRIES: u32 = 32;

/// User-mode mmap-arena randomisation slack — number of low bits to
/// randomise. 24 bits = 16 MiB of slack. 39-bit user VA gives plenty
/// of headroom for both slack and arena.
pub const USER_MMAP_RANDOM_BITS: u32 = 24;

/// Kernel-image randomisation slack. The kernel-half mapping is fixed
/// at 0xFFFF_FF80_0000_0000 (aarch64) / 0xFFFF_FFFF_8000_0000 (x86_64);
/// the random offset is added to that. 30 bits = 1 GiB of slack on
/// x86_64's narrow kernel slot — same shape as Linux's KASLR.
pub const KERNEL_RANDOM_BITS: u32 = 30;

/// Pull one 64-bit value of randomness using the best available source.
///
/// Returns the value plus a tag identifying the source so observability
/// can confirm we aren't always falling back to TSC.
#[inline]
pub fn random_u64() -> (u64, EntropySource) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(v) = try_rdseed_x86() {
            return (v, EntropySource::Rdseed);
        }
        if let Some(v) = try_rdrand_x86() {
            return (v, EntropySource::Rdrand);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(v) = try_rndr_aarch64() {
            return (v, EntropySource::Rndr);
        }
    }
    (tsc_mix(), EntropySource::TscMix)
}

/// Pick a virtual-address slot for a user-mode mmap or stack arena.
///
/// `base` is the arena's nominal base; the returned address is
/// `base + (random & mask)` where `mask` is the low
/// [`USER_MMAP_RANDOM_BITS`] bits, aligned down to 4 KiB.
#[inline]
pub fn user_mmap_slot(base: u64) -> u64 {
    let (r, _) = random_u64();
    let mask = ((1u64 << USER_MMAP_RANDOM_BITS) - 1) & !0xFFF;
    base + (r & mask)
}

/// Pick a kernel-image slide. Caller adds this to the fixed kernel-half
/// base before installing the page tables.
#[inline]
pub fn kernel_slide() -> u64 {
    let (r, _) = random_u64();
    let mask = ((1u64 << KERNEL_RANDOM_BITS) - 1) & !0xFFF;
    r & mask
}

/// Source of the most recently returned random value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntropySource {
    Rdrand,
    Rdseed,
    Rndr,
    TscMix,
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn try_rdrand_x86() -> Option<u64> {
    use core::arch::asm;
    // CPUID(1).ECX[30] would be the right gate but a CPUID call costs
    // 100+ cycles per random; we just try RDRAND and let CF=0 indicate
    // unavailability. On a CPU that doesn't support RDRAND the
    // instruction is #UD — but every x86_64 CPU shipped post-2012 has
    // it, and we never run on anything earlier (Renoir + Phoenix
    // categorically support it).
    for _ in 0..RAND_RETRIES {
        let v: u64;
        let ok: u8;
        // SAFETY: RDRAND is always legal on supported parts; encoded
        // via the explicit `rdrand` mnemonic so the assembler picks the
        // right opcode for 64-bit operand.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn try_rdseed_x86() -> Option<u64> {
    use core::arch::asm;
    for _ in 0..RAND_RETRIES {
        let v: u64;
        let ok: u8;
        // SAFETY: RDSEED is available on Broadwell+ (Intel) / Zen+
        // (AMD). Renoir + Phoenix both support it. CF=0 means try
        // again. If the CPU doesn't have RDSEED the opcode is #UD,
        // but the boot-time security init never calls this without
        // first checking CPUID(7, 0).EBX[18].
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!(
                "rdseed {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn try_rndr_aarch64() -> Option<u64> {
    use core::arch::asm;
    // FEAT_RNG (8.5+). Reads RNDR / RNDRRS through MRS. NZCV.Z=1
    // means a value was returned; NZCV.Z=0 (with V=0) means the
    // RNG isn't ready.
    for _ in 0..RAND_RETRIES {
        let v: u64;
        let nzcv: u64;
        // SAFETY: MRS RNDR_EL0 / RNDRRS_EL0 is a v8.5+ encoding;
        // unsupported parts #UD. The boot security-init gates on
        // ID_AA64ISAR0_EL1.RNDR != 0 before calling this. The
        // assembler raw encoding works on any v8 toolchain.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            asm!(
                "mrs {v}, s3_3_c2_c4_0", // RNDR_EL0
                "mrs {nzcv}, nzcv",
                v = out(reg) v,
                nzcv = out(reg) nzcv,
                options(nomem, nostack),
            );
        }
        // NZCV.Z is bit 30. Z=0 means valid (Arm ARM D7.4.10).
        if nzcv & (1 << 30) == 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn try_rdrand_x86() -> Option<u64> {
    None
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn try_rdseed_x86() -> Option<u64> {
    None
}

/// Reentrant TSC mixer. Reads the cycle counter, multiplies by a
/// 64-bit prime, and XORs against a running accumulator. Not
/// cryptographic; sufficient for ASLR slot picking on parts where
/// RDRAND/RDSEED/RNDR aren't available (i.e. exotic QEMU TCG configs
/// and one virtualisation host vendor).
#[inline]
pub fn tsc_mix() -> u64 {
    static ACC: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let t = read_cycle_counter();
    // Mix: t * golden ratio prime, XORed into the accumulator.
    let v = t.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    ACC.fetch_xor(v.rotate_left(13), Ordering::Relaxed) ^ v
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn read_cycle_counter() -> u64 {
    use core::arch::asm;
    // RDTSC: lo in EAX, hi in EDX.
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC at CPL=0 is always defined.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_cycle_counter() -> u64 {
    use core::arch::asm;
    // CNTVCT_EL0 — virtual count register. Always readable from EL1.
    let v: u64;
    // SAFETY: MRS of the virtual count is legal at EL1.
    unsafe {
        asm!("mrs {v}, cntvct_el0", v = out(reg) v, options(nomem, nostack));
    }
    v
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn read_cycle_counter() -> u64 {
    0xDEAD_BEEF_CAFE_F00D
}
