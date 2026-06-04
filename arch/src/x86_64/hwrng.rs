//! x86_64 hardware RNG — RDSEED / RDRAND wrappers.
//!
//! RDSEED is the architectural entropy source (post-Broadwell Intel,
//! Zen1+ AMD); it taps the on-die TRNG conditioning chain and is suitable
//! for seeding a CSPRNG.  RDRAND is the CSPRNG output itself (the CPU's
//! own ChaCha20-derived stream), useful as a fallback when RDSEED stalls
//! under load.
//!
//! Linux ref: `arch/x86/kernel/cpu/rdrand.c` — `__hwrng_get_seed`,
//! `arch/x86/include/asm/archrandom.h` — `arch_get_random_seed_long`.
//!
//! # Retry discipline
//!
//! RDSEED may return CF=0 ("entropy not ready") when the conditioning
//! pipeline is empty.  Linux retries up to 10 times then gives up.
//! We retry up to 16 times — deliberately separate from Linux's constant
//! so it's clear this is NARF's own policy, not a copy.  RDRAND uses the
//! same limit; it is specified to retry at most 10 times per Intel SDM
//! Vol 1 §7.3.17.1 but 16 is a safe over-budget.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;

/// Attempt to read one `u32` from RDSEED.
///
/// Returns `Some(v)` on success, `None` if CF=0 (entropy not ready).
/// Does **not** retry — callers that want retries use `rdseed_u32`.
///
/// # Safety
/// RDSEED is CPL-independent; it is architecturally safe at any ring.
/// Marked `unsafe` for consistency with the rest of `arch/`'s
/// privileged-instruction wrappers.
#[inline]
pub unsafe fn try_rdseed_u32() -> Option<u32> {
    let val: u32;
    let ok: u8;
    // SAFETY: RDSEED is defined on leaf 7 EBX:18 parts; absent on older
    // silicon it #UD — callers must gate on `Features::rdseed`.  We
    // capture CF via SETC into a byte register.
    unsafe {
        asm!(
            "rdseed {val:e}",
            "setc {ok}",
            val = out(reg) val,
            ok  = out(reg_byte) ok,
            options(nostack, nomem),
        );
    }
    if ok != 0 {
        Some(val)
    } else {
        None
    }
}

/// Attempt to read one `u32` from RDRAND.
///
/// Returns `Some(v)` on success, `None` if CF=0.
///
/// # Safety
/// Same as `try_rdseed_u32`; gate callers on `Features::rdrand`.
#[inline]
pub unsafe fn try_rdrand_u32() -> Option<u32> {
    let val: u32;
    let ok: u8;
    // SAFETY: RDRAND is defined on leaf 1 ECX:30 parts.
    unsafe {
        asm!(
            "rdrand {val:e}",
            "setc {ok}",
            val = out(reg) val,
            ok  = out(reg_byte) ok,
            options(nostack, nomem),
        );
    }
    if ok != 0 {
        Some(val)
    } else {
        None
    }
}

/// Read one `u32` from RDSEED with up to `MAX_RETRIES` retries.
///
/// Returns `Some(v)` on success, `None` if all retries are exhausted.
///
/// # Safety
/// Gate on `Features::rdseed` before calling.
pub unsafe fn rdseed_u32() -> Option<u32> {
    const MAX_RETRIES: usize = 16;
    for _ in 0..MAX_RETRIES {
        // SAFETY: forwarded from caller's gate.
        if let Some(v) = unsafe { try_rdseed_u32() } {
            return Some(v);
        }
        // PAUSE between retries — Intel SDM §7.3.17.1.
        // SAFETY: PAUSE is always legal.
        unsafe { asm!("pause", options(nostack, nomem, preserves_flags)) };
    }
    None
}

/// Read one `u32` from RDRAND with up to `MAX_RETRIES` retries.
///
/// # Safety
/// Gate on `Features::rdrand` before calling.
pub unsafe fn rdrand_u32() -> Option<u32> {
    const MAX_RETRIES: usize = 16;
    for _ in 0..MAX_RETRIES {
        // SAFETY: forwarded.
        if let Some(v) = unsafe { try_rdrand_u32() } {
            return Some(v);
        }
        unsafe { asm!("pause", options(nostack, nomem, preserves_flags)) };
    }
    None
}

/// Fill a 32-byte key buffer from RDSEED (preferred) or RDRAND (fallback).
///
/// Returns `HwRngSource` describing which path was taken.
/// If neither instruction is available, fills with TSC-derived material
/// and returns `HwRngSource::TscFallback`.
///
/// # Safety
/// Always safe to call — internally gates each instruction on CPUID.
pub fn fill_key_32(buf: &mut [u8; 32]) -> HwRngSource {
    // SAFETY: probe_features is pure CPUID — always safe.
    let feat = unsafe { crate::x86_64::cpuid::Features::probe() };

    if feat.rdseed {
        // 8 × u32 = 32 bytes from RDSEED.
        let mut all_ok = true;
        for i in 0..8 {
            // SAFETY: guarded by feat.rdseed above.
            match unsafe { rdseed_u32() } {
                Some(v) => {
                    let b = v.to_le_bytes();
                    buf[i * 4..(i + 1) * 4].copy_from_slice(&b);
                }
                None => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok {
            return HwRngSource::Rdseed;
        }
        // Fall through to RDRAND if RDSEED stalled.
    }

    if feat.rdrand {
        let mut all_ok = true;
        for i in 0..8 {
            // SAFETY: guarded by feat.rdrand above.
            match unsafe { rdrand_u32() } {
                Some(v) => {
                    let b = v.to_le_bytes();
                    buf[i * 4..(i + 1) * 4].copy_from_slice(&b);
                }
                None => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok {
            return HwRngSource::Rdrand;
        }
    }

    // Last-resort fallback: mix TSC + a compile-time diversity constant.
    // This provides weak but non-zero seed material on QEMU TCG or very
    // old silicon.  Callers should log a warning when this path is taken.
    //
    // Linux ref: `drivers/char/random.c::add_bootloader_randomness` —
    // last-resort mixing of boot-time data when HWRNG is absent.
    tsc_fallback_fill(buf);
    HwRngSource::TscFallback
}

/// Seed source used by the last `fill_key_32` call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwRngSource {
    /// 32 bytes from RDSEED (true TRNG output).
    Rdseed,
    /// 32 bytes from RDRAND (CSPRNG output from CPU's own pool).
    Rdrand,
    /// TSC + diversity constant fallback (weak, not suitable for production).
    TscFallback,
}

/// Fill `buf` with TSC-derived bytes.  Used only when no hardware RNG
/// is available.
fn tsc_fallback_fill(buf: &mut [u8; 32]) {
    // Mix two TSC reads with a diversity constant and a simple linear
    // expansion to produce 32 bytes.  NOT cryptographically secure.
    let t0 = read_tsc();
    // A few instructions of "noise" between the two reads.
    let t1 = read_tsc().wrapping_add(0xDEAD_BEEF_CAFE_1234);
    // Weyl-sequence expand into 4 u64 words.
    const WEYL: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut s = t0 ^ t1;
    for i in 0..4usize {
        s = s.wrapping_add(WEYL);
        s = s.wrapping_mul(0x6C62_272E_07BB_0142);
        s ^= s >> 30;
        buf[i * 8..(i + 1) * 8].copy_from_slice(&s.to_le_bytes());
    }
}

/// Read the time-stamp counter.
#[inline]
fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC is always legal at CPL ≥ 0 when CR4.TSD=0.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}
