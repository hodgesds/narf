//! Intel KeyLocker.
//!
//! Spec: `arch/specification/cpu-security.md` §6.
//!
//! KeyLocker wraps user-supplied AES keys with a CPU-internal
//! key (the IWKEY) into "handles." Userspace then computes
//! AES-128 / AES-256 against handles instead of plaintext
//! keys, so a memory leak or stale-buffer disclosure of a
//! handle doesn't compromise the key material.
//!
//! Stage cut: detection only. Instruction wrappers
//! (`LOADIWKEY` / `ENCODEKEY128` / `ENCODEKEY256` /
//! `AESENC128KL` / etc.) land when a userspace crypto consumer
//! needs them.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

/// `true` iff CPUID(7, 0).ECX[23] is set (KL feature present).
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 valid.
    let (_, _, ecx, _) = unsafe { cpuid(7, 0) };
    ecx & (1 << 23) != 0
}

/// CPUID(0x19, 0).EAX bitmap — feature variants present.
///
/// | bit | feature                                    |
/// |-----|--------------------------------------------|
/// | 0   | AES_KLE (KeyLocker)                        |
/// | 2   | KL wide (KeyLocker wide-instruction subset)|
/// | 3   | KL with hardware key support               |
pub fn caps() -> u32 {
    if !supported() {
        return 0;
    }
    // SAFETY: leaf 0x19 valid when bit 23 of CPUID(7).ECX is set.
    let (eax, _, _, _) = unsafe { cpuid(0x19, 0) };
    eax
}

pub const KL_AES_KLE: u32 = 1 << 0;
pub const KL_WIDE: u32 = 1 << 2;
pub const KL_HARDWARE_KEY: u32 = 1 << 3;
