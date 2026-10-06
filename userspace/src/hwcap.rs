//! `AT_HWCAP` / `AT_HWCAP2` — the CPU-capability words libc reads at startup.
//!
//! These are the only channel a process has for discovering what the hardware
//! can do before it may execute a feature-dependent instruction. On aarch64 in
//! particular they are load-bearing: libc selects its `memcpy`/`strlen` variants
//! from `AT_HWCAP`, and `HWCAP2_MTE` is how a program learns it may use Memory
//! Tagging at all. This kernel supported MTE while advertising `AT_HWCAP2 == 0`
//! and emitting no `AT_HWCAP` entry whatsoever, so no userspace could find it.
//!
//! Bit assignments are Linux's (`arch/arm64/include/uapi/asm/hwcap.h`, and for
//! x86 the `CPUID.1:EDX` word `ELF_HWCAP` carries); they are ABI, so they are
//! spelled out rather than derived.

/// aarch64 `AT_HWCAP` bits this kernel can attest to.
#[cfg(target_arch = "aarch64")]
mod bits {
    pub const HWCAP_FP: u64 = 1 << 0;
    pub const HWCAP_ASIMD: u64 = 1 << 1;
    pub const HWCAP_ATOMICS: u64 = 1 << 8;
    pub const HWCAP_PACA: u64 = 1 << 30;
    pub const HWCAP2_BTI: u64 = 1 << 17;
    pub const HWCAP2_MTE: u64 = 1 << 18;
    pub const HWCAP2_MTE3: u64 = 1 << 22;
}

/// `(AT_HWCAP, AT_HWCAP2)` for this machine.
///
/// Reports only what the kernel has actually probed and can support. An
/// over-reported bit is worse than a missing one: libc will execute the
/// instruction it implies, and a wrong answer is an illegal-instruction fault
/// in userspace with no diagnostic.
#[cfg(target_arch = "aarch64")]
pub fn hwcaps() -> (u64, u64) {
    use bits::*;
    // SAFETY: `MRS` on the ID_AA64*_EL1 registers is legal at EL1 and has no
    // side effects; this runs on the boot/exec path at EL1.
    let features = unsafe { narf_arch::aarch64::cpuid::Features::probe() };

    // FP and AdvSIMD are mandatory in ARMv8-A and their ID fields use 0b1111
    // for "not implemented", so anything else means present.
    let mut hwcap = HWCAP_FP | HWCAP_ASIMD;
    // Large System Extensions (LSE) atomics: libc's lock fast paths select on
    // this, and using `casal` without it faults.
    // SAFETY: as above — an ID-register read at EL1.
    if unsafe { narf_arch::aarch64::cpuid::lse_atomics() } {
        hwcap |= HWCAP_ATOMICS;
    }
    if features.pauth {
        hwcap |= HWCAP_PACA;
    }

    let mut hwcap2 = 0;
    if features.bti {
        hwcap2 |= HWCAP2_BTI;
    }
    // Only advertise MTE once the kernel's own tagging support is live —
    // advertising it while tag checking is off would invite userspace to tag
    // pointers the kernel then fails to check.
    if features.mte >= 2 && narf_arch::aarch64::mte::supported() {
        hwcap2 |= HWCAP2_MTE;
        if features.mte >= 3 {
            hwcap2 |= HWCAP2_MTE3;
        }
    }
    (hwcap, hwcap2)
}

/// `(AT_HWCAP, AT_HWCAP2)` for this machine.
///
/// x86_64's `AT_HWCAP` is the `CPUID.1:EDX` feature word, exactly as Linux's
/// `ELF_HWCAP` is defined. Userspace on this arch mostly calls `CPUID` itself,
/// so the word matters less than on aarch64 — but glibc still reads it, and an
/// absent entry reads as zero, which claims the CPU has no FPU.
#[cfg(target_arch = "x86_64")]
pub fn hwcaps() -> (u64, u64) {
    // SAFETY: `CPUID` leaf 1 is architecturally present on every x86_64 CPU and
    // has no side effects.
    let (_, _, _, edx) = unsafe { narf_arch::x86_64::cpuid::cpuid(1, 0) };
    // HWCAP2_FSGSBASE (bit 1, arch/x86/include/uapi/asm/hwcap2.h): Linux sets
    // it when CR4.FSGSBASE is on (arch/x86/kernel/cpu/common.c), telling
    // userspace it may use RD/WR{FS,GS}BASE directly. NARF enables CR4.FSGSBASE
    // and saves/restores both bases per task across every switch. RING3MWAIT
    // is not implemented and stays clear.
    const HWCAP2_FSGSBASE: u64 = 1 << 1;
    let hwcap2 = if narf_arch::x86_64::cr::cached_cr4() & narf_arch::x86_64::cr::CR4_FSGSBASE != 0 {
        HWCAP2_FSGSBASE
    } else {
        0
    };
    (u64::from(edx), hwcap2)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn hwcaps() -> (u64, u64) {
    (0, 0)
}
