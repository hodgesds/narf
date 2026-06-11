//! CPUID feature detection.
//!
//! Stage 2 uses this to probe for PKS, UIPI, NX, and a handful of
//! related features before enabling the corresponding MSR / CR bits.
//! The spec (`arch/` §4) is clear that required features fail boot
//! and optional features degrade to fallbacks — this module provides
//! the raw queries; policy lives in `frame/`.

use core::arch::asm;

/// Raw CPUID leaf read: returns (eax, ebx, ecx, edx).
///
/// # Safety
/// `CPUID` is legal at CPL=0 for any leaf; invalid leaves return
/// zeros in all four output registers rather than faulting. Safe
/// in any context but marked `unsafe` for consistency with the
/// rest of `arch/`'s privileged-instruction wrappers.
#[inline]
pub unsafe fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (a, c, d): (u32, u32, u32);
    let b: u64;
    // LLVM reserves rbx; the conventional workaround is to save it
    // around CPUID via push/pop and move the result into a scratch
    // register that Rust can see.
    // SAFETY: CPUID is always legal at CPL=0; we preserve rbx.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {b:r}, rbx",
            "pop rbx",
            inout("eax") leaf => a,
            inout("ecx") sub  => c,
            out("edx") d,
            b = out(reg) b,
            options(nostack, preserves_flags),
        );
    }
    (a, b as u32, c, d)
}

/// CPU-feature flags we care about during Stage 1–2 bring-up. Each
/// flag has a `has_*` accessor rather than a single `FeatureFlags`
/// bitset because the sources (multiple CPUID leaves) don't all live
/// in the same register.
#[derive(Copy, Clone, Debug, Default)]
pub struct Features {
    pub nx: bool,            // leaf 80000001h EDX:20 — NX page bit
    pub pku: bool,           // leaf 7, sub 0 ECX:3  — user-mode protection keys
    pub pks: bool,           // leaf 7, sub 0 ECX:31 — supervisor protection keys
    pub uipi: bool,          // leaf 7, sub 0 EDX:13 — User Interrupts
    pub invariant_tsc: bool, // leaf 80000007h EDX:8
    pub rdseed: bool,        // leaf 7, sub 0 EBX:18
    pub rdrand: bool,        // leaf 1 ECX:30
    pub x2apic: bool,        // leaf 1 ECX:21
    pub apic: bool,          // leaf 1 EDX:9
    pub tsc_deadline: bool,  // leaf 1 ECX:24 — LAPIC TSC-deadline mode
    /// Always Running APIC Timer: leaf 0x06 EAX:2.
    ///
    /// Intel-only feature (AMD doesn't populate CPUID 0x06 — the
    /// "Thermal and Power Management" leaf is Intel-architected).
    /// When set, the LAPIC timer does NOT stop in C3 or deeper
    /// C-states. Linux uses this to (a) clear the C3STOP feature
    /// from the LAPIC clockevent and (b) bump its rating above
    /// HPET so the per-CPU LAPIC timer is preferred over the
    /// global HPET as the primary clockevent on Intel ≥ Nehalem.
    /// See `setup_APIC_timer` in `arch/x86/kernel/apic/apic.c`.
    pub arat: bool,
    /// Hybrid topology indicator: leaf 7 sub 0 EDX:15.
    ///
    /// Intel Alder Lake (12th gen) and later — and only Intel —
    /// set this bit to signal that CPUID leaf 0x1A exposes per-LP
    /// `core_type` in EAX[31:24]. AMD parts and pre-12th-gen Intel
    /// leave the bit clear, in which case leaf 0x1A is reserved
    /// and reads zero (which decodes to `CpuType::Unknown` — the
    /// right answer for uniform-core silicon).
    ///
    /// This flag is a *capability* probe only; the actual core
    /// type is per-CPU and read via `read_hybrid_cpu_type()` from
    /// each CPU's bring-up path.
    pub hybrid: bool,
}

impl Features {
    /// Probe CPUID and build the Stage-2 feature snapshot.
    ///
    /// # Safety
    /// CPUID is always legal; marked `unsafe` for the inline-asm
    /// boundary only.
    pub unsafe fn probe() -> Self {
        let mut f = Features::default();

        // Leaf 1: ECX:21 = x2APIC, ECX:30 = RDRAND, EDX:9 = APIC.
        // SAFETY: CPUID at CPL=0 is always defined.
        let (_, _, ecx1, edx1) = unsafe { cpuid(0x0000_0001, 0) };
        f.rdrand = ecx1 & (1 << 30) != 0;
        f.x2apic = ecx1 & (1 << 21) != 0;
        f.apic = edx1 & (1 << 9) != 0;
        f.tsc_deadline = ecx1 & (1 << 24) != 0;

        // Leaf 7, sub 0 — extended features.
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        let (_, ebx7, ecx7, edx7) = unsafe { cpuid(0x0000_0007, 0) };
        f.rdseed = ebx7 & (1 << 18) != 0;
        f.pku = ecx7 & (1 << 3) != 0;
        f.pks = ecx7 & (1 << 31) != 0;
        f.uipi = edx7 & (1 << 13) != 0;
        // EDX:15 = Hybrid topology indicator (Intel Alder Lake+).
        // When set, CPUID leaf 0x1A exposes per-LP core_type.
        f.hybrid = edx7 & (1 << 15) != 0;

        // Leaf 80000001h EDX:20 = NX.
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        let (_, _, _, edx_ext) = unsafe { cpuid(0x8000_0001, 0) };
        f.nx = edx_ext & (1 << 20) != 0;

        // Leaf 80000007h EDX:8 = Invariant TSC.
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        let (_, _, _, edx_adv) = unsafe { cpuid(0x8000_0007, 0) };
        f.invariant_tsc = edx_adv & (1 << 8) != 0;

        // Leaf 0x06 EAX:2 = ARAT (Always Running APIC Timer). Only
        // populated on Intel — AMD parts return 0 for the whole
        // "Thermal and Power Management" leaf. CPUID max guard
        // ensures we don't read past the implemented range.
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        let (max, _, _, _) = unsafe { cpuid(0, 0) };
        if max >= 6 {
            // SAFETY: the operation upholds its documented invariant (see surrounding context).
            let (eax6, _, _, _) = unsafe { cpuid(0x0000_0006, 0) };
            f.arat = eax6 & (1 << 2) != 0;
        }

        f
    }
}

/// Read this CPU's hybrid `core_type` byte from CPUID leaf 0x1A
/// EAX[31:24] (Intel Alder Lake+). Returns the raw 8-bit value so the
/// caller can decode it through `narf_lib::percpu::CpuType::from_raw`
/// — keeping the byte-level encoding (matching Linux's
/// `X86_CPU_TYPE_*` defines) at the arch boundary.
///
/// On AMD silicon and pre-12th-gen Intel, leaf 0x1A is reserved and
/// reads zero, decoding to `CpuType::Unknown`. QEMU TCG and most
/// hypervisor guests also report zero. Callers MUST gate on
/// `Features::hybrid` before invoking this in the hot path; the
/// CPUID-max guard below makes a stray call safe but pointless.
///
/// **This is per-CPU**: each AP must call it from its own bring-up
/// path. Calling it on the BSP for AP-0's type gives the wrong answer
/// on heterogeneous parts where the calling CPU isn't AP-0.
///
/// Reference: Linux `arch/x86/kernel/cpu/intel.c::intel_get_cpu_type`,
/// callable as `get_this_hybrid_cpu_type()` from cpufreq + sched.
///
/// # Safety
/// CPUID is always legal at CPL=0; marked `unsafe` for the inline-asm
/// boundary only.
pub unsafe fn read_hybrid_cpu_type() -> u8 {
    // SAFETY: CPUID at CPL=0 is always defined.
    let (max, _, _, _) = unsafe { cpuid(0, 0) };
    if max < 0x1A {
        // Pre-Alder-Lake Intel or AMD — leaf doesn't exist.
        return 0;
    }
    // SAFETY: leaf 0x1A is now within the implemented range.
    let (eax, _, _, _) = unsafe { cpuid(0x0000_001A, 0) };
    (eax >> 24) as u8
}
