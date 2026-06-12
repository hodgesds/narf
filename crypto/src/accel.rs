//! Hardware-accelerated crypto — clean-room.
//!
//! ## Sources (public only)
//!
//! - **Intel® 64 and IA-32 Architectures Software Developer's
//!   Manual, Volume 2 (Instruction Set Reference)** — Intel.
//!   <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
//!   - AES-NI: `AESENC` / `AESENCLAST` / `AESDEC` / `AESDECLAST` /
//!     `AESKEYGENASSIST` (vol 2, "AES" entries).
//!   - SHA-NI: `SHA1RNDS4` / `SHA256RNDS2` / `SHA256MSG1` /
//!     `SHA256MSG2` (vol 2, "SHA" entries).
//!   - PCLMULQDQ for GHASH.
//! - **Arm Architecture Reference Manual for A-profile architecture
//!   (ARM ARM)** — Arm.
//!   <https://developer.arm.com/documentation/ddi0487/latest/>
//!   - `AESE` / `AESD` / `AESMC` / `AESIMC` (FEAT_AES).
//!   - `SHA1H` / `SHA1C` / `SHA1P` / `SHA1M` (FEAT_SHA1).
//!   - `SHA256H` / `SHA256H2` / `SHA256SU0` / `SHA256SU1` (FEAT_SHA256).
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Two pieces:
//!
//! 1. **Capability detection** — `Features::probe()` reads CPUID
//!    (x86) or `ID_AA64ISAR0_EL1` (aarch64) once and exposes a
//!    static struct callers consult before dispatching to a
//!    hardware-accelerated path.
//! 2. **Per-instruction wrappers** — single-block primitives the
//!    full AES / SHA implementations build on. AES round, SHA-256
//!    round, GHASH product. Each wrapper tightly mirrors one
//!    instruction so it stays inspectable and benchmarkable.
//!
//! Full key-schedule expansion / mode (CBC, CTR, GCM) and
//! digest pipelines (SHA-256 block compress) live in `crypto::aes`
//! and `crypto::sha2` respectively (not yet committed) — those will
//! dispatch through `Features::probe()`.

extern crate alloc;

/// Hardware-accelerated crypto features detected at boot.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Features {
    /// AES-NI on x86 (CPUID.01:ECX bit 25) or FEAT_AES on aarch64
    /// (`ID_AA64ISAR0_EL1`[7:4] >= 1).
    pub aes: bool,
    /// SHA-NI on x86 (CPUID.07.0:EBX bit 29) or FEAT_SHA256 on
    /// aarch64 (`ID_AA64ISAR0_EL1`[15:12] >= 1).
    pub sha2: bool,
    /// FEAT_SHA1 on aarch64 (`ID_AA64ISAR0_EL1`[11:8] >= 1). Always
    /// `false` on x86 — Intel never shipped a SHA-1 acceleration.
    pub sha1: bool,
    /// PCLMULQDQ on x86 (CPUID.01:ECX bit 1) or FEAT_PMULL on
    /// aarch64 (`ID_AA64ISAR0_EL1`[7:4] >= 2). Used by GHASH.
    pub pmull: bool,
    /// CRC32C on x86 (SSE 4.2, CPUID.01:ECX bit 20) or FEAT_CRC32
    /// on aarch64 (`ID_AA64ISAR0_EL1`[19:16] >= 1).
    pub crc32: bool,
}

impl Features {
    /// Probe the running CPU. Safe to call from any privilege
    /// level — neither CPUID nor `MRS` from `ID_AA64ISAR0_EL1`
    /// require kernel mode (CPUID is always-available; the EL1
    /// system register is readable from EL1 + EL2 + EL3 only,
    /// which is the only place this crate runs).
    #[cfg(target_arch = "x86_64")]
    pub fn probe() -> Self {
        // CPUID leaf 1: ECX bit 25 (AES-NI), bit 1 (PCLMULQDQ),
        // bit 20 (SSE4.2 CRC32).
        let mut f = Self::default();
        // SAFETY: CPUID is unprivileged; the assembly is read-only.
        let (_, _, ecx_1, _) = unsafe { cpuid(1, 0) };
        f.aes = ecx_1 & (1 << 25) != 0;
        f.pmull = ecx_1 & (1 << 1) != 0;
        f.crc32 = ecx_1 & (1 << 20) != 0;
        // CPUID leaf 7 sub-leaf 0: EBX bit 29 (SHA-NI).
        // SAFETY: same.
        let (_, ebx_7, _, _) = unsafe { cpuid(7, 0) };
        f.sha2 = ebx_7 & (1 << 29) != 0;
        f
    }

    #[cfg(target_arch = "aarch64")]
    pub fn probe() -> Self {
        // SAFETY: ID_AA64ISAR0_EL1 is readable from EL1 (ARM ARM
        // §D17.2.71). Architectural register, no side effects.
        // SAFETY: Valid memory or trusted environment
        let isar0 = unsafe { read_id_aa64isar0_el1() };
        Self {
            aes: ((isar0 >> 4) & 0xF) >= 1,
            pmull: ((isar0 >> 4) & 0xF) >= 2,
            sha1: ((isar0 >> 8) & 0xF) >= 1,
            sha2: ((isar0 >> 12) & 0xF) >= 1,
            crc32: ((isar0 >> 16) & 0xF) >= 1,
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn probe() -> Self {
        Self::default()
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    // LLVM reserves rbx for its own use, so we can't bind `ebx`
    // directly; route the result through the architectural-intrinsic
    // wrapper which save / restore rbx around the underlying CPUID.
    // SAFETY: CPUID with caller-validated leaf is well-defined.
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, sub) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

#[cfg(target_arch = "aarch64")]
unsafe fn read_id_aa64isar0_el1() -> u64 {
    let mut v: u64;
    // SAFETY: caller-guaranteed EL1 + register architecturally
    // readable from EL1.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {x}, ID_AA64ISAR0_EL1",
            x = out(reg) v,
            options(nostack, preserves_flags),
        );
    }
    v
}

// ── Per-instruction wrappers ─────────────────────────────────────

/// AES single-round forward. Performs one `AESENC` (x86) or
/// `AESE` + `AESMC` (aarch64) on a 128-bit block under a
/// 128-bit round key. Caller is responsible for the key
/// schedule (the full 10/12/14-round key array is built once at
/// key-set time).
#[cfg(target_arch = "x86_64")]
pub fn aes_round_forward(state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: AESENC operates on aligned XMM regs — both inputs
    // come in as `[u8; 16]` arrays loaded into XMM via MOVDQU.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "movdqu xmm0, [{s}]",
            "movdqu xmm1, [{k}]",
            "aesenc xmm0, xmm1",
            "movdqu [{o}], xmm0",
            s = in(reg) state.as_ptr(),
            k = in(reg) round_key.as_ptr(),
            o = in(reg) out.as_mut_ptr(),
            out("xmm0") _,
            out("xmm1") _,
            options(nostack, preserves_flags),
        );
    }
    out
}

#[cfg(target_arch = "aarch64")]
pub fn aes_round_forward(state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: AESE + AESMC operate on V registers; we load + store
    // via LDR/STR, no alignment concerns on aarch64 NEON. The
    // `.arch_extension aes` directive tells the assembler to accept
    // AES instructions even when the build's base CPU doesn't list
    // `aes` in `--target-cpu`'s feature set; the runtime feature
    // probe (`Features::probe()`) is the actual gate against
    // executing on a CPU that lacks FEAT_AES.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            ".arch_extension aes",
            "ldr q0, [{s}]",
            "ldr q1, [{k}]",
            "aese v0.16b, v1.16b",
            "aesmc v0.16b, v0.16b",
            "str q0, [{o}]",
            s = in(reg) state.as_ptr(),
            k = in(reg) round_key.as_ptr(),
            o = in(reg) out.as_mut_ptr(),
            out("v0") _,
            out("v1") _,
            options(nostack, preserves_flags),
        );
    }
    out
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn aes_round_forward(state: [u8; 16], _round_key: [u8; 16]) -> [u8; 16] {
    // No accelerator on this arch; caller should dispatch via
    // `Features::probe()` and pick the portable software path.
    state
}
