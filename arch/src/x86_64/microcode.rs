//! CPU microcode loading.
//!
//! Two register interfaces, vendor-specific:
//!
//! - **Intel** (SDM Vol 3 §9.11): write the linear address of a
//!   48-byte-header microcode update to MSR `0x79` (`IA32_BIOS_UPDT_TRIG`).
//!   The CPU validates the header (header_version must be 1) and
//!   applies the update. Read MSR `0x8B` (`IA32_BIOS_SIGN_ID`) before
//!   + after to confirm the revision changed. The pre-write
//!   handshake is: WRMSR `0x8B = 0`, CPUID, RDMSR `0x8B` to obtain
//!   the current revision.
//! - **AMD** (BKDG): write the linear address of the patch blob to
//!   MSR `0xC0010020` (`AMD_PATCH_LOADER`). Read patch level via
//!   MSR `0x8B` (same MSR as Intel — AMD reuses it).
//!
//! Caller supplies the blob bytes; the kernel passes the linear
//! address straight to the CPU. Blobs are typically pulled from
//! `narf-firmware` (kernel firmware-blob registry) at boot.
//!
//! Stage cut: simple "load this blob" surface + a revision-check
//! helper. Selecting the right blob from a multi-CPU bundle
//! (Intel ships per-signature updates) is the caller's job.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

/// MSR carrying the BIOS signature / patch revision.
pub const MSR_BIOS_SIGN_ID: u32 = 0x8B;
/// Intel BIOS update trigger MSR — write linear address of header.
pub const MSR_INTEL_BIOS_UPDT_TRIG: u32 = 0x79;
/// AMD patch loader MSR — write linear address of patch blob.
pub const MSR_AMD_PATCH_LOADER: u32 = 0xC001_0020;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    Unknown,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UcodeError {
    UnknownVendor,
    /// Update was applied but the CPU didn't bump the revision —
    /// blob was likely already current (or didn't match this CPU).
    NoRevisionChange,
    /// The patch-loader MSR write raised `#GP`. Most common cause:
    /// the BIOS locked microcode updates (CPU is treated as
    /// already-up-to-date by firmware). Caller continues at the
    /// firmware-supplied revision.
    LoaderLocked,
}

/// Detect CPU vendor via CPUID leaf 0.
pub fn vendor() -> Vendor {
    // SAFETY: leaf 0 is always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    let id: [u32; 3] = [ebx, edx, ecx];
    // Reinterpret as 12 ASCII bytes.
    let mut s = [0u8; 12];
    for (i, w) in id.iter().enumerate() {
        s[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    match &s {
        b"GenuineIntel" => Vendor::Intel,
        b"AuthenticAMD" => Vendor::Amd,
        _ => Vendor::Unknown,
    }
}

/// Read the current microcode revision (MSR 0x8B).
///
/// On Intel the protocol requires a CPUID handshake first to
/// flush any cached value: `WRMSR 0x8B = 0; CPUID; RDMSR 0x8B`
/// yields the current revision in EDX (high 32 bits of the MSR).
///
/// # Safety
/// CPL = 0; the MSR is architecturally defined on every supported
/// x86_64 part.
pub unsafe fn read_revision() -> u32 {
    // Handshake: write 0 then issue CPUID(1).
    // SAFETY: caller-asserted CPL=0; MSR architecturally defined.
    unsafe {
        wrmsr(MSR_BIOS_SIGN_ID, 0);
    }
    // SAFETY: leaf 1 is always defined.
    let _ = unsafe { cpuid(1, 0) };
    // SAFETY: same.
    let v = unsafe { rdmsr(MSR_BIOS_SIGN_ID) };
    (v >> 32) as u32
}

/// Apply an Intel microcode update.
///
/// `blob` must point at the start of an Intel microcode header
/// (48 bytes, `header_version == 1`) followed by the update body.
/// Caller-supplied blob lifetime extends through the WRMSR.
///
/// Returns `Ok(new_rev)` if the patch revision moved, otherwise
/// `Err(NoRevisionChange)`.
///
/// # Safety
/// CPL = 0. The blob must be the right format (`header_version =
/// 1`). Wrong blobs corrupt the CPU's state — only ever feed
/// vendor-signed bundles from `narf-firmware`.
pub unsafe fn apply_intel(blob: &[u8]) -> Result<u32, UcodeError> {
    use crate::x86_64::msr::wrmsr_or_gp;
    if blob.len() < 48 {
        return Err(UcodeError::NoRevisionChange);
    }
    // SAFETY: caller-asserted.
    let _before = unsafe { read_revision() };
    let addr = blob.as_ptr() as u64;
    // BIOS-locked microcode updates surface as `#GP` on the trigger
    // MSR write rather than a quiet no-op. Surface that distinctly
    // so the caller can keep going at the firmware revision.
    if wrmsr_or_gp(MSR_INTEL_BIOS_UPDT_TRIG, addr).is_err() {
        return Err(UcodeError::LoaderLocked);
    }
    // SAFETY: same.
    let after = unsafe { read_revision() };
    if after == _before {
        return Err(UcodeError::NoRevisionChange);
    }
    Ok(after)
}

/// Apply an AMD microcode patch.
///
/// `blob` must point at an AMD container blob (the per-CPU
/// section, not the multi-CPU container). MSR 0xC0010020 takes
/// the linear address.
///
/// # Safety
/// Same as `apply_intel`; AMD blobs only.
pub unsafe fn apply_amd(blob: &[u8]) -> Result<u32, UcodeError> {
    use crate::x86_64::msr::wrmsr_or_gp;
    if blob.is_empty() {
        return Err(UcodeError::NoRevisionChange);
    }
    // SAFETY: caller-asserted.
    let before = unsafe { read_revision() };
    let addr = blob.as_ptr() as u64;
    if wrmsr_or_gp(MSR_AMD_PATCH_LOADER, addr).is_err() {
        return Err(UcodeError::LoaderLocked);
    }
    // SAFETY: same.
    let after = unsafe { read_revision() };
    if after == before {
        return Err(UcodeError::NoRevisionChange);
    }
    Ok(after)
}

/// Vendor-aware apply: dispatches to the right MSR.
///
/// # Safety
/// CPL=0 + caller-asserted blob format matches the running CPU's
/// vendor.
pub unsafe fn apply(blob: &[u8]) -> Result<u32, UcodeError> {
    // SAFETY: caller-asserted.
    match vendor() {
        Vendor::Intel => unsafe { apply_intel(blob) },
        Vendor::Amd => unsafe { apply_amd(blob) },
        Vendor::Unknown => Err(UcodeError::UnknownVendor),
    }
}

/// Intel ucode header decoder (§9.11.1, Table 9-7). All fields
/// little-endian.
#[derive(Copy, Clone, Debug)]
pub struct IntelUcodeHeader {
    pub header_version: u32,
    pub update_revision: u32,
    pub date: u32,
    pub processor_signature: u32,
    pub checksum: u32,
    pub loader_revision: u32,
    pub processor_flags: u32,
    pub data_size: u32,
    pub total_size: u32,
}

impl IntelUcodeHeader {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 48 {
            return None;
        }
        let r32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let h = Self {
            header_version: r32(0),
            update_revision: r32(4),
            date: r32(8),
            processor_signature: r32(12),
            checksum: r32(16),
            loader_revision: r32(20),
            processor_flags: r32(24),
            data_size: r32(28),
            total_size: r32(32),
        };
        if h.header_version != 1 {
            return None;
        }
        Some(h)
    }
}
