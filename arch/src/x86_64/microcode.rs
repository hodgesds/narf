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
//! Linux references (GPL-2.0-or-later, adapted directly):
//!   - `arch/x86/kernel/cpu/microcode/intel.c`
//!   - `arch/x86/kernel/cpu/microcode/amd.c`
//!   - `arch/x86/include/asm/microcode_amd.h`
//!   - `arch/x86/kernel/cpu/microcode/core.c`

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};

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
    /// Blob slice is too short to hold the expected header.
    TooShort,
    /// Header validation failed (bad magic, version, or impossible
    /// size). Distinct from `SignatureMismatch` — this is malformed
    /// data, not the wrong CPU.
    BadHeader,
    /// Header decoded cleanly but its `processor_signature` doesn't
    /// match the running CPU's CPUID(1).EAX. Wrong blob for this
    /// silicon.
    SignatureMismatch,
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

/// CPUID(1).EAX `processor_signature` of the running CPU. The same
/// 32-bit value Intel ships in the microcode header
/// (`processor_signature` field) so a direct equality check tells
/// us whether a blob is for our silicon.
#[inline]
pub fn cpu_signature() -> u32 {
    // SAFETY: leaf 1 always defined on x86_64.
    let (eax, _, _, _) = unsafe { cpuid(1, 0) };
    eax
}

/// Decoded family/model/stepping for the running CPU. Computed
/// per Intel SDM §3.3.5 (`ext_family` is added to `base_family`
/// only when `base_family == 0xF`; on AMD `base_family == 0xF`
/// triggers `ext_family` for every family above 0x0F too).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FamilyModelStepping {
    pub family: u16,
    pub model: u16,
    pub stepping: u8,
    /// Raw CPUID(1).EAX as encoded by the silicon.
    pub raw: u32,
}

impl FamilyModelStepping {
    /// Decode a raw CPUID(1).EAX value.
    pub fn from_raw(sig: u32) -> Self {
        let stepping = (sig & 0xF) as u8;
        let base_model = ((sig >> 4) & 0xF) as u16;
        let base_family = ((sig >> 8) & 0xF) as u16;
        let ext_model = ((sig >> 16) & 0xF) as u16;
        let ext_family = ((sig >> 20) & 0xFF) as u16;
        let family = base_family + if base_family == 0xF { ext_family } else { 0 };
        let model = if base_family >= 0x6 || base_family == 0xF {
            base_model | (ext_model << 4)
        } else {
            base_model
        };
        Self {
            family,
            model,
            stepping,
            raw: sig,
        }
    }

    /// Decode the running CPU's family/model/stepping.
    pub fn current() -> Self {
        Self::from_raw(cpu_signature())
    }

    /// Intel canonical blob filename — `"06-A7-01"` style. Matches
    /// what Intel's `iucode_tool` and Linux's `intel-ucode/`
    /// directory naming uses.
    ///
    /// 8 ASCII bytes: 2 hex family, '-', 2 hex model, '-', 2 hex
    /// stepping. Returns just the leaf name (no directory prefix);
    /// callers prefix with `"intel-ucode/"`.
    pub fn intel_filename(&self) -> [u8; 8] {
        let mut out = [b'0'; 8];
        fn hex(n: u16) -> [u8; 2] {
            let hi = ((n >> 4) & 0xF) as u8;
            let lo = (n & 0xF) as u8;
            fn d(n: u8) -> u8 {
                if n < 10 {
                    b'0' + n
                } else {
                    b'A' + (n - 10)
                }
            }
            [d(hi), d(lo)]
        }
        let f = hex(self.family);
        let m = hex(self.model);
        let s = hex(self.stepping as u16);
        out[0] = f[0];
        out[1] = f[1];
        out[2] = b'-';
        out[3] = m[0];
        out[4] = m[1];
        out[5] = b'-';
        out[6] = s[0];
        out[7] = s[1];
        out
    }

    /// AMD canonical container filename — `"microcode_amd_fam17h.bin"`
    /// (Zen/Zen2) or `"microcode_amd_fam19h.bin"` (Zen3/Zen4) etc.
    /// Returns the family-tag (e.g. `b"17h"`) so callers can
    /// assemble the full name; family-tag is two hex digits + 'h'.
    pub fn amd_family_tag(&self) -> [u8; 3] {
        let hi = ((self.family >> 4) & 0xF) as u8;
        let lo = (self.family & 0xF) as u8;
        fn d(n: u8) -> u8 {
            if n < 10 {
                b'0' + n
            } else {
                b'a' + (n - 10)
            }
        }
        [d(hi), d(lo), b'h']
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
        return Err(UcodeError::TooShort);
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
    set_applied_revision(after);
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
        return Err(UcodeError::TooShort);
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
    set_applied_revision(after);
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

/// Intel ucode header is exactly 48 bytes.
pub const INTEL_HEADER_LEN: usize = 48;
/// When `data_size == 0`, Intel defines the body length as 2000
/// bytes (legacy short blobs). Per SDM Vol 3 §9.11.1.
pub const INTEL_DEFAULT_DATA_SIZE: u32 = 2000;
/// Intel's microcode header version is always 1.
pub const INTEL_HEADER_VERSION: u32 = 1;
/// Intel's loader revision is always 1.
pub const INTEL_LOADER_REVISION: u32 = 1;

impl IntelUcodeHeader {
    /// Decode the 48-byte header. Returns `None` only on slice too
    /// short — content validation lives in `validate()`.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < INTEL_HEADER_LEN {
            return None;
        }
        let r32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        Some(Self {
            header_version: r32(0),
            update_revision: r32(4),
            date: r32(8),
            processor_signature: r32(12),
            checksum: r32(16),
            loader_revision: r32(20),
            processor_flags: r32(24),
            data_size: r32(28),
            total_size: r32(32),
        })
    }

    /// Effective payload length (Intel SDM §9.11.1: `total_size == 0`
    /// means the legacy 2048-byte (48 + 2000) layout).
    pub fn effective_total_size(&self) -> u32 {
        if self.total_size == 0 {
            INTEL_HEADER_LEN as u32 + INTEL_DEFAULT_DATA_SIZE
        } else {
            self.total_size
        }
    }

    /// Effective `data_size` (body bytes only — excludes the 48-byte
    /// header). `data_size == 0` means the legacy 2000-byte body.
    pub fn effective_data_size(&self) -> u32 {
        if self.data_size == 0 {
            INTEL_DEFAULT_DATA_SIZE
        } else {
            self.data_size
        }
    }

    /// Full header + body validation. Reject blobs whose
    /// `header_version`, `loader_revision`, declared `total_size`,
    /// `data_size`, or checksum are inconsistent with the slice
    /// they live in. Linux: `microcode_sanity_check` in
    /// `arch/x86/kernel/cpu/microcode/intel.c`.
    pub fn validate(&self, blob: &[u8]) -> Result<(), UcodeError> {
        if blob.len() < INTEL_HEADER_LEN {
            return Err(UcodeError::TooShort);
        }
        if self.header_version != INTEL_HEADER_VERSION {
            return Err(UcodeError::BadHeader);
        }
        if self.loader_revision != INTEL_LOADER_REVISION {
            return Err(UcodeError::BadHeader);
        }
        let total = self.effective_total_size() as usize;
        let data = self.effective_data_size() as usize;
        // `total_size` must be a multiple of 4 (Intel pads to dword).
        if total & 3 != 0 || data & 3 != 0 {
            return Err(UcodeError::BadHeader);
        }
        // `total_size` covers header + data; data must fit.
        if data + INTEL_HEADER_LEN > total {
            return Err(UcodeError::BadHeader);
        }
        // The slice must contain the full declared blob (header +
        // optional extended signature table). Some Intel blobs
        // carry an extended-signature table after the data section;
        // the loader still validates `total_size` against the slice.
        if blob.len() < total {
            return Err(UcodeError::TooShort);
        }
        // Sum-to-zero checksum over the entire declared blob,
        // treated as `u32`s. Intel SDM §9.11.1: "the sum of all
        // dwords (including the checksum field) over the data of
        // the update must equal zero".
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 4 <= total {
            let dw = u32::from_le_bytes([blob[i], blob[i + 1], blob[i + 2], blob[i + 3]]);
            sum = sum.wrapping_add(dw);
            i += 4;
        }
        if sum != 0 {
            return Err(UcodeError::BadHeader);
        }
        Ok(())
    }

    /// `true` if this header's `processor_signature` matches the
    /// given CPUID(1).EAX. Intel also gates per `processor_flags`
    /// (a bitmask the CPU advertises in MSR 0x17 platform-id); for
    /// our use case (one blob per CPU-id directory) the signature
    /// match alone is sufficient — Intel ships disambiguated blobs.
    pub fn matches_signature(&self, sig: u32) -> bool {
        self.processor_signature == sig
    }
}

/// AMD microcode container header. Linux source:
/// `arch/x86/kernel/cpu/microcode/amd.c::__find_equiv_id` +
/// `struct microcode_amd` in `arch/x86/include/asm/microcode_amd.h`.
///
/// On-disk layout for `microcode_amd_famXXh.bin`:
///
/// ```text
/// magic              u32   (0x00414D44, "AMD\0" / "DMA")
/// equiv_table_type   u32   (must be 0x00000001 — "equiv table")
/// equiv_table_len    u32   (bytes; covers the equiv-CPU array
///                          following this 12-byte container header)
/// equiv_cpu_table    [EquivEntry; equiv_table_len/8]
/// (then a sequence of per-patch sections, each prefixed by a
///  patch-section header described in `AmdPatchHeader`).
/// ```
pub const AMD_CONTAINER_MAGIC: u32 = 0x0041_4D44;
/// `equiv_table_type` in the container header — always 1.
pub const AMD_EQUIV_TYPE: u32 = 0x0000_0001;
/// Per-patch section type — Linux's `UCODE_UCODE_TYPE`.
pub const AMD_PATCH_SECTION_TYPE: u32 = 0x0000_0001;
/// AMD patch-section magic. Linux's
/// `arch/x86/kernel/cpu/microcode/amd.c` calls this `SECTION_HDR_SIZE`
/// = 8 (section_type u32 + section_size u32 prefix). The patch body
/// itself starts immediately after.
pub const AMD_PATCH_SECTION_HDR_LEN: usize = 8;

#[derive(Copy, Clone, Debug)]
pub struct AmdContainerHeader {
    pub magic: u32,
    pub equiv_table_type: u32,
    pub equiv_table_len: u32,
}

impl AmdContainerHeader {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let r32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        Some(Self {
            magic: r32(0),
            equiv_table_type: r32(4),
            equiv_table_len: r32(8),
        })
    }

    pub fn validate(&self) -> Result<(), UcodeError> {
        if self.magic != AMD_CONTAINER_MAGIC {
            return Err(UcodeError::BadHeader);
        }
        if self.equiv_table_type != AMD_EQUIV_TYPE {
            return Err(UcodeError::BadHeader);
        }
        // equiv_table_len must be a multiple of an EquivCpuEntry (16 bytes).
        if self.equiv_table_len as usize % 16 != 0 {
            return Err(UcodeError::BadHeader);
        }
        Ok(())
    }
}

/// One entry in the AMD equiv-CPU table. The table maps the
/// `installed_cpu` CPUID signature to an `equiv_cpu` 16-bit code
/// that subsequent patch-section headers reference.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AmdEquivCpu {
    pub installed_cpu: u32,
    pub fixed_errata_mask: u32,
    pub fixed_errata_compare: u32,
    pub equiv_cpu: u16,
    pub _reserved: u16,
}

impl AmdEquivCpu {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let r32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let r16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
        Some(Self {
            installed_cpu: r32(0),
            fixed_errata_mask: r32(4),
            fixed_errata_compare: r32(8),
            equiv_cpu: r16(12),
            _reserved: r16(14),
        })
    }
}

/// Per-patch AMD header. Linux: `struct microcode_amd` in
/// `arch/x86/include/asm/microcode_amd.h`. Reproduced here as a
/// flat decoder — the fields we care about for selecting and
/// applying a patch.
#[derive(Copy, Clone, Debug)]
pub struct AmdPatchHeader {
    pub data_code: u32,
    pub patch_id: u32,
    pub mc_patch_data_id: u16,
    pub mc_patch_data_len: u8,
    pub init_flag: u8,
    pub mc_patch_data_checksum: u32,
    pub nb_dev_id: u32,
    pub sb_dev_id: u32,
    pub processor_rev_id: u16,
    pub nb_rev_id: u8,
    pub sb_rev_id: u8,
    pub bios_api_rev: u8,
    pub reserved1: [u8; 3],
    pub match_reg: [u32; 8],
}

/// AMD per-patch header is exactly 64 bytes (Linux's `struct
/// microcode_amd` minus the variable-length `bin_data` field).
pub const AMD_PATCH_HDR_LEN: usize = 64;

impl AmdPatchHeader {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < AMD_PATCH_HDR_LEN {
            return None;
        }
        let r32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let r16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
        let mut match_reg = [0u32; 8];
        for (i, v) in match_reg.iter_mut().enumerate() {
            *v = r32(32 + i * 4);
        }
        Some(Self {
            data_code: r32(0),
            patch_id: r32(4),
            mc_patch_data_id: r16(8),
            mc_patch_data_len: buf[10],
            init_flag: buf[11],
            mc_patch_data_checksum: r32(12),
            nb_dev_id: r32(16),
            sb_dev_id: r32(20),
            processor_rev_id: r16(24),
            nb_rev_id: buf[26],
            sb_rev_id: buf[27],
            bios_api_rev: buf[28],
            reserved1: [buf[29], buf[30], buf[31]],
            match_reg,
        })
    }

    /// `true` if this patch's `processor_rev_id` matches the
    /// equiv-CPU code resolved from the container's equiv table.
    pub fn matches_equiv(&self, equiv: u16) -> bool {
        self.processor_rev_id == equiv
    }
}

/// Walk an AMD container blob's equiv-CPU table looking for the
/// running CPU's `cpuid(1).EAX`. Returns the `equiv_cpu` code on
/// match; subsequent patch sections reference this code in their
/// `processor_rev_id` field.
///
/// The walk stops at the first match — AMD's table is ordered with
/// the most specific entries first.
pub fn amd_find_equiv(blob: &[u8], cpuid_eax: u32) -> Option<u16> {
    let hdr = AmdContainerHeader::decode(blob)?;
    hdr.validate().ok()?;
    let table_end = 12 + hdr.equiv_table_len as usize;
    if blob.len() < table_end {
        return None;
    }
    let mut off = 12;
    while off + 16 <= table_end {
        let e = AmdEquivCpu::decode(&blob[off..off + 16])?;
        // Sentinel: an all-zero entry terminates the table early.
        if e.installed_cpu == 0 && e.equiv_cpu == 0 {
            return None;
        }
        if e.installed_cpu == cpuid_eax {
            return Some(e.equiv_cpu);
        }
        off += 16;
    }
    None
}

/// Walk an AMD container blob's patch sections looking for the
/// patch whose `processor_rev_id` matches `equiv`. Returns the
/// patch's body slice (header + body — what
/// `MSR_AMD_PATCH_LOADER` wants the linear address of).
///
/// Each patch section is laid out as:
///   `section_type: u32`  (must be `AMD_PATCH_SECTION_TYPE = 1`)
///   `section_size: u32`  (bytes following this 8-byte prefix)
///   `<patch header + body>: [u8; section_size]`
pub fn amd_find_patch(blob: &[u8], equiv: u16) -> Option<&[u8]> {
    let hdr = AmdContainerHeader::decode(blob)?;
    hdr.validate().ok()?;
    let mut off = 12 + hdr.equiv_table_len as usize;
    while off + AMD_PATCH_SECTION_HDR_LEN <= blob.len() {
        let section_type = u32::from_le_bytes([
            blob[off],
            blob[off + 1],
            blob[off + 2],
            blob[off + 3],
        ]);
        let section_size = u32::from_le_bytes([
            blob[off + 4],
            blob[off + 5],
            blob[off + 6],
            blob[off + 7],
        ]) as usize;
        if section_type != AMD_PATCH_SECTION_TYPE {
            // Unknown section type — bail rather than guess at
            // length; the container is malformed or a newer rev.
            return None;
        }
        let body_off = off + AMD_PATCH_SECTION_HDR_LEN;
        if body_off + section_size > blob.len() {
            return None;
        }
        let body = &blob[body_off..body_off + section_size];
        let ph = AmdPatchHeader::decode(body)?;
        if ph.matches_equiv(equiv) {
            return Some(body);
        }
        off = body_off + section_size;
    }
    None
}

/// Latest revision applied by this loader on the running CPU. The
/// errata module reads this so workaround dispatch can suppress
/// MSR fiddling on a CPU whose silicon bug is already fixed by
/// the microcode patch. `0` means "no microcode load happened
/// through this loader yet" — the firmware-supplied revision is
/// still active.
static APPLIED_REVISION: AtomicU32 = AtomicU32::new(0);

#[inline]
fn set_applied_revision(rev: u32) {
    APPLIED_REVISION.store(rev, Ordering::Release);
}

/// Most recent revision reported by `apply_intel`/`apply_amd`.
/// Used by `arch::errata` to gate workarounds against the patch
/// level. Returns 0 if no patch has been applied through this
/// loader on the running CPU.
#[inline]
pub fn applied_revision() -> u32 {
    APPLIED_REVISION.load(Ordering::Acquire)
}

#[doc(hidden)]
pub fn __reset_applied_revision_for_test() {
    APPLIED_REVISION.store(0, Ordering::Release);
}

/// Derive the canonical firmware-registry name for the running
/// CPU's microcode container.
///
/// - Intel:  `"intel-ucode/06-A6-01"`-style. 8-byte FMS triple
///   under the `intel-ucode/` directory the registry mirrors from
///   Linux's `linux-firmware` package.
/// - AMD:    `"amd-ucode/microcode_amd_fam17h.bin"`-style. Family-
///   wide container; the equiv-table walker picks the right patch
///   inside it.
///
/// Output is written into the caller-supplied byte buffer (kept
/// stack-allocated to avoid pulling `alloc` into this module);
/// returns the length actually written, or `None` if the buffer
/// is too small or the vendor isn't supported.
///
/// Buffer must hold at least 40 bytes — the longest name we emit
/// (`"amd-ucode/microcode_amd_famFFh.bin"` = 34 bytes; 40 leaves
/// slack for future family widths).
pub fn blob_filename_for_current_cpu(out: &mut [u8]) -> Option<usize> {
    let fms = FamilyModelStepping::current();
    match vendor() {
        Vendor::Intel => {
            const PREFIX: &[u8] = b"intel-ucode/";
            let name = fms.intel_filename();
            let total = PREFIX.len() + name.len();
            if out.len() < total {
                return None;
            }
            out[..PREFIX.len()].copy_from_slice(PREFIX);
            out[PREFIX.len()..total].copy_from_slice(&name);
            Some(total)
        }
        Vendor::Amd => {
            const PREFIX: &[u8] = b"amd-ucode/microcode_amd_fam";
            const SUFFIX: &[u8] = b".bin";
            let tag = fms.amd_family_tag();
            let total = PREFIX.len() + tag.len() + SUFFIX.len();
            if out.len() < total {
                return None;
            }
            out[..PREFIX.len()].copy_from_slice(PREFIX);
            out[PREFIX.len()..PREFIX.len() + tag.len()].copy_from_slice(&tag);
            out[PREFIX.len() + tag.len()..total].copy_from_slice(SUFFIX);
            Some(total)
        }
        Vendor::Unknown => None,
    }
}

/// Resolve the on-disk blob bytes to the per-CPU patch this
/// silicon needs.
///
/// For Intel the input is the FMS-specific blob already
/// (per-signature file in `intel-ucode/`); the function only
/// validates the header + checksum.
///
/// For AMD the input is the family-wide container; the function
/// walks the equiv-table for our CPUID, finds the matching patch
/// section, and returns the per-patch slice.
///
/// Returns `Err(SignatureMismatch)` when the blob exists but
/// doesn't carry a patch for our silicon, `Err(BadHeader)` when
/// the bytes are malformed.
pub fn resolve_for_current_cpu(blob: &[u8]) -> Result<&[u8], UcodeError> {
    match vendor() {
        Vendor::Intel => {
            let hdr = IntelUcodeHeader::decode(blob).ok_or(UcodeError::TooShort)?;
            hdr.validate(blob)?;
            if !hdr.matches_signature(cpu_signature()) {
                return Err(UcodeError::SignatureMismatch);
            }
            let total = hdr.effective_total_size() as usize;
            Ok(&blob[..total])
        }
        Vendor::Amd => {
            let sig = cpu_signature();
            let equiv = amd_find_equiv(blob, sig).ok_or(UcodeError::SignatureMismatch)?;
            amd_find_patch(blob, equiv).ok_or(UcodeError::SignatureMismatch)
        }
        Vendor::Unknown => Err(UcodeError::UnknownVendor),
    }
}

/// Boot-time + per-AP entry point.
///
/// Resolves the right per-CPU patch out of the caller-supplied
/// container blob, applies it via the vendor-specific MSR, and
/// confirms the revision moved. The caller (boot path on the BSP;
/// AP startup stub on every AP) has already fetched the container
/// from the firmware registry.
///
/// Returns the post-apply revision on success. Failure cases:
/// - `Err(UnknownVendor)`     — non-Intel/AMD silicon
/// - `Err(SignatureMismatch)` — blob doesn't cover this CPU
/// - `Err(BadHeader)`         — malformed bytes
/// - `Err(LoaderLocked)`      — BIOS locked the loader MSR
/// - `Err(NoRevisionChange)`  — patch applied but rev didn't
///   advance (blob was already the current rev, or wrong subspec)
///
/// # Safety
/// CPL = 0 and the running CPU is the one the patch should target
/// (the caller is the BSP for the BSP-side call and the AP itself
/// for the per-AP call — never one CPU applying on another's
/// behalf, since the patch loader is per-core).
pub unsafe fn apply_for_current_cpu(container: &[u8]) -> Result<u32, UcodeError> {
    let patch = resolve_for_current_cpu(container)?;
    // SAFETY: caller-asserted CPL=0; `resolve_for_current_cpu`
    // confirmed the patch matches our silicon.
    unsafe { apply(patch) }
}
