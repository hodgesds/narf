//! AMD CPPC (Collaborative Processor Performance Control) — clean-room.
//!
//! ## Sources (public only)
//!
//! - **AMD64 Architecture Programmer's Manual, Volume 2**, AMD —
//!   §17 ("Power and Thermal Management") + Appendix A (model-
//!   specific register table) for the AMD CPPC MSRs.
//!   <https://www.amd.com/system/files/TechDocs/24593.pdf>
//! - **ACPI Specification 6.5 §8.4.7** — CPPC ACPI methods + the
//!   _CPC capability table. The MSRs here are the AMD-specific
//!   instantiation of the CPPC abstract registers ACPI defines.
//!   <https://uefi.org/specs/ACPI/>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Register layouts + bit-field decoders for the four AMD CPPC
//! MSRs every Zen-2-and-newer core implements. Reading + writing
//! the MSRs is arch-specific (`rdmsr` / `wrmsr` on x86_64 with a
//! cap) and lives in `arch/x86_64::msr` — this module decodes
//! the values.

extern crate alloc;

/// AMD CPPC MSR addresses (AMD64 APM §17 + AMD PPR for Zen 2+).
pub const MSR_AMD_CPPC_CAP1: u32 = 0xC001_0294;
pub const MSR_AMD_CPPC_ENABLE: u32 = 0xC001_0295;
pub const MSR_AMD_CPPC_CAP2: u32 = 0xC001_0296;
pub const MSR_AMD_CPPC_REQ: u32 = 0xC001_0297;
pub const MSR_AMD_CPPC_STATUS: u32 = 0xC001_0298;

/// `MSR_AMD_CPPC_CAP1` decoder (read-only).
///
/// ```text
///   bits[7:0]    Lowest Performance — minimum the cores will
///                 generate at any time.
///   bits[15:8]   Lowest Nonlinear Performance — slowest stable
///                 below which power savings flatten.
///   bits[23:16]  Nominal Performance — guaranteed long-term.
///   bits[31:24]  Highest Performance — peak boost.
///   bits[63:32]  Reserved.
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cap1(pub u64);

impl Cap1 {
    pub fn lowest_perf(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    pub fn lowest_nonlinear_perf(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
    pub fn nominal_perf(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
    pub fn highest_perf(self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }
}

/// `MSR_AMD_CPPC_CAP2` decoder.
///
/// ```text
///   bits[7:0]    Guaranteed Performance — value the FW will
///                 deliver under nominal conditions.
///   bits[39:32]  Energy Performance Preference — 0 = pure perf,
///                 0xFF = pure energy efficiency.
///                 (Some BKDG drafts placed this in CPPC_REQ; the
///                  AMD64 APM canonicalises it here.)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cap2(pub u64);

impl Cap2 {
    pub fn guaranteed_perf(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

/// `MSR_AMD_CPPC_REQ` request register layout.
///
/// ```text
///   bits[7:0]    Min Performance — floor the FW must honour.
///   bits[15:8]   Max Performance — ceiling.
///   bits[23:16]  Desired Performance — non-binding hint;
///                  takes effect when MinPerf == 0 == MaxPerf.
///   bits[31:24]  Energy Performance Preference (0..255).
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Request(pub u64);

impl Request {
    pub fn build(min_perf: u8, max_perf: u8, desired_perf: u8, epp: u8) -> Self {
        Self(
            (min_perf as u64)
                | ((max_perf as u64) << 8)
                | ((desired_perf as u64) << 16)
                | ((epp as u64) << 24),
        )
    }
    pub fn min_perf(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    pub fn max_perf(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
    pub fn desired_perf(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
    pub fn energy_performance_preference(self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }
}

/// `MSR_AMD_CPPC_STATUS` decoder — bits[7:0] hold the currently
/// delivered Performance value (fed back by the FW).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Status(pub u64);

impl Status {
    pub fn delivered_perf(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

/// `MSR_AMD_CPPC_ENABLE` — bit 0 = master enable.
pub const ENABLE_BIT: u64 = 1 << 0;

/// Canonical Energy-Performance-Preference values used by Linux
/// + Windows + ACPI. AMD honours arbitrary 0..=255 values; these
/// are the well-known anchors.
pub mod epp {
    pub const PERFORMANCE: u8 = 0x00;
    pub const BALANCED_PERFORMANCE: u8 = 0x40;
    pub const BALANCED_POWER: u8 = 0x80;
    pub const POWERSAVE: u8 = 0xFF;
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use narf_arch::x86_64::cpuid::cpuid;
    use narf_arch::x86_64::msr::{rdmsr, wrmsr};

    /// AMD APM Vol 2 §17 / PPR: `CPUID(0x8000_0008).EBX[27] = CPPC`.
    /// Set when the core implements the CPPC MSRs at
    /// 0xC001_0294..0xC001_0298. Distinct from the legacy HwPstate
    /// bit (`CPUID(0x8000_0007).EDX[7]`) — Zen2+ parts typically
    /// expose both, in which case we prefer CPPC for finer-grained
    /// EPP control.
    pub fn supported() -> bool {
        // SAFETY: extended-leaf cpuid; bounded by the max-extended check.
        let (max, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
        if max < 0x8000_0008 {
            return false;
        }
        let (_, ebx, _, _) = unsafe { cpuid(0x8000_0008, 0) };
        ebx & (1 << 27) != 0
    }

    /// Read `MSR_AMD_CPPC_CAP1`. Caller must have verified `supported()`.
    ///
    /// # Safety
    /// CPL = 0; CPPC supported on this core.
    pub unsafe fn read_cap1() -> Cap1 {
        // SAFETY: caller-asserted.
        Cap1(unsafe { rdmsr(MSR_AMD_CPPC_CAP1) })
    }

    /// Set the master CPPC enable bit. Sticky — once set the MSR
    /// can't be cleared without a reset.
    ///
    /// # Safety
    /// CPL = 0; CPPC supported on this core.
    pub unsafe fn enable() {
        // SAFETY: caller-asserted.
        unsafe {
            wrmsr(MSR_AMD_CPPC_ENABLE, ENABLE_BIT);
        }
    }

    /// Program `MSR_AMD_CPPC_REQ` from a built `Request`.
    ///
    /// # Safety
    /// CPL = 0; CPPC enabled on this core.
    pub unsafe fn write_request(req: Request) {
        // SAFETY: caller-asserted.
        unsafe {
            wrmsr(MSR_AMD_CPPC_REQ, req.0);
        }
    }

    /// Boot-time bring-up: if CPPC is supported, enable it and
    /// program a "use the full perf range, balanced EPP" request so
    /// the firmware governor is allowed to climb to highest_perf.
    /// Returns `Some(cap1)` when programmed, `None` otherwise.
    ///
    /// # Safety
    /// CPL = 0, boot context.
    pub unsafe fn init() -> Option<Cap1> {
        if !supported() {
            return None;
        }
        // SAFETY: gated by `supported()`.
        unsafe {
            enable();
        }
        // SAFETY: same.
        let caps = unsafe { read_cap1() };
        let req = Request::build(
            caps.lowest_perf(),
            caps.highest_perf(),
            /*desired*/ 0,
            epp::BALANCED_PERFORMANCE,
        );
        // SAFETY: same; ENABLE_BIT was set above.
        unsafe {
            write_request(req);
        }
        Some(caps)
    }
}

#[cfg(target_arch = "x86_64")]
pub use x86::{enable, init, read_cap1, supported, write_request};
