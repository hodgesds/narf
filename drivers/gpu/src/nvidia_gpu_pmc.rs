//! NVIDIA PMC (Master Control) register-block codec — clean-room.
//!
//! Reference: **`open-gpu-doc/manuals/turing/tu102/dev_pmc.ref.txt`**
//! and the equivalent files for Ampere (`ga102`) and Ada (`ad102`).
//! All three carry an identical `NV_PMC_BOOT_0` layout — the
//! register has been stable since Fermi, only the architecture
//! tag in bits[28:20] changes per generation.
//!
//! License note: open-gpu-doc is MIT-licensed top-to-bottom; the
//! register listings consumed here are safe for clean-room use.
//! **No GPL Linux `nouveau` source consulted.**
//!
//! ## NV_PMC_BOOT_0
//!
//! BAR0 offset `0x000000`. The universal NVIDIA chip-id register;
//! reading it is the canonical "is there an NVIDIA GPU here"
//! presence test. Layout (`dev_pmc.ref.txt` §"NV_PMC_BOOT_0"):
//!
//! ```text
//!   bits  3:0   minor revision
//!   bits  7:4   major revision
//!   bits 19: 8  implementation (chip variant within an arch)
//!   bits 28:20  architecture
//!   bit  31     [reserved, reads 0 on documented parts]
//! ```
//!
//! ## NV_PMC_ENABLE
//!
//! BAR0 offset `0x000200`. Per-engine reset/enable bits. The host
//! driver clears the bit to put an engine in reset, sets it to
//! release. The bit assignments are arch-stable on the relevant
//! engines (PFIFO, PGRAPH, PMSPDEC, PMSENC, PSEC, PCE, PDISP).
//!
//! ## NV_PMC_INTR_*
//!
//! BAR0 offsets `0x000100..0x000110`. Top-level interrupt status /
//! mask. Stage-2 ships the offsets and the documented top-level
//! engine bits; per-engine interrupt sub-trees live in their own
//! register blocks.

// ── Register offsets ─────────────────────────────────────────────

/// `NV_PMC_BOOT_0` — chip identifier. Read-only.
pub const NV_PMC_BOOT_0: u64 = 0x0000_0000;

/// `NV_PMC_INTR_0` — top-level interrupt status, host group.
pub const NV_PMC_INTR_0: u64 = 0x0000_0100;
/// `NV_PMC_INTR_EN_0` — interrupt enable, host group.
pub const NV_PMC_INTR_EN_0: u64 = 0x0000_0140;
/// `NV_PMC_INTR_1` — interrupt status, secondary group.
pub const NV_PMC_INTR_1: u64 = 0x0000_0104;
/// `NV_PMC_INTR_EN_1` — interrupt enable, secondary group.
pub const NV_PMC_INTR_EN_1: u64 = 0x0000_0144;

/// `NV_PMC_ENABLE` — per-engine reset/enable.
pub const NV_PMC_ENABLE: u64 = 0x0000_0200;

// ── NV_PMC_BOOT_0 field accessors ────────────────────────────────

/// Architecture id encoded in `NV_PMC_BOOT_0[28:20]`. Values are
/// the documented arch tags from `dev_pmc.ref.txt`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Architecture {
    /// Turing (TU10x). Tag `0x160`.
    Turing,
    /// Ampere (GA10x). Tag `0x170`.
    Ampere,
    /// Ada Lovelace (AD10x). Tag `0x190`.
    Ada,
    /// Hopper (GH10x). Tag `0x180`.
    Hopper,
    /// Architecture tag the driver doesn't recognise. Carries the
    /// raw 9-bit value so a future maintainer can extend the
    /// classifier without losing data.
    Unknown(u16),
}

impl Architecture {
    /// Numeric arch tag the silicon reports.
    pub const fn tag(self) -> u16 {
        match self {
            Architecture::Turing => 0x160,
            Architecture::Ampere => 0x170,
            Architecture::Hopper => 0x180,
            Architecture::Ada => 0x190,
            Architecture::Unknown(t) => t,
        }
    }
}

/// Decoded `NV_PMC_BOOT_0`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Boot0 {
    pub architecture: Architecture,
    /// Implementation (chip variant within an architecture). For
    /// Turing TU102 = 0x002, TU104 = 0x004, etc.
    pub implementation: u16,
    pub major_rev: u8,
    pub minor_rev: u8,
}

impl Boot0 {
    pub fn decode(raw: u32) -> Self {
        let minor = (raw & 0xF) as u8;
        let major = ((raw >> 4) & 0xF) as u8;
        let imp = ((raw >> 8) & 0xFFF) as u16;
        let arch_tag = ((raw >> 20) & 0x1FF) as u16;
        let architecture = match arch_tag {
            0x160 => Architecture::Turing,
            0x170 => Architecture::Ampere,
            0x180 => Architecture::Hopper,
            0x190 => Architecture::Ada,
            t => Architecture::Unknown(t),
        };
        Self {
            architecture,
            implementation: imp,
            major_rev: major,
            minor_rev: minor,
        }
    }

    /// `true` iff the register read indicates the device is
    /// present and responsive (raw value isn't `0xFFFFFFFF` from a
    /// PCI master abort, and the architecture tag is non-zero).
    pub fn looks_present(raw: u32) -> bool {
        raw != 0xFFFF_FFFF && raw != 0 && (raw >> 20) & 0x1FF != 0
    }
}

// ── NV_PMC_ENABLE engine bits ────────────────────────────────────
//
// Source: `dev_pmc.ref.txt` §"NV_PMC_ENABLE". Bit positions are
// arch-stable on Turing+; Stage-2 ships the engines a display-
// path driver needs.

/// Host FIFO engine enable.
pub const NV_PMC_ENABLE_PFIFO: u32 = 1 << 8;
/// Graphics engine enable.
pub const NV_PMC_ENABLE_PGRAPH: u32 = 1 << 12;
/// Display engine enable.
pub const NV_PMC_ENABLE_PDISP: u32 = 1 << 30;
/// Copy engine 0 enable. (Per-CE bits are at +1 each.)
pub const NV_PMC_ENABLE_CE0: u32 = 1 << 18;
/// SEC2 engine enable.
pub const NV_PMC_ENABLE_PSEC: u32 = 1 << 14;

// ── NV_PMC_INTR_0 top-level engine bits ──────────────────────────

/// Display interrupt routed in the top-level INTR_0.
pub const NV_PMC_INTR_PDISP: u32 = 1 << 26;
/// PFIFO interrupt.
pub const NV_PMC_INTR_PFIFO: u32 = 1 << 8;
/// PGRAPH interrupt.
pub const NV_PMC_INTR_PGRAPH: u32 = 1 << 12;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_boot0_decodes_turing_tu102() -> TestResult {
        // Synthesise a TU102 BOOT_0: arch=Turing(0x160), impl=0x002,
        // major=0xA, minor=0x1 → 0x162_002A1 (laid out per spec).
        let raw: u32 = (0x160 << 20) | (0x002 << 8) | (0xA << 4) | 0x1;
        let b = Boot0::decode(raw);
        if b.architecture != Architecture::Turing {
            return TestResult::Fail("Turing tag not classified");
        }
        if b.implementation != 0x002 {
            return TestResult::Fail("implementation lost in decode");
        }
        if b.major_rev != 0xA || b.minor_rev != 0x1 {
            return TestResult::Fail("revision lost in decode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_pmc",
        smoke_boot0_decodes_turing_tu102
    );

    fn smoke_boot0_decodes_ampere() -> TestResult {
        let raw: u32 = 0x170 << 20;
        if Boot0::decode(raw).architecture != Architecture::Ampere {
            return TestResult::Fail("Ampere tag not classified");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_pmc", smoke_boot0_decodes_ampere);

    fn smoke_boot0_decodes_ada() -> TestResult {
        let raw: u32 = 0x190 << 20;
        if Boot0::decode(raw).architecture != Architecture::Ada {
            return TestResult::Fail("Ada tag not classified");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_pmc", smoke_boot0_decodes_ada);

    fn smoke_boot0_unknown_arch_preserves_raw() -> TestResult {
        let raw: u32 = 0x123 << 20;
        match Boot0::decode(raw).architecture {
            Architecture::Unknown(0x123) => TestResult::Pass,
            _ => TestResult::Fail("unknown arch must preserve tag"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_pmc",
        smoke_boot0_unknown_arch_preserves_raw
    );

    fn smoke_present_classifier() -> TestResult {
        if Boot0::looks_present(0xFFFF_FFFF) {
            return TestResult::Fail("master-abort must read as absent");
        }
        if Boot0::looks_present(0) {
            return TestResult::Fail("zero must read as absent");
        }
        if !Boot0::looks_present(0x160 << 20) {
            return TestResult::Fail("Turing arch must read as present");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_pmc", smoke_present_classifier);
}
