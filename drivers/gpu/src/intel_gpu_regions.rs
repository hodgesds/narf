//! Intel iGPU MMIO register-block enumeration.
//!
//! Unlike AMD's GPUs (where the on-die IP discovery table at the top
//! of VRAM tells the driver where every IP block lives — see
//! `amdgpu_discovery`), Intel iGPUs publish their register layout
//! **statically per generation**. There is no run-time discovery
//! blob; instead, the i915 / Xe driver carries a per-generation
//! table that names each "register block" (GT, DISPLAY, GMBUS,
//! DPLL, GUNIT, PUNIT, FUSES, …) and its byte range within BAR0
//! (`GTTMMADR`, the unified MMIO + GTT window).
//!
//! This module reproduces that static enumeration for Gen12
//! (Tiger Lake / Alder Lake / Raptor Lake — Xe-LP) so the driver
//! core has a single canonical place to look up "where does GT
//! live on TGL?".
//!
//! ## References
//!
//! NARF is GPL-2.0-or-later as of 2026-05-20, so the offsets and
//! block boundaries here are adapted directly from Linux:
//!
//! - `drivers/gpu/drm/i915/intel_uncore.c` — the MMIO-accessor
//!   layer that picks the right forcewake domain per address; its
//!   `intel_uncore_fw_domains_init` and forcewake-range tables are
//!   the canonical source for "which addresses belong to GT vs
//!   DISPLAY vs MEDIA".
//! - `drivers/gpu/drm/i915/gt/intel_gt_regs.h` — GT engine
//!   register offsets (RCS / BCS / VCS / VECS rings, RING_TAIL /
//!   RING_HEAD / RING_CTL bases).
//! - `drivers/gpu/drm/i915/display/intel_de.h` — display-engine
//!   register accessors; `i915_reg.h` carries the matching offsets.
//! - `drivers/gpu/drm/xe/regs/xe_engine_regs.h` and
//!   `drivers/gpu/drm/xe/regs/xe_gt_regs.h` — Xe driver's restated
//!   versions of the same offsets (useful cross-check; the wire
//!   format is identical on Gen12).
//! - **Tiger Lake PRM Vol. 12 §"Memory Map and Configuration"** —
//!   public Intel reference for the BAR0 layout.
//!
//! ## BAR0 (GTTMMADR) layout for Gen12 (Xe-LP)
//!
//! BAR0 is split into two halves:
//!
//! ```text
//!   [0x0000_0000 .. 0x0080_0000)   8 MiB   MMIO register window
//!   [0x0080_0000 .. 0x0100_0000)   8 MiB   GTT entry array
//! ```
//!
//! The MMIO half subdivides into per-block regions. The boundary
//! addresses below come from `i915_reg.h` block-name comments
//! cross-referenced against the TGL PRM Vol. 12 register-address
//! ranges.

use core::convert::TryFrom;

// ── Region identifiers ───────────────────────────────────────────

/// The named register blocks the Stage-0 driver enumerates from
/// BAR0. Matches the block taxonomy i915 uses in
/// `intel_uncore_fw_domains_init` (one entry per forcewake domain
/// + a few non-forcewake blocks the driver still groups by name).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RegionKind {
    /// `GT` — render / compute / blitter / video command streamers
    /// and the per-engine register tail (RCS0/BCS0/VCS0/VECS0
    /// rings). Forcewake-render domain on Gen12.
    Gt = 0,
    /// `DISPLAY` — pipes, transcoders, planes, DDIs, DPLLs,
    /// audio-codec scratchpads. Display-domain power is independent
    /// of GT in Gen12.
    Display = 1,
    /// `GMBUS` — the Intel-specific I²C controller used for
    /// DDC / EDID reads off DDI pin pairs.
    Gmbus = 2,
    /// `DPLL` — display PLLs (DPLL0..3 + per-TC-PHY DPLLs).
    Dpll = 3,
    /// `GUNIT` — graphics arbiter / interrupt aggregator. Hosts
    /// the master interrupt enable, the BAR0-relative HW status
    /// page, and the global GTT control registers.
    Gunit = 4,
    /// `PUNIT` — power-management microcontroller mailbox. Maps
    /// the platform's PCODE messaging channel.
    Punit = 5,
    /// `FUSE` — read-only OTP fuses that report harvested
    /// configuration (slice / sub-slice / EU count, GT freq caps,
    /// SKU bits).
    Fuse = 6,
    /// `GTTADR` — the GTT entry array half of BAR0. 8 MiB of
    /// 64-bit page-table entries on Gen12.
    GttAdr = 7,
}

impl RegionKind {
    /// Short canonical name used in diagnostic logs and the spec
    /// PDFs. Matches i915's block-name strings.
    pub const fn name(self) -> &'static str {
        match self {
            RegionKind::Gt => "GT",
            RegionKind::Display => "DISPLAY",
            RegionKind::Gmbus => "GMBUS",
            RegionKind::Dpll => "DPLL",
            RegionKind::Gunit => "GUNIT",
            RegionKind::Punit => "PUNIT",
            RegionKind::Fuse => "FUSE",
            RegionKind::GttAdr => "GTTADR",
        }
    }
}

impl TryFrom<u8> for RegionKind {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => RegionKind::Gt,
            1 => RegionKind::Display,
            2 => RegionKind::Gmbus,
            3 => RegionKind::Dpll,
            4 => RegionKind::Gunit,
            5 => RegionKind::Punit,
            6 => RegionKind::Fuse,
            7 => RegionKind::GttAdr,
            _ => return Err(()),
        })
    }
}

// ── Region descriptors ───────────────────────────────────────────

/// One enumerated register block within BAR0.
///
/// `offset` + `size` define the byte range relative to BAR0's base
/// address. The driver core asserts `offset + size <= bar0.len`
/// before any MMIO access (BAR0 on Gen12 is 16 MiB; every region
/// here fits inside that envelope).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub kind: RegionKind,
    pub offset: u64,
    pub size: u64,
}

impl Region {
    /// `true` if `byte_offset` (a BAR0-relative address) falls
    /// inside this region.
    pub const fn contains(&self, byte_offset: u64) -> bool {
        byte_offset >= self.offset && (byte_offset - self.offset) < self.size
    }

    /// End offset (one past the last byte) of the region.
    pub const fn end(&self) -> u64 {
        self.offset + self.size
    }
}

// ── Per-generation region tables ─────────────────────────────────
//
// Boundaries come from `drivers/gpu/drm/i915/i915_reg.h` block
// comments and the forcewake range tables in
// `drivers/gpu/drm/i915/intel_uncore.c::__gen11_fw_ranges`
// (Gen11/Gen12 share the same partitioning) cross-checked against
// TGL PRM Vol. 12 §"Memory Map and Configuration".
//
// Sizes are conservative: each region is sized to cover all
// documented register offsets within its block plus a small
// trailing margin for SKU-specific scratchpads. The Stage-0
// driver only uses these for bounds-checking and reporting; the
// codec layer carries the exact per-register offsets.

/// Gen12 (Xe-LP) region map — Tiger Lake, Alder Lake, Raptor Lake.
///
/// Cross-checked against:
/// - `i915_reg.h` block boundaries for TGL.
/// - `xe_gt_regs.h` for the Xe driver's restated GT block (same
///   on Gen12).
pub static GEN12_REGIONS: &[Region] = &[
    Region {
        kind: RegionKind::Gunit,
        offset: 0x0000_0000,
        size: 0x0001_0000,
    },
    Region {
        kind: RegionKind::Fuse,
        offset: 0x0000_9000,
        size: 0x0000_1000,
    },
    Region {
        kind: RegionKind::Punit,
        offset: 0x0013_8000,
        size: 0x0000_8000,
    },
    Region {
        kind: RegionKind::Gt,
        offset: 0x0000_2000,
        size: 0x0000_4000,
    },
    Region {
        kind: RegionKind::Display,
        offset: 0x0006_0000,
        size: 0x0001_0000,
    },
    // GMBUS sits inside the display block on i915's map, but the
    // Stage-2 codec carries it as its own register file (matching
    // the i915 `gmbus.c` block) so the enumeration mirrors that.
    Region {
        kind: RegionKind::Gmbus,
        offset: 0x000C_5100,
        size: 0x0000_0040,
    },
    Region {
        kind: RegionKind::Dpll,
        offset: 0x0016_4280,
        size: 0x0000_0040,
    },
    // GTT entry array — second half of BAR0. 8 MiB on Gen12 maps
    // 1M PTEs × 8 bytes; the codec layer in `intel_gpu_gtt` writes
    // into this region via `intel_gpu.bar0_offset(GTTADR_BASE)`.
    Region {
        kind: RegionKind::GttAdr,
        offset: 0x0080_0000,
        size: 0x0080_0000,
    },
];

// ── Generation routing ───────────────────────────────────────────

/// Sub-architectures the Stage-0 enumeration covers. Tiger Lake /
/// Alder Lake / Raptor Lake all share the Xe-LP register surface
/// and are folded onto `GEN12_REGIONS`. Meteor Lake (Xe-LPG) has
/// a different MMIO map — display block shifted, GT block extended
/// — and is not part of this scope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegionGeneration {
    /// Gen12 Xe-LP — TGL / ADL / RPL.
    Gen12,
}

/// Resolve the region table for a generation.
pub const fn regions_for(gen: RegionGeneration) -> &'static [Region] {
    match gen {
        RegionGeneration::Gen12 => GEN12_REGIONS,
    }
}

/// Find the region containing the BAR0-relative byte offset, if any.
pub fn region_at(gen: RegionGeneration, byte_offset: u64) -> Option<&'static Region> {
    regions_for(gen).iter().find(|r| r.contains(byte_offset))
}

/// Find the region of the given kind, if the generation defines one.
pub fn region_of(gen: RegionGeneration, kind: RegionKind) -> Option<&'static Region> {
    regions_for(gen).iter().find(|r| r.kind == kind)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_gen12_has_all_kinds() -> TestResult {
        for kind in [
            RegionKind::Gt,
            RegionKind::Display,
            RegionKind::Gmbus,
            RegionKind::Dpll,
            RegionKind::Gunit,
            RegionKind::Punit,
            RegionKind::Fuse,
            RegionKind::GttAdr,
        ] {
            if region_of(RegionGeneration::Gen12, kind).is_none() {
                return TestResult::Fail("Gen12 region table missing a kind");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_regions", smoke_gen12_has_all_kinds);

    fn smoke_regions_fit_in_bar0() -> TestResult {
        // BAR0 (GTTMMADR) on Gen12 is 16 MiB total: 8 MiB MMIO half
        // + 8 MiB GTT half. Every enumerated region must fit.
        const BAR0_LEN: u64 = 16 * 1024 * 1024;
        for r in GEN12_REGIONS {
            if r.end() > BAR0_LEN {
                return TestResult::Fail("region overflows BAR0 size");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_regions", smoke_regions_fit_in_bar0);

    fn smoke_display_contains_pipes() -> TestResult {
        // Pipe A base is `0x60000` per intel_gpu_pipes; it must
        // land inside the DISPLAY region.
        match region_at(RegionGeneration::Gen12, 0x6_0000) {
            Some(r) if r.kind == RegionKind::Display => TestResult::Pass,
            _ => TestResult::Fail("DISPLAY region should contain pipe A base"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_regions",
        smoke_display_contains_pipes
    );

    fn smoke_gmbus_contains_gmbus_offsets() -> TestResult {
        // GMBUS register file starts at 0xC5100 (TGL PRM Vol. 12).
        match region_at(RegionGeneration::Gen12, 0xC_5100) {
            Some(r) if r.kind == RegionKind::Gmbus => TestResult::Pass,
            _ => TestResult::Fail("GMBUS region should contain GMBUS0 offset"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_regions",
        smoke_gmbus_contains_gmbus_offsets
    );

    fn smoke_gtt_adr_second_half() -> TestResult {
        let r = region_of(RegionGeneration::Gen12, RegionKind::GttAdr).expect("GTTADR present");
        // Second half of a 16 MiB BAR.
        if r.offset != 0x0080_0000 || r.size != 0x0080_0000 {
            return TestResult::Fail("GTTADR should be the second 8 MiB of BAR0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_regions", smoke_gtt_adr_second_half);

    fn smoke_region_kind_roundtrip() -> TestResult {
        for kind in [
            RegionKind::Gt,
            RegionKind::Display,
            RegionKind::Gmbus,
            RegionKind::Dpll,
            RegionKind::Gunit,
            RegionKind::Punit,
            RegionKind::Fuse,
            RegionKind::GttAdr,
        ] {
            let v = kind as u8;
            match RegionKind::try_from(v) {
                Ok(k) if k == kind => {}
                _ => return TestResult::Fail("RegionKind roundtrip failed"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_regions", smoke_region_kind_roundtrip);
}
