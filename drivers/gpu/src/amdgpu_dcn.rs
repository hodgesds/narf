//! AMD DCN (Display Core Next) HUBP / OPP / OTG register codec —
//! clean-room.
//!
//! ## Reference
//!
//! - **AMD GPUOpen "GPU architecture programming documentation"
//!   hub** — links per-generation DCN register references.
//!   <https://gpuopen.com/amd-gpu-architecture-programming-documentation/>
//! - **AMD DCN1 / DCN2 / DCN3 register reference** (per-family
//!   PDFs published on developer.amd.com): documents the HUBP
//!   (Hub Pixel Pipe), OPP (Output Pixel Processor), and OTG
//!   (Output Timing Generator) per-block register tables.
//! - **`amdgpu_offsets`** — runtime registry that supplies
//!   per-family DCN block bases. Stage-2 leaves Phoenix / Strix /
//!   Renoir as "register at boot"; Vega + Navi 1 fall back to
//!   the published GPUOpen IP-table values.
//!
//! No GPL Linux `amdgpu` source consulted. Per-block register
//! offsets transcribed from the public AMD DCN reference PDFs
//! cited above. The AMD PPR (the per-SoC document that maps a
//! family's *base* offsets) supplies the runtime registry input;
//! its tables are not transcribed into this source tree.
//!
//! ## DCN model
//!
//! DCN drives a display through a three-stage pipeline:
//!
//! ```text
//!   [VRAM scanout buffer]
//!         │
//!         │  reads framebuffer
//!         ▼
//!   ┌───────────────┐
//!   │     HUBP      │   primary-plane fetch unit
//!   │ (Hub Pixel    │   - PRIMARY_SURFACE_ADDR_*
//!   │   Pipe)       │   - PRIMARY_SURFACE_PITCH
//!   │               │   - HUBP_BLANK
//!   └───────┬───────┘
//!           │
//!           ▼
//!   ┌───────────────┐
//!   │      OPP      │   output pixel processor
//!   │ (Output Pixel │   - OPP_PIPE_TOP_GAMMA_PASSTHROUGH
//!   │   Processor)  │   - OPP_PIPE_CONTROL
//!   └───────┬───────┘
//!           │
//!           ▼
//!   ┌───────────────┐
//!   │      OTG      │   output timing generator
//!   │ (Output       │   - OTG_H_TOTAL / OTG_V_TOTAL
//!   │   Timing Gen) │   - OTG_H_BLANK_START_END
//!   │               │   - OTG_MASTER_EN
//!   └───────────────┘
//!           │
//!           ▼ (to DDI / DCN-AUX → DP/HDMI)
//! ```
//!
//! ## Scope
//!
//! Codec layer only — produces the (offset, value) pairs the
//! Stage-3 driver core writes to BAR5 through the existing
//! `mm_read` / `mm_write` indirection in `amdgpu`. The actual
//! MMIO sequencing (disable scanout → reprogram → re-enable)
//! lives in `amdgpu::set_mode` once this codec lands.

use crate::amdgpu::Family;
use crate::amdgpu_offsets;

// ── HUBP register offsets (AMD DCN1+ register reference) ─────────
//
// Offsets are *relative* to the per-family `dcn_hubp_base`
// registered through `amdgpu_offsets`. Without a registered
// base, the codec returns `None` rather than poking the wrong
// register window.

/// HUBP_BLANK control. Bit 0 = 1 forces the pipe blank.
pub const HUBP_BLANK_REL: u32 = 0x0064;
/// HUBP primary surface address (low 32 bits).
pub const HUBP_PRIMARY_SURFACE_ADDRESS_REL: u32 = 0x00A4;
/// HUBP primary surface address (high 32 bits).
pub const HUBP_PRIMARY_SURFACE_ADDRESS_HIGH_REL: u32 = 0x00A0;
/// HUBP primary surface pitch.
pub const HUBP_PRIMARY_SURFACE_PITCH_REL: u32 = 0x00A8;

/// HUBP_BLANK[0] — force-blank.
pub const HUBP_BLANK_FORCE: u32 = 1 << 0;

// ── OPP register offsets (AMD DCN1+ register reference) ──────────

/// OPP_PIPE_CONTROL — top-level pipe enable + format.
pub const OPP_PIPE_CONTROL_REL: u32 = 0x0040;
/// OPP top-of-gamma passthrough toggle (0 = pass linear).
pub const OPP_PIPE_TOP_GAMMA_REL: u32 = 0x0044;

/// OPP_PIPE_CONTROL[0] — pipe enable.
pub const OPP_PIPE_ENABLE: u32 = 1 << 0;

// ── OTG register offsets (AMD DCN1+ register reference) ──────────

/// OTG_H_TOTAL — bits[15:0] = h_total - 1.
pub const OTG_H_TOTAL_REL: u32 = 0x0000;
/// OTG_V_TOTAL — bits[15:0] = v_total - 1.
pub const OTG_V_TOTAL_REL: u32 = 0x0004;
/// OTG_H_BLANK_START_END — bits[15:0]=start, bits[31:16]=end.
pub const OTG_H_BLANK_START_END_REL: u32 = 0x0008;
pub const OTG_V_BLANK_START_END_REL: u32 = 0x000C;
pub const OTG_H_SYNC_A_REL: u32 = 0x0010;
pub const OTG_V_SYNC_A_REL: u32 = 0x0014;
/// OTG_MASTER_EN — bit 0 = 1 starts scanout.
pub const OTG_CONTROL_REL: u32 = 0x0040;

pub const OTG_MASTER_EN: u32 = 1 << 0;

// ── Codec error type ─────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DcnError {
    /// Family has no DCN block bases registered. Scanout cannot
    /// be programmed without `register_family_offsets` being
    /// called first.
    OffsetsUnregistered,
    /// Mode timings violate documented limits.
    BadTiming,
    /// Stride not a multiple of 256 bytes (DCN1+ requires 256-
    /// byte aligned primary-surface pitch).
    BadStride,
    /// Surface address not 256-byte aligned.
    BadSurfaceAddr,
}

// ── Programmed sequences ─────────────────────────────────────────

/// One MMIO write the caller will dispatch through `mm_write`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DcnWrite {
    pub addr: u32,
    pub value: u32,
}

/// Display timings, in pixels / scanlines. Mirrors
/// `intel_gpu_pipes::DisplayTiming` but kept local so the AMD
/// codec doesn't pull Intel definitions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DcnTiming {
    pub htotal: u16,
    pub vtotal: u16,
    pub hblank_start: u16,
    pub hblank_end: u16,
    pub vblank_start: u16,
    pub vblank_end: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
}

/// Complete modeset write sequence: blank → reprogram → unblank.
/// All offsets are absolute register-bus addresses (already
/// folded against the per-family DCN block bases).
#[derive(Debug, Default)]
pub struct ModesetSequence {
    pub disable: [Option<DcnWrite>; 2],
    pub program: [Option<DcnWrite>; 12],
    pub enable: [Option<DcnWrite>; 2],
}

impl ModesetSequence {
    pub fn iter(&self) -> impl Iterator<Item = DcnWrite> + '_ {
        self.disable
            .iter()
            .copied()
            .chain(self.program.iter().copied())
            .chain(self.enable.iter().copied())
            .flatten()
    }
}

fn pack_pair(end: u16, start: u16) -> u32 {
    ((end as u32) << 16) | (start as u32)
}

/// Build the full HUBP / OPP / OTG modeset write sequence.
///
/// `surface_addr` is the GPU virtual address of the primary
/// scanout buffer (typically the VRAM aperture base).
/// `stride_bytes` is the row stride in bytes; `surface_addr` and
/// `stride_bytes` must both be 256-byte aligned per the DCN1+
/// register reference.
pub fn build_modeset(
    family: Family,
    timing: &DcnTiming,
    surface_addr: u64,
    stride_bytes: u32,
) -> Result<ModesetSequence, DcnError> {
    let regs = amdgpu_offsets::offsets_of(family);
    let hubp_base = regs.dcn_hubp_base.ok_or(DcnError::OffsetsUnregistered)?;
    let opp_base = regs.dcn_opp_base.ok_or(DcnError::OffsetsUnregistered)?;
    let otg_base = regs.dcn_otg_base.ok_or(DcnError::OffsetsUnregistered)?;

    if timing.htotal < 64 || timing.vtotal < 64 || timing.htotal > 16384 || timing.vtotal > 16384 {
        return Err(DcnError::BadTiming);
    }
    if surface_addr & 0xFF != 0 {
        return Err(DcnError::BadSurfaceAddr);
    }
    if stride_bytes == 0 || stride_bytes & 0xFF != 0 {
        return Err(DcnError::BadStride);
    }

    let mut seq = ModesetSequence::default();

    // Disable: blank HUBP and stop OTG before reprogramming.
    seq.disable[0] = Some(DcnWrite {
        addr: hubp_base + HUBP_BLANK_REL,
        value: HUBP_BLANK_FORCE,
    });
    seq.disable[1] = Some(DcnWrite {
        addr: otg_base + OTG_CONTROL_REL,
        value: 0,
    });

    // Program: HUBP surface + pitch.
    let surf_lo = surface_addr as u32;
    let surf_hi = (surface_addr >> 32) as u32;
    seq.program[0] = Some(DcnWrite {
        addr: hubp_base + HUBP_PRIMARY_SURFACE_ADDRESS_HIGH_REL,
        value: surf_hi,
    });
    seq.program[1] = Some(DcnWrite {
        addr: hubp_base + HUBP_PRIMARY_SURFACE_ADDRESS_REL,
        value: surf_lo,
    });
    seq.program[2] = Some(DcnWrite {
        addr: hubp_base + HUBP_PRIMARY_SURFACE_PITCH_REL,
        value: stride_bytes,
    });

    // Program: OPP — gamma passthrough (linear scanout).
    seq.program[3] = Some(DcnWrite {
        addr: opp_base + OPP_PIPE_CONTROL_REL,
        value: OPP_PIPE_ENABLE,
    });
    seq.program[4] = Some(DcnWrite {
        addr: opp_base + OPP_PIPE_TOP_GAMMA_REL,
        value: 0,
    });

    // Program: OTG H/V totals + blank/sync.
    seq.program[5] = Some(DcnWrite {
        addr: otg_base + OTG_H_TOTAL_REL,
        value: (timing.htotal - 1) as u32,
    });
    seq.program[6] = Some(DcnWrite {
        addr: otg_base + OTG_V_TOTAL_REL,
        value: (timing.vtotal - 1) as u32,
    });
    seq.program[7] = Some(DcnWrite {
        addr: otg_base + OTG_H_BLANK_START_END_REL,
        value: pack_pair(timing.hblank_end, timing.hblank_start),
    });
    seq.program[8] = Some(DcnWrite {
        addr: otg_base + OTG_V_BLANK_START_END_REL,
        value: pack_pair(timing.vblank_end, timing.vblank_start),
    });
    seq.program[9] = Some(DcnWrite {
        addr: otg_base + OTG_H_SYNC_A_REL,
        value: pack_pair(timing.hsync_end, timing.hsync_start),
    });
    seq.program[10] = Some(DcnWrite {
        addr: otg_base + OTG_V_SYNC_A_REL,
        value: pack_pair(timing.vsync_end, timing.vsync_start),
    });

    // Enable: unblank HUBP, start OTG.
    seq.enable[0] = Some(DcnWrite {
        addr: hubp_base + HUBP_BLANK_REL,
        value: 0,
    });
    seq.enable[1] = Some(DcnWrite {
        addr: otg_base + OTG_CONTROL_REL,
        value: OTG_MASTER_EN,
    });

    Ok(seq)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::amdgpu::Family;
    use crate::amdgpu_offsets::{register_family_offsets, FamilyOffsets};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn timing() -> DcnTiming {
        DcnTiming {
            htotal: 2200,
            vtotal: 1125,
            hblank_start: 1920,
            hblank_end: 2200,
            vblank_start: 1080,
            vblank_end: 1125,
            hsync_start: 2008,
            hsync_end: 2052,
            vsync_start: 1084,
            vsync_end: 1089,
        }
    }

    fn smoke_modeset_unregistered_fails() -> TestResult {
        // Use a family that's intentionally not pre-registered.
        // The offsets registry is process-wide; reset only the
        // slot we care about.
        register_family_offsets(Family::Renoir, FamilyOffsets::empty());
        match build_modeset(Family::Renoir, &timing(), 0x1000_0000, 1920 * 4) {
            Err(DcnError::OffsetsUnregistered) => TestResult::Pass,
            _ => TestResult::Fail("missing offsets must surface explicitly"),
        }
    }
    kernel_test_in!("drivers/gpu/amdgpu_dcn", smoke_modeset_unregistered_fails);

    fn smoke_modeset_program_layout() -> TestResult {
        // Register a synthetic offset triple.
        register_family_offsets(
            Family::Vega,
            FamilyOffsets {
                mp0_base: Some(0x000B_0000),
                dcn_hubp_base: Some(0x0000_3000),
                dcn_opp_base: Some(0x0000_4000),
                dcn_otg_base: Some(0x0000_5000),
                dcn_aux_base: None,
                gfx_rb_base: None,
            },
        );
        let seq = match build_modeset(Family::Vega, &timing(), 0x0010_0000, 1920 * 4) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        // Disable phase blanks HUBP and clears OTG control.
        let writes: alloc::vec::Vec<_> = seq.iter().collect();
        if writes.is_empty() {
            return TestResult::Fail("empty sequence");
        }
        // First write must be HUBP blank.
        if writes[0].addr != 0x0000_3000 + HUBP_BLANK_REL {
            return TestResult::Fail("first write should be HUBP blank");
        }
        if writes[0].value & HUBP_BLANK_FORCE == 0 {
            return TestResult::Fail("HUBP blank not forced");
        }
        // Last enable write must assert OTG_MASTER_EN.
        let last = writes.last().copied().unwrap();
        if last.addr != 0x0000_5000 + OTG_CONTROL_REL || last.value != OTG_MASTER_EN {
            return TestResult::Fail("last write should enable OTG master");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu_dcn", smoke_modeset_program_layout);

    fn smoke_modeset_rejects_bad_stride() -> TestResult {
        register_family_offsets(
            Family::Vega,
            FamilyOffsets {
                mp0_base: Some(0x000B_0000),
                dcn_hubp_base: Some(0x3000),
                dcn_opp_base: Some(0x4000),
                dcn_otg_base: Some(0x5000),
                dcn_aux_base: None,
                gfx_rb_base: None,
            },
        );
        match build_modeset(Family::Vega, &timing(), 0x100, 1920 * 4 + 1) {
            Err(DcnError::BadStride) => TestResult::Pass,
            _ => TestResult::Fail("non-256B stride must be rejected"),
        }
    }
    kernel_test_in!("drivers/gpu/amdgpu_dcn", smoke_modeset_rejects_bad_stride);
}
