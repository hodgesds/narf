//! The GFX11 clear-state block and the CP preamble that installs it.
//!
//! Before the graphics ring can run anything, the CP has to be given a known
//! context: a block of context-register values the hardware keeps as "state 0"
//! and reloads on every `CLEAR_STATE`. Linux calls this the CSB (clear-state
//! block) and emits it as the first thing on the GFX ring in
//! `gfx_v11_0_cp_gfx_start`.
//!
//! ## References
//!
//! - Linux `drivers/gpu/drm/amd/amdgpu/gfx_v11_0.c::gfx_v11_0_cp_gfx_start`
//!   and `gfx_v11_0_get_csb_size`.
//! - Linux `drivers/gpu/drm/amd/amdgpu/clearstate_gfx11.h` — the table itself
//!   (`gfx11_cs_data` -> `gfx11_SECT_CONTEXT_defs`).
//! - Linux `drivers/gpu/drm/amd/amdgpu/nvd.h` — the PACKET3 opcodes and
//!   `PACKET3_SET_CONTEXT_REG_START`.
//!
//! ## Why the table is stored sparsely
//!
//! `gfx11_SECT_CONTEXT_defs` is seven extents covering 934 context registers,
//! and **78** of those values are non-zero. Transcribing 934 literals would
//! produce a table nobody can check against the header; the 78 below can be
//! read against `clearstate_gfx11.h`'s own register-name comments one line at
//! a time, and every unlisted register in an extent's span is zero — which is
//! both the header's value and the safe default. [`EXTENTS`] pins the spans
//! and counts, so a missing entry shows up as a length mismatch rather than a
//! silently zeroed register.

extern crate alloc;

use alloc::vec::Vec;

/// `PACKET3_SET_CONTEXT_REG_START` (`nvd.h:517`). Context-register writes
/// carry their index relative to this base.
pub const SET_CONTEXT_REG_START: u32 = 0x0000_a000;

/// `PACKET3_PREAMBLE_BEGIN_CLEAR_STATE` (`nvd.h:395`) — `2 << 28`.
pub const PREAMBLE_BEGIN_CLEAR_STATE: u32 = 2 << 28;
/// `PACKET3_PREAMBLE_END_CLEAR_STATE` (`nvd.h:396`) — `3 << 28`.
pub const PREAMBLE_END_CLEAR_STATE: u32 = 3 << 28;

/// `CONTEXT_CONTROL`'s two dwords, both `0x80000000` in
/// `gfx_v11_0_cp_gfx_start`: load the whole context, shadow nothing.
pub const CONTEXT_CONTROL_LOAD_ENABLE: u32 = 0x8000_0000;

/// One `cs_extent_def`: the first context-register index it covers and how
/// many consecutive registers follow.
///
/// The spans are NOT contiguous — extent 1 ends at 0xa0d6 and extent 2 starts
/// at 0xa0d8, and there are four more gaps after that. Each extent therefore
/// becomes its own `SET_CONTEXT_REG` packet rather than one long run.
pub const EXTENTS: &[(u32, u32)] = &[
    (0xa000, 215),
    (0xa0d8, 272),
    (0xa1f5, 4),
    (0xa1ff, 158),
    (0xa2a0, 2),
    (0xa2a3, 1),
    (0xa2a6, 282),
];

/// The non-zero entries of `gfx11_SECT_CONTEXT_defs`, as
/// (context-register index, value). Every register inside an [`EXTENTS`] span
/// and absent here is zero.
///
/// The comment on each line is the register name
/// `clearstate_gfx11.h` gives it, so a reader can check any one of these
/// against the header without counting array positions.
pub const NONZERO: &[(u32, u32)] = &[
    (0xa00d, 0x40004000), // PA_SC_SCREEN_SCISSOR_BR
    (0xa01f, 0x00150055), // DB_RMI_L2_CACHE_CONTROL
    (0xa081, 0x80000000), // PA_SC_WINDOW_SCISSOR_TL
    (0xa082, 0x40004000), // PA_SC_WINDOW_SCISSOR_BR
    (0xa083, 0x0000ffff), // PA_SC_CLIPRECT_RULE
    (0xa085, 0x40004000), // PA_SC_CLIPRECT_0_BR
    (0xa087, 0x40004000), // PA_SC_CLIPRECT_1_BR
    (0xa089, 0x40004000), // PA_SC_CLIPRECT_2_BR
    (0xa08b, 0x40004000), // PA_SC_CLIPRECT_3_BR
    (0xa08c, 0xaa99aaaa), // PA_SC_EDGERULE
    (0xa08e, 0xffffffff), // CB_TARGET_MASK
    (0xa08f, 0xffffffff), // CB_SHADER_MASK
    (0xa090, 0x80000000), // PA_SC_GENERIC_SCISSOR_TL
    (0xa091, 0x40004000), // PA_SC_GENERIC_SCISSOR_BR
    (0xa094, 0x80000000), // PA_SC_VPORT_SCISSOR_0_TL
    (0xa095, 0x40004000), // PA_SC_VPORT_SCISSOR_0_BR
    (0xa096, 0x80000000), // PA_SC_VPORT_SCISSOR_1_TL
    (0xa097, 0x40004000), // PA_SC_VPORT_SCISSOR_1_BR
    (0xa098, 0x80000000), // PA_SC_VPORT_SCISSOR_2_TL
    (0xa099, 0x40004000), // PA_SC_VPORT_SCISSOR_2_BR
    (0xa09a, 0x80000000), // PA_SC_VPORT_SCISSOR_3_TL
    (0xa09b, 0x40004000), // PA_SC_VPORT_SCISSOR_3_BR
    (0xa09c, 0x80000000), // PA_SC_VPORT_SCISSOR_4_TL
    (0xa09d, 0x40004000), // PA_SC_VPORT_SCISSOR_4_BR
    (0xa09e, 0x80000000), // PA_SC_VPORT_SCISSOR_5_TL
    (0xa09f, 0x40004000), // PA_SC_VPORT_SCISSOR_5_BR
    (0xa0a0, 0x80000000), // PA_SC_VPORT_SCISSOR_6_TL
    (0xa0a1, 0x40004000), // PA_SC_VPORT_SCISSOR_6_BR
    (0xa0a2, 0x80000000), // PA_SC_VPORT_SCISSOR_7_TL
    (0xa0a3, 0x40004000), // PA_SC_VPORT_SCISSOR_7_BR
    (0xa0a4, 0x80000000), // PA_SC_VPORT_SCISSOR_8_TL
    (0xa0a5, 0x40004000), // PA_SC_VPORT_SCISSOR_8_BR
    (0xa0a6, 0x80000000), // PA_SC_VPORT_SCISSOR_9_TL
    (0xa0a7, 0x40004000), // PA_SC_VPORT_SCISSOR_9_BR
    (0xa0a8, 0x80000000), // PA_SC_VPORT_SCISSOR_10_TL
    (0xa0a9, 0x40004000), // PA_SC_VPORT_SCISSOR_10_BR
    (0xa0aa, 0x80000000), // PA_SC_VPORT_SCISSOR_11_TL
    (0xa0ab, 0x40004000), // PA_SC_VPORT_SCISSOR_11_BR
    (0xa0ac, 0x80000000), // PA_SC_VPORT_SCISSOR_12_TL
    (0xa0ad, 0x40004000), // PA_SC_VPORT_SCISSOR_12_BR
    (0xa0ae, 0x80000000), // PA_SC_VPORT_SCISSOR_13_TL
    (0xa0af, 0x40004000), // PA_SC_VPORT_SCISSOR_13_BR
    (0xa0b0, 0x80000000), // PA_SC_VPORT_SCISSOR_14_TL
    (0xa0b1, 0x40004000), // PA_SC_VPORT_SCISSOR_14_BR
    (0xa0b2, 0x80000000), // PA_SC_VPORT_SCISSOR_15_TL
    (0xa0b3, 0x40004000), // PA_SC_VPORT_SCISSOR_15_BR
    (0xa0b5, 0x3f800000), // PA_SC_VPORT_ZMAX_0
    (0xa0b7, 0x3f800000), // PA_SC_VPORT_ZMAX_1
    (0xa0b9, 0x3f800000), // PA_SC_VPORT_ZMAX_2
    (0xa0bb, 0x3f800000), // PA_SC_VPORT_ZMAX_3
    (0xa0bd, 0x3f800000), // PA_SC_VPORT_ZMAX_4
    (0xa0bf, 0x3f800000), // PA_SC_VPORT_ZMAX_5
    (0xa0c1, 0x3f800000), // PA_SC_VPORT_ZMAX_6
    (0xa0c3, 0x3f800000), // PA_SC_VPORT_ZMAX_7
    (0xa0c5, 0x3f800000), // PA_SC_VPORT_ZMAX_8
    (0xa0c7, 0x3f800000), // PA_SC_VPORT_ZMAX_9
    (0xa0c9, 0x3f800000), // PA_SC_VPORT_ZMAX_10
    (0xa0cb, 0x3f800000), // PA_SC_VPORT_ZMAX_11
    (0xa0cd, 0x3f800000), // PA_SC_VPORT_ZMAX_12
    (0xa0cf, 0x3f800000), // PA_SC_VPORT_ZMAX_13
    (0xa0d1, 0x3f800000), // PA_SC_VPORT_ZMAX_14
    (0xa0d3, 0x3f800000), // PA_SC_VPORT_ZMAX_15
    (0xa104, 0x00550055), // CB_RMI_GL2_CACHE_CONTROL
    (0xa10c, 0x01000000), // DB_STENCILREFMASK
    (0xa10d, 0x01000000), // DB_STENCILREFMASK_BF
    (0xa1b6, 0x00000002), // SPI_PS_IN_CONTROL
    (0xa204, 0x00090000), // PA_CL_CLIP_CNTL
    (0xa205, 0x00000004), // PA_SU_SC_MODE_CNTL
    (0xa2f7, 0x00001000), // PA_SC_LINE_CNTL
    (0xa2f9, 0x00000005), // PA_SU_VTX_CNTL
    (0xa2fa, 0x3f800000), // PA_CL_GB_VERT_CLIP_ADJ
    (0xa2fb, 0x3f800000), // PA_CL_GB_VERT_DISC_ADJ
    (0xa2fc, 0x3f800000), // PA_CL_GB_HORZ_CLIP_ADJ
    (0xa2fd, 0x3f800000), // PA_CL_GB_HORZ_DISC_ADJ
    (0xa30e, 0xffffffff), // PA_SC_AA_MASK_X0Y0_X1Y0
    (0xa30f, 0xffffffff), // PA_SC_AA_MASK_X0Y1_X1Y1
    (0xa311, 0x00000003), // PA_SC_BINNER_CNTL_0
    (0xa313, 0x00100000), // PA_SC_CONSERVATIVE_RASTERIZATION_CNTL
];

/// Total context registers the table covers — the sum of [`EXTENTS`]' counts.
pub const REGISTER_COUNT: u32 = 934;

/// Dwords `build_preamble` emits, matching `gfx_v11_0_get_csb_size`:
/// 2 for BEGIN_CLEAR_STATE, 3 for CONTEXT_CONTROL, `2 + reg_count` per
/// extent, 3 for the tile-steering override, 2 for END_CLEAR_STATE and 2 for
/// CLEAR_STATE.
pub const CSB_DWORDS: u32 = 2 + 3 + (2 * EXTENTS.len() as u32 + REGISTER_COUNT) + 3 + 2 + 2;

/// `regPA_SC_TILE_STEERING_OVERRIDE` — dword 0x00d7 on **GC BASE_IDX 1**.
///
/// Unlike [`EXTENTS`], whose indices are already context-register indices
/// straight out of `cs_extent_def`, this one is a register id and has to be
/// resolved before it means anything:
/// `SOC15_REG_OFFSET(GC, 0, regPA_SC_TILE_STEERING_OVERRIDE) -
/// PACKET3_SET_CONTEXT_REG_START`. So [`build_preamble`] takes the GC window-1
/// base rather than carrying a constant — there is no fixed context index to
/// carry, and inventing one would put the per-ASIC tile-steering value on some
/// other context register.
pub const PA_SC_TILE_STEERING_OVERRIDE_REL: u32 = 0x0000_00d7;

/// Expand one extent into its dense register values.
fn extent_values(reg_index: u32, count: u32) -> Vec<u32> {
    let mut out = alloc::vec![0u32; count as usize];
    for (reg, value) in NONZERO.iter().copied() {
        if reg >= reg_index && reg < reg_index + count {
            out[(reg - reg_index) as usize] = value;
        }
    }
    out
}

/// Build the CP preamble `gfx_v11_0_cp_gfx_start` writes to the GFX ring.
///
/// `tile_steering_override` is `adev->gfx.config.pa_sc_tile_steering_override`,
/// which comes from GC configuration rather than the clear-state table, and
/// `gc_base_idx1` is `AmdGpu::gc_base_1()` — see
/// [`PA_SC_TILE_STEERING_OVERRIDE_REL`] for why that base is needed here and
/// nowhere else in this function.
///
/// `None` when the resolved register does not land in the context-register
/// aperture at all, which would mean the base is wrong rather than the table.
///
/// The ordering is the substance: BEGIN_CLEAR_STATE brackets the context
/// writes so the hardware records them as state 0, the per-extent
/// `SET_CONTEXT_REG` packets fill it, the tile-steering override lands inside
/// the bracket, END_CLEAR_STATE closes it, and only then does `CLEAR_STATE`
/// load state 0 into the active context. Emitting `CLEAR_STATE` before the
/// bracket closed would load whatever the context held before.
pub fn build_preamble(gc_base_idx1: u32, tile_steering_override: u32) -> Option<Vec<u32>> {
    let steering_index = gc_base_idx1.checked_add(PA_SC_TILE_STEERING_OVERRIDE_REL)?;
    let steering_offset = steering_index.checked_sub(SET_CONTEXT_REG_START)?;
    use crate::amdgpu_pm4_defs as pm4;
    let mut dws: Vec<u32> = Vec::with_capacity(CSB_DWORDS as usize);

    dws.push(pm4::packet3(pm4::PACKET3_PREAMBLE_CNTL, 0));
    dws.push(PREAMBLE_BEGIN_CLEAR_STATE);

    dws.push(pm4::packet3(pm4::PACKET3_CONTEXT_CONTROL, 1));
    dws.push(CONTEXT_CONTROL_LOAD_ENABLE);
    dws.push(CONTEXT_CONTROL_LOAD_ENABLE);

    for (reg_index, count) in EXTENTS.iter().copied() {
        // `PACKET3(PACKET3_SET_CONTEXT_REG, reg_count)` — the count field is
        // the register count, so the packet carries `count + 1` dwords: the
        // relative index then the values.
        dws.push(pm4::packet3(pm4::PACKET3_SET_CONTEXT_REG, count));
        dws.push(reg_index - SET_CONTEXT_REG_START);
        dws.extend_from_slice(&extent_values(reg_index, count));
    }

    dws.push(pm4::packet3(pm4::PACKET3_SET_CONTEXT_REG, 1));
    dws.push(steering_offset);
    dws.push(tile_steering_override);

    dws.push(pm4::packet3(pm4::PACKET3_PREAMBLE_CNTL, 0));
    dws.push(PREAMBLE_END_CLEAR_STATE);

    dws.push(pm4::packet3(pm4::PACKET3_CLEAR_STATE, 0));
    dws.push(0);
    Some(dws)
}

/// The two dwords a SECOND graphics ring gets — just `CLEAR_STATE`, to copy
/// state 0 into its own context (`gfx_v11_0_cp_gfx_start`'s tail, for
/// `num_gfx_rings > 1`).
pub fn build_secondary_ring_clear_state() -> Vec<u32> {
    use crate::amdgpu_pm4_defs as pm4;
    alloc::vec![pm4::packet3(pm4::PACKET3_CLEAR_STATE, 0), 0]
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The table's shape, against `gfx11_SECT_CONTEXT_defs` and
    /// `gfx_v11_0_get_csb_size`.
    fn smoke_clearstate_table_shape() -> TestResult {
        // Seven extents, these spans and counts.
        let want: &[(u32, u32)] = &[
            (0xa000, 215),
            (0xa0d8, 272),
            (0xa1f5, 4),
            (0xa1ff, 158),
            (0xa2a0, 2),
            (0xa2a3, 1),
            (0xa2a6, 282),
        ];
        if EXTENTS != want {
            return TestResult::Fail("an extent span or count does not match the header");
        }
        // The spans are not contiguous — extent 1 ends at 0xa0d6 and extent 2
        // starts at 0xa0d8. One long run would write the gaps.
        for pair in EXTENTS.windows(2) {
            let (start, count) = pair[0];
            if start + count > pair[1].0 {
                return TestResult::Fail("extents must not overlap");
            }
        }
        if EXTENTS[0].0 + EXTENTS[0].1 == EXTENTS[1].0 {
            return TestResult::Fail("extents 1 and 2 are expected to have a gap between them");
        }
        let total: u32 = EXTENTS.iter().map(|e| e.1).sum();
        if total != REGISTER_COUNT || total != 934 {
            return TestResult::Fail("the table covers 934 context registers");
        }
        // `gfx_v11_0_get_csb_size`: 2 + 3 + sum(2 + reg_count) + 3 + 2 + 2.
        if CSB_DWORDS != 960 {
            return TestResult::Fail("the clear-state block is 960 dwords");
        }
        // Every non-zero entry has to land inside some extent, or it would be
        // silently dropped when the dense values are built.
        for (reg, value) in NONZERO.iter().copied() {
            if value == 0 {
                return TestResult::Fail("a zero has no business in the sparse table");
            }
            if !EXTENTS
                .iter()
                .any(|(start, count)| reg >= *start && reg < start + count)
            {
                return TestResult::Fail("a non-zero entry falls outside every extent");
            }
        }
        if NONZERO.len() != 78 {
            return TestResult::Fail("78 of the 934 values are non-zero");
        }
        // A handful of values spot-checked against `clearstate_gfx11.h`'s own
        // register-name comments.
        for (reg, value) in [
            (0xa00du32, 0x40004000u32), // PA_SC_SCREEN_SCISSOR_BR
            (0xa01f, 0x00150055),       // DB_RMI_L2_CACHE_CONTROL
            (0xa081, 0x80000000),       // PA_SC_WINDOW_SCISSOR_TL
            (0xa083, 0x0000ffff),       // PA_SC_CLIPRECT_RULE
            (0xa311, 0x00000003),       // PA_SC_BINNER_CNTL_0
        ] {
            if !NONZERO.contains(&(reg, value)) {
                return TestResult::Fail("a spot-checked clear-state value is missing");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/clearstate",
        smoke_clearstate_table_shape
    );

    /// The preamble's packet sequence, against `gfx_v11_0_cp_gfx_start`.
    fn smoke_clearstate_preamble_sequence() -> TestResult {
        use crate::amdgpu_pm4_defs as pm4;
        // GC window 1 chosen so the resolved tile-steering register lands in
        // the context aperture.
        let gc_base_1 = 0xa000u32;
        let dws = match build_preamble(gc_base_1, 0xDEAD_BEEF) {
            Some(d) => d,
            None => return TestResult::Fail("preamble refused a valid base"),
        };
        if dws.len() as u32 != CSB_DWORDS {
            return TestResult::Fail("the preamble is not CSB_DWORDS long");
        }
        // PACKET3_PREAMBLE_CNTL 0x4a with BEGIN_CLEAR_STATE = 2 << 28.
        if dws[0] != pm4::packet3(0x4A, 0) || dws[1] != 2 << 28 {
            return TestResult::Fail("BEGIN_CLEAR_STATE must open the block");
        }
        // PACKET3_CONTEXT_CONTROL 0x28, count 1, both dwords 0x80000000.
        if dws[2] != pm4::packet3(0x28, 1) || dws[3] != 0x8000_0000 || dws[4] != 0x8000_0000 {
            return TestResult::Fail("CONTEXT_CONTROL");
        }
        // First extent: SET_CONTEXT_REG 0x69 with the register count, then the
        // index relative to 0xa000 — which is zero for the first extent.
        if dws[5] != pm4::packet3(0x69, 215) || dws[6] != 0 {
            return TestResult::Fail("the first SET_CONTEXT_REG packet");
        }
        // PA_SC_SCREEN_SCISSOR_BR is 0xa00d, so index 13 within extent 1, and
        // the values start two dwords after the packet header.
        if dws[7 + 13] != 0x4000_4000 {
            return TestResult::Fail("a non-zero value did not reach its dense position");
        }
        if dws[7] != 0 {
            return TestResult::Fail("DB_RENDER_CONTROL is zero in the clear state");
        }
        // The tail: tile steering, then END_CLEAR_STATE, then CLEAR_STATE.
        let n = dws.len();
        if dws[n - 2] != pm4::packet3(0x12, 0) || dws[n - 1] != 0 {
            return TestResult::Fail("CLEAR_STATE must close the sequence");
        }
        if dws[n - 4] != pm4::packet3(0x4A, 0) || dws[n - 3] != 3 << 28 {
            return TestResult::Fail("END_CLEAR_STATE must precede CLEAR_STATE");
        }
        // The override is written INSIDE the bracket, so it lands in state 0.
        if dws[n - 7] != pm4::packet3(0x69, 1) || dws[n - 5] != 0xDEAD_BEEF {
            return TestResult::Fail("the tile-steering override must be inside the bracket");
        }
        // Its context index is the resolved register minus 0xa000 — not a
        // constant.
        if dws[n - 6] != gc_base_1 + 0x00d7 - 0xa000 {
            return TestResult::Fail("the tile-steering context index must be resolved");
        }
        // A base that puts the register below the context aperture is refused
        // rather than wrapping.
        if build_preamble(0, 0).is_some() {
            return TestResult::Fail("a base outside the context aperture must be refused");
        }
        // The secondary ring gets only CLEAR_STATE.
        let second = build_secondary_ring_clear_state();
        if second.len() != 2 || second[0] != pm4::packet3(0x12, 0) || second[1] != 0 {
            return TestResult::Fail("the secondary ring's clear state");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/clearstate",
        smoke_clearstate_preamble_sequence
    );
}
