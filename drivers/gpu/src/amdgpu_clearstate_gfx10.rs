//! GFX10 clear-state block (Linux `clearstate_gfx10.h`, `gfx10_cs_data`) and
//! the CSB stream built by `gfx_v10_0_get_csb_buffer` / `gfx_v10_0_cp_gfx_start`.
//! Stored sparsely like the GFX11 table in `amdgpu_clearstate.rs`: the extents
//! pin every span and count, every unlisted register in a span is zero, and a
//! dense-table hash pins the transcription against the header.
use crate::amdgpu_pm4_defs::{
    packet3, PACKET3_CLEAR_STATE, PACKET3_CONTEXT_CONTROL, PACKET3_PREAMBLE_CNTL,
    PACKET3_SET_CONTEXT_REG,
};
/// `PACKET3_SET_CONTEXT_REG_START` (`nvd.h`).
pub const SET_CONTEXT_REG_START: u32 = 0xa000;
/// `PACKET3_PREAMBLE_BEGIN_CLEAR_STATE` / `_END_CLEAR_STATE` (`nvd.h`).
pub const PREAMBLE_BEGIN_CLEAR_STATE: u32 = 2 << 28;
pub const PREAMBLE_END_CLEAR_STATE: u32 = 3 << 28;
/// `gfx10_SECT_CONTEXT_defs`: first context register and register count.
pub const EXTENTS: &[(u32, u32)] = &[
    (0xa000, 215),
    (0xa0d8, 272),
    (0xa1f5, 4),
    (0xa1ff, 158),
    (0xa2a0, 2),
    (0xa2a3, 1),
    (0xa2a5, 66),
    (0xa2f5, 203),
];
/// Non-zero `gfx10_SECT_CONTEXT_def_*` values with the header register names.
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
    (0xa100, 0xffffffff), // VGT_MAX_VTX_INDX
    (0xa104, 0x00550055), // CB_RMI_GL2_CACHE_CONTROL
    (0xa10c, 0x01000000), // DB_STENCILREFMASK
    (0xa10d, 0x01000000), // DB_STENCILREFMASK_BF
    (0xa1b6, 0x00000002), // SPI_PS_IN_CONTROL
    (0xa204, 0x00090000), // PA_CL_CLIP_CNTL
    (0xa205, 0x00000004), // PA_SU_SC_MODE_CNTL
    (0xa295, 0x00000100), // VGT_GS_PER_ES
    (0xa296, 0x00000080), // VGT_ES_PER_GS
    (0xa297, 0x00000002), // VGT_GS_PER_VS
    (0xa2aa, 0x000000ff), // IA_MULTI_VGT_PARAM
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
    (0xa316, 0x0000001e), // VGT_VERTEX_REUSE_BLOCK_CNTL
    (0xa317, 0x00000020), // VGT_OUT_DEALLOC_CNTL
];
pub const REGISTER_COUNT: u32 = 921;
/// `gfx_v10_0_get_csb_size`: begin(2) + context control(3) + extents +
/// tile steering(3) + end(2) + clear state(2).
pub const CSB_DWORDS: usize = 2 + 3 + (2 * EXTENTS.len() + REGISTER_COUNT as usize) + 3 + 2 + 2;
/// FNV-1a over the dense little-endian table, computed from the Linux header.
pub const DENSE_FNV1A: u64 = 0x9ab8_799f_b2c4_a559;
/// `mmPA_SC_TILE_STEERING_OVERRIDE`, GC BASE_IDX 1 (gc_10_1_0/gc_10_3_0).
pub const PA_SC_TILE_STEERING_OVERRIDE: u32 = 0x00d7;

fn value(reg: u32) -> u32 {
    NONZERO
        .iter()
        .find(|(r, _)| *r == reg)
        .map_or(0, |(_, v)| *v)
}
/// Every dense table value in extent order.
pub fn dense() -> impl Iterator<Item = u32> {
    EXTENTS
        .iter()
        .flat_map(|&(start, count)| (start..start + count).map(value))
}
/// The CSB both the RLC CSIB and the GFX ring preamble consume. `gc1` is the
/// GC BASE_IDX 1 dword segment; `steering` is
/// `gfx_v10_0_init_pa_sc_tile_steering_override` (0 on GC 10.3).
pub fn csb(gc1: u32, steering: u32) -> Option<[u32; CSB_DWORDS]> {
    let steering_index = gc1
        .checked_add(PA_SC_TILE_STEERING_OVERRIDE)?
        .checked_sub(SET_CONTEXT_REG_START)?;
    if steering_index >= 0x400 {
        return None; // not a context register; the base is wrong
    }
    let mut out = [0; CSB_DWORDS];
    let mut n = 0;
    let mut push = |v| {
        out[n] = v;
        n += 1;
    };
    push(packet3(PACKET3_PREAMBLE_CNTL, 0));
    push(PREAMBLE_BEGIN_CLEAR_STATE);
    push(packet3(PACKET3_CONTEXT_CONTROL, 1));
    push(0x8000_0000);
    push(0x8000_0000);
    for &(start, count) in EXTENTS {
        push(packet3(PACKET3_SET_CONTEXT_REG, count));
        push(start - SET_CONTEXT_REG_START);
        for reg in start..start + count {
            push(value(reg));
        }
    }
    push(packet3(PACKET3_SET_CONTEXT_REG, 1));
    push(steering_index);
    push(steering);
    push(packet3(PACKET3_PREAMBLE_CNTL, 0));
    push(PREAMBLE_END_CLEAR_STATE);
    push(packet3(PACKET3_CLEAR_STATE, 0));
    push(0);
    Some(out)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn clearstate_gfx10_matches_linux_table() -> TestResult {
        if REGISTER_COUNT != EXTENTS.iter().map(|e| e.1).sum::<u32>() || CSB_DWORDS != 949 {
            return TestResult::Fail("gfx10 clear-state extent counts");
        }
        for pair in EXTENTS.windows(2) {
            if pair[0].0 + pair[0].1 > pair[1].0 {
                return TestResult::Fail("overlapping gfx10 extents");
            }
        }
        if NONZERO.len() != 85
            || NONZERO.windows(2).any(|p| p[0].0 >= p[1].0)
            || NONZERO
                .iter()
                .any(|&(r, v)| v == 0 || !EXTENTS.iter().any(|&(s, c)| (s..s + c).contains(&r)))
        {
            return TestResult::Fail("sparse gfx10 entries outside extents");
        }
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for word in dense() {
            for byte in word.to_le_bytes() {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
            }
        }
        if hash != DENSE_FNV1A {
            return TestResult::Fail("gfx10 clear-state transcription");
        }
        let out = csb(0xa000, 0).unwrap();
        if out[..5] != [0xc0004a00, 2 << 28, 0xc0012800, 1 << 31, 1 << 31]
            || out[5] != 0xc0d76900
            || out[6] != 0
            || out[CSB_DWORDS - 7..] != [0xc0016900, 0xd7, 0, 0xc0004a00, 3 << 28, 0xc0001200, 0]
            || csb(0, 0).is_some()
            || csb(0xb000, 0).is_some()
        {
            return TestResult::Fail("gfx10 CSB packet layout");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/cp-navi22",
        clearstate_gfx10_matches_linux_table
    );
}
