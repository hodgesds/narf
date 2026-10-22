//! Bounded GC12.0.0/12.0.1 wave32 compute proof, on the retained VMID0 test pages.
//! Shader bytes are independently assembled by tests/gfx12_shader/check.sh.
//! PM4 logical SH offsets follow Mesa 26.0 ac_cmdbuf.c/si_compute.c;
//! these are NOT the physical GC12 MMIO register offsets.
use super::amdgpu_gfx12_queue::Error;
use crate::amdgpu_pm4::Pm4Builder;

pub const LANES: u32 = 32;
pub(crate) const IB_OFFSET: u64 = 256;
pub(crate) const OUTPUT_OFFSET: u64 = 4096 + 64;
pub(crate) const POISON: u32 = 0xdead_c0de;
pub(crate) const SALTS: [u32; 2] = [0x9070_1201, 0x1201_9070];
// v_lshlrev v0,2,v0; VALU dependency; v_xor v1,s2,v0;
// global_store_b32 v0,v1,s[0:1] scope:SYS; wait stores; endpgm.
pub const PROGRAM: [u32; 8] = [
    0x3000_0082,
    0xbf87_0001,
    0x3a02_0002,
    0xee06_8000,
    0x008c_0000,
    0,
    0xbfc1_0000,
    0xbfb0_0000,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub lanes: u32,
    /// Each queue's real job fence, independently checked with its EOP IV.
    pub fences: [u32; 2],
    pub msi_verified: bool,
}
pub(crate) fn expected(lane: u32, pipe: usize) -> u32 {
    SALTS[pipe] ^ (lane << 2)
}

/// A fixed 1x1x1 grid, with one 32-thread wave and no LDS/scratch or user
/// resources. Both addresses belong to the caller's two-page VMID0 aperture.
pub(crate) fn ib(code: u64, output: u64, engines: u8, salt: u32) -> Result<[u32; 256], Error> {
    if code & 255 != 0
        || code >= 1 << 48
        || output & 3 != 0
        || output
            .checked_add(u64::from(LANES) * 4)
            .is_none_or(|v| v > 1 << 48)
        || !(1..=8).contains(&engines)
    {
        return Err(Error::Invalid);
    }
    let mut words = [0; 256];
    let mut n = 0;
    // SET_SH_REG's register space starts at logical byte address 0xb000.
    let mut sh = |reg: u32, values: &[u32]| {
        words[n] = 0xc000_7602 | ((values.len() as u32) << 16);
        words[n + 1] = (reg - 0xb000) / 4;
        words[n + 2..n + 2 + values.len()].copy_from_slice(values);
        n += values.len() + 2;
    };
    sh(0xb810, &[0, 0, 0]); // start XYZ (also forced to zero by dispatch)
                            // GFX12's full-thread count occupies bits 0..12.
    sh(0xb81c, &[LANES, 1, 1]);
    sh(
        0xb82c,
        &[0, (code >> 8) as u32, (code >> 40) as u32, 0, 0, 0, 0],
    );
    // Two VGPRs round to the minimum allocation; three user SGPRs, X only.
    sh(0xb848, &[0x6000_0000, 3 << 1]); // WGP_MODE | MEM_ORDERED; no PRIV
    sh(0xb854, &[0]); // one threadgroup per CU, no artificial wave limit
    sh(0xb860, &[0]); // no scratch
    for (se, reg) in [
        0xb858, 0xb85c, 0xb864, 0xb868, 0xb8ac, 0xb8b0, 0xb8b4, 0xb8b8,
    ]
    .into_iter()
    .enumerate()
    {
        // SPI applies harvested CU masks, as Mesa's default spi_cu_en does.
        sh(
            reg,
            &[if se < usize::from(engines) {
                u32::MAX
            } else {
                0
            }],
        );
    }
    sh(0xb88c, &[0]); // Neither supported RDNA4 die has SE8
    sh(0xb890, &[0; 4]); // accumulators
    sh(0xb8a0, &[0]); // RSRC3: no shared VGPRs
    sh(0xb8bc, &[0]); // no 2D interleave
    sh(0xb9f4, &[0]); // no dispatch tunneling
    sh(0xb900, &[output as u32, (output >> 32) as u32, salt]);
    words[n..n + 5].copy_from_slice(&[0xc003_1502, 1, 1, 1, 0x8045]);
    n += 5; // shader enable, force start 000, order mode and wave32
    words[n] = 0xc000_1000 | ((256 - n - 2) as u32) << 16;
    Ok(words)
}

pub(crate) fn ring(ib: u64, fence: u64, seq: u32, graphics: bool) -> Result<[u32; 256], Error> {
    let mut words = [0; 256];
    let mut b = Pm4Builder::new(&mut words);
    let build = (|| {
        if graphics {
            b.context_control(0x8101_8003, 0)?;
        }
        b.acquire_mem_gfx11(0, 0, 0x00ff_ffff_ffff_ffff, 10, 0xc3b1)?;
        if graphics {
            b.indirect_buffer(ib, 256, 0)?;
        } else {
            b.indirect_buffer_valid(ib, 256, 0)?;
        }
        b.release_mem_fence(fence, u64::from(seq), false, true)?;
        let used = b.words().len();
        b.nop(256 - used - 1)
    })();
    build.map_err(|_| Error::Invalid)?;
    Ok(words)
}
