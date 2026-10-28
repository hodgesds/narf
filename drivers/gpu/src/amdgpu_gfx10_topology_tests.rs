use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The Navi22 GC table (discovery v1: 2 SE, 2 SA/SE, 5+0 WGPs/SA, 4 RB/SE).
pub(crate) fn navi22_gc() -> GcInfo {
    GcInfo {
        version_major: 1,
        version_minor: 0,
        num_se: 2,
        num_sa_per_se: 2,
        num_cu_per_sa: 10,
        num_rb_per_se: 4,
        num_tccs: 12,
        num_gprs: 1024,
        num_max_gs_thds: 32,
        gs_table_depth: 32,
        gsprim_buff_depth: 1792,
        double_offchip_lds_buffer: 1,
        wave_size: 32,
        max_waves_per_simd: 16,
        ..GcInfo::default()
    }
}
/// A plausible posted GB_ADDR_CONFIG (8 pipes, 256 B interleave, 8 packers).
pub(crate) const GB_ADDR: u32 = 0x0000_0343;

fn limits() -> Limits {
    Limits::from_gc(&navi22_gc()).unwrap()
}

fn gfx10_topology_full_navi22_matches_linux() -> TestResult {
    let raw = Sample {
        gb_addr_config: GB_ADDR,
        ..Sample::default()
    };
    let t = match derive(limits(), &raw) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("unharvested Navi22 refused"),
    };
    // Linux on a full Navi22: 40 CUs, 0x3ff per SA, every CU always-on,
    // ao mask 0x3ff | 0x3ff<<8 | 0x3ff<<16 | 0x3ff<<24 truncated to u32,
    // 2 RBs per SA (4/2) packed into 0xff.
    let sa = [0x3ff, 0x3ff, 0, 0];
    if t.active_cus != 40
        || t.cu_bitmap != [sa, sa, [0; 4], [0; 4]]
        || t.ao_cu_bitmap != t.cu_bitmap
        || t.ao_cu_mask != 0xffff_ffff
        || t.enabled_rb_mask != 0xff
        || t.tcc_disabled_mask != 0
        || t.rev_id != 0
        || t.gb_addr_config != GB_ADDR
    {
        return TestResult::Fail("full Navi22 topology differs from Linux derivation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    gfx10_topology_full_navi22_matches_linux
);

fn gfx10_topology_applies_fuse_and_user_harvesting() -> TestResult {
    let mut raw = Sample {
        strap0: 0x0100_0000 | 0x1234,
        gb_addr_config: GB_ADDR,
        ..Sample::default()
    };
    // SE1/SA1: fused-off WGP4 (CC INACTIVE_WGPS bit 4). SE0/SA0: user-disabled
    // WGP0 (GC_USER bit 0). Bits above max_cu_per_sh/2 are ignored.
    raw.wgp_disable[1][1] = 1 << (16 + 4);
    raw.wgp_disable[0][0] = (1 << 16) | (1 << (16 + 9));
    // SE1/SA0 RB0 disabled: bitmap position (1*2+0)*2 = bit 4.
    raw.rb_disable[1][0] = 1 << 16;
    // TCC 3 and HI_TCC 0: 0x8 | 1 << 16.
    raw.tcc_disable = (1 << (16 + 3)) | (1 << 8);
    let t = derive(limits(), &raw).unwrap();
    if t.active_cus != 36
        || t.cu_bitmap[0][0] != 0x3fc
        || t.cu_bitmap[1][1] != 0x0ff
        || t.cu_bitmap[0][1] != 0x3ff
        || t.ao_cu_bitmap[1][1] != 0x0ff
        // 0x3fc | 0x3ff<<8 | 0x3ff<<16 | 0x0ff<<24
        || t.ao_cu_mask != 0x3fc | (0x3ff << 8) | (0x3ff << 16) | (0xff << 24)
        || t.enabled_rb_mask != 0xef
        || t.tcc_disabled_mask != 0x1_0008
        || t.rev_id != 1
    {
        return TestResult::Fail("harvesting not applied as gfx_v10_0_get_cu_info/setup_rb do");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    gfx10_topology_applies_fuse_and_user_harvesting
);

fn gfx10_topology_refuses_unposted_or_impossible_inputs() -> TestResult {
    let mut raw = Sample::default();
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("zero GB_ADDR_CONFIG accepted");
    }
    raw.gb_addr_config = GB_ADDR | (1 << 3);
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("non-256B pipe interleave accepted");
    }
    raw.gb_addr_config = GB_ADDR;
    raw.wgp_disable = [[0xffff_0000; 2]; 4];
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("zero active CUs accepted");
    }
    for gc in [
        GcInfo {
            num_se: 5,
            ..navi22_gc()
        },
        GcInfo {
            num_sa_per_se: 3,
            ..navi22_gc()
        },
        GcInfo {
            num_cu_per_sa: 9,
            ..navi22_gc()
        },
        GcInfo {
            num_rb_per_se: 3,
            ..navi22_gc()
        },
    ] {
        if Limits::from_gc(&gc).is_ok() {
            return TestResult::Fail("GC table outside the GFX10 DRM layout accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    gfx10_topology_refuses_unposted_or_impossible_inputs
);

/// GC base segments 0x1260 / 0xA000 and NBIO segment 2 at 0xD20, in bytes.
fn layout() -> Layout {
    Layout {
        profile: &crate::amdgpu_rdna2::NAVI22,
        sdma_high: None,
        gc: [0x1260 * 4, 0xa000 * 4],
        nbio: 0xd20 * 4,
        hdp: 0xf20 * 4,
        oss: 0x10a0 * 4,
    }
}
struct Fake {
    index: u32,
    index_extra: u32,
    writes: Vec<u32>,
    dead: bool,
    disabled_sa: u8,
}
impl Io for Fake {
    fn read(&mut self, a: u64) -> u32 {
        let se = (self.index >> 16) & 0xff;
        let sh = (self.index >> 8) & 0xff;
        match a / 4 {
            0x2249 => u32::from(self.disabled_sa) << 8,
            0x224a => 0,
            0xc200 => self.index | self.index_extra, // GRBM_GFX_INDEX
            0x0d31 => 0x0200_0000,                   // NBIO 0xD20+0x11
            0x263e => GB_ADDR,                       // the Mesa-visible 0x263e
            0x263d => (se * 2 + sh) << 16 & 0x10000, // CC_RB: RB0 off on odd SAs
            0x26df => 0,                             // GC_USER_RB 0x1260+0x147f
            0x226f => {
                if self.dead {
                    u32::MAX
                } else {
                    (1 << (16 + se)) * u32::from(sh == 1) // CC_GC_SHADER_ARRAY_CONFIG
                }
            }
            0x2270 => 0,              // GC_USER_SHADER_ARRAY_CONFIG
            0xf006 => 1 << (16 + 11), // CGTS_TCC_DISABLE 0xA000+0x5006
            0xf007 => 0,              // CGTS_USER_TCC_DISABLE
            _ => panic!("GC10 topology read an unexpected register"),
        }
    }
    fn write(&mut self, a: u64, v: u32) {
        assert_eq!(a / 4, 0xc200, "only GRBM_GFX_INDEX may be written");
        self.writes.push(v);
        self.index = v;
    }
}

fn gfx10_topology_register_model_selects_each_array_and_restores_broadcast() -> TestResult {
    let mut f = Fake {
        index: BROADCAST,
        index_extra: 0,
        writes: Vec::new(),
        dead: false,
        disabled_sa: 0,
    };
    let raw = sample(&mut f, &layout(), limits()).unwrap();
    let t = derive(limits(), &raw).unwrap();
    let selectors = [
        0x4000_0000,
        0x4000_0100,
        0x4001_0000,
        0x4001_0100,
        BROADCAST,
    ];
    // Odd SAs lose RB0 (bits 2 and 6) and WGP<se> (SE0/SA1: WGP0, SE1/SA1: WGP1).
    if f.writes != selectors
        || f.index != BROADCAST
        || t.rev_id != 2
        || t.enabled_rb_mask != 0xff & !(1 << 2) & !(1 << 6)
        || t.cu_bitmap[0][1] != 0x3fc
        || t.cu_bitmap[1][1] != 0x3f3
        || t.active_cus != 36
        || t.tcc_disabled_mask != 1 << 11
    {
        return TestResult::Fail("GC10 selector sequence, offsets or derivation");
    }
    let mut dead = Fake {
        index: BROADCAST,
        index_extra: 0,
        writes: Vec::new(),
        dead: true,
        disabled_sa: 0,
    };
    if sample(&mut dead, &layout(), limits()) != Err(Error::DeviceGone) || dead.index != BROADCAST {
        return TestResult::Fail("device loss left the GRBM selector changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    gfx10_topology_register_model_selects_each_array_and_restores_broadcast
);

fn rdna2_navi21_skips_whole_disabled_shader_arrays() -> TestResult {
    let mut f = Fake {
        index: BROADCAST,
        index_extra: 0,
        writes: Vec::new(),
        dead: false,
        disabled_sa: 2,
    };
    let mut layout = layout();
    layout.profile = &crate::amdgpu_rdna2::NAVI21;
    let raw = sample(&mut f, &layout, limits()).unwrap();
    let t = derive(limits(), &raw).unwrap();
    if f.writes.contains(&0x4000_0100)
        || f.index != BROADCAST
        || t.cu_bitmap[0][1] != 0
        || t.enabled_rb_mask & 0xc != 0
    {
        return TestResult::Fail("Navi21 sampled or exposed a disabled shader array");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_navi21_skips_whole_disabled_shader_arrays
);

fn gfx10_topology_ignores_reserved_index_bits_but_checks_selector() -> TestResult {
    let mut f = Fake {
        index: BROADCAST,
        index_extra: 0x1f00_0000,
        writes: Vec::new(),
        dead: false,
        disabled_sa: 0,
    };
    if sample(&mut f, &layout(), limits()).is_err() || f.index != BROADCAST {
        return TestResult::Fail("reserved selector bits rejected valid topology");
    }
    f.index_extra = 1 << 8;
    if sample(&mut f, &layout(), limits()) != Err(Error::Readback) {
        return TestResult::Fail("a stuck SA selector was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    gfx10_topology_ignores_reserved_index_bits_but_checks_selector
);
