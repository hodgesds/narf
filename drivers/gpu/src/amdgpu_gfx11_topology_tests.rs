use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// The Phoenix GC table: 1 SE, 2 SA/SE, 6 CU/SA (3 WGPs), 2 RB/SE.
pub(crate) fn phoenix_gc() -> GcInfo {
    GcInfo {
        version_major: 1,
        version_minor: 0,
        num_se: 1,
        num_sa_per_se: 2,
        num_cu_per_sa: 6,
        num_rb_per_se: 2,
        num_tccs: 8,
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
    Limits::from_gc(&phoenix_gc()).unwrap()
}

fn gfx11_topology_full_phoenix_matches_linux() -> TestResult {
    let raw = Sample {
        gb_addr_config: GB_ADDR,
        ..Sample::default()
    };
    let t = match derive(limits(), &raw) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("unharvested Phoenix refused"),
    };
    // Linux on a full Phoenix: 12 CUs, 0x3f per SA, every CU always-on,
    // ao mask 0x3f | 0x3f<<8, 1 RB per SA (2/2) packed into 0x3.
    if t.active_cus != 12
        || t.cu_bitmap != [[0x3f, 0x3f, 0, 0], [0; 4], [0; 4], [0; 4]]
        || t.ao_cu_bitmap != t.cu_bitmap
        || t.ao_cu_mask != 0x3f3f
        || t.enabled_rb_mask != 0x3
        || t.tcc_disabled_mask != 0
        || t.rev_id != 0
        || t.gb_addr_config != GB_ADDR
    {
        return TestResult::Fail("full Phoenix topology differs from Linux derivation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_full_phoenix_matches_linux
);

fn gfx11_topology_applies_fuse_and_user_harvesting() -> TestResult {
    let mut raw = Sample {
        strap0: 0x0200_0000 | 0x1234,
        gb_addr_config: GB_ADDR,
        ..Sample::default()
    };
    // SH1: fused-off WGP2 (CC INACTIVE_WGPS bit 2). SH0: user-disabled
    // WGP0 (GC_USER bit 0). Bits above max_cu_per_sh/2 are ignored.
    // Full Phoenix is 12 CUs (2 SA x 6); SH0 loses WGP0 (2 CUs, 0x3c)
    // and SH1 loses WGP2 (2 CUs, 0x0f), so 12 - 2 - 2 = 8. Linux's
    // gfx_v11_0_get_cu_info sums the per-(SE,SH) CU-bitmap popcounts
    // into cu_info->number, so active_cus is that same sum.
    raw.wgp_disable[0][1] = 1 << (16 + 2);
    raw.wgp_disable[0][0] = (1 << 16) | (1 << (16 + 9));
    // RB0 disabled in the global BACKEND_DISABLE field (bits[31:4]).
    raw.rb_disable[0][0] = 1 << 4;
    // TCC 3 and HI_TCC 0: 0x8 | 1 << 16.
    raw.tcc_disable = (1 << (16 + 3)) | (1 << 8);
    let t = derive(limits(), &raw).unwrap();
    if t.active_cus != 8
        || t.cu_bitmap[0][0] != 0x3c
        || t.cu_bitmap[0][1] != 0x0f
        || t.cu_bitmap[1][0] != 0
        || t.ao_cu_bitmap[0][1] != 0x0f
        // 0x3c | 0x0f<<8
        || t.ao_cu_mask != 0x0f3c
        || t.enabled_rb_mask != 0x2
        || t.tcc_disabled_mask != 0x1_0008
        || t.rev_id != 2
    {
        return TestResult::Fail("harvesting not applied as gfx_v11_0_get_cu_info/setup_rb do");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_applies_fuse_and_user_harvesting
);

fn gfx11_topology_folds_ses_4_to_7_into_columns_2_and_3() -> TestResult {
    let gc = GcInfo {
        num_se: 5,
        num_sa_per_se: 2,
        num_cu_per_sa: 2,
        num_rb_per_se: 2,
        ..phoenix_gc()
    };
    let limits = Limits::from_gc(&gc).unwrap();
    let raw = Sample {
        gb_addr_config: GB_ADDR,
        ..Sample::default()
    };
    let t = derive(limits, &raw).unwrap();
    // 5 SEs x 2 SH x 2 CUs; SE4/SH0 lands in bitmap[0][2], SE4/SH1 in
    // bitmap[0][3]; 1 RB per SA across 10 SAs.
    if t.active_cus != 20
        || t.cu_bitmap[0][0] != 0x3
        || t.cu_bitmap[0][2] != 0x3
        || t.cu_bitmap[0][3] != 0x3
        || t.cu_bitmap[1][0] != 0x3
        || t.enabled_rb_mask != 0x3ff
    {
        return TestResult::Fail("SE 4-7 fold differs from gfx_v11_0_get_cu_info");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_folds_ses_4_to_7_into_columns_2_and_3
);

fn gfx11_topology_refuses_unposted_or_impossible_inputs() -> TestResult {
    let mut raw = Sample::default();
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("zero GB_ADDR_CONFIG accepted");
    }
    raw.gb_addr_config = GB_ADDR | (1 << 3);
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("non-256B pipe interleave accepted");
    }
    raw.gb_addr_config = GB_ADDR;
    raw.wgp_disable = [[0xffff_0000; 2]; 8];
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("zero active CUs accepted");
    }
    raw.wgp_disable = [[0; 2]; 8];
    raw.disabled_sa = 0x3;
    if derive(limits(), &raw) != Err(Error::Invalid) {
        return TestResult::Fail("zero active SAs accepted");
    }
    for gc in [
        GcInfo {
            num_se: 9,
            ..phoenix_gc()
        },
        GcInfo {
            num_sa_per_se: 3,
            ..phoenix_gc()
        },
        GcInfo {
            num_cu_per_sa: 9,
            ..phoenix_gc()
        },
        GcInfo {
            num_rb_per_se: 3,
            ..phoenix_gc()
        },
    ] {
        if Limits::from_gc(&gc).is_ok() {
            return TestResult::Fail("GC table outside the GFX11 DRM layout accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_refuses_unposted_or_impossible_inputs
);

/// GC base segments 0x1260 / 0xA000 and NBIO segment 2 at 0xD20, in bytes.
fn layout() -> Layout {
    Layout {
        gc: [0x1260 * 4, 0xa000 * 4],
        nbio: 0xd20 * 4,
    }
}
struct Fake {
    index: u32,
    writes: Vec<u32>,
    dead: bool,
    disabled_sa: u16,
}
impl Io for Fake {
    fn read(&mut self, a: u64) -> u32 {
        let se = (self.index >> 16) & 0xff;
        let sh = (self.index >> 8) & 0xff;
        match a / 4 {
            0x2249 => u32::from(self.disabled_sa) << 8,
            0xfb92 => 0,
            // RX 6750 XT under Linux amdgpu_regs2: selections are not echoed.
            0xc200 => 0,
            0x0d31 => 0x0200_0000,                   // NBIO 0xD20+0x11
            0x263e => GB_ADDR,                       // the Mesa-visible 0x263e
            0x263d => 0,                             // CC_RB_BACKEND_DISABLE 0x1260+0x13dd
            0xfb94 => (1 << 4) * u32::from(sh == 1), // GC_USER_RB 0xA000+0x5b94
            0x226f => {
                if self.dead {
                    u32::MAX
                } else {
                    (1 << (16 + se)) * u32::from(sh == 1) // CC_GC_SHADER_ARRAY_CONFIG
                }
            }
            0xfb90 => 0,              // GC_USER_SHADER_ARRAY_CONFIG 0xA000+0x5b90
            0xf006 => 1 << (16 + 11), // CGTS_TCC_DISABLE 0xA000+0x5006
            0xfb96 => 0,              // CGTS_USER_TCC_DISABLE 0xA000+0x5b96
            _ => panic!("GC11 topology read an unexpected register"),
        }
    }
    fn write(&mut self, a: u64, v: u32) {
        assert_eq!(a / 4, 0xc200, "only GRBM_GFX_INDEX may be written");
        self.writes.push(v);
        self.index = v;
    }
}

fn gfx11_topology_register_model_selects_each_array_and_restores_broadcast() -> TestResult {
    let mut f = Fake {
        index: BROADCAST,
        writes: Vec::new(),
        dead: false,
        disabled_sa: 0,
    };
    let raw = sample(&mut f, &layout(), limits(), RCC_DEV0_EPF0_STRAP0).unwrap();
    let t = derive(limits(), &raw).unwrap();
    let selectors = [0x4000_0000, 0x4000_0100, BROADCAST];
    // SH1 loses WGP0 (bitmap 0x3c, 4 CUs); the GC_USER_RB value staged on
    // SH1 is ignored — Linux reads the RB mask once, from SE0/SH0.
    if f.writes != selectors
        || f.index != BROADCAST
        || t.rev_id != 2
        || t.enabled_rb_mask != 0x3
        || t.cu_bitmap[0][0] != 0x3f
        || t.cu_bitmap[0][1] != 0x3c
        || t.active_cus != 10
        || t.tcc_disabled_mask != 1 << 11
    {
        return TestResult::Fail("GC11 selector sequence, offsets or derivation");
    }
    let mut dead = Fake {
        index: BROADCAST,
        writes: Vec::new(),
        dead: true,
        disabled_sa: 0,
    };
    if sample(&mut dead, &layout(), limits(), RCC_DEV0_EPF0_STRAP0) != Err(Error::DeviceGone)
        || dead.index != BROADCAST
    {
        return TestResult::Fail("device loss left the GRBM selector changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_register_model_selects_each_array_and_restores_broadcast
);

fn gfx11_topology_skips_whole_disabled_shader_arrays() -> TestResult {
    let mut f = Fake {
        index: BROADCAST,
        writes: Vec::new(),
        dead: false,
        disabled_sa: 2,
    };
    let raw = sample(&mut f, &layout(), limits(), RCC_DEV0_EPF0_STRAP0).unwrap();
    let t = derive(limits(), &raw).unwrap();
    if f.writes.contains(&0x4000_0100)
        || f.index != BROADCAST
        || t.cu_bitmap[0][1] != 0
        || t.enabled_rb_mask & 0x2 != 0
        || t.active_cus != 6
    {
        return TestResult::Fail("Phoenix sampled or exposed a disabled shader array");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_skips_whole_disabled_shader_arrays
);

fn gfx11_topology_revision_does_not_require_gc_harvest() -> TestResult {
    let mut f = Fake {
        index: BROADCAST,
        writes: Vec::new(),
        dead: true,
        disabled_sa: 0,
    };
    if sample_revision(&mut f, &layout(), RCC_DEV0_EPF0_STRAP0) != Ok(2)
        || !f.writes.is_empty()
        || sample(&mut f, &layout(), limits(), RCC_DEV0_EPF0_STRAP0) != Err(Error::DeviceGone)
        || f.index != BROADCAST
    {
        return TestResult::Fail("NBIO revision coupled to GC availability or changed selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_revision_does_not_require_gc_harvest
);

fn gfx11_topology_layout_resolves_only_phoenix() -> TestResult {
    use crate::amdgpu_discovery as d;
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::PHOENIX1,
        )
        .unwrap();
        let template = gpu.ip_blocks[0];
        let ip = |id, v: (u8, u8, u8), base: u32| {
            let mut block = template;
            block.hw_id = id;
            (block.major, block.minor, block.revision) = v;
            block.num_bases = 1;
            block.base_addrs[0] = base;
            block
        };
        let mut nbif = ip(d::HW_ID_NBIF, (7, 7, 1), 0);
        nbif.num_bases = 3;
        nbif.base_addrs[2] = 0x3000;
        let mut gc = ip(d::HW_ID_GC, (11, 0, 1), 0x4000);
        gc.num_bases = 2;
        gc.base_addrs[1] = 0x8000;
        gpu.ip_blocks = vec![gc, nbif];
        gpu
    };
    let layout = match Layout::resolve_phoenix(&gpu()) {
        Ok(layout) => layout,
        Err(_) => return TestResult::Fail("Phoenix topology layout refused"),
    };
    if layout.gc != [0x4000 * 4, 0x8000 * 4] || layout.nbio != 0x3000 * 4 {
        return TestResult::Fail("Phoenix topology banks");
    }
    let mut strix = gpu();
    strix.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::STRIX_POINT,
    )
    .unwrap();
    let mut gc110 = gpu();
    gc110.ip_blocks[0].revision = 0;
    let mut nbif2 = gpu();
    nbif2.ip_blocks[1].num_bases = 2;
    for (bad, why) in [
        (strix, "topology layout admitted Strix"),
        (gc110, "topology layout admitted GC 11.0.0"),
        (nbif2, "topology layout admitted a window-0-only NBIF"),
    ] {
        if Layout::resolve_phoenix(&bad).is_ok() {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/phoenix",
    gfx11_topology_layout_resolves_only_phoenix
);

/// Strix Point resolves its own topology layout: GC 11.5.0 banks, the
/// NBIO bank bounded by the 7.11 strap dword (0x0021), and the strap
/// dword itself from the discovered NBIO version — 0x0015 on 7.11.0,
/// 0x0021 on 7.11.5. A Phoenix DID, GC 11.0.1, a window-0-only NBIF,
/// and an NBIO 7.11.6 are all refused.
fn gfx11_topology_layout_resolves_strix() -> TestResult {
    use crate::amdgpu_discovery as d;
    let gpu = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        gpu.chip = crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::STRIX_POINT,
        )
        .unwrap();
        let template = gpu.ip_blocks[0];
        let ip = |id, v: (u8, u8, u8), base: u32| {
            let mut block = template;
            block.hw_id = id;
            (block.major, block.minor, block.revision) = v;
            block.num_bases = 1;
            block.base_addrs[0] = base;
            block
        };
        let mut nbif = ip(d::HW_ID_NBIF, (7, 11, 0), 0);
        nbif.num_bases = 3;
        nbif.base_addrs[2] = 0x3000;
        let mut gc = ip(d::HW_ID_GC, (11, 5, 0), 0x4000);
        gc.num_bases = 2;
        gc.base_addrs[1] = 0x8000;
        gpu.ip_blocks = vec![gc, nbif];
        gpu
    };
    let layout = match Layout::resolve_strix(&gpu()) {
        Ok(layout) => layout,
        Err(_) => return TestResult::Fail("Strix topology layout refused"),
    };
    if layout.gc != [0x4000 * 4, 0x8000 * 4] || layout.nbio != 0x3000 * 4 {
        return TestResult::Fail("Strix topology banks");
    }
    if strap_dword(&gpu()) != Ok(0x0015) {
        return TestResult::Fail("NBIO 7.11.0 strap dword");
    }
    let mut nbif5 = gpu();
    nbif5.ip_blocks[1].revision = 5;
    if strap_dword(&nbif5) != Ok(0x0021) {
        return TestResult::Fail("NBIO 7.11.5 strap dword");
    }
    if Layout::resolve_strix(&nbif5).is_err() {
        return TestResult::Fail("Strix topology layout refused NBIO 7.11.5");
    }
    let mut phoenix = gpu();
    phoenix.chip = crate::amdgpu::__test_chip_info_for_pci_id(
        crate::amdgpu::AMD_VENDOR,
        crate::amdgpu::PHOENIX1,
    )
    .unwrap();
    let mut gc110 = gpu();
    gc110.ip_blocks[0].revision = 1;
    gc110.ip_blocks[0].minor = 0;
    let mut nbif2 = gpu();
    nbif2.ip_blocks[1].num_bases = 2;
    let mut nbif716 = gpu();
    nbif716.ip_blocks[1].revision = 6;
    // The strap resolver fails closed on the unlisted NBIO version too.
    if strap_dword(&nbif716).is_ok() {
        return TestResult::Fail("strap resolver admitted NBIO 7.11.6");
    }
    for (bad, why) in [
        (phoenix, "topology layout admitted Phoenix"),
        (gc110, "topology layout admitted GC 11.0.1"),
        (nbif2, "topology layout admitted a window-0-only NBIF"),
        (nbif716, "topology layout admitted NBIO 7.11.6"),
    ] {
        if Layout::resolve_strix(&bad).is_ok() {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/strix",
    gfx11_topology_layout_resolves_strix
);
