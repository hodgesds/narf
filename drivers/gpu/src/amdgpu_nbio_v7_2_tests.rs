use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Every literal is `nbio_7_2_0_offset.h`'s / `_sh_mask.h`'s. The segment-2
/// ones equal `nbio_2_3_offset.h`'s (`mmRCC_DEV0_EPF0_RCC_DOORBELL_APER_EN`
/// 0xc0, `mmINTERRUPT_CNTL` 0xf1, `mmBIF_BX_PF_GPU_HDP_FLUSH_REQ` 0x106, ...),
/// which is why the RDNA2 backends' NBIO writes carry over unchanged.
fn nbio_v7_2_registers_match_the_headers() -> TestResult {
    if (DOORBELL_APER_EN, INTERRUPT_CNTL, INTERRUPT_CNTL2) != (0xc0, 0xf1, 0xf2)
        || (SELFRING_BASE_HIGH, SELFRING_BASE_LOW, SELFRING_CNTL) != (0xf3, 0xf4, 0xf5)
        || (HDP_FLUSH_REQ, HDP_FLUSH_DONE, REMAP_HDP_MEM_FLUSH_CNTL) != (0x106, 0x107, 0x12d)
        || (
            GDC0_SDMA0_DOORBELL_RANGE,
            GDC0_IH_DOORBELL_RANGE,
            GDC0_VCN0_DOORBELL_RANGE,
        ) != (0x4f0af0, 0x4f0af2, 0x4f0af3)
        || (crate::amdgpu_smn::RSMU_INDEX, crate::amdgpu_smn::RSMU_DATA) != (0, 1)
        || (RANGE_OFFSET_MASK, RANGE_SIZE_MASK) != (0xffc, 0x1f0000)
    {
        return TestResult::Fail("NBIO 7.2 register or field differs from nbio_7_2_0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/nbio-v7-2",
    nbio_v7_2_registers_match_the_headers
);

/// `nbio_v7_2_{ih,sdma,vcn}_doorbell_range`: a claim sets OFFSET and SIZE
/// (2 for IH, the caller's for SDMA, 8 for VCN); a release clears only SIZE;
/// every other bit is kept.
fn nbio_v7_2_doorbell_ranges_follow_linux() -> TestResult {
    let other = 0xffe0_f003;
    if ih_doorbell_range(other, Some(0x10)) != other & !0x1f_0ffc | 0x10 << 2 | 2 << 16
        || sdma_doorbell_range(0, Some((0x100, 4))) != 0x100 << 2 | 4 << 16
        || vcn_doorbell_range(0, Some(0x1f)) != 0x1f << 2 | 8 << 16
        || ih_doorbell_range(0x0012_0040, None) != 0x0000_0040
        || sdma_doorbell_range(0xffff_ffff, None) != 0xffe0_ffff
        // Fields are masked, as REG_SET_FIELD masks them.
        || ih_doorbell_range(0, Some(0x400)) != 2 << 16
    {
        return TestResult::Fail("doorbell range encoding differs from nbio_v7_2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/nbio-v7-2",
    nbio_v7_2_doorbell_ranges_follow_linux
);

/// A GPU whose NBIO has Raphael's segments (`dcn315_resource.c`'s
/// NBIO_BASE__INST0_SEG0..5), over `memory`.
fn gpu(memory: &mut Vec<u32>, version: (u8, u8, u8)) -> AmdGpu {
    use crate::amdgpu_discovery as d;
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.regs = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64 * 4,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut nbio = gpu.ip_blocks[0];
    nbio.hw_id = d::HW_ID_NBIF;
    (nbio.major, nbio.minor, nbio.revision) = version;
    nbio.num_bases = 6;
    nbio.base_addrs[..6].copy_from_slice(&[0, 0x14, 0xd20, 0x10400, 0x241_b000, 0x404_0000]);
    gpu.ip_blocks = vec![nbio];
    gpu
}

/// Segment 2 is bounded through the HDP remap, segment 1 through RSMU_DATA,
/// and a segment-3 register's port address is `(base + reg) * 4`. NBIO 7.7
/// and NBIO 2.3 are refused, as is an NBIO without a fourth segment.
fn nbio_v7_2_banks_resolve_raphaels_segments() -> TestResult {
    let mut memory = vec![0u32; 0x1000];
    let banks = Banks::resolve(&gpu(&mut memory, (7, 2, 1)));
    let Some(banks) = banks else {
        return TestResult::Fail("NBIO 7.2 refused");
    };
    if banks.bif != 0xd20 * 4
        || banks.bif(INTERRUPT_CNTL) != (0xd20 + 0xf1) * 4
        || banks.port_address(GDC0_IH_DOORBELL_RANGE) != Some((0x10400 + 0x4f0af2) * 4)
    {
        return TestResult::Fail("NBIO 7.2 segment addresses");
    }
    for version in [(7, 3, 0), (7, 5, 0), (7, 5, 1), (7, 2, 0)] {
        if Banks::resolve(&gpu(&mut memory, version)).is_none() {
            return TestResult::Fail("an nbio_v7_2 version refused");
        }
    }
    for version in [(7, 7, 0), (7, 7, 1), (2, 3, 0), (4, 3, 0)] {
        if Banks::resolve(&gpu(&mut memory, version)).is_some() {
            return TestResult::Fail("an NBIO other than nbio_v7_2 admitted");
        }
    }
    let mut short = gpu(&mut memory, (7, 2, 1));
    short.ip_blocks[0].num_bases = 5;
    if Banks::resolve(&short).is_some() {
        return TestResult::Fail("NBIO without its fifth segment admitted");
    }
    if banks.version != (7, 2, 1)
        || banks.smn_pair() != (0xe * 4, 0xf * 4)
        || banks.port_pair() != (0x14 * 4, (0x14 + 1) * 4)
        || banks.seg5_address(PCIE_CONFIG_CNTL) != Some((0x404_0000 + 0x42_0011) * 4)
    {
        return TestResult::Fail("NBIO 7.2 index pairs or segment 5");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/nbio-v7-2",
    nbio_v7_2_banks_resolve_raphaels_segments
);

/// `amdgpu_device_pcie_port_rreg`/`_wreg`: the port address goes to
/// RSMU_INDEX (segment 1), then the data moves through RSMU_DATA.
fn nbio_v7_2_port_access_goes_through_the_rsmu_pair() -> TestResult {
    let mut memory = vec![0u32; 0x1000];
    let g = gpu(&mut memory, (7, 2, 1));
    let banks = Banks::resolve(&g).unwrap();
    let address = (0x10400 + GDC0_IH_DOORBELL_RANGE) * 4;
    // SAFETY: the mapping is this test's own memory.
    let read = unsafe {
        g.regs.write32((0x14 + 1) * 4, 0x0012_0040);
        banks.port_read(&g.regs, GDC0_IH_DOORBELL_RANGE)
    };
    // SAFETY: as above.
    let (index, data) = unsafe {
        banks
            .port_write(&g.regs, GDC0_IH_DOORBELL_RANGE, 0x0002_0040)
            .unwrap();
        (g.regs.read32(0x14 * 4), g.regs.read32((0x14 + 1) * 4))
    };
    if read != Some(0x0012_0040) || (index, data) != (address, 0x0002_0040) {
        return TestResult::Fail("port access missed the RSMU index/data pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/nbio-v7-2",
    nbio_v7_2_port_access_goes_through_the_rsmu_pair
);

/// `nbio_v7_2_init_registers`: the read-request register by version, both
/// fields set to 1 and nothing else changed, and the DEV2 strap only on 7.3.0
/// and 7.5.1.
fn nbio_v7_2_init_registers_follow_the_version() -> TestResult {
    let versions = [(7, 2, 0), (7, 2, 1), (7, 3, 0), (7, 5, 0), (7, 5, 1)];
    if versions.map(read_request_register)
        != [
            PCIE_CONFIG_CNTL,
            BIF1_PCIE_MST_CTRL_3,
            BIF1_PCIE_MST_CTRL_3,
            BIF1_PCIE_MST_CTRL_3,
            PCIE_CONFIG_CNTL,
        ]
        || versions.map(clears_dev2_soft_reset_strap) != [false, false, true, false, true]
        || read_request_size(0) != 0x1800_0000
        || read_request_size(0xffff_ffff) != 0xdfff_ffff
        || (PCIE_CONFIG_CNTL, BIF1_PCIE_MST_CTRL_3, RCC_DEV2_EPF0_STRAP2)
            != (0x420011, 0x4601c6, 0xd802)
        || STRAP_NO_SOFT_RESET_DEV2_F0 != 0x80
    {
        return TestResult::Fail("NBIO 7.2 init_registers differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/nbio-v7-2",
    nbio_v7_2_init_registers_follow_the_version
);
