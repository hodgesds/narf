//! Navi48 probe regressions. No physical card or firmware writes required.
use crate::{
    amdgpu::{self, AmdGpu, Family, AMD_VENDOR, NAVI48},
    amdgpu_discovery::{self as ip, GcInfo, IpBlock, MAX_BASE_ADDRS},
    amdgpu_info::{query_against, Snapshot},
    amdgpu_uapi as u,
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn block(hw_id: u16, version: (u8, u8, u8)) -> IpBlock {
    IpBlock {
        hw_id,
        instance: 0,
        major: version.0,
        minor: version.1,
        revision: version.2,
        sub_revision: 0,
        variant: 0,
        base_addrs: [0; MAX_BASE_ADDRS],
        num_bases: 4,
    }
}
fn gpu() -> AmdGpu {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, NAVI48).unwrap();
    gpu.ip_blocks = vec![
        block(ip::HW_ID_GC, (12, 0, 1)),
        block(ip::HW_ID_MP0, (14, 0, 3)),
        block(ip::HW_ID_MP1, (14, 0, 2)),
        // Linux translates this discovery version to DCN4.0.1 in its DC path.
        block(ip::HW_ID_DCN, (4, 1, 0)),
    ];
    // Synthetic geometry: DEV_INFO must forward it, never guess a retail SKU.
    gpu.gc_info = Some(GcInfo {
        num_se: 3,
        num_sa_per_se: 2,
        num_cu_per_sa: 8,
        wave_size: 32,
        ..GcInfo::default()
    });
    gpu
}

fn navi48_identity_and_memory_follow_discovery_and_bar_bounds() -> TestResult {
    let mut gpu = gpu();
    if NAVI48 != 0x7550 || gpu.chip.family != Family::Navi4 || gpu.chip.is_apu() {
        return TestResult::Fail("Navi48 PCI identity inherited another family");
    }
    if amdgpu::__test_chip_info_for_pci_id(0x10de, NAVI48).is_some() {
        return TestResult::Fail("foreign vendor admitted");
    }
    // Every listed RDNA4 board, including the AI PRO R9700 and Navi44.
    for did in [0x7551, 0x7590] {
        if amdgpu::__test_chip_info_for_pci_id(AMD_VENDOR, did).map(|c| c.family)
            != Some(Family::Navi4)
        {
            return TestResult::Fail("listed RDNA4 board refused");
        }
    }
    let mut regs = vec![0u32; 0x4000 / 4];
    regs[0xde3] = 16 * 1024;
    gpu.regs.virt = regs.as_mut_ptr() as u64;
    gpu.regs.len = regs.len() as u64 * 4;
    for aperture in [256u64 << 20, 16 << 30, 32 << 30] {
        gpu.fb_bar.len = aperture;
        // SAFETY: live RAM-backed register model; BAR0 is used only as metadata.
        gpu.vram = unsafe { amdgpu::read_vram_info(&gpu.regs, &gpu.fb_bar) };
        let snap = Snapshot::from_gpu(&gpu);
        if snap.is_apu
            || snap.vram_size != 16 << 30
            || snap.visible_vram_size != aperture.min(16 << 30)
        {
            return TestResult::Fail("Navi48 physical/visible VRAM or ReBAR identity");
        }
        let bytes = query_against(&snap, u::AMDGPU_INFO_DEV_INFO, [0; 4]).unwrap();
        // SAFETY: complete POD UAPI reply; its alignment is not assumed.
        let dev =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<u::DrmAmdgpuInfoDevice>()) };
        if dev.family != 152
            || dev.device_id != 0x7550
            || dev.ids_flags != 0
            || dev.cu_active_number != 0
            || dev.num_cu_per_sh != 8
            || dev.num_shader_engines != 3
            || dev.num_hw_gfx_contexts != 8
            || dev.wave_front_size != 32
            || dev.high_va_max != crate::amdgpu_vm::Geometry::GMC11.va_info().high_max
        {
            return TestResult::Fail("Navi48 DEV_INFO family, topology or VA geometry");
        }
        if query_against(&snap, u::AMDGPU_INFO_ACCEL_WORKING, [0; 4]).unwrap() != [0; 4] {
            return TestResult::Fail("probe claimed acceleration");
        }
        let bytes = query_against(&snap, u::AMDGPU_INFO_MEMORY, [0; 4]).unwrap();
        // SAFETY: complete POD UAPI reply.
        let memory =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<u::DrmAmdgpuMemoryInfo>()) };
        if memory.vram.total_heap_size != 16 << 30
            || memory.cpu_accessible_vram.total_heap_size != aperture.min(16 << 30)
            || memory.gtt.total_heap_size != crate::amdgpu_gem::gtt_limit()
            || memory.gtt.total_heap_size == 0
        {
            return TestResult::Fail("Navi48 heap query ignored aperture");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_identity_and_memory_follow_discovery_and_bar_bounds
);

fn navi48_identity_rejects_missing_mismatched_and_duplicate_gc() -> TestResult {
    for case in 0..5 {
        let mut gpu = gpu();
        match case {
            0 => gpu.ip_blocks.clear(),
            1 => gpu.ip_blocks[0].revision = 2, // No RDNA4 die is GC 12.0.2.
            2 => gpu.ip_blocks.push(gpu.ip_blocks[0]),
            3 => gpu.gc_info = None,
            _ => gpu.chip.family = Family::Navi3,
        }
        if query_against(&Snapshot::from_gpu(&gpu), u::AMDGPU_INFO_DEV_INFO, [0; 4]).is_ok() {
            return TestResult::Fail("unverified Navi48 identity/topology reported");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_identity_rejects_missing_mismatched_and_duplicate_gc
);

fn navi48_refuses_legacy_engines_before_mmio_or_firmware_access() -> TestResult {
    let mut gpu = gpu();
    gpu.regs.virt = 0;
    gpu.fw_loaded = true; // Even a mistaken caller cannot opt into DCN2 writes.
    let (_, firmware) = narf_firmware::bootstrap_authority();
    firmware.revoke();
    let mode = amdgpu::Mode {
        width: 1920,
        height: 1080,
        stride: 1920,
    };
    let mut seq = crate::amdgpu_gfx::Gfx11Sequence { steps: vec![] };
    seq.write(0, 0, 0x1234);
    // SAFETY: Navi48 must reject every legacy operation before dereferencing
    // the deliberately null register mapping or accessing the registry.
    unsafe {
        if gpu.read_grbm_status().is_some()
            || gpu.write_grbm_gfx_index(0).is_some()
            || gpu.start_gfx_cp(0, 0, 0).is_some()
            || gpu.read_mes_fw_versions().is_some()
            || gpu.read_aperture_layout().is_some()
            || gpu.hpd_asserted(0).is_some()
            || gpu.current_mode().is_some()
            || gpu.set_mode(mode).is_ok()
        {
            return TestResult::Fail("Navi48 reached a legacy GFX/GMC/DCN path");
        }
        gpu.apply_gfx11_sequence(&seq);
        gpu.mode = Some(mode);
        if gpu.set_backlight(50).is_ok()
            || gpu.load_firmware(&firmware).is_ok()
            || gpu.load_firmware_multi(&firmware).is_ok()
            || gpu.initialize(&firmware).is_ok()
        {
            return TestResult::Fail("Navi48 reached legacy PWM/PSP initialization");
        }
    }
    if gpu.mp1_mailbox_base().is_some()
        || gpu.expected_smu_driver_if_version().is_some()
        || crate::amdgpu_video::VcnVersion::from_family(Family::Navi4).is_some()
    {
        return TestResult::Fail("Navi48 inherited APU SMU or VCN4");
    }
    // Mismatched discovery must not override the Navi48 mailbox exclusion.
    gpu.ip_blocks[0].major = 11;
    if gpu.mp1_mailbox_base().is_some() {
        return TestResult::Fail("APU GC identity bypassed Navi48 SMU exclusion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    navi48_refuses_legacy_engines_before_mmio_or_firmware_access
);
