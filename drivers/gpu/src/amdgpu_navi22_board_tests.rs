//! Metadata captured from the MSI 1462:3985 RX 6750 XT, revision c0.
//! These tests validate later startup layouts without touching the device.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_navi22_modeset as modeset};
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};

type DiscoveryRow<'a> = (u16, u8, (u8, u8, u8), &'a [u32]);

fn gpu() -> AmdGpu {
    let mut gpu = super::tests::gpu();
    // Linux's ip_discovery/die/0 on this board. SDMA's two engines are
    // distinct HWIDs with local instance zero; GC segment 2 is 0x1c000.
    let gc = &[0x1260, 0xa000, 0x1c000, 0x02402c00][..];
    let mp = &[0x16000, 0xdc0000, 0xe00000, 0xe40000, 0x0243fc00][..];
    let blocks: &[DiscoveryRow<'_>] = &[
        (11, 0, (10, 3, 2), gc),
        (42, 0, (5, 2, 2), gc),
        (43, 0, (5, 2, 2), gc),
        (255, 0, (11, 0, 11), mp),
        (1, 0, (11, 0, 11), mp),
        (108, 0, (3, 3, 1), &[0, 0x14, 0xd20, 0x10400, 0x0241b000]),
        (41, 0, (5, 0, 3), &[0xf20, 0x0240a400]),
        (40, 0, (5, 0, 3), &[0x10a0, 0x0240a000]),
        (34, 0, (2, 1, 0), &[0x1a000, 0x02408800]),
        (271, 0, (3, 0, 0), &[0x12, 0xc0, 0x34c0, 0x9000, 0x02403c00]),
        (12, 0, (3, 0, 0), &[0x7800, 0x7e00, 0x02403000]),
        (12, 1, (3, 0, 1), &[0x7b00, 0x12000, 0x02445000]),
        (3, 0, (11, 0, 5), &[0x16600, 0x02400c00]),
        (4, 0, (11, 0, 6), &[0x16800, 0x16a00, 0x440000, 0x02401000]),
    ];
    gpu.ip_blocks = blocks
        .iter()
        .map(|&(hw_id, instance, version, bases)| {
            let mut base_addrs = [0; ip::MAX_BASE_ADDRS];
            base_addrs[..bases.len()].copy_from_slice(bases);
            ip::IpBlock {
                hw_id,
                instance,
                major: version.0,
                minor: version.1,
                revision: version.2,
                sub_revision: 0,
                variant: 0,
                base_addrs,
                num_bases: bases.len() as u8,
            }
        })
        .collect();
    gpu.chip.revision = 0xc0;
    gpu.regs.len = 1 << 20;
    gpu.regs.phys = narf_memory::PhysAddr::new(0xdfb00000);
    gpu.fb_bar.phys = narf_memory::PhysAddr::new(0xf800000000);
    gpu.fb_bar.len = 16 << 30;
    // RCC_CONFIG_MEMSIZE, not the nominal 12 GiB or the rounded ReBAR size.
    gpu.vram.base = gpu.fb_bar.phys.raw();
    gpu.vram.size = 12272 << 20;
    gpu.vram.visible_size = gpu.vram.size;
    gpu
}

fn rx6750xt_later_display_layouts_accept_captured_discovery() -> TestResult {
    use crate::{
        amdgpu_dcn_inventory::{Connector as Kind, Path},
        amdgpu_navi22_display::{Connector, Signal},
    };
    let gpu = gpu();
    let cap = Cap::bootstrap();
    cap.revoke();
    // Actual VBIOS paths, decoded independently from the GPIO LUT. HDMI is
    // transmitter A/DDC4/HPD4; the DP paths have intentionally crossed wiring.
    for (kind, tx, aux, hpd, instance, signal) in [
        (Kind::DisplayPort, 3, 0, 1, 1, Signal::DisplayPort),
        (Kind::DisplayPort, 2, 1, 2, 2, Signal::DisplayPort),
        (Kind::DisplayPort, 4, 5, 6, 3, Signal::DisplayPort),
        (Kind::HdmiTypeA, 0, 3, 4, 1, Signal::Hdmi),
    ] {
        let connector = Connector {
            path: Path {
                connector: kind,
                connector_instance: instance,
                transmitter: tx,
                aux: Some(aux),
                hpd,
                device_tag: 0,
                max_speed_mhz: 0,
            },
            signal,
            line: aux,
            hpd: Some(hpd - 1),
        };
        let mut resources = modeset::Resources::for_gpu(&gpu).unwrap();
        let route = resources.acquire(&connector).unwrap();
        // SAFETY: inert mappings and revoked authority; construction performs
        // no I/O. This bounds DAL, all DCN/HDMI/audio blocks and NBIO banks.
        if unsafe { modeset::Pipeline::new(&gpu, cap, connector, route) }.is_err() {
            return TestResult::Fail("later display layout rejects actual RX 6750 XT banks");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-board",
    rx6750xt_later_display_layouts_accept_captured_discovery
);

fn rx6750xt_queue_preflight_uses_real_banks_and_high_mc_addresses() -> TestResult {
    let gpu = gpu();
    let cap = Cap::bootstrap();
    cap.revoke();
    let mapping = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(gpu.vram.base + (16 << 20)),
        virt: 16 << 20,
        len: 16 << 20,
        kind: gpu.fb_bar.kind,
    };
    // SAFETY: bookkeeping only, no aperture is dereferenced. The test pool
    // lies above the boot prefix at the actual 0x80... MC aperture.
    let pool =
        unsafe { crate::amdgpu_vram::Pool::from_owned_range(mapping, 0x8001000000) }.unwrap();
    let doorbells = crate::amdgpu_cp_navi22::Doorbells::from_region(narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xfc00000000),
        virt: 0,
        len: 4096,
        kind: mapping.kind,
    });
    // SAFETY: each owner only reserves private model memory; all mappings
    // are inert, authority revoked, and no engine is started.
    unsafe {
        let mut gmc = crate::amdgpu_gmc_navi22::Gmc::new_rdna2(&gpu, cap, &pool).unwrap();
        if gmc.prepare_gart().is_err()
            || crate::amdgpu_sdma_navi22::Sdma::new_rdna2(&gpu, cap, &pool).is_err()
            || crate::amdgpu_cp_navi22::Gfx::new_rdna2(&gpu, cap, &pool, doorbells).is_err()
            || crate::amdgpu_kiq_navi22::Compute::new_rdna2(&gpu, cap, &pool, doorbells).is_err()
        {
            return TestResult::Fail("GMC/GART/SDMA/CP constructor rejects captured board");
        }
        let sdma =
            crate::amdgpu_sdma_navi22_queues::Sdma::new_rdna2(&gpu, cap, &pool, doorbells).unwrap();
        if sdma.instance_count() != 2 {
            return TestResult::Fail("captured HWIDs did not produce exactly two SDMA queues");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-board",
    rx6750xt_queue_preflight_uses_real_banks_and_high_mc_addresses
);
