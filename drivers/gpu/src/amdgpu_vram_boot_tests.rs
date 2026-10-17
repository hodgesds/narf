use super::*;
use alloc::vec;
use narf_bus::BarKind;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

const MIB: u64 = 1024 * 1024;
const GPU_BASE: u64 = 0x2_0000_0000;
const BAR_BASE: u64 = 0x6000_0000;
fn navi22_plan(visible: u64, image: &[u8], clients: &[Range<u64>]) -> Result<Plan, Error> {
    let size = 12 << 30;
    let mut plan = snapshot_with_fields(
        mapping(visible),
        image,
        None,
        clients,
        [
            (GPU_BASE >> 24) as u32,
            ((GPU_BASE + size) >> 24) as u32 - 1,
            0x80,
        ],
        |_| 0,
    )?;
    plan.reserve_training(image)?;
    Ok(plan)
}
fn navi22_vram_training_reservations_survive_bar_clipping() -> TestResult {
    let mut image = bios();
    put32(&mut image, 0x110, 0x400);
    let size = 12 << 30;
    for visible in [256 * MIB, size] {
        let plan = navi22_plan(visible, &image, &[]).unwrap();
        let t = plan.training().unwrap();
        if t != (Training {
            p2c: size - 0x8000,
            c2p: size - 9 * MIB,
            size: 4096,
        }) || plan.vram_size() != size
            || plan.visible_size() != visible
        {
            return TestResult::Fail(
                "training buffers located relative to BAR rather than physical VRAM",
            );
        }
        let exclusions = plan.protected.clone();
        // SAFETY: model-only allocator; no hardware memory is accessed.
        let pool = unsafe { plan.into_pool() }.unwrap();
        let mut allocations = Vec::new();
        while let Ok(r) = pool.reserve(MIB) {
            let start = r.address() - GPU_BASE;
            if exclusions
                .iter()
                .any(|e| start < e.range.end && e.range.start < start + r.size())
            {
                return TestResult::Fail("allocator reused firmware/training/client memory");
            }
            allocations.push(r);
        }
    }
    if navi22_plan(256 * MIB, &bios(), &[])
        .unwrap()
        .training()
        .is_some()
    {
        return TestResult::Fail("training inferred without firmware capability");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    navi22_vram_training_reservations_survive_bar_clipping
);

fn navi22_vram_training_rejects_collisions_and_bounds() -> TestResult {
    let mut image = bios();
    put32(&mut image, 0x110, 0x400);
    let c2p = GPU_BASE + (12 << 30) - 9 * MIB;
    if navi22_plan(256 * MIB, &image, core::slice::from_ref(&(c2p..c2p + 1))).err()
        != Some(Error::Invalid)
    {
        return TestResult::Fail("training exchange overlaps another client");
    }
    // Non-MiB-aligned firmware tails round the C2P address upwards; the 4 KiB
    // exchange must fit below the tail and above the VGA/scanout prefix.
    put32(&mut image, 0x154, 8193);
    let p = navi22_plan(256 * MIB, &image, &[]).unwrap();
    if p.training().unwrap().c2p != (12 << 30) - 9 * MIB {
        return TestResult::Fail("training C2P alignment differs from PSP ABI");
    }
    put32(&mut image, 0x154, 12 * 1024 * 1024);
    if navi22_plan(256 * MIB, &image, &[]).err() != Some(Error::Invalid) {
        return TestResult::Fail("training reservation underflow accepted");
    }
    for reg in [0x19e, 0x19f, 0x1a0, 0x1a4] {
        let mut regs = registers();
        regs[reg] = ENABLE | 4095;
        if plan(128 * MIB, &bios(), &regs, &[]).err() != Some(Error::Unsupported) {
            return TestResult::Fail("unknown live DMUB region omitted from inventory");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    navi22_vram_training_rejects_collisions_and_bounds
);
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn bios() -> Vec<u8> {
    let mut image = vec![0; 1024];
    image[..2].copy_from_slice(&[0x55, 0xaa]);
    put16(&mut image, 0x48, 0x80);
    image[0x80..0x88].copy_from_slice(&[40, 0, 2, 1, b'A', b'T', b'O', b'M']);
    put16(&mut image, 0xa0, 0xc0);
    image[0xc0..0xc4].copy_from_slice(&[28, 0, 2, 1]);
    put16(&mut image, 0xcc, 0x100); // directory index 4: FirmwareInfo
    put16(&mut image, 0xda, 0x200); // index 11: VRAM usage
    image[0x100..0x104].copy_from_slice(&[108, 0, 3, 4]);
    put32(&mut image, 0x154, 8192); // 8 MiB reserved at VRAM top
    image[0x200..0x204].copy_from_slice(&[48, 0, 2, 2]);
    put32(&mut image, 0x204, 40 * 1024);
    put16(&mut image, 0x208, 2048);
    put32(&mut image, 0x20c, 48 * 1024);
    put32(&mut image, 0x210, 2048);
    image
}
fn mapping(visible: u64) -> MmioRegion {
    MmioRegion {
        phys: PhysAddr::new(BAR_BASE),
        virt: 0,
        len: visible,
        kind: BarKind::Mmio64 { prefetchable: true },
    }
}
fn registers() -> Vec<u32> {
    let mut regs = vec![0; 0x478];
    regs[0x475] = (GPU_BASE >> 24) as u32;
    regs[0x476] = ((GPU_BASE + 128 * MIB) >> 24) as u32 - 1;
    regs[0x477] = 0x80;
    regs
}
fn plan(visible: u64, bios: &[u8], regs: &[u32], extra: &[Range<u64>]) -> Result<Plan, Error> {
    snapshot(
        mapping(visible),
        bios,
        BAR_BASE + MIB..BAR_BASE + 5 * MIB,
        extra,
        |reg| regs[reg as usize],
    )
}

fn vram_boot_pool_excludes_firmware_windows_and_clients() -> TestResult {
    let mut regs = registers();
    // CW0's address is translated MC space, not GPU space.
    regs[0x1ad] = ENABLE | 0xffff;
    regs[0x1b5] = 0x8000_0000 + (24 * MIB) as u32;
    // CW4 and Region5 point directly into GPU VRAM.
    regs[0x1a9] = 0x6400_0000;
    regs[0x1b1] = ENABLE | 0x0400_4000;
    regs[0x1bd] = (32 * MIB) as u32;
    regs[0x1be] = 2;
    regs[0x1a2] = ENABLE | 0x3fff;
    regs[0x198] = (56 * MIB) as u32;
    regs[0x199] = 2;
    let plan = plan(
        128 * MIB,
        &bios(),
        &regs,
        core::slice::from_ref(&(GPU_BASE + 12 * MIB..GPU_BASE + 20 * MIB)),
    )
    .unwrap();
    let excluded = plan.protected.clone();
    if !excluded
        .iter()
        .any(|r| r.owner == Owner::Dmub && r.range == (24 * MIB..24 * MIB + 65536))
    {
        return TestResult::Fail("CW0 translation lost reserved memory");
    }
    // SAFETY: model-only allocator bookkeeping; no physical access occurs.
    let pool = unsafe { plan.into_pool() }.unwrap();
    let first = pool.reserve(3 * MIB).unwrap();
    let second = pool.reserve(4 * MIB).unwrap();
    if first.address() != GPU_BASE + 9 * MIB || second.address() != GPU_BASE + 20 * MIB {
        return TestResult::Fail("boot prefix or explicit client allocation reused");
    }
    let mut reservations = vec![first, second];
    while let Ok(allocation) = pool.reserve(MIB) {
        let start = allocation.address() - GPU_BASE;
        let end = start + allocation.size();
        if excluded
            .iter()
            .any(|r| start < r.range.end && r.range.start < end)
        {
            return TestResult::Fail("firmware allocation overlaps a protected range");
        }
        reservations.push(allocation);
    }
    drop(reservations);
    let first = pool.reserve(3 * MIB).unwrap();
    if first.address() != GPU_BASE + 9 * MIB {
        return TestResult::Fail("released allocations destroyed permanent exclusions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_pool_excludes_firmware_windows_and_clients
);

fn vram_boot_uses_full_aperture_for_tail_and_clips_visible_bar() -> TestResult {
    let plan = plan(
        16 * MIB,
        &bios(),
        &registers(),
        core::slice::from_ref(&(GPU_BASE + 80 * MIB..GPU_BASE + 81 * MIB)),
    )
    .unwrap();
    if plan.vram_size() != 128 * MIB
        || plan.visible_size() != 16 * MIB
        || !plan
            .protected()
            .iter()
            .any(|r| r.owner == Owner::FirmwareTail && r.range == (120 * MIB..128 * MIB))
    {
        return TestResult::Fail("firmware tail inferred from CPU BAR size");
    }
    // SAFETY: model-only ownership and range bookkeeping.
    let pool = unsafe { plan.into_pool() }.unwrap();
    if pool.available() != 7 * MIB || pool.reserve(7 * MIB).unwrap().address() != GPU_BASE + 9 * MIB
    {
        return TestResult::Fail("out-of-BAR reservations consumed visible memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_uses_full_aperture_for_tail_and_clips_visible_bar
);

fn vram_boot_v21_driver_area_and_v35_protection() -> TestResult {
    let mut image = bios();
    image[0x103] = 5;
    put32(&mut image, 0x114, 16 * 1024); // write protection larger than FW reserve
    image[0x200..0x204].copy_from_slice(&[12, 0, 2, 1]);
    put32(&mut image, 0x204, 40 * 1024);
    put16(&mut image, 0x208, 2048);
    put16(&mut image, 0x20a, 1024);
    let plan = plan(128 * MIB, &image, &registers(), &[]).unwrap();
    if !plan
        .protected()
        .iter()
        .any(|r| r.owner == Owner::DriverUsage && r.range == (39 * MIB..40 * MIB))
        || !plan
            .protected()
            .iter()
            .any(|r| r.owner == Owner::FirmwareTail && r.range == (112 * MIB..128 * MIB))
    {
        return TestResult::Fail("firmware revision reservation semantics");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_v21_driver_area_and_v35_protection
);

fn vram_boot_rejects_unknown_or_impossible_metadata() -> TestResult {
    for (offset, value) in [(0xc2, 1), (0x102, 2), (0x103, 6), (0x203, 3), (0x200, 12)] {
        let mut image = bios();
        image[offset] = value;
        if plan(128 * MIB, &image, &registers(), &[]).is_ok() {
            return TestResult::Fail("unknown/truncated firmware reservation layout");
        }
    }
    for (offset, value) in [
        (0x154, u32::MAX),
        (0x204, 127 * 1024),
        (0x204, 0x8000_0000),
        (0x210, u32::MAX),
    ] {
        let mut image = bios();
        put32(&mut image, offset, value);
        if plan(128 * MIB, &image, &registers(), &[]).is_ok() {
            return TestResult::Fail("overflow/SR-IOV reservation accepted");
        }
    }
    let mut image = bios();
    put16(&mut image, 0xcc, 0);
    if plan(128 * MIB, &image, &registers(), &[]).err() != Some(Error::MissingMetadata) {
        return TestResult::Fail("missing FirmwareInfo treated as free VRAM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_rejects_unknown_or_impossible_metadata
);

fn vram_boot_rejects_invalid_addresses_and_register_reads() -> TestResult {
    for index in [0x1af, 0x1b4, 0x1a1, 0x1a3] {
        let mut regs = registers();
        regs[index] = ENABLE | 0xfff;
        if plan(128 * MIB, &bios(), &regs, &[]).err() != Some(Error::Unsupported) {
            return TestResult::Fail("unsupported active window translated by guess");
        }
    }
    for index in [0x475, 0x476, 0x477, 0x1ad, 0x1a2] {
        let mut regs = registers();
        regs[index] = u32::MAX;
        if plan(128 * MIB, &bios(), &regs, &[]).is_ok() {
            return TestResult::Fail("absent hardware accepted");
        }
    }
    let mut regs = registers();
    regs[0x1ad] = ENABLE | 0xffff;
    regs[0x1b5] = 0x1000; // underflows FB_OFFSET translation
    if plan(128 * MIB, &bios(), &regs, &[]).is_ok() {
        return TestResult::Fail("untranslatable cache window accepted");
    }
    for range in [
        BAR_BASE - 1..BAR_BASE + 4096,
        BAR_BASE..BAR_BASE,
        BAR_BASE..BAR_BASE + 129 * MIB,
    ] {
        if snapshot(mapping(128 * MIB), &bios(), range, &[], |reg| {
            registers()[reg as usize]
        })
        .is_ok()
        {
            return TestResult::Fail("boot framebuffer outside mapped GPU accepted");
        }
    }
    if plan(
        128 * MIB,
        &bios(),
        &registers(),
        core::slice::from_ref(&(GPU_BASE - 4096..GPU_BASE)),
    )
    .is_ok()
    {
        return TestResult::Fail("other client uses wrong GPU address space");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_rejects_invalid_addresses_and_register_reads
);

fn vram_exclusions_round_merge_and_survive_drop() -> TestResult {
    let ranges = [0x1001..0x2fff, 0..0x1001, 0x2fff..0x3100, 0x9001..0x9ffe];
    // SAFETY: pure bookkeeping; this model has no mapped hardware clients.
    let pool = unsafe { Pool::from_owned_aperture(mapping(65536), GPU_BASE, &ranges) }.unwrap();
    if pool.available() != 11 * 4096 {
        return TestResult::Fail("overlapping exclusions counted twice or rounded inward");
    }
    let first = pool.reserve(5 * 4096).unwrap();
    let second = pool.clone().reserve(6 * 4096).unwrap();
    if first.address() != GPU_BASE + 0x4000
        || second.address() != GPU_BASE + 0xa000
        || pool.reserve(1).is_ok()
    {
        return TestResult::Fail("allocator crossed protected hole");
    }
    drop(first);
    drop(second);
    if pool.available() != 11 * 4096 {
        return TestResult::Fail("allocation drop freed permanent protection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_exclusions_round_merge_and_survive_drop
);

fn vram_boot_revalidates_pci_authority_before_mmio() -> TestResult {
    use crate::amdgpu::{ChipInfo, Family};
    use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};
    let gpu = AmdGpu {
        fb_bar: mapping(128 * MIB),
        regs: MmioRegion {
            len: 0x478 * 4,
            ..mapping(0)
        },
        chip: ChipInfo {
            vid: 0x1002,
            did: 0x1900,
            family: Family::Phoenix,
            asic: "phoenix",
            fw_name: "",
            fw_list: &[],
        },
        vram: Default::default(),
        mode: None,
        fw_loaded: false,
        ip_blocks: vec![IpBlock {
            hw_id: HW_ID_DCN,
            instance: 0,
            major: 3,
            minor: 1,
            revision: 4,
            sub_revision: 0,
            variant: 0,
            base_addrs: [0; MAX_BASE_ADDRS],
            num_bases: 3,
        }],
        vbios: Some(crate::amdgpu_vbios::tests::fixture()),
        // Synthetic fixture: no discovery blob, so no GC table.
        gc_info: None,
    };
    let cap = Cap::bootstrap();
    cap.revoke();
    // SAFETY: revoked authority prevents MMIO to the deliberately null mapping.
    if unsafe { Plan::read(&gpu, &cap, BAR_BASE..BAR_BASE + MIB, &[]) }.err()
        != Some(Error::Revoked)
    {
        return TestResult::Fail("revoked authority reached aperture registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_revalidates_pci_authority_before_mmio
);

fn navi22_vram_checks_gmc_dcn_size_and_authority() -> TestResult {
    use crate::amdgpu::{ChipInfo, Family, VramInfo, NAVI22};
    use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, HW_ID_GC, HW_ID_MMHUB, MAX_BASE_ADDRS};
    let mut regs = vec![0; 0x2000];
    regs[0x16fc] = (GPU_BASE >> 24) as u32;
    regs[0x16fd] = ((GPU_BASE + (12 << 30)) >> 24) as u32 - 1;
    regs[0x16e7] = 0x80;
    regs[0x475] = regs[0x16fc];
    regs[0x476] = regs[0x16fd];
    regs[0x477] = regs[0x16e7];
    for pipe in 0..6 {
        regs[0x5f3 + pipe * 0xdc] = 1;
    }
    let before = regs.clone();
    let mut gpu = AmdGpu {
        fb_bar: mapping(256 * MIB),
        regs: MmioRegion {
            virt: regs.as_mut_ptr() as u64,
            len: regs.len() as u64 * 4,
            ..mapping(0)
        },
        chip: ChipInfo {
            vid: 0x1002,
            did: NAVI22,
            family: Family::Navi2,
            asic: "navi22",
            fw_name: "",
            fw_list: &[],
        },
        vram: VramInfo {
            base: BAR_BASE,
            size: 12 << 30,
            visible_size: 256 * MIB,
        },
        mode: None,
        fw_loaded: false,
        gc_info: None,
        ip_blocks: [
            (HW_ID_GC, 10, 3, 2),
            (HW_ID_DCN, 3, 0, 0),
            (HW_ID_MMHUB, 2, 1, 0),
        ]
        .iter()
        .map(|&(hw_id, major, minor, revision)| IpBlock {
            hw_id,
            instance: 0,
            major,
            minor,
            revision,
            sub_revision: 0,
            variant: 0,
            base_addrs: {
                let mut bases = [0; MAX_BASE_ADDRS];
                if hw_id == HW_ID_MMHUB {
                    bases[0] = 0x1000;
                }
                bases
            },
            num_bases: 3,
        })
        .collect(),
        vbios: Some(crate::amdgpu_vbios::tests::with_image(bios())),
    };
    let cap = Cap::bootstrap();
    // SAFETY: owned RAM registers; BAR0 is never dereferenced by inventory.
    if unsafe { Plan::read_navi22(&gpu, &cap, None, &[]) }.is_err() || regs != before {
        return TestResult::Fail("GMC10/DCN30 inventory modified hardware or rejected a valid map");
    }
    for reg in [0x15fc, 0x160b, 0x16c0, 0x16cf] {
        regs[reg] = 1;
        // SAFETY: private RAM model; an active inherited VM must prevent allocation.
        if unsafe { Plan::read_navi22(&gpu, &cap, None, &[]) }.err() != Some(Error::Busy) {
            return TestResult::Fail("live GFXHUB/MMHUB context admitted into boot pool");
        }
        regs[reg] = 0;
    }
    // The final cursor must be excluded even when caller supplies no clients.
    regs[0xac4] = 1 | (2 << 8);
    regs[0xac5] = 24 * MIB as u32;
    regs[0xac6] = 2;
    regs[0xac7] = (64 << 16) | 64;
    // SAFETY: same read-only fixture; no BAR0 dereference occurs.
    let plan = unsafe { Plan::read_navi22(&gpu, &cap, None, &[]) }.unwrap();
    if !plan
        .protected()
        .iter()
        .any(|r| r.range == (24 * MIB..24 * MIB + 16384))
    {
        return TestResult::Fail("inherited sixth-pipe cursor omitted from automatic exclusions");
    }
    regs[0xac4] = 0;
    regs[0x477] += 1;
    // SAFETY: same RAM-only read fixture.
    if unsafe { Plan::read_navi22(&gpu, &cap, None, &[]) }.err() != Some(Error::Invalid) {
        return TestResult::Fail("inconsistent GMC/DCN translation accepted");
    }
    regs[0x477] -= 1;
    gpu.vram.size -= 16 * MIB;
    // SAFETY: same RAM-only read fixture.
    if unsafe { Plan::read_navi22(&gpu, &cap, None, &[]) }.err() != Some(Error::Invalid) {
        return TestResult::Fail("GMC aperture not checked against physical memory");
    }
    cap.revoke();
    gpu.regs.virt = 0;
    // SAFETY: revoked authority must reject before dereferencing null MMIO.
    if unsafe { Plan::read_navi22(&gpu, &cap, None, &[]) }.err() != Some(Error::Revoked) {
        return TestResult::Fail("Navi22 inventory bypassed capability invocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    navi22_vram_checks_gmc_dcn_size_and_authority
);

fn vram_boot_loader_construction_does_not_modify_hardware() -> TestResult {
    use crate::amdgpu::{ChipInfo, Family};
    use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};
    use crate::amdgpu_dmub_boot::{Loader, State};
    if crate::amdgpu::is_probed() {
        return TestResult::Skip("requires no physical AMD GPU mailbox owner");
    }
    let mut vram = vec![0xa5u8; 16 * MIB as usize + 4095];
    let aligned = (vram.as_mut_ptr() as u64 + 4095) & !4095;
    let mut regs = registers();
    regs[0xca] = 1 << 16; // DMCUB supported fuse
    let before = regs.clone();
    let gpu = AmdGpu {
        fb_bar: MmioRegion {
            virt: aligned,
            ..mapping(16 * MIB)
        },
        regs: MmioRegion {
            virt: regs.as_mut_ptr() as u64,
            len: regs.len() as u64 * 4,
            ..mapping(0)
        },
        chip: ChipInfo {
            vid: 0x1002,
            did: 0x1900,
            family: Family::Phoenix,
            asic: "phoenix",
            fw_name: "",
            fw_list: &[],
        },
        vram: Default::default(),
        mode: None,
        fw_loaded: false,
        ip_blocks: vec![IpBlock {
            hw_id: HW_ID_DCN,
            instance: 0,
            major: 3,
            minor: 1,
            revision: 4,
            sub_revision: 0,
            variant: 0,
            base_addrs: [0; MAX_BASE_ADDRS],
            num_bases: 3,
        }],
        vbios: Some(crate::amdgpu_vbios::tests::with_image(bios())),
        // Synthetic fixture: no discovery blob, so no GC table.
        gc_info: None,
    };
    let firmware = crate::amdgpu_dmub::tests::fixture_firmware();
    let authority = Cap::bootstrap();
    // SAFETY: RAM-backed model owns the complete register/VRAM mappings. They
    // outlive the loader; only construction/drop run, never hardware boot.
    let loader = match unsafe {
        Loader::from_boot_memory(
            &gpu,
            authority,
            &firmware,
            BAR_BASE + MIB..BAR_BASE + 5 * MIB,
            &[],
        )
    } {
        Ok(loader) => loader,
        Err(_) => return TestResult::Fail("boot inventory did not construct a loader"),
    };
    if loader.state() != State::Prepared {
        return TestResult::Fail("constructor started firmware");
    }
    drop(loader);
    if regs != before || vram.iter().any(|byte| *byte != 0xa5) {
        return TestResult::Fail("construction/drop wrote registers or VRAM before boot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    vram_boot_loader_construction_does_not_modify_hardware
);

fn navi48_vram_checks_gmc12_dcn4_and_training() -> TestResult {
    use crate::amdgpu::{ChipInfo, Family, VramInfo, NAVI48};
    use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, HW_ID_GC, HW_ID_MMHUB, MAX_BASE_ADDRS};
    let mut regs = vec![0; 0x2000];
    regs[0x1614] = (GPU_BASE >> 24) as u32;
    regs[0x1615] = ((GPU_BASE + (16 << 30)) >> 24) as u32 - 1;
    regs[0x15a7] = 0x80;
    regs[0x475] = regs[0x1614];
    regs[0x476] = regs[0x1615];
    regs[0x477] = regs[0x15a7];
    for pipe in 0..4 {
        regs[0x5f4 + pipe * 0xdc] = 1;
    }
    regs[0x1a3] = (1 << 31) | 0x3fff;
    regs[0x19a] = (40 * MIB) as u32;
    regs[0x19b] = (GPU_BASE >> 32) as u32;
    let before = regs.clone();
    let mut gpu = AmdGpu {
        fb_bar: mapping(256 * MIB),
        regs: MmioRegion {
            virt: regs.as_mut_ptr() as u64,
            len: regs.len() as u64 * 4,
            ..mapping(0)
        },
        chip: ChipInfo {
            vid: 0x1002,
            did: NAVI48,
            family: Family::Navi4,
            asic: "navi48",
            fw_name: "",
            fw_list: &[],
        },
        vram: VramInfo {
            base: BAR_BASE,
            size: 16 << 30,
            visible_size: 256 * MIB,
        },
        mode: None,
        fw_loaded: false,
        gc_info: None,
        ip_blocks: [
            (HW_ID_GC, 12, 0, 1),
            (HW_ID_DCN, 4, 1, 0),
            (HW_ID_MMHUB, 4, 1, 0),
        ]
        .iter()
        .map(|&(hw_id, major, minor, revision)| IpBlock {
            hw_id,
            instance: 0,
            major,
            minor,
            revision,
            sub_revision: 0,
            variant: 0,
            base_addrs: {
                let mut bases = [0; MAX_BASE_ADDRS];
                if hw_id == HW_ID_MMHUB {
                    bases[0] = 0x1000;
                }
                bases
            },
            num_bases: 3,
        })
        .collect(),
        vbios: Some(crate::amdgpu_vbios::tests::with_image(bios())),
    };
    let cap = Cap::bootstrap();
    // SAFETY: owned RAM registers; BAR0 is never dereferenced by inventory.
    if unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.is_err() || regs != before {
        return TestResult::Fail("GMC12/DCN4 inventory modified hardware or rejected a valid map");
    }
    for reg in [0x1624, 0x1633, 0x1564, 0x1573] {
        regs[reg] = 1;
        // SAFETY: private RAM model; an active inherited VM must prevent allocation.
        if unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.err() != Some(Error::Busy) {
            return TestResult::Fail("live GFXHUB/MMHUB context admitted into boot pool");
        }
        regs[reg] = 0;
    }
    // The final cursor must be excluded even when caller supplies no clients.
    regs[0x90d] = 1 | (2 << 8);
    regs[0x90e] = 24 * MIB as u32;
    regs[0x90f] = 2;
    regs[0x910] = (64 << 16) | 64;
    // SAFETY: same read-only fixture; no BAR0 dereference occurs.
    let plan = unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.unwrap();
    if !plan
        .protected()
        .iter()
        .any(|r| r.owner == Owner::Dmub && r.range == (40 * MIB..40 * MIB + 0x4000))
    {
        return TestResult::Fail("DCN4 Region6 shared state was not reserved");
    }
    if !plan
        .protected()
        .iter()
        .any(|r| r.range == (24 * MIB..24 * MIB + 16384))
    {
        return TestResult::Fail("inherited fourth-pipe cursor omitted from automatic exclusions");
    }
    regs[0x90d] = 0;
    // DCN4 has 16-bit viewport-start/pitch fields, but 14-bit dimensions.
    // Truncating these to DCN3 widths would under-reserve an inherited surface.
    regs[0x5f4] = 0;
    regs[0x5e5] = 8;
    regs[0x5e9] = 0x4000 << 16;
    regs[0x5eb] = (1 << 16) | 1;
    regs[0x607] = 0xffff;
    regs[0x60a] = (32 * MIB) as u32;
    regs[0x60b] = (GPU_BASE >> 32) as u32;
    // SAFETY: read-only, array-backed register model.
    let plan = unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.unwrap();
    let end = 32 * MIB + 65536 * 16385 * 4;
    if !plan.protected().iter().any(|r| r.range == (32 * MIB..end)) {
        return TestResult::Fail("DCN4 pitch/start truncated to DCN3 field widths");
    }
    regs[0x5f4] = 1;
    regs[0x477] += 1;
    // SAFETY: same RAM-only read fixture.
    if unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.err() != Some(Error::Invalid) {
        return TestResult::Fail("inconsistent GMC/DCN translation accepted");
    }
    regs[0x477] -= 1;
    gpu.vram.size -= 16 * MIB;
    // SAFETY: same RAM-only read fixture.
    if unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.err() != Some(Error::Invalid) {
        return TestResult::Fail("GMC aperture not checked against physical memory");
    }
    cap.revoke();
    gpu.regs.virt = 0;
    // SAFETY: revoked authority must reject before dereferencing null MMIO.
    if unsafe { Plan::read_navi48(&gpu, &cap, None, &[]) }.err() != Some(Error::Revoked) {
        return TestResult::Fail("Navi48 inventory bypassed capability invocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vram",
    navi48_vram_checks_gmc12_dcn4_and_training
);
