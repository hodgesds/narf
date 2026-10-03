use super::*;
use alloc::vec;
use narf_bus::BarKind;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

const MIB: u64 = 1024 * 1024;
const GPU_BASE: u64 = 0x2_0000_0000;
const BAR_BASE: u64 = 0x6000_0000;
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
