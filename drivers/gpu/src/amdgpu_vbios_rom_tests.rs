use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    bytes: Vec<u8>,
    index: u32,
    reads: usize,
    writes: Vec<u32>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
}
impl Io for Fake {
    fn read_index(&mut self) -> u32 {
        self.index
    }
    fn write_index(&mut self, value: u32) {
        self.index = value;
        self.writes.push(value);
    }
    fn read_data(&mut self) -> u32 {
        let offset = self.index as usize;
        self.index += 4;
        self.reads += 1;
        if let Some((at, cap)) = self.revoke {
            if self.reads == at {
                cap.revoke();
            }
        }
        u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }
}
fn fixture() -> (BusDevice, Fake) {
    let mut device = super::super::tests::device();
    device.id.device = crate::amdgpu::NAVI22;
    let mut bytes = super::super::tests::image();
    bytes.resize(8192, 0);
    bytes[2] = 16;
    bytes[0x30..0x3a].copy_from_slice(b" 761295520");
    bytes[0x186..0x188].copy_from_slice(&crate::amdgpu::NAVI22.to_le_bytes());
    (
        device,
        Fake {
            bytes,
            index: 0xdead_0000,
            reads: 0,
            writes: Vec::new(),
            revoke: None,
        },
    )
}
fn navi22_rom_snapshot_preserves_index_and_retains_image() -> TestResult {
    let (device, mut io) = fixture();
    let cap = Cap::bootstrap();
    let vbios = read(&mut io, &device, &cap).unwrap();
    if vbios.bytes() != io.bytes
        || vbios.source() != Source::RomRegisters
        || vbios.version().as_deref() != Some("VBIOS-1")
        || io.writes != [0, 0xdead_0000, 0, 0xdead_0000, 4096, 0xdead_0000]
        || io.index != 0xdead_0000
    {
        return TestResult::Fail(
            "ROM autoincrement, chunk addressing, retained image or latch restoration",
        );
    }
    io.bytes.fill(0);
    if vbios.bytes()[0] != 0x55 {
        return TestResult::Fail("snapshot aliases ROM backing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    navi22_rom_snapshot_preserves_index_and_retains_image
);

fn navi22_rom_rejects_bad_header_identity_and_tables() -> TestResult {
    for (offset, value) in [
        (0, 0),
        (2, 0),
        (0x30, 0),
        (0x186, 0),
        (0xd4, 0xff),
        (0xd5, 0xff),
    ] {
        let (device, mut io) = fixture();
        io.bytes[offset] = value;
        if read(&mut io, &device, &Cap::bootstrap()).is_ok() || io.index != 0xdead_0000 {
            return TestResult::Fail(
                "bad ROM accepted or read latch not restored on validation failure",
            );
        }
    }
    let (device, mut io) = fixture();
    io.index = u32::MAX;
    if read(&mut io, &device, &Cap::bootstrap()).err() != Some(Error::NotFound)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("absent ROM interface accessed");
    }
    let (_, mut io) = fixture();
    let mut bytes = [0; 8];
    for offset in [1, MAX_IMAGE - 4, usize::MAX] {
        if chunk(&mut io, offset, &mut bytes).is_ok() || !io.writes.is_empty() {
            return TestResult::Fail("invalid ROM range changed the index");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    navi22_rom_rejects_bad_header_identity_and_tables
);

fn navi22_rom_rechecks_authority_between_chunks() -> TestResult {
    for revoke_after_header in [false, true] {
        let (device, mut io) = fixture();
        let cap = Cap::bootstrap();
        if revoke_after_header {
            io.revoke = Some((16 + 1024, cap));
        } else {
            cap.revoke();
        }
        if read(&mut io, &device, &cap).err() != Some(Error::Revoked)
            || io.index != 0xdead_0000
            || io.reads != if revoke_after_header { 1040 } else { 0 }
        {
            return TestResult::Fail("ROM read ignored revocation or abandoned the index latch");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    navi22_rom_rechecks_authority_between_chunks
);

fn navi22_rom_bank_is_selected_before_hardware_access() -> TestResult {
    use crate::amdgpu_discovery as d;
    let (device, _) = fixture();
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 0x10000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut gpu = AmdGpu {
        regs: map,
        fb_bar: map,
        chip: crate::amdgpu::__test_chip_info_for_pci_id(0x1002, crate::amdgpu::NAVI22).unwrap(),
        vram: Default::default(),
        mode: None,
        fw_loaded: false,
        gc_info: None,
        vbios: None,
        ip_blocks: [
            (d::HW_ID_GC, 10, 3, 2),
            (d::HW_ID_NBIF, 3, 3, 0),
            (d::HW_ID_SMUIO, 11, 0, 7),
        ]
        .iter()
        .map(|&(hw_id, major, minor, revision)| {
            let mut bases = [0; d::MAX_BASE_ADDRS];
            bases[0] = 0x1000;
            d::IpBlock {
                hw_id,
                major,
                minor,
                revision,
                instance: 0,
                sub_revision: 0,
                variant: 0,
                base_addrs: bases,
                num_bases: 3,
            }
        })
        .collect(),
    };
    if bank(&gpu, &device) != Ok(0x4000) {
        return TestResult::Fail("ROM port is not SMUIO base index zero");
    }
    let cap = Cap::bootstrap();
    cap.revoke();
    // SAFETY: revoked authority rejects before touching the null MMIO mapping.
    if unsafe { read_discrete(&gpu, &device, &cap) }.err() != Some(Error::Revoked) {
        return TestResult::Fail("ROM backend bypassed live PCI invocation");
    }
    gpu.ip_blocks[2].revision = 6;
    if bank(&gpu, &device).is_ok() {
        return TestResult::Fail("different SMUIO generation inherited ROM offsets");
    }
    gpu.ip_blocks[2].revision = 7;
    gpu.regs.len = 0x4000 + DATA as u64 * 4;
    if bank(&gpu, &device).is_ok() {
        return TestResult::Fail("ROM_DATA lies outside BAR5");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    navi22_rom_bank_is_selected_before_hardware_access
);

fn navi48_rom_profile_and_snapshot_are_independent_of_navi22() -> TestResult {
    use crate::{amdgpu, amdgpu_discovery as ip};
    let (mut device, mut io) = fixture();
    device.id.device = amdgpu::NAVI48;
    io.bytes[0x186..0x188].copy_from_slice(&0x7550u16.to_le_bytes());
    let cap = Cap::bootstrap();
    let image = read(&mut io, &device, &cap).unwrap();
    if image.bytes() != io.bytes || io.index != 0xdead_0000 {
        return TestResult::Fail("Navi48 ROM snapshot identity or latch restoration");
    }
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    gpu.chip = amdgpu::__test_chip_info_for_pci_id(0x1002, 0x7550).unwrap();
    gpu.regs.len = 0x10000;
    gpu.regs.virt = 0;
    let template = gpu.ip_blocks[0];
    gpu.ip_blocks = [
        (ip::HW_ID_GC, 12, 0, 1),
        (ip::HW_ID_NBIF, 7, 7, 0),
        (ip::HW_ID_SMUIO, 14, 0, 2),
    ]
    .iter()
    .map(|&(hw_id, major, minor, revision)| ip::IpBlock {
        hw_id,
        major,
        minor,
        revision,
        base_addrs: [0x1000, 0, 0, 0, 0],
        num_bases: 1,
        ..template
    })
    .collect();
    if bank(&gpu, &device) != Ok(0x4000) {
        return TestResult::Fail("SMUIO14 ROM base index/offset");
    }
    cap.revoke();
    // SAFETY: revoked authority must reject before dereferencing the null map.
    if unsafe { read_discrete(&gpu, &device, &cap) }.err() != Some(Error::Revoked) {
        return TestResult::Fail("Navi48 ROM ignored live authority");
    }
    let good = gpu.ip_blocks.clone();
    for case in 0..7 {
        gpu.ip_blocks = good.clone();
        gpu.regs.len = 0x10000;
        match case {
            0 => gpu.ip_blocks[0].revision = 0,
            1 => gpu.ip_blocks[1].major = 3,
            2 => gpu.ip_blocks[2].major = 11,
            3 => gpu.ip_blocks[2].revision = 3,
            4 => gpu.ip_blocks.push(gpu.ip_blocks[2]),
            5 => gpu.ip_blocks[2].num_bases = 0,
            _ => gpu.regs.len = 0x4000 + 0xe5 * 4 + 3,
        }
        if bank(&gpu, &device).is_ok() {
            return TestResult::Fail(
                "Navi48 ROM admitted ambiguous, unsupported or truncated bank",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    navi48_rom_profile_and_snapshot_are_independent_of_navi22
);
