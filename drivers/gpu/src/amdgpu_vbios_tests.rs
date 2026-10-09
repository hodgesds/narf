use super::*;
use alloc::vec;
use narf_bus::{BarKind, BusKind, DeviceId, PcieAddr};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

fn device() -> BusDevice {
    let addr = PcieAddr::new(0, 0xc4, 0, 0);
    BusDevice {
        addr: BusAddr::Pcie(addr),
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
        id: DeviceId {
            vendor: 0x1002,
            device: 0x1900,
            class: 0x030000,
            subsystem_vendor: 0x17aa,
            subsystem_id: 0x50ee,
        },
    }
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn image() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..3].copy_from_slice(&[0x55, 0xaa, 1]);
    put16(&mut bytes, 0x48, 0x80);
    bytes[0x80..0x88].copy_from_slice(&[40, 0, 2, 1, b'A', b'T', b'O', b'M']);
    put16(&mut bytes, 0x90, 0x140); // boot message
    put16(&mut bytes, 0x9e, 0xc0); // command directory
    put16(&mut bytes, 0xa0, 0xd0); // data directory
    put16(&mut bytes, 0xc0, 6);
    put16(&mut bytes, 0xc4, 0x100);
    put16(&mut bytes, 0x100, 6);
    put16(&mut bytes, 0xd0, 8);
    put16(&mut bytes, 0xd4, 0x110);
    put16(&mut bytes, 0x110, 8);
    bytes[0x140..0x148].copy_from_slice(b"VBIOS-1\0");
    put16(&mut bytes, 0x18, 0x180);
    bytes[0x180..0x184].copy_from_slice(b"PCIR");
    put16(&mut bytes, 0x184, 0x1002);
    put16(&mut bytes, 0x186, 0x1900);
    put16(&mut bytes, 0x18a, 24);
    bytes
}
fn checksum(table: &mut [u8]) {
    table[9] = 0;
    table[9] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
}
fn vfct(images: &[Vec<u8>]) -> Vec<u8> {
    let mut table = vec![0; VFCT_HEADER];
    table[..4].copy_from_slice(b"VFCT");
    table[8] = 1;
    put32(&mut table, 0x34, VFCT_HEADER as u32);
    for image in images {
        let start = table.len();
        table.resize(start + IMAGE_HEADER, 0);
        put32(&mut table, start, 0xc4);
        put16(&mut table, start + 12, 0x1002);
        put16(&mut table, start + 14, 0x1900);
        put16(&mut table, start + 16, 0x17aa);
        put16(&mut table, start + 18, 0x50ee);
        put32(&mut table, start + 24, image.len() as u32);
        table.extend_from_slice(image);
    }
    let len = table.len() as u32;
    put32(&mut table, 4, len);
    checksum(&mut table);
    table
}
fn error(table: &[u8], expected: Error) -> bool {
    Vbios::from_vfct(table, &device()).err() == Some(expected)
}
pub(crate) fn fixture() -> Vbios {
    Vbios::from_vfct(&vfct(&[image()]), &device()).unwrap()
}
pub(crate) fn with_image(image: Vec<u8>) -> Vbios {
    Vbios::from_vfct(&vfct(&[image]), &device()).unwrap()
}

fn vbios_vfct_owns_correct_atom_image() -> TestResult {
    let image = image();
    let mut table = vfct(core::slice::from_ref(&image));
    let bios = Vbios::from_vfct(&table, &device()).unwrap();
    table.fill(0);
    let atom = Atombios::parse(bios.bytes()).unwrap();
    if bios.bytes() != image
        || bios.source() != Source::Vfct
        || bios.version().as_deref() != Some("VBIOS-1")
        || atom.cmd_table_offset(0) != Ok(0x100)
        || atom.data_table_offset(0) != Ok(0x110)
        || atom.data_table_count() != 2
    {
        return TestResult::Fail("VBIOS image ownership/header indirection");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vbios", vbios_vfct_owns_correct_atom_image);

fn vbios_vfct_rejects_truncation_and_bad_offsets() -> TestResult {
    let table = vfct(&[image()]);
    for len in 0..table.len() {
        if Vbios::from_vfct(&table[..len], &device()).is_ok() {
            return TestResult::Fail("truncated VFCT accepted");
        }
    }
    for (offset, value) in [
        (4, u32::MAX),
        (0x34, 1),
        (0x34, u32::MAX),
        (0x38, 77),
        (VFCT_HEADER + 24, u32::MAX),
    ] {
        let mut bad = table.clone();
        put32(&mut bad, offset, value);
        checksum(&mut bad);
        if !error(&bad, Error::InvalidTable) {
            return TestResult::Fail("invalid VFCT range accepted");
        }
    }
    let mut bad = table;
    bad[10] ^= 1;
    if !error(&bad, Error::InvalidTable) {
        return TestResult::Fail("VFCT checksum ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    vbios_vfct_rejects_truncation_and_bad_offsets
);

fn vbios_vfct_matches_function_and_rejects_ambiguity() -> TestResult {
    let table = vfct(&[image()]);
    // The identity fields `amdgpu_acpi_vfct_match` requires: slot (4),
    // function (8), vendor (12), device (14), and the two subsystem ids.
    // The bus at offset 0 is deliberately absent — it is a preference, see
    // `smoke_vfct_bus_number_is_a_preference_not_a_requirement`.
    for offset in [4, 8, 12, 14, 16, 18] {
        let mut other = table.clone();
        other[VFCT_HEADER + offset] ^= 1;
        checksum(&mut other);
        if !error(&other, Error::NotFound) {
            return TestResult::Fail("wrong function/subsystem matched");
        }
    }
    let mut dev = device();
    dev.addr = BusAddr::Pcie(PcieAddr::new(1, 0xc4, 0, 0));
    if Vbios::from_vfct(&table, &dev).err() != Some(Error::Unsupported)
        || !error(&vfct(&[image(), image()]), Error::Ambiguous)
    {
        return TestResult::Fail("ambiguous identity accepted");
    }
    let mut table = vfct(&[image(), image()]);
    put32(&mut table, VFCT_HEADER, 0xc5); // skip the first GPU
    checksum(&mut table);
    if Vbios::from_vfct(&table, &device()).is_err() {
        return TestResult::Fail("later exact match not selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    vbios_vfct_matches_function_and_rejects_ambiguity
);

fn vbios_vfct_honors_library_boundary() -> TestResult {
    let mut table = vfct(&[image()]);
    let boundary = table.len() as u32;
    put32(&mut table, 0x38, boundary);
    table.extend_from_slice(&[0xa5; 32]); // not another VBIOS image
    let len = table.len() as u32;
    put32(&mut table, 4, len);
    checksum(&mut table);
    if Vbios::from_vfct(&table, &device()).is_err() {
        return TestResult::Fail("library parsed as a VBIOS image");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vbios", vbios_vfct_honors_library_boundary);

fn vbios_vfct_caps_sizes_and_skips_empty_records() -> TestResult {
    let mut oversized = image();
    oversized.resize(MAX_IMAGE + 1, 0);
    if !error(&vfct(&[oversized]), Error::InvalidImage) {
        return TestResult::Fail("oversized VBIOS accepted");
    }
    if !error(&vfct(&[Vec::new()]), Error::NotFound)
        || Vbios::from_vfct(&vfct(&[Vec::new(), image()]), &device()).is_err()
    {
        return TestResult::Fail("zero-length record handling");
    }
    let mut table = vfct(&[image()]);
    table.resize(MAX_VFCT + 1, 0);
    put32(&mut table, 4, (MAX_VFCT + 1) as u32);
    checksum(&mut table);
    if !error(&table, Error::InvalidTable) {
        return TestResult::Fail("oversized VFCT accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    vbios_vfct_caps_sizes_and_skips_empty_records
);

fn vbios_rejects_fictional_layout_and_malformed_tables() -> TestResult {
    for (offset, value) in [
        (0, 0xaa),
        (0x80, 32),
        (0x84, b'X'),
        (0xc0, 5),
        (0xd0, 3),
        (0x100, 5),
        (0x110, 3),
    ] {
        let mut bytes = image();
        bytes[offset] = value;
        if !error(&vfct(&[bytes]), Error::InvalidImage) {
            return TestResult::Fail("invalid ATOM structure accepted");
        }
    }
    for (offset, value) in [
        (0x48, 0),
        (0x48, 0xffff),
        (0x80, 0xffff),
        (0xa0, 0),
        (0xc4, 0xffff),
        (0xd4, 0xffff),
    ] {
        let mut bytes = image();
        put16(&mut bytes, offset, value);
        if !error(&vfct(&[bytes]), Error::InvalidImage) {
            return TestResult::Fail("invalid ATOM pointer accepted");
        }
    }
    let mut bytes = image();
    bytes[0x84..0x88].copy_from_slice(b"MOTA");
    if Vbios::from_vfct(&vfct(&[bytes]), &device()).is_err() {
        return TestResult::Fail("legacy MOTA signature rejected");
    }
    let mut bytes = image();
    put16(&mut bytes, 0x186, 0x9999);
    if !error(&vfct(&[bytes]), Error::WrongDevice) {
        return TestResult::Fail("PCIR GPU mismatch ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    vbios_rejects_fictional_layout_and_malformed_tables
);

fn vbios_shadow_requires_pcir_and_live_authority() -> TestResult {
    let bytes = image();
    let mut memory = vec![0u32; MAX_IMAGE / 4];
    for (dst, src) in memory.iter_mut().zip(bytes.chunks_exact(4)) {
        *dst = u32::from_le_bytes(src.try_into().unwrap());
    }
    let mapping = MmioRegion {
        phys: PhysAddr::new(0),
        virt: memory.as_ptr() as u64,
        len: MAX_IMAGE as u64,
        kind: BarKind::Mmio32 { prefetchable: true },
    };
    let cap = Cap::bootstrap();
    // SAFETY: model-owned memory supplies the entire mapped range.
    let bios = unsafe { shadow(mapping, &device(), &cap) }.unwrap();
    if bios.source() != Source::VramShadow || bios.bytes()[..512] != bytes {
        return TestResult::Fail("VRAM shadow copy");
    }
    memory[0x18 / 4] = 0;
    // SAFETY: the same model-owned mapping remains readable after mutation.
    if unsafe { shadow(mapping, &device(), &cap) }.err() != Some(Error::InvalidImage) {
        return TestResult::Fail("unidentified VRAM shadow accepted");
    }
    cap.revoke();
    // An invalid address proves revocation fails before the first MMIO read.
    let invalid = MmioRegion { virt: 0, ..mapping };
    // SAFETY: revoked authority prevents this deliberately invalid mapping's use.
    if unsafe { shadow(invalid, &device(), &cap) }.err() != Some(Error::Revoked) {
        return TestResult::Fail("revoked shadow access");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    vbios_shadow_requires_pcir_and_live_authority
);

/// `amdgpu_acpi_vfct_match`: vendor, device, slot and function must match;
/// the bus number is a preference. A kernel that renumbers PCI buses leaves
/// the POST-time bus in the table disagreeing with the runtime one, and Linux
/// deliberately accepts that rather than losing the VBIOS.
fn smoke_vfct_bus_number_is_a_preference_not_a_requirement() -> TestResult {
    // One image recorded on a different bus than the device now sits on.
    let mut table = vfct(&[image()]);
    put32(&mut table, VFCT_HEADER, 0x11);
    checksum(&mut table);
    if Vbios::from_vfct(&table, &device()).is_err() {
        return TestResult::Fail("an identity match with a stale bus must still be accepted");
    }

    // Two images, one on the right bus and one not: the exact match wins
    // rather than being reported as ambiguous.
    let mut table = vfct(&[image(), image()]);
    put32(&mut table, VFCT_HEADER, 0x11);
    checksum(&mut table);
    if Vbios::from_vfct(&table, &device()).is_err() {
        return TestResult::Fail("an exact bus match must win over a stale one");
    }

    // Identity still has to match: a different device id is not our VBIOS,
    // whatever bus it claims.
    let mut table = vfct(&[image()]);
    put16(&mut table, VFCT_HEADER + 14, 0x1901);
    checksum(&mut table);
    if Vbios::from_vfct(&table, &device()).err() != Some(Error::NotFound) {
        return TestResult::Fail("a foreign device id must not match");
    }

    // Two equally stale entries are genuinely ambiguous.
    let mut table = vfct(&[image(), image()]);
    put32(&mut table, VFCT_HEADER, 0x11);
    let second = VFCT_HEADER + IMAGE_HEADER + image().len();
    put32(&mut table, second, 0x12);
    checksum(&mut table);
    if Vbios::from_vfct(&table, &device()).err() != Some(Error::Ambiguous) {
        return TestResult::Fail("two stale matches are ambiguous");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vbios",
    smoke_vfct_bus_number_is_a_preference_not_a_requirement
);
