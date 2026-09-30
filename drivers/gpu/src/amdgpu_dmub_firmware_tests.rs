use super::*;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn write_metadata(bytes: &mut [u8]) {
    bytes[..META_SIZE].fill(0);
    put32(bytes, 0, META_MAGIC);
    put32(bytes, 4, 51712);
    put32(bytes, 8, 65552);
    put32(bytes, 12, 0x0800_5d00);
    bytes[16] = 1;
}
pub(crate) fn combined(footer: usize, padding: usize) -> Vec<u8> {
    let payload_start = 256;
    let inst_size = PSP_HEADER_SIZE + 512 + padding + footer;
    let mut bytes = vec![0u8; payload_start + inst_size];
    let size = bytes.len();
    put32(&mut bytes, 0, size as u32);
    put32(&mut bytes, 4, HEADER_SIZE as u32);
    bytes[8] = 1;
    bytes[12] = 3;
    bytes[14] = 1;
    put32(&mut bytes, 16, 0x0800_5d00);
    put32(&mut bytes, 20, inst_size as u32);
    put32(&mut bytes, 24, payload_start as u32);
    put32(&mut bytes, 32, inst_size as u32);
    bytes[payload_start..payload_start + PSP_HEADER_SIZE].fill(0xa7);
    bytes[payload_start + PSP_HEADER_SIZE..size - footer].fill(0x9c);
    bytes[size - footer..].fill(0x5a);
    write_metadata(&mut bytes[size - footer - padding - META_SIZE..]);
    bytes
}

fn dmub_firmware_combined_footer_variants() -> TestResult {
    for footer in [256, 512] {
        for padding in 0..16 {
            let bytes = combined(footer, padding);
            let Ok(image) = Image::parse(&bytes) else {
                return TestResult::Fail("valid combined metadata/footer rejected");
            };
            if image.signed_offset() != 256
                || image.signed_instructions() != &bytes[256..]
                || image.instructions() != &bytes[512..bytes.len() - footer]
                || image.instructions().len() != 512 + padding
                || !image.bss_data().is_empty()
                || image.version() != 0x0800_5d00
                || image.metadata().state_size != 51712
                || image.metadata().trace_size != 65552
            {
                return TestResult::Fail("PSP/executable split or metadata ABI");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_firmware_combined_footer_variants
);

fn dmub_firmware_legacy_metadata() -> TestResult {
    let mut bytes = combined(256, 0);
    let inst_size = bytes.len() - 256;
    // Erase the combined metadata; a legacy container finds it in BSS/data.
    let meta = bytes.len() - 256 - META_SIZE;
    bytes[meta..meta + META_SIZE].fill(0);
    bytes.extend_from_slice(&[0u8; 128]);
    let size = bytes.len();
    put32(&mut bytes, 0, size as u32);
    put32(&mut bytes, 20, (inst_size + 128) as u32);
    put32(&mut bytes, 36, 128);
    write_metadata(&mut bytes[size - 0x24 - META_SIZE..]);
    let Ok(image) = Image::parse(&bytes) else {
        return TestResult::Fail("legacy BSS metadata rejected");
    };
    if image.bss_data() != &bytes[size - 128..]
        || image.instructions().len() != 512
        || image.signed_instructions().len() != inst_size
        || image.prepare_dcn314(&[0; 512]).err() != Some(Error::UnsupportedLayout)
    {
        return TestResult::Fail("legacy split or unsupported DCN314 BSS mapping");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu-dmub", dmub_firmware_legacy_metadata);

fn dmub_firmware_rejects_truncation_and_bad_ranges() -> TestResult {
    let good = combined(256, 4);
    for len in 0..good.len() {
        if Image::parse(&good[..len]).is_ok() {
            return TestResult::Fail("truncated container accepted");
        }
    }
    for (offset, value) in [
        (0, u32::MAX),
        (4, 32),
        (8, 2),
        (8, 0x0001_0001),
        (20, u32::MAX),
        (24, 32),
        (24, u32::MAX),
        (32, PSP_HEADER_SIZE as u32),
        (32, u32::MAX),
        (36, 1),
        (36, u32::MAX),
    ] {
        let mut bytes = good.clone();
        put32(&mut bytes, offset, value);
        if Image::parse(&bytes).is_ok() {
            return TestResult::Fail("invalid header/range accepted");
        }
    }
    let mut extra = good;
    extra.push(0);
    if Image::parse(&extra).is_ok() {
        return TestResult::Fail("unaccounted trailing container data accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_firmware_rejects_truncation_and_bad_ranges
);

fn dmub_firmware_rejects_missing_or_unbounded_metadata() -> TestResult {
    let good = combined(256, 4);
    let meta = good.len() - 256 - 4 - META_SIZE;
    for (offset, value, expected) in [
        (0, 0, Error::MetadataMissing),
        (4, 0, Error::InvalidMetadata),
        (4, u32::MAX, Error::InvalidMetadata),
        (8, 0, Error::InvalidMetadata),
        (8, u32::MAX, Error::InvalidMetadata),
        (16, 0, Error::InvalidMetadata),
        (16, 2, Error::InvalidMetadata),
        (20, u32::MAX, Error::InvalidMetadata),
    ] {
        let mut bytes = good.clone();
        put32(&mut bytes, meta + offset, value);
        if Image::parse(&bytes).err() != Some(expected) {
            return TestResult::Fail("invalid metadata did not fail closed");
        }
    }
    // There is no arbitrary scan through executable bytes for a magic value.
    let bytes = combined(256, 16);
    if Image::parse(&bytes).err() != Some(Error::MetadataMissing) {
        return TestResult::Fail("out-of-ABI metadata location accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_firmware_rejects_missing_or_unbounded_metadata
);

fn dmub_firmware_layout_alignment_and_initialization() -> TestResult {
    let bytes = combined(512, 3);
    let vbios = vec![0x3c; 513];
    let prepared = Image::parse(&bytes)
        .unwrap()
        .prepare_dcn314(&vbios)
        .unwrap();
    let layout = prepared.layout();
    let mut end = 0;
    for region in layout.regions {
        if region.offset % 256 != 0 || region.size % 64 != 0 || region.offset < end {
            return TestResult::Fail("unaligned or overlapping cache window");
        }
        end = region.offset + region.size;
    }
    if layout.size() % 4096 != 0
        || layout.size() < end
        || layout.region(Window::Stack).size != 640 * 1024
        || layout.region(Window::BssData).size != 0
        || layout.region(Window::Mailbox).size != 16384
        || layout.region(Window::State).size != 51712
        || layout.region(Window::Trace).size != 65600
    {
        return TestResult::Fail("Linux region sizing mismatch");
    }
    let mut destination = vec![0xa5; layout.size() as usize + 64];
    if prepared.stage(&mut destination).is_err() {
        return TestResult::Fail("staging failed");
    }
    let bios_start = layout.region(Window::Vbios).offset as usize;
    let inst = prepared.image.instructions();
    for (offset, byte) in destination.iter().copied().enumerate() {
        let expected = if offset < inst.len() {
            inst[offset]
        } else if (bios_start..bios_start + vbios.len()).contains(&offset) {
            0x3c
        } else if offset >= layout.size() as usize {
            0xa5
        } else {
            0
        };
        if byte != expected {
            return TestResult::Fail("image copy, zeroing or destination boundary");
        }
    }
    destination.fill(0xa5);
    if prepared.stage(&mut destination[..layout.size() as usize - 1]) != Err(Error::BufferTooSmall)
        || destination.iter().any(|b| *b != 0xa5)
    {
        return TestResult::Fail("short destination was partially modified");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_firmware_layout_alignment_and_initialization
);

fn dmub_firmware_placement_requires_bounded_vram() -> TestResult {
    let bytes = combined(256, 0);
    let prepared = Image::parse(&bytes)
        .unwrap()
        .prepare_dcn314(&[0; 512])
        .unwrap();
    let layout = prepared.layout();
    let base = 0x1_0000_0000;
    let end = base + layout.size() as u64;
    let Ok(placement) = layout.place(base, base..end) else {
        return TestResult::Fail("exact-fit 64-bit VRAM placement rejected");
    };
    if placement.outbox() - placement.inbox() != 8192
        || placement.inbox() != base + layout.region(Window::Mailbox).offset as u64
    {
        return TestResult::Fail("mailbox address translation");
    }
    for (address, aperture) in [
        (base + 1, base..end + 4096),
        (base - 4096, base..end),
        (base, base..end - 1),
        (base, base..base),
        (u64::MAX & !4095, 0..u64::MAX),
        (1u64 << 48, 0..u64::MAX),
    ] {
        if layout.place(address, aperture).is_ok() {
            return TestResult::Fail("invalid VRAM placement accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_firmware_placement_requires_bounded_vram
);

fn dmub_firmware_unsupported_layout_and_bios_bounds() -> TestResult {
    let bytes = combined(256, 0);
    let image = Image::parse(&bytes).unwrap();
    if image.clone().prepare_dcn314(&[]).err() != Some(Error::InvalidSize)
        || image.prepare_dcn314(&vec![0; MAX_VBIOS_SIZE + 1]).err() != Some(Error::InvalidSize)
    {
        return TestResult::Fail("VBIOS storage bounds not enforced");
    }
    let mut bytes = bytes;
    let meta = bytes.len() - 256 - META_SIZE;
    put32(&mut bytes, meta + 20, 1024);
    if Image::parse(&bytes)
        .unwrap()
        .prepare_dcn314(&[0; 512])
        .err()
        != Some(Error::UnsupportedLayout)
    {
        return TestResult::Fail("unimplemented shared-state mapping accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_firmware_unsupported_layout_and_bios_bounds
);
