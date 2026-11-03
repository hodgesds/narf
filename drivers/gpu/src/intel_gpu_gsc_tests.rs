//! Byte-level vectors for the MTL GSC / GSC-headered HuC formats and the
//! GSC HECI protocol, built from the MIT Linux b90c984d structure layouts
//! (xe_uc_fw_abi.h, abi/gsc_*.h, instructions/xe_gsc_commands.h).

use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

/// A blob mutation and the refusal it must produce.
type Refusal = (fn(&mut Vec<u8>), GscError);

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// gsc_cpd_entry: NUL-padded 12-byte name, offset (bits 24:0), length.
fn cpd_entry(bytes: &mut [u8], at: usize, name: &str, offset: u32) {
    bytes[at..at + 12].fill(0);
    bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
    put32(bytes, at + 12, offset);
}

/// gsc_cpd_header_v2 with `entries` at `header_length`.
fn cpd_header(bytes: &mut [u8], at: usize, header_length: u8, entries: &[(&str, u32)]) {
    put32(bytes, at, 0x4450_4324);
    put32(bytes, at + 4, entries.len() as u32);
    bytes[at + 8] = 2;
    bytes[at + 9] = 1;
    bytes[at + 10] = header_length;
    for (index, (name, offset)) in entries.iter().enumerate() {
        cpd_entry(
            bytes,
            at + usize::from(header_length) + index * 24,
            name,
            *offset,
        );
    }
}

/// gsc_manifest_header fw_version and security_version.
fn manifest(bytes: &mut [u8], at: usize, version: Version, security: u32) {
    put32(bytes, at, 4);
    put16(bytes, at + 36, version.major);
    put16(bytes, at + 38, version.minor);
    put16(bytes, at + 40, version.patch);
    put16(bytes, at + 42, version.build);
    put32(bytes, at + 44, security);
}

/// uc_css_header: 32 header dwords plus a 64-dword key, 64-dword modulus
/// and one exponent dword; `ucode` uCode bytes.
fn css(bytes: &mut [u8], at: usize, ucode: u32, version: (u8, u8, u8)) {
    put32(bytes, at, 6);
    put32(bytes, at + 4, 32 + 64 + 64 + 1);
    put32(bytes, at + 8, 0x10000);
    put32(bytes, at + 16, 0x8086);
    put32(bytes, at + 24, 32 + 64 + 64 + 1 + ucode / 4);
    put32(bytes, at + 28, 64);
    put32(bytes, at + 32, 64);
    put32(bytes, at + 36, 1);
    put32(
        bytes,
        at + 64,
        u32::from(version.0) << 16 | u32::from(version.1) << 8 | u32::from(version.2),
    );
}

/// GSC image: layout pointers, boot1 at 0x100 (0x400 bytes) holding a BPDT
/// whose second entry is the RBE code partition (type bit 18 set) at +0x80;
/// its CPD names RBEP.man at +0x100 (Huffman bit set to prove the mask).
fn gsc_image(len: usize) -> Vec<u8> {
    let mut image = vec![0u8; len];
    put32(&mut image, 32, 0x100);
    put32(&mut image, 36, 0x400);
    put32(&mut image, 0x100, 0x55aa);
    put16(&mut image, 0x104, 2);
    put32(&mut image, 0x100 + 24, 0x0002);
    put32(&mut image, 0x100 + 28, 0x10);
    put32(&mut image, 0x100 + 36, 1 << 18 | 0x0001);
    put32(&mut image, 0x100 + 40, 0x80);
    put32(&mut image, 0x100 + 44, 0x300);
    cpd_header(
        &mut image,
        0x180,
        20,
        &[("FOO.man", 0x40), ("RBEP.man", 1 << 25 | 0x100)],
    );
    manifest(&mut image, 0x280, Version::new(102, 0, 10, 1499), 3);
    image
}

fn smoke_media_gsc_firmware_identities_and_compatibility_policy() -> TestResult {
    kt_assert_eq!(GSC_FIRMWARE, "i915/mtl_gsc_1.bin");
    kt_assert_eq!(HUC_FIRMWARE, "i915/mtl_huc_gsc.bin");
    kt_assert_eq!(GSC_WANTED, Version::new(102, 1, 0, 0));
    kt_assert_eq!(PRIVATE_BYTES, 4 * 1024 * 1024);
    kt_assert_eq!(
        (LOAD_WAIT_NS, AUTH_WAIT_NS, AUTH_RETRY_NS, AUTH_ATTEMPTS),
        (500_000_000, 100_000_000, 50_000_000, 5)
    );
    kt_assert_eq!(PACKET_HALF, 4096);
    // major_ver: only the compatibility major must match; an older minor
    // is a notice in xe_uc_fw_check_version_requirements, never a refusal.
    for ok in [
        Version::new(102, 1, 0, 0),
        Version::new(102, 0, 0, 0),
        Version::new(102, 7, 3, 0),
    ] {
        kt_assert_eq!(check_compatibility(ok), Ok(()));
    }
    for bad in [Version::new(101, 1, 0, 0), Version::new(103, 1, 0, 0)] {
        kt_assert_eq!(check_compatibility(bad), Err(GscError::NoExec));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_firmware_identities_and_compatibility_policy
);

/// xe_uc_fw.c::parse_gsc_layout -> parse_cpd_header("RBEP.man"), with every
/// source refusal in order.
fn smoke_media_gsc_layout_parse_and_every_refusal() -> TestResult {
    let image = gsc_image(0x1000);
    kt_assert_eq!(
        GscImage::parse(&image),
        Ok(GscImage {
            release: Version::new(102, 0, 10, 1499),
            security_version: 3,
            size: 0x1000,
        })
    );
    // Too small for the layout pointers.
    kt_assert_eq!(GscImage::parse(&image[..79]), Err(GscError::NoData));
    let refusals: [Refusal; 9] = [
        // boot1 extends past the blob.
        (|i| put32(i, 36, 0x1000), GscError::NoData),
        (|i| put32(i, 32, 0xffff_ff00), GscError::NoData),
        // boot1 too small for the BPDT header, then a bad signature.
        (|i| put32(i, 36, 16), GscError::NoData),
        (|i| put32(i, 0x100, 0x55ab), GscError::Invalid),
        // Too many BPDT entries for boot1.
        (|i| put16(i, 0x104, 100), GscError::NoData),
        // No RBE entry at all; an RBE partition past boot1.
        (|i| put32(i, 0x100 + 36, 1 << 18 | 0x0002), GscError::NoData),
        (|i| put32(i, 0x100 + 40, 0x500), GscError::NoData),
        // The RBE partition is not a CPD (-ENOENT propagates); no manifest.
        (|i| put32(i, 0x180, 0), GscError::NotCpd),
        (
            |i| cpd_entry(i, 0x180 + 20 + 24, "RBEP.mam", 0x100),
            GscError::NoData,
        ),
    ];
    for (corrupt, error) in refusals {
        let mut bad = image.clone();
        corrupt(&mut bad);
        kt_assert_eq!(GscImage::parse(&bad), Err(error));
    }
    // A CPD name without its NUL terminator is not a strcmp match.
    let mut bad = image.clone();
    cpd_entry(&mut bad, 0x180 + 20 + 24, "RBEP.manX", 0x100);
    kt_assert_eq!(GscImage::parse(&bad), Err(GscError::NoData));
    // Larger than the GSC private object.
    let mut large = gsc_image(PRIVATE_BYTES + 4);
    kt_assert_eq!(GscImage::parse(&large), Err(GscError::TooLarge));
    large.truncate(PRIVATE_BYTES);
    kt_assert_eq!(GscImage::parse(&large).map(|i| i.size), Ok(PRIVATE_BYTES));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_layout_parse_and_every_refusal
);

/// HuC CPD with a 24-byte header: huc_fw CSS at 0x200, HUCP.man at 0x100.
fn huc_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x800];
    cpd_header(
        &mut image,
        0,
        24,
        &[("huc_fw", 0x200), ("HUCP.man", 0x100), ("other", 0)],
    );
    manifest(&mut image, 0x100, Version::new(8, 5, 4, 1), 0);
    css(&mut image, 0x200, 1024, (8, 5, 3));
    image
}

/// xe_uc_fw.c::parse_headers for a HuC: CPD (HUCP.man, huc_fw) with the
/// CSS overriding the manifest's release version, or a whole-file CSS
/// without a CPD marker; every parse_cpd_header/parse_css_header refusal.
fn smoke_media_huc_gsc_image_versions_offsets_and_refusals() -> TestResult {
    let image = huc_image();
    let huc = HucImage::parse(&image);
    kt_assert_eq!(
        huc,
        Ok(HucImage {
            release: Version::new(8, 5, 3, 0),
            css_offset: 0x200,
            ucode_size: 1024,
            rsa_size: 256,
            gsc_headers: true,
            size: 0x800,
        })
    );
    let Ok(huc) = huc else {
        return TestResult::Fail("GSC-headered HuC refused");
    };
    kt_assert_eq!(huc.dma_bytes(), 128 + 1024);
    kt_assert_eq!(huc.rsa_offset(), 0x200 + 128 + 1024);
    // The manifest alone, as parse_cpd_header records it before the CSS.
    let cpd = parse_cpd(&image, "HUCP.man", None);
    kt_assert_eq!(
        cpd.map(|c| (c.manifest, c.css)),
        Ok((Version::new(8, 5, 4, 1), None))
    );
    let refusals: [Refusal; 9] = [
        (|i| i[10] = 16, GscError::Invalid),
        (|i| put32(i, 4, 1000), GscError::NoData),
        (
            |i| cpd_entry(i, 24 + 24, "HUCP.mam", 0x100),
            GscError::NoData,
        ),
        (
            |i| cpd_entry(i, 24 + 24, "HUCP.man", 0x7c0),
            GscError::NoData,
        ),
        (|i| cpd_entry(i, 24, "huc_fw", 0x900), GscError::NoData),
        (|i| cpd_entry(i, 24, "huc_fw", 0x7c0), GscError::NoData),
        // CSS header-size integrity, then sizes beyond the blob.
        (|i| put32(i, 0x200 + 36, 2), GscError::Protocol),
        (|i| put32(i, 0x200 + 24, 0x10000), GscError::NoExec),
        // No huc_fw entry: offset 0 parses the CPD header itself as CSS.
        (|i| cpd_entry(i, 24, "huc_fx", 0x200), GscError::Protocol),
    ];
    for (corrupt, error) in refusals {
        let mut bad = image.clone();
        corrupt(&mut bad);
        kt_assert_eq!(HucImage::parse(&bad), Err(error));
    }
    // No CPD marker: a plain CSS HuC without GSC headers (GSC auth then
    // has no packet object, -ENODEV in huc_auth_via_gsccs).
    let plain = image[0x200..].to_vec();
    kt_assert_eq!(
        HucImage::parse(&plain),
        Ok(HucImage {
            release: Version::new(8, 5, 3, 0),
            css_offset: 0,
            ucode_size: 1024,
            rsa_size: 256,
            gsc_headers: false,
            size: 0x600,
        })
    );
    kt_assert_eq!(HucImage::parse(&plain[..127]), Err(GscError::NoData));
    kt_assert_eq!(HucImage::parse(&plain[..0x400]), Err(GscError::NoExec));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_huc_gsc_image_versions_offsets_and_refusals
);

fn reply(size: u32, status: u32, payload: &[u8]) -> Vec<u8> {
    let mut reply = vec![0u8; 4096];
    put32(&mut reply, 0, 0xa578_875a);
    put32(&mut reply, 24, size);
    put32(&mut reply, 32, status);
    reply[36..36 + payload.len()].copy_from_slice(payload);
    reply
}

/// xe_gsc_submit.c header/batch helpers, the MKHI compatibility query and
/// the PXP 4.3 NEW_HUC_AUTH packet, byte for byte.
fn smoke_media_gsc_heci_packets_follow_xe_gsc_submit() -> TestResult {
    kt_assert_eq!(HEADER, 36);
    kt_assert_eq!(GSC_HECI_CMD_PKT, 0x4000_0006);
    kt_assert_eq!(GSC_FW_LOAD, 0x4040_0002);
    let mut out = [0xffu8; 64];
    kt_assert_eq!(emit_header(&mut out, HECI_PXP, 0, 28), Ok(36));
    let mut header = vec![0u8; 36];
    put32(&mut header, 0, 0xa578_875a);
    header[4] = 17;
    put16(&mut header, 6, 1);
    put32(&mut header, 24, 64);
    kt_assert_eq!(&out[..36], &header[..]);
    kt_assert_eq!(&out[36..], &[0xff; 28]);
    kt_assert_eq!(emit_header(&mut out, HECI_MKHI, 0x1234, 4), Ok(36));
    kt_assert_eq!(
        u64::from_le_bytes(out[8..16].try_into().unwrap()),
        7 << 56 | 0x1234
    );
    kt_assert_eq!(
        emit_header(&mut out, HECI_PXP, 1 << 56, 0),
        Err(GscError::Invalid)
    );
    kt_assert_eq!(
        emit_header(&mut out[..35], HECI_PXP, 0, 0),
        Err(GscError::Invalid)
    );
    // xe_gsc_read_out_header: marker, then status, then sizes.
    kt_assert_eq!(read_out_header(&reply(56, 0, &[]), 20), Ok(36));
    let mut bad = reply(56, 1, &[]);
    put32(&mut bad, 0, 0);
    kt_assert_eq!(read_out_header(&bad, 0), Err(GscError::Protocol));
    kt_assert_eq!(
        read_out_header(&reply(56, 1, &[]), 0),
        Err(GscError::Invalid)
    );
    kt_assert_eq!(
        read_out_header(&reply(35, 0, &[]), 0),
        Err(GscError::NoData)
    );
    kt_assert_eq!(
        read_out_header(&reply(55, 0, &[]), 20),
        Err(GscError::NoData)
    );
    // Pending replies hand their message handle to the resubmission.
    let mut input = [0u8; 64];
    let mut pending = reply(52, 0, &[]);
    put32(&mut pending, 28, 1);
    put64(&mut pending, 16, 0xfeed_beef_0000_0042);
    kt_assert!(check_and_update_pending(&mut input, &pending));
    kt_assert_eq!(
        u64::from_le_bytes(input[16..24].try_into().unwrap()),
        0xfeed_beef_0000_0042
    );
    let mut untouched = [0u8; 64];
    kt_assert!(!check_and_update_pending(
        &mut untouched,
        &reply(52, 0, &[])
    ));
    kt_assert_eq!(untouched, [0u8; 64]);
    // xe_gsc_pkt_submit_kernel and emit_gsc_upload batches.
    kt_assert_eq!(
        heci_packet(0x1_2345_6000, 64, 0x1_2345_7000, 4096),
        Ok([0x4000_0006, 0x2345_6000, 1, 64, 0x2345_7000, 1, 4096, 0])
    );
    kt_assert_eq!(heci_packet(0, 35, 0, 35), Err(GscError::NoData));
    kt_assert_eq!(heci_packet(0, 36, 0, 35), Err(GscError::NoMemory));
    kt_assert_eq!(
        fw_load(0x1_2340_0000, PRIVATE_BYTES),
        [0x4040_0002, 0x2340_0000, 1, 1024 | 1 << 31]
    );
    // MKHI GFX_SRV GET_HOST_COMPATIBILITY_VERSION and its reply.
    let mut query = [0xaau8; 4096];
    kt_assert_eq!(compatibility_query(&mut query), Ok(40));
    kt_assert_eq!(
        (
            query[4],
            u32::from_le_bytes(query[24..28].try_into().unwrap())
        ),
        (7, 40)
    );
    kt_assert_eq!(&query[36..40], &[0x30, 0x42, 0, 0]);
    let compat = [
        0x30, 0x42, 0, 0, 102, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    kt_assert_eq!(
        compatibility_reply(&reply(56, 0, &compat)),
        Ok(Version::new(102, 1, 0, 0))
    );
    kt_assert_eq!(
        compatibility_reply(&reply(55, 0, &compat)),
        Err(GscError::NoData)
    );
    // PXP 4.3 NEW_HUC_AUTH: the whole HuC object's address and size.
    let mut auth = [0xaau8; 4096];
    kt_assert_eq!(huc_auth_request(&mut auth, 0x1_0000_2000, 0x8000), Ok(64));
    kt_assert_eq!(
        (
            auth[4],
            u32::from_le_bytes(auth[24..28].try_into().unwrap())
        ),
        (17, 64)
    );
    let mut message = vec![0u8; 28];
    put32(&mut message, 0, 0x0004_0003);
    put32(&mut message, 4, 0x3f);
    put32(&mut message, 12, 12);
    put64(&mut message, 16, 0x1_0000_2000);
    put32(&mut message, 24, 0x8000);
    kt_assert_eq!(&auth[36..64], &message[..]);
    kt_assert_eq!(&auth[64..68], &[0xaa; 4]);
    for (status, result) in [
        (0, Ok(())),
        (0x4013, Ok(())),
        (0x1002, Err(GscError::Io)),
        (0x100e, Err(GscError::Io)),
    ] {
        let mut out = [0u8; 16];
        put32(&mut out, 8, status);
        kt_assert_eq!(huc_auth_reply(&reply(52, 0, &out)), result);
    }
    kt_assert_eq!(
        huc_auth_reply(&reply(51, 0, &[0; 16])),
        Err(GscError::NoData)
    );
    kt_assert_eq!(
        huc_auth_reply(&reply(52, 5, &[0; 16])),
        Err(GscError::Invalid)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_heci_packets_follow_xe_gsc_submit
);

struct Regs(RefCell<BTreeMap<u64, u32>>);
impl MmioWindow for Regs {
    fn read32(&self, offset: u64) -> u32 {
        *self.0.borrow().get(&offset).unwrap_or(&0)
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("HuC authentication status is read-only");
    }
}

/// xe_huc.c huc_auth_modes through the media GT's MMIO view: the GuC mode's
/// HUC_KERNEL_LOAD_INFO is GSI-adjusted, the GSC mode's HECI1 FWSTS5 is not.
fn smoke_media_huc_auth_modes_read_gt1_registers() -> TestResult {
    let regs = Regs(RefCell::new(BTreeMap::new()));
    let media = crate::intel_gpu_gt::media::MediaWindow::new(&regs);
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Guc), Some(false));
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Gsc), Some(false));
    // GT0's HUC_KERNEL_LOAD_INFO and a GSI-shifted FWSTS5 do not count.
    regs.0.borrow_mut().insert(0xc1dc, 1);
    regs.0.borrow_mut().insert(0x116c68 + 0x380000, 1 << 19);
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Guc), Some(false));
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Gsc), Some(false));
    regs.0.borrow_mut().insert(0x38c1dc, 1);
    regs.0.borrow_mut().insert(0x116c68, 1 << 19);
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Guc), Some(true));
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Gsc), Some(true));
    // Lost MMIO is never authentication.
    regs.0.borrow_mut().insert(0x38c1dc, u32::MAX);
    regs.0.borrow_mut().insert(0x116c68, u32::MAX);
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Guc), None);
    kt_assert_eq!(huc_authenticated(&media, HucAuth::Gsc), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_huc_auth_modes_read_gt1_registers
);
