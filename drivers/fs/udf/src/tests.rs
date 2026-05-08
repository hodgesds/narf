//! Kernel-test entries for the UDF driver.
//!
//! Pure-logic tests cover the Descriptor Tag header, the AVDP tag
//! identifier, FID decode, icb_tag flag/file-type recognition, and
//! both short_ad / long_ad allocation-descriptor decode. The
//! end-to-end test builds a minimal UDF image entirely in heap
//! memory — AVDP at sector 256, Main VDS at sectors 32+, FSD in
//! the partition data, root-directory File Entry + FID stream, and
//! one regular file File Entry + body — wraps it in
//! `RamBlockDevice`, mounts via `UdfVolume::mount`, enumerates the
//! root, opens a file, and reads the bytes back.
//!
//! References (test fixture layout — same set as the rest of the
//! crate; no GPL/LGPL UDF code consulted):
//! - ECMA-167 §3/7.2 (Descriptor Tag — TagChecksum + DescriptorCRC).
//! - ECMA-167 §3/10.2 (AVDP layout — Main + Reserve VDS extent_ad
//!   pair).
//! - ECMA-167 §3/10.5 (Partition Descriptor — partition_starting_
//!   location + partition_length).
//! - ECMA-167 §3/10.6 (LVD — fixed 440-byte header + partition map
//!   array).
//! - ECMA-167 §3/10.7.2 (Type-1 partition map — 6-byte map: type=1,
//!   length=6, volume_seq, partition_number).
//! - ECMA-167 §3/10.9 (Terminating Descriptor).
//! - ECMA-167 §4/14.1 (FSD — root_directory_icb at offset 400).
//! - ECMA-167 §4/14.4 (FID — 38-byte fixed header + L_IU + L_FI +
//!   pad-to-4).
//! - ECMA-167 §4/14.6 (icb_tag — 20-byte block, file_type byte at
//!   offset 11 within the block).
//! - ECMA-167 §4/14.9 (File Entry — InformationLength at offset
//!   56, L_EA at 168, L_AD at 172, AD area starts at offset 176).
//! - ECMA-167 §4/14.14.2 (long_ad — 16 bytes).

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::descriptor::{
    crc_ccitt, read_anchor, read_descriptor_tag, tag_checksum, tag_id,
    LogicalVolumeDescriptorHeader,
};
use super::fid::{decode_fid, decode_identifier};
use super::icb::{
    ad_type, file_type, flags as icb_flags, read_long_ad, read_short_ad,
};
use super::SECTOR_SIZE;

// ── Pure-logic smokes ──────────────────────────────────────────────

fn smoke_udf_tag_id_constants() -> TestResult {
    // ECMA-167 §3/7.2.1 — TagIdentifier values. Spot-check the ones
    // we depend on at mount time + during the directory walk.
    if tag_id::ANCHOR_VOLUME_DESCRIPTOR_POINTER != 2 {
        return TestResult::Fail("AVDP tag id must be 2");
    }
    if tag_id::PRIMARY_VOLUME_DESCRIPTOR != 1 {
        return TestResult::Fail("PVD tag id must be 1");
    }
    if tag_id::PARTITION_DESCRIPTOR != 5 {
        return TestResult::Fail("Partition Descriptor tag id must be 5");
    }
    if tag_id::LOGICAL_VOLUME_DESCRIPTOR != 6 {
        return TestResult::Fail("LVD tag id must be 6");
    }
    if tag_id::TERMINATING_DESCRIPTOR != 8 {
        return TestResult::Fail("Terminating Descriptor tag id must be 8");
    }
    if tag_id::FILE_SET_DESCRIPTOR != 256 {
        return TestResult::Fail("FSD tag id must be 256");
    }
    if tag_id::FILE_IDENTIFIER_DESCRIPTOR != 257 {
        return TestResult::Fail("FID tag id must be 257");
    }
    if tag_id::FILE_ENTRY != 261 {
        return TestResult::Fail("File Entry tag id must be 261");
    }
    if tag_id::EXTENDED_FILE_ENTRY != 266 {
        return TestResult::Fail("Extended File Entry tag id must be 266");
    }
    TestResult::Pass
}

fn smoke_udf_descriptor_tag_decode() -> TestResult {
    // ECMA-167 §3/7.2 — hand-build a 16-byte tag with TagId=2 (AVDP),
    // TagSerial=0x1234, TagLocation=256, valid TagChecksum, then
    // decode it through the public helper.
    let mut buf = [0u8; 16];
    // tag_identifier = 2 (AVDP)
    buf[0..2].copy_from_slice(&2u16.to_le_bytes());
    // descriptor_version = 2
    buf[2..4].copy_from_slice(&2u16.to_le_bytes());
    // tag_checksum left as zero — we'll recompute below.
    // reserved (offset 5) stays zero.
    buf[6..8].copy_from_slice(&0x1234u16.to_le_bytes());
    // descriptor_crc + descriptor_crc_length stay zero.
    buf[12..16].copy_from_slice(&256u32.to_le_bytes());
    let cs = tag_checksum(&buf);
    buf[4] = cs;

    let tag = read_descriptor_tag(&buf, 0);
    if tag.tag_identifier != 2 {
        return TestResult::Fail("tag_identifier round-trip mismatch");
    }
    if tag.descriptor_version != 2 {
        return TestResult::Fail("descriptor_version round-trip mismatch");
    }
    if tag.tag_serial_number != 0x1234 {
        return TestResult::Fail("tag_serial_number round-trip mismatch");
    }
    if tag.tag_location != 256 {
        return TestResult::Fail("tag_location round-trip mismatch");
    }
    // The checksum byte must equal the recomputed sum-of-bytes (mod
    // 256) excluding byte 4 itself. Verify that re-running the
    // function on the live buffer reproduces the stored value.
    if tag_checksum(&buf) != tag.tag_checksum {
        return TestResult::Fail("tag_checksum recomputation mismatch");
    }
    TestResult::Pass
}

fn smoke_udf_avdp_recognition() -> TestResult {
    // ECMA-167 §3/10.2 — fill a 512-byte AVDP starting with the
    // 16-byte tag (TagId=2), Main VDS extent_ad at offset 16, Reserve
    // at offset 24. Round-trip the tag identifier through `read_anchor`.
    let mut buf = vec![0u8; SECTOR_SIZE];
    buf[0..2].copy_from_slice(&2u16.to_le_bytes()); // AVDP
    buf[2..4].copy_from_slice(&2u16.to_le_bytes());
    buf[12..16].copy_from_slice(&256u32.to_le_bytes());
    buf[4] = tag_checksum(buf[..16].try_into().unwrap());
    // Main VDS extent_ad: length=0x4000 (8 sectors), location=32.
    buf[16..20].copy_from_slice(&0x4000u32.to_le_bytes());
    buf[20..24].copy_from_slice(&32u32.to_le_bytes());
    // Reserve VDS: length=0x4000, location=48.
    buf[24..28].copy_from_slice(&0x4000u32.to_le_bytes());
    buf[28..32].copy_from_slice(&48u32.to_le_bytes());

    let avdp = read_anchor(&buf);
    if avdp.tag.tag_identifier != tag_id::ANCHOR_VOLUME_DESCRIPTOR_POINTER {
        return TestResult::Fail("AVDP tag identifier mismatch");
    }
    if avdp.main_vds.extent_length != 0x4000 || avdp.main_vds.extent_location != 32 {
        return TestResult::Fail("Main VDS extent_ad mismatch");
    }
    if avdp.reserve_vds.extent_length != 0x4000 || avdp.reserve_vds.extent_location != 48 {
        return TestResult::Fail("Reserve VDS extent_ad mismatch");
    }
    TestResult::Pass
}

fn smoke_udf_short_long_ad_decode() -> TestResult {
    // ECMA-167 §4/14.14.1 — short_ad (8 bytes).
    // §4/14.14.2 — long_ad (16 bytes).
    let mut buf = [0u8; 24];
    // short_ad: extent_length_raw = 0x40000800 (type 1 = NOT_RECORDED
    // _BUT_ALLOCATED, length 0x800), extent_position = 100.
    let raw_short = (1u32 << 30) | 0x800;
    buf[0..4].copy_from_slice(&raw_short.to_le_bytes());
    buf[4..8].copy_from_slice(&100u32.to_le_bytes());
    let s = read_short_ad(&buf, 0);
    if s.extent_type() != ad_type::NOT_RECORDED_BUT_ALLOCATED {
        return TestResult::Fail("short_ad extent_type mismatch");
    }
    if s.extent_length() != 0x800 {
        return TestResult::Fail("short_ad extent_length mismatch");
    }
    if s.extent_position != 100 {
        return TestResult::Fail("short_ad extent_position mismatch");
    }
    // long_ad: extent_length_raw = 0x1000 (RECORDED, length 0x1000),
    // LBN = 50, partition_ref = 0, implementation_use = [0xAA; 6].
    buf[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[12..16].copy_from_slice(&50u32.to_le_bytes());
    buf[16..18].copy_from_slice(&0u16.to_le_bytes());
    for i in 0..6 {
        buf[18 + i] = 0xAA;
    }
    let l = read_long_ad(&buf, 8);
    if l.extent_type() != ad_type::RECORDED {
        return TestResult::Fail("long_ad extent_type mismatch");
    }
    if l.extent_length() != 0x1000 {
        return TestResult::Fail("long_ad extent_length mismatch");
    }
    if l.extent_lbn != 50 {
        return TestResult::Fail("long_ad extent_lbn mismatch");
    }
    if l.partition_ref != 0 {
        return TestResult::Fail("long_ad partition_ref mismatch");
    }
    if l.implementation_use != [0xAA; 6] {
        return TestResult::Fail("long_ad implementation_use mismatch");
    }
    TestResult::Pass
}

fn smoke_udf_icb_flag_constants() -> TestResult {
    // ECMA-167 §4/14.6.6 — file_type byte values + §4/14.6.8 — flag
    // bits (low 3 bits select the AD format).
    if file_type::DIRECTORY != 4 {
        return TestResult::Fail("file_type::DIRECTORY must be 4");
    }
    if file_type::REGULAR_FILE != 5 {
        return TestResult::Fail("file_type::REGULAR_FILE must be 5");
    }
    if file_type::SYMBOLIC_LINK != 10 {
        return TestResult::Fail("file_type::SYMBOLIC_LINK must be 10");
    }
    if icb_flags::ALLOC_DESC_TYPE_MASK != 0b111 {
        return TestResult::Fail("flags ALLOC_DESC_TYPE_MASK must be 0b111");
    }
    if icb_flags::ALLOC_TYPE_LONG != 1 {
        return TestResult::Fail("ALLOC_TYPE_LONG must be 1");
    }
    if icb_flags::ALLOC_TYPE_EMBEDDED != 3 {
        return TestResult::Fail("ALLOC_TYPE_EMBEDDED must be 3");
    }
    TestResult::Pass
}

fn smoke_udf_fid_decode() -> TestResult {
    // ECMA-167 §4/14.4 — build one FID for a regular file named
    // "TEST.TXT": L_IU = 0, identifier bytes = "\x08TEST.TXT" (the
    // 0x08 byte is the CompressionID for plain 8-bit characters).
    //
    // Layout:
    //   0  16  Descriptor Tag (TagId=257)
    //  16   2  FileVersionNumber = 1
    //  18   1  FileCharacteristics = 0
    //  19   1  L_FI = 9 (1 compression byte + "TEST.TXT")
    //  20  16  ICB long_ad (extent_length=0x800, lbn=42, partition=0)
    //  36   2  L_IU = 0
    //  38   9  identifier bytes
    //  47   1  pad to 4-byte boundary
    let mut buf = vec![0u8; 64];
    // Tag (only TagId is checked by `decode_fid`; checksum + CRC
    // can be left zero in unit tests).
    buf[0..2].copy_from_slice(&257u16.to_le_bytes());
    buf[2..4].copy_from_slice(&2u16.to_le_bytes());
    // FileVersionNumber
    buf[16..18].copy_from_slice(&1u16.to_le_bytes());
    // FileCharacteristics (regular file).
    buf[18] = 0;
    // L_FI = 9.
    buf[19] = 9;
    // ICB long_ad (offset 20).
    buf[20..24].copy_from_slice(&0x800u32.to_le_bytes());
    buf[24..28].copy_from_slice(&42u32.to_le_bytes());
    buf[28..30].copy_from_slice(&0u16.to_le_bytes());
    // L_IU at offset 36.
    buf[36..38].copy_from_slice(&0u16.to_le_bytes());
    // Identifier (offset 38..47): CompressionID 8 then "TEST.TXT".
    buf[38] = 8;
    buf[39..47].copy_from_slice(b"TEST.TXT");
    // Padding byte at 47 is already zero.

    let fid = match decode_fid(&buf, 0) {
        Ok(f) => f,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("decode_fid returned an error");
        }
    };
    if fid.identifier != "TEST.TXT" {
        return TestResult::Fail("FID identifier mismatch");
    }
    if fid.is_directory() {
        return TestResult::Fail("FID directory bit must be clear");
    }
    if fid.icb.extent_lbn != 42 {
        return TestResult::Fail("FID ICB lbn mismatch");
    }
    if fid.record_length != 48 {
        return TestResult::Fail("FID record_length must round 47 up to 48");
    }
    // Decode-only check on the raw identifier bytes too.
    if decode_identifier(b"\x08HI") != "HI" {
        return TestResult::Fail("decode_identifier 8-bit mismatch");
    }
    if decode_identifier(b"") != "" {
        return TestResult::Fail("decode_identifier empty mismatch");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/udf", smoke_udf_tag_id_constants);
kernel_test_in!("drivers/fs/udf", smoke_udf_descriptor_tag_decode);
kernel_test_in!("drivers/fs/udf", smoke_udf_avdp_recognition);
kernel_test_in!("drivers/fs/udf", smoke_udf_short_long_ad_decode);
kernel_test_in!("drivers/fs/udf", smoke_udf_icb_flag_constants);
kernel_test_in!("drivers/fs/udf", smoke_udf_fid_decode);

// ── End-to-end mount + enumerate + read against RamBlockDevice ────

/// Synchronous-only future poll. `RamBlockDevice::submit` returns
/// `Ready` after the in-memory copy, so every UDF operation we
/// drive in tests completes on the first poll.
fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Compute Descriptor Tag CRC-CCITT over the body bytes and write
/// the four CRC fields (descriptor_crc, descriptor_crc_length) into
/// the tag header at `tag_off` in `buf`. Also writes the
/// TagChecksum byte. `body_off` and `body_len` describe the body
/// region the CRC should cover.
fn finalise_tag(buf: &mut [u8], tag_off: usize, body_off: usize, body_len: usize) {
    let crc = crc_ccitt(&buf[body_off..body_off + body_len]);
    buf[tag_off + 8..tag_off + 10].copy_from_slice(&crc.to_le_bytes());
    buf[tag_off + 10..tag_off + 12]
        .copy_from_slice(&(body_len as u16).to_le_bytes());
    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(&buf[tag_off..tag_off + 16]);
    let cs = tag_checksum(&tag_bytes);
    buf[tag_off + 4] = cs;
}

/// Write a 16-byte Descriptor Tag header at `tag_off` (the
/// descriptor_crc / descriptor_crc_length / tag_checksum bytes are
/// finalised in a second pass via `finalise_tag` once the body is
/// in place).
fn write_tag_header(
    buf: &mut [u8],
    tag_off: usize,
    tag_id_value: u16,
    tag_serial: u16,
    tag_location: u32,
) {
    buf[tag_off..tag_off + 2].copy_from_slice(&tag_id_value.to_le_bytes());
    // DescriptorVersion = 2.
    buf[tag_off + 2..tag_off + 4].copy_from_slice(&2u16.to_le_bytes());
    // checksum (offset 4) zero for now.
    buf[tag_off + 4] = 0;
    // reserved (offset 5).
    buf[tag_off + 5] = 0;
    buf[tag_off + 6..tag_off + 8].copy_from_slice(&tag_serial.to_le_bytes());
    // crc + crc_length zero — finalised later.
    buf[tag_off + 8..tag_off + 12].copy_from_slice(&[0u8; 4]);
    buf[tag_off + 12..tag_off + 16].copy_from_slice(&tag_location.to_le_bytes());
}

/// Encode a long_ad at `dst[off..off+16]`.
fn write_long_ad(
    dst: &mut [u8],
    off: usize,
    extent_length_raw: u32,
    lbn: u32,
    partition_ref: u16,
) {
    dst[off..off + 4].copy_from_slice(&extent_length_raw.to_le_bytes());
    dst[off + 4..off + 8].copy_from_slice(&lbn.to_le_bytes());
    dst[off + 8..off + 10].copy_from_slice(&partition_ref.to_le_bytes());
    for i in 0..6 {
        dst[off + 10 + i] = 0;
    }
}

/// Encode one FID into `dst[off..]`. Returns the total bytes
/// consumed (already padded to a 4-byte boundary).
fn write_fid(
    dst: &mut [u8],
    off: usize,
    file_characteristics: u8,
    icb_lbn: u32,
    icb_partition: u16,
    icb_length_bytes: u32,
    name: &[u8], // 8-bit ASCII identifier (no compression byte)
    tag_location: u32,
) -> usize {
    let l_fi = if name.is_empty() { 0 } else { 1 + name.len() };
    let l_iu = 0usize;
    let raw_len = 38 + l_iu + l_fi;
    let total = (raw_len + 3) & !3;

    write_tag_header(dst, off, tag_id::FILE_IDENTIFIER_DESCRIPTOR, 1, tag_location);
    dst[off + 16..off + 18].copy_from_slice(&1u16.to_le_bytes()); // FileVersionNumber
    dst[off + 18] = file_characteristics;
    dst[off + 19] = l_fi as u8;
    write_long_ad(dst, off + 20, icb_length_bytes, icb_lbn, icb_partition);
    dst[off + 36..off + 38].copy_from_slice(&(l_iu as u16).to_le_bytes());
    if l_fi > 0 {
        dst[off + 38] = 8; // CompressionID 8
        dst[off + 39..off + 39 + name.len()].copy_from_slice(name);
    }
    // Pad bytes beyond raw_len already zero.
    finalise_tag(dst, off, off + 16, raw_len - 16);
    total
}

/// Build a minimal valid UDF image with one regular file in the
/// root directory. Layout:
///
/// ```text
/// sectors  0..32   System area (zeros).
/// sector  32       Primary Volume Descriptor (tag 1).
/// sector  33       Implementation Use VD (tag 4).
/// sector  34       Partition Descriptor (tag 5).
/// sector  35       Logical Volume Descriptor (tag 6).
/// sector  36       Unallocated Space Descriptor (tag 7).
/// sector  37       Terminating Descriptor (tag 8).
/// sector 256       Anchor Volume Descriptor Pointer (tag 2).
/// sector 257       File Set Descriptor (tag 256). Partition starts here.
/// sector 258       Root Directory File Entry (tag 261).
/// sector 259       Root Directory FID stream (parent + one file).
/// sector 260       Regular file File Entry (tag 261).
/// sector 261       Regular file body.
/// ```
///
/// Returns `(image_bytes, file_payload)`.
fn build_udf_image() -> (Vec<u8>, &'static [u8]) {
    const TOTAL_SECTORS: usize = 264;
    let mut img = vec![0u8; SECTOR_SIZE * TOTAL_SECTORS];
    let payload: &'static [u8] = b"narf-udf\n";

    // ── Partition layout ──────────────────────────────────────
    // The single Type-1 partition starts at sector 257 (so its
    // LBN 0 = sector 257, LBN 1 = 258, etc.).
    let partition_start: u32 = 257;
    let partition_length: u32 = (TOTAL_SECTORS as u32) - partition_start;

    // ICBs / data within the partition (LBNs).
    let fsd_lbn: u32 = 0; // sector 257
    let root_fe_lbn: u32 = 1; // sector 258
    let root_data_lbn: u32 = 2; // sector 259
    let file_fe_lbn: u32 = 3; // sector 260
    let file_data_lbn: u32 = 4; // sector 261

    // ── Sector 32: Primary Volume Descriptor (tag 1) ──────────
    let pvd_off = 32 * SECTOR_SIZE;
    write_tag_header(&mut img, pvd_off, tag_id::PRIMARY_VOLUME_DESCRIPTOR, 1, 32);
    // Body: at minimum we need 16+ bytes after the tag for the CRC.
    // We finalise over a small window — the mount path doesn't
    // actually verify CRCs, but writing a real one keeps the fixture
    // honest for a future hardening pass.
    let pvd_body_len = 64;
    finalise_tag(&mut img, pvd_off, pvd_off + 16, pvd_body_len);

    // ── Sector 33: Implementation Use VD (tag 4) ──────────────
    let iuvd_off = 33 * SECTOR_SIZE;
    write_tag_header(&mut img, iuvd_off, tag_id::IMPLEMENTATION_USE_VD, 1, 33);
    finalise_tag(&mut img, iuvd_off, iuvd_off + 16, 64);

    // ── Sector 34: Partition Descriptor (tag 5) ───────────────
    let pd_off = 34 * SECTOR_SIZE;
    write_tag_header(&mut img, pd_off, tag_id::PARTITION_DESCRIPTOR, 1, 34);
    // Body fields used by the driver: starting_location (offset 188),
    // length (offset 192). See descriptor.rs `PartitionDescriptor`.
    img[pd_off + 188..pd_off + 192]
        .copy_from_slice(&partition_start.to_le_bytes());
    img[pd_off + 192..pd_off + 196]
        .copy_from_slice(&partition_length.to_le_bytes());
    // partition_number at offset 22.
    img[pd_off + 22..pd_off + 24].copy_from_slice(&0u16.to_le_bytes());
    finalise_tag(&mut img, pd_off, pd_off + 16, 496);

    // ── Sector 35: Logical Volume Descriptor (tag 6) ──────────
    let lvd_off = 35 * SECTOR_SIZE;
    write_tag_header(&mut img, lvd_off, tag_id::LOGICAL_VOLUME_DESCRIPTOR, 1, 35);
    // logical_block_size at offset 16+4+64+128 = 212.
    let lbs_off = lvd_off
        + core::mem::offset_of!(LogicalVolumeDescriptorHeader, logical_block_size);
    img[lbs_off..lbs_off + 4].copy_from_slice(&(SECTOR_SIZE as u32).to_le_bytes());
    // logical_volume_contents_use long_ad → FSD at (LBN 0, partition 0).
    let lvcu_off = lvd_off
        + core::mem::offset_of!(LogicalVolumeDescriptorHeader, logical_volume_contents_use);
    write_long_ad(&mut img, lvcu_off, SECTOR_SIZE as u32, fsd_lbn, 0);
    // map_table_length = 6, number_of_partition_maps = 1.
    let mtl_off = lvd_off
        + core::mem::offset_of!(LogicalVolumeDescriptorHeader, map_table_length);
    img[mtl_off..mtl_off + 4].copy_from_slice(&6u32.to_le_bytes());
    let nopm_off = lvd_off
        + core::mem::offset_of!(LogicalVolumeDescriptorHeader, number_of_partition_maps);
    img[nopm_off..nopm_off + 4].copy_from_slice(&1u32.to_le_bytes());
    // Type-1 partition map immediately after the fixed header
    // (offset 440):
    //   [0] = 1 (type)
    //   [1] = 6 (length)
    //   [2..4] = volume_seq = 1
    //   [4..6] = partition_number = 0
    let map_off = lvd_off + core::mem::size_of::<LogicalVolumeDescriptorHeader>();
    img[map_off] = 1;
    img[map_off + 1] = 6;
    img[map_off + 2..map_off + 4].copy_from_slice(&1u16.to_le_bytes());
    img[map_off + 4..map_off + 6].copy_from_slice(&0u16.to_le_bytes());
    finalise_tag(&mut img, lvd_off, lvd_off + 16, 440 - 16 + 6);

    // ── Sector 36: Unallocated Space Descriptor (tag 7) ───────
    let usd_off = 36 * SECTOR_SIZE;
    write_tag_header(&mut img, usd_off, tag_id::UNALLOCATED_SPACE_DESCRIPTOR, 1, 36);
    finalise_tag(&mut img, usd_off, usd_off + 16, 8);

    // ── Sector 37: Terminating Descriptor (tag 8) ─────────────
    let td_off = 37 * SECTOR_SIZE;
    write_tag_header(&mut img, td_off, tag_id::TERMINATING_DESCRIPTOR, 1, 37);
    finalise_tag(&mut img, td_off, td_off + 16, 8);

    // ── Sector 256: AVDP (tag 2) ──────────────────────────────
    let avdp_off = 256 * SECTOR_SIZE;
    write_tag_header(&mut img, avdp_off, tag_id::ANCHOR_VOLUME_DESCRIPTOR_POINTER, 1, 256);
    // Main VDS: extent_length covers sectors 32..38 = 6 sectors =
    // 0x3000 bytes; extent_location = 32.
    img[avdp_off + 16..avdp_off + 20].copy_from_slice(&(6u32 * SECTOR_SIZE as u32).to_le_bytes());
    img[avdp_off + 20..avdp_off + 24].copy_from_slice(&32u32.to_le_bytes());
    // Reserve VDS — give it the same range; the driver only walks
    // the Main copy.
    img[avdp_off + 24..avdp_off + 28].copy_from_slice(&(6u32 * SECTOR_SIZE as u32).to_le_bytes());
    img[avdp_off + 28..avdp_off + 32].copy_from_slice(&32u32.to_le_bytes());
    finalise_tag(&mut img, avdp_off, avdp_off + 16, 16); // CRC over the two extent_ad pairs.

    // ── Sector 257: File Set Descriptor (tag 256) ─────────────
    let fsd_off = (partition_start as usize + fsd_lbn as usize) * SECTOR_SIZE;
    write_tag_header(&mut img, fsd_off, tag_id::FILE_SET_DESCRIPTOR, 1, fsd_lbn);
    // root_directory_icb at offset 16 + 384 = 400 (per the
    // FileSetDescriptor field layout — CRecording date 12, ints 16,
    // strings 64+128+64+32+32+32 = 352, total preceding = 12+16+352
    // = 380. Then root_directory_icb at 380 within the body. Plus
    // 16 for tag = 396.) — we use offset_of! to be exact:
    use super::descriptor::FileSetDescriptor;
    let rdi_off = fsd_off + core::mem::offset_of!(FileSetDescriptor, root_directory_icb);
    write_long_ad(
        &mut img,
        rdi_off,
        SECTOR_SIZE as u32,
        root_fe_lbn,
        0,
    );
    finalise_tag(&mut img, fsd_off, fsd_off + 16, 496);

    // ── Sector 258: Root Directory File Entry (tag 261) ───────
    let root_fe_off = (partition_start as usize + root_fe_lbn as usize) * SECTOR_SIZE;
    write_tag_header(&mut img, root_fe_off, tag_id::FILE_ENTRY, 1, root_fe_lbn);
    // icb_tag at offset 16:
    //   strategy_type = 4
    //   number_of_entries = 1
    //   file_type at offset 11 within the icb_tag = DIRECTORY (4)
    //   flags at offset 18 within the icb_tag = ALLOC_TYPE_LONG (1)
    img[root_fe_off + 16 + 4..root_fe_off + 16 + 6].copy_from_slice(&4u16.to_le_bytes());
    img[root_fe_off + 16 + 8..root_fe_off + 16 + 10].copy_from_slice(&1u16.to_le_bytes());
    img[root_fe_off + 16 + 11] = file_type::DIRECTORY;
    img[root_fe_off + 16 + 18..root_fe_off + 16 + 20]
        .copy_from_slice(&icb_flags::ALLOC_TYPE_LONG.to_le_bytes());
    // FIDs are written below into sector 259; we'll set its byte
    // length after laying them out.
    // Allocation descriptor area starts at offset 176 (L_EA = 0,
    // L_AD = 16). We'll come back to fill InformationLength + the
    // long_ad once we know the FID stream length.

    // ── Sector 259: Root Directory FID stream ────────────────
    let root_data_off = (partition_start as usize + root_data_lbn as usize) * SECTOR_SIZE;
    let mut cursor = 0usize;
    // Parent ".." FID — name empty, file_characteristics = DIR | PARENT.
    cursor += write_fid(
        &mut img[root_data_off..],
        cursor,
        super::fid::characteristics::DIRECTORY | super::fid::characteristics::PARENT,
        root_fe_lbn,
        0,
        SECTOR_SIZE as u32,
        &[],
        root_data_lbn,
    );
    // "TEST.TXT" FID pointing at the file's File Entry.
    cursor += write_fid(
        &mut img[root_data_off..],
        cursor,
        0,
        file_fe_lbn,
        0,
        SECTOR_SIZE as u32,
        b"TEST.TXT",
        root_data_lbn,
    );
    let root_dir_size = cursor as u64;

    // Root File Entry: InformationLength + L_EA + L_AD + long_ad.
    img[root_fe_off + 56..root_fe_off + 64].copy_from_slice(&root_dir_size.to_le_bytes());
    img[root_fe_off + 168..root_fe_off + 172].copy_from_slice(&0u32.to_le_bytes()); // L_EA
    img[root_fe_off + 172..root_fe_off + 176].copy_from_slice(&16u32.to_le_bytes()); // L_AD
    write_long_ad(
        &mut img,
        root_fe_off + 176,
        SECTOR_SIZE as u32, // recorded extent of one sector
        root_data_lbn,
        0,
    );
    finalise_tag(&mut img, root_fe_off, root_fe_off + 16, 176);

    // ── Sector 260: Regular file File Entry ───────────────────
    let file_fe_off = (partition_start as usize + file_fe_lbn as usize) * SECTOR_SIZE;
    write_tag_header(&mut img, file_fe_off, tag_id::FILE_ENTRY, 1, file_fe_lbn);
    img[file_fe_off + 16 + 4..file_fe_off + 16 + 6].copy_from_slice(&4u16.to_le_bytes());
    img[file_fe_off + 16 + 8..file_fe_off + 16 + 10].copy_from_slice(&1u16.to_le_bytes());
    img[file_fe_off + 16 + 11] = file_type::REGULAR_FILE;
    img[file_fe_off + 16 + 18..file_fe_off + 16 + 20]
        .copy_from_slice(&icb_flags::ALLOC_TYPE_LONG.to_le_bytes());
    img[file_fe_off + 56..file_fe_off + 64]
        .copy_from_slice(&(payload.len() as u64).to_le_bytes());
    img[file_fe_off + 168..file_fe_off + 172].copy_from_slice(&0u32.to_le_bytes());
    img[file_fe_off + 172..file_fe_off + 176].copy_from_slice(&16u32.to_le_bytes());
    write_long_ad(
        &mut img,
        file_fe_off + 176,
        payload.len() as u32,
        file_data_lbn,
        0,
    );
    finalise_tag(&mut img, file_fe_off, file_fe_off + 16, 176);

    // ── Sector 261: file body ────────────────────────────────
    let body_off = (partition_start as usize + file_data_lbn as usize) * SECTOR_SIZE;
    img[body_off..body_off + payload.len()].copy_from_slice(payload);

    (img, payload)
}

fn smoke_udf_mount_ramblock_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::UdfVolume;

    let (img, payload) = build_udf_image();
    let device = RamBlockDevice::from_image(SECTOR_SIZE as u32, img);

    let volume = match poll_once(UdfVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        Some(Err(_)) => return TestResult::Fail("UdfVolume::mount returned an error"),
        None => return TestResult::Fail("UdfVolume::mount did not complete on first poll"),
    };
    if volume.name() != "udf" {
        return TestResult::Fail("FsInstance::name did not report udf");
    }

    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    if entries.len() != 1 {
        return TestResult::Fail("root must contain exactly one user-visible entry");
    }
    if entries[0].0 != "TEST.TXT" || entries[0].1 != FileType::File {
        return TestResult::Fail("root entry mismatch (expected TEST.TXT)");
    }

    let file = match poll_once(root.lookup_async("TEST.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async TEST.TXT failed"),
    };
    // Trigger a read so the lazy stat refresh latches the size.
    let mut buf = [0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read failed"),
    };
    if n != payload.len() || &buf[..n] != payload {
        return TestResult::Fail("file contents mismatch");
    }
    if file.stat().size != payload.len() as u64 {
        return TestResult::Fail("stat.size mismatch after read");
    }

    // Lookups must be ASCII case-insensitive.
    if poll_once(root.lookup_async("test.txt"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("case-insensitive lookup failed");
    }

    // EOF behaviour — read past end yields 0.
    let m = match poll_once(file.read(payload.len() as u64, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("EOF read failed"),
    };
    if m != 0 {
        return TestResult::Fail("read past end must return 0");
    }

    // Missing entry must surface NotFound, not Unsupported.
    match poll_once(root.lookup_async("NOSUCH.TXT")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("missing entry must yield NotFound"),
    }

    TestResult::Pass
}

kernel_test_in!("drivers/fs/udf", smoke_udf_mount_ramblock_round_trip);
