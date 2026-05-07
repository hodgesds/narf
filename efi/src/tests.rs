//! Smoke tests for narf-efi.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── EFI_TIME ──────────────────────────────────────────────────────

fn smoke_efi_time_round_trip() -> TestResult {
    use crate::time::{EfiTime, EFI_UNSPECIFIED_TIMEZONE};
    let t = EfiTime {
        year: 2026,
        month: 5,
        day: 7,
        hour: 14,
        minute: 35,
        second: 22,
        nanosecond: 123_456_789,
        time_zone: EFI_UNSPECIFIED_TIMEZONE,
        daylight: 0,
    };
    let r = EfiTime::decode(&t.encode()).expect("decode");
    if r != t {
        return TestResult::Fail("EFI_TIME round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("efi/time", smoke_efi_time_round_trip);

fn smoke_efi_time_rejects_out_of_range() -> TestResult {
    use crate::time::{EfiTime, TimeError};
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&2026u16.to_le_bytes());
    buf[2] = 13; // month out of range
    buf[3] = 1;
    match EfiTime::decode(&buf) {
        Err(TimeError::OutOfRange) => TestResult::Pass,
        _ => TestResult::Fail("month=13 must be rejected"),
    }
}
kernel_test_in!("efi/time", smoke_efi_time_rejects_out_of_range);

// ── ResetType ─────────────────────────────────────────────────────

fn smoke_efi_reset_type_round_trip() -> TestResult {
    use crate::reset::EfiResetType;
    let cases = [
        EfiResetType::Cold,
        EfiResetType::Warm,
        EfiResetType::Shutdown,
        EfiResetType::PlatformSpecific,
    ];
    for c in cases {
        let v = c as u32;
        if EfiResetType::from_u32(v) != Some(c) {
            return TestResult::Fail("EfiResetType round-trip");
        }
    }
    if EfiResetType::from_u32(99).is_some() {
        return TestResult::Fail("99 must not be a valid reset type");
    }
    TestResult::Pass
}
kernel_test_in!("efi/reset", smoke_efi_reset_type_round_trip);

// ── Variable name encoding ───────────────────────────────────────

fn smoke_variable_name_ucs2_encode_decode() -> TestResult {
    use crate::variable::{decode_name, encode_name};
    let s = "BootOrder";
    let buf = encode_name(s);
    if buf.len() != (s.len() + 1) * 2 {
        return TestResult::Fail("UCS-2 length wrong");
    }
    if buf[0] != b'B' || buf[1] != 0 {
        return TestResult::Fail("first char wrong");
    }
    if &buf[buf.len() - 2..] != [0, 0] {
        return TestResult::Fail("missing NUL terminator");
    }
    if decode_name(&buf) != s {
        return TestResult::Fail("decode round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("efi/variable", smoke_variable_name_ucs2_encode_decode);

// ── Variable Attributes ──────────────────────────────────────────

fn smoke_variable_attribute_constants() -> TestResult {
    use crate::variable::attr;
    // SecureBoot variables are NV+RT+BS+AUTH (timed-based auth).
    let secure_db = attr::NON_VOLATILE
        | attr::BOOTSERVICE_ACCESS
        | attr::RUNTIME_ACCESS
        | attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    if secure_db != 0x27 {
        return TestResult::Fail("SecureBoot db attribute set wrong");
    }
    TestResult::Pass
}
kernel_test_in!("efi/variable", smoke_variable_attribute_constants);

// ── EFI_SIGNATURE_LIST walker ────────────────────────────────────

fn smoke_signature_list_parses_two_entries() -> TestResult {
    use crate::variable::{parse_signature_list, EFI_CERT_SHA256_GUID};
    use alloc::vec::Vec;
    // Build a SignatureList with two SHA-256 entries.
    // SignatureType = SHA256
    // SignatureListSize = 28 + 0 + 2*(16+32) = 124
    // SignatureHeaderSize = 0
    // SignatureSize = 16+32 = 48
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&EFI_CERT_SHA256_GUID.0);
    buf.extend_from_slice(&124u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&48u32.to_le_bytes());
    // Entry 0: owner GUID + 32 bytes of payload (0xAA repeated)
    let owner0 = [0u8; 16];
    buf.extend_from_slice(&owner0);
    buf.extend_from_slice(&[0xAAu8; 32]);
    // Entry 1: owner GUID + 32 bytes of payload (0xBB repeated)
    let owner1 = [0xFFu8; 16];
    buf.extend_from_slice(&owner1);
    buf.extend_from_slice(&[0xBBu8; 32]);

    let (h, entries) = parse_signature_list(&buf).expect("parse");
    if h.entry_count() != 2 {
        return TestResult::Fail("entry count wrong");
    }
    if entries.len() != 2 {
        return TestResult::Fail("walked entry count wrong");
    }
    if entries[0].data.len() != 32 || entries[0].data[0] != 0xAA {
        return TestResult::Fail("entry 0 data wrong");
    }
    if entries[1].owner.0 != owner1 {
        return TestResult::Fail("entry 1 owner wrong");
    }
    TestResult::Pass
}
kernel_test_in!("efi/variable", smoke_signature_list_parses_two_entries);

// ── CRC-32/IEEE for table-header verification ────────────────────

fn smoke_crc32_known_vector() -> TestResult {
    use crate::system_table::crc32_ieee;
    // Standard ASCII test vector: "123456789" → CRC32 = 0xCBF43926.
    if crc32_ieee(b"123456789") != 0xCBF4_3926 {
        return TestResult::Fail("CRC32(\"123456789\") wrong");
    }
    if crc32_ieee(b"") != 0 {
        return TestResult::Fail("CRC32(\"\") must be 0");
    }
    TestResult::Pass
}
kernel_test_in!("efi/system-table", smoke_crc32_known_vector);

fn smoke_table_header_verifies_signature_and_checksum() -> TestResult {
    use crate::system_table::{crc32_ieee, signature, TableHeader, TableHeaderError};
    // Build a synthetic 24-byte header. Compute CRC32 over the
    // 24 bytes with the CRC field zeroed, store it back in.
    let mut buf = [0u8; 24];
    buf[0..8].copy_from_slice(&signature::SYSTEM_TABLE.to_le_bytes());
    buf[8..12].copy_from_slice(&((2u32 << 16) | 100).to_le_bytes()); // 2.10
    buf[12..16].copy_from_slice(&24u32.to_le_bytes()); // header size
    let mut tmp = buf;
    for i in 16..20 {
        tmp[i] = 0;
    }
    let crc = crc32_ieee(&tmp);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());
    let h = TableHeader::decode(&buf).expect("decode");
    h.verify(signature::SYSTEM_TABLE, &buf).expect("verify");
    if h.major_revision() != 2 || h.minor_revision() != 100 {
        return TestResult::Fail("revision decode");
    }
    // Tamper a byte to confirm the check fails.
    let mut bad = buf;
    bad[0] ^= 0x10;
    let h2 = TableHeader::decode(&bad).expect("decode");
    match h2.verify(signature::SYSTEM_TABLE, &bad) {
        Err(TableHeaderError::BadSignature) => TestResult::Pass,
        _ => TestResult::Fail("tampered signature must fail"),
    }
}
kernel_test_in!("efi/system-table", smoke_table_header_verifies_signature_and_checksum);
