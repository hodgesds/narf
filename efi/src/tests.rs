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
    if buf[buf.len() - 2..] != [0, 0] {
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
    for val in tmp[16..20].iter_mut() {
        *val = 0;
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
kernel_test_in!(
    "efi/system-table",
    smoke_table_header_verifies_signature_and_checksum
);

// ── deep efi/time + efi/reset coverage ────────────────────────────

fn smoke_efi_time_decode_rejects_short_buffer() -> TestResult {
    use crate::time::{EfiTime, TimeError};
    if EfiTime::decode(&[0u8; 15]) != Err(TimeError::Short) {
        return TestResult::Fail("< 16 bytes didn't surface Short");
    }
    TestResult::Pass
}
kernel_test_in!("efi/time", smoke_efi_time_decode_rejects_short_buffer);

fn smoke_efi_time_rejects_year_outside_range() -> TestResult {
    use crate::time::{EfiTime, TimeError};
    let bad = EfiTime {
        year: 1800,
        month: 1,
        day: 1,
        ..EfiTime::default()
    };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("year=1800 accepted");
    }
    let bad = EfiTime {
        year: 10_000,
        month: 1,
        day: 1,
        ..EfiTime::default()
    };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("year=10000 accepted");
    }
    TestResult::Pass
}
kernel_test_in!("efi/time", smoke_efi_time_rejects_year_outside_range);

fn smoke_efi_time_rejects_month_day_hour_minute() -> TestResult {
    use crate::time::{EfiTime, TimeError};
    let base = EfiTime {
        year: 2025,
        month: 1,
        day: 1,
        ..EfiTime::default()
    };
    let bad = EfiTime { month: 0, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("month=0 accepted");
    }
    let bad = EfiTime { month: 13, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("month=13 accepted");
    }
    let bad = EfiTime { day: 0, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("day=0 accepted");
    }
    let bad = EfiTime { day: 32, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("day=32 accepted");
    }
    let bad = EfiTime { hour: 24, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("hour=24 accepted");
    }
    let bad = EfiTime { minute: 60, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("minute=60 accepted");
    }
    let bad = EfiTime { second: 60, ..base };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("second=60 accepted");
    }
    let bad = EfiTime {
        nanosecond: 1_000_000_000,
        ..base
    };
    if EfiTime::decode(&bad.encode()) != Err(TimeError::OutOfRange) {
        return TestResult::Fail("nanosecond=10^9 accepted");
    }
    TestResult::Pass
}
kernel_test_in!("efi/time", smoke_efi_time_rejects_month_day_hour_minute);

fn smoke_efi_time_unspecified_timezone_sentinel() -> TestResult {
    use crate::time::EFI_UNSPECIFIED_TIMEZONE;
    if EFI_UNSPECIFIED_TIMEZONE != 0x07FF {
        return TestResult::Fail("EFI_UNSPECIFIED_TIMEZONE drifted from 0x07FF");
    }
    TestResult::Pass
}
kernel_test_in!("efi/time", smoke_efi_time_unspecified_timezone_sentinel);

fn smoke_efi_time_capabilities_decode() -> TestResult {
    use crate::time::{EfiTimeCapabilities, TimeError};
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&1000u32.to_le_bytes());
    buf[4..8].copy_from_slice(&50_000u32.to_le_bytes());
    buf[8] = 1;
    let caps = EfiTimeCapabilities::decode(&buf).expect("decode");
    if caps.resolution != 1000 || caps.accuracy != 50_000 || !caps.sets_to_zero {
        return TestResult::Fail("EfiTimeCapabilities field decode wrong");
    }
    if EfiTimeCapabilities::decode(&[0u8; 11]) != Err(TimeError::Short) {
        return TestResult::Fail("< 12 bytes didn't surface Short");
    }
    TestResult::Pass
}
kernel_test_in!("efi/time", smoke_efi_time_capabilities_decode);

fn smoke_efi_reset_type_variants_distinct() -> TestResult {
    use crate::reset::EfiResetType;
    let all = [
        EfiResetType::Cold,
        EfiResetType::Warm,
        EfiResetType::Shutdown,
        EfiResetType::PlatformSpecific,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("EfiResetType variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("efi/reset", smoke_efi_reset_type_variants_distinct);

// ── TCG2 event log ──────────────────────────────────────────────
//
// Fixtures are built byte-by-byte from the spec layouts (TCG EFI
// Protocol Spec + PC Client §9–§10), never by calling the decoder
// under test — a fixture and its decoder must not be able to agree
// on a wrong constant.

fn tcg2_push_u16(v: &mut alloc::vec::Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn tcg2_push_u32(v: &mut alloc::vec::Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn tcg2_push_u64(v: &mut alloc::vec::Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// `TCG_EfiSpecIdEventStruct` body, per the spec layout:
/// signature[16], platformClass u32, minor/major/errata/uintnSize
/// u8s, numberOfAlgorithms u32, {algId u16, digestSize u16} pairs,
/// vendorInfoSize u8 (0 here, no vendor info).
fn tcg2_spec_id_body(algs: &[(u16, u16)]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    // The signature is 16 bytes: the 15 ASCII bytes plus the NUL
    // terminator the TCG spec counts in TCG_SPECID_SIG. A 15-byte
    // signature shifts every later field one byte early and the
    // parser rejects the log (TooManyAlgorithms at the nAlgs field).
    v.extend_from_slice(b"Spec ID Event03\0");
    tcg2_push_u32(&mut v, 0); // platformClass: CLIENT
    v.push(0); // specVersionMinor
    v.push(2); // specVersionMajor
    v.push(2); // specErrata
    v.push(2); // uintnSize
    tcg2_push_u32(&mut v, algs.len() as u32);
    for &(alg, size) in algs {
        tcg2_push_u16(&mut v, alg);
        tcg2_push_u16(&mut v, size);
    }
    v.push(0); // vendorInfoSize
    v
}

/// The Spec ID event as the log's first record: a legacy
/// `TCG_PCR_EVENT` (pcrIndex, eventType `EV_NO_ACTION`, 20 zero
/// digest bytes, eventSize, event).
fn tcg2_spec_id_record(algs: &[(u16, u16)]) -> alloc::vec::Vec<u8> {
    let body = tcg2_spec_id_body(algs);
    let mut v = alloc::vec::Vec::new();
    tcg2_push_u32(&mut v, 0); // pcrIndex
    tcg2_push_u32(&mut v, 0x0000_0003); // EV_NO_ACTION
    v.extend_from_slice(&[0u8; 20]); // digest (zero)
    tcg2_push_u32(&mut v, body.len() as u32);
    v.extend_from_slice(&body);
    v
}

/// One `TCG_PCR_EVENT2` record: pcrIndex, eventType, digestCount,
/// (algId, digest) pairs, eventSize, event.
fn tcg2_event2_record(
    pcr: u32,
    event_type: u32,
    digests: &[(u16, &[u8])],
    event: &[u8],
) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    tcg2_push_u32(&mut v, pcr);
    tcg2_push_u32(&mut v, event_type);
    tcg2_push_u32(&mut v, digests.len() as u32);
    for &(alg, digest) in digests {
        tcg2_push_u16(&mut v, alg);
        v.extend_from_slice(digest);
    }
    tcg2_push_u32(&mut v, event.len() as u32);
    v.extend_from_slice(event);
    v
}

fn smoke_tcg2_guid_byte_order() -> TestResult {
    use crate::tcg2::{EFI_TCG2_FINAL_EVENTS_TABLE_GUID, LINUX_EFI_TPM_EVENT_LOG_GUID};
    // EFI_GUID wire order: data1/data2/data3 little-endian, then
    // the 8 tail bytes verbatim. This pins the order the
    // configuration-table walk compares against — a swapped field
    // silently finds no table.
    if EFI_TCG2_FINAL_EVENTS_TABLE_GUID.0
        != [
            0x96, 0xd0, 0x2e, 0x1e, 0xe2, 0x30, 0x54, 0x42, 0xbd, 0x89, 0x86, 0x3b, 0xbe, 0xf8,
            0x23, 0x25,
        ]
    {
        return TestResult::Fail("final-events GUID bytes wrong");
    }
    if LINUX_EFI_TPM_EVENT_LOG_GUID.0
        != [
            0xb0, 0x9c, 0x79, 0xb7, 0xa2, 0xec, 0x43, 0x49, 0x96, 0x67, 0x1f, 0xae, 0x07, 0xb7,
            0x47, 0xfa,
        ]
    {
        return TestResult::Fail("Linux event-log GUID bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("efi/tcg2", smoke_tcg2_guid_byte_order);

fn smoke_tcg2_table_headers_decode() -> TestResult {
    use crate::tcg2::{decode_final_events_table_header, decode_linux_tpm_event_log_header};
    let mut fin = alloc::vec::Vec::new();
    tcg2_push_u64(&mut fin, 1); // Version
    tcg2_push_u64(&mut fin, 3); // NumberOfEvents
    match decode_final_events_table_header(&fin) {
        Some(h) if h.version == 1 && h.number_of_events == 3 => {}
        _ => return TestResult::Fail("final-events header decode wrong"),
    }
    let mut bad = fin.clone();
    bad[0] = 2; // Version 2: not understood
    if decode_final_events_table_header(&bad).is_some() {
        return TestResult::Fail("final-events version 2 accepted");
    }
    if decode_final_events_table_header(&fin[..15]).is_some() {
        return TestResult::Fail("short final-events header accepted");
    }
    let mut log = alloc::vec::Vec::new();
    tcg2_push_u32(&mut log, 0x1234); // size
    tcg2_push_u32(&mut log, 0x40); // final_events_preboot_size
    log.push(2); // version = TCG2
    match decode_linux_tpm_event_log_header(&log) {
        Some(h) if h.size == 0x1234 && h.final_events_preboot_size == 0x40 && h.version == 2 => {}
        _ => return TestResult::Fail("Linux event-log header decode wrong"),
    }
    let mut sha1_only = log.clone();
    sha1_only[8] = 1; // version = TCG_1_2: no SHA-256 bank
    if decode_linux_tpm_event_log_header(&sha1_only).is_some() {
        return TestResult::Fail("SHA-1-only event-log header accepted");
    }
    TestResult::Pass
}
kernel_test_in!("efi/tcg2", smoke_tcg2_table_headers_decode);

fn smoke_tcg2_log_parses_spec_stream() -> TestResult {
    use crate::tcg2::{parse_tcg2_log, SPEC_ID_SIGNATURE};
    let algs = [(0x0004u16, 20u16), (0x000Bu16, 32u16)];
    let mut log = tcg2_spec_id_record(&algs);
    // EV_S_CRTM_VERSION (0x8) into PCR 0, SHA-1 + SHA-256 digests.
    log.extend_from_slice(&tcg2_event2_record(
        0,
        0x0000_0008,
        &[(0x0004, &[0x11u8; 20]), (0x000B, &[0x22u8; 32])],
        b"v1.0",
    ));
    // EV_SEPARATOR (0x4) into PCR 0.
    log.extend_from_slice(&tcg2_event2_record(
        0,
        0x0000_0004,
        &[(0x0004, &[0x33u8; 20]), (0x000B, &[0x44u8; 32])],
        &[4, 0, 0, 0],
    ));
    // EV_NO_ACTION into PCR 7, zero digests.
    log.extend_from_slice(&tcg2_event2_record(
        7,
        0x0000_0003,
        &[(0x0004, &[0u8; 20]), (0x000B, &[0u8; 32])],
        b"note",
    ));
    let (info, events) = match parse_tcg2_log(&log) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("valid TCG2 log rejected"),
    };
    if info.number_of_algorithms != 2 || !info.has_sha256 {
        return TestResult::Fail("Spec ID info wrong");
    }
    if events.len() != 4 {
        return TestResult::Fail("expected Spec ID + 3 records");
    }
    // Record 0 is the Spec ID event itself: never extended.
    if events[0].event_type != 0x0000_0003 || events[0].sha256_digest.is_some() {
        return TestResult::Fail("Spec ID record misparsed");
    }
    if &events[0].event[0..16] != SPEC_ID_SIGNATURE {
        return TestResult::Fail("Spec ID signature not carried");
    }
    if events[1].sha256_digest != Some([0x22u8; 32]) || events[1].event != b"v1.0" {
        return TestResult::Fail("first EVENT2 record misparsed");
    }
    if events[2].event_type != 0x0000_0004 || events[2].sha256_digest != Some([0x44u8; 32]) {
        return TestResult::Fail("separator record misparsed");
    }
    if events[3].pcr != 7 || events[3].sha256_digest != Some([0u8; 32]) {
        return TestResult::Fail("NO_ACTION record misparsed");
    }
    // A zero-padded tail ends the log cleanly (Linux rule).
    let mut padded = log.clone();
    padded.extend_from_slice(&[0u8; 24]);
    match parse_tcg2_log(&padded) {
        Ok((_, evs)) if evs.len() == 4 => TestResult::Pass,
        _ => TestResult::Fail("zero-padded tail rejected"),
    }
}
kernel_test_in!("efi/tcg2", smoke_tcg2_log_parses_spec_stream);

fn smoke_tcg2_log_rejects_malformed() -> TestResult {
    use crate::tcg2::{parse_tcg2_log, Tcg2LogError};
    let algs = [(0x0004u16, 20u16), (0x000Bu16, 32u16)];
    let good = tcg2_spec_id_record(&algs);
    let mut rec = tcg2_event2_record(
        0,
        0x0000_0008,
        &[(0x0004, &[0x11u8; 20]), (0x000B, &[0x22u8; 32])],
        b"v1.0",
    );
    // Bad Spec ID signature.
    let mut bad_sig = good.clone();
    bad_sig[32] = b'X';
    if parse_tcg2_log(&bad_sig) != Err(Tcg2LogError::BadSpecIdSignature) {
        return TestResult::Fail("bad Spec ID signature accepted");
    }
    // SHA-1-only algorithm list: no SHA-256 bank to replay.
    let sha1_only = tcg2_spec_id_record(&[(0x0004u16, 20u16)]);
    if parse_tcg2_log(&sha1_only) != Err(Tcg2LogError::NoSha256Bank) {
        return TestResult::Fail("SHA-1-only log accepted");
    }
    // Digest count (1) != numberOfAlgorithms (2).
    let mut log = good.clone();
    rec[8..12].copy_from_slice(&1u32.to_le_bytes());
    log.extend_from_slice(&rec);
    if parse_tcg2_log(&log) != Err(Tcg2LogError::BadDigestCount) {
        return TestResult::Fail("digest-count mismatch accepted");
    }
    // Truncated tail.
    let mut truncated = good.clone();
    truncated.extend_from_slice(&rec[..rec.len() - 3]);
    if parse_tcg2_log(&truncated) != Err(Tcg2LogError::Short) {
        return TestResult::Fail("truncated record accepted");
    }
    // PCR out of range.
    let mut bad_pcr = good.clone();
    bad_pcr.extend_from_slice(&tcg2_event2_record(
        24,
        0x0000_0008,
        &[(0x0004, &[0x11u8; 20]), (0x000B, &[0x22u8; 32])],
        b"x",
    ));
    if parse_tcg2_log(&bad_pcr) != Err(Tcg2LogError::BadPcrIndex) {
        return TestResult::Fail("PCR 24 accepted");
    }
    TestResult::Pass
}
kernel_test_in!("efi/tcg2", smoke_tcg2_log_rejects_malformed);

fn smoke_tcg2_final_events_parse() -> TestResult {
    use crate::tcg2::{parse_final_events, Tcg2LogError};
    let first = tcg2_event2_record(
        5,
        0x8000_0007, // EV_EFI_ACTION
        &[(0x0004, &[0x55u8; 20]), (0x000B, &[0x66u8; 32])],
        b"Exit Boot Services Invocation",
    );
    let second = tcg2_event2_record(
        5,
        0x8000_0007,
        &[(0x0004, &[0x77u8; 20]), (0x000B, &[0x88u8; 32])],
        b"Exit Boot Services Returned with Success",
    );
    let mut body = alloc::vec::Vec::new();
    body.extend_from_slice(&first);
    body.extend_from_slice(&second);
    // Exact count, Spec ID count known from the main log.
    match parse_final_events(&body, 2, Some(2), 0) {
        Ok(evs) if evs.len() == 2 && evs[0].sha256_digest == Some([0x66u8; 32]) => {}
        _ => return TestResult::Fail("final-events parse wrong"),
    }
    // Without the main log's Spec ID anchor, single-bank records
    // still parse.
    let single = tcg2_event2_record(5, 0x8000_0007, &[(0x000B, &[0x99u8; 32])], b"x");
    match parse_final_events(&single, 1, None, 0) {
        Ok(evs) if evs.len() == 1 => {}
        _ => return TestResult::Fail("anchorless final-events parse wrong"),
    }
    // `final_events_preboot_size`: the first record is already in
    // the main log and must be skipped, never replayed twice.
    match parse_final_events(&body, 2, Some(2), first.len()) {
        Ok(evs) if evs.len() == 1 && evs[0].sha256_digest == Some([0x88u8; 32]) => {}
        _ => return TestResult::Fail("preboot dedup skip wrong"),
    }
    // A prefix that lands mid-record is corrupt, not a skip.
    if parse_final_events(&body, 2, Some(2), 5) != Err(Tcg2LogError::BadPrebootSize) {
        return TestResult::Fail("mid-record preboot skip accepted");
    }
    // A prefix longer than the table overruns it.
    if parse_final_events(&body, 2, Some(2), body.len() + 1) != Err(Tcg2LogError::BadPrebootSize) {
        return TestResult::Fail("overrunning preboot skip accepted");
    }
    // Fewer records than NumberOfEvents.
    if parse_final_events(&body, 3, Some(2), 0) != Err(Tcg2LogError::Short) {
        return TestResult::Fail("short final table accepted");
    }
    // Digest count disagrees with the anchor.
    if parse_final_events(&body, 2, Some(1), 0) != Err(Tcg2LogError::BadDigestCount) {
        return TestResult::Fail("final-events digest-count mismatch accepted");
    }
    // A non-NO_ACTION record without a SHA-256 digest cannot replay.
    let no_sha256 = tcg2_event2_record(5, 0x8000_0007, &[(0x0004, &[0x11u8; 20])], b"x");
    if parse_final_events(&no_sha256, 1, None, 0) != Err(Tcg2LogError::NoSha256Bank) {
        return TestResult::Fail("SHA-256-less final event accepted");
    }
    TestResult::Pass
}
kernel_test_in!("efi/tcg2", smoke_tcg2_final_events_parse);
