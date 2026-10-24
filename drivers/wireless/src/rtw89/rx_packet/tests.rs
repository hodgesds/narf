use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");

pub(super) fn packet(kind: u8, payload: &[u8], long: bool, driver: usize) -> Vec<u8> {
    let offset = 4 + if long { 32 } else { 16 } + driver * 8;
    let mut bytes = vec![0; offset + payload.len()];
    let info = bytes.len() as u32 | 0xc000;
    bytes[..4].copy_from_slice(&info.to_le_bytes());
    let d0 = payload.len() as u32
        | ((kind as u32) << 24)
        | ((driver as u32) << 28)
        | if long { 1 << 31 } else { 0 };
    bytes[4..8].copy_from_slice(&d0.to_le_bytes());
    bytes[offset..].copy_from_slice(payload);
    bytes
}
fn smoke_rtw89_rx_metadata_matches_original_linux_c() -> TestResult {
    for &(input, expected) in RXD {
        let mut bytes = vec![0; 128];
        for (offset, value) in [4, 8, 16].into_iter().zip(input) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let actual = Descriptor::parse(&bytes).unwrap();
        let values = [
            actual.size as u32,
            actual.offset as u32,
            actual.kind as u32,
            actual.rate as u32,
            actual.bandwidth as u32,
            actual.crc_error as u32,
            actual.icv_error as u32,
        ];
        if values != expected {
            return TestResult::Fail("AX RXD layout differs from original Linux C");
        }
    }
    for &(words, expected) in C2H {
        let mut bytes = vec![0; 12];
        bytes[..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        let parsed = C2h::parse(bytes).unwrap();
        if [
            parsed.category as u16,
            parsed.class as u16,
            parsed.function as u16,
            parsed.bytes.len() as u16,
        ] != expected
        {
            return TestResult::Fail("C2H envelope differs from original Linux C");
        }
    }
    for &(word, expected) in RPP {
        let parsed = tx_transport::parse_report(&word.to_le_bytes()).unwrap();
        if [
            parsed.sequence,
            parsed.qsel as u16,
            parsed.status as u16,
            parsed.channel as u16,
            parsed.mac_id as u16,
        ] != expected
        {
            return TestResult::Fail("RPQ identity/channel differs from original Linux C");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_metadata_matches_original_linux_c
);

fn smoke_rtw89_rx_segment_fcs_report_and_ack_boundaries() -> TestResult {
    let payload: Vec<u8> = (0..40).collect();
    for long in [false, true] {
        for driver in 0..8 {
            let bytes = packet(0, &payload, long, driver);
            let mut assembler = Assembler::default();
            match assembler.segment(&bytes, false) {
                Ok(Some(Event::Wifi(_, frame))) if frame == payload[..36] => {}
                _ => return TestResult::Fail("RX long/short/driver-info/FCS geometry"),
            }
        }
    }
    let mut first = packet(0, &payload, false, 0);
    first.truncate(4 + 16 + 13);
    let size = first.len() as u32 | 0x8000;
    first[..4].copy_from_slice(&size.to_le_bytes());
    let mut last = vec![0; 4];
    last.extend_from_slice(&payload[13..]);
    let size = last.len() as u32 | 0x4000;
    last[..4].copy_from_slice(&size.to_le_bytes());
    let mut assembler = Assembler::default();
    if assembler.segment(&first, false) != Ok(None)
        || !matches!(assembler.segment(&last, false), Ok(Some(Event::Wifi(_, frame))) if frame == payload[..36])
    {
        return TestResult::Fail("RX bounded multi-descriptor packet assembly");
    }
    // RXD claims one four-byte release, while the real RXBD contains two.
    let reports = [0x0000_1201u32, 0x0001_0001];
    let body: Vec<u8> = reports.into_iter().flat_map(u32::to_le_bytes).collect();
    let mut bytes = packet(7, &body, true, 2);
    let d0 = word(&bytes, 4).unwrap();
    bytes[4..8].copy_from_slice(&((d0 & !0x3fff) | 4).to_le_bytes());
    if !matches!(Assembler::default().segment(&bytes, true),
        Ok(Some(Event::Releases(records))) if records.len() == 2 && records[0].channel == 8 && records[1].channel == 0)
    {
        return TestResult::Fail("RPQ used RXD size instead of actual RXBD write_size");
    }
    bytes[4..8].copy_from_slice(&(d0 & !0x3fff).to_le_bytes());
    if !matches!(Assembler::default().segment(&bytes, true),
        Ok(Some(Event::Releases(records))) if records.len() == 2)
    {
        return TestResult::Fail("RPQ imposed an unused RXD packet-size requirement");
    }
    for done in [false, true] {
        let mut c2h = vec![0; 12];
        c2h[0] = 1;
        c2h[1] = u8::from(done);
        c2h[4] = 12;
        let w2: u32 = 1
            | (3 << 2)
            | (0x42 << 8)
            | if done {
                (9 << 16) | (0x8e << 24)
            } else {
                0x8e << 16
            };
        c2h[8..12].copy_from_slice(&w2.to_le_bytes());
        let parsed = C2h::parse(c2h).unwrap();
        if parsed.ack()
            != Ok(Some(Ack {
                category: 1,
                class: 3,
                function: 0x42,
                sequence: 0x8e,
                result: done.then_some(9),
            }))
        {
            return TestResult::Fail("receive/execution C2H acknowledgements confused");
        }
        if !matches!(Assembler::default().segment(&packet(10, &parsed.bytes, false, 0), false),
            Ok(Some(Event::Firmware(event))) if event.bytes.len() == 12)
        {
            return TestResult::Fail("C2H data incorrectly stripped a Wi-Fi FCS");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_segment_fcs_report_and_ack_boundaries
);

fn smoke_rtw89_rx_malformed_extent_and_profile_never_publish_frames() -> TestResult {
    let payload = vec![0x5a; 40];
    let base = packet(0, &payload, false, 0);
    for end in 0..base.len() {
        if Assembler::default().segment(&base[..end], false).is_ok() {
            return TestResult::Fail("truncated RXBD or RXD accepted");
        }
    }
    for (offset, mask) in [(4, 0x4000u32), (4, 1 << 22), (4, 7 << 28)] {
        let mut bytes = base.clone();
        let w = word(&bytes, offset).unwrap() | mask;
        bytes[offset..offset + 4].copy_from_slice(&w.to_le_bytes());
        if Assembler::default().segment(&bytes, false).is_ok() {
            return TestResult::Fail("unsupported RXD shift/PHY/driver extent accepted");
        }
    }
    for flag in [4, 1 << 3, 1 << 5, 1 << 6, 1 << 9, 1 << 10] {
        let mut bytes = base.clone();
        bytes[16..20].copy_from_slice(&(flag as u32).to_le_bytes());
        if Assembler::default().segment(&bytes, false) != Ok(Some(Event::Dropped)) {
            return TestResult::Fail("bad FCS/ICV/aggregate/hardware crypto became station RX");
        }
    }
    let mut bytes = base.clone();
    bytes[1] &= !0x80;
    if Assembler::default().segment(&bytes, false) != Err(Error::Segment) {
        return TestResult::Fail("continuation without first descriptor accepted");
    }
    let mut c2h = vec![0; 12];
    c2h[0] = 1;
    c2h[4] = 11;
    if C2h::parse(c2h).is_ok() {
        return TestResult::Fail("inconsistent C2H header extent accepted");
    }
    let mut short = vec![0; 8];
    short[0] = 1;
    short[4] = 8;
    if C2h::parse(short).is_ok() {
        return TestResult::Fail("MAC ACK without actual third dword accepted");
    }
    let mut polluted = packet(7, &0x8000_0000u32.to_le_bytes(), false, 0);
    if Assembler::default().segment(&polluted, true).is_ok() {
        return TestResult::Fail("polluted RPQ report accepted");
    }
    polluted.pop();
    if Assembler::default().segment(&polluted, true).is_ok() {
        return TestResult::Fail("partial RPQ release record accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_malformed_extent_and_profile_never_publish_frames
);
