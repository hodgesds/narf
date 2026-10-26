use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
const LOCAL: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn smoke_ar9285_native_four_series_literals_and_bound_feedback() -> TestResult {
    let series = Series {
        rates: [11, 10, 9, 8],
        tries: [4, 2, 2, 2],
        basic: 0,
    };
    let mut words = match transmit_series(&frame(80, false), LOCAL, 0x12345000, series) {
        Ok(words) => words,
        Err(_) => return TestResult::Fail("native MRR encode"),
    };
    // Literal ar9002 ctl2/ctl3, four durations, ctl7 and fallback powers.
    if words[4] != 0x22248000
        || words[5] != 0x090d080c
        || words[6] != 0x00340034
        || words[7] != 0x00440038
        || words[9] != 0x01b21084
        || words[11..14] != [0x3f000000; 3]
    {
        return TestResult::Fail("native four-series rate/tries/duration/chain/power literals");
    }
    words[15] = 1;
    for (slot, rate) in [11, 10, 9, 8].into_iter().enumerate() {
        words[TX_DONE] = 1 | ((slot as u32) << 21);
        if transmit_status(&words, false) != Ok(TxStatus::Delivered)
            || transmit_feedback(&words)
                != Ok(Feedback {
                    rate,
                    retried: slot != 0,
                    radio: true,
                })
        {
            return TestResult::Fail("FinalTxIdx misclassified or actual rate lost");
        }
    }
    words[15] = 1 | 0x100;
    words[TX_DONE] = 1;
    if !transmit_feedback(&words).unwrap().retried {
        return TestResult::Fail("native DATA retry count ignored");
    }
    words[15] = 4;
    if transmit_feedback(&words).unwrap().radio {
        return TestResult::Fail("FIFO underrun treated as RF evidence");
    }
    let mut invalid = series;
    invalid.tries[1] = 0;
    if transmit_series(&frame(80, false), LOCAL, 0x1000, invalid) != Err(Error::Profile)
        || transmit_series(&frame(80, true), LOCAL, 0x1000, series) != Err(Error::Profile)
    {
        return TestResult::Fail("sparse or broadcast retry chain admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rates",
    smoke_ar9285_native_four_series_literals_and_bound_feedback
);
fn frame(length: usize, group: bool) -> Vec<u8> {
    let mut bytes = vec![0x59; length];
    bytes[..2].copy_from_slice(&[8, 1]);
    bytes[4..10].copy_from_slice(if group {
        &[0xff; 6]
    } else {
        &[2, 0, 0, 0, 0, 1]
    });
    bytes[10..16].copy_from_slice(&LOCAL);
    bytes[22..24].copy_from_slice(&[0x30, 0]);
    bytes
}
fn check_tx_descriptor_matches_frozen_reference() -> Result<(), &'static str> {
    if BYTES != DESC_BYTES || TX_STATUS_OFFSET != 14 * 4 || RX_STATUS_OFFSET != 4 * 4 {
        return Err("native descriptor geometry differs");
    }
    for &(rate, length, group, expected) in TX_CASES {
        let bytes = frame(length, group);
        if transmit(&bytes, LOCAL, 0x1234_5000, rate) != Ok(expected) {
            return Err("native legacy TX descriptor differs from Linux C");
        }
    }
    Ok(())
}
fn check_descriptor_extent_and_raw_transmit_admission() -> Result<(), &'static str> {
    let base = frame(80, false);
    for address in [0, 1, 0x1_0000_0000, 0xffff_fffc] {
        if transmit(&base, LOCAL, address, 0) != Err(Error::Address) {
            return Err("bad complete DMA extent accepted");
        }
    }
    for length in [0, 23, MAX_MPDU + 1] {
        if transmit(&vec![0; length], LOCAL, 0x1000, 0) != Err(Error::Length) {
            return Err("bad MPDU length admitted");
        }
    }
    if transmit(&base, LOCAL, 0x1000, 12) != Err(Error::Profile) {
        return Err("unknown PHY rate admitted");
    }
    for (byte, mask) in [
        (0, 1),
        (0, 0x80),
        (1, 4),
        (1, 0x10),
        (1, 0x80),
        (10, 4),
        (22, 1),
    ] {
        let mut invalid = base.clone();
        invalid[byte] ^= mask;
        if transmit(&invalid, LOCAL, 0x1000, 0).is_ok() {
            return Err("non-native raw frame admitted");
        }
    }
    for (address, next) in [
        (0, 0),
        (0xffff_fffc, 0),
        (0x1000, 3),
        (0x1000, 0x1_0000_0000),
    ] {
        if receive_descriptor(address, next).is_ok() {
            return Err("bad receive allocation/link admitted");
        }
    }
    let receive = receive_descriptor(0x8000, 0x9000).map_err(|_| "RX descriptor")?;
    if receive[0..4] != [0x9000, 0x8000, 0, 4092] || receive[4..].iter().any(|&word| word != 0) {
        return Err("RX setup/status clearing differs");
    }
    Ok(())
}
fn check_exact_done_and_native_failure_receipts() -> Result<(), &'static str> {
    let mut words = transmit(&frame(80, false), LOCAL, 0x1000, 0).map_err(|_| "encode")?;
    words[15] = 1;
    if transmit_status(&words, false) != Ok(TxStatus::Pending) {
        return Err("ACK without Done retired");
    }
    words[TX_DONE] = 1;
    if transmit_status(&words, false) != Ok(TxStatus::Delivered) {
        return Err("exact Done/ACK refused");
    }
    for error in [2, 4, 8, 1 << 16, 1 << 17, 1 << 18, 1 << 19] {
        words[15] = 1 | error;
        if transmit_status(&words, false) != Ok(TxStatus::Failed) {
            return Err("native TX error hidden");
        }
    }
    words[15] = 0;
    if transmit_status(&words, false) != Ok(TxStatus::Failed)
        || transmit_status(&words, true) != Ok(TxStatus::Delivered)
    {
        return Err("ACK expectation not bound to receiver address");
    }
    words[TX_DONE] = 1 | (1 << 17);
    if transmit_status(&words, true) != Ok(TxStatus::Failed) {
        return Err("TXOP failure admitted");
    }
    for error in [1 << 21, 2 << 21, 3 << 21] {
        words[TX_DONE] = 1 | error;
        if transmit_status(&words, true) != Err(Error::Status) {
            return Err("unprogrammed fallback series admitted");
        }
    }
    words[TX_DONE] = u32::MAX;
    if transmit_status(&words, false) != Err(Error::Status) {
        return Err("absent status accepted");
    }
    Ok(())
}
fn check_raw_rx_profile_fcs_and_decrypt_admission() -> Result<(), &'static str> {
    let mut bytes = frame(100, false);
    bytes[1] = 0x42; // FromDS protected, still containing original CCMP bytes.
    let mut words = receive_descriptor(0x8000, 0).map_err(|_| "RX encode")?;
    words[4] = 0x1b << 24;
    words[5] = bytes.len() as u32;
    words[8] = 0xd8 << 24;
    words[RX_DONE] = 0x8000_0003; // key miss is expected with no hardware keys.
    let parsed = receive(&words, &bytes)
        .map_err(|_| "RX parse")?
        .ok_or("raw frame lost")?;
    if parsed.bytes() != &bytes[..96] || parsed.rate != 0 || parsed.rssi != -40 {
        return Err("RX changed ciphertext or retained FCS");
    }
    for &(native, errors, flags, key) in RX_STATUS_CASES {
        let mut test = words;
        test[RX_DONE] = native;
        let expected = errors & !0x20 == 0
            && flags == 0
            && key == 0xff
            && (native & 2 != 0 || errors & 0x20 != 0);
        if receive(&test, &bytes)
            .map_err(|_| "native C RX status extent")?
            .is_some()
            != expected
        {
            return Err("raw key-miss/error admission differs from original Linux status");
        }
    }
    let mut no_frame_ok = words;
    no_frame_ok[RX_DONE] = 0x8000_0001;
    let mut unprotected = bytes.clone();
    unprotected[1] &= !0x40;
    if receive(&no_frame_ok, &unprotected)
        .map_err(|_| "unprotected key miss")?
        .is_some()
    {
        return Err("key miss authorized unprotected data without FrameOK");
    }
    for flag in [
        4,
        8,
        16,
        32,
        64,
        0x100,
        0x10000,
        0x20000,
        0x40000,
        0x2000_0000,
        0x4000_0000,
    ] {
        let mut invalid = words;
        invalid[RX_DONE] |= flag;
        if receive(&invalid, &bytes)
            .map_err(|_| "bad status bounds")?
            .is_some()
        {
            return Err("error/decrypted/aggregate RX admitted");
        }
    }
    for (word, flag) in [(5, 0x1000), (7, 1), (7, 2), (7, 8)] {
        let mut invalid = words;
        invalid[word] |= flag;
        if receive(&invalid, &bytes)
            .map_err(|_| "profile bounds")?
            .is_some()
        {
            return Err("RX PHY profile expanded");
        }
    }
    for code in [0x80, 0x90, 0xff] {
        let mut invalid = words;
        invalid[4] = code << 24;
        if receive(&invalid, &bytes)
            .map_err(|_| "rate bounds")?
            .is_some()
        {
            return Err("unknown RX rate admitted");
        }
    }
    words[4] = 0x1e << 24;
    if receive(&words, &bytes)
        .map_err(|_| "short preamble")?
        .ok_or("short preamble lost")?
        .rate
        != 1
    {
        return Err("CCK short preamble rate mapping");
    }
    words[5] = 101;
    if receive(&words, &bytes) != Err(Error::Length) {
        return Err("RX extent overrun accepted");
    }
    Ok(())
}

fn smoke_ar9285_tx_descriptor_matches_frozen_reference() -> TestResult {
    match check_tx_descriptor_matches_frozen_reference() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

fn smoke_ar9285_descriptor_extent_and_raw_transmit_admission() -> TestResult {
    match check_descriptor_extent_and_raw_transmit_admission() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

fn smoke_ar9285_exact_done_and_native_failure_receipts() -> TestResult {
    match check_exact_done_and_native_failure_receipts() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

fn smoke_ar9285_raw_rx_profile_fcs_and_decrypt_admission() -> TestResult {
    match check_raw_rx_profile_fcs_and_decrypt_admission() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

kernel_test_in!(
    "drivers/wireless/ath9k/descriptor",
    smoke_ar9285_tx_descriptor_matches_frozen_reference
);

kernel_test_in!(
    "drivers/wireless/ath9k/descriptor",
    smoke_ar9285_descriptor_extent_and_raw_transmit_admission
);

kernel_test_in!(
    "drivers/wireless/ath9k/descriptor",
    smoke_ar9285_exact_done_and_native_failure_receipts
);

kernel_test_in!(
    "drivers/wireless/ath9k/descriptor",
    smoke_ar9285_raw_rx_profile_fcs_and_decrypt_admission
);
