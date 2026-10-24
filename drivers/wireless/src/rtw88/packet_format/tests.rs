use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(crate) fn frame(length: usize, management: bool) -> alloc::vec::Vec<u8> {
    let mut frame = vec![0x59; length];
    frame[..2].copy_from_slice(if management { &[0xb0, 0] } else { &[8, 1] });
    frame[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[10..16].copy_from_slice(&OWN);
    frame[22..24].copy_from_slice(&[0xc0, 0xab]);
    frame
}
fn smoke_rtw8822ce_packet_geometry_and_original_pci_tx() -> TestResult {
    if LINUX_GEOMETRY != [40, TX_BD, RX_DESC, RX_BD] {
        return TestResult::Fail("native packet geometry differs");
    }
    for &(length, management, mac_id, report, expected, bd) in TX_CASES {
        let frame = frame(length, management);
        let Ok((actual, queue)) = transmit(&frame, OWN, mac_id, report) else {
            return TestResult::Fail("native frame rejected");
        };
        for (index, value) in expected.into_iter().enumerate() {
            if word(&actual, index * 4) != value {
                return TestResult::Fail("packet TXD differs from original C");
            }
        }
        if queue
            != if management {
                Queue::Management
            } else {
                Queue::Data
            }
        {
            return TestResult::Fail("native queue differs");
        }
        let Ok(actual) = buffer_descriptor(0x1234_5000, length) else {
            return TestResult::Fail("native BD rejected");
        };
        for (index, value) in bd.into_iter().enumerate() {
            if word(&actual, index * 4) != value {
                return TestResult::Fail("PCI TXBD differs from original C");
            }
        }
    }
    TestResult::Pass
}
fn smoke_rtw8822ce_raw_rx_and_ccx_original_c() -> TestResult {
    for &(words, start, length, c2h, decrypted) in RX_CASES {
        let mut descriptor = [0; RX_DESC];
        for (index, value) in words.into_iter().enumerate() {
            put(&mut descriptor, index * 4, value);
        }
        let result = receive(&descriptor);
        if decrypted && !c2h {
            if result.is_ok() {
                return TestResult::Fail("hardware plaintext admitted as raw");
            }
        } else if result
            != Ok(Receive {
                payload: start..start + length,
                c2h,
                rate: 11,
            })
        {
            return TestResult::Fail("RX envelope differs from original C");
        }
    }
    for &(id, sequence, status, expected, ack) in REPORT_CASES {
        let mut body = [0; 12];
        body[0] = id;
        if id == 3 {
            body[2] = status;
            body[8] = sequence;
        } else {
            body[2] = 15;
            body[10] = sequence;
            body[11] = status;
        }
        if report(&body)
            != Ok(Some(Report {
                sequence: expected,
                acknowledged: ack,
            }))
        {
            return TestResult::Fail("CCX result differs from original C");
        }
    }
    TestResult::Pass
}
fn smoke_rtw8822ce_packet_metadata_extent_and_profile_refusals() -> TestResult {
    let original = frame(100, false);
    for (index, mask) in [
        (0, 0x80),
        (1, 2),
        (1, 4),
        (1, 16),
        (1, 32),
        (1, 128),
        (10, 1),
        (22, 1),
    ] {
        let mut bad = original.clone();
        bad[index] ^= mask;
        if transmit(&bad, OWN, 0, None).is_ok() {
            return TestResult::Fail("unsupported native TX admitted");
        }
    }
    if transmit(&original, OWN, 128, None).is_ok() || transmit(&original, OWN, 0, Some(3)).is_ok() {
        return TestResult::Fail("invalid MAC/report identity admitted");
    }
    for base in [0, 1, u64::from(u32::MAX) - 3, 0x1_0000_0000] {
        if buffer_descriptor(base, 100).is_ok() {
            return TestResult::Fail("incomplete DMA extent accepted");
        }
    }
    let mut descriptor = [0; RX_DESC];
    put(&mut descriptor, 0, 100);
    for (first, rate, bw) in [
        (0, 0, 0),
        (4, 0, 0),
        (100 | 1 << 14, 0, 0),
        (100 | 1 << 15, 0, 0),
        (100 | 1 << 16, 0, 0),
        (100 | 1 << 26, 0, 0),
        (100 | 4 << 20, 0, 0),
        (100, 12, 0),
        (100, 0, 0x10),
    ] {
        put(&mut descriptor, 0, first);
        put(&mut descriptor, 12, rate);
        put(&mut descriptor, 16, bw);
        if receive(&descriptor).is_ok() {
            return TestResult::Fail("invalid raw RX profile admitted");
        }
    }
    for id in [3, 255] {
        let mut body = [0; 12];
        body[0] = id;
        if id == 255 {
            body[2] = 15;
        }
        let minimum = if id == 3 { 9 } else { 12 };
        for length in 0..minimum {
            if report(&body[..length]).is_ok() {
                return TestResult::Fail("truncated CCX accepted");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/packet",
    smoke_rtw8822ce_packet_geometry_and_original_pci_tx
);
kernel_test_in!(
    "drivers/wireless/rtw88/packet",
    smoke_rtw8822ce_raw_rx_and_ccx_original_c
);
kernel_test_in!(
    "drivers/wireless/rtw88/packet",
    smoke_rtw8822ce_packet_metadata_extent_and_profile_refusals
);
