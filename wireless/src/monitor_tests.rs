use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_monitor_radiotap_preserves_raw_headers_and_only_observed_metadata() -> TestResult {
    let mut frame = vec![0; 30];
    frame[..2].copy_from_slice(&[0x88, 0xc2]);
    frame[24..30].copy_from_slice(&[5, 0, 0x1b, 0, 0, 0]);
    let Ok(bytes) = encode(
        &frame,
        Metadata {
            frequency_mhz: 5180,
            signal_dbm: Some(-42),
        },
    ) else {
        return TestResult::Fail("raw +HTC monitor frame rejected");
    };
    if bytes[..15] != [0, 0, 15, 0, 0x2a, 0, 0, 0, 4, 0, 0x3c, 0x14, 0, 1, 214]
        || bytes[15..] != frame
    {
        return TestResult::Fail(
            "radiotap alignment/presence/literal metadata or original MPDU changed",
        );
    }
    let mut ack = vec![0; 10];
    ack[0] = 0xd4;
    let Ok(bytes) = encode(
        &ack,
        Metadata {
            frequency_mhz: 5975,
            signal_dbm: None,
        },
    ) else {
        return TestResult::Fail("monitor ACK or exact six-GHz identity refused");
    };
    if bytes[..14] != [0, 0, 14, 0, 0x0a, 0, 0, 0, 0, 0, 0x57, 0x17, 0, 0] || bytes[14..] != ack {
        return TestResult::Fail("absent metadata was synthesized or six-GHz mislabeled");
    }
    for n in 0..10 {
        if encode(
            &ack[..n],
            Metadata {
                frequency_mhz: 2412,
                signal_dbm: None,
            },
        )
        .is_ok()
        {
            return TestResult::Fail("truncated monitor header admitted");
        }
    }
    if encode(
        &frame,
        Metadata {
            frequency_mhz: 5001,
            signal_dbm: None,
        },
    ) != Err(Error::Frequency)
    {
        return TestResult::Fail("invalid RX frequency became valid radiotap metadata");
    }
    let mut block_ack = vec![0; 32];
    block_ack[0] = 0x94;
    block_ack[22] = 0xff;
    let encoded = encode(
        &block_ack,
        Metadata {
            frequency_mhz: 2412,
            signal_dbm: None,
        },
    )
    .unwrap();
    if encoded[8] != 0 {
        return TestResult::Fail("control bitmap byte fabricated sequence-fragment metadata");
    }
    if encode(
        &ack,
        Metadata {
            frequency_mhz: 5965,
            signal_dbm: None,
        },
    ) != Err(Error::Frequency)
    {
        return TestResult::Fail("six-GHz center-only frequency became primary RX metadata");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/monitor",
    smoke_monitor_radiotap_preserves_raw_headers_and_only_observed_metadata
);
