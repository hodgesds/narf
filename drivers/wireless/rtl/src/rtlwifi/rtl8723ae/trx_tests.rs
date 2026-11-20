// SPDX-License-Identifier: GPL-2.0-or-later
//! Native descriptor literals distinguish the AE hardware-sequence field.
use super::*;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
fn smoke_ae_native_tx_descriptor_source_hwseq_and_command_literals() -> TestResult {
    let p = TxParams {
        pkt_size: 42,
        queue_sel: 0x12,
        macid: 0,
        rate_id: 7,
        hw_rate: 8,
        use_driver_rate: true,
        fwctrl_lps: true,
        seq: 0x123,
        buffer_addr: 0x01234000,
        ..TxParams::default()
    };
    let d = fill(&p);
    kt_assert_eq!(d[0], 42 | (32 << 16) | (1 << 26) | (1 << 27));
    kt_assert_eq!(d[1], 0x0007_1200);
    kt_assert_eq!(d[3], 0x8123_0000); // ONLY AE DW3 BIT31, no DW4 BIT7
    kt_assert_eq!(d[4], 0x0000_0100);
    kt_assert_eq!(d[5], 0x0001_ff08);
    kt_assert_eq!(d[7], 42);
    kt_assert_eq!(d[8], 0x01234000);
    kt_assert_eq!(d[9], 0);
    kt_assert!(!own(d[0]));
    let c = fill_cmd(768, 0x123400, false);
    kt_assert_eq!(c[0], 0x0c20_0300);
    kt_assert_eq!(c[1], 0x0007_1000);
    kt_assert_eq!(c[3], 0x8000_0000);
    kt_assert_eq!(c[4], 0x0000_0100);
    kt_assert_eq!(c[5], 0);
    kt_assert_eq!(c[7], 768);
    kt_assert_eq!(c[8], 0x123400);
    let q = fill(&TxParams {
        qos_data: true,
        ..p
    });
    kt_assert_eq!(q[3], 0x0123_0000);
    kt_assert_eq!(q[4] & 0x80, 0);
    TestResult::Pass
}
fn smoke_ae_native_rx_descriptor_buffer_offset_and_swdecrypt_literals() -> TestResult {
    let mut d = [0; 8];
    rx_arm(&mut d, 0x200000, 9100, true);
    kt_assert_eq!(d[0], 0xc000_238c);
    kt_assert_eq!(d[6], 0x200000);
    kt_assert!(RxStatus::parse(&d).is_none());
    // Driver-owned byte80 frame,8 bytes PHY info,shift2,FCS included,
    // software-decrypt required and legacy OFDM6M.
    d[0] = 80 | (1 << 16) | (2 << 24) | (1 << 26) | (1 << 27);
    d[3] = 4;
    d[5] = 0x12345678;
    let r = RxStatus::parse(&d).unwrap();
    kt_assert_eq!(r.length, 80);
    kt_assert_eq!(r.payload_offset(), 10);
    kt_assert!(!r.decrypted && !r.hw_error() && !r.ht && !r.bw_40);
    kt_assert_eq!(r.rate, 4);
    kt_assert_eq!(r.tsfl, 0x12345678);
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_native_tx_descriptor_source_hwseq_and_command_literals}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_native_rx_descriptor_buffer_offset_and_swdecrypt_literals}
