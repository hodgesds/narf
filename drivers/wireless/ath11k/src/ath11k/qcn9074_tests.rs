//! `hal_rx_desc_qcn9074` decode smoke. Field offsets are written out
//! from Linux `rx_desc.h` (`__packed` layout), not from the Rust structs.

use super::super::hw::HwRev;
use super::super::rx_descriptor::RxDescriptor;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn smoke_ath11k_hal_rx_desc_qcn9074_layout() -> TestResult {
    let mut b = [0u8; 384];
    // msdu_end (at 4): info4 (u16) at +42 — first, last, L3 pad 2.
    b[46..48].copy_from_slice(&((1u16 << 12) | (1 << 13) | (2 << 10)).to_le_bytes());
    // attention (at 76): info2 at +8 — msdu_done.
    put32(&mut b, 84, 1 << 31);
    // msdu_start (at 92): info1 +4 len 1500, info2 +8 decap 2, info3 +20,
    // phy_meta_data +28.
    put32(&mut b, 96, 1500);
    put32(&mut b, 100, 2 << 8);
    put32(&mut b, 112, 0x0000_2a00);
    put32(&mut b, 120, 5180);
    // mpdu_start_tag at 132; mpdu_start (at 136): info9 +28 (TID 6,
    // enc 3), sw_peer_id +42, info11 +44 (enc valid, seq 0x123), addr2 +66.
    put32(&mut b, 132, 0x64 << 1);
    put32(&mut b, 164, (6 << 15) | (3 << 2));
    b[178..180].copy_from_slice(&0x0042u16.to_le_bytes());
    put32(&mut b, 180, (0x123 << 20) | (1 << 9));
    b[202..208].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    // hdr_status at 264.
    b[264] = 0x88;
    let Some(d) = RxDescriptor::decode(HwRev::Qcn9074Hw10, &b) else {
        return TestResult::Fail("QCN9074 descriptor not decoded");
    };
    kt_assert!(matches!(d, RxDescriptor::Qcn9074(_)));
    kt_assert!(d.first_msdu() && d.last_msdu());
    kt_assert_eq!(d.l3_pad_bytes(), 2);
    kt_assert!(d.msdu_done());
    kt_assert_eq!(d.msdu_len(), 1500);
    kt_assert_eq!(d.decap_type(), 2);
    kt_assert_eq!(d.rate_info(), 0x2a00);
    kt_assert_eq!(d.msdu_freq(), 5180);
    kt_assert_eq!(d.mpdu_start_tag(), 0x64);
    kt_assert_eq!(d.mpdu_tid(), 6);
    kt_assert_eq!(d.encrypt_type(), 3);
    kt_assert!(d.encrypt_valid());
    kt_assert_eq!(d.mpdu_start_seq_no(), 0x123);
    kt_assert_eq!(d.mpdu_peer_id(), 0x42);
    kt_assert_eq!(d.mpdu_info1(), (0x123 << 20) | (1 << 9));
    kt_assert_eq!(d.addr2(), [2, 4, 6, 8, 10, 12]);
    kt_assert_eq!(d.hdr_status()[0], 0x88);
    kt_assert_eq!(RxDescriptor::msdu_len_offset(HwRev::Qcn9074Hw10), Some(96));
    kt_assert!(RxDescriptor::decode(HwRev::Qcn9074Hw10, &b[..383]).is_none());
    // copy_attention_end: msdu_end/attention/mpdu_end from the last.
    let mut first = d;
    let mut lb = b;
    lb[46..48].copy_from_slice(&0u16.to_le_bytes());
    put32(&mut lb, 84, 0);
    let Some(last) = RxDescriptor::decode(HwRev::Qcn9074Hw10, &lb) else {
        return TestResult::Fail("decode last");
    };
    kt_assert!(first.copy_attention_end(&last).is_ok());
    kt_assert!(!first.first_msdu() && !first.msdu_done());
    kt_assert_eq!(first.msdu_len(), 1500);
    let Some(ipq) = RxDescriptor::decode(HwRev::Qca6390Hw20, &b) else {
        return TestResult::Fail("decode ipq8074 layout");
    };
    kt_assert!(first.copy_attention_end(&ipq).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_rx_desc_qcn9074_layout
);
