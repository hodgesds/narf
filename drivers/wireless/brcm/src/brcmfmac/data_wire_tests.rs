use super::msgbuf::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn smoke_brcmf_linux_literal_tx_frame_descriptor() -> TestResult {
    let expected = [
        0x0f, 0, 0, 0, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x61, 1, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x34, 0x12, 0x78, 0x56, 0, 0, 0, 0,
    ];
    let desc = TxPost {
        hdr: CommonHdr {
            msgtype: 0xf,
            ifidx: 0,
            flags: 0,
            request_id: 0x01020304,
        },
        tx_header: core::array::from_fn(|i| i as u8),
        flags: 0x61,
        segments: 1,
        metadata_buf_addr: BufAddr(0x1122334455667788),
        data_buf_addr: BufAddr(0x1112131415161718),
        metadata_len: 0x1234,
        data_len: 0x5678,
    };
    let mut bytes = [0xa5; 48];
    if desc.encode(&mut bytes) != Some(())
        || bytes != expected
        || TxPost::decode(&expected) != Some(desc)
    {
        return TestResult::Fail("Linux txhdr/flags/segment/DMA/length offsets differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_linux_literal_tx_frame_descriptor
);
fn smoke_brcmf_linux_literal_classic_completions() -> TestResult {
    let tx = [
        0x10, 0, 0, 0, 4, 3, 2, 1, 0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0xf0, 0xde,
    ];
    let t = match TxStatus::decode(&tx) {
        Some(v) => v,
        None => return TestResult::Fail("classic16-byte TX status rejected"),
    };
    if t.status != 0x1234
        || t.flow_ring_id != 0x5678
        || t.metadata_len != 0x9abc
        || t.tx_status != 0xdef0
    {
        return TestResult::Fail("TX status metadata/status truncated or offset");
    }
    let rx = [
        0x12, 0, 0, 0, 4, 3, 2, 1, 0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0xf0, 0xde, 0x34, 0x12,
        0x78, 0x56, 0xbc, 0x9a, 0xf0, 0xde, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0,
    ];
    let r = match RxComplete::decode(&rx) {
        Some(v) => v,
        None => return TestResult::Fail("classic32-byte RX completion rejected"),
    };
    if r.metadata_len != 0x9abc
        || r.data_len != 0xdef0
        || r.data_offset != 0x1234
        || r.flags != 0x5678
        || r.rx_status_0 != 0xdef09abc
        || r.rx_status_1 != 0x78563412
    {
        return TestResult::Fail("RX completion wide fields truncated or misplaced");
    }
    if TxStatus::decode(&tx[..15]).is_some() || RxComplete::decode(&rx[..31]).is_some() {
        return TestResult::Fail("short classic completion accepted");
    }
    let mut wrong = tx;
    wrong[0] = 0x12;
    if TxStatus::decode(&wrong).is_some() {
        return TestResult::Fail("wrong completion type accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_linux_literal_classic_completions
);
