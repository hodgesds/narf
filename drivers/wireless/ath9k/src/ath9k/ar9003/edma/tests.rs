use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Log(Vec<(u64, u32)>);

impl RegisterIo for Log {
    fn read32(&mut self, _offset: u64) -> u32 {
        0
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.0.push((offset, value));
    }
}

fn smoke_ath9k_ar9300_edma_tx_control_and_status_ring() -> TestResult {
    let info = TxInfo {
        qcu: 1,
        link: 0x1000_0080,
        buffers: [(0x2000_0000, 1500), (0, 0), (0, 0), (0, 0)],
        is_first: true,
        is_last: true,
        pkt_len: 1504,
        frame_type: 0,
        flags: flag::CLRDMASK | flag::RTSENA,
        keyix: None,
        dur_update: true,
        rates: [
            Series {
                tries: 4,
                rate: 0x0b,
                packet_duration: 0x123,
                chain_select: 7,
                rts_cts: true,
                ..Series::default()
            },
            Series::default(),
            Series::default(),
            Series::default(),
        ],
        rtscts_rate: 0x1b,
        txpower: [20, 0, 0, 0],
    };
    let mut w = tx_control(&info);
    let info_word = (0x168c << 16) | 0xc000 | (1 << 8) | 0x17;
    let len = 1500u32 << 16;
    let sum = info_word + 0x1000_0080 + 0x2000_0000 + len;
    let expected_sum = ((sum & 0xffff) + (sum >> 16)) & 0xffff;
    if w[0] != info_word
        || w[3] != len
        || w[10] != expected_sum
        || w[11] != 1504 | (20 << 16) | 0x100_0000 | 0x40_0000
        || w[12] != 0
        || w[13] != (4 << 16) | 0x8000
        || w[14] != 0x0b
        || w[15] != 0x123 | 0x8000
        || w[18] != (7 << 2) | (0x1b << 20)
        || w[19] != 0x2000_0000
    {
        return TestResult::Fail("ar9003_set_txdesc words differ");
    }
    set_link(&mut w, 0x1000_0100);
    let sum = sum - 0x1000_0080 + 0x1000_0100;
    if w[1] != 0x1000_0100 || w[10] & 0xffff != ((sum & 0xffff) + (sum >> 16)) & 0xffff {
        return TestResult::Fail("ar9003_hw_set_desc_link checksum differs");
    }
    // Middle buffer of a chain: only DMA words and AR_TxMore.
    let middle = tx_control(&TxInfo {
        is_first: false,
        is_last: false,
        ..info
    });
    if middle[11] != 0 || middle[12] != 0x1000 || middle[13] != 0 || middle[18] != 0 {
        return TestResult::Fail("non-first descriptor carries frame controls");
    }
    let mut io = Log::default();
    let Ok(mut ring) = StatusRing::setup(&mut io, 0x3000_0000, 512) else {
        return TestResult::Fail("status ring setup refused");
    };
    if io.0 != [(0x830, 0x3000_0000), (0x834, 0x3000_0000 + 512 * 36)] {
        return TestResult::Fail("AR_Q_STATUS_RING_START/END differ");
    }
    let mut entry = [0u32; TXS_WORDS];
    if ring.process(&mut entry) != Ok(None) || ring.tail != 0 {
        return TestResult::Fail("pending status consumed");
    }
    entry[0] = (0x168c << 16) | 0x8000 | (1 << 8);
    entry[1] = 7 << 16;
    entry[2] = 0x4000_0000 | 0x30_2010;
    entry[3] = 0x2 | (3 << 4) | (5 << 8);
    entry[4] = 0xdead;
    entry[5] = 0xff;
    entry[6] = 1;
    entry[7] = 0x2a00_0000;
    entry[8] = 1 | (0x55 << 1) | (2 << 21) | (6 << 28);
    let Ok(Some(status)) = ring.process(&mut entry) else {
        return TestResult::Fail("completed status not parsed");
    };
    if ring.tail != 1
        || entry != [0; TXS_WORDS]
        || status.qid != 1
        || status.desc_id != 7
        || status.seqnum != 0x55
        || status.rate_index != 2
        || status.tid != 6
        || !status.excessive_retries
        || status.block_ack != Some((0xff, 1))
        || (status.short_retry, status.long_retry) != (3, 5)
        || status.rssi != 0x2a
        || status.rssi_ctl != [0x10, 0x20, 0x30]
        || status.tstamp != 0xdead
    {
        return TestResult::Fail("ar9003_hw_proc_txdesc fields differ");
    }
    if status.raises_trigger_level() {
        return TestResult::Fail("underrun-free status raises the trigger level");
    }
    entry[8] = 1;
    entry[0] = 0x1234 << 16;
    if ring.process(&mut entry) != Err(BringUpError::BadState) || ring.tail != 2 {
        return TestResult::Fail("foreign TX status not refused after advancing");
    }
    io.0.clear();
    if ring.reset(&mut io).is_err() || ring.tail != 0 || io.0.len() != 2 {
        return TestResult::Fail("ath9k_hw_reset_txstatus_ring differs");
    }
    if (RX_HP_QDEPTH, RX_LP_QDEPTH) != (16, 128) {
        return TestResult::Fail("EDMA RX queue depths differ");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_edma_tx_control_and_status_ring
);

fn rx_buffer(words: [u32; 12]) -> [u8; RXS_BYTES] {
    let mut out = [0u8; RXS_BYTES];
    for (i, w) in words.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn smoke_ath9k_ar9300_edma_rx_status() -> TestResult {
    let mut w = [0u32; 12];
    w[0] = 0x168c << 16;
    w[1] = (0x0b << 24) | 0x0003_0201;
    w[2] = 1500;
    w[3] = 77;
    w[4] = (5 << 8) | 0x1;
    w[5] = 0x2d00_0000;
    w[11] = 1 | 0x2 | 0x100 | (9 << 9);
    let mut io = Log::default();
    if set_rx_bufsize(&mut io, 0x1f00).is_err()
        || add_rx_buffer(&mut io, RxQueue::High, 0x4000).is_err()
        || add_rx_buffer(&mut io, RxQueue::Low, 0x5000).is_err()
        || io.0 != [(0x60, 0xf00), (0x74, 0x4000), (0x78, 0x5000)]
    {
        return TestResult::Fail("RX FIFO register writes differ");
    }
    let Ok(Some(good)) = process_rx(&rx_buffer(w)) else {
        return TestResult::Fail("completed RX status not parsed");
    };
    if good.datalen != 1500
        || good.rate != 0x0b
        || good.rssi != 0x2d
        || good.rssi_ctl != [1, 2, 3]
        || good.keyix != Some(9)
        || good.antenna != 5
        || !good.short_gi
        || good.crc_error
        || good.phy_error.is_some()
    {
        return TestResult::Fail("ath9k_hw_process_rxdesc_edma fields differ");
    }
    // Not done, TX/control descriptor, foreign ID, CRC and restart rules.
    let mut pending = w;
    pending[11] = 0;
    let mut control = w;
    control[0] |= 0x4000;
    let mut foreign = w;
    foreign[0] = 0;
    let mut crc = w;
    crc[11] = 1 | 0x4 | 0x8 | 0x10 | (23 << 8);
    let mut restart = crc;
    restart[11] |= 0x4_0000;
    let crc = process_rx(&rx_buffer(crc));
    let restart = process_rx(&rx_buffer(restart));
    if process_rx(&rx_buffer(pending)) != Ok(None)
        || process_rx(&rx_buffer(control)) != Ok(None)
        || process_rx(&rx_buffer(foreign)) != Err(BringUpError::BadState)
        || process_rx(&[0; 47]) != Err(BringUpError::BadLength)
        || !matches!(crc, Ok(Some(s)) if s.crc_error && !s.decrypt_error && s.phy_error == Some(23))
        || !matches!(restart, Ok(Some(s)) if s.phy_error.is_none() && s.delim_crc_post)
    {
        return TestResult::Fail("RX status refusal or error decode differs");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_edma_rx_status
);

fn smoke_ath9k_ar9300_edma_rx_status_sample_never_mixes_occupants() -> TestResult {
    // A receive buffer is handed to the device with its 48-byte status
    // cleared, and the host may be sampling it when the device writes the
    // completed status. Model the device posting the WHOLE status after
    // each possible number of host loads. Whatever the interleaving, a
    // sample that reports AR_RxDone must be the completed status in full:
    // with the cleared buffer's words under a set AR_RxDone the frame is
    // delivered with a zero length and a wrong `more` flag.
    let old = [0u32; 12];
    let mut new = [0u32; 12];
    for (index, word) in new.iter_mut().enumerate() {
        *word = 0xA500_0000 | ((index as u32) << 8);
    }
    new[0] = 0x168c << 16; // AR_DescId: Atheros vendor id
    new[2] = 0x1000 | 0x5EA; // more + datalen
    new[11] = 0x3; // AR_RxDone | AR_RxFrameOK

    for post_after in 0..=12usize {
        let slot = core::cell::Cell::new(old);
        let loads = core::cell::Cell::new(0usize);
        let acquired = core::cell::Cell::new(false);
        let sampled = sample_rx_status(
            |index| {
                if loads.get() == post_after {
                    slot.set(new);
                }
                loads.set(loads.get() + 1);
                Ok::<u32, ()>(slot.get()[index])
            },
            || acquired.set(true),
        );
        let Ok(sampled) = sampled else {
            return TestResult::Fail("infallible status sample failed");
        };
        let Some(status) = sampled else {
            // Not completed yet: the driver polls again.
            if post_after == 0 {
                return TestResult::Fail("a status posted before the sample read as pending");
            }
            if loads.get() != 1 || acquired.get() {
                return TestResult::Fail("a pending status was read past its done word");
            }
            continue;
        };
        if loads.get() != 12 || !acquired.get() {
            return TestResult::Fail("a completed sample is not done word, barrier, 11 words");
        }
        let words: [u32; 12] = core::array::from_fn(|index| {
            u32::from_le_bytes(status[4 * index..4 * index + 4].try_into().unwrap())
        });
        if words != new {
            return TestResult::Fail("AR_RxDone sampled with words of the cleared status");
        }
        let Ok(Some(decoded)) = process_rx(&status) else {
            return TestResult::Fail("completed status sample did not decode");
        };
        if decoded.datalen != 0x5EA || !decoded.more {
            return TestResult::Fail("AR_RxDone sampled with a stale datalen or more flag");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_edma_rx_status_sample_never_mixes_occupants
);
