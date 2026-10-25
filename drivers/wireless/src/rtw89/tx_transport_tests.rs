//! Shared native PCI transport tests; no hardware or global registry mutation.
use super::mac::ChipId;
use super::tx_transport::{parse_report, prepare_header, Error, Report, TxQueue};
use super::txrx::TxwdInfo;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn frame(length: usize) -> Vec<u8> {
    let mut frame = vec![0; length];
    frame[0] = 8; // Native ordinary data (not an Ethernet packet).
    frame[1] = 1; // To DS, three addresses.
    frame[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    frame
}
fn info(length: usize) -> TxwdInfo {
    TxwdInfo {
        channel: 0,
        qsel: 0,
        mac_id: 7,
        pkt_size: length as u16,
    }
}
fn report(sequence: u16) -> Report {
    Report {
        sequence,
        channel: 0,
        qsel: 0,
        mac_id: 7,
        status: 0,
    }
}
struct Resource(Arc<AtomicUsize>);
impl Drop for Resource {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn resource(count: &Arc<AtomicUsize>) -> Resource {
    Resource(count.clone())
}

fn smoke_rtw89_native_pci_headers() -> TestResult {
    let frame = frame(4090);
    for chip in [ChipId::Rtl8852A, ChipId::Rtl8852B, ChipId::Rtl8851B] {
        let high = if chip == ChipId::Rtl8852B { 0xb } else { 0xab };
        let header = prepare_header(
            chip,
            info(frame.len()),
            0x3456,
            (high << 32) | 0x1234_5000,
            &frame,
        )
        .unwrap();
        if header.len() != 40
            || word(&header, 0) != (12 << 11 | 1 << 7)
            || word(&header, 4) != 0
            || word(&header, 8) != (7 << 24 | 4090)
            || word(&header, 12) != 0x123
            || header[24..32] != [0x56, 0xb4, 0, 0, 0, 0, 0, 0]
            || header[32..34] != 4090u16.to_le_bytes()
            || header[34..36] != (0x8001u16 | ((high as u16) << 6)).to_le_bytes()
            || word(&header, 36) != 0x1234_5000
        {
            return TestResult::Fail("baseline TXWD/WP/address-info differs from Linux layout");
        }
    }
    let header = prepare_header(
        ChipId::Rtl8852C,
        info(frame.len()),
        5,
        0xa_1234_5000,
        &frame,
    )
    .unwrap();
    if header.len() != 58
        || word(&header, 4) != 3 << 26
        || header[24..32] != [0; 8]
        || header[32..40] != [5, 0x80, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("8852C body/WP/address-info extent");
    }
    let mut dma = 0xa_1234_5000u64;
    for (index, length) in [2044, 2044, 2].into_iter().enumerate() {
        let start = 40 + 6 * index;
        let flags = u16::from_le_bytes(header[start..start + 2].try_into().unwrap());
        let expected = length | 0xa << 11 | if index == 2 { 1 << 15 } else { 0 };
        if flags != expected || word(&header, start + 2) != dma as u32 {
            return TestResult::Fail("8852C 2044-byte contiguous segment split");
        }
        dma += length as u64;
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_native_pci_headers);

fn smoke_rtw89_native_rejects_unsupported_extents() -> TestResult {
    let good = frame(100);
    for chip in [ChipId::Rtl8852A, ChipId::Rtl8852C] {
        for index in [0, 1, 22] {
            let mut bad = good.clone();
            bad[index] |= match index {
                0 => 0x80,
                1 => 0x40,
                _ => 1,
            };
            if prepare_header(chip, info(100), 0, 0, &bad) != Err(Error::BadFrame) {
                return TestResult::Fail("QoS/protected/fragmented frame accepted");
            }
        }
        let mask = if chip == ChipId::Rtl8852C {
            0xf_ffff_ffff
        } else {
            0xff_ffff_ffff
        };
        for dma in [mask - 98, u64::MAX] {
            if prepare_header(chip, info(100), 0, dma, &good) != Err(Error::BadDma) {
                return TestResult::Fail("DMA extent crossed address mask");
            }
        }
    }
    let mut wrong = info(100);
    wrong.channel = 1;
    if prepare_header(ChipId::Rtl8852A, wrong, 0, 0, &good) != Err(Error::BadFrame)
        || prepare_header(ChipId::Rtl8922A, info(100), 0, 0, &good) != Err(Error::BadQueue)
        || prepare_header(ChipId::Rtl8852A, info(100), 0x8000, 0, &good) != Err(Error::BadFrame)
    {
        return TestResult::Fail("channel/profile/sequence mismatch accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_rejects_unsupported_extents
);

fn smoke_rtw89_rpq_pcie_mapping() -> TestResult {
    for qsel in 0..32u8 {
        let expected = match qsel {
            0..=15 => Some(qsel % 4),
            0x12 => Some(8),
            0x11 => Some(9),
            0x1a => Some(10),
            0x19 => Some(11),
            _ => None,
        };
        let raw = (0x3456u32 << 16 | 2 << 13 | (qsel as u32) << 8 | 7).to_le_bytes();
        match (parse_report(&raw), expected) {
            (Ok(parsed), Some(channel))
                if parsed
                    == (Report {
                        sequence: 0x3456,
                        channel,
                        qsel,
                        mac_id: 7,
                        status: 2,
                    }) => {}
            (Err(Error::BadQueue), None) => (),
            _ => return TestResult::Fail("RPQ PCI AC/management mapping"),
        }
    }
    for raw in [0x8000_0000u32, 4 << 13] {
        if parse_report(&raw.to_le_bytes()).is_ok() {
            return TestResult::Fail("polluted/reserved-status RPQ accepted");
        }
    }
    if parse_report(&[0; 8]).is_ok() {
        return TestResult::Fail("BE RPQ accepted as AX");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_rpq_pcie_mapping);

fn smoke_rtw89_native_retains_until_two_completions() -> TestResult {
    let count = Arc::new(AtomicUsize::new(0));
    let mut queue = TxQueue::new(0, 4).unwrap();
    let first = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    if !matches!(
        queue.observe_report(report(first.sequence)),
        Err(Error::NotPublished)
    ) {
        return TestResult::Fail("unpublished reservation released");
    }
    queue.publish(first).unwrap();
    if !queue.observe_read_pointer(1).unwrap().is_empty() || count.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("TXBD consumption freed packet before RPQ");
    }
    let done = queue
        .observe_report(report(first.sequence))
        .unwrap()
        .unwrap();
    if done.status != 0 || count.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("completion failed to transfer resource");
    }
    drop(done);
    let second = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    queue.publish(second).unwrap();
    if queue
        .observe_report(report(second.sequence))
        .unwrap()
        .is_some()
        || count.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("RPQ freed packet before TXBD consumption");
    }
    drop(queue.observe_read_pointer(2).unwrap());
    if count.load(Ordering::Relaxed) != 2 || queue.observe_report(report(first.sequence)).is_ok() {
        return TestResult::Fail("retirement leaked or accepted stale release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_retains_until_two_completions
);

fn smoke_rtw89_native_backpressure_and_invalid_updates() -> TestResult {
    let count = Arc::new(AtomicUsize::new(0));
    let mut queue = TxQueue::new(0, 3).unwrap();
    let first = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    queue.publish(first).unwrap();
    let second = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    queue.publish(second).unwrap();
    if !queue.is_full()
        || !matches!(queue.observe_read_pointer(3), Err(Error::BadIndex))
        || queue.write_pointer() != 2
    {
        return TestResult::Fail("ring bound/update validation");
    }
    // Wrong identity/status cannot authorize freeing either DMA allocation.
    for bad in [
        Report {
            mac_id: 8,
            ..report(first.sequence)
        },
        Report {
            channel: 1,
            ..report(first.sequence)
        },
    ] {
        if queue.observe_report(bad).is_ok() {
            return TestResult::Fail("mismatched RPQ identity accepted");
        }
    }
    queue.observe_report(report(first.sequence)).unwrap();
    if !matches!(
        queue.observe_report(Report {
            status: 1,
            ..report(first.sequence)
        }),
        Err(Error::ConflictingReport)
    ) {
        return TestResult::Fail("contradictory duplicate status accepted");
    }
    drop(queue.observe_read_pointer(2).unwrap()); // first retired, second still retained
    let third = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    queue.publish(third).unwrap();
    let fourth = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    queue.publish(fourth).unwrap();
    // Hardware caught up, but WP now targets the second packet awaiting RPQ.
    drop(queue.observe_read_pointer(1).unwrap());
    if !queue.is_full() || count.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("ring wrap reused packet still owned by firmware");
    }
    for ticket in [second, third, fourth] {
        drop(queue.observe_report(report(ticket.sequence)).unwrap());
    }
    if count.load(Ordering::Relaxed) != 4 {
        return TestResult::Fail("wrapped retirement did not free once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_backpressure_and_invalid_updates
);

fn smoke_rtw89_native_abort_and_unquiesced_drop() -> TestResult {
    let count = Arc::new(AtomicUsize::new(0));
    let mut queue = TxQueue::new(0, 2).unwrap();
    let first = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    drop(queue.abort(first).unwrap());
    if count.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("pre-publication abort leaked");
    }
    let next = queue.reserve(resource(&count), 7, 0).ok().unwrap();
    queue.publish(next).unwrap();
    if queue.abort(next).is_ok() {
        return TestResult::Fail("published packet aborted without quiescence");
    }
    drop(queue);
    if count.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("unquiesced DMA freed on owner Drop");
    }
    // One bounded deliberately retained test resource, mirroring hardware
    // ownership: a future reset owner must establish quiescence to reclaim it.
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_native_abort_and_unquiesced_drop
);
