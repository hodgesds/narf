use super::super::{frame_api, transport::IwlMmio};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Mmio;
impl IwlMmio for Mmio {
    fn read(&mut self, _: u32) -> u32 {
        0
    }
    fn write(&mut self, _: u32, _: u32) {}
}
fn queue(id: u16, tid: u8, start: u16) -> DataQueue {
    let mut q = DataQueue::new().unwrap();
    q.configure(0, tid).unwrap();
    let mut response = [0; 8];
    put16(&mut response, 0, id);
    put16(&mut response, 4, start);
    q.activate(&response).unwrap();
    q.enable_aggregation();
    q
}

fn smoke_ampdu_tx_completion_is_atomic_and_wraps() -> TestResult {
    let mut queues = [queue(17, 0, 65534), queue(18, 4, 9)];
    for q in &mut queues {
        for _ in 0..3 {
            q.send(&mut Mmio, &[0; 30], 26, None).unwrap();
        }
    }
    let mut body = [0; 48];
    put16(&mut body, 28, 2);
    put16(&mut body, 32, 17);
    put16(&mut body, 34, 1);
    put16(&mut body, 40, 18);
    put16(&mut body, 42, 13);
    body[45] = 4;
    // The first entry is valid; the second points beyond submitted DMA.
    if complete_tx_ba(&mut queues, &body).is_ok() || queues[0].is_idle() || queues[1].is_idle() {
        return TestResult::Fail("partial DMA reclaim on malformed compressed BA");
    }
    put16(&mut body, 42, 12);
    body[45] = 3;
    if complete_tx_ba(&mut queues, &body).is_ok() || queues[0].is_idle() {
        return TestResult::Fail("cross-TID BA reclaimed DMA");
    }
    body[45] = 4;
    // Firmware debug RA/TID counts do not change the TFD array layout.
    put16(&mut body, 30, 2);
    complete_tx_ba(&mut queues, &body).unwrap();
    if !queues.iter().all(DataQueue::is_idle) || !queues[0].has_completed(0) {
        return TestResult::Fail("compressed BA did not reclaim wrapped interval");
    }
    // Repeated cumulative status is harmless but cannot return more credit.
    complete_tx_ba(&mut queues, &body).unwrap();
    body[4] = 1;
    if complete_tx_ba(&mut queues, &body).is_ok() {
        return TestResult::Fail("cross-station BA accepted");
    }
    body[4] = 0;
    put16(&mut body, 40, 17);
    body[45] = 0;
    if complete_tx_ba(&mut queues, &body).is_ok()
        || complete_tx_ba(&mut queues, &body[..47]).is_ok()
    {
        return TestResult::Fail("duplicate/truncated BA accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_ampdu_tx_completion_is_atomic_and_wraps
);

fn smoke_ampdu_single_retry_cumulative_completion() -> TestResult {
    let mut q = queue(17, 0, 127);
    for _ in 0..3 {
        q.send(&mut Mmio, &[0; 30], 26, None).unwrap();
    }
    let first = q.next_completion();
    let mut body = [0; 48];
    body[0] = 1;
    put16(&mut body, 36, 17);
    put32(&mut body, 44, 130);
    if first != 128 || q.complete(&body) != Ok((130, false)) || !q.is_idle() {
        return TestResult::Fail("failed single retry did not retire cumulative TFD interval");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_ampdu_single_retry_cumulative_completion
);

fn packet(sn: u16, nssn: u16, pn: u64) -> Vec<u8> {
    let mut packet = alloc::vec![0; 64 + 26 + 8 + 10];
    put16(&mut packet, 0, 44);
    put32(&mut packet, 12, 0x243); // CRC, overrun and CCMP MIC valid
    put32(
        &mut packet,
        16,
        (3 << 24) | ((sn as u32) << 12) | nssn as u32,
    );
    let frame = &mut packet[64..];
    frame[..2].copy_from_slice(&[0x88, 0x42]);
    frame[4..10].copy_from_slice(&[2; 6]);
    frame[10..16].copy_from_slice(&[4; 6]);
    frame[16..22].copy_from_slice(&[6; 6]);
    put16(frame, 22, sn << 4);
    frame[26..34].copy_from_slice(&[
        pn as u8,
        (pn >> 8) as u8,
        0,
        0x20,
        (pn >> 16) as u8,
        (pn >> 24) as u8,
        (pn >> 32) as u8,
        (pn >> 40) as u8,
    ]);
    frame[34..44].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, sn as u8, 0]);
    packet
}

fn smoke_ampdu_rx_reorder_before_ccmp_replay() -> TestResult {
    let mut window = Window::new(3, 0, 7, 100, 64, 0, 0).unwrap();
    let mut replay = frame_api::Replay::default();
    if !window.push(&packet(101, 100, 11), 1).is_empty() {
        return TestResult::Fail("released past a hole");
    }
    if !window.push(&packet(101, 100, 11), 2).is_empty() {
        return TestResult::Fail("duplicate buffered MPDU released");
    }
    let released = window.push(&packet(100, 102, 10), 3);
    if released.len() != 2 {
        return TestResult::Fail("out-of-order MPDUs not released contiguously");
    }
    for (i, bytes) in released.iter().enumerate() {
        let frame = frame_api::receive(
            &scan_api::mpdu(bytes).unwrap(),
            [2; 6],
            [4; 6],
            true,
            &mut replay,
        );
        if frame.as_ref().is_none_or(|f| f[14] != 100 + i as u8) {
            return TestResult::Fail("PN checked before sequence reordering");
        }
    }
    if replay.pairwise[0] != 11 || !window.push(&packet(100, 102, 10), 4).is_empty() {
        return TestResult::Fail("old BA sequence or PN replay accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_ampdu_rx_reorder_before_ccmp_replay
);

fn smoke_ampdu_rx_wrap_nonpower_window_and_release() -> TestResult {
    let mut window = Window::new(3, 0, 1, 4094, 63, 0, 0).unwrap();
    if !window.push(&packet(0, 4094, 3), 0).is_empty()
        || !window.push(&packet(4095, 4094, 2), 0).is_empty()
    {
        return TestResult::Fail("wrapped RX window released across hole");
    }
    let frames = window.push(&packet(4094, 1, 1), 0);
    if frames.len() != 3 || window.head != 1 {
        return TestResult::Fail("non-power-of-two BA window aliases across sequence wrap");
    }
    window.push(&packet(3, 1, 5), 0);
    if window.release(4, 1).len() != 1 || window.head != 4 {
        return TestResult::Fail("firmware/BAR release lost buffered packet");
    }
    if !window.release(4095, 2).is_empty() || window.head != 4 {
        return TestResult::Fail("stale release moved window backwards");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_ampdu_rx_wrap_nonpower_window_and_release
);

fn smoke_ampdu_rx_hole_timeout_and_key_discard() -> TestResult {
    let mut window = Window::new(3, 0, 1, 10, 16, 100, 0).unwrap();
    window.push(&packet(11, 10, 1), 0);
    let elapsed = narf_time::wall::ns_to_cycles(101_000_000);
    if window.tick(elapsed).len() != 1 || window.head != 12 {
        return TestResult::Fail("lost MPDU stalls RX indefinitely");
    }
    window.push(&packet(13, 12, 2), elapsed);
    window.discard();
    if !window.release(14, elapsed).is_empty() {
        return TestResult::Fail("key transition delivered buffered old-key MPDU");
    }
    if !window.expired(elapsed + narf_time::wall::ns_to_cycles(103_000_000)) {
        return TestResult::Fail("BA session inactivity timeout not enforced");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_ampdu_rx_hole_timeout_and_key_discard
);

fn smoke_block_ack_actions_and_firmware_commands() -> TestResult {
    let request = [3, 0, 9, 0x13, 0x10, 100, 0, 0x30, 0x12]; // TID4,64,SSN0x123
    if action(&request)
        != Some(Action::Add {
            token: 9,
            tid: 4,
            window: 64,
            ssn: 0x123,
            timeout: 100,
            immediate: true,
        })
    {
        return TestResult::Fail("ADDBA request wire decode");
    }
    if add_response(9, 4, 64, 100, 0) != [3, 1, 9, 0, 0, 0x12, 0x10, 100, 0]
        || allocate(4, 0x123, 64) != [0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0x23, 1, 64, 0]
        || remove(4) != [2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("BAID v2 or ADDBA response layout/A-MSDU policy");
    }
    if action(&[3, 2, 0, 0x48, 39, 0])
        != Some(Action::Delete {
            tid: 4,
            originator: true,
        })
        || action(&request[..8]).is_some()
    {
        return TestResult::Fail("DELBA direction or truncated action");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_block_ack_actions_and_firmware_commands
);

fn smoke_rx_deaggregated_amsdu_pn_and_subframe_order() -> TestResult {
    let mut first = packet(100, 101, 5);
    first[3] = 0x40;
    first[4] = 1;
    first[64 + 24] = 0x80;
    let mut replay = frame_api::Replay::default();
    let receive = |p: &[u8], replay: &mut frame_api::Replay| {
        frame_api::receive(&scan_api::mpdu(p).unwrap(), [2; 6], [4; 6], true, replay)
    };
    if receive(&first, &mut replay).is_none() || receive(&first, &mut replay).is_some() {
        return TestResult::Fail("A-MSDU first subframe/duplicate validation");
    }
    let mut last = first.clone();
    last[4] = 0x82;
    if receive(&last, &mut replay).is_none() || receive(&last, &mut replay).is_some() {
        return TestResult::Fail("same-PN A-MSDU continuation not bound to ordered subframe");
    }
    last[4] = 0x83;
    if receive(&last, &mut replay).is_some() {
        return TestResult::Fail("accepted subframe after final A-MSDU member");
    }
    let mut gap = frame_api::Replay::default();
    last[4] = 0x82;
    if receive(&last, &mut gap).is_some() {
        return TestResult::Fail("A-MSDU tail bypassed first-subframe PN validation");
    }
    let mut zero_based = first.clone();
    zero_based[4] = 0;
    if receive(&zero_based, &mut gap).is_none() {
        return TestResult::Fail("zero-based firmware A-MSDU first member rejected");
    }
    zero_based[4] = 0x81;
    if receive(&zero_based, &mut gap).is_none() {
        return TestResult::Fail("zero-based A-MSDU continuation rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_rx_deaggregated_amsdu_pn_and_subframe_order
);

fn smoke_amsdu_continuation_cannot_cross_keys() -> TestResult {
    let mut first = packet(100, 101, 5);
    first[3] = 0x40;
    first[4] = 1;
    first[88] = 0x80;
    let mut replay = frame_api::Replay::default();
    replay.group_valid[0] = true;
    replay.group[0][0] = 5;
    let receive = |p: &[u8], replay: &mut frame_api::Replay| {
        frame_api::receive(&scan_api::mpdu(p).unwrap(), [2; 6], [4; 6], true, replay)
    };
    receive(&first, &mut replay).unwrap();
    let mut tail = first.clone();
    tail[4] = 0x82;
    tail[68] = 0xff; // change pairwise aggregate into GTK continuation
    if receive(&tail, &mut replay).is_some() {
        return TestResult::Fail("same-PN A-MSDU continuation crossed key identity");
    }
    tail[68] = 2;
    if receive(&tail, &mut replay).is_none() {
        return TestResult::Fail("rejected cross-key frame poisoned valid continuation");
    }
    replay.reset_subframes();
    if receive(&tail, &mut replay).is_some() {
        return TestResult::Fail("key transition retained A-MSDU continuation state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_amsdu_continuation_cannot_cross_keys
);
