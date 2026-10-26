//! Native cut-through queue ownership; no host completion or synthetic BA ACK.
use super::*;

fn mt76_native_originator_txd_eligibility_keeps_per_msdu_tokens_and_no_amsdu() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("native originator allocation"),
    };
    hw.owner.published = true;
    for n in 0..8 {
        let frame = ethernet(n as u8);
        if hw
            .submit_data_profile(&frame, true, true, true, true)
            .is_err()
        {
            return TestResult::Fail("native originator queued packet");
        }
        let slot = &hw.owner.storage.as_ref().unwrap().data.buffers[n];
        let bytes = slot.as_slice();
        if bytes[12..16] != (15u32 << 11 | 2).to_le_bytes()
            || bytes[4..8] != 0x8000_8001u32.to_le_bytes()
            || bytes[8..12] != [0x28, 0, 0, 0]
            || bytes[28..32] != 0x0028_0000u32.to_le_bytes()
            || bytes[32..34] != (0x8001 + n as u16).to_le_bytes()
            || bytes[64..124] != frame
        {
            return TestResult::Fail(
                "originator TXD changed source QoS/key/sequence/no-AMSDU/per-MSDU ownership fields",
            );
        }
    }
    let records: Vec<_> = (1..=8).map(|token| (token, 0)).collect();
    inject_rx(&mut words, &hw, 0, &free(&records));
    if hw.receive() != Ok(None) || hw.management_complete() != Ok(None) {
        return TestResult::Fail("native BA TX-free replaced DMA terminal proof");
    }
    for slot in 0..8 {
        hw.owner
            .storage
            .as_ref()
            .unwrap()
            .data
            .set_word(slot, 1, (64 << 16) | LAST | DONE);
    }
    words[(TX_DATA + 12) as usize / 4] = 8;
    for token in 1..=8 {
        if hw.management_complete() != Ok(Some(packet_tx::Completion { token, status: 0 })) {
            return TestResult::Fail("originator aggregate lost per-MSDU retirement");
        }
    }
    hw.owner.published = false;
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_native_originator_txd_eligibility_keeps_per_msdu_tokens_and_no_amsdu
);

fn ethernet(value: u8) -> Vec<u8> {
    let mut frame = vec![value; 60];
    frame[..6].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[6..12].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame
}
fn free(records: &[(u16, u8)]) -> Vec<u8> {
    // mt76_connac_tx_free: byte count:u16,ctrl low10 MSDU count,txd:u32;
    // MT_TX_FREE_PAIR/WLAN_ID, then native token/status/retry-count entries.
    let len = 12 + records.len() * 4;
    let mut bytes = vec![0; len];
    bytes[..2].copy_from_slice(&(len as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(records.len() as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&0x8000_4000u32.to_le_bytes());
    for (n, (token, status)) in records.iter().enumerate() {
        bytes[12 + n * 4..16 + n * 4].copy_from_slice(
            &(u32::from(*token) << 16 | u32::from(*status) << 13 | 1).to_le_bytes(),
        );
    }
    bytes
}
fn native_order() -> Result<(), &'static str> {
    for firmware_first in [false, true] {
        let (mut words, mut hw) = rig().map_err(|_| "native pipeline allocation")?;
        hw.owner.published = true;
        for round in 0..4 {
            let first = round * packet_tx::PIPELINE;
            for offset in 0..packet_tx::PIPELINE {
                let frame = ethernet((first + offset) as u8);
                hw.submit_data_mode(&frame, true, true, true)
                    .map_err(|_| "native pipeline publish")?;
                let slot = (first + offset) % DEPTH;
                let ring = &hw.owner.storage.as_ref().unwrap().data;
                let bytes = ring.buffers[slot].as_slice();
                if bytes[packet_tx::HEADER..packet_tx::HEADER + frame.len()] != frame
                    || ring.word(slot, 1) != (64 << 16) | LAST
                    || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) & (1 << 28) == 0
                {
                    return Err(
                        "native slot/payload ownership or single-frame BA fallback changed",
                    );
                }
            }
            let cidx = words[(TX_DATA + 8) as usize / 4];
            if cidx != (first + packet_tx::PIPELINE) as u32 % DEPTH as u32
                || hw.submit_data_mode(&ethernet(99), true, true, true) != Err(Error::Busy)
                || words[(TX_DATA + 8) as usize / 4] != cidx
            {
                return Err("pipeline overflow advanced native producer");
            }
            let records: Vec<_> = (0..packet_tx::PIPELINE)
                .rev()
                .map(|i| ((first + i + 1) as u16, 0))
                .collect();
            if firmware_first {
                inject_rx(&mut words, &hw, 0, &free(&records));
                if hw.receive() != Ok(None) || hw.management_complete() != Ok(None) {
                    return Err("TX-free released payload before descriptor proof");
                }
            }
            for offset in 0..packet_tx::PIPELINE {
                hw.owner.storage.as_ref().unwrap().data.set_word(
                    (first + offset) % DEPTH,
                    1,
                    (64 << 16) | LAST | DONE,
                );
            }
            words[(TX_DATA + 12) as usize / 4] = cidx;
            if !firmware_first {
                if hw.management_complete() != Ok(None) {
                    return Err("DMA prefix released payload before native TX-free");
                }
                inject_rx(&mut words, &hw, 0, &free(&records));
                if hw.receive() != Ok(None) {
                    return Err("TX-free reached MCU waiter");
                }
            }
            for offset in 0..packet_tx::PIPELINE {
                if hw.management_complete()
                    != Ok(Some(packet_tx::Completion {
                        token: (first + offset + 1) as u16,
                        status: 0,
                    }))
                {
                    return Err("out-of-order firmware reports changed submitted FIFO retirement");
                }
            }
            if !hw.owner.storage.as_ref().unwrap().tokens.is_empty()
                || hw.owner.storage.as_ref().unwrap().data.pending
            {
                return Err("terminal pipeline retained reusable slots");
            }
        }
        hw.owner.published = false;
    }
    Ok(())
}
fn mt76_native_tx_pipeline_wrap_and_dual_proof_retirement() -> TestResult {
    native_order().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_native_tx_pipeline_wrap_and_dual_proof_retirement
);

fn prefix() -> Result<(), &'static str> {
    let (mut words, mut hw) = rig().map_err(|_| "native prefix allocation")?;
    hw.owner.published = true;
    for n in 0..packet_tx::PIPELINE {
        hw.submit_data_mode(&ethernet(n as u8), false, true, true)
            .map_err(|_| "prefix submit")?;
    }
    let records: Vec<_> = (1..=packet_tx::PIPELINE).map(|n| (n as u16, 0)).collect();
    inject_rx(&mut words, &hw, 1, &free(&records));
    hw.receive().map_err(|_| "prefix release event")?;
    for slot in 0..4 {
        hw.owner
            .storage
            .as_ref()
            .unwrap()
            .data
            .set_word(slot, 1, (64 << 16) | LAST | DONE);
    }
    words[(TX_DATA + 12) as usize / 4] = 4;
    for token in 1..=4 {
        if hw.management_complete() != Ok(Some(packet_tx::Completion { token, status: 0 })) {
            return Err("valid DMA prefix did not retire exact payloads");
        }
    }
    if hw.management_complete() != Ok(None) {
        return Err("DMA prefix freed an unconsumed tail");
    }
    // A later producer location is not proof for the four still-owned slots.
    words[(TX_DATA + 12) as usize / 4] = 9;
    if hw.management_complete() != Err(Error::Ring) {
        return Err("DIDX beyond submitted interval accepted");
    }
    words[(TX_DATA + 12) as usize / 4] = 8;
    if hw.management_complete() != Ok(None) {
        return Err("DIDX without DDONE freed native tail");
    }
    for slot in 4..8 {
        hw.owner
            .storage
            .as_ref()
            .unwrap()
            .data
            .set_word(slot, 1, (64 << 16) | LAST | DONE);
    }
    for token in 5..=8 {
        if hw.management_complete() != Ok(Some(packet_tx::Completion { token, status: 0 })) {
            return Err("tail did not retain its original token after stalled prefix");
        }
    }
    hw.owner.published = false;
    Ok(())
}
fn mt76_native_tx_pipeline_partial_dma_and_invalid_prefix_keep_tail_owned() -> TestResult {
    prefix().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_native_tx_pipeline_partial_dma_and_invalid_prefix_keep_tail_owned
);

fn atomic() -> Result<(), &'static str> {
    let mut tokens = packet_tx::Tokens::new();
    for slot in 0..packet_tx::PIPELINE {
        tokens
            .begin_at(slot as u16 + 1, slot)
            .map_err(|_| "token reserve")?;
        tokens.dma_done_at(slot).map_err(|_| "token DMA proof")?;
    }
    let bad = packet_tx::releases(&free(&[(1, 0), (8, 0), (8, 3)]))
        .map_err(|_| "source-format conflict fixture")?;
    if tokens.firmware_done(&bad) != Err(Error::MalformedEvent) || tokens.finish().is_some() {
        return Err("contradictory tail partially committed earlier native releases");
    }
    let foreign = packet_tx::releases(&free(&[(777, 0)])).map_err(|_| "foreign fixture")?;
    tokens
        .firmware_done(&foreign)
        .map_err(|_| "foreign release")?;
    if tokens.finish().is_some() {
        return Err("foreign token completed native payload");
    }
    let valid: Vec<_> = (1..=8)
        .map(|token| packet_tx::Completion {
            token,
            status: if token == 5 { 3 } else { 0 },
        })
        .collect();
    tokens
        .firmware_done(&valid)
        .map_err(|_| "genuine token statuses")?;
    for expected in valid {
        if tokens.finish() != Some(expected) {
            return Err("per-frame terminal status was replaced by aggregate success");
        }
    }
    Ok(())
}
fn mt76_native_tx_pipeline_release_packet_commits_atomically_per_token() -> TestResult {
    atomic().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_pipeline",
    mt76_native_tx_pipeline_release_packet_commits_atomically_per_token
);
