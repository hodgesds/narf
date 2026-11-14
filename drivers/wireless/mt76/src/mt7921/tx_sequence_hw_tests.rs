//! Native RX rings, TXD/PID, DMA and TX_FREE authority in every receipt order.
use super::*;
fn txs(pid: u8, tid: u8, sequence: u16) -> Vec<u8> {
    let words = [
        1u32 << 27 | 40,
        0,
        u32::from(tid) << 26 | 1 << 15,
        u32::from(sequence) << 20,
        1 << 16,
        u32::from(pid) << 24,
        0,
        0,
        0,
        0,
    ];
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}
fn terminal(words: &mut [u32], hw: &mut Hardware, slot: usize, token: u16) -> Result<(), Error> {
    hw.owner
        .storage
        .as_ref()
        .unwrap()
        .data
        .set_word(slot, 1, (64 << 16) | LAST | DONE);
    words[(TX_DATA + 12) as usize / 4] = ((slot + 1) % DEPTH) as u32;
    inject_rx(
        words,
        hw,
        0,
        &super::tx_pipeline_hw_tests::free(&[(token, 0)]),
    );
    if hw.management_complete()? != Some(packet_tx::Completion { token, status: 0 }) {
        return Err(Error::Ring);
    }
    Ok(())
}
fn native() -> Result<(), &'static str> {
    for tid in [0, 7] {
        for order in [
            [0, 1, 2],
            [1, 2, 0],
            [2, 0, 1],
            [0, 2, 1],
            [1, 0, 2],
            [2, 1, 0],
        ] {
            let (mut words, mut hw) = rig().map_err(|_| "native sequence rig")?;
            hw.owner.published = true;
            hw.hw_amsdu = true;
            hw.arm_transmit_sequence(tid)
                .map_err(|_| "native sample reserve")?;
            let frame = super::tx_pipeline_hw_tests::ethernet(0x63);
            hw.submit_data_txd(
                crate::mt7921::vif_slots::Link::HOME,
                &frame,
                true,
                true,
                true,
                false,
                tid,
            )
            .map_err(|_| "native true user MSDU sample")?;
            let bytes = hw.owner.storage.as_ref().unwrap().data.buffers[0].as_slice();
            if bytes[20..24] != [3, 4, 0, 0]
                || bytes[28..32] != [0, 0, 0x28, 0]
                || bytes[12..16] != (1u32 << 28 | 15 << 11 | 2).to_le_bytes()
                || bytes[64..124] != frame
                || hw.submit_data_txd(
                    crate::mt7921::vif_slots::Link::HOME,
                    &frame,
                    true,
                    true,
                    true,
                    false,
                    tid,
                ) != Err(Error::Busy)
            {
                return Err("native sample HOST/PID/AMSDU/BA/ciphertext owner");
            }
            for (turn, receipt) in order.into_iter().enumerate() {
                match receipt {
                    0 => inject_rx(&mut words, &hw, 0, &txs(3, tid, 4095)),
                    1 => inject_rx(
                        &mut words,
                        &hw,
                        1,
                        &super::tx_pipeline_hw_tests::free(&[(1, 0)]),
                    ),
                    _ => {
                        hw.owner.storage.as_ref().unwrap().data.set_word(
                            0,
                            1,
                            (64 << 16) | LAST | DONE,
                        );
                        words[(TX_DATA + 12) as usize / 4] = 1;
                    }
                }
                if !hw.owner.storage.as_ref().unwrap().tokens.is_empty() {
                    let _ = hw
                        .management_complete()
                        .map_err(|_| "native sample packet proof progress")?;
                }
                let sample = hw
                    .poll_transmit_sequence(tid)
                    .map_err(|_| "native sample report progress")?;
                if sample != if turn == 2 { Some(4095) } else { None } {
                    return Err("native TXS or DMA/TX_FREE alone manufactured a sample");
                }
            }
            hw.submit_data_txd(
                crate::mt7921::vif_slots::Link::HOME,
                &frame,
                true,
                true,
                true,
                false,
                tid,
            )
            .map_err(|_| "normal MSDU after sample")?;
            let bytes = hw.owner.storage.as_ref().unwrap().data.buffers[1].as_slice();
            if bytes[20..24] != [0; 4]
                || u32::from_le_bytes(bytes[28..32].try_into().unwrap()) & (1 << 10) == 0
            {
                return Err("single sample disabled ordinary native TX A-MSDU");
            }
            if hw.arm_transmit_sequence(tid) != Err(Error::Busy) {
                return Err("native sample armed before older firmware/MAC packet retired");
            }
            terminal(&mut words, &mut hw, 1, 2).map_err(|_| "normal native MSDU terminal")?;
            hw.arm_transmit_sequence(tid)
                .map_err(|_| "native repeated sample")?;
            hw.submit_data_txd(
                crate::mt7921::vif_slots::Link::HOME,
                &frame,
                true,
                true,
                true,
                false,
                tid,
            )
            .map_err(|_| "second native sample")?;
            let bytes = hw.owner.storage.as_ref().unwrap().data.buffers[2].as_slice();
            if bytes[20..24] != [4, 4, 0, 0] {
                return Err("native PID reused after old receipt");
            }
            inject_rx(&mut words, &hw, 2, &txs(3, tid, 123));
            if hw.poll_transmit_sequence(tid) != Ok(None) {
                return Err("late prior native TXS aliased a new sample");
            }
            terminal(&mut words, &mut hw, 2, 3).map_err(|_| "second sample native terminal")?;
            inject_rx(&mut words, &hw, 0, &txs(4, tid, 17));
            if hw.poll_transmit_sequence(tid) != Ok(Some(17)) {
                return Err("second native sample missed current PID");
            }
            hw.owner.published = false;
        }
    }
    Ok(())
}
fn mt76_native_sequence_sample_requires_txs_dma_and_free_preserving_normal_amsdu() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_native_sequence_sample_requires_txs_dma_and_free_preserving_normal_amsdu
);
fn fragments() -> Result<(), &'static str> {
    let (mut words, mut hw) = rig().map_err(|_| "fragment sample rig")?;
    hw.owner.published = true;
    hw.arm_transmit_sequence(5)
        .map_err(|_| "fragment sample reserve")?;
    let mut first = vec![0; 40];
    first[..2].copy_from_slice(&[0x88, 0x45]);
    first[4] = 2;
    first[24] = 5;
    hw.submit_fragment(crate::mt7921::vif_slots::Link::HOME, &first)
        .map_err(|_| "first actual user fragment")?;
    if hw.transmit_sequence_published(5)
        || hw.owner.storage.as_ref().unwrap().data.buffers[0].as_slice()[20..24] != [0; 4]
    {
        return Err("sample observed a partial fragmented MSDU");
    }
    terminal(&mut words, &mut hw, 0, 1).map_err(|_| "first fragment native retirement")?;
    let mut last = first;
    last[1] = 0x41;
    last[22] = 1;
    hw.submit_fragment(crate::mt7921::vif_slots::Link::HOME, &last)
        .map_err(|_| "final actual user fragment")?;
    if !hw.transmit_sequence_published(5)
        || hw.owner.storage.as_ref().unwrap().data.buffers[1].as_slice()[20..24] != [3, 4, 0, 0]
    {
        return Err("final native fragment did not carry retained PID sample");
    }
    terminal(&mut words, &mut hw, 1, 2).map_err(|_| "final fragment native retirement")?;
    inject_rx(&mut words, &hw, 0, &txs(3, 5, 0x73));
    if hw.poll_transmit_sequence(5) != Ok(Some(0x73)) {
        return Err("fragment sample lost native sequence");
    }
    hw.owner.published = false;
    Ok(())
}
fn mt76_native_restart_samples_only_final_real_fragment_after_predecessor_retirement() -> TestResult
{
    fragments().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/tx_ba",
    mt76_native_restart_samples_only_final_real_fragment_after_predecessor_retirement
);

/// `mt7921e_tx_prepare_skb` through the production TXD writer: the home
/// station's first data frame requests a HOST TX status on its own PID
/// (hardware A-MSDU off for that frame, mt76_connac_mac.c), the next frame
/// inside HZ/4 is ordinary, and the matching report becomes the station's
/// TX rate once the frame has retired.
fn rate_sample() -> Result<(), &'static str> {
    let (mut words, mut hw) = rig().map_err(|_| "rate sample rig")?;
    hw.owner.storage.as_mut().unwrap().tx_sequence = crate::mt7921::tx_sequence::Owner::new();
    hw.owner.published = true;
    hw.hw_amsdu = true;
    let frame = super::tx_pipeline_hw_tests::ethernet(0x52);
    for _ in 0..2 {
        hw.submit_data_txd(
            crate::mt7921::vif_slots::Link::HOME,
            &frame,
            true,
            true,
            true,
            false,
            0,
        )
        .map_err(|_| "home data frame")?;
    }
    let ring = &hw.owner.storage.as_ref().unwrap().data;
    let (first, second) = (ring.buffers[0].as_slice(), ring.buffers[1].as_slice());
    let word = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    if first[20..24] != [3, 4, 0, 0]
        || word(first, 28) & (1 << 10) != 0
        || word(first, 12) & (1 << 28) == 0
        || first[64..124] != frame
    {
        return Err("first home frame did not request a rate status");
    }
    if second[20..24] != [0; 4] || word(second, 28) & (1 << 10) == 0 {
        return Err("a frame inside HZ/4 was sampled again");
    }
    if Backend::tx_rate_report(&hw).is_some() {
        return Err("rate reported before any TX status");
    }
    terminal(&mut words, &mut hw, 0, 1).map_err(|_| "sampled frame retirement")?;
    // VHT (mode 4) MCS 7, two streams, 80 MHz.
    let mut report = txs(3, 0, 0);
    let rate = 7u32 | 4 << 6 | 1 << 10;
    let r0 = u32::from_le_bytes(report[8..12].try_into().unwrap()) | rate | 2 << 29;
    report[8..12].copy_from_slice(&r0.to_le_bytes());
    inject_rx(&mut words, &hw, 0, &report);
    for _ in 0..3 {
        hw.route_rx(None).map_err(|_| "TX status receipt")?;
    }
    let sampled = Backend::tx_rate_report(&hw).ok_or("TX status not taken as a rate")?;
    if sampled.wcid != 1 || u32::from(sampled.tx_rate) != rate || sampled.bw != 2 {
        return Err("rate report fields");
    }
    let decoded = crate::mt7921::link_stats::tx_rate(sampled.tx_rate, sampled.bw)
        .ok_or("rate word did not decode")?;
    if decoded.vht_mcs != Some((7, 2)) || decoded.width_mhz != 80 {
        return Err("decoded TX rate");
    }
    hw.owner.published = false;
    Ok(())
}
fn mt76_native_home_data_requests_periodic_rate_status() -> TestResult {
    rate_sample().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mt76_native_home_data_requests_periodic_rate_status
);
