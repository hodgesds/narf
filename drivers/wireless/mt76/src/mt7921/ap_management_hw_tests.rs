//! Real descriptor/PID/WCID and native TXS/DMA/TX_FREE join for AP management.
use super::*;
fn report(wcid: u8, acked: bool) -> Vec<u8> {
    [
        1u32 << 27 | 40,
        0,
        if acked { 0 } else { 1 << 16 },
        0,
        u32::from(wcid) << 16,
        3u32 << 24,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}
fn native() -> Result<(), &'static str> {
    for wcid in [1u8, 13, 19] {
        for acked in [false, true] {
            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                let (mut words, mut hw) = rig().map_err(|_| "native AP management DMA fixture")?;
                hw.owner.published = true;
                let mut frame = vec![0; 30];
                frame[0] = 0xb0;
                frame[4] = 2;
                frame[10] = 2;
                frame[16] = 2;
                frame[26] = 2;
                hw.arm_ap_management(crate::mt7921::vif_slots::Vif::HOME, wcid)
                    .map_err(|_| "native AP management report reservation")?;
                Backend::submit_ap_management(
                    &mut hw,
                    crate::mt7921::vif_slots::Vif::HOME,
                    &frame,
                    wcid,
                    crate::mt7921::association::LegacyRate::ONE_MBPS,
                )
                .map_err(|_| "native AP management publication")?;
                let bytes = hw.owner.storage.as_ref().unwrap().data.buffers[0].as_slice();
                if bytes[4..8] != (0x80026000u32 | u32::from(wcid)).to_le_bytes()
                    || bytes[20..24] != [3, 4, 0, 0]
                    || bytes[64..94] != frame
                {
                    return Err("AP native management omitted actual PID/WCID/frame");
                }
                for (turn, receipt) in order.into_iter().enumerate() {
                    match receipt {
                        0 => inject_rx(&mut words, &hw, 0, &report(wcid, acked)),
                        1 => inject_rx(&mut words, &hw, 1, &release_event(1, 0, true)),
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
                            .map_err(|_| "AP native management packet receipt")?;
                    }
                    let ack = hw
                        .poll_ap_management_ack()
                        .map_err(|_| "AP native management status receipt")?;
                    if ack != if turn == 2 { Some(acked) } else { None } {
                        return Err("AP ACK invented before native TXS plus both packet receipts");
                    }
                }
                hw.owner.published = false;
            }
        }
    }
    let (mut words, mut hw) = rig().map_err(|_| "native wrong-WCID ACK fixture")?;
    hw.owner.published = true;
    hw.arm_ap_management(crate::mt7921::vif_slots::Vif::HOME, 13)
        .map_err(|_| "foreign ACK reservation")?;
    let mut frame = vec![0; 30];
    frame[0] = 0xb0;
    frame[4] = 2;
    frame[10] = 2;
    frame[16] = 2;
    Backend::submit_ap_management(
        &mut hw,
        crate::mt7921::vif_slots::Vif::HOME,
        &frame,
        13,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .map_err(|_| "foreign ACK native frame")?;
    inject_rx(&mut words, &hw, 0, &report(1, true));
    if hw.poll_ap_management_ack() != Err(Error::MalformedEvent) {
        return Err("foreign native WCID supplied AP management ACK");
    }
    hw.owner.published = false; // no DMA engine exists in this owned-memory fixture.
    Ok(())
}
fn mt76_ap_actual_management_ack_requires_matching_txs_and_both_packet_receipts() -> TestResult {
    native().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_actual_management_ack_requires_matching_txs_and_both_packet_receipts
);
