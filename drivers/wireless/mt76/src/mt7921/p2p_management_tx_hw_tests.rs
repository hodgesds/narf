//! Actual coherent descriptors and independent TXS/DMA/TX_FREE receipts.
use super::*;
fn report(wcid: u8, tid: u8, pid: u8, ack: bool) -> Vec<u8> {
    [
        1u32 << 27 | 40,
        0,
        u32::from(tid) << 26 | if ack { 0 } else { 1 << 16 },
        0,
        u32::from(wcid) << 16,
        u32::from(pid) << 24,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}
fn frame(add_ba: bool) -> Vec<u8> {
    let mut bytes = vec![0; if add_ba { 33 } else { 30 }];
    bytes[0] = if add_ba { 0xd0 } else { 0xb0 };
    bytes[4..10].copy_from_slice(&[2, 0, 0, 0, 0x79, 1]);
    bytes[10..16].copy_from_slice(&[2, 0, 0, 0, 0x79, 2]);
    bytes[16..22].fill(0xff);
    if add_ba {
        bytes[24..26].copy_from_slice(&[3, 0]);
        bytes[27..29].copy_from_slice(&(7u16 << 2).to_le_bytes());
    }
    bytes
}
fn joined() -> Result<(), &'static str> {
    let vif = crate::mt7921::vif_slots::Vif::new(1).map_err(|_| "actual independent VIF")?;
    for add_ba in [false, true] {
        let tid = if add_ba { 7 } else { 0 };
        for ack in [false, true] {
            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                let (mut words, mut hw) = rig().map_err(|_| "native device TX fixture")?;
                hw.owner.published = true;
                let frame = frame(add_ba);
                Backend::arm_p2p_management(&mut hw, vif, tid)
                    .map_err(|_| "native device PID arm")?;
                Backend::submit_p2p_management(
                    &mut hw,
                    &frame,
                    vif,
                    crate::mt7921::association::LegacyRate::ONE_MBPS,
                )
                .map_err(|_| "native independent management publication")?;
                let bytes = hw.owner.storage.as_ref().unwrap().data.buffers[0].as_slice();
                if bytes[..4] != (0x20000020u32 + frame.len() as u32).to_le_bytes()
                    || bytes[4..8] != (0x81026012u32 | u32::from(tid) << 20).to_le_bytes()
                    || bytes[12..16] != 0x10007800u32.to_le_bytes()
                    || bytes[20..24] != (0x403u32 | if add_ba { 1 << 14 } else { 0 }).to_le_bytes()
                    || bytes[24..28] != 4u32.to_le_bytes()
                    || bytes[64..64 + frame.len()] != frame
                {
                    return Err(
                        "device TXD lost actual OMAC1/BMC18/PID/TID or selected a key/manual SN",
                    );
                }
                for (turn, receipt) in order.into_iter().enumerate() {
                    match receipt {
                        0 => inject_rx(&mut words, &hw, 0, &report(18, tid, 3, ack)),
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
                            .map_err(|_| "native device packet retirement")?;
                    }
                    let observed = Backend::poll_p2p_management_ack(&mut hw)
                        .map_err(|_| "native device TXS join")?;
                    if observed != if turn == 2 { Some(ack) } else { None } {
                        return Err(
                            "device ACK invented before matching TXS and both packet receipts",
                        );
                    }
                }
                hw.owner.published = false;
            }
        }
    }
    let (mut words, mut hw) = rig().map_err(|_| "foreign device TXS fixture")?;
    hw.owner.published = true;
    Backend::arm_p2p_management(&mut hw, vif, 0).map_err(|_| "foreign TXS actual PID")?;
    Backend::submit_p2p_management(
        &mut hw,
        &frame(false),
        vif,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .map_err(|_| "foreign TXS actual frame")?;
    inject_rx(&mut words, &hw, 0, &report(19, 0, 3, true));
    if Backend::poll_p2p_management_ack(&mut hw) != Err(Error::MalformedEvent) {
        return Err("home/AP BMC19 supplied independent device BMC18 ACK");
    }
    hw.owner.published = false;
    Ok(())
}
fn mt76_p2p_management_native_omac_bmc_txs_and_packet_receipts_are_independent() -> TestResult {
    joined().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_management_native_omac_bmc_txs_and_packet_receipts_are_independent
);
