//! Actual WFDMA descriptor and token retirement for software-encrypted AP TX.
use super::*;
fn mt76_ap_actual_peer_and_bmc_raw_descriptors_require_both_packet_receipts() -> TestResult {
    for dma_first in [false, true] {
        for wcid in [1u8, 13, 19] {
            let (mut words, mut hw) = match rig() {
                Ok(r) => r,
                Err(_) => return TestResult::Fail("AP native packet DMA"),
            };
            hw.owner.published = true;
            let mut frame = vec![0; 64];
            frame[0] = 8;
            frame[1] = 0x42;
            frame[4..10].copy_from_slice(&[if wcid == 19 { 0xff } else { 2 }, 0, 0, 0, 0, 1]);
            frame[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
            frame[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
            if Backend::submit_ap_frame(
                &mut hw,
                crate::mt7921::vif_slots::Vif::HOME,
                &frame,
                wcid,
                crate::mt7921::association::LegacyRate::ONE_MBPS,
            )
            .is_err()
            {
                return TestResult::Fail("AP native raw packet publish");
            }
            let ring = &hw.owner.storage.as_ref().unwrap().data;
            // SAFETY: fixture owns this coherent allocation; the model has
            // no concurrent DMA engine, and its allocation exceeds128 bytes.
            let bytes =
                unsafe { core::slice::from_raw_parts(ring.buffers[0].cpu_mut_ptr::<u8>(), 128) };
            let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let payload = ring.buffers[0].dma_addr().raw() + 64;
            if words[(TX_DATA + 8) as usize / 4] != 1
                || word(4) != 0x80026000 | u32::from(wcid)
                || word(12) & ((1 << 1) | (1 << 31)) != 0
                || bytes[64..128] != frame
                || word(40) != payload as u32
                || u16::from_le_bytes(bytes[44..46].try_into().unwrap()) != 0x8040
            {
                return TestResult::Fail("AP native frame WCID/payload/protection or manual SN");
            }
            if Backend::submit_ap_frame(
                &mut hw,
                crate::mt7921::vif_slots::Vif::HOME,
                &frame,
                wcid,
                crate::mt7921::association::LegacyRate::ONE_MBPS,
            ) != Err(Error::Busy)
            {
                return TestResult::Fail("AP reused a still-owned DMA/token payload");
            }
            if dma_first {
                hw.owner
                    .storage
                    .as_ref()
                    .unwrap()
                    .data
                    .set_word(0, 1, (64 << 16) | LAST | DONE);
                words[(TX_DATA + 12) as usize / 4] = 1;
                if hw.management_complete() != Ok(None) {
                    return TestResult::Fail("AP DMA-only completion retired firmware token");
                }
            }
            inject_rx(&mut words, &hw, 0, &release_event(1, 0, true));
            if hw.receive() != Ok(None) {
                return TestResult::Fail("AP TX_FREE leaked into command/data delivery");
            }
            if !dma_first {
                if hw.management_complete() != Ok(None) {
                    return TestResult::Fail("AP TX_FREE retired a DMA-owned payload");
                }
                hw.owner
                    .storage
                    .as_ref()
                    .unwrap()
                    .data
                    .set_word(0, 1, (64 << 16) | LAST | DONE);
                words[(TX_DATA + 12) as usize / 4] = 1;
            }
            if hw.management_complete()
                != Ok(Some(packet_tx::Completion {
                    token: 1,
                    status: 0,
                }))
            {
                return TestResult::Fail("AP native dual packet retirement");
            }
            hw.owner.published = false;
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_actual_peer_and_bmc_raw_descriptors_require_both_packet_receipts
);
