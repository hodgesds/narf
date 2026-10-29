//! HT Operation protection modes 1-3 (firmware-owned on CONNAC2).
use super::vht_tests::{elements, join, prepared};
use super::*;

const OWN: [u8; 6] = super::amsdu_rx_tests::OWN;
const AP: [u8; 6] = super::amsdu_rx_tests::AP;

/// Set HT Operation subset 2 (operation byte 2) in a complete IE list.
fn set_operation_byte2(ies: &mut [u8], value: u8) -> bool {
    let mut offset = 0;
    let mut found = false;
    while offset + 2 <= ies.len() {
        let length = usize::from(ies[offset + 1]);
        if ies[offset] == 61 && length == 22 {
            ies[offset + 4] = value;
            found = true;
        }
        offset += 2 + length;
    }
    found
}

fn beacon(operation_byte2: u8, operation_byte1: Option<u8>) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[0] = 0x80;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(&super::wmm_tests::PARAMETERS);
    let (mut ht, vht) = elements(2, 36);
    ht[32] = operation_byte2;
    if let Some(byte1) = operation_byte1 {
        ht[31] = byte1;
    }
    frame.extend_from_slice(&ht);
    frame.extend_from_slice(&vht);
    let mut packet = descriptor(&frame);
    packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    packet
}

fn protection() -> Result<(), &'static str> {
    // Mixed (3), non-member (1) and 20-MHz (2) protection, with the
    // non-greenfield and OBSS non-HT presence bits the AP sets alongside.
    for mode in [1u8, 2, 3] {
        let byte2 = mode | 0b1_0100;
        let (mut s, mut b, p) = prepared(2, false);
        if !set_operation_byte2(&mut b.information_elements, byte2) {
            return Err("fixture HT Operation missing");
        }
        let (mut ht, _) = elements(2, 36);
        ht[32] = byte2;
        s.backend.ht_reply = Some(ht);
        if join(&mut s, &b, p, false) != Ok(42) || s.vht_profile.is_none() {
            return Err("HT protection mode refused a VHT80 association");
        }
        // The AP's protection state changes as legacy/non-GF stations come
        // and go; that is not a PHY change and keeps both packet owners.
        for changed in [0, 1, 2, 3, 0b1_0111, 0b0_0100] {
            s.backend.packets.push_back(beacon(changed, None));
            if s.receive_ethernet() != Ok(None) || s.peer_lost {
                return Err("dynamic HT protection change ended the link");
            }
        }
        // A real HT Operation change (secondary/width) still ends it.
        s.backend.packets.push_back(beacon(byte2, Some(0)));
        if s.receive_ethernet() != Err(Error::DeviceGone) {
            return Err("HT width change survived the protection mask");
        }
    }
    Ok(())
}
fn mt76_ht_protection_modes_associate_and_track_dynamic_operation() -> TestResult {
    protection().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_ht_protection_modes_associate_and_track_dynamic_operation
);

fn mt76_ht_static_operation_masks_only_dynamic_subset2_bits() -> TestResult {
    let mut operation = [0u8; 22];
    operation[0] = 36;
    operation[1] = 5;
    operation[2] = 0xff;
    operation[3] = 0xff;
    operation[6] = 0xff;
    let masked = crate::mt7921::ht20::static_operation(operation);
    // Only HT Protection, Nongreenfield Present and OBSS Non-HT Present
    // are cleared; reserved b3, CCFS2 b5-7 and every other byte remain.
    if masked[2] != 0b1110_1000 || masked[..2] != operation[..2] || masked[3..] != operation[3..] {
        return TestResult::Fail("HT Operation dynamic mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht",
    mt76_ht_static_operation_masks_only_dynamic_subset2_bits
);
