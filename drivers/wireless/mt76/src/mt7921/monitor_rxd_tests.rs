//! Source RXD3 field separation through the production passive raw decoder.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
fn mt76_connac2_monitor_raw_unicast_address_type_never_changes_radiotap_frequency() -> TestResult {
    let mut frame = vec![0; 40];
    frame[0] = 8;
    frame[1] = 0x42;
    frame[4..10].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame[10..16].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    let mut packet = vec![0; 24];
    packet[..4].copy_from_slice(&((2u32 << 27) | (24 + frame.len()) as u32).to_le_bytes());
    packet.extend_from_slice(&frame);
    for (tag, frequency) in [(6u32, 2437), (36, 5180), (181, 5955), (239, 7115)] {
        for address in 0..4u32 {
            packet[12..16].copy_from_slice(&((tag << 8) | address << 16).to_le_bytes());
            let original = packet.clone();
            let Some((metadata, raw)) = decode(&packet, 2) else {
                return TestResult::Fail("valid native raw U2M/address type rejected by monitor");
            };
            if metadata.frequency_mhz != frequency || raw != frame || packet != original {
                return TestResult::Fail(
                    "native address type contaminated monitor channel or altered raw frame",
                );
            }
            packet[4..8].copy_from_slice(&(4u32 << 16).to_le_bytes());
            if decode(&packet, 2).is_some() {
                return TestResult::Fail(
                    "address-type fix turned hardware plaintext into passive capture",
                );
            }
            packet[4..8].fill(0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_descriptor",
    mt76_connac2_monitor_raw_unicast_address_type_never_changes_radiotap_frequency
);
