//! Literal CONNAC2 RXD3 CH_FREQ/ADDR_TYPE separation, from connac2_mac.h.
//! Address-type observations are preserved; they never become channel bits
//! or a software-created decryption/native-interface authority.
use super::*;

fn scan_fields() -> Result<(), &'static str> {
    use crate::mt7921::channel::{self, Band};
    for (tag, band, channel) in [
        (6, Band::Ghz2, 6),
        (36, Band::Ghz5, 36),
        (181, Band::Ghz6, 1),
        (239, Band::Ghz6, 233),
    ] {
        for address in 0..4u32 {
            let mut packet = scan_beacon(channel, b"native-rxd");
            if band == Band::Ghz6 {
                // Six-GHz channel geometry belongs to HE Operation, not a
                // fictitious ninth CH_FREQ bit or legacy DS Parameter IE.
                packet.truncate(packet.len() - 3);
                let length = packet.len() as u32;
                packet[..4].copy_from_slice(&((2 << 27) | length).to_le_bytes());
            }
            packet[12..16].copy_from_slice(&((u32::from(tag) << 8) | address << 16).to_le_bytes());
            let frame = &mut packet[32..];
            frame[4..10].copy_from_slice(&if address == 1 {
                [2, 0x11, 0x22, 0x33, 0x44, 0x55]
            } else {
                [0xff; 6]
            });
            if address == 1 {
                frame[0] = 0x50;
            } // Actual directed probe response/U2M.
            let original = packet.clone();
            let native =
                scan::rx_native(&packet).ok_or("valid native address type/channel rejected")?;
            let bss = scan::beacon(&packet, 2).ok_or("actual U2M probe/native beacon rejected")?;
            if native.channel != tag
                || bss.channel != channel
                || bss.band
                    != (band == Band::Ghz6)
                        .then_some(narf_wireless::association::channel::Band::Ghz6)
                || native.frame != &packet[32..]
                || packet != original
                || channel::from_rx_channel(native.channel) != Some((band, channel))
            {
                return Err(
                    "native address type changed channel/band/frame or original RXD fields",
                );
            }
            packet[7] |= 1 << 4; // Actual FCS_ERR bit28 remains a refusal.
            if scan::rx_native(&packet).is_some() || scan::beacon(&packet, 2).is_some() {
                return Err("U2M channel fix admitted malformed native FCS metadata");
            }
        }
    }
    let mut invalid = scan_beacon(6, b"invalid-channel");
    for tag in [0u32, 240, 255] {
        invalid[12..16].copy_from_slice(&((tag << 8) | 1 << 16).to_le_bytes());
        if scan::rx_native(&invalid).is_some() {
            return Err("invalid native channel tag became a U2M alias");
        }
    }
    Ok(())
}
fn mt76_connac2_native_channel_and_probe_observation_exclude_original_address_type_bits(
) -> TestResult {
    scan_fields().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_descriptor",
    mt76_connac2_native_channel_and_probe_observation_exclude_original_address_type_bits
);

fn raw_ap_fields() -> Result<(), &'static str> {
    use crate::mt7921::channel::Band;
    let mut frame = vec![0; 48];
    frame[0] = 8;
    frame[1] = 0x41; // Native encrypted ToDS bytes, not authenticated plaintext.
    frame[4..10].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[10..16].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    let mut packet = descriptor(&frame);
    packet[4..8].copy_from_slice(&3u32.to_le_bytes());
    for (tag, band, channel) in [
        (6u32, Band::Ghz2, 6),
        (36, Band::Ghz5, 36),
        (181, Band::Ghz6, 1),
    ] {
        for address in 0..4u32 {
            packet[12..16].copy_from_slice(&((tag << 8) | address << 16).to_le_bytes());
            let original = packet.clone();
            let raw = super::super::ap_rx::decode(&packet, 2)
                .ok_or("valid raw AP native U2M metadata")?;
            if raw.channel != channel
                || raw.band != band
                || raw.wcid != 3
                || raw.frame != frame
                || packet != original
            {
                return Err(
                    "AP raw channel parse changed native ownership/address-type or cipher bytes",
                );
            }
            packet[4..8].copy_from_slice(&(3 | 4u32 << 16).to_le_bytes());
            if super::super::ap_rx::decode(&packet, 2).is_some() {
                return Err(
                    "U2M correction synthesized raw validity for hardware-decrypted plaintext",
                );
            }
            packet[4..8].copy_from_slice(&3u32.to_le_bytes());
        }
    }
    Ok(())
}
fn mt76_connac2_unkeyed_ap_rx_keeps_channel_separate_and_refuses_hardware_plaintext() -> TestResult
{
    raw_ap_fields().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_descriptor",
    mt76_connac2_unkeyed_ap_rx_keeps_channel_separate_and_refuses_hardware_plaintext
);
