// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent Linux-listed raw field layout; actual identity/PHY/calibration
//! source paths consume every image. No production RF measurements supplied.
use super::*;
use crate::ath9k::{
    channel_width::{Geometry, Width},
    identity::{eeprom_dword, eeprom_word},
};
#[derive(Clone, Copy)]
pub(in crate::ath9k) struct Selection {
    pub minor: u16,
    pub big: bool,
    pub swapped: bool,
    pub high: bool,
    pub xe2: bool,
}
pub(in crate::ath9k) fn checksum(bytes: &mut [u8; EEPROM_4K_BYTES]) {
    bytes[2..4].fill(0);
    let sum = bytes
        .chunks_exact(2)
        .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]));
    bytes[2..4].copy_from_slice(&(sum ^ 0xffff).to_le_bytes());
}
pub(in crate::ath9k) fn image(selection: Selection) -> [u8; EEPROM_4K_BYTES] {
    let mut image = wide_image();
    image[4..6].copy_from_slice(&(0xe000 | selection.minor).to_le_bytes());
    image[31] = u8::from(selection.high);
    image[52..56].copy_from_slice(&0x01234567u32.to_le_bytes());
    image[56..60].copy_from_slice(&0x89abcdefu32.to_le_bytes());
    image[61] = 11;
    image[76] = 3;
    image[80] = 21;
    image[81] = 17;
    image[82] = 5;
    image[85] = 27;
    for (index, value) in [1125u16, 1375, 1625, 0x8000, 0x8000]
        .into_iter()
        .enumerate()
    {
        image[100 + index * 4..102 + index * 4].copy_from_slice(&value.to_le_bytes());
    }
    image[7] = u8::from(selection.big);
    if selection.big {
        // eeprom_4k.c swaps these exact scalar fields after raw checksum:
        // base length/checksum/version/domain/rfsilent/BT/devicecap,
        // modal antCtrlChain/Common and five spurChan values. U8 tables,
        // MAC bytes and target/PDADC/CTL bytes are never word-swapped here.
        for offset in [0, 2, 4, 8, 10, 20, 22, 24, 100, 104, 108, 112, 116] {
            image[offset..offset + 2].reverse();
        }
        for offset in [52, 56] {
            image[offset..offset + 4].reverse();
        }
    }
    checksum(&mut image);
    image
}
fn smoke_ar9285_factory_field_orders_minor_boundaries_all_gain_tables_and_actual_calibration(
) -> TestResult {
    for minor in 1..=3 {
        for high in [false, true] {
            for xe2 in [false, true] {
                let selected = Selection {
                    minor,
                    high,
                    xe2,
                    big: false,
                    swapped: false,
                };
                let little = image(selected);
                let big = image(Selection {
                    big: true,
                    ..selected
                });
                let original_little = little;
                let original_big = big;
                for frequency in [2412, 2437, 2472] {
                    let le = channel_receipt_factory(frequency, 40, little, false, xe2).unwrap();
                    for swapped in [false, true] {
                        let be = channel_receipt_factory(frequency, 40, big, swapped, xe2).unwrap();
                        if be.image != original_big
                            || le.image != original_little
                            || !be.identity.big_endian_fields
                            || be.identity.eeprom_version != (0xe000 | minor)
                            || be.identity.regulatory_domains != le.identity.regulatory_domains
                            || be.prepared != le.prepared
                            || be.report != le.report
                            || be.registers != le.registers
                            || be.prepared.high_power_gain != high
                            || be.prepared.xe2_gain != xe2
                            || eeprom_dword(&be.image, 52) != 0x01234567
                            || eeprom_dword(&be.image, 56) != 0x89abcdef
                            || eeprom_word(&be.image, 8) != 0x64
                        {
                            return TestResult::Fail("actual raw BE reset/PHY/calibration differs from semantic LE source profile");
                        }
                        if be.registers[&0xa26c] & 15 != if minor < 2 { 6 } else { 3 } {
                            return TestResult::Fail(
                                "BE detector used wrong EEPROM minor boundary",
                            );
                        }
                    }
                }
                for width in [Width::FortyAbove, Width::FortyBelow] {
                    let geometry = Geometry::new(6, width).unwrap();
                    let le = wide_receipt_factory(geometry, 40, little, None, false, xe2).unwrap();
                    let be = wide_receipt_factory(geometry, 40, big, None, true, xe2).unwrap();
                    if be.image != original_big
                        || be.prepared != le.prepared
                        || be.report != le.report
                        || be.registers != le.registers
                        || be.report.powers.increment != if minor < 2 { 2 } else { 5 }
                        || (be.registers[&0x9844] >> 7) & 127 != if minor < 3 { 11 } else { 27 }
                    {
                        return TestResult::Fail(
                            "actual BE40 modal/center/CTL/increment/NF/ADC/IQ differs from LE",
                        );
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/factory",
    smoke_ar9285_factory_field_orders_minor_boundaries_all_gain_tables_and_actual_calibration
);
fn smoke_ar9285_factory_bad_checksum_endian_version_and_foreign_domain_fail_before_native(
) -> TestResult {
    let selected = Selection {
        minor: 3,
        big: true,
        swapped: false,
        high: false,
        xe2: false,
    };
    let image = image(selected);
    for kind in 0..4 {
        let mut bad = image;
        let expected = match kind {
            0 => {
                bad[60] ^= 1;
                BringUpError::BadChecksum
            }
            1 => {
                bad[7] = 0;
                checksum(&mut bad);
                BringUpError::BadLength
            }
            2 => {
                bad[4..6].copy_from_slice(&0xd001u16.to_be_bytes());
                checksum(&mut bad);
                BringUpError::BadVersion
            }
            _ => {
                bad[8..10].copy_from_slice(&0x7777u16.to_be_bytes());
                checksum(&mut bad);
                BringUpError::BadCalibration
            }
        };
        if channel_receipt_factory(2437, 40, bad, false, false).err() != Some(expected) {
            return TestResult::Fail(
                "foreign raw BE checksum/version/domain admitted to calibration/native path",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/factory",
    smoke_ar9285_factory_bad_checksum_endian_version_and_foreign_domain_fail_before_native
);
