// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic offline inputs for isolated native Device fixtures. These are
//! neither physical measurements nor assets admitted by the production loader.
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
pub(in crate::ath9k) fn record(base: &Arc<super::super::ht::Grant>) -> Vec<u8> {
    let request = request(base);
    let mut bytes = vec![0; 160];
    bytes[..8].copy_from_slice(&[b'N', b'8', b'5', b'P', 1, 0, 160, 0]);
    bytes[8..12].copy_from_slice(&160u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54..58].copy_from_slice(&base.geometry().body());
    bytes[58..60].copy_from_slice(&base.ba_limit().0.to_le_bytes());
    bytes[60..62].copy_from_slice(&18i16.to_le_bytes());
    bytes[62..64].copy_from_slice(&base.ba_limit().1.to_le_bytes());
    for (at, value) in [
        (64, 1000u32),
        (68, 30000),
        (72, 1200000),
        (76, 1000),
        (80, 30000000),
        (84, 222000),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[88..92].copy_from_slice(&[base.version(), 1, 0, 0]);
    bytes[92..124].copy_from_slice(&base.ba_identity().1);
    bytes[124..128].copy_from_slice(&[10, 1, 64, 128]);
    bytes
}
pub(in crate::ath9k) fn qualify(
    model: &Arc<crate::ath9k::packet::tests::Model>,
) -> Cap<FirmwareBlob, Read> {
    qualify_peak(model, 18)
}
pub(in crate::ath9k) fn qualify_peak(
    model: &Arc<crate::ath9k::packet::tests::Model>,
    peak: i16,
) -> Cap<FirmwareBlob, Read> {
    let base = { model.ht.borrow().clone().unwrap() };
    let cap = Cap::bootstrap();
    let mut bytes = record(&base);
    bytes[60..62].copy_from_slice(&peak.to_le_bytes());
    let source = Source::Verified {
        bytes,
        signer: Some([0x85; 32]),
        cap,
    }
    .load(base.clone())
    .unwrap();
    // Preserve actual full reset/calibration values from the wide fixtures.
    // The older minimal20 fixture needs the exact original H seed registers;
    // subsequent periodic coefficients are produced only by real algorithms.
    let report = base.initial_calibration();
    let wide = { model.wide.borrow().is_some() };
    let column = if wide { 3 } else { 4 };
    let mut registers = model.registers.borrow_mut();
    for row in crate::ath9k::initvals::AR9285_MODES_9285_1_2 {
        if [0x9868, 0x986c, 0x99c0, 0x9858, 0x9840, 0x9924, 0x99bc].contains(&row[0]) {
            registers.entry(u64::from(row[0])).or_insert(row[column]);
        }
    }
    registers.entry(0x7044).or_insert(2);
    registers
        .entry(0x9874)
        .or_insert(0x3000_0000 | (u32::from(base.geometry().center()) * 0x10000 / 15));
    registers.entry(0x981c).or_insert(1);
    registers.entry(0x9860).or_insert(0x8000);
    registers
        .entry(0x9920)
        .or_insert(0x800 | (u32::from(report.iq_i) << 5) | (report.iq_q as u32 & 31));
    if let Some(offset) = report.pa_offset {
        registers
            .entry(0x7834)
            .or_insert(1 | (u32::from(offset >> 1) << 20));
        registers
            .entry(0x7828)
            .or_insert(u32::from(offset & 1) << 25);
    }
    for register in [0x9864, 0x99bc] {
        let value = registers.get(&register).copied().unwrap_or(0);
        registers.insert(register, (value & !511) | ((-50i32 as u32) << 1 & 511));
    }
    for (register, value) in [
        (0x9c10, 20000),
        (0x9c14, 16000),
        (0x9c18, 5000),
        (0x9c1c, 12000),
    ] {
        registers.insert(register, value);
    }
    drop(registers);
    model.periodic.borrow_mut().source = Some(source);
    cap
}
