// SPDX-License-Identifier: GPL-2.0-or-later
//! Model-only signed source inputs. Power outcomes come from actual native
//! register/descriptor/IRQ/Radio/Device paths in the interface fixtures.
use super::*;
use crate::ath9k::packet::tests::Model;
pub(in crate::ath9k) fn record(base: &ht::Grant) -> Vec<u8> {
    let r = request(base);
    let mut bytes = alloc::vec![0;128];
    bytes[..8].copy_from_slice(&[b'N', b'8', b'5', b'S', 1, 0, 128, 0]);
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    bytes[16..48].copy_from_slice(&r.identity);
    bytes[48..54].copy_from_slice(&r.mac);
    bytes[54..58].copy_from_slice(&base.geometry().body());
    bytes[58..60].copy_from_slice(&base.ba_limit().0.to_le_bytes());
    bytes[60..62].copy_from_slice(&12i16.to_le_bytes());
    bytes[62..64].copy_from_slice(&40i16.to_le_bytes());
    bytes[64..80].copy_from_slice(&[
        1,
        0,
        0,
        4,
        255,
        8,
        0xd0,
        7,
        0,
        4,
        base.version(),
        1,
        0,
        0,
        0,
        0,
    ]);
    bytes[80..112].copy_from_slice(&base.ba_identity().1);
    bytes
}
pub(in crate::ath9k) fn qualify(model: &Arc<Model>) -> Cap<FirmwareBlob, Read> {
    let base = model.ht.borrow().clone().unwrap();
    let cap = Cap::bootstrap();
    let source = Source::Verified {
        bytes: record(&base),
        signer: Some([0x85; 32]),
        cap,
    }
    .load(base)
    .unwrap();
    *model.ps.borrow_mut() = Some(source);
    model.registers.borrow_mut().insert(0x7044, 2);
    model.registers.borrow_mut().insert(0x704c, 3);
    model.registers.borrow_mut().insert(0x806c, 0);
    cap
}
