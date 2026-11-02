//! Independent P2P GO management facts around the real FakeAp RSNA owner.
//! Only unprotected beacon/association metadata is appended; authenticated
//! key/data frames retain their original real MIC/AES/PN conversation.
use alloc::{vec, vec::Vec};
pub(super) const LOCAL_DEVICE: [u8; 6] = [2, 0x43, 1, 2, 3, 4];
pub(super) const PEER_DEVICE: [u8; 6] = [2, 0x44, 5, 6, 7, 8];
fn vendor(frame: &mut Vec<u8>, attrs: &[u8]) {
    frame.extend_from_slice(&[221, (4 + attrs.len()) as u8, 0x50, 0x6f, 0x9a, 9]);
    frame.extend_from_slice(attrs);
}
pub(super) fn request() -> Vec<u8> {
    let mut attrs = vec![2, 2, 0, 0x25, 0, 13, 17, 0];
    attrs.extend_from_slice(&LOCAL_DEVICE);
    attrs.extend_from_slice(&[0, 0, 0, 1, 0, 0x50, 0xf2, 4, 0, 1, 0]);
    let mut out = Vec::new();
    vendor(&mut out, &attrs);
    out
}
pub(super) fn beacon(mut frame: Vec<u8>, index: u8, ctwindow: Option<u8>) -> Vec<u8> {
    let mut attrs = vec![2, 2, 0, 0x25, 1, 3, 6, 0];
    attrs.extend_from_slice(&PEER_DEVICE);
    if let Some(window) = ctwindow {
        attrs.extend_from_slice(&[12, 2, 0, index, window]);
    }
    vendor(&mut frame, &attrs);
    frame
}
pub(super) fn response(frame: &mut Vec<u8>) {
    if frame.len() >= 30 && matches!(frame[0], 0x10 | 0x30) && frame[1] & 0xc7 == 0 {
        vendor(frame, &[0, 1, 0, 0]); // Actual P2P Status: success.
    }
}
pub(super) fn check_request(frame: &[u8]) -> Result<(), &'static str> {
    if frame.first() == Some(&0) {
        let ies = frame.get(28..).ok_or("P2P client request body")?;
        let attrs = super::p2p_go::attributes(ies)?;
        let info = super::p2p_go::unique(&attrs, 13)?
            .ok_or("P2P client request lost actual DeviceInfo")?;
        if info.get(..6) != Some(&LOCAL_DEVICE) {
            return Err("P2P client association changed protocol Device Address");
        }
    }
    Ok(())
}

pub(super) fn mac(stage: u8, body: &[u8]) -> Result<u8, &'static str> {
    if body.len() != 52 || body[..4] != [0; 4] {
        return Err("P2P client native MAC0 extent/identity");
    }
    let action = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let kind = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let window = u32::from_le_bytes(body[48..52].try_into().unwrap());
    match (stage, action, kind) {
        (0 | 4, 1, 5) => Ok(stage),
        (0 | 4, 3, 5) => Ok(1),
        (1, 1, 7) if window == 32 => Ok(2),
        (2, 2, 7) if window <= 127 => Ok(2),
        (2, 3, 7) => Ok(3),
        (3, 1, 5) => Ok(4),
        _ => Err("P2P client firmware type/ADD-MODIFY-REMOVE/CTWindow order invalid"),
    }
}
