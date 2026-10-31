//! Raw unkeyed management subscription/descriptor admission for the actual device.
/// cfg80211's default DEVICE RX subscriptions (mac80211/main.c736ff).
/// Prefixes match the bytes after the24-byte management header (mlme.c).
pub(super) fn registration(frame_type: u16, prefix: &[u8]) -> Result<(), i32> {
    if !matches!(frame_type, 0x40 | 0xb0 | 0xd0) || prefix.len() > 4008 {
        return Err(22);
    }
    Ok(())
}
#[derive(Debug)]
pub(super) struct Received<'a> {
    pub frame: &'a [u8],
    pub frame_type: u16,
    pub signal_dbm: Option<i8>,
}
/// Unkeyed native management admission only; raw bytes do not authenticate
/// a peer. Unknown/unassociated RX WCIDs are not mapped to a data owner.
/// Linux DEVICE handling uses public/action/address semantics, not an
/// invented meaning for the unused RXD2.BSSID field (rx.c4647ff).
pub(super) fn received<'a>(
    packet: &'a [u8],
    nss: u8,
    local: [u8; 6],
    frequency_mhz: u32,
) -> Option<Received<'a>> {
    let raw = super::ap_rx::decode(packet, nss)?;
    if crate::mt7921::channel::frequency_in(raw.band, raw.channel)? != frequency_mhz || raw.fragment
    {
        return None;
    }
    let frame = raw.frame;
    if !(24..=4032).contains(&frame.len())
        || frame[0] & 15 != 0
        || frame[1] & 0xc7 != 0
        || frame[22] & 15 != 0
        || frame[10..16] == [0; 6]
        || frame[10] & 1 != 0
        || !(frame[4..10] == local || frame[4] & 1 != 0)
    {
        return None;
    }
    let frame_type = u16::from(frame[0]);
    match frame_type {
        0x40 => {}
        0xb0 if frame[4..10] == local => {}
        0xd0 if frame.get(24) == Some(&4) => {}
        _ => return None,
    }
    Some(Received {
        frame,
        frame_type,
        signal_dbm: raw.signal_dbm,
    })
}
