//! UMAC scan v14..18 and AX210+ receive MPDU envelope.

use super::boot_context::{put16, put32};
use alloc::{vec, vec::Vec};

pub fn dtim_period(beacon_body: &[u8]) -> u8 {
    let mut ies = beacon_body.get(12..).unwrap_or(&[]);
    while ies.len() >= 2 {
        let len = ies[1] as usize;
        if len > ies.len() - 2 {
            break;
        }
        if ies[0] == 5 && len >= 4 {
            return ies[3].max(1);
        }
        ies = &ies[len + 2..];
    }
    1
}

/// Build a passive scan (including DFS channels without transmitting).
/// Scanning SSIDs is a host-side filter for passive scans.
pub fn passive(version: u8, uid: u32, channels: &[u8]) -> Result<Vec<u8>, &'static str> {
    let capacity = match version {
        14..=17 => 67,
        18 => 68,
        _ => return Err("unsupported scan command version"),
    };
    if channels.is_empty() || channels.len() > capacity || channels.contains(&0) {
        return Err("invalid scan channels");
    }
    // uid/ooc(8), general(36), channel(4+8*N), periodic(12),
    // probe(532+4+20*34+8*4+16*6). See fw/api/scan.h.
    let periodic = 48 + capacity * 8;
    let mut out = vec![0; periodic + 12 + 1344];
    put32(&mut out, 0, uid);
    put32(&mut out, 4, 6);
    put16(&mut out, 8, (1 << 1) | (1 << 11)); // PASS_ALL | FORCE_PASSIVE
    out[12..14].fill(10); // active dwell (unused)
    put32(&mut out, 36, 6); // scan priority
    out[40..42].fill(110); // passive dwell per LMAC (TU)
    out[45] = channels.len() as u8;
    for (i, &channel) in channels.iter().enumerate() {
        let start = 48 + i * 8;
        // Modern channel flags use PHY_BAND_24=1, PHY_BAND_5=0
        // (opposite the legacy scan v2 band's numbering).
        put32(&mut out, start, if channel <= 14 { 1 << 30 } else { 0 });
        out[start + 4] = channel;
        out[start + 5] = 127; // PSD reserved
        out[start + 6] = 1; // one iteration
    }
    out[periodic + 2] = 1;
    Ok(out)
}

/// Directed/wildcard probes only on channels authorized by both the signed
/// host policy and the firmware MCC response. A zero SSID bitmap leaves an
/// individual channel passive. Layout is SCAN_PROBE_PARAMS_API_S_VER_4.
pub fn active(
    version: u8,
    uid: u32,
    channels: &[u8],
    permitted: &[bool],
    local: [u8; 6],
    ssids: &[Vec<u8>],
) -> Result<Vec<u8>, &'static str> {
    if permitted.len() != channels.len()
        || ssids.len() > 20
        || ssids.iter().any(|s| s.len() > 32)
        || local[0] & 1 != 0
        || local == [0; 6]
    {
        return Err("invalid active scan request");
    }
    let mut out = passive(version, uid, channels)?;
    if !permitted.iter().any(|&allowed| allowed) {
        return Ok(out);
    }
    put16(&mut out, 8, 1 << 1); // PASS_ALL, without FORCE_PASSIVE
    out[12..14].fill(30);
    let count = ssids.len().max(1); // empty list means a wildcard probe
    let bitmap = (1u32 << count) - 1;
    for (i, &allowed) in permitted.iter().enumerate() {
        if allowed {
            let offset = 48 + i * 8;
            let flags = u32::from_le_bytes(out[offset..offset + 4].try_into().unwrap());
            put32(&mut out, offset, flags | bitmap);
        }
    }
    let capacity = if version == 18 { 68 } else { 67 };
    let probe = 48 + capacity * 8 + 12;
    let data = probe + 20; // five offset/length segment descriptors
    let mut header = super::frame_api::management(0x40, local, [0xff; 6], 0, &[0, 0]);
    header[1] = 0;
    out[data..data + header.len()].copy_from_slice(&header);
    put16(&mut out, probe + 2, header.len() as u16);
    let rates24 = [
        1, 8, 0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108,
    ];
    let rates5 = [1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108];
    let mut offset = header.len();
    for (segment, bytes) in [(4, rates24.as_slice()), (8, rates5.as_slice())] {
        put16(&mut out, probe + segment, offset as u16);
        put16(&mut out, probe + segment + 2, bytes.len() as u16);
        out[data + offset..data + offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
    }
    // 6 GHz/common segments stay empty. Firmware substitutes each
    // selected direct_scan SSID into the wildcard IE in the MAC segment.
    for (i, ssid) in ssids.iter().enumerate() {
        let entry = probe + 536 + i * 34;
        out[entry + 1] = ssid.len() as u8;
        out[entry + 2..entry + 2 + ssid.len()].copy_from_slice(ssid);
    }
    Ok(out)
}

#[derive(Debug)]
pub struct Mpdu<'a> {
    pub frame: &'a [u8],
    pub channel: u8,
    pub rssi: i8,
    pub status: u32,
    padding: usize,
    trailer: usize,
    pub amsdu: bool,
}

impl<'a> Mpdu<'a> {
    /// Firmware padding follows the MAC header and any crypto IV.
    /// The envelope says how many CRC/MIC bytes remain at the tail.
    pub fn body(&self, header_len: usize, crypto_len: usize) -> Option<&'a [u8]> {
        let begin = header_len
            .checked_add(crypto_len)?
            .checked_add(self.padding)?;
        let end = self.frame.len().checked_sub(self.trailer)?;
        self.frame.get(begin..end)
    }
}

/// AX210+ uses the 64-byte v3 envelope. CRC/overrun failures must
/// never enter the 802.11 parser or the network stack.
pub fn mpdu(bytes: &[u8]) -> Option<Mpdu<'_>> {
    if bytes.len() < 64 {
        return None;
    }
    let len = u16::from_le_bytes(bytes[..2].try_into().ok()?) as usize;
    let status = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    if status & 3 != 3 || len < 10 || len > bytes.len() - 64 {
        return None;
    }
    let energy_a = bytes[40];
    let energy_b = bytes[41];
    let energy = match (energy_a, energy_b) {
        (0, b) => b,
        (a, 0) => a,
        (a, b) => a.min(b),
    };
    Some(Mpdu {
        frame: &bytes[64..64 + len],
        channel: bytes[42],
        rssi: -(energy.min(127) as i8),
        status,
        padding: if bytes[3] & 0x20 != 0 { 2 } else { 0 },
        trailer: ((bytes[2] >> 4) as usize) * 2,
        amsdu: bytes[3] & 0x40 != 0,
    })
}
