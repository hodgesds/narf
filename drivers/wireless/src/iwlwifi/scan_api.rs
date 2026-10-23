//! UMAC scan v14..18 and generation-specific receive MPDU envelopes.

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
        let band = u8::from(channel <= 14);
        if version < 17 {
            // SCAN_CHANNEL_CONFIG v2: band is the byte after channel.
            out[start + 5] = band;
        } else {
            // v5 moves band into flags and reuses that byte for PSD.
            put32(&mut out, start, u32::from(band) << 30);
            out[start + 5] = 127; // PSD reserved
        }
        out[start + 4] = channel;
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
    pub reorder: u32,
    padding: usize,
    trailer: usize,
    pub amsdu: bool,
    pub amsdu_index: u8,
    pub amsdu_last: bool,
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
    mpdu_layout(bytes, 64, 40)
}
/// Pre-AX210 MVM API4 envelope is 48 bytes. Fields before the PHY union
/// are shared, but chain energy/channel live eight bytes earlier.
pub fn mpdu_gen2(bytes: &[u8]) -> Option<Mpdu<'_>> {
    mpdu_layout(bytes, 48, 32)
}
fn mpdu_layout(bytes: &[u8], prefix: usize, energy_offset: usize) -> Option<Mpdu<'_>> {
    if bytes.len() < prefix {
        return None;
    }
    let len = u16::from_le_bytes(bytes[..2].try_into().ok()?) as usize;
    let status = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    if status & 3 != 3 || len < 10 || len > bytes.len() - prefix {
        return None;
    }
    let energy_a = bytes[energy_offset];
    let energy_b = bytes[energy_offset + 1];
    let energy = match (energy_a, energy_b) {
        (0, b) => b,
        (a, 0) => a,
        (a, b) => a.min(b),
    };
    Some(Mpdu {
        frame: &bytes[prefix..prefix + len],
        channel: bytes[energy_offset + 2],
        rssi: -(energy.min(127) as i8),
        status,
        reorder: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
        padding: if bytes[3] & 0x20 != 0 { 2 } else { 0 },
        trailer: ((bytes[2] >> 4) as usize) * 2,
        amsdu: bytes[3] & 0x40 != 0,
        amsdu_index: bytes[4] & 0x7f,
        amsdu_last: bytes[4] & 0x80 != 0,
    })
}

/// Add band-specific PHY capabilities to active probe templates. Direct
/// SSID entries are outside the 512-byte packet buffer and stay in place.
pub fn with_phy_capabilities(
    version: u8,
    body: &mut [u8],
    local: super::ht_vht::Local,
) -> Result<(), &'static str> {
    let capacity = match version {
        14..=17 => 67,
        18 => 68,
        _ => return Err("unsupported scan version"),
    };
    let probe = 48 + capacity * 8 + 12;
    if body.len() < probe + 1344 {
        return Err("short scan probe template");
    }
    if u16::from_le_bytes(body[8..10].try_into().unwrap()) & (1 << 11) != 0 {
        return Ok(());
    }
    let mut segments = Vec::new();
    for (descriptor, band) in [(4, 2400), (8, 5000)] {
        let offset = u16::from_le_bytes(
            body[probe + descriptor..probe + descriptor + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let length = u16::from_le_bytes(
            body[probe + descriptor + 2..probe + descriptor + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if offset + length > 512 {
            return Err("invalid probe segment");
        }
        let mut bytes = body[probe + 20 + offset..probe + 20 + offset + length].to_vec();
        if let Some(caps) = local.capabilities(band) {
            bytes.extend_from_slice(&[45, 26]);
            bytes.extend_from_slice(&caps.ht);
            if let Some(vht) = caps.vht {
                bytes.extend_from_slice(&[191, 12]);
                bytes.extend_from_slice(&vht);
            }
        }
        segments.push((descriptor, bytes));
    }
    let mut offset = 26usize;
    for (descriptor, bytes) in segments {
        if offset + bytes.len() > 512 {
            return Err("probe capabilities exceed template");
        }
        put16(body, probe + descriptor, offset as u16);
        put16(body, probe + descriptor + 2, bytes.len() as u16);
        body[probe + 20 + offset..probe + 20 + offset + bytes.len()].copy_from_slice(&bytes);
        offset += bytes.len();
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod gen2_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_iwl_gen2_mpdu_native48_prefix_and_phy_offsets() -> TestResult {
        // Literal RX_MPDU_RES_START_API_S_VER_4: common20 + v1 tail28.
        // PHY union has RSS/filter/rate, then energy A/B and channel.
        let mut bytes = [0; 48 + 36];
        bytes[..5].copy_from_slice(&[36, 0, 0x20, 0x60, 0x83]);
        bytes[12..16].copy_from_slice(&0x12340003u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x56789abcu32.to_le_bytes());
        bytes[32..36].copy_from_slice(&[75, 43, 36, 0]);
        // Distinguish from the modern PHY position and catch a reused64 prefix.
        bytes[40..44].copy_from_slice(&[21, 22, 11, 0]);
        bytes[48..].fill(0xab);
        bytes[48..50].copy_from_slice(&[0x88, 2]);
        let Some(mpdu) = mpdu_gen2(&bytes) else {
            return TestResult::Fail("valid48-byte MVM envelope rejected");
        };
        if mpdu.frame != &bytes[48..]
            || mpdu.channel != 36
            || mpdu.rssi != -43
            || mpdu.status != 0x12340003
            || mpdu.reorder != 0x56789abc
            || !mpdu.amsdu
            || mpdu.amsdu_index != 3
            || !mpdu.amsdu_last
            || mpdu.body(26, 0) != Some(&bytes[76..80])
            || mpdu_gen2(&bytes[..47]).is_some()
            || super::mpdu(&bytes).is_some()
        {
            return TestResult::Fail("Gen2 envelope extent/PHY/padding/trailer used modern layout");
        }
        bytes[0..2].copy_from_slice(&37u16.to_le_bytes());
        if mpdu_gen2(&bytes).is_some() {
            return TestResult::Fail("Gen2 MPDU body escaped received extent");
        }
        bytes[0..2].copy_from_slice(&36u16.to_le_bytes());
        bytes[12] &= !1;
        if mpdu_gen2(&bytes).is_some() {
            return TestResult::Fail("Gen2 CRC failure admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2",
        smoke_iwl_gen2_mpdu_native48_prefix_and_phy_offsets
    );
}
