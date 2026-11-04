//! Source-qualified UMAC14..18 PSC/RNR scan parameters. Linux
//! mld/scan.c and mvm/scan.c keep the6GHz channel/probe namespace separate.
use super::{
    boot_context::{put16, put32},
    ht_vht::Local,
    native_band::{Band, Channel},
};
use alloc::{vec, vec::Vec};
use narf_wireless::scan::{self, Scan6GhzTarget};

pub(super) struct Active<'a> {
    pub permitted: &'a [bool],
    pub ssids: &'a [Vec<u8>],
    pub targets: &'a [Scan6GhzTarget],
    pub phy: Local,
    pub hidden: bool,
    pub tpc: bool,
    pub fixed: bool,
    pub extra_ies: &'a [u8],
}
pub(super) fn power(
    local: Local,
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: Channel,
    mcc: &super::mld_regulatory::Mcc,
) -> Option<i8> {
    if channel.band != Band::Six || !local.he || !mcc.he_allowed {
        return None;
    }
    let flags = *mcc.channels.get(channel.index()?)?;
    if flags & 9 != 9 || flags & 16 != 0 {
        return None;
    }
    let span = super::six_ghz_span::Span::new(channel.number, 0, channel.number)?;
    span.rule(domain, span.nvm_flags(local)?, Some(mcc))
        .map(|rule| rule.max_power_dbm)
}
pub(super) fn request(
    version: u8,
    uid: u32,
    channels: &[Channel],
    local: [u8; 6],
    scan: &Active<'_>,
) -> Result<Vec<u8>, &'static str> {
    if channels.iter().any(|ch| ch.band != Band::Six)
        || scan.permitted.len() != channels.len()
        || scan.ssids.len() > 20
        || scan.ssids.iter().any(|s| s.len() > 32)
        || local == [0; 6]
        || local[0] & 1 != 0
    {
        return Err("native6GHz scan source/target shape invalid");
    }
    let mut out = super::scan_api::passive_channels(version, uid, channels)?;
    if scan.fixed {
        out[17] = 1 << 2;
    }
    if !scan.permitted.iter().any(|&p| p) {
        return Ok(out);
    }
    if !scan.phy.he {
        return Err("active6GHz scan has no actual local HE source");
    }
    let capacity = if version == 18 { 68 } else { 67 };
    let probe = 48 + capacity * 8 + 12;
    let mut short = Vec::new();
    let mut direct = Vec::new();
    let mut bssid = Vec::new();
    for ssid in scan.ssids.iter().filter(|s| !s.is_empty()).take(8) {
        short.push(scan::short_ssid(ssid));
        direct.push(if scan.hidden { ssid.as_slice() } else { &[] });
    }
    for target in scan.targets {
        if target.bssid == [0; 6]
            || target.bssid[0] & 1 != 0
            || Channel::six(target.channel).is_none_or(|ch| ch.frequency() != target.frequency_mhz)
        {
            return Err("native6GHz RNR target has invalid physical identity");
        }
        if let Some(crc) = target.short_ssid {
            if short.len() < 8 && !short.contains(&crc) {
                short.push(crc);
                direct.push(&[]);
            }
        }
        if bssid.len() < 16 && !bssid.contains(&target.bssid) {
            bssid.push(target.bssid);
        }
    }
    put16(
        &mut out,
        8,
        (1 << 1)
            | if scan.ssids.len() == 1 && !scan.ssids[0].is_empty() {
                1 << 6
            } else {
                0
            },
    );
    out[12..14].fill(30);
    out[44] = if scan.ssids.is_empty() || scan.ssids.len() == 1 && scan.ssids[0].is_empty() {
        1 << 6
    } else {
        0
    };
    out[probe + 532] = short.len() as u8;
    out[probe + 533] = bssid.len() as u8;
    for (i, &crc) in short.iter().enumerate() {
        put32(&mut out, probe + 1216 + i * 4, crc);
        let at = probe + 536 + i * 34;
        out[at + 1] = direct[i].len() as u8;
        out[at + 2..at + 2 + direct[i].len()].copy_from_slice(direct[i]);
    }
    for (i, mac) in bssid.iter().enumerate() {
        out[probe + 1248 + i * 6..probe + 1254 + i * 6].copy_from_slice(mac);
    }
    for (i, &channel) in channels.iter().enumerate() {
        let psc = scan::is_psc_6ghz(channel.number);
        let targets: Vec<_> = scan
            .targets
            .iter()
            .filter(|t| t.frequency_mhz == channel.frequency())
            .collect();
        let unsolicited = targets.iter().any(|t| t.unsolicited_probe);
        let no_listen = psc && targets.iter().any(|t| t.psc_no_listen);
        let (max_short, max_bssid) = if !psc || no_listen {
            if unsolicited {
                (2, 6)
            } else {
                (3, 9)
            }
        } else {
            (2, 6)
        };
        let (mut shorts, mut bssids, mut ns, mut nb) = (0u32, 0u32, 0u8, 0u8);
        let (mut force, mut passive) = (false, true);
        for target in &targets {
            let mut found = false;
            if !target.unsolicited_probe {
                if let Some(crc) = target.short_ssid {
                    if let Some(k) = short.iter().position(|&s| s == crc) {
                        if ns < max_short {
                            if shorts & (1 << k) != 0 {
                                found = true;
                            } else if 3 * ns <= nb || !direct[k].is_empty() {
                                passive &= direct[k].is_empty();
                                shorts |= 1 << k;
                                ns += 1;
                                found = true;
                            }
                        }
                    }
                }
            }
            if !found {
                if let Some(k) = bssid.iter().position(|&mac| mac == target.bssid) {
                    if bssids & (1 << k) == 0 {
                        if nb < max_bssid {
                            bssids |= 1 << k;
                            nb += 1;
                        } else {
                            force = true;
                        }
                    }
                }
            }
        }
        let flags = if !scan.permitted[i] || (passive && force) || (!psc && (shorts | bssids) == 0)
        {
            1 << 26
        } else {
            bssids | (shorts << 16)
        } | if no_listen { 1 << 25 } else { 0 }
            | if unsolicited { 1 << 24 } else { 0 };
        let at = 48 + i * 8;
        put32(
            &mut out,
            at,
            flags | if version >= 17 { 2 << 30 } else { 0 },
        );
        if version >= 17 {
            out[at + 5] = targets
                .iter()
                .map(|t| t.psd_20)
                .filter(|p| *p != scan::PSD_RESERVED)
                .max()
                .unwrap_or(scan::PSD_RESERVED) as u8;
        } else {
            out[at + 5] = 2;
        }
    }
    probe_template(&mut out, probe, local, scan)?;
    Ok(out)
}

fn probe_template(
    out: &mut [u8],
    probe: usize,
    local: [u8; 6],
    scan: &Active<'_>,
) -> Result<(), &'static str> {
    let header = super::frame_api::management(0x40, local, [0xff; 6], 0, &[0, 0]);
    let mut phy = vec![1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108];
    let he = super::sc_he::local_six_width(scan.phy, 0)?;
    let body = he.capability_body();
    phy.extend_from_slice(&[255, body.len() as u8]);
    phy.extend_from_slice(&body);
    if scan.phy.eht {
        let eht = super::sc_eht::local_six_width(scan.phy, &he, 0)?.capability_body();
        phy.extend_from_slice(&[255, eht.len() as u8]);
        phy.extend_from_slice(&eht);
    }
    phy.extend_from_slice(
        &narf_wireless::association::six_ghz::He6GhzCapability::new(4 | (3 << 3) | (3 << 9))
            .element(),
    );
    let mut common = scan.extra_ies.to_vec();
    let mut rest = common.as_slice();
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or("short6GHz probe extra IE")?);
        let body = rest.get(2..2 + len).ok_or("short6GHz probe extra extent")?;
        if matches!(rest[0], 0 | 1 | 3 | 45 | 50 | 61 | 191 | 192)
            || rest[0] == 255 && body.first().is_some_and(|id| matches!(id, 35 | 59 | 108))
        {
            return Err("6GHz probe extra IE overrides native source capability");
        }
        rest = &rest[2 + len..];
    }
    if scan.tpc {
        common.extend_from_slice(&[221, 7, 0, 0x50, 0xf2, 8, 0, 0, 0]);
    }
    let total = header.len() + phy.len() + common.len();
    if total > 512 {
        return Err("6GHz native probe template exceeds source512-byte buffer");
    }
    put16(out, probe + 2, header.len() as u16);
    put16(out, probe + 12, header.len() as u16);
    put16(out, probe + 14, phy.len() as u16);
    put16(out, probe + 16, (header.len() + phy.len()) as u16);
    put16(out, probe + 18, common.len() as u16);
    let at = probe + 20;
    out[at..at + header.len()].copy_from_slice(&header);
    out[at + header.len()..at + header.len() + phy.len()].copy_from_slice(&phy);
    out[at + header.len() + phy.len()..at + total].copy_from_slice(&common);
    Ok(())
}
