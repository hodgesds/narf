//! Linux ethtool ioctl wire codec. All user access and CAP_NET_ADMIN checks
//! remain in userspace/; this bounded codec calls native device controls.
use crate::nic::{self, LinkSettings, Pause};
pub(crate) mod features;
mod genl;

fn get(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}
fn put(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
}

pub fn header_size(cmd: u32) -> Option<usize> {
    Some(match cmd {
        0x01 | 0x02 => 44,
        0x05 | 0x06 => 20,
        0x04 => 12,
        0x07 | 0x08 | 0x25..=0x28 | 0x3a | 0x3b => 8,
        0x20 => 8,
        0x0b | 0x0c => 16,
        0x09 => 4,
        0x0e | 0x0f => 92,
        0x10 | 0x11 | 0x3c | 0x3d => 36,
        0x12 | 0x13 => 16,
        0x14..=0x19 | 0x1e | 0x1f | 0x21..=0x24 | 0x2b..=0x2d => 8,
        0x1b => 12,
        0x1d => 8,
        0x1a => 16,
        0x29 | 0x2a | 0x2e..=0x32 => 192,
        0x37 => 16,
        0x38 | 0x39 => 8,
        0x41 => 44,
        0x44 | 0x45 => 40,
        0x46 | 0x47 => 24,
        0x4c | 0x4d => 48,
        _ => return None,
    })
}

pub fn request_size(header: &[u8]) -> nic::Result<usize> {
    if header.len() < 4 {
        return Err(22);
    }
    let cmd = get(header, 0);
    let base = header_size(cmd).ok_or(95)?;
    if header.len() < base {
        return Err(22);
    }
    let extra = match cmd {
        0x04 => get(header, 8) as usize,
        // GPERMADDR: the user buffer follows the 8-byte header; Linux
        // `ethtool_get_perm_addr` fails a buffer smaller than the
        // address with -ETOOSMALL (133).
        0x20 => {
            let size = get(header, 4) as usize;
            if size < 6 {
                return Err(133);
            }
            size
        }
        0x0b | 0x0c => get(header, 12) as usize,
        0x1b => (get(header, 8) as usize).checked_mul(32).ok_or(22)?,
        0x1d => (get(header, 4) as usize).checked_mul(8).ok_or(22)?,
        0x1a => (get(header, 12) as usize).checked_mul(8).ok_or(22)?,
        0x37 => u64::from_ne_bytes(header[8..16].try_into().unwrap()).count_ones() as usize * 4,
        0x3a => (get(header, 4) as usize).checked_mul(16).ok_or(22)?,
        0x3b => (get(header, 4) as usize).checked_mul(8).ok_or(22)?,
        0x38 | 0x39 => {
            let size = get(header, 4) as usize;
            if size > 128 {
                return Err(22);
            }
            size.checked_mul(4).ok_or(22)?
        }
        0x46 | 0x47 => {
            let indir = get(header, 8);
            let key = get(header, 12);
            if (indir != u32::MAX && indir > 128) || key > 40 {
                return Err(22);
            }
            (if indir == u32::MAX {
                0
            } else {
                indir as usize * 4
            }) + key as usize
        }
        0x30 => (get(header, 184) as usize).checked_mul(4).ok_or(22)?,
        0x4c | 0x4d => {
            if header[15] as i8 == 2 {
                24
            } else {
                0
            }
        }
        _ => 0,
    };
    let total = base.checked_add(extra).ok_or(22)?;
    if total > 65536 {
        return Err(22);
    }
    Ok(total)
}
fn legacy_modes(bits: u32) -> u32 {
    (bits & 15) | ((bits & 16) << 1)
}
fn native_modes(bits: u32) -> u32 {
    (bits & 15) | ((bits >> 1) & 16)
}

pub fn execute(name: &str, b: &mut [u8]) -> nic::Result<()> {
    execute_with_result(name, b).map(|_| ())
}

/// Linux SFEATURES returns a nonnegative status bitmap, not just zero.
pub fn execute_with_result(name: &str, b: &mut [u8]) -> nic::Result<u32> {
    if request_size(b)? != b.len() {
        return Err(22);
    }
    if let Some(result) = features::legacy(name, b)? {
        return Ok(result);
    }
    match get(b, 0) {
        0x37 => {
            let mask = u64::from_ne_bytes(b[8..16].try_into().unwrap());
            let mut supported = 0u64;
            let mut at = 16;
            for id in 0..64 {
                if mask & (1u64 << id) == 0 {
                    continue;
                }
                match strings(Some(name), id) {
                    Ok(names) => {
                        supported |= 1u64 << id;
                        put(b, at, names.len() as u32);
                        at += 4;
                    }
                    Err(95) => {}
                    Err(e) => return Err(e),
                }
            }
            put64(b, 8, supported);
            return Ok(0);
        }
        0x1b => {
            let names = strings(Some(name), get(b, 4))?;
            let requested = get(b, 8) as usize;
            if requested != 0 && requested < names.len() {
                return Err(22);
            }
            put(b, 8, names.len() as u32);
            b[12..].fill(0);
            for (i, name) in names.iter().take(requested).enumerate() {
                let text = name.as_bytes();
                let n = text.len().min(31);
                b[12 + i * 32..12 + i * 32 + n].copy_from_slice(&text[..n]);
            }
            return Ok(0);
        }
        _ => {}
    }
    execute_device(name, b).map(|_| 0)
}

fn strings(name: Option<&str>, id: u32) -> nic::Result<alloc::vec::Vec<alloc::string::String>> {
    use alloc::string::String;
    if id == 4 {
        return Ok(features::NAMES.iter().map(|s| String::from(*s)).collect());
    }
    if let Some(names) = genl::global_strings(id) {
        return Ok(names.iter().map(|s| String::from(*s)).collect());
    }
    nic::with_control(name.ok_or(95)?, |d| match id {
        0 => Ok(d
            .diagnostics(false)?
            .into_iter()
            .map(|t| String::from(t.name))
            .collect()),
        1 => Ok(d.statistics()?.into_iter().map(|s| s.name).collect()),
        2 => Ok(d
            .priv_flag_names()
            .iter()
            .map(|s| String::from(*s))
            .collect()),
        _ => Err(95),
    })
}

fn execute_device(name: &str, b: &mut [u8]) -> nic::Result<()> {
    let size = request_size(b)?;
    if b.len() != size {
        return Err(22);
    }
    let cmd = get(b, 0);
    nic::with_control(name, |driver| {
        match cmd {
            0x04 => {
                let regs = driver.registers()?;
                let bytes = (get(b, 8) as usize).min(regs.len() * 4);
                put(b, 4, driver.registers_version());
                put(b, 8, bytes as u32);
                for i in 0..bytes {
                    b[12 + i] = regs[i / 4].to_ne_bytes()[i % 4];
                }
                return Ok(());
            }
            0x0b => {
                let (magic, _) = driver.nvm_info()?;
                put(b, 4, magic);
                let offset = get(b, 8);
                let len = get(b, 12);
                let bytes = driver.nvm(offset, len)?;
                if bytes.len() != len as usize {
                    return Err(5);
                }
                b[16..].copy_from_slice(&bytes);
                return Ok(());
            }
            0x0c => {
                let magic = get(b, 4);
                let offset = get(b, 8);
                let len = get(b, 12) as usize;
                driver.set_nvm(magic, offset, &b[16..16 + len])?;
                return Ok(());
            }
            0x20 => {
                // Linux `ethtool_get_perm_addr`: the size word is the
                // user buffer size on entry and the address size (6)
                // on return; `request_size` already rejected a buffer
                // smaller than the address with -ETOOSMALL.
                let mac = driver.permanent_mac()?;
                put(b, 4, 6);
                b[8..14].copy_from_slice(&mac);
                return Ok(());
            }
            0x2e..=0x32 => {
                let mut rules = driver.flow_rules()?;
                let location = get(b, 176);
                match cmd {
                    0x2e => {
                        put(b, 184, rules.len() as u32);
                        put64(b, 8, u64::from(nic::MAX_RXNFC_RULES));
                    }
                    0x30 => {
                        let capacity = get(b, 184) as usize;
                        if capacity < rules.len() {
                            return Err(90);
                        }
                        put64(b, 8, u64::from(nic::MAX_RXNFC_RULES));
                        put(b, 184, rules.len() as u32);
                        for (i, r) in rules.iter().enumerate() {
                            put(b, 188 + i * 4, u32::from(r.location));
                        }
                    }
                    0x2f => {
                        let r = rules
                            .iter()
                            .find(|r| u32::from(r.location) == location)
                            .ok_or(2)?;
                        // Linux `igc_ethtool_get_nfc_rule` reports the
                        // table size here too.
                        put64(b, 8, u64::from(nic::MAX_RXNFC_RULES));
                        encode_rule(b, r);
                    }
                    0x32 => {
                        if get(b, 176) == u32::MAX {
                            let location = (0..u32::from(nic::MAX_RXNFC_RULES))
                                .find(|i| !rules.iter().any(|r| u32::from(r.location) == *i))
                                .ok_or(28)?;
                            put(b, 176, location);
                        }
                        let r = decode_rule(b)?;
                        if rules.iter().any(|old| old.location == r.location) {
                            rules.retain(|old| old.location != r.location);
                        }
                        rules.push(r);
                        rules.sort_by_key(|r| r.location);
                        driver.set_flow_rules(rules)?;
                    }
                    0x31 => {
                        if !rules.iter().any(|r| u32::from(r.location) == location) {
                            return Err(2);
                        }
                        rules.retain(|r| u32::from(r.location) != location);
                        driver.set_flow_rules(rules)?;
                    }
                    _ => unreachable!(),
                }
                return Ok(());
            }
            0x07 => {
                put(b, 4, driver.msglevel()?);
                return Ok(());
            }
            0x08 => {
                return driver.set_msglevel(get(b, 4));
            }
            0x27 => {
                put(b, 4, driver.priv_flags()?);
                return Ok(());
            }
            0x28 => {
                return driver.set_priv_flags(get(b, 4));
            }
            0x29 | 0x2a => {
                // struct ethtool_rxnfc: cmd(0), flow_type(4), data(8).
                let flow_type = u8::try_from(get(b, 4)).map_err(|_| 22)?;
                if cmd == 0x29 {
                    put64(b, 8, u64::from(driver.rxfh_fields(flow_type)?));
                } else {
                    let data = u64::from_ne_bytes(b[8..16].try_into().unwrap());
                    let data = u32::try_from(data).map_err(|_| 22)?;
                    driver.set_rxfh_fields(flow_type, data)?;
                }
                return Ok(());
            }
            0x09 => return driver.restart_link(),
            0x1d => {
                let stats = driver.statistics()?;
                let requested = get(b, 4) as usize;
                if requested != 0 && requested < stats.len() {
                    return Err(22);
                }
                put(b, 4, stats.len() as u32);
                for (i, s) in stats.iter().take(requested).enumerate() {
                    put64(b, 8 + i * 8, s.value);
                }
                return Ok(());
            }
            0x1a => {
                let requested = get(b, 12) as usize;
                let tests = driver.diagnostics(get(b, 4) & 1 != 0)?;
                put(b, 12, tests.len() as u32);
                if tests.iter().any(|t| !t.passed) {
                    put(b, 4, get(b, 4) | 2);
                }
                for (i, test) in tests.iter().take(requested).enumerate() {
                    put64(b, 16 + i * 8, u64::from(!test.passed));
                }
                return Ok(());
            }
            0x41 => {
                b[4..].fill(0);
                let (timestamping, tx_types, rx_filters) = driver.timestamp_info();
                put(b, 4, timestamping);
                put(b, 8, driver.clock_index() as u32);
                put(b, 12, tx_types);
                put(b, 28, rx_filters);
                return Ok(());
            }
            0x2d => {
                put(b, 4, u32::from(driver.settings()?.channels));
                return Ok(());
            }
            _ => {}
        }
        let mut s = driver.settings()?;
        let mut changed = false;
        match cmd {
            0x01 => {
                let link = crate::iface::lookup(name).ok_or(19)?;
                put(b, 4, legacy_modes(driver.supported_link_modes()) | (1 << 6));
                put(b, 8, legacy_modes(s.link.advertised));
                let speed = link.speed_mbps.unwrap_or(u32::MAX);
                b[12..14].copy_from_slice(&(speed as u16).to_ne_bytes());
                b[14] = u8::from(link.duplex == Some(crate::iface::LinkDuplex::Full));
                b[18] = u8::from(s.link.autoneg);
                b[28..30].copy_from_slice(&((speed >> 16) as u16).to_ne_bytes());
            }
            0x02 => {
                s.link = LinkSettings {
                    advertised: native_modes(get(b, 8)),
                    autoneg: b[18] != 0,
                    speed_mbps: u32::from(u16::from_ne_bytes(b[12..14].try_into().unwrap()))
                        | (u32::from(u16::from_ne_bytes(b[28..30].try_into().unwrap())) << 16),
                    full_duplex: b[14] != 0,
                };
                changed = true;
            }
            0x05 => {
                put(b, 4, 0x2f);
                put(b, 8, s.wake);
            }
            0x06 => {
                s.wake = get(b, 8);
                changed = true;
            }
            0x0e => {
                b[4..].fill(0);
                put(b, 4, s.coalesce_us);
                put(b, 20, s.coalesce_us);
            }
            0x0f => {
                if get(b, 4) != get(b, 20) {
                    return Err(95);
                }
                // Linux igc_ethtool_set_coalesce ignores every field other
                // than rx/tx usecs; the driver hook validates the pair.
                driver.check_coalesce(get(b, 4), get(b, 20))?;
                s.coalesce_us = get(b, 4);
                changed = true;
            }
            0x10 => {
                b[4..].fill(0);
                put(b, 4, 4096);
                put(b, 16, 4096);
                put(b, 20, s.rx_entries);
                put(b, 32, s.tx_entries);
            }
            0x11 => {
                if get(b, 24) != 0 || get(b, 28) != 0 {
                    return Err(22);
                }
                s.rx_entries = get(b, 20);
                s.tx_entries = get(b, 32);
                changed = true;
            }
            0x12 => {
                put(b, 4, u32::from(s.pause.autoneg));
                put(b, 8, u32::from(s.pause.rx));
                put(b, 12, u32::from(s.pause.tx));
            }
            0x13 => {
                s.pause = Pause {
                    autoneg: get(b, 4) != 0,
                    rx: get(b, 8) != 0,
                    tx: get(b, 12) != 0,
                };
                changed = true;
            }
            0x3c => {
                b[4..].fill(0);
                put(b, 12, 1);
                put(b, 16, 4);
                put(b, 28, 1);
                put(b, 32, u32::from(s.channels));
            }
            0x3d => {
                // Linux igc_ethtool_set_channels: no separate rx/tx vectors,
                // and other_count must stay NON_Q_VECTORS (1).
                if [20, 24].iter().any(|i| get(b, *i) != 0) || get(b, 28) != 1 {
                    return Err(22);
                }
                let count = get(b, 32);
                if count == 0 || count > 4 {
                    return Err(22);
                }
                s.channels = count as u16;
                s.rss = crate::rss::RssConfig::standard(count as usize, 128);
                changed = true;
            }
            0x44 => {
                b[4..].fill(0);
                let status = driver.eee_status()?;
                put(b, 4, legacy_modes(driver.supported_link_modes()) & 0x28);
                put(b, 8, legacy_modes(status.advertised) & 0x28);
                put(b, 12, legacy_modes(status.partner) & 0x28);
                put(b, 16, u32::from(status.active));
                put(b, 20, u32::from(s.eee));
                put(b, 24, u32::from(status.tx_lpi));
            }
            0x45 => {
                // Linux igc_ethtool_set_eee: while EEE is enabled, tx-lpi
                // cannot change and the LPI timer is not implemented; while
                // it is disabled, a set that does not enable EEE is rejected.
                let enabled = get(b, 20) != 0;
                let tx_lpi = get(b, 24) != 0;
                let timer = get(b, 28);
                if s.eee {
                    let current_lpi = driver.eee_status().map(|st| st.tx_lpi).unwrap_or(false);
                    if tx_lpi != current_lpi || timer != 0 {
                        return Err(22);
                    }
                } else if !enabled {
                    return Err(22);
                }
                s.eee = enabled;
                changed = true;
            }
            0x38 | 0x39 => {
                // Legacy RXFH indirection (struct ethtool_rxfh_indir: cmd,
                // size, then size u32 queue indices). A GET with size 0
                // reports the table size (128) with no entries.
                let size = get(b, 4) as usize;
                if cmd == 0x38 {
                    put(b, 4, 128);
                    for i in 0..size {
                        put(b, 8 + i * 4, u32::from(s.rss.indirection[i]));
                    }
                } else {
                    if size != 128 {
                        return Err(22);
                    }
                    for i in 0..128 {
                        let q = get(b, 8 + i * 4);
                        if q >= u32::from(s.channels) {
                            return Err(22);
                        }
                        s.rss.indirection[i] = q as u8;
                    }
                    changed = true;
                }
            }
            0x46 | 0x47 => {
                if get(b, 4) != 0 || b[17] != 0 || (b[16] != 0 && b[16] != 1) {
                    return Err(95);
                }
                let n = get(b, 8);
                let k = get(b, 12);
                let entries = if n == u32::MAX { 0 } else { n as usize };
                if (n != 0 && n != u32::MAX && n != 128) || (k != 0 && k != 40) {
                    return Err(22);
                }
                if cmd == 0x46 {
                    put(b, 8, 128);
                    put(b, 12, 40);
                    b[16] = 1;
                    for i in 0..entries {
                        put(b, 24 + i * 4, u32::from(s.rss.indirection[i]));
                    }
                    if k != 0 {
                        b[24 + entries * 4..24 + entries * 4 + 40].copy_from_slice(&s.rss.key);
                    }
                } else {
                    for i in 0..entries {
                        let q = get(b, 24 + i * 4);
                        if q >= u32::from(s.channels) {
                            return Err(22);
                        }
                        s.rss.indirection[i] = q as u8;
                    }
                    if k != 0 {
                        s.rss
                            .key
                            .copy_from_slice(&b[24 + entries * 4..24 + entries * 4 + 40]);
                    }
                    changed = true;
                }
            }
            0x4c | 0x4d => {
                if b[15] as i8 != 2 {
                    if cmd == 0x4d {
                        return Err(22);
                    }
                    // Linux returns a cleared base header and the required
                    // bitmap word count as a negative s8, with success.
                    b.fill(0);
                    put(b, 0, cmd);
                    b[15] = (-2i8) as u8;
                    return Ok(());
                }
                if cmd == 0x4c {
                    let link = crate::iface::lookup(name).ok_or(19)?;
                    put(b, 4, link.speed_mbps.unwrap_or(u32::MAX));
                    b[8] = u8::from(link.duplex == Some(crate::iface::LinkDuplex::Full));
                    b[11] = u8::from(s.link.autoneg);
                    // ksettings word 0: speed bits (native bit 4 is
                    // 1000baseT_Full, ksettings bit 5), Autoneg (6), TP (7),
                    // Pause (13). Word 1 bit 15 is 2500baseT_Full.
                    let supported = driver.supported_link_modes();
                    put(
                        b,
                        48,
                        legacy_modes(supported) | (1 << 6) | (1 << 7) | (1 << 13),
                    );
                    put(b, 52, if supported & 0x20 != 0 { 1 << 15 } else { 0 });
                    // Advertising: TP always; speeds, Autoneg and
                    // Pause/Asym_Pause only while autoneg is on (Linux
                    // igc_ethtool_get_link_ksettings). Pause follows the
                    // flow-control mode: full -> Pause, rx-only -> Pause +
                    // Asym_Pause, tx-only -> Asym_Pause.
                    let mut adv_w0 = 1 << 7;
                    let mut adv_w1 = 0;
                    if s.link.autoneg {
                        adv_w0 |= (1 << 6) | legacy_modes(s.link.advertised);
                        if s.link.advertised & 0x20 != 0 {
                            adv_w1 |= 1 << 15;
                        }
                        match (s.pause.rx, s.pause.tx) {
                            (true, true) => adv_w0 |= 1 << 13,
                            (true, false) => adv_w0 |= (1 << 13) | (1 << 14),
                            (false, true) => adv_w0 |= 1 << 14,
                            (false, false) => {}
                        }
                    }
                    put(b, 56, adv_w0);
                    put(b, 60, adv_w1);
                    put(b, 64, 0);
                    put(b, 68, 0);
                } else {
                    // Advertised modes must be a subset of supported: the
                    // driver's speeds, plus TP / Autoneg / Pause /
                    // Asym_Pause (Linux advertises Asym_Pause although it
                    // is not in the supported mask, so it is allowed here).
                    let supported = driver.supported_link_modes();
                    let sup_w0 =
                        legacy_modes(supported) | (1 << 6) | (1 << 7) | (1 << 13) | (1 << 14);
                    let sup_w1 = if supported & 0x20 != 0 { 1 << 15 } else { 0 };
                    if get(b, 56) & !sup_w0 != 0 || get(b, 60) & !sup_w1 != 0 {
                        return Err(22);
                    }
                    if b[11] != 0 && b[11] != 1 {
                        return Err(22);
                    }
                    s.link = LinkSettings {
                        advertised: native_modes(get(b, 56))
                            | if get(b, 60) & (1 << 15) != 0 { 0x20 } else { 0 },
                        autoneg: b[11] != 0,
                        speed_mbps: get(b, 4),
                        full_duplex: b[8] != 0,
                    };
                    changed = true;
                }
            }
            _ => return Err(95),
        }
        if changed {
            driver.set_settings(s)?;
        }
        Ok(())
    })
}

/// Linux `igc_ethtool_init_nfc_rule` + `igc_ethtool_add_nfc_rule`
/// (igc_ethtool.c:1225-1420), against the uapi layout
/// (`struct ethtool_rx_flow_spec`: h_u @20, h_ext @72, m_u @92,
/// m_ext @144, ring_cookie @168, location @176).
///
/// Accepted masks are full-only, as in Linux: a partial MAC/ethertype
/// mask is -EOPNOTSUPP, a VLAN TCI mask other than the priority mask
/// (0xe000) or the full mask (0xffff) is -EOPNOTSUPP, and a VLAN
/// EtherType mask other than full is -EOPNOTSUPP. `FLOW_MAC_EXT` is
/// not accepted: Linux igc requires `flow_type & ~FLOW_EXT` to be
/// exactly `ETHER_FLOW`. A rule with no match field at all and a plain
/// `ETHER_FLOW` type is the wildcard/default-queue rule; the same
/// empty rule with `FLOW_EXT` set is -EINVAL (Linux
/// `igc_ethtool_check_nfc_rule`: a rule with no match).
fn decode_rule(b: &[u8]) -> nic::Result<nic::FlowRule> {
    let flow = get(b, 16);
    if flow & !0x80000000 != 0x12 {
        return Err(95);
    }
    let cookie = u64::from_ne_bytes(b[168..176].try_into().unwrap());
    let queue = u16::try_from(cookie).map_err(|_| 22)?;
    let mut r = nic::FlowRule {
        location: u16::try_from(get(b, 176)).map_err(|_| 22)?,
        queue,
        ethertype: None,
        destination_mac: None,
        source_mac: None,
        vlan_priority: None,
        vlan_etype: None,
        vlan_tci: None,
        user_data: None,
        user_mask: None,
        default_queue: false,
    };
    // Masks with no Linux-igc meaning: the ether_spec union tail, the
    // flow-ext padding, and the flow-ext destination MAC (FLOW_MAC_EXT
    // is not a Linux-igc match).
    if b[106..144].iter().any(|v| *v != 0)
        || b[144..146].iter().any(|v| *v != 0)
        || b[146..152].iter().any(|v| *v != 0)
    {
        return Err(95);
    }
    if b[92..98].iter().any(|v| *v != 0) {
        if b[92..98] != [255; 6] {
            return Err(95);
        }
        r.destination_mac = Some(b[20..26].try_into().unwrap());
    }
    if b[98..104].iter().any(|v| *v != 0) {
        if b[98..104] != [255; 6] {
            return Err(95);
        }
        r.source_mac = Some(b[26..32].try_into().unwrap());
    }
    if b[104..106] != [0; 2] {
        if b[104..106] != [255; 2] {
            return Err(95);
        }
        r.ethertype = Some(u16::from_be_bytes(b[32..34].try_into().unwrap()));
    }
    if flow & 0x80000000 != 0 {
        // VLAN EtherType: Linux keys the match on a nonzero value and
        // requires a full mask when one is given.
        if b[152..154] != [0; 2] && b[152..154] != [255; 2] {
            return Err(95);
        }
        if b[80..82] != [0; 2] {
            r.vlan_etype = Some(u16::from_be_bytes(b[80..82].try_into().unwrap()));
        }
        // VLAN TCI: Linux accepts only the priority mask (0xe000) and
        // the full mask (0xffff). A nonzero value with a zero mask
        // behaves as a priority match, as in Linux (the stored TCI
        // feeds the VLAN-priority filter).
        let tci = u16::from_be_bytes(b[82..84].try_into().unwrap());
        match b[154..156] {
            [0, 0] => {
                if tci != 0 {
                    r.vlan_priority = Some((tci >> 13) as u8);
                }
            }
            [0xe0, 0] => r.vlan_priority = Some((tci >> 13) as u8),
            [0xff, 0xff] => r.vlan_tci = Some(tci),
            _ => return Err(95),
        }
        // User data: Linux sets the flag only when either data word is
        // nonzero; the mask rides along verbatim.
        let data: [u8; 8] = b[84..92].try_into().unwrap();
        if data.iter().any(|v| *v != 0) {
            r.user_data = Some(data);
            r.user_mask = Some(b[156..164].try_into().unwrap());
        }
    }
    if r.ethertype.is_none()
        && r.destination_mac.is_none()
        && r.source_mac.is_none()
        && r.vlan_priority.is_none()
        && r.vlan_etype.is_none()
        && r.vlan_tci.is_none()
        && r.user_data.is_none()
    {
        if flow == 0x12 {
            r.default_queue = true;
        } else {
            return Err(22);
        }
    }
    Ok(r)
}
/// Linux `igc_ethtool_get_nfc_rule` (igc_ethtool.c:963-1021): FLOW_EXT
/// is set for VLAN EtherType, VLAN TCI (including the priority-only
/// form) and user data; masks are written full. A default-queue rule
/// encodes as a plain `ETHER_FLOW` with zero masks.
fn encode_rule(b: &mut [u8], r: &nic::FlowRule) {
    b[16..184].fill(0);
    put(
        b,
        16,
        0x12 | if r.vlan_priority.is_some()
            || r.vlan_tci.is_some()
            || r.vlan_etype.is_some()
            || r.user_data.is_some()
        {
            0x80000000
        } else {
            0
        },
    );
    put64(b, 168, u64::from(r.queue));
    put(b, 176, u32::from(r.location));
    if let Some(mac) = r.destination_mac {
        b[20..26].copy_from_slice(&mac);
        b[92..98].fill(255);
    }
    if let Some(mac) = r.source_mac {
        b[26..32].copy_from_slice(&mac);
        b[98..104].fill(255);
    }
    if let Some(t) = r.ethertype {
        b[32..34].copy_from_slice(&t.to_be_bytes());
        b[104..106].fill(255);
    }
    if let Some(t) = r.vlan_etype {
        b[80..82].copy_from_slice(&t.to_be_bytes());
        b[152..154].fill(255);
    }
    if let Some(p) = r.vlan_priority {
        b[82..84].copy_from_slice(&(u16::from(p) << 13).to_be_bytes());
        b[154..156].copy_from_slice(&[0xe0, 0]);
    }
    if let Some(t) = r.vlan_tci {
        b[82..84].copy_from_slice(&t.to_be_bytes());
        b[154..156].fill(255);
    }
    if let Some(data) = r.user_data {
        b[84..92].copy_from_slice(&data);
        // No mask stored means "match all eight bytes".
        b[156..164].copy_from_slice(&r.user_mask.unwrap_or([0xff; 8]));
    }
}

// ── Generic Netlink "ethtool" MAC Merge (802.3br / 802.1Qbu) ───────────

pub const GENL_ID_ETHTOOL: u16 = 0x14;
pub const ETHTOOL_GENL_NAME: &str = "ethtool";
pub const ETHTOOL_GENL_VERSION: u8 = 1;

pub const ETHTOOL_MSG_MM_GET: u8 = 42;
pub const ETHTOOL_MSG_MM_SET: u8 = 43;
pub const ETHTOOL_MSG_MM_GET_REPLY: u8 = 42;

pub const ETHTOOL_A_HEADER_DEV_INDEX: u16 = 1;
pub const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;
pub const ETHTOOL_A_HEADER_FLAGS: u16 = 3;

pub const ETHTOOL_FLAG_STATS: u32 = 1 << 2;

pub const ETHTOOL_A_MM_HEADER: u16 = 1;
pub const ETHTOOL_A_MM_PMAC_ENABLED: u16 = 2;
pub const ETHTOOL_A_MM_TX_ENABLED: u16 = 3;
pub const ETHTOOL_A_MM_TX_ACTIVE: u16 = 4;
pub const ETHTOOL_A_MM_TX_MIN_FRAG_SIZE: u16 = 5;
pub const ETHTOOL_A_MM_RX_MIN_FRAG_SIZE: u16 = 6;
pub const ETHTOOL_A_MM_VERIFY_ENABLED: u16 = 7;
pub const ETHTOOL_A_MM_VERIFY_STATUS: u16 = 8;
pub const ETHTOOL_A_MM_VERIFY_TIME: u16 = 9;
pub const ETHTOOL_A_MM_MAX_VERIFY_TIME: u16 = 10;
pub const ETHTOOL_A_MM_STATS: u16 = 11;

pub const ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS: u16 = 2;
pub const ETHTOOL_A_MM_STAT_SMD_ERRORS: u16 = 3;
pub const ETHTOOL_A_MM_STAT_REASSEMBLY_OK: u16 = 4;
pub const ETHTOOL_A_MM_STAT_RX_FRAG_COUNT: u16 = 5;
pub const ETHTOOL_A_MM_STAT_TX_FRAG_COUNT: u16 = 6;

pub const ETHTOOL_MM_VERIFY_STATUS_INITIAL: u8 = 0;
pub const ETHTOOL_MM_VERIFY_STATUS_VERIFYING: u8 = 1;
pub const ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED: u8 = 2;
pub const ETHTOOL_MM_VERIFY_STATUS_FAILED: u8 = 3;
pub const ETHTOOL_MM_VERIFY_STATUS_DISABLED: u8 = 4;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(3 << 14);

static ETHTOOL_GENL_OPS: &[crate::netlink_generic::GenlOperation] = genl::OPS;

fn unsupported_genl(
    _: u8,
    _: &[u8],
    _: bool,
) -> Result<alloc::vec::Vec<crate::netlink_generic::GenlReply>, i32> {
    Err(95)
}

pub fn ensure_genl_registered() {
    let _ = crate::netlink_generic::register_family(crate::netlink_generic::GenlFamily {
        id: GENL_ID_ETHTOOL,
        name: ETHTOOL_GENL_NAME,
        version: ETHTOOL_GENL_VERSION,
        max_attr: 11,
        operations: ETHTOOL_GENL_OPS,
        groups: &[],
        handler: unsupported_genl,
    });
    let _ = crate::netlink_generic::register_context_handler(GENL_ID_ETHTOOL, handle_genl);
}

fn push_nla(body: &mut alloc::vec::Vec<u8>, kind: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    body.extend_from_slice(&len.to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    let aligned = (body.len() + 3) & !3;
    body.resize(aligned, 0);
}

fn walk_nla<'a>(
    raw: &'a [u8],
    mut f: impl FnMut(u16, &'a [u8]) -> Result<(), i32>,
) -> Result<(), i32> {
    let mut off = 0usize;
    while off < raw.len() {
        if off + 4 > raw.len() {
            return Err(22);
        }
        let len = u16::from_ne_bytes(raw[off..off + 2].try_into().map_err(|_| 22)?) as usize;
        let kind =
            u16::from_ne_bytes(raw[off + 2..off + 4].try_into().map_err(|_| 22)?) & NLA_TYPE_MASK;
        if len < 4 || off + len > raw.len() {
            return Err(22);
        }
        f(kind, &raw[off + 4..off + len])?;
        off = off.saturating_add((len + 3) & !3);
    }
    Ok(())
}

fn parse_header_dev(raw: &[u8], net_ns_id: u64) -> Result<(u32, alloc::string::String, u32), i32> {
    let mut dev_index: Option<u32> = None;
    let mut dev_name: Option<alloc::string::String> = None;
    let mut flags: u32 = 0;
    walk_nla(raw, |kind, payload| {
        match kind {
            ETHTOOL_A_HEADER_DEV_INDEX => {
                if payload.len() != 4 {
                    return Err(22);
                }
                dev_index = Some(u32::from_ne_bytes(payload.try_into().map_err(|_| 22)?));
            }
            ETHTOOL_A_HEADER_DEV_NAME => {
                let trimmed = payload.strip_suffix(&[0]).unwrap_or(payload);
                let s = core::str::from_utf8(trimmed).map_err(|_| 22)?;
                if s.is_empty() {
                    return Err(22);
                }
                dev_name = Some(alloc::string::String::from(s));
            }
            ETHTOOL_A_HEADER_FLAGS => {
                if payload.len() != 4 {
                    return Err(22);
                }
                flags = u32::from_ne_bytes(payload.try_into().map_err(|_| 22)?);
            }
            _ => return Err(22),
        }
        Ok(())
    })?;
    if let Some(ifindex) = dev_index {
        let name = crate::netlink_route::iface_name_for_index(ifindex).ok_or(19)?;
        if name != "lo" && crate::iface::lookup_in(net_ns_id, &name).is_none() {
            return Err(19);
        }
        return Ok((ifindex, name, flags));
    }
    if let Some(name) = dev_name {
        if name != "lo" && crate::iface::lookup_in(net_ns_id, &name).is_none() {
            return Err(19);
        }
        let ifindex = crate::netlink_route::ifindex_for_name(&name).ok_or(19)?;
        return Ok((ifindex, name, flags));
    }
    Err(22)
}

/// Request-header flags for a dump, where the device spec is ignored.
/// Returns 0 when the header is absent.
fn header_flags(raw: Option<&[u8]>) -> Result<u32, i32> {
    let Some(raw) = raw else {
        return Ok(0);
    };
    let mut flags: u32 = 0;
    walk_nla(raw, |kind, payload| {
        if kind == ETHTOOL_A_HEADER_FLAGS {
            if payload.len() != 4 {
                return Err(22);
            }
            flags = u32::from_ne_bytes(payload.try_into().map_err(|_| 22)?);
        }
        Ok(())
    })?;
    Ok(flags)
}

fn encode_mm_reply(
    ifindex: u32,
    name: &str,
    cfg: nic::Preemption,
    status: nic::PreemptionStatus,
    stats: Option<nic::MmStats>,
) -> crate::netlink_generic::GenlReply {
    let mut hdr = alloc::vec::Vec::new();
    push_nla(&mut hdr, ETHTOOL_A_HEADER_DEV_INDEX, &ifindex.to_ne_bytes());
    let mut name_bytes = name.as_bytes().to_vec();
    name_bytes.push(0);
    push_nla(&mut hdr, ETHTOOL_A_HEADER_DEV_NAME, &name_bytes);

    let verify_status = if !cfg.verify {
        ETHTOOL_MM_VERIFY_STATUS_DISABLED
    } else if status.verified {
        ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED
    } else if status.failed {
        ETHTOOL_MM_VERIFY_STATUS_FAILED
    } else if status.attempts > 0 {
        ETHTOOL_MM_VERIFY_STATUS_VERIFYING
    } else {
        ETHTOOL_MM_VERIFY_STATUS_INITIAL
    };

    let mut attrs = alloc::vec::Vec::new();
    push_nla(&mut attrs, ETHTOOL_A_MM_HEADER | NLA_F_NESTED, &hdr);
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_PMAC_ENABLED,
        &[u8::from(cfg.enabled)],
    );
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_TX_ENABLED,
        &[u8::from(cfg.tx_enabled)],
    );
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_TX_ACTIVE,
        &[u8::from(status.active)],
    );
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_TX_MIN_FRAG_SIZE,
        &u32::from(cfg.minimum_fragment).to_ne_bytes(),
    );
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_RX_MIN_FRAG_SIZE,
        // Linux IGC_RX_MIN_FRAG_SIZE (igc_tsn.h).
        &60u32.to_ne_bytes(),
    );
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_VERIFY_ENABLED,
        &[u8::from(cfg.verify)],
    );
    push_nla(&mut attrs, ETHTOOL_A_MM_VERIFY_STATUS, &[verify_status]);
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_VERIFY_TIME,
        &u32::from(cfg.verify_ms).to_ne_bytes(),
    );
    push_nla(
        &mut attrs,
        ETHTOOL_A_MM_MAX_VERIFY_TIME,
        &128u32.to_ne_bytes(),
    );
    // Linux igc reports the five MACMerge counters only when the request
    // asked for stats; HOLD_COUNT is not reported by igc.
    if let Some(stats) = stats {
        let mut nest = alloc::vec::Vec::new();
        push_nla(
            &mut nest,
            ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS,
            &stats.reassembly_errors.to_ne_bytes(),
        );
        push_nla(
            &mut nest,
            ETHTOOL_A_MM_STAT_SMD_ERRORS,
            &stats.smd_errors.to_ne_bytes(),
        );
        push_nla(
            &mut nest,
            ETHTOOL_A_MM_STAT_REASSEMBLY_OK,
            &stats.reassembly_ok.to_ne_bytes(),
        );
        push_nla(
            &mut nest,
            ETHTOOL_A_MM_STAT_RX_FRAG_COUNT,
            &stats.rx_frag_count.to_ne_bytes(),
        );
        push_nla(
            &mut nest,
            ETHTOOL_A_MM_STAT_TX_FRAG_COUNT,
            &stats.tx_frag_count.to_ne_bytes(),
        );
        push_nla(&mut attrs, ETHTOOL_A_MM_STATS | NLA_F_NESTED, &nest);
    }
    crate::netlink_generic::GenlReply {
        command: ETHTOOL_MSG_MM_GET_REPLY,
        attrs,
    }
}

pub(crate) fn handle_genl(
    command: u8,
    attrs: &[u8],
    dump: bool,
    context: crate::netlink_generic::RequestContext<'_>,
) -> Result<alloc::vec::Vec<crate::netlink_generic::GenlReply>, i32> {
    if command < ETHTOOL_MSG_MM_GET {
        return genl::handle(command, attrs, dump, context);
    }
    match command {
        ETHTOOL_MSG_MM_GET => {
            let mut header_raw: Option<&[u8]> = None;
            walk_nla(attrs, |kind, payload| {
                if kind == ETHTOOL_A_MM_HEADER {
                    header_raw = Some(payload);
                    Ok(())
                } else {
                    Err(22)
                }
            })?;
            if dump {
                let flags = header_flags(header_raw)?;
                let mut out = alloc::vec::Vec::new();
                for snap in crate::iface::snapshot_all() {
                    if snap.net_ns_id != context.net_ns_id {
                        continue;
                    }
                    if let Ok((cfg, status)) = nic::with_control(&snap.name, |d| d.preemption()) {
                        let stats = if flags & ETHTOOL_FLAG_STATS != 0 {
                            nic::with_control(&snap.name, |d| d.mm_stats()).ok()
                        } else {
                            None
                        };
                        out.push(encode_mm_reply(
                            snap.ifindex,
                            &snap.name,
                            cfg,
                            status,
                            stats,
                        ));
                    }
                }
                return Ok(out);
            }
            let (ifindex, name, flags) =
                parse_header_dev(header_raw.ok_or(22)?, context.net_ns_id)?;
            let (cfg, status) = nic::with_control(&name, |d| d.preemption())?;
            let stats = if flags & ETHTOOL_FLAG_STATS != 0 {
                nic::with_control(&name, |d| d.mm_stats()).ok()
            } else {
                None
            };
            Ok(alloc::vec![encode_mm_reply(
                ifindex, &name, cfg, status, stats,
            )])
        }
        ETHTOOL_MSG_MM_SET => {
            let mut header_raw: Option<&[u8]> = None;
            let mut pmac_enabled: Option<bool> = None;
            let mut tx_enabled: Option<bool> = None;
            let mut verify_enabled: Option<bool> = None;
            let mut verify_time: Option<u8> = None;
            let mut min_frag: Option<u16> = None;

            walk_nla(attrs, |kind, payload| {
                match kind {
                    ETHTOOL_A_MM_HEADER => header_raw = Some(payload),
                    ETHTOOL_A_MM_PMAC_ENABLED => {
                        if payload.len() != 1 || payload[0] > 1 {
                            return Err(22);
                        }
                        pmac_enabled = Some(payload[0] != 0);
                    }
                    ETHTOOL_A_MM_TX_ENABLED => {
                        if payload.len() != 1 || payload[0] > 1 {
                            return Err(22);
                        }
                        tx_enabled = Some(payload[0] != 0);
                    }
                    ETHTOOL_A_MM_VERIFY_ENABLED => {
                        if payload.len() != 1 || payload[0] > 1 {
                            return Err(22);
                        }
                        verify_enabled = Some(payload[0] != 0);
                    }
                    ETHTOOL_A_MM_VERIFY_TIME => {
                        if payload.len() != 4 {
                            return Err(22);
                        }
                        let v = u32::from_ne_bytes(payload.try_into().map_err(|_| 22)?);
                        verify_time = Some(u8::try_from(v).map_err(|_| 22)?);
                    }
                    ETHTOOL_A_MM_TX_MIN_FRAG_SIZE => {
                        if payload.len() != 4 {
                            return Err(22);
                        }
                        let v = u32::from_ne_bytes(payload.try_into().map_err(|_| 22)?);
                        // Linux `ethnl_mm_set_policy` (net/ethtool/mm.c):
                        // NLA_POLICY_RANGE(NLA_U32, 60, 252). The driver
                        // then rounds the surviving value up to a
                        // supported size (see `set_preemption`).
                        if !(60..=252).contains(&v) {
                            return Err(22);
                        }
                        min_frag = Some(u16::try_from(v).map_err(|_| 22)?);
                    }
                    _ => return Err(22),
                }
                Ok(())
            })?;
            let (_ifindex, name, _) = parse_header_dev(header_raw.ok_or(22)?, context.net_ns_id)?;
            if !context.capable {
                let admin = context.admin.ok_or(1)?;
                admin
                    .authorize_interface(&name, context.net_ns_id)
                    .map_err(|_| 1)?;
            }
            let (mut cfg, _) = nic::with_control(&name, |d| d.preemption())?;
            if let Some(v) = pmac_enabled {
                cfg.enabled = v;
            }
            if let Some(v) = tx_enabled {
                cfg.tx_enabled = v;
            }
            if let Some(v) = verify_enabled {
                cfg.verify = v;
            }
            if let Some(v) = verify_time {
                cfg.verify_ms = v;
            }
            if let Some(v) = min_frag {
                cfg.minimum_fragment = v;
            }
            nic::with_control(&name, |d| d.set_preemption(cfg))?;
            Ok(alloc::vec::Vec::new())
        }
        _ => Err(95),
    }
}
