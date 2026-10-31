//! Linux ethtool ioctl wire codec. All user access and CAP_NET_ADMIN checks
//! remain in userspace/; this bounded codec calls native device controls.
use crate::nic::{self, LinkSettings, Pause};

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
        0x0b => 16,
        0x09 => 4,
        0x0e | 0x0f => 92,
        0x10 | 0x11 | 0x3c | 0x3d => 36,
        0x12 | 0x13 => 16,
        0x14 | 0x16 | 0x18 | 0x1e | 0x23 | 0x2b | 0x2d => 8,
        0x1b => 12,
        0x1d => 8,
        0x1a => 16,
        0x2e..=0x32 => 192,
        0x37 => 16,
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
        0x0b => get(header, 12) as usize,
        0x1b => (get(header, 8) as usize).checked_mul(32).ok_or(22)?,
        0x1d => (get(header, 4) as usize).checked_mul(8).ok_or(22)?,
        0x1a => (get(header, 12) as usize).checked_mul(8).ok_or(22)?,
        0x37 => {
            (u64::from_ne_bytes(header[8..16].try_into().unwrap()) & 3).count_ones() as usize * 4
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
                put(b, 4, 1);
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
            0x2e..=0x32 => {
                let mut rules = driver.flow_rules()?;
                let location = get(b, 176);
                match cmd {
                    0x2e => {
                        put(b, 184, rules.len() as u32);
                        put64(b, 8, 32);
                    }
                    0x30 => {
                        let capacity = get(b, 184) as usize;
                        if capacity < rules.len() {
                            return Err(90);
                        }
                        put64(b, 8, 32);
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
                        encode_rule(b, r);
                    }
                    0x32 => {
                        if get(b, 176) == u32::MAX {
                            let location = (0..32)
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
            0x09 => return driver.restart_link(),
            0x1b | 0x1d | 0x37 => {
                if cmd == 0x1b && get(b, 4) == 0 {
                    let diagnostics = driver.diagnostics(false)?;
                    let requested = get(b, 8) as usize;
                    if requested != 0 && requested < diagnostics.len() {
                        return Err(22);
                    }
                    put(b, 8, diagnostics.len() as u32);
                    for (i, d) in diagnostics.iter().take(requested).enumerate() {
                        let name = d.name.as_bytes();
                        let n = name.len().min(31);
                        b[12 + i * 32..12 + i * 32 + n].copy_from_slice(&name[..n]);
                    }
                    return Ok(());
                }
                let stats = driver.statistics()?;
                let count = stats.len() as u32;
                if cmd == 0x37 {
                    let mask = u64::from_ne_bytes(b[8..16].try_into().unwrap());
                    put64(b, 8, mask & 3);
                    let mut at = 16;
                    if mask & 1 != 0 {
                        put(b, at, driver.diagnostics(false)?.len() as u32);
                        at += 4;
                    }
                    if mask & 2 != 0 {
                        put(b, at, count);
                    }
                    return Ok(());
                }
                let requested = get(b, if cmd == 0x1b { 8 } else { 4 });
                if requested != 0 && requested < count {
                    return Err(22);
                }
                if cmd == 0x1b {
                    if get(b, 4) != 1 {
                        return Err(95);
                    }
                    put(b, 8, count);
                    for (i, s) in stats.iter().take(requested as usize).enumerate() {
                        let text = s.name.as_bytes();
                        let n = text.len().min(31);
                        b[12 + i * 32..12 + i * 32 + n].copy_from_slice(&text[..n]);
                    }
                } else {
                    put(b, 4, count);
                    for (i, s) in stats.iter().take(requested as usize).enumerate() {
                        put64(b, 8 + i * 8, s.value);
                    }
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
                put(b, 4, (1 << 0) | (1 << 2) | (1 << 6));
                put(b, 8, driver.clock_index() as u32);
                put(b, 12, 3);
                put(b, 28, 3);
                return Ok(());
            }
            0x14 | 0x16 | 0x18 | 0x1e | 0x23 | 0x2b | 0x2d => {
                let iface = crate::iface::lookup(name).ok_or(19)?;
                let value = match cmd {
                    0x14 => u32::from(iface.offloads.rx_checksum),
                    0x16 => u32::from(iface.offloads.tx_checksum),
                    0x1e | 0x23 => u32::from(iface.offloads.max_tso_bytes > 0),
                    0x2b => u32::from(iface.software_gro),
                    0x2d => u32::from(driver.settings()?.channels),
                    _ => 1,
                };
                put(b, 4, value);
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
                if get(b, 4) != get(b, 20)
                    || (8..92)
                        .step_by(4)
                        .filter(|i| *i != 20)
                        .any(|i| get(b, i) != 0)
                {
                    return Err(95);
                }
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
                put(b, 16, 4);
                put(b, 32, u32::from(s.channels));
            }
            0x3d => {
                if [20, 24, 28].iter().any(|i| get(b, *i) != 0) {
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
                s.eee = get(b, 20) != 0;
                changed = true;
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
                    b[15] = (-2i8) as u8;
                    return Ok(());
                }
                if cmd == 0x4c {
                    let link = crate::iface::lookup(name).ok_or(19)?;
                    put(b, 4, link.speed_mbps.unwrap_or(u32::MAX));
                    b[8] = u8::from(link.duplex == Some(crate::iface::LinkDuplex::Full));
                    b[11] = u8::from(s.link.autoneg);
                    put(
                        b,
                        48,
                        legacy_modes(driver.supported_link_modes()) | (1 << 6),
                    );
                    put(
                        b,
                        52,
                        if driver.supported_link_modes() & 0x20 != 0 {
                            1 << 15
                        } else {
                            0
                        },
                    );
                    put(b, 56, legacy_modes(s.link.advertised));
                    put(
                        b,
                        60,
                        if s.link.advertised & 0x20 != 0 {
                            1 << 15
                        } else {
                            0
                        },
                    );
                    put(b, 64, 0);
                    put(b, 68, 0);
                } else {
                    if get(b, 60) & !(1 << 15) != 0 {
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
        vlan_priority: None,
    };
    // Ethernet union starts at 20/92. Source matching, partial masks and
    // user-defined extension data have no equivalent in IGC's hardware filters.
    if b[98..104].iter().any(|v| *v != 0)
        || b[106..144].iter().any(|v| *v != 0)
        || b[144..154].iter().any(|v| *v != 0)
        || b[156..164].iter().any(|v| *v != 0)
    {
        return Err(95);
    }
    if b[92..98].iter().any(|v| *v != 0) {
        if b[92..98] != [255; 6] {
            return Err(95);
        }
        r.destination_mac = Some(b[20..26].try_into().unwrap());
    }
    if b[104..106] != [0; 2] {
        if b[104..106] != [255; 2] {
            return Err(95);
        }
        r.ethertype = Some(u16::from_be_bytes(b[32..34].try_into().unwrap()));
    }
    if flow & 0x80000000 != 0 && b[154..156] != [0; 2] {
        if b[154..156] != [0xe0, 0] {
            return Err(95);
        }
        r.vlan_priority = Some((u16::from_be_bytes(b[82..84].try_into().unwrap()) >> 13) as u8);
    }
    Ok(r)
}
fn encode_rule(b: &mut [u8], r: &nic::FlowRule) {
    b[16..184].fill(0);
    put(
        b,
        16,
        0x12 | if r.vlan_priority.is_some() {
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
    if let Some(t) = r.ethertype {
        b[32..34].copy_from_slice(&t.to_be_bytes());
        b[104..106].fill(255);
    }
    if let Some(p) = r.vlan_priority {
        b[82..84].copy_from_slice(&(u16::from(p) << 13).to_be_bytes());
        b[154..156].copy_from_slice(&[0xe0, 0]);
    }
}

// ── Generic Netlink "ethtool" MAC Merge (802.3br / 802.1Qbu) ───────────

pub const GENL_ID_ETHTOOL: u16 = 0x14;
pub const ETHTOOL_GENL_NAME: &str = "ethtool";
pub const ETHTOOL_GENL_VERSION: u8 = 1;

pub const ETHTOOL_MSG_MM_GET: u8 = 35;
pub const ETHTOOL_MSG_MM_SET: u8 = 36;
pub const ETHTOOL_MSG_MM_GET_REPLY: u8 = 44;

pub const ETHTOOL_A_HEADER_DEV_INDEX: u16 = 1;
pub const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;
pub const ETHTOOL_A_HEADER_FLAGS: u16 = 3;

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

pub const ETHTOOL_MM_VERIFY_STATUS_INITIAL: u8 = 0;
pub const ETHTOOL_MM_VERIFY_STATUS_VERIFYING: u8 = 1;
pub const ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED: u8 = 2;
pub const ETHTOOL_MM_VERIFY_STATUS_FAILED: u8 = 3;
pub const ETHTOOL_MM_VERIFY_STATUS_DISABLED: u8 = 4;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(3 << 14);

static ETHTOOL_GENL_OPS: &[crate::netlink_generic::GenlOperation] = &[
    crate::netlink_generic::GenlOperation {
        command: ETHTOOL_MSG_MM_GET,
        flags: 0x02 | 0x04, // GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP
    },
    crate::netlink_generic::GenlOperation {
        command: ETHTOOL_MSG_MM_SET,
        flags: 0x02 | crate::netlink_generic::GENL_UNS_ADMIN_PERM,
    },
];

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

fn parse_header_dev(raw: &[u8], net_ns_id: u64) -> Result<(u32, alloc::string::String), i32> {
    let mut dev_index: Option<u32> = None;
    let mut dev_name: Option<alloc::string::String> = None;
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
        return Ok((ifindex, name));
    }
    if let Some(name) = dev_name {
        if name != "lo" && crate::iface::lookup_in(net_ns_id, &name).is_none() {
            return Err(19);
        }
        let ifindex = crate::netlink_route::ifindex_for_name(&name).ok_or(19)?;
        return Ok((ifindex, name));
    }
    Err(22)
}

fn encode_mm_reply(
    ifindex: u32,
    name: &str,
    cfg: nic::Preemption,
    status: nic::PreemptionStatus,
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
        &64u32.to_ne_bytes(),
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
    crate::netlink_generic::GenlReply {
        command: ETHTOOL_MSG_MM_GET_REPLY,
        attrs,
    }
}

fn handle_genl(
    command: u8,
    attrs: &[u8],
    dump: bool,
    context: crate::netlink_generic::RequestContext<'_>,
) -> Result<alloc::vec::Vec<crate::netlink_generic::GenlReply>, i32> {
    match command {
        ETHTOOL_MSG_MM_GET => {
            if dump {
                let mut out = alloc::vec::Vec::new();
                for snap in crate::iface::snapshot_all() {
                    if snap.net_ns_id != context.net_ns_id {
                        continue;
                    }
                    if let Ok((cfg, status)) = nic::with_control(&snap.name, |d| d.preemption()) {
                        out.push(encode_mm_reply(snap.ifindex, &snap.name, cfg, status));
                    }
                }
                return Ok(out);
            }
            let mut header_raw: Option<&[u8]> = None;
            walk_nla(attrs, |kind, payload| {
                if kind == ETHTOOL_A_MM_HEADER {
                    header_raw = Some(payload);
                    Ok(())
                } else {
                    Err(22)
                }
            })?;
            let (ifindex, name) = parse_header_dev(header_raw.ok_or(22)?, context.net_ns_id)?;
            let (cfg, status) = nic::with_control(&name, |d| d.preemption())?;
            Ok(alloc::vec![encode_mm_reply(ifindex, &name, cfg, status)])
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
                        min_frag = Some(u16::try_from(v).map_err(|_| 22)?);
                    }
                    _ => return Err(22),
                }
                Ok(())
            })?;
            let (_ifindex, name) = parse_header_dev(header_raw.ok_or(22)?, context.net_ns_id)?;
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
