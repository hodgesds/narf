//! Linux ethtool Generic Netlink adapters for the native control surface.
use super::*;
use crate::netlink_generic::{GenlOperation, GenlReply, RequestContext, GENL_UNS_ADMIN_PERM};
use alloc::{vec, vec::Vec};

pub(super) const OPS: &[GenlOperation] = &[
    GenlOperation {
        command: 1,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 2,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 4,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 5,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 6,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 7,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 8,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 9,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 10,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 11,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 12,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 13,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 14,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 15,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 16,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 17,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 18,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 19,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 20,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 21,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 22,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 23,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 24,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 25,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 42,
        flags: 0x02 | 0x04,
    },
    GenlOperation {
        command: 43,
        flags: 0x02 | GENL_UNS_ADMIN_PERM,
    },
];
pub(super) fn global_strings(id: u32) -> Option<&'static [&'static str]> {
    Some(match id {
        9 => &[
            "10baseT/Half",
            "10baseT/Full",
            "100baseT/Half",
            "100baseT/Full",
            "1000baseT/Half",
            "1000baseT/Full",
            "Autoneg",
            "TP",
            "AUI",
            "MII",
            "FIBRE",
            "BNC",
            "10000baseT/Full",
            "Pause",
            "Asym_Pause",
            "2500baseX/Full",
            "Backplane",
            "1000baseKX/Full",
            "10000baseKX4/Full",
            "10000baseKR/Full",
            "10000baseR_FEC",
            "20000baseMLD2/Full",
            "20000baseKR2/Full",
            "40000baseKR4/Full",
            "40000baseCR4/Full",
            "40000baseSR4/Full",
            "40000baseLR4/Full",
            "56000baseKR4/Full",
            "56000baseCR4/Full",
            "56000baseSR4/Full",
            "56000baseLR4/Full",
            "25000baseCR/Full",
            "25000baseKR/Full",
            "25000baseSR/Full",
            "50000baseCR2/Full",
            "50000baseKR2/Full",
            "100000baseKR4/Full",
            "100000baseSR4/Full",
            "100000baseCR4/Full",
            "100000baseLR4_ER4/Full",
            "50000baseSR2/Full",
            "1000baseX/Full",
            "10000baseCR/Full",
            "10000baseSR/Full",
            "10000baseLR/Full",
            "10000baseLRM/Full",
            "10000baseER/Full",
            "2500baseT/Full",
            "5000baseT/Full",
            "None",
            "RS",
            "BASER",
            "50000baseKR/Full",
            "50000baseSR/Full",
            "50000baseCR/Full",
            "50000baseLR_ER_FR/Full",
            "50000baseDR/Full",
            "100000baseKR2/Full",
            "100000baseSR2/Full",
            "100000baseCR2/Full",
            "100000baseLR2_ER2_FR2/Full",
            "100000baseDR2/Full",
            "200000baseKR4/Full",
            "200000baseSR4/Full",
        ],
        10 => &[
            "drv",
            "probe",
            "link",
            "timer",
            "ifdown",
            "ifup",
            "rx_err",
            "tx_err",
            "tx_queued",
            "intr",
            "tx_done",
            "rx_status",
            "pktdata",
            "hw",
            "wol",
        ],
        11 => &[
            "phy",
            "ucast",
            "mcast",
            "bcast",
            "arp",
            "magic",
            "magicsecure",
            "filter",
        ],
        12 => &[
            "hardware-transmit",
            "software-transmit",
            "hardware-receive",
            "software-receive",
            "software-system-clock",
            "hardware-legacy-clock",
            "hardware-raw-clock",
            "option-id",
            "sched-transmit",
            "ack-transmit",
            "option-cmsg",
            "option-tsonly",
            "option-stats",
            "option-pktinfo",
            "option-tx-swhw",
            "bind-phc",
            "option-id-tcp",
            "option-rx-filter",
            "tx-completion",
        ],
        13 => &["off", "on", "onestep-sync", "onestep-p2p"],
        14 => &[
            "none",
            "all",
            "some",
            "ptpv1-l4-event",
            "ptpv1-l4-sync",
            "ptpv1-l4-delay-req",
            "ptpv2-l4-event",
            "ptpv2-l4-sync",
            "ptpv2-l4-delay-req",
            "ptpv2-l2-event",
            "ptpv2-l2-sync",
            "ptpv2-l2-delay-req",
            "ptpv2-event",
            "ptpv2-sync",
            "ptpv2-delay-req",
            "ntp-all",
        ],
        _ => return None,
    })
}
fn u32_value(p: &[u8]) -> Result<u32, i32> {
    Ok(u32::from_ne_bytes(p.try_into().map_err(|_| 22)?))
}
fn low_mask(n: usize) -> u64 {
    if n == 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}
fn bitset(
    out: &mut Vec<u8>,
    kind: u16,
    value: u64,
    mask: Option<u64>,
    names: &[&str],
    compact: bool,
) {
    let value = value & low_mask(names.len());
    let mask = mask.map(|m| m & low_mask(names.len()));
    let mut nest = Vec::new();
    if mask.is_none() {
        push_nla(&mut nest, 1, &[]);
    }
    push_nla(&mut nest, 2, &(names.len() as u32).to_ne_bytes());
    if compact {
        let bytes = names.len().div_ceil(32) * 4;
        push_nla(&mut nest, 4, &value.to_ne_bytes()[..bytes]);
        if let Some(m) = mask {
            push_nla(&mut nest, 5, &m.to_ne_bytes()[..bytes]);
        }
    } else {
        let mut bits = Vec::new();
        for (i, name) in names.iter().enumerate() {
            if mask.unwrap_or(value) & (1u64 << i) == 0 {
                continue;
            }
            let mut bit = Vec::new();
            push_nla(&mut bit, 1, &(i as u32).to_ne_bytes());
            if !name.is_empty() {
                let mut text = name.as_bytes().to_vec();
                text.push(0);
                push_nla(&mut bit, 2, &text);
            }
            if value & (1u64 << i) != 0 {
                push_nla(&mut bit, 3, &[]);
            }
            push_nla(&mut bits, 1 | NLA_F_NESTED, &bit);
        }
        push_nla(&mut nest, 3 | NLA_F_NESTED, &bits);
    }
    push_nla(out, kind | NLA_F_NESTED, &nest);
}
fn parse_bitset(raw: &[u8], names: &[&str]) -> Result<(u64, u64), i32> {
    let mut attrs = [None; 6];
    walk_nla(raw, |k, p| {
        let slot = attrs.get_mut(k as usize).filter(|_| k != 0).ok_or(22)?;
        if slot.replace(p).is_some() {
            return Err(22);
        }
        Ok(())
    })?;
    if attrs[1].is_some_and(|p| !p.is_empty()) {
        return Err(22);
    }
    let nomask = attrs[1].is_some();
    let size = attrs[2]
        .map(u32_value)
        .transpose()?
        .unwrap_or(names.len() as u32) as usize;
    if size > names.len() {
        return Err(22);
    }
    let mut value = 0u64;
    let mut mask = 0u64;
    if let Some(bits) = attrs[3] {
        if attrs[4].is_some() || attrs[5].is_some() {
            return Err(22);
        }
        walk_nla(bits, |k, p| {
            if k != 1 {
                return Err(22);
            }
            let mut index = None;
            let mut name = None;
            let mut enabled = false;
            let mut seen = 0u8;
            walk_nla(p, |k, p| {
                if !(1..=3).contains(&k) || seen & (1 << k) != 0 {
                    return Err(22);
                }
                seen |= 1 << k;
                match k {
                    1 => index = Some(u32_value(p)? as usize),
                    2 => {
                        name = Some(
                            core::str::from_utf8(p.strip_suffix(&[0]).ok_or(22)?)
                                .map_err(|_| 22)?,
                        )
                    }
                    3 => {
                        if !p.is_empty() {
                            return Err(22);
                        }
                        enabled = true;
                    }
                    _ => return Err(22),
                }
                Ok(())
            })?;
            let i = match (index, name) {
                (Some(i), Some(n)) => {
                    if names.get(i) != Some(&n) {
                        return Err(22);
                    }
                    i
                }
                (Some(i), None) => i,
                (None, Some(n)) => names.iter().position(|s| *s == n).ok_or(22)?,
                _ => return Err(22),
            };
            if i >= size || mask & (1u64 << i) != 0 {
                return Err(22);
            }
            mask |= 1u64 << i;
            if enabled || nomask {
                value |= 1u64 << i;
            }
            Ok(())
        })?;
        if nomask {
            mask = low_mask(size);
        }
    } else {
        let bytes = size.div_ceil(32) * 4;
        let v = attrs[4].ok_or(22)?;
        if v.len() != bytes {
            return Err(22);
        }
        let mut buf = [0u8; 8];
        buf[..bytes].copy_from_slice(v);
        value = u64::from_ne_bytes(buf);
        if nomask {
            if attrs[5].is_some() {
                return Err(22);
            }
            mask = low_mask(size);
        } else {
            let m = attrs[5].ok_or(22)?;
            if m.len() != bytes {
                return Err(22);
            }
            buf.fill(0);
            buf[..bytes].copy_from_slice(m);
            mask = u64::from_ne_bytes(buf);
        }
        if (value | mask) & !low_mask(size) != 0 {
            return Err(22);
        }
    }
    Ok((value, mask))
}
fn reply_header(name: &str, index: u32) -> Vec<u8> {
    let mut h = Vec::new();
    push_nla(&mut h, 1, &index.to_ne_bytes());
    let mut n = name.as_bytes().to_vec();
    n.push(0);
    push_nla(&mut h, 2, &n);
    let mut out = Vec::new();
    push_nla(&mut out, 1 | NLA_F_NESTED, &h);
    out
}
fn wire(name: &str, cmd: u32) -> Result<Vec<u8>, i32> {
    let mut b = vec![0; header_size(cmd).ok_or(95)?];
    put(&mut b, 0, cmd);
    if cmd == 0x4c {
        b.resize(72, 0);
        b[15] = 2;
    }
    execute(name, &mut b)?;
    Ok(b)
}
// Scalar netlink attribute -> ioctl offset and scalar width. SET rejects
// every attribute absent from the write map, before invoking the driver.
type ScalarMap = (u32, u8, &'static [(u16, usize, usize)]);
fn map(command: u8, set: bool) -> Option<ScalarMap> {
    Some(match (command, set) {
        (15, false) => (
            0x10,
            16,
            &[
                (2, 4, 4),
                (3, 8, 4),
                (4, 12, 4),
                (5, 16, 4),
                (6, 20, 4),
                (7, 24, 4),
                (8, 28, 4),
                (9, 32, 4),
            ],
        ),
        (16, true) => (0x10, 16, &[(6, 20, 4), (7, 24, 4), (8, 28, 4), (9, 32, 4)]),
        (17, false) => (
            0x3c,
            18,
            &[
                (2, 4, 4),
                (3, 8, 4),
                (4, 12, 4),
                (5, 16, 4),
                (6, 20, 4),
                (7, 24, 4),
                (8, 28, 4),
                (9, 32, 4),
            ],
        ),
        (18, true) => (0x3c, 18, &[(6, 20, 4), (7, 24, 4), (8, 28, 4), (9, 32, 4)]),
        (19, false) => (0x0e, 20, &[(2, 4, 4), (6, 20, 4)]),
        (20, true) => (0x0e, 20, &[(2, 4, 4), (6, 20, 4)]),
        (21, false) => (0x12, 22, &[(2, 4, 1), (3, 8, 1), (4, 12, 1)]),
        (22, true) => (0x12, 22, &[(2, 4, 1), (3, 8, 1), (4, 12, 1)]),
        (23, false) => (0x44, 24, &[(4, 16, 1), (5, 20, 1), (6, 24, 1), (7, 28, 4)]),
        (24, true) => (0x44, 24, &[(5, 20, 1), (6, 24, 1), (7, 28, 4)]),
        _ => return None,
    })
}
fn is_set(cmd: u8) -> bool {
    matches!(cmd, 5 | 8 | 10 | 12 | 14 | 16 | 18 | 20 | 22 | 24)
}
pub(super) fn handle(
    command: u8,
    raw: &[u8],
    dump: bool,
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    if raw.len() > 65536 {
        return Err(22);
    }
    if !OPS.iter().any(|op| op.command == command) {
        return Err(95);
    }
    let mut attrs = [None; 32];
    walk_nla(raw, |k, p| {
        let slot = attrs.get_mut(k as usize).filter(|_| k != 0).ok_or(22)?;
        if slot.replace(p).is_some() {
            return Err(22);
        }
        Ok(())
    })?;
    if command == 1 {
        return strsets(&attrs, context);
    }
    let set = is_set(command);
    if set && dump {
        return Err(22);
    }
    // Validate top-level policy even for an empty dump.
    for (k, p) in attrs.iter().enumerate().skip(2) {
        if p.is_none() {
            continue;
        }
        let valid = if set {
            match command {
                5 => matches!(k, 2 | 3 | 5 | 6),
                8 | 10 | 14 => k == 2,
                12 => k == 3,
                _ => {
                    map(command, true).is_some_and(|(_, _, m)| m.iter().any(|x| x.0 as usize == k))
                }
            }
        } else {
            false
        };
        if !valid {
            return Err(22);
        }
    }
    if dump {
        let flags = header_flags(attrs[1])?;
        if flags & !7 != 0 {
            return Err(22);
        }
        let mut result = Vec::new();
        for e in crate::iface::snapshot_all_in(context.net_ns_id) {
            match one(command, &attrs, &e.name, e.ifindex, flags, context) {
                Ok(r) => result.extend(r),
                Err(95) => {}
                Err(e) => return Err(e),
            }
        }
        return Ok(result);
    }
    let (index, name, flags) = parse_header_dev(attrs[1].ok_or(22)?, context.net_ns_id)?;
    if flags & !7 != 0 {
        return Err(22);
    }
    if set && !context.capable {
        context
            .admin
            .ok_or(1)?
            .authorize_interface(&name, context.net_ns_id)
            .map_err(|_| 1)?;
    }
    one(command, &attrs, &name, index, flags, context)
}
fn one(
    command: u8,
    attrs: &[Option<&[u8]>; 32],
    name: &str,
    index: u32,
    flags: u32,
    _context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let compact = flags & 1 != 0;
    let mut out = reply_header(name, index);
    let mut reply = command;
    let set = is_set(command);
    if let Some((cmd, response, fields)) = map(command, set) {
        let mut b = wire(name, cmd)?;
        reply = response;
        if set {
            for &(kind, offset, width) in fields {
                if let Some(p) = attrs[kind as usize] {
                    if p.len() != width {
                        return Err(22);
                    }
                    let v = if width == 1 {
                        if p[0] > 1 {
                            return Err(22);
                        }
                        u32::from(p[0])
                    } else {
                        u32_value(p)?
                    };
                    put(&mut b, offset, v);
                }
            }
            put(&mut b, 0, cmd + 1);
            execute(name, &mut b)?;
        } else {
            for &(kind, offset, width) in fields {
                let v = get(&b, offset).to_ne_bytes();
                push_nla(&mut out, kind, &v[..width]);
            }
            if command == 23 {
                let names = global_strings(9).unwrap();
                bitset(
                    &mut out,
                    2,
                    u64::from(get(&b, 8)),
                    Some(u64::from(get(&b, 4))),
                    names,
                    compact,
                );
                bitset(&mut out, 3, u64::from(get(&b, 12)), None, names, compact);
            }
        }
    } else {
        match command {
            2 => {
                wire(name, 0x4c)?;
                push_nla(&mut out, 2, &[0]);
            } // PORT_TP
            4 | 5 => {
                let mut b = wire(name, 0x4c)?;
                if set {
                    if let Some(p) = attrs[2] {
                        if p.len() != 1 || p[0] > 1 {
                            return Err(22);
                        }
                        b[11] = p[0];
                    }
                    if let Some(p) = attrs[5] {
                        put(&mut b, 4, u32_value(p)?);
                    }
                    if let Some(p) = attrs[6] {
                        if p.len() != 1 || p[0] > 1 {
                            return Err(22);
                        }
                        b[8] = p[0];
                    }
                    if let Some(p) = attrs[3] {
                        let (v, m) = parse_bitset(p, global_strings(9).unwrap())?;
                        let old = u64::from(get(&b, 56)) | (u64::from(get(&b, 60)) << 32);
                        let v = (old & !m) | (v & m);
                        put(&mut b, 56, v as u32);
                        put(&mut b, 60, (v >> 32) as u32);
                    }
                    put(&mut b, 0, 0x4d);
                    execute(name, &mut b)?;
                } else {
                    push_nla(&mut out, 2, &[b[11]]);
                    push_nla(&mut out, 5, &b[4..8]);
                    push_nla(&mut out, 6, &[b[8]]);
                    let supported = u64::from(get(&b, 48)) | (u64::from(get(&b, 52)) << 32);
                    let adv = u64::from(get(&b, 56)) | (u64::from(get(&b, 60)) << 32);
                    let peer = u64::from(get(&b, 64)) | (u64::from(get(&b, 68)) << 32);
                    bitset(
                        &mut out,
                        3,
                        adv,
                        Some(supported),
                        global_strings(9).unwrap(),
                        compact,
                    );
                    bitset(&mut out, 4, peer, None, global_strings(9).unwrap(), compact);
                }
            }
            6 => {
                let e = crate::iface::lookup(name).ok_or(19)?;
                push_nla(&mut out, 2, &[u8::from(e.link_up && e.carrier)]);
            }
            7 | 8 | 9 | 10 | 13 | 14 => {
                let cmd = match command {
                    7 | 8 => 0x07,
                    9 | 10 => 0x05,
                    _ => 0x27,
                };
                let mut b = wire(name, cmd)?;
                let names: Vec<alloc::string::String> = if command >= 13 {
                    strings(Some(name), 2)?
                } else {
                    strings(None, if command <= 8 { 10 } else { 11 })?
                };
                if names.len() > 64 {
                    return Err(95);
                }
                let names: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
                let offset = if cmd == 5 { 8 } else { 4 };
                let value = get(&b, offset) as u64;
                if set {
                    let (v, m) = parse_bitset(attrs[2].ok_or(22)?, &names)?;
                    let new = (value & !m) | (v & m);
                    if new > u64::from(u32::MAX) {
                        return Err(22);
                    }
                    put(&mut b, offset, new as u32);
                    put(&mut b, 0, cmd + 1);
                    execute(name, &mut b)?;
                } else {
                    bitset(
                        &mut out,
                        2,
                        value,
                        Some(if cmd == 5 {
                            u64::from(get(&b, 4))
                        } else {
                            low_mask(names.len())
                        }),
                        &names,
                        compact,
                    );
                    reply = if command == 13 { 14 } else { command };
                }
            }
            11 | 12 => {
                let (hw, wanted, active) = features::snapshot(name)?;
                if set {
                    let (v, m) = parse_bitset(attrs[3].ok_or(22)?, features::NAMES)?;
                    features::update(name, m, v)?;
                    let (_, _, new) = features::snapshot(name)?;
                    let wanted_diff = (v ^ new) & m;
                    let active_diff = active ^ new;
                    bitset(
                        &mut out,
                        3,
                        v & wanted_diff,
                        Some(wanted_diff),
                        features::NAMES,
                        compact,
                    );
                    bitset(
                        &mut out,
                        4,
                        new & active_diff,
                        Some(active_diff),
                        features::NAMES,
                        compact,
                    );
                } else {
                    bitset(&mut out, 2, hw, Some(u64::MAX), features::NAMES, compact);
                    bitset(&mut out, 3, wanted, None, features::NAMES, compact);
                    bitset(&mut out, 4, active, None, features::NAMES, compact);
                    bitset(&mut out, 5, 0, None, features::NAMES, compact);
                }
            }
            25 => {
                let b = wire(name, 0x41)?;
                reply = 26;
                for (kind, offset, id) in [(2, 4, 12), (3, 12, 13), (4, 28, 14)] {
                    bitset(
                        &mut out,
                        kind,
                        u64::from(get(&b, offset)),
                        None,
                        global_strings(id).unwrap(),
                        compact,
                    );
                }
                push_nla(&mut out, 5, &b[8..12]);
            }
            _ => return Err(95),
        }
    }
    if set && (command != 12 || flags & 2 != 0) {
        Ok(Vec::new())
    } else {
        Ok(vec![GenlReply {
            command: reply,
            attrs: out,
        }])
    }
}
fn strsets(
    attrs: &[Option<&[u8]>; 32],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    if attrs.iter().skip(4).any(Option::is_some) || attrs[3].is_some_and(|p| !p.is_empty()) {
        return Err(22);
    }
    let name = if let Some(h) = attrs[1] {
        // Empty global header has no device.
        let mut device = false;
        walk_nla(h, |k, _| {
            device |= k == 1 || k == 2;
            Ok(())
        })?;
        if device {
            Some(parse_header_dev(h, context.net_ns_id)?)
        } else {
            header_flags(Some(h))?;
            None
        }
    } else {
        None
    };
    let mut ids = Vec::new();
    if let Some(sets) = attrs[2] {
        walk_nla(sets, |k, p| {
            if k != 1 {
                return Err(22);
            }
            let mut id = None;
            walk_nla(p, |k, p| {
                if k != 1 || id.is_some() {
                    return Err(22);
                }
                id = Some(u32_value(p)?);
                Ok(())
            })?;
            let id = id.ok_or(22)?;
            if id >= 64 || ids.contains(&id) {
                return Err(22);
            }
            ids.push(id);
            Ok(())
        })?;
    }
    if ids.is_empty() {
        ids = vec![4, 9, 10, 11, 12, 13, 14];
        if name.is_some() {
            ids.extend([0, 1, 2]);
        }
    }
    let mut sets = Vec::new();
    for id in ids {
        let ns = match strings(name.as_ref().map(|(_, n, _)| n.as_str()), id) {
            Ok(ns) => ns,
            Err(95) => continue,
            Err(e) => return Err(e),
        };
        let mut set = Vec::new();
        push_nla(&mut set, 1, &id.to_ne_bytes());
        push_nla(&mut set, 2, &(ns.len() as u32).to_ne_bytes());
        if attrs[3].is_none() {
            let mut entries = Vec::new();
            for (i, n) in ns.iter().enumerate() {
                let mut entry = Vec::new();
                push_nla(&mut entry, 1, &(i as u32).to_ne_bytes());
                let mut text = n.as_bytes().to_vec();
                text.push(0);
                push_nla(&mut entry, 2, &text);
                push_nla(&mut entries, 1 | NLA_F_NESTED, &entry);
            }
            push_nla(&mut set, 3 | NLA_F_NESTED, &entries);
        }
        push_nla(&mut sets, 1 | NLA_F_NESTED, &set);
    }
    let mut out = if let Some((i, n, _)) = name {
        reply_header(&n, i)
    } else {
        Vec::new()
    };
    push_nla(&mut out, 2 | NLA_F_NESTED, &sets);
    if out.len() > 65536 {
        return Err(90);
    }
    Ok(vec![GenlReply {
        command: 1,
        attrs: out,
    }])
}
