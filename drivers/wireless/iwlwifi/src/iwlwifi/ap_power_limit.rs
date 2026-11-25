// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! The AP's advertised transmit-power limit (Country, Power Constraint and
//! Cisco DTPC elements), as Linux mac80211 derives it. Pure IE parsing:
//! shared by the platform power owner (`mld_power`), the station
//! (`connection`, `sc_mlo_assoc`) and the module build.

/// Linux mac80211's legacy2.4/5GHz AP limit. This bound is intersected with
/// the host/MCC maximum; AP data never establishes a country or permission.
/// The caller supplies complete parsed IE bodies and a bound AP's capability
/// field.6GHz TPE/power-type admission is a different native contract.
pub(super) fn legacy_ap_limit(
    channel: u8,
    capabilities: u16,
    country: Option<&[u8]>,
    reduction: Option<u8>,
    cisco_dtpc: Option<i8>,
) -> Option<i16> {
    let standard = country
        .filter(|body| body.len() >= 6 && body.len() % 2 == 0)
        .filter(|_| capabilities & ((1 << 8) | (1 << 12)) != 0)
        .and_then(|body| {
            let increment: u16 = if channel <= 14 { 1 } else { 4 };
            body[3..].chunks_exact(3).find_map(|triplet| {
                if triplet[0] >= 201 {
                    return None;
                }
                (0..u16::from(triplet[1]))
                    .any(|index| u16::from(triplet[0]) + increment * index == u16::from(channel))
                    .then(|| (i16::from(triplet[2]) - i16::from(reduction.unwrap_or(0))).max(0))
            })
        });
    match (standard, cisco_dtpc) {
        (Some(a), Some(b)) => Some(a.min(i16::from(b))),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(i16::from(b)),
        (None, None) => None,
    }
}

pub(super) fn ap_limit_in_ies(
    ies: &[u8],
    capabilities: u16,
    channel: u8,
) -> Result<Option<i16>, &'static str> {
    let (mut country, mut reduction, mut dtpc) = (None, None, None);
    let mut at = 0;
    while at < ies.len() {
        let header = ies.get(at..at + 2).ok_or("short AP power IE header")?;
        let id = header[0];
        let length = usize::from(header[1]);
        at += 2;
        let body = ies.get(at..at + length).ok_or("truncated AP power IE")?;
        at += length;
        match id {
            7 if country.is_none() => country = Some(body),
            32 if reduction.is_none() && body.len() == 1 => reduction = Some(body[0]),
            150 if body.len() == 6 && body[..4] == [0, 0x40, 0x96, 0] => dtpc = Some(body[4] as i8),
            _ => {}
        }
    }
    Ok(legacy_ap_limit(
        channel,
        capabilities,
        country,
        reduction,
        dtpc,
    ))
}
