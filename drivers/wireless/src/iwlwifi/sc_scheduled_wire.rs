// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Linux scheduled-scan wire helpers. These bytes grant no firmware,
//! PCI, regulatory, receive or autonomous-emission authority.
use super::super::super::{ht_vht, scan_api};
use alloc::{vec, vec::Vec};
use narf_wireless::{NetDetectMatch, NetDetectScanPlan};

/// Linux mld/scan.c::iwl_mld_scan_cmd_set_sched_params and scan.h's
/// SCAN_PERIODIC_PARAMS_API_S_VER_1. Infinite final plan is exactly0xff.
pub(super) fn periodic(plans: &[NetDetectScanPlan], delay: u32) -> Result<[u8; 12], &'static str> {
    if plans.is_empty() || plans.len() > 2 {
        return Err("scheduled scan needs one or two plans");
    }
    let mut bytes = [0; 12];
    for (i, plan) in plans.iter().enumerate() {
        if !(1..=u32::from(u16::MAX)).contains(&plan.interval_secs) {
            return Err("scheduled interval exceeds native u16");
        }
        let count = match plan.iterations {
            Some(count) if (1..=254).contains(&count) => count as u8,
            None if i + 1 == plans.len() => 255,
            _ => return Err("scheduled iteration count or infinite non-final plan"),
        };
        bytes[4 * i..4 * i + 2].copy_from_slice(&(plan.interval_secs as u16).to_le_bytes());
        bytes[4 * i + 2] = count;
    }
    // Linux trims an oversized initial delay, without wrapping it.
    bytes[8..10].copy_from_slice(&(delay.min(u32::from(u16::MAX)) as u16).to_le_bytes());
    Ok(bytes)
}

/// SCAN_OFFLOAD_PROFILES_CFG_API_S_VER_3 with the native empty64-entry
/// blocklist. Profiles are matching facts, never instructions to probe.
pub(super) fn profiles(matches: &[NetDetectMatch]) -> Result<Vec<u8>, &'static str> {
    if matches.len() > 8 || matches.iter().any(|m| m.ssid.len() > 32) {
        return Err("scheduled match count/SSID exceeds native profile");
    }
    let mut bytes = vec![0; 64 * 8 + 8 * 8 + 8];
    for i in 0..matches.len() {
        let at = 64 * 8 + i * 8;
        bytes[at..at + 8].copy_from_slice(&[i as u8, 255, 0x3f, 3, 0x0c, 1, 0, 0]);
    }
    let at = 64 * 8 + 8 * 8;
    bytes[at..at + 8].copy_from_slice(&[
        0,
        matches.len() as u8,
        1,
        1,
        1,
        u8::from(matches.first().is_none_or(|m| m.ssid.is_empty())),
        0,
        0,
    ]);
    Ok(bytes)
}

pub(super) struct Ssids {
    pub table: [u8; 20 * 34],
    pub probes: u32,
}
/// Linux's firmware reverses this direct-SSID order. Match rows occupy
/// their original slots even when empty; only requested probe SSIDs set
/// active channel bitmap bits. Receiving a match never grants emission.
pub(super) fn ssids(matches: &[NetDetectMatch], probes: &[Vec<u8>]) -> Result<Ssids, &'static str> {
    if matches.len() > 8
        || probes.len() > 20
        || matches.iter().any(|m| m.ssid.len() > 32)
        || probes.iter().any(|s| s.len() > 32)
    {
        return Err("scheduled direct SSID limits");
    }
    let mut table = [0; 20 * 34];
    let mut count = 0;
    for row in matches.iter().rev() {
        table[count * 34 + 1] = row.ssid.len() as u8;
        table[count * 34 + 2..count * 34 + 2 + row.ssid.len()].copy_from_slice(&row.ssid);
        count += 1;
    }
    let mut bitmap = 0;
    for ssid in probes.iter().rev() {
        let index = (0..count).find(|i| {
            table[i * 34 + 1] as usize == ssid.len()
                && table[i * 34 + 2..i * 34 + 2 + ssid.len()] == ssid[..]
        });
        let index = if let Some(index) = index {
            index
        } else {
            if count == 20 {
                return Err("scheduled match/probe union exceeds native table");
            }
            let index = count;
            count += 1;
            table[index * 34 + 1] = ssid.len() as u8;
            table[index * 34 + 2..index * 34 + 2 + ssid.len()].copy_from_slice(ssid);
            index
        };
        bitmap |= 1u32 << index;
    }
    Ok(Ssids {
        table,
        probes: bitmap,
    })
}

/// SCAN_REQ_UMAC's fixed UID is a firmware slot (Linux owns four slots),
/// never a host generation number. Slot zero remains ordinary scan.
pub(super) const UID: u32 = 1;

pub(super) fn request(
    version: u8,
    channels: &[u8],
    permitted: &[bool],
    local: [u8; 6],
    phy: ht_vht::Local,
    request: &narf_wireless::SchedScanRequest,
) -> Result<Vec<u8>, &'static str> {
    if permitted.len() != channels.len() {
        return Err("scheduled per-channel permissions differ from request");
    }
    let ssids = ssids(&request.matches, &request.probe_ssids)?;
    let active = !request.probe_ssids.is_empty() && permitted.iter().any(|&p| p);
    let mut body = if active {
        scan_api::active(
            version,
            UID,
            channels,
            permitted,
            local,
            &request.probe_ssids,
        )?
    } else {
        scan_api::passive(version, UID, channels)?
    };
    scan_api::with_phy_capabilities(version, &mut body, phy)?;
    let capacity = if version == 18 { 68 } else { 67 };
    let periodic_at = 48 + capacity * 8;
    body[periodic_at..periodic_at + 12]
        .copy_from_slice(&periodic(&request.plans, request.delay_secs)?);
    let pass_all = request.matches.first().is_none_or(|m| m.ssid.is_empty());
    // fw/api/scan.h IWL_UMAC_SCAN_GEN_FLAGS_V2_*; actual periodic native
    // offload with preemption, no host timer synthesizing scan iterations.
    let flags: u16 = 1
        | (1 << 8)
        | if pass_all {
            (1 << 1) | (1 << 2)
        } else {
            1 << 5
        }
        | if !active { 1 << 11 } else { 0 };
    body[8..10].copy_from_slice(&flags.to_le_bytes());
    // iwl_mld_scan_ooc_priority: periodic/scheduled scans use EXT_2;
    // scan_priority inside general params stays EXT_6 like Linux.
    body[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (i, &allowed) in permitted.iter().enumerate() {
        let at = 48 + i * 8;
        let flags = u32::from_le_bytes(body[at..at + 4].try_into().unwrap()) & !0xfffff;
        body[at..at + 4].copy_from_slice(
            &(flags | if active && allowed { ssids.probes } else { 0 }).to_le_bytes(),
        );
    }
    let probe = periodic_at + 12;
    body[probe + 536..probe + 536 + ssids.table.len()].copy_from_slice(&ssids.table);
    if request.probe_ies.len() > 256 {
        return Err("scheduled probe IE limit");
    }
    let mut ies = request.probe_ies.as_slice();
    while !ies.is_empty() {
        if ies.len() < 2 || usize::from(ies[1]) + 2 > ies.len() {
            return Err("scheduled malformed probe IEs");
        }
        ies = &ies[usize::from(ies[1]) + 2..];
    }
    if active && !request.probe_ies.is_empty() {
        let end = (0..4)
            .map(|i| {
                let at = probe + i * 4;
                usize::from(u16::from_le_bytes(body[at..at + 2].try_into().unwrap()))
                    + usize::from(u16::from_le_bytes(body[at + 2..at + 4].try_into().unwrap()))
            })
            .max()
            .unwrap();
        if end + request.probe_ies.len() > 512 {
            return Err("scheduled probe template extent");
        }
        body[probe + 16..probe + 18].copy_from_slice(&(end as u16).to_le_bytes());
        body[probe + 18..probe + 20]
            .copy_from_slice(&(request.probe_ies.len() as u16).to_le_bytes());
        body[probe + 20 + end..probe + 20 + end + request.probe_ies.len()]
            .copy_from_slice(&request.probe_ies);
    }
    Ok(body)
}

pub(super) fn aborted_reply(bytes: &[u8]) -> Result<bool, &'static str> {
    match bytes {
        [0 | 1, 0, 0, 0] => Ok(false), // SUCCESS or IN_PROGRESS: await UID completion
        [2, 0, 0, 0] => Ok(true),      // NOT_FOUND: actual firmware absence proof
        _ => Err("scheduled abort has no native status proof"),
    }
}
pub(super) fn complete(bytes: &[u8]) -> Result<Option<u8>, &'static str> {
    if bytes.len() != 16 {
        return Err("scheduled malformed scan completion");
    }
    if bytes[..4] != UID.to_le_bytes() {
        return Ok(None);
    }
    if !matches!(bytes[6], 1 | 2) {
        return Err("scheduled unknown scan completion status");
    }
    Ok(Some(bytes[6]))
}
