//! A passive scan consumes the configured MVM boot owner's live transport.
//! Cancellation leaves its phase closed; it cannot launch a second scan or
//! admit a station while firmware owns the first operation.
use super::super::{
    boot_context::{put16, put32},
    connection::Beacon,
    firmware_api::FirmwareApi,
    scan_api,
};
use super::{Owner, Phase};
use alloc::vec::Vec;
use narf_wireless::{reg::RegulatoryDomain, scan::BssSecurity, BssInfo};

/// Firmware/NVM profile and completed preparation remain with the boot owner.
/// No inferred board calibration, world transmit policy or synthetic MAC/link
/// identity is accepted as a replacement for real command receipts.
pub(super) struct ScanContext {
    dqa: bool,
    reduced: bool,
    lar: bool,
    mcc_he: bool,
    multi_mcc: bool,
    mld: bool,
    smart_fifo_offload: bool,
    beacon_filter_v4: bool,
    pub(super) nvm_lar: bool,
    pub(super) ready: bool,
    pub(super) permissions: Option<Vec<u32>>,
}
impl ScanContext {
    pub(super) fn new(api: &FirmwareApi<'_>) -> Self {
        Self {
            dqa: api.has_capability(12),
            reduced: api.api_changes[1] & (1 << 24) != 0,
            lar: api.has_capability(1),
            mcc_he: api.has_capability(89),
            multi_mcc: api.api_changes[0] & (1 << 9) != 0 || api.has_capability(29),
            mld: api.has_capability(110),
            smart_fifo_offload: api.api_changes[2] & (1 << 4) != 0,
            beacon_filter_v4: api.api_changes[1] & (1 << 15) != 0,
            nvm_lar: false,
            ready: false,
            permissions: None,
        }
    }
}

/// Packed 52-byte MAC_CONFIG for the API77 MVM MLD command profile.
/// Linux mld-mac.c sends its v3-named struct for negotiated versions1..3;
/// all generation/association fields remain zero for this idle BSS-STA.
fn idle_mac(local: [u8; 6]) -> [u8; 52] {
    let mut b = [0; 52];
    put32(&mut b, 4, 1);
    put32(&mut b, 8, 5);
    b[12..18].copy_from_slice(&local);
    put32(&mut b, 20, (1 << 2) | (1 << 3)); // GROUP | BEACON
                                            // HE/EHT, association, NIC-not-ACK and all client fields remain clear.
    b
}

fn idle_link(local: [u8; 6]) -> [u8; 208] {
    let mut b = [0; 208];
    put32(&mut b, 0, 1); // ADD; link0 belongs to MAC0
    put32(&mut b, 12, u32::MAX); // FW_CTXT_INVALID, no PHY binding
    b[16..22].copy_from_slice(&local);
    // No MODIFY flags, active link, basic rates, beacon timing or QoS are
    // advertised by an unbound ADD. They belong to later station binding.
    b
}

fn smart_fifo() -> [u8; 92] {
    let mut b = [0; 92];
    put32(&mut b, 0, 3); // SF_INIT_OFF: one unassociated BSS-STA
    put32(&mut b, 4, 4096);
    put32(&mut b, 8, 8192);
    for offset in (12..52).step_by(4) {
        put32(&mut b, offset, 1_000_000);
    }
    for offset in (52..92).step_by(8) {
        put32(&mut b, offset, 400);
        put32(&mut b, offset + 4, 160);
    }
    b
}

pub(super) fn awake_mac_power() -> [u8; 40] {
    let mut b = [0; 40];
    put16(&mut b, 6, 25); // required keep-alive even with PM disabled
    b
}

fn mcc_query(multi_source: bool) -> [u8; 28] {
    let mut query = [0; 28];
    query[..2].copy_from_slice(b"ZZ");
    query[2] = if multi_source { 0x10 } else { 0 };
    query
}

fn mcc_permissions(version: u8, bytes: &[u8]) -> Result<Vec<u32>, &'static str> {
    let (header, count_offset) = match version {
        3 => (16, 12),
        4 => (20, 16),
        8 => (24, 20),
        _ => return Err("unsupported MVM MCC response"),
    };
    if bytes.len() < header || u32::from_le_bytes(bytes[..4].try_into().unwrap()) > 1 {
        return Err("invalid MVM MCC response/status");
    }
    let count =
        u32::from_le_bytes(bytes[count_offset..count_offset + 4].try_into().unwrap()) as usize;
    if count == 0 || count > 110 || bytes.len() != header + count * 4 {
        return Err("invalid MVM MCC response extent");
    }
    Ok(bytes[header..]
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect())
}

pub(super) fn passive_permitted(domain: &RegulatoryDomain, channel: u8) -> bool {
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    let centre = match channel {
        1..=13 => 2407 + 5 * u32::from(channel),
        14 => 2484,
        36..=181 => 5000 + 5 * u32::from(channel),
        _ => return false,
    };
    // Passive reception makes no power, indoor or DFS transmit decision.
    // Its complete 20MHz receive interval must still be covered by a rule
    // from the deployment's authenticated policy; NVM alone is not policy.
    let mut covering = false;
    for rule in &domain.rules {
        if rule.freq_end_mhz <= centre - 10 || centre + 10 <= rule.freq_start_mhz {
            continue;
        }
        // A permissive covering rule cannot erase a stricter overlapping
        // receive-bandwidth constraint from the same authenticated policy.
        if rule.freq_end_mhz <= rule.freq_start_mhz || rule.max_bandwidth_mhz < 20 {
            return false;
        }
        covering |= rule.freq_start_mhz <= centre - 10 && rule.freq_end_mhz >= centre + 10;
    }
    covering
}

impl Owner {
    pub fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<&[u8]> {
        self.beacons
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.information_elements.as_slice())
    }
    /// Only channels present in this owner's firmware NVM and the currently
    /// installed authenticated regulatory policy are eligible. Force passive
    /// is set on every channel, including DFS; no TX/rate/board-power authority
    /// or probe template is synthesized by scanning.
    pub async fn passive_scan(&mut self, channels: &[u8]) -> Result<Vec<BssInfo>, &'static str> {
        // The native binding installs only a signed regulatory blob into the
        // existing trusted registry. Refresh the snapshot for every operation
        // rather than retaining a permissive country across later updates.
        let policy = narf_wireless::reg::db::get_domain()
            .ok_or("missing authenticated MVM regulatory policy")?;
        self.passive_scan_in_domain(channels, &policy).await
    }
    async fn passive_scan_in_domain(
        &mut self,
        channels: &[u8],
        domain: &RegulatoryDomain,
    ) -> Result<Vec<BssInfo>, &'static str> {
        if self.phase != Phase::Configured || self.hardware.is_failed() {
            return Err("MVM owner is not ready for scan");
        }
        let nvm = self.nvm.as_ref().ok_or("missing retained MVM NVM")?;
        if channels.is_empty()
            || channels.len() > 51
            || channels.iter().enumerate().any(|(i, ch)| {
                !nvm.channels.contains(ch)
                    || channels[..i].contains(ch)
                    || !passive_permitted(domain, *ch)
            })
        {
            return Err("invalid MVM scan channels");
        }
        let version = self.validate_scan_profile()?;
        // Firmware has a finite scan-slot namespace; slot0 is reused only
        // after its exact terminal notification. Failed/dropped attempts never
        // return to Configured. Retire previously queued notifications before
        // publishing this operation, as Linux's scan slot lifecycle requires.
        let request = scan_api::passive(version, 0, channels)?;
        self.phase = Phase::Scanning;
        let result = self.passive_scan_inner(channels, &request).await;
        match result {
            Ok((beacons, results)) => {
                self.beacons = beacons;
                self.phase = Phase::Configured;
                Ok(results)
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }
    pub(super) fn validate_scan_profile(&self) -> Result<u8, &'static str> {
        if !self.scan.reduced
            || !self.scan.mld
            || self.hardware.version(1, 0xc).map(|v| v.0) != Some(5)
            || !self
                .hardware
                .version(3, 8)
                .is_some_and(|v| matches!(v.0, 1..=3))
            || self
                .hardware
                .version(3, 9)
                .is_some_and(|v| !matches!(v.0, 0 | 1 | 99))
            || (self.scan.dqa
                && self
                    .hardware
                    .version(5, 0)
                    .is_some_and(|v| !matches!(v.0, 0 | 1 | 99)))
            || (!self.scan.smart_fifo_offload
                && self
                    .hardware
                    .version(1, 0xd1)
                    .is_some_and(|v| !matches!(v.0, 0 | 2 | 3 | 99)))
            || self
                .hardware
                .version(1, 0xd2)
                .is_some_and(|v| v.0 != if self.scan.beacon_filter_v4 { 4 } else { 3 })
            || self
                .hardware
                .version(1, 0xa9)
                .is_some_and(|v| !matches!(v.0, 0..=2 | 99))
        {
            return Err("unsupported MVM scan preparation profile");
        }
        let version = self
            .hardware
            .version(1, 0xd)
            .ok_or("missing MVM scan API")?
            .0;
        if !matches!(version, 14..=17) || self.hardware.version(0, 0xf).is_some_and(|v| v.1 != 1) {
            return Err("unsupported MVM scan API");
        }
        Ok(version)
    }
    pub(super) async fn prepare_scan(&mut self) -> Result<(), &'static str> {
        if !self.scan.ready && self.scan.dqa {
            self.hardware.command(5, 0, &[0; 4]).await?; // DQA HCMD queue0
        }
        self.refresh_mcc().await?;
        if self.scan.ready {
            return Ok(());
        }
        self.hardware
            .command(
                1,
                0xc,
                &super::super::station_api::scan_config(
                    self.nvm.as_ref().ok_or("missing MVM scan NVM")?,
                ),
            )
            .await?;
        let local = self.mac.ok_or("missing MVM scan identity")?;
        self.hardware.command(3, 8, &idle_mac(local)).await?;
        let filter = [0; 60];
        self.hardware
            .command(
                1,
                0xd2,
                &filter[..if self.scan.beacon_filter_v4 { 60 } else { 44 }],
            )
            .await?;
        if !self.scan.smart_fifo_offload {
            self.hardware.command(1, 0xd1, &smart_fifo()).await?;
        }
        self.hardware.command(3, 9, &idle_link(local)).await?;
        self.hardware.command(1, 0xa9, &awake_mac_power()).await?;
        self.scan.ready = true;
        Ok(())
    }
    pub(super) fn mcc_request(&self) -> Result<Option<(u8, [u8; 28])>, &'static str> {
        // The firmware can change its current profile after a successful
        // scan (e.g. CHUB/MCC updates). Requery every operation; an earlier
        // successful scan never turns its channel map into lasting policy.
        if self.scan.lar && self.scan.nvm_lar {
            let version = self.hardware.version(1, 0xc8).map(|v| v.1).unwrap_or(0);
            let version = if version >= 8 {
                if version != 8 {
                    return Err("unsupported MCC API");
                }
                8
            } else if self.scan.mcc_he {
                4
            } else {
                3
            };
            let query = mcc_query(self.scan.multi_mcc);
            return Ok(Some((version, query)));
        }
        Ok(None)
    }
    pub(super) fn accept_mcc(&mut self, version: u8, payload: &[u8]) -> Result<(), &'static str> {
        self.scan.permissions = Some(mcc_permissions(version, payload)?);
        Ok(())
    }
    pub(super) async fn refresh_mcc(&mut self) -> Result<(), &'static str> {
        if let Some((version, query)) = self.mcc_request()? {
            let reply = self.hardware.command(1, 0xc8, &query).await?;
            self.accept_mcc(version, &reply.payload)?;
        }
        Ok(())
    }
    async fn passive_scan_inner(
        &mut self,
        channels: &[u8],
        request: &[u8],
    ) -> Result<(Vec<Beacon>, Vec<BssInfo>), &'static str> {
        self.hardware.poll()?;
        self.hardware.notifications.clear();
        self.prepare_scan().await?;
        if let Some(permissions) = &self.scan.permissions {
            for channel in channels {
                let index = super::super::station_api::channel_index(*channel)
                    .ok_or("invalid MVM scan band/channel")?;
                if permissions.get(index).is_none_or(|flags| flags & 1 == 0) {
                    return Err("channel absent from current firmware regulatory profile");
                }
            }
        }
        // Preparation can itself await several firmware commands. Retire any
        // notifications received during those waits before slot0 is actually
        // published; a prior scan's terminal event cannot finish this one.
        self.hardware.poll()?;
        self.hardware.notifications.clear();
        self.hardware.command(1, 0xd, request).await?;
        let deadline = narf_time::Deadline::after_ms(15_000);
        let mut beacons: Vec<Beacon> = Vec::new();
        let mut results: Vec<BssInfo> = Vec::new();
        // The iteration bound also terminates a broken monotonic clock. Every
        // loop drains at most32 decoded notifications and awaits Activity's
        // mandatory yield before repeating; one poll cannot spin indefinitely.
        for _ in 0..20_000 {
            let activity = self.hardware.activity();
            self.hardware.poll()?;
            for _ in 0..32 {
                let Some(packet) = self.hardware.notifications.pop_front() else {
                    break;
                };
                if packet.header.group_id != 0 {
                    continue;
                }
                match packet.header.cmd {
                    0xf => {
                        // Literal SCAN_COMPLETE_NTF_UMAC_API_S_VER_1.
                        if packet.payload.len() != 16
                            || packet.payload[..4] != [0; 4]
                            || packet.payload[6] != 1
                        {
                            return Err("MVM scan completion mismatch or failure");
                        }
                        return Ok((beacons, results));
                    }
                    0xc1 => {
                        let Some((beacon, rssi)) = observed_beacon(
                            &packet.payload,
                            channels,
                            self.mac.ok_or("missing MVM scan identity")?,
                        ) else {
                            continue;
                        };
                        let record = BssInfo {
                            bssid: beacon.bssid,
                            ssid: beacon.ssid.clone(),
                            channel: u32::from(beacon.channel),
                            frequency_mhz: match beacon.channel {
                                14 => 2484,
                                1..=13 => 2407 + 5 * u32::from(beacon.channel),
                                ch => 5000 + 5 * u32::from(ch),
                            },
                            rssi,
                            security: if beacon.rsn.is_some() {
                                BssSecurity::Wpa2
                            } else if beacon.privacy {
                                BssSecurity::Wep
                            } else {
                                BssSecurity::Open
                            },
                        };
                        if let Some(i) = beacons.iter().position(|b| b.bssid == beacon.bssid) {
                            beacons[i] = beacon;
                            results[i] = record;
                        } else if beacons.len() < 256 {
                            beacons.push(beacon);
                            results.push(record);
                        }
                    }
                    _ => (),
                }
            }
            if deadline.expired() {
                return Err("MVM passive scan timed out");
            }
            activity.await;
        }
        Err("MVM scan progress bound exceeded")
    }
}

/// Beacons/probe responses must come from their native BSSID on a requested
/// NVM channel. Unsupported DS/protection/fragment/header shapes never become
/// association input. Original AP IEs and RSNE bytes are retained unchanged.
fn observed_beacon(payload: &[u8], channels: &[u8], local: [u8; 6]) -> Option<(Beacon, i8)> {
    let mpdu = scan_api::mpdu_gen2(payload)?;
    let frame = mpdu.frame;
    if frame.len() < 36
        || !matches!(frame[0], 0x80 | 0x50)
        || frame[1] & 0xc7 != 0
        || frame[22] & 15 != 0
        || mpdu.amsdu
        || mpdu.status & 0xf00 != 0
        || !channels.contains(&mpdu.channel)
    {
        return None;
    }
    let bssid: [u8; 6] = frame[16..22].try_into().ok()?;
    if bssid == [0; 6]
        || bssid[0] & 1 != 0
        || bssid == local
        || frame[10..16] != bssid
        || (frame[0] == 0x80 && frame[4..10] != [0xff; 6])
        || (frame[0] == 0x50 && frame[4..10] != local)
    {
        return None;
    }
    let body = mpdu.body(24, 0)?;
    let interval = u16::from_le_bytes(body.get(8..10)?.try_into().ok()?);
    let capability = u16::from_le_bytes(body.get(10..12)?.try_into().ok()?);
    if interval == 0 || capability & 3 != 1 {
        return None;
    }
    let mut ssid = None;
    let mut rsn = None;
    let mut ds = false;
    let mut ht_operation = false;
    let mut rates = false;
    let information_elements = body.get(12..)?;
    if information_elements.len() > 2048 {
        return None;
    }
    let mut ies = information_elements;
    while !ies.is_empty() {
        let id = *ies.first()?;
        let len = usize::from(*ies.get(1)?);
        let value = ies.get(2..2 + len)?;
        match id {
            0 => {
                if ssid.is_some() || len > 32 {
                    return None;
                }
                ssid = Some(value.to_vec());
            }
            1 => {
                if rates || len == 0 || len > 8 {
                    return None;
                }
                rates = true;
            }
            3 => {
                if ds || value != [mpdu.channel] {
                    return None;
                }
                ds = true;
            }
            48 => {
                if rsn.is_some() {
                    return None;
                }
                // Preserve the original AP wire bytes, including suite order.
                rsn = Some(value.to_vec());
            }
            61 => {
                if ht_operation || len != 22 || value[0] != mpdu.channel {
                    return None;
                }
                ht_operation = true;
            }
            _ => (),
        }
        ies = &ies[2 + len..];
    }
    if !rates {
        return None;
    }
    Some((
        Beacon {
            bssid,
            ssid: ssid?,
            channel: mpdu.channel,
            interval,
            dtim: scan_api::dtim_period(body),
            rsn,
            privacy: capability & 16 != 0,
            capabilities: capability,
            information_elements: information_elements.to_vec(),
        },
        mpdu.rssi,
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_scan_tests.rs"]
mod tests;
