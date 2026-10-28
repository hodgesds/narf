// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! API77 v5 SAR + host TX-power preparation behind the inactive/disabled peer.
//! Linux mvm/{fw,mac80211}.c and fw/{regulatory.c,api/power.h}. Real platform
//! limits come only from a signed, identity-bound qualification; no absent-BIOS
//! fallback or inferred table grants transmit authority.
use super::super::{
    boot_context::{put16, put32},
    firmware_api::FirmwareApi,
};
use super::{Owner, Phase};
use crate::firmware_asset::Asset;
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::reg::RegulatoryDomain;

const RECORD_LEN: usize = 64;
const REDUCE_TX_POWER: u8 = 0x9f;

/// Distinct externally qualified emission programs. Profile2 includes the
/// legacy management/EAPOL program and HT20/SISO/MCS0..7/SGI20 with WMM BE.
/// A profile1 measurement never authorizes that additional emission set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::iwlwifi) enum Emission {
    #[default]
    Legacy,
    Ht20,
    /// Firmware-managed TID0 aggregation and recipient autonomous Block Ack.
    Ht20Ba,
    /// The tag3 program plus negotiated nested recipient A-MSDU-in-A-MPDU.
    Ht20NestedBa,
    /// Generic feature program (tag5): the tag2 HT20/SISO/WMM base plus
    /// exactly the [`feature`] bits it names. Each distinct bit set is its
    /// own externally qualified program, bound by name, binding domain and
    /// record bytes 62..64; one set never authorizes another.
    Features(u16),
}

/// Emitting-feature bits of a tag5 program.
pub(in crate::iwlwifi) mod feature {
    /// Firmware-managed TID0 TX BA pipeline and recipient BA (tag3 set).
    pub const BA: u16 = 1 << 0;
    /// Negotiated nested recipient A-MSDU-in-A-MPDU (tag4 set).
    pub const NESTED_BA: u16 = 1 << 1;
    /// Per-TID QoS data queues for all eight TIDs / four access categories.
    pub const QOS_TIDS: u16 = 1 << 2;
    /// HT TX LDPC coding toward an LDPC-capable peer
    /// (`IWL_TLC_MNG_CFG_FLAGS_LDPC_MSK`).
    pub const TX_LDPC: u16 = 1 << 3;
    /// HT TX STBC from two transmit chains toward a peer with Rx STBC
    /// (`IWL_TLC_MNG_CFG_FLAGS_STBC_MSK`, HT Tx STBC advertised).
    pub const TX_STBC: u16 = 1 << 4;
    /// HT 20/40MHz operation on the AP's secondary channel: a 40MHz PHY
    /// context, `STA_FLG_FAT_EN_40MHZ` and TLC `max_ch_width` 40MHz.
    pub const HT40: u16 = 1 << 5;
    /// Every bit this driver can emit; other bits are refused.
    pub const KNOWN: u16 = BA | NESTED_BA | QOS_TIDS | TX_LDPC | TX_STBC | HT40;
}

impl Emission {
    /// NIPW record byte 46.
    pub(in crate::iwlwifi) fn tag(self) -> u8 {
        match self {
            Emission::Legacy => 1,
            Emission::Ht20 => 2,
            Emission::Ht20Ba => 3,
            Emission::Ht20NestedBa => 4,
            Emission::Features(_) => 5,
        }
    }
    /// Feature bits granted by this program (tag3/4 imply their BA bits).
    pub(in crate::iwlwifi) fn features(self) -> u16 {
        match self {
            Emission::Legacy | Emission::Ht20 => 0,
            Emission::Ht20Ba => feature::BA,
            Emission::Ht20NestedBa => feature::BA | feature::NESTED_BA,
            Emission::Features(bits) => bits,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowerRequest {
    pub name: String,
    pub binding: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerStatus {
    pub channel: u8,
    pub conducted_eighth_dbm: i16,
    pub qualification_digest: [u8; 32],
}

pub(super) struct Context {
    reduced_v5: bool,
    pub(super) nvm_permissions: Option<Vec<u32>>,
    pub(super) prepared: Option<Prepared>,
    pub(super) phy: super::phy::Context,
}
impl Context {
    pub(super) fn new(api: &FirmwareApi<'_>) -> Self {
        Self {
            reduced_v5: api.api_changes[1] & (1 << 13) != 0,
            nvm_permissions: None,
            prepared: None,
            phy: super::phy::Context::default(),
        }
    }
}

pub(super) struct Prepared {
    pub(super) emission: Emission,
    source: Asset,
    sar: [[u8; 5]; 2],
    maximum: i16,
    gain: i16,
    channel: u8,
    /// The secondary channel of a granted 40MHz operation; every power
    /// decision then covers the whole occupied span.
    span: Option<u8>,
    applied: Option<i16>,
    pub(super) active_link: Option<super::link::ActiveLinkStatus>,
    pub(super) mlme: super::assoc::Context,
    pub(super) stop: Option<Arc<AtomicBool>>,
}

/// Host power for the primary channel, or for a 40MHz span: the lower of
/// both 20MHz subchannels and of the rules covering the whole 40MHz
/// interval, each of which must permit a 40MHz bandwidth and initiation
/// (the conservative single-rule form of cfg80211 `reg_does_bw_fit`).
pub(super) fn span_power(domain: &RegulatoryDomain, channel: u8, span: Option<u8>) -> Option<i8> {
    use super::super::connection::host_channel_power;
    let primary = host_channel_power(domain, channel, true)?;
    let Some(secondary) = span else {
        return Some(primary);
    };
    if channel.abs_diff(secondary) != 4 || (channel <= 14) != (secondary <= 14) {
        return None;
    }
    let mut power = primary.min(host_channel_power(domain, secondary, true)?);
    let base = if channel <= 14 { 2407 } else { 5000 };
    let center = base + 5 * (u32::from(channel) + u32::from(secondary)) / 2;
    let (low, high) = (center - 20, center + 20);
    let mut covering = false;
    for rule in &domain.rules {
        if rule.freq_end_mhz <= low || rule.freq_start_mhz >= high {
            continue;
        }
        if rule.freq_end_mhz <= rule.freq_start_mhz
            || rule.max_bandwidth_mhz < 40
            || rule.flags.contains(narf_wireless::reg::RegFlags::NO_IR)
        {
            return None;
        }
        covering |= rule.freq_start_mhz <= low && rule.freq_end_mhz >= high;
        power = power.min(rule.max_power_dbm);
    }
    covering.then_some(power)
}

impl Prepared {
    /// Bind the 40MHz span of a granted HT40 program.
    pub(super) fn with_span(mut self, span: Option<u8>) -> Self {
        self.span = span;
        self
    }
    pub(super) fn host_ceiling(&self, domain: &RegulatoryDomain) -> Result<i16, &'static str> {
        if !self.source.current() || !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err("MVM platform power authority or host policy is no longer valid");
        }
        let power = span_power(domain, self.channel, self.span)
            .ok_or("MVM current host channel prohibits initial transmit-power preparation")?;
        let applied = (i16::from(power) * 8)
            .checked_sub(self.gain)
            .ok_or("MVM antenna power arithmetic overflow")?
            .min(self.maximum);
        if !(-1024..=1016).contains(&applied) {
            return Err("MVM current radiated ceiling is outside the supported power range");
        }
        Ok(applied)
    }

    /// A ready receipt is historical metadata. Every active command waiter
    /// must retain/check this actual source instance and its applied ceiling.
    pub(super) fn check_applied(&self, domain: &RegulatoryDomain) -> Result<(), &'static str> {
        let applied = self
            .applied
            .ok_or("MVM link power has no completed native receipt")?;
        if self.host_ceiling(domain)? < applied {
            return Err("MVM current host policy is below acknowledged link power");
        }
        Ok(())
    }
}

fn request(binding: [u8; 32], mac: [u8; 6], emission: Emission) -> PowerRequest {
    let features;
    let program = match emission {
        Emission::Legacy => "mvm-api77-power-v1",
        Emission::Ht20 => "mvm-api77-ht20-siso-wmm-power-v2",
        Emission::Ht20Ba => "mvm-api77-ht20-siso-wmm-ba-power-v3",
        Emission::Ht20NestedBa => "mvm-api77-ht20-siso-wmm-nested-ba-power-v4",
        Emission::Features(bits) => {
            features = format!("mvm-api77-ht20-siso-wmm-features-{bits:04x}-power-v5");
            &features
        }
    };
    PowerRequest {
        name: format!(
            "iwlwifi/{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            program, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
        binding,
    }
}

pub(super) fn parse(
    source: Asset,
    binding: [u8; 32],
    mac: [u8; 6],
    channel: u8,
) -> Result<Prepared, &'static str> {
    parse_for(source, binding, mac, channel, Emission::Legacy)
}
pub(super) fn parse_for(
    source: Asset,
    binding: [u8; 32],
    mac: [u8; 6],
    channel: u8,
    emission: Emission,
) -> Result<Prepared, &'static str> {
    let values = validate_record(&source, binding, mac, emission)?;
    Ok(Prepared {
        emission,
        source,
        sar: values.sar,
        maximum: values.maximum,
        gain: values.gain,
        channel,
        span: None,
        applied: None,
        active_link: None,
        mlme: super::assoc::Context::default(),
        stop: None,
    })
}

pub(super) struct Values {
    sar: [[u8; 5]; 2],
    maximum: i16,
    gain: i16,
}
pub(super) fn validate_record(
    source: &Asset,
    binding: [u8; 32],
    mac: [u8; 6],
    emission: Emission,
) -> Result<Values, &'static str> {
    let bytes = &source.bytes;
    if let Emission::Features(bits) = emission {
        if bits == 0
            || bits & !feature::KNOWN != 0
            || bits & feature::NESTED_BA != 0 && bits & feature::BA == 0
        {
            return Err("MVM feature program names an unsupported emission set");
        }
    }
    if !source.current() || source.signer.is_none() {
        return Err("MVM platform power qualification is unsigned or revoked");
    }
    if bytes.len() != RECORD_LEN
        || bytes[..4] != *b"NIPW"
        || bytes[4..8] != [1, 0, RECORD_LEN as u8, 0]
        || bytes[8..40] != binding
        || bytes[40..46] != mac
        || bytes[46..48] != [emission.tag(), 0]
        || bytes[62..64]
            != match emission {
                Emission::Features(bits) => bits.to_le_bytes(),
                _ => [0; 2],
            }
    {
        return Err("MVM platform power qualification format or identity mismatch");
    }
    let maximum = i16::from_le_bytes(bytes[58..60].try_into().unwrap());
    let gain = i16::from_le_bytes(bytes[60..62].try_into().unwrap());
    if !(-1024..=1016).contains(&maximum) || !(0..=512).contains(&gain) {
        return Err("MVM platform power qualification contains unsupported limits");
    }
    let sar = [
        bytes[48..53].try_into().unwrap(),
        bytes[53..58].try_into().unwrap(),
    ];
    Ok(Values { sar, maximum, gain })
}

/// Current-operation publication contract copied only from an acknowledged
/// native power owner. It retains the actual signed source, not a ready bit.
#[derive(Clone)]
pub(in crate::iwlwifi) struct Fence {
    cap: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    maximum: i16,
    gain: i16,
    channel: u8,
    span: Option<u8>,
    applied: i16,
    stop: Option<Arc<AtomicBool>>,
}
impl Fence {
    pub(in crate::iwlwifi) fn invoke<T>(
        &self,
        domain: &RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        use narf_capabilities::{Cap, CapError, CapOp, Read};
        struct Live<'a, F> {
            fence: &'a Fence,
            domain: &'a RegulatoryDomain,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, &'static str>> CapOp<narf_firmware::FirmwareBlob, Read>
            for Live<'_, F>
        {
            type Output = Result<T, &'static str>;
            fn execute(
                self,
                _: &Cap<narf_firmware::FirmwareBlob, Read>,
            ) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let f = self.fence;
                    if f.stop.as_ref().is_some_and(|s| s.load(Ordering::Acquire))
                        || !self.domain.country_code.iter().all(u8::is_ascii_uppercase)
                    {
                        return Err("MVM current station publication is closed");
                    }
                    let power = span_power(self.domain, f.channel, f.span)
                        .ok_or("MVM current publication channel prohibited")?;
                    let ceiling = (i16::from(power) * 8)
                        .checked_sub(f.gain)
                        .ok_or("MVM current publication power overflow")?
                        .min(f.maximum);
                    if ceiling < f.applied {
                        return Err("MVM current publication ceiling tightened");
                    }
                    (self.operation)()
                })())
            }
        }
        self.cap
            .invoke(Live {
                fence: self,
                domain,
                operation,
            })
            .map_err(|_| "MVM publication power source revoked")?
    }
}
impl Prepared {
    pub(super) fn fence(&self) -> Result<Fence, &'static str> {
        Ok(Fence {
            cap: self.source.cap,
            maximum: self.maximum,
            gain: self.gain,
            channel: self.channel,
            span: self.span,
            applied: self.applied.ok_or("MVM power not acknowledged")?,
            stop: self.stop.clone(),
        })
    }
}

/// Fixed legacy v5 prefix, not the Gen3 v10/v11 structure. Linux computes
/// sizeof(common)+sizeof(per_band)+sizeof(v5), and RAW WRDS values are eighth-dBm.
fn chain_command(sar: [[u8; 5]; 2]) -> [u8; 44] {
    let mut body = [0; 44];
    put32(&mut body, 0, 2); // IWL_TX_POWER_MODE_SET_CHAINS
    for (index, limit) in sar.into_iter().flatten().enumerate() {
        put16(&mut body, 16 + index * 2, u16::from(limit));
    }
    body
}
fn link_command(power: i16) -> [u8; 44] {
    let mut body = [0; 44];
    // SET_LINK, MAC0 on pre-v9 firmware; remaining mode-specific fields zero.
    body[8..10].copy_from_slice(&power.to_le_bytes());
    body
}

fn platform_digest() -> Result<[u8; 32], &'static str> {
    use narf_firmware_smbios::{SmbiosBaseboard, SmbiosBios, SmbiosSystem};
    let mut systems = [SmbiosSystem::ZERO; 2];
    let mut boards = [SmbiosBaseboard::ZERO; 2];
    let mut bios = [SmbiosBios::ZERO; 2];
    if !narf_firmware_smbios::is_known()
        || narf_firmware_smbios::copy_system(&mut systems) != 1
        || narf_firmware_smbios::copy_baseboard(&mut boards) != 1
        || narf_firmware_smbios::copy_bios(&mut bios) != 1
    {
        return Err("MVM platform power requires unambiguous SMBIOS system/board/BIOS identity");
    }
    let system = systems[0];
    let board = boards[0];
    let bios = bios[0];
    if system.uuid == [0; 16]
        || system.uuid == [255; 16]
        || system.manufacturer[0] == 0
        || system.product_name[0] == 0
        || board.manufacturer[0] == 0
        || board.product[0] == 0
        || bios.vendor[0] == 0
        || bios.version[0] == 0
    {
        return Err("MVM platform power identity is incomplete");
    }
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF Intel MVM platform identity v1");
    for value in [
        &system.manufacturer[..],
        &system.product_name,
        &system.version,
        &system.serial_number,
        &system.uuid,
        &board.manufacturer,
        &board.product,
        &board.version,
        &board.serial,
        &bios.vendor,
        &bios.version,
        &bios.release_date,
    ] {
        hash.update(value);
    }
    Ok(hash.finalize())
}

impl Owner {
    /// Exact physical/firmware/platform binding requested from the image
    /// builder. Identification grants no calibration or transmit authority.
    pub fn transmit_power_request(&mut self) -> Result<PowerRequest, &'static str> {
        self.transmit_power_request_for(Emission::Legacy)
    }
    pub(in crate::iwlwifi) fn transmit_power_request_for(
        &mut self,
        emission: Emission,
    ) -> Result<PowerRequest, &'static str> {
        let mac = self.mac.ok_or("MVM power identity is not initialized")?;
        let nvm = self
            .nvm
            .as_ref()
            .ok_or("MVM power NVM is not initialized")?;
        if self.hardware.is_failed() {
            return Err("MVM power transport failed");
        }
        let (profile, facts) = self.hardware.gen2_power_facts()?;
        if profile != self.profile {
            return Err("MVM power hardware profile changed");
        }
        let mut image = narf_crypto::sha256::Sha256::new();
        image.update(&self.firmware);
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(match emission {
            Emission::Legacy => &b"NARF Intel MVM API77 qualified static legacy20 power v1"[..],
            Emission::Ht20 => {
                &b"NARF Intel MVM API77 qualified static HT20 SISO MCS0-7 SGI20 WMM-BE power v2"[..]
            }
            Emission::Ht20Ba => {
                &b"NARF Intel MVM API77 qualified HT20 SISO MCS0-7 SGI20 WMM-BE TID0 TX-BA pipeline8 RX-BA32 control power v3"[..]
            }
            Emission::Ht20NestedBa => {
                &b"NARF Intel MVM API77 qualified HT20 SISO MCS0-7 SGI20 WMM-BE TID0 TX-BA pipeline8 RX-BA32 nested-AMSDU3839 control power v4"[..]
            }
            Emission::Features(_) => {
                &b"NARF Intel MVM API77 qualified HT20 SISO MCS0-7 SGI20 WMM feature program power v5"[..]
            }
        });
        if let Emission::Features(bits) = emission {
            hash.update(&bits.to_le_bytes());
        }
        hash.update(&facts);
        hash.update(&mac);
        hash.update(&nvm.tx_chains.to_le_bytes());
        hash.update(&nvm.rx_chains.to_le_bytes());
        hash.update(profile.prefix.as_bytes());
        hash.update(&image.finalize());
        hash.update(&platform_digest()?);
        Ok(request(hash.finalize(), mac, emission))
    }

    pub fn prepared_transmit_power(&self) -> Option<PowerStatus> {
        if !matches!(
            self.phase,
            Phase::TransmitPowerPrepared
                | Phase::LinkActive
                | Phase::Associated
                | Phase::DataPrepared
        ) || self.hardware.is_failed()
        {
            return None;
        }
        let prepared = self.power.prepared.as_ref()?;
        if !prepared.source.current() {
            return None;
        }
        Some(PowerStatus {
            channel: prepared.channel,
            conducted_eighth_dbm: prepared.applied?,
            qualification_digest: prepared.source.digest,
        })
    }

    /// Load only the signed exact-platform qualification. It must certify
    /// actual conservative SAR limits and the radiated-gain envelope across
    /// every platform posture/state; this driver invents no absent-BIOS policy.
    pub async fn prepare_transmit_power(&mut self) -> Result<(), &'static str> {
        let request = self.transmit_power_request()?;
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or("MVM platform power firmware authority unavailable")?;
        let source = crate::firmware_asset::load(&authority, &request.name, RECORD_LEN, true)
            .map_err(|_| "MVM signed platform power qualification unavailable")?;
        self.prepare_power_using(source, request.binding, || {
            narf_wireless::reg::db::get_domain()
                .ok_or("MVM current host transmit policy unavailable")
        })
        .await
    }

    pub(super) async fn prepare_power_using(
        &mut self,
        source: Asset,
        binding: [u8; 32],
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::ManagementQueuePrepared
            || self.hardware.is_failed()
            || self.prepared_management_queue().is_none()
            || self.power.prepared.is_some()
        {
            return Err("MVM power preparation requires its unused native management queue");
        }
        if !self.power.reduced_v5 || self.hardware.version(1, REDUCE_TX_POWER) != Some((5, 0)) {
            return Err("unsupported MVM platform power command API");
        }
        let channel = self
            .channel
            .current
            .ok_or("MVM power requires retained inactive PHY")?;
        let nvm = self.nvm.as_ref().ok_or("MVM power NVM unavailable")?;
        if !nvm.channels.contains(&channel) || self.power.nvm_permissions.is_none() {
            return Err("MVM power channel lacks actual retained NVM permission");
        }
        let prepared = if self.power.phy.emission() == Emission::Legacy {
            parse(
                source,
                binding,
                self.mac.ok_or("MVM power MAC unavailable")?,
                channel,
            )?
        } else {
            parse_for(
                source,
                binding,
                self.mac.ok_or("MVM power MAC unavailable")?,
                channel,
                self.power.phy.emission(),
            )?
        }
        .with_span(self.power.phy.span());
        let domain = policy()?;
        if !domain.country_code.iter().all(u8::is_ascii_uppercase)
            || span_power(&domain, channel, self.power.phy.span()).is_none()
        {
            return Err("MVM platform power prohibited by current host policy");
        }
        self.power.prepared = Some(prepared);
        self.phase = Phase::PreparingTransmitPower;
        let result = self.prepare_power_inner(&mut policy).await;
        match result {
            Ok(applied) => {
                self.power.prepared.as_mut().unwrap().applied = Some(applied);
                self.phase = Phase::TransmitPowerPrepared;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    pub(super) fn current_power(&self, domain: &RegulatoryDomain) -> Result<i16, &'static str> {
        let prepared = self
            .power
            .prepared
            .as_ref()
            .ok_or("MVM power input was not retained")?;
        if !prepared.source.current() || !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err("MVM platform power authority or host policy is no longer valid");
        }
        let index = super::super::station_api::channel_index(prepared.channel)
            .ok_or("MVM power channel has no firmware index")?;
        let (permissions, ibss_required) = if let Some(current) = self.scan.permissions.as_ref() {
            (current, false)
        } else {
            (
                self.power
                    .nvm_permissions
                    .as_ref()
                    .ok_or("MVM current firmware transmit permission unavailable")?,
                true,
            )
        };
        let flags = *permissions
            .get(index)
            .ok_or("MVM current power channel absent from firmware")?;
        // iwl-nvm-parse.h: VALID, ACTIVE and 20MHz; a non-LAR NVM profile
        // additionally requires IBSS because Linux maps its absence to NO_IR.
        // This initial power stage has no DFS/beacon-hint relaxation.
        let required = 1 | (1 << 3) | (1 << 8) | if ibss_required { 1 << 1 } else { 0 };
        if flags & required != required || flags & (1 << 4) != 0 {
            return Err(
                "MVM current firmware channel prohibits initial transmit-power preparation",
            );
        }
        if let Some(secondary) = prepared.span {
            // NVM_CHANNEL_40MHZ (bit 9) on both subchannels, and the
            // secondary carries the same transmit permissions.
            let wide = super::super::station_api::channel_index(secondary)
                .and_then(|index| permissions.get(index).copied())
                .ok_or("MVM current 40MHz secondary absent from firmware")?;
            let required = required | (1 << 9);
            if flags & required != required || wide & required != required || wide & (1 << 4) != 0 {
                return Err("MVM current firmware channel prohibits the 40MHz span");
            }
        }
        prepared.host_ceiling(domain)
    }

    async fn prepare_power_inner(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<i16, &'static str> {
        // A prior successful scan grants no permanent country/channel right.
        if !self.power.prepared.as_ref().unwrap().source.current() {
            return Err("MVM platform power authority revoked before MCC query");
        }
        self.refresh_mcc().await?;
        self.current_power(&policy()?)?;
        let chains = chain_command(self.power.prepared.as_ref().unwrap().sar);
        let reply = self.hardware.command(1, REDUCE_TX_POWER, &chains).await?;
        if !reply.payload.is_empty() {
            return Err("invalid MVM SAR command receipt");
        }
        let applied = self.current_power(&policy()?)?;
        let reply = self
            .hardware
            .command(1, REDUCE_TX_POWER, &link_command(applied))
            .await?;
        if !reply.payload.is_empty() {
            return Err("invalid MVM link power command receipt");
        }
        if self.current_power(&policy()?)? < applied {
            return Err("MVM host power policy tightened during firmware programming");
        }
        Ok(applied)
    }

    /// Forget power admission while PHY/peer TX are still inactive. Firmware
    /// restrictions remain in place; this never sends a permissive reset. A
    /// later station attempt must earn fresh qualification/policy/receipts.
    pub fn release_transmit_power(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::TransmitPowerPrepared
            || self.hardware.is_failed()
            || self
                .power
                .prepared
                .as_ref()
                .is_some_and(|power| power.active_link.is_some())
        {
            return Err("MVM owner has no completed inactive transmit-power preparation");
        }
        self.power.prepared = None;
        self.power.phy = super::phy::Context::default();
        self.phase = Phase::ManagementQueuePrepared;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_power_tests.rs"]
pub(super) mod tests;
