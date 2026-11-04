// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Optional native MLD BIOS SAR inputs, following Linux fw/{acpi,uefi,
//! regulatory}.c and mld/regulatory.c. Absent/disabled profiles leave the
//! calibrated firmware/NVM policy in force; they create no host measurement.
use alloc::vec::Vec;
use narf_aml::Value;

fn revision(value: &Value) -> Result<u8, &'static str> {
    match value {
        Value::Package(entries) if entries.len() >= 2 => integer(&entries[0]),
        _ => Err("Intel BIOS table has no revision/data package"),
    }
}
fn integer(value: &Value) -> Result<u8, &'static str> {
    match value {
        Value::Integer(value) => u8::try_from(*value).map_err(|_| "Intel BIOS value exceeds byte"),
        _ => Err("Intel BIOS value is not an integer"),
    }
}
fn wifi(value: &Value, size: usize) -> Result<&[Value], &'static str> {
    let Value::Package(entries) = value else {
        return Err("Intel BIOS table is not a package");
    };
    entries[1..]
        .iter()
        .find_map(|entry| match entry {
            Value::Package(fields)
                if fields.len() == size && fields.first() == Some(&Value::Integer(7)) =>
            {
                Some(fields.as_slice())
            }
            _ => None,
        })
        .ok_or("Intel BIOS table has no correctly sized Wi-Fi domain")
}
fn bands(version: u8) -> Result<usize, &'static str> {
    match version {
        5 => Ok(5),
        8 | 10 => Ok(11),
        11 => Ok(12),
        _ => Err("unsupported Intel MLD REDUCE_TX_POWER version"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Sar {
    enabled: bool,
    flags: u32,
    chains: [[u8; 12]; 4],
}
impl Sar {
    /// WRDS revisions0/1 carry A/B; revisions2/3 additionally carry CDB A/B.
    /// Missing higher subbands are zero-filled exactly as Linux parses them.
    pub fn acpi(value: &Value) -> Result<Self, &'static str> {
        let (chains, bands) = match revision(value)? {
            0 => (2, 5),
            1 => (2, 11),
            2 => (4, 11),
            3 => (4, 12),
            _ => return Err("unsupported Intel ACPI WRDS revision"),
        };
        let fields = wifi(value, 2 + chains * bands)?;
        let Value::Integer(flags) = fields[1] else {
            return Err("Intel ACPI WRDS flags are not an integer");
        };
        let mut sar = Self {
            enabled: flags & 1 != 0,
            flags: (flags as u32) >> 1,
            chains: [[0; 12]; 4],
        };
        for (chain, out) in sar.chains[..chains].iter_mut().enumerate() {
            for (band, value) in out[..bands].iter_mut().enumerate() {
                *value = integer(&fields[2 + chain * bands + band])?;
            }
        }
        Ok(sar)
    }
    /// Payload after the real UEFI provider's signature/hash verification.
    /// This decoder itself never establishes that verification or authority.
    pub fn uefi(bytes: &[u8]) -> Result<Self, &'static str> {
        let count = match bytes.first() {
            Some(2) => 11,
            Some(3) => 12,
            _ => return Err("unsupported Intel UEFI WRDS revision"),
        };
        if bytes.len() != 5 + 4 * count {
            return Err("Intel UEFI WRDS extent mismatch");
        }
        let mode = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        let mut sar = Self {
            enabled: mode & 1 != 0,
            // Linux's UEFI WRDS parser only adopts the profile-enable bit.
            flags: 0,
            chains: [[0; 12]; 4],
        };
        for (chain, out) in sar.chains.iter_mut().enumerate() {
            out[..count].copy_from_slice(&bytes[5 + chain * count..5 + (chain + 1) * count]);
        }
        Ok(sar)
    }
    pub fn command(&self, version: u8) -> Result<Option<Vec<u8>>, &'static str> {
        let bands = bands(version)?;
        if !self.enabled {
            // iwl_sar_fill_table returns1: no SAR command is sent. Do not
            // synthesize an all-zero replacement or an enabling default.
            return Ok(None);
        }
        let (length, first, flags) = match version {
            5 => (44, 16, None),
            8 => (120, 16, Some(112)),
            10 => (108, 10, Some(104)),
            11 => (116, 10, Some(112)),
            _ => return Err("unsupported native SAR profile"),
        };
        let mut body = alloc::vec![0; length];
        body[0] = 2; // IWL_TX_POWER_MODE_SET_CHAINS
        for (chain, values) in self.chains[..2].iter().enumerate() {
            for (band, value) in values[..bands].iter().enumerate() {
                let at = first + 2 * (chain * bands + band);
                body[at..at + 2].copy_from_slice(&u16::from(*value).to_le_bytes());
            }
        }
        // Linux currently fills IWL_NUM_CHAIN_TABLES=1. CDB remains zero,
        // even when the BIOS supplied the extra chains in its newer format.
        if let Some(at) = flags {
            body[at..at + 4].copy_from_slice(&self.flags.to_le_bytes());
        }
        Ok(Some(body))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct GeoBand {
    maximum: u8,
    chains: [u8; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Geo {
    revision: u8,
    source: u8,
    profiles: [[GeoBand; 4]; 8],
}
impl Geo {
    pub fn acpi(value: &Value) -> Result<Self, &'static str> {
        let revision = revision(value)?;
        let (bands, capacity, header) = match revision {
            0 | 1 => (2, 3, 1),
            2 => (3, 3, 1),
            3 => (3, 8, 2),
            4 => (4, 8, 2),
            _ => return Err("unsupported Intel ACPI WGDS revision"),
        };
        let fields = wifi(value, header + capacity * bands * 3)?;
        let profiles = if header == 2 {
            usize::from(integer(&fields[1])?)
        } else {
            capacity
        };
        if !(3..=capacity).contains(&profiles) {
            return Err("Intel ACPI WGDS profile count outside native bounds");
        }
        let mut geo = Self {
            revision,
            source: 1,
            profiles: [[GeoBand::default(); 4]; 8],
        };
        for (profile, out) in geo.profiles[..profiles].iter_mut().enumerate() {
            for (band, value) in out[..bands].iter_mut().enumerate() {
                let at = header + (profile * bands + band) * 3;
                *value = GeoBand {
                    maximum: integer(&fields[at])?,
                    chains: [integer(&fields[at + 1])?, integer(&fields[at + 2])?],
                };
            }
            // Linux extends older tables'5GHz values to missing6GHz bands.
            for band in bands..4 {
                out[band] = out[1];
            }
        }
        Ok(geo)
    }
    /// Already verified UEFI WGDS payload, not an authentication operation.
    pub fn uefi(bytes: &[u8]) -> Result<Self, &'static str> {
        let bands = match bytes.first() {
            Some(3) => 3,
            Some(4) => 4,
            _ => return Err("unsupported Intel UEFI WGDS revision"),
        };
        if bytes.len() != 2 + 8 * bands * 3 || !(3..=8).contains(&bytes[1]) {
            return Err("Intel UEFI WGDS extent/profile count mismatch");
        }
        let mut geo = Self {
            revision: bytes[0],
            source: 2,
            profiles: [[GeoBand::default(); 4]; 8],
        };
        for (profile, out) in geo.profiles[..usize::from(bytes[1])].iter_mut().enumerate() {
            for (band, value) in out[..bands].iter_mut().enumerate() {
                let at = 2 + (profile * bands + band) * 3;
                *value = GeoBand {
                    maximum: bytes[at],
                    chains: [bytes[at + 1], bytes[at + 2]],
                };
            }
            // Unlike ACPI's parser, Linux's UEFI path leaves absent bands0.
        }
        Ok(geo)
    }
    pub fn command(&self, version: u8) -> Result<Vec<u8>, &'static str> {
        let count = match version {
            5 => 3,
            6 => 4,
            _ => return Err("unsupported Intel MLD PER_CHAIN_LIMIT_OFFSET version"),
        };
        let mut body = alloc::vec![0;4+8*count*4+4];
        // ops0 = IWL_PER_CHAIN_OFFSET_SET_TABLES
        for (profile, values) in self.profiles.iter().enumerate() {
            for (band, value) in values[..count].iter().enumerate() {
                let at = 4 + (profile * count + band) * 4;
                body[at..at + 2].copy_from_slice(&u16::from(value.maximum).to_le_bytes());
                body[at + 2..at + 4].copy_from_slice(&value.chains);
            }
        }
        let at = body.len() - 4;
        if version == 5 {
            body[at..].copy_from_slice(&u32::from(self.revision == 1).to_le_bytes());
        } else {
            body[at..].copy_from_slice(&[self.source, self.revision, 0, 0]);
        }
        Ok(body)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Ppag {
    revision: u8,
    source: u8,
    flags: u32,
    gain: [[u8; 12]; 2],
}
impl Ppag {
    pub fn source(&self) -> u8 {
        self.source
    }
    /// Linux's zero-initialized fwrt when a DMI-approved machine has no
    /// usable PPAG table. Mode0 disables PPAG; gains0 grant no feature.
    pub fn disabled() -> Self {
        Self {
            revision: 0,
            source: 0,
            flags: 0,
            gain: [[0; 12]; 2],
        }
    }
    pub fn acpi(value: &Value) -> Result<Self, &'static str> {
        let revision = revision(value)?;
        let bands = match revision {
            0 => 5,
            1..=4 => 11,
            5 => 12,
            _ => return Err("unsupported Intel ACPI PPAG revision"),
        };
        let fields = wifi(value, 2 + 2 * bands)?;
        let Value::Integer(mode) = fields[1] else {
            return Err("Intel ACPI PPAG mode is not an integer");
        };
        let mut ppag = Self {
            revision,
            source: 1,
            flags: Self::flags(revision, mode as u32),
            gain: [[0; 12]; 2],
        };
        for (chain, out) in ppag.gain.iter_mut().enumerate() {
            for (band, value) in out[..bands].iter_mut().enumerate() {
                let Value::Integer(raw) = fields[2 + chain * bands + band] else {
                    return Err("Intel ACPI PPAG gain is not an integer");
                };
                // The BIOS integer can encode a signed s8. Linux adopts its
                // low byte, without replacing absent platform measurements.
                *value = raw as u8;
            }
        }
        Ok(ppag)
    }
    pub fn uefi(bytes: &[u8]) -> Result<Self, &'static str> {
        let bands = match bytes.first() {
            Some(4) => 11,
            Some(5) => 12,
            _ => return Err("unsupported Intel UEFI PPAG revision"),
        };
        if bytes.len() != 5 + 2 * bands {
            return Err("Intel UEFI PPAG extent mismatch");
        }
        let mut ppag = Self {
            revision: bytes[0],
            source: 2,
            flags: Self::flags(
                bytes[0],
                u32::from_le_bytes(bytes[1..5].try_into().unwrap()),
            ),
            gain: [[0; 12]; 2],
        };
        for (chain, out) in ppag.gain.iter_mut().enumerate() {
            out[..bands].copy_from_slice(&bytes[5 + chain * bands..5 + (chain + 1) * bands]);
        }
        Ok(ppag)
    }
    fn flags(revision: u8, flags: u32) -> u32 {
        match revision {
            0..=2 => flags & 3,
            3 => flags & 0x7ff,
            _ => flags,
        }
    }
    pub fn command(
        &self,
        version: u8,
        supported_bios: u8,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        if version == 5 {
            let mut body = alloc::vec![0;28];
            body[..4].copy_from_slice(&(self.flags & 0x27).to_le_bytes());
            for (chain, gain) in self.gain.iter().enumerate() {
                body[4 + chain * 11..15 + chain * 11].copy_from_slice(&gain[..11]);
            }
            return Ok(Some(body));
        }
        let bands = match version {
            7 => 11,
            8 => 12,
            _ => return Err("unsupported Intel MLD PER_PLATFORM_ANT_GAIN version"),
        };
        if self.revision > supported_bios {
            // Linux warns and skips a table newer than firmware supports.
            return Ok(None);
        }
        let mut body = alloc::vec![0;32];
        body[..4].copy_from_slice(&[self.source, self.revision, 0, 0]);
        body[4..8].copy_from_slice(&self.flags.to_le_bytes());
        for (chain, gain) in self.gain.iter().enumerate() {
            body[8 + chain * bands..8 + (chain + 1) * bands].copy_from_slice(&gain[..bands]);
        }
        Ok(Some(body))
    }
}

/// Linux's DMI PPAG allowlist. Metadata controls this optional feature,
/// never admission to a radio or creation of a power/SAR measurement.
pub(super) fn ppag_approved(system: &[u8], board: &[u8]) -> bool {
    let contains = |bytes: &[u8], text: &[u8]| bytes.windows(text.len()).any(|part| part == text);
    [
        b"HP".as_slice(),
        b"SAMSUNG ELECTRONICS CO., LTD",
        b"Microsoft Corporation",
        b"ASUSTeK COMPUTER INC.",
        b"ASUS",
        b"Dell Inc.",
        b"Alienware",
        b"Razer",
        b"HONOR",
        b"WIKO",
        b"XIAOMI",
    ]
    .iter()
    .any(|vendor| contains(system, vendor))
        || contains(system, b"Google")
            && [
                b"HP".as_slice(),
                b"ASUSTek COMPUTER INC.",
                b"SAMSUNG ELECTRONICS CO., LTD",
            ]
            .iter()
            .any(|vendor| contains(board, vendor))
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum InputStatus {
    #[default]
    NotRead,
    Absent,
    Present,
    Invalid,
    Authority,
    Unavailable,
    Ambiguous,
    Firmware,
}
pub(super) type InputRead = Result<Option<Value>, InputStatus>;

/// Owned BIOS snapshots are data, not a new radio/platform grant. The
/// metadata facade performs each real method under its current authorities.
#[derive(Clone, Debug, Default)]
pub(super) struct Inputs {
    pub sar: Option<Sar>,
    pub geo: Option<Geo>,
    pub ppag: Option<Ppag>,
    pub ppag_approved: bool,
    /// EWRD profiles are not selected by MLD's default A/B profile1.
    pub ewrd: Option<Value>,
    /// WRDS, EWRD, WGDS, PPAG retrieval/decoding facts respectively.
    pub status: [InputStatus; 4],
}
impl Inputs {
    pub fn decoded(
        wrds: InputRead,
        ewrd: InputRead,
        wgds: InputRead,
        ppag: InputRead,
        ppag_approved: bool,
    ) -> Self {
        fn parse<T>(
            read: InputRead,
            parse: impl FnOnce(&Value) -> Result<T, &'static str>,
        ) -> (Option<T>, InputStatus) {
            match read {
                Ok(Some(value)) => match parse(&value) {
                    Ok(value) => (Some(value), InputStatus::Present),
                    Err(_) => (None, InputStatus::Invalid),
                },
                Ok(None) => (None, InputStatus::Absent),
                Err(error) => (None, error),
            }
        }
        let (sar, wrds) = parse(wrds, Sar::acpi);
        let (geo, wgds) = parse(wgds, Geo::acpi);
        let (ppag, ppag_status) = parse(ppag, Ppag::acpi);
        let (ewrd, ewrd_status) = match ewrd {
            Ok(Some(value)) => (Some(value), InputStatus::Present),
            Ok(None) => (None, InputStatus::Absent),
            Err(error) => (None, error),
        };
        Self {
            sar,
            geo,
            ppag,
            ppag_approved,
            ewrd,
            status: [wrds, ewrd_status, wgds, ppag_status],
        }
    }
    pub fn unavailable(error: InputStatus) -> Self {
        Self {
            status: [error; 4],
            ..Self::default()
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn table(revision: u8, fields: Vec<Value>) -> Value {
        Value::Package(alloc::vec![
            Value::Integer(u64::from(revision)),
            Value::Package(fields)
        ])
    }
    fn smoke_iwl_mld_wrds_optional_profile_and_native_v10_v11_literals() -> TestResult {
        for (revision, chains, bands) in [(0, 2, 5), (1, 2, 11), (2, 4, 11), (3, 4, 12)] {
            let mut fields = alloc::vec![Value::Integer(7), Value::Integer(0x0b)];
            fields.extend((0..chains * bands).map(|i| Value::Integer(40 + i as u64)));
            let input = table(revision, fields.clone());
            let sar = Sar::acpi(&input).unwrap();
            for version in [10, 11] {
                let body = sar.command(version).unwrap().unwrap();
                let native_bands = if version == 10 { 11 } else { 12 };
                if body.len() != if version == 10 { 108 } else { 116 }
                    || body[..10] != [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    || body[body.len() - 4..] != [5, 0, 0, 0]
                    || body[10 + 4 * native_bands..body.len() - 4]
                        .iter()
                        .any(|v| *v != 0)
                {
                    return TestResult::Fail("WRDS native mode/offset/flags/CDB extent");
                }
                for chain in 0..2 {
                    for band in 0..native_bands {
                        let at = 10 + 2 * (chain * native_bands + band);
                        let expected = if band < bands {
                            40 + (chain * bands + band) as u16
                        } else {
                            0
                        };
                        if body[at..at + 2] != expected.to_le_bytes() {
                            return TestResult::Fail(
                                "WRDS chain/subband mapping or missing-band value",
                            );
                        }
                    }
                }
            }
            fields[1] = Value::Integer(0);
            if Sar::acpi(&table(revision, fields))
                .unwrap()
                .command(10)
                .unwrap()
                .is_some()
            {
                return TestResult::Fail("disabled BIOS SAR synthesized a firmware command");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/power",
        smoke_iwl_mld_wrds_optional_profile_and_native_v10_v11_literals
    );
    fn smoke_iwl_mld_wgds_native_geo_revision_source_and_padding() -> TestResult {
        for revision in 0..=4 {
            let bands = match revision {
                0 | 1 => 2,
                2 | 3 => 3,
                _ => 4,
            };
            let capacity = if revision < 3 { 3 } else { 8 };
            let mut fields = alloc::vec![Value::Integer(7)];
            if revision >= 3 {
                fields.push(Value::Integer(3));
            }
            fields.extend((0..capacity * bands * 3).map(|i| Value::Integer(20 + i as u64)));
            let geo = Geo::acpi(&table(revision, fields)).unwrap();
            for version in [5, 6] {
                let body = geo.command(version).unwrap();
                if body.len() != if version == 5 { 104 } else { 136 }
                    || body[..8] != [0, 0, 0, 0, 20, 0, 21, 22]
                    || body[body.len() - 4..]
                        != if version == 5 {
                            [u8::from(revision == 1), 0, 0, 0]
                        } else {
                            [1, revision, 0, 0]
                        }
                {
                    return TestResult::Fail("WGDS native GEO command extent/source/revision");
                }
                if body[4 + 3 * (if version == 5 { 3 } else { 4 }) * 4..body.len() - 4]
                    .iter()
                    .any(|v| *v != 0)
                {
                    return TestResult::Fail("WGDS unused native profiles were invented");
                }
            }
            if geo.profiles[0][3] != geo.profiles[0][1] && bands < 4 {
                return TestResult::Fail("older WGDS missing-band mapping differs from Linux");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/power",
        smoke_iwl_mld_wgds_native_geo_revision_source_and_padding
    );

    fn smoke_iwl_mld_uefi_sar_geo_payloads_preserve_source_specific_padding() -> TestResult {
        for revision in [2, 3] {
            let bands = if revision == 2 { 11 } else { 12 };
            let mut bytes = alloc::vec![0;5+4*bands];
            bytes[0] = revision;
            bytes[1] = 1;
            for (index, value) in bytes[5..].iter_mut().enumerate() {
                *value = 30 + index as u8;
            }
            let sar = Sar::uefi(&bytes).unwrap();
            let body = sar.command(11).unwrap().unwrap();
            if body[10..12] != [30, 0]
                || body[116 - 4..] != [0; 4]
                || body[10 + 2 * 12..10 + 2 * 12 + 2] != [30 + bands as u8, 0]
                || body[10 + 4 * 12..116 - 4].iter().any(|v| *v != 0)
            {
                return TestResult::Fail("UEFI WRDS native scalar/chain/CDB/flags extent");
            }
            bytes[1] = 0;
            if Sar::uefi(&bytes).unwrap().command(10).unwrap().is_some() {
                return TestResult::Fail("disabled UEFI profile synthesized a SAR command");
            }
            bytes.pop();
            if Sar::uefi(&bytes).is_ok() {
                return TestResult::Fail("truncated UEFI WRDS accepted");
            }
        }
        for revision in [3, 4] {
            let bands = if revision == 3 { 3 } else { 4 };
            let mut bytes = alloc::vec![0;2+8*bands*3];
            bytes[0] = revision;
            bytes[1] = 3;
            for (index, value) in bytes[2..].iter_mut().enumerate() {
                *value = 10 + index as u8;
            }
            let geo = Geo::uefi(&bytes).unwrap();
            let body = geo.command(6).unwrap();
            if body[..8] != [0, 0, 0, 0, 10, 0, 11, 12]
                || body[132..] != [2, revision, 0, 0]
                || revision == 3 && body[16..20] != [0; 4]
            {
                return TestResult::Fail("UEFI WGDS source/revision or missing-band value");
            }
            bytes[1] = 2;
            if Geo::uefi(&bytes).is_ok() {
                return TestResult::Fail("UEFI WGDS omitted mandatory profiles");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/power",
        smoke_iwl_mld_uefi_sar_geo_payloads_preserve_source_specific_padding
    );

    fn smoke_iwl_mld_ppag_source_bios_compatibility_and_linux_dmi_scope() -> TestResult {
        for revision in 0..=5 {
            let bands = if revision == 0 {
                5
            } else if revision == 5 {
                12
            } else {
                11
            };
            let mut fields = alloc::vec![Value::Integer(7), Value::Integer(0x8fff)];
            fields.extend(
                (0..2 * bands)
                    .map(|i| Value::Integer(if i == 0 { u64::MAX - 15 } else { i as u64 })),
            );
            let ppag = Ppag::acpi(&table(revision, fields)).unwrap();
            for version in [7, 8] {
                let body = ppag.command(version, 5).unwrap().unwrap();
                let expected_flags: u32 = match revision {
                    0..=2 => 3,
                    3 => 0x7ff,
                    _ => 0x8fff,
                };
                if body.len() != 32
                    || body[..4] != [1, revision, 0, 0]
                    || body[4..8] != expected_flags.to_le_bytes()
                    || body[8] != 0xf0
                {
                    return TestResult::Fail(
                        "PPAG source/revision/mode/signed gain differs from BIOS",
                    );
                }
            }
            if revision > 0 && ppag.command(8, revision - 1).unwrap().is_some() {
                return TestResult::Fail("PPAG ignored firmware BIOS revision compatibility");
            }
        }
        for revision in [4, 5] {
            let bands = if revision == 4 { 11 } else { 12 };
            let mut bytes = alloc::vec![0;5+2*bands];
            bytes[0] = revision;
            bytes[1..5].fill(255);
            bytes[5] = 0xf0;
            let body = Ppag::uefi(&bytes).unwrap().command(8, 5).unwrap().unwrap();
            if body[..8] != [2, revision, 0, 0, 255, 255, 255, 255] || body[8] != 0xf0 {
                return TestResult::Fail("UEFI PPAG source/mode/signed gain encoding changed");
            }
            bytes.pop();
            if Ppag::uefi(&bytes).is_ok() {
                return TestResult::Fail("truncated UEFI PPAG payload accepted");
            }
        }
        if Ppag::disabled().command(8, 5).unwrap().unwrap() != [0; 32]
            || !ppag_approved(b"HP Inc.", b"")
            || !ppag_approved(b"Google", b"ASUSTek COMPUTER INC.")
            || ppag_approved(b"Google", b"Unknown")
            || ppag_approved(b"Unknown", b"HP")
            || ppag_approved(b"", b"")
        {
            return TestResult::Fail(
                "optional PPAG DMI selection created board admission prerequisite",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/power",
        smoke_iwl_mld_ppag_source_bios_compatibility_and_linux_dmi_scope
    );

    fn smoke_iwl_mld_legacy_ap_constraints_are_bounds_with_native_channel_steps() -> TestResult {
        let five = b"US \xc9\x01\x00\x24\x04\x17\x00";
        if legacy_ap_limit(44, 1 << 8, Some(five), Some(3), None) != Some(20)
            || legacy_ap_limit(44, 1 << 12, Some(five), Some(3), Some(15)) != Some(15)
            || legacy_ap_limit(42, 1 << 8, Some(five), Some(3), None).is_some()
            || legacy_ap_limit(44, 0, Some(five), Some(3), None).is_some()
            || legacy_ap_limit(44, 0, Some(five), Some(3), Some(-5)) != Some(-5)
            || legacy_ap_limit(44, 1 << 8, Some(five), Some(30), None) != Some(0)
            || legacy_ap_limit(11, 1 << 8, Some(b"US \x01\x0b\x14"), Some(2), None) != Some(18)
            || legacy_ap_limit(11, 1 << 8, Some(b"US \x01\x0b\x14\x00"), Some(2), None).is_some()
            || legacy_ap_limit(11, 1 << 8, None, Some(10), None).is_some()
        {
            return TestResult::Fail(
                "legacy AP power constraint changed channel/capability/minimum rules",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/power",
        smoke_iwl_mld_legacy_ap_constraints_are_bounds_with_native_channel_steps
    );
}
