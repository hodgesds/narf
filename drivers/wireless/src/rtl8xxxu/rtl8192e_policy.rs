// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed, per-device RTL8192EU/RTL8191EU 2.4 GHz station qualification
//! (`N92P` v1, see `specification/rtl8xxxu.md` "RTL8192EU signed records").
//!
//! Linux `8192e.c::rtl8192e_set_tx_power` programs raw factory gain indices
//! (CCK base, HT40 base + OFDM/HT20/HT40 diffs) per path; rtl8xxxu has no
//! dBm conversion and there is no RTL8192EU board curve in Linux. This
//! record therefore qualifies the *exact* indices that
//! `rtl8192e_phy::tx_power` programs on each channel/width, per TX path, as
//! conservative conducted upper bounds measured by the signer. It also
//! carries the admitted firmware-RA rate mask; a peer outside it is refused
//! by `rtl8192e_ra::Ra::new`, never narrowed. No board value is shipped.
use super::rtl8192e_init::Factory;
use super::rtl8192e_radio::{channel_geometry, Width};
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};

pub(super) const MAGIC: [u8; 4] = *b"N92P";
pub(super) const HEADER: usize = 128;
pub(super) const ROW: usize = 28;
pub(super) const UNKNOWN: i16 = i16::MAX;
/// 13 HT20 rows + 9 HT40-above (1..=9) + 9 HT40-below (5..=13).
pub(super) const MAX_ROWS: usize = 31;
/// Two TX chains carrying the same rate: the aggregate conducted power is
/// at most the larger chain bound + 10*log10(2) dB = 3.0103 dB. Quarter-dB
/// arithmetic never rounds down, so 13 (3.25 dB), not 12.
const TWO_CHAIN_QDB: i32 = 13;
/// `DESC_RATE_*` bits 0..=27 (CCK 0..3, OFDM 4..11, MCS0..15 12..27).
const CCK: u32 = 0x0000_000f;
const OFDM: u32 = 0x0000_0ff0;
const MCS: u32 = 0x0fff_f000;
const MCS_2SS: u32 = 0x0ff0_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Firmware(FirmwareError),
    Unsigned,
    Format,
    Identity,
    Allocation,
    Policy,
    NoMeasuredGain,
}

/// Row width code: HT20 also covers NL80211_CHAN_WIDTH_20_NOHT (Linux
/// programs the same `set_tx_power(…, ht40 = false)` indices).
fn width_code(width: Width) -> u8 {
    match width {
        Width::NoHt20 | Width::Ht20 => 0,
        Width::Ht40Above => 1,
        Width::Ht40Below => 2,
    }
}

fn row_width(code: u8) -> Option<Width> {
    match code {
        0 => Some(Width::Ht20),
        1 => Some(Width::Ht40Above),
        2 => Some(Width::Ht40Below),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathRow {
    /// `[cck, ofdm, mcs]` qualified upper bounds, quarter-dBm.
    bounds: [i16; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    channel: u8,
    width: u8,
    paths: [PathRow; 2],
}

/// A registry-verified qualification. Only the signed registry path (and the
/// kernel-test parser child) constructs one; bytes alone mint no permission.
pub struct Calibration {
    factory: Factory,
    vid: u16,
    pid: u16,
    antenna_qdbi: i16,
    qualified_eirp_qdbm: i16,
    admitted: u32,
    rows: Vec<Row>,
    signer: [u8; 32],
    digest: [u8; 32],
    authority: Option<Cap<FirmwareBlob, Read>>,
}

impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8192euQualification")
            .field("mac", &self.factory.mac)
            .field("vid", &self.vid)
            .field("pid", &self.pid)
            .field("admitted", &self.admitted)
            .field("rows", &self.rows.len())
            .field("signer", &self.signer)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// The qualified primary channel/width and admitted RA mask for this exact
/// device. All fields are private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    factory: Factory,
    vid: u16,
    pid: u16,
    primary: u8,
    width: Width,
    admitted: u32,
    eirp_limit_qdbm: i16,
}

impl Permission {
    pub fn primary(&self) -> u8 {
        self.primary
    }
    pub fn width(&self) -> Width {
        self.width
    }
    /// The signed admitted rate mask handed to `Ra::new`.
    pub fn admitted(&self) -> u32 {
        self.admitted
    }
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp_limit_qdbm
    }
    /// Revalidate against the retained identity and the channel about to
    /// be programmed. Returns the admitted mask.
    pub fn check(
        &self,
        factory: &Factory,
        vid: u16,
        pid: u16,
        primary: u8,
        width: Width,
    ) -> Result<u32, Error> {
        if self.factory != *factory
            || self.vid != vid
            || self.pid != pid
            || self.primary != primary
            || self.width != width
        {
            return Err(Error::Identity);
        }
        Ok(self.admitted)
    }
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn signed(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Header bytes 12..82: USB identity, chip/cut/profile/paths and every
/// retained `rtl8192eu_parse_efuse` field. A replacement device cannot reuse
/// another's record.
pub(super) fn factory_bytes(factory: &Factory, vid: u16, pid: u16) -> [u8; 70] {
    let mut bytes = [0; 70];
    bytes[..2].copy_from_slice(&vid.to_le_bytes());
    bytes[2..4].copy_from_slice(&pid.to_le_bytes());
    bytes[4..6].copy_from_slice(&0x8192u16.to_le_bytes());
    bytes[6] = factory.identity.cut;
    bytes[7] = 1; // RTL8192EU/8191EU USB, 2.4 GHz HT20/40 station, no tracking.
    bytes[8] = factory.identity.tx_paths;
    bytes[9] = factory.identity.rom_rev;
    bytes[10..16].copy_from_slice(&factory.mac);
    for (p, power) in factory.power.iter().enumerate() {
        let at = 16 + p * 23;
        bytes[at..at + 6].copy_from_slice(&power.cck);
        bytes[at + 6..at + 11].copy_from_slice(&power.ht40);
        for i in 0..4 {
            bytes[at + 11 + i] = power.ofdm_diff[i] as u8;
            bytes[at + 15 + i] = power.ht20_diff[i] as u8;
            bytes[at + 19 + i] = power.ht40_diff[i] as u8;
        }
    }
    bytes[62..70].copy_from_slice(&[
        factory.crystal_cap,
        factory.channel_plan,
        factory.thermal,
        factory.board_option,
        factory.antenna_option,
        factory.pa_type,
        factory.lna_type_2g,
        factory.iqk_lck,
    ]);
    bytes
}

/// The `[cck, ofdm, mcs]` indices `rtl8192e_set_tx_power` programs on one
/// path for a row (the low byte of each splatted word).
pub(super) fn programmed(factory: &Factory, channel: u8, width: Width, path: usize) -> [u8; 3] {
    let ht40 = matches!(width, Width::Ht40Above | Width::Ht40Below);
    let (cck, ofdm, mcs) = super::rtl8192e_phy::tx_power(factory, channel, ht40)[path];
    [cck, ofdm as u8, mcs as u8]
}

impl Calibration {
    pub fn asset_name(factory: &Factory) -> alloc::string::String {
        let m = factory.mac;
        format!(
            "rtl8xxxu/rtl8192eu-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }

    pub fn load_registered(factory: &Factory, vid: u16, pid: u16) -> Result<Self, Error> {
        let name = Self::asset_name(factory);
        let loader = narf_firmware::trusted_loader_authority()
            .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let auth = loader
            .derive()
            .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let asset = crate::firmware_asset::load(&auth, &name, HEADER + MAX_ROWS * ROW, true)
            .map_err(Error::Firmware)?;
        let mut record =
            Self::from_verified(&asset.bytes, asset.signer, asset.digest, factory, vid, pid)?;
        record.authority = Some(asset.cap);
        Ok(record)
    }

    pub fn admitted(&self) -> u32 {
        self.admitted
    }

    /// Called only after narf_firmware authenticated the current cap view.
    pub(super) fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        digest: [u8; 32],
        factory: &Factory,
        vid: u16,
        pid: u16,
    ) -> Result<Self, Error> {
        let signer = signer.ok_or(Error::Unsigned)?;
        if bytes.len() < HEADER
            || bytes.len() > HEADER + MAX_ROWS * ROW
            || bytes[..4] != MAGIC
            || le16(bytes, 4) != 1
            || le16(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len()
            || bytes[82] != 1 // Whole qualified board operating envelope.
            || bytes[83] != 0
            || bytes[90..92] != [0; 2]
            || bytes[96..HEADER] != [0; HEADER - 96]
        {
            return Err(Error::Format);
        }
        let tx_paths = factory.identity.tx_paths;
        if bytes[12..82] != factory_bytes(factory, vid, pid)
            || factory.mac == [0; 6]
            || factory.mac[0] & 1 != 0
            || !matches!(tx_paths, 1 | 2)
        {
            return Err(Error::Identity);
        }
        let antenna_qdbi = signed(bytes, 84);
        let qualified_eirp_qdbm = signed(bytes, 86);
        let count = usize::from(le16(bytes, 88));
        let admitted = u32::from_le_bytes(bytes[92..96].try_into().unwrap());
        // No cable-loss / negative-gain credit. The admitted set is the
        // signer's: a 1T board may not admit 2SS MCS8..15, nothing beyond
        // MCS15, and an empty set admits nothing.
        if !(0..=128).contains(&antenna_qdbi)
            || !(-512..=256).contains(&qualified_eirp_qdbm)
            || count == 0
            || count > MAX_ROWS
            || bytes.len() != HEADER + count * ROW
            || admitted == 0
            || admitted & !(CCK | OFDM | MCS) != 0
            || tx_paths == 1 && admitted & MCS_2SS != 0
        {
            return Err(Error::Format);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let mut previous: Option<(u8, u8)> = None;
        for raw in bytes[HEADER..].chunks_exact(ROW) {
            let (channel, code) = (raw[0], raw[1]);
            let width = row_width(code).ok_or(Error::Format)?;
            if !(1..=13).contains(&channel)
                || channel_geometry(channel, width).is_none()
                || previous.is_some_and(|p| p >= (channel, code))
                || raw[2..4] != [0; 2]
            {
                return Err(Error::Format);
            }
            previous = Some((channel, code));
            let mut paths = [PathRow {
                bounds: [UNKNOWN; 3],
            }; 2];
            for (p, path) in paths.iter_mut().enumerate() {
                let at = 4 + p * 12;
                // The signer states the indices it measured; they must be
                // exactly what this driver programs from the bound EFUSE.
                if raw[at..at + 3] != programmed(factory, channel, width, p)
                    || raw[at + 3] != 0
                    || raw[at + 10..at + 12] != [0; 2]
                {
                    return Err(Error::Format);
                }
                path.bounds = core::array::from_fn(|i| signed(raw, at + 4 + i * 2));
                if path
                    .bounds
                    .iter()
                    .any(|&b| b != UNKNOWN && !(-512..=256).contains(&b))
                    // A 1T2R board has no path-B transmitter to qualify.
                    || p == 1 && tx_paths == 1 && path.bounds != [UNKNOWN; 3]
                {
                    return Err(Error::Format);
                }
            }
            rows.push(Row {
                channel,
                width: code,
                paths,
            });
        }
        Ok(Self {
            factory: *factory,
            vid,
            pid,
            antenna_qdbi,
            qualified_eirp_qdbm,
            admitted,
            rows,
            signer,
            digest,
            authority: None,
        })
    }

    /// Fixed primary/width permission. Every regulatory rule overlapping the
    /// occupied 20 or 40 MHz span must cover it completely at that width
    /// with no unsupported flags; the most restrictive dBm ceiling is an
    /// EIRP ceiling intersected with the board EIRP. Every rate class in the
    /// admitted mask must be qualified on every TX path at or below it:
    /// an unknown or excessive class refuses the channel, never narrows.
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        primary: u8,
        width: Width,
    ) -> Result<Permission, Error> {
        if let Some(cap) = &self.authority {
            cap.invoke(NoopOp)
                .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
        }
        if !(1..=13).contains(&primary)
            || channel_geometry(primary, width).is_none()
            || !domain.country_code.iter().all(u8::is_ascii_uppercase)
        {
            return Err(Error::Policy);
        }
        let center = 2407 + u32::from(primary) * 5;
        let (lower, upper, need) = match width {
            Width::NoHt20 | Width::Ht20 => (center - 10, center + 10, 20),
            Width::Ht40Above => (center - 10, center + 30, 40),
            Width::Ht40Below => (center - 30, center + 10, 40),
        };
        let mut ceiling = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz < upper && rule.freq_end_mhz > lower {
                if rule.freq_start_mhz > lower
                    || rule.freq_end_mhz < upper
                    || rule.max_bandwidth_mhz < need
                    || !rule.flags.is_empty()
                {
                    return Err(Error::Policy);
                }
                let limit = i16::from(rule.max_power_dbm) * 4;
                ceiling = Some(ceiling.map_or(limit, |old: i16| old.min(limit)));
            }
        }
        let eirp_limit_qdbm = ceiling.ok_or(Error::Policy)?.min(self.qualified_eirp_qdbm);
        let code = width_code(width);
        let row = self
            .rows
            .iter()
            .find(|r| r.channel == primary && r.width == code)
            .ok_or(Error::NoMeasuredGain)?;
        let chains = usize::from(self.factory.identity.tx_paths);
        for (class, mask) in [CCK, OFDM, MCS].into_iter().enumerate() {
            if self.admitted & mask == 0 {
                continue;
            }
            let mut peak = i32::MIN;
            for path in &row.paths[..chains] {
                let bound = path.bounds[class];
                if bound == UNKNOWN {
                    return Err(Error::NoMeasuredGain);
                }
                peak = peak.max(i32::from(bound));
            }
            if chains == 2 {
                peak += TWO_CHAIN_QDB;
            }
            if peak + i32::from(self.antenna_qdbi) > i32::from(eirp_limit_qdbm) {
                return Err(Error::NoMeasuredGain);
            }
        }
        Ok(Permission {
            factory: self.factory,
            vid: self.vid,
            pid: self.pid,
            primary,
            width,
            admitted: self.admitted,
            eirp_limit_qdbm,
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "rtl8192e_policy_tests.rs"]
mod tests;
