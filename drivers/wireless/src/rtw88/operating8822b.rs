// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822BE ("B22") operating/station record family after the `N2BQ` IQK.
//!
//! `N2BP` is the parked 2T2R legacy operating-power record (the B22
//! counterpart of C21 `N21P`): explicit measured per-rate coded TXAGC indices
//! for both RF paths on channel 1 / 20 MHz, written through
//! `rtw8822b.c::rtw8822b_set_tx_power_index_by_rate` (0x1d00 / 0x1d80) and
//! bounded by the retained factory `txpwr_idx_table` channel-group-0 bases
//! (`phy.c::rtw_phy_get_2g_tx_power_index`, `txgi_factor` 1,
//! `max_power_index` 0x3f; 8822B has no BTG path substitution). `N2BS` is the
//! awake-station grant (counterpart of C21 `N21S`). Both are keyed by the B22
//! PCI identity `10ec:b822`, bound to the exact retained `N2BQ` board and
//! carry only provisioner-measured facts; no value here is inferred from
//! factory dBm or substituted from C21/C22 assets. Neither record alone
//! grants packet, peer or station authority.
use super::calibration8821c::Error as QError;
use super::{
    calibration8822b,
    efuse8822b::Factory8822b,
    firmware_transport::{Error, Io},
    radio8822b,
};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::RegulatoryDomain;

fn denied(error: QError) -> Error {
    Error::Calibration8822b(error)
}
/// `N2BP` record length.
pub(super) const POWER_LENGTH: usize = 192;
/// `N2BS` record length.
pub(super) const STATION_LENGTH: usize = 128;
/// Linux `main.h::RRSR_INIT_2G` (parked response mask).
pub(super) const RRSR_INIT_2G: u32 = 0x15f;
/// The twelve legacy DESC_RATE indices (CCK1..11, OFDM6..54) per path.
pub(super) const LEGACY: usize = 12;

fn filename(kind: &str, m: [u8; 6]) -> String {
    format!(
        "rtw88/rtw8822be-{}-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
        kind, m[0], m[1], m[2], m[3], m[4], m[5]
    )
}
fn signed(raw: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([raw[at], raw[at + 1]])
}
fn header(raw: &[u8], magic: &[u8; 4], length: usize) -> bool {
    raw.len() == length
        && &raw[..4] == magic
        && raw[4..6] == [1, 0]
        && raw[6..8] == (length as u16).to_le_bytes()
        && raw[8..12] == (length as u32).to_le_bytes()
        && raw[12..16] == calibration8822b::HEADER
        && raw[54..56] == [1, 20]
}
/// Current US policy plainly covering 2402..2422 MHz at 20 MHz; returns the
/// minimum of `ceiling`, the conservative 20 dBm board profile and every
/// intersecting rule (quarter-dBm).
fn policy_limit(domain: &RegulatoryDomain, ceiling: i16) -> Result<i16, Error> {
    if domain.country_code != *b"US" {
        return Err(denied(QError::Policy));
    }
    let mut limit = ceiling.min(80);
    let mut covering = false;
    for (i, rule) in domain.rules.iter().enumerate() {
        if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
            continue;
        }
        if !super::channel_policy::plain_rule(domain, i, 20) {
            return Err(denied(QError::Policy));
        }
        covering |= rule.freq_start_mhz <= 2402 && rule.freq_end_mhz >= 2422;
        limit = limit.min(i16::from(rule.max_power_dbm) * 4);
    }
    if !covering {
        return Err(denied(QError::Policy));
    }
    Ok(limit)
}

/// `phy.c::rtw_phy_get_2g_tx_power_index` channel group 0 (channel 1) over a
/// raw `struct rtw2g_txpwr_idx` path record: CCK `cck_base[0]` and 1S OFDM
/// `bw40_base[0] + ofdm_diff` (signed low nibble of byte 11), `txgi_factor`
/// 1, capped at `max_power_index` 0x3f. Erased or wrapped cells fail.
pub(super) fn factory_limits(raw: &[u8]) -> Result<[u8; 2], QError> {
    group_limits(raw, 0)
}
/// [`factory_limits`] for any 2.4GHz `phy.c::rtw_get_channel_group` group
/// 0..=4: CCK `cck_base[group]` (bytes 0..6) and 1S OFDM `bw40_base[group]`
/// (bytes 6..11) + `ht_1s_diff.ofdm`.
pub(super) fn group_limits(raw: &[u8], group: usize) -> Result<[u8; 2], QError> {
    if group > 4 || raw.len() < 12 || raw[group] > 63 || raw[6 + group] > 63 || raw[11] == 255 {
        return Err(QError::Factory);
    }
    let nibble = i16::from(raw[11] & 15);
    let ofdm = i16::from(raw[6 + group]) + if nibble & 8 != 0 { nibble - 16 } else { nibble };
    if ofdm < 0 {
        return Err(QError::Factory);
    }
    Ok([raw[group], ofdm.min(63) as u8])
}
/// `phy.c::rtw_phy_get_5g_tx_power_index` OFDM for one 5GHz channel group
/// (`band5::Power5g::ofdm`, `txgi_factor` 1) over a raw path record, refused
/// above `max_power_index` 0x3f.
pub(super) fn band5_limit(raw: &[u8], group: usize) -> Option<u8> {
    super::band5::Power5g::parse(raw)?
        .ofdm(group, 1)
        .filter(|v| *v <= 63)
}
/// `phy.c::rtw_phy_get_2g_tx_power_index` HT20 over a raw path record for
/// one 2.4GHz `rtw_get_channel_group` group, `txgi_factor` 1:
/// `bw40_base[group]` + `ht_1s_diff.bw20` (signed high nibble of byte 11),
/// plus `ht_2s_diff.bw20` (signed low nibble of byte 12) for two streams,
/// capped at `max_power_index` 0x3f. Erased or wrapped cells fail.
pub(super) fn ht20_limit(raw: &[u8], group: usize, two: bool) -> Option<u8> {
    let nibble = |v: u8| {
        let n = i16::from(v & 15);
        if n & 8 != 0 {
            n - 16
        } else {
            n
        }
    };
    if group > 4 || raw.len() < 13 || raw[6 + group] > 63 || raw[11] == 255 {
        return None;
    }
    let mut v = i16::from(raw[6 + group]) + nibble(raw[11] >> 4);
    if two {
        if raw[12] == 255 {
            return None;
        }
        v += nibble(raw[12]);
    }
    (v >= 0).then_some(v.min(63) as u8)
}
/// Both B22 RF paths (`txpwr_idx_table[0]`/`[1]`, `rtw8822b_read_efuse`).
pub(super) fn board_limits(factory: &Factory8822b) -> Result<[[u8; 2]; 2], QError> {
    let path = |p| factory.power_path(p).ok_or(QError::Factory);
    Ok([factory_limits(path(0)?)?, factory_limits(path(1)?)?])
}

/// Metadata a provisioner measures and signs as `N2BP`; grants nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
/// One completed parked operating-power program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// Coded TXAGC per path (A, B) for DESC_RATE 0..11.
    pub indices: [[u8; LEGACY]; 2],
    pub thermal: u8,
    pub response_rates: u32,
    pub identity: [u8; 32],
}
pub(super) fn request(
    calibration: calibration8822b::Request,
    receipt: radio8822b::Calibration,
) -> Request {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(
        b"NARF RTL8822BE parked legacy operating-power v1 ch1/20 2T2R BB_PATH_AB; no station grant",
    );
    hash.update(&calibration.identity);
    hash.update(&[receipt.channel, receipt.bandwidth_mhz]);
    hash.update(b"same-owner completed N2BQ IQK; current meter in both signed thermal intervals");
    hash.update(b"rtw8822b_pwr_track RF42[17:16]=3; 2000000us; RF-A RF42[15:10]; RF08 clear; 1bf0 low8/reload16 zero");
    hash.update(b"rtw8822b_set_tx_power_index_by_rate 1d00/1d80 + rate&0xfc words 0..2 measured, words 3..6 and 11..15 zero; readback");
    hash.update(b"indices<=factory txpwr_idx_table[path] group0 CCK/OFDM base txgi1 max3f; RRSR440=15f; closed CR TXPAUSE DMA IRQ");
    Request {
        identity: hash.finalize(),
        mac: calibration.mac,
        filename: filename("power", calibration.mac),
    }
}

pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
fn open(filename: &str) -> Result<Cap<FirmwareBlob, Read>, Error> {
    let loader = narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive::<Read>().ok())
        .ok_or_else(|| denied(QError::Authority))?;
    narf_firmware::open(filename, &loader).map_err(Error::Firmware)
}

/// Decoded, still-authorized `N2BP` record.
pub(super) struct Envelope {
    request: Request,
    cap: Cap<FirmwareBlob, Read>,
    calibration: Arc<calibration8822b::Envelope>,
    indices: [[u8; LEGACY]; 2],
    antenna: i16,
    ceiling: i16,
    /// Program peak, response peak, then twelve per-rate peaks.
    peaks: [i16; 14],
    thermal: [u8; 2],
    limits: [[u8; 2]; 2],
    /// Raw `txpwr_idx_table[0]`/`[1]` retained for the per-channel `N2BO`
    /// factory ceilings of the other channel groups.
    paths: [[u8; super::efuse8822b::POWER_PATH_LEN]; 2],
}
impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("B22OperatingEnvelope")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}
impl Source {
    pub(super) fn load(
        self,
        request: Request,
        factory: &Factory8822b,
        calibration: Arc<calibration8822b::Envelope>,
    ) -> Result<Envelope, Error> {
        let limits = board_limits(factory).map_err(denied)?;
        let mut paths = [[0; super::efuse8822b::POWER_PATH_LEN]; 2];
        for (p, out) in paths.iter_mut().enumerate() {
            out.copy_from_slice(
                factory
                    .power_path(p as u8)
                    .ok_or_else(|| denied(QError::Factory))?,
            );
        }
        struct Decode {
            request: Request,
            calibration: Arc<calibration8822b::Envelope>,
            limits: [[u8; 2]; 2],
            paths: [[u8; super::efuse8822b::POWER_PATH_LEN]; 2],
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Envelope, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Envelope::decode(
                        view.bytes,
                        view.signer,
                        *cap,
                        self.request,
                        self.calibration,
                        self.limits,
                        self.paths,
                    )
                })())
            }
        }
        match self {
            Self::Registered => open(&request.filename)?
                .invoke(Decode {
                    request,
                    calibration,
                    limits,
                    paths,
                })
                .map_err(|_| denied(QError::Authority))?,
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                Envelope::decode(&bytes, signer, cap, request, calibration, limits, paths)
            }
        }
    }
}
impl Envelope {
    /// `N2BP` v1 (192 bytes, little-endian): magic 0, version 4, header and
    /// total length 6/8, VID/DID 12, identity 16, MAC 48, channel/width 54,
    /// antenna gain 56 (quarter-dBi), board EIRP ceiling 58, complete-program
    /// and automatic-response conducted peaks 60/62 (quarter-dBm), thermal
    /// min/max 64/65, `US` 66, path-A and path-B coded indices 68/80 (DESC_RATE
    /// 0..11), twelve per-rate combined-chain conducted peaks 92, zero 116..192.
    fn decode(
        raw: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        request: Request,
        calibration: Arc<calibration8822b::Envelope>,
        limits: [[u8; 2]; 2],
        paths: [[u8; super::efuse8822b::POWER_PATH_LEN]; 2],
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| denied(QError::Authority))?;
        signer.ok_or_else(|| denied(QError::Unsigned))?;
        if !header(raw, b"N2BP", POWER_LENGTH)
            || &raw[66..68] != b"US"
            || raw[116..].iter().any(|&b| b != 0)
        {
            return Err(denied(QError::Format));
        }
        if raw[16..48] != request.identity || raw[48..54] != request.mac {
            return Err(denied(QError::Identity));
        }
        let (antenna, ceiling) = (signed(raw, 56), signed(raw, 58));
        let mut indices = [[0; LEGACY]; 2];
        indices[0].copy_from_slice(&raw[68..80]);
        indices[1].copy_from_slice(&raw[80..92]);
        let mut peaks = [0; 14];
        peaks[0] = signed(raw, 60);
        peaks[1] = signed(raw, 62);
        for (i, peak) in peaks[2..].iter_mut().enumerate() {
            *peak = signed(raw, 92 + 2 * i);
        }
        let thermal = [raw[64], raw[65]];
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&ceiling)
            || peaks.iter().any(|peak| !(-512..=256).contains(peak))
            || peaks[1..].iter().any(|peak| *peak > peaks[0])
            || thermal[0] > thermal[1]
            || thermal[1] > 63
            || indices.iter().zip(limits).any(|(path, limit)| {
                path.iter()
                    .enumerate()
                    .any(|(i, &index)| index > 63 || index > limit[usize::from(i >= 4)])
            })
        {
            return Err(denied(QError::Format));
        }
        Ok(Self {
            request,
            cap,
            calibration,
            indices,
            antenna,
            ceiling,
            peaks,
            thermal,
            limits,
            paths,
        })
    }
    pub(super) fn matches(&self, request: &Request) -> bool {
        &self.request == request
    }
    pub(super) fn indices(&self) -> [[u8; LEGACY]; 2] {
        self.indices
    }
    pub(super) fn factory_limits(&self) -> [[u8; 2]; 2] {
        self.limits
    }
    /// Per-path `[CCK, OFDM]` factory ceilings of one 2.4GHz channel group
    /// (`group_limits`); None when either path's cells are erased/wrapped.
    pub(super) fn group_limits(&self, group: usize) -> Option<[[u8; 2]; 2]> {
        Some([
            group_limits(&self.paths[0], group).ok()?,
            group_limits(&self.paths[1], group).ok()?,
        ])
    }
    /// Per-path factory OFDM ceilings of one 5GHz channel group.
    pub(super) fn band5_limits(&self, group: usize) -> Option<[u8; 2]> {
        Some([
            band5_limit(&self.paths[0], group)?,
            band5_limit(&self.paths[1], group)?,
        ])
    }
    /// HT20 `(1S, 2S)` factory ceilings of one channel group (2.4GHz
    /// [`ht20_limit`], or 5GHz `band5::Power5g::bw20`, factor 1, ≤ 0x3f),
    /// intersected over both paths. The 2S ceiling is None when either
    /// path's HT2S cell is erased.
    pub(super) fn ht_limits(&self, five: bool, group: usize) -> Option<(u8, Option<u8>)> {
        let one = |p: &[u8], two| {
            if five {
                super::band5::Power5g::parse(p)?
                    .bw20(group, two, 1)
                    .filter(|v| *v <= 63)
            } else {
                ht20_limit(p, group, two)
            }
        };
        let maximum = one(&self.paths[0], false)?.min(one(&self.paths[1], false)?);
        let two = one(&self.paths[0], true).zip(one(&self.paths[1], true));
        Some((maximum, two.map(|(a, b)| a.min(b))))
    }
    pub(super) fn calibration(&self) -> &calibration8822b::Envelope {
        &self.calibration
    }
    pub(super) fn temperature(&self, value: u8) -> Result<(), Error> {
        self.calibration.temperature(value).map_err(denied)?;
        if (self.thermal[0]..=self.thermal[1]).contains(&value) {
            Ok(())
        } else {
            Err(denied(QError::Thermal))
        }
    }
    fn policy(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        self.calibration.validate(domain).map_err(denied)?;
        let limit = policy_limit(domain, self.ceiling)?;
        if self.peaks.iter().any(|&peak| peak + self.antenna > limit) {
            return Err(denied(QError::Policy));
        }
        Ok(())
    }
    /// The `N2BQ` and `N2BP` source invocations and current policy enclose
    /// every native operation.
    pub(super) fn invoke<T>(
        &self,
        policy: &impl Fn() -> Result<RegulatoryDomain, Error>,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Invoke<'a, P, F> {
            envelope: &'a Envelope,
            policy: &'a P,
            operation: F,
        }
        impl<T, P: Fn() -> Result<RegulatoryDomain, Error>, F: FnOnce() -> Result<T, Error>>
            CapOp<FirmwareBlob, Read> for Invoke<'_, P, F>
        {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.envelope.policy(&(self.policy)()?)?;
                    (self.operation)()
                })())
            }
        }
        super::calibration8821c::Enclosure::invoke(&*self.calibration, policy, || {
            self.cap
                .invoke(Invoke {
                    envelope: self,
                    policy,
                    operation,
                })
                .map_err(|_| denied(QError::Authority))?
        })
    }
    /// Per-path DESC_RATE table for `rtw8822b_set_tx_power_index_by_rate`:
    /// the twelve measured legacy indices, every other rate zero.
    pub(super) fn txagc(&self, path: usize) -> [u8; 64] {
        let mut table = [0; 64];
        table[..LEGACY].copy_from_slice(&self.indices[path]);
        table
    }
    /// Parked program: fresh RF42 conversion (`rtw8822b_pwr_track` trigger and
    /// 2 s watchdog interval), thermal/IQK/RF08 receipts, both paths' TXAGC
    /// words with readback, then `RRSR_INIT_2G`. Packet gates stay closed.
    pub(super) async fn prepare(
        &self,
        io: &mut impl Io,
        policy: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<Info, Error> {
        use crate::rtw88::firmware_transport::enclosed;
        enclosed(|op| self.invoke(&policy, op), async {
            io.begin_operating8821c()?;
            radio8822b::rf(io, 0, 0x42, 3 << 16, 3).await
        })
        .await?;
        io.delay_us(2_000_000).await;
        let thermal = enclosed(|op| self.invoke(&policy, op), async {
            let thermal = ((radio8822b::rf_read(io, 0, 0x42).await? & 0xfc00) >> 10) as u8;
            self.temperature(thermal)?;
            if radio8822b::rf_read(io, 0, 0x08).await? != 0
                || super::radio::read(io, 0x1bf0).await? & 0x100ff != 0
            {
                return Err(denied(QError::Thermal));
            }
            Ok(thermal)
        })
        .await?;
        for path in 0..2u8 {
            let table = self.txagc(usize::from(path));
            enclosed(|op| self.invoke(&policy, op), async {
                radio8822b::write_txagc(io, path, &table).await?;
                let base = if path == 0 { 0x1d00 } else { 0x1d80 };
                for (word, rates) in table.chunks_exact(4).enumerate() {
                    if (7..11).contains(&word) {
                        continue;
                    }
                    let value = u32::from_le_bytes([rates[0], rates[1], rates[2], rates[3]]);
                    if io.read32(base + word as u16 * 4).await? != value {
                        return Err(Error::Prerequisite);
                    }
                }
                Ok(())
            })
            .await?;
            // Cooperative ownership boundary, not a radio settle bit.
            narf_scheduler::yield_now().await;
        }
        enclosed(|op| self.invoke(&policy, op), async {
            io.write32(0x440, RRSR_INIT_2G).await?;
            if io.read32(0x440).await? != RRSR_INIT_2G {
                return Err(Error::Prerequisite);
            }
            io.finish_operating8821c()?;
            Ok(Info {
                indices: self.indices,
                thermal,
                response_rates: RRSR_INIT_2G,
                identity: self.request.identity,
            })
        })
        .await
    }
}

/// Metadata a provisioner measures and signs as `N2BS`; grants nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StationRequest {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn station_request(power: Info, mac: [u8; 6]) -> StationRequest {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8822BE full awake ch1/20 2T2R native PCI STA legacy CCK1 v1");
    hash.update(&power.identity);
    for path in power.indices {
        hash.update(&path);
    }
    hash.update(&power.response_rates.to_le_bytes());
    hash.update(&0x1fu32.to_le_bytes()); // station response mask, distinct from parked 15f
    hash.update(b"static awake measured peaks cover all six-bit thermal values 0..63; pwr_track only under its own record");
    // radio8822b::prepare_station, literally.
    hash.update(b"radio8822b::prepare_station v1: retained N2BQ ch1/20 rtw8822b_set_channel RF18 A+B 8ac; cut f0; RF08 clear; 1bf0 low8/reload16 zero; N2BP 1d00/1d80 readback");
    hash.update(b"RF42[17:16]=3 2000000us RF-A RF42[15:10] in N2BP windows; RRSR440=1f; CAM32 invalidate 670/674; CR sec off; SECCFG 680 &~cf; RCR 608; RPWM 3d9/CPWM 3da awake");
    hash.update(b"re-verify geometry TXAGC RRSR; PCIe 303 stop f7; HIMR b0 b8 10b8 zero; CR cc and TXPAUSE ff closed; B22 Gate to PCI transport; no C21/C22 callbacks");
    hash.update(b"shared rtw88 PCI TXDESC48 TXBD16 RXDESC24 RXBD8; port0 MAC610 BSSID618 AID6a8; H2C ACTIVE/RA/media; conservative DCF");
    StationRequest {
        identity: hash.finalize(),
        mac,
        filename: filename("station", mac),
    }
}
pub(super) enum StationSource {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
/// Decoded, still-authorized `N2BS` record nested in its `N2BP` envelope.
pub(super) struct Grant {
    request: StationRequest,
    digest: [u8; 32],
    cap: Cap<FirmwareBlob, Read>,
    power: Arc<Envelope>,
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 3],
}
impl core::fmt::Debug for Grant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("B22StationGrant")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}
impl StationSource {
    pub(super) fn load(
        self,
        request: StationRequest,
        power: Arc<Envelope>,
    ) -> Result<Arc<Grant>, Error> {
        struct Decode {
            request: StationRequest,
            power: Arc<Envelope>,
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(view.bytes, view.signer, *cap, self.request, self.power)
                })())
            }
        }
        let grant = match self {
            Self::Registered => open(&request.filename)?
                .invoke(Decode { request, power })
                .map_err(|_| denied(QError::Authority))??,
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                Grant::decode(&bytes, signer, cap, request, power)?
            }
        };
        Ok(Arc::new(grant))
    }
}
impl Grant {
    /// `N2BS` v1 (128 bytes): the `N21S` layout with B22 magic/header —
    /// antenna 56, ceiling 58, ordinary/automatic-response/complete-program
    /// peaks 60/62/64, thermal 66/67 which must be exactly 0/63 (no
    /// continuous conversion watchdog), `US` 68, zero 70..128.
    fn decode(
        raw: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        request: StationRequest,
        power: Arc<Envelope>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| denied(QError::Authority))?;
        signer.ok_or_else(|| denied(QError::Unsigned))?;
        if !header(raw, b"N2BS", STATION_LENGTH)
            || &raw[68..70] != b"US"
            || raw[70..].iter().any(|&b| b != 0)
        {
            return Err(denied(QError::Format));
        }
        if raw[16..48] != request.identity || raw[48..54] != request.mac {
            return Err(denied(QError::Identity));
        }
        let (antenna, ceiling) = (signed(raw, 56), signed(raw, 58));
        let peaks = [signed(raw, 60), signed(raw, 62), signed(raw, 64)];
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&ceiling)
            || peaks.iter().any(|p| !(-512..=256).contains(p))
            || raw[66..68] != [0, 63]
        {
            return Err(denied(QError::Format));
        }
        Ok(Self {
            request,
            digest: {
                let mut h = narf_crypto::sha256::Sha256::new();
                h.update(raw);
                h.finalize()
            },
            cap,
            power,
            antenna,
            ceiling,
            peaks,
        })
    }
    pub(super) fn matches(&self, request: &StationRequest) -> bool {
        &self.request == request
    }
    pub(super) fn power(&self) -> &Envelope {
        &self.power
    }
    /// The factory MAC the record is bound to.
    pub(super) fn own(&self) -> [u8; 6] {
        self.request.mac
    }
    pub(super) fn identity(&self) -> [u8; 32] {
        self.request.identity
    }
    /// The exact `N2BS` request: the base every B22 continuation record
    /// (`N2BO` channel records first) binds.
    pub(super) fn request(&self) -> &StationRequest {
        &self.request
    }
    /// Both `N2BP` thermal windows (`N2BS` itself must cover 0..63).
    pub(super) fn temperature(&self, value: u8) -> Result<(), Error> {
        self.power.temperature(value)
    }
    /// The `N2BL` legacy12/WMM request this exact `N2BS` grant anchors
    /// (`station_profile::request_b22`).
    pub(super) fn extension_request(&self) -> super::station_profile::Request {
        super::station_profile::request_b22(
            self.request.identity,
            self.digest,
            self.power.indices(),
            self.own(),
        )
    }
    /// HT20 facts of channel 1 (group 0): the firmware hardware report the
    /// `N2BQ` board bound, both paths' intersected factory HT20 ceilings and
    /// path A's `N2BP` legacy indices. No CCK reference exists on B22.
    pub(super) fn ht_facts(&self) -> Option<super::ht::Facts> {
        let (maximum, maximum_2ss) = self.power.ht_limits(false, 0)?;
        Some(super::ht::Facts {
            hardware: self.power.calibration().hardware(),
            maximum,
            maximum_2ss,
            legacy: self.power.indices()[0],
            cck: [0; 2],
        })
    }
    /// The current station policy limit under `domain`, inside all three
    /// source invocations (the N2xL extension ceiling input).
    pub(super) fn extension_limit(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        self.invoke(&|| Ok(domain.clone()), || self.policy_limit(domain))
    }
    pub(super) fn policy_limit(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        let limit = policy_limit(domain, self.ceiling)?;
        if self.peaks.iter().any(|&p| p + self.antenna > limit) {
            return Err(denied(QError::Policy));
        }
        Ok(limit)
    }
    /// All three source invocations (`N2BQ`, `N2BP`, `N2BS`) and current
    /// policy enclose every native operation.
    pub(super) fn invoke<T>(
        &self,
        policy: &impl Fn() -> Result<RegulatoryDomain, Error>,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<'a, P, F> {
            grant: &'a Grant,
            policy: &'a P,
            operation: F,
        }
        impl<T, P: Fn() -> Result<RegulatoryDomain, Error>, F: FnOnce() -> Result<T, Error>>
            CapOp<FirmwareBlob, Read> for Live<'_, P, F>
        {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.grant.policy_limit(&(self.policy)()?)?;
                    (self.operation)()
                })())
            }
        }
        self.power.invoke(policy, || {
            self.cap
                .invoke(Live {
                    grant: self,
                    policy,
                    operation,
                })
                .map_err(|_| denied(QError::Authority))?
        })
    }
}
impl super::calibration8821c::Enclosure for Grant {
    fn invoke<T, F, Op>(&self, policy: &F, operation: Op) -> Result<T, Error>
    where
        F: Fn() -> Result<RegulatoryDomain, Error>,
        Op: FnOnce() -> Result<T, Error>,
    {
        Grant::invoke(self, policy, operation)
    }
}
