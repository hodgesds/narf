// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed per-device qualification for the initial awake ch1/basic1Mbps
//! RTL8822CE profile. Indices never stand in for a measured dBm envelope.
use super::{efuse::Factory, hardware::Features, phy};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
#[path = "factory/power_values.rs"]
mod values;
const HEADER: usize = 128;
const LENGTH: usize = HEADER + 2 * 128 * 2;
const UNKNOWN: i16 = i16::MAX;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    FactoryPower,
    Policy,
    NoMeasuredGain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    maximum: [u8; 2],
    /// Per-path CCK reference ceilings for 2.4GHz channel groups 0..=4
    /// (Linux `rtw_get_channel_group`), None if erased or out of range.
    groups: [Option<[u8; 2]>; 5],
    ht: Option<super::ht::Facts>,
    /// HT20 one-/two-stream factory ceilings per 2.4GHz channel group
    /// (`bw40_base[group]` plus the HT20 differences), min over both paths.
    ht_groups: [Option<(u8, Option<u8>)>; 5],
    /// HT40 one-/two-stream factory ceilings per group (`bw40_base[group]`
    /// plus `ht_2s_diff.bw40`), min over both paths.
    ht40_groups: [Option<(u8, Option<u8>)>; 5],
    /// Per-path 5GHz OFDM ceilings per 5GHz channel group
    /// (`band5::Power5g::ofdm`, txgi factor 2, max index 0x7f).
    band5_groups: [Option<[u8; 2]>; 14],
    /// HT20 one-/two-stream factory ceilings per 5GHz channel group
    /// (`band5::Power5g::bw20`, txgi factor 2), min over both paths.
    ht5_groups: [Option<(u8, Option<u8>)>; 14],
    /// HT40 one-/two-stream factory ceilings per 5GHz channel group
    /// (`band5::Power5g::bw40`, txgi factor 2), min over both paths.
    ht40_5_groups: [Option<(u8, Option<u8>)>; 14],
    /// VHT80 one-/two-stream factory ceilings per 5GHz group of an 80MHz
    /// center (`band5::Power5g::bw80`, txgi factor 2), min over both paths.
    vht80_groups: [Option<(u8, Option<u8>)>; 14],
}
impl Board {
    pub(super) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(super) fn new(
        factory: &Factory,
        info: phy::Info,
        hardware: Features,
        firmware: [u8; 32],
    ) -> Result<Self, Error> {
        if phy::Info::from_factory(factory, info.cut, hardware).ok() != Some(info) {
            return Err(Error::Identity);
        }
        let mut maximum = [0; 2];
        for (path, limit) in maximum.iter_mut().enumerate() {
            let base = *factory
                .power_path(path as u8)
                .and_then(|p| p.first())
                .ok_or(Error::FactoryPower)?;
            let bound = i16::from(base) + values::CCK_RESPONSE_ADJUST[usize::from(info.rfe)][path];
            if base > 127 || !(0..=127).contains(&bound) {
                return Err(Error::FactoryPower);
            }
            *limit = bound as u8;
        }
        let groups = core::array::from_fn(|group| {
            let mut limit = [0; 2];
            for (path, slot) in limit.iter_mut().enumerate() {
                let base = *factory.power_path(path as u8)?.get(group)?;
                let bound =
                    i16::from(base) + values::CCK_RESPONSE_ADJUST[usize::from(info.rfe)][path];
                if base > 127 || !(0..=127).contains(&bound) {
                    return None;
                }
                *slot = bound as u8;
            }
            Some(limit)
        });
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8822CE awake ch1 legacy20 basic1 txA rxAB v2");
        hash.update(b"fresh DACK IQK; no GAPK DPD tracking; software CCMP raw RX");
        // Bind actual native automatic-response programming as well as host
        // TXDs: all four CCK response indices are bounded, OFDM reference0
        // and all legacy relative differences0, source fixed1M RRSR mask1f.
        hash.update(b"RRSR=1f CCKref=selected OFDMref=0 legacydiff=0 native response envelope");
        hash.update(b"IGI=1c EDCCA=40/33 fixed maximum-coverage adaptive bound");
        hash.update(factory.logical());
        hash.update(factory.trims());
        hash.update(&[info.cut, info.rfe, info.paths, info.crystal]);
        hash.update(&[
            hardware.hci,
            hardware.bandwidth,
            hardware.streams,
            hardware.antennas,
            hardware.protocol,
        ]);
        hash.update(&firmware);
        hash.update(&maximum);
        phy::bind_tables(&mut hash, info).map_err(|_| Error::Identity)?;
        let ht_groups = core::array::from_fn(|group| {
            let one = |path: u8| {
                factory
                    .power_path(path)
                    .and_then(|p| super::ht::factory_limit_group(p, group, 2, 127))
            };
            let two = |path: u8| {
                factory
                    .power_path(path)
                    .and_then(|p| super::ht::factory_limit_2ss_group(p, group))
            };
            Some((
                one(0)?.min(one(1)?),
                two(0).zip(two(1)).map(|(a, b)| a.min(b)),
            ))
        });
        let ht40_groups = core::array::from_fn(|group| {
            let one = |path: u8| {
                factory
                    .power_path(path)
                    .and_then(|p| super::ht::factory_limit_bw40(p, group, 127))
            };
            let two = |path: u8| {
                factory
                    .power_path(path)
                    .and_then(|p| super::ht::factory_limit_bw40_2ss(p, group, 2))
            };
            Some((
                one(0)?.min(one(1)?),
                two(0).zip(two(1)).map(|(a, b)| a.min(b)),
            ))
        });
        let band5_groups = core::array::from_fn(|group| {
            let mut limit = [0; 2];
            for (path, slot) in limit.iter_mut().enumerate() {
                *slot = super::band5::Power5g::parse(factory.power_path(path as u8)?)?
                    .ofdm(group, 2)?
                    .min(127);
            }
            Some(limit)
        });
        let ht5_groups = core::array::from_fn(|group| {
            let path = |path: u8| super::band5::Power5g::parse(factory.power_path(path)?);
            let (a, b) = (path(0)?, path(1)?);
            Some((
                a.bw20(group, false, 2)?.min(b.bw20(group, false, 2)?),
                a.bw20(group, true, 2)
                    .zip(b.bw20(group, true, 2))
                    .map(|(a, b)| a.min(b)),
            ))
        });
        let ht40_5_groups = core::array::from_fn(|group| {
            let path = |path: u8| super::band5::Power5g::parse(factory.power_path(path)?);
            let (a, b) = (path(0)?, path(1)?);
            Some((
                a.bw40(group, false, 2)?.min(b.bw40(group, false, 2)?),
                a.bw40(group, true, 2)
                    .zip(b.bw40(group, true, 2))
                    .map(|(a, b)| a.min(b)),
            ))
        });
        let vht80_groups = core::array::from_fn(|group| {
            let path = |path: u8| super::band5::Power5g::parse(factory.power_path(path)?);
            let (a, b) = (path(0)?, path(1)?);
            Some((
                a.bw80(group, false, 2)?.min(b.bw80(group, false, 2)?),
                a.bw80(group, true, 2)
                    .zip(b.bw80(group, true, 2))
                    .map(|(a, b)| a.min(b)),
            ))
        });
        Ok(Self {
            identity: hash.finalize(),
            mac: factory.mac(),
            maximum,
            groups,
            band5_groups,
            ht5_groups,
            ht40_5_groups,
            vht80_groups,
            ht_groups,
            ht40_groups,
            ht: factory
                .power_path(0)
                .and_then(|a| super::ht::factory_limit(a, 2, 127))
                .zip(
                    factory
                        .power_path(1)
                        .and_then(|b| super::ht::factory_limit(b, 2, 127)),
                )
                .map(|(a, b)| super::ht::Facts {
                    hardware,
                    maximum: a.min(b),
                    maximum_2ss: factory
                        .power_path(0)
                        .and_then(super::ht::factory_limit_2ss)
                        .zip(factory.power_path(1).and_then(super::ht::factory_limit_2ss))
                        .map(|(a, b)| a.min(b)),
                    legacy: [0; 12],
                    cck: [0; 2],
                }),
        })
    }
}
struct Authority(Cap<FirmwareBlob, Read>);
struct Confirm;
impl CapOp<FirmwareBlob, Read> for Confirm {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
impl Authority {
    fn current(&self) -> Result<(), Error> {
        self.0.invoke(Confirm).map_err(|_| Error::Authority)
    }
}
pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: alloc::vec::Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
impl Source {
    pub(super) fn load(self, board: Board) -> Result<Calibration, Error> {
        match self {
            Self::Registered => Calibration::load_registered(board),
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                Calibration::from_verified(&bytes, signer, board, Authority(cap))
            }
        }
    }
}
pub(super) struct Calibration {
    board: Board,
    authority: Authority,
    digest: [u8; 32],
    antenna: i16,
    qualified: i16,
    calibration_peak: i16,
    response_peak: i16,
    curves: [[i16; 128]; 2],
}
impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822cePowerQualification")
            .field("board", &self.board)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    calibration: [u8; 32],
    gains: [u8; 2],
    eirp: i16,
}
/// Sealed retained calibration grant. Only the enclosing successful radio
/// continuation can supply one to the native packet owner.
#[derive(Clone)]
pub struct Gate {
    host: Option<narf_net::native_emission::Lifetime>,
    tracking: Option<alloc::sync::Arc<super::tracking8821c::Grant>>,
    scope: Scope,
    extension: Option<alloc::sync::Arc<super::station_profile::Grant>>,
    ht: Option<alloc::sync::Arc<super::ht::Grant>>,
    rx_ba: Option<alloc::sync::Arc<super::rx_ba_power::Grant>>,
    tx_ba: Option<alloc::sync::Arc<super::tx_ba_power::Grant>>,
    protection: Option<alloc::sync::Arc<super::protection::Grant>>,
    /// Separately qualified N2xC TX coding over the exact base and bound H.
    /// Not part of `current`/`invoke`: revocation downgrades to uncoded TX.
    coding: Option<alloc::sync::Arc<super::qualification::Grant>>,
    /// Separately qualified N2xQ all-TID QoS routing over the WMM extension.
    /// Not part of `current`/`invoke`: revocation returns to BE/TID0.
    qos: Option<alloc::sync::Arc<super::qualification::Grant>>,
    /// Separately qualified N2xF DATA rate fallback over the extension.
    /// Revocation returns to fixed-rate DATA.
    fallback: Option<alloc::sync::Arc<super::qualification::Grant>>,
    /// Separately signed N2xO noninitial 2.4GHz/20MHz channel program over
    /// the exact base. Present only while retuned away from channel 1; its
    /// live regulatory/capability check is part of `current`.
    channel: Option<alloc::sync::Arc<super::qualification::Grant>>,
    /// Separately signed N2xB 2.4GHz HT40 program over the bound HT program.
    /// Once the hardware runs at 40MHz there is no in-place downgrade, so its
    /// live regulatory/capability/factory check is part of `current` and
    /// every `invoke`.
    ht40: Option<alloc::sync::Arc<super::qualification::Grant>>,
    /// Separately signed N2xV 5GHz VHT80 program over the bound HT program
    /// on the same primary; like N2xB there is no in-place downgrade, so its
    /// live check is part of `current` and every `invoke`.
    vht: Option<alloc::sync::Arc<super::qualification::Grant>>,
}
/// A C22 calibration source without extension dispatch. N22L retains this
/// narrower type, so invoking its base cannot recursively invoke N22L again.
#[derive(Clone)]
pub(super) struct CalibratedBase {
    calibration: alloc::sync::Arc<Calibration>,
    permission: Permission,
    own: [u8; 6],
}
impl CalibratedBase {
    pub(super) fn request(&self) -> super::station_profile::Request {
        super::station_profile::request(
            self.permission.identity,
            self.calibration.digest,
            self.permission.gains,
            self.own,
        )
    }
    pub(super) fn current(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        self.calibration.validate(self.permission, domain)
    }
    pub(super) fn eirp(&self) -> i16 {
        self.permission.eirp
    }
    pub(super) fn invoke<T>(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        struct Invoke<'a, F> {
            base: &'a CalibratedBase,
            domain: &'a narf_wireless::reg::RegulatoryDomain,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, super::firmware_transport::Error>>
            CapOp<FirmwareBlob, Read> for Invoke<'_, F>
        {
            type Output = Result<T, super::firmware_transport::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.base
                        .current(self.domain)
                        .map_err(super::firmware_transport::Error::Power)?;
                    (self.operation)()
                })())
            }
        }
        self.calibration
            .authority
            .0
            .invoke(Invoke {
                base: self,
                domain,
                operation,
            })
            .map_err(|_| super::firmware_transport::Error::Power(Error::Authority))?
    }
}
/// Extension bases never contain an extension-aware Gate. Both arms dispatch
/// directly into their chip's retained qualification, keeping invocation
/// statically acyclic and preventing C22 gain/measurement substitution.
pub(super) enum ExtensionChip {
    C22(CalibratedBase),
    C21(alloc::sync::Arc<super::station_power8821c::Grant>),
    /// RTL8822BE `N2BS` (nesting `N2BQ` + `N2BP`).
    B22(alloc::sync::Arc<super::operating8822b::Grant>),
}
/// The chip base plus, off channel 1, the bound N2xO channel record. Every
/// program loaded over a channel-scoped base is a distinct per-channel record
/// (`channel_policy::scope_request`): its identity, filename, factory facts
/// (`rtw_get_channel_group` of that primary) and live regulatory check all
/// belong to that channel; nothing measured on channel 1 is reused.
pub(super) struct ExtensionBase {
    chip: ExtensionChip,
    channel: Option<alloc::sync::Arc<super::qualification::Grant>>,
}
impl ExtensionBase {
    pub(super) fn ht_facts(&self) -> Option<super::ht::Facts> {
        let facts = match &self.chip {
            ExtensionChip::C21(b) => b.ht_facts(),
            ExtensionChip::C22(b) => b.calibration.board.ht.map(|mut f| {
                f.cck = b.permission.gains;
                f
            }),
            ExtensionChip::B22(b) => b.ht_facts(),
        };
        let group = |five: bool, g: usize| match &self.chip {
            ExtensionChip::C21(b) if five => b.ht5_group(g).map(|m| (m, None)),
            ExtensionChip::C21(b) => b.ht_group(g).map(|m| (m, None)),
            ExtensionChip::C22(b) if five => b.calibration.board.ht5_groups[g],
            ExtensionChip::C22(b) => b.calibration.board.ht_groups[g],
            ExtensionChip::B22(b) => b.power().ht_limits(five, g),
        };
        overlay(self.did(), facts, self.channel.as_deref(), group)
    }
    pub(super) fn did(&self) -> u16 {
        match &self.chip {
            ExtensionChip::C22(_) => 0xc822,
            ExtensionChip::C21(_) => 0xc821,
            ExtensionChip::B22(_) => 0xb822,
        }
    }
    /// Host identity keying this board's records (`phy8821c::Host`).
    pub(super) fn host(&self) -> super::phy8821c::Host {
        match &self.chip {
            ExtensionChip::C22(_) => super::phy8821c::Host::PCI_C22,
            ExtensionChip::C21(b) => b.host(),
            ExtensionChip::B22(b) => b.host(),
        }
    }
    /// Operating primary of this base: 1, or the bound N2xO record's.
    pub(super) fn channel(&self) -> u8 {
        self.channel
            .as_ref()
            .and_then(|g| super::channel_policy::Record::decode(self.did(), g.payload()))
            .map_or(1, |r| r.channel)
    }
    /// C22 5GHz OFDM6..54 TX indices of the bound N2xO record, as one
    /// both-path selection: `min(ofdm[A] + diff(r), ofdm[B] + diff(r))`
    /// (`rtw8822c_set_tx_power_index` takes the per-rate minimum of the two
    /// paths' differences). None off a C22 5GHz record.
    pub(super) fn ofdm5_indices(&self) -> Option<[u8; 8]> {
        if self.did() != 0xc822 {
            return None;
        }
        super::channel_policy::Record::decode(self.did(), self.channel.as_ref()?.payload())?
            .ofdm5_indices()
    }
    /// B22 per-path DESC_RATE 0..11 TXAGC indices of this base's primary:
    /// the bound `N2BO` record's, else the `N2BP` channel-1 ones.
    pub(super) fn b22_indices(&self) -> Option<[[u8; 12]; 2]> {
        let ExtensionChip::B22(b) = &self.chip else {
            return None;
        };
        match &self.channel {
            Some(g) => super::channel_policy::Record::decode(0xb822, g.payload())
                .map(|r| [r.indices, r.indices_b]),
            None => Some(b.power().indices()),
        }
    }
    pub(super) fn temperature(&self, value: u8) -> Result<(), super::firmware_transport::Error> {
        match &self.chip {
            ExtensionChip::C21(b) => b.temperature(value),
            ExtensionChip::B22(b) => b.temperature(value),
            ExtensionChip::C22(_) => Ok(()),
        }
    }
    pub(super) fn request(&self) -> super::station_profile::Request {
        let base = match &self.chip {
            ExtensionChip::C22(b) => b.request(),
            ExtensionChip::C21(b) => b.extension_request(),
            ExtensionChip::B22(b) => b.extension_request(),
        };
        scoped(base, self.did(), self.channel.as_deref())
    }
    pub(super) fn current(
        &self,
        d: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<i16, super::firmware_transport::Error> {
        let limit = match &self.chip {
            ExtensionChip::C22(b) => {
                b.current(d)
                    .map_err(super::firmware_transport::Error::Power)?;
                b.eirp()
            }
            ExtensionChip::C21(b) => {
                b.check()?;
                b.extension_limit(d)?
            }
            ExtensionChip::B22(b) => b.extension_limit(d)?,
        };
        match &self.channel {
            Some(g) => Ok(limit.min(super::channel_policy::limit_in(g, self.did(), d)?)),
            None => Ok(limit),
        }
    }
    pub(super) fn invoke<T>(
        &self,
        d: &narf_wireless::reg::RegulatoryDomain,
        op: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        // The channel record's own capability and span are re-checked inside
        // the base invocation, immediately before the operation.
        let did = self.did();
        let op = || match &self.channel {
            Some(g) => g.invoke_source(|| {
                super::channel_policy::limit_in(g, did, d)?;
                op()
            }),
            None => op(),
        };
        match &self.chip {
            ExtensionChip::C22(b) => b.invoke(d, op),
            ExtensionChip::C21(b) => b.invoke(op),
            ExtensionChip::B22(b) => b.invoke(&|| Ok(d.clone()), op),
        }
    }
}
/// Channel-scope a base request: identity bound to the N2xO record and a
/// per-channel filename. The unscoped channel-1 request is unchanged.
fn scoped(
    base: super::station_profile::Request,
    did: u16,
    channel: Option<&super::qualification::Grant>,
) -> super::station_profile::Request {
    match channel.and_then(|g| super::channel_policy::scope_request(&base, did, g)) {
        Some(r) => r,
        None => base,
    }
}
/// HT factory facts for the bound primary: the channel's own
/// `rtw_get_channel_group` HT20 ceilings and, as the reference/legacy gains,
/// the N2xO record's C22 CCK references or C21 TXAGC indices.
fn overlay(
    did: u16,
    facts: Option<super::ht::Facts>,
    channel: Option<&super::qualification::Grant>,
    group: impl Fn(bool, usize) -> Option<(u8, Option<u8>)>,
) -> Option<super::ht::Facts> {
    let mut facts = facts?;
    let Some(g) = channel else {
        return Some(facts);
    };
    let record = super::channel_policy::Record::decode(did, g.payload())?;
    // 5GHz: `rtw_phy_get_5g_tx_power_index` HT20 of the primary's 5GHz
    // group; the record's CCK references / TXAGC CCK indices are zero.
    let (maximum, maximum_2ss) = if record.band5() {
        group(true, super::band5::group(record.channel)?)?
    } else {
        group(false, super::channel_policy::group(record.channel)?)?
    };
    facts.maximum = maximum;
    facts.maximum_2ss = maximum_2ss.filter(|_| facts.maximum_2ss.is_some());
    match did {
        0xc822 => facts.cck = record.gains,
        0xc821 | 0xb822 => facts.legacy = record.indices,
        _ => return None,
    }
    Some(facts)
}
#[derive(Clone)]
enum Scope {
    C22 {
        calibration: alloc::sync::Arc<Calibration>,
        permission: Permission,
        own: [u8; 6],
    },
    C21(alloc::sync::Arc<super::station_power8821c::Grant>),
    /// RTL8822BE `N2BS` awake-station grant (nesting `N2BQ` + `N2BP`) and
    /// the retained `rtw8822b_phy_set_param` facts `rtw8822b_set_channel`
    /// needs on a retune. Per-channel `N2BO` records bind over it
    /// ([`Gate::with_channel`]) and the `N2BL` legacy12/WMM extension over
    /// that ([`ExtensionChip::B22`]).
    B22(
        alloc::sync::Arc<super::operating8822b::Grant>,
        super::phy8822b::Info,
    ),
}
/// Current policy for the B22 grant invoker (`operating8822b::Grant::invoke`).
fn b22_policy() -> Result<narf_wireless::reg::RegulatoryDomain, super::firmware_transport::Error> {
    narf_wireless::reg::db::get_domain().ok_or(super::firmware_transport::Error::Calibration8822b(
        super::calibration8821c::Error::Policy,
    ))
}
fn b22_error(e: super::firmware_transport::Error) -> Error {
    match e {
        super::firmware_transport::Error::Calibration8822b(
            super::calibration8821c::Error::Authority,
        ) => Error::Authority,
        _ => Error::Policy,
    }
}
impl Gate {
    fn host_current(&self) -> Result<(), Error> {
        if self.host.as_ref().is_some_and(|host| !host.current()) {
            Err(Error::Authority)
        } else {
            Ok(())
        }
    }
    pub(super) fn with_host(
        &self,
        host: narf_net::native_emission::Lifetime,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.host.is_some() || !host.current() {
            return Err(super::firmware_transport::Error::Access);
        }
        let mut gate = self.clone();
        gate.host = Some(host);
        Ok(gate)
    }
    /// The base for a new N2xL extension: the chip base plus any bound
    /// N2xO channel record, so the extension is that channel's own program.
    pub(super) fn extension_base(&self) -> Option<ExtensionBase> {
        if self.extension.is_some() {
            return None;
        }
        let chip = match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                own,
            } => ExtensionChip::C22(CalibratedBase {
                calibration: calibration.clone(),
                permission: *permission,
                own: *own,
            }),
            Scope::C21(b) => ExtensionChip::C21(b.clone()),
            Scope::B22(b, _) => ExtensionChip::B22(b.clone()),
        };
        Some(ExtensionBase {
            chip,
            channel: self.channel.clone(),
        })
    }
    pub(super) fn calibrated_base(&self) -> Option<CalibratedBase> {
        if self.extension.is_some() || self.channel.is_some() {
            return None;
        }
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                own,
            } => Some(CalibratedBase {
                calibration: calibration.clone(),
                permission: *permission,
                own: *own,
            }),
            Scope::C21(_) | Scope::B22(..) => None,
        }
    }
    pub(super) fn new(
        calibration: alloc::sync::Arc<Calibration>,
        permission: Permission,
        own: [u8; 6],
    ) -> Self {
        Self {
            host: None,
            tracking: None,
            extension: None,
            ht: None,
            rx_ba: None,
            tx_ba: None,
            protection: None,
            coding: None,
            qos: None,
            fallback: None,
            channel: None,
            ht40: None,
            vht: None,
            scope: Scope::C22 {
                calibration,
                permission,
                own,
            },
        }
    }
    /// The B22 base gate over its `N2BS` grant (`radio8822b::prepare_station`).
    pub(super) fn b22(
        grant: alloc::sync::Arc<super::operating8822b::Grant>,
        phy: super::phy8822b::Info,
    ) -> Self {
        Self {
            host: None,
            scope: Scope::B22(grant, phy),
            tracking: None,
            extension: None,
            ht: None,
            rx_ba: None,
            tx_ba: None,
            protection: None,
            coding: None,
            qos: None,
            fallback: None,
            channel: None,
            ht40: None,
            vht: None,
        }
    }
    pub(super) fn c21(grant: alloc::sync::Arc<super::station_power8821c::Grant>) -> Self {
        Self {
            host: None,
            scope: Scope::C21(grant),
            tracking: None,
            extension: None,
            ht: None,
            rx_ba: None,
            tx_ba: None,
            protection: None,
            coding: None,
            qos: None,
            fallback: None,
            channel: None,
            ht40: None,
            vht: None,
        }
    }
    /// Current operating 2.4GHz primary: 1 for the base, else the bound
    /// N2xO record's channel.
    pub(super) fn channel(&self) -> u8 {
        self.channel
            .as_ref()
            .and_then(|g| super::channel_policy::Record::decode(self.did(), g.payload()))
            .map_or(1, |r| r.channel)
    }
    pub(super) fn channel_grant(&self) -> Option<alloc::sync::Arc<super::qualification::Grant>> {
        self.channel.clone()
    }
    /// True when only the base program is bound: no extension, HT, BA,
    /// protection, coding/QoS/fallback or power tracking continuation.
    pub(super) fn base_only(&self) -> bool {
        self.extension.is_none()
            && self.ht.is_none()
            && self.rx_ba.is_none()
            && self.tx_ba.is_none()
            && self.protection.is_none()
            && self.coding.is_none()
            && self.qos.is_none()
            && self.fallback.is_none()
            && self.tracking.is_none()
            && self.ht40.is_none()
            && self.vht.is_none()
    }
    pub(super) fn without_channel(&self) -> Self {
        let mut gate = self.clone();
        gate.channel = None;
        gate
    }
    /// Bind one N2xO channel record over this exact base-only gate.
    pub(super) fn with_channel(
        &self,
        g: alloc::sync::Arc<super::qualification::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        let record = super::channel_policy::Record::decode(self.did(), g.payload())
            .ok_or(super::firmware_transport::Error::State)?;
        if !self.base_only()
            || self.channel.is_some()
            || super::channel_policy::kind(record.channel).is_none_or(|k| !g.is(k))
            || !g.matches(self)
            || !super::channel_policy::within_factory(self, &record)
        {
            return Err(super::firmware_transport::Error::State);
        }
        super::channel_policy::current(&g, self.did())?;
        let mut gate = self.clone();
        gate.channel = Some(g);
        Ok(gate)
    }
    /// Factory per-group ceilings: C22 per-path CCK references, C21
    /// [CCK, OFDM] indices.
    pub(super) fn group_limits(&self, group: usize) -> Option<[u8; 2]> {
        match &self.scope {
            Scope::C22 { calibration, .. } => {
                calibration.board.groups.get(group).copied().flatten()
            }
            Scope::C21(g) => g.group_limits(group),
            Scope::B22(..) => None,
        }
    }
    /// B22 per-path `[CCK, OFDM]` factory ceilings of one 2.4GHz group
    /// (`operating8822b::group_limits`).
    pub(super) fn b22_group_limits(&self, group: usize) -> Option<[[u8; 2]; 2]> {
        match &self.scope {
            Scope::B22(grant, _) => grant.power().group_limits(group),
            _ => None,
        }
    }
    /// The retained B22 PHY facts (`rtw8822b_set_channel` RFE/cut).
    pub(super) fn b22_phy(&self) -> Option<super::phy8822b::Info> {
        match &self.scope {
            Scope::B22(_, phy) => Some(*phy),
            _ => None,
        }
    }
    /// B22 per-path coded TXAGC indices (DESC_RATE 0..11) of the committed
    /// primary: the bound `N2BO` record's, else the `N2BP` channel-1 ones.
    pub(super) fn b22_indices(&self) -> Option<[[u8; 12]; 2]> {
        let Scope::B22(grant, _) = &self.scope else {
            return None;
        };
        match &self.channel {
            Some(g) => super::channel_policy::Record::decode(0xb822, g.payload())
                .map(|r| [r.indices, r.indices_b]),
            None => Some(grant.power().indices()),
        }
    }
    /// B22 per-path TXAGC indices of the committed program for DESC_RATE
    /// 0..count: [`Self::b22_indices`], plus the bound `N2BH` HT words
    /// (`ht::Grant::b22_rates`; count 20 for 1SS, 28 for 2SS), or under a
    /// bound `N2BB` the HT40 words that replace them (`ht40::b22_words`).
    /// Under a bound `N2BV` the whole DESC_RATE 0x00..0x3f tables
    /// (`vht::b22_tables`: legacy12, HT zero, VHT1SS/2SS; count 64), with
    /// path-B VHT1SS (programmed zero) taking path A's index.
    pub(super) fn b22_rate_indices(
        &self,
    ) -> Option<([[u8; super::tracking8822b::RATES]; 2], usize)> {
        if let Some(g) = &self.ht {
            if let Some(r) = self.ht40_record() {
                let words = super::ht40::b22_words(self.b22_indices()?, &r);
                let mut rates = [[0; super::tracking8822b::RATES]; 2];
                for (rate, w) in rates.iter_mut().zip(words) {
                    for (i, v) in w.into_iter().enumerate() {
                        rate[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
                    }
                }
                // Path-B HT1S is programmed zero (1SS transmits on A):
                // headroom uses path A's index, as for `N2BH`.
                rates[1][12..20].copy_from_slice(&r.indices[..8]);
                return Some((rates, if r.mcs & 0xff00 != 0 { 28 } else { 20 }));
            }
            if let Some(v) = self.vht_record() {
                let mut rates = super::vht::b22_tables(self.b22_indices()?, &v);
                let one: [u8; 10] = rates[0][0x2c..0x36].try_into().ok()?;
                rates[1][0x2c..0x36].copy_from_slice(&one);
                return Some((rates, super::tracking8822b::RATES));
            }
            return g.b22_rates();
        }
        let legacy = self.b22_indices()?;
        let mut rates = [[0; super::tracking8822b::RATES]; 2];
        for (r, l) in rates.iter_mut().zip(legacy) {
            r[..12].copy_from_slice(&l);
        }
        Some((rates, 12))
    }
    /// B22 `N2BP` measured thermal windows (`operating8822b::Grant::temperature`).
    pub(super) fn b22_temperature(
        &self,
        value: u8,
    ) -> Result<(), super::firmware_transport::Error> {
        match &self.scope {
            Scope::B22(grant, _) => grant.temperature(value),
            _ => Err(super::firmware_transport::Error::Unsupported),
        }
    }
    /// C21 cross-band `rtw8821c_set_channel` facts (None on C22).
    pub(super) fn band_facts(&self) -> Option<super::radio8821c::BandFacts> {
        match &self.scope {
            Scope::C21(g) => Some(g.band_facts()),
            Scope::B22(..) => None,
            Scope::C22 { .. } => None,
        }
    }
    /// C22 5GHz OFDM references and difference words of the bound 5GHz
    /// N2xO record.
    pub(super) fn ofdm5(&self) -> Option<([u8; 2], [u32; 2])> {
        let g = self.channel.as_ref()?;
        super::channel_policy::Record::decode(self.did(), g.payload())
            .filter(|r| self.did() == 0xc822 && r.band5())
            .map(|r| (r.ofdm, r.diffs))
    }
    /// Factory 5GHz OFDM index ceilings for one 5GHz channel group: C22
    /// per path, C21 path A in both slots.
    pub(super) fn band5_limits(&self, group: usize) -> Option<[u8; 2]> {
        match &self.scope {
            Scope::C22 { calibration, .. } => {
                calibration.board.band5_groups.get(group).copied().flatten()
            }
            Scope::C21(g) => g.band5_group(group).map(|l| [l; 2]),
            Scope::B22(grant, _) => grant.power().band5_limits(group),
        }
    }
    /// Factory HT40 `(1S, 2S)` index ceilings for the group of a 40MHz
    /// `center` channel: 2.4GHz `rtw_get_channel_group` (`bw40_base`) or
    /// the 5GHz group (`band5::Power5g::bw40`; C21 path A, factor 1).
    pub(super) fn ht40_limits(&self, center: u8) -> Option<(u8, Option<u8>)> {
        if let Some(group) = super::channel_policy::group(center) {
            return match &self.scope {
                Scope::C22 { calibration, .. } => {
                    calibration.board.ht40_groups.get(group).copied().flatten()
                }
                Scope::C21(g) => g.ht40_group(group).map(|m| (m, None)),
                Scope::B22(grant, _) => grant.power().ht40_limits(false, group),
            };
        }
        let group = super::band5::group(center)?;
        match &self.scope {
            Scope::C22 { calibration, .. } => calibration
                .board
                .ht40_5_groups
                .get(group)
                .copied()
                .flatten(),
            Scope::C21(g) => g.ht40_5_group(group).map(|m| (m, None)),
            Scope::B22(grant, _) => grant.power().ht40_limits(true, group),
        }
    }
    /// Factory VHT80 `(1S, 2S)` index ceilings for an 80MHz `center`
    /// (`rtw_phy_get_5g_tx_power_index` BW80 over the center's 5GHz group;
    /// C21 path A, factor 1).
    pub(super) fn vht80_limits(&self, center: u8) -> Option<(u8, Option<u8>)> {
        if !super::band5::is_center80(center) {
            return None;
        }
        let group = super::band5::group(center)?;
        match &self.scope {
            Scope::C22 { calibration, .. } => {
                calibration.board.vht80_groups.get(group).copied().flatten()
            }
            Scope::C21(g) => g.vht80_group(group).map(|m| (m, None)),
            Scope::B22(grant, _) => grant.power().vht80_limits(group),
        }
    }
    /// C22 5GHz OFDM6..54 both-path selection of the bound 5GHz N2xO
    /// record (`channel_policy::Record::ofdm5_indices`).
    pub(super) fn ofdm5_indices(&self) -> Option<[u8; 8]> {
        if self.did() != 0xc822 {
            return None;
        }
        super::channel_policy::Record::decode(self.did(), self.channel.as_ref()?.payload())?
            .ofdm5_indices()
    }
    pub(super) fn did(&self) -> u16 {
        match &self.scope {
            Scope::C22 { .. } => 0xc822,
            Scope::C21(_) => 0xc821,
            Scope::B22(..) => 0xb822,
        }
    }
    /// Host identity keying this board's records (`phy8821c::Host`).
    pub(super) fn host(&self) -> super::phy8821c::Host {
        match &self.scope {
            Scope::C22 { .. } => super::phy8821c::Host::PCI_C22,
            Scope::C21(grant) => grant.host(),
            Scope::B22(grant, _) => grant.host(),
        }
    }
    pub(super) fn own(&self) -> [u8; 6] {
        match &self.scope {
            Scope::C22 { own, .. } => *own,
            Scope::C21(grant) => grant.own(),
            Scope::B22(grant, _) => grant.own(),
        }
    }
    pub(super) fn current(&self) -> Result<(), Error> {
        self.host_current()?;
        if let Some(g) = &self.channel {
            super::channel_policy::current(g, self.did()).map_err(|_| Error::Policy)?;
        }
        if let Some(g) = &self.ht40 {
            super::ht40::current(g, self).map_err(|_| Error::Policy)?;
        }
        if let Some(g) = &self.vht {
            super::vht::current(g, self).map_err(|_| Error::Policy)?;
        }
        if let Some(g) = &self.tracking {
            g.invoke(|| Ok(())).map_err(|_| Error::Authority)?;
        }
        if let Some(g) = &self.protection {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.tx_ba {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.rx_ba {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.ht {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.extension {
            return g.check().map_err(|_| Error::Authority);
        }
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                ..
            } => {
                let domain = narf_wireless::reg::db::get_domain().ok_or(Error::Policy)?;
                calibration.validate(*permission, &domain)
            }
            Scope::C21(grant) => grant.check().map_err(|e| match e {
                super::firmware_transport::Error::Calibration8821c(
                    super::calibration8821c::Error::Authority,
                ) => Error::Authority,
                _ => Error::Policy,
            }),
            Scope::B22(grant, _) => grant.invoke(&b22_policy, || Ok(())).map_err(b22_error),
        }
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        match &self.tracking {
            Some(g) => g.invoke(|| self.invoke_base(operation)),
            None => self.invoke_base(operation),
        }
    }
    /// Deliberately never dispatch through N21W: maintenance and retained
    /// source checks cannot recursively instantiate the full Gate invoker.
    pub(super) fn invoke_base<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        self.host_current()
            .map_err(super::firmware_transport::Error::Power)?;
        if let Some(g) = &self.ht40 {
            super::ht40::current(g, self)?;
        }
        if let Some(g) = &self.vht {
            super::vht::current(g, self)?;
        }
        if let Some(g) = &self.protection {
            return g.invoke(operation);
        }
        if let Some(g) = &self.tx_ba {
            return g.invoke(operation);
        }
        if let Some(g) = &self.rx_ba {
            return g.invoke(operation);
        }
        if let Some(g) = &self.ht {
            return g.invoke(operation);
        }
        if let Some(g) = &self.extension {
            return g.invoke(operation);
        }
        self.invoke_inner(None, operation)
    }
    pub(super) fn current_in(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        self.host_current()?;
        if let Some(g) = &self.channel {
            super::channel_policy::current_in(g, self.did(), domain).map_err(|_| Error::Policy)?;
        }
        if let Some(g) = &self.ht40 {
            super::ht40::current_in(g, self, domain).map_err(|_| Error::Policy)?;
        }
        if let Some(g) = &self.vht {
            super::vht::current_in(g, self, domain).map_err(|_| Error::Policy)?;
        }
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                ..
            } => calibration.validate(*permission, domain),
            Scope::C21(_) => self.current(),
            Scope::B22(grant, _) => grant
                .invoke(&|| Ok(domain.clone()), || Ok(()))
                .map_err(b22_error),
        }
    }
    /// The committed primary's admitted span is passive-only under `domain`
    /// (a 5GHz N2xO record under a DFS / NO_IR rule, `channel_policy::
    /// passive_rule`). The base channel 1 never is. Live, like `current_in`.
    pub(super) fn passive_in(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<bool, Error> {
        match &self.channel {
            Some(g) => {
                super::channel_policy::passive_in(g, self.did(), domain).map_err(|_| Error::Policy)
            }
            None => Ok(false),
        }
    }
    /// Identity every continuation program is qualified over: the exact
    /// base, channel-scoped by the bound N2xO record off channel 1.
    pub(super) fn extension_request(&self) -> Option<super::station_profile::Request> {
        // B22's unscoped base is the N2BS station record (what N2BO binds);
        // its continuations bind the N2BL request over it, exactly as
        // `ExtensionBase::request` scopes it.
        let base = match &self.scope {
            Scope::B22(grant, _) => Some(grant.extension_request()),
            _ => self.base_request(),
        };
        base.map(|b| scoped(b, self.did(), self.channel.as_deref()))
    }
    /// The unscoped base (N22Cv2/N21S) request, which N2xO records bind.
    pub(super) fn base_request(&self) -> Option<super::station_profile::Request> {
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                own,
            } => Some(super::station_profile::request(
                permission.identity,
                calibration.digest,
                permission.gains,
                *own,
            )),
            Scope::C21(g) => Some(g.extension_request()),
            Scope::B22(grant, _) => {
                let r = grant.request();
                Some(super::station_profile::Request {
                    identity: r.identity,
                    mac: r.mac,
                    filename: r.filename.clone(),
                })
            }
        }
    }
    pub(super) fn eirp(&self) -> Option<i16> {
        match &self.scope {
            Scope::C22 { permission, .. } => Some(permission.eirp),
            Scope::C21(_) | Scope::B22(..) => None,
        }
    }
    pub(super) fn cck_gains(&self) -> Option<[u8; 2]> {
        if let Some(g) = &self.channel {
            return super::channel_policy::Record::decode(self.did(), g.payload())
                .filter(|r| self.did() == 0xc822 && !r.band5())
                .map(|r| r.gains);
        }
        match &self.scope {
            Scope::C22 { permission, .. } => Some(permission.gains),
            Scope::C21(_) | Scope::B22(..) => None,
        }
    }
    pub(super) fn allows_profile(&self, p: super::packet_format::DataProfile) -> bool {
        // The profile's band is the committed primary's band.
        if p.band5 != super::band5::primary(self.channel()) {
            return false;
        }
        if (p.ldpc || p.stbc)
            && !self.coding.as_ref().is_some_and(|g| {
                super::coding::bounds(self.did(), g.payload())
                    .is_some_and(|f| super::coding::permits(f, p))
                    && g.check(self).is_ok()
            })
        {
            return false;
        }
        if p.acs != 0
            && !self.qos.as_ref().is_some_and(|g| {
                super::qos::bounds(g.payload()).is_some_and(|a| p.acs & !a == 0)
                    && g.check(self).is_ok()
            })
        {
            return false;
        }
        if p.fallback
            && !self
                .fallback
                .as_ref()
                .is_some_and(|g| super::fallback::bounds(g.payload()) && g.check(self).is_ok())
        {
            return false;
        }
        if p.bw40
            && !self.ht40.as_ref().is_some_and(|g| {
                super::ht40::Record::decode(self.did(), g.payload())
                    .is_some_and(|r| p.mcs != 0 && p.mcs & !r.mcs == 0 && (!p.sgi || r.sgi))
                    && super::ht40::current(g, self).is_ok()
            })
        {
            return false;
        }
        // VHT at 80MHz: the TX set within the bound N2xV selection, the RX
        // set exactly `rtw_init_vht_cap` on the HT program's streams, SGI80
        // only under the record's SGI80 qualification; uncoded.
        if let Some(v) = p.vht {
            let rx = super::packet_format::DataProfile::vht_rx_for(p.rx_mcs);
            if p.ldpc
                || p.stbc
                || v.rx != rx
                || !self.vht.as_ref().is_some_and(|g| {
                    super::vht::Record::decode(self.did(), g.payload())
                        .is_some_and(|r| v.tx & !r.tx_mask() == 0 && (!p.sgi || r.sgi))
                        && super::vht::current(g, self).is_ok()
                })
            {
                return false;
            }
        }
        // At 40MHz the SGI bit is SGI40, admitted by N2xB above, and at 80MHz
        // SGI80 by N2xV; the HT program admits the remaining HT20-qualified
        // fields.
        let p = super::packet_format::DataProfile {
            acs: 0,
            fallback: false,
            bw40: false,
            vht: None,
            sgi: p.sgi && !p.bw40 && p.vht.is_none(),
            ..p.uncoded()
        };
        if let Some(g) = &self.ht {
            return g.allows(p);
        }
        if p.mcs != 0 || p.sgi {
            return false;
        }
        p.valid()
            && match &self.extension {
                Some(g) => p.rates & !g.rates() == 0 && (!p.qos || g.wmm()),
                None => {
                    p == if p.band5 {
                        super::packet_format::DataProfile::LEGACY5
                    } else {
                        super::packet_format::DataProfile::LEGACY
                    }
                }
            }
    }
    pub(super) fn with_extension(
        &self,
        g: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.did() != g.did() || self.extension.is_some() || !g.matches(self) {
            return Err(super::firmware_transport::Error::State);
        }
        g.check()?;
        let mut gate = self.clone();
        gate.extension = Some(g);
        Ok(gate)
    }
    pub(super) fn ht_facts(&self) -> Option<super::ht::Facts> {
        let facts = match &self.scope {
            Scope::B22(b, _) => b.ht_facts(),
            Scope::C21(b) => b.ht_facts(),
            Scope::C22 {
                calibration,
                permission,
                ..
            } => calibration.board.ht.map(|mut f| {
                f.cck = permission.gains;
                f
            }),
        };
        let group = |five: bool, g: usize| match &self.scope {
            Scope::C21(b) if five => b.ht5_group(g).map(|m| (m, None)),
            Scope::C21(b) => b.ht_group(g).map(|m| (m, None)),
            Scope::C22 { calibration, .. } if five => calibration.board.ht5_groups[g],
            Scope::C22 { calibration, .. } => calibration.board.ht_groups[g],
            Scope::B22(b, _) => b.power().ht_limits(five, g),
        };
        overlay(self.did(), facts, self.channel.as_deref(), group)
    }
    pub(super) fn ht_base(&self) -> Option<alloc::sync::Arc<super::station_profile::Grant>> {
        self.extension.clone().filter(|_| self.ht.is_none())
    }
    pub(super) fn ht_grant(&self) -> Option<alloc::sync::Arc<super::ht::Grant>> {
        self.ht.clone()
    }
    pub(super) fn with_rx_ba(
        &self,
        g: alloc::sync::Arc<super::rx_ba_power::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.rx_ba.is_some()
            || self.tx_ba.is_some()
            || self.protection.is_some()
            || self.ht.as_ref().is_none_or(|h| !g.matches(h))
        {
            return Err(super::firmware_transport::Error::State);
        }
        g.check()?;
        let mut gate = self.clone();
        gate.rx_ba = Some(g);
        Ok(gate)
    }
    pub(super) fn allows_rx_ba(&self) -> bool {
        self.rx_ba.is_some()
    }
    pub(super) fn tx_base(&self) -> Option<super::tx_ba_power::Base> {
        if self.tx_ba.is_some() || self.protection.is_some() {
            return None;
        }
        match &self.rx_ba {
            Some(r) => Some(super::tx_ba_power::Base::R(r.clone())),
            None => self.ht.clone().map(super::tx_ba_power::Base::H),
        }
    }
    pub(super) fn with_tx_ba(
        &self,
        g: alloc::sync::Arc<super::tx_ba_power::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.tx_base().as_ref().is_none_or(|b| !g.matches(b)) {
            return Err(super::firmware_transport::Error::State);
        }
        g.check()?;
        let mut gate = self.clone();
        gate.tx_ba = Some(g);
        Ok(gate)
    }
    pub(super) fn allows_tx_ba(&self) -> bool {
        self.tx_ba.is_some()
    }
    pub(super) fn protection_base(&self) -> Option<super::protection::Base> {
        if self.protection.is_some() {
            return None;
        }
        if let Some(t) = &self.tx_ba {
            return Some(super::protection::Base::T(t.clone()));
        }
        if let Some(r) = &self.rx_ba {
            return Some(super::protection::Base::R(r.clone()));
        }
        self.ht.clone().map(super::protection::Base::H)
    }
    pub(super) fn with_protection(
        &self,
        g: alloc::sync::Arc<super::protection::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self
            .protection_base()
            .as_ref()
            .is_none_or(|b| !g.matches(b))
        {
            return Err(super::firmware_transport::Error::State);
        }
        g.check()?;
        let mut gate = self.clone();
        gate.protection = Some(g);
        Ok(gate)
    }
    /// Bind N2xC TX coding (over the bound HT program) or N2xQ QoS routing
    /// (over the bound WMM extension) into a new gate.
    pub(super) fn with_continuation(
        &self,
        g: alloc::sync::Arc<super::qualification::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        let coding = g.is(&super::coding::KIND)
            && self.ht.is_some()
            && self.coding.is_none()
            && super::coding::bounds(self.did(), g.payload()).is_some();
        let qos = g.is(&super::qos::KIND)
            && self.extension.as_ref().is_some_and(|e| e.wmm())
            && self.qos.is_none()
            && super::qos::bounds(g.payload()).is_some();
        let fallback = g.is(&super::fallback::KIND)
            && self.extension.is_some()
            && self.fallback.is_none()
            && super::fallback::bounds(g.payload());
        // N2xB HT40: over the bound HT program with its exact MCS set, on the
        // gate's own primary, within the center group's factory BW40 base.
        let ht40 = g.is(super::ht40::kind(self.channel()))
            && self.ht40.is_none()
            && super::ht40::Record::decode(self.did(), g.payload()).is_some_and(|r| {
                self.ht.as_ref().is_some_and(|h| h.mcs() == r.mcs)
                    && r.primary == self.channel()
                    && super::ht40::within_factory(self, &r)
            });
        // N2xV VHT80: over the bound HT program on the gate's own 5GHz
        // primary, never together with N2xB, within the center group's
        // factory BW80 base.
        let vht = g.is(&super::vht::KIND)
            && self.vht.is_none()
            && self.ht40.is_none()
            && self.ht.is_some()
            && super::vht::Record::decode(self.did(), g.payload()).is_some_and(|r| {
                r.primary == self.channel() && super::vht::within_factory(self, &r)
            });
        if !coding && !qos && !fallback && !ht40 && !vht {
            return Err(super::firmware_transport::Error::State);
        }
        g.check(self)?;
        if ht40 {
            super::ht40::current(&g, self)?;
        }
        if vht {
            super::vht::current(&g, self)?;
        }
        let mut gate = self.clone();
        if coding {
            gate.coding = Some(g);
        } else if qos {
            gate.qos = Some(g);
        } else if fallback {
            gate.fallback = Some(g);
        } else if ht40 {
            gate.ht40 = Some(g);
        } else {
            gate.vht = Some(g);
        }
        Ok(gate)
    }
    /// The bound N2xB HT40 record, if any.
    pub(super) fn ht40_record(&self) -> Option<super::ht40::Record> {
        self.ht40
            .as_ref()
            .and_then(|g| super::ht40::Record::decode(self.did(), g.payload()))
    }
    /// The bound N2xV VHT80 record, if any.
    pub(super) fn vht_record(&self) -> Option<super::vht::Record> {
        self.vht
            .as_ref()
            .and_then(|g| super::vht::Record::decode(self.did(), g.payload()))
    }
    pub(super) fn coding_grant(&self) -> Option<alloc::sync::Arc<super::qualification::Grant>> {
        self.coding.clone()
    }
    pub(super) fn protection_grant(&self) -> Option<alloc::sync::Arc<super::protection::Grant>> {
        self.protection.clone()
    }
    pub(super) fn rts_threshold(&self) -> Option<u32> {
        self.protection.as_ref().map(|g| g.threshold())
    }
    pub(super) fn tx_grant(&self) -> Option<alloc::sync::Arc<super::tx_ba_power::Grant>> {
        self.tx_ba.clone()
    }
    pub(super) fn with_ht(
        &self,
        g: alloc::sync::Arc<super::ht::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.ht.is_some() || self.extension.as_ref().is_none_or(|b| !g.matches(b)) {
            return Err(super::firmware_transport::Error::State);
        }
        g.check()?;
        let mut gate = self.clone();
        gate.ht = Some(g);
        Ok(gate)
    }
    /// Keep the exact current all-AC continuation around the real immutable
    /// batch publication; checking a cached profile before callbacks is not
    /// authority to ring a later BK/VI doorbell.
    pub(super) fn invoke_batch<T>(
        &self,
        profile: super::packet_format::DataProfile,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        self.host_current()
            .map_err(super::firmware_transport::Error::Power)?;
        if !self.allows_profile(profile) {
            return Err(super::firmware_transport::Error::Prerequisite);
        }
        if profile.acs == 0 {
            self.invoke(operation)
        } else {
            self.qos
                .as_ref()
                .ok_or(super::firmware_transport::Error::State)?
                .invoke(self, operation)
        }
    }
    pub(super) fn power_tracking(&self) -> Option<alloc::sync::Arc<super::tracking8821c::Grant>> {
        self.tracking.clone()
    }
    pub(super) fn without_power_tracking(&self) -> Self {
        let mut g = self.clone();
        g.tracking = None;
        g
    }
    pub(super) fn with_power_tracking(
        &self,
        g: alloc::sync::Arc<super::tracking8821c::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.tracking.is_some() || !g.matches(self) {
            return Err(super::firmware_transport::Error::State);
        }
        g.invoke(|| Ok(()))?;
        let mut gate = self.clone();
        gate.tracking = Some(g);
        Ok(gate)
    }
    pub(super) fn tracking_sources(
        &self,
    ) -> [Option<alloc::sync::Arc<super::qualification::Grant>>; 3] {
        [self.coding.clone(), self.qos.clone(), self.fallback.clone()]
    }
    pub(super) fn tracking_factory_limits(&self) -> Option<[u8; 3]> {
        let Scope::C21(g) = &self.scope else {
            return None;
        };
        // Off channel 1 the bound primary's own rtw_get_channel_group.
        let [cck, ofdm] = match &self.channel {
            None => g.factory_limits(),
            Some(_) => g.group_limits(super::channel_policy::group(self.channel())?)?,
        };
        Some([cck, ofdm, self.ht_facts()?.maximum])
    }
    /// Current ceiling of the exact H/R/T/RTS prefix, without W dispatch.
    pub(super) fn tracking_limit(&self) -> Result<i16, super::firmware_transport::Error> {
        if let Some(g) = &self.protection {
            return g.limit();
        }
        if let Some(g) = &self.tx_ba {
            return g.limit();
        }
        if let Some(g) = &self.rx_ba {
            return g.limit();
        }
        self.ht
            .as_ref()
            .ok_or(super::firmware_transport::Error::State)?
            .rx_ba_limit()
    }
    pub(super) fn tracking_identity(
        &self,
        h: &mut narf_crypto::sha256::Sha256,
    ) -> Result<(), super::firmware_transport::Error> {
        let ht = self
            .ht
            .as_ref()
            .ok_or(super::firmware_transport::Error::State)?;
        let (id, digest, did) = ht.rx_ba_identity();
        h.update(&did.to_le_bytes());
        h.update(&id);
        h.update(&digest);
        h.update(
            &self
                .tracking_factory_limits()
                .ok_or(super::firmware_transport::Error::State)?,
        );
        if let Some(r) = &self.rx_ba {
            let (i, d) = r.tx_identity();
            h.update(b"R");
            h.update(&i);
            h.update(&d);
        } else {
            h.update(b"noR");
        }
        if let Some(t) = &self.tx_ba {
            let (i, d) = t.protection_identity();
            h.update(b"T");
            h.update(&i);
            h.update(&d);
        } else {
            h.update(b"noT");
        }
        if let Some(x) = &self.protection {
            let (i, d) = x.tracking_identity();
            h.update(b"X");
            h.update(&i);
            h.update(&d);
        } else {
            h.update(b"noX");
        }
        for g in &self.tracking_sources() {
            match g {
                Some(g) => {
                    let (i, d) = g.source_identity();
                    h.update(&[g.tag()]);
                    h.update(&i);
                    h.update(&d);
                }
                None => h.update(&[0]),
            }
        }
        // The N21W program's MCS indices follow the bound width: an HT20
        // record must not authorize HT40 tracking or vice versa. The None
        // arm hashes nothing, so HT20 request identities — and every
        // already-provisioned HT20 record — are byte-identical to before.
        if let Some(g) = &self.ht40 {
            let (i, d) = g.source_identity();
            h.update(b"B");
            h.update(&i);
            h.update(&d);
        }
        Ok(())
    }
    pub(super) fn c21_indices(&self) -> Option<[u8; 12]> {
        if let Some(g) = &self.channel {
            return super::channel_policy::Record::decode(self.did(), g.payload())
                .filter(|_| self.did() == 0xc821)
                .map(|r| r.indices);
        }
        match &self.scope {
            Scope::C21(g) => Some(g.indices()),
            Scope::C22 { .. } | Scope::B22(..) => None,
        }
    }
    pub(super) fn invoke_with_domain<T>(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        if let Some(g) = &self.tracking {
            return g.invoke(|| self.invoke_base(operation));
        }
        if let Some(g) = &self.protection {
            return g.invoke(operation);
        }
        if let Some(g) = &self.tx_ba {
            return g.invoke(operation);
        }
        if let Some(g) = &self.rx_ba {
            return g.invoke(operation);
        }
        if let Some(g) = &self.ht {
            return g.invoke(operation);
        }
        if let Some(g) = &self.extension {
            return g.invoke(operation);
        }
        self.invoke_inner(Some(domain), operation)
    }
    fn invoke_inner<T>(
        &self,
        domain: Option<&narf_wireless::reg::RegulatoryDomain>,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        self.host_current()
            .map_err(super::firmware_transport::Error::Power)?;
        match &self.scope {
            Scope::C21(grant) => grant.invoke(operation),
            Scope::B22(grant, _) => {
                // The bound `N2BO` record and its span re-enter inside the
                // nested `N2BQ` + `N2BP` + `N2BS` invocation.
                let operation = || {
                    if let Some(g) = &self.channel {
                        match domain {
                            Some(d) => super::channel_policy::current_in(g, 0xb822, d)?,
                            None => super::channel_policy::current(g, 0xb822)?,
                        }
                    }
                    operation()
                };
                match domain {
                    Some(d) => grant.invoke(&|| Ok(d.clone()), operation),
                    None => grant.invoke(&b22_policy, operation),
                }
            }
            Scope::C22 { calibration, .. } => {
                struct Invoke<'a, F> {
                    gate: &'a Gate,
                    domain: Option<&'a narf_wireless::reg::RegulatoryDomain>,
                    operation: F,
                }
                impl<T, F: FnOnce() -> Result<T, super::firmware_transport::Error>>
                    CapOp<FirmwareBlob, Read> for Invoke<'_, F>
                {
                    type Output = Result<T, super::firmware_transport::Error>;
                    fn execute(
                        self,
                        _: &Cap<FirmwareBlob, Read>,
                    ) -> Result<Self::Output, CapError> {
                        Ok((|| {
                            match self.domain {
                                Some(d) => self.gate.current_in(d),
                                None => self.gate.current(),
                            }
                            .map_err(super::firmware_transport::Error::Power)?;
                            (self.operation)()
                        })())
                    }
                }
                calibration
                    .authority
                    .0
                    .invoke(Invoke {
                        gate: self,
                        domain,
                        operation,
                    })
                    .map_err(|_| super::firmware_transport::Error::Power(Error::Authority))?
            }
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn current_with_policy_for_test(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        self.host_current()?;
        if let Some(g) = &self.protection {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.tx_ba {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.rx_ba {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.ht {
            return g.check().map_err(|_| Error::Authority);
        }
        if let Some(g) = &self.extension {
            return g.check().map_err(|_| Error::Authority);
        }
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                ..
            } => calibration.validate(*permission, domain),
            Scope::C21(_) => self.current(),
            Scope::B22(grant, _) => grant
                .invoke(&|| Ok(domain.clone()), || Ok(()))
                .map_err(b22_error),
        }
    }
}
impl Permission {
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp
    }
}
fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn signed(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
struct ReadCalibration(Board);
impl CapOp<FirmwareBlob, Read> for ReadCalibration {
    type Output = Result<Calibration, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            Calibration::from_verified(view.bytes, view.signer, self.0, Authority(*cap))
        })())
    }
}
impl Calibration {
    fn load_registered(board: Board) -> Result<Self, Error> {
        let m = board.mac;
        let name = format!(
            "rtw88/rtw8822ce-cal-v2-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &authority).map_err(Error::Firmware)?;
        cap.invoke(ReadCalibration(board))
            .map_err(|_| Error::Authority)?
    }
    fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Authority,
    ) -> Result<Self, Error> {
        authority.current()?;
        signer.ok_or(Error::Unsigned)?;
        if bytes.len() != LENGTH
            || &bytes[..4] != b"N22C"
            || half(bytes, 4) != 2
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != LENGTH
            || half(bytes, 12) != 0x10ec
            || half(bytes, 14) != 0xc822
            || bytes[54] != 1
            || bytes[55] != 3
            || half(bytes, 60) != 2
            || bytes[66..HEADER] != [0; HEADER - 66]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let antenna = signed(bytes, 56);
        let qualified = signed(bytes, 58);
        let calibration_peak = signed(bytes, 62);
        let response_peak = signed(bytes, 64);
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&qualified)
            || !(-512..=256).contains(&calibration_peak)
            || !(-512..=256).contains(&response_peak)
        {
            return Err(Error::Format);
        }
        let curves = core::array::from_fn(|path| {
            core::array::from_fn(|index| signed(bytes, HEADER + path * 256 + index * 2))
        });
        if curves
            .iter()
            .flatten()
            .any(|v| *v != UNKNOWN && !(-512..=256).contains(v))
        {
            return Err(Error::Format);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(bytes);
        Ok(Self {
            board,
            authority,
            digest: hash.finalize(),
            antenna,
            qualified,
            calibration_peak,
            response_peak,
            curves,
        })
    }
    pub(super) fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Permission, Error> {
        self.authority.current()?;
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let mut covering = false;
        let mut ceiling = None;
        for (i, rule) in domain.rules.iter().enumerate() {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz > 2402
                || rule.freq_end_mhz < 2422
                || !super::channel_policy::plain_rule(domain, i, 20)
            {
                return Err(Error::Policy);
            }
            covering |= rule.freq_start_mhz <= 2402 && rule.freq_end_mhz >= 2422;
            let limit = i16::from(rule.max_power_dbm) * 4;
            ceiling = Some(ceiling.map_or(limit, |old: i16| old.min(limit)));
        }
        if !covering {
            return Err(Error::Policy);
        }
        // Explicit conservative initial-profile ceiling; additional source
        // factory/PG/region restrictions were already applied to each index.
        let eirp = ceiling.ok_or(Error::Policy)?.min(self.qualified).min(80);
        if i32::from(self.calibration_peak) + i32::from(self.antenna) > i32::from(eirp) {
            return Err(Error::Policy);
        }
        if i32::from(self.response_peak) + i32::from(self.antenna) > i32::from(eirp) {
            return Err(Error::Policy);
        }
        let mut gains = [0; 2];
        for (path, gain) in gains.iter_mut().enumerate() {
            *gain = (0..=self.board.maximum[path])
                .rev()
                .find(|index| {
                    let bound = self.curves[path][usize::from(*index)];
                    bound != UNKNOWN
                        && i32::from(bound) + i32::from(self.antenna) <= i32::from(eirp)
                })
                .ok_or(Error::NoMeasuredGain)?;
        }
        Ok(Permission {
            identity: self.board.identity,
            calibration: self.digest,
            gains,
            eirp,
        })
    }
    pub(super) fn validate(
        &self,
        permission: Permission,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        if self.permission(domain)? == permission {
            Ok(())
        } else {
            Err(Error::Policy)
        }
    }
    pub(super) fn matches(&self, board: Board) -> bool {
        self.board == board
    }
    pub(super) fn gains(
        &self,
        permission: Permission,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<[u8; 2], Error> {
        self.validate(permission, domain)?;
        Ok(permission.gains)
    }
}
