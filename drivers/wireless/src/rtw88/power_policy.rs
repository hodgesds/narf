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
    ht: Option<super::ht::Facts>,
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
        Ok(Self {
            identity: hash.finalize(),
            mac: factory.mac(),
            maximum,
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
    scope: Scope,
    extension: Option<alloc::sync::Arc<super::station_profile::Grant>>,
    ht: Option<alloc::sync::Arc<super::ht::Grant>>,
    rx_ba: Option<alloc::sync::Arc<super::rx_ba_power::Grant>>,
    tx_ba: Option<alloc::sync::Arc<super::tx_ba_power::Grant>>,
    protection: Option<alloc::sync::Arc<super::protection::Grant>>,
    /// Separately qualified N2xC TX coding over the exact base and bound H.
    /// Not part of `current`/`invoke`: revocation downgrades to uncoded TX.
    coding: Option<alloc::sync::Arc<super::qualification::Grant>>,
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
pub(super) enum ExtensionBase {
    C22(CalibratedBase),
    C21(alloc::sync::Arc<super::station_power8821c::Grant>),
}
impl ExtensionBase {
    pub(super) fn ht_facts(&self) -> Option<super::ht::Facts> {
        match self {
            Self::C21(b) => b.ht_facts(),
            Self::C22(b) => b.calibration.board.ht.map(|mut f| {
                f.cck = b.permission.gains;
                f
            }),
        }
    }
    pub(super) fn did(&self) -> u16 {
        match self {
            Self::C22(_) => 0xc822,
            Self::C21(_) => 0xc821,
        }
    }
    pub(super) fn request(&self) -> super::station_profile::Request {
        match self {
            Self::C22(b) => b.request(),
            Self::C21(b) => b.extension_request(),
        }
    }
    pub(super) fn current(
        &self,
        d: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<i16, super::firmware_transport::Error> {
        match self {
            Self::C22(b) => {
                b.current(d)
                    .map_err(super::firmware_transport::Error::Power)?;
                Ok(b.eirp())
            }
            Self::C21(b) => {
                b.check()?;
                b.extension_limit(d)
            }
        }
    }
    pub(super) fn invoke<T>(
        &self,
        d: &narf_wireless::reg::RegulatoryDomain,
        op: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
        match self {
            Self::C22(b) => b.invoke(d, op),
            Self::C21(b) => b.invoke(op),
        }
    }
}
#[derive(Clone)]
enum Scope {
    C22 {
        calibration: alloc::sync::Arc<Calibration>,
        permission: Permission,
        own: [u8; 6],
    },
    C21(alloc::sync::Arc<super::station_power8821c::Grant>),
}
impl Gate {
    pub(super) fn extension_base(&self) -> Option<ExtensionBase> {
        if self.extension.is_some() {
            return None;
        }
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                own,
            } => Some(ExtensionBase::C22(CalibratedBase {
                calibration: calibration.clone(),
                permission: *permission,
                own: *own,
            })),
            Scope::C21(b) => Some(ExtensionBase::C21(b.clone())),
        }
    }
    pub(super) fn calibrated_base(&self) -> Option<CalibratedBase> {
        if self.extension.is_some() {
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
            Scope::C21(_) => None,
        }
    }
    pub(super) fn new(
        calibration: alloc::sync::Arc<Calibration>,
        permission: Permission,
        own: [u8; 6],
    ) -> Self {
        Self {
            extension: None,
            ht: None,
            rx_ba: None,
            tx_ba: None,
            protection: None,
            coding: None,
            scope: Scope::C22 {
                calibration,
                permission,
                own,
            },
        }
    }
    pub(super) fn c21(grant: alloc::sync::Arc<super::station_power8821c::Grant>) -> Self {
        Self {
            scope: Scope::C21(grant),
            extension: None,
            ht: None,
            rx_ba: None,
            tx_ba: None,
            protection: None,
            coding: None,
        }
    }
    pub(super) fn did(&self) -> u16 {
        match &self.scope {
            Scope::C22 { .. } => 0xc822,
            Scope::C21(_) => 0xc821,
        }
    }
    pub(super) fn own(&self) -> [u8; 6] {
        match &self.scope {
            Scope::C22 { own, .. } => *own,
            Scope::C21(grant) => grant.own(),
        }
    }
    pub(super) fn current(&self) -> Result<(), Error> {
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
        }
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
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
        match &self.scope {
            Scope::C22 {
                calibration,
                permission,
                ..
            } => calibration.validate(*permission, domain),
            Scope::C21(_) => self.current(),
        }
    }
    pub(super) fn extension_request(&self) -> Option<super::station_profile::Request> {
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
        }
    }
    pub(super) fn eirp(&self) -> Option<i16> {
        match &self.scope {
            Scope::C22 { permission, .. } => Some(permission.eirp),
            Scope::C21(_) => None,
        }
    }
    pub(super) fn cck_gains(&self) -> Option<[u8; 2]> {
        match &self.scope {
            Scope::C22 { permission, .. } => Some(permission.gains),
            Scope::C21(_) => None,
        }
    }
    pub(super) fn allows_profile(&self, p: super::packet_format::DataProfile) -> bool {
        if (p.ldpc || p.stbc)
            && !self.coding.as_ref().is_some_and(|g| {
                super::coding::bounds(self.did(), g.payload())
                    .is_some_and(|f| super::coding::permits(f, p))
                    && g.check(self).is_ok()
            })
        {
            return false;
        }
        if let Some(g) = &self.ht {
            return g.allows(p.uncoded());
        }
        if p.mcs != 0 || p.sgi {
            return false;
        }
        p.valid()
            && match &self.extension {
                Some(g) => p.rates & !g.rates() == 0 && (!p.qos || g.wmm()),
                None => p == super::packet_format::DataProfile::LEGACY,
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
        match &self.scope {
            Scope::C21(b) => b.ht_facts(),
            Scope::C22 {
                calibration,
                permission,
                ..
            } => calibration.board.ht.map(|mut f| {
                f.cck = permission.gains;
                f
            }),
        }
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
    /// Bind the N2xC TX-coding continuation over the bound HT program.
    pub(super) fn with_coding(
        &self,
        g: alloc::sync::Arc<super::qualification::Grant>,
    ) -> Result<Self, super::firmware_transport::Error> {
        if self.ht.is_none()
            || self.coding.is_some()
            || !g.is(&super::coding::KIND)
            || super::coding::bounds(self.did(), g.payload()).is_none()
        {
            return Err(super::firmware_transport::Error::State);
        }
        g.check(self)?;
        let mut gate = self.clone();
        gate.coding = Some(g);
        Ok(gate)
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
    pub(super) fn c21_indices(&self) -> Option<[u8; 12]> {
        match &self.scope {
            Scope::C21(g) => Some(g.indices()),
            Scope::C22 { .. } => None,
        }
    }
    pub(super) fn invoke_with_domain<T>(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, super::firmware_transport::Error>,
    ) -> Result<T, super::firmware_transport::Error> {
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
        match &self.scope {
            Scope::C21(grant) => grant.invoke(operation),
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
        for rule in &domain.rules {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz > 2402
                || rule.freq_end_mhz < 2422
                || rule.max_bandwidth_mhz < 20
                || rule.flags.bits() & !narf_wireless::reg::RegFlags::NO_P2P.bits() != 0
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
