// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Current host policy for native MLD station publication. A cached MCC
//! map is bound to its host country and already-programmed span/ceiling;
//! it is never a replacement for SAR or measured platform qualification.
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicI8, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::reg::RegulatoryDomain;

#[derive(Clone)]
pub(super) struct Source(Arc<dyn Fn() -> Option<Arc<RegulatoryDomain>> + Send + Sync>);
impl Source {
    pub fn native() -> Self {
        Self(Arc::new(narf_wireless::reg::db::snapshot))
    }
    pub fn snapshot(&self) -> Result<Arc<RegulatoryDomain>, &'static str> {
        (self.0)().ok_or("Intel current regulatory policy unavailable")
    }
    pub fn transaction(&self, requested: &RegulatoryDomain) -> Result<Transaction, &'static str> {
        let initial = self.snapshot()?;
        if initial.country_code != requested.country_code || initial.rules != requested.rules {
            return Err("Intel requested policy is no longer the installed authority");
        }
        Ok(Transaction {
            source: self.clone(),
            initial,
            validity: Validity::new(),
            mvm_ap: None,
        })
    }
    pub fn bind(&self, program: Program) -> Result<Fence, &'static str> {
        let fence = Fence {
            source: self.clone(),
            program,
        };
        fence.check()?;
        Ok(fence)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn database(database: Arc<narf_wireless::reg::db::Database>) -> Self {
        Self(Arc::new(move || database.snapshot()))
    }
}
#[derive(Clone)]
pub(super) struct Transaction {
    source: Source,
    initial: Arc<RegulatoryDomain>,
    validity: Validity,
    mvm_ap: Option<Arc<super::mvm_boot::ApPower>>,
}
impl Transaction {
    pub fn with_mvm_ap(
        mut self,
        power: Arc<super::mvm_boot::ApPower>,
    ) -> Result<Self, &'static str> {
        power.check(&self.initial)?;
        self.mvm_ap = Some(power);
        Ok(self)
    }
    pub fn invalidate(&self) {
        self.validity.invalidate();
    }
    pub fn check(&self) -> Result<(), &'static str> {
        self.validity.check()?;
        if !Arc::ptr_eq(&self.initial, &self.source.snapshot()?) {
            return Err("Intel regulatory policy changed during native configuration");
        }
        if let Some(power) = &self.mvm_ap {
            power.check(&self.initial)?;
        }
        Ok(())
    }
}
/// A native MCC notification or transport stop invalidates every copied
/// authority, including a delivery that already left the device mutex.
#[derive(Clone)]
pub(super) struct Validity(Arc<AtomicBool>);
impl Validity {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
    fn check(&self) -> Result<(), &'static str> {
        self.0
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or("Intel native MCC/policy epoch retired")
    }
    fn invalidate(&self) {
        self.0.store(false, Ordering::Release);
    }
}
/// Actual scanner requester and policy retained by native MLD ownership.
/// Currentness validation does not acquire native state; no user callback
/// runs while the short MCC fact cell is locked.
#[derive(Clone)]
pub(super) struct ScanAuthority(Arc<ScanProof>);
struct ScanProof {
    policy: Transaction,
    device: Weak<super::device::Device>,
    event: narf_wireless::ap_control::RadioEventAuthority,
    cancel: Arc<AtomicBool>,
}
impl ScanAuthority {
    pub fn new(
        policy: Transaction,
        device: Weak<super::device::Device>,
        event: narf_wireless::ap_control::RadioEventAuthority,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, &'static str> {
        let proof = Self(Arc::new(ScanProof {
            policy,
            device,
            event,
            cancel,
        }));
        proof.check()?;
        Ok(proof)
    }
    pub fn check(&self) -> Result<(), &'static str> {
        if self.0.cancel.load(Ordering::Acquire) {
            return Err("Intel periodic request canceled");
        }
        self.0.policy.check()?;
        let device = self
            .0
            .device
            .upgrade()
            .ok_or("Intel periodic device retired")?;
        self.0
            .event
            .check_for(device.as_ref())
            .map_err(|_| "Intel periodic caller/source retired")
    }
    pub fn invalidate(&self) {
        self.0.policy.invalidate();
    }
}

#[derive(Clone)]
pub(super) enum Authority {
    Transaction(Transaction),
    Station(Fence),
    StationAndScan { home: Fence, scan: ScanAuthority },
}
impl Authority {
    pub fn domain(&self) -> Result<Arc<RegulatoryDomain>, &'static str> {
        self.check()?;
        match self {
            Self::Transaction(t) => Ok(t.initial.clone()),
            Self::Station(f) => f.source.snapshot(),
            Self::StationAndScan { scan, .. } => Ok(scan.0.policy.initial.clone()),
        }
    }
    pub fn check(&self) -> Result<(), &'static str> {
        match self {
            Self::Transaction(t) => t.check(),
            Self::Station(f) => f.check(),
            Self::StationAndScan { home, scan } => {
                home.check()?;
                scan.check()
            }
        }
    }
    pub fn validity(&self) -> Validity {
        match self {
            Self::Transaction(t) => t.validity.clone(),
            Self::Station(f) => f.program.validity.clone(),
            Self::StationAndScan { home, .. } => home.program.validity.clone(),
        }
    }
    pub fn invalidate(&self) {
        self.validity().invalidate();
        if let Self::StationAndScan { scan, .. } = self {
            scan.invalidate();
        }
    }
}

/// Facts from the actual correlated MCC reply and completed link power
/// programming. Construction is private to the native association owner.
#[derive(Clone)]
pub(super) struct Program {
    country: [u8; 2],
    validity: Validity,
    firmware: Arc<IrqSafeSpinLock<super::mld_regulatory::Mcc>>,
    pub primary: u8,
    width: u8,
    center: u8,
    applied_dbm: Arc<AtomicI8>,
    qos: Option<super::qos::Parameters>,
    he: bool,
    eht: bool,
    band: super::native_band::Band,
    six: Option<(narf_wireless::reg::PowerType6Ghz, u32)>,
    ap: bool,
    mvm_ap: Option<(Arc<super::mvm_boot::ApPower>, bool)>,
}
impl Program {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: &RegulatoryDomain,
        firmware: super::mld_regulatory::Mcc,
        primary: u8,
        width: u8,
        center: u8,
        applied_dbm: i8,
        qos: Option<super::qos::Parameters>,
        validity: Validity,
    ) -> Result<Self, &'static str> {
        let program = Self {
            country: domain.country_code,
            validity,
            firmware: Arc::new(IrqSafeSpinLock::new(firmware)),
            primary,
            width,
            center,
            applied_dbm: Arc::new(AtomicI8::new(applied_dbm)),
            qos,
            he: false,
            eht: false,
            band: super::native_band::Channel::legacy(primary)
                .ok_or("Intel legacy policy channel absent")?
                .band,
            six: None,
            ap: false,
            mvm_ap: None,
        };
        program.check(domain)?;
        Ok(program)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new_six(
        domain: &RegulatoryDomain,
        firmware: super::mld_regulatory::Mcc,
        profile: &super::six_ghz_station::Profile,
        applied_dbm: i8,
        qos: Option<super::qos::Parameters>,
        validity: Validity,
    ) -> Result<Self, &'static str> {
        let channel = profile.channel();
        let program = Self {
            country: domain.country_code,
            validity,
            firmware: Arc::new(IrqSafeSpinLock::new(firmware)),
            primary: channel.number,
            width: profile.span.width,
            center: profile.span.center,
            applied_dbm: Arc::new(AtomicI8::new(applied_dbm)),
            qos,
            he: true,
            eht: false,
            band: channel.band,
            six: Some((profile.power_type(), profile.nvm_flags)),
            ap: false,
            mvm_ap: None,
        };
        program.check(domain)?;
        Ok(program)
    }
    /// Autonomous AP20 additionally requires actual ACTIVE/non-radar MCC
    /// and host non-DFS permission at every copied/current publication.
    pub fn with_ap(mut self) -> Result<Self, &'static str> {
        if self.width != 0 || self.six.is_some() {
            return Err("Intel AP policy lacks native AP20 span");
        }
        self.ap = true;
        Ok(self)
    }
    pub fn new_mvm_ap(
        domain: &RegulatoryDomain,
        firmware: super::mld_regulatory::Mcc,
        primary: u8,
        power: Arc<super::mvm_boot::ApPower>,
        ibss: bool,
        validity: Validity,
    ) -> Result<Self, &'static str> {
        let program = Self {
            country: domain.country_code,
            validity,
            firmware: Arc::new(IrqSafeSpinLock::new(firmware)),
            primary,
            width: 0,
            center: primary,
            applied_dbm: Arc::new(AtomicI8::new(power.radiated_dbm()?)),
            qos: None,
            he: false,
            eht: false,
            band: super::native_band::Channel::legacy(primary)
                .ok_or("MVM AP band/channel absent")?
                .band,
            six: None,
            ap: true,
            mvm_ap: Some((power, ibss)),
        };
        program.check(domain)?;
        Ok(program)
    }
    pub fn emission_ready(&self) -> Result<(), &'static str> {
        self.mvm_ap
            .as_ref()
            .map_or(Ok(()), |(power, _)| power.ready())
    }
    pub fn with_he(mut self, he: bool) -> Result<Self, &'static str> {
        if he && !self.firmware.lock().he_allowed {
            return Err("Intel native MCC prohibits HE operation");
        }
        self.he = he;
        Ok(self)
    }
    pub fn with_eht(mut self, eht: bool) -> Result<Self, &'static str> {
        if eht && (!self.he || !self.firmware.lock().eht_allowed) {
            return Err("Intel native MCC prohibits EHT operation");
        }
        self.eht = eht;
        Ok(self)
    }
    pub fn power(&self) -> i8 {
        self.applied_dbm.load(Ordering::Acquire)
    }
    pub fn ceiling(&self, domain: &RegulatoryDomain) -> Result<i8, &'static str> {
        let firmware = self.firmware.lock();
        self.check_firmware(domain, &firmware)?;
        self.allowed_power(domain, &firmware)
            .ok_or("Intel current policy has no station power ceiling")
    }
    fn allowed_power(
        &self,
        domain: &RegulatoryDomain,
        firmware: &super::mld_regulatory::Mcc,
    ) -> Option<i8> {
        if self.ap {
            if let Some((_, ibss)) = &self.mvm_ap {
                let flags = *firmware
                    .channels
                    .get(super::station_api::channel_index(self.primary)?)?;
                let required = 1 | 8 | 256 | if *ibss { 2 } else { 0 };
                if flags & required != required || flags & 16 != 0 {
                    return None;
                }
                return super::connection::host_channel_power(domain, self.primary, true);
            }
            return super::connection::channel_power(
                domain,
                self.primary,
                &firmware.channels,
                true,
            );
        }
        if let Some((power_type, nvm_flags)) = self.six {
            return super::six_ghz_span::Span::new(self.primary, self.width, self.center)?
                .rule(domain, nvm_flags, Some(firmware))
                .filter(|rule| rule.allows_6ghz_client(power_type))
                .map(|rule| rule.max_power_dbm);
        }
        super::connection::channel_power_width(
            domain,
            self.primary,
            self.width,
            self.center,
            &firmware.channels,
        )
    }
    /// A planned increase is part of every copied proof before publication.
    /// Decreases become visible only after their native receipt completes.
    pub fn reserve_power(&self, power: i8) {
        self.applied_dbm.fetch_max(power, Ordering::AcqRel);
    }
    pub fn commit_power(&self, power: i8) {
        self.applied_dbm.store(power, Ordering::Release);
    }
    /// Only the native owner calls this with its actual correlated MCC
    /// response. Program geometry/features/applied power remain fixed; all
    /// copied proofs see current facts, and forbidden home state is sticky.
    pub fn refresh_mcc(
        &self,
        domain: &RegulatoryDomain,
        current: super::mld_regulatory::Mcc,
    ) -> Result<(), &'static str> {
        let mut firmware = self.firmware.lock();
        *firmware = current;
        let result = self.check_firmware(domain, &firmware);
        if result.is_err() {
            self.validity.invalidate();
        }
        result
    }
    fn check(&self, domain: &RegulatoryDomain) -> Result<(), &'static str> {
        let firmware = self.firmware.lock();
        self.check_firmware(domain, &firmware)
    }
    fn check_firmware(
        &self,
        domain: &RegulatoryDomain,
        firmware: &super::mld_regulatory::Mcc,
    ) -> Result<(), &'static str> {
        self.validity.check()?;
        if let Some((power, _)) = &self.mvm_ap {
            power.check(domain)?;
        }
        if domain.country_code != self.country
            || !firmware.widths.permits(self.width)
            || self.he && !firmware.he_allowed
            || self.eht && !firmware.eht_allowed
            || self.country != *b"00" && !self.country.iter().all(u8::is_ascii_uppercase)
            || self
                .allowed_power(domain, firmware)
                .is_none_or(|ceiling| ceiling < self.power())
            || firmware.country != *b"00" && !firmware.country.iter().all(u8::is_ascii_uppercase)
            || firmware.limit_qos_band(
                domain,
                self.band,
                self.primary,
                self.width,
                self.center,
                self.qos,
            ) != self.qos
        {
            return Err("Intel current regulatory policy forbids the programmed station span");
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct Fence {
    source: Source,
    program: Program,
}
impl Fence {
    pub fn check(&self) -> Result<(), &'static str> {
        let domain = self.source.snapshot()?;
        self.program.check(domain.as_ref())
    }
    pub fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        self.check()?;
        operation()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_wireless::reg::{db::Database, RegFlags, RegRule};
    fn domain() -> RegulatoryDomain {
        RegulatoryDomain {
            country_code: *b"US",
            rules: alloc::vec![RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5250,
                max_bandwidth_mhz: 80,
                max_power_dbm: 17,
                flags: RegFlags::empty()
            }],
        }
    }
    fn smoke_iwl_mld_current_policy_span_country_ceiling_and_replacement_fences() -> TestResult {
        (|| {
            let db = Arc::new(Database::new());
            let original = domain();
            db.install(original.clone());
            let source = Source::database(db.clone());
            let mut permissions = alloc::vec![0;51];
            for channel in [36, 40, 44, 48] {
                permissions[super::super::station_api::channel_index(channel).unwrap()] = 0x70d;
            }
            let program = Program::new(
                &original,
                super::super::mld_regulatory::Mcc {
                    channels: permissions.into(),
                    country: *b"US",
                    etsi_5ghz: false,
                    he_allowed: false,
                    eht_allowed: false,
                    widths: super::super::gen3_wire::Widths {
                        forty: true,
                        eighty: true,
                        one_sixty: true,
                        three_twenty: false,
                    },
                },
                36,
                2,
                42,
                17,
                None,
                Validity::new(),
            )?;
            let fence = source.bind(program)?;
            let transaction = source.transaction(&original)?;
            db.install(original.clone());
            if transaction.check().is_ok() || fence.check().is_err() {
                return Err(
                    "MLD transaction accepted replaced policy or safe retained span was lost",
                );
            }
            let mut change = original.clone();
            change.rules[0].max_power_dbm = 16;
            db.install(change);
            if fence.invoke(|| Ok(())).is_ok() {
                return Err("MLD old programmed power survived policy tightening");
            }
            let mut change = original.clone();
            change.country_code = *b"CA";
            db.install(change);
            if fence.check().is_ok() {
                return Err("MLD cached MCC map crossed a host country change");
            }
            let mut change = original.clone();
            change.rules[0].max_bandwidth_mhz = 40;
            db.install(change);
            if fence.check().is_ok() {
                return Err("MLD full-span width revocation ignored");
            }
            let mut change = original.clone();
            change.rules.push(RegRule {
                freq_start_mhz: 5201,
                freq_end_mhz: 5203,
                max_bandwidth_mhz: 80,
                max_power_dbm: 17,
                flags: RegFlags::NO_IR,
            });
            db.install(change);
            if fence.check().is_ok() {
                return Err("MLD overlapping NO_IR failed to close span");
            }
            db.clear();
            if source.snapshot().is_ok() || fence.check().is_ok() {
                return Err("MLD clear retained stale policy authority");
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/policy",
        smoke_iwl_mld_current_policy_span_country_ceiling_and_replacement_fences
    );
    fn smoke_iwl_mld_current_mcc_cell_keeps_program_bounds_and_retires_stickily() -> TestResult {
        (|| {
            let db = Arc::new(Database::new());
            let original = domain();
            db.install(original.clone());
            let source = Source::database(db);
            let mut permissions = alloc::vec![0; 51];
            for channel in [36, 40, 44, 48] {
                permissions[super::super::station_api::channel_index(channel).unwrap()] = 0x70d;
            }
            let initial = super::super::mld_regulatory::Mcc {
                channels: permissions.into(),
                country: *b"US",
                etsi_5ghz: false,
                he_allowed: true,
                eht_allowed: false,
                widths: super::super::gen3_wire::Widths {
                    forty: true,
                    eighty: true,
                    one_sixty: false,
                    three_twenty: false,
                },
            };
            for he_prohibition in [false, true] {
                let program = Program::new(
                    &original,
                    initial.clone(),
                    36,
                    2,
                    42,
                    17,
                    None,
                    Validity::new(),
                )?
                .with_he(true)?;
                let held = source.bind(program.clone())?;
                let mut looser = initial.clone();
                looser.widths.one_sixty = true;
                program.refresh_mcc(&original, looser.clone())?;
                held.invoke(|| Ok(()))?;
                if program.width != 2 || program.center != 42 || program.power() != 17 {
                    return Err("MLD refreshed MCC enlarged an already issued station program");
                }
                let mut forbidden = initial.clone();
                if he_prohibition {
                    forbidden.he_allowed = false;
                } else {
                    forbidden.widths.eighty = false;
                }
                if program.refresh_mcc(&original, forbidden).is_ok()
                    || held.invoke(|| Ok(())).is_ok()
                {
                    return Err("MLD held home proof ignored actual tighter MCC facts");
                }
                if program.refresh_mcc(&original, looser).is_ok() || held.check().is_ok() {
                    return Err("MLD later looser MCC resurrected a retired home proof");
                }
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/policy",
        smoke_iwl_mld_current_mcc_cell_keeps_program_bounds_and_retires_stickily
    );
}
