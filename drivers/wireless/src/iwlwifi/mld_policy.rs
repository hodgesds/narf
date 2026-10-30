// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Current host policy for native MLD station publication. A cached MCC
//! map is bound to its host country and already-programmed span/ceiling;
//! it is never a replacement for SAR or measured platform qualification.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI8, Ordering};
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
}
impl Transaction {
    pub fn check(&self) -> Result<(), &'static str> {
        self.validity.check()?;
        if !Arc::ptr_eq(&self.initial, &self.source.snapshot()?) {
            return Err("Intel regulatory policy changed during native configuration");
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
#[derive(Clone)]
pub(super) enum Authority {
    Transaction(Transaction),
    Station(Fence),
}
impl Authority {
    pub fn domain(&self) -> Result<Arc<RegulatoryDomain>, &'static str> {
        self.check()?;
        match self {
            Self::Transaction(t) => Ok(t.initial.clone()),
            Self::Station(f) => f.source.snapshot(),
        }
    }
    pub fn check(&self) -> Result<(), &'static str> {
        match self {
            Self::Transaction(t) => t.check(),
            Self::Station(f) => f.check(),
        }
    }
    pub fn validity(&self) -> Validity {
        match self {
            Self::Transaction(t) => t.validity.clone(),
            Self::Station(f) => f.program.validity.clone(),
        }
    }
    pub fn invalidate(&self) {
        self.validity().invalidate();
    }
}

/// Facts from the actual correlated MCC reply and completed link power
/// programming. Construction is private to the native association owner.
#[derive(Clone)]
pub(super) struct Program {
    country: [u8; 2],
    validity: Validity,
    firmware: super::mld_regulatory::Mcc,
    pub primary: u8,
    width: u8,
    center: u8,
    applied_dbm: Arc<AtomicI8>,
    qos: Option<super::qos::Parameters>,
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
            firmware,
            primary,
            width,
            center,
            applied_dbm: Arc::new(AtomicI8::new(applied_dbm)),
            qos,
        };
        program.check(domain)?;
        Ok(program)
    }
    pub fn power(&self) -> i8 {
        self.applied_dbm.load(Ordering::Acquire)
    }
    pub fn ceiling(&self, domain: &RegulatoryDomain) -> Result<i8, &'static str> {
        self.check(domain)?;
        super::connection::channel_power_width(
            domain,
            self.primary,
            self.width,
            self.center,
            &self.firmware.channels,
        )
        .ok_or("Intel current policy has no station power ceiling")
    }
    /// A planned increase is part of every copied proof before publication.
    /// Decreases become visible only after their native receipt completes.
    pub fn reserve_power(&self, power: i8) {
        self.applied_dbm.fetch_max(power, Ordering::AcqRel);
    }
    pub fn commit_power(&self, power: i8) {
        self.applied_dbm.store(power, Ordering::Release);
    }
    fn check(&self, domain: &RegulatoryDomain) -> Result<(), &'static str> {
        self.validity.check()?;
        if domain.country_code != self.country
            || self.country != *b"00" && !self.country.iter().all(u8::is_ascii_uppercase)
            || super::connection::channel_power_width(
                domain,
                self.primary,
                self.width,
                self.center,
                &self.firmware.channels,
            )
            .is_none_or(|ceiling| ceiling < self.power())
            || self.firmware.country != *b"00"
                && !self.firmware.country.iter().all(u8::is_ascii_uppercase)
            || self
                .firmware
                .limit_qos(domain, self.primary, self.width, self.center, self.qos)
                != self.qos
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
}
