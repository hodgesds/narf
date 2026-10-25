use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[path = "reg/policy.rs"]
pub mod policy;

#[derive(Clone)]
pub struct RegulatoryDomain {
    pub country_code: [u8; 2],
    pub rules: Vec<RegRule>,
}

#[derive(Clone)]
pub struct RegRule {
    pub freq_start_mhz: u32,
    pub freq_end_mhz: u32,
    pub max_bandwidth_mhz: u32,
    pub max_power_dbm: i8,
    pub flags: RegFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RegFlags: u32 {
        const DFS        = 1 << 0;
        const INDOOR_ONLY = 1 << 1;
        const NO_P2P     = 1 << 2;
        /// Receive/passive discovery only until a driver proves a supported
        /// relaxation; no active probes or host-initiated station TX.
        const NO_IR      = 1 << 3;
    }
}

/// Decode a deployment-selected regulatory policy. Callers must authenticate
/// the enclosing blob before installing it; parsing does not establish trust.
/// NRGD v1: magic[4], version:u16, country[2], count:u16, reserved:u16,
/// followed by 16-byte rules (start/end/bandwidth:u32, power:i8,
/// flags:u8, reserved:u16), all integers little-endian.
pub fn parse_policy(bytes: &[u8]) -> Result<RegulatoryDomain, &'static str> {
    if bytes.len() < 12
        || &bytes[..4] != b"NRGD"
        || bytes[4..6] != [1, 0]
        || bytes[10..12] != [0; 2]
        || !bytes[6..8].iter().all(u8::is_ascii_uppercase)
    {
        return Err("invalid regulatory policy header");
    }
    let count = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
    if count == 0 || count > 64 || bytes.len() != 12 + count * 16 {
        return Err("invalid regulatory rule count");
    }
    let mut rules = Vec::new();
    for raw in bytes[12..].chunks_exact(16) {
        let start = u32::from_le_bytes(raw[..4].try_into().unwrap());
        let end = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let bandwidth = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = RegFlags::from_bits(u32::from(raw[13])).ok_or("unknown regulatory flags")?;
        if start < 2000
            || end > 71000
            || end <= start
            || bandwidth == 0
            || bandwidth > end - start
            || raw[14..] != [0; 2]
        {
            return Err("invalid regulatory rule");
        }
        rules.push(RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: raw[12] as i8,
            flags,
        });
    }
    Ok(RegulatoryDomain {
        country_code: bytes[6..8].try_into().unwrap(),
        rules,
    })
}

pub mod db {
    use super::*;
    use alloc::sync::Arc;

    /// Immutable snapshots permit cheap policy-change observation without
    /// cloning the rule vector on each packet/progress poll. Installing a
    /// domain still requires trusted caller authority, as with set_domain.
    pub struct Database {
        pub(super) state: IrqSafeSpinLock<State>,
    }
    pub(super) struct State {
        pub(super) domain: Option<Arc<RegulatoryDomain>>,
        pub(super) revision: u64,
    }
    impl Default for Database {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Database {
        pub const fn new() -> Self {
            Self {
                state: IrqSafeSpinLock::new(State {
                    domain: None,
                    revision: 0,
                }),
            }
        }
        pub fn install(&self, domain: RegulatoryDomain) {
            let domain = Arc::new(domain);
            let retired = {
                let mut state = self.state.lock();
                state.revision = state.revision.saturating_add(1);
                state.domain.replace(domain)
            };
            // Free the retired rule storage outside the IRQ-safe DB lock.
            drop(retired);
        }
        pub fn clear(&self) {
            let retired = {
                let mut state = self.state.lock();
                state.revision = state.revision.saturating_add(1);
                state.domain.take()
            };
            drop(retired);
        }
        pub fn snapshot(&self) -> Option<Arc<RegulatoryDomain>> {
            self.state.lock().domain.clone()
        }
    }
    static ACTIVE_DOMAIN: Database = Database::new();

    pub fn set_domain(domain: RegulatoryDomain) {
        ACTIVE_DOMAIN.install(domain);
    }

    /// Retire the shared installation. Live consumers must close admission
    /// on absence; a previously issued immutable snapshot is not current proof.
    pub fn clear_domain() {
        ACTIVE_DOMAIN.clear();
    }

    pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
        ACTIVE_DOMAIN.snapshot()
    }

    pub fn get_domain() -> Option<RegulatoryDomain> {
        snapshot().map(|domain| domain.as_ref().clone())
    }

    /// Use the caller-installed domain, or bootstrap the staged signed policy
    /// when no domain exists. No device or other driver must have run first.
    pub fn ensure_domain() -> Result<RegulatoryDomain, policy::Error> {
        ensure_snapshot().map(|domain| domain.as_ref().clone())
    }

    pub fn ensure_snapshot() -> Result<Arc<RegulatoryDomain>, policy::Error> {
        ensure_with(&ACTIVE_DOMAIN, policy::load)
    }

    pub(super) fn ensure_with(
        database: &Database,
        load: impl FnOnce() -> Result<RegulatoryDomain, policy::Error>,
    ) -> Result<Arc<RegulatoryDomain>, policy::Error> {
        let revision = {
            let state = database.state.lock();
            if let Some(domain) = &state.domain {
                return Ok(domain.clone());
            }
            // Never let revision exhaustion create a bootstrap ABA.
            if state.revision == u64::MAX {
                return Err(policy::Error::Authority);
            }
            state.revision
        };
        // Firmware lookup/invocation and decoding must happen without the
        // database's IRQ-disabling lock. Failed loads publish no partial state.
        let loaded = Arc::new(load()?);
        let mut guard = database.state.lock();
        // A concurrently installed caller policy wins over this bootstrap.
        let selected = if let Some(domain) = &guard.domain {
            Ok(domain.clone())
        } else if guard.revision != revision {
            // An explicit clear during lookup wins over stale loaded bytes.
            Err(policy::Error::Authority)
        } else {
            guard.revision += 1;
            guard.domain = Some(loaded.clone());
            Ok(loaded.clone())
        };
        drop(guard);
        selected
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_regulatory_policy_boundaries() -> TestResult {
        let mut bytes = alloc::vec![0;28];
        bytes[..4].copy_from_slice(b"NRGD");
        bytes[4] = 1;
        bytes[6..8].copy_from_slice(b"US");
        bytes[8] = 1;
        bytes[12..16].copy_from_slice(&2402u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2472u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&20u32.to_le_bytes());
        bytes[24] = 17;
        let domain = parse_policy(&bytes).unwrap();
        if domain.country_code != *b"US" || domain.rules[0].max_power_dbm != 17 {
            return TestResult::Fail("regulatory policy decode");
        }
        bytes[25] = 1 << 3;
        if parse_policy(&bytes)
            .ok()
            .is_none_or(|domain| domain.rules[0].flags != RegFlags::NO_IR)
        {
            return TestResult::Fail("NO_IR policy bit was lost or rejected");
        }
        bytes[25] = 0x80;
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("unknown rule flags accepted");
        }
        bytes[25] = 0;
        bytes.pop();
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("truncated rule accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/regulatory", smoke_regulatory_policy_boundaries);
}
