use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[path = "reg/policy.rs"]
pub mod policy;

#[derive(Clone)]
pub struct RegulatoryDomain {
    pub country_code: [u8; 2],
    pub rules: Vec<RegRule>,
}

impl RegulatoryDomain {
    /// cfg80211 `freq_reg_info`: the rule covering `mhz`, if any.
    pub fn rule_for(&self, mhz: u32) -> Option<&RegRule> {
        self.rules.iter().find(|rule| rule.covers_mhz(mhz))
    }
    /// The WMM floor (`reg_query_regdb_wmm`) for a channel at `mhz`.
    pub fn wmm_rule_for(&self, mhz: u32) -> Option<WmmRule> {
        self.rule_for(mhz).and_then(RegRule::wmm_rule)
    }
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
        /// cfg80211 `NL80211_RRF_NO_6GHZ_VLP_CLIENT`: a client may not
        /// connect to a 6 GHz Very Low Power AP under this rule.
        const NO_6GHZ_VLP_CLIENT = 1 << 4;
        /// cfg80211 `NL80211_RRF_NO_6GHZ_AFC_CLIENT`: a client may not
        /// connect to a 6 GHz Standard Power (AFC) AP under this rule.
        const NO_6GHZ_AFC_CLIENT = 1 << 5;
        /// The rule carries wireless-regdb's `wmmrule=ETSI` (ETSI EN 301 893
        /// channel-access limits): `RegRule::wmm_rule()`.
        const WMM_ETSI = 1 << 6;
    }
}

/// cfg80211 `struct ieee80211_wmm_ac`: the regulatory floor for one access
/// category. `cot_us` is the Channel Occupancy Time limit in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmmAcRule {
    pub cw_min: u16,
    pub cw_max: u16,
    pub cot_us: u16,
    pub aifsn: u8,
}

/// cfg80211 `struct ieee80211_wmm_rule`, indexed by access category in
/// mac80211 order: 0 = VO, 1 = VI, 2 = BE, 3 = BK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmmRule {
    pub client: [WmmAcRule; 4],
    pub ap: [WmmAcRule; 4],
}

const fn wmm_ac(cw_min: u16, cw_max: u16, aifsn: u8, cot_ms: u16) -> WmmAcRule {
    WmmAcRule {
        cw_min,
        cw_max,
        cot_us: cot_ms * 1000,
        aifsn,
    }
}

impl WmmRule {
    /// wireless-regdb `db.txt` `wmmrule ETSI` (ETSI EN 301 893), the only
    /// WMM rule the regulatory database defines.
    pub const ETSI: Self = Self {
        client: [
            wmm_ac(3, 7, 2, 2),
            wmm_ac(7, 15, 2, 4),
            wmm_ac(15, 1023, 3, 6),
            wmm_ac(15, 1023, 7, 6),
        ],
        ap: [
            wmm_ac(3, 7, 1, 2),
            wmm_ac(7, 15, 1, 4),
            wmm_ac(15, 63, 3, 6),
            wmm_ac(15, 1023, 7, 6),
        ],
    };

    /// mac80211 `ieee80211_regulatory_limit_wmm_params` for access category
    /// `ac` (0 = VO .. 3 = BK): raise CWmin, CWmax and AIFSN to the rule's
    /// floor and cap the TXOP limit (32 us units) at its COT. `ap` selects
    /// the AP table. An out-of-range category leaves `params` unchanged.
    pub fn limit(&self, ac: usize, ap: bool, params: crate::wmm::Ac) -> crate::wmm::Ac {
        let table = if ap { &self.ap } else { &self.client };
        let Some(rule) = table.get(ac) else {
            return params;
        };
        // CW = 2^ECW - 1.
        let ecw = |cw: u16| (u16::BITS - cw.leading_zeros()) as u8;
        let ecw_min = params.ecw_min.max(ecw(rule.cw_min));
        crate::wmm::Ac {
            aifsn: params.aifsn.max(rule.aifsn),
            ecw_min,
            ecw_max: params.ecw_max.max(ecw(rule.cw_max)).max(ecw_min),
            txop: params.txop.min(rule.cot_us / 32),
            admission_control: params.admission_control,
        }
    }

    /// `limit` over a parsed `wmm::Parameters` (canonical ACI order BE, BK,
    /// VI, VO), the form drivers program from.
    pub fn limit_parameters(
        &self,
        ap: bool,
        params: crate::wmm::Parameters,
    ) -> crate::wmm::Parameters {
        let mut out = params;
        // ACI -> mac80211 AC index (VO = 0, VI = 1, BE = 2, BK = 3).
        for (aci, ac) in [2usize, 3, 1, 0].into_iter().enumerate() {
            out.ac[aci] = self.limit(ac, ap, params.ac[aci]);
        }
        out
    }
}

/// 6 GHz AP regulatory power type (`enum ieee80211_ap_reg_power`): Low
/// Power Indoor, Standard Power (AFC-controlled) or Very Low Power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerType6Ghz {
    Lpi,
    Sp,
    Vlp,
}

impl RegRule {
    /// True when `mhz` lies inside `[freq_start_mhz, freq_end_mhz]`.
    pub fn covers_mhz(&self, mhz: u32) -> bool {
        (self.freq_start_mhz..=self.freq_end_mhz).contains(&mhz)
    }
    /// `NO_6GHZ_AFC_CLIENT`: also selects LPI for an Indoor SP AP
    /// (`cfg80211_6ghz_power_type`).
    pub fn no_6ghz_afc_client(&self) -> bool {
        self.flags.contains(RegFlags::NO_6GHZ_AFC_CLIENT)
    }
    /// cfg80211 `cfg80211_6ghz_power_type_valid`: whether a station may
    /// associate with a 6 GHz AP of `power` under this rule. LPI is always
    /// permitted by the rule itself (INDOOR_ONLY still applies).
    /// cfg80211 `ieee80211_reg_rule.wmm_rule` when `has_wmm`: the WMM
    /// channel-access floor a driver applies to every EDCA parameter set it
    /// programs on a channel this rule covers (`WmmRule::limit`).
    pub fn wmm_rule(&self) -> Option<WmmRule> {
        self.flags.contains(RegFlags::WMM_ETSI).then_some(WmmRule::ETSI)
    }
    pub fn allows_6ghz_client(&self, power: PowerType6Ghz) -> bool {
        match power {
            PowerType6Ghz::Lpi => true,
            PowerType6Ghz::Sp => !self.flags.contains(RegFlags::NO_6GHZ_AFC_CLIENT),
            PowerType6Ghz::Vlp => !self.flags.contains(RegFlags::NO_6GHZ_VLP_CLIENT),
        }
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "reg/wmm_rule_tests.rs"]
mod wmm_rule_tests;
