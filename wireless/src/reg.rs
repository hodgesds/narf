use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[path = "reg/linux.rs"]
pub(crate) mod linux;
#[path = "reg/policy.rs"]
pub mod policy;
#[path = "reg/witness.rs"]
pub mod witness;

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
    /// cfg80211 `reg_get_max_bandwidth` as `handle_channel` applies it
    /// (net/wireless/reg.c): the usable bandwidth of `rules[index]` in MHz.
    /// Under AUTO_BW it is the span of the run of rules adjacent to it in
    /// policy order (`reg_get_max_bandwidth_from_range`: a neighbour joins
    /// while its range touches or overlaps the run), otherwise the rule's
    /// own maximum. NO_160MHZ caps either at 80 MHz. Zero for a bad index.
    pub fn max_bandwidth(&self, index: usize) -> u32 {
        let Some(rule) = self.rules.get(index) else {
            return 0;
        };
        let mut bandwidth = if rule.flags.contains(RegFlags::AUTO_BW) {
            let mut start = rule.freq_start_mhz;
            for r in self.rules[..index].iter().rev() {
                if r.freq_end_mhz < start {
                    break;
                }
                start = r.freq_start_mhz;
            }
            let mut end = rule.freq_end_mhz;
            for r in &self.rules[index + 1..] {
                if r.freq_start_mhz > end {
                    break;
                }
                end = r.freq_end_mhz;
            }
            end.saturating_sub(start)
        } else {
            rule.max_bandwidth_mhz
        };
        if rule.flags.contains(RegFlags::NO_160MHZ) {
            bandwidth = bandwidth.min(80);
        }
        bandwidth
    }
    /// cfg80211 `cfg80211_chandef_usable` bandwidth test for a block of
    /// `width` MHz occupying `low..high`: every rule overlapping the block
    /// must allow `width` (`max_bandwidth`), so a 160 MHz channel crosses a
    /// rule boundary only through AUTO_BW on both sides. Coverage and every
    /// other restriction remain the caller's to check.
    pub fn allows_bandwidth(&self, low: u32, high: u32, width: u32) -> bool {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.freq_start_mhz < high && low < r.freq_end_mhz)
            .all(|(i, _)| self.max_bandwidth(i) >= width)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
        /// The trusted deployment policy asserts that this installation is
        /// indoors. Valid only alongside INDOOR_ONLY; parsing alone does not
        /// authenticate the assertion. Drivers must retain current-policy
        /// checks and every other factory, power and bandwidth restriction.
        const DEPLOYMENT_INDOOR = 1 << 7;
        /// cfg80211 `NL80211_RRF_AUTO_BW` (wireless-regdb `AUTO-BW`,
        /// `FWDB_FLAG_AUTO_BW`): the rule's usable bandwidth is the span of
        /// the run of adjacent rules it belongs to, so a wide channel may
        /// cross a rule boundary (`RegulatoryDomain::max_bandwidth`).
        /// NRGD second flag byte, bit0.
        const AUTO_BW = 1 << 8;
        /// cfg80211 `NL80211_RRF_NO_160MHZ`: no 160 MHz (or 80+80) channel
        /// may occupy this rule, whatever its bandwidth or AUTO_BW run.
        /// NRGD second flag byte, bit1.
        const NO_160MHZ = 1 << 9;
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
        self.flags
            .contains(RegFlags::WMM_ETSI)
            .then_some(WmmRule::ETSI)
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
/// flags:u8, flags2:u8, reserved:u8), all integers little-endian. flags2
/// carries `RegFlags` bits 8.. (AUTO_BW, NO_160MHZ); unknown bits reject.
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
        let flags = RegFlags::from_bits(u32::from(raw[13]) | u32::from(raw[14]) << 8)
            .ok_or("unknown regulatory flags")?;
        if flags.contains(RegFlags::DEPLOYMENT_INDOOR) && !flags.contains(RegFlags::INDOOR_ONLY) {
            return Err("indoor installation fact without indoor-only rule");
        }
        if start < 2000
            || end > 71000
            || end <= start
            || bandwidth == 0
            || bandwidth > end - start
            || raw[15] != 0
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
        source: Source,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Source {
        Caller,
        Deployment,
        Linux(u8),
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
                    source: Source::Caller,
                }),
            }
        }
        pub fn install(&self, domain: RegulatoryDomain) {
            let domain = Arc::new(domain);
            let retired = {
                let mut state = self.state.lock();
                state.revision = state.revision.saturating_add(1);
                state.source = Source::Caller;
                state.domain.replace(domain)
            };
            // Free the retired rule storage outside the IRQ-safe DB lock.
            drop(retired);
        }
        pub fn clear(&self) {
            let retired = {
                let mut state = self.state.lock();
                state.revision = state.revision.saturating_add(1);
                state.source = Source::Caller;
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
        ensure_source_with(&ACTIVE_DOMAIN, policy::load_bootstrap)
    }

    pub(crate) fn ensure_with_info() -> Result<(Arc<RegulatoryDomain>, u8), policy::Error> {
        ensure_snapshot()?;
        let state = ACTIVE_DOMAIN.state.lock();
        let domain = state.domain.clone().ok_or(policy::Error::Authority)?;
        let dfs = match state.source {
            Source::Linux(dfs) => dfs,
            _ => 0,
        };
        Ok((domain, dfs))
    }

    /// Country hints may replace only the Linux database installation. A
    /// signed deployment override or trusted caller policy keeps its bounds.
    pub(crate) fn select_linux_country(alpha2: [u8; 2]) -> Result<(), policy::Error> {
        ensure_snapshot()?;
        select_linux_with(&ACTIVE_DOMAIN, || {
            super::linux::country(narf_firmware::linux_regulatory_database(), alpha2)
                .map_err(policy::Error::Format)
        })
    }

    pub(super) fn select_linux_with(
        database: &Database,
        load: impl FnOnce() -> Result<(RegulatoryDomain, u8), policy::Error>,
    ) -> Result<(), policy::Error> {
        let revision = {
            let state = database.state.lock();
            if !matches!(state.source, Source::Linux(_)) || state.domain.is_none() {
                return Err(policy::Error::Authority);
            }
            state.revision
        };
        let (domain, dfs) = load()?;
        let domain = Arc::new(domain);
        let retired = {
            let mut state = database.state.lock();
            if !matches!(state.source, Source::Linux(_))
                || state.revision != revision
                || state.revision == u64::MAX
                || state.domain.is_none()
            {
                return Err(policy::Error::Authority);
            }
            state.revision += 1;
            state.source = Source::Linux(dfs);
            state.domain.replace(domain)
        };
        drop(retired);
        Ok(())
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn ensure_with(
        database: &Database,
        load: impl FnOnce() -> Result<RegulatoryDomain, policy::Error>,
    ) -> Result<Arc<RegulatoryDomain>, policy::Error> {
        ensure_source_with(database, || {
            load().map(|domain| (domain, Source::Deployment))
        })
    }

    pub(super) fn ensure_source_with(
        database: &Database,
        load: impl FnOnce() -> Result<(RegulatoryDomain, Source), policy::Error>,
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
        let (loaded, source) = load()?;
        let loaded = Arc::new(loaded);
        let mut guard = database.state.lock();
        // A concurrently installed caller policy wins over this bootstrap.
        let selected = if let Some(domain) = &guard.domain {
            Ok(domain.clone())
        } else if guard.revision != revision {
            // An explicit clear during lookup wins over stale loaded bytes.
            Err(policy::Error::Authority)
        } else {
            guard.revision += 1;
            guard.source = source;
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
            return TestResult::Fail("unpaired installation fact accepted");
        }
        bytes[25] = 0;
        bytes.pop();
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("truncated rule accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/regulatory", smoke_regulatory_policy_boundaries);

    fn rule(start: u32, end: u32, bandwidth: u32, flags: RegFlags) -> RegRule {
        RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: 23,
            flags,
        }
    }

    /// wireless-regdb `US`: `(5170 - 5250 @ 80), (23), AUTO-BW` then
    /// `(5250 - 5330 @ 80), (23), DFS, AUTO-BW` must join into 160 MHz.
    fn smoke_regulatory_auto_bw_chain_admits_and_refuses_160() -> TestResult {
        let auto = RegFlags::AUTO_BW;
        let mut domain = RegulatoryDomain {
            country_code: *b"US",
            rules: alloc::vec![
                rule(5170, 5250, 80, auto),
                rule(5250, 5330, 80, auto | RegFlags::DFS),
                rule(5490, 5730, 160, RegFlags::DFS),
                rule(5735, 5835, 80, RegFlags::empty()),
            ],
        };
        if domain.max_bandwidth(0) != 160
            || domain.max_bandwidth(1) != 160
            || !domain.allows_bandwidth(5170, 5330, 160)
        {
            return TestResult::Fail("AUTO_BW run did not join 5170-5330 into 160 MHz");
        }
        // A rule wide enough on its own admits 160 directly.
        if domain.max_bandwidth(2) != 160 || !domain.allows_bandwidth(5490, 5650, 160) {
            return TestResult::Fail("direct 160 MHz rule refused");
        }
        // No AUTO_BW: the rule's own maximum binds, and a gap ends a run.
        if domain.max_bandwidth(3) != 80 || domain.allows_bandwidth(5735, 5835, 160) {
            return TestResult::Fail("plain 80 MHz rule admitted 160");
        }
        // One side without AUTO_BW keeps its own 80 MHz: the crossing fails.
        domain.rules[1].flags = RegFlags::DFS;
        if domain.max_bandwidth(1) != 80 || domain.allows_bandwidth(5170, 5330, 160) {
            return TestResult::Fail("one-sided AUTO_BW crossed a rule boundary");
        }
        domain.rules[1].flags = auto | RegFlags::DFS;
        // NO_160MHZ on either constituent rule caps the run at 80 MHz.
        domain.rules[0].flags = auto | RegFlags::NO_160MHZ;
        if domain.max_bandwidth(0) != 80
            || domain.allows_bandwidth(5170, 5330, 160)
            || !domain.allows_bandwidth(5170, 5250, 80)
        {
            return TestResult::Fail("NO_160MHZ did not cap the AUTO_BW run");
        }
        domain.rules[0].flags = auto;
        // A gap between rules ends the run (reg_get_max_bandwidth_from_range).
        domain.rules[1].freq_start_mhz = 5260;
        if domain.max_bandwidth(0) != 80 || domain.max_bandwidth(1) != 70 {
            return TestResult::Fail("AUTO_BW run crossed a frequency gap");
        }
        if domain.max_bandwidth(9) != 0 {
            return TestResult::Fail("out-of-range rule index had bandwidth");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/regulatory",
        smoke_regulatory_auto_bw_chain_admits_and_refuses_160
    );

    /// NRGD flags2 (rule byte 14) carries AUTO_BW / NO_160MHZ; its unknown
    /// bits and the last reserved byte stay rejected.
    fn smoke_regulatory_policy_second_flag_byte() -> TestResult {
        let mut bytes = alloc::vec![0; 28];
        bytes[..4].copy_from_slice(b"NRGD");
        bytes[4] = 1;
        bytes[6..8].copy_from_slice(b"US");
        bytes[8] = 1;
        bytes[12..16].copy_from_slice(&5170u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&5250u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&80u32.to_le_bytes());
        bytes[24] = 23;
        bytes[25] = 1;
        bytes[26] = 0b11;
        if parse_policy(&bytes).ok().is_none_or(|d| {
            d.rules[0].flags != RegFlags::DFS | RegFlags::AUTO_BW | RegFlags::NO_160MHZ
        }) {
            return TestResult::Fail("flags2 AUTO_BW/NO_160MHZ lost or rejected");
        }
        bytes[26] = 0b100;
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("unknown flags2 bit accepted");
        }
        bytes[26] = 0;
        bytes[27] = 1;
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("reserved rule byte accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/regulatory",
        smoke_regulatory_policy_second_flag_byte
    );
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "reg/wmm_rule_tests.rs"]
mod wmm_rule_tests;
