//! Station-client passive-channel witness (cfg80211 `beacon_found`).
//!
//! Linux 7.3-rc4 marks a 20 MHz channel `IEEE80211_CHAN_RADAR` when any
//! regulatory rule overlapping it carries `NL80211_RRF_DFS` (reg.c
//! `handle_channel_single_rule`: `reg_rule->flags & NL80211_RRF_DFS`), and
//! `IEEE80211_CHAN_NO_IR` for `NL80211_RRF_NO_IR`. mac80211 never sends a
//! probe request on either (scan.c `ieee80211_scan_state_decision`,
//! `ieee80211_prep_hw_scan`: `chan->flags & (NO_IR | RADAR)` selects the
//! passive dwell), and a station joins only a BSS it actually heard
//! (scan.c `cfg80211_bss_update` keeps the received Beacon). reg.c
//! `regulatory_hint_found_beacon` sets `beacon_found` only on non-RADAR
//! channels; the witness here is the stricter NARF client rule: a station
//! performs no radar detection, so on a RADAR or NO_IR channel it only
//! follows an AP whose Beacon it heard in the latest scan of that channel.
//!
//! `BeaconWitness` is the driver-neutral record of that fact: per 20 MHz
//! center, whether a Beacon was heard in the *latest* scan generation that
//! covered it. A newer scan covering the center retracts the old witness
//! until it is re-heard; a policy change discards every witness. The
//! witness never grants probe, AP, IBSS or off-channel TX.
use super::{RegFlags, RegulatoryDomain};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Union of the flags of every rule overlapping the 20 MHz channel centred
/// at `center` (`center - 10 .. center + 10`, open interval as cfg80211
/// `reg_does_bw_fit`/`freq_in_rule_band` treat a shared edge), or `None`
/// when no rule overlaps it.
pub fn span_flags(domain: &RegulatoryDomain, center: u16) -> Option<RegFlags> {
    let low = u32::from(center).saturating_sub(10);
    let high = u32::from(center) + 10;
    domain
        .rules
        .iter()
        .filter(|rule| rule.freq_start_mhz < high && low < rule.freq_end_mhz)
        .map(|rule| rule.flags)
        .reduce(|a, b| a | b)
}

/// cfg80211 `IEEE80211_CHAN_RADAR` for the 20 MHz channel at `center`.
pub fn is_radar(domain: &RegulatoryDomain, center: u16) -> bool {
    span_flags(domain, center).is_some_and(|f| f.contains(RegFlags::DFS))
}

/// The channel is passive-only for a station: RADAR or NO_IR. Such a
/// channel is scanned without probe requests and joined only under a
/// `BeaconWitness`.
pub fn passive_only(domain: &RegulatoryDomain, center: u16) -> bool {
    span_flags(domain, center).is_some_and(|f| f.intersects(RegFlags::DFS | RegFlags::NO_IR))
}

/// mac80211 active-scan decision: a probe request may be sent at `center`
/// only when a rule covers it and it is neither RADAR nor NO_IR.
pub fn may_probe(domain: &RegulatoryDomain, center: u16) -> bool {
    span_flags(domain, center).is_some_and(|f| !f.intersects(RegFlags::DFS | RegFlags::NO_IR))
}

/// Token of one scan generation; only Beacons received under the latest
/// generation covering a center are witnesses (`BeaconWitness::beacon_found`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanGeneration(u64);

#[derive(Clone, Copy, Debug)]
struct Entry {
    center: u16,
    generation: u64,
    heard: bool,
}

/// Per-20 MHz `beacon_found` witnesses, scoped to one installed policy
/// snapshot and to the latest covering scan generation.
#[derive(Default)]
pub struct BeaconWitness {
    policy: Option<Arc<RegulatoryDomain>>,
    generation: u64,
    entries: Vec<Entry>,
}

impl core::fmt::Debug for BeaconWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BeaconWitness")
            .field("bound", &self.policy.is_some())
            .field("generation", &self.generation)
            .field("entries", &self.entries)
            .finish()
    }
}

impl BeaconWitness {
    pub const fn new() -> Self {
        Self {
            policy: None,
            generation: 0,
            entries: Vec::new(),
        }
    }

    /// Discard every witness (radio reset, factory/policy change, `retire`).
    pub fn clear(&mut self) {
        self.policy = None;
        self.entries.clear();
    }

    /// Open a new scan generation under `policy` covering `centers`. A
    /// different policy snapshot (by identity) discards all witnesses; each
    /// covered center loses its earlier witness until re-heard in this scan.
    /// Duplicate centers are harmless.
    pub fn begin_scan(
        &mut self,
        policy: &Arc<RegulatoryDomain>,
        centers: &[u16],
    ) -> ScanGeneration {
        if !self.policy.as_ref().is_some_and(|p| Arc::ptr_eq(p, policy)) {
            self.entries.clear();
            self.policy = Some(policy.clone());
        }
        // A wrapped generation could alias a stale token: start afresh.
        self.generation = match self.generation.checked_add(1) {
            Some(next) => next,
            None => {
                self.entries.clear();
                1
            }
        };
        for &center in centers {
            let entry = Entry {
                center,
                generation: self.generation,
                heard: false,
            };
            match self.entries.iter_mut().find(|e| e.center == center) {
                Some(slot) => *slot = entry,
                None => self.entries.push(entry),
            }
        }
        ScanGeneration(self.generation)
    }

    /// Record a Beacon received while dwelling on `center` during `scan`.
    /// The caller has already validated the frame (Beacon subtype, nonzero
    /// interval, DS/HT channel equals the dwell) and the dwell itself.
    /// Ignored, returning false, unless `scan` is the latest generation
    /// that covered `center`.
    pub fn beacon_found(&mut self, scan: ScanGeneration, center: u16) -> bool {
        match self
            .entries
            .iter_mut()
            .find(|e| e.center == center && e.generation == scan.0)
        {
            Some(entry) => {
                entry.heard = true;
                true
            }
            None => false,
        }
    }

    /// Whether `center` was heard in its latest covering scan under exactly
    /// the `policy` snapshot the witness was taken under.
    pub fn heard(&self, policy: &Arc<RegulatoryDomain>, center: u16) -> bool {
        self.policy.as_ref().is_some_and(|p| Arc::ptr_eq(p, policy))
            && self.entries.iter().any(|e| e.center == center && e.heard)
    }

    /// May a station associate (or follow a CSA) onto the channel whose
    /// 20 MHz constituents are `centers`? Every constituent must be covered
    /// by a rule; each passive-only (RADAR / NO_IR) constituent additionally
    /// needs a current witness. Bandwidth, power, indoor and driver
    /// inventory checks remain the caller's.
    pub fn may_associate(&self, policy: &Arc<RegulatoryDomain>, centers: &[u16]) -> bool {
        !centers.is_empty()
            && centers
                .iter()
                .all(|&center| match span_flags(policy, center) {
                    None => false,
                    Some(flags) => {
                        !flags.intersects(RegFlags::DFS | RegFlags::NO_IR)
                            || self.heard(policy, center)
                    }
                })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::reg::RegRule;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn rule(start: u32, end: u32, flags: RegFlags) -> RegRule {
        RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: 80,
            max_power_dbm: 23,
            flags,
        }
    }

    fn us() -> Arc<RegulatoryDomain> {
        Arc::new(RegulatoryDomain {
            country_code: *b"US",
            rules: alloc::vec![
                rule(5170, 5250, RegFlags::AUTO_BW),
                rule(5250, 5330, RegFlags::DFS | RegFlags::AUTO_BW),
                rule(5490, 5730, RegFlags::DFS | RegFlags::NO_IR),
                rule(5735, 5835, RegFlags::NO_IR),
            ],
        })
    }

    /// RADAR / NO_IR classification follows reg.c `handle_channel`: a
    /// channel sharing only an edge with a DFS rule is not radar.
    fn smoke_reg_witness_classifies_passive_channels() -> TestResult {
        let d = us();
        if is_radar(&d, 5240) || !may_probe(&d, 5240) || passive_only(&d, 5240) {
            return TestResult::Fail("ch48 shares only an edge with the DFS rule");
        }
        if !is_radar(&d, 5260) || may_probe(&d, 5260) || !passive_only(&d, 5260) {
            return TestResult::Fail("ch52 must be radar and passive");
        }
        if is_radar(&d, 5745) || may_probe(&d, 5745) || !passive_only(&d, 5745) {
            return TestResult::Fail("NO_IR ch149 must be passive without radar");
        }
        if span_flags(&d, 5400).is_some() || may_probe(&d, 5400) {
            return TestResult::Fail("uncovered channel admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/reg/witness",
        smoke_reg_witness_classifies_passive_channels
    );

    /// cfg80211 `beacon_found`: association on a radar span needs every
    /// radar constituent heard in its latest covering scan; a newer scan
    /// retracts, a stale generation and a new policy never witness.
    fn smoke_reg_witness_scan_generation_retracts_and_scopes() -> TestResult {
        let d = us();
        let mut w = BeaconWitness::new();
        if !w.may_associate(&d, &[5180]) || w.may_associate(&d, &[5260]) {
            return TestResult::Fail("non-DFS must not need, radar must need, a witness");
        }
        let first = w.begin_scan(&d, &[5260, 5280]);
        if !w.beacon_found(first, 5260) || w.beacon_found(first, 5300) {
            return TestResult::Fail("witness outside the scan's coverage recorded");
        }
        if !w.may_associate(&d, &[5260]) || w.may_associate(&d, &[5260, 5280]) {
            return TestResult::Fail("partial witness must not admit 40 MHz");
        }
        // A newer scan covering 5260 retracts it; the old token is stale.
        let second = w.begin_scan(&d, &[5260]);
        if w.may_associate(&d, &[5260]) || w.beacon_found(first, 5260) {
            return TestResult::Fail("newer covering scan did not retract");
        }
        let _ = w.beacon_found(second, 5260);
        if !w.may_associate(&d, &[5260]) {
            return TestResult::Fail("re-heard witness not admitted");
        }
        // A scan not covering 5260 keeps its witness.
        let _ = w.begin_scan(&d, &[5180]);
        if !w.may_associate(&d, &[5180, 5260]) {
            return TestResult::Fail("non-covering scan retracted a witness");
        }
        // Same rules, new policy snapshot: identity, not equality, scopes.
        let replaced = us();
        if w.may_associate(&replaced, &[5260]) {
            return TestResult::Fail("witness survived a policy change");
        }
        let _ = w.begin_scan(&replaced, &[5180]);
        if w.heard(&d, 5260) || w.heard(&replaced, 5260) {
            return TestResult::Fail("new policy scan kept the old witnesses");
        }
        w.clear();
        if w.may_associate(&replaced, &[5745]) {
            return TestResult::Fail("cleared NO_IR witness admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/reg/witness",
        smoke_reg_witness_scan_generation_retracts_and_scopes
    );
}
