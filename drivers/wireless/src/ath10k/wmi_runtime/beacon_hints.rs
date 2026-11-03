// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-radio native observations lifting only the factory World NO_IR layer.
//! Linux7.2 ath/regd.c and cfg80211 reg.c; signed host rules stay separate.
//!
//! The same native dwell observation also records cfg80211 `beacon_found`
//! on host-DFS (radar) channels for any factory SKU. That radar witness is
//! handed only to the station client (`Owner::client_receipt`): Linux
//! mac80211 scans RADAR channels passively (scan.c
//! `ieee80211_prep_hw_scan`/`ieee80211_scan_state_decision` with
//! `IEEE80211_CHAN_RADAR`), a STA performs no radar detection, and a client
//! only follows an AP it actually heard there. AP, active-probe and
//! off-channel TX keep using `Owner::receipt`, which never carries radar.
use super::{beacon, wire, Error, Management, ScanEvent};
use crate::ath10k::regulatory::Factory;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::reg::witness::{self, BeaconWitness, ScanGeneration};
use narf_wireless::reg::{db, RegulatoryDomain};

const FREQUENCIES: [u16; 25] = [
    5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825, 5260, 5280, 5300, 5320, 5500, 5520, 5540,
    5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700, 5720,
];
pub(in crate::ath10k) fn bit(frequency: u16) -> Option<u32> {
    FREQUENCIES
        .iter()
        .position(|f| *f == frequency)
        .map(|at| 1 << at)
}
fn same_domain(a: &RegulatoryDomain, b: &RegulatoryDomain) -> bool {
    a.country_code == b.country_code && a.rules == b.rules
}
fn world(factory: Factory) -> bool {
    // ath_is_world_regd strips WORLDWIDE_ROAMING_FLAG. The existing factory
    // table admits WOR0..WORC; WOR6B uses ath_world_regdomain's conservative
    // WOR4 fallback. These SKUs all have NO_IR on these non-DFS5GHz centers.
    // The separate WORLD0x199 constant has no current factory-table entry.
    factory.country == 0
        && (0x60..=0x6c).contains(&factory.pair)
        && factory.eeprom & !0x4000 == factory.pair
}

#[derive(Clone)]
enum Policy {
    Installed,
    #[cfg(any(test, feature = "kernel-test"))]
    Scoped(Arc<db::Database>),
}
impl core::fmt::Debug for Policy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Installed => f.write_str("Installed"),
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Scoped(_) => f.write_str("Scoped"),
        }
    }
}
impl Policy {
    fn snapshot(&self) -> Option<Arc<RegulatoryDomain>> {
        match self {
            Self::Installed => db::snapshot(),
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Scoped(database) => database.snapshot(),
        }
    }
}
#[derive(Debug)]
struct Life(AtomicBool);
struct Window {
    policy: Policy,
    original: Arc<RegulatoryDomain>,
    factory: Factory,
    radio: Weak<Life>,
}
impl core::fmt::Debug for Window {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Window")
            .field("factory", &self.factory)
            .field("country", &self.original.country_code)
            .finish_non_exhaustive()
    }
}
impl Window {
    fn current(&self) -> bool {
        self.radio
            .upgrade()
            .is_some_and(|radio| radio.0.load(Ordering::Acquire))
            && self
                .policy
                .snapshot()
                .is_some_and(|now| Arc::ptr_eq(&now, &self.original))
    }
}
/// Immutable witness captured at admission, never a live/global hint lookup.
/// The original policy Arc and radio life remain bound across firmware waits,
/// copied RX and future Clone operations. New beacons cannot widen this mask.
#[derive(Clone, Debug)]
pub(in crate::ath10k) struct Receipt {
    window: Arc<Window>,
    observed: u32,
    /// Host-DFS channels whose Beacon this window's latest covering scan
    /// heard (cfg80211 `beacon_found`). Zero in every non-client receipt.
    radar: u32,
}
impl PartialEq for Receipt {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.window, &other.window)
            && self.observed == other.observed
            && self.radar == other.radar
    }
}
impl Eq for Receipt {}
impl Receipt {
    pub fn permits(
        &self,
        factory: Factory,
        domain: &RegulatoryDomain,
        frequencies: &[u16],
    ) -> bool {
        world(factory)
            && !frequencies.is_empty()
            && self.window.factory == factory
            && self.window.current()
            && same_domain(&self.window.original, domain)
            && frequencies
                .iter()
                .all(|frequency| bit(*frequency).is_some_and(|b| self.observed & b != 0))
    }
    pub fn restrict(
        self: &Arc<Self>,
        factory: Factory,
        domain: &RegulatoryDomain,
        frequencies: &[u16],
    ) -> Option<Arc<Self>> {
        if !self.permits(factory, domain, frequencies) {
            return None;
        }
        let observed = frequencies
            .iter()
            .try_fold(0, |mask, f| bit(*f).map(|b| mask | b))?;
        Some(self.narrowed(observed, self.radar & observed))
    }
    /// cfg80211 `beacon_found` for every host-DFS 20 MHz constituent: the
    /// client heard an AP Beacon on each in this window's latest scan of it.
    /// Any factory SKU; the World NO_IR layer is still `permits`' business.
    pub fn permits_radar(
        &self,
        factory: Factory,
        domain: &RegulatoryDomain,
        frequencies: &[u16],
    ) -> bool {
        !frequencies.is_empty()
            && self.window.factory == factory
            && self.window.current()
            && same_domain(&self.window.original, domain)
            && frequencies
                .iter()
                .all(|frequency| bit(*frequency).is_some_and(|b| self.radar & b != 0))
    }
    /// Narrow to exactly the radar constituents `frequencies` (non-World
    /// factory: no NO_IR observation is retained alongside).
    pub fn restrict_radar(
        self: &Arc<Self>,
        factory: Factory,
        domain: &RegulatoryDomain,
        frequencies: &[u16],
    ) -> Option<Arc<Self>> {
        if !self.permits_radar(factory, domain, frequencies) {
            return None;
        }
        let radar = frequencies
            .iter()
            .try_fold(0, |mask, f| bit(*f).map(|b| mask | b))?;
        Some(self.narrowed(0, radar))
    }
    /// Radar constituents this receipt retains, as `bit` masks.
    pub fn radar_mask(&self) -> u32 {
        self.radar
    }
    fn narrowed(self: &Arc<Self>, observed: u32, radar: u32) -> Arc<Self> {
        if observed == self.observed && radar == self.radar {
            return self.clone();
        }
        Arc::new(Self {
            window: self.window.clone(),
            observed,
            radar,
        })
    }
    pub fn union(self: &Arc<Self>, other: &Arc<Self>) -> Option<Arc<Self>> {
        if !Arc::ptr_eq(&self.window, &other.window) || !self.window.current() {
            return None;
        }
        Some(self.narrowed(self.observed | other.observed, self.radar | other.radar))
    }
}
#[derive(Debug)]
pub(super) struct Scan {
    window: Arc<Window>,
    sequence: u16,
    allowed: u32,
    started: bool,
    dwell: Option<u16>,
    terminal: bool,
    /// Shared `narf_wireless::reg::witness` generation of this scan.
    generation: ScanGeneration,
    /// The vdev whose scan events this hint scan observes.
    vdev: u32,
}
impl Scan {
    pub(super) fn on_vdev(mut self, vdev: u32) -> Self {
        self.vdev = vdev;
        self
    }
    pub fn event(&mut self, event: &ScanEvent, channels: &[u16]) {
        if event.sequence != 0xa000 | u32::from(self.sequence)
            || event.request != 0xa001
            || event.vdev != self.vdev
            || self.terminal
        {
            return;
        }
        match event.kind {
            1 if event.reason == 0 => {
                self.started = true;
                self.dwell = None;
            }
            8 if self.started && event.reason == 0 => {
                self.dwell = u16::try_from(event.frequency).ok().filter(|frequency| {
                    channels.contains(frequency)
                        && bit(*frequency).is_some_and(|b| self.allowed & b != 0)
                });
            }
            2 | 64 => {
                self.terminal = true;
                self.dwell = None;
            }
            4 | 16 | 32 | 128 | 256 => self.dwell = None,
            _ => {}
        }
    }
}
#[derive(Debug)]
pub(super) struct Owner {
    policy: Policy,
    radio: Arc<Life>,
    window: Option<Arc<Window>>,
    observed: u32,
    /// Radar `beacon_found` witnesses (shared driver-neutral record, scoped
    /// to the window's policy snapshot and latest covering scan).
    radar: BeaconWitness,
}
impl Owner {
    pub fn new() -> Self {
        Self {
            policy: Policy::Installed,
            radio: Arc::new(Life(AtomicBool::new(true))),
            window: None,
            observed: 0,
            radar: BeaconWitness::new(),
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn scoped(database: Arc<db::Database>) -> Self {
        let mut owner = Self::new();
        owner.policy = Policy::Scoped(database);
        owner
    }
    pub fn begin(&mut self, factory: Factory, sequence: u16, channels: &[u16]) -> Option<Scan> {
        // Every SKU records radar `beacon_found`; only World SKUs record the
        // NO_IR lift (`observe`).
        if !self.radio.0.load(Ordering::Acquire) {
            return None;
        }
        let current = self.policy.snapshot()?;
        let allowed = channels
            .iter()
            .filter_map(|f| bit(*f))
            .fold(0, |mask, b| mask | b);
        if allowed == 0 {
            return None;
        }
        if self.window.as_ref().is_none_or(|window| {
            window.factory != factory || !Arc::ptr_eq(&window.original, &current)
        }) {
            self.window = Some(Arc::new(Window {
                policy: self.policy.clone(),
                original: current,
                factory,
                radio: Arc::downgrade(&self.radio),
            }));
            self.observed = 0;
            self.radar.clear();
        }
        let window = self.window.as_ref()?.clone();
        // A radar witness is "heard in the current scan": a new scan that
        // covers a channel retracts its earlier observation until re-heard.
        let covered: alloc::vec::Vec<u16> = channels
            .iter()
            .copied()
            .filter(|f| bit(*f).is_some())
            .collect();
        let generation = self.radar.begin_scan(&window.original, &covered);
        Some(Scan {
            window,
            sequence,
            allowed,
            started: false,
            dwell: None,
            terminal: false,
            generation,
            vdev: 0,
        })
    }
    /// Called only with the original decoded native WMI event in the actual
    /// scan's current FOREIGN_CHANNEL dwell. Public ScanBss never enters here.
    pub fn observe(
        &mut self,
        scan: &Scan,
        event: &Management,
        channels: &[u16],
    ) -> Result<(), Error> {
        if scan.terminal
            || !scan.started
            || !scan.window.current()
            || !self
                .window
                .as_ref()
                .is_some_and(|window| Arc::ptr_eq(window, &scan.window))
            || event.frame.first() != Some(&0x80)
            || event.frame.get(4..10) != Some(&[0xff; 6])
        {
            return Ok(());
        }
        let Some(frequency) = wire::channel_to_frequency(event.channel) else {
            return Ok(());
        };
        if scan.dwell != Some(frequency) {
            return Ok(());
        }
        let Some(found) = beacon(event, channels)? else {
            return Ok(());
        };
        if found.frequency != frequency || found.beacon_interval == 0 {
            return Ok(());
        }
        // Explicit host DFS never becomes a World NO_IR hint, even on a
        // normally non-DFS center; it becomes only the client radar witness.
        // NO_IR remains a separate immutable host restriction.
        let radar = witness::is_radar(&scan.window.original, frequency);
        if !scan.window.current() {
            return Ok(());
        }
        let b = bit(frequency).unwrap_or(0);
        if radar {
            if crate::ath10k::regulatory::Permission::dfs_frequency(frequency) {
                let _ = self.radar.beacon_found(scan.generation, frequency);
            }
        } else if world(scan.window.factory) {
            self.observed |= b;
        }
        Ok(())
    }
    pub fn receipt(&self, domain: &RegulatoryDomain) -> Option<Arc<Receipt>> {
        let window = self.window.as_ref()?;
        if !window.current() || !same_domain(&window.original, domain) {
            return None;
        }
        Some(Arc::new(Receipt {
            window: window.clone(),
            observed: self.observed,
            radar: 0,
        }))
    }
    /// The station client's receipt: also carries the radar `beacon_found`
    /// witnesses (which satisfy the World NO_IR layer on those channels,
    /// as cfg80211 `handle_reg_beacon` clears NO_IR without a RADAR test).
    /// Never pass this to an AP, active-probe or off-channel TX path.
    pub fn client_receipt(&self, domain: &RegulatoryDomain) -> Option<Arc<Receipt>> {
        let window = self.window.as_ref()?;
        if !window.current() || !same_domain(&window.original, domain) {
            return None;
        }
        let radar = FREQUENCIES
            .iter()
            .filter(|f| self.radar.heard(&window.original, **f))
            .filter_map(|f| bit(*f))
            .fold(0, |mask, b| mask | b);
        Some(Arc::new(Receipt {
            window: window.clone(),
            observed: self.observed | radar,
            radar,
        }))
    }
    pub fn retire(&self) {
        self.radio.0.store(false, Ordering::Release);
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.retire();
    }
}

impl<T: super::Hif + super::HostMemory + super::HttMemory> super::Radio<T> {
    pub(super) fn hinted_permission(
        &self,
        domain: &RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
        width80: bool,
    ) -> Result<crate::ath10k::regulatory::Permission, Error> {
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        crate::ath10k::regulatory::Permission::occupied_width_with_hint(
            caps,
            domain,
            frequency,
            secondary,
            width80,
            self.beacon_hints.receipt(domain),
        )
    }
    pub(super) fn begin_beacon_hint_scan(&mut self, sequence: u16, channels: &[u16]) {
        self.hint_scan = self
            .htt
            .wmi
            .caps
            .as_ref()
            .and_then(|caps| Factory::from_eeprom(caps.eeprom_domain).ok())
            .and_then(|factory| self.beacon_hints.begin(factory, sequence, channels))
            .map(|scan| scan.on_vdev(u32::from(self.primary.id())));
    }
    pub(super) fn observe_beacon_hint_event(
        &mut self,
        event: &crate::ath10k::htt_runtime::Event,
    ) -> Result<(), Error> {
        let Some(scan) = &mut self.hint_scan else {
            return Ok(());
        };
        let crate::ath10k::htt_runtime::Event::Wmi(bytes) = event else {
            return Ok(());
        };
        let id = wire::word(bytes, 0)? & 0xffffff;
        if id == self.wire.scan_event {
            scan.event(&self.wire.scan_event(&bytes[4..])?, &self.channels);
        } else if id == self.wire.management_event {
            let native = self.wire.management(&bytes[4..], self.features)?;
            self.beacon_hints.observe(scan, &native, &self.channels)?;
        }
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn beacon_policy_for_test(&mut self, database: Arc<db::Database>) {
        self.beacon_hints.retire();
        self.beacon_hints = Owner::scoped(database);
        self.hint_scan = None;
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "beacon_hint_tests.rs"]
mod tests;
