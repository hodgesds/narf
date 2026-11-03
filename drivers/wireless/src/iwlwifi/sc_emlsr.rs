//! EMLSR (enhanced multi-link single radio) policy for the native Sc/Bz
//! station MLD. Pure decision state mirroring Linux 7.3 iwlwifi
//! mld/{mlo.c,mlo.h,iface.h,constants.h} and fw/api/{mac-cfg,datapath}.h.
//! It owns no firmware object: every second-link PHY/LINK/STA/queue/key
//! owner must exist before a selection may be applied, and nothing here
//! advertises EML capability to an AP.
use super::native_band::Band;
use alloc::vec::Vec;
use narf_wireless::association::mlo::EmlCapabilities;

/// Linux mld/iface.h `enum iwl_mld_emlsr_blocked`.
pub(super) mod blocked {
    pub const PREVENTION: u32 = 0x1;
    pub const WOWLAN: u32 = 0x2;
    pub const ROC: u32 = 0x4;
    pub const NON_BSS: u32 = 0x8;
    pub const TMP_NON_BSS: u32 = 0x10;
    pub const TPT: u32 = 0x20;
    pub const NAN: u32 = 0x40;
    pub const TDLS: u32 = 0x80;
}

/// Linux mld/iface.h `enum iwl_mld_emlsr_exit`.
pub(super) mod exit {
    pub const BLOCK: u32 = 0x1;
    pub const MISSED_BEACON: u32 = 0x2;
    pub const FAIL_ENTRY: u32 = 0x4;
    pub const CSA: u32 = 0x8;
    pub const EQUAL_BAND: u32 = 0x10;
    pub const LOW_RSSI: u32 = 0x20;
    pub const LINK_USAGE: u32 = 0x40;
    pub const BT_COEX: u32 = 0x80;
    pub const CHAN_LOAD: u32 = 0x100;
    pub const RFI: u32 = 0x200;
    pub const FW_REQUEST: u32 = 0x400;
    pub const INVALID: u32 = 0x800;
}

/// mlo.c IWL_MLD_PREVENT_EMLSR_REASONS.
const PREVENT_REASONS: u32 = exit::MISSED_BEACON | exit::LINK_USAGE | exit::FW_REQUEST;
/// mlo.c/constants.h timing in milliseconds.
const TRIGGER_LINK_SEL_MS: u64 = 30_000;
const PREVENT_TIMEOUT_MS: u64 = 400_000;
const PREVENT_SHORT_MS: u64 = 300_000;
const PREVENT_LONG_MS: u64 = 600_000;

/// fw/api/datapath.h ESR_MODE_NOTIF (DATA_PATH_GROUP 0xF3), v2 only in
/// Linux mld/notif.c.
pub(super) const ESR_MODE_NOTIF: (u8, u8) = (5, 0xf3);
/// fw/api/mac-cfg.h EMLSR_TRANS_FAIL_NOTIF (MAC_CONF_GROUP 0xF7), v1.
pub(super) const EMLSR_TRANS_FAIL_NOTIF: (u8, u8) = (3, 0xf7);

/// mlo.h iwl_mld_vif_has_emlsr_cap: an authorized station MLD whose AP
/// advertised EMLSR support, on a non-CDB (single-radio) device. The
/// caller supplies the NVM sku 11be fact that Linux uses to publish
/// IWL_MLD_EMLSR_CAPA at all (mld/mac80211.c iwl_mld_hw_set_*).
pub(super) fn capable(
    authorized: bool,
    station: bool,
    nvm_11be: bool,
    ap: Option<EmlCapabilities>,
    cdb: bool,
) -> bool {
    authorized && station && nvm_11be && ap.is_some_and(EmlCapabilities::emlsr) && !cdb
}

/// Per-link selection facts (mlo.c `iwl_mld_link_sel_data` plus the
/// primary-link channel-load inputs iwl_mld_channel_load_allows_emlsr uses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Candidate {
    pub spec_link: u8,
    pub band: Band,
    /// Control channel centre, MHz.
    pub primary_mhz: u32,
    /// Operating centre_freq1, MHz.
    pub center_mhz: u32,
    pub width_mhz: u32,
    pub signal_dbm: i8,
    pub csa_active: bool,
    /// iwl_mld_get_link_grade result (caller-computed).
    pub grade: u16,
    /// iwl_mld_get_chan_load, scaled by 1/256.
    pub chan_load: u32,
    /// Link currently active with a channel context.
    pub active: bool,
    /// phy->avg_channel_load_not_by_us, percent.
    pub load_not_by_us: u32,
}

/// mlo.c iwl_mld_get_emlsr_rssi_thresh with constants.h values. Unknown
/// widths are refused (Linux returns S8_MAX).
pub(super) fn rssi_threshold(width_mhz: u32, low: bool) -> Option<i8> {
    let (high, low_value) = match width_mhz {
        20 | 320 => (-67, -72),
        40 => (-64, -72),
        80 => (-61, -72),
        160 => (-58, -72),
        _ => return None,
    };
    Some(if low { low_value } else { high })
}

/// mlo.c iwl_mld_emlsr_disallowed_with_link.
pub(super) fn link_disallowed(link: &Candidate, bt_active: bool) -> u32 {
    let mut reasons = 0;
    if link.band == Band::Two && bt_active {
        reasons |= exit::BT_COEX;
    }
    match rssi_threshold(link.width_mhz, false) {
        Some(threshold) if link.signal_dbm >= threshold => {}
        _ => reasons |= exit::LOW_RSSI,
    }
    if link.csa_active {
        reasons |= exit::CSA;
    }
    reasons
}

/// mlo.c iwl_mld_get_min_chan_load_thresh.
fn min_chan_load(width_mhz: u32) -> u32 {
    match width_mhz {
        160 | 320 => 5,
        80 => 7,
        _ => 10,
    }
}

/// mlo.c iwl_mld_channel_load_allows_emlsr; `a` is the primary.
pub(super) fn channel_load_allows(a: &Candidate, b: &Candidate, low_latency: bool) -> bool {
    if !a.active || a.load_not_by_us < min_chan_load(a.width_mhz) {
        return false;
    }
    if low_latency || a.width_mhz <= b.width_mhz {
        return true;
    }
    match a.width_mhz / b.width_mhz.max(1) {
        2 => a.load_not_by_us > 25,
        4 => a.load_not_by_us > 40,
        8 | 16 => a.load_not_by_us > 50,
        _ => false,
    }
}

/// mlo.c iwl_mld_emlsr_pair_state: zero means a valid EMLSR pair.
pub(super) fn pair_state(a: &Candidate, b: &Candidate, bt_active: bool, low_latency: bool) -> u32 {
    let reasons = link_disallowed(a, bt_active);
    if reasons != 0 {
        return reasons;
    }
    let reasons = link_disallowed(b, bt_active);
    if reasons != 0 {
        return reasons;
    }
    let mut reasons = 0;
    if a.band == b.band {
        let (low, high) = if a.primary_mhz > b.primary_mhz {
            (b, a)
        } else {
            (a, b)
        };
        let low_upper = low.center_mhz + low.width_mhz / 2;
        let high_lower = high.center_mhz.saturating_sub(high.width_mhz / 2);
        // Only 5GHz UNII-1/2 versus UNII-2e/3 has enough HW separation.
        if !(a.band == Band::Five && low_upper <= 5330 && high_lower >= 5490) {
            reasons |= exit::EQUAL_BAND;
        }
    }
    if !channel_load_allows(a, b, low_latency) {
        reasons |= exit::CHAN_LOAD;
    }
    reasons
}

/// mlo.c iwl_mld_get_emlsr_grade: (grade, primary spec link).
fn pair_grade(a: &Candidate, b: &Candidate, bt_active: bool, low_latency: bool) -> (u32, u8) {
    let (a, b) = if b.grade > a.grade { (b, a) } else { (a, b) };
    if pair_state(a, b, bt_active, low_latency) != 0 {
        return (0, a.spec_link);
    }
    (
        u32::from(a.grade) + u32::from(b.grade) * a.chan_load / 256,
        a.spec_link,
    )
}

/// Result of `_iwl_mld_select_links`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    pub active: u16,
    pub primary: u8,
}

/// The firmware station contract: IWL_FW_MAX_ACTIVE_LINKS_NUM.
pub(super) const MAX_ACTIVE_LINKS: usize = super::sc_mlo::MAX_ACTIVE_LINKS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Emlsr {
    pub blocked: u32,
    /// Currently active spec links (mac80211 vif->active_links).
    pub active: u16,
    pub primary: u8,
    pub selected: u16,
    pub selected_primary: u8,
    last_exit_reason: u32,
    last_exit_ms: Option<u64>,
    exit_repeat: u8,
    prevent_until_ms: Option<u64>,
    /// mlo.h `emlsr.last_entry_ts`: when EMLSR last became active.
    entered_ms: Option<u64>,
}

impl Emlsr {
    /// mlo.h iwl_mld_emlsr_active: more than one link active.
    pub fn emlsr_active(&self) -> bool {
        self.active.count_ones() > 1
    }

    /// mlo.h iwl_mld_get_primary_link.
    pub fn primary_link(&self) -> u8 {
        if self.emlsr_active() && self.active & (1 << self.primary) != 0 {
            return self.primary;
        }
        (self.active.trailing_zeros() as u8).min(15)
    }

    /// `_iwl_mld_select_links` over already-qualified candidates (fresh
    /// MLO scan, usable links, authorized). Returns the requested set.
    pub fn select(
        &mut self,
        candidates: &[Candidate],
        capable: bool,
        bt_active: bool,
        low_latency: bool,
    ) -> Option<Selection> {
        let best = candidates
            .iter()
            .enumerate()
            .fold(None::<usize>, |best, (index, link)| match best {
                Some(at) if candidates[at].grade >= link.grade => Some(at),
                _ => Some(index),
            })?;
        let mut primary = candidates[best].spec_link;
        let mut active = 1u16 << primary;
        let mut max_grade = u32::from(candidates[best].grade);
        if candidates.len() > 1 && capable && self.blocked == 0 {
            for (index, a) in candidates.iter().enumerate() {
                for b in &candidates[index + 1..] {
                    let (grade, pair_primary) = pair_grade(a, b, bt_active, low_latency);
                    // Prefer an EMLSR pair over the single link at equality.
                    if grade < max_grade {
                        continue;
                    }
                    max_grade = grade;
                    primary = pair_primary;
                    active = (1 << a.spec_link) | (1 << b.spec_link);
                }
            }
        }
        self.selected = active;
        self.selected_primary = primary;
        Some(Selection { active, primary })
    }

    /// mac80211.c iwl_mld_assign_vif_chanctx bookkeeping once every link
    /// owner in `active` is installed.
    pub fn links_activated(&mut self, active: u16, now_ms: u64) {
        if active.count_ones() > 1 && !self.emlsr_active() {
            self.entered_ms = Some(now_ms);
        }
        self.active = active;
        if active.count_ones() > 1 {
            self.primary = if active == self.selected {
                self.selected_primary
            } else {
                active.trailing_zeros() as u8
            };
        }
    }

    /// mlo.c _iwl_mld_exit_emlsr: the single link to keep, if active.
    pub fn exit(&mut self, reason: u32, keep: u8, now_ms: u64) -> Option<u16> {
        if !self.emlsr_active() {
            return None;
        }
        let keep = if self.active & (1 << keep) != 0 {
            keep
        } else {
            self.active.trailing_zeros() as u8
        };
        self.check_prevention(reason, now_ms);
        Some(1 << keep)
    }

    /// mlo.c iwl_mld_check_emlsr_prevention.
    fn check_prevention(&mut self, reason: u32, now_ms: u64) {
        if self
            .last_exit_ms
            .is_none_or(|last| now_ms > last + PREVENT_TIMEOUT_MS)
            || self.last_exit_reason != reason
        {
            self.exit_repeat = 0;
        }
        self.last_exit_reason = reason;
        self.last_exit_ms = Some(now_ms);
        self.exit_repeat = self.exit_repeat.saturating_add(1);
        if reason == exit::BLOCK {
            return;
        }
        self.blocked |= blocked::PREVENTION;
        let mut delay = TRIGGER_LINK_SEL_MS;
        if self.exit_repeat > 1 && reason & PREVENT_REASONS != 0 {
            delay = if self.exit_repeat == 2 {
                PREVENT_SHORT_MS
            } else {
                PREVENT_LONG_MS
            };
        }
        self.prevent_until_ms = Some(now_ms + delay);
    }

    /// Prevention work: returns true if EMLSR became fully unblocked.
    pub fn prevention_tick(&mut self, capable: bool, now_ms: u64) -> bool {
        match self.prevent_until_ms {
            Some(until) if now_ms >= until => {
                self.prevent_until_ms = None;
                self.unblock(blocked::PREVENTION, capable)
            }
            _ => false,
        }
    }

    /// mlo.c _iwl_mld_emlsr_block: returns the link set to request.
    pub fn block(&mut self, reason: u32, keep: u8, capable: bool, now_ms: u64) -> Option<u16> {
        if !capable || self.blocked & reason != 0 {
            return None;
        }
        self.blocked |= reason;
        self.exit(exit::BLOCK, keep, now_ms)
    }

    /// mlo.c iwl_mld_unblock_emlsr: true means rescan + reselect.
    pub fn unblock(&mut self, reason: u32, capable: bool) -> bool {
        if !capable || self.blocked & reason == 0 {
            return false;
        }
        self.blocked &= !reason;
        self.blocked == 0
    }

    /// mlo.c iwl_mld_vif_iter_emlsr_mode_notif.
    pub fn mode_notification(
        &mut self,
        payload: &[u8],
        capable: bool,
        now_ms: u64,
    ) -> Result<Option<u16>, &'static str> {
        let action = word(payload, 0).ok_or("ESR mode notification short")?;
        word(payload, 4).ok_or("ESR mode notification v2 short")?;
        if !capable {
            return Ok(None);
        }
        // ESR_RECOMMEND_LEAVE only; force-leave/enter are unexpected.
        Ok(match action {
            0 => self.exit(exit::FW_REQUEST, self.primary_link(), now_ms),
            _ => None,
        })
    }

    /// mlo.c iwl_mld_handle_emlsr_trans_fail_notif. `spec_of_fw` maps an
    /// owned firmware link id to its spec link id.
    pub fn transition_failure(
        &mut self,
        payload: &[u8],
        spec_of_fw: impl Fn(u32) -> Option<u8>,
        now_ms: u64,
    ) -> Result<TransitionFailure, &'static str> {
        let fw_link = word(payload, 0).ok_or("EMLSR transition failure short")?;
        let activation = word(payload, 4).ok_or("EMLSR transition failure short")?;
        word(payload, 8).ok_or("EMLSR transition failure short")?;
        let Some(spec) = spec_of_fw(fw_link) else {
            return Ok(TransitionFailure::Disconnect);
        };
        if activation == 0 {
            return Ok(TransitionFailure::Disconnect);
        }
        Ok(match self.exit(exit::FAIL_ENTRY, spec, now_ms) {
            Some(keep) => TransitionFailure::Keep(keep),
            None => TransitionFailure::Ignored,
        })
    }
}

impl Emlsr {
    /// link.c iwl_mld_handle_missed_beacon_notif (v5). `spec_of_fw` maps
    /// an owned firmware link id to its spec link id. The connection-quality
    /// beacon-loss event and the single-link `iwl_mld_int_mlo_scan` switch
    /// attempt have no counterpart here. The BSS-parameters-changed
    /// threshold is not applied: the per-link `bss_param_ch_cnt_link_id`
    /// tracking it depends on is not kept.
    pub fn missed_beacons(
        &mut self,
        payload: &[u8],
        spec_of_fw: impl Fn(u32) -> Option<u8>,
        now_ms: u64,
    ) -> Result<MissedBeacons, &'static str> {
        let field = |at| word(payload, at).ok_or("missed beacons notification short");
        let (fw_link, since_rx, missed) = (field(0)?, field(4)?, field(8)?);
        let (other_fw, other_missed) = (field(12)?, field(16)?);
        let Some(link) = spec_of_fw(fw_link) else {
            return Ok(MissedBeacons::Ignored);
        };
        if missed >= MISSED_THRESHOLD_LONG {
            return Ok(if since_rx >= MISSED_SINCE_RX_THOLD {
                MissedBeacons::Disconnect
            } else {
                MissedBeacons::Ignored
            });
        }
        if self.active.count_ones() <= 1 || other_fw == FW_CTXT_ID_INVALID {
            return Ok(MissedBeacons::Ignored);
        }
        if spec_of_fw(other_fw).is_none() {
            return Ok(MissedBeacons::Ignored);
        }
        let keep = if missed >= BCN_LOSS_EXIT_2_LINKS && other_missed >= BCN_LOSS_EXIT_2_LINKS {
            // Symmetric failure keeps the primary.
            self.primary_link()
        } else if missed >= BCN_LOSS_EXIT {
            // Only this link is sick: keep iwl_mld_get_other_link.
            let other = self.active & !(1u16 << link);
            if other == 0 {
                return Ok(MissedBeacons::Ignored);
            }
            other.trailing_zeros() as u8
        } else {
            return Ok(MissedBeacons::Ignored);
        };
        Ok(match self.exit(exit::MISSED_BEACON, keep, now_ms) {
            Some(set) => MissedBeacons::Keep(set),
            None => MissedBeacons::Ignored,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransitionFailure {
    /// ieee80211_connection_loss: unknown link or failed deactivation.
    Disconnect,
    /// Return to the firmware-named surviving link.
    Keep(u16),
    Ignored,
}

/// MAC_CONFIG client esr_transition_timeout/medium_sync_delay (mld/iface.c
/// iwl_mld_mac_cmd_fill_sta): only meaningful for an MLD association.
pub(super) fn client_mld_fields(
    ap: Option<EmlCapabilities>,
    medium_sync: Option<u16>,
) -> (u8, u16) {
    (
        ap.map_or(0, EmlCapabilities::transition_timeout_code),
        // ieee80211_mle_get_eml_med_sync_delay: absent means the default.
        medium_sync.unwrap_or(MED_SYNC_DELAY_DEFAULT),
    )
}

/// ieee80211-eht.h IEEE80211_MED_SYNC_DELAY_DEFAULT.
pub(super) const MED_SYNC_DELAY_DEFAULT: u16 = 0x10ac;

/// fw/api/mac-cfg.h MISSED_BEACONS_NOTIF (MAC_CONF_GROUP 0xF6), v5.
pub(super) const MISSED_BEACONS_NOTIF: (u8, u8) = (3, 0xf6);
/// mld/constants.h missed-beacon thresholds.
const MISSED_SINCE_RX_THOLD: u32 = 6;
const MISSED_THRESHOLD_LONG: u32 = 19;
const BCN_LOSS_EXIT_2_LINKS: u32 = 5;
const BCN_LOSS_EXIT: u32 = 15;
/// fw/api FW_CTXT_ID_INVALID.
const FW_CTXT_ID_INVALID: u32 = 0xffff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MissedBeacons {
    /// ieee80211_connection_loss.
    Disconnect,
    /// Leave EMLSR keeping this single link set.
    Keep(u16),
    Ignored,
}

fn word(payload: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        payload.get(at..at + 4)?.try_into().ok()?,
    ))
}

/// link.c `iwl_mld_rssi_to_grade` tables, sorted by increasing RSSI:
/// (2.4GHz RSSI, 5/6GHz RSSI, grade).
const GRADE_20: &[(i8, i8, u16)] = &[
    (-94, -95, 9),
    (-92, -93, 17),
    (-90, -90, 34),
    (-87, -87, 52),
    (-83, -84, 69),
    (-79, -80, 103),
    (-75, -75, 137),
    (-72, -73, 155),
    (-70, -71, 172),
    (-67, -68, 206),
    (-64, -65, 230),
    (-59, -60, 258),
    (-57, -58, 287),
    (-52, -53, 310),
    (-50, -50, 345),
];
const GRADE_40: &[(i8, i8, u16)] = &[
    (-95, -95, 9),
    (-93, -93, 17),
    (-91, -92, 18),
    (-89, -90, 34),
    (-87, -87, 68),
    (-84, -84, 104),
    (-80, -81, 138),
    (-77, -77, 206),
    (-72, -72, 274),
    (-69, -70, 310),
    (-67, -68, 344),
    (-64, -65, 412),
    (-61, -62, 460),
    (-56, -57, 516),
    (-54, -55, 574),
    (-49, -50, 620),
    (-46, -47, 690),
];
/// The 80/160/320MHz tables use one RSSI for every band.
const GRADE_80: &[(i8, u16)] = &[
    (-95, 9),
    (-93, 17),
    (-92, 18),
    (-90, 34),
    (-89, 36),
    (-87, 68),
    (-83, 136),
    (-80, 208),
    (-77, 276),
    (-74, 412),
    (-69, 548),
    (-67, 620),
    (-66, 688),
    (-61, 824),
    (-59, 920),
    (-54, 1032),
    (-52, 1148),
    (-47, 1240),
    (-44, 1380),
];
const GRADE_160: &[(i8, u16)] = &[
    (-95, 9),
    (-93, 17),
    (-92, 18),
    (-90, 34),
    (-89, 36),
    (-87, 68),
    (-86, 72),
    (-84, 136),
    (-81, 272),
    (-78, 416),
    (-75, 552),
    (-71, 824),
    (-67, 1096),
    (-65, 1240),
    (-63, 1376),
    (-59, 1648),
    (-57, 1840),
    (-52, 2064),
    (-50, 2296),
    (-46, 2480),
    (-42, 2760),
];
const GRADE_320: &[(i8, u16)] = &[
    (-95, 9),
    (-93, 17),
    (-92, 18),
    (-90, 34),
    (-89, 36),
    (-87, 68),
    (-86, 72),
    (-84, 136),
    (-83, 144),
    (-81, 272),
    (-78, 544),
    (-75, 832),
    (-72, 1104),
    (-69, 1648),
    (-64, 2192),
    (-62, 2480),
    (-61, 2752),
    (-57, 3296),
    (-55, 3680),
    (-50, 4128),
    (-47, 4592),
    (-43, 4960),
    (-40, 5520),
];

/// link.c fixed-point channel-load scale (1/256).
pub(super) const MAX_CHAN_LOAD: u32 = 256;

/// link.h NORMALIZE_PERCENT_TO_255.
pub(super) fn percent_to_255(percent: u32) -> u32 {
    percent * 256 / 100
}

/// link.c `iwl_mld_get_chan_load_from_element`: the BSS Load element
/// (WLAN_EID_QBSS_LOAD, exactly five data bytes) channel utilisation.
pub(super) fn bss_load_channel_util(ies: &[u8]) -> Option<u8> {
    let mut at = 0;
    while at + 2 <= ies.len() {
        let (id, len) = (ies[at], usize::from(ies[at + 1]));
        let data = ies.get(at + 2..at + 2 + len)?;
        if id == 11 {
            return (len == 5).then_some(data[2]);
        }
        at += 2 + len;
    }
    None
}

/// link.c `iwl_mld_get_chan_load`: the element's load minus our own PHY
/// load (`channel_load_by_us`, percent; zero for an inactive link), or the
/// per-band default when the AP sent no valid element.
pub(super) fn chan_load(band: Band, element: Option<u8>, by_us_percent: u32) -> u32 {
    if let Some(load) = element {
        let load = u32::from(load);
        let by_us = percent_to_255(by_us_percent);
        // Use only values that firmware sends that can possibly be valid.
        return if by_us <= load { load - by_us } else { load };
    }
    percent_to_255(match band {
        Band::Two => 30,
        Band::Five => 15,
        Band::Six => 0,
    })
}

/// link.c `iwl_mld_get_link_grade` for a 2.4/5GHz link: the bandwidth
/// table grade for the beacon RSSI (a zero RSSI takes the table's lowest
/// line), scaled by the available channel load and the puncturing
/// penalty. 6GHz links are not graded: their duplicated-beacon and
/// TPE PSD/EIRP RSSI adjustments are not kept, and no 6GHz further link is
/// requested. Unknown widths grade nothing, as Linux returns 0.
pub(super) fn link_grade(
    band: Band,
    width_mhz: u32,
    signal_dbm: i32,
    chan_load: u32,
    punctured: u16,
) -> Option<u16> {
    if band == Band::Six {
        return None;
    }
    let index = usize::from(band != Band::Two);
    let table: Vec<(i32, u16)> = match width_mhz {
        20 => GRADE_20
            .iter()
            .map(|&(lb, hb, g)| (i32::from(if index == 0 { lb } else { hb }), g))
            .collect(),
        40 => GRADE_40
            .iter()
            .map(|&(lb, hb, g)| (i32::from(if index == 0 { lb } else { hb }), g))
            .collect(),
        80 => GRADE_80.iter().map(|&(r, g)| (i32::from(r), g)).collect(),
        160 => GRADE_160.iter().map(|&(r, g)| (i32::from(r), g)).collect(),
        320 => GRADE_320.iter().map(|&(r, g)| (i32::from(r), g)).collect(),
        _ => return None,
    };
    let rssi = if signal_dbm == 0 {
        table[0].0
    } else {
        signal_dbm
    };
    let grade = table
        .iter()
        .find(|&&(line, _)| rssi <= line)
        .map_or(table[table.len() - 1].1, |&(_, grade)| grade);
    let mut grade = u32::from(grade) * (MAX_CHAN_LOAD - chan_load.min(MAX_CHAN_LOAD)) / 256;
    // iwl_mld_apply_puncturing_penalty: only for 80MHz and wider.
    let punctured = punctured.count_ones();
    if width_mhz >= 80 && punctured != 0 {
        let subchannels = width_mhz / 20;
        grade = grade * subchannels.saturating_sub(punctured) / subchannels;
    }
    Some(grade as u16)
}

/// fw/api/stats.h STATISTICS_OPER_NOTIF (STATISTICS_GROUP 0x10).
pub(super) const STATISTICS_OPER_NOTIF: (u8, u8) = (0x10, 0);
/// fw/api/commands.h SYSTEM_STATISTICS_CMD (SYSTEM_GROUP 2).
pub(super) const SYSTEM_STATISTICS_CMD: (u8, u8) = (2, 0xf);
/// stats.c PERIODIC_STATS_SECONDS.
const PERIODIC_STATS_SECONDS: u32 = 5;
/// fw/api/stats.h IWL_STATS_UNKNOWN_CHANNEL_LOAD.
const UNKNOWN_CHANNEL_LOAD: u32 = 0xffff_ffff;
/// fw/api/stats.h IWL_STATS_MAX_PHY_OPERATIONAL.
pub(super) const STATS_PHYS: usize = 3;

/// stats.c `iwl_mld_clear_stats_in_fw` (on demand, OPER|OPER_PART1) and
/// `iwl_mld_request_periodic_fw_stats` bodies, `iwl_system_statistics_cmd`
/// {cfg_mask, config_time_sec, type_id_mask}.
pub(super) fn stats_command(clear: bool, enable: bool) -> [u8; 12] {
    let (cfg, time, types) = match (clear, enable) {
        (true, _) => (1u32 << 1, 0, 0b11u32),
        (false, true) => (0, PERIODIC_STATS_SECONDS, 0b11),
        (false, false) => (1, 0, 0),
    };
    let mut body = [0; 12];
    body[..4].copy_from_slice(&cfg.to_le_bytes());
    body[4..8].copy_from_slice(&time.to_le_bytes());
    body[8..].copy_from_slice(&types.to_le_bytes());
    body
}

/// STATISTICS_OPER_NOTIF per-PHY {channel_load_by_us,
/// channel_load_not_by_us} in percent. v3 (per_phy_v1, 88 bytes) and v4
/// (per_phy v2, 104 bytes) differ only in the per-PHY stride; the exact
/// notification sizes (444/492: time stamp, four 28-byte links, three
/// PHYs, sixteen 4-byte stations) select the layout.
pub(super) fn per_phy_loads(payload: &[u8]) -> Result<[(u32, u32); STATS_PHYS], &'static str> {
    let stride = match payload.len() {
        444 => 88,
        492 => 104,
        _ => return Err("statistics notification size"),
    };
    let mut loads = [(0, 0); STATS_PHYS];
    for (index, load) in loads.iter_mut().enumerate() {
        let at = 4 + 4 * 28 + index * stride;
        *load = (
            word(payload, at + 4).ok_or("statistics notification short")?,
            word(payload, at + 8).ok_or("statistics notification short")?,
        );
    }
    Ok(loads)
}

/// mld/constants.h IWL_MLD_TPT_COUNT_WINDOW and
/// IWL_MLD_ENTER_EMLSR_TPT_THRESH.
const TPT_WINDOW_MS: u64 = 5_000;
const ENTER_TPT_THRESH: u32 = 400;
/// mlo.c EMLSR secondary-link usage rule.
const EMLSR_MIN_TX: u32 = 3000;
const EMLSR_MIN_RX: u32 = 400;
const SEC_LINK_MIN_PERC: u32 = 10;
/// scan.c IWL_MLD_MLO_SCAN_BLOCKOUT_TIME and the 5s link-selection
/// freshness of `_iwl_mld_select_links`.
pub(super) const MLO_SCAN_BLOCKOUT_MS: u64 = 5_000;
pub(super) const MLO_SCAN_FRESH_MS: u64 = 5_000;

/// Per-PHY and per-queue measurement state (stats.c
/// `iwl_mld_fill_chanctx_stats`, sta.c `iwl_mld_count_mpdu`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Measurements {
    /// phy->channel_load_by_us, percent, by firmware PHY id.
    pub load_by_us: [u32; STATS_PHYS],
    /// phy->avg_channel_load_not_by_us, percent, by firmware PHY id.
    pub avg_not_by_us: [u32; STATS_PHYS],
    /// Per RX queue: (window start, per FW link (tx, rx)).
    queues: Vec<(u64, [(u32, u32); 4])>,
}

impl Measurements {
    /// stats.c `iwl_mld_fill_chanctx_stats` for each PHY in `active`
    /// (Linux iterates only existing channel contexts). An out-of-range
    /// load leaves that PHY unchanged; an unknown one keeps the average.
    pub fn update_phys(&mut self, loads: &[(u32, u32); STATS_PHYS], active: &[u8]) {
        for &phy in active {
            let Some(&(by_us, new)) = loads.get(usize::from(phy)) else {
                continue;
            };
            if new != UNKNOWN_CHANNEL_LOAD && new > 100 {
                continue;
            }
            let phy = usize::from(phy);
            self.load_by_us[phy] = by_us;
            if new != UNKNOWN_CHANNEL_LOAD {
                self.avg_not_by_us[phy] = (new >> 1) + (self.avg_not_by_us[phy] >> 1);
            }
        }
    }

    fn queue(&mut self, queue: usize) -> Option<&mut (u64, [(u32, u32); 4])> {
        if queue >= 16 {
            return None;
        }
        if self.queues.len() <= queue {
            self.queues.resize(queue + 1, (0, [(0, 0); 4]));
        }
        self.queues.get_mut(queue)
    }

    /// sta.c `iwl_mld_count_mpdu`: count `count` MPDUs on firmware link
    /// `fw_link` and RX queue `queue` (TX counts on queue 0). While
    /// `tpt_blocked`, an expired window is cleared first and the return is
    /// true exactly when this update crossed the threshold (queue the TPT
    /// unblock).
    pub fn count_mpdus(
        &mut self,
        queue: usize,
        fw_link: u8,
        count: u32,
        tx: bool,
        tpt_blocked: bool,
        now_ms: u64,
    ) -> bool {
        let Some(slot) = self.queue(queue) else {
            return false;
        };
        if usize::from(fw_link) >= slot.1.len() {
            return false;
        }
        if tpt_blocked && now_ms > slot.0 + TPT_WINDOW_MS {
            slot.1 = [(0, 0); 4];
            slot.0 = now_ms;
        }
        let link = &mut slot.1[usize::from(fw_link)];
        if tx {
            link.0 = link.0.saturating_add(count);
        } else {
            link.1 = link.1.saturating_add(count);
        }
        if !tpt_blocked {
            return false;
        }
        let total: u32 = slot
            .1
            .iter()
            .map(|&(t, r)| if tx { t } else { r })
            .fold(0, u32::saturating_add);
        total.saturating_sub(count) < ENTER_TPT_THRESH && total >= ENTER_TPT_THRESH
    }

    /// mlo.c `iwl_mld_emlsr_check_tpt` sums: (total tx, total rx,
    /// secondary tx, secondary rx), clearing every window.
    fn take_counts(&mut self, secondary: Option<u8>) -> (u64, u64, u64, u64) {
        let mut sums = (0u64, 0u64, 0u64, 0u64);
        for (_, links) in &mut self.queues {
            for (index, &(tx, rx)) in links.iter().enumerate() {
                sums.0 += u64::from(tx);
                sums.1 += u64::from(rx);
                if secondary == Some(index as u8) {
                    sums.2 += u64::from(tx);
                    sums.3 += u64::from(rx);
                }
            }
            *links = [(0, 0); 4];
        }
        sums
    }
}

/// Result of the periodic `iwl_mld_emlsr_check_tpt` work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TptCheck {
    /// Not enough MPDUs: block EMLSR (TPT) keeping this set.
    Block(u16),
    /// Secondary link underused: exit (LINK_USAGE) keeping this set.
    Exit(u16),
    Continue,
}

impl Emlsr {
    /// mlo.c `iwl_mld_emlsr_check_tpt`, run every IWL_MLD_TPT_COUNT_WINDOW
    /// while the TPT blocker is clear. `secondary_fw` is the active
    /// secondary link's firmware id once EMLSR has lasted a full window.
    pub fn check_tpt(
        &mut self,
        measurements: &mut Measurements,
        secondary_fw: Option<u8>,
        capable: bool,
        now_ms: u64,
    ) -> TptCheck {
        if !capable || self.blocked & blocked::TPT != 0 {
            return TptCheck::Continue;
        }
        let secondary = secondary_fw.filter(|_| {
            self.emlsr_active()
                && self
                    .entered_ms
                    .is_some_and(|at| now_ms > at + TPT_WINDOW_MS)
        });
        let (tx, rx, sec_tx, sec_rx) = measurements.take_counts(secondary);
        let keep = self.primary_link();
        if tx < u64::from(ENTER_TPT_THRESH) && rx < u64::from(ENTER_TPT_THRESH) {
            return match self.block(blocked::TPT, keep, capable, now_ms) {
                Some(set) => TptCheck::Block(set),
                None => TptCheck::Continue,
            };
        }
        if secondary.is_none() {
            return TptCheck::Continue;
        }
        let tx_perc = if tx == 0 { 0 } else { sec_tx * 100 / tx };
        let rx_perc = if rx == 0 { 0 } else { sec_rx * 100 / rx };
        if (tx > u64::from(EMLSR_MIN_TX) && tx_perc < u64::from(SEC_LINK_MIN_PERC))
            || (rx > u64::from(EMLSR_MIN_RX) && rx_perc < u64::from(SEC_LINK_MIN_PERC))
        {
            if let Some(set) = self.exit(exit::LINK_USAGE, keep, now_ms) {
                return TptCheck::Exit(set);
            }
        }
        TptCheck::Continue
    }
}

/// fw/api/commands.h SCAN_START_NOTIFICATION_UMAC and
/// SCAN_COMPLETE_UMAC (LONG_GROUP).
pub(super) const SCAN_START_NOTIF: u8 = 0xb2;
pub(super) const SCAN_COMPLETE_NOTIF: u8 = 0xf;
/// The internal MLO scan's firmware UID: Linux takes the first free slot
/// (`iwl_mld_scan_uid_by_status`); a station scan and a periodic scan are
/// both refused while the native station is associated with this scan
/// running, so slot0 is free.
pub(super) const MLO_SCAN_UID: u32 = 0;

/// One affiliated AP beacon received after the internal MLO scan started
/// (`link_conf->bss->ts_boottime` newer than `last_mlo_scan_start_time`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Seen {
    pub spec_link: u8,
    pub signal_dbm: i8,
    /// BSS Load channel utilisation, if the beacon carried a valid one.
    pub util: Option<u8>,
}

/// Internal MLO scan and link-selection trigger state (scan.c
/// `iwl_mld_int_mlo_scan`, mlo.c `iwl_mld_select_links`, mld/iface.h
/// `last_link_activation_time`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Selector {
    pub measure: Measurements,
    /// An `iwl_mld_int_mlo_scan` is wanted.
    pub scan_requested: bool,
    pub scan_running: bool,
    /// `last_mlo_scan_start_time` (scan-start notification), ms.
    pub scan_started_ms: Option<u64>,
    pub seen: Vec<Seen>,
    pub last_activation_ms: Option<u64>,
    /// Authorized-station setup (stats request, TPT block) performed.
    pub authorized_setup: bool,
    pub next_tpt_ms: Option<u64>,
    /// A periodic scan owns the firmware scan slot.
    pub scheduled_busy: bool,
}

impl Selector {
    /// scan.c `iwl_mld_int_mlo_scan` preconditions beyond association
    /// (more than one valid link, checked by the caller): one at a time,
    /// none within IWL_MLD_MLO_SCAN_BLOCKOUT_TIME of a link activation.
    pub fn may_start_scan(&self, now_ms: u64) -> bool {
        self.scan_requested
            && !self.scan_running
            && !self.scheduled_busy
            && self
                .last_activation_ms
                .is_none_or(|at| now_ms >= at + MLO_SCAN_BLOCKOUT_MS)
    }

    /// The UMAC scan body for `iwl_mld_int_mlo_scan_start`: every usable
    /// link's channel, no SSIDs (passive), NTF_START, scan priority EXT_4
    /// (`iwl_mld_scan_ooc_priority`), serving firmware link and the
    /// associated low-load timing the periodic owner uses.
    pub fn scan_body(
        version: u8,
        channels: &[super::native_band::Channel],
        serving_fw_link: u8,
    ) -> Result<Vec<u8>, &'static str> {
        let mut body = super::scan_api::passive_channels(version, MLO_SCAN_UID, channels)?;
        let flags = u16::from_le_bytes([body[8], body[9]]) | (1 << 9);
        body[8..10].copy_from_slice(&flags.to_le_bytes());
        body[11] = serving_fw_link;
        body[20..24].copy_from_slice(&120u32.to_le_bytes());
        body[28..32].copy_from_slice(&30u32.to_le_bytes());
        body[36..40].copy_from_slice(&4u32.to_le_bytes());
        Ok(body)
    }

    /// scan.c `iwl_mld_handle_scan_start_notif` for our UID.
    pub fn scan_started(&mut self, payload: &[u8], now_ms: u64) -> bool {
        if !self.scan_running || word(payload, 0) != Some(MLO_SCAN_UID) {
            return false;
        }
        self.scan_started_ms = Some(now_ms);
        self.seen.clear();
        true
    }

    /// Record (newest wins) one affiliated beacon after the scan started.
    pub fn observe(&mut self, seen: Seen) {
        if !self.scan_running || self.scan_started_ms.is_none() {
            return;
        }
        if let Some(old) = self
            .seen
            .iter_mut()
            .find(|old| old.spec_link == seen.spec_link)
        {
            *old = seen;
        } else if self.seen.len() < 16 {
            self.seen.push(seen);
        }
    }

    /// scan.c `iwl_mld_handle_scan_complete_notif` for our UID: true
    /// means `iwl_mld_select_links` (also after an aborted scan).
    pub fn scan_completed(&mut self, payload: &[u8]) -> bool {
        if !self.scan_running || word(payload, 0) != Some(MLO_SCAN_UID) {
            return false;
        }
        self.scan_running = false;
        true
    }

    /// `_iwl_mld_select_links` freshness: the last MLO scan started within
    /// the last five seconds.
    pub fn fresh(&self, now_ms: u64) -> bool {
        self.scan_started_ms
            .is_some_and(|at| now_ms <= at + MLO_SCAN_FRESH_MS)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sc_emlsr_tests.rs"]
mod tests;
