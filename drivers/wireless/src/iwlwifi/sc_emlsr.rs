//! EMLSR (enhanced multi-link single radio) policy for the native Sc/Bz
//! station MLD. Pure decision state mirroring Linux 7.3 iwlwifi
//! mld/{mlo.c,mlo.h,iface.h,constants.h} and fw/api/{mac-cfg,datapath}.h.
//! It owns no firmware object: every second-link PHY/LINK/STA/queue/key
//! owner must exist before a selection may be applied, and nothing here
//! advertises EML capability to an AP.
use super::native_band::Band;
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
    pub fn links_activated(&mut self, active: u16) {
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sc_emlsr_tests.rs"]
mod tests;
