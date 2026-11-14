//! mac80211's software connection-quality monitor for a station whose
//! driver does not report RSSI crossings itself (no
//! `IEEE80211_VIF_SUPPORTS_CQM_RSSI`): `ieee80211_rx_bss_info` keeps
//! `ewma_beacon_signal` (`DECLARE_EWMA(beacon_signal, 4, 4)`) over the AP's
//! Beacons and, after `IEEE80211_SIGNAL_AVE_MIN_COUNT` of them, reports a
//! crossing of the configured threshold (with hysteresis), or of the
//! `cfg80211_cqm_rssi_update` range for a threshold list, as
//! NL80211_CMD_NOTIFY_CQM.
use crate::CqmRssiConfig;

/// `IEEE80211_SIGNAL_AVE_MIN_COUNT`.
const MIN_BEACONS: u32 = 4;

/// One association's beacon-signal average and CQM event state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SoftwareCqm {
    /// EWMA internal value: 16 × the positive signal magnitude.
    ewma: Option<u32>,
    beacons: u32,
    /// `ifmgd->last_cqm_event_signal`; `None` is mac80211's 0 sentinel.
    last_event_dbm: Option<i32>,
}

impl SoftwareCqm {
    /// One Beacon from the AP at `signal_dbm`, under `config`. Returns
    /// `Some(high)` when NL80211_CMD_NOTIFY_CQM must report a crossing
    /// (`true` = above, `false` = below) at [`Self::level_dbm`].
    pub fn beacon(&mut self, signal_dbm: i32, config: Option<&CqmRssiConfig>) -> Option<bool> {
        let magnitude = signal_dbm.saturating_neg().max(0) as u32;
        let scaled = magnitude.saturating_mul(16);
        let ewma = match self.ewma {
            Some(previous) => (previous.saturating_mul(3).saturating_add(scaled)) / 4,
            None => scaled,
        };
        self.ewma = Some(ewma);
        self.beacons = self.beacons.saturating_add(1);
        let config = config?;
        if self.beacons < MIN_BEACONS || config.thresholds_dbm.is_empty() {
            return None;
        }
        let level = self.level_dbm()?;
        let high = if config.thresholds_dbm.len() > 1 {
            let (low, high) = range(config, self.last_event_dbm.unwrap_or(0));
            if level < low && self.last_event_dbm.is_none_or(|last| last >= low) {
                false
            } else if level > high && self.last_event_dbm.is_none_or(|last| last <= high) {
                true
            } else {
                return None;
            }
        } else {
            let threshold = config.thresholds_dbm[0];
            let hysteresis = config.hysteresis_db.min(i32::MAX as u32) as i32;
            if level < threshold
                && self
                    .last_event_dbm
                    .is_none_or(|last| level < last.saturating_sub(hysteresis))
            {
                false
            } else if level > threshold
                && self
                    .last_event_dbm
                    .is_none_or(|last| level > last.saturating_add(hysteresis))
            {
                true
            } else {
                return None;
            }
        };
        self.last_event_dbm = Some(level);
        Some(high)
    }

    /// The averaged beacon signal (`-ewma_beacon_signal_read`).
    pub fn level_dbm(&self) -> Option<i32> {
        self.ewma.map(|ewma| -((ewma / 16) as i32))
    }

    /// A new or removed configuration restarts event tracking
    /// (`ieee80211_cqm_rssi_config` clears `last_cqm_event_signal`).
    pub fn reconfigured(&mut self) {
        self.last_event_dbm = None;
    }
}

/// `cfg80211_cqm_rssi_update`: the two bounds around `last`.
fn range(config: &CqmRssiConfig, last: i32) -> (i32, i32) {
    let next = config
        .thresholds_dbm
        .iter()
        .position(|threshold| last < *threshold)
        .unwrap_or(config.thresholds_dbm.len());
    let hysteresis = config.hysteresis_db.min(i32::MAX as u32) as i32;
    let low = next
        .checked_sub(1)
        .map(|index| config.thresholds_dbm[index].saturating_sub(hysteresis))
        .unwrap_or(i32::MIN);
    let high = config
        .thresholds_dbm
        .get(next)
        .map(|threshold| threshold.saturating_add(hysteresis).saturating_sub(1))
        .unwrap_or(i32::MAX);
    (low, high)
}

#[cfg(feature = "kernel-test")]
#[path = "cqm_tests.rs"]
mod tests;
