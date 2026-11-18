// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE software leisure power save (`rtl_lps_enter_core`,
//! `rtl_swlps_beacon`, `rtl_swlps_rf_sleep`, `ps.c`).
//!
//! Composed here are the decisions: the `rtl_lps_enter_core` gates,
//! the `rtl_swlps_beacon` TIM decision, and the
//! `rtl_swlps_rf_sleep` sleep interval. The executions are
//! remainders: `rtl_ps_set_rf_state` (RF sleep/awake) has no NARF
//! primitive for the 92D, and the delayed `ps_work` / `ps_rfon_wq`
//! workqueues have no NARF counterpart — so a `SleepDue` decision
//! only records the sw-LPS state, it does not sleep the radio.
//!
//! Native sleep also lacks a source-defined on-air Null-PM ACK producer.
//! Linux 7.3-rc4 rtl8192de/trx.c:44..229 never invokes rtl_set_tx_report
//! or writes SPE_RPT / SW_DEFINE. The actual RX parser is
//! rtl8192d/trx_common.c:384..431 (sw.c:209), which never assigns
//! packet_report_type; pci.c:979..987 schedules mailbox C2H work only
//! for RTL8723AE. Merely enabling IMR_C2HCMD (DE sw.c:121) supplies no
//! event parser. Null host retirement instead queues rtl_tx_ackqueue
//! (pci.c:511..549), whose timeout reports failure (base.c:1939..1955).
//! mac80211/mlme.c:3948..3966 requires NULLFUNC_ACKED before CONF_PS;
//! status.c:1120..1129 sets it only from a real TX_STAT_ACK receipt.
//! Neither DD, a timer, the common software sequence helper nor
//! rtl_check_tx_report_acked's unrelated key-disable timeout proves AP
//! buffering agreement. No RF sleep/awake execution is authorized here
//! until an actual DE firmware/descriptor receipt protocol is sourced.
//! The retained native packet queue also rejects PM=1 frames; this
//! decision-only module cannot change that gate or the requested PS state.
//!
//! TIM element layout (IEEE 802.11 §9.4.2.5; the low-order bit of
//! the first partial-bitmap octet is AID `bitmap_control.offset ×
//! 16`, bits LSB-first, octet `N/8`, bit `N mod 8`): element ID 5,
//! length, DTIM count, DTIM period, bitmap control (bit 0 =
//! broadcast/multicast buffered, bits 1-7 = bitmap offset), partial
//! virtual bitmap.

/// `MAX_SW_LPS_SLEEP_INTV` (`ps.h:7`).
pub const MAX_SW_LPS_SLEEP_INTV: u8 = 5;
/// Watchdog periods after link before LPS may sleep
/// (`ps.c:402`: `cnt_after_linked < 5` — 5 × 2 s periods, "sleep
/// after linked 10s, to let DHCP and 4-way handshake ok").
pub const CNT_AFTER_LINKED_MIN: u32 = 5;
/// Minimum beacon length (`ps.c:497`: `len <= 40 + FCS_LEN`
/// refuses; FCS is 4 bytes).
pub const BEACON_MIN_LEN: usize = 40 + 4;
/// TIM element ID (`WLAN_EID_TIM`).
pub const TIM_EID: u8 = 5;
/// `struct ieee80211_tim_ie` size (`ps.c:503`: `tim[1] <
/// sizeof(*tim_ie)` refuses).
pub const TIM_IE_MIN_LEN: usize = 4;
/// Beacon fixed parameters (timestamp + interval + capability)
/// after the 24-byte management header: information elements start
/// here.
pub const BEACON_IES_OFFSET: usize = 24 + 12;

/// `rtl_lps_enter_core` (`ps.c:392`) gates, in order: firmware LPS
/// must be enabled (`fwctrl_lps` — false on the 92D, so this first
/// gate refuses); no key being set; no busy traffic; linked at
/// least [`CNT_AFTER_LINKED_MIN`] watchdog periods; not adhoc;
/// linked. True when the station may enter firmware LPS
/// (`rtl_lps_set_psmode(EAUTOPS)`).
pub const fn enter_core_allowed(
    fwctrl_lps: bool,
    being_setkey: bool,
    busytraffic: bool,
    cnt_after_linked: u32,
    adhoc: bool,
    linked: bool,
) -> bool {
    fwctrl_lps
        && !being_setkey
        && !busytraffic
        && cnt_after_linked >= CNT_AFTER_LINKED_MIN
        && !adhoc
        && linked
}

/// Software-LPS beacon state: the `struct rtl_ps_ctl` fields
/// `rtl_swlps_beacon` / `rtl_swlps_rf_sleep` read and write.
/// `last_beacon` is a jiffies timestamp in Linux; NARF keeps only
/// the fact that a matching beacon was seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SwLps {
    pub beacon_seen: bool,
    /// `dtim_counter` (`ps.c:508`).
    pub dtim_counter: u8,
    /// `multi_buffered` (`ps.c:518`): broadcast/multicast traffic
    /// is buffered at the AP.
    pub multi_buffered: bool,
}

/// The `rtl_swlps_beacon` outcome once the gates pass and a TIM
/// element was found: sleep after 5 ms when no multicast is
/// buffered (`queue_delayed_work(..., ps_work, MSECS(5))`), or
/// stay awake — unicast is handled by mac80211, multicast by
/// staying up for the DTIM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconAction {
    SleepDue,
    StayAwake,
}

/// `ieee80211_check_tim` from the TIM element layout (see the
/// module note): whether the partial virtual bitmap has the bit
/// for `aid` set. `tim` is the TIM element value (DTIM count,
/// DTIM period, bitmap control, partial virtual bitmap); the
/// bitmap starts at AID `offset × 16` where `offset` is
/// `bitmap_ctrl >> 1`, bits LSB-first. Bits outside the partial
/// bitmap are implicitly zero.
pub fn check_tim(tim: &[u8], aid: u16) -> bool {
    if tim.len() < 3 {
        return false;
    }
    let offset = u32::from((tim[2] >> 1) & 0x7f);
    let first_aid = offset * 16;
    let Some(position) = u32::from(aid).checked_sub(first_aid) else {
        return false;
    };
    let octet = (position / 8) as usize;
    if 3 + octet >= tim.len() {
        return false;
    }
    tim[3 + octet] & (1 << (position % 8)) != 0
}

/// Find the TIM element (`rtl_find_ie(data, len - FCS_LEN,
/// WLAN_EID_TIM)`) in a beacon frame's information elements:
/// returns the element value (DTIM count first). `None` when no
/// well-formed TIM element is present.
pub fn find_tim(frame: &[u8]) -> Option<&[u8]> {
    let mut at = BEACON_IES_OFFSET;
    while at + 2 <= frame.len() {
        let eid = frame[at];
        let len = usize::from(frame[at + 1]);
        let end = at.checked_add(2).and_then(|s| s.checked_add(len))?;
        if end > frame.len() {
            return None;
        }
        if eid == TIM_EID {
            return Some(&frame[at + 2..end]);
        }
        at = end;
    }
    None
}

/// `rtl_swlps_beacon` (`ps.c:462`): the software-LPS beacon
/// decision. Gates, in order: station mode (the caller), software
/// LPS (`swctrl_lps`), linked, software PS enabled
/// (`sw_ps_enabled`), firmware LPS off (`!fwctrl_lps`), mac80211 PS
/// enabled (`IEEE80211_CONF_PS`, `ps_enabled`), a beacon frame
/// (`ieee80211_is_beacon`: type management, subtype beacon) longer
/// than [`BEACON_MIN_LEN`], from the associated BSSID (addr3).
/// Then `last_beacon` is recorded, the TIM element is found
/// (`tim[1] >= sizeof(*tim_ie)`), `dtim_counter` is set from the
/// TIM's DTIM count when the TIM's DTIM period is non-zero, and
/// the buffered-traffic decision is taken: unicast for this AID
/// (`ieee80211_check_tim`) is mac80211's business; multicast
/// buffered (`bitmap_ctrl & 0x01`) stays awake, otherwise sleep is
/// due. Returns `None` when any gate refuses or no TIM element
/// is present (the beacon-seen record is still kept when the
/// BSSID matched).
#[allow(clippy::too_many_arguments)]
pub fn swlps_beacon(
    state: &mut SwLps,
    frame: &[u8],
    bssid: &[u8; 6],
    aid: u16,
    swctrl_lps: bool,
    linked: bool,
    sw_ps_enabled: bool,
    fwctrl_lps: bool,
    ps_enabled: bool,
) -> Option<BeaconAction> {
    if !swctrl_lps || !linked || !sw_ps_enabled || fwctrl_lps || !ps_enabled {
        return None;
    }
    if frame.len() <= BEACON_MIN_LEN || frame[0] & 0xfc != 0x80 {
        return None;
    }
    if frame.len() < 22 || frame[16..22] != *bssid {
        return None;
    }
    state.beacon_seen = true;
    let tim = find_tim(frame)?;
    if tim.len() < TIM_IE_MIN_LEN {
        return None;
    }
    if tim[1] != 0 {
        state.dtim_counter = tim[0];
    }
    let _unicast_buffered = check_tim(tim, aid);
    state.multi_buffered = tim[2] & 0x01 != 0;
    if state.multi_buffered {
        Some(BeaconAction::StayAwake)
    } else {
        Some(BeaconAction::SleepDue)
    }
}

/// `rtl_swlps_rf_sleep` sleep interval (`ps.c:618`): on a DTIM
/// beacon (`dtim_counter == 0`) sleep `ps_dtim_period` (doubled
/// when the period is 1); otherwise sleep `dtim_counter`;
/// capped at [`MAX_SW_LPS_SLEEP_INTV`].
pub fn sleep_interval(dtim_counter: u8, ps_dtim_period: u8) -> u8 {
    let interval = if dtim_counter == 0 {
        if ps_dtim_period == 1 {
            ps_dtim_period * 2
        } else {
            ps_dtim_period
        }
    } else {
        dtim_counter
    };
    interval.min(MAX_SW_LPS_SLEEP_INTV)
}

/// `rtl_swlps_rf_sleep` wake delay (`ps.c:636`):
/// `sleep_intv * beacon_int - 40` ms (the 40 ms covers the
/// software/hardware switch delay). Saturates at zero.
pub fn sleep_delay_ms(sleep_intv: u8, beacon_int_ms: u16) -> u32 {
    u32::from(sleep_intv)
        .saturating_mul(u32::from(beacon_int_ms))
        .saturating_sub(40)
}
