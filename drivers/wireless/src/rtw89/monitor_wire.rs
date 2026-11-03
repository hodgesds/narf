// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Pure AX-v0 monitor program metadata, not mode/RF/capture authority.
//! Linux7.3-rc4 mac80211 configure_filter, phy PHYSTS, fw role/join.
//! Unreferenced draft until the same-native role/capture owner is complete.
use narf_wireless::monitor::Channel;
pub(super) const IFTYPE: u32 = 6;
pub(super) const FREQUENCY: u32 = 2412;
pub(super) const CMAC_TX: u32 = 1 << 29;
pub(super) const SNIFFER: u32 = 1;
pub(super) const RX_FILTER: u32 = 0xce20;
pub(super) const FORWARD: [u32; 3] = [0xce24, 0xce28, 0xce2c];
pub(super) const TO_HOST: u32 = 0x55555555;
/// Only receive-only CONTROL/OTHER_BSS requests. Bad FCS/PLCP, cooked,
/// active ACK generation and injection/skip-TX semantics are not promised.
pub(super) fn flags(value: u32) -> bool {
    value & !((1 << 3) | (1 << 4)) == 0
}
/// The advertised admitted profile is ch1/20MHz. Wider channels/other
/// bands have their separate native/qualification rows; never narrow a request.
pub(super) fn channel(value: Channel) -> bool {
    value.frequency_mhz == FREQUENCY
        && matches!(value.width, 0 | 1)
        && value.center1_mhz == FREQUENCY
        && value.center2_mhz == 0
}
/// Actual firmware role MONITOR7, SELF_ROLE_NONE0, MACID0/MAC0/port0.
/// This is an exact payload; no enum can install a native role by itself.
pub(super) fn role(remove: bool) -> [u8; 4] {
    (7u32 << 13 | u32::from(remove) << 10).to_le_bytes()
}
/// Source monitor mapping retains NoLink/no trigger, explicit disconnect.
pub(super) fn join() -> [u8; 4] {
    (7u32 << 26 | 1 << 8).to_le_bytes()
}
/// Source receive filter: preserve its actual max-MPDU/UID settings while
/// disabling address/BSSID/CAM gating and refusing error/unsupported frames.
/// Native must read/write/readback under the exact current monitor program.
pub(super) fn receive_filter(old: u32) -> Option<u32> {
    if old == u32::MAX {
        return None;
    }
    let reject = (1 << 1)
        | (1 << 2)
        | (1 << 3)
        | (1 << 4)
        | (1 << 5)
        | (1 << 6)
        | (1 << 7)
        | (1 << 11)
        | (1 << 12)
        | (1 << 13);
    Some(old & !reject | SNIFFER)
}
/// NoLink port0: no beacon/prohibit/BSSID-fit/TSF synchronization/force TX.
/// CMAC TX is separately and continuously disabled by the native owner.
pub(super) fn port(old: u32) -> Option<u32> {
    if old == u32::MAX {
        return None;
    }
    let clear = (3 << 10) | (1 << 16) | (1 << 13) | (1 << 12) | (1 << 9) | (1 << 4) | (1 << 3);
    Some(old & !clear | 1 << 2)
}
/// Source AX PHYSTS pages. Reserved9 is skipped; monitor adds actual IE09
/// and MU IE10, without inventing signal/rate metadata for other packets.
pub(super) fn physts(page: u8, old: u32) -> Option<u32> {
    if old == u32::MAX || page >= 16 || page == 9 {
        return None;
    }
    Some(match page {
        6 | 7 => old | 1 << 13 | 1 << 9 | 1 << 10,
        10 => old | 1 << 13 | 1 << 1,
        11 => old & !0xf0 | 1 << 1,
        12 => old & !0xf0,
        13 => old & !0xf0 | 1 << 20,
        14 | 15 => old & !0xf0 | 1 << 20 | 1 << 9,
        _ => old,
    })
}
/// Validate four ACTUAL captured RF channel readbacks (pathA/B legacy and
/// direct), not a requested/configured channel. A future opaque same-native
/// receipt may be constructed only after these reads and current PHY/MAC
/// source proof; this pure predicate itself grants no capture/retune/RF.
pub(super) fn observed_channel(words: [u32; 4]) -> bool {
    words
        .into_iter()
        .all(|word| word <= 0xfffff && word & 0x3ffff == 0x1c01)
}
