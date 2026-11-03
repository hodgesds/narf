//! Association-preserving PTK0 replacement follows the Linux mt792x
//! `NL80211_EXT_FEATURE_CAN_REPLACE_PTK0` contract (mt792x_core.c
//! `mt792x_init_wiphy`): no firmware DISABLE_KEY window, one in-place
//! WCID-1 `STA_REC_KEY_V2` SET_KEY after message 4/4, BA retirement before
//! the key and a fresh per-key receive replay counter.
use super::vht_tests::{data, join, prepared, record};
use super::*;

const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];

/// `STA_REC_KEY_V2` (mt76_connac_mcu.h) and the STA_REC header WCID byte.
const KEY_V2: u16 = 17;
const WCID: usize = 49;

fn replace() -> Result<(), &'static str> {
    let (mut s, b, p) = prepared(2, true);
    if join(&mut s, &b, p, true) != Ok(42) {
        return Err("WPA2 association before PTK0 replacement");
    }
    s.backend.packets.push_back(data(true, 2, 7, 1, 9));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("old pairwise key data before replacement");
    }
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    let mut packet = descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol()));
    packet[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
    s.backend.packets.push_back(packet);
    if s.receive_ethernet() != Ok(None) || !s.keys_pending() {
        return Err("replacement M1");
    }
    s.backend.access_point = None;
    s.backend.psk = [0x55; 32];
    s.backend.own_mac = OWN;
    s.backend.ap_mac = AP;
    s.backend.anonce = [0x55; 32];
    let before = s.backend.frames.len();
    run(s.service_keys()).map_err(|_| "replacement M2")?;
    if s.receive_ethernet() != Ok(None) || !s.keys_pending() {
        return Err("replacement M3");
    }
    run(s.service_keys()).map_err(|_| "replacement M4 and native PTK")?;
    let frames = &s.backend.frames[before..];
    // mt7921_set_key: an associated station's DISABLE_KEY returns before
    // mt76_connac_mcu_add_key, so the WTBL key is overwritten in place and
    // the firmware never encrypts or accepts frames without a pairwise key.
    let keys: Vec<(usize, &[u8], u8)> = frames
        .iter()
        .enumerate()
        .filter_map(|(i, (_, f))| Some((i, record(f, KEY_V2)?, *f.get(WCID)?)))
        .collect();
    if keys.iter().any(|(_, body, _)| body.get(4) != Some(&0)) {
        return Err("associated PTK0 replacement sent firmware DISABLE_KEY");
    }
    let pairwise: Vec<_> = keys.iter().filter(|(_, _, wcid)| *wcid == 1).collect();
    let [(index, body, _)] = pairwise.as_slice() else {
        return Err("replacement needs exactly one in-place WCID-1 SET_KEY");
    };
    if body.get(8..12) != Some(&[5, 36, 0, 16]) {
        return Err("replacement key is not CCMP-128 key id 0");
    }
    // wpa_supplicant sends 4/4 before wpa_supplicant_install_ptk.
    let m4 = frames
        .iter()
        .rposition(|(_, f)| extract_eapol(f).is_some())
        .ok_or("replacement M4")?;
    if m4 > *index {
        return Err("PTK0 replaced before message 4/4");
    }
    // ieee80211_pairwise_rekey tears down BA before the key changes.
    if s.tx_ba.published() || s.tx_ba.active() {
        return Err("BA survived PTK0 replacement");
    }
    // mt76_wcid_key_setup reloads every per-TID receive counter from the
    // new key; PN 1 is fresh under it although PN 9 preceded under the old.
    s.backend.packets.push_back(data(true, 2, 7, 1, 1));
    if s.receive_ethernet().ok().flatten().is_none() {
        return Err("new key retained the old receive replay counter");
    }
    s.backend.packets.push_back(data(true, 2, 7, 1, 1));
    if s.receive_ethernet().ok().flatten().is_some() {
        return Err("new key accepted a replayed PN");
    }
    Ok(())
}
fn mt76_ptk0_replacement_overwrites_wtbl_key_in_place_after_m4_without_disable() -> TestResult {
    replace().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/key_replace",
    mt76_ptk0_replacement_overwrites_wtbl_key_in_place_after_m4_without_disable
);
