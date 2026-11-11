// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8852C 6GHz station facts: the HE 6GHz Band Capabilities, the 6GHz
//! probe-request content and the regd.c TPE constraint of an AP's Transmit
//! Power Envelope elements. Pure parsing/encoding: no channel, transmit or
//! association right follows from anything here.
use alloc::{vec, vec::Vec};
use narf_wireless::association::{phy::Width, six_ghz};

/// `WLAN_EID_TX_POWER_ENVELOPE`.
const EID_TPE: u8 = 195;
/// `IEEE80211_TPE_CAT_6GHZ_DEFAULT`.
const CATEGORY_DEFAULT: u8 = 0;
/// `IEEE80211_TPE_{MAX_TX_PWR_NO_CONSTRAINT,PSD_NO_LIMIT}` (the
/// `ieee80211_clear_tpe` fill of entries an element leaves out).
const NO_LIMIT: i8 = 127;

/// core.c `rtw89_init_he_cap` HE 6GHz Band Capabilities for RTL8852C:
/// `IEEE80211_HT_MPDU_DENSITY_NONE` (0), `IEEE80211_VHT_MAX_AMPDU_1024K`
/// (7) and `chip->max_vht_mpdu_cap` restricted to 3895 octets (0): this
/// station profile admits no RX A-MSDU (`station_amsdu_allowed` is false on
/// RTL8852C), so the 11454-octet MPDU of `rtw8852c_chip_info` is not
/// promised. SM power save is set by mac80211 at transmission
/// (`SixGhzLocal::transmitted_capability`).
pub(super) fn capability() -> six_ghz::He6GhzCapability {
    six_ghz::He6GhzCapability::new(7 << 3 & six_ghz::CAP_MAX_AMPDU_LEN_EXP)
}

/// mac80211 `ieee80211_build_probe_req` (`ieee80211_build_preq_ies_band`)
/// on `NL80211_BAND_6GHZ` for the HE20 station: SSID, the eight OFDM
/// Supported Rates (no Extended Supported Rates, no DS Parameter Set, no
/// HT/VHT on 6GHz), HE Capabilities (`ieee80211_put_he_cap`) and HE 6GHz
/// Band Capabilities (`ieee80211_put_he_6ghz_cap`, SMPS off), then the
/// caller's extra IEs.
pub(super) fn probe_request(own: [u8; 6], ssid: &[u8], ies: &[u8]) -> Option<Vec<u8>> {
    let he = crate::rtw89::station_control::local_he()?.capability_body();
    let mut frame = vec![0x40, 0, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, ssid.len() as u8]);
    frame.extend_from_slice(ssid);
    frame.extend_from_slice(&[1, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]);
    frame.extend_from_slice(&[255, u8::try_from(he.len()).ok()?]);
    frame.extend_from_slice(&he);
    let transmitted = capability().bits() & !six_ghz::CAP_SM_PS | 3 << 9;
    frame.extend_from_slice(&six_ghz::He6GhzCapability::new(transmitted).element());
    frame.extend_from_slice(ies);
    Some(frame)
}

/// One `ieee80211_parse_tpe` slot (default category only: regd.c
/// `rtw89_calculate_tpe` reads `IEEE80211_TPE_CAT_6GHZ_DEFAULT`).
#[derive(Clone, Copy)]
struct Slot {
    power: [i8; 16],
    count: usize,
    /// PSD `N` (0: the all-subchannels form).
    n: usize,
}

/// regd.c `tpe_get_constraint`: hw deviation 3 + antenna gain 10 + array
/// gain 6 (0.5 dB units) off the raw field, in dB.
fn constraint(raw: i8) -> i8 {
    ((i16::from(raw) - 19) / 2) as i8
}

/// The regd.c `rtw89_calculate_tpe` constraint (dBm) for a 20MHz station
/// on `primary` inside the AP's HE 6GHz channel `ap`: mac80211
/// `ieee80211_parse_tpe` (after `ieee80211_valid_tpe_element`; a later
/// element replaces an earlier one of the same interpretation), then
/// `ieee80211_rearrange_tpe` to the used 20MHz chandef (EIRP: the 20MHz
/// entry; PSD: the primary's subchannel), then the minimum over the local
/// and regulatory-client EIRP and PSD limits (PSD + `10 * log10(20)`).
/// `Ok(None)`: no valid default-category TPE. `Err`: an 80+80MHz AP channel
/// (not rearranged here) or a primary outside `ap`.
pub(in crate::rtw89) fn tpe(ies: &[u8], ap: &six_ghz::SixGhzChannel) -> Result<Option<i8>, ()> {
    let have: u32 = match ap.width {
        _ if ap.discontiguous => return Err(()),
        Width::Twenty => 1,
        Width::Forty => 2,
        Width::Eighty => 4,
        Width::OneSixty => 8,
    };
    let low = ap.center_mhz.checked_sub(10 * have).ok_or(())?;
    let index = ap.primary_mhz.checked_sub(low).ok_or(())? / 20;
    if index >= have {
        return Err(());
    }
    let (have, index) = (have as usize, index as usize);
    // max_local, psd_local, max_reg_client, psd_reg_client.
    let mut slots: [Option<Slot>; 4] = [None; 4];
    let mut rest = ies;
    while rest.len() >= 2 {
        let len = usize::from(rest[1]);
        let Some(body) = rest.get(2..2 + len) else {
            break;
        };
        if rest[0] == EID_TPE {
            if let Some((interpret, slot)) = parse(body) {
                slots[usize::from(interpret)] = Some(slot);
            }
        }
        rest = &rest[2 + len..];
    }
    let mut result: Option<i8> = None;
    let mut intersect = |cstr: i8| {
        result = Some(result.map_or(cstr, |r| r.min(cstr)));
    };
    for (interpret, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else {
            continue;
        };
        if interpret & 1 == 0 {
            // EIRP: `count` limited to `ieee80211_chandef_num_widths` (1).
            intersect(constraint(slot.power[0]));
            continue;
        }
        // PSD: `ieee80211_rearrange_tpe_psd` with needed = 1.
        let value = if slot.n == 0 {
            slot.power[0]
        } else {
            let offset = if have <= slot.n {
                0
            } else {
                index - index % slot.n
            };
            let i = if index < offset {
                index + slot.n
            } else if index < offset + slot.n {
                index - offset
            } else {
                index
            };
            slot.power[i]
        };
        // tpe_convert_psd_to_eirp: + 10 * 1301 / 1000.
        intersect(constraint(value).saturating_add(13));
    }
    Ok(result)
}

/// `ieee80211_valid_tpe_element` + `ieee80211_parse_tpe` for one default
/// category element: (interpretation, slot).
fn parse(body: &[u8]) -> Option<(u8, Slot)> {
    let (&info, values) = body.split_first()?;
    let count = usize::from(info & 7);
    let interpret = (info >> 3) & 7;
    let category = info >> 6;
    if category > 1 || interpret > 3 {
        return None;
    }
    let mut slot = Slot {
        power: [NO_LIMIT; 16],
        count: 0,
        n: 0,
    };
    if interpret & 1 == 0 {
        if count > 3 || values.len() < count + 1 {
            return None;
        }
        for (out, value) in slot.power.iter_mut().zip(&values[..count + 1]) {
            *out = *value as i8;
        }
        slot.count = count + 1;
        if count == 3 && values.len() > count + 1 {
            slot.power[4] = values[4] as i8;
            slot.count = 5;
        }
    } else {
        if count > 4 {
            return None;
        }
        let n = if count == 0 { 1 } else { 1 << (count - 1) };
        if values.len() < n {
            return None;
        }
        let k = if values.len() > n {
            let k = usize::from(values[n] & 0xf);
            if values.len() < n + 1 + k {
                return None;
            }
            k
        } else {
            0
        };
        if count == 0 {
            slot.power = [values[0] as i8; 16];
            slot.count = 16;
        } else {
            for (out, value) in slot.power.iter_mut().zip(&values[..n]) {
                *out = *value as i8;
            }
            // No extension count byte (`values.len() == n`) means no
            // extension entries; `values[n + 1..]` would start past
            // the end of the field then.
            let k = k.min(16 - n);
            let ext = values.get(n + 1..n + 1 + k).unwrap_or(&[]);
            for (out, value) in slot.power[n..].iter_mut().zip(ext) {
                *out = *value as i8;
            }
            slot.count = n + k;
            slot.n = n;
        }
    }
    (category == CATEGORY_DEFAULT).then_some((interpret, slot))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_wireless::association::six_ghz::SixGhzChannel;

    fn smoke_rtw8852c_6ghz_tpe_follows_mac80211_rearrange_and_regd() -> TestResult {
        let ap80 = SixGhzChannel {
            primary: 5,
            primary_mhz: 5975,
            width: Width::Eighty,
            discontiguous: false,
            center_mhz: 5985,
            center2_mhz: None,
        };
        // Local EIRP 20/40/80 (raw 72/80/88): 20MHz entry only, (72-19)/2.
        let eirp = [195, 4, 0x02, 72, 80, 88];
        // Regulatory-client PSD, N = 4: primary 5 is subchannel 1 of the
        // 80MHz span, raw 40 -> (40 - 19) / 2 + 13 = 23.
        let both = [195, 4, 0x02, 72, 80, 88, 195, 5, 0x1b, 30, 40, 50, 60];
        let cases: [(&[u8], Option<i8>); 6] = [
            (&[], None),
            (&eirp, Some(26)),
            (&both, Some(23)),
            // Subordinate category: validated, unused.
            (&[195, 2, 0x40, 0], None),
            // EIRP count 3 with two values: invalid, ignored.
            (&[195, 3, 0x03, 10, 10], None),
            // PSD count 0: one value for every subchannel, (21-19)/2 + 13.
            (&[195, 2, 0x08, 21], Some(14)),
        ];
        for (ies, expected) in cases {
            if tpe(ies, &ap80) != Ok(expected) {
                return TestResult::Fail("rtw89 6GHz TPE differs from mac80211/regd.c");
            }
        }
        if capability().bits() != 0x0038 {
            return TestResult::Fail("rtw89 HE 6GHz capability");
        }
        let Some(probe) = probe_request([2, 0, 0, 0, 0, 1], b"", &[]) else {
            return TestResult::Fail("rtw89 6GHz probe request");
        };
        if probe[24..].windows(2).any(|w| w == [3, 1] || w == [50, 4])
            || probe[probe.len() - 5..] != [255, 3, 59, 0x38, 0x06]
        {
            return TestResult::Fail("rtw89 6GHz probe request content");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw8852c_6ghz_tpe_follows_mac80211_rearrange_and_regd
    );
}
