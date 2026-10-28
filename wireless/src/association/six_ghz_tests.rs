//! 6 GHz band identity, HE 6 GHz Operation/Band Capabilities admission and
//! the regulatory power-type check.
use super::*;
use crate::association::{Bss, JoinPlan, SecurityMode};
use crate::reg::RegFlags;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
macro_rules! smoke {
    ($name:ident, $body:ident) => {
        fn $name() -> TestResult {
            match $body() {
                Ok(()) => TestResult::Pass,
                Err(error) => TestResult::Fail(error),
            }
        }
        kernel_test_in!("wireless/association/six_ghz", $name);
    };
}
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
}
fn he_cap() -> Vec<u8> {
    let mut body = vec![he::EXT_HE_CAPABILITIES, 0, 0, 0, 0, 0, 0];
    let mut phy = [0; 11];
    phy[0] = 0x04 | 0x08; // 40/80 and 160 MHz in 5/6 GHz
    body.extend_from_slice(&phy);
    body.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff]);
    body
}
/// HE Operation with 6 GHz Operation Information (and optionally the
/// Max Co-Hosted BSSID Indicator before it).
fn he_op(six: [u8; 5], co_hosted: bool) -> Vec<u8> {
    let params: u32 = 1023 << 4 | 0x0002_0000 | if co_hosted { 0x8000 } else { 0 };
    let mut body = vec![he::EXT_HE_OPERATION];
    body.extend_from_slice(&params.to_le_bytes());
    body.extend_from_slice(&0xfffcu16.to_le_bytes());
    if co_hosted {
        body.push(3);
    }
    body.extend_from_slice(&six);
    body
}
fn ies(six: [u8; 5], with_6ghz_cap: bool) -> Vec<u8> {
    let mut out = vec![0, 4, b'n', b'a', b'r', b'f', 1, 1, 0x8c];
    element(&mut out, 255, &he_cap());
    element(&mut out, 255, &he_op(six, false));
    if with_6ghz_cap {
        out.extend_from_slice(&He6GhzCapability::new(0x003d).element());
    }
    out
}

fn band_identity() -> Result<(), &'static str> {
    if channel::frequency_in(Band::Ghz6, 37) != Some(6135)
        || channel::frequency_in(Band::Ghz6, 2) != Some(5935)
        || channel::frequency_in(Band::Ghz6, 235) != None
        || channel::frequency_in(Band::Ghz5, 37) != None
        || channel::frequency_in(Band::Ghz5, 36) != Some(5180)
        || channel::frequency(36) != Some(5180)
        || channel::band(37) != None
    {
        return Err("6 GHz channel-to-frequency mapping");
    }
    if channel::from_frequency_band(6135) != Some((Band::Ghz6, 37))
        || channel::from_frequency_band(5935) != Some((Band::Ghz6, 2))
        || channel::from_frequency_band(2412) != Some((Band::Ghz2, 1))
        || channel::from_frequency_band(5180) != Some((Band::Ghz5, 36))
        || channel::from_frequency_band(7120).is_some()
    {
        return Err("frequency-to-band mapping");
    }
    let mut bss = Bss {
        bssid: [2, 0, 0, 0, 0, 2],
        ssid: b"narf".to_vec(),
        channel: 1,
        band: None,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![0, 4, b'n', b'a', b'r', b'f', 1, 1, 0x82],
    };
    if bss.band() != Some(Band::Ghz2) || bss.frequency_mhz() != Some(2412) {
        return Err("legacy Bss band");
    }
    if JoinPlan::prepare(&bss, [2, 0, 0, 0, 0, 1], b"narf", SecurityMode::Open).is_err() {
        return Err("legacy Bss with band None refused");
    }
    bss.band = Some(Band::Ghz6);
    if bss.frequency_mhz() != Some(5955) {
        return Err("6 GHz channel 1 is 5955 MHz");
    }
    // JoinPlan is a 2.4/5 GHz plan: a 6 GHz channel 1 is not 2412 MHz.
    if JoinPlan::prepare(&bss, [2, 0, 0, 0, 0, 1], b"narf", SecurityMode::Open).is_ok() {
        return Err("JoinPlan admitted a 6 GHz BSS as 2.4 GHz channel 1");
    }
    Ok(())
}
smoke!(smoke_six_ghz_band_identity, band_identity);

fn operation_parse() -> Result<(), &'static str> {
    // 80 MHz on primary 37, centre 39 (6145 MHz), SP AP.
    let six = [37, 2 | 1 << 3, 39, 0, 6];
    let body = he_op(six, true);
    let op = HeOperation::parse(&body[1..]).map_err(|_| "6 GHz HE Operation refused")?;
    let info = op.six_ghz_operation().ok_or("missing 6 GHz info")?;
    if info.primary != 37
        || op.max_co_hosted_bssid_indicator() != Some(3)
        || info.power_type(false) != Some(PowerType6Ghz::Sp)
        || info.min_rate != 6
    {
        return Err("6 GHz Operation Information fields");
    }
    let ch = info.channel().map_err(|_| "80 MHz channel invalid")?;
    if ch.width != Width::Eighty || ch.center_mhz != 6145 || ch.primary_mhz != 6135 {
        return Err("80 MHz chandef");
    }
    // 160 MHz: CCFS0 is the 80 MHz centre, CCFS1 the 160 MHz centre.
    let wide = He6GhzOperation::from_bytes([37, 3, 39, 47, 6]).channel();
    if wide.map(|c| (c.width, c.discontiguous, c.center_mhz)) != Ok((Width::OneSixty, false, 6185))
    {
        return Err("160 MHz chandef");
    }
    // Primary outside the announced 80 MHz span.
    if He6GhzOperation::from_bytes([53, 2, 39, 0, 6])
        .channel()
        .is_ok()
    {
        return Err("primary outside the span admitted");
    }
    // Indoor SP falls back to LPI under NO_6GHZ_AFC_CLIENT.
    let indoor = He6GhzOperation::from_bytes([37, 8 << 3, 37, 0, 6]);
    if indoor.power_type(false) != Some(PowerType6Ghz::Sp)
        || indoor.power_type(true) != Some(PowerType6Ghz::Lpi)
        || He6GhzOperation::from_bytes([37, 5 << 3, 37, 0, 6])
            .power_type(false)
            .is_some()
    {
        return Err("power type mapping");
    }
    // The 2.4/5 GHz element parser still refuses 6 GHz information.
    let mut bytes = Vec::new();
    element(&mut bytes, 255, &body);
    if crate::association::phy::ApElements::parse(&bytes).is_ok() {
        return Err("ApElements admitted 6 GHz HE Operation");
    }
    Ok(())
}
smoke!(smoke_six_ghz_he_operation_parse, operation_parse);

fn admission() -> Result<(), &'static str> {
    let six = [37, 2 | 2 << 3, 39, 0, 6];
    let bss = admit(&ies(six, true), 37).map_err(|_| "valid 6 GHz BSS refused")?;
    if bss.capability.max_ampdu_len_exp() != 7
        || bss.capability.min_mpdu_start() != 5
        || bss.power_type != Some(PowerType6Ghz::Vlp)
        || bss.channel.width != Width::Eighty
    {
        return Err("admitted 6 GHz facts");
    }
    if admit(&ies(six, false), 37) != Err(Error::UnsupportedRates) {
        return Err("6 GHz BSS without HE 6 GHz capability admitted");
    }
    if admit(&ies(six, true), 33).is_ok() {
        return Err("primary disagreeing with the receive channel admitted");
    }
    let mut dup = ies(six, true);
    dup.extend_from_slice(&He6GhzCapability::new(0).element());
    if admit(&dup, 37).is_ok() || He6GhzCapability::parse(&[1]).is_ok() {
        return Err("malformed HE 6 GHz capability admitted");
    }
    let rule = |flags| RegRule {
        freq_start_mhz: 5925,
        freq_end_mhz: 7125,
        max_bandwidth_mhz: 320,
        max_power_dbm: 24,
        flags,
    };
    if admit_with_rule(&ies(six, true), 37, &rule(RegFlags::empty())).is_err() {
        return Err("VLP AP refused without NO_6GHZ_VLP_CLIENT");
    }
    if admit_with_rule(&ies(six, true), 37, &rule(RegFlags::NO_6GHZ_VLP_CLIENT)).is_ok() {
        return Err("VLP AP admitted under NO_6GHZ_VLP_CLIENT");
    }
    let r = rule(RegFlags::NO_6GHZ_AFC_CLIENT);
    if !r.allows_6ghz_client(PowerType6Ghz::Lpi) || r.allows_6ghz_client(PowerType6Ghz::Sp) {
        return Err("AFC client restriction");
    }
    let indoor_sp = [37, 2 | 8 << 3, 39, 0, 6];
    let lpi = admit_with_rule(&ies(indoor_sp, true), 37, &r).map_err(|_| "indoor SP")?;
    if lpi.power_type != Some(PowerType6Ghz::Lpi) {
        return Err("indoor SP did not fall back to LPI");
    }
    Ok(())
}
smoke!(smoke_six_ghz_admission_and_power_type, admission);
