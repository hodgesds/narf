//! Pure opt-in CCK-only14 geometry/planning; no native/factory/host RF grant.
use super::*;
use crate::station_security::RawFrame;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
struct Native {
    bytes: Vec<u8>,
    original: bool,
}
impl RawFrame for Native {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        self.original
    }
}
fn beacon(protected: bool) -> Native {
    let mut bytes = vec![0; 36];
    bytes[0] = 0x80;
    bytes[4..10].copy_from_slice(&[255; 6]);
    bytes[10..16].copy_from_slice(&AP);
    bytes[16..22].copy_from_slice(&AP);
    bytes[32..34].copy_from_slice(&100u16.to_le_bytes());
    bytes[34] = if protected { 17 } else { 1 };
    bytes.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 14,
    ]);
    if protected {
        let mut rsn = RsnIe::wpa2_psk_ccmp();
        rsn.rsn_capabilities = rsn::RSN_CAP_MFP_CAPABLE;
        let body = rsn.encode_body();
        bytes.extend_from_slice(&[48, body.len() as u8]);
        bytes.extend_from_slice(&body);
    }
    Native {
        bytes,
        original: true,
    }
}
fn response(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut out = management(subtype, AP, OWN);
    // management() constructs own->peer; an AP response has physical TA/APBSSID.
    out[16..22].copy_from_slice(&AP);
    out.extend_from_slice(body);
    out
}
fn awaiting(protected: bool) -> Result<JoinPlan, Error> {
    let observed = observe_cck14(&beacon(protected), OWN, None)?;
    let mut plan = JoinPlan::prepare_cck14(
        &observed.bss,
        OWN,
        b"narf",
        if protected {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        },
        JoinOptions::default().with_pmf(Pmf::Optional),
    )?;
    plan.start_authentication()?;
    plan.authentication_response(&response(0xb0, &[0, 0, 2, 0, 0, 0]))?;
    Ok(plan)
}
fn positive() -> Result<(), &'static str> {
    use channel::Band;
    if channel::frequency_in(Band::Ghz2, 14) != Some(2484)
        || channel::from_frequency_band(2484) != Some((Band::Ghz2, 14))
        || channel::band(14).is_some()
        || channel::frequency(14).is_some()
        || channel::from_frequency(2484).is_some()
        || channel::channels(1).contains(&14)
        || channel::frequency_in(Band::Ghz5, 14).is_some()
        || channel::frequency_in(Band::Ghz6, 14).is_some()
    {
        return Err("explicit CCK14 geometry broadened ordinary/other band profiles");
    }
    for protected in [false, true] {
        let input = beacon(protected);
        let observed =
            observe_cck14(&input, OWN, Some(-47)).map_err(|_| "native CCK14 observer")?;
        if observed.bss.channel != 14
            || observed.bss.band != Some(Band::Ghz2)
            || observed.bss.frequency_mhz() != Some(2484)
            || observed.rates != 15
            || observed.basic_rates != 15
            || observed.bss.information_elements != input.bytes[36..]
        {
            return Err("CCK14 rewrote original BSS/rates/security/native facts");
        }
        let mut plan = awaiting(protected).map_err(|_| "explicit CCK14 original authentication")?;
        if plan.legacy_rates() != (15, 15)
            || plan.offered_phy().is_some()
            || plan.negotiated_phy().is_some()
            || plan.mld().is_some()
            || plan.six_ghz().is_some()
            || plan.pmf() != protected
            || plan.enable_spp_amsdu() != Err(Error::UnsupportedRates)
        {
            return Err("CCK14 invented PHY/MLD/AMSDU or lost original PMF rule");
        }
        let mut body = vec![
            if protected { 17 } else { 1 },
            0,
            0,
            0,
            42,
            0xc0,
            1,
            4,
            0x82,
            0x84,
            0x8b,
            0x96,
        ];
        if plan.association_response(&response(0x10, &body)) != Ok(Some(42))
            || plan.phase() != (Phase::Associated { aid: 42 })
        {
            return Err("CCK14 original bound association response");
        }
        body[9] = 0x8c;
        if awaiting(protected)
            .map_err(|_| "new original CCK14 plan")?
            .association_response(&response(0x10, &body))
            != Err(Error::UnsupportedRates)
        {
            return Err("CCK14 response promoted OFDM basic/rate");
        }
    }
    Ok(())
}
fn smoke_association_cck14_explicit_geometry_rates_authentication_and_pmf() -> TestResult {
    positive().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/association/cck14",
    smoke_association_cck14_explicit_geometry_rates_authentication_and_pmf
);
fn negative() -> Result<(), &'static str> {
    let input = beacon(true);
    if observe(&input, 14, OWN, None).is_ok() {
        return Err("ordinary observer admitted14 without opt-in");
    }
    let observed =
        observe_cck14(&input, OWN, None).map_err(|_| "original CCK14 negative fixture")?;
    if JoinPlan::prepare(&observed.bss, OWN, b"narf", SecurityMode::Wpa2Psk).is_ok() {
        return Err("ordinary planner admitted14 without opt-in");
    }
    for mutate in 0..9 {
        let mut bss = observed.bss.clone();
        match mutate {
            0 => bss.band = None,
            1 => bss.band = Some(channel::Band::Ghz5),
            2 => bss.band = Some(channel::Band::Ghz6),
            3 => bss.channel = 1,
            4 => bss.bssid = OWN,
            5 => bss.ssid = b"other".to_vec(),
            6 => bss.capability &= !16,
            7 => bss.information_elements.extend_from_slice(&[50, 1, 12]),
            _ => bss.information_elements.extend_from_slice(&[45, 1, 0]),
        }
        if JoinPlan::prepare_cck14(
            &bss,
            OWN,
            b"narf",
            SecurityMode::Wpa2Psk,
            JoinOptions::default(),
        )
        .is_ok()
        {
            return Err("CCK14 planner accepted wrong band/native peer/security/SSID/OFDM/PHY");
        }
    }
    for extra in [
        vec![61, 1, 14],
        vec![191, 1, 0],
        vec![192, 1, 0],
        vec![255, 1, 35],
        vec![255, 1, 36],
        vec![255, 1, 106],
        vec![255, 1, 107],
        vec![255, 1, 108],
        vec![50, 1, 0x8c],
    ] {
        let mut input = beacon(false);
        input.bytes.extend_from_slice(&extra);
        if observe_cck14(&input, OWN, None).is_ok() {
            return Err("CCK14 original observer accepted PHY/OFDM alias");
        }
        let mut plan = awaiting(false).map_err(|_| "original CCK14 response negative")?;
        let mut body = vec![1, 0, 0, 0, 42, 0xc0, 1, 4, 0x82, 0x84, 0x8b, 0x96];
        body.extend_from_slice(&extra);
        if plan.association_response(&response(0x10, &body)).is_ok() {
            return Err("CCK14 response added unsupported PHY/OFDM mode");
        }
    }
    for (index, bit) in [(0, 0x10), (1, 4), (4, 2), (10, 1), (16, 2), (22, 1)] {
        let mut input = beacon(false);
        input.bytes[index] ^= bit;
        if observe_cck14(&input, OWN, None).is_ok() {
            return Err("CCK14 observer accepted foreign/malformed raw fields");
        }
    }
    let mut input = beacon(false);
    input.original = false;
    if observe_cck14(&input, OWN, None).is_ok() {
        return Err("CCK14 observer fabricated original native bytes");
    }
    Ok(())
}
fn smoke_association_cck14_default_refusal_original_source_and_phy_security_negatives() -> TestResult
{
    negative().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/association/cck14",
    smoke_association_cck14_default_refusal_original_source_and_phy_security_negatives
);
