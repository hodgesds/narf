use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn bss(mandatory: bool, capability: u16) -> Bss {
    let mut ies = vec![0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96];
    if mandatory {
        ies.extend_from_slice(&[50, 1, 0x80 | 124]);
    }
    Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 1,
        band: None,
        signal_dbm: None,
        capability,
        beacon_interval: 100,
        information_elements: ies,
    }
}
fn epd_options() -> JoinOptions {
    JoinOptions::default().with_epd(true)
}
fn associate(plan: &mut JoinPlan, capability: u16) -> Result<Vec<u8>, Error> {
    let assoc = plan.start_authentication()?.to_vec();
    let mut auth = management(0xb0, AP, OWN);
    auth[4..10].copy_from_slice(&OWN);
    auth[10..16].copy_from_slice(&AP);
    auth[16..22].copy_from_slice(&AP);
    auth.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
    let request = plan
        .authentication_response(&auth)?
        .ok_or(Error::Protocol)?
        .to_vec();
    let mut resp = auth.clone();
    resp[0] = 0x10;
    resp.truncate(24);
    resp.extend_from_slice(&capability.to_le_bytes());
    resp.extend_from_slice(&[
        0,
        0,
        7,
        0xc0,
        1,
        4,
        0x82,
        0x84,
        0x8b,
        0x96,
        50,
        1,
        0x80 | 124,
    ]);
    let _ = assoc;
    plan.association_response(&resp)?;
    Ok(request)
}
fn epd() -> Result<(), &'static str> {
    let ap = bss(true, 1 | CAP_EPD);
    if JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Open).is_ok() {
        return Err("EPD-mandatory BSS admitted without the EPD opt-in");
    }
    let mut plan =
        JoinPlan::prepare_with_options(&ap, OWN, b"narf", SecurityMode::Open, None, epd_options())
            .map_err(|_| "EPD BSS refused")?;
    if !plan.epd() {
        return Err("EPD not reported");
    }
    let request = associate(&mut plan, 1 | CAP_EPD).map_err(|_| "EPD association")?;
    if u16::from_le_bytes([request[24], request[25]]) & CAP_EPD == 0 {
        return Err("request lacks the EPD capability subfield");
    }
    let mut plan =
        JoinPlan::prepare_with_options(&ap, OWN, b"narf", SecurityMode::Open, None, epd_options())
            .unwrap();
    if associate(&mut plan, 1) != Err(Error::Protocol) || plan.phase() != Phase::Failed {
        return Err("response without EPD admitted");
    }
    if JoinPlan::prepare_with_options(
        &bss(true, 1),
        OWN,
        b"narf",
        SecurityMode::Open,
        None,
        epd_options(),
    )
    .err()
        != Some(Error::InvalidBss)
    {
        return Err("EPD selector without the EPD capability admitted");
    }
    // A BSS that does not mandate EPD keeps LPD framing.
    let optional = JoinPlan::prepare_with_options(
        &bss(false, 1 | CAP_EPD),
        OWN,
        b"narf",
        SecurityMode::Open,
        None,
        epd_options(),
    )
    .map_err(|_| "optional EPD BSS refused")?;
    if optional.epd() {
        return Err("EPD reported for a non-mandatory BSS");
    }
    Ok(())
}
fn smoke_shared_join_epd_membership_and_capability() -> TestResult {
    match epd() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_epd_membership_and_capability
);
