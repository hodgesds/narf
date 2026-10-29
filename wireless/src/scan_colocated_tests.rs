//! Reduced Neighbor Report parsing into colocated 6 GHz APs and the
//! cfg80211 `cfg80211_scan_6ghz` target plan.
use super::*;
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
        kernel_test_in!("wireless/scan/colocated_6ghz", $name);
    };
}
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message);
        }
    };
}
const COLOC: u8 = 0x40;
/// A Neighbor AP Information field: `count` TBTT entries of `len` octets.
fn ap_info(out: &mut Vec<u8>, count: u8, len: u8, op_class: u8, channel: u8, entries: &[Vec<u8>]) {
    out.extend_from_slice(&[(count - 1) << 4, len, op_class, channel]);
    for e in entries {
        out.extend_from_slice(e);
    }
}
fn tbtt9(bssid: [u8; 6], params: u8, psd: i8) -> Vec<u8> {
    let mut e = vec![0xff];
    e.extend_from_slice(&bssid);
    e.extend_from_slice(&[params, psd as u8]);
    e
}
fn tbtt13(bssid: [u8; 6], short: u32, params: u8, psd: i8) -> Vec<u8> {
    let mut e = vec![0xff];
    e.extend_from_slice(&bssid);
    e.extend_from_slice(&short.to_le_bytes());
    e.extend_from_slice(&[params, psd as u8]);
    e
}
fn ies(rnr: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 4, b'n', b'a', b'r', b'f', 1, 1, 0x8c];
    out.extend_from_slice(&[EID_REDUCED_NEIGHBOR_REPORT, rnr.len() as u8]);
    out.extend_from_slice(rnr);
    out
}
const A: [u8; 6] = [2, 0, 0, 0, 0, 0xa];
const B: [u8; 6] = [2, 0, 0, 0, 0, 0xb];
const C: [u8; 6] = [2, 0, 0, 0, 0, 0xc];

fn short_ssid_crc() -> Result<(), &'static str> {
    check!(
        short_ssid(b"123456789") == 0xcbf4_3926,
        "CRC-32 check value"
    );
    check!(short_ssid(b"") == 0, "empty SSID");
    check!(is_psc_6ghz(5) && is_psc_6ghz(37) && !is_psc_6ghz(1), "PSC");
    Ok(())
}
smoke!(smoke_colocated_short_ssid, short_ssid_crc);

fn parse_rnr() -> Result<(), &'static str> {
    let mut rnr = Vec::new();
    // 6 GHz op class 131, channel 37: same-SSID AP (9-octet form) + a
    // duplicate + a non-colocated AP.
    ap_info(
        &mut rnr,
        3,
        9,
        131,
        37,
        &[
            tbtt9(A, COLOC | 0x02 | 0x10 | 0x20, 10),
            tbtt9(A, COLOC, 0),
            tbtt9(B, 0x02, 0),
        ],
    );
    // 13-octet form with a short SSID on channel 5.
    ap_info(
        &mut rnr,
        1,
        13,
        133,
        5,
        &[tbtt13(B, 0x1234_5678, COLOC | 0x04, -1)],
    );
    // A 5 GHz neighbor (op class 115) is not a 6 GHz target.
    ap_info(&mut rnr, 1, 9, 115, 36, &[tbtt9(C, COLOC, 0)]);
    // An MLD entry type (1) is skipped.
    rnr.extend_from_slice(&[0x01, 9, 131, 53]);
    rnr.extend_from_slice(&tbtt9(C, COLOC, 0));
    let aps = parse_colocated_aps(&ies(&rnr));
    check!(aps.len() == 2, "colocated AP count");
    let a = &aps[0];
    check!(
        a.bssid == A
            && a.channel == 37
            && a.frequency_mhz == 6135
            && a.same_ssid
            && a.ssid == b"narf"
            && a.short_ssid == Some(short_ssid(b"narf"))
            && a.colocated_ess
            && a.unsolicited_probe
            && a.psd_20 == 10,
        "same-SSID AP"
    );
    let b = &aps[1];
    check!(
        b.bssid == B
            && b.frequency_mhz == 5975
            && b.short_ssid == Some(0x1234_5678)
            && b.ssid.is_empty()
            && b.multi_bss
            && !b.transmitted_bssid
            && b.psd_20 == -1,
        "short-SSID AP"
    );
    // An 8-octet entry has no PSD.
    let mut short = Vec::new();
    let mut e = tbtt9(C, COLOC, 0);
    e.pop();
    ap_info(&mut short, 1, 8, 131, 1, &[e]);
    let aps = parse_colocated_aps(&ies(&short));
    check!(
        aps.len() == 1 && aps[0].psd_20 == PSD_RESERVED && aps[0].short_ssid.is_none(),
        "8-octet entry"
    );
    // A disabled MLD link (16-octet form) is ignored.
    let mut mld = Vec::new();
    let mut e = tbtt13(C, 1, COLOC, 0);
    e.extend_from_slice(&[0, 0x00, 0x20]);
    ap_info(&mut mld, 1, 16, 131, 1, &[e]);
    check!(
        parse_colocated_aps(&ies(&mld)).is_empty(),
        "disabled MLD link"
    );
    // A truncated RNR invalidates the whole element stream.
    let mut bad = rnr.clone();
    bad.push(0);
    check!(
        parse_colocated_aps(&ies(&bad)).is_empty(),
        "trailing RNR octet"
    );
    let mut over = Vec::new();
    ap_info(&mut over, 2, 9, 131, 37, &[tbtt9(A, COLOC, 0)]);
    check!(
        parse_colocated_aps(&ies(&over)).is_empty(),
        "TBTT count overrun"
    );
    // Without an SSID element nothing is reported.
    let mut no_ssid = ies(&rnr);
    no_ssid.drain(..6);
    check!(parse_colocated_aps(&no_ssid).is_empty(), "no SSID element");
    // Multicast BSSID.
    let mut mc = Vec::new();
    ap_info(
        &mut mc,
        1,
        9,
        131,
        37,
        &[tbtt9([3, 0, 0, 0, 0, 1], COLOC, 0)],
    );
    check!(parse_colocated_aps(&ies(&mc)).is_empty(), "multicast BSSID");
    Ok(())
}
smoke!(smoke_colocated_parse_rnr, parse_rnr);

fn request(ssids: Vec<Vec<u8>>, frequencies_mhz: Vec<u32>, colocated_6ghz: bool) -> ScanRequest {
    ScanRequest {
        ssids,
        frequencies_mhz,
        channels: Vec::new(),
        active: true,
        random_mac: None,
        colocated_6ghz,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn ap(bssid: [u8; 6], channel: u8, ssid: &[u8], ess: bool) -> ColocatedAp {
    ColocatedAp {
        bssid,
        channel,
        frequency_mhz: 5950 + 5 * u32::from(channel),
        short_ssid: Some(short_ssid(ssid)),
        ssid: ssid.to_vec(),
        oct_recommended: false,
        same_ssid: true,
        multi_bss: false,
        transmitted_bssid: false,
        unsolicited_probe: false,
        colocated_ess: ess,
        psd_20: PSD_RESERVED,
    }
}
fn scan_plan() -> Result<(), &'static str> {
    // 6 GHz channels 1 (non-PSC), 5 (PSC), 37 (PSC), 41; plus 2.4 GHz.
    let freqs = vec![2412, 5955, 5975, 6135, 6155];
    let aps = vec![ap(A, 41, b"narf", false), ap(B, 1, b"other", false)];
    // Without the flag every requested 6 GHz channel, no targets.
    let plan = plan_6ghz_scan(&request(vec![Vec::new()], freqs.clone(), false), &aps, None);
    check!(
        plan.frequencies_mhz == [5955, 5975, 6135, 6155] && plan.targets.is_empty(),
        "no flag"
    );
    // Wildcard colocated scan: PSC channels + every colocated AP.
    let plan = plan_6ghz_scan(&request(vec![Vec::new()], freqs.clone(), true), &aps, None);
    check!(
        plan.frequencies_mhz == [5975, 6135, 6155, 5955],
        "wildcard channels"
    );
    check!(
        plan.targets.len() == 2 && plan.targets[0].bssid == A,
        "wildcard targets"
    );
    // Directed scan: only the matching SSID.
    let plan = plan_6ghz_scan(
        &request(vec![b"narf".to_vec()], freqs.clone(), true),
        &aps,
        None,
    );
    check!(
        plan.targets.len() == 1 && plan.targets[0].frequency_mhz == 6155,
        "directed target"
    );
    check!(
        plan.frequencies_mhz == [5975, 6135, 6155],
        "directed channels keep PSC"
    );
    // A colocated-ESS AP with the SSID: PSC channels are not scanned blind.
    let ess = vec![ap(A, 37, b"narf", true)];
    let plan = plan_6ghz_scan(
        &request(vec![b"narf".to_vec()], freqs.clone(), true),
        &ess,
        None,
    );
    check!(plan.frequencies_mhz == [6135], "colocated ESS skips PSC");
    check!(
        plan.targets.len() == 1 && plan.targets[0].psc_no_listen,
        "psc_no_listen"
    );
    // Short-SSID match without the SSID text.
    let mut hidden = ap(C, 41, b"narf", false);
    hidden.ssid.clear();
    let plan = plan_6ghz_scan(
        &request(vec![b"narf".to_vec()], freqs.clone(), true),
        &[hidden],
        None,
    );
    check!(plan.targets.len() == 1, "short-SSID match");
    // BSSID filter, unrequested channel and non-transmitted multi-BSS.
    let plan = plan_6ghz_scan(
        &request(vec![Vec::new()], freqs.clone(), true),
        &aps,
        Some(B),
    );
    check!(
        plan.targets.len() == 1 && plan.targets[0].bssid == B,
        "BSSID filter"
    );
    let far = vec![ap(A, 101, b"narf", false)];
    let plan = plan_6ghz_scan(&request(vec![Vec::new()], freqs.clone(), true), &far, None);
    check!(plan.targets.is_empty(), "AP on an unrequested channel");
    let mut nontx = ap(A, 41, b"narf", false);
    nontx.multi_bss = true;
    let plan = plan_6ghz_scan(
        &request(Vec::new(), freqs.clone(), true),
        &[nontx.clone()],
        None,
    );
    check!(
        plan.targets.is_empty(),
        "non-transmitted BSSID without SSIDs"
    );
    let plan = plan_6ghz_scan(&request(vec![Vec::new()], freqs, true), &[nontx], None);
    check!(
        plan.targets.is_empty(),
        "non-transmitted BSSID under a wildcard SSID"
    );
    Ok(())
}
smoke!(smoke_colocated_scan_plan, scan_plan);
