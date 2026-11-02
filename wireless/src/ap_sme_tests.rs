//! Actual GET_WIPHY route: firmware SME is a capability u32, including zero.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};
fn get(f: &Fixture) -> Result<Vec<Vec<u8>>, &'static str> {
    let _ = crate::nl80211::register();
    let mut request = alloc::vec![0;28];
    request[..4].copy_from_slice(&28u32.to_ne_bytes());
    request[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&0x534d4530u32.to_ne_bytes());
    request[16..20].copy_from_slice(&[1, 1, 0, 0]);
    request[20..22].copy_from_slice(&8u16.to_ne_bytes());
    request[22..24].copy_from_slice(&3u16.to_ne_bytes());
    request[24..28].copy_from_slice(&f.ifindex.to_ne_bytes());
    build_replies_with_endpoint(
        &request,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&f.admin),
            ..RequestContext::default()
        },
        f.source.clone(),
    )
    .map_err(|_| "AP SME raw GET_WIPHY")
}
fn field(mut raw: &[u8], want: u16) -> Option<&[u8]> {
    while !raw.is_empty() {
        let h = raw.get(..4)?;
        let n = usize::from(u16::from_ne_bytes([h[0], h[1]]));
        if n < 4 {
            return None;
        }
        if u16::from_ne_bytes([h[2], h[3]]) & 0x3fff == want {
            return raw.get(4..n);
        }
        raw = raw.get(n.next_multiple_of(4)..)?;
    }
    None
}
fn check() -> Result<(), &'static str> {
    let f = fixture()?;
    for (cap, available, want) in [
        (u64::MAX, true, None),
        (0, true, Some(0u32)),
        (1, true, Some(1)),
        (0x80000001, true, Some(1)),
        (0, false, None),
    ] {
        f.radio.ap_sme.store(cap, Ordering::Release);
        f.radio.ap_available.store(available, Ordering::Release);
        let replies = get(&f)?;
        let reply = replies
            .iter()
            .find(|r| r.len() >= 20 && r[16] == 3)
            .ok_or("AP SME wiphy reply")?;
        let actual = field(&reply[20..], 141);
        let expected = want.map(u32::to_ne_bytes);
        if actual != expected.as_ref().map(|v| v.as_slice()) {
            return Err("DEVICE_AP_SME absent/default/AP gate or u32 capability encoding");
        }
    }
    Ok(())
}
fn firmware_ap_sme_discovery_is_explicit_gated_capabilities_not_a_flag() -> TestResult {
    check().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_control",
    firmware_ap_sme_discovery_is_explicit_gated_capabilities_not_a_flag
);
