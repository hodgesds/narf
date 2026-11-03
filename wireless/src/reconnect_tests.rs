//! Retained reconnection profiles (wpa_supplicant network block across a
//! recovered generation).
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn request(security: SecurityConfig) -> AssociateRequest {
    AssociateRequest {
        bssid: [2, 8, 9, 10, 11, 12],
        ssid: b"narf".to_vec(),
        frequency_mhz: 2412,
        channel: 1,
        security,
        ie: alloc::vec![0xdd, 1, 7],
    }
}

fn smoke_wireless_reconnect_profile_retains_credentials_once() -> TestResult {
    let name = "reconnect-test0";
    let Some(profile) = Profile::capture(&request(SecurityConfig::Wpa2 { psk: [0x55; 32] })) else {
        return TestResult::Fail("WPA2 profile not captured");
    };
    retain(name, profile);
    let Some(profile) = take(name) else {
        return TestResult::Fail("retained profile missing");
    };
    let replay = profile.request();
    if replay.bssid != [2, 8, 9, 10, 11, 12]
        || replay.ssid != b"narf"
        || replay.frequency_mhz != 2412
        || replay.channel != 1
        || replay.ie != [0xdd, 1, 7]
        || !matches!(replay.security, SecurityConfig::Wpa2 { psk } if psk == [0x55; 32])
    {
        return TestResult::Fail("replayed request differs from the retained profile");
    }
    if take(name).is_some() {
        return TestResult::Fail("profile replayed twice");
    }
    let sae = request(SecurityConfig::Wpa3 {
        password: b"narf-sae".to_vec(),
    });
    retain(name, Profile::capture(&sae).unwrap());
    // A newer association replaces, and forget drops, the profile.
    retain(
        name,
        Profile::capture(&request(SecurityConfig::Open)).unwrap(),
    );
    if !take(name).is_some_and(|p| matches!(p.request().security, SecurityConfig::Open)) {
        return TestResult::Fail("newer profile did not replace the older one");
    }
    retain(name, Profile::capture(&sae).unwrap());
    if !matches!(take(name).map(|p| p.request().security), Some(SecurityConfig::Wpa3 { password }) if password == b"narf-sae")
    {
        return TestResult::Fail("SAE password not retained");
    }
    retain(name, Profile::capture(&sae).unwrap());
    forget(name);
    if retained(name) || take(name).is_some() {
        return TestResult::Fail("forgotten profile replayed");
    }
    if Profile::capture(&request(SecurityConfig::External(Default::default()))).is_some()
        || Profile::capture(&request(SecurityConfig::Wpa3 {
            password: Vec::new(),
        }))
        .is_some()
    {
        return TestResult::Fail("external supplicant or empty SAE password retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reconnect",
    smoke_wireless_reconnect_profile_retains_credentials_once
);
