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

const OWNER: Owner = Owner {
    family: "test",
    permanent_mac: [2, 3, 4, 5, 6, 7],
};

fn smoke_wireless_reconnect_profile_retains_credentials_once() -> TestResult {
    let name = "reconnect-test0";
    let Some(profile) = Profile::capture(&request(SecurityConfig::Wpa2 { psk: [0x55; 32] })) else {
        return TestResult::Fail("WPA2 profile not captured");
    };
    retain(name, OWNER, profile);
    let Some(profile) = take(name, OWNER) else {
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
    if take(name, OWNER).is_some() {
        return TestResult::Fail("profile replayed twice");
    }
    let sae = request(SecurityConfig::Wpa3 {
        password: b"narf-sae".to_vec(),
    });
    retain(name, OWNER, Profile::capture(&sae).unwrap());
    // A newer association replaces, and forget drops, the profile.
    retain(
        name,
        OWNER,
        Profile::capture(&request(SecurityConfig::Open)).unwrap(),
    );
    if !take(name, OWNER).is_some_and(|p| matches!(p.request().security, SecurityConfig::Open)) {
        return TestResult::Fail("newer profile did not replace the older one");
    }
    retain(name, OWNER, Profile::capture(&sae).unwrap());
    if !matches!(take(name, OWNER).map(|p| p.request().security), Some(SecurityConfig::Wpa3 { password }) if password == b"narf-sae")
    {
        return TestResult::Fail("SAE password not retained");
    }
    retain(name, OWNER, Profile::capture(&sae).unwrap());
    forget(name);
    if retained(name, OWNER) || take(name, OWNER).is_some() {
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

/// Another device or driver that later registers the same name never
/// receives the credential; the mismatched take destroys the profile.
fn smoke_wireless_reconnect_profile_refuses_foreign_owner() -> TestResult {
    let name = "reconnect-test1";
    let profile = Profile::capture(&request(SecurityConfig::Wpa2 { psk: [0x55; 32] })).unwrap();
    for foreign in [
        Owner {
            family: "other",
            ..OWNER
        },
        Owner {
            permanent_mac: [2, 3, 4, 5, 6, 8],
            ..OWNER
        },
    ] {
        retain(name, OWNER, Profile::capture(&profile.request()).unwrap());
        if retained(name, foreign) {
            return TestResult::Fail("foreign owner sees the retained profile");
        }
        if take(name, foreign).is_some() {
            return TestResult::Fail("foreign owner took the retained credential");
        }
        if retained(name, OWNER) || take(name, OWNER).is_some() {
            return TestResult::Fail("mismatched take left the credential retained");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/reconnect",
    smoke_wireless_reconnect_profile_refuses_foreign_owner
);
