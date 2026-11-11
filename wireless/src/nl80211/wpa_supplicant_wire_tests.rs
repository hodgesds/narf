//! The NL80211_CMD_CONNECT wpa_supplicant 2.12 puts on the wire for a
//! NetworkManager `wpa-psk` profile on a handshake-offloading wiphy, taken
//! from hostap's `nl80211_connect_common` and
//! `wpa_driver_nl80211_try_connect`, against a WPA2/WPA3 transition-mode AP
//! on 5200 MHz.
//!
//! Four things in that message differ from a hand-written minimal CONNECT,
//! and each used to refuse the request:
//!
//! * NL80211_ATTR_SOCKET_OWNER occurs twice (once under its old name
//!   NL80211_ATTR_IFACE_SOCKET_OWNER);
//! * NL80211_ATTR_AKM_SUITES lists the selected AKM and one more the driver
//!   may use (`wpas_update_allowed_key_mgmt`; a wiphy without
//!   NL80211_ATTR_MAX_NUM_AKM_SUITES gets NL80211_MAX_NR_AKM_SUITES = 2);
//! * CONTROL_PORT_OVER_NL80211 and CONTROL_PORT_NO_PREAUTH are requested
//!   whenever the wiphy advertises the ext features, also when the driver
//!   runs the 4-way handshake itself;
//! * the RSN element's capabilities are 0x000c: sixteen PTKSA replay
//!   counters for an AP with WMM (`rsn_supp_capab`).
use super::*;
use narf_net::netlink_generic::{build_replies_with_context, ReplyOptions, RequestContext};

const BSSID: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x40];
const SSID: &[u8] = b"narf-transition";
const PMK: [u8; 32] = [0x5a; 32];
const PORT: u32 = 0x4d2;
const AKM_PSK: u32 = 0x000f_ac02;
const AKM_PSK_SHA256: u32 = 0x000f_ac06;
const CCMP: u32 = 0x000f_ac04;

/// `wpa_gen_wpa_ie_rsn` for CCMP / CCMP / PSK without PMF, WMM AP.
const RSNE: [u8; 22] = [
    48, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0x0c,
    0x00,
];

/// `wpas_populate_assoc_ies`: the RSN element, Supported Operating Classes
/// and Extended Capabilities.
fn association_ies() -> Vec<u8> {
    let mut ie = RSNE.to_vec();
    ie.extend_from_slice(&[59, 4, 115, 115, 116, 117]);
    ie.extend_from_slice(&[127, 10, 0x04, 0, 0x08, 0, 0, 0, 0, 0x40, 0, 0x20]);
    ie
}

fn akm_list(suites: &[u32]) -> Vec<u8> {
    suites
        .iter()
        .flat_map(|suite| suite.to_ne_bytes())
        .collect()
}

/// The request in the order hostap emits it.
fn connect(ifindex: u32, akms: &[u32]) -> Vec<u8> {
    let mut a = Vec::new();
    push_attr(&mut a, 3, &ifindex.to_ne_bytes());
    // nl80211_connect_common
    push_attr(&mut a, 204, &[]); // IFACE_SOCKET_OWNER
    push_attr(&mut a, 6, &BSSID); // "Limit connection to BSSID"
    push_attr(&mut a, 200, &BSSID); // MAC_HINT
    push_attr(&mut a, 38, &5200u32.to_ne_bytes());
    push_attr(&mut a, 201, &5200u32.to_ne_bytes()); // WIPHY_FREQ_HINT
    push_attr(&mut a, 52, SSID);
    push_attr(&mut a, 42, &association_ies());
    push_attr(&mut a, 75, &2u32.to_ne_bytes()); // NL80211_WPA_VERSION_2
    push_attr(&mut a, 73, &CCMP.to_ne_bytes());
    push_attr(&mut a, 74, &CCMP.to_ne_bytes());
    push_attr(&mut a, 76, &akm_list(akms));
    push_attr(&mut a, 254, &PMK);
    // nl80211_put_control_port
    push_attr(&mut a, 68, &[]);
    push_attr(&mut a, 102, &0x888eu16.to_ne_bytes());
    push_attr(&mut a, 264, &[]); // CONTROL_PORT_OVER_NL80211
    push_attr(&mut a, 286, &[]); // CONTROL_PORT_NO_PREAUTH
    push_attr(&mut a, 315, &[]); // MLO_SUPPORT (every non-SME driver)
                                 // wpa_driver_nl80211_try_connect
    push_attr(&mut a, 53, &0u32.to_ne_bytes()); // NL80211_AUTHTYPE_OPEN_SYSTEM
    push_attr(&mut a, 204, &[]); // SOCKET_OWNER, a second time
    a
}

/// A wiphy like the MT7921 one: PSK 4-way handshake offload for stations,
/// control port over nl80211 advertised for its AP authenticator.
fn offload_wiphy() -> ConnectCaps {
    ConnectCaps {
        psk_offload: true,
        control_port_over_nl80211: true,
        cipher_suites: &[crate::CIPHER_SUITE_CCMP],
        ..ConnectCaps::default()
    }
}

fn parse(bytes: &[u8], caps: ConnectCaps) -> Result<Operation, i32> {
    parse_operation_caps(CONNECT, &message_attributes(bytes)?, caps, PORT)
}

/// The errno the generic-netlink entry point answers a CONNECT with.
fn routed_errno(attrs: &[u8]) -> Option<i32> {
    crate::nl80211::register();
    let mut message = Vec::new();
    message.extend_from_slice(&((16 + 4 + attrs.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message.extend_from_slice(&5u16.to_ne_bytes()); // NLM_F_REQUEST | NLM_F_ACK
    message.extend_from_slice(&9u32.to_ne_bytes());
    message.extend_from_slice(&PORT.to_ne_bytes());
    message.extend_from_slice(&[CONNECT, 0, 0, 0]);
    message.extend_from_slice(attrs);
    let replies = build_replies_with_context(
        &message,
        ReplyOptions::default(),
        RequestContext {
            init_net_admin: true,
            net_admin: true,
            portid: PORT,
            ..RequestContext::default()
        },
    )
    .ok()?;
    let first = replies.first()?;
    // NLMSG_ERROR carries the errno right after the netlink header.
    (first.len() >= 20 && u16::from_ne_bytes([first[4], first[5]]) == 2)
        .then(|| i32::from_ne_bytes(first[16..20].try_into().unwrap()))
}

fn check() -> Result<(), &'static str> {
    // The message as sent: PSK selected, PSK-SHA256 allowed.
    let wire = connect(7, &[AKM_PSK, AKM_PSK_SHA256]);
    match &parse(&wire, offload_wiphy()) {
        Ok(Operation::Connect {
            ssid,
            bssid,
            frequency_mhz,
            cred: Credential::Psk(pmk),
            ie,
            owner,
            ..
        }) => {
            if ssid.as_slice() != SSID
                || *bssid != Some(BSSID)
                || *frequency_mhz != Some(5200)
                || **pmk != PMK
                || *ie != association_ies()
                || *owner != Some(PORT)
            {
                return Err("wpa_supplicant's CONNECT decoded to a different request");
            }
        }
        Ok(_) => return Err("wpa_supplicant's WPA2-PSK CONNECT did not take the PMK path"),
        Err(EINVAL) => return Err("wpa_supplicant's WPA2-PSK CONNECT refused with EINVAL"),
        Err(EOPNOTSUPP) => return Err("wpa_supplicant's WPA2-PSK CONNECT refused with EOPNOTSUPP"),
        Err(_) => return Err("wpa_supplicant's WPA2-PSK CONNECT refused"),
    }

    // The same message reaches the device lookup through the real entry
    // point: no such ifindex is -ENODEV, not a parse error.
    if routed_errno(&connect(0x7fff_fff0, &[AKM_PSK, AKM_PSK_SHA256])) != Some(-19) {
        return Err("the routed CONNECT was refused before the device lookup");
    }

    // __nla_parse: the last occurrence of an attribute is the one used.
    let mut twice = Vec::new();
    push_attr(&mut twice, 52, b"first");
    push_attr(&mut twice, 52, b"second");
    match message_attributes(&twice) {
        Ok(attrs) if attrs.len() == 1 && attrs[0] == (52, &b"second"[..]) => {}
        _ => return Err("a repeated attribute did not replace its earlier occurrence"),
    }
    if message_attributes(&[8, 0, 3, 0, 0]).is_ok() || message_attributes(&[3, 0, 3, 0]).is_ok() {
        return Err("truncated attribute accepted");
    }

    // Only the selected (first) AKM picks the credential: a PMK does not
    // make a PSK-SHA256 or SAE selection a PSK connection.
    for akms in [&[AKM_PSK_SHA256, AKM_PSK][..], &[0x000f_ac08, AKM_PSK]] {
        if !matches!(parse(&connect(7, akms), offload_wiphy()), Err(EOPNOTSUPP)) {
            return Err("an allowed AKM was used in place of the selected one");
        }
    }
    // NL80211_MAX_NR_AKM_SUITES.
    if !matches!(
        parse(
            &connect(7, &[AKM_PSK, AKM_PSK_SHA256, 0x000f_ac08]),
            offload_wiphy()
        ),
        Err(EINVAL)
    ) {
        return Err("more AKM suites than max_num_akm_suites accepted");
    }

    // validate_pae_over_nl80211: a wiphy without the ext feature still
    // refuses control port over nl80211.
    let plain = ConnectCaps {
        control_port_over_nl80211: false,
        ..offload_wiphy()
    };
    if !matches!(parse(&wire, plain), Err(EOPNOTSUPP)) {
        return Err("control port over nl80211 accepted without the ext feature");
    }

    // The native owner's admission of the same elements.
    if crate::association::validate_sme_ies(&association_ies(), true).is_err() {
        return Err("the supplicant's WPA2-PSK association elements were refused");
    }
    // Management-frame protection bits are a different RSNA, not a count.
    let mut mfp = association_ies();
    mfp[20] = 0x8c;
    if crate::association::validate_sme_ies(&mfp, true)
        != Err(crate::association::Error::UnsupportedSecurity)
    {
        return Err("an MFP-capable RSNE passed as plain WPA2-PSK");
    }
    Ok(())
}

fn smoke_nl80211_wpa_supplicant_2_12_psk_connect_on_the_wire() -> TestResult {
    match check() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "wireless/nl80211/wpa_supplicant",
    smoke_nl80211_wpa_supplicant_2_12_psk_connect_on_the_wire
);

// ── SAE offload: a NetworkManager `key-mgmt=sae` profile ───────────────
//
// With NL80211_EXT_FEATURE_SAE_OFFLOAD (and the PSK 4-way handshake
// offload) wpa_supplicant keeps SAE in its selection, sets auth_alg SAE,
// puts the password in NL80211_ATTR_SAE_PASSWORD and waits for
// PORT_AUTHORIZED (`wpa_supplicant_set_suites`, `wpas_start_assoc_cb`,
// `wpa_driver_nl80211_try_connect`, `wpa_supplicant_event_assoc`).
// NetworkManager forces `ieee80211w=2` for such a profile.

const AKM_SAE: u32 = 0x000f_ac08;
const PASSWORD: &[u8] = b"correct horse battery";

/// `wpa_gen_wpa_ie_rsn` for CCMP / CCMP / SAE with `ieee80211w=2` on a WMM
/// AP: capabilities MFPC | MFPR | sixteen PTKSA replay counters (0x00cc), a
/// zero PMKID count and the BIP-CMAC-128 group management cipher.
const SAE_RSNE: [u8; 28] = [
    48, 26, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 8, 0xcc,
    0x00, 0, 0, 0x00, 0x0f, 0xac, 6,
];

/// The RSN element of a WPA3-Personal transition-mode AP: PSK and SAE,
/// MFP capable but not required.
const TRANSITION_AP_RSNE: [u8; 26] = [
    48, 24, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 2, 0, 0x00, 0x0f, 0xac, 2, 0x00,
    0x0f, 0xac, 8, 0x80, 0x00,
];

fn sae_association_ies() -> Vec<u8> {
    let mut ie = SAE_RSNE.to_vec();
    ie.extend_from_slice(&[59, 4, 115, 115, 116, 117]);
    ie.extend_from_slice(&[127, 10, 0x04, 0, 0x08, 0, 0, 0, 0, 0x40, 0, 0x20]);
    ie.extend_from_slice(&[244, 1, 0x20]); // RSNXE: SAE hash-to-element
    ie
}

fn sae_connect(ifindex: u32, wpa_version: u32) -> Vec<u8> {
    let mut a = Vec::new();
    push_attr(&mut a, 3, &ifindex.to_ne_bytes());
    // nl80211_connect_common
    push_attr(&mut a, 204, &[]); // IFACE_SOCKET_OWNER
    push_attr(&mut a, 6, &BSSID);
    push_attr(&mut a, 200, &BSSID);
    push_attr(&mut a, 38, &5200u32.to_ne_bytes());
    push_attr(&mut a, 201, &5200u32.to_ne_bytes());
    push_attr(&mut a, 52, SSID);
    push_attr(&mut a, 42, &sae_association_ies());
    push_attr(&mut a, 75, &wpa_version.to_ne_bytes());
    push_attr(&mut a, 73, &CCMP.to_ne_bytes());
    push_attr(&mut a, 74, &CCMP.to_ne_bytes());
    push_attr(&mut a, 76, &akm_list(&[AKM_SAE]));
    push_attr(&mut a, 68, &[]);
    push_attr(&mut a, 102, &0x888eu16.to_ne_bytes());
    push_attr(&mut a, 264, &[]);
    push_attr(&mut a, 286, &[]);
    push_attr(&mut a, 261, &[]); // EXTERNAL_AUTH_SUPPORT (SAE AKM, no SME)
    push_attr(&mut a, 315, &[]); // MLO_SUPPORT
                                 // wpa_driver_nl80211_try_connect
    push_attr(&mut a, 66, &1u32.to_ne_bytes()); // NL80211_MFP_REQUIRED
    push_attr(&mut a, 298, &[2]); // SAE_PWE
    push_attr(&mut a, 277, PASSWORD); // SAE_PASSWORD
    push_attr(&mut a, 53, &4u32.to_ne_bytes()); // NL80211_AUTHTYPE_SAE
    push_attr(&mut a, 204, &[]); // SOCKET_OWNER, a second time
    a
}

fn sae_wiphy() -> ConnectCaps {
    ConnectCaps {
        sae_offload: true,
        ..offload_wiphy()
    }
}

fn check_sae() -> Result<(), &'static str> {
    use crate::association::{validate_sme_ies_for, Error, SmeRsna};
    // NL80211_WPA_VERSION_2 is what a family below NL80211_ATTR_SAE_PASSWORD
    // gets, NL80211_WPA_VERSION_3 (4) what Linux gets (`wpa_ver_supported`).
    for wpa_version in [2u32, 4] {
        match &parse(&sae_connect(7, wpa_version), sae_wiphy()) {
            Ok(Operation::Connect {
                bssid,
                frequency_mhz,
                cred: Credential::Sae(password),
                owner,
                ..
            }) => {
                if password.as_slice() != PASSWORD
                    || *bssid != Some(BSSID)
                    || *frequency_mhz != Some(5200)
                    || *owner != Some(PORT)
                {
                    return Err("wpa_supplicant's SAE CONNECT decoded to a different request");
                }
            }
            Ok(_) => return Err("wpa_supplicant's SAE CONNECT did not take the SAE path"),
            Err(_) => return Err("wpa_supplicant's SAE-offload CONNECT refused"),
        }
    }
    if !matches!(parse(&sae_connect(7, 1), sae_wiphy()), Err(EOPNOTSUPP)) {
        return Err("SAE accepted under WPA version 1");
    }
    // nl80211_crypto_settings: a SAE password needs the SAE_OFFLOAD feature.
    if !matches!(parse(&sae_connect(7, 2), offload_wiphy()), Err(EINVAL)) {
        return Err("SAE password accepted without SAE offload");
    }

    // The native owner's admission of the supplicant's elements.
    let ies = sae_association_ies();
    if validate_sme_ies_for(&ies, SmeRsna::Wpa3Sae).is_err() {
        return Err("the supplicant's SAE association elements were refused");
    }
    if validate_sme_ies_for(&ies, SmeRsna::Wpa2Psk) != Err(Error::UnsupportedSecurity)
        || validate_sme_ies_for(&association_ies(), SmeRsna::Wpa3Sae)
            != Err(Error::UnsupportedSecurity)
    {
        return Err("SAE and WPA2-PSK association elements were interchangeable");
    }
    // PMF required is part of the SAE request: MFPC alone is not it.
    let mut optional = ies.clone();
    optional[20] = 0x8c;
    // The only RSNXE capability the owner negotiates is hash-to-element.
    let mut rsnxe = ies.clone();
    let last = rsnxe.len() - 1;
    rsnxe[last] = 0x21;
    for bad in [&optional, &rsnxe] {
        if validate_sme_ies_for(bad, SmeRsna::Wpa3Sae) != Err(Error::UnsupportedSecurity) {
            return Err("an SAE request with other RSN capabilities was admitted");
        }
    }

    // BSS selection: the transition-mode BSS is summarised as WPA2 but its
    // RSN element offers SAE; a WPA2-only neighbour on the same SSID does not.
    let bss = |bssid: [u8; 6], rssi: i8| crate::BssInfo {
        bssid,
        ssid: SSID.to_vec(),
        frequency_mhz: 5200,
        channel: 40,
        rssi,
        security: crate::scan::BssSecurity::Wpa2,
    };
    let other = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x41];
    let results = [
        (bss(other, -30), RSNE.to_vec()),
        (bss(BSSID, -60), TRANSITION_AP_RSNE.to_vec()),
    ];
    let pick = |list: &[(crate::BssInfo, Vec<u8>)], akm| {
        select_bss_with_ies(
            list.iter().map(|(b, ies)| (b, ies.as_slice())),
            SSID,
            None,
            Some(5200),
            akm,
        )
        .map(|b| b.bssid)
    };
    if pick(&results, Akm::Sae) != Some(BSSID) {
        return Err("an SAE connect did not find the transition-mode BSS");
    }
    if pick(&results[..1], Akm::Sae).is_some() {
        return Err("an SAE connect selected a BSS that offers only PSK");
    }
    if pick(&results, Akm::Psk) != Some(other) {
        return Err("PSK selection changed");
    }
    Ok(())
}

fn smoke_nl80211_wpa_supplicant_2_12_sae_offload_connect_on_the_wire() -> TestResult {
    match check_sae() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "wireless/nl80211/wpa_supplicant",
    smoke_nl80211_wpa_supplicant_2_12_sae_offload_connect_on_the_wire
);

/// wpa_supplicant reconnecting (another BSS of the ESS, or the same one)
/// while the wiphy is connected: `cfg80211_connect` refuses a CONNECT on a
/// connected station with -EALREADY unless the driver reassociates, and
/// `wpa_driver_nl80211_connect` answers that with DISCONNECT and a second
/// CONNECT. A non-roaming offload driver (MT7921/MT7922) must get that
/// errno, not a failed CONNECT event while its old link stays up.
fn smoke_nl80211_wpa_supplicant_connect_while_connected_is_ealready() -> TestResult {
    let connected = ConnectCaps {
        connected: true,
        ..offload_wiphy()
    };
    let roaming = ConnectCaps {
        roam: true,
        ..connected
    };
    let wire = connect(7, &[AKM_PSK]);
    if parse(&wire, connected).err() != Some(EALREADY)
        || parse(
            &sae_connect(7, 4),
            ConnectCaps {
                sae_offload: true,
                ..connected
            },
        )
        .err()
            != Some(EALREADY)
    {
        return TestResult::Fail("CONNECT on a connected non-roaming wiphy was not -EALREADY");
    }
    if !matches!(parse(&wire, roaming), Ok(Operation::Connect { .. }))
        || !matches!(parse(&wire, offload_wiphy()), Ok(Operation::Connect { .. }))
    {
        return TestResult::Fail("CONNECT refused on a roaming or disconnected wiphy");
    }
    // Malformed requests keep their own errno ahead of the state check.
    let mut bad = wire.clone();
    push_attr(&mut bad, 66, &3u32.to_ne_bytes()); // USE_MFP out of range
    if parse(&bad, connected).err() != Some(ERANGE) {
        return TestResult::Fail("connected state masked an invalid CONNECT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211/wpa_supplicant",
    smoke_nl80211_wpa_supplicant_connect_while_connected_is_ealready
);
