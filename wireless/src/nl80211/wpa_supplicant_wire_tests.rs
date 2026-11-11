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
