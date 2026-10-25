//! Native station operations behind Linux messages.
//!
//! Permission follows Linux generic netlink: every mutating command here is
//! `GENL_UNS_ADMIN_PERM` (or `GENL_ADMIN_PERM`) in `nl80211_ops`, checked by
//! the generic-netlink layer against the sender before this handler runs.
//! A sender that passed it acts on any interface of its network namespace,
//! as cfg80211 does; one that did not reached here only because its socket
//! carries NARF's delegated interface-bound handle, which must then cover
//! the interface the request names ([`authority`]).

use super::*;
use alloc::{string::String, sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::netlink_generic::{publish_event, RequestContext};
use zeroize::Zeroizing;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "control_tests.rs"]
mod tests;

#[path = "station.rs"]
pub(super) mod station;

#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn set_owner_for_test(name: &str, namespace: u64, portid: u32, bssid: [u8; 6]) {
    station::set_owner(name, namespace, portid, Some(bssid));
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn unregister_owner_for_test(name: &str) {
    station::unregister_wdev(name);
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_tests.rs"]
mod station_tests;

const EINVAL: i32 = 22;
const EPERM: i32 = 1;
const EBUSY: i32 = 16;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const ERANGE: i32 = 34;
const EALREADY: i32 = 114;
const SCAN: u8 = 33;
const GET_SCAN: u8 = 32;
const CONNECT: u8 = 46;
const ROAM: u8 = 47;
const DISCONNECT: u8 = 48;
const PORT_AUTHORIZED: u8 = 125;
const SET_INTERFACE: u8 = 6;
const NEW_INTERFACE: u8 = 7;
const DEL_INTERFACE: u8 = 8;
const GET_STATION: u8 = 17;
const SET_WIPHY: u8 = super::NL80211_CMD_SET_WIPHY;
const GET_SURVEY: u8 = super::NL80211_CMD_GET_SURVEY;
const SET_TX_BITRATE_MASK: u8 = super::NL80211_CMD_SET_TX_BITRATE_MASK;
/// `NL80211_CMD_SET_CQM` (software RSSI threshold monitoring).
const SET_CQM: u8 = 63;
/// `NL80211_CMD_GET_WOWLAN` / `NL80211_CMD_SET_WOWLAN`.
const GET_WOWLAN: u8 = 73;
const SET_WOWLAN: u8 = 74;
/// `NL80211_CMD_SET_SAR_SPECS` is wiphy-wide, not per-link.
const SET_SAR_SPECS: u8 = 140;
// Userspace-SME MLME command numbers (nl80211_commands).
const AUTHENTICATE: u8 = 37;
const ASSOCIATE: u8 = 38;
const DEAUTHENTICATE: u8 = 39;
const DISASSOCIATE: u8 = 40;
const ASSOC_COMEBACK: u8 = 152;
const ATTR_TIMEOUT: u16 = 248;
const REGISTER_FRAME: u8 = 58;
const FRAME: u8 = 59;
const FRAME_TX_STATUS: u8 = 60;
const EXTERNAL_AUTH: u8 = 127;
const REMAIN_ON_CHANNEL: u8 = 55;
const CANCEL_REMAIN_ON_CHANNEL: u8 = 56;
// Access-Point command numbers (nl80211_commands).
const SET_BEACON: u8 = 14;
const START_AP: u8 = 15;
const STOP_AP: u8 = 16;
const SET_STATION: u8 = 18;
const NEW_STATION: u8 = 19;
const DEL_STATION: u8 = 20;
const CHANNEL_SWITCH: u8 = 107;
const COLOR_CHANGE_REQUEST: u8 = 142;

/// Monotonic cookie source for NL80211_CMD_FRAME transmissions. The cookie
/// returned in the FRAME reply is echoed back in the matching
/// NL80211_CMD_FRAME_TX_STATUS notification.
static FRAME_COOKIE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
/// Cookie source shared by the direct ROC reply and its later ready/expired
/// notifications, as `nl80211_remain_on_channel` does.
static ROC_COOKIE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

struct Cache {
    name: String,
    namespace: u64,
    busy: bool,
    results: Vec<(crate::BssInfo, Vec<u8>)>,
}
static CACHE: IrqSafeSpinLock<Vec<Cache>> = IrqSafeSpinLock::new(Vec::new());

// Clearing on Drop also covers cancellation before the first poll.
struct OperationGuard(String);
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Some(cache) = CACHE.lock().iter_mut().find(|c| c.name == self.0) {
            cache.busy = false;
        }
    }
}

enum Operation {
    Scan(crate::ScanRequest),
    Connect {
        ssid: Vec<u8>,
        bssid: Option<[u8; 6]>,
        frequency_mhz: Option<u32>,
        cred: Credential,
        /// NL80211_ATTR_IE (the SME's association elements).
        ie: Vec<u8>,
        /// The sender, when NL80211_ATTR_SOCKET_OWNER was set.
        owner: Option<u32>,
    },
    Disconnect,
}

/// The authentication/key-management method and its secret, decoded from the
/// nl80211 CONNECT attributes. WPA2-PSK and WPA3-SAE are both firmware/driver
/// offload paths (PMK and password respectively).
enum Credential {
    Open,
    Psk(Zeroizing<[u8; 32]>),
    Sae(Zeroizing<Vec<u8>>),
    /// No PMK / SAE password: the supplicant runs in userspace.
    External(crate::ExternalSecurity),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Akm {
    Open,
    Psk,
    Sae,
    /// Any protected BSS (the supplicant chose the AKM).
    Rsn,
}

impl Credential {
    fn akm(&self) -> Akm {
        match self {
            Credential::Open => Akm::Open,
            Credential::Psk(_) => Akm::Psk,
            Credential::Sae(_) => Akm::Sae,
            Credential::External(_) => Akm::Rsn,
        }
    }
}

/// Reject malformed tails and duplicate attributes, including unknown
/// attributes: ambiguity must not silently select different credentials.
fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, i32> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || result.len() == 128 {
            return Err(EINVAL);
        }
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        if length < 4 || length > bytes.len() || result.iter().any(|(k, _)| *k == kind) {
            return Err(EINVAL);
        }
        result.push((kind, &bytes[4..length]));
        let next = align(length);
        if next > bytes.len() {
            if length != bytes.len() {
                return Err(EINVAL);
            }
            break;
        }
        bytes = &bytes[next..];
    }
    Ok(result)
}

fn attr<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, bytes)| *bytes)
}
fn u32_attr(attrs: &[(u16, &[u8])], kind: u16) -> Result<Option<u32>, i32> {
    attr(attrs, kind)
        .map(|b| Ok(u32::from_ne_bytes(b.try_into().map_err(|_| EINVAL)?)))
        .transpose()
}
fn u64_attr(attrs: &[(u16, &[u8])], kind: u16) -> Result<Option<u64>, i32> {
    attr(attrs, kind)
        .map(|b| Ok(u64::from_ne_bytes(b.try_into().map_err(|_| EINVAL)?)))
        .transpose()
}
fn u16_attr(attrs: &[(u16, &[u8])], kind: u16) -> Result<Option<u16>, i32> {
    attr(attrs, kind)
        .map(|b| Ok(u16::from_ne_bytes(b.try_into().map_err(|_| EINVAL)?)))
        .transpose()
}
fn u8_attr(attrs: &[(u16, &[u8])], kind: u16) -> Result<Option<u8>, i32> {
    attr(attrs, kind)
        .map(|b| {
            b.try_into()
                .map(|bytes: &[u8; 1]| bytes[0])
                .map_err(|_| EINVAL)
        })
        .transpose()
}
fn mac_attr(attrs: &[(u16, &[u8])], kind: u16) -> Result<Option<[u8; 6]>, i32> {
    attr(attrs, kind)
        .map(|b| b.try_into().map_err(|_| EINVAL))
        .transpose()
}
fn channel(frequency: u32) -> Result<u32, i32> {
    match frequency {
        2484 => Ok(14),
        2412..=2472 if (frequency - 2407) % 5 == 0 => Ok((frequency - 2407) / 5),
        5180..=5905 if (frequency - 5000) % 5 == 0 => Ok((frequency - 5000) / 5),
        5935 => Ok(2),
        5955..=7115 if (frequency - 5950) % 5 == 0 => Ok((frequency - 5950) / 5),
        _ => Err(EINVAL),
    }
}

/// `IEEE80211_MAX_DATA_LEN`, the upper netlink policy bound for AP discovery
/// templates. The driver later applies its WMI endpoint's independent frame
/// size limit before submitting the template.
const IEEE80211_MAX_DATA_LEN: usize = 2304;

/// `nl80211_parse_fils_discovery`. An empty nested attribute requests the
/// documented disable/delete form; otherwise all three fields are required.
fn fils_discovery_config(raw: &[u8]) -> Result<Option<crate::FilsDiscoveryConfig>, i32> {
    let attrs = attributes(raw)?;
    if attrs.is_empty() {
        return Ok(None);
    }
    reject_unknown(&attrs, &[1, 2, 3])?;
    let min_interval_tu = u32_attr(&attrs, 1)?.ok_or(EINVAL)?;
    let max_interval_tu = u32_attr(&attrs, 2)?.ok_or(EINVAL)?;
    let template = attr(&attrs, 3).ok_or(EINVAL)?;
    if min_interval_tu > 10_000
        || max_interval_tu > 10_000
        || !(42..=IEEE80211_MAX_DATA_LEN).contains(&template.len())
    {
        return Err(EINVAL);
    }
    Ok(Some(crate::FilsDiscoveryConfig {
        min_interval_tu,
        max_interval_tu,
        template: template.to_vec(),
    }))
}

/// `nl80211_parse_unsol_bcast_probe_resp`, including its empty nested
/// disable/delete request.
fn unsol_bcast_probe_resp_config(
    raw: &[u8],
) -> Result<Option<crate::UnsolBcastProbeRespConfig>, i32> {
    let attrs = attributes(raw)?;
    if attrs.is_empty() {
        return Ok(None);
    }
    reject_unknown(&attrs, &[1, 2])?;
    let interval_tu = u32_attr(&attrs, 1)?.ok_or(EINVAL)?;
    let template = attr(&attrs, 2).ok_or(EINVAL)?;
    if interval_tu > 20 || template.len() > IEEE80211_MAX_DATA_LEN {
        return Err(EINVAL);
    }
    Ok(Some(crate::UnsolBcastProbeRespConfig {
        interval_tu,
        template: template.to_vec(),
    }))
}

/// `nl80211_parse_beacon`'s enabled FTM-responder form. LCI and civic-location
/// Measurement Report bodies are independently optional but u8-bounded.
fn ftm_responder_config(raw: &[u8]) -> Result<crate::FtmResponderConfig, i32> {
    let attrs = attributes(raw)?;
    reject_unknown(&attrs, &[1, 2, 3])?;
    match attr(&attrs, 1) {
        Some([]) => {}
        Some(_) => return Err(EINVAL),
        None => return Err(EOPNOTSUPP),
    }
    let lci = attr(&attrs, 2).unwrap_or(&[]);
    let civicloc = attr(&attrs, 3).unwrap_or(&[]);
    if lci.len() > u8::MAX as usize || civicloc.len() > u8::MAX as usize {
        return Err(EINVAL);
    }
    Ok(crate::FtmResponderConfig {
        lci: lci.to_vec(),
        civicloc: civicloc.to_vec(),
    })
}

/// `nl80211_parse_he_obss_pd`. The bitmaps are copied as native-endian u32
/// words exactly as cfg80211 copies the eight opaque bytes into its in-memory
/// `u32[2]` arrays before ath11k serializes them for WMI.
fn he_obss_pd_config(raw: &[u8]) -> Result<crate::HeObssPdConfig, i32> {
    let attrs = attributes(raw)?;
    reject_unknown(&attrs, &[1, 2, 3, 4, 5, 6])?;
    let offset = |kind| match attr(&attrs, kind) {
        Some(value) if value.len() == 1 && (1..=20).contains(&value[0]) => Ok(value[0]),
        Some(_) => Err(EINVAL),
        None => Ok(0),
    };
    let bitmap = |kind| match attr(&attrs, kind) {
        Some(value) if value.len() == 8 => Ok([
            u32::from_ne_bytes(value[..4].try_into().unwrap()),
            u32::from_ne_bytes(value[4..].try_into().unwrap()),
        ]),
        Some(_) => Err(EINVAL),
        None => Ok([0; 2]),
    };
    let min_offset = offset(1)?;
    let max_offset = offset(2)?;
    if min_offset > max_offset {
        return Err(EINVAL);
    }
    let sr_ctrl = attr(&attrs, 6)
        .filter(|value| value.len() == 1)
        .map(|value| value[0])
        .ok_or(EINVAL)?;
    Ok(crate::HeObssPdConfig {
        min_offset,
        max_offset,
        non_srg_max_offset: offset(3)?,
        bss_color_bitmap: bitmap(4)?,
        partial_bssid_bitmap: bitmap(5)?,
        sr_ctrl,
    })
}

/// `nl80211_parse_he_bss_color`. The color is mandatory even when the
/// DISABLED flag is present; both flag attributes must have an empty payload.
fn he_bss_color_config(raw: &[u8]) -> Result<crate::HeBssColorConfig, i32> {
    let attrs = attributes(raw)?;
    reject_unknown(&attrs, &[1, 2, 3])?;
    let color = attr(&attrs, 1)
        .filter(|color| color.len() == 1)
        .map(|color| color[0])
        .ok_or(EINVAL)?;
    if !(1..=63).contains(&color) {
        return Err(EINVAL);
    }
    let flag = |kind| match attr(&attrs, kind) {
        Some([]) => Ok(true),
        Some(_) => Err(EINVAL),
        None => Ok(false),
    };
    Ok(crate::HeBssColorConfig {
        color,
        disabled: flag(2)?,
        partial: flag(3)?,
    })
}

fn authorized(admin: &narf_net::AdminHandle, iface: &dyn crate::WirelessNetIface, ns: u64) -> bool {
    admin.authorize_interface(iface.name(), ns).is_ok()
}

/// The handle a mutating request acts with on `iface`, or -EPERM.
///
/// A sender that passed the op's Linux permission check
/// ([`RequestContext::capable`]) acts with the kernel-held handle of the
/// interface — the request already resolved it within the sender's own
/// namespace (`nl80211_pre_doit` → `__cfg80211_wdev_from_attrs(sock_net)`).
/// Otherwise the socket's delegated handle must be bound to this interface.
/// Either way the handle stays revocable: a namespace move or interface
/// removal during the asynchronous operation is caught by [`authorized`].
fn authority(
    context: &RequestContext<'_>,
    iface: &dyn crate::WirelessNetIface,
) -> Result<narf_net::AdminHandle, i32> {
    if let Some(admin) = context
        .admin
        .filter(|admin| authorized(admin, iface, context.net_ns_id))
    {
        return Ok(admin.clone());
    }
    if context.capable {
        return narf_net::kernel_admin(iface.name())
            .filter(|admin| authorized(admin, iface, context.net_ns_id))
            .ok_or(ENODEV);
    }
    Err(EPERM)
}

/// Attributes NARF's CONNECT accepts. Beyond the ones that select the
/// network and credential, these are what wpa_supplicant and NetworkManager
/// send on every connect (`nl80211_connect_common`): advisory hints and
/// capability overrides cfg80211 passes to the driver, and the control-port
/// settings an offloading driver already honours. [`connect_side_attrs`]
/// validates them as `nl80211_connect` / `nl80211_crypto_settings` do.
const CONNECT_ATTRS: &[u16] = &[
    3,   // IFINDEX
    6,   // MAC (BSSID)
    31,  // HT_CAPABILITY
    38,  // WIPHY_FREQ
    42,  // IE
    52,  // SSID
    53,  // AUTH_TYPE
    66,  // USE_MFP
    68,  // CONTROL_PORT
    70,  // PRIVACY
    73,  // CIPHER_SUITES_PAIRWISE
    74,  // CIPHER_SUITE_GROUP
    75,  // WPA_VERSIONS
    76,  // AKM_SUITES
    79,  // PREV_BSSID
    102, // CONTROL_PORT_ETHERTYPE
    103, // CONTROL_PORT_NO_ENCRYPT
    148, // HT_CAPABILITY_MASK
    152, // BG_SCAN_PERIOD
    157, // VHT_CAPABILITY
    176, // VHT_CAPABILITY_MASK
    200, // MAC_HINT
    201, // WIPHY_FREQ_HINT
    204, // SOCKET_OWNER
    254, // PMK (PSK 4-way handshake offload)
    261, // EXTERNAL_AUTH_SUPPORT
    264, // CONTROL_PORT_OVER_NL80211
    277, // SAE_PASSWORD (SAE offload)
    286, // CONTROL_PORT_NO_PREAUTH
    298, // SAE_PWE
    315, // MLO_SUPPORT
];

/// `nl80211_connect`'s checks of the advisory attributes. The hints
/// (MAC_HINT, WIPHY_FREQ_HINT, BG_SCAN_PERIOD, PREV_BSSID), the HT/VHT
/// override masks and MLO_SUPPORT only steer driver BSS selection and are
/// not acted on; CONTROL_PORT is what an offloading driver does anyway (no
/// data before the 4-way handshake completes).
fn connect_side_attrs(attrs: &[(u16, &[u8])]) -> Result<(), i32> {
    for kind in [200u16, 79] {
        if attr(attrs, kind).is_some_and(|b| b.len() != 6) {
            return Err(EINVAL);
        }
    }
    if let Some(freq) = u32_attr(attrs, 201)? {
        channel(freq)?;
    }
    // An HT/VHT capability override needs its mask (-EINVAL).
    if attr(attrs, 31).is_some() && attr(attrs, 148).is_none()
        || attr(attrs, 157).is_some() && attr(attrs, 176).is_none()
    {
        return Err(EINVAL);
    }
    // EXTERNAL_AUTH_SUPPORT needs SOCKET_OWNER (-EINVAL).
    if attr(attrs, 261).is_some() && attr(attrs, 204).is_none() {
        return Err(EINVAL);
    }
    Ok(())
}

/// The control-port part of `nl80211_crypto_settings`: without
/// WIPHY_FLAG_CONTROL_PORT_PROTOCOL only ETH_P_PAE (-EINVAL), and
/// CONTROL_PORT_OVER_NL80211 (`validate_pae_over_nl80211`) needs
/// SOCKET_OWNER (-EINVAL) and the ext feature (-EOPNOTSUPP).
fn control_port(attrs: &[(u16, &[u8])], over_nl80211_ok: bool) -> Result<crate::ControlPort, i32> {
    let mut port = crate::ControlPort {
        enabled: attr(attrs, 68).is_some(),
        ..crate::ControlPort::default()
    };
    if let Some(proto) = u16_attr(attrs, 102)? {
        if proto != crate::ETH_P_PAE {
            return Err(EINVAL);
        }
        port.no_encrypt = attr(attrs, 103).is_some();
    }
    if attr(attrs, 264).is_some() {
        if attr(attrs, 204).is_none() {
            return Err(EINVAL);
        }
        if !over_nl80211_ok {
            return Err(EOPNOTSUPP);
        }
        port.over_nl80211 = true;
        port.no_preauth = attr(attrs, 286).is_some();
    }
    Ok(port)
}

/// The ciphers / AKMs of `nl80211_crypto_settings` against the wiphy's
/// cipher suites (`cfg80211_supported_cipher_suite`, -EINVAL). CONNECT has
/// cfg80211's five-suite limit; ASSOCIATE passes one.
fn crypto_suites(attrs: &[(u16, &[u8])], suites: &[u32], cipher_limit: usize) -> Result<(), i32> {
    if let Some(raw) = attr(attrs, 73) {
        if raw.len() % 4 != 0 || raw.len() / 4 > cipher_limit {
            return Err(EINVAL);
        }
        for c in raw.chunks_exact(4) {
            if !suites.contains(&u32::from_ne_bytes(c.try_into().unwrap())) {
                return Err(EINVAL);
            }
        }
    }
    if let Some(group) = u32_attr(attrs, 74)? {
        if !suites.contains(&group) {
            return Err(EINVAL);
        }
    }
    if let Some(raw) = attr(attrs, 76) {
        // NL80211_MAX_NR_AKM_SUITES (max_num_akm_suites default).
        if raw.len() % 4 != 0 || raw.len() / 4 > 2 {
            return Err(EINVAL);
        }
    }
    Ok(())
}

/// The information elements wpa_supplicant puts in a WPA2-PSK CONNECT's
/// NL80211_ATTR_IE: the RSN element it will advertise plus extended
/// capabilities, RSNXE and vendor elements. The offloading driver builds
/// its own RSN element (CCMP, PSK, no MFP), so a requested RSN element must
/// describe exactly that suite; other elements are accepted but not
/// forwarded. A second RSN element, or an MFP-required one, is refused.
fn psk_association_ies(ie: &[u8]) -> Result<(), i32> {
    let ies = elements(ie)?;
    let mut rsn = ies.iter().filter(|(id, _)| *id == 48);
    let Some((_, body)) = rsn.next() else {
        return Ok(());
    };
    if rsn.next().is_some() {
        return Err(EOPNOTSUPP);
    }
    let rsn = crate::rsn::RsnIe::decode_body(body).ok_or(EINVAL)?;
    let ccmp = crate::rsn::Suite::standard(crate::rsn::CIPHER_CCMP_128);
    if rsn.group_cipher != ccmp
        || rsn.pairwise_ciphers != [ccmp]
        || rsn.akms != [crate::rsn::Suite::standard(crate::rsn::AKM_PSK)]
        || rsn.rsn_capabilities & crate::rsn::RSN_CAP_MFP_REQUIRED != 0
    {
        return Err(EOPNOTSUPP);
    }
    Ok(())
}

/// Split an information-element list (`validate_ie_attr`: well-formed
/// element TLVs, else -EINVAL).
fn elements(mut ie: &[u8]) -> Result<Vec<(u8, &[u8])>, i32> {
    let mut out = Vec::new();
    while !ie.is_empty() {
        if ie.len() < 2 || ie.len() < 2 + ie[1] as usize {
            return Err(EINVAL);
        }
        let len = ie[1] as usize;
        out.push((ie[0], &ie[2..2 + len]));
        ie = &ie[2 + len..];
    }
    Ok(out)
}

/// `nl80211_check_scan_flags`: flags that need a wiphy feature NARF never
/// advertises are -EOPNOTSUPP (LOW_PRIORITY and the ext-feature-gated bits
/// 4..=12); FLUSH, AP and COLOCATED_6GHZ need none.  RANDOM_ADDR is accepted
/// only when the physical wiphy exposed its firmware capability.
/// FLUSH is what NARF always does — a scan replaces the cached results.
/// FREQ_KHZ is refused because the frequency list would then be in kHz,
/// which this handler does not decode.
fn scan_flags(flags: u32, random_mac_supported: bool, connected: bool) -> Result<(), i32> {
    const LOW_PRIORITY: u32 = 1 << 0;
    const RANDOM_ADDR: u32 = 1 << 3;
    const FEATURE_GATED: u32 = 0x1ff0; // bits 4..=12
    const FREQ_KHZ: u32 = 1 << 13;
    if flags & (LOW_PRIORITY | FEATURE_GATED | FREQ_KHZ) != 0 {
        return Err(EOPNOTSUPP);
    }
    if flags & RANDOM_ADDR != 0 && (!random_mac_supported || connected) {
        return Err(EOPNOTSUPP);
    }
    Ok(())
}

/// Linux's `nl80211_parse_random_mac`: either both address attributes are
/// supplied or neither is.  The omitted form means fully randomized, except
/// for the locally-administered/unicast bits.  Clearing address bits outside
/// the mask keeps the firmware command independent of userspace sloppiness.
fn scan_random_mac(
    attrs: &[(u16, &[u8])],
    flags: u32,
) -> Result<Option<crate::ScanRandomMac>, i32> {
    const RANDOM_ADDR: u32 = 1 << 3;
    const ATTR_MAC: u16 = 6;
    const ATTR_MAC_MASK: u16 = 215;
    if flags & RANDOM_ADDR == 0 {
        if attr(attrs, ATTR_MAC).is_some() || attr(attrs, ATTR_MAC_MASK).is_some() {
            return Err(EINVAL);
        }
        return Ok(None);
    }
    let (mut addr, mask) = match (attr(attrs, ATTR_MAC), attr(attrs, ATTR_MAC_MASK)) {
        (None, None) => ([0x02, 0, 0, 0, 0, 0], [0x03, 0, 0, 0, 0, 0]),
        (Some(addr), Some(mask)) => (
            addr.try_into().map_err(|_| EINVAL)?,
            mask.try_into().map_err(|_| EINVAL)?,
        ),
        _ => return Err(EINVAL),
    };
    // Never let a scan choose or preserve a multicast source address.
    if mask[0] & 1 == 0 || addr[0] & 1 != 0 {
        return Err(EINVAL);
    }
    for (byte, keep) in addr.iter_mut().zip(mask) {
        *byte &= keep;
    }
    Ok(Some(crate::ScanRandomMac { addr, mask }))
}

/// What a wiphy offers the CONNECT parser.
#[derive(Clone, Copy, Default)]
struct ConnectCaps {
    psk_offload: bool,
    sae_offload: bool,
    external: bool,
    cipher_suites: &'static [u32],
    scan_random_mac: bool,
    connected: bool,
    max_scan_ssids: u8,
    max_scan_ie_len: u16,
}

impl ConnectCaps {
    fn of(iface: &dyn crate::WirelessNetIface) -> Self {
        ConnectCaps {
            psk_offload: iface.supports_handshake_offload(),
            sae_offload: iface.supports_sae_offload(),
            external: iface.supports_external_supplicant(),
            cipher_suites: iface.cipher_suites(),
            scan_random_mac: iface.supports_scan_random_mac(),
            connected: iface.connected_bssid().is_some(),
            max_scan_ssids: iface.max_scan_ssids(),
            max_scan_ie_len: iface.max_scan_ie_len(),
        }
    }
}

#[allow(dead_code)]
fn parse_operation(
    command: u8,
    attrs: &[(u16, &[u8])],
    psk_offload: bool,
    sae_offload: bool,
) -> Result<Operation, i32> {
    parse_operation_caps(
        command,
        attrs,
        ConnectCaps {
            psk_offload,
            sae_offload,
            external: false,
            cipher_suites: &[],
            scan_random_mac: false,
            connected: false,
            max_scan_ssids: 16,
            max_scan_ie_len: 512,
        },
        0,
    )
}

fn parse_operation_caps(
    command: u8,
    attrs: &[(u16, &[u8])],
    caps: ConnectCaps,
    portid: u32,
) -> Result<Operation, i32> {
    let (psk_offload, sae_offload) = (caps.psk_offload, caps.sae_offload);
    let allowed: &[u16] = match command {
        // 158 = NL80211_ATTR_SCAN_FLAGS, 42 = NL80211_ATTR_IE (probe IEs),
        // 221/222 = MEASUREMENT_DURATION / _MANDATORY.
        // 6 = MAC, 215 = MAC_MASK.  They are accepted only together with
        // RANDOM_ADDR, where they configure the randomized probe source.
        SCAN => &[3, 6, 42, 44, 45, 158, 215, 221, 222],
        CONNECT => CONNECT_ATTRS,
        DISCONNECT => &[3, 54],
        _ => return Err(EOPNOTSUPP),
    };
    if attrs.iter().any(|(kind, _)| !allowed.contains(kind)) {
        return Err(EOPNOTSUPP);
    }
    match command {
        SCAN => {
            if attr(attrs, 42).is_some_and(|ie| ie.len() > usize::from(caps.max_scan_ie_len)) {
                return Err(EINVAL);
            }
            let flags = u32_attr(attrs, 158)?.unwrap_or(0);
            scan_flags(flags, caps.scan_random_mac, caps.connected)?;
            let random_mac = scan_random_mac(attrs, flags)?;
            let ssids = attr(attrs, 45)
                .map(attributes)
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(|(_, b)| {
                    if b.len() > 32 {
                        Err(EINVAL)
                    } else {
                        Ok(b.to_vec())
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            let frequencies_mhz = attr(attrs, 44)
                .map(attributes)
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(|(_, b)| {
                    let frequency_mhz = u32::from_ne_bytes(b.try_into().map_err(|_| EINVAL)?);
                    channel(frequency_mhz)?;
                    Ok::<u32, i32>(frequency_mhz)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if ssids.len() > usize::from(caps.max_scan_ssids) || frequencies_mhz.len() > 68 {
                return Err(EINVAL);
            }
            let duration_tu = u16_attr(attrs, 221)?;
            if let Some(mandatory) = attr(attrs, 222) {
                // `NLA_FLAG`: unlike a u8 boolean, the payload is empty.
                if !mandatory.is_empty() {
                    return Err(EINVAL);
                }
            }
            // Presence of at least one SSID (including the empty wildcard)
            // requests active scanning. Preserve directed entries even when
            // a wildcard is also present, for hidden-network discovery.
            let active = !ssids.is_empty();
            Ok(Operation::Scan(crate::ScanRequest {
                ssids,
                frequencies_mhz,
                channels: Vec::new(),
                active,
                random_mac,
                colocated_6ghz: flags & (1 << 14) != 0,
                duration_tu,
                duration_mandatory: duration_tu.is_some() && attr(attrs, 222).is_some(),
                extra_ies: attr(attrs, 42).unwrap_or(&[]).to_vec(),
            }))
        }
        CONNECT => {
            connect_side_attrs(attrs)?;
            let port = control_port(attrs, caps.external)?;
            let ssid = attr(attrs, 52).ok_or(EINVAL)?;
            if ssid.is_empty() || ssid.len() > 32 {
                return Err(EINVAL);
            }
            let bssid: Option<[u8; 6]> = attr(attrs, 6)
                .map(|raw| raw.try_into().map_err(|_| EINVAL))
                .transpose()?;
            if bssid.is_some_and(|b| b[0] & 1 != 0 || b == [0; 6]) {
                return Err(EINVAL);
            }
            let frequency_mhz = u32_attr(attrs, 38)?;
            if let Some(frequency_mhz) = frequency_mhz {
                channel(frequency_mhz)?;
            }
            // 53 = NL80211_ATTR_AUTH_TYPE (0 = OPEN_SYSTEM, 4 = SAE),
            // 66 = NL80211_ATTR_USE_MFP (enum nl80211_mfp: NO 0, REQUIRED 1,
            // OPTIONAL 2). OPTIONAL needs NL80211_EXT_FEATURE_MFP_OPTIONAL,
            // which no NARF wiphy has (mac80211 does not set it either).
            let auth = u32_attr(attrs, 53)?.unwrap_or(0);
            let mfp = u32_attr(attrs, 66)?.unwrap_or(0);
            if mfp > 2 {
                return Err(ERANGE);
            }
            if mfp == 2 {
                return Err(EOPNOTSUPP);
            }
            let suites: &[u32] = if caps.external {
                caps.cipher_suites
            } else if psk_offload || sae_offload {
                &[crate::CIPHER_SUITE_CCMP]
            } else {
                &[]
            };
            crypto_suites(attrs, suites, 5)?;
            // nl80211_crypto_settings: a PMK needs 32 octets and the
            // 4WAY_HANDSHAKE_STA_PSK ext feature, a SAE password the
            // SAE_OFFLOAD ext feature (-EINVAL).
            if let Some(pmk) = attr(attrs, 254) {
                if pmk.len() != 32 || !psk_offload {
                    return Err(EINVAL);
                }
            }
            if attr(attrs, 277).is_some() && !sae_offload {
                return Err(EINVAL);
            }
            // CCMP (00-0F-AC:4) pairwise+group are required for every offload
            // suite this profile accepts.
            let ccmp = u32_attr(attrs, 73)? == Some(0x000fac04)
                && u32_attr(attrs, 74)? == Some(0x000fac04);
            let cred = if let Some(password) = attr(attrs, 277) {
                // WPA3-SAE offload: SAE auth, RSN (WPA2 versions), AKM SAE
                // (00-0F-AC:8), CCMP, and mandatory management-frame protection.
                if !sae_offload
                    || auth != 4
                    || mfp != 1
                    || !ccmp
                    || u32_attr(attrs, 75)? != Some(2)
                    || u32_attr(attrs, 76)? != Some(0x000fac08)
                    || attr(attrs, 254).is_some()
                {
                    return Err(EOPNOTSUPP);
                }
                if password.is_empty() || password.len() > 128 {
                    return Err(EINVAL);
                }
                Credential::Sae(Zeroizing::new(password.to_vec()))
            } else if let Some(pmk) = attr(attrs, 254) {
                // WPA2-PSK offload: OPEN auth, no MFP, AKM PSK (00-0F-AC:2), CCMP.
                if !psk_offload
                    || auth != 0
                    || mfp != 0
                    || !ccmp
                    || u32_attr(attrs, 75)? != Some(2)
                    || u32_attr(attrs, 76)? != Some(0x000fac02)
                {
                    return Err(EOPNOTSUPP);
                }
                if let Some(ie) = attr(attrs, 42) {
                    psk_association_ies(ie)?;
                }
                Credential::Psk(Zeroizing::new(pmk.try_into().map_err(|_| EINVAL)?))
            } else if caps.external
                && (attr(attrs, 70).is_some()
                    || u32_attr(attrs, 75)?.unwrap_or(0) != 0
                    || attr(attrs, 76).is_some()
                    || attr(attrs, 73).is_some()
                    || attr(attrs, 42)
                        .map(elements)
                        .transpose()?
                        .is_some_and(|ies| ies.iter().any(|(id, _)| *id == 48)))
            {
                // No PMK / SAE password on a protected network: the
                // supplicant runs the handshake. Open System only: SAE over
                // CONNECT would need the external-auth flow.
                if auth != 0 {
                    return Err(EOPNOTSUPP);
                }
                Credential::External(crate::ExternalSecurity {
                    use_mfp: mfp == 1,
                    privacy: true,
                    control_port: port,
                })
            } else {
                // Open: no security negotiation, no MFP, no RSN element.
                if auth != 0
                    || mfp != 0
                    || attr(attrs, 70).is_some()
                    || u32_attr(attrs, 75)?.unwrap_or(0) != 0
                    || attr(attrs, 76).is_some()
                    || attr(attrs, 73).is_some()
                    || attr(attrs, 74).is_some()
                    || attr(attrs, 42)
                        .map(elements)
                        .transpose()?
                        .is_some_and(|ies| ies.iter().any(|(id, _)| *id == 48))
                {
                    return Err(EOPNOTSUPP);
                }
                Credential::Open
            };
            if let Some(ie) = attr(attrs, 42) {
                elements(ie)?;
            }
            Ok(Operation::Connect {
                ssid: ssid.to_vec(),
                bssid,
                frequency_mhz,
                cred,
                ie: attr(attrs, 42).unwrap_or(&[]).to_vec(),
                owner: attr(attrs, 204).is_some().then_some(portid),
            })
        }
        DISCONNECT => {
            if attr(attrs, 54).is_some_and(|b| b.len() != 2) {
                return Err(EINVAL);
            }
            // "Reason Code 0 is reserved" (default DEAUTH_LEAVING).
            if u16_attr(attrs, 54)? == Some(0) {
                return Err(EINVAL);
            }
            Ok(Operation::Disconnect)
        }
        _ => Err(EOPNOTSUPP),
    }
}

pub(super) fn handle(
    command: u8,
    bytes: &[u8],
    dump: bool,
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    if matches!(command, NEW_INTERFACE | DEL_INTERFACE) {
        return virtual_interface_handle(command, bytes, context);
    }
    if matches!(command, GET_WOWLAN | SET_WOWLAN) {
        return wowlan_handle(command, bytes, context);
    }
    if command == SET_SAR_SPECS {
        return sar_handle(bytes, context);
    }
    if command == SET_CQM {
        return cqm_handle(bytes, context);
    }
    if command == SET_WIPHY {
        return set_wiphy_handle(bytes, context);
    }
    if command == SET_TX_BITRATE_MASK {
        return bitrate_mask_handle(bytes, context);
    }
    if command == GET_SURVEY {
        return survey_handle(bytes, dump, context.net_ns_id);
    }
    if matches!(command, REMAIN_ON_CHANNEL | CANCEL_REMAIN_ON_CHANNEL) {
        return roc_handle(command, bytes, context);
    }
    if matches!(
        command,
        AUTHENTICATE
            | ASSOCIATE
            | DEAUTHENTICATE
            | DISASSOCIATE
            | REGISTER_FRAME
            | FRAME
            | EXTERNAL_AUTH
    ) {
        return mlme_handle(command, bytes, context);
    }
    if matches!(
        command,
        station::NEW_KEY
            | station::SET_KEY
            | station::DEL_KEY
            | station::SET_PMKSA
            | station::DEL_PMKSA
            | station::FLUSH_PMKSA
            | station::CONTROL_PORT_FRAME
            | station::SET_POWER_SAVE
            | station::GET_POWER_SAVE
            | station::SET_REKEY_OFFLOAD
    ) || command == SET_STATION && station_iface(bytes, context.net_ns_id)
    {
        return station_handle(command, bytes, context);
    }
    if command == station::GET_REG {
        return station::get_reg(bytes, dump, context.net_ns_id);
    }
    if matches!(
        command,
        START_AP
            | STOP_AP
            | SET_BEACON
            | NEW_STATION
            | SET_STATION
            | DEL_STATION
            | CHANNEL_SWITCH
            | COLOR_CHANGE_REQUEST
    ) {
        return ap_handle(command, bytes, context);
    }
    if matches!(command, SET_INTERFACE | GET_STATION) {
        return interface_handle(command, bytes, dump, context);
    }
    if !matches!(command, SCAN | GET_SCAN | CONNECT | DISCONNECT) {
        return super::handle_in(command, bytes, dump, context.net_ns_id);
    }
    let attrs = attributes(bytes)?;
    let index = u32_attr(&attrs, 3)?.ok_or(EINVAL)?;
    let iface = crate::registry::list()
        .into_iter()
        .find(|iface| {
            narf_net::netlink_route::ifindex_for_name(iface.name()) == Some(index)
                && super::in_namespace(iface.as_ref(), context.net_ns_id)
        })
        .ok_or(ENODEV)?;
    if command == GET_SCAN {
        if !dump {
            return Err(EOPNOTSUPP);
        }
        let connected = iface.connected_bssid();
        let cache = CACHE.lock();
        let results = cache
            .iter()
            .find(|c| c.name == iface.name() && c.namespace == context.net_ns_id)
            .map(|c| c.results.as_slice())
            .unwrap_or_default();
        return Ok(results
            .iter()
            .map(|(bss, ies)| scan_reply(index, bss, ies, connected == Some(bss.bssid)))
            .collect());
    }
    if dump {
        return Err(EOPNOTSUPP);
    }
    let admin = authority(&context, iface.as_ref())?;
    if command == DISCONNECT {
        station::check_owner(iface.name(), context.portid)?;
    }
    let operation = parse_operation_caps(
        command,
        &attrs,
        ConnectCaps::of(iface.as_ref()),
        context.portid,
    )?;
    let name = String::from(iface.name());
    {
        let mut caches = CACHE.lock();
        if let Some(cache) = caches.iter_mut().find(|c| c.name == name) {
            if cache.busy {
                return Err(EBUSY);
            }
            if cache.namespace != context.net_ns_id {
                cache.results.clear();
                cache.namespace = context.net_ns_id;
            }
            cache.busy = true;
        } else {
            caches.push(Cache {
                name: name.clone(),
                namespace: context.net_ns_id,
                busy: true,
                results: Vec::new(),
            });
        }
    }
    let guard = OperationGuard(name);
    let namespace = context.net_ns_id;
    match &operation {
        // nl80211_connect: `if (!err && SOCKET_OWNER) conn_owner_nlportid =
        // snd_portid` — before any EAPOL of the association can arrive.
        Operation::Connect {
            owner, cred, bssid, ..
        } => {
            if let Some(portid) = owner {
                station::set_owner(iface.name(), namespace, *portid, *bssid);
            }
            let over = matches!(cred, Credential::External(e) if e.control_port.over_nl80211);
            station::set_control_port(iface.name(), namespace, over);
        }
        // cfg80211_disconnect: the owner goes first.
        Operation::Disconnect => station::clear_owner(iface.name()),
        Operation::Scan(_) => {}
    }
    narf_scheduler::spawn(async move {
        let _guard = guard;
        execute(iface, admin, namespace, index, operation).await;
    });
    Ok(Vec::new()) // generic netlink emits the requested ACK
}

/// `NL80211_CMD_SET_SAR_SPECS` → `set_sar_specs`. The wiphy advertises its
/// fixed frequency ranges in GET_WIPHY; this request only supplies the
/// type, a non-duplicate subset of indices, and their quarter-dBm limits.
/// Like cfg80211, omitted ranges mean no host SAR restriction and every
/// successful request replaces the preceding table.
fn sar_handle(bytes: &[u8], context: RequestContext<'_>) -> Result<Vec<GenlReply>, i32> {
    const ATTR_WIPHY: u16 = 1;
    const ATTR_IFINDEX: u16 = 3;
    const ATTR_WDEV: u16 = 153;
    const ATTR_SAR_SPEC: u16 = 300;
    const SAR_TYPE: u16 = 1;
    const SAR_SPECS: u16 = 2;
    const SAR_POWER: u16 = 1;
    const SAR_RANGE_INDEX: u16 = 2;

    let attrs = attributes(bytes)?;
    reject_unknown(
        &attrs,
        &[ATTR_WIPHY, ATTR_IFINDEX, ATTR_WDEV, ATTR_SAR_SPEC],
    )?;
    let interfaces = crate::registry::list();
    let index = super::wiphy_from_attrs(&interfaces, bytes, context.net_ns_id)? as usize;
    let iface = crate::registry::wiphys()
        .get(index)
        .cloned()
        .ok_or(ENODEV)?;
    let capability = iface.sar_capability().ok_or(EOPNOTSUPP)?;
    let _admin = authority(&context, iface.as_ref())?;

    let sar = attributes(attr(&attrs, ATTR_SAR_SPEC).ok_or(EINVAL)?)?;
    reject_unknown(&sar, &[SAR_TYPE, SAR_SPECS])?;
    let sar_type = u32_attr(&sar, SAR_TYPE)?.ok_or(EINVAL)?;
    if sar_type != capability.sar_type {
        return Err(EINVAL);
    }
    let records = attributes(attr(&sar, SAR_SPECS).ok_or(EINVAL)?)?;
    if records.len() > capability.frequency_ranges.len() {
        return Err(EINVAL);
    }
    let mut limits = Vec::new();
    for (_, raw) in records {
        let record = attributes(raw)?;
        reject_unknown(&record, &[SAR_POWER, SAR_RANGE_INDEX])?;
        let range_index = u32_attr(&record, SAR_RANGE_INDEX)?.ok_or(EINVAL)?;
        let power = attr(&record, SAR_POWER).ok_or(EINVAL).and_then(|raw| {
            let bytes: [u8; 4] = raw.try_into().map_err(|_| EINVAL)?;
            Ok::<i32, i32>(i32::from_ne_bytes(bytes))
        })?;
        if range_index as usize >= capability.frequency_ranges.len()
            || limits
                .iter()
                .any(|limit: &crate::SarPowerLimit| limit.range_index == range_index)
        {
            return Err(EINVAL);
        }
        limits.push(crate::SarPowerLimit {
            range_index,
            power_quarter_dbm: power,
        });
    }
    iface.set_sar_power_limits(&limits)?;
    Ok(Vec::new())
}

/// `NL80211_CMD_SET_WIPHY`'s physical-radio controls used by ath11k.
///
/// Linux accepts a request addressed by wiphy, WDEV, or a sibling ifindex,
/// then applies the resulting pdev chain mask and per-vdev RTS policy across
/// the whole physical radio.  An all-ones antenna request means "all
/// available chains".  ath11k deliberately rejects fragmentation thresholds:
/// target firmware clears the More-Fragments bit, so advertising a functional
/// `set_frag_threshold` would be worse than the Linux-visible EOPNOTSUPP.
fn set_wiphy_handle(bytes: &[u8], context: RequestContext<'_>) -> Result<Vec<GenlReply>, i32> {
    const ATTR_WIPHY: u16 = 1;
    const ATTR_IFINDEX: u16 = 3;
    const ATTR_WDEV: u16 = 153;
    const ATTR_FRAG_THRESHOLD: u16 = 63;
    const ATTR_RTS_THRESHOLD: u16 = 64;
    const ATTR_ANTENNA_TX: u16 = 105;
    const ATTR_ANTENNA_RX: u16 = 106;

    let attrs = attributes(bytes)?;
    reject_unknown(
        &attrs,
        &[
            ATTR_WIPHY,
            ATTR_IFINDEX,
            ATTR_WDEV,
            ATTR_FRAG_THRESHOLD,
            ATTR_RTS_THRESHOLD,
            ATTR_ANTENNA_TX,
            ATTR_ANTENNA_RX,
        ],
    )?;
    let interfaces = crate::registry::list();
    let index = super::wiphy_from_attrs(&interfaces, bytes, context.net_ns_id)? as usize;
    let iface = crate::registry::wiphys()
        .get(index)
        .cloned()
        .ok_or(ENODEV)?;
    let _admin = authority(&context, iface.as_ref())?;

    let tx = u32_attr(&attrs, ATTR_ANTENNA_TX)?;
    let rx = u32_attr(&attrs, ATTR_ANTENNA_RX)?;
    // `nl80211_set_wiphy` changes chains only when userspace supplied the
    // pair. A sole half is accepted and leaves the current masks unchanged.
    if let (Some(mut tx), Some(mut rx)) = (tx, rx) {
        let antennas = iface.antenna_info().ok_or(EOPNOTSUPP)?;
        if tx != u32::MAX && tx & !antennas.available_tx != 0 {
            return Err(EINVAL);
        }
        if rx != u32::MAX && rx & !antennas.available_rx != 0 {
            return Err(EINVAL);
        }
        if tx == u32::MAX {
            tx = antennas.available_tx;
        }
        if rx == u32::MAX {
            rx = antennas.available_rx;
        }
        if tx == 0 || rx == 0 {
            return Err(EINVAL);
        }
        iface.set_antenna(tx, rx)?;
    }

    if let Some(threshold) = u32_attr(&attrs, ATTR_RTS_THRESHOLD)? {
        iface.rts_threshold().ok_or(EOPNOTSUPP)?;
        iface.set_rts_threshold(threshold)?;
    }

    if let Some(threshold) = u32_attr(&attrs, ATTR_FRAG_THRESHOLD)? {
        // cfg80211's common validity bound, before ath11k's explicitly
        // unsupported mac80211 operation. `u32::MAX` is the disabled form.
        if threshold < 256 {
            return Err(EINVAL);
        }
        return Err(EOPNOTSUPP);
    }
    Ok(Vec::new())
}

/// `NL80211_CMD_SET_TX_BITRATE_MASK`: retain the cfg80211 mask in the
/// driver.  The wire layout is deliberately preserved rather than collapsed
/// into one selected rate: ath11k must intersect each PHY family with the
/// active peer when it builds `WMI_PEER_ASSOC_CMDID`.
fn bitrate_mask_handle(bytes: &[u8], context: RequestContext<'_>) -> Result<Vec<GenlReply>, i32> {
    const ATTR_IFINDEX: u16 = 3;
    const ATTR_TX_RATES: u16 = super::NL80211_ATTR_TX_RATES;

    let attrs = attributes(bytes)?;
    reject_unknown(&attrs, &[ATTR_IFINDEX, ATTR_TX_RATES])?;
    let (_, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
    let _admin = authority(&context, iface.as_ref())?;
    if !iface.supports_tx_bitrate_mask() {
        return Err(EOPNOTSUPP);
    }
    let raw = attr(&attrs, ATTR_TX_RATES).ok_or(EINVAL)?;
    iface.set_tx_bitrate_mask(parse_tx_bitrate_mask(raw)?)?;
    Ok(Vec::new())
}

/// Decode `NL80211_ATTR_TX_RATES` into the stable wireless-trait form.
///
/// The outer attribute is indexed directly by `enum nl80211_band`; fields
/// omitted for a band retain cfg80211's automatic/negotiated default.  NARF
/// implements HT/VHT/HE for ath11k, while EHT is intentionally refused until
/// a driver can honour it rather than silently weakening a rate restriction.
fn parse_tx_bitrate_mask(raw: &[u8]) -> Result<crate::TxBitrateMask, i32> {
    const TXRATE_LEGACY: u16 = 1;
    const TXRATE_HT: u16 = 2;
    const TXRATE_VHT: u16 = 3;
    const TXRATE_GI: u16 = 4;
    const TXRATE_HE: u16 = 5;
    const TXRATE_HE_GI: u16 = 6;
    const TXRATE_HE_LTF: u16 = 7;
    const TXRATE_EHT: u16 = 8;
    const TXRATE_EHT_GI: u16 = 9;
    const TXRATE_EHT_LTF: u16 = 10;
    const MAX_SUPP_RATES: usize = 32;
    const HT_MCS_MASK_LEN: usize = 10;
    const MCS_NSS_LEN: usize = 16;

    let mut bands = Vec::new();
    for (band, nested) in attributes(raw)? {
        // Current UAPI band ordinals end at LC=5. Do not turn a future band
        // into a different current one through a lossy u16→u8 conversion.
        if band > 5 {
            return Err(EINVAL);
        }
        let rates = attributes(nested)?;
        reject_unknown(
            &rates,
            &[
                TXRATE_LEGACY,
                TXRATE_HT,
                TXRATE_VHT,
                TXRATE_GI,
                TXRATE_HE,
                TXRATE_HE_GI,
                TXRATE_HE_LTF,
                TXRATE_EHT,
                TXRATE_EHT_GI,
                TXRATE_EHT_LTF,
            ],
        )?;
        if attr(&rates, TXRATE_EHT).is_some()
            || attr(&rates, TXRATE_EHT_GI).is_some()
            || attr(&rates, TXRATE_EHT_LTF).is_some()
        {
            return Err(EOPNOTSUPP);
        }

        let legacy = attr(&rates, TXRATE_LEGACY)
            .map(|value| {
                if value.len() > MAX_SUPP_RATES {
                    Err(EINVAL)
                } else {
                    Ok(value.to_vec())
                }
            })
            .transpose()?;
        let ht_mcs = attr(&rates, TXRATE_HT)
            .map(|value| {
                (value.len() == HT_MCS_MASK_LEN)
                    .then(|| value.to_vec())
                    .ok_or(EINVAL)
            })
            .transpose()?;
        let vht_mcs = attr(&rates, TXRATE_VHT)
            .map(|value| {
                let bytes: [u8; MCS_NSS_LEN] = value.try_into().map_err(|_| EINVAL)?;
                let mut result = [0u16; 8];
                for (index, entry) in result.iter_mut().enumerate() {
                    *entry = u16::from_ne_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
                }
                Ok::<[u16; 8], i32>(result)
            })
            .transpose()?;
        let gi = attr(&rates, TXRATE_GI)
            .map(|value| match value {
                [value @ 0..=2] => Ok(*value),
                _ => Err(EINVAL),
            })
            .transpose()?;
        let he_mcs = attr(&rates, TXRATE_HE)
            .map(|value| {
                let bytes: [u8; MCS_NSS_LEN] = value.try_into().map_err(|_| EINVAL)?;
                let mut result = [0u16; 8];
                for (index, entry) in result.iter_mut().enumerate() {
                    *entry = u16::from_ne_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
                }
                Ok::<[u16; 8], i32>(result)
            })
            .transpose()?;
        let he_gi = attr(&rates, TXRATE_HE_GI)
            .map(|value| match value {
                [value @ 0..=2] => Ok(*value),
                _ => Err(EINVAL),
            })
            .transpose()?;
        let he_ltf = attr(&rates, TXRATE_HE_LTF)
            .map(|value| match value {
                [value @ 0..=2] => Ok(*value),
                _ => Err(EINVAL),
            })
            .transpose()?;
        bands.push(crate::TxBitrateBand {
            band: band as u8,
            legacy,
            ht_mcs,
            vht_mcs,
            gi,
            he_mcs,
            he_gi,
            he_ltf,
        });
    }
    Ok(crate::TxBitrateMask { bands })
}

/// `nl80211_set_cqm` → mac80211's one-threshold or range-based RSSI-list
/// path. ath11k leaves beacon filtering off, so its mac layer samples the
/// associated AP's beacons in software. TX-error CQM remains a separate,
/// unadvertised cfg80211 interface.
fn cqm_handle(bytes: &[u8], context: RequestContext<'_>) -> Result<Vec<GenlReply>, i32> {
    const ATTR_IFINDEX: u16 = 3;
    const ATTR_CQM: u16 = 94;
    const CQM_RSSI_THOLD: u16 = 1;
    const CQM_RSSI_HYST: u16 = 2;

    let attrs = attributes(bytes)?;
    reject_unknown(&attrs, &[ATTR_IFINDEX, ATTR_CQM])?;
    let (_, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
    let _admin = authority(&context, iface.as_ref())?;
    if !iface.supports_cqm_rssi() {
        return Err(EOPNOTSUPP);
    }
    let cqm = attributes(attr(&attrs, ATTR_CQM).ok_or(EINVAL)?)?;
    reject_unknown(&cqm, &[CQM_RSSI_THOLD, CQM_RSSI_HYST])?;
    let thresholds = attr(&cqm, CQM_RSSI_THOLD).ok_or(EINVAL)?;
    let hysteresis = u32_attr(&cqm, CQM_RSSI_HYST)?.ok_or(EINVAL)?;
    if thresholds.len() % 4 != 0 {
        return Err(EINVAL);
    }
    let thresholds: Vec<i32> = thresholds
        .chunks_exact(4)
        .map(|raw| raw.try_into().map(i32::from_ne_bytes).map_err(|_| EINVAL))
        .collect::<Result<_, _>>()?;
    let mut previous = i32::MIN;
    for threshold in &thresholds {
        // This is cfg80211's `thresholds[i] > 0 || thresholds[i] <= prev`.
        if *threshold > 0 || *threshold <= previous {
            return Err(EINVAL);
        }
        previous = *threshold;
    }
    // cfg80211 treats the singleton zero form as an explicit disable. An
    // empty array does likewise; zero in a longer strictly ordered list is a
    // valid upper threshold.
    let config = if thresholds.is_empty() || thresholds.as_slice() == [0] {
        None
    } else {
        if thresholds.len() > 1 && !iface.supports_cqm_rssi_list() {
            return Err(EOPNOTSUPP);
        }
        Some(crate::CqmRssiConfig {
            thresholds_dbm: thresholds,
            hysteresis_db: hysteresis,
        })
    };
    iface.set_cqm_rssi(config)?;
    Ok(Vec::new())
}

/// `nl80211_remain_on_channel` / `_cancel_remain_on_channel`. ath11k turns
/// ROC into a passive one-channel WMI scan, so the direct reply only returns
/// the cookie; the actual on-channel and expiry transitions arrive later as
/// multicast events from the runtime after firmware confirms them.
fn roc_handle(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    let index = u32_attr(&attrs, 3)?.ok_or(EINVAL)?;
    let iface = crate::registry::list()
        .into_iter()
        .find(|iface| {
            narf_net::netlink_route::ifindex_for_name(iface.name()) == Some(index)
                && super::in_namespace(iface.as_ref(), context.net_ns_id)
        })
        .ok_or(ENODEV)?;
    let _admin = authority(&context, iface.as_ref())?;
    station::netdev_up(iface.as_ref())?;
    match command {
        REMAIN_ON_CHANNEL => {
            reject_unknown(&attrs, &[3, 38, 87])?;
            let frequency_mhz = u32_attr(&attrs, 38)?.ok_or(EINVAL)?;
            channel(frequency_mhz)?;
            let duration_ms = u32_attr(&attrs, 87)?.ok_or(EINVAL)?;
            let max = iface.max_remain_on_channel_duration_ms();
            if max == 0 {
                return Err(EOPNOTSUPP);
            }
            if duration_ms == 0 || duration_ms > max {
                return Err(EINVAL);
            }
            let cookie = ROC_COOKIE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            iface
                .remain_on_channel(cookie, frequency_mhz, duration_ms)
                .map_err(mlme_errno)?;
            let mut reply = Vec::new();
            push_attr(&mut reply, 88, &cookie.to_ne_bytes());
            Ok(alloc::vec![GenlReply {
                command: REMAIN_ON_CHANNEL,
                attrs: reply,
            }])
        }
        CANCEL_REMAIN_ON_CHANNEL => {
            reject_unknown(&attrs, &[3, 88])?;
            let cookie = u64_attr(&attrs, 88)?.ok_or(EINVAL)?;
            iface.cancel_remain_on_channel(cookie).map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        _ => Err(EOPNOTSUPP),
    }
}

/// `nl80211_dump_survey`: each reply carries a single nested
/// `NL80211_ATTR_SURVEY_INFO` record. The driver deliberately returns its
/// cached physical-radio counters here and schedules the target refresh on
/// its runtime worker; generic-netlink may itself be running in an executor
/// poll and must not synchronously re-enter WMI completion processing.
fn survey_handle(bytes: &[u8], dump: bool, namespace: u64) -> Result<Vec<GenlReply>, i32> {
    if !dump {
        return Err(EOPNOTSUPP);
    }
    let attrs = attributes(bytes)?;
    reject_unknown(&attrs, &[3])?; // NL80211_ATTR_IFINDEX
    let (ifindex, iface) = netdev_from_attrs(&attrs, namespace)?;
    if !iface.supports_survey() {
        return Err(EOPNOTSUPP);
    }
    Ok(iface
        .survey_info()
        .into_iter()
        .map(|survey| {
            let mut info = Vec::new();
            // enum nl80211_survey_info: FREQUENCY=1, NOISE=2, IN_USE=3,
            // TIME=4, TIME_BUSY=5, TIME_RX=7, TIME_TX=8, PAD=10.
            push_attr(&mut info, 1, &survey.frequency_mhz.to_ne_bytes());
            if let Some(noise) = survey.noise_dbm {
                push_attr(&mut info, 2, &[noise as u8]);
            }
            if survey.in_use {
                push_attr(&mut info, 3, &[]);
            }
            if let Some(time) = survey.time_ms {
                push_attr(&mut info, 4, &time.to_ne_bytes());
            }
            if let Some(time_busy) = survey.time_busy_ms {
                push_attr(&mut info, 5, &time_busy.to_ne_bytes());
            }
            if let Some(time_rx) = survey.time_rx_ms {
                push_attr(&mut info, 7, &time_rx.to_ne_bytes());
            }
            if let Some(time_tx) = survey.time_tx_ms {
                push_attr(&mut info, 8, &time_tx.to_ne_bytes());
            }
            let mut reply = Vec::new();
            push_attr(&mut reply, 3, &ifindex.to_ne_bytes());
            push_attr(
                &mut reply,
                super::NL80211_ATTR_SURVEY_INFO | NLA_F_NESTED,
                &info,
            );
            GenlReply {
                command: super::NL80211_CMD_NEW_SURVEY_RESULTS,
                attrs: reply,
            }
        })
        .collect())
}

/// Does SET_STATION name a station-type interface (the external-supplicant
/// port authorization) rather than an AP's station table?
fn station_iface(bytes: &[u8], namespace: u64) -> bool {
    attributes(bytes)
        .ok()
        .and_then(|attrs| netdev_from_attrs(&attrs, namespace).ok())
        .is_some_and(|(_, iface)| matches!(iface.current_iftype(), 2 | 8))
}

/// The external-supplicant station commands: `nl80211_pre_doit`
/// (NEED_NETDEV / NEED_NETDEV_UP: -EINVAL / -ENODEV / -ENETDOWN), the
/// delegated-handle check for the mutating ones, then the command.
fn station_handle(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    let (_, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
    if command == station::GET_POWER_SAVE {
        return station::power_save(command, iface, &attrs, context.net_ns_id);
    }
    if command != station::SET_POWER_SAVE {
        station::netdev_up(iface.as_ref())?;
    }
    let _admin = authority(&context, iface.as_ref())?;
    match command {
        station::NEW_KEY => station::new_key(iface, &attrs),
        station::SET_KEY => station::set_key(iface, &attrs),
        station::DEL_KEY => station::del_key(iface, &attrs),
        SET_STATION => station::set_station(iface, &attrs),
        station::SET_PMKSA | station::DEL_PMKSA | station::FLUSH_PMKSA => {
            station::pmksa(command, iface.as_ref(), &attrs)
        }
        station::CONTROL_PORT_FRAME => station::tx_control_port(iface, &attrs, &context),
        station::SET_POWER_SAVE => station::power_save(command, iface, &attrs, context.net_ns_id),
        station::SET_REKEY_OFFLOAD => station::set_rekey_offload(iface, &attrs),
        _ => Err(EOPNOTSUPP),
    }
}

/// `NL80211_CMD_GET_WOWLAN` / `NL80211_CMD_SET_WOWLAN`.  Linux owns this
/// configuration per wiphy (not per transient link); NARF's currently
/// single-interface radios map that to their registered station interface.
/// The setting is retained now and consumed by the driver's asynchronous
/// system-suspend handoff later.
fn wowlan_handle(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    const ATTR_WIPHY: u16 = 1;
    const ATTR_WOWLAN_TRIGGERS: u16 = 117;
    let attrs = attributes(bytes)?;
    let interfaces = crate::registry::list();
    let index = super::wiphy_from_attrs(&interfaces, bytes, context.net_ns_id)? as usize;
    let iface = crate::registry::wiphys()
        .get(index)
        .cloned()
        .ok_or(ENODEV)?;
    let support = iface.wowlan_support().ok_or(EOPNOTSUPP)?;
    match command {
        GET_WOWLAN => {
            let mut reply = Vec::new();
            push_attr(&mut reply, ATTR_WIPHY, &(index as u32).to_ne_bytes());
            if let Some(config) = iface.wowlan_config() {
                push_attr(
                    &mut reply,
                    ATTR_WOWLAN_TRIGGERS | NLA_F_NESTED,
                    &wowlan_attrs(&config),
                );
            }
            Ok(alloc::vec![GenlReply {
                command: GET_WOWLAN,
                attrs: reply,
            }])
        }
        SET_WOWLAN => {
            let _admin = authority(&context, iface.as_ref())?;
            let config = attr(&attrs, ATTR_WOWLAN_TRIGGERS)
                .map(|raw| parse_wowlan(raw, support))
                .transpose()?;
            iface.set_wowlan(config)?;
            Ok(Vec::new())
        }
        _ => Err(EOPNOTSUPP),
    }
}

/// Parse `NL80211_ATTR_WOWLAN_TRIGGERS` using the exact trigger subset
/// ath11k advertises.  Unsupported known triggers fail like cfg80211;
/// unknown future attributes remain ignored by the deprecated Linux parser.
fn parse_wowlan(raw: &[u8], support: crate::WowlanSupport) -> Result<crate::WowlanConfig, i32> {
    const ANY: u16 = 1;
    const DISCONNECT: u16 = 2;
    const MAGIC_PACKET: u16 = 3;
    const PACKET_PATTERN: u16 = 4;
    const GTK_REKEY_SUPPORTED: u16 = 5;
    const GTK_REKEY_FAILURE: u16 = 6;
    const EAP_IDENTITY_REQUEST: u16 = 7;
    const FOUR_WAY_HANDSHAKE: u16 = 8;
    const RFKILL_RELEASE: u16 = 9;
    const NET_DETECT: u16 = 17;
    let triggers = attributes(raw)?;
    let mut config = crate::WowlanConfig::default();
    for (kind, value) in triggers {
        match kind {
            ANY | GTK_REKEY_SUPPORTED => return Err(EINVAL),
            DISCONNECT => {
                if !support.disconnect {
                    return Err(EINVAL);
                }
                config.disconnect = true;
            }
            MAGIC_PACKET => {
                if !support.magic_packet {
                    return Err(EINVAL);
                }
                config.magic_packet = true;
            }
            GTK_REKEY_FAILURE => {
                if !support.gtk_rekey_failure {
                    return Err(EINVAL);
                }
                config.gtk_rekey_failure = true;
            }
            PACKET_PATTERN => {
                let patterns = attributes(value)?;
                if patterns.len() > support.max_patterns as usize {
                    return Err(EINVAL);
                }
                for (_, one) in patterns {
                    // `enum nl80211_wowlan_trig_pkt_pattern`: MASK=1,
                    // PATTERN=2, PKT_OFFSET=3.
                    let fields = attributes(one)?;
                    let mask = attr(&fields, 1).ok_or(EINVAL)?;
                    let pattern = attr(&fields, 2).ok_or(EINVAL)?;
                    let offset = u32_attr(&fields, 3)?.unwrap_or(0);
                    if pattern.len() < support.min_pattern_len as usize
                        || pattern.len() > support.max_pattern_len as usize
                        || mask.len() != pattern.len().div_ceil(8)
                        || offset > support.max_packet_offset as u32
                    {
                        return Err(EINVAL);
                    }
                    config.patterns.push(crate::WowlanPattern {
                        mask: mask.to_vec(),
                        pattern: pattern.to_vec(),
                        offset,
                    });
                }
            }
            NET_DETECT => {
                config.net_detect = Some(parse_net_detect(value, support)?);
            }
            // Linux sees these as requests for capabilities ath11k does not
            // advertise, hence -EINVAL rather than silently accepting them.
            EAP_IDENTITY_REQUEST | FOUR_WAY_HANDSHAKE | RFKILL_RELEASE => return Err(EINVAL),
            _ => {}
        }
    }
    Ok(config)
}

/// Decode the scheduled-scan-shaped payload nested in
/// `NL80211_WOWLAN_TRIG_NET_DETECT`.  ath11k consumes it only as the
/// low-power network-list offload configured at suspend time; it deliberately
/// does not expose a general `START_SCHED_SCAN` command.
fn parse_net_detect(
    raw: &[u8],
    support: crate::WowlanSupport,
) -> Result<crate::NetDetectConfig, i32> {
    // These are the nested NL80211_ATTR_* values accepted by
    // nl80211_parse_sched_scan for WoW net-detect. Linux ath11k advertises
    // the PNO 512-byte probe-IE limit even though this WMI layout only has
    // an IE bitmap; retain the bytes for GET_WOWLAN like cfg80211 does.
    const ATTR_MAC: u16 = 6;
    const ATTR_IE: u16 = 42;
    const ATTR_SCAN_FREQUENCIES: u16 = 44;
    const ATTR_SCAN_SSIDS: u16 = 45;
    const ATTR_SCHED_SCAN_INTERVAL: u16 = 119;
    const ATTR_SCHED_SCAN_MATCH: u16 = 132;
    const ATTR_SCAN_FLAGS: u16 = 158;
    const ATTR_MAC_MASK: u16 = 215;
    const ATTR_SCHED_SCAN_DELAY: u16 = 220;
    const ATTR_SCHED_SCAN_PLANS: u16 = 225;
    const MAX_CHANNELS: usize = 60; // WMI_PNO_MAX_NETW_CHANNELS_EX
    const MAX_SSIDS: usize = 16; // WMI_NLO_MAX_SSIDS
    const MAX_PLAN_INTERVAL_SECS: u32 = 7200;
    const MAX_PLAN_ITERATIONS: u32 = 100;

    if support.net_detect_max_match_sets == 0 {
        return Err(EOPNOTSUPP);
    }
    let fields = attributes(raw)?;
    if fields.iter().any(|(kind, _)| {
        ![
            ATTR_MAC,
            ATTR_IE,
            ATTR_SCAN_FREQUENCIES,
            ATTR_SCAN_SSIDS,
            ATTR_SCHED_SCAN_INTERVAL,
            ATTR_SCHED_SCAN_MATCH,
            ATTR_SCAN_FLAGS,
            ATTR_MAC_MASK,
            ATTR_SCHED_SCAN_DELAY,
            ATTR_SCHED_SCAN_PLANS,
        ]
        .contains(kind)
    }) {
        return Err(EOPNOTSUPP);
    }
    let probe_ies = attr(&fields, ATTR_IE).unwrap_or_default();
    if probe_ies.len() > 512 {
        return Err(EINVAL);
    }
    let flags = u32_attr(&fields, ATTR_SCAN_FLAGS)?.unwrap_or(0);
    scan_flags(flags, support.net_detect_random_mac, false)?;
    let random_mac = scan_random_mac(&fields, flags)?;

    let probe_ssids = attr(&fields, ATTR_SCAN_SSIDS)
        .map(attributes)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(|(_, ssid)| (ssid.len() <= 32).then(|| ssid.to_vec()).ok_or(EINVAL))
        .collect::<Result<Vec<_>, _>>()?;
    if probe_ssids.len() > MAX_SSIDS {
        return Err(EINVAL);
    }
    let frequencies_mhz = attr(&fields, ATTR_SCAN_FREQUENCIES)
        .map(attributes)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(|(_, raw)| {
            let frequency = u32::from_ne_bytes(raw.try_into().map_err(|_| EINVAL)?);
            channel(frequency)?;
            Ok::<u32, i32>(frequency)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if frequencies_mhz.len() > MAX_CHANNELS {
        return Err(EINVAL);
    }

    let raw_matches = attr(&fields, ATTR_SCHED_SCAN_MATCH)
        .map(attributes)
        .transpose()?
        .ok_or(EINVAL)?;
    if raw_matches.is_empty() || raw_matches.len() > support.net_detect_max_match_sets as usize {
        return Err(EINVAL);
    }
    let mut matches = Vec::with_capacity(raw_matches.len());
    for (_, raw_match) in raw_matches {
        let one = attributes(raw_match)?;
        if one.iter().any(|(kind, _)| ![1, 2].contains(kind)) {
            // The WMI NLO record has only SSID and absolute RSSI matching.
            return Err(EOPNOTSUPP);
        }
        let ssid = attr(&one, 1).ok_or(EINVAL)?;
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(EINVAL);
        }
        let rssi_threshold_dbm = attr(&one, 2)
            .map(|raw| {
                let bytes: [u8; 4] = raw.try_into().map_err(|_| EINVAL)?;
                Ok::<i32, i32>(i32::from_ne_bytes(bytes))
            })
            .transpose()?;
        matches.push(crate::NetDetectMatch {
            ssid: ssid.to_vec(),
            rssi_threshold_dbm,
        });
    }

    let plans = match (
        attr(&fields, ATTR_SCHED_SCAN_PLANS),
        attr(&fields, ATTR_SCHED_SCAN_INTERVAL),
    ) {
        (Some(_), Some(_)) => return Err(EINVAL),
        (Some(raw_plans), None) => {
            let raw_plans = attributes(raw_plans)?;
            if raw_plans.is_empty() || raw_plans.len() > 2 {
                return Err(EINVAL);
            }
            let last = raw_plans.len() - 1;
            let mut plans = Vec::with_capacity(raw_plans.len());
            for (index, (_, raw_plan)) in raw_plans.into_iter().enumerate() {
                let plan = attributes(raw_plan)?;
                if plan.iter().any(|(kind, _)| ![1, 2].contains(kind)) {
                    return Err(EOPNOTSUPP);
                }
                let interval_secs = u32_attr(&plan, 1)?.ok_or(EINVAL)?;
                if interval_secs == 0 || interval_secs > MAX_PLAN_INTERVAL_SECS {
                    return Err(EINVAL);
                }
                let iterations = u32_attr(&plan, 2)?;
                if index == last {
                    if iterations.is_some() {
                        return Err(EINVAL);
                    }
                } else if !matches!(iterations, Some(1..=MAX_PLAN_ITERATIONS)) {
                    return Err(EINVAL);
                }
                plans.push(crate::NetDetectScanPlan {
                    interval_secs,
                    iterations,
                });
            }
            plans
        }
        (None, Some(raw_interval)) => {
            let interval_ms = u32::from_ne_bytes(raw_interval.try_into().map_err(|_| EINVAL)?);
            if interval_ms == 0 {
                return Err(EINVAL);
            }
            // cfg80211 rounds this legacy milliseconds value up to whole
            // seconds before passing it to ath11k's PNO converter.
            let interval_secs = interval_ms.div_ceil(1000).min(MAX_PLAN_INTERVAL_SECS);
            alloc::vec![crate::NetDetectScanPlan {
                interval_secs,
                iterations: None,
            }]
        }
        (None, None) => return Err(EINVAL),
    };
    let delay_secs = u32_attr(&fields, ATTR_SCHED_SCAN_DELAY)?.unwrap_or(0);
    Ok(crate::NetDetectConfig {
        probe_ssids,
        frequencies_mhz,
        probe_ies: probe_ies.to_vec(),
        matches,
        plans,
        delay_secs,
        random_mac,
    })
}

/// Encode a retained `cfg80211_wowlan` for GET_WOWLAN.  Packet-pattern
/// masks stay bit-packed at the nl80211 boundary; only ath11k's WMI builder
/// expands them to byte masks.
fn wowlan_attrs(config: &crate::WowlanConfig) -> Vec<u8> {
    const DISCONNECT: u16 = 2;
    const MAGIC_PACKET: u16 = 3;
    const PACKET_PATTERN: u16 = 4;
    const GTK_REKEY_FAILURE: u16 = 6;
    const NET_DETECT: u16 = 17;
    let mut out = Vec::new();
    if config.disconnect {
        push_attr(&mut out, DISCONNECT, &[]);
    }
    if config.magic_packet {
        push_attr(&mut out, MAGIC_PACKET, &[]);
    }
    if config.gtk_rekey_failure {
        push_attr(&mut out, GTK_REKEY_FAILURE, &[]);
    }
    if !config.patterns.is_empty() {
        let mut list = Vec::new();
        for (index, pattern) in config.patterns.iter().enumerate() {
            let mut one = Vec::new();
            push_attr(&mut one, 1, &pattern.mask);
            push_attr(&mut one, 2, &pattern.pattern);
            if pattern.offset != 0 {
                push_attr(&mut one, 3, &pattern.offset.to_ne_bytes());
            }
            push_attr(&mut list, (index as u16 + 1) | NLA_F_NESTED, &one);
        }
        push_attr(&mut out, PACKET_PATTERN | NLA_F_NESTED, &list);
    }
    if let Some(net_detect) = config.net_detect.as_ref() {
        let mut nested = Vec::new();
        if !net_detect.probe_ssids.is_empty() {
            let mut ssids = Vec::new();
            for (index, ssid) in net_detect.probe_ssids.iter().enumerate() {
                push_attr(&mut ssids, index as u16 + 1, ssid);
            }
            push_attr(&mut nested, 45 | NLA_F_NESTED, &ssids);
        }
        if !net_detect.frequencies_mhz.is_empty() {
            let mut frequencies = Vec::new();
            for (index, frequency) in net_detect.frequencies_mhz.iter().enumerate() {
                push_attr(&mut frequencies, index as u16 + 1, &frequency.to_ne_bytes());
            }
            push_attr(&mut nested, 44 | NLA_F_NESTED, &frequencies);
        }
        if !net_detect.probe_ies.is_empty() {
            push_attr(&mut nested, 42, &net_detect.probe_ies);
        }
        let mut matches = Vec::new();
        for (index, matched) in net_detect.matches.iter().enumerate() {
            let mut one = Vec::new();
            push_attr(&mut one, 1, &matched.ssid);
            if let Some(rssi) = matched.rssi_threshold_dbm {
                push_attr(&mut one, 2, &rssi.to_ne_bytes());
            }
            push_attr(&mut matches, (index as u16 + 1) | NLA_F_NESTED, &one);
        }
        push_attr(&mut nested, 132 | NLA_F_NESTED, &matches);
        let mut plans = Vec::new();
        for (index, plan) in net_detect.plans.iter().enumerate() {
            let mut one = Vec::new();
            push_attr(&mut one, 1, &plan.interval_secs.to_ne_bytes());
            if let Some(iterations) = plan.iterations {
                push_attr(&mut one, 2, &iterations.to_ne_bytes());
            }
            push_attr(&mut plans, (index as u16 + 1) | NLA_F_NESTED, &one);
        }
        push_attr(&mut nested, 225 | NLA_F_NESTED, &plans);
        if net_detect.delay_secs != 0 {
            push_attr(&mut nested, 220, &net_detect.delay_secs.to_ne_bytes());
        }
        if let Some(random_mac) = net_detect.random_mac {
            push_attr(&mut nested, 158, &(1u32 << 3).to_ne_bytes());
            push_attr(&mut nested, 6, &random_mac.addr);
            push_attr(&mut nested, 215, &random_mac.mask);
        }
        push_attr(&mut out, NET_DETECT | NLA_F_NESTED, &nested);
    }
    out
}

/// The netdev a request names by NL80211_ATTR_IFINDEX in the sender's
/// namespace (`nl80211_pre_doit` with NEED_NETDEV): missing -EINVAL, not a
/// wireless netdev of this namespace -ENODEV.
fn netdev_from_attrs(
    attrs: &[(u16, &[u8])],
    namespace: u64,
) -> Result<(u32, Arc<dyn crate::WirelessNetIface>), i32> {
    let index = u32_attr(attrs, 3)?.ok_or(EINVAL)?;
    let iface = crate::registry::list()
        .into_iter()
        .find(|iface| {
            narf_net::netlink_route::ifindex_for_name(iface.name()) == Some(index)
                && super::in_namespace(iface.as_ref(), namespace)
        })
        .ok_or(ENODEV)?;
    Ok((index, iface))
}

/// `NL80211_CMD_NEW_INTERFACE` / `NL80211_CMD_DEL_INTERFACE`.  Creation is
/// addressed to the physical wiphy, while deletion is addressed to a
/// concrete netdev.  This is deliberately separate from SET_INTERFACE:
/// changing a down vdev's role does not allocate another firmware slot.
fn virtual_interface_handle(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    match command {
        NEW_INTERFACE => {
            if attrs.iter().any(|(kind, _)| ![1, 4, 5, 6].contains(kind)) {
                return Err(EOPNOTSUPP);
            }
            let wiphy = u32_attr(&attrs, 1)?.ok_or(EINVAL)?;
            let raw_name = attr(&attrs, 4).ok_or(EINVAL)?;
            let raw_name = raw_name.strip_suffix(&[0]).unwrap_or(raw_name);
            let name = core::str::from_utf8(raw_name).map_err(|_| EINVAL)?;
            if name.is_empty()
                || name.len() > 15 // IFNAMSIZ - 1
                || raw_name.contains(&0)
            {
                return Err(EINVAL);
            }
            if narf_net::iface::lookup(name).is_some()
                || crate::registry::list()
                    .iter()
                    .any(|iface| iface.name() == name)
            {
                return Err(EEXIST);
            }
            let iftype = u32_attr(&attrs, 5)?.ok_or(EINVAL)?;
            if !matches!(iftype, 2 | 3 | 8 | 9 | 10) {
                return Err(EOPNOTSUPP);
            }
            let mac = mac_attr(&attrs, 6)?;
            if mac.is_some_and(|mac| mac == [0; 6] || mac[0] & 1 != 0) {
                return Err(EINVAL);
            }
            let radio = crate::registry::wiphys()
                .into_iter()
                .find(|iface| crate::registry::wiphy_index(iface.wiphy_id()) == Some(wiphy))
                .filter(|iface| super::in_namespace(iface.as_ref(), context.net_ns_id))
                .ok_or(ENODEV)?;
            let _admin = authority(&context, radio.as_ref())?;
            if !radio.supports_virtual_interfaces() {
                return Err(EOPNOTSUPP);
            }
            let iface = radio
                .new_virtual_interface(name, iftype, mac)
                .map_err(virtual_interface_errno)?;
            let actual_wiphy = crate::registry::wiphy_index(iface.wiphy_id()).ok_or(ENODEV)?;
            Ok(alloc::vec![GenlReply {
                command: NEW_INTERFACE,
                attrs: super::interface_attrs(actual_wiphy, iface.as_ref(), iface.current_iftype(),),
            }])
        }
        DEL_INTERFACE => {
            if attrs.iter().any(|(kind, _)| *kind != 3) {
                return Err(EOPNOTSUPP);
            }
            let (_ifindex, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
            let _admin = authority(&context, iface.as_ref())?;
            iface
                .delete_virtual_interface()
                .map_err(virtual_interface_errno)?;
            station::unregister_wdev(iface.name());
            CACHE.lock().retain(|cache| cache.name != iface.name());
            Ok(Vec::new())
        }
        _ => Err(EOPNOTSUPP),
    }
}

fn virtual_interface_errno(error: crate::WirelessError) -> i32 {
    match error {
        crate::WirelessError::InvalidArgs => EINVAL,
        crate::WirelessError::Busy => EBUSY,
        crate::WirelessError::Denied => EPERM,
        crate::WirelessError::NotSupported => EOPNOTSUPP,
        crate::WirelessError::Timeout | crate::WirelessError::HardwareError => ENODEV,
    }
}

/// NL80211_CMD_SET_INTERFACE and NL80211_CMD_GET_STATION.
///
/// SET_INTERFACE (`nl80211_set_interface`): the IFTYPE policy (> MAX is
/// -EINVAL) runs before the device lookup; MESH_ID on a non-mesh type and
/// MNTR_FLAGS on a non-monitor type are -EINVAL; four-address station mode
/// follows cfg80211's `nl80211_valid_4addr` policy; any unsupported real type
/// change is -EOPNOTSUPP. A driver may implement a down-only type change;
/// setting the current type remains a successful no-op, which is what
/// wpa_supplicant's `nl80211_set_mode(STATION)` does at startup.
///
/// GET_STATION (`nl80211_get_station` / `nl80211_dump_station`): a station
/// interface has one station (its AP), while an AP/GO exposes every associated
/// client. A do needs NL80211_ATTR_MAC (-EINVAL) and is -ENOENT for an absent
/// peer. STA_INFO carries only what NARF has observed; AP-client PPDU
/// telemetry is optional and may therefore be empty.
fn interface_handle(
    command: u8,
    bytes: &[u8],
    dump: bool,
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    match command {
        SET_INTERFACE => {
            const NL80211_IFTYPE_MAX: u32 = 12;
            let iftype = u32_attr(&attrs, 5)?;
            if iftype.is_some_and(|t| t > NL80211_IFTYPE_MAX) {
                return Err(EINVAL);
            }
            let (_, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
            let _admin = authority(&context, iface.as_ref())?;
            let current = iface.current_iftype();
            let new = iftype.unwrap_or(current);
            // NL80211_ATTR_MESH_ID needs a mesh point on both sides.
            const MESH_POINT: u32 = 7;
            if attr(&attrs, 24).is_some() && (new != MESH_POINT || current != MESH_POINT) {
                return Err(EINVAL);
            }
            // `NL80211_ATTR_4ADDR` is NLA_U8. Enabling it needs
            // WIPHY_FLAG_4ADDR_STATION (`nl80211_valid_4addr`); disabling
            // is accepted for every interface type by cfg80211 (apart from
            // its bridge-port check, which NARF's net stack does not model).
            let four_addr = u8_attr(&attrs, 83)?;
            if four_addr.is_some_and(|enabled| enabled != 0)
                && (new != 2 || !iface.supports_four_addr_station())
            {
                return Err(EOPNOTSUPP);
            }
            // NL80211_ATTR_MNTR_FLAGS needs a monitor interface.
            const MONITOR: u32 = 6;
            if attr(&attrs, 23).is_some() && new != MONITOR {
                return Err(EINVAL);
            }
            if new != current {
                iface.set_iftype(new).map_err(mlme_errno)?;
            }
            if let Some(enabled) = four_addr {
                // A supported station owns the retained state. A clear on a
                // different interface type is cfg80211's harmless no-op.
                if iface.current_iftype() == 2 && iface.supports_four_addr_station() {
                    iface.set_four_addr(enabled != 0)?;
                }
            }
            Ok(Vec::new())
        }
        GET_STATION => {
            let (index, iface) = netdev_from_attrs(&attrs, context.net_ns_id)?;
            let wanted = if dump {
                None
            } else {
                Some(mac_attr(&attrs, 6)?.ok_or(EINVAL)?)
            };
            let ap = matches!(iface.current_iftype(), 3 | 9);
            let peers = if ap {
                match wanted {
                    Some(peer) if iface.ap_station_info(peer).is_some() => alloc::vec![peer],
                    Some(_) => return Err(ENOENT),
                    None => iface.ap_station_macs(),
                }
            } else {
                let peer = iface.connected_bssid();
                let Some(peer) = peer.filter(|peer| wanted.is_none_or(|w| w == *peer)) else {
                    return if dump { Ok(Vec::new()) } else { Err(ENOENT) };
                };
                alloc::vec![peer]
            };
            let mut replies = Vec::new();
            for peer in peers {
                // A client can leave after a dump snapshot. Omit that stale
                // element; a direct query rechecks it above and returns
                // ENOENT instead.
                let tracked = if ap {
                    match iface.ap_station_info(peer) {
                        Some(info) => info,
                        None if dump => continue,
                        None => return Err(ENOENT),
                    }
                } else {
                    iface.station_info().unwrap_or_default()
                };
                let signal = (!ap)
                    .then(|| {
                        CACHE
                            .lock()
                            .iter()
                            .find(|c| c.name == iface.name() && c.namespace == context.net_ns_id)
                            .and_then(|c| c.results.iter().find(|(bss, _)| bss.bssid == peer))
                            .map(|(bss, _)| bss.rssi)
                    })
                    .flatten();
                let mut info = Vec::new();
                // The driver's last-frame signal, else the AP's scan record.
                if let Some(signal) = tracked.signal_dbm.or(signal) {
                    push_attr(&mut info, 7, &[signal as u8]); // NL80211_STA_INFO_SIGNAL
                }
                sta_info_attrs(&mut info, &tracked);
                let mut attrs = Vec::new();
                push_attr(&mut attrs, 3, &index.to_ne_bytes());
                push_attr(&mut attrs, 6, &peer);
                push_attr(&mut attrs, 46, &0u32.to_ne_bytes()); // NL80211_ATTR_GENERATION
                push_attr(&mut attrs, 21 | NLA_F_NESTED, &info); // NL80211_ATTR_STA_INFO
                replies.push(GenlReply {
                    command: NEW_STATION,
                    attrs,
                });
            }
            Ok(replies)
        }
        _ => Err(EOPNOTSUPP),
    }
}

/// `nl80211_put_sta_rate`: BITRATE (u16, when it fits), BITRATE32, then
/// the MCS / width / GI attributes of the rate's kind.
fn put_sta_rate(out: &mut Vec<u8>, kind: u16, r: &crate::RateInfo) {
    let mut rate = Vec::new();
    if r.bitrate_100kbps > 0 {
        if r.bitrate_100kbps <= u16::MAX as u32 {
            push_attr(&mut rate, 1, &(r.bitrate_100kbps as u16).to_ne_bytes());
        }
        push_attr(&mut rate, 5, &r.bitrate_100kbps.to_ne_bytes());
    }
    // Linux represents an HE OFDMA rate by HE_RU_ALLOC rather than the
    // channel-width attributes: an RU's physical bandwidth is not a full
    // channel width. Keep the two encodings mutually exclusive.
    if r.he_ru_alloc.is_none() {
        match r.width_mhz {
            40 => push_attr(&mut rate, 3, &[]),
            80 => push_attr(&mut rate, 8, &[]),
            160 => push_attr(&mut rate, 9, &[]),
            _ => {}
        }
    }
    if let Some(mcs) = r.ht_mcs {
        push_attr(&mut rate, 2, &[mcs]);
        if r.short_gi {
            push_attr(&mut rate, 4, &[]);
        }
    } else if let Some((mcs, nss)) = r.vht_mcs {
        push_attr(&mut rate, 6, &[mcs]);
        push_attr(&mut rate, 7, &[nss]);
        if r.short_gi {
            push_attr(&mut rate, 4, &[]);
        }
    } else if let Some((mcs, nss, gi)) = r.he_mcs {
        push_attr(&mut rate, 13, &[mcs]);
        push_attr(&mut rate, 14, &[nss]);
        push_attr(&mut rate, 15, &[gi]);
        // `nl80211_put_sta_rate` always writes HE_DCM, including its
        // explicit zero value, whenever the rate is HE.
        push_attr(&mut rate, 16, &[r.he_dcm as u8]);
        if let Some(ru) = r.he_ru_alloc {
            push_attr(&mut rate, 17, &[ru]);
        }
    }
    push_attr(out, kind | NLA_F_NESTED, &rate);
}

/// The STA_INFO members a driver tracks (`nl80211_send_station`).
fn sta_info_attrs(info: &mut Vec<u8>, s: &crate::StationInfo) {
    if let Some(v) = s.rx_packets {
        push_attr(info, 9, &v.to_ne_bytes());
    }
    if let Some(v) = s.tx_packets {
        push_attr(info, 10, &v.to_ne_bytes());
    }
    if let Some(v) = s.tx_retries {
        push_attr(info, 11, &v.to_ne_bytes());
    }
    if let Some(v) = s.tx_failed {
        push_attr(info, 12, &v.to_ne_bytes());
    }
    if let Some(v) = s.signal_avg_dbm {
        push_attr(info, 13, &[v as u8]);
    }
    let mut chain_signal = Vec::new();
    for (chain, signal) in s.chain_signal_dbm.iter().enumerate() {
        if let Some(signal) = signal {
            // `NL80211_STA_INFO_CHAIN_SIGNAL` is a nested indexed array;
            // `nl80211_put_signal` emits the physical chain's zero-based
            // index as the nested attribute type.
            push_attr(&mut chain_signal, chain as u16, &[*signal as u8]);
        }
    }
    if !chain_signal.is_empty() {
        push_attr(info, 25 | NLA_F_NESTED, &chain_signal);
    }
    if let Some(r) = s.tx_bitrate.as_ref() {
        put_sta_rate(info, 8, r);
    }
    if let Some(r) = s.rx_bitrate.as_ref() {
        put_sta_rate(info, 14, r);
    }
    if let Some(v) = s.ack_signal_dbm {
        push_attr(info, 34, &[v as u8]);
    }
    if let Some(v) = s.tx_duration_us {
        // `NL80211_STA_INFO_TX_DURATION` is a native-endian u64 in usec.
        // The generic netlink writer already 4-byte-aligns attributes; like
        // the existing COOKIE/WDEV u64 attributes, consumers must not assume
        // stronger in-packet alignment than netlink promises.
        push_attr(info, 39, &v.to_ne_bytes());
    }
    if let Some(v) = s.rx_duration_us {
        // `NL80211_STA_INFO_RX_DURATION` is a native-endian u64 in usec.
        push_attr(info, 32, &v.to_ne_bytes());
    }
}

/// Reject any attribute outside the per-command allowlist, so an ambiguous or
/// unhandled parameter never silently changes the request (matches the CONNECT
/// path and `nl80211`'s strict per-op attribute policy).
fn reject_unknown(attrs: &[(u16, &[u8])], allowed: &[u16]) -> Result<(), i32> {
    if attrs.iter().any(|(kind, _)| !allowed.contains(kind)) {
        Err(EOPNOTSUPP)
    } else {
        Ok(())
    }
}

/// A unicast peer/BSSID address: present, individual (not group), non-zero.
fn require_peer(attrs: &[(u16, &[u8])]) -> Result<[u8; 6], i32> {
    let peer = mac_attr(attrs, 6)?.ok_or(EINVAL)?;
    if peer[0] & 1 != 0 || peer == [0; 6] {
        return Err(EINVAL);
    }
    Ok(peer)
}

fn mlme_errno(err: crate::WirelessError) -> i32 {
    match err {
        crate::WirelessError::InvalidArgs => EINVAL,
        crate::WirelessError::Busy => EBUSY,
        crate::WirelessError::Denied => EPERM,
        _ => EOPNOTSUPP,
    }
}

/// Publish an MLME notification carrying the exchanged management frame
/// (NL80211_ATTR_FRAME) on the `mlme` multicast group, as cfg80211 does for
/// the authenticate/associate/deauthenticate/disassociate events.
fn publish_mlme_frame(
    iface: &dyn crate::WirelessNetIface,
    ns: u64,
    index: u32,
    command: u8,
    frame: &[u8],
) {
    publish_mlme_frame_ie(iface, ns, index, command, frame, &[]);
}

/// `nl80211_send_mlme_event`: WIPHY, IFINDEX, FRAME, REQ_IE (when given).
fn publish_mlme_frame_ie(
    iface: &dyn crate::WirelessNetIface,
    ns: u64,
    index: u32,
    command: u8,
    frame: &[u8],
    req_ie: &[u8],
) {
    if !super::in_namespace(iface, ns) {
        return;
    }
    let mut attrs = Vec::new();
    if let Some(wiphy) = wiphy_index(iface) {
        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    }
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    push_attr(&mut attrs, 51, frame); // NL80211_ATTR_FRAME
    if !req_ie.is_empty() {
        push_attr(&mut attrs, 77, req_ie); // NL80211_ATTR_REQ_IE
    }
    publish_event(NL80211_FAMILY_ID, 19, ns, GenlReply { command, attrs });
}

/// The `WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY` (30) / Timeout Interval
/// element combination for `WLAN_TIMEOUT_ASSOC_COMEBACK` (3).  The generic
/// nl80211 layer cannot depend on a particular driver's management parser,
/// so it validates the fixed Association/Reassociation Response layout here.
fn assoc_comeback_tu(frame: &[u8]) -> Option<u32> {
    if frame.len() < 30
        || !matches!(frame[0] & 0xfc, 0x10 | 0x30)
        || u16::from_le_bytes([frame[26], frame[27]]) != 30
    {
        return None;
    }
    let mut pos = 30;
    while pos + 2 <= frame.len() {
        let id = frame[pos];
        let len = usize::from(frame[pos + 1]);
        let end = pos.checked_add(2 + len)?;
        if end > frame.len() {
            return None;
        }
        if id == 56 && len == 5 && frame[pos + 2] == 3 {
            return Some(u32::from_le_bytes([
                frame[pos + 3],
                frame[pos + 4],
                frame[pos + 5],
                frame[pos + 6],
            ]));
        }
        pos = end;
    }
    None
}

/// `cfg80211_assoc_comeback`: signal a temporary association rejection to a
/// userspace SME.  Linux places the AP's Timeout Interval value in TUs,
/// rather than converting this netlink attribute to milliseconds.
fn publish_assoc_comeback(
    iface: &dyn crate::WirelessNetIface,
    ns: u64,
    index: u32,
    peer: [u8; 6],
    timeout_tu: u32,
) {
    if !super::in_namespace(iface, ns) {
        return;
    }
    let mut attrs = Vec::new();
    if let Some(wiphy) = wiphy_index(iface) {
        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes()); // NL80211_ATTR_WIPHY
    }
    push_attr(&mut attrs, 3, &index.to_ne_bytes()); // NL80211_ATTR_IFINDEX
    push_attr(&mut attrs, 6, &peer); // NL80211_ATTR_MAC
    push_attr(&mut attrs, ATTR_TIMEOUT, &timeout_tu.to_ne_bytes());
    // NL80211_ATTR_TIMEOUT
    publish_event(
        NL80211_FAMILY_ID,
        19,
        ns,
        GenlReply {
            command: ASSOC_COMEBACK,
            attrs,
        },
    );
}

/// A validated userspace-SME frame exchange, run asynchronously off the
/// `mlme_handle` dispatch (split out so the resulting event is exercisable
/// directly, as `execute` is for CONNECT/SCAN).
enum MlmeExec {
    Authenticate(crate::MlmeAuthRequest),
    Associate(crate::MlmeAssocRequest),
    Deauthenticate {
        peer: [u8; 6],
        reason: u16,
    },
    Disassociate {
        peer: [u8; 6],
        reason: u16,
    },
    MgmtTx {
        cookie: u64,
        request: crate::MgmtTxRequest,
    },
    ExternalAuth {
        bssid: [u8; 6],
        status: u16,
    },
}

async fn run_mlme(iface: Arc<dyn crate::WirelessNetIface>, ns: u64, index: u32, exec: MlmeExec) {
    match exec {
        MlmeExec::Authenticate(request) => {
            let peer = request.peer;
            match iface.mlme_authenticate(request).await {
                // cfg80211_rx_mlme_mgmt → nl80211_send_rx_auth.
                Ok(frame) => publish_mlme_frame(iface.as_ref(), ns, index, AUTHENTICATE, &frame),
                // cfg80211_auth_timeout.
                Err(crate::WirelessError::Timeout) => {
                    publish_mlme_timeout(iface.as_ref(), ns, index, AUTHENTICATE, peer)
                }
                Err(_) => {}
            }
        }
        MlmeExec::Associate(request) => {
            let peer = request.peer;
            let req_ie = request.ie.clone();
            match iface.mlme_associate(request).await {
                // cfg80211_rx_assoc_resp: the frame (+ REQ_IE), then the
                // connect result from its status code.
                Ok(frame) => {
                    publish_mlme_frame_ie(iface.as_ref(), ns, index, ASSOCIATE, &frame, &req_ie);
                    let status = frame
                        .get(26..28)
                        .map_or(1, |s| u16::from_le_bytes([s[0], s[1]]));
                    let resp_ie = frame.get(30..).unwrap_or(&[]);
                    if let Some(timeout_tu) = assoc_comeback_tu(&frame) {
                        publish_assoc_comeback(iface.as_ref(), ns, index, peer, timeout_tu);
                    } else {
                        if status != 0 {
                            station::clear_owner(iface.name());
                        }
                        publish_connect_result(
                            iface.as_ref(),
                            ns,
                            index,
                            peer,
                            status,
                            &req_ie,
                            resp_ie,
                        );
                    }
                }
                Err(crate::WirelessError::Timeout) => {
                    publish_mlme_timeout(iface.as_ref(), ns, index, ASSOCIATE, peer)
                }
                // cfg80211_abandon_assoc: no event.
                Err(_) => {}
            }
        }
        MlmeExec::Deauthenticate { peer, reason } => {
            // A driver that reports its own disconnects emits the
            // DEAUTHENTICATE + DISCONNECT pair of its teardown
            // ([`station::notify_mlme_disconnect`]) itself.
            if let Ok(frame) = iface.mlme_deauthenticate(peer, reason).await {
                if !iface.reports_disconnect_events() {
                    publish_mlme_frame(iface.as_ref(), ns, index, DEAUTHENTICATE, &frame);
                }
            }
        }
        MlmeExec::Disassociate { peer, reason } => {
            if let Ok(frame) = iface.mlme_disassociate(peer, reason).await {
                if !iface.reports_disconnect_events() {
                    publish_mlme_frame(iface.as_ref(), ns, index, DISASSOCIATE, &frame);
                }
            }
        }
        MlmeExec::MgmtTx { cookie, request } => {
            let sent = request.frame.clone();
            let acked = iface.mgmt_tx(cookie, request).await.unwrap_or(false);
            if super::in_namespace(iface.as_ref(), ns) {
                let mut attrs = Vec::new();
                push_attr(&mut attrs, 3, &index.to_ne_bytes());
                push_attr(&mut attrs, 51, &sent);
                push_attr(&mut attrs, 88, &cookie.to_ne_bytes()); // COOKIE
                if acked {
                    push_attr(&mut attrs, 92, &[]); // NL80211_ATTR_ACK flag
                }
                publish_event(
                    NL80211_FAMILY_ID,
                    19,
                    ns,
                    GenlReply {
                        command: FRAME_TX_STATUS,
                        attrs,
                    },
                );
            }
        }
        MlmeExec::ExternalAuth { bssid, status } => {
            let _ = iface.external_auth_status(bssid, status).await;
        }
    }
}

/// Userspace-SME management path: AUTHENTICATE / ASSOCIATE / DEAUTHENTICATE /
/// DISASSOCIATE / REGISTER_FRAME / FRAME / EXTERNAL_AUTH. Mirrors the CONNECT
/// path: interface-bound admin authority is required, the frame exchanges run
/// asynchronously and surface their result as `mlme`-group events, and FRAME
/// returns its cookie synchronously (as cfg80211's nl80211_tx_mgmt does).
fn mlme_handle(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    let index = u32_attr(&attrs, 3)?.ok_or(EINVAL)?;
    let iface = crate::registry::list()
        .into_iter()
        .find(|iface| {
            narf_net::netlink_route::ifindex_for_name(iface.name()) == Some(index)
                && super::in_namespace(iface.as_ref(), context.net_ns_id)
        })
        .ok_or(ENODEV)?;
    let _admin = authority(&context, iface.as_ref())?;
    let ns = context.net_ns_id;
    if matches!(
        command,
        AUTHENTICATE | ASSOCIATE | DEAUTHENTICATE | DISASSOCIATE
    ) {
        // NL80211_FLAG_NEED_NETDEV_UP; each op then checks its driver op.
        station::netdev_up(iface.as_ref())?;
        return sme_command(command, iface, index, &attrs, &context);
    }
    // cfg80211 rejects these on a driver that offloads its SME (-EOPNOTSUPP
    // before the op is attempted).
    if !iface.supports_userspace_mlme() {
        return Err(EOPNOTSUPP);
    }
    match command {
        REGISTER_FRAME => {
            reject_unknown(&attrs, &[3, 91, 101])?;
            let frame_type = u16_attr(&attrs, 101)?.ok_or(EINVAL)?;
            // Must name a management frame: FC type bits (2..3) == 00.
            if frame_type & 0x000c != 0 {
                return Err(EINVAL);
            }
            // cfg80211 requires FRAME_MATCH even when the desired filter is
            // empty; presence distinguishes a registration from a malformed
            // request.
            let match_prefix = attr(&attrs, 91).ok_or(EINVAL)?;
            iface
                .register_mgmt_frame(frame_type, match_prefix)
                .map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        FRAME => {
            reject_unknown(&attrs, &[3, 38, 51, 87, 108])?;
            // `nl80211_tx_mgmt` is NL80211_FLAG_NEED_NETDEV_UP.
            station::netdev_up(iface.as_ref())?;
            let frame = attr(&attrs, 51).ok_or(EINVAL)?;
            // At least a 24-byte MAC header, and a management frame.
            if frame.len() < 24 || frame[0] & 0x000c != 0 {
                return Err(EINVAL);
            }
            let frequency_mhz = u32_attr(&attrs, 38)?;
            if let Some(frequency_mhz) = frequency_mhz {
                channel(frequency_mhz)?;
            }
            let request = crate::MgmtTxRequest {
                frequency_mhz: frequency_mhz.unwrap_or(0),
                frame: frame.to_vec(),
                offchannel_ok: attr(&attrs, 108).is_some(),
                duration: u32_attr(&attrs, 87)?.unwrap_or(0),
            };
            let cookie = FRAME_COOKIE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            narf_scheduler::spawn(run_mlme(
                iface,
                ns,
                index,
                MlmeExec::MgmtTx { cookie, request },
            ));
            // Return the cookie synchronously, as cfg80211's nl80211_tx_mgmt does.
            let mut attrs = Vec::new();
            push_attr(&mut attrs, 88, &cookie.to_ne_bytes());
            Ok(alloc::vec![GenlReply {
                command: FRAME,
                attrs,
            }])
        }
        EXTERNAL_AUTH => {
            reject_unknown(&attrs, &[3, 6, 52, 72, 76])?;
            let bssid = require_peer(&attrs)?;
            let status = u16_attr(&attrs, 72)?.ok_or(EINVAL)?;
            narf_scheduler::spawn(run_mlme(
                iface,
                ns,
                index,
                MlmeExec::ExternalAuth { bssid, status },
            ));
            Ok(Vec::new())
        }
        AUTHENTICATE | ASSOCIATE | DEAUTHENTICATE | DISASSOCIATE => {
            sme_command(command, iface, index, &attrs, &context)
        }
        _ => Err(EOPNOTSUPP),
    }
}

/// The scan-cache entry `cfg80211_get_bss(chan, bssid, ssid, ESS,
/// PRIVACY_ANY)` finds (-ENOENT when there is none).
fn cached_bss(
    iface: &dyn crate::WirelessNetIface,
    ns: u64,
    bssid: [u8; 6],
    frequency_mhz: u32,
    ssid: &[u8],
) -> Result<crate::BssInfo, i32> {
    CACHE
        .lock()
        .iter()
        .find(|c| c.name == iface.name() && c.namespace == ns)
        .and_then(|c| {
            c.results.iter().find(|(b, _)| {
                b.bssid == bssid && b.frequency_mhz == frequency_mhz && b.ssid == ssid
            })
        })
        .map(|(b, _)| b.clone())
        .ok_or(ENOENT)
}

/// The userspace-SME MLME commands, in `nl80211_authenticate` /
/// `nl80211_associate` / `nl80211_deauthenticate` /
/// `nl80211_disassociate` order (+ `cfg80211_mlme_*`); the frame exchange
/// then runs asynchronously and reports as cfg80211 does.
fn sme_command(
    command: u8,
    iface: Arc<dyn crate::WirelessNetIface>,
    index: u32,
    attrs: &[(u16, &[u8])],
    context: &RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let ns = context.net_ns_id;
    let has_op = iface.supports_userspace_mlme();
    let station = matches!(iface.current_iftype(), 2 | 8);
    let own = iface.mac();
    match command {
        AUTHENTICATE => {
            // NL80211_ATTR_AUTH_DATA = NLA_POLICY_MIN_LEN(4).
            if attr(attrs, 156).is_some_and(|d| d.len() < 4) {
                return Err(ERANGE);
            }
            if attr(attrs, 6).is_none()
                || attr(attrs, 53).is_none()
                || attr(attrs, 52).is_none()
                || attr(attrs, 38).is_none()
            {
                return Err(EINVAL);
            }
            // A WEP key (nl80211_parse_key) needs a WEP cipher suite, which
            // no NARF wiphy has.
            if attr(attrs, 80).is_some() || attr(attrs, 8).is_some() {
                return Err(EINVAL);
            }
            if !has_op || !station {
                return Err(EOPNOTSUPP);
            }
            let peer = mac_attr(attrs, 6)?.ok_or(EINVAL)?;
            let frequency_mhz = u32_attr(attrs, 38)?.ok_or(EINVAL)?;
            channel(frequency_mhz)?;
            let ssid = attr(attrs, 52).unwrap_or(&[]);
            if ssid.len() > 32 {
                return Err(EINVAL);
            }
            // nl80211_valid_auth_type: 0..=NL80211_AUTHTYPE_MAX (8); SAE
            // needs NL80211_FEATURE_SAE (set with userspace MLME), FILS
            // (5..=7) NL80211_EXT_FEATURE_FILS_STA and EPPKE (8) its ext
            // feature, neither of which NARF advertises.
            let auth_type = u32_attr(attrs, 53)?.ok_or(EINVAL)?;
            if auth_type > 4 {
                return Err(EINVAL);
            }
            let auth_data = attr(attrs, 156);
            if auth_type == 4 && auth_data.is_none() {
                return Err(EINVAL);
            }
            if auth_data.is_some() && auth_type != 4 {
                return Err(EINVAL);
            }
            // "we no longer track auth state": a local state change is a
            // successful no-op.
            if attr(attrs, 95).is_some() {
                return Ok(Vec::new());
            }
            if attr(attrs, 313).is_some() {
                return Err(EINVAL); // no WIPHY_FLAG_SUPPORTS_MLO
            }
            cached_bss(iface.as_ref(), ns, peer, frequency_mhz, ssid)?;
            // cfg80211_mlme_auth.
            if iface.connected_bssid() == Some(peer) {
                return Err(EALREADY);
            }
            if peer == own {
                return Err(EINVAL);
            }
            let request = crate::MlmeAuthRequest {
                peer,
                ssid: ssid.to_vec(),
                frequency_mhz,
                auth_type,
                auth_data: auth_data.unwrap_or(&[]).to_vec(),
                ie: attr(attrs, 42).unwrap_or(&[]).to_vec(),
            };
            narf_scheduler::spawn(run_mlme(iface, ns, index, MlmeExec::Authenticate(request)));
            Ok(Vec::new())
        }
        ASSOCIATE => {
            station::check_owner(iface.name(), context.portid)?;
            let ssid = attr(attrs, 52).ok_or(EINVAL)?;
            if !has_op || !station {
                return Err(EOPNOTSUPP);
            }
            let ie = attr(attrs, 42).unwrap_or(&[]);
            let ies = elements(ie)?;
            // WLAN_EID_EXT_NON_INHERITANCE: "non-inheritance makes no sense".
            if ies
                .iter()
                .any(|(id, b)| *id == 255 && b.first() == Some(&56))
            {
                return Err(EINVAL);
            }
            let use_mfp = match u32_attr(attrs, 66)? {
                None | Some(0) => false,
                Some(1) => true,
                Some(2) => return Err(EINVAL),
                Some(_) => return Err(ERANGE),
            };
            let prev_bssid = mac_attr(attrs, 79)?;
            if attr(attrs, 31).is_some() && attr(attrs, 148).is_none()
                || attr(attrs, 157).is_some() && attr(attrs, 176).is_none()
            {
                return Err(EINVAL);
            }
            if attr(attrs, 313).is_some() || attr(attrs, 312).is_some() {
                return Err(EINVAL); // MLO without WIPHY_FLAG_SUPPORTS_MLO
            }
            // nl80211_assoc_bss.
            let (Some(peer), Some(freq)) = (mac_attr(attrs, 6)?, u32_attr(attrs, 38)?) else {
                return Err(EINVAL);
            };
            channel(freq)?;
            if ssid.len() > 32 {
                return Err(EINVAL);
            }
            let bss = cached_bss(iface.as_ref(), ns, peer, freq, ssid)?;
            // nl80211_crypto_settings.
            let port = control_port(attrs, iface.supports_external_supplicant())?;
            crypto_suites(attrs, station::cipher_suites(iface.as_ref()), 1)?;
            // cfg80211_mlme_assoc.
            if let Some(current) = iface.connected_bssid() {
                if prev_bssid != Some(current) {
                    return Err(EALREADY);
                }
            }
            if peer == own {
                return Err(EINVAL);
            }
            if attr(attrs, 204).is_some() {
                station::set_owner(iface.name(), ns, context.portid, Some(peer));
            }
            station::set_control_port(iface.name(), ns, port.over_nl80211);
            let request = crate::MlmeAssocRequest {
                peer,
                ssid: ssid.to_vec(),
                frequency_mhz: freq,
                ie: ie.to_vec(),
                prev_bssid,
                use_mfp,
                control_port: port,
                privacy: !matches!(bss.security, crate::scan::BssSecurity::Open),
            };
            narf_scheduler::spawn(run_mlme(iface, ns, index, MlmeExec::Associate(request)));
            Ok(Vec::new())
        }
        _ => {
            // DEAUTHENTICATE / DISASSOCIATE.
            station::check_owner(iface.name(), context.portid)?;
            let peer = mac_attr(attrs, 6)?.ok_or(EINVAL)?;
            let reason = u16_attr(attrs, 54)?.ok_or(EINVAL)?;
            if !has_op || !station {
                return Err(EOPNOTSUPP);
            }
            if reason == 0 {
                return Err(EINVAL); // "Reason Code 0 is reserved"
            }
            let local_state_change = attr(attrs, 95).is_some();
            let connected = iface.connected_bssid();
            let exec = if command == DEAUTHENTICATE {
                // cfg80211_mlme_deauth.
                if local_state_change && connected != Some(peer) {
                    return Ok(Vec::new());
                }
                let target = station::with_wdev(iface.name(), ns, |w| w.disconnect_bssid);
                if target == peer || connected == Some(peer) {
                    station::clear_owner(iface.name());
                }
                MlmeExec::Deauthenticate { peer, reason }
            } else {
                // cfg80211_mlme_disassoc.
                if connected != Some(peer) {
                    return Err(station::ENOTCONN);
                }
                MlmeExec::Disassociate { peer, reason }
            };
            narf_scheduler::spawn(run_mlme(iface, ns, index, exec));
            Ok(Vec::new())
        }
    }
}

/// `nl80211_send_mlme_timeout`: WIPHY, IFINDEX, TIMED_OUT, MAC.
fn publish_mlme_timeout(
    iface: &dyn crate::WirelessNetIface,
    ns: u64,
    index: u32,
    command: u8,
    peer: [u8; 6],
) {
    if !super::in_namespace(iface, ns) {
        return;
    }
    let mut attrs = Vec::new();
    if let Some(wiphy) = wiphy_index(iface) {
        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    }
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    push_attr(&mut attrs, 65, &[]); // NL80211_ATTR_TIMED_OUT
    push_attr(&mut attrs, 6, &peer);
    publish_event(NL80211_FAMILY_ID, 19, ns, GenlReply { command, attrs });
}

/// `nl80211_send_connect_result` for an association the userspace SME
/// completed (`cfg80211_rx_assoc_resp` → `__cfg80211_connect_result`):
/// WIPHY, IFINDEX, MAC, STATUS_CODE, REQ_IE, RESP_IE.
fn publish_connect_result(
    iface: &dyn crate::WirelessNetIface,
    ns: u64,
    index: u32,
    peer: [u8; 6],
    status: u16,
    req_ie: &[u8],
    resp_ie: &[u8],
) {
    if !super::in_namespace(iface, ns) {
        return;
    }
    let mut attrs = Vec::new();
    if let Some(wiphy) = wiphy_index(iface) {
        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    }
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    push_attr(&mut attrs, 6, &peer);
    push_attr(&mut attrs, 72, &status.to_ne_bytes());
    if !req_ie.is_empty() {
        push_attr(&mut attrs, 77, req_ie);
    }
    if !resp_ie.is_empty() {
        push_attr(&mut attrs, 78, resp_ie);
    }
    publish_event(
        NL80211_FAMILY_ID,
        19,
        ns,
        GenlReply {
            command: CONNECT,
            attrs,
        },
    );
}

/// Access-Point configuration path: START_AP / STOP_AP / SET_BEACON and the
/// NEW/SET/DEL_STATION table operations. The reply covers netlink validation
/// and driver admission. The ath11k implementation serializes target WMI
/// completion on its runtime task, because a generic-netlink syscall can run
/// inside that executor and cannot synchronously wait for the same task.
fn ap_handle(
    command: u8,
    bytes: &[u8],
    context: RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    let attrs = attributes(bytes)?;
    let index = u32_attr(&attrs, 3)?.ok_or(EINVAL)?;
    let iface = crate::registry::list()
        .into_iter()
        .find(|iface| {
            narf_net::netlink_route::ifindex_for_name(iface.name()) == Some(index)
                && super::in_namespace(iface.as_ref(), context.net_ns_id)
        })
        .ok_or(ENODEV)?;
    let _admin = authority(&context, iface.as_ref())?;
    if !iface.supports_ap() {
        return Err(EOPNOTSUPP);
    }
    match command {
        START_AP => {
            reject_unknown(
                &attrs,
                &[
                    3, 12, 13, 14, 15, 38, 39, 52, 53, 70, 126, 145, 159, 160, 161, 270, 278, 279,
                    283, 294, 295, 306, 307, 325,
                ],
            )?;
            let ssid = attr(&attrs, 52).ok_or(EINVAL)?;
            if ssid.is_empty() || ssid.len() > 32 {
                return Err(EINVAL);
            }
            // The beacon head carries the 802.11 header + fixed beacon fields.
            let beacon_head = attr(&attrs, 14).ok_or(EINVAL)?;
            if beacon_head.len() < 24 {
                return Err(EINVAL);
            }
            let beacon_interval = u32_attr(&attrs, 12)?.ok_or(EINVAL)?;
            if beacon_interval == 0 {
                return Err(EINVAL);
            }
            let dtim_period = u32_attr(&attrs, 13)?.unwrap_or(1);
            // The TIM element and WMI vdev-start field carry DTIM as u8.
            if dtim_period == 0 || dtim_period > u8::MAX as u32 {
                return Err(EINVAL);
            }
            // An AP must be given an operating channel.
            let frequency_mhz = u32_attr(&attrs, 38)?.ok_or(EINVAL)?;
            // Retain the exact frequency in ApConfig. `channel()` remains
            // the cfg80211 validity check, but its channel number cannot
            // distinguish 2.4 from 6 GHz channel 1.
            channel(frequency_mhz)?;
            let fils_discovery = match attr(&attrs, 294) {
                Some(raw) if iface.supports_fils_discovery() => fils_discovery_config(raw)?,
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let unsol_bcast_probe_resp = match attr(&attrs, 295) {
                Some(raw) if iface.supports_unsol_bcast_probe_resp() => {
                    unsol_bcast_probe_resp_config(raw)?
                }
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let ftm_responder = match attr(&attrs, 270) {
                Some(raw) if iface.supports_ftm_responder() => Some(ftm_responder_config(raw)?),
                Some(_) => return Err(EOPNOTSUPP),
                None => None,
            };
            let twt_responder = match attr(&attrs, 278) {
                Some(flag) if flag.is_empty() && iface.supports_twt_responder() => true,
                Some(flag) if !flag.is_empty() => return Err(EINVAL),
                Some(_) => return Err(EOPNOTSUPP),
                None => false,
            };
            let he_obss_pd = attr(&attrs, 279).map(he_obss_pd_config).transpose()?;
            let he_bss_color = attr(&attrs, 283).map(he_bss_color_config).transpose()?;
            // `nl80211_parse_mbssid_config` and `nl80211_parse_beacon`.
            // The elements are already complete IEs as supplied by hostapd;
            // their nested attribute numbers are list positions only.
            let mbssid_elems = attr(&attrs, 307)
                .map(|raw| {
                    attributes(raw).map(|entries| {
                        entries
                            .into_iter()
                            .map(|(_, bytes)| bytes.to_vec())
                            .collect::<Vec<_>>()
                    })
                })
                .transpose()?
                .unwrap_or_default();
            let ema_rnr_elems = attr(&attrs, 325)
                .map(|raw| {
                    attributes(raw).and_then(|entries| {
                        let mut elems = Vec::with_capacity(entries.len());
                        for (_, bytes) in entries {
                            // `validate_ie_attr`: RNR payloads are complete
                            // information elements, not an arbitrary byte
                            // suffix. The actual element content remains
                            // userspace/mac80211-owned.
                            if bytes.len() < 2 || bytes.len() != bytes[1] as usize + 2 {
                                return Err(EINVAL);
                            }
                            elems.push(bytes.to_vec());
                        }
                        Ok(elems)
                    })
                })
                .transpose()?
                .unwrap_or_default();
            let mbssid = match attr(&attrs, 306) {
                None => {
                    if !mbssid_elems.is_empty() || !ema_rnr_elems.is_empty() {
                        return Err(EINVAL);
                    }
                    None
                }
                Some(raw) => {
                    let support = iface.mbssid_support().ok_or(EOPNOTSUPP)?;
                    let config = attributes(raw)?;
                    // MAX_* are GET_WIPHY-only. TX_LINK_ID is an MLO field;
                    // NARF has no MLO links and therefore rejects it rather
                    // than silently treating a link-local BSS as a radio-wide
                    // transmitting profile.
                    reject_unknown(&config, &[3, 4, 5])?;
                    let index = attr(&config, 3)
                        .filter(|bytes| bytes.len() == 1)
                        .map(|bytes| bytes[0])
                        .ok_or(EINVAL)?;
                    let tx_ifindex = u32_attr(&config, 4)?;
                    let ema = match attr(&config, 5) {
                        Some([]) => true,
                        Some(_) => return Err(EINVAL),
                        None => false,
                    };
                    if index >= support.max_interfaces
                        || (index == 0 && mbssid_elems.is_empty())
                        || (index != 0 && tx_ifindex.is_none())
                    {
                        return Err(EINVAL);
                    }
                    if ema && support.ema_max_profile_periodicity == 0 {
                        return Err(EOPNOTSUPP);
                    }
                    if ema && mbssid_elems.len() > support.ema_max_profile_periodicity as usize {
                        return Err(EINVAL);
                    }
                    if !ema_rnr_elems.is_empty()
                        && (!ema || ema_rnr_elems.len() < mbssid_elems.len())
                    {
                        return Err(EINVAL);
                    }
                    Some(crate::MbssidConfig {
                        index,
                        tx_ifindex,
                        ema,
                    })
                }
            };
            // A transmitting profile may omit TX_IFINDEX (it aliases itself);
            // a non-transmitting one must name a different AP netdev. This
            // needs the actual request ifindex, not the MBSSID index.
            if let Some(mbssid) = mbssid {
                if (mbssid.index == 0 && mbssid.tx_ifindex.is_some_and(|tx| tx != index))
                    || (mbssid.index != 0 && mbssid.tx_ifindex == Some(index))
                {
                    return Err(EINVAL);
                }
            }
            let cfg = crate::ApConfig {
                ssid: ssid.to_vec(),
                beacon_head: beacon_head.to_vec(),
                beacon_tail: attr(&attrs, 15).unwrap_or(&[]).to_vec(),
                probe_resp: attr(&attrs, 145).map(|frame| frame.to_vec()),
                beacon_interval,
                dtim_period,
                frequency_mhz,
                // cfg80211 permits old userspace to omit the chandef; its
                // legacy meaning is an HT-capable 20 MHz channel.
                channel_width: u32_attr(&attrs, 159)?.unwrap_or(1),
                center_freq1_mhz: u32_attr(&attrs, 160)?,
                center_freq2_mhz: u32_attr(&attrs, 161)?,
                hidden_ssid: u32_attr(&attrs, 126)?.unwrap_or(0),
                privacy: attr(&attrs, 70).is_some(),
                mbssid,
                mbssid_elems,
                ema_rnr_elems,
                fils_discovery,
                unsol_bcast_probe_resp,
                ftm_responder,
                twt_responder,
                he_obss_pd,
                he_bss_color,
            };
            iface.start_ap(cfg).map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        STOP_AP => {
            reject_unknown(&attrs, &[3])?;
            iface.stop_ap().map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        SET_BEACON => {
            reject_unknown(&attrs, &[3, 14, 15, 145, 270, 283, 294, 295])?;
            let head = attr(&attrs, 14);
            let tail = attr(&attrs, 15);
            let probe_resp = attr(&attrs, 145);
            let fils = match attr(&attrs, 294) {
                Some(raw) if iface.supports_fils_discovery() => Some(fils_discovery_config(raw)?),
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let unsol_bcast_probe_resp = match attr(&attrs, 295) {
                Some(raw) if iface.supports_unsol_bcast_probe_resp() => {
                    Some(unsol_bcast_probe_resp_config(raw)?)
                }
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let ftm_responder = match attr(&attrs, 270) {
                Some(raw) if iface.supports_ftm_responder() => Some(ftm_responder_config(raw)?),
                Some(_) => return Err(EOPNOTSUPP),
                None => None,
            };
            let he_bss_color = attr(&attrs, 283).map(he_bss_color_config).transpose()?;
            // At least one beacon/template family must be updated.
            if head.is_none()
                && tail.is_none()
                && probe_resp.is_none()
                && fils.is_none()
                && unsol_bcast_probe_resp.is_none()
                && ftm_responder.is_none()
                && he_bss_color.is_none()
            {
                return Err(EINVAL);
            }
            if head.is_some_and(|h| h.len() < 24) {
                return Err(EINVAL);
            }
            if head.is_some() || tail.is_some() || probe_resp.is_some() {
                iface
                    .set_beacon(
                        head.map(|v| v.to_vec()),
                        tail.map(|v| v.to_vec()),
                        probe_resp.map(|v| v.to_vec()),
                    )
                    .map_err(mlme_errno)?;
            }
            if fils.is_some() || unsol_bcast_probe_resp.is_some() {
                iface
                    .set_ap_discovery(fils, unsol_bcast_probe_resp)
                    .map_err(mlme_errno)?;
            }
            if let Some(ftm_responder) = ftm_responder {
                iface
                    .set_ap_ftm_responder(ftm_responder)
                    .map_err(mlme_errno)?;
            }
            if let Some(he_bss_color) = he_bss_color {
                iface
                    .set_ap_he_bss_color(he_bss_color)
                    .map_err(mlme_errno)?;
            }
            Ok(Vec::new())
        }
        COLOR_CHANGE_REQUEST => {
            // `nl80211_color_change`: this is deliberately AP-only (not
            // P2P-GO), and uses a normal post-change beacon plus a nested
            // temporary countdown beacon.
            reject_unknown(&attrs, &[3, 14, 15, 145, 295, 303, 304, 305])?;
            if !iface.supports_bss_color() || iface.current_iftype() != 3 {
                return Err(EOPNOTSUPP);
            }
            let count = attr(&attrs, 303)
                .filter(|value| value.len() == 1)
                .map(|value| value[0])
                .ok_or(EINVAL)?;
            let color = attr(&attrs, 304)
                .filter(|value| value.len() == 1)
                .map(|value| value[0])
                .ok_or(EINVAL)?;
            if !(1..=63).contains(&color) {
                return Err(EINVAL);
            }
            let change = attributes(attr(&attrs, 305).ok_or(EINVAL)?)?;
            reject_unknown(&change, &[14, 15, 145, 186, 187])?;
            let beacon_color_tail = attr(&change, 15).ok_or(EINVAL)?;
            let counter_offset_beacon = u16_attr(&change, 186)?.ok_or(EINVAL)?;
            if beacon_color_tail.get(counter_offset_beacon as usize) != Some(&count) {
                return Err(EINVAL);
            }
            let beacon_color_head = attr(&change, 14)
                .map(|head| {
                    if head.len() < 24 {
                        Err(EINVAL)
                    } else {
                        Ok(head.to_vec())
                    }
                })
                .transpose()?;
            let probe_resp_color = attr(&change, 145).map(|frame| frame.to_vec());
            let counter_offset_presp = match u16_attr(&change, 187)? {
                Some(offset) => {
                    let Some(probe_resp) = probe_resp_color.as_ref() else {
                        return Err(EINVAL);
                    };
                    if probe_resp.get(offset as usize) != Some(&count) {
                        return Err(EINVAL);
                    }
                    Some(offset)
                }
                None => None,
            };
            let beacon_next_head = attr(&attrs, 14)
                .map(|head| {
                    if head.len() < 24 {
                        Err(EINVAL)
                    } else {
                        Ok(head.to_vec())
                    }
                })
                .transpose()?;
            let unsol_bcast_probe_resp = match attr(&attrs, 295) {
                Some(raw) if iface.supports_unsol_bcast_probe_resp() => {
                    Some(unsol_bcast_probe_resp_config(raw)?)
                }
                Some(_) => return Err(EOPNOTSUPP),
                None => None,
            };
            iface
                .color_change(crate::ColorChangeConfig {
                    count,
                    color,
                    beacon_next_head,
                    beacon_next_tail: attr(&attrs, 15).map(|tail| tail.to_vec()),
                    probe_resp_next: attr(&attrs, 145).map(|frame| frame.to_vec()),
                    beacon_color_head,
                    beacon_color_tail: beacon_color_tail.to_vec(),
                    counter_offset_beacon,
                    probe_resp_color,
                    counter_offset_presp,
                    unsol_bcast_probe_resp,
                })
                .map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        CHANNEL_SWITCH => {
            // `nl80211_channel_switch`: the top-level beacon/probe-response
            // pieces are the post-switch templates, while CSA_IES holds the
            // temporary countdown templates.
            reject_unknown(
                &attrs,
                &[
                    3, 14, 15, 38, 145, 159, 160, 161, 183, 184, 185, 270, 283, 295,
                ],
            )?;
            if !iface.supports_channel_switch() {
                return Err(EOPNOTSUPP);
            }
            let frequency_mhz = u32_attr(&attrs, 38)?.ok_or(EINVAL)?;
            channel(frequency_mhz)?;
            let count = u32_attr(&attrs, 183)?.ok_or(EINVAL)?;
            if count > u8::MAX as u32 {
                return Err(EINVAL);
            }
            let csa = attributes(attr(&attrs, 185).ok_or(EINVAL)?)?;
            reject_unknown(&csa, &[14, 15, 145, 186, 187])?;
            let beacon_csa_head = attr(&csa, 14).ok_or(EINVAL)?;
            let beacon_csa_tail = attr(&csa, 15).ok_or(EINVAL)?;
            if beacon_csa_head.len() < 24 {
                return Err(EINVAL);
            }
            let raw_offsets = attr(&csa, 186).ok_or(EINVAL)?;
            if raw_offsets.is_empty() || raw_offsets.len() % 2 != 0 || raw_offsets.len() > 4 {
                return Err(EINVAL);
            }
            let mut counter_offsets_beacon = Vec::with_capacity(raw_offsets.len() / 2);
            for raw in raw_offsets.chunks_exact(2) {
                let offset = u16::from_ne_bytes(raw.try_into().unwrap());
                let Some(counter) = beacon_csa_tail.get(offset as usize) else {
                    return Err(EINVAL);
                };
                if *counter != count as u8 {
                    return Err(EINVAL);
                }
                counter_offsets_beacon.push(offset);
            }
            let probe_resp_csa = attr(&csa, 145).map(|frame| frame.to_vec());
            let mut counter_offsets_presp = Vec::new();
            if let Some(raw_offsets) = attr(&csa, 187) {
                let Some(probe_resp) = probe_resp_csa.as_ref() else {
                    return Err(EINVAL);
                };
                if raw_offsets.is_empty() || raw_offsets.len() % 2 != 0 || raw_offsets.len() > 4 {
                    return Err(EINVAL);
                }
                counter_offsets_presp.reserve(raw_offsets.len() / 2);
                for raw in raw_offsets.chunks_exact(2) {
                    let offset = u16::from_ne_bytes(raw.try_into().unwrap());
                    let Some(counter) = probe_resp.get(offset as usize) else {
                        return Err(EINVAL);
                    };
                    if *counter != count as u8 {
                        return Err(EINVAL);
                    }
                    counter_offsets_presp.push(offset);
                }
            }
            let beacon_after_head = attr(&attrs, 14)
                .map(|head| {
                    if head.len() < 24 {
                        Err(EINVAL)
                    } else {
                        Ok(head.to_vec())
                    }
                })
                .transpose()?;
            // cfg80211 permits this 6 GHz discovery update alongside CSA,
            // but not FILS discovery.  Preserve nested-attribute presence so
            // an empty body deletes the existing unsolicited-response state
            // after the new chandef is live.
            let unsol_bcast_probe_resp = match attr(&attrs, 295) {
                Some(raw) if iface.supports_unsol_bcast_probe_resp() => {
                    Some(unsol_bcast_probe_resp_config(raw)?)
                }
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let ftm_responder = match attr(&attrs, 270) {
                Some(raw) if iface.supports_ftm_responder() => Some(ftm_responder_config(raw)?),
                Some(_) => return Err(EOPNOTSUPP),
                None => None,
            };
            let he_bss_color = attr(&attrs, 283).map(he_bss_color_config).transpose()?;
            let cfg = crate::ChannelSwitchConfig {
                frequency_mhz,
                channel_width: u32_attr(&attrs, 159)?.unwrap_or(1),
                center_freq1_mhz: u32_attr(&attrs, 160)?,
                center_freq2_mhz: u32_attr(&attrs, 161)?,
                count: count as u8,
                block_tx: attr(&attrs, 184).is_some(),
                beacon_csa_head: beacon_csa_head.to_vec(),
                beacon_csa_tail: beacon_csa_tail.to_vec(),
                counter_offsets_beacon,
                probe_resp_csa,
                counter_offsets_presp,
                beacon_after_head,
                beacon_after_tail: attr(&attrs, 15).map(|tail| tail.to_vec()),
                probe_resp_after: attr(&attrs, 145).map(|frame| frame.to_vec()),
                ftm_responder,
                he_bss_color,
                unsol_bcast_probe_resp,
            };
            iface.channel_switch(cfg).map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        NEW_STATION | SET_STATION => {
            reject_unknown(
                &attrs,
                &[
                    3, 6, 16, 17, 18, 19, 31, 67, 129, 157, 171, 172, 269, 275, 276, 293,
                ],
            )?;
            let mac = require_peer(&attrs)?;
            // A fully-associated station needs an AID (1..=2007) and the rates
            // it negotiated; NL80211_CMD_NEW_STATION requires both.
            let aid = u16_attr(&attrs, 16)?.unwrap_or(0);
            if command == NEW_STATION && !(1..=2007).contains(&aid) {
                return Err(EINVAL);
            }
            let exact_capability = |kind: u16, len: usize| -> Result<Option<Vec<u8>>, i32> {
                let Some(raw) = attr(&attrs, kind) else {
                    return Ok(None);
                };
                if raw.len() != len {
                    return Err(ERANGE);
                }
                Ok(Some(raw.to_vec()))
            };
            let he_capability = attr(&attrs, 269)
                .map(|raw| {
                    // ieee80211_sta_he_cap is variable-length; the fixed
                    // MAC + PHY portion is 17 bytes and PPE/MCS expansion is
                    // bounded by the 802.11 element length.
                    if !(17..=255).contains(&raw.len()) {
                        Err(ERANGE)
                    } else {
                        Ok(raw.to_vec())
                    }
                })
                .transpose()?;
            let ext_capability = attr(&attrs, 172)
                .map(|raw| {
                    if raw.len() > 255 {
                        Err(ERANGE)
                    } else {
                        Ok(raw.to_vec())
                    }
                })
                .transpose()?;
            let flags = ap_station_flags(&attrs)?;
            let wme = ap_station_wme(&attrs)?;
            let station_tx_power = station::station_tx_power(&attrs, iface.as_ref())?;
            let sta = crate::StationConfig {
                mac,
                aid,
                listen_interval: u16_attr(&attrs, 18)?.unwrap_or(0),
                supported_rates: attr(&attrs, 19).unwrap_or(&[]).to_vec(),
                wme: flags.wme.or(wme.as_ref().map(|_| true)),
                uapsd_queues: wme.as_ref().and_then(|wme| wme.uapsd_queues),
                uapsd_max_sp: wme.as_ref().and_then(|wme| wme.max_sp),
                mfp: flags.mfp,
                capability: u16_attr(&attrs, 171)?,
                ext_capability,
                ht_capability: exact_capability(31, 26)?,
                vht_capability: exact_capability(157, 12)?,
                he_capability,
                he_6ghz_capability: u16_attr(&attrs, 293)?,
                authorized: flags.authorized,
                station_tx_power,
            };
            if command == NEW_STATION {
                iface.add_station(sta).map_err(mlme_errno)?;
            } else {
                iface.set_station(sta).map_err(mlme_errno)?;
            }
            Ok(Vec::new())
        }
        DEL_STATION => {
            reject_unknown(&attrs, &[3, 6, 54])?;
            // MAC is optional: its absence removes every station.
            let mac = mac_attr(&attrs, 6)?;
            if mac.is_some_and(|m| m[0] & 1 != 0 && m != [0xff; 6]) {
                return Err(EINVAL);
            }
            let reason = u16_attr(&attrs, 54)?.unwrap_or(2);
            iface.del_station(mac, reason).map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        _ => Err(EOPNOTSUPP),
    }
}

/// `NL80211_ATTR_STA_WME` — per-client U-APSD request. The firmware owns
/// buffering and TIM state after the AP peer parameters are installed.
struct ApStationWme {
    uapsd_queues: Option<u8>,
    max_sp: Option<u8>,
}

fn ap_station_wme(attrs: &[(u16, &[u8])]) -> Result<Option<ApStationWme>, i32> {
    let Some(raw) = attr(attrs, 129) else {
        return Ok(None);
    };
    let mut out = ApStationWme {
        uapsd_queues: None,
        max_sp: None,
    };
    for (kind, value) in attributes(raw).map_err(|_| EINVAL)? {
        if !(1..=2).contains(&kind) || value.len() != 1 {
            return Err(EINVAL);
        }
        match kind {
            1 if value[0] & !0x0f == 0 => out.uapsd_queues = Some(value[0]),
            2 if value[0] & !0x03 == 0 => out.max_sp = Some(value[0]),
            _ => return Err(EINVAL),
        }
    }
    Ok(Some(out))
}

/// The AP subset of `parse_station_flags` / `cfg80211_check_station_change`.
/// An AP client is already associated when hostapd sends NEW_STATION. The
/// associated/authenticated/short-preamble flags therefore describe the
/// accepted association rather than separate state transitions. WME changes
/// peer QoS state; PMF selects firmware's per-peer PMF bit and the AP
/// software BIP / IGTK state used for robust group management frames.
#[derive(Default)]
struct ApStationFlags {
    authorized: Option<bool>,
    wme: Option<bool>,
    mfp: Option<bool>,
}

fn ap_station_flags(attrs: &[(u16, &[u8])]) -> Result<ApStationFlags, i32> {
    const AUTHORIZED: u32 = 1 << 1;
    const SHORT_PREAMBLE: u32 = 1 << 2;
    const WME: u32 = 1 << 3;
    const MFP: u32 = 1 << 4;
    const AUTHENTICATED: u32 = 1 << 5;
    const ASSOCIATED: u32 = 1 << 7;
    const ALLOWED: u32 = AUTHORIZED | SHORT_PREAMBLE | WME | MFP | AUTHENTICATED | ASSOCIATED;
    if let Some(raw) = attr(attrs, 67) {
        if raw.len() < 8 {
            return Err(ERANGE);
        }
        let mask = u32::from_ne_bytes(raw[0..4].try_into().unwrap());
        let set = u32::from_ne_bytes(raw[4..8].try_into().unwrap()) & mask;
        if mask & 1 != 0 || mask & !ALLOWED != 0 {
            return Err(EINVAL);
        }
        return Ok(ApStationFlags {
            authorized: (mask & AUTHORIZED != 0).then_some(set & AUTHORIZED != 0),
            wme: (mask & WME != 0).then_some(set & WME != 0),
            mfp: (mask & MFP != 0).then_some(set & MFP != 0),
        });
    }
    let Some(raw) = attr(attrs, 17) else {
        return Ok(ApStationFlags::default());
    };
    let flags = attributes(raw).map_err(|_| EINVAL)?;
    let mut out = ApStationFlags::default();
    for (flag, _) in flags {
        let bit = match flag {
            1 => AUTHORIZED,
            2 => SHORT_PREAMBLE,
            3 => WME,
            4 => MFP,
            5 => AUTHENTICATED,
            7 => ASSOCIATED,
            _ => return Err(EINVAL),
        };
        if bit == AUTHORIZED {
            out.authorized = Some(true);
        }
        if bit == WME {
            out.wme = Some(true);
        }
        if bit == MFP {
            out.mfp = Some(true);
        }
        if bit & !ALLOWED != 0 {
            return Err(EINVAL);
        }
    }
    Ok(out)
}

async fn execute(
    iface: Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    ns: u64,
    index: u32,
    operation: Operation,
) {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    let live = authorized(&admin, iface.as_ref(), ns);
    // The peer whose controlled port opened with this connect.
    let mut port_authorized = None;
    let (command, group) = match operation {
        Operation::Scan(request) => {
            let result = if live {
                iface.scan(request).await
            } else {
                Err(crate::WirelessError::HardwareError)
            };
            if let Ok(mut results) = result {
                results.truncate(256);
                if authorized(&admin, iface.as_ref(), ns) {
                    let results = results
                        .into_iter()
                        .map(|bss| {
                            let ies = iface
                                .scan_information_elements(bss.bssid)
                                .unwrap_or_default();
                            (bss, ies)
                        })
                        .collect();
                    if let Some(cache) = CACHE.lock().iter_mut().find(|c| c.name == iface.name()) {
                        cache.results = results;
                    }
                    (34, 18)
                } else {
                    (35, 18)
                }
            } else {
                (35, 18)
            }
        }
        Operation::Connect {
            ssid,
            bssid,
            frequency_mhz,
            cred,
            ie,
            owner: _,
        } => {
            let akm = cred.akm();
            let mut selected = None;
            let mut roaming = false;
            let result = async {
                if !live {
                    return Err(crate::WirelessError::Denied);
                }
                selected = {
                    let cache = CACHE.lock();
                    let results = cache
                        .iter()
                        .find(|c| c.name == iface.name() && c.namespace == ns);
                    results.and_then(|c| {
                        select_bss(
                            c.results.iter().map(|(b, _)| b),
                            &ssid,
                            bssid,
                            frequency_mhz,
                            akm,
                        )
                    })
                };
                if selected.is_none() {
                    // CONNECT requests discovery, not a particular scan form.
                    // Passive-only radios cannot service a directed probe, and
                    // a failed active attempt is not a safe fallback boundary.
                    let active = iface.max_scan_ssids() != 0;
                    let mut results = iface
                        .scan(crate::ScanRequest {
                            ssids: if active {
                                alloc::vec![ssid.clone()]
                            } else {
                                Vec::new()
                            },
                            frequencies_mhz: frequency_mhz.into_iter().collect(),
                            channels: Vec::new(),
                            active,
                            random_mac: None,
                            colocated_6ghz: false,
                            duration_tu: None,
                            duration_mandatory: false,
                            extra_ies: Vec::new(),
                        })
                        .await?;
                    results.truncate(256);
                    selected = select_bss(results.iter(), &ssid, bssid, frequency_mhz, akm);
                    if !authorized(&admin, iface.as_ref(), ns) {
                        return Err(crate::WirelessError::Denied);
                    }
                    let entries = results
                        .into_iter()
                        .map(|bss| {
                            let ies = iface
                                .scan_information_elements(bss.bssid)
                                .unwrap_or_default();
                            (bss, ies)
                        })
                        .collect();
                    if let Some(cache) = CACHE.lock().iter_mut().find(|c| c.name == iface.name()) {
                        cache.results = entries;
                    }
                }
                let bss = selected.as_ref().ok_or(crate::WirelessError::InvalidArgs)?;
                if !authorized(&admin, iface.as_ref(), ns) {
                    return Err(crate::WirelessError::Denied);
                }
                let security = match &cred {
                    Credential::Open => crate::SecurityConfig::Open,
                    Credential::Psk(psk) => crate::SecurityConfig::Wpa2 { psk: **psk },
                    Credential::Sae(password) => crate::SecurityConfig::Wpa3 {
                        password: (**password).clone(),
                    },
                    Credential::External(e) => crate::SecurityConfig::External(*e),
                };
                let request = crate::AssociateRequest {
                    ssid,
                    bssid: bss.bssid,
                    frequency_mhz: bss.frequency_mhz,
                    channel: bss.channel,
                    security,
                    ie,
                };
                // Already associated to a different BSS of this ESS → roam
                // (reassociate) rather than a fresh connect.
                roaming = iface
                    .connected_bssid()
                    .is_some_and(|current| current != bss.bssid);
                if roaming {
                    iface.roam(request).await
                } else {
                    iface.associate(request).await
                }
            }
            .await;
            let still_live = authorized(&admin, iface.as_ref(), ns);
            if result.is_ok() && !still_live {
                let _ = iface.disassociate().await;
            }
            let status: u16 = if result.is_ok() && still_live { 0 } else { 1 };
            if let Some(index) = wiphy_index(iface.as_ref()) {
                push_attr(&mut attrs, 1, &index.to_ne_bytes()); // NL80211_ATTR_WIPHY
            }
            if let Some(address) = selected.map(|b| b.bssid).or(bssid) {
                push_attr(&mut attrs, 6, &address);
                // The offloading driver completed the 4-way handshake (or
                // SAE + 4-way) before associate() returned: the port is
                // authorized, which cfg80211 reports as a separate
                // NL80211_CMD_PORT_AUTHORIZED (`cfg80211_port_authorized`)
                // after the connect result — the event wpa_supplicant waits
                // for with WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK.
                if status == 0 && matches!(akm, Akm::Psk | Akm::Sae) {
                    port_authorized = Some(address);
                }
            }
            push_attr(&mut attrs, 72, &status.to_ne_bytes());
            if status != 0 {
                // __cfg80211_connect_result failure: owner cleared.
                station::clear_owner(iface.name());
            }
            // A successful move to a new BSS is a ROAM event; a fresh
            // association is a CONNECT. Failures report as CONNECT(status!=0).
            let command = if roaming && result.is_ok() {
                ROAM
            } else {
                CONNECT
            };
            (command, 19)
        }
        Operation::Disconnect => {
            if !live || iface.disassociate().await.is_err() {
                return;
            }
            if iface.reports_disconnect_events() {
                return;
            }
            push_attr(&mut attrs, 54, &3u16.to_ne_bytes());
            (DISCONNECT, 19)
        }
    };
    // A namespace move during a firmware wait must not leak its new
    // interface state into the previous namespace's event listeners.
    if super::in_namespace(iface.as_ref(), ns) {
        publish_event(NL80211_FAMILY_ID, group, ns, GenlReply { command, attrs });
        if let Some(peer) = port_authorized {
            publish_event(
                NL80211_FAMILY_ID,
                19,
                ns,
                port_authorized_event(iface.as_ref(), index, peer),
            );
        }
    }
}

/// The wiphy index nl80211 reports for `iface` (its registry position).
fn wiphy_index(iface: &dyn crate::WirelessNetIface) -> Option<u32> {
    crate::registry::wiphy_index(iface.wiphy_id())
}

/// `nl80211_send_port_authorized`: WIPHY, IFINDEX, MAC (the AP).
fn port_authorized_event(
    iface: &dyn crate::WirelessNetIface,
    index: u32,
    peer: [u8; 6],
) -> GenlReply {
    let mut attrs = Vec::new();
    if let Some(wiphy) = wiphy_index(iface) {
        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    }
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    push_attr(&mut attrs, 6, &peer);
    GenlReply {
        command: PORT_AUTHORIZED,
        attrs,
    }
}

fn select_bss<'a>(
    results: impl Iterator<Item = &'a crate::BssInfo>,
    ssid: &[u8],
    bssid: Option<[u8; 6]>,
    frequency_mhz: Option<u32>,
    akm: Akm,
) -> Option<crate::BssInfo> {
    results
        .filter(|b| {
            b.ssid == ssid
                && bssid.is_none_or(|address| address == b.bssid)
                && frequency_mhz.is_none_or(|freq| freq == b.frequency_mhz)
                && match akm {
                    Akm::Open => matches!(b.security, crate::scan::BssSecurity::Open),
                    Akm::Psk => matches!(b.security, crate::scan::BssSecurity::Wpa2),
                    Akm::Sae => matches!(b.security, crate::scan::BssSecurity::Wpa3),
                    Akm::Rsn => !matches!(b.security, crate::scan::BssSecurity::Open),
                }
        })
        .max_by_key(|b| b.rssi)
        .cloned()
}

fn scan_reply(
    index: u32,
    bss: &crate::BssInfo,
    information_elements: &[u8],
    associated: bool,
) -> GenlReply {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    let mut nested = Vec::new();
    push_attr(&mut nested, 1, &bss.bssid);
    if associated {
        // NL80211_BSS_STATUS = NL80211_BSS_STATUS_ASSOCIATED: `iw link` and
        // wpa_supplicant's nl80211_get_assoc_freq find the current BSS by it.
        push_attr(&mut nested, 9, &1u32.to_ne_bytes());
    }
    push_attr(&mut nested, 2, &bss.frequency_mhz.to_ne_bytes());
    push_attr(&mut nested, 7, &(i32::from(bss.rssi) * 100).to_ne_bytes());
    let private = !matches!(bss.security, crate::scan::BssSecurity::Open);
    push_attr(
        &mut nested,
        5,
        &(1u16 | if private { 0x10 } else { 0 }).to_ne_bytes(),
    );
    let mut ies = alloc::vec![0, bss.ssid.len() as u8];
    ies.extend_from_slice(&bss.ssid);
    // Preserve the AP's actual security suites; never synthesize RSN.
    push_attr(
        &mut nested,
        6,
        if information_elements.is_empty() {
            &ies
        } else {
            information_elements
        },
    );
    push_attr(&mut attrs, 47 | NLA_F_NESTED, &nested);
    GenlReply { command: 34, attrs }
}
