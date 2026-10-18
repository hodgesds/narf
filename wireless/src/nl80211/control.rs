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
use alloc::{string::String, sync::Arc};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::netlink_generic::{publish_event, RequestContext};
use zeroize::Zeroizing;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "control_tests.rs"]
mod tests;

#[path = "station.rs"]
pub(super) mod station;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_tests.rs"]
mod station_tests;

const EINVAL: i32 = 22;
const EPERM: i32 = 1;
const EBUSY: i32 = 16;
const ENOENT: i32 = 2;
const ERANGE: i32 = 34;
const EALREADY: i32 = 114;
const SCAN: u8 = 33;
const GET_SCAN: u8 = 32;
const CONNECT: u8 = 46;
const ROAM: u8 = 47;
const DISCONNECT: u8 = 48;
const PORT_AUTHORIZED: u8 = 125;
const SET_INTERFACE: u8 = 6;
const GET_STATION: u8 = 17;
// Userspace-SME MLME command numbers (nl80211_commands).
const AUTHENTICATE: u8 = 37;
const ASSOCIATE: u8 = 38;
const DEAUTHENTICATE: u8 = 39;
const DISASSOCIATE: u8 = 40;
const REGISTER_FRAME: u8 = 58;
const FRAME: u8 = 59;
const FRAME_TX_STATUS: u8 = 60;
const EXTERNAL_AUTH: u8 = 127;
// Access-Point command numbers (nl80211_commands).
const SET_BEACON: u8 = 14;
const START_AP: u8 = 15;
const STOP_AP: u8 = 16;
const SET_STATION: u8 = 18;
const NEW_STATION: u8 = 19;
const DEL_STATION: u8 = 20;

/// Monotonic cookie source for NL80211_CMD_FRAME transmissions. The cookie
/// returned in the FRAME reply is echoed back in the matching
/// NL80211_CMD_FRAME_TX_STATUS notification.
static FRAME_COOKIE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

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
        channel: Option<u32>,
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
fn u16_attr(attrs: &[(u16, &[u8])], kind: u16) -> Result<Option<u16>, i32> {
    attr(attrs, kind)
        .map(|b| Ok(u16::from_ne_bytes(b.try_into().map_err(|_| EINVAL)?)))
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
        _ => Err(EINVAL),
    }
}
fn frequency(channel: u32) -> u32 {
    match channel {
        14 => 2484,
        1..=13 => 2407 + 5 * channel,
        _ => 5000 + 5 * channel,
    }
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
/// cipher suites (`cfg80211_supported_cipher_suite`, -EINVAL).
fn crypto_suites(attrs: &[(u16, &[u8])], suites: &[u32]) -> Result<(), i32> {
    if let Some(raw) = attr(attrs, 73) {
        if raw.len() % 4 != 0 || raw.len() > 4 {
            return Err(EINVAL); // cipher_limit 1
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
/// advertises are -EOPNOTSUPP (LOW_PRIORITY, RANDOM_ADDR and the
/// ext-feature-gated bits 4..=12); FLUSH, AP and COLOCATED_6GHZ need none.
/// FLUSH is what NARF always does — a scan replaces the cached results.
/// FREQ_KHZ is refused because the frequency list would then be in kHz,
/// which this handler does not decode.
fn scan_flags(flags: u32) -> Result<(), i32> {
    const LOW_PRIORITY: u32 = 1 << 0;
    const RANDOM_ADDR: u32 = 1 << 3;
    const FEATURE_GATED: u32 = 0x1ff0; // bits 4..=12
    const FREQ_KHZ: u32 = 1 << 13;
    if flags & (LOW_PRIORITY | RANDOM_ADDR | FEATURE_GATED | FREQ_KHZ) != 0 {
        return Err(EOPNOTSUPP);
    }
    Ok(())
}

/// What a wiphy offers the CONNECT parser.
#[derive(Clone, Copy, Default)]
struct ConnectCaps {
    psk_offload: bool,
    sae_offload: bool,
    external: bool,
}

impl ConnectCaps {
    fn of(iface: &dyn crate::WirelessNetIface) -> Self {
        ConnectCaps {
            psk_offload: iface.supports_handshake_offload(),
            sae_offload: iface.supports_sae_offload(),
            external: iface.supports_external_supplicant(),
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
        // 158 = NL80211_ATTR_SCAN_FLAGS, 42 = NL80211_ATTR_IE (probe IEs).
        SCAN => &[3, 42, 44, 45, 158],
        CONNECT => CONNECT_ATTRS,
        DISCONNECT => &[3, 54],
        _ => return Err(EOPNOTSUPP),
    };
    if attrs.iter().any(|(kind, _)| !allowed.contains(kind)) {
        return Err(EOPNOTSUPP);
    }
    match command {
        SCAN => {
            // wiphy max_scan_ie_len is 0 (NL80211_ATTR_MAX_SCAN_IE_LEN):
            // nl80211_trigger_scan refuses longer extra IEs with -EINVAL.
            if attr(attrs, 42).is_some_and(|ie| !ie.is_empty()) {
                return Err(EINVAL);
            }
            scan_flags(u32_attr(attrs, 158)?.unwrap_or(0))?;
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
            let channels = attr(attrs, 44)
                .map(attributes)
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(|(_, b)| channel(u32::from_ne_bytes(b.try_into().map_err(|_| EINVAL)?)))
                .collect::<Result<Vec<_>, _>>()?;
            if ssids.len() > 16 || channels.len() > 68 {
                return Err(EINVAL);
            }
            // Presence of at least one SSID (including the empty wildcard)
            // requests active scanning. Preserve directed entries even when
            // a wildcard is also present, for hidden-network discovery.
            let active = !ssids.is_empty();
            Ok(Operation::Scan(crate::ScanRequest {
                ssids,
                channels,
                active,
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
            let channel = u32_attr(attrs, 38)?.map(channel).transpose()?;
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
                &[crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC]
            } else if psk_offload || sae_offload {
                &[crate::CIPHER_SUITE_CCMP]
            } else {
                &[]
            };
            crypto_suites(attrs, suites)?;
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
                channel,
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
    ) || command == SET_STATION && station_iface(bytes, context.net_ns_id)
    {
        return station_handle(command, bytes, context);
    }
    if command == station::GET_REG {
        return station::get_reg(bytes, dump, context.net_ns_id);
    }
    if matches!(
        command,
        START_AP | STOP_AP | SET_BEACON | NEW_STATION | SET_STATION | DEL_STATION
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
        _ => Err(EOPNOTSUPP),
    }
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

/// NL80211_CMD_SET_INTERFACE and NL80211_CMD_GET_STATION.
///
/// SET_INTERFACE (`nl80211_set_interface`): the IFTYPE policy (> MAX is
/// -EINVAL) runs before the device lookup; MESH_ID on a non-mesh type and
/// MNTR_FLAGS on a non-monitor type are -EINVAL; 4ADDR and any real type
/// change are -EOPNOTSUPP, the `cfg80211_change_iface` answer for a wiphy
/// without `change_virtual_intf` — no NARF driver switches type at runtime.
/// Setting the current type is a successful no-op, which is what
/// wpa_supplicant's `nl80211_set_mode(STATION)` does at startup.
///
/// GET_STATION (`nl80211_get_station` / `nl80211_dump_station`): a station
/// interface's one station is its AP. A do needs NL80211_ATTR_MAC (-EINVAL)
/// and is -ENOENT for any other peer (mac80211 `sta_info_get_bss`).
/// STA_INFO carries only what NARF knows: the signal of the AP's last scan
/// record.
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
            // NL80211_ATTR_4ADDR: enabling it needs WIPHY_FLAG_4ADDR_STATION
            // (`nl80211_valid_4addr`); clearing it is a change.
            let four_addr = attr(&attrs, 83);
            if four_addr.is_some_and(|b| b.first().is_some_and(|v| *v != 0)) {
                return Err(EOPNOTSUPP);
            }
            // NL80211_ATTR_MNTR_FLAGS needs a monitor interface.
            const MONITOR: u32 = 6;
            if attr(&attrs, 23).is_some() && new != MONITOR {
                return Err(EINVAL);
            }
            if four_addr.is_some() || new != current {
                return Err(EOPNOTSUPP);
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
            let peer = iface.connected_bssid();
            let Some(peer) = peer.filter(|peer| wanted.is_none_or(|w| w == *peer)) else {
                return if dump { Ok(Vec::new()) } else { Err(ENOENT) };
            };
            let signal = CACHE
                .lock()
                .iter()
                .find(|c| c.name == iface.name() && c.namespace == context.net_ns_id)
                .and_then(|c| c.results.iter().find(|(bss, _)| bss.bssid == peer))
                .map(|(bss, _)| bss.rssi);
            let mut info = Vec::new();
            let tracked = iface.station_info().unwrap_or_default();
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
            Ok(alloc::vec![GenlReply {
                command: NEW_STATION,
                attrs,
            }])
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
    match r.width_mhz {
        40 => push_attr(&mut rate, 3, &[]),
        80 => push_attr(&mut rate, 8, &[]),
        160 => push_attr(&mut rate, 9, &[]),
        _ => {}
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
    if let Some(v) = s.tx_failed {
        push_attr(info, 12, &v.to_ne_bytes());
    }
    if let Some(v) = s.signal_avg_dbm {
        push_attr(info, 13, &[v as u8]);
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
            let match_prefix = attr(&attrs, 91).unwrap_or(&[]);
            iface
                .register_mgmt_frame(frame_type, match_prefix)
                .map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        FRAME => {
            reject_unknown(&attrs, &[3, 38, 51, 87, 108])?;
            let frame = attr(&attrs, 51).ok_or(EINVAL)?;
            // At least a 24-byte MAC header, and a management frame.
            if frame.len() < 24 || frame[0] & 0x000c != 0 {
                return Err(EINVAL);
            }
            let channel = u32_attr(&attrs, 38)?.map(channel).transpose()?.unwrap_or(0);
            let request = crate::MgmtTxRequest {
                channel,
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
    channel: u32,
    ssid: &[u8],
) -> Result<crate::BssInfo, i32> {
    CACHE
        .lock()
        .iter()
        .find(|c| c.name == iface.name() && c.namespace == ns)
        .and_then(|c| {
            c.results
                .iter()
                .find(|(b, _)| b.bssid == bssid && b.channel == channel && b.ssid == ssid)
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
            let channel = channel(u32_attr(attrs, 38)?.ok_or(EINVAL)?)?;
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
            cached_bss(iface.as_ref(), ns, peer, channel, ssid)?;
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
                channel,
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
            let channel = channel(freq)?;
            if ssid.len() > 32 {
                return Err(EINVAL);
            }
            let bss = cached_bss(iface.as_ref(), ns, peer, channel, ssid)?;
            // nl80211_crypto_settings.
            let port = control_port(attrs, iface.supports_external_supplicant())?;
            crypto_suites(attrs, station::cipher_suites(iface.as_ref()))?;
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
                channel,
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
/// NEW/SET/DEL_STATION table operations. Beacon and station setup are
/// synchronous — the netlink reply is the result hostapd waits on — so these
/// return the driver's errno directly rather than deferring to an event.
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
            reject_unknown(&attrs, &[3, 12, 13, 14, 15, 38, 39, 52, 53, 70, 126, 159])?;
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
            if dtim_period == 0 {
                return Err(EINVAL);
            }
            // An AP must be given an operating channel.
            let channel = u32_attr(&attrs, 38)?
                .map(channel)
                .transpose()?
                .ok_or(EINVAL)?;
            let cfg = crate::ApConfig {
                ssid: ssid.to_vec(),
                beacon_head: beacon_head.to_vec(),
                beacon_tail: attr(&attrs, 15).unwrap_or(&[]).to_vec(),
                beacon_interval,
                dtim_period,
                channel,
                hidden_ssid: u32_attr(&attrs, 126)?.unwrap_or(0),
                privacy: attr(&attrs, 70).is_some(),
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
            reject_unknown(&attrs, &[3, 14, 15])?;
            let head = attr(&attrs, 14);
            let tail = attr(&attrs, 15);
            // At least one of head/tail must be present to change anything.
            if head.is_none() && tail.is_none() {
                return Err(EINVAL);
            }
            if head.is_some_and(|h| h.len() < 24) {
                return Err(EINVAL);
            }
            iface
                .set_beacon(head.unwrap_or(&[]).to_vec(), tail.unwrap_or(&[]).to_vec())
                .map_err(mlme_errno)?;
            Ok(Vec::new())
        }
        NEW_STATION | SET_STATION => {
            reject_unknown(&attrs, &[3, 6, 16, 17, 18, 19, 67])?;
            let mac = require_peer(&attrs)?;
            // A fully-associated station needs an AID (1..=2007) and the rates
            // it negotiated; NL80211_CMD_NEW_STATION requires both.
            let aid = u16_attr(&attrs, 16)?.unwrap_or(0);
            if command == NEW_STATION && !(1..=2007).contains(&aid) {
                return Err(EINVAL);
            }
            let sta = crate::StationConfig {
                mac,
                aid,
                listen_interval: u16_attr(&attrs, 18)?.unwrap_or(0),
                supported_rates: attr(&attrs, 19).unwrap_or(&[]).to_vec(),
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
            channel,
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
                        select_bss(c.results.iter().map(|(b, _)| b), &ssid, bssid, channel, akm)
                    })
                };
                if selected.is_none() {
                    let mut results = iface
                        .scan(crate::ScanRequest {
                            ssids: alloc::vec![ssid.clone()],
                            channels: channel.into_iter().collect(),
                            active: true,
                        })
                        .await?;
                    results.truncate(256);
                    selected = select_bss(results.iter(), &ssid, bssid, channel, akm);
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
    crate::registry::list()
        .iter()
        .position(|known| known.name() == iface.name())
        .map(|index| index as u32)
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
    channel: Option<u32>,
    akm: Akm,
) -> Option<crate::BssInfo> {
    results
        .filter(|b| {
            b.ssid == ssid
                && bssid.is_none_or(|address| address == b.bssid)
                && channel.is_none_or(|ch| ch == b.channel)
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
    push_attr(&mut nested, 2, &frequency(bss.channel).to_ne_bytes());
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
