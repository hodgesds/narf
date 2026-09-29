//! Native station operations behind Linux messages. Mutations require
//! a live, interface-bound admin handle supplied by the socket layer.

use super::*;
use alloc::{string::String, sync::Arc};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::netlink_generic::{publish_event, RequestContext};
use zeroize::Zeroizing;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "control_tests.rs"]
mod tests;

const EINVAL: i32 = 22;
const EPERM: i32 = 1;
const EBUSY: i32 = 16;
const SCAN: u8 = 33;
const GET_SCAN: u8 = 32;
const CONNECT: u8 = 46;
const DISCONNECT: u8 = 48;

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
        bssid: [u8; 6],
        channel: u32,
        pmk: Option<Zeroizing<[u8; 32]>>,
    },
    Disconnect,
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

fn parse_operation(command: u8, attrs: &[(u16, &[u8])], offload: bool) -> Result<Operation, i32> {
    let allowed: &[u16] = match command {
        SCAN => &[3, 44, 45],
        CONNECT => &[3, 6, 38, 42, 52, 53, 66, 70, 73, 74, 75, 76, 254],
        DISCONNECT => &[3, 54],
        _ => return Err(EOPNOTSUPP),
    };
    if attrs.iter().any(|(kind, _)| !allowed.contains(kind)) {
        return Err(EOPNOTSUPP);
    }
    match command {
        SCAN => {
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
            // Empty SSID is the nl80211 wildcard. The underlying passive
            // scanner uses an empty filter list for that same request.
            let ssids = if ssids.iter().any(Vec::is_empty) {
                Vec::new()
            } else {
                ssids
            };
            Ok(Operation::Scan(crate::ScanRequest {
                ssids,
                channels,
                active: false,
            }))
        }
        CONNECT => {
            // This station profile does not negotiate protected management
            // frames or arbitrary extra association IEs.
            if u32_attr(attrs, 66)?.unwrap_or(0) != 0 {
                return Err(EOPNOTSUPP);
            }
            if let Some(ie) = attr(attrs, 42) {
                let rsn = crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
                if !ie.is_empty()
                    && (ie.len() != rsn.len() + 2
                        || ie[..2] != [48, rsn.len() as u8]
                        || ie[2..] != rsn)
                {
                    return Err(EOPNOTSUPP);
                }
            }
            let ssid = attr(attrs, 52).ok_or(EINVAL)?;
            if ssid.is_empty() || ssid.len() > 32 {
                return Err(EINVAL);
            }
            let bssid = attr(attrs, 6)
                .ok_or(EINVAL)?
                .try_into()
                .map_err(|_| EINVAL)?;
            let channel = channel(u32_attr(attrs, 38)?.ok_or(EINVAL)?)?;
            if u32_attr(attrs, 53)?.is_some_and(|auth| auth != 0) {
                return Err(EOPNOTSUPP);
            }
            let pmk = match attr(attrs, 254) {
                Some(pmk) => {
                    if !offload
                        || u32_attr(attrs, 75)? != Some(2)
                        || u32_attr(attrs, 76)? != Some(0x000fac02)
                        || u32_attr(attrs, 73)? != Some(0x000fac04)
                        || u32_attr(attrs, 74)? != Some(0x000fac04)
                    {
                        return Err(EOPNOTSUPP);
                    }
                    Some(Zeroizing::new(pmk.try_into().map_err(|_| EINVAL)?))
                }
                None => {
                    if attr(attrs, 70).is_some()
                        || u32_attr(attrs, 75)?.unwrap_or(0) != 0
                        || attr(attrs, 76).is_some()
                        || attr(attrs, 73).is_some()
                        || attr(attrs, 74).is_some()
                    {
                        return Err(EOPNOTSUPP);
                    }
                    None
                }
            };
            Ok(Operation::Connect {
                ssid: ssid.to_vec(),
                bssid,
                channel,
                pmk,
            })
        }
        DISCONNECT => {
            if attr(attrs, 54).is_some_and(|b| b.len() != 2) {
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
        let cache = CACHE.lock();
        let results = cache
            .iter()
            .find(|c| c.name == iface.name() && c.namespace == context.net_ns_id)
            .map(|c| c.results.as_slice())
            .unwrap_or_default();
        return Ok(results
            .iter()
            .map(|(bss, ies)| scan_reply(index, bss, ies))
            .collect());
    }
    if dump {
        return Err(EOPNOTSUPP);
    }
    let admin = context
        .admin
        .filter(|admin| authorized(admin, iface.as_ref(), context.net_ns_id))
        .ok_or(EPERM)?
        .clone();
    let operation = parse_operation(command, &attrs, iface.supports_handshake_offload())?;
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
    narf_scheduler::spawn(async move {
        let _guard = guard;
        execute(iface, admin, namespace, index, operation).await;
    });
    Ok(Vec::new()) // generic netlink emits the requested ACK
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
            pmk,
        } => {
            let security = pmk
                .as_ref()
                .map(|key| crate::SecurityConfig::Wpa2 { psk: **key })
                .unwrap_or(crate::SecurityConfig::Open);
            let result = if live {
                iface
                    .associate(crate::AssociateRequest {
                        ssid,
                        bssid,
                        channel,
                        security,
                    })
                    .await
            } else {
                Err(crate::WirelessError::HardwareError)
            };
            let still_live = authorized(&admin, iface.as_ref(), ns);
            if result.is_ok() && !still_live {
                let _ = iface.disassociate().await;
            }
            let status: u16 = if result.is_ok() && still_live { 0 } else { 1 };
            push_attr(&mut attrs, 6, &bssid);
            push_attr(&mut attrs, 72, &status.to_ne_bytes());
            (CONNECT, 19)
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
    }
}

fn scan_reply(index: u32, bss: &crate::BssInfo, information_elements: &[u8]) -> GenlReply {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    let mut nested = Vec::new();
    push_attr(&mut nested, 1, &bss.bssid);
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
