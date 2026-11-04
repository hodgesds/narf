//! `NL80211_CMD_TRIGGER_SCAN` / `NL80211_CMD_GET_SCAN` addressed by
//! `NL80211_ATTR_WDEV` to an actual control-only P2P_DEVICE WDEV (Linux
//! `net/wireless/nl80211.c` `nl80211_trigger_scan` → `rdev_scan` with the
//! P2P_DEVICE `wdev`, `nl80211_dump_scan`, `nl80211_send_scan_msg`).
//!
//! wpa_supplicant's `p2p_find` scans from the P2P device by WDEV, never by
//! an IFINDEX. Such a request keeps its exact source like the other
//! control-WDEV operations (`p2p_async::defer`): the driver's
//! `p2p_device_scan_async` runs under the request's
//! `RadioControlAuthority`, so the ACK is sent after the native scan
//! completed (Linux ACKs at `rdev_scan` acceptance). The scan-done
//! `NL80211_CMD_NEW_SCAN_RESULTS` multicast on the `scan` group carries
//! `NL80211_ATTR_WIPHY` and `NL80211_ATTR_WDEV` (no IFINDEX, as
//! `nl80211_prep_scan_msg` for a wdev without netdev) and precedes the ACK.
//! A failed native scan is reported through the ACK errno only.
//!
//! The results are kept per WDEV identity and namespace and dumped with
//! the WDEV selector (`nl80211_send_bss`). Linux keeps one BSS list per
//! wiphy; NARF keeps the netdev and WDEV caches separate, so an ifindex
//! `GET_SCAN` never returns P2P-device results and vice versa.
use super::*;

const WDEV: u16 = 153;
/// `NL80211_MCGRP_SCAN`.
const SCAN_GROUP: u32 = 18;
const NEW_SCAN_RESULTS: u8 = 34;

struct WdevCache {
    id: u64,
    namespace: u64,
    busy: bool,
    results: Vec<(crate::BssInfo, Vec<u8>)>,
}

static WDEV_CACHE: IrqSafeSpinLock<Vec<WdevCache>> = IrqSafeSpinLock::new(Vec::new());

/// One in-flight WDEV scan (`rdev->scan_req`): a second trigger on the
/// same WDEV is `-EBUSY` until this guard is dropped with the request.
pub(super) struct ScanGuard {
    id: u64,
    namespace: u64,
}

impl ScanGuard {
    pub(super) fn begin(id: u64, namespace: u64) -> Result<Self, i32> {
        let mut caches = WDEV_CACHE.lock();
        // Retired WDEV identities never come back; drop their results.
        caches.retain(|cache| {
            cache.busy || crate::registry::control_by_id(cache.id, cache.namespace).is_some()
        });
        match caches
            .iter_mut()
            .find(|cache| cache.id == id && cache.namespace == namespace)
        {
            Some(cache) if cache.busy => return Err(EBUSY),
            Some(cache) => cache.busy = true,
            None => caches.push(WdevCache {
                id,
                namespace,
                busy: true,
                results: Vec::new(),
            }),
        }
        Ok(ScanGuard { id, namespace })
    }

    /// Replace the WDEV's results after a completed scan.
    pub(super) fn store(&self, results: Vec<(crate::BssInfo, Vec<u8>)>) {
        if let Some(cache) = WDEV_CACHE
            .lock()
            .iter_mut()
            .find(|cache| cache.id == self.id && cache.namespace == self.namespace)
        {
            cache.results = results;
        }
    }

    /// `nl80211_send_scan_msg(..., NL80211_CMD_NEW_SCAN_RESULTS)`.
    pub(super) fn done_event(&self, wiphy: u32) -> GenlReply {
        let mut attrs = Vec::new();
        push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
        push_attr(&mut attrs, WDEV, &self.id.to_ne_bytes());
        GenlReply {
            command: NEW_SCAN_RESULTS,
            attrs,
        }
    }

    pub(super) fn publish_done(&self, wiphy: u32) {
        publish_event(
            NL80211_FAMILY_ID,
            SCAN_GROUP,
            self.namespace,
            self.done_event(wiphy),
        );
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        if let Some(cache) = WDEV_CACHE
            .lock()
            .iter_mut()
            .find(|cache| cache.id == self.id && cache.namespace == self.namespace)
        {
            cache.busy = false;
        }
    }
}

/// The dumped results of one WDEV (`nl80211_dump_scan` with a wdev).
fn dump(id: u64, namespace: u64) -> Vec<GenlReply> {
    WDEV_CACHE
        .lock()
        .iter()
        .find(|cache| cache.id == id && cache.namespace == namespace)
        .map(|cache| {
            cache
                .results
                .iter()
                .map(|(bss, ies)| scan_reply_wdev(id, bss, ies))
                .collect()
        })
        .unwrap_or_default()
}

/// `attrs` already resolved (`p2p_async::interface`) to the control-only
/// `iface` named by its `NL80211_ATTR_WDEV`.
pub(super) fn handle(
    command: u8,
    attrs: &[(u16, &[u8])],
    dump_request: bool,
    context: RequestContext<'_>,
    slot: Option<&narf_net::netlink_generic::DeferredRequest>,
    iface: Arc<dyn crate::WirelessNetIface>,
) -> Result<Vec<GenlReply>, i32> {
    let id = crate::registry::control_for(iface.as_ref())
        .ok_or(ENODEV)?
        .id();
    if command == GET_SCAN {
        if !dump_request {
            return Err(EOPNOTSUPP);
        }
        return Ok(dump(id, context.net_ns_id));
    }
    if dump_request {
        return Err(EOPNOTSUPP);
    }
    if iface.current_iftype() != 10 || !iface.async_p2p_device_scan_control() {
        return Err(EOPNOTSUPP);
    }
    let admin = p2p_async::source_authority(&context, iface.as_ref(), slot)?;
    let scan_attrs: Vec<(u16, &[u8])> = attrs
        .iter()
        .filter(|(kind, _)| *kind != WDEV)
        .copied()
        .collect();
    // A control WDEV has no IFINDEX alias (`p2p_async::interface`).
    if attr(&scan_attrs, 3).is_some() {
        return Err(EINVAL);
    }
    let request = match parse_operation_caps(
        SCAN,
        &scan_attrs,
        ConnectCaps::of(iface.as_ref()),
        context.portid,
    )? {
        Operation::Scan(request) => request,
        // No `ScanFlags` bit is offered to a control WDEV.
        _ => return Err(EOPNOTSUPP),
    };
    let guard = ScanGuard::begin(id, context.net_ns_id)?;
    p2p_async::defer(
        iface,
        admin,
        context.net_ns_id,
        None,
        slot,
        p2p_async::Operation::Scan { request, guard },
    )
}
