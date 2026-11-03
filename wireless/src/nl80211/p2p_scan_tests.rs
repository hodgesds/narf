//! `NL80211_ATTR_WDEV`-addressed TRIGGER_SCAN / GET_SCAN routing
//! (`p2p_scan_async.rs`): IFINDEX scans keep their path, a netdev WDEV is
//! the same request as its IFINDEX, and the control-WDEV hook is opt-in.
use super::*;

fn reply_attr(reply: &GenlReply, kind: u16) -> Option<Vec<u8>> {
    attributes(&reply.attrs)
        .ok()?
        .into_iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, value)| value.to_vec())
}

fn smoke_nl80211_wdev_scan_routing_keeps_ifindex_scans() -> TestResult {
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(InterfaceStub {
        name: "nlwifi-wscan",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    // The trait defaults leave every driver without a WDEV scan hook.
    if iface.async_p2p_device_scan_control() {
        return TestResult::Fail("WDEV scan hook is not opt-in");
    }
    narf_net::iface::register(iface.name(), iface.mac(), |_, _| Ok(()));
    crate::registry::register(iface.clone());
    let _cleanup = CacheNetdev("nlwifi-wscan");
    let index = narf_net::netlink_route::ifindex_for_name(iface.name()).unwrap();
    let Some(wiphy) = crate::registry::wiphy_index(iface.wiphy_id()) else {
        return TestResult::Fail("stub radio has no wiphy");
    };
    let wdev = station::wdev_id(wiphy, index);
    // Unchanged IFINDEX TRIGGER_SCAN: authority still precedes the scan.
    let mut by_index = Vec::new();
    push_attr(&mut by_index, 3, &index.to_ne_bytes());
    if !matches!(
        handle(SCAN, &by_index, false, RequestContext::default()),
        Err(EPERM)
    ) {
        return TestResult::Fail("IFINDEX TRIGGER_SCAN changed its authority path");
    }
    // A netdev WDEV is the same request (`nl80211_trigger_scan` resolves
    // the wdev's netdev), alone or with an agreeing IFINDEX.
    let mut by_wdev = Vec::new();
    push_attr(&mut by_wdev, 153, &wdev.to_ne_bytes());
    let mut both = by_index.clone();
    push_attr(&mut both, 153, &wdev.to_ne_bytes());
    for attrs in [&by_wdev, &both] {
        if !matches!(
            handle(SCAN, attrs, false, RequestContext::default()),
            Err(EPERM)
        ) {
            return TestResult::Fail("netdev WDEV TRIGGER_SCAN not routed to its IFINDEX");
        }
    }
    // Disagreeing selectors and unknown WDEVs name no device.
    let mut disagree = Vec::new();
    push_attr(&mut disagree, 3, &(index + 1000).to_ne_bytes());
    push_attr(&mut disagree, 153, &wdev.to_ne_bytes());
    let mut unknown = Vec::new();
    push_attr(&mut unknown, 153, &(wdev ^ 0x7fff_0000_0000).to_ne_bytes());
    for attrs in [&disagree, &unknown] {
        if !matches!(
            handle(SCAN, attrs, false, RequestContext::default()),
            Err(ENODEV)
        ) {
            return TestResult::Fail("mismatched or unknown WDEV scan accepted");
        }
    }
    // Populate the IFINDEX cache exactly as a completed scan does.
    let admin = narf_net::kernel_admin(iface.name()).unwrap();
    let guard = begin_operation(iface.name(), 0, index).unwrap();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        admin,
        0,
        index,
        Operation::Scan(crate::ScanRequest {
            ssids: Vec::new(),
            frequencies_mhz: Vec::new(),
            channels: Vec::new(),
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }),
    ));
    drop(guard);
    let (Ok(indexed), Ok(wdev_dump)) = (
        handle(GET_SCAN, &by_index, true, RequestContext::default()),
        handle(GET_SCAN, &by_wdev, true, RequestContext::default()),
    ) else {
        return TestResult::Fail("GET_SCAN dump refused");
    };
    if indexed.len() != 1
        || indexed.len() != wdev_dump.len()
        || indexed
            .iter()
            .zip(&wdev_dump)
            .any(|(a, b)| a.command != b.command || a.attrs != b.attrs)
    {
        return TestResult::Fail("netdev WDEV GET_SCAN differs from its IFINDEX dump");
    }
    if reply_attr(&indexed[0], 3) != Some(index.to_ne_bytes().to_vec())
        || reply_attr(&indexed[0], 153).is_some()
    {
        return TestResult::Fail("IFINDEX scan dump selector changed");
    }
    // Control-WDEV replies and scan-done events carry only the WDEV.
    let Some(bss) = CACHE
        .lock()
        .iter()
        .find(|c| c.matches(iface.name(), 0, index))
        .and_then(|c| c.results.first().cloned())
    else {
        return TestResult::Fail("IFINDEX scan cache empty");
    };
    let id = 0x5a5a_0000_0000_0001u64;
    let reply = scan_reply_wdev(id, &bss.0, &bss.1);
    if reply_attr(&reply, 153) != Some(id.to_ne_bytes().to_vec())
        || reply_attr(&reply, 3).is_some()
        || reply_attr(&reply, 47).is_none()
    {
        return TestResult::Fail("WDEV BSS reply selector");
    }
    let Ok(scan) = super::super::p2p_scan_async::ScanGuard::begin(id, 77) else {
        return TestResult::Fail("first WDEV scan refused");
    };
    if !matches!(
        super::super::p2p_scan_async::ScanGuard::begin(id, 77),
        Err(EBUSY)
    ) {
        return TestResult::Fail("concurrent WDEV scan not EBUSY");
    }
    let done = scan.done_event(wiphy);
    if done.command != 34
        || reply_attr(&done, 1) != Some(wiphy.to_ne_bytes().to_vec())
        || reply_attr(&done, 153) != Some(id.to_ne_bytes().to_vec())
        || reply_attr(&done, 3).is_some()
    {
        return TestResult::Fail("WDEV NEW_SCAN_RESULTS selector");
    }
    drop(scan);
    if super::super::p2p_scan_async::ScanGuard::begin(id, 77).is_err() {
        return TestResult::Fail("WDEV scan stayed busy after its request");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_wdev_scan_routing_keeps_ifindex_scans
);
