//! SET_WIPHY fragmentation threshold, scan RANDOM_SN and
//! START/STOP_SCHED_SCAN through the generic-netlink entry point.
use super::*;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_net::netlink_generic::{build_replies_with_context, ReplyOptions};

const NAME: &str = "wlan-wops";

struct OpsIface {
    base: InterfaceStub,
    frag: AtomicU32,
    sched_started: AtomicU32,
    sched_match_sets: AtomicU32,
    sched_stopped: AtomicU32,
}
impl Interface for OpsIface {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.base.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        false
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.base.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.base.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for OpsIface {
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessNetIface::get_wireless_info(&self.base)
    }
    async fn scan(
        &self,
        request: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        crate::WirelessNetIface::scan(&self.base, request).await
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        Ok(())
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    fn fragmentation_threshold(&self) -> Option<u32> {
        Some(self.frag.load(Ordering::Relaxed))
    }
    fn set_fragmentation_threshold(&self, threshold: u32) -> Result<(), i32> {
        self.frag.store(threshold, Ordering::Relaxed);
        Ok(())
    }
    fn sched_scan_support(&self) -> Option<crate::SchedScanSupport> {
        Some(crate::SchedScanSupport {
            max_match_sets: 4,
            ..crate::SchedScanSupport::NET_DETECT
        })
    }
    fn start_sched_scan(&self, request: crate::SchedScanRequest) -> Result<(), i32> {
        self.sched_match_sets
            .store(request.matches.len() as u32, Ordering::Relaxed);
        self.sched_started.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn stop_sched_scan(&self) -> Result<(), i32> {
        self.sched_stopped.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn message(command: u8, attrs: &[u8]) -> Vec<u8> {
    let mut body = alloc::vec![command, 1, 0, 0];
    body.extend_from_slice(attrs);
    let len = 16 + body.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&NL80211_FAMILY_ID.to_ne_bytes());
    out.extend_from_slice(&5u16.to_ne_bytes()); // NLM_F_REQUEST | NLM_F_ACK
    out.extend_from_slice(&9u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&body);
    out
}
/// The errno of the first reply (0 for an ACK).
fn send(command: u8, attrs: &[u8]) -> i32 {
    let root = RequestContext {
        init_net_admin: true,
        net_admin: true,
        ..RequestContext::default()
    };
    let replies =
        build_replies_with_context(&message(command, attrs), ReplyOptions::default(), root)
            .unwrap();
    let first = &replies[0];
    if u16::from_ne_bytes(first[4..6].try_into().unwrap()) == 2 {
        -i32::from_ne_bytes(first[16..20].try_into().unwrap())
    } else {
        0
    }
}
fn with_ifindex(ifindex: u32, rest: &[(u16, &[u8])]) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    for (kind, value) in rest {
        push_attr(&mut attrs, *kind, value);
    }
    attrs
}

fn smoke_nl80211_frag_threshold_sched_scan_and_random_sn() -> TestResult {
    register();
    let ops = Arc::new(OpsIface {
        base: InterfaceStub {
            name: NAME,
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        },
        frag: AtomicU32::new(u32::MAX),
        sched_started: AtomicU32::new(0),
        sched_match_sets: AtomicU32::new(0),
        sched_stopped: AtomicU32::new(0),
    });
    let iface: Arc<dyn crate::WirelessNetIface> = ops.clone();
    narf_net::iface::register(NAME, iface.mac(), |_, _| Ok(()));
    crate::registry::register(iface);
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(NAME) else {
        return TestResult::Fail("stub has no ifindex");
    };

    // SET_WIPHY fragmentation threshold (attribute 63).
    if send(2, &with_ifindex(ifindex, &[(63, &1001u32.to_ne_bytes())])) != 0
        || ops.frag.load(Ordering::Relaxed) != 1000
    {
        return TestResult::Fail("odd fragmentation threshold not rounded down and applied");
    }
    if send(2, &with_ifindex(ifindex, &[(63, &255u32.to_ne_bytes())])) != EINVAL
        || ops.frag.load(Ordering::Relaxed) != 1000
    {
        return TestResult::Fail("threshold below 256 accepted");
    }
    if send(2, &with_ifindex(ifindex, &[(63, &u32::MAX.to_ne_bytes())])) != 0
        || ops.frag.load(Ordering::Relaxed) != u32::MAX
    {
        return TestResult::Fail("disabling fragmentation failed");
    }

    // START_SCHED_SCAN: one SSID match set and one plan.
    let mut ssid = Vec::new();
    push_attr(&mut ssid, 1, b"narf");
    let mut matches = Vec::new();
    push_attr(&mut matches, 1 | NLA_F_NESTED, &ssid);
    let mut plan = Vec::new();
    push_attr(&mut plan, 1, &30u32.to_ne_bytes());
    let mut plans = Vec::new();
    push_attr(&mut plans, 1 | NLA_F_NESTED, &plan);
    let start = with_ifindex(
        ifindex,
        &[(132 | NLA_F_NESTED, &matches), (225 | NLA_F_NESTED, &plans)],
    );
    if send(75, &start) != 0
        || ops.sched_started.load(Ordering::Relaxed) != 1
        || ops.sched_match_sets.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("START_SCHED_SCAN did not reach the driver");
    }
    // Missing match sets: EINVAL from nl80211_parse_sched_scan's checks.
    let bad = with_ifindex(ifindex, &[(225 | NLA_F_NESTED, &plans)]);
    if send(75, &bad) != EINVAL || ops.sched_started.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("START_SCHED_SCAN without match sets accepted");
    }
    if send(76, &with_ifindex(ifindex, &[(88, &5u64.to_ne_bytes())])) != ENOENT {
        return TestResult::Fail("STOP_SCHED_SCAN for an unknown request id");
    }
    if send(76, &with_ifindex(ifindex, &[])) != 0 || ops.sched_stopped.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("STOP_SCHED_SCAN did not reach the driver");
    }

    // RANDOM_SN is gated on the wiphy capability.
    let flags = (1u32 << 11).to_ne_bytes();
    let scan = [(158u16, &flags[..])];
    let attrs = attributes_owned(&scan);
    let caps = |random_sn| ConnectCaps {
        max_scan_ssids: 16,
        max_scan_ie_len: 512,
        scan_random_sn: random_sn,
        ..ConnectCaps::default()
    };
    if !matches!(
        parse_operation_caps(SCAN, &attributes(&attrs).unwrap(), caps(false), 0),
        Err(EOPNOTSUPP)
    ) {
        return TestResult::Fail("RANDOM_SN accepted without the extended feature");
    }
    if !matches!(
        parse_operation_caps(SCAN, &attributes(&attrs).unwrap(), caps(true), 0),
        Ok(Operation::ScanFlagged(
            _,
            crate::ScanFlags { random_sn: true }
        ))
    ) {
        return TestResult::Fail("RANDOM_SN not carried to the driver");
    }
    if !matches!(
        parse_operation_caps(SCAN, &[], caps(true), 0),
        Ok(Operation::Scan(_))
    ) {
        return TestResult::Fail("flagless scan changed shape");
    }
    TestResult::Pass
}
fn attributes_owned(list: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in list {
        push_attr(&mut out, *kind, value);
    }
    out
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_frag_threshold_sched_scan_and_random_sn
);
