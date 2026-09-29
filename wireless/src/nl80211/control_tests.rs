use super::*;
use alloc::boxed::Box;
use narf_ipc::{Consumer, Producer};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};

struct InterfaceStub {
    name: &'static str,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl Interface for InterfaceStub {
    fn name(&self) -> &str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 1]
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        false
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for InterfaceStub {
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac(),
            bands: Vec::new(),
            modes: crate::iface::WirelessModes::STATION,
            hw_caps: crate::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Ok(alloc::vec![crate::BssInfo {
            bssid: [2, 1, 2, 3, 4, 5],
            ssid: b"test".to_vec(),
            channel: 36,
            rssi: -47,
            security: crate::scan::BssSecurity::Wpa2
        }])
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
}

fn smoke_nl80211_attribute_and_security_validation() -> TestResult {
    let mut bytes = Vec::new();
    push_attr(&mut bytes, 52, b"test");
    push_attr(&mut bytes, 6, &[2, 1, 2, 3, 4, 5]);
    push_attr(&mut bytes, 38, &5180u32.to_ne_bytes());
    if !matches!(
        parse_operation(CONNECT, &attributes(&bytes).unwrap(), true),
        Ok(Operation::Connect {
            channel: Some(36),
            pmk: None,
            ..
        })
    ) {
        return TestResult::Fail("open connect decode");
    }
    let mut duplicate = bytes.clone();
    push_attr(&mut duplicate, 52, b"other");
    if attributes(&duplicate).is_ok() || attributes(&[8, 0, 3, 0, 0]).is_ok() {
        return TestResult::Fail("ambiguous/truncated attributes accepted");
    }
    let mut excessive = Vec::new();
    for kind in 1..=129 {
        push_attr(&mut excessive, kind, &[]);
    }
    if attributes(&excessive).is_ok() {
        return TestResult::Fail("unbounded attribute walk accepted");
    }
    push_attr(&mut bytes, 254, &[7; 32]);
    for (kind, value) in [
        (75, 2u32),
        (76, 0x000fac02),
        (73, 0x000fac04),
        (74, 0x000fac04),
    ] {
        push_attr(&mut bytes, kind, &value.to_ne_bytes());
    }
    if parse_operation(CONNECT, &attributes(&bytes).unwrap(), true).is_err()
        || parse_operation(CONNECT, &attributes(&bytes).unwrap(), false).is_ok()
    {
        return TestResult::Fail("PSK handshake offload gating");
    }
    push_attr(&mut bytes, 66, &2u32.to_ne_bytes());
    if parse_operation(CONNECT, &attributes(&bytes).unwrap(), true).is_ok() {
        return TestResult::Fail("unsupported MFP request silently downgraded");
    }
    if channel(5955).is_ok() || channel(5181).is_ok() {
        return TestResult::Fail("unsupported frequency accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_attribute_and_security_validation
);

fn smoke_nl80211_authority_and_scan_completion() -> TestResult {
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(InterfaceStub {
        name: "nlwifi-test",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(iface.name(), iface.mac(), |_| Ok(()));
    crate::registry::register(iface.clone());
    let index = narf_net::netlink_route::ifindex_for_name(iface.name()).unwrap();
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    if !matches!(
        handle(SCAN, &attrs, false, RequestContext::default()),
        Err(EPERM)
    ) {
        return TestResult::Fail("ambient netlink scan authority");
    }
    let wrong = narf_net::initial_loopback_admin();
    if !matches!(
        handle(
            SCAN,
            &attrs,
            false,
            RequestContext {
                net_ns_id: 0,
                admin: Some(&wrong)
            }
        ),
        Err(EPERM)
    ) {
        return TestResult::Fail("cross-interface capability accepted");
    }
    // Use the public synthetic-loopback authority for a standalone stub,
    // without registering or changing the real loopback interface.
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(InterfaceStub {
        name: "lo",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    let admin = narf_net::initial_loopback_admin();
    if !authorized(&admin, iface.as_ref(), 0) || authorized(&admin, iface.as_ref(), 99) {
        return TestResult::Fail("namespace-bound admin validation");
    }
    CACHE.lock().push(Cache {
        name: iface.name().into(),
        namespace: 0,
        busy: true,
        results: Vec::new(),
    });
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        admin.clone(),
        0,
        index,
        Operation::Scan(crate::ScanRequest {
            ssids: Vec::new(),
            channels: Vec::new(),
            active: false,
        }),
    ));
    let cached = CACHE
        .lock()
        .iter()
        .find(|c| c.name == "lo")
        .unwrap()
        .results
        .clone();
    if cached.len() != 1
        || !scan_reply(index, &cached[0].0, &cached[0].1)
            .attrs
            .windows(4)
            .any(|b| b == b"test")
    {
        return TestResult::Fail("native scan did not populate Linux dump");
    }
    drop(OperationGuard(iface.name().into()));
    if CACHE
        .lock()
        .iter()
        .find(|c| c.name == iface.name())
        .unwrap()
        .busy
    {
        return TestResult::Fail("cancelled operation stayed busy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_authority_and_scan_completion
);

fn smoke_nl80211_active_scan_and_ssid_connect() -> TestResult {
    let mut ssids = Vec::new();
    push_attr(&mut ssids, 1, &[]);
    push_attr(&mut ssids, 2, b"hidden");
    let mut request = Vec::new();
    push_attr(&mut request, 45 | NLA_F_NESTED, &ssids);
    match parse_operation(SCAN, &attributes(&request).unwrap(), true).unwrap() {
        Operation::Scan(req)
            if req.active && req.ssids == alloc::vec![Vec::new(), b"hidden".to_vec()] => {}
        _ => return TestResult::Fail("active wildcard/directed scan request lost"),
    }
    if !matches!(
        parse_operation(SCAN, &[], true),
        Ok(Operation::Scan(crate::ScanRequest { active: false, .. }))
    ) {
        return TestResult::Fail("passive scan became active");
    }
    request.clear();
    push_attr(&mut request, 52, b"home");
    if !matches!(
        parse_operation(CONNECT, &attributes(&request).unwrap(), true),
        Ok(Operation::Connect {
            bssid: None,
            channel: None,
            ..
        })
    ) {
        return TestResult::Fail("SSID-only Linux connect rejected");
    }
    let weak = crate::BssInfo {
        bssid: [2; 6],
        ssid: b"home".to_vec(),
        channel: 1,
        rssi: -80,
        security: crate::scan::BssSecurity::Wpa2,
    };
    let mut strong = weak.clone();
    strong.bssid = [4; 6];
    strong.channel = 36;
    strong.rssi = -40;
    let mut open = strong.clone();
    open.bssid = [6; 6];
    open.rssi = -10;
    open.security = crate::scan::BssSecurity::Open;
    let list = [weak, strong, open];
    if select_bss(list.iter(), b"home", None, None, true)
        .unwrap()
        .bssid
        != [4; 6]
        || select_bss(list.iter(), b"home", None, Some(1), true)
            .unwrap()
            .bssid
            != [2; 6]
        || select_bss(list.iter(), b"home", Some([6; 6]), None, true).is_some()
    {
        return TestResult::Fail("connect selection ignored security/BSSID/channel filters");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_active_scan_and_ssid_connect
);
