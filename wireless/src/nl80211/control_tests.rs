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
    fn phy_capabilities(&self, band: u32) -> Option<crate::iface::PhyCapabilities> {
        let mut ht = [0; 26];
        ht[..5].copy_from_slice(&[0x6e, 0, 0x13, 0xff, 0xff]);
        ht[15] = 1;
        Some(crate::iface::PhyCapabilities {
            ht,
            vht: (band == 5000).then_some([0x20, 0, 0x80, 1, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0]),
        })
    }
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

fn smoke_nl80211_band_ht_vht_attributes() -> TestResult {
    let iface = InterfaceStub {
        name: "wlan-phy-test",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    };
    let mut info = crate::WirelessNetIface::get_wireless_info(&iface);
    info.bands = alloc::vec![
        crate::iface::WirelessBand {
            freq_mhz: 2400,
            channels: alloc::vec![1, 6, 11]
        },
        crate::iface::WirelessBand {
            freq_mhz: 5000,
            channels: alloc::vec![36, 40]
        },
    ];
    let attrs = wiphy_attrs(7, &info, Some(&iface));
    let bands = find_attr(&attrs, 22 | NLA_F_NESTED).unwrap();
    for band_id in 0..=1 {
        let band = find_attr(bands, band_id | NLA_F_NESTED).unwrap();
        if find_attr(band, 3).is_none_or(|mcs| mcs.len() != 16 || mcs[..2] != [0xff; 2])
            || find_attr(band, 4) != Some(&0x6eu16.to_ne_bytes()[..])
            || find_attr(band, 5) != Some(&[3][..])
            || find_attr(band, 6) != Some(&[4][..])
        {
            return TestResult::Fail("nl80211 HT capability/MCS/AMPDU fields");
        }
        if band_id == 0 {
            if find_attr(band, 7).is_some() || find_attr(band, 8).is_some() {
                return TestResult::Fail("VHT incorrectly advertised in 2.4 GHz band");
            }
        } else if find_attr(band, 7) != Some(&[0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0][..])
            || find_attr(band, 8) != Some(&0x01800020u32.to_ne_bytes()[..])
        {
            return TestResult::Fail("nl80211 VHT capability/MCS fields");
        }
    }
    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_band_ht_vht_attributes);

fn smoke_nl80211_attribute_and_security_validation() -> TestResult {
    let mut bytes = Vec::new();
    push_attr(&mut bytes, 52, b"test");
    push_attr(&mut bytes, 6, &[2, 1, 2, 3, 4, 5]);
    push_attr(&mut bytes, 38, &5180u32.to_ne_bytes());
    if !matches!(
        parse_operation(CONNECT, &attributes(&bytes).unwrap(), true, false),
        Ok(Operation::Connect {
            channel: Some(36),
            cred: Credential::Open,
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
    if parse_operation(CONNECT, &attributes(&bytes).unwrap(), true, false).is_err()
        || parse_operation(CONNECT, &attributes(&bytes).unwrap(), false, false).is_ok()
    {
        return TestResult::Fail("PSK handshake offload gating");
    }
    push_attr(&mut bytes, 66, &2u32.to_ne_bytes());
    if parse_operation(CONNECT, &attributes(&bytes).unwrap(), true, false).is_ok() {
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
    match parse_operation(SCAN, &attributes(&request).unwrap(), true, false).unwrap() {
        Operation::Scan(req)
            if req.active && req.ssids == alloc::vec![Vec::new(), b"hidden".to_vec()] => {}
        _ => return TestResult::Fail("active wildcard/directed scan request lost"),
    }
    if !matches!(
        parse_operation(SCAN, &[], true, false),
        Ok(Operation::Scan(crate::ScanRequest { active: false, .. }))
    ) {
        return TestResult::Fail("passive scan became active");
    }
    request.clear();
    push_attr(&mut request, 52, b"home");
    if !matches!(
        parse_operation(CONNECT, &attributes(&request).unwrap(), true, false),
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
    if select_bss(list.iter(), b"home", None, None, Akm::Psk)
        .unwrap()
        .bssid
        != [4; 6]
        || select_bss(list.iter(), b"home", None, Some(1), Akm::Psk)
            .unwrap()
            .bssid
            != [2; 6]
        || select_bss(list.iter(), b"home", Some([6; 6]), None, Akm::Psk).is_some()
    {
        return TestResult::Fail("connect selection ignored security/BSSID/channel filters");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_active_scan_and_ssid_connect
);

// ── Full supplicant-interoperability walk ─────────────────────────
//
// Replays the exact nl80211 exchange a real wpa_supplicant (via libnl)
// drives against a firmware-SME/offload station, through the production
// `netlink_generic` dispatcher and multicast event sink:
//
//   CTRL_CMD_GETFAMILY("nl80211")  → family id + scan/mlme group ids
//   GET_WIPHY                      → SUPPORTED_COMMANDS + CCMP + 4-way PSK
//   GET_INTERFACE                  → station iftype/MAC/ifindex
//   TRIGGER_SCAN completion        → NEW_SCAN_RESULTS on the scan group
//   GET_SCAN (dump)                → the scanned BSS record
//   CONNECT (WPA2-PSK, PMK)        → CONNECT success event + BSSID
//   DISCONNECT                     → DISCONNECT event with reason code
//
// All command/attribute/group ids and errnos are validated against
// /usr/src/linux include/uapi/linux/nl80211.h (6.17-rc2).

/// An offload-capable station: advertises WPA2-PSK handshake offload, so the
/// PMK connect path (what wpa_supplicant uses with a firmware-SME driver) is
/// exercised, and reports a single WPA2 AP from `scan()`.
struct OffloadStub {
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
const INTEROP_NAME: &str = "wlan-interop";
const INTEROP_MAC: [u8; 6] = [2, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
const INTEROP_BSSID: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const INTEROP_SAE_BSSID: [u8; 6] = [2, 0x66, 0x77, 0x88, 0x99, 0xaa];
impl Interface for OffloadStub {
    fn name(&self) -> &str {
        INTEROP_NAME
    }
    fn mac(&self) -> [u8; 6] {
        INTEROP_MAC
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
impl crate::WirelessNetIface for OffloadStub {
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn supports_sae_offload(&self) -> bool {
        true
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: INTEROP_NAME.into(),
            base_mac: INTEROP_MAC,
            bands: alloc::vec![
                crate::iface::WirelessBand {
                    freq_mhz: 2400,
                    channels: alloc::vec![1, 6, 11],
                },
                crate::iface::WirelessBand {
                    freq_mhz: 5000,
                    channels: alloc::vec![36, 40],
                },
            ],
            modes: crate::iface::WirelessModes::STATION,
            hw_caps: crate::iface::HwCaps {
                ht_supported: true,
                vht_supported: true,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Ok(alloc::vec![
            crate::BssInfo {
                bssid: INTEROP_BSSID,
                ssid: b"narf-ap".to_vec(),
                channel: 36,
                rssi: -42,
                security: crate::scan::BssSecurity::Wpa2,
            },
            crate::BssInfo {
                bssid: INTEROP_SAE_BSSID,
                ssid: b"narf-ap3".to_vec(),
                channel: 40,
                rssi: -45,
                security: crate::scan::BssSecurity::Wpa3,
            },
        ])
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

static INTEROP_EVENTS: IrqSafeSpinLock<Vec<(u64, u32, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
fn interop_sink(net_ns_id: u64, group: u32, message: &[u8]) {
    INTEROP_EVENTS
        .lock()
        .push((net_ns_id, group, message.to_vec()));
}

/// Restore the production multicast sink when the test ends, on every path.
struct SinkRestore(Option<fn(u64, u32, &[u8])>);
impl Drop for SinkRestore {
    fn drop(&mut self) {
        if let Some(previous) = self.0 {
            narf_net::netlink_generic::install_event_sink(previous);
        }
        CACHE.lock().retain(|c| c.name != INTEROP_NAME);
    }
}

/// Frame one generic-netlink request as libnl would: nlmsghdr + genlmsghdr.
fn genl_request(family: u16, command: u8, flags: u16, seq: u32, attrs: &[u8]) -> Vec<u8> {
    let mut body = alloc::vec![command, 1, 0, 0];
    body.extend_from_slice(attrs);
    let len = 16 + body.len();
    let mut out = Vec::with_capacity(align(len));
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&family.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&body);
    out.resize(align(len), 0);
    out
}

/// Extract the u32 payloads of a flat nested attribute set (e.g. the command
/// list inside NL80211_ATTR_SUPPORTED_COMMANDS).
fn nested_u32s(nested: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= nested.len() {
        let len = u16::from_ne_bytes(nested[off..off + 2].try_into().unwrap()) as usize;
        if len < 4 || off + len > nested.len() {
            break;
        }
        if len >= 8 {
            out.push(u32::from_ne_bytes(
                nested[off + 4..off + 8].try_into().unwrap(),
            ));
        }
        off += align(len);
    }
    out
}

fn smoke_nl80211_supplicant_interop() -> TestResult {
    use narf_net::netlink_generic::{build_replies_with_context, install_event_sink, ReplyOptions};
    const NL: u16 = NL80211_FAMILY_ID; // 0x13
    const CTRL: u16 = 0x10; // GENL_ID_CTRL
    const REQUEST: u16 = 1; // NLM_F_REQUEST
    const DUMP: u16 = 0x300; // NLM_F_DUMP (ROOT|MATCH)

    super::register();
    let _restore = SinkRestore(install_event_sink(interop_sink));

    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(OffloadStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(INTEROP_NAME, INTEROP_MAC, |_| Ok(()));
    crate::registry::register(iface.clone());
    let ifindex = match narf_net::netlink_route::ifindex_for_name(INTEROP_NAME) {
        Some(index) => index,
        None => return TestResult::Fail("interop iface has no ifindex"),
    };
    let wiphy = match crate::registry::list()
        .iter()
        .position(|i| i.name() == INTEROP_NAME)
    {
        Some(index) => index as u32,
        None => return TestResult::Fail("interop iface missing from registry"),
    };
    let ctx = RequestContext {
        net_ns_id: 0,
        admin: None,
    };

    // 1. CTRL_CMD_GETFAMILY("nl80211"): family id + scan/mlme group resolution.
    let mut family_name = b"nl80211".to_vec();
    family_name.push(0);
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 2, &family_name); // CTRL_ATTR_FAMILY_NAME
    let request = genl_request(CTRL, 3, REQUEST, 1, &attrs); // CTRL_CMD_GETFAMILY
    let replies = match build_replies_with_context(&request, ReplyOptions::default(), ctx) {
        Ok(replies) if !replies.is_empty() => replies,
        _ => return TestResult::Fail("GETFAMILY(nl80211) returned nothing"),
    };
    let reply = &replies[0];
    if u16::from_ne_bytes(reply[4..6].try_into().unwrap()) != CTRL {
        return TestResult::Fail("GETFAMILY reply not from nlctrl");
    }
    let body = &reply[20..];
    if find_attr(body, 1) != Some(&NL.to_ne_bytes()[..]) {
        return TestResult::Fail("GETFAMILY did not resolve nl80211 family id");
    }
    let groups = match find_attr(body, 7 | NLA_F_NESTED) {
        Some(groups) => groups,
        None => return TestResult::Fail("GETFAMILY lacks CTRL_ATTR_MCAST_GROUPS"),
    };
    let (mut scan_group, mut mlme_group) = (None, None);
    let mut off = 0;
    while off + 4 <= groups.len() {
        let len = u16::from_ne_bytes(groups[off..off + 2].try_into().unwrap()) as usize;
        if len < 4 || off + len > groups.len() {
            break;
        }
        let entry = &groups[off + 4..off + len];
        let name = find_attr(entry, 1).map(|n| n.strip_suffix(&[0]).unwrap_or(n));
        let id = find_attr(entry, 2)
            .filter(|b| b.len() == 4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
        match (name, id) {
            (Some(b"scan"), id) => scan_group = id,
            (Some(b"mlme"), id) => mlme_group = id,
            _ => {}
        }
        off += align(len);
    }
    if scan_group != Some(18) || mlme_group != Some(19) {
        return TestResult::Fail("GETFAMILY mcast group ids mismatch (scan=18, mlme=19)");
    }

    // 2. GET_WIPHY: capabilities wpa_supplicant keys off to pick the PMK path.
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 1, &wiphy.to_ne_bytes()); // NL80211_ATTR_WIPHY
    let request = genl_request(NL, NL80211_CMD_GET_WIPHY, REQUEST, 2, &attrs);
    let replies = match build_replies_with_context(&request, ReplyOptions::default(), ctx) {
        Ok(replies) if !replies.is_empty() => replies,
        _ => return TestResult::Fail("GET_WIPHY returned nothing"),
    };
    let reply = &replies[0];
    if reply[16] != NL80211_CMD_NEW_WIPHY {
        return TestResult::Fail("GET_WIPHY did not return NEW_WIPHY");
    }
    let body = &reply[20..];
    let commands = match find_attr(body, NL80211_ATTR_SUPPORTED_COMMANDS | NLA_F_NESTED) {
        Some(commands) => nested_u32s(commands),
        None => return TestResult::Fail("GET_WIPHY lacks SUPPORTED_COMMANDS"),
    };
    for needed in [33u32, 32, 46, 48] {
        if !commands.contains(&needed) {
            return TestResult::Fail("GET_WIPHY missing a supplicant-required command");
        }
    }
    if find_attr(body, 57) != Some(&0x000fac04u32.to_ne_bytes()[..]) {
        return TestResult::Fail("GET_WIPHY cipher suites not CCMP");
    }
    match find_attr(body, 217) {
        Some(ext) if ext.len() >= 2 && ext[1] & 0x80 != 0 => {}
        _ => return TestResult::Fail("GET_WIPHY missing 4WAY_HANDSHAKE_STA_PSK ext feature"),
    }
    if find_attr(body, 43).is_none() {
        return TestResult::Fail("GET_WIPHY missing MAX_NUM_SCAN_SSIDS");
    }

    // 3. GET_INTERFACE: station-mode identity.
    let mut attrs = Vec::new();
    let mut ifname = INTEROP_NAME.as_bytes().to_vec();
    ifname.push(0);
    push_attr(&mut attrs, NL80211_ATTR_IFNAME, &ifname);
    let request = genl_request(NL, NL80211_CMD_GET_INTERFACE, REQUEST, 3, &attrs);
    let replies = match build_replies_with_context(&request, ReplyOptions::default(), ctx) {
        Ok(replies) if !replies.is_empty() => replies,
        _ => return TestResult::Fail("GET_INTERFACE returned nothing"),
    };
    let reply = &replies[0];
    if reply[16] != NL80211_CMD_NEW_INTERFACE {
        return TestResult::Fail("GET_INTERFACE did not return NEW_INTERFACE");
    }
    let body = &reply[20..];
    if find_attr(body, NL80211_ATTR_IFTYPE) != Some(&NL80211_IFTYPE_STATION.to_ne_bytes()[..]) {
        return TestResult::Fail("GET_INTERFACE iftype not STATION");
    }
    if find_attr(body, NL80211_ATTR_MAC) != Some(&INTEROP_MAC[..]) {
        return TestResult::Fail("GET_INTERFACE MAC mismatch");
    }
    if find_attr(body, NL80211_ATTR_IFINDEX) != Some(&ifindex.to_ne_bytes()[..]) {
        return TestResult::Fail("GET_INTERFACE ifindex mismatch");
    }

    // 4. TRIGGER_SCAN completion → NEW_SCAN_RESULTS (cmd 34) on the scan group.
    CACHE.lock().retain(|c| c.name != INTEROP_NAME);
    CACHE.lock().push(Cache {
        name: INTEROP_NAME.into(),
        namespace: 0,
        busy: true,
        results: Vec::new(),
    });
    INTEROP_EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        narf_net::kernel_admin(INTEROP_NAME).unwrap(),
        0,
        ifindex,
        Operation::Scan(crate::ScanRequest {
            ssids: Vec::new(),
            channels: Vec::new(),
            active: false,
        }),
    ));
    if !INTEROP_EVENTS
        .lock()
        .iter()
        .any(|(ns, group, msg)| *ns == 0 && *group == 18 && msg.get(16) == Some(&34))
    {
        return TestResult::Fail("scan completion did not emit NEW_SCAN_RESULTS on group 18");
    }

    // 5. GET_SCAN (dump) → the BSS record libnl parses.
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    let request = genl_request(NL, 32, REQUEST | DUMP, 4, &attrs); // GET_SCAN
    let replies = match build_replies_with_context(&request, ReplyOptions::default(), ctx) {
        Ok(replies) => replies,
        _ => return TestResult::Fail("GET_SCAN failed"),
    };
    let bss_present = replies.iter().any(|reply| {
        reply.get(16) == Some(&34)
            && find_attr(&reply[20..], 47 | NLA_F_NESTED)
                .and_then(|bss| find_attr(bss, 1)) // NL80211_BSS_BSSID
                == Some(&INTEROP_BSSID[..])
    });
    if !bss_present {
        return TestResult::Fail("GET_SCAN dump missing the scanned BSS");
    }

    // 6. CONNECT (WPA2-PSK offload) → CONNECT (cmd 46) success event with BSSID.
    INTEROP_EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        narf_net::kernel_admin(INTEROP_NAME).unwrap(),
        0,
        ifindex,
        Operation::Connect {
            ssid: b"narf-ap".to_vec(),
            bssid: None,
            channel: None,
            cred: Credential::Psk(Zeroizing::new([0x42u8; 32])),
        },
    ));
    if !INTEROP_EVENTS.lock().iter().any(|(ns, group, msg)| {
        *ns == 0
            && *group == 19
            && msg.get(16) == Some(&46)
            && find_attr(&msg[20..], 72) == Some(&0u16.to_ne_bytes()[..]) // STATUS_CODE = success
            && find_attr(&msg[20..], 6) == Some(&INTEROP_BSSID[..]) // NL80211_ATTR_MAC = BSSID
    }) {
        return TestResult::Fail("CONNECT did not emit a success event with the BSSID");
    }

    // 7. DISCONNECT → DISCONNECT (cmd 48) event with a reason code.
    INTEROP_EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        narf_net::kernel_admin(INTEROP_NAME).unwrap(),
        0,
        ifindex,
        Operation::Disconnect,
    ));
    if !INTEROP_EVENTS.lock().iter().any(|(ns, group, msg)| {
        *ns == 0 && *group == 19 && msg.get(16) == Some(&48) && find_attr(&msg[20..], 54).is_some()
    }) {
        return TestResult::Fail("DISCONNECT did not emit an event with a reason code");
    }

    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_supplicant_interop);

// ── WPA3-SAE (NL80211_EXT_FEATURE_SAE_OFFLOAD) ────────────────────
//
// wpa_supplicant drives WPA3-Personal against an SAE-offload driver by
// issuing CONNECT with AKM=SAE (00-0F-AC:8), SAE auth, required MFP, CCMP,
// and NL80211_ATTR_SAE_PASSWORD(277) instead of a PMK. Attribute/suite
// values are validated against /usr/src/linux nl80211.h / ieee80211.h.

fn smoke_nl80211_wpa3_sae_connect() -> TestResult {
    use narf_net::netlink_generic::install_event_sink;

    // A complete WPA3-SAE CONNECT attribute set.
    let mut sae = Vec::new();
    push_attr(&mut sae, 52, b"narf-ap3"); // SSID
    push_attr(&mut sae, 53, &4u32.to_ne_bytes()); // AUTH_TYPE = SAE
    push_attr(&mut sae, 66, &2u32.to_ne_bytes()); // USE_MFP = REQUIRED
    push_attr(&mut sae, 75, &2u32.to_ne_bytes()); // WPA_VERSIONS = 2 (RSN)
    push_attr(&mut sae, 76, &0x000fac08u32.to_ne_bytes()); // AKM_SUITES = SAE
    push_attr(&mut sae, 73, &0x000fac04u32.to_ne_bytes()); // CIPHER pairwise = CCMP
    push_attr(&mut sae, 74, &0x000fac04u32.to_ne_bytes()); // CIPHER group = CCMP
    push_attr(&mut sae, 277, b"correct horse battery"); // SAE_PASSWORD
    let parsed = attributes(&sae).unwrap();

    // Decoded only when the driver offloads SAE; never silently downgraded.
    if !matches!(
        parse_operation(CONNECT, &parsed, false, true),
        Ok(Operation::Connect {
            cred: Credential::Sae(_),
            ..
        })
    ) {
        return TestResult::Fail("SAE connect not decoded under sae offload");
    }
    if parse_operation(CONNECT, &parsed, true, false).is_ok() {
        return TestResult::Fail("SAE connect accepted without sae offload capability");
    }
    // A SAE password alongside a PMK, or with OPEN-system auth, is contradictory.
    let mut with_pmk = sae.clone();
    push_attr(&mut with_pmk, 254, &[0u8; 32]);
    if parse_operation(CONNECT, &attributes(&with_pmk).unwrap(), true, true).is_ok() {
        return TestResult::Fail("SAE password combined with a PMK accepted");
    }
    let mut open_auth = Vec::new();
    push_attr(&mut open_auth, 52, b"narf-ap3");
    push_attr(&mut open_auth, 53, &0u32.to_ne_bytes()); // AUTH_TYPE = OPEN
    push_attr(&mut open_auth, 66, &2u32.to_ne_bytes());
    push_attr(&mut open_auth, 75, &2u32.to_ne_bytes());
    push_attr(&mut open_auth, 76, &0x000fac08u32.to_ne_bytes());
    push_attr(&mut open_auth, 73, &0x000fac04u32.to_ne_bytes());
    push_attr(&mut open_auth, 74, &0x000fac04u32.to_ne_bytes());
    push_attr(&mut open_auth, 277, b"correct horse battery");
    if parse_operation(CONNECT, &attributes(&open_auth).unwrap(), true, true).is_ok() {
        return TestResult::Fail("SAE password with OPEN-system auth accepted");
    }

    // End to end: SAE association selects the WPA3 BSS and emits a success event.
    super::register();
    let _restore = SinkRestore(install_event_sink(interop_sink));
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(OffloadStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(INTEROP_NAME, INTEROP_MAC, |_| Ok(()));
    crate::registry::register(iface.clone());
    let ifindex = match narf_net::netlink_route::ifindex_for_name(INTEROP_NAME) {
        Some(index) => index,
        None => return TestResult::Fail("sae iface has no ifindex"),
    };
    INTEROP_EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        narf_net::kernel_admin(INTEROP_NAME).unwrap(),
        0,
        ifindex,
        Operation::Connect {
            ssid: b"narf-ap3".to_vec(),
            bssid: None,
            channel: None,
            cred: Credential::Sae(Zeroizing::new(b"correct horse battery".to_vec())),
        },
    ));
    if !INTEROP_EVENTS.lock().iter().any(|(ns, group, msg)| {
        *ns == 0
            && *group == 19
            && msg.get(16) == Some(&46)
            && find_attr(&msg[20..], 72) == Some(&0u16.to_ne_bytes()[..]) // STATUS_CODE = success
            && find_attr(&msg[20..], 6) == Some(&INTEROP_SAE_BSSID[..]) // WPA3 BSSID
    }) {
        return TestResult::Fail("WPA3-SAE connect did not emit a success event with the BSSID");
    }

    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_wpa3_sae_connect);

// A CONNECT targeting a different BSS of the current ESS must route through
// roam() and surface an NL80211_CMD_ROAM (47) event, not CONNECT (46).
const ROAM_NAME: &str = "wlan-roam";
const ROAM_NEW_BSSID: [u8; 6] = [2, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb];
struct RoamStub {
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl Interface for RoamStub {
    fn name(&self) -> &str {
        ROAM_NAME
    }
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 2]
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for RoamStub {
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: ROAM_NAME.into(),
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
    // Already associated to another BSS of this ESS.
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        Some([2, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa])
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Ok(alloc::vec![crate::BssInfo {
            bssid: ROAM_NEW_BSSID,
            ssid: b"roam-net".to_vec(),
            channel: 36,
            rssi: -40,
            security: crate::scan::BssSecurity::Open,
        }])
    }
    // associate() must NOT be used for a roam; fail loudly if it is.
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::HardwareError)
    }
    async fn roam(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        Ok(())
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
}

fn smoke_nl80211_connect_to_new_bss_roams() -> TestResult {
    use narf_net::netlink_generic::install_event_sink;
    super::register();
    let _restore = SinkRestore(install_event_sink(interop_sink));
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(RoamStub {
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(ROAM_NAME, iface.mac(), |_| Ok(()));
    crate::registry::register(iface.clone());
    let ifindex = match narf_net::netlink_route::ifindex_for_name(ROAM_NAME) {
        Some(index) => index,
        None => return TestResult::Fail("roam iface has no ifindex"),
    };
    CACHE.lock().retain(|c| c.name != ROAM_NAME);
    CACHE.lock().push(Cache {
        name: ROAM_NAME.into(),
        namespace: 0,
        busy: true,
        results: Vec::new(),
    });
    INTEROP_EVENTS.lock().clear();
    narf_scheduler::block_on_spin(execute(
        iface.clone(),
        narf_net::kernel_admin(ROAM_NAME).unwrap(),
        0,
        ifindex,
        Operation::Connect {
            ssid: b"roam-net".to_vec(),
            bssid: None,
            channel: None,
            cred: Credential::Open,
        },
    ));
    let roamed = INTEROP_EVENTS.lock().iter().any(|(ns, group, msg)| {
        *ns == 0
            && *group == 19
            && msg.get(16) == Some(&47) // NL80211_CMD_ROAM
            && find_attr(&msg[20..], 72) == Some(&0u16.to_ne_bytes()[..])
            && find_attr(&msg[20..], 6) == Some(&ROAM_NEW_BSSID[..])
    });
    CACHE.lock().retain(|c| c.name != ROAM_NAME);
    if !roamed {
        return TestResult::Fail("CONNECT to a new BSS did not emit a ROAM event");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_connect_to_new_bss_roams);
