//! The public multi-link (MLO) station surface: WIPHY_FLAG_SUPPORTS_MLO,
//! the station EML/MLD iftype capabilities, CONNECT's MLO_SUPPORT flag
//! (`CONNECT_REQ_MLO_SUPPORT`) and MLO link reporting in GET_INTERFACE,
//! the CONNECT event and GET_STATION (nl80211.c `nl80211_send_wiphy`,
//! `nl80211_send_iface`, `nl80211_send_connect_result`,
//! `nl80211_send_station`).
use super::*;

const AP_MLD: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 0x10];
const LINK0_AP: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 0x01];
const LINK1_AP: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 0x02];
const LINK2_AP: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 0x03];
const OWN0: [u8; 6] = [0x02, 0xbb, 0, 0, 0, 0x01];
const OWN1: [u8; 6] = [0x06, 0xbb, 0, 0, 0, 0x02];
const OWN2: [u8; 6] = [0x06, 0xbb, 0, 0, 0, 0x03];

fn connection() -> crate::MloConnection {
    crate::MloConnection {
        ap_mld: AP_MLD,
        assoc_link_id: 1,
        links: alloc::vec![
            crate::MloLink {
                link_id: 0,
                address: OWN1,
                bssid: LINK1_AP,
                status: 0,
                channel: Some(crate::LinkChannel {
                    frequency_mhz: 2437,
                    width: 2,
                    center_freq1_mhz: 2447,
                    center_freq2_mhz: 0,
                }),
            },
            crate::MloLink {
                link_id: 1,
                address: OWN0,
                bssid: LINK0_AP,
                status: 0,
                channel: Some(crate::LinkChannel {
                    frequency_mhz: 5180,
                    width: 3,
                    center_freq1_mhz: 5210,
                    center_freq2_mhz: 0,
                }),
            },
            crate::MloLink {
                link_id: 2,
                address: OWN2,
                bssid: LINK2_AP,
                status: 37, // WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS
                channel: None,
            },
        ],
    }
}

struct MloIface {
    base: InterfaceStub,
}
impl Interface for MloIface {
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
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.base.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.base.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for MloIface {
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
    fn supports_mlo(&self) -> bool {
        true
    }
    fn iftype_extended_capabilities(&self) -> Vec<crate::IftypeExtendedCapability> {
        alloc::vec![crate::IftypeExtendedCapability {
            iftype: 2,
            capabilities: Vec::new(),
            mask: Vec::new(),
            eml_capabilities: crate::association::mlo::EmlCapabilities::INTEL_MLD_LOCAL.0,
            mld_capa_and_ops: 0,
            ext_mld_capa_and_ops: 0,
        }]
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        Some(LINK0_AP)
    }
    fn mlo_connection(&self) -> Option<crate::MloConnection> {
        Some(connection())
    }
}

fn nested(attrs: &[u8], kind: u16) -> Option<&[u8]> {
    crate::nl80211::find_attr(attrs, kind | NLA_F_NESTED)
}

fn smoke_nl80211_mlo_wiphy_connect_and_link_reporting() -> TestResult {
    let mlo = MloIface {
        base: InterfaceStub {
            name: "wifi-mlo-pub",
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        },
    };
    let plain = InterfaceStub {
        name: "wifi-mlo-plain",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    };
    let find = crate::nl80211::find_attr;

    // GET_WIPHY: NL80211_ATTR_MLO_SUPPORT and the station EML/MLD values.
    let info = crate::WirelessNetIface::get_wireless_info(&mlo);
    let wiphy = crate::nl80211::wiphy_attrs(0, &info, Some(&mlo));
    if find(&wiphy, 315) != Some(&[][..]) {
        return TestResult::Fail("MLO wiphy lacks NL80211_ATTR_MLO_SUPPORT");
    }
    let Some(record) = find(&wiphy, 230).and_then(|records| find(records, 0)) else {
        return TestResult::Fail("MLO wiphy lacks the station IFTYPE_EXT_CAPA record");
    };
    if find(record, 5) != Some(&2u32.to_ne_bytes()[..])
        || find(record, 317) != Some(&0x0033u16.to_ne_bytes()[..])
        || find(record, 318) != Some(&0u16.to_ne_bytes()[..])
        || find(record, 337).is_some()
    {
        return TestResult::Fail("station EML/MLD capabilities differ from IWL_MLD_EMLSR_CAPA");
    }
    let info = crate::WirelessNetIface::get_wireless_info(&plain);
    let wiphy = crate::nl80211::wiphy_attrs(0, &info, Some(&plain));
    if find(&wiphy, 315).is_some() {
        return TestResult::Fail("non-MLO wiphy advertised NL80211_ATTR_MLO_SUPPORT");
    }

    // CONNECT: MLO_SUPPORT is an empty flag routed as CONNECT_REQ_MLO_SUPPORT.
    let base: [(u16, &[u8]); 2] = [(52, b"mld-net"), (38, &5180u32.to_ne_bytes())];
    let mut with = base.to_vec();
    with.push((315, &[]));
    if !matches!(
        parse_operation(CONNECT, &with, true, false),
        Ok(Operation::Connect { mlo: true, .. })
    ) || !matches!(
        parse_operation(CONNECT, &base, true, false),
        Ok(Operation::Connect { mlo: false, .. })
    ) {
        return TestResult::Fail("CONNECT MLO_SUPPORT flag not decoded");
    }
    let mut bad = base.to_vec();
    bad.push((315, &[1]));
    if parse_operation(CONNECT, &bad, true, false).err() != Some(EINVAL) {
        return TestResult::Fail("CONNECT MLO_SUPPORT with a payload accepted");
    }

    // GET_INTERFACE: one entry (link_id + 1) per valid link only.
    let iface = crate::nl80211::interface_attrs(0, &mlo, 2);
    let Some(links) = nested(&iface, 312) else {
        return TestResult::Fail("GET_INTERFACE lacks NL80211_ATTR_MLO_LINKS");
    };
    let (Some(first), Some(second)) = (nested(links, 1), nested(links, 2)) else {
        return TestResult::Fail("GET_INTERFACE MLO link entries not keyed link_id + 1");
    };
    if nested(links, 3).is_some()
        || find(first, 313) != Some(&[0][..])
        || find(first, 6) != Some(&OWN1[..])
        || find(first, 38) != Some(&2437u32.to_ne_bytes()[..])
        || find(first, 39) != Some(&3u32.to_ne_bytes()[..]) // HT40PLUS
        || find(first, 159) != Some(&2u32.to_ne_bytes()[..])
        || find(first, 160) != Some(&2447u32.to_ne_bytes()[..])
        || find(second, 313) != Some(&[1][..])
        || find(second, 6) != Some(&OWN0[..])
        || find(second, 39).is_some()
        || find(second, 159) != Some(&3u32.to_ne_bytes()[..])
        || find(second, 160) != Some(&5210u32.to_ne_bytes()[..])
        || find(second, 161).is_some()
    {
        return TestResult::Fail("GET_INTERFACE MLO link id/address/chandef");
    }
    if nested(&crate::nl80211::interface_attrs(0, &plain, 2), 312).is_some() {
        return TestResult::Fail("non-MLO GET_INTERFACE reported MLO links");
    }

    // CONNECT event: every requested link numbered from 1 with its status.
    let mut event = Vec::new();
    crate::nl80211::push_connect_mlo_links(&mut event, &connection());
    let Some(links) = nested(&event, 312) else {
        return TestResult::Fail("CONNECT event lacks NL80211_ATTR_MLO_LINKS");
    };
    let Some(rejected) = nested(links, 3) else {
        return TestResult::Fail("CONNECT event omitted the rejected requested link");
    };
    if nested(links, 1).and_then(|e| find(e, 245)) != Some(&LINK1_AP[..])
        || nested(links, 2).and_then(|e| find(e, 72)) != Some(&0u16.to_ne_bytes()[..])
        || find(rejected, 313) != Some(&[2][..])
        || find(rejected, 245) != Some(&LINK2_AP[..])
        || find(rejected, 6) != Some(&OWN2[..])
        || find(rejected, 72) != Some(&37u16.to_ne_bytes()[..])
    {
        return TestResult::Fail("CONNECT event MLO link BSSID/address/status");
    }

    // GET_STATION mlo_params_valid: association link id and AP MLD.
    let mut station = Vec::new();
    crate::nl80211::push_station_mlo_params(&mut station, &connection());
    if find(&station, 313) != Some(&[1][..]) || find(&station, 314) != Some(&AP_MLD[..]) {
        return TestResult::Fail("GET_STATION MLO link id / MLD address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_mlo_wiphy_connect_and_link_reporting
);
