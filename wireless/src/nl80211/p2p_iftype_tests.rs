//! Wiphy role subsets must not turn DEVICE support into CLIENT/GO claims.
use super::*;
use crate::WirelessNetIface;

struct Subset {
    base: InterfaceStub,
    p2p: bool,
    types: Vec<u32>,
}
impl Interface for Subset {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.base.mac()
    }
    fn mtu(&self) -> u32 {
        self.base.mtu()
    }
    fn link_up(&self) -> bool {
        self.base.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.base.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.base.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for Subset {
    fn p2p_interface_types(&self) -> Vec<u32> {
        self.types.clone()
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        let mut info = self.base.get_wireless_info();
        if self.p2p {
            info.modes.insert(crate::iface::WirelessModes::P2P);
        }
        info
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
}
fn types(attrs: &[u8]) -> Vec<u16> {
    find_attr(attrs, NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED)
        .map(|nested| {
            attributes(nested)
                .unwrap()
                .into_iter()
                .map(|(kind, _)| kind)
                .collect()
        })
        .unwrap_or_default()
}
fn smoke_nl80211_p2p_wiphy_subset_preserves_defaults_and_refuses_role_invention() -> TestResult {
    let mut iface = Subset {
        base: InterfaceStub {
            name: "p2p-types",
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        },
        p2p: true,
        types: alloc::vec![10],
    };
    let info = iface.get_wireless_info();
    if types(&wiphy_attrs(0, &info, Some(&iface))) != [2, 10] {
        return TestResult::Fail("DEVICE-only P2P wiphy invented a CLIENT/GO role");
    }
    // Preserve existing drivers' default bytes, including the old10/8/9 order.
    if types(&wiphy_attrs(0, &info, Some(&iface.base))) != [2, 10, 8, 9]
        || types(&wiphy_attrs(0, &info, None)) != [2, 10, 8, 9]
    {
        return TestResult::Fail("legacy P2P default/fallback advertisement changed");
    }
    iface.types = alloc::vec![2, 3, 7, 10, 10, u32::MAX, 11, 8, 9, 8];
    if types(&wiphy_attrs(0, &iface.get_wireless_info(), Some(&iface))) != [2, 10, 8, 9] {
        return TestResult::Fail("P2P subset serialized invalid/duplicate interface types");
    }
    iface.types = alloc::vec![9];
    if types(&wiphy_attrs(0, &iface.get_wireless_info(), Some(&iface))) != [2, 9] {
        return TestResult::Fail("P2P subset expanded a single admitted GO role");
    }
    iface.p2p = false;
    iface.types = alloc::vec![8, 9, 10];
    if types(&wiphy_attrs(0, &iface.get_wireless_info(), Some(&iface))) != [2] {
        return TestResult::Fail("P2P subset bypassed the family's actual P2P mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_p2p_wiphy_subset_preserves_defaults_and_refuses_role_invention
);
