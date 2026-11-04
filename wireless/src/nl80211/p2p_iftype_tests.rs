//! Wiphy role subsets must not turn DEVICE support into CLIENT/GO claims.
use super::*;
use crate::WirelessNetIface;

struct Subset {
    base: InterfaceStub,
    p2p: bool,
    types: Vec<u32>,
    power: bool,
    generation: bool,
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
    fn supports_ap(&self) -> bool {
        true
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        if self.generation {
            core::num::NonZeroU64::new(1)
        } else {
            None
        }
    }
    fn supports_p2p_go_power_save(&self) -> bool {
        self.power
    }
    fn nl80211_feature_flags(&self) -> u32 {
        // A legacy feature word cannot confer the separately implemented
        // native GO PS contract. The unrelated flag must remain unchanged.
        (1 << 11) | (1 << 12) | (1 << 17)
    }
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
        power: false,
        generation: true,
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

fn smoke_nl80211_go_power_advertisement_requires_native_role_and_optin() -> TestResult {
    let mut iface = Subset {
        base: InterfaceStub {
            name: "go-power-types",
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        },
        p2p: true,
        types: alloc::vec![9],
        power: false,
        generation: true,
    };
    for variant in 0..5 {
        iface.power = variant != 0;
        iface.types = if variant == 2 {
            alloc::vec![10]
        } else {
            alloc::vec![9]
        };
        iface.p2p = variant != 3;
        iface.generation = variant != 4;
        let mut security = Vec::new();
        wiphy_security_attrs(&mut security, &iface);
        let flags = find_attr(&security, 143)
            .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
            .map(u32::from_ne_bytes)
            .unwrap_or(0);
        let attrs = wiphy_attrs(0, &iface.get_wireless_info(), Some(&iface));
        let commands = find_attr(&attrs, NL80211_ATTR_SUPPORTED_COMMANDS | NLA_F_NESTED)
            .map(|raw| {
                attributes(raw)
                    .unwrap()
                    .iter()
                    .any(|(_, raw)| *raw == 25u32.to_ne_bytes())
            })
            .unwrap_or(false);
        let expected = variant == 1;
        if (flags & ((1 << 11) | (1 << 12)) == ((1 << 11) | (1 << 12))) != expected
            || (!expected && flags & ((1 << 11) | (1 << 12)) != 0)
            || flags & (1 << 17) == 0
            || commands != expected
        {
            return TestResult::Fail(
                "GO power flags/SET_BSS invented native role, generation or opt-in",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_go_power_advertisement_requires_native_role_and_optin
);

/// A radio with the control-only opt-in and an optional iftype mask.
struct Routed {
    base: InterfaceStub,
    optin: bool,
    mask: Option<u32>,
}
impl Interface for Routed {
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
impl crate::WirelessNetIface for Routed {
    fn async_control_interfaces(&self) -> bool {
        self.optin
    }
    fn async_control_iftypes(&self) -> u32 {
        self.mask.unwrap_or(u32::MAX)
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        self.base.get_wireless_info()
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

fn smoke_nl80211_async_control_iftype_mask_preserves_default_dispatch() -> TestResult {
    let stub = |name| InterfaceStub {
        name,
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    };
    // The trait defaults (no opt-in, full mask) keep every iftype legacy.
    let legacy = stub("route-legacy");
    if legacy.async_control_iftypes() != u32::MAX
        || [2, 3, 8, 9, 10, 31, 32, u32::MAX]
            .iter()
            .any(|&iftype| super::super::routes_async_control(&legacy, iftype))
    {
        return TestResult::Fail("default radio left the legacy NEW/DEL_INTERFACE path");
    }
    // An opted-in radio without a mask (iwlwifi, mt76) routes every iftype
    // async, exactly as `async_control_interfaces()` alone did.
    let all = Routed {
        base: stub("route-all"),
        optin: true,
        mask: None,
    };
    if [2, 3, 8, 9, 10, 31, 32, u32::MAX]
        .iter()
        .any(|&iftype| !super::super::routes_async_control(&all, iftype))
    {
        return TestResult::Fail("default iftype mask changed opted-in radios' dispatch");
    }
    // A DEVICE-only mask (brcmfmac) routes only iftype 10 async.
    let device = Routed {
        base: stub("route-device"),
        optin: true,
        mask: Some(1 << 10),
    };
    if !super::super::routes_async_control(&device, 10)
        || [2, 3, 8, 9, 32, u32::MAX]
            .iter()
            .any(|&iftype| super::super::routes_async_control(&device, iftype))
    {
        return TestResult::Fail("P2P_DEVICE-only mask routed another iftype async");
    }
    // The mask never grants async routing without the opt-in.
    let masked_off = Routed {
        base: stub("route-off"),
        optin: false,
        mask: Some(1 << 10),
    };
    if super::super::routes_async_control(&masked_off, 10) {
        return TestResult::Fail("iftype mask bypassed the async control opt-in");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_async_control_iftype_mask_preserves_default_dispatch
);
