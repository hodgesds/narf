//! Per-family WoW bounds through actual generic-netlink GET/SET routing.
use super::*;

struct Data {
    base: InterfaceStub,
    config: IrqSafeSpinLock<Option<crate::WowlanConfig>>,
    sets: AtomicU32,
    matches: u8,
}
struct DefaultProfile(Data);
struct ConnacProfile(Data);

macro_rules! profile {
    ($name:ident, $($extra:tt)*) => {
        impl Interface for $name {
            fn name(&self) -> &str { self.0.base.name() }
            fn mac(&self) -> [u8; 6] { self.0.base.mac() }
            fn mtu(&self) -> u32 { 1500 }
            fn link_up(&self) -> bool { false }
            fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> { &self.0.base.rx }
            fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> { &self.0.base.tx }
        }
        #[async_trait::async_trait]
        impl crate::WirelessNetIface for $name {
            fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
                crate::WirelessNetIface::get_wireless_info(&self.0.base)
            }
            async fn scan(&self, _: crate::ScanRequest) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
                Err(crate::WirelessError::NotSupported)
            }
            async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
                Err(crate::WirelessError::NotSupported)
            }
            async fn disassociate(&self) -> Result<(), crate::WirelessError> { Ok(()) }
            async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
                Err(crate::WirelessError::NotSupported)
            }
            fn wowlan_support(&self) -> Option<crate::WowlanSupport> {
                Some(crate::WowlanSupport {
                    net_detect_max_match_sets: self.0.matches,
                    net_detect_random_mac: true,
                    ..crate::WowlanSupport::default()
                })
            }
            fn set_wowlan(&self, config: Option<crate::WowlanConfig>) -> Result<(), i32> {
                *self.0.config.lock() = config;
                self.0.sets.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn wowlan_config(&self) -> Option<crate::WowlanConfig> { self.0.config.lock().clone() }
            $($extra)*
        }
    };
}
profile!(DefaultProfile,);
profile!(
    ConnacProfile,
    fn wowlan_net_detect_limits(&self) -> Option<crate::SchedScanSupport> {
        Some(crate::SchedScanSupport {
            max_match_sets: 10,
            max_ssids: 10,
            max_ie_len: 512,
            max_scan_plans: 1,
            max_plan_interval_secs: 65535,
            max_plan_iterations: 0,
            max_frequencies: 64,
            random_mac: true,
        })
    }
);

fn data(name: &'static str, matches: u8) -> Data {
    Data {
        base: InterfaceStub {
            name,
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        },
        config: IrqSafeSpinLock::new(None),
        sets: AtomicU32::new(0),
        matches,
    }
}

fn query(command: u8, attrs: &[u8]) -> Option<Vec<u8>> {
    let replies = build_replies_with_context(
        &message(command, attrs),
        ReplyOptions::default(),
        RequestContext::default(),
    )
    .ok()?;
    replies
        .into_iter()
        .find(|reply| {
            reply.len() >= 20 && u16::from_ne_bytes([reply[4], reply[5]]) == NL80211_FAMILY_ID
        })
        .map(|reply| reply[20..].to_vec())
}

fn request(index: u32, ssid_count: u16, interval: u32, two_plans: bool) -> Vec<u8> {
    let mut match_ssid = Vec::new();
    push_attr(&mut match_ssid, 1, b"narf");
    let mut matches = Vec::new();
    push_attr(&mut matches, 1 | NLA_F_NESTED, &match_ssid);
    let mut scan = Vec::new();
    push_attr(&mut scan, 132 | NLA_F_NESTED, &matches);
    if ssid_count != 0 {
        let mut ssids = Vec::new();
        for entry in 1..=ssid_count {
            push_attr(&mut ssids, entry, b"narf");
        }
        push_attr(&mut scan, 45 | NLA_F_NESTED, &ssids);
    }
    let mut first = Vec::new();
    push_attr(&mut first, 1, &interval.to_ne_bytes());
    if two_plans {
        push_attr(&mut first, 2, &2u32.to_ne_bytes());
    }
    let mut plans = Vec::new();
    push_attr(&mut plans, 1 | NLA_F_NESTED, &first);
    if two_plans {
        let mut second = Vec::new();
        push_attr(&mut second, 1, &60u32.to_ne_bytes());
        push_attr(&mut plans, 2 | NLA_F_NESTED, &second);
    }
    push_attr(&mut scan, 225 | NLA_F_NESTED, &plans);
    let mut triggers = Vec::new();
    push_attr(&mut triggers, 17 | NLA_F_NESTED, &scan);
    with_ifindex(index, &[(117 | NLA_F_NESTED, &triggers)])
}

fn family_limits() -> Result<(), &'static str> {
    register();
    let default = Arc::new(DefaultProfile(data("wow-default-limits", 16)));
    let connac = Arc::new(ConnacProfile(data("wow-connac-limits", 10)));
    let _default_cleanup = CacheNetdev("wow-default-limits");
    let _connac_cleanup = CacheNetdev("wow-connac-limits");
    for iface in [
        default.clone() as Arc<dyn crate::WirelessNetIface>,
        connac.clone(),
    ] {
        narf_net::iface::register(iface.name(), iface.mac(), |_, _| Ok(()));
        crate::registry::register(iface);
    }
    let default_index =
        narf_net::netlink_route::ifindex_for_name(default.name()).ok_or("default ifindex")?;
    let connac_index =
        narf_net::netlink_route::ifindex_for_name(connac.name()).ok_or("CONNAC ifindex")?;
    for (index, ssids, matches, plans, interval, iterations) in [
        (default_index, 16u8, 16u8, 2u32, 7200u32, 100u32),
        (connac_index, 10u8, 10u8, 1u32, 65535u32, 0u32),
    ] {
        let attrs =
            query(NL80211_CMD_GET_WIPHY, &with_ifindex(index, &[])).ok_or("GET_WIPHY reply")?;
        if find_attr(&attrs, 123) != Some(&[ssids][..])
            || find_attr(&attrs, 133) != Some(&[matches][..])
            || find_attr(&attrs, 222) != Some(&plans.to_ne_bytes()[..])
            || find_attr(&attrs, 223) != Some(&interval.to_ne_bytes()[..])
            || find_attr(&attrs, 224) != Some(&iterations.to_ne_bytes()[..])
        {
            return Err("GET_WIPHY substituted another family's NET_DETECT limits");
        }
    }
    if send(74, &request(default_index, 11, 30, true)) != 0
        || send(74, &request(connac_index, 11, 30, false)) != EINVAL
        || send(74, &request(connac_index, 10, 30, true)) != EINVAL
        || send(74, &request(default_index, 10, 65535, false)) != EINVAL
        || send(74, &request(connac_index, 10, 65535, false)) != 0
        || send(74, &request(connac_index, 10, 65536, false)) != EINVAL
        || default.0.sets.load(Ordering::Relaxed) != 1
        || connac.0.sets.load(Ordering::Relaxed) != 1
    {
        return Err("SET_WOWLAN did not enforce independent family limits before mutation");
    }
    let reply = query(73, &with_ifindex(connac_index, &[])).ok_or("GET_WOWLAN roundtrip")?;
    let triggers = find_attr(&reply, 117 | NLA_F_NESTED).ok_or("GET_WOWLAN trigger nesting")?;
    if find_attr(triggers, 17 | NLA_F_NESTED).is_none()
        || connac
            .0
            .config
            .lock()
            .as_ref()
            .and_then(|config| config.net_detect.as_ref())
            .is_none_or(|nd| nd.probe_ssids.len() != 10 || nd.plans[0].interval_secs != 65535)
    {
        return Err("GET_WOWLAN lost the admitted family's native request");
    }
    Ok(())
}

fn nl80211_net_detect_get_set_preserves_default_and_connac_family_limits() -> TestResult {
    family_limits().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    nl80211_net_detect_get_set_preserves_default_and_connac_family_limits
);
