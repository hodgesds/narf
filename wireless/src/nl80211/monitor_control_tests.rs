//! Literal monitor nl80211 admission through the real generic-netlink router.
use super::*;
use crate::{monitor::Channel, WirelessError, WirelessNetIface};
struct MonitorIface {
    base: InterfaceStub,
    mode: AtomicU32,
    selected: IrqSafeSpinLock<Option<Channel>>,
}
impl Interface for MonitorIface {
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
impl WirelessNetIface for MonitorIface {
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        let mut info = WirelessNetIface::get_wireless_info(&self.base);
        info.modes = crate::iface::WirelessModes::STATION | crate::iface::WirelessModes::MONITOR;
        info
    }
    async fn scan(&self, _: crate::ScanRequest) -> Result<Vec<crate::BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Ok(())
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    fn current_iftype(&self) -> u32 {
        self.mode.load(Ordering::Acquire)
    }
    fn set_iftype(&self, mode: u32) -> Result<(), WirelessError> {
        self.mode.store(mode, Ordering::Release);
        Ok(())
    }
    fn set_monitor_channel(&self, channel: Channel) -> Result<(), WirelessError> {
        *self.selected.lock() = Some(channel);
        Ok(())
    }
}
fn send_in(command: u8, attrs: &[u8], context: RequestContext<'_>) -> i32 {
    let replies =
        build_replies_with_context(&message(command, attrs), ReplyOptions::default(), context)
            .unwrap();
    let first = &replies[0];
    if u16::from_ne_bytes(first[4..6].try_into().unwrap()) == 2 {
        -i32::from_ne_bytes(first[16..20].try_into().unwrap())
    } else {
        0
    }
}
fn check() -> Result<(), &'static str> {
    register();
    const MON_NAME: &str = "wlan-monitor-control";
    let monitor = Arc::new(MonitorIface {
        base: InterfaceStub {
            name: MON_NAME,
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        },
        mode: AtomicU32::new(2),
        selected: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(MON_NAME, monitor.mac(), |_, _| Ok(()));
    crate::registry::register(monitor.clone());
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            crate::registry::unregister(MON_NAME);
            narf_net::iface::unregister(MON_NAME);
        }
    }
    let _cleanup = Cleanup;
    let index = narf_net::iface::ifindex_of(MON_NAME).ok_or("monitor control ifindex")?;
    let mode = with_ifindex(index, &[(5, &6u32.to_ne_bytes())]);
    if send_in(6, &mode, RequestContext::default()) != 1 || monitor.current_iftype() != 2 {
        return Err("unprivileged SET_INTERFACE changed monitor mode");
    }
    for flag in [1u16, 2, 3, 4, 5, 6, 7] {
        let mut nested = Vec::new();
        push_attr(&mut nested, flag, &[]);
        if send(
            6,
            &with_ifindex(index, &[(5, &6u32.to_ne_bytes()), (23, &nested)]),
        ) != EOPNOTSUPP
            || monitor.current_iftype() != 2
        {
            return Err("unsupported monitor FCS/control/active/injection flags were ignored or changed mode");
        }
    }
    if send(
        6,
        &with_ifindex(index, &[(5, &6u32.to_ne_bytes()), (23, &[])]),
    ) != EOPNOTSUPP
        || send(6, &mode) != 0
        || monitor.current_iftype() != 6
    {
        return Err("default monitor mode or explicit unsupported flags");
    }
    let channel = with_ifindex(
        index,
        &[
            (38, &5180u32.to_ne_bytes()),
            (159, &3u32.to_ne_bytes()),
            (160, &5210u32.to_ne_bytes()),
        ],
    );
    if send_in(2, &channel, RequestContext::default()) != 1 || monitor.selected.lock().is_some() {
        return Err("unprivileged monitor channel wrote configuration");
    }
    if send(2, &channel) != 0
        || *monitor.selected.lock()
            != Some(Channel {
                frequency_mhz: 5180,
                width: 3,
                center1_mhz: 5210,
                center2_mhz: 0,
            })
    {
        return Err("monitor channel primary/width/center wire fields lost");
    }
    if send(2, &with_ifindex(index, &[(159, &3u32.to_ne_bytes())])) != EINVAL {
        return Err("monitor center/width without primary frequency accepted");
    }
    monitor.mode.store(2, Ordering::Release);
    if send(2, &channel) != EOPNOTSUPP {
        return Err("station accepted monitor channel control");
    }
    Ok(())
}
fn smoke_monitor_nl80211_mode_and_channel_require_authority_and_reject_flags() -> TestResult {
    check().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_monitor_nl80211_mode_and_channel_require_authority_and_reject_flags
);
