//! Actual typed control registration/namespace grants, with no netdev.
//! These boundary fixtures make no native started-wdev or RF-grant claim.
use super::*;
use crate::registry::ControlWdev;
use narf_capabilities::Write;

struct ControlRadio {
    inner: Radio,
    namespace: u64,
    physical: u64,
    metadata: IrqSafeSpinLock<Option<(Cap<narf_net::NetIface, Write>, ControlWdev)>>,
    metadata_releases: AtomicU32,
    retirement_hook: IrqSafeSpinLock<Option<lifecycle::RetirementHook>>,
    successor: IrqSafeSpinLock<Option<lifecycle::Successor>>,
    post_retirement_hold: AtomicBool,
    post_retirement_seen: AtomicBool,
}
impl ControlRadio {
    async fn terminal_callback(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        struct Borrowed<'a>(&'a AtomicU32);
        impl Drop for Borrowed<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let _borrowed = Borrowed(&self.inner.start_drops);
        core::future::poll_fn(|cx| {
            authority.check_for(self)?;
            self.inner.start_polls.fetch_add(1, Ordering::AcqRel);
            if self.inner.start_ready.load(Ordering::Acquire) {
                self.inner.starts.fetch_add(1, Ordering::AcqRel);
                core::task::Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        })
        .await
    }
}
impl Interface for ControlRadio {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        Some(self.namespace)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.inner.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.inner.tx
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for ControlRadio {
    fn async_control_interfaces(&self) -> bool {
        true
    }
    async fn delete_control_interface_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioControlRetirement, WirelessError> {
        self.terminal_callback(authority).await?;
        let cap = self
            .metadata
            .lock()
            .as_ref()
            .map(|(cap, _)| *cap)
            .ok_or(WirelessError::Denied)?;
        let retired = authority.retire_control(&cap)?;
        let hook = { self.retirement_hook.lock().take() };
        if let Some(hook) = hook {
            hook(self)?;
        }
        core::future::poll_fn(|cx| {
            self.post_retirement_seen.store(true, Ordering::Release);
            if self.post_retirement_hold.load(Ordering::Acquire) {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            } else {
                core::task::Poll::Ready(())
            }
        })
        .await;
        Ok(retired)
    }
    fn release_control_metadata(&self) {
        let metadata = { self.metadata.lock().take() };
        if let Some((cap, wdev)) = metadata {
            crate::registry::unregister_control(wdev, self);
            narf_net::registry().unregister_for_handle(&cap);
            self.metadata_releases.fetch_add(1, Ordering::AcqRel);
        }
    }
    fn wiphy_id(&self) -> u64 {
        self.physical
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        let mut info = self.inner.get_wireless_info();
        info.modes = crate::iface::WirelessModes::empty();
        info
    }
    async fn scan(&self, _: crate::ScanRequest) -> Result<Vec<crate::BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    fn current_iftype(&self) -> u32 {
        self.inner.mode.load(Ordering::Acquire)
    }
    fn radio_control_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.inner.generation.load(Ordering::Acquire))
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn ApControlReservation>>, WirelessError> {
        self.inner.serial.try_reserve().map(Some)
    }
    fn async_p2p_device_control(&self) -> bool {
        true
    }
    fn async_roc_control(&self) -> bool {
        true
    }
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        5000
    }
    async fn start_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.terminal_callback(authority).await
    }
    async fn stop_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        self.terminal_callback(authority).await
    }
    async fn remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        _: u64,
        _: u32,
        _: u32,
    ) -> Result<(), WirelessError> {
        self.terminal_callback(authority).await
    }
    async fn cancel_remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        _: u64,
    ) -> Result<(), WirelessError> {
        self.terminal_callback(authority).await
    }
}
struct RegisteredControl(Arc<ControlRadio>);
impl Interface for RegisteredControl {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        self.0.control_namespace()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
struct Child {
    radio: Arc<ControlRadio>,
    iface: Arc<dyn WirelessNetIface>,
    cap: Cap<narf_net::NetIface, Write>,
    admin: AdminHandle,
    registration: ControlWdev,
}
impl Drop for Child {
    fn drop(&mut self) {
        crate::registry::unregister_control(self.registration, self.radio.as_ref());
        narf_net::registry().unregister_for_handle(&self.cap);
    }
}
fn child(parent: &Fixture, name: Option<&str>, namespace: u64) -> Result<Child, &'static str> {
    child_at(parent, name, namespace, false)
}
fn paired_child(parent: &Fixture) -> Result<Child, &'static str> {
    child_at(parent, None, 0, true)
}
fn child_at(
    parent: &Fixture,
    name: Option<&str>,
    namespace: u64,
    paired: bool,
) -> Result<Child, &'static str> {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let name = name
        .map(String::from)
        .unwrap_or_else(|| alloc::format!("p2p-ctl{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let radio = Arc::new(ControlRadio {
        inner: Radio::new(name),
        namespace,
        physical: parent.iface.wiphy_id(),
        metadata: IrqSafeSpinLock::new(None),
        metadata_releases: AtomicU32::new(0),
        retirement_hook: IrqSafeSpinLock::new(None),
        successor: IrqSafeSpinLock::new(None),
        post_retirement_hold: AtomicBool::new(false),
        post_retirement_seen: AtomicBool::new(false),
    });
    radio.inner.mode.store(10, Ordering::Release);
    let grant = narf_net::bootstrap_authority();
    let cap = if paired {
        narf_net::registry().register_control_child(
            &grant,
            &parent.cap,
            RegisteredControl(radio.clone()),
        )
    } else {
        narf_net::registry().register_control(&grant, RegisteredControl(radio.clone()))
    }
    .map_err(|_| "actual control-interface grant registration")?;
    let iface: Arc<dyn WirelessNetIface> = radio.clone();
    let registration = crate::registry::register_control(&parent.iface, iface.clone())
        .map_err(|_| "actual parent-bound control wdev registration")?;
    *radio.metadata.lock() = Some((cap, registration));
    let admin = if paired {
        parent
            .admin
            .control_registered_child(&cap)
            .map_err(|_| "actual parent-bound child delegation")?
            .ok_or("actual child daemon grant missing")?
    } else {
        narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon: parent.daemon,
        })
        .map_err(|_| "actual child-bound delegated administration")?
        .admin
    };
    Ok(Child {
        radio,
        iface,
        cap,
        admin,
        registration,
    })
}
fn bind(child: &Child, source: Arc<Source>) -> Result<RadioControlAuthority, WirelessError> {
    RadioControlAuthority::bind_wdev(
        child.admin.clone(),
        &child.iface,
        child.registration.namespace(),
        child.registration.id(),
        source,
    )
}
fn no_netdev() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = child(&parent, None, 27)?;
    let source = Arc::new(Source(
        AtomicBool::new(true),
        IrqSafeSpinLock::new(Vec::new()),
    ));
    let guard = bind(&child, source)
        .map_err(|_| "actual no-netdev radio guard")?
        .reserve()
        .map_err(|_| "actual child admission lease")?;
    let identity = guard
        .identity()
        .map_err(|_| "actual control wdev identity without IFF_UP")?;
    if !child.registration.current_for(child.radio.as_ref())
        || guard.require_link().is_err()
        || guard.check_for(child.radio.as_ref()).is_err()
        || identity.current().is_err()
        || narf_net::iface::lookup(child.radio.name()).is_some()
        || narf_net::iface::ifindex_of(child.radio.name()).is_some()
        || narf_net::registry()
            .snapshots()
            .iter()
            .any(|iface| iface.name == child.radio.name())
        || child.radio.rx_ring().lock().is_some()
        || child.radio.tx_ring().lock().is_some()
        || child.admin.net_ns_id() != Ok(27)
        || child
            .admin
            .authorize_interface(child.radio.name(), 27)
            .is_err()
        || child
            .admin
            .authorize_interface(child.radio.name(), 0)
            .is_ok()
        || child.admin.set_link(true) != Err(narf_net::stack::AdminError::NoIface)
        || child.admin.set_mtu(1500) != Err(narf_net::stack::AdminError::NoIface)
        || RadioControlAuthority::bind_wdev(
            parent.admin.clone(),
            &child.iface,
            27,
            child.registration.id(),
            parent.source.clone(),
        )
        .is_ok()
    {
        return Err(
            "control wdev invented an Ethernet/UP/index boundary or inherited parent admin",
        );
    }
    let kernel = narf_net::stack::kernel_admin(child.radio.name())
        .ok_or("actual control namespace kernel handle")?;
    if kernel.authorize_interface(child.radio.name(), 27).is_err()
        || kernel.authorize_interface(child.radio.name(), 0).is_ok()
    {
        return Err("control-only kernel namespace authorization escaped actual scope");
    }
    Ok(())
}
fn control_only_wdev_binds_actual_namespace_grants_without_ifindex_or_up() -> TestResult {
    no_netdev().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_wdev_binds_actual_namespace_grants_without_ifindex_or_up
);

fn replacement() -> Result<(), &'static str> {
    let parent = fixture()?;
    let old = child(&parent, None, 27)?;
    let source = Arc::new(Source(
        AtomicBool::new(true),
        IrqSafeSpinLock::new(Vec::new()),
    ));
    let guard = bind(&old, source.clone()).map_err(|_| "original actual control source")?;
    let identity = guard
        .identity()
        .map_err(|_| "original actual control identity")?;
    if !crate::registry::unregister_control(old.registration, old.radio.as_ref())
        || !narf_net::registry().unregister_for_handle(&old.cap)
    {
        return Err("actual old control-object retirement");
    }
    let next = child(&parent, Some(old.radio.name()), 27)?;
    if old.cap.check_live().is_err()
        || next.registration.id() == old.registration.id()
        || guard.current() != Err(WirelessError::Denied)
        || identity.current() != Err(WirelessError::Denied)
        || old.registration.current_for(next.radio.as_ref())
        || crate::registry::unregister_control(old.registration, next.radio.as_ref())
        || narf_net::registry().unregister_for_handle(&old.cap)
        || RadioControlAuthority::bind_wdev(
            old.admin.clone(),
            &next.iface,
            27,
            next.registration.id(),
            source.clone(),
        )
        .is_ok()
        || bind(&next, source).is_err()
    {
        return Err("same name/MAC/mode control rebind revived an old source/grant/identity");
    }
    Ok(())
}
fn control_only_wdev_same_name_mac_mode_rebind_never_retargets_old_caps() -> TestResult {
    replacement().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_wdev_same_name_mac_mode_rebind_never_retargets_old_caps
);

fn current_source() -> Result<(), &'static str> {
    for close in [false, true] {
        let parent = fixture()?;
        let child = child(&parent, None, 27)?;
        let source = Arc::new(Source(
            AtomicBool::new(true),
            IrqSafeSpinLock::new(Vec::new()),
        ));
        let guard = bind(&child, source.clone()).map_err(|_| "current actual child source")?;
        let identity = guard.identity().map_err(|_| "actual child observation")?;
        if crate::registry::control_by_id(child.registration.id(), 0).is_some()
            || RadioControlAuthority::bind_wdev(
                child.admin.clone(),
                &child.iface,
                0,
                child.registration.id(),
                source.clone(),
            )
            .is_ok()
            || RadioControlAuthority::bind(child.admin.clone(), &child.iface, 27, 1, source.clone())
                .is_ok()
        {
            return Err("control wdev accepted another namespace or fabricated ifindex");
        }
        if close {
            source.0.store(false, Ordering::Release);
        } else {
            parent.daemon.revoke();
        }
        if guard.current() != Err(WirelessError::Denied) || identity.current().is_err() {
            return Err("control identity observation replaced actual current source invocation");
        }
    }
    Ok(())
}
fn control_only_wdev_rechecks_exact_source_current_grants_and_namespace() -> TestResult {
    current_source().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_wdev_rechecks_exact_source_current_grants_and_namespace
);

fn query(child: &Child, namespace: u64, command: u8) -> Result<Vec<Vec<u8>>, &'static str> {
    use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};
    let _ = crate::nl80211::register();
    let mut message = alloc::vec![0u8;32];
    message[..4].copy_from_slice(&32u32.to_ne_bytes());
    message[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message[6..8].copy_from_slice(&1u16.to_ne_bytes());
    message[8..12].copy_from_slice(&0x7610u32.to_ne_bytes());
    message[16] = command;
    message[17] = 1;
    message[20..22].copy_from_slice(&12u16.to_ne_bytes());
    message[22..24].copy_from_slice(&153u16.to_ne_bytes());
    message[24..32].copy_from_slice(&child.registration.id().to_ne_bytes());
    build_replies_with_endpoint(
        &message,
        ReplyOptions::default(),
        RequestContext {
            net_ns_id: namespace,
            ..RequestContext::default()
        },
        Arc::new(Source(
            AtomicBool::new(true),
            IrqSafeSpinLock::new(Vec::new()),
        )),
    )
    .map_err(|_| "actual control-WDEV generic netlink discovery")
}
fn value(mut attrs: &[u8], kind: u16) -> Option<&[u8]> {
    while attrs.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes(attrs[..2].try_into().ok()?));
        let found = u16::from_ne_bytes(attrs[2..4].try_into().ok()?);
        if len < 4 || len > attrs.len() {
            return None;
        }
        if found == kind {
            return Some(&attrs[4..len]);
        }
        attrs = attrs.get((len + 3) & !3..)?;
    }
    None
}
fn discovery() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = child(&parent, None, 27)?;
    let replies = query(&child, 27, 5)?;
    let message = replies
        .iter()
        .find(|message| message.len() >= 20 && message[16] == 7)
        .ok_or("actual GET_INTERFACE by opaque WDEV")?;
    let attrs = &message[20..];
    if value(attrs, 3).is_some()
        || value(attrs, 153) != Some(&child.registration.id().to_ne_bytes())
        || value(attrs, 5) != Some(&10u32.to_ne_bytes())
        || query(&child, 0, 5)?
            .iter()
            .any(|message| message.len() >= 20 && message[16] == 7)
    {
        return Err(
            "control-WDEV discovery invented IFINDEX or ignored actual namespace/opaque ID",
        );
    }
    if !query(&child, 27, 1)?
        .iter()
        .any(|message| message.len() >= 20 && message[16] == 3)
    {
        return Err("control-WDEV did not resolve its real parent wiphy");
    }
    crate::registry::unregister_control(child.registration, child.radio.as_ref());
    if query(&child, 27, 5)?
        .iter()
        .any(|message| message.len() >= 20 && message[16] == 7)
    {
        return Err("retired control-WDEV ID selected a current successor/netdev");
    }
    Ok(())
}
fn control_only_wdev_actual_nl80211_discovery_has_no_fabricated_ifindex() -> TestResult {
    discovery().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_only_wdev_actual_nl80211_discovery_has_no_fabricated_ifindex
);

#[path = "control_child_tests.rs"]
mod delegation;
#[path = "p2p_dispatch_tests.rs"]
mod dispatch;
#[path = "control_lifecycle_tests.rs"]
pub(super) mod lifecycle;
