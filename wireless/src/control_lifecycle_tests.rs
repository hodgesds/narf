//! Real NEW/DEL dispatch, registration and exact-socket terminal ownership.
//! Held callbacks model only the shared boundary; native MCU tests are separate.
use super::*;
use alloc::sync::Weak;
use narf_net::netlink_generic::{
    build_replies_with_endpoint, DeferredReplySink, ReplyOptions, RequestContext,
};
#[derive(Clone)]
pub(in crate::ap_control::tests) struct Factory {
    parent: Weak<dyn WirelessNetIface>,
    cap: Cap<narf_net::NetIface, Write>,
    children: Arc<IrqSafeSpinLock<Vec<Arc<ControlRadio>>>>,
}
pub(super) type RetirementHook = fn(&ControlRadio) -> Result<(), WirelessError>;
pub(super) struct Successor {
    radio: Arc<Radio>,
    iface: Arc<dyn WirelessNetIface>,
    admin: AdminHandle,
    ifindex: u32,
    _owner: crate::nl80211::ConnectionOwnerFixture,
    _binding: Binding,
}
fn seed_successor(child: &ControlRadio) -> Result<(), WirelessError> {
    // The old control entry has already been withdrawn. Register an actual
    // unrelated ordinary station with the same name before old DEL returns.
    let name = narf_net::iface::register(child.name(), [2, 0, 0, 0, 0x76, 0x41], reject);
    let binding = Binding(name.clone());
    let radio = Arc::new(Radio::new(name));
    radio.mode.store(2, Ordering::Release);
    let iface: Arc<dyn WirelessNetIface> = radio.clone();
    let cap = narf_net::registry()
        .register(&narf_net::bootstrap_authority(), Registered(radio.clone()))
        .map_err(|_| WirelessError::Denied)?;
    let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
    let admin =
        narf_net::stack::control_registered(&narf_net::stack::StackAttach { iface: cap, daemon })
            .map_err(|_| WirelessError::Denied)?
            .admin;
    crate::registry::register(iface.clone());
    admin.set_link(true).map_err(|_| WirelessError::Denied)?;
    let ifindex = narf_net::iface::lookup(radio.name())
        .ok_or(WirelessError::Denied)?
        .ifindex;
    let owner = crate::nl80211::__connection_owner_for_test(
        radio.name(),
        0,
        0x7611,
        [2, 0, 0, 0, 0x76, 0x42],
    );
    let source = Arc::new(Source::new());
    let events = RadioControlAuthority::bind(admin.clone(), &iface, 0, ifindex, source)?
        .event_authority()?;
    // Supply one explicit BSS to the production typed cache update; this
    // fixture tests metadata ownership and makes no native scan claim.
    events.scheduled_scan_results_with_bss(alloc::vec![(
        crate::BssInfo {
            bssid: [2, 0, 0, 0, 0x76, 0x42],
            ssid: b"successor-cache".to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            rssi: -43,
            security: crate::scan::BssSecurity::Open,
        },
        Vec::new()
    )])?;
    let successor = Successor {
        radio,
        iface,
        admin,
        ifindex,
        _owner: owner,
        _binding: binding,
    };
    let previous = { child.successor.lock().replace(successor) };
    drop(previous);
    Ok(())
}
impl Successor {
    fn query(&self, command: u8, flags: u16) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut attrs = Vec::new();
        dispatch::attr(&mut attrs, 3, &self.ifindex.to_ne_bytes());
        let request = message(command, flags, attrs);
        build_replies_with_endpoint(
            &request,
            ReplyOptions::default(),
            RequestContext {
                admin: Some(&self.admin),
                portid: 0x7622,
                ..RequestContext::default()
            },
            Arc::new(Source::new()),
        )
        .map_err(|_| "actual successor station/cache query framing")
    }
    fn preserved(&self) -> Result<(), &'static str> {
        if self
            .admin
            .authorize_interface(self.radio.name(), 0)
            .is_err()
            || !crate::registry::list()
                .iter()
                .any(|actual| Arc::ptr_eq(actual, &self.iface))
            || !self
                .query(32, 0x301)?
                .iter()
                .any(|reply| reply.get(16) == Some(&34))
        {
            return Err("old control DEL removed unrelated same-name station registration/cache");
        }
        let refused = self.query(48, 5)?;
        if refused.len() != 1 || refused[0].get(16..20) != Some(&(-1i32).to_ne_bytes()) {
            return Err("old control DEL erased unrelated same-name station socket-owner metadata");
        }
        Ok(())
    }
}
pub(in crate::ap_control::tests) async fn create(
    radio: &Radio,
    authority: &RadioControlAuthority,
    name: &str,
    iftype: u32,
    mac: Option<[u8; 6]>,
) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
    if iftype != 10 || mac.is_some() {
        return Err(WirelessError::NotSupported);
    }
    let factory = radio
        .control_factory
        .lock()
        .clone()
        .ok_or(WirelessError::NotSupported)?;
    core::future::poll_fn(|cx| {
        authority.check_for(radio)?;
        radio.start_polls.fetch_add(1, Ordering::AcqRel);
        if radio.start_ready.load(Ordering::Acquire) {
            core::task::Poll::Ready(Ok::<_, WirelessError>(()))
        } else {
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await?;
    let parent = factory.parent.upgrade().ok_or(WirelessError::Denied)?;
    let mut inner = Radio::new(name.into());
    inner.serial = radio.serial.clone();
    let child = Arc::new(ControlRadio {
        inner,
        namespace: 0,
        physical: parent.wiphy_id(),
        metadata: IrqSafeSpinLock::new(None),
        metadata_releases: AtomicU32::new(0),
        retirement_hook: IrqSafeSpinLock::new(None),
        successor: IrqSafeSpinLock::new(None),
        post_retirement_hold: AtomicBool::new(false),
        post_retirement_seen: AtomicBool::new(false),
    });
    child.inner.mode.store(10, Ordering::Release);
    let cap = narf_net::registry()
        .register_control_child(
            &narf_net::bootstrap_authority(),
            &factory.cap,
            RegisteredControl(child.clone()),
        )
        .map_err(|_| WirelessError::Denied)?;
    let iface: Arc<dyn WirelessNetIface> = child.clone();
    let wdev = match crate::registry::register_control(&parent, iface.clone()) {
        Ok(wdev) => wdev,
        Err(_) => {
            narf_net::registry().unregister_for_handle(&cap);
            return Err(WirelessError::Denied);
        }
    };
    *child.metadata.lock() = Some((cap, wdev));
    factory.children.lock().push(child.clone());
    if let Err(error) = authority.retain_control_child(&iface, &cap) {
        child.release_control_metadata();
        return Err(error);
    }
    Ok(iface)
}
#[derive(Debug)]
struct Endpoint {
    alive: AtomicBool,
    deliveries: AtomicU32,
    fail_on: u32,
    controls: IrqSafeSpinLock<Vec<AdminHandle>>,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    probe_new_start: AtomicBool,
    start_blocked: AtomicBool,
}
impl Endpoint {
    fn new(fail_on: u32) -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            deliveries: AtomicU32::new(0),
            fail_on,
            controls: IrqSafeSpinLock::new(Vec::new()),
            messages: IrqSafeSpinLock::new(Vec::new()),
            probe_new_start: AtomicBool::new(false),
            start_blocked: AtomicBool::new(false),
        })
    }
}
impl DeferredReplySink for Endpoint {
    fn current(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        let number = self.deliveries.fetch_add(1, Ordering::AcqRel) + 1;
        if !self.current() || number == self.fail_on {
            return Err(125);
        }
        if message.get(16) == Some(&7) && self.probe_new_start.load(Ordering::Acquire) {
            self.start_blocked
                .store(self.competing_start(&message), Ordering::Release);
        }
        self.messages.lock().push(message);
        Ok(())
    }
    fn retain_control_admin(&self, admin: AdminHandle) -> Result<(), i32> {
        if !self.current() || !admin.is_control_child() {
            return Err(1);
        }
        self.controls.lock().push(admin);
        Ok(())
    }
    fn control_admin(&self, name: &str, ns: u64) -> Option<AdminHandle> {
        if !self.current() {
            return None;
        }
        let mut controls = self.controls.lock();
        controls.retain(AdminHandle::is_live);
        controls
            .iter()
            .find(|admin| admin.authorize_interface(name, ns).is_ok())
            .cloned()
    }
}
impl Endpoint {
    fn competing_start(&self, new_reply: &[u8]) -> bool {
        let Some(id) = value(&new_reply[20..], 153)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_ne_bytes)
        else {
            return false;
        };
        let Some(child) = crate::registry::control_by_id(id, 0) else {
            return false;
        };
        let Some(admin) = self.control_admin(child.name(), 0) else {
            return false;
        };
        let mut attrs = Vec::new();
        dispatch::attr(&mut attrs, 153, &id.to_ne_bytes());
        let request = message(89, 5, attrs);
        let source = Arc::new(Source::new());
        narf_net::netlink_generic::build_replies_with_endpoint(
            &request,
            ReplyOptions::default(),
            RequestContext {
                admin: Some(&admin),
                portid: 77,
                ..RequestContext::default()
            },
            source,
        )
        .is_ok_and(|replies| {
            replies.len() == 1 && replies[0].get(16..20) == Some(&(-16i32).to_ne_bytes())
        })
    }
}
fn factory(parent: &Fixture) -> Factory {
    let factory = Factory {
        parent: Arc::downgrade(&parent.iface),
        cap: parent.cap,
        children: Arc::new(IrqSafeSpinLock::new(Vec::new())),
    };
    *parent.radio.control_factory.lock() = Some(factory.clone());
    factory
}
fn send(
    parent: &Fixture,
    endpoint: Arc<Endpoint>,
    command: u8,
    attrs: Vec<u8>,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let _ = crate::nl80211::register();
    let message = message(command, 5, attrs);
    build_replies_with_endpoint(
        &message,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(&parent.admin),
            portid: 77,
            ..RequestContext::default()
        },
        endpoint,
    )
    .map_err(|_| "actual lifecycle netlink framing")
}
fn message(command: u8, flags: u16, attrs: Vec<u8>) -> Vec<u8> {
    let mut message = alloc::vec![0;20];
    message[..4].copy_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&0x76cd_0007u32.to_ne_bytes());
    message[16] = command;
    message[17] = 1;
    message.extend_from_slice(&attrs);
    message
}
fn new_attrs(parent: &Fixture, name: &str) -> Result<Vec<u8>, &'static str> {
    let mut attrs = Vec::new();
    dispatch::attr(
        &mut attrs,
        1,
        &crate::registry::wiphy_index(parent.iface.wiphy_id())
            .ok_or("actual parent wiphy index")?
            .to_ne_bytes(),
    );
    dispatch::attr(&mut attrs, 4, name.as_bytes());
    dispatch::attr(&mut attrs, 5, &10u32.to_ne_bytes());
    Ok(attrs)
}
fn selector(child: &ControlRadio) -> Result<Vec<u8>, &'static str> {
    let mut attrs = Vec::new();
    dispatch::attr(
        &mut attrs,
        153,
        &crate::registry::control_for(child)
            .ok_or("actual lifecycle WDEV")?
            .id()
            .to_ne_bytes(),
    );
    Ok(attrs)
}
fn poll() {
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
    }
}
fn success(endpoint: &Endpoint) -> usize {
    endpoint
        .messages
        .lock()
        .iter()
        .filter(|m| {
            m.len() >= 20 && m[4..6] == 2u16.to_ne_bytes() && m[16..20] == 0i32.to_ne_bytes()
        })
        .count()
}
fn reachable() -> Result<(), &'static str> {
    let parent = fixture()?;
    let factory = factory(&parent);
    let endpoint = Endpoint::new(0);
    endpoint.probe_new_start.store(true, Ordering::Release);
    let name = alloc::format!("ctl-{}", parent.ifindex);
    if !send(&parent, endpoint.clone(), 7, new_attrs(&parent, &name)?)?.is_empty() {
        return Err("NEW acknowledged before callback");
    }
    poll();
    if !factory.children.lock().is_empty() || !endpoint.messages.lock().is_empty() {
        return Err("held NEW created or published metadata");
    }
    parent.radio.start_ready.store(true, Ordering::Release);
    poll();
    let child = factory
        .children
        .lock()
        .last()
        .cloned()
        .ok_or("actual NEW child")?;
    let attrs = selector(&child)?;
    if !endpoint.start_blocked.load(Ordering::Acquire)
        || child.inner.start_polls.load(Ordering::Acquire) != 0
        || success(&endpoint) != 1
        || endpoint.control_admin(&name, 0).is_none()
        || narf_net::iface::lookup(&name).is_some()
        || !endpoint.messages.lock().iter().any(|m| {
            m.get(16) == Some(&7) && value(&m[20..], 3).is_none() && value(&m[20..], 153).is_some()
        })
    {
        return Err("NEW lost its WDEV response, exact retained grant or no-netdev boundary");
    }
    if !send(&parent, endpoint.clone(), 89, attrs.clone())?.is_empty() {
        return Err("fresh NEW source cannot START its actual child");
    }
    poll();
    if success(&endpoint) != 1 {
        return Err("START acknowledged held callback");
    }
    child.inner.start_ready.store(true, Ordering::Release);
    poll();
    if success(&endpoint) != 2 {
        return Err("actual source-retained START did not complete");
    }
    child.inner.start_ready.store(false, Ordering::Release);
    if !send(&parent, endpoint.clone(), 8, attrs.clone())?.is_empty() {
        return Err("DEL failed current WDEV source admission");
    }
    poll();
    if success(&endpoint) != 2 || crate::registry::control_for(child.as_ref()).is_none() {
        return Err("held DEL acknowledged or removed native-pending metadata");
    }
    child.inner.start_ready.store(true, Ordering::Release);
    poll();
    if success(&endpoint) != 3
        || endpoint.control_admin(&name, 0).is_some()
        || crate::registry::control_for(child.as_ref()).is_some()
        || child.metadata_releases.load(Ordering::Acquire) != 1
    {
        return Err("native-complete DEL failed final ACK or exact metadata retirement");
    }
    let old = send(&parent, endpoint.clone(), 89, attrs)?;
    if old.len() != 1 || old[0][16..20] != (-19i32).to_ne_bytes() {
        return Err("old retired WDEV remained selectable");
    }
    if !send(&parent, endpoint.clone(), 7, new_attrs(&parent, &name)?)?.is_empty() {
        return Err("same-name fresh NEW admission");
    }
    poll();
    let successor = factory
        .children
        .lock()
        .last()
        .cloned()
        .ok_or("actual same-name new child")?;
    if Arc::ptr_eq(&successor, &child)
        || selector(&successor)? == selector_from_messages(&endpoint)?
    {
        return Err("same-name NEW reused an old object or WDEV");
    }
    successor.release_control_metadata();
    Ok(())
}
fn selector_from_messages(endpoint: &Endpoint) -> Result<Vec<u8>, &'static str> {
    let messages = endpoint.messages.lock();
    let message = messages
        .iter()
        .find(|m| m.get(16) == Some(&7))
        .ok_or("first NEW response")?;
    let id = value(&message[20..], 153).ok_or("first actual WDEV attr")?;
    let mut attrs = Vec::new();
    dispatch::attr(&mut attrs, 153, id);
    Ok(attrs)
}
fn control_wdev_new_start_delete_routes_exact_child_and_retires_terminal_ack() -> TestResult {
    reachable().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_new_start_delete_routes_exact_child_and_retires_terminal_ack
);

fn unpublished() -> Result<(), &'static str> {
    for fail in [1, 2] {
        let parent = fixture()?;
        let factory = factory(&parent);
        let endpoint = Endpoint::new(fail);
        parent.radio.start_ready.store(true, Ordering::Release);
        let name = alloc::format!("unpub-{}", parent.ifindex);
        if !send(&parent, endpoint.clone(), 7, new_attrs(&parent, &name)?)?.is_empty() {
            return Err("unpublished NEW admission");
        }
        poll();
        let child = factory
            .children
            .lock()
            .last()
            .cloned()
            .ok_or("unpublished actual child")?;
        if crate::registry::control_for(child.as_ref()).is_some()
            || endpoint.control_admin(&name, 0).is_some()
            || child.metadata_releases.load(Ordering::Acquire) != 1
            || success(&endpoint) != 0
        {
            return Err("failed NEW response/ACK leaked metadata, retained grant or success");
        }
        if parent.radio.serial.try_reserve().is_err() {
            return Err("unpublished NEW retained the serial owner after cleanup");
        }
    }
    Ok(())
}
fn control_wdev_failed_new_reply_or_ack_withdraws_unpublished_child() -> TestResult {
    unpublished().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_failed_new_reply_or_ack_withdraws_unpublished_child
);

fn retired() -> Result<(), &'static str> {
    for cause in 0..5 {
        let parent = fixture()?;
        let child = paired_child(&parent)?;
        let source = Endpoint::new(0);
        let authority = RadioControlAuthority::bind_wdev(
            child.admin.clone(),
            &child.iface,
            0,
            child.registration.id(),
            source.clone(),
        )
        .and_then(RadioControlAuthority::reserve)
        .map_err(|_| "actual retiring source")?;
        let receipt = authority
            .retire_control(&child.cap)
            .map_err(|_| "exact invoked native-retirement observation")?;
        if !receipt.current()
            || authority.current().is_ok()
            || crate::registry::control_by_id(child.registration.id(), 0).is_some()
            || crate::registry::list()
                .iter()
                .any(|actual| Arc::ptr_eq(actual, &child.iface))
        {
            return Err("hidden retired child restored normal authority or public discovery");
        }
        match cause {
            0 => {
                source.alive.store(false, Ordering::Release);
            }
            1 => {
                child.radio.inner.generation.fetch_add(1, Ordering::AcqRel);
            }
            2 => {
                parent.daemon.revoke();
            }
            3 => {
                child.cap.revoke();
            }
            _ => {
                crate::registry::unregister(parent.radio.name());
            }
        };
        if receipt.current() {
            return Err("retired final ACK ignored exact socket/mode/grant/parent loss");
        }
        drop(receipt);
        if child.radio.metadata_releases.load(Ordering::Acquire) != 1 {
            return Err("retired exact metadata cleanup was not once");
        }
    }
    Ok(())
}
fn control_wdev_retirement_hides_selector_and_rechecks_original_publication_scope() -> TestResult {
    retired().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_retirement_hides_selector_and_rechecks_original_publication_scope
);

fn delete_delivery() -> Result<(), &'static str> {
    for fail_on in [0, 1] {
        let parent = fixture()?;
        let child = paired_child(&parent)?;
        let endpoint = Endpoint::new(fail_on);
        endpoint
            .retain_control_admin(child.admin.clone())
            .map_err(|_| "actual child source before DEL")?;
        child.radio.inner.start_ready.store(true, Ordering::Release);
        *child.radio.retirement_hook.lock() = Some(seed_successor);
        child
            .radio
            .post_retirement_hold
            .store(true, Ordering::Release);
        if !send(&parent, endpoint.clone(), 8, selector(&child.radio)?)?.is_empty() {
            return Err("native-complete DEL admission");
        }
        poll();
        if !child.radio.post_retirement_seen.load(Ordering::Acquire)
            || !endpoint.messages.lock().is_empty()
            || child.admin.check_live().is_ok()
            || crate::registry::control_by_id(child.registration.id(), 0).is_some()
            || child.radio.metadata_releases.load(Ordering::Acquire) != 0
        {
            return Err("post-retirement pending owner handoff revived administration, ACKed early or lost its exact receipt");
        }
        child
            .radio
            .post_retirement_hold
            .store(false, Ordering::Release);
        poll();
        if (fail_on == 1 && !endpoint.messages.lock().is_empty())
            || (fail_on == 0 && success(&endpoint) != 1)
            || crate::registry::control_for(child.radio.as_ref()).is_some()
            || child.radio.metadata_releases.load(Ordering::Acquire) != 1
            || endpoint.control_admin(child.radio.name(), 0).is_some()
        {
            return Err("DEL ACK/drop retained old metadata/admin or missed actual success");
        }
        let successor = { child.radio.successor.lock().take() }
            .ok_or("actual unrelated successor before old DEL completion")?;
        successor.preserved()?;
    }
    Ok(())
}
fn control_wdev_failed_delete_ack_finishes_only_original_metadata_retirement() -> TestResult {
    delete_delivery().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_failed_delete_ack_finishes_only_original_metadata_retirement
);
