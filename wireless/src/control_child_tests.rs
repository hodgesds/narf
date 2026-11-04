//! Actual fresh parent/child grants + exact source retained controls. The
//! interface callback is held; native MCU/CNM receipts have separate tests.
use super::*;
use narf_net::netlink_generic::DeferredReplySink;
#[derive(Debug)]
struct Retained {
    source: Source,
    controls: IrqSafeSpinLock<Vec<AdminHandle>>,
}
impl Retained {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            source: Source(AtomicBool::new(true), IrqSafeSpinLock::new(Vec::new())),
            controls: IrqSafeSpinLock::new(Vec::new()),
        })
    }
}
impl DeferredReplySink for Retained {
    fn current(&self) -> bool {
        self.source.current()
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        self.source.deliver(message)
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
fn guard(parent: &Fixture, source: Arc<Retained>) -> Result<RadioControlAuthority, &'static str> {
    RadioControlAuthority::bind(
        parent.admin.clone(),
        &parent.iface,
        0,
        parent.ifindex,
        source,
    )
    .map_err(|_| "actual creating parent source guard")
}
fn reachable() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = paired_child(&parent)?;
    let source = Retained::new();
    let refused = dispatch::send_with_admin(&child, source.clone(), 89, &[], &parent.admin)?;
    if refused.len() != 1 || refused[0][16..20] != (-1i32).to_ne_bytes() {
        return Err(
            "creating parent handle silently administered a child without explicit delegation",
        );
    }
    guard(&parent, source.clone())?
        .retain_control_child(&child.iface, &child.cap)
        .map_err(|_| "actual typed parent-child grant retained on creating source")?;
    if !dispatch::send_with_admin(&child, source.clone(), 89, &[], &parent.admin)?.is_empty() {
        return Err("explicit retained child grant failed actual source-to-child START routing");
    }
    narf_scheduler::poll_one_round();
    if child.radio.inner.start_polls.load(Ordering::Acquire) == 0
        || !source.source.1.lock().is_empty()
    {
        return Err("source-retained child acknowledged a queued callback");
    }
    dispatch::complete(&child);
    if child.radio.inner.starts.load(Ordering::Acquire) != 1
        || source.source.1.lock().is_empty()
        || narf_net::iface::lookup(child.radio.name()).is_some()
        || child.radio.link_up()
    {
        return Err("retained child source lost terminal completion or invented a netdev");
    }
    Ok(())
}
fn control_wdev_fresh_child_delegation_makes_actual_parent_source_start_reachable() -> TestResult {
    reachable().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_fresh_child_delegation_makes_actual_parent_source_start_reachable
);

fn scope() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = paired_child(&parent)?;
    let other = fixture()?;
    let foreign = paired_child(&other)?;
    let source = Retained::new();
    let grant = guard(&parent, source.clone())?;
    if grant
        .retain_control_child(&child.iface, &foreign.cap)
        .is_ok()
        || guard(&other, source.clone())?
            .retain_control_child(&child.iface, &child.cap)
            .is_ok()
        || !source.controls.lock().is_empty()
    {
        return Err("typed source retained a name-only/foreign-cap/foreign-parent child grant");
    }
    grant
        .retain_control_child(&child.iface, &child.cap)
        .map_err(|_| "actual child source retention")?;
    source.source.0.store(false, Ordering::Release);
    if source.control_admin(child.radio.name(), 0).is_some()
        || grant.retain_control_child(&child.iface, &child.cap).is_ok()
    {
        return Err("closed exact source retained new child administration");
    }
    Ok(())
}
fn control_wdev_child_delegation_requires_actual_parent_cap_receiver_and_source() -> TestResult {
    scope().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_child_delegation_requires_actual_parent_cap_receiver_and_source
);

fn retired_parent() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = paired_child(&parent)?;
    let source = Retained::new();
    guard(&parent, source.clone())?
        .retain_control_child(&child.iface, &child.cap)
        .map_err(|_| "actual child source before parent retirement")?;
    if !dispatch::send_with_admin(&child, source.clone(), 89, &[], &parent.admin)?.is_empty() {
        return Err("actual child request admission");
    }
    narf_scheduler::poll_one_round();
    crate::registry::unregister(parent.iface.name());
    if parent.cap.check_live().is_err()
        || child.cap.check_live().is_err()
        || crate::registry::control_by_id(child.registration.id(), 0).is_some()
        || crate::registry::control_for(child.radio.as_ref()).is_some()
        || crate::registry::wiphys()
            .iter()
            .any(|iface| Arc::ptr_eq(iface, &child.iface))
    {
        return Err("retired physical parent left a discoverable/orphan-physical control child");
    }
    dispatch::complete(&child);
    if child.radio.inner.starts.load(Ordering::Acquire) != 0
        || source
            .source
            .1
            .lock()
            .iter()
            .any(|message| message.len() >= 20 && message[16..20] == 0i32.to_ne_bytes())
    {
        return Err("child native callback published after actual parent registration retired");
    }
    Ok(())
}
fn control_wdev_actual_parent_retirement_retires_discovery_and_pending_child_publication(
) -> TestResult {
    retired_parent().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_actual_parent_retirement_retires_discovery_and_pending_child_publication
);
