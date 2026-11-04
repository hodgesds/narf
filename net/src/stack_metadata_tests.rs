//! Interleave actual retirement after admission and before pure mutation.
//! The hooks run outside PUBLISH/Registry/IFACES and never fake a grant.
use super::*;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

fn arm(name: &str, action: fn(&str)) {
    *super::super::metadata::BEFORE_APPLY.lock() = Some((String::from(name), action));
}
fn replace_legacy(name: &str) {
    assert!(crate::iface::retire_for_rebind(name));
    let original = crate::iface::rebind_name(name).expect("actual retired name");
    assert_eq!(
        crate::iface::register(original, [2, 0, 0, 0, 0x76, 0x66], reject),
        name
    );
}
fn replace_typed(name: &str) {
    crate::registry().unregister(name);
    crate::registry()
        .register(
            &crate::bootstrap_authority(),
            Device::new(String::from(name)),
        )
        .expect("actual successor device");
}
fn races(typed: bool) -> Result<(), &'static str> {
    for operation in 0..3 {
        let f = Fixture::new(true)?;
        arm(&f.name, if typed { replace_typed } else { replace_legacy });
        let result = match operation {
            0 => f.admin.set_link(true),
            1 => f.admin.set_mtu(1300),
            _ => f.admin.set_mac([2, 1, 2, 3, 4, 5]),
        };
        let current = crate::iface::lookup(&f.name).ok_or("actual successor metadata")?;
        if result != Err(AdminError::NoIface)
            || current.link_up
            || current.mtu != 1500
            || current.mac != [2, 0, 0, 0, 0x76, 0x66]
        {
            return Err("metadata mutation retargeted replacement after admission");
        }
        kernel_admin(&f.name)
            .ok_or("current independent kernel admin")?
            .set_mtu(1450)
            .map_err(|_| "kernel namespace/name scope lost")?;
        if crate::iface::lookup(&f.name).is_none_or(|entry| entry.mtu != 1450) {
            return Err("actual current kernel mutation did not publish");
        }
    }
    Ok(())
}
fn delegated_admin_metadata_mutation_fences_legacy_rebind_after_admission() -> TestResult {
    races(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_metadata_mutation_fences_legacy_rebind_after_admission
);
fn delegated_admin_metadata_mutation_fences_typed_replacement_after_admission() -> TestResult {
    races(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_metadata_mutation_fences_typed_replacement_after_admission
);

#[derive(Debug)]
struct Target {
    calls: Arc<AtomicU32>,
    successor: Arc<AtomicU32>,
    stale: Arc<AtomicBool>,
    replace: bool,
}
impl crate::iface::OpenStopTarget for Target {
    fn transition(&self, event: crate::iface::OpenStopEvent) {
        // These both reacquire the actual registries; any outer registry
        // lock or PUBLISH guard would deadlock this native regression.
        let _ = crate::registry().snapshots();
        let _ = crate::iface::lookup(event.name());
        if !event.current() {
            return;
        }
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.replace {
            replace_typed(event.name());
            replace_legacy(event.name());
            let expected = crate::iface::lookup(event.name()).expect("original callback successor");
            assert!(crate::iface::set_open_stop_target(
                &expected,
                Arc::new(Self {
                    calls: self.successor.clone(),
                    successor: self.successor.clone(),
                    stale: self.stale.clone(),
                    replace: false,
                })
            ));
            self.stale.store(!event.current(), Ordering::Release);
        }
    }
}
fn callback() -> Result<(), &'static str> {
    let f = Fixture::new(true)?;
    let calls = Arc::new(AtomicU32::new(0));
    let successor = Arc::new(AtomicU32::new(0));
    let stale = Arc::new(AtomicBool::new(false));
    let expected = crate::iface::lookup(&f.name).ok_or("callback actual registration")?;
    if !crate::iface::set_open_stop_target(
        &expected,
        Arc::new(Target {
            calls: calls.clone(),
            successor: successor.clone(),
            stale: stale.clone(),
            replace: true,
        }),
    ) {
        return Err("original receiver target installation");
    }
    f.admin
        .set_link(true)
        .map_err(|_| "original delegated open")?;
    if calls.load(Ordering::Acquire) != 1
        || successor.load(Ordering::Acquire) != 0
        || !stale.load(Ordering::Acquire)
        || f.admin.check_live() != Err(AdminError::NoIface)
        || crate::iface::set_open_stop_target(
            &expected,
            Arc::new(Target {
                calls: calls.clone(),
                successor: successor.clone(),
                stale: stale.clone(),
                replace: false,
            }),
        )
    {
        return Err("stale callback/installation retargeted a same-name successor");
    }
    // Retirement intentionally preserved UP metadata, but not the old
    // source grant or callback receiver. A current kernel request has its
    // own name scope and invokes only the successor's installed target.
    kernel_admin(&f.name)
        .ok_or("successor kernel admin")?
        .set_link(false)
        .map_err(|_| "successor actual stop")?;
    if calls.load(Ordering::Acquire) != 1 || successor.load(Ordering::Acquire) != 1 {
        return Err("current successor transition reached retired callback receiver");
    }
    Ok(())
}
fn delegated_admin_original_callback_is_unlocked_and_cannot_retarget_successor() -> TestResult {
    callback().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_original_callback_is_unlocked_and_cannot_retarget_successor
);

#[derive(Debug)]
struct IdentityTarget {
    events: Arc<narf_lib::sync::IrqSafeSpinLock<Vec<crate::iface::OpenStopEvent>>>,
    previous: Arc<narf_lib::sync::IrqSafeSpinLock<Option<crate::native_emission::Lifetime>>>,
    down_was_closed: Arc<AtomicBool>,
}
impl crate::iface::OpenStopTarget for IdentityTarget {
    fn transition(&self, event: crate::iface::OpenStopEvent) {
        // First operation in DOWN: no registry query/driver action is needed
        // to see synchronous retirement that preceded this callback.
        if !event.up() {
            let closed = self
                .previous
                .lock()
                .as_ref()
                .is_some_and(|old| !old.current());
            self.down_was_closed.store(closed, Ordering::Release);
        } else {
            let identity = event.native_identity();
            *self.previous.lock() = identity;
        }
        self.events.lock().push(event);
    }
}
fn event_native_identity() -> Result<(), &'static str> {
    let f = Fixture::new(true)?;
    let events = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    let previous = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(None));
    let down = Arc::new(AtomicBool::new(false));
    let registration =
        crate::iface::lookup(&f.name).ok_or("original event identity registration")?;
    let initial = crate::iface::OpenStopEvent::observe(&registration)
        .ok_or("exact initial administrative observation")?;
    if initial.up() || !initial.current() || initial.native_identity().is_some() {
        return Err("initial DOWN observation invented UP or native authority");
    }
    let target = Arc::new(IdentityTarget {
        events: events.clone(),
        previous,
        down_was_closed: down.clone(),
    });
    if !crate::iface::set_open_stop_target(&registration, target.clone()) {
        return Err("original identity target installation");
    }
    f.admin.set_link(true).map_err(|_| "actual original UP")?;
    let first = events.lock().last().cloned().ok_or("original UP event")?;
    let original = first.original_snapshot();
    let observed =
        crate::iface::OpenStopEvent::observe(&original).ok_or("exact existing UP observation")?;
    if original.name != registration.name
        || original.ownership_epoch != registration.ownership_epoch
        || original.ifindex != registration.ifindex
        || original.mac != registration.mac
        || !original.link_up
        || !crate::iface::set_open_stop_target(&original, target.clone())
        || !observed.up()
        || !observed.current()
        || crate::iface::OpenStopEvent::observe(&registration).is_some()
    {
        return Err("event did not retain its original complete transition snapshot");
    }
    let mut detached = first.original_snapshot();
    detached.name.push_str("-detached");
    detached.mac[5] ^= 1;
    if first.original_snapshot().name != original.name
        || first.original_snapshot().mac != original.mac
    {
        return Err("snapshot clone changed the sealed original event");
    }
    let first_identity = first
        .native_identity()
        .ok_or("current original UP Ethernet identity")?;
    if !first_identity.current() {
        return Err("current original observation absent");
    }
    f.admin
        .set_link(false)
        .map_err(|_| "actual original DOWN")?;
    let stopped = events.lock().last().cloned().ok_or("original DOWN event")?;
    if !down.load(Ordering::Acquire)
        || first_identity.current()
        || first.native_identity().is_some()
        || stopped.native_identity().is_some()
    {
        return Err("DOWN native identity was not closed before original callback");
    }
    f.admin.set_link(true).map_err(|_| "new original UP")?;
    let second = events.lock().last().cloned().ok_or("new UP event")?;
    let second_identity = second.native_identity().ok_or("new current UP identity")?;
    if first_identity.current() || first.native_identity().is_some() || !second_identity.current() {
        return Err("DOWN/UP revived original event or weak identity");
    }
    f.admin
        .set_mac([2, 1, 2, 3, 4, 5])
        .map_err(|_| "actual original MAC change")?;
    f.admin
        .set_mac(registration.mac)
        .map_err(|_| "actual original MAC return")?;
    if second_identity.current() || second.native_identity().is_some() {
        return Err("MAC away/back revived an event identity");
    }
    f.admin.set_link(false).map_err(|_| "MAC epoch DOWN")?;
    f.admin.set_link(true).map_err(|_| "MAC epoch UP")?;
    let third = events
        .lock()
        .last()
        .cloned()
        .ok_or("namespace original UP event")?;
    let third_identity = third
        .native_identity()
        .ok_or("namespace current identity")?;
    f.admin
        .move_to_net_ns(0x7671)
        .map_err(|_| "actual original namespace transfer")?;
    f.admin
        .move_to_net_ns(0)
        .map_err(|_| "actual original namespace return")?;
    if third_identity.current() || third.native_identity().is_some() {
        return Err("namespace away/back revived an event identity");
    }
    f.admin.set_link(false).map_err(|_| "representation DOWN")?;
    crate::iface::set_link_metadata(&f.name, false, None, None);
    crate::iface::set_link_layer(&f.name, crate::iface::LinkLayer::Ieee80211Radiotap)
        .map_err(|_| "actual representation change")?;
    f.admin.set_link(true).map_err(|_| "monitor metadata UP")?;
    let monitor = events
        .lock()
        .last()
        .cloned()
        .ok_or("monitor current UP event")?;
    if !monitor.current() || monitor.native_identity().is_some() {
        return Err("current non-Ethernet event acquired native Ethernet identity");
    }
    let monitor_original = monitor.original_snapshot();
    let token = crate::iface::begin_monitor_rx(&monitor_original)
        .ok_or("actual original monitor metadata capture")?;
    if !crate::iface::monitor_rx_current(token) {
        return Err("unchanged original monitor capture was refused");
    }
    f.admin
        .set_mac([2, 1, 2, 3, 4, 6])
        .map_err(|_| "monitor actual MAC change")?;
    f.admin
        .set_mac(monitor_original.mac)
        .map_err(|_| "monitor actual MAC return")?;
    let mut raw = [0; 10];
    raw[2] = 8;
    if crate::iface::monitor_rx_current(token)
        || crate::iface::on_monitor_frame_from(token, &raw)
        || crate::iface::begin_monitor_rx(&monitor_original).is_some()
        || monitor.current()
        || monitor.original_snapshot().mac != monitor_original.mac
        || monitor.original_snapshot().ownership_epoch != monitor_original.ownership_epoch
    {
        return Err("monitor MAC away/back revived original event, token or snapshot");
    }
    f.admin
        .set_link(false)
        .map_err(|_| "monitor metadata DOWN")?;
    crate::iface::set_link_layer(&f.name, crate::iface::LinkLayer::Ethernet)
        .map_err(|_| "actual representation return")?;

    f.admin.set_link(true).map_err(|_| "namespace epoch UP")?;
    let fourth = events
        .lock()
        .last()
        .cloned()
        .ok_or("rebind original UP event")?;
    let fourth_identity = fourth.native_identity().ok_or("rebind current identity")?;
    replace_legacy(&f.name);
    if fourth_identity.current()
        || fourth.native_identity().is_some()
        || first.native_identity().is_some()
        || stopped.native_identity().is_some()
        || crate::iface::set_open_stop_target(&first.original_snapshot(), target)
        || first.original_snapshot().ownership_epoch != original.ownership_epoch
        || crate::iface::OpenStopEvent::observe(&original).is_some()
        || crate::iface::OpenStopEvent::observe(&fourth.original_snapshot()).is_some()
    {
        return Err("same-name/index/MAC successor revived original event identity");
    }
    // Rebind preserves actual IFF_UP, without a new UP callback or a toggle.
    // A fresh receiver may observe only that new exact registration; the old
    // event and its lifetime remain permanently retired.
    let successor = crate::iface::lookup(&f.name).ok_or("preserved-UP successor metadata")?;
    let observed = crate::iface::OpenStopEvent::observe(&successor)
        .ok_or("exact preserved-UP successor observation")?;
    if !successor.link_up
        || !observed.up()
        || !observed.current()
        || observed.native_identity().is_none()
        || fourth_identity.current()
        || fourth.current()
    {
        return Err("preserved-UP observation rebound old identity or invented a transition");
    }
    Ok(())
}
fn delegated_admin_event_native_identity_is_fixed_denial_only_and_never_revives() -> TestResult {
    event_native_identity().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_event_native_identity_is_fixed_denial_only_and_never_revives
);
