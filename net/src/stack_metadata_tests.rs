//! Interleave actual retirement after admission and before pure mutation.
//! The hooks run outside PUBLISH/Registry/IFACES and never fake a grant.
use super::*;
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
