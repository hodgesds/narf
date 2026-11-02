//! Real parent/child caps and provider retirement at a fixed native boundary.
use super::*;

struct Control {
    device: Device,
    namespace: u64,
    callbacks: Arc<AtomicU32>,
}
impl Interface for Control {
    fn name(&self) -> &str {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
        self.device.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
        self.device.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
        Some(self.namespace)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.device.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.device.tx_ring()
    }
}
struct Child {
    name: String,
    cap: Cap<NetIface, Write>,
    callbacks: Arc<AtomicU32>,
}
impl Drop for Child {
    fn drop(&mut self) {
        crate::registry().unregister_for_handle(&self.cap);
    }
}
fn make_child(parent: &Fixture, name: Option<&str>) -> Result<Child, &'static str> {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let name = name
        .map(String::from)
        .unwrap_or_else(|| format!("native-child-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let callbacks = Arc::new(AtomicU32::new(0));
    let cap = crate::registry()
        .register_control_child(
            &crate::bootstrap_authority(),
            &parent.iface,
            Control {
                device: Device::new(name.clone()),
                namespace: 0,
                callbacks: callbacks.clone(),
            },
        )
        .map_err(|_| "actual native control-child registration")?;
    Ok(Child {
        name,
        cap,
        callbacks,
    })
}
fn delegate(parent: &Fixture, child: &Child) -> Result<AdminHandle, &'static str> {
    parent
        .admin
        .control_registered_child(&child.cap)
        .map_err(|_| "actual native child delegation")?
        .ok_or("actual delegated child lost its source lineage")
}
fn capture_child(
    admin: &AdminHandle,
    child: &Child,
) -> Result<crate::AdminEmissionAuthority, &'static str> {
    admin
        .native_control_emission(&child.cap, 0)
        .map_err(|_| "actual native control-child capture")
}
fn exact_scope() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let child = make_child(&parent, None)?;
    let admin = delegate(&parent, &child)?;
    let guard = capture_child(&admin, &child)?;
    let kernel = kernel_admin(&child.name).ok_or("actual namespace child Admin")?;
    let kernel_guard = capture_child(&kernel, &child)?;
    if !guard.current()
        || !kernel_guard.current()
        || crate::iface::lookup(&child.name).is_some()
        || crate::iface::lookup(&parent.name).is_none_or(|link| link.link_up)
        || parent.admin.native_control_emission(&child.cap, 0).is_ok()
        || admin.native_control_emission(&child.cap, 9).is_ok()
        || admin.native_control_emission(&parent.iface, 0).is_ok()
        || capture(&parent).is_ok()
    {
        return Err("native control capture invented netdev/UP or changed original scope");
    }
    let other = make_child(&parent, None)?;
    if admin.native_control_emission(&other.cap, 0).is_ok() {
        return Err("native control capture followed another actual child cap");
    }
    let count = child.callbacks.load(Ordering::Acquire);
    let fixed_current = {
        let _registry = crate::registry().inner.lock();
        guard.current() && kernel_guard.current()
    };
    if !fixed_current || child.callbacks.load(Ordering::Acquire) != count {
        return Err("fixed native control proof reentered Registry or virtual provider");
    }
    // The original autonomous-AP constructor still requires an UP netdev.
    if admin
        .native_emission(&child.name, 0, 1, 1, [2, 0, 0, 0, 0x76, 0x66])
        .is_ok()
    {
        return Err("control proof weakened the ordinary native netdev constructor");
    }
    let orphan_name = format!("{}-orphan", child.name);
    let callbacks = Arc::new(AtomicU32::new(0));
    let orphan_cap = crate::registry()
        .register_control(
            &crate::bootstrap_authority(),
            Control {
                device: Device::new(orphan_name.clone()),
                namespace: 0,
                callbacks: callbacks.clone(),
            },
        )
        .map_err(|_| "actual unparented control registration")?;
    let orphan = Child {
        name: orphan_name,
        cap: orphan_cap,
        callbacks,
    };
    let orphan_admin = kernel_admin(&orphan.name).ok_or("actual unparented Admin")?;
    if capture_child(&orphan_admin, &orphan).is_ok() {
        return Err("unknown control ancestry manufactured a native parent proof");
    }
    Ok(())
}
fn native_control_emission_keeps_actual_lineage_without_fabricating_up_or_ifindex() -> TestResult {
    exact_scope().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_native",
    native_control_emission_keeps_actual_lineage_without_fabricating_up_or_ifindex
);

fn revocations() -> Result<(), &'static str> {
    for boundary in 0..12 {
        let parent = Fixture::new(true)?;
        let child = make_child(&parent, None)?;
        let admin = delegate(&parent, &child)?;
        let guard = capture_child(&admin, &child)?;
        match boundary {
            0 => admin.cap.revoke(),
            1 => parent.admin.cap.revoke(),
            2 => parent.daemon.revoke(),
            3 => parent.iface.revoke(),
            4 => child.cap.revoke(),
            5 => {
                crate::registry().unregister_for_handle(&child.cap);
                let replacement = make_child(&parent, Some(&child.name))?;
                let fresh = delegate(&parent, &replacement)?;
                if !capture_child(&fresh, &replacement)?.current()
                    || admin.native_control_emission(&replacement.cap, 0).is_ok()
                {
                    return Err("fresh child lost its grant or old Admin followed namesake");
                }
            }
            6 => {
                crate::registry().unregister_for_handle(&parent.iface);
                crate::registry()
                    .register(
                        &crate::bootstrap_authority(),
                        Device::new(parent.name.clone()),
                    )
                    .map_err(|_| "native typed parent replacement")?;
            }
            7 => {
                crate::iface::set_net_ns(&parent.name, 27);
                crate::iface::set_net_ns(&parent.name, 0);
            }
            8 => {
                crate::iface::register(&parent.name, [2, 0, 0, 0, 0x76, 0x66], reject);
            }
            9 => {
                parent
                    .admin
                    .set_mac([2, 0, 0, 0, 7, 9])
                    .map_err(|_| "native parent MAC replacement")?;
                parent
                    .admin
                    .set_mac([2, 0, 0, 0, 0x76, 0x66])
                    .map_err(|_| "native parent MAC restoration")?;
            }
            10 => {
                parent
                    .admin
                    .set_link(true)
                    .map_err(|_| "native parent UP")?;
                parent
                    .admin
                    .set_link(false)
                    .map_err(|_| "native parent DOWN")?;
            }
            _ => {
                crate::iface::register(&child.name, [2, 0, 0, 0, 0x76, 0x66], reject);
                if guard.current() {
                    return Err("same-name legacy representation did not close control proof");
                }
                crate::iface::unregister(&child.name);
                // A new capture under the still-current original grant is
                // allowed after the alias dies. The old weak fence stays dead.
                if !capture_child(&admin, &child)?.current() {
                    return Err("retired legacy alias prevented fresh actual control capture");
                }
            }
        }
        if guard.current() {
            return Err("native control proof survived original grant/provider retirement");
        }
    }
    for boundary in 0..3 {
        let parent = Fixture::new(true)?;
        let child = make_child(&parent, None)?;
        let kernel = kernel_admin(&child.name).ok_or("actual kernel child Admin")?;
        let guard = capture_child(&kernel, &child)?;
        // This independent namespace grant does not acquire a fresh parent
        // Admin, nor depend on the other daemon's delegated Admin capability.
        parent.admin.cap.revoke();
        if !guard.current() {
            return Err("kernel native capture invented a delegated parent Admin dependency");
        }
        match boundary {
            0 => kernel.cap.revoke(),
            1 => parent.iface.revoke(),
            _ => child.cap.revoke(),
        }
        if guard.current() {
            return Err("kernel native control bypassed its original Admin/parent/child cap");
        }
    }
    Ok(())
}
fn native_control_emission_never_follows_revoked_parent_child_or_namesake_providers() -> TestResult
{
    revocations().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_native",
    native_control_emission_never_follows_revoked_parent_child_or_namesake_providers
);

fn wake_owners() -> Result<(), &'static str> {
    for boundary in 0..3 {
        let parent = Fixture::new(true)?;
        let child = make_child(&parent, None)?;
        let admin = delegate(&parent, &child)?;
        let guard = capture_child(&admin, &child)?;
        let first = Arc::new(Wakes(AtomicU32::new(0)));
        let second = Arc::new(Wakes(AtomicU32::new(0)));
        if !guard.watch(&Waker::from(first.clone())) || !guard.watch(&Waker::from(second.clone())) {
            return Err("actual control provider could not arm two native cleanup owners");
        }
        match boundary {
            0 => {
                crate::registry().unregister_for_handle(&child.cap);
            }
            1 => {
                crate::registry().unregister_for_handle(&parent.iface);
            }
            _ => {
                parent
                    .admin
                    .set_link(true)
                    .map_err(|_| "watched parent UP")?;
                parent
                    .admin
                    .set_link(false)
                    .map_err(|_| "watched parent DOWN")?;
            }
        }
        if guard.current()
            || first.0.load(Ordering::Acquire) != 1
            || second.0.load(Ordering::Acquire) != 1
            || guard.watch(&Waker::from(first))
        {
            return Err("actual parent/child provider retirement lost cleanup wake or revived");
        }
    }
    Ok(())
}
fn native_control_emission_wakes_retained_cleanup_after_actual_provider_retirement() -> TestResult {
    wake_owners().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_native",
    native_control_emission_wakes_retained_cleanup_after_actual_provider_retirement
);
