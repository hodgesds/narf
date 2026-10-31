//! Actual typed parent-child registration receipts and live source lineage.
use super::*;

struct Control(Device, u64);
impl Interface for Control {
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
        Some(self.1)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
struct Child {
    name: String,
    cap: Cap<NetIface, Write>,
}
impl Drop for Child {
    fn drop(&mut self) {
        crate::registry().unregister_for_handle(&self.cap);
    }
}
fn child(parent: &Fixture, name: Option<&str>) -> Result<Child, &'static str> {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let name = name
        .map(String::from)
        .unwrap_or_else(|| format!("child-src-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let cap = crate::registry()
        .register_control_child(
            &crate::bootstrap_authority(),
            &parent.iface,
            Control(Device::new(name.clone()), 0),
        )
        .map_err(|_| "actual parent-bound control registration")?;
    Ok(Child { name, cap })
}
fn delegate(parent: &Fixture, child: &Child) -> Result<AdminHandle, &'static str> {
    parent
        .admin
        .control_registered_child(&child.cap)
        .map_err(|_| "current parent control delegation")?
        .ok_or("delegated parent lost actual daemon identity")
}
fn scope() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let child = child(&parent, None)?;
    let admin = delegate(&parent, &child)?;
    let kernel = kernel_admin(&parent.name).ok_or("actual namespace parent handle")?;
    if kernel
        .control_registered_child(&child.cap)
        .map(|admin| admin.is_none())
        != Ok(true)
        || kernel.control_registered_child(&parent.iface).is_ok()
    {
        return Err(
            "kernel namespace child check invented a daemon grant or accepted a nonchild cap",
        );
    }
    if admin.authorize_interface(&child.name, 0).is_err()
        || parent.admin.authorize_interface(&child.name, 0).is_ok()
        || admin.authorize_interface(&parent.name, 0).is_ok()
        || admin.authorize_interface(&child.name, 27).is_ok()
        || admin.set_link(true) != Err(AdminError::NoIface)
        || crate::iface::lookup(&child.name).is_some()
    {
        return Err("fresh child grant inherited a parent name/namespace/netdev alias");
    }
    let foreign = Fixture::new(true)?;
    if foreign.admin.control_registered_child(&child.cap).is_ok() {
        return Err("unrelated actual parent delegated another parent's child cap");
    }
    if crate::registry()
        .register_control_child(
            &crate::bootstrap_authority(),
            &parent.iface,
            Control(Device::new(format!("{}-wrong-ns", child.name)), 27),
        )
        .err()
        != Some(crate::ControlRegisterError::NotControl)
    {
        return Err("physical parent registered a control child in another namespace");
    }
    let unpaired = crate::registry()
        .register_control(
            &crate::bootstrap_authority(),
            Control(Device::new(format!("{}-unpaired", child.name)), 0),
        )
        .map_err(|_| "actual unpaired control registration")?;
    let accepted = parent.admin.control_registered_child(&unpaired).is_ok();
    crate::registry().unregister_for_handle(&unpaired);
    if accepted {
        return Err("a metadata-only control name minted parent-child authority");
    }
    Ok(())
}
fn fresh_control_child_delegation_requires_exact_parent_cap_and_namespace() -> TestResult {
    scope().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    fresh_control_child_delegation_requires_exact_parent_cap_and_namespace
);

fn revoke() -> Result<(), &'static str> {
    for cause in 0..3 {
        let parent = Fixture::new(true)?;
        let child = child(&parent, None)?;
        let admin = delegate(&parent, &child)?;
        match cause {
            0 => parent.admin.cap.revoke(),
            1 => parent.daemon.revoke(),
            _ => child.cap.revoke(),
        }
        if admin.check_live().is_ok()
            || admin.authorize_interface(&child.name, 0).is_ok()
            || parent.admin.control_registered_child(&child.cap).is_ok()
        {
            return Err("control-child delegation outlived actual parent/daemon/child revocation");
        }
        if cause == 2 && !parent.admin.is_live() {
            return Err("child revoke incorrectly revoked parent authority");
        }
    }
    Ok(())
}
fn control_child_admin_retains_parent_daemon_and_child_grant_lifetimes() -> TestResult {
    revoke().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_child_admin_retains_parent_daemon_and_child_grant_lifetimes
);

fn replacement() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let old = child(&parent, None)?;
    let admin = delegate(&parent, &old)?;
    crate::registry().unregister_for_handle(&old.cap);
    let next = child(&parent, Some(&old.name))?;
    if old.cap.check_live().is_err()
        || admin.check_live().is_ok()
        || parent.admin.control_registered_child(&old.cap).is_ok()
        || crate::registry().unregister_for_handle(&old.cap)
        || delegate(&parent, &next)?
            .authorize_interface(&next.name, 0)
            .is_err()
    {
        return Err("same-name child replacement revived old actual source/grant");
    }
    let retained = delegate(&parent, &next)?;
    crate::registry().unregister(&parent.name);
    let cap = crate::registry()
        .register(
            &crate::bootstrap_authority(),
            Device::new(parent.name.clone()),
        )
        .map_err(|_| "actual same-name parent replacement")?;
    let fresh = parent.delegate(cap)?;
    if retained.check_live().is_ok() || fresh.control_registered_child(&next.cap).is_ok() {
        return Err("same-name physical parent replacement inherited an old child's relation");
    }
    Ok(())
}
fn control_child_and_physical_parent_replacement_do_not_retarget_delegation() -> TestResult {
    replacement().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_child_and_physical_parent_replacement_do_not_retarget_delegation
);

fn transfer() -> Result<(), &'static str> {
    let parent = Fixture::new(true)?;
    let old = child(&parent, None)?;
    let admin = delegate(&parent, &old)?;
    parent
        .admin
        .move_to_net_ns(27)
        .map_err(|_| "actual parent namespace transfer")?;
    if admin.check_live().is_ok() || parent.admin.control_registered_child(&old.cap).is_ok() {
        return Err("control child retained administration across parent namespace transfer");
    }
    parent
        .admin
        .move_to_net_ns(0)
        .map_err(|_| "actual parent namespace return")?;
    if admin.check_live().is_ok() {
        return Err("parent namespace ABA revived old control-child admin");
    }
    // A new explicit delegation after the completed return is a fresh grant.
    if delegate(&parent, &old)?
        .authorize_interface(&old.name, 0)
        .is_err()
    {
        return Err("fresh explicit child delegation after parent return refused");
    }
    Ok(())
}
fn control_child_parent_namespace_aba_requires_fresh_explicit_delegation() -> TestResult {
    transfer().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    control_child_parent_namespace_aba_requires_fresh_explicit_delegation
);
