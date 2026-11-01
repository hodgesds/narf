//! Actual delegated source identity through typed/legacy rebinds. These
//! controls use real registry capabilities, never a source-liveness boolean.
use super::*;
use crate::{Frame, RX_RING_N, TX_RING_N};
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU32, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
#[path = "stack_child_tests.rs"]
mod child;
#[path = "stack_metadata_tests.rs"]
mod metadata;
#[path = "stack_native_tests.rs"]
mod native;

struct Device {
    name: String,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl Device {
    fn new(name: String) -> Self {
        Self {
            name,
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        }
    }
}
impl Interface for Device {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0x76, 0x66]
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        false
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
fn reject(_: &[u8], _: crate::TxMeta) -> Result<(), ()> {
    Err(())
}
struct Fixture {
    name: String,
    iface: Cap<NetIface, Write>,
    daemon: Cap<StackDaemon, Invoke>,
    admin: AdminHandle,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        crate::registry().unregister(&self.name);
        crate::iface::unregister(&self.name);
    }
}
impl Fixture {
    fn new(legacy: bool) -> Result<Self, &'static str> {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let name = if legacy {
            crate::iface::register("src-bind%d", [2, 0, 0, 0, 0x76, 0x66], reject)
        } else {
            format!("src-only-{}", NEXT.fetch_add(1, Ordering::Relaxed))
        };
        let iface = crate::registry()
            .register(&crate::bootstrap_authority(), Device::new(name.clone()))
            .map_err(|_| "source device registration")?;
        let daemon = Cap::<StackDaemon, Invoke>::bootstrap();
        let admin = control_registered(&StackAttach { iface, daemon })
            .map_err(|_| "actual source delegation")?
            .admin;
        Ok(Self {
            name,
            iface,
            daemon,
            admin,
        })
    }
    fn delegate(&self, iface: Cap<NetIface, Write>) -> Result<AdminHandle, &'static str> {
        control_registered(&StackAttach {
            iface,
            daemon: self.daemon,
        })
        .map(|reply| reply.admin)
        .map_err(|_| "fresh actual source delegation")
    }
}
fn typed_replacement() -> Result<(), &'static str> {
    let f = Fixture::new(true)?;
    let kernel = kernel_admin(&f.name).ok_or("kernel namespace administration")?;
    crate::registry().unregister(&f.name);
    let new_cap = crate::registry()
        .register(&crate::bootstrap_authority(), Device::new(f.name.clone()))
        .map_err(|_| "replacement typed registry")?;
    if f.iface.check_live().is_err() {
        return Err("fixture did not retain live unregistered source cap");
    }
    if f.admin.check_live() != Err(AdminError::NoIface)
        || f.admin.authorize_interface(&f.name, 0) != Err(AdminError::NoIface)
        || f.admin.set_link(true) != Err(AdminError::NoIface)
        || crate::iface::lookup(&f.name).is_none_or(|link| link.link_up)
    {
        return Err("old delegated admin retargeted replacement typed interface");
    }
    let current = f.delegate(new_cap)?;
    if current.authorize_interface(&f.name, 0).is_err()
        || current.set_link(true).is_err()
        || kernel.authorize_interface(&f.name, 0).is_err()
    {
        return Err("fresh delegation or independent kernel namespace authority lost");
    }
    Ok(())
}
fn delegated_admin_requires_exact_still_registered_interface_handle() -> TestResult {
    typed_replacement().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_requires_exact_still_registered_interface_handle
);
fn legacy_replacement() -> Result<(), &'static str> {
    let f = Fixture::new(true)?;
    let before = crate::iface::lookup(&f.name).ok_or("legacy source snapshot")?;
    if !crate::iface::retire_for_rebind(&f.name) {
        return Err("legacy source retirement");
    }
    let name = crate::iface::rebind_name(&f.name).ok_or("legacy source name claim")?;
    let name = crate::iface::register(name, [2, 0, 0, 0, 0x76, 0x66], reject);
    let after = crate::iface::lookup(&name).ok_or("legacy successor snapshot")?;
    if name != f.name
        || before.ifindex != after.ifindex
        || before.mac != after.mac
        || f.admin.check_live() != Err(AdminError::NoIface)
        || f.admin.set_mtu(1400) != Err(AdminError::NoIface)
        || f.admin.authorize_interface(&f.name, 0) != Err(AdminError::NoIface)
        || crate::iface::lookup(&f.name).is_none_or(|link| link.mtu != 1500)
    {
        return Err("same name/index/MAC legacy rebind revived old delegated authority");
    }
    f.delegate(f.iface)?
        .authorize_interface(&f.name, 0)
        .map_err(|_| "fresh same-device delegation after legacy rebind")?;
    Ok(())
}
fn delegated_admin_fresh_bind_refuses_same_name_index_mac_registration_aba() -> TestResult {
    legacy_replacement().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_fresh_bind_refuses_same_name_index_mac_registration_aba
);
fn namespace_and_revocation() -> Result<(), &'static str> {
    let f = Fixture::new(true)?;
    let kernel = kernel_admin(&f.name).ok_or("namespace kernel control")?;
    f.admin
        .move_to_net_ns(0x7662)
        .map_err(|_| "source-owned namespace transfer")?;
    if f.admin.authorize_interface(&f.name, 0) != Err(AdminError::NoIface)
        || f.admin.authorize_interface(&f.name, 0x7662).is_err()
        || kernel.authorize_interface(&f.name, 0) != Err(AdminError::NoIface)
        || kernel.authorize_interface(&f.name, 0x7662).is_err()
    {
        return Err("delegated or kernel namespace control escaped current scope");
    }
    f.admin
        .move_to_net_ns(0)
        .map_err(|_| "source-owned namespace return")?;
    if f.admin.check_live().is_err() {
        return Err("namespace move replaced actual device registration");
    }
    f.daemon.revoke();
    if f.admin.check_live() != Err(AdminError::AuthorityRevoked)
        || f.admin.authorize_interface(&f.name, 0) != Err(AdminError::AuthorityRevoked)
        || kernel.authorize_interface(&f.name, 0).is_err()
    {
        return Err("source invocation ignored revocation or revoked independent kernel scope");
    }
    Ok(())
}
fn delegated_admin_invokes_source_grants_and_preserves_namespace_kernel_scope() -> TestResult {
    namespace_and_revocation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_admin_invokes_source_grants_and_preserves_namespace_kernel_scope
);
fn typed_only() -> Result<(), &'static str> {
    let f = Fixture::new(false)?;
    if f.admin.authorize_interface(&f.name, 0).is_err() {
        return Err("typed-only device lost registered control");
    }
    crate::iface::register(f.name.as_str(), [2, 0, 0, 0, 0x76, 0x66], reject);
    if f.admin.check_live() != Err(AdminError::NoIface)
        || f.admin.authorize_interface(&f.name, 0) != Err(AdminError::NoIface)
    {
        return Err("old typed-only delegation silently acquired new legacy-device identity");
    }
    f.delegate(f.iface)?
        .authorize_interface(&f.name, 0)
        .map_err(|_| "fresh paired typed/legacy source delegation")?;
    Ok(())
}
fn delegated_typed_only_interface_cannot_inherit_later_legacy_registration() -> TestResult {
    typed_only().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_identity",
    delegated_typed_only_interface_cannot_inherit_later_legacy_registration
);
