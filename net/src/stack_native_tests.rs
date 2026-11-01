//! Actual delegated capability/registration/UP revocations at a native fence.
use super::*;
use alloc::task::Wake;
use core::task::Waker;

fn capture(f: &Fixture) -> Result<crate::AdminEmissionAuthority, &'static str> {
    let link = crate::iface::lookup(&f.name).ok_or("actual native netdev")?;
    f.admin
        .native_emission(
            &f.name,
            link.net_ns_id,
            link.ifindex,
            link.ownership_epoch,
            link.mac,
        )
        .map_err(|_| "actual native emission capture")
}
fn revocations() -> Result<(), &'static str> {
    for boundary in 0..10 {
        let f = Fixture::new(true)?;
        if capture(&f).is_ok() {
            return Err("administratively DOWN metadata armed native emission");
        }
        f.admin.set_link(true).map_err(|_| "actual admin UP")?;
        let guard = capture(&f)?;
        if !guard.current() {
            return Err("original actual native grant was not current");
        }
        match boundary {
            0 => f.admin.cap.revoke(),
            1 => f.daemon.revoke(),
            2 => f.iface.revoke(),
            3 => {
                crate::registry().unregister_for_handle(&f.iface);
                crate::registry()
                    .register(&crate::bootstrap_authority(), Device::new(f.name.clone()))
                    .map_err(|_| "replacement typed provider")?;
            }
            4 => {
                f.admin.set_link(false).map_err(|_| "actual admin DOWN")?;
                f.admin
                    .set_link(true)
                    .map_err(|_| "actual admin UP again")?;
            }
            5 => {
                f.admin
                    .set_mac([2, 0, 0, 0, 9, 1])
                    .map_err(|_| "actual MAC change")?;
                f.admin
                    .set_mac([2, 0, 0, 0, 0x76, 0x66])
                    .map_err(|_| "actual MAC restore")?;
            }
            6 => {
                crate::iface::set_net_ns(&f.name, 77);
                crate::iface::set_net_ns(&f.name, 0);
            }
            7 => {
                crate::iface::register(&f.name, [2, 0, 0, 0, 0x76, 0x66], reject);
            }
            8 => {
                crate::iface::retire_for_rebind(&f.name);
                crate::iface::register(&f.name, [2, 0, 0, 0, 0x76, 0x66], reject);
            }
            _ => {
                crate::iface::unregister(&f.name);
                crate::iface::register(&f.name, [2, 0, 0, 0, 0x76, 0x66], reject);
            }
        }
        // Numeric identity/MAC/UP restored and original caps may still be
        // live. The old weak provider receipt must never follow a successor.
        if guard.current() {
            return Err("native emission survived cap/provider/UP ownership retirement");
        }
    }
    Ok(())
}
fn native_emission_invokes_original_caps_and_never_follows_rebound_providers() -> TestResult {
    revocations().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_native",
    native_emission_invokes_original_caps_and_never_follows_rebound_providers
);

struct Wakes(AtomicU32);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
fn wake_retirement() -> Result<(), &'static str> {
    let f = Fixture::new(true)?;
    f.admin.set_link(true).map_err(|_| "actual admin UP")?;
    let guard = capture(&f)?;
    let wakes = Arc::new(Wakes(AtomicU32::new(0)));
    if !guard.watch(&Waker::from(wakes.clone())) {
        return Err("current emission owner could not arm cleanup wake");
    }
    f.admin.set_link(false).map_err(|_| "actual admin DOWN")?;
    if guard.current() || wakes.0.load(Ordering::Acquire) != 1 {
        return Err("admin DOWN did not atomically close and wake native cleanup owner");
    }
    let provider = crate::native_emission::ProviderLifetime::new();
    let weak = provider.observe();
    let first = Arc::new(Wakes(AtomicU32::new(0)));
    let second = Arc::new(Wakes(AtomicU32::new(0)));
    if !weak.watch(Waker::from(first.clone())) || !weak.watch(Waker::from(second.clone())) {
        return Err("one actual socket source could not watch two native AP owners");
    }
    let retired = provider.retire();
    if weak.current() || first.0.load(Ordering::Acquire) != 0 {
        return Err("provider retirement failed to close synchronously/defer wake");
    }
    retired.notify();
    if first.0.load(Ordering::Acquire) != 1
        || second.0.load(Ordering::Acquire) != 1
        || weak.watch(Waker::from(first.clone()))
    {
        return Err("provider retirement lost an owner or revived a retired watch");
    }
    Ok(())
}
fn native_emission_down_and_shared_source_retirement_wake_retained_cleanup_owners() -> TestResult {
    wake_retirement().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "net/stack_native",
    native_emission_down_and_shared_source_retirement_wake_retained_cleanup_owners
);
