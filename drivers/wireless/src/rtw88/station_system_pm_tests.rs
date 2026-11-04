//! Durable worker owns actual native old-DMA/card-off/fresh-firmware receipts.
//! Synthetic PCI sleep is modeled; these cases do not create physical evidence.
use super::*;
use crate::rtw88::{
    endpoints, operating_reset,
    power::reset_tests as power_model,
    system_pm_worker::{self, Backend, Control, Phase},
};
type FreshSlot = Arc<IrqSafeSpinLock<Option<Arc<Harness>>>>;
type Setup<F> = (Arc<Harness>, FreshSlot, Arc<Control>, F);
struct NativeModel {
    old: Arc<Harness>,
    fresh: FreshSlot,
    idle: bool,
}
struct Parked {
    retired: operating_reset::Retired,
    power: power_model::ParkedPower,
    name: &'static str,
}
#[async_trait::async_trait]
impl Backend for NativeModel {
    type Parked = Parked;
    async fn prepare(&mut self) -> Result<Parked, narf_power::device_pm::DevicePmError> {
        let error = narf_power::device_pm::DevicePmError::DriverError;
        if self.idle {
            self.old
                .device
                .idle_claim(|| Ok(()))
                .await
                .map_err(|_| narf_power::device_pm::DevicePmError::Busy)?;
        }
        self.old.device.withdraw_for_rebind().map_err(|_| error)?;
        let retired = operating_reset::retire(&self.old.device, &self.old.lifecycle)
            .await
            .map_err(|_| error)?;
        let name = self.old.device.rebound_name().ok_or(error)?;
        let power = power_model::park().map_err(|_| error)?;
        Ok(Parked {
            retired,
            power,
            name,
        })
    }
    async fn resume(&mut self, parked: Parked) -> Result<(), narf_power::device_pm::DevicePmError> {
        let Parked {
            retired,
            power,
            name,
        } = parked;
        power_model::resume(power)
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)?;
        // The new inert constructor consumes the actual old-retirement
        // precondition, then earns its own full radio/firmware/DMA receipts.
        fn fresh(_retired: operating_reset::Retired, name: &'static str) -> Arc<Harness> {
            Arc::new(Harness::build_named(true, OWN, true, false, Some(name)))
        }
        let fresh = fresh(retired, name);
        fresh.env.nonce_seed.store(0x45, Ordering::Release);
        *self.fresh.lock() = Some(fresh);
        Ok(())
    }
}
fn setup() -> Setup<impl Future<Output = ()>> {
    setup_mode(true, false)
}
fn setup_mode(join: bool, idle: bool) -> Setup<impl Future<Output = ()>> {
    let old = Arc::new(Harness::build(true, OWN, true));
    if join {
        old.join();
    }
    let fresh = Arc::new(IrqSafeSpinLock::new(None));
    let control = Control::new();
    let future = system_pm_worker::run(
        NativeModel {
            old: old.clone(),
            fresh: fresh.clone(),
            idle,
        },
        control.clone(),
    );
    (old, fresh, control, future)
}
fn smoke_rtw8822ce_ips_original_passive_native_off_same_interface_fresh_start() -> TestResult {
    let (old, fresh, control, future) = setup_mode(false, true);
    let cookie = endpoints::cookie(old.device.name()).unwrap();
    let ifindex = narf_net::iface::lookup(old.device.name()).unwrap().ifindex;
    let idle = crate::rtw88::runtime_idle::RuntimeIdle::new(control.clone());
    let mut future = Box::pin(future);
    for _ in 0..16384 {
        if control.phase() == Phase::Suspended {
            break;
        }
        let _ = poll(future.as_mut());
    }
    if !idle.suspended() || !old.lifecycle.removed() || fresh.lock().is_some() {
        return TestResult::Fail("IPS did not retain actual passive DMA/card-off receipts");
    }
    drop(idle);
    if !poll(future.as_mut()).is_ready() || control.phase() != Phase::Resumed {
        return TestResult::Fail("IPS handle drop failed to drive durable fresh startup");
    }
    let fresh = fresh.lock().clone().unwrap();
    if fresh.device.name() != old.device.name()
        || narf_net::iface::lookup(fresh.device.name())
            .unwrap()
            .ifindex
            != ifindex
        || endpoints::cookie(fresh.device.name()) == Some(cookie)
        || fresh.device.link_up()
    {
        return TestResult::Fail("IPS reused old admission/endpoint or lost original interface");
    }
    fresh.join();
    let lease = narf_net::dhcp::dhcp_acquire(fresh.device.name(), 0).unwrap();
    if !fresh.plan.matches_lease(&lease) || !multi_tests::routed(&fresh, b"native-IPS-fresh-data") {
        return TestResult::Fail("IPS fresh firmware/association/CCMP/DHCP path");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8822ce_ips_original_passive_native_off_same_interface_fresh_start
);

fn smoke_rtw8822ce_ips_associated_owner_refusal_preserves_actual_data_path() -> TestResult {
    let (old, fresh, control, future) = setup_mode(true, true);
    let mut future = Box::pin(future);
    if !poll(future.as_mut()).is_ready()
        || control.phase() != Phase::Failed
        || control.error() != narf_power::device_pm::DevicePmError::Busy
        || old.lifecycle.removed()
        || old.device.closed()
        || fresh.lock().is_some()
        || !multi_tests::routed(&old, b"associated-IPS-refusal-still-live")
    {
        return TestResult::Fail("IPS retired or closed an actually associated owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8822ce_ips_associated_owner_refusal_preserves_actual_data_path
);

fn smoke_rtw8822ce_ips_cancelled_waiter_preserves_original_retirement_worker() -> TestResult {
    let (old, fresh, control, future) = setup_mode(false, true);
    let delivery = old.device.delivery_for_test();
    let idle = crate::rtw88::runtime_idle::RuntimeIdle::new(control.clone());
    let mut future = Box::pin(future);
    if poll(future.as_mut()).is_ready() || control.phase() != Phase::Preparing {
        return TestResult::Fail("IPS skipped actual original unlocked callback");
    }
    drop(idle);
    if poll(future.as_mut()).is_ready() || fresh.lock().is_some() {
        return TestResult::Fail("IPS cancellation fabricated original callback retirement");
    }
    drop(delivery);
    for _ in 0..16384 {
        if poll(future.as_mut()).is_ready() {
            break;
        }
    }
    if control.phase() != Phase::Resumed || fresh.lock().is_none() || !old.lifecycle.removed() {
        return TestResult::Fail("IPS foreground cancellation lost real fresh-start worker");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw8822ce_ips_cancelled_waiter_preserves_original_retirement_worker
);
fn poll(future: core::pin::Pin<&mut impl Future<Output = ()>>) -> Poll<()> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn smoke_rtw8822ce_system_pm_native_off_fresh_keys_same_name_and_dhcp() -> TestResult {
    let (old, fresh, control, future) = setup();
    let cookie = endpoints::cookie(old.device.name()).unwrap();
    let snapshot = narf_net::iface::lookup(old.device.name()).unwrap();
    let key = old.peer.lock().ap.pairwise_tk();
    let mut future = Box::pin(future);
    for _ in 0..16384 {
        if control.phase() == Phase::Suspended {
            break;
        }
        let _ = poll(future.as_mut());
    }
    if control.phase() != Phase::Suspended
        || fresh.lock().is_some()
        || !old.lifecycle.removed()
        || old.device.link_up()
    {
        return TestResult::Fail("worker did not retain actual parked native state");
    }
    control.request_resume();
    if !poll(future.as_mut()).is_ready() || control.phase() != Phase::Resumed {
        return TestResult::Fail("native resume did not earn fresh firmware owner");
    }
    let fresh = fresh.lock().clone().unwrap();
    if fresh.device.name() != old.device.name()
        || narf_net::iface::lookup(fresh.device.name())
            .unwrap()
            .ifindex
            != snapshot.ifindex
        || fresh.device.link_up()
        || endpoints::cookie(fresh.device.name()) == Some(cookie)
    {
        return TestResult::Fail("system PM reused old port/endpoint or lost original ifindex");
    }
    fresh.join();
    let lease = narf_net::dhcp::dhcp_acquire(fresh.device.name(), 0).unwrap();
    let fresh_key = { fresh.peer.lock().ap.pairwise_tk() };
    if key == fresh_key
        || !fresh.plan.matches_lease(&lease)
        || !multi_tests::routed(&fresh, b"fresh-explicit-connect-after-system-sleep")
    {
        return TestResult::Fail("resume replayed old keys or lost native DHCP/data");
    }
    old.device.withdraw();
    old.calibration.revoke();
    if !multi_tests::routed(&fresh, b"old-suspended-generation-cannot-close-new") {
        return TestResult::Fail("late old PM cleanup changed fresh carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/system_pm",
    smoke_rtw8822ce_system_pm_native_off_fresh_keys_same_name_and_dhcp
);
fn smoke_rtw8822ce_system_pm_foreground_cancel_does_not_drop_native_retirement() -> TestResult {
    let (old, fresh, control, future) = setup();
    let delivery = old.device.delivery_for_test();
    let mut future = Box::pin(future);
    if poll(future.as_mut()).is_ready() || control.phase() != Phase::Preparing {
        return TestResult::Fail("native retirement did not wait original unlocked ingress");
    }
    // This is the same operation the foreground Attempt::drop requests.
    // The durable worker and its original owner remain alive and are polled.
    control.request_resume();
    if poll(future.as_mut()).is_ready() || fresh.lock().is_some() {
        return TestResult::Fail("cancel bypassed unfinished old native callbacks");
    }
    drop(delivery);
    for _ in 0..16384 {
        if poll(future.as_mut()).is_ready() {
            break;
        }
    }
    if control.phase() != Phase::Resumed || fresh.lock().is_none() {
        return TestResult::Fail("cancelled waiter lost durable native rollback");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/system_pm",
    smoke_rtw8822ce_system_pm_foreground_cancel_does_not_drop_native_retirement
);
fn smoke_rtw8822ce_system_pm_failed_dma_cannot_create_parked_receipt() -> TestResult {
    let (old, fresh, control, future) = setup();
    old.model(|io| io.rx_dma_busy = true);
    let mut future = Box::pin(future);
    for _ in 0..16384 {
        if poll(future.as_mut()).is_ready() {
            break;
        }
    }
    control.request_resume();
    if control.phase() != Phase::Failed
        || fresh.lock().is_some()
        || old.device.link_up()
        || complete(operating_reset::retire(&old.device, &old.lifecycle)).is_ok()
    {
        return TestResult::Fail("failed actual RXDMA minted a parked/reset receipt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/system_pm",
    smoke_rtw8822ce_system_pm_failed_dma_cannot_create_parked_receipt
);
