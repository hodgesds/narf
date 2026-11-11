use super::*;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Clock;
#[async_trait::async_trait]
impl Environment for Clock {
    fn now_ms(&self) -> u64 {
        0
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        None
    }
    async fn pause(&self) {
        core::future::pending::<()>().await;
    }
}
fn shell() -> Native {
    Device::new(
        "rtw8822ce-unclaimed-shell",
        [2, 4, 6, 8, 10, 12],
        Arc::new(Lifecycle::new(0xc822)),
        Arc::new(Clock),
    )
}
fn poll<F: Future>(future: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn smoke_rtw8822ce_shell_cannot_activate_before_registration_and_cancel_cannot_reclaim(
) -> TestResult {
    let device = shell();
    let mut unpublished = Box::pin(device.activate());
    if !matches!(poll(unpublished.as_mut()), Poll::Ready(Err(Error::State))) {
        return TestResult::Fail("unregistered shell attempted station activation");
    }
    drop(unpublished);
    if device.closed() || device.link_up() || device.connected_bssid().is_some() {
        return TestResult::Fail("unregistered shell invented carrier or terminal state");
    }
    device.admit_for_test(); // Registry publication only; no firmware/PHY grant.
    let storage = device.lifecycle.retained.try_lock().unwrap();
    let mut activation = Box::pin(device.activate());
    if !poll(activation.as_mut()).is_pending() {
        return TestResult::Fail("activation bypassed the retained-owner mutex");
    }
    // The cancelled future never reached an Owner, let alone native DMA.
    // Its shell admission must nevertheless be terminal before lock release.
    drop(activation);
    if !device.closed() || storage.is_some() || device.link_up() {
        return TestResult::Fail("cancelled activation retained a reusable admission");
    }
    drop(storage);
    let mut retry = Box::pin(device.activate());
    if !matches!(poll(retry.as_mut()), Poll::Ready(Err(Error::State)))
        || device.lifecycle.status().stage != super::super::firmware_lifecycle::Stage::Detected
        || device.lifecycle.retained.try_lock().unwrap().is_some()
    {
        return TestResult::Fail("cancelled shell allocated or retried a firmware owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_shell_cannot_activate_before_registration_and_cancel_cannot_reclaim
);

fn smoke_rtw8822ce_device_disconnect_reserves_before_mutex_and_cancel_releases_cleanup(
) -> TestResult {
    let device = shell();
    let storage = device.lifecycle.retained.try_lock().unwrap();
    let mut disconnect = Box::pin(device.disassociate());
    if !poll(disconnect.as_mut()).is_pending()
        || !device.closed()
        || !device.admission.teardown_pending()
        || device.link_up()
        || device.connected_bssid().is_some()
    {
        return TestResult::Fail(
            "public disconnect did not close and reserve before awaiting owner",
        );
    }
    let mut published = false;
    if device
        .admission
        .run(|| {
            published = true;
            Ok(())
        })
        .is_ok()
        || published
    {
        return TestResult::Fail("pending public disconnect admitted a new publication");
    }
    // A synchronous DHCP/stack drain must return with the control mutex held.
    if device.drain() {
        return TestResult::Fail("blocked disconnect synthesized receive progress");
    }
    drop(disconnect);
    if !device.closed() || device.admission.teardown_pending() {
        return TestResult::Fail("cancelled public disconnect stranded its teardown reservation");
    }
    drop(storage);
    if device.drain() {
        return TestResult::Fail("cancelled empty owner produced a packet");
    }
    let mut cleanup = Box::pin(device.disassociate());
    if !matches!(poll(cleanup.as_mut()), Poll::Ready(Ok(()))) {
        return TestResult::Fail("terminal shell could not finish cleanup after cancellation");
    }
    drop(cleanup);
    if !device.closed()
        || device.admission.teardown_pending()
        || device.lifecycle.retained.try_lock().unwrap().is_some()
    {
        return TestResult::Fail("cleanup reopened or reconstructed the empty owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_device_disconnect_reserves_before_mutex_and_cancel_releases_cleanup
);

static HOOK_DEVICE: IrqSafeSpinLock<Option<Arc<Native>>> = IrqSafeSpinLock::new(None);
static HOOK_CALLS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static HOOK_BLOCKED: AtomicBool = AtomicBool::new(false);
fn admin_hook(_: &str, _: bool) {
    HOOK_CALLS.fetch_add(1, Ordering::AcqRel);
    let device = HOOK_DEVICE.lock().clone().unwrap();
    let owner_available = device.lifecycle.retained.try_lock().is_some();
    let metadata_available = device.metadata.try_lock().is_some();
    if !owner_available || !metadata_available {
        HOOK_BLOCKED.store(true, Ordering::Release);
    }
    // Exercise the real synchronous callback entry, without waiting for a
    // driver task or attempting a recursive blocking owner acquisition.
    device.drain();
}
fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}
struct Registration;
impl Drop for Registration {
    fn drop(&mut self) {
        narf_net::iface::unregister("rtw8822ce-admin-carrier-model");
        *HOOK_DEVICE.lock() = None;
    }
}
fn smoke_rtw8822ce_carrier_preserves_admin_state_without_reentering_locked_owner() -> TestResult {
    let name = "rtw8822ce-admin-carrier-model";
    let device = Arc::new(Device::new(
        name,
        [2, 4, 6, 8, 10, 12],
        Arc::new(Lifecycle::<super::super::pci_firmware::Transport>::new(
            0xc822,
        )),
        Arc::new(Clock),
    ));
    narf_net::iface::register(name, device.local, reject);
    let _registration = Registration;
    *HOOK_DEVICE.lock() = Some(device.clone());
    HOOK_CALLS.store(0, Ordering::Release);
    HOOK_BLOCKED.store(false, Ordering::Release);
    if !narf_net::iface::set_open_stop(name, admin_hook) {
        return TestResult::Fail("carrier model could not install real administrative hook");
    }
    {
        let _owner = device.lifecycle.retained.try_lock().unwrap();
        device.link(Some([2, 0, 0, 0, 0, 2]), true);
    }
    let info = narf_net::iface::lookup(name).unwrap();
    if info.link_up || !info.carrier || HOOK_CALLS.load(Ordering::Acquire) != 0 {
        return TestResult::Fail(
            "carrier-up changed admin-down or invoked callback under driver locks",
        );
    }
    // Only the operator changes IFF_UP. Prove this installed hook really
    // executes and can reenter the facade when that administrative call runs.
    narf_net::iface::set_link_state(name, true);
    if HOOK_CALLS.load(Ordering::Acquire) != 1 || HOOK_BLOCKED.load(Ordering::Acquire) {
        return TestResult::Fail("operator hook could not reenter the unlocked facade");
    }
    {
        let _owner = device.lifecycle.retained.try_lock().unwrap();
        device.link(None, false);
    }
    let info = narf_net::iface::lookup(name).unwrap();
    if !info.link_up || info.carrier || HOOK_CALLS.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("carrier-down cleared operator IFF_UP or reentered locked owner");
    }
    device.close();
    let info = narf_net::iface::lookup(name).unwrap();
    if !info.link_up || info.carrier || !device.closed() || HOOK_BLOCKED.load(Ordering::Acquire) {
        return TestResult::Fail("terminal driver closure changed administrative authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_carrier_preserves_admin_state_without_reentering_locked_owner
);

fn wow_config() -> narf_wireless::WowlanConfig {
    narf_wireless::WowlanConfig {
        disconnect: true,
        magic_packet: true,
        gtk_rekey_failure: false,
        patterns: vec![narf_wireless::WowlanPattern {
            mask: vec![0x3f],
            pattern: vec![2, 4, 6, 8, 10, 12],
            offset: 0,
        }],
        net_detect: None,
    }
}
/// `SET_WOWLAN` on the RTL8822CE shell: advertised stub, validated retained
/// configuration, and an unlinked station never arms (cold path instead).
fn smoke_rtw88_wow_interface_config_and_unlinked_suspend() -> TestResult {
    let device = shell();
    if device.wowlan_support() != super::super::wow::support(0xc822) {
        return TestResult::Fail("C22 shell did not advertise rtw_wowlan_stub_8822c");
    }
    let mut bad = wow_config();
    bad.patterns[0].offset = 1;
    if device.set_wowlan(Some(bad)) != Err(EINVAL) || device.wowlan_config().is_some() {
        return TestResult::Fail("packet offset outside the stub was retained");
    }
    if device.set_wowlan(Some(wow_config())).is_err()
        || device.wowlan_config() != Some(wow_config())
    {
        return TestResult::Fail("valid WoW configuration was not retained");
    }
    let mut suspend = core::pin::pin!(device.wow_suspend());
    match poll(suspend.as_mut()) {
        Poll::Ready(Ok(None)) => {}
        _ => return TestResult::Fail("unlinked shell armed WoW instead of the cold path"),
    }
    if device.wow_armed.load(Ordering::Acquire) || device.wakeup().is_some() {
        return TestResult::Fail("refused WoW suspend changed the shell");
    }
    if device.set_wowlan(None).is_err() || device.wowlan_config().is_some() {
        return TestResult::Fail("WoW configuration could not be cleared");
    }
    device.restore_wowlan(Some(wow_config()), None);
    if device.wowlan_config() != Some(wow_config()) {
        return TestResult::Fail("cold resume did not carry the WoW configuration");
    }
    let c21: Native = Device::new(
        "rtw8821ce-wow-shell",
        [2, 4, 6, 8, 10, 14],
        Arc::new(Lifecycle::new(0xc821)),
        Arc::new(Clock),
    );
    if c21.wowlan_support().is_some()
        || c21.set_wowlan(Some(wow_config())) != Err(narf_wireless::EOPNOTSUPP)
    {
        return TestResult::Fail("RTL8821CE advertised or accepted WoW");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/wow",
    smoke_rtw88_wow_interface_config_and_unlinked_suspend
);

/// 5GHz wiphy capabilities (main.c `rtw_init_ht_cap`/`rtw_init_vht_cap` on
/// the 5GHz sband) carry exactly the qualified offer retained at activate:
/// none for a legacy-only 5GHz join, HT20 alone, or HT20/40 + VHT80 when an
/// admitted N2xV join exists. 2.4GHz keeps its own HT body and no VHT.
fn smoke_rtw88_band5_wiphy_caps_follow_admitted_station_offer() -> TestResult {
    let device = shell();
    if device.phy_capabilities(5000).is_some()
        || device.get_wireless_info().hw_caps.vht_supported
        || device.get_wireless_info().hw_caps.ht_supported
    {
        return TestResult::Fail("unactivated shell advertised 5GHz HT/VHT");
    }
    let ht = [
        0x2c, 0x01, 0x03, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let vht = [0x30, 0x11, 0x13, 0x03, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0];
    *device.band5_capability.lock() = Some((ht, None));
    match device.phy_capabilities(5000) {
        Some(c) if c.ht == ht && c.vht.is_none() => {}
        _ => return TestResult::Fail("admitted 5GHz HT20 offer not advertised"),
    }
    if device.get_wireless_info().hw_caps.vht_supported
        || !device.get_wireless_info().hw_caps.ht_supported
        || device.phy_capabilities(2400).is_some()
    {
        return TestResult::Fail("HT20-only 5GHz offer advertised VHT or leaked to 2.4GHz");
    }
    *device.band5_capability.lock() = Some((ht, Some(vht)));
    match device.phy_capabilities(5000) {
        Some(c) if c.ht == ht && c.vht == Some(vht) => {}
        _ => return TestResult::Fail("admitted 5GHz VHT80 offer not advertised"),
    }
    if !device.get_wireless_info().hw_caps.vht_supported || device.phy_capabilities(6000).is_some()
    {
        return TestResult::Fail("VHT80 offer not reported or 6GHz advertised");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_band5_wiphy_caps_follow_admitted_station_offer
);

/// main.c `SUPPORTS_PS`: power save is advertised and settable only with a
/// composed LPS owner (`Owner::lps_capable`), off by default; the watchdog
/// enters LPS only below `RTW_LPS_THRESHOLD` (`ps_active` false).
fn smoke_rtw88_power_save_interface_follows_lps_capability() -> TestResult {
    let device = shell();
    if device.power_save_default().is_some()
        || device.set_power_save(true) != Err(narf_wireless::EOPNOTSUPP)
        || device.sleep_enabled.load(Ordering::Acquire)
    {
        return TestResult::Fail("shell without an LPS owner advertised power save");
    }
    device.sleep_capable.store(true, Ordering::Release);
    if device.power_save_default() != Some(false) {
        return TestResult::Fail("power save not advertised off by default");
    }
    if device.set_power_save(true).is_err() || device.power_save_default() != Some(true) {
        return TestResult::Fail("power save enable not retained");
    }
    if device.set_power_save(false).is_err() || device.power_save_default() != Some(false) {
        return TestResult::Fail("power save disable not retained");
    }
    if !lps_due(true, 0, 0)
        || !lps_due(true, LPS_THRESHOLD, LPS_THRESHOLD)
        || lps_due(true, LPS_THRESHOLD + 1, 0)
        || lps_due(true, 0, LPS_THRESHOLD + 1)
        || lps_due(false, 0, 0)
    {
        return TestResult::Fail("LPS entry differs from rtw_watch_dog_work ps_active");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/ps",
    smoke_rtw88_power_save_interface_follows_lps_capability
);
