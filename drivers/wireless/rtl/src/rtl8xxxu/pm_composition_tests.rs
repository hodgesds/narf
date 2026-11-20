// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual registration/OpenStopTarget/executor/native USB park and wake.
//! Only physical EP0/bulk/AP replies and entropy are inert fixture inputs.
use super::*;

#[derive(Clone, Default)]
struct PmEnv {
    clock: Env,
    nonces: Arc<AtomicU64>,
}
impl Environment for PmEnv {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
    fn fresh_nonce(&self) -> Result<[u8; 32], ServiceError> {
        let mut nonce = [0x73; 32];
        nonce[..8].copy_from_slice(&self.nonces.fetch_add(1, Ordering::AcqRel).to_le_bytes());
        Ok(nonce)
    }
    async fn pause(&self) {
        self.clock.pause().await;
    }
}
type PmDevice = Device<Fake, ChannelLink, PmEnv>;
static ACTIVE_PM: IrqSafeSpinLock<Option<Arc<PmDevice>>> = IrqSafeSpinLock::new(None);
fn send_pm(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_PM.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain_pm() -> bool {
    let device = ACTIVE_PM.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct Harness {
    device: Arc<PmDevice>,
    link: ChannelLink,
    control: Fake,
    source: Cap<FirmwareBlob, Read>,
    firmware: Arc<Owner<Fake>>,
    name: String,
}
impl Harness {
    #[inline(never)]
    fn new(protected: bool) -> Result<Box<Self>, &'static str> {
        let (control, firmware) = initialized_registered_firmware();
        let factory = firmware.factory().ok_or("PM original factory")?;
        let domain = Arc::new(IrqSafeSpinLock::new(narf_wireless::reg::RegulatoryDomain {
            country_code: *b"US",
            rules: vec![narf_wireless::reg::RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2482,
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: narf_wireless::reg::RegFlags::empty(),
            }],
        }));
        let calibration = calibration(factory);
        let power = calibration
            .permission(&domain.lock(), 1)
            .map_err(|_| "PM signed profile")?;
        let source = Cap::<FirmwareBlob, Read>::bootstrap();
        let proof = Proof::model(calibration, power, source, domain.clone());
        let network = plan(factory.mac);
        let mut peer = Peer::new(network, protected);
        peer.ap = ap(network, protected);
        let link = ChannelLink {
            bulk: Link(Arc::new(IrqSafeSpinLock::new(peer))),
            control: control.clone(),
            seen_reset: Arc::new(AtomicU64::new(control.0.lock().cold_generation)),
            beacon: Arc::new(AtomicBool::new(true)),
            beacon_generation: Arc::new(AtomicU64::new(u64::MAX)),
        };
        let mut receiver = Receiver::new(
            firmware.clone(),
            link.clone(),
            ReceivePermission::from_domain(&domain.lock()).map_err(|_| "PM receive policy")?,
        )
        .map_err(|_| "PM original retained receiver")?;
        receiver.install_wmm_model(proof);
        let mut service = drive(Service::start(receiver, power, PmEnv::default()))?
            .map_err(|_| "PM actual initial service")?;
        drive(service.park())?.map_err(|_| "PM actual initial cold park")?;
        let name = narf_net::iface::register("wlan%d", factory.mac, send_pm);
        let device = Arc::new(Device::new(&name, service));
        let registration = narf_net::iface::lookup(&name).ok_or("PM original registration")?;
        device
            .bind_admin(registration)
            .map_err(|_| "PM original OpenStopTarget binding")?;
        *ACTIVE_PM.lock() = Some(device.clone());
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain_pm);
        Ok(Box::new(Self {
            device,
            link,
            control,
            source,
            firmware,
            name,
        }))
    }
    fn request(&self, up: bool) -> Result<(), &'static str> {
        narf_net::stack::kernel_admin(&self.name)
            .ok_or("PM actual kernel admin")?
            .set_link(up)
            .map_err(|_| "PM actual administrative metadata transition")
    }
    fn settle(&self) -> Result<(), &'static str> {
        for _ in 0..10_000 {
            narf_scheduler::poll_one_round();
            if !self.device.admin_pending() {
                return Ok(());
            }
        }
        Err("PM retained executor owner did not settle")
    }
    fn wait_held(&self) -> Result<(), &'static str> {
        for _ in 0..64 {
            narf_scheduler::poll_one_round();
            if self.control.0.lock().active_td {
                return Ok(());
            }
        }
        Err("PM actual delayed EP0 publication was not reached")
    }
    fn release(&self, terminal: bool) {
        let waker = {
            let mut model = self.control.0.lock();
            model.delayed_complete = terminal;
            model.delayed_waker.clone()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    fn scan(&self) -> ScanRequest {
        ScanRequest {
            ssids: vec![SSID.to_vec()],
            channels: vec![6],
            frequencies_mhz: Vec::new(),
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(2),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }
    }
    fn join(&self) -> Result<(), &'static str> {
        let results = drive(self.device.scan(self.scan()))?.map_err(|_| "PM fresh actual scan")?;
        ensure!(
            results.len() == 1 && results[0].channel == 6,
            "PM actual target discovery"
        );
        let request = AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            channel: 6,
            frequency_mhz: 2437,
            security: if self.link.bulk.0.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        };
        drive(self.device.associate(request))?.map_err(|_| "PM actual MLME/RSNA")?;
        let lease = narf_net::dhcp::dhcp_acquire(&self.name, 0).map_err(|_| "PM actual DHCP")?;
        ensure!(
            self.link.bulk.0.lock().network.matches_lease(&lease),
            "PM actual DHCP identity"
        );
        Ok(())
    }
    fn parked(&self) -> bool {
        self.firmware.status().stage == FirmwareStage::Parked
            && self.link.bulk.0.lock().rx.is_none()
            && self.control.0.lock().regs[0x100] & 0xc0 == 0
            && self.control.0.lock().regs[0x1f] == 0
            && !self.device.link_up()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_PM.lock() = None;
        narf_net::iface::unregister(&self.name);
    }
}
fn ap(network: NetworkPlan, protected: bool) -> FakeAp {
    if protected {
        FakeAp::wpa2(network, SSID, 6, 42, PMK, ANONCE)
    } else {
        FakeAp::open(network, SSID, 6, 42)
    }
    .unwrap()
    .with_basic_1mbps()
    .unwrap()
}
fn initial_down() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    ensure!(
        h.parked() && h.control.0.lock().cold_generation == 1,
        "PM published initial DOWN without completed native cold park"
    );
    let registration = narf_net::iface::lookup(&h.name).ok_or("PM initial metadata")?;
    ensure!(
        !registration.link_up && !registration.carrier && !h.device.admin_pending(),
        "PM initial radio state disagrees with IFF_DOWN"
    );
    let before = h.control.0.lock().ops.len();
    ensure!(
        drive(h.device.scan(h.scan()))?.is_err()
            && drive(h.device.set_config(narf_wireless::WirelessConfig {
                channel: 6,
                tx_power_dbm: None
            }))?
            .is_err()
            && h.control.0.lock().ops.len() == before,
        "PM DOWN control path performed IO or waited for another executor task"
    );
    Ok(())
}
fn smoke_rtl8188eu_pm_initial_down_is_physically_parked_and_rejects_control() -> TestResult {
    initial_down().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_initial_down_is_physically_parked_and_rejects_control
);

fn conversation(protected: bool) -> Result<(), &'static str> {
    let h = Harness::new(protected)?;
    h.request(true)?;
    h.settle()?;
    h.join()?;
    let old_tk = h.link.bulk.0.lock().ptk.as_ref().map(|ptk| ptk.tk.to_vec());
    let old_rx = h.link.bulk.0.lock().rx;
    h.request(false)?;
    ensure!(
        !h.device.link_up() && send_pm(&[0; 60], narf_net::TxMeta::default()).is_err(),
        "PM DOWN did not immediately close old admission"
    );
    h.settle()?;
    ensure!(
        h.parked() && h.link.bulk.0.lock().stops > 0 && old_rx.is_some(),
        "PM DOWN did not retire original USB and power-FSM ownership"
    );
    {
        let mut peer = h.link.bulk.0.lock();
        peer.ap = ap(peer.network, protected);
        peer.ptk = None;
        peer.replay.last_seen_pn = 0;
        peer.next_pn = 1;
    }
    h.request(true)?;
    h.settle()?;
    ensure!(
        h.firmware.status().stage == FirmwareStage::Receiving
            && h.control.0.lock().rf[0x18] & 0xff == 6
            && h.link.bulk.0.lock().rx != old_rx,
        "PM wake lost the selected channel or reused its old receive TD"
    );
    h.join()?;
    if protected {
        ensure!(
            h.link
                .bulk
                .0
                .lock()
                .ptk
                .as_ref()
                .is_some_and(|ptk| Some(ptk.tk.to_vec()) != old_tk),
            "PM WPA2 wake reused old PTK material"
        );
    }
    ensure!(
        h.control.0.lock().unsafe_reuses == 0,
        "PM wake reused a live EP0 receipt"
    );
    let resets = h.control.0.lock().cold_generation;
    h.request(false)?;
    h.request(true)?;
    h.settle()?;
    ensure!(
        h.firmware.status().stage == FirmwareStage::Receiving
            && h.control.0.lock().cold_generation > resets
            && !h.device.link_up()
            && send_pm(&[0; 60], narf_net::TxMeta::default()).is_err(),
        "PM coalesced DOWN/UP kept the old association or controlled port"
    );
    h.request(false)?;
    h.settle()?;
    ensure!(h.parked(), "PM second DOWN did not park");
    Ok(())
}
fn smoke_rtl8188eu_pm_open_admin_down_up_and_native_dhcp() -> TestResult {
    conversation(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_pm_wpa2_admin_down_up_fresh_rsna_and_native_dhcp() -> TestResult {
    conversation(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_open_admin_down_up_and_native_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_wpa2_admin_down_up_fresh_rsna_and_native_dhcp
);

fn caller_loss() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.control.0.lock().delayed_write = Some(0x100);
    let mut caller = Box::pin(async {
        h.request(true)?;
        core::future::pending::<Result<(), &'static str>>().await
    });
    ensure!(
        caller
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "PM triggering caller did not queue the actual owner"
    );
    h.wait_held()?;
    drop(caller);
    ensure!(
        h.device.admin_pending() && h.control.0.lock().active_td,
        "PM caller Drop cancelled the published native owner"
    );
    h.release(true);
    h.settle()?;
    ensure!(
        h.firmware.status().stage == FirmwareStage::Receiving
            && h.link.bulk.0.lock().rx.is_some()
            && h.control.0.lock().unsafe_reuses == 0,
        "PM retained task did not finish after caller loss"
    );
    h.request(false)?;
    h.settle()?;
    ensure!(h.parked(), "PM caller-loss cleanup did not park");
    Ok(())
}
fn smoke_rtl8188eu_pm_dropped_triggering_caller_cannot_drop_published_usb_work() -> TestResult {
    caller_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_dropped_triggering_caller_cannot_drop_published_usb_work
);

fn reversal() -> Result<(), &'static str> {
    for final_up in [false, true] {
        let h = Harness::new(false)?;
        h.control.0.lock().delayed_write = Some(0x100);
        h.request(true)?;
        h.wait_held()?;
        let before = h.control.0.lock().ops.len();
        h.request(false)?;
        if final_up {
            h.request(true)?;
        }
        ensure!(
            drive(h.device.scan(h.scan()))?.is_err()
                && h.control.0.lock().ops.len() == before
                && h.control.0.lock().active_td,
            "PM reversal interrupted EP0 or sync control waited for its task"
        );
        h.release(true);
        h.settle()?;
        if final_up {
            ensure!(
                h.firmware.status().stage == FirmwareStage::Receiving
                    && h.link.bulk.0.lock().rx.is_some(),
                "PM latest UP was lost behind an old DOWN"
            );
            h.request(false)?;
            h.settle()?;
        }
        ensure!(
            h.parked() && h.control.0.lock().unsafe_reuses == 0,
            "PM reversal failed to finish real USB work before its final state"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_pm_fast_reversals_finish_original_ep0_before_latest_request() -> TestResult {
    reversal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_fast_reversals_finish_original_ep0_before_latest_request
);

fn source_loss() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.control.0.lock().delayed_write = Some(0x100);
    h.request(true)?;
    h.wait_held()?;
    let before = h.control.0.lock().ops.len();
    h.source.revoke();
    h.release(false);
    h.settle()?;
    ensure!(
        h.firmware.status().stage == FirmwareStage::Failed
            && h.control.0.lock().active_td
            && h.control.0.lock().unsafe_reuses == 0
            && h.control.0.lock().ops.len() == before
            && h.link.bulk.0.lock().rx.is_none(),
        "PM source loss reused or released a pending native receipt"
    );
    h.request(false)?;
    h.settle()?;
    h.request(true)?;
    h.settle()?;
    ensure!(
        h.control.0.lock().ops.len() == before && !h.device.link_up(),
        "PM source-lost owner was revived by a later administrative request"
    );
    Ok(())
}
fn smoke_rtl8188eu_pm_source_loss_keeps_published_ep0_terminal_and_retained() -> TestResult {
    source_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_source_loss_keeps_published_ep0_terminal_and_retained
);

fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}
fn stale_registration() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.control.0.lock().delayed_write = Some(0x100);
    h.request(true)?;
    h.wait_held()?;
    ensure!(
        narf_net::iface::retire_for_rebind(&h.name),
        "PM actual original retirement"
    );
    let name = narf_net::iface::rebind_name(&h.name).ok_or("PM actual successor name")?;
    narf_net::iface::register(name, h.device.mac(), reject);
    narf_net::iface::set_link_state(name, true);
    narf_net::iface::set_link_metadata(name, true, None, None);
    h.release(true);
    h.settle()?;
    let successor = narf_net::iface::lookup(name).ok_or("PM actual successor metadata")?;
    ensure!(
        h.parked()
            && successor.link_up
            && successor.carrier
            && h.control.0.lock().unsafe_reuses == 0,
        "PM stale wake published or withdrew carrier on a same-name successor"
    );
    Ok(())
}
fn smoke_rtl8188eu_pm_stale_up_cleans_only_original_receiver_after_rebind() -> TestResult {
    stale_registration().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_stale_up_cleans_only_original_receiver_after_rebind
);

fn failed_stop() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.request(true)?;
    h.settle()?;
    let old = h.link.bulk.0.lock().rx;
    let resets = h.control.0.lock().cold_generation;
    h.link.bulk.0.lock().fail_stop = true;
    h.request(false)?;
    h.settle()?;
    ensure!(
        h.firmware.status().stage == FirmwareStage::Failed
            && old.is_some()
            && h.link.bulk.0.lock().rx == old
            && h.control.0.lock().cold_generation == resets
            && h.control.0.lock().regs[0x100] & 0xc0 == 0,
        "PM failed native Stop discarded a receipt or became a cold-park completion"
    );
    let before = h.control.0.lock().ops.len();
    h.link.bulk.0.lock().fail_stop = false;
    h.request(true)?;
    h.settle()?;
    ensure!(
        h.control.0.lock().ops.len() == before && h.link.bulk.0.lock().rx == old,
        "PM failed USB owner was retried after a later UP"
    );
    Ok(())
}
fn smoke_rtl8188eu_pm_failed_native_bulk_stop_retains_original_receive_receipt() -> TestResult {
    failed_stop().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/runtime_pm",
    smoke_rtl8188eu_pm_failed_native_bulk_stop_retains_original_receive_receipt
);
