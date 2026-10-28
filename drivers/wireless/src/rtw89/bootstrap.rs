// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained B discovery/reset/firmware/radio/Device composition.
//! This module is wired only with the complete source full-radio continuation.
use super::{
    interface::Device,
    pci_reset,
    startup::{self, Phase},
    station,
    station_lifecycle::Lifecycle,
};
use alloc::{string::String, sync::Arc};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Stage {
    Reset,
    Discovery,
    Firmware,
    Radio,
    WaitingAssets,
    Station,
    /// Generation retired for system suspend; waits for resume.
    Suspended,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Reset(pci_reset::Error),
    Startup(startup::Error),
    Station(station::Error),
    Cancelled,
}
pub(super) struct Bootstrap {
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    reset: Mutex<Option<pci_reset::Reset>>,
    lifecycle: IrqSafeSpinLock<Option<Arc<Lifecycle<startup::Startup>>>>,
    shell: IrqSafeSpinLock<Option<Arc<Device<startup::Startup>>>>,
    stage: AtomicU8,
    error: IrqSafeSpinLock<Option<Error>>,
    request: IrqSafeSpinLock<Option<super::command_native::QualificationRequest>>,
    running: AtomicBool,
    /// Set by the PCI remove hook before it retires the owner.
    removed: AtomicBool,
    /// A retired generation could not prove its DMA stopped.
    pinned: AtomicBool,
    /// Generations started after the first (SER L2-style resets).
    generation: AtomicU32,
    /// System suspend requested; the supervisor parks instead of resetting.
    suspended: AtomicBool,
}
static OWNER: IrqSafeSpinLock<Option<Arc<Bootstrap>>> = IrqSafeSpinLock::new(None);
static RESERVED: AtomicBool = AtomicBool::new(false);
struct Attempt<'a> {
    owner: &'a Bootstrap,
    complete: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner
                .stage
                .store(Stage::Terminal as u8, Ordering::Release);
            let shell = {
                let retained = self.owner.shell.lock();
                retained.clone()
            };
            if let Some(shell) = shell {
                shell.admission().close();
            }
            // Never park/configure/drop a hardware producer here. A cancelled
            // reset may still own its mandatory no-config FLR quarantine.
        }
    }
}
impl Bootstrap {
    fn set_stage(&self, stage: Stage) {
        self.stage.store(stage as u8, Ordering::Release);
    }
    fn report(&self, error: Error) {
        let changed = {
            let mut old = self.error.lock();
            let changed = *old != Some(error);
            *old = Some(error);
            changed
        };
        if changed {
            narf_console::klog!("rtw8852b: retained startup {:?}\n", error);
        }
    }
    fn report_request(&self, request: Option<super::command_native::QualificationRequest>) {
        let changed = {
            let mut old = self.request.lock();
            let changed = *old != request;
            *old = request;
            changed
        };
        if changed {
            if let Some(request) = request {
                let mut digest = String::with_capacity(64);
                for byte in request.digest() {
                    let _ = write!(&mut digest, "{byte:02x}");
                }
                narf_console::klog!(
                    "rtw8852b: measured qualification {} identity={}\n",
                    request.name(),
                    digest
                );
                if let Some(identity) = request.qos_digest() {
                    let mut digest = String::with_capacity(64);
                    for byte in identity {
                        let _ = write!(&mut digest, "{byte:02x}");
                    }
                    narf_console::klog!(
                        "rtw8852b: optional all-AC QoS qualification {} flags=15 identity={}\n",
                        request.name(),
                        digest
                    );
                }
                if let Some(identity) = request.wmm_digest() {
                    let mut digest = String::with_capacity(64);
                    for byte in identity {
                        let _ = write!(&mut digest, "{byte:02x}");
                    }
                    narf_console::klog!(
                        "rtw8852b: optional WMM qualification {} flags=7 identity={}\n",
                        request.name(),
                        digest
                    );
                }
            }
        }
    }
    /// Generation supervisor (Linux SER L2, `ser.c::ser_l2_reset_st_hdl`:
    /// `rtw89_core_stop` then `ieee80211_restart_hw`). Every generation that
    /// reached a started station and then closed (firmware HALT_C2H/WDT,
    /// a fatal transport error or a disconnect) is retired behind the DMA
    /// proof; a proven reclamation rearms a fresh FLR and a new startup on
    /// the same function and interface name so the station can rejoin.
    async fn drive(&self) -> Result<(), Error> {
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Cancelled)?;
        let mut attempt = Attempt {
            owner: self,
            complete: false,
        };
        let mut name: Option<String> = None;
        loop {
            let result = self.generation(name.as_deref()).await;
            let reclaimed = self.retire_generation().await;
            let generation = self.generation.load(Ordering::Acquire);
            let action = supervise(
                result.is_ok(),
                self.removed.load(Ordering::Acquire),
                reclaimed,
                self.suspended.load(Ordering::Acquire),
                generation,
            );
            if action == Action::Park {
                // Linux `rtw89_ops_stop` without WoW: the generation is
                // retired; resume restarts with a fresh FLR.
                self.set_stage(Stage::Suspended);
                while self.suspended.load(Ordering::Acquire)
                    && !self.removed.load(Ordering::Acquire)
                {
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(10_000_000)).await;
                }
                if self.removed.load(Ordering::Acquire) {
                    self.set_stage(Stage::Terminal);
                    attempt.complete = true;
                    return Err(Error::Cancelled);
                }
                narf_console::klog!("rtw8852b: resuming with a fresh FLR\n");
            } else if action == Action::Stop {
                self.set_stage(Stage::Terminal);
                attempt.complete = result.is_ok();
                return result;
            }
            if action == Action::Regenerate {
                narf_console::klog!("rtw8852b: generation {} closed; resetting\n", generation);
            }
            match self.rearm().await {
                Some(kept) => name = kept.or(name),
                None => {
                    self.set_stage(Stage::Terminal);
                    attempt.complete = true;
                    return Err(Error::Cancelled);
                }
            }
        }
    }
    /// Retire the current generation's owner (station stop, DMA proof,
    /// reclamation, XTAL/RF shutdown) under its lifecycle mutex. True only
    /// when nothing remains pinned; a pinned owner marks the function.
    async fn retire_generation(&self) -> bool {
        let lifecycle = {
            let lifecycle = self.lifecycle.lock();
            lifecycle.clone()
        };
        let Some(lifecycle) = lifecycle else {
            return !self.pinned.load(Ordering::Acquire);
        };
        let mut retained = lifecycle.retained.lock().await;
        let reclaimed = match retained.as_mut() {
            Some(owner) => {
                let reclaimed = owner.retire();
                let _ = owner.io.finish_station_shutdown().await;
                reclaimed
            }
            None => !self.pinned.load(Ordering::Acquire),
        };
        *retained = None;
        if !reclaimed {
            self.pinned.store(true, Ordering::Release);
        }
        reclaimed
    }
    /// Withdraw the closed shell (keeping its name), drop the retired
    /// lifecycle and claim a fresh reset for the next generation. The reset
    /// is stored under its mutex after the removed check, so a concurrent
    /// removal either sees it (and drops it) or stops this rearm.
    async fn rearm(&self) -> Option<Option<String>> {
        if self.removed.load(Ordering::Acquire) {
            return None;
        }
        let shell = self.shell.lock().take();
        let kept = shell
            .as_ref()
            .map(|shell| super::interface::withdraw_keep_name(shell));
        *self.lifecycle.lock() = None;
        // SAFETY: the singleton reservation is still held, the previous
        // generation's DMA was proven stopped/reclaimed with BME off and no
        // producer remains; the reset still earns its own temporal fence.
        let reset = unsafe { pci_reset::Reset::claim(self.device, self.authority) }
            .ok()?
            .repeat();
        let mut slot = self.reset.lock().await;
        if self.removed.load(Ordering::Acquire) {
            return None;
        }
        *slot = Some(reset);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Some(kept)
    }
    async fn generation(&self, kept: Option<&str>) -> Result<(), Error> {
        let retained_lifecycle = {
            let owner = self.lifecycle.lock();
            owner.clone()
        };
        let lifecycle = match retained_lifecycle {
            Some(lifecycle) => lifecycle,
            None => {
                self.set_stage(Stage::Reset);
                // The reset guard stays held until the lifecycle is
                // published, so removal sees either the reset or the owner.
                let mut reset = self.reset.lock().await;
                let fence = reset
                    .as_mut()
                    .ok_or(Error::Cancelled)?
                    .run()
                    .await
                    .map_err(Error::Reset)?;
                if self.removed.load(Ordering::Acquire) {
                    return Err(Error::Cancelled);
                }
                let startup = startup::Startup::claim_reset(self.device, self.authority, fence)
                    .map_err(Error::Startup)?;
                // Retain the exact startup before its first cold/firmware attempt.
                let lifecycle = Arc::new(Lifecycle::new(startup));
                *self.lifecycle.lock() = Some(lifecycle.clone());
                drop(reset);
                lifecycle
            }
        };
        self.set_stage(Stage::Discovery);
        let identity = {
            let mut retained = lifecycle.retained.lock().await;
            retained
                .as_mut()
                .ok_or(Error::Cancelled)?
                .io
                .discover()
                .await
                .map_err(Error::Startup)?
        };
        let name = kept.unwrap_or_else(|| narf_net::iface::reserve_name("wlan%d"));
        let shell = Arc::new(Device::new(
            name,
            identity.mac(),
            lifecycle.clone(),
            Arc::new(station::NativeEnvironment),
        ));
        *self.shell.lock() = Some(shell.clone());
        // Source factory discovery ended with BME off. The exact same shell
        // reaches all registries before the first CH12/firmware BME attempt.
        if self.removed.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        super::interface::publish(shell.clone()).map_err(Error::Station)?;
        // A removal that read no shell before this publication withdraws it.
        if self.removed.load(Ordering::Acquire) {
            super::interface::withdraw(&shell);
            return Err(Error::Cancelled);
        }
        loop {
            if shell.closed() || self.suspended.load(Ordering::Acquire) {
                terminalize(&shell, &lifecycle).await;
                return Err(Error::Cancelled);
            }
            let result = {
                let mut retained = lifecycle.retained.lock().await;
                let owner = retained.as_mut().ok_or(Error::Cancelled)?;
                self.set_stage(if owner.io.phase() == Phase::Discovered {
                    Stage::Firmware
                } else {
                    Stage::Radio
                });
                advance(&mut owner.io).await
            };
            match result {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    let (retry, request) = {
                        let retained = lifecycle.retained.lock().await;
                        let retry = retained.as_ref().is_some_and(|owner| {
                            matches!(
                                owner.io.phase(),
                                Phase::Discovered
                                    | Phase::RadioTablesLoaded
                                    | Phase::BasicCalibrated
                            )
                        });
                        (
                            retry,
                            retained
                                .as_ref()
                                .and_then(|owner| owner.io.qualification_request().ok()),
                        )
                    };
                    if !retry {
                        return Err(Error::Startup(error));
                    }
                    self.set_stage(Stage::WaitingAssets);
                    self.report_request(request);
                    self.report(Error::Startup(error));
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
                }
            }
        }
        shell.activate().await.map_err(Error::Station)?;
        // rtw89_pci_ops_start: the packet runtime is live, enable MSI.
        match shell.arm_interrupts().await {
            Ok(vector) => narf_console::klog!("rtw8852b: MSI delivery on vector {}\n", vector),
            Err(error) => narf_console::klog!("rtw8852b: polled delivery ({:?})\n", error),
        }
        self.set_stage(Stage::Station);
        *self.error.lock() = None;
        // Device's independent bounded drain worker handles stack progress.
        // Terminal analog shutdown awaits after the explicit disconnect's
        // reservation is released, preserving its CH12/media-down operation.
        loop {
            if shell.closed() && !shell.admission().teardown_pending() {
                terminalize(&shell, &lifecycle).await;
                break;
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Regenerate,
    /// System suspend: hold the retired generation until resume.
    Park,
    Stop,
}
/// Bound on generations per boot, so a station that keeps halting cannot
/// cycle FLR/firmware download forever.
const MAX_GENERATIONS: u32 = 64;
/// Regenerate only a generation that reached a started station, while the
/// function is not being removed and its DMA was proven reclaimed. A startup
/// failure before the station (missing assets, firmware, calibration) stops.
/// A suspend parks any generation whose DMA was reclaimed, started or not.
fn supervise(
    reached_station: bool,
    removed: bool,
    reclaimed: bool,
    suspended: bool,
    generation: u32,
) -> Action {
    if suspended && !removed && reclaimed && generation + 1 < MAX_GENERATIONS {
        Action::Park
    } else if !suspended
        && reached_station
        && !removed
        && reclaimed
        && generation + 1 < MAX_GENERATIONS
    {
        Action::Regenerate
    } else {
        Action::Stop
    }
}
async fn terminalize(shell: &Device<startup::Startup>, lifecycle: &Lifecycle<startup::Startup>) {
    loop {
        if shell.admission().teardown_pending() {
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
            continue;
        }
        let mut retained = lifecycle.retained.lock().await;
        if shell.admission().teardown_pending() {
            drop(retained);
            continue;
        }
        if let Some(owner) = retained.as_mut() {
            let _ = owner.station_stop();
            let _ = owner.io.finish_station_shutdown().await;
        }
        return;
    }
}
async fn advance(io: &mut startup::Startup) -> Result<bool, startup::Error> {
    match io.phase() {
        // B has no C-only PCI_BER quirk. pcie::Pcie rejects that quirk for B.
        Phase::Discovered => io.start(false).await?,
        Phase::Running => io.prepare_mac().await?,
        Phase::MacPrepared => io.prepare_receive().await?,
        Phase::Receiving => io.prepare_radio_tables().await?,
        Phase::RadioTablesLoaded => io.prepare_basic_calibration().await?,
        Phase::BasicCalibrated => io.prepare_full_radio().await?,
        Phase::RadioReady => return Ok(true),
        _ => return Err(startup::Error::Terminal),
    }
    Ok(false)
}
impl Bootstrap {
    /// Linux `rtw89_pci_remove` order: withdraw the interface
    /// (`rtw89_core_unregister`), wait out any in-flight FLR quarantine,
    /// then stop the station and release DMA (`rtw89_pci_clear_resource`)
    /// behind the stop proof. True only when nothing remains pinned.
    async fn retire(&self) -> bool {
        self.removed.store(true, Ordering::Release);
        let shell = {
            let shell = self.shell.lock();
            shell.clone()
        };
        if let Some(shell) = shell.as_ref() {
            super::interface::withdraw(shell);
        }
        // An accepted FLR keeps its mandatory no-config quarantine; the
        // reset is dropped only after `run` returned.
        drop(self.reset.lock().await.take());
        let reclaimed = self.retire_generation().await;
        self.set_stage(Stage::Terminal);
        reclaimed
    }
}
/// How long system suspend waits for the generation to retire.
const SUSPEND_MS: u64 = 10_000;
/// `rtw89_ops_stop` (no WoW) for system suspend: close the current
/// generation and wait until the supervisor retired it behind the DMA proof
/// and parked (or stopped). On timeout the request is withdrawn so the
/// device stays usable, as `AsyncSystemPm::prepare_suspend` requires.
async fn suspend_owner(
    owner: &Bootstrap,
    timeout_ms: u64,
) -> Result<(), narf_power::device_pm::DevicePmError> {
    let stage = owner.stage.load(Ordering::Acquire);
    if stage == Stage::Terminal as u8 || !owner.running.load(Ordering::Acquire) {
        return Ok(());
    }
    owner.suspended.store(true, Ordering::Release);
    let shell = {
        let shell = owner.shell.lock();
        shell.clone()
    };
    if let Some(shell) = shell {
        shell.admission().close();
    }
    let deadline = narf_time::Deadline::after_ms(timeout_ms);
    loop {
        let stage = owner.stage.load(Ordering::Acquire);
        if stage == Stage::Suspended as u8 || stage == Stage::Terminal as u8 {
            return Ok(());
        }
        if deadline.expired() {
            owner.suspended.store(false, Ordering::Release);
            return Err(narf_power::device_pm::DevicePmError::Busy);
        }
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
}
/// `rtw89_ops_start` after resume: release the parked supervisor, which
/// claims a fresh FLR and restarts with the `Repeat` radio identity.
fn resume_owner(owner: &Bootstrap) {
    owner.suspended.store(false, Ordering::Release);
}
/// Async system-PM hook (the interrupt-gated `DevicePmOps` fan-out cannot
/// await firmware/H2C or the DMA-stop retirement).
pub(super) struct SystemPm;
impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            let owner = OWNER.lock().clone();
            match owner {
                Some(owner) => suspend_owner(&owner, SUSPEND_MS).await,
                None => Ok(()),
            }
        })
    }
    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            if let Some(owner) = OWNER.lock().clone() {
                resume_owner(&owner);
            }
            Ok(())
        })
    }
}
/// Release the singleton reservation only after proven reclamation. A
/// pinned owner stays reserved (and its address quarantined) for the boot.
async fn finish_remove(owner: Arc<Bootstrap>) -> bool {
    let reclaimed = owner.retire().await;
    if reclaimed {
        let mut retained = OWNER.lock();
        if retained
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &owner))
        {
            *retained = None;
            RESERVED.store(false, Ordering::Release);
        }
    }
    narf_console::klog!(
        "rtw8852b: removed; DMA {}\n",
        if reclaimed {
            "reclaimed"
        } else {
            "pinned, function quarantined"
        }
    );
    reclaimed
}
/// `narf_bus` PCI remove hook for the retained RTL8852B owner.
pub(super) fn remove(device: BusDevice, _authority: Cap<BusDeviceCap, Write>) {
    let owner = OWNER.lock().clone();
    let Some(owner) = owner else {
        return;
    };
    if owner.device.addr != device.addr || owner.removed.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(async move {
        finish_remove(owner).await;
    });
}
/// Safe bus-match path only uses an observed successful FLR. Unsupported
/// functions remain parked; no board assertion becomes a temporal reset proof.
pub(super) fn probe(
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let existing = OWNER.lock().clone();
    if let Some(owner) = existing {
        if owner.device.addr == device.addr {
            return Ok(());
        }
        return crate::rtw88::pci_park::invoke(&authority, || {
            crate::rtw88::pci_park::park(&device, &authority)
        })
        .map_err(|_| narf_bus::ProbeError::BadDevice)?
        .map_err(|_| narf_bus::ProbeError::BadDevice);
    }
    RESERVED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: singleton reservation above is retained permanently before the
    // first await; no diagnostic, IRQ or other producer can reach this BDF.
    let reset = match unsafe { pci_reset::Reset::claim(device, authority) } {
        Ok(reset) => reset,
        Err(_) => {
            RESERVED.store(false, Ordering::Release);
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    // A parking operation before reset only limits inherited DMA. It grants
    // no fence; the retained reset below must still earn an actual FLR receipt.
    if crate::rtw88::pci_park::invoke(&authority, || {
        crate::rtw88::pci_park::park(&device, &authority)
    })
    .ok()
        != Some(Ok(()))
    {
        RESERVED.store(false, Ordering::Release);
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let owner = Arc::new(Bootstrap {
        device,
        authority,
        reset: Mutex::new(Some(reset)),
        lifecycle: IrqSafeSpinLock::new(None),
        shell: IrqSafeSpinLock::new(None),
        stage: AtomicU8::new(Stage::Reset as u8),
        error: IrqSafeSpinLock::new(None),
        request: IrqSafeSpinLock::new(None),
        running: AtomicBool::new(false),
        removed: AtomicBool::new(false),
        pinned: AtomicBool::new(false),
        generation: AtomicU32::new(0),
        suspended: AtomicBool::new(false),
    });
    publish_owner(owner);
    Ok(())
}
fn publish_owner(owner: Arc<Bootstrap>) {
    let device = owner.device;
    *OWNER.lock() = Some(owner.clone());
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: String::from("rtw89-rtl8852b"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    narf_scheduler::spawn(async move {
        if let Err(error) = owner.drive().await {
            owner.report(error);
        }
    });
}
/// # Safety
/// A trusted platform has actually reset/power-cycled this exact function,
/// drained posted traffic and proved that firmware/another driver has not
/// owned Wi-Fi DMA since. The function and its cap remain exclusively held.
/// BME-off, a static board manifest or a claimed cold boot is insufficient.
/// Call before generic PCI binding; an existing owner is never replaced.
pub(super) unsafe fn attach_cold(
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != 0x10ec
        || !matches!(device.id.device, 0xb852 | 0xb85b)
        || OWNER.lock().is_some()
    {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    RESERVED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller's actual temporal platform-reset and exclusive function
    // contract above replaces only the observed FLR receipt, not any later
    // firmware/factory/radio/policy/packet prerequisite.
    let startup = match unsafe { startup::Startup::claim(device, authority) } {
        Ok(startup) => startup,
        Err(_) => {
            RESERVED.store(false, Ordering::Release);
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    let lifecycle = Arc::new(Lifecycle::new(startup));
    let owner = Arc::new(Bootstrap {
        device,
        authority,
        reset: Mutex::new(None),
        lifecycle: IrqSafeSpinLock::new(Some(lifecycle)),
        shell: IrqSafeSpinLock::new(None),
        stage: AtomicU8::new(Stage::Discovery as u8),
        error: IrqSafeSpinLock::new(None),
        request: IrqSafeSpinLock::new(None),
        running: AtomicBool::new(false),
        removed: AtomicBool::new(false),
        pinned: AtomicBool::new(false),
        generation: AtomicU32::new(0),
        suspended: AtomicBool::new(false),
    });
    publish_owner(owner);
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Reservation;
    impl Drop for Reservation {
        fn drop(&mut self) {
            *OWNER.lock() = None;
            RESERVED.store(false, Ordering::Release);
        }
    }
    fn device() -> BusDevice {
        let addr = narf_bus::PcieAddr::new(u16::MAX, u8::MAX, 31, 7);
        BusDevice {
            addr: narf_bus::BusAddr::Pcie(addr),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0xb852,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        }
    }
    fn smoke_rtw8852b_retained_probe_never_reparks_or_replaces_reset_owner() -> TestResult {
        if OWNER.lock().is_some()
            || RESERVED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return TestResult::Skip("physical RTL8852B reservation already exists");
        }
        let _reservation = Reservation;
        let device = device();
        let authority = Cap::bootstrap();
        // Pure ownership fixture: deliberately no Reset or native producer.
        // Any attempted config access to its zero ECAM would be invalid.
        let owner = Arc::new(Bootstrap {
            device,
            authority,
            reset: Mutex::new(None),
            lifecycle: IrqSafeSpinLock::new(None),
            shell: IrqSafeSpinLock::new(None),
            stage: AtomicU8::new(Stage::Reset as u8),
            error: IrqSafeSpinLock::new(None),
            request: IrqSafeSpinLock::new(None),
            running: AtomicBool::new(true),
            removed: AtomicBool::new(false),
            pinned: AtomicBool::new(false),
            generation: AtomicU32::new(0),
            suspended: AtomicBool::new(false),
        });
        *OWNER.lock() = Some(owner.clone());
        if probe(device, authority).is_err() {
            return TestResult::Fail("retained same-function probe did not return without access");
        }
        // SAFETY: the existing singleton must reject before any hardware or
        // platform-reset claim is used; fixture has no physical PCI function.
        if unsafe { attach_cold(device, authority) }.is_ok() {
            return TestResult::Fail("cold-platform entry replaced a retained reset owner");
        }
        if OWNER
            .lock()
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &owner))
            || owner.reset.try_lock().is_none_or(|reset| reset.is_some())
            || owner.stage.load(Ordering::Acquire) != Stage::Reset as u8
        {
            return TestResult::Fail("reprobe reconstructed or advanced the reserved reset");
        }
        TestResult::Pass
    }
    fn fixture(
        device: BusDevice,
        lifecycle: Option<Arc<Lifecycle<startup::Startup>>>,
    ) -> Arc<Bootstrap> {
        Arc::new(Bootstrap {
            device,
            authority: Cap::bootstrap(),
            reset: Mutex::new(None),
            lifecycle: IrqSafeSpinLock::new(lifecycle),
            shell: IrqSafeSpinLock::new(None),
            stage: AtomicU8::new(Stage::Reset as u8),
            error: IrqSafeSpinLock::new(None),
            request: IrqSafeSpinLock::new(None),
            running: AtomicBool::new(true),
            removed: AtomicBool::new(false),
            pinned: AtomicBool::new(false),
            generation: AtomicU32::new(0),
            suspended: AtomicBool::new(false),
        })
    }
    fn ready<T>(future: impl core::future::Future<Output = T>) -> Option<T> {
        let mut future = core::pin::pin!(future);
        match future.as_mut().poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) {
            core::task::Poll::Ready(value) => Some(value),
            core::task::Poll::Pending => None,
        }
    }
    fn smoke_rtw8852b_remove_releases_unpublished_and_quarantines_pinned_owner() -> TestResult {
        if OWNER.lock().is_some()
            || RESERVED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return TestResult::Skip("physical RTL8852B reservation already exists");
        }
        let _reservation = Reservation;
        let device = device();
        // Owner that never completed reset: nothing was published.
        let owner = fixture(device, None);
        *OWNER.lock() = Some(owner.clone());
        let mut other = device;
        other.addr = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(u16::MAX, u8::MAX, 30, 7));
        remove(other, Cap::bootstrap());
        if owner.removed.load(Ordering::Acquire) {
            return TestResult::Fail("remove hook acted on a different function");
        }
        if ready(finish_remove(owner.clone())) != Some(true)
            || OWNER.lock().is_some()
            || RESERVED.load(Ordering::Acquire)
            || !owner.removed.load(Ordering::Acquire)
            || owner.stage.load(Ordering::Acquire) != Stage::Terminal as u8
        {
            return TestResult::Fail("unpublished owner removal kept the singleton reservation");
        }
        // Owner whose retained DMA owner cannot be proven reclaimed (already
        // taken): the reservation and address stay quarantined.
        RESERVED.store(true, Ordering::Release);
        let lifecycle = Arc::new(Lifecycle {
            retained: Mutex::new(None),
        });
        let pinned = fixture(device, Some(lifecycle));
        pinned.pinned.store(true, Ordering::Release);
        *OWNER.lock() = Some(pinned.clone());
        if ready(finish_remove(pinned.clone())) != Some(false)
            || OWNER
                .lock()
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &pinned))
            || !RESERVED.load(Ordering::Acquire)
        {
            return TestResult::Fail("unproven removal released the singleton reservation");
        }
        // A quarantined address re-probe returns without configuration access.
        if probe(device, Cap::bootstrap()).is_err() {
            return TestResult::Fail("quarantined function re-probe touched the device");
        }
        // A second hook invocation never schedules another retirement.
        remove(device, Cap::bootstrap());
        TestResult::Pass
    }
    fn smoke_rtw8852b_generation_supervisor_regenerates_only_proven_station_closures() -> TestResult
    {
        // Halted or disconnected started station with proven reclamation.
        if supervise(true, false, true, false, 0) != Action::Regenerate
            || supervise(true, false, true, false, MAX_GENERATIONS - 2) != Action::Regenerate
        {
            return TestResult::Fail("closed station with reclaimed DMA was not reset");
        }
        for (reached, removed, reclaimed, generation) in [
            (false, false, true, 0),
            (true, true, true, 0),
            (true, false, false, 0),
            (true, false, true, MAX_GENERATIONS - 1),
        ] {
            if supervise(reached, removed, reclaimed, false, generation) != Action::Stop {
                return TestResult::Fail(
                    "startup failure, removal, pinned DMA or generation bound regenerated",
                );
            }
        }
        // Retirement of a generation with no owner reports the pinned mark.
        let lifecycle = Arc::new(Lifecycle {
            retained: Mutex::new(None),
        });
        let owner = fixture(device(), Some(lifecycle.clone()));
        if ready(owner.retire_generation()) != Some(true) {
            return TestResult::Fail("ownerless unpinned generation was not reclaimable");
        }
        owner.pinned.store(true, Ordering::Release);
        if ready(owner.retire_generation()) != Some(false) {
            return TestResult::Fail("pinned generation reported reclamation");
        }
        // System suspend parks any reclaimed generation, never one with
        // pinned DMA or a removed function; resume then regenerates.
        if supervise(false, false, true, true, 0) != Action::Park
            || supervise(true, false, true, true, 3) != Action::Park
            || supervise(true, false, false, true, 0) != Action::Stop
            || supervise(true, true, true, true, 0) != Action::Stop
        {
            return TestResult::Fail("suspend parking policy differed");
        }
        // A removal racing a rearm stops it before any reset is stored.
        let owner = fixture(device(), None);
        owner.removed.store(true, Ordering::Release);
        if ready(owner.rearm()) != Some(None)
            || owner.reset.try_lock().is_none_or(|reset| reset.is_some())
            || owner.generation.load(Ordering::Acquire) != 0
        {
            return TestResult::Fail("rearm stored a reset for a removed function");
        }
        TestResult::Pass
    }
    fn smoke_rtw8852b_system_suspend_waits_for_parked_generation_or_withdraws() -> TestResult {
        use narf_power::device_pm::DevicePmError;
        // No running supervisor: nothing to suspend.
        let idle = fixture(device(), None);
        idle.running.store(false, Ordering::Release);
        if ready(suspend_owner(&idle, 0)) != Some(Ok(())) || idle.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("idle owner suspend did not complete without a request");
        }
        // A supervisor that already parked the retired generation.
        let parked = fixture(device(), None);
        parked.set_stage(Stage::Suspended);
        if ready(suspend_owner(&parked, 0)) != Some(Ok(()))
            || !parked.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("parked generation did not satisfy suspend");
        }
        resume_owner(&parked);
        if parked.suspended.load(Ordering::Acquire) {
            return TestResult::Fail("resume did not release the parked supervisor");
        }
        // A generation that never retires: suspend fails and withdraws its
        // request so the device stays usable.
        let busy = fixture(device(), None);
        busy.set_stage(Stage::Station);
        if ready(suspend_owner(&busy, 0)) != Some(Err(DevicePmError::Busy))
            || busy.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("unretired generation suspended or kept the request");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/bootstrap",
        smoke_rtw8852b_retained_probe_never_reparks_or_replaces_reset_owner
    );
    kernel_test_in!(
        "drivers/wireless/rtw89/bootstrap",
        smoke_rtw8852b_system_suspend_waits_for_parked_generation_or_withdraws
    );
    kernel_test_in!(
        "drivers/wireless/rtw89/bootstrap",
        smoke_rtw8852b_generation_supervisor_regenerates_only_proven_station_closures
    );
    kernel_test_in!(
        "drivers/wireless/rtw89/bootstrap",
        smoke_rtw8852b_remove_releases_unpublished_and_quarantines_pinned_owner
    );
}
