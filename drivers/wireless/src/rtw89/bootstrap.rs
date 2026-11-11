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
use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use narf_bus::{BusAddr, BusDevice, BusDeviceCap};
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
    desired: Arc<super::monitor::Desired>,
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
    /// System suspend took the WoW branch: the generation stays live (D3hot,
    /// no card-off) with the WoW image owning the radio until resume; the
    /// config header and MSI capability `pci_save_state` saved before the
    /// driver op.
    wow: IrqSafeSpinLock<Option<PciState>>,
    /// cfg80211 `wiphy->wowlan_config` and the last wake report, carried
    /// from a retired generation's shell into the next one.
    wowlan: IrqSafeSpinLock<(
        Option<narf_wireless::WowlanConfig>,
        Option<super::wow_wire::WakeReport>,
    )>,
}
/// Reservation precedes any config/reset access. A pinned function keeps
/// its own entry while unrelated functions may continue to run or bind.
struct Function {
    addr: BusAddr,
    owner: Option<Arc<Bootstrap>>,
}
struct Functions {
    entries: Vec<Function>,
    suspending: bool,
}
impl Functions {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
            suspending: false,
        }
    }
    fn owner(&self, addr: BusAddr) -> Option<Arc<Bootstrap>> {
        self.entries
            .iter()
            .find(|entry| entry.addr == addr)?
            .owner
            .clone()
    }
    fn snapshot(&self) -> Vec<Arc<Bootstrap>> {
        self.entries
            .iter()
            .filter_map(|entry| entry.owner.clone())
            .collect()
    }
    fn reserve(&mut self, addr: BusAddr) -> Result<bool, narf_bus::ProbeError> {
        if self.suspending {
            return Err(narf_bus::ProbeError::BadDevice);
        }
        if let Some(entry) = self.entries.iter().find(|entry| entry.addr == addr) {
            return if entry.owner.is_some() {
                Ok(false)
            } else {
                Err(narf_bus::ProbeError::BadDevice)
            };
        }
        if self.entries.len() == super::endpoints::MAX_FUNCTIONS {
            return Err(narf_bus::ProbeError::BadDevice);
        }
        self.entries.push(Function { addr, owner: None });
        Ok(true)
    }
    fn forget(&mut self, owner: &Arc<Bootstrap>) {
        self.entries.retain(|entry| {
            entry
                .owner
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, owner))
        });
    }
}
static OWNERS: IrqSafeSpinLock<Functions> = IrqSafeSpinLock::new(Functions::new());
struct Reservation {
    addr: BusAddr,
}
impl Reservation {
    fn claim(addr: BusAddr) -> Result<Option<Self>, narf_bus::ProbeError> {
        let reserved = OWNERS.lock().reserve(addr)?;
        Ok(if reserved { Some(Self { addr }) } else { None })
    }
    fn publish(self, owner: Arc<Bootstrap>) {
        let mut owners = OWNERS.lock();
        let entry = owners
            .entries
            .iter_mut()
            .find(|entry| entry.addr == self.addr)
            .expect("retained function reservation");
        assert!(entry.owner.is_none());
        entry.owner = Some(owner);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        OWNERS
            .lock()
            .entries
            .retain(|entry| entry.addr != self.addr || entry.owner.is_some());
    }
}
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
            let selected = self.desired.snapshot();
            let result = self.generation(name.as_deref()).await;
            let role_changed = !self.desired.current(selected);
            let reclaimed = self.retire_generation().await;
            let generation = self.generation.load(Ordering::Acquire);
            let action = supervise(
                result.is_ok() || role_changed,
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
                // A deep/uncertain LPS owner retains DMA until its awaited
                // actual FLR fence. Re-sample that terminal retirement after
                // cleanup instead of permanently pinning a proven generation.
                reclaimed || owner.io.retire_published_dma()
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
        if let Some(shell) = &shell {
            *self.wowlan.lock() = shell.wowlan();
        }
        let kept = shell
            .as_ref()
            .map(|shell| super::interface::withdraw_keep_name(shell));
        if let Some(shell) = &shell {
            shell.wait_withdrawn().await;
        }
        *self.lifecycle.lock() = None;
        // SAFETY: the exclusive function reservation is still held, the previous
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
        let name = kept
            .and_then(narf_net::iface::rebind_name)
            .unwrap_or_else(|| narf_net::iface::reserve_name("wlan%d"));
        let shell = Arc::new(Device::new_selected(
            name,
            identity.mac(),
            lifecycle.clone(),
            Arc::new(station::NativeEnvironment),
            self.desired.clone(),
        ));
        {
            let (config, wakeup) = self.wowlan.lock().clone();
            shell.restore_wowlan(config, wakeup);
        }
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
        // RTL8852C: one owner for DM/RFK/channel at Linux's default unlinked
        // chandef (2.4GHz channel 1, 20MHz; core.c `rtw89_get_default_chandef`).
        Phase::RadioTablesLoaded
            if io
                .identity()
                .is_some_and(|identity| identity.chip() == super::mac::ChipId::Rtl8852C) =>
        {
            io.prepare_radio_c(super::operating_channel_c::Profile::INITIAL)
                .await?
        }
        // RTL8851B: its own `radio_51` owner at the same default chandef;
        // never B's basic/full calibration.
        Phase::RadioTablesLoaded
            if io
                .identity()
                .is_some_and(|identity| identity.chip() == super::mac::ChipId::Rtl8851B) =>
        {
            io.prepare_radio_51(super::operating_channel::Profile::INITIAL)
                .await?
        }
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
            shell.wait_withdrawn().await;
        }
        // An accepted FLR keeps its mandatory no-config quarantine; the
        // reset is dropped only after `run` returned.
        let _ = self.reset.lock().await.take();
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
    let shell = {
        let shell = owner.shell.lock();
        shell.clone()
    };
    // `rtw89_ops_suspend` with WoWLAN on a WoW-configured, associated,
    // settled station: the PCI core's `pci_save_state`, the driver op, then
    // `pci_prepare_to_sleep` to D3hot without card-off (as rtw88). Any
    // failure falls through to the cold path; PME/wake enable stays with
    // system PM (iwlwifi.md section 3.80).
    if stage == Stage::Station as u8 {
        if let Some(shell) = shell.as_ref() {
            if wow_suspend_owner(owner, shell).await {
                return Ok(());
            }
        }
    }
    owner.suspended.store(true, Ordering::Release);
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
    if owner.wow.lock().take().is_some() {
        // A rolled-back WoW suspend cannot await the D3hot exit delay or
        // `rtw89_wow_resume` here: return to D0 and close the shell so the
        // supervisor regenerates the station behind a fresh FLR.
        let _ = narf_bus::pci::set_power_state(
            &owner.authority,
            &owner.device,
            narf_bus::pci::PciPowerState::D0,
        );
        if let Some(shell) = owner.shell.lock().clone() {
            shell.admission().close();
        }
    }
    owner.suspended.store(false, Ordering::Release);
}
async fn pci_settle() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        narf_bus::pci::PM_D3HOT_DELAY_MS * 1_000_000,
    ))
    .await;
}
fn pci_state(owner: &Bootstrap, expected: narf_bus::pci::PciPowerState) -> bool {
    narf_bus::pci::power_state(&owner.authority, &owner.device) == Ok(Some(expected))
}
/// `pci_pm_resume_noirq`: D0, the exit delay, `pci_restore_state`
/// (header, then MSI) and a read-back of the restored BARs, command
/// register and MSI capability.
/// `pci_save_state`: the type-0 header and the MSI capability (address,
/// data, mask, Multi-Message Enable and Enable), which a function may lose
/// across D3hot (Linux `pci_restore_msi_state`).
#[derive(Clone, Copy)]
struct PciState {
    config: narf_bus::pci::SavedPciConfig,
    msi: narf_bus::msi::SavedMsi,
}
fn pci_save(owner: &Bootstrap) -> Option<PciState> {
    Some(PciState {
        config: narf_bus::pci::save_config(&owner.authority, &owner.device).ok()?,
        msi: narf_bus::msi::save_msi(&owner.authority, &owner.device).ok()?,
    })
}
async fn pci_wake(owner: &Bootstrap, saved: &PciState) -> bool {
    if narf_bus::pci::set_power_state(
        &owner.authority,
        &owner.device,
        narf_bus::pci::PciPowerState::D0,
    )
    .is_err()
    {
        return false;
    }
    pci_settle().await;
    let config = &saved.config;
    pci_state(owner, narf_bus::pci::PciPowerState::D0)
        && narf_bus::pci::restore_config(&owner.authority, &owner.device, config).is_ok()
        && narf_bus::pci::save_config(&owner.authority, &owner.device).is_ok_and(|now| {
            now.bars == config.bars
                && now.expansion_rom_bar == config.expansion_rom_bar
                && now.command == config.command
        })
        // `__pci_restore_msi_state`, proven by read-back of the capability.
        && narf_bus::msi::restore_msi(&owner.authority, &owner.device, &saved.msi).is_ok()
}
/// The WoW suspend branch; false means the cold path must run (a failed
/// WoW owner already closed its shell).
async fn wow_suspend_owner(owner: &Bootstrap, shell: &Arc<Device<startup::Startup>>) -> bool {
    // The WoW resume needs the bound MSI vector: refuse WoW unless it is
    // enabled and saved (polled delivery keeps the cold path).
    let Some(saved) = pci_save(owner).filter(|saved| saved.msi.enabled()) else {
        return false;
    };
    if shell.wow_suspend().await != Ok(true) {
        return false;
    }
    if narf_bus::pci::set_power_state(
        &owner.authority,
        &owner.device,
        narf_bus::pci::PciPowerState::D3Hot,
    )
    .is_ok()
    {
        pci_settle().await;
        if pci_state(owner, narf_bus::pci::PciPowerState::D3Hot) {
            *owner.wow.lock() = Some(saved);
            return true;
        }
    }
    // Back to D0 and restore the station before the cold path retires it.
    if pci_wake(owner, &saved).await {
        let _ = shell.wow_resume().await;
    }
    false
}
/// `rtw89_ops_resume` -> `rtw89_wow_resume` for a WoW-suspended
/// generation; a failure closed its shell, so the supervisor regenerates
/// it (cold path). Cold-suspended owners are released as before.
async fn resume_owner_async(owner: &Bootstrap) {
    let saved = owner.wow.lock().take();
    if let Some(saved) = saved {
        let shell = owner.shell.lock().clone();
        if let Some(shell) = shell {
            let woke = pci_wake(owner, &saved).await;
            if !woke || shell.wow_resume().await.is_err() {
                // Any failure closes the shell; the supervisor regenerates.
                shell.admission().close();
                narf_console::klog!("rtw8852b: WoW resume failed; regenerating\n");
            }
        }
    }
    owner.suspended.store(false, Ordering::Release);
}
/// Cancellation of preparation rolls back every request made so far. Once
/// preparation succeeds the barrier remains until resume_from_suspend.
struct SuspendAttempt {
    owners: Vec<Arc<Bootstrap>>,
    armed: bool,
}
impl Drop for SuspendAttempt {
    fn drop(&mut self) {
        if self.armed {
            for owner in &self.owners {
                resume_owner(owner);
            }
            OWNERS.lock().suspending = false;
        }
    }
}
/// Async system-PM hook (the interrupt-gated `DevicePmOps` fan-out cannot
/// await firmware/H2C or the DMA-stop retirement).
pub(super) struct SystemPm;
async fn suspend_all(timeout_ms: u64) -> Result<(), narf_power::device_pm::DevicePmError> {
    let owners = {
        let mut registry = OWNERS.lock();
        // An unpublished claim may be touching config/reset. Do not enter
        // system suspend until every claim has become retained.
        if registry.suspending || registry.entries.iter().any(|entry| entry.owner.is_none()) {
            return Err(narf_power::device_pm::DevicePmError::Busy);
        }
        registry.suspending = true;
        registry.snapshot()
    };
    let mut attempt = SuspendAttempt {
        owners,
        armed: true,
    };
    for owner in &attempt.owners {
        suspend_owner(owner, timeout_ms).await?;
    }
    attempt.armed = false;
    Ok(())
}
async fn resume_all() {
    let owners = OWNERS.lock().snapshot();
    for owner in owners {
        resume_owner_async(&owner).await;
    }
    OWNERS.lock().suspending = false;
}
impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(suspend_all(SUSPEND_MS))
    }
    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            resume_all().await;
            Ok(())
        })
    }
}
/// Release only this function's reservation after proven reclamation. A
/// pinned owner keeps its address quarantined for the boot.
async fn finish_remove(owner: Arc<Bootstrap>) -> bool {
    let reclaimed = owner.retire().await;
    if reclaimed {
        OWNERS.lock().forget(&owner);
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
/// `narf_bus` PCI remove hook for the retained B/C/8851B owner.
pub(super) fn remove(device: BusDevice, _authority: Cap<BusDeviceCap, Write>) {
    let owner = OWNERS.lock().owner(device.addr);
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
    let Some(reservation) = Reservation::claim(device.addr)? else {
        // An active or quarantined same-function reprobe is observational.
        return Ok(());
    };
    // SAFETY: this BDF's reservation precedes all hardware access and is
    // retained across the reset/firmware/radio/station lifetime.
    let reset = unsafe { pci_reset::Reset::claim(device, authority) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // A parking operation before reset only limits inherited DMA. It grants
    // no fence; the retained reset below must still earn an actual FLR receipt.
    if crate::rtw88::pci_park::invoke(&authority, || {
        crate::rtw88::pci_park::park(&device, &authority)
    })
    .ok()
        != Some(Ok(()))
    {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let owner = Arc::new(Bootstrap {
        device,
        authority,
        reset: Mutex::new(Some(reset)),
        lifecycle: IrqSafeSpinLock::new(None),
        shell: IrqSafeSpinLock::new(None),
        desired: crate::rtw89::monitor::Desired::new(),
        stage: AtomicU8::new(Stage::Reset as u8),
        error: IrqSafeSpinLock::new(None),
        request: IrqSafeSpinLock::new(None),
        running: AtomicBool::new(false),
        removed: AtomicBool::new(false),
        pinned: AtomicBool::new(false),
        generation: AtomicU32::new(0),
        suspended: AtomicBool::new(false),
        wow: IrqSafeSpinLock::new(None),
        wowlan: IrqSafeSpinLock::new((None, None)),
    });
    publish_owner(owner, reservation);
    Ok(())
}
fn publish_owner(owner: Arc<Bootstrap>, reservation: Reservation) {
    let device = owner.device;
    reservation.publish(owner.clone());
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
    if device.id.vendor != 0x10ec || !super::bootstrap_did(device.id.device) {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let reservation = Reservation::claim(device.addr)?.ok_or(narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller's actual temporal platform-reset and exclusive function
    // contract above replaces only the observed FLR receipt, not any later
    // firmware/factory/radio/policy/packet prerequisite.
    let startup = match unsafe { startup::Startup::claim(device, authority) } {
        Ok(startup) => startup,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let lifecycle = Arc::new(Lifecycle::new(startup));
    let owner = Arc::new(Bootstrap {
        device,
        authority,
        reset: Mutex::new(None),
        lifecycle: IrqSafeSpinLock::new(Some(lifecycle)),
        shell: IrqSafeSpinLock::new(None),
        desired: crate::rtw89::monitor::Desired::new(),
        stage: AtomicU8::new(Stage::Discovery as u8),
        error: IrqSafeSpinLock::new(None),
        request: IrqSafeSpinLock::new(None),
        running: AtomicBool::new(false),
        removed: AtomicBool::new(false),
        pinned: AtomicBool::new(false),
        generation: AtomicU32::new(0),
        suspended: AtomicBool::new(false),
        wow: IrqSafeSpinLock::new(None),
        wowlan: IrqSafeSpinLock::new((None, None)),
    });
    publish_owner(owner, reservation);
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::future::Future;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct TestReservation(BusAddr);
    impl Drop for TestReservation {
        fn drop(&mut self) {
            OWNERS.lock().entries.retain(|entry| entry.addr != self.0);
        }
    }
    fn test_reserve(addr: BusAddr) -> Option<TestReservation> {
        OWNERS
            .lock()
            .reserve(addr)
            .ok()
            .filter(|reserved| *reserved)?;
        Some(TestReservation(addr))
    }
    fn install(owner: Arc<Bootstrap>) {
        let mut registry = OWNERS.lock();
        let entry = registry
            .entries
            .iter_mut()
            .find(|entry| entry.addr == owner.device.addr)
            .unwrap();
        assert!(entry.owner.is_none());
        entry.owner = Some(owner);
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
        let device = device();
        let Some(_reservation) = test_reserve(device.addr) else {
            return TestResult::Skip("RTL8852B fixture function unavailable");
        };
        let authority = Cap::bootstrap();
        // Pure ownership fixture: deliberately no Reset or native producer.
        // Any attempted config access to its zero ECAM would be invalid.
        let owner = Arc::new(Bootstrap {
            device,
            authority,
            reset: Mutex::new(None),
            lifecycle: IrqSafeSpinLock::new(None),
            shell: IrqSafeSpinLock::new(None),
            desired: crate::rtw89::monitor::Desired::new(),
            stage: AtomicU8::new(Stage::Reset as u8),
            error: IrqSafeSpinLock::new(None),
            request: IrqSafeSpinLock::new(None),
            running: AtomicBool::new(true),
            removed: AtomicBool::new(false),
            pinned: AtomicBool::new(false),
            generation: AtomicU32::new(0),
            suspended: AtomicBool::new(false),
            wow: IrqSafeSpinLock::new(None),
            wowlan: IrqSafeSpinLock::new((None, None)),
        });
        install(owner.clone());
        if probe(device, authority).is_err() {
            return TestResult::Fail("retained same-function probe did not return without access");
        }
        // SAFETY: the existing function owner must reject before any hardware or
        // platform-reset claim is used; fixture has no physical PCI function.
        if unsafe { attach_cold(device, authority) }.is_ok() {
            return TestResult::Fail("cold-platform entry replaced a retained reset owner");
        }
        if OWNERS
            .lock()
            .owner(device.addr)
            .is_none_or(|current| !Arc::ptr_eq(&current, &owner))
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
            desired: crate::rtw89::monitor::Desired::new(),
            stage: AtomicU8::new(Stage::Reset as u8),
            error: IrqSafeSpinLock::new(None),
            request: IrqSafeSpinLock::new(None),
            running: AtomicBool::new(true),
            removed: AtomicBool::new(false),
            pinned: AtomicBool::new(false),
            generation: AtomicU32::new(0),
            suspended: AtomicBool::new(false),
            wow: IrqSafeSpinLock::new(None),
            wowlan: IrqSafeSpinLock::new((None, None)),
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
        let device = device();
        let Some(_reservation) = test_reserve(device.addr) else {
            return TestResult::Skip("RTL8852B fixture function unavailable");
        };
        // Owner that never completed reset: nothing was published.
        let owner = fixture(device, None);
        install(owner.clone());
        let mut other = device;
        other.addr = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(u16::MAX, u8::MAX, 30, 7));
        remove(other, Cap::bootstrap());
        if owner.removed.load(Ordering::Acquire) {
            return TestResult::Fail("remove hook acted on a different function");
        }
        if ready(finish_remove(owner.clone())) != Some(true)
            || OWNERS
                .lock()
                .entries
                .iter()
                .any(|entry| entry.addr == device.addr)
            || !owner.removed.load(Ordering::Acquire)
            || owner.stage.load(Ordering::Acquire) != Stage::Terminal as u8
        {
            return TestResult::Fail("unpublished owner removal kept the function reservation");
        }
        // Owner whose retained DMA owner cannot be proven reclaimed (already
        // taken): the reservation and address stay quarantined.
        assert_eq!(OWNERS.lock().reserve(device.addr).ok(), Some(true));
        let lifecycle = Arc::new(Lifecycle {
            retained: Mutex::new(None),
        });
        let pinned = fixture(device, Some(lifecycle));
        pinned.pinned.store(true, Ordering::Release);
        install(pinned.clone());
        if ready(finish_remove(pinned.clone())) != Some(false)
            || OWNERS
                .lock()
                .owner(device.addr)
                .is_none_or(|current| !Arc::ptr_eq(&current, &pinned))
        {
            return TestResult::Fail("unproven removal released the function reservation");
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
    fn other_device(slot: u8) -> BusDevice {
        let mut other = device();
        other.addr = BusAddr::Pcie(narf_bus::PcieAddr::new(u16::MAX, u8::MAX, slot, 7));
        other
    }
    fn smoke_rtw8852b_function_reservations_bound_duplicate_and_stale_removal() -> TestResult {
        let mut functions = Functions::new();
        let first = fixture(other_device(20), None);
        let second = fixture(other_device(21), None);
        if functions.reserve(first.device.addr).ok() != Some(true)
            || functions.reserve(first.device.addr).is_ok()
        {
            return TestResult::Fail("pending BDF reservation admitted another reset producer");
        }
        functions.entries[0].owner = Some(first.clone());
        if functions.reserve(first.device.addr).ok() != Some(false)
            || functions.reserve(second.device.addr).ok() != Some(true)
        {
            return TestResult::Fail("live duplicate or independent function admission differed");
        }
        functions.entries[1].owner = Some(second.clone());
        for slot in 22..24 {
            functions.reserve(other_device(slot).addr).unwrap();
        }
        if functions.reserve(other_device(24).addr).is_ok() {
            return TestResult::Fail("function bound exceeded native endpoint/IRQ capacity");
        }
        functions.forget(&first);
        functions.reserve(first.device.addr).unwrap();
        let replacement = fixture(first.device, None);
        functions.entries.last_mut().unwrap().owner = Some(replacement.clone());
        functions.forget(&first);
        if functions
            .owner(first.device.addr)
            .is_none_or(|owner| !Arc::ptr_eq(&owner, &replacement))
            || functions
                .owner(second.device.addr)
                .is_none_or(|owner| !Arc::ptr_eq(&owner, &second))
        {
            return TestResult::Fail("late retirement released a different function/generation");
        }
        TestResult::Pass
    }
    fn smoke_rtw8852b_system_pm_fans_out_and_rolls_back_failed_or_cancelled_prepare() -> TestResult
    {
        use narf_power::device_pm::DevicePmError;
        let first = fixture(other_device(28), None);
        let second = fixture(other_device(29), None);
        {
            let mut registry = OWNERS.lock();
            if !registry.entries.is_empty() || registry.suspending {
                return TestResult::Skip("physical function owners already present");
            }
            registry.reserve(first.device.addr).unwrap();
            registry.reserve(second.device.addr).unwrap();
        }
        let _first = TestReservation(first.device.addr);
        let _second = TestReservation(second.device.addr);
        install(first.clone());
        install(second.clone());
        first.set_stage(Stage::Suspended);
        second.set_stage(Stage::Station);
        if ready(suspend_all(0)) != Some(Err(DevicePmError::Busy))
            || first.suspended.load(Ordering::Acquire)
            || second.suspended.load(Ordering::Acquire)
            || OWNERS.lock().suspending
        {
            let _ = ready(resume_all());
            return TestResult::Fail("later suspend failure left an earlier function parked");
        }
        // Cancellation after the first owner parks and the second awaits its
        // supervisor must withdraw both requests and the new-probe barrier.
        let mut future = alloc::boxed::Box::pin(suspend_all(SUSPEND_MS));
        let pending = future
            .as_mut()
            .poll(&mut core::task::Context::from_waker(
                core::task::Waker::noop(),
            ))
            .is_pending();
        drop(future);
        if !pending
            || first.suspended.load(Ordering::Acquire)
            || second.suspended.load(Ordering::Acquire)
            || OWNERS.lock().suspending
        {
            let _ = ready(resume_all());
            return TestResult::Fail("cancelled multi-function suspend retained requests");
        }
        second.set_stage(Stage::Suspended);
        if ready(suspend_all(0)) != Some(Ok(()))
            || !first.suspended.load(Ordering::Acquire)
            || !second.suspended.load(Ordering::Acquire)
            || Reservation::claim(other_device(27).addr).is_ok()
        {
            let _ = ready(resume_all());
            return TestResult::Fail(
                "successful multi-function suspend missed an owner/probe fence",
            );
        }
        let _ = ready(resume_all());
        if first.suspended.load(Ordering::Acquire)
            || second.suspended.load(Ordering::Acquire)
            || Reservation::claim(other_device(27).addr).is_err()
        {
            return TestResult::Fail("resume did not release every function and probe fence");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/multiple",
        smoke_rtw8852b_function_reservations_bound_duplicate_and_stale_removal
    );
    kernel_test_in!(
        "drivers/wireless/rtw89/multiple",
        smoke_rtw8852b_system_pm_fans_out_and_rolls_back_failed_or_cancelled_prepare
    );
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
