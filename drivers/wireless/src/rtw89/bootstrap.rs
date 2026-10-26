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
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
    async fn drive(&self) -> Result<(), Error> {
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Cancelled)?;
        let mut attempt = Attempt {
            owner: self,
            complete: false,
        };
        let retained_lifecycle = {
            let owner = self.lifecycle.lock();
            owner.clone()
        };
        let lifecycle = match retained_lifecycle {
            Some(lifecycle) => lifecycle,
            None => {
                self.set_stage(Stage::Reset);
                let fence = self
                    .reset
                    .lock()
                    .await
                    .as_mut()
                    .ok_or(Error::Cancelled)?
                    .run()
                    .await
                    .map_err(Error::Reset)?;
                let startup = startup::Startup::claim_reset(self.device, self.authority, fence)
                    .map_err(Error::Startup)?;
                // Retain the exact startup before its first cold/firmware attempt.
                let lifecycle = Arc::new(Lifecycle::new(startup));
                *self.lifecycle.lock() = Some(lifecycle.clone());
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
        let name = narf_net::iface::reserve_name("wlan%d");
        let shell = Arc::new(Device::new(
            name,
            identity.mac(),
            lifecycle.clone(),
            Arc::new(station::NativeEnvironment),
        ));
        *self.shell.lock() = Some(shell.clone());
        // Source factory discovery ended with BME off. The exact same shell
        // reaches all registries before the first CH12/firmware BME attempt.
        super::interface::publish(shell.clone()).map_err(Error::Station)?;
        loop {
            if shell.closed() {
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
        self.set_stage(Stage::Terminal);
        attempt.complete = true;
        Ok(())
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
    kernel_test_in!(
        "drivers/wireless/rtw89/bootstrap",
        smoke_rtw8852b_retained_probe_never_reparks_or_replaces_reset_owner
    );
}
