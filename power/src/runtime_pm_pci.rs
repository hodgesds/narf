//! PCI bus layer of runtime PM: Linux `drivers/pci/pci-driver.c`
//! `pci_pm_runtime_{idle,suspend,resume}` with `pci_save_state` /
//! `pci_restore_state` and `pci_finish_runtime_suspend` /
//! `pci_pm_default_resume_early`.
//!
//! [`PciRuntimePm`] wraps a driver's [`RuntimePmOps`] the way the PCI bus
//! type wraps `dev_pm_ops`:
//!
//! - suspend: run the driver's `runtime_suspend`; on success, unless the
//!   driver saved the config state itself (`state_saved`) or left the
//!   function in a low-power state, save the config state and move the
//!   function to its target state: D3cold when the platform can remove
//!   power (ACPI `_PR3`), else D3hot, with the 10 ms PMCSR settle.
//! - resume: power the function back up (platform power-on from D3cold,
//!   then D0 with the settle), restore the saved config state, then run the
//!   driver's `runtime_resume`.
//! - idle: the driver's `runtime_idle`, or success.
//!
//! An unbound function (no driver) only saves/restores its state and stays
//! in D0, as Linux does. NARF executes no AML (`power/` §8.3), so the
//! default platform cannot provide D3cold; a platform that can supplies a
//! [`PciPlatformPm`].
//!
//! [`register_pci_device`] creates the runtime-PM device of a PCI function
//! with its parent chain: each upstream bridge gets one shared node, which
//! (like an unbound Linux bridge after `pci_pm_init`) is active with runtime
//! PM forbidden, so a child always resumes under a powered link.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::pci::{PciError, PciPowerState, SavedPciConfig};
use narf_bus::{BusDevice, BusDeviceCap, BusKind, PcieAddr};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::runtime_pm::{RpmEnv, RpmError, RpmFuture, RuntimePmDevice, RuntimePmOps};

/// Config-space access the PCI layer needs. [`EcamPciPm`] is the hardware
/// implementation; tests provide models.
pub trait PciPmIo: Send + Sync {
    /// PMCSR PowerState; `Ok(None)` when the function reads all-ones.
    fn power_state(&self) -> Result<Option<PciPowerState>, PciError>;
    fn set_power_state(&self, state: PciPowerState) -> Result<(), PciError>;
    /// `pci_save_state`.
    fn save_state(&self) -> Result<(), PciError>;
    /// `pci_restore_state`; a no-op when nothing was saved.
    fn restore_state(&self) -> Result<(), PciError>;
    /// The settle after a PowerState write. Async: never a spin.
    fn delay_ms(&self, ms: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
        })
    }
}

/// ECAM-backed [`PciPmIo`]: the type-0 header snapshot of
/// `narf_bus::pci::save_config` (BARs, command, interrupt line, …).
pub struct EcamPciPm {
    cap: Cap<BusDeviceCap, Write>,
    device: BusDevice,
    saved: IrqSafeSpinLock<Option<SavedPciConfig>>,
}
impl fmt::Debug for EcamPciPm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcamPciPm")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}
impl EcamPciPm {
    pub fn new(cap: Cap<BusDeviceCap, Write>, device: BusDevice) -> Self {
        Self {
            cap,
            device,
            saved: IrqSafeSpinLock::new(None),
        }
    }
}
impl PciPmIo for EcamPciPm {
    fn power_state(&self) -> Result<Option<PciPowerState>, PciError> {
        match narf_bus::pci::power_state(&self.cap, &self.device) {
            // No PM capability: always D0 (pci_set_power_state no-op).
            Err(PciError::CapNotPresent) => Ok(Some(PciPowerState::D0)),
            other => other,
        }
    }
    fn set_power_state(&self, state: PciPowerState) -> Result<(), PciError> {
        narf_bus::pci::set_power_state(&self.cap, &self.device, state)
    }
    fn save_state(&self) -> Result<(), PciError> {
        let saved = narf_bus::pci::save_config(&self.cap, &self.device)?;
        *self.saved.lock() = Some(saved);
        Ok(())
    }
    fn restore_state(&self) -> Result<(), PciError> {
        let saved = *self.saved.lock();
        match saved {
            Some(saved) => narf_bus::pci::restore_config(&self.cap, &self.device, &saved),
            None => Ok(()),
        }
    }
}

/// Platform power control below D3hot (Linux `platform_pci_set_power_state`
/// through ACPI `_PR3`/`_PS3`).
pub trait PciPlatformPm: Send + Sync {
    /// `pci_target_state` may pick D3cold.
    fn d3cold_supported(&self) -> bool;
    /// Remove power after the function reached D3hot.
    fn power_off(&self) -> Pin<Box<dyn Future<Output = Result<(), PciError>> + Send + '_>>;
    /// Restore power before the function is moved to D0.
    fn power_on(&self) -> Pin<Box<dyn Future<Output = Result<(), PciError>> + Send + '_>>;
}

/// The PCI layer's view of a function's power (`pci_dev->current_state`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciTarget {
    D0,
    D3Hot,
    D3Cold,
}

/// Linux `pci_bus_type.pm` runtime callbacks around one driver.
pub struct PciRuntimePm {
    io: Arc<dyn PciPmIo>,
    driver: Option<Arc<dyn RuntimePmOps>>,
    platform: Option<Arc<dyn PciPlatformPm>>,
    /// `pci_dev->state_saved`, cleared before the driver's suspend.
    state_saved: AtomicBool,
    current: IrqSafeSpinLock<PciTarget>,
}
impl fmt::Debug for PciRuntimePm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PciRuntimePm")
            .field("bound", &self.driver.is_some())
            .field("current", &*self.current.lock())
            .finish_non_exhaustive()
    }
}
impl PciRuntimePm {
    pub fn new(
        io: Arc<dyn PciPmIo>,
        driver: Option<Arc<dyn RuntimePmOps>>,
        platform: Option<Arc<dyn PciPlatformPm>>,
    ) -> Self {
        Self {
            io,
            driver,
            platform,
            state_saved: AtomicBool::new(false),
            current: IrqSafeSpinLock::new(PciTarget::D0),
        }
    }
    /// `pci_save_state` from a driver's runtime_suspend: the PCI layer then
    /// leaves the power state to the driver.
    pub fn save_state(&self) -> Result<(), PciError> {
        self.io.save_state()?;
        self.state_saved.store(true, Ordering::Release);
        Ok(())
    }
    pub fn current(&self) -> PciTarget {
        *self.current.lock()
    }
    fn pci_error(error: PciError) -> RpmError {
        match error {
            PciError::AuthorityRevoked => RpmError::NotPermitted,
            _ => RpmError::Failed,
        }
    }
    /// `pci_finish_runtime_suspend` → `pci_set_power_state(target)`.
    async fn finish_suspend(&self) -> Result<(), RpmError> {
        let d3cold = self.platform.as_ref().is_some_and(|p| p.d3cold_supported());
        if self.io.power_state().map_err(Self::pci_error)? != Some(PciPowerState::D3Hot) {
            match self.io.set_power_state(PciPowerState::D3Hot) {
                // No PM capability: pci_target_state is D0, nothing to do.
                Err(PciError::CapNotPresent) => return Ok(()),
                other => other.map_err(Self::pci_error)?,
            }
            self.io.delay_ms(narf_bus::pci::PM_D3HOT_DELAY_MS).await;
        }
        *self.current.lock() = PciTarget::D3Hot;
        if d3cold {
            let platform = self.platform.as_ref().unwrap();
            platform.power_off().await.map_err(Self::pci_error)?;
            *self.current.lock() = PciTarget::D3Cold;
        }
        Ok(())
    }
    /// `pci_pm_default_resume_early`: power up and verify, restore state.
    async fn resume_early(&self) -> Result<(), RpmError> {
        let was = *self.current.lock();
        if was == PciTarget::D3Cold {
            if let Some(platform) = &self.platform {
                platform.power_on().await.map_err(Self::pci_error)?;
            }
        }
        match self.io.power_state().map_err(Self::pci_error)? {
            // pci_device_is_present: an all-ones read is a lost device.
            None => return Err(RpmError::Failed),
            Some(PciPowerState::D0) => {}
            Some(_) => {
                self.io
                    .set_power_state(PciPowerState::D0)
                    .map_err(Self::pci_error)?;
                self.io.delay_ms(narf_bus::pci::PM_D3HOT_DELAY_MS).await;
            }
        }
        *self.current.lock() = PciTarget::D0;
        self.io.restore_state().map_err(Self::pci_error)
    }
}
impl RuntimePmOps for PciRuntimePm {
    fn runtime_idle(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            match &self.driver {
                Some(driver) => driver.runtime_idle().await,
                None => Ok(()),
            }
        })
    }
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            let Some(driver) = &self.driver else {
                // Unbound: stay in D0, but save state in case the bridge
                // above removes power.
                return self.io.save_state().map_err(Self::pci_error);
            };
            self.state_saved.store(false, Ordering::Release);
            driver.runtime_suspend().await?;
            if self.state_saved.load(Ordering::Acquire) {
                return Ok(());
            }
            // The driver left the function in a low-power state without
            // saving it: leave it alone (Linux WARNs and returns 0).
            if self.io.power_state().map_err(Self::pci_error)? != Some(PciPowerState::D0) {
                return Ok(());
            }
            self.io.save_state().map_err(Self::pci_error)?;
            self.finish_suspend().await
        })
    }
    fn runtime_resume(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            self.resume_early().await?;
            match &self.driver {
                Some(driver) => driver.runtime_resume().await,
                None => Ok(()),
            }
        })
    }
}

/// One function's registration: its runtime-PM device and PCI layer.
#[derive(Clone, Debug)]
pub struct PciRuntimeNode {
    pub device: Arc<RuntimePmDevice>,
    pub pci: Arc<PciRuntimePm>,
}

static BRIDGES: IrqSafeSpinLock<Vec<(PcieAddr, Arc<RuntimePmDevice>)>> =
    IrqSafeSpinLock::new(Vec::new());

/// The shared runtime-PM node of `bridge` and its ancestors: active and
/// enabled, with runtime PM forbidden (an unbound Linux bridge).
pub fn bridge_node(bridge: &BusDevice, env: &Arc<dyn RpmEnv>) -> Option<Arc<RuntimePmDevice>> {
    let BusKind::Pcie { addr, .. } = bridge.kind else {
        return None;
    };
    if let Some((_, node)) = BRIDGES.lock().iter().find(|(a, _)| *a == addr) {
        return Some(node.clone());
    }
    let parent = narf_bus::pci::upstream_bridge(bridge).and_then(|up| bridge_node(&up, env));
    let node = RuntimePmDevice::new("pci-bridge", None, parent, env.clone());
    if node.set_active().is_err() {
        return None;
    }
    node.enable();
    // pci_pm_init: pm_runtime_forbid; nothing allows an unbound bridge.
    node.get_noresume();
    let _ = node.set_forbidden_active();
    let mut bridges = BRIDGES.lock();
    if let Some((_, existing)) = bridges.iter().find(|(a, _)| *a == addr) {
        return Some(existing.clone());
    }
    bridges.push((addr, node.clone()));
    Some(node)
}

/// Create the runtime-PM device of a bound PCI function, parented on its
/// upstream bridge chain. The device starts as `pci_pm_init` + probe leave
/// it: active, enabled, runtime PM forbidden and the probe's usage
/// reference held. A driver then configures autosuspend and calls
/// `allow()` + `put_autosuspend()`, as amdgpu's probe does.
pub fn register_pci_device(
    name: &str,
    cap: Cap<BusDeviceCap, Write>,
    device: BusDevice,
    driver: Arc<dyn RuntimePmOps>,
    platform: Option<Arc<dyn PciPlatformPm>>,
    env: Arc<dyn RpmEnv>,
) -> Result<PciRuntimeNode, RpmError> {
    let parent = narf_bus::pci::upstream_bridge(&device).and_then(|b| bridge_node(&b, &env));
    let io: Arc<dyn PciPmIo> = Arc::new(EcamPciPm::new(cap, device));
    register_with_io(name, io, driver, platform, parent, env)
}

/// [`register_pci_device`] over an explicit [`PciPmIo`] and parent (models).
pub fn register_with_io(
    name: &str,
    io: Arc<dyn PciPmIo>,
    driver: Arc<dyn RuntimePmOps>,
    platform: Option<Arc<dyn PciPlatformPm>>,
    parent: Option<Arc<RuntimePmDevice>>,
    env: Arc<dyn RpmEnv>,
) -> Result<PciRuntimeNode, RpmError> {
    let pci = Arc::new(PciRuntimePm::new(io, Some(driver), platform));
    let ops: Arc<dyn RuntimePmOps> = pci.clone();
    let device = RuntimePmDevice::new(name, Some(ops), parent, env);
    device.set_active()?;
    device.enable();
    // local_pci_probe's pm_runtime_get_sync, and pci_pm_init's forbid.
    device.get_noresume();
    device.set_forbidden_active()?;
    Ok(PciRuntimeNode { device, pci })
}

#[doc(hidden)]
pub fn __reset_bridges_for_test() {
    BRIDGES.lock().clear();
}
