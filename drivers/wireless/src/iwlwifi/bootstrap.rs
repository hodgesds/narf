// SPDX-License-Identifier: GPL-2.0-or-later
//! Probe retains the exact parked PCI binding; executor-time asset resolution
//! runs after Stage::Late. Only pre-attempt denial is retryable.
use super::{device::Device, rx_rfh::CompletionFormat, ChipConfig};
use alloc::{string::String, sync::Arc};
use core::sync::atomic::{AtomicU8, Ordering};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Read, Write};
use narf_firmware::{FirmwareError, FirmwareRegistry};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvisionState {
    Parking = 0,
    Parked = 1,
    Starting = 2,
    Ready = 3,
    Failed = 4,
}
struct State {
    interface: Option<Arc<Device>>,
}
pub(super) struct Owner {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    chip: ChipConfig,
    phase: AtomicU8,
    state: Mutex<State>,
}
impl Owner {
    fn new(device: BusDevice, cap: Cap<BusDeviceCap, Write>, chip: ChipConfig) -> Self {
        Self {
            device,
            cap,
            chip,
            phase: AtomicU8::new(ProvisionState::Parking as u8),
            state: Mutex::new(State { interface: None }),
        }
    }
    pub(super) fn parked(&self) {
        let _ = self.phase.compare_exchange(
            ProvisionState::Parking as u8,
            ProvisionState::Parked as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub(super) fn fail(&self) {
        self.phase
            .store(ProvisionState::Failed as u8, Ordering::Release);
    }
    fn phase(&self) -> ProvisionState {
        match self.phase.load(Ordering::Acquire) {
            0 => ProvisionState::Parking,
            1 => ProvisionState::Parked,
            2 => ProvisionState::Starting,
            3 => ProvisionState::Ready,
            _ => ProvisionState::Failed,
        }
    }
    async fn provision(&self) -> Result<(), &'static str> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or("firmware authority unavailable")?;
        self.provision_using(&authority, &super::firmware_filename_ladder(&self.chip))
            .await
    }
    async fn provision_using(
        &self,
        authority: &Cap<FirmwareRegistry, Read>,
        candidates: &[String],
    ) -> Result<(), &'static str> {
        let mut state = self.state.lock().await;
        if self.phase() != ProvisionState::Parked {
            return Err("Intel startup already attempted");
        }
        let format =
            CompletionFormat::for_mac(self.chip.mac).ok_or("Gen2 native station remains gated")?;
        let input = resolve(authority, candidates)?;
        let mut parsed =
            super::parse_ucode(&input.firmware.bytes).map_err(|_| "invalid Intel firmware")?;
        if parsed.api.pnvm.is_none() {
            parsed.api.pnvm = input.pnvm.as_ref().map(|asset| asset.bytes.as_slice());
        }
        // Policy absence still permits the existing firmware/receive setup;
        // station TX/active scan separately retry authenticated policy and fail shut.
        let _ = narf_wireless::reg::db::ensure_domain();
        if !input.firmware.current() || input.pnvm.as_ref().is_some_and(|asset| !asset.current()) {
            return Err("Intel selected asset authority revoked before attempt");
        }
        self.phase
            .store(ProvisionState::Starting as u8, Ordering::Release);
        let _attempt = Attempt(self);
        let region = super::mmio::map(&self.device, &self.cap)?;
        let hardware =
            super::runtime::Hardware::new(self.device, self.cap, region, &parsed, format)?;
        let interface = Device::initialize(hardware, &parsed, &input.firmware.bytes).await?;
        // Retain this SAME live Device before registration/pump publication.
        state.interface = Some(interface.clone());
        interface.start_pumps()?;
        narf_wireless::registry::register(interface);
        self.phase
            .store(ProvisionState::Ready as u8, Ordering::Release);
        Ok(())
    }
}
struct Attempt<'a>(&'a Owner);
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.0.phase() == ProvisionState::Starting {
            self.0.fail();
        }
    }
}
struct Inputs {
    firmware: crate::firmware_asset::Asset,
    pnvm: Option<crate::firmware_asset::Asset>,
}
fn resolve(
    authority: &Cap<FirmwareRegistry, Read>,
    candidates: &[String],
) -> Result<Inputs, &'static str> {
    for name in candidates {
        let firmware = match crate::firmware_asset::load(authority, name, 16 * 1024 * 1024, false) {
            Ok(asset) => asset,
            Err(FirmwareError::NotFound) => continue,
            Err(_) => return Err("Intel firmware source authority/extent failed"),
        };
        let parsed = super::parse_ucode(&firmware.bytes).map_err(|_| "invalid Intel firmware")?;
        let pnvm = if parsed.api.pnvm.is_none() {
            if let Some((prefix, _)) = name.rsplit_once('-') {
                let name = alloc::format!("{prefix}.pnvm");
                match crate::firmware_asset::load(authority, &name, 16 * 1024 * 1024, false) {
                    Ok(asset) => Some(asset),
                    Err(FirmwareError::NotFound) => None,
                    Err(_) => return Err("Intel PNVM source authority/extent failed"),
                }
            } else {
                None
            }
        } else {
            None
        };
        return Ok(Inputs { firmware, pnvm });
    }
    Err("Intel firmware not staged; parked owner retained")
}
static NATIVE: IrqSafeSpinLock<Option<Arc<Owner>>> = IrqSafeSpinLock::new(None);
pub(super) fn retain(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    chip: ChipConfig,
) -> Arc<Owner> {
    let owner = Arc::new(Owner::new(device, cap, chip));
    *NATIVE.lock() = Some(owner.clone());
    owner
}
pub(super) fn schedule(owner: Arc<Owner>) {
    narf_scheduler::spawn(async move {
        if let Err(reason) = owner.provision().await {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "iwlwifi: retained startup: {}",
                reason
            );
        }
    });
}
/// Retry newly staged inputs only before any mapped/runtime startup attempt.
pub async fn provision() -> Result<(), &'static str> {
    let owner = NATIVE
        .lock()
        .clone()
        .ok_or("no retained Intel native startup")?;
    owner.provision().await
}
pub fn provision_state() -> Option<ProvisionState> {
    Some(NATIVE.lock().as_ref()?.phase())
}

#[cfg(feature = "kernel-test")]
#[path = "bootstrap_tests.rs"]
mod tests;
