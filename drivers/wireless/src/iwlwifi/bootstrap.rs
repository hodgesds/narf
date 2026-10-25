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
    discovery: Option<narf_bus::MmioRegion>,
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
            state: Mutex::new(State {
                interface: None,
                discovery: None,
            }),
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
        if narf_net::trusted_net_authority().is_none() {
            return Err("network registration authority unavailable");
        }
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or("firmware authority unavailable")?;
        self.provision_with_authority(&authority).await
    }
    async fn provision_with_authority(
        &self,
        authority: &Cap<FirmwareRegistry, Read>,
    ) -> Result<(), &'static str> {
        let mut state = self.state.lock().await;
        self.admit()?;
        let (candidates, identity) = self.candidates(&mut state)?;
        self.start(&mut state, authority, &candidates, identity)
            .await
    }
    fn admit(&self) -> Result<(), &'static str> {
        if self.phase() != ProvisionState::Parked {
            return Err("Intel startup already attempted");
        }
        Ok(())
    }
    fn candidates(
        &self,
        state: &mut State,
    ) -> Result<
        (
            alloc::vec::Vec<String>,
            Option<super::firmware_identity::Sc>,
        ),
        &'static str,
    > {
        if self.chip.mac != super::MacFamily::ScA0 {
            return Ok((super::firmware_filename_ladder(&self.chip), None));
        }
        let region = match state.discovery {
            Some(region) => region,
            None => {
                // Identity discovery enables only checked memory decode; BME
                // stays off. Retain this same mapping across missing assets.
                let region = super::mmio::map(&self.device, &self.cap)?;
                state.discovery = Some(region);
                region
            }
        };
        let mut io = super::IwlMmioImpl::new(region, self.cap);
        let identity = super::firmware_identity::Sc::read(&mut io)?;
        Ok((identity.ladder(&self.chip)?, Some(identity)))
    }
    #[cfg(feature = "kernel-test")]
    async fn provision_using(
        &self,
        authority: &Cap<FirmwareRegistry, Read>,
        candidates: &[String],
    ) -> Result<(), &'static str> {
        let mut state = self.state.lock().await;
        self.admit()?;
        self.start(&mut state, authority, candidates, None).await
    }
    async fn start(
        &self,
        state: &mut State,
        authority: &Cap<FirmwareRegistry, Read>,
        candidates: &[String],
        identity: Option<super::firmware_identity::Sc>,
    ) -> Result<(), &'static str> {
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
        if let Some(identity) = identity {
            let mut io = super::IwlMmioImpl::new(
                state.discovery.ok_or("Sc discovery mapping unavailable")?,
                self.cap,
            );
            identity.check(&mut io)?;
        }
        self.phase
            .store(ProvisionState::Starting as u8, Ordering::Release);
        let _attempt = Attempt(self);
        let region = match state.discovery {
            Some(region) => region,
            None => super::mmio::map(&self.device, &self.cap)?,
        };
        let hardware = super::runtime::Hardware::new(
            self.device,
            self.cap,
            region,
            &parsed,
            format,
            identity,
        )?;
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
pub(super) async fn drive_scheduled<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut phase: impl FnMut() -> ProvisionState,
    mut step: Step,
    mut wait: Wait,
) -> Result<(), &'static str>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<(), &'static str>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = "Intel firmware not staged; parked owner retained";
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err;
                if !matches!(phase(), ProvisionState::Parking | ProvisionState::Parked) {
                    return Err(err);
                }
            }
        }
    }
    Err(last_err)
}
pub(super) fn schedule(owner: Arc<Owner>) {
    narf_scheduler::spawn(async move {
        let phase_owner = owner.clone();
        if let Err(reason) = drive_scheduled(
            120,
            || phase_owner.phase(),
            || owner.provision(),
            || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
        )
        .await
        {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "iwlwifi: retained startup: {}",
                reason
            );
        }
    });
}
/// Retry newly staged inputs before firmware/runtime startup; Sc identity-only
/// discovery retains the same mapping with bus mastering disabled.
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
