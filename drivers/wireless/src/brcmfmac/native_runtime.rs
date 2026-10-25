// SPDX-License-Identifier: GPL-2.0-or-later
//! Native retained PCIe/TCM/DMA backend and signed board-policy dispatch.
//! Exact host/chip-qualified manifests or trusted platform registrations select
//! verified calibration assets; no board profile is guessed from a PCI DID.
use super::{
    boot::{self, BoardProfile},
    chip::Backplane,
    pcie::{invoke_registers, BrcmfmacDevice, PcieBackplane},
    runtime::{self, Memory},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    fmt::Write,
    sync::atomic::{compiler_fence, AtomicU8, Ordering},
};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
static PROFILES: IrqSafeSpinLock<Vec<BoardProfile>> = IrqSafeSpinLock::new(Vec::new());
static RUNTIME: Mutex<Option<runtime::Runtime<PcieBackplane>>> = Mutex::new(None);
static EVENTS: IrqSafeSpinLock<VecDeque<Vec<u8>>> = IrqSafeSpinLock::new(VecDeque::new());
/// Register exact platform calibration policy before PCI matching runs.
/// This kernel-only entry does not grant firmware access or override chip
/// discovery. Multi-device NVRAM and newer Apple OTP selection remain gated.
pub fn register_board_profile(profile: BoardProfile) -> bool {
    if profile.chip != 43602
        || profile.revision_mask == 0
        || profile.pci.vendor != 0x14e4
        || !super::pcie::ALL_DEV_IDS.contains(&profile.pci.device)
    {
        return false;
    }
    let mut profiles = PROFILES.lock();
    if profiles.len() == 16 || profiles.iter().any(|p| p.pci == profile.pci) {
        return false;
    }
    profiles.push(profile);
    true
}
pub(super) fn selected_profile(device: &narf_bus::BusDevice) -> Option<BoardProfile> {
    let id = identity(device);
    PROFILES.lock().iter().copied().find(|p| p.pci == id)
}
fn identity(device: &narf_bus::BusDevice) -> boot::PciIdentity {
    boot::PciIdentity {
        vendor: device.id.vendor,
        device: device.id.device,
        subsystem_vendor: device.id.subsystem_vendor,
        subsystem_device: device.id.subsystem_id,
    }
}
/// Startup is retryable only while no firmware/native DMA attempt has begun.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProvisionState {
    Parked = 0,
    Starting = 1,
    Ready = 2,
    Failed = 3,
}
struct Bootstrap {
    parked: Mutex<Option<PcieBackplane>>,
    state: AtomicU8,
    chip: u16,
    revision: u8,
}
static BOOTSTRAP: IrqSafeSpinLock<Option<Arc<Bootstrap>>> = IrqSafeSpinLock::new(None);
struct Attempt<'a>(&'a AtomicU8);
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.0.load(Ordering::Acquire) == ProvisionState::Starting as u8 {
            self.0
                .store(ProvisionState::Failed as u8, Ordering::Release);
        }
    }
}
pub fn provision_state() -> Option<ProvisionState> {
    let owner = BOOTSTRAP.lock().clone()?;
    Some(match owner.state.load(Ordering::Acquire) {
        0 => ProvisionState::Parked,
        1 => ProvisionState::Starting,
        2 => ProvisionState::Ready,
        _ => ProvisionState::Failed,
    })
}
pub(super) async fn drive_scheduled<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut state: impl FnMut() -> Option<ProvisionState>,
    mut step: Step,
    mut wait: Wait,
) -> Result<(), &'static str>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<(), &'static str>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = "signed BCM43602 board selection unavailable or mismatched";
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err;
                if state() != Some(ProvisionState::Parked) {
                    return Err(err);
                }
            }
        }
    }
    Err(last_err)
}
pub(super) fn start(device: &mut BrcmfmacDevice) {
    // BAR mapping and immutable discovery need no board calibration guess.
    // Registry payloads arrive in Stage::Late, after synchronous PCI matching.
    if device.chip.id != 43602
        || device
            .backplane
            .as_ref()
            .is_none_or(|bus| bus.bar2.is_none())
    {
        return;
    }
    let Some(bus) = device.backplane.take() else {
        return;
    };
    let owner = Arc::new(Bootstrap {
        parked: Mutex::new(Some(bus)),
        state: AtomicU8::new(ProvisionState::Parked as u8),
        chip: device.chip.id,
        revision: device.chip.revision,
    });
    *BOOTSTRAP.lock() = Some(owner);
    narf_scheduler::spawn(async {
        if let Err(reason) = drive_scheduled(120, provision_state, provision, || {
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000))
        })
        .await
        {
            let _ = writeln!(narf_console::Writer, "brcmfmac: {}", reason);
        }
    });
}
/// Retry newly staged signed provisioning only before a hardware attempt.
/// The exact parked bus remains retained; this never resets/rebuilds an owner.
pub async fn provision() -> Result<(), &'static str> {
    let owner = BOOTSTRAP
        .lock()
        .clone()
        .ok_or("no retained BCM43602 owner")?;
    if narf_net::trusted_net_authority().is_none() {
        return Err("network registration authority unavailable");
    }
    let authority = super::provision::authority().map_err(|_| "firmware authority unavailable")?;
    provision_using(&owner, &authority, super::provision::MANIFEST).await
}
async fn provision_using(
    owner: &Bootstrap,
    authority: &narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    manifest: &str,
) -> Result<(), &'static str> {
    provision_checked(owner, authority, manifest, || {
        narf_wireless::reg::db::ensure_domain()
            .map(|_| ())
            .map_err(|_| "signed regulatory policy unavailable")
    })
    .await
}
async fn provision_checked(
    owner: &Bootstrap,
    authority: &narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    manifest: &str,
    policy: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    if owner.state.load(Ordering::Acquire) != ProvisionState::Parked as u8 {
        return Err("BCM43602 provisioning already attempted");
    }
    let mut slot = owner.parked.lock().await;
    if owner.state.load(Ordering::Acquire) != ProvisionState::Parked as u8 {
        return Err("BCM43602 provisioning already attempted");
    }
    let bus = slot.as_ref().ok_or("parked BCM43602 owner unavailable")?;
    let pci = identity(&bus.device);
    let explicit = selected_profile(&bus.device);
    let selection = if explicit.is_none() {
        let host = narf_drivers_sdio::pio::HostIdentity {
            address: bus.device.addr,
            id: bus.device.id,
        };
        Some(
            super::provision::select_using(
                authority,
                manifest,
                super::provision::Family::Pcie43602,
                host,
                None,
            )
            .map_err(|_| "signed BCM43602 board selection unavailable or mismatched")?,
        )
    } else {
        None
    };
    let assets = if let Some(profile) = explicit {
        if profile.chip != owner.chip
            || owner.revision >= 16
            || profile.revision_mask & (1 << owner.revision) == 0
        {
            return Err("explicit BCM43602 chip/revision mismatch");
        }
        super::provision::trusted_assets_using(authority, profile.firmware, profile.nvram)
            .map_err(|_| "board-selected firmware/signed NVRAM unavailable")?
    } else {
        let selection = selection.as_ref().unwrap();
        if !selection.admits_chip(owner.chip, owner.revision) {
            return Err("BCM43602 discovered chip/revision mismatch");
        }
        selection
            .load_using(authority)
            .map_err(|_| "selected BCM43602 asset signature/key/length/hash mismatch")?
    };
    let nvram = boot::pack_nvram(&assets.nvram).map_err(|_| "invalid selected BCM43602 NVRAM")?;
    policy()?;
    assets
        .proof
        .validate()
        .map_err(|_| "BCM43602 provisioning revoked/replaced before boot")?;
    // All provisioning failures above preserve the exact parked bus. From
    // this point cancellation/error is one-shot and the device claim survives.
    owner
        .state
        .store(ProvisionState::Starting as u8, Ordering::Release);
    let _attempt = Attempt(&owner.state);
    let mut bus = slot.take().ok_or("parked BCM43602 owner unavailable")?;
    bus.proof = Some(assets.proof.clone());
    let boot = if let Some(profile) = explicit {
        boot::Cr4::claim(bus, pci, profile)
    } else {
        boot::Cr4::claim_selected(bus, pci, selection.as_ref().unwrap())
    }
    .map_err(|_| "CR4 passive/RAM/identity discovery failed")?;
    let boot = boot
        .boot(&assets.firmware, &nvram)
        .map_err(|_| "CR4 firmware bootstrap failed")?;
    let mut runtime =
        runtime::Runtime::attach(boot).map_err(|_| "common-ring/DMA attachment failed")?;
    runtime
        .enable_data()
        .map_err(|_| "RX buffer posting failed")?;
    let adapter = super::station_transport::Adapter::new(runtime)
        .map_err(|_| "station transport setup failed")?;
    drop(slot);
    let name = narf_net::iface::reserve_name("wlan%d");
    crate::cyw43439::interface::attach_runtime(name, adapter, &[])
        .await
        .map_err(|_| "BCM43602 station attachment failed")?;
    owner
        .state
        .store(ProvisionState::Ready as u8, Ordering::Release);
    Ok(())
}
/// One serialized production control request. Cancellation makes the owner
/// terminal while retaining all device-visible addresses and request bytes.
pub async fn command(
    command: u32,
    input: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, runtime::Error> {
    let mut slot = RUNTIME.lock().await;
    let owner = slot.as_mut().ok_or(runtime::Error::Failed)?;
    owner.command(command, input, maximum).await
}
pub fn pop_event() -> Option<Vec<u8>> {
    EVENTS.lock().pop_front()
}
fn barrier() {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: order peripheral ownership across the outer-shareable domain.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}
impl Memory for narf_io::DmaBuffer {
    fn address(&self) -> u64 {
        self.dma_addr().raw()
    }
    fn len(&self) -> usize {
        self.len()
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), runtime::Error> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.len())
        {
            return Err(runtime::Error::Bounds);
        }
        // SAFETY: checked allocated extent, CPU pointer is separate from DMA address.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.cpu_ptr::<u8>().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), runtime::Error> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len())
        {
            return Err(runtime::Error::Bounds);
        }
        // SAFETY: checked extent; caller holds exclusive current CPU ownership.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.cpu_mut_ptr::<u8>().add(offset),
                bytes.len(),
            );
        }
        Ok(())
    }
    fn to_device(&mut self, offset: usize, length: usize) {
        self.sync(offset, length);
        barrier();
    }
    fn release(&mut self) {
        barrier();
    }
    fn sync_from_device(&mut self, offset: usize, length: usize) {
        barrier();
        self.sync(offset, length);
        barrier();
    }
}
impl PcieBackplane {
    fn aperture(&self, address: u32, length: usize) -> Result<narf_bus::MmioRegion, boot::Error> {
        // Called only inside the enclosing register CapOp. The command read
        // additionally verifies that the retained memory aperture is enabled.
        let command = narf_bus::pci::read_command(&self.cap, &self.device)
            .map_err(|_| boot::Error::Access)?;
        if command == u16::MAX
            || command & (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE)
                != (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE)
        {
            return Err(boot::Error::Access);
        }
        let region = self.bar2.ok_or(boot::Error::Extent)?;
        if u64::from(address)
            .checked_add(length as u64)
            .is_none_or(|end| end > region.len)
        {
            return Err(boot::Error::Extent);
        }
        Ok(region)
    }
}
impl boot::Bus for PcieBackplane {
    fn tcm_extent(&self) -> u32 {
        self.bar2
            .map_or(0, |bar| bar.len.min(u64::from(u32::MAX)) as u32)
    }
    fn dma_enabled(&mut self) -> Result<bool, boot::Error> {
        self.qualified().map_err(|_| boot::Error::Access)?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            narf_bus::pci::read_command(&self.cap, &self.device)
                .map(|v| v & narf_bus::pci::cmd::BUS_MASTER != 0)
                .map_err(|_| boot::Error::Access)
        })
        .map_err(|_| boot::Error::Access)?
    }
    // SAFETY for MMIO below: aperture checks exclusive retained authority and
    // the entire extent. Each branch separately proves natural width/alignment.
    fn read_tcm(&mut self, address: u32, out: &mut [u8]) -> Result<(), boot::Error> {
        self.qualified().map_err(|_| boot::Error::Access)?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            let region = self.aperture(address, out.len())?;
            let mut at = 0;
            while at < out.len() {
                let offset = u64::from(address) + at as u64;
                if offset & 3 == 0 && out.len() - at >= 4 {
                    // SAFETY: aperture validated the full live owned range; this
                    // branch proves dword alignment and four available bytes.
                    let value = unsafe { region.read32(offset) };
                    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
                    at += 4;
                } else if offset & 1 == 0 && out.len() - at >= 2 {
                    // SAFETY: live owned aperture, word alignment and two bytes
                    // remaining in the validated extent are proved above.
                    let value = unsafe { region.read16(offset) };
                    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
                    at += 2;
                } else {
                    // SAFETY: at is below out.len() within the validated aperture;
                    // byte MMIO has no additional alignment requirement.
                    out[at] = unsafe { region.read8(offset) };
                    at += 1;
                }
            }
            Ok(())
        })
        .map_err(|_| boot::Error::Access)?
    }
    // SAFETY: same complete extent/authority and per-branch width proof as read.
    fn write_tcm(&mut self, address: u32, bytes: &[u8]) -> Result<(), boot::Error> {
        self.qualified().map_err(|_| boot::Error::Access)?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            let region = self.aperture(address, bytes.len())?;
            let mut at = 0;
            while at < bytes.len() {
                let offset = u64::from(address) + at as u64;
                if offset & 3 == 0 && bytes.len() - at >= 4 {
                    // SAFETY: aperture validated exclusive authority and extent;
                    // this branch proves dword alignment and four remaining bytes.
                    unsafe {
                        region.write32(
                            offset,
                            u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
                        )
                    };
                    at += 4;
                } else if offset & 1 == 0 && bytes.len() - at >= 2 {
                    // SAFETY: live owned aperture and full extent were checked;
                    // this branch proves word alignment and two available bytes.
                    unsafe {
                        region.write16(
                            offset,
                            u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()),
                        )
                    };
                    at += 2;
                } else {
                    // SAFETY: at is below bytes.len() in the validated owned range;
                    // the byte write needs no further alignment.
                    unsafe { region.write8(offset, bytes[at]) };
                    at += 1;
                }
            }
            Ok(())
        })
        .map_err(|_| boot::Error::Access)?
    }
}
impl runtime::Bus for PcieBackplane {
    type Memory = narf_io::DmaBuffer;
    fn allocate(&mut self, length: usize) -> Result<Self::Memory, runtime::Error> {
        self.qualified().map_err(|_| runtime::Error::Access)?;
        invoke_registers(&self.cap, || {
            let command = narf_bus::pci::read_command(&self.cap, &self.device)
                .map_err(|_| runtime::Error::Access)?;
            if command == u16::MAX
                || command & (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE)
                    != (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE)
                || narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain
            {
                return Err(runtime::Error::Access);
            }
            narf_io::alloc_coherent(length, narf_lib::id::DomainId::DRIVER_0)
                .map_err(|_| runtime::Error::Access)
        })
        .map_err(|_| runtime::Error::Access)?
    }
    fn enable_dma(&mut self) -> Result<(), runtime::Error> {
        self.qualified().map_err(|_| runtime::Error::Access)?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            narf_bus::pci::set_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                .map_err(|_| runtime::Error::Access)?;
            let command = narf_bus::pci::read_command(&self.cap, &self.device)
                .map_err(|_| runtime::Error::Access)?;
            if command == u16::MAX
                || command
                    & (narf_bus::pci::cmd::BUS_MASTER
                        | narf_bus::pci::cmd::MEM_SPACE
                        | narf_bus::pci::cmd::INTX_DISABLE)
                    != (narf_bus::pci::cmd::BUS_MASTER
                        | narf_bus::pci::cmd::MEM_SPACE
                        | narf_bus::pci::cmd::INTX_DISABLE)
            {
                return Err(runtime::Error::Access);
            }
            Ok(())
        })
        .map_err(|_| runtime::Error::Access)?
    }
    fn park_dma(&mut self) -> Result<(), runtime::Error> {
        let cap = self.cap;
        invoke_registers(&cap, || {
            narf_bus::pci::clear_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                .map_err(|_| runtime::Error::Access)?;
            let command = narf_bus::pci::read_command(&self.cap, &self.device)
                .map_err(|_| runtime::Error::Access)?;
            if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
                return Err(runtime::Error::Access);
            }
            Ok(())
        })
        .map_err(|_| runtime::Error::Access)?
    }
    fn doorbell(&mut self) -> Result<(), runtime::Error> {
        let core = self.pcie_core.ok_or(runtime::Error::Protocol)?;
        barrier();
        self.write32(
            core.base + if core.revision >= 64 { 0xa20 } else { 0x140 },
            1,
        )
        .map_err(|_| runtime::Error::Access)
    }
    fn host_ready(&mut self, db1: bool) -> Result<(), runtime::Error> {
        if db1 {
            let core = self.pcie_core.ok_or(runtime::Error::Protocol)?;
            barrier();
            self.write32(
                core.base + if core.revision >= 64 { 0xa24 } else { 0x144 },
                1,
            )
            .map_err(|_| runtime::Error::Access)?;
        }
        Ok(())
    }
}

/// Transport entry points for the station owner. These do not publish or
/// authorize a network interface; that requires the station event/key lifecycle.
pub async fn open_flow(
    source: [u8; 6],
    destination: [u8; 6],
    priority: u8,
) -> Result<runtime::FlowToken, runtime::Error> {
    RUNTIME
        .lock()
        .await
        .as_mut()
        .ok_or(runtime::Error::Failed)?
        .open_flow(source, destination, priority)
}
pub async fn flow_state(flow: runtime::FlowToken) -> Result<runtime::FlowState, runtime::Error> {
    RUNTIME
        .lock()
        .await
        .as_ref()
        .ok_or(runtime::Error::Failed)?
        .flow_state(flow)
}
pub async fn close_flow(flow: runtime::FlowToken) -> Result<(), runtime::Error> {
    RUNTIME
        .lock()
        .await
        .as_mut()
        .ok_or(runtime::Error::Failed)?
        .close_flow(flow)
}
pub async fn send(flow: runtime::FlowToken, frame: &[u8]) -> Result<u32, runtime::Error> {
    RUNTIME
        .lock()
        .await
        .as_mut()
        .ok_or(runtime::Error::Failed)?
        .send(flow, frame)
}
pub async fn pop_received() -> Option<Vec<u8>> {
    RUNTIME.lock().await.as_mut()?.pop_received()
}
pub async fn pop_tx_receipt() -> Option<runtime::TxReceipt> {
    RUNTIME.lock().await.as_mut()?.pop_tx_receipt()
}

fn station_policy() -> bool {
    narf_wireless::reg::db::ensure_domain().is_ok()
}

fn available_name() -> Option<alloc::string::String> {
    (0..16).map(|i| alloc::format!("wlan{}", i)).find(|name| {
        narf_net::iface::lookup(name).is_none()
            && !narf_wireless::registry::list()
                .iter()
                .any(|iface| iface.name() == name)
    })
}

#[cfg(feature = "kernel-test")]
mod provision_tests {
    use super::*;
    use crate::brcmfmac::provision::{tests::*, Family};
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use narf_capabilities::{Cap, Write};
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn ready<F: Future>(future: F) -> Option<F::Output> {
        let mut future = core::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        }
    }
    fn smoke_brcmf_board_provisioning_preboot_retry_retains_exact_owner_terminal_attempt_does_not_retry(
    ) -> TestResult {
        let (write, read) = registry().unwrap();
        let selection = choose(&read, Family::Pcie43602).unwrap();
        let host = selection.host();
        let narf_bus::BusAddr::Pcie(address) = host.address else {
            return TestResult::Fail("PCI fixture identity");
        };
        let cap = Cap::<narf_bus::BusDeviceCap, Write>::bootstrap();
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 4096,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let owner = Bootstrap {
            parked: Mutex::new(Some(PcieBackplane {
                proof: None,
                bar0: region,
                bar2: Some(region),
                device: narf_bus::BusDevice {
                    addr: host.address,
                    id: host.id,
                    kind: narf_bus::BusKind::Pcie {
                        addr: address,
                        cfg_phys: narf_memory::PhysAddr::new(0),
                    },
                },
                cap,
                pcie_core: None,
            })),
            state: AtomicU8::new(ProvisionState::Parked as u8),
            chip: 43602,
            revision: 3,
        };
        for _ in 0..2 {
            if !matches!(
                ready(provision_using(
                    &owner,
                    &read,
                    "narf-test/brcm/missing-selection"
                )),
                Some(Err(_))
            ) || owner.state.load(Ordering::Acquire) != ProvisionState::Parked as u8
                || ready(async {
                    owner
                        .parked
                        .lock()
                        .await
                        .as_ref()
                        .map(|bus| bus.cap.slot().index)
                }) != Some(Some(cap.slot().index))
            {
                return TestResult::Fail(
                    "missing board selection lost or replaced exact parked PCI owner",
                );
            }
        }
        stage_invalid_executable(&write, Family::Pcie43602);
        if !matches!(
            ready(provision_checked(&owner, &read, TEST_MANIFEST, || Ok(()))),
            Some(Err(_))
        ) || owner.state.load(Ordering::Acquire) != ProvisionState::Parked as u8
            || ready(async { owner.parked.lock().await.is_some() }) != Some(true)
        {
            return TestResult::Fail(
                "exact signed short CR4 image consumed parked hardware attempt",
            );
        }
        registry().unwrap(); // valid newly staged bytes can continue the same owner.
        if !matches!(
            ready(provision_checked(&owner, &read, TEST_MANIFEST, || Err(
                "policy absent"
            ))),
            Some(Err(_))
        ) || owner.state.load(Ordering::Acquire) != ProvisionState::Parked as u8
        {
            return TestResult::Fail(
                "valid board assets without regulatory policy began CR4 attempt",
            );
        }
        // Current revoked PCI authority must reject discovery before the
        // deliberately invalid ECAM/BAR addresses. The admitted one-shot
        // attempt then stays terminal, with no reconstructed hardware owner.
        cap.revoke();
        if !matches!(
            ready(provision_checked(&owner, &read, TEST_MANIFEST, || Ok(()))),
            Some(Err(_))
        ) || owner.state.load(Ordering::Acquire) != ProvisionState::Failed as u8
            || ready(async { owner.parked.lock().await.is_none() }) != Some(true)
            || !matches!(
                ready(provision_checked(&owner, &read, TEST_MANIFEST, || Ok(()))),
                Some(Err(_))
            )
        {
            return TestResult::Fail(
                "failed CR4 native attempt became retryable or retained unsafe parked owner",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/brcmfmac/provision",
        smoke_brcmf_board_provisioning_preboot_retry_retains_exact_owner_terminal_attempt_does_not_retry
    );

    fn smoke_brcmf_drive_scheduled_retries_and_terminates() -> TestResult {
        let state = core::sync::atomic::AtomicU8::new(ProvisionState::Parked as u8);

        // Case 1: retries while state() == Some(ProvisionState::Parked) and succeeds
        let attempts = core::cell::Cell::new(0);
        let waits = core::cell::Cell::new(0);
        let result = narf_scheduler::block_on(drive_scheduled(
            5,
            || match state.load(Ordering::Acquire) {
                0 => Some(ProvisionState::Parked),
                1 => Some(ProvisionState::Starting),
                2 => Some(ProvisionState::Ready),
                _ => Some(ProvisionState::Failed),
            },
            || {
                let n = attempts.get();
                attempts.set(n + 1);
                async move {
                    if n < 2 {
                        Err("missing asset")
                    } else {
                        Ok(())
                    }
                }
            },
            || {
                waits.set(waits.get() + 1);
                async {}
            },
        ));
        if result.is_err() || attempts.get() != 3 || waits.get() != 2 {
            return TestResult::Fail("brcmfmac drive_scheduled failed to retry while parked");
        }

        // Case 2: exits immediately when state is unretryable (Failed)
        state.store(ProvisionState::Failed as u8, Ordering::Release);
        attempts.set(0);
        waits.set(0);
        let result = narf_scheduler::block_on(drive_scheduled(
            10,
            || match state.load(Ordering::Acquire) {
                0 => Some(ProvisionState::Parked),
                1 => Some(ProvisionState::Starting),
                2 => Some(ProvisionState::Ready),
                _ => Some(ProvisionState::Failed),
            },
            || {
                let n = attempts.get();
                attempts.set(n + 1);
                async move { Err("missing asset") }
            },
            || {
                waits.set(waits.get() + 1);
                async {}
            },
        ));
        if result != Err("missing asset") || attempts.get() != 1 || waits.get() != 0 {
            return TestResult::Fail(
                "brcmfmac drive_scheduled did not exit immediately when unretryable",
            );
        }

        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/brcmfmac/provision",
        smoke_brcmf_drive_scheduled_retries_and_terminates
    );
}
