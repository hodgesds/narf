// SPDX-License-Identifier: GPL-2.0-or-later
//! Native retained PCIe/TCM/DMA backend and explicit board-policy dispatch.
//! No board profile is guessed from a PCI DID. Platform code must register
//! verified chip/revision/subsystem-specific firmware and calibration names.
use super::{
    boot::{self, BoardProfile},
    chip::Backplane,
    pcie::{invoke_registers, BrcmfmacDevice, PcieBackplane},
    runtime::{self, Memory},
};
use alloc::{collections::VecDeque, vec::Vec};
use core::{
    fmt::Write,
    sync::atomic::{compiler_fence, Ordering},
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
fn blob(name: &str) -> Result<Vec<u8>, &'static str> {
    let authority = narf_firmware::trusted_loader_authority()
        .and_then(|c| c.derive().ok())
        .ok_or("firmware authority unavailable")?;
    let cap = narf_firmware::open(name, &authority)
        .map_err(|_| "board-selected firmware/NVRAM unavailable")?;
    Ok(narf_firmware::view_of(&cap)
        .map_err(|_| "firmware authority revoked")?
        .bytes
        .to_vec())
}
pub(super) fn start(device: &mut BrcmfmacDevice) {
    let Some(backplane) = device.backplane.as_ref() else {
        return;
    };
    let Some(profile) = selected_profile(&backplane.device) else {
        return;
    };
    let Some(backplane) = device.backplane.take() else {
        return;
    };
    let pci = identity(&backplane.device);
    narf_scheduler::spawn(async move {
        let result: Result<runtime::Runtime<PcieBackplane>, &'static str> = (|| {
            let firmware = blob(profile.firmware)?;
            let nvram = boot::pack_nvram(&blob(profile.nvram)?)
                .map_err(|_| "invalid/unsupported board NVRAM")?;
            let boot = boot::Cr4::claim(backplane, pci, profile)
                .map_err(|_| "CR4 passive/RAM discovery failed")?
                .boot(&firmware, &nvram)
                .map_err(|_| "CR4 firmware bootstrap failed")?;
            let mut runtime =
                runtime::Runtime::attach(boot).map_err(|_| "common-ring/DMA attachment failed")?;
            runtime
                .enable_data()
                .map_err(|_| "RX buffer posting failed")?;
            Ok(runtime)
        })();
        let runtime = match result {
            Ok(owner) => owner,
            Err(reason) => {
                let _ = writeln!(narf_console::Writer, "brcmfmac: {}", reason);
                return;
            }
        };
        // Authenticated regulatory policy and exact board firmware are both
        // prerequisites. Missing policy leaves only the diagnostic control
        // owner; it cannot register a NIC or authorize a station.
        if station_policy() {
            let Some(name) = available_name() else {
                let _ = writeln!(narf_console::Writer, "brcmfmac: no free interface name");
                return;
            };
            let adapter = match super::station_transport::Adapter::new(runtime) {
                Ok(a) => a,
                Err(_) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "brcmfmac: station transport setup failed"
                    );
                    return;
                }
            };
            match crate::cyw43439::interface::attach_runtime(&name, adapter, &[]).await {
                Ok(_) => {}
                Err(error) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "brcmfmac: station attachment failed: {:?}",
                        error
                    );
                }
            }
            return;
        }
        *RUNTIME.lock().await = Some(runtime);
        loop {
            {
                let mut slot = RUNTIME.lock().await;
                let Some(owner) = slot.as_mut() else {
                    return;
                };
                if owner.poll().is_err() {
                    return;
                }
                // Bound the worker and its event retention. Overflow fail-stops
                // the retained runtime instead of silently losing link state.
                while let Some(event) = owner.pop_event() {
                    let mut events = EVENTS.lock();
                    if events.len() == 32 {
                        owner.fail();
                        return;
                    }
                    events.push_back(event);
                }
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    });
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
        if command & narf_bus::pci::cmd::MEM_SPACE == 0 {
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
        narf_io::alloc_coherent(length, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| runtime::Error::Access)
    }
    fn enable_dma(&mut self) -> Result<(), runtime::Error> {
        let cap = self.cap;
        invoke_registers(&cap, || {
            narf_bus::pci::set_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                .map_err(|_| runtime::Error::Access)?;
            let command = narf_bus::pci::read_command(&self.cap, &self.device)
                .map_err(|_| runtime::Error::Access)?;
            if command
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
