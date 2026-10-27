// SPDX-License-Identifier: GPL-2.0-or-later
//! PCIe boot transport: owned DMA32 rings, CE7 diagnostics, target setup
//! and real CE0/CE1 BMI exchanges. No WLAN interface is claimed here.
//!
//! Linux reference: `ath10k/pci.c` reset, init_config, diag and BMI paths.
//! Timeouts poison the session. Drop only frees memory after CE halt and
//! verified PCI bus-master disable; otherwise allocations remain retained.

use core::mem::ManuallyDrop;

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Write};
use narf_io::DmaBuffer;
use narf_lib::id::DomainId;

use super::bmi::{word, BmiError, Transport};
use super::ce::{self, Ath10kMmio};
use super::dma::{barrier, Direction, Memory, Ring};
use super::hw::{self, HwRev, Registers};

#[path = "boot/hif.rs"]
mod hif;
#[cfg(any(test, feature = "kernel-test"))]
pub(super) use hif::tests::CeFixture;
#[path = "boot/htt_memory.rs"]
mod htt_memory;
#[path = "boot/recovery.rs"]
mod recovery;
#[path = "boot/wmi_memory.rs"]
mod wmi_memory;

const HOST_INTEREST: u32 = 0x400800;

#[derive(Debug)]
struct RawMmio(MmioRegion);
impl Ath10kMmio for RawMmio {
    fn read32(&mut self, offset: u64) -> u32 {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.0.len) {
            return u32::MAX;
        }
        // SAFETY: complete checked BAR extent; called inside Cap::invoke.
        unsafe { self.0.read32(offset) }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.0.len) {
            return;
        }
        // SAFETY: complete checked BAR extent; called inside Cap::invoke.
        unsafe { self.0.write32(offset, value) }
    }
}

#[derive(Debug)]
struct Mmio<I = RawMmio> {
    cap: Cap<BusDeviceCap, Write>,
    io: I,
    sources: Option<super::firmware_source::Source>,
}
struct RegisterOp<'a, I> {
    io: &'a mut I,
    offset: u64,
    value: Option<u32>,
}
impl<I: Ath10kMmio> CapOp<BusDeviceCap, Write> for RegisterOp<'_, I> {
    type Output = u32;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<u32, CapError> {
        Ok(match self.value {
            Some(value) => {
                self.io.write32(self.offset, value);
                0
            }
            None => self.io.read32(self.offset),
        })
    }
}
impl<I: Ath10kMmio> Ath10kMmio for Mmio<I> {
    fn authorized(&self) -> bool {
        self.cap.invoke(NoopOp).is_ok()
            && self
                .sources
                .as_ref()
                .is_none_or(|s| s.invoke_boot(|| ()).is_ok())
    }
    fn read32(&mut self, offset: u64) -> u32 {
        let operation = RegisterOp {
            io: &mut self.io,
            offset,
            value: None,
        };
        match &self.sources {
            Some(s) => s
                .invoke_boot(|| self.cap.invoke(operation))
                .ok()
                .and_then(Result::ok),
            None => self.cap.invoke(operation).ok(),
        }
        .unwrap_or(u32::MAX)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        let operation = RegisterOp {
            io: &mut self.io,
            offset,
            value: Some(value),
        };
        if let Some(s) = &self.sources {
            let _ = s.invoke_boot(|| self.cap.invoke(operation));
        } else {
            let _ = self.cap.invoke(operation);
        }
    }
}

#[derive(Debug)]
struct Resources<B = DmaBuffer> {
    tx: Ring<B>,
    rx: Ring<B>,
    diag_tx: Ring<B>,
    diag_rx: Ring<B>,
    request: B,
    response: B,
    diag: B,
    codeswap: Option<B>,
}

fn allocate(bytes: usize) -> Result<DmaBuffer, BmiError> {
    narf_io::alloc_coherent_masked(bytes, DomainId::DRIVER_0, u32::MAX as u64)
        .map_err(|_| BmiError::NoMemory)
}

impl Resources<DmaBuffer> {
    fn allocate(hardware: HwRev) -> Result<Self, BmiError> {
        Ok(Self {
            tx: Ring::new(allocate(16 * 8)?, hardware, 0, 16, Direction::Source)?,
            rx: Ring::new(allocate(512 * 8)?, hardware, 1, 512, Direction::Destination)?,
            diag_tx: Ring::new(allocate(2 * 8)?, hardware, 7, 2, Direction::Source)?,
            diag_rx: Ring::new(allocate(2 * 8)?, hardware, 7, 2, Direction::Destination)?,
            request: allocate(256)?,
            response: allocate(2048)?,
            diag: allocate(2048)?,
            codeswap: None,
        })
    }
}

#[derive(Debug)]
pub(super) struct PciBoot {
    mmio: Mmio,
    hardware: HwRev,
    registers: Registers,
    device: BusDevice,
    resources: ManuallyDrop<Resources>,
    hif: ManuallyDrop<Option<hif::Runtime<DmaBuffer>>>,
    hif_live: bool,
    mission_pending: bool,
    power_ready: bool,
    armed: bool,
    poisoned: bool,
    saved_aspm: Option<u16>,
    retired: bool,
}

impl PciBoot {
    pub(super) fn bind_sources(&mut self, source: super::firmware_source::Source) {
        // Set once after ROM identity and before the first executable copy.
        if self.mmio.sources.is_some() || source.bind_pci(self.mmio.cap).is_err() {
            self.poisoned = true;
            return;
        }
        self.mmio.sources = Some(source);
    }
    pub(super) fn current_sources(&self) -> Option<super::firmware_source::Source> {
        self.mmio.sources.clone()
    }
    pub(super) fn check_sources(&self) -> Result<(), BmiError> {
        if self.retired
            || self.poisoned
            || !self.mmio.authorized()
            || self
                .mmio
                .sources
                .as_ref()
                .is_none_or(|s| s.check().is_err())
        {
            return Err(BmiError::DeviceGone);
        }
        Ok(())
    }
    /// Probe must already have disabled inherited PCI bus mastering.
    pub fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        mmio: MmioRegion,
        hardware: HwRev,
    ) -> Result<Self, BmiError> {
        let registers = hardware.registers().ok_or(BmiError::Unsupported)?;
        let command = narf_bus::pci::read_command(&cap, &device).map_err(|_| BmiError::Pci)?;
        if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(BmiError::Pci);
        }
        let resources = Resources::allocate(hardware)?;
        Ok(Self {
            mmio: Mmio {
                cap,
                io: RawMmio(mmio),
                sources: None,
            },
            hardware,
            registers,
            device,
            resources: ManuallyDrop::new(resources),
            hif: ManuallyDrop::new(None),
            hif_live: false,
            mission_pending: false,
            power_ready: false,
            armed: false,
            poisoned: false,
            saved_aspm: None,
            retired: false,
        })
    }

    async fn delay(ms: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ms * 1_000_000)).await;
    }

    async fn wake(&mut self) -> Result<(), BmiError> {
        self.mmio.write32(self.registers.pcie_local + 4, 1);
        let on = if self.hardware == HwRev::Qca99x0 {
            7
        } else {
            3
        };
        let deadline = narf_time::Deadline::after_ms(30);
        loop {
            let value = self.mmio.read32(self.registers.pcie_local);
            if value == u32::MAX {
                return Err(BmiError::DeviceGone);
            }
            if value & 7 == on {
                return Ok(());
            }
            if deadline.expired() {
                return Err(BmiError::Timeout);
            }
            Self::delay(1).await;
        }
    }

    fn initialize_pipes(&mut self) -> Result<(), BmiError> {
        self.resources
            .tx
            .initialize(&mut self.mmio, self.hardware, 0, 256)?;
        self.resources
            .rx
            .initialize(&mut self.mmio, self.hardware, 1, 2048)?;
        self.resources
            .diag_tx
            .initialize(&mut self.mmio, self.hardware, 7, 2048)?;
        self.resources
            .diag_rx
            .initialize(&mut self.mmio, self.hardware, 7, 2048)?;
        Ok(())
    }

    async fn target_ready(&mut self) -> Result<(), BmiError> {
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            let value = self.mmio.read32(self.registers.fw_indicator);
            if value != u32::MAX && value & hw::FW_IND_EVENT_PENDING != 0 {
                return Err(BmiError::BadResponse);
            }
            if value != u32::MAX && value & hw::FW_IND_INITIALIZED != 0 {
                return Ok(());
            }
            if deadline.expired() {
                return Err(if value == u32::MAX {
                    BmiError::DeviceGone
                } else {
                    BmiError::Timeout
                });
            }
            Self::delay(10).await;
        }
    }

    fn reset_cpu(&mut self) {
        self.mmio.write32(self.registers.fw_indicator, 0);
        let reset = self.mmio.read32(self.registers.rtc_soc);
        self.mmio.write32(self.registers.rtc_soc, reset | 0x40);
    }

    async fn warm_reset(&mut self) -> Result<(), BmiError> {
        // Linux first resets SI0/CPU before touching CE; resetting CE
        // while the target CPU accesses it can hang the PCIe controller.
        let si0 = if matches!(self.hardware, HwRev::Qca6174 | HwRev::Qca9377) {
            0
        } else {
            1
        };
        let reset = self.mmio.read32(self.registers.rtc_soc);
        self.mmio.write32(self.registers.rtc_soc, reset | si0);
        let _ = self.mmio.read32(self.registers.rtc_soc);
        Self::delay(10).await;
        let reset = self.mmio.read32(self.registers.rtc_soc);
        self.mmio.write32(self.registers.rtc_soc, reset & !si0);
        let _ = self.mmio.read32(self.registers.rtc_soc);
        Self::delay(10).await;
        self.reset_cpu();
        self.initialize_pipes()?;
        self.target_ready().await?;
        let timer = self.mmio.read32(self.registers.rtc_soc + 0x50);
        self.mmio.write32(self.registers.rtc_soc + 0x50, timer & !4);
        let reset = self.mmio.read32(self.registers.rtc_soc);
        self.mmio
            .write32(self.registers.rtc_soc, reset | self.registers.ce_reset);
        Self::delay(10).await;
        self.mmio
            .write32(self.registers.rtc_soc, reset & !self.registers.ce_reset);
        self.reset_cpu();
        self.initialize_pipes()?;
        self.target_ready().await
    }

    async fn cold_reset(&mut self) -> Result<(), BmiError> {
        let address = self.registers.pcie_local + 8;
        let value = self.mmio.read32(address);
        if value == u32::MAX {
            return Err(BmiError::DeviceGone);
        }
        self.mmio.write32(address, value | 1);
        // No PCIe register access while the link is settling.
        Self::delay(20).await;
        self.mmio.write32(address, value & !1);
        Self::delay(20).await;
        self.wake().await?;
        self.target_ready().await
    }

    pub async fn power_up(&mut self, chip_revision: u32) -> Result<(), BmiError> {
        if self.retired {
            return Err(BmiError::BadResponse);
        }
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        self.saved_aspm = narf_bus::pci_express::clear_and_set_link_control(
            &self.mmio.cap,
            &self.device,
            narf_bus::pci_express::LNKCTL_ASPMC,
            0,
        )
        .ok();
        self.wake().await?;
        // Boot exchanges are polled, so no interrupt is enabled before a
        // live dispatch owner exists. Runtime MSI setup belongs to HIF start.
        self.mmio.write32(self.registers.soc_core + 8, 0);
        match self.hardware {
            // Prefer the safe warm reset on QCA988X. Do not automatically
            // cold-reset boards Linux documents can lock up on that path.
            // Linux `pci.c` gives QCA9887 the same warm soft reset.
            HwRev::Qca988x | HwRev::Qca9887 => self.warm_reset().await?,
            HwRev::Qca6174 | HwRev::Qca9377 => {
                self.cold_reset().await?;
                self.warm_reset().await?;
            }
            HwRev::Qca99x0 | HwRev::Qca9888 | HwRev::Qca9984 => self.cold_reset().await?,
            HwRev::Ar9462Legacy => return Err(BmiError::Unsupported),
        }
        self.initialize_pipes()?;
        barrier();
        // Mark the resources as published before the first fallible enable.
        self.armed = true;
        narf_bus::pci::set_command(&self.mmio.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
            .map_err(|_| BmiError::Pci)?;
        self.configure_target(chip_revision).await?;
        let control = self.mmio.read32(self.registers.soc_core);
        self.mmio.write32(self.registers.soc_core, control | 0x2000);
        self.power_ready = true;
        Ok(())
    }

    fn target_address(&mut self, address: u32) -> Result<u32, BmiError> {
        let raw = if self.registers.ce_count == 12 {
            self.mmio.read32(0x40030)
        } else {
            self.mmio.read32(self.registers.soc_core)
        };
        if raw == u32::MAX {
            return Err(BmiError::DeviceGone);
        }
        let base = if self.registers.ce_count == 12 {
            raw
        } else {
            (raw & 0x7ff) << 21
        };
        let region =
            if matches!(self.hardware, HwRev::Qca6174 | HwRev::Qca9377) && address < 0x100000 {
                0
            } else {
                0x100000
            };
        Ok(base | region | (address & 0xfffff))
    }

    async fn diag_transfer(
        &mut self,
        address: u32,
        bytes: &mut [u8],
        write: bool,
    ) -> Result<(), BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if self.poisoned
            || address & 3 != 0
            || bytes.is_empty()
            || bytes.len() > 2048
            || bytes.len() & 3 != 0
        {
            return Err(BmiError::BadResponse);
        }
        address
            .checked_add(bytes.len() as u32)
            .ok_or(BmiError::AddressOverflow)?;
        let target = self.target_address(address)?;
        self.resources
            .diag_exchange(&mut self.mmio, &mut self.poisoned, target, bytes, write)
            .await
    }

    async fn diag_read(&mut self, address: u32) -> Result<u32, BmiError> {
        let mut value = [0; 4];
        self.diag_transfer(address, &mut value, false).await?;
        Ok(word(&value))
    }

    async fn diag_write(&mut self, address: u32, value: u32) -> Result<(), BmiError> {
        self.diag_transfer(address, &mut value.to_le_bytes(), true)
            .await
    }

    async fn configure_target(&mut self, revision: u32) -> Result<(), BmiError> {
        let state = self.diag_read(HOST_INTEREST + 0xf8).await?;
        if state == 0 || state & 3 != 0 {
            return Err(BmiError::BadResponse);
        }
        let pipe_config = self.diag_read(state).await?;
        let services = self
            .diag_read(state.checked_add(4).ok_or(BmiError::AddressOverflow)?)
            .await?;
        if pipe_config == 0 || services == 0 {
            return Err(BmiError::BadResponse);
        }
        let mut config = target_pipe_config(self.hardware);
        self.diag_transfer(pipe_config, &mut config, true).await?;
        let mut map = service_map(self.hardware);
        self.diag_transfer(services, &mut map, true).await?;
        let flags_at = state.checked_add(32).ok_or(BmiError::AddressOverflow)?;
        let flags = self.diag_read(flags_at).await?;
        self.diag_write(flags_at, flags & !1).await?;
        let banks = match self.hardware {
            HwRev::Qca9377 => 9,
            HwRev::Qca6174 => match revision {
                0 | 1 | 4 | 5 => 3,
                2 => 2,
                8..=10 => 9,
                _ => return Err(BmiError::Unsupported),
            },
            _ => 1,
        };
        let early = self.diag_read(HOST_INTEREST + 0x100).await?;
        self.diag_write(HOST_INTEREST + 0x100, early | 0x6d8a0000 | banks)
            .await?;
        let flags = self.diag_read(HOST_INTEREST + 0xcc).await?;
        self.diag_write(HOST_INTEREST + 0xcc, flags | 0x10).await
    }
}

impl Transport for PciBoot {
    fn prepare_done(&mut self) -> Result<(), BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if self.poisoned || self.hif.is_none() || self.hif_live {
            return Err(BmiError::Unsupported);
        }
        self.mission_pending = true;
        Ok(())
    }
    fn done_complete(&mut self) {
        self.hif_live = true;
    }

    async fn exchange(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, BmiError> {
        self.resources
            .bmi_exchange(&mut self.mmio, &mut self.poisoned, request, response)
            .await
    }

    async fn calibration_eeprom(
        &mut self,
        length: usize,
    ) -> Result<Option<alloc::vec::Vec<u8>>, BmiError> {
        if self.hardware != HwRev::Qca9887 {
            return Ok(None);
        }
        if self.retired || self.poisoned || self.hif_live || !self.power_ready {
            return Err(BmiError::BadResponse);
        }
        super::eeprom::fetch(&mut self.mmio, self.registers, length).await
    }

    fn prepare_codeswap(&mut self, bytes: &[u8]) -> Result<(u32, [u8; 208]), BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if self.poisoned || self.resources.codeswap.is_some() {
            return Err(BmiError::BadResponse);
        }
        let layout = super::swap::Layout::parse(bytes)?;
        let mut memory = allocate(layout.size)?;
        let info = layout.fill(bytes, &mut memory)?;
        // This allocation becomes part of the same fail-safe teardown owner
        // as every CE buffer before its address enters target memory.
        self.resources.codeswap = Some(memory);
        Ok((layout.target, info))
    }
}

impl<B: Memory> Resources<B> {
    async fn wait_pair(
        &mut self,
        mmio: &mut impl Ath10kMmio,
        diag: bool,
        receive: bool,
        budget_ms: u64,
    ) -> Result<u16, BmiError> {
        let deadline = narf_time::Deadline::after_ms(budget_ms);
        let mut sent = false;
        let mut received = if receive { None } else { Some(0) };
        loop {
            let Resources {
                tx,
                rx,
                diag_tx,
                diag_rx,
                ..
            } = self;
            let (tx, rx) = if diag { (diag_tx, diag_rx) } else { (tx, rx) };
            if !sent {
                sent = tx.completion(mmio)?.is_some();
            }
            if received.is_none() {
                received = rx.completion(mmio)?;
            }
            if sent {
                if let Some(count) = received {
                    return Ok(count);
                }
            }
            if deadline.expired() {
                return Err(BmiError::Timeout);
            }
            PciBoot::delay(1).await;
        }
    }

    async fn diag_exchange(
        &mut self,
        mmio: &mut impl Ath10kMmio,
        poisoned: &mut bool,
        target: u32,
        bytes: &mut [u8],
        write: bool,
    ) -> Result<(), BmiError> {
        if !mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if *poisoned
            || bytes.is_empty()
            || bytes.len() > 2048
            || target & 3 != 0
            || bytes.len() & 3 != 0
        {
            return Err(BmiError::BadResponse);
        }
        // Poison before the first shared bounce-buffer mutation. Dropping
        // this future after publication leaves the same terminal gate set.
        *poisoned = true;
        let host = self.diag.dma_address() as u32;
        if write {
            for (i, byte) in bytes.iter().enumerate() {
                self.diag.write(i, *byte);
            }
        }
        let (source, destination) = if write {
            (host, target)
        } else {
            (target, host)
        };
        let result = async {
            self.diag_rx.post(mmio, destination, bytes.len() as u16)?;
            barrier();
            self.diag_tx.post(mmio, source, bytes.len() as u16)?;
            if self.wait_pair(mmio, true, true, 1000).await? as usize != bytes.len() {
                return Err(BmiError::BadResponse);
            }
            if !write {
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = self.diag.read(i);
                }
            }
            Ok(())
        }
        .await;
        if result.is_ok() {
            *poisoned = false;
        }
        result
    }

    async fn bmi_exchange(
        &mut self,
        mmio: &mut impl Ath10kMmio,
        poisoned: &mut bool,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, BmiError> {
        if !mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if *poisoned {
            return Err(BmiError::BadResponse);
        }
        if request.is_empty() || request.len() > 256 || response.len() > 2048 {
            return Err(BmiError::BadResponse);
        }
        // Neither pending CE slots nor their bounce bytes may be reused
        // after cancellation. Set this before copying, not after an await.
        *poisoned = true;
        for (i, byte) in request.iter().enumerate() {
            self.request.write(i, *byte);
        }
        let result = async {
            if !response.is_empty() {
                let address = self.response.dma_address() as u32;
                self.rx.post(mmio, address, 2048)?;
            }
            let address = self.request.dma_address() as u32;
            self.tx.post(mmio, address, request.len() as u16)?;
            let count = self
                .wait_pair(mmio, false, !response.is_empty(), 3000)
                .await? as usize;
            if count > response.len() {
                return Err(BmiError::BadResponse);
            }
            for (i, byte) in response[..count].iter_mut().enumerate() {
                *byte = self.response.read(i);
            }
            Ok(count)
        }
        .await;
        if result.is_ok() {
            *poisoned = false;
        }
        result
    }
}

impl Drop for PciBoot {
    fn drop(&mut self) {
        if self.retired {
            // A successor owns this function. Keep every old mapping pinned
            // and never halt or reconfigure the new physical generation.
            return;
        }
        let mut stopped = true;
        if self.armed {
            for pipe in 0..self.registers.ce_count {
                stopped &= ce::halt_pipe(&mut self.mmio, self.hardware, pipe).is_ok();
            }
        }
        let disabled = narf_bus::pci::clear_command(
            &self.mmio.cap,
            &self.device,
            narf_bus::pci::cmd::BUS_MASTER,
        )
        .is_ok()
            && narf_bus::pci::read_command(&self.mmio.cap, &self.device)
                .is_ok_and(|command| command & narf_bus::pci::cmd::BUS_MASTER == 0);
        if stopped && disabled && !self.mission_pending {
            barrier();
            // SAFETY: no CE can access the allocations and PCI BME is clear.
            unsafe {
                ManuallyDrop::drop(&mut self.resources);
                ManuallyDrop::drop(&mut self.hif);
            }
        }
        // After DONE may have reached firmware, CE halt plus BME readback
        // cannot prove CPU-directed/autonomous writes have drained. Keep every
        // published mapping retained until an owned reset/drain implementation.
        if let Some(link) = self.saved_aspm {
            let _ = narf_bus::pci_express::clear_and_set_link_control(
                &self.mmio.cap,
                &self.device,
                narf_bus::pci_express::LNKCTL_ASPMC,
                link & narf_bus::pci_express::LNKCTL_ASPMC,
            );
        }
    }
}

fn target_pipe_config(hardware: HwRev) -> alloc::vec::Vec<u8> {
    let pipes: [[u32; 6]; 10] = [
        [0, 2, 32, 256, 0, 0],
        [1, 1, 32, 2048, 0, 0],
        [2, 1, 64, 2048, 0, 0],
        [3, 2, 32, 2048, 0, 0],
        [4, 2, 256, 256, 0, 0],
        // QCA6174/9377 use CE1 for HTT RX and repurpose CE5.
        [
            5,
            if matches!(hardware, HwRev::Qca6174 | HwRev::Qca9377) {
                2
            } else {
                1
            },
            32,
            if matches!(hardware, HwRev::Qca6174 | HwRev::Qca9377) {
                2048
            } else {
                512
            },
            0,
            0,
        ],
        [6, 3, 32, 4096, 0, 0],
        [7, 3, 0, 0, 0, 0],
        [8, 1, 64, 2048, 8, 0],
        [9, 3, 32, 2048, 8, 0],
    ];
    let count = if hardware.registers().is_some_and(|r| r.ce_count == 12) {
        10
    } else {
        7
    };
    pipes[..count]
        .iter()
        .flat_map(|pipe| pipe.iter().flat_map(|word| word.to_le_bytes()))
        .collect()
}

fn service_map(hardware: HwRev) -> alloc::vec::Vec<u8> {
    let mut map = alloc::vec::Vec::new();
    for service in [0x104u32, 0x102, 0x101, 0x103, 0x100, 1, 0xfe00, 0x300] {
        let (tx, rx) = if matches!(service, 1 | 0xfe00) {
            (0, 1)
        } else if service == 0x300 {
            (
                4,
                if matches!(hardware, HwRev::Qca6174 | HwRev::Qca9377) {
                    1
                } else {
                    5
                },
            )
        } else {
            (3, 2)
        };
        for (direction, pipe) in [(2u32, tx), (1, rx)] {
            for value in [service, direction, pipe] {
                map.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    map.extend_from_slice(&[0; 12]);
    map
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "boot/tests.rs"]
mod tests;
