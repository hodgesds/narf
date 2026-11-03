// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned PCIe dongle boot (BCM43602 and the `chip_profile` CR4/CA7 chips),
//! staged against Linux brcmfmac/{chip,pcie}.c. No DMA or station admission:
//! this hands validated firmware metadata to the retained common-ring owner.
//! Board calibration is selected explicitly.
use super::chip::{self, Backplane, Chip, Core};
use super::chip_profile::{self, Cpu};
use super::shared::SharedInfo;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Gone,
    Unsupported,
    Board,
    Image,
    Extent,
    State,
    Timeout,
    Metadata,
    Chip(chip::Error),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciIdentity {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
}
/// Kernel/platform calibration policy, never constructed from the PCI DID
/// filename heuristic. Firmware bytes come from named verified registry caps.
#[derive(Clone, Copy, Debug)]
pub struct BoardProfile {
    pub chip: u16,
    pub revision_mask: u16,
    pub pci: PciIdentity,
    pub firmware: &'static str,
    pub nvram: &'static str,
}
impl BoardProfile {
    fn admits(self, chip: &Chip, pci: PciIdentity) -> bool {
        chip_profile::profile(self.chip, chip.revision).is_some()
            // A trusted registration carries no PCI class; the Linux id row
            // must still bind with an implemented vendor path.
            && (self.chip == chip_profile::BRCM_CC_43602
                || chip_profile::pci_row(
                    pci.vendor,
                    pci.device,
                    (pci.subsystem_vendor, pci.subsystem_device),
                )
                .is_some_and(chip_profile::implemented))
            && chip.id == self.chip
            && chip.revision < 16
            && self.revision_mask & (1 << chip.revision) != 0
            && self.pci == pci
            && !self.firmware.is_empty()
            && !self.nvram.is_empty()
            && !self.firmware.starts_with('/')
            && !self.nvram.starts_with('/')
            && !self.firmware.split('/').any(|p| p == "..")
            && !self.nvram.split('/').any(|p| p == "..")
    }
}
/// Exclusive BAR0 + checked BAR2 owner. RAM addresses are absolute TCM
/// offsets, as in Linux memcpy_toio(tcm + address). Implementations check
/// PCI authority on every transaction and keep BME disabled during boot.
pub trait Bus: Backplane {
    fn tcm_extent(&self) -> u32;
    fn read_tcm(&mut self, address: u32, bytes: &mut [u8]) -> Result<(), Error>;
    fn write_tcm(&mut self, address: u32, bytes: &[u8]) -> Result<(), Error>;
    fn dma_enabled(&mut self) -> Result<bool, Error>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ram {
    pub base: u32,
    pub size: u32,
}
impl Ram {
    pub fn contains(self, address: u32, length: usize) -> bool {
        let Some(end) = address.checked_add(length.try_into().unwrap_or(u32::MAX)) else {
            return false;
        };
        address >= self.base && end <= self.base.saturating_add(self.size)
    }
}
#[derive(Debug)]
pub struct Booted<B: Bus> {
    pub(crate) bus: B,
    pub ram: Ram,
    pub shared_address: u32,
    pub shared: SharedInfo,
    pub chip: Chip,
}
/// The retained loader. Named for the original CR4 path; `cpu` selects the
/// Linux `brcmf_chip_cr4_*` or `brcmf_chip_ca7_*` passive/active sequence.
pub struct Cr4<B: Bus> {
    bus: B,
    chip: Chip,
    arm: Core,
    cpu: Cpu,
    ram: Ram,
    used: bool,
}
impl<B: Bus> core::fmt::Debug for Cr4<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmCr4")
            .field("cpu", &self.cpu)
            .field("ram", &self.ram)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}
/// A refused claim or boot hands the bus back, so the retained owner can
/// reset and retry (or release) it instead of losing the function.
pub struct Refused<B: Bus> {
    pub error: Error,
    pub bus: B,
}
impl<B: Bus> core::fmt::Debug for Refused<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmRefused")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<B: Bus> Cr4<B> {
    /// Policy/identity admission precedes writes; actual cores come from
    /// EROM. Missing calibration policy is a software gate, not a fallback.
    pub fn claim(bus: B, pci: PciIdentity, profile: BoardProfile) -> Result<Self, Refused<B>> {
        Self::claim_checked(bus, |chip| profile.admits(chip, pci))
    }
    pub(super) fn claim_selected(
        bus: B,
        pci: PciIdentity,
        selection: &super::provision::Selection,
    ) -> Result<Self, Refused<B>> {
        let expected = selection.host().id;
        Self::claim_checked(bus, |chip| {
            // Family 3 additionally needs the Linux PCI/vendor admission of
            // the actual discovered chip and revision.
            let family = match selection.family() {
                super::provision::Family::Pcie43602 => true,
                super::provision::Family::PcieFullmac => {
                    chip_profile::admit(chip.id, chip.revision, &expected).is_some()
                }
                super::provision::Family::Sdio43439 => false,
            };
            family
                && expected.vendor == pci.vendor
                && expected.device == pci.device
                && expected.subsystem_vendor == pci.subsystem_vendor
                && expected.subsystem_id == pci.subsystem_device
                && selection.admits_chip(chip.id, chip.revision)
        })
    }
    fn claim_checked(mut bus: B, admitted: impl FnOnce(&Chip) -> bool) -> Result<Self, Refused<B>> {
        match Self::discover(&mut bus, admitted) {
            Ok((chip, arm, cpu, ram)) => Ok(Self {
                bus,
                chip,
                arm,
                cpu,
                ram,
                used: false,
            }),
            Err(error) => Err(Refused { error, bus }),
        }
    }
    fn discover(
        bus: &mut B,
        admitted: impl FnOnce(&Chip) -> bool,
    ) -> Result<(Chip, Core, Cpu, Ram), Error> {
        if bus.dma_enabled()? {
            return Err(Error::State);
        }
        let chip = Chip::discover(bus).map_err(Error::Chip)?;
        if !admitted(&chip) {
            return Err(Error::Board);
        }
        let profile = chip_profile::profile(chip.id, chip.revision).ok_or(Error::Unsupported)?;
        let only = |id: u16| {
            let mut cores = chip.cores.iter().copied().filter(move |c| c.id == id);
            match (cores.next(), cores.next()) {
                (Some(core), None) => Ok(Some(core)),
                (None, _) => Ok(None),
                _ => Err(Error::Unsupported),
            }
        };
        // Linux brcmf_chip_set_passive dispatches CR4 first, then CA7.
        let (cr4, ca7) = (only(chip::CORE_ARM_CR4)?, only(chip::CORE_ARM_CA7)?);
        let arm = match (profile.cpu, cr4, ca7) {
            (Cpu::Cr4, Some(arm), _) => arm,
            (Cpu::Ca7, None, Some(arm)) => arm,
            _ => return Err(Error::Unsupported),
        };
        // BCM43602 additionally resets SOCRAM at exit (pcie.c
        // brcmf_pcie_exit_download_state); CA7 sizes RAM from SYS_MEM.
        if chip.id == chip_profile::BRCM_CC_43602
            && chip.core(chip_profile::CORE_INTERNAL_MEM).is_none()
            || profile.cpu == Cpu::Ca7
                && (chip.core(chip_profile::CORE_SYS_MEM).is_none()
                    || chip.core(chip::CORE_D11).is_none())
        {
            return Err(Error::Unsupported);
        }
        // The ARM HALT survives reset while its local TCM remains accessible.
        let previous = bus.read32(arm.wrapper + 0x408).map_err(Error::Chip)?;
        if previous == u32::MAX {
            return Err(Error::Gone);
        }
        // brcmf_chip_disable_arm: keep only HALT, reset with HALT.
        Chip::reset_core(bus, arm, previous & 0x20, 0x20, 0x20).map_err(Error::Chip)?;
        let size = match profile.cpu {
            Cpu::Cr4 => {
                // brcmf_chip_cr4_set_passive: disable every D11 core.
                for core in chip
                    .cores
                    .iter()
                    .copied()
                    .filter(|c| c.id == chip::CORE_D11)
                {
                    Chip::disable_core(bus, core, 12, 4).map_err(Error::Chip)?;
                }
                cr4_ramsize(bus, arm)?
            }
            Cpu::Ca7 => {
                // brcmf_chip_ca7_set_passive: reset the first 80211 core
                // (PHYRESET|PHYCLOCKEN, PHYCLOCKEN, PHYCLOCKEN).
                let d11 = chip.core(chip::CORE_D11).ok_or(Error::Unsupported)?;
                Chip::reset_core(bus, d11, 12, 4, 4).map_err(Error::Chip)?;
                let sysmem = chip
                    .core(chip_profile::CORE_SYS_MEM)
                    .ok_or(Error::Unsupported)?;
                sysmem_ramsize(bus, sysmem)?
            }
        };
        let ram = Ram {
            base: profile.rambase,
            size,
        };
        if !(8..=chip_profile::MAX_MEMSIZE).contains(&size)
            || ram
                .base
                .checked_add(size)
                .filter(|&end| end <= bus.tcm_extent())
                .is_none()
        {
            return Err(Error::Extent);
        }
        Ok((chip, arm, profile.cpu, ram))
    }
    /// NVRAM is already board-selected single-device packed data, with
    /// Linux's final list NUL, alignment and token excluding token bytes.
    /// The bus that a successful claim retained, returned without booting.
    pub fn into_bus(self) -> B {
        self.bus
    }
    pub fn boot(mut self, firmware: &[u8], nvram: &[u8]) -> Result<Booted<B>, Refused<B>> {
        match self.download(firmware, nvram) {
            Ok((shared_address, shared)) => Ok(Booted {
                bus: self.bus,
                ram: self.ram,
                shared_address,
                shared,
                chip: self.chip,
            }),
            Err(error) => Err(Refused {
                error,
                bus: self.bus,
            }),
        }
    }
    fn download(&mut self, firmware: &[u8], nvram: &[u8]) -> Result<(u32, SharedInfo), Error> {
        if self.used {
            return Err(Error::State);
        }
        self.used = true;
        if firmware.len() < 4
            || firmware.len() > self.ram.size as usize
            || nvram.len() < 8
            || nvram.len() % 4 != 0
        {
            return Err(Error::Image);
        }
        let token = u32::from_le_bytes(nvram[nvram.len() - 4..].try_into().unwrap());
        let words = token & 0xffff;
        if (token >> 16) != (!words & 0xffff)
            || words as usize * 4 != nvram.len() - 4
            || firmware.len() + nvram.len() > self.ram.size as usize
        {
            return Err(Error::Image);
        }
        if let Some(size) = super::firmware::embedded_ramsize(firmware) {
            // Never let a firmware hint enlarge actual hardware RAM.
            if size < 8 || size > self.ram.size || firmware.len() + nvram.len() > size as usize {
                return Err(Error::Image);
            }
            self.ram.size = size;
        }
        // brcmf_pcie_enter_download_state, BCM43602 only: remove the
        // bank5/7 power-down before firmware writes.
        for bank in if self.chip.id == chip_profile::BRCM_CC_43602 {
            &[5u32, 7][..]
        } else {
            &[][..]
        } {
            self.bus
                .write32(self.arm.base + 0x40, *bank)
                .map_err(Error::Chip)?;
            self.bus
                .write32(self.arm.base + 0x4c, 0)
                .map_err(Error::Chip)?;
        }
        self.bus.write_tcm(self.ram.base, firmware)?;
        let tail = self.ram.base + self.ram.size - 4;
        self.bus.write_tcm(tail, &[0; 4])?;
        let nvram_address = self.ram.base + self.ram.size - nvram.len() as u32;
        self.bus.write_tcm(nvram_address, nvram)?;
        let sentinel = read32(&mut self.bus, tail)?;
        // brcmf_pcie_exit_download_state: BCM43602 resets SOCRAM first.
        if self.chip.id == chip_profile::BRCM_CC_43602 {
            let memory = self
                .chip
                .core(chip_profile::CORE_INTERNAL_MEM)
                .ok_or(Error::Unsupported)?;
            Chip::reset_core(&mut self.bus, memory, 0, 0, 0).map_err(Error::Chip)?;
        }
        // brcmf_pcie_buscore_activate writes the image's first reset vector
        // at TCM0; brcmf_chip_{cr4,ca7}_set_active then release the ARM.
        self.bus.write_tcm(0, &firmware[..4])?;
        Chip::reset_core(&mut self.bus, self.arm, 0x20, 0, 0).map_err(Error::Chip)?;
        let mut shared = sentinel;
        let mut failure = None;
        let ready = narf_scheduler::responsive_spin_until(
            || match read32(&mut self.bus, tail) {
                Ok(value) => {
                    shared = value;
                    value != sentinel
                }
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_ms(5_000),
        );
        if let Some(error) = failure {
            return Err(error);
        }
        if !ready {
            return Err(Error::Timeout);
        }
        if shared & 3 != 0 || !self.ram.contains(shared, 76) {
            return Err(Error::Metadata);
        }
        let mut bytes = [0; 76];
        self.bus.read_tcm(shared, &mut bytes)?;
        let info = SharedInfo::parse(&bytes).ok_or(Error::Metadata)?;
        // The runtime handles v5/v6 classic msgbuf and v7's wider D2H
        // completion items (Linux brcmf_ring_itemsize) over TCM indices.
        if !(5..=7).contains(&info.version)
            || super::msgbuf::completion_prefix(info.version, info.rx_dataoffset).is_none()
            || !self.ram.contains(info.ring_info_addr, 58)
            || !self.ram.contains(info.htod_mb_data_addr, 4)
            || !self.ram.contains(info.dtoh_mb_data_addr, 4)
        {
            return Err(Error::Metadata);
        }
        Ok((shared, info))
    }
}
/// `chip.c::brcmf_chip_tcm_ramsize`: CR4 A+B TCM banks.
fn cr4_ramsize(bus: &mut impl Bus, arm: Core) -> Result<u32, Error> {
    let capability = bus.read32(arm.base + 4).map_err(Error::Chip)?;
    if capability == u32::MAX {
        return Err(Error::Gone);
    }
    let banks = (capability & 15) + ((capability >> 4) & 15);
    if banks == 0 {
        return Err(Error::Unsupported);
    }
    let mut size = 0u32;
    for bank in 0..banks {
        bus.write32(arm.base + 0x40, bank).map_err(Error::Chip)?;
        let info = bus.read32(arm.base + 0x44).map_err(Error::Chip)?;
        if info == u32::MAX {
            return Err(Error::Gone);
        }
        let unit = if info & 0x200 != 0 { 1024 } else { 8192 };
        size = size
            .checked_add(((info & 0x7f) + 1) * unit)
            .ok_or(Error::Extent)?;
    }
    Ok(size)
}
/// `chip.c::brcmf_chip_sysmem_ramsize`: bring SYS_MEM up when it is not
/// (`brcmf_chip_ai_iscoreup`: ioctl CLK without FGC, reset released), then
/// sum `SRCI_SRNB` RAM banks through `bankidx` (0x10) / `bankinfo` (0x40).
fn sysmem_ramsize(bus: &mut impl Bus, sysmem: Core) -> Result<u32, Error> {
    let ioctl = bus.read32(sysmem.wrapper + 0x408).map_err(Error::Chip)?;
    let reset = bus.read32(sysmem.wrapper + 0x800).map_err(Error::Chip)?;
    if ioctl == u32::MAX || reset == u32::MAX {
        return Err(Error::Gone);
    }
    if ioctl & 3 != 1 || reset & 1 != 0 {
        Chip::reset_core(bus, sysmem, 0, 0, 0).map_err(Error::Chip)?;
    }
    let coreinfo = bus.read32(sysmem.base).map_err(Error::Chip)?;
    if coreinfo == u32::MAX {
        return Err(Error::Gone);
    }
    let banks = (coreinfo & 0xf0) >> 4;
    if banks == 0 {
        return Err(Error::Unsupported);
    }
    let mut size = 0u32;
    for bank in 0..banks {
        // SOCRAM_MEMTYPE_RAM << SOCRAM_BANKIDX_MEMTYPE_SHIFT is zero.
        bus.write32(sysmem.base + 0x10, bank).map_err(Error::Chip)?;
        let info = bus.read32(sysmem.base + 0x40).map_err(Error::Chip)?;
        if info == u32::MAX {
            return Err(Error::Gone);
        }
        size = size
            .checked_add(((info & 0x7f) + 1) * 8192)
            .ok_or(Error::Extent)?;
    }
    Ok(size)
}
fn read32(bus: &mut impl Bus, address: u32) -> Result<u32, Error> {
    let mut bytes = [0; 4];
    bus.read_tcm(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Pack only an explicitly selected single-board calibration file. Multi-device
/// selectors need an independent platform policy and are deliberately rejected.
pub fn pack_nvram(text: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    if text.len() > super::firmware::NVRAM_MAX_SIZE || text.is_empty() {
        return Err(Error::Image);
    }
    let parsed = super::firmware::parse_nvram(text);
    if parsed.multi_dev_v1
        || parsed.multi_dev_v2
        || !parsed.boardrev_seen
        || parsed.bytes.is_empty()
    {
        return Err(Error::Board);
    }
    let mut bytes = parsed.bytes;
    bytes.push(0); // final list terminator is separate from last record NUL
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    if bytes.len() > super::firmware::NVRAM_MAX_SIZE {
        return Err(Error::Image);
    }
    let words = (bytes.len() / 4) as u32;
    let token = (!words & 0xffff) << 16 | words;
    bytes.extend_from_slice(&token.to_le_bytes());
    Ok(bytes)
}
