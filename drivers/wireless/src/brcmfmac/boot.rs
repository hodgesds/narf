// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned BCM43602 CR4 boot, staged against Linux brcmfmac/{chip,pcie}.c.
//! No DMA or station admission: this hands validated firmware metadata to
//! the retained common-ring owner. Board calibration is selected explicitly.
use super::chip::{self, Backplane, Chip, Core};
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
        self.chip == 43602
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
pub struct Cr4<B: Bus> {
    bus: B,
    chip: Chip,
    arm: Core,
    ram: Ram,
    used: bool,
}
impl<B: Bus> core::fmt::Debug for Cr4<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmCr4")
            .field("ram", &self.ram)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}
impl<B: Bus> Cr4<B> {
    /// Policy/identity admission precedes writes; actual cores come from
    /// EROM. Missing calibration policy is a software gate, not a fallback.
    pub fn claim(bus: B, pci: PciIdentity, profile: BoardProfile) -> Result<Self, Error> {
        Self::claim_checked(bus, |chip| profile.admits(chip, pci))
    }
    pub(super) fn claim_selected(
        bus: B,
        pci: PciIdentity,
        selection: &super::provision::Selection,
    ) -> Result<Self, Error> {
        let expected = selection.host().id;
        Self::claim_checked(bus, |chip| {
            selection.family() == super::provision::Family::Pcie43602
                && expected.vendor == pci.vendor
                && expected.device == pci.device
                && expected.subsystem_vendor == pci.subsystem_vendor
                && expected.subsystem_id == pci.subsystem_device
                && selection.admits_chip(chip.id, chip.revision)
        })
    }
    fn claim_checked(mut bus: B, admitted: impl FnOnce(&Chip) -> bool) -> Result<Self, Error> {
        if bus.dma_enabled()? {
            return Err(Error::State);
        }
        let chip = Chip::discover(&mut bus).map_err(Error::Chip)?;
        if !admitted(&chip) {
            return Err(Error::Board);
        }
        let mut arms = chip
            .cores
            .iter()
            .copied()
            .filter(|c| c.id == chip::CORE_ARM_CR4);
        let arm = arms.next().ok_or(Error::Unsupported)?;
        if arms.next().is_some() || chip.core(0x80e).is_none() {
            return Err(Error::Unsupported);
        }
        // CR4 HALT survives reset while its local TCM remains accessible.
        let previous = bus.read32(arm.wrapper + 0x408).map_err(Error::Chip)?;
        if previous == u32::MAX {
            return Err(Error::Gone);
        }
        Chip::reset_core(&mut bus, arm, previous & 0x20, 0x20, 0x20).map_err(Error::Chip)?;
        for core in chip
            .cores
            .iter()
            .copied()
            .filter(|c| c.id == chip::CORE_D11)
        {
            Chip::disable_core(&mut bus, core, 12, 4).map_err(Error::Chip)?;
        }
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
        let ram = Ram {
            base: 0x180000,
            size,
        };
        if !(8..=4 * 1024 * 1024).contains(&size)
            || ram
                .base
                .checked_add(size)
                .filter(|&end| end <= bus.tcm_extent())
                .is_none()
        {
            return Err(Error::Extent);
        }
        Ok(Self {
            bus,
            chip,
            arm,
            ram,
            used: false,
        })
    }
    /// NVRAM is already board-selected single-device packed data, with
    /// Linux's final list NUL, alignment and token excluding token bytes.
    pub fn boot(mut self, firmware: &[u8], nvram: &[u8]) -> Result<Booted<B>, Error> {
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
        // BCM43602 quirk: remove bank5/7 power-down before firmware writes.
        for bank in [5, 7] {
            self.bus
                .write32(self.arm.base + 0x40, bank)
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
        let memory = self.chip.core(0x80e).ok_or(Error::Unsupported)?;
        Chip::reset_core(&mut self.bus, memory, 0, 0, 0).map_err(Error::Chip)?;
        // Linux PCIe activate writes the image's first reset vector at TCM0.
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
        // First runtime handles v5/v6 classic msgbuf and TCM indices. No v7
        // admission until its completion geometry has a real runtime owner.
        if !(5..=6).contains(&info.version)
            || info.rx_dataoffset != 0
            || !self.ram.contains(info.ring_info_addr, 58)
            || !self.ram.contains(info.htod_mb_data_addr, 4)
            || !self.ram.contains(info.dtoh_mb_data_addr, 4)
        {
            return Err(Error::Metadata);
        }
        Ok(Booted {
            bus: self.bus,
            ram: self.ram,
            shared_address: shared,
            shared: info,
            chip: self.chip,
        })
    }
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
