//! Bounded AI/AMBA chip discovery over the PCIe BAR0 backplane window.
//!
//! Linux reference: `brcmfmac/chip.c::brcmf_chip_dmp_erom_scan` and
//! `brcmf_chip_dmp_get_regaddr`. Discovery does not halt a CPU, enable
//! bus mastering, or infer a RAM layout from the PCI device ID.

use alloc::vec::Vec;

pub const ENUM_BASE: u32 = 0x1800_0000;
const BACKPLANE_END: u32 = 0x2000_0000;
const EROM_POINTER: u32 = ENUM_BASE + 0xfc;
const MAX_EROM_WORDS: usize = 1024;
const MAX_CORES: usize = 64;

pub const CORE_CHIPCOMMON: u16 = 0x800;
pub const CORE_D11: u16 = 0x812;
pub const CORE_PCIE2: u16 = 0x83c;
pub const CORE_ARM_CR4: u16 = 0x83e;
pub const CORE_ARM_CA7: u16 = 0x847;
const CORE_PMU: u16 = 0x827;
const CORE_GCI: u16 = 0x840;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Gone,
    Address,
    UnsupportedInterconnect,
    MalformedErom,
    EromLimit,
    MissingCore,
    Timeout,
}

/// Exclusive, serialized register access. Implementations must preserve each
/// window-select/read or window-select/write pair against concurrent users.
pub trait Backplane {
    fn read32(&mut self, address: u32) -> Result<u32, Error>;
    fn write32(&mut self, address: u32, value: u32) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Core {
    pub id: u16,
    pub revision: u8,
    pub base: u32,
    pub wrapper: u32,
}

#[derive(Debug)]
pub struct Chip {
    pub id: u16,
    pub revision: u8,
    pub cores: Vec<Core>,
}

/// The register layout changes at PCIe core revision 64, independently of
/// the firmware shared-memory version. Offsets are relative to that core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcieRegisters {
    pub interrupt_mask: u32,
    pub mailbox_status: u32,
    pub mailbox_mask: u32,
}

pub const fn pcie_registers(revision: u8) -> PcieRegisters {
    if revision >= 64 {
        PcieRegisters {
            interrupt_mask: 0xc14,
            mailbox_status: 0xc30,
            mailbox_mask: 0xc34,
        }
    } else {
        PcieRegisters {
            interrupt_mask: 0x24,
            mailbox_status: 0x48,
            mailbox_mask: 0x4c,
        }
    }
}

pub fn valid_address(address: u32) -> bool {
    (ENUM_BASE..BACKPLANE_END).contains(&address) && address & 3 == 0
}

struct Erom {
    next: u32,
    end: u32,
    remaining: usize,
    saved: Option<u32>,
}

impl Erom {
    fn read(&mut self, bus: &mut impl Backplane) -> Result<u32, Error> {
        if let Some(word) = self.saved.take() {
            return Ok(word);
        }
        if self.remaining == 0 || self.next >= self.end {
            return Err(Error::EromLimit);
        }
        self.remaining -= 1;
        let word = bus.read32(self.next)?;
        self.next = self.next.checked_add(4).ok_or(Error::Address)?;
        if word == u32::MAX {
            return Err(Error::Gone);
        }
        Ok(word)
    }

    fn unread(&mut self, word: u32) {
        debug_assert!(self.saved.is_none());
        self.saved = Some(word);
    }
}

fn descriptor(word: u32) -> u8 {
    let tag = (word & 15) as u8;
    if tag & !8 == 5 {
        5
    } else {
        tag
    }
}

/// Read the component's register and wrapper regions, consuming extended
/// address/size words even for regions that this 32-bit bus cannot address.
fn regions(bus: &mut impl Backplane, rom: &mut Erom) -> Result<(u32, u32), Error> {
    let first = rom.read(bus)?;
    let wrapper_kind = match descriptor(first) {
        3 => 3, // A master port uses its master wrapper.
        5 => {
            rom.unread(first);
            2 // Otherwise the component uses a slave wrapper.
        }
        _ => {
            rom.unread(first);
            return Ok((0, 0));
        }
    };
    let (mut base, mut wrapper) = (0, 0);
    loop {
        let word = rom.read(bus)?;
        match descriptor(word) {
            1 | 15 => {
                rom.unread(word);
                return Ok((base, wrapper));
            }
            5 => {}
            _ => continue,
        }
        let upper = if word & 8 != 0 { rom.read(bus)? } else { 0 };
        let size_type = (word >> 4) & 3;
        if size_type == 3 {
            let size = rom.read(bus)?;
            if size & 8 != 0 {
                let _ = rom.read(bus)?;
            }
        }
        // Linux only selects 4/8-KiB register regions. Never truncate a
        // nonzero high address word into the 32-bit register window.
        if upper != 0 || size_type > 1 {
            continue;
        }
        let address = word & 0xffff_f000;
        if !valid_address(address) {
            return Err(Error::Address);
        }
        let kind = (word >> 6) & 3;
        if kind == 0 && base == 0 {
            base = address;
        } else if kind == wrapper_kind && wrapper == 0 {
            wrapper = address;
        }
        if base != 0 && wrapper != 0 {
            return Ok((base, wrapper));
        }
    }
}

fn wait_register(
    bus: &mut impl Backplane,
    address: u32,
    mask: u32,
    wanted: u32,
    us: u64,
) -> Result<(), Error> {
    let mut failure = None;
    let complete = narf_scheduler::responsive_spin_until(
        || match bus.read32(address) {
            Ok(u32::MAX) => {
                failure = Some(Error::Gone);
                true
            }
            Ok(value) => value & mask == wanted,
            Err(error) => {
                failure = Some(error);
                true
            }
        },
        narf_time::Deadline::after_us(us),
    );
    if let Some(error) = failure {
        Err(error)
    } else if complete {
        Ok(())
    } else {
        Err(Error::Timeout)
    }
}

impl Chip {
    pub fn core(&self, id: u16) -> Option<Core> {
        self.cores.iter().copied().find(|core| core.id == id)
    }

    pub fn discover(bus: &mut impl Backplane) -> Result<Self, Error> {
        let chip = Self::discover_ai(bus)?;
        if chip
            .cores
            .iter()
            .filter(|core| core.id == CORE_PCIE2)
            .count()
            != 1
        {
            return Err(Error::MissingCore);
        }
        Ok(chip)
    }

    /// AI discovery shared with SDIO CM3 parts. The PCIe entry additionally
    /// requires one PCIe2 core; an SDIO caller validates its own core profile.
    pub fn discover_ai(bus: &mut impl Backplane) -> Result<Self, Error> {
        let identity = bus.read32(ENUM_BASE)?;
        if identity == u32::MAX || identity & 0xffff == 0 {
            return Err(Error::Gone);
        }
        // PCIe FullMAC parts use AI. The older Sonics/4329 discovery
        // algorithm is specific to the SDIO family.
        if identity >> 28 != 1 {
            return Err(Error::UnsupportedInterconnect);
        }
        let start = bus.read32(EROM_POINTER)?;
        if !valid_address(start) {
            return Err(Error::Address);
        }
        let mut rom = Erom {
            next: start,
            end: start
                .saturating_add((MAX_EROM_WORDS * 4) as u32)
                .min(BACKPLANE_END),
            remaining: MAX_EROM_WORDS,
            saved: None,
        };
        let mut chip = Self {
            id: identity as u16,
            revision: ((identity >> 16) & 15) as u8,
            cores: Vec::new(),
        };
        loop {
            let first = rom.read(bus)?;
            if descriptor(first) == 15 {
                break;
            }
            if descriptor(first) != 1 {
                continue;
            }
            let second = rom.read(bus)?;
            if descriptor(second) != 1 {
                return Err(Error::MalformedErom);
            }
            let id = ((first >> 8) & 0xfff) as u16;
            let master_wrappers = (second >> 14) & 31;
            let slave_wrappers = (second >> 19) & 31;
            if master_wrappers + slave_wrappers == 0 && !matches!(id, CORE_PMU | CORE_GCI) {
                continue;
            }
            let (base, wrapper) = regions(bus, &mut rom)?;
            if base == 0 || (wrapper == 0 && !matches!(id, CORE_PMU | CORE_GCI)) {
                return Err(Error::MalformedErom);
            }
            if chip.cores.len() == MAX_CORES {
                return Err(Error::EromLimit);
            }
            // Multiple D11 cores are legitimate. Register regions may
            // not alias: later writes must name the discovered core.
            if chip.cores.iter().any(|core| core.base == base) {
                return Err(Error::MalformedErom);
            }
            chip.cores.push(Core {
                id,
                revision: (second >> 24) as u8,
                base,
                wrapper,
            });
        }
        if chip
            .core(CORE_CHIPCOMMON)
            .is_none_or(|core| core.base != ENUM_BASE)
        {
            return Err(Error::MissingCore);
        }
        Ok(chip)
    }

    /// AI core-disable contract from Linux brcmf_chip_ai_coredisable.
    pub fn disable_core(
        bus: &mut impl Backplane,
        core: Core,
        before: u32,
        reset: u32,
    ) -> Result<(), Error> {
        if !valid_address(core.wrapper) || core.wrapper & 0xfff != 0 {
            return Err(Error::Address);
        }
        let control = core.wrapper + 0x408;
        let reset_control = core.wrapper + 0x800;
        let state = bus.read32(reset_control)?;
        if state == u32::MAX {
            return Err(Error::Gone);
        }
        if state & 1 == 0 {
            bus.write32(control, before | 3)?;
            let _ = bus.read32(control)?;
            bus.write32(reset_control, 1)?;
            let _ =
                narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(10));
            wait_register(bus, reset_control, 1, 1, 300)?;
        }
        bus.write32(control, reset | 3)?;
        let _ = bus.read32(control)?;
        Ok(())
    }

    /// Reset release is checked before removing forced clocks. Failure is
    /// terminal for the calling owner; firmware must not run on a guessed core.
    pub fn reset_core(
        bus: &mut impl Backplane,
        core: Core,
        before: u32,
        reset: u32,
        after: u32,
    ) -> Result<(), Error> {
        Self::disable_core(bus, core, before, reset)?;
        bus.write32(core.wrapper + 0x800, 0)?;
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(40));
        wait_register(bus, core.wrapper + 0x800, 1, 0, 3_000)?;
        bus.write32(core.wrapper + 0x408, after | 1)?;
        let _ = bus.read32(core.wrapper + 0x408)?;
        Ok(())
    }

    /// Mask both interrupt paths before acknowledging the sampled mailbox
    /// status. This parks interrupts only; it is not an ARM/chip reset.
    pub fn park_pcie(&self, bus: &mut impl Backplane) -> Result<(), Error> {
        let core = self.core(CORE_PCIE2).ok_or(Error::MissingCore)?;
        let registers = pcie_registers(core.revision);
        bus.write32(core.base + registers.interrupt_mask, 0)?;
        bus.write32(core.base + registers.mailbox_mask, 0)?;
        let pending = bus.read32(core.base + registers.mailbox_status)?;
        if pending == u32::MAX {
            return Err(Error::Gone);
        }
        bus.write32(core.base + registers.mailbox_status, pending)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "chip/tests.rs"]
mod tests;
