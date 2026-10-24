//! RTW88 factory identity from the sparse physical EFUSE stream.
//!
//! Ported from Linux `rtw88/efuse.c::{rtw_dump_physical_efuse_map,
//! rtw_dump_logical_efuse_map}` and the PCIe maps in `rtw8821c.h`,
//! `rtw8822b.h`, and `rtw8822c.h`. Physical bytes are programming records,
//! not a direct-addressed logical EEPROM image.

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::regs::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EfuseError {
    /// The hardware did not set the completion flag within the budget.
    Timeout,
    /// No valid unicast factory MAC was programmed.
    MacUninitialized,
    /// The PCI ID has no known physical/logical EFUSE geometry.
    UnsupportedChip,
    /// A programming record was truncated or targeted outside the logical map.
    MalformedMap,
}

const EFUSE_POLL_MS: u64 = 5;

/// Original RTL8822CE logical factory map, retained from the same physical
/// read that established the PCI MAC. Factory data selects hardware tables;
/// it does not authenticate a country or grant a conducted-power limit.
#[derive(Clone)]
pub struct Factory {
    logical: [u8; 768],
    trims: [u8; 19],
}
// Linux rtw8822c.h PPG_* locations. These are raw protected OTP cells,
// never sparse-map programming records: thermalA/B,2G gainL/M/H,
// 5G gainA/B (low1,low2,mid1,mid2,high1), PA bias2GA/B then5GA/B.
pub(super) const TRIM_ADDRESSES: [u16; 19] = [
    0x1ef, 0x1b0, 0x1d4, 0x1ee, 0x1d2, 0x1ec, 0x1e8, 0x1e4, 0x1e0, 0x1dc, 0x1eb, 0x1e7, 0x1e3,
    0x1df, 0x1db, 0x1d6, 0x1d5, 0x1d8, 0x1d7,
];
impl core::fmt::Debug for Factory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822ceFactory")
            .field("mac", &self.mac())
            .field("rfe", &self.rfe())
            .field("crystal", &self.crystal())
            .field("thermal", &self.thermal())
            .finish_non_exhaustive()
    }
}
impl Factory {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn for_test(logical: [u8; 768]) -> Result<Self, EfuseError> {
        let factory = Self {
            logical,
            trims: [255; 19],
        };
        if !mac_is_valid(factory.mac()) {
            return Err(EfuseError::MacUninitialized);
        }
        Ok(factory)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn for_test_with_trims(
        logical: [u8; 768],
        trims: [u8; 19],
    ) -> Result<Self, EfuseError> {
        let mut factory = Self::for_test(logical)?;
        factory.trims = trims;
        Ok(factory)
    }
    pub fn mac(&self) -> [u8; 6] {
        self.logical[0x120..0x126].try_into().unwrap()
    }
    pub fn rfe(&self) -> u8 {
        self.logical[0xca]
    }
    /// Raw OTP value. An erased value remains erased; no default is supplied.
    pub fn crystal(&self) -> u8 {
        self.logical[0xb9]
    }
    pub fn board_option(&self) -> u8 {
        self.logical[0xc1]
    }
    pub fn bt_setting(&self) -> u8 {
        self.logical[0xc3]
    }
    pub fn thermal(&self) -> [u8; 2] {
        self.logical[0xd0..0xd2].try_into().unwrap()
    }
    pub fn channel_plan(&self) -> u8 {
        self.logical[0xb8]
    }
    pub fn country(&self) -> [u8; 2] {
        self.logical[0xcb..0xcd].try_into().unwrap()
    }
    pub(super) fn logical(&self) -> &[u8; 768] {
        &self.logical
    }
    pub(super) fn trims(&self) -> &[u8; 19] {
        &self.trims
    }
    pub(super) fn power_path(&self, path: u8) -> Option<&[u8]> {
        if path > 3 {
            return None;
        }
        let at = 0x10 + usize::from(path) * 42;
        Some(&self.logical[at..at + 42])
    }
}

/// Sizes/protected tails from the Linux per-chip `rtw_chip_info` tables.
#[derive(Clone, Copy, Debug)]
struct Geometry {
    readable: usize,
    logical: usize,
    mac: usize,
    ldo_addr: u64,
    ldo_mask: u8,
}

fn geometry(did: u16) -> Result<Geometry, EfuseError> {
    let (readable, logical, mac, ldo_addr, ldo_mask) = match did {
        RTL_DEV_8821CE => (512 - 96, 512, 0xd0, REG_LDO_EFUSE_CTRL + 3, 1 << 7),
        RTL_DEV_8822BE => (1024 - 96, 768, 0xd0, REG_LDO_EFUSE_CTRL + 3, 1 << 7),
        RTL_DEV_8822CE => (512 - 124, 768, 0x120, REG_ANAPARLDO_POW_MAC, 1),
        _ => return Err(EfuseError::UnsupportedChip),
    };
    Ok(Geometry {
        readable,
        logical,
        mac,
        ldo_addr,
        ldo_mask,
    })
}

/// Private register seam: the production path and trace-based smokes run the
/// same access sequence, including the hardware completion predicate.
pub(super) trait EfuseIo {
    fn read8(&mut self, addr: u64) -> u8;
    fn write8(&mut self, addr: u64, value: u8);
    fn read32(&mut self, addr: u64) -> u32;
    fn write32(&mut self, addr: u64, value: u32);
}

struct MmioEfuse<'a>(&'a MmioRegion);

impl EfuseIo for MmioEfuse<'_> {
    fn read8(&mut self, addr: u64) -> u8 {
        // SAFETY: read_mac's caller guarantees exclusive, powered BAR2 control access.
        unsafe { self.0.read8(addr) }
    }
    fn write8(&mut self, addr: u64, value: u8) {
        // SAFETY: as above; only known EFUSE/LDO registers are supplied.
        unsafe { self.0.write8(addr, value) }
    }
    fn read32(&mut self, addr: u64) -> u32 {
        // SAFETY: as above; only known EFUSE registers are supplied.
        unsafe { self.0.read32(addr) }
    }
    fn write32(&mut self, addr: u64, value: u32) {
        // SAFETY: as above; only known EFUSE registers are supplied.
        unsafe { self.0.write32(addr, value) }
    }
}

fn read_physical(io: &mut impl EfuseIo, chip: Geometry, out: &mut [u8]) -> Result<(), EfuseError> {
    // Read bank 0 (Wi-Fi), with the programming LDO *disabled*. 8822C
    // controls LDO25 through ANAPARLDO instead of the 8821C/8822B register.
    let bank = io.read32(REG_LDO_EFUSE_CTRL);
    io.write32(REG_LDO_EFUSE_CTRL, bank & !EFUSE_BANK_MASK);
    let ldo = io.read8(chip.ldo_addr);
    io.write8(chip.ldo_addr, ldo & !chip.ldo_mask);

    let mut control = io.read32(REG_EFUSE_CTRL);
    for (addr, byte) in out.iter_mut().enumerate() {
        control &= !(EFUSE_CTRL_DATA_MASK
            | (EFUSE_CTRL_ADDR_MASK << EFUSE_CTRL_ADDR_SHIFT)
            | EFUSE_CTRL_VALID);
        control |= (addr as u32) << EFUSE_CTRL_ADDR_SHIFT;
        // Writing a *clear* flag starts the read; hardware sets it on
        // completion. Preserve unrelated control bits between transactions.
        io.write32(REG_EFUSE_CTRL, control);
        let done = narf_scheduler::responsive_spin_until(
            || {
                control = io.read32(REG_EFUSE_CTRL);
                control & EFUSE_CTRL_VALID != 0
            },
            Deadline::after_ms(EFUSE_POLL_MS),
        );
        if !done {
            return Err(EfuseError::Timeout);
        }
        *byte = (control & EFUSE_CTRL_DATA_MASK) as u8;
    }
    Ok(())
}
fn read_trims(io: &mut impl EfuseIo, chip: Geometry) -> Result<[u8; 19], EfuseError> {
    let bank = io.read32(REG_LDO_EFUSE_CTRL);
    io.write32(REG_LDO_EFUSE_CTRL, bank & !EFUSE_BANK_MASK);
    let ldo = io.read8(chip.ldo_addr);
    io.write8(chip.ldo_addr, ldo & !chip.ldo_mask);
    let mut control = io.read32(REG_EFUSE_CTRL);
    let mut trims = [255; 19];
    for (address, byte) in TRIM_ADDRESSES.into_iter().zip(&mut trims) {
        control &= !(EFUSE_CTRL_DATA_MASK
            | (EFUSE_CTRL_ADDR_MASK << EFUSE_CTRL_ADDR_SHIFT)
            | EFUSE_CTRL_VALID);
        control |= u32::from(address) << EFUSE_CTRL_ADDR_SHIFT;
        io.write32(REG_EFUSE_CTRL, control);
        if !narf_scheduler::responsive_spin_until(
            || {
                control = io.read32(REG_EFUSE_CTRL);
                control & EFUSE_CTRL_VALID != 0
            },
            Deadline::after_ms(EFUSE_POLL_MS),
        ) {
            return Err(EfuseError::Timeout);
        }
        *byte = (control & EFUSE_CTRL_DATA_MASK) as u8;
    }
    Ok(trims)
}

/// Decode one-/two-byte headers, sparse word enables, and later word
/// overrides. Protected physical bytes must be excluded by the caller.
pub(crate) fn decode_map(physical: &[u8], logical: &mut [u8]) -> Result<(), EfuseError> {
    logical.fill(0xff);
    let mut cursor = 0;
    while cursor < physical.len() {
        let first = physical[cursor];
        cursor += 1;
        if first == 0xff {
            break;
        }
        let (block, word_enable) = if first & 0x1f == 0x0f {
            let second = *physical.get(cursor).ok_or(EfuseError::MalformedMap)?;
            cursor += 1;
            if second == 0xff {
                break;
            }
            (
                (((second & 0xf0) >> 1) | (first >> 5)) as usize,
                second & 0x0f,
            )
        } else {
            ((first >> 4) as usize, first & 0x0f)
        };

        for word in 0..4 {
            if word_enable & (1 << word) != 0 {
                continue;
            }
            let target = block * 8 + word * 2;
            let source = physical
                .get(cursor..cursor + 2)
                .ok_or(EfuseError::MalformedMap)?;
            logical
                .get_mut(target..target + 2)
                .ok_or(EfuseError::MalformedMap)?
                .copy_from_slice(source);
            cursor += 2;
        }
    }
    Ok(())
}

pub(super) fn read_mac_with(
    io: &mut impl EfuseIo,
    did: u16,
) -> Result<[u8; MAC_ADDR_LEN], EfuseError> {
    let chip = geometry(did)?;
    let logical = read_map_with(io, chip)?;
    let mut mac = [0; MAC_ADDR_LEN];
    mac.copy_from_slice(&logical[chip.mac..chip.mac + MAC_ADDR_LEN]);
    if !mac_is_valid(mac) {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(mac)
}
fn read_map_with(io: &mut impl EfuseIo, chip: Geometry) -> Result<[u8; 768], EfuseError> {
    // Read only the unprotected programming area. Protected bytes cannot
    // masquerade as sparse programming records or radio calibration.
    let mut physical = [0xff; 1024];
    read_physical(io, chip, &mut physical[..chip.readable])?;
    let mut logical = [0xff; 768];
    decode_map(&physical[..chip.readable], &mut logical[..chip.logical])?;
    Ok(logical)
}
pub(super) fn read_factory_with(io: &mut impl EfuseIo, did: u16) -> Result<Factory, EfuseError> {
    if did != RTL_DEV_8822CE {
        return Err(EfuseError::UnsupportedChip);
    }
    let chip = geometry(did)?;
    let logical = read_map_with(io, chip)?;
    if !mac_is_valid(logical[0x120..0x126].try_into().unwrap()) {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(Factory {
        logical,
        trims: read_trims(io, chip)?,
    })
}
/// # Safety
/// Same powered, exclusive BAR2 ownership contract as `read_mac`.
pub unsafe fn read_factory(mmio: &MmioRegion, did: u16) -> Result<Factory, EfuseError> {
    read_factory_with(&mut MmioEfuse(mmio), did)
}

/// Read and decode the chip-specific PCIe factory MAC.
///
/// # Safety
/// Caller owns the powered BAR2 register mapping exclusively. The mapping must cover
/// the EFUSE control (0x30), bank/LDO (0x34), and 8822C LDO (0x29) registers.
pub unsafe fn read_mac(mmio: &MmioRegion, did: u16) -> Result<[u8; MAC_ADDR_LEN], EfuseError> {
    read_mac_with(&mut MmioEfuse(mmio), did)
}

/// A factory station identity must be nonzero and unicast.
pub fn mac_is_valid(mac: [u8; MAC_ADDR_LEN]) -> bool {
    mac != [0; MAC_ADDR_LEN] && mac[0] & 1 == 0
}
