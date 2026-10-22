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

/// Decode one-/two-byte headers, sparse word enables, and later word
/// overrides. Protected physical bytes must be excluded by the caller.
pub(super) fn decode_map(physical: &[u8], logical: &mut [u8]) -> Result<(), EfuseError> {
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
    // Reject unknown geometry before touching hardware. Read only the
    // unprotected programming area; the protected tail is not map records.
    let chip = geometry(did)?;
    let mut physical = [0xff; 1024];
    read_physical(io, chip, &mut physical[..chip.readable])?;
    let mut logical = [0xff; 768];
    decode_map(&physical[..chip.readable], &mut logical[..chip.logical])?;
    let mut mac = [0; MAC_ADDR_LEN];
    mac.copy_from_slice(&logical[chip.mac..chip.mac + MAC_ADDR_LEN]);
    if !mac_is_valid(mac) {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(mac)
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
