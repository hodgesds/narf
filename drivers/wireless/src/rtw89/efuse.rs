//! AX factory identity through the DDV EFUSE read/power lifecycle.
//!
//! Linux `rtw89/efuse.c` defines DDV power-cut sequencing and two-byte
//! sparse records. PCI MAC is at logical 0x400 in the complete 8852A/B/C
//! and 8851B maps, rather than at offset zero of the nested PCI substruct.

use super::mac::{ChipId, B_AX_EF_ADDR_SHIFT, B_AX_EF_RDY, R_AX_EFUSE_CTRL, R_AX_EFUSE_CTRL_1};
use narf_bus::MmioRegion;
use narf_time::Deadline;

pub const MAC_ADDR_LEN: usize = 6;
const PHYSICAL_SIZE: usize = 1216;
const SECURITY_CONTROL_SIZE: usize = 4;
pub const EFUSE_MAC_OFFSET: usize = 0x400;
const REG_PMC_DBG_CTRL2: u64 = 0xcc;
const REG_SYS_ISO_CTRL: u64 = 0;
const WRITE_MASK: u8 = 1 << 2;
const POWER_14: u16 = 1 << 14;
const POWER_15: u16 = 1 << 15;
const ISO_CORE: u16 = 1 << 8;
const BURST: u32 = 1 << 19;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfuseError {
    Timeout,
    MacUninitialized,
    UnsupportedChip,
    MalformedMap,
    BankSwitch,
}

pub(super) trait Io {
    fn read8(&mut self, addr: u64) -> u8;
    fn write8(&mut self, addr: u64, value: u8);
    fn read16(&mut self, addr: u64) -> u16;
    fn write16(&mut self, addr: u64, value: u16);
    fn read32(&mut self, addr: u64) -> u32;
    fn write32(&mut self, addr: u64, value: u32);
    fn delay_us(&mut self, us: u64) {
        narf_scheduler::responsive_spin_until(|| false, Deadline::after_us(us));
    }
}
struct Mmio<'a>(&'a MmioRegion);
impl Io for Mmio<'_> {
    fn read8(&mut self, a: u64) -> u8 {
        // SAFETY: read_mac's owned-register contract.
        unsafe { self.0.read8(a) }
    }
    fn write8(&mut self, a: u64, v: u8) {
        // SAFETY: same; known control offset.
        unsafe { self.0.write8(a, v) }
    }
    fn read16(&mut self, a: u64) -> u16 {
        // SAFETY: same.
        unsafe { self.0.read16(a) }
    }
    fn write16(&mut self, a: u64, v: u16) {
        // SAFETY: same.
        unsafe { self.0.write16(a, v) }
    }
    fn read32(&mut self, a: u64) -> u32 {
        // SAFETY: same.
        unsafe { self.0.read32(a) }
    }
    fn write32(&mut self, a: u64, v: u32) {
        // SAFETY: same.
        unsafe { self.0.write32(a, v) }
    }
}

pub(super) fn decode_map(raw: &[u8], logical: &mut [u8]) -> Result<(), EfuseError> {
    if raw.len() < 2 * SECURITY_CONTROL_SIZE {
        return Err(EfuseError::MalformedMap);
    }
    logical.fill(0xff);
    let mut cursor = SECURITY_CONTROL_SIZE;
    let end = raw.len() - SECURITY_CONTROL_SIZE;
    while cursor < end {
        let first = raw[cursor];
        if first == 0xff {
            break;
        }
        let second = *raw
            .get(cursor + 1)
            .filter(|_| cursor + 1 < end)
            .ok_or(EfuseError::MalformedMap)?;
        if second == 0xff {
            break;
        }
        cursor += 2;
        let block = (((first & 0xf) as usize) << 4) | ((second >> 4) as usize);
        for word in 0..4 {
            if second & (1 << word) != 0 {
                continue;
            }
            if cursor + 2 > end {
                return Err(EfuseError::MalformedMap);
            }
            let target = block * 8 + word * 2;
            logical
                .get_mut(target..target + 2)
                .ok_or(EfuseError::MalformedMap)?
                .copy_from_slice(&raw[cursor..cursor + 2]);
            cursor += 2;
        }
    }
    Ok(())
}

pub(super) fn read_mac_with(
    io: &mut impl Io,
    chip: ChipId,
    cut: u8,
) -> Result<[u8; 6], EfuseError> {
    let logical_size = match chip {
        ChipId::Rtl8852A => 1536,
        ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B => 2048,
        ChipId::Rtl8922A => return Err(EfuseError::UnsupportedChip),
    };
    if chip == ChipId::Rtl8852A {
        let value = io.read32(R_AX_EFUSE_CTRL_1);
        io.write32(R_AX_EFUSE_CTRL_1, value & !(3 << 8));
        if io.read32(R_AX_EFUSE_CTRL_1) & (3 << 8) != 0 {
            return Err(EfuseError::BankSwitch);
        }
    } else {
        let value = io.read8(REG_PMC_DBG_CTRL2);
        io.write8(REG_PMC_DBG_CTRL2, value | WRITE_MASK);
        let value = io.read16(REG_SYS_ISO_CTRL);
        io.write16(REG_SYS_ISO_CTRL, value | POWER_14);
        io.delay_us(1000);
        let value = io.read16(REG_SYS_ISO_CTRL);
        io.write16(REG_SYS_ISO_CTRL, (value | POWER_15) & !ISO_CORE);
        if chip == ChipId::Rtl8852B && cut == 0 {
            let value = io.read32(R_AX_EFUSE_CTRL_1);
            io.write32(R_AX_EFUSE_CTRL_1, value | BURST);
        }
    }
    let mut raw = [0xff; PHYSICAL_SIZE];
    let result = (|| {
        for (addr, byte) in raw.iter_mut().enumerate() {
            io.write32(R_AX_EFUSE_CTRL, (addr as u32) << B_AX_EF_ADDR_SHIFT);
            let mut value = 0;
            if !narf_scheduler::responsive_spin_until(
                || {
                    value = io.read32(R_AX_EFUSE_CTRL);
                    value & B_AX_EF_RDY != 0
                },
                Deadline::after_ms(50),
            ) {
                return Err(EfuseError::Timeout);
            }
            *byte = value as u8;
        }
        Ok(())
    })();
    // Power-cut/burst cleanup also runs on an incomplete physical read.
    if chip != ChipId::Rtl8852A {
        if chip == ChipId::Rtl8852B && cut == 0 {
            let value = io.read32(R_AX_EFUSE_CTRL_1);
            io.write32(R_AX_EFUSE_CTRL_1, value & !BURST);
        }
        let value = io.read16(REG_SYS_ISO_CTRL);
        io.write16(REG_SYS_ISO_CTRL, (value | ISO_CORE) & !POWER_15);
        io.delay_us(1000);
        let value = io.read16(REG_SYS_ISO_CTRL);
        io.write16(REG_SYS_ISO_CTRL, value & !POWER_14);
        let value = io.read8(REG_PMC_DBG_CTRL2);
        io.write8(REG_PMC_DBG_CTRL2, value & !WRITE_MASK);
    }
    result?;
    let mut logical = [0xff; 2048];
    decode_map(&raw, &mut logical[..logical_size])?;
    let mut mac = [0; 6];
    mac.copy_from_slice(&logical[EFUSE_MAC_OFFSET..EFUSE_MAC_OFFSET + 6]);
    if !mac_is_valid(mac) {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(mac)
}

/// Read the chip/cut-specific AX factory identity. BE generation has a
/// different block layout/read protocol and is rejected before EFUSE MMIO.
///
/// # Safety
/// Caller owns powered BAR2 exclusively, including SYS/PMC/EFUSE controls.
pub unsafe fn read_mac(mmio: &MmioRegion, chip: ChipId, cut: u8) -> Result<[u8; 6], EfuseError> {
    read_mac_with(&mut Mmio(mmio), chip, cut)
}
pub fn mac_is_valid(mac: [u8; MAC_ADDR_LEN]) -> bool {
    mac != [0; MAC_ADDR_LEN] && mac[0] & 1 == 0
}
