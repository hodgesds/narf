//! Factory identity from rtlwifi's physical programming records.
//!
//! Linux: `rtlwifi/efuse.c::{efuse_power_switch,read_efuse_byte,read_efuse}`
//! and per-chip `reg.h` geometry/EEPROM_MAC_ADDR definitions. The 8192DE
//! dual-MAC offsets are selected by `rtl8192d/hw_common.c`.

use super::regs::*;
use narf_bus::MmioRegion;
use narf_time::Deadline;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfuseError {
    Timeout,
    MacUninitialized,
    UnsupportedChip,
    MalformedMap,
}

/// One decoded read-only factory map, retained for radio calibration/power.
#[derive(Debug, Clone)]
pub struct Factory {
    pub mac: [u8; 6],
    pub logical: [u8; 512],
}

pub(super) trait Io {
    fn read8(&mut self, addr: u64) -> u8;
    fn write8(&mut self, addr: u64, value: u8);
    fn read16(&mut self, addr: u64) -> u16;
    fn write16(&mut self, addr: u64, value: u16);
    fn read32(&mut self, addr: u64) -> u32;
    fn settle(&mut self) {
        narf_scheduler::responsive_spin_until(|| false, Deadline::after_us(50));
    }
}

struct Mmio<'a>(&'a MmioRegion);
impl Io for Mmio<'_> {
    fn read8(&mut self, addr: u64) -> u8 {
        // SAFETY: read_mac's exclusive powered-register contract.
        unsafe { self.0.read8(addr) }
    }
    fn write8(&mut self, addr: u64, value: u8) {
        // SAFETY: as above; all offsets name EFUSE/SYS controls.
        unsafe { self.0.write8(addr, value) }
    }
    fn read16(&mut self, addr: u64) -> u16 {
        // SAFETY: as above.
        unsafe { self.0.read16(addr) }
    }
    fn write16(&mut self, addr: u64, value: u16) {
        // SAFETY: as above.
        unsafe { self.0.write16(addr, value) }
    }
    fn read32(&mut self, addr: u64) -> u32 {
        // SAFETY: as above.
        unsafe { self.0.read32(addr) }
    }
}

pub(super) fn read_mac_with(
    io: &mut impl Io,
    did: u16,
    function: u8,
) -> Result<[u8; 6], EfuseError> {
    Ok(read_factory_with(io, did, function)?.mac)
}

pub(super) fn read_factory_with(
    io: &mut impl Io,
    did: u16,
    function: u8,
) -> Result<Factory, EfuseError> {
    let (physical, logical_size, mac_offset, access_gate) = match did {
        RTL_DEV_8188EE | RTL_DEV_8192EE | RTL_DEV_8723BE | RTL_DEV_8821AE => {
            (256 - 18, 512, 0xd0, true)
        }
        RTL_DEV_8192CE | RTL_DEV_8192CE_ALT => (512 - 15, 128, 0x16, false),
        RTL_DEV_8192DE if function < 2 => (
            512 - 15,
            256,
            if function == 0 { 0x55 } else { 0x5b },
            false,
        ),
        RTL_DEV_8723AE => (512 - 15, 256, 0x67, true),
        _ => return Err(EfuseError::UnsupportedChip),
    };
    if access_gate {
        io.write8(REG_EFUSE_ACCESS, 0x69);
    } else {
        let value = io.read16(REG_SYS_ISO_CTRL);
        io.write16(REG_SYS_ISO_CTRL, value | (1 << 15));
    }
    let value = io.read16(REG_SYS_FUNC_EN);
    io.write16(REG_SYS_FUNC_EN, value | (1 << 12));
    let value = io.read16(REG_SYS_CLKR);
    let clock = if did == RTL_DEV_8192DE {
        1 << 5
    } else {
        (1 << 5) | (1 << 1)
    };
    io.write16(REG_SYS_CLKR, value | clock);

    // Read power does not enable LDOE25: that voltage is for programming.
    let mut raw = [0xff; 512];
    let result = (|| {
        for (address, byte) in raw[..physical].iter_mut().enumerate() {
            io.write8(REG_EFUSE_CTRL + 1, address as u8);
            let value = io.read8(REG_EFUSE_CTRL + 2);
            io.write8(
                REG_EFUSE_CTRL + 2,
                (value & 0xfc) | ((address >> 8) as u8 & 3),
            );
            let value = io.read8(REG_EFUSE_CTRL + 3);
            io.write8(REG_EFUSE_CTRL + 3, value & 0x7f);
            let mut last = 0;
            if !narf_scheduler::responsive_spin_until(
                || {
                    last = io.read32(REG_EFUSE_CTRL);
                    last & EFUSE_CTRL_VALID != 0
                },
                Deadline::after_ms(5),
            ) {
                return Err(EfuseError::Timeout);
            }
            // Linux read_efuse_byte allows the data output to settle after
            // the ready flag. Keep that explicit delay in the real path.
            io.settle();
            *byte = io.read32(REG_EFUSE_CTRL) as u8;
        }
        Ok(())
    })();
    if access_gate {
        io.write8(REG_EFUSE_ACCESS, 0);
    }
    result?;
    let mut logical = [0xff; 512];
    crate::rtw88::efuse::decode_map(&raw[..physical], &mut logical[..logical_size])
        .map_err(|_| EfuseError::MalformedMap)?;
    let mut mac = [0; 6];
    mac.copy_from_slice(&logical[mac_offset..mac_offset + 6]);
    if !mac_is_valid(mac) {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(Factory { mac, logical })
}

/// # Safety
/// Same exclusive powered BAR2 contract as read_mac; no programming occurs.
pub unsafe fn read_factory(
    mmio: &MmioRegion,
    did: u16,
    function: u8,
) -> Result<Factory, EfuseError> {
    read_factory_with(&mut Mmio(mmio), did, function)
}

/// Read the appropriate logical factory MAC, including dual-MAC PCI function.
///
/// # Safety
/// Caller exclusively owns powered BAR2, covering SYS/EFUSE access registers
/// through 0xCF. The caller must not invoke this concurrently with EFUSE write.
pub unsafe fn read_mac(mmio: &MmioRegion, did: u16, function: u8) -> Result<[u8; 6], EfuseError> {
    read_mac_with(&mut Mmio(mmio), did, function)
}

pub fn mac_is_valid(mac: [u8; MAC_ADDR_LEN]) -> bool {
    mac != [0; MAC_ADDR_LEN] && mac[0] & 1 == 0
}
