//! ITE IT87xx Super-I/O Hardware Monitor driver.
//!
//! Ref: Linux `drivers/hwmon/it87.c`.

extern crate alloc;

use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::registry;

pub const IT8705F_ID: u16 = 0x8705;
pub const IT8712F_ID: u16 = 0x8712;
pub const IT8716F_ID: u16 = 0x8716;
pub const IT8718F_ID: u16 = 0x8718;
pub const IT8720F_ID: u16 = 0x8720;
pub const IT8721F_ID: u16 = 0x8721;
pub const IT8726F_ID: u16 = 0x8726;
pub const IT8728F_ID: u16 = 0x8728;
pub const IT8732F_ID: u16 = 0x8732;
pub const IT8792E_ID: u16 = 0x8733;
pub const IT8603E_ID: u16 = 0x8603;
pub const IT8620E_ID: u16 = 0x8620;
pub const IT8622E_ID: u16 = 0x8622;
pub const IT8628E_ID: u16 = 0x8628;

pub const SIO_INDEX_STD: u16 = 0x2E;
pub const SIO_DATA_STD: u16 = 0x2F;
pub const SIO_INDEX_ALT: u16 = 0x4E;
pub const SIO_DATA_ALT: u16 = 0x4F;

pub const SIO_CHIP_ID: u8 = 0x20; // 16-bit word read via inw? No, in Linux it uses superio_inw which does two outb/inb pairs.
pub const SIO_CHIP_ID_HI: u8 = 0x20;
pub const SIO_CHIP_ID_LO: u8 = 0x21;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum It87Chip {
    It8705F,
    It8712F,
    It8716F,
    It8718F,
    It8720F,
    It8721F,
    It8726F,
    It8728F,
    It8732F,
    It8792E,
    It8603E,
    It8620E,
    It8622E,
    It8628E,
    Unknown(u16),
}

impl It87Chip {
    pub fn from_id(id: u16) -> Self {
        match id {
            IT8705F_ID => It87Chip::It8705F,
            IT8712F_ID => It87Chip::It8712F,
            IT8716F_ID => It87Chip::It8716F,
            IT8718F_ID => It87Chip::It8718F,
            IT8720F_ID => It87Chip::It8720F,
            IT8721F_ID => It87Chip::It8721F,
            IT8726F_ID => It87Chip::It8726F,
            IT8728F_ID => It87Chip::It8728F,
            IT8732F_ID => It87Chip::It8732F,
            IT8792E_ID => It87Chip::It8792E,
            IT8603E_ID => It87Chip::It8603E,
            IT8620E_ID => It87Chip::It8620E,
            IT8622E_ID => It87Chip::It8622E,
            IT8628E_ID => It87Chip::It8628E,
            other => It87Chip::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            It87Chip::It8705F => "IT8705F",
            It87Chip::It8712F => "IT8712F",
            It87Chip::It8716F => "IT8716F",
            It87Chip::It8718F => "IT8718F",
            It87Chip::It8720F => "IT8720F",
            It87Chip::It8721F => "IT8721F",
            It87Chip::It8726F => "IT8726F",
            It87Chip::It8728F => "IT8728F",
            It87Chip::It8732F => "IT8732F",
            It87Chip::It8792E => "IT8792E",
            It87Chip::It8603E => "IT8603E",
            It87Chip::It8620E => "IT8620E",
            It87Chip::It8622E => "IT8622E",
            It87Chip::It8628E => "IT8628E",
            It87Chip::Unknown(_) => "IT87xxUnknown",
        }
    }

    pub fn num_fans(self) -> u8 {
        match self {
            It87Chip::It8705F | It87Chip::It8712F => 3,
            It87Chip::It8603E => 3,
            It87Chip::It8620E | It87Chip::It8622E | It87Chip::It8628E => 6,
            _ => 5, // most modern variants have 5 or 6 fans
        }
    }

    pub fn num_temps(self) -> u8 {
        match self {
            It87Chip::It8705F | It87Chip::It8712F => 3,
            _ => 6,
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
/// # Safety
/// Caller must ensure index_port is valid for Super I/O access.
pub unsafe fn sio_enter(index_port: u16) {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, 0x87);
        narf_arch::x86_64::io_port::outb(index_port, 0x01);
        narf_arch::x86_64::io_port::outb(index_port, 0x55);
        if index_port == SIO_INDEX_ALT {
            narf_arch::x86_64::io_port::outb(index_port, 0xAA);
        } else {
            narf_arch::x86_64::io_port::outb(index_port, 0x55);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
/// # Safety
/// Caller must ensure index_port is valid for Super I/O access.
pub unsafe fn sio_exit(index_port: u16) {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, 0x02);
        narf_arch::x86_64::io_port::outb(index_port + 1, 0x02);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
/// # Safety
/// Caller must ensure index_port and data_port are valid for Super I/O access.
pub unsafe fn sio_read(index_port: u16, data_port: u16, reg: u8) -> u8 {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        narf_arch::x86_64::io_port::outb(index_port, reg);
        narf_arch::x86_64::io_port::inb(data_port)
    }
}

#[cfg(target_arch = "x86_64")]
pub fn detect_chip(index_port: u16, data_port: u16) -> Option<(It87Chip, u16)> {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let chip_id = unsafe {
        sio_enter(index_port);
        let hi = sio_read(index_port, data_port, SIO_CHIP_ID_HI);
        let lo = sio_read(index_port, data_port, SIO_CHIP_ID_LO);
        sio_exit(index_port);
        ((hi as u16) << 8) | (lo as u16)
    };
    let chip = It87Chip::from_id(chip_id);
    match chip {
        It87Chip::Unknown(_) => None,
        _ => Some((chip, chip_id)),
    }
}

pub const TEMP_LABELS: &[&str] = &["temp1", "temp2", "temp3", "temp4", "temp5", "temp6"];
pub const FAN_LABELS: &[&str] = &["fan1", "fan2", "fan3", "fan4", "fan5", "fan6"];
pub const VOLT_LABELS: &[&str] = &["in0", "in1", "in2", "in3", "in4", "in5", "in6", "in7"];

#[derive(Debug)]
pub struct It87Hwmon {
    pub chip: It87Chip,
    pub chip_id: u16,
    pub index_port: u16,
    pub data_port: u16,
}

impl It87Hwmon {
    pub fn new(chip: It87Chip, chip_id: u16, index_port: u16, data_port: u16) -> Self {
        Self {
            chip,
            chip_id,
            index_port,
            data_port,
        }
    }
}

impl crate::HwmonDevice for It87Hwmon {
    fn name(&self) -> &str {
        "it87"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        let idx = TEMP_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_temps() as usize {
            return None;
        }
        // Deferred I/O reads.
        None
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        let idx = FAN_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_fans() as usize {
            return None;
        }
        // Deferred I/O reads.
        None
    }

    fn read_voltage(&self, label: &str) -> Option<i32> {
        let _idx = VOLT_LABELS.iter().position(|&l| l == label)?;
        None
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        for &l in TEMP_LABELS.iter().take(self.chip.num_temps() as usize) {
            v.push(l);
        }
        for &l in FAN_LABELS.iter().take(self.chip.num_fans() as usize) {
            v.push(l);
        }
        for &l in VOLT_LABELS {
            v.push(l);
        }
        v
    }
}

pub fn register_isa_driver() {
    #[cfg(target_arch = "x86_64")]
    use core::fmt::Write as _;
    #[cfg(target_arch = "x86_64")]
    {
        let candidates = [(SIO_INDEX_STD, SIO_DATA_STD), (SIO_INDEX_ALT, SIO_DATA_ALT)];
        for (idx, dat) in candidates {
            if let Some((chip, chip_id)) = detect_chip(idx, dat) {
                let _ = writeln!(
                    narf_console::Writer,
                    "  it87: {} (id=0x{:04X}) at 0x{:02X}",
                    chip.name(),
                    chip_id,
                    idx
                );
                registry::register(registry::RegisteredSensor {
                    name: "it87",
                    description: chip.name(),
                    bus_loc: "isa",
                });
                use alloc::sync::Arc;
                registry::register_device(Arc::new(It87Hwmon::new(chip, chip_id, idx, dat)));
                return;
            }
        }
        let _ = writeln!(narf_console::Writer, "  it87: no chip found");
    }
}
