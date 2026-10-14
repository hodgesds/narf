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

// Super-I/O logical-device / config registers (it87.c:73-80,168-169,200,206).
/// Logical device select register (`DEV`, it87.c:73).
pub const SIO_LDN_SELECT: u8 = 0x07;
/// LDN of the Environment Controller / PME device holding the fan/temp regs
/// (`PME`, it87.c:75).
pub const SIO_LDN_EC: u8 = 0x04;
/// Activation register for the EC logical device (`IT87_ACT_REG`, it87.c:168).
pub const SIO_ACT_REG: u8 = 0x30;
/// Base-address register (high byte); low byte is 0x61 (`IT87_BASE_REG`, it87.c:169).
pub const SIO_BASE_REG: u8 = 0x60;
/// I/O window size reserved by the EC; the base is aligned to this
/// (`IT87_EXTENT`, it87.c:200).
pub const IT87_EXTENT: u16 = 8;

// Offsets from the EC base address to the ISA index/data register pair.
/// Offset of the EC register block from the ISA base (`IT87_EC_OFFSET`, it87.c:206).
pub const IT87_EC_OFFSET: u16 = 5;
/// Index (address) register offset within the EC block (`IT87_ADDR_REG_OFFSET`, it87.c:209).
pub const IT87_ADDR_REG_OFFSET: u16 = 0;
/// Data register offset within the EC block (`IT87_DATA_REG_OFFSET`, it87.c:210).
pub const IT87_DATA_REG_OFFSET: u16 = 1;

// EC register map (it87.c:244-258).
/// Base of the temperature registers: `IT87_REG_TEMP(nr) = 0x29 + nr` (it87.c:258).
pub const IT87_REG_TEMP_BASE: u8 = 0x29;
/// Base of the voltage (VIN) registers: `IT87_REG_VIN[]` starts at 0x20 (it87.c:255).
pub const IT87_REG_VIN_BASE: u8 = 0x20;
/// Fan tachometer low bytes `IT87_REG_FAN[]` (it87.c:244).
pub const IT87_REG_FAN: [u8; 6] = [0x0d, 0x0e, 0x0f, 0x80, 0x82, 0x4c];
/// Fan tachometer high bytes `IT87_REG_FANX[]` (16-bit fans, it87.c:246).
pub const IT87_REG_FANX: [u8; 6] = [0x18, 0x19, 0x1a, 0x81, 0x83, 0x4d];
/// PWM duty-cycle control registers `IT87_REG_PWM[]` (it87.c:252).
pub const IT87_REG_PWM: [u8; 6] = [0x15, 0x16, 0x17, 0x7f, 0xa7, 0xaf];
/// Main fan control register `IT87_REG_FAN_MAIN_CTRL` (it87.c:250).
pub const IT87_REG_FAN_MAIN_CTRL: u8 = 0x13;
/// Fan control mode register `IT87_REG_FAN_CTL` (it87.c:251).
pub const IT87_REG_FAN_CTL: u8 = 0x14;

/// Default ADC LSB for IT87xx voltage inputs, in 1/10 mV units.
///
/// `adc_lsb()` (it87.c:641-655) returns 160 for the common (non-12mV,
/// non-10.9mV) case; `in_from_reg()` (it87.c:663-666) computes
/// `DIV_ROUND_CLOSEST(raw * lsb, 10)`, i.e. `raw * 160 / 10 == raw * 16` mV.
pub const IT87_ADC_LSB: i32 = 160;

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

/// Convert a 16-bit fan tachometer count into RPM.
///
/// Clean-room port of `FAN16_FROM_REG` (it87.c:686-687): the 16-bit divider is
/// fixed at 2, so `rpm = 1350000 / (count * 2)`. A count of 0 means "no reading"
/// and 0xFFFF means "stalled / 0 RPM"; both map to `None` here (callers treat a
/// missing/zero reading identically).
pub fn fan16_to_rpm(count: u16) -> Option<u32> {
    if count == 0 || count == 0xffff {
        return None;
    }
    Some(1_350_000 / (count as u32 * 2))
}

/// Convert an 8-bit fan tachometer count into RPM for legacy 8-bit fans.
///
/// Clean-room port of `FAN_FROM_REG` (it87.c:683-684): `rpm = 1350000 /
/// (count * divisor)`. A count of 0 means "no reading" and 255 means "0 RPM";
/// both map to `None`.
pub fn fan8_to_rpm(count: u8, divisor: u8) -> Option<u32> {
    if count == 0 || count == 255 || divisor == 0 {
        return None;
    }
    Some(1_350_000 / (count as u32 * divisor as u32))
}

/// Convert a raw 8-bit VIN register value into millivolts.
///
/// Clean-room port of `in_from_reg()` (it87.c:663-666) for the common ADC LSB
/// of 160 (1/10 mV units): `mV = DIV_ROUND_CLOSEST(raw * 160, 10) == raw * 16`.
/// Rails with a resistor divider (e.g. in3/AVCC, in7/VSB, in8/Vbat) double the
/// LSB in `adc_lsb()` (it87.c:641-655); that per-rail scaling is not applied in
/// this first cut, so divided rails read half their true voltage.
pub fn vin_from_reg(raw: u8) -> i32 {
    // DIV_ROUND_CLOSEST(raw * 160, 10).
    (raw as i32 * IT87_ADC_LSB + 5) / 10
}

/// Convert a raw signed 8-bit temperature register value into millidegrees C.
///
/// Clean-room port of `TEMP_FROM_REG` (it87.c:691): `TEMP_FROM_REG(val) =
/// val * 1000`, where `val` is read as a signed byte.
pub fn temp_from_reg(raw: u8) -> i32 {
    (raw as i8 as i32) * 1000
}

#[cfg(target_arch = "x86_64")]
#[inline]
/// Read one EC register through the ISA index/data pair.
///
/// `ec_base` is the raw Super-I/O base; the register block lives at
/// `ec_base + IT87_EC_OFFSET` (it87.c:206), with the index port at
/// `+IT87_ADDR_REG_OFFSET` and the data port at `+IT87_DATA_REG_OFFSET`
/// (it87.c:781-784 `it87_read_value`).
///
/// # Safety
/// Caller must ensure `ec_base` is the valid, probed EC base for an IT87xx chip.
pub unsafe fn ec_read(ec_base: u16, reg: u8) -> u8 {
    let index = ec_base + IT87_EC_OFFSET + IT87_ADDR_REG_OFFSET;
    let data = ec_base + IT87_EC_OFFSET + IT87_DATA_REG_OFFSET;
    // SAFETY: index/data are the probed EC port pair; outb selects the register
    // then inb returns its value, exactly as it87_read_value() (it87.c:781-784).
    unsafe {
        narf_arch::x86_64::io_port::outb(index, reg);
        narf_arch::x86_64::io_port::inb(data)
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
/// Write one EC register through the ISA index/data pair.
///
/// Mirror of [`ec_read`]; port of `it87_write_value` (it87.c:793-796).
///
/// # Safety
/// Caller must ensure `ec_base` is the valid, probed EC base for an IT87xx chip.
pub unsafe fn ec_write(ec_base: u16, reg: u8, val: u8) {
    let index = ec_base + IT87_EC_OFFSET + IT87_ADDR_REG_OFFSET;
    let data = ec_base + IT87_EC_OFFSET + IT87_DATA_REG_OFFSET;
    // SAFETY: index/data are the probed EC port pair; outb the register then
    // outb the value, exactly as it87_write_value() (it87.c:793-796).
    unsafe {
        narf_arch::x86_64::io_port::outb(index, reg);
        narf_arch::x86_64::io_port::outb(data, val);
    }
}

#[cfg(target_arch = "x86_64")]
/// Discover the Environment Controller I/O base for a probed IT87xx chip.
///
/// Port of the base-read portion of `it87_find()` (it87.c:2812-2820): enter EFM,
/// select the PME/EC logical device (LDN 0x04), require the activation bit
/// (`IT87_ACT_REG & 0x01`), read the 16-bit base from registers 0x60/0x61, align
/// it down to the `IT87_EXTENT` window, exit EFM. Returns `None` if the device is
/// inactive or the base is zero.
pub fn discover_ec_base(index_port: u16, data_port: u16) -> Option<u16> {
    // SAFETY: index/data are the probed Super-I/O port pair; the whole sequence
    // runs inside an EFM enter/exit bracket just like it87_find().
    let base = unsafe {
        sio_enter(index_port);
        // superio_select(PME): write LDN-select reg then the LDN (it87.c:114-119).
        narf_arch::x86_64::io_port::outb(index_port, SIO_LDN_SELECT);
        narf_arch::x86_64::io_port::outb(data_port, SIO_LDN_EC);
        let active = sio_read(index_port, data_port, SIO_ACT_REG) & 0x01;
        // superio_inw(IT87_BASE_REG): hi at 0x60, lo at 0x61 (it87.c:103-111).
        let hi = sio_read(index_port, data_port, SIO_BASE_REG);
        let lo = sio_read(index_port, data_port, SIO_BASE_REG + 1);
        sio_exit(index_port);
        if active == 0 {
            return None;
        }
        (((hi as u16) << 8) | (lo as u16)) & !(IT87_EXTENT - 1)
    };
    if base == 0 {
        None
    } else {
        Some(base)
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
    /// Environment Controller I/O base discovered during probe. `0` means the
    /// base was never resolved (non-x86 build, or probe failed); reads bail out.
    pub ec_base: u16,
}

impl It87Hwmon {
    pub fn new(
        chip: It87Chip,
        chip_id: u16,
        index_port: u16,
        data_port: u16,
        ec_base: u16,
    ) -> Self {
        Self {
            chip,
            chip_id,
            index_port,
            data_port,
            ec_base,
        }
    }

    /// Whether this chip exposes 16-bit fan tachometers.
    ///
    /// `has_16bit_fans()` keys off `FEAT_16BIT_FANS` (it87.c:517); the IT8705F
    /// and IT8712F are the legacy 8-bit-only parts, everything else here carries
    /// the feature bit.
    pub fn has_16bit_fans(&self) -> bool {
        !matches!(self.chip, It87Chip::It8705F | It87Chip::It8712F)
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
        #[cfg(target_arch = "x86_64")]
        {
            if self.ec_base == 0 {
                return None;
            }
            // IT87_REG_TEMP(nr) = 0x29 + nr (it87.c:258), read as signed byte.
            // SAFETY: ec_base was validated during probe; reg is in range.
            let raw = unsafe { ec_read(self.ec_base, IT87_REG_TEMP_BASE + idx as u8) };
            Some(temp_from_reg(raw))
        }
        #[cfg(not(target_arch = "x86_64"))]
        None
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        let idx = FAN_LABELS.iter().position(|&l| l == label)?;
        if idx >= self.chip.num_fans() as usize {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        {
            if self.ec_base == 0 || idx >= IT87_REG_FAN.len() {
                return None;
            }
            if self.has_16bit_fans() {
                // count = low | (high << 8) (it87.c:914-918), then FAN16_FROM_REG.
                // SAFETY: ec_base validated at probe; regs come from the static map.
                let (low, high) = unsafe {
                    (
                        ec_read(self.ec_base, IT87_REG_FAN[idx]),
                        ec_read(self.ec_base, IT87_REG_FANX[idx]),
                    )
                };
                let count = (low as u16) | ((high as u16) << 8);
                return fan16_to_rpm(count);
            }
            // Legacy 8-bit tach with a fixed divisor of 2 as a sane default
            // (FAN_FROM_REG, it87.c:683-684); exact per-fan divisor lives in
            // IT87_REG_FAN_DIV which the first cut does not decode.
            // SAFETY: ec_base validated at probe; reg from the static map.
            let raw = unsafe { ec_read(self.ec_base, IT87_REG_FAN[idx]) };
            fan8_to_rpm(raw, 2)
        }
        #[cfg(not(target_arch = "x86_64"))]
        None
    }

    fn read_voltage(&self, label: &str) -> Option<i32> {
        let idx = VOLT_LABELS.iter().position(|&l| l == label)?;
        #[cfg(target_arch = "x86_64")]
        {
            if self.ec_base == 0 {
                return None;
            }
            // IT87_REG_VIN[] starts at 0x20 (it87.c:255); plain 16 mV/LSB scale.
            // SAFETY: ec_base validated at probe; reg stays within the VIN window.
            let raw = unsafe { ec_read(self.ec_base, IT87_REG_VIN_BASE + idx as u8) };
            Some(vin_from_reg(raw))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = idx;
            None
        }
    }

    fn set_fan(&self, label: &str, level: u8) -> bool {
        let Some(idx) = FAN_LABELS.iter().position(|&l| l == label) else {
            return false;
        };
        #[cfg(target_arch = "x86_64")]
        {
            if self.ec_base == 0
                || idx >= IT87_REG_PWM.len()
                || idx >= self.chip.num_fans() as usize
            {
                return false;
            }
            // Best-effort PWM duty write to IT87_REG_PWM[nr] (it87.c:252). A fully
            // correct write would first put the channel in manual mode via
            // IT87_REG_FAN_MAIN_CTRL / IT87_REG_FAN_CTL; we only set the duty and
            // trust that firmware left the channel in manual (software) mode.
            // SAFETY: ec_base validated at probe; reg from the static PWM map.
            unsafe { ec_write(self.ec_base, IT87_REG_PWM[idx], level) };
            true
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (idx, level);
            false
        }
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
                let ec_base = discover_ec_base(idx, dat).unwrap_or(0);
                let _ = writeln!(
                    narf_console::Writer,
                    "  it87: {} (id=0x{:04X}) at 0x{:02X}, ec_base=0x{:04X}",
                    chip.name(),
                    chip_id,
                    idx,
                    ec_base
                );
                registry::register(registry::RegisteredSensor {
                    name: "it87",
                    description: chip.name(),
                    bus_loc: "isa",
                });
                use alloc::sync::Arc;
                registry::register_device(Arc::new(It87Hwmon::new(
                    chip, chip_id, idx, dat, ec_base,
                )));
                return;
            }
        }
        let _ = writeln!(narf_console::Writer, "  it87: no chip found");
    }
}
