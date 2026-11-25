//! SPD5118 — the JEDEC DDR5 SPD hub's temperature sensor.
//!
//! Port of Linux `drivers/hwmon/spd5118.c` (hwmon half). Every DDR5
//! module carries an SPD5118 hub at SMBus address `0x50 + slot`; besides
//! fronting the SPD EEPROM it has a temperature sensor with programmable
//! low/high/critical limits and latched alarms. The I2C core instantiates
//! `spd5118` clients from SMBIOS (`narf_drivers_i2c::spd`); this driver
//! probes each one and publishes it as a hwmon device:
//!
//! | Attribute                       | Mode | Register            |
//! |---------------------------------|------|---------------------|
//! | `temp1_input`                   | 0444 | MR49:MR50           |
//! | `temp1_{lcrit,min,max,crit}`    | 0644 | MR34/MR30/MR28/MR32 |
//! | `temp1_{lcrit,min,max,crit}_alarm` | 0444 | MR51 (cleared via MR19 on read) |
//! | `temp1_enable`                  | 0644 | MR26 bit 0 (inverted) |
//!
//! There is no `temp1_label`, as in Linux.
//!
//! Not ported: the nvmem view of the SPD EEPROM (`eeprom` attribute),
//! the thermal-zone registration, and the suspend/resume register
//! cache. A hub in 16-bit addressing mode is refused: it needs raw I2C,
//! and the SMBus hosts SPD clients live on have none (Linux refuses on
//! such adapters too).

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_console::Writer;
use narf_drivers_i2c::client::I2cClient;
use narf_drivers_i2c::smbus::{self, I2cFunc};
use narf_drivers_i2c::{I2cBus, I2cError};

use crate::{AttrMode, HwmonError, TempAttr};

// SPD5118 registers (MRn = register n).
const SPD5118_REG_TYPE: u8 = 0x00; // MR0:MR1
const SPD5118_REG_REVISION: u8 = 0x02; // MR2
const SPD5118_REG_VENDOR: u8 = 0x03; // MR3:MR4
const SPD5118_REG_CAPABILITY: u8 = 0x05; // MR5
const SPD5118_REG_I2C_LEGACY_MODE: u8 = 0x0B; // MR11
const SPD5118_REG_TEMP_CLR: u8 = 0x13; // MR19
const SPD5118_REG_TEMP_CONFIG: u8 = 0x1A; // MR26
const SPD5118_REG_TEMP_MAX: u8 = 0x1c; // MR28:MR29
const SPD5118_REG_TEMP_MIN: u8 = 0x1e; // MR30:MR31
const SPD5118_REG_TEMP_CRIT: u8 = 0x20; // MR32:MR33
const SPD5118_REG_TEMP_LCRIT: u8 = 0x22; // MR34:MR35
const SPD5118_REG_TEMP: u8 = 0x31; // MR49:MR50
const SPD5118_REG_TEMP_STATUS: u8 = 0x33; // MR51

const SPD5118_TEMP_STATUS_HIGH: u8 = 1 << 0;
const SPD5118_TEMP_STATUS_LOW: u8 = 1 << 1;
const SPD5118_TEMP_STATUS_CRIT: u8 = 1 << 2;
const SPD5118_TEMP_STATUS_LCRIT: u8 = 1 << 3;

const SPD5118_CAP_TS_SUPPORT: u8 = 1 << 1;
const SPD5118_TS_DISABLE: u8 = 1 << 0;

const SPD5118_LEGACY_MODE_ADDR: u8 = 1 << 3;
const SPD5118_LEGACY_PAGE_MASK: u8 = 0x07;
const SPD5118_LEGACY_MODE_MASK: u8 = SPD5118_LEGACY_MODE_ADDR | SPD5118_LEGACY_PAGE_MASK;

/// MR0:MR1 of an SPD5118 hub, read byte-swapped.
const SPD5118_TYPE: u16 = 0x5118;

/// One LSB, in millidegrees (0.25 °C).
const SPD5118_TEMP_UNIT: i64 = 250;
const SPD5118_TEMP_RANGE_MIN: i64 = -256_000;
const SPD5118_TEMP_RANGE_MAX: i64 = 255_750;

/// `spd5118_temp_from_reg`: an 11-bit two's-complement count of
/// 0.25 °C in bits 12:2.
pub fn temp_from_reg(reg: u16) -> i64 {
    let raw = i64::from((reg >> 2) & 0x7ff);
    let signed = if raw & 0x400 != 0 { raw - 0x800 } else { raw };
    signed * SPD5118_TEMP_UNIT
}

/// Linux `DIV_ROUND_CLOSEST` on signed values (C division truncates).
fn div_round_closest(x: i64, d: i64) -> i64 {
    if (x > 0) == (d > 0) {
        (x + d / 2) / d
    } else {
        (x - d / 2) / d
    }
}

/// `spd5118_temp_to_reg`: clamp to the representable range and encode.
pub fn temp_to_reg(temp: i64) -> u16 {
    let t = temp.clamp(SPD5118_TEMP_RANGE_MIN, SPD5118_TEMP_RANGE_MAX);
    (((div_round_closest(t, SPD5118_TEMP_UNIT)) & 0x7ff) as u16) << 2
}

/// `spd5118_vendor_valid`: JEP106 bank and id bytes have odd parity,
/// and ids 0 and 0x7f are unassigned.
pub fn vendor_valid(bank: u8, id: u8) -> bool {
    if bank.count_ones() % 2 == 0 || id.count_ones() % 2 == 0 {
        return false;
    }
    let id = id & 0x7f;
    id != 0 && id != 0x7f
}

/// Why [`probe`] did not bind a client. Linux returns `-ENODEV` for
/// everything but a failed register read, whose error it passes up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Not an SPD5118 hub, or a hub this host cannot drive.
    NoDevice,
    /// A register read failed.
    Bus(I2cError),
}

impl From<I2cError> for ProbeError {
    fn from(e: I2cError) -> Self {
        ProbeError::Bus(e)
    }
}

fn hwmon_error(e: I2cError) -> HwmonError {
    match e {
        I2cError::Nack => HwmonError::NoResponse,
        I2cError::Timeout => HwmonError::Timeout,
        I2cError::Busy => HwmonError::Busy,
        I2cError::ArbLost => HwmonError::Again,
        I2cError::InvalidArgs => HwmonError::InvalidValue,
        I2cError::Abort(_) | I2cError::BadHardware | I2cError::Unsupported | I2cError::Protocol => {
            HwmonError::Io
        }
    }
}

/// One bound SPD5118 hub.
#[derive(Debug)]
pub struct Spd5118 {
    bus: Arc<dyn I2cBus>,
    addr: u8,
}

impl Spd5118 {
    async fn read(&self, reg: u8) -> Result<u8, I2cError> {
        smbus::read_byte_data(self.bus.as_ref(), self.addr, reg).await
    }

    async fn write(&self, reg: u8, value: u8) -> Result<(), I2cError> {
        smbus::write_byte_data(self.bus.as_ref(), self.addr, reg, value).await
    }

    /// A 16-bit register pair, low byte first — regmap's bulk read over
    /// an SMBus byte bus.
    async fn read16(&self, reg: u8) -> Result<u16, I2cError> {
        let lo = self.read(reg).await?;
        let hi = self.read(reg + 1).await?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    async fn read_attr(&self, attr: TempAttr) -> Result<i64, I2cError> {
        let limit = match attr {
            TempAttr::Max => Some(SPD5118_REG_TEMP_MAX),
            TempAttr::Min => Some(SPD5118_REG_TEMP_MIN),
            TempAttr::Crit => Some(SPD5118_REG_TEMP_CRIT),
            TempAttr::Lcrit => Some(SPD5118_REG_TEMP_LCRIT),
            _ => None,
        };
        if let Some(reg) = limit {
            return self.read16(reg).await.map(temp_from_reg);
        }
        let mask = match attr {
            TempAttr::MaxAlarm => SPD5118_TEMP_STATUS_HIGH,
            TempAttr::MinAlarm => SPD5118_TEMP_STATUS_LOW,
            TempAttr::CritAlarm => SPD5118_TEMP_STATUS_CRIT,
            TempAttr::LcritAlarm => SPD5118_TEMP_STATUS_LCRIT,
            TempAttr::Enable => {
                let config = self.read(SPD5118_REG_TEMP_CONFIG).await?;
                return Ok(i64::from(config & SPD5118_TS_DISABLE == 0));
            }
            _ => return Err(I2cError::Unsupported),
        };
        // `spd5118_read_alarm`: a latched alarm is cleared by reading it.
        let status = self.read(SPD5118_REG_TEMP_STATUS).await?;
        let set = status & mask != 0;
        if set {
            self.write(SPD5118_REG_TEMP_CLR, mask).await?;
        }
        Ok(i64::from(set))
    }

    async fn write_attr(&self, attr: TempAttr, value: i64) -> Result<(), HwmonError> {
        let reg = match attr {
            TempAttr::Max => SPD5118_REG_TEMP_MAX,
            TempAttr::Min => SPD5118_REG_TEMP_MIN,
            TempAttr::Crit => SPD5118_REG_TEMP_CRIT,
            TempAttr::Lcrit => SPD5118_REG_TEMP_LCRIT,
            TempAttr::Enable => {
                // `spd5118_write_enable`: 0 or 1, then update MR26 bit 0.
                if value != 0 && value != 1 {
                    return Err(HwmonError::InvalidValue);
                }
                let config = self
                    .read(SPD5118_REG_TEMP_CONFIG)
                    .await
                    .map_err(hwmon_error)?;
                let want = if value != 0 {
                    config & !SPD5118_TS_DISABLE
                } else {
                    config | SPD5118_TS_DISABLE
                };
                if want != config {
                    self.write(SPD5118_REG_TEMP_CONFIG, want)
                        .await
                        .map_err(hwmon_error)?;
                }
                return Ok(());
            }
            _ => return Err(HwmonError::InvalidValue),
        };
        let [lo, hi] = temp_to_reg(value).to_le_bytes();
        self.write(reg, lo).await.map_err(hwmon_error)?;
        self.write(reg + 1, hi).await.map_err(hwmon_error)
    }
}

impl crate::HwmonDevice for Spd5118 {
    fn name(&self) -> &str {
        "spd5118"
    }

    fn read_temp(&self, _label: &str) -> Option<i32> {
        let reg = narf_filesystem::wait_sync(self.read16(SPD5118_REG_TEMP)).ok()?;
        i32::try_from(temp_from_reg(reg)).ok()
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    /// `spd5118_is_visible`.
    fn temp_attr_mode(&self, _label: &str, attr: TempAttr) -> Option<AttrMode> {
        Some(match attr {
            TempAttr::Min | TempAttr::Max | TempAttr::Lcrit | TempAttr::Crit | TempAttr::Enable => {
                AttrMode::ReadWrite
            }
            TempAttr::MinAlarm
            | TempAttr::MaxAlarm
            | TempAttr::CritAlarm
            | TempAttr::LcritAlarm => AttrMode::ReadOnly,
        })
    }

    fn read_temp_attr(&self, _label: &str, attr: TempAttr) -> Option<i64> {
        narf_filesystem::wait_sync(self.read_attr(attr)).ok()
    }

    fn write_temp_attr(&self, _label: &str, attr: TempAttr, value: i64) -> Result<(), HwmonError> {
        narf_filesystem::wait_sync(self.write_attr(attr, value))
    }

    fn temp_label_visible(&self, _label: &str) -> bool {
        false
    }

    fn list_labels(&self) -> Vec<&str> {
        vec!["temp1"]
    }
}

/// `spd5118_i2c_init`: confirm an SPD5118 answers at `addr`, switching
/// a hub left on another legacy-mode page back to page 0.
async fn init(bus: &dyn I2cBus, addr: u8) -> Result<(), ProbeError> {
    if !bus
        .functionality()
        .contains(I2cFunc::SMBUS_BYTE_DATA | I2cFunc::SMBUS_WORD_DATA)
    {
        return Err(ProbeError::NoDevice);
    }
    let regval = smbus::read_word_swapped(bus, addr, SPD5118_REG_TYPE)
        .await
        .map_err(|_| ProbeError::NoDevice)?;
    if regval != 0 && regval != SPD5118_TYPE {
        return Err(ProbeError::NoDevice);
    }
    if regval == 0 {
        // Page 0 is not selected: MR0 reads as zero on other pages.
        match smbus::read_word_data(bus, addr, SPD5118_REG_VENDOR).await {
            Ok(0) => {}
            _ => return Err(ProbeError::NoDevice),
        }
        let mode = smbus::read_byte_data(bus, addr, SPD5118_REG_I2C_LEGACY_MODE)
            .await
            .map_err(|_| ProbeError::NoDevice)?;
        if mode & !SPD5118_LEGACY_MODE_MASK != 0 || mode & SPD5118_LEGACY_PAGE_MASK == 0 {
            return Err(ProbeError::NoDevice);
        }
        smbus::write_byte_data(
            bus,
            addr,
            SPD5118_REG_I2C_LEGACY_MODE,
            mode & SPD5118_LEGACY_MODE_ADDR,
        )
        .await
        .map_err(|_| ProbeError::NoDevice)?;
        match smbus::read_word_swapped(bus, addr, SPD5118_REG_TYPE).await {
            Ok(SPD5118_TYPE) => {}
            _ => {
                let _ = smbus::write_byte_data(bus, addr, SPD5118_REG_I2C_LEGACY_MODE, mode).await;
                return Err(ProbeError::NoDevice);
            }
        }
    }
    Ok(())
}

/// `spd5118_i2c_probe` + `spd5118_common_probe` for one instantiated
/// client. Returns the bound device and its identification line.
pub async fn probe(client: &I2cClient) -> Result<Spd5118, ProbeError> {
    let bus = client.bus().clone();
    let addr = client.addr();
    init(bus.as_ref(), addr).await?;

    let mode = smbus::read_byte_data(bus.as_ref(), addr, SPD5118_REG_I2C_LEGACY_MODE).await?;
    if mode & SPD5118_LEGACY_MODE_ADDR != 0 {
        if !bus.functionality().contains(I2cFunc::I2C) {
            log(
                client,
                format_args!("Adapter does not support 16-bit register addresses"),
            );
        } else {
            log(
                client,
                format_args!("16-bit register addressing is not supported"),
            );
        }
        return Err(ProbeError::NoDevice);
    }

    let dev = Spd5118 { bus, addr };
    let capability = dev.read(SPD5118_REG_CAPABILITY).await?;
    if capability & SPD5118_CAP_TS_SUPPORT == 0 {
        return Err(ProbeError::NoDevice);
    }
    let revision = dev.read(SPD5118_REG_REVISION).await?;
    let bank = dev.read(SPD5118_REG_VENDOR).await?;
    let vendor = dev.read(SPD5118_REG_VENDOR + 1).await?;
    if !vendor_valid(bank, vendor) {
        return Err(ProbeError::NoDevice);
    }
    log(
        client,
        format_args!(
            "DDR5 temperature sensor: vendor {:#04x}:{:#04x} revision {}.{}",
            bank & 0x7f,
            vendor,
            ((revision >> 4) & 0x03) + 1,
            ((revision >> 1) & 0x07) + 1
        ),
    );
    Ok(dev)
}

fn log(client: &I2cClient, args: core::fmt::Arguments<'_>) {
    let _ = writeln!(
        Writer,
        "spd5118 {} {:#04x}: {}",
        client.bus().name(),
        client.addr(),
        args
    );
}

/// Register the Stage::Device job that binds every `spd5118` client.
///
/// Called from the hwmon crate's Stage::Subsys initcall. The clients
/// come from the SMBus host probes in `pci-probe-all` (Stage::Device);
/// a Device job registered during Subsys runs after it, and before the
/// hwmon sysfs bridge snapshots the registry at Stage::Late (the jc42
/// ordering).
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "spd5118", || {
        if bind_clients() == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
}

/// Probe every `spd5118` client and register the hubs that bind as
/// hwmon devices. Returns how many bound. A client that fails probe
/// stays registered and unbound, as in Linux.
pub fn bind_clients() -> usize {
    let mut bound = 0usize;
    for client in narf_drivers_i2c::client::clients_of_kind("spd5118") {
        // Initcall context: no executor poll, spin the probe.
        if let Ok(dev) = narf_scheduler::block_on_spin(probe(&client)) {
            crate::registry::register(crate::registry::RegisteredSensor {
                name: "spd5118",
                description: "JEDEC SPD5118 DDR5 hub temperature sensor",
                bus_loc: "smbus",
            });
            crate::registry::register_device(Arc::new(dev));
            bound += 1;
        }
    }
    bound
}
