// SPDX-License-Identifier: GPL-2.0-or-later
//! QCA9887 serial-interface (SI) I2C calibration EEPROM.
//!
//! Linux `pci.c::{ath10k_pci_enable_eeprom,ath10k_pci_read_eeprom,
//! ath10k_pci_validate_cal,ath10k_pci_hif_fetch_cal_eeprom}` and
//! `core.c::ath10k_download_cal_eeprom`: on QCA9887 only, the host reads
//! `cal_data_len` (2116) bytes through the target SI block, accepts them only
//! when the little-endian 16-bit XOR checksum is 0xffff, and downloads them as
//! board data instead of running OTP calibration. Any EEPROM failure falls back
//! to the board-file/OTP path. These factory bytes are read from the device under
//! the current PCI capability; they grant no regulatory or transmit authority.
use super::{bmi::BmiError, ce::Ath10kMmio, hw::Registers};
use alloc::vec::Vec;

/// `hw.h::SOC_CLOCK_CONTROL_OFFSET`, relative to the RTC SoC window.
const CLOCK_CONTROL: u64 = 0x28;
/// `hw.h::WLAN_GPIO_BASE_ADDRESS` and `WLAN_GPIO_PIN0_ADDRESS`.
const GPIO_BASE: u64 = 0x14000;
const GPIO_PIN0: u64 = 0x28;
/// `hw.h::QCA9887_1_0_GPIO_ENABLE_W1TS_LOW_ADDRESS`.
const GPIO_ENABLE_W1TS_LOW: u64 = 0x10;
/// `hw.h::QCA9887_1_0_{I2C_SDA,SI_CLK}_{GPIO_PIN,PIN_CONFIG}`.
const SDA_PIN: u64 = 5;
const SDA_CONFIG: u32 = 3;
const CLK_PIN: u64 = 17;
const CLK_CONFIG: u32 = 3;
/// `GPIO_PIN0_CONFIG` (bits 11..14) and `GPIO_PIN0_PAD_PULL` (bits 5..6).
const PIN_CONFIG_LSB: u32 = 11;
const PIN_PAD_PULL_UP: u32 = 1 << 5;
/// `hw.h::WLAN_SI_BASE_ADDRESS` and SI register offsets.
const SI_BASE: u64 = 0x10000;
const SI_CONFIG: u64 = 0x0;
const SI_CS: u64 = 0x4;
const SI_TX_DATA0: u64 = 0x8;
const SI_RX_DATA0: u64 = 0x10;
/// SI_CONFIG: ERR_INT(19) | BIDIR_OD_DATA(18) | I2C(16) | POS_SAMPLE(7) |
/// INACTIVE_DATA(5) | INACTIVE_CLK(4) | DIVIDER=8 (110 MHz / 512 ≈ 214 kHz).
const SI_CONFIG_I2C_EEPROM: u32 =
    (1 << 19) | (1 << 18) | (1 << 16) | (1 << 7) | (1 << 5) | (1 << 4) | 8;
/// SI_CS: DONE_ERR(10), DONE_INT(9), START(8), RX_CNT(4..7), TX_CNT(0..3).
const SI_CS_DONE_ERR: u32 = 1 << 10;
const SI_CS_DONE_INT: u32 = 1 << 9;
const SI_CS_READ_ONE: u32 = (1 << 8) | (1 << 4) | 4;
/// `hw.h::QCA9887_EEPROM_SELECT_READ` plus ADDR_LO (16..23) / ADDR_HI (8..15).
const SELECT_READ: u32 = 0xa100_00a0;

/// Fixed QCA9887 calibration length (`core.c` hw_params `cal_data_len`).
pub(super) const QCA9887_CALIBRATION: usize = 2116;

/// `ath10k_pci_validate_cal`: even length and 16-bit LE XOR equal to 0xffff.
pub(super) fn valid(data: &[u8]) -> bool {
    data.len() % 2 == 0
        && data
            .chunks_exact(2)
            .fold(0u16, |sum, w| sum ^ u16::from_le_bytes([w[0], w[1]]))
            == 0xffff
}

fn read(io: &mut impl Ath10kMmio, offset: u64) -> Result<u32, BmiError> {
    if !io.authorized() {
        return Err(BmiError::Pci);
    }
    match io.read32(offset) {
        u32::MAX => Err(BmiError::DeviceGone),
        value => Ok(value),
    }
}
fn write(io: &mut impl Ath10kMmio, offset: u64, value: u32) -> Result<(), BmiError> {
    if !io.authorized() {
        return Err(BmiError::Pci);
    }
    io.write32(offset, value);
    Ok(())
}

/// `ath10k_pci_enable_eeprom`: SI clock, I2C GPIO muxing and SI mode.
fn enable(io: &mut impl Ath10kMmio, registers: Registers) -> Result<(), BmiError> {
    write(io, registers.rtc_soc + CLOCK_CONTROL, 0)?;
    for (pin, config) in [(SDA_PIN, SDA_CONFIG), (CLK_PIN, CLK_CONFIG)] {
        write(
            io,
            GPIO_BASE + GPIO_PIN0 + 4 * pin,
            (config << PIN_CONFIG_LSB) | PIN_PAD_PULL_UP,
        )?;
    }
    write(io, GPIO_BASE + GPIO_ENABLE_W1TS_LOW, 1 << CLK_PIN)?;
    write(io, SI_BASE + SI_CONFIG, SI_CONFIG_I2C_EEPROM)
}

/// One `ath10k_pci_read_eeprom` byte. `Ok(None)` is Linux's ETIMEDOUT/EIO
/// fallback; authority loss and an absent device are terminal errors.
async fn byte(io: &mut impl Ath10kMmio, address: u16) -> Result<Option<u8>, BmiError> {
    let select = SELECT_READ | (u32::from(address & 0xff) << 16) | (u32::from(address >> 8) << 8);
    write(io, SI_BASE + SI_TX_DATA0, select)?;
    write(io, SI_BASE + SI_CS, SI_CS_READ_ONE)?;
    // Linux bounds the wait at 100000 polls of 10 us. Sleep between polls
    // rather than spinning on the SI register.
    let deadline = narf_time::Deadline::after_ms(1000);
    let status = loop {
        let status = read(io, SI_BASE + SI_CS)?;
        if status & SI_CS_DONE_INT != 0 {
            break status;
        }
        if deadline.expired() {
            return Ok(None);
        }
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(20_000)).await;
    };
    write(io, SI_BASE + SI_CS, status)?; // Clear DONE_INT (write-one).
    if status & SI_CS_DONE_ERR != 0 {
        return Ok(None);
    }
    Ok(Some(read(io, SI_BASE + SI_RX_DATA0)? as u8))
}

/// `ath10k_pci_hif_fetch_cal_eeprom`. `Ok(None)` selects the Linux fallback
/// (board file plus OTP); only a complete checksum-valid image is returned.
pub(super) async fn fetch(
    io: &mut impl Ath10kMmio,
    registers: Registers,
    length: usize,
) -> Result<Option<Vec<u8>>, BmiError> {
    if length != QCA9887_CALIBRATION {
        return Ok(None);
    }
    let mut data = Vec::new();
    data.try_reserve_exact(length)
        .map_err(|_| BmiError::NoMemory)?;
    enable(io, registers)?;
    for address in 0..length as u16 {
        match byte(io, address).await? {
            Some(value) => data.push(value),
            None => return Ok(None),
        }
    }
    Ok(valid(&data).then_some(data))
}

#[cfg(feature = "kernel-test")]
pub(super) mod tests;
