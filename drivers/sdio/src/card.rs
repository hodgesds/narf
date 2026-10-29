// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned 3.3-V SDIO card lifecycle over standard SDHCI PIO. References:
//! Linux mmc/core/{sdio,sdio_ops,sdio_cis}.c and mmc/host/sdhci.c.

use crate::host::SdhciHost;
use crate::pio::{Controller, Data, Error as HostError, Registers, Response};
use crate::sdhci::{cmd::*, regs::*};
use crate::sdio::{
    cccr::*,
    function::{SdioError, SdioFunction},
};
use narf_time::Deadline;

const VDD_33: u32 = 0x0030_0000; // 3.2–3.4 V, matching POWER_330.
const MAX_CIS_BYTES: u32 = 1024;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Platform has a soldered card and no valid card-detect input.
    pub non_removable: bool,
    /// Board clock ceiling. Legacy timing stays at or below 25 MHz;
    /// negotiated SDIO high speed raises the card limit to 50 MHz.
    pub max_clock_hz: u32,
    /// Board wiring permits a 4-bit data bus (sdhci-pci `MMC_CAP_4_BIT_DATA`).
    pub four_bit: bool,
    /// Board permits SD high-speed timing (`MMC_CAP_SD_HIGHSPEED`, still
    /// gated by the controller's `CAN_DO_HISPD` capability).
    pub high_speed: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            non_removable: false,
            max_clock_hz: 25_000_000,
            four_bit: true,
            high_speed: true,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Host(HostError),
    Unsupported,
    NoCard,
    Cis,
    Response,
}
impl From<HostError> for Error {
    fn from(e: HostError) -> Self {
        Self::Host(e)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FunctionInfo {
    pub vendor: u16,
    pub device: u16,
    pub max_block_size: u16,
    pub enable_timeout_ms: u16,
}

/// Exclusively owns the controller and selected card. PIO copies finish
/// before return; no task or device retains a caller's transfer buffer.
#[derive(Debug)]
pub struct Card<R: Registers> {
    controller: Controller<R>,
    host: SdhciHost,
    functions: [FunctionInfo; 8],
    block_sizes: [u16; 8],
    enabled: u8,
}
impl<R: Registers> Drop for Card<R> {
    fn drop(&mut self) {
        let io = self.controller.registers();
        io.write32(SIGNAL_ENABLE, 0);
        io.write32(INT_ENABLE, 0);
        io.write16(CLOCK_CONTROL, 0);
        io.write8(POWER_CONTROL, 0);
    }
}
impl<R: Registers> Card<R> {
    /// Reset, power, negotiate CMD5, obtain RCA/select, and read bounded CIS.
    /// Consumes an exclusive standard-register aperture; failure powers down.
    pub fn initialize(io: R, config: Config) -> Result<Self, Error> {
        let mut card = Self {
            controller: Controller::new(io),
            host: SdhciHost::new(0, 0, 0, 0),
            functions: [FunctionInfo::default(); 8],
            block_sizes: [0; 8],
            enabled: 0,
        };
        card.start(config)?;
        Ok(card)
    }
    pub fn host(&self) -> &SdhciHost {
        &self.host
    }
    pub fn host_identity(&self) -> Option<crate::pio::HostIdentity> {
        self.controller.host_identity()
    }
    pub fn function(&self, number: u8) -> Option<FunctionInfo> {
        if number > self.host.func_count {
            None
        } else {
            Some(self.functions[number as usize])
        }
    }
    pub fn is_failed(&self) -> bool {
        self.controller.is_failed()
    }

    fn delay(us: u64) {
        let _ = narf_scheduler::responsive_spin_until(|| false, Deadline::after_us(us));
    }
    fn set_clock(&mut self, target: u32) -> Result<(), Error> {
        if target == 0 || self.host.clock_base_hz == 0 {
            return Err(Error::Unsupported);
        }
        let divisor = self.host.clock_divisor(target);
        // A saturated divider must not overclock an initialization/card limit.
        if u64::from(self.host.clock_base_hz) > u64::from(target) * u64::from(divisor) {
            return Err(Error::Unsupported);
        }
        let word = self.host.calc_clk_div(target) | CLK_INT_EN;
        self.controller.registers().write16(CLOCK_CONTROL, 0);
        self.controller.registers().write16(CLOCK_CONTROL, word);
        self.controller.wait(Deadline::after_us(150_000), |io| {
            let value = io.read16(CLOCK_CONTROL);
            if value == u16::MAX {
                Err(HostError::Gone)
            } else {
                Ok(value & CLK_INT_STABLE != 0)
            }
        })?;
        self.controller
            .registers()
            .write16(CLOCK_CONTROL, word | CLK_CARD_EN);
        self.host.current_clock_hz = self.host.clock_base_hz / divisor;
        Ok(())
    }
    fn start(&mut self, config: Config) -> Result<(), Error> {
        let io = self.controller.registers();
        io.write32(SIGNAL_ENABLE, 0);
        io.write32(INT_ENABLE, 0);
        io.write8(SOFTWARE_RESET, RESET_ALL);
        self.controller.wait(Deadline::after_us(100_000), |io| {
            let value = io.read8(SOFTWARE_RESET);
            if value == u8::MAX {
                Err(HostError::Gone)
            } else {
                Ok(value & RESET_ALL == 0)
            }
        })?;
        let io = self.controller.registers();
        let version = (io.read16(HOST_VERSION) & SPEC_VER_MASK) as u8;
        let caps = io.read32(CAPABILITIES);
        let caps1 = if version >= SPEC_300 as u8 {
            io.read32(CAPABILITIES_1)
        } else {
            0
        };
        if caps == u32::MAX || version > SPEC_400 as u8 || caps & CAPS_CAN_VDD_330 == 0 {
            return Err(Error::Unsupported);
        }
        self.host = SdhciHost::new(0, version, caps, caps1);
        if !config.non_removable && io.read32(PRESENT_STATE) & PS_CARD_PRESENT == 0 {
            return Err(Error::NoCard);
        }
        io.write8(HOST_CONTROL, 0); // 1-bit, legacy timing; DMA disabled in transfers.
        if version >= SPEC_300 as u8 {
            io.write16(HOST_CONTROL2, 0);
        }
        io.write8(POWER_CONTROL, POWER_330);
        io.write8(POWER_CONTROL, POWER_330 | POWER_ON);
        Self::delay(10_000);
        // Enable status latches while leaving all interrupt signalling off.
        let io = self.controller.registers();
        io.write32(INT_STATUS, INT_ALL_MASK);
        io.write32(
            INT_ENABLE,
            INT_CMD_MASK | INT_DATA_MASK | INT_ERROR | INT_BUS_POWER | INT_AUTO_CMD_ERR,
        );
        self.set_clock(400_000)?;
        Self::delay(1_000); // >74 initialization clocks at 400 kHz.
        self.controller.execute(0, 0, Response::None, None)?;
        let query = self.controller.execute(5, 0, Response::R4, None)?;
        let count = ((query & OCR_FUNC_COUNT_MASK) >> OCR_FUNC_COUNT_SHIFT) as u8;
        let voltage = query & VDD_33;
        if count == 0 || voltage == 0 || query & OCR_MEM_PRESENT != 0 {
            return Err(Error::Unsupported);
        }
        let mut outcome = Ok(0);
        let ready = narf_scheduler::responsive_spin_until(
            || {
                outcome = self.controller.execute(5, voltage, Response::R4, None);
                match outcome {
                    Ok(value) => value & OCR_CARD_READY != 0,
                    Err(_) => true,
                }
            },
            Deadline::after_us(1_000_000),
        );
        let ocr = outcome?;
        if !ready || ocr & OCR_CARD_READY == 0 {
            return Err(Error::Host(HostError::Timeout));
        }
        if ((ocr & OCR_FUNC_COUNT_MASK) >> OCR_FUNC_COUNT_SHIFT) as u8 != count {
            return Err(Error::Response);
        }
        self.host.ocr = ocr;
        self.host.func_count = count;
        let rca = self.controller.execute(3, 0, Response::Short, None)?;
        if rca & 0xe000 != 0 || rca >> 16 == 0 {
            return Err(Error::Response);
        }
        self.host.rca = (rca >> 16) as u16;
        let status = self
            .controller
            .execute(7, rca & 0xffff_0000, Response::Busy, None)?;
        if status & 0xfdff_e008 != 0 {
            return Err(Error::Response);
        }
        self.host.card_selected = true;
        let revision = self
            .direct(false, 0, CCCR_SDIO_REVISION, 0)
            .map_err(|_| Error::Response)?;
        if revision & SDIO_REV_MASK > SDIO_REV_3_00 {
            return Err(Error::Unsupported);
        }
        // No interrupt consumer is installed by the host; clients poll boundedly.
        self.direct(true, 0, CCCR_INT_ENABLE, 0)
            .map_err(|_| Error::Response)?;
        // A host reset need not reset a soldered card's always-on supply.
        // Retire inherited function/F2 state before a new firmware owner.
        self.direct(true, 0, CCCR_IO_ENABLE, 0)
            .map_err(|_| Error::Response)?;
        let (common, max_rate) = self.read_cis(0, revision & SDIO_REV_MASK)?;
        self.functions[0] = common;
        for function in 1..=count {
            let (mut info, _) = self.read_cis(function, revision & SDIO_REV_MASK)?;
            if info.vendor == 0 {
                info.vendor = common.vendor;
                info.device = common.device;
            }
            self.functions[function as usize] = info;
        }
        // mmc_sdio_init_card after the CIS: sdio_read_cccr capability bits,
        // sdio_enable_hs, mmc_sdio_get_max_clock, sdio_enable_4bit_bus.
        let capability = self
            .direct(false, 0, CCCR_CARD_CAPABILITY, 0)
            .map_err(|_| Error::Response)?;
        let mut high_speed = false;
        if config.high_speed
            && self.host.can_do_hispeed()
            && revision & SDIO_REV_MASK >= SDIO_REV_1_20
        {
            let speed = self
                .direct(false, 0, CCCR_HIGH_SPEED, 0)
                .map_err(|_| Error::Response)?;
            if speed & HIGH_SPEED_SHS != 0 {
                self.direct(true, 0, CCCR_HIGH_SPEED, speed | HIGH_SPEED_EHS)
                    .map_err(|_| Error::Response)?;
                let io = self.controller.registers();
                let control = io.read8(HOST_CONTROL);
                io.write8(HOST_CONTROL, control | CTRL_HISPD);
                high_speed = true;
            }
        }
        // High speed makes 50 MHz mandatory; legacy timing keeps the CIS rate.
        let card_limit = if high_speed {
            50_000_000
        } else {
            max_rate.min(25_000_000)
        };
        self.set_clock(config.max_clock_hz.min(card_limit))?;
        // sdio_enable_wide: not for a low-speed card without 4BLS.
        if config.four_bit && (capability & CARD_CAP_LSC == 0 || capability & CARD_CAP_4BLS != 0) {
            let ctrl = self
                .direct(false, 0, CCCR_BUS_IFACE, 0)
                .map_err(|_| Error::Response)?;
            self.direct(
                true,
                0,
                CCCR_BUS_IFACE,
                (ctrl & !BUS_IFACE_BW_MASK) | BUS_IFACE_BW_4BIT,
            )
            .map_err(|_| Error::Response)?;
            let io = self.controller.registers();
            let control = io.read8(HOST_CONTROL);
            io.write8(HOST_CONTROL, control | CTRL_4BITBUS);
            self.host.bus_width = 4;
        }
        self.host.high_speed = high_speed;
        Ok(())
    }
    fn direct(&mut self, write: bool, func: u8, addr: u32, value: u8) -> Result<u8, SdioError> {
        if func > self.host.func_count {
            return Err(SdioError::BadFunction);
        }
        if addr > 0x1ffff {
            return Err(SdioError::AddressOverflow);
        }
        self.controller
            .execute(
                52,
                cmd52_arg(write, func, false, addr, value),
                Response::R5,
                None,
            )
            .map(r5_data)
            .map_err(map_error)
    }
    fn read_cis(&mut self, function: u8, revision: u8) -> Result<(FunctionInfo, u32), Error> {
        let mut byte = |address| {
            self.direct(false, 0, address, 0)
                .map_err(|_| Error::Response)
        };
        let base = fbr_base(function) + FBR_CIS_PTR_0;
        let mut address = cis_ptr_from_bytes(byte(base)?, byte(base + 1)?, byte(base + 2)?);
        if !(0x1000..=0x1ffff).contains(&address) {
            return Err(Error::Cis);
        }
        let end = address.saturating_add(MAX_CIS_BYTES).min(0x20000);
        let mut info = FunctionInfo {
            enable_timeout_ms: 1000,
            ..FunctionInfo::default()
        };
        let mut rate = 0;
        let mut found = false;
        while address < end {
            let code = byte(address)?;
            address += 1;
            if code == CISTPL_END {
                return if found {
                    Ok((info, rate))
                } else {
                    Err(Error::Cis)
                };
            }
            if code == CISTPL_NULL {
                continue;
            }
            if address >= end {
                return Err(Error::Cis);
            }
            let len = u32::from(byte(address)?);
            address += 1;
            if address.checked_add(len).filter(|v| *v <= end).is_none() {
                return Err(Error::Cis);
            }
            if code == CISTPL_MANFID && len >= 4 {
                info.vendor = u16::from_le_bytes([byte(address)?, byte(address + 1)?]);
                info.device = u16::from_le_bytes([byte(address + 2)?, byte(address + 3)?]);
            }
            if code == CISTPL_FUNCE && function == 0 && len >= 4 && byte(address)? == 0 {
                info.max_block_size = u16::from_le_bytes([byte(address + 1)?, byte(address + 2)?]);
                let speed = byte(address + 3)?;
                const VALUES: [u32; 16] = [
                    0, 10, 12, 13, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80,
                ];
                const UNITS: [u32; 8] = [10_000, 100_000, 1_000_000, 10_000_000, 0, 0, 0, 0];
                rate = VALUES[((speed >> 3) & 15) as usize] * UNITS[(speed & 7) as usize];
                found = info.max_block_size != 0 && rate != 0;
            } else if code == CISTPL_FUNCE && function != 0 && len != 0 && byte(address)? == 1 {
                let minimum = if revision == SDIO_REV_1_00 { 28 } else { 42 };
                if len < minimum {
                    return Err(Error::Cis);
                }
                info.max_block_size =
                    u16::from_le_bytes([byte(address + 12)?, byte(address + 13)?]);
                if revision != SDIO_REV_1_00 {
                    let ms = u16::from_le_bytes([byte(address + 28)?, byte(address + 29)?]);
                    info.enable_timeout_ms = ms.saturating_mul(10).max(1000);
                }
                found = info.max_block_size != 0;
            }
            address += len;
        }
        Err(Error::Cis)
    }
    fn transfer(
        &mut self,
        func: u8,
        addr: u32,
        increment: bool,
        block_mode: bool,
        data: Data<'_>,
    ) -> Result<(), SdioError> {
        if func == 0 || func > self.host.func_count {
            return Err(SdioError::BadFunction);
        }
        if self.enabled & (1 << func) == 0 {
            return Err(SdioError::NotEnabled);
        }
        let (len, block, write) = match &data {
            Data::Read { bytes, block_size } => (bytes.len(), *block_size, false),
            Data::Write { bytes, block_size } => (bytes.len(), *block_size, true),
        };
        if addr > 0x1ffff || (increment && len > (0x20000 - addr) as usize) {
            return Err(SdioError::AddressOverflow);
        }
        if len == 0
            || len > crate::pio::MAX_TRANSFER
            || block == 0
            || block > 512
            || block > self.functions[func as usize].max_block_size
            || len % usize::from(block) != 0
            || len / usize::from(block) > 511
            || (!block_mode && len > 512)
            || (block_mode && self.block_sizes[func as usize] != block)
        {
            return Err(SdioError::LengthOverflow);
        }
        let count = if block_mode {
            len / usize::from(block)
        } else {
            len & 511
        } as u16;
        let argument = cmd53_arg(write, func, block_mode, increment, addr, count);
        self.controller
            .execute(53, argument, Response::R5, Some(data))
            .map(|_| ())
            .map_err(map_error)
    }
}
fn map_error(error: HostError) -> SdioError {
    match error {
        HostError::Card(flags) => SdioError::ResponseError(flags),
        _ => SdioError::HostError,
    }
}
impl<R: Registers> SdioFunction for Card<R> {
    fn cmd52_read(&mut self, func: u8, addr: u32) -> Result<u8, SdioError> {
        self.direct(false, func, addr, 0)
    }
    fn cmd52_write(&mut self, func: u8, addr: u32, val: u8) -> Result<(), SdioError> {
        self.direct(true, func, addr, val).map(|_| ())
    }
    fn cmd53_read(&mut self, func: u8, addr: u32, buf: &mut [u8]) -> Result<(), SdioError> {
        let size = u16::try_from(buf.len()).map_err(|_| SdioError::LengthOverflow)?;
        self.transfer(
            func,
            addr,
            true,
            false,
            Data::Read {
                bytes: buf,
                block_size: size,
            },
        )
    }
    fn cmd53_write(&mut self, func: u8, addr: u32, buf: &[u8]) -> Result<(), SdioError> {
        let size = u16::try_from(buf.len()).map_err(|_| SdioError::LengthOverflow)?;
        self.transfer(
            func,
            addr,
            true,
            false,
            Data::Write {
                bytes: buf,
                block_size: size,
            },
        )
    }
    fn cmd53_read_fixed(&mut self, func: u8, addr: u32, buf: &mut [u8]) -> Result<(), SdioError> {
        let size = u16::try_from(buf.len()).map_err(|_| SdioError::LengthOverflow)?;
        self.transfer(
            func,
            addr,
            false,
            false,
            Data::Read {
                bytes: buf,
                block_size: size,
            },
        )
    }
    fn cmd53_block_read(
        &mut self,
        func: u8,
        addr: u32,
        size: u16,
        count: u16,
        buf: &mut [u8],
    ) -> Result<(), SdioError> {
        if usize::from(size) * usize::from(count) != buf.len() {
            return Err(SdioError::LengthOverflow);
        }
        self.transfer(
            func,
            addr,
            true,
            true,
            Data::Read {
                bytes: buf,
                block_size: size,
            },
        )
    }
    fn cmd53_block_write(
        &mut self,
        func: u8,
        addr: u32,
        size: u16,
        count: u16,
        buf: &[u8],
    ) -> Result<(), SdioError> {
        if usize::from(size) * usize::from(count) != buf.len() {
            return Err(SdioError::LengthOverflow);
        }
        self.transfer(
            func,
            addr,
            true,
            true,
            Data::Write {
                bytes: buf,
                block_size: size,
            },
        )
    }
    fn set_block_size(&mut self, func: u8, size: u16) -> Result<(), SdioError> {
        if func == 0 || func > self.host.func_count {
            return Err(SdioError::BadFunction);
        }
        if size == 0
            || u32::from(size) > self.host.max_block_size()
            || size > 512
            || size > self.functions[func as usize].max_block_size
        {
            return Err(SdioError::LengthOverflow);
        }
        self.direct(true, 0, fbr_base(func) + FBR_BLKSZ_0, size as u8)?;
        self.direct(true, 0, fbr_base(func) + FBR_BLKSZ_1, (size >> 8) as u8)?;
        self.block_sizes[func as usize] = size;
        Ok(())
    }
    fn enable_func(&mut self, func: u8) -> Result<(), SdioError> {
        if func == 0 || func > self.host.func_count {
            return Err(SdioError::BadFunction);
        }
        let value = self.direct(false, 0, CCCR_IO_ENABLE, 0)?;
        self.direct(true, 0, CCCR_IO_ENABLE, value | (1 << func))?;
        let mut error = None;
        let deadline =
            Deadline::after_us(u64::from(self.functions[func as usize].enable_timeout_ms) * 1000);
        let ready = narf_scheduler::responsive_spin_until(
            || match self.direct(false, 0, CCCR_IO_READY, 0) {
                Ok(value) => value & (1 << func) != 0,
                Err(e) => {
                    error = Some(e);
                    true
                }
            },
            deadline,
        );
        if let Some(e) = error {
            return Err(e);
        }
        if !ready {
            return Err(SdioError::NotEnabled);
        }
        self.enabled |= 1 << func;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "card_tests.rs"]
pub mod tests;
