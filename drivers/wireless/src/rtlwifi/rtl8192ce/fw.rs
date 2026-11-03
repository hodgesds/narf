// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE firmware image and paged MMIO download.
//!
//! `rtl8192ce/sw.c::rtl92c_init_sw_vars` selects one of
//! `rtl8192cfw.bin` / `rtl8192cfwU.bin` / `rtl8192cfwU_B.bin` from the chip
//! version ([`super::version::Version::firmware`]) with `max_fw_size =
//! 0x4000` (the whole file, `core.c::rtl_fw_cb`). `rtl8192c/fw_common.c::
//! rtl92c_download_fw` strips the 32-byte header when `IS_FW_HEADER_EXIST`
//! (`signature & 0xfff0` is `0x92c0` or `0x88c0`) and, for a normal chip,
//! writes the remainder as at most four 4 KiB pages.
//!
//! The filename (bound to the measured chip version by the owner) is the
//! authentication selector. The parser additionally requires the header
//! RAM-code size to equal the payload exactly (true for the Linux-firmware
//! images: `rtl8192cfw.bin` `0x3f20`, `rtl8192cfwU.bin` `0x39c2`,
//! `rtl8192cfwU_B.bin` `0x3fac`) and rejects headerless, empty or oversized
//! images before any register I/O.
//!
//! Linux's `rtl92c_download_fw` logs a `_rtl92c_fw_free_to_go` failure and
//! still returns 0; here a missing checksum report or `WINTINI_RDY` is an
//! error, so nothing downstream runs over a CPU that never started.

use crate::rtlwifi::firmware_transport::{Error, Info, Io};

/// `sizeof(struct rtlwifi_firmware_header)`.
pub const HEADER: usize = 32;
/// `FW_8192C_PAGE_SIZE`.
pub const PAGE: usize = 4096;
/// `rtlpriv->max_fw_size` bounds the whole file.
pub const MAX_FILE: usize = 0x4000;
/// Largest admitted RAM-code payload.
pub const MAX_PAYLOAD: usize = MAX_FILE - HEADER;
/// `FW_8192C_POLLING_TIMEOUT_COUNT`.
const POLL_COUNT: u32 = 100;
/// `mdelay(FW_8192C_POLLING_DELAY)` between `WINTINI_RDY` reads.
const WINTINI_DELAY_US: u64 = 5 * 1000;
/// `rtl92c_firmware_selfreset`: `u8 delay = 100`, `udelay(50)`.
const SELFRESET_TRIES: u32 = 100;

/// `REG_MCUFWDL` and bits (`reg.h`).
pub const REG_MCUFWDL: u16 = 0x0080;
pub const MCUFWDL_EN: u8 = 1 << 0;
pub const MCUFWDL_RDY: u32 = 1 << 1;
pub const FWDL_CHKSUM_RPT: u32 = 1 << 2;
pub const WINTINI_RDY: u32 = 1 << 6;
pub const RAM_DL_SEL: u8 = 1 << 7;
/// `REG_SYS_FUNC_EN`, `REG_HMETFR`.
pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_HMETFR: u16 = 0x01cc;
/// `FW_8192C_START_ADDRESS`.
const START: u16 = 0x1000;

/// Validate an RTL8192C-family PCI image header and return its payload.
pub fn parse(bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
    if bytes.len() <= HEADER || bytes.len() > MAX_FILE {
        return Err(Error::Image);
    }
    let signature = u16::from_le_bytes([bytes[0], bytes[1]]) & 0xfff0;
    if signature != 0x92c0 && signature != 0x88c0 {
        return Err(Error::Image);
    }
    let body = &bytes[HEADER..];
    if usize::from(u16::from_le_bytes([bytes[12], bytes[13]])) != body.len() {
        return Err(Error::Image);
    }
    Ok((
        Info {
            version: u16::from_le_bytes([bytes[4], bytes[5]]),
            subversion: bytes[6],
            payload: body.len(),
        },
        body,
    ))
}

/// `rtl92c_firmware_selfreset`: ask the running 8051 to reset
/// (`REG_HMETFR+3 = 0x20`) and wait up to 100 × 50 us for
/// `REG_SYS_FUNC_EN+1` BIT2 to drop. Linux only `WARN_ONCE`s on expiry; the
/// caller's subsequent download then runs regardless, as here.
pub async fn selfreset<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    io.write8(REG_HMETFR + 3, 0x20)?;
    let mut value = io.read8(REG_SYS_FUNC_EN + 1)?;
    let mut tries = SELFRESET_TRIES;
    while value & (1 << 2) != 0 {
        tries -= 1;
        if tries == 0 {
            break;
        }
        io.delay_us(50).await;
        value = io.read8(REG_SYS_FUNC_EN + 1)?;
    }
    Ok(())
}

fn mcu32<I: Io + ?Sized>(io: &I) -> Result<u32, Error> {
    let value = io.read32(REG_MCUFWDL)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    Ok(value)
}

/// Stop a still-running RAM image the way `_rtl92ce_poweroff_adapter` does
/// before a later `rtl92ce_hw_init` (`REG_MCUFWDL` BIT7 ⇒
/// `rtl92c_firmware_selfreset`, then `REG_MCUFWDL = 0`). Probe does not power
/// the adapter off, so the owner runs this ahead of the download.
pub async fn stop_running<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    if io.read8(REG_MCUFWDL)? & RAM_DL_SEL != 0 {
        selfreset(io).await?;
        io.write8(REG_MCUFWDL, 0)?;
    }
    Ok(())
}

/// `rtl92c_download_fw` for a normal (`CHIP_VER_B`) RTL8192CE-family chip.
/// Returns once `WINTINI_RDY` is set; `Checksum` / `Start` report the two
/// `_rtl92c_fw_free_to_go` polling failures.
pub async fn download<I: Io + ?Sized>(io: &I, payload: &[u8]) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::Image);
    }
    // _rtl92c_enable_fw_download(hw, true), HARDWARE_TYPE_RTL8192CE.
    let value = io.read8(REG_SYS_FUNC_EN + 1)?;
    io.write8(REG_SYS_FUNC_EN + 1, value | 0x04)?;
    let value = io.read8(REG_MCUFWDL)?;
    io.write8(REG_MCUFWDL, value | 0x01)?;
    let value = io.read8(REG_MCUFWDL + 2)?;
    io.write8(REG_MCUFWDL + 2, value & 0xf7)?;
    // _rtl92c_write_fw: rtl_fill_dummy pads the image to a dword, then
    // rtl_fw_page_write per full page and the remainder page (no delay).
    for (page, data) in payload.chunks(PAGE).enumerate() {
        let value = io.read8(REG_MCUFWDL + 2)?;
        io.write8(REG_MCUFWDL + 2, (value & 0xf8) | (page as u8 & 7))?;
        for (offset, chunk) in data.chunks(256).enumerate() {
            io.write_bytes(START + (offset * 256) as u16, chunk)?;
        }
        let pad = data.len().next_multiple_of(4) - data.len();
        if pad != 0 {
            io.write_bytes(START + data.len() as u16, &[0; 3][..pad])?;
        }
    }
    // _rtl92c_enable_fw_download(hw, false).
    let value = io.read8(REG_MCUFWDL)?;
    io.write8(REG_MCUFWDL, value & 0xfe)?;
    io.write8(REG_MCUFWDL + 1, 0x00)?;
    // _rtl92c_fw_free_to_go: undelayed checksum reads succeed only while the
    // post-incremented counter stays below the limit (first 99 reads).
    let mut ok = false;
    for _ in 1..POLL_COUNT {
        if mcu32(io)? & FWDL_CHKSUM_RPT != 0 {
            ok = true;
            break;
        }
        io.delay_us(0).await;
    }
    if !ok {
        return Err(Error::Checksum);
    }
    let value = mcu32(io)?;
    io.write32(REG_MCUFWDL, (value | MCUFWDL_RDY) & !WINTINI_RDY)?;
    for _ in 0..=POLL_COUNT {
        if mcu32(io)? & WINTINI_RDY != 0 {
            return Ok(());
        }
        io.delay_us(WINTINI_DELAY_US).await;
    }
    Err(Error::Start)
}
