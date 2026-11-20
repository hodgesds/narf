// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE firmware image and paged MMIO download.
//!
//! `rtl8723be/sw.c::rtl8723be_init_sw_vars` requests
//! `rtl8723befw_36.bin` (`alt_fw_name` `rtl8723befw.bin`) with
//! `max_fw_size = 0x8000`. `rtl8723com/fw_common.c::rtl8723_download_fw`
//! (`is_8723be = true`, `max_count = FW_8723B_POLLING_TIMEOUT_COUNT`)
//! strips the 32-byte header when `is_fw_header` (`signature & 0xfff0 ==
//! 0x5300`), self-resets a still-running RAM image
//! (`rtl8723be_firmware_selfreset`, then `REG_MCUFWDL = 0`), writes at most
//! eight 4 KiB pages and runs `rtl8723_fw_free_to_go` with the
//! 8723BE 8051 reset between the `MCUFWDL_RDY` handshake and the
//! `WINTINI_RDY` poll.
//!
//! The registered filename is the authentication selector. The parser also
//! requires the header RAM-code size to equal the payload exactly (true for
//! the linux-firmware images: `rtl8723befw_36.bin` `0x7bf2`,
//! `rtl8723befw.bin` `0x77fa`) and rejects headerless, empty or oversized
//! images before any register I/O.
//!
//! Linux logs a `rtl8723_fw_free_to_go` failure and still returns 0 from
//! `rtl8723_download_fw`; here a missing checksum report or `WINTINI_RDY`
//! is an error, so nothing downstream runs over a CPU that never started.

use crate::rtlwifi::firmware_transport::{Error, Info, Io};

/// `sizeof(struct rtlwifi_firmware_header)`.
pub const HEADER: usize = 32;
/// `FW_8192C_PAGE_SIZE`.
pub const PAGE: usize = 4096;
/// `rtlpriv->max_fw_size` bounds the whole file.
pub const MAX_FILE: usize = 0x8000;
/// `max_page = 8` for `is_8723be`.
pub const MAX_PAGES: usize = 8;
/// Largest admitted RAM-code payload.
pub const MAX_PAYLOAD: usize = MAX_FILE - HEADER;
/// `FW_8723B_POLLING_TIMEOUT_COUNT`.
pub const POLL_COUNT: u32 = 6000;
/// `mdelay(FW_8192C_POLLING_DELAY)` between `WINTINI_RDY` reads.
pub const WINTINI_DELAY_US: u64 = 5 * 1000;

/// `REG_MCUFWDL` and bits (`reg.h`).
pub const REG_MCUFWDL: u16 = 0x0080;
pub const MCUFWDL_EN: u8 = 1 << 0;
pub const MCUFWDL_RDY: u32 = 1 << 1;
pub const FWDL_CHKSUM_RPT: u32 = 1 << 2;
pub const WINTINI_RDY: u32 = 1 << 6;
pub const RAM_DL_SEL: u8 = 1 << 7;
/// `REG_SYS_FUNC_EN`, `REG_RSV_CTRL`.
pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_RSV_CTRL: u16 = 0x001c;
/// `FW_8192C_START_ADDRESS`.
const START: u16 = 0x1000;

/// Validate an RTL8723BE PCI image header and return its payload.
pub fn parse(bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
    if bytes.len() <= HEADER || bytes.len() > MAX_FILE {
        return Err(Error::Image);
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) & 0xfff0 != 0x5300 {
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

/// `rtl8723be_firmware_selfreset`: pulse `REG_RSV_CTRL+1` BIT0 and
/// `REG_SYS_FUNC_EN+1` BIT2 (8051 reset) low for 50 us.
pub async fn selfreset<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    let value = io.read8(REG_RSV_CTRL + 1)?;
    io.write8(REG_RSV_CTRL + 1, value & !1)?;
    let value = io.read8(REG_SYS_FUNC_EN + 1)?;
    io.write8(REG_SYS_FUNC_EN + 1, value & !(1 << 2))?;
    io.delay_us(50).await;
    let value = io.read8(REG_RSV_CTRL + 1)?;
    io.write8(REG_RSV_CTRL + 1, value | 1)?;
    let value = io.read8(REG_SYS_FUNC_EN + 1)?;
    io.write8(REG_SYS_FUNC_EN + 1, value | (1 << 2))
}

fn mcu32<I: Io + ?Sized>(io: &I) -> Result<u32, Error> {
    let value = io.read32(REG_MCUFWDL)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    Ok(value)
}

/// `rtl8723_download_fw(hw, true, FW_8723B_POLLING_TIMEOUT_COUNT)`.
/// Returns once `WINTINI_RDY` is set; `Checksum` / `Start` report the two
/// `rtl8723_fw_free_to_go` polling failures.
pub async fn download<I: Io + ?Sized>(io: &I, payload: &[u8]) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::Image);
    }
    // A still-running RAM image: rtl8723be_firmware_selfreset, MCUFWDL = 0.
    if io.read8(REG_MCUFWDL)? & RAM_DL_SEL != 0 {
        selfreset(io).await?;
        io.write8(REG_MCUFWDL, 0)?;
    }
    // rtl8723_enable_fw_download(hw, true).
    let value = io.read8(REG_SYS_FUNC_EN + 1)?;
    io.write8(REG_SYS_FUNC_EN + 1, value | 0x04)?;
    let value = io.read8(REG_MCUFWDL)?;
    io.write8(REG_MCUFWDL, value | 0x01)?;
    let value = io.read8(REG_MCUFWDL + 2)?;
    io.write8(REG_MCUFWDL + 2, value & 0xf7)?;
    // rtl8723_write_fw: rtl_fill_dummy pads the image to a dword, then
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
    // rtl8723_enable_fw_download(hw, false).
    let value = io.read8(REG_MCUFWDL)?;
    io.write8(REG_MCUFWDL, value & 0xfe)?;
    io.write8(REG_MCUFWDL + 1, 0x00)?;
    // rtl8723_fw_free_to_go: undelayed checksum reads succeed only while the
    // post-incremented counter stays below max_count.
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
    selfreset(io).await?;
    for _ in 0..=POLL_COUNT {
        if mcu32(io)? & WINTINI_RDY != 0 {
            return Ok(());
        }
        io.delay_us(WINTINI_DELAY_US).await;
    }
    Err(Error::Start)
}
