// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE firmware image and paged MMIO download.
//!
//! Linux `rtl8192ee/sw.c::rtl92ee_init_sw_vars` requests
//! `rtlwifi/rtl8192eefw.bin` (no `alt_fw_name`, no separate WoWLAN image;
//! `max_fw_size = 0x8000`). `rtl8192ee/fw.c::rtl92ee_download_fw` strips the
//! 32-byte `rtlwifi_firmware_header` when `IS_FW_HEADER_EXIST`
//! (`signature & 0xfff0 == 0x92e0`) and writes the remainder as at most
//! eight 4 KiB pages at `FW_8192C_START_ADDRESS`.
//!
//! The filename is the authentication selector. The parser additionally
//! requires the header RAM-code size to equal the payload exactly (true for
//! the Linux-firmware image: header `0x7dfe`, payload 32254 bytes) and
//! rejects headerless, empty or oversized images before any register I/O.
//! Linux downloads a headerless image as raw code; that form is refused here
//! because nothing would then authenticate the image geometry.

use crate::rtlwifi::firmware_transport::{Error, Info, Io};

/// `sw.c:146`.
pub const FW_NORMAL: &str = "rtlwifi/rtl8192eefw.bin";

/// `sizeof(struct rtlwifi_firmware_header)`.
pub const HEADER: usize = 32;
/// `FW_8192C_PAGE_SIZE` (`rtl8192ee/fw.h`).
pub const PAGE: usize = 4096;
/// `_rtl92ee_write_fw` reports more than eight pages as an error; the
/// `max_fw_size` of `0x8000` bounds the image at eight pages.
pub const MAX_PAYLOAD: usize = PAGE * 8;
/// `FW_8192C_POLLING_TIMEOUT_COUNT`.
const POLL_COUNT: u32 = 3000;
/// `FW_8192C_POLLING_DELAY * 10` (us) between `WINTINI_RDY` reads.
const WINTINI_DELAY_US: u64 = 5 * 10;

/// `REG_MCUFWDL` and bits (`reg.h`).
pub const REG_MCUFWDL: u16 = 0x0080;
pub const MCUFWDL_EN: u8 = 1 << 0;
pub const MCUFWDL_RDY: u32 = 1 << 1;
pub const FWDL_CHKSUM_RPT: u32 = 1 << 2;
pub const WINTINI_RDY: u32 = 1 << 6;
pub const RAM_DL_SEL: u8 = 1 << 7;
/// `REG_SYS_FUNC_EN` / `REG_RSV_CTRL`.
pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_RSV_CTRL: u16 = 0x001c;
/// `FW_8192C_START_ADDRESS`.
const START: u16 = 0x1000;

/// Validate an RTL8192EE image header and return its payload.
pub fn parse(bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
    if bytes.len() <= HEADER {
        return Err(Error::Image);
    }
    let signature = u16::from_le_bytes([bytes[0], bytes[1]]);
    if signature & 0xfff0 != 0x92e0 {
        return Err(Error::Image);
    }
    let body = &bytes[HEADER..];
    if usize::from(u16::from_le_bytes([bytes[12], bytes[13]])) != body.len()
        || body.len() > MAX_PAYLOAD
    {
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

/// `rtl92ee_firmware_selfreset` (`fw.c`): `REG_RSV_CTRL+1` BIT0 and
/// `REG_SYS_FUNC_EN+1` BIT2 low, 50 us, both high.
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

/// `rtl92ee_download_fw` body after image selection. `mac_func_enable`
/// mirrors `rtlhal->mac_func_enable`: a running RAM image (`REG_MCUFWDL`
/// BIT7) is stopped and the 8051 self-reset first. Returns once
/// `WINTINI_RDY` is set; `Checksum` / `Start` report the two Linux
/// `_rtl92ee_fw_free_to_go` polling failures.
pub async fn download<I: Io + ?Sized>(
    io: &I,
    payload: &[u8],
    mac_func_enable: bool,
) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::Image);
    }
    if mac_func_enable && io.read8(REG_MCUFWDL)? & RAM_DL_SEL != 0 {
        io.write8(REG_MCUFWDL, 0)?;
        selfreset(io).await?;
    }
    // _rtl92ee_enable_fw_download(hw, true)
    io.write8(REG_MCUFWDL, 0x05)?;
    let value = io.read8(REG_MCUFWDL + 2)?;
    io.write8(REG_MCUFWDL + 2, value & 0xf7)?;
    // _rtl92ee_write_fw: rtl_fill_dummy pads the whole image to a dword,
    // then rtl_fw_page_write per full page (udelay(2) after each) and the
    // remainder page.
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
        if data.len() == PAGE {
            io.delay_us(2).await;
        }
    }
    // _rtl92ee_enable_fw_download(hw, false)
    let value = io.read8(REG_MCUFWDL)?;
    io.write8(REG_MCUFWDL, value & 0xfe)?;
    // _rtl92ee_fw_free_to_go: the checksum loop has no delay and succeeds
    // only while the post-incremented counter stays below the limit, i.e.
    // within the first POLL_COUNT - 1 reads.
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

/// Parse then download; returns the header info on `WINTINI_RDY`.
pub async fn load<I: Io + ?Sized>(
    io: &I,
    bytes: &[u8],
    mac_func_enable: bool,
) -> Result<Info, Error> {
    let (info, payload) = parse(bytes)?;
    download(io, payload, mac_func_enable).await?;
    Ok(info)
}
