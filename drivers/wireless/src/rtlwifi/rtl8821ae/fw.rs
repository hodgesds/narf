// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE firmware images and paged MMIO download.
//!
//! Linux `rtl8821ae/sw.c::rtl8821ae_init_sw_vars` requests
//! `rtlwifi/rtl8821aefw_29.bin` (falling back to `alt_fw_name`
//! `rtlwifi/rtl8821aefw.bin`) and, separately, the WoWLAN image
//! `rtlwifi/rtl8821aefw_wowlan.bin`. `rtl8821ae/fw.c::rtl8821ae_download_fw`
//! strips the 32-byte `rtlwifi_firmware_header` when
//! `IS_FW_HEADER_EXIST_8821` (`signature & 0xfff0 == 0x2100`) and writes the
//! remainder as at most eight 4 KiB pages at `0x1000`.
//!
//! Filenames are the authentication selector; the signature alone does not
//! distinguish the normal from the WoWLAN image. The parser additionally
//! requires the header RAM-code size to equal the payload exactly (true for
//! all three Linux-firmware images) and rejects empty or oversized images
//! before any register I/O.

use crate::rtlwifi::firmware_transport::{Error, Info, Io};

/// Primary normal-mode image (`sw.c:179`).
pub const FW_NORMAL: &str = "rtlwifi/rtl8821aefw_29.bin";
/// `rtl8821ae_hal_cfg.alt_fw_name` (`sw.c:296`).
pub const FW_NORMAL_ALT: &str = "rtlwifi/rtl8821aefw.bin";
/// WoWLAN image (`sw.c:180`).
pub const FW_WOWLAN: &str = "rtlwifi/rtl8821aefw_wowlan.bin";

/// `sizeof(struct rtlwifi_firmware_header)`.
pub const HEADER: usize = 32;
/// `FW_8821AE_PAGE_SIZE`.
pub const PAGE: usize = 4096;
/// `_rtl8821ae_write_fw` refuses more than eight pages.
pub const MAX_PAYLOAD: usize = PAGE * 8;
/// `FW_8821AE_POLLING_TIMEOUT_COUNT`.
const POLL_COUNT: u32 = 6000;
/// `FW_8821AE_POLLING_DELAY` (us).
const POLL_DELAY_US: u64 = 5;

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
/// `REG_HMETFR` — H2C mailbox busy bits.
pub const REG_HMETFR: u16 = 0x01cc;
/// `FW_8821AE_START_ADDRESS`.
const START: u16 = 0x1000;

/// Which of the two images a bounded attempt downloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Image {
    Normal,
    Wowlan,
}

impl Image {
    /// Registry names tried in Linux order.
    pub const fn names(self) -> &'static [&'static str] {
        match self {
            Self::Normal => &[FW_NORMAL, FW_NORMAL_ALT],
            Self::Wowlan => &[FW_WOWLAN],
        }
    }
}

/// Validate an RTL8821AE image header and return its payload.
pub fn parse(bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
    if bytes.len() <= HEADER {
        return Err(Error::Image);
    }
    let signature = u16::from_le_bytes([bytes[0], bytes[1]]);
    if signature & 0xfff0 != 0x2100 {
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

/// `rtl8821ae_firmware_selfreset` (8821A branch: `REG_RSV_CTRL+1` BIT0).
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

/// `_rtl8821ae_wait_for_h2c_cmd_finish`: wait until the four H2C mailbox
/// busy bits clear (bounded at 1000 x 1 ms) before replacing the image.
pub async fn wait_h2c_idle<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    for _ in 0..1000 {
        let value = io.read8(REG_HMETFR)?;
        io.delay_us(1000).await;
        if value & 0x0f == 0 {
            return Ok(());
        }
    }
    Err(Error::Deadline)
}

fn mcu32<I: Io + ?Sized>(io: &I) -> Result<u32, Error> {
    let value = io.read32(REG_MCUFWDL)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    Ok(value)
}

/// `rtl8821ae_download_fw` body after image selection. `mac_func_enable`
/// mirrors `rtlhal->mac_func_enable`: a running RAM image (`RAM_DL_SEL`) is
/// stopped and the 8051 self-reset first. Returns once `WINTINI_RDY` is set;
/// `Checksum` / `Start` report the two Linux polling failures.
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
    // _rtl8821ae_enable_fw_download(hw, true)
    io.write8(REG_MCUFWDL, 0x05)?;
    let value = io.read8(REG_MCUFWDL + 2)?;
    io.write8(REG_MCUFWDL + 2, value & 0xf7)?;
    io.read8(REG_MCUFWDL)?;
    // _rtl8821ae_write_fw: rtl_fw_page_write per page, rtl_fill_dummy pad.
    for (page, data) in payload.chunks(PAGE).enumerate() {
        let value = io.read8(REG_MCUFWDL + 2)?;
        io.write8(REG_MCUFWDL + 2, (value & 0xf8) | (page as u8 & 7))?;
        for (offset, chunk) in data.chunks(256).enumerate() {
            io.write_bytes(START + (offset * 256) as u16, chunk)?;
            io.delay_us(0).await;
        }
        let pad = data.len().next_multiple_of(4) - data.len();
        if pad != 0 {
            io.write_bytes(START + data.len() as u16, &[0; 3][..pad])?;
        }
    }
    // _rtl8821ae_enable_fw_download(hw, false)
    let value = io.read8(REG_MCUFWDL)?;
    io.write8(REG_MCUFWDL, value & !MCUFWDL_EN)?;
    io.read8(REG_MCUFWDL)?;
    // _rtl8821ae_fw_free_to_go
    let mut ok = false;
    for _ in 0..POLL_COUNT {
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
        io.delay_us(POLL_DELAY_US).await;
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
