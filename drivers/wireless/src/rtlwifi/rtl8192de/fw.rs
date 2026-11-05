// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE firmware image and paged MMIO download.
//!
//! `rtl8192de/sw.c::rtl92d_init_sw_vars` requests the single image
//! `rtlwifi/rtl8192defw.bin` with `max_fw_size = 0x8000` (no alt name,
//! no chip-version selection). `rtl8192d/fw_common.c` +
//! `rtl8192de/fw.c::rtl92d_download_fw` strip the 32-byte header when
//! `IS_FW_HEADER_EXIST` holds, coordinate the two MACs through register
//! `0x1f` bit 5 (the second function waits for the first function's
//! download instead of racing it), self-reset a still-running RAM image,
//! write at most eight 4 KiB pages and run `rtl92d_fw_free_to_go`.
//!
//! The registered filename is the authentication selector. The parser
//! also requires the header RAM-code size to equal the payload exactly
//! (the `rtl8192ce` profile's rule for this same `0x92c0`/`0x88c0`
//! signature family) and rejects headerless, empty or oversized images
//! before any register I/O.
//!
//! Linux logs a `rtl92d_fw_free_to_go` failure and still runs
//! `rtl92d_fw_init`; here a missing checksum report is an error, so
//! nothing downstream runs over a CPU that never started. Linux also
//! takes over the download after the 5000-read wait even if the other
//! MAC is still in process; here that case is a deadline error rather
//! than a race on the shared page writer. Linux's self-reset only
//! warns on a stuck 8051; here it is an error for the same reason.

use crate::rtlwifi::firmware_transport::{Error, Info, Io};

/// `sizeof(struct rtlwifi_firmware_header)`.
pub const HEADER: usize = 32;
/// `FW_8192D_PAGE_SIZE`.
pub const PAGE: usize = 4096;
/// `rtlpriv->max_fw_size` bounds the whole file.
pub const MAX_FILE: usize = 0x8000;
/// `max_page = 8` (`rtl92d_write_fw` warns past eight pages; here it
/// refuses, so no page-select wrap can alias an earlier page).
pub const MAX_PAGES: usize = 8;
/// Largest admitted RAM-code payload.
pub const MAX_PAYLOAD: usize = MAX_FILE - HEADER;
/// `FW_8192D_POLLING_TIMEOUT_COUNT` (checksum reads).
pub const POLL_CHECKSUM: u32 = 1000;
/// `POLLING_READY_TIMEOUT_COUNT` (firmware-ready reads).
pub const POLL_READY: u32 = 1000;
/// Dual-MAC wait iterations while the other function downloads.
pub const WAIT_IN_PROCESS: u32 = 5000;
/// `udelay(500)` between dual-MAC wait reads.
pub const WAIT_DELAY_US: u64 = 500;
/// `udelay(5)` between firmware-ready reads.
pub const READY_DELAY_US: u64 = 5;
/// Self-reset CPU-enable wait iterations.
pub const SELFRESET_POLLS: u32 = 100;
/// `udelay(50)` between self-reset CPU-enable reads.
pub const SELFRESET_DELAY_US: u64 = 50;
/// `FW_8192D_START_ADDRESS`.
const START: u16 = 0x1000;

/// Firmware image name (`rtl8192de/sw.c`).
pub const FW_NAME: &str = "rtlwifi/rtl8192defw.bin";

/// `REG_MCUFWDL` and bits (`rtl8192d/reg.h`).
pub const REG_MCUFWDL: u16 = 0x0080;
pub const MCUFWDL_EN: u8 = 1 << 0;
pub const MCUFWDL_RDY: u32 = 1 << 1;
pub const FWDL_CHKSUM_RPT: u32 = 1 << 2;
/// `REG_MCUFWDL` bit 7: a RAM-code image is running.
pub const RAM_DL_SEL: u8 = 1 << 7;
/// `REG_SYS_FUNC_EN`.
pub const REG_SYS_FUNC_EN: u16 = 0x0002;
/// `REG_HMETFR` (self-reset writes `+3 = 0x20`).
pub const REG_HMETFR: u16 = 0x01cc;
/// `FEN_CPUEN` is bit 10 of `REG_SYS_FUNC_EN`, so bit 2 of `+1`.
pub const SYS_FUNC_EN_CPUEN: u8 = 1 << 2;
/// Dual-MAC download coordination register (`0x1f`).
pub const REG_IN_PROCESS: u16 = 0x001f;
/// `0x1f` bit 5: a download is in process on the other function.
pub const IN_PROCESS_BIT: u8 = 1 << 5;
/// `FW_MAC0_READY` (`reg.h`).
pub const FW_MAC0_READY: u16 = 0x0018;
/// `FW_MAC1_READY` (`reg.h`).
pub const FW_MAC1_READY: u16 = 0x001a;
/// `MAC0_READY` / `MAC1_READY` (both bit 0).
pub const MAC_READY: u8 = 1 << 0;

/// `IS_FW_HEADER_EXIST` (`rtl8192d/fw_common.h`): the signature's low
/// 16 bits masked with `0xfff0` equal `0x92c0` or `0x88c0`, or equal
/// `0x92d0`..=`0x92d3` exactly.
pub fn is_header(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let signature = u16::from_le_bytes([bytes[0], bytes[1]]);
    signature & 0xfff0 == 0x92c0
        || signature & 0xfff0 == 0x88c0
        || (0x92d0..=0x92d3).contains(&signature)
}

/// Validate an RTL8192DE PCI image header and return its payload.
pub fn parse(bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
    if bytes.len() <= HEADER || bytes.len() > MAX_FILE {
        return Err(Error::Image);
    }
    if !is_header(bytes) {
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

fn mcu32<I: Io + ?Sized>(io: &I) -> Result<u32, Error> {
    let value = io.read32(REG_MCUFWDL)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    Ok(value)
}

/// `rtl92d_is_fw_downloaded`: `REG_MCUFWDL & MCUFWDL_RDY`.
fn is_downloaded<I: Io + ?Sized>(io: &I) -> Result<bool, Error> {
    Ok(mcu32(io)? & MCUFWDL_RDY != 0)
}

/// `rtl92d_firmware_selfreset` (PCI path only: the USB-only
/// `REG_FSIMR` / `REG_FWIMR` / `REG_FTIMR` prefix is not ported, as
/// NARF's 8192DE is PCI-only). Sets `REG_HMETFR + 3 = 0x20` (reset
/// 8051) and waits for `SYS_FUNC_EN+1` bit 2 to clear over
/// 100 x 50 us; a still-running CPU is an error here (Linux only
/// warns and continues).
pub async fn selfreset<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    io.write8(REG_HMETFR + 3, 0x20)?;
    for _ in 0..SELFRESET_POLLS {
        if io.read8(REG_SYS_FUNC_EN + 1)? & SYS_FUNC_EN_CPUEN == 0 {
            return Ok(());
        }
        io.delay_us(SELFRESET_DELAY_US).await;
    }
    if io.read8(REG_SYS_FUNC_EN + 1)? & SYS_FUNC_EN_CPUEN == 0 {
        return Ok(());
    }
    Err(Error::Start)
}

/// `rtl92d_enable_fw_download`. The disable path deliberately does NOT
/// write `REG_MCUFWDL + 1`: Linux's comment reserves `0x81[7]` for
/// MAC0 status.
fn enable_download<I: Io + ?Sized>(io: &I, enable: bool) -> Result<(), Error> {
    if enable {
        let value = io.read8(REG_SYS_FUNC_EN + 1)?;
        io.write8(REG_SYS_FUNC_EN + 1, value | 0x04)?;
        let value = io.read8(REG_MCUFWDL)?;
        io.write8(REG_MCUFWDL, value | MCUFWDL_EN)?;
        let value = io.read8(REG_MCUFWDL + 2)?;
        io.write8(REG_MCUFWDL + 2, value & 0xf7)?;
    } else {
        let value = io.read8(REG_MCUFWDL)?;
        io.write8(REG_MCUFWDL, value & !MCUFWDL_EN)?;
    }
    Ok(())
}

/// `rtl92d_write_fw` (the `version` parameter is unused in Linux and
/// dropped here): `rtl_fill_dummy` pads the image to a dword, then
/// `rtl_fw_page_write` per full page and the remainder page (page
/// select `(MCUFWDL+2 & 0xf8) | (page & 7)`, 256-byte block writes at
/// `0x1000`).
fn write_fw<I: Io + ?Sized>(io: &I, payload: &[u8]) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::Image);
    }
    let padded = payload.len().next_multiple_of(4);
    if padded.div_ceil(PAGE) > MAX_PAGES {
        return Err(Error::Image);
    }
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
    Ok(())
}

/// `rtl92d_fw_free_to_go`: undelayed checksum reads succeed only while
/// the counter stays below `POLL_CHECKSUM`; then `MCUFWDL_RDY` is set.
/// A missing report is an error here (Linux logs and continues into
/// `rtl92d_fw_init` anyway).
fn free_to_go<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    let mut ok = false;
    for _ in 0..POLL_CHECKSUM {
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
    io.write32(REG_MCUFWDL, value | MCUFWDL_RDY)?;
    Ok(())
}

/// `rtl92d_fw_init`: the firmware is ready when either MAC's ready
/// byte reports its bit. Linux polls only the calling function's own
/// byte; NARF's firmware owner is not told the PCI function number,
/// and the downloaded image is shared across both MACs, so either bit
/// satisfies this stage. The per-function refinement belongs to the
/// future `Prepared::Chip::Rtl8192de` integration, which knows the
/// function.
fn fw_init<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    for _ in 0..POLL_READY {
        if io.read8(FW_MAC0_READY)? & MAC_READY != 0 || io.read8(FW_MAC1_READY)? & MAC_READY != 0 {
            return Ok(());
        }
        io.delay_us(READY_DELAY_US).await;
    }
    Err(Error::Start)
}

/// `rtl92d_download_fw`: dual-MAC coordination, then the download
/// itself, then `rtl92d_fw_init`. The in-process flag (`0x1f` bit 5)
/// is taken only by the function that actually downloads, and is
/// cleared on every exit after it is taken — including failures — so
/// a failed download never wedges the other function.
pub async fn download<I: Io + ?Sized>(io: &I, payload: &[u8]) -> Result<(), Error> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::Image);
    }
    if is_downloaded(io)? {
        return fw_init(io).await;
    }
    if io.read8(REG_IN_PROCESS)? & IN_PROCESS_BIT != 0 {
        let mut waited_out = false;
        for _ in 0..WAIT_IN_PROCESS {
            io.delay_us(WAIT_DELAY_US).await;
            if is_downloaded(io)? {
                return fw_init(io).await;
            }
            if io.read8(REG_IN_PROCESS)? & IN_PROCESS_BIT == 0 {
                waited_out = true;
                break;
            }
        }
        if !waited_out {
            return Err(Error::Deadline);
        }
    }
    let value = io.read8(REG_IN_PROCESS)?;
    io.write8(REG_IN_PROCESS, value | IN_PROCESS_BIT)?;
    let result = download_inner(io, payload).await;
    let value = io.read8(REG_IN_PROCESS)?;
    io.write8(REG_IN_PROCESS, value & !IN_PROCESS_BIT)?;
    result?;
    fw_init(io).await
}

/// The downloading half of [`download`]: self-reset, enable, pages,
/// disable, checksum handshake.
async fn download_inner<I: Io + ?Sized>(io: &I, payload: &[u8]) -> Result<(), Error> {
    // If 8051 is running in RAM code, inform the firmware to reset
    // itself, or the download fails.
    if io.read8(REG_MCUFWDL)? & RAM_DL_SEL != 0 {
        selfreset(io).await?;
        io.write8(REG_MCUFWDL, 0)?;
    }
    enable_download(io, true)?;
    write_fw(io, payload)?;
    enable_download(io, false)?;
    free_to_go(io).await
}
