//! RTW89 firmware download — Stage-1 stub.
//!
//! The Wi-Fi 6 silicon ships a multi-MB firmware blob (`rtw89/8852a_fw.bin`,
//! `rtw89/8852b_fw.bin`, `rtw89/8852c_fw.bin`, `rtw89/8851b_fw.bin`,
//! `rtw89/8922a_fw.bin`) that Linux uploads via `rtw89_fw_download`. The
//! downloader has three substantial pieces:
//!
//!   1. Header parse — the blob is a custom Realtek container, not raw
//!      WCPU code. `rtw89_fw_validate_format_v1` (Linux `fw.c` ~L1700)
//!      walks the section-table-of-contents.
//!   2. DMA-fed transfer — sections get pushed via the HCI DMA channel
//!      (`RTW89_DMA_H2C` on PCI). That needs the Stage-2 ring
//!      infrastructure in place.
//!   3. H2C/C2H mailbox handshake — once the WCPU is alive, all further
//!      configuration goes through the host-to-card / card-to-host
//!      message system (`fw.c::rtw89_h2c_*`, `fw.c::rtw89_c2h_*`).
//!
//! None of (1)..(3) fit in a Stage-1 bring-up since (2) depends on the
//! DMA-ring code that lands in Stage 2 and (3) depends on the WCPU
//! actually running. This file is a placeholder so:
//!
//!   - The probe path can call into it without `cfg`-gating churn when
//!     the Stage-2 code lands.
//!   - The `narf-firmware` blob-name → on-device upload contract has
//!     a single spot to fill in (see [`expected_blob_name`]).
//!
//! ## References (GPL-2.0)
//!
//! - Linux `drivers/net/wireless/realtek/rtw89/fw.c` — `rtw89_fw_download`
//!   entry point (~L1900) and the format-v1 walker.
//! - Linux `drivers/net/wireless/realtek/rtw89/fw.h` — `enum rtw89_fw_type`
//!   for the per-section types (`RTW89_FW_NORMAL`, `RTW89_FW_WOWLAN`,
//!   `RTW89_FW_BBMCU0`, etc.).
//! - Realtek's `rtw89-firmware` package ships the blobs under
//!   `linux-firmware:rtw89/`.

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::mac::ChipId;

/// Stage-1 stub. Returns `Ok(false)` to signal "no firmware uploaded,
/// but bring-up should continue." Stage 2 will replace this with the
/// real `rtw89_fw_download` port + the `narf-firmware` blob lookup.
///
/// # Safety
/// Caller owns BAR2 + power-on completed. The future real implementation
/// will DMA-push firmware sections through the H2C channel, so the
/// invariant matters even though the stub doesn't touch hardware.
pub unsafe fn download_stub(_mmio: &MmioRegion) -> Result<bool, FwError> {
    // Intentionally a no-op for Stage 1. The Stage-2 wire-in will:
    //   1. resolve `expected_blob_name(chip_id)` against
    //      `narf-firmware::open(...)`,
    //   2. parse the format-v1 TOC,
    //   3. push sections via the H2C DMA channel,
    //   4. wait for `B_AX_WCPU_FW_RDY` in `R_AX_WCPU_FW_CTRL`.
    Ok(false)
}

/// Expected firmware blob name for the chip. Matches the path Linux
/// requests via `request_firmware`; the `narf-firmware` registry
/// indexes by the same key. `None` for chips we don't have a blob
/// shipped for.
pub const fn expected_blob_name(chip_id: ChipId) -> Option<&'static str> {
    match chip_id {
        ChipId::Rtl8852A => Some("rtw89/8852a_fw.bin"),
        ChipId::Rtl8852B => Some("rtw89/8852b_fw.bin"),
        ChipId::Rtl8852C => Some("rtw89/8852c_fw.bin"),
        ChipId::Rtl8851B => Some("rtw89/8851b_fw.bin"),
        ChipId::Rtl8922A => Some("rtw89/8922a_fw.bin"),
    }
}

/// Errors raised by the firmware-download path. The Stage-1 stub
/// can't actually return any of these (it short-circuits to
/// `Ok(false)`), but the typed shape is here so the Stage-2 wire-in
/// is a drop-in.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// `narf-firmware` couldn't locate the requested blob.
    BlobMissing,
    /// Blob header didn't match the format-v1 magic.
    BadFormat,
    /// DMA-push timed out — H2C channel didn't accept the transfer
    /// within the wall-clock budget.
    DmaTimeout,
    /// WCPU never asserted `B_AX_WCPU_FW_RDY` after upload completed.
    WcpuTimeout,
}
