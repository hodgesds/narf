//! SD card state machine for the RTSX card reader.
//!
//! This module holds the per-slot card state (inserted / initialised /
//! capacity) and the SD identification sequence:
//!   CMD0 → CMD8 → CMD55+ACMD41 (loop) → CMD2 → CMD3 → CMD7 → ready
//!
//! References:
//!   SD Physical Layer Simplified Spec v8.00 §4 (SD card initialisation).
//!   Linux `drivers/mmc/host/rtsx_pci_sdmmc.c` (GPL-2.0-or-later).

use super::regs::{
    BIPR_SD_EXIST, CARD_CLK_EN, CARD_CLK_EN_SD, CARD_OE, CARD_OE_SD, CARD_SELECT, CARD_SELECT_SD,
    SD_BUS_WIDTH_1, SD_CFG1,
};

/// SD card response types (determines how many bytes of response to
/// read back from the command engine).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RspType {
    /// No response (CMD0 / GO_IDLE_STATE).
    None,
    /// 48-bit R1/R3/R6/R7 response.
    R1,
    /// 136-bit R2 (CID / CSD).
    R2,
    /// 48-bit R1b (busy after response — CMD7 SELECT).
    R1b,
}

/// One SD command descriptor.
#[derive(Copy, Clone, Debug)]
pub struct SdCmd {
    /// Command index (0..63).
    pub index: u8,
    /// 32-bit argument.
    pub arg: u32,
    /// Expected response type.
    pub rsp: RspType,
    /// True for application-specific commands (issued after CMD55).
    pub app_cmd: bool,
}

impl SdCmd {
    /// CMD0 — GO_IDLE_STATE.
    pub const fn go_idle() -> Self {
        SdCmd {
            index: 0,
            arg: 0,
            rsp: RspType::None,
            app_cmd: false,
        }
    }

    /// CMD8 — SEND_IF_COND (SD 2.0 voltage check).
    /// Argument: VHS=0x1 (2.7–3.6 V) + check pattern 0xAA → 0x000001AA.
    pub const fn send_if_cond() -> Self {
        SdCmd {
            index: 8,
            arg: 0x000001AA,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }

    /// ACMD41 — SD_SEND_OP_COND (after CMD55 with RCA=0).
    /// `hcs` = 1 for SDHC/SDXC support.
    pub const fn acmd41(hcs: bool) -> Self {
        let ocr = 0x00FF_8000 | if hcs { 1u32 << 30 } else { 0 };
        SdCmd {
            index: 41,
            arg: ocr,
            rsp: RspType::R1,
            app_cmd: true,
        }
    }

    /// CMD55 — APP_CMD (sets RCA=0 before ACMD41).
    pub const fn app_cmd_prefix() -> Self {
        SdCmd {
            index: 55,
            arg: 0,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }

    /// CMD2 — ALL_SEND_CID.
    pub const fn all_send_cid() -> Self {
        SdCmd {
            index: 2,
            arg: 0,
            rsp: RspType::R2,
            app_cmd: false,
        }
    }

    /// CMD3 — SEND_RELATIVE_ADDR (get RCA from card).
    pub const fn send_relative_addr() -> Self {
        SdCmd {
            index: 3,
            arg: 0,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }

    /// CMD7 — SELECT/DESELECT_CARD (select by RCA).
    pub const fn select_card(rca: u16) -> Self {
        SdCmd {
            index: 7,
            arg: (rca as u32) << 16,
            rsp: RspType::R1b,
            app_cmd: false,
        }
    }

    /// CMD17 — READ_SINGLE_BLOCK.
    pub const fn read_single_block(lba: u32) -> Self {
        SdCmd {
            index: 17,
            arg: lba,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }

    /// CMD24 — WRITE_BLOCK.
    pub const fn write_block(lba: u32) -> Self {
        SdCmd {
            index: 24,
            arg: lba,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }

    /// CMD16 — SET_BLOCKLEN (for SDSC cards; SDHC always 512).
    pub const fn set_blocklen(len: u32) -> Self {
        SdCmd {
            index: 16,
            arg: len,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }

    /// CMD13 — SEND_STATUS.
    pub const fn send_status(rca: u16) -> Self {
        SdCmd {
            index: 13,
            arg: (rca as u32) << 16,
            rsp: RspType::R1,
            app_cmd: false,
        }
    }
}

/// Inserted SD card information, populated after successful identification.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SdCardInfo {
    /// Relative card address, negotiated in CMD3.
    pub rca: u16,
    /// True if the card is SDHC/SDXC (block-addressed).
    pub high_capacity: bool,
    /// Capacity in 512-byte blocks.  0 = not yet known (CMD9/CSD
    /// parsing deferred to the MMC layer for SDHC; for SDSC the CSD
    /// capacity formula applies).
    pub capacity_blocks: u64,
    /// Card selected (CMD7 done).
    pub selected: bool,
}

/// Card detection state for one RTSX slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlotState {
    /// No card / GPIO line not asserted.
    Empty,
    /// Card inserted but identification not yet run.
    Inserted,
    /// Card successfully identified and ready for I/O.
    Ready(SdCardInfo),
    /// Identification failed.
    Error,
}

impl SlotState {
    /// Is there a card present at all?
    pub fn card_present(&self) -> bool {
        !matches!(self, SlotState::Empty)
    }

    /// Is the card ready for data I/O?
    pub fn is_ready(&self) -> bool {
        matches!(self, SlotState::Ready(_))
    }
}

/// Decode whether SD_EXIST is set in the BIPR snapshot `bipr`.
#[inline]
pub fn sd_card_detected(bipr: u32) -> bool {
    bipr & BIPR_SD_EXIST != 0
}

/// Build the sequence of WRITE_REG commands needed to enable the SD
/// slot's output drivers, clock, and card-select mux.
///
/// Returns an array of `(addr, mask, data)` tuples ready to be pushed
/// into a `CmdBuf`.
pub fn enable_sd_slot_cmds() -> [(u16, u8, u8); 3] {
    [
        (CARD_SELECT, 0x07, CARD_SELECT_SD),
        (CARD_OE, CARD_OE_SD, CARD_OE_SD),
        (CARD_CLK_EN, CARD_CLK_EN_SD, CARD_CLK_EN_SD),
    ]
}

/// Initial SD bus configuration commands: 1-bit bus width, slow clock.
pub fn init_bus_width_cmds() -> [(u16, u8, u8); 1] {
    [(SD_CFG1, 0x03, SD_BUS_WIDTH_1)]
}

/// Decode the R7 check-pattern response (CMD8 response low 8 bits).
/// Returns `(voltage_accepted, pattern_ok)`.
#[inline]
pub fn decode_r7(resp: u32) -> (bool, bool) {
    let voltage = (resp >> 8) & 0x0F;
    let pattern = resp & 0xFF;
    (voltage == 0x01, pattern == 0xAA)
}

/// Extract the RCA from an R6 response (high 16 bits = RCA).
#[inline]
pub fn r6_rca(resp: u32) -> u16 {
    (resp >> 16) as u16
}
