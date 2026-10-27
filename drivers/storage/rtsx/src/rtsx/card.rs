//! SD card state machine for the RTSX card reader.
//!
//! This module holds the per-slot card state (inserted / initialised /
//! capacity / identity) and the SD command descriptors used by the
//! identification sequence:
//!   CMD0 → CMD8 → CMD55+ACMD41 (loop) → CMD2 → CMD3 → CMD9 → CMD7
//!   (→ CMD16 for SDSC) → ready
//!
//! References:
//!   SD Physical Layer Simplified Spec v8.00 §4 (SD card initialisation).
//!   Linux `drivers/mmc/host/rtsx_pci_sdmmc.c` (GPL-2.0-or-later).
//!   Linux `include/linux/mfd/rtsx_pci.h` — `SD_RSP_TYPE_*` encodings.

use super::regs::{
    BIPR_SD_EXIST, CARD_CLK_EN, CARD_OE, CARD_SELECT, SD_BUS_WIDTH_1, SD_BUS_WIDTH_MASK, SD_CFG1,
    SD_CLK_EN, SD_MOD_SEL, SD_OUTPUT_EN, SD_RSP_TYPE_R0, SD_RSP_TYPE_R1, SD_RSP_TYPE_R1B,
    SD_RSP_TYPE_R2, SD_RSP_TYPE_R3, SD_RSP_TYPE_R6, SD_RSP_TYPE_R7,
};

/// SD card response types. Each maps to the composite SD_CFG2 byte
/// the RTSX controller expects for the transfer (Linux `rtsx_pci.h`
/// `SD_RSP_TYPE_*` — the byte already encodes response length, CRC7
/// check enable, and busy-wait behaviour).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RspType {
    /// No response (CMD0 / GO_IDLE_STATE).
    None,
    /// 48-bit R1 response.
    R1,
    /// 136-bit R2 (CID / CSD), delivered via the ping-pong buffer.
    R2,
    /// 48-bit R1b (busy signalled after the response — CMD7 SELECT).
    R1b,
    /// 48-bit R3 (OCR — ACMD41; no CRC7 on the wire).
    R3,
    /// 48-bit R6 (RCA — CMD3).
    R6,
    /// 48-bit R7 (interface condition — CMD8).
    R7,
}

impl RspType {
    /// The SD_CFG2 byte for a command transfer with this response.
    pub const fn cfg2(self) -> u8 {
        match self {
            RspType::None => SD_RSP_TYPE_R0,
            RspType::R1 => SD_RSP_TYPE_R1,
            RspType::R2 => SD_RSP_TYPE_R2,
            RspType::R1b => SD_RSP_TYPE_R1B,
            RspType::R3 => SD_RSP_TYPE_R3,
            RspType::R6 => SD_RSP_TYPE_R6,
            RspType::R7 => SD_RSP_TYPE_R7,
        }
    }

    /// True when the controller checks the response CRC7 for this
    /// response type (SD_CFG2 `SD_NO_CHECK_CRC7` bit clear). R3 (OCR)
    /// carries no CRC7 on the wire, so its composite byte sets the
    /// no-check bit.
    pub const fn crc_checked(self) -> bool {
        !matches!(self, RspType::None | RspType::R3)
    }

    /// True for the 136-bit R2 response (delivered via PPBUF).
    pub const fn is_long(self) -> bool {
        matches!(self, RspType::R2)
    }
}

/// A decoded SD command response, as returned by
/// `RtsxController::issue_sd_cmd`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdResponse {
    /// No response was expected (R0).
    None,
    /// 32-bit response argument (R1/R1b/R3/R6/R7 — the four bytes
    /// following the response header byte).
    Short(u32),
    /// 128-bit register (R2 — CID/CSD) in the shifted word layout
    /// `narf_drivers_storage_core::sd_proto` consumes: `w[3]` is the
    /// most significant word and the register's CRC7+end byte has been
    /// stripped by the controller, so the logical register occupies
    /// bits [119:0] of the 128-bit field (top byte zero).
    Long([u32; 4]),
}

/// Convert an R2 frame as delivered by the RTSX controller into the
/// shifted `[u32; 4]` layout of `sd_proto::{Cid, Csd}::parse_shifted`.
///
/// `frame` is the 16 bytes read from the ping-pong buffer by Linux
/// `sd_send_cmd_get_rsp` (READ_REG PPBUF_BASE2..PPBUF_BASE2+15):
/// byte 0 is the response header, bytes 1..15 are the 15 register
/// bytes the controller delivers — it "offloads" the final byte
/// (CRC7 + end bit) while receiving an R2 response (Linux commit
/// d1419d50c, `rtsx_pci_sdmmc.c`). The shifted layout right-aligns
/// those 15 bytes in a 16-byte field (byte 0 = 0), which is exactly
/// the SDHCI hand-off convention `sd_proto` documents.
pub fn r2_frame_to_shifted_words(frame: &[u8; 16]) -> [u32; 4] {
    // bytes16 = [0, reg0, reg1, ..., reg14]; frame[i + 1] = reg[i].
    let b = |i: usize| frame[i] as u32;
    [
        // w[0] = bytes16[12..16] = reg11..reg14
        (b(12) << 24) | (b(13) << 16) | (b(14) << 8) | b(15),
        // w[1] = bytes16[8..12] = reg7..reg10
        (b(8) << 24) | (b(9) << 16) | (b(10) << 8) | b(11),
        // w[2] = bytes16[4..8] = reg3..reg6
        (b(4) << 24) | (b(5) << 16) | (b(6) << 8) | b(7),
        // w[3] = bytes16[0..4] = 0, reg0, reg1, reg2
        (b(1) << 16) | (b(2) << 8) | b(3),
    ]
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
            rsp: RspType::R7,
            app_cmd: false,
        }
    }

    /// ACMD41 — SD_SEND_OP_COND (after CMD55 with RCA=0).
    /// `hcs` = 1 for SDHC/SDXC support. Response is R3 (OCR).
    pub const fn acmd41(hcs: bool) -> Self {
        let ocr = 0x00FF_8000 | if hcs { 1u32 << 30 } else { 0 };
        SdCmd {
            index: 41,
            arg: ocr,
            rsp: RspType::R3,
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

    /// CMD3 — SEND_RELATIVE_ADDR (get RCA from card). Response is R6.
    pub const fn send_relative_addr() -> Self {
        SdCmd {
            index: 3,
            arg: 0,
            rsp: RspType::R6,
            app_cmd: false,
        }
    }

    /// CMD9 — SEND_CSD (read the card-specific data register for the
    /// card at `rca`; the CSD carries the real capacity).
    pub const fn send_csd(rca: u16) -> Self {
        SdCmd {
            index: 9,
            arg: (rca as u32) << 16,
            rsp: RspType::R2,
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
    /// Capacity in 512-byte blocks, decoded from the card's real CSD
    /// (CMD9) via `sd_proto::Csd::parse_shifted`. Always > 0 for an
    /// identified card: identification fails with a typed error when
    /// the CSD is absent or unparseable — a capacity is never
    /// invented.
    pub capacity_blocks: u64,
    /// Card selected (CMD7 done).
    pub selected: bool,
    /// Raw CID register captured from CMD2, in the shifted `[u32; 4]`
    /// layout `sd_proto::Cid::parse_shifted` consumes (`cid[3]` =
    /// MSW, top byte zero — the controller strips CRC7 + end bit).
    pub cid: [u32; 4],
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

/// Build the sequence of WRITE_REG commands that connect the SD
/// interface after power is applied: card-select mux, output enable,
/// clock enable. Values from Linux `rtsx_pci.h` (`SD_MOD_SEL`,
/// `SD_OUTPUT_EN`, `SD_CLK_EN`); the per-chip `card_power_on` ops in
/// `rts5209.c` / `rts5227.c` write the same registers.
///
/// Returns an array of `(addr, mask, data)` tuples ready to be pushed
/// into a `CmdBuf`. Power itself is sequenced separately (two-step
/// CARD_PWR_CTL ramp in `RtsxController::enable_sd_slot`).
pub fn enable_sd_slot_cmds() -> [(u16, u8, u8); 3] {
    [
        (CARD_SELECT, 0xFF, SD_MOD_SEL),
        (CARD_OE, SD_OUTPUT_EN, SD_OUTPUT_EN),
        (CARD_CLK_EN, SD_CLK_EN, SD_CLK_EN),
    ]
}

/// Initial SD bus configuration: 1-bit bus width. The bus-width field
/// is SD_CFG1 bits[1:0] (Linux `rtsx_pci.h` — `SD_BUS_WIDTH_1BIT`).
/// The clock divider field (bits[7:6]) is programmed separately so
/// identification runs at SD_CLK_DIVIDE_128 and data transfers at
/// SD_CLK_DIVIDE_0.
pub fn init_bus_width_cmds() -> [(u16, u8, u8); 1] {
    [(SD_CFG1, SD_BUS_WIDTH_MASK, SD_BUS_WIDTH_1)]
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
