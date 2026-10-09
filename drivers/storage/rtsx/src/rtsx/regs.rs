//! Realtek RTSX PCIe card-reader — MMIO register definitions.
//!
//! # Source
//! Linux `include/linux/rtsx_pci.h` (GPL-2.0-or-later), cited and
//! adapted under NARF's GPL-2.0-or-later licence.
//!
//! BAR0 is a 4 KiB MMIO window. The first 0x20 bytes are HBA control
//! registers; the rest (0x1000..0x1FFF) are an internal register
//! address space accessed through HAIMR or via the host-command-buffer
//! engine.

// ── HBA control registers (BAR0 offsets) ─────────────────────────

/// Host Command Buffer Address Register — u32, physical address of
/// the 4 KiB host-command-buffer page.
/// Linux `rtsx_pci.h:19` — `RTSX_HCBAR`
pub const HCBAR: u64 = 0x00;

/// Host Command Buffer Control Register — u32.
/// Bit 28 = `STOP_CMD`; bits[16:8] = interrupt-on-command-done.
/// Write bits[7:0] = number of commands in the buffer to launch.
/// Linux `rtsx_pci.h:20` — `RTSX_HCBCTLR`
pub const HCBCTLR: u64 = 0x04;

/// Bit 28 of HCBCTLR — abort the current command sequence.
/// Linux `rtsx_pci.h:21`
pub const HCBCTLR_STOP_CMD: u32 = 1 << 28;

/// Host Data Buffer Address Register — u32, physical address of
/// the DMA scatter-gather descriptor or data buffer.
/// Linux `rtsx_pci.h:26` — `RTSX_HDBAR`
pub const HDBAR: u64 = 0x08;

/// Host Data Buffer Control Register — u32.
/// Bits[1:0] = direction (1 = read / device-to-host, 2 = write / host-to-device).
/// Bit 31 = start DMA transfer.
/// Linux `rtsx_pci.h:33` — `RTSX_HDBCTLR`
pub const HDBCTLR: u64 = 0x0C;

/// HDBCTLR direction: device-to-host (SD read).
pub const HDBCTLR_DMA_READ: u32 = 0x01;
/// HDBCTLR direction: host-to-device (SD write).
pub const HDBCTLR_DMA_WRITE: u32 = 0x02;
/// HDBCTLR bit 31 — start DMA.
pub const HDBCTLR_START: u32 = 1 << 31;

/// Host ASIC Internal Memory Register — u32.
/// Direct single-register access path: write `(addr << 8) | mask | data`
/// with bit 31 = write-mode, or `(addr << 8)` with bit 30 = read-mode.
/// Linux `rtsx_pci.h:39` — `RTSX_HAIMR`
pub const HAIMR: u64 = 0x10;

/// HAIMR write-mode bit.
pub const HAIMR_WRITE: u32 = 1 << 31;
/// HAIMR read-mode bit.
pub const HAIMR_READ: u32 = 1 << 30;
/// HAIMR valid-response bit (cleared by hardware when result is ready).
pub const HAIMR_VALID: u32 = 1 << 31;

/// Bus-Interface Pending Register — u32, W1C interrupt status.
/// Linux `rtsx_pci.h:47` — `RTSX_BIPR`
pub const BIPR: u64 = 0x14;

/// BIPR bit 31 — host-command-buffer done.
/// Linux `rtsx_pci.h:48` — `CMD_DONE_INT`
pub const BIPR_CMD_DONE: u32 = 1 << 31;
/// BIPR bit 30 — need_complete (data DMA done).
pub const BIPR_DATA_DONE: u32 = 1 << 30;
/// BIPR bit 29 — transfer OK.
pub const BIPR_TRANS_OK: u32 = 1 << 29;
/// BIPR bit 28 — transfer fail.
pub const BIPR_TRANS_FAIL: u32 = 1 << 28;
/// BIPR bit 16 — SD card present.
/// Linux `rtsx_pci.h:60` — `SD_EXIST`
pub const BIPR_SD_EXIST: u32 = 1 << 16;
/// BIPR bit 17 — MS card present.
pub const BIPR_MS_EXIST: u32 = 1 << 17;
/// BIPR bit 18 — XD card present.
pub const BIPR_XD_EXIST: u32 = 1 << 18;

/// All completion interrupts (`NEED_COMPLETE_INT`).
/// Linux `rtsx_pci.h:67`
pub const BIPR_NEED_COMPLETE: u32 = BIPR_DATA_DONE | BIPR_TRANS_OK | BIPR_TRANS_FAIL;

/// All interrupts we unmask.
/// Linux `rtsx_pci.h:68` — `RTSX_INT`
pub const BIPR_ALL: u32 = BIPR_CMD_DONE | BIPR_NEED_COMPLETE | BIPR_SD_EXIST;

/// Bus-Interface Enable Register — u32, interrupt mask (1 = enabled).
/// Linux `rtsx_pci.h:72` — `RTSX_BIER`
pub const BIER: u64 = 0x18;

/// BIER bit 31 — enable CMD_DONE interrupt.
/// Linux `rtsx_pci.h:73` — `CMD_DONE_INT_EN`
pub const BIER_CMD_DONE: u32 = 1 << 31;

// ── Host command-buffer command types ────────────────────────────

/// Command type: read internal register.
/// Linux `rtsx_pci.h:22` — `READ_REG_CMD`
pub const READ_REG_CMD: u8 = 0;
/// Command type: write internal register.
/// Linux `rtsx_pci.h:23` — `WRITE_REG_CMD`
pub const WRITE_REG_CMD: u8 = 1;
/// Command type: check register (compare & branch).
/// Linux `rtsx_pci.h:24` — `CHECK_REG_CMD`
pub const CHECK_REG_CMD: u8 = 2;

// ── Internal register addresses (accessed via HAIMR or cmd buffer) ─

/// SD CMD0..5 registers — 6 bytes for the SD command frame.
/// Linux `rtsx_pci.h:260` — `SD_CMD0..SD_CMD5`
pub const SD_CMD0: u16 = 0xFDA9;
pub const SD_CMD1: u16 = 0xFDAA;
pub const SD_CMD2: u16 = 0xFDAB;
pub const SD_CMD3: u16 = 0xFDAC;
pub const SD_CMD4: u16 = 0xFDAD;
pub const SD_CMD5: u16 = 0xFDAE;

/// SD byte-count low / high — number of bytes per block.
/// Linux `rtsx_pci.h:267`
pub const SD_BYTE_CNT_L: u16 = 0xFDAF;
pub const SD_BYTE_CNT_H: u16 = 0xFDB0;

/// SD block-count low / high.
/// Linux `rtsx_pci.h:269`
pub const SD_BLOCK_CNT_L: u16 = 0xFDB1;
pub const SD_BLOCK_CNT_H: u16 = 0xFDB2;

/// SD Transfer Control — starts the transfer engine.
/// Linux `rtsx_pci.h:271` — `SD_TRANSFER`
pub const SD_TRANSFER: u16 = 0xFDB3;

/// SD_TRANSFER bits — direction and type.
/// Linux `rtsx_pci.h:272–286`
/// Bit 7 — transfer start.
pub const SD_TRANSFER_START: u8 = 1 << 7;
/// Bits[2:0] — transfer type: NORMAL = 0x00.
pub const SD_TF_NORMAL: u8 = 0x00;
/// Bit 4 — auto-response (card sends R1 after data).
pub const SD_AUTO_RSP: u8 = 1 << 4;
/// Bit 3 — block-transfer (vs. byte transfer).
pub const SD_BLOCK_XFER: u8 = 1 << 3;
/// Bit 2 — write direction (host-to-card).
pub const SD_TF_WRITE: u8 = 1 << 2;
/// Bit 1 — send command before data phase.
pub const SD_SEND_CMD: u8 = 1 << 1;
/// Bit 0 — check status (CMD13 inline).
pub const SD_CHECK_STATUS: u8 = 1 << 0;

/// SD command-state register — polled for busy-done.
/// Linux `rtsx_pci.h:288` — `SD_CMD_STATE`
pub const SD_CMD_STATE: u16 = 0xFDB5;
/// SD_CMD_STATE bit 7 — command engine busy.
pub const SD_CMD_IDLE: u8 = 0; // 0 = idle
pub const SD_CMD_BUSY: u8 = 1 << 7;

/// SD status registers.
/// Linux `rtsx_pci.h:212` — `SD_STAT1`
pub const SD_STAT1: u16 = 0xFDA3;
/// Linux `rtsx_pci.h:219` — `SD_STAT2`
pub const SD_STAT2: u16 = 0xFDA4;

/// Card clock source — must be set to 0 (DPLL) before speed change.
/// Linux `rtsx_pci.h:339` — `CARD_CLK_SOURCE`
pub const CARD_CLK_SOURCE: u16 = 0xFC2E;

/// Card output-enable register.
/// Linux `rtsx_pci.h:399` — `CARD_OE`
pub const CARD_OE: u16 = 0xFD55;
pub const CARD_OE_SD: u8 = 1 << 1;

/// Card select register — selects which card slot is active.
/// Linux `rtsx_pci.h:413` — `CARD_SELECT`
pub const CARD_SELECT: u16 = 0xFD5C;
pub const CARD_SELECT_SD: u8 = 0x02;

/// Card clock-enable register.
/// Linux `rtsx_pci.h:423` — `CARD_CLK_EN`
pub const CARD_CLK_EN: u16 = 0xFD69;
pub const CARD_CLK_EN_SD: u8 = 1 << 1;

/// SD bus width — 1, 4, or 8 bit.
pub const SD_CFG1: u16 = 0xFDA0;
pub const SD_BUS_WIDTH_1: u8 = 0x00;
pub const SD_BUS_WIDTH_4: u8 = 0x01;

/// Initial 400 kHz clock divider setting (approx.).
/// Actual divisor programming goes through CARD_CLK_SOURCE / SSC registers.
pub const INIT_CLK_DIV: u8 = 0x80; // 96 MHz / 256 ≈ 375 kHz
