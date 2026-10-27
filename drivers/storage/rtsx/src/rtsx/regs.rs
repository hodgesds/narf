//! Realtek RTSX PCIe card-reader — MMIO register definitions.
//!
//! # Source
//! Linux `include/linux/mfd/rtsx_pci.h` (GPL-2.0-or-later), cited and
//! adapted under NARF's GPL-2.0-or-later licence. All bit layouts
//! below were cross-checked against that header (torvalds/linux,
//! `include/linux/mfd/rtsx_pci.h` at commit d1419d50c and its modern
//! successor `include/linux/rtsx_pci.h`; the values are identical).
//!
//! BAR0 is a 4 KiB MMIO window. The first 0x20 bytes are HBA control
//! registers; the internal register space (0xF800..0xFEFF) is accessed
//! through HAIMR or via the host-command-buffer engine.

// ── HBA control registers (BAR0 offsets) ─────────────────────────

/// Host Command Buffer Address Register — u32, physical address of
/// the host-command-buffer page.
/// Linux `rtsx_pci.h` — `RTSX_HCBAR`
pub const HCBAR: u64 = 0x00;

/// Host Command Buffer Control Register — u32.
/// Bit 31 = trigger (start the command engine), bit 30 = hardware
/// auto-response enable, bit 28 = `STOP_CMD`, bits[23:0] = command
/// buffer length **in bytes**.
/// Linux `rtsx_pci.h` — `RTSX_HCBCTLR`; written by
/// `rtsx_pci_send_cmd_no_wait` in `rtsx_pcr.c`.
pub const HCBCTLR: u64 = 0x04;

/// Bit 31 of HCBCTLR — start executing the command buffer.
pub const HCBCTLR_TRIGGER: u32 = 1 << 31;
/// Bit 30 of HCBCTLR — hardware auto-response (READ/CHECK results are
/// written back into the command buffer page).
pub const HCBCTLR_HW_AUTO_RSP: u32 = 1 << 30;
/// Bit 28 of HCBCTLR — abort the current command sequence.
/// Linux `rtsx_pci.h` — `STOP_CMD`
pub const HCBCTLR_STOP_CMD: u32 = 1 << 28;
/// Bits[23:0] of HCBCTLR — command-buffer length mask (bytes).
pub const HCBCTLR_LEN_MASK: u32 = 0x00FF_FFFF;

/// Host Data Buffer Address Register — u32, physical address of the
/// DMA scatter-gather table (ADMA mode).
/// Linux `rtsx_pci.h` — `RTSX_HDBAR`
pub const HDBAR: u64 = 0x08;

/// Host Data Buffer Control Register — u32 (ADMA data path).
/// Bit 31 = `TRIG_DMA`, bit 29 = direction (1 = device-to-host),
/// bits[27:26] = `ADMA_MODE` (0x02), bit 28 = `STOP_DMA`.
/// Linux `rtsx_pci.h` — `RTSX_HDBCTLR`, `TRIG_DMA`, `ADMA_MODE`,
/// `STOP_DMA`; composed by `rtsx_pci_dma_transfer` in `rtsx_pcr.c`.
/// This driver moves single blocks through the ping-pong buffer
/// instead (see `card.rs` / `mod.rs`), so the ADMA path is documented
/// here for the multi-block follow-up, not programmed.
pub const HDBCTLR: u64 = 0x0C;

/// HDBCTLR bit 31 — start DMA.
pub const HDBCTLR_TRIG_DMA: u32 = 1 << 31;
/// HDBCTLR bit 29 — direction device-to-host (read).
pub const HDBCTLR_DIR_FROM_CARD: u32 = 1 << 29;
/// HDBCTLR bits[27:26] — ADMA mode encoding.
pub const HDBCTLR_ADMA_MODE: u32 = 0x02 << 26;
/// HDBCTLR bit 28 — stop DMA.
pub const HDBCTLR_STOP_DMA: u32 = 1 << 28;

/// Host Access Internal Memory Register — u32.
/// Direct single-register access path (Linux `rtsx_pci_read_register`
/// / `rtsx_pci_write_register` in `rtsx_pcr.c`):
///   bits[31]    = transaction start (hardware clears on completion)
///   bits[30]    = 1 for write, 0 for read
///   bits[29:16] = internal register address (14 bits, `addr & 0x3FFF`)
///   bits[15:8]  = write mask
///   bits[7:0]   = write data in / read data out
/// Linux `rtsx_pci.h` — `RTSX_HAIMR`, `HAIMR_TRANS_START`,
/// `HAIMR_WRITE`, `HAIMR_READ`.
pub const HAIMR: u64 = 0x10;

/// HAIMR bit 31 — transaction start; reads back 0 when complete.
pub const HAIMR_TRANS_START: u32 = 1 << 31;
/// HAIMR bit 30 — write transaction (clear = read).
pub const HAIMR_WRITE: u32 = 1 << 30;
/// HAIMR address-field mask (bits[29:16]).
pub const HAIMR_ADDR_MASK: u32 = 0x3FFF;

/// Bus-Interface Pending Register — u32, W1C interrupt status.
/// Linux `rtsx_pci.h` — `RTSX_BIPR`
pub const BIPR: u64 = 0x14;

/// BIPR bit 31 — host-command-buffer done.
/// Linux `rtsx_pci.h` — `CMD_DONE_INT`
pub const BIPR_CMD_DONE: u32 = 1 << 31;
/// BIPR bit 30 — data DMA done.
pub const BIPR_DATA_DONE: u32 = 1 << 30;
/// BIPR bit 29 — transfer OK. This (with TRANS_FAIL) is the
/// command-batch completion signal `rtsx_pci_send_cmd` waits on.
/// Linux `rtsx_pci.h` — `TRANS_OK_INT`
pub const BIPR_TRANS_OK: u32 = 1 << 29;
/// BIPR bit 28 — transfer failed.
/// Linux `rtsx_pci.h` — `TRANS_FAIL_INT`
pub const BIPR_TRANS_FAIL: u32 = 1 << 28;
/// BIPR bit 25 — SD card interrupt (insert/remove event).
/// Linux `rtsx_pci.h` — `SD_INT`
pub const BIPR_SD_INT: u32 = 1 << 25;
/// BIPR bit 19 — SD write-protect level.
/// Linux `rtsx_pci.h` — `SD_WRITE_PROTECT`
pub const BIPR_SD_WRITE_PROTECT: u32 = 1 << 19;
/// BIPR bit 16 — SD card present (level).
/// Linux `rtsx_pci.h` — `SD_EXIST`
pub const BIPR_SD_EXIST: u32 = 1 << 16;
/// BIPR bit 17 — MS card present (level).
pub const BIPR_MS_EXIST: u32 = 1 << 17;
/// BIPR bit 18 — XD card present (level).
pub const BIPR_XD_EXIST: u32 = 1 << 18;

/// Completion interrupts (`NEED_COMPLETE_INT`).
/// Linux `rtsx_pci.h`
pub const BIPR_NEED_COMPLETE: u32 = BIPR_DATA_DONE | BIPR_TRANS_OK | BIPR_TRANS_FAIL;

/// Bus-Interface Enable Register — u32, interrupt mask (1 = enabled).
/// Linux `rtsx_pci.h` — `RTSX_BIER`
pub const BIER: u64 = 0x18;

/// BIER bit 31 — enable CMD_DONE interrupt.
pub const BIER_CMD_DONE_EN: u32 = 1 << 31;
/// BIER bit 29 — enable TRANS_OK interrupt.
/// Linux `rtsx_pci.h` — `TRANS_OK_INT_EN`
pub const BIER_TRANS_OK_EN: u32 = 1 << 29;
/// BIER bit 28 — enable TRANS_FAIL interrupt.
/// Linux `rtsx_pci.h` — `TRANS_FAIL_INT_EN`
pub const BIER_TRANS_FAIL_EN: u32 = 1 << 28;
/// BIER bit 25 — enable SD card interrupt.
/// Linux `rtsx_pci.h` — `SD_INT_EN`
pub const BIER_SD_INT_EN: u32 = 1 << 25;

// ── Host command-buffer command types ────────────────────────────

/// Command type: read internal register.
/// Linux `rtsx_pci.h` — `READ_REG_CMD`
pub const READ_REG_CMD: u8 = 0;
/// Command type: write internal register.
/// Linux `rtsx_pci.h` — `WRITE_REG_CMD`
pub const WRITE_REG_CMD: u8 = 1;
/// Command type: check register (stall until `(reg & mask) == data`;
/// the masked value read is stored in the response area).
/// Linux `rtsx_pci.h` — `CHECK_REG_CMD`
pub const CHECK_REG_CMD: u8 = 2;

// ── Internal register addresses (accessed via HAIMR or cmd buffer) ─

/// SD command frame registers. Only SD_CMD0..SD_CMD4 are written by
/// the host (header byte + 32-bit argument); the controller generates
/// CRC7 itself and overwrites SD_CMD0..SD_CMD4 with the response
/// frame after a command transfer.
/// Linux `rtsx_pci.h` — `SD_CMD0..SD_CMD5`
pub const SD_CMD0: u16 = 0xFDA9;
pub const SD_CMD1: u16 = 0xFDAA;
pub const SD_CMD2: u16 = 0xFDAB;
pub const SD_CMD3: u16 = 0xFDAC;
pub const SD_CMD4: u16 = 0xFDAD;
pub const SD_CMD5: u16 = 0xFDAE;

/// SD byte-count low / high — bytes per block.
/// Linux `rtsx_pci.h`
pub const SD_BYTE_CNT_L: u16 = 0xFDAF;
pub const SD_BYTE_CNT_H: u16 = 0xFDB0;

/// SD block-count low / high.
/// Linux `rtsx_pci.h`
pub const SD_BLOCK_CNT_L: u16 = 0xFDB1;
pub const SD_BLOCK_CNT_H: u16 = 0xFDB2;

/// SD Transfer Control — writing a transfer mode | SD_TRANSFER_START
/// runs the SD command/data engine.
/// Linux `rtsx_pci.h` — `SD_TRANSFER`
pub const SD_TRANSFER: u16 = 0xFDB3;

/// SD_TRANSFER bit 7 — start the transfer.
/// Linux `rtsx_pci.h` — `SD_TRANSFER_START`
pub const SD_TRANSFER_START: u8 = 0x80;
/// SD_TRANSFER bit 6 — transfer ended.
/// Linux `rtsx_pci.h` — `SD_TRANSFER_END`
pub const SD_TRANSFER_END: u8 = 0x40;
/// SD_TRANSFER bit 5 — SD bus idle.
/// Linux `rtsx_pci.h` — `SD_STAT_IDLE`
pub const SD_STAT_IDLE: u8 = 0x20;
/// SD_TRANSFER bit 4 — transfer error.
/// Linux `rtsx_pci.h` — `SD_TRANSFER_ERR`
pub const SD_TRANSFER_ERR: u8 = 0x10;

/// SD transfer modes (SD_TRANSFER bits[3:0]).
/// Linux `rtsx_pci.h` — `SD_TM_*` definitions, used by
/// `drivers/mmc/host/rtsx_pci_sdmmc.c`.
/// TM_NORMAL_WRITE — command in SD_CMD0..4, data host→card via DMA.
pub const SD_TM_NORMAL_WRITE: u8 = 0x00;
/// TM_AUTO_WRITE_3 — command + multi-block write via ring buffer.
pub const SD_TM_AUTO_WRITE_3: u8 = 0x01;
/// TM_AUTO_WRITE_4 — command + write with CMD12 auto-stop.
pub const SD_TM_AUTO_WRITE_4: u8 = 0x02;
/// TM_AUTO_READ_3 — command + multi-block read via ring buffer.
pub const SD_TM_AUTO_READ_3: u8 = 0x05;
/// TM_AUTO_READ_4 — command + read with CMD12 auto-stop.
pub const SD_TM_AUTO_READ_4: u8 = 0x06;
/// TM_CMD_RSP — command/response only, no data phase. Used by
/// `sd_send_cmd_get_rsp` for every identify/control command.
pub const SD_TM_CMD_RSP: u8 = 0x08;
/// TM_AUTO_WRITE_1 — command + single-block write variant.
pub const SD_TM_AUTO_WRITE_1: u8 = 0x09;
/// TM_AUTO_WRITE_2 — command in SD_CMD0..4 + data card-ward from the
/// ping-pong buffer. Used by `sd_write_data` for CMD24.
pub const SD_TM_AUTO_WRITE_2: u8 = 0x0A;
/// TM_NORMAL_READ — command in SD_CMD0..4 + data to the ping-pong
/// buffer. Used by `sd_read_data` for CMD17.
pub const SD_TM_NORMAL_READ: u8 = 0x0C;
/// TM_AUTO_READ_1 — command + single-block read variant.
pub const SD_TM_AUTO_READ_1: u8 = 0x0D;
/// TM_AUTO_READ_2 — command + single-block read variant.
pub const SD_TM_AUTO_READ_2: u8 = 0x0E;

/// SD command-state register.
/// Linux `rtsx_pci.h` — `SD_CMD_STATE`
pub const SD_CMD_STATE: u16 = 0xFDB5;
/// SD_CMD_STATE bit 7 — command engine idle when **set**.
/// Linux `rtsx_pci.h` — `SD_CMD_IDLE`
pub const SD_CMD_IDLE: u8 = 0x80;

/// SD status register 1 — CRC / timeout status of the last transfer.
/// Linux `rtsx_pci.h` — `SD_STAT1`
pub const SD_STAT1: u16 = 0xFDA3;
/// SD_STAT1 bit 7 — response CRC7 error.
/// Linux `rtsx_pci.h` — `SD_CRC7_ERR`
pub const SD_STAT1_CRC7_ERR: u8 = 0x80;
/// SD_STAT1 bit 6 — data CRC16 error.
/// Linux `rtsx_pci.h` — `SD_CRC16_ERR`
pub const SD_STAT1_CRC16_ERR: u8 = 0x40;
/// SD_STAT1 bit 5 — write CRC error.
/// Linux `rtsx_pci.h` — `SD_CRC_WRITE_ERR`
pub const SD_STAT1_CRC_WRITE_ERR: u8 = 0x20;
/// SD status register 2.
/// Linux `rtsx_pci.h` — `SD_STAT2`
pub const SD_STAT2: u16 = 0xFDA4;

/// SD Configure 1 — clock divider (bits[7:6]), mode (bits[3:2]),
/// bus width (bits[1:0]).
/// Linux `rtsx_pci.h` — `SD_CFG1`
pub const SD_CFG1: u16 = 0xFDA0;
/// SD_CFG1 clock divider field mask (bits[7:6]).
pub const SD_CLK_DIVIDE_MASK: u8 = 0xC0;
/// SD_CFG1 divider: no division (running clock).
/// Linux `rtsx_pci.h` — `SD_CLK_DIVIDE_0`
pub const SD_CLK_DIVIDE_0: u8 = 0x00;
/// SD_CFG1 divider: /128 of the SSC clock — the identification clock
/// programmed by `rtsx_pci_switch_clock(..., initial_mode = true)`.
/// Linux `rtsx_pci.h` — `SD_CLK_DIVIDE_128`
pub const SD_CLK_DIVIDE_128: u8 = 0x80;
/// SD_CFG1 divider: /256.
/// Linux `rtsx_pci.h` — `SD_CLK_DIVIDE_256`
pub const SD_CLK_DIVIDE_256: u8 = 0xC0;
/// SD_CFG1 bus-width field mask (bits[1:0]).
pub const SD_BUS_WIDTH_MASK: u8 = 0x03;
/// SD_CFG1 bus width: 1 bit.
/// Linux `rtsx_pci.h` — `SD_BUS_WIDTH_1BIT`
pub const SD_BUS_WIDTH_1: u8 = 0x00;
/// SD_CFG1 bus width: 4 bit.
/// Linux `rtsx_pci.h` — `SD_BUS_WIDTH_4BIT`
pub const SD_BUS_WIDTH_4: u8 = 0x01;
/// SD_CFG1 bus width: 8 bit.
/// Linux `rtsx_pci.h` — `SD_BUS_WIDTH_8BIT`
pub const SD_BUS_WIDTH_8: u8 = 0x02;

/// SD Configure 2 — CRC handling + response length for a transfer.
/// For command/response transfers the whole byte is one of the
/// `SD_RSP_TYPE_*` composite encodings below (they already include
/// the RSP_LEN and CRC-check flag bits).
/// Linux `rtsx_pci.h` — `SD_CFG2`
pub const SD_CFG2: u16 = 0xFDA1;
/// SD_CFG2 bit 7 — do not calculate CRC7 (clear = calculate).
/// Linux `rtsx_pci.h` — `SD_NO_CALCULATE_CRC7`
pub const SD_CFG2_NO_CALCULATE_CRC7: u8 = 0x80;
/// SD_CFG2 bit 6 — do not check data CRC16 (clear = check).
/// Linux `rtsx_pci.h` — `SD_NO_CHECK_CRC16`
pub const SD_CFG2_NO_CHECK_CRC16: u8 = 0x40;
/// SD_CFG2 bit 3 — wait for busy end after the response.
/// Linux `rtsx_pci.h` — `SD_WAIT_BUSY_END`
pub const SD_CFG2_WAIT_BUSY_END: u8 = 0x08;
/// SD_CFG2 bit 2 — do not check response CRC7 (clear = check).
/// Linux `rtsx_pci.h` — `SD_NO_CHECK_CRC7`
pub const SD_CFG2_NO_CHECK_CRC7: u8 = 0x04;
/// SD_CFG2 bits[1:0] — response length: 6 bytes (48-bit response).
/// Linux `rtsx_pci.h` — `SD_RSP_LEN_6`
pub const SD_CFG2_RSP_LEN_6: u8 = 0x01;
/// SD_CFG2 bits[1:0] — response length: 17 bytes (136-bit response).
/// Linux `rtsx_pci.h` — `SD_RSP_LEN_17`
pub const SD_CFG2_RSP_LEN_17: u8 = 0x02;

/// SD_CFG2 composite response-type bytes.
/// Linux `rtsx_pci.h` — `SD_RSP_TYPE_*`
/// No response.
pub const SD_RSP_TYPE_R0: u8 = 0x04;
/// R1 (48-bit, CRC7 checked, no busy wait).
pub const SD_RSP_TYPE_R1: u8 = 0x01;
/// R1b (48-bit, CRC7 checked, wait busy end).
pub const SD_RSP_TYPE_R1B: u8 = 0x09;
/// R2 (136-bit CID/CSD, CRC7 checked).
pub const SD_RSP_TYPE_R2: u8 = 0x02;
/// R3 (48-bit OCR, CRC7 not checked).
pub const SD_RSP_TYPE_R3: u8 = 0x05;
/// R6 (48-bit RCA response, CRC7 checked).
pub const SD_RSP_TYPE_R6: u8 = 0x01;
/// R7 (48-bit interface-condition response, CRC7 checked).
pub const SD_RSP_TYPE_R7: u8 = 0x01;

/// Card clock source.
/// Linux `rtsx_pci.h` — `CARD_CLK_SOURCE`
pub const CARD_CLK_SOURCE: u16 = 0xFC2E;

/// Function Power Down Control — bit 0 gates SSC (the card clock
/// source) power; `rtsx_pci_init_hw` clears it at probe.
/// Linux `rtsx_pci.h` — `FPDCTL`, `SSC_POWER_DOWN`
pub const FPDCTL: u16 = 0xFC00;
/// FPDCTL bit 0 — SSC power down when set.
pub const SSC_POWER_DOWN: u8 = 0x01;

/// Card Power Control.
/// Linux `rtsx_pci.h` — `CARD_PWR_CTL`
pub const CARD_PWR_CTL: u16 = 0xFD50;
/// CARD_PWR_CTL bits[1:0] — SD power field mask.
/// Linux `rtsx_pci.h` — `SD_POWER_MASK`
pub const SD_POWER_MASK: u8 = 0x03;
/// SD power fully off.
/// Linux `rtsx_pci.h` — `SD_POWER_OFF`
pub const SD_POWER_OFF: u8 = 0x03;
/// SD partial power on (ramp step 1 of the per-chip `card_power_on`
/// sequences in `rts5227.c` / `rts5249.c`).
/// Linux `rtsx_pci.h` — `SD_PARTIAL_POWER_ON`
pub const SD_PARTIAL_POWER_ON: u8 = 0x01;
/// SD power fully on (ramp step 2).
/// Linux `rtsx_pci.h` — `SD_POWER_ON`
pub const SD_POWER_ON: u8 = 0x00;

/// Card Transfer Reset — stops a card interface / clears its errors.
/// Linux `rtsx_pci.h` — `CARD_STOP`
pub const CARD_STOP: u16 = 0xFD54;
/// CARD_STOP bit 2 — stop the SD interface.
/// Linux `rtsx_pci.h` — `SD_STOP`
pub const SD_STOP: u8 = 0x04;
/// CARD_STOP bit 6 — clear SD interface errors.
/// Linux `rtsx_pci.h` — `SD_CLR_ERR`
pub const SD_CLR_ERR: u8 = 0x40;

/// Card output-enable register.
/// Linux `rtsx_pci.h` — `CARD_OE`
pub const CARD_OE: u16 = 0xFD55;
/// CARD_OE SD bit — output enable for the SD interface.
/// Linux `rtsx_pci.h` — `SD_OUTPUT_EN`
pub const SD_OUTPUT_EN: u8 = 0x04;

/// Card Data Source — selects where SD data transfers stage.
/// Linux `rtsx_pci.h` — `CARD_DATA_SOURCE`
pub const CARD_DATA_SOURCE: u16 = 0xFD5B;
/// CARD_DATA_SOURCE field mask (bit 0).
pub const CARD_DATA_SOURCE_MASK: u8 = 0x01;
/// Data staged in the ring buffer (ADMA data path).
/// Linux `rtsx_pci.h` — `RING_BUFFER`
pub const RING_BUFFER: u8 = 0x00;
/// Data staged in the ping-pong buffer.
/// Linux `rtsx_pci.h` — `PINGPONG_BUFFER`
pub const PINGPONG_BUFFER: u8 = 0x01;

/// Card select register — selects which card interface is active.
/// Linux `rtsx_pci.h` — `CARD_SELECT`
pub const CARD_SELECT: u16 = 0xFD5C;
/// CARD_SELECT value selecting the SD interface.
/// Linux `rtsx_pci.h` — `SD_MOD_SEL`
pub const SD_MOD_SEL: u8 = 0x02;

/// Card clock-enable register.
/// Linux `rtsx_pci.h` — `CARD_CLK_EN`
pub const CARD_CLK_EN: u16 = 0xFD69;
/// CARD_CLK_EN SD bit — clock enable for the SD interface.
/// Linux `rtsx_pci.h` — `SD_CLK_EN`
pub const SD_CLK_EN: u8 = 0x04;

/// Ping-pong buffer base 2 — the 512-byte staging buffer used for
/// R2 responses and single-block data transfers. Accessed one byte at
/// a time through READ_REG/WRITE_REG command entries (Linux
/// `rtsx_pci_read_ppbuf` / `rtsx_pci_write_ppbuf`).
/// Linux `rtsx_pci.h` — `PPBUF_BASE2`
pub const PPBUF_BASE2: u16 = 0xFA00;
