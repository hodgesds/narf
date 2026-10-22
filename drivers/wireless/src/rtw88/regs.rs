//! RTW88 register definitions for the RTL8821CE / RTL8822BE / RTL8822CE
//! PCIe Wi-Fi 5 silicon family.
//!
//! Offsets are taken from the Realtek public RTL8822C datasheet (where
//! available) and cross-referenced against Linux's GPL-2.0 driver tree:
//!
//! - `drivers/net/wireless/realtek/rtw88/reg.h` — REG_* offsets
//!   (Linux v6.6, lines 1..~600 cover the SYS/PWR/MAC block this
//!   baseline touches).
//! - `drivers/net/wireless/realtek/rtw88/main.c` — chip-init entry
//!   sequencing showing which of these registers participate in
//!   power-on (Linux v6.6 lines ~1900..2100 — `rtw_power_on`).
//! - `drivers/net/wireless/realtek/rtw88/mac.c` — `rtw_pwr_seq_parser`
//!   semantics for the PWR-state register byte writes (Linux v6.6
//!   lines ~140..280).
//! - `drivers/net/wireless/realtek/rtw88/efuse.c` — EFUSE pin layout
//!   and the EEPROM/EFUSE mux probe used to derive `REG_EFUSE_CTRL` +
//!   `REG_LDO_EFUSE_CTRL` semantics (Linux v6.6, lines ~50..~200).
//!
//! NARF is GPL-2.0-or-later (root `LICENSE`), so direct reference and
//! adaptation of these Linux files is in-policy.

#![allow(dead_code)]

// ── MCU / Firmware control ─────────────────────────────────────────

/// `REG_MCUFW_CTRL` — MCU firmware control + status. `reg.h` ~L80.
pub const REG_MCUFW_CTRL: u64 = 0x0080;

/// `FW_READY` bits — mask of (INIT_RDY | DW_RDY | IMEM_DW_OK | DMEM_DW_OK | CHKSUM_OK).
/// Linux: `(BIT_FW_INIT_RDY | BIT_FW_DW_RDY | BIT_IMEM_DW_OK | BIT_DMEM_DW_OK | BIT_CHECK_SUM_OK)`.
pub const FW_READY_MASK: u32 = (1 << 15) | (1 << 14) | (1 << 5) | (1 << 3) | (1 << 4) | (1 << 6);

/// `BIT_MCUFWDL_EN` — bit 0 of `REG_MCUFW_CTRL`. Enables MCU firmware download.
pub const BIT_MCUFWDL_EN: u32 = 1 << 0;

// ── IDDMA (Internal Direct DMA) ────────────────────────────────────

/// `REG_DDMA_CH0SA` — IDDMA Channel 0 Source Address. `reg.h` ~L1200.
pub const REG_DDMA_CH0SA: u64 = 0x1200;
/// `REG_DDMA_CH0DA` — IDDMA Channel 0 Destination Address. `reg.h` ~L1204.
pub const REG_DDMA_CH0DA: u64 = 0x1204;
/// `REG_DDMA_CH0CTRL` — IDDMA Channel 0 Control. `reg.h` ~L1208.
pub const REG_DDMA_CH0CTRL: u64 = 0x1208;

/// `BIT_DDMACH0_OWN` — bit 31 of `REG_DDMA_CH0CTRL`. Host-owned (0) vs HW-owned (1).
pub const BIT_DDMACH0_OWN: u32 = 1 << 31;
/// `BIT_DDMACH0_CHKSUM_EN` — bit 29 of `REG_DDMA_CH0CTRL`. Enable checksum.
pub const BIT_DDMACH0_CHKSUM_EN: u32 = 1 << 29;
/// `BIT_MASK_DDMACH0_DLEN` — mask for transfer length in `REG_DDMA_CH0CTRL`.
pub const BIT_MASK_DDMACH0_DLEN: u32 = 0x0007FFFF;

/// `OCPBASE_TXBUF_88XX` — On-chip TX buffer base address. Used as DDMA source.
pub const OCPBASE_TXBUF_88XX: u32 = 0x18780000;
/// `OCPBASE_IMEM_88XX` — On-chip Instruction memory base address.
pub const OCPBASE_IMEM_88XX: u32 = 0x00000000;
/// `OCPBASE_DMEM_88XX` — On-chip Data memory base address.
pub const OCPBASE_DMEM_88XX: u32 = 0x00200000;

// ── PCI device IDs (vendor 0x10EC = Realtek Semi.) ─────────────────
//
// Per Linux `drivers/net/wireless/realtek/rtw88/pci.c::rtw_pci_id_table`
// (search for `PCI_VDEVICE(REALTEK, 0xC821)` etc.). All three parts
// sit on the same PCI vendor and expose their register aperture at BAR2.

/// Realtek Semiconductor Corp.
pub const REALTEK_VENDOR: u16 = 0x10EC;

/// RTL8821CE — Wi-Fi 5 1x1 (cited in `rtw88/pci.c`).
pub const RTL_DEV_8821CE: u16 = 0xC821;
/// RTL8822CE — Wi-Fi 5 2x2 (cited in `rtw88/pci.c`).
pub const RTL_DEV_8822CE: u16 = 0xC822;
/// RTL8822BE — Wi-Fi 5 2x2, older B-cut sibling of 8822CE (cited in
/// `rtw88/pci.c`).
pub const RTL_DEV_8822BE: u16 = 0xB822;

pub const ALL_DEV_IDS: &[u16] = &[RTL_DEV_8821CE, RTL_DEV_8822CE, RTL_DEV_8822BE];

// ── SYS / power-control registers (BAR2 + offset) ──────────────────
// Per Linux `rtw88/reg.h`. The "REG_SYS_*" block lives in the lower
// 0x80 bytes of BAR2 and is what `rtw_power_on` touches before the
// MAC block comes alive.

/// `REG_SYS_FUNC_EN` — system-wide function enable. Bit 13 (FEN_MREGEN)
/// gates the rest of the MAC. `rtw88/reg.h` ~L21.
pub const REG_SYS_FUNC_EN: u64 = 0x0002;

/// `REG_SYS_PW_CTRL` — system power control. Cleared as the first step
/// of `rtw_power_on` for the chips that need a full PWR reset. `reg.h`
/// ~L17.
pub const REG_SYS_PW_CTRL: u64 = 0x0006;

/// `REG_SYS_CLK_CTRL` — system clock gating. `reg.h` ~L24.
pub const REG_SYS_CLK_CTRL: u64 = 0x0008;

/// `REG_RSV_CTRL` — reserved control. RTL8822C/RTL8821C bring-up sets
/// this to 0 prior to PWR-seq writes (rtw88/rtw8822c.c, `_rtw8822c_pwr_seq_*`).
pub const REG_RSV_CTRL: u64 = 0x001C;

/// `REG_AFE_CTRL3` — analog-frontend ctrl-3. Probed by the power-seq
/// parser when polling for AFE PLL lock. `reg.h` ~L33.
pub const REG_AFE_CTRL3: u64 = 0x001E;

// ── CR (chip command register) ──────────────────────────────────────
//
// `REG_CR` is the chip's master command/reset latch. Bit 0 (CR.RST in
// Linux's macro nomenclature, see `rtw88/reg.h::BIT_HCI_TXDMA_EN`-
// adjacent definitions) is the function-enable; clearing the full
// register and re-issuing CR_OPEN re-arms the MAC. The baseline reset
// path here clears CR to 0, waits, then writes the enable mask.

/// `REG_CR` — MAC chip command. `reg.h` ~L40.
pub const REG_CR: u64 = 0x0100;

/// CR.HCI_TXDMA_EN — bit 0. (`reg.h::BIT_HCI_TXDMA_EN`.)
pub const CR_HCI_TXDMA_EN: u16 = 1 << 0;
/// CR.HCI_RXDMA_EN — bit 1.
pub const CR_HCI_RXDMA_EN: u16 = 1 << 1;
/// CR.TXDMA_EN — bit 2.
pub const CR_TXDMA_EN: u16 = 1 << 2;
/// CR.RXDMA_EN — bit 3.
pub const CR_RXDMA_EN: u16 = 1 << 3;
/// CR.PROTOCOL_EN — bit 4.
pub const CR_PROTOCOL_EN: u16 = 1 << 4;
/// CR.SCHEDULE_EN — bit 5.
pub const CR_SCHEDULE_EN: u16 = 1 << 5;
/// CR.MACTXEN — bit 6.
pub const CR_MAC_TX_EN: u16 = 1 << 6;
/// CR.MACRXEN — bit 7.
pub const CR_MAC_RX_EN: u16 = 1 << 7;

/// Composite "CR open" mask used by `rtw_mac_init` once the PWR-seq
/// completes. Reset = clear; re-arm = write this.
pub const CR_OPEN: u16 = CR_HCI_TXDMA_EN
    | CR_HCI_RXDMA_EN
    | CR_TXDMA_EN
    | CR_RXDMA_EN
    | CR_PROTOCOL_EN
    | CR_SCHEDULE_EN
    | CR_MAC_TX_EN
    | CR_MAC_RX_EN;

// ── EFUSE / EEPROM access ───────────────────────────────────────────
//
// Linux `rtw88/efuse.c`: clear bit 31 to start a physical byte read,
// wait for hardware to set it, then take the low data byte.

/// `REG_EFUSE_CTRL` — EFUSE control + data window. `reg.h` ~L141.
pub const REG_EFUSE_CTRL: u64 = 0x0030;

/// Bit 31 of `REG_EFUSE_CTRL`: clear to start, set by hardware when ready.
pub const EFUSE_CTRL_VALID: u32 = 1 << 31;
/// Address field shift within `REG_EFUSE_CTRL`. Linux: bits [17:8] hold
/// the EFUSE byte offset for the 8821C/8822B/8822C family.
pub const EFUSE_CTRL_ADDR_SHIFT: u32 = 8;
/// Physical address mask before shifting (`BIT_MASK_EF_ADDR`).
pub const EFUSE_CTRL_ADDR_MASK: u32 = 0x3ff;
/// Data byte mask within `REG_EFUSE_CTRL`. Low byte after a successful
/// read.
pub const EFUSE_CTRL_DATA_MASK: u32 = 0x0000_00FF;

/// `REG_LDO_EFUSE_CTRL` — EFUSE bank and 8821C/8822B programming LDO.
pub const REG_LDO_EFUSE_CTRL: u64 = 0x0034;

/// 8821C/8822B programming LDO25 enable; keep clear for reads.
pub const LDO_EFUSE_EN: u32 = 1 << 31;

/// EFUSE bank selector; bank zero is Wi-Fi.
pub const EFUSE_BANK_MASK: u32 = 3 << 8;

/// 8822C programming LDO25 enable is bit zero of this byte register.
pub const REG_ANAPARLDO_POW_MAC: u64 = 0x0029;

// ── EFUSE map offsets ──────────────────────────────────────────────
//
// The PCIe MAC lives at logical 0xd0 on 8821C/8822B and 0x120 on
// 8822C (Linux's per-chip *_efuse structs). See efuse::geometry.

/// Number of MAC-address bytes to read from EFUSE.
pub const MAC_ADDR_LEN: usize = 6;
