//! rtlwifi — shared register definitions.
//!
//! Covers the common register block used by RTL8188EE, RTL8192CE/DE/EE/SE,
//! RTL8723AE/BE, RTL8821AE, and RTL8822BE (the "legacy PCIe rtlwifi" family
//! shipping circa 2010–2017).
//!
//! All offsets are taken from the per-chip `reg.h` headers under
//! `drivers/net/wireless/realtek/rtlwifi/` in the Linux kernel.  The
//! dominant register layout is shared; only a handful of offsets diverge
//! between chip generations and those are noted in comments.
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8188ee/reg.h`  — RTL8188EE offsets
//! - `rtlwifi/rtl8192ee/reg.h`  — RTL8192EE offsets (mostly identical)
//! - `rtlwifi/rtl8821ae/reg.h`  — RTL8821AE / RTL8822BE offsets
//! - `rtlwifi/pci.h`            — queue-index constants and TX/RX desc sizes

#![allow(dead_code)]

// ── Vendor / device IDs (PCI config space) ────────────────────────────────
//
// Linux `rtlwifi/pci.h`: `RTL_PCI_*_DID` macros; all share PCI vendor 0x10EC.

/// Realtek Semiconductor Corp. PCI vendor ID.
pub const REALTEK_VENDOR: u16 = 0x10EC;

/// RTL8188EE — 1T1R 802.11n 2.4 GHz PCIe.
/// Linux `pci.h`: `RTL_PCI_8188EE_DID = 0x8179`.
pub const RTL_DEV_8188EE: u16 = 0x8179;

/// RTL8192CE — 2T2R 802.11n 2.4 GHz PCIe (original "8192CE" DID).
/// Linux `pci.h`: `RTL_PCI_8192CE_DID = 0x8178`.
pub const RTL_DEV_8192CE: u16 = 0x8178;

/// RTL8192CE — alternate DID used on some board designs.
/// Linux `pci.h`: `RTL_PCI_8188CE_DID = 0x8176` (labelled "8188ce" in
/// the table but shares the 8192CE driver).
pub const RTL_DEV_8192CE_ALT: u16 = 0x8176;

/// RTL8192DE — dual-band 2T2R 802.11n PCIe.
/// Linux `pci.h`: `RTL_PCI_8192DE_DID = 0x8193`.
pub const RTL_DEV_8192DE: u16 = 0x8193;

/// RTL8192EE — 2T2R 802.11n PCIe (newer 8192 cut).
/// Linux `pci.h`: `RTL_PCI_8192EE_DID = 0x818B`.
pub const RTL_DEV_8192EE: u16 = 0x818B;

/// RTL8723AE — 1T1R 802.11n + Bluetooth combo, PCIe.
/// Linux `pci.h`: `RTL_PCI_8723AE_DID = 0x8723`.
pub const RTL_DEV_8723AE: u16 = 0x8723;

/// RTL8723BE — 1T1R 802.11n + Bluetooth combo, PCIe (B-cut).
/// Linux `pci.h`: `RTL_PCI_8723BE_DID = 0xB723`.
pub const RTL_DEV_8723BE: u16 = 0xB723;

/// RTL8821AE — 1T1R 802.11ac 2.4 + 5 GHz PCIe.
/// Linux `pci.h`: `RTL_PCI_8821AE_DID = 0x8821`.
pub const RTL_DEV_8821AE: u16 = 0x8821;

/// RTL8822BE — 2T2R 802.11ac Wave-2 PCIe (same DID reused in rtw88).
/// Linux `pci.h`: `RTL_PCI_8822BE_DID = 0xB822`.
pub const RTL_DEV_8822BE: u16 = 0xB822;

/// All device IDs handled by this driver, in the same order as
/// `rtlwifi/pci.c`'s `rtl_pci_id_tbl[]`.
pub const ALL_DEV_IDS: &[u16] = &[
    RTL_DEV_8188EE,
    RTL_DEV_8192CE,
    RTL_DEV_8192CE_ALT,
    RTL_DEV_8192DE,
    RTL_DEV_8192EE,
    RTL_DEV_8723AE,
    RTL_DEV_8723BE,
    RTL_DEV_8821AE,
    RTL_DEV_8822BE,
];

// ── System / power-control (BAR0 low-byte block) ───────────────────────────
//
// These exist at the same offsets across every chip in the family.
// Source: `rtl8188ee/reg.h` §SYS block; cross-checked against
// `rtl8192ee/reg.h` and `rtl8821ae/reg.h`.

/// `REG_SYS_ISO_CTRL` — system ISO control. `reg.h:0x0000`.
pub const REG_SYS_ISO_CTRL: u64 = 0x0000;

/// `REG_SYS_FUNC_EN` — function enable. Bit 13 gates MAC DMA engines.
/// `reg.h:0x0002`.
pub const REG_SYS_FUNC_EN: u64 = 0x0002;

/// `REG_APS_FSMCO` — auto-PS FSM control. `reg.h:0x0004`.
pub const REG_APS_FSMCO: u64 = 0x0004;

/// `REG_SYS_CLKR` — system clock register. `reg.h:0x0008`.
pub const REG_SYS_CLKR: u64 = 0x0008;

/// `REG_9346CR` — EEPROM/EFUSE-select control. `reg.h:0x000A`.
pub const REG_9346CR: u64 = 0x000A;

/// `REG_RSV_CTRL` — reserved control (written during power-on).
/// `reg.h:0x001C`.
pub const REG_RSV_CTRL: u64 = 0x001C;

/// `REG_AFE_XTAL_CTRL` — analog front-end crystal control.
/// `reg.h:0x0024`.
pub const REG_AFE_XTAL_CTRL: u64 = 0x0024;

// ── EFUSE access ──────────────────────────────────────────────────────────
//
// The rtlwifi family (unlike rtw88) gates EFUSE with a voltage switch on
// `REG_EFUSE_TEST`.  The per-byte read protocol is shared:
//   write `(addr << 8)` → REG_EFUSE_CTRL, set bit 31, poll bit 31 → 0.
//
// Source: `rtl8188ee/reg.h:0x0030..0x0034`.

/// `REG_EFUSE_CTRL` — EFUSE byte access window. `reg.h:0x0030`.
pub const REG_EFUSE_CTRL: u64 = 0x0030;

/// `REG_EFUSE_TEST` — EFUSE power / test control. `reg.h:0x0034`.
/// `LDOE25_EN` (bits[31:28] = 0x3) is set before EFUSE reads.
pub const REG_EFUSE_TEST: u64 = 0x0034;

/// Bit 31 of `REG_EFUSE_CTRL`: set to trigger a read; hardware clears
/// when the byte is ready.
pub const EFUSE_CTRL_VALID: u32 = 1 << 31;

/// Address field shift within `REG_EFUSE_CTRL`.  The 8-bit EFUSE address
/// occupies bits [15:8] for the 8188EE / 8192EE generation.
pub const EFUSE_CTRL_ADDR_SHIFT: u32 = 8;

/// Address mask (8-bit: 256 raw cells; full logical map after repeated
/// reading is up to 512 B depending on chip).
pub const EFUSE_CTRL_ADDR_MASK: u32 = 0x0000_00FF;

/// Data byte mask — low 8 bits of `REG_EFUSE_CTRL` after a successful
/// read.
pub const EFUSE_CTRL_DATA_MASK: u32 = 0x0000_00FF;

/// LDOE25 enable value written to bits[31:28] of `REG_EFUSE_TEST`.
/// Linux `efuse.c::efuse_power_switch` writes `(VOLTAGE_V25 << LDOE25_SHIFT)`
/// = `(0x03 << 28)` before each EFUSE access.
pub const EFUSE_TEST_LDOE25_EN: u32 = 0x03 << 28;

/// MAC address length (bytes).
pub const MAC_ADDR_LEN: usize = 6;

/// Logical EFUSE map offset for the factory-programmed MAC address.
/// Per `rtlwifi/efuse.h::EFUSE_MAC_ADDR` entry and the chip-specific
/// `rtl_get_hwinfo` call chains.
pub const EFUSE_MAC_OFFSET: u32 = 0x0000;

// ── MCU firmware download ─────────────────────────────────────────────────
//
// `REG_MCUFWDL` at 0x0080 controls the firmware download state machine.
// Source: `rtl8188ee/reg.h:0x0080`.

/// `REG_MCUFWDL` — MCU firmware download control. `reg.h:0x0080`.
pub const REG_MCUFWDL: u64 = 0x0080;

/// `BIT_MCUFWDL_EN` — bit 0: enable firmware download.
pub const BIT_MCUFWDL_EN: u32 = 1 << 0;

/// `BIT_MCUFWDL_RDY` — bit 1: firmware download complete.
pub const BIT_MCUFWDL_RDY: u32 = 1 << 1;

/// `BIT_FWDL_CHK_RPT` — bit 7: firmware download checksum pass.
pub const BIT_FWDL_CHK_RPT: u32 = 1 << 7;

/// Composite firmware-ready mask (RDY + CHK_RPT).
pub const FW_READY_MASK: u32 = BIT_MCUFWDL_RDY | BIT_FWDL_CHK_RPT;

// ── Interrupt management ──────────────────────────────────────────────────
//
// Source: `rtl8188ee/reg.h:0x00B0..0x00BC`.

/// `REG_HIMR` — host interrupt mask register. `reg.h:0x00B0`.
pub const REG_HIMR: u64 = 0x00B0;

/// `REG_HISR` — host interrupt status register. `reg.h:0x00B4`.
pub const REG_HISR: u64 = 0x00B4;

/// `REG_HIMRE` — extended host interrupt mask. `reg.h:0x00B8`.
pub const REG_HIMRE: u64 = 0x00B8;

/// `REG_HISRE` — extended host interrupt status. `reg.h:0x00BC`.
pub const REG_HISRE: u64 = 0x00BC;

// ── MAC command register (CR) ─────────────────────────────────────────────
//
// Identical across 8188EE / 8192EE / 8821AE / 8822BE.
// Source: `rtl8188ee/reg.h:0x0100`.

/// `REG_CR` — MAC chip command register. `reg.h:0x0100`.
pub const REG_CR: u64 = 0x0100;

/// `REG_PBP` — page boundary pointer. `reg.h:0x0104`.
pub const REG_PBP: u64 = 0x0104;

/// `REG_TRXDMA_CTRL` — TX/RX DMA control. `reg.h:0x010C`.
pub const REG_TRXDMA_CTRL: u64 = 0x010C;

/// `REG_TRXFF_BNDY` — TX/RX FIFO boundary. `reg.h:0x0114`.
pub const REG_TRXFF_BNDY: u64 = 0x0114;

/// CR bit 0: HCI TX DMA enable.
pub const CR_HCI_TXDMA_EN: u16 = 1 << 0;
/// CR bit 1: HCI RX DMA enable.
pub const CR_HCI_RXDMA_EN: u16 = 1 << 1;
/// CR bit 2: TX DMA enable.
pub const CR_TXDMA_EN: u16 = 1 << 2;
/// CR bit 3: RX DMA enable.
pub const CR_RXDMA_EN: u16 = 1 << 3;
/// CR bit 4: protocol engine enable.
pub const CR_PROTOCOL_EN: u16 = 1 << 4;
/// CR bit 5: scheduler enable.
pub const CR_SCHEDULE_EN: u16 = 1 << 5;
/// CR bit 6: MAC TX enable.
pub const CR_MAC_TX_EN: u16 = 1 << 6;
/// CR bit 7: MAC RX enable.
pub const CR_MAC_RX_EN: u16 = 1 << 7;

/// "Open" mask: all DMA + MAC engines running.
pub const CR_OPEN: u16 = CR_HCI_TXDMA_EN
    | CR_HCI_RXDMA_EN
    | CR_TXDMA_EN
    | CR_RXDMA_EN
    | CR_PROTOCOL_EN
    | CR_SCHEDULE_EN
    | CR_MAC_TX_EN
    | CR_MAC_RX_EN;

// ── TX / RX queue indices ─────────────────────────────────────────────────
//
// Source: Linux `rtlwifi/pci.h`.

/// Background queue index.
pub const BK_QUEUE: usize = 0;
/// Best-effort queue index (primary data traffic).
pub const BE_QUEUE: usize = 1;
/// Video queue index.
pub const VI_QUEUE: usize = 2;
/// Voice queue index.
pub const VO_QUEUE: usize = 3;
/// Beacon queue index.
pub const BEACON_QUEUE: usize = 4;
/// TX command (H2C) queue index.
pub const TXCMD_QUEUE: usize = 5;
/// Management queue index.
pub const MGNT_QUEUE: usize = 6;
/// High-priority queue index.
pub const HIGH_QUEUE: usize = 7;
/// HCCA queue index.
pub const HCCA_QUEUE: usize = 8;

/// Total number of TX queues in the rtlwifi model.
pub const RTL_PCI_MAX_TX_QUEUE_COUNT: usize = 9;

/// Number of TX descriptors per non-BE queue.  `pci.h::RT_TXDESC_NUM`.
pub const RT_TXDESC_NUM: usize = 128;

/// Number of TX descriptors for the BE queue.  `pci.h::RT_TXDESC_NUM_BE_QUEUE`.
pub const RT_TXDESC_NUM_BE_QUEUE: usize = 256;

/// Number of RX descriptors (MPDU queue).  `pci.h::RTL_PCI_MAX_RX_COUNT`.
pub const RTL_PCI_MAX_RX_COUNT: usize = 512;

/// Queue-select values written into TX descriptor `queuesel` field.
/// Source: `rtl8192ee/def.h::rtl_desc_qsel`.
pub const QSLT_BK: u8 = 0x02;
pub const QSLT_BE: u8 = 0x00;
pub const QSLT_VI: u8 = 0x05;
pub const QSLT_VO: u8 = 0x07;
pub const QSLT_BEACON: u8 = 0x10;
pub const QSLT_HIGH: u8 = 0x11;
pub const QSLT_MGNT: u8 = 0x12;
pub const QSLT_CMD: u8 = 0x13;

// ── TX/RX descriptor sizes ────────────────────────────────────────────────
//
// Source: `rtl8188ee/trx.h`.

/// TX descriptor size in bytes (16 dwords × 4 = 64 B).
pub const TX_DESC_SIZE: usize = 64;

/// RX descriptor size in bytes (8 dwords × 4 = 32 B).
pub const RX_DESC_SIZE: usize = 32;
