//! RTL8XXXU register definitions — USB WiFi family.
//!
//! Covers RTL8188EU, RTL8192EU, RTL8723BU, RTL8821CU, RTL8822BU and
//! related rebranded variants.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/regs.h` — REG_* offsets
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c` — chip constants
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h` — fops/priv

#![allow(dead_code)]

// ── USB Realtek vendor constants ────────────────────────────────────
//
// Source: `rtl8xxxu.h` REALTEK_USB_* / USB_VENDOR_ID_REALTEK.

/// Realtek Semiconductor Corp. USB vendor ID.
pub const RTL8XXXU_VENDOR: u16 = 0x0BDA;

/// USB control-transfer request type: device-to-host vendor.
/// `REALTEK_USB_READ = 0xC0` in `rtl8xxxu.h`.
pub const REALTEK_USB_READ: u8 = 0xC0;

/// USB control-transfer request type: host-to-device vendor.
/// `REALTEK_USB_WRITE = 0x40` in `rtl8xxxu.h`.
pub const REALTEK_USB_WRITE: u8 = 0x40;

/// USB bRequest field for all Realtek register read/write.
/// `REALTEK_USB_CMD_REQ = 0x05`.
pub const REALTEK_USB_CMD_REQ: u8 = 0x05;

/// USB wIndex for Realtek register transfers (always 0).
/// `REALTEK_USB_CMD_IDX = 0x00`.
pub const REALTEK_USB_CMD_IDX: u16 = 0x00;

/// USB control-transfer timeout in ms.
/// `RTW_USB_CONTROL_MSG_TIMEOUT = 500`.
pub const USB_CTRL_TIMEOUT_MS: u32 = 500;

/// USB interrupt-IN endpoint content length (bytes).
/// `USB_INTR_CONTENT_LENGTH = 56`.
pub const USB_INTR_CONTENT_LEN: usize = 56;

/// Maximum out-endpoints on the RTL8XXXU parts.
/// `RTL8XXXU_OUT_ENDPOINTS = 6`.
pub const USB_OUT_ENDPOINTS: usize = 6;

/// Maximum register poll count before timeout.
/// `RTL8XXXU_MAX_REG_POLL = 500`.
pub const MAX_REG_POLL: usize = 500;

// ── USB device IDs per chip family ─────────────────────────────────
//
// Source: `core.c::dev_table[]` lines ~7942..8060.
// At least 20 IDs covering the 5 target chip families.

/// RTL8188EU native ID — 802.11n 1x1 USB (`0x0BDA:0x8179`).
pub const RTL8188EU_ID: u16 = 0x8179;
/// RTL8188EU alternate ID — `0x0BDA:0x0179` (rtl8188etv).
pub const RTL8188EU_ID_ALT: u16 = 0x0179;

/// RTL8192EU native ID — 802.11n 2x2 USB (`0x0BDA:0x818B`).
pub const RTL8192EU_ID: u16 = 0x818B;

/// RTL8723BU native ID — 802.11n 1x1 + BT combo (`0x0BDA:0xB720`).
pub const RTL8723BU_ID: u16 = 0xB720;

/// RTL8821CU — 802.11ac 1x1 USB (`0x0BDA:0xC811`).
pub const RTL8821CU_ID: u16 = 0xC811;

/// RTL8822BU — 802.11ac 2x2 USB (`0x0BDA:0xB82C`).
pub const RTL8822BU_ID: u16 = 0xB82C;

/// All USB IDs carried by the Realtek vendor. Rebranded dongles use
/// third-party vendor IDs; those appear in `REBRANDED_IDS`.
pub const REALTEK_USB_IDS: &[(u16, u16)] = &[
    (RTL8XXXU_VENDOR, RTL8188EU_ID),
    (RTL8XXXU_VENDOR, RTL8188EU_ID_ALT),
    (RTL8XXXU_VENDOR, RTL8192EU_ID),
    (RTL8XXXU_VENDOR, RTL8723BU_ID),
    (RTL8XXXU_VENDOR, RTL8821CU_ID),
    (RTL8XXXU_VENDOR, RTL8822BU_ID),
    // RTL8710BU / RTL8188GU
    (RTL8XXXU_VENDOR, 0xB711),
    // RTL8188EU rosewill ffef
    (RTL8XXXU_VENDOR, 0xFFEF),
];

/// Rebranded dongle (vid, pid, chip) table.
/// Source: `core.c::dev_table[]` lines ~7951..8060.
///
/// Each entry is `(vendor_id, product_id, chip_family)` where
/// `chip_family` is one of the `ChipFamily` variant discriminants.
pub const REBRANDED_IDS: &[(u16, u16, ChipFamily)] = &[
    // TP-Link TL-WN822N v4 / TL-WN823Nv2 — RTL8192EU
    (0x2357, 0x0108, ChipFamily::Rtl8192eu),
    (0x2357, 0x0109, ChipFamily::Rtl8192eu),
    (0x2357, 0x0135, ChipFamily::Rtl8192eu),
    // D-Link DWA-131 rev E1 — RTL8192EU
    (0x2001, 0x3319, ChipFamily::Rtl8192eu),
    // EDIMAX EW-7722UTn V3 — RTL8192EU
    (0x7392, 0xB722, ChipFamily::Rtl8192eu),
    // Edimax EW-7811Un V2 — RTL8188EU
    (0x7392, 0xB811, ChipFamily::Rtl8188eu),
    // TP-Link TL-WN722N v2, TL-WN727N v5.21 — RTL8188EU
    (0x2357, 0x010C, ChipFamily::Rtl8188eu),
    (0x2357, 0x0111, ChipFamily::Rtl8188eu),
    // ASUS USB-N10 Nano B1 — RTL8188EU
    (0x0B05, 0x18F0, ChipFamily::Rtl8188eu),
    // Abocom — RTL8188EU
    (0x07B8, 0x8179, ChipFamily::Rtl8188eu),
    // D-Link USB-GO-N150 — RTL8188EU
    (0x2001, 0x3311, ChipFamily::Rtl8188eu),
    // 7392:a611 — RTL8723BU
    (0x7392, 0xA611, ChipFamily::Rtl8723bu),
];

// ── Chip family discriminant ────────────────────────────────────────

/// Identifies which RTL8XXXU chip variant is bound to a USB device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipFamily {
    Rtl8188eu,
    Rtl8192eu,
    Rtl8723bu,
    Rtl8821cu,
    Rtl8822bu,
    Unknown,
}

impl ChipFamily {
    /// Map a (vendor_id, product_id) pair to a chip family.
    pub fn from_usb_id(vid: u16, pid: u16) -> Self {
        match (vid, pid) {
            (RTL8XXXU_VENDOR, RTL8188EU_ID) | (RTL8XXXU_VENDOR, RTL8188EU_ID_ALT) => {
                ChipFamily::Rtl8188eu
            }
            (RTL8XXXU_VENDOR, RTL8192EU_ID) => ChipFamily::Rtl8192eu,
            (RTL8XXXU_VENDOR, RTL8723BU_ID) => ChipFamily::Rtl8723bu,
            (RTL8XXXU_VENDOR, RTL8821CU_ID) => ChipFamily::Rtl8821cu,
            (RTL8XXXU_VENDOR, RTL8822BU_ID) => ChipFamily::Rtl8822bu,
            _ => {
                // Walk rebranded table.
                for &(rv, rp, fam) in REBRANDED_IDS {
                    if rv == vid && rp == pid {
                        return fam;
                    }
                }
                ChipFamily::Unknown
            }
        }
    }

    /// Human-readable chip name.
    pub const fn name(self) -> &'static str {
        match self {
            ChipFamily::Rtl8188eu => "rtl8188eu",
            ChipFamily::Rtl8192eu => "rtl8192eu",
            ChipFamily::Rtl8723bu => "rtl8723bu",
            ChipFamily::Rtl8821cu => "rtl8821cu",
            ChipFamily::Rtl8822bu => "rtl8822bu",
            ChipFamily::Unknown => "rtl8xxxu",
        }
    }

    /// `rtlwifi/rtl8XXXfw.bin` path for use with the firmware registry.
    /// Source: kernel module firmware aliases in each chip's `.c` file.
    pub const fn firmware_name(self) -> Option<&'static str> {
        match self {
            ChipFamily::Rtl8188eu => Some("rtlwifi/rtl8188eufw.bin"),
            ChipFamily::Rtl8192eu => Some("rtlwifi/rtl8192eufw.bin"),
            ChipFamily::Rtl8723bu => Some("rtlwifi/rtl8723bufw.bin"),
            ChipFamily::Rtl8821cu => Some("rtlwifi/rtl8821cufw.bin"),
            ChipFamily::Rtl8822bu => Some("rtlwifi/rtl8822bufw.bin"),
            ChipFamily::Unknown => None,
        }
    }
}

// ── System / power registers ────────────────────────────────────────
//
// Source: `regs.h` 0x0000..0x00FF block.

/// `REG_SYS_ISO_CTRL` — system isolation control. `regs.h` L9.
pub const REG_SYS_ISO_CTRL: u16 = 0x0000;
/// `SYS_ISO_PWC_EV12V` — 1.2V power-cut enable. Bit 15. `regs.h` L14.
pub const SYS_ISO_PWC_EV12V: u16 = 1 << 15;

/// `REG_SYS_FUNC` — system function enable. `regs.h` L16.
pub const REG_SYS_FUNC: u16 = 0x0002;
/// `SYS_FUNC_ELDR` — EFUSE loader function enable. Bit 12. `regs.h` L29.
pub const SYS_FUNC_ELDR: u16 = 1 << 12;
/// `SYS_FUNC_CPU_ENABLE` — MCU CPU enable. Bit 10. `regs.h` L27.
pub const SYS_FUNC_CPU_ENABLE: u16 = 1 << 10;

/// `REG_APS_FSMCO` — auto power-save FSM control. `regs.h` L34.
pub const REG_APS_FSMCO: u16 = 0x0004;
/// `APS_FSMCO_MAC_ENABLE` — enable MAC after power-on. Bit 8. `regs.h` L38.
pub const APS_FSMCO_MAC_ENABLE: u32 = 1 << 8;
/// `APS_FSMCO_MAC_OFF` — power-down MAC. Bit 9.
pub const APS_FSMCO_MAC_OFF: u32 = 1 << 9;

/// `REG_SYS_CLKR` — system clock register. `regs.h` L47.
pub const REG_SYS_CLKR: u16 = 0x0008;
/// `SYS_CLK_ANA8M` — 8 MHz analog clock enable. Bit 1. `regs.h` L49.
pub const SYS_CLK_ANA8M: u16 = 1 << 1;
/// `SYS_CLK_LOADER_ENABLE` — firmware-loader clock. Bit 5. `regs.h` L51.
pub const SYS_CLK_LOADER_ENABLE: u16 = 1 << 5;

/// `REG_9346CR` — EEPROM/EFUSE selection register. `regs.h` L60.
pub const REG_9346CR: u16 = 0x000A;
/// EEPROM boot flag in `REG_9346CR`. Bit 4. `regs.h` L61.
pub const EEPROM_BOOT: u16 = 1 << 4;
/// EEPROM enable flag in `REG_9346CR`. Bit 5. `regs.h` L62.
pub const EEPROM_ENABLE: u16 = 1 << 5;

// ── EFUSE registers ─────────────────────────────────────────────────
//
// Source: `regs.h` L121..L134, `core.c::rtl8xxxu_read_efuse8`.

/// `REG_EFUSE_CTRL` — EFUSE control + per-byte data window. `regs.h` L121.
///
/// Write protocol (per `core.c::rtl8xxxu_read_efuse8`):
///
/// 1. Write byte-address low byte to `REG_EFUSE_CTRL + 1`.
/// 2. Read `REG_EFUSE_CTRL + 2`, mask bits[1:0] to zero, OR in
///    address bits[9:8], write back.
/// 3. Clear bit 7 of `REG_EFUSE_CTRL + 3` to arm the read trigger.
/// 4. Poll `REG_EFUSE_CTRL` (32-bit read) — bit 31 goes high when
///    the data byte is ready in bits[7:0].
pub const REG_EFUSE_CTRL: u16 = 0x0030;

/// `REG_EFUSE_TEST` — EFUSE test / power + WiFi/BT select. `regs.h` L122.
/// `EFUSE_LDOE25_ENABLE` lives here (bit 31).
pub const REG_EFUSE_TEST: u16 = 0x0034;
/// Bit 31 of `REG_EFUSE_TEST` — enable 2.5 V LDO for EFUSE cell.
/// `EFUSE_LDOE25_ENABLE`. `regs.h` L127.
pub const EFUSE_LDOE25_ENABLE: u32 = 1 << 31;
/// Bits[9:8] mask in `REG_EFUSE_TEST` for cell selection.
/// `EFUSE_SELECT_MASK = 0x0300`. `regs.h` L130.
pub const EFUSE_SELECT_MASK: u32 = 0x0300;
/// WiFi cell selection (bits[9:8] = 00). `regs.h` L131.
pub const EFUSE_WIFI_SELECT: u32 = 0x0000;

/// `REG_EFUSE_ACCESS` — enable EFUSE direct access (`REG_00CF`). `regs.h` L301.
pub const REG_EFUSE_ACCESS: u16 = 0x00CF;
/// Magic value to enable EFUSE access. `EFUSE_ACCESS_ENABLE = 0x69`. `regs.h` L133.
pub const EFUSE_ACCESS_ENABLE: u8 = 0x69;
/// Magic value to disable EFUSE access. `EFUSE_ACCESS_DISABLE = 0x00`. `regs.h` L134.
pub const EFUSE_ACCESS_DISABLE: u8 = 0x00;

/// EFUSE physical map length in bytes.
/// `EFUSE_MAP_LEN = 512`. `rtl8xxxu.h` L87.
pub const EFUSE_MAP_LEN: usize = 512;

/// Max EFUSE real content length (same as map for USB family).
/// `EFUSE_REAL_CONTENT_LEN_8723A = 512`.
pub const EFUSE_REAL_CONTENT_LEN: usize = 512;

/// Undefined / unprogrammed EFUSE cell marker.
/// `EFUSE_UNDEFINED = 0xFF`. `rtl8xxxu.h` L93.
pub const EFUSE_UNDEFINED: u8 = 0xFF;

/// Max word unit per EFUSE section (4 × 16-bit words = 8 bytes per section).
/// `EFUSE_MAX_WORD_UNIT = 4`. `rtl8xxxu.h` L92.
pub const EFUSE_MAX_WORD_UNIT: usize = 4;

/// Ready-bit (bit 31) in the 32-bit `REG_EFUSE_CTRL` read, indicates
/// the byte read is valid (set by hardware, polled by driver).
pub const EFUSE_CTRL_VALID: u32 = 1 << 31;

// ── MAC / CR register ───────────────────────────────────────────────
//
// Source: `regs.h` L370.

/// `REG_CR` — chip command register. `regs.h` L370.
pub const REG_CR: u16 = 0x0100;

/// `CR_HCI_TXDMA_ENABLE` — HCI TX DMA enable (bit 0).
pub const CR_HCI_TXDMA_ENABLE: u16 = 1 << 0;
/// `CR_HCI_RXDMA_ENABLE` — HCI RX DMA enable (bit 1).
pub const CR_HCI_RXDMA_ENABLE: u16 = 1 << 1;
/// `CR_TXDMA_ENABLE` — TX DMA enable (bit 2).
pub const CR_TXDMA_ENABLE: u16 = 1 << 2;
/// `CR_RXDMA_ENABLE` — RX DMA enable (bit 3).
pub const CR_RXDMA_ENABLE: u16 = 1 << 3;
/// `CR_PROTOCOL_ENABLE` — protocol engine enable (bit 4).
pub const CR_PROTOCOL_ENABLE: u16 = 1 << 4;
/// `CR_SCHEDULE_ENABLE` — scheduler enable (bit 5).
pub const CR_SCHEDULE_ENABLE: u16 = 1 << 5;
/// `CR_SECURITY_ENABLE` — security engine enable (bit 6).
pub const CR_SECURITY_ENABLE: u16 = 1 << 6;
/// `CR_CALTIMER_ENABLE` — 32 kHz calibration timer enable (bit 7).
pub const CR_CALTIMER_ENABLE: u16 = 1 << 7;

/// CR open mask for 8188EU-style bring-up.
/// Source: `8188e.c::rtl8188eu_power_on` — `CR_HCI_TXDMA_ENABLE |
/// CR_HCI_RXDMA_ENABLE | CR_TXDMA_ENABLE | CR_RXDMA_ENABLE |
/// CR_PROTOCOL_ENABLE | CR_SCHEDULE_ENABLE | CR_SECURITY_ENABLE |
/// CR_CALTIMER_ENABLE`.
pub const CR_OPEN_8188E: u16 = CR_HCI_TXDMA_ENABLE
    | CR_HCI_RXDMA_ENABLE
    | CR_TXDMA_ENABLE
    | CR_RXDMA_ENABLE
    | CR_PROTOCOL_ENABLE
    | CR_SCHEDULE_ENABLE
    | CR_SECURITY_ENABLE
    | CR_CALTIMER_ENABLE;

// ── TX page counts per chip ─────────────────────────────────────────
//
// Source: `rtl8xxxu.h` TX_TOTAL_PAGE_NUM_* defines.

/// TX total pages: 8188E. `TX_TOTAL_PAGE_NUM_8188E = 0xA9`.
pub const TX_TOTAL_PAGE_NUM_8188E: u8 = 0xA9;
/// TX total pages: 8192E. `TX_TOTAL_PAGE_NUM_8192E = 0xF3`.
pub const TX_TOTAL_PAGE_NUM_8192E: u8 = 0xF3;
/// TX total pages: 8723B. `TX_TOTAL_PAGE_NUM_8723B = 0xF7`.
pub const TX_TOTAL_PAGE_NUM_8723B: u8 = 0xF7;
/// TX total pages: default / 8822B. `TX_TOTAL_PAGE_NUM = 0xF8`.
pub const TX_TOTAL_PAGE_NUM_DEFAULT: u8 = 0xF8;

// ── MCU firmware control ────────────────────────────────────────────
//
// Source: `regs.h` (various REG_MCU_* defines).

/// `REG_MCU_FW_DL` — MCU firmware download control register.
/// Value 0x00 = firmware not loaded; `MCU_FW_RAM_SEL (BIT6)` set =
/// firmware running from RAM.
pub const REG_MCU_FW_DL: u16 = 0x0080;
/// Bit 6 of `REG_MCU_FW_DL` — firmware running from on-chip RAM.
pub const MCU_FW_RAM_SEL: u8 = 1 << 6;
/// Firmware page size for IDDMA transfers.
/// `RTL_FW_PAGE_SIZE = 4096`.
pub const RTL_FW_PAGE_SIZE: usize = 4096;
/// Max firmware-download polling iterations.
/// `RTL8XXXU_FIRMWARE_POLL_MAX = 1000`.
pub const FW_POLL_MAX: usize = 1000;

// ── TX descriptor sizes ─────────────────────────────────────────────

/// TX descriptor size for 32-byte descriptor chips (8188EU, 8192EU,
/// 8723BU). Source: `sizeof(struct rtl8xxxu_txdesc32)` in `rtl8xxxu.h`.
pub const TXDESC_SIZE_32: usize = 32;

/// TX descriptor size for 40-byte descriptor chips (8821CU, 8822BU).
/// Source: `sizeof(struct rtl8xxxu_txdesc40)` in `rtl8xxxu.h`.
pub const TXDESC_SIZE_40: usize = 40;

/// RX descriptor size for 8188EU / 8192EU / 8723BU (16 bytes).
/// Source: `sizeof(struct rtl8xxxu_rxdesc16)` in `rtl8xxxu.h` L135.
pub const RXDESC_SIZE_16: usize = 16;

/// RX descriptor size for 8821CU / 8822BU (24 bytes).
/// Source: `sizeof(struct rtl8xxxu_rxdesc24)` in `rtl8xxxu.h` L275.
pub const RXDESC_SIZE_24: usize = 24;

// ── MCU firmware download details ────────────────────────────────────

/// `MCU_FW_DL_ENABLE` — bit 0 of `REG_MCU_FW_DL`. `regs.h` L220.
pub const MCU_FW_DL_ENABLE: u8 = 1 << 0;
/// `MCU_FW_DL_READY` — bit 1 of `REG_MCU_FW_DL`. `regs.h` L221.
pub const MCU_FW_DL_READY: u8 = 1 << 1;
/// `MCU_FW_DL_CSUM_REPORT` — bit 2 of `REG_MCU_FW_DL`. `regs.h` L222.
pub const MCU_FW_DL_CSUM_REPORT: u8 = 1 << 2;
/// `MCU_WINT_INIT_READY` — bit 6 of `REG_MCU_FW_DL`. `regs.h` L226.
pub const MCU_WINT_INIT_READY: u32 = 1 << 6;

/// `REG_FW_START_ADDRESS` — firmware download write window. `regs.h` L1200.
pub const REG_FW_START_ADDRESS: u16 = 0x1000;
/// `REG_HMTFR` — host-to-MCU H2C command FIFO. `regs.h` L456.
pub const REG_HMTFR: u16 = 0x01CC;
/// `REG_TX_REPORT_CTRL` — TX report control.
pub const REG_TX_REPORT_CTRL: u16 = 0x06D2;

/// `REG_TRXFF_BNDY` — TRX FIFO boundary. `regs.h` L423 (= 0x0114).
pub const REG_TRXFF_BNDY: u16 = 0x0114;
/// `REG_TRXDMA_CTRL` — TRX DMA / queue priority control.
pub const REG_TRXDMA_CTRL: u16 = 0x010C;

/// `REG_EDCA_VO_PARAM` — EDCA voice queue parameters. `regs.h` L655.
pub const REG_EDCA_VO_PARAM: u16 = 0x0500;
/// `REG_EDCA_VI_PARAM` — EDCA video queue parameters. `regs.h` L656.
pub const REG_EDCA_VI_PARAM: u16 = 0x0504;
/// `REG_EDCA_BE_PARAM` — EDCA best-effort queue parameters. `regs.h` L657.
pub const REG_EDCA_BE_PARAM: u16 = 0x0508;
/// `REG_EDCA_BK_PARAM` — EDCA background queue parameters. `regs.h` L658.
pub const REG_EDCA_BK_PARAM: u16 = 0x050C;

/// `REG_MACID` — MAC address bytes 0-3 (= 0x0610).
pub const REG_MACID: u16 = 0x0610;
/// `REG_MACID + 4` holds MAC bytes 4-5.
pub const REG_MACID_4_5: u16 = 0x0614;

/// `REG_RCR` — RX configuration. `regs.h` ~L443 (= 0x0608).
pub const REG_RCR: u16 = 0x0608;
/// `REG_BCN_INTERVAL` — beacon interval (1024 µs units). `regs.h` ~L590.
pub const REG_BCN_INTERVAL: u16 = 0x0540;
/// `REG_BSSID` — BSSID register block.
pub const REG_BSSID: u16 = 0x0618;

// ── TX descriptor field shifts ───────────────────────────────────────

/// TX descriptor queue shift in DW1. `rtl8xxxu.h` L494.
pub const TXDESC_QUEUE_SHIFT: u32 = 8;
/// TX descriptor queue mask in DW1. `rtl8xxxu.h` L495.
pub const TXDESC_QUEUE_MASK: u32 = 0x1F00;
/// QSEL: best-effort. `rtl8xxxu.h` L497.
pub const TXDESC_QUEUE_BE: u8 = 0x00;
/// QSEL: background. `rtl8xxxu.h` L496.
pub const TXDESC_QUEUE_BK: u8 = 0x02;
/// QSEL: video. `rtl8xxxu.h` L498.
pub const TXDESC_QUEUE_VI: u8 = 0x05;
/// QSEL: voice. `rtl8xxxu.h` L499.
pub const TXDESC_QUEUE_VO: u8 = 0x07;
/// QSEL: beacon. `rtl8xxxu.h` L500.
pub const TXDESC_QUEUE_BEACON: u8 = 0x10;
/// QSEL: high priority. `rtl8xxxu.h` L501.
pub const TXDESC_QUEUE_HIGH: u8 = 0x11;
/// QSEL: management. `rtl8xxxu.h` L502.
pub const TXDESC_QUEUE_MGNT: u8 = 0x12;
/// QSEL: H2C command. `rtl8xxxu.h` L503.
pub const TXDESC_QUEUE_CMD: u8 = 0x13;

/// `TXDESC_OWN` — bit 31 of DW0. `rtl8xxxu.h` L472.
pub const TXDESC_OWN: u32 = 1 << 31;
/// `TXDESC32_USE_DRIVER_RATE` — DW4 bit 8. `rtl8xxxu.h` L550.
pub const TXDESC32_USE_DRIVER_RATE: u32 = 1 << 8;
/// `TXDESC32_SEQ_SHIFT` — DW3 sequence number shift.
pub const TXDESC32_SEQ_SHIFT: u32 = 16;
/// `TXDESC32_SHORT_GI` — DW4 bit 6. `rtl8xxxu.h` L573.
pub const TXDESC32_SHORT_GI: u32 = 1 << 6;
/// `TXDESC32_RETRY_LIMIT_ENABLE` — DW4 bit 17. `rtl8xxxu.h` L575.
pub const TXDESC32_RETRY_LIMIT_ENABLE: u32 = 1 << 17;
/// `TXDESC32_RETRY_LIMIT_SHIFT` — DW4 bits[23:18]. `rtl8xxxu.h` L576.
pub const TXDESC32_RETRY_LIMIT_SHIFT: u32 = 18;

// ── PHY/BB/RF registers ──────────────────────────────────────────────

/// `REG_FPGA0_RF_MODE` — FPGA RF mode register (0x0800).
pub const REG_FPGA0_RF_MODE: u16 = 0x0800;
/// `REG_FPGA0_TX_INFO` — FPGA TX info register (0x0804).
pub const REG_FPGA0_TX_INFO: u16 = 0x0804;
/// `REG_FPGA0_XAB_RF_SW_CTRL` — FPGA X-AB RF software ctrl (0x0870).
pub const REG_FPGA0_XAB_RF_SW_CTRL: u16 = 0x0870;
/// `REG_RF_CTRL` — RF control register (0x001F).
pub const REG_RF_CTRL: u16 = 0x001F;
/// `REG_OFDM0_TRX_PATH_ENABLE` — OFDM TRX path enable (0x0C04).
pub const REG_OFDM0_TRX_PATH_ENABLE: u16 = 0x0C04;
/// `REG_OFDM0_TR_MUX_PAR` — OFDM TR mux parameter (0x0C08).
pub const REG_OFDM0_TR_MUX_PAR: u16 = 0x0C08;

// ── 5 GHz channel set (8821CU/8822BU) ───────────────────────────────

/// `REG_RF_MODE_AG` — RF mode A/G register for channel switch (0x0D08).
pub const REG_RF_MODE_AG: u16 = 0x0D08;

// ── RF path identifier ──────────────────────────────────────────────

/// RF path A index. `rtl8xxxu.h::RF_A`.
pub const RF_PATH_A: u8 = 0;
/// RF path B index. `rtl8xxxu.h::RF_B`.
pub const RF_PATH_B: u8 = 1;
/// RF register `RF_AC` (channel + bandwidth) — 8821C/8822B 0x18.
pub const RF_REG_CHANNEL: u8 = 0x18;
/// RF register `RF_RXBB2` — 8821C/8822B 0x35.
pub const RF_REG_RXBB2: u8 = 0x35;

// ── IQ calibration register block ────────────────────────────────────

/// `REG_FPGA0_IQK` — start of the IQ-calibration register block (0x0E28).
pub const REG_FPGA0_IQK: u16 = 0x0E28;
/// IQK PI control register A (0x0E40).
pub const REG_TX_IQK_PI_A: u16 = 0x0E40;
/// IQK tone register A (0x0E30).
pub const REG_TX_IQK_TONE_A: u16 = 0x0E30;
/// IQK return value status register (0x0E50).
pub const REG_RX_IQK_TONE_A: u16 = 0x0E50;
/// IQK trigger register (0x0E48).
pub const REG_IQK_AGC_PTS: u16 = 0x0E48;
/// IQK control register (0x0E4C).
pub const REG_IQK_AGC_RSP: u16 = 0x0E4C;

/// `REG_RX_IQK_PI_A` — RX IQK PI control A (0x0E44).
pub const REG_RX_IQK_PI_A: u16 = 0x0E44;
/// `REG_TX_IQK` — TX IQK base (0x0E38).
pub const REG_TX_IQK: u16 = 0x0E38;
/// `REG_RX_IQK` — RX IQK base (0x0E3C).
pub const REG_RX_IQK: u16 = 0x0E3C;
/// `REG_TX_POWER_BEFORE_IQK_A` (0x0E94).
pub const REG_TX_POWER_BEFORE_IQK_A: u16 = 0x0E94;
/// `REG_TX_POWER_AFTER_IQK_A` (0x0E9C).
pub const REG_TX_POWER_AFTER_IQK_A: u16 = 0x0E9C;
/// `REG_RX_POWER_BEFORE_IQK_A_2` (0x0EA4).
pub const REG_RX_POWER_BEFORE_IQK_A_2: u16 = 0x0EA4;
/// `REG_RX_POWER_AFTER_IQK_A_2` (0x0EAC).
pub const REG_RX_POWER_AFTER_IQK_A_2: u16 = 0x0EAC;
/// `REG_TX_POWER_BEFORE_IQK_B` (0x0EB4).
pub const REG_TX_POWER_BEFORE_IQK_B: u16 = 0x0EB4;
/// `REG_TX_POWER_AFTER_IQK_B` (0x0EBC).
pub const REG_TX_POWER_AFTER_IQK_B: u16 = 0x0EBC;

// ── LC calibration register ─────────────────────────────────────────

/// `RF_CHNLBW` — RF channel/bandwidth register used during LC cal (0x18).
pub const RF_REG_LC_CAL: u8 = 0x18;

// ── Additional channel-set + gen2 registers ─────────────────────────

/// `REG_FPGA1_RF_MODE` — secondary FPGA RF mode (0x0900).
pub const REG_FPGA1_RF_MODE: u16 = 0x0900;
/// `REG_CCK0_SYSTEM` — CCK0 system register (0x0A00).
pub const REG_CCK0_SYSTEM: u16 = 0x0A00;
/// `REG_OFDM1_LSTF` — OFDM1 long-symbol training field (0x0D00).
pub const REG_OFDM1_LSTF: u16 = 0x0D00;
/// `REG_WMAC_TRXPTCL_CTL` — TRX protocol control (0x0668).
pub const REG_WMAC_TRXPTCL_CTL: u16 = 0x0668;
/// `REG_DATA_SUBCHANNEL` — data sub-channel (0x0483).
pub const REG_DATA_SUBCHANNEL: u16 = 0x0483;
/// `REG_SIFS_CCK` — SIFS for CCK (0x0514).
pub const REG_SIFS_CCK: u16 = 0x0514;
/// `REG_SIFS_OFDM` — SIFS for OFDM (0x0516).
pub const REG_SIFS_OFDM: u16 = 0x0516;
/// `REG_R2T_SIFS` — RX-to-TX SIFS (0x063A).
pub const REG_R2T_SIFS: u16 = 0x063A;
/// `REG_T2T_SIFS` — TX-to-TX SIFS (0x063C).
pub const REG_T2T_SIFS: u16 = 0x063C;
/// `REG_S0S1_PATH_SWITCH` — antenna S0/S1 path switch (0x0948).
pub const REG_S0S1_PATH_SWITCH: u16 = 0x0948;

/// `WMAC_TRXPTCL_CTL_BW_MASK` (bits 7..8).
pub const WMAC_TRXPTCL_CTL_BW_MASK: u16 = 0x0180;
pub const WMAC_TRXPTCL_CTL_BW_20: u16 = 0x0000;
pub const WMAC_TRXPTCL_CTL_BW_40: u16 = 0x0080;
pub const WMAC_TRXPTCL_CTL_BW_80: u16 = 0x0100;

/// `MODE_AG_CHANNEL_MASK` — channel field (low 8 bits).
pub const MODE_AG_CHANNEL_MASK: u32 = 0x000000FF;
/// `MODE_AG_BW_MASK` — bandwidth field.
pub const MODE_AG_BW_MASK: u32 = 0x00000C00;
pub const MODE_AG_BW_20MHZ_8723B: u32 = 0x00000400;
pub const MODE_AG_BW_40MHZ_8723B: u32 = 0x00000800;
pub const MODE_AG_BW_80MHZ_8723B: u32 = 0x00000C00;

/// `RF6052_REG_MODE_AG` (0x18).
pub const RF6052_REG_MODE_AG: u8 = 0x18;
/// `RF6052_REG_WE_LUT` (0xEF).
pub const RF6052_REG_WE_LUT: u8 = 0xEF;
/// `RF6052_REG_RCK_OS` (0x30).
pub const RF6052_REG_RCK_OS: u8 = 0x30;
/// `RF6052_REG_TXPA_G1` (0x31).
pub const RF6052_REG_TXPA_G1: u8 = 0x31;
/// `RF6052_REG_TXPA_G2` (0x32).
pub const RF6052_REG_TXPA_G2: u8 = 0x32;

// ── 8723B BT coexistence ─────────────────────────────────────────────

/// BT coex H2C command — set TDMA params. `8723b.c` H2C 0x60.
pub const H2C_BT_TDMA: u8 = 0x60;
/// BT coex H2C command — set coex mode. `8723b.c` H2C 0x66.
pub const H2C_BT_SET_MODE: u8 = 0x66;
/// BT coex H2C command — wlan-only. `8723b.c` H2C 0x62.
pub const H2C_BT_WLAN_ONLY: u8 = 0x62;
/// BT coex H2C command — BT info update. 0x63.
pub const H2C_BT_INFO: u8 = 0x63;
