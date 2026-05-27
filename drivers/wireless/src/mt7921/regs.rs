//! MediaTek MT7921 / MT7922 / MT7961 (CONNAC 2.0) register map.
//!
//! Adapted from Linux's `drivers/net/wireless/mediatek/mt76/` tree
//! (GPL-2.0). NARF has been GPL-2.0-or-later since 2026-05-20 so
//! direct adaptation is in-policy.
//!
//! Specifically:
//!
//! - `drivers/net/wireless/mediatek/mt76/mt792x_regs.h` —
//!   `MT_HW_CHIPID` / `MT_HW_REV` / `MT_HW_BOUND`, the `MT_PCIE_MAC`
//!   block, the `MT_CONN_ON_LPCTL` driver-own latch, the `MT_TOP_*`
//!   firmware-state regs, and the `MT_WFDMA0` global config.
//! - `drivers/net/wireless/mediatek/mt76/mt7921/pci.c` —
//!   `mt7921_pci_device_table` for the PCI ID list, plus the
//!   `chipid` derivation around line 358 that re-tags `0x7961`
//!   to `0x7920` when `MT_HW_BOUND` bit 7 is set.
//! - `drivers/net/wireless/mediatek/mt76/mt792x.h` — firmware
//!   filename constants `MT7921_FIRMWARE_WM`, `MT7922_FIRMWARE_WM`,
//!   `MT7921_ROM_PATCH`, `MT7922_ROM_PATCH`.
//! - `drivers/net/wireless/mediatek/mt76/mt7921/mt7921.h` —
//!   `enum mt7921_txq_id` / `enum mt7921_rxq_id`.
//!
//! The MT7921 silicon (Pebble) exposes a flat 32-bit BAR0 register
//! window. The register *addresses* are 32-bit absolute on-chip
//! addresses — Linux uses a per-chip "L1" remap to fold them into
//! the BAR window. The remap is documented in
//! `mt7921/mt7921_l1_rr`; for the baseline we use the same low-16-MiB
//! mapping as Linux: BAR0 starts at chip address 0, so absolute
//! addresses 0x0_0000..0xff_ffff are direct offsets.

#![allow(dead_code)]

// ── PCI device IDs (vendor 0x14C3 = MediaTek Inc.) ─────────────────
//
// Per Linux `mt7921/pci.c::mt7921_pci_device_table`. The MT7920 (DBDC
// variant) appears via runtime re-tagging from 0x7961 — see
// `chip_re_id_on_bound`.

/// MediaTek Inc.
pub const MTK_VENDOR: u16 = 0x14C3;
/// ITTIM Corp. — surfaces MT7922 under a different vendor on some
/// laptop SKUs (per Linux's table).
pub const ITTIM_VENDOR: u16 = 0x0E8D;

/// MT7961 (Wi-Fi 6E 2x2). Cited in `mt7921_pci_device_table`.
pub const MTK_DEV_MT7961: u16 = 0x7961;
/// MT7922 (Wi-Fi 6E 2x2, newer cut). Cited in `mt7921_pci_device_table`.
pub const MTK_DEV_MT7922: u16 = 0x7922;
/// MT7921 reference / engineering SKU. Cited as `0x0608` in
/// `mt7921_pci_device_table`.
pub const MTK_DEV_MT7921: u16 = 0x0608;
/// MT7921 alternate SKU.
pub const MTK_DEV_MT7921_ALT: u16 = 0x0616;
/// MT7920 (DBDC variant). Cited at line 26 of `mt7921_pci_device_table`.
pub const MTK_DEV_MT7920: u16 = 0x7920;

/// Every PCI device id we register a match for. Sync with `name_for`.
pub const ALL_DEV_IDS: &[u16] = &[
    MTK_DEV_MT7961,
    MTK_DEV_MT7922,
    MTK_DEV_MT7921,
    MTK_DEV_MT7921_ALT,
    MTK_DEV_MT7920,
];

// ── Identity / revision (absolute addresses) ───────────────────────
//
// Per Linux `mt792x_regs.h`:
//   #define MT_HW_BOUND   0x70010020
//   #define MT_HW_CHIPID  0x70010200
//   #define MT_HW_REV     0x70010204

/// 32-bit chip-id register. Reads back to e.g. `0x7961`, `0x7922`.
pub const MT_HW_CHIPID: u32 = 0x70010200;
/// 32-bit chip revision (8-bit field in low byte).
pub const MT_HW_REV: u32 = 0x70010204;
/// 32-bit "HW bound" register. Bit 7 distinguishes MT7920 from
/// MT7961 — see `chip_re_id_on_bound`.
pub const MT_HW_BOUND: u32 = 0x70010020;
/// Bit 7 of `MT_HW_BOUND`: silicon was bonded as MT7920 (DBDC).
pub const MT_HW_BOUND_DBDC: u32 = 1 << 7;

// ── PCIe MAC block (BAR0 + offset) ─────────────────────────────────
//
// Per `mt792x_regs.h`:
//   #define MT_PCIE_MAC_BASE        0x10000
//   #define MT_PCIE_MAC(ofs)        (MT_PCIE_MAC_BASE + (ofs))
//   #define MT_PCIE_MAC_INT_ENABLE  MT_PCIE_MAC(0x188)
//   #define MT_PCIE_MAC_PM          MT_PCIE_MAC(0x194)
//   #define MT_PCIE_MAC_PM_L0S_DIS  BIT(8)

/// Base of the PCIe-MAC register block in BAR0.
pub const MT_PCIE_MAC_BASE: u32 = 0x10000;
/// Interrupt-enable mask in the PCIe MAC block. Linux writes 0xff
/// during probe to enable the host-IRQ delivery.
pub const MT_PCIE_MAC_INT_ENABLE: u32 = MT_PCIE_MAC_BASE + 0x188;
/// Power-management override. Bit 8 disables L0s entry.
pub const MT_PCIE_MAC_PM: u32 = MT_PCIE_MAC_BASE + 0x194;
/// PM bit: disable L0s low-power entry (kept off while driver holds
/// ownership of the link).
pub const MT_PCIE_MAC_PM_L0S_DIS: u32 = 1 << 8;

// ── Driver / firmware ownership handshake ──────────────────────────
//
// Per `mt792x_regs.h` ~L469:
//   #define MT_CONN_ON_LPCTL        0x7c060010
//   #define PCIE_LPCR_HOST_SET_OWN  BIT(0)
//   #define PCIE_LPCR_HOST_CLR_OWN  BIT(1)
//   #define PCIE_LPCR_HOST_OWN_SYNC BIT(2)
//
// Driver takes ownership by writing PCIE_LPCR_HOST_CLR_OWN and
// polling `PCIE_LPCR_HOST_OWN_SYNC` for 0 (sync clear). Driver gives
// ownership back to firmware by writing `PCIE_LPCR_HOST_SET_OWN` and
// polling `PCIE_LPCR_HOST_OWN_SYNC` for 4 (sync set, BIT(2)).

/// Driver-own / FW-own latch register.
pub const MT_CONN_ON_LPCTL: u32 = 0x7c060010;
/// Write-1 to give the link back to firmware (sleep).
pub const PCIE_LPCR_HOST_SET_OWN: u32 = 1 << 0;
/// Write-1 to take the link for the driver (wake).
pub const PCIE_LPCR_HOST_CLR_OWN: u32 = 1 << 1;
/// Status bit: ownership sync in flight (busy while not zero after
/// CLR; non-zero indicates FW still owns the link).
pub const PCIE_LPCR_HOST_OWN_SYNC: u32 = 1 << 2;

// ── Firmware-state probe (CONNAC2 TOP block) ───────────────────────
//
// Per `mt792x_regs.h`:
//   #define MT_TOP_BASE           0x18060000
//   #define MT_TOP(ofs)           (MT_TOP_BASE + (ofs))
//   #define MT_TOP_LPCR_HOST_BAND0    MT_TOP(0x10)
//   #define MT_TOP_LPCR_HOST_FW_OWN   BIT(0)
//   #define MT_TOP_LPCR_HOST_DRV_OWN  BIT(1)
//   #define MT_TOP_MISC               MT_TOP(0xf0)
//   #define MT_TOP_MISC_FW_STATE      GENMASK(2, 0)

/// Top-of-CONNAC misc/status register. The low 3 bits encode
/// firmware state (`MT_TOP_MISC_FW_STATE`). Driver waits for state
/// `FW_STATE_RDY = 7` before issuing MCU commands.
pub const MT_TOP_MISC: u32 = 0x18060000 + 0xf0;
/// Mask of the FW_STATE field in `MT_TOP_MISC`.
pub const MT_TOP_MISC_FW_STATE: u32 = 0x7;
/// Value of `MT_TOP_MISC_FW_STATE` once firmware patch is loaded and
/// the chip's MCU is in the steady-state.
pub const FW_STATE_RDY: u32 = 1;

// ── WFDMA0 (host DMA controller) ───────────────────────────────────
//
// Per `mt792x_regs.h`:
//   #define MT_WFDMA0_BASE   0xd4000
//   #define MT_WFDMA0(ofs)   (MT_WFDMA0_BASE + (ofs))
//   #define MT_WFDMA0_RST            MT_WFDMA0(0x100)
//   #define MT_WFDMA0_RST_LOGIC_RST  BIT(4)
//   #define MT_WFDMA0_RST_DMASHDL_ALL_RST BIT(5)
//   #define MT_WFDMA0_GLO_CFG        MT_WFDMA0(0x208)
//   #define MT_WFDMA0_GLO_CFG_TX_DMA_EN  BIT(0)
//   #define MT_WFDMA0_GLO_CFG_RX_DMA_EN  BIT(2)
//   #define MT_MCU_CMD                   MT_WFDMA0(0x1f0)
//   #define MT_MCU_CMD_WAKE_RX_PCIE      BIT(0)

/// WFDMA0 base in BAR0.
pub const MT_WFDMA0_BASE: u32 = 0xd4000;
/// WFDMA0 reset register.
pub const MT_WFDMA0_RST: u32 = MT_WFDMA0_BASE + 0x100;
/// `MT_WFDMA0_RST_LOGIC_RST` — reset host-DMA logic.
pub const MT_WFDMA0_RST_LOGIC_RST: u32 = 1 << 4;
/// `MT_WFDMA0_RST_DMASHDL_ALL_RST` — reset DMA scheduler.
pub const MT_WFDMA0_RST_DMASHDL_ALL_RST: u32 = 1 << 5;
/// WFDMA0 global-config register.
pub const MT_WFDMA0_GLO_CFG: u32 = MT_WFDMA0_BASE + 0x208;
/// `MT_WFDMA0_GLO_CFG_TX_DMA_EN` — enable host TX DMA.
pub const MT_WFDMA0_GLO_CFG_TX_DMA_EN: u32 = 1 << 0;
/// `MT_WFDMA0_GLO_CFG_RX_DMA_EN` — enable host RX DMA.
pub const MT_WFDMA0_GLO_CFG_RX_DMA_EN: u32 = 1 << 2;
/// MCU command mailbox.
pub const MT_MCU_CMD: u32 = MT_WFDMA0_BASE + 0x1f0;
/// MCU command: wake the PCIe RX path.
pub const MT_MCU_CMD_WAKE_RX_PCIE: u32 = 1 << 0;

// ── Driver-own poll budget ─────────────────────────────────────────
//
// Linux retries `__mt792xe_mcu_drv_pmctrl` up to MT792x_DRV_OWN_RETRY_COUNT
// times, each polling MT_CONN_ON_LPCTL for up to 50 ms in 1 ms ticks.
// Match the shape but keep the budget bounded so the probe path
// doesn't wedge if the chip is absent.

/// Number of CLR_OWN write retries (Linux: `MT792x_DRV_OWN_RETRY_COUNT`).
pub const DRV_OWN_RETRY_COUNT: usize = 10;
/// Per-retry wall-clock budget for the OWN_SYNC poll, in ms.
pub const DRV_OWN_POLL_MS: u64 = 50;

// ── Firmware filenames ─────────────────────────────────────────────
//
// Per `mt792x.h` ~L45..L51:
//   MT7921_FIRMWARE_WM = "mediatek/WIFI_RAM_CODE_MT7961_1.bin"
//   MT7922_FIRMWARE_WM = "mediatek/WIFI_RAM_CODE_MT7922_1.bin"
//   MT7921_ROM_PATCH   = "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin"
//   MT7922_ROM_PATCH   = "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin"
//
// MT7921 family ships a "patch" blob applied first, then a "RAM
// code" blob that is the runtime firmware. The patch primes the MCU
// boot ROM; the RAM code is the live image.

/// Runtime ("WM") firmware blob name for MT7961-class silicon.
pub const MT7961_FIRMWARE_WM: &str = "mediatek/WIFI_RAM_CODE_MT7961_1.bin";
/// Runtime ("WM") firmware blob name for MT7922-class silicon.
pub const MT7922_FIRMWARE_WM: &str = "mediatek/WIFI_RAM_CODE_MT7922_1.bin";
/// ROM patch blob for MT7961.
pub const MT7961_ROM_PATCH: &str = "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin";
/// ROM patch blob for MT7920 (DBDC bond of MT7961 silicon).
pub const MT7920_ROM_PATCH: &str = "mediatek/WIFI_MT7961_patch_mcu_1a_2_hdr.bin";
/// ROM patch blob for MT7922.
pub const MT7922_ROM_PATCH: &str = "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin";

// ── EFUSE access ───────────────────────────────────────────────────
//
// MT7921 reads EFUSE through an MCU command (`MCU_CMD_EFUSE_ACCESS`)
// rather than a direct register loop — see Linux
// `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c::
//  mt76_connac_mcu_get_eeprom`. Because that path requires the MCU
// to be alive (post-firmware-load), Stage-1 here only stages the MCU
// command opcode; the actual read goes via the MCU mailbox in
// `mcu.rs`.

/// MCU command opcode: EFUSE access (Linux `MCU_EXT_CMD_EFUSE_ACCESS`).
pub const MCU_EXT_CMD_EFUSE_ACCESS: u8 = 0x01;
/// MCU command opcode: EFUSE bulk read (Linux `MCU_EXT_CMD_EFUSE_BUFFER_MODE`).
pub const MCU_EXT_CMD_EFUSE_BUFFER_MODE: u8 = 0x21;
/// Logical EFUSE offset of the factory MAC. Linux: `eeprom.mac_addr`
/// at offset 0 of the EFUSE map (`mt76_connac_eeprom_get_mac`).
pub const EFUSE_MAC_OFFSET: u32 = 0x0000;
/// MAC address length in bytes.
pub const MAC_ADDR_LEN: usize = 6;

// ── TX / RX ring queue ids ─────────────────────────────────────────
//
// Per `mt7921.h::enum mt7921_txq_id` and `enum mt7921_rxq_id`.
//
// Linux uses the WMM AC ordering for the four data TX rings (VO/VI/
// BE/BK = 0..3) plus a beacon-multicast (BMC) ring for groupcast +
// CAB delivery. MCU command + firmware-download rings live on the
// MCU side.

/// TX ring 0 — AC_VO (voice). Highest-priority data ring.
pub const MT7921_TXQ_AC_VO: u8 = 0;
/// TX ring 1 — AC_VI (video).
pub const MT7921_TXQ_AC_VI: u8 = 1;
/// TX ring 2 — AC_BE (best-effort, default).
pub const MT7921_TXQ_AC_BE: u8 = 2;
/// TX ring 3 — AC_BK (background).
pub const MT7921_TXQ_AC_BK: u8 = 3;
/// TX ring 4 — beacon / multicast / CAB.
pub const MT7921_TXQ_BMC: u8 = 4;
/// Number of TX rings provisioned (4 AC + 1 BMC).
pub const MT7921_TX_RING_COUNT: usize = 5;

/// RX ring 0 — host-bound data frames (BAND0).
pub const MT7921_RXQ_DATA: u8 = 0;
/// RX ring 1 — MCU event ring (firmware → host responses).
pub const MT7921_RXQ_MCU_EVENT: u8 = 1;
/// Number of RX rings provisioned (data + event).
pub const MT7921_RX_RING_COUNT: usize = 2;

/// Default per-ring depth. Linux uses 128 entries for the data rings
/// and 32 for the MCU event ring; the baseline picks a single power-
/// of-two depth that fits both — DMA ring init in `mac.rs` will
/// refine per-ring once real silicon bring-up lands.
pub const MT7921_RING_DEPTH: usize = 128;
