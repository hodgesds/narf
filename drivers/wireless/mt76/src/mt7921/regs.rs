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
//! Chip addresses are not BAR offsets. A 1 MiB BAR contains fixed windows
//! and a 64 KiB L1 aperture selected through a read-modify-write register.
//! See `registers` for checked translation and posted-write ordering.

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
/// MT7925 (Wi-Fi 7 2x2, CONNAC3). Cited as `0x7925` in upstream
/// `mt7925/pci.c::mt7925_pci_device_table`.
pub const MTK_DEV_MT7925: u16 = 0x7925;
/// MT7925 alternate SKU — the PCI device id on Daniel's Alder Lake card
/// (`14c3:0717`). Cited as `0x0717` in upstream
/// `mt7925/pci.c::mt7925_pci_device_table`.
pub const MTK_DEV_MT7925_ALT: u16 = 0x0717;

/// Every PCI device id we register a match for. Sync with `name_for`.
pub const ALL_DEV_IDS: &[u16] = &[
    MTK_DEV_MT7961,
    MTK_DEV_MT7922,
    MTK_DEV_MT7921,
    MTK_DEV_MT7921_ALT,
    MTK_DEV_MT7920,
    MTK_DEV_MT7925,
    MTK_DEV_MT7925_ALT,
];

/// True when `did` is an MT7925 PCI id — `0x7925` or its `0x0717`
/// alias. Per-chip branches (DMA layout, register map) key off this,
/// not off the raw `MT_HW_CHIPID` value: the probe's chip-id gate
/// (`pci.rs:441`) is still closed for MT7925 pending the Q1 hardware
/// read, so the PCI id is the only 7925 identity the driver can
/// trust today.
pub const fn is_mt7925_did(did: u16) -> bool {
    matches!(did, MTK_DEV_MT7925 | MTK_DEV_MT7925_ALT)
}

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
/// MT7920's distinct WM image, paired with its `1a_2` ROM patch (Linux mt7921).
pub const MT7920_FIRMWARE_WM: &str = "mediatek/WIFI_RAM_CODE_MT7961_1a.bin";
/// Runtime ("WM") firmware blob name for MT7922-class silicon.
pub const MT7922_FIRMWARE_WM: &str = "mediatek/WIFI_RAM_CODE_MT7922_1.bin";
/// ROM patch blob for MT7961.
pub const MT7961_ROM_PATCH: &str = "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin";
/// ROM patch blob for MT7920 (DBDC bond of MT7961 silicon).
pub const MT7920_ROM_PATCH: &str = "mediatek/WIFI_MT7961_patch_mcu_1a_2_hdr.bin";
/// ROM patch blob for MT7922.
pub const MT7922_ROM_PATCH: &str = "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin";
/// Runtime ("WM") firmware blob name for MT7925-class silicon. Per
/// upstream `mt792x.h:51` (`MT7925_FIRMWARE_WM`).
pub const MT7925_FIRMWARE_WM: &str = "mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin";
/// ROM patch blob for MT7925. Per upstream `mt792x.h:59`
/// (`MT7925_ROM_PATCH`).
pub const MT7925_ROM_PATCH: &str = "mediatek/mt7925/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin";

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

/// MT7925 TX queue ids — per upstream `mt7925.h:218-241`
/// (`enum mt7925_txq_id`). CONNAC3 numbering differs from CONNAC2:
/// MCU_WM is 15 (not 17) and FWDL keeps 16.
pub const MT7925_TXQ_BAND0: u8 = 0;
/// TX queue 1 — BAND1 data. In the enum, but not wired in the MT7925
/// DMA layout (no BAND1 data ring), so `mt7925_tx_ring_regs` rejects it.
pub const MT7925_TXQ_BAND1: u8 = 1;
/// TX queue 15 — MCU command ring (CONNAC2: 17).
pub const MT7925_TXQ_MCU_WM: u8 = 15;
/// TX queue 16 — firmware-download ring.
pub const MT7925_TXQ_FWDL: u8 = 16;
/// Number of TX data rings in the MT7925 DMA layout (BAND0 only).
pub const MT7925_TX_DATA_RING_COUNT: usize = 1;

/// MT7925 RX queue ids — per upstream `mt7925.h:218-241`
/// (`enum mt7925_rxq_id`). Data is BAND0 = 2 (CONNAC2: 0) and the
/// MCU event ring is 0.
pub const MT7925_RXQ_MCU_WM: u8 = 0;
/// RX queue 1 — MCU_WM2 (TX-done). In the enum, but MT7928-only: it
/// is not wired in the MT7925 DMA layout, so `mt7925_rx_ring_regs`
/// rejects it.
pub const MT7925_RXQ_MCU_WM2: u8 = 1;
/// RX queue 2 — host-bound data frames (BAND0).
pub const MT7925_RXQ_BAND0: u8 = 2;
/// RX queue 3 — BAND1 data. In the enum, but not wired in the MT7925
/// DMA layout (no BAND1 data ring).
pub const MT7925_RXQ_BAND1: u8 = 3;

/// Default per-ring depth. Linux uses 128 entries for the data rings
/// and 32 for the MCU event ring; the baseline picks a single power-
/// of-two depth that fits both — DMA ring init in `mac.rs` will
/// refine per-ring once real silicon bring-up lands.
pub const MT7921_RING_DEPTH: usize = 128;

// ── Per-ring sizes (Linux `mt7921.h` ~L10..L16) ────────────────────

/// TX data ring depth on real Linux (`MT7921_TX_RING_SIZE`).
pub const LINUX_MT7921_TX_RING_SIZE: usize = 2048;
/// MCU command TX ring depth on real Linux (`MT7921_TX_MCU_RING_SIZE`).
pub const LINUX_MT7921_TX_MCU_RING_SIZE: usize = 256;
/// Firmware-download TX ring depth on real Linux (`MT7921_TX_FWDL_RING_SIZE`).
pub const LINUX_MT7921_TX_FWDL_RING_SIZE: usize = 128;
/// Data RX ring depth on real Linux (`MT7921_RX_RING_SIZE`).
pub const LINUX_MT7921_RX_RING_SIZE: usize = 1536;
/// Pre-firmware MCU event RX ring depth (`MT7921_RX_MCU_RING_SIZE`).
pub const LINUX_MT7921_RX_MCU_RING_SIZE: usize = 8;
/// Post-firmware MCU "WA" event RX ring depth (`MT7921_RX_MCU_WA_RING_SIZE`).
pub const LINUX_MT7921_RX_MCU_WA_RING_SIZE: usize = 512;

/// MT7925 ring sizes + token size — per upstream `mt7925.h:27-43`
/// (torvalds/linux `8d7fe988`). TX / TX_MCU / FWDL / RX / TOKEN are
/// identical to MT7921; only RX_MCU differs (512 vs 7921's 8).
/// `MT7928_RX_MCU_WA_RING_SIZE` (512) is a 7928-only constant and is
/// deliberately not used here.
///
/// TX data ring depth (`MT7925_TX_RING_SIZE`).
pub const LINUX_MT7925_TX_RING_SIZE: usize = 2048;
/// MCU command TX ring depth (`MT7925_TX_MCU_RING_SIZE`).
pub const LINUX_MT7925_TX_MCU_RING_SIZE: usize = 256;
/// Firmware-download TX ring depth (`MT7925_TX_FWDL_RING_SIZE`).
pub const LINUX_MT7925_TX_FWDL_RING_SIZE: usize = 128;
/// Data RX ring depth (`MT7925_RX_RING_SIZE`).
pub const LINUX_MT7925_RX_RING_SIZE: usize = 1536;
/// MCU event RX ring depth (`MT7925_RX_MCU_RING_SIZE`). The only
/// size that differs from MT7921.
pub const LINUX_MT7925_RX_MCU_RING_SIZE: usize = 512;
/// Token-table size (`MT7925_TOKEN_SIZE`). Same value as MT7921's
/// (`packet_tx.rs::TOKEN_LIMIT`).
pub const LINUX_MT7925_TOKEN_SIZE: usize = 8192;
/// TXWI size in bytes. Upstream `mt7925/pci.c:1113`: `.txwi_size =
/// MT_TXD_SIZE + sizeof(struct mt76_connac_hw_txp)` = 32 + 32.
/// Same value as MT7921 (`txrx.rs::TXD_SIZE` = 32).
pub const MT7925_TXWI_SIZE: usize = 64;

/// Stage-4 baseline ring depth (one 4 KiB DmaBuffer = 16 entries of
/// 16-byte mt76_desc).
pub const MT7921_BASELINE_RING_DEPTH: usize = 16;

// ── WFDMA0 control extensions (mt792x_regs.h ~L290..L350) ──────────

/// `MT_WFDMA0_GLO_CFG_TX_DMA_BUSY` — TX engine busy.
pub const MT_WFDMA0_GLO_CFG_TX_DMA_BUSY: u32 = 1 << 1;
/// `MT_WFDMA0_GLO_CFG_RX_DMA_BUSY` — RX engine busy.
pub const MT_WFDMA0_GLO_CFG_RX_DMA_BUSY: u32 = 1 << 3;
/// `MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN`.
pub const MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN: u32 = 1 << 12;
/// `MT_WFDMA0_GLO_CFG_RX_WB_DDONE`.
pub const MT_WFDMA0_GLO_CFG_RX_WB_DDONE: u32 = 1 << 13;
/// `MT_WFDMA0_GLO_CFG_OMIT_RX_INFO`.
pub const MT_WFDMA0_GLO_CFG_OMIT_RX_INFO: u32 = 1 << 27;
/// `MT_WFDMA0_GLO_CFG_OMIT_TX_INFO`.
pub const MT_WFDMA0_GLO_CFG_OMIT_TX_INFO: u32 = 1 << 28;
/// `MT_WFDMA0_GLO_CFG_CLK_GAT_DIS`.
pub const MT_WFDMA0_GLO_CFG_CLK_GAT_DIS: u32 = 1 << 30;

/// `MT_TX_RING_BASE` (== `MT_WFDMA0(0x300)`).
pub const MT_TX_RING_BASE: u32 = MT_WFDMA0_BASE + 0x300;
/// `MT_RX_EVENT_RING_BASE` (== `MT_WFDMA0(0x500)`).
pub const MT_RX_EVENT_RING_BASE: u32 = MT_WFDMA0_BASE + 0x500;
/// Post-firmware MCU-WA event ring base.
pub const MT_RX_MCU_WA_RING_BASE: u32 = MT_WFDMA0_BASE + 0x540;
/// `MT_RX_DATA_RING_BASE` (== `MT_WFDMA0(0x520)`).
pub const MT_RX_DATA_RING_BASE: u32 = MT_WFDMA0_BASE + 0x520;

/// Per-ring MMIO stride (16 bytes: base_lo + depth + cidx + didx).
pub const RING_REG_STRIDE: u32 = 0x10;

/// `MT_WFDMA0_HOST_INT_ENA`.
pub const MT_WFDMA0_HOST_INT_ENA: u32 = MT_WFDMA0_BASE + 0x204;
/// `MT_WFDMA0_HOST_INT_STA`.
pub const MT_WFDMA0_HOST_INT_STA: u32 = MT_WFDMA0_BASE + 0x200;
/// `MT_MCU2HOST_SW_INT_ENA`.
pub const MT_MCU2HOST_SW_INT_ENA: u32 = MT_WFDMA0_BASE + 0x1f4;

// ── INFRA bus windows (mt7921/regs.h:63..70) ───────────────────────

/// `MT_INFRA_CFG_BASE` (BAR0 offset 0xfe000).
pub const MT_INFRA_CFG_BASE: u32 = 0xfe000;
/// `MT_HIF_REMAP_L1` — per-driver L1 remap register.
pub const MT_HIF_REMAP_L1: u32 = MT_INFRA_CFG_BASE + 0x24c;
/// Lower-half mask of `MT_HIF_REMAP_L1`.
pub const MT_HIF_REMAP_L1_MASK: u32 = 0x0000_FFFF;
/// Upper-half mask of `MT_HIF_REMAP_L1`.
pub const MT_HIF_REMAP_L1_BASE: u32 = 0xFFFF_0000;
/// Where the L1-remapped slab lands in BAR0.
pub const MT_HIF_REMAP_BASE_L1: u32 = 0x40000;

/// `MT_WFSYS_SW_RST_B` — Wi-Fi subsystem soft-reset.
pub const MT_WFSYS_SW_RST_B: u32 = 0x18000140;

// ── MT7925 (CONNAC3) L1 remap + reset (mt7925/regs.h:80..92) ───────
//
// Verified against torvalds/linux 8d7fe9885c62. The 7925 values are
// NOT the 7921 values shifted: the selector is a literal `0x155024`
// (not `MT_INFRA(0x24c)` — 7925's `MT_INFRA_CFG_BASE` is `0xd1000`,
// so that would be `0xd124c`), the page field sits in the HIGH half
// of the selector (`GENMASK(31, 16)`, where 7921 uses the low half),
// and the remapped slab lands at `0x130000`, not `0x40000`.
// `MT_HIF_REMAP_L1_OFFSET` (`GENMASK(15, 0)`) is the same on both
// chips, so the window offset is `base + (addr & 0xffff)` either way.

/// `MT_HIF_REMAP_L1` on MT7925 — upstream `mt7925/regs.h:83`.
pub const MT7925_HIF_REMAP_L1: u32 = 0x155024;
/// `MT_HIF_REMAP_L1_MASK` on MT7925 — `GENMASK(31, 16)`.
pub const MT7925_HIF_REMAP_L1_MASK: u32 = 0xFFFF_0000;
/// `MT_HIF_REMAP_BASE_L1` on MT7925.
pub const MT7925_HIF_REMAP_BASE_L1: u32 = 0x130000;
/// `MT_WFSYS_SW_RST_B` on MT7925 — upstream `mt7925/regs.h:92`.
pub const MT7925_WFSYS_SW_RST_B: u32 = 0x7c000140;

/// Per-chip L1 remap geometry: selector BAR0 offset, selector field
/// mask, and window base. Both chips take the page from the same
/// bits of the chip address (`addr >> 16`); only where the field
/// lands in the selector differs, so [`L1Remap::field`] shifts the
/// page to the mask's low bit (`FIELD_PREP(mask, page)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L1Remap {
    /// BAR0 offset of the L1 selector register.
    pub selector: u32,
    /// Selector field mask holding the page (`GENMASK(15, 0)` on
    /// CONNAC2, `GENMASK(31, 16)` on MT7925).
    pub mask: u32,
    /// BAR0 offset where the L1-remapped slab lands.
    pub base: u32,
}
impl L1Remap {
    /// L1 geometry for `did`: MT7925 ids select the CONNAC3 values,
    /// every other registered id keeps the CONNAC2 values.
    pub const fn for_chip(did: u16) -> Self {
        if is_mt7925_did(did) {
            Self {
                selector: MT7925_HIF_REMAP_L1,
                mask: MT7925_HIF_REMAP_L1_MASK,
                base: MT7925_HIF_REMAP_BASE_L1,
            }
        } else {
            Self {
                selector: MT_HIF_REMAP_L1,
                mask: MT_HIF_REMAP_L1_MASK,
                base: MT_HIF_REMAP_BASE_L1,
            }
        }
    }
    /// `FIELD_PREP(mask, page)`: the page value placed in the
    /// selector field, preserving the unrelated selector bits
    /// outside the mask when ORed in by the caller.
    pub const fn field(&self, page: u16) -> u32 {
        (page as u32) << self.mask.trailing_zeros()
    }
}

/// WFSYS soft-reset chip address for `did`: MT7925 ids select the
/// CONNAC3 address, every other registered id keeps the CONNAC2 one.
/// Both addresses route through the per-chip L1/fixed map in
/// `registers::plan`, so callers pass the chip address unchanged.
pub const fn wfsys_sw_rst_b(did: u16) -> u32 {
    if is_mt7925_did(did) {
        MT7925_WFSYS_SW_RST_B
    } else {
        MT_WFSYS_SW_RST_B
    }
}

// ── Extra MCU command opcodes (mt76_connac_mcu.h:1215..L1313) ──────

/// `MCU_EXT_CMD_PM_STATE_CTRL`.
pub const MCU_EXT_CMD_PM_STATE_CTRL: u8 = 0x07;
/// `MCU_EXT_CMD_CHANNEL_SWITCH`.
pub const MCU_EXT_CMD_CHANNEL_SWITCH: u8 = 0x08;
/// `MCU_EXT_CMD_DEV_INFO_UPDATE`.
pub const MCU_EXT_CMD_DEV_INFO_UPDATE: u8 = 0x2A;
/// `MCU_EXT_CMD_BSS_INFO_UPDATE`.
pub const MCU_EXT_CMD_BSS_INFO_UPDATE: u8 = 0x26;

/// `MCU_UNI_CMD_DEV_INFO_UPDATE`.
pub const MCU_UNI_CMD_DEV_INFO_UPDATE: u8 = 0x01;

// ── Patch / firmware-download MCU opcodes ──────────────────────────

/// `MCU_CMD_TARGET_ADDRESS_LEN_REQ` (opcode 0x01).
pub const MCU_CMD_TARGET_ADDRESS_LEN_REQ: u8 = 0x01;
/// `MCU_CMD_FW_START_REQ` (opcode 0x02).
pub const MCU_CMD_FW_START_REQ: u8 = 0x02;
/// `MCU_CMD_PATCH_START_REQ` (opcode 0x05).
pub const MCU_CMD_PATCH_START_REQ: u8 = 0x05;
/// `MCU_CMD_FW_SCATTER` (opcode 0xee).
pub const MCU_CMD_FW_SCATTER: u8 = 0xEE;

// ── 5 GHz channels ────────────────────────────────────────────────

/// Channel 36 (5180 MHz). Default Stage-7 association channel.
pub const MT7921_DEFAULT_CHAN_5G: u8 = 36;
/// Channel 36 centre frequency (MHz).
pub const MT7921_DEFAULT_CHAN_5G_MHZ: u16 = 5180;

// ── INIT_RA_CFG (per Linux `mt76_connac_mcu.h:1226`, ext-cid 0x90) ─

/// `MCU_EXT_CMD_INIT_RA_CFG` — initialise the rate-adaptation config.
/// Per `mt76_connac_mcu.h` the opcode is part of the `MCU_EXT_CMD_*`
/// table; Linux's `mt76_connac_mcu_set_rate_txpower` ultimately routes
/// to opcode `0x90` for this leg.
pub const MCU_EXT_CMD_INIT_RA_CFG: u8 = 0x90;
