//! Qualcomm Atheros QCA-family register + chip-ID constants.
//!
//! Numbers sourced from Linux `drivers/net/wireless/ath/ath10k/hw.h`
//! (kernel 6.10+; ISC-licensed but NARF is GPL-2.0-or-later post
//! 2026-05-20, so direct reference + adaptation is in-policy per
//! `memory/MEMORY.md::feedback_no_gpl_links.md`). The ath10k vendor
//! ID is the Atheros / Qualcomm Atheros legacy 0x168c.
//!
//! ## Layout primer
//!
//! ath10k devices expose a single PCIe BAR0 register window. From
//! the host's perspective the device memory map is:
//!
//! ```text
//!   0x00000 .. 0x07fff   SoC core / PCIe local
//!   0x08000 .. 0x0ffff   SoC PCIe block (CORE_CTRL, PCIE_INTR_*)
//!   0x10000 .. 0x1ffff   WLAN (mac / phy / efuse)
//!   0x20000 .. 0x2ffff   reserved
//!   0x30000 .. 0x6ffff   per-chip private (BTI / DBI / analog)
//! ```
//!
//! Within "SoC core" lives the global-reset register
//! (`SOC_GLOBAL_RESET_ADDRESS = 0x0008`). Within "SoC PCIe block"
//! live `PCIE_INTR_ENABLE` / `PCIE_INTR_CAUSE`. Within "WLAN" live
//! the Copy-Engine register banks `CE0..CE7`.
//!
//! ## References (Linux v6.10)
//!
//! - `ath10k/hw.h` lines ~860..1020 — base-address + reset offsets.
//! - `ath10k/hw.h` lines ~24..50 — PCI device IDs.
//! - `ath10k/hw.h` lines ~227..240 — `enum ath10k_hw_rev`.
//! - `ath10k/hw.c` lines ~462..481 — `qcax_ce_regs` (CE register
//!   offsets shared by 988X / 6174 / 99X0 / 9377 / 9888 / 9984).
//! - `ath10k/pci.c` lines ~57..97 — PCI ID table + chip_id_rev list.

#![allow(dead_code)]

// ── PCI vendor / device IDs ─────────────────────────────────────────
//
// `ath10k/hw.h`:
//   #define QCA988X_2_0_DEVICE_ID        (0x003c)
//   #define QCA6164_2_1_DEVICE_ID        (0x0041)
//   #define QCA6174_2_1_DEVICE_ID        (0x003e)
//   #define QCA99X0_2_0_DEVICE_ID        (0x0040)
//   #define QCA9888_2_0_DEVICE_ID        (0x0056)
//   #define QCA9984_1_0_DEVICE_ID        (0x0046)
//   #define QCA9377_1_0_DEVICE_ID        (0x0042)
//
// Vendor IDs:
//   - 0x168c  ATHEROS / Qualcomm Atheros (canonical for ath10k)
//   - 0x0777  UBIQUITI (rebadged QCA988X)

/// Qualcomm Atheros — the canonical vendor for the QCA family.
pub const ATHEROS_VENDOR: u16 = 0x168c;
/// Ubiquiti Networks — rebadge of the QCA988X.
pub const UBNT_VENDOR: u16 = 0x0777;

/// QCA988X v2.0 — Wave 1 802.11ac 2x2 (cited in `hw.h`).
pub const QCA988X_DEVICE_ID: u16 = 0x003c;
/// Ubiquiti rebadge of QCA988X v2.0.
pub const QCA988X_UBNT_DEVICE_ID: u16 = 0x11ac;
/// QCA6174 v2.1 — Wave 2 802.11ac 2x2, common laptop SKU.
pub const QCA6174_DEVICE_ID: u16 = 0x003e;
/// QCA6164 v2.1 — single-stream sibling of QCA6174.
pub const QCA6164_DEVICE_ID: u16 = 0x0041;
/// QCA99X0 v2.0 — QCA9990 high-end MU-MIMO.
pub const QCA99X0_DEVICE_ID: u16 = 0x0040;
/// QCA9888 v2.0 — 2x2 client variant.
pub const QCA9888_DEVICE_ID: u16 = 0x0056;
/// QCA9984 v1.0 — 4x4 high-end Wave-2 chipset.
pub const QCA9984_DEVICE_ID: u16 = 0x0046;
/// QCA9377 v1.0 — Wi-Fi 5 1x1, found on cheap laptops.
pub const QCA9377_DEVICE_ID: u16 = 0x0042;
/// AR9462 — pre-ath10k legacy chip; not actually ath10k-controlled
/// in Linux (uses `ath9k` instead), but the task plan lists it as
/// part of the match scope. Driver returns NotForThisDriver.
pub const AR9462_DEVICE_ID: u16 = 0x0034;

/// Hardware revision tag. Same enumeration as Linux's
/// `enum ath10k_hw_rev` in `ath10k/hw.h`. Drives per-chip quirks
/// (which we mostly defer — Stage 0 only needs to identify the
/// chip + log the rev).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwRev {
    Qca988x,
    Qca6174,
    Qca99x0,
    Qca9888,
    Qca9984,
    Qca9377,
    Ar9462Legacy,
}

impl HwRev {
    /// Short, lowercase canonical name. Used in firmware-path
    /// construction (`/firmware/ath10k/<name>/...`) and the
    /// `BoundDriver.name` value.
    pub const fn short_name(self) -> &'static str {
        match self {
            HwRev::Qca988x => "QCA988X",
            HwRev::Qca6174 => "QCA6174",
            HwRev::Qca99x0 => "QCA99X0",
            HwRev::Qca9888 => "QCA9888",
            HwRev::Qca9984 => "QCA9984",
            HwRev::Qca9377 => "QCA9377",
            HwRev::Ar9462Legacy => "AR9462",
        }
    }

    /// Probe-table mapping: `(vendor, device) -> HwRev`. Returns
    /// `None` for unknown device IDs.
    pub const fn from_pci_id(vendor: u16, device: u16) -> Option<HwRev> {
        match (vendor, device) {
            (ATHEROS_VENDOR, QCA988X_DEVICE_ID) => Some(HwRev::Qca988x),
            (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID) => Some(HwRev::Qca988x),
            (ATHEROS_VENDOR, QCA6174_DEVICE_ID) => Some(HwRev::Qca6174),
            (ATHEROS_VENDOR, QCA6164_DEVICE_ID) => Some(HwRev::Qca6174),
            (ATHEROS_VENDOR, QCA99X0_DEVICE_ID) => Some(HwRev::Qca99x0),
            (ATHEROS_VENDOR, QCA9888_DEVICE_ID) => Some(HwRev::Qca9888),
            (ATHEROS_VENDOR, QCA9984_DEVICE_ID) => Some(HwRev::Qca9984),
            (ATHEROS_VENDOR, QCA9377_DEVICE_ID) => Some(HwRev::Qca9377),
            // AR9462 is ath9k territory — list it so the match
            // table claims it, then refuse politely in probe.
            (ATHEROS_VENDOR, AR9462_DEVICE_ID) => Some(HwRev::Ar9462Legacy),
            _ => None,
        }
    }
}

/// Every PCI ID this driver registers against. The legacy AR9462
/// entry is included only so the parallel ath9k port doesn't end
/// up with a vendor-only fallback — the probe path explicitly
/// rejects it (see `pci.rs`).
pub const ALL_PCI_MATCHES: &[(u16, u16)] = &[
    (ATHEROS_VENDOR, QCA988X_DEVICE_ID),
    (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID),
    (ATHEROS_VENDOR, QCA6174_DEVICE_ID),
    (ATHEROS_VENDOR, QCA6164_DEVICE_ID),
    (ATHEROS_VENDOR, QCA99X0_DEVICE_ID),
    (ATHEROS_VENDOR, QCA9888_DEVICE_ID),
    (ATHEROS_VENDOR, QCA9984_DEVICE_ID),
    (ATHEROS_VENDOR, QCA9377_DEVICE_ID),
    (ATHEROS_VENDOR, AR9462_DEVICE_ID),
];

// ── SoC core base-address window ───────────────────────────────────
//
// All offsets below are BAR0-relative, i.e. read/write to the BAR0
// MMIO at `phys + OFFSET`.
//
// `ath10k/hw.h` (~L865..L869):
//   #define RTC_STATE_ADDRESS              0x0000
//   #define PCIE_SOC_WAKE_ADDRESS          0x0004
//   #define PCIE_SOC_WAKE_RESET            0x00000000
//   #define SOC_GLOBAL_RESET_ADDRESS       0x0008
//
// `hw.h` (~L985..L990):
//   #define FW_INDICATOR_ADDRESS           0x40050  (varies — see below)
//   #define FW_IND_INITIALIZED             2
//   #define FW_IND_HOST_READY              0x80000000

/// Real-time-clock state. Read-only. `ath10k/hw.h::RTC_STATE_ADDRESS`.
pub const RTC_STATE_ADDRESS: u64 = 0x0000;
/// Mask for the "RTC on" state value within `RTC_STATE_ADDRESS`.
pub const RTC_STATE_V_MASK: u32 = 0x0000_0007;
/// "RTC is up" state value. Used to validate the SoC didn't drop
/// off the link mid-reset.
pub const RTC_STATE_V_ON_DEFAULT: u32 = 5;

/// PCIe→SoC wake request. Writing 1 wakes the SoC out of L2; writing
/// the reset value (0) lets it sleep. `hw.h::PCIE_SOC_WAKE_ADDRESS`.
pub const PCIE_SOC_WAKE_ADDRESS: u64 = 0x0004;
/// Wake-bit set value.
pub const PCIE_SOC_WAKE_V_MASK: u32 = 0x0000_0001;
/// Wake-bit reset (sleep) value.
pub const PCIE_SOC_WAKE_RESET_V: u32 = 0x0000_0000;

/// SoC global-reset latch. Writing 1 triggers a full SoC reset —
/// equivalent to a cold PCIe link toggle from the device's
/// perspective. `hw.h::SOC_GLOBAL_RESET_ADDRESS`.
pub const SOC_GLOBAL_RESET_ADDRESS: u64 = 0x0008;
/// Pulse value to write to `SOC_GLOBAL_RESET_ADDRESS`. The chip
/// self-clears the bit after the reset completes.
pub const SOC_GLOBAL_RESET_PULSE: u32 = 0x0000_0001;

// ── Chip-ID read ────────────────────────────────────────────────────
//
// `hw.h` (~L915..L917):
//   #define SOC_CHIP_ID_ADDRESS            (per-chip; see soc_chip_id_address)
//   #define SOC_CHIP_ID_REV_LSB            8
//   #define SOC_CHIP_ID_REV_MASK           0x00000f00
//
// QCA988x : SOC_CHIP_ID @ 0x000000ec
// QCA6174 : SOC_CHIP_ID @ 0x000000f0
// QCA99X0 : SOC_CHIP_ID @ 0x000000ec
// QCA9377 : SOC_CHIP_ID @ 0x000000ec
//
// Encode the per-chip offset in `soc_chip_id_address`.

/// Per-chip offset of the SOC_CHIP_ID register within the SoC-core
/// block (BAR0-relative).
pub const fn soc_chip_id_address(rev: HwRev) -> u64 {
    match rev {
        HwRev::Qca6174 => 0x0000_00f0,
        HwRev::Qca988x | HwRev::Qca99x0 | HwRev::Qca9888 | HwRev::Qca9984 | HwRev::Qca9377 => {
            0x0000_00ec
        }
        HwRev::Ar9462Legacy => 0x0000_00ec, // not really used; AR9462 is rejected
    }
}

/// Bit-shift of the rev field within `SOC_CHIP_ID`.
pub const SOC_CHIP_ID_REV_LSB: u32 = 8;
/// Bit-mask of the rev field within `SOC_CHIP_ID`.
pub const SOC_CHIP_ID_REV_MASK: u32 = 0x0000_0F00;

/// Extract the chip-id-rev field from a raw `SOC_CHIP_ID` read.
#[inline]
pub fn chip_id_rev(raw: u32) -> u32 {
    (raw & SOC_CHIP_ID_REV_MASK) >> SOC_CHIP_ID_REV_LSB
}

// ── SoC PCIe block ──────────────────────────────────────────────────
//
// `hw.h` (~L975..L980):
//   #define PCIE_INTR_ENABLE_ADDRESS       0x0008  (SOC_PCIE-relative)
//   #define PCIE_INTR_CAUSE_ADDRESS        0x000c
//   #define CPU_INTR_ADDRESS               0x0010
//   #define FW_RAM_CONFIG_ADDRESS          0x0018
//
// SOC_PCIE base = 0x8000.

/// Base address of the "SoC PCIe block" within BAR0.
pub const SOC_PCIE_BASE_ADDRESS: u64 = 0x0000_8000;

/// PCIe interrupt-enable mask. Driver writes 1-bits for the
/// interrupt sources it wants delivered.
pub const PCIE_INTR_ENABLE_OFFSET: u64 = 0x0008;
/// PCIe interrupt-cause read register. RW1C — write a 1 to clear
/// the corresponding cause bit.
pub const PCIE_INTR_CAUSE_OFFSET: u64 = 0x000c;
/// CPU interrupt latch.
pub const CPU_INTR_OFFSET: u64 = 0x0010;

/// Firmware status indicator. Written by the firmware once it's up.
/// `FW_IND_INITIALIZED = 2`, `FW_IND_HOST_READY = 0x80000000`.
/// Lives at SOC_PCIE_BASE + 0x40 for QCA988X / QCA9377 / QCA6174.
pub const FW_INDICATOR_OFFSET_988X: u64 = 0x0040;
/// QCA99X0 / QCA9888 / QCA9984 moved this register.
pub const FW_INDICATOR_OFFSET_99X0: u64 = 0x0050;

/// Firmware-status sentinel: "firmware is initialised".
pub const FW_IND_INITIALIZED: u32 = 2;
/// Firmware-status sentinel: "host is ready" (driver writes this).
pub const FW_IND_HOST_READY: u32 = 0x8000_0000;
/// Firmware-status sentinel: "event pending — read SCRATCH_3".
pub const FW_IND_EVENT_PENDING: u32 = 1;

/// Per-chip absolute BAR0 offset of the FW_INDICATOR register.
pub const fn fw_indicator_address(rev: HwRev) -> u64 {
    SOC_PCIE_BASE_ADDRESS
        + match rev {
            HwRev::Qca99x0 | HwRev::Qca9888 | HwRev::Qca9984 => FW_INDICATOR_OFFSET_99X0,
            _ => FW_INDICATOR_OFFSET_988X,
        }
}

// ── Copy Engine register bank ──────────────────────────────────────
//
// `hw.h` (~L885..L893): each CE has a private 0x1000-byte register
// window. The CE_WRAPPER lives at SOC_CORE + 0x00d000, and per-CE
// banks at SOC_CORE + 0x4000, 0x5000, 0x6000, ... 0xB000.
//
// `hw.c::qcax_ce_regs` (~L462..L481) gives the within-bank offsets
// shared by 988X / 6174 / 99X0 / 9377 / 9888 / 9984:
//
//   .sr_base_addr_lo       = 0x00
//   .sr_size_addr          = 0x04
//   .dr_base_addr_lo       = 0x08
//   .dr_size_addr          = 0x0c
//   .ctrl1_regs.addr       = 0x10
//   .ce_cmd_addr           = 0x18
//   .host_ie_addr          = 0x2c
//   .misc_ie_addr          = 0x34
//   .sr_wr_index_addr      = 0x3c
//   .dst_wr_index_addr     = 0x40
//   .current_srri_addr     = 0x44
//   .current_drri_addr     = 0x48

/// CE register-bank stride in BAR0.
pub const CE_BANK_STRIDE: u64 = 0x1000;

/// CE base addresses for CE0..CE7 (BAR0-relative). The chip exposes
/// eight CE banks; ath10k uses CE0..CE5 for control + WMI/HTT
/// traffic and the upper CEs for diagnostics / per-AC TX.
pub const CE_BASE_ADDRESSES: [u64; 8] = [
    0x0004_0000, // CE0
    0x0004_1000, // CE1
    0x0004_2000, // CE2
    0x0004_3000, // CE3
    0x0004_4000, // CE4
    0x0004_5000, // CE5
    0x0004_6000, // CE6
    0x0004_7000, // CE7
];

/// CE-wrapper base. Contains global CE enable/disable + per-bank
/// status mirrors.
pub const CE_WRAPPER_BASE_ADDRESS: u64 = 0x0004_d000;

/// CE register offsets (within a single CE bank — add to
/// `CE_BASE_ADDRESSES[i]` to get the BAR0-relative offset).
/// Sourced from `hw.c::qcax_ce_regs`.
pub mod ce_off {
    /// Source-ring base address, lo 32 bits. (`sr_base_addr_lo`)
    pub const SR_BASE_LO: u64 = 0x00;
    /// Source-ring number of entries × CE_DESC_SIZE.
    pub const SR_SIZE: u64 = 0x04;
    /// Destination-ring base address, lo 32 bits.
    pub const DR_BASE_LO: u64 = 0x08;
    /// Destination-ring number of entries × CE_DESC_SIZE.
    pub const DR_SIZE: u64 = 0x0c;
    /// CE control 1. Encodes ring shape (max descriptor data length,
    /// host_int_disable, etc.) Bit-fields per
    /// `hw.h::ath10k_hw_ce_ctrl1`.
    pub const CTRL1: u64 = 0x10;
    /// CE command register (halt / re-enable).
    pub const CMD: u64 = 0x18;
    /// Host interrupt-enable mask.
    pub const HOST_IE: u64 = 0x2c;
    /// Misc interrupt-enable mask (axi_err, dest_addr_err, etc.).
    pub const MISC_IE: u64 = 0x34;
    /// Source-ring write index (driver writes when posting TX).
    pub const SR_WR_INDEX: u64 = 0x3c;
    /// Destination-ring write index.
    pub const DR_WR_INDEX: u64 = 0x40;
    /// Cached source-ring read index (HW writes).
    pub const CURRENT_SRRI: u64 = 0x44;
    /// Cached destination-ring read index (HW writes).
    pub const CURRENT_DRRI: u64 = 0x48;
}

/// CE descriptor size (matches `struct ce_desc` — `__le32 addr; __le16 nbytes; __le16 flags`).
pub const CE_DESC_SIZE: usize = 8;

/// Wider 64-bit descriptor for WCN3990 / QCA99X0 (`struct ce_desc_64`).
pub const CE_DESC_SIZE_64: usize = 16;

/// Number of CE banks the QCA988X exposes.
pub const CE_COUNT_988X: usize = 8;
/// Number of CE banks the QCA99X0 / QCA9984 expose.
pub const CE_COUNT_99X0: usize = 12;

/// CE_CTRL1.HOST_INT_DISABLE — bit 17.
pub const CE_CTRL1_HOST_INT_DISABLE: u32 = 1 << 17;
/// CE_CTRL1.SRC_RING_BYTE_SWAP_EN — bit 16 (QCA988X-class).
pub const CE_CTRL1_SRC_RING_BYTE_SWAP_EN: u32 = 1 << 16;
/// CE_CTRL1.DMAX_LENGTH — bits 15:0 (`hw_ce_regs_addr_map` qcax_dmax).
pub const CE_CTRL1_DMAX_LENGTH_MASK: u32 = 0x0000_ffff;

/// CE_CMD.HALT — bit 0. Driver writes 1 to halt a CE pipe, polls
/// for halt-ack via `CE_CMD_HALT_STATUS` (offset 0x14).
pub const CE_CMD_HALT: u32 = 1 << 0;
/// Offset of the CE command-halt status register within the bank.
pub const CE_CMD_HALT_STATUS_OFFSET: u64 = 0x14;
/// CE_CMD_HALT_STATUS.HALTED — bit 0.
pub const CE_CMD_HALT_STATUS_HALTED: u32 = 1 << 0;

// ── Descriptor flag bits ───────────────────────────────────────────
//
// `ath10k/ce.h::CE_DESC_FLAGS_*`.

/// CE descriptor flag: gather (chained — more descriptors follow).
pub const CE_DESC_FLAGS_GATHER: u16 = 1 << 0;
/// CE descriptor flag: byte-swap the payload (BE-targeted parts).
pub const CE_DESC_FLAGS_BYTE_SWAP: u16 = 1 << 1;
/// CE descriptor flag (QCA99X0+): disable host-interrupt for this
/// descriptor. Used when the driver wants to batch completions.
pub const CE_DESC_FLAGS_HOST_INT_DIS: u16 = 1 << 2;
/// CE descriptor flag (QCA99X0+): disable target-interrupt.
pub const CE_DESC_FLAGS_TGT_INT_DIS: u16 = 1 << 3;
