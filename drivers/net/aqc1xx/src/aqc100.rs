//! Aquantia/Marvell AQC1xx older generations — AQC100/107/108/109/
//! 111/112 (`hw_atl` B1) and legacy D-series (`hw_atl` A0/B0) —
//! Stage-2 cut: probe + firmware boot + TX/RX rings + one MSI-X
//! vector + publication + carrier, fixture-validated against a
//! simulated device conversation.
//!
//! ## Reference
//!
//! Linux `drivers/net/ethernet/aquantia/atlantic/` (GPL-2.0;
//! NARF is GPL-2.0-or-later since 2026-05-20 so adaptation is
//! permitted), reference tree
//! `~/workspace/scratch/ethernet/linux-atlantic` @ `4dce97c6`
//! (sparse clone, `drivers/net/ethernet/aquantia/atlantic/` only):
//!
//! - `atlantic/aq_common.h` — PCI IDs (`PCI_VENDOR_ID_AQUANTIA`
//!   `0x1D6A`, `AQ_DEVICE_ID_*`), `AQ_NIC_RATE_*` bits.
//! - `atlantic/aq_pci_func.c` — `aq_pci_tbl`, `hw_atl_boards`
//!   (D-series rev 1 → `hw_atl_ops_a0`, rev 2 → `hw_atl_ops_b0`,
//!   B1 family → `hw_atl_ops_b1`, which is `#define`d to
//!   `hw_atl_ops_b0` in `hw_atl_b0.h`).
//! - `atlantic/hw_atl/hw_atl_utils.c` — `hw_atl_utils_soft_reset`
//!   (FLB/RBL firmware kickstart), `hw_atl_utils_initfw` (FW
//!   version → 1x/2x ops), `hw_atl_utils_mpi_set_speed` /
//!   `mpi_set_state` / `mpi_get_link_status` (FW 1x MPI register
//!   interface), `hw_atl_utils_get_mac_permanent` (efuse MAC +
//!   UCP fallback), `hw_atl_utils_fw_downld_dwords` (MIF
//!   download), `hw_atl_utils_init_ucp` (mailbox/RPC address
//!   discovery), `hw_atl_utils_ver_match`.
//! - `atlantic/hw_atl/hw_atl_utils_fw2x.c` — FW 2x/3x/4x ops
//!   (`aq_fw2x_set_link_speed` / `set_state` /
//!   `update_link_status` / `get_mac_permanent`, `FW2X_RATE_*`,
//!   `CAPS_HI_*`).
//! - `atlantic/hw_atl/hw_atl_utils.h` — `hal_atl_utils_fw_state_e`
//!   (`MPI_DEINIT`/`RESET`/`INIT`/`POWER`), `HAL_ATLANTIC_RATE_*`,
//!   `hw_atl_fw2x_rate`, `hw_atl_fw2x_caps_hi`,
//!   `hw_atl_utils_mbox_header`.
//! - `atlantic/hw_atl/hw_atl_b0.c` — `hw_atl_b0_hw_reset`,
//!   `hw_atl_b0_hw_init` (TX/RX path, MAC filter, `MPI_INIT`,
//!   PCI MRRS limit, TX DMA request limit, IRQ global control),
//!   `hw_atl_b0_hw_ring_tx_init` / `rx_init` / `tx_xmit` /
//!   `rx_receive`, `hw_atl_b0_caps_aqc100` … `aqc112`
//!   (S variants are `#define` aliases in `hw_atl_b0.h`).
//! - `atlantic/hw_atl/hw_atl_a0.c` — `hw_atl_a0_hw_reset`
//!   (GLB soft-reset bit dance, no firmware reboot),
//!   `hw_atl_a0_hw_init` (TX DMA debug writes, 4-field IRQ map),
//!   `hw_atl_a0_hw_ring_rx_receive` (descriptor-0 errata:
//!   `status & 0x5` completion test, RX-DMA-status bit-4 reset
//!   dance, slot-1 fallback), `hw_atl_a0_caps_aqc100` … `aqc109`.
//! - `atlantic/hw_atl/hw_atl_llh_internal.h` and
//!   `atlantic/hw_atl/hw_atl_llh.c` — register addresses and
//!   bitfields (every address below cites its `HW_ATL_*` name).
//! - `atlantic/hw_atl/hw_atl_b0_internal.h` /
//!   `atlantic/hw_atl/hw_atl_a0_internal.h` — `HW_ATL_B0_*` /
//!   `HW_ATL_A0_*` constants (`MAC_MAX` 33, `MTU_JUMBO`,
//!   MPI register addresses, TXD/RXD sizes).
//! - `atlantic/aq_cfg.h` — defaults (TXDS 4096, RXDS 2048,
//!   MTU 1514, TX frame max 16 KiB, RX frame max 2 KiB).
//! - `atlantic/aq_nic.c` — `aq_nic_hw_prepare` (soft reset, then
//!   `initfw`) and `aq_nic_init` (`hw_reset`, `hw_init`, PHY-ID
//!   scan, ring alloc, carrier off).
//!
//! The TX/RX descriptor rings, descriptor layouts and RX
//! writeback decode are the `hw_atl_b0` model shared with the
//! AQC113 driver, so this module reuses `aqc113`'s `TxDesc` /
//! `RxDesc` / `RxdWb` / `build_tx_desc` / `build_rx_desc` /
//! `decode_rx_wb` / `program_rings` / `set_rx_tail` / `start_hw`
//! / `mac_filter_words` / `LinkStatus` / `link_sample`
//! unchanged. (`mac_addr_set` is NOT reused: the AQC113 version
//! programs the `HW_ATL2`-only unicast tag field, which does not
//! exist in the `hw_atl` filter control register.) Only the
//! firmware conversation and
//! the init sequence differ: the older backends drive the MAC/PHY
//! registers directly through the MPI control register (`0x368`)
//! instead of the AQC113 MIF shared-buffer mailbox
//! (`0x12000`/`0x13000`).
//!
//! ## Deliberate asymmetries (Stage 2)
//!
//! - Single queue pair (queue 0) + one MSI-X vector; Linux defaults
//!   to 8 vectors / 4 TX + 4 RX rings. RSS stays off (no RSS hash
//!   key / redirection programming; `RX_FLR_RSS_CONTROL1` is
//!   written 0, the disabled value).
//! - RX VLAN stripping stays OFF; TX VLAN insertion is not
//!   programmed. TC mode, LSO flag words, DCA and the TPS rate
//!   limiter are deferred — they do not gate single-queue TX/RX
//!   on TC0 under reset defaults (same cut as the AQC113 lane).
//! - No TX/RX checksum offload or TSO/LSO yet (the TX context
//!   descriptor exists in the spec; the datapath uses plain
//!   frames). `hw_atl_b0_hw_offload_set` /
//!   `hw_atl_a0_hw_offload_set` are deferred with it.
//! - No FW statistics (`update_stats`, which needs the FW1x RPC
//!   channel) and no FW1x RPC handshake (`fw_rpc_init`): the
//!   mailbox/RPC addresses are discovered by `init_ucp`, but the
//!   RPC tid handshake itself is deferred — link-up does not
//!   depend on it (MPI state only), and stats/power/LED are all
//!   deferred with it.
//! - No MDIO PHY-ID scan (`aq_phy_init`): the firmware owns the
//!   PHY and link status comes from the MPI state register; the
//!   scan only identifies the PHY for PTP-disable quirks, which
//!   are deferred with PTP itself. AQC111/112 carry the
//!   `AQ_NIC_QUIRK_BAD_PTP` quirk in Linux; the PTP block is left
//!   exactly as the firmware left it.
//! - The driver maps BAR0; Linux scans BARs 0..3 for the first MEM
//!   BAR. BAR0 is the MMIO BAR on AQC1xx hardware.
//! - TX completion is the descriptor-DD writeback poll (Atlantic
//!   has no OWN bit); the polled `transmit` waits for DD with a
//!   250 ms deadline, mirroring the RTL8125 driver's poll budget.
//! - RX buffers are 2048 bytes (Linux's `AQ_CFG_RX_FRAME_MAX`); a
//!   frame larger than one buffer spans descriptors and is dropped
//!   (multi-descriptor RX chaining is a remainder).
//! - The firmware lives in the device's own flash: no blob is
//!   loaded by the driver. `soft_reset` kickstarts the on-chip
//!   firmware through the FLB/RBL boot sequence, exactly as
//!   Linux does.
//! - Backend selection (A0 vs B0 vs B1) comes from the MIF ID
//!   register (`0x1C`, low nibble: 1 → A0, 2 → B0, `0xA` → B1),
//!   read after `soft_reset` the way
//!   `hw_atl_utils_hw_chip_features_init` does it — not from the
//!   PCI revision, which NARF's `BusDevice` does not carry.
//!   Linux's board table agrees (D-series rev 1 → A0 ops, rev 2
//!   → B0 ops, B1 family → B0 ops).
//! - `hw_reset` runs `soft_reset` a second time for B0/B1, exactly
//!   as Linux does (`aq_nic_hw_prepare` soft-resets, then
//!   `aq_nic_init` calls `hw_reset`, which soft-resets again
//!   before `MPI_RESET`).

#![allow(dead_code)]

mod tests;

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, Ordering};

use alloc::sync::Arc;
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

use super::aqc113::{
    build_rx_desc, build_tx_desc, decode_rx_wb, link_sample, mac_filter_words, mac_is_invalid,
    program_rings, set_rx_tail, start_hw, LinkStatus, NicError, RegIo, RxCsumResult, RxDecode,
    RxdWb, AQC_VENDOR, RING_BYTES, RING_LEN, RX_BUF_LEN, TX_BUF_LEN,
};
use super::aqc113::{
    RXD_WB_CSUM_EN_SHIFT, RXD_WB_DD, RXD_WB_DMA_ERR, RXD_WB_EOP, RXD_WB_PKTTYPE_MSK,
    RXD_WB_PKTTYPE_SHIFT, RXD_WB_RXSTAT_MSK, RXD_WB_RXSTAT_SHIFT,
};

// ── PCI ids ─────────────────────────────────────────────────────────

/// D-series engineering-sample id (`AQ_DEVICE_ID_0001`).
pub const AQC_DEV_0001: u16 = 0x0001;
/// D100 (`AQ_DEVICE_ID_D100`).
pub const AQC_DEV_D100: u16 = 0xD100;
/// D107 (`AQ_DEVICE_ID_D107`).
pub const AQC_DEV_D107: u16 = 0xD107;
/// D108 (`AQ_DEVICE_ID_D108`).
pub const AQC_DEV_D108: u16 = 0xD108;
/// D109 (`AQ_DEVICE_ID_D109`).
pub const AQC_DEV_D109: u16 = 0xD109;
/// AQC100 (`AQ_DEVICE_ID_AQC100`).
pub const AQC_DEV_100: u16 = 0x00B1;
/// AQC107 (`AQ_DEVICE_ID_AQC107`).
pub const AQC_DEV_107: u16 = 0x07B1;
/// AQC108 (`AQ_DEVICE_ID_AQC108`).
pub const AQC_DEV_108: u16 = 0x08B1;
/// AQC109 (`AQ_DEVICE_ID_AQC109`).
pub const AQC_DEV_109: u16 = 0x09B1;
/// AQC111 (`AQ_DEVICE_ID_AQC111`).
pub const AQC_DEV_111: u16 = 0x11B1;
/// AQC112 (`AQ_DEVICE_ID_AQC112`).
pub const AQC_DEV_112: u16 = 0x12B1;
/// AQC100S (`AQ_DEVICE_ID_AQC100S`).
pub const AQC_DEV_100S: u16 = 0x80B1;
/// AQC107S (`AQ_DEVICE_ID_AQC107S`).
pub const AQC_DEV_107S: u16 = 0x87B1;
/// AQC108S (`AQ_DEVICE_ID_AQC108S`).
pub const AQC_DEV_108S: u16 = 0x88B1;
/// AQC109S (`AQ_DEVICE_ID_AQC109S`).
pub const AQC_DEV_109S: u16 = 0x89B1;
/// AQC111S (`AQ_DEVICE_ID_AQC111S`).
pub const AQC_DEV_111S: u16 = 0x91B1;
/// AQC112S (`AQ_DEVICE_ID_AQC112S`).
pub const AQC_DEV_112S: u16 = 0x92B1;

const ALL_DEV_IDS: &[u16] = &[
    AQC_DEV_0001,
    AQC_DEV_D100,
    AQC_DEV_D107,
    AQC_DEV_D108,
    AQC_DEV_D109,
    AQC_DEV_100,
    AQC_DEV_107,
    AQC_DEV_108,
    AQC_DEV_109,
    AQC_DEV_111,
    AQC_DEV_112,
    AQC_DEV_100S,
    AQC_DEV_107S,
    AQC_DEV_108S,
    AQC_DEV_109S,
    AQC_DEV_111S,
    AQC_DEV_112S,
];

/// Human-readable name for a known device id. D-series parts take
/// the name of the caps family Linux binds them to (`0x0001` →
/// `aqc107` caps in both `hw_atl_a0_caps_*` and
/// `hw_atl_b0_caps_*`).
pub const fn name_for(did: u16) -> &'static str {
    match did {
        AQC_DEV_0001 | AQC_DEV_D107 | AQC_DEV_107 | AQC_DEV_107S => "aqc107",
        AQC_DEV_D100 | AQC_DEV_100 | AQC_DEV_100S => "aqc100",
        AQC_DEV_D108 | AQC_DEV_108 | AQC_DEV_108S => "aqc108",
        AQC_DEV_D109 | AQC_DEV_109 | AQC_DEV_109S => "aqc109",
        AQC_DEV_111 | AQC_DEV_111S => "aqc111",
        AQC_DEV_112 | AQC_DEV_112S => "aqc112",
        _ => "aqc100",
    }
}

// `AQ_NIC_RATE_*` link-speed mask bits (`aq_common.h`), shared
// with the AQC113 driver (`RATE_10G` … `RATE_10M` there).
pub(crate) const RATE_10G: u32 = 1 << 0;
pub(crate) const RATE_5G: u32 = 1 << 1;
pub(crate) const RATE_2G5: u32 = 1 << 2;
pub(crate) const RATE_1G: u32 = 1 << 3;
pub(crate) const RATE_100M: u32 = 1 << 4;

/// Advertised link-speed mask for a device id under `backend`,
/// per `hw_atl_b0_caps_aqc100` … `aqc112` (`hw_atl_b0.c`) and
/// `hw_atl_a0_caps_aqc100` … `aqc109` (`hw_atl_a0.c`). The
/// A0 caps are the only ones that differ from the B0 caps: A0
/// AQC100 tops out at 5G (no 10G). S variants share their
/// non-S caps (`hw_atl_b0.h` `#define` aliases).
pub const fn speed_mask_for(did: u16, backend: Backend) -> u32 {
    match backend {
        Backend::A0 => match did {
            AQC_DEV_D100 | AQC_DEV_100 | AQC_DEV_100S => RATE_5G | RATE_2G5 | RATE_1G | RATE_100M,
            AQC_DEV_0001 | AQC_DEV_D107 | AQC_DEV_107 | AQC_DEV_107S => {
                RATE_10G | RATE_5G | RATE_2G5 | RATE_1G | RATE_100M
            }
            AQC_DEV_D108 | AQC_DEV_108 | AQC_DEV_108S => RATE_5G | RATE_2G5 | RATE_1G | RATE_100M,
            _ => RATE_2G5 | RATE_1G | RATE_100M,
        },
        Backend::B0 | Backend::B1 => match did {
            AQC_DEV_D100 | AQC_DEV_100 | AQC_DEV_100S => {
                RATE_10G | RATE_5G | RATE_2G5 | RATE_1G | RATE_100M
            }
            AQC_DEV_0001 | AQC_DEV_D107 | AQC_DEV_107 | AQC_DEV_107S => {
                RATE_10G | RATE_5G | RATE_2G5 | RATE_1G | RATE_100M
            }
            AQC_DEV_D108 | AQC_DEV_108 | AQC_DEV_108S => RATE_5G | RATE_2G5 | RATE_1G | RATE_100M,
            AQC_DEV_111 | AQC_DEV_111S => RATE_5G | RATE_2G5 | RATE_1G | RATE_100M,
            _ => RATE_2G5 | RATE_1G | RATE_100M,
        },
    }
}

// ── Backend / firmware generation ───────────────────────────────────

/// Atlantic hardware backend, selected from the MIF ID register
/// (`hw_atl_utils_hw_chip_features_init`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// D-series revision 1 (`hw_atl_ops_a0`).
    A0,
    /// D-series revision 2 (`hw_atl_ops_b0`).
    B0,
    /// AQC100/107/108/109/111/112 family (`hw_atl_ops_b1`, an
    /// alias for `hw_atl_ops_b0`).
    B1,
}

/// Chip features decoded from the MIF ID register
/// (`HW_ATL_GLB_MIF_ID_ADR` `0x1C`): the low nibble of the
/// revision selects the backend, and B0/B1 carry the TPO2/RPF2
/// features (`hw_atl_utils_hw_chip_features_init`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChipFeatures {
    pub backend: Backend,
    /// `ATL_HW_CHIP_TPO2` — the `0x7040` TX-path write applies.
    pub tpo2: bool,
    /// `ATL_HW_CHIP_RPF2` — the `0x5040` RX-path write applies.
    pub rpf2: bool,
}

/// Decode chip features from a MIF ID register value. `None`
/// when the low nibble names no known revision.
pub const fn chip_features(mif_id: u32) -> Option<ChipFeatures> {
    match mif_id & 0xF {
        1 => Some(ChipFeatures {
            backend: Backend::A0,
            tpo2: false,
            rpf2: false,
        }),
        2 => Some(ChipFeatures {
            backend: Backend::B0,
            tpo2: true,
            rpf2: true,
        }),
        0xA => Some(ChipFeatures {
            backend: Backend::B1,
            tpo2: true,
            rpf2: true,
        }),
        _ => None,
    }
}

/// On-chip firmware generation, selected from the firmware
/// version word (`hw_atl_utils_initfw`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwGen {
    /// FW 1.x — MPI register interface (`aq_fw_1x_ops`).
    Fw1x,
    /// FW 2.x/3.x/4.x — FW2x MPI interface (`aq_fw_2x_ops`).
    Fw2x,
}

/// Map a raw firmware version word (register `0x18`) to its
/// generation, mirroring `hw_atl_utils_ver_match`: the major
/// byte must match and the minor must be at least the expected
/// floor (`HW_ATL_FW_VER_1X` `0x01050006`, `2X`/`3X`/`4X`
/// `0x02000000`/`0x03000000`/`0x04000000`). `None` when no
/// generation matches (Linux returns `-EOPNOTSUPP`).
pub const fn fw_gen_for(version: u32) -> Option<FwGen> {
    let major = version >> 24;
    if major == 1 {
        if version >= 0x0105_0006 {
            return Some(FwGen::Fw1x);
        }
        return None;
    }
    if major == 2 || major == 3 || major == 4 {
        return Some(FwGen::Fw2x);
    }
    None
}

// ── Register offsets (BAR0, MMIO) ───────────────────────────────────
// Addresses from `hw_atl_llh_internal.h` / `hw_atl_utils.c` /
// `hw_atl_utils_fw2x.c` / `hw_atl_b0_internal.h` /
// `hw_atl_a0_internal.h`. TX/RX DMA, RPF filter and IRQ-block
// registers are shared with the AQC113 driver — see `aqc113.rs`
// (`REG_MIF_BOOT` there is the AQC113-only MIF boot register and
// is NOT reused: the older backends have no MIF boot register).

/// MIF ID / chip revision (`HW_ATL_GLB_MIF_ID_ADR`).
pub(crate) const REG_MIF_ID: u64 = 0x001C;
/// Firmware version word (`HW_ATL_MPI_FW_VERSION`, `0x18`).
pub(crate) const REG_MPI_FW_VERSION: u64 = 0x0018;
/// Global soft reset + register-reset-disable
/// (`HW_ATL_GLB_SOFT_RES_ADR` / `HW_ATL_GLB_REG_RES_DIS_ADR`,
/// both `0x0`: soft-reset bit 15, reg-reset-disable bit 14).
pub(crate) const REG_GLB_SOFT_RES: u64 = 0x0000;
/// MIF command (`HW_ATL_MIF_CMD`).
pub(crate) const REG_MIF_CMD: u64 = 0x0200;
/// MIF address (`HW_ATL_MIF_ADDR`).
pub(crate) const REG_MIF_ADDR: u64 = 0x0208;
/// MIF value (`HW_ATL_MIF_VAL`).
pub(crate) const REG_MIF_VAL: u64 = 0x020C;
/// Alive-check / flush read address (`hw_alive_check_addr`,
/// also `HW_ATL_B0_FLUSH`).
pub(crate) const REG_ALIVE_CHECK: u64 = 0x0010;
/// MIF reset timeout, ms (`HW_ATL_MIF_RESET_TIMEOUT_ADR`).
pub(crate) const REG_MIF_RESET_TIMEOUT: u64 = 0x0348;
/// MPI RPC address (`HW_ATL_MPI_RPC_ADDR`, FW1x;
/// `HW_ATL_FW2X_MPI_RPC_ADDR`).
pub(crate) const REG_MPI_RPC_ADDR: u64 = 0x0334;
/// MPI control — FW1x speed/state, FW2x rate mask
/// (`HW_ATL_MPI_CONTROL_ADR` / `HW_ATL_FW2X_MPI_CONTROL_ADDR`).
pub(crate) const REG_MPI_CONTROL: u64 = 0x0368;
/// MPI state — FW1x state/speed, FW2x control-2
/// (`HW_ATL_MPI_STATE_ADR` / `HW_ATL_FW2X_MPI_CONTROL2_ADDR`).
pub(crate) const REG_MPI_STATE: u64 = 0x036C;
/// UCP scratch (`HW_ATL_UCP_0X370_REG`, FW1x) / FW2x MPI state
/// (`HW_ATL_FW2X_MPI_STATE_ADDR`).
pub(crate) const REG_UCP_0X370: u64 = 0x0370;
/// FW1x efuse address register (`0x374`, read by
/// `hw_atl_utils_get_mac_permanent`).
pub(crate) const REG_EFUSE_ADDR_1X: u64 = 0x0374;
/// FW2x efuse address register
/// (`HW_ATL_FW2X_MPI_EFUSE_ADDR`).
pub(crate) const REG_EFUSE_ADDR_2X: u64 = 0x0364;
/// FW2x mailbox address (`HW_ATL_FW2X_MPI_MBOX_ADDR`, == the
/// scratchpad-25 register).
pub(crate) const REG_FW2X_MBOX_ADDR: u64 = 0x0360;
/// MPI daisy-chain status (`HW_ATL_MPI_DAISY_CHAIN_STATUS`).
pub(crate) const REG_MPI_DAISY_CHAIN_STATUS: u64 = 0x0704;
/// MPI boot exit code / RBL status
/// (`HW_ATL_MPI_BOOT_EXIT_CODE`, `0x388`).
pub(crate) const REG_MPI_BOOT_EXIT_CODE: u64 = 0x0388;
/// MAC/PHY control (`HW_ATL_MAC_PHY_CONTROL`).
pub(crate) const REG_MAC_PHY_CONTROL: u64 = 0x4000;
/// MCP up-force-interrupt (`HW_ATL_MCP_UP_FORCE_INTERRUPT_ADR`,
/// `0x404`; the FLB/RBL sequences write whole-register
/// kickstart values here, not bitfields).
pub(crate) const REG_MCP_UP_FORCE_INT: u64 = 0x0404;
/// SPI control (`0x53C`, used by the FLB/RBL sequences).
pub(crate) const REG_SPI_CTL: u64 = 0x053C;
/// Kickstart scratch (`0x32a8`, used by the FLB/RBL sequences).
pub(crate) const REG_KICKSTART_SCRATCH: u64 = 0x32A8;
/// Kickstart control (`0x520`, used by the FLB sequence).
pub(crate) const REG_KICKSTART_CTL: u64 = 0x0520;
/// Global CPU semaphore base (`HW_ATL_GLB_CPU_SEM_ADR(sem)`).
pub(crate) const REG_GLB_CPU_SEM_BASE: u64 = 0x03A0;
/// Global CPU scratchpad base
/// (`HW_ATL_GLB_CPU_SCRATCH_SCP_ADR(n)` = `0x300 + n*4`;
/// scratchpad 25 is the FW1x mailbox address, scratchpad 12
/// the RPC completion flag).
pub(crate) const REG_GLB_CPU_SCRATCH_BASE: u64 = 0x0300;
/// PCI register control 6 — MRRS limit
/// (`HW_ATL_PCI_REG_CONTROL6_ADR`).
pub(crate) const REG_PCI_REG_CONTROL6: u64 = 0x1014;
/// TX DMA total request limit
/// (`HW_ATL_TX_DMA_TOTAL_REQ_LIMIT_ADR`).
pub(crate) const REG_TX_DMA_TOTAL_REQ_LIMIT: u64 = 0x7B20;
/// TX DMA debug control (`HW_ATL_TX_DMA_DEBUG_CTL_ADR`, A0
/// init only).
pub(crate) const REG_TX_DMA_DEBUG_CTL: u64 = 0x8920;
/// PCI register-reset-disable (`HW_ATL_PCI_REG_RES_DSBL_ADR`).
pub(crate) const REG_PCI_REG_RES_DSBL: u64 = 0x1000;
/// RX register-reset-disable (`HW_ATL_RX_REG_RES_DSBL_ADR`).
pub(crate) const REG_RX_REG_RES_DSBL: u64 = 0x5000;
/// TX register-reset-disable (`HW_ATL_TX_REG_RES_DSBL_ADR`).
pub(crate) const REG_TX_REG_RES_DSBL: u64 = 0x7000;
/// ITR register-reset-disable + ITR reset, same register as
/// the IRQ global control (`HW_ATL_ITR_REG_RES_DSBL_ADR` /
/// `HW_ATL_ITR_RES_ADR`, `0x2300`).
pub(crate) const REG_ITR_RES: u64 = 0x2300;
/// TPO2 TX-path control (`0x7040`, written raw by the B0/A0
/// TX-path init).
pub(crate) const REG_TPO2_CTL: u64 = 0x7040;
/// RPF2 RX-path control (`0x5040`, written raw by the B0
/// RX-path init).
pub(crate) const REG_RPF2_CTL: u64 = 0x5040;
/// RX flow-control mode + RX buffer enable share one register
/// (`HW_ATL_RPB_RX_FC_MODE_ADR` == `HW_ATL_RPB_RX_BUF_EN_ADR`
/// `0x5700`: flow-control mode bits [5:4], buffer enable
/// bit 0).
pub(crate) const REG_RPB_RX_BUF: u64 = 0x5700;
/// RSS control 1 (`HW_ATL_RX_FLR_RSS_CONTROL1_ADR`).
pub(crate) const REG_RX_FLR_RSS_CONTROL1: u64 = 0x54C0;
/// RX DMA descriptor status (`HW_ATL_RX_DMA_DESC_STAT_ADR(q)`,
/// A0 errata check).
pub(crate) const fn reg_rx_dma_stat(q: u64) -> u64 {
    0x5B14 + q * 0x20
}
/// RX DMA descriptor head pointer (`HW_ATL_RDM_DESCDHD_ADR(q)`,
/// A0 errata check; the pointer is bits [12:0]).
pub(crate) const fn reg_rx_dma_head_ptr(q: u64) -> u64 {
    0x5B0C + q * 0x20
}
/// RX DMA descriptor control — EN (bit 31) + descriptor reset
/// (bit 25) share the control register
/// (`HW_ATL_RDM_DESCDEN_ADR(q)` / `HW_ATL_RDM_DESCDRESET_ADR(q)`).
pub(crate) const fn reg_rx_dma_ctl(q: u64) -> u64 {
    0x5B08 + q * 0x20
}
/// IRQ global control (`HW_ATL_INTR_GLB_CTL_ADR`, shared with
/// the AQC113 driver).
pub(crate) const REG_IRQ_GLB_CTL: u64 = 0x2300;
/// IRQ auto-mask LSW (`HW_ATL_ITR_IAMRLSW_ADR`, shared).
pub(crate) const REG_ITR_IAMRLSW: u64 = 0x2090;
/// General IRQ map base (`HW_ATL_GEN_INTR_MAP_ADR(idx)`, shared).
pub(crate) const REG_GEN_IRQ_MAP_BASE: u64 = 0x2180;

/// Global CPU semaphore register for semaphore `sem`
/// (`HW_ATL_GLB_CPU_SEM_ADR(sem)` = `0x3A0 + sem*4`).
pub(crate) const fn reg_glb_cpu_sem(sem: u64) -> u64 {
    REG_GLB_CPU_SEM_BASE + sem * 4
}
/// Global CPU scratchpad register `n`
/// (`HW_ATL_GLB_CPU_SCRATCH_SCP_ADR(n)` = `0x300 + n*4`).
/// Naming trap: Linux's `hw_atl_scrpad25_get` /
/// `hw_atl_scrpad12_get` are 1-based names — they read indices
/// `0x18` (24, `0x360`, the mailbox address) and `0xB` (11,
/// `0x32C`, the RPC completion flag), not indices 25/12.
pub(crate) const fn reg_glb_cpu_scratch(n: u64) -> u64 {
    REG_GLB_CPU_SCRATCH_BASE + n * 4
}
/// Scratchpad 25 — the FW1x mailbox address
/// (`hw_atl_scrpad25_get` reads scratchpad `0x18`).
pub(crate) const REG_SCRPAD_MBOX_ADDR: u64 = 0x0360;

// ── Register bitfields ──────────────────────────────────────────────

// Global soft-reset register bits (`HW_ATL_GLB_SOFT_RES_ADR`).
/// Soft-reset bit (`HW_ATL_GLB_SOFT_RES_MSK`, bit 15).
pub(crate) const GLB_SOFT_RES: u32 = 1 << 15;
/// Register-reset-disable bit (`HW_ATL_GLB_REG_RES_DIS_MSK`,
/// bit 14, same register).
pub(crate) const GLB_REG_RES_DIS: u32 = 1 << 14;
/// Register-reset-disable bit, PCI/RX/TX/ITR blocks
/// (`HW_ATL_*_REG_RES_DSBL_MSK`, bit 29).
pub(crate) const REG_RES_DSBL: u32 = 1 << 29;
/// ITR reset bit (`HW_ATL_ITR_RES_MSK`, bit 31 of `0x2300`).
pub(crate) const ITR_RES: u32 = 1 << 31;
/// SPI reset bit (`0x10` in `0x53C`, per the FLB/RBL code).
pub(crate) const SPI_RESET: u32 = 1 << 4;
/// MAC/PHY MPI reset bit (`HW_ATL_MAC_PHY_MPI_RESET_BIT`, 29).
pub(crate) const MAC_PHY_MPI_RESET_BIT: u32 = 1 << 29;
/// RBL "no firmware" status (`0xF1A7` in `0x388`).
pub(crate) const RBL_STATUS_NO_FW: u32 = 0xF1A7;
/// RBL status marker the driver writes before the RBL boot
/// poll (`0xDEAD` in `0x388`).
pub(crate) const RBL_STATUS_MARKER: u32 = 0xDEAD;
/// FLB started value: the entry loop breaks unless the
/// daisy-chain status reads exactly `0x06000000` with a zero
/// boot exit code.
pub(crate) const FLB_NOT_STARTED: u32 = 0x0600_0000;
/// FLB daisy-chain ready bit (`0x10` in `0x704`).
pub(crate) const FLB_DAISY_READY: u32 = 1 << 4;

/// Firmware-version floors (`HW_ATL_FW_VER_*`).
pub(crate) const FW_VER_1X: u32 = 0x0105_0006;
/// MIF command: start a download (`0x8000` in `HW_ATL_MIF_CMD`).
pub(crate) const MIF_CMD_START: u32 = 0x0000_8000;
/// MIF command busy bit for A0/B0 (`0x100` in `HW_ATL_MIF_CMD`).
pub(crate) const MIF_CMD_BUSY: u32 = 1 << 8;
/// CPU semaphore indices (`HW_ATL_FW_SM_RAM` 2, `RESET1` 3,
/// `RESET2` 4).
pub(crate) const FW_SEM_RAM: u64 = 2;
pub(crate) const FW_SEM_RESET1: u64 = 3;
pub(crate) const FW_SEM_RESET2: u64 = 4;

/// MPI state field (`HW_ATL_MPI_STATE_MSK` `0xFF`).
pub(crate) const MPI_STATE_MSK: u32 = 0x00FF;
/// MPI speed field (`HW_ATL_MPI_SPEED_MSK` `0x00FF0000`).
pub(crate) const MPI_SPEED_MSK: u32 = 0x00FF_0000;
/// MPI speed shift (`HW_ATL_MPI_SPEED_SHIFT` 16).
pub(crate) const MPI_SPEED_SHIFT: u32 = 16;
/// MPI dirty-wake bit (`HW_ATL_MPI_DIRTY_WAKE_MSK`).
pub(crate) const MPI_DIRTY_WAKE: u32 = 1 << 25;
/// MPI firmware states (`hal_atl_utils_fw_state_e`).
pub(crate) const MPI_DEINIT: u32 = 0;
pub(crate) const MPI_RESET: u32 = 1;
pub(crate) const MPI_INIT: u32 = 2;
pub(crate) const MPI_POWER: u32 = 4;

/// FW1x link-rate codes (`HAL_ATLANTIC_RATE_*`).
pub(crate) const HAL_RATE_10G: u32 = 1 << 0;
pub(crate) const HAL_RATE_5G: u32 = 1 << 1;
pub(crate) const HAL_RATE_5GSR: u32 = 1 << 2;
pub(crate) const HAL_RATE_2G5: u32 = 1 << 3;
pub(crate) const HAL_RATE_1G: u32 = 1 << 4;
pub(crate) const HAL_RATE_100M: u32 = 1 << 5;

/// FW2x link-rate bits (`hw_atl_fw2x_rate`, in the MPI control
/// `0x368` write and the MPI state `0x370` read).
pub(crate) const FW2X_RATE_100M: u32 = 0x20;
pub(crate) const FW2X_RATE_1G: u32 = 0x100;
pub(crate) const FW2X_RATE_2G5: u32 = 0x200;
pub(crate) const FW2X_RATE_5G: u32 = 0x400;
pub(crate) const FW2X_RATE_10G: u32 = 0x800;
/// FW2x control-2 bits (`hw_atl_fw2x_caps_hi` / `hw_atl_fw2x_ctrl`,
/// register `0x36C`): link-drop 22, statistics 30, pause 3,
/// asymmetric-pause 4.
pub(crate) const FW2X_LINK_DROP_BIT: u32 = 22;
pub(crate) const FW2X_CTRL_PAUSE: u32 = 1 << 3;
pub(crate) const FW2X_CTRL_ASYMMETRIC_PAUSE: u32 = 1 << 4;

/// RPB RX flow-control mode field (`HW_ATL_RPB_RX_FC_MODE_MSK`
/// `0x30`, shift 4, in register `0x5700`).
pub(crate) const RPB_RX_FC_MODE_MSK: u32 = 0x30;
pub(crate) const RPB_RX_FC_MODE_SHIFT: u32 = 4;
/// RX buffer enable bit (`HW_ATL_RPB_RX_BUF_EN_MSK`, bit 0 of
/// `0x5700`).
pub(crate) const RPB_RX_BUF_EN: u32 = 1 << 0;
/// RX DMA descriptor status bit 4 — the A0 errata trigger
/// (`(1U << 4) & hw_atl_reg_rx_dma_desc_status_get`).
pub(crate) const RX_DMA_STAT_BIT4: u32 = 1 << 4;
/// RX DMA descriptor head-pointer mask
/// (`HW_ATL_RDM_DESCDHD_MSK` `0x1FFF`).
pub(crate) const RX_DMA_HEAD_PTR_MSK: u32 = 0x1FFF;
/// RX descriptor reset bit (`HW_ATL_RDM_DESCDRESET_MSK`,
/// bit 25 of the RX control register).
pub(crate) const RXD_RESET: u32 = 1 << 25;
/// RX descriptor enable bit (`HW_ATL_RDM_DESCDEN_MSK`,
/// bit 31 of the RX control register).
pub(crate) const RXD_EN: u32 = 1 << 31;
/// TX DMA debug-control values (`hw_atl_a0_hw_init`).
pub(crate) const TX_DMA_DEBUG_CTL_SET: u32 = 0x8000_00B8;
pub(crate) const TX_DMA_DEBUG_CTL_CLEAR: u32 = 0x0000_00B8;
/// PCI control-6 MRRS value (`(val & ~0x707) | 0x404` in
/// `hw_atl_b0_hw_init`).
pub(crate) const PCI_CTL6_MRRSMASK: u32 = 0x707;
pub(crate) const PCI_CTL6_MRRSVAL: u32 = 0x404;
/// TX DMA total request limit (`24` in `hw_atl_b0_hw_init`).
pub(crate) const TX_DMA_TOTAL_REQ_LIMIT: u32 = 24;
/// TPO2 TX-path control value (`0x10000` in `0x7040`).
pub(crate) const TPO2_CTL_VALUE: u32 = 0x0001_0000;
/// RPF2 RX-path control value (`0xF0000` in `0x5040`).
pub(crate) const RPF2_CTL_VALUE: u32 = 0x000F_0000;
/// IRQ global-control value for MSI-X, single vector
/// (`aq_hw_atl_igcr_table_[AQ_HW_IRQ_MSIX][0]`, shared with
/// the AQC113 driver).
pub(crate) const IRQ_GLB_CTL_MSIX_1VEC: u32 = 0x2000_0022;
/// IRQ auto-mask value (`irq_mask = ~0U`).
pub(crate) const IRQ_AUTO_MASK: u32 = 0xFFFF_FFFF;
/// General IRQ map 0, B0/B1 — error interrupt 8 in the two
/// low fields (`hw_atl_b0_hw_init`).
pub(crate) const GEN_IRQ_MAP0_B0: u32 = (8 << 24) | (1 << 31) | (8 << 16) | (1 << 23);
/// General IRQ map 0, A0 — error interrupt 8 in all four
/// fields (`hw_atl_a0_hw_init`).
pub(crate) const GEN_IRQ_MAP0_A0: u32 = 0x8888_8888;
/// Maximum L2 unicast filters (`HW_ATL_B0_MAC_MAX` /
/// `HW_ATL_A0_MAC_MAX`, 33; filter 0 is the MAC filter).
pub(crate) const MAC_FILTER_MAX: u32 = 33;
/// RX descriptor writeback `status` completion test for A0
/// (`status & 0x5`, `hw_atl_a0_hw_ring_rx_receive`).
pub(crate) const RXD_WB_DONE_A0: u16 = 0x0005;

// ── Pure decodes ────────────────────────────────────────────────────

/// Build the FW2x rate mask for the MPI control register from a
/// Linux `AQ_NIC_RATE_*` speed mask, mirroring
/// `link_speed_mask_2fw2x_ratemask` in `hw_atl_utils_fw2x.c`.
pub const fn fw2x_rate_mask(speed_msk: u32) -> u32 {
    let mut rate: u32 = 0;
    if speed_msk & RATE_10G != 0 {
        rate |= FW2X_RATE_10G;
    }
    if speed_msk & RATE_5G != 0 {
        rate |= FW2X_RATE_5G;
    }
    if speed_msk & RATE_2G5 != 0 {
        rate |= FW2X_RATE_2G5;
    }
    if speed_msk & RATE_1G != 0 {
        rate |= FW2X_RATE_1G;
    }
    if speed_msk & RATE_100M != 0 {
        rate |= FW2X_RATE_100M;
    }
    rate
}

/// Map a FW1x MPI speed field (`HAL_ATLANTIC_RATE_*`) to Mbit/s
/// (0 when down/unknown), mirroring
/// `hw_atl_utils_mpi_get_link_status`. `HAL_RATE_5GSR` reports
/// 5G, like 5G.
pub const fn hal_rate_to_mbps(rate: u32) -> u32 {
    match rate {
        HAL_RATE_10G => 10000,
        HAL_RATE_5G | HAL_RATE_5GSR => 5000,
        HAL_RATE_2G5 => 2500,
        HAL_RATE_1G => 1000,
        HAL_RATE_100M => 100,
        _ => 0,
    }
}

/// Decode a FW1x MPI state register word (`0x36C`: state in
/// bits [7:0], speed in bits [23:16]) into a link status,
/// mirroring `hw_atl_utils_mpi_get_link_status`. An unknown
/// speed code decodes as down (Linux returns `-EBUSY`; the
/// pump treats that as down either way). Full duplex always.
pub const fn link_status_1x_decode(mpi_state: u32) -> LinkStatus {
    let mbps = hal_rate_to_mbps((mpi_state >> MPI_SPEED_SHIFT) & 0xFF);
    LinkStatus {
        carrier: mbps != 0,
        mbps,
        full_duplex: true,
    }
}

/// Decode a FW2x MPI state register word (`0x370`: `FW2X_RATE_*`
/// bits) into a link status, mirroring
/// `aq_fw2x_update_link_status`. Highest rate wins.
pub const fn link_status_2x_decode(mpi_state: u32) -> LinkStatus {
    let mbps = if mpi_state & FW2X_RATE_10G != 0 {
        10000
    } else if mpi_state & FW2X_RATE_5G != 0 {
        5000
    } else if mpi_state & FW2X_RATE_2G5 != 0 {
        2500
    } else if mpi_state & FW2X_RATE_1G != 0 {
        1000
    } else if mpi_state & FW2X_RATE_100M != 0 {
        100
    } else {
        0
    };
    LinkStatus {
        carrier: mbps != 0,
        mbps,
        full_duplex: true,
    }
}

/// Decode the two efuse MAC dwords read by
/// `hw_atl_utils_fw_downld_dwords`: each dword is byte-swapped
/// (`__swab32`) and then copied in memory order
/// (`ether_addr_copy`), so the MAC bytes are the big-endian
/// bytes of each word in turn.
pub const fn decode_mac_efuse(dwords: &[u32; 2]) -> [u8; 6] {
    let w0 = dwords[0].swap_bytes();
    let w1 = dwords[1].swap_bytes();
    let b0 = w0.to_le_bytes();
    let b1 = w1.to_le_bytes();
    [b0[0], b0[1], b0[2], b0[3], b1[0], b1[1]]
}

/// Fallback permanent MAC (`hw_atl_utils_get_mac_permanent`):
/// when the efuse MAC is multicast or its first three bytes
/// are zero, Linux builds `30:0E:E3:00:XX:XX` from the low 16
/// bits of the UCP `0x370` register (`h = 0x8001300E`,
/// `l = 0xE3000000 | (ucp370 & 0xFFFF)`).
pub const fn fallback_mac(ucp370: u32) -> [u8; 6] {
    [
        0x30,
        0x0E,
        0xE3,
        0x00,
        ((ucp370 >> 8) & 0xFF) as u8,
        (ucp370 & 0xFF) as u8,
    ]
}

/// `true` when the efuse MAC needs the fallback (multicast bit
/// set, or the first three bytes zero), per
/// `hw_atl_utils_get_mac_permanent`.
pub const fn mac_needs_fallback(mac: [u8; 6]) -> bool {
    (mac[0] & 0x01) != 0 || (mac[0] | mac[1] | mac[2]) == 0
}

/// Decode an A0 RX writeback, mirroring
/// `hw_atl_a0_hw_ring_rx_receive`. Differences from the B0
/// decode (`decode_rx_wb`): the error flag is DMA-error only
/// (the A0 `is_err` is masked to zero by the
/// `&= ~0x18; &= ~0x04` pair), the L4 verdict trusts the
/// checksum-enable bit plus a clear error bit without
/// requiring the verified bit, and `Fail` never arises (A0
/// never sets `is_cso_err`). Length follows the same EOP rule.
pub fn decode_rx_wb_a0(wb: &RxdWb, frame_max: u32) -> RxDecode {
    let status = wb.status;
    let type_ = wb.type_;
    let rx_stat = (status & RXD_WB_RXSTAT_MSK) >> RXD_WB_RXSTAT_SHIFT;
    let pkt_type = (type_ & RXD_WB_PKTTYPE_MSK) >> RXD_WB_PKTTYPE_SHIFT;
    let csum_en = (type_ >> RXD_WB_CSUM_EN_SHIFT) & 0x3;
    let is_eop = status & RXD_WB_EOP != 0;
    let error = (type_ & RXD_WB_DMA_ERR) != 0;
    let pkt_len = wb.pkt_len as u32;

    let mut l4_ok = false;
    if csum_en & 0x2 != 0 && ((pkt_type & 0x1C) == 0x04 || (pkt_type & 0x1C) == 0x00) {
        l4_ok = (rx_stat & 0x4) == 0;
    }
    let csum = if l4_ok {
        RxCsumResult::Ok
    } else {
        RxCsumResult::None
    };

    let len = if is_eop {
        let r = pkt_len % frame_max;
        if r == 0 {
            frame_max as usize
        } else {
            r as usize
        }
    } else {
        core::cmp::min(pkt_len, frame_max) as usize
    };
    RxDecode {
        len,
        csum,
        error,
        is_eop,
    }
}

/// Sample an A0 RX ring slot the NIC may be completing right
/// now, mirroring `RxdWb::sample` except for the completion
/// test: A0 treats a descriptor as done when
/// `status & 0x5 != 0` (`hw_atl_a0_hw_ring_rx_receive`), not
/// just on DD. The same load-order discipline applies: dword 2
/// (status + length) is taken first and as ONE load, so a set
/// completion always comes with the length written with it.
#[inline]
pub(crate) fn sample_a0_wb(mut dword: impl FnMut(usize) -> u32) -> Option<RxdWb> {
    let status_len = dword(2);
    if status_len as u16 & RXD_WB_DONE_A0 == 0 {
        return None;
    }
    // Pair the NIC's completion write with the loads that follow it.
    compiler_fence(Ordering::SeqCst);
    let type_ = dword(0);
    let rss_hash = dword(1);
    let next_vlan = dword(3);
    Some(RxdWb {
        type_,
        rss_hash,
        status: status_len as u16,
        pkt_len: (status_len >> 16) as u16,
        next_desc_ptr: next_vlan as u16,
        vlan: (next_vlan >> 16) as u16,
    })
}

// ── Small helpers ───────────────────────────────────────────────────

/// Fixed sync delay, the `drivers/audio` precedent:
/// `responsive_spin_until` against an always-false condition
/// pumps the sleep pumps while the deadline runs out.
fn sleep_ms(ms: u64) {
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(ms));
}

/// UCP `0x370` seed, the NARF analogue of Linux's
/// `get_random_bytes` call in `hw_atl_utils_init_ucp` /
/// `hw_atl_utils_get_mac_permanent`: TSC cycles mixed with a
/// monotonic counter, masked to `0x02020202 | (0xFEFEFEFE & rnd)`.
/// The seed only feeds the fallback MAC for unprovisioned efuse
/// parts; its exact value is unspecified by Linux (random).
static UCP_SEED_CTR: AtomicU32 = AtomicU32::new(0xA5A5_5A5A);

fn ucp_seed() -> u32 {
    let ctr = UCP_SEED_CTR.fetch_add(0x9E37_79B9, Ordering::Relaxed);
    let t = narf_time::now_cycles() as u32;
    let rnd = (t ^ ctr).wrapping_mul(0x9E37_79B9).rotate_left(13) ^ (t >> 16);
    0x0202_0202 | (0xFEFE_FEFE & rnd)
}

/// Seed the UCP `0x370` register when it reads zero, mirroring
/// the head of `hw_atl_utils_init_ucp` /
/// `hw_atl_utils_get_mac_permanent`.
fn seed_ucp_0x370(regs: &impl RegIo) {
    if regs.read32(REG_UCP_0X370) == 0 {
        regs.write32(REG_UCP_0X370, ucp_seed());
    }
}

// ── MIF download ────────────────────────────────────────────────────
// `hw_atl_utils_fw_downld_dwords`: acquire the RAM semaphore,
// write the address, then per dword write `MIF_CMD = 0x8000`
// and poll for completion — B1 polls `MIF_ADDR != a`, A0/B0
// poll `!(MIF_CMD & 0x100)` — then read `MIF_VAL`. The
// semaphore is released afterwards.

/// Read `cnt` dwords starting at device address `addr` through
/// the MIF download interface.
pub(crate) fn mif_download(
    regs: &impl RegIo,
    mut addr: u32,
    out: &mut [u32],
    is_b1: bool,
) -> Result<(), NicError> {
    let sem = reg_glb_cpu_sem(FW_SEM_RAM);
    let acquired = narf_scheduler::responsive_spin_until(
        || regs.read32(sem) == 1,
        narf_time::Deadline::after_ms(10),
    );
    if !acquired {
        // Linux forces the semaphore and re-checks on timeout.
        regs.write32(sem, 1);
        if regs.read32(sem) != 1 {
            return Err(NicError::FwTimeout);
        }
    }
    regs.write32(REG_MIF_ADDR, addr);
    for w in out.iter_mut() {
        regs.write32(REG_MIF_CMD, MIF_CMD_START);
        let done = if is_b1 {
            narf_scheduler::responsive_spin_until(
                || regs.read32(REG_MIF_ADDR) != addr,
                narf_time::Deadline::after_ms(1),
            )
        } else {
            narf_scheduler::responsive_spin_until(
                || regs.read32(REG_MIF_CMD) & MIF_CMD_BUSY == 0,
                narf_time::Deadline::after_ms(1),
            )
        };
        if !done {
            regs.write32(sem, 1);
            return Err(NicError::FwTimeout);
        }
        *w = regs.read32(REG_MIF_VAL);
        addr = addr.wrapping_add(4);
    }
    regs.write32(sem, 1);
    Ok(())
}

/// Read the mailbox header's transaction id
/// (`hw_atl_utils_mbox_header`: version, transaction_id,
/// error) from `mbox_addr` via the MIF download interface.
pub(crate) fn read_mbox_tid(
    regs: &impl RegIo,
    mbox_addr: u32,
    is_b1: bool,
) -> Result<u32, NicError> {
    let mut header = [0u32; 3];
    mif_download(regs, mbox_addr, &mut header, is_b1)?;
    Ok(header[1])
}

// ── MPI firmware interface ──────────────────────────────────────────
// FW1x (`aq_fw_1x_ops`) and FW2x (`aq_fw_2x_ops`) share the
// `0x368`/`0x36C`/`0x370` registers with different field
// semantics; the generation selects the accessor.

/// FW1x `set_link_speed` (`hw_atl_utils_mpi_set_speed`): the
/// `AQ_NIC_RATE_*` mask goes into the MPI speed field
/// (bits [23:16] of `0x368`).
pub(crate) fn mpi_set_speed_1x(regs: &impl RegIo, speed_msk: u32) {
    let mut val = regs.read32(REG_MPI_CONTROL);
    val &= !MPI_SPEED_MSK;
    val |= (speed_msk << MPI_SPEED_SHIFT) & MPI_SPEED_MSK;
    regs.write32(REG_MPI_CONTROL, val);
}

/// FW2x `set_link_speed` (`aq_fw2x_set_link_speed`): the FW2x
/// rate mask is written whole to `0x368`.
pub(crate) fn mpi_set_speed_2x(regs: &impl RegIo, speed_msk: u32) {
    regs.write32(REG_MPI_CONTROL, fw2x_rate_mask(speed_msk));
}

/// Set the link speed for the firmware generation.
pub(crate) fn mpi_set_speed(regs: &impl RegIo, fw_gen: FwGen, speed_msk: u32) {
    match fw_gen {
        FwGen::Fw1x => mpi_set_speed_1x(regs, speed_msk),
        FwGen::Fw2x => mpi_set_speed_2x(regs, speed_msk),
    }
}

/// FW1x `set_state` (`hw_atl_utils_mpi_set_state`). `MPI_RESET`
/// first reads the mailbox transaction id and waits for the
/// firmware to advance it (100 ms) — the wait happens BEFORE
/// the state write — then the state is written.
/// `MPI_DEINIT`/`MPI_POWER` set the dirty-wake bit, other
/// states clear it; the state field is then written.
pub(crate) fn mpi_set_state_1x(
    regs: &impl RegIo,
    state: u32,
    mbox_addr: u32,
    is_b1: bool,
) -> Result<(), NicError> {
    if state == MPI_RESET {
        let tid = read_mbox_tid(regs, mbox_addr, is_b1)?;
        let changed = narf_scheduler::responsive_spin_until(
            || {
                read_mbox_tid(regs, mbox_addr, is_b1)
                    .map(|t| t != tid)
                    .unwrap_or(false)
            },
            narf_time::Deadline::after_ms(100),
        );
        if !changed {
            return Err(NicError::FwTimeout);
        }
    }
    let mut val = regs.read32(REG_MPI_CONTROL);
    if state == MPI_DEINIT || state == MPI_POWER {
        val |= MPI_DIRTY_WAKE;
    } else {
        val &= !MPI_DIRTY_WAKE;
    }
    val = (val & !MPI_STATE_MSK) | (state & MPI_STATE_MSK);
    regs.write32(REG_MPI_CONTROL, val);
    Ok(())
}

/// FW2x `set_state` (`aq_fw2x_set_state`): `MPI_INIT` clears
/// the link-drop bit (22) of control-2 (`0x36C`) and sets flow
/// control to FULL (pause + asymmetric-pause bits 3/4, EEE
/// off); `MPI_DEINIT` sets link-drop; `MPI_RESET`/`MPI_POWER`
/// are no-ops.
pub(crate) fn mpi_set_state_2x(regs: &impl RegIo, state: u32) {
    let mut mpi_state = regs.read32(REG_MPI_STATE);
    match state {
        MPI_INIT => {
            mpi_state &= !(1 << FW2X_LINK_DROP_BIT);
            mpi_state |= FW2X_CTRL_PAUSE | FW2X_CTRL_ASYMMETRIC_PAUSE;
        }
        MPI_DEINIT => {
            mpi_state |= 1 << FW2X_LINK_DROP_BIT;
        }
        _ => {}
    }
    regs.write32(REG_MPI_STATE, mpi_state);
}

/// Set the firmware state for the generation. `mbox_addr` is
/// only used by the FW1x `MPI_RESET` path.
pub(crate) fn mpi_set_state(
    regs: &impl RegIo,
    fw_gen: FwGen,
    state: u32,
    mbox_addr: u32,
    is_b1: bool,
) -> Result<(), NicError> {
    match fw_gen {
        FwGen::Fw1x => mpi_set_state_1x(regs, state, mbox_addr, is_b1),
        FwGen::Fw2x => {
            mpi_set_state_2x(regs, state);
            Ok(())
        }
    }
}

/// Read the current firmware link status for the generation.
pub(crate) fn read_link_status(regs: &impl RegIo, fw_gen: FwGen) -> LinkStatus {
    match fw_gen {
        FwGen::Fw1x => link_status_1x_decode(regs.read32(REG_MPI_STATE)),
        FwGen::Fw2x => link_status_2x_decode(regs.read32(REG_UCP_0X370)),
    }
}

// ── Firmware boot ───────────────────────────────────────────────────
// `hw_atl_utils_soft_reset` + `hw_atl_utils_initfw` + the
// `aq_fw_*_ops->init` mailbox discovery.

/// Reboot the on-chip firmware through the FLB/RBL kickstart
/// sequence and wait for it to come up, mirroring
/// `hw_atl_utils_soft_reset`. Returns the raw firmware version
/// word (register `0x18`, read before the kickstart).
///
/// Entry: poll the daisy-chain status (`0x704`) and boot exit
/// code (`0x388`) — unless the status reads exactly
/// `0x06000000` with a zero exit code the firmware has started
/// (either the RBL or the FLB path). `rbl_enabled` follows the
/// exit code. FW 1.x is forced back to `MPI_DEINIT` first (WOL
/// workaround); FW 4.x acquires the two reset semaphores first.
/// Then the RBL or FLB path runs; both end polling the firmware
/// version register for nonzero (10 s budget each).
pub(crate) fn soft_reset(regs: &impl RegIo) -> Result<u32, NicError> {
    let version = regs.read32(REG_MPI_FW_VERSION);

    // Entry: the firmware has started unless the status is
    // exactly 0x06000000 with a zero boot exit code (tight
    // 1000-iteration poll, no sleep — as in Linux).
    let mut started = false;
    for _ in 0..1000 {
        let flb_status = regs.read32(REG_MPI_DAISY_CHAIN_STATUS);
        let boot_exit_code = regs.read32(REG_MPI_BOOT_EXIT_CODE);
        if flb_status != FLB_NOT_STARTED || boot_exit_code != 0 {
            started = true;
            break;
        }
    }
    if !started {
        return Err(NicError::Other("neither RBL nor FLB firmware started"));
    }
    let rbl_enabled = regs.read32(REG_MPI_BOOT_EXIT_CODE) != 0;

    if let Some(FwGen::Fw1x) = fw_gen_for(version) {
        // FW 1.x may boot in an invalid POWER state (WOL); force
        // it back to DEINIT and wait for the state to land.
        mpi_set_state_1x(regs, MPI_DEINIT, 0, false)?;
        let deinit = narf_scheduler::responsive_spin_until(
            || regs.read32(REG_MPI_STATE) & MPI_STATE_MSK == MPI_DEINIT,
            narf_time::Deadline::after_ms(10),
        );
        if !deinit {
            return Err(NicError::FwTimeout);
        }
    } else if let Some(FwGen::Fw2x) = fw_gen_for(version) {
        if version >> 24 == 4 {
            // FW 4.x: acquire both reset semaphores before
            // issuing the reset (timeouts are logged, not
            // fatal, in Linux — same here).
            let mut sem_timeout = regs.read32(REG_MIF_RESET_TIMEOUT);
            if sem_timeout > 3000 {
                sem_timeout = 3000;
            }
            let sem_timeout_us = sem_timeout * 1000;
            if sem_timeout_us != 0 {
                let _ = narf_scheduler::responsive_spin_until(
                    || regs.read32(reg_glb_cpu_sem(FW_SEM_RESET1)) == 1,
                    narf_time::Deadline::after_us(sem_timeout_us as u64),
                );
                let _ = narf_scheduler::responsive_spin_until(
                    || regs.read32(reg_glb_cpu_sem(FW_SEM_RESET2)) == 1,
                    narf_time::Deadline::after_us(sem_timeout_us as u64),
                );
            }
        }
    }

    if rbl_enabled {
        soft_reset_rbl(regs)
    } else {
        soft_reset_flb(regs)
    }?;
    Ok(version)
}

/// FLB kickstart (`hw_atl_utils_soft_reset_flb`): MCP force
/// interrupt + SPI cleanup + global soft reset, MAC kickstart,
/// SPI reset toggle, daisy-chain ready poll, firmware reset,
/// then the firmware-version poll. (The "Kickstart PHY" step
/// is skipped in Linux itself — the comment says so.)
fn soft_reset_flb(regs: &impl RegIo) -> Result<(), NicError> {
    regs.write32(REG_MCP_UP_FORCE_INT, 0x40E1);
    sleep_ms(50);

    // Cleanup SPI.
    let val = regs.read32(REG_SPI_CTL);
    regs.write32(REG_SPI_CTL, val | SPI_RESET);

    let gsr = regs.read32(REG_GLB_SOFT_RES);
    regs.write32(REG_GLB_SOFT_RES, (gsr & !GLB_REG_RES_DIS) | GLB_SOFT_RES);

    // Kickstart MAC.
    regs.write32(REG_MCP_UP_FORCE_INT, 0x80E0);
    regs.write32(REG_KICKSTART_SCRATCH, 0x0);
    regs.write32(REG_KICKSTART_CTL, 0x1);

    // Reset SPI again because of a possible interrupted burst.
    let val = regs.read32(REG_SPI_CTL);
    regs.write32(REG_SPI_CTL, val | SPI_RESET);
    sleep_ms(10);
    regs.write32(REG_SPI_CTL, val & !SPI_RESET);

    regs.write32(REG_MCP_UP_FORCE_INT, 0x180E0);

    let daisy_ready = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_MPI_DAISY_CHAIN_STATUS) & FLB_DAISY_READY != 0,
        narf_time::Deadline::after_ms(10_000),
    );
    if !daisy_ready {
        return Err(NicError::Other("MAC kickstart failed"));
    }

    // FW reset.
    regs.write32(REG_MCP_UP_FORCE_INT, 0x80E0);
    sleep_ms(50);
    regs.write32(reg_glb_cpu_sem(0), 0x1);

    // Global software reset.
    regs.rmw32(REG_RX_REG_RES_DSBL, REG_RES_DSBL, 0);
    regs.rmw32(REG_TX_REG_RES_DSBL, REG_RES_DSBL, 0);
    regs.rmw32(REG_MAC_PHY_CONTROL, MAC_PHY_MPI_RESET_BIT, 0);
    let gsr = regs.read32(REG_GLB_SOFT_RES);
    regs.write32(REG_GLB_SOFT_RES, (gsr & !GLB_REG_RES_DIS) | GLB_SOFT_RES);

    let fw_up = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_MPI_FW_VERSION) != 0,
        narf_time::Deadline::after_ms(10_000),
    );
    if !fw_up {
        return Err(NicError::Other("FW kickstart failed"));
    }
    // Old FW requires a fixed delay after init.
    sleep_ms(15);
    Ok(())
}

/// RBL kickstart (`hw_atl_utils_soft_reset_rbl`): MCP force
/// interrupt + semaphore, RBL status marker, SPI cleanup,
/// global soft reset, RBL boot poll (`0x388` low half nonzero
/// and not the `0xDEAD` marker; `0xF1A7` means no firmware),
/// then the firmware-version poll. (`FORCE_FLASHLESS` is 0 in
/// Linux, so the flashless branches are omitted.)
fn soft_reset_rbl(regs: &impl RegIo) -> Result<(), NicError> {
    regs.write32(REG_MCP_UP_FORCE_INT, 0x40E1);
    regs.write32(reg_glb_cpu_sem(0), 0x1);
    regs.write32(REG_KICKSTART_SCRATCH, 0x0);

    // Alter RBL status.
    regs.write32(REG_MPI_BOOT_EXIT_CODE, RBL_STATUS_MARKER);

    // Cleanup SPI.
    let val = regs.read32(REG_SPI_CTL);
    regs.write32(REG_SPI_CTL, val | SPI_RESET);

    // Global software reset.
    regs.rmw32(REG_RX_REG_RES_DSBL, REG_RES_DSBL, 0);
    regs.rmw32(REG_TX_REG_RES_DSBL, REG_RES_DSBL, 0);
    regs.rmw32(REG_MAC_PHY_CONTROL, MAC_PHY_MPI_RESET_BIT, 0);
    let gsr = regs.read32(REG_GLB_SOFT_RES);
    regs.write32(REG_GLB_SOFT_RES, (gsr & 0xFFFF_BFFF) | GLB_SOFT_RES);

    regs.write32(REG_MCP_UP_FORCE_INT, 0x40E0);

    // Wait for RBL boot.
    let mut rbl_status = 0u32;
    let booted = narf_scheduler::responsive_spin_until(
        || {
            rbl_status = regs.read32(REG_MPI_BOOT_EXIT_CODE) & 0xFFFF;
            rbl_status != 0 && rbl_status != RBL_STATUS_MARKER
        },
        narf_time::Deadline::after_ms(10_000),
    );
    if !booted || rbl_status == 0 || rbl_status == RBL_STATUS_MARKER {
        return Err(NicError::Other("RBL restart failed"));
    }
    if rbl_status == RBL_STATUS_NO_FW {
        return Err(NicError::NoFirmware);
    }

    let fw_up = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_MPI_FW_VERSION) != 0,
        narf_time::Deadline::after_ms(10_000),
    );
    if !fw_up {
        return Err(NicError::Other("FW kickstart failed"));
    }
    // Old FW requires a fixed delay after init.
    sleep_ms(15);
    Ok(())
}

/// Discover the firmware mailbox/RPC addresses, mirroring the
/// `init` half of the `aq_fw_*_ops`:
/// - FW 1.x (`hw_atl_utils_mpi_create` = `init_ucp` +
///   `fw_rpc_init`): seed UCP `0x370`, write scratchpad index 25
///   (`0x364`) to 0, poll scratchpad index 24 (`0x360`,
///   Linux's `hw_atl_scrpad25_get` — the "25" in that name is
///   1-based, the index is `0x18`) for the mailbox address
///   (10 ms), poll the RPC address register for the RPC address
///   (100 ms). The RPC tid handshake (`fw_rpc_init`) is
///   deferred (see the module header), so the RPC address is
///   best-effort here — but the mailbox address is required by
///   `MPI_RESET`, so its poll is fatal.
/// - FW 2.x (`aq_fw2x_init`): poll the mailbox address (10 ms)
///   and the RPC address (100 ms); the settings fetch is
///   deferred with the FW config upload. Neither address is
///   needed by the Stage-2 datapath, so both polls are
///   best-effort. FW2x never writes scratchpad index 25:
///   `0x364` is its efuse-address register, so the clear is
///   FW1x-only.
///
/// Returns `(mbox_addr, rpc_addr)`; either may be 0 on the
/// FW2x path.
pub(crate) fn fw_mpi_init(regs: &impl RegIo, fw_gen: FwGen) -> Result<(u32, u32), NicError> {
    if fw_gen == FwGen::Fw1x {
        seed_ucp_0x370(regs);
        regs.write32(reg_glb_cpu_scratch(25), 0x0);
    }
    let mbox_ok = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_SCRPAD_MBOX_ADDR) != 0,
        narf_time::Deadline::after_ms(10),
    );
    let mbox_addr = regs.read32(REG_SCRPAD_MBOX_ADDR);
    let rpc_ok = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_MPI_RPC_ADDR) != 0,
        narf_time::Deadline::after_ms(100),
    );
    let rpc_addr = regs.read32(REG_MPI_RPC_ADDR);
    match fw_gen {
        FwGen::Fw1x => {
            if !mbox_ok || mbox_addr == 0 {
                return Err(NicError::FwTimeout);
            }
            let _ = rpc_ok;
            Ok((mbox_addr, rpc_addr))
        }
        FwGen::Fw2x => Ok((mbox_addr, rpc_addr)),
    }
}

/// Read the permanent MAC for the firmware generation:
/// - FW 1.x (`hw_atl_utils_get_mac_permanent`): seed UCP
///   `0x370`, read the efuse address from `0x374`, download
///   two dwords at `efuse + 160`, byte-swap them. A download
///   failure zeroes the MAC (Linux resets the error) and the
///   fallback below applies. When the MAC is multicast or its
///   first three bytes are zero, build the fallback MAC from
///   UCP `0x370`.
/// - FW 2.x (`aq_fw2x_get_mac_permanent`): read the efuse
///   address from `0x364`; when nonzero, download two dwords
///   at `efuse + 160` and byte-swap them (a download failure
///   is fatal here); otherwise the MAC stays zero and the
///   caller rejects it as invalid. No fallback exists.
pub(crate) fn get_mac_permanent(
    regs: &impl RegIo,
    fw_gen: FwGen,
    is_b1: bool,
) -> Result<[u8; 6], NicError> {
    match fw_gen {
        FwGen::Fw1x => {
            seed_ucp_0x370(regs);
            let efuse_addr = regs.read32(REG_EFUSE_ADDR_1X);
            let mut dwords = [0u32; 2];
            let downld = mif_download(regs, efuse_addr.wrapping_add(40 * 4), &mut dwords, is_b1);
            if downld.is_err() {
                dwords = [0, 0];
            }
            let mac = decode_mac_efuse(&dwords);
            if mac_needs_fallback(mac) {
                Ok(fallback_mac(regs.read32(REG_UCP_0X370)))
            } else {
                Ok(mac)
            }
        }
        FwGen::Fw2x => {
            let efuse_addr = regs.read32(REG_EFUSE_ADDR_2X);
            if efuse_addr == 0 {
                return Ok([0; 6]);
            }
            let mut dwords = [0u32; 2];
            mif_download(regs, efuse_addr.wrapping_add(40 * 4), &mut dwords, is_b1)?;
            Ok(decode_mac_efuse(&dwords))
        }
    }
}

// ── Reset / init ────────────────────────────────────────────────────

/// Reset the controller, mirroring `hw_atl_b0_hw_reset` /
/// `hw_atl_a0_hw_reset`:
/// - B0/B1: `soft_reset` again, then firmware
///   `MPI_RESET`.
/// - A0: register-reset-disable dance + global soft-reset bit
///   poll + ITR reset dance (no firmware reboot), then
///   firmware `MPI_RESET`.
pub(crate) fn hw_reset(
    regs: &impl RegIo,
    backend: Backend,
    mbox_addr: u32,
    fw_gen: FwGen,
) -> Result<(), NicError> {
    let is_b1 = backend == Backend::B1;
    match backend {
        Backend::A0 => {
            regs.rmw32(REG_GLB_SOFT_RES, GLB_REG_RES_DIS, GLB_REG_RES_DIS);
            regs.rmw32(REG_PCI_REG_RES_DSBL, REG_RES_DSBL, 0);
            regs.rmw32(REG_RX_REG_RES_DSBL, REG_RES_DSBL, 0);
            regs.rmw32(REG_TX_REG_RES_DSBL, REG_RES_DSBL, 0);
            // Flush read.
            let _ = regs.read32(REG_ALIVE_CHECK);
            regs.rmw32(REG_GLB_SOFT_RES, GLB_SOFT_RES, GLB_SOFT_RES);
            let reset_done = narf_scheduler::responsive_spin_until(
                || regs.read32(REG_GLB_SOFT_RES) & GLB_SOFT_RES == 0,
                narf_time::Deadline::after_ms(10),
            );
            if !reset_done {
                return Err(NicError::FwTimeout);
            }
            regs.rmw32(REG_ITR_RES, REG_RES_DSBL, 0);
            regs.rmw32(REG_ITR_RES, ITR_RES, ITR_RES);
            let itr_done = narf_scheduler::responsive_spin_until(
                || regs.read32(REG_ITR_RES) & ITR_RES == 0,
                narf_time::Deadline::after_ms(10),
            );
            if !itr_done {
                return Err(NicError::FwTimeout);
            }
        }
        Backend::B0 | Backend::B1 => {
            soft_reset(regs)?;
        }
    }
    mpi_set_state(regs, fw_gen, MPI_RESET, mbox_addr, is_b1)
}

/// Initialise the TX path, mirroring the gating writes of
/// `hw_atl_b0_hw_init_tx_path` / `hw_atl_a0_hw_init_tx_path`:
/// TX-descriptor writeback interrupts on, TPO2 control
/// (`0x7040` = `0x10000` when the chip has TPO2, else 0).
/// TC mode, LSO flag words, DCA and the TX-path scope-insert
/// enable are deferred (see the module header).
pub(crate) fn init_tx_path(regs: &impl RegIo, features: ChipFeatures) {
    regs.set_bit(
        super::aqc113::REG_TDM_INT_DESC_WRB_EN,
        super::aqc113::TDM_WRB_IRQ_EN,
    );
    regs.write32(REG_TPO2_CTL, if features.tpo2 { TPO2_CTL_VALUE } else { 0 });
}

/// Initialise the RX path, mirroring the gating writes of
/// `hw_atl_b0_hw_init_rx_path` / `hw_atl_a0_hw_init_rx_path`:
/// RX flow-control mode 1, RSS control 1 = 0 (RSS disabled),
/// L2 unicast filters (only filter 0 enabled, all with the
/// host action), multicast mask 0 + ANY_TO_HOST, VLAN TPIDs,
/// VLAN promiscuous mode (+ accept-untagged + untagged-act
/// HOST on B0/B1 only — A0's RX path does not program them),
/// RX-descriptor writeback interrupts on, RPF2 control
/// (`0x5040` = `0xF0000`, B0/B1 only), broadcast filter
/// (host action, threshold `0xFFFF`).
pub(crate) fn init_rx_path(regs: &impl RegIo, features: ChipFeatures) {
    use super::aqc113::{
        L2_ACT_HOST, MCST_FLT_ANY_TO_HOST, RDM_WRB_IRQ_EN, REG_RDM_INT_DESC_WRB_EN, REG_RPF_BC,
        REG_RPF_MCST_FLR_BASE, REG_RPF_MCST_MSK, REG_RPF_VLAN_CTL, REG_RPF_VLAN_TPID,
        RPF_BC_ACT_MSK, RPF_BC_ACT_SHIFT, RPF_BC_THRESH, RPF_BC_THRESH_MSK, RPF_BC_THRESH_SHIFT,
        RPF_UC_ACT_MSK, RPF_UC_ACT_SHIFT, RPF_UC_EN, RPF_VL_ACCEPT_UNTAGGED, RPF_VL_PROMIS_MODE,
        RPF_VL_UNTAGGED_ACT_MSK, RPF_VL_UNTAGGED_ACT_SHIFT,
    };
    regs.rmw32(
        REG_RPB_RX_BUF,
        RPB_RX_FC_MODE_MSK,
        1 << RPB_RX_FC_MODE_SHIFT,
    );
    regs.write32(REG_RX_FLR_RSS_CONTROL1, 0);
    for i in 0..MAC_FILTER_MAX {
        let en = if i == 0 { RPF_UC_EN } else { 0 };
        regs.rmw32(
            super::aqc113::reg_rpf_uc_ctl(i as u64),
            RPF_UC_EN | RPF_UC_ACT_MSK,
            en | (L2_ACT_HOST << RPF_UC_ACT_SHIFT),
        );
    }
    regs.write32(REG_RPF_MCST_MSK, 0);
    regs.write32(REG_RPF_MCST_FLR_BASE, MCST_FLT_ANY_TO_HOST);
    regs.write32(REG_RPF_VLAN_TPID, (0x88A8 << 16) | 0x8100);
    let mut vlan_ctl = RPF_VL_PROMIS_MODE;
    if features.backend != Backend::A0 {
        vlan_ctl |= RPF_VL_ACCEPT_UNTAGGED | (L2_ACT_HOST << RPF_VL_UNTAGGED_ACT_SHIFT);
    }
    regs.rmw32(
        REG_RPF_VLAN_CTL,
        RPF_VL_PROMIS_MODE | RPF_VL_ACCEPT_UNTAGGED | RPF_VL_UNTAGGED_ACT_MSK,
        vlan_ctl,
    );
    regs.set_bit(REG_RDM_INT_DESC_WRB_EN, RDM_WRB_IRQ_EN);
    if features.backend != Backend::A0 {
        regs.write32(REG_RPF2_CTL, RPF2_CTL_VALUE);
    }
    regs.rmw32(
        REG_RPF_BC,
        RPF_BC_ACT_MSK | RPF_BC_THRESH_MSK,
        (L2_ACT_HOST << RPF_BC_ACT_SHIFT) | (RPF_BC_THRESH << RPF_BC_THRESH_SHIFT),
    );
}

/// Program the permanent MAC into the RPF L2 unicast filter at
/// `location`, mirroring `hw_atl_b0_hw_mac_addr_set` /
/// `hw_atl_a0_hw_mac_addr_set`: disable the filter, write the
/// address words, set the host action, re-enable. Unlike the
/// AQC113 driver's `mac_addr_set`, this does NOT program the
/// unicast tag — the TAG field (bits [27:22] of the control
/// register) is `HW_ATL2`-only; `hw_atl`'s control register
/// has no such field.
pub(crate) fn mac_addr_set(regs: &impl RegIo, location: u32, mac: [u8; 6]) {
    use super::aqc113::{
        L2_ACT_HOST, RPF_UC_ACT_MSK, RPF_UC_ACT_SHIFT, RPF_UC_DAFMSW_MSK, RPF_UC_EN,
    };
    let (l, h) = mac_filter_words(mac);
    let ctl = super::aqc113::reg_rpf_uc_ctl(location as u64);
    regs.clear_bit(ctl, RPF_UC_EN);
    regs.write32(super::aqc113::reg_rpf_uc_daflsw(location as u64), l);
    regs.rmw32(ctl, RPF_UC_DAFMSW_MSK, h);
    regs.rmw32(ctl, RPF_UC_ACT_MSK, L2_ACT_HOST << RPF_UC_ACT_SHIFT);
    regs.set_bit(ctl, RPF_UC_EN);
}

/// Program the interrupt block for MSI-X with a single vector,
/// mirroring the interrupt tail of `hw_atl_b0_hw_init` /
/// `hw_atl_a0_hw_init`: global control `0x20000022`,
/// auto-mask `~0U`, general IRQ map 0 (B0/B1: error interrupt
/// in two fields; A0: in all four).
pub(crate) fn init_interrupts(regs: &impl RegIo, backend: Backend) {
    regs.write32(REG_IRQ_GLB_CTL, IRQ_GLB_CTL_MSIX_1VEC);
    regs.write32(REG_ITR_IAMRLSW, IRQ_AUTO_MASK);
    regs.write32(
        REG_GEN_IRQ_MAP_BASE,
        match backend {
            Backend::A0 => GEN_IRQ_MAP0_A0,
            Backend::B0 | Backend::B1 => GEN_IRQ_MAP0_B0,
        },
    );
}

/// Full hardware init, mirroring `hw_atl_b0_hw_init` /
/// `hw_atl_a0_hw_init`: TX + RX path, MAC filter, firmware
/// link speed + `MPI_INIT`, then the backend extras — B0/B1
/// force the PCI MRRS limit to 2K and the TX DMA total
/// request limit to 24; A0 writes the TX DMA debug control
/// twice — and the interrupt block. (QoS, RSS tables, stats
/// and offload programming are deferred; see the module
/// header.)
pub(crate) fn hw_init(
    regs: &impl RegIo,
    features: ChipFeatures,
    fw_gen: FwGen,
    mac: [u8; 6],
    speed_msk: u32,
) -> Result<(), NicError> {
    init_tx_path(regs, features);
    init_rx_path(regs, features);
    mac_addr_set(regs, 0, mac);
    mpi_set_speed(regs, fw_gen, speed_msk);
    mpi_set_state(regs, fw_gen, MPI_INIT, 0, features.backend == Backend::B1)?;
    match features.backend {
        Backend::B0 | Backend::B1 => {
            let val = regs.read32(REG_PCI_REG_CONTROL6);
            regs.write32(
                REG_PCI_REG_CONTROL6,
                (val & !PCI_CTL6_MRRSMASK) | PCI_CTL6_MRRSVAL,
            );
            regs.write32(REG_TX_DMA_TOTAL_REQ_LIMIT, TX_DMA_TOTAL_REQ_LIMIT);
        }
        Backend::A0 => {
            regs.write32(REG_TX_DMA_DEBUG_CTL, TX_DMA_DEBUG_CTL_SET);
            regs.write32(REG_TX_DMA_DEBUG_CTL, TX_DMA_DEBUG_CTL_CLEAR);
        }
    }
    init_interrupts(regs, features.backend);
    Ok(())
}

// ── Live driver state ───────────────────────────────────────────────

/// A live AQC100/107/108/109/111/112 or D-series controller.
/// Same shape as the AQC113 `AqcNic`: MMIO mapping,
/// descriptor rings, RX/TX buffer pools, one MSI-X vector,
/// publication + carrier. The bring-up sequence is the
/// `hw_atl` one (see `bring_up`); the rings and datapath are
/// the shared `hw_atl_b0` model.
pub struct Aqc100Nic {
    mmio: MmioRegion,
    /// TX descriptor ring (`RING_LEN * 16` bytes).
    tx_ring: DmaBuffer,
    /// Persistent per-slot TX frame buffers; indexed by slot.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side TX producer cursor (next slot to fill).
    tx_head: IrqSafeSpinLock<u32>,
    /// RX descriptor ring (`RING_LEN * 16` bytes).
    rx_ring: DmaBuffer,
    /// One DMA buffer per RX descriptor. Kept alive for the
    /// driver's lifetime — descriptor `i` always points at
    /// `rx_pool[i]`.
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX consumer cursor.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from the device efuse at bring-up.
    pub mac: [u8; 6],
    /// Raw firmware version word at bring-up.
    pub fw_version: u32,
    /// Firmware generation at bring-up (`Fw1x` or `Fw2x`).
    pub fw_gen: FwGen,
    /// Hardware backend at bring-up (A0/B0/B1).
    pub backend: Backend,
    /// PCI address this controller was probed at — the
    /// per-device identity the `CONTROLLERS` dedup and detach
    /// paths key on (issue #795).
    pub addr: narf_bus::BusAddr,
    /// Set by [`aqc100_detach`]; datapath entry points fail fast
    /// once set, and [`live_controller`] filters the slot out.
    detached: AtomicBool,
    /// Interface name `publish_netdev_with_context` assigned this
    /// NIC (`eth%d`).
    ifname: crate::publish::IfName,
    /// Last observed link state (refreshed by the RX pump).
    pub link_up: bool,
    /// Last observed negotiated speed in Mbit/s, when up.
    pub link_mbps: Option<u32>,
    /// IDT vector wired to MSI-X entry 0, when MSI-X is enabled.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table — kept alive so the device's MSI-X enable
    /// stays sticky.
    msix: Option<narf_bus::MsixTable>,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: `Aqc100Nic` only owns an `MmioRegion` (identity-mapped
// BAR0 device window) and `DmaBuffer`s (identity-mapped DMA
// pages). Those raw pointers are the sole reason auto `Send` is
// not derived; the underlying device window is not
// thread-affine, so the struct may be moved between cores.
unsafe impl Send for Aqc100Nic {}
// SAFETY: every interior-mutable field (`tx_head`, `rx_head`,
// the IPC rings) is guarded by `IrqSafeSpinLock`, so concurrent
// `&Aqc100Nic` access is serialised. The MMIO/DMA windows are
// device registers/buffers safe for shared volatile access from
// multiple cores.
unsafe impl Sync for Aqc100Nic {}

impl core::fmt::Debug for Aqc100Nic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aqc100Nic")
            .field("addr", &self.addr)
            .field("mac", &self.mac)
            .field("fw_version", &self.fw_version)
            .field("fw_gen", &self.fw_gen)
            .field("backend", &self.backend)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl Aqc100Nic {
    /// Bring up the controller: firmware kickstart + mailbox
    /// discovery, permanent MAC, reset, `hw_init`, rings,
    /// datapath enable, link snapshot. Returns the controller
    /// already wrapped in `Arc` (the AQC113 shape: the pump
    /// pair spawned here holds Arc clones).
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively for
    /// the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Arc<Self>, NicError> {
        // Atlantic ships its operational registers in the first
        // MEM BAR (Linux's `aq_pci_probe` scans BARs 0..3 for the
        // first MEM resource; on AQC1xx hardware that is BAR0).
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| NicError::BarMapFailed)?;

        // 1. Firmware kickstart (`hw_atl_utils_soft_reset`) and
        // backend selection from the MIF ID register
        // (`hw_atl_utils_hw_chip_features_init`).
        let fw_version = soft_reset(&mmio)?;
        let features = chip_features(RegIo::read32(&mmio, REG_MIF_ID))
            .ok_or(NicError::Other("unknown Atlantic chip revision"))?;
        let fw_gen = fw_gen_for(fw_version)
            .ok_or(NicError::Other("unsupported Atlantic firmware version"))?;
        let is_b1 = features.backend == Backend::B1;

        // 2. Mailbox/RPC address discovery (`aq_fw_*_ops->init`).
        let (mbox_addr, _rpc_addr) = fw_mpi_init(&mmio, fw_gen)?;

        // 3. Permanent MAC from the device efuse.
        let mac = get_mac_permanent(&mmio, fw_gen, is_b1)?;
        if mac_is_invalid(mac) {
            return Err(NicError::BadMac);
        }

        // 4. Reset (`hw_atl_b0_hw_reset` / `hw_atl_a0_hw_reset`).
        hw_reset(&mmio, features.backend, mbox_addr, fw_gen)?;

        // 5. Allocate descriptor rings + per-slot buffers. Zeroed
        // pages give us inert TX descriptors (ctl = 0, not a valid
        // TXD type) and empty RX descriptors, both correct initial
        // states — the tail pointers below are what arms the rings.
        let tx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let rx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            rx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            tx_pool.push(
                alloc_coherent(TX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }

        // 6. TX + RX path, MAC filter, firmware link-up,
        // interrupts (`hw_atl_b0_hw_init` / `hw_atl_a0_hw_init`
        // order). The advertised rates come from the probed
        // device id's caps under the detected backend.
        hw_init(
            &mmio,
            features,
            fw_gen,
            mac,
            speed_mask_for(device.id.device, features.backend),
        )?;

        // 7. Program queue 0's rings.
        let tx_phys = tx_ring.dma_addr().raw();
        let rx_phys = rx_ring.dma_addr().raw();
        program_rings(&mmio, tx_phys, rx_phys);

        // 8. Pre-fill RX descriptors 0..RING_LEN-2 (one slot kept
        // empty per the tail invariant), then publish the tail.
        for (i, buf) in rx_pool.iter().enumerate().take(RING_LEN - 1) {
            let buf_phys = buf.dma_addr().raw();
            let d = build_rx_desc(i, buf_phys);
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN - 1.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_phys + (i * 16) as u64)
                        .kernel_mut_ptr::<super::aqc113::RxDesc>(),
                    d,
                );
            }
        }
        compiler_fence(Ordering::SeqCst);
        set_rx_tail(&mmio, (RING_LEN - 1) as u32);

        // 9. Enable the datapath (`aq_vec_start` then
        // `hw_atl_b0_hw_start` / `hw_atl_a0_hw_start`).
        start_hw(&mmio);

        // 10. Link snapshot from the MPI state register.
        let link = read_link_status(&mmio, fw_gen);

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let aqc = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            fw_version,
            fw_gen,
            backend: features.backend,
            link_up: link.carrier,
            link_mbps: if link.carrier { Some(link.mbps) } else { None },
            addr: device.addr,
            detached: AtomicBool::new(false),
            ifname: crate::publish::IfName::new(),
            irq_vector: None,
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn the device's only pump pair — probe spawns none, so the
        // pair fed here is the pair whose halves occupy the ring slots.
        spawn_pumps(aqc.clone(), rx_prod, tx_cons);

        Ok(aqc)
    }

    /// Bring up MSI-X with a single vector wired to MSI-X table
    /// entry 0. After this call, `wait_for_irq(self.irq_vector
    /// .unwrap()).await` resolves on TX/RX writeback interrupts.
    /// The Atlantic interrupt routing (ITR map + IRQ global
    /// control) is already programmed by `bring_up`; this only
    /// brings up the PCI MSI-X table itself.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, NicError> {
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| NicError::MsixSetup)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| NicError::MsixSetup)?;
        let _ = table.alloc_vector().ok_or(NicError::MsixSetup)?;
        // SAFETY: x2APIC is online by Stage-4 boot.
        let target_apic = unsafe { narf_interrupts::current_cpu_target_id() };
        // SAFETY: caller-authority over the device.
        unsafe { table.program_vector(0, target_apic, v) }.map_err(|_| NicError::MsixSetup)?;
        // SAFETY: same.
        unsafe { table.enable() }.map_err(|_| NicError::MsixSetup)?;

        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// This NIC's interface name; empty until probe published it.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }

    /// Transmit a single Ethernet frame. Polled completion: spins
    /// on the slot's descriptor-DD writeback bit until the NIC
    /// sets it. Frames up to the TX slot buffer (16384 bytes) are
    /// accepted; the chip pads frames < 64 bytes itself.
    pub fn transmit(&self, frame: &[u8], meta: &TxMeta) -> Result<(), NicError> {
        let _ = meta;
        if self.detached.load(Ordering::Acquire) {
            return Err(NicError::Other("aqc100 device detached"));
        }
        if frame.is_empty() || frame.len() > TX_BUF_LEN {
            return Err(NicError::FrameTooLong);
        }
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        let ring_phys = self.tx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let d = build_tx_desc(slot, phys, frame.len() as u32);
        // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<super::aqc113::TxDesc>(),
                d,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // Publish the descriptor: tail = next slot to fill.
        *head_g = (*head_g + 1) % (RING_LEN as u32);
        let next_tail = *head_g;
        drop(head_g);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write32(super::aqc113::reg_tx_dma_tail(0), next_tail);
        }
        // Poll the descriptor's DD writeback bit (ctl word at
        // desc + 8). The 250 ms budget mirrors the RTL8125
        // driver's polled-TX budget.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA ring; desc_addr + 8 is the ctl word of the
            // in-bounds descriptor at slot < RING_LEN; volatile read only.
            || unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 8).kernel_ptr::<u32>(),
                )
            } & super::aqc113::TXD_CTL_DD
                != 0,
            narf_time::Deadline::after_ms(250),
        );
        if done {
            Ok(())
        } else {
            Err(NicError::TxTimeout)
        }
    }

    /// Poll one RX descriptor. Returns the frame bytes plus the
    /// checksum verdict, or `None` when no completed frame is
    /// waiting. A completed-but-errored or multi-descriptor frame
    /// is dropped (its descriptor is still refilled).
    ///
    /// B0/B1 use the shared `hw_atl_b0` receive model (DD
    /// completion test, B0 writeback decode). A0 additionally
    /// runs the `hw_atl_a0_hw_ring_rx_receive` errata: the
    /// completion test is `status & 0x5`, a set RX-DMA-status
    /// bit 4 triggers the descriptor-engine reset dance, and
    /// when the head is descriptor 0 with the hardware head
    /// pointer at 2 or more, a completed descriptor 1 stands
    /// in for a descriptor 0 the hardware never completed
    /// (synthesised as `pkt_len` 1514, `status` 3).
    pub fn receive_with_meta(&self) -> Option<(alloc::vec::Vec<u8>, RxCsumResult)> {
        if self.detached.load(Ordering::Acquire) {
            return None;
        }
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let sample_dword = |dword: usize| {
            // SAFETY: identity-mapped DMA ring; `slot < RING_LEN` and
            // `dword < 4`, so the aligned dword lies inside descriptor
            // `slot`.
            u32::from_le(unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(desc_addr + dword as u64 * 4).kernel_ptr::<u32>(),
                )
            })
        };
        let wb = match self.backend {
            Backend::A0 => match sample_a0_wb(sample_dword) {
                Some(wb) => wb,
                None => self.a0_slot0_fallback(slot, desc_addr)?,
            },
            Backend::B0 | Backend::B1 => RxdWb::sample(sample_dword)?,
        };
        let decoded = match self.backend {
            Backend::A0 => decode_rx_wb_a0(&wb, RX_BUF_LEN as u32),
            Backend::B0 | Backend::B1 => decode_rx_wb(&wb, RX_BUF_LEN as u32),
        };
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(decoded.len.min(RX_BUF_LEN));
        if decoded.is_eop && !decoded.error {
            let copy_len = decoded.len.min(RX_BUF_LEN);
            // SAFETY: identity-mapped DMA buffer.
            for i in 0..copy_len {
                // SAFETY: `buf_phys` is the identity-mapped DMA buffer the NIC
                // just filled for this slot; `i < copy_len <= RX_BUF_LEN`, so
                // `buf_phys + i` stays inside the buffer.
                out.push(unsafe {
                    core::ptr::read_volatile(self.rx_pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }

        // Rearm the descriptor: fresh RXD pointing at the same
        // pooled buffer; the writeback is overwritten in place.
        let d = build_rx_desc(slot, buf_phys);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<super::aqc113::RxDesc>(),
                d,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // Advance the tail past the refilled descriptor so the NIC
        // may use it again.
        let next_tail = (slot as u32 + 1) % RING_LEN as u32;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write32(super::aqc113::reg_rx_dma_tail(0), next_tail);
        }

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        if decoded.is_eop && !decoded.error {
            Some((out, decoded.csum))
        } else {
            None
        }
    }

    /// A0 descriptor-0 errata fallback
    /// (`hw_atl_a0_hw_ring_rx_receive`): called when the head
    /// slot shows no completion. When the RX DMA descriptor
    /// status bit 4 is set, reset the descriptor engine
    /// (EN off, reset toggle, EN on). Then, only when the head
    /// is descriptor 0 and the hardware head pointer is at 2
    /// or more, a completed descriptor 1 stands in for the
    /// missing descriptor-0 completion: the returned writeback
    /// carries descriptor 0's `type`/`rss_hash` with
    /// `pkt_len` 1514 and `status` 3, exactly as Linux
    /// synthesises it in place.
    fn a0_slot0_fallback(&self, slot: usize, desc_addr: u64) -> Option<RxdWb> {
        if RegIo::read32(&self.mmio, reg_rx_dma_stat(0)) & RX_DMA_STAT_BIT4 != 0 {
            RegIo::rmw32(&self.mmio, reg_rx_dma_ctl(0), RXD_EN, 0);
            RegIo::rmw32(&self.mmio, reg_rx_dma_ctl(0), RXD_RESET, RXD_RESET);
            RegIo::rmw32(&self.mmio, reg_rx_dma_ctl(0), RXD_RESET, 0);
            RegIo::rmw32(&self.mmio, reg_rx_dma_ctl(0), RXD_EN, RXD_EN);
        }
        if slot != 0 {
            return None;
        }
        let head_ptr = RegIo::read32(&self.mmio, reg_rx_dma_head_ptr(0)) & RX_DMA_HEAD_PTR_MSK;
        if head_ptr < 2 {
            return None;
        }
        // Descriptor 1's writeback: DD set means the hardware
        // moved past descriptor 0 without completing it.
        let desc1_addr = desc_addr + 16;
        // SAFETY: identity-mapped DMA ring; `slot == 0`, so
        // descriptor 1 exists and its dword 2 lies inside it.
        let wb1_status_len = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc1_addr + 8).kernel_ptr::<u32>())
        };
        if wb1_status_len as u16 & RXD_WB_DD == 0 {
            return None;
        }
        // SAFETY: identity-mapped DMA ring; descriptor 0's dword 0
        // lies inside descriptor `slot`.
        let type_ = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        // SAFETY: identity-mapped DMA ring; descriptor 0's dword 1
        // lies inside descriptor `slot`.
        let rss_hash = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 4).kernel_ptr::<u32>())
        };
        Some(RxdWb {
            type_: u32::from_le(type_),
            rss_hash: u32::from_le(rss_hash),
            status: 0x0003,
            pkt_len: 1514,
            next_desc_ptr: 0,
            vlan: 0,
        })
    }

    /// Poll one RX descriptor, discarding the checksum verdict.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        self.receive_with_meta().map(|(pkt, _)| pkt)
    }

    /// Largest frame this driver will transmit: the TX slot buffer
    /// size (Linux's `AQ_CFG_TX_FRAME_MAX`).
    pub fn max_frame(&self) -> u32 {
        TX_BUF_LEN as u32
    }

    /// Current firmware link status (MPI state read).
    pub fn link_status(&self) -> LinkStatus {
        read_link_status(&self.mmio, self.fw_gen)
    }

    /// Refresh the cached link snapshot; returns true when it
    /// changed.
    pub fn refresh_link_state(&mut self) -> bool {
        let link = self.link_status();
        let changed = link.carrier != self.link_up
            || (if link.carrier { Some(link.mbps) } else { None }) != self.link_mbps;
        self.link_up = link.carrier;
        self.link_mbps = if link.carrier { Some(link.mbps) } else { None };
        changed
    }
}

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`aqc100_send_frame`] — the i40e `CONTROLLERS` pattern, so a
/// second AQC port's frames resolve to its own NIC (issue #795).
/// The vec never shrinks: detaches mark the device in place
/// instead of removing its slot, so a live controller's cookie
/// stays valid for the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<Aqc100Nic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// The probed controller at `index`, if it is live (probed and not
/// detached).
fn live_controller(index: usize) -> Option<Arc<Aqc100Nic>> {
    CONTROLLERS
        .lock()
        .get(index)
        .filter(|c| !c.detached.load(Ordering::Acquire))
        .cloned()
}

/// `SendCtxFn` registered with `narf_net::iface` at probe time.
fn aqc100_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = live_controller(cookie as usize).ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // A second probe of the SAME live function is a no-op success;
    // a second FUNCTION binds as a new instance instead of being
    // dropped (issue #795). A detached entry does not block a
    // re-probe of its address.
    if CONTROLLERS
        .lock()
        .iter()
        .any(|c| c.addr == device.addr && !c.detached.load(Ordering::Acquire))
    {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER are both required: the chip DMAs the
    // descriptor rings + frame buffers, and we map BAR0 as MMIO.
    // INTX_DISABLE silences the legacy line so MSI-X can take over
    // cleanly later.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe holds exclusive authority over `device` and its cfg `cap`
    // for the duration of `bring_up`, satisfying its `# Safety` contract.
    let dev = match unsafe { Aqc100Nic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    // Retain before any ring DMA address reaches the device; the
    // index is this instance's send-path cookie (see `CONTROLLERS`).
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(dev.clone());
        g.len() - 1
    };

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Publish to the kernel-side stack (issue #784): a dynamic `eth%d`
    // name + carrier metadata via the shared helper.
    let mac = dev.mac;
    let status = dev.link_status();
    let name = crate::publish::publish_netdev_with_context(
        mac,
        index as u64,
        aqc100_send_frame,
        link_sample(status),
    );
    dev.ifname.set(name);

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Aqc100NicAdapter { nic: dev.clone() });
    }

    // No pump spawn here: `bring_up` spawned the device's single RX/TX
    // pump pair, fed by the channel pair whose halves occupy the
    // `rx_ipc_ring`/`tx_ipc_ring` slots.

    Ok(())
}

fn spawn_pumps(
    device: Arc<Aqc100Nic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        aqc100_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        aqc100_tx_pump(d2, tx_cons).await;
    });
}

async fn aqc100_rx_pump(device: Arc<Aqc100Nic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Carrier refresh (issue #791): the production datapath is polled
    // (probe never enables MSI-X, so the writeback-interrupt bits have
    // no consumer), which makes this pump the family's link observer.
    let mut last_sample = link_sample(device.link_status());
    loop {
        let sample = link_sample(device.link_status());
        if sample != last_sample {
            last_sample = sample;
            crate::publish::publish_link(device.ifname(), sample);
        }
        if let Some((pkt, csum)) = device.receive_with_meta() {
            let dma_buf =
                alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
            // RX checksum verification from the descriptor: only
            // `Ok` marks the checksums verified; `Fail` and `None`
            // both leave the flags clear so the stack re-checks.
            let mut rx_meta = narf_net::RxMeta::default();
            if csum == RxCsumResult::Ok {
                rx_meta.csum_l3 = true;
                rx_meta.csum_l4 = true;
            }
            frame.set_rx_meta(rx_meta);
            let name = device.ifname();
            crate::publish::dispatch_rx(
                name,
                &mut frame,
                crate::publish::rx_mirror_attached(name),
                |mirror| {
                    let _ = rx_prod.try_send(mirror);
                },
            );
        }
        narf_scheduler::yield_now().await;
    }
}

async fn aqc100_tx_pump(device: Arc<Aqc100Nic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
    }
}

/// Register a PCI match-table entry per supported device id. Linux
/// keeps the IDs distinct across the AQC100 family and the
/// D-series even though the register model is shared (modulo the
/// A0/B0/B1 backend selected at runtime); we register all
/// seventeen.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: AQC_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Frame-ring / `Interface` adapter for one probed AQC100-family
/// NIC. The rings are borrowed from the NIC's own
/// `rx_ipc_ring` / `tx_ipc_ring` fields.
#[derive(Debug)]
pub struct Aqc100NicAdapter {
    nic: Arc<Aqc100Nic>,
}

impl narf_net::Interface for Aqc100NicAdapter {
    fn name(&self) -> &str {
        self.nic.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        // Probe-time value, gated on detach: a detached device
        // reports down so the stack stops routing at it.
        self.nic.link_up && !self.nic.detached.load(Ordering::Acquire)
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        // Stage 2: plain frames only — no checksum offload, no TSO,
        // no VLAN insertion.
        narf_net::OffloadCapabilities {
            tx_checksum: false,
            rx_checksum: false,
            max_tso_bytes: 0,
            vlan_insert: false,
        }
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        crate::publish::note_rx_mirror_attached(self.nic.ifname());
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

impl crate::HwNic for Aqc100NicAdapter {
    fn name(&self) -> &'static str {
        self.nic.ifname()
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.nic.link_up && !self.nic.detached.load(Ordering::Acquire)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::MarvellAqc100
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        RING_LEN
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}

/// Detach the bound aqc100 device at `index`, if any: device half
/// (set the datapath gate, so `transmit` / `receive_with_meta`
/// fail fast and the parked pumps stop touching the rings), then
/// the registry half the net spec §3 obliges — publish link down,
/// clear the RX-mirror attach note for the interface name, and
/// unregister the interface. Idempotent. The `CONTROLLERS` slot
/// is kept so other controllers' cookies stay valid. (No
/// `device_pm` withdrawal: this family never registered
/// `DevicePmOps` — it has no suspend/resume path yet.)
pub fn aqc100_detach(index: usize) {
    let Some(device) = CONTROLLERS.lock().get(index).cloned() else {
        return;
    };
    if device.detached.load(Ordering::Acquire) {
        return;
    }
    device.detached.store(true, Ordering::Release);
    let name = device.ifname();
    crate::publish::publish_link(name, crate::publish::LinkSample::DOWN);
    crate::publish::clear_rx_mirror_attached(name);
    let _ = narf_net::iface::unregister(name);
}

/// `true` once at least one controller has been probed and not
/// detached.
pub fn is_probed() -> bool {
    CONTROLLERS
        .lock()
        .iter()
        .any(|c| !c.detached.load(Ordering::Acquire))
}

/// Number of live controllers. The index of a controller in
/// `CONTROLLERS` is its send-path cookie; the vec never shrinks, so
/// a live controller's cookie is stable for the kernel lifetime.
pub fn instance_count() -> usize {
    CONTROLLERS
        .lock()
        .iter()
        .filter(|c| !c.detached.load(Ordering::Acquire))
        .count()
}

/// Clone the controller handle at `index`, holding `CONTROLLERS`
/// only for the refcount bump. Returns `None` for an out-of-range
/// index or a detached device.
pub fn controller(index: usize) -> Option<Arc<Aqc100Nic>> {
    live_controller(index)
}

/// Test-side accessor: run `f` against the live probed controller
/// at `index` (i40e shape).
pub fn with_controller<R>(index: usize, f: impl FnOnce(&Aqc100Nic) -> R) -> Option<R> {
    live_controller(index).map(|a| f(&a))
}

/// Mutable accessor — used by tests that want to switch on MSI-X
/// after probe.
pub fn with_controller_mut<R>(index: usize, f: impl FnOnce(&mut Aqc100Nic) -> R) -> Option<R> {
    CONTROLLERS
        .lock()
        .get_mut(index)
        .map(|a| f(Arc::get_mut(a).expect("Aqc100Nic static has multiple owners")))
}
