//! Aquantia/Marvell AQC113 (Atlantic `hw_atl2`) 2.5–10 GbE driver —
//! Stage-2 cut: probe + firmware-boot handshake + TX/RX rings + one
//! MSI-X vector + publication + carrier, fixture-validated against a
//! simulated device conversation.
//!
//! ## Reference
//!
//! Linux `drivers/net/ethernet/aquantia/atlantic/` (GPL-2.0;
//! NARF is GPL-2.0-or-later since 2026-05-20 so adaptation is
//! permitted), reference tree `~/workspace/scratch/ethernet/linux2`
//! @ `cbbddb6`:
//!
//! - `atlantic/aq_common.h` — PCI IDs (`PCI_VENDOR_ID_AQUANTIA`
//!   `0x1D6A`, `AQ_DEVICE_ID_AQC113*`), `AQ_NIC_RATE_*` bits.
//! - `atlantic/aq_pci_func.c` — `aq_pci_tbl`, `hw_atl_boards`
//!   (AQC113 family → `hw_atl2_ops` / `hw_atl2_caps_aqc113`),
//!   first-MEM-BAR scan for the register window.
//! - `atlantic/hw_atl2/hw_atl2_utils.c` —
//!   `hw_atl2_utils_soft_reset` (MIF boot handshake) and the
//!   `hw_atl2_utils_hw_mac_regs` list.
//! - `atlantic/hw_atl2/hw_atl2_utils_fw.c` — shared-buffer mailbox
//!   (`fw_interface_in` / `fw_interface_out`), `aq_a2_fw_init`
//!   (link_control ACTIVE, MTU = `HW_ATL2_MTU_JUMBO`), `aq_a2_fw_*`
//!   link-speed / MAC / link-status helpers, `a2_link_speed_mask2fw`.
//! - `atlantic/hw_atl2/hw_atl2_utils.h` — `link_status_s`,
//!   `filter_caps_s`, `fw_interface_in` / `fw_interface_out`
//!   layout, `AQ_A2_FW_LINK_RATE_*`.
//! - `atlantic/hw_atl2/hw_atl2.c` — `hw_atl2_hw_init` (TX/RX path,
//!   MAC filter, MPI_INIT, IRQ global control),
//!   `hw_atl2_caps_aqc113` (10G/5G/2.5G/1G/100M/10M),
//!   `hw_atl2_caps_aqc115c` (2.5G max), `hw_atl2_caps_aqc116c`
//!   (1G max).
//! - `atlantic/hw_atl/hw_atl_b0.c` — ring init/start, TX xmit, RX
//!   receive/fill (reused verbatim by `hw_atl2`).
//! - `atlantic/hw_atl/hw_atl_utils.h` — `hw_atl_txd_s` /
//!   `hw_atl_rxd_s` / `hw_atl_rxd_wb_s` descriptor structs.
//! - `atlantic/hw_atl/hw_atl_llh_internal.h` and
//!   `atlantic/hw_atl2/hw_atl2_llh_internal.h` — register
//!   addresses and bitfields.
//! - `atlantic/aq_cfg.h` — defaults (TXDS 4096, RXDS 2048,
//!   MTU 1514, TX frame max 16 KiB, RX frame max 2 KiB,
//!   `AQ_CFG_IRQ_MASK 0x3FF`).
//!
//! ## Deliberate asymmetries (Stage 2)
//!
//! - Single queue pair (queue 0) + one MSI-X vector; Linux defaults
//!   to 8 vectors / 4 TX + 4 RX rings. RSS stays off (no RSS hash
//!   type / redirection programming).
//! - RX VLAN stripping stays OFF (no VLAN-tag field in
//!   `Frame::rx_meta`); TX VLAN insertion is not programmed.
//! - No TX/RX checksum offload or TSO/LSO yet (the TX context
//!   descriptor exists in the spec; the datapath uses plain frames).
//! - `downshift` is 0 (disabled) in the firmware `link_options`;
//!   Linux programs a downshift counter from its netdev config.
//! - TC/QoS programming (TX/RX TC mode, queue-to-TC map, TPS
//!   scheduler credits), RX flow-control mode and the RPF RSS
//!   control block are deferred — they do not gate single-queue
//!   TX/RX on TC0 under reset defaults.
//! - The driver maps BAR0; Linux scans BARs 0..3 for the first MEM
//!   BAR. BAR0 is the MMIO BAR on AQC113 hardware.
//! - TX completion is the descriptor-DD writeback poll (Atlantic
//!   has no OWN bit); the polled `transmit` waits for DD with a
//!   250 ms deadline, mirroring the RTL8125 driver's poll budget.
//! - RX buffers are 2048 bytes (Linux's `AQ_CFG_RX_FRAME_MAX`); a
//!   frame larger than one buffer spans descriptors and is dropped
//!   (multi-descriptor RX chaining is a remainder).
//! - The firmware lives in the device's own flash: no blob is
//!   loaded by the driver. `soft_reset` reboots the on-chip
//!   firmware through the MIF boot register and waits for its
//!   boot-complete status, exactly as Linux does.

#![allow(dead_code)]

mod tests;

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Aquantia / Marvell (`PCI_VENDOR_ID_AQUANTIA`).
pub const AQC_VENDOR: u16 = 0x1D6A;
/// AQC113DEV — development silicon (`AQ_DEVICE_ID_AQC113DEV`).
pub const AQC_DEV_113DEV: u16 = 0x00C0;
/// AQC113 — the common 10 GbE part (`AQ_DEVICE_ID_AQC113`).
pub const AQC_DEV_113: u16 = 0x04C0;
/// AQC116C — 1 GbE-max cost part (`AQ_DEVICE_ID_AQC116C`).
pub const AQC_DEV_116C: u16 = 0x11C0;
/// AQC115C — 2.5 GbE-max cost part (`AQ_DEVICE_ID_AQC115C`).
pub const AQC_DEV_115C: u16 = 0x12C0;
/// AQC113C (`AQ_DEVICE_ID_AQC113C`).
pub const AQC_DEV_113C: u16 = 0x14C0;
/// AQC113CA (`AQ_DEVICE_ID_AQC113CA`).
pub const AQC_DEV_113CA: u16 = 0x34C0;
/// AQC114CS (`AQ_DEVICE_ID_AQC114CS`).
pub const AQC_DEV_114CS: u16 = 0x93C0;
/// AQC113CS (`AQ_DEVICE_ID_AQC113CS`).
pub const AQC_DEV_113CS: u16 = 0x94C0;

const ALL_DEV_IDS: &[u16] = &[
    AQC_DEV_113DEV,
    AQC_DEV_113,
    AQC_DEV_116C,
    AQC_DEV_115C,
    AQC_DEV_113C,
    AQC_DEV_113CA,
    AQC_DEV_114CS,
    AQC_DEV_113CS,
];

/// Human-readable name for a known device id; `"aqc113"` falls back
/// for anything not on the match table.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        AQC_DEV_113DEV => "aqc113dev",
        AQC_DEV_113 => "aqc113",
        AQC_DEV_116C => "aqc116c",
        AQC_DEV_115C => "aqc115c",
        AQC_DEV_113C => "aqc113c",
        AQC_DEV_113CA => "aqc113ca",
        AQC_DEV_114CS => "aqc114cs",
        AQC_DEV_113CS => "aqc113cs",
        _ => "aqc113",
    }
}

// `AQ_NIC_RATE_*` link-speed mask bits (`aq_common.h`).
pub(crate) const RATE_10G: u32 = 1 << 0;
pub(crate) const RATE_5G: u32 = 1 << 1;
pub(crate) const RATE_2G5: u32 = 1 << 2;
pub(crate) const RATE_1G: u32 = 1 << 3;
pub(crate) const RATE_100M: u32 = 1 << 4;
pub(crate) const RATE_10M: u32 = 1 << 5;

/// Advertised link-speed mask for a device id, per
/// `hw_atl2_caps_aqc113` / `hw_atl2_caps_aqc115c` /
/// `hw_atl2_caps_aqc116c` in `hw_atl2.c`.
pub const fn speed_mask_for(did: u16) -> u32 {
    match did {
        AQC_DEV_115C => RATE_2G5 | RATE_1G | RATE_100M | RATE_10M,
        AQC_DEV_116C => RATE_1G | RATE_100M | RATE_10M,
        _ => RATE_10G | RATE_5G | RATE_2G5 | RATE_1G | RATE_100M | RATE_10M,
    }
}

// ── Register offsets (BAR0, MMIO) ───────────────────────────────────
// Addresses from `hw_atl_llh_internal.h` / `hw_atl2_llh_internal.h`
// (generated from the Atlantic datasheet). Per-queue strides:
// TX DMA 0x40, RX DMA 0x20, RPF L2 unicast filter 0x8.

/// MIF boot register (`HW_ATL2_MIF_BOOT_REG_ADR`).
pub(crate) const REG_MIF_BOOT: u64 = 0x3040;
/// MIF host-request interrupt status (`HW_ATL2_MCP_HOST_REQ_INT_ADR`).
pub(crate) const REG_MIF_HOST_REQ_INT: u64 = 0x0F00;
/// MIF host-request interrupt clear (`HW_ATL2_MCP_HOST_REQ_INT_CLR_ADR`).
pub(crate) const REG_MIF_HOST_REQ_INT_CLR: u64 = 0x0F08;
/// MIF shared-buffer IN base, host → firmware
/// (`HW_ATL2_MIF_SHARED_BUFFER_IN_ADR`).
pub(crate) const REG_MIF_SHARED_IN: u64 = 0x12000;
/// MIF shared-buffer OUT base, firmware → host
/// (`HW_ATL2_MIF_SHARED_BUFFER_OUT_ADR`).
pub(crate) const REG_MIF_SHARED_OUT: u64 = 0x13000;
/// Host-finished-write handshake bit (`HW_ATL2_MIF_HOST_FINISHED_WRITE_ADR`).
pub(crate) const REG_MIF_HOST_FINISHED_WRITE: u64 = 0x0E00;
/// MCP-finished-read handshake bit (`HW_ATL2_MIF_MCP_FINISHED_READ_ADR`).
pub(crate) const REG_MIF_MCP_FINISHED_READ: u64 = 0x0E04;
/// Global CPU semaphore base (`HW_ATL_GLB_CPU_SEM_ADR(sem)`).
pub(crate) const REG_GLB_CPU_SEM_BASE: u64 = 0x03A0;
/// Alive-check / flush read address (`hw_alive_check_addr`, also
/// `HW_ATL_B0_FLUSH`).
pub(crate) const REG_ALIVE_CHECK: u64 = 0x0010;

/// TX DMA descriptor base LSW (`HW_ATL_TX_DMA_DESC_BASE_ADDRLSW_ADR(q)`).
pub(crate) const fn reg_tx_dma_base_lsw(q: u64) -> u64 {
    0x7C00 + q * 0x40
}
/// TX DMA descriptor base MSW (`HW_ATL_TX_DMA_DESC_BASE_ADDRMSW_ADR(q)`).
pub(crate) const fn reg_tx_dma_base_msw(q: u64) -> u64 {
    0x7C04 + q * 0x40
}
/// TX DMA descriptor control — EN (bit 31) + LEN (bits [12:3])
/// (`HW_ATL_TDM_DESCDEN_ADR` / `HW_ATL_TDM_DESCDLEN_ADR`).
pub(crate) const fn reg_tx_dma_ctl(q: u64) -> u64 {
    0x7C08 + q * 0x40
}
/// TX DMA descriptor head pointer (`HW_ATL_TDM_DESCDHD_ADR(q)`).
pub(crate) const fn reg_tx_dma_head(q: u64) -> u64 {
    0x7C0C + q * 0x40
}
/// TX DMA descriptor tail pointer (`HW_ATL_TX_DMA_DESC_TAIL_PTR_ADR(q)`).
pub(crate) const fn reg_tx_dma_tail(q: u64) -> u64 {
    0x7C10 + q * 0x40
}
/// TX DMA descriptor writeback threshold (`HW_ATL_TDM_DESCDWRB_THRESH_ADR(q)`).
pub(crate) const fn reg_tx_dma_wrb_thresh(q: u64) -> u64 {
    0x7C18 + q * 0x40
}
/// TX descriptor writeback IRQ enable (`HW_ATL_TDM_INT_DESC_WRB_EN_ADR`,
/// bit 1).
pub(crate) const REG_TDM_INT_DESC_WRB_EN: u64 = 0x7B40;
/// RX DMA descriptor base LSW (`HW_ATL_RX_DMA_DESC_BASE_ADDRLSW_ADR(q)`).
pub(crate) const fn reg_rx_dma_base_lsw(q: u64) -> u64 {
    0x5B00 + q * 0x20
}
/// RX DMA descriptor base MSW (`HW_ATL_RX_DMA_DESC_BASE_ADDRMSW_ADR(q)`).
pub(crate) const fn reg_rx_dma_base_msw(q: u64) -> u64 {
    0x5B04 + q * 0x20
}
/// RX DMA descriptor control — EN (bit 31) + LEN (bits [12:3]) +
/// header-split (bit 28) + VLAN-strip (bit 29)
/// (`HW_ATL_RDM_DESCDEN_ADR` / `HW_ATL_RDM_DESCDLEN_ADR` /
/// `HW_ATL_RDM_DESCDHDR_SPLIT_ADR` / `HW_ATL_RPO_DESCDVL_STRIP_ADR`).
pub(crate) const fn reg_rx_dma_ctl(q: u64) -> u64 {
    0x5B08 + q * 0x20
}
/// RX DMA descriptor tail pointer (`HW_ATL_RX_DMA_DESC_TAIL_PTR_ADR(q)`).
pub(crate) const fn reg_rx_dma_tail(q: u64) -> u64 {
    0x5B10 + q * 0x20
}
/// RX DMA descriptor status (`HW_ATL_RX_DMA_DESC_STAT_ADR(q)`).
/// Not polled by this driver (the RX writeback DD bit is the
/// completion signal, as in Linux's `hw_atl_b0_hw_ring_rx_receive`).
pub(crate) const fn reg_rx_dma_stat(q: u64) -> u64 {
    0x5B14 + q * 0x20
}
/// RX DMA descriptor buffer sizes — data size (bits [4:0], units of
/// 1 KiB) + header size (bits [12:8])
/// (`HW_ATL_RDM_DESCDDATA_SIZE_ADR` / `HW_ATL_RDM_DESCDHDR_SIZE_ADR`).
pub(crate) const fn reg_rx_dma_buf_size(q: u64) -> u64 {
    0x5B18 + q * 0x20
}
/// RX descriptor writeback IRQ enable (`HW_ATL_RDM_INT_DESC_WRB_EN_ADR`,
/// bit 2).
pub(crate) const REG_RDM_INT_DESC_WRB_EN: u64 = 0x5A30;
/// TX packet-buffer enable, bit 0 (`HW_ATL_TPB_TX_BUF_EN_ADR`).
/// Bit 5 of the same register is the TX buffer clock-gate enable.
pub(crate) const REG_TPB_TX_BUF: u64 = 0x7900;
/// RX packet-buffer enable, bit 0 (`HW_ATL_RPB_RX_BUF_EN_ADR`).
pub(crate) const REG_RPB_RX_BUF: u64 = 0x5700;
/// IRQ global control (`HW_ATL_INTR_GLB_CTL_ADR`).
pub(crate) const REG_IRQ_GLB_CTL: u64 = 0x2300;
/// IRQ auto-mask LSW (`HW_ATL_ITR_IAMRLSW_ADR`).
pub(crate) const REG_ITR_IAMRLSW: u64 = 0x2090;
/// General IRQ map base (`HW_ATL_GEN_INTR_MAP_ADR(idx)`).
pub(crate) const REG_GEN_IRQ_MAP_BASE: u64 = 0x2180;
/// ITR IRQ map register for a queue pair
/// (`itr_imr_txt_adr` / `itr_imr_rxr_adr`: `0x2100 + (q/2)*4`).
pub(crate) const fn reg_itr_map(q: u64) -> u64 {
    0x2100 + (q / 2) * 4
}
/// RPF L2 unicast filter destination-address LSW
/// (`HW_ATL_RPFL2UC_DAFLSW_ADR(f)`).
pub(crate) const fn reg_rpf_uc_daflsw(f: u64) -> u64 {
    0x5110 + f * 0x8
}
/// RPF L2 unicast filter control — DAFMSW (bits [15:0]) + action
/// (bits [18:16]) + tag (bits [27:22]) + enable (bit 31)
/// (`HW_ATL_RPFL2UC_DAFMSW_ADR` / `HW_ATL_RPFL2UC_ACTF_ADR` /
/// `HW_ATL2_RPFL2UC_TAG_ADR` / `HW_ATL_RPFL2UC_ENF_ADR`).
pub(crate) const fn reg_rpf_uc_ctl(f: u64) -> u64 {
    0x5114 + f * 0x8
}
/// RPF multicast filter mask (`HW_ATL_RX_FLR_MCST_FLR_MSK_ADR`).
pub(crate) const REG_RPF_MCST_MSK: u64 = 0x5270;
/// RPF multicast filter base (`HW_ATL_RX_FLR_MCST_FLR_ADR(f)`).
pub(crate) const REG_RPF_MCST_FLR_BASE: u64 = 0x5250;
/// RPF VLAN TPID register — inner (bits [15:0], default `0x8100`)
/// + outer (bits [31:16], default `0x88A8`)
///   (`HW_ATL_RPF_VL_INNER_TPID_ADR` / `HW_ATL_RPF_VL_OUTER_TPID_ADR`).
pub(crate) const REG_RPF_VLAN_TPID: u64 = 0x5284;
/// RPF VLAN control — promiscuous mode (bit 1) + accept-untagged
/// (bit 2) + untagged action (bits [5:3])
/// (`HW_ATL_RPF_VL_PROMIS_MODE_ADR` /
/// `HW_ATL_RPF_VL_ACCEPT_UNTAGGED_MODE_ADR` /
/// `HW_ATL_RPF_VL_UNTAGGED_ACT_ADR`).
pub(crate) const REG_RPF_VLAN_CTL: u64 = 0x5280;
/// RPF broadcast filter — threshold (bits [31:16]) + action
/// (bits [14:12]) (`HW_ATL_RPFL2BC_THRESH_ADR` /
/// `HW_ATL_RPFL2BC_ACT_ADR`).
pub(crate) const REG_RPF_BC: u64 = 0x5100;
/// RPF new-filter enable, bit 11 (`HW_ATL2_RPF_NEW_EN_ADR`).
pub(crate) const REG_RPF_NEW_EN: u64 = 0x5104;

// ── Register bitfields ──────────────────────────────────────────────

// MIF boot register bits (`hw_atl2_utils.c`).
pub(crate) const MIF_BOOT_REQ_REBOOT: u32 = 1 << 0;
pub(crate) const MIF_BOOT_STARTED: u32 = 1 << 24;
pub(crate) const MIF_BOOT_CRASH_INIT: u32 = 1 << 27;
pub(crate) const MIF_BOOT_CODE_FAILED: u32 = 1 << 28;
pub(crate) const MIF_BOOT_FW_INIT_FAILED: u32 = 1 << 29;
pub(crate) const MIF_BOOT_FW_INIT_COMP_SUCCESS: u32 = 1 << 31;
pub(crate) const MIF_BOOT_FAILED_MASK: u32 =
    MIF_BOOT_CRASH_INIT | MIF_BOOT_CODE_FAILED | MIF_BOOT_FW_INIT_FAILED;
pub(crate) const MIF_BOOT_COMPLETE_MASK: u32 = MIF_BOOT_FAILED_MASK | MIF_BOOT_FW_INIT_COMP_SUCCESS;
/// Host-request-interrupt READY bit (`HW_ATL2_MCP_HOST_REQ_INT_READY`).
pub(crate) const MIF_HOST_REQ_READY: u32 = 1 << 0;

// Descriptor-control fields (`HW_ATL_TDM_DESCDEN` / `HW_ATL_TDM_DESCDLEN`).
pub(crate) const DESC_EN: u32 = 1 << 31;
pub(crate) const DESC_LEN_MSK: u32 = 0x0000_1FF8;
pub(crate) const DESC_LEN_SHIFT: u32 = 3;
/// RX descriptor header-split bit (`HW_ATL_RDM_DESCDHDR_SPLIT_MSK`).
pub(crate) const RXD_HDR_SPLIT: u32 = 1 << 28;
/// RX descriptor VLAN-strip bit (`HW_ATL_RPO_DESCDVL_STRIP_MSK`).
pub(crate) const RXD_VL_STRIP: u32 = 1 << 29;
/// TX descriptor writeback-IRQ-enable bit (`HW_ATL_TDM_INT_DESC_WRB_EN_MSK`).
pub(crate) const TDM_WRB_IRQ_EN: u32 = 1 << 1;
/// RX descriptor writeback-IRQ-enable bit (`HW_ATL_RDM_INT_DESC_WRB_EN_MSK`).
pub(crate) const RDM_WRB_IRQ_EN: u32 = 1 << 2;
/// TX packet-buffer enable bit (`HW_ATL_TPB_TX_BUF_EN_MSK`).
pub(crate) const TPB_TX_BUF_EN: u32 = 1 << 0;
/// TX packet-buffer clock-gate enable bit
/// (`HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_MSK`).
pub(crate) const TPB_TX_BUF_CLK_GATE_EN: u32 = 1 << 5;
/// RX packet-buffer enable bit (`HW_ATL_RPB_RX_BUF_EN_MSK`).
pub(crate) const RPB_RX_BUF_EN: u32 = 1 << 0;
/// RPF new-filter enable bit (`HW_ATL2_RPF_NEW_EN_MSK`).
pub(crate) const RPF_NEW_EN: u32 = 1 << 11;
/// RPF VLAN promiscuous-mode bit (`HW_ATL_RPF_VL_PROMIS_MODE_MSK`).
pub(crate) const RPF_VL_PROMIS_MODE: u32 = 1 << 1;
/// RPF VLAN accept-untagged bit
/// (`HW_ATL_RPF_VL_ACCEPT_UNTAGGED_MODE_MSK`).
pub(crate) const RPF_VL_ACCEPT_UNTAGGED: u32 = 1 << 2;
/// RPF VLAN untagged-action field (bits [5:3],
/// `HW_ATL_RPF_VL_UNTAGGED_ACT_MSK`).
pub(crate) const RPF_VL_UNTAGGED_ACT_MSK: u32 = 0x38;
pub(crate) const RPF_VL_UNTAGGED_ACT_SHIFT: u32 = 3;
/// RPF broadcast-filter action field (bits [14:12],
/// `HW_ATL_RPFL2BC_ACT_MSK`).
pub(crate) const RPF_BC_ACT_MSK: u32 = 0x7000;
pub(crate) const RPF_BC_ACT_SHIFT: u32 = 12;
/// RPF broadcast-filter threshold field (bits [31:16],
/// `HW_ATL_RPFL2BC_THRESH_MSK`).
pub(crate) const RPF_BC_THRESH_MSK: u32 = 0xFFFF_0000;
pub(crate) const RPF_BC_THRESH_SHIFT: u32 = 16;
/// RPF L2 unicast-filter enable bit (`HW_ATL_RPFL2UC_ENF_MSK`).
pub(crate) const RPF_UC_EN: u32 = 1 << 31;
/// RPF L2 unicast-filter destination-MSW field (bits [15:0],
/// `HW_ATL_RPFL2UC_DAFMSW_MSK`).
pub(crate) const RPF_UC_DAFMSW_MSK: u32 = 0xFFFF;
/// RPF L2 unicast-filter action field (bits [18:16],
/// `HW_ATL_RPFL2UC_ACTF_MSK`).
pub(crate) const RPF_UC_ACT_MSK: u32 = 0x70000;
pub(crate) const RPF_UC_ACT_SHIFT: u32 = 16;
/// RPF L2 unicast-filter tag field (bits [27:22],
/// `HW_ATL2_RPFL2UC_TAG_MSK`).
pub(crate) const RPF_UC_TAG_MSK: u32 = 0x0FC0_0000;
pub(crate) const RPF_UC_TAG_SHIFT: u32 = 22;
/// L2 filter action: deliver to host (`L2_FILTER_ACTION_HOST`).
pub(crate) const L2_ACT_HOST: u32 = 1;
/// RPF unicast tag base (`HW_ATL2_RPF_TAG_BASE_UC` =
/// `BIT(HW_ATL2_RPF_TAG_UC_OFFSET)` with offset 0).
pub(crate) const RPF_TAG_BASE_UC: u32 = 1;
/// Multicast "any to host" filter value
/// (`HW_ATL_MCAST_FLT_ANY_TO_HOST`).
pub(crate) const MCST_FLT_ANY_TO_HOST: u32 = 0x0001_0FFF;
/// Broadcast-filter threshold Linux programs
/// (`0xFFFFU & (~0U / 256U)` in `hw_atl2_hw_init_rx_path`).
pub(crate) const RPF_BC_THRESH: u32 = 0xFFFF;
/// IRQ global-control value for MSI-X, single vector
/// (`aq_hw_atl2_igcr_table_[AQ_HW_IRQ_MSIX][0]` in `hw_atl2_hw_init`).
pub(crate) const IRQ_GLB_CTL_MSIX_1VEC: u32 = 0x2000_0022;
/// IRQ auto-mask value for the AQC113 caps (`irq_mask = ~0U` in
/// `DEFAULT_BOARD_BASIC_CAPABILITIES`).
pub(crate) const IRQ_AUTO_MASK: u32 = 0xFFFF_FFFF;
/// General IRQ map 0 value (`hw_atl2_hw_init`: error interrupt 8
/// mapped to vectors 31/23).
pub(crate) const GEN_IRQ_MAP0: u32 = (8 << 24) | (1 << 31) | (8 << 16) | (1 << 23);
/// Error interrupt index (`HW_ATL2_ERR_INT`).
pub(crate) const ERR_INT: u32 = 8;

// ── Firmware shared-buffer layout ───────────────────────────────────
// `fw_interface_in` (host → firmware, `REG_MIF_SHARED_IN`) and
// `fw_interface_out` (firmware → host, `REG_MIF_SHARED_OUT`) in
// `hw_atl2_utils.h`. Offsets are in 32-bit dwords; every field is
// 4-byte aligned (the Linux shared-buffer macros `BUILD_BUG_ON`
// on unaligned accesses).

/// IN dword 0: MTU. Linux's `aq_a2_fw_init` writes
/// `HW_ATL2_MTU_JUMBO` (16352) here.
pub(crate) const SH_IN_MTU_DWORD: u64 = 0;
/// IN dwords 2–3: permanent MAC address
/// (`mac_address_aligned_s`: 6 MAC bytes + 2 reserved).
pub(crate) const SH_IN_MAC_DWORD: u64 = 2;
/// IN dword 4: link control (`link_control_s`; mode in bits [3:0]).
pub(crate) const SH_IN_LINK_CONTROL_DWORD: u64 = 4;
/// IN dword 6: link options (`link_options_s`).
pub(crate) const SH_IN_LINK_OPTIONS_DWORD: u64 = 6;
/// OUT dword 0: transaction counter (`transaction_counter_s`:
/// `cnt_a` low 16 bits, `cnt_b` high 16 bits).
pub(crate) const SH_OUT_TRANSACTION_DWORD: u64 = 0;
/// OUT dwords 1–4: firmware version (`version_s`: bundle 4 B,
/// MAC 4 B, PHY 4 B, iface 4 B).
pub(crate) const SH_OUT_VERSION_DWORD: u64 = 1;
/// OUT dword 5: link status (`link_status_s`).
pub(crate) const SH_OUT_LINK_STATUS_DWORD: u64 = 5;
/// OUT dwords 477–479: filter capabilities (`filter_caps_s`).
/// Computed from the `fw_interface_out` field order in
/// `hw_atl2_utils.h`: transaction(1) + version(4) + link_status(1)
/// + wol_status(380) + rsvd(1) + rsvd2(1) + mac_health(2) +
///   rsvd3(1) + rsvd4(1) + phy_health(2) + rsvd5(1) + rsvd6(1) +
///   cable_diag(5) + rsvd7(1) + device_link_caps(1) + rsvd8(1) +
///   sleep_proxy_caps(3) + rsvd9(1) + lkp_link_caps(1) + rsvd10(1) +
///   core_dump(37) + rsvd11(1) + statistics(29) = 477.
pub(crate) const SH_OUT_FILTER_CAPS_DWORD: u64 = 477;

/// Host mode ACTIVE (`AQ_HOST_MODE_ACTIVE`).
pub(crate) const HOST_MODE_ACTIVE: u32 = 1;
/// Firmware MTU (`HW_ATL2_MTU_JUMBO`).
pub(crate) const FW_MTU_JUMBO: u32 = 16352;
/// Maximum L2 unicast filters (`HW_ATL2_MAC_MAX`).
pub(crate) const MAC_FILTER_MAX: u32 = 38;

// ── Ring sizing ─────────────────────────────────────────────────────

/// Descriptors per ring. Linux defaults to TXDS 4096 / RXDS 2048
/// (`AQ_CFG_TXDS_DEF` / `AQ_CFG_RXDS_DEF`); NARF family drivers use
/// 256-slot rings. 256 ≥ `HW_ATL2_MIN_RXD`/`HW_ATL2_MIN_TXD`
/// (`ALIGN(AQ_CFG_SKB_FRAGS_MAX + 1, 8)` = 40) and ≤
/// `HW_ATL2_MAX_RXD`/`HW_ATL2_MAX_TXD` (8184).
pub const RING_LEN: usize = 256;
/// Ring allocation size in bytes (16-byte descriptors).
pub const RING_BYTES: usize = RING_LEN * 16;
/// TX slot buffer size (`AQ_CFG_TX_FRAME_MAX`, 16 KiB).
pub const TX_BUF_LEN: usize = 16384;
/// RX slot buffer size (`AQ_CFG_RX_FRAME_MAX`, 2 KiB).
pub const RX_BUF_LEN: usize = 2048;

// ── Firmware mailbox decode (pure) ──────────────────────────────────

/// Decoded permanent MAC from the shared IN buffer's MAC dwords
/// (`aq_a2_fw_get_mac_permanent` reads `mac_address` from
/// `fw_interface_in`). `dwords[0]` holds MAC bytes 0..3 (LE),
/// `dwords[1]` holds bytes 4..5 (LE) + 2 reserved bytes.
pub fn decode_mac_from_shared(dwords: &[u32; 2]) -> Option<[u8; 6]> {
    let b0 = dwords[0].to_le_bytes();
    let b1 = dwords[1].to_le_bytes();
    Some([b0[0], b0[1], b0[2], b0[3], b1[0], b1[1]])
}

/// `true` iff the MAC reads as either all-zero (no firmware image)
/// or all-FF (controller floor / disconnected).
pub const fn mac_is_invalid(mac: [u8; 6]) -> bool {
    let mut all_zero = true;
    let mut all_ff = true;
    let mut i = 0;
    while i < 6 {
        if mac[i] != 0x00 {
            all_zero = false;
        }
        if mac[i] != 0xFF {
            all_ff = false;
        }
        i += 1;
    }
    all_zero || all_ff
}

/// Firmware version from the shared OUT version dwords
/// (`hw_atl2_utils_get_fw_version`: "A2 FW version is stored in
/// reverse order" — `major << 24 | minor << 16 | build`).
pub const fn decode_fw_version(dwords: &[u32; 4]) -> (u8, u8, u16) {
    let b = dwords[0].to_le_bytes();
    (b[0], b[1], ((b[3] as u16) << 8) | b[2] as u16)
}

/// Raw firmware version word, as `hw_atl2_utils_get_fw_version`
/// returns it.
pub const fn fw_version_word(dwords: &[u32; 4]) -> u32 {
    let (major, minor, build) = decode_fw_version(dwords);
    ((major as u32) << 24) | ((minor as u32) << 16) | build as u32
}

/// Filter capabilities decoded from the shared OUT filter-caps
/// dwords (`filter_caps_s`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FilterCaps {
    /// First L2 unicast filter the driver may use
    /// (`l2_filters_base_index`, bits [5:0] of byte 0).
    pub l2_base_index: u8,
    /// Number of L2 unicast filters (`l2_filter_count`, byte 1).
    pub l2_count: u8,
    /// Action-resolver table base index
    /// (`rslv_tbl_base_index`, byte 10 of the struct).
    pub rslv_base_index: u8,
    /// Action-resolver table entry count
    /// (`rslv_tbl_count`, byte 11 of the struct).
    pub rslv_count: u8,
}

impl FilterCaps {
    /// Decode the three filter-caps dwords (OUT dwords 477–479).
    pub const fn decode(dwords: &[u32; 3]) -> Self {
        let d0 = dwords[0].to_le_bytes();
        let d2 = dwords[2].to_le_bytes();
        Self {
            l2_base_index: d0[0] & 0x3F,
            l2_count: d0[1],
            rslv_base_index: d2[2],
            rslv_count: d2[3],
        }
    }

    /// Action-resolver table base, as Linux computes it
    /// (`priv->art_base_index = filter_caps.rslv_tbl_base_index * 8`).
    pub const fn art_base_index(self) -> u32 {
        self.rslv_base_index as u32 * 8
    }

    /// Action-resolver table entry count
    /// (`priv->art_count = filter_caps.rslv_tbl_count * 8`).
    pub const fn art_count(self) -> u32 {
        self.rslv_count as u32 * 8
    }
}

/// Negotiated link rate codes (`AQ_A2_FW_LINK_RATE_*`).
pub(crate) const LINK_RATE_INVALID: u8 = 0;
pub(crate) const LINK_RATE_10M: u8 = 1;
pub(crate) const LINK_RATE_100M: u8 = 2;
pub(crate) const LINK_RATE_1G: u8 = 3;
pub(crate) const LINK_RATE_2G5: u8 = 4;
pub(crate) const LINK_RATE_5G: u8 = 5;
pub(crate) const LINK_RATE_10G: u8 = 6;

/// Map a firmware link-rate code to Mbit/s (0 when down/unknown),
/// mirroring `aq_a2_fw_update_link_status`.
pub const fn link_rate_to_mbps(rate: u8) -> u32 {
    match rate {
        LINK_RATE_10M => 10,
        LINK_RATE_100M => 100,
        LINK_RATE_1G => 1000,
        LINK_RATE_2G5 => 2500,
        LINK_RATE_5G => 5000,
        LINK_RATE_10G => 10000,
        _ => 0,
    }
}

/// Decoded firmware link status (`link_status_s` at OUT dword 5:
/// byte 0 = `link_state` [3:0] | `link_rate` [7:4]; byte 1 =
/// `pause_tx` bit 0, `pause_rx` bit 1, `eee` bit 2, `duplex` bit 3).
/// Carrier follows Linux's `aq_nic_update_link_status`: up iff the
/// negotiated rate is non-zero.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkStatus {
    pub carrier: bool,
    pub mbps: u32,
    pub full_duplex: bool,
}

impl LinkStatus {
    /// Decode the single OUT dword 5 word.
    pub const fn decode(word: u32) -> Self {
        let b0 = word as u8;
        let b1 = (word >> 8) as u8;
        let mbps = link_rate_to_mbps(b0 >> 4);
        Self {
            carrier: mbps != 0,
            mbps,
            full_duplex: b1 & 0x08 != 0,
        }
    }
}

/// Build the firmware `link_options` word (IN dword 6) from a
/// Linux `AQ_NIC_RATE_*` speed mask, mirroring
/// `a2_link_speed_mask2fw` + `aq_a2_fw_set_state(MPI_INIT)`:
/// `link_up` = 1, the advertised rates, `rate_N5G` mirroring
/// `rate_5G` and `rate_N2P5G` mirroring `rate_2P5G`, EEE off,
/// `pause_rx`/`pause_tx` = 1 (flow control FULL,
/// `AQ_CFG_FC_MODE`), `downshift` = 0 (disabled, Stage 2).
///
/// Byte layout of `link_options_s` (little-endian u32): byte 0 =
/// `link_up` bit 0, `link_renegotiate` bit 1, `minimal_link_speed`
/// bit 2, loopbacks bits 3–4, half-duplex rates bits 5–7; byte 1 =
/// `rate_10M` bit 0, `rate_100M` bit 1, `rate_1G` bit 2,
/// `rate_2P5G` bit 3, `rate_N2P5G` bit 4, `rate_5G` bit 5,
/// `rate_N5G` bit 6, `rate_10G` bit 7; byte 2 = EEE rates; byte 3
/// = `pause_rx` bit 0, `pause_tx` bit 1, `downshift` bit 3,
/// `downshift_retry` bits [7:4].
pub const fn build_link_options(speed_msk: u32) -> u32 {
    let mut byte1: u32 = 0;
    if speed_msk & RATE_10M != 0 {
        byte1 |= 1 << 0;
    }
    if speed_msk & RATE_100M != 0 {
        byte1 |= 1 << 1;
    }
    if speed_msk & RATE_1G != 0 {
        byte1 |= 1 << 2;
    }
    if speed_msk & RATE_2G5 != 0 {
        byte1 |= (1 << 3) | (1 << 4);
    }
    if speed_msk & RATE_5G != 0 {
        byte1 |= (1 << 5) | (1 << 6);
    }
    if speed_msk & RATE_10G != 0 {
        byte1 |= 1 << 7;
    }
    (1 << 0) | (byte1 << 8) | ((1 << 0 | 1 << 1) << 24)
}

/// Split a MAC into the RPF L2 unicast filter words
/// (`hw_atl2_hw_mac_addr_set`): `h = mac[0] << 8 | mac[1]`,
/// `l = mac[2] << 24 | mac[3] << 16 | mac[4] << 8 | mac[5]`.
pub const fn mac_filter_words(mac: [u8; 6]) -> (u32, u32) {
    let h = ((mac[0] as u32) << 8) | mac[1] as u32;
    let l =
        ((mac[2] as u32) << 24) | ((mac[3] as u32) << 16) | ((mac[4] as u32) << 8) | mac[5] as u32;
    (l, h)
}

/// ITR IRQ-map field for a TX queue: (register, mask, shift).
/// TX vector field is bits [28:24] for even queues, [20:16] for
/// odd queues (`itr_imr_txt_adr` / `itr_imr_txt_msk` /
/// `itr_imr_txt_shift`).
pub const fn itr_map_tx_field(q: u32) -> (u64, u32, u32) {
    let reg = reg_itr_map(q as u64);
    if q % 2 == 0 {
        (reg, 0x1F00_0000, 24)
    } else {
        (reg, 0x001F_0000, 16)
    }
}

/// ITR IRQ-map field for an RX queue: (register, mask, shift).
/// RX vector field is bits [12:8] for even queues, [4:0] for odd
/// queues.
pub const fn itr_map_rx_field(q: u32) -> (u64, u32, u32) {
    let reg = reg_itr_map(q as u64);
    if q % 2 == 0 {
        (reg, 0x0000_1F00, 8)
    } else {
        (reg, 0x0000_001F, 0)
    }
}

/// ITR IRQ-map-enable bit for a TX queue: bit 31 (even) / bit 23
/// (odd) of the same register.
pub const fn itr_map_tx_en_bit(q: u32) -> u32 {
    if q % 2 == 0 {
        1 << 31
    } else {
        1 << 23
    }
}

/// ITR IRQ-map-enable bit for an RX queue: bit 15 (even) / bit 7
/// (odd) of the same register.
pub const fn itr_map_rx_en_bit(q: u32) -> u32 {
    if q % 2 == 0 {
        1 << 15
    } else {
        1 << 7
    }
}

// ── Descriptors ─────────────────────────────────────────────────────
// `hw_atl_txd_s` / `hw_atl_rxd_s` / `hw_atl_rxd_wb_s`
// (`hw_atl_utils.h`): TXD and RXD are both 16 bytes; the RX
// writeback overlays the RXD in place.

/// Hardware TX descriptor (`struct __packed hw_atl_txd_s`):
/// `buf_addr` (u64), `ctl` (u32), `ctl2` (u32).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct TxDesc {
    pub buf_addr: u64,
    pub ctl: u32,
    pub ctl2: u32,
}
const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);

/// Hardware RX descriptor (`struct __packed hw_atl_rxd_s`):
/// `buf_addr` (u64), `hdr_addr` (u64).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct RxDesc {
    pub buf_addr: u64,
    pub hdr_addr: u64,
}
const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);

/// Hardware RX descriptor writeback (`struct __packed
/// hw_atl_rxd_wb_s`): `type` (u32), `rss_hash` (u32), `status`
/// (u16), `pkt_len` (u16), `next_desc_ptr` (u16), `vlan` (u16).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct RxdWb {
    pub type_: u32,
    pub rss_hash: u32,
    pub status: u16,
    pub pkt_len: u16,
    pub next_desc_ptr: u16,
    pub vlan: u16,
}
const _: () = assert!(core::mem::size_of::<RxdWb>() == 16);

// TXD `ctl` bits (`hw_atl_b0_internal.h`).
pub(crate) const TXD_CTL_DESC_TYPE_TXD: u32 = 0x0000_0001;
pub(crate) const TXD_CTL_BLEN: u32 = 0x000F_FFF0;
pub(crate) const TXD_CTL_DD: u32 = 0x0010_0000;
pub(crate) const TXD_CTL_EOP: u32 = 0x0020_0000;
pub(crate) const TXD_CTL_CMD_WB: u32 = 1 << 27;
/// TXD `ctl2` payload-length field (`HW_ATL_B0_TXD_CTL2_LEN`).
pub(crate) const TXD_CTL2_LEN: u32 = 0xFFFF_C000;

// RXD writeback `status` bits (`HW_ATL_B0_RXD_WB_STAT2_*`).
pub(crate) const RXD_WB_DD: u16 = 0x0001;
pub(crate) const RXD_WB_EOP: u16 = 0x0002;
pub(crate) const RXD_WB_RXSTAT_MSK: u16 = 0x003C;
pub(crate) const RXD_WB_RXSTAT_SHIFT: u16 = 2;
/// RXD writeback `type` packet-type field
/// (`HW_ATL_B0_RXD_WB_STAT_PKTTYPE`).
pub(crate) const RXD_WB_PKTTYPE_MSK: u32 = 0x0000_0FF0;
pub(crate) const RXD_WB_PKTTYPE_SHIFT: u32 = 4;
/// RXD writeback `type` DMA-error bit (bit 12, `0x1000U` in
/// `hw_atl_b0_hw_ring_rx_receive`).
pub(crate) const RXD_WB_DMA_ERR: u32 = 0x1000;
/// RXD writeback `type` checksum-enable field (bits [20:19]).
pub(crate) const RXD_WB_CSUM_EN_SHIFT: u32 = 19;

/// Build a single-buffer TX descriptor for a frame of `len` bytes
/// at physical address `phys`, mirroring
/// `hw_atl_b0_hw_ring_tx_xmit` for a single-segment, no-offload
/// frame: `ctl` = buffer length (`len << 4`, `BLEN` mask) +
/// `DESC_TYPE_TXD` + `EOP` + `CMD_WB` (writeback so `DD` signals
/// completion); `ctl2` = payload length (`len << 14`, `CTL2_LEN`
/// mask). `len` is masked to the fields' widths per the spec.
pub const fn build_tx_desc(slot: usize, phys: u64, len: u32) -> TxDesc {
    let _ = slot;
    TxDesc {
        buf_addr: phys,
        ctl: ((len << 4) & TXD_CTL_BLEN) | TXD_CTL_DESC_TYPE_TXD | TXD_CTL_EOP | TXD_CTL_CMD_WB,
        ctl2: (len << 14) & TXD_CTL2_LEN,
    }
}

/// Build an RX descriptor for `slot` pointing at `phys` with no
/// header buffer, mirroring `hw_atl_b0_hw_ring_rx_fill`:
/// `buf_addr` = buffer, `hdr_addr` = 0. RX descriptors carry no
/// ownership bit — availability is signalled purely by the RX tail
/// pointer.
pub const fn build_rx_desc(slot: usize, phys: u64) -> RxDesc {
    let _ = slot;
    RxDesc {
        buf_addr: phys,
        hdr_addr: 0,
    }
}

/// RX checksum decode result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    None,
    Ok,
    Fail,
}

/// Decoded RX writeback: length, checksum verdict, error flag,
/// end-of-packet flag.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxDecode {
    pub len: usize,
    pub csum: RxCsumResult,
    pub error: bool,
    pub is_eop: bool,
}

/// Decode an RX writeback, mirroring
/// `hw_atl_b0_hw_ring_rx_receive`: `rx_stat` = `status` bits
/// [5:2]; MAC error = `rx_stat` bit 0 or `type` DMA-error bit;
/// checksum-enable = `type` bits [20:19]; packet type = `type`
/// bits [11:4]. L4 checksum is trusted when the L4 enable bit is
/// set, the packet is TCP (`pkt_type & 0x1C == 0`) or UDP
/// (`== 4`), `rx_stat` bit 2 is clear and bit 3 is set; `cso_err`
/// = `rx_stat & 0x6`. Frames ≤ 60 bytes clear the IP verdict and
/// the error flag (the Linux small-packet workaround). Length
/// follows the EOP rule: `pkt_len % frame_max`, or `frame_max`
/// when the remainder is 0.
pub fn decode_rx_wb(wb: &RxdWb, frame_max: u32) -> RxDecode {
    let status = wb.status;
    let type_ = wb.type_;
    let rx_stat = (status & RXD_WB_RXSTAT_MSK) >> RXD_WB_RXSTAT_SHIFT;
    let pkt_type = (type_ & RXD_WB_PKTTYPE_MSK) >> RXD_WB_PKTTYPE_SHIFT;
    let csum_en = (type_ >> RXD_WB_CSUM_EN_SHIFT) & 0x3;
    let is_eop = status & RXD_WB_EOP != 0;
    let error = (rx_stat & 0x1) != 0 || (type_ & RXD_WB_DMA_ERR) != 0;
    let pkt_len = wb.pkt_len as u32;

    let mut l4_ok = false;
    if csum_en & 0x2 != 0 && ((pkt_type & 0x1C) == 0x04 || (pkt_type & 0x1C) == 0x00) {
        l4_ok = (rx_stat & 0x4) == 0 && (rx_stat & 0x8) != 0;
    }
    let mut cso_err = (rx_stat & 0x6) != 0;
    if pkt_len <= 60 {
        // Linux small-packet workaround: clears the IP verdict and
        // the error flag, keeps the L4 verdict.
        cso_err = false;
    }
    let csum = if l4_ok {
        RxCsumResult::Ok
    } else if cso_err {
        RxCsumResult::Fail
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

// ── Register I/O ────────────────────────────────────────────────────
// The bring-up sequence is written against this trait — not
// directly against `MmioRegion` — so the kernel-test fixture can
// drive the whole conversation through a spec-built fake device
// (`tests::FakeRegs`) while the live path uses the real BAR.
// Every constant the sequence writes comes from the Linux sources
// cited at the top of this file; the fake's expected values are
// computed from the same sources independently (see `tests.rs`).

/// Minimal 32-bit register access for the Atlantic register file.
pub(crate) trait RegIo {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&self, offset: u64, value: u32);

    /// Read-modify-write of a bitfield: set the masked bits to
    /// `value` (already shifted into place).
    fn rmw32(&self, offset: u64, mask: u32, value: u32) {
        let cur = self.read32(offset);
        self.write32(offset, (cur & !mask) | (value & mask));
    }

    /// Set one bit.
    fn set_bit(&self, offset: u64, bit: u32) {
        self.rmw32(offset, bit, bit);
    }

    /// Clear one bit.
    fn clear_bit(&self, offset: u64, bit: u32) {
        self.rmw32(offset, bit, 0);
    }
}

impl RegIo for MmioRegion {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: identity-mapped MMIO; the caller owns the BAR.
        unsafe { MmioRegion::read32(self, offset) }
    }

    fn write32(&self, offset: u64, value: u32) {
        // SAFETY: identity-mapped MMIO; the caller owns the BAR.
        unsafe { MmioRegion::write32(self, offset, value) }
    }
}

// ── Bring-up sequence (register conversation) ───────────────────────

/// Reboot the on-chip firmware through the MIF boot register and
/// wait for its boot-complete status, mirroring
/// `hw_atl2_utils_soft_reset`:
/// clear host-req-int, write REBOOT, poll BOOT_STARTED (200 ms),
/// poll boot-complete — success bit 31 or any failure bit 27/28/29
/// (2 s) — then fail on failure bits, and fail when the host-req
/// interrupt reports READY ("No FW detected. Dynamic FW load not
/// implemented").
pub(crate) fn soft_reset(regs: &impl RegIo) -> Result<(), NicError> {
    regs.write32(REG_MIF_HOST_REQ_INT_CLR, 0x01);
    regs.write32(REG_MIF_BOOT, MIF_BOOT_REQ_REBOOT);
    let started = narf_scheduler::responsive_spin_until(
        || {
            let s = regs.read32(REG_MIF_BOOT);
            s != 0xFFFF_FFFF && s & MIF_BOOT_STARTED != 0
        },
        narf_time::Deadline::after_ms(200),
    );
    if !started {
        return Err(NicError::FwTimeout);
    }
    let done = narf_scheduler::responsive_spin_until(
        || {
            let s = regs.read32(REG_MIF_BOOT);
            s & MIF_BOOT_COMPLETE_MASK != 0
                || regs.read32(REG_MIF_HOST_REQ_INT) & MIF_HOST_REQ_READY != 0
        },
        narf_time::Deadline::after_ms(2000),
    );
    if !done {
        return Err(NicError::FwTimeout);
    }
    let status = regs.read32(REG_MIF_BOOT);
    if status & MIF_BOOT_FAILED_MASK != 0 {
        return Err(NicError::FwFailed);
    }
    if regs.read32(REG_MIF_HOST_REQ_INT) & MIF_HOST_REQ_READY != 0 {
        return Err(NicError::NoFirmware);
    }
    Ok(())
}

/// Complete a firmware shared-buffer write: set
/// HOST_FINISHED_WRITE, then poll MCP_FINISHED_READ to 0,
/// mirroring `hw_atl2_shared_buffer_finish_ack` (100 ms).
pub(crate) fn finish_ack(regs: &impl RegIo) -> Result<(), NicError> {
    regs.write32(REG_MIF_HOST_FINISHED_WRITE, 1);
    let acked = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_MIF_MCP_FINISHED_READ) == 0,
        narf_time::Deadline::after_ms(100),
    );
    if acked {
        Ok(())
    } else {
        Err(NicError::FwTimeout)
    }
}

/// Read a block of shared OUT dwords with the firmware transaction
/// counter guard, mirroring `hw_atl2_shared_buffer_read_block`:
/// the counter's halves must agree and be unchanged across the
/// read, otherwise retry (up to 1000 attempts).
pub(crate) fn read_shared_out_block(
    regs: &impl RegIo,
    offset_dwords: u64,
    out: &mut [u32],
) -> Result<(), NicError> {
    let stable = |t: u32| (t & 0xFFFF) == (t >> 16);
    for _ in 0..1000 {
        let tid1 = regs.read32(REG_MIF_SHARED_OUT + SH_OUT_TRANSACTION_DWORD * 4);
        for (i, w) in out.iter_mut().enumerate() {
            *w = regs.read32(REG_MIF_SHARED_OUT + (offset_dwords + i as u64) * 4);
        }
        let tid2 = regs.read32(REG_MIF_SHARED_OUT + SH_OUT_TRANSACTION_DWORD * 4);
        if stable(tid1) && stable(tid2) && (tid1 & 0xFFFF) == (tid2 & 0xFFFF) {
            return Ok(());
        }
    }
    Err(NicError::FwTimeout)
}

/// Read the firmware filter capabilities (OUT dwords 477–479),
/// mirroring `hw_atl2_utils_get_filter_caps`.
pub(crate) fn read_filter_caps(regs: &impl RegIo) -> Result<FilterCaps, NicError> {
    let mut dwords = [0u32; 3];
    read_shared_out_block(regs, SH_OUT_FILTER_CAPS_DWORD, &mut dwords)?;
    Ok(FilterCaps::decode(&dwords))
}

/// Read the firmware version word (OUT dwords 1–4), mirroring
/// `hw_atl2_utils_get_fw_version`.
pub(crate) fn read_fw_version(regs: &impl RegIo) -> Result<u32, NicError> {
    let mut dwords = [0u32; 4];
    read_shared_out_block(regs, SH_OUT_VERSION_DWORD, &mut dwords)?;
    Ok(fw_version_word(&dwords))
}

/// Read the permanent MAC from the shared IN buffer (dwords 2–3),
/// mirroring `aq_a2_fw_get_mac_permanent`.
pub(crate) fn read_permanent_mac(regs: &impl RegIo) -> Option<[u8; 6]> {
    let dwords = [
        regs.read32(REG_MIF_SHARED_IN + (SH_IN_MAC_DWORD) * 4),
        regs.read32(REG_MIF_SHARED_IN + (SH_IN_MAC_DWORD + 1) * 4),
    ];
    decode_mac_from_shared(&dwords)
}

/// Establish the firmware interface, mirroring `aq_a2_fw_init`:
/// read the filter caps, set `link_control.mode` = ACTIVE,
/// write the jumbo MTU (16352), and finish the handshake
/// (5 s timeout, as in `aq_a2_fw_init`'s inlined ack wait).
/// Linux runs this both at probe and after reset; this driver runs
/// it once, after `soft_reset`, which is the pass that matters —
/// the reset reboots the firmware, so the pre-reset pass would be
/// discarded with it.
pub(crate) fn fw_init(regs: &impl RegIo) -> Result<FilterCaps, NicError> {
    let caps = read_filter_caps(regs)?;
    let mut link_control = regs.read32(REG_MIF_SHARED_IN + SH_IN_LINK_CONTROL_DWORD * 4);
    link_control = (link_control & !0xF) | HOST_MODE_ACTIVE;
    regs.write32(
        REG_MIF_SHARED_IN + SH_IN_LINK_CONTROL_DWORD * 4,
        link_control,
    );
    regs.write32(REG_MIF_SHARED_IN + SH_IN_MTU_DWORD * 4, FW_MTU_JUMBO);
    regs.write32(REG_MIF_HOST_FINISHED_WRITE, 1);
    let acked = narf_scheduler::responsive_spin_until(
        || regs.read32(REG_MIF_MCP_FINISHED_READ) == 0,
        narf_time::Deadline::after_ms(5000),
    );
    if acked {
        Ok(caps)
    } else {
        Err(NicError::FwTimeout)
    }
}

/// Initialise the TX path, mirroring the register writes in
/// `hw_atl2_hw_init_tx_path` that gate single-queue TX: enable
/// TX-descriptor writeback interrupts and disable the TX buffer
/// clock gate. (TC mode, LSO flags, DCA and the TC map are
/// multi-queue/QoS state, deferred.)
pub(crate) fn init_tx_path(regs: &impl RegIo) {
    regs.set_bit(REG_TDM_INT_DESC_WRB_EN, TDM_WRB_IRQ_EN);
    regs.clear_bit(REG_TPB_TX_BUF, TPB_TX_BUF_CLK_GATE_EN);
}

/// Initialise the RX path, mirroring `hw_atl2_hw_init_rx_path` /
/// `hw_atl2_hw_init_new_rx_filters` for the single-queue case:
/// enable RX-descriptor writeback interrupts, accept all multicast
/// (mask 0 + ANY_TO_HOST), set the VLAN TPIDs, accept untagged
/// frames with the host action in VLAN-promiscuous mode, enable the
/// new RPF filter engine, and program the L2 unicast filters —
/// only the firmware's base filter enabled, all with the host
/// action (the MAC itself is programmed by [`mac_addr_set`]).
pub(crate) fn init_rx_path(regs: &impl RegIo, l2_base: u32) {
    regs.set_bit(REG_RDM_INT_DESC_WRB_EN, RDM_WRB_IRQ_EN);
    regs.write32(REG_RPF_MCST_MSK, 0);
    regs.write32(REG_RPF_MCST_FLR_BASE, MCST_FLT_ANY_TO_HOST);
    regs.write32(REG_RPF_VLAN_TPID, (0x88A8 << 16) | 0x8100);
    regs.rmw32(
        REG_RPF_VLAN_CTL,
        RPF_VL_PROMIS_MODE | RPF_VL_ACCEPT_UNTAGGED | RPF_VL_UNTAGGED_ACT_MSK,
        RPF_VL_PROMIS_MODE | RPF_VL_ACCEPT_UNTAGGED | (L2_ACT_HOST << RPF_VL_UNTAGGED_ACT_SHIFT),
    );
    regs.set_bit(REG_RPF_NEW_EN, RPF_NEW_EN);
    for i in 0..MAC_FILTER_MAX {
        let en = if i == l2_base { RPF_UC_EN } else { 0 };
        regs.rmw32(
            reg_rpf_uc_ctl(i as u64),
            RPF_UC_EN | RPF_UC_ACT_MSK,
            en | (L2_ACT_HOST << RPF_UC_ACT_SHIFT),
        );
    }
    regs.rmw32(
        REG_RPF_BC,
        RPF_BC_ACT_MSK | RPF_BC_THRESH_MSK,
        (L2_ACT_HOST << RPF_BC_ACT_SHIFT) | (RPF_BC_THRESH << RPF_BC_THRESH_SHIFT),
    );
}

/// Program the permanent MAC into the RPF L2 unicast filter at
/// `location`, mirroring `hw_atl2_hw_mac_addr_set`: disable the
/// filter, write the address words, set the host action + unicast
/// tag, re-enable.
pub(crate) fn mac_addr_set(regs: &impl RegIo, location: u32, mac: [u8; 6]) {
    let (l, h) = mac_filter_words(mac);
    let ctl = reg_rpf_uc_ctl(location as u64);
    regs.clear_bit(ctl, RPF_UC_EN);
    regs.write32(reg_rpf_uc_daflsw(location as u64), l);
    regs.rmw32(ctl, RPF_UC_DAFMSW_MSK, h);
    regs.rmw32(
        ctl,
        RPF_UC_ACT_MSK | RPF_UC_TAG_MSK,
        (L2_ACT_HOST << RPF_UC_ACT_SHIFT) | (RPF_TAG_BASE_UC << RPF_UC_TAG_SHIFT),
    );
    regs.set_bit(ctl, RPF_UC_EN);
}

/// Bring the firmware link up, mirroring
/// `aq_a2_fw_set_state(MPI_INIT)`: write `link_options` with
/// `link_up` = 1 and the advertised rates, then finish the
/// handshake.
pub(crate) fn mpi_init(regs: &impl RegIo, speed_msk: u32) -> Result<(), NicError> {
    regs.write32(
        REG_MIF_SHARED_IN + SH_IN_LINK_OPTIONS_DWORD * 4,
        build_link_options(speed_msk),
    );
    finish_ack(regs)
}

/// Program the interrupt block for MSI-X with a single vector,
/// mirroring `hw_atl2_hw_init`'s interrupt tail: global control
/// `0x20000022`, auto-mask `~0U`, general IRQ map 0.
pub(crate) fn init_interrupts(regs: &impl RegIo) {
    regs.write32(REG_IRQ_GLB_CTL, IRQ_GLB_CTL_MSIX_1VEC);
    regs.write32(REG_ITR_IAMRLSW, IRQ_AUTO_MASK);
    regs.write32(REG_GEN_IRQ_MAP_BASE, GEN_IRQ_MAP0);
}

/// Program queue 0's TX + RX descriptor rings, mirroring
/// `hw_atl_b0_hw_ring_tx_init` / `hw_atl_b0_hw_ring_rx_init`:
/// 64-bit ring bases, ring length `size/8` in the control field,
/// TX writeback threshold 0, RX data-buffer size
/// (`frame_max / 1024` = 2 KiB units), header size 0, header
/// splitting off, VLAN stripping off, TX/RX IRQ maps to vector 0
/// with mapping enabled. The RX tail is NOT set here — the caller
/// fills the RX descriptors first, then calls [`set_rx_tail`].
pub(crate) fn program_rings(regs: &impl RegIo, tx_phys: u64, rx_phys: u64) {
    // TX ring 0.
    regs.write32(reg_tx_dma_base_lsw(0), tx_phys as u32);
    regs.write32(reg_tx_dma_base_msw(0), (tx_phys >> 32) as u32);
    regs.rmw32(
        reg_tx_dma_ctl(0),
        DESC_LEN_MSK,
        ((RING_LEN as u32 / 8) << DESC_LEN_SHIFT) & DESC_LEN_MSK,
    );
    regs.write32(reg_tx_dma_tail(0), 0);
    regs.rmw32(reg_tx_dma_wrb_thresh(0), 0x7F00, 0);
    let (tx_map_reg, tx_map_msk, tx_map_shift) = itr_map_tx_field(0);
    regs.rmw32(tx_map_reg, tx_map_msk, 0 << tx_map_shift);
    regs.set_bit(tx_map_reg, itr_map_tx_en_bit(0));

    // RX ring 0.
    regs.write32(reg_rx_dma_base_lsw(0), rx_phys as u32);
    regs.write32(reg_rx_dma_base_msw(0), (rx_phys >> 32) as u32);
    regs.rmw32(
        reg_rx_dma_ctl(0),
        DESC_LEN_MSK | RXD_HDR_SPLIT | RXD_VL_STRIP,
        ((RING_LEN as u32 / 8) << DESC_LEN_SHIFT) & DESC_LEN_MSK,
    );
    regs.write32(reg_rx_dma_buf_size(0), (RX_BUF_LEN as u32 / 1024) & 0x1F);
    let (rx_map_reg, rx_map_msk, rx_map_shift) = itr_map_rx_field(0);
    regs.rmw32(rx_map_reg, rx_map_msk, 0 << rx_map_shift);
    regs.set_bit(rx_map_reg, itr_map_rx_en_bit(0));
}

/// Publish the RX tail pointer after the RX descriptors are
/// filled: `tail` is the next descriptor the driver will
/// (re)fill, so after filling `RING_LEN - 1` descriptors it is
/// `RING_LEN - 1` — one slot is always kept empty, matching
/// Linux's `aq_ring_avail_dx` reserve-one invariant.
pub(crate) fn set_rx_tail(regs: &impl RegIo, tail: u32) {
    regs.write32(reg_rx_dma_tail(0), tail);
}

/// Enable the datapath, mirroring `aq_vec_start` then
/// `hw_atl_b0_hw_start`: descriptor engines on, then the TX/RX
/// packet buffers.
pub(crate) fn start_hw(regs: &impl RegIo) {
    regs.set_bit(reg_tx_dma_ctl(0), DESC_EN);
    regs.set_bit(reg_rx_dma_ctl(0), DESC_EN);
    regs.set_bit(REG_TPB_TX_BUF, TPB_TX_BUF_EN);
    regs.set_bit(REG_RPB_RX_BUF, RPB_RX_BUF_EN);
}

/// Read the current firmware link status (OUT dword 5).
pub(crate) fn read_link_status(regs: &impl RegIo) -> LinkStatus {
    LinkStatus::decode(regs.read32(REG_MIF_SHARED_OUT + SH_OUT_LINK_STATUS_DWORD * 4))
}

// ── Live driver state ───────────────────────────────────────────────

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use alloc::sync::Arc;
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    /// Frame outside [1, chip max frame].
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// `transmit` polled too long for the descriptor-DD writeback.
    TxTimeout,
    /// MSI-X table couldn't be brought up.
    MsixSetup,
    /// The firmware did not answer a handshake in time.
    FwTimeout,
    /// The firmware reported a boot failure.
    FwFailed,
    /// The firmware boot handshake reports no firmware present.
    NoFirmware,
    /// The permanent MAC read back invalid.
    BadMac,
    /// Catch-all.
    Other(&'static str),
}

/// A live AQC113 controller. Holds the MMIO mapping, the
/// descriptor rings, and the RX/TX buffer pools.
///
/// On-wire layout follows the Atlantic model: per-direction
/// 256-slot 16-byte-descriptor rings, one DMA buffer per slot
/// for RX, one DMA buffer per slot for TX (persistent — the
/// descriptor's `buf_addr` always points at its slot's buffer).
pub struct AqcNic {
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
    /// MAC address read from the firmware shared buffer at bring-up.
    pub mac: [u8; 6],
    /// Raw firmware version word at bring-up
    /// (`major << 24 | minor << 16 | build`).
    pub fw_version: u32,
    /// Firmware filter capabilities at bring-up.
    pub filter_caps: FilterCaps,
    /// PCI address this controller was probed at — the per-device
    /// identity the `CONTROLLERS` dedup and detach paths key on
    /// (issue #795). Two AQC functions never share a `BusAddr`.
    pub addr: narf_bus::BusAddr,
    /// Set by [`aqc113_detach`]; datapath entry points fail fast
    /// once set, and [`live_controller`] filters the slot out, so a
    /// detached device's cookie stops resolving while its slot —
    /// and every other controller's cookie — stays valid.
    detached: AtomicBool,
    /// Interface name `publish_netdev_with_context` assigned this
    /// NIC (`eth%d`); per-device, so a second AQC port's pump and
    /// adapter report its own name instead of the first port's.
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

// SAFETY: `AqcNic` only owns an `MmioRegion` (identity-mapped BAR0 device
// window) and `DmaBuffer`s (identity-mapped DMA pages). Those raw pointers are
// the sole reason auto `Send` is not derived; the underlying device window is
// not thread-affine, so the struct may be moved between cores.
unsafe impl Send for AqcNic {}
// SAFETY: every interior-mutable field (`tx_head`, `rx_head`, the IPC rings) is
// guarded by `IrqSafeSpinLock`, so concurrent `&AqcNic` access is serialised.
// The MMIO/DMA windows are device registers/buffers safe for shared volatile
// access from multiple cores.
unsafe impl Sync for AqcNic {}

impl core::fmt::Debug for AqcNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AqcNic")
            .field("addr", &self.addr)
            .field("mac", &self.mac)
            .field("fw_version", &self.fw_version)
            .field("filter_caps", &self.filter_caps)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl AqcNic {
    /// Bring up the controller: firmware reboot + handshake, read
    /// MAC / caps / version, install TX + RX rings, enable the
    /// datapath, observe link state. Returns the controller already
    /// wrapped in `Arc` (igc's shape): the pump pair spawned here
    /// holds Arc clones, so returning bare `Self` via
    /// `Arc::try_unwrap` would always fail — the clones keep the
    /// refcount above 1 (e1000 documents the same trap and returns
    /// its halves to probe instead).
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
        // first MEM resource; on AQC113 hardware that is BAR0).
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| NicError::BarMapFailed)?;

        // 1. Reboot the on-chip firmware and wait for boot-complete
        // (`hw_atl2_utils_soft_reset`).
        soft_reset(&mmio)?;
        // 2. Establish the firmware interface: filter caps, ACTIVE
        // mode, jumbo MTU (`aq_a2_fw_init`).
        let filter_caps = fw_init(&mmio)?;
        // 3. Firmware version (recorded; Linux warns and continues
        // on a mismatch, so we do too).
        let fw_version = read_fw_version(&mmio)?;
        // 4. Permanent MAC from the firmware shared buffer.
        let mac = read_permanent_mac(&mmio).ok_or(NicError::BadMac)?;
        if mac_is_invalid(mac) {
            return Err(NicError::BadMac);
        }
        let l2_base = filter_caps.l2_base_index as u32;
        if l2_base >= MAC_FILTER_MAX {
            return Err(NicError::Other("firmware L2 filter base out of range"));
        }

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

        // 6. TX + RX path, MAC filter, firmware link-up, interrupts
        // (`hw_atl2_hw_init` order). The advertised rates come
        // from the probed device id's caps
        // (`hw_atl2_caps_aqc113` / `_aqc115c` / `_aqc116c`).
        init_tx_path(&mmio);
        init_rx_path(&mmio, l2_base);
        mac_addr_set(&mmio, l2_base, mac);
        mpi_init(&mmio, speed_mask_for(device.id.device))?;
        init_interrupts(&mmio);

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
                        .kernel_mut_ptr::<RxDesc>(),
                    d,
                );
            }
        }
        compiler_fence(Ordering::SeqCst);
        set_rx_tail(&mmio, (RING_LEN - 1) as u32);

        // 9. Enable the datapath (`aq_vec_start` then `hw_start`).
        start_hw(&mmio);

        // 10. Link snapshot from the firmware shared buffer.
        let link = read_link_status(&mmio);

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
            filter_caps,
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
            return Err(NicError::Other("aqc113 device detached"));
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
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<TxDesc>(),
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
            self.mmio.write32(reg_tx_dma_tail(0), next_tail);
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
            } & TXD_CTL_DD
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
    pub fn receive_with_meta(&self) -> Option<(alloc::vec::Vec<u8>, RxCsumResult)> {
        if self.detached.load(Ordering::Acquire) {
            return None;
        }
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
        let wb = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<RxdWb>())
        };
        if wb.status & RXD_WB_DD == 0 {
            return None;
        }
        let decoded = decode_rx_wb(&wb, RX_BUF_LEN as u32);
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(decoded.len.min(RX_BUF_LEN));
        if decoded.is_eop && !decoded.error {
            let copy_len = decoded.len.min(RX_BUF_LEN);
            // SAFETY: identity-mapped DMA buffer.
            for i in 0..copy_len {
                // SAFETY: `buf_phys` is the identity-mapped DMA buffer the NIC
                // just filled for this slot; `i < copy_len <= RX_BUF_LEN`, so
                // `buf_phys + i` stays inside the buffer.
                // SAFETY: Valid MMIO bounds or trusted driver environment
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
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<RxDesc>(),
                d,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // Advance the tail past the refilled descriptor so the NIC
        // may use it again.
        let next_tail = (slot as u32 + 1) % RING_LEN as u32;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(reg_rx_dma_tail(0), next_tail);
        }

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        if decoded.is_eop && !decoded.error {
            Some((out, decoded.csum))
        } else {
            None
        }
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

    /// Current firmware link status (shared-buffer read).
    pub fn link_status(&self) -> LinkStatus {
        read_link_status(&self.mmio)
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

/// Convert a firmware link status into a publication sample.
pub fn link_sample(status: LinkStatus) -> crate::publish::LinkSample {
    if !status.carrier {
        return crate::publish::LinkSample::DOWN;
    }
    crate::publish::LinkSample::up(
        Some(status.mbps),
        Some(if status.full_duplex {
            narf_net::iface::LinkDuplex::Full
        } else {
            narf_net::iface::LinkDuplex::Half
        }),
    )
}

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`aqc113_send_frame`] — the i40e `CONTROLLERS` pattern, so a
/// second AQC113 on the same machine probes, binds, and carries
/// traffic instead of being dropped by a singleton slot (issue
/// #795). The vec never shrinks: detaches mark the device in place
/// instead of removing its slot, so a live controller's cookie
/// stays valid for the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<AqcNic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// The probed controller at `index`, if it is live (probed and not
/// detached). The index is the cookie probe assigned (see
/// `CONTROLLERS`); it is stable because the vec never shrinks.
fn live_controller(index: usize) -> Option<Arc<AqcNic>> {
    CONTROLLERS
        .lock()
        .get(index)
        .filter(|c| !c.detached.load(Ordering::Acquire))
        .cloned()
}

/// `SendCtxFn` registered with `narf_net::iface` at probe time.
/// Routes the kernel-side TCP stack's outbound frames through
/// `AqcNic::transmit`; the cookie is the controller's index in
/// `CONTROLLERS`. The Arc is cloned out rather than holding the
/// IRQ-masking `CONTROLLERS` lock across `transmit` (same
/// reasoning as e1000).
fn aqc113_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = live_controller(cookie as usize).ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // A second probe of the SAME live function is a no-op success
    // (the old idempotent behaviour): the bus re-walks devices, and
    // rebuilding a second `AqcNic` for the same silicon would let two
    // instances drive one chip's rings. A second FUNCTION binds as a
    // new instance instead of being dropped (issue #795). A detached
    // entry does not block a re-probe of its address, so a hot
    // re-bind after detach can reclaim the function.
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
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { AqcNic::bring_up(&device, &cap) } {
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
    // name + carrier metadata via the shared helper. The send hook
    // carries this instance's `CONTROLLERS` index as its cookie, so
    // each port's outbound frames resolve to its own NIC.
    let mac = dev.mac;
    let status = dev.link_status();
    let name = crate::publish::publish_netdev_with_context(
        mac,
        index as u64,
        aqc113_send_frame,
        link_sample(status),
    );
    dev.ifname.set(name);

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Aqc113Nic { nic: dev.clone() });
    }

    // No pump spawn here: `bring_up` spawned the device's single RX/TX
    // pump pair, fed by the channel pair whose halves occupy the
    // `rx_ipc_ring`/`tx_ipc_ring` slots (igc's discipline). A second
    // pair spawned from probe would drain the same descriptor ring
    // while its mirror sink's consumer is overwritten away — silently
    // losing frames an attached ring consumer must see.

    Ok(())
}

fn spawn_pumps(
    device: Arc<AqcNic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        aqc113_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        aqc113_tx_pump(d2, tx_cons).await;
    });
}

async fn aqc113_rx_pump(device: Arc<AqcNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Carrier refresh (issue #791): the production datapath is polled
    // (probe never enables MSI-X, so the writeback-interrupt bits have
    // no consumer), which makes this pump the family's link observer.
    // `link_status()` is an `&self` shared-buffer read — unlike
    // `refresh_link_state(&mut self)`, it is safe to call while pumps
    // hold Arc clones. A transition republishes the iface metadata;
    // the cached `Interface::link_up` snapshot is left as-is.
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
            // RX fan-out (issue #784), e1000's `dispatch_rx_frame`
            // shape via the shared helper: an attached ring consumer
            // gets a pristine pre-dispatch copy; the original goes to
            // the kernel stack in place. The mirror is non-blocking —
            // a full/closed ring drops its copy, never the stack's
            // packet.
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

async fn aqc113_tx_pump(device: Arc<AqcNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
    }
}

/// Register a PCI match-table entry per supported device id. Linux
/// keeps the IDs distinct across the AQC113 family even though the
/// register model is shared; we register all eight.
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

/// Frame-ring / `Interface` adapter for one probed AQC113. The old
/// zero-sized `Aqc113Nic` resolved every call through the
/// module-level `CONTROLLER` singleton, so a second AQC113's
/// interface reported the first port's MAC, link state, and rings
/// (issue #795). The rings are borrowed from the NIC's own
/// `rx_ipc_ring` / `tx_ipc_ring` fields. The name always comes from
/// `AqcNic::ifname()`, which is `""` before probe publishes it.
#[derive(Debug)]
pub struct Aqc113Nic {
    nic: Arc<AqcNic>,
}

impl narf_net::Interface for Aqc113Nic {
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
        // no VLAN insertion (the TX context descriptor exists in
        // the spec; the datapath does not program it yet).
        narf_net::OffloadCapabilities {
            tx_checksum: false,
            rx_checksum: false,
            max_tso_bytes: 0,
            vlan_insert: false,
        }
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        // Ring consumer attached: enable this instance's RX mirror —
        // the old take-into-static set the attach note at this
        // moment — and record the attach under this port's own name,
        // so detach can clear it.
        crate::publish::note_rx_mirror_attached(self.nic.ifname());
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

impl crate::HwNic for Aqc113Nic {
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
        crate::NicModel::MarvellAqc113
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

/// Detach the bound aqc113 device at `index`, if any: device half
/// (set the datapath gate, so `transmit` / `receive_with_meta`
/// fail fast and the parked pumps stop touching the rings), then
/// the registry half the net spec §3 obliges — publish link down,
/// clear the RX-mirror attach note for the interface name (names
/// are lowest-free-allocated and reused), and unregister the
/// interface. Idempotent: an out-of-range index or an
/// already-detached device does nothing. The async pumps are not
/// joined (they hold `Arc<AqcNic>` clones), but every datapath
/// entry point fails fast once detached, so a parked pump can no
/// longer touch the device. The `CONTROLLERS` slot is kept so other
/// controllers' cookies stay valid. (No `device_pm` withdrawal:
/// this family never registered `DevicePmOps` — it has no
/// suspend/resume path yet.)
pub fn aqc113_detach(index: usize) {
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
pub fn controller(index: usize) -> Option<Arc<AqcNic>> {
    live_controller(index)
}

/// Test-side accessor: run `f` against the live probed controller
/// at `index` (i40e shape).
pub fn with_controller<R>(index: usize, f: impl FnOnce(&AqcNic) -> R) -> Option<R> {
    live_controller(index).map(|a| f(&a))
}

/// Mutable accessor — used by tests that want to switch on MSI-X
/// after probe.
pub fn with_controller_mut<R>(index: usize, f: impl FnOnce(&mut AqcNic) -> R) -> Option<R> {
    CONTROLLERS
        .lock()
        .get_mut(index)
        .map(|a| f(Arc::get_mut(a).expect("AqcNic static has multiple owners")))
}
