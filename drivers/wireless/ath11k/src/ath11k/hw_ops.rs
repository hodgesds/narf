//! Per-chip `hw_ops` (Linux `hw.c`: `ipq8074_ops`, `ipq6018_ops`,
//! `qca6390_ops`, `qcn9074_ops`, `wcn6855_ops`, `wcn6750_ops`,
//! `ipq5018_ops`), keyed by [`HwRev`].
//!
//! The `rx_desc_*` members are [`super::rx_descriptor::RxDescriptor`]
//! (keyed by `HwRev` the same way); this module holds the rest:
//! pdev ↔ hw-mac ↔ SRNG mapping, the WMI resource config flavour, the
//! TCL mesh bit, `reo_setup` and the TCL ring selector.

use super::ahb::MacMap;
use super::dp_ring::{
    HAL_DEFAULT_REO_TIMEOUT_USEC, HAL_HASH_ROUTING_RING_SW1, HAL_HASH_ROUTING_RING_SW2,
    HAL_HASH_ROUTING_RING_SW3, HAL_HASH_ROUTING_RING_SW4, HAL_REO1_DEST_RING_CTRL_IX_0,
    HAL_REO1_DEST_RING_CTRL_IX_1, HAL_REO1_DEST_RING_CTRL_IX_2, HAL_REO1_DEST_RING_CTRL_IX_3,
    HAL_REO1_GEN_ENABLE, HAL_REO1_GEN_ENABLE_AGING_FLUSH_ENABLE,
    HAL_REO1_GEN_ENABLE_AGING_LIST_ENABLE,
};
use super::hal::{field_prep, genmask, ring_id, HAL_SEQ_WCSS_UMAC_REO_REG};
use super::hw::{HalRegs, HwRev};
use super::power::ChipIo;

/// `HAL_REO1_GEN_ENABLE_FRAG_DST_RING` (`hal.h`).
pub const HAL_REO1_GEN_ENABLE_FRAG_DST_RING: u32 = genmask(25, 23);
/// `HAL_REO_DEST_RING_CTRL_HASH_RING_MAP` (`hal.h`).
pub const HAL_REO_DEST_RING_CTRL_HASH_RING_MAP: u32 = genmask(31, 8);
const REO_BASE: u32 = HAL_SEQ_WCSS_UMAC_REO_REG;

/// `hw_ops->wmi_init_config`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WmiInitConfig {
    /// `ath11k_init_wmi_config_qca6390` (single pdev).
    Qca6390,
    /// `ath11k_init_wmi_config_ipq8074` (per-radio vdevs, DBS/DBS_SBS
    /// peers, peer-map v2, TWT AP / EMA per radio).
    Ipq8074,
}

/// `hw_ops->tx_mesh_enable`: which TCL data-command word carries the
/// mesh bit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxMesh {
    /// `HAL_IPQ8074_TCL_DATA_CMD_INFO2_MESH_ENABLE`.
    Ipq8074Info2,
    /// `HAL_QCN9074_TCL_DATA_CMD_INFO3_MESH_ENABLE` (QCN9074, WCN6855,
    /// WCN6750, IPQ5018).
    Qcn9074Info3,
}

/// `hw_ops->reo_setup`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReoSetup {
    /// `ath11k_hw_ipq8074_reo_setup`: FRAG_DST_RING in GEN_ENABLE,
    /// 3-bit hash map shifted into `DEST_RING_CTRL_IX_0..3`.
    Ipq8074,
    /// `ath11k_hw_wcn6855_reo_setup`
    /// ([`super::dp_ring::wcn6855_reo_setup`]): fragment ring in
    /// MISC_CTL, 4-bit map in `IX_2` / `IX_3`.
    Wcn6855,
    /// `ath11k_hw_ipq5018_reo_setup`: as IPQ8074 with the 4-bit map
    /// written raw.
    Ipq5018,
}

/// `hw_ops->get_ring_selector`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingSelector {
    /// `ath11k_hw_ipq8074_get_tcl_ring_selector`: `smp_processor_id()`.
    Cpu,
    /// `ath11k_hw_wcn6750_get_tcl_ring_selector`: `skb_get_hash()`.
    FlowHash,
}

/// `struct ath11k_hw_ops` (non-RX-descriptor members).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HwOps {
    pub name: &'static str,
    /// `get_hw_mac_from_pdev_id`.
    pub mac_from_pdev: MacMap,
    pub wmi_init_config: WmiInitConfig,
    /// `mac_id_to_pdev_id` / `mac_id_to_srng_id`: `true` = the ipq8074
    /// pair (`pdev = mac_id`, `srng = 0`), `false` = qca6390
    /// (`pdev = 0`, `srng = mac_id`).
    pub mac_id_ipq8074: bool,
    pub tx_mesh: TxMesh,
    pub reo_setup: ReoSetup,
    pub ring_selector: RingSelector,
}

pub const IPQ8074_OPS: HwOps = HwOps {
    name: "ipq8074_ops",
    mac_from_pdev: MacMap::Ipq8074,
    wmi_init_config: WmiInitConfig::Ipq8074,
    mac_id_ipq8074: true,
    tx_mesh: TxMesh::Ipq8074Info2,
    reo_setup: ReoSetup::Ipq8074,
    ring_selector: RingSelector::Cpu,
};
pub const IPQ6018_OPS: HwOps = HwOps {
    name: "ipq6018_ops",
    mac_from_pdev: MacMap::Identity,
    ..IPQ8074_OPS
};
pub const QCA6390_OPS: HwOps = HwOps {
    name: "qca6390_ops",
    mac_from_pdev: MacMap::Ipq8074,
    wmi_init_config: WmiInitConfig::Qca6390,
    mac_id_ipq8074: false,
    tx_mesh: TxMesh::Ipq8074Info2,
    reo_setup: ReoSetup::Ipq8074,
    ring_selector: RingSelector::Cpu,
};
pub const QCN9074_OPS: HwOps = HwOps {
    name: "qcn9074_ops",
    mac_from_pdev: MacMap::Identity,
    tx_mesh: TxMesh::Qcn9074Info3,
    ..IPQ8074_OPS
};
pub const WCN6855_OPS: HwOps = HwOps {
    name: "wcn6855_ops",
    tx_mesh: TxMesh::Qcn9074Info3,
    reo_setup: ReoSetup::Wcn6855,
    ..QCA6390_OPS
};
pub const WCN6750_OPS: HwOps = HwOps {
    name: "wcn6750_ops",
    ring_selector: RingSelector::FlowHash,
    ..WCN6855_OPS
};
pub const IPQ5018_OPS: HwOps = HwOps {
    name: "ipq5018_ops",
    reo_setup: ReoSetup::Ipq5018,
    ..QCN9074_OPS
};

impl HwRev {
    /// `hw_params.hw_ops`.
    pub const fn hw_ops(self) -> Option<&'static HwOps> {
        Some(match self {
            HwRev::Ipq8074 => &IPQ8074_OPS,
            HwRev::Ipq6018Hw10 => &IPQ6018_OPS,
            HwRev::Qca6390Hw20 => &QCA6390_OPS,
            HwRev::Qcn9074Hw10 => &QCN9074_OPS,
            HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
                &WCN6855_OPS
            }
            HwRev::Wcn6750Hw10 => &WCN6750_OPS,
            HwRev::Ipq5018Hw10 => &IPQ5018_OPS,
            HwRev::Unknown => return None,
        })
    }
}

impl HwOps {
    /// `get_hw_mac_from_pdev_id` (`None` = `ATH11K_INVALID_HW_MAC_ID`).
    pub fn hw_mac_from_pdev_id(&self, pdev_idx: u32) -> Option<u32> {
        self.mac_from_pdev.mac_from_pdev(pdev_idx)
    }
    /// `mac_id_to_pdev_id`.
    pub const fn mac_id_to_pdev_id(&self, mac_id: u32) -> u32 {
        if self.mac_id_ipq8074 {
            mac_id
        } else {
            0
        }
    }
    /// `mac_id_to_srng_id`.
    pub const fn mac_id_to_srng_id(&self, mac_id: u32) -> u32 {
        if self.mac_id_ipq8074 {
            0
        } else {
            mac_id
        }
    }
    /// `get_ring_selector`: `cpu` for the CPU flavour, `flow_hash` for
    /// WCN6750.
    pub const fn ring_selector(&self, cpu: u32, flow_hash: u32) -> u32 {
        match self.ring_selector {
            RingSelector::Cpu => cpu,
            RingSelector::FlowHash => flow_hash,
        }
    }

    /// `reo_setup` (end of `ath11k_dp_srng_common_setup`).
    pub fn reo_setup(&self, io: &impl ChipIo, regs: &HalRegs) {
        let aging = [
            regs.hal_reo1_aging_thresh_ix_0,
            regs.hal_reo1_aging_thresh_ix_1,
            regs.hal_reo1_aging_thresh_ix_2,
            regs.hal_reo1_aging_thresh_ix_3,
        ];
        match self.reo_setup {
            ReoSetup::Wcn6855 => {
                super::dp_ring::wcn6855_reo_setup(io, regs.hal_reo1_misc_ctl, aging)
            }
            ReoSetup::Ipq8074 => ipq_reo_setup(io, aging, 3, true),
            ReoSetup::Ipq5018 => ipq_reo_setup(io, aging, 4, false),
        }
    }
}

/// `ath11k_hw_ipq8074_reo_setup` (`shift` 3, map in the
/// `HASH_RING_MAP` field) and `ath11k_hw_ipq5018_reo_setup` (`shift`
/// 4, map written raw).
fn ipq_reo_setup(io: &impl ChipIo, aging: [u32; 4], shift: u32, field: bool) {
    let sw = [
        HAL_HASH_ROUTING_RING_SW1,
        HAL_HASH_ROUTING_RING_SW2,
        HAL_HASH_ROUTING_RING_SW3,
        HAL_HASH_ROUTING_RING_SW4,
    ];
    let mut map = 0u32;
    for i in 0..8 {
        map |= sw[i % 4] << (shift * i as u32);
    }
    let mut val = io.read32(REO_BASE + HAL_REO1_GEN_ENABLE);
    val &= !HAL_REO1_GEN_ENABLE_FRAG_DST_RING;
    val |= field_prep(HAL_REO1_GEN_ENABLE_FRAG_DST_RING, ring_id::REO2SW1)
        | field_prep(HAL_REO1_GEN_ENABLE_AGING_LIST_ENABLE, 1)
        | field_prep(HAL_REO1_GEN_ENABLE_AGING_FLUSH_ENABLE, 1);
    io.write32(REO_BASE + HAL_REO1_GEN_ENABLE, val);
    for a in aging {
        io.write32(REO_BASE + a, HAL_DEFAULT_REO_TIMEOUT_USEC);
    }
    let v = if field {
        field_prep(HAL_REO_DEST_RING_CTRL_HASH_RING_MAP, map)
    } else {
        map
    };
    for ix in [
        HAL_REO1_DEST_RING_CTRL_IX_0,
        HAL_REO1_DEST_RING_CTRL_IX_1,
        HAL_REO1_DEST_RING_CTRL_IX_2,
        HAL_REO1_DEST_RING_CTRL_IX_3,
    ] {
        io.write32(REO_BASE + ix, v);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "hw_ops_tests.rs"]
mod tests;
