//! ath11k AHB / platform glue — IPQ8074, IPQ6018, IPQ5018, WCN6750.
//!
//! Linux `drivers/net/wireless/ath/ath11k/ahb.c` (+ the AHB rows of
//! `core.c::ath11k_hw_params`, `hw.c`, `ce.c`, `pcic.c`) on top of the
//! Qualcomm SoC layer `narf_drivers_qcom_soc`:
//!
//! - [`AhbChip`] / [`AHB_OF_MATCH`] — `ath11k_ahb_of_match`.
//! - [`AhbHwParams`] — the AHB `ath11k_hw_params` entries (CE tables,
//!   ring masks, HAL register maps, QMI instance ids, CE remap/IE
//!   addresses, bus flavour, firmware directory, BDF address).
//! - [`IRQ_NAMES`], [`ce_irqs`], [`ext_irq_groups`] — the 52 named
//!   platform interrupts and `ath11k_ahb_config_{irq,ext_irq}`'s CE and
//!   DP-group mapping.
//! - [`wcn6750_window_offset`] — WCN6750's static register windows.
//! - [`probe_resources`] — `ath11k_ahb_setup_resources`,
//!   `_setup_msi_resources` (WCN6750 hybrid bus), `_setup_msa_resources`
//!   (`fixed_fw_mem`), `_ce_remap`, `qcom,rproc` and `wlan-smp2p-out`.
//! - [`AhbRemote`] — `ath11k_core_get_rproc` + `power_up`/`power_down`
//!   (`rproc_boot`/`rproc_shutdown`) over the WCSS or PAS loader.
//!
//! QMI rides QRTR over GLINK ([`super::qrtr_glink`]); the WLFW AHB paths
//! (`fixed_mem_region`, `fixed_bdf_addr`, DEVICE_INFO) take
//! [`AhbChip::wlfw_hw_params`]. The HIF is [`super::ahb_hif`], the DT
//! bring-up [`super::ahb_probe`], the per-SoC `hw_ops`
//! [`super::hw_ops`]. Not here (ledger rows `ipq8074_enablement`, …):
//! the multi-pdev core/DP runtime; see
//! `drivers/wireless/specification/ath11k.md` §8.

use alloc::string::String;
use alloc::vec::Vec;

use narf_drivers_qcom_soc::dt::{self, DtError, PlatformDevice};
use narf_drivers_qcom_soc::platform::{self, Q6Platform, RprocKind};

use super::ce::{CeAttr, CeRecv, CeSend, CE_ATTR_DIS_INTR, CE_ATTR_FLAGS};
use super::htc::{
    svc_id, ServiceToPipe, PIPEDIR_IN, PIPEDIR_INOUT, PIPEDIR_INOUT_H2H, PIPEDIR_OUT,
    TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
};
use super::hw::{
    HalRegs, HwParams, HwRev, MsiConfig, MsiUser, RingMask, ATH11K_EXT_IRQ_GRP_NUM_MAX,
    IPQ5018_REGS, IPQ8074_REGS, MSI_CONFIG_NONE, RING_MASK_IPQ8074, RING_MASK_WCN6750,
    WCN6750_REGS,
};
use super::qmi_wlfw::{
    CeTgtPipeCfg, WlfwHwParams, ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_IPQ8074,
    TARGET_CE_CONFIG_WLAN_QCA6390,
};

/// `ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750`.
pub const ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750: u32 = 0x03;

/// The AHB subset of Linux `enum ath11k_hw_rev`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AhbChip {
    Ipq8074,
    Ipq6018Hw10,
    Ipq5018Hw10,
    Wcn6750Hw10,
}

/// `ath11k_ahb_of_match`.
pub const AHB_OF_MATCH: [(&str, AhbChip); 4] = [
    ("qcom,ipq8074-wifi", AhbChip::Ipq8074),
    ("qcom,ipq6018-wifi", AhbChip::Ipq6018Hw10),
    ("qcom,wcn6750-wifi", AhbChip::Wcn6750Hw10),
    ("qcom,ipq5018-wifi", AhbChip::Ipq5018Hw10),
];

/// Which RX descriptor layout `hal_desc_sz` names.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HalDesc {
    /// `struct hal_rx_desc_ipq8074` (ported: `super::ipq8074`).
    Ipq8074,
    /// `struct hal_rx_desc_qcn9074` (not ported; shared QCN9074 gap).
    Qcn9074,
}

/// `struct ce_ie_addr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CeIeAddr {
    pub ie1: u32,
    pub ie2: u32,
    pub ie3: u32,
}

/// `CE_HOST_IE_ADDRESS` / `_2_` / `_3_` (ce.h).
pub const CE_IE_ADDR_IPQ8074: CeIeAddr = CeIeAddr {
    ie1: 0x00a1_803c,
    ie2: 0x00a1_8040,
    ie3: 0x00a1_803c,
};
/// `CE_HOST_IPQ5018_IE_*_ADDRESS - HAL_IPQ5018_CE_WFSS_REG_BASE`.
pub const CE_IE_ADDR_IPQ5018: CeIeAddr = CeIeAddr {
    ie1: 0x0841_804c - HAL_IPQ5018_CE_WFSS_REG_BASE,
    ie2: 0x0841_8050 - HAL_IPQ5018_CE_WFSS_REG_BASE,
    ie3: 0x0841_804c - HAL_IPQ5018_CE_WFSS_REG_BASE,
};
/// `CE_HOST_IE_3_SHIFT`.
pub const CE_HOST_IE_3_SHIFT: u32 = 0xc;
pub const HAL_IPQ5018_CE_WFSS_REG_BASE: u32 = 0x0840_0000;
pub const HAL_IPQ5018_CE_SIZE: u32 = 0x20_0000;
/// `HAL_SEQ_WCSS_UMAC_OFFSET`.
pub const HAL_SEQ_WCSS_UMAC_OFFSET: u32 = 0x00a0_0000;
pub const ATH11K_PCI_WINDOW_START: u32 = 0x8_0000;
pub const ATH11K_PCI_WINDOW_RANGE_MASK: u32 = 0x7_ffff;

/// `struct ce_remap` — a CE register space outside the WiFi window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CeRemap {
    pub base: u32,
    pub size: u32,
}

/// `pdev_idx → hw mac` (`hw_ops->get_hw_mac_from_pdev_id`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacMap {
    /// `ath11k_hw_ipq8074_mac_from_pdev_id`: 0→0, 1→2, 2→1.
    Ipq8074,
    /// `ath11k_hw_ipq6018_mac_from_pdev_id`: identity.
    Identity,
}

impl MacMap {
    pub fn mac_from_pdev(self, pdev: u32) -> Option<u32> {
        match (self, pdev) {
            (MacMap::Identity, p) => Some(p),
            (MacMap::Ipq8074, 0) => Some(0),
            (MacMap::Ipq8074, 1) => Some(2),
            (MacMap::Ipq8074, 2) => Some(1),
            _ => None,
        }
    }
}

/// The AHB entries of Linux `ath11k_hw_params[]` (bus / CE / DP-IRQ
/// subset).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AhbHwParams {
    pub chip: AhbChip,
    pub name: &'static str,
    pub fw_dir: &'static str,
    pub max_radios: u32,
    pub bdf_addr: u32,
    pub regs: &'static HalRegs,
    pub ring_mask: &'static RingMask,
    pub qmi_service_ins_id: u32,
    pub host_ce_config: &'static [CeAttr],
    pub target_ce_config: &'static [CeTgtPipeCfg],
    pub svc_to_ce_map: &'static [ServiceToPipe],
    pub ce_ie_addr: CeIeAddr,
    pub ce_remap: Option<CeRemap>,
    pub single_pdev_only: bool,
    pub rxdma1_enable: bool,
    pub htt_peer_map_v2: bool,
    pub supports_shadow_regs: bool,
    pub credit_flow: bool,
    pub hal_desc: HalDesc,
    pub hybrid_bus_type: bool,
    pub static_window_map: bool,
    pub fixed_fw_mem: bool,
    pub fixed_bdf_addr: bool,
    pub smp2p_wow_exit: bool,
    pub mac_map: MacMap,
    /// `ath11k_msi_config` for the hybrid bus.
    pub msi: Option<&'static MsiConfig>,
}

impl AhbHwParams {
    pub fn ce_count(&self) -> usize {
        self.host_ce_config.len()
    }

    /// `ATH11K_CE_OFFSET(ab)`: [`AHB_CE_WINDOW_OFFSET`] where the CE
    /// space is remapped (IPQ5018), else 0.
    pub const fn ce_offset(&self) -> u32 {
        if self.ce_remap.is_some() {
            AHB_CE_WINDOW_OFFSET
        } else {
            0
        }
    }

    /// The same entry as the `HwRev`-keyed [`HwParams`] the CE / HAL /
    /// DP layers take (`rev` = [`AhbChip::hw_rev`]). IPQ parts have no
    /// MSI ([`MSI_CONFIG_NONE`]); WCN6750 uses its hybrid-bus layout.
    pub const fn hw_params(&self, rev: HwRev) -> HwParams {
        HwParams {
            hw_rev: rev,
            fw_dir: self.fw_dir,
            msi: match self.msi {
                Some(m) => m,
                None => &MSI_CONFIG_NONE,
            },
            fix_l1ss: None,
            static_window_map: self.static_window_map,
            regs: Some(self.regs),
            host_ce_config: self.host_ce_config,
            supports_shadow_regs: self.supports_shadow_regs,
            credit_flow: self.credit_flow,
            ring_mask: self.ring_mask,
            ce_offset: self.ce_offset(),
        }
    }
}

const fn attr(f: u32, src: u32, sz: u32, dst: u32, r: Option<CeRecv>, s: Option<CeSend>) -> CeAttr {
    CeAttr {
        flags: f,
        src_nentries: src,
        src_sz_max: sz,
        dest_nentries: dst,
        recv_cb: r,
        send_cb: s,
    }
}

/// Linux `ath11k_host_ce_config_ipq8074` (ce.c).
pub const HOST_CE_CONFIG_IPQ8074: [CeAttr; 12] = [
    attr(CE_ATTR_FLAGS, 16, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 2048, 256, 0, None, None),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::HttT2h), None),
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 0, 0, 0, None, None),
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 0, 0, 0, None, None),
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 0, 0, 0, None, None),
];

/// Linux `ath11k_host_ce_config_qcn9074` (IPQ5018 uses it, `CE_CNT_5018`
/// = 6). The CE0 `send_cb` matches Linux.
pub const HOST_CE_CONFIG_QCN9074_AHB: [CeAttr; 6] = [
    attr(CE_ATTR_FLAGS, 16, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 0, 2048, 32, Some(CeRecv::Htc), None),
    attr(CE_ATTR_FLAGS, 32, 2048, 0, None, Some(CeSend::Htc)),
    attr(CE_ATTR_FLAGS | CE_ATTR_DIS_INTR, 2048, 256, 0, None, None),
    attr(CE_ATTR_FLAGS, 0, 2048, 512, Some(CeRecv::HttT2h), None),
];

const fn tgt(n: u32, dir: u32, ent: u32, max: u32, flags: u32) -> CeTgtPipeCfg {
    CeTgtPipeCfg {
        pipe_num: n,
        pipe_dir: dir,
        nentries: ent,
        nbytes_max: max,
        flags,
    }
}

/// Linux `ath11k_target_ce_config_wlan_ipq8074` (`target_ce_count` 11).
pub const TARGET_CE_CONFIG_WLAN_IPQ8074: [CeTgtPipeCfg; 11] = [
    tgt(0, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(1, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(2, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(3, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(4, PIPEDIR_OUT, 256, 256, CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
    tgt(5, PIPEDIR_IN, 32, 2048, 0),
    tgt(6, PIPEDIR_INOUT, 32, 65535, CE_ATTR_FLAGS),
    tgt(7, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(8, PIPEDIR_INOUT, 32, 65535, CE_ATTR_FLAGS),
    tgt(9, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(10, PIPEDIR_INOUT_H2H, 0, 0, CE_ATTR_FLAGS),
];

/// Linux `ath11k_target_ce_config_wlan_ipq5018` (`TARGET_CE_CNT_5018` 9).
pub const TARGET_CE_CONFIG_WLAN_IPQ5018: [CeTgtPipeCfg; 9] = [
    tgt(0, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(1, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(2, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(3, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS),
    tgt(4, PIPEDIR_OUT, 256, 256, CE_ATTR_FLAGS | CE_ATTR_DIS_INTR),
    tgt(5, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS),
    tgt(6, PIPEDIR_INOUT, 32, 16384, CE_ATTR_FLAGS),
    tgt(7, PIPEDIR_OUT, 32, 2048, 0x2000),
    tgt(8, PIPEDIR_INOUT, 32, 16384, CE_ATTR_FLAGS),
];

const fn s2p(service_id: u16, pipedir: u32, pipenum: u32) -> ServiceToPipe {
    ServiceToPipe {
        service_id: service_id as u32,
        pipedir,
        pipenum,
    }
}

macro_rules! ipq_common_svc {
    () => {
        [
            s2p(svc_id::WMI_DATA_VO, PIPEDIR_OUT, 3),
            s2p(svc_id::WMI_DATA_VO, PIPEDIR_IN, 2),
            s2p(svc_id::WMI_DATA_BK, PIPEDIR_OUT, 3),
            s2p(svc_id::WMI_DATA_BK, PIPEDIR_IN, 2),
            s2p(svc_id::WMI_DATA_BE, PIPEDIR_OUT, 3),
            s2p(svc_id::WMI_DATA_BE, PIPEDIR_IN, 2),
            s2p(svc_id::WMI_DATA_VI, PIPEDIR_OUT, 3),
            s2p(svc_id::WMI_DATA_VI, PIPEDIR_IN, 2),
            s2p(svc_id::WMI_CONTROL, PIPEDIR_OUT, 3),
            s2p(svc_id::WMI_CONTROL, PIPEDIR_IN, 2),
        ]
    };
}

const IPQ_HEAD: [ServiceToPipe; 10] = ipq_common_svc!();
const IPQ_TAIL: [ServiceToPipe; 7] = [
    s2p(svc_id::RSVD_CTRL, PIPEDIR_OUT, 0),
    s2p(svc_id::RSVD_CTRL, PIPEDIR_IN, 1),
    s2p(svc_id::TEST_RAW_STREAMS, PIPEDIR_OUT, 0),
    s2p(svc_id::TEST_RAW_STREAMS, PIPEDIR_IN, 1),
    s2p(svc_id::HTT_DATA_MSG, PIPEDIR_OUT, 4),
    s2p(svc_id::HTT_DATA_MSG, PIPEDIR_IN, 1),
    s2p(svc_id::PKT_LOG, PIPEDIR_IN, 5),
];

const fn concat<const A: usize, const B: usize, const C: usize, const N: usize>(
    a: [ServiceToPipe; A],
    b: [ServiceToPipe; B],
    c: [ServiceToPipe; C],
) -> [ServiceToPipe; N] {
    let mut out = [s2p(0, 0, 0); N];
    let mut i = 0;
    while i < A {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < B {
        out[A + j] = b[j];
        j += 1;
    }
    let mut k = 0;
    while k < C {
        out[A + B + k] = c[k];
        k += 1;
    }
    out
}

/// Linux `ath11k_target_service_to_ce_map_wlan_ipq8074` (21 entries).
pub const TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ8074: [ServiceToPipe; 21] = concat(
    IPQ_HEAD,
    [
        s2p(svc_id::WMI_CONTROL_MAC1, PIPEDIR_OUT, 7),
        s2p(svc_id::WMI_CONTROL_MAC1, PIPEDIR_IN, 2),
        s2p(svc_id::WMI_CONTROL_MAC2, PIPEDIR_OUT, 9),
        s2p(svc_id::WMI_CONTROL_MAC2, PIPEDIR_IN, 2),
    ],
    IPQ_TAIL,
);

/// Linux `ath11k_target_service_to_ce_map_wlan_ipq6018` (19 entries).
pub const TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ6018: [ServiceToPipe; 19] = concat(
    IPQ_HEAD,
    [
        s2p(svc_id::WMI_CONTROL_MAC1, PIPEDIR_OUT, 7),
        s2p(svc_id::WMI_CONTROL_MAC1, PIPEDIR_IN, 2),
    ],
    IPQ_TAIL,
);

/// Linux `ath11k_target_service_to_ce_map_wlan_ipq5018` (17 entries).
pub const TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ5018: [ServiceToPipe; 17] =
    concat(IPQ_HEAD, [], IPQ_TAIL);

/// Linux `ath11k_target_service_to_ce_map_wlan_qcn9074`: the same 17
/// entries as IPQ5018 (no per-pdev WMI MAC1/MAC2 pipes).
pub const TARGET_SERVICE_TO_CE_MAP_WLAN_QCN9074: [ServiceToPipe; 17] =
    TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ5018;

/// `ath11k_msi_config` for `ATH11K_HW_WCN6750_HW10` (pcic.c).
pub const MSI_CONFIG_WCN6750: MsiConfig = MsiConfig {
    total_vectors: 28,
    users: &[
        MsiUser {
            name: "CE",
            num_vectors: 10,
            base_vector: 0,
        },
        MsiUser {
            name: "DP",
            num_vectors: 18,
            base_vector: 10,
        },
    ],
};

impl AhbChip {
    /// The `enum ath11k_hw_rev` value (`ath11k_ahb_probe`:
    /// `ab->hw_rev = (enum ath11k_hw_rev)of_device_get_match_data()`).
    pub const fn hw_rev(self) -> HwRev {
        match self {
            AhbChip::Ipq8074 => HwRev::Ipq8074,
            AhbChip::Ipq6018Hw10 => HwRev::Ipq6018Hw10,
            AhbChip::Ipq5018Hw10 => HwRev::Ipq5018Hw10,
            AhbChip::Wcn6750Hw10 => HwRev::Wcn6750Hw10,
        }
    }

    /// `ath11k_ahb_of_match` lookup over a node's compatible list.
    pub fn from_compatible(compat: &[String]) -> Option<Self> {
        AHB_OF_MATCH
            .iter()
            .find(|(c, _)| compat.iter().any(|x| x == c))
            .map(|(_, chip)| *chip)
    }

    /// The Linux `ath11k_hw_params[]` entry.
    pub const fn params(self) -> AhbHwParams {
        let ipq = AhbHwParams {
            chip: self,
            name: "ipq8074 hw2.0",
            fw_dir: "IPQ8074/hw2.0",
            max_radios: 3,
            bdf_addr: 0x4b0c_0000,
            regs: &IPQ8074_REGS,
            ring_mask: &RING_MASK_IPQ8074,
            qmi_service_ins_id: ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_IPQ8074,
            host_ce_config: &HOST_CE_CONFIG_IPQ8074,
            target_ce_config: &TARGET_CE_CONFIG_WLAN_IPQ8074,
            svc_to_ce_map: &TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ8074,
            ce_ie_addr: CE_IE_ADDR_IPQ8074,
            ce_remap: None,
            single_pdev_only: false,
            rxdma1_enable: true,
            htt_peer_map_v2: true,
            supports_shadow_regs: false,
            credit_flow: false,
            hal_desc: HalDesc::Ipq8074,
            hybrid_bus_type: false,
            static_window_map: false,
            fixed_fw_mem: false,
            fixed_bdf_addr: true,
            smp2p_wow_exit: false,
            mac_map: MacMap::Ipq8074,
            msi: None,
        };
        match self {
            AhbChip::Ipq8074 => ipq,
            AhbChip::Ipq6018Hw10 => AhbHwParams {
                name: "ipq6018 hw1.0",
                fw_dir: "IPQ6018/hw1.0",
                max_radios: 2,
                bdf_addr: 0x4abc_0000,
                svc_to_ce_map: &TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ6018,
                mac_map: MacMap::Identity,
                ..ipq
            },
            AhbChip::Ipq5018Hw10 => AhbHwParams {
                name: "ipq5018 hw1.0",
                fw_dir: "IPQ5018/hw1.0",
                max_radios: 1,
                bdf_addr: 0x4ba0_0000,
                regs: &IPQ5018_REGS,
                host_ce_config: &HOST_CE_CONFIG_QCN9074_AHB,
                target_ce_config: &TARGET_CE_CONFIG_WLAN_IPQ5018,
                svc_to_ce_map: &TARGET_SERVICE_TO_CE_MAP_WLAN_IPQ5018,
                ce_ie_addr: CE_IE_ADDR_IPQ5018,
                ce_remap: Some(CeRemap {
                    base: HAL_IPQ5018_CE_WFSS_REG_BASE,
                    size: HAL_IPQ5018_CE_SIZE,
                }),
                hal_desc: HalDesc::Qcn9074,
                mac_map: MacMap::Identity,
                ..ipq
            },
            AhbChip::Wcn6750Hw10 => AhbHwParams {
                name: "wcn6750 hw1.0",
                fw_dir: "WCN6750/hw1.0",
                max_radios: 1,
                bdf_addr: 0x4b0c_0000,
                regs: &WCN6750_REGS,
                ring_mask: &RING_MASK_WCN6750,
                qmi_service_ins_id: ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750,
                host_ce_config: &super::ce::HOST_CE_CONFIG_QCA6390,
                target_ce_config: &TARGET_CE_CONFIG_WLAN_QCA6390,
                svc_to_ce_map: &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
                single_pdev_only: true,
                rxdma1_enable: false,
                htt_peer_map_v2: false,
                supports_shadow_regs: true,
                credit_flow: true,
                hal_desc: HalDesc::Qcn9074,
                hybrid_bus_type: true,
                static_window_map: true,
                fixed_fw_mem: true,
                fixed_bdf_addr: false,
                smp2p_wow_exit: true,
                msi: Some(&MSI_CONFIG_WCN6750),
                ..ipq
            },
        }
    }

    /// The QMI fields of the same `ath11k_hw_params[]` entry
    /// (`core.c`): IPQ parts take target memory from the reserved
    /// region and write the BDF through `bdf_addr`; WCN6750 uses the
    /// hybrid bus (DEVICE_INFO) with firmware-owned memory.
    pub const fn wlfw_hw_params(self) -> WlfwHwParams {
        let p = self.params();
        let ipq = WlfwHwParams {
            qmi_service_ins_id: p.qmi_service_ins_id,
            m3_fw_support: false,
            internal_sleep_clock: false,
            global_reset: false,
            fw_mem_mode: 0,
            fixed_fw_mem: false,
            fixed_bdf_addr: true,
            supports_shadow_regs: false,
            fw_wmi_diag_event: false,
            supports_regdb: false,
            board_size: 256 * 1024,
            coldboot_cal_mm: true,
            coldboot_cal_ftm: true,
            cbcal_restart_fw: true,
            fixed_mem_region: true,
            hybrid_bus_type: false,
            bdf_addr: p.bdf_addr as u64,
            cal_offset: 128 * 1024,
        };
        match self {
            AhbChip::Ipq8074 | AhbChip::Ipq6018Hw10 | AhbChip::Ipq5018Hw10 => ipq,
            AhbChip::Wcn6750Hw10 => WlfwHwParams {
                fixed_fw_mem: true,
                fixed_bdf_addr: false,
                supports_shadow_regs: true,
                supports_regdb: true,
                cbcal_restart_fw: false,
                fixed_mem_region: false,
                hybrid_bus_type: true,
                ..ipq
            },
        }
    }
}

// ── interrupts ─────────────────────────────────────────────────────

/// Linux `ahb.c` `irq_name[ATH11K_IRQ_NUM_MAX]`.
pub const IRQ_NAMES: [&str; 52] = narf_drivers_qcom_soc_irq_names();

const fn narf_drivers_qcom_soc_irq_names() -> [&'static str; 52] {
    [
        "misc-pulse1",
        "misc-latch",
        "sw-exception",
        "watchdog",
        "ce0",
        "ce1",
        "ce2",
        "ce3",
        "ce4",
        "ce5",
        "ce6",
        "ce7",
        "ce8",
        "ce9",
        "ce10",
        "ce11",
        "host2wbm-desc-feed",
        "host2reo-re-injection",
        "host2reo-command",
        "host2rxdma-monitor-ring3",
        "host2rxdma-monitor-ring2",
        "host2rxdma-monitor-ring1",
        "reo2ost-exception",
        "wbm2host-rx-release",
        "reo2host-status",
        "reo2host-destination-ring4",
        "reo2host-destination-ring3",
        "reo2host-destination-ring2",
        "reo2host-destination-ring1",
        "rxdma2host-monitor-destination-mac3",
        "rxdma2host-monitor-destination-mac2",
        "rxdma2host-monitor-destination-mac1",
        "ppdu-end-interrupts-mac3",
        "ppdu-end-interrupts-mac2",
        "ppdu-end-interrupts-mac1",
        "rxdma2host-monitor-status-ring-mac3",
        "rxdma2host-monitor-status-ring-mac2",
        "rxdma2host-monitor-status-ring-mac1",
        "host2rxdma-host-buf-ring-mac3",
        "host2rxdma-host-buf-ring-mac2",
        "host2rxdma-host-buf-ring-mac1",
        "rxdma2host-destination-ring-mac3",
        "rxdma2host-destination-ring-mac2",
        "rxdma2host-destination-ring-mac1",
        "host2tcl-input-ring4",
        "host2tcl-input-ring3",
        "host2tcl-input-ring2",
        "host2tcl-input-ring1",
        "wbm2host-tx-completions-ring3",
        "wbm2host-tx-completions-ring2",
        "wbm2host-tx-completions-ring1",
        "tcl2host-status-ring",
    ]
}

/// `ATH11K_IRQ_CE0_OFFSET`.
pub const ATH11K_IRQ_CE0_OFFSET: usize = 4;
/// `ATH11K_EXT_IRQ_NUM_MAX`.
pub const ATH11K_EXT_IRQ_NUM_MAX: usize = 16;

/// `enum ext_irq_num` anchors (indices into [`IRQ_NAMES`]).
pub mod ext_irq {
    pub const REO2HOST_EXCEPTION: u8 = 22;
    pub const WBM2HOST_RX_RELEASE: u8 = 23;
    pub const REO2HOST_STATUS: u8 = 24;
    pub const REO2HOST_DESTINATION_RING1: u8 = 28;
    pub const PPDU_END_INTERRUPTS_MAC1: u8 = 34;
    pub const RXDMA2HOST_MONITOR_STATUS_RING_MAC1: u8 = 37;
    pub const HOST2RXDMA_HOST_BUF_RING_MAC1: u8 = 40;
    pub const RXDMA2HOST_DESTINATION_RING_MAC1: u8 = 43;
    pub const WBM2HOST_TX_COMPLETIONS_RING1: u8 = 50;
}

/// `ath11k_ahb_config_irq` (non-hybrid): `(ce_id, irq index)` for every
/// CE without `CE_ATTR_DIS_INTR`.
pub fn ce_irqs(p: &AhbHwParams) -> Vec<(usize, usize)> {
    p.host_ce_config
        .iter()
        .enumerate()
        .filter(|(_, a)| a.flags & CE_ATTR_DIS_INTR == 0)
        .map(|(i, _)| (i, ATH11K_IRQ_CE0_OFFSET + i))
        .collect()
}

/// `ath11k_ahb_config_ext_irq`: the [`IRQ_NAMES`] indices each of the 11
/// DP interrupt groups requests, in Linux's order.
pub fn ext_irq_groups(p: &AhbHwParams) -> [Vec<u8>; ATH11K_EXT_IRQ_GRP_NUM_MAX] {
    use ext_irq::*;
    let m = p.ring_mask;
    core::array::from_fn(|i| {
        let mut irqs = Vec::new();
        for j in 0..ATH11K_EXT_IRQ_NUM_MAX as u32 {
            let b = 1u32 << j;
            let jj = j as u8;
            if m.tx[i] as u32 & b != 0 {
                irqs.push(WBM2HOST_TX_COMPLETIONS_RING1.wrapping_sub(jj));
            }
            if m.rx[i] as u32 & b != 0 {
                irqs.push(REO2HOST_DESTINATION_RING1.wrapping_sub(jj));
            }
            if m.rx_err[i] as u32 & b != 0 {
                irqs.push(REO2HOST_EXCEPTION);
            }
            if m.rx_wbm_rel[i] as u32 & b != 0 {
                irqs.push(WBM2HOST_RX_RELEASE);
            }
            if m.reo_status[i] as u32 & b != 0 {
                irqs.push(REO2HOST_STATUS);
            }
            if j < p.max_radios {
                let mac = p.mac_map.mac_from_pdev(j).unwrap_or(0) as u8;
                if m.rxdma2host[i] as u32 & b != 0 {
                    irqs.push(RXDMA2HOST_DESTINATION_RING_MAC1 - mac);
                }
                if m.host2rxdma[i] as u32 & b != 0 {
                    irqs.push(HOST2RXDMA_HOST_BUF_RING_MAC1 - mac);
                }
                if m.rx_mon_status[i] as u32 & b != 0 {
                    irqs.push(PPDU_END_INTERRUPTS_MAC1 - mac);
                    irqs.push(RXDMA2HOST_MONITOR_STATUS_RING_MAC1 - mac);
                }
            }
        }
        irqs
    })
}

/// `ath11k_ahb_ce_irq_enable` register writes for `ce_id`:
/// `(register offset, bit)` pairs set in IE1 (source ring) and IE2/IE3
/// (destination ring), relative to `ab->mem` with the CE window offset
/// `ce_offset` (`ATH11K_CE_OFFSET`, 0 unless the CE space is remapped).
pub fn ce_irq_enable_bits(p: &AhbHwParams, ce_id: usize, ce_offset: u32) -> Vec<(u32, u32)> {
    let Some(a) = p.host_ce_config.get(ce_id) else {
        return Vec::new();
    };
    let ie = p.ce_ie_addr;
    let mut out = Vec::new();
    if a.src_nentries != 0 {
        out.push((ie.ie1 + ce_offset, ce_id as u32));
    }
    if a.dest_nentries != 0 {
        out.push((ie.ie2 + ce_offset, ce_id as u32));
        out.push((ie.ie3 + ce_offset, ce_id as u32 + CE_HOST_IE_3_SHIFT));
    }
    out
}

/// `ath11k_ahb_get_window_start_wcn6750` + offset masking: the byte
/// offset into the WCN6750 register space for HAL offset `offset`.
pub fn wcn6750_window_offset(regs: &HalRegs, offset: u32) -> u32 {
    let start = if (offset ^ HAL_SEQ_WCSS_UMAC_OFFSET) < ATH11K_PCI_WINDOW_RANGE_MASK {
        ATH11K_PCI_WINDOW_START
    } else if (offset ^ regs.hal_seq_wcss_umac_ce0_src_reg) < ATH11K_PCI_WINDOW_RANGE_MASK {
        2 * ATH11K_PCI_WINDOW_START
    } else {
        0
    };
    start + (offset & ATH11K_PCI_WINDOW_RANGE_MASK)
}

/// `enum ath11k_ahb_smp2p_msg_id`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum PowerSaveMsg {
    Enter = 1,
    Exit = 2,
}

/// The `wlan` SMP2P value `ath11k_ahb_hif_{suspend,resume}` writes:
/// `seq_no` in bits 31:16, message in 15:0.
pub const fn smp2p_power_save_value(seq_no: u16, msg: PowerSaveMsg) -> u32 {
    ((seq_no as u32) << 16) | msg as u32
}

// ── register access (HIF read32/write32) ───────────────────────────

/// `ATH11K_CE_OFFSET(ab)` for a part whose CE space is remapped
/// (IPQ5018): Linux adds the VA distance `mem_ce - mem` to CE register
/// offsets; NARF uses this fixed marker instead, above any WiFi window,
/// and [`AhbIo`] routes offsets at or above it to the CE mapping.
pub const AHB_CE_WINDOW_OFFSET: u32 = 0x4000_0000;

/// `ath11k_ahb_read32`/`write32` (IPQ: `ab->mem + offset`, CE offsets via
/// `ab->mem_ce`) and `ath11k_ahb_window_{read,write}32_wcn6750` (static
/// windows). For WCN6750 `mem` is the BAR the QMI DEVICE_INFO response
/// names (`ath11k_qmi_request_device_info`), not a DT `reg`.
#[derive(Debug)]
pub struct AhbIo<R: narf_drivers_qcom_soc::io::RegIo> {
    pub mem: R,
    pub ce: Option<R>,
    /// `Some` for WCN6750's static-window access.
    pub window: Option<&'static HalRegs>,
}

impl<R: narf_drivers_qcom_soc::io::RegIo> AhbIo<R> {
    /// The `ATH11K_CE_OFFSET` this mapping implies.
    pub fn ce_offset(&self) -> u32 {
        if self.ce.is_some() {
            AHB_CE_WINDOW_OFFSET
        } else {
            0
        }
    }

    fn route(&self, offset: u32) -> (&R, u32) {
        if let Some(ce) = &self.ce {
            if offset >= AHB_CE_WINDOW_OFFSET {
                return (ce, offset - AHB_CE_WINDOW_OFFSET);
            }
        }
        match self.window {
            Some(regs) => (&self.mem, wcn6750_window_offset(regs, offset)),
            None => (&self.mem, offset),
        }
    }
}

impl<R: narf_drivers_qcom_soc::io::RegIo> super::power::ChipIo for AhbIo<R> {
    fn read32(&self, offset: u32) -> u32 {
        let (r, o) = self.route(offset);
        r.read32(o)
    }
    fn write32(&self, offset: u32, value: u32) {
        let (r, o) = self.route(offset);
        r.write32(o, value)
    }
    fn delay_ms(&self, ms: u32) {
        let deadline = narf_time::Deadline::after_ms(ms as u64);
        narf_scheduler::responsive_spin_until(
            || deadline.expired(),
            narf_time::Deadline::after_ms(ms as u64 + 1),
        );
    }
    /// AHB has no sliding window to restore.
    fn restore_window(&self) {}
}

/// `ath11k_ahb_ce_irq_enable` / `_disable` for one CE through `io`
/// (`setbit32`/`clearbit32` read-modify-writes).
pub fn ce_irq_set(
    io: &impl super::power::ChipIo,
    p: &AhbHwParams,
    ce_id: usize,
    ce_offset: u32,
    enable: bool,
) {
    for (reg, bit) in ce_irq_enable_bits(p, ce_id, ce_offset) {
        let v = io.read32(reg);
        io.write32(
            reg,
            if enable {
                v | (1 << bit)
            } else {
                v & !(1 << bit)
            },
        );
    }
}

/// `ath11k_ahb_ce_irqs_enable`: every CE without `CE_ATTR_DIS_INTR`.
pub fn ce_irqs_set(io: &impl super::power::ChipIo, p: &AhbHwParams, ce_offset: u32, enable: bool) {
    for (ce, _) in ce_irqs(p) {
        ce_irq_set(io, p, ce, ce_offset, enable);
    }
}

// ── resources ──────────────────────────────────────────────────────

/// Probe failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AhbError {
    /// No `ath11k_ahb_of_match` compatible.
    Unsupported,
    Dt(DtError),
    /// A named interrupt the CE/DP mapping needs is missing.
    MissingIrq(&'static str),
    /// `qcom,rproc` absent (`-ENOENT`).
    NoRproc,
    /// The remoteproc's loader does not match the chip (IPQ: WCSS;
    /// WCN6750: PAS).
    LoaderMismatch,
    /// A bring-up action failed with this errno.
    Failed(i32),
}

impl From<DtError> for AhbError {
    fn from(e: DtError) -> Self {
        AhbError::Dt(e)
    }
}

/// WCN6750 hybrid-bus MSI (`ath11k_ahb_setup_msi_resources`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridMsi {
    /// `reg[0]` start — the MSI doorbell address the device writes.
    pub addr: u64,
    /// `interrupts[1] + 32` (the first SPI number + 32).
    pub ep_base_data: u32,
    /// GIC hwirqs of the first `total_vectors` interrupts.
    pub irqs: Vec<u32>,
}

/// Everything `ath11k_ahb_probe` reads from the devicetree.
#[derive(Clone, Debug)]
pub struct AhbResources {
    pub chip: AhbChip,
    pub params: AhbHwParams,
    pub node: PlatformDevice,
    /// `reg[0]` (non-hybrid): the WiFi register window (`ab->mem`).
    pub mem: Option<(u64, u64)>,
    /// The CE register window (`ab->mem_ce`): `mem`, or the remap.
    pub ce: Option<(u64, u64)>,
    /// `(irq index, GIC hwirq)` for every named interrupt the CE and DP
    /// groups request (non-hybrid).
    pub irqs: Vec<(usize, u32)>,
    pub msi: Option<HybridMsi>,
    /// `fixed_fw_mem`: (MSA region, CE region) from `memory-region[0/1]`.
    pub msa: Option<((u64, u64), (u64, u64))>,
    /// `qcom,rproc`.
    pub rproc_phandle: u32,
    /// `smp2p_wow_exit`: the `wlan-smp2p-out` state (edge, entry, bit).
    pub wlan_smp2p_out: Option<(String, String, u32)>,
}

/// Every AHB WiFi node in the tree with its chip.
pub fn find_ahb_devices(blob: &[u8]) -> Vec<(PlatformDevice, AhbChip)> {
    let mut out = Vec::new();
    for (compat, chip) in AHB_OF_MATCH {
        for n in dt::find_compatible(blob, compat) {
            if n.enabled {
                out.push((n, chip));
            }
        }
    }
    out
}

/// `ath11k_ahb_probe`'s resource half.
pub fn probe_resources(blob: &[u8], node: &PlatformDevice) -> Result<AhbResources, AhbError> {
    let chip = AhbChip::from_compatible(&node.compatible).ok_or(AhbError::Unsupported)?;
    let p = chip.params();
    let mut res = AhbResources {
        chip,
        params: p,
        node: node.clone(),
        mem: None,
        ce: None,
        irqs: Vec::new(),
        msi: None,
        msa: None,
        rproc_phandle: 0,
        wlan_smp2p_out: None,
    };
    if p.hybrid_bus_type {
        let addr = node.reg(0)?.0;
        let first = node
            .irqs
            .first()
            .ok_or(AhbError::MissingIrq("interrupts"))?;
        let spi = *first
            .cells
            .get(1)
            .ok_or(AhbError::MissingIrq("interrupts"))?;
        let total = p.msi.map(|m| m.total_vectors).unwrap_or(0) as usize;
        if node.irqs.len() < total {
            return Err(AhbError::MissingIrq("msi vectors"));
        }
        let irqs = node.irqs[..total]
            .iter()
            .map(|s| s.gic_hwirq().ok_or(AhbError::MissingIrq("msi vector")))
            .collect::<Result<Vec<_>, _>>()?;
        res.msi = Some(HybridMsi {
            addr,
            ep_base_data: spi + 32,
            irqs,
        });
    } else {
        let mem = node.reg(0)?;
        res.mem = Some(mem);
        res.ce = Some(match p.ce_remap {
            Some(r) => (r.base as u64, r.size as u64),
            None => mem,
        });
        let mut wanted: Vec<usize> = ce_irqs(&p).into_iter().map(|(_, i)| i).collect();
        for g in ext_irq_groups(&p) {
            wanted.extend(g.into_iter().map(|i| i as usize));
        }
        for idx in wanted {
            let name = IRQ_NAMES[idx];
            let spec = node
                .irq_by_name(name)
                .map_err(|_| AhbError::MissingIrq(name))?;
            let hw = spec.gic_hwirq().ok_or(AhbError::MissingIrq(name))?;
            res.irqs.push((idx, hw));
        }
    }
    if p.fixed_fw_mem {
        res.msa = Some((node.memory_region(0)?, node.memory_region(1)?));
    }
    if p.smp2p_wow_exit {
        let s = node.phandle_args_by_name(
            blob,
            "qcom,smem-states",
            "#qcom,smem-state-cells",
            "qcom,smem-state-names",
            "wlan-smp2p-out",
        )?;
        let (edge, entry) = platform::smp2p_entry(blob, s.phandle)
            .ok_or(AhbError::Dt(DtError::Malformed("wlan-smp2p-out")))?;
        res.wlan_smp2p_out = Some((edge, entry, s.args.first().copied().unwrap_or(0)));
    }
    res.rproc_phandle = node.prop_u32("qcom,rproc").ok_or(AhbError::NoRproc)?;
    Ok(res)
}

/// `ath11k_core_get_rproc`: the remote processor behind `qcom,rproc`,
/// resolved to its loader resources.
#[derive(Clone, Debug)]
pub struct AhbRemote {
    pub platform: Q6Platform,
}

impl AhbRemote {
    pub fn resolve(blob: &[u8], res: &AhbResources) -> Result<Self, AhbError> {
        let platform = platform::q6_platform(blob, res.rproc_phandle)?;
        Ok(Self { platform })
    }

    /// Whether the chip/loader pairing matches Linux: IPQ parts boot a
    /// host-reset WCSS, WCN6750 a TrustZone PAS WPSS.
    pub fn loader_matches(&self, chip: AhbChip) -> bool {
        matches!(
            (chip, self.platform.kind),
            (AhbChip::Wcn6750Hw10, RprocKind::Pas { .. })
                | (
                    AhbChip::Ipq8074 | AhbChip::Ipq6018Hw10 | AhbChip::Ipq5018Hw10,
                    RprocKind::Wcss
                )
        )
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ahb_tests.rs"]
mod tests;
