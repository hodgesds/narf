//! Multi-pdev bring-up pieces for IPQ8074 / IPQ6018 / QCN9074: per-pdev
//! DP rings with the rxdma1 monitor rings and their HTT SRING_SETUP
//! batch, the `ath11k_init_wmi_config_ipq8074` resource config and the
//! band-to-mac init TLVs, and the QCN9074 register map / static BAR
//! windows. Fixture-only (RAM-backed HAL, recording register I/O);
//! nothing has run on IPQ / QCN9074 silicon.

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::core::CoreConfig;
use super::dp_ring::*;
use super::hal::*;
use super::power::ChipIo;

struct RecIo;
impl ChipIo for RecIo {
    fn read32(&self, _offset: u32) -> u32 {
        0
    }
    fn write32(&self, _offset: u32, _value: u32) {}
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}
use super::hw::*;
use super::wmi::{self, InitCmdParam, PdevCap, ServiceReadyExt, TargetResourceConfig};

const SIZES: DpRingSizes = DpRingSizes {
    wbm_release: 16,
    tcl_cmd: 8,
    tcl_status: 8,
    tcl_data: Some(8),
    tx_comp: 16,
    reo_reinject: 8,
    rx_release: 16,
    reo_exception: 16,
    reo_cmd: 8,
    reo_status: 16,
    reo_dst: 16,
    rxdma_buf: 16,
    rx_mac_buf: 16,
    rxdma_err_dst: 16,
    rxdma_mon_status: 8,
    rxdma_mon_buf: 8,
    rxdma_mon_dst: 8,
    rxdma_mon_desc: 8,
    tx_status_fifo: 8,
    n_link_desc: Some(64),
};

/// `ath11k_dp_pdev_alloc` over three radios: each pdev gets refill,
/// RXDMA error, the three rxdma1 monitor rings and the monitor-status
/// ring (six HTT SRING_SETUP messages), the monitor link descriptors
/// land in its desc ring, pdevs allocate only in order, and
/// `pdev_free` returns every ring to the HAL.
fn smoke_ath11k_multi_pdev_dp_rings() -> TestResult {
    for rev in [HwRev::Ipq8074, HwRev::Ipq6018Hw10, HwRev::Qcn9074Hw10] {
        let Some(cfg) = DpHwParams::for_rev(rev) else {
            return TestResult::Fail("multi-pdev DP params");
        };
        kt_assert!(cfg.rxdma1_enable && cfg.htt_peer_map_v2 && !cfg.single_pdev_only);
        kt_assert_eq!(cfg.num_tx_rings(), 3);
        let mut hal = Box::new(Hal::new(&cfg.hw).expect("hal"));
        let io = RecIo;
        let mut dp = Box::new(Dp::alloc(&mut hal, &io, &cfg, SIZES, None).expect("dp alloc"));
        dp.pdev_reo_setup(&mut hal, &io).expect("reo setup");
        let before = hal.srng_ids().len();
        kt_assert!(
            dp.pdev_alloc(&mut hal, &io, 1).is_err(),
            "pdev 1 before pdev 0"
        );
        for mac in 0..3u32 {
            let msgs = match dp.pdev_alloc(&mut hal, &io, mac) {
                Ok(m) => m,
                Err(_) => return TestResult::Fail("pdev alloc"),
            };
            kt_assert_eq!(msgs.len(), 6);
        }
        kt_assert!(dp.pdev_alloc(&mut hal, &io, 2).is_err(), "pdev 2 twice");
        kt_assert_eq!(dp.extra_pdevs.len(), 2);
        let macs: Vec<u32> = dp.pdevs().map(|p| p.mac_id).collect();
        kt_assert_eq!(macs, vec![0, 1, 2]);
        for p in dp.pdevs() {
            kt_assert!(p.rxdma_mon_buf_ring.is_some() && p.rxdma_mon_dst_ring.is_some());
            kt_assert!(
                p.mon_link_desc_posted > 0,
                "monitor link descriptors posted"
            );
            kt_assert_eq!(p.mon_link_desc_banks.len(), 1);
        }
        kt_assert_eq!(hal.srng_ids().len(), before + 3 * 6);
        dp.pdev_free(&mut hal);
        kt_assert_eq!(hal.srng_ids().len(), before);
        kt_assert!(dp.pdev.is_none() && dp.extra_pdevs.is_empty());
    }
    // Single-pdev parts keep mac 0 only and no rxdma1 rings.
    let cfg = DpHwParams::for_rev(HwRev::Wcn6750Hw10).unwrap();
    let mut hal = Box::new(Hal::new(&cfg.hw).expect("hal"));
    let io = RecIo;
    let mut dp = Box::new(Dp::alloc(&mut hal, &io, &cfg, SIZES, None).expect("dp"));
    dp.pdev_reo_setup(&mut hal, &io).expect("reo");
    kt_assert!(dp.pdev_alloc(&mut hal, &io, 0).is_ok());
    kt_assert!(dp.pdev_alloc(&mut hal, &io, 1).is_err());
    kt_assert!(dp
        .pdev
        .as_ref()
        .is_some_and(|p| p.rxdma_mon_buf_ring.is_none()));
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_multi_pdev_dp_rings);

/// `ath11k_init_wmi_config_ipq8074` for 2 and 3 radios, the band-to-mac
/// map from SERVICE_READY_EXT and the multi-pdev WMI_INIT_CMDID tail.
fn smoke_ath11k_multi_pdev_wmi_init() -> TestResult {
    let r = TargetResourceConfig::ipq8074(17, 512, 3, 4, true);
    // TARGET_NUM_PEERS_DBS_SBS = 3 * (512 + 17); num_tids = 2p + 4*17 + 8.
    kt_assert_eq!((r.num_vdevs, r.num_peers, r.num_tids), (51, 1587, 3250));
    kt_assert_eq!(
        (r.tx_chain_mask, r.num_offload_peers, r.num_msdu_desc),
        (0xf, 4, 2500)
    );
    kt_assert_eq!(r.beacon_tx_offload_max_vdev, 3 * 16 + 3);
    kt_assert_eq!((r.peer_map_unmap_v2_support, r.twt_ap_pdev_count), (1, 3));
    kt_assert_eq!(r.flag1, (1 << 5) | (1 << 18));
    let r2 = TargetResourceConfig::ipq8074(17, 512, 2, 2, false);
    kt_assert_eq!((r2.num_vdevs, r2.num_peers), (34, 1058));

    let mut ext = ServiceReadyExt::default();
    for (i, bands) in [(0u32, 1u32), (1, 2), (2, 2)] {
        ext.pdevs.push(PdevCap {
            pdev_id: i + 1,
            supported_bands: bands,
            ..Default::default()
        });
        ext.hal_reg_caps.push(wmi::HalRegCapExt {
            phy_id: i,
            low_2ghz_chan: 2312,
            high_2ghz_chan: 2732,
            low_5ghz_chan: 5150 + i * 100,
            high_5ghz_chan: 5900,
            ..Default::default()
        });
    }
    let b = wmi::band_to_mac(&ext, 3);
    kt_assert_eq!(b.len(), 3);
    kt_assert_eq!(
        (b[0].pdev_id, b[0].start_freq, b[0].end_freq),
        (1, 2312, 2732)
    );
    kt_assert_eq!(
        (b[2].pdev_id, b[2].start_freq, b[2].end_freq),
        (3, 5350, 5900)
    );
    let single = wmi::init_cmd(&InitCmdParam::single_pdev(r)).unwrap();
    let multi = wmi::init_cmd(&InitCmdParam::multi_pdev(r, wmi::hw_mode::DBS_SBS, b)).unwrap();
    let (s, m) = (&single.buf, &multi.buf);
    // + PDEV_SET_HW_MODE_CMD (16) + array header (4) + 3 x band_to_mac (16).
    kt_assert_eq!(m.len(), s.len() + 16 + 4 + 3 * 16);
    let w = |off: usize| u32::from_le_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]]);
    let end = m.len();
    kt_assert_eq!((w(end - 12), w(end - 8), w(end - 4)), (3, 5350, 5900));
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_multi_pdev_wmi_init);

/// QCN9074: `qcn9074_regs`, the static BAR windows of pci.c, the core
/// admission (`core.c`: one radio, 8 vdevs, 128 peers) and the PCI
/// runtime profile check.
fn smoke_ath11k_qcn9074_regs_windows_admission() -> TestResult {
    use super::qcn9074::{static_bar_offset, static_window_select_value, static_window_start};
    let p = HwRev::Qcn9074Hw10.params().unwrap();
    let regs = p.regs.expect("qcn9074_regs");
    kt_assert!(p.static_window_map);
    kt_assert_eq!(regs.hal_seq_wcss_umac_ce0_src_reg, 0x01b8_0000);
    kt_assert_eq!(regs.hal_tcl1_ring_base_lsb, 0x0000_04f0);
    kt_assert!(Hal::new(&p).is_ok());
    // DP (UMAC) → window 3, CE → window 2, the rest → dynamic window 1.
    kt_assert_eq!(static_window_start(regs, 0x00a0_0510), 0x18_0000);
    kt_assert_eq!(static_bar_offset(regs, 0x00a0_0510), Some(0x18_0510));
    kt_assert_eq!(static_bar_offset(regs, 0x01b8_1004), Some(0x10_1004));
    kt_assert_eq!(static_bar_offset(regs, 0x01e0_c0ac), None);
    kt_assert_eq!(static_window_select_value(), 0x4001_4dc0);
    let c = CoreConfig::for_hw(&p).expect("qcn9074 core config");
    kt_assert_eq!((c.max_radios, c.num_vdevs, c.num_peers), (1, 8, 128));
    kt_assert!(!c.single_pdev_only);
    kt_assert!(super::pci::validate_runtime_profile(HwRev::Qcn9074Hw10).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_qcn9074_regs_windows_admission
);

/// `get_ring_selector`: WCN6750 feeds the frame's flow hash, the
/// IPQ8074-ops parts the current CPU (the hash is not computed).
fn smoke_ath11k_tcl_ring_selector_input() -> TestResult {
    use super::runtime::tx_ring_selector;
    let mut eth = vec![0u8; 60];
    eth[12] = 0x08;
    let h = super::txq::flow_hash(&eth);
    kt_assert_eq!(tx_ring_selector(HwRev::Wcn6750Hw10, || h), h);
    let cpu = narf_lib::percpu::current_cpu() as u32;
    kt_assert_eq!(tx_ring_selector(HwRev::Ipq8074, || h ^ 1), cpu);
    kt_assert_eq!(tx_ring_selector(HwRev::Wcn6855Hw21, || 7), cpu);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_tcl_ring_selector_input
);

use alloc::boxed::Box;
