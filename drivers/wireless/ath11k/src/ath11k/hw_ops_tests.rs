//! `hw_ops` smokes: the per-chip table (`hw.c` `*_ops`) and the three
//! `reo_setup` flavours over a register fixture.

use narf_drivers_qcom_soc::fixtures::FakeRegs;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::super::ahb::AhbIo;
use super::super::hw::IPQ8074_REGS;
use super::*;

fn smoke_ath11k_hw_ops_table() -> TestResult {
    let i8 = HwRev::Ipq8074.hw_ops().unwrap();
    let i6 = HwRev::Ipq6018Hw10.hw_ops().unwrap();
    let w = HwRev::Wcn6750Hw10.hw_ops().unwrap();
    let q = HwRev::Qcn9074Hw10.hw_ops().unwrap();
    // ath11k_hw_ipq8074_mac_from_pdev_id: 0→0, 1→2, 2→1.
    kt_assert_eq!(
        (0..3)
            .map(|p| i8.hw_mac_from_pdev_id(p))
            .collect::<alloc::vec::Vec<_>>(),
        alloc::vec![Some(0), Some(2), Some(1)]
    );
    kt_assert_eq!(i6.hw_mac_from_pdev_id(1), Some(1));
    kt_assert_eq!((i8.mac_id_to_pdev_id(2), i8.mac_id_to_srng_id(2)), (2, 0));
    kt_assert_eq!((w.mac_id_to_pdev_id(1), w.mac_id_to_srng_id(1)), (0, 1));
    kt_assert_eq!(i8.wmi_init_config, WmiInitConfig::Ipq8074);
    kt_assert_eq!(w.wmi_init_config, WmiInitConfig::Qca6390);
    kt_assert_eq!(w.ring_selector(3, 0x55), 0x55);
    kt_assert_eq!(i8.ring_selector(3, 0x55), 3);
    kt_assert_eq!(q.tx_mesh, TxMesh::Qcn9074Info3);
    kt_assert_eq!(i8.tx_mesh, TxMesh::Ipq8074Info2);
    kt_assert_eq!(
        HwRev::Ipq5018Hw10.hw_ops().unwrap().reo_setup,
        ReoSetup::Ipq5018
    );
    kt_assert_eq!(
        HwRev::Qca6390Hw20.hw_ops().unwrap().reo_setup,
        ReoSetup::Ipq8074
    );
    kt_assert_eq!(
        HwRev::Wcn6855Hw21.hw_ops().unwrap().reo_setup,
        ReoSetup::Wcn6855
    );
    kt_assert!(HwRev::Unknown.hw_ops().is_none());
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_hw_ops_table);

fn smoke_ath11k_hw_ops_reo_setup() -> TestResult {
    let io = AhbIo {
        mem: FakeRegs::new(),
        ce: None,
        window: None,
    };
    IPQ8074_OPS.reo_setup(&io, &IPQ8074_REGS);
    let base = super::super::hal::HAL_SEQ_WCSS_UMAC_REO_REG;
    // SW1..SW4 = 1..4, 3-bit entries, in HASH_RING_MAP (bits 31:8).
    let map3: u32 = (1 | 2 << 3 | 3 << 6 | 4 << 9) | (1 | 2 << 3 | 3 << 6 | 4 << 9) << 12;
    kt_assert_eq!(io.mem.get(base + HAL_REO1_DEST_RING_CTRL_IX_0), map3 << 8);
    kt_assert_eq!(io.mem.get(base + HAL_REO1_DEST_RING_CTRL_IX_3), map3 << 8);
    // Aging list + flush on, FRAG_DST_RING = REO2SW1 (0).
    kt_assert_eq!(io.mem.get(base + HAL_REO1_GEN_ENABLE), (1 << 2) | (1 << 3));
    kt_assert_eq!(
        io.mem.get(base + IPQ8074_REGS.hal_reo1_aging_thresh_ix_2),
        HAL_DEFAULT_REO_TIMEOUT_USEC
    );
    let io5 = AhbIo {
        mem: FakeRegs::new(),
        ce: None,
        window: None,
    };
    IPQ5018_OPS.reo_setup(&io5, &IPQ8074_REGS);
    kt_assert_eq!(
        io5.mem.get(base + HAL_REO1_DEST_RING_CTRL_IX_1),
        0x4321_4321
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_hw_ops_reo_setup);
