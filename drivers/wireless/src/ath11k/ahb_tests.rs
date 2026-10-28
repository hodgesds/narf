//! ath11k AHB glue smokes. Expected values are hand-derived from Linux
//! `ath11k/{ahb.c,core.c,hw.c,ce.c,ce.h,hal.h,pcic.c}` and the
//! `ipq6018.dtsi` / `sc7280.dtsi` / `qcom,ath11k.yaml` nodes.

use alloc::vec;
use alloc::vec::Vec;

use narf_drivers_qcom_soc::fixtures::{
    ipq6018_wifi_dt, run, sc7280_wifi_dt, FakeAlloc, FakeDelay, FakeRegs, FakeSmc, FwStore, Seg,
    AHB_IRQ_NAMES,
};
use narf_drivers_qcom_soc::mdt::{PT_LOAD, QCOM_MDT_TYPE_HASH};
use narf_drivers_qcom_soc::pas::PasRproc;
use narf_drivers_qcom_soc::platform::RprocKind;
use narf_drivers_qcom_soc::q6v5::{Q6Event, Q6v5};
use narf_drivers_qcom_soc::rproc::{Carveout, RprocState};
use narf_drivers_qcom_soc::scm::Scm;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::*;

/// The `qcom,ath11k.yaml` example's 52 GIC SPIs, in `irq_name` order.
const YAML_SPIS: [u32; 52] = [
    320, 319, 318, 317, 316, 315, 314, 311, 310, 411, 410, 40, 39, 302, 301, 37, 36, 296, 295, 294,
    293, 292, 291, 290, 289, 288, 239, 236, 235, 234, 233, 232, 231, 230, 229, 228, 224, 223, 203,
    183, 180, 179, 178, 177, 176, 163, 162, 160, 159, 158, 157, 156,
];

fn smoke_ath11k_ahb_hw_params() -> TestResult {
    let i8 = AhbChip::Ipq8074.params();
    let i6 = AhbChip::Ipq6018Hw10.params();
    let i5 = AhbChip::Ipq5018Hw10.params();
    let w = AhbChip::Wcn6750Hw10.params();
    kt_assert_eq!(
        (i8.ce_count(), i6.ce_count(), i5.ce_count(), w.ce_count()),
        (12, 12, 6, 9)
    );
    kt_assert_eq!(
        (
            i8.target_ce_config.len(),
            i6.target_ce_config.len(),
            i5.target_ce_config.len(),
            w.target_ce_config.len()
        ),
        (11, 11, 9, 9)
    );
    kt_assert_eq!(
        (
            i8.svc_to_ce_map.len(),
            i6.svc_to_ce_map.len(),
            i5.svc_to_ce_map.len(),
            w.svc_to_ce_map.len()
        ),
        (21, 19, 17, 14)
    );
    kt_assert_eq!(
        (
            i8.qmi_service_ins_id,
            i5.qmi_service_ins_id,
            w.qmi_service_ins_id
        ),
        (2, 2, 3)
    );
    kt_assert_eq!(
        (i8.bdf_addr, i6.bdf_addr, i5.bdf_addr, w.bdf_addr),
        (0x4b0c_0000, 0x4abc_0000, 0x4ba0_0000, 0x4b0c_0000)
    );
    kt_assert_eq!(
        (i8.fw_dir, i6.fw_dir, i5.fw_dir, w.fw_dir),
        (
            "IPQ8074/hw2.0",
            "IPQ6018/hw1.0",
            "IPQ5018/hw1.0",
            "WCN6750/hw1.0"
        )
    );
    kt_assert_eq!(
        (i8.max_radios, i6.max_radios, i5.max_radios, w.max_radios),
        (3, 2, 1, 1)
    );
    kt_assert_eq!(i8.regs.hal_tcl1_ring_base_lsb, 0x510);
    kt_assert_eq!(
        i6.regs.hal_tcl1_ring_base_lsb,
        0x510,
        "IPQ6018 reuses ipq8074_regs"
    );
    kt_assert_eq!(i5.regs.hal_tcl1_ring_base_lsb, 0x694);
    kt_assert_eq!(w.regs.hal_seq_wcss_umac_ce0_src_reg, 0x01b8_0000);
    kt_assert_eq!(
        i5.regs.hal_seq_wcss_umac_ce1_dst_reg,
        0x3000,
        "relative to the CE remap"
    );
    kt_assert_eq!(
        i5.ce_remap,
        Some(CeRemap {
            base: 0x0840_0000,
            size: 0x20_0000
        })
    );
    kt_assert_eq!((i5.ce_ie_addr.ie1, i5.ce_ie_addr.ie2), (0x1_804c, 0x1_8050));
    kt_assert_eq!(
        (i8.ce_ie_addr.ie1, i8.ce_ie_addr.ie2, i8.ce_ie_addr.ie3),
        (0xa1_803c, 0xa1_8040, 0xa1_803c)
    );
    kt_assert!(w.hybrid_bus_type && w.static_window_map && w.fixed_fw_mem && w.smp2p_wow_exit);
    kt_assert!(!i8.hybrid_bus_type && !i8.fixed_fw_mem && i8.fixed_bdf_addr);
    kt_assert_eq!(
        (i8.hal_desc, i5.hal_desc, w.hal_desc),
        (HalDesc::Ipq8074, HalDesc::Qcn9074, HalDesc::Qcn9074)
    );
    kt_assert_eq!(
        i8.svc_to_ce_map[12],
        s2p(svc_id::WMI_CONTROL_MAC2, PIPEDIR_OUT, 9)
    );
    kt_assert_eq!(i8.svc_to_ce_map[20], s2p(svc_id::PKT_LOG, PIPEDIR_IN, 5));
    kt_assert_eq!(i5.target_ce_config[7].flags, 0x2000);
    kt_assert_eq!(i8.target_ce_config[6].nbytes_max, 65535);
    kt_assert_eq!(
        w.msi.unwrap().user_assignment("DP", 800),
        Some((18, 810, 10))
    );
    kt_assert_eq!(
        AhbChip::from_compatible(&["qcom,ipq5018-wifi".into()]),
        Some(AhbChip::Ipq5018Hw10)
    );
    kt_assert_eq!(
        AhbChip::from_compatible(&["qcom,ipq9574-wifi".into()]),
        None
    );
    kt_assert_eq!(smp2p_power_save_value(7, PowerSaveMsg::Exit), (7 << 16) | 2);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_hw_params);

fn smoke_ath11k_ahb_irq_mapping() -> TestResult {
    kt_assert!(
        IRQ_NAMES == AHB_IRQ_NAMES,
        "fixture labels match ahb.c irq_name[]"
    );
    let i8 = AhbChip::Ipq8074.params();
    let ce: Vec<usize> = ce_irqs(&i8).into_iter().map(|(_, i)| i).collect();
    kt_assert_eq!(
        ce,
        vec![4, 5, 6, 7, 9, 11, 13, 14, 15],
        "CE4/6/8 are DIS_INTR"
    );
    let g = ext_irq_groups(&i8);
    kt_assert_eq!(g[0], vec![50, 22, 23, 43, 40]);
    kt_assert_eq!(g[1], vec![49, 41, 38], "pdev1 → mac2");
    kt_assert_eq!(g[2], vec![48, 42, 39], "pdev2 → mac1");
    kt_assert_eq!(g[3], vec![24]);
    kt_assert_eq!(
        (g[4].clone(), g[5].clone(), g[6].clone()),
        (vec![34, 37], vec![32, 35], vec![33, 36])
    );
    kt_assert_eq!((g[7].clone(), g[10].clone()), (vec![28], vec![25]));
    let g6 = ext_irq_groups(&AhbChip::Ipq6018Hw10.params());
    kt_assert_eq!(g6[1], vec![49, 42, 39], "identity mac map");
    kt_assert_eq!(g6[2], vec![48], "pdev2 >= max_radios");
    kt_assert!(g6[6].is_empty());
    kt_assert_eq!(ce_irq_enable_bits(&i8, 0, 0), vec![(0xa1_803c, 0)]);
    kt_assert_eq!(
        ce_irq_enable_bits(&i8, 1, 0),
        vec![(0xa1_8040, 1), (0xa1_803c, 13)]
    );
    kt_assert_eq!(
        ce_irq_enable_bits(&AhbChip::Ipq5018Hw10.params(), 5, 0),
        vec![(0x1_8050, 5), (0x1_804c, 17)]
    );
    let w = AhbChip::Wcn6750Hw10.params();
    kt_assert_eq!(
        wcn6750_window_offset(w.regs, 0x00a0_0010),
        0x8_0010,
        "DP window"
    );
    kt_assert_eq!(
        wcn6750_window_offset(w.regs, 0x01b8_0010),
        0x10_0010,
        "CE window"
    );
    kt_assert_eq!(wcn6750_window_offset(w.regs, 0x0000_1000), 0x1000, "direct");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_irq_mapping);

fn smoke_ath11k_ahb_probe_ipq6018_dt() -> TestResult {
    let blob = ipq6018_wifi_dt("qcom,ipq6018-wifi", &YAML_SPIS);
    let devs = find_ahb_devices(&blob);
    kt_assert_eq!(devs.len(), 1);
    kt_assert_eq!(devs[0].1, AhbChip::Ipq6018Hw10);
    let r = probe_resources(&blob, &devs[0].0).unwrap();
    kt_assert_eq!(r.mem, Some((0x0c00_0000, 0x200_0000)));
    kt_assert_eq!(r.ce, r.mem, "no CE remap on IPQ6018");
    kt_assert!(r.msi.is_none() && r.msa.is_none() && r.wlan_smp2p_out.is_none());
    // ce0 is irq index 4 → yaml SPI 316.
    kt_assert!(r.irqs.contains(&(4, 316 + 32)));
    kt_assert!(
        r.irqs.contains(&(50, 157 + 32)),
        "wbm2host-tx-completions-ring1"
    );
    let remote = AhbRemote::resolve(&blob, &r).unwrap();
    kt_assert_eq!(remote.platform.kind, RprocKind::Wcss);
    kt_assert!(remote.loader_matches(r.chip));
    kt_assert!(!remote.loader_matches(AhbChip::Wcn6750Hw10));
    // Only two interrupts described → the CE mapping cannot be built.
    let short = ipq6018_wifi_dt("qcom,ipq6018-wifi", &YAML_SPIS[..2]);
    let d = &find_ahb_devices(&short)[0].0;
    kt_assert_eq!(
        probe_resources(&short, d).err(),
        Some(AhbError::MissingIrq("ce0"))
    );
    // IPQ5018's CE window is the remap, not reg[0].
    let i5 = ipq6018_wifi_dt("qcom,ipq5018-wifi", &YAML_SPIS);
    let d = &find_ahb_devices(&i5)[0].0;
    kt_assert_eq!(
        probe_resources(&i5, d).unwrap().ce,
        Some((0x0840_0000, 0x20_0000))
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_probe_ipq6018_dt);

fn smoke_ath11k_ahb_wcn6750_power_up() -> TestResult {
    let blob = sc7280_wifi_dt();
    let devs = find_ahb_devices(&blob);
    kt_assert_eq!(devs.len(), 1);
    let r = probe_resources(&blob, &devs[0].0).unwrap();
    kt_assert_eq!(r.chip, AhbChip::Wcn6750Hw10);
    let msi = r.msi.clone().unwrap();
    kt_assert_eq!(
        (msi.addr, msi.ep_base_data, msi.irqs.len()),
        (0x17a1_0040, 768 + 32, 28)
    );
    kt_assert_eq!(msi.irqs[27], 795 + 32);
    kt_assert_eq!(
        r.msa,
        Some(((0x80c0_0000, 0xc0_0000), (0x004c_d000, 0x1000)))
    );
    kt_assert_eq!(
        r.wlan_smp2p_out,
        Some(("/smp2p-wpss".into(), "wlan".into(), 0))
    );
    kt_assert!(r.mem.is_none(), "hybrid bus maps no reg window");
    let remote = AhbRemote::resolve(&blob, &r).unwrap();
    let p = &remote.platform;
    kt_assert!(remote.loader_matches(r.chip));
    let RprocKind::Pas { pas_id } = p.kind else {
        return TestResult::Fail("WPSS must be PAS");
    };
    // power_up = rproc_boot over the PAS loader with the DT's carve-out.
    let segs = [
        Seg {
            p_type: 0,
            flags: 0x0700_0000,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            fill: 0,
        },
        Seg {
            p_type: 0,
            flags: QCOM_MDT_TYPE_HASH,
            paddr: 0,
            filesz: 0x20,
            memsz: 0x20,
            fill: 0x5a,
        },
        Seg {
            p_type: PT_LOAD,
            flags: 0,
            paddr: p.carveout.0 as u32,
            filesz: 0x40,
            memsz: 0x80,
            fill: 0x33,
        },
    ];
    let (img, _) = narf_drivers_qcom_soc::fixtures::build_mdt(p.carveout.0 as u32, &segs, true);
    let smc = FakeSmc::ok();
    let mut scm = Scm::new(&smc);
    let mut alloc = FakeAlloc::default();
    let d = FakeDelay::new();
    let mut mem = vec![0u8; 0x1000];
    let mut co = Carveout {
        phys: p.carveout.0,
        mem: &mut mem,
    };
    let mut rp = PasRproc::new(pas_id);
    let started = run(rp.start(
        &mut scm,
        &mut alloc,
        p.firmware,
        &img,
        &FwStore::default(),
        &mut co,
        &d,
        &mut |q: &Q6v5| q.signal(Q6Event::Ready),
    ));
    kt_assert_eq!(started, Some(Ok(())));
    kt_assert_eq!(rp.state(), RprocState::Running);
    kt_assert!(smc.calls()[1..].iter().all(|c| c[2] == 6), "WPSS PAS id 6");
    kt_assert!(mem[..0x40].iter().all(|&b| b == 0x33));
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_wcn6750_power_up);

fn smoke_ath11k_ahb_register_access() -> TestResult {
    use super::super::power::ChipIo;
    // IPQ8074: direct ab->mem; CE IE bits at CE_HOST_IE_ADDRESS.
    let p = AhbChip::Ipq8074.params();
    let io = AhbIo {
        mem: FakeRegs::new(),
        ce: None,
        window: None,
    };
    kt_assert_eq!(io.ce_offset(), 0);
    ce_irqs_set(&io, &p, io.ce_offset(), true);
    // Src rings: CE0,3,7,9 → IE1; dest rings: CE1,2,5,10 → IE2 + IE3 (bit + 12).
    let src = (1 << 0) | (1 << 3) | (1 << 7) | (1 << 9);
    let dst = (1 << 1) | (1 << 2) | (1 << 5) | (1 << 10);
    kt_assert_eq!(
        io.mem.get(0xa1_803c),
        src | (dst << 12),
        "IE1 == IE3 register"
    );
    kt_assert_eq!(io.mem.get(0xa1_8040), dst);
    ce_irq_set(&io, &p, 1, 0, false);
    kt_assert_eq!(io.mem.get(0xa1_8040), dst & !(1 << 1));
    // IPQ5018: CE registers live in the remapped window.
    let p5 = AhbChip::Ipq5018Hw10.params();
    let io5 = AhbIo {
        mem: FakeRegs::new(),
        ce: Some(FakeRegs::new()),
        window: None,
    };
    kt_assert_eq!(io5.ce_offset(), AHB_CE_WINDOW_OFFSET);
    ce_irqs_set(&io5, &p5, io5.ce_offset(), true);
    kt_assert_eq!(
        io5.ce.as_ref().unwrap().get(0x1_8050),
        (1 << 1) | (1 << 2) | (1 << 5)
    );
    kt_assert!(
        io5.mem.writes().is_empty(),
        "nothing leaked into the WiFi window"
    );
    io5.write32(0x30, 7);
    kt_assert_eq!(io5.mem.get(0x30), 7);
    // WCN6750: static windows over the DEVICE_INFO BAR.
    let io6 = AhbIo {
        mem: FakeRegs::new(),
        ce: None,
        window: Some(&WCN6750_REGS),
    };
    io6.write32(0x00a0_0010, 1);
    io6.write32(0x01b8_0010, 2);
    io6.write32(0x0000_0040, 3);
    kt_assert_eq!(
        io6.mem.writes(),
        vec![(0x8_0010, 1), (0x10_0010, 2), (0x40, 3)]
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_register_access);
