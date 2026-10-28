//! AHB bring-up smokes over the `ipq6018.dtsi` / `sc7280.dtsi`-shaped
//! fixtures: the DT composition and the Linux step order with unwind.
//! Fixture-only; nothing has run on IPQ / WCN6750 silicon.

use alloc::vec::Vec;

use narf_drivers_qcom_soc::fixtures::{ipq6018_wifi_dt, run, sc7280_wifi_dt};
use narf_drivers_qcom_soc::platform::KickDt;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use super::super::ahb::{find_ahb_devices, AhbChip};
use super::super::ahb_hif::AhbLineKind;
use super::*;

const SPIS: [u32; 52] = [
    320, 319, 318, 317, 316, 315, 314, 311, 310, 411, 410, 40, 39, 302, 301, 37, 36, 296, 295, 294,
    293, 292, 291, 290, 289, 288, 239, 236, 235, 234, 233, 232, 231, 230, 229, 228, 224, 223, 203,
    183, 180, 179, 178, 177, 176, 163, 162, 160, 159, 158, 157, 156,
];

fn smoke_ath11k_ahb_probe_composition() -> TestResult {
    let blob = ipq6018_wifi_dt("qcom,ipq6018-wifi", &SPIS);
    let node = find_ahb_devices(&blob)[0].0.clone();
    let p = match AhbPlatform::probe(&blob, &node) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("ipq6018 probe"),
    };
    kt_assert_eq!(p.res.chip, AhbChip::Ipq6018Hw10);
    // glink-edge { interrupts = <GIC_SPI 321 ..>; label = "rtr";
    // qcom,remote-pid = <1>; mboxes = <&apcs_glb 8>; IPCRTR }.
    kt_assert_eq!(p.glink.irq.gic_hwirq(), Some(321 + 32));
    kt_assert_eq!((p.glink.label.as_str(), p.glink.remote_pid), ("rtr", 1));
    kt_assert!(matches!(p.glink.kick, KickDt::Apcs { channel: 8, .. }));
    kt_assert_eq!(
        p.glink.channels,
        alloc::vec![alloc::string::String::from("IPCRTR")]
    );
    kt_assert!(!p.q6_irqs.routes.is_empty(), "q6 interrupts");
    kt_assert!(!p.smp2p_edges().is_empty(), "wcss smp2p edge");
    kt_assert!(p
        .lines
        .iter()
        .any(|l| l.kind == AhbLineKind::Ce(1) && l.intid == 316 + 32));
    // WCN6750: PAS remoteproc, IPCC-routed glink edge, MSI lines.
    let blob = sc7280_wifi_dt();
    let node = find_ahb_devices(&blob)[0].0.clone();
    let w = match AhbPlatform::probe(&blob, &node) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("wcn6750 probe"),
    };
    kt_assert_eq!(w.glink.remote_pid, 13);
    kt_assert!(matches!(
        w.glink.kick,
        KickDt::Ipcc {
            client: 24,
            signal: 0,
            ..
        }
    ));
    kt_assert!(!w.lines.is_empty(), "hybrid MSI lines");
    kt_assert!(
        w.smp2p_edges().len() == 1,
        "one smp2p-wpss edge (stop, q6 bits, wlan-smp2p-out)"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_probe_composition
);

struct Rec {
    log: Vec<&'static str>,
    fail: Option<BringUpStep>,
}

impl Rec {
    fn step(&mut self, s: BringUpStep, name: &'static str) -> Result<(), AhbError> {
        self.log.push(name);
        if self.fail == Some(s) {
            Err(AhbError::Failed(-5))
        } else {
            Ok(())
        }
    }
}

impl AhbBringUp for Rec {
    fn hal_ce_alloc(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::HalCeAlloc, "hal_ce")
    }
    fn qmi_init_service(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::QmiInit, "qmi_init")
    }
    async fn rproc_irqs(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::RprocIrqs, "q6_irqs")
    }
    async fn rproc_boot(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::RprocBoot, "rproc_boot")
    }
    async fn glink_start(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::GlinkStart, "glink")
    }
    fn config_irq(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::ConfigIrq, "config_irq")
    }
    async fn qmi_ready(&mut self, _p: &AhbPlatform) -> Result<(), AhbError> {
        self.step(BringUpStep::QmiReady, "qmi_ready")
    }
    async fn rproc_shutdown(&mut self, _p: &AhbPlatform) {
        self.log.push("shutdown");
    }
}

fn smoke_ath11k_ahb_bring_up_order() -> TestResult {
    let blob = ipq6018_wifi_dt("qcom,ipq6018-wifi", &SPIS);
    let node = find_ahb_devices(&blob)[0].0.clone();
    let p = AhbPlatform::probe(&blob, &node).expect("probe");
    let mut ok = Rec {
        log: Vec::new(),
        fail: None,
    };
    kt_assert_eq!(run(bring_up(&p, &mut ok)), Some(Ok(())));
    kt_assert_eq!(
        ok.log,
        alloc::vec![
            "hal_ce",
            "qmi_init",
            "q6_irqs",
            "rproc_boot",
            "glink",
            "config_irq",
            "qmi_ready"
        ]
    );
    // Before boot: no shutdown. After boot: rproc_shutdown.
    let mut early = Rec {
        log: Vec::new(),
        fail: Some(BringUpStep::RprocBoot),
    };
    kt_assert_eq!(
        run(bring_up(&p, &mut early)),
        Some(Err((BringUpStep::RprocBoot, AhbError::Failed(-5))))
    );
    kt_assert_eq!(early.log.last(), Some(&"rproc_boot"));
    let mut late = Rec {
        log: Vec::new(),
        fail: Some(BringUpStep::GlinkStart),
    };
    kt_assert_eq!(
        run(bring_up(&p, &mut late)),
        Some(Err((BringUpStep::GlinkStart, AhbError::Failed(-5))))
    );
    kt_assert_eq!(late.log.last(), Some(&"shutdown"));
    kt_assert!(!late.log.contains(&"config_irq"), "stops at the failure");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_bring_up_order);

/// The bus DT match table binds the AHB node once, through
/// `ahb_dt_probe`, by its full path; a second walk is a no-op and a
/// driver-less tree binds nothing.
static PROBED: narf_lib::sync::IrqSafeSpinLock<Vec<AhbPlatform>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

/// `ahb_dt_probe` minus the live task (QEMU has no IPQ MMIO).
fn fixture_dt_probe(blob: &'static [u8], path: &str) -> Result<(), narf_bus::ProbeError> {
    let p = probe_node(blob, path).map_err(|e| dt_probe_error(&e))?;
    PROBED.lock().push(p);
    Ok(())
}

fn take_probed() -> Vec<AhbPlatform> {
    core::mem::take(&mut *PROBED.lock())
}

fn smoke_ath11k_ahb_dt_driver_match() -> TestResult {
    let blob: &'static [u8] =
        alloc::boxed::Box::leak(ipq6018_wifi_dt("qcom,ipq6018-wifi", &SPIS).into_boxed_slice());
    narf_bus::unregister_dt_driver(AHB_DT_DRIVER);
    kt_assert_eq!(narf_bus::probe_dt_blob(blob), 0);
    let _ = take_probed();
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: AHB_DT_DRIVER,
        compatible: &AHB_DT_COMPATIBLE,
        probe: fixture_dt_probe,
    });
    let n = narf_bus::probe_dt_blob(blob);
    let again = narf_bus::probe_dt_blob(blob);
    let bound = narf_bus::bound_dt_nodes();
    let probed = take_probed();
    narf_bus::unregister_dt_driver(AHB_DT_DRIVER);
    kt_assert_eq!(n, 1);
    kt_assert_eq!(again, 0);
    kt_assert!(bound
        .iter()
        .any(|(p, d)| p.ends_with("/wifi@c000000") && *d == AHB_DT_DRIVER));
    kt_assert_eq!(probed.len(), 1);
    kt_assert_eq!(probed[0].res.chip, AhbChip::Ipq6018Hw10);
    kt_assert!(narf_bus::bound_dt_nodes()
        .iter()
        .all(|(_, d)| *d != AHB_DT_DRIVER));
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_dt_driver_match);
