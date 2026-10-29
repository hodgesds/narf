//! AHB HIF smokes: line mapping (`ath11k_ahb_config_irq` /
//! `_config_ext_irq`, `ath11k_pcic_config_irq`), the handler / tasklet /
//! NAPI masking protocol, `CE_HOST_IE` gating at start / stop and a CE
//! HIF over a register fixture. Masked-edge delivery through a real GIC
//! SPI is `drivers/soc/qcom` `smoke_qcom_irq_gic_spi_mask_latches`.
//! Nothing here has run on IPQ / WCN6750 silicon.

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_drivers_qcom_soc::fixtures::{ipq6018_wifi_dt, sc7280_wifi_dt, FakeRegs};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::super::ahb::{
    ce_irq_enable_bits, ce_irqs, ext_irq_groups, find_ahb_devices, probe_resources, AhbChip, AhbIo,
    AhbResources,
};
use super::super::core::Hif;
use super::super::runtime::{self, group_has_rings, DpIrq};
use super::*;

/// The `qcom,ath11k.yaml` example's SPIs (as in `ahb_tests`).
const YAML_SPIS: [u32; 52] = [
    320, 319, 318, 317, 316, 315, 314, 311, 310, 411, 410, 40, 39, 302, 301, 37, 36, 296, 295, 294,
    293, 292, 291, 290, 289, 288, 239, 236, 235, 234, 233, 232, 231, 230, 229, 228, 224, 223, 203,
    183, 180, 179, 178, 177, 176, 163, 162, 160, 159, 158, 157, 156,
];

fn ipq6018_res() -> AhbResources {
    let blob = ipq6018_wifi_dt("qcom,ipq6018-wifi", &YAML_SPIS);
    let devs = find_ahb_devices(&blob);
    probe_resources(&blob, &devs[0].0).expect("ipq6018 probe")
}

static CTL_LOG: IrqSafeSpinLock<Vec<(u32, bool)>> = IrqSafeSpinLock::new(Vec::new());
fn rec_ctl(intid: u32, on: bool) {
    CTL_LOG.lock().push((intid, on));
}
fn take_log() -> Vec<(u32, bool)> {
    core::mem::take(&mut *CTL_LOG.lock())
}

fn smoke_ath11k_ahb_hif_lines() -> TestResult {
    let r = ipq6018_res();
    let p = r.params;
    let lines = ahb_lines(&r);
    let n_ce = ce_irqs(&p).len();
    let groups = ext_irq_groups(&p);
    let n_dp: usize = groups.iter().map(|g| g.len()).sum();
    kt_assert_eq!(lines.len(), n_ce + n_dp);
    // ce0 is irq index 4 → yaml SPI 316.
    kt_assert_eq!(
        lines[0],
        AhbLine {
            intid: 316 + 32,
            kind: AhbLineKind::Ce(1)
        }
    );
    let ce_mask = lines.iter().fold(0, |a, l| match l.kind {
        AhbLineKind::Ce(m) => a | m,
        _ => a,
    });
    let want: u32 = ce_irqs(&p).iter().fold(0, |a, (c, _)| a | 1 << c);
    kt_assert_eq!(ce_mask, want);
    // wbm2host-tx-completions-ring1 (index 50, SPI 157) is group 0's.
    kt_assert!(lines.contains(&AhbLine {
        intid: 157 + 32,
        kind: AhbLineKind::Dp(1)
    }));
    // WCN6750 (hybrid): the DT MSI vectors, per the pcic user layout.
    let blob = sc7280_wifi_dt();
    let w = probe_resources(&blob, &find_ahb_devices(&blob)[0].0).unwrap();
    let wl = ahb_lines(&w);
    let msi = w.msi.clone().unwrap();
    kt_assert!(wl.iter().all(|l| msi.irqs.contains(&l.intid)));
    let wce = wl.iter().fold(0, |a, l| match l.kind {
        AhbLineKind::Ce(m) => a | m,
        _ => a,
    });
    let wwant: u32 = ce_irqs(&w.params).iter().fold(0, |a, (c, _)| a | 1 << c);
    kt_assert_eq!(wce, wwant);
    let wdp = wl.iter().fold(0, |a, l| match l.kind {
        AhbLineKind::Dp(m) => a | m,
        _ => a,
    });
    let gwant = (0..ATH11K_EXT_IRQ_GRP_NUM_MAX)
        .filter(|g| group_has_rings(w.params.ring_mask, *g))
        .fold(0u32, |a, g| a | 1 << g);
    kt_assert_eq!(wdp, gwant);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_hif_lines);

fn smoke_ath11k_ahb_hif_irq_protocol() -> TestResult {
    let r = ipq6018_res();
    let lines = ahb_lines(&r);
    let irq = AhbIrq::new(lines.clone(), r.params, rec_ctl);
    let _ = take_log();
    ce::set_ce_irqs_enabled(true);
    runtime::set_dp_irqs_enabled(true);
    let _ = MsiCeIrq.take_pending();
    let _ = MsiCeIrq.take_dp_pending();
    // CE1's line: masked by the handler, unmasked when the work is taken.
    let i = lines
        .iter()
        .position(|l| l.kind == AhbLineKind::Ce(1 << 1))
        .unwrap();
    irq.line_fired(i);
    kt_assert_eq!(irq.masked(), 1 << i);
    kt_assert_eq!(take_log(), alloc::vec![(lines[i].intid, false)]);
    // A second edge while masked does not re-mask.
    irq.line_fired(i);
    kt_assert!(take_log().is_empty(), "no double mask");
    kt_assert_eq!(irq.take_pending(), 1 << 1);
    kt_assert_eq!(irq.masked(), 0);
    kt_assert_eq!(take_log(), alloc::vec![(lines[i].intid, true)]);
    kt_assert_eq!(irq.take_pending(), 0);
    // A DP line masks its whole group (ath11k_ahb_ext_grp_disable).
    let g = lines
        .iter()
        .find_map(|l| match l.kind {
            AhbLineKind::Dp(m) => Some(m),
            _ => None,
        })
        .unwrap();
    let members: Vec<usize> = (0..lines.len())
        .filter(|j| lines[*j].kind == AhbLineKind::Dp(g))
        .collect();
    irq.line_fired(members[0]);
    let want: u64 = members.iter().fold(0, |a, j| a | 1 << j);
    kt_assert_eq!(irq.masked(), want);
    kt_assert_eq!(take_log().len(), members.len());
    kt_assert_eq!(irq.take_dp_pending(), g);
    kt_assert_eq!(irq.masked(), 0);
    kt_assert!(take_log().iter().all(|(_, on)| *on));
    // Disabled sides ignore their lines and leave them unmasked.
    ce::set_ce_irqs_enabled(false);
    runtime::set_dp_irqs_enabled(false);
    irq.line_fired(i);
    irq.line_fired(members[0]);
    kt_assert_eq!(irq.masked(), 0);
    kt_assert_eq!((irq.take_pending(), irq.take_dp_pending()), (0, 0));
    kt_assert!(irq.fires() >= 4);
    // CE_HOST_IE gating at start / stop.
    let io = AhbIo {
        mem: FakeRegs::new(),
        ce: None,
        window: None,
    };
    irq.hif_start(&io);
    for (ce, _) in ce_irqs(&r.params) {
        for (reg, bit) in ce_irq_enable_bits(&r.params, ce, 0) {
            kt_assert!(io.mem.get(reg) & (1 << bit) != 0, "IE bit set");
        }
    }
    let ie1 = r.params.ce_ie_addr.ie1;
    let before = io.mem.get(ie1);
    irq.hif_stop(&io, true);
    kt_assert_eq!(io.mem.get(ie1), before, "crash flush keeps IE");
    irq.hif_stop(&io, false);
    kt_assert_eq!(io.mem.get(ie1), 0);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_hif_irq_protocol);

/// `ath11k_ahb_probe`'s CE half and `ath11k_ahb_start` over a register
/// fixture: twelve IPQ pipes, non-shadow SRNGs, IE bits on start.
fn smoke_ath11k_ahb_hif_ce_start() -> TestResult {
    let r = ipq6018_res();
    let irq = AhbIrq::new(ahb_lines(&r), r.params, rec_ctl);
    let io = AhbIo {
        mem: FakeRegs::new(),
        ce: None,
        window: None,
    };
    let mut hif = match ahb_ce_hif(&r, io, irq, || 0) {
        Ok(h) => Box::new(h),
        Err(_) => return TestResult::Fail("ahb_ce_hif"),
    };
    kt_assert_eq!(hif.ce.ce_count(), 12);
    kt_assert!(hif.shadow_reg_v2().is_empty(), "IPQ has no shadow regs");
    if hif.init_pipes().is_err() {
        return TestResult::Fail("init_pipes");
    }
    hif.start();
    let ie2 = r.params.ce_ie_addr.ie2;
    kt_assert!(hif.io.mem.get(ie2) & (1 << 1) != 0, "CE1 dest IE");
    hif.stop();
    kt_assert_eq!(hif.io.mem.get(ie2), 0);
    ce::set_ce_irqs_enabled(false);
    // The AHB chip names its own rev in the HwRev-keyed tables.
    kt_assert_eq!(r.chip, AhbChip::Ipq6018Hw10);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_hif_ce_start);
