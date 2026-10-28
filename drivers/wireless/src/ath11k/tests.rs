//! ath11k smoke tests — co-located per project convention.
//!
//! Pure-data only: PCI match presence, hw_rev decode, and power-up sequence.
//! MHI tests live in `mhi_tests.rs`; HAL / DP / CE tests in `hal_tests.rs` /
//! `ce_tests.rs`; QMI / QRTR tests in `qmi_tests.rs`; WMI / HTC tests in
//! `wmi_tests.rs`. Live silicon
//! is exercised by the probe-bound-or-skip smoke at the bottom —
//! that one Skips cleanly on QEMU.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// DP descriptor layouts are tested in `hal_tests.rs`.
use super::hw::*;
use super::mhi::*;
use super::pci::{is_probed, with_controller};

// ── PCI match table ────────────────────────────────────────────────

fn smoke_ath11k_pci_match_table_registers() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::pci::register_pci_driver();
    let registered = registered_pci_drivers();
    for &did in ALL_DEV_IDS {
        let found = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice { vendor, device }
                    if vendor == QCOM_VENDOR && device == did
            )
        });
        if !found {
            return TestResult::Fail("ath11k PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_pci_match_table_registers
);

fn smoke_ath11k_name_for_known_ids() -> TestResult {
    if name_for(ATH11K_DEV_QCA6390) != "ath11k-qca6390" {
        return TestResult::Fail("qca6390 name mismatch");
    }
    if name_for(ATH11K_DEV_QCN9074) != "ath11k-qcn9074" {
        return TestResult::Fail("qcn9074 name mismatch");
    }
    if name_for(ATH11K_DEV_WCN6855) != "ath11k-wcn6855" {
        return TestResult::Fail("wcn6855 name mismatch");
    }
    if name_for(0xFFFF) != "ath11k" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_name_for_known_ids);

// ── ChipInfo decode ────────────────────────────────────────────────

fn smoke_ath11k_chip_for_pci_id_known_pairs() -> TestResult {
    // Positive: every Linux `ath11k_pci_id_table` entry resolves.
    for &(did, rev) in &[
        (ATH11K_DEV_QCA6390, HwRev::Qca6390Hw20),
        (ATH11K_DEV_WCN6855, HwRev::Wcn6855Hw20),
        (ATH11K_DEV_QCN9074, HwRev::Qcn9074Hw10),
    ] {
        match chip_for_pci_id(QCOM_VENDOR, did) {
            Some(c) if c.did == did && c.default_hw_rev == rev => {}
            _ => return TestResult::Fail("ath11k PCI id did not resolve to its ChipInfo"),
        }
    }
    // Negative: ath12k parts (WCN7850 1107, QCN9274 1109) and the
    // never-assigned 1105 are not ath11k; nor is a non-Qualcomm vid.
    for &did in &[0x1105u16, 0x1107, 0x1109] {
        if chip_for_pci_id(QCOM_VENDOR, did).is_some() {
            return TestResult::Fail("ath11k claimed a non-ath11k Qualcomm PCI id");
        }
    }
    if chip_for_pci_id(0x8086, ATH11K_DEV_WCN6855).is_some() {
        return TestResult::Fail("ath11k claimed a non-Qualcomm vendor id");
    }
    if ALL_DEV_IDS.len() != 3 {
        return TestResult::Fail("ath11k match table is not exactly Linux's three ids");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_chip_for_pci_id_known_pairs
);

fn smoke_ath11k_refine_hw_rev_wcn6855_subversions() -> TestResult {
    // Linux `ath11k_pci_probe`: WCN6855 major 2, minor 0x00/0x01 → HW2.0.
    for minor in [0x00, 0x01] {
        if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, 0) != HwRev::Wcn6855Hw20 {
            return TestResult::Fail("WCN6855 2.0x not classified as HW2.0");
        }
        if needs_sub_version(ATH11K_DEV_WCN6855, 2, minor) {
            return TestResult::Fail("WCN6855 HW2.0 should not read TCSR_SOC_HW_SUB_VER");
        }
    }
    // minor 0x10/0x11 → classify by TCSR_SOC_HW_SUB_VER.
    for minor in [0x10, 0x11] {
        if !needs_sub_version(ATH11K_DEV_WCN6855, 2, minor) {
            return TestResult::Fail("WCN6855 2.1x must read TCSR_SOC_HW_SUB_VER");
        }
        for sub in [0x1019_A0E1, 0x1019_B0E1, 0x1019_C0E1, 0x1019_D0E1] {
            if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, sub) != HwRev::Qca2066Hw21 {
                return TestResult::Fail("QCA2066 sub-version not classified as QCA2066");
            }
        }
        if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, 0x001E_60E1) != HwRev::Qca6698aqHw21 {
            return TestResult::Fail("QCA6698AQ sub-version not classified as QCA6698AQ");
        }
        if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, 0x1234_5678) != HwRev::Wcn6855Hw21 {
            return TestResult::Fail("other sub-version not classified as WCN6855 HW2.1");
        }
    }
    // Steppings Linux rejects (`unsupported_wcn6855_soc`).
    if refine_hw_rev(ATH11K_DEV_WCN6855, 2, 0x12, 0x1019_A0E1) != HwRev::Unknown {
        return TestResult::Fail("WCN6855 minor 0x12 must be unsupported, as in Linux");
    }
    if refine_hw_rev(ATH11K_DEV_WCN6855, 1, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("WCN6855 major 1 must be unsupported, as in Linux");
    }
    if refine_hw_rev(ATH11K_DEV_QCA6390, 3, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("QCA6390 major != 2 must be unsupported, as in Linux");
    }
    if refine_hw_rev(0x9999, 0, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("unknown PCI id should produce HwRev::Unknown");
    }
    // Firmware dirs = Linux `hw_params.fw.dir`.
    for (rev, dir) in [
        (HwRev::Wcn6855Hw20, "WCN6855/hw2.0"),
        (HwRev::Wcn6855Hw21, "WCN6855/hw2.1"),
        (HwRev::Qca2066Hw21, "QCA2066/hw2.1"),
        (HwRev::Qca6698aqHw21, "QCA6698AQ/hw2.1"),
    ] {
        if rev.fw_dir() != Some(dir) {
            return TestResult::Fail("hw_rev firmware dir differs from Linux hw_params");
        }
    }
    if HwRev::Unknown.fw_dir().is_some() {
        return TestResult::Fail("HwRev::Unknown must have no firmware dir");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_refine_hw_rev_wcn6855_subversions
);

// ── Window-register arithmetic ─────────────────────────────────────

fn smoke_ath11k_probe_requires_complete_runtime_profile() -> TestResult {
    use super::pci::{validate_runtime_profile, ProbeError};
    for revision in [HwRev::Qcn9074Hw10, HwRev::Unknown] {
        if validate_runtime_profile(revision)
            != Err(ProbeError::UnsupportedRuntime { hw_rev: revision })
        {
            return TestResult::Fail("incomplete family must be rejected before MHI activation");
        }
    }
    for revision in [
        HwRev::Qca6390Hw20,
        HwRev::Wcn6855Hw20,
        HwRev::Wcn6855Hw21,
        HwRev::Qca2066Hw21,
        HwRev::Qca6698aqHw21,
    ] {
        if validate_runtime_profile(revision).is_err() {
            return TestResult::Fail("complete native descriptor family must remain reachable");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_probe_requires_complete_runtime_profile
);

fn smoke_ath11k_window_constants_consistent() -> TestResult {
    // ATH11K_PCI_WINDOW_RANGE_MASK covers exactly the 19 low bits.
    if ATH11K_PCI_WINDOW_RANGE_MASK != (1u32 << 19) - 1 {
        return TestResult::Fail("window range mask not (1<<19)-1");
    }
    // Window value mask occupies bits [24:19].
    if ATH11K_PCI_WINDOW_VALUE_MASK != (0x3F) << 19 {
        return TestResult::Fail("window value mask not bits[24:19]");
    }
    // Enable bit is bit 30.
    if ATH11K_PCI_WINDOW_ENABLE_BIT != 1u32 << 30 {
        return TestResult::Fail("window enable bit not at bit 30");
    }
    // Linux `ath11k_pci_select_window` writes the window *number*
    // (FIELD_GET of bits[24:19]), not the shifted field. 0x1910010
    // (TCSR_SOC_HW_SUB_VER) lives in window 0x32.
    use super::pci::{window_of, window_select_value, windowed_bar_offset};
    if window_of(TCSR_SOC_HW_SUB_VER) != 0x32 {
        return TestResult::Fail("window_of(0x1910010) != 0x32");
    }
    if window_select_value(TCSR_SOC_HW_SUB_VER) != (1 << 30) | 0x32 {
        return TestResult::Fail("window select must write ENABLE | window number");
    }
    if windowed_bar_offset(TCSR_SOC_HW_SUB_VER) != 0x80000 + 0x10010 {
        return TestResult::Fail("windowed BAR offset wrong for 0x1910010");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_window_constants_consistent
);

fn smoke_ath11k_msi_probe_unwind_releases_handlers_and_vector() -> TestResult {
    let vector = match narf_interrupts::vector::alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("ath11k: could not allocate test MSI vector"),
    };
    // The single-vector fallback assigns every MHI IRQ entry to vector 0,
    // represented by the combined cookie below.  Install precisely what
    // `alloc_msi` installs, then exercise its error-unwind helper.
    narf_interrupts::install_handler_named(vector, "ath11k-mhi", 0b111, |_| {
        narf_interrupts::IrqStatus::Handled
    });
    super::pci::teardown_msi_vectors(&MSI_CONFIG_ONE, vector as u32, 1, vector);

    if narf_interrupts::vector::is_allocated(vector) {
        return TestResult::Fail("ath11k: failed probe leaked its MSI vector");
    }
    if !narf_interrupts::installed_handler_names(vector).is_empty() {
        return TestResult::Fail("ath11k: failed probe left an MSI handler installed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_msi_probe_unwind_releases_handlers_and_vector
);

// MHI protocol + host tests live in `mhi_tests.rs`.

// ── Live-silicon smoke ─────────────────────────────────────────────
//
// QEMU doesn't emulate any ath11k part — Skip cleanly so the
// real-HW lane lights up without restructuring the test list.

fn smoke_ath11k_probe_bound_or_skip() -> TestResult {
    if !is_probed() {
        return TestResult::Skip("ath11k: no ath11k device bound (expected on QEMU)");
    }
    let hw_rev = match with_controller(|d| d.hw_rev) {
        Some(r) => r,
        None => return TestResult::Skip("ath11k: probed flag set but no controller"),
    };
    if hw_rev == HwRev::Unknown {
        return TestResult::Fail("ath11k: bound device reports HwRev::Unknown");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_probe_bound_or_skip);

/// QCNFA765 exposes the WCN6855 PCI function (`17cb:1103`).  Linux resolves
/// the NFA765 module to WCN6855 HW2.1, whose firmware lives under
/// `ath11k/WCN6855/hw2.1`.  This is deliberately a PCI/power-up qualification:
/// the kernel-test runner begins before the async MHI task gets a scheduler
/// turn, so MHI/QMI/radio readiness is exercised by the normal-boot smoke
/// (`ath11k.scan=1`), not falsely required here.
fn smoke_ath11k_qcnfa765_pci_powerup_or_skip() -> TestResult {
    let Some((chip_vid, chip_did, device_id, hw_rev, params_rev, fw_dir, wanted_msi, msi_cfg, msi)) =
        with_controller(|d| {
            (
                d.chip.vid,
                d.chip.did,
                d.device_id,
                d.hw_rev,
                d.params.hw_rev,
                d.params.fw_dir,
                d.params.msi.total_vectors,
                d.msi.config.total_vectors,
                d.msi.n_vectors,
            )
        })
    else {
        return TestResult::Skip("ath11k: no QCNFA765/WCN6855 bound (expected on QEMU)");
    };

    if device_id != ATH11K_DEV_WCN6855 {
        return TestResult::Skip("ath11k: bound device is not QCNFA765/WCN6855");
    }
    if chip_vid != QCOM_VENDOR || chip_did != device_id {
        return TestResult::Fail("ath11k: WCN6855 PCI identity changed during bring-up");
    }
    if hw_rev != HwRev::Wcn6855Hw21 || params_rev != hw_rev {
        return TestResult::Fail("ath11k: QCNFA765 did not resolve to WCN6855 HW2.1 parameters");
    }
    if fw_dir != "WCN6855/hw2.1" {
        return TestResult::Fail("ath11k: QCNFA765 selected the wrong firmware directory");
    }
    // WCN6855 requests Linux's 32-vector layout, but a single shared MSI is
    // a supported fallback when the platform cannot allocate the full block.
    if wanted_msi != 32 || !matches!(msi_cfg, 1 | 32) || msi as u32 != msi_cfg {
        return TestResult::Fail("ath11k: QCNFA765 MSI allocation has an invalid layout");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_qcnfa765_pci_powerup_or_skip
);

// ── Phase 1: power-up sequence (Linux ath11k_pci_sw_reset) ─────────

mod fake_io {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use super::super::power::ChipIo;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Op {
        R(u32),
        W(u32, u32),
        Delay(u32),
        RestoreWindow,
    }

    /// Register file: writes stick unless the offset is `stuck`, in
    /// which case reads always return the stuck value.
    #[derive(Default)]
    pub struct FakeIo {
        pub regs: RefCell<BTreeMap<u32, u32>>,
        pub stuck: BTreeMap<u32, u32>,
        pub ops: RefCell<Vec<Op>>,
    }

    impl ChipIo for FakeIo {
        fn read32(&self, offset: u32) -> u32 {
            self.ops.borrow_mut().push(Op::R(offset));
            if let Some(&v) = self.stuck.get(&offset) {
                return v;
            }
            *self.regs.borrow().get(&offset).unwrap_or(&0)
        }
        fn write32(&self, offset: u32, value: u32) {
            self.ops.borrow_mut().push(Op::W(offset, value));
            self.regs.borrow_mut().insert(offset, value);
        }
        fn delay_ms(&self, ms: u32) {
            self.ops.borrow_mut().push(Op::Delay(ms));
        }
        fn restore_window(&self) {
            self.ops.borrow_mut().push(Op::RestoreWindow);
        }
    }
}

fn smoke_ath11k_sw_reset_matches_linux_sequence() -> TestResult {
    use super::power::*;
    use fake_io::{FakeIo, Op::*};
    let io = FakeIo::default();
    io.regs.borrow_mut().insert(WLAON_QFPROM_PWR_CTRL_REG, 0xF);
    io.regs.borrow_mut().insert(PCIE_SOC_GLOBAL_RESET, 0x10);
    io.regs.borrow_mut().insert(WLAON_SOC_RESET_CAUSE_REG, 0x5);
    io.regs.borrow_mut().insert(MHISTATUS, 0x4); // SYSERR latched
                                                 // WCN6855: fix_l1ss = false.
    let report = sw_reset(&io, true, None);
    let expected = [
        Delay(100),
        // ath11k_pci_enable_ltssm
        R(PCIE_PCIE_PARF_LTSSM),
        W(PCIE_PCIE_PARF_LTSSM, PARM_LTSSM_VALUE),
        R(PCIE_PCIE_PARF_LTSSM),
        R(GCC_GCC_PCIE_HOT_RST),
        W(GCC_GCC_PCIE_HOT_RST, GCC_GCC_PCIE_HOT_RST_VAL),
        R(GCC_GCC_PCIE_HOT_RST),
        Delay(5),
        // ath11k_pci_clear_all_intrs
        W(PCIE_PCIE_INT_ALL_CLEAR, PCIE_INT_CLEAR_ALL),
        // ath11k_pci_set_wlaon_pwr_ctrl: clear VDD4BLOW (bit 2)
        R(WLAON_QFPROM_PWR_CTRL_REG),
        W(WLAON_QFPROM_PWR_CTRL_REG, 0xB),
        // ath11k_mhi_clear_vector
        W(0x360, 0),
        W(0x368, 0),
        W(0x394, 0),
        W(0x39C, 0),
        // ath11k_pci_clear_dbg_registers
        R(PCIE_Q6_COOKIE_ADDR),
        R(WLAON_WARM_SW_ENTRY),
        Delay(10),
        W(WLAON_WARM_SW_ENTRY, 0),
        Delay(10),
        R(WLAON_WARM_SW_ENTRY),
        R(WLAON_SOC_RESET_CAUSE_REG),
        // ath11k_pci_soc_global_reset: set V, then toggle it back
        R(PCIE_SOC_GLOBAL_RESET),
        W(PCIE_SOC_GLOBAL_RESET, 0x11),
        Delay(10),
        W(PCIE_SOC_GLOBAL_RESET, 0x10),
        Delay(10),
        R(PCIE_SOC_GLOBAL_RESET),
        RestoreWindow,
        // ath11k_mhi_set_mhictrl_reset
        R(0x48),
        W(0x38, 0x2),
        Delay(10),
    ];
    if io.ops.borrow().as_slice() != expected {
        return TestResult::Fail("sw_reset(power_on) op sequence differs from Linux");
    }
    if report.ltssm != PARM_LTSSM_VALUE
        || report.reset_cause != 0x5
        || report.mhistatus != 0x4
        || report.link_down_after_reset
        || report.l1ss_failed_reg.is_some()
    {
        return TestResult::Fail("sw_reset report fields wrong on a healthy chip");
    }
    // power_on = false skips LTSSM / interrupt clear / WLAON / L1SS.
    let io = FakeIo::default();
    let _ = sw_reset(&io, false, None);
    if io.ops.borrow().contains(&R(PCIE_PCIE_PARF_LTSSM)) {
        return TestResult::Fail("sw_reset(power_on=false) touched LTSSM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_sw_reset_matches_linux_sequence
);

fn smoke_ath11k_power_up_failure_paths() -> TestResult {
    use super::power::*;
    use fake_io::{FakeIo, Op};
    // LTSSM never settles and reads all-ones: 5 retries, 5 ms apart.
    let mut io = FakeIo::default();
    io.stuck.insert(PCIE_PCIE_PARF_LTSSM, 0xffff_ffff);
    let mut report = PowerUpReport::default();
    enable_ltssm(&io, &mut report);
    let writes = io
        .ops
        .borrow()
        .iter()
        .filter(|o| matches!(o, Op::W(PCIE_PCIE_PARF_LTSSM, _)))
        .count();
    if writes != 5 || report.ltssm != 0xffff_ffff {
        return TestResult::Fail("stuck LTSSM must be retried exactly 5 times");
    }
    // Link down after global reset is reported, not fatal.
    io = FakeIo::default();
    io.stuck.insert(PCIE_SOC_GLOBAL_RESET, 0xffff_ffff);
    let report = sw_reset(&io, true, None);
    if !report.link_down_after_reset {
        return TestResult::Fail("all-ones after global reset not reported as link down");
    }
    if !io.ops.borrow().contains(&Op::W(0x38, 0x2)) {
        return TestResult::Fail("MHICTRL reset must still run after a link-down warning");
    }
    // set_link_reg: a register that never takes the value fails after
    // 10 attempts, 2 ms apart, naming the register.
    io = FakeIo::default();
    io.stuck.insert(0x1000, 0x0);
    if set_link_reg(&io, 0x1000, 0x52, 0xff) != Err(0x1000) {
        return TestResult::Fail("set_link_reg must fail with the stuck register offset");
    }
    let attempts = io
        .ops
        .borrow()
        .iter()
        .filter(|o| matches!(o, Op::W(0x1000, _)))
        .count();
    if attempts != 10 {
        return TestResult::Fail("set_link_reg must make exactly 10 write attempts");
    }
    // Already-correct register: no write at all.
    io = FakeIo::default();
    io.regs.borrow_mut().insert(0x2000, 0x1252);
    if set_link_reg(&io, 0x2000, 0x52, 0xff) != Ok(())
        || io.ops.borrow().iter().any(|o| matches!(o, Op::W(..)))
    {
        return TestResult::Fail("set_link_reg wrote a register already holding the value");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_power_up_failure_paths
);

fn smoke_ath11k_fix_l1ss_programs_qca6390_phy() -> TestResult {
    use super::power::*;
    use fake_io::FakeIo;
    let regs = match HwRev::Qca6390Hw20.params().and_then(|p| p.fix_l1ss) {
        Some(r) => r,
        None => return TestResult::Fail("QCA6390 must have fix_l1ss (Linux true)"),
    };
    let io = FakeIo::default();
    if fix_l1ss(&io, &regs).is_err() {
        return TestResult::Fail("fix_l1ss failed on a writable register file");
    }
    let r = io.regs.borrow();
    let get = |o: u32| *r.get(&o).unwrap_or(&0);
    if get(0x01e0_c0ac) != 0x10
        || get(0x01e0_c628) != 0x02
        || get(0x01e0_c62c) != 0x52
        || get(0x01e0_c634) != 0xff
    {
        return TestResult::Fail("fix_l1ss did not program Linux's qca6390 PHY values");
    }
    // WCN6855 family: fix_l1ss = false in every Linux hw_params entry.
    for rev in [
        HwRev::Wcn6855Hw20,
        HwRev::Wcn6855Hw21,
        HwRev::Qca2066Hw21,
        HwRev::Qca6698aqHw21,
    ] {
        match rev.params() {
            Some(p) if p.fix_l1ss.is_none() && !p.static_window_map => {}
            _ => return TestResult::Fail("WCN6855-family hw_params differ from Linux"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_fix_l1ss_programs_qca6390_phy
);

fn smoke_ath11k_msi_user_assignment() -> TestResult {
    // Linux ath11k_pcic_get_user_msi_assignment for WCN6855 HW2.1
    // with ep_base_data 64: user_base_data = base_vector + 64.
    let p = match HwRev::Wcn6855Hw21.params() {
        Some(p) => p,
        None => return TestResult::Fail("WCN6855 HW2.1 has no hw_params"),
    };
    if p.msi.total_vectors != 32 {
        return TestResult::Fail("WCN6855 must request 32 MSI vectors");
    }
    for (name, want) in [
        ("MHI", (3, 64, 0)),
        ("CE", (10, 67, 3)),
        ("WAKE", (1, 77, 13)),
        ("DP", (18, 78, 14)),
    ] {
        if p.msi.user_assignment(name, 64) != Some(want) {
            return TestResult::Fail("WCN6855 MSI user layout differs from Linux");
        }
    }
    if p.msi.user_assignment("BOGUS", 64).is_some() {
        return TestResult::Fail("unknown MSI user must not resolve");
    }
    // Single-vector fallback: every user on vector 0, MHI still 3.
    if MSI_CONFIG_ONE.user_assignment("CE", 50) != Some((1, 50, 0))
        || MSI_CONFIG_ONE.user_assignment("MHI", 50) != Some((3, 50, 0))
    {
        return TestResult::Fail("one-MSI fallback layout differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_msi_user_assignment);

// ── Failure-step codes: one namespace across every layer ───────────

fn smoke_ath11k_step_codes_unique_and_in_range() -> TestResult {
    // The framebuffer panel shows only `wifi: <stage> FAILED step=N`,
    // so a code shared by two layers makes a bare-metal failure
    // ambiguous. Each layer owns a disjoint range; every constant must
    // be unique and inside its range.
    // Add new `step` constants here.
    let layers: &[(&str, u32, u32, &[u32])] = &[
        (
            "pci",
            1,
            9,
            &[
                super::pci::step::BAR0_MAP,
                super::pci::step::LINK_DOWN,
                super::pci::step::UNSUPPORTED_SOC,
                super::pci::step::NO_HW_PARAMS,
                super::pci::step::MSI_UNAVAILABLE,
            ],
        ),
        (
            "mhi_host",
            10,
            39,
            &[
                super::mhi_host::step::NO_DMA_MEMORY,
                super::mhi_host::step::BHI_OFFSET_RANGE,
                super::mhi_host::step::BHIE_OFFSET_RANGE,
                super::mhi_host::step::POWER_UP_BAD_EE,
                super::mhi_host::step::SYSERR_RESET_TIMEOUT,
                super::mhi_host::step::NO_FIRMWARE_IMAGE,
                super::mhi_host::step::BHI_ERROR,
                super::mhi_host::step::BHI_TIMEOUT,
                super::mhi_host::step::BHIE_ERROR,
                super::mhi_host::step::BHIE_TIMEOUT,
                super::mhi_host::step::MHI_RESET_TIMEOUT,
                super::mhi_host::step::READY_TIMEOUT,
                super::mhi_host::step::CHDB_RANGE,
                super::mhi_host::step::ERDB_RANGE,
                super::mhi_host::step::SYS_ERR,
                super::mhi_host::step::MISSION_BAD_EE,
                super::mhi_host::step::M0_TIMEOUT,
                super::mhi_host::step::POWER_UP_TIMEOUT,
                super::mhi_host::step::CHAN_START,
                super::mhi_host::step::CHAN_WRONG_EE,
                super::mhi_host::step::FW_NOT_FOUND,
                super::mhi_host::step::PM_TRANSITION,
                super::mhi_host::step::EVENT_RING_RP,
                super::mhi_host::step::DL_QUEUE,
                super::mhi_host::step::BAD_CONFIG,
                super::mhi_host::step::REG_ACCESS,
            ],
        ),
        (
            "wlfw",
            40,
            79,
            &[
                super::wlfw::step::NO_FW_AUTHORITY,
                super::wlfw::step::SERVER_TIMEOUT,
                super::wlfw::step::SERVER_EXIT,
                super::wlfw::step::IND_REGISTER,
                super::wlfw::step::HOST_CAP,
                super::wlfw::step::MEM_REQUEST_TIMEOUT,
                super::wlfw::step::TARGET_MEM_ALLOC,
                super::wlfw::step::RESPOND_MEM,
                super::wlfw::step::MEM_READY_TIMEOUT,
                super::wlfw::step::TARGET_CAP,
                super::wlfw::step::BDF_FETCH,
                super::wlfw::step::BDF_DOWNLOAD,
                super::wlfw::step::CALDATA_FETCH,
                super::wlfw::step::CALDATA_DOWNLOAD,
                super::wlfw::step::M3_LOAD,
                super::wlfw::step::M3_ALLOC,
                super::wlfw::step::M3_INFO,
                super::wlfw::step::FW_READY_TIMEOUT,
                super::wlfw::step::WLAN_INI,
                super::wlfw::step::WLAN_CFG,
                super::wlfw::step::WLAN_MODE,
                super::wlfw::step::COLDBOOT_MODE,
                super::wlfw::step::FW_RESTART,
                super::wlfw::step::UNSUPPORTED,
                super::wlfw::step::DEVICE_INFO,
                super::wlfw::step::BDF_IOREMAP,
            ],
        ),
        (
            "hal",
            80,
            89,
            &[
                super::hal::step::NO_DMA_MEMORY,
                super::hal::step::BAD_RING_NUM,
                super::hal::step::RING_ID_RANGE,
                super::hal::step::SHADOW_FULL,
                super::hal::step::NO_SHADOW_REG,
                super::hal::step::BAD_RING_SIZE,
                super::hal::step::NO_REGS,
                super::hal::step::RING_MEM_SIZE,
                super::hal::step::RING_IN_USE,
            ],
        ),
        (
            "ce",
            90,
            119,
            &[
                super::ce::step::ALLOC_SRC_RING,
                super::ce::step::ALLOC_DST_RING,
                super::ce::step::ALLOC_STATUS_RING,
                super::ce::step::ALLOC_TX_BUF,
                super::ce::step::ALLOC_RX_BUF,
                super::ce::step::INIT_RING,
                super::ce::step::BAD_PIPE,
                super::ce::step::OVERSIZE,
                super::ce::step::RING_FULL,
                super::ce::step::SHUTDOWN,
                super::ce::step::RX_BAD_LEN,
                super::ce::step::RX_POST,
            ],
        ),
        (
            "core",
            120,
            149,
            &[
                super::core::step::UNSUPPORTED,
                super::core::step::NO_DEVICE,
                super::core::step::HTC_INIT,
                super::core::step::HTC_READY_TIMEOUT,
                super::core::step::HTC_BAD_READY,
                super::core::step::HTT_CONNECT,
                super::core::step::HTT_CONNECT_TIMEOUT,
                super::core::step::WMI_CONNECT,
                super::core::step::WMI_CONNECT_TIMEOUT,
                super::core::step::HTC_START,
                super::core::step::SERVICE_READY_TIMEOUT,
                super::core::step::SERVICE_READY_DECODE,
                super::core::step::WMI_INIT,
                super::core::step::WMI_SEND_CREDITS,
                super::core::step::WMI_SEND,
                super::core::step::READY_TIMEOUT,
                super::core::step::READY_DECODE,
                super::core::step::NO_WMI_EP,
                super::core::step::EVENT_TIMEOUT,
                super::core::step::HTT_SEND,
            ],
        ),
        (
            "mac",
            150,
            199,
            &[
                super::mac::step::START_PDEV_PARAM,
                super::mac::step::START_PROBE_OUI,
                super::mac::step::START_DFS_OFFLOAD,
                super::mac::step::START_CHAN_LIST,
                super::mac::step::START_LRO,
                super::mac::step::START_DP,
                super::mac::step::VDEV_CREATE,
                super::mac::step::VDEV_PARAM,
                super::mac::step::STA_PS,
                super::mac::step::REG_EVENT,
                super::mac::step::SCAN_BUSY,
                super::mac::step::SCAN_START_CMD,
                super::mac::step::SCAN_START_TIMEOUT,
                super::mac::step::SCAN_START_FAILED,
                super::mac::step::SCAN_TIMEOUT,
                super::mac::step::SCAN_STOP_TIMEOUT,
                super::mac::step::SCAN_11D,
                super::mac::step::CONNECT_NO_BSS,
                super::mac::step::CONNECT_UNSUPPORTED,
                super::mac::step::CONNECT_STATE,
                super::mac::step::TXPOWER,
                super::mac::step::WMM_PARAMS,
                super::mac::step::PEER_CREATE,
                super::mac::step::PEER_MAP_TIMEOUT,
                super::mac::step::VDEV_START,
                super::mac::step::VDEV_START_TIMEOUT,
                super::mac::step::VDEV_START_STATUS,
                super::mac::step::AUTH_TX,
                super::mac::step::AUTH_TIMEOUT,
                super::mac::step::AUTH_REJECTED,
                super::mac::step::ASSOC_TX,
                super::mac::step::ASSOC_TIMEOUT,
                super::mac::step::ASSOC_REJECTED,
                super::mac::step::PEER_ASSOC,
                super::mac::step::PEER_ASSOC_TIMEOUT,
                super::mac::step::VDEV_UP,
                super::mac::step::EAPOL_TIMEOUT,
                super::mac::step::EAPOL_MIC,
                super::mac::step::EAPOL_PROTO,
                super::mac::step::KEY_INSTALL,
                super::mac::step::KEY_INSTALL_TIMEOUT,
                super::mac::step::KEY_INSTALL_STATUS,
                super::mac::step::PEER_AUTHORIZE,
                super::mac::step::LINK_KICKOUT,
                super::mac::step::LINK_BEACON_LOSS,
                super::mac::step::LINK_DEAUTH_RX,
                super::mac::step::VDEV_STOP_TIMEOUT,
                super::mac::step::PEER_DELETE_TIMEOUT,
                super::mac::step::WMI_SEND,
                super::mac::step::EAPOL_GTK,
            ],
        ),
        (
            "mac (security / HE)",
            270,
            299,
            &[
                super::mac::step::SA_QUERY_TIMEOUT,
                super::mac::step::SAE_PWE,
                super::mac::step::SAE_REJECTED,
                super::mac::step::SAE_COMMIT,
                super::mac::step::SAE_CONFIRM,
                super::mac::step::SAE_TIMEOUT,
                super::mac::step::HE_PARAM,
                super::mac::step::PTK_REKEY,
            ],
        ),
        (
            "dp_ring",
            200,
            219,
            &[
                super::dp_ring::step::SRNG_SETUP,
                super::dp_ring::step::RING_ALLOC,
                super::dp_ring::step::LINK_DESC_BANKS,
                super::dp_ring::step::LINK_DESC_ALLOC,
                super::dp_ring::step::SCATTER_UNSUPPORTED,
                super::dp_ring::step::BAD_RING_TYPE,
                super::dp_ring::step::ALREADY_SET_UP,
                super::dp_ring::step::NOT_SET_UP,
                super::dp_ring::step::TX_IDR_FULL,
                super::dp_ring::step::TX_RING_FULL,
                super::dp_ring::step::TX_NOT_DATA,
                super::dp_ring::step::TX_BAD_ENCAP,
                super::dp_ring::step::TX_SHUTDOWN,
                super::dp_ring::step::TX_DMA,
                super::dp_ring::step::TX_FRAME_LEN,
                super::dp_ring::step::LINK_DESC_LOOKUP,
                super::dp_ring::step::LINK_DESC_RETURN,
            ],
        ),
        (
            "htt",
            220,
            229,
            &[
                super::htt::step::RING_TYPE,
                super::htt::step::RING_ID,
                super::htt::step::NO_RING,
                super::htt::step::T2H_TRUNCATED,
                super::htt::step::VERSION,
                super::htt::step::VERSION_TIMEOUT,
            ],
        ),
        (
            "dp_peer",
            230,
            249,
            &[
                super::dp_peer::step::PEER_NOT_FOUND,
                super::dp_peer::step::QDESC_ALLOC,
                super::dp_peer::step::REO_CMD_RING_FULL,
                super::dp_peer::step::REO_CMD_SHUTDOWN,
                super::dp_peer::step::REO_CMD_UNSUPPORTED,
                super::dp_peer::step::REO_CMD_UNKNOWN,
                super::dp_peer::step::REO_CMD_NUM_ZERO,
                super::dp_peer::step::REO_CMD_NO_BLOCK_RES,
                super::dp_peer::step::BAD_TID,
                super::dp_peer::step::WMI_SEND,
            ],
        ),
        (
            "runtime",
            250,
            269,
            &[
                super::runtime::step::DP_UNSUPPORTED,
                super::runtime::step::DP_MISSING,
                super::runtime::step::HTT_VER_SEND,
                super::runtime::step::SRING_SETUP_SEND,
                super::runtime::step::DP_IRQ_CONFIG,
                super::runtime::step::MAC_CAPS,
                super::runtime::step::NET_REGISTER,
                super::runtime::step::IF_DOWN_VDEV_DELETE,
                super::runtime::step::RECOVERY_LIMIT,
                super::runtime::step::RECOVERY_FW,
                super::runtime::step::RECOVERY_CORE,
                super::runtime::step::RECOVERY_MAC,
            ],
        ),
    ];
    let mut seen: Vec<u32> = Vec::new();
    for &(_name, lo, hi, codes) in layers {
        for &c in codes {
            if c < lo || c > hi {
                return TestResult::Fail("ath11k step code outside its layer's range");
            }
            if seen.contains(&c) {
                return TestResult::Fail("ath11k step code used by two constants");
            }
            seen.push(c);
        }
    }
    if seen.contains(&0) {
        return TestResult::Fail("step 0 means no failure and must not be a code");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_step_codes_unique_and_in_range
);

// Suppress the unused-import warning when the `Vec` import isn't
// used by any helper above (compiler can't tell from the macro
// expansion).
#[allow(dead_code)]
fn _force_used() {
    let _: Vec<u8> = Vec::new();
}
