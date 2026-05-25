//! iwlwifi smokes — co-located with the driver per project
//! convention.
//!
//! Stage 1: PCI match-table registration only.
//! Stage 2: CSR offset table sanity + PRPH packing + ucode TLV
//!          header decode.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    apm, csr, prph, register_pci_driver, IWL_DEV_AX200, IWL_DEV_AX201, IWL_DEV_AX210,
    IWL_DEV_AX211, IWL_VENDOR,
};

// ── Stage 1 — PCI match table ─────────────────────────────────────

fn smoke_iwlwifi_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [IWL_DEV_AX200, IWL_DEV_AX201, IWL_DEV_AX210, IWL_DEV_AX211];
    for did in want {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: IWL_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("iwlwifi PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_pci_match_table);

// ── Stage 2 — CSR layout sanity ───────────────────────────────────

/// CSRs adapted from Linux `iwl-csr.h` — these absolute offsets are
/// load-bearing across every AX-class part. If the value drifts the
/// driver silently writes to the wrong register, so we lock them in
/// to specific bytes.
fn smoke_iwlwifi_csr_offsets() -> TestResult {
    let pairs = [
        ("CSR_HW_IF_CONFIG_REG", csr::CSR_HW_IF_CONFIG_REG, 0x000u32),
        ("CSR_INT_COALESCING", csr::CSR_INT_COALESCING, 0x004),
        ("CSR_INT", csr::CSR_INT, 0x008),
        ("CSR_INT_MASK", csr::CSR_INT_MASK, 0x00C),
        ("CSR_FH_INT_STATUS", csr::CSR_FH_INT_STATUS, 0x010),
        ("CSR_RESET", csr::CSR_RESET, 0x020),
        ("CSR_GP_CNTRL", csr::CSR_GP_CNTRL, 0x024),
        ("CSR_HW_REV", csr::CSR_HW_REV, 0x028),
        ("CSR_HW_RF_ID", csr::CSR_HW_RF_ID, 0x09C),
        ("CSR_GIO_REG", csr::CSR_GIO_REG, 0x03C),
        ("CSR_GIO_CHICKEN_BITS", csr::CSR_GIO_CHICKEN_BITS, 0x100),
        ("CSR_ANA_PLL_CFG", csr::CSR_ANA_PLL_CFG, 0x20C),
        ("HBUS_BASE", csr::HBUS_BASE, 0x400),
        (
            "HBUS_TARG_PRPH_WADDR",
            csr::HBUS_TARG_PRPH_WADDR,
            0x400 + 0x044,
        ),
        (
            "HBUS_TARG_PRPH_RADDR",
            csr::HBUS_TARG_PRPH_RADDR,
            0x400 + 0x048,
        ),
        (
            "HBUS_TARG_PRPH_WDAT",
            csr::HBUS_TARG_PRPH_WDAT,
            0x400 + 0x04C,
        ),
        (
            "HBUS_TARG_PRPH_RDAT",
            csr::HBUS_TARG_PRPH_RDAT,
            0x400 + 0x050,
        ),
        ("CSR_MSIX_BASE", csr::CSR_MSIX_BASE, 0x2000),
        (
            "CSR_MSIX_FH_INT_CAUSES_AD",
            csr::CSR_MSIX_FH_INT_CAUSES_AD,
            0x2800,
        ),
    ];
    for (name, got, want) in pairs {
        if got != want {
            let _ = name;
            return TestResult::Fail("iwlwifi CSR offset drifted from Linux iwl-csr.h");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_csr_offsets);

fn smoke_iwlwifi_csr_reset_bits() -> TestResult {
    // The SW_RESET bit is the load-bearing one for `iwl_pcie_sw_reset`
    // on pre-Bz parts. Linux uses 0x80 (bit 7).
    if csr::CSR_RESET_REG_FLAG_SW_RESET != 0x0000_0080 {
        return TestResult::Fail("CSR_RESET SW_RESET bit drifted");
    }
    // GP_CNTRL bits that drive `iwl_pcie_apm_init`'s INIT_DONE +
    // MAC_CLOCK_READY handshake.
    if csr::CSR_GP_CNTRL_REG_FLAG_INIT_DONE != 0x0000_0004 {
        return TestResult::Fail("GP_CNTRL INIT_DONE bit drifted");
    }
    if csr::CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY != 0x0000_0001 {
        return TestResult::Fail("GP_CNTRL MAC_CLOCK_READY bit drifted");
    }
    // CSR_INI_SET_MASK should include ALIVE, HW_ERR, SW_ERR, RF_KILL.
    let must = csr::CSR_INT_BIT_ALIVE
        | csr::CSR_INT_BIT_HW_ERR
        | csr::CSR_INT_BIT_SW_ERR
        | csr::CSR_INT_BIT_RF_KILL;
    if csr::CSR_INI_SET_MASK & must != must {
        return TestResult::Fail("CSR_INI_SET_MASK lost a load-bearing bit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_csr_reset_bits);

// ── Stage 2 — PRPH indirect-access packing ────────────────────────

fn smoke_iwlwifi_prph_pack_pre_ax210() -> TestResult {
    // Pre-AX210 mask = 0x000F_FFFF; size-code (3<<24) = 0x0300_0000.
    // pack(0x1234_5, Mask20) == 0x0301_2345.
    let p = prph::pack_addr(0x0001_2345, prph::PrphMask::Mask20);
    if p != 0x0301_2345 {
        return TestResult::Fail("PRPH-20 pack value drifted");
    }
    // Address out of range must be truncated, never wrap into the
    // size-code field.
    let trunc = prph::pack_addr(0xFFFF_FFFF, prph::PrphMask::Mask20);
    if trunc != (0x0300_0000 | 0x000F_FFFF) {
        return TestResult::Fail("PRPH-20 mask must truncate to 20 bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_prph_pack_pre_ax210);

fn smoke_iwlwifi_prph_pack_ax210() -> TestResult {
    // AX210 mask = 0x00FF_FFFF.
    let p = prph::pack_addr(0x0012_3456, prph::PrphMask::Mask24);
    if p != 0x0312_3456 {
        return TestResult::Fail("PRPH-24 pack value drifted");
    }
    // Address beyond 24 bits truncates within the size code.
    let trunc = prph::pack_addr(0xFFFF_FFFF, prph::PrphMask::Mask24);
    if trunc != (0x0300_0000 | 0x00FF_FFFF) {
        return TestResult::Fail("PRPH-24 mask must truncate to 24 bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_prph_pack_ax210);

fn smoke_iwlwifi_prph_apmg_offsets() -> TestResult {
    // APMG sub-block within PRPH is at +0x3000 per iwl-prph.h.
    if prph::APMG_BASE != 0x3000 {
        return TestResult::Fail("APMG_BASE drifted");
    }
    if prph::APMG_CLK_EN_REG != 0x3004 {
        return TestResult::Fail("APMG_CLK_EN_REG drifted");
    }
    if prph::APMG_PCIDEV_STT_REG != 0x3010 {
        return TestResult::Fail("APMG_PCIDEV_STT_REG drifted");
    }
    if prph::APMG_CLK_VAL_DMA_CLK_RQT != 0x0000_0200 {
        return TestResult::Fail("DMA-CLK-RQT bit drifted");
    }
    if prph::APMG_PCIDEV_STT_VAL_L1_ACT_DIS != 0x0000_0800 {
        return TestResult::Fail("L1_ACT_DIS bit drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_prph_apmg_offsets);

fn smoke_iwlwifi_csr_hw_rev_decode() -> TestResult {
    // From Linux: `CSR_HW_REV_TYPE(_val) = ((_val) & 0x000FFF0) >> 4`.
    // Test: HW_REV = 0x_____YYx where YY is the type, x is step+dash.
    let v = (csr::CSR_HW_REV_TYPE_SO << 4) | 0x05; // type=0x370, step+dash=5
    if csr::csr_hw_rev_type(v) != csr::CSR_HW_REV_TYPE_SO {
        return TestResult::Fail("csr_hw_rev_type decode wrong");
    }
    if csr::csr_hw_rev_step_dash(v) != 0x05 {
        return TestResult::Fail("csr_hw_rev_step_dash decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_csr_hw_rev_decode);
