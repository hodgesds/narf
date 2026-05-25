//! iwlwifi smokes — co-located with the driver per project
//! convention.
//!
//! Stage 1: PCI match-table registration only.
//! Stage 2: CSR offset table sanity + PRPH packing + ucode TLV
//!          header decode.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    apm, csr, prph, register_pci_driver, ucode, IWL_DEV_AX200, IWL_DEV_AX201, IWL_DEV_AX210,
    IWL_DEV_AX211, IWL_VENDOR,
};

extern crate alloc;

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

// ── Stage 2 — APM init sequence constants ─────────────────────────

fn smoke_iwlwifi_apm_timeouts_sane() -> TestResult {
    // Pre-Bz settle: Linux uses usleep_range(5000, 6000); pick 6ms.
    if apm::APM_SW_RESET_PRE_BZ_MS == 0 || apm::APM_SW_RESET_PRE_BZ_MS > 50 {
        return TestResult::Fail("pre-Bz reset settle outside sane range");
    }
    if apm::APM_SW_RESET_BZ_MS == 0 || apm::APM_SW_RESET_BZ_MS > 50 {
        return TestResult::Fail("Bz reset settle outside sane range");
    }
    // Linux activate-NIC poll budget is iwl_poll_bits(...,25000) = 25 ms.
    if apm::APM_ACTIVATE_NIC_TIMEOUT_MS != 25 {
        return TestResult::Fail("activate-NIC timeout drifted from 25 ms");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_apm_timeouts_sane);

// ── Stage 2 — ucode TLV header decode ─────────────────────────────

fn smoke_iwlwifi_ucode_magic_constant() -> TestResult {
    // Magic per Linux fw/file.h IWL_TLV_UCODE_MAGIC.
    if ucode::IWL_TLV_UCODE_MAGIC != 0x0A4C_5749 {
        return TestResult::Fail("ucode magic value drifted from Linux fw/file.h");
    }
    if ucode::TLV_HEADER_BYTES != 88 {
        return TestResult::Fail("ucode TLV header length should be 88");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_ucode_magic_constant);

fn smoke_iwlwifi_ucode_parse_rejects_short_blob() -> TestResult {
    // 80 bytes is shorter than the 88-byte header — must fail with
    // TooShort (not crash on out-of-bounds reads).
    let blob = [0u8; 80];
    match ucode::parse_header(&blob) {
        Err(ucode::ParseError::TooShort) => TestResult::Pass,
        _ => TestResult::Fail("expected TooShort error on undersized blob"),
    }
}
kernel_test_in!(
    "drivers/net/iwlwifi",
    smoke_iwlwifi_ucode_parse_rejects_short_blob
);

fn smoke_iwlwifi_ucode_parse_rejects_bad_magic() -> TestResult {
    let mut blob = [0u8; 96];
    // Magic at bytes 4..8 — set to a wrong value.
    blob[4..8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    match ucode::parse_header(&blob) {
        Err(ucode::ParseError::BadMagic(0x1122_3344)) => TestResult::Pass,
        _ => TestResult::Fail("expected BadMagic for non-magic blob"),
    }
}
kernel_test_in!(
    "drivers/net/iwlwifi",
    smoke_iwlwifi_ucode_parse_rejects_bad_magic
);

fn smoke_iwlwifi_ucode_parse_header_minimal() -> TestResult {
    // Hand-assemble a minimal TLV blob: header + a single SEC_RT
    // TLV with dest_offset=0x00880000 and a 16-byte payload.
    let payload = b"sixteen-byte-pay";
    assert!(payload.len() == 16);
    let tlv_len: u32 = 4 + 16; // dest_offset + payload
    let mut blob = alloc::vec::Vec::<u8>::new();
    blob.extend_from_slice(&0u32.to_le_bytes()); // zero
    blob.extend_from_slice(&ucode::IWL_TLV_UCODE_MAGIC.to_le_bytes());
    blob.extend_from_slice(b"AX210-77.ucode\0"); // human readable (15 bytes)
    blob.extend_from_slice(&[0u8; 49]); // pad to 64 bytes
    blob.extend_from_slice(&0x0001_0002u32.to_le_bytes()); // ver
    blob.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // build
    blob.extend_from_slice(&0u64.to_le_bytes()); // ignore
    // TLV: type=19 (SecRt), len=20, payload[dest=0x00880000, "sixteen-byte-pay"]
    blob.extend_from_slice(&19u32.to_le_bytes());
    blob.extend_from_slice(&tlv_len.to_le_bytes());
    blob.extend_from_slice(&0x0088_0000u32.to_le_bytes());
    blob.extend_from_slice(payload);

    let parsed = match ucode::parse_header(&blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("expected successful header parse"),
    };
    if parsed.header.version != 0x0001_0002 {
        return TestResult::Fail("version mis-decoded");
    }
    if parsed.header.build != 0x1234_5678 {
        return TestResult::Fail("build mis-decoded");
    }
    if !parsed.header.human_readable.starts_with("AX210-77.ucode") {
        return TestResult::Fail("human-readable mis-decoded");
    }
    if parsed.sections.len() != 1 {
        return TestResult::Fail("expected one section");
    }
    let s = &parsed.sections[0];
    if s.kind != ucode::TlvType::SecRt {
        return TestResult::Fail("section kind mis-decoded");
    }
    if s.dest_offset != 0x0088_0000 {
        return TestResult::Fail("dest_offset mis-decoded");
    }
    if s.payload_len != 16 {
        return TestResult::Fail("payload len mis-decoded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/iwlwifi",
    smoke_iwlwifi_ucode_parse_header_minimal
);

fn smoke_iwlwifi_ucode_parse_rejects_truncated_tlv() -> TestResult {
    // A TLV whose declared length runs past EOF must be rejected.
    let mut blob = alloc::vec::Vec::<u8>::new();
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&ucode::IWL_TLV_UCODE_MAGIC.to_le_bytes());
    blob.extend_from_slice(&[0u8; 64]);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    // Type = SecRt(19), declared length = 100 but only 4 bytes follow.
    blob.extend_from_slice(&19u32.to_le_bytes());
    blob.extend_from_slice(&100u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    match ucode::parse_header(&blob) {
        Err(ucode::ParseError::TruncatedTlv { .. }) => TestResult::Pass,
        _ => TestResult::Fail("expected TruncatedTlv error"),
    }
}
kernel_test_in!(
    "drivers/net/iwlwifi",
    smoke_iwlwifi_ucode_parse_rejects_truncated_tlv
);

fn smoke_iwlwifi_ucode_metadata_tlv_counted() -> TestResult {
    // FwVersion (type 36) is metadata, not a section — should bump
    // the metadata counter but not append to sections.
    let mut blob = alloc::vec::Vec::<u8>::new();
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&ucode::IWL_TLV_UCODE_MAGIC.to_le_bytes());
    blob.extend_from_slice(&[0u8; 64]);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    // Two FwVersion TLVs, 12 bytes each (3 × u32).
    for _ in 0..2 {
        blob.extend_from_slice(&36u32.to_le_bytes());
        blob.extend_from_slice(&12u32.to_le_bytes());
        blob.extend_from_slice(&[0u8; 12]);
    }
    let parsed = match ucode::parse_header(&blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("expected successful parse"),
    };
    if !parsed.sections.is_empty() {
        return TestResult::Fail("FwVersion TLVs should not produce sections");
    }
    if parsed.metadata_tlv_count != 2 {
        return TestResult::Fail("expected metadata_tlv_count = 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/iwlwifi",
    smoke_iwlwifi_ucode_metadata_tlv_counted
);

fn smoke_iwlwifi_apm_family_default() -> TestResult {
    // AX-class default is the pre-Bz flow (uses CSR_RESET's bit 7,
    // polls MAC_CLOCK_READY). Bz/Be200 is a future task.
    if apm::Family::default_for_ax() != apm::Family::Pre {
        return TestResult::Fail("AX-class default must be Family::Pre");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_apm_family_default);

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
