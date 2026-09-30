//! RTL8127 driver smokes.
//!
//! Covers the pieces that are pure data or pure decode and therefore
//! checkable without hardware: the PCI match table, the VER_80 XID
//! decode, descriptor layout, PHYStatus decode, and the structural
//! shape of the transcribed PHY-config table.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    build_rx_desc, build_tx_desc, cr_reset_value, decode_mac, decode_xid, firmware_name_for_xid,
    mac_is_invalid, mac_version_from_xid, name_for, phy_config_table_is_well_formed, MacVersion,
    PhyConfigKind, PhyStatus, TxDesc, COALESCE_BLOCK_END_8127, COALESCE_BLOCK_START, CR_RST,
    FIRMWARE_8127A_1, INT32_LINKCHG, INT32_ROK, INT32_TOK, PHYSTAT_1000BPSF, PHYSTAT_FULLDUP,
    PHYSTAT_LINKSTS, PHY_CONFIG_TABLE, PHY_CONFIG_TABLE_LEN, REG_IMR_8125, REG_INT_CFG0_8125,
    REG_INT_CFG1_8125, REG_ISR_8125, REG_TPPOLL_8125, RING_LEN, RTL_DEV_8127, RTL_VENDOR, RXD_EOR,
    RXD_LEN_MASK, RXD_OWN, RX_BUF_LEN, RX_FETCH_DFLT_8125, RX_PAUSE_SLOT_ON, TPPOLL_NPQ, TXD_EOR,
    TXD_FS, TXD_LS, TXD_OWN,
};

// ── PCI match table ──────────────────────────────────────────────────

fn smoke_rtl8127_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m| {
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: RTL_VENDOR, device,
        } if device == RTL_DEV_8127)
    });
    if !matched {
        return TestResult::Fail("rtl8127 PCI match table missing 10ec:8127");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_pci_match_table);

fn smoke_rtl8127_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8127) != "rtl8127" {
        return TestResult::Fail("rtl8127 name wrong");
    }
    if name_for(0xFFFF) != "rtl8127" {
        return TestResult::Fail("default name wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_name_for_known_ids);

// ── MAC version (VER_80) ─────────────────────────────────────────────

fn smoke_rtl8127_mac_version_ver80() -> TestResult {
    // Linux rtl_chip_infos[]:
    //   { 0x7cf, 0x6c9, RTL_GIGA_MAC_VER_80, "RTL8127A", FIRMWARE_8127A_1 }
    let xid = decode_xid(0x6c9u32 << 20);
    if xid != 0x6c9 {
        return TestResult::Fail("decode_xid mangled 0x6c9");
    }
    if mac_version_from_xid(xid) != MacVersion::Ver80 {
        return TestResult::Fail("XID 0x6c9 did not decode to Ver80");
    }
    // An XID outside the table stays Unknown rather than silently
    // claiming VER_80.
    match mac_version_from_xid(0x649) {
        MacVersion::Unknown(0x649) => {}
        _ => return TestResult::Fail("RTL8126A XID misclassified as RTL8127A"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_mac_version_ver80);

fn smoke_rtl8127_firmware_name() -> TestResult {
    if firmware_name_for_xid(0x6c9) != FIRMWARE_8127A_1 {
        return TestResult::Fail("firmware name for 0x6c9 wrong");
    }
    if FIRMWARE_8127A_1 != "rtl_nic/rtl8127a-1.fw" {
        return TestResult::Fail("FIRMWARE_8127A_1 does not match Linux");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_firmware_name);

// ── Register-offset floor shared with the 8125 family ────────────────

fn smoke_rtl8127_register_floor_matches_8125() -> TestResult {
    // The RTL8127 inherits the 8125 register map unchanged; these are
    // the offsets `rtl_hw_start_8125_common` touches.
    if REG_INT_CFG0_8125 != 0x34 {
        return TestResult::Fail("INT_CFG0_8125 offset wrong");
    }
    if REG_IMR_8125 != 0x38 || REG_ISR_8125 != 0x3C {
        return TestResult::Fail("IntrMask/IntrStatus offsets wrong");
    }
    if REG_INT_CFG1_8125 != 0x7A {
        return TestResult::Fail("INT_CFG1_8125 offset wrong");
    }
    if REG_TPPOLL_8125 != 0x90 || TPPOLL_NPQ != 1 << 6 {
        return TestResult::Fail("TxPoll doorbell wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_register_floor_matches_8125
);

fn smoke_rtl8127_coalesce_block_is_ver80_width() -> TestResult {
    // VER_63 / VER_70 clear 0xa00..0xa80; VER_80 clears the full
    // 0xa00..0xb00. Getting this wrong leaves half the coalescing
    // block live on the RTL8127.
    if COALESCE_BLOCK_START != 0xa00 {
        return TestResult::Fail("coalesce block start wrong");
    }
    if COALESCE_BLOCK_END_8127 != 0xb00 {
        return TestResult::Fail("coalesce block end is not the VER_80 width");
    }
    if (COALESCE_BLOCK_END_8127 - COALESCE_BLOCK_START) % 4 != 0 {
        return TestResult::Fail("coalesce block is not a whole number of dwords");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_coalesce_block_is_ver80_width
);

fn smoke_rtl8127_rxcfg_has_pause_slot_on() -> TestResult {
    // `rtl_init_rxcfg` VER_63..VER_LAST arm.
    if RX_FETCH_DFLT_8125 != 8 << 27 {
        return TestResult::Fail("RX_FETCH_DFLT_8125 wrong");
    }
    if RX_PAUSE_SLOT_ON != 1 << 11 {
        return TestResult::Fail("RX_PAUSE_SLOT_ON wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_rxcfg_has_pause_slot_on);

// ── Descriptor layout ────────────────────────────────────────────────

fn smoke_rtl8127_descriptor_layout() -> TestResult {
    if core::mem::size_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc is not 16 bytes");
    }
    let tx = build_tx_desc(0, 0x1234_5678_9ABC_D000, 64);
    if tx.flags_len & (TXD_OWN | TXD_FS | TXD_LS) != (TXD_OWN | TXD_FS | TXD_LS) {
        return TestResult::Fail("TX descriptor missing OWN/FS/LS");
    }
    if tx.flags_len & TXD_EOR != 0 {
        return TestResult::Fail("non-wrap TX slot must not set EOR");
    }
    if tx.addr_lo != 0x9ABC_D000 || tx.addr_hi != 0x1234_5678 {
        return TestResult::Fail("TX descriptor address split wrong");
    }
    let tx_last = build_tx_desc(RING_LEN - 1, 0, 64);
    if tx_last.flags_len & TXD_EOR == 0 {
        return TestResult::Fail("wrap TX slot must set EOR");
    }

    let rx = build_rx_desc(0, 0xDEAD_0000, RX_BUF_LEN as u32);
    if rx.flags_len & RXD_OWN == 0 {
        return TestResult::Fail("fresh RX descriptor must be NIC-owned");
    }
    if rx.flags_len & RXD_LEN_MASK != RX_BUF_LEN as u32 {
        return TestResult::Fail("RX descriptor buffer size wrong");
    }
    let rx_last = build_rx_desc(RING_LEN - 1, 0, RX_BUF_LEN as u32);
    if rx_last.flags_len & RXD_EOR == 0 {
        return TestResult::Fail("wrap RX slot must set EOR");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_descriptor_layout);

// ── PHYStatus decode ─────────────────────────────────────────────────

fn smoke_rtl8127_phy_status_decode() -> TestResult {
    let down = PhyStatus::parse(0);
    if down.link_up || down.speed_label() != "down" {
        return TestResult::Fail("zero PHYStatus should read as down");
    }
    let up_1g = PhyStatus::parse(PHYSTAT_LINKSTS | PHYSTAT_FULLDUP | PHYSTAT_1000BPSF);
    if !up_1g.link_up || !up_1g.full_duplex || !up_1g.speed_1000m_or_above {
        return TestResult::Fail("1G full-duplex PHYStatus decoded wrong");
    }
    // The register carries no 10G bit — the label must not claim one.
    if up_1g.speed_label() != ">=1G" {
        return TestResult::Fail("speed_label invented a rate the register cannot report");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_phy_status_decode);

// ── MAC helpers ──────────────────────────────────────────────────────

fn smoke_rtl8127_mac_helpers() -> TestResult {
    if cr_reset_value() != CR_RST {
        return TestResult::Fail("cr_reset_value wrong");
    }
    if decode_mac(&[1, 2, 3, 4, 5]).is_some() {
        return TestResult::Fail("decode_mac accepted a short slice");
    }
    match decode_mac(&[0x2C, 0xEA, 0xFC, 0xC7, 0xAC, 0x9A]) {
        Some(m) => {
            if m != [0x2C, 0xEA, 0xFC, 0xC7, 0xAC, 0x9A] {
                return TestResult::Fail("decode_mac mangled the address");
            }
        }
        None => return TestResult::Fail("decode_mac rejected a 6-byte slice"),
    }
    if !mac_is_invalid([0; 6]) || !mac_is_invalid([0xFF; 6]) {
        return TestResult::Fail("all-zero / all-FF must be invalid");
    }
    if mac_is_invalid([0x2C, 0xEA, 0xFC, 0xC7, 0xAC, 0x9A]) {
        return TestResult::Fail("a real MAC was rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_mac_helpers);

// ── PHY-config table shape ───────────────────────────────────────────

fn smoke_rtl8127_phy_config_table_shape() -> TestResult {
    // The transcription of `rtl8127a_1_hw_phy_config` is long; assert
    // it is non-trivial and structurally consistent rather than
    // re-listing 130+ register writes here.
    if PHY_CONFIG_TABLE_LEN != PHY_CONFIG_TABLE.len() {
        return TestResult::Fail("PHY_CONFIG_TABLE_LEN out of sync");
    }
    if PHY_CONFIG_TABLE_LEN < 100 {
        return TestResult::Fail("PHY config table looks truncated");
    }
    if !phy_config_table_is_well_formed() {
        return TestResult::Fail("a PHY config entry uses the wrong register for its kind");
    }
    // The first entry must be rtl8168g_enable_gphy_10m, which is the
    // first thing the Linux function does after applying firmware.
    let first = PHY_CONFIG_TABLE[0];
    if first.kind != PhyConfigKind::ModifyPaged
        || first.page != 0x0a44
        || first.reg != 0x11
        || first.val != 1 << 11
    {
        return TestResult::Fail("first PHY entry is not enable_gphy_10m");
    }
    // The last three entries are rtl8125_common_config_eee_phy.
    let tail = &PHY_CONFIG_TABLE[PHY_CONFIG_TABLE_LEN - 3..];
    let expect = [(0x0a6du16, 0x14u16), (0x0a42, 0x14), (0x0a4a, 0x11)];
    for (e, (page, reg)) in tail.iter().zip(expect.iter()) {
        if e.page != *page || e.reg != *reg || e.kind != PhyConfigKind::ModifyPaged {
            return TestResult::Fail("PHY config table does not end with the EEE clears");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_phy_config_table_shape);

// ── IRQ mask ─────────────────────────────────────────────────────────

fn smoke_rtl8127_irq_mask_bits() -> TestResult {
    if INT32_ROK != 1 << 0 || INT32_TOK != 1 << 2 || INT32_LINKCHG != 1 << 5 {
        return TestResult::Fail("32-bit IMR/ISR bit positions wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_irq_mask_bits);

// ── PHY: OCP addressing ──────────────────────────────────────────────

fn smoke_rtl8127_ocp_address_validation() -> TestResult {
    use super::phy::ocp_addr_ok;
    // GPHY_OCP packs the address at bit 15, so an odd address or one
    // above 16 bits would corrupt the transaction. Linux's
    // rtl_ocp_reg_failure rejects exactly `reg & 0xffff0001`.
    if !ocp_addr_ok(0xB87C) || !ocp_addr_ok(0) || !ocp_addr_ok(0xFFFE) {
        return TestResult::Fail("a valid even address was rejected");
    }
    if ocp_addr_ok(0xB87D) {
        return TestResult::Fail("an odd address was accepted");
    }
    if ocp_addr_ok(0x1_0000) {
        return TestResult::Fail("an address above 16 bits was accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_ocp_address_validation);

fn smoke_rtl8127_paged_address_translation() -> TestResult {
    use super::phy::{PhyAccess, OCP_STD_PHY_BASE};
    // phy_modify_paged(0x0bf3, 0x14, ...) -> ocp_base 0xbf30,
    // register rebased by 0x10 and doubled: 0xbf30 + 4*2 = 0xbf38.
    match PhyAccess::paged_addr(0x0BF3, 0x14) {
        Ok(0xBF38) => {}
        other => {
            let _ = other;
            return TestResult::Fail("paged address translation wrong");
        }
    }
    // r8168g_phy_param's selector: page 0x0a43 reg 0x13 -> 0xa436.
    match PhyAccess::paged_addr(0x0A43, 0x13) {
        Ok(0xA436) => {}
        _ => return TestResult::Fail("r8168g param selector address wrong"),
    }
    // ...and its data register 0x14 -> 0xa438.
    match PhyAccess::paged_addr(0x0A43, 0x14) {
        Ok(0xA438) => {}
        _ => return TestResult::Fail("r8168g param data address wrong"),
    }
    // Page 0 is the asymmetric case: OCP_STD_PHY_BASE with the
    // register *not* rebased. Applying the -0x10 here would shift
    // every page-0 access by 0x20 bytes.
    match PhyAccess::paged_addr(0, 0x04) {
        Ok(a) if a == OCP_STD_PHY_BASE as u32 + 8 => {}
        _ => return TestResult::Fail("page 0 must not rebase the register"),
    }
    // A paged access below the vendor window has no valid address.
    if PhyAccess::paged_addr(0x0A43, 0x04).is_ok() {
        return TestResult::Fail("a paged register below 0x10 was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_paged_address_translation
);

fn smoke_rtl8127_every_table_entry_has_an_address() -> TestResult {
    use super::phy::{
        ocp_addr_ok, PhyAccess, R8168G_PARAM_PAGE, RTL8125_PARAM_DATA_ADDR, RTL8125_PARAM_SEL_ADDR,
    };
    use super::{PhyConfigKind, PHY_CONFIG_TABLE};
    // Every one of the 134 transcribed entries must translate to a
    // legal OCP address. An entry that does not would abort the whole
    // table part-way, leaving the PHY half-configured.
    for e in PHY_CONFIG_TABLE.iter().copied() {
        let addr = match e.kind {
            PhyConfigKind::ModifyPaged | PhyConfigKind::WritePaged => {
                match PhyAccess::paged_addr(e.page, e.reg) {
                    Ok(a) => a,
                    Err(_) => return TestResult::Fail("a paged entry has no valid address"),
                }
            }
            PhyConfigKind::R8168gParam => match PhyAccess::paged_addr(R8168G_PARAM_PAGE, e.reg) {
                Ok(a) => a,
                Err(_) => return TestResult::Fail("an r8168g param entry has no valid address"),
            },
            PhyConfigKind::Rtl8125Param => {
                if e.reg as u32 != RTL8125_PARAM_DATA_ADDR {
                    return TestResult::Fail("an rtl8125 param entry names the wrong MMD register");
                }
                e.reg as u32
            }
        };
        if !ocp_addr_ok(addr) {
            return TestResult::Fail("a table entry translates to an illegal OCP address");
        }
    }
    if !ocp_addr_ok(RTL8125_PARAM_SEL_ADDR) || !ocp_addr_ok(RTL8125_PARAM_DATA_ADDR) {
        return TestResult::Fail("the MMD VEND2 selector/data addresses are illegal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_every_table_entry_has_an_address
);

// ── PHY: firmware container ──────────────────────────────────────────

/// Build a magic==0 container around `code`, with the trailing
/// checksum byte chosen so the whole file sums to zero.
fn build_fw_container(code: &[u32]) -> alloc::vec::Vec<u8> {
    use super::phy::{FW_INFO_BYTES, FW_INFO_LEN_OFF, FW_INFO_START_OFF};
    let mut v = alloc::vec![0u8; FW_INFO_BYTES];
    v[FW_INFO_START_OFF..FW_INFO_START_OFF + 4]
        .copy_from_slice(&(FW_INFO_BYTES as u32).to_le_bytes());
    v[FW_INFO_LEN_OFF..FW_INFO_LEN_OFF + 4].copy_from_slice(&(code.len() as u32).to_le_bytes());
    for w in code {
        v.extend_from_slice(&w.to_le_bytes());
    }
    // The last header byte is the checksum; pick it so the file sums
    // to zero mod 256.
    let sum = v.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    v[FW_INFO_BYTES - 1] = v[FW_INFO_BYTES - 1].wrapping_sub(sum);
    v
}

fn smoke_rtl8127_firmware_container_parse() -> TestResult {
    use super::phy::parse_firmware;
    let code = [0x8000_1234u32, 0xE000_000A, 0x0000_0000];

    // Header form: magic 0, checksum must balance.
    let blob = build_fw_container(&code);
    match parse_firmware(&blob) {
        Ok(c) if c == code => {}
        _ => return TestResult::Fail("header-form container did not parse"),
    }
    // Corrupt one payload byte: the checksum must catch it.
    let mut bad = build_fw_container(&code);
    let n = bad.len();
    bad[n - 1] ^= 0xFF;
    if parse_firmware(&bad).is_ok() {
        return TestResult::Fail("a corrupt container passed the checksum");
    }

    // Bare form: non-zero magic means the file is just opcodes.
    let mut bare = alloc::vec::Vec::new();
    for w in &code {
        bare.extend_from_slice(&w.to_le_bytes());
    }
    match parse_firmware(&bare) {
        Ok(c) if c == code => {}
        _ => return TestResult::Fail("bare opcode array did not parse"),
    }
    // ...and it must be a whole number of opcodes.
    if parse_firmware(&bare[..bare.len() - 1]).is_ok() {
        return TestResult::Fail("a misaligned bare array was accepted");
    }
    // Too short to hold even one opcode.
    if parse_firmware(&[0u8; 3]).is_ok() {
        return TestResult::Fail("a 3-byte file was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_firmware_container_parse
);

fn smoke_rtl8127_firmware_opcode_decode() -> TestResult {
    use super::phy::{decode_action, PHY_DELAY_MS, PHY_WRITE};
    // opcode in 31:28, regno in 27:16, data in 15:0.
    let (op, regno, data) = decode_action(0x8123_4567);
    if op != PHY_WRITE {
        return TestResult::Fail("opcode nibble decoded wrong");
    }
    if regno != 0x123 {
        return TestResult::Fail("regno is bits 27:16");
    }
    if data != 0x4567 {
        return TestResult::Fail("data is bits 15:0");
    }
    let (op, _, ms) = decode_action(0xE000_0064);
    if op != PHY_DELAY_MS || ms != 100 {
        return TestResult::Fail("delay opcode decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8127", smoke_rtl8127_firmware_opcode_decode);

fn smoke_rtl8127_firmware_validation_rejects_bad_jumps() -> TestResult {
    use super::phy::validate_firmware;
    // A straight-line program is fine.
    if validate_firmware(&[0x8000_0001, 0x8000_0002]).is_err() {
        return TestResult::Fail("a straight-line program was rejected");
    }
    // PHY_SKIPN past the end would run off the slice.
    if validate_firmware(&[0xD004_0000, 0x8000_0001]).is_ok() {
        return TestResult::Fail("a forward jump past the end was accepted");
    }
    // PHY_BJMPN further back than the current index.
    if validate_firmware(&[0x3004_0000]).is_ok() {
        return TestResult::Fail("a backward jump before the start was accepted");
    }
    // PHY_READCOUNT_EQ_SKIP needs two more opcodes after it.
    if validate_firmware(&[0x9000_0000, 0x8000_0001]).is_ok() {
        return TestResult::Fail("readcount-skip without room was accepted");
    }
    // PHY_MDIO_CHG only takes 0 or 1.
    if validate_firmware(&[0x4000_0002]).is_ok() {
        return TestResult::Fail("an out-of-range MDIO_CHG operand was accepted");
    }
    if validate_firmware(&[0x4000_0001]).is_err() {
        return TestResult::Fail("a valid MDIO_CHG was rejected");
    }
    // An opcode outside the known set.
    if validate_firmware(&[0x5000_0000]).is_ok() {
        return TestResult::Fail("an unknown opcode was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_firmware_validation_rejects_bad_jumps
);

fn smoke_rtl8127_firmware_delay_is_capped() -> TestResult {
    use super::phy::MAX_FIRMWARE_DELAY_MS;
    // PHY_DELAY_MS takes a 16-bit operand, so a corrupt blob could
    // ask for 65 seconds and hang boot inside a spin loop.
    if MAX_FIRMWARE_DELAY_MS == 0 || MAX_FIRMWARE_DELAY_MS > 1000 {
        return TestResult::Fail("firmware delay cap is not a sane bound");
    }
    if MAX_FIRMWARE_DELAY_MS >= u16::MAX as u64 {
        return TestResult::Fail("the cap does not actually bound the operand");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8127",
    smoke_rtl8127_firmware_delay_is_capped
);
