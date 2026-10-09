//! RTL8126 driver smokes.
//!
//! Stage 1: PCI match table for RTL8126 + 0x5000 variant.
//! Stage 2: MAC-version decode (VER_70 XIDs 0x649 / 0x64a), descriptor
//!          layout shared with RTL8125, 5G link-status decode via
//!          PHYStatus bit 7 (`TBI_Enable` / 5G flag).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    build_rx_desc, build_tx_desc, cr_reset_value, decode_mac, decode_xid, mac_is_invalid,
    mac_version_from_xid, name_for, MacVersion, PhyStatus, TxDesc, CR_RST, INT32_LINKCHG,
    INT32_ROK, INT32_TOK, PHYSTAT_1000BPSF, PHYSTAT_FULLDUP, PHYSTAT_LINKSTS, PHYSTAT_TBI_OR_5G,
    REG_IMR_8125, REG_INT_CFG0_8125, REG_ISR_8125, REG_TPPOLL_8125, RING_LEN, RTL_DEV_8126,
    RTL_DEV_8126_VAR, RTL_VENDOR, RXD_EOR, RXD_LEN_MASK, RXD_OWN, RX_BUF_LEN, RX_FETCH_DFLT_8125,
    RX_PAUSE_SLOT_ON, TPPOLL_NPQ, TXD_EOR, TXD_FS, TXD_LS, TXD_OWN,
};

// ── Smoke 1: PCI match table ──────────────────────────────────────────

fn smoke_rtl8126_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [RTL_DEV_8126, RTL_DEV_8126_VAR] {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: RTL_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("rtl8126 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_pci_match_table);

fn smoke_rtl8126_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8126) != "rtl8126" {
        return TestResult::Fail("rtl8126 name wrong");
    }
    if name_for(RTL_DEV_8126_VAR) != "rtl8126-var" {
        return TestResult::Fail("rtl8126-var name wrong");
    }
    if name_for(0xFFFF) != "rtl8126" {
        return TestResult::Fail("default name wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_name_for_known_ids);

// ── Smoke 2: MAC version detect (VER_70) ─────────────────────────────

fn smoke_rtl8126_mac_version_ver70() -> TestResult {
    // Linux rtl_chip_infos[] lines 109–110:
    //   { 0x7cf, 0x64a, RTL_GIGA_MAC_VER_70, "RTL8126A", … },
    //   { 0x7cf, 0x649, RTL_GIGA_MAC_VER_70, "RTL8126A", … },
    // Both XIDs must map to MacVersion::Ver70.
    let xid_a = decode_xid(0x649u32 << 20);
    if xid_a != 0x649 {
        return TestResult::Fail("decode_xid mangled 0x649");
    }
    let xid_b = decode_xid(0x64au32 << 20);
    if xid_b != 0x64a {
        return TestResult::Fail("decode_xid mangled 0x64a");
    }
    if mac_version_from_xid(0x649) != MacVersion::Ver70 {
        return TestResult::Fail("XID 0x649 should be Ver70");
    }
    if mac_version_from_xid(0x64a) != MacVersion::Ver70 {
        return TestResult::Fail("XID 0x64a should be Ver70");
    }
    // RTL8125B XID (0x641) must NOT match Ver70.
    match mac_version_from_xid(0x641) {
        MacVersion::Unknown(0x641) => {}
        _ => return TestResult::Fail("RTL8125B XID 0x641 wrongly classified as Ver70"),
    }
    // Unknown XID surfaces the raw value.
    match mac_version_from_xid(0xABC) {
        MacVersion::Unknown(0xABC) => {}
        _ => return TestResult::Fail("unknown XID didn't surface raw value"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_mac_version_ver70);

// ── Smoke 3: 5G link-status decode ───────────────────────────────────

fn smoke_rtl8126_5g_link_status_decode() -> TestResult {
    // 5 Gbps link: TBI_Enable (bit 7) + LinkStatus (bit 1) + FullDup.
    let byte_5g = PHYSTAT_TBI_OR_5G | PHYSTAT_LINKSTS | PHYSTAT_FULLDUP;
    let ps = PhyStatus::parse(byte_5g);
    if !ps.link_up {
        return TestResult::Fail("5G: LinkSts not decoded");
    }
    if !ps.full_duplex {
        return TestResult::Fail("5G: FullDup not decoded");
    }
    if !ps.speed_5g {
        return TestResult::Fail("5G: TBI_Enable / 5G flag not decoded");
    }
    if ps.speed_1000m_or_above {
        return TestResult::Fail("5G: speed_1000m_or_above wrongly set when bit4=0");
    }
    if ps.speed_label() != "5G" {
        return TestResult::Fail("5G: speed_label not '5G'");
    }

    // 1G link (no TBI_Enable): surfaces as "1000M-or-2.5G".
    let byte_1g = PHYSTAT_LINKSTS | PHYSTAT_FULLDUP | PHYSTAT_1000BPSF;
    let ps1g = PhyStatus::parse(byte_1g);
    if !ps1g.speed_1000m_or_above {
        return TestResult::Fail("1G: speed_1000m_or_above not set");
    }
    if ps1g.speed_5g {
        return TestResult::Fail("1G: speed_5g wrongly set");
    }
    if ps1g.speed_label() != "1000M-or-2.5G" {
        return TestResult::Fail("1G: speed_label wrong");
    }

    // Link down.
    let down = PhyStatus::parse(0);
    if down.link_up {
        return TestResult::Fail("down: link_up set on zero");
    }
    if down.speed_label() != "down" {
        return TestResult::Fail("down: speed_label not 'down'");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_5g_link_status_decode);

// ── Smoke 4: TX/RX descriptor layout shared with RTL8125 ─────────────

fn smoke_rtl8126_txdesc_layout_shared_with_8125() -> TestResult {
    // Same 16-byte `repr(C, align(16))` shape as rtl8125::TxDesc.
    // The RTL8126 `rtl_hw_start_8125_common` keeps new-descriptor-
    // format disabled, so the on-wire layout is identical.
    if core::mem::size_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16 bytes");
    }
    if core::mem::align_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16-byte aligned");
    }
    let d = TxDesc {
        flags_len: 0x11223344,
        vlan: 0x55667788,
        addr_lo: 0x99AABBCC,
        addr_hi: 0xDDEEFF00,
    };
    let p = (&d) as *const _ as *const u32;
    // SAFETY: repr(C) layout, in-bounds read.
    let (w0, w1, w2, w3) = unsafe { (*p, *p.add(1), *p.add(2), *p.add(3)) };
    if w0 != 0x11223344 || w1 != 0x55667788 || w2 != 0x99AABBCC || w3 != 0xDDEEFF00 {
        return TestResult::Fail("TxDesc word order mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8126",
    smoke_rtl8126_txdesc_layout_shared_with_8125
);

fn smoke_rtl8126_build_tx_desc_round_trip() -> TestResult {
    // Mid-ring slot must not carry EOR.
    let d = build_tx_desc(7, 0xDEAD_BEEF_CAFE_F00Du64, 0x05DC);
    let want_flags = TXD_OWN | TXD_FS | TXD_LS | 0x05DC;
    if d.flags_len != want_flags {
        return TestResult::Fail("mid-ring flags_len mismatch");
    }
    if d.flags_len & TXD_EOR != 0 {
        return TestResult::Fail("mid-ring slot wrongly carries EOR");
    }
    if d.addr_lo != 0xCAFE_F00D || d.addr_hi != 0xDEAD_BEEF {
        return TestResult::Fail("64-bit phys split wrong");
    }
    // Last slot must carry EOR.
    let last = build_tx_desc(RING_LEN - 1, 0x1_0000_0000u64, 64);
    if last.flags_len & TXD_EOR == 0 {
        return TestResult::Fail("RING_LEN-1 slot missing EOR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8126",
    smoke_rtl8126_build_tx_desc_round_trip
);

fn smoke_rtl8126_build_rx_desc_round_trip() -> TestResult {
    let d = build_rx_desc(13, 0xCAFE_BABE_DEAD_BEEFu64, RX_BUF_LEN as u32);
    if d.flags_len & RXD_OWN == 0 {
        return TestResult::Fail("OWN not set on prepared RX desc");
    }
    if d.flags_len & RXD_LEN_MASK != RX_BUF_LEN as u32 {
        return TestResult::Fail("RX buffer length not preserved");
    }
    if d.flags_len & RXD_EOR != 0 {
        return TestResult::Fail("mid-ring slot wrongly carries EOR");
    }
    if d.addr_lo != 0xDEAD_BEEF || d.addr_hi != 0xCAFE_BABE {
        return TestResult::Fail("phys split wrong");
    }
    let last = build_rx_desc(RING_LEN - 1, 0, RX_BUF_LEN as u32);
    if last.flags_len & RXD_EOR == 0 {
        return TestResult::Fail("last slot missing EOR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8126",
    smoke_rtl8126_build_rx_desc_round_trip
);

// ── Smoke 5: RX_PAUSE_SLOT_ON constant ───────────────────────────────

fn smoke_rtl8126_rx_pause_slot_on() -> TestResult {
    // Linux r8169_main.c line 282:
    //   #define RX_PAUSE_SLOT_ON (1 << 11)  /* 8125b and later */
    // RTL8126 (VER_70) falls in the VER_63..LAST range that enables
    // this bit. Off-by-one here would set the wrong RCR bit.
    if RX_PAUSE_SLOT_ON != 1 << 11 {
        return TestResult::Fail("RX_PAUSE_SLOT_ON must be bit 11 (1 << 11)");
    }
    // Also confirm RX_FETCH_DFLT_8125 is still 8 << 27 (shared constant).
    if RX_FETCH_DFLT_8125 != 8 << 27 {
        return TestResult::Fail("RX_FETCH_DFLT_8125 != 8 << 27");
    }
    // RCR value for RTL8126 must include both.
    let rcr = RX_FETCH_DFLT_8125 | RX_PAUSE_SLOT_ON;
    if rcr & RX_PAUSE_SLOT_ON == 0 {
        return TestResult::Fail("RX_PAUSE_SLOT_ON not set in RCR mask");
    }
    if rcr & RX_FETCH_DFLT_8125 == 0 {
        return TestResult::Fail("RX_FETCH_DFLT_8125 not set in RCR mask");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_rx_pause_slot_on);

// ── Smoke 6: register offsets (inherited from RTL8125) ───────────────

fn smoke_rtl8126_register_offsets() -> TestResult {
    // RTL8126 inherits the RTL8125 register floor unchanged.
    if REG_INT_CFG0_8125 != 0x34 {
        return TestResult::Fail("INT_CFG0_8125 must be at 0x34");
    }
    if REG_IMR_8125 != 0x38 {
        return TestResult::Fail("IMR_8125 must be at 0x38");
    }
    if REG_ISR_8125 != 0x3C {
        return TestResult::Fail("ISR_8125 must be at 0x3C");
    }
    if REG_TPPOLL_8125 != 0x90 {
        return TestResult::Fail("TxPoll_8125 must be at 0x90");
    }
    if TPPOLL_NPQ != 1 << 6 {
        return TestResult::Fail("TPPOLL_NPQ must be bit 6");
    }
    if CR_RST != 1 << 4 {
        return TestResult::Fail("CR_RST not at bit 4");
    }
    if cr_reset_value() != CR_RST {
        return TestResult::Fail("cr_reset_value != CR_RST");
    }
    if INT32_ROK != 1 << 0 {
        return TestResult::Fail("INT32_ROK wrong");
    }
    if INT32_TOK != 1 << 2 {
        return TestResult::Fail("INT32_TOK wrong");
    }
    if INT32_LINKCHG != 1 << 5 {
        return TestResult::Fail("INT32_LINKCHG wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_register_offsets);

// ── Smoke 7: MAC decode helpers ───────────────────────────────────────

fn smoke_rtl8126_mac_decode_helpers() -> TestResult {
    let raw = [0x52u8, 0x54, 0x00, 0xAB, 0xCD, 0xEF, 0xFF, 0xFF];
    let mac = match decode_mac(&raw) {
        Some(m) => m,
        None => return TestResult::Fail("decode_mac returned None"),
    };
    if mac != [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF] {
        return TestResult::Fail("MAC bytes wrong");
    }
    if mac_is_invalid(mac) {
        return TestResult::Fail("valid MAC flagged as invalid");
    }
    if !mac_is_invalid([0; 6]) {
        return TestResult::Fail("all-zero not flagged");
    }
    if !mac_is_invalid([0xFF; 6]) {
        return TestResult::Fail("all-FF not flagged");
    }
    if decode_mac(&[0u8; 5]).is_some() {
        return TestResult::Fail("decode_mac accepted < 6 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8126", smoke_rtl8126_mac_decode_helpers);
