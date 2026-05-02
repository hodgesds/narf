//! rtl8125 driver smokes — co-located per project convention.
//!
//! Stage 1: PCI match-table entries for RTL8125 + RTL8125B.
//! Stage 2: MAC-address decode + reset-value bit pattern.
//! Stage 3: TX descriptor packing + 16-byte layout assertions.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    build_tx_desc, cr_reset_value, decode_mac, mac_is_invalid, name_for,
    CR_RST, RING_LEN, RTL_DEV_8125, RTL_DEV_8125B, RTL_VENDOR,
    TxDesc, TXD_EOR, TXD_FS, TXD_LS, TXD_OWN,
};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_rtl8125_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [RTL_DEV_8125, RTL_DEV_8125B] {
        let matched = registered.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: RTL_VENDOR, device,
            } if device == did));
        if !matched {
            return TestResult::Fail("rtl8125 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_pci_match_table);

fn smoke_rtl8125_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8125)  != "rtl8125"  { return TestResult::Fail("rtl8125 name"); }
    if name_for(RTL_DEV_8125B) != "rtl8125b" { return TestResult::Fail("rtl8125b name"); }
    if name_for(0xFFFF)        != "rtl8125"  { return TestResult::Fail("default name"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_name_for_known_ids);

// ── Stage 2: MAC decode + CR.RST ───────────────────────────────────

fn smoke_rtl8125_mac_decode_round_trip() -> TestResult {
    // IDR0..5 → on-wire MAC, byte-by-byte.
    let raw = [0x52u8, 0x54, 0x00, 0xAB, 0xCD, 0xEF, 0xFF, 0xFF];
    let mac = match decode_mac(&raw) {
        Some(m) => m,
        None    => return TestResult::Fail("decode_mac returned None on 8-byte input"),
    };
    if mac != [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF] {
        return TestResult::Fail("MAC bytes did not match IDR0..5 input");
    }
    if mac_is_invalid(mac) {
        return TestResult::Fail("locally-administered MAC flagged as invalid");
    }
    if decode_mac(&[0u8; 5]).is_some() {
        return TestResult::Fail("decode_mac accepted < 6-byte input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_mac_decode_round_trip);

fn smoke_rtl8125_mac_invalid_sentinels() -> TestResult {
    if !mac_is_invalid([0; 6])    { return TestResult::Fail("all-zero MAC not flagged"); }
    if !mac_is_invalid([0xFF; 6]) { return TestResult::Fail("all-FF MAC not flagged"); }
    if  mac_is_invalid([0, 0, 0, 0, 0, 1]) {
        return TestResult::Fail("non-zero MAC false-flagged");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_mac_invalid_sentinels);

fn smoke_rtl8125_cr_reset_bit() -> TestResult {
    // §2.4 places RST at bit 4. cr_reset_value() must produce exactly
    // that bit so the bring-up path's CR write doesn't accidentally
    // flip TE/RE in the same cycle.
    if cr_reset_value() != CR_RST     { return TestResult::Fail("cr_reset_value != CR_RST"); }
    if cr_reset_value() != 1 << 4     { return TestResult::Fail("CR_RST not at bit 4 per §2.4"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_cr_reset_bit);

// ── Stage 3: TX descriptor layout ──────────────────────────────────

fn smoke_rtl8125_txdesc_layout() -> TestResult {
    if core::mem::size_of::<TxDesc>()  != 16 {
        return TestResult::Fail("TxDesc not 16 bytes");
    }
    if core::mem::align_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16-byte aligned");
    }
    // Word ordering: flags_len at offset 0, vlan @ 4, addr_lo @ 8,
    // addr_hi @ 12. The chip DMAs the descriptor in this exact order.
    let d = TxDesc { flags_len: 0x11223344, vlan: 0x55667788,
                     addr_lo:   0x99AABBCC, addr_hi: 0xDDEEFF00 };
    let p = (&d) as *const _ as *const u32;
    // SAFETY: structurally-sized read in-bounds, repr(C) layout.
    let (w0, w1, w2, w3) = unsafe { (*p, *p.add(1), *p.add(2), *p.add(3)) };
    if w0 != 0x11223344 || w1 != 0x55667788
        || w2 != 0x99AABBCC || w3 != 0xDDEEFF00 {
        return TestResult::Fail("TxDesc word order mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_txdesc_layout);

fn smoke_rtl8125_build_tx_desc_round_trip() -> TestResult {
    // Mid-ring slot: must NOT carry EOR.
    let d = build_tx_desc(7, 0xDEAD_BEEF_CAFE_F00Du64, 0x05DC); // 1500
    let want_flags = TXD_OWN | TXD_FS | TXD_LS | 0x05DC;
    if d.flags_len != want_flags {
        return TestResult::Fail("mid-ring flags_len mismatch");
    }
    if d.flags_len & TXD_EOR != 0 {
        return TestResult::Fail("mid-ring slot wrongly carries EOR");
    }
    if d.vlan    != 0           { return TestResult::Fail("vlan not zero"); }
    if d.addr_lo != 0xCAFE_F00D  { return TestResult::Fail("addr_lo wrong"); }
    if d.addr_hi != 0xDEAD_BEEF  { return TestResult::Fail("addr_hi wrong"); }

    // Last slot: EOR must be set so the controller's internal pointer
    // wraps to slot 0.
    let last = build_tx_desc(RING_LEN - 1, 0x1_0000_0000u64, 64);
    if last.flags_len & TXD_EOR == 0 {
        return TestResult::Fail("RING_LEN-1 slot missing EOR");
    }
    if last.flags_len & 0xFFFF != 64 {
        return TestResult::Fail("length field corrupted by EOR set");
    }
    if last.addr_lo != 0 || last.addr_hi != 1 {
        return TestResult::Fail("64-bit phys split wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_build_tx_desc_round_trip);

fn smoke_rtl8125_tx_desc_len_truncates() -> TestResult {
    // §3.1.1 frame-length field is 16 bits; values > 0xFFFF should
    // mask cleanly without bleeding into the flag bits.
    let d = build_tx_desc(0, 0, 0x1_FFFF);
    if d.flags_len & 0xFFFF != 0xFFFF {
        return TestResult::Fail("length not masked to 16 bits");
    }
    // Make sure flags above bit 16 still carry only OWN/FS/LS.
    let want_top = TXD_OWN | TXD_FS | TXD_LS;
    if d.flags_len & 0xFFFF_0000 != want_top {
        return TestResult::Fail("length overflow leaked into flag bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_tx_desc_len_truncates);
