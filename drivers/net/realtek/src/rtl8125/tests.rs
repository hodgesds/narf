//! rtl8125 driver smokes — co-located per project convention.
//!
//! Stage 1: PCI match-table entries for RTL8125 + RTL8125B.
//! Stage 2: MAC-address decode + reset-value bit pattern + chip XID
//!          classification + RTL8125-specific register-block layout
//!          (32-bit IMR/ISR at 0x38/0x3C, TxPoll at 0x90).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    build_rx_desc, build_tx_desc, chip_kind_from_xid, cr_reset_value, decode_mac, decode_xid,
    mac_is_invalid, name_for, ChipKind, PhyStatus, TxDesc, CR_RST, INT32_LINKCHG, INT32_ROK,
    INT32_TOK, PHYSTAT_1000BPSF, PHYSTAT_FULLDUP, PHYSTAT_LINKSTS, REG_IMR_8125, REG_INT_CFG0_8125,
    REG_ISR_8125, REG_TPPOLL_8125, RING_LEN, RTL_DEV_8125, RTL_DEV_8125B, RTL_VENDOR,
    RXD_EOR_LOCAL, RXD_LEN_MASK_LOCAL, RXD_OWN_LOCAL, RX_BUF_LEN, RX_FETCH_DFLT_8125, TPPOLL_NPQ,
    TXD_EOR, TXD_FS, TXD_LS, TXD_OWN,
};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_rtl8125_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [RTL_DEV_8125, RTL_DEV_8125B] {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: RTL_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("rtl8125 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_pci_match_table);

fn smoke_rtl8125_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8125) != "rtl8125" {
        return TestResult::Fail("rtl8125 name");
    }
    if name_for(RTL_DEV_8125B) != "rtl8125b" {
        return TestResult::Fail("rtl8125b name");
    }
    if name_for(0xFFFF) != "rtl8125" {
        return TestResult::Fail("default name");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_name_for_known_ids);

// ── Stage 2: MAC decode + CR.RST ───────────────────────────────────

fn smoke_rtl8125_mac_decode_round_trip() -> TestResult {
    // IDR0..5 → on-wire MAC, byte-by-byte.
    let raw = [0x52u8, 0x54, 0x00, 0xAB, 0xCD, 0xEF, 0xFF, 0xFF];
    let mac = match decode_mac(&raw) {
        Some(m) => m,
        None => return TestResult::Fail("decode_mac returned None on 8-byte input"),
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
    if !mac_is_invalid([0; 6]) {
        return TestResult::Fail("all-zero MAC not flagged");
    }
    if !mac_is_invalid([0xFF; 6]) {
        return TestResult::Fail("all-FF MAC not flagged");
    }
    if mac_is_invalid([0, 0, 0, 0, 0, 1]) {
        return TestResult::Fail("non-zero MAC false-flagged");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_mac_invalid_sentinels);

fn smoke_rtl8125_cr_reset_bit() -> TestResult {
    // §2.4 places RST at bit 4. cr_reset_value() must produce exactly
    // that bit so the bring-up path's CR write doesn't accidentally
    // flip TE/RE in the same cycle.
    if cr_reset_value() != CR_RST {
        return TestResult::Fail("cr_reset_value != CR_RST");
    }
    if cr_reset_value() != 1 << 4 {
        return TestResult::Fail("CR_RST not at bit 4 per §2.4");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_cr_reset_bit);

// ── Stage 3: TX descriptor layout ──────────────────────────────────

fn smoke_rtl8125_txdesc_layout() -> TestResult {
    if core::mem::size_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16 bytes");
    }
    if core::mem::align_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16-byte aligned");
    }
    // Word ordering: flags_len at offset 0, vlan @ 4, addr_lo @ 8,
    // addr_hi @ 12. The chip DMAs the descriptor in this exact order.
    let d = TxDesc {
        flags_len: 0x11223344,
        vlan: 0x55667788,
        addr_lo: 0x99AABBCC,
        addr_hi: 0xDDEEFF00,
    };
    let p = (&d) as *const _ as *const u32;
    // SAFETY: structurally-sized read in-bounds, repr(C) layout.
    let (w0, w1, w2, w3) = unsafe { (*p, *p.add(1), *p.add(2), *p.add(3)) };
    if w0 != 0x11223344 || w1 != 0x55667788 || w2 != 0x99AABBCC || w3 != 0xDDEEFF00 {
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
    if d.vlan != 0 {
        return TestResult::Fail("vlan not zero");
    }
    if d.addr_lo != 0xCAFE_F00D {
        return TestResult::Fail("addr_lo wrong");
    }
    if d.addr_hi != 0xDEAD_BEEF {
        return TestResult::Fail("addr_hi wrong");
    }

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
kernel_test_in!(
    "drivers/net/rtl8125",
    smoke_rtl8125_build_tx_desc_round_trip
);

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

// ── Stage 2: 8125-specific register block ──────────────────────────

fn smoke_rtl8125_register_offsets() -> TestResult {
    // Per Linux `enum rtl8125_registers` lines 427–443 the new
    // register block lives at:
    //   INT_CFG0_8125  @ 0x34
    //   IMR_8125       @ 0x38
    //   ISR_8125       @ 0x3C
    //   TxPoll_8125    @ 0x90
    // These offsets are load-bearing: writing the 32-bit IMR to the
    // 16-bit alias at 0x3C corrupts the high half of ISR (which is
    // write-1-clear) and produces phantom IRQs on real silicon.
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
    // RX_FETCH_DFLT_8125 is `8 << 27` per
    // `rtl_init_rxcfg(RTL_GIGA_MAC_VER_61)`. Off-by-one here would
    // silently kill RX throughput on real silicon.
    if RX_FETCH_DFLT_8125 != 8 << 27 {
        return TestResult::Fail("RX_FETCH_DFLT_8125 != 8 << 27");
    }
    // TxPoll NPQ bit didn't move between RTL8169 (0x38) and RTL8125
    // (0x90) — same bit-6 of the byte.
    if TPPOLL_NPQ != 1 << 6 {
        return TestResult::Fail("TPPOLL_NPQ must be bit 6");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_register_offsets);

fn smoke_rtl8125_int32_bits() -> TestResult {
    // The 32-bit IMR/ISR bits at the low 8 bits match the legacy
    // 16-bit alias bit numbers (ROK=0, TOK=2, LinkChg=5). Higher
    // bits are 8125-only.
    if INT32_ROK != 1 << 0 {
        return TestResult::Fail("INT32_ROK at wrong bit");
    }
    if INT32_TOK != 1 << 2 {
        return TestResult::Fail("INT32_TOK at wrong bit");
    }
    if INT32_LINKCHG != 1 << 5 {
        return TestResult::Fail("INT32_LINKCHG at wrong bit");
    }
    // ROK + TOK + LinkChg = 0x25. This is the mask Stage 2 unmasks
    // at IMR — make sure the bitwise OR doesn't silently collapse.
    if INT32_ROK | INT32_TOK | INT32_LINKCHG != 0x25 {
        return TestResult::Fail("Stage-2 IMR unmask set != 0x25");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_int32_bits);

// ── Stage 2: chip XID classification ──────────────────────────────

fn smoke_rtl8125_decode_xid() -> TestResult {
    // Linux r8169_main.c:5647 — xid = (txconfig >> 20) & 0xfcf.
    // A TxConfig word with the 12 XID bits at positions [31:20]
    // landing 0x641 → RTL8125B.
    let txcfg = 0x641u32 << 20;
    if decode_xid(txcfg) != 0x641 {
        return TestResult::Fail("decode_xid stripped too much");
    }
    // The high 4 bits of the 16-bit XID slot are reserved; the
    // 0xfcf mask drops them so 0xf41 → 0xf41 & 0xfcf = 0xf41
    // *with* the f0 bits cleared = 0xc41. Verify the mask works.
    let txcfg2 = 0xf41u32 << 20;
    if decode_xid(txcfg2) != (0xf41 & 0xfcf) {
        return TestResult::Fail("decode_xid mask wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_decode_xid);

fn smoke_rtl8125_chip_kind_classification() -> TestResult {
    // The four XIDs we definitely see on consumer hardware.
    if chip_kind_from_xid(0x609) != ChipKind::Rtl8125A {
        return TestResult::Fail("0x609 should classify as RTL8125A");
    }
    if chip_kind_from_xid(0x641) != ChipKind::Rtl8125B {
        return TestResult::Fail("0x641 should classify as RTL8125B");
    }
    if chip_kind_from_xid(0x688) != ChipKind::Rtl8125D {
        return TestResult::Fail("0x688 should classify as RTL8125D");
    }
    if chip_kind_from_xid(0x681) != ChipKind::Rtl8125Bp {
        return TestResult::Fail("0x681 should classify as RTL8125BP");
    }
    // 0x123 is reserved / unknown. Driver still attempts bring-up.
    match chip_kind_from_xid(0x123) {
        ChipKind::Unknown(0x123) => {}
        _ => return TestResult::Fail("unknown XID didn't surface raw value"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8125",
    smoke_rtl8125_chip_kind_classification
);

// ── Stage 2: RX descriptor ring round-trip ────────────────────────
//
// FakeMmio isn't useful here — the on-wire RX descriptor IS the data
// the chip DMAs to. These tests use a real `[TxDesc; RING_LEN]` page
// (the RX and TX descriptors share the 16-byte shape per
// `rtl_hw_start_8125_common` line 3877 of Linux r8169_main.c which
// holds the "new descriptor format" *disabled*) and exercise the
// pure-data side of the prepare → consume cycle.

fn smoke_rtl8125_build_rx_desc_round_trip() -> TestResult {
    // Mid-ring slot 13 carrying a 2 KiB buffer (the Stage-2 default
    // RX_BUF_LEN). OWN must be set, length must round-trip.
    let d = build_rx_desc(13, 0xCAFE_BABE_DEAD_BEEFu64, RX_BUF_LEN as u32);
    if d.flags_len & RXD_OWN_LOCAL == 0 {
        return TestResult::Fail("OWN not set on prepared RX desc");
    }
    if d.flags_len & RXD_LEN_MASK_LOCAL != RX_BUF_LEN as u32 {
        return TestResult::Fail("RX buffer length not preserved");
    }
    if d.flags_len & RXD_EOR_LOCAL != 0 {
        return TestResult::Fail("mid-ring slot wrongly carries EOR");
    }
    if d.vlan != 0 {
        return TestResult::Fail("vlan not zero");
    }
    if d.addr_lo != 0xDEAD_BEEF {
        return TestResult::Fail("addr_lo wrong");
    }
    if d.addr_hi != 0xCAFE_BABE {
        return TestResult::Fail("addr_hi wrong");
    }

    // Last slot must set EOR so the chip's ring pointer wraps.
    let last = build_rx_desc(RING_LEN - 1, 0xABCD_0000_1234_0000u64, RX_BUF_LEN as u32);
    if last.flags_len & RXD_EOR_LOCAL == 0 {
        return TestResult::Fail("RING_LEN-1 slot missing EOR");
    }
    // EOR set must not corrupt the length field.
    if last.flags_len & RXD_LEN_MASK_LOCAL != RX_BUF_LEN as u32 {
        return TestResult::Fail("EOR set leaked into length field");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/rtl8125",
    smoke_rtl8125_build_rx_desc_round_trip
);

fn smoke_rtl8125_rx_ring_populate() -> TestResult {
    // Mirror what `bring_up` does at step 6b: pre-fill an RX ring
    // with one descriptor per slot, each pointing at a distinct
    // phys-addr cookie. The ring is host-side memory here so we use
    // an `alloc::vec::Vec` instead of `alloc_coherent`; the layout
    // is what matters.
    let mut ring: alloc::vec::Vec<TxDesc> = alloc::vec::Vec::with_capacity(RING_LEN);
    for i in 0..RING_LEN {
        // Make each phys-addr a unique sentinel so a misaligned
        // store to the wrong slot surfaces.
        let cookie = 0x1000_0000u64 | ((i as u64) << 4);
        ring.push(build_rx_desc(i, cookie, RX_BUF_LEN as u32));
    }
    // Every slot must be NIC-owned (OWN=1) after prepare.
    for (i, d) in ring.iter().enumerate() {
        if d.flags_len & RXD_OWN_LOCAL == 0 {
            return TestResult::Fail("OWN missing on a prepared RX slot");
        }
        // Only the last slot may carry EOR.
        let has_eor = d.flags_len & RXD_EOR_LOCAL != 0;
        if i == RING_LEN - 1 {
            if !has_eor {
                return TestResult::Fail("last slot missing EOR");
            }
        } else if has_eor {
            return TestResult::Fail("mid slot carries EOR");
        }
        // Phys cookies must be at their assigned slot — catches a
        // build_rx_desc swap of word2/word3.
        let want_lo = (0x1000_0000u64 | ((i as u64) << 4)) as u32;
        let want_hi = ((0x1000_0000u64 | ((i as u64) << 4)) >> 32) as u32;
        if d.addr_lo != want_lo || d.addr_hi != want_hi {
            return TestResult::Fail("phys address split landed on wrong slot");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_rx_ring_populate);

fn smoke_rtl8125_rx_buf_len_fits_mask() -> TestResult {
    // RX_BUF_LEN must fit inside the 14-bit RXD length field. A
    // larger value would silently corrupt the OWN/EOR/LS bits when
    // OR'd into word0.
    if RX_BUF_LEN as u32 > RXD_LEN_MASK_LOCAL {
        return TestResult::Fail("RX_BUF_LEN overflows 14-bit RXD length");
    }
    // The 14-bit ceiling for the length field is 0x3FFF = 16383
    // bytes; the 8125 supports up to 16 KiB - 1 jumbo frames per
    // Linux's `R8169_RX_BUF_SIZE` = `(SZ_16K - 1)`. Stage 2 picks
    // 2 KiB — plenty of headroom.
    if RXD_LEN_MASK_LOCAL != 0x3FFF {
        return TestResult::Fail("RXD_LEN_MASK should be 14-bit (0x3FFF)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_rx_buf_len_fits_mask);

// ── Stage 2: PHYStatus decode ─────────────────────────────────────

fn smoke_rtl8125_phystat_decode() -> TestResult {
    // 1000bpsF + LinkStatus + FullDup — what a 1G or 2.5G live link
    // reports (2.5G surfaces as 1000bpsF in PHYStatus; the real speed
    // comes from PHYAR-side registers).
    let ps = PhyStatus::parse(PHYSTAT_LINKSTS | PHYSTAT_FULLDUP | PHYSTAT_1000BPSF);
    if !ps.link_up {
        return TestResult::Fail("LinkSts bit not decoded");
    }
    if !ps.full_duplex {
        return TestResult::Fail("FullDup bit not decoded");
    }
    if !ps.speed_1000m {
        return TestResult::Fail("1000bpsF bit not decoded");
    }
    if ps.speed_100m || ps.speed_10m {
        return TestResult::Fail("Spurious 10/100M flag set");
    }
    if ps.speed_label() != "1000M-or-2.5G" {
        return TestResult::Fail("speed_label wrong for 1G/2.5G");
    }

    // Link down — every speed bit should read false.
    let down = PhyStatus::parse(0);
    if down.link_up {
        return TestResult::Fail("link_up set on zero PHYStatus");
    }
    if down.speed_label() != "down" {
        return TestResult::Fail("speed_label not 'down' on zero status");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_phystat_decode);
