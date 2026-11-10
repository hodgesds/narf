//! aqc113 driver smokes — co-located per project convention.
//!
//! Fixture discipline: every expected value below is transcribed
//! from the Linux atlantic sources (see the driver header), never
//! from the implementation's constants. The fake device carries its
//! own address table and bit definitions (`FAKE_*` literals, each
//! cited), and the pure tests assert hand-computed literals. A
//! driver bug in an address or bit therefore fails the test instead
//! of passing against a mirror of itself.

#![cfg(target_arch = "x86_64")]

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::{
    build_link_options, build_rx_desc, build_tx_desc, decode_fw_version, decode_mac_from_shared,
    decode_rx_wb, fw_version_word, link_rate_to_mbps, link_sample, mac_filter_words,
    mac_is_invalid, name_for, read_link_status, speed_mask_for, FilterCaps, LinkStatus, RegIo,
    RxCsumResult, RxdWb, TxDesc, AQC_DEV_113, AQC_DEV_113C, AQC_DEV_113CA, AQC_DEV_113CS,
    AQC_DEV_113DEV, AQC_DEV_114CS, AQC_DEV_115C, AQC_DEV_116C, AQC_VENDOR, RING_LEN, RX_BUF_LEN,
};

// ── Spec literals (transcribed from Linux atlantic; independent ────
// of the driver's constants — a mismatch between the two sides is
// a test failure, by design.

/// `HW_ATL2_MIF_BOOT_REG_ADR` (`hw_atl2_llh_internal.h`).
const FAKE_MIF_BOOT: u64 = 0x3040;
/// `HW_ATL2_MCP_HOST_REQ_INT_ADR`.
const FAKE_MIF_HOST_REQ_INT: u64 = 0x0F00;
/// `HW_ATL2_MCP_HOST_REQ_INT_CLR_ADR`.
const FAKE_MIF_HOST_REQ_INT_CLR: u64 = 0x0F08;
/// `HW_ATL2_MIF_SHARED_BUFFER_IN_ADR(dword)`.
const FAKE_MIF_SHARED_IN: u64 = 0x12000;
/// `HW_ATL2_MIF_SHARED_BUFFER_OUT_ADR(dword)`.
const FAKE_MIF_SHARED_OUT: u64 = 0x13000;
/// `HW_ATL2_MIF_HOST_FINISHED_WRITE_ADR`.
const FAKE_MIF_HOST_FINISHED_WRITE: u64 = 0x0E00;
/// `HW_ATL2_MIF_MCP_FINISHED_READ_ADR`.
const FAKE_MIF_MCP_FINISHED_READ: u64 = 0x0E04;
/// Boot bits (`hw_atl2_utils.c`): REBOOT 0, STARTED 24,
/// CRASH 27, CODE_FAILED 28, FW_INIT_FAILED 29, COMPLETE 31.
const FAKE_BOOT_REQ_REBOOT: u32 = 1 << 0;
const FAKE_BOOT_STARTED: u32 = 1 << 24;
const FAKE_BOOT_CODE_FAILED: u32 = 1 << 28;
const FAKE_BOOT_COMPLETE: u32 = 1 << 31;
/// `HW_ATL2_MCP_HOST_REQ_INT_READY`.
const FAKE_HOST_REQ_READY: u32 = 1 << 0;
/// TX DMA q0 regs (`hw_atl_llh_internal.h`).
const FAKE_TX_BASE_LSW: u64 = 0x7C00;
const FAKE_TX_BASE_MSW: u64 = 0x7C04;
const FAKE_TX_CTL: u64 = 0x7C08;
const FAKE_TX_TAIL: u64 = 0x7C10;
const FAKE_TX_WRB_THRESH: u64 = 0x7C18;
/// RX DMA q0 regs.
const FAKE_RX_BASE_LSW: u64 = 0x5B00;
const FAKE_RX_BASE_MSW: u64 = 0x5B04;
const FAKE_RX_CTL: u64 = 0x5B08;
const FAKE_RX_TAIL: u64 = 0x5B10;
const FAKE_RX_BUF_SIZE: u64 = 0x5B18;
/// Writeback-IRQ enables.
const FAKE_TDM_WRB_EN: u64 = 0x7B40;
const FAKE_RDM_WRB_EN: u64 = 0x5A30;
/// Packet-buffer enables.
const FAKE_TPB_TX_BUF: u64 = 0x7900;
const FAKE_RPB_RX_BUF: u64 = 0x5700;
/// Interrupt block.
const FAKE_IRQ_GLB_CTL: u64 = 0x2300;
const FAKE_ITR_IAMRLSW: u64 = 0x2090;
const FAKE_GEN_IRQ_MAP0: u64 = 0x2180;
const FAKE_ITR_MAP_Q0: u64 = 0x2100;
/// RPF registers.
const FAKE_RPF_MCST_MSK: u64 = 0x5270;
const FAKE_RPF_MCST_FLR0: u64 = 0x5250;
const FAKE_RPF_VLAN_TPID: u64 = 0x5284;
const FAKE_RPF_VLAN_CTL: u64 = 0x5280;
const FAKE_RPF_BC: u64 = 0x5100;
const FAKE_RPF_NEW_EN: u64 = 0x5104;
/// RPF L2 unicast filter `f`: DAFLSW `0x5110 + f*8`, CTL `0x5114 + f*8`.
const fn fake_rpf_uc_daflsw(f: u64) -> u64 {
    0x5110 + f * 8
}
const fn fake_rpf_uc_ctl(f: u64) -> u64 {
    0x5114 + f * 8
}

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_aqc113_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [
        AQC_DEV_113DEV,
        AQC_DEV_113,
        AQC_DEV_116C,
        AQC_DEV_115C,
        AQC_DEV_113C,
        AQC_DEV_113CA,
        AQC_DEV_114CS,
        AQC_DEV_113CS,
    ] {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: AQC_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("aqc113 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_pci_match_table);

fn smoke_aqc113_name_and_speed_for_known_ids() -> TestResult {
    if name_for(AQC_DEV_113) != "aqc113" {
        return TestResult::Fail("aqc113 name");
    }
    if name_for(AQC_DEV_113CS) != "aqc113cs" {
        return TestResult::Fail("aqc113cs name");
    }
    if name_for(AQC_DEV_115C) != "aqc115c" {
        return TestResult::Fail("aqc115c name");
    }
    if name_for(0xFFFF) != "aqc113" {
        return TestResult::Fail("default name");
    }
    // Caps from hw_atl2.c: 113 = 10G/5G/2.5G/1G/100M/10M (0x3F),
    // 115C = 2.5G max (0x3C), 116C = 1G max (0x38).
    if speed_mask_for(AQC_DEV_113) != 0x3F {
        return TestResult::Fail("aqc113 speed mask != 0x3F");
    }
    if speed_mask_for(AQC_DEV_115C) != 0x3C {
        return TestResult::Fail("aqc115c speed mask != 0x3C");
    }
    if speed_mask_for(AQC_DEV_116C) != 0x38 {
        return TestResult::Fail("aqc116c speed mask != 0x38");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/aqc113",
    smoke_aqc113_name_and_speed_for_known_ids
);

// ── Stage 2: firmware mailbox decode ───────────────────────────────

fn smoke_aqc113_mac_decode_from_shared() -> TestResult {
    // MAC 52:54:00:AB:CD:EF in the IN buffer's MAC dwords:
    // dword0 LE bytes [52,54,00,AB] = 0xAB005452,
    // dword1 LE bytes [EF,CD,00,00] = 0x0000CDEF.
    let mac = match decode_mac_from_shared(&[0xAB00_5452, 0x0000_CDEF]) {
        Some(m) => m,
        None => return TestResult::Fail("decode_mac_from_shared returned None"),
    };
    if mac != [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF] {
        return TestResult::Fail("MAC bytes did not match shared-buffer input");
    }
    if mac_is_invalid(mac) {
        return TestResult::Fail("valid MAC flagged as invalid");
    }
    if !mac_is_invalid([0; 6]) || !mac_is_invalid([0xFF; 6]) {
        return TestResult::Fail("invalid MAC sentinels not flagged");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_mac_decode_from_shared);

fn smoke_aqc113_fw_version_decode() -> TestResult {
    // Version dword 0: bundle major 1, minor 2, build 0x0345 →
    // LE bytes [01,02,45,03] = 0x03450201.
    let (major, minor, build) = decode_fw_version(&[0x0345_0201, 0, 0, 0]);
    if major != 1 || minor != 2 || build != 0x0345 {
        return TestResult::Fail("fw version fields wrong");
    }
    // Linux's get_fw_version returns major<<24|minor<<16|build.
    if fw_version_word(&[0x0345_0201, 0, 0, 0]) != 0x0102_0345 {
        return TestResult::Fail("fw version word != 0x01020345");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_fw_version_decode);

fn smoke_aqc113_filter_caps_decode() -> TestResult {
    // filter_caps_s bytes: [l2_base|flex, l2_count, etht_base,
    // etht_count, vlan_base, vlan_count, l3_ip4, l3_ip6, l4,
    // l4_flex, rslv_base, rslv_count]. l2_base 2, l2_count 38,
    // rslv_base 5, rslv_count 8 →
    // dword0 = 0x00002602, dword1 = 0, dword2 = 0x08050000.
    let caps = FilterCaps::decode(&[0x0000_2602, 0x0000_0000, 0x0805_0000]);
    if caps.l2_base_index != 2 {
        return TestResult::Fail("l2_base_index != 2");
    }
    if caps.l2_count != 38 {
        return TestResult::Fail("l2_count != 38");
    }
    if caps.rslv_base_index != 5 || caps.rslv_count != 8 {
        return TestResult::Fail("rslv base/count wrong");
    }
    if caps.art_base_index() != 40 || caps.art_count() != 64 {
        return TestResult::Fail("ART base/count != 40/64");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_filter_caps_decode);

fn smoke_aqc113_link_status_decode() -> TestResult {
    // 2.5G full duplex: byte0 = rate 4 << 4 = 0x40, byte1 = duplex
    // bit 3 = 0x08 → word 0x00000840.
    let up = LinkStatus::decode(0x0000_0840);
    if !up.carrier || up.mbps != 2500 || !up.full_duplex {
        return TestResult::Fail("2.5G full-duplex decode wrong");
    }
    // 10G half duplex: byte0 = 0x60, byte1 = 0x00.
    let ten = LinkStatus::decode(0x0000_0060);
    if !ten.carrier || ten.mbps != 10000 || ten.full_duplex {
        return TestResult::Fail("10G half-duplex decode wrong");
    }
    // Down: rate 0 → no carrier, 0 Mbps.
    let down = LinkStatus::decode(0x0000_0000);
    if down.carrier || down.mbps != 0 {
        return TestResult::Fail("down link decoded as up");
    }
    // Tampered: undefined rate 7 → 0 Mbps, no carrier.
    if link_rate_to_mbps(7) != 0 || LinkStatus::decode(0x0000_0070).carrier {
        return TestResult::Fail("undefined rate 7 decoded as up");
    }
    // Publication: up sample carries speed + duplex, down drops them.
    let sample = link_sample(up);
    if !sample.carrier || sample.speed_mbps != Some(2500) {
        return TestResult::Fail("link sample wrong");
    }
    if link_sample(down).carrier {
        return TestResult::Fail("down sample reports carrier");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_link_status_decode);

fn smoke_aqc113_link_options_build() -> TestResult {
    // Full mask 0x3F: byte0 link_up = 0x01, byte1 all rates = 0xFF,
    // byte2 EEE = 0x00, byte3 pause_rx|pause_tx = 0x03.
    if build_link_options(0x3F) != 0x0300_FF01 {
        return TestResult::Fail("full-mask link_options != 0x0300FF01");
    }
    // AQC116C mask 0x38 (1G/100M/10M): byte1 = 0x07.
    if build_link_options(0x38) != 0x0300_0701 {
        return TestResult::Fail("116C link_options != 0x03000701");
    }
    // 10G-only: byte1 = 0x80.
    if build_link_options(0x01) != 0x0300_8001 {
        return TestResult::Fail("10G-only link_options != 0x03008001");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_link_options_build);

// ── Stage 3: descriptor layout (byte-exact) ────────────────────────

fn smoke_aqc113_tx_desc_layout() -> TestResult {
    if core::mem::size_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16 bytes");
    }
    if core::mem::align_of::<TxDesc>() != 16 {
        return TestResult::Fail("TxDesc not 16-byte aligned");
    }
    // Frame 1514 bytes at phys 0x0000123456789ABC.
    // ctl = (1514<<4 & 0xFFFF0) | TYPE_TXD | EOP | WB
    //     = 0x5EA0 | 0x1 | 0x200000 | 0x8000000 = 0x08205EA1.
    // ctl2 = (1514<<14) & 0xFFFFC000 = 0x017A8000.
    let d = build_tx_desc(0, 0x0000_1234_5678_9ABC, 1514);
    let mut bytes = [0u8; 16];
    // SAFETY: TxDesc is 16 bytes; copying it out is a plain read.
    unsafe {
        core::ptr::copy_nonoverlapping(&d as *const TxDesc as *const u8, bytes.as_mut_ptr(), 16);
    }
    let expected: [u8; 16] = [
        0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, // buf_addr LE
        0xA1, 0x5E, 0x20, 0x08, // ctl LE
        0x00, 0x80, 0x7A, 0x01, // ctl2 LE
    ];
    if bytes != expected {
        return TestResult::Fail("TxDesc bytes do not match the spec layout");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_tx_desc_layout);

fn smoke_aqc113_rx_desc_layout() -> TestResult {
    // RXD: buf_addr + hdr_addr 0, no flags (availability is the
    // tail pointer, not an OWN bit).
    let d = build_rx_desc(3, 0x0000_0000_ABCD_1000);
    let mut bytes = [0u8; 16];
    // SAFETY: RxDesc is 16 bytes; copying it out is a plain read.
    unsafe {
        core::ptr::copy_nonoverlapping(
            &d as *const super::RxDesc as *const u8,
            bytes.as_mut_ptr(),
            16,
        );
    }
    let expected: [u8; 16] = [
        0x00, 0x10, 0xCD, 0xAB, 0x00, 0x00, 0x00, 0x00, // buf_addr LE
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hdr_addr
    ];
    if bytes != expected {
        return TestResult::Fail("RxDesc bytes do not match the spec layout");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_rx_desc_layout);

fn smoke_aqc113_rx_wb_decode() -> TestResult {
    // (a) TCP checksum OK: type L4-enable (bit 20) = 0x100000,
    // pkt_type TCP (0); status DD|EOP = 0x3, rx_stat bit 3 set
    // (L4 verified) → status = 0x3 | (0x8 << 2) = 0x23.
    let ok = decode_rx_wb(
        &RxdWb {
            type_: 0x0010_0000,
            rss_hash: 0,
            status: 0x0023,
            pkt_len: 100,
            next_desc_ptr: 0,
            vlan: 0,
        },
        RX_BUF_LEN as u32,
    );
    if ok.len != 100 || ok.csum != RxCsumResult::Ok || ok.error || !ok.is_eop {
        return TestResult::Fail("TCP-OK writeback misdecoded");
    }
    // (b) UDP checksum fail: pkt_type UDP (4 << 4), rx_stat bit 2
    // set → status = 0x3 | (0x4 << 2) = 0x13.
    let fail = decode_rx_wb(
        &RxdWb {
            type_: 0x0010_0040,
            rss_hash: 0,
            status: 0x0013,
            pkt_len: 200,
            next_desc_ptr: 0,
            vlan: 0,
        },
        RX_BUF_LEN as u32,
    );
    if fail.csum != RxCsumResult::Fail || fail.error {
        return TestResult::Fail("UDP-fail writeback misdecoded");
    }
    // (c) MAC error: rx_stat bit 0 → status = 0x3 | (0x1 << 2).
    let mac_err = decode_rx_wb(
        &RxdWb {
            type_: 0,
            rss_hash: 0,
            status: 0x0007,
            pkt_len: 64,
            next_desc_ptr: 0,
            vlan: 0,
        },
        RX_BUF_LEN as u32,
    );
    if !mac_err.error {
        return TestResult::Fail("MAC-error writeback not flagged");
    }
    // (d) Small packet (60 B) with IP+TCP error bits set: the
    // Linux workaround clears the error verdict → None.
    let small = decode_rx_wb(
        &RxdWb {
            type_: 0x0010_0000,
            rss_hash: 0,
            status: 0x001B, // DD|EOP + rx_stat 0x6
            pkt_len: 60,
            next_desc_ptr: 0,
            vlan: 0,
        },
        RX_BUF_LEN as u32,
    );
    if small.csum != RxCsumResult::None {
        return TestResult::Fail("small-packet workaround not applied");
    }
    // (e) EOP length wrap: pkt_len == frame_max → len = frame_max.
    let wrap = decode_rx_wb(
        &RxdWb {
            type_: 0,
            rss_hash: 0,
            status: 0x0003,
            pkt_len: 2048,
            next_desc_ptr: 0,
            vlan: 0,
        },
        RX_BUF_LEN as u32,
    );
    if wrap.len != 2048 || !wrap.is_eop {
        return TestResult::Fail("EOP length wrap wrong");
    }
    // (f) Non-EOP fragment: len capped at frame_max, not EOP.
    let frag = decode_rx_wb(
        &RxdWb {
            type_: 0,
            rss_hash: 0,
            status: 0x0001,
            pkt_len: 2048,
            next_desc_ptr: 7,
            vlan: 0,
        },
        RX_BUF_LEN as u32,
    );
    if frag.is_eop || frag.len != 2048 {
        return TestResult::Fail("non-EOP fragment misdecoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_rx_wb_decode);

fn smoke_aqc113_register_offsets() -> TestResult {
    // TX DMA q0/q1 strides (0x40) and RX DMA q0/q2 strides (0x20).
    if super::reg_tx_dma_base_lsw(0) != 0x7C00 || super::reg_tx_dma_base_lsw(1) != 0x7C40 {
        return TestResult::Fail("TX base LSW stride wrong");
    }
    if super::reg_tx_dma_tail(0) != 0x7C10 || super::reg_tx_dma_head(0) != 0x7C0C {
        return TestResult::Fail("TX tail/head wrong");
    }
    if super::reg_rx_dma_base_lsw(2) != 0x5B40 || super::reg_rx_dma_tail(3) != 0x5B70 {
        return TestResult::Fail("RX base/tail stride wrong");
    }
    if super::reg_rx_dma_buf_size(0) != 0x5B18 {
        return TestResult::Fail("RX buf-size reg wrong");
    }
    // RPF L2 unicast filter stride (0x8).
    if super::reg_rpf_uc_daflsw(5) != 0x5138 || super::reg_rpf_uc_ctl(5) != 0x513C {
        return TestResult::Fail("RPF UC stride wrong");
    }
    // ITR map fields for queue 0 (even) and queue 1 (odd).
    if super::itr_map_tx_field(0) != (0x2100, 0x1F00_0000, 24) {
        return TestResult::Fail("ITR TX field q0 wrong");
    }
    if super::itr_map_rx_field(1) != (0x2100, 0x0000_001F, 0) {
        return TestResult::Fail("ITR RX field q1 wrong");
    }
    if super::itr_map_tx_en_bit(0) != (1 << 31) || super::itr_map_rx_en_bit(1) != (1 << 7) {
        return TestResult::Fail("ITR map-enable bits wrong");
    }
    // MAC filter words: h = mac[0]<<8|mac[1], l = mac[2..5] BE.
    let (l, h) = mac_filter_words([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    if h != 0x5254 || l != 0x00AB_CDEF {
        return TestResult::Fail("MAC filter words wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_register_offsets);

// ── Stage 4: fake-device end-to-end conversation ────────────────────
// The fake models the device side of the Atlantic conversation from
// the Linux sources: MIF boot handshake, shared-buffer mailbox
// with transaction counters, RPF filter registers, descriptor
// ring registers. It answers only on its own `FAKE_*` addresses —
// if the driver writes a wrong address, the handshake times out
// and the test fails.

/// Fake boot outcomes.
const FAKE_BOOT_OK: u32 = 0;
const FAKE_BOOT_FAIL: u32 = 1;
const FAKE_BOOT_NO_FW: u32 = 2;

struct FakeRegs {
    regs: IrqSafeSpinLock<Vec<(u64, u32)>>,
    sh_in: IrqSafeSpinLock<Vec<u32>>,
    sh_out: IrqSafeSpinLock<Vec<u32>>,
    log: IrqSafeSpinLock<Vec<(u64, u32)>>,
    boot_mode: IrqSafeSpinLock<u32>,
}

impl FakeRegs {
    fn new() -> Self {
        Self {
            regs: IrqSafeSpinLock::new(Vec::new()),
            sh_in: IrqSafeSpinLock::new(alloc::vec![0; 16]),
            sh_out: IrqSafeSpinLock::new(alloc::vec![0; 512]),
            log: IrqSafeSpinLock::new(Vec::new()),
            boot_mode: IrqSafeSpinLock::new(FAKE_BOOT_OK),
        }
    }

    fn set_boot_mode(&self, mode: u32) {
        *self.boot_mode.lock() = mode;
    }

    /// Preload the firmware's shared OUT buffer the way a booted
    /// AQC113 would present it (transaction counter stable at 1,
    /// FW 1.0 build 0x1234, 2.5G full-duplex link, filter caps
    /// l2_base 2 / 38 filters / rslv base 5 / count 8).
    fn preload_fw_out(&self) {
        let mut out = self.sh_out.lock();
        out[0] = 0x0001_0001;
        out[1] = 0x1234_0001;
        out[5] = 0x0000_0840;
        out[477] = 0x0000_2602;
        out[478] = 0;
        out[479] = 0x0805_0000;
    }

    /// Preload the firmware's shared IN buffer with the permanent
    /// MAC 52:54:00:AB:CD:EF (dwords 2–3).
    fn preload_fw_in_mac(&self) {
        let mut sh_in = self.sh_in.lock();
        sh_in[2] = 0xAB00_5452;
        sh_in[3] = 0x0000_CDEF;
    }

    fn bank_read(&self, off: u64) -> u32 {
        self.regs
            .lock()
            .iter()
            .find(|(a, _)| *a == off)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    fn bank_write(&self, off: u64, value: u32) {
        let mut regs = self.regs.lock();
        if let Some(slot) = regs.iter_mut().find(|(a, _)| *a == off) {
            slot.1 = value;
        } else {
            regs.push((off, value));
        }
    }

    /// Current value of a register as the driver would observe it.
    fn observed(&self, off: u64) -> u32 {
        self.read32(off)
    }

    /// True when the write log contains exactly this write.
    fn logged(&self, off: u64, value: u32) -> bool {
        self.log
            .lock()
            .iter()
            .any(|(a, v)| *a == off && *v == value)
    }
}

impl RegIo for FakeRegs {
    fn read32(&self, off: u64) -> u32 {
        if (FAKE_MIF_SHARED_IN..FAKE_MIF_SHARED_IN + 16 * 4).contains(&off) {
            let idx = ((off - FAKE_MIF_SHARED_IN) / 4) as usize;
            return self.sh_in.lock()[idx];
        }
        if (FAKE_MIF_SHARED_OUT..FAKE_MIF_SHARED_OUT + 512 * 4).contains(&off) {
            let idx = ((off - FAKE_MIF_SHARED_OUT) / 4) as usize;
            return self.sh_out.lock()[idx];
        }
        self.bank_read(off)
    }

    fn write32(&self, off: u64, value: u32) {
        self.log.lock().push((off, value));
        if (FAKE_MIF_SHARED_IN..FAKE_MIF_SHARED_IN + 16 * 4).contains(&off) {
            let idx = ((off - FAKE_MIF_SHARED_IN) / 4) as usize;
            self.sh_in.lock()[idx] = value;
            return;
        }
        if off == FAKE_MIF_BOOT && value & FAKE_BOOT_REQ_REBOOT != 0 {
            // Fake firmware boots instantly on a REBOOT request.
            let boot = match *self.boot_mode.lock() {
                FAKE_BOOT_FAIL => FAKE_BOOT_STARTED | FAKE_BOOT_CODE_FAILED,
                FAKE_BOOT_NO_FW => FAKE_BOOT_STARTED,
                _ => FAKE_BOOT_STARTED | FAKE_BOOT_COMPLETE,
            };
            self.bank_write(FAKE_MIF_BOOT, boot);
            if *self.boot_mode.lock() == FAKE_BOOT_NO_FW {
                self.bank_write(FAKE_MIF_HOST_REQ_INT, FAKE_HOST_REQ_READY);
            }
            return;
        }
        self.bank_write(off, value);
    }
}

fn smoke_aqc113_fake_bringup_conversation() -> TestResult {
    let fake = FakeRegs::new();
    fake.preload_fw_out();
    fake.preload_fw_in_mac();

    // 1. Firmware reboot handshake.
    if super::soft_reset(&fake).is_err() {
        return TestResult::Fail("soft_reset failed against the fake firmware");
    }
    // 2. Firmware interface: filter caps + ACTIVE + jumbo MTU.
    let caps = match super::fw_init(&fake) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("fw_init failed against the fake firmware"),
    };
    if caps.l2_base_index != 2 || caps.l2_count != 38 {
        return TestResult::Fail("filter caps misread from the fake");
    }
    if caps.art_base_index() != 40 || caps.art_count() != 64 {
        return TestResult::Fail("ART base/count misread from the fake");
    }
    // MTU + ACTIVE mode landed in the IN buffer.
    if fake.observed(FAKE_MIF_SHARED_IN) != 16352 {
        return TestResult::Fail("FW MTU != 16352 in the shared IN buffer");
    }
    if fake.observed(FAKE_MIF_SHARED_IN + 4 * 4) & 0xF != 1 {
        return TestResult::Fail("link_control.mode != ACTIVE");
    }
    // 3. Version + MAC.
    match super::read_fw_version(&fake) {
        Ok(0x0100_1234) => {}
        _ => return TestResult::Fail("fw version != 0x01001234"),
    }
    match super::read_permanent_mac(&fake) {
        Some([0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]) => {}
        _ => return TestResult::Fail("permanent MAC misread from the fake"),
    }
    // 4. TX/RX path + MAC filter + MPI_INIT + interrupts.
    super::init_tx_path(&fake);
    super::init_rx_path(&fake, 2);
    super::mac_addr_set(&fake, 2, [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    if super::mpi_init(&fake, 0x3F).is_err() {
        return TestResult::Fail("mpi_init failed against the fake firmware");
    }
    super::init_interrupts(&fake);
    // 5. Rings (fake phys addresses) + tail + start.
    super::program_rings(&fake, 0x0000_0001_0000_0000, 0x0000_0002_0000_0000);
    super::set_rx_tail(&fake, (RING_LEN - 1) as u32);
    super::start_hw(&fake);

    // ── Assert the exact conversation (hand-computed literals) ──
    // TX ring base: LSW 0x00000000 / MSW 0x1; RX: LSW 0 / MSW 0x2.
    if fake.observed(FAKE_TX_BASE_LSW) != 0x0000_0000
        || fake.observed(FAKE_TX_BASE_MSW) != 0x0000_0001
    {
        return TestResult::Fail("TX ring base wrong");
    }
    if fake.observed(FAKE_RX_BASE_LSW) != 0x0000_0000
        || fake.observed(FAKE_RX_BASE_MSW) != 0x0000_0002
    {
        return TestResult::Fail("RX ring base wrong");
    }
    // Ring controls: LEN field (256/8)<<3 = 0x100, EN set by start.
    if fake.observed(FAKE_TX_CTL) != 0x8000_0100 {
        return TestResult::Fail("TX ctl != EN|LEN(0x80000100)");
    }
    if fake.observed(FAKE_RX_CTL) != 0x8000_0100 {
        return TestResult::Fail("RX ctl != EN|LEN(0x80000100)");
    }
    // Tails: TX 0, RX 255 (one slot kept empty).
    if fake.observed(FAKE_TX_TAIL) != 0 {
        return TestResult::Fail("TX tail != 0");
    }
    if fake.observed(FAKE_RX_TAIL) != 255 {
        return TestResult::Fail("RX tail != 255 (reserve-one violated)");
    }
    // RX buffer size: 2048/1024 = 2, header size 0.
    if fake.observed(FAKE_RX_BUF_SIZE) != 2 {
        return TestResult::Fail("RX buf-size != 2");
    }
    // Writeback IRQ enables + buffer enables.
    if fake.observed(FAKE_TDM_WRB_EN) != 0x2 || fake.observed(FAKE_RDM_WRB_EN) != 0x4 {
        return TestResult::Fail("TX/RX writeback-IRQ enables wrong");
    }
    if fake.observed(FAKE_TPB_TX_BUF) != 0x1 || fake.observed(FAKE_RPB_RX_BUF) != 0x1 {
        return TestResult::Fail("TX/RX packet-buffer enables wrong");
    }
    // Interrupt block: GLB 0x20000022, auto-mask all ones,
    // GEN map0 0x88880000, ITR map q0 TX-en bit 31 + RX-en bit 15.
    if fake.observed(FAKE_IRQ_GLB_CTL) != 0x2000_0022 {
        return TestResult::Fail("IRQ global ctl != 0x20000022");
    }
    if fake.observed(FAKE_ITR_IAMRLSW) != 0xFFFF_FFFF {
        return TestResult::Fail("IRQ auto-mask != all ones");
    }
    if fake.observed(FAKE_GEN_IRQ_MAP0) != 0x8888_0000 {
        return TestResult::Fail("GEN IRQ map0 != 0x88880000");
    }
    if fake.observed(FAKE_ITR_MAP_Q0) != ((1 << 31) | (1 << 15)) {
        return TestResult::Fail("ITR map q0 != TX-en|RX-en");
    }
    // RPF: multicast mask 0 + ANY_TO_HOST, VLAN TPIDs, VLAN ctl
    // (promisc|accept-untagged|untagged-act HOST = 0xE), broadcast
    // (act HOST + thresh 0xFFFF = 0xFFFF1000), RPF new-enable bit 11.
    if fake.observed(FAKE_RPF_MCST_MSK) != 0 || fake.observed(FAKE_RPF_MCST_FLR0) != 0x10FFF {
        return TestResult::Fail("multicast filter wrong");
    }
    if fake.observed(FAKE_RPF_VLAN_TPID) != 0x88A8_8100 {
        return TestResult::Fail("VLAN TPID != 0x88A88100");
    }
    if fake.observed(FAKE_RPF_VLAN_CTL) != 0xE {
        return TestResult::Fail("VLAN ctl != 0xE");
    }
    if fake.observed(FAKE_RPF_BC) != 0xFFFF_1000 {
        return TestResult::Fail("broadcast filter != 0xFFFF1000");
    }
    if fake.observed(FAKE_RPF_NEW_EN) != (1 << 11) {
        return TestResult::Fail("RPF new-enable != bit 11");
    }
    // MAC filter 2: DAFLSW 0x00ABCDEF, CTL = EN | DAFMSW 0x5254 |
    // ACT HOST<<16 | TAG 1<<22 = 0x80415254.
    if fake.observed(fake_rpf_uc_daflsw(2)) != 0x00AB_CDEF {
        return TestResult::Fail("MAC filter LSW wrong");
    }
    if fake.observed(fake_rpf_uc_ctl(2)) != 0x8041_5254 {
        return TestResult::Fail("MAC filter CTL != 0x80415254");
    }
    // Multi-entry check (defeats single-entry masking): ALL 38 L2
    // filters were programmed, only index 2 enabled.
    for i in 0..38u64 {
        let ctl = fake.observed(fake_rpf_uc_ctl(i));
        let enabled = ctl & (1 << 31) != 0;
        if enabled != (i == 2) {
            return TestResult::Fail("L2 filter enable map wrong (not only index 2)");
        }
        if ctl & (0x7 << 16) != (1 << 16) {
            return TestResult::Fail("L2 filter action != HOST");
        }
    }
    // Link options: full mask → 0x0300FF01 in IN dword 6.
    if fake.observed(FAKE_MIF_SHARED_IN + 6 * 4) != 0x0300_FF01 {
        return TestResult::Fail("link_options != 0x0300FF01");
    }
    // Link status reads back as 2.5G full duplex.
    if read_link_status(&fake)
        != (LinkStatus {
            carrier: true,
            mbps: 2500,
            full_duplex: true,
        })
    {
        return TestResult::Fail("link status misread from the fake");
    }
    // The TX writeback-threshold write landed (value 0).
    if !fake.logged(FAKE_TX_WRB_THRESH, 0) {
        return TestResult::Fail("TX writeback threshold never programmed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_fake_bringup_conversation);

fn smoke_aqc113_fake_boot_failure() -> TestResult {
    // Tampered firmware: boot reports a code failure → FwFailed.
    let fake = FakeRegs::new();
    fake.set_boot_mode(FAKE_BOOT_FAIL);
    if super::soft_reset(&fake).is_ok() {
        return TestResult::Fail("soft_reset accepted a failed boot");
    }
    // Tampered firmware: host-req READY with no firmware → NoFirmware.
    let fake = FakeRegs::new();
    fake.set_boot_mode(FAKE_BOOT_NO_FW);
    if super::soft_reset(&fake).is_ok() {
        return TestResult::Fail("soft_reset accepted a firmware-less device");
    }
    // Tampered mailbox: transaction counter halves disagree →
    // the guarded block read must fail, not return torn data.
    let fake = FakeRegs::new();
    fake.preload_fw_out();
    fake.sh_out.lock()[0] = 0x0002_0001;
    if super::read_filter_caps(&fake).is_ok() {
        return TestResult::Fail("filter-caps read accepted a torn transaction");
    }
    if super::read_fw_version(&fake).is_ok() {
        return TestResult::Fail("fw-version read accepted a torn transaction");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/aqc113", smoke_aqc113_fake_boot_failure);

// ── Multi-instance (issue #795) ────────────────────────────────────

/// Same shape as `smoke_ixgbe_multi_instance_cookie_dispatch` in
/// `drivers/net/ixgbe/src/ixgbe/tests.rs`: two AQC devices probe,
/// both register in the `CONTROLLERS` vec; a transmit on the second
/// device routes to the second instance (not the first); removing
/// one device leaves the other functional. The QEMU test VM has no
/// AQC silicon, so only the no-silicon branch runs in CI; the live
/// branch runs on real hardware with one or two AQC NICs. The
/// endpoint piece for a QEMU two-NIC run is #1632.
///
/// Routing is proven by the posted frame itself, not by the send
/// result: `transmit` copies the frame into the slot buffer and
/// advances `tx_head` when the descriptor is posted, before the
/// 250 ms DD-writeback poll, so a link-down device still shows the
/// post on the right instance even when the poll times out — and a
/// concurrent stack frame on another port cannot fake the addressed
/// port's slot bytes.
fn smoke_aqc113_multi_instance_cookie_dispatch() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: the kernel-test runner executes post-boot, so the memory
    // map and allocator are online; `ECAM_DEFAULT_BASE` is the standard
    // MMCONFIG window and the enumerator only reads 4-byte config words,
    // rejecting all-1s for unpopulated slots.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let aqc_addrs: Vec<narf_bus::BusAddr> = devs
        .iter()
        .filter(|d| {
            matches!(&d.kind, BusKind::Pcie { .. })
                && d.id.vendor == super::AQC_VENDOR
                && super::ALL_DEV_IDS.contains(&d.id.device)
        })
        .map(|d| d.addr)
        .collect();
    let n = aqc_addrs.len();
    if n == 0 {
        if super::instance_count() != 0 {
            return TestResult::Fail("instance_count != 0 with no aqc113 silicon");
        }
        if super::controller(0).is_some() {
            return TestResult::Fail("controller(0) Some with no aqc113 silicon");
        }
        if super::controller(usize::MAX).is_some() {
            return TestResult::Fail("controller(MAX) Some with no aqc113 silicon");
        }
        if super::is_probed() {
            return TestResult::Fail("is_probed with no aqc113 silicon");
        }
        if super::with_controller(0, |c| c.mac).is_some() {
            return TestResult::Fail("with_controller(0) Some with no aqc113 silicon");
        }
        if super::with_controller_mut(0, |_| ()).is_some() {
            return TestResult::Fail("with_controller_mut(0) Some with no aqc113 silicon");
        }
        // Detach is a no-op without silicon — must not panic, and
        // must not conjure an instance.
        super::aqc113_detach(0);
        super::aqc113_detach(usize::MAX);
        if super::instance_count() != 0 {
            return TestResult::Fail("detach conjured an instance with no silicon");
        }
        // Cookie dispatch without a controller fails instead of
        // resolving to a first (nonexistent) instance.
        let frame = [0u8; 64];
        if super::aqc113_send_frame(0, &frame, narf_net::TxMeta::plain()).is_ok() {
            return TestResult::Fail("aqc113_send_frame resolved cookie 0 with no silicon");
        }
        if super::aqc113_send_frame(1, &frame, narf_net::TxMeta::plain()).is_ok() {
            return TestResult::Fail("aqc113_send_frame resolved cookie 1 with no silicon");
        }
        if narf_net::iface::send_on("eth999", &frame).is_ok() {
            return TestResult::Fail("send_on resolved a nonexistent iface");
        }
        return TestResult::Pass;
    }
    __reset_for_test();
    super::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !super::is_probed() {
        return TestResult::Fail("aqc113 not probed");
    }
    if super::instance_count() != n {
        return TestResult::Fail("instance_count != enumerated AQC device count after probe");
    }
    if super::controller(n).is_some() {
        return TestResult::Fail("controller(n) Some with n NICs");
    }
    if super::controller(usize::MAX).is_some() {
        return TestResult::Fail("controller(MAX) Some");
    }
    // One distinct published name per controller, each resolvable,
    // each bound to the PCI address it was probed at.
    let mut names: Vec<&str> = Vec::new();
    let mut ctrls: Vec<alloc::sync::Arc<super::AqcNic>> = Vec::new();
    for (i, addr) in aqc_addrs.iter().enumerate().take(n) {
        let ctrl = match super::controller(i) {
            Some(c) => c,
            None => return TestResult::Fail("controller(i) None after probe"),
        };
        if ctrl.addr != *addr {
            return TestResult::Fail("controller(i) bound to the wrong PCI address");
        }
        let name = ctrl.ifname();
        if name.is_empty() {
            return TestResult::Fail("published name empty after probe");
        }
        if names.contains(&name) {
            return TestResult::Fail("two controllers share one published name");
        }
        if narf_net::iface::lookup(name).is_none() {
            return TestResult::Fail("iface not published under its name");
        }
        names.push(name);
        ctrls.push(ctrl);
    }
    // Re-probe keeps the same Arcs (same-function dedup by PCI addr).
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    if super::instance_count() != n {
        return TestResult::Fail("instance_count changed across re-probe");
    }
    for (i, ctrl) in ctrls.iter().enumerate().take(n) {
        let after = match super::controller(i) {
            Some(c) => c,
            None => return TestResult::Fail("controller(i) vanished across re-probe"),
        };
        if alloc::sync::Arc::as_ptr(&after) != alloc::sync::Arc::as_ptr(ctrl) {
            return TestResult::Fail("re-probe replaced controller(i)");
        }
    }
    // Registry adapter borrows the NIC's own rings (first port):
    // querying them must not take the consumer/producer out of the
    // NIC's ring.
    let ring_ptr =
        narf_net::registry().with_interface(names[0], |i| i.rx_ring() as *const _ as usize);
    if ring_ptr != Some(&ctrls[0].rx_ipc_ring as *const _ as usize) {
        return TestResult::Fail("adapter rx_ring is not the NIC's own ring");
    }
    if ctrls[0].rx_ipc_ring.lock().is_none() {
        return TestResult::Fail("querying rx_ring took the NIC's RX ring");
    }
    let tx_ptr =
        narf_net::registry().with_interface(names[0], |i| i.tx_ring() as *const _ as usize);
    if tx_ptr != Some(&ctrls[0].tx_ipc_ring as *const _ as usize) {
        return TestResult::Fail("adapter tx_ring is not the NIC's own ring");
    }
    if ctrls[0].tx_ipc_ring.lock().is_none() {
        return TestResult::Fail("querying tx_ring took the NIC's TX ring");
    }
    // Send routing: a frame addressed to port i lands in port i's
    // TX slot buffer and no other port's next slot. The frame is
    // distinctive (broadcast dst, locally-administered src, 0xFFFF
    // ethertype) so no background frame can fake it.
    let mut frame = [0u8; 64];
    frame[..6].fill(0xFF);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame[12] = 0xFF;
    frame[13] = 0xFF;
    for (i, name) in names.iter().enumerate().take(n) {
        let heads: Vec<u32> = ctrls.iter().map(|c| *c.tx_head.lock()).collect();
        let _ = narf_net::iface::send_on(name, &frame);
        for (j, c) in ctrls.iter().enumerate() {
            let slot = (heads[j] as usize) % super::RING_LEN;
            let posted = slot_matches_frame(c, slot, &frame);
            if j == i {
                if !posted {
                    return TestResult::Fail(
                        "send_on did not post the frame to the addressed port's TX ring",
                    );
                }
                if *c.tx_head.lock() == heads[j] {
                    return TestResult::Fail("send_on left the addressed port's TX head unmoved");
                }
            } else if posted {
                return TestResult::Fail(
                    "send_on posted the frame to a port other than the addressed one",
                );
            }
        }
    }
    if n >= 2 {
        // Direct cookie dispatch: cookie 1 resolves to the second
        // instance, never the first.
        let heads: Vec<u32> = ctrls.iter().map(|c| *c.tx_head.lock()).collect();
        let _ = super::aqc113_send_frame(1, &frame, narf_net::TxMeta::plain());
        if !slot_matches_frame(&ctrls[1], (heads[1] as usize) % super::RING_LEN, &frame) {
            return TestResult::Fail("cookie-1 send did not post to the second controller");
        }
        if slot_matches_frame(&ctrls[0], (heads[0] as usize) % super::RING_LEN, &frame) {
            return TestResult::Fail("cookie-1 send posted to the first controller");
        }
    }
    // Removing one device leaves the other functional: detach port
    // 0, then port 1 (when present) still carries traffic and the
    // detached port's cookie no longer resolves.
    super::aqc113_detach(0);
    if super::instance_count() != n - 1 {
        return TestResult::Fail("instance_count did not drop after detach(0)");
    }
    if super::controller(0).is_some() {
        return TestResult::Fail("controller(0) still live after detach(0)");
    }
    if super::with_controller(0, |c| c.mac).is_some() {
        return TestResult::Fail("with_controller(0) still resolves after detach(0)");
    }
    // Detach is idempotent.
    super::aqc113_detach(0);
    if super::instance_count() != n - 1 {
        return TestResult::Fail("second detach(0) changed instance_count");
    }
    if n >= 2 {
        let survivor = match super::controller(1) {
            Some(c) => c,
            None => return TestResult::Fail("controller(1) lost after detach(0)"),
        };
        if alloc::sync::Arc::as_ptr(&survivor) != alloc::sync::Arc::as_ptr(&ctrls[1]) {
            return TestResult::Fail("detach(0) replaced controller(1)");
        }
        let head = *survivor.tx_head.lock();
        let _ = narf_net::iface::send_on(names[1], &frame);
        if !slot_matches_frame(&survivor, (head as usize) % super::RING_LEN, &frame) {
            return TestResult::Fail("surviving port stopped transmitting after detach(0)");
        }
        if super::aqc113_send_frame(0, &frame, narf_net::TxMeta::plain()).is_ok() {
            return TestResult::Fail("detached cookie 0 still transmits");
        }
    }
    // Hot re-bind: a detached entry does not block re-probe of its
    // address, so a fresh probe reclaims the function (at a new
    // cookie — the vec never shrinks) while the survivor keeps its
    // own cookie and Arc.
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    if super::instance_count() != n {
        return TestResult::Fail("instance_count did not recover after re-probe");
    }
    if n >= 2 {
        let after = match super::controller(1) {
            Some(c) => c,
            None => return TestResult::Fail("controller(1) vanished across re-bind"),
        };
        if alloc::sync::Arc::as_ptr(&after) != alloc::sync::Arc::as_ptr(&ctrls[1]) {
            return TestResult::Fail("re-bind replaced the surviving controller(1)");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/aqc113",
    smoke_aqc113_multi_instance_cookie_dispatch
);

/// True when the TX slot buffer `slot` of `ctrl` currently holds
/// the first 14 bytes of `frame` — the routing proof for
/// [`smoke_aqc113_multi_instance_cookie_dispatch`]: `transmit`
/// copies the frame into the slot buffer before posting the
/// descriptor, so the bytes land exactly on the instance that was
/// addressed.
fn slot_matches_frame(ctrl: &super::AqcNic, slot: usize, frame: &[u8]) -> bool {
    for (k, expected) in frame[..14].iter().enumerate() {
        // SAFETY: `slot` is reduced mod `RING_LEN` by the caller, so it
        // indexes a live TX pool buffer; `k < 14`, so the read stays
        // within the frame prefix; the reads are volatile, as in the
        // driver's own receive path.
        let b = unsafe { core::ptr::read_volatile(ctrl.tx_pool[slot].cpu_ptr_at::<u8>(k as u64)) };
        if b != *expected {
            return false;
        }
    }
    true
}

fn smoke_aqc113_rxd_wb_sample_never_mixes_occupants() -> TestResult {
    // An armed RX slot holds the read format (buffer address, zero header
    // address) until the NIC overwrites it with the write-back, and the
    // host may be sampling the slot at that moment. Model the NIC posting
    // the WHOLE write-back after each possible number of host loads.
    // Whatever the interleaving, a sample that reports DD must be the
    // write-back in full: with the armed slot's address bits read as
    // `type` under a fresh DD the frame is dropped or its checksum
    // verdict is wrong.
    //
    // `hw_atl_rxd_wb_s`: type at bytes 0..4, rss_hash 4..8, status 8..10
    // (DD bit 0, EOP bit 1), pkt_len 10..12, next_desc_ptr 12..14, vlan
    // 14..16.
    let old = [0x2345_6000u32, 0x0000_0001, 0, 0];
    let new = [
        0x0008_0045u32,
        0x5EED_CAFE,
        0x0003 | (0x05EA << 16),
        0x0007 | (0x0123 << 16),
    ];

    for post_after in 0..=4usize {
        let slot = core::cell::Cell::new(old);
        let loads = core::cell::Cell::new(0usize);
        let sampled = RxdWb::sample(|dword| {
            if loads.get() == post_after {
                slot.set(new);
            }
            loads.set(loads.get() + 1);
            slot.get()[dword]
        });
        let Some(wb) = sampled else {
            // Not completed yet: the driver polls again.
            if post_after == 0 {
                return TestResult::Fail("a write-back posted before the sample read as armed");
            }
            if loads.get() != 1 {
                return TestResult::Fail("an incomplete slot was read past its status dword");
            }
            continue;
        };
        if loads.get() != 4 {
            return TestResult::Fail("a completed sample is not exactly four dword loads");
        }
        if wb.status != 0x0003 || wb.pkt_len != 0x05EA {
            return TestResult::Fail("fresh DD sampled with a stale packet length");
        }
        if wb.type_ != 0x0008_0045 || wb.rss_hash != 0x5EED_CAFE {
            return TestResult::Fail("fresh DD sampled with the armed slot's address as type");
        }
        if wb.next_desc_ptr != 0x0007 || wb.vlan != 0x0123 {
            return TestResult::Fail("fresh DD sampled with a stale VLAN dword");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/aqc113",
    smoke_aqc113_rxd_wb_sample_never_mixes_occupants
);
