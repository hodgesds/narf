//! RTL8192EU txdesc40 / rxdesc24 / C2H codec regressions. Expected words
//! are derived from Linux `rtl8xxxu/core.c` (`rtl8xxxu_tx`,
//! `rtl8xxxu_fill_txdesc_v2`, `rtl8xxxu_parse_rxdesc24`) by hand; nothing
//! here is a hardware receipt.

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::packet_codec::{Error, Kind};
use super::rtl8192e_packet::{self as packet, C2h, Record, TxControl, TX_DESC};

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn auth() -> Vec<u8> {
    let mut f = vec![0u8; 30];
    f[0] = 0xb0;
    f[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    f[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    f[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    f[22..24].copy_from_slice(&(0x123u16 << 4).to_le_bytes());
    f
}

fn qos_data(tid: u8) -> Vec<u8> {
    let mut f = vec![0u8; 40];
    f[0] = 0x88;
    f[1] = 0x01;
    f[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    f[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    f[16..22].copy_from_slice(&[0xff; 6]);
    f[22..24].copy_from_slice(&(7u16 << 4).to_le_bytes());
    f[24] = tid;
    f
}

fn csum_ok(p: &[u8]) -> bool {
    p[..32]
        .chunks_exact(2)
        .fold(0u16, |v, b| v ^ u16::from_le_bytes([b[0], b[1]]))
        == 0
}

fn smoke_rtl8192eu_txdesc40_management() -> TestResult {
    let f = auth();
    let p = match packet::transmit(&f, Kind::Management, TxControl::default()) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("auth rejected"),
    };
    if p.len() != TX_DESC + f.len() || &p[TX_DESC..] != f.as_slice() {
        return TestResult::Fail("layout");
    }
    if u16::from_le_bytes([p[0], p[1]]) != 30 || p[2] != 40 || p[3] != 0x8c {
        return TestResult::Fail("dw0");
    }
    if word(&p, 4) != 0x12 << 8 || word(&p, 8) != 1 << 16 || word(&p, 12) != 1 << 8 {
        return TestResult::Fail("dw1..dw3");
    }
    if word(&p, 16) != (6 << 18 | 1 << 17) || word(&p, 20) != 0 {
        return TestResult::Fail("dw4/dw5");
    }
    if word(&p, 32) != 0 || word(&p, 36) != 0x123 << 12 {
        return TestResult::Fail("dw8/dw9 sequence");
    }
    if !csum_ok(&p) {
        return TestResult::Fail("checksum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_txdesc40_management
);

fn smoke_rtl8192eu_txdesc40_data_ampdu() -> TestResult {
    let f = qos_data(5);
    let control = TxControl {
        macid: 0,
        ampdu_density: Some(6),
        tid_operational: true,
        short_preamble: true,
        ..TxControl::default()
    };
    let p = match packet::transmit(&f, Kind::Data, control) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("qos data rejected"),
    };
    // DA = A3 broadcast for ToDS.
    if p[3] != 0x8d || word(&p, 4) != 5 << 8 {
        return TestResult::Fail("bmc/queue VI");
    }
    if word(&p, 8) != (6 << 20 | 1 << 12) {
        return TestResult::Fail("AGG_ENABLE + density");
    }
    if word(&p, 12) != (1 << 12 | 1 << 13) {
        return TestResult::Fail("RTS/HW RTS");
    }
    if word(&p, 16) != (0x1f << 8 | 8 << 24) || word(&p, 20) != 1 << 4 {
        return TestResult::Fail("fallback/RTS rate/preamble");
    }
    if word(&p, 36) != 7 << 12 || !csum_ok(&p) {
        return TestResult::Fail("seq/checksum");
    }
    let plain = TxControl {
        use_cts_prot: true,
        ..TxControl::default()
    };
    let p = packet::transmit(&qos_data(0), Kind::Data, plain).unwrap();
    if word(&p, 8) != 1 << 16 || word(&p, 12) != 1 << 11 || word(&p, 16) != (0x1f << 8 | 8 << 24) {
        return TestResult::Fail("CTS-to-self without HW RTS");
    }
    let mut frag = qos_data(0);
    frag[1] |= 4;
    if packet::transmit(&frag, Kind::Data, plain) != Err(Error::Header) {
        return TestResult::Fail("more-fragments accepted");
    }
    if packet::transmit(&auth(), Kind::Management, control) != Err(Error::Header) {
        return TestResult::Fail("A-MPDU fields on management");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_txdesc40_data_ampdu
);

fn rxdesc(len: usize, info: u8, d1: u32, d2: u32, rate: u8, d4: u32) -> Vec<u8> {
    let mut d = vec![0u8; 24];
    let d0 = len as u32 | u32::from(info) << 16 | 1 << 26 | 1 << 28 | 1 << 29;
    d[0..4].copy_from_slice(&d0.to_le_bytes());
    d[4..8].copy_from_slice(&d1.to_le_bytes());
    d[8..12].copy_from_slice(&d2.to_le_bytes());
    d[12..16].copy_from_slice(&u32::from(rate).to_le_bytes());
    d[16..20].copy_from_slice(&d4.to_le_bytes());
    d[20..24].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    d
}

fn smoke_rtl8192eu_rxdesc24_records() -> TestResult {
    let mut urb = rxdesc(30, 4, 0, 0, 0x0c + 7, 1 << 4);
    let mut phy = vec![0u8; 32];
    phy[4] = 100;
    urb.extend_from_slice(&phy);
    let mut mpdu = vec![0u8; 30];
    mpdu[0] = 0x08;
    mpdu[1] = 0x02;
    urb.extend_from_slice(&mpdu);
    while urb.len() % 8 != 0 {
        urb.push(0);
    }
    // C2H RA report: id, seq, rate|sgi, macid, flags, 3 reserved, bw=1.
    let c2h = [0x0c, 1, 0x80 | 0x13, 0, 0x01, 0, 0, 0, 1];
    let mut d = rxdesc(c2h.len(), 0, 0, 1 << 28, 0, 0);
    d[3] &= !(1 << 2); // phy_stats clear
    urb.extend_from_slice(&d);
    urb.extend_from_slice(&c2h);
    let records = match packet::receive(&urb) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("parse failed"),
    };
    let [Record::Frame(frame), Record::C2h(C2h::RaReport(report))] = records.as_slice() else {
        return TestResult::Fail("record shapes");
    };
    if frame.bytes != mpdu || frame.phy.len() != 32 || frame.rate != 19 || !frame.bandwidth40 {
        return TestResult::Fail("frame fields");
    }
    if frame.timestamp != 0xdead_beef || !frame.ht() {
        return TestResult::Fail("tsfl/ht");
    }
    if !frame.admitted(true, true, false) || frame.admitted(true, false, false) {
        return TestResult::Fail("HT40 admission gate");
    }
    if packet::signal(&frame.phy, frame.rate, false) != Some(50 - 110) {
        return TestResult::Fail("OFDM signal");
    }
    if report.rate != 0x13 || !report.sgi || !report.ldpc || report.bandwidth40 != Some(true) {
        return TestResult::Fail("RA report");
    }
    if report.nss() != Some(1) || !report.valid() {
        return TestResult::Fail("RA nss");
    }
    // Truncated record extent is a length error, not a partial MPDU.
    let short = &urb[..40];
    if packet::receive(short) != Err(Error::Length) {
        return TestResult::Fail("truncated record accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_rxdesc24_records
);

fn smoke_rtl8192eu_rx_admission_and_cck_signal() -> TestResult {
    // CRC error record is dropped, the following one survives.
    let mut urb = rxdesc(16, 0, 0, 0, 0, 0);
    urb[1] |= 0x40; // crc32
    urb.extend_from_slice(&[0u8; 16]);
    let mut mpdu = vec![0u8; 26];
    mpdu[0] = 0x88;
    mpdu[1] = 0x02;
    mpdu[24] = 3;
    let mut d = rxdesc(mpdu.len(), 0, 3 << 8 | 1 << 15, 0, 2, 0);
    d[2] |= 1 << 7; // qos (d0 bit 23)
    urb.extend_from_slice(&d);
    urb.extend_from_slice(&mpdu);
    let records = packet::receive(&urb).unwrap();
    let [Record::Frame(frame)] = records.as_slice() else {
        return TestResult::Fail("crc record not dropped");
    };
    if !frame.qos || frame.tid != 3 || !frame.paggr {
        return TestResult::Fail("qos/tid/paggr");
    }
    // A legacy A-MPDU member is never admitted, even with a BA session.
    if frame.admitted(true, false, true) {
        return TestResult::Fail("legacy paggr admitted");
    }
    let mut plain = frame.clone();
    plain.paggr = false;
    if !plain.admitted(false, false, false) {
        return TestResult::Fail("legacy 5.5M refused");
    }
    plain.decrypted = true;
    if plain.admitted(true, true, true) {
        return TestResult::Fail("hardware-decrypted admitted");
    }
    let mut phy = [0u8; 8];
    phy[5] = 2 << 5 | 3;
    if packet::signal(&phy, 0, false) != Some(-16) || packet::signal(&phy, 0, true) != Some(7) {
        return TestResult::Fail("rtl8192e_cck_rssi tables");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_rx_admission_and_cck_signal
);
