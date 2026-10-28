// SPDX-License-Identifier: GPL-2.0-or-later
//! N2xQ all-AC/all-TID WMM routing regressions. Composed cases run through
//! the actual retained C21/C22 station; narrow cases need no station model.
//! The N2xQ records are private inert fixture inputs, not measured assets.
//! Expected values are authored from cfg80211/mac80211 and rtw88 `pci.h`.
use super::ht_tests::{self as ht, Fixture};
use super::packet_format::{self, DataProfile, Queue, ACS_BK, ACS_VI, ACS_VO};
use super::qos;
use alloc::{vec, vec::Vec};
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::{Interface, TxMeta};
use narf_wireless::WirelessNetIface;

pub(super) fn record<F: Fixture>(f: &F, acs: u8) -> Result<Vec<u8>, &'static str> {
    let r = f
        .kind_request(&qos::KIND)
        .map_err(|_| "qos request over the exact base")?;
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(if F::c21() { b"N21Q" } else { b"N22Q" });
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[b'Q', 1]);
    b[56] = acs;
    Ok(b)
}
/// IPv4/UDP uplink with the given TOS byte and a recomputed header checksum.
fn ip(tos: u8, label: u8) -> Vec<u8> {
    let mut up = narf_wifi_fixtures::udp_ipv4(
        [2, 0, 0, 0, 0, 1],
        ht::OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        &[label; 24],
    );
    up[15] = tos;
    up[24] = 0;
    up[25] = 0;
    let mut sum = 0u32;
    for pair in up[14..34].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    up[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    up
}
/// Send one frame; return (recorded QoS TID, descriptor QSEL).
fn send<F: Fixture>(f: &F, tos: u8, label: u8) -> Result<(u8, u8), &'static str> {
    let up = ip(tos, label);
    let _ = f.received();
    f.device()
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "QoS enqueue")?;
    f.pump();
    let p = f.peer().lock();
    if p.uplink.last() != Some(&up) {
        return Err("QoS uplink not delivered");
    }
    let tid = *p.tids.last().ok_or("uplink was not QoS DATA")?;
    drop(p);
    let d = f.descriptor().ok_or("QoS descriptor absent")?;
    Ok((tid, d[5] & 0x1f))
}
// TOS bytes: 0 (BE), CS1 0x20 (BK, TID1), CS5 0xa0 (VI, TID5),
// EF 0xb8 (VO, TID6), CS7 0xe0 (VO, TID7). RFC 8325 / cfg80211.
const CASES: [(u8, u8); 5] = [(0, 0), (0x20, 1), (0xa0, 5), (0xb8, 6), (0xe0, 7)];

/// Success, revocation and teardown through the actual station.
pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let cap = Cap::bootstrap();
    f.stage_kind(&qos::KIND, record(&f, ACS_BK | ACS_VI | ACS_VO)?, cap, true)
        .map_err(|_| "distinct synthetic N2xQ qualification")?;
    f.peer().lock().any_tid = true;
    ht::join(&f)?;
    for (i, (tos, tid)) in CASES.into_iter().enumerate() {
        if send(&f, tos, i as u8)? != (tid, tid) {
            return Err("N2xQ TID/QSEL routing differs from cfg80211_classify8021d");
        }
    }
    cap.revoke();
    if send(&f, 0xb8, 9)? != (0, 0) || !f.device().link_up() {
        return Err("revoked N2xQ kept VO routing or lost the link");
    }
    ht::run(f.device().disassociate())?.map_err(|_| "QoS disconnect")?;
    if f.device().link_up() {
        return Err("QoS station link survived disconnect");
    }
    Ok(())
}

/// Contract not granted, or granted for only a subset of ACs.
pub(super) fn not_granted<F: Fixture>() -> Result<(), &'static str> {
    {
        let f = F::make(false, 255, true, true)?;
        f.peer().lock().any_tid = true;
        ht::join(&f)?;
        for (i, (tos, _)) in CASES.into_iter().enumerate() {
            if send(&f, tos, i as u8)? != (0, 0) {
                return Err("unqualified station left BE/TID0");
            }
        }
    }
    let g = F::make(false, 255, true, true)?;
    g.stage_kind(&qos::KIND, record(&g, ACS_VI)?, Cap::bootstrap(), true)
        .map_err(|_| "N2xQ VI-only qualification")?;
    g.peer().lock().any_tid = true;
    ht::join(&g)?;
    // VO steps down to the qualified VI (TID5); BK falls back to BE.
    let expected = [(0, 0), (0, 0), (5, 5), (5, 5), (5, 5)];
    for (i, (tos, _)) in CASES.into_iter().enumerate() {
        if send(&g, tos, i as u8)? != expected[i] {
            return Err("VI-only N2xQ used an unqualified AC");
        }
    }
    Ok(())
}

/// Unsigned, altered, foreign and revoked records are refused.
pub(super) fn refusals<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let good = record(&f, ACS_VO)?;
    if f.stage_kind(&qos::KIND, good.clone(), Cap::bootstrap(), false)
        .is_ok()
    {
        return Err("unsigned N2xQ admitted");
    }
    let mut cases = Vec::new();
    let mut tag = good.clone();
    tag[3] = b'C';
    cases.push(tag);
    let mut id = good.clone();
    id[40] ^= 4;
    cases.push(id);
    let mut mac = good.clone();
    mac[50] ^= 1;
    cases.push(mac);
    let mut tail = good.clone();
    tail[100] = 1;
    cases.push(tail);
    cases.push(record(&f, 0)?);
    cases.push(record(&f, 1 << 3)?);
    for b in cases {
        if f.stage_kind(&qos::KIND, b, Cap::bootstrap(), true).is_ok() {
            return Err("altered/foreign N2xQ admitted");
        }
    }
    let revoked = Cap::bootstrap();
    revoked.revoke();
    if f.stage_kind(&qos::KIND, good, revoked, true).is_ok() {
        return Err("revoked N2xQ source admitted");
    }
    Ok(())
}

fn profile(acs: u8) -> DataProfile {
    DataProfile {
        rates: 0xff0,
        qos: true,
        mcs: 0,
        sgi: false,
        ldpc: false,
        stbc: false,
        acs,
    }
}
fn eth(tos: u8) -> Vec<u8> {
    let mut e = vec![0; 34];
    e[12..14].copy_from_slice(&[8, 0]);
    e[14] = 0x45;
    e[15] = tos;
    e
}

fn smoke_rtw88_qos_classify_downgrade_and_queues() -> TestResult {
    // RFC 8325 / cfg80211_classify8021d.
    for (tos, tid) in [
        (0u8, 0u8),
        (0x20, 1),
        (0x28, 0),
        (0x48, 3),
        (0xa0, 5),
        (0xb8, 6),
        (0xc0, 7),
        (0xe0, 7),
    ] {
        if qos::classify(&eth(tos)) != tid {
            return TestResult::Fail("cfg80211_classify8021d IPv4 mapping");
        }
    }
    let mut v6 = vec![0; 34];
    v6[12..14].copy_from_slice(&[0x86, 0xdd]);
    v6[14] = 0x6b; // version6, traffic class 0xb8 (EF)
    v6[15] = 0x80;
    if qos::classify(&v6) != 6 || qos::classify(&[0; 10]) != 0 {
        return TestResult::Fail("cfg80211_classify8021d IPv6/short mapping");
    }
    let all = profile(ACS_BK | ACS_VI | ACS_VO);
    // ACM on VO and VI downgrades EF to BE; ACM everywhere ends on BK.
    if qos::tid_for(&eth(0xb8), [false, false, true, true], all) != 0
        || qos::tid_for(&eth(0xb8), [true, true, true, true], all) != 2
        || qos::tid_for(&eth(0xb8), [false; 4], profile(0)) != 0
        || qos::tid_for(&eth(0x20), [false; 4], profile(ACS_VO)) != 0
    {
        return TestResult::Fail("ieee80211_downgrade_queue or qualified-AC fallback");
    }
    let q = [
        (0u8, Queue::Data, 0x3a8),
        (1, Queue::Background, 0x3ac),
        (2, Queue::Background, 0x3ac),
        (3, Queue::Data, 0x3a8),
        (4, Queue::Video, 0x3a4),
        (5, Queue::Video, 0x3a4),
        (6, Queue::Voice, 0x3a0),
        (7, Queue::Voice, 0x3a0),
    ];
    for (tid, queue, index) in q {
        if all.tid_queue(tid) != Some(queue) || queue.index() != index {
            return TestResult::Fail("rtw_tx_ac_to_hwq ring or TXBD index");
        }
    }
    if profile(0).tid_queue(3).is_some()
        || profile(ACS_VI).tid_queue(6).is_some()
        || all.tid_queue(8).is_some()
        || (DataProfile { qos: false, ..all }).valid()
        || profile(1 << 3).valid()
    {
        return TestResult::Fail("unqualified TID admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/narrow/qos",
    smoke_rtw88_qos_classify_downgrade_and_queues
);

fn smoke_rtw88_qos_descriptor_qsel_and_bounds() -> TestResult {
    let own = ht::OWN;
    let mut frame = vec![0x88, 1, 0, 0];
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x10, 0, 6, 0]);
    frame.extend_from_slice(&[0; 32]);
    let all = profile(ACS_BK | ACS_VI | ACS_VO);
    let Ok((d, queue)) = packet_format::transmit_profile(&frame, own, 0, None, all) else {
        return TestResult::Fail("qualified TID6 refused");
    };
    if queue != Queue::Voice || d[5] & 0x1f != 6 {
        return TestResult::Fail("TID6 QSEL/VO ring");
    }
    if packet_format::transmit_profile(&frame, own, 0, None, profile(0)).is_ok() {
        return TestResult::Fail("TID6 admitted without N2xQ");
    }
    // EOSP / non-normal ack policy stay refused.
    frame[24] = 0x16;
    if packet_format::transmit_profile(&frame, own, 0, None, all).is_ok() {
        return TestResult::Fail("EOSP QoS control admitted");
    }
    let mut p = [0u8; 64];
    p[0] = ACS_VO | ACS_BK;
    if qos::bounds(&p) != Some(ACS_VO | ACS_BK) {
        return TestResult::Fail("N2xQ bounds");
    }
    p[0] = 0;
    let zero = qos::bounds(&p);
    p[0] = 8;
    let reserved = qos::bounds(&p);
    p[0] = 1;
    p[9] = 1;
    if zero.is_some() || reserved.is_some() || qos::bounds(&p).is_some() {
        return TestResult::Fail("N2xQ inadmissible payload accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/narrow/qos",
    smoke_rtw88_qos_descriptor_qsel_and_bounds
);
