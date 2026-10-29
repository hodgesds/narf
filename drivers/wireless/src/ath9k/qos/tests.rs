//! Native retained AR9285 four-AC/eight-TID transmit: actual WMM response,
//! QCU/DCU programs and DMA receipts. Model records are synthetic test-only
//! inputs, never physical RF measurements.
use super::*;
use crate::ath9k::{
    ht,
    packet::tests::Model,
    station::tests::{self as station, AP, PMK, SSID},
};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use zeroize::Zeroizing;

fn record(base: &ht::Grant) -> Vec<u8> {
    let r = request(base);
    let mut b = vec![0; 96];
    b[..8].copy_from_slice(&[b'N', b'8', b'5', b'Q', 1, 0, 96, 0]);
    b[8..12].copy_from_slice(&96u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 4]);
    b[58..60].copy_from_slice(&12i16.to_le_bytes());
    b[60] = TIDS;
    b[61] = STARVE;
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    b
}
pub(in crate::ath9k) fn qualify(model: &Arc<Model>) -> Cap<FirmwareBlob, Read> {
    let base = model.ht.borrow().clone().unwrap();
    let cap = Cap::bootstrap();
    let g = Source::Verified {
        bytes: record(&base),
        signer: Some([0x85; 32]),
        cap,
    }
    .load(base)
    .unwrap();
    *model.qos.borrow_mut() = Some(g);
    cap
}
fn associate(f: &mut station::Fixture, protected: bool) {
    station::complete(
        f.radio
            .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
    )
    .unwrap();
}
fn settle(f: &mut station::Fixture) {
    for _ in 0..16 {
        f.radio.poll().unwrap();
    }
}
fn ipv4(f: &station::Fixture, dscp: u8, n: u8) -> Vec<u8> {
    let mut p = vec![n; 200];
    p[..6].copy_from_slice(&AP);
    p[6..12].copy_from_slice(&f.plan.station);
    p[12..14].copy_from_slice(&[8, 0]);
    p[14] = 0x45;
    p[15] = dscp << 2;
    p
}
fn last_data(f: &station::Fixture) -> Option<Vec<u8>> {
    f.model
        .transmitted
        .borrow()
        .iter()
        .rev()
        .find(|f| f.first() == Some(&0x88))
        .cloned()
}
/// Expected `AR_D_LCL_IFS` words from `ht::tests::elements()`.
const WORDS: [u32; 4] = [
    15 | (1023 << 10) | (3 << 20),
    7 | (15 << 10) | (2 << 20),
    3 | (7 << 10) | (2 << 20),
    15 | (1023 << 10) | (7 << 20),
];

fn smoke_ar9285_qos_classify_downgrade_and_scheduler_order() -> TestResult {
    let mut frame = vec![0; 40];
    frame[12..14].copy_from_slice(&[8, 0]);
    for (dscp, up) in [
        (46, 6),
        (48, 7),
        (34, 4),
        (18, 3),
        (8, 1),
        (0, 0),
        (10, 0),
        (24, 4),
    ] {
        frame[15] = dscp << 2;
        if classify8021d(&frame) != up {
            return TestResult::Fail("IPv4 DSCP did not follow cfg80211_classify8021d");
        }
    }
    let mut v6 = vec![0; 40];
    v6[12..14].copy_from_slice(&[0x86, 0xdd]);
    v6[14] = 0x60 | (46 >> 2);
    v6[15] = (46 << 6) & 0xc0;
    let mut mpls = vec![0; 40];
    mpls[12..14].copy_from_slice(&[0x88, 0x47]);
    mpls[16] = 5 << 1;
    let mut arp = vec![0; 40];
    arp[12..14].copy_from_slice(&[8, 6]);
    let mut short = vec![0; 14];
    short[12..14].copy_from_slice(&[8, 0]);
    let mut mih = vec![0; 20];
    mih[12..14].copy_from_slice(&[0x89, 0x17]);
    if classify8021d(&v6) != 6
        || classify8021d(&mpls) != 5
        || classify8021d(&arp) != 0
        || classify8021d(&short) != 0
        || classify8021d(&mih) != 7
        || classify8021d(&[0; 4]) != 0
    {
        return TestResult::Fail("IPv6/MPLS/802.21/short classification");
    }
    // VO and VI require admission: VO -> VI -> BE; BE/BK untouched.
    let acm = 0xf0;
    if downgrade(6, acm) != 3 || downgrade(4, acm) != 3 || downgrade(1, acm) != 1 {
        return TestResult::Fail("ACM downgrade");
    }
    if (0..8).map(queue).collect::<Vec<_>>() != [0, 3, 3, 0, 1, 1, 2, 2] {
        return TestResult::Fail("TID to QCU mapping");
    }
    let mut s = Scheduler::default();
    for (tid, n) in [(1, 10), (0, 20), (6, 30), (4, 40)] {
        s.push(tid, n).unwrap();
    }
    let order: Vec<_> = core::iter::from_fn(|| s.pop()).collect();
    if order != [(6, 30), (4, 40), (0, 20), (1, 10)] {
        return TestResult::Fail("strict VO VI BE BK service order");
    }
    s.clear();
    for (tid, n) in [(0, 1), (0, 2), (3, 3)] {
        s.push(tid, n).unwrap();
    }
    if s.pop() != Some((0, 1)) || s.pop() != Some((3, 3)) || s.pop() != Some((0, 2)) {
        return TestResult::Fail("per-AC TID round robin");
    }
    for n in 0..PER_TID as u32 {
        s.push(6, n).unwrap();
        s.push(7, n).unwrap();
    }
    if s.push(6, 99) != Err(99) {
        return TestResult::Fail("per-TID bound");
    }
    s.push(1, 500).unwrap();
    let served = (0..=STARVE as usize).position(|_| s.pop().is_some_and(|(t, _)| t == 1));
    if served != Some(STARVE as usize) {
        return TestResult::Fail("starvation bound did not serve BK");
    }
    if s.pop_tid(7).is_none() || s.is_empty() {
        return TestResult::Fail("pop_tid");
    }
    s.clear();
    if !s.is_empty() || s.pop().is_some() {
        return TestResult::Fail("clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/qos",
    smoke_ar9285_qos_classify_downgrade_and_scheduler_order
);

fn smoke_ar9285_qos_signed_contract_and_missing_source_keeps_be_queue0() -> TestResult {
    let _policy = ht::tests::Policy::install();
    let mut f = station::fixture_ht(true, 255).unwrap();
    let base = f.model.ht.borrow().clone().unwrap();
    let r = request(&base);
    if r.identity == base.ba_identity().0
        || r.identity == crate::ath9k::tx_ba::request(&base).identity
        || r.identity == crate::ath9k::rx_ba::request(&base).identity
        || !r.filename.starts_with("ath9k/ar9285-qos-v1-")
    {
        return TestResult::Fail("QoS qualification aliased another profile");
    }
    let b = record(&base);
    for at in [0, 4, 6, 8, 12, 14, 16, 48, 54, 55, 56, 57, 60, 61, 64, 95] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        if Grant::decode(&bad, Some([1; 32]), Cap::bootstrap(), base.clone()).is_ok() {
            return TestResult::Fail("foreign QoS contract accepted");
        }
    }
    let mut hot = b.clone();
    hot[58..60].copy_from_slice(&300i16.to_le_bytes());
    if Grant::decode(&b, None, Cap::bootstrap(), base.clone()).is_ok()
        || Grant::decode(&hot, Some([1; 32]), Cap::bootstrap(), base.clone()).is_ok()
        || b.len() != 96
    {
        return TestResult::Fail("unsigned or out-of-range QoS record");
    }
    // Peak plus antenna above the signed ceiling never authorizes.
    let mut over = b.clone();
    over[58..60].copy_from_slice(&200i16.to_le_bytes());
    if Grant::decode(&over, Some([1; 32]), Cap::bootstrap(), base.clone())
        .is_ok_and(|g| g.check().is_ok())
    {
        return TestResult::Fail("peak above ceiling authorized QoS");
    }
    // Not granted: a VO-marked frame stays BE/TID0 on QCU0.
    associate(&mut f, true);
    settle(&mut f);
    let voice = ipv4(&f, 46, 1);
    if f.radio.transmit_tid(&voice) != 0 {
        return TestResult::Fail("ungranted owner classified a non-zero TID");
    }
    f.radio.send(&voice).unwrap();
    settle(&mut f);
    let sent = last_data(&f).unwrap();
    if sent[24..26] != [0, 0]
        || f.model.queues.borrow().iter().any(|q| *q != 0)
        || f.model.registers.borrow().contains_key(&0x1044)
    {
        return TestResult::Fail("missing QoS source programmed another AC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/qos",
    smoke_ar9285_qos_signed_contract_and_missing_source_keeps_be_queue0
);

fn smoke_ar9285_qos_native_four_ac_program_tids_and_queues() -> TestResult {
    let _policy = ht::tests::Policy::install();
    for protected in [false, true] {
        let mut f = station::fixture_ht(protected, 255).unwrap();
        qualify(&f.model);
        f.peer.lock().qos_tids = true;
        associate(&mut f, protected);
        settle(&mut f);
        {
            let regs = f.model.registers.borrow();
            let reg = |r: u64| *regs.get(&r).unwrap_or(&0);
            for q in 0..4u64 {
                if reg(0x1040 + q * 4) != WORDS[q as usize] || reg(0x10c0 + q * 4) != 0 {
                    return TestResult::Fail("actual AP WMM did not reach each DCU");
                }
                if q != 0
                    && (reg(0x1000 + q * 4) != 1 << q
                        || reg(0x1080 + q * 4) != 10 | (32 << 8) | (32 << 14)
                        || reg(0x9c0 + q * 4) != 0x800
                        || reg(0x1100 + q * 4) != 0x1102)
                {
                    return TestResult::Fail("additional QCU/DCU recipe");
                }
            }
        }
        f.model.queues.borrow_mut().clear();
        let mut first = [0u16; 8];
        for (n, (dscp, tid, q)) in [
            (46, 6, 2),
            (34, 4, 1),
            (8, 1, 3),
            (18, 3, 0),
            (0, 0, 0),
            (48, 7, 2),
        ]
        .into_iter()
        .enumerate()
        {
            let frame = ipv4(&f, dscp, n as u8);
            if f.radio.transmit_tid(&frame) != tid {
                return TestResult::Fail("granted owner classification");
            }
            f.radio.send(&frame).unwrap();
            settle(&mut f);
            let sent = last_data(&f).unwrap();
            first[usize::from(tid)] = u16::from_le_bytes([sent[22], sent[23]]) >> 4;
            if sent[24] != tid
                || sent[25] != 0
                || f.model.queues.borrow().last() != Some(&q)
                || !protected && first[usize::from(tid)] != 1
                || !f.radio.ready()
            {
                return TestResult::Fail("QoS DATA TID/QCU/per-TID sequence/receipt");
            }
        }
        // A second VO frame advances only TID6's sequence space.
        let again = ipv4(&f, 46, 9);
        f.radio.send(&again).unwrap();
        settle(&mut f);
        let sent = last_data(&f).unwrap();
        if sent[24] != 6 || u16::from_le_bytes([sent[22], sent[23]]) >> 4 != (first[6] + 1) & 4095 {
            return TestResult::Fail("independent TID sequence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/qos",
    smoke_ar9285_qos_native_four_ac_program_tids_and_queues
);

fn smoke_ar9285_qos_teardown_revocation_and_invalid_ac_fallback() -> TestResult {
    let _policy = ht::tests::Policy::install();
    // Teardown with a VO frame owned by QCU2: the stop proof reclaims it,
    // and a wedged DCU pins every mapping.
    for stuck in [false, true] {
        let mut f = station::fixture_ht(false, 255).unwrap();
        qualify(&f.model);
        f.peer.lock().qos_tids = true;
        associate(&mut f, false);
        settle(&mut f);
        f.peer.lock().hold_data = true;
        f.model.stuck_tx.set(stuck);
        f.radio.send(&ipv4(&f, 46, 1)).unwrap();
        if f.model.tx_queue.get() != 2 || f.model.registers.borrow().get(&(0xa00 + 8)) != Some(&1) {
            return TestResult::Fail("VO frame not owned by QCU2");
        }
        if f.radio.retire() == stuck || !stuck && f.model.master.get() {
            return TestResult::Fail("QCU2 teardown reclamation proof");
        }
    }
    // Revoked N85Q authority closes the owner before any further access.
    let mut f = station::fixture_ht(true, 255).unwrap();
    let cap = qualify(&f.model);
    f.peer.lock().qos_tids = true;
    associate(&mut f, true);
    settle(&mut f);
    let before = f.model.transmitted.borrow().len();
    cap.revoke();
    if f.radio.send(&ipv4(&f, 34, 2)).is_ok()
        || f.model.transmitted.borrow().len() != before
        || f.radio.poll().is_ok()
    {
        return TestResult::Fail("revoked QoS program transmitted");
    }
    // A response whose VI CWmax exceeds the DCU field keeps the BE-only
    // queue0 owner (the shared parser already refuses AIFSN<2/min>max).
    let mut response = ht::tests::elements();
    let at = response.len() - 7;
    response[at] = 0xf3;
    let mut f = station::fixture_ht_profile(false, ht::tests::elements(), response).unwrap();
    qualify(&f.model);
    associate(&mut f, false);
    settle(&mut f);
    let voice = ipv4(&f, 46, 3);
    f.radio.send(&voice).unwrap();
    settle(&mut f);
    if f.radio.transmit_tid(&voice) != 0
        || last_data(&f).unwrap()[24] != 0
        || f.model.queues.borrow().iter().any(|q| *q != 0)
        || f.model.registers.borrow().contains_key(&0x1044)
    {
        return TestResult::Fail("invalid non-BE AC programmed a queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/qos",
    smoke_ar9285_qos_teardown_revocation_and_invalid_ac_fallback
);
