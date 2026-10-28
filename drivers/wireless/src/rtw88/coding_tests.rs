// SPDX-License-Identifier: GPL-2.0-or-later
//! N2xC TX coding (LDPC/STBC) regressions. Composed cases run through the
//! actual retained C21/C22 HT station; narrow cases need no station model.
//! The N2xC records are private inert fixture inputs, not measured assets.
//! Expected bits are authored from Linux `tx.h`/`fw.h`/`main.c`.
use super::coding::{self, LDPC, STBC};
use super::ht_tests::{self as ht, Fixture};
use super::packet_format::{self, DataProfile};
use alloc::{vec, vec::Vec};
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::{Interface, TxMeta};
use narf_wireless::WirelessNetIface;

pub(super) fn record<F: Fixture>(f: &F, flags: u8) -> Result<Vec<u8>, &'static str> {
    let r = f
        .kind_request(&coding::KIND)
        .map_err(|_| "coding request over the exact base")?;
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(if F::c21() { b"N21C" } else { b"N22C" });
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[b'C', 1]);
    b[56] = flags;
    Ok(b)
}
/// Re-advertise the AP with HT LDPC (cap bit0) and/or one RX STBC stream.
fn peer<F: Fixture>(f: &F, ldpc: bool, stbc: bool) -> Result<(), &'static str> {
    let mut elements = ht::elements(true);
    elements[2] |= u8::from(ldpc);
    elements[3] |= u8::from(stbc);
    let beacon = {
        let p = f.peer().lock();
        let mut b = p.ap.beacon();
        b.extend_from_slice(p.wmm.as_ref().ok_or("fixture WMM")?);
        b.extend_from_slice(&elements);
        b
    };
    f.peer().lock().ht = Some(elements);
    // Age out the fixture's first observation (10 s lifetime) so the scan
    // binds the re-advertised capabilities.
    f.advance_ms(20_000);
    f.inject(&beacon, 0, 0);
    Ok(())
}
fn requested_cap<F: Fixture>(f: &F) -> Result<u16, &'static str> {
    let a = f
        .peer()
        .lock()
        .association
        .clone()
        .ok_or("actual association request missing")?;
    let at = a
        .windows(2)
        .position(|w| w == [45, 26])
        .ok_or("actual request has no HT IE")?;
    Ok(u16::from_le_bytes([a[at + 2], a[at + 3]]))
}
fn uplink<F: Fixture>(f: &F, label: u8) -> Result<[u8; 48], &'static str> {
    let up = narf_wifi_fixtures::udp_ipv4(
        [2, 0, 0, 0, 0, 1],
        ht::OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        &[label; 24],
    );
    let _ = f.received();
    f.device()
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "coded HT enqueue")?;
    f.pump();
    if f.peer().lock().uplink.last() != Some(&up) {
        return Err("coded HT uplink not delivered");
    }
    f.descriptor().ok_or("coded HT descriptor absent")
}
fn ra_info(m: &[[u8; 8]]) -> Option<u8> {
    m.iter().rev().find(|w| w[0] == 0x40).map(|w| w[3])
}
fn word5(d: &[u8; 48]) -> u32 {
    u32::from_le_bytes([d[20], d[21], d[22], d[23]])
}

/// Success and revocation: qualified flags plus a capable peer select the
/// source W5/RA_INFO bits; revoking the continuation downgrades to uncoded.
pub(super) fn composition<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let flags = if F::c21() { LDPC } else { LDPC | STBC };
    let cap = Cap::bootstrap();
    f.stage_kind(&coding::KIND, record(&f, flags)?, cap, true)
        .map_err(|_| "distinct synthetic N2xC qualification")?;
    peer(&f, true, true)?;
    ht::join(&f)?;
    let c = requested_cap(&f)?;
    // RX STBC1 on all chips; RX LDPC only with rx_ldpc (C22); TX STBC only
    // with tx_stbc (C22) and only once qualified.
    let expected = if F::c21() { 0x100 } else { 0x181 };
    if c & 0x381 != expected {
        return Err("advertised HT LDPC/TX STBC/RX STBC bits");
    }
    let d = uplink(&f, 1)?;
    let w = word5(&d);
    let stbc = if F::c21() { 0 } else { 1 << 8 };
    if w & (1 << 7) == 0 || w & (3 << 8) != stbc || w & (1 << 4) == 0 {
        return Err("coded DATA W5 LDPC/STBC/SGI bits");
    }
    if ra_info(&f.mailboxes()) != Some(0x44) {
        return Err("RA_INFO LDPC bit26 not set for a coded peer");
    }
    cap.revoke();
    let d = uplink(&f, 2)?;
    if word5(&d) & (7 << 7) != 0 || word5(&d) & (1 << 4) == 0 || !f.device().link_up() {
        return Err("revoked N2xC kept coding or lost the base HT link");
    }
    let _ = ht::run(f.device().watchdog())?;
    if ra_info(&f.mailboxes()) != Some(0x40) || !f.device().link_up() {
        return Err("revoked N2xC did not restore uncoded RA_INFO");
    }
    Ok(())
}

/// Contract not granted, or a peer without coding: base RX advertisement
/// only and an uncoded descriptor/RA_INFO.
pub(super) fn not_granted<F: Fixture>() -> Result<(), &'static str> {
    {
        let f = F::make(false, 255, true, true)?;
        peer(&f, true, true)?;
        ht::join(&f)?;
        let rx = if F::c21() { 0x100 } else { 0x101 };
        if requested_cap(&f)? & 0x381 != rx {
            return Err("unqualified station advertised TX STBC or wrong RX coding");
        }
        let d = uplink(&f, 3)?;
        if word5(&d) & (7 << 7) != 0 || ra_info(&f.mailboxes()) != Some(0x40) {
            return Err("unqualified station emitted coded DATA");
        }
    }
    // Qualified, but the AP advertises neither LDPC nor RX STBC.
    let g = F::make(false, 255, true, true)?;
    let flags = if F::c21() { LDPC } else { LDPC | STBC };
    g.stage_kind(&coding::KIND, record(&g, flags)?, Cap::bootstrap(), true)
        .map_err(|_| "N2xC qualification")?;
    peer(&g, false, false)?;
    ht::join(&g)?;
    let d = uplink(&g, 4)?;
    if word5(&d) & (7 << 7) != 0 || ra_info(&g.mailboxes()) != Some(0x40) {
        return Err("coding emitted toward a peer without LDPC/RX STBC");
    }
    Ok(())
}

/// Failure: unsigned, altered, foreign and revoked records are refused, and
/// teardown clears the bound coding before a fresh lifecycle.
pub(super) fn refusals<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let good = record(&f, LDPC)?;
    if f.stage_kind(&coding::KIND, good.clone(), Cap::bootstrap(), false)
        .is_ok()
    {
        return Err("unsigned N2xC admitted");
    }
    let mut cases = Vec::new();
    let mut tag = good.clone();
    tag[3] = b'D';
    cases.push(tag);
    let mut id = good.clone();
    id[30] ^= 1;
    cases.push(id);
    let mut kind = good.clone();
    kind[54] = b'D';
    cases.push(kind);
    let mut tail = good.clone();
    tail[57] = 1;
    cases.push(tail);
    cases.push(record(&f, 0)?);
    cases.push(record(&f, 1 << 2)?);
    if F::c21() {
        // TX STBC needs two transmit paths.
        cases.push(record(&f, STBC)?);
    }
    for b in cases {
        if f.stage_kind(&coding::KIND, b, Cap::bootstrap(), true)
            .is_ok()
        {
            return Err("altered/foreign N2xC admitted");
        }
    }
    let revoked = Cap::bootstrap();
    revoked.revoke();
    if f.stage_kind(&coding::KIND, good.clone(), revoked, true)
        .is_ok()
    {
        return Err("revoked N2xC source admitted");
    }
    // A qualified station tears down cleanly and keeps the HT link uncoded
    // when its staged continuation is revoked before association.
    let late = Cap::bootstrap();
    f.stage_kind(&coding::KIND, good, late, true)
        .map_err(|_| "N2xC qualification")?;
    late.revoke();
    peer(&f, true, true)?;
    ht::join(&f)?;
    let d = uplink(&f, 5)?;
    if word5(&d) & (7 << 7) != 0 {
        return Err("revoked-before-join N2xC emitted coded DATA");
    }
    ht::run(f.device().disassociate())?.map_err(|_| "coded station disconnect")?;
    if f.device().link_up() {
        return Err("coded station link survived disconnect");
    }
    Ok(())
}

fn ht_profile(ldpc: bool, stbc: bool) -> DataProfile {
    DataProfile {
        rates: 0xff0,
        qos: true,
        mcs: 0xff,
        sgi: true,
        ldpc,
        stbc,
        acs: 0,
    }
}

fn smoke_rtw88_coding_descriptor_word5_bits() -> TestResult {
    let mut frame = vec![0x88, 1, 0, 0];
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&ht::OWN);
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x10, 0, 0, 0]);
    frame.extend_from_slice(&[0; 32]);
    for (ldpc, stbc, expected) in [
        (false, false, 1u32 << 4),
        (true, false, 1 << 4 | 1 << 7),
        (false, true, 1 << 4 | 1 << 8),
        (true, true, 1 << 4 | 1 << 7 | 1 << 8),
    ] {
        let Ok((d, _)) =
            packet_format::transmit_profile(&frame, ht::OWN, 0, None, ht_profile(ldpc, stbc))
        else {
            return TestResult::Fail("rtw88 TX coding narrow check");
        };
        if u32::from_le_bytes([d[20], d[21], d[22], d[23]]) != expected {
            return TestResult::Fail("rtw88 TX coding narrow check");
        }
    }
    // Legacy (non-HT) profiles can never carry TX coding.
    let legacy = DataProfile {
        ldpc: true,
        ..DataProfile::LEGACY
    };
    if legacy.valid() || !ht_profile(true, true).valid() {
        return TestResult::Fail("rtw88 TX coding narrow check");
    }
    if ht_profile(true, true).uncoded() != ht_profile(false, false) {
        return TestResult::Fail("rtw88 TX coding narrow check");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/narrow/coding",
    smoke_rtw88_coding_descriptor_word5_bits
);

fn smoke_rtw88_coding_payload_bounds_and_apply() -> TestResult {
    let mut p = [0u8; 64];
    let ok = |did, flags: u8, p: &mut [u8; 64]| {
        p[0] = flags;
        coding::bounds(did, p)
    };
    if ok(0xc822, LDPC | STBC, &mut p) != Some(3)
        || ok(0xc821, LDPC, &mut p) != Some(1)
        || ok(0xc821, STBC, &mut p).is_some()
        || ok(0xc822, 0, &mut p).is_some()
        || ok(0xc822, 4, &mut p).is_some()
        || ok(0xb822, LDPC, &mut p).is_some()
    {
        return TestResult::Fail("rtw88 TX coding narrow check");
    }
    p[0] = LDPC;
    p[63] = 1;
    if coding::bounds(0xc822, &p).is_some() {
        return TestResult::Fail("rtw88 TX coding narrow check");
    }
    let base = ht_profile(false, false);
    // Peer capability and qualified flags must both allow each coding.
    if coding::apply(LDPC | STBC, base, true, true) != ht_profile(true, true)
        || coding::apply(LDPC, base, true, true) != ht_profile(true, false)
        || coding::apply(LDPC | STBC, base, false, true) != ht_profile(false, true)
        || coding::apply(LDPC | STBC, DataProfile::LEGACY, true, true) != DataProfile::LEGACY
    {
        return TestResult::Fail("rtw88 TX coding narrow check");
    }
    if !coding::permits(LDPC, ht_profile(true, false))
        || coding::permits(LDPC, ht_profile(false, true))
        || !coding::rx_ldpc(0xc822)
        || coding::rx_ldpc(0xc821)
    {
        return TestResult::Fail("rtw88 TX coding narrow check");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/narrow/coding",
    smoke_rtw88_coding_payload_bounds_and_apply
);
