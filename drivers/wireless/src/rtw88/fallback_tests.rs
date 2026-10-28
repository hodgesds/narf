// SPDX-License-Identifier: GPL-2.0-or-later
//! N2xF DATA rate fallback regressions. Composed cases run through the
//! actual retained C21/C22 station; narrow cases need no station model.
//! The N2xF records are private inert fixture inputs, not measured assets.
//! Expected descriptor bits are authored from Linux v7.2 rtw88 `tx.c`.
use super::fallback;
use super::ht_tests::{self as ht, Fixture};
use super::packet_format::{self, DataProfile};
use super::qualification::PAYLOAD;
use alloc::{vec, vec::Vec};
use narf_capabilities::Cap;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::{Interface, TxMeta};
use narf_wireless::WirelessNetIface;

/// W3 USE_RATE (bit 8) | DISDATAFB (bit 10).
const FIXED: u8 = 0x05;

pub(super) fn record<F: Fixture>(f: &F, enable: u8) -> Result<Vec<u8>, &'static str> {
    let r = f
        .kind_request(&fallback::KIND)
        .map_err(|_| "fallback request over the exact base")?;
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(if F::c21() { b"N21F" } else { b"N22F" });
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[b'F', 1]);
    b[56] = enable;
    Ok(b)
}
fn uplink(label: u8) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        [2, 0, 0, 0, 0, 1],
        ht::OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        &[label; 24],
    )
}
/// Send one uplink; return the W3 USE_RATE|DISDATAFB bits it carried.
fn send<F: Fixture>(f: &F, label: u8) -> Result<u8, &'static str> {
    let up = uplink(label);
    f.device()
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "fallback enqueue")?;
    f.pump();
    if f.peer().lock().uplink.last() != Some(&up) {
        return Err("fallback uplink not delivered");
    }
    let d = f.descriptor().ok_or("fallback descriptor absent")?;
    Ok(d[13] & FIXED)
}

/// Success, revocation and teardown through the actual station.
pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let cap = Cap::bootstrap();
    f.stage_kind(&fallback::KIND, record(&f, 1)?, cap, true)
        .map_err(|_| "distinct synthetic N2xF qualification")?;
    ht::join(&f)?;
    for label in 0..3 {
        if send(&f, label)? != 0 {
            return Err("qualified N2xF DATA kept USE_RATE/DISDATAFB");
        }
    }
    cap.revoke();
    if send(&f, 7)? != FIXED || !f.device().link_up() {
        return Err("revoked N2xF kept firmware fallback or lost the link");
    }
    ht::run(f.device().disassociate())?.map_err(|_| "fallback disconnect")?;
    if f.device().link_up() || f.device().enqueue(&uplink(9), TxMeta::default()).is_ok() {
        return Err("fallback station survived disconnect");
    }
    Ok(())
}

/// Contract not granted: DATA stays fixed-rate.
pub(super) fn not_granted<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    ht::join(&f)?;
    for label in 0..2 {
        if send(&f, label)? != FIXED {
            return Err("unqualified station enabled rate fallback");
        }
    }
    Ok(())
}

/// Unsigned, altered, foreign and revoked records are refused.
pub(super) fn refusals<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let good = record(&f, 1)?;
    if f.stage_kind(&fallback::KIND, good.clone(), Cap::bootstrap(), false)
        .is_ok()
    {
        return Err("unsigned N2xF admitted");
    }
    let mut cases = Vec::new();
    let mut tag = good.clone();
    tag[3] = b'Q';
    cases.push(tag);
    let mut id = good.clone();
    id[40] ^= 4;
    cases.push(id);
    let mut tail = good.clone();
    tail[100] = 1;
    cases.push(tail);
    cases.push(record(&f, 0)?);
    cases.push(record(&f, 2)?);
    for b in cases {
        if f.stage_kind(&fallback::KIND, b, Cap::bootstrap(), true)
            .is_ok()
        {
            return Err("altered/foreign N2xF admitted");
        }
    }
    let revoked = Cap::bootstrap();
    revoked.revoke();
    if f.stage_kind(&fallback::KIND, good, revoked, true).is_ok() {
        return Err("revoked N2xF source admitted");
    }
    Ok(())
}

fn data(qos: bool) -> Vec<u8> {
    let mut b = vec![if qos { 0x88 } else { 0x08 }, 1, 0, 0];
    b.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    b.extend_from_slice(&ht::OWN);
    b.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    b.extend_from_slice(&[0x10, 0]);
    if qos {
        b.extend_from_slice(&[0, 0]);
    }
    b.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
    b.extend_from_slice(&[0x45; 28]);
    b
}

/// Payload bounds and the descriptor W3 bits for DATA versus management,
/// with and without the qualified profile.
fn smoke_rtw88_fallback_payload_bounds_and_descriptor_bits() -> TestResult {
    let mut p = [0; PAYLOAD];
    if fallback::bounds(&p) {
        return TestResult::Fail("empty N2xF payload admitted");
    }
    p[0] = 1;
    if !fallback::bounds(&p)
        || !(fallback::KIND.admit)(0xc821, &p)
        || (fallback::KIND.admit)(0xb822, &p)
    {
        return TestResult::Fail("N2xF chip/payload bounds differ");
    }
    p[5] = 1;
    if fallback::bounds(&p) {
        return TestResult::Fail("nonzero N2xF tail admitted");
    }
    let fixed = DataProfile {
        qos: true,
        ..DataProfile::LEGACY
    };
    let ra = DataProfile {
        fallback: true,
        ..fixed
    };
    for (profile, frame, bits) in [
        (fixed, data(true), FIXED),
        (ra, data(true), 0),
        (
            DataProfile {
                fallback: true,
                ..DataProfile::LEGACY
            },
            data(false),
            0,
        ),
    ] {
        match packet_format::transmit_profile(&frame, ht::OWN, 0, None, profile) {
            Ok((d, _)) if d[13] & FIXED == bits => {}
            _ => return TestResult::Fail("DATA W3 USE_RATE/DISDATAFB differ from tx.c"),
        }
    }
    // A Probe Request (management) keeps the fixed rate under fallback.
    let mut probe = vec![0x40, 0, 0, 0];
    probe.extend_from_slice(&[255; 6]);
    probe.extend_from_slice(&ht::OWN);
    probe.extend_from_slice(&[255; 6]);
    probe.extend_from_slice(&[0x10, 0, 0, 0]);
    match packet_format::transmit_profile(&probe, ht::OWN, 0, None, ra) {
        Ok((d, _)) if d[13] & FIXED == FIXED => {}
        _ => return TestResult::Fail("management frame lost the fixed rate"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/narrow/fallback",
    smoke_rtw88_fallback_payload_bounds_and_descriptor_bits
);
