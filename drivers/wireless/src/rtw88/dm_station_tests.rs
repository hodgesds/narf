// SPDX-License-Identifier: GPL-2.0-or-later
//! Composed dm watchdog cases through the actual retained C21/C22 station.
//! The N2xD records are private inert fixture inputs, not measured assets.
use super::ht_tests::{self as ht, Fixture};
use alloc::{vec, vec::Vec};
use narf_capabilities::Cap;
use narf_net::Interface;

pub(super) fn record<F: Fixture>(f: &F, enabled: u16) -> Result<Vec<u8>, &'static str> {
    let r = f
        .dm_request()
        .map_err(|_| "dm request over the exact base")?;
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(if F::c21() { b"N21D" } else { b"N22D" });
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[b'D', 1]);
    b[56..58].copy_from_slice(&enabled.to_le_bytes());
    b[58] = 0x40;
    b[59] = 4;
    b[63] = 0;
    b[64] = 63;
    Ok(b)
}
fn igi<F: Fixture>(f: &F) -> u32 {
    f.register(if F::c21() { 0xc50 } else { 0x1d70 }) & 0x7f
}
fn tracking<F: Fixture>(f: &F) -> Option<(u64, u8)> {
    let storage = f.device().lifecycle.retained.try_lock()?;
    let s = storage.as_ref()?.station_tracking()?;
    Some((s.tracking_ticks(), s.tracker().map_or(0, |t| t.igi())))
}
const MECHANISMS: u16 = super::dm::DIG | super::dm::CCK_PD | super::dm::RA;

pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let cap = Cap::bootstrap();
    f.stage_dm(record(&f, MECHANISMS)?, cap, true)
        .map_err(|_| "distinct synthetic N2xD qualification")?;
    ht::join(&f)?;
    let base = igi(&f);
    if tracking(&f).map(|t| t.0) != Some(0) {
        return Err("N2xD continuation not bound at association");
    }
    f.advance_ms(2000);
    if !ht::run(f.device().watchdog())? {
        return Err("qualified watchdog period did not run");
    }
    let (ticks, tracked) = tracking(&f).ok_or("tracking dropped after one period")?;
    if ticks != 1 || u32::from(tracked) != igi(&f) || !f.device().link_up() {
        return Err("watchdog IGI/readback/link mismatch");
    }
    if !F::c21() && igi(&f) < 0x20 {
        return Err("C22 linked DIG left the source lower boundary");
    }
    // Rate limited to the source 2s period.
    if ht::run(f.device().watchdog())? {
        return Err("watchdog ran inside the 2s period");
    }
    // Revoking the continuation restores the base program under the base gate.
    cap.revoke();
    f.advance_ms(2000);
    if ht::run(f.device().watchdog())? || tracking(&f).is_some() {
        return Err("revoked N2xD kept tracking");
    }
    if igi(&f) != base || !f.device().link_up() {
        return Err("revoked tracking did not restore the base IGI");
    }
    f.advance_ms(2000);
    if ht::run(f.device().watchdog())? {
        return Err("tracking resumed without a current continuation");
    }
    Ok(())
}

pub(super) fn refusals<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let good = record(&f, MECHANISMS)?;
    if f.stage_dm(good.clone(), Cap::bootstrap(), false).is_ok() {
        return Err("unsigned N2xD admitted");
    }
    let mut cases = Vec::new();
    let mut tag = good.clone();
    tag[3] = b'X';
    cases.push(tag);
    let mut id = good.clone();
    id[20] ^= 1;
    cases.push(id);
    let mut mac = good.clone();
    mac[48] ^= 2;
    cases.push(mac);
    let mut kind = good.clone();
    kind[54] = b'E';
    cases.push(kind);
    let mut tail = good.clone();
    tail[127] = 1;
    cases.push(tail);
    // C21 may not enable C22-only CFO; C22 may not enable reserved bit7.
    cases.push(record(
        &f,
        if F::c21() {
            MECHANISMS | super::dm::CFO
        } else {
            MECHANISMS | 1 << 7
        },
    )?);
    for b in cases {
        if f.stage_dm(b, Cap::bootstrap(), true).is_ok() {
            return Err("altered/foreign N2xD admitted");
        }
    }
    let revoked = Cap::bootstrap();
    revoked.revoke();
    if f.stage_dm(good, revoked, true).is_ok() {
        return Err("revoked N2xD source admitted");
    }
    // Without a continuation the station never runs the watchdog.
    ht::join(&f)?;
    let base = igi(&f);
    f.advance_ms(4000);
    if ht::run(f.device().watchdog())? || igi(&f) != base || tracking(&f).is_some() {
        return Err("unqualified station ran dynamic mechanisms");
    }
    Ok(())
}

/// `ht_protection_modes`: upstream reads no `ht_operation_mode`, so an AP
/// advertising each nonzero HT protection mode is joined unchanged.
pub(super) fn protection_modes<F: Fixture>(mode: u8) -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let mut elements = ht::elements(true);
    // HT Operation body follows 28 HT Capabilities bytes + 2 header; byte2 bits1:0.
    elements[30 + 2] = mode;
    let beacon = {
        let p = f.peer().lock();
        let mut b = p.ap.beacon();
        b.extend_from_slice(p.wmm.as_ref().ok_or("fixture WMM")?);
        b.extend_from_slice(&elements);
        b
    };
    f.peer().lock().ht = Some(elements);
    f.inject(&beacon, 0, 0);
    ht::join(&f)?;
    if !f.device().link_up() {
        return Err("HT protection-mode AP refused");
    }
    Ok(())
}
