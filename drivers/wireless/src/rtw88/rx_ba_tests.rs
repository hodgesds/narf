//! Authored on-air BA conversations through both retained native packet owners.
use super::ht_tests::{self as ht, Fixture, AP, OWN};
use alloc::{vec, vec::Vec};
use core::sync::atomic::Ordering;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_net::{Interface, TxMeta};
use narf_wireless::WirelessNetIface;

pub(super) fn record<F: Fixture>(f: &F) -> Result<Vec<u8>, &'static str> {
    let r = f
        .ba_request()
        .map_err(|_| "exact H recipient BA metadata")?;
    let mut b = vec![0; 128];
    b[..4].copy_from_slice(if F::c21() { b"N21R" } else { b"N22R" });
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&OWN);
    b[54..56].copy_from_slice(&[1, 20]);
    for at in [60, 62, 64] {
        b[at..at + 2].copy_from_slice(&8i16.to_le_bytes());
    }
    b[58..60].copy_from_slice(&80i16.to_le_bytes());
    b[67] = 63;
    b[68] = 64;
    b[69] = 255;
    Ok(b)
}
fn fixture<F: Fixture>(protected: bool) -> Result<(F, Cap<FirmwareBlob, Read>), &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let cap = Cap::bootstrap();
    f.stage_ba(record(&f)?, cap)
        .map_err(|_| "distinct synthetic RX BA record")?;
    ht::join(&f)?;
    Ok((f, cap))
}
fn request(tid: u8, dialog: u8, ssn: u16, window: u16, timeout: u16) -> Vec<u8> {
    let mut b = vec![0xd0, 0, 0, 0];
    b.extend_from_slice(&OWN);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&[0, 0, 3, 0, dialog]);
    b.extend_from_slice(&(3 | u16::from(tid) << 2 | window << 6).to_le_bytes());
    b.extend_from_slice(&timeout.to_le_bytes());
    b.extend_from_slice(&(ssn << 4).to_le_bytes());
    b
}
pub(super) fn agreement<F: Fixture>(
    f: &F,
    tid: u8,
    dialog: u8,
    ssn: u16,
    window: u16,
    timeout: u16,
) -> Result<(), &'static str> {
    f.inject(&request(tid, dialog, ssn, window, timeout), 0, 0);
    f.pump();
    let p = f.peer().lock();
    let b = p
        .ba_controls
        .last()
        .ok_or("native success not transmitted")?;
    let expected = 3 | u16::from(tid) << 2 | if window == 0 { 64 } else { window } << 6;
    if b.len() != 33
        || b[24..29] != [3, 1, dialog, 0, 0]
        || b[29..31] != expected.to_le_bytes()
        || b[31..33] != timeout.to_le_bytes()
    {
        return Err("literal success response/parameter binding");
    }
    Ok(())
}
fn ethernet(label: u8) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        OWN,
        AP,
        [10, 88, 1, 1],
        [10, 88, 1, 42],
        7,
        49152,
        &[label; 24],
    )
}
fn raw<F: Fixture>(f: &F, label: u8) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let ethernet = ethernet(label);
    let raw = f.peer().lock().downlink(&ethernet)?;
    Ok((ethernet, raw))
}
fn bar(tid: u8, ssn: u16) -> Vec<u8> {
    let mut b = vec![0x84, 0, 0, 0];
    b.extend_from_slice(&OWN);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&(4 | u16::from(tid) << 12).to_le_bytes());
    b.extend_from_slice(&(ssn << 4).to_le_bytes());
    b
}
fn delba(tid: u8, initiator: bool) -> Vec<u8> {
    let mut b = vec![0xd0, 0, 0, 0];
    b.extend_from_slice(&OWN);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&[0, 0, 3, 2]);
    b.extend_from_slice(&(u16::from(tid) << 12 | u16::from(initiator) << 11).to_le_bytes());
    b.extend_from_slice(&39u16.to_le_bytes());
    b
}
pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    let (f, _) = fixture::<F>(protected)?;
    let retained = f.retained();
    agreement(&f, 0, 7, 0, 64, 0)?;
    f.peer().lock().reorder_downlink = true;
    let lease = narf_net::dhcp::dhcp_acquire(f.device().name(), 0)
        .map_err(|_| "RX BA reordered real DHCP")?;
    if !f.peer().lock().plan.matches_lease(&lease) {
        return Err("RX BA DHCP lease binding");
    }
    let _ = f.received();
    let (first, a) = raw(&f, 11)?;
    let (second, b) = raw(&f, 12)?;
    f.inject(&b, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("future MPDU bypassed explicit SSN/reorder");
    }
    f.inject(&a, 19, 0);
    f.pump();
    if f.received() != vec![first, second] {
        return Err("original MPDUs not ordered before per-TID CCMP/PN");
    }
    let up = narf_wifi_fixtures::udp_ipv4(
        AP,
        OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        b"recipient BA leaves TX standalone",
    );
    f.device()
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "RX BA standalone TX enqueue")?;
    f.pump();
    let d = f.descriptor().ok_or("RX BA native DATA descriptor")?;
    if f.peer().lock().uplink.last() != Some(&up)
        || u32::from_le_bytes(d[8..12].try_into().unwrap()) & (1 << 12) != 0
        || u32::from_le_bytes(d[12..16].try_into().unwrap()) & (31 << 17) != 0
        || !f.device().link_up()
        || f.retained() != retained
    {
        return Err("RX BA widened TX aggregation or retired native owner");
    }
    Ok(())
}
pub(super) fn windows_bar_timers<F: Fixture>() -> Result<(), &'static str> {
    for window in [1, 3, 64, 0] {
        let (f, _) = fixture::<F>(true)?;
        f.peer().lock().data_sequence = 4094;
        agreement(&f, 0, 8, 4095, window, 0)?;
        let (preceding, p) = raw(&f, 20)?;
        f.inject(&p, 19, 0);
        f.pump();
        if f.received() != vec![preceding] {
            return Err("source pre-start/pre-SSN original semantics");
        }
        let (first, a) = raw(&f, 21)?;
        let (second, b) = raw(&f, 22)?;
        if window != 1 {
            f.inject(&b, 19, 0);
            f.pump();
            if !f.received().is_empty() {
                return Err("wrap future before SSN");
            }
        }
        f.inject(&a, 19, 0);
        f.pump();
        if window == 1 {
            f.inject(&b, 19, 0);
            f.pump();
        }
        if f.received() != vec![first, second] {
            return Err("explicit SSN4095 wrap/window");
        }
        f.peer().lock().data_sequence = 3;
        let (held, c) = raw(&f, 23)?;
        f.inject(&c, 19, 0);
        f.pump();
        if window == 1 {
            if f.received() != vec![held] {
                return Err("window1 advance");
            }
            continue;
        }
        if !f.received().is_empty() {
            return Err("hole not held");
        }
        let mut foreign = bar(0, 3);
        foreign[10] ^= 2;
        f.inject(&foreign, 0, 0);
        f.pump();
        if !f.received().is_empty() {
            return Err("foreign BAR advanced");
        }
        f.inject(&bar(0, 3), 0, 0);
        f.pump();
        if f.received() != vec![held] {
            return Err("genuine20-byte BAR failed native ingress");
        }
        f.peer().lock().data_sequence = 6;
        let (expired, d) = raw(&f, 24)?;
        f.inject(&d, 19, 0);
        f.pump();
        f.advance_ms(99);
        f.pump();
        if !f.received().is_empty() {
            return Err("hole expired before100ms");
        }
        f.advance_ms(1);
        f.pump();
        if f.received() != vec![expired] {
            return Err("RX-idle did not drive100ms hole");
        }
    }
    let (f, _) = fixture::<F>(false)?;
    agreement(&f, 0, 9, 0, 8, 1)?;
    f.peer().lock().data_sequence = 1;
    let (_, b) = raw(&f, 25)?;
    f.inject(&b, 19, 0);
    f.pump();
    f.advance_ms(2);
    f.pump();
    if !f.received().is_empty()
        || f.peer()
            .lock()
            .ba_controls
            .last()
            .is_none_or(|b| b.len() != 30 || b[24..30] != [3, 2, 0, 0, 39, 0])
        || !f.device().link_up()
    {
        return Err("TU inactivity did not retire before native recipient DELBA");
    }
    Ok(())
}
pub(super) fn original_amsdu<F: Fixture>() -> Result<(), &'static str> {
    let (f, _) = fixture::<F>(true)?;
    agreement(&f, 7, 1, 0, 64, 0)?;
    let mut expected = Vec::new();
    for (i, len) in [1514, 1514, 783].into_iter().enumerate() {
        let mut e = vec![i as u8; len];
        e[..6].copy_from_slice(&OWN);
        e[6..12].copy_from_slice(&AP);
        e[12..14].copy_from_slice(&[8, 0]);
        expected.push(e);
    }
    let first = ht::aggregate(&f, &expected, 1, 7)?;
    let mut wide = [0; 32];
    wide[0] = 1;
    wide[4..8].copy_from_slice(&(9u32 << 12 | 1 << 16).to_le_bytes());
    f.inject_status(&first, &wide, 4, true, 2);
    f.pump();
    if !f.received().is_empty() {
        return Err("wide PHY reached BA reorder/CCMP");
    }
    f.inject(&first, 19, 0);
    f.pump();
    if f.received() != expected {
        return Err("bad PHY consumed BA SSN or PN before valid original retry");
    }
    let a = ht::aggregate_sequence(&f, &expected, 2, 7, 1)?;
    let mut bad = a.clone();
    *bad.last_mut().unwrap() ^= 1;
    f.inject(&bad, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("RX BA MIC failure leaked A-MSDU prefix");
    }
    // Fresh on-air dialog/SSN retires ordering, never the real PTK replay owner.
    agreement(&f, 7, 2, 1, 64, 0)?;
    f.inject(&a, 19, 0);
    f.pump();
    if f.received() != expected {
        return Err("original3839 A-MSDU same PN after bad MIC");
    }
    agreement(&f, 7, 3, 1, 64, 0)?;
    f.inject(&a, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("fresh BA dialog reset per-TID PN");
    }
    let block_ack = ht::aggregate_block_ack(&f, &expected, 3, 7, 2)?;
    f.inject(&block_ack, 19, 0);
    f.pump();
    if f.received() != expected {
        return Err("live ordered BlockAck A-MSDU original was normalized or refused");
    }
    f.inject(&delba(7, true), 0, 0);
    f.pump();
    let retired = ht::aggregate_block_ack(&f, &expected, 4, 7, 3)?;
    f.inject(&retired, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("BlockAck aggregate admitted without a live recipient agreement");
    }
    let standalone = ht::aggregate_sequence(&f, &expected, 4, 7, 3)?;
    f.inject(&standalone, 19, 0);
    f.pump();
    if f.received() != expected {
        return Err("retired BA consumed PN or lost standalone normal-ACK aggregate");
    }
    // Independent TID0 can still accept PN1 after TID7 consumed its PN1.
    agreement(&f, 0, 4, 0, 64, 0)?;
    let (e, b) = raw(&f, 31)?;
    f.inject(&b, 19, 0);
    f.pump();
    if f.received() != vec![e] {
        return Err("RX BA mixed per-TID replay owners");
    }
    let mut oversized = vec![0; 2400];
    oversized[..6].copy_from_slice(&OWN);
    oversized[6..12].copy_from_slice(&AP);
    oversized[12..14].copy_from_slice(&[8, 0]);
    let invalid = f.peer().lock().downlink(&oversized)?;
    f.inject(&invalid, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("oversized non-A-MSDU reached BA/crypto");
    }
    {
        let mut p = f.peer().lock();
        p.pn = 2;
        p.data_sequence = 1;
    }
    let (retry, b) = raw(&f, 32)?;
    f.inject(&b, 19, 0);
    f.pump();
    if f.received() != vec![retry] {
        return Err("invalid ordinary shape consumed BA SSN or CCMP PN");
    }
    // Many short subframes in a legal default-size original must not trip the
    // ordinary64-frame output batching limit after authentication commits PN.
    agreement(&f, 6, 5, 0, 64, 0)?;
    let mut tiny = OWN.to_vec();
    tiny.extend_from_slice(&AP);
    tiny.extend_from_slice(&[0x88, 0xb5]);
    let tiny = vec![tiny; 160];
    let original = ht::aggregate(&f, &tiny, 1, 6)?;
    f.inject(&original, 19, 0);
    let mut output = Vec::new();
    for _ in 0..4 {
        let mut retained = f
            .device()
            .lifecycle
            .retained
            .try_lock()
            .ok_or("short-subframe owner lock")?;
        output.extend(
            retained
                .as_mut()
                .ok_or("short-subframe native owner")?
                .station_poll()
                .map_err(|_| "short-subframe native receive")?,
        );
    }
    if output != tiny {
        return Err("whole default-size160-subframe original was partially admitted");
    }
    Ok(())
}
pub(super) fn receipt_and_delba<F: Fixture>() -> Result<(), &'static str> {
    for retire in [false, true] {
        let (f, _) = fixture::<F>(true)?;
        let retained = f.retained();
        f.peer().lock().hold_decline = true;
        f.inject(&request(0, 3, 0, 64, 0), 0, 0);
        f.pump();
        if !f.controls().held.load(Ordering::Acquire) {
            return Err("actual success DMA not held");
        }
        let (early, b) = raw(&f, 41)?;
        let (second, c) = raw(&f, 40)?;
        f.inject(&c, 19, 0);
        f.inject(&b, 19, 0);
        f.pump();
        if !f.received().is_empty() {
            return Err("pre-CCX BA data delivered");
        }
        if retire {
            f.inject(&delba(0, true), 0, 0);
            f.pump();
        }
        f.controls().release.store(true, Ordering::Release);
        f.peer().lock().hold_decline = false;
        f.pump();
        if retire {
            if !f.received().is_empty() {
                return Err("cancelled published proposal retained its opaque prefix");
            }
            f.peer().lock().data_sequence = 2;
            let (e, c) = raw(&f, 42)?;
            f.inject(&c, 19, 0);
            f.pump();
            if f.received() != vec![e] {
                return Err("peer DELBA failed to cancel held proposal");
            }
        } else {
            if f.received() != vec![early, second] {
                return Err(
                    "published proposal prefix did not reorder/authenticate after exact CCX+idle",
                );
            }
            f.inject(&b, 19, 0);
            f.pump();
            if !f.received().is_empty() {
                return Err("staged prefix replay was delivered twice");
            }
            f.peer().lock().hold_decline = true;
            f.inject(&request(0, 3, 0, 64, 0), 0, 0);
            f.pump();
            let (expected, next) = raw(&f, 44)?;
            f.inject(&next, 19, 0);
            f.pump();
            if !f.received().is_empty() {
                return Err("duplicate response escaped actual held native receipt");
            }
            f.peer().lock().hold_decline = false;
            f.controls().release.store(true, Ordering::Release);
            f.pump();
            if f.received() != vec![expected] {
                return Err(
                    "identical retry discarded the committed window or reset its actual head",
                );
            }
        }
        if !f.device().link_up() || f.retained() != retained {
            return Err("held BA response released native allocation");
        }
    }
    Ok(())
}
pub(super) fn delba_before_submit<F: Fixture>() -> Result<(), &'static str> {
    let (f, _) = fixture::<F>(true)?;
    let retained = f.retained();
    let (before, original) = raw(&f, 43)?;
    f.peer().lock().hold_decline = true;
    f.inject(&request(0, 18, 0, 64, 0), 0, 0);
    f.inject(&original, 19, 0);
    f.pump();
    f.controls().release.store(true, Ordering::Release);
    f.peer().lock().hold_decline = false;
    f.pump();
    if !f.received().is_empty() {
        return Err("pre-proposal original gained retrospective BA authority");
    }
    f.inject(&original, 19, 0);
    f.pump();
    if f.received() != vec![before] {
        return Err("pre-proposal discard consumed PN or sequence");
    }
    // Both originals are consumed in one real native RX batch. The DELBA
    // cancels the not-yet-proposed request, not merely a Table flag.
    f.inject(&request(1, 20, 0, 64, 0), 0, 0);
    f.inject(&delba(1, true), 0, 0);
    f.pump();
    if f.peer().lock().ba_controls.len() != 1 {
        return Err("same-batch DELBA emitted stale success");
    }
    // A second accepted TID can queue behind a genuinely held first CCX.
    f.peer().lock().hold_decline = true;
    f.inject(&request(0, 21, 0, 64, 0), 0, 0);
    f.inject(&request(1, 22, 0, 64, 0), 0, 0);
    f.pump();
    if !f.controls().held.load(Ordering::Acquire) || f.peer().lock().ba_controls.len() != 2 {
        return Err("native first response was not held before queued second response");
    }
    f.inject(&delba(1, true), 0, 0);
    f.pump();
    f.controls().release.store(true, Ordering::Release);
    f.peer().lock().hold_decline = false;
    f.pump();
    if f.peer().lock().ba_controls.len() != 2 || f.retained() != retained || !f.device().link_up() {
        return Err("DELBA left an unsent positive control queued or released DMA");
    }
    agreement(&f, 1, 23, 0, 64, 0)?;
    Ok(())
}
pub(super) fn assets_and_fallback<F: Fixture>() -> Result<(), &'static str> {
    for fault in 0..7 {
        let f = F::make(false, 255, true, true)?;
        let mut b = record(&f)?;
        let cap = Cap::bootstrap();
        match fault {
            0 => b[0] ^= 1,
            1 => b[16] ^= 1,
            2 => b[48] ^= 1,
            3 => b[68] = 65,
            4 => b[69] = 0,
            5 => b[70] = 1,
            _ => b[62..64].copy_from_slice(&120i16.to_le_bytes()),
        }
        if f.stage_ba(b, cap).is_ok() {
            return Err("mismatched or unbounded BA asset accepted");
        }
        f.stage_ba(record(&f)?, cap)
            .map_err(|_| "missing/malformed RX BA asset was not retryable")?;
    }
    let f = F::make(false, 255, true, true)?;
    ht::join(&f)?;
    f.inject(&request(0, 1, 0, 64, 0), 0, 0);
    f.pump();
    let declined = {
        let p = f.peer().lock();
        p.declines.len() == 1 && p.ba_controls.is_empty()
    };
    if !declined || !f.device().link_up() {
        return Err("H without R stopped declining or closed legacy HT");
    }
    drop(f);
    let f = F::make(false, 255, true, true)?;
    let mut limited = record(&f)?;
    limited[68] = 3;
    limited[69] = 1;
    f.stage_ba(limited, Cap::bootstrap())
        .map_err(|_| "bounded recipient record")?;
    ht::join(&f)?;
    f.inject(&request(0, 11, 0, 64, 0), 0, 0);
    f.pump();
    let narrowed = f
        .peer()
        .lock()
        .ba_controls
        .last()
        .cloned()
        .ok_or("bounded native response")?;
    if narrowed[29..31] != [0xc3, 0] {
        return Err("signed maximum did not narrow actual response window");
    }
    f.inject(&request(7, 12, 0, 64, 0), 0, 0);
    f.pump();
    let mut no_amsdu = request(0, 13, 0, 64, 0);
    no_amsdu[27] &= !1;
    f.inject(&no_amsdu, 0, 0);
    f.pump();
    // Process each request with its own management receipt, not a model ACK.
    f.pump();
    if f.peer().lock().ba_controls.len() != 1 {
        return Err("R allowed an excluded TID or absent peer A-MSDU permission");
    }
    let mut expected = Vec::new();
    for size in [1514, 1514, 783] {
        let mut e = vec![0; size];
        e[..6].copy_from_slice(&OWN);
        e[6..12].copy_from_slice(&AP);
        e[12..14].copy_from_slice(&[8, 0]);
        expected.push(e);
    }
    let standalone = ht::aggregate(&f, &expected, 1, 7)?;
    f.inject(&standalone, 19, 0);
    f.pump();
    if f.received() != expected || !f.device().link_up() {
        return Err("declined recipient profile lost standalone3839 A-MSDU");
    }
    Ok(())
}
pub(super) fn authority_and_uncertainty<F: Fixture>() -> Result<(), &'static str> {
    for point in 0..16 {
        let (f, cap) = fixture::<F>(true)?;
        let sources = f.sources();
        if point >= sources.len() + 4 {
            break;
        }
        let retained = f.retained();
        f.peer().lock().hold_decline = true;
        f.inject(&request(0, 4, 0, 64, 0), 0, 0);
        f.pump();
        if !f.controls().held.load(Ordering::Acquire) {
            return Err("BA uncertainty did not reach actual held33-byte response");
        }
        let (_, prefix) = raw(&f, 61)?;
        f.inject(&prefix, 19, 0);
        f.pump();
        if !f.received().is_empty() {
            return Err("unacknowledged proposal prefix authenticated early");
        }
        if point < sources.len() {
            sources[point].revoke();
        } else {
            match point - sources.len() {
                0 => cap.revoke(),
                1 => f.clear_policy(),
                2 => f.controls().corrupt_receipt.store(true, Ordering::Release),
                _ => f.device().admission().close(),
            }
        }
        f.controls().release.store(true, Ordering::Release);
        f.pump();
        f.install_policy();
        f.pump();
        if !f.device().closed() {
            return Err(if point == sources.len() + 2 {
                "corrupt native33-byte response retained BA admission"
            } else {
                "revoked/cancelled native BA owner reopened"
            });
        }
        if !f.received().is_empty() {
            return Err("uncertain BA published its unacknowledged original prefix");
        }
        if f.retained() != retained {
            return Err("uncertain/revoked/cancelled BA released retained native DMA");
        }
    }
    Ok(())
}
pub(super) fn key_epoch<F: Fixture>() -> Result<(), &'static str> {
    let (f, _) = fixture::<F>(true)?;
    agreement(&f, 0, 5, 0, 64, 0)?;
    f.peer().lock().data_sequence = 1;
    let (_, held) = raw(&f, 51)?;
    f.inject(&held, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("old original not staged behind hole");
    }
    // Build genuine non-QoS EAPOL with the installed old PTK. The negotiated
    // QoS peer stays unchanged; a private key exchange need not occupy TID0.
    f.peer().lock().qos = false;
    let group = ht::group_rekey(&f)?;
    f.peer().lock().qos = true;
    f.inject(&group, 19, 0);
    f.peer().lock().hold_data = true;
    f.pump();
    if !f.received().is_empty() {
        return Err("buffered old BA data escaped during group reply");
    }
    if !f.controls().held.load(Ordering::Acquire) {
        return Err("real group reply not held");
    }
    f.controls().release.store(true, Ordering::Release);
    f.peer().lock().hold_data = false;
    f.pump();
    f.advance_ms(101);
    f.pump();
    if !f.received().is_empty() || !f.device().link_up() {
        return Err("old BA buffer survived key/reply epoch");
    }
    // Old agreement is gone: no old BAR may manufacture a new session.
    f.inject(&bar(0, 0), 0, 0);
    f.pump();
    Ok(())
}
pub(super) fn pre_m4_denial<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(true, 255, true, true)?;
    let cap = Cap::bootstrap();
    f.stage_ba(record(&f)?, cap)
        .map_err(|_| "pre-M4 R qualification")?;
    f.peer().lock().hold_m4 = true;
    let retained = f.retained();
    let controls = f.controls();
    ht::scan(&f)?;
    let mut future = alloc::boxed::Box::pin(f.device().associate(ht::request(&f)));
    let mut cx = Context::from_waker(Waker::noop());
    let mut reached = false;
    for _ in 0..16384 {
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("R join skipped genuine held M4");
        }
        if controls.held.load(Ordering::Acquire) {
            reached = true;
            break;
        }
    }
    if !reached || f.device().link_up() {
        return Err("pre-M4 R closed port not reached");
    }
    let expected = ethernet(71);
    let original = ht::aggregate(&f, core::slice::from_ref(&expected), 1, 0)?;
    controls
        .incoming_profiles
        .lock()
        .push_back((request(0, 24, 0, 64, 0), 0, 0));
    controls
        .incoming_profiles
        .lock()
        .push_back((original.clone(), 19, 0));
    for _ in 0..4 {
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("M4 opened without held native receipt");
        }
    }
    controls.release.store(true, Ordering::Release);
    f.peer().lock().hold_m4 = false;
    let mut completed = false;
    for _ in 0..16384 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            result.map_err(|_| "R join after real M4 receipt")?;
            completed = true;
            break;
        }
    }
    drop(future);
    if !completed
        || !f.device().link_up()
        || f.retained() != retained
        || !f.received().is_empty()
        || !f.peer().lock().ba_controls.is_empty()
    {
        return Err("pre-M4 request/data acquired retrospective R authority");
    }
    agreement(&f, 0, 25, 0, 64, 0)?;
    f.inject(&original, 19, 0);
    f.pump();
    if f.received() != vec![expected] {
        return Err("pre-M4 denial consumed original PN or SSN");
    }
    Ok(())
}
