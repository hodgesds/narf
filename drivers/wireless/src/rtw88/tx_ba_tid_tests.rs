// SPDX-License-Identifier: GPL-2.0-or-later
//! Real retained C21/C22 DATA/control/DMA compositions. Synthetic signed
//! records below describe model measurements, never physical board assets.
use super::ht_tests::{self as ht, Fixture, AP, OWN};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::Ordering;
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_net::{Interface, TxMeta};

fn record<F: Fixture>(f: &F) -> Result<Vec<u8>, &'static str> {
    let request = f.tx_request().map_err(|_| "T2 actual H/R request")?;
    let mut bytes = super::tx_ba_tests::record(f)?;
    bytes[4] = 2;
    bytes[16..48].copy_from_slice(&request.all_tids_identity);
    bytes[108..110].copy_from_slice(&[0x3f, 3]);
    Ok(bytes)
}
type Prepared<F> = (F, Cap<FirmwareBlob, Read>, Cap<FirmwareBlob, Read>);
fn setup<F: Fixture>(protected: bool, all: bool) -> Result<Prepared<F>, &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let q = Cap::bootstrap();
    f.stage_kind(&super::qos::KIND, super::qos_tests::record(&f, 7)?, q, true)
        .map_err(|_| "T2 current all-AC Q source")?;
    f.stage_ba(super::rx_ba_tests::record(&f)?, Cap::bootstrap())
        .map_err(|_| "T2 exact retained recipient R")?;
    {
        let mut peer = f.peer().lock();
        peer.any_tid = true;
        peer.tx_ba_window = Some(64);
    }
    let t = Cap::bootstrap();
    let bytes = if all {
        record(&f)?
    } else {
        super::tx_ba_tests::record(&f)?
    };
    f.stage_tx(bytes, t)
        .map_err(|_| "T2 distinct signed source")?;
    ht::join(&f)?;
    Ok((f, q, t))
}
/// Literal MPLS TC selects every TID, including RFC8325's otherwise
/// downgraded IPv4 CS2. These are ordinary native Ethernet DATA originals.
fn frame(tid: u8, label: u8) -> Vec<u8> {
    let mut bytes = AP.to_vec();
    bytes.extend_from_slice(&OWN);
    bytes.extend_from_slice(&[0x88, 0x47, 0, 0, tid << 1 | 1, 64]);
    bytes.extend_from_slice(&[label; 32]);
    bytes
}
fn send<F: Fixture>(f: &F, bytes: &[u8]) -> Result<(), &'static str> {
    f.device()
        .enqueue(bytes, TxMeta::default())
        .map_err(|_| "T2 real public enqueue")
}
fn warm<F: Fixture>(f: &F, tid: u8) -> Result<(), &'static str> {
    send(f, &frame(tid, 0xf0 | tid))?;
    f.pump();
    f.pump();
    if !f.device().link_up() {
        return Err("T2 demand/actual native dialog closed port");
    }
    Ok(())
}
fn aggregated(descriptor: &[u8; 48]) -> bool {
    u32::from_le_bytes(descriptor[8..12].try_into().unwrap()) & (1 << 12) != 0
}
fn data_descriptors<F: Fixture>(f: &F, start: usize) -> Vec<[u8; 48]> {
    f.descriptors()[start..]
        .iter()
        .filter(|d| d[5] & 31 < 8)
        .copied()
        .collect()
}
fn monotone<F: Fixture>(f: &F, protected: bool) -> Result<(), &'static str> {
    let log = { f.peer().lock().tx_sequences.clone() };
    let mut sequences = [None; 8];
    let mut previous_pn = None;
    for (tid, sequence, pn) in log {
        if sequences[usize::from(tid)].is_some_and(|old| sequence != ((old + 1) & 4095)) {
            return Err("T2 mixed prefix consumed/reused another TID sequence");
        }
        sequences[usize::from(tid)] = Some(sequence);
        if protected && previous_pn.is_some_and(|old| pn != old + 1) {
            return Err("T2 unsent suffix consumed/reused a native packet-key PN");
        }
        previous_pn = Some(pn);
    }
    Ok(())
}
pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    let (f, _, _) = setup::<F>(protected, true)?;
    let retained = f.retained();
    let lease =
        narf_net::dhcp::dhcp_acquire(f.device().name(), 0).map_err(|_| "T2 real kernel DHCP")?;
    if !f.peer().lock().plan.matches_lease(&lease) {
        return Err("T2 native DHCP exact lease");
    }
    for tid in 0..8 {
        warm(&f, tid)?;
        let before = f.peer().lock().uplink.len();
        let descriptors = f.descriptors().len();
        let controls = f.controls();
        let doorbells = controls.tx_doorbells.lock().len();
        let expected = (0..4).map(|i| frame(tid, tid * 8 + i)).collect::<Vec<_>>();
        for bytes in &expected {
            send(&f, bytes)?;
        }
        f.pump();
        f.pump();
        let delivered = { f.peer().lock().uplink[before..] == expected };
        let actual = data_descriptors(&f, descriptors);
        if !delivered
            || actual.len() != 4
            || actual
                .iter()
                .any(|d| d[5] & 31 != tid || aggregated(d) != (tid < 6))
        {
            return Err("T2 actual four originals/TID/QSEL/AGGEN/VO exclusion");
        }
        let ring = match tid {
            1 | 2 => 0x3ac,
            4 | 5 => 0x3a4,
            6 | 7 => 0x3a0,
            _ => 0x3a8,
        };
        let data = controls.tx_doorbells.lock()[doorbells..]
            .iter()
            .filter(|(r, _)| *r != 0x3b0)
            .map(|(r, _)| *r)
            .collect::<Vec<_>>();
        if data.iter().any(|&r| r != ring) || data.len() != if tid < 6 { 1 } else { 4 } {
            return Err("T2 native physical ring or one-WP burst differs");
        }
    }
    let requests = {
        f.peer()
            .lock()
            .tx_ba_controls
            .iter()
            .filter(|b| b.len() == 33 && b[25] == 0)
            .cloned()
            .collect::<Vec<_>>()
    };
    let tids = requests
        .iter()
        .map(|b| (u16::from_le_bytes([b[27], b[28]]) >> 2) & 15)
        .collect::<Vec<_>>();
    let tokens = requests.iter().map(|b| b[26]).collect::<Vec<_>>();
    if tids != vec![0, 1, 2, 3, 4, 5]
        || tokens != vec![1, 2, 3, 4, 5, 6]
        || f.retained() != retained
        || !f.device().link_up()
    {
        return Err("T2 real independent peer dialogs or original DMA owner");
    }
    monotone(&f, protected)
}
pub(super) fn mixed_prefix<F: Fixture>() -> Result<(), &'static str> {
    let (f, _, _) = setup::<F>(true, true)?;
    warm(&f, 1)?;
    warm(&f, 5)?;
    let before = f.peer().lock().uplink.len();
    let controls = f.controls();
    let doorbells = controls.tx_doorbells.lock().len();
    let expected = [1, 1, 5, 5, 1, 6, 5]
        .into_iter()
        .enumerate()
        .map(|(i, tid)| frame(tid, i as u8))
        .collect::<Vec<_>>();
    for b in &expected {
        send(&f, b)?;
    }
    f.pump();
    f.pump();
    let delivered = { f.peer().lock().uplink[before..] == expected };
    let rings = controls.tx_doorbells.lock()[doorbells..]
        .iter()
        .filter(|(r, _)| *r != 0x3b0)
        .map(|(r, _)| *r)
        .collect::<Vec<_>>();
    if !delivered || rings != vec![0x3ac, 0x3a4, 0x3ac, 0x3a0, 0x3a4] {
        return Err("T2 public IPC mixed FIFO prefix was relabelled, skipped or reordered");
    }
    monotone(&f, true)
}
pub(super) fn v1_and_invalid<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let request = f.tx_request().map_err(|_| "T2 distinct metadata")?;
    if request.identity == request.all_tids_identity
        || request.filename == request.all_tids_filename
    {
        return Err("T2 borrowed v1 request identity/registry name");
    }
    for kind in 0..9 {
        let mut b = record(&f)?;
        match kind {
            0 => b[16..48].copy_from_slice(&request.identity),
            1 => b[108] = 0xff,
            2 => b[108] = 0x1f,
            3 => b[109] = 7,
            4 => b[110] = 1,
            5 => b[4] = 1,
            6 => b[69] = 62,
            7 => b[58..60].copy_from_slice(&0i16.to_le_bytes()),
            _ => b.truncate(191),
        }
        if f.stage_tx(b, Cap::bootstrap()).is_ok() {
            return Err("T2 malformed/narrow/all-VO envelope accepted");
        }
    }
    drop(f);
    let (f, _, _) = setup::<F>(true, false)?;
    for tid in [1, 3, 5, 6] {
        warm(&f, tid)?;
    }
    let start = f.descriptors().len();
    for tid in [0, 1, 3, 5, 6] {
        send(&f, &frame(tid, tid))?;
    }
    f.pump();
    f.pump();
    if data_descriptors(&f, start)
        .iter()
        .any(|d| aggregated(d) != (d[5] & 31 == 0))
        || f.peer()
            .lock()
            .tx_ba_controls
            .iter()
            .filter(|b| b.len() == 33 && b[25] == 0)
            .count()
            != 1
    {
        return Err("T2 silently widened the original v1 BE/TID0 permission");
    }
    monotone(&f, true)
}
pub(super) fn timeout_delba_and_key<F: Fixture>() -> Result<(), &'static str> {
    let (f, _, _) = setup::<F>(true, true)?;
    f.peer().lock().tx_ba_timeout = 1;
    warm(&f, 5)?;
    f.advance_ms(2);
    f.pump();
    let start = f.descriptors().len();
    send(&f, &frame(5, 1))?;
    send(&f, &frame(0, 2))?;
    f.pump();
    f.pump();
    let d = data_descriptors(&f, start);
    if d.len() != 2 || aggregated(&d[0]) || !aggregated(&d[1]) {
        return Err("T2 per-TID TU expiry damaged independent TID0 agreement");
    }
    // A genuine key exchange retires every old agreement, then reopens each
    // demanded TID using fresh globally unique tokens and the retained SSN.
    f.peer().lock().tx_ba_timeout = 0;
    f.peer().lock().qos = false;
    let group = ht::group_rekey(&f)?;
    f.peer().lock().qos = true;
    f.inject(&group, 19, 0);
    f.pump();
    f.advance_ms(101);
    f.pump();
    f.pump();
    let start = f.descriptors().len();
    send(&f, &frame(5, 3))?;
    send(&f, &frame(0, 4))?;
    f.pump();
    f.pump();
    let d = data_descriptors(&f, start);
    if d.len() != 2 || d.iter().any(|d| !aggregated(d)) {
        return Err("T2 actual terminal key receipt failed to restore independent agreements");
    }
    let mut delba = vec![0xd0, 0, 0, 0];
    delba.extend_from_slice(&OWN);
    delba.extend_from_slice(&AP);
    delba.extend_from_slice(&AP);
    delba.extend_from_slice(&[0, 0, 3, 2, 0, 0x50, 39, 0]);
    f.inject(&delba, 0, 0);
    f.pump();
    let start = f.descriptors().len();
    send(&f, &frame(5, 5))?;
    send(&f, &frame(0, 6))?;
    f.pump();
    f.pump();
    let d = data_descriptors(&f, start);
    if d.len() != 2 || aggregated(&d[0]) || !aggregated(&d[1]) || !f.device().link_up() {
        return Err("T2 actual recipient DELBA crossed TID/key ownership");
    }
    let tokens = {
        f.peer()
            .lock()
            .tx_ba_controls
            .iter()
            .filter(|b| b.len() == 33 && b[25] == 0)
            .map(|b| b[26])
            .collect::<Vec<_>>()
    };
    if tokens.windows(2).any(|w| w[0] >= w[1]) || tokens.len() < 4 {
        return Err("T2 key epoch reused a live dialog token");
    }
    monotone(&f, true)
}
pub(super) fn current_q_and_partial<F: Fixture>() -> Result<(), &'static str> {
    let (f, q, _) = setup::<F>(true, true)?;
    warm(&f, 5)?;
    q.revoke();
    let before = f.peer().lock().uplink.len();
    send(&f, &frame(5, 1))?;
    f.pump();
    f.pump();
    let (delivered, last_tid) = {
        let peer = f.peer().lock();
        (peer.uplink.len(), peer.tids.last().copied())
    };
    if !f.device().link_up() || delivered != before + 1 || last_tid != Some(0) {
        return Err("T2 revoked Q continued nonzero-TID routing or lost legitimate TID0 fallback");
    }
    drop(f);
    let (f, q, _) = setup::<F>(true, true)?;
    warm(&f, 5)?;
    let retained = f.retained();
    let before = f.peer().lock().uplink.len();
    let controls = f.controls();
    let doorbells = controls.tx_doorbells.lock().len();
    f.after_descriptor(Arc::new(move || {
        q.revoke();
    }));
    for i in 0..4 {
        send(&f, &frame(5, i))?;
    }
    f.pump();
    let writes = controls.tx_doorbells.lock()[doorbells..]
        .iter()
        .filter(|(r, _)| *r == 0x3a4)
        .count();
    if f.device().link_up()
        || f.retained() != retained
        || f.peer().lock().uplink.len() != before
        || writes != 0
    {
        return Err("T2 partial BD/current-Q loss published stale WP or released original DMA");
    }
    controls.release.store(true, Ordering::Release);
    f.pump();
    if f.device().link_up() {
        return Err("T2 late native completion resurrected revoked Q publication");
    }
    Ok(())
}

pub(super) fn wrong_tid_held_control<F: Fixture>() -> Result<(), &'static str> {
    let (f, _, _) = setup::<F>(true, true)?;
    // Token2 belongs to demanded TID4; a TID5 success with that token
    // must cancel that proposal, rather than activate either agreement.
    let mut wrong = vec![0xd0, 0, 0, 0];
    wrong.extend_from_slice(&OWN);
    wrong.extend_from_slice(&AP);
    wrong.extend_from_slice(&AP);
    wrong.extend_from_slice(&[0, 0, 3, 1, 2, 0, 0, 22, 16, 0, 0]);
    {
        let mut peer = f.peer().lock();
        peer.hold_tx_ba = true;
        peer.tx_ba_override = Some(wrong);
    }
    warm(&f, 4)?;
    let controls = f.controls();
    let before = f.peer().lock().uplink.len();
    if !controls.held.load(Ordering::Acquire) {
        return Err("T2 real requested ADDBA CCX not held");
    }
    if f.device().enqueue(&frame(5, 1), TxMeta::default()).is_ok() {
        return Err("T2 another TID bypassed outstanding original control ownership");
    }
    f.pump();
    if f.peer().lock().uplink.len() != before {
        return Err("T2 held control unexpectedly published DATA");
    }
    {
        let mut peer = f.peer().lock();
        peer.hold_tx_ba = false;
        peer.tx_ba_override = None;
    }
    controls.release.store(true, Ordering::Release);
    f.pump();
    f.pump();
    warm(&f, 5)?;
    let start = f.descriptors().len();
    send(&f, &frame(4, 2))?;
    send(&f, &frame(5, 3))?;
    f.pump();
    f.pump();
    let descriptors = data_descriptors(&f, start);
    if descriptors.len() != 2 || aggregated(&descriptors[0]) || !aggregated(&descriptors[1]) {
        return Err(
            "T2 wrong-TID response activated an agreement or poisoned the independent valid one",
        );
    }
    let requests = {
        f.peer()
            .lock()
            .tx_ba_controls
            .iter()
            .filter(|b| b.len() == 33 && b[25] == 0)
            .map(|b| (b[26], (u16::from_le_bytes([b[27], b[28]]) >> 2) & 15))
            .collect::<Vec<_>>()
    };
    if requests != vec![(1, 0), (2, 4), (3, 5)] || !f.device().link_up() {
        return Err("T2 held-control/global-token/independent-TID owner changed");
    }
    monotone(&f, true)
}
