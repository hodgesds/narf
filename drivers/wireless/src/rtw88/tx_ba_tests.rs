//! Actual retained C21/C22 originator conversations; fixture qualifications are
//! test-only signed inputs, never physical measurements or real board assets.
use super::ht_tests::{self as ht, Fixture, AP, OWN};
use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_net::{Interface, TxMeta};
use narf_wireless::WirelessNetIface;

fn record<F: Fixture>(f: &F) -> Result<Vec<u8>, &'static str> {
    let request = f.tx_request().map_err(|_| "T exact current H/R identity")?;
    let mut b = vec![0; 192];
    b[..4].copy_from_slice(if F::c21() { b"N21T" } else { b"N22T" });
    b[4..8].copy_from_slice(&[1, 0, 192, 0]);
    b[8..12].copy_from_slice(&192u32.to_le_bytes());
    b[12..16].copy_from_slice(if F::c21() {
        &[0xec, 0x10, 0x21, 0xc8]
    } else {
        &[0xec, 0x10, 0x22, 0xc8]
    });
    b[16..48].copy_from_slice(&request.identity);
    b[48..54].copy_from_slice(&OWN);
    b[54..56].copy_from_slice(&[1, 20]);
    b[58..60].copy_from_slice(&80i16.to_le_bytes());
    for at in [60, 62, 64, 66].into_iter().chain((76..108).step_by(2)) {
        b[at..at + 2].copy_from_slice(&8i16.to_le_bytes());
    }
    b[69] = 63;
    b[70] = 4;
    b[71] = 64;
    b[72..74].copy_from_slice(&8191u16.to_le_bytes());
    b[74..76].copy_from_slice(&4000u16.to_le_bytes());
    Ok(b)
}
type Qualified<F> = (F, Cap<FirmwareBlob, Read>, Option<Cap<FirmwareBlob, Read>>);
fn setup<F: Fixture>(protected: bool, recipient: bool) -> Result<Qualified<F>, &'static str> {
    let f = F::make(protected, 255, true, true)?;
    let r = if recipient {
        let cap = Cap::bootstrap();
        f.stage_ba(super::rx_ba_tests::record(&f)?, cap)
            .map_err(|_| "stage R before T")?;
        Some(cap)
    } else {
        None
    };
    f.peer().lock().tx_ba_window = Some(64);
    let cap = Cap::bootstrap();
    f.stage_tx(record(&f)?, cap)
        .map_err(|_| "distinct synthetic T record")?;
    Ok((f, cap, r))
}
fn fixture<F: Fixture>(protected: bool, recipient: bool) -> Result<Qualified<F>, &'static str> {
    let values = setup::<F>(protected, recipient)?;
    ht::join(&values.0)?;
    Ok(values)
}
fn up(label: u8) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        AP,
        OWN,
        [10, 88, 1, 42],
        [10, 88, 1, 1],
        49152,
        7,
        &[label; 24],
    )
}
fn down(label: u8) -> Vec<u8> {
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
fn word(b: &[u8; 48], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn has_aggregation(d: &[u8; 48]) -> bool {
    word(d, 8) & (1 << 12) != 0
}
fn send<F: Fixture>(f: &F, b: &[u8]) -> Result<(), &'static str> {
    f.device()
        .enqueue(b, TxMeta::default())
        .map_err(|_| "enqueue native BA Ethernet")
}
fn live<F: Fixture>(f: &F) -> Result<(), &'static str> {
    if !f.device().link_up() || f.retained().0 == 0 {
        return Err("T lost port/native DMA");
    }
    Ok(())
}
pub(super) fn composition<F: Fixture>(protected: bool) -> Result<(), &'static str> {
    let (f, _, _) = fixture::<F>(protected, true)?;
    let retained = f.retained();
    if f.register(0x42a) & 0xffff != 0x0808
        || (f.register(0x455) & 255) != 0x20
        || f.register(0x4ce) & 0xffff != 0x0801
    {
        return Err("distinct T retry/time and unchanged R BAR mode");
    }
    let request = f
        .peer()
        .lock()
        .tx_ba_controls
        .first()
        .cloned()
        .ok_or("actual native ADDBA request absent")?;
    if request.len() != 33
        || request[24..27] != [3, 0, 1]
        || request[27..31] != [2, 16, 0, 0]
        || request[31] & 15 != 0
    {
        return Err("literal native originator request/dialog/SSN");
    }
    let lease = narf_net::dhcp::dhcp_acquire(f.device().name(), 0)
        .map_err(|_| "originator BA actual DHCP/IP")?;
    if !f.peer().lock().plan.matches_lease(&lease) {
        return Err("T DHCP lease");
    }
    let _ = f.received();
    let before = f.peer().lock().uplink.len();
    let packets = (0..4).map(up).collect::<Vec<_>>();
    for p in &packets {
        send(&f, p)?;
    }
    f.pump();
    if f.peer().lock().uplink[before..] != packets || !f.received().is_empty() {
        return Err("native batch exact CCMP/Ethernet data");
    }
    let descriptors = f.descriptors();
    let agg = descriptors
        .iter()
        .filter(|d| has_aggregation(d))
        .collect::<Vec<_>>();
    if agg.len() < 6
        || agg.iter().any(|d| {
            word(d, 8) & (1 << 19) == 0
                || word(d, 12) >> 17 & 31 != 3
                || word(d, 16) & 127 != 19
                || word(d, 20) & 16 == 0
                || word(d, 4) >> 8 & 31 != 0
        })
    {
        return Err("literal AGGEN/density/MAXAGG/CCX/MCS/GI/TID0 native TXD");
    }
    let last = f
        .peer()
        .lock()
        .tx_ba_controls
        .last()
        .cloned()
        .ok_or("native current-SSN BAR absent")?;
    if last.len() != 20 || last[..2] != [0x84, 0] || last[16..18] != [4, 0] {
        return Err("actual20-byte compressed BAR absent");
    }
    // T -> R -> H must preserve actual recipient admission under the changed
    // retry program; no R-only grant may authorize that program.
    super::rx_ba_tests::agreement(&f, 0, 71, 0, 64, 0)?;
    f.peer().lock().data_sequence = 0;
    let a = down(31);
    let b = down(32);
    let first = f.peer().lock().downlink(&a)?;
    let second = f.peer().lock().downlink(&b)?;
    f.inject(&second, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("T bypassed R opaque ordering");
    }
    f.inject(&first, 19, 0);
    f.pump();
    if f.received() != vec![a, b] || f.retained() != retained {
        return Err("T/R coexistence native RX/PN/ownership");
    }
    live(&f)
}
pub(super) fn refusal_and_legacy<F: Fixture>() -> Result<(), &'static str> {
    let f = F::make(false, 255, true, true)?;
    let original = (f.register(0x42a), f.register(0x455));
    for kind in 0..11 {
        let mut b = record(&f)?;
        match kind {
            0 => b[0] ^= 3,
            1 => b[16] ^= 1,
            2 => b[48] ^= 2,
            3 => b[69] = 62,
            4 => b[70] = 5,
            5 => b[71] = 65,
            6 => b[72..74].copy_from_slice(&8192u16.to_le_bytes()),
            7 => b[74..76].copy_from_slice(&4001u16.to_le_bytes()),
            8 => b[108] = 1,
            9 => b[58..60].copy_from_slice(&0i16.to_le_bytes()),
            _ => b.truncate(191),
        };
        if f.stage_tx(b, Cap::bootstrap()).is_ok()
            || (f.register(0x42a), f.register(0x455)) != original
        {
            return Err("invalid T wrote hardware or could authorize burst");
        }
    }
    ht::join(&f)?;
    send(&f, &up(60))?;
    f.pump();
    if !f.peer().lock().tx_ba_controls.is_empty()
        || f.descriptors().iter().any(has_aggregation)
        || (f.register(0x42a), f.register(0x455)) != original
    {
        return Err("missing T widened H connection/emitter program");
    }
    live(&f)?;
    drop(f);
    let f = F::make(false, 255, true, true)?;
    let old = record(&f)?;
    let mut r = super::rx_ba_tests::record(&f)?;
    for at in [60, 62, 64] {
        r[at..at + 2].copy_from_slice(&76i16.to_le_bytes());
    }
    f.stage_ba(r, Cap::bootstrap())
        .map_err(|_| "valid high-peak R record")?;
    if f.stage_tx(old, Cap::bootstrap()).is_ok() {
        return Err("H-alone T identity also authorized changed R program");
    }
    let mut narrowed = record(&f)?;
    narrowed[58..60].copy_from_slice(&68i16.to_le_bytes());
    if f.stage_tx(narrowed, Cap::bootstrap()).is_ok() {
        return Err("narrow T ceiling failed to include prior R automatic-response peaks");
    }
    Ok(())
}
pub(super) fn peer_response_and_ssn<F: Fixture>() -> Result<(), &'static str> {
    for kind in 0..6 {
        let (f, _, _) = setup::<F>(true, false)?;
        if kind == 0 {
            f.peer().lock().tx_ba_window = Some(0);
        } else {
            let mut b = vec![0xd0, 0, 0, 0];
            b.extend_from_slice(&OWN);
            b.extend_from_slice(&AP);
            b.extend_from_slice(&AP);
            b.extend_from_slice(&[0, 0, 3, 1, 1, 0, 0, 2, 16, 0, 0]);
            match kind {
                1 => b[26] = 2,
                2 => b[10] ^= 2,
                3 => b[29] &= !2,
                4 => b[29] |= 4,
                _ => {
                    b[29] = 2;
                    b[30] = 32;
                }
            };
            f.peer().lock().tx_ba_override = Some(b);
        }
        ht::join(&f)?;
        send(&f, &up(kind))?;
        f.pump();
        if f.descriptors().iter().any(has_aggregation) || !f.device().link_up() {
            return Err(
                "unbound/refused BA response activated native AGGEN or destroyed H fallback",
            );
        }
    }
    let (f, _, _) = fixture::<F>(true, false)?;
    // Peer actor validates every actual QoS sequence against the on-air SSN.
    for i in 0..3 {
        send(&f, &up(i))?;
        f.pump();
    }
    if f.peer().lock().uplink.len() != 3 {
        return Err("actual next per-TID SSN not consumed before CCMP");
    }
    live(&f)?;
    drop(f);
    let (f, _, _) = setup::<F>(false, false)?;
    f.peer().lock().tx_ba_timeout = 1;
    ht::join(&f)?;
    f.advance_ms(2);
    f.pump();
    let before = f.descriptors().len();
    send(&f, &up(90))?;
    f.pump();
    if f.descriptors()[before..].iter().any(has_aggregation)
        || !f
            .peer()
            .lock()
            .tx_ba_controls
            .iter()
            .any(|b| b.len() == 30 && b[26..30] == [0, 8, 39, 0])
    {
        return Err(
            "negotiated TU inactivity failed to retire native aggregation before DELBA/data",
        );
    }
    live(&f)
}
pub(super) fn held_dialog_and_cancel<F: Fixture>() -> Result<(), &'static str> {
    for cancel in [false, true] {
        let (f, _, _) = setup::<F>(true, false)?;
        ht::scan(&f)?;
        f.peer().lock().hold_tx_ba = true;
        let controls = f.controls();
        let retained = f.retained();
        let mut future = alloc::boxed::Box::pin(f.device().associate(ht::request(&f)));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..8192 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("held request CCX did not retain association");
            }
            if controls.held.load(Ordering::Acquire) {
                break;
            }
        }
        if !controls.held.load(Ordering::Acquire) || f.peer().lock().tx_ba_controls.len() != 1 {
            return Err("native ADDBA publication not actually reached");
        }
        if !cancel {
            f.peer().lock().hold_tx_ba = false;
            controls.release.store(true, Ordering::Release);
            let mut finished = false;
            for _ in 0..8192 {
                if let Poll::Ready(r) = future.as_mut().poll(&mut cx) {
                    r.map_err(|_| "ADDBA exact native CCX/response/RXidle continuation")?;
                    finished = true;
                    break;
                }
            }
            if !finished {
                return Err("ADDBA CCX continuation pending");
            }
        }
        // The pinned future still owns lifecycle until its scope ends. No
        // fixture model accessor is called while that lock is held.
        drop(future);
        if cancel {
            f.device().admission().close();
            controls.release.store(true, Ordering::Release);
            f.pump();
            if f.device().link_up() {
                return Err("late CCX resurrected cancelled BA owner");
            }
        } else {
            send(&f, &up(72))?;
            f.pump();
            live(&f)?;
        }
        if f.retained() != retained {
            return Err("held/cancelled BA request released retained DMA");
        }
    }
    Ok(())
}
pub(super) fn fifo_and_authority<F: Fixture>() -> Result<(), &'static str> {
    for bad in [false, true] {
        let (f, _, _) = fixture::<F>(true, true)?;
        let retained = f.retained();
        f.peer().lock().hold_data = true;
        for i in 0..4 {
            send(&f, &up(i))?;
        }
        f.pump();
        let controls = f.controls();
        controls.fifo_stuck.store(!bad, Ordering::Release);
        controls.fifo_invalid.store(bad, Ordering::Release);
        controls.release.store(true, Ordering::Release);
        f.pump();
        if !bad {
            f.advance_ms(1001);
            f.pump();
        }
        if f.device().link_up() || f.retained() != retained {
            return Err(
                "PCI+CCX bypassed invalid/nonempty actual MAC FIFO or released native pool",
            );
        }
    }
    let total = {
        let (f, _, _) = fixture::<F>(true, true)?;
        f.sources().len()
    };
    for which in 0..total + 3 {
        let (f, t, r) = fixture::<F>(true, true)?;
        let retained = f.retained();
        f.peer().lock().hold_data = true;
        send(&f, &up(81))?;
        f.pump();
        if which < total {
            f.sources()[which].revoke();
        } else if which == total {
            t.revoke();
        } else if which == total + 1 {
            r.ok_or("R cap")?.revoke();
        } else {
            f.clear_policy();
        }
        f.controls().release.store(true, Ordering::Release);
        f.pump();
        f.install_policy();
        f.pump();
        if f.device().link_up() || f.retained() != retained {
            return Err("current T/R/H/prior source/policy loss was retryable or released DMA");
        }
    }
    Ok(())
}
pub(super) fn partial_publication_and_close<F: Fixture>() -> Result<(), &'static str> {
    let (f, t, _) = fixture::<F>(true, false)?;
    let retained = f.retained();
    let before = f.peer().lock().uplink.len();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    f.after_descriptor(Arc::new(move || {
        if observed.fetch_add(1, Ordering::AcqRel) == 1 {
            t.revoke();
        }
    }));
    for i in 0..4 {
        send(&f, &up(i))?;
    }
    f.pump();
    if calls.load(Ordering::Acquire) != 2
        || f.peer().lock().uplink.len() != before
        || f.device().link_up()
        || f.retained() != retained
    {
        return Err("partial-BD revoke published doorbell, revived or released native DMA");
    }
    drop(f);
    let (f, _, _) = fixture::<F>(true, false)?;
    let retained = f.retained();
    f.peer().lock().hold_data = true;
    send(&f, &up(91))?;
    f.pump();
    f.device().admission().close();
    f.controls().release.store(true, Ordering::Release);
    f.pump();
    if f.device().link_up() || f.retained() != retained {
        return Err("close/late CCX reused or released native batch");
    }
    Ok(())
}
pub(super) fn delba_and_key_epoch<F: Fixture>() -> Result<(), &'static str> {
    let (f, _, _) = fixture::<F>(true, true)?;
    let mut delba = vec![0xd0, 0, 0, 0];
    delba.extend_from_slice(&OWN);
    delba.extend_from_slice(&AP);
    delba.extend_from_slice(&AP);
    delba.extend_from_slice(&[0, 0, 3, 2, 0, 0, 39, 0]);
    f.inject(&delba, 0, 0);
    f.pump();
    let before = f.descriptors().len();
    send(&f, &up(101))?;
    f.pump();
    if f.descriptors()[before..].iter().any(has_aggregation) {
        return Err("peer recipient DELBA failed to retire TX aggregation before next packet");
    }
    live(&f)?;
    drop(f);
    let (f, _, _) = fixture::<F>(true, true)?;
    let retained = f.retained();
    super::rx_ba_tests::agreement(&f, 0, 72, 0, 64, 0)?;
    f.peer().lock().data_sequence = 1;
    let expected = down(111);
    let held = f.peer().lock().downlink(&expected)?;
    f.inject(&held, 19, 0);
    f.pump();
    if !f.received().is_empty() {
        return Err("T/R old key window not held");
    }
    f.peer().lock().qos = false;
    let group = ht::group_rekey(&f)?;
    f.peer().lock().qos = true;
    f.peer().lock().hold_data = true;
    for i in 0..4 {
        send(&f, &up(i))?;
    }
    f.pump();
    let before = f.peer().lock().uplink.len();
    let controls = f.controls();
    f.inject(&group, 19, 0);
    f.pump();
    if f.peer().lock().uplink.len() != before || !f.received().is_empty() {
        return Err("key work bypassed old native burst drain");
    }
    controls.release.store(true, Ordering::Release);
    f.pump();
    if !controls.held.load(Ordering::Acquire) {
        return Err("actual group reply receipt not held after old batch drain");
    }
    let before = f.descriptors().len();
    f.peer().lock().hold_data = false;
    controls.release.store(true, Ordering::Release);
    f.pump();
    f.advance_ms(101);
    f.pump();
    if !f.received().is_empty() || f.retained() != retained {
        return Err("T/R key epoch published old reordered original or released pool");
    }
    send(&f, &up(112))?;
    f.pump();
    if f.descriptors()[before..]
        .iter()
        .filter(|d| has_aggregation(d))
        .count()
        != 1
    {
        return Err("fresh real dialog did not restore originator after terminal key receipt");
    }
    let dialogs = f
        .peer()
        .lock()
        .tx_ba_controls
        .iter()
        .filter(|b| b.len() == 33 && b[25] == 0)
        .map(|b| b[26])
        .collect::<Vec<_>>();
    if dialogs != vec![1, 2] {
        return Err("key replacement reused originator dialog/SSN owner");
    }
    live(&f)
}
