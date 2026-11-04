// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual C21 retained firmware/radio/Core/Device compositions. All signed
//! values below describe inert model measurements, never deployment assets.
use super::*;
use crate::rtw88::{
    ht_tests::{self as native, Fixture},
    tracking8821c as power,
};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_net::{Interface, TxMeta};

fn record(f: &Case) -> Result<Vec<u8>, &'static str> {
    let r =
        f.e.h
            .port
            .power_tracking_request()
            .map_err(|_| "W exact native full-program request")?;
    let mut b = vec![0; 192];
    b[..4].copy_from_slice(b"N21W");
    b[4..8].copy_from_slice(&[1, 0, 192, 0]);
    b[8..12].copy_from_slice(&192u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    b[56..58].copy_from_slice(&4i16.to_le_bytes());
    b[58..60].copy_from_slice(&76i16.to_le_bytes());
    b[60..66].copy_from_slice(&[0, 63, (-15i8) as u8, 15, 0, 36]);
    for i in 0..16 {
        b[66 + i * 2..68 + i * 2].copy_from_slice(&40i16.to_le_bytes());
    }
    Ok(b)
}
fn stage(f: &Case, b: Vec<u8>, cap: Cap<FirmwareBlob, Read>, signed: bool) -> Result<(), Error> {
    f.e.h.port.qualify_power_tracking(power::Source::Verified {
        bytes: b,
        cap,
        signer: signed.then_some([23; 32]),
    })
}
fn prepare(
    protected: bool,
    full: bool,
    bound: bool,
) -> Result<(Case, Cap<FirmwareBlob, Read>), &'static str> {
    let f = Case::make(protected, 255, true, true)?;
    if bound {
        let mut b = native::record(&f.request()?, 255, true, true);
        b[68] = 30;
        f.stage(b, Cap::bootstrap())
            .map_err(|_| "W independent nonselected MCS0 factory boundary")?;
    }
    if full {
        f.stage_kind(
            &crate::rtw88::qos::KIND,
            crate::rtw88::qos_tests::record(&f, 7)?,
            Cap::bootstrap(),
            true,
        )
        .map_err(|_| "W Q")?;
        f.stage_ba(crate::rtw88::rx_ba_tests::record(&f)?, Cap::bootstrap())
            .map_err(|_| "W R")?;
        {
            let mut p = f.peer().lock();
            p.tx_ba_window = Some(64);
            p.any_tid = true;
        }
        let mut b = crate::rtw88::tx_ba_tests::record(&f)?;
        let r = f.tx_request().map_err(|_| "W T2 request")?;
        b[4] = 2;
        b[16..48].copy_from_slice(&r.all_tids_identity);
        b[108..110].copy_from_slice(&[0x3f, 3]);
        f.stage_tx(b, Cap::bootstrap()).map_err(|_| "W T2")?;
        let r = f.rts_request().map_err(|_| "W actual T2 RTS request")?;
        let mut b = vec![0; 128];
        b[..4].copy_from_slice(b"N21X");
        b[4..8].copy_from_slice(&[1, 0, 128, 0]);
        b[8..12].copy_from_slice(&128u32.to_le_bytes());
        b[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
        b[16..48].copy_from_slice(&r.identity);
        b[48..54].copy_from_slice(&r.mac);
        b[54..56].copy_from_slice(&[1, 20]);
        b[58..60].copy_from_slice(&76i16.to_le_bytes());
        for i in 0..4 {
            b[60 + i * 2..62 + i * 2].copy_from_slice(&40i16.to_le_bytes());
        }
        b[69] = 63;
        f.stage_rts(b, Cap::bootstrap(), true)
            .map_err(|_| "W RTS")?;
    }
    let cap = Cap::bootstrap();
    stage(&f, record(&f)?, cap, true).map_err(|_| "W signed model program")?;
    native::join(&f)?;
    f.pump();
    f.pump();
    Ok((f, cap))
}
fn packet(tid: u8, label: u8) -> Vec<u8> {
    let mut b = native::AP.to_vec();
    b.extend_from_slice(&native::OWN);
    b.extend_from_slice(&[0x88, 0x47, 0, 0, tid << 1 | 1, 64]);
    b.extend_from_slice(&[label; 48]);
    b
}
fn send(f: &Case, tid: u8, label: u8) -> Result<(), &'static str> {
    let b = packet(tid, label);
    f.device()
        .enqueue(&b, TxMeta::default())
        .map_err(|_| "W real native DATA enqueue")?;
    f.pump();
    f.pump();
    if f.peer().lock().uplink.last() != Some(&b) {
        return Err("W native original DATA not delivered");
    }
    Ok(())
}
fn sample(f: &Case, t: u8) -> Result<bool, &'static str> {
    f.e.h.port.0.lock().tracking_sample = Some(t);
    if native::run(f.device().watchdog())? {
        return Err("W trigger fabricated a converted sample");
    }
    f.advance_ms(2000);
    native::run(f.device().watchdog())
}
fn monotone(f: &Case, protected: bool) -> Result<(), &'static str> {
    let log = f.peer().lock().tx_sequences.clone();
    let mut seq = [None; 8];
    let mut pn = None;
    for (t, s, p) in log {
        if seq[usize::from(t)].is_some_and(|old| s != ((old + 1) & 4095))
            || protected && pn.is_some_and(|old| p != old + 1)
        {
            return Err("W tracking consumed/reused another TID SN or native key PN");
        }
        seq[usize::from(t)] = Some(s);
        pn = Some(p);
    }
    Ok(())
}
fn composition(protected: bool, cool: bool) -> Result<(), &'static str> {
    let (f, cap) = prepare(protected, false, false)?;
    let retained = f.retained();
    let lease =
        narf_net::dhcp::dhcp_acquire(f.device().name(), 0).map_err(|_| "W native kernel DHCP")?;
    if !f.peer().lock().plan.matches_lease(&lease) {
        return Err("W actual native DHCP lease");
    }
    let _ = f.received();
    send(&f, 0, 11)?;
    let before = f.e.h.port.0.lock().commands.len();
    if !sample(&f, if cool { 0 } else { 34 })? {
        return Err("W fresh native meter did not program");
    }
    let (pause, rx, commands, index, iqk) = {
        let m = f.e.h.port.0.lock();
        (
            m.bytes[0x522],
            word(&m.bytes, 0x284),
            m.commands.clone(),
            m.command_index,
            m.iqk_reads,
        )
    };
    let mut expected = [0; 32];
    expected[..9].copy_from_slice(&[1, 255, 14, 0, 9, 0, 3, 0, 2]);
    if commands.len() != before + 1
        || commands.last() != Some(&expected)
        || index != 0x40004
        || iqk != 2
        || f.register(0x2820) != 0
        || f.register(0x1bf0) & 0x100ff != 0
        || pause != 0
        || rx & (1 << 18) != 0
        || f.register(0xc94) & 0x7e != if cool { 0x7c } else { 6 }
        || f.register(0xc1c) >> 21 != if cool { 0x110 } else { 0x16a }
    {
        return Err("W actual signed AGC/swing or associated fresh IQK receipt");
    }
    send(&f, 0, 12)?;
    let mut down = packet(0, 13);
    down[..6].copy_from_slice(&native::OWN);
    down[6..12].copy_from_slice(&native::AP);
    let raw = f.peer().lock().downlink(&down)?;
    f.inject(&raw, 19, 0);
    f.pump();
    if f.received() != vec![down] || !f.device().link_up() || f.retained() != retained {
        return Err("W physical current native RX/DMA/keys/link");
    }
    monotone(&f, protected)?;
    cap.revoke();
    let _ = native::run(f.device().watchdog())?;
    if f.device().link_up()
        || f.device()
            .enqueue(&packet(0, 14), TxMeta::default())
            .is_ok()
        || f.retained() != retained
    {
        return Err("W periodic IQK source loss pretended static coefficient restoration");
    }
    Ok(())
}
fn full_program() -> Result<(), &'static str> {
    let (f, _) = prepare(true, true, true)?;
    send(&f, 1, 21)?;
    send(&f, 5, 22)?;
    let old =
        f.e.h
            .port
            .clone()
            .station_publication()
            .map_err(|_| "W current native copy proof")?
            .with_epoch(f.device().admission().epoch());
    let retained = f.retained();
    if !sample(&f, 34)? || f.register(0xc94) & 0x7e != 0 || f.register(0xc1c) >> 21 != 0x1af {
        return Err("W ignored nonselected MCS0 factory ceiling/global offset");
    }
    if old.invoke(|| Ok(())).is_ok() {
        return Err("W mutation did not retire original copied admission");
    }
    for tid in [1u8, 5] {
        let before = f.peer().lock().uplink.len();
        for label in 0..4 {
            f.device()
                .enqueue(&packet(tid, 30 + label), TxMeta::default())
                .map_err(|_| "W T2 actual IPC burst")?;
        }
        f.pump();
        f.pump();
        let actual = f
            .descriptors()
            .into_iter()
            .rev()
            .find(|d| d[5] & 31 < 8)
            .ok_or("W native burst descriptor")?;
        if f.peer().lock().uplink.len() != before + 4
            || actual[5] & 31 != tid
            || u32::from_le_bytes(actual[8..12].try_into().unwrap()) & (1 << 12) == 0
        {
            return Err("W T2/Q immutable original lost aggregate/ring ownership");
        }
    }
    if f.retained() != retained || !f.device().link_up() {
        return Err("W full-source maintenance changed owner");
    }
    monotone(&f, true)
}
fn assets() -> Result<(), &'static str> {
    // The old static prefix fits70qdbm; the new W program72qdbm fits H76
    // but must not bypass an independently narrower R, T or RTS ceiling.
    for narrow in 0..3 {
        let f = Case::make(false, 255, true, true)?;
        let mut r = crate::rtw88::rx_ba_tests::record(&f)?;
        if narrow == 0 {
            r[58..60].copy_from_slice(&70i16.to_le_bytes());
        }
        f.stage_ba(r, Cap::bootstrap())
            .map_err(|_| "W narrow R setup")?;
        let mut t = crate::rtw88::tx_ba_tests::record(&f)?;
        if narrow == 1 {
            t[58..60].copy_from_slice(&70i16.to_le_bytes());
        }
        f.stage_tx(t, Cap::bootstrap())
            .map_err(|_| "W narrow T setup")?;
        let request = f.rts_request().map_err(|_| "W narrow RTS request")?;
        let mut x = vec![0; 128];
        x[..4].copy_from_slice(b"N21X");
        x[4..8].copy_from_slice(&[1, 0, 128, 0]);
        x[8..12].copy_from_slice(&128u32.to_le_bytes());
        x[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
        x[16..48].copy_from_slice(&request.identity);
        x[48..54].copy_from_slice(&request.mac);
        x[54..56].copy_from_slice(&[1, 20]);
        x[58..60].copy_from_slice(&(if narrow == 2 { 70i16 } else { 76 }).to_le_bytes());
        for at in [60, 62, 64, 66] {
            x[at..at + 2].copy_from_slice(&40i16.to_le_bytes());
        }
        x[69] = 63;
        f.stage_rts(x, Cap::bootstrap(), true)
            .map_err(|_| "W narrow RTS setup")?;
        let mut w = record(&f)?;
        for at in (66..98).step_by(2) {
            w[at..at + 2].copy_from_slice(&68i16.to_le_bytes());
        }
        let calls = f.e.h.port.0.lock().calls;
        if stage(&f, w, Cap::bootstrap(), true).is_ok() || f.e.h.port.0.lock().calls != calls {
            return Err("W program bypassed original signed R/T/RTS ceiling");
        }
    }
    let f = Case::make(false, 255, true, true)?;
    let good = record(&f)?;
    let calls = f.e.h.port.0.lock().calls;
    for case in 0..13 {
        let mut b = good.clone();
        match case {
            0 => b[3] = b'X',
            1 => b[16] ^= 1,
            2 => b[48] ^= 2,
            3 => b[61] = 24,
            4 => b[62] = (-16i8) as u8,
            5 => b[63] = 16,
            6 => b[64] = 36,
            7 => b[65] = 37,
            8 => b[98] = 1,
            9 => b[58..60].copy_from_slice(&0i16.to_le_bytes()),
            10 => {
                b.pop();
            }
            11 => b[96..98].copy_from_slice(&100i16.to_le_bytes()),
            _ => (),
        }
        if stage(&f, b, Cap::bootstrap(), case != 12).is_ok() {
            return Err("W unqualified/foreign/unsigned full program admitted");
        }
    }
    if f.e.h.port.0.lock().calls != calls {
        return Err("W pure qualification rejection mutated native state");
    }
    native::join(&f)?;
    f.advance_ms(2000);
    if native::run(f.device().watchdog())? || f.e.h.port.0.lock().commands.len() != 3 {
        return Err("W old H alone enabled thermal tracking");
    }
    Ok(())
}
fn quiet_and_restore() -> Result<(), &'static str> {
    let (f, cap) = prepare(true, true, false)?;
    let retained = f.retained();
    send(&f, 1, 40)?;
    f.controls().held.store(true, Ordering::Release);
    f.device()
        .enqueue(&packet(1, 41), TxMeta::default())
        .map_err(|_| "W held actual native DATA")?;
    f.pump();
    let before = (
        f.register(0xc94),
        f.register(0xc1c),
        f.e.h.port.0.lock().commands.len(),
    );
    if native::run(f.device().watchdog())?
        || (
            f.register(0xc94),
            f.register(0xc1c),
            f.e.h.port.0.lock().commands.len(),
        ) != before
    {
        return Err("W changed power before actual native DATA terminal");
    }
    f.controls().held.store(false, Ordering::Release);
    f.e.h.port.0.lock().packet_model.complete_held();
    f.pump();
    f.pump();
    if !sample(&f, 29)? {
        return Err("W actual terminal did not permit thermal program");
    }
    cap.revoke();
    // Do not drive ordinary DATA on a revoked proof; the retained maintenance
    // continuation performs the real static restore before another enqueue.
    if !native::run(f.device().watchdog())?
        || f.register(0xc94) & 0x7e != 0
        || f.register(0xc1c) >> 21 != 0x16a
    {
        return Err("W revoked program did not restore actual static power");
    }
    send(&f, 1, 42)?;
    if f.retained() != retained || !f.device().link_up() {
        return Err("W restore lost actual keys/DMA/BA");
    }
    monotone(&f, true)
}
fn failures() -> Result<(), &'static str> {
    for fault in 0..5 {
        let (f, _) = prepare(true, false, false)?;
        let retained = f.retained();
        f.e.h.port.0.lock().tracking_sample = Some(34);
        let _ = native::run(f.device().watchdog())?;
        f.advance_ms(2000);
        {
            let mut m = f.e.h.port.0.lock();
            match fault {
                0 => m.ignore_write = Some(0xc94),
                1 => m.command_stall = true,
                2 => m.iqk_complete = false,
                3 => m.bytes[0x1bf0..0x1bf4].copy_from_slice(&1u32.to_le_bytes()),
                _ => m.rx_dma_busy = true,
            }
        }
        let _ = native::run(f.device().watchdog())?;
        if f.device().link_up()
            || f.device()
                .enqueue(&packet(0, 50), TxMeta::default())
                .is_ok()
            || f.retained() != retained
        {
            return Err("W failed program/RX park/H2C/applied IQK retained live DATA or freed DMA");
        }
    }
    Ok(())
}
fn cancel() -> Result<(), &'static str> {
    let (f, _) = prepare(true, false, false)?;
    let retained = f.retained();
    f.e.h.port.0.lock().tracking_sample = Some(34);
    let _ = native::run(f.device().watchdog())?;
    f.advance_ms(2000);
    f.e.h.port.0.lock().hold_delay = Some(20_000);
    let mut future = alloc::boxed::Box::pin(f.device().watchdog());
    let mut cx = Context::from_waker(Waker::noop());
    if !matches!(future.as_mut().poll(&mut cx), Poll::Pending)
        || !f.e.h.port.0.lock().tracking_maintenance
    {
        return Err("W missed actual pending associated IQK await");
    }
    drop(future);
    if !f.device().closed()
        || f.device()
            .enqueue(&packet(0, 60), TxMeta::default())
            .is_ok()
        || f.retained() != retained
    {
        return Err("W cancelled partial program reopened/published/freed original owner");
    }
    Ok(())
}
fn coding_fallback_dm() -> Result<(), &'static str> {
    let f = Case::make(true, 255, true, true)?;
    for (kind, b) in [
        (
            &crate::rtw88::coding::KIND,
            crate::rtw88::coding_tests::record(&f, 1)?,
        ),
        (
            &crate::rtw88::fallback::KIND,
            crate::rtw88::fallback_tests::record(&f, 1)?,
        ),
        (
            &crate::rtw88::dm::KIND,
            crate::rtw88::dm_station_tests::record(
                &f,
                crate::rtw88::dm::DIG | crate::rtw88::dm::CCK_PD | crate::rtw88::dm::RA,
            )?,
        ),
    ] {
        f.stage_kind(kind, b, Cap::bootstrap(), true)
            .map_err(|_| "W exact C/F/D source")?;
    }
    let mut elements = native::elements(true);
    elements[2] |= 1;
    let beacon = {
        let mut p = f.peer().lock();
        p.ht = Some(elements.clone());
        let mut b = p.ap.beacon();
        b.extend_from_slice(p.wmm.as_ref().ok_or("W C/F/D WMM")?);
        b.extend_from_slice(&elements);
        b
    };
    f.e.h
        .port
        .0
        .lock()
        .packet_model
        .receive(&beacon, false, false);
    stage(&f, record(&f)?, Cap::bootstrap(), true).map_err(|_| "W C/F/D composed grant")?;
    native::join(&f)?;
    f.pump();
    // Actual C2H0c7-byte RA report: native RX decoder, MACID0, MCS7.
    f.e.h
        .port
        .0
        .lock()
        .packet_model
        .receive(&[0x0c, 0, 19, 0, 0, 0, 0, 0, 0], true, false);
    f.pump();
    f.e.h.port.0.lock().tracking_sample = Some(34);
    let _ = native::run(f.device().watchdog())?;
    f.advance_ms(2000);
    let _ = native::run(f.device().watchdog())?;
    if f.register(0xc94) & 0x7e != 6 || !f.device().link_up() {
        return Err("W real C2H-selected F/C/D tracking program missing");
    }
    send(&f, 0, 70)?;
    monotone(&f, true)
}
fn smoke_rtw8821ce_power_tracking_open_fresh_meter_native_iqk_and_dhcp() -> TestResult {
    check(|| composition(false, false))
}
fn smoke_rtw8821ce_power_tracking_wpa2_signed_negative_swing_and_native_keys() -> TestResult {
    check(|| composition(true, true))
}
fn smoke_rtw8821ce_power_tracking_t2_q_rts_factory_all_rate_boundary_and_copy_epoch() -> TestResult
{
    check(full_program)
}
fn smoke_rtw8821ce_power_tracking_distinct_full_source_assets_and_original_h() -> TestResult {
    check(assets)
}
fn smoke_rtw8821ce_power_tracking_held_native_terminal_and_static_restore() -> TestResult {
    check(quiet_and_restore)
}
fn smoke_rtw8821ce_power_tracking_real_program_iqk_and_rx_park_failures_pin_dma() -> TestResult {
    check(failures)
}
fn smoke_rtw8821ce_power_tracking_cancelled_applied_iqk_keeps_publication_closed() -> TestResult {
    check(cancel)
}
fn smoke_rtw8821ce_power_tracking_coding_actual_c2h_fallback_and_dm_composition() -> TestResult {
    check(coding_fallback_dm)
}
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_open_fresh_meter_native_iqk_and_dhcp
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_wpa2_signed_negative_swing_and_native_keys
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_t2_q_rts_factory_all_rate_boundary_and_copy_epoch
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_distinct_full_source_assets_and_original_h
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_held_native_terminal_and_static_restore
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_real_program_iqk_and_rx_park_failures_pin_dma
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_cancelled_applied_iqk_keeps_publication_closed
);
kernel_test_in!(
    "drivers/wireless/rtw88/power_tracking/rtl8821c",
    smoke_rtw8821ce_power_tracking_coding_actual_c2h_fallback_and_dm_composition
);
