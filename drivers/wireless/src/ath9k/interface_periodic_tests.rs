// SPDX-License-Identifier: GPL-2.0-or-later
//! Native Device/Radio/Packet/DMA periodic calibration composition.
use super::*;
use crate::ath9k::periodic::{self, Source};
use narf_capabilities::{Cap, NoopOp};
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !($condition) {
            return Err($message);
        }
    };
}
fn verdict(case: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match case() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
fn profile(
    protected: bool,
) -> (
    Harness,
    Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
) {
    let h = Harness::new_ht(protected, 255);
    let cap = periodic::tests::qualify(&h.model);
    h.join();
    h.pump();
    (h, cap)
}
fn advance(h: &Harness, time: u64) -> Result<(), &'static str> {
    h.model.now.set(time);
    h.env
        .now
        .store(time / 1000, core::sync::atomic::Ordering::Release);
    let beacon = { h.peer.lock().beacon() };
    h.model
        .inject(&beacon, 0)
        .map_err(|_| "periodic real current-peer beacon after clock advance")?;
    h.pump();
    Ok(())
}
fn upload(h: &Harness, body: &[u8]) -> Result<(), &'static str> {
    let frame = udp_ipv4(
        AP,
        h.plan.station,
        h.plan.lease_ip,
        h.plan.server_ip,
        49001,
        7,
        body,
    );
    h.device
        .enqueue(&frame, Default::default())
        .map_err(|_| "periodic native enqueue")?;
    h.pump();
    let received = { h.peer.lock().uplink.last().cloned() };
    check!(
        received.as_ref() == Some(&frame),
        "periodic exact native original uplink"
    );
    Ok(())
}
fn source() -> Result<(), &'static str> {
    let h = Harness::new_ht(true, 255);
    let base = { h.model.ht.borrow().clone().unwrap() };
    let record = periodic::tests::record(&base);
    for at in [
        0, 4, 6, 8, 12, 16, 48, 54, 55, 56, 57, 64, 68, 72, 76, 80, 84, 88, 92, 124, 128, 159,
    ] {
        let mut bad = record.clone();
        bad[at] ^= 1;
        check!(
            Source::Verified {
                bytes: bad,
                signer: Some([1; 32]),
                cap: Cap::bootstrap()
            }
            .load(base.clone())
            .is_err(),
            "unknown/foreign periodic source admitted"
        );
    }
    check!(
        Source::Verified {
            bytes: record.clone(),
            signer: None,
            cap: Cap::bootstrap()
        }
        .load(base.clone())
        .is_err(),
        "unsigned periodic source admitted"
    );
    let revoked = Cap::bootstrap();
    revoked.revoke();
    check!(
        Source::Verified {
            bytes: record,
            signer: Some([1; 32]),
            cap: revoked
        }
        .load(base.clone())
        .is_err(),
        "revoked periodic source decoded"
    );
    let old = crate::ath9k::ps::tests::record(&base);
    check!(
        Source::Verified {
            bytes: old,
            signer: Some([1; 32]),
            cap: Cap::bootstrap()
        }
        .load(base)
        .is_err(),
        "S1 bytes reinterpreted as periodic authority"
    );
    h.join();
    h.pump();
    advance(&h, 35_000_000)?;
    let bound = { h.model.periodic.borrow().bound.is_some() };
    let trace_empty = { h.model.periodic.borrow().trace.is_empty() };
    check!(
        !bound && trace_empty && h.device.link_up(),
        "absent P changed old H program"
    );
    Ok(())
}
fn smoke_ar9285_periodic_signed_full_program_and_old_sources_fail_closed() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    verdict(source)
}
kernel_test_in!(
    "drivers/wireless/ath9k/periodic",
    smoke_ar9285_periodic_signed_full_program_and_old_sources_fail_closed
);

fn measurement() -> Result<(), &'static str> {
    for protected in [false, true] {
        let (h, cap) = profile(protected);
        let base = { h.model.ht.borrow().clone().unwrap() };
        let identity = base.ba_identity();
        let epoch = { h.device.radio.try_lock().unwrap().receive_epoch() };
        let before = h.model.registers.borrow()[&0x9920] & 0xfff;
        h.model.periodic.borrow_mut().hold_cal = true;
        advance(&h, 1_000_000)?;
        let running = h.model.registers.borrow()[&0x9920] & 0x10000 != 0;
        let unchanged = h.model.registers.borrow()[&0x9920] & 0xfff == before;
        // The actual just-consumed beacon tail stays DMA-mapped and terminal
        // while source DO_CAL starts; periodic work must never clear/rearm
        // buf_hold or release its storage merely to obtain eligibility.
        let held = h
            .model
            .last_rx
            .get()
            .ok_or("periodic real completed beacon tail missing")?;
        let held_terminal = h
            .model
            .word(held + 48)
            .map_err(|_| "periodic retained completed tail lost its DMA mapping")?
            & 1
            != 0;
        let retained = { h.model.released.borrow().is_empty() };
        check!(
            held_terminal && retained,
            "periodic recycled or released actual buf_hold while starting measurement"
        );
        check!(
            running && unchanged && h.device.link_up(),
            "actual IQ sample did not retain prior coefficient receipt"
        );
        upload(
            &h,
            b"old factual coefficients during actual hardware measurement",
        )?;
        h.model.periodic.borrow_mut().hold_cal = false;
        advance(&h, h.model.now.get() + 100)?;
        let actual = h.model.registers.borrow()[&0x9920];
        let after_epoch = { h.device.radio.try_lock().unwrap().receive_epoch() };
        check!(
            actual & 0x10000 == 0 && actual & 0xfff != before && after_epoch == epoch,
            "actual IQ completion changed key/copy generation or kept old coefficients"
        );
        check!(
            base.ba_identity() == identity
                && base.readback(&h.model).is_ok()
                && cap.invoke(NoopOp).is_ok(),
            "periodic rewrote H identity or used a prior source grant"
        );
        upload(
            &h,
            b"new factual coefficients retain original key PN and SC owners",
        )?;
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "periodic kernel DHCP after actual IQ completion")?;
        check!(
            h.plan.matches_lease(&lease),
            "periodic DHCP lease differs from real native peer"
        );
        let iface: &dyn WirelessNetIface = &*h.device;
        check!(
            iface.power_save_default().is_none()
                && iface.set_power_save(true) == Err(-95)
                && h.device.link_up(),
            "P silently combined static S1 or unsupported setting killed live station"
        );
    }
    Ok(())
}
fn smoke_ar9285_periodic_native_iq_old_live_traffic_fresh_receipt_and_kernel_dhcp() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    verdict(measurement)
}
kernel_test_in!(
    "drivers/wireless/ath9k/periodic",
    smoke_ar9285_periodic_native_iq_old_live_traffic_fresh_receipt_and_kernel_dhcp
);

fn counters(h: &Harness, now: u64, ofdm: u32, cck: u32) -> Result<(), &'static str> {
    for (register, value) in [
        (0x80f8, 44_000_000),
        (0x80f4, 0),
        (0x80f0, 0),
        (0x80ec, 0),
        (0x812c, ofdm),
        (0x8134, cck),
    ] {
        h.model.registers.borrow_mut().insert(register, value);
    }
    advance(h, now)
}
fn maintenance() -> Result<(), &'static str> {
    let (h, _) = profile(true);
    advance(&h, 1_000_000)?;
    advance(&h, 1_000_100)?;
    let beacon = { h.peer.lock().beacon() };
    h.model
        .inject(&beacon, 0)
        .map_err(|_| "periodic current native beacon")?;
    counters(&h, 2_000_000, 1000, 0)?;
    let spur = h.model.registers.borrow()[&0x9924] >> 1 & 127;
    let firstep = h.model.registers.borrow()[&0x9858] >> 12 & 63;
    check!(
        spur == 10 && firstep == 6,
        "ANI did not use actual listen/PHY counters and source AR9285 levels"
    );
    counters(&h, 3_000_000, 0, 0)?;
    counters(&h, 4_000_000, 0, 0)?;
    let lower = h.model.registers.borrow()[&0x9924] >> 1 & 127;
    check!(
        lower == 8,
        "ANI lower turns replayed initial INI instead of actual source transition"
    );
    advance(&h, 30_000_000)?;
    let busy = h.model.registers.borrow()[&0x9860] & 2 != 0;
    check!(busy, "long calibration did not start actual NF measurement");
    advance(&h, 30_000_100)?;
    let control = h.model.registers.borrow()[&0x9864] & 511;
    let nf_idle = h.model.registers.borrow()[&0x9860] & 2 == 0;
    let trace = { h.model.periodic.borrow().trace.clone() };
    let pa = trace
        .iter()
        .any(|&(register, value)| register == 0x7868 && value == 0xca0358a0);
    let loaded = trace.iter().any(|&(register, value)| {
        register == 0x9864 && value & 511 == ((-115i32 as u32) << 1 & 511)
    });
    check!(
        pa && loaded && nf_idle && control == ((-50i32 as u32) << 1 & 511) && h.device.link_up(),
        "actual PA/median-load/maxCCA continuation incomplete"
    );
    advance(&h, 1_204_000_000)?;
    advance(&h, 1_204_000_100)?;
    let restarted = h.model.registers.borrow()[&0x9920] & 0x10000 != 0;
    check!(
        restarted,
        "20-minute source validity reset did not start actual fresh IQ list"
    );
    advance(&h, 1_204_000_200)?;
    upload(
        &h,
        b"live station after periodic ANI PA NF and valid-list restart",
    )?;
    Ok(())
}
fn smoke_ar9285_periodic_actual_ani_pa_nf_load_and_twenty_minute_restart() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    verdict(maintenance)
}
kernel_test_in!(
    "drivers/wireless/ath9k/periodic",
    smoke_ar9285_periodic_actual_ani_pa_nf_load_and_twenty_minute_restart
);

fn negative() -> Result<(), &'static str> {
    {
        let (h, cap) = profile(true);
        h.peer.lock().hold_data = true;
        let frame = udp_ipv4(
            AP,
            h.plan.station,
            h.plan.lease_ip,
            h.plan.server_ip,
            49003,
            7,
            b"retained native original before calibration",
        );
        h.device
            .enqueue(&frame, Default::default())
            .map_err(|_| "periodic held original enqueue")?;
        h.pump();
        let native = h.model.tx.get().ok_or("periodic held native QCU")?;
        let original = { h.model.dma_transmitted.borrow().last().cloned().unwrap() };
        advance(&h, 1_000_000)?;
        let not_started = h.model.registers.borrow()[&0x9920] & 0x10000 == 0;
        check!(
            not_started && h.model.tx.get() == Some(native),
            "calibration stole pending native original"
        );
        h.model
            .put(native + 92, 1)
            .map_err(|_| "periodic native DONE")?;
        h.pump();
        let still_not_started = h.model.registers.borrow()[&0x9920] & 0x10000 == 0;
        check!(
            still_not_started,
            "calibration accepted DONE while actual QCU retained original"
        );
        h.model
            .complete(true)
            .map_err(|_| "periodic actual native terminal")?;
        h.peer.lock().hold_data = false;
        h.pump();
        let running = h.model.registers.borrow()[&0x9920] & 0x10000 != 0;
        let same_original = { h.model.dma_transmitted.borrow().last() == Some(&original) };
        check!(
            running && same_original,
            "native receipt calibration changed original PN/SC bytes"
        );
        let old_iq = h.model.registers.borrow()[&0x9920] & 0xfff;
        h.model.periodic.borrow_mut().hold_cal = true;
        // Retain a real completed original whose software receipt has not
        // been consumed. Deadline admission must not retire or replace it.
        h.peer.lock().hold_data = true;
        let held = udp_ipv4(
            AP,
            h.plan.station,
            h.plan.lease_ip,
            h.plan.server_ip,
            49004,
            7,
            b"original ticket retained across expired sample admission",
        );
        h.device
            .enqueue(&held, Default::default())
            .map_err(|_| "periodic in-measurement held original enqueue")?;
        h.pump();
        let held_native = h
            .model
            .tx
            .get()
            .ok_or("periodic in-measurement native ticket")?;
        let held_dma = { h.model.dma_transmitted.borrow().last().cloned().unwrap() };
        let held_wire = { h.model.transmitted.borrow().last().cloned().unwrap() };
        let header = if held_wire[0] == 0x88 { 26 } else { 24 };
        let (held_pn, _) = narf_wireless::ccmp::decode_ccmp_header(
            held_wire[header..header + 8].try_into().unwrap(),
        )
        .map_err(|_| "periodic held original actual CCMP header")?;
        let held_sequence = u16::from_le_bytes([held_wire[22], held_wire[23]]) >> 4;
        h.model
            .complete(true)
            .map_err(|_| "periodic deadline actual old terminal")?;
        h.peer.lock().hold_data = false;
        h.model.now.set(31_000_000);
        h.env
            .now
            .store(31_000, core::sync::atomic::Ordering::Release);
        let beacon = { h.peer.lock().beacon() };
        h.model
            .inject(&beacon, 0)
            .map_err(|_| "periodic deadline actual peer beacon")?;
        let deferred = udp_ipv4(
            AP,
            h.plan.station,
            h.plan.lease_ip,
            h.plan.server_ip,
            49005,
            7,
            b"enqueue-first must defer before any source IO or PN",
        );
        let epoch = { h.device.radio.try_lock().unwrap().receive_epoch() };
        let waiting = { !h.device.radio.try_lock().unwrap().ready() };
        let before_io = h.model.count.get();
        let before_trace = { h.model.periodic.borrow().trace.len() };
        let before_tx = { h.model.transmitted.borrow().len() };
        check!(
            h.device.enqueue(&deferred, Default::default()).is_err(),
            "enqueue-first expired calibration falsely admitted DATA"
        );
        let after_io = h.model.count.get();
        let after_trace = { h.model.periodic.borrow().trace.len() };
        let after_tx = { h.model.transmitted.borrow().len() };
        let still_waiting = { !h.device.radio.try_lock().unwrap().ready() };
        let after_epoch = { h.device.radio.try_lock().unwrap().receive_epoch() };
        let same_dma = { h.model.dma_transmitted.borrow().last() == Some(&held_dma) };
        check!(
            waiting
                && still_waiting
                && before_io == after_io
                && before_trace == after_trace
                && before_tx == after_tx
                && same_dma
                && epoch == after_epoch
                && h.device.link_up()
                && h.model.master.get(),
            "enqueue-first deadline touched IO/original ticket or closed retained station"
        );
        check!(
            h.model
                .word(held_native + 92)
                .map_err(|_| "periodic retained DONE")?
                & 1
                != 0,
            "deferred admission discarded real old native completion"
        );
        h.pump(); // the retained poll owner now performs the actual quiet retry.
        let same_iq = h.model.registers.borrow()[&0x9920] & 0xfff == old_iq;
        check!(
            same_iq && h.device.link_up(),
            "timeout fabricated a fresh correction or lost retained station"
        );
        h.device
            .enqueue(&deferred, Default::default())
            .map_err(|_| "periodic real quiet retry did not restore DATA admission")?;
        h.pump();
        let next_wire = { h.model.transmitted.borrow().last().cloned().unwrap() };
        let next_header = if next_wire[0] == 0x88 { 26 } else { 24 };
        let (next_pn, _) = narf_wireless::ccmp::decode_ccmp_header(
            next_wire[next_header..next_header + 8].try_into().unwrap(),
        )
        .map_err(|_| "periodic post-retry actual CCMP header")?;
        let next_sequence = u16::from_le_bytes([next_wire[22], next_wire[23]]) >> 4;
        let delivered = { h.peer.lock().uplink.last() == Some(&deferred) };
        check!(
            delivered && next_pn == held_pn + 1 && next_sequence == ((held_sequence + 1) & 4095),
            "deferred enqueue consumed a PN/SC or actual quiet retry lost original DATA"
        );
        cap.revoke();
        h.pump();
        let pinned = { h.model.released.borrow().is_empty() };
        check!(
            h.closed() && !h.model.master.get() && pinned,
            "lost periodic source did not close BME and quarantine unproved mappings"
        );
    }
    {
        let (h, _) = profile(false);
        let before = h.model.registers.borrow()[&0x9920] & 0xfff;
        h.model.ignore.set(Some(0x9920));
        advance(&h, 1_000_000)?;
        let unchanged = h.model.registers.borrow()[&0x9920] & 0xfff == before;
        check!(
            h.closed() && unchanged && !h.model.master.get(),
            "ignored calibration write minted live native receipt"
        );
    }
    Ok(())
}
fn smoke_ar9285_periodic_native_pending_ticket_timeout_revocation_and_ignored_write() -> TestResult
{
    let _policy = crate::ath9k::ht::tests::Policy::install();
    verdict(negative)
}
kernel_test_in!(
    "drivers/wireless/ath9k/periodic",
    smoke_ar9285_periodic_native_pending_ticket_timeout_revocation_and_ignored_write
);
