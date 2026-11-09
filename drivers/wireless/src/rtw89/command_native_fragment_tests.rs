// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual Native/NativeIo/Core/retained-DMA publication, with explicit inert
//! PCI/RFK/authenticated-record startup. No physical attach/calibration claim.
use super::*;
use crate::rtw89::{
    fragment_wire, packet_core as packet, radio_policy, rx_packet, station_control,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const AP: [u8; 6] = [2, 3, 5, 7, 11, 13];
struct FragmentFixture(Fixture);
impl Drop for FragmentFixture {
    fn drop(&mut self) {
        // SAFETY: same private inert DMA/RAM; all Native operations ended and
        // no hardware, prefetch or concurrent producer has ever existed.
        unsafe {
            if let Some(core) = self.0.native.station_runtime.core.as_mut() {
                core.reclaim_fenced();
            }
            self.0.native.receive.reclaim_fenced();
        }
    }
}
fn setup() -> (
    FragmentFixture,
    station_control::Admission,
    Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
) {
    let mut f = Fixture::aperture(ChipId::Rtl8852B, 0x20000).unwrap();
    f.activate().unwrap();
    let (qualification, base, companion) = radio_policy::tests::fragment_model(None);
    f.native.ordinary = Some(OrdinaryGrant::B(Arc::new(qualification)));
    let (admission, peer) = crate::rtw89::lps::tests::peer();
    f.native.station_runtime.peer = Some(peer);
    f.native.receive = crate::rtw89::rx_dma::tests::native_fixture();
    let (core, registers) = packet::tests::native_fragment_core(OWN).unwrap();
    for (a, v) in registers {
        f.words[a as usize / 4] = v;
    }
    f.native.station_runtime.core = Some(core);
    f.native.station_runtime.model_started();
    (FragmentFixture(f), admission, base, companion)
}
fn frames() -> Vec<Vec<u8>> {
    let mut bytes = vec![8, 1, 0, 0];
    bytes.extend_from_slice(&AP);
    bytes.extend_from_slice(&OWN);
    bytes.extend_from_slice(&[2, 1, 1, 1, 1, 1]);
    bytes.extend_from_slice(&0x3250u16.to_le_bytes());
    bytes.extend_from_slice(&[0x59; 600]);
    let mut parts = fragment_wire::split(&bytes, 256).unwrap();
    fragment_wire::durations(&mut parts).unwrap();
    parts
}
fn report(snapshot: &packet::tests::FragmentSnapshot) -> rx_packet::Event {
    // Actual independent RPQ encoding -> original RXBD/RXD/RPQ parser.
    let mut bytes = vec![0; 24];
    bytes[..4].copy_from_slice(&(24u32 | 1 << 15 | 1 << 14).to_le_bytes());
    bytes[4..8].copy_from_slice(&(4u32 | 7 << 24).to_le_bytes());
    let release = u32::from(snapshot.ticket.sequence) << 16 | u32::from(snapshot.queue.qsel()) << 8;
    bytes[20..24].copy_from_slice(&release.to_le_bytes());
    rx_packet::Assembler::default()
        .segment(&bytes, true)
        .unwrap()
        .unwrap()
}
fn terminal() -> Result<(), &'static str> {
    let (mut f, admission, _, _) = setup();
    let parts = frames();
    let train =
        f.0.native
            .fragment_binding(&admission)
            .map_err(|_| "native precrypto binding")?
            .plain(parts.clone())
            .map_err(|_| "native original immutable train")?;
    for (number, expected) in parts.iter().enumerate() {
        let part = train.next().ok_or("next exact terminal fragment")?;
        let id =
            f.0.native
                .submit_fragment(&part, false)
                .map_err(|_| "actual Native fragment issue")?;
        if train.next().is_some()
            || part.current().is_ok()
            || f.0.native.submit_fragment(&part, false) != Err(packet::Error::Busy)
        {
            return Err("issued fragment allowed reuse or premature next part");
        }
        let snapshot =
            f.0.native
                .station_runtime
                .core
                .as_ref()
                .unwrap()
                .model_fragment()
                .map_err(|_| "actual fragment DMA snapshot")?
                .ok_or("retained issued maps")?;
        let word =
            |offset| u32::from_le_bytes(snapshot.header[offset..offset + 4].try_into().unwrap());
        if snapshot.id != id
            || &snapshot.body != expected
            || word(0) & 7 != 0
            || word(12) & 0xfff != 0x325
            || word(12) & 1 << 12 != 0
            || word(24) != 1 << 30 | 1 << 10
            || snapshot.body[22] & 15 != number as u8
            || snapshot.descriptors[usize::from(snapshot.ticket.slot) * 8..][..2]
                != 64u16.to_le_bytes()
        {
            return Err("native descriptor altered original fragment SW_SN/rate/NAV/bytes");
        }
        let idx = snapshot.queue.regs().idx as usize / 4;
        // DMA read pointer alone cannot release retained bytes or advance train.
        f.0.words[idx] = u32::from(snapshot.next) << 16 | u32::from(snapshot.next);
        if f.0
            .native
            .poll_packets()
            .map_err(|_| "native DMA-only poll")?
            .receipt
            .is_some()
            || train.next().is_some()
        {
            return Err("DMA-only consumption retired fragment before exact RPQ");
        }
        f.0.native
            .retain_event(report(&snapshot))
            .map_err(|_| "actual parsed RPQ retain")?;
        let receipt =
            f.0.native
                .poll_packets()
                .map_err(|_| "native RPQ terminal poll")?
                .receipt
                .ok_or("actual two-fact fragment terminal")?;
        if receipt.id != id || receipt.bytes != *expected || !receipt.radio_acknowledged {
            return Err("native fragment terminal byte/identity/status mismatch");
        }
    }
    if !train.complete() || train.next().is_some() {
        return Err("whole train did not terminate once");
    }
    Ok(())
}
fn smoke_rtw8852b_fragment_native_original_descriptor_and_two_fact_terminal_train() -> TestResult {
    terminal().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_native_original_descriptor_and_two_fact_terminal_train
);
fn fences() -> Result<(), &'static str> {
    for loss in 0..6 {
        let (mut f, admission, base, companion) = setup();
        let train =
            f.0.native
                .fragment_binding(&admission)
                .map_err(|_| "original before loss")?
                .plain(frames())
                .map_err(|_| "original train before loss")?;
        let part = train.next().ok_or("original part")?;
        let ring = f.0.native.station_runtime.core.as_ref().unwrap();
        if ring.model_fragment().unwrap().is_some() {
            return Err("new native core already pending");
        }
        let idx = crate::rtw89::packet_format::Queue::Data.regs().idx as usize / 4;
        let before = f.0.words[idx];
        match loss {
            0 => {
                base.revoke();
            }
            1 => {
                companion.revoke();
            }
            2 => admission.close(),
            3 => {
                f.0.native.station_runtime.peer = Some(crate::rtw89::lps::tests::peer().1);
            }
            4 => {
                f.0.native.authority.revoke();
            }
            _ => {
                f.0.native.sleep_blocked = true;
            }
        }
        if f.0.native.submit_fragment(&part, false).is_ok()
            || f.0.words[idx] != before
            || f.0
                .native
                .station_runtime
                .core
                .as_ref()
                .unwrap()
                .model_fragment()
                .unwrap()
                .is_some()
        {
            return Err("lost original source/program/peer/awake grant published fragment");
        }
    }
    let (mut f, admission, _, _) = setup();
    let mut original_rx = vec![8, 2, 0, 0];
    original_rx.extend_from_slice(&OWN);
    original_rx.extend_from_slice(&AP);
    original_rx.extend_from_slice(&AP);
    original_rx.extend_from_slice(&[0, 0]);
    original_rx.extend_from_slice(&[0x61; 40]);
    crate::rtw89::rx_dma::tests::native_publish_one(&mut f.0.native.receive, &original_rx);
    let armed = Arc::new(AtomicBool::new(false));
    let observed = armed.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let record_attempts = attempts.clone();
    let rx = addr_set_for_chip(ChipId::Rtl8852B).rx[0].idx as usize;
    let ptr = f.0.words.as_mut_ptr() as usize + rx;
    let effect = Arc::new(move || {
        if observed.load(Ordering::Acquire) && record_attempts.fetch_add(1, Ordering::AcqRel) >= 1 {
            // SAFETY: exclusively retained inert MMIO RAM, original HCI RX producer,
            // no Rust alias/concurrent producer. Runs at actual final cap boundary.
            unsafe {
                (ptr as *mut u32).write_volatile(1 << 16);
            }
        }
    });
    let (qualification, _, _) = radio_policy::tests::fragment_model(Some(effect));
    f.0.native.ordinary = Some(OrdinaryGrant::B(Arc::new(qualification)));
    let train =
        f.0.native
            .fragment_binding(&admission)
            .map_err(|_| "prefix original binding")?
            .plain(frames())
            .map_err(|_| "prefix train")?;
    let part = train.next().ok_or("prefix part")?;
    armed.store(true, Ordering::Release);
    let idx = crate::rtw89::packet_format::Queue::Data.regs().idx as usize / 4;
    let before = f.0.words[idx];
    if f.0.native.submit_fragment(&part, false) != Err(packet::Error::Busy)
        || f.0.native.state != State::Active
        || part.current().is_err()
        || train.next().is_none()
        || f.0.words[idx] != before
        || f.0
            .native
            .station_runtime
            .core
            .as_ref()
            .unwrap()
            .model_fragment()
            .unwrap()
            .is_some()
    {
        return Err("final actual RX producer refusal consumed part or issued DMA instead of unpublished Busy");
    }
    // The SAME retained part may publish once the original prefix is actually
    // serviced; no new peer/key/program or ciphertext is captured.
    armed.store(false, Ordering::Release);
    let step =
        f.0.native
            .poll_packets()
            .map_err(|_| "actual deferred original RX prefix consumption")?;
    if !step.consumed_rx
        || step
            .frame
            .as_ref()
            .map(narf_wireless::station_security::RawFrame::bytes)
            != Some(original_rx.as_slice())
        || f.0.words[rx / 4] != 0x00010001
    {
        return Err("actual native RX prefix/consumer rearm was not observed");
    }
    if f.0.native.submit_fragment(&part, false).is_err() || train.next().is_some() {
        return Err("strictly unpublished Busy could not retry same original part");
    }
    // A SECOND producer arrives specifically after issue/BD publication but
    // before the actual native doorbell, independently of callback counts.
    let (mut late, admission, _, _) = setup();
    let rx = addr_set_for_chip(ChipId::Rtl8852B).rx[0].idx as usize;
    let ptr = late.0.words.as_mut_ptr() as usize + rx;
    let slot = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
        None::<alloc::sync::Weak<crate::rtw89::command_native::FragmentTrain>>,
    ));
    let observed = slot.clone();
    let effect = Arc::new(move || {
        let issued = observed
            .lock()
            .as_ref()
            .and_then(alloc::sync::Weak::upgrade)
            .is_some_and(|train| train.model_issued());
        if issued {
            // SAFETY: original exclusively retained private MMIO RAM; actual
            // source HCI producer changes only after the original issued flag.
            unsafe {
                (ptr as *mut u32).write_volatile(1 << 16);
            }
        }
    });
    let (qualification, _, _) = radio_policy::tests::fragment_model(Some(effect));
    late.0.native.ordinary = Some(OrdinaryGrant::B(Arc::new(qualification)));
    let train = late
        .0
        .native
        .fragment_binding(&admission)
        .map_err(|_| "late original binding")?
        .plain(frames())
        .map_err(|_| "late immutable train")?;
    *slot.lock() = Some(Arc::downgrade(&train));
    let part = train.next().ok_or("late original part")?;
    let idx = crate::rtw89::packet_format::Queue::Data.regs().idx as usize / 4;
    let before = late.0.words[idx];
    let result = late.0.native.submit_fragment(&part, false);
    let core = late
        .0
        .native
        .station_runtime
        .core
        .as_ref()
        .ok_or("late retained actual Core")?;
    let retained = core
        .model_fragment()
        .map_err(|_| "late retained issued DMA")?
        .ok_or("late refusal released uncertain DMA")?;
    if result != Err(packet::Error::Access)
        || late.0.native.state != State::Terminal
        || late.0.words[idx] != before
        || late.0.words[rx / 4] != 1 << 16
        || !train.model_issued()
        || train.next().is_some()
        || part.current().is_ok()
        || core.reclaimed()
        || retained.body != part.bytes()
        || retained.descriptors[..8] == [0; 8]
    {
        return Err("post-issue actual producer was ignored at final doorbell, downgraded to Busy, or released uncertain DMA");
    }
    Ok(())
}
fn smoke_rtw8852b_fragment_native_final_producer_loss_and_original_current_fences() -> TestResult {
    fences().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_native_final_producer_loss_and_original_current_fences
);
fn ppdu_step() -> Result<(), &'static str> {
    let (mut f, _, _, _) = setup();
    // MACID-matched PPDU status: RSSI + CFO reach the station tracker
    // and the classified observation reaches the diversity owner.
    f.0.native
        .retain_event(rx_packet::Event::PhyStatus(rx_packet::PhyStatus {
            mac_id: 0,
            rssi: 120,
            cfo: Some(-3),
            evm: 0x2a,
            class: rx_packet::PpduClass::Ofdm,
        }))
        .map_err(|_| "actual PPDU status retain")?;
    let step =
        f.0.native
            .poll_packets()
            .map_err(|_| "actual PPDU status poll")?;
    if step.rssi != Some(120)
        || step.cfo != Some(-3)
        || step.antdiv
            != Some(rx_packet::AntDivObservation {
                class: rx_packet::PpduClass::Ofdm,
                rssi: 120,
                evm: 0x2a,
            })
    {
        return Err("PPDU status did not reach the packet step");
    }
    // Another MACID's report is not this owner's observation.
    f.0.native
        .retain_event(rx_packet::Event::PhyStatus(rx_packet::PhyStatus {
            mac_id: 3,
            rssi: 90,
            cfo: None,
            evm: 0,
            class: rx_packet::PpduClass::Cck,
        }))
        .map_err(|_| "actual foreign PPDU status retain")?;
    let step =
        f.0.native
            .poll_packets()
            .map_err(|_| "actual foreign PPDU poll")?;
    if step.rssi.is_some() || step.cfo.is_some() || step.antdiv.is_some() {
        return Err("foreign MACID PPDU status reached this owner's step");
    }
    Ok(())
}
fn smoke_rtw89_b_packet_ppdu_status_feeds_antdiv_observation() -> TestResult {
    ppdu_step().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_ppdu_status_feeds_antdiv_observation
);
