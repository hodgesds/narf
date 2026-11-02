// SPDX-License-Identifier: GPL-2.0-or-later
//! Fresh reset/EEPROM/20->40 calibration with actual periodic ADC/IQ/PA/NF
//! and retained T4/QoS/key/native descriptors. No board measurements supplied.
use super::*;
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
fn advance(owner: &Arc<Owner>, now: u64) -> Result<(), &'static str> {
    let model = owner.model();
    let clock = { owner.clocks.lock().last().unwrap().clone() };
    model.now.set(now);
    clock.now.store(now / 1000, Ordering::Release);
    let previous = model.last_rx.get().ok_or("periodic wide prior RX tail")?;
    let beacon = { owner.peer().lock().beacon() };
    model
        .inject(&beacon, 0)
        .map_err(|_| "periodic wide real current-peer beacon")?;
    let device = owner.device();
    for _ in 0..24 {
        device.drain();
        let terminal = {
            device
                .radio
                .try_lock()
                .is_some_and(|radio| radio.terminal())
        };
        if terminal || model.word(previous + 48).is_ok_and(|word| word & 1 == 0) {
            return Ok(());
        }
    }
    Err("periodic wide beacon lacks actual prior-tail rearm or terminal owner")
}
fn actual_width() -> Result<(), &'static str> {
    for width in [Width::FortyAbove, Width::FortyBelow] {
        for protected in [false, true] {
            let mut selected = spec(width, 3, protected);
            selected.large = true;
            selected.periodic = true;
            let owner = Owner::new(selected);
            owner
                .join()
                .map_err(|_| "periodic full-reset native40 join")?;
            network(&owner)?;
            let device = owner.device();
            let model = owner.model();
            let base = { model.ht.borrow().clone().unwrap() };
            let identity = base.ba_identity();
            let original = { model.wide.borrow().unwrap() };
            let epoch = { device.radio.try_lock().unwrap().receive_epoch() };
            for (index, mode) in [1u32, 2, 0].into_iter().enumerate() {
                let now = (index as u64 + 1) * 1_000_000;
                advance(&owner, now)?;
                let actual_mode = model.registers.borrow()[&0x99f0];
                let running = model.registers.borrow()[&0x9920] & 0x10000 != 0;
                check!(
                    actual_mode == mode && running,
                    "actual HT40 ADCgain/DC/IQ source list missing or reordered"
                );
                network(&owner)?; // actual DATA and native original receipts under old coefficients.
                advance(&owner, now + 100)?;
            }
            let actual_adc = model.registers.borrow()[&0x99b4];
            let actual_iq = model.registers.borrow()[&0x9920] & 0xfff;
            let expected_old_iq =
                0x800 | (u32::from(original.report.iq_i) << 5) | (original.report.iq_q as u32 & 31);
            let same_initial = { model.wide.borrow().as_ref() == Some(&original) };
            let after_epoch = { device.radio.try_lock().unwrap().receive_epoch() };
            check!(
                actual_adc != original.adc
                    && actual_iq != expected_old_iq
                    && same_initial
                    && after_epoch == epoch,
                "periodic40 lacked actual new ADC/IQ or rewrote original H/key receipt"
            );
            check!(
                base.ba_identity() == identity && base.readback(&model).is_ok(),
                "periodic40 aliased original signed H or dynamic readback failed"
            );
            let peer = owner.peer();
            let plan = { peer.lock().plan };
            let frames: Vec<Vec<u8>> = (0..8)
                .map(|index| {
                    udp_ipv4(
                        AP,
                        plan.station,
                        plan.lease_ip,
                        plan.server_ip,
                        4920 + index,
                        7,
                        &[index as u8; 32],
                    )
                })
                .collect();
            for frame in &frames {
                device
                    .enqueue(frame, narf_net::TxMeta::plain())
                    .map_err(|_| "periodic40 eight-original IPC enqueue")?;
            }
            owner.pump();
            let chain = { model.last_chain.borrow().clone() };
            let delivered = { peer.lock().uplink.ends_with(&frames) };
            check!(
                chain.len() == 8 && delivered,
                "periodic40 changed actual eight-member BA/PN/SC/native original ownership"
            );
            let flags = model
                .word(chain[0] + 36)
                .map_err(|_| "periodic40 actual descriptor")?;
            let nominal = { owner.models.lock()[0].clone() };
            let old_released = { !nominal.released.borrow().is_empty() };
            check!(
                flags & 3 == 3
                    && old_released
                    && !nominal.master.get()
                    && device.channel_geometry() == Some(selected.geometry),
                "periodic40 changed SGI/center geometry or old-generation terminal proof"
            );
            network(&owner)?;
        }
    }
    Ok(())
}
fn smoke_ar9285_periodic_full_reset_ht40_adc_iq_both_extensions_eight_originals_and_dhcp(
) -> TestResult {
    let _policy = policy();
    verdict(actual_width)
}
kernel_test_in!(
    "drivers/wireless/ath9k/periodic",
    smoke_ar9285_periodic_full_reset_ht40_adc_iq_both_extensions_eight_originals_and_dhcp
);

fn faults() -> Result<(), &'static str> {
    {
        let mut selected = spec(Width::FortyBelow, 0, true);
        selected.periodic = true;
        selected.large = true;
        selected.factory = Some(calibration::tests::factory::Selection {
            minor: 3,
            high: true,
            xe2: true,
            big: true,
            swapped: true,
        });
        let owner = Owner::new(selected);
        owner
            .join()
            .map_err(|_| "periodic high-power BE actual40 join")?;
        network(&owner)?;
        let device = owner.device();
        let model = owner.model();
        let high_power = { model.wide.borrow().unwrap().report.pa_offset.is_none() };
        check!(
            high_power,
            "periodic high-power factory did not preserve actual initial PA branch"
        );
        for index in 1..=3 {
            advance(&owner, index * 1_000_000)?;
            advance(&owner, index * 1_000_000 + 100)?;
        }
        advance(&owner, 30_000_000)?;
        advance(&owner, 30_000_100)?;
        let pa_written = {
            model
                .periodic
                .borrow()
                .trace
                .iter()
                .any(|&(register, value)| register == 0x7868 && value == 0xca0358a0)
        };
        check!(
            !pa_written && device.link_up(),
            "periodic high-power branch invented PA calibration"
        );
        {
            let mut state = model.periodic.borrow_mut();
            state.hold_nf_load = true;
            state.delay_jump = 222_000;
        }
        advance(&owner, 60_000_000)?;
        advance(&owner, 60_000_100)?;
        let low = model.registers.borrow()[&0x9864] & 511;
        let failed = { model.periodic.borrow().failed };
        let pinned = { model.released.borrow().is_empty() };
        check!(
            failed
                && !device.link_up()
                && !model.master.get()
                && pinned
                && low != ((-50i32 as u32) << 1 & 511),
            "wedged median load restored maxCCA or released unproved DMA"
        );
        let before = { model.transmitted.borrow().len() };
        {
            let mut state = model.periodic.borrow_mut();
            state.hold_nf_load = false;
            state.delay_jump = 0;
        }
        owner.pump();
        let after = { model.transmitted.borrow().len() };
        check!(
            !device.link_up() && before == after,
            "repaired hardware reopened retired periodic owner"
        );
    }
    {
        let mut selected = spec(Width::FortyAbove, 3, true);
        selected.periodic = true;
        selected.periodic_low_child = true;
        selected.large = true;
        let owner = Owner::new(selected);
        // Association can finish before the optional P worker's first idle
        // bind. Drive that actual native admission boundary; an early public
        // join return neither proves nor bypasses a P current-child check.
        let _joined = owner.join();
        let model = owner.model();
        for _ in 0..24 {
            owner.device().drain();
            if owner
                .device()
                .radio
                .try_lock()
                .is_some_and(|radio| radio.terminal())
            {
                break;
            }
        }
        let (source, attempted, untouched) = {
            let state = model.periodic.borrow();
            let source = state.source.clone().unwrap();
            let attempted = state
                .bound
                .as_ref()
                .is_some_and(|bound| Arc::ptr_eq(bound, &source));
            (source, attempted, state.trace.is_empty())
        };
        let child_current = {
            let child = model.tx_ba.borrow().clone().unwrap();
            child.signed_ceiling() == 24 && child.check().is_ok()
        };
        check!(
            attempted && child_current && !owner.device().link_up() && !model.master.get(),
            "P global peak bypassed actually installed child signed ceiling"
        );
        check!(
            source.check().is_ok() && untouched && !owner.device().link_up() && !model.master.get(),
            "child ceiling rejection used unsigned source or changed calibration hardware"
        );
    }
    Ok(())
}
fn smoke_ar9285_periodic_factory_high_power_nf_load_timeout_and_child_current_ceiling() -> TestResult
{
    let _policy = policy();
    verdict(faults)
}
kernel_test_in!(
    "drivers/wireless/ath9k/periodic",
    smoke_ar9285_periodic_factory_high_power_nf_load_timeout_and_child_current_ceiling
);
