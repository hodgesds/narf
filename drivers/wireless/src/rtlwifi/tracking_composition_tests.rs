// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual retained EE thermal RF/TXAGC/IQK/LCK and native DHCP/RSNA fixtures.
use super::*;
use crate::rtlwifi::{channel_power::Calibration, protection, tracking};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
fn require(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
fn factory() -> crate::rtlwifi::efuse::Factory {
    let mut f = power::factory();
    f.logical[0xba] = 24;
    f
}
fn harness(protected: bool, ht: bool) -> Harness {
    Harness::with_factory(protected, ht, None, false, factory())
}
type Sources = (
    Arc<Calibration>,
    Option<Arc<ht::Grant>>,
    Option<Arc<protection::Grant>>,
);
pub(super) fn sources(h: &Harness) -> Result<Sources, &'static str> {
    let (base, ht) = super::protection_tests::source(h)?;
    let source = h.device.environment_for_test().protection.lock().clone();
    let protection = source
        .map(|(channel, bytes, cap)| {
            protection::Grant::parse(
                base.clone(),
                h.firmware.identity().unwrap(),
                channel,
                ht.clone(),
                &bytes,
                Some([7; 32]),
                cap,
            )
            .map(Arc::new)
        })
        .transpose()
        .map_err(|_| "NETH actual preceding NERT")?;
    Ok((base, ht, protection))
}
pub(super) fn qualify(h: &Harness) -> Result<Cap<FirmwareBlob, Read>, &'static str> {
    let (base, ht, protection) = sources(h)?;
    let cap = Cap::bootstrap();
    let bytes = tracking::artifact(
        &base,
        h.firmware.identity().unwrap(),
        h.device.channel_for_test(),
        ht.as_deref(),
        protection.as_deref(),
    );
    *h.device.environment_for_test().tracking.lock() =
        Some((h.device.channel_for_test(), bytes, cap));
    Ok(cap)
}
fn join(h: &Harness) -> Result<(), &'static str> {
    h.scan();
    complete(h.device.associate(h.request())).map_err(|_| "NETH native MLME/RSNA")?;
    require(h.device.link_up(), "NETH native carrier")
}
fn gains(h: &Harness) -> Result<tracking::Gains, &'static str> {
    h.device
        .prepared
        .try_lock()
        .and_then(|owner| owner.as_ref().and_then(|o| o.tracking_for_test()))
        .map(|s| s.0)
        .ok_or("NETH native retained gain state")
}
fn heartbeat(h: &Harness) -> Result<(), &'static str> {
    let b = {
        let p = h.peer.lock();
        let mut b = p.ap.beacon();
        if let Some(w) = &p.wmm {
            b.extend_from_slice(w);
        }
        if let Some(ht) = &p.ht {
            b.extend_from_slice(ht);
        }
        if p.erp {
            b.extend_from_slice(&[42, 1, 2]);
        }
        b
    };
    h.packet.emit(&b).map_err(|_| "NETH native heartbeat RX")?;
    h.pump();
    Ok(())
}
/// Each real source step is one2s watchdog, preserving unrelated RF42 bits.
fn step(h: &Harness, raw: u8) -> Result<(), &'static str> {
    h.env.now.fetch_add(2000, Ordering::AcqRel);
    heartbeat(h)?;
    let old = h.packet.radio.rf(0x42);
    h.packet
        .radio
        .hardware_rf(0x42, (old & !0xfc00) | (u32::from(raw) << 10));
    complete(h.device.gain_tracking());
    require(h.device.link_up(), "NETH native watchdog failed")
}
fn sample(h: &Harness, raw: u8) -> Result<(), &'static str> {
    step(h, raw)?;
    step(h, raw)
}
fn data(h: &Harness) -> Result<(), &'static str> {
    let up = packet(h, 39, true);
    h.device
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "NETH actual IP enqueue")?;
    h.pump();
    require(
        h.peer.lock().uplink.last() == Some(&up),
        "NETH actual peer DATA/CCMP",
    )
}
fn smoke_rtl8188ee_thermal_signed_full_dimensional_identity_unknown_and_current_sources(
) -> TestResult {
    check(|| {
        let h = harness(true, true);
        super::protection_tests::qualify(&h)?;
        let (base, ht, protection) = sources(&h)?;
        let fw = h.firmware.identity().unwrap();
        let cap = Cap::bootstrap();
        let bytes = tracking::artifact(&base, fw, 1, ht.as_deref(), protection.as_deref());
        let parse = |b: &[u8], signer| {
            tracking::Grant::parse(
                base.clone(),
                fw,
                1,
                ht.clone(),
                protection.clone(),
                b,
                signer,
                cap,
            )
        };
        let q = parse(&bytes, Some([7; 32])).map_err(|_| "NETH exact signed parse")?;
        let domain = power::domain(17);
        let permission = base
            .permission(&domain, 1)
            .map_err(|_| "NETH primary permission")?;
        q.check_sources(&domain, permission)
            .map_err(|_| "NETH full program admission")?;
        for at in [
            0, 4, 6, 8, 12, 16, 48, 80, 112, 118, 119, 122, 128, 160, 192, 193, 196,
        ] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            require(
                parse(&bad, Some([7; 32])).is_err(),
                "NETH source/geometry/shape alias",
            )?;
        }
        require(parse(&bytes, None).is_err(), "NETH unsigned accepted")?;
        let selected = tracking::Gains::nominal(ht.as_deref(), &domain, permission)
            .map_err(|_| "NETH nominal gains")?;
        for (row, gain) in [
            (0, selected.cck[0]),
            (1, selected.ofdm[0]),
            (2, selected.mcs[0]),
        ] {
            // The CURRENT sensor may never visit63: one missing remote row
            // must still deny that index to cover autonomous/sample-gap TX.
            let mut bad = bytes.clone();
            let at = 256 + 63 * 10 * 128 + row * 128 + usize::from(gain) * 2;
            bad[at..at + 2].copy_from_slice(&i16::MAX.to_le_bytes());
            let unknown =
                parse(&bad, Some([7; 32])).map_err(|_| "NETH unknown dimensional parse")?;
            require(
                unknown.check_sources(&domain, permission).is_err(),
                "NETH interpolated missing remote thermal row",
            )?;
        }
        cap.revoke();
        require(
            q.check_sources(&domain, permission).is_err(),
            "NETH revoked qualification remained current",
        )?;
        require(
            !h.packet.model.lock().master,
            "NETH metadata started native DMA",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/tracking",
    smoke_rtl8188ee_thermal_signed_full_dimensional_identity_unknown_and_current_sources
);
fn smoke_rtl8188ee_thermal_open_wpa2_legacy_ht_native_dhcp_and_exact_gain_restore() -> TestResult {
    check(|| {
        for protected in [false, true] {
            for ht in [false, true] {
                let h = harness(protected, ht);
                qualify(&h)?;
                join(&h)?;
                let nominal = gains(&h)?;
                let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
                    .map_err(|_| "NETH native DHCP DORA")?;
                require(h.peer.lock().plan.matches_lease(&lease), "NETH DORA lease")?;
                sample(&h, 20)?; // EEPROM24, delta4 -> exact cold swing+2 -> TXAGC-2.
                let reduced = gains(&h)?;
                require(
                    reduced.cck == nominal.cck.map(|g| g.saturating_sub(2))
                        && reduced.ofdm == nominal.ofdm.map(|g| g.saturating_sub(2))
                        && reduced.mcs == nominal.mcs.map(|g| g.saturating_sub(2)),
                    "NETH literal source TXAGC reduction",
                )?;
                require(
                    h.packet.radio.rf(0x42) & 0x30000 == 0x30000,
                    "NETH actual RF42 trigger",
                )?;
                require(
                    (h.packet.radio.word(0xe08) >> 8) as u8 == reduced.cck[0]
                        && h.packet.radio.word(0xe00)
                            == u32::from_le_bytes(reduced.ofdm[..4].try_into().unwrap())
                        && h.packet.radio.word(0xe10)
                            == u32::from_le_bytes(reduced.mcs[..4].try_into().unwrap()),
                    "NETH real TXAGC readbacks",
                )?;
                data(&h)?;
                // Four hotter samples replace every cold averaging slot. A source
                // boost restores the preceding qualified point and never exceeds it.
                for _ in 0..4 {
                    sample(&h, 32)?;
                }
                require(
                    gains(&h)? == nominal,
                    "NETH average4 restoration exceeded/failed original ceiling",
                )?;
                data(&h)?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/tracking",
    smoke_rtl8188ee_thermal_open_wpa2_legacy_ht_native_dhcp_and_exact_gain_restore
);
fn smoke_rtl8188ee_thermal_ht40_rts_native_program_and_fallback_geometry_compose() -> TestResult {
    check(|| {
        for (primary, secondary) in [(1, 5), (6, 2)] {
            for narrow in [false, true] {
                let w = super::ht40_tests::Wide::with_factory(true, primary, secondary, factory())?;
                if narrow {
                    let mut e = ht::tests::ap_elements(255);
                    e[30] = primary;
                    let mut peer = w.h.peer.lock();
                    peer.response_ht = Some(e);
                    peer.ht40 = false;
                }
                super::protection_tests::qualify(&w.h)?;
                w.h.device
                    .set_rts_threshold(0)
                    .map_err(|_| "NETH actual RTS setting")?;
                qualify(&w.h)?;
                w.join()?;
                let rf = w.h.packet.radio.rf(0x18);
                let nominal = gains(&w.h)?;
                sample(&w.h, 20)?;
                require(
                    gains(&w.h)?.mcs == nominal.mcs.map(|g| g.saturating_sub(2)),
                    "NETH wide/narrow gain reduction",
                )?;
                let expected = if narrow {
                    0xc00 | u32::from(primary)
                } else {
                    0x400 | u32::from((primary + secondary) / 2)
                };
                require(
                    w.h.packet.radio.rf(0x18) == rf && rf & 0xfff == expected,
                    "NETH RF primary/center/BW changed with TX power",
                )?;
                data(&w.h)?;
                let m = w.h.packet.model.lock();
                let d = m.descriptors.last().ok_or("NETH width descriptor")?;
                require(
                    word(d, 16) & 0xfc00381f == 0x1008
                        && word(d, 16) & 0x02300000 == if narrow { 0 } else { 0x02300000 },
                    "NETH actual width/SC/RTS24 descriptor",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/tracking",
    smoke_rtl8188ee_thermal_ht40_rts_native_program_and_fallback_geometry_compose
);
fn smoke_rtl8188ee_thermal_drift_repeats_real_iqk_lck_and_restores_native_radio() -> TestResult {
    check(|| {
        let h = harness(true, true);
        qualify(&h)?;
        join(&h)?;
        sample(&h, 24)?;
        let rf18 = h.packet.radio.rf(0x18);
        let rf0 = h.packet.radio.rf(0);
        let start = h.packet.radio.trace().len();
        sample(&h, 8)?; // Average(24,8)=16: exactly8 since real calibration reference.
        let trace = h.packet.radio.trace();
        let suffix = &trace[start..];
        require(
            suffix
                .iter()
                .any(|(w, reg, v)| *w == 32 && *reg == 0xe48 && *v == 0xf8000000),
            "NETH skipped actual IQK measurement",
        )?;
        require(
            suffix.iter().any(|(w, reg, v)| {
                *w == 32 && *reg == 0x840 && *v >> 20 == 0x18 && *v & 0x8000 != 0
            }),
            "NETH skipped actual LCK trigger",
        )?;
        require(
            h.packet.radio.rf(0x18) == rf18
                && h.packet.radio.rf(0) == rf0
                && h.packet.radio.hardware_read8(0x100) & 0xc0 == 0xc0
                && h.packet.radio.hardware_read8(0x522) == 0,
            "NETH calibration restore failed",
        )?;
        let state = h
            .device
            .prepared
            .try_lock()
            .and_then(|o| o.as_ref().and_then(|o| o.tracking_for_test()));
        require(
            state.is_some_and(|s| s.1 == Some(16) && s.2 == Some(16)),
            "NETH advanced thermal calibration reference without result",
        )?;
        data(&h)
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/tracking",
    smoke_rtl8188ee_thermal_drift_repeats_real_iqk_lck_and_restores_native_radio
);
fn smoke_rtl8188ee_thermal_unknown_asset_sensor_and_native_write_faults_fail_closed() -> TestResult
{
    check(|| {
        for fault in 0..5 {
            let h = harness(true, true);
            qualify(&h)?;
            if fault == 0 {
                let mut source = h.device.environment_for_test().tracking.lock();
                source.as_mut().unwrap().1[256..256 + 10 * 128].fill(0x7f);
                h.scan();
                let kicks = h.packet.model.lock().kicks.len();
                require(
                    complete(h.device.associate(h.request())).is_err(),
                    "NETH invalid thermal bounds admitted auth",
                )?;
                require(
                    h.packet.model.lock().kicks.len() == kicks && !h.device.link_up(),
                    "NETH invalid bounds emitted auth",
                )?;
                continue;
            }
            join(&h)?;
            step(&h, 20)?;
            if fault == 2 {
                h.packet.radio.ignore(0xe00);
            }
            if fault == 3 {
                h.packet.radio.hardware_word(0x5f8, 1);
            }
            if fault == 4 {
                h.packet.radio.bad_calibration();
            }
            h.env.now.fetch_add(2000, Ordering::AcqRel);
            heartbeat(&h)?;
            let raw: u8 = if fault == 1 { 0 } else { 20 };
            h.packet
                .radio
                .hardware_rf(0x42, 0x30000 | (u32::from(raw) << 10));
            complete(h.device.gain_tracking());
            if fault == 4 {
                // First valid sample establishes the measured reference. A
                // subsequent large drift must use the bad native IQK result.
                require(h.device.link_up(), "NETH premature calibration failure")?;
                step(&h, 1)?;
                h.env.now.fetch_add(2000, Ordering::AcqRel);
                heartbeat(&h)?;
                h.packet.radio.hardware_rf(0x42, 0x30000 | (1 << 10));
                complete(h.device.gain_tracking());
            }
            require(
                !h.device.link_up() && !h.packet.model.lock().master,
                "NETH sensor/write/scheduler/calibration failure left native TX open",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/tracking",
    smoke_rtl8188ee_thermal_unknown_asset_sensor_and_native_write_faults_fail_closed
);
fn smoke_rtl8188ee_thermal_revoked_m4_and_cancelled_rf_wait_retain_real_dma() -> TestResult {
    check(|| {
        let h = harness(true, true);
        let cap = qualify(&h)?;
        h.peer.lock().hold_m4 = true;
        h.scan();
        let mut joining = Box::pin(h.device.associate(h.request()));
        let mut held = false;
        for _ in 0..4096 {
            require(
                joining
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "NETH M4 completed before OWN",
            )?;
            if h.packet.model.lock().held.is_some() {
                held = true;
                break;
            }
        }
        require(held, "NETH native M4 OWN hold absent")?;
        let drops = h.packet.drops.load(Ordering::Acquire);
        cap.revoke();
        require(
            complete(joining).is_err() && !h.device.link_up(),
            "NETH revoked M4 admitted controlled port",
        )?;
        require(
            h.packet.model.lock().held.is_some() && h.packet.drops.load(Ordering::Acquire) == drops,
            "NETH revoked M4 forged DMA retirement",
        )?;
        drop(h);
        let h = harness(true, true);
        qualify(&h)?;
        join(&h)?;
        h.packet.radio.pause_after(1);
        let before = h.packet.radio.trace().len();
        let mut future = Box::pin(h.device.gain_tracking());
        require(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "NETH RF delay did not retain native future",
        )?;
        drop(future);
        h.pump();
        require(
            !h.device.link_up() && !h.packet.model.lock().master,
            "NETH cancelled native RF read reopened owner",
        )?;
        require(
            !h.packet.radio.trace()[before..]
                .iter()
                .any(|(_, reg, _)| matches!(*reg, 0xe00 | 0xe04 | 0xe10 | 0xe14)),
            "NETH cancelled sensor wait reached gain writes",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/tracking",
    smoke_rtl8188ee_thermal_revoked_m4_and_cancelled_rf_wait_retain_real_dma
);
