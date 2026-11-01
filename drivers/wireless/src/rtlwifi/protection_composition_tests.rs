// SPDX-License-Identifier: GPL-2.0-or-later
//! Native EE RTS/CTS descriptors, current measurements and terminal DMA owners.
use super::*;
use crate::rtlwifi::{channel_power::Calibration, protection};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
fn require(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
pub(super) fn source(
    h: &Harness,
) -> Result<(Arc<Calibration>, Option<Arc<ht::Grant>>), &'static str> {
    let channel = h.device.channel_for_test();
    let base = Arc::new(if channel == 1 {
        power::calibration(h.device.factory_for_test())
    } else {
        power::calibration_for_channel(h.device.factory_for_test(), channel)
    });
    let wide = h.device.environment_for_test().ht_wide.lock().clone();
    let bytes = if let Some((_, bytes, cap)) = wide {
        Some((bytes, cap, h.firmware.identity().unwrap()))
    } else {
        h.ht_source
            .as_ref()
            .map(|(bytes, cap, fw)| (bytes.lock().clone(), *cap, *fw))
    };
    let ht = bytes
        .map(|(b, cap, fw)| {
            ht::Grant::parse(base.clone(), fw, &b, Some([7; 32]), cap).map(Arc::new)
        })
        .transpose()
        .map_err(|_| "NERT native fixture HT source")?;
    Ok((base, ht))
}
pub(super) fn qualify(h: &Harness) -> Result<Cap<FirmwareBlob, Read>, &'static str> {
    let (base, ht) = source(h)?;
    let cap = Cap::bootstrap();
    let channel = h.device.channel_for_test();
    let bytes = protection::artifact(
        &base,
        h.firmware.identity().unwrap(),
        channel,
        ht.as_deref(),
    );
    *h.device.environment_for_test().protection.lock() = Some((channel, bytes, cap));
    Ok(cap)
}
fn join(h: &Harness) -> Result<(), &'static str> {
    h.scan();
    complete(h.device.associate(h.request())).map_err(|_| "NERT native MLME/RSNA")?;
    require(h.device.link_up(), "NERT carrier")
}
fn data(h: &Harness, mode: u32) -> Result<(), &'static str> {
    let up = packet(h, 21, true);
    h.device
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "NERT actual IP enqueue")?;
    h.pump();
    require(
        h.peer.lock().uplink.last() == Some(&up),
        "NERT original plaintext/CCMP DATA",
    )?;
    let model = h.packet.model.lock();
    let d = model
        .descriptors
        .last()
        .ok_or("NERT actual descriptor absent")?;
    require(
        word(d, 16) & 0xfc00381f == mode,
        "NERT literal RTS24/CTS/HW/BW/SC/STBC fields",
    )?;
    require(
        word(d, 20) & 0x1e000 == 0x1e000,
        "NERT actual source RTS fallback limit",
    )
}
fn smoke_rtl8188ee_rts_cts_signed_full_program_identity_and_unknown_bounds() -> TestResult {
    check(|| {
        let h = Harness::new_profile(true, true);
        let (base, ht) = source(&h)?;
        let fw = h.firmware.identity().unwrap();
        let cap = Cap::bootstrap();
        let bytes = protection::artifact(&base, fw, 1, ht.as_deref());
        let q =
            protection::Grant::parse(base.clone(), fw, 1, ht.clone(), &bytes, Some([7; 32]), cap)
                .map_err(|_| "NERT exact parse")?;
        let domain = power::domain(17);
        let permission = base
            .permission(&domain, 1)
            .map_err(|_| "NERT primary permission")?;
        q.check(&domain, permission)
            .map_err(|_| "NERT selected gain envelope")?;
        for at in [
            0, 4, 6, 8, 12, 16, 48, 80, 112, 118, 119, 120, 121, 122, 123, 128, 160,
        ] {
            let mut wrong = bytes.clone();
            wrong[at] ^= 1;
            require(
                protection::Grant::parse(
                    base.clone(),
                    fw,
                    1,
                    ht.clone(),
                    &wrong,
                    Some([7; 32]),
                    cap,
                )
                .is_err(),
                "NERT foreign/old/geometry/HT measurement alias",
            )?;
        }
        for row in [0, 1, 2] {
            let mut unknown = bytes.clone();
            for v in unknown[192 + row * 128..192 + (row + 1) * 128].chunks_exact_mut(2) {
                v.copy_from_slice(&i16::MAX.to_le_bytes());
            }
            let q = protection::Grant::parse(
                base.clone(),
                fw,
                1,
                ht.clone(),
                &unknown,
                Some([7; 32]),
                cap,
            )
            .map_err(|_| "NERT unknown parse")?;
            require(
                q.check(&domain, permission).is_err(),
                "NERT invented RTS/control/MCS peak",
            )?;
        }
        require(
            protection::Grant::parse(base.clone(), fw, 1, ht.clone(), &bytes, None, cap).is_err(),
            "NERT unsigned record",
        )?;
        cap.revoke();
        require(
            q.check(&domain, permission).is_err(),
            "NERT revoked source remained current",
        )?;
        let model = h.packet.model.lock();
        require(
            !model.master && model.kicks.is_empty(),
            "NERT pure measurement performed native DMA",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/protection",
    smoke_rtl8188ee_rts_cts_signed_full_program_identity_and_unknown_bounds
);
fn smoke_rtl8188ee_cts_erp_open_wpa2_legacy_ht_native_dhcp_and_ip() -> TestResult {
    check(|| {
        for protected in [false, true] {
            for ht in [false, true] {
                let h = Harness::new_profile(protected, ht);
                h.peer.lock().erp = true;
                qualify(&h)?;
                join(&h)?;
                let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
                    .map_err(|_| "NERT ERP actual DHCP")?;
                require(
                    h.peer.lock().plan.matches_lease(&lease),
                    "NERT ERP DORA terms",
                )?;
                data(&h, 0x808)?;
                let model = h.packet.model.lock();
                require(
                    model
                        .observed
                        .iter()
                        .zip(&model.descriptors)
                        .filter(|(f, _)| matches!(f.first(), Some(0 | 0xb0)))
                        .all(|(_, d)| word(d, 16) & 0x381f == 0),
                    "NERT CTS decorated native authentication/association",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/protection",
    smoke_rtl8188ee_cts_erp_open_wpa2_legacy_ht_native_dhcp_and_ip
);
fn smoke_rtl8188ee_rts_threshold_native_boundary_and_cts_precedence() -> TestResult {
    check(|| {
        let h = Harness::new_profile(true, true);
        h.peer.lock().erp = true;
        qualify(&h)?;
        join(&h)?;
        data(&h, 0x808)?;
        let length = h
            .packet
            .model
            .lock()
            .observed
            .last()
            .ok_or("NERT original air length")?
            .len()
            + 4;
        let iface: &dyn WirelessNetIface = h.device.as_ref();
        require(
            iface.rts_threshold() == Some(u32::MAX),
            "NERT SET_WIPHY default",
        )?;
        require(
            iface.set_rts_threshold(2348) == Err(-22),
            "NERT invalid wiphy threshold",
        )?;
        require(
            iface.rts_threshold() == Some(u32::MAX),
            "NERT invalid setting mutated policy",
        )?;
        iface
            .set_rts_threshold(length as u32)
            .map_err(|_| "NERT trait exact threshold")?;
        require(
            iface.rts_threshold() == Some(length as u32),
            "NERT wiphy setting not retained",
        )?;
        data(&h, 0x808)?;
        iface
            .set_rts_threshold(length as u32 - 1)
            .map_err(|_| "NERT trait boundary threshold")?;
        data(&h, 0x1008)?;
        complete(iface.disassociate()).map_err(|_| "NERT wiphy disconnect")?;
        require(
            iface.rts_threshold() == Some(length as u32 - 1),
            "NERT station reset lost physical policy",
        )?;
        join(&h)?;
        data(&h, 0x1008)?;
        iface
            .set_rts_threshold(u32::MAX)
            .map_err(|_| "NERT trait disable")?;
        require(
            iface.rts_threshold() == Some(u32::MAX),
            "NERT disable not reported",
        )?;
        data(&h, 0x808)?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/protection",
    smoke_rtl8188ee_rts_threshold_native_boundary_and_cts_precedence
);
fn smoke_rtl8188ee_rts_cts_ht40_source_fields_preserve_wide_data_and_security() -> TestResult {
    check(|| {
        for cts in [false, true] {
            let w = super::ht40_tests::Wide::new(true, 1, 5)?;
            w.h.peer.lock().erp = cts;
            qualify(&w.h)?;
            if !cts {
                w.h.device
                    .set_rts_threshold(0)
                    .map_err(|_| "NERT wide wiphy threshold")?;
            }
            w.join()?;
            data(&w.h, if cts { 0x808 } else { 0x1008 })?;
            let model = w.h.packet.model.lock();
            let d = model
                .descriptors
                .last()
                .ok_or("NERT wide native DATA absent")?;
            require(
                word(d, 16) & 0x02300000 == 0x02300000 && word(d, 20) & 0x40 == 0,
                "NERT protection changed actual BW40/SC3/LGI",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/protection",
    smoke_rtl8188ee_rts_cts_ht40_source_fields_preserve_wide_data_and_security
);
fn smoke_rtl8188ee_rts_cts_missing_or_unknown_asset_refuses_before_auth_tx() -> TestResult {
    check(|| {
        for bad in [false, true] {
            let h = Harness::new_profile(true, true);
            h.peer.lock().erp = true;
            if bad {
                qualify(&h)?;
                let mut source = h.device.environment_for_test().protection.lock();
                for v in source.as_mut().unwrap().1[192..320].chunks_exact_mut(2) {
                    v.copy_from_slice(&i16::MAX.to_le_bytes());
                }
            }
            h.scan();
            let before = h.packet.model.lock().kicks.len();
            require(
                complete(h.device.associate(h.request())).is_err(),
                "NERT missing/unknown measurement emitted protected program",
            )?;
            require(
                h.packet.model.lock().kicks.len() == before && !h.device.link_up(),
                "NERT bad qualification reached native auth/data",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/protection",
    smoke_rtl8188ee_rts_cts_missing_or_unknown_asset_refuses_before_auth_tx
);
fn smoke_rtl8188ee_rts_cts_live_erp_and_source_loss_keep_held_m4_dma() -> TestResult {
    check(|| {
        let h = Harness::new_profile(false, true);
        qualify(&h)?;
        join(&h)?;
        data(&h, 0)?;
        let beacon = {
            let p = h.peer.lock();
            let mut b = p.ap.beacon();
            b.extend_from_slice(p.wmm.as_ref().unwrap());
            b.extend_from_slice(p.ht.as_ref().unwrap());
            b.extend_from_slice(&[42, 1, 2]);
            b
        };
        h.packet
            .emit(&beacon)
            .map_err(|_| "NERT live ERP native RX")?;
        h.pump();
        data(&h, 0x808)?;
        drop(h);
        let h = Harness::new_profile(true, true);
        let cap = qualify(&h)?;
        h.device
            .set_rts_threshold(0)
            .map_err(|_| "NERT wiphy threshold")?;
        h.peer.lock().hold_m4 = true;
        h.scan();
        let mut future = Box::pin(h.device.associate(h.request()));
        let mut held = false;
        for _ in 0..4096 {
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "NERT M4 finished before actual OWN hold",
            )?;
            if h.packet.model.lock().held.is_some() {
                held = true;
                break;
            }
        }
        require(held, "NERT actual protected M4 descriptor absent")?;
        let own = h.packet.model.lock().held;
        let regions = h.packet.live_regions();
        cap.revoke();
        require(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready(),
            "NERT revoked M4 wait resumed physical work",
        )?;
        drop(future);
        require(
            h.closed()
                && h.packet.model.lock().held == own
                && regions.iter().all(|r| r.live.load(Ordering::Acquire)),
            "NERT source loss reclaimed held M4 DMA or opened port",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/protection",
    smoke_rtl8188ee_rts_cts_live_erp_and_source_loss_keep_held_m4_dma
);
