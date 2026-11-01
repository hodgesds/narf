// SPDX-License-Identifier: GPL-2.0-or-later
//! Native actual PHY mux/TXD/MMIO, SMART training, source and DMA compositions.
use super::*;
use crate::rtlwifi::{antenna, tracking};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
fn require(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
fn factory(kind: u8, hp: bool) -> crate::rtlwifi::efuse::Factory {
    let mut f = power::factory();
    f.logical[0xc9] = kind;
    f.logical[0xba] = 24;
    if hp {
        f.logical[0xda..0xdc].copy_from_slice(&0x103cu16.to_le_bytes());
        f.logical[0xdc..0xde].copy_from_slice(&0x197du16.to_le_bytes());
    }
    f
}
fn harness(kind: u8, protected: bool, ht: bool, hp: bool) -> Harness {
    Harness::with_factory(protected, ht, None, false, factory(kind, hp))
}
fn program(h: &Harness) -> Result<antenna::Program, &'static str> {
    let (base, ht, protection) = super::tracking_tests::sources(h)?;
    let source = h.device.environment_for_test().tracking.lock().clone();
    let tracking = source
        .map(|(channel, bytes, cap)| {
            tracking::Grant::parse(
                base.clone(),
                h.firmware.identity().unwrap(),
                channel,
                ht.clone(),
                protection.clone(),
                &bytes,
                Some([7; 32]),
                cap,
            )
            .map(Arc::new)
        })
        .transpose()
        .map_err(|_| "NEAN actual preceding NETH")?;
    Ok(antenna::Program {
        base,
        ht,
        protection,
        tracking,
        channel: h.device.channel_for_test(),
        firmware: h.firmware.identity().unwrap(),
    })
}
fn qualify(h: &Harness) -> Result<Cap<FirmwareBlob, Read>, &'static str> {
    let cap = Cap::bootstrap();
    let p = program(h)?;
    let bytes = antenna::artifact(&p).map_err(|_| "NEAN fixture full program")?;
    *h.device.environment_for_test().antenna.lock() = Some((p.channel, bytes, cap));
    Ok(cap)
}
fn join(h: &Harness) -> Result<(), &'static str> {
    h.scan();
    complete(h.device.associate(h.request())).map_err(|_| "NEAN actual MLME/RSNA")?;
    require(h.device.link_up(), "NEAN carrier")
}
fn state(h: &Harness) -> Result<(u8, u8, bool, [u64; 2]), &'static str> {
    h.device
        .prepared
        .try_lock()
        .and_then(|s| s.as_ref().and_then(|o| o.antenna_for_test()))
        .ok_or("NEAN retained state")
}
fn service(h: &Harness) -> Result<(), &'static str> {
    h.pump();
    complete(h.device.antenna_diversity());
    require(h.device.link_up(), "NEAN native automatic transition")
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
    h.packet.emit(&b).map_err(|_| "NEAN native heartbeat")?;
    h.pump();
    Ok(())
}
fn period(h: &Harness) -> Result<(), &'static str> {
    h.env.now.fetch_add(2000, Ordering::AcqRel);
    heartbeat(h)?;
    service(h)
}
fn sample(
    h: &Harness,
    mux: u8,
    pwdb_all: u8,
    to_self: bool,
    foreign: bool,
) -> Result<(), &'static str> {
    let mut frame = if to_self {
        let down = packet(h, mux, false);
        h.peer.lock().downlink(&down)?
    } else {
        let p = h.peer.lock();
        let mut b = p.ap.beacon();
        if let Some(w) = &p.wmm {
            b.extend_from_slice(w);
        }
        if let Some(ht) = &p.ht {
            b.extend_from_slice(ht);
        }
        b
    };
    if foreign {
        frame[10..16].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        frame[16..22].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    }
    let mut phy = [0; 28];
    phy[4] = pwdb_all;
    phy[27] = ((mux & 1) << 7) | (((mux >> 1) & 1) << 6) | ((mux >> 2) & 1);
    h.packet
        .emit_native(&frame, 11, 0, Some(&phy))
        .map_err(|_| "NEAN actual native PHY mux")?;
    h.pump();
    Ok(())
}
fn data(h: &Harness, tx: Option<u8>) -> Result<(), &'static str> {
    let up = packet(h, 47, true);
    h.device
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "NEAN native IP enqueue")?;
    h.pump();
    require(
        h.peer.lock().uplink.last() == Some(&up),
        "NEAN actual IP/CCMP peer",
    )?;
    let m = h.packet.model.lock();
    let d = m.descriptors.last().ok_or("NEAN actual TXD")?;
    require(
        word(d, 8) & 0x03000000 == u32::from(tx.unwrap_or(0)) << 24 && word(d, 28) & (1 << 29) == 0,
        "NEAN literal TXD2[24,25]/D7[29]",
    )
}
fn smoke_rtl8188ee_antenna_signed_factory_full_program_mux_thermal_holes_fail_closed() -> TestResult
{
    check(|| {
        let h = harness(1, true, true, false);
        super::protection_tests::qualify(&h)?;
        super::tracking_tests::qualify(&h)?;
        let p = program(&h)?;
        let cap = Cap::bootstrap();
        let bytes = antenna::artifact(&p).map_err(|_| "NEAN asset")?;
        let parse = |b: &[u8], signer| antenna::Grant::parse(p.clone(), b, signer, cap);
        let q = parse(&bytes, Some([7; 32])).map_err(|_| "NEAN exact signed parse")?;
        let domain = power::domain(17);
        let permission = p
            .base
            .permission(&domain, 1)
            .map_err(|_| "NEAN primary permission")?;
        q.check_sources(&domain, permission)
            .map_err(|_| "NEAN all mux/thermal admission")?;
        for at in [
            0, 4, 6, 8, 12, 16, 48, 80, 112, 118, 119, 121, 122, 130, 136, 168, 200, 232,
        ] {
            let mut wrong = bytes.clone();
            wrong[at] ^= 1;
            require(
                parse(&wrong, Some([7; 32])).is_err(),
                "NEAN identity/geometry/parent payload alias",
            )?;
        }
        require(parse(&bytes, None).is_err(), "NEAN unsigned accepted")?;
        let gains = q
            .nominal(&domain, permission)
            .map_err(|_| "NEAN original gains")?;
        for (row, gain) in [(0, gains.cck[0]), (1, gains.ofdm[0]), (2, gains.mcs[0])] {
            let mut hole = bytes.clone();
            let at = 320 + 64 * 10 * 128 + 63 * 10 * 128 + row * 128 + usize::from(gain) * 2;
            hole[at..at + 2].copy_from_slice(&i16::MAX.to_le_bytes());
            let unknown = parse(&hole, Some([7; 32]))
                .map_err(|_| "NEAN other-mux remote-thermal hole parse")?;
            require(
                unknown.check_sources(&domain, permission).is_err(),
                "NEAN inferred unobserved antenna/temperature peak",
            )?;
        }
        cap.revoke();
        require(
            q.check_sources(&domain, permission).is_err(),
            "NEAN revoked source remained current",
        )?;
        require(!h.packet.model.lock().master, "NEAN metadata performed DMA")?;
        drop(h);
        for kind in [0, 3, 5, 255] {
            let h = harness(kind, true, true, false);
            require(
                antenna::artifact(&program(&h)?).is_err(),
                "NEAN fixed/unknown/erased factory invented automatic paths",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/antenna",
    smoke_rtl8188ee_antenna_signed_factory_full_program_mux_thermal_holes_fail_closed
);
fn smoke_rtl8188ee_antenna_hardware_diversity_actual_phy_tie_default_readback_and_dhcp(
) -> TestResult {
    check(|| {
        for (kind, protected, ht, hp) in [
            (1, false, false, false),
            (1, true, true, false),
            (1, true, true, true),
            (2, false, false, false),
            (2, true, true, false),
        ] {
            let h = harness(kind, protected, ht, hp);
            qualify(&h)?;
            join(&h)?;
            let initial = if kind == 1 { 1 } else { 0 };
            require(
                state(&h)?.0 == initial && h.packet.radio.word(0x914) & 0xffff == 0x201,
                "NEAN initial mapping",
            )?;
            require(
                h.packet.radio.word(0x864) & 0x1f8
                    == (u32::from(initial) << 3) | (u32::from(initial ^ 1) << 6),
                "NEAN skipped first actual default programming",
            )?;
            if kind == 1 {
                require(
                    h.packet.radio.word(0x860) & 0x7000 == 0x1000
                        && h.packet.radio.word(0x6d8) & 0xc0 == 0x40,
                    "NEAN type1 logical/type initialization alias",
                )?;
            }
            service(&h)?;
            let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
                .map_err(|_| "NEAN HW native DHCP")?;
            require(h.peer.lock().plan.matches_lease(&lease), "NEAN HW DORA")?;
            sample(&h, 0, 0xa0, false, false)?;
            sample(&h, 1, 0x50, false, false)?;
            period(&h)?;
            require(state(&h)?.0 == 0, "NEAN hardware chose weaker PHY mux")?;
            data(&h, if kind == 1 { Some(0) } else { None })?;
            sample(&h, 0, 0x50, false, false)?;
            sample(&h, 1, 0xa0, false, false)?;
            period(&h)?;
            require(
                state(&h)?.0 == 1,
                "NEAN hardware failed alternate native selector",
            )?;
            data(&h, if kind == 1 { Some(1) } else { None })?;
            sample(&h, 0, 0xa0, false, false)?;
            sample(&h, 1, 0xa0, false, false)?;
            sample(&h, 0, 0xe0, false, true)?;
            sample(&h, 2, 0xe0, false, false)?;
            period(&h)?;
            require(
                state(&h)?.0 == 1,
                "NEAN tie/foreign/reserved mux changed current selection",
            )?;
            require(
                h.packet.radio.word(0xb2c) & (1 << 22) == if kind == 2 { 1 << 22 } else { 0 },
                "NEAN RX-only vs TRX LNA program",
            )?;
            require(
                h.packet.radio.word(0xc50) & (1 << 7) != 0
                    && h.packet.radio.word(0xa00) & (1 << 15) != 0,
                "NEAN linked actual HW-div enable",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/antenna",
    smoke_rtl8188ee_antenna_hardware_diversity_actual_phy_tie_default_readback_and_dhcp
);
fn smoke_rtl8188ee_antenna_smart_real_timed_own_phy_training_and_native_descriptors() -> TestResult
{
    check(|| {
        let h = harness(4, true, true, false);
        qualify(&h)?;
        join(&h)?;
        service(&h)?;
        let own = h.device.mac();
        require(
            state(&h)?.2 && h.packet.radio.word(0xe08) & (1 << 16) != 0,
            "NEAN SMART training command absent",
        )?;
        require(
            h.packet.radio.word(0x7b0) == u32::from_le_bytes(own[..4].try_into().unwrap())
                && h.packet.radio.word(0x7b4) & 0x3ffff
                    == 0x30000 | u32::from(u16::from_le_bytes(own[4..].try_into().unwrap())),
            "NEAN SMART actual station target",
        )?;
        service(&h)?;
        require(state(&h)?.2, "NEAN SMART finished without real2s deadline")?;
        sample(&h, 1, 0xe0, false, false)?;
        sample(&h, 2, 0xe0, true, false)?;
        require(
            state(&h)?.3 == [0, 0],
            "NEAN SMART accepted broadcast/reserved mux as own training",
        )?;
        period(&h)?;
        require(
            !state(&h)?.2 && state(&h)?.1 == 0 && h.packet.radio.word(0xc50) & (1 << 7) == 0,
            "NEAN SMART no-sample completion invented path",
        )?;
        period(&h)?;
        sample(&h, 0, 0x50, true, false)?;
        sample(&h, 1, 0xa0, true, false)?;
        require(
            state(&h)?.3 == [1, 1],
            "NEAN SMART missing actual native own PHY samples",
        )?;
        period(&h)?;
        require(
            !state(&h)?.2 && state(&h)?.1 == 1 && h.packet.radio.word(0xe08) & (1 << 16) == 0,
            "NEAN SMART failed selected completion",
        )?;
        data(&h, Some(1))?;
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "NEAN SMART native DHCP")?;
        require(h.peer.lock().plan.matches_lease(&lease), "NEAN SMART lease")?;
        period(&h)?;
        sample(&h, 0, 0xa0, true, false)?;
        sample(&h, 1, 0x50, true, false)?;
        period(&h)?;
        require(
            state(&h)?.1 == 0 && h.packet.radio.word(0xc50) & (1 << 7) == 0,
            "NEAN SMART second real training retained stale path",
        )?;
        data(&h, Some(0))
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/antenna",
    smoke_rtl8188ee_antenna_smart_real_timed_own_phy_training_and_native_descriptors
);
fn smoke_rtl8188ee_antenna_ht40_rts_thermal_full_program_native_composition() -> TestResult {
    check(|| {
        for kind in [1, 2, 4] {
            let w = super::ht40_tests::Wide::with_factory(true, 1, 5, factory(kind, false))?;
            super::protection_tests::qualify(&w.h)?;
            super::tracking_tests::qualify(&w.h)?;
            qualify(&w.h)?;
            w.h.device
                .set_rts_threshold(0)
                .map_err(|_| "NEAN public RTS")?;
            w.join()?;
            service(&w.h)?;
            let rf = w.h.packet.radio.rf(0x18);
            let before = (w.h.packet.radio.word(0xe08) >> 8) as u8;
            // Actual source thermal trigger/sample; SMART training bit16 must
            // survive the independent CCK TXAGC byte8..15 update.
            complete(w.h.device.gain_tracking());
            w.h.env.now.fetch_add(2000, Ordering::AcqRel);
            heartbeat(&w.h)?;
            w.h.packet.radio.hardware_rf(0x42, 0x30000 | (20 << 10));
            complete(w.h.device.gain_tracking());
            require(
                w.h.device.link_up()
                    && (w.h.packet.radio.word(0xe08) >> 8) as u8 == before.saturating_sub(2),
                "NEAN thermal continuation lost actual current antenna permission",
            )?;
            if kind == 4 {
                require(
                    w.h.packet.radio.word(0xe08) & (1 << 16) != 0,
                    "NEAN thermal write clobbered SMART bit16",
                )?;
            }
            sample(&w.h, 1, 0xa0, kind == 4, false)?;
            sample(&w.h, 0, 0x50, kind == 4, false)?;
            service(&w.h)?;
            require(
                w.h.packet.radio.rf(0x18) == rf && rf & 0xfff == 0x403,
                "NEAN antenna/thermal changed real40MHz RF center",
            )?;
            data(&w.h, if kind == 2 { None } else { Some(1) })?;
            let m = w.h.packet.model.lock();
            let d = m.descriptors.last().ok_or("NEAN composed DATA TXD")?;
            require(
                word(d, 16) & 0xfc00381f == 0x1008 && word(d, 16) & 0x02300000 == 0x02300000,
                "NEAN actual width/RTS fields aliased antenna",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/antenna",
    smoke_rtl8188ee_antenna_ht40_rts_thermal_full_program_native_composition
);
fn smoke_rtl8188ee_antenna_unknown_measurement_ignored_mmio_cancel_and_static_restore() -> TestResult
{
    check(|| {
        for fault in 0..3 {
            let h = harness(1, true, true, false);
            qualify(&h)?;
            if fault == 0 {
                let mut source = h.device.environment_for_test().antenna.lock();
                source.as_mut().unwrap().1[320..320 + 128].fill(0x7f);
            }
            if fault == 1 {
                h.packet.radio.ignore(0x4c);
            }
            if fault == 2 {
                h.packet.radio.hardware_word(0x5f8, 1);
            }
            h.scan();
            let kicks = h.packet.model.lock().kicks.len();
            require(
                complete(h.device.associate(h.request())).is_err() && !h.device.link_up(),
                "NEAN unknown/readback/scheduler failure admitted auth",
            )?;
            require(
                h.packet.model.lock().kicks.len() == kicks,
                "NEAN failed init published new auth",
            )?;
        }
        let h = harness(1, true, true, false);
        qualify(&h)?;
        join(&h)?;
        service(&h)?;
        let before = h.packet.radio.word(0x860) & 0x7000;
        complete(h.device.disassociate()).map_err(|_| "NEAN disassociate")?;
        // The previous real AP session is Authorized and owns its old PTK/
        // replay state. A new MLME/RSNA exchange needs a fresh peer session,
        // as in the pre-existing native Device rejoin composition.
        {
            let mut peer = h.peer.lock();
            let fresh = Peer::new(true);
            peer.ap = fresh.ap;
            peer.ptk = fresh.ptk;
            peer.replay = fresh.replay;
            peer.pn = fresh.pn;
        }
        join(&h)?;
        require(
            h.device.link_up() && h.packet.radio.word(0x860) & 0x7000 == before,
            "NEAN original static restore/new peer qualification failed",
        )?;
        h.packet.radio.pause_after(1);
        h.env.now.fetch_add(2000, Ordering::AcqRel);
        heartbeat(&h)?;
        let mut future = Box::pin(h.device.antenna_diversity());
        require(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "NEAN native RF transition did not retain future",
        )?;
        drop(future);
        h.pump();
        require(
            !h.device.link_up() && !h.packet.model.lock().master,
            "NEAN cancelled RF transition reopened owner",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/antenna",
    smoke_rtl8188ee_antenna_unknown_measurement_ignored_mmio_cancel_and_static_restore
);
fn smoke_rtl8188ee_antenna_revocation_after_native_copy_and_held_m4_retains_dma() -> TestResult {
    check(|| {
        let h = harness(1, true, true, false);
        let cap = qualify(&h)?;
        join(&h)?;
        service(&h)?;
        let down = packet(&h, 55, false);
        let frame = h.peer.lock().downlink(&down)?;
        h.packet.emit(&frame).map_err(|_| "NEAN actual copied RX")?;
        crate::rtlwifi::interface::publication_test::copied_then_revoke(&h.device, cap)?;
        h.pump();
        require(
            !h.device.link_up(),
            "NEAN revoked copied source retained carrier",
        )?;
        drop(h);
        let h = harness(4, true, true, false);
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
                "NEAN M4 completed before actual OWN",
            )?;
            if h.packet.model.lock().held.is_some() {
                held = true;
                break;
            }
        }
        require(held, "NEAN actual held M4 absent")?;
        let drops = h.packet.drops.load(Ordering::Acquire);
        cap.revoke();
        require(
            complete(joining).is_err() && !h.device.link_up(),
            "NEAN revoked held M4 opened controlled port",
        )?;
        require(
            h.packet.model.lock().held.is_some() && h.packet.drops.load(Ordering::Acquire) == drops,
            "NEAN revocation forged native DMA retirement",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/antenna",
    smoke_rtl8188ee_antenna_revocation_after_native_copy_and_held_m4_retains_dma
);
