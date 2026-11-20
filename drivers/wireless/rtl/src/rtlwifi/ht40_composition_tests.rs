// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual EE40 native DMA/PHY/peer/key/IPC/DHCP compositions.
use super::*;
use ht::Geometry;
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;

fn domain() -> narf_wireless::reg::RegulatoryDomain {
    let mut d = power::domain(17);
    d.rules[0].max_bandwidth_mhz = 40;
    d
}
/// Explicit inert dimensional peaks, never installed as a board measurement.
fn artifact(
    base: &crate::rtlwifi::channel_power::Calibration,
    fw: crate::rtlwifi::firmware_transport::Identity,
    g: Geometry,
) -> Vec<u8> {
    let mut b = vec![0; 1472];
    b[..4].copy_from_slice(b"NEHT");
    b[4..8].copy_from_slice(&[4, 0, 192, 0]);
    b[8..12].copy_from_slice(&1472u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x79, 0x81]);
    b[16..48].copy_from_slice(&ht::wide_request(base, fw, g).binding);
    b[48..80].copy_from_slice(&radio::factory_identity(base.factory()));
    b[80..112].copy_from_slice(&base.digest);
    b[112..118].copy_from_slice(&base.factory().mac);
    b[118..124].copy_from_slice(&[g.primary(), 40, 1, 1, g.secondary(), g.center()]);
    b[124..126].copy_from_slice(&8i16.to_le_bytes());
    b[126..128].copy_from_slice(&80i16.to_le_bytes());
    b[128..160].copy_from_slice(&ht::request_on_channel(base, fw, g.primary()).binding);
    for row in b[192..].chunks_exact_mut(128) {
        for (gain, v) in row.chunks_exact_mut(2).enumerate() {
            v.copy_from_slice(&(gain as i16 * 2).to_le_bytes());
        }
    }
    b
}
fn elements(g: Geometry) -> Vec<u8> {
    let mut b = ht::tests::ap_elements(255);
    b[2] |= 2;
    b[30] = g.primary();
    b[31] = if g.primary() < g.secondary() { 5 } else { 7 };
    b
}
fn require(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
pub(super) struct Wide {
    pub(super) h: Harness,
    g: Geometry,
    db: Arc<narf_wireless::reg::db::Database>,
    cap: Cap<FirmwareBlob, Read>,
}
impl Wide {
    #[inline(never)]
    pub(super) fn new(protected: bool, primary: u8, secondary: u8) -> Result<Self, &'static str> {
        Self::with_factory(protected, primary, secondary, power::factory())
    }
    pub(super) fn with_factory(
        protected: bool,
        primary: u8,
        secondary: u8,
        factory: crate::rtlwifi::efuse::Factory,
    ) -> Result<Self, &'static str> {
        let g = Geometry::new(primary, secondary).map_err(|_| "EE40 geometry")?;
        let db = Arc::new(narf_wireless::reg::db::Database::new());
        db.install(domain());
        let base = if primary == 1 {
            power::calibration(&factory)
        } else {
            power::calibration_for_channel(&factory, primary)
        };
        let h = Harness::with_factory(protected, true, Some(db.clone()), false, factory);
        let cap = Cap::bootstrap();
        *h.device.environment_for_test().ht_wide.lock() = Some((
            primary,
            artifact(&base, h.firmware.identity().unwrap(), g),
            cap,
        ));
        if primary != 1 {
            super::super::channel_tests::idle_receipt(&h);
            super::super::channel_tests::peer_channel(&h, primary);
            complete(h.device.set_config(narf_wireless::WirelessConfig {
                channel: u32::from(primary),
                tx_power_dbm: None,
            }))
            .map_err(|_| "EE40 actual primary rebuild")?;
        }
        {
            let mut p = h.peer.lock();
            p.ht = Some(elements(g));
            p.ht40 = true;
        }
        Ok(Self { h, g, db, cap })
    }
    pub(super) fn join(&self) -> Result<(), &'static str> {
        complete(self.h.device.scan(ScanRequest {
            channels: vec![u32::from(self.g.primary())],
            frequencies_mhz: Vec::new(),
            ssids: vec![SSID.to_vec()],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(2),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))
        .map_err(|_| "EE40 actual discovery")?;
        let mut request = self.h.request();
        request.channel = u32::from(self.g.primary());
        request.frequency_mhz = 2407 + u32::from(self.g.primary()) * 5;
        complete(self.h.device.associate(request)).map_err(|_| "EE40 native MLME/keys")?;
        require(self.h.device.link_up(), "EE40 carrier")
    }
    fn registers(&self, wide: bool) -> Result<(), &'static str> {
        let r = &self.h.packet.radio;
        let lower = self.g.primary() < self.g.secondary();
        require(
            r.rf(0x18) & 0xfff
                == if wide {
                    u32::from(self.g.center()) | 0x400
                } else {
                    u32::from(self.g.primary()) | 0xc00
                },
            "EE40 literal RF width/center",
        )?;
        require(
            (r.hardware_read8(0x603) & 4 == 0) == wide
                && (r.word(0x800) & 1 != 0) == wide
                && (r.word(0x900) & 1 != 0) == wide,
            "EE40 literal MAC/BB width",
        )?;
        if wide {
            require(
                r.word(0x440) & 0x600000 == (if lower { 0x200000 } else { 0x400000 })
                    && r.word(0xa00) & 0x10 == (if lower { 0 } else { 0x10 })
                    && r.word(0xd00) & 0xc00 == (if lower { 0x400 } else { 0x800 })
                    && r.word(0x818) & 0xc000000 == (if lower { 0x8000000 } else { 0x4000000 }),
                "EE40 literal sideband routing",
            )?;
        }
        Ok(())
    }
}
fn smoke_rtl8188ee_ht40_v4_full_program_binding_and_center_factory_group() -> TestResult {
    check(|| {
        let h = Harness::new_profile(false, true);
        let mut f = power::factory();
        f.logical[0xc1] = 2;
        f.logical[0x17] = 17;
        f.logical[0x18] = 15;
        f.logical[0x1b] = 0x70;
        let base = Arc::new(power::calibration_for_channel(&f, 6));
        let g = Geometry::new(6, 2).unwrap();
        let fw = h.firmware.identity().unwrap();
        let cap = Cap::bootstrap();
        let bytes = artifact(&base, fw, g);
        let q = ht::Grant::parse(base.clone(), fw, &bytes, Some([7; 32]), cap)
            .map_err(|_| "EE40 v4 parse")?;
        let permission = base
            .permission(&domain(), 6)
            .map_err(|_| "EE40 pure primary")?;
        require(
            q.gains(&domain(), permission).is_ok_and(|g| g == [17; 8]),
            "EE40 used PRIMARY factory group for wide RF CENTER",
        )?;
        for at in [
            0, 4, 6, 8, 12, 16, 48, 79, 80, 112, 118, 119, 120, 121, 122, 123, 128, 160,
        ] {
            let mut wrong = bytes.clone();
            wrong[at] ^= 1;
            require(
                ht::Grant::parse(base.clone(), fw, &wrong, Some([7; 32]), cap).is_err(),
                "EE40 foreign/malformed record admitted",
            )?;
        }
        for row in [0, 1, 2] {
            let mut unknown = bytes.clone();
            for v in unknown[192 + row * 128..192 + (row + 1) * 128].chunks_exact_mut(2) {
                v.copy_from_slice(&i16::MAX.to_le_bytes());
            }
            let bad = ht::Grant::parse(base.clone(), fw, &unknown, Some([7; 32]), cap)
                .map_err(|_| "EE40 unknown record parse")?;
            require(
                bad.gains(&domain(), permission).is_err(),
                "EE40 invented unknown legacy/MCS peaks",
            )?;
        }
        require(
            ht::Grant::parse(base.clone(), fw, &bytes, None, cap).is_err()
                && ht::Grant::parse(base, fw, &bytes[..1471], Some([7; 32]), cap).is_err(),
            "EE40 unsigned/truncated record",
        )?;
        {
            let model = h.packet.model.lock();
            require(
                !model.master && model.kicks.is_empty(),
                "EE40 pure record parsing performed native TX",
            )?;
        }
        cap.revoke();
        require(
            q.gains(&domain(), permission).is_err(),
            "EE40 retired v4 source",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_v4_full_program_binding_and_center_factory_group
);
fn conversation(protected: bool, primary: u8, secondary: u8) -> Result<(), &'static str> {
    let w = Wide::new(protected, primary, secondary)?;
    w.join()?;
    w.registers(true)?;
    let plan = w.h.peer.lock().plan;
    let lease = narf_net::dhcp::dhcp_acquire(w.h.device.name(), 0).map_err(|_| "EE40 real DHCP")?;
    require(plan.matches_lease(&lease), "EE40 actual DORA terms")?;
    let up = packet(&w.h, 7, true);
    w.h.device
        .enqueue(&up, TxMeta::default())
        .map_err(|_| "EE40 actual enqueue")?;
    w.h.pump();
    require(
        w.h.peer.lock().uplink.last() == Some(&up),
        "EE40 exact protected/plain IP uplink",
    )?;
    let model = w.h.packet.model.lock();
    let descriptor = model.descriptors.last().ok_or("EE40 descriptor absent")?;
    require(
        word(descriptor, 16) & 0x02300000 == 0x02300000
            && word(descriptor, 20) & 0x40 == 0
            && word(descriptor, 16) & 0x500 == 0x500,
        "EE40 literal DATA BW/SC3 LGI fixed descriptor",
    )?;
    let management = model
        .observed
        .iter()
        .zip(&model.descriptors)
        .filter(|(f, _)| matches!(f.first(), Some(0 | 0xb0)));
    require(
        management.clone().count() >= 2
            && management
                .clone()
                .all(|(_, d)| word(d, 16) & 0x02300000 == u32::from(w.g.prime()) << 20),
        "EE40 actual basic20 management primary subcarrier",
    )?;
    drop(model);
    // DHCP already delivered its real OFFER/ACK into this same IPC ring.
    // Consume that completed phase before asserting an exact one-frame
    // native downlink window; retain strict equality for the injected IP.
    let _ = w.h.received();
    let down = packet(&w.h, 8, false);
    let raw = w.h.peer.lock().downlink(&down)?;
    w.h.packet
        .emit_native(&raw, 0x253, 0, None)
        .map_err(|_| "EE40 native downlink DMA")?;
    w.h.pump();
    require(
        w.h.received() == vec![down],
        "EE40 native BW40/key/IPC exact downlink",
    )?;
    require(
        w.h.device
            .phy_capabilities(2400)
            .is_some_and(|p| p.ht[0] & 0x62 == 0x22),
        "EE40 actual public20/40 SGI20-only promise",
    )?;
    Ok(())
}
fn smoke_rtl8188ee_ht40_plus_open_native_dhcp_ip_and_literal_descriptors() -> TestResult {
    check(|| conversation(false, 1, 5))
}
fn smoke_rtl8188ee_ht40_minus_wpa2_noninitial_primary_native_dhcp_ip() -> TestResult {
    check(|| conversation(true, 6, 2))
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_plus_open_native_dhcp_ip_and_literal_descriptors
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_minus_wpa2_noninitial_primary_native_dhcp_ip
);
fn smoke_rtl8188ee_ht40_initial_and_response_twenty_fallback_before_keys() -> TestResult {
    check(|| {
        for mode in 0..3 {
            let w = Wide::new(true, 6, 2)?;
            {
                let mut p = w.h.peer.lock();
                p.ht40 = false;
                if mode == 2 {
                    p.ht = Some(elements(Geometry::new(6, 10).unwrap()));
                } else {
                    let mut e = ht::tests::ap_elements(255);
                    e[30] = 6;
                    p.response_ht = Some(e.clone());
                    if mode == 0 {
                        p.ht = Some(e);
                    }
                }
            }
            w.join()?;
            w.registers(false)?;
            let lease = narf_net::dhcp::dhcp_acquire(w.h.device.name(), 0)
                .map_err(|_| "EE40 real20 fallback DHCP")?;
            require(
                w.h.peer.lock().plan.matches_lease(&lease),
                "EE40 fallback native IP",
            )?;
            let model = w.h.packet.model.lock();
            require(
                model
                    .descriptors
                    .iter()
                    .all(|d| word(d, 16) & 0x02300000 == 0 || mode == 1),
                "EE40 unoffered secondary reused wide descriptor",
            )?;
            let last = model
                .descriptors
                .last()
                .ok_or("EE40 fallback DATA absent")?;
            require(
                word(last, 16) & 0x02300000 == 0,
                "EE40 response20 inherited stale wide DATA fields",
            )?;
            if mode == 1 {
                require(
                    model.observed.iter().zip(&model.descriptors).any(|(f, d)| {
                        f.first() == Some(&0) && word(d, 16) & 0x00300000 == 0x00200000
                    }),
                    "EE40 narrowing never issued actual wide-primary association",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_initial_and_response_twenty_fallback_before_keys
);
fn smoke_rtl8188ee_ht40_native_width_gi_rejection_preserves_same_pn() -> TestResult {
    check(|| {
        for wide in [false, true] {
            let w = Wide::new(true, 1, 5)?;
            if !wide {
                let mut p = w.h.peer.lock();
                p.ht = Some(ht::tests::ap_elements(255));
                p.ht40 = false;
            }
            w.join()?;
            let down = packet(&w.h, 9, false);
            let raw = w.h.peer.lock().downlink(&down)?;
            w.h.packet
                .emit_native(&raw, if wide { 0x353 } else { 0x253 }, 0, None)
                .map_err(|_| "EE40 bad native metadata injection")?;
            w.h.pump();
            require(
                w.h.received().is_empty(),
                "EE40 raw BW40 or unqualified SGI40 advanced security/IPC",
            )?;
            w.h.packet
                .emit_native(&raw, if wide { 0x253 } else { 0x53 }, 0, None)
                .map_err(|_| "EE40 valid same-PN injection")?;
            w.h.pump();
            require(
                w.h.received() == vec![down],
                "EE40 bad width/GI consumed original PN",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_native_width_gi_rejection_preserves_same_pn
);
fn smoke_rtl8188ee_ht40_secondary_span_policy_and_revoked_v4_keep_native_own() -> TestResult {
    check(|| {
        for revoke in [false, true] {
            let w = Wide::new(true, 6, 2)?;
            w.join()?;
            w.h.pump();
            w.h.peer.lock().hold_data = true;
            let up = packet(&w.h, 10, true);
            w.h.device
                .enqueue(&up, TxMeta::default())
                .map_err(|_| "EE40 held enqueue")?;
            w.h.pump();
            let held =
                w.h.packet
                    .model
                    .lock()
                    .held
                    .ok_or("EE40 actual OWN not held")?;
            let count = retained(&w.h);
            if revoke {
                w.cap.revoke();
            } else {
                let mut d = domain();
                d.rules.push(narf_wireless::reg::RegRule {
                    freq_start_mhz: 2410,
                    freq_end_mhz: 2411,
                    max_bandwidth_mhz: 40,
                    max_power_dbm: 17,
                    flags: narf_wireless::reg::RegFlags::NO_IR,
                });
                require(
                    power::calibration_for_channel(&power::factory(), 6)
                        .permission(&d, 6)
                        .is_ok(),
                    "EE40 span restriction also changed primary20 fixture",
                )?;
                w.db.install(d);
            }
            w.h.pump();
            let held_after = w.h.packet.model.lock().held;
            let retained_after = retained(&w.h);
            require(
                w.h.closed()
                    && !w.h.device.link_up()
                    && held_after == Some(held)
                    && retained_after >= count,
                "EE40 source/span failure reclaimed held native DMA",
            )?;
            w.db.install(domain());
            w.h.pump();
            require(w.h.closed(), "EE40 loose policy resurrected failed owner")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_secondary_span_policy_and_revoked_v4_keep_native_own
);
fn smoke_rtl8188ee_ht40_cancelled_or_revoked_native_rf_wait_retains_dma() -> TestResult {
    check(|| {
        for cancel in [false, true] {
            let w = Wide::new(true, 1, 5)?;
            w.h.scan();
            let regions = w.h.packet.live_regions();
            let drops = w.h.packet.drops.load(Ordering::Acquire);
            w.h.packet.model.lock().wait = true;
            let mut association = Box::pin(w.h.device.associate(w.h.request()));
            require(
                association
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "EE40 RF HSSI wait was not actual native work",
            )?;
            require(
                w.h.packet.radio.hardware_read8(0x100) & 0xc0 == 0
                    && w.h.packet.radio.hardware_read8(0x522) == 255,
                "EE40 actual RF await left MAC open",
            )?;
            if cancel {
                drop(association);
            } else {
                w.cap.revoke();
                require(
                    association
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready(),
                    "EE40 revoked source resumed held RF I/O",
                )?;
                drop(association);
            }
            w.h.packet.model.lock().wait = false;
            require(
                w.h.closed()
                    && !w.h.device.link_up()
                    && regions.iter().all(|r| r.live.load(Ordering::Acquire))
                    && w.h.packet.drops.load(Ordering::Acquire) == drops,
                "EE40 cancelled/RF authority loss freed physical DMA or reopened",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_cancelled_or_revoked_native_rf_wait_retains_dma
);
fn smoke_rtl8188ee_ht40_program_readback_and_actual_tx_scheduler_terminal() -> TestResult {
    check(|| {
        let w = Wide::new(false, 1, 5)?;
        w.join()?;
        let up = packet(&w.h, 11, true);
        let before = w.h.packet.model.lock().kicks.len();
        w.h.packet
            .radio
            .hardware_word(0x818, w.h.packet.radio.word(0x818) ^ 0x4000000);
        let _ = w.h.device.enqueue(&up, TxMeta::default());
        w.h.pump();
        require(
            w.h.closed() && w.h.packet.model.lock().kicks.len() == before,
            "EE40 BB secondary readback failure reached actual TX",
        )?;
        drop(w);
        let w = Wide::new(false, 1, 5)?;
        w.h.scan();
        let rf = w.h.packet.radio.rf(0x18);
        w.h.packet.radio.hardware_word(0x5f8, 0x80000000);
        require(
            complete(w.h.device.associate(w.h.request())).is_err()
                && w.h.packet.radio.rf(0x18) == rf,
            "EE40 ignored high SCH_TX_CMD bits or retuned before actual idle",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/ht40",
    smoke_rtl8188ee_ht40_program_readback_and_actual_tx_scheduler_terminal
);
