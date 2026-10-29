//! Native AR9285 HT tests. Synthetic signed records authorize only the model;
//! they are not measured RF inputs and cannot be loaded by the real controller.
use super::*;
use crate::ath9k::{
    packet::tests::Model,
    station::tests::{self as station_tests, AP, PMK, SSID},
};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{self, RegFlags, RegRule, RegulatoryDomain};
use zeroize::Zeroizing;
pub(in crate::ath9k) struct Policy(Option<RegulatoryDomain>);
impl Policy {
    pub(in crate::ath9k) fn install() -> Self {
        let old = reg::db::get_domain();
        reg::db::set_domain(domain());
        Self(old)
    }
}
impl Drop for Policy {
    fn drop(&mut self) {
        if let Some(d) = self.0.take() {
            reg::db::set_domain(d)
        } else {
            reg::db::clear_domain()
        }
    }
}
pub(in crate::ath9k) fn domain() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    }
}
fn image() -> [u8; EEPROM_4K_BYTES] {
    let mut b = [0; EEPROM_4K_BYTES];
    b[..2].copy_from_slice(&376u16.to_le_bytes());
    b[4..6].copy_from_slice(&0xe002u16.to_le_bytes());
    b[6] = 2;
    b[8..10].copy_from_slice(&0x64u16.to_le_bytes());
    b[12..18].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    b[18..20].copy_from_slice(&[1, 1]);
    b[60] = 4;
    for (at, n) in [(183, 4), (198, 4), (213, 8)] {
        b[at] = 112;
        b[at + 1..at + 1 + n].fill(18);
        b[at + n + 1] = 255;
        b[at + 2 * (n + 1)] = 255;
    }
    b[267..270].copy_from_slice(&[0x11, 0x12, 0x15]);
    for i in 0..3 {
        b[279 + i * 8] = 112;
        b[280 + i * 8] = 18;
        b[281 + i * 8] = 255;
    }
    checksum(&mut b);
    b
}
fn checksum(b: &mut [u8; EEPROM_4K_BYTES]) {
    b[2..4].fill(0);
    let sum = b
        .chunks_exact(2)
        .fold(0u16, |s, b| s ^ u16::from_le_bytes([b[0], b[1]]));
    b[2..4].copy_from_slice(&(sum ^ 0xffff).to_le_bytes());
}
fn inputs() -> (narf_bus::BusDevice, Identity, Prepared, Report) {
    use narf_bus::{BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    let address = PcieAddr::new(0, 0, 7, 0);
    (
        BusDevice {
            addr: BusAddr::Pcie(address),
            id: DeviceId {
                vendor: 0x168c,
                device: 0x002b,
                class: 0x028000,
                subsystem_vendor: 0x168c,
                subsystem_id: 0x30a4,
            },
            kind: BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        },
        Identity {
            revision: 2,
            mac: [2, 1, 2, 3, 4, 5],
            eeprom_version: 0xe002,
            regulatory_domains: [0x64, 0],
            rx_chainmask: 1,
            tx_chainmask: 1,
            big_endian_fields: false,
        },
        Prepared {
            reference_frequency: 2412,
            high_power_gain: false,
            xe2_gain: false,
            ini_writes: 655,
        },
        Report {
            country: *b"US",
            frequency_mhz: 2412,
            max_power_half_dbm: 34,
            pa_offset: Some(9),
            iq_i: 3,
            iq_q: -2,
            measured_noise_dbm: -118,
            noise_dbm: -118,
        },
    )
}
fn facts() -> Facts {
    let (d, i, p, r) = inputs();
    Facts::new(d, i, p, r, &image()).unwrap()
}
fn record(f: &Facts, mcs: u8) -> Vec<u8> {
    let mut b = vec![0; 160];
    b[..8].copy_from_slice(&[b'N', b'8', b'5', b'H', 1, 0, 160, 0]);
    b[8..12].copy_from_slice(&160u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0x8c, 0x16, 0x2b, 0]);
    b[16..48].copy_from_slice(&f.request.identity);
    b[48..54].copy_from_slice(&f.request.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 0]);
    b[58..60].copy_from_slice(&4i16.to_le_bytes());
    b[60..62].copy_from_slice(&40i16.to_le_bytes());
    b[62] = mcs;
    for at in (64..106).step_by(2) {
        b[at..at + 2].copy_from_slice(&12i16.to_le_bytes());
    }
    b
}
pub(in crate::ath9k) fn qualify(model: &Arc<Model>, mcs: u8) -> Result<(), &'static str> {
    let f = facts();
    let b = record(&f, mcs);
    let g = Source::Verified {
        bytes: b,
        signer: Some([0x85; 32]),
        cap: Cap::<FirmwareBlob, Read>::bootstrap(),
    }
    .load(f)
    .map_err(|_| "model measured HT record")?;
    for (r, v) in g.facts.powers {
        model.registers.borrow_mut().insert(r, v);
    }
    for (r, v) in [
        (0x9804, 0x3c0),
        (0x99a4, 1),
        (0xa39c, 1),
        (0x832c, 1),
        (0xa200, 4),
        (0x8114, 0x200),
        (0x8340, 0x380),
    ] {
        model.registers.borrow_mut().insert(r, v);
    }
    *model.ht.borrow_mut() = Some(g);
    Ok(())
}
pub(in crate::ath9k) fn elements() -> Vec<u8> {
    let mut e = vec![45, 26];
    let mut c = [0; 26];
    c[0] = 12 | 32;
    c[2] = 24;
    c[3] = 255;
    c[15] = 1;
    e.extend_from_slice(&c);
    e.extend_from_slice(&[61, 22]);
    let mut op = [0; 22];
    op[0] = 1;
    e.extend_from_slice(&op);
    e.extend_from_slice(&[
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 0, 0,
        0x62, 0x32, 0, 0,
    ]);
    e
}
pub(in crate::ath9k) fn protection_elements(mode: u8, erp: bool) -> Vec<u8> {
    let mut e = elements();
    e[32] = mode;
    if erp {
        e.extend_from_slice(&[42, 1, 2]);
    }
    e
}
fn join(f: &mut station_tests::Fixture, protected: bool) -> Result<(), &'static str> {
    station_tests::complete(f.radio.associate(
        AP,
        SSID,
        protected.then(|| Zeroizing::new(PMK)),
        &[],
    ))
    .map_err(|_| "native HT join")
}
fn data(f: &station_tests::Fixture) -> Vec<u8> {
    narf_wifi_fixtures::udp_ipv4(
        f.plan.bssid,
        f.plan.station,
        f.plan.lease_ip,
        f.plan.server_ip,
        4101,
        4102,
        b"AR9285 original HT20 IP",
    )
}
fn smoke_ar9285_ht20_factory_disable_flags_and_exact_new_measured_identity() -> TestResult {
    let _policy = Policy::install();
    let (d, i, p, r) = inputs();
    for (revision, rx, tx) in [(1, 1, 1), (2, 2, 1), (2, 1, 2)] {
        let mut bad = i;
        bad.revision = revision;
        bad.rx_chainmask = rx;
        bad.tx_chainmask = tx;
        if Facts::new(d, bad, p, r, &image()).is_ok() {
            return TestResult::Fail("HT INI revision or actual single chain gate");
        }
    }
    for at in [184, 199, 214] {
        let mut bad = image();
        bad[at] = 64;
        checksum(&mut bad);
        if Facts::new(d, i, p, r, &bad).is_ok() {
            return TestResult::Fail("invalid source target power admitted by HT request");
        }
    }
    for flag in [0, 0x20, 0x22, 0xff] {
        let mut b = image();
        b[6] = flag;
        checksum(&mut b);
        if Facts::new(d, i, p, r, &b).is_ok() {
            return TestResult::Fail("EEPROM negative HT20 capability ignored");
        }
    }
    for at in [0, 2, 4, 12, 18, 19, 183, 213, 267, 279] {
        let mut b = image();
        b[at] ^= 1;
        if Facts::new(d, i, p, r, &b).is_ok() {
            return TestResult::Fail("invalid exact EEPROM admitted");
        }
    }
    let f = facts();
    let b = record(&f, 255);
    for at in [0, 4, 6, 8, 12, 14, 16, 48, 54, 55, 56, 57, 62, 63, 106, 159] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        if at == 62 {
            bad[at] = 0;
        }
        if Grant::decode(&bad, Some([1; 32]), Cap::bootstrap(), f.clone()).is_ok() {
            return TestResult::Fail("foreign/incomplete HT measurement record");
        }
    }
    if Grant::decode(&b, None, Cap::bootstrap(), f.clone()).is_ok() {
        return TestResult::Fail("unsigned HT record admitted");
    }
    let mut changed = f.clone();
    changed.request.identity[0] ^= 1;
    if Grant::decode(&b, Some([1; 32]), Cap::bootstrap(), changed).is_ok() {
        return TestResult::Fail("calibration/recipe identity not bound");
    }
    let cap = Cap::bootstrap();
    let g = Grant::decode(&b, Some([1; 32]), cap, f).unwrap();
    if g.check().is_err() {
        return TestResult::Fail("current valid model record");
    }
    cap.revoke();
    if g.check().is_ok() {
        return TestResult::Fail("revoked measured source remained current");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_factory_disable_flags_and_exact_new_measured_identity
);
fn smoke_ar2427_bonded_out_ht_never_reaches_measured_facts() -> TestResult {
    // Linux hw.c::ath9k_hw_fill_cap_info clears ATH9K_HW_CAP_HT for
    // AR2427_DEVID_PCIE (0x002c) although it is AR9285 silicon; the shared
    // probe/legacy owner admits it while every HT/BA source stays closed.
    let _policy = Policy::install();
    let (d, i, p, r) = inputs();
    let mut ar2427 = d;
    ar2427.id.device = 0x002c;
    if !crate::ath9k::ar9285_silicon(&d.id) || !crate::ath9k::ar9285_silicon(&ar2427.id) {
        return TestResult::Fail("AR9285-silicon PCI functions were not admitted");
    }
    for (vendor, device) in [
        (0x168c, 0x0029),
        (0x168c, 0x002d),
        (0x168c, 0x0034),
        (0x1234, 0x002c),
    ] {
        let mut other = d;
        other.id.vendor = vendor;
        other.id.device = device;
        if crate::ath9k::ar9285_silicon(&other.id) {
            return TestResult::Fail("non-AR9285 silicon reached the AR9285 owner");
        }
    }
    if Facts::new(ar2427, i, p, r, &image()).is_ok() {
        return TestResult::Fail("AR2427 bonded-out HT reached a measured HT request");
    }
    if Facts::new(d, i, p, r, &image()).is_err() {
        return TestResult::Fail("AR9285 HT facts regressed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar2427_bonded_out_ht_never_reaches_measured_facts
);
fn smoke_ar9285_ht20_all_mcs_native_qos_dma_pad_fcs_duration_and_original_ccmp() -> TestResult {
    let _policy = Policy::install();
    for protected in [false, true] {
        for mcs in 0..8u8 {
            let mut f = station_tests::fixture_ht(protected, 1 << mcs).unwrap();
            if join(&mut f, protected).is_err() {
                return TestResult::Fail("native HT association/response");
            }
            f.peer.lock().hold_data = true;
            let ethernet = data(&f);
            if f.radio.send(&ethernet).is_err() {
                return TestResult::Fail("native HT DATA send");
            }
            let desc = f.model.tx.get().unwrap();
            let original = f.model.transmitted.borrow().last().unwrap().clone();
            let dma = f.model.dma_transmitted.borrow().last().unwrap().clone();
            let air = (original.len() + 4) as u32;
            let duration = 36
                + (air * 8 + 22)
                    .div_ceil([26u32, 52, 78, 104, 156, 208, 234, 260][usize::from(mcs)])
                    * 4;
            if original[..2] != [0x88, if protected { 0x41 } else { 1 }]
                || original[24..26] != [0, 0]
                || dma.len() != original.len() + 2
                || dma[..26] != original[..26]
                || dma[26..28] != [0, 0]
                || dma[28..] != original[26..]
                || f.model.word(desc + 8).unwrap() & 0xfff != air
                || f.model.word(desc + 12).unwrap() & 0xfff != dma.len() as u32
                || f.model.word(desc + 20) != Ok(u32::from(0x80 | mcs))
                || f.model.word(desc + 16) != Ok(0x48000)
                || f.model.word(desc + 24) != Ok(duration)
                || f.model.word(desc + 36).unwrap() & 0xf000_001f != 4
                || f.peer.lock().uplink.last() != Some(&ethernet)
            {
                return TestResult::Fail(
                    "actual HT descriptor/pad/duration or independently authenticated IP",
                );
            }
            f.model.complete(true).unwrap();
            if f.radio.poll().is_err() {
                return TestResult::Fail("actual HT native terminal receipt");
            }
            let mut down = ethernet.clone();
            down[..6].copy_from_slice(&f.plan.station);
            down[6..12].copy_from_slice(&AP);
            let wire = f.peer.lock().downlink(&down).unwrap();
            f.model.ht_rate.set(0x80 | mcs);
            f.model.inject(&wire, 0).unwrap();
            if f.radio.poll().unwrap() != vec![down] {
                return TestResult::Fail("native HT rate/original padded CCMP RX");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_all_mcs_native_qos_dma_pad_fcs_duration_and_original_ccmp
);
fn smoke_ar9285_ht20_native_phy_status_rejects_sgi20_width_stbc_ampdu_before_pn() -> TestResult {
    let _policy = Policy::install();
    let mut f = station_tests::fixture_ht(true, 255).unwrap();
    join(&mut f, true).unwrap();
    let mut eth = data(&f);
    eth[..6].copy_from_slice(&f.plan.station);
    eth[6..12].copy_from_slice(&AP);
    let wire = f.peer.lock().downlink(&eth).unwrap();
    for (offset, bits) in [
        (28, 1),
        (28, 2),
        (28, 4),
        (28, 8),
        (48, 1 << 17),
        (48, 1 << 16),
        (48, 1 << 29),
        (20, 1 << 12),
        (48, 1 << 6),
        (48, 1 << 7),
    ] {
        f.model.inject(&wire, 0).unwrap();
        let d = f.model.last_rx.get().unwrap();
        let old = f.model.word(d + offset).unwrap();
        f.model.put(d + offset, old | bits).unwrap();
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("invalid HT native metadata reached CCMP");
        }
    }
    for code in [0x88, 0x8f, 0xff] {
        f.model.ht_rate.set(code);
        f.model.inject(&wire, 0).unwrap();
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("unsupported native HT MCS");
        }
    }
    f.model.ht_rate.set(0x87);
    f.model.inject(&wire, 0).unwrap();
    if f.radio.poll().unwrap() != vec![eth] {
        return TestResult::Fail("rejected PHY status advanced PN or consumed original bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_phy_status_rejects_sgi20_width_stbc_ampdu_before_pn
);
fn smoke_ar9285_ht20_rx_stbc1_all_mcs_original_ccmp_and_tx_stbc_stays_disabled() -> TestResult {
    let _policy = Policy::install();
    let (_, cap) = local(255).unwrap();
    if cap[..2] != [12, 1] {
        return TestResult::Fail("AR9285 local RX_STBC1/TX_STBC/SGI20 capability");
    }
    for protected in [false, true] {
        let mut f = station_tests::fixture_ht_stbc(protected, true, true).unwrap();
        join(&mut f, protected).unwrap();
        let mut eth = data(&f);
        eth[..6].copy_from_slice(&f.plan.station);
        eth[6..12].copy_from_slice(&AP);
        for mcs in 0..8 {
            let wire = f.peer.lock().downlink(&eth).unwrap();
            f.model.ht_rate.set(0x80 | mcs);
            for status in [9, 10, 12] {
                f.model.inject(&wire, 0).unwrap();
                let d = f.model.last_rx.get().unwrap();
                f.model.put(d + 28, status).unwrap();
                if !f.radio.poll().unwrap().is_empty() {
                    return TestResult::Fail("STBC enabled SGI20/HT40/parallel40");
                }
            }
            for rate in [0x1b, 0x88, 0x8f] {
                f.model.ht_rate.set(rate);
                f.model.inject(&wire, 0).unwrap();
                let d = f.model.last_rx.get().unwrap();
                f.model.put(d + 28, 8).unwrap();
                if !f.radio.poll().unwrap().is_empty() {
                    return TestResult::Fail("STBC enabled legacy or extra-stream MCS");
                }
            }
            f.model.ht_rate.set(0x80 | mcs);
            f.model.inject(&wire, 0).unwrap();
            let d = f.model.last_rx.get().unwrap();
            f.model.put(d + 28, 8).unwrap();
            if f.radio.poll().unwrap() != vec![eth.clone()] {
                return TestResult::Fail("actual RX_STBC1 original CCMP or rejected-status PN");
            }
            if protected {
                f.model.inject(&wire, 0).unwrap();
                let d = f.model.last_rx.get().unwrap();
                f.model.put(d + 28, 8).unwrap();
                if !f.radio.poll().unwrap().is_empty() {
                    return TestResult::Fail("RX_STBC1 bypassed native CCMP replay");
                }
            }
        }
        f.peer.lock().hold_data = true;
        let up = data(&f);
        f.radio.send(&up).unwrap();
        let d = f.model.tx.get().unwrap();
        if f.model.word(d + 36).unwrap() & 0xf000_001f != 4 {
            return TestResult::Fail("RX_STBC1 enabled TX STBC/GI/width or extra chains");
        }
        f.model.complete(true).unwrap();
        f.radio.poll().unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_rx_stbc1_all_mcs_original_ccmp_and_tx_stbc_stays_disabled
);
fn smoke_ar9285_ht20_rx_stbc1_requires_actual_offer_and_response_tx_support() -> TestResult {
    let _policy = Policy::install();
    for (offer, response) in [(false, false), (true, false), (false, true)] {
        let mut f = station_tests::fixture_ht_stbc(true, offer, response).unwrap();
        join(&mut f, true).unwrap();
        let mut eth = data(&f);
        eth[..6].copy_from_slice(&f.plan.station);
        eth[6..12].copy_from_slice(&AP);
        let wire = f.peer.lock().downlink(&eth).unwrap();
        f.model.inject(&wire, 0).unwrap();
        let d = f.model.last_rx.get().unwrap();
        f.model.put(d + 28, 8).unwrap();
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("AP RX capability or stale offer admitted native RX STBC");
        }
        f.model.inject(&wire, 0).unwrap();
        if f.radio.poll().unwrap() != vec![eth] {
            return TestResult::Fail("unnegotiated STBC advanced PN or disabled ordinary HT");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_rx_stbc1_requires_actual_offer_and_response_tx_support
);
fn smoke_ar9285_ht20_native_rts_cts_all_mcs_actual_ht_and_erp_requirements() -> TestResult {
    let _policy = Policy::install();
    let cases = [
        (1, 0, false, false),
        (0, 1, false, false),
        (2, 0, false, false),
        (0, 2, false, false),
        (3, 0, false, false),
        (0, 3, false, false),
        (0, 0, true, false),
        (0, 0, false, true),
    ];
    for protected in [false, true] {
        for (mcs, (offer, response, offer_erp, response_erp)) in cases.into_iter().enumerate() {
            let mut f = station_tests::fixture_ht_profile(
                protected,
                protection_elements(offer, offer_erp),
                protection_elements(response, response_erp),
            )
            .unwrap();
            qualify(&f.model, 1 << mcs).unwrap();
            join(&mut f, protected).unwrap();
            f.peer.lock().hold_data = true;
            let eth = data(&f);
            f.radio.send(&eth).unwrap();
            let d = f.model.tx.get().unwrap();
            let original = f.model.transmitted.borrow().last().unwrap().clone();
            let air = (original.len() + 4) as u32;
            let duration =
                36 + 4 * (8 * air + 22).div_ceil([26, 52, 78, 104, 156, 208, 234, 260][mcs]);
            if f.model.word(d + 8).unwrap() & ((1 << 22) | (1 << 31)) != 1 << 22
                || f.model.word(d + 24).unwrap() != duration | 0x8000
                || f.model.word(d + 36).unwrap() != (0x1b << 20) | 4
                || f.model.word(d + 20).unwrap() != 0x80 + mcs as u32
                || f.model.word(d + 12).unwrap() & 0x6000_0000 != 0
                || f.peer.lock().uplink.last() != Some(&eth)
            {
                return TestResult::Fail(
                    "native RTS/CTS qualifier/duration/control rate/original CCMP",
                );
            }
            // Actual RTS exhaustion is a failed DATA attempt, never a positive
            // native receipt. Existing station/data authority remains usable.
            f.model.complete(false).unwrap();
            f.model.put(d + 60, 2 | (3 << 4)).unwrap();
            if f.radio.poll().is_err() || f.radio.peer().is_none() {
                return TestResult::Fail(
                    "bounded native RTS failure destroyed the current station",
                );
            }
            f.radio.send(&eth).unwrap();
            f.model.complete(true).unwrap();
            if f.radio.poll().is_err() {
                return TestResult::Fail("fresh RTS-protected DATA did not complete natively");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_rts_cts_all_mcs_actual_ht_and_erp_requirements
);
fn smoke_ar9285_ht20_current_beacon_sticky_protection_and_held_original_dma() -> TestResult {
    let _policy = Policy::install();
    for protected in [false, true] {
        let mut f = station_tests::fixture_ht(protected, 255).unwrap();
        join(&mut f, protected).unwrap();
        f.peer.lock().hold_data = true;
        let eth = data(&f);
        // Foreign native beacons supply no current-peer protection authority.
        f.peer.lock().ht = Some(protection_elements(3, true));
        let mut foreign = f.peer.lock().beacon();
        foreign[10..16].copy_from_slice(&[2, 9, 9, 9, 9, 9]);
        foreign[16..22].copy_from_slice(&[2, 9, 9, 9, 9, 9]);
        f.model.inject(&foreign, 0).unwrap();
        f.radio.poll().unwrap();
        f.radio.send(&eth).unwrap();
        let held = f.model.tx.get().unwrap();
        let words = [
            f.model.word(held + 8).unwrap(),
            f.model.word(held + 24).unwrap(),
        ];
        if words[0] & (1 << 22) != 0 || words[1] & 0x8000 != 0 {
            return TestResult::Fail("foreign AP changed current native protection");
        }
        let beacon = f.peer.lock().beacon();
        f.model.inject(&beacon, 0).unwrap();
        f.radio.poll().unwrap(); // Fresh RX must progress during held DATA.
        if f.model.tx.get() != Some(held)
            || f.model.word(held + 8) != Ok(words[0])
            || f.model.word(held + 24) != Ok(words[1])
        {
            return TestResult::Fail("beacon update rewrote/reclaimed device-owned original DMA");
        }
        f.model.complete(true).unwrap();
        f.radio.poll().unwrap();
        for clear in [false, true] {
            if clear {
                f.peer.lock().ht = Some(elements());
                let beacon = f.peer.lock().beacon();
                f.model.inject(&beacon, 0).unwrap();
                f.radio.poll().unwrap();
            }
            f.radio.send(&eth).unwrap();
            let d = f.model.tx.get().unwrap();
            if f.model.word(d + 8).unwrap() & (1 << 22) == 0
                || f.model.word(d + 24).unwrap() & 0x8000 == 0
            {
                return TestResult::Fail(
                    "current beacon was ignored or later beacon removed required RTS",
                );
            }
            f.model.complete(true).unwrap();
            f.radio.poll().unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_current_beacon_sticky_protection_and_held_original_dma
);
fn smoke_ar9285_ht20_protection_timing_and_terminal_descriptor_are_current() -> TestResult {
    let _policy = Policy::install();
    for register in [0x1030, 0x1070, 0x8014, 0x801c] {
        let mut f = station_tests::fixture_ht_profile(
            true,
            protection_elements(3, true),
            protection_elements(3, true),
        )
        .unwrap();
        join(&mut f, true).unwrap();
        let old = f.model.registers.borrow()[&register];
        f.model.registers.borrow_mut().insert(register, old ^ 1);
        if f.radio.poll().is_ok() || f.radio.peer().is_some() || f.model.master.get() {
            return TestResult::Fail("changed native RTS/CTS timing retained current authority");
        }
        f.model.registers.borrow_mut().insert(register, old);
        let eth = data(&f);
        if f.radio.send(&eth).is_ok() || f.radio.poll().is_ok() {
            return TestResult::Fail("restoring timing reopened a terminal native owner");
        }
    }
    for (offset, bit) in [(8, 1 << 22), (24, 1 << 15), (36, 1 << 20)] {
        let mut f = station_tests::fixture_ht_profile(
            true,
            protection_elements(3, true),
            protection_elements(3, true),
        )
        .unwrap();
        join(&mut f, true).unwrap();
        f.peer.lock().hold_data = true;
        let eth = data(&f);
        f.radio.send(&eth).unwrap();
        let d = f.model.tx.get().unwrap();
        f.model.complete(true).unwrap();
        f.model
            .put(d + offset, f.model.word(d + offset).unwrap() ^ bit)
            .unwrap();
        if f.radio.poll().is_ok() || f.radio.peer().is_some() || f.model.master.get() {
            return TestResult::Fail("modified RTS descriptor retired immutable native DMA");
        }
    }
    for extra in [vec![42, 1, 8], vec![42, 1, 2, 42, 1, 2], vec![42, 2, 2]] {
        let mut response = elements();
        response.extend(extra);
        let mut f = station_tests::fixture_ht_profile(true, elements(), response).unwrap();
        if join(&mut f, true).is_ok() || f.radio.peer().is_some() || f.model.master.get() {
            return TestResult::Fail("malformed/duplicate/reserved ERP response authorized HT");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_protection_timing_and_terminal_descriptor_are_current
);
fn request(tid: u8) -> Vec<u8> {
    let mut f = vec![0xd0, 0, 0, 0];
    f.extend_from_slice(&[2, 1, 2, 3, 4, 5]);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0, 0, 3, 0, 9]);
    f.extend_from_slice(&(2u16 | (u16::from(tid) << 2) | (64 << 6)).to_le_bytes());
    f.extend_from_slice(&[0, 0, 0x30, 0]);
    f
}
fn smoke_ar9285_ht20_native_addba_decline_requires_ack_idle_and_retains_cancelled_dma() -> TestResult
{
    let _policy = Policy::install();
    for cancel in [false, true] {
        let mut f = station_tests::fixture_ht(false, 255).unwrap();
        join(&mut f, false).unwrap();
        f.peer.lock().hold_decline = true;
        let req = request(7);
        f.model.inject(&req, 0).unwrap();
        assert!(f.radio.poll().unwrap().is_empty());
        let desc = f.model.tx.get().unwrap();
        let bytes = f.model.transmitted.borrow().last().unwrap().clone();
        if bytes.len() != 33
            || bytes[24..29] != [3, 1, 9, 37, 0]
            || bytes[29..33] != [30, 0, 0, 0]
            || f.model.word(desc + 20) != Ok(0x1b)
            || f.radio.ready()
        {
            return TestResult::Fail("ADDBA native legacy decline/receipt not held");
        }
        let regions = f
            .model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>();
        if cancel {
            f.radio.stop().unwrap();
            f.model.complete(true).unwrap();
            if f.radio.poll().is_ok() {
                return TestResult::Fail("cancelled BA decline reopened owner");
            }
        } else {
            f.model.complete(true).unwrap();
            f.radio.poll().unwrap();
            if !f.radio.ready() || f.peer.lock().declines.len() != 1 {
                return TestResult::Fail("native ACK+idle did not release decline");
            }
        }
        if regions
            != f.model
                .regions
                .borrow()
                .iter()
                .map(|r| (r.bus, r.cpu, r.len))
                .collect::<Vec<_>>()
        {
            return TestResult::Fail("decline/cancel replaced retained DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_addba_decline_requires_ack_idle_and_retains_cancelled_dma
);
pub(in crate::ath9k) fn aggregate_body(destination: [u8; 6]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut body = Vec::new();
    let mut result = Vec::new();
    for (i, length) in [1514, 1514, 783].into_iter().enumerate() {
        let mut ethernet = vec![0x50 + i as u8; length];
        ethernet[..6].copy_from_slice(&destination);
        ethernet[6..12].copy_from_slice(&AP);
        ethernet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let length = (ethernet.len() - 14 + 8) as u16;
        body.extend_from_slice(&destination);
        body.extend_from_slice(&AP);
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        body.extend_from_slice(&ethernet[12..]);
        result.push(ethernet);
        if i != 2 {
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
    }
    assert_eq!(body.len(), 3839);
    (body, result)
}
pub(in crate::ath9k) fn aggregate(
    f: &station_tests::Fixture,
    body: &[u8],
    protected: bool,
    tid: u8,
    pn: u64,
    group: bool,
) -> Vec<u8> {
    let mut header = vec![0x88, if protected { 0x42 } else { 2 }, 0, 0];
    header.extend_from_slice(&if group { [0xff; 6] } else { f.plan.station });
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0x10, 0, 0x80 | tid, 0]);
    let wire = if protected {
        let key = if group {
            [0x77; 16]
        } else {
            f.peer
                .lock()
                .ptk
                .as_ref()
                .unwrap()
                .tk
                .as_slice()
                .try_into()
                .unwrap()
        };
        let mut clear = body.to_vec();
        narf_wireless::ccmp::protect(
            &station_tests::Ccm,
            &header,
            &key,
            pn,
            if group { 1 } else { 0 },
            tid,
            false, // GTK data uses a data nonce, never the management bit.
            &mut clear,
        )
        .unwrap()
    } else {
        body.to_vec()
    };
    header.extend_from_slice(&wire);
    header
}
fn smoke_ar9285_ht20_original_full3839_pairwise_group_and_sixteen_tid_atomic_amsdu() -> TestResult {
    let _policy = Policy::install();
    for protected in [false, true] {
        let mut f = station_tests::fixture_ht(protected, 255).unwrap();
        join(&mut f, protected).unwrap();
        for group in [false, true] {
            for tid in 0..16 {
                let (body, expected) =
                    aggregate_body(if group { [255; 6] } else { f.plan.station });
                let valid = aggregate(&f, &body, protected, tid, 8, group);
                // A later malformed subframe has a valid MIC but must consume no
                // PN or decoded prefix. Same original PN remains admissible.
                let mut malformed = body.clone();
                malformed[3060..3062].copy_from_slice(&0xffffu16.to_be_bytes());
                let bad = aggregate(&f, &malformed, protected, tid, 8, group);
                f.model.inject(&bad, 0).unwrap();
                if !f.radio.poll().unwrap().is_empty() {
                    return TestResult::Fail("malformed later subframe published a prefix");
                }
                if protected {
                    let mut flip = valid.clone();
                    flip[24] ^= 1;
                    f.model.inject(&flip, 0).unwrap();
                    if !f.radio.poll().unwrap().is_empty() {
                        return TestResult::Fail("original QoS authentication bypass");
                    }
                    if group {
                        let mut clear = body.clone();
                        let wrong_nonce = narf_wireless::ccmp::protect(
                            &station_tests::Ccm,
                            &valid[..26],
                            &[0x77; 16],
                            8,
                            1,
                            tid,
                            true,
                            &mut clear,
                        )
                        .unwrap();
                        let mut wrong = valid[..26].to_vec();
                        wrong.extend_from_slice(&wrong_nonce);
                        f.model.inject(&wrong, 0).unwrap();
                        if !f.radio.poll().unwrap().is_empty() {
                            return TestResult::Fail("GTK DATA accepted a management CCMP nonce");
                        }
                    }
                }
                f.model.inject(&valid, 0).unwrap();
                if f.radio.poll().unwrap() != expected {
                    return TestResult::Fail("full original aggregate/GTK/TID or atomic PN retry");
                }
                if protected {
                    f.model.inject(&valid, 0).unwrap();
                    if !f.radio.poll().unwrap().is_empty() {
                        return TestResult::Fail("native aggregate replay admitted");
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_original_full3839_pairwise_group_and_sixteen_tid_atomic_amsdu
);
fn smoke_ar9285_ht20_open_aggregate_native_qos_address_and_control_injection_closed() -> TestResult
{
    let _policy = Policy::install();
    let mut f = station_tests::fixture_ht(false, 255).unwrap();
    join(&mut f, false).unwrap();
    let (body, expected) = aggregate_body(f.plan.station);
    let valid = aggregate(&f, &body, false, 3, 1, false);
    for at in [1, 4, 10, 16, 22, 24, 25] {
        let mut bad = valid.clone();
        bad[at] ^= if at == 24 { 0x10 } else { 1 };
        f.model.inject(&bad, 0).unwrap();
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("unbound Open aggregate/native QoS header");
        }
    }
    for (at, value) in [(0, 0xaa), (6, 1), (14, 0xab)] {
        let mut bad = body.clone();
        bad[at] = value;
        let wire = aggregate(&f, &bad, false, 3, 1, false);
        f.model.inject(&wire, 0).unwrap();
        if !f.radio.poll().unwrap().is_empty() {
            return TestResult::Fail("malformed/injected aggregate prefix escaped");
        }
    }
    let mut eapol = body.clone();
    eapol[20..22].copy_from_slice(&[0x88, 0x8e]);
    let wire = aggregate(&f, &eapol, false, 3, 1, false);
    f.model.inject(&wire, 0).unwrap();
    if !f.radio.poll().unwrap().is_empty() {
        return TestResult::Fail("aggregate EAPOL injection");
    }
    f.model.inject(&valid, 0).unwrap();
    if f.radio.poll().unwrap() != expected {
        return TestResult::Fail("invalid Open aggregate retired valid data authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_open_aggregate_native_qos_address_and_control_injection_closed
);
fn smoke_ar9285_ht20_profile_readbacks_policy_source_and_pending_dma_are_terminal() -> TestResult {
    let _policy = Policy::install();
    for fault in 0..7 {
        reg::db::set_domain(domain());
        let mut f = station_tests::fixture_ht(true, 255).unwrap();
        join(&mut f, true).unwrap();
        f.peer.lock().hold_data = true;
        let packet = data(&f);
        f.radio.send(&packet).unwrap();
        let retained = f
            .model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>();
        match fault {
            0 => f.model.allowed.set(false),
            1 => f.model.authority.set(false),
            2 => {
                f.model.ht.borrow().as_ref().unwrap().cap.revoke();
            }
            3 => {
                f.model.registers.borrow_mut().insert(0xa38c, 0);
            }
            4 => {
                f.model.registers.borrow_mut().insert(0x1040, 0);
            }
            5 => reg::db::clear_domain(),
            _ => {
                let mut d = domain();
                d.rules[0].max_power_dbm = 0;
                reg::db::set_domain(d);
            }
        }
        if f.radio.poll().is_ok() || f.radio.peer().is_some() {
            return TestResult::Fail("current policy/source/power/EDCA loss left HT owner open");
        }
        f.model.allowed.set(true);
        f.model.authority.set(true);
        if f.radio.poll().is_ok() || f.radio.ready() {
            return TestResult::Fail("restored policy/source reopened terminal owner");
        }
        if retained
            != f.model
                .regions
                .borrow()
                .iter()
                .map(|r| (r.bus, r.cpu, r.len))
                .collect::<Vec<_>>()
        {
            return TestResult::Fail("fault replaced published native mapping");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_profile_readbacks_policy_source_and_pending_dma_are_terminal
);
fn smoke_ar9285_ht20_native_response_and_caller_ies_cannot_promote_or_downgrade_profile(
) -> TestResult {
    let _policy = Policy::install();
    for case in 0..8 {
        let mut f = station_tests::fixture_ht(true, 255).unwrap();
        let mut bad = elements();
        match case {
            0 => bad.truncate(28),
            1 => bad[30] = 6,
            2 => bad[31] = 5, // Secondary/40MHz response is outside this profile.
            3 => bad[37] = 1,
            4 => bad[5] = 0,
            5 => bad[62] |= 16,
            6 => {
                let duplicate = bad[..28].to_vec();
                bad.extend_from_slice(&duplicate);
            }
            _ => bad.truncate(52),
        };
        f.peer.lock().ht = Some(bad);
        if join(&mut f, true).is_ok() || f.radio.peer().is_some() || f.model.master.get() {
            return TestResult::Fail("invalid actual HT/WMM response published profile/carrier");
        }
    }
    for ie in [
        vec![45, 26].into_iter().chain([0; 26]).collect::<Vec<_>>(),
        narf_wireless::wmm::INFORMATION.to_vec(),
    ] {
        let mut f = station_tests::fixture_ht(false, 255).unwrap();
        let before = f.model.transmitted.borrow().len();
        if station_tests::complete(f.radio.associate(AP, SSID, None, &ie)).is_ok()
            || f.model.transmitted.borrow().len() != before
        {
            return TestResult::Fail("caller PHY/WMM bytes authorized native HT");
        }
    }
    // Optional qualification is absent before new live EDCA/profile writes.
    // The AP observes an ordinary legacy request and answers legacy DATA.
    let mut f = station_tests::fixture_ht(true, 255).unwrap();
    *f.model.ht.borrow_mut() = None;
    let old = f.model.registers.borrow().get(&0x1040).copied();
    if join(&mut f, true).is_err()
        || f.peer.lock().ht_active
        || f.model.registers.borrow().get(&0x1040).copied() != old
    {
        return TestResult::Fail("pre-program missing HT qualification did not preserve legacy");
    }
    let packet = data(&f);
    if f.radio.send(&packet).is_err()
        || f.radio.poll().is_err()
        || f.model
            .transmitted
            .borrow()
            .last()
            .is_none_or(|b| b[0] != 8)
    {
        return TestResult::Fail("qualified legacy fallback lost original native CCMP path");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_response_and_caller_ies_cannot_promote_or_downgrade_profile
);
fn smoke_ar9285_ht20_pending_padded_dma_mutation_final_series_and_close_retain_owner() -> TestResult
{
    let _policy = Policy::install();
    for change in 0..4 {
        let mut f = station_tests::fixture_ht(true, 255).unwrap();
        join(&mut f, true).unwrap();
        f.peer.lock().hold_data = true;
        let packet = data(&f);
        f.radio.send(&packet).unwrap();
        let d = f.model.tx.get().unwrap();
        let b = f.model.word(d + 4).unwrap();
        let addresses = f
            .model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>();
        match change {
            0 => {
                let word = f.model.word(b + 24).unwrap();
                f.model.put(b + 24, word ^ 0x10000).unwrap();
            }
            1 => {
                let word = f.model.word(d + 36).unwrap();
                f.model.put(d + 36, word | 1).unwrap();
            }
            2 => {}
            _ => {
                f.radio.stop().unwrap();
            }
        }
        f.model.complete(true).unwrap();
        if change == 2 {
            f.model.put(d + 92, 1 | (1 << 21)).unwrap();
        }
        if f.radio.poll().is_ok()
            || f.radio.ready()
            || addresses
                != f.model
                    .regions
                    .borrow()
                    .iter()
                    .map(|r| (r.bus, r.cpu, r.len))
                    .collect::<Vec<_>>()
        {
            return TestResult::Fail(
                "modified padded DMA/disabled final HT series/close released or reopened owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_pending_padded_dma_mutation_final_series_and_close_retain_owner
);
fn smoke_ar9285_ht20_late_optional_qualification_keeps_same_native_dma_owner() -> TestResult {
    let _policy = Policy::install();
    let mut f = station_tests::fixture_ht(true, 255).unwrap();
    let grant = f.model.ht.borrow().clone().unwrap();
    *f.model.ht.borrow_mut() = None;
    let retained = f
        .model
        .regions
        .borrow()
        .iter()
        .map(|r| (r.bus, r.cpu, r.len))
        .collect::<Vec<_>>();
    let before = f.model.transmitted.borrow().len();
    // A validated external record becomes available after calibration/cache,
    // before the first HT request. It installs no descriptor or EDCA by itself.
    *f.model.ht.borrow_mut() = Some(grant);
    if f.model.transmitted.borrow().len() != before
        || join(&mut f, true).is_err()
        || !f.peer.lock().ht_active
    {
        return TestResult::Fail(
            "late optional source did not join through actual HT request/response",
        );
    }
    if retained
        != f.model
            .regions
            .borrow()
            .iter()
            .map(|r| (r.bus, r.cpu, r.len))
            .collect::<Vec<_>>()
    {
        return TestResult::Fail("late measured qualification reconstructed native mappings");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_late_optional_qualification_keeps_same_native_dma_owner
);
fn smoke_ar9285_ht20_unowned_native_tx_queue_never_becomes_retryable_credit() -> TestResult {
    let _policy = Policy::install();
    for register in [0x840, 0xa00] {
        let mut f = station_tests::fixture_ht(true, 255).unwrap();
        join(&mut f, true).unwrap();
        let count = f.model.transmitted.borrow().len();
        f.model.registers.borrow_mut().insert(register, 1);
        let bytes = data(&f);
        if f.radio.send(&bytes).is_ok()
            || f.radio.peer().is_some()
            || f.model.transmitted.borrow().len() != count
        {
            return TestResult::Fail(
                "unowned native live queue published DATA or remained authorized",
            );
        }
        f.model.registers.borrow_mut().insert(register, 0);
        if f.radio.send(&bytes).is_ok() || f.radio.poll().is_ok() {
            return TestResult::Fail("restored queue status reopened ambiguous DMA owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_unowned_native_tx_queue_never_becomes_retryable_credit
);
