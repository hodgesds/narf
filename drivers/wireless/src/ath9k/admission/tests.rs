use super::*;
use crate::ath9k::{channel_width::Geometry, phy::ar9287::power::tests::image};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn device(id: u16) -> narf_bus::DeviceId {
    narf_bus::DeviceId {
        vendor: 0x168c,
        device: id,
        class: 0x0002_8000,
        subsystem_vendor: 0x1a3b,
        subsystem_id: 0x1186,
    }
}

fn identity() -> Identity {
    Identity {
        revision: 3,
        mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        eeprom_version: 0xe003,
        regulatory_domains: [0x64, 0],
        rx_chainmask: 3,
        tx_chainmask: 3,
        big_endian_fields: false,
    }
}

fn facts_for(id: u16, map: &[u8]) -> Result<Facts, BringUpError> {
    let prepared = Prepared {
        geometry: Geometry::from_frequency(2422)?,
        ini_writes: 711,
    };
    Facts::new(
        &device(id),
        &Revision::decode(0x0018_03ff).ok_or(BringUpError::UnsupportedRevision)?,
        &identity(),
        &prepared,
        map,
        2422,
    )
}

/// Format-only synthetic record; the measured fields are markers.
fn record(facts: &Facts, antenna: u8, ceiling: u8) -> Vec<u8> {
    let r = facts.request();
    let mut b = vec![0u8; 128];
    b[..8].copy_from_slice(&[b'N', b'8', b'7', b'A', 1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..14].copy_from_slice(&0x168cu16.to_le_bytes());
    b[14..16].copy_from_slice(&r.device.to_le_bytes());
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..58].copy_from_slice(&[3, 20, 3, 3]);
    b[58] = antenna;
    b[59] = ceiling;
    b
}

fn load(facts: Facts, bytes: Vec<u8>, signed: bool) -> Result<Arc<Grant>, BringUpError> {
    Source::Verified {
        bytes,
        signer: signed.then_some([0x87; 32]),
        cap: Cap::<FirmwareBlob, Read>::bootstrap(),
    }
    .load(facts)
}

fn smoke_ath9k_ar9287_admission_record_binds_device_map_and_envelope() -> TestResult {
    let Ok(facts) = facts_for(0x002e, &image(3)) else {
        return TestResult::Fail("AR9287 admission facts refused");
    };
    let request = facts.request();
    if request.filename != "ath9k/ar9287-admit-v1-ch3-02aabbccddee.bin" {
        return TestResult::Fail("AR9287 admission filename differs");
    }
    let grant = match load(facts.clone(), record(&facts, 6, 36), true) {
        Ok(grant) => grant,
        Err(_) => return TestResult::Fail("well-formed signed N87A record refused"),
    };
    // Measured antenna 6 over factory 4 removes 2 more half-dB from the host
    // limit; the measured ceiling bounds the result.
    if grant.ceiling(40) != 36 || grant.ceiling(30) != 28 || grant.request() != request {
        return TestResult::Fail("admitted power ceiling differs");
    }
    if grant.invoke(|| Ok(1)) != Ok(1) {
        return TestResult::Fail("current record capability not invocable");
    }
    // Every bound fact changes the request identity.
    let mut other = image(3);
    other[200] ^= 1;
    let changed = [
        facts_for(0x002d, &image(3)).map(|f| f.request().identity),
        facts_for(0x002e, &other).map(|f| f.request().identity),
    ];
    if changed
        .iter()
        .any(|c| c.as_ref().map_or(true, |i| *i == request.identity))
    {
        return TestResult::Fail("request identity ignores device or factory map");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9287_admission_record_binds_device_map_and_envelope
);

fn smoke_ath9k_ar9287_unprovisioned_or_foreign_record_stays_unadmitted() -> TestResult {
    let Ok(facts) = facts_for(0x002e, &image(3)) else {
        return TestResult::Fail("AR9287 admission facts refused");
    };
    let good = record(&facts, 6, 36);
    let mut cases = vec![(good.clone(), false)];
    for (at, value) in [
        (14, 0x2d),
        (20, 0),
        (50, 0),
        (54, 4),
        (58, 3),
        (59, 41),
        (100, 1),
    ] {
        let mut bad = good.clone();
        bad[at] = if at == 20 { bad[at] ^ 1 } else { value };
        cases.push((bad, true));
    }
    let mut short = good.clone();
    short.pop();
    cases.push((short, true));
    for (bytes, signed) in cases {
        if load(facts.clone(), bytes, signed).is_ok() {
            return TestResult::Fail("unsigned, foreign or out-of-envelope record admitted");
        }
    }
    let mut closed = image(3);
    closed[31] = 0;
    if facts_for(0x002b, &image(3)).is_ok()
        || facts_for(0x002e, &closed).is_ok()
        || facts_for(0x002e, &image(3)[..700]).is_ok()
    {
        return TestResult::Fail("non-AR9287 device or unsupported map produced a request");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9287_unprovisioned_or_foreign_record_stays_unadmitted
);

/// The AR9287 native owner binds the admitted device, primary, factory chain
/// masks and MAC profile, and every access (including long calibration)
/// stops at a revoked PCI capability.
fn smoke_ath9k_ar9287_native_profile_binds_admission_and_chains() -> TestResult {
    use crate::ath9k::{
        calibration::ar9287::Report,
        mac::{Clock, Profile},
        packet::{Error as PacketError, Port},
        packet_native::Native,
    };
    use narf_bus::{BarKind, BusAddr, BusDevice, BusDeviceCap, BusKind, MmioRegion, PcieAddr};
    use narf_capabilities::Write;
    let mut map = image(3);
    map[18..20].copy_from_slice(&[3, 3]);
    let Ok(facts) = facts_for(0x002e, &map) else {
        return TestResult::Fail("facts");
    };
    let bytes = record(&facts, facts.factory_antenna, 34);
    let Ok(grant) = load(facts, bytes, true) else {
        return TestResult::Fail("verified record refused");
    };
    let address = PcieAddr::new(0, 0, 9, 0);
    let bus = |id: u16| BusDevice {
        addr: BusAddr::Pcie(address),
        id: device(id),
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let bar = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: crate::ath9k::phy::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let report = |frequency_mhz| Report {
        country: *b"US",
        frequency_mhz,
        max_power_half_dbm: 34,
        rx_chainmask: 3,
        init_pdadc: 0,
        iq: [Some((0, 0)), Some((0, 0))],
        measured_noise_dbm: [Some(-112), Some(-112)],
        noise_dbm: [Some(-112), Some(-112)],
    };
    let profile = Profile::ar9287(3, 3, true);
    let build_mask = |id, frequency, profile, map: &[u8], mask| {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        // SAFETY: the revoked fixture capability makes every config, DMA and
        // BAR path unreachable; no physical device is touched.
        unsafe {
            Native::new_ar9287(
                bus(id),
                cap,
                bar,
                report(frequency),
                grant.clone(),
                map,
                profile,
                mask,
            )
        }
    };
    let build =
        |id, frequency, profile, map: &[u8]| build_mask(id, frequency, profile, map, 1 << 2);
    for (id, frequency, profile) in [
        (0x002b, 2422, profile),
        (0x002d, 2422, profile),
        (0x002e, 2412, profile),
        (0x002e, 2422, Profile::ar9287(1, 1, true)),
        (0x002e, 2422, Profile::AR9285),
    ] {
        if build(id, frequency, profile, &map).is_ok() {
            return TestResult::Fail("AR9287 owner accepted a foreign device/primary/profile");
        }
    }
    if build(0x002e, 2422, profile, &map[..map.len() - 2]).is_ok() {
        return TestResult::Fail("AR9287 owner accepted a short map");
    }
    let Ok(native) = build(0x002e, 2422, profile, &map) else {
        return TestResult::Fail("admitted AR9287 owner refused");
    };
    if native.tx_chainmask() != 3
        || native.mac_clock() != Clock::AsyncFifo
        || native.channel_mask() != 1 << 2
        || native.frequency_mhz() != 2422
        || native.ht_grant().is_some()
    {
        return TestResult::Fail("AR9287 native profile differs");
    }
    // Per-channel records: the mask must name the calibrated primary and
    // stay inside channels 1..=13.
    for mask in [1 << 5, (1 << 2) | (1 << 13)] {
        if build_mask(0x002e, 2422, profile, &map, mask).is_ok() {
            return TestResult::Fail("AR9287 owner accepted a mask without its primary");
        }
    }
    match build_mask(0x002e, 2422, profile, &map, (1 << 2) | (1 << 5)) {
        Ok(native) if native.channel_mask() == (1 << 2) | (1 << 5) => {}
        _ => return TestResult::Fail("AR9287 per-channel record mask not retained"),
    }
    if native.long_calibration() != Err(PacketError::Access)
        || native.read(0x4020) != Err(PacketError::Access)
        || native.master(true) != Err(PacketError::Access)
    {
        return TestResult::Fail("revoked AR9287 authority reached the BAR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9287_native_profile_binds_admission_and_chains
);

fn facts_at(frequency: u16) -> Result<Facts, BringUpError> {
    let prepared = Prepared {
        geometry: Geometry::from_frequency(frequency)?,
        ini_writes: 711,
    };
    Facts::new(
        &device(0x002e),
        &Revision::decode(0x0018_03ff).ok_or(BringUpError::UnsupportedRevision)?,
        &identity(),
        &prepared,
        &image(3),
        frequency,
    )
}

/// Cold retunes load the target channel's own record: each channel has its
/// own filename and identity, and a record for one channel never admits
/// another channel's facts.
fn smoke_ath9k_ar9287_records_are_keyed_per_channel() -> TestResult {
    let (Ok(one), Ok(six)) = (facts_at(2412), facts_at(2437)) else {
        return TestResult::Fail("AR9287 per-channel facts refused");
    };
    let (a, b) = (one.request(), six.request());
    if a.filename != "ath9k/ar9287-admit-v1-ch1-02aabbccddee.bin"
        || b.filename != "ath9k/ar9287-admit-v1-ch6-02aabbccddee.bin"
        || a.identity == b.identity
        || b.frequency_mhz != 2437
    {
        return TestResult::Fail("AR9287 records are not keyed per channel");
    }
    let mut for_one = record(&one, 6, 36);
    for_one[54] = 1;
    let mut for_six = record(&six, 6, 36);
    for_six[54] = 6;
    if load(six.clone(), for_one.clone(), true).is_ok() {
        return TestResult::Fail("channel-1 record admitted channel 6");
    }
    // Same identity bytes but the channel field of another channel.
    let mut relabelled = for_one;
    relabelled[54] = 6;
    if load(six.clone(), relabelled, true).is_ok() {
        return TestResult::Fail("relabelled channel-1 record admitted channel 6");
    }
    match load(six, for_six, true) {
        Ok(grant) if grant.request() == b => TestResult::Pass,
        _ => TestResult::Fail("channel-6 record refused for channel 6"),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9287_records_are_keyed_per_channel
);

fn ar9280_facts(id: u16, frequency: u16) -> Result<Facts, BringUpError> {
    use crate::ath9k::phy::{ar9280, Tune};
    let tune = match ar9280::channel_5ghz(frequency) {
        Some(_) => Tune::Five {
            frequency,
            frac_n: false,
        },
        None => Tune::Two(Geometry::from_frequency(frequency)?),
    };
    let prepared = ar9280::Prepared {
        tune,
        ini_writes: if tune.is_5ghz() { 560 } else { 547 },
    };
    Facts::new_ar9280(
        &device(id),
        &Revision::decode(0x0008_01ff).ok_or(BringUpError::UnsupportedRevision)?,
        &crate::ath9k::phy::ar9280::power::tests::identity(0x10),
        &prepared,
        &crate::ath9k::phy::ar9280::power::tests::image(3),
        frequency,
        0,
    )
}

/// Format-only synthetic N80A record; the measured fields are markers.
fn ar9280_record(facts: &Facts, channel: u8, antenna: u8, ceiling: u8) -> Vec<u8> {
    let mut b = record(facts, antenna, ceiling);
    b[..4].copy_from_slice(b"N80A");
    b[54] = channel;
    b
}

fn smoke_ath9k_ar9280_admission_records_bind_band_channel_and_magic() -> TestResult {
    let (Ok(two), Ok(five)) = (ar9280_facts(0x002a, 2412), ar9280_facts(0x0029, 5180)) else {
        return TestResult::Fail("AR9280 admission facts refused");
    };
    if two.request().filename != "ath9k/ar9280-admit-v1-ch1-02aabbccddee.bin"
        || five.request().filename != "ath9k/ar9280-admit-v1-ch36-02aabbccddee.bin"
        || two.request().identity == five.request().identity
    {
        return TestResult::Fail("AR9280 records are not keyed per band and channel");
    }
    // Synthetic map: 2 GHz antennaGainCh max 4, 5 GHz all zero.
    let Ok(grant) = load(five.clone(), ar9280_record(&five, 36, 2, 30), true) else {
        return TestResult::Fail("well-formed signed 5 GHz N80A record refused");
    };
    if grant.ceiling(40) != 30 || grant.ceiling(20) != 18 {
        return TestResult::Fail("AR9280 measured antenna gain not removed from host limit");
    }
    for bytes in [
        record(&two, 4, 30),            // AR9287 magic
        ar9280_record(&two, 36, 4, 30), // wrong channel byte
        ar9280_record(&two, 1, 3, 30),  // antenna below factory
        ar9280_record(&two, 1, 4, 41),  // ceiling above 40
        ar9280_record(&five, 36, 0, 30)[..127].to_vec(),
    ] {
        if load(two.clone(), bytes, true).is_ok() {
            return TestResult::Fail("malformed or foreign N80A record admitted");
        }
    }
    if load(two.clone(), ar9280_record(&two, 1, 4, 30), false).is_ok()
        || load(two.clone(), ar9280_record(&two, 1, 4, 30), true).is_err()
    {
        return TestResult::Fail("AR9280 signer requirement differs");
    }
    // Wrong device, band/tune mismatch and non-channels are refused.
    if ar9280_facts(0x002e, 2412).is_ok()
        || ar9280_facts(0x002a, 5185).is_ok()
        || ar9280_facts(0x002a, 2484).is_ok()
    {
        return TestResult::Fail("AR9280 facts accepted a foreign device or channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9280_admission_records_bind_band_channel_and_magic
);
