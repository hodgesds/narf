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

/// The dual-band AR9280 native owner binds the admitted device, primary,
/// band (tune, report and MAC clock), def-map chain masks and a
/// `channels::bit` mask over both bands, and every access (including the
/// AR9002 periodic calibration) stops at a revoked PCI capability.
fn smoke_ath9k_ar9280_native_profile_binds_band_admission_and_chains() -> TestResult {
    use crate::ath9k::{
        calibration::ar9280::Report,
        channels,
        mac::{Clock, Profile},
        packet::{Error as PacketError, Port},
        packet_native::Native,
        phy::{ar9280, Tune},
    };
    use narf_bus::{BarKind, BusAddr, BusDevice, BusDeviceCap, BusKind, MmioRegion, PcieAddr};
    use narf_capabilities::Write;
    let identity = ar9280::power::tests::identity(0x10);
    let mut map = ar9280::power::tests::image(3);
    map[18] = 3;
    let five = Tune::Five {
        frequency: 5180,
        frac_n: false,
    };
    let prepared = ar9280::Prepared {
        tune: five,
        ini_writes: 560,
    };
    let Some(revision) = Revision::decode(0x0008_01ff) else {
        return TestResult::Fail("AR9280 revision");
    };
    let Ok(facts) = Facts::new_ar9280(
        &device(0x002a),
        &revision,
        &identity,
        &prepared,
        &map,
        5180,
        0,
    ) else {
        return TestResult::Fail("AR9280 5 GHz facts refused");
    };
    let Ok(grant) = load(facts.clone(), ar9280_record(&facts, 36, 0, 30), true) else {
        return TestResult::Fail("signed 5 GHz N80A record refused");
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
    let report = |frequency_mhz, five_ghz| Report {
        country: *b"US",
        frequency_mhz,
        five_ghz,
        max_power_half_dbm: 30,
        rx_chainmask: 3,
        iq: [Some((0, 0)), Some((0, 0))],
        measured_noise_dbm: [Some(-112), Some(-112)],
        noise_dbm: [Some(-112), Some(-112)],
    };
    let (Some(bit36), Some(bit1)) = (channels::bit(5180), channels::bit(2412)) else {
        return TestResult::Fail("dual-band channel bits");
    };
    let build = |id, report: Report, profile, tune, mask: u64| {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        // SAFETY: the revoked fixture capability makes every config, DMA and
        // BAR path unreachable; no physical device is touched.
        unsafe {
            Native::new_ar9280(
                bus(id),
                cap,
                bar,
                report,
                grant.clone(),
                &identity,
                &map,
                profile,
                tune,
                0,
                mask,
            )
        }
    };
    let profile = Profile::ar9280(3, 3, true);
    let Ok(two) = Geometry::from_frequency(2412) else {
        return TestResult::Fail("2.4 GHz geometry");
    };
    for (id, report, profile, tune, mask) in [
        (0x002e, report(5180, true), profile, five, 1 << bit36),
        (0x0029, report(5180, true), profile, five, 1 << bit36),
        (0x002a, report(5180, false), profile, five, 1 << bit36),
        (
            0x002a,
            report(5180, true),
            Profile::ar9280(3, 3, false),
            five,
            1 << bit36,
        ),
        (
            0x002a,
            report(5180, true),
            Profile::ar9280(1, 1, true),
            five,
            1 << bit36,
        ),
        (
            0x002a,
            report(2412, false),
            profile,
            Tune::Two(two),
            1 << bit1,
        ),
        (0x002a, report(5180, true), profile, five, 1 << bit1),
        (
            0x002a,
            report(5180, true),
            profile,
            five,
            (1 << bit36) | (1 << 38),
        ),
    ] {
        if build(id, report, profile, tune, mask).is_ok() {
            return TestResult::Fail("AR9280 owner accepted a foreign device/band/profile/mask");
        }
    }
    let mask = (1 << bit36) | (1 << bit1);
    let Ok(native) = build(0x002a, report(5180, true), profile, five, mask) else {
        return TestResult::Fail("admitted 5 GHz AR9280 owner refused");
    };
    let geometry = native.geometry();
    if native.tx_chainmask() != 3
        || native.mac_clock() != Clock::Fast5g
        || native.channel_mask() != mask
        || native.frequency_mhz() != 5180
        || !geometry.is_5ghz()
        || geometry.control() != 5180
        || geometry.is_wide()
        || native.ht_grant().is_some()
    {
        return TestResult::Fail("AR9280 5 GHz native profile differs");
    }
    if native.long_calibration() != Err(PacketError::Access)
        || native.read(0x4020) != Err(PacketError::Access)
        || native.master(true) != Err(PacketError::Access)
    {
        return TestResult::Fail("revoked AR9280 authority reached the BAR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9280_native_profile_binds_band_admission_and_chains
);

/// `channels::bit` numbers 2.4 GHz channel `n` as bit `n - 1` (the
/// historical mask) and the 25 AR9280 5 GHz channels as bits 13..37;
/// numbering, frequency and the 5 GHz `Geometry` round-trip.
fn smoke_ath9k_dual_band_channel_bits_roundtrip() -> TestResult {
    use crate::ath9k::channels;
    let mut seen = 0u64;
    for bit in 0..channels::CHANNEL_BITS {
        let Some(frequency) = channels::bit_frequency(bit) else {
            return TestResult::Fail("channel bit without a primary");
        };
        let Ok(channel) = channels::channel(frequency) else {
            return TestResult::Fail("primary without an IEEE channel");
        };
        let Ok(geometry) = Geometry::from_frequency_dual(frequency) else {
            return TestResult::Fail("primary without a 20 MHz geometry");
        };
        if channels::bit(frequency) != Some(bit)
            || channels::frequency(u32::from(channel)) != Ok(frequency)
            || geometry.control() != frequency
            || geometry.center() != frequency
            || geometry.primary() != channel
            || geometry.is_5ghz() != (frequency >= 5000)
            || !channels::admits(1 << bit, frequency)
        {
            return TestResult::Fail("dual-band channel numbering does not round-trip");
        }
        seen |= 1 << bit;
    }
    if seen != (1 << 38) - 1
        || channels::bit_frequency(38).is_some()
        || channels::bit(2412) != Some(0)
        || channels::bit(2472) != Some(12)
        || channels::bit(5180) != Some(13)
        || channels::bit(5825) != Some(37)
    {
        return TestResult::Fail("dual-band channel mask layout differs");
    }
    // Non-channels: 2484 (channel 14), 5 GHz off-raster, 5170, 5260+2.
    for frequency in [2484, 2417 + 1, 5170, 5185, 5262, 5845, 4920] {
        if channels::bit(frequency).is_some() || Geometry::from_frequency_dual(frequency).is_ok() {
            return TestResult::Fail("a non-channel received a mask bit or geometry");
        }
    }
    for channel in [0, 14, 34, 68, 96, 148, 169, 255, 1 << 20] {
        if channels::frequency(channel).is_ok() {
            return TestResult::Fail("a non-channel number mapped to a frequency");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_dual_band_channel_bits_roundtrip
);

fn ar5008_facts(id: u16, frequency: u16, rx: u8) -> Result<Facts, BringUpError> {
    use crate::ath9k::phy::{ar5008, ar9280, Tune};
    let tune = match ar9280::channel_5ghz(frequency) {
        Some(_) => Tune::Five {
            frequency,
            frac_n: false,
        },
        None => Tune::Two(Geometry::from_frequency(frequency)?),
    };
    // Marker row count; never a board value.
    let prepared = ar5008::Prepared {
        tune,
        ini_writes: 534,
    };
    let srev = if id == 0x0027 {
        0x0004_01ff
    } else {
        0x0000_00d1
    };
    let mut identity = crate::ath9k::phy::ar9280::power::tests::identity(0x10);
    identity.rx_chainmask = rx;
    Facts::new_ar5008(
        &device(id),
        &Revision::decode(srev).ok_or(BringUpError::UnsupportedRevision)?,
        0x40,
        &identity,
        &prepared,
        &crate::ath9k::phy::ar9280::power::tests::image(3),
        frequency,
        0,
    )
}

fn smoke_ath9k_ar5008_admission_records_bind_chip_masks_and_channel() -> TestResult {
    let (Ok(ar5416), Ok(ar9160), Ok(five), Ok(cb71)) = (
        ar5008_facts(0x0023, 2412, 7),
        ar5008_facts(0x0027, 2412, 7),
        ar5008_facts(0x0024, 5180, 7),
        ar5008_facts(0x0023, 2412, 5),
    ) else {
        return TestResult::Fail("AR5008 admission facts refused");
    };
    if ar5416.request().filename != "ath9k/ar5416-admit-v1-ch1-02aabbccddee.bin"
        || ar9160.request().filename != "ath9k/ar9160-admit-v1-ch1-02aabbccddee.bin"
        || five.request().filename != "ath9k/ar5416-admit-v1-ch36-02aabbccddee.bin"
    {
        return TestResult::Fail("AR5008 record filenames not keyed per chip and channel");
    }
    let ids = [&ar5416, &ar9160, &five, &cb71].map(|f| f.request().identity);
    if (0..4).any(|i| (i + 1..4).any(|j| ids[i] == ids[j])) {
        return TestResult::Fail("AR5008 identities do not bind chip, band and RX mask");
    }
    let with = |facts: &Facts, magic: &[u8; 4], rx: u8| {
        let mut b = record(facts, 4, 30);
        b[..4].copy_from_slice(magic);
        b[54..58].copy_from_slice(&[1, 20, rx, 3]);
        b
    };
    if load(ar5416.clone(), with(&ar5416, b"N54A", 7), true).is_err()
        || load(ar9160.clone(), with(&ar9160, b"N60A", 7), true).is_err()
        || load(cb71.clone(), with(&cb71, b"N54A", 5), true).is_err()
    {
        return TestResult::Fail("well-formed signed AR5008 record refused");
    }
    for (facts, bytes) in [
        (&ar5416, with(&ar5416, b"N60A", 7)), // AR9160 magic on AR5416
        (&ar9160, with(&ar9160, b"N54A", 7)), // AR5416 magic on AR9160
        (&ar9160, with(&ar9160, b"N80A", 7)), // AR9280 magic
        (&cb71, with(&cb71, b"N54A", 7)),     // map mask, not the CB71 mask
    ] {
        if load(facts.clone(), bytes, true).is_ok() {
            return TestResult::Fail("foreign-chip or wrong-mask AR5008 record admitted");
        }
    }
    if ar5008_facts(0x0029, 2412, 7).is_ok()
        || ar5008_facts(0x0027, 2484, 7).is_ok()
        || ar5008_facts(0x0027, 2412, 8).is_ok()
    {
        return TestResult::Fail("AR5008 facts accepted a foreign device, channel or mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar5008_admission_records_bind_chip_masks_and_channel
);

/// The AR5416/AR5418/AR9160 native owner binds the admitted device and
/// chip, the primary and band (tune, report and the 40 MHz OFDM 5 GHz MAC
/// clock), the effective three-chain masks, the generation's MFP branch and
/// CB71 rule, and a `channels::bit` mask naming the primary; every access
/// (including the AR5008 periodic calibration) stops at a revoked PCI
/// capability.
fn smoke_ath9k_ar5008_native_profile_binds_chip_band_and_masks() -> TestResult {
    use crate::ath9k::{
        calibration::ar5008::Report,
        channels,
        chips::Chip,
        mac::{Clock, Profile},
        packet::{Error as PacketError, Port},
        packet_native::Native,
        phy::Tune,
    };
    use narf_bus::{BarKind, BusAddr, BusDevice, BusDeviceCap, BusKind, MmioRegion, PcieAddr};
    use narf_capabilities::Write;
    let map = crate::ath9k::phy::ar9280::power::tests::image(3);
    let mut identity = crate::ath9k::phy::ar9280::power::tests::identity(0x10);
    identity.rx_chainmask = 7;
    let tx = identity.tx_chainmask;
    let with = |facts: &Facts, magic: &[u8; 4], channel: u8| {
        let mut b = record(facts, 4, 30);
        b[..4].copy_from_slice(magic);
        b[54..58].copy_from_slice(&[channel, 20, 7, tx]);
        b
    };
    let (Ok(f9160), Ok(f5418)) = (ar5008_facts(0x0027, 2412, 7), ar5008_facts(0x0024, 5180, 7))
    else {
        return TestResult::Fail("AR5008 native facts refused");
    };
    let (Ok(g9160), Ok(g5418)) = (
        load(f9160.clone(), with(&f9160, b"N60A", 1), true),
        load(f5418.clone(), with(&f5418, b"N54A", 36), true),
    ) else {
        return TestResult::Fail("signed AR5008 records refused");
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
    let report = |chip, frequency_mhz, five_ghz| Report {
        chip,
        country: *b"US",
        frequency_mhz,
        five_ghz,
        max_power_half_dbm: 30,
        rx_chainmask: 7,
        iq: [None; 3],
        measured_noise_dbm: [Some(-95), Some(-95), Some(-95)],
        noise_dbm: [Some(-95), Some(-95), Some(-95)],
    };
    let (Some(bit1), Some(bit36), Ok(two)) = (
        channels::bit(2412),
        channels::bit(5180),
        Geometry::from_frequency(2412),
    ) else {
        return TestResult::Fail("AR5008 channel bits");
    };
    let two = Tune::Two(two);
    let five = Tune::Five {
        frequency: 5180,
        frac_n: false,
    };
    let build = |id, grant: &Arc<Grant>, report: Report, profile, tune, mask: u64| {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        // SAFETY: the revoked fixture capability makes every config, DMA and
        // BAR path unreachable; no physical device is touched.
        unsafe {
            Native::new_ar5008(
                bus(id),
                cap,
                bar,
                report,
                grant.clone(),
                &identity,
                &map,
                profile,
                tune,
                0,
                mask,
            )
        }
    };
    let p9160 = Profile::ar5008(7, tx, false, true, false);
    let p5418 = Profile::ar5008(7, tx, true, false, false);
    let r9160 = report(Chip::Ar9160, 2412, false);
    let r5418 = report(Chip::Ar5416, 5180, true);
    for (id, grant, report, profile, tune, mask) in [
        // AR9280 device, or the AR9160 grant on another device.
        (0x0029, &g9160, r9160, p9160, two, 1 << bit1),
        (0x0024, &g9160, r9160, p9160, two, 1 << bit1),
        // AR5416 calibration report on the AR9160.
        (
            0x0027,
            &g9160,
            report(Chip::Ar5416, 2412, false),
            p9160,
            two,
            1 << bit1,
        ),
        // AR5416 MFP (none) on the AR9160, CB71 on a non-AR5416 part.
        (
            0x0027,
            &g9160,
            r9160,
            Profile::ar5008(7, tx, false, false, false),
            two,
            1 << bit1,
        ),
        (
            0x0027,
            &g9160,
            r9160,
            Profile::ar5008(7, tx, false, true, true),
            two,
            1 << bit1,
        ),
        // Effective RX mask differing from the identity's.
        (
            0x0027,
            &g9160,
            r9160,
            Profile::ar5008(5, tx, false, true, false),
            two,
            1 << bit1,
        ),
        // 5 GHz MAC clock on a 2.4 GHz primary; tune of another band.
        (
            0x0027,
            &g9160,
            r9160,
            Profile::ar5008(7, tx, true, true, false),
            two,
            1 << bit1,
        ),
        (0x0024, &g5418, r5418, p5418, two, 1 << bit36),
        // Mask without the primary or beyond CHANNEL_BITS.
        (0x0027, &g9160, r9160, p9160, two, 1 << bit36),
        (0x0027, &g9160, r9160, p9160, two, (1 << bit1) | (1 << 38)),
    ] {
        if build(id, grant, report, profile, tune, mask).is_ok() {
            return TestResult::Fail("AR5008 owner accepted a foreign device/chip/profile/mask");
        }
    }
    let Ok(native) = build(0x0027, &g9160, r9160, p9160, two, 1 << bit1) else {
        return TestResult::Fail("admitted AR9160 owner refused");
    };
    if native.tx_chainmask() != tx
        || native.mac_clock() != Clock::Ofdm2g
        || native.channel_mask() != 1 << bit1
        || native.frequency_mhz() != 2412
        || native.ht_grant().is_some()
    {
        return TestResult::Fail("AR9160 native profile differs");
    }
    let mask = (1 << bit36) | (1 << bit1);
    let Ok(native5) = build(0x0024, &g5418, r5418, p5418, five, mask) else {
        return TestResult::Fail("admitted 5 GHz AR5418 owner refused");
    };
    let geometry = native5.geometry();
    if native5.mac_clock() != Clock::Ofdm5g
        || native5.channel_mask() != mask
        || !geometry.is_5ghz()
        || geometry.control() != 5180
        || geometry.is_wide()
    {
        return TestResult::Fail("AR5418 5 GHz native profile differs");
    }
    for native in [&native, &native5] {
        if native.long_calibration() != Err(PacketError::Access)
            || native.read(0x4020) != Err(PacketError::Access)
            || native.master(true) != Err(PacketError::Access)
        {
            return TestResult::Fail("revoked AR5008 authority reached the BAR");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar5008_native_profile_binds_chip_band_and_masks
);

fn ar9300_facts(id: u16, frequency: u16, ctl: u16) -> Result<Facts, BringUpError> {
    ar9003_facts(crate::ath9k::ar9003::Chip::Ar9300, id, frequency, ctl)
}

fn ar9003_facts(
    chip: crate::ath9k::ar9003::Chip,
    id: u16,
    frequency: u16,
    ctl: u16,
) -> Result<Facts, BringUpError> {
    use crate::ath9k::ar9003::{eeprom, phy, power, templates::AR9300_DEFAULT, Chip, Revision};
    let identity = eeprom::Identity {
        mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        eeprom_version: 2,
        template_version: 2,
        regulatory_domains: [0x3a, 0],
        op_flags: 3,
        rx_chainmask: 7,
        tx_chainmask: 7,
        tx_gain: 0,
        rx_gain: 0,
    };
    let prepared = phy::Prepared {
        frequency,
        modes_index: if frequency >= 4800 { 1 } else { 4 },
        carrier_leak_cal: true,
        selfgen_mask: 3,
        power: power::plan(&AR9300_DEFAULT, frequency, ctl, 40, 7)?,
        ini_writes: 200,
    };
    let revision = Revision {
        chip,
        mac_rev: if chip == Chip::Ar9580 { 4 } else { 3 },
        pcie: true,
    };
    Facts::new_ar9003(
        &device(id),
        &revision,
        &identity,
        &prepared,
        &AR9300_DEFAULT,
        frequency,
        ctl,
    )
}

fn ar9300_record(facts: &Facts, channel: u8, antenna: u8, ceiling: u8) -> Vec<u8> {
    let mut b = record(facts, antenna, ceiling);
    b[..4].copy_from_slice(b"N93A");
    b[54..58].copy_from_slice(&[channel, 20, 7, 7]);
    b
}

fn smoke_ath9k_ar9300_admission_records_bind_channel_ctl_and_magic() -> TestResult {
    let (Ok(two), Ok(fourteen), Ok(five)) = (
        ar9300_facts(0x0030, 2412, 0x12),
        ar9300_facts(0x0030, 2484, 0x12),
        ar9300_facts(0x0030, 5180, 0x10),
    ) else {
        return TestResult::Fail("AR9300 admission facts refused");
    };
    if two.request().filename != "ath9k/ar9300-admit-v1-ch1-02aabbccddee.bin"
        || fourteen.request().filename != "ath9k/ar9300-admit-v1-ch14-02aabbccddee.bin"
        || five.request().filename != "ath9k/ar9300-admit-v1-ch36-02aabbccddee.bin"
        || two.request().identity == five.request().identity
        || ar9300_facts(0x0030, 2412, 0x32)
            .is_ok_and(|other| other.request().identity == two.request().identity)
    {
        return TestResult::Fail("AR9300 records are not keyed per channel and CTL");
    }
    let factory = two.factory_antenna;
    let Ok(grant) = load(two.clone(), ar9300_record(&two, 1, factory + 2, 30), true) else {
        return TestResult::Fail("well-formed signed N93A record refused");
    };
    if grant.ceiling(40) != 30 || grant.ceiling(20) != 18 {
        return TestResult::Fail("AR9300 measured antenna gain not removed from host limit");
    }
    let mut chains = ar9300_record(&two, 1, factory, 30);
    chains[56] = 3;
    for bytes in [
        ar9280_record(&two, 1, factory, 30),  // AR9280 magic
        ar9300_record(&two, 36, factory, 30), // wrong channel byte
        ar9300_record(&two, 1, factory, 41),  // ceiling above 40
        chains,                               // foreign chain mask
        ar9300_record(&two, 1, factory, 30)[..127].to_vec(),
    ] {
        if load(two.clone(), bytes, true).is_ok() {
            return TestResult::Fail("malformed or foreign N93A record admitted");
        }
    }
    if load(two.clone(), ar9300_record(&two, 1, factory, 30), false).is_ok() {
        return TestResult::Fail("unsigned N93A record admitted");
    }
    // Foreign device and unsupported channels are refused.
    if ar9300_facts(0x002a, 2412, 0x12).is_ok()
        || ar9300_facts(0x0030, 2414, 0x12).is_ok()
        || ar9300_facts(0x0030, 5170, 0x10).is_ok()
    {
        return TestResult::Fail("AR9300 facts accepted a foreign device or channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9300_admission_records_bind_channel_ctl_and_magic
);

fn ar9580_record(facts: &Facts, channel: u8, antenna: u8, ceiling: u8) -> Vec<u8> {
    let mut b = ar9300_record(facts, channel, antenna, ceiling);
    b[..4].copy_from_slice(b"N95A");
    b
}

fn smoke_ath9k_ar9580_admission_records_bind_part_channel_and_magic() -> TestResult {
    use crate::ath9k::ar9003::Chip;
    let (Ok(two), Ok(five), Ok(ar9300)) = (
        ar9003_facts(Chip::Ar9580, 0x0033, 2412, 0x12),
        ar9003_facts(Chip::Ar9580, 0x0033, 5180, 0x10),
        ar9300_facts(0x0030, 2412, 0x12),
    ) else {
        return TestResult::Fail("AR9580 admission facts refused");
    };
    if two.request().filename != "ath9k/ar9580-admit-v1-ch1-02aabbccddee.bin"
        || five.request().filename != "ath9k/ar9580-admit-v1-ch36-02aabbccddee.bin"
        || two.request().device != 0x0033
        || two.request().identity == five.request().identity
        || two.request().identity == ar9300.request().identity
    {
        return TestResult::Fail("AR9580 records are not keyed per part and channel");
    }
    // Each AR9003 part is bound to its own device ID.
    if ar9003_facts(Chip::Ar9580, 0x0030, 2412, 0x12).is_ok()
        || ar9003_facts(Chip::Ar9300, 0x0033, 2412, 0x12).is_ok()
        || ar9003_facts(Chip::Ar9580, 0x0033, 2414, 0x12).is_ok()
    {
        return TestResult::Fail("AR9580 facts accepted a foreign device or channel");
    }
    let factory = two.factory_antenna;
    let Ok(grant) = load(two.clone(), ar9580_record(&two, 1, factory, 30), true) else {
        return TestResult::Fail("well-formed signed N95A record refused");
    };
    if grant.ceiling(40) != 30 {
        return TestResult::Fail("AR9580 signed ceiling not applied");
    }
    for bytes in [
        ar9300_record(&two, 1, factory, 30),  // AR9300 magic
        ar9580_record(&two, 36, factory, 30), // wrong channel byte
        ar9580_record(&two, 1, factory, 41),  // ceiling above 40
    ] {
        if load(two.clone(), bytes, true).is_ok() {
            return TestResult::Fail("foreign or malformed N95A record admitted");
        }
    }
    // An AR9580 record never admits the AR9300 facts.
    if load(ar9300.clone(), ar9580_record(&ar9300, 1, factory, 30), true).is_ok()
        || load(two.clone(), ar9580_record(&two, 1, factory, 30), false).is_ok()
    {
        return TestResult::Fail("N95A record crossed parts or admitted unsigned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/admission",
    smoke_ath9k_ar9580_admission_records_bind_part_channel_and_magic
);
