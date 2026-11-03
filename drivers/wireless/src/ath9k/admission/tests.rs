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
