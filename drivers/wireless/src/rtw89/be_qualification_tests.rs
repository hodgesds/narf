// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
pub(in crate::rtw89) fn device() -> narf_bus::DeviceId {
    narf_bus::DeviceId {
        vendor: 0x10ec,
        device: 0x8922,
        class: 0x028000,
        subsystem_vendor: 0x10ec,
        subsystem_id: 0xa891,
    }
}
pub(in crate::rtw89) fn fixtures() -> (Snapshot, HalChipVer, Assets, Receipt, Features) {
    fixtures_version([0; 4])
}
pub(in crate::rtw89) fn fixtures_version(
    version: [u8; 4],
) -> (Snapshot, HalChipVer, Assets, Receipt, Features) {
    // Source-shaped MFW/element bytes; never a device firmware fixture.
    let mut bytes = vec![0; 48];
    bytes[0] = 255;
    bytes[1] = 1;
    bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&16u32.to_le_bytes());
    for (id, index, address, value) in [
        (2u32, 0, 0x100u32, 0x1111u32),
        (3, 0, 0, 0x01020304),
        (4, 0, 0x10055, 0xc0ffe),
        (5, 1, 0x10055, 0xd0ffe),
        (8, 0, 0x200, 0),
    ] {
        let at = bytes.len();
        bytes.resize(at + 32, 0);
        bytes[at..at + 4].copy_from_slice(&id.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&8u32.to_le_bytes());
        bytes[at + 24] = index;
        bytes.extend_from_slice(&address.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.resize(bytes.len().div_ceil(16) * 16, 0);
    }
    let factory = super::super::efuse_be::BeFactory {
        mac: [2, 1, 2, 3, 4, 5],
        rfe_type: 1,
        xtal_cap: 0x3a,
        country: *b"US",
        phycap: [0; super::super::chip_8922a::PHYCAP_SIZE],
        cv: Some(0),
        thermal_k: None,
        secure: super::super::efuse_be::SecureInfo::disabled(),
    };
    let rf = vec![255; 0x240];
    let calibration = super::super::factory_be::Calibration::from_logical(&rf).unwrap();
    let snapshot = Snapshot {
        factory,
        rf,
        hci: vec![255; 0x4800],
        calibration,
    };
    let chip = HalChipVer {
        cv: 0,
        acv: 1,
        aid: 0x1234,
        cid: super::super::mac_pre_init_8922a::Cid::from_raw(0x22),
    };
    let assets = Assets::fixture_be_observed_version(&bytes, chip.aid, version);
    let features = Features::fixture(version);
    let phycap = Receipt::fixture(features, 0x8922, [0x403, 0, 0, 0], None);
    (snapshot, chip, assets, phycap, features)
}
pub(in crate::rtw89) fn revocable() -> (
    Partial,
    narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
) {
    let (factory, chip, assets, phycap, features) = fixtures();
    let board = Board::new_partial_be(&Facts {
        device: device(),
        factory: &factory,
        chip,
        assets: &assets,
        features,
        phycap: &phycap,
    })
    .unwrap();
    let (calibration, cap) =
        super::super::calibration_policy::tests::revocable_model_partial_be(board);
    (Partial { calibration }, cap)
}
fn smoke_rtw8922a_partial_identity_binds_actual_maps_quirk_chip_and_phycap() -> TestResult {
    let (mut factory, mut chip, assets, phycap, features) = fixtures();
    let mut id = device();
    let measure = |factory: &Snapshot, chip, id, phycap: &Receipt| {
        identity(&Facts {
            device: id,
            factory,
            chip,
            assets: &assets,
            features,
            phycap,
        })
    };
    let initial = measure(&factory, chip, id, &phycap).unwrap();
    for location in 0..3 {
        match location {
            0 => factory.rf[40] ^= 1,
            1 => factory.hci[44] ^= 1,
            _ => factory.factory.phycap[6] ^= 1,
        }
        kt_assert!(measure(&factory, chip, id, &phycap).unwrap() != initial);
        match location {
            0 => factory.rf[40] ^= 1,
            1 => factory.hci[44] ^= 1,
            _ => factory.factory.phycap[6] ^= 1,
        }
    }
    chip.acv ^= 1;
    kt_assert!(measure(&factory, chip, id, &phycap).unwrap() != initial);
    chip.acv ^= 1;
    chip.aid ^= 1;
    kt_assert_eq!(measure(&factory, chip, id, &phycap), Err(Error::Identity));
    chip.aid ^= 1;
    id.subsystem_id ^= 1;
    kt_assert_eq!(thermal_threshold(id), 0);
    kt_assert!(measure(&factory, chip, id, &phycap).unwrap() != initial);
    id.subsystem_id ^= 1;
    kt_assert_eq!(thermal_threshold(id), 0xb4);
    let changed = Receipt::fixture(features, 0x8922, [0x403, 1, 0, 0], None);
    kt_assert!(measure(&factory, chip, id, &changed).unwrap() != initial);
    let wrong = Receipt::fixture(
        Features::fixture([0, 35, 31, 0]),
        0x8922,
        [0x403, 0, 0, 0],
        None,
    );
    kt_assert_eq!(measure(&factory, chip, id, &wrong), Err(Error::Identity));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_partial_identity_binds_actual_maps_quirk_chip_and_phycap
);
fn smoke_rtw8922a_partial_measurement_current_scope_encloses_effect() -> TestResult {
    let (grant, cap) = revocable();
    let mut effects = 0;
    kt_assert!(grant
        .with_current(|| {
            effects += 1;
            Ok::<(), power::Error>(())
        })
        .is_ok());
    cap.revoke();
    kt_assert_eq!(
        grant.with_current(|| {
            effects += 1;
            Ok::<(), power::Error>(())
        }),
        Err(power::Error::Access)
    );
    kt_assert_eq!(effects, 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_partial_measurement_current_scope_encloses_effect
);
