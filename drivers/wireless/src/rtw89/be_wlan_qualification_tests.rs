// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
pub(in crate::rtw89) fn revocable() -> (
    WlanOnly,
    narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
) {
    let (factory, chip, assets, phycap, features) =
        super::super::be_qualification::tests::fixtures_version([0, 35, 8, 0]);
    let board = Board::new_wlan_be(&Facts {
        device: super::super::be_qualification::tests::device(),
        factory: &factory,
        chip,
        assets: &assets,
        features,
        phycap: &phycap,
    })
    .unwrap();
    let (calibration, cap) =
        super::super::calibration_policy::tests::revocable_model_wlan_be(board);
    (WlanOnly { calibration }, cap)
}
fn smoke_rtw8922a_wlan_identity_is_distinct_current_and_binds_actual_sources() -> TestResult {
    let (mut factory, chip, assets, phycap, features) =
        super::super::be_qualification::tests::fixtures_version([0, 35, 8, 0]);
    let device = super::super::be_qualification::tests::device();
    let measure = |factory: &super::super::efuse_be::checked::Snapshot, chip| {
        identity(&Facts {
            device,
            factory,
            chip,
            assets: &assets,
            features,
            phycap: &phycap,
        })
    };
    let first = measure(&factory, chip).unwrap();
    let partial = super::super::be_qualification::identity(&Facts {
        device,
        factory: &factory,
        chip,
        assets: &assets,
        features,
        phycap: &phycap,
    })
    .unwrap();
    kt_assert!(first != partial);
    factory.factory.rfe_type = 2;
    kt_assert!(measure(&factory, chip).unwrap() != first);
    factory.factory.rfe_type = 1;
    kt_assert!(
        measure(
            &factory,
            super::super::mac_pre_init_8922a::HalChipVer {
                acv: chip.acv ^ 1,
                ..chip
            }
        )
        .unwrap()
            != first
    );
    let bad = super::super::rfk::be_features::Features::fixture([0, 35, 9, 0]);
    kt_assert!(identity(&Facts {
        device,
        factory: &factory,
        chip,
        assets: &assets,
        features: bad,
        phycap: &phycap
    })
    .is_err());
    let (grant, cap) = revocable();
    kt_assert_eq!(grant.with_current(|| Ok::<_, power::Error>(7)), Ok(7));
    cap.revoke();
    let mut called = false;
    kt_assert_eq!(
        grant.with_current(|| {
            called = true;
            Ok::<_, power::Error>(())
        }),
        Err(power::Error::Access)
    );
    kt_assert!(!called);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_wlan_identity_is_distinct_current_and_binds_actual_sources
);
