//! Actual Native/NativeIo current-cap register publication, with explicit
//! inert RF/DPK-input boundaries. No real attach/measurement is claimed.
use super::*;
use crate::rtw89::{rf_tracking, station_control::Admission};
use alloc::sync::Arc;

fn setup() -> Fixture {
    let mut fixture = Fixture::aperture(ChipId::Rtl8852B, 0x20000).unwrap();
    fixture.activate().unwrap();
    for (path, thermal, txagc, tp, hw_offset, txdpd) in [
        (0, 30, 0xfe0a0001, 3, false, false),
        (1, 36, 0x04140002, 7, true, true),
    ] {
        for (address, value) in [
            (0x1c10 + (path << 13), thermal << 24),
            (0x1c60 + (path << 13), txagc),
            (0x1c04 + (path << 13), tp),
            (0x58d4 + (path << 13), u32::from(txdpd) << 28),
            (0x5820 + (path << 13), 1 << 31),
            (0x5818 + (path << 13), 0x18000000),
            (0x81c8 + (path << 8), u32::from(hw_offset) << 15),
            (0x81b4 + (path << 8), 0xa600c600),
        ] {
            fixture.words[(rf_tracking::BASE + address) as usize / 4] = value;
        }
    }
    fixture.native.station_runtime.model_started();
    fixture.native.station_runtime.rf_tracking = Some(rf_tracking::tests::tracker());
    fixture
}
fn pwsf(fixture: &Fixture) -> [u32; 2] {
    [fixture.words[0x181b4 / 4], fixture.words[0x182b4 / 4]]
}
fn smoke_rtw8852b_periodic_dpk_native_current_program_window_and_original_owner() -> TestResult {
    for failure in 0..6 {
        let mut f = setup();
        let window = rf_tracking::Window {
            low: 100,
            high: 140,
        };
        let (qualification, base, tracking) =
            crate::rtw89::radio_policy::tests::rf_tracking_model(window, failure == 0);
        f.native.ordinary = Some(OrdinaryGrant::B(Arc::new(qualification)));
        let admission = Admission::new();
        let before = pwsf(&f);
        match failure {
            1 => admission.close(),
            2 => {
                base.revoke();
            }
            3 => {
                tracking.revoke();
            }
            4 => {
                f.native.station_runtime.rf_tracking = None;
            }
            5 => {
                f.words[0x15820 / 4] = 0;
            }
            _ => {}
        }
        let result = f.native.station_rf_tracking(&admission);
        if failure == 0 {
            if result.is_err()
                || pwsf(&f) != [0xa672c672, 0xa67ec67e]
                || f.native.station_runtime.rf_tracking.is_none()
            {
                return TestResult::Fail(
                    "actual Native source/current joint-program PWSF publication",
                );
            }
        } else if result.is_ok() || pwsf(&f) != before {
            return TestResult::Fail(
                "lost original source/calibration/TSSI authority changed native PWSF",
            );
        }
    }
    // Old full-radio/A-MPDU programs remain operational with no periodic
    // RF operation or manufactured DPK input; optional absence means no-op.
    let mut f = setup();
    let (qualification, _) = crate::rtw89::radio_policy::tests::revocable_model();
    f.native.ordinary = Some(OrdinaryGrant::B(Arc::new(qualification)));
    f.native.station_runtime.rf_tracking = None;
    let before = pwsf(&f);
    if f.native.station_rf_tracking(&Admission::new()).is_err() || pwsf(&f) != before {
        return TestResult::Fail("absent periodic RF record changed old native program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/tracking",
    smoke_rtw8852b_periodic_dpk_native_current_program_window_and_original_owner
);
