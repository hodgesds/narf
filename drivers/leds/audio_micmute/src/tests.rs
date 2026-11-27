//! Smoke tests for `narf-drivers-leds-audio-micmute`.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::trigger::micmute_brightness;

fn smoke_audio_micmute_brightness() -> TestResult {
    if micmute_brightness(true, 1) != 1 || micmute_brightness(false, 1) != 0 {
        return TestResult::Fail("micmute level must be max while muted, 0 while unmuted");
    }
    if micmute_brightness(true, 255) != 255 {
        return TestResult::Fail("micmute level must reach max_brightness");
    }
    if micmute_brightness(false, 255) != 0 {
        return TestResult::Fail("micmute level must be 0 while unmuted at any max");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/leds/audio-micmute", smoke_audio_micmute_brightness);
