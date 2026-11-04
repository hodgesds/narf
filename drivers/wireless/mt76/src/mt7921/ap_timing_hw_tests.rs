//! Actual checked MMIO transaction; the Session's timer/grants are tested
//! separately through native AP bootstrap, not invented by this fixture.
use super::*;
fn mt76_ap_actual_mac_timing_layout_preserves_arb_and_current_device_authority() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("native AP timing DMA fixture"),
    };
    for (five, short, expected, rate) in [
        (false, false, 0x140a0968, 3),
        (false, true, 0x090a0968, 0x49),
        (true, false, 0x09100968, 0x49),
    ] {
        words[0x20c80 / 4] = 0x01234000;
        words[0x20884 / 4] = 0xabcdffff;
        if hw.pause_ap_timing() != Ok(()) || words[0x20c80 / 4] != 0x01234300 {
            return TestResult::Fail("native AP timing did not pause actual ARB TX/RX");
        }
        if hw.finish_ap_timing(five, short) != Ok(())
            || words[0x21090 / 4] != 0x003000e7
            || words[0x21094 / 4] != 0x001c003c
            || words[0x210a4 / 4] != expected
            || words[0x20884 / 4] != (0xabcdc000 | rate)
            || words[0x20c80 / 4] != 0x01234000
        {
            return TestResult::Fail(
                "native AP TMAC/SIFS/slot/CFEND profile or unrelated ARB bits",
            );
        }
    }
    if hw.pause_ap_timing() != Ok(()) {
        return TestResult::Fail("native AP timing pause before revocation");
    }
    hw.authority.revoke();
    let before = words.clone();
    if hw.finish_ap_timing(false, false) != Err(Error::Authority) || before != words {
        return TestResult::Fail("revoked device authority resumed or rewrote native AP MAC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ap",
    mt76_ap_actual_mac_timing_layout_preserves_arb_and_current_device_authority
);
