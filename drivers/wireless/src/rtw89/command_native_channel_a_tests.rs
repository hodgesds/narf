// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use crate::rtw89::{channel_a, operating_channel::Profile, power, rfk};

fn smoke_rtw8852a_native_channel_requires_current_qualification() -> TestResult {
    let mut fixture = Fixture::aperture(ChipId::Rtl8852A, 0x40020).unwrap();
    fixture.activate().unwrap();
    // Coexistence/NCTL presence never substitutes for actual signed A
    // calibration/channel qualification or the native factory/RX checks.
    fixture.native.coex_ready = true;
    fixture.native.nctl_ready = true;
    let before = fixture.words.clone();
    let plan = channel_a::tests::power_plan(Profile::INITIAL);
    let mut channel = channel_a::Channel::default();
    // SAFETY: private inert Native BAR fixture; no producer/emission.
    let result =
        ready(unsafe { channel.set_channel(&mut fixture.native, Profile::INITIAL, &plan) });
    if result != Some(Err(rfk::Error::Register(power::Error::Access)))
        || channel.state() != channel_a::State::Busy
        || channel.programmed().is_some()
        || fixture.words != before
        || fixture.native.channel.is_some()
        || fixture.native.ordinary_current().is_ok()
    {
        return TestResult::Fail("A channel program bypassed actual Native qualification");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_channel_requires_current_qualification
);

/// Actual Native dispatch with an inert LTE completion script. Linux's
/// wl_only branch precedes band dispatch and forces both bands to WONLY;
/// A uses the generic AX grant, independently of Native.channel readiness.
fn smoke_rtw8852a_native_band_notify_keeps_wlan_only_grants() -> TestResult {
    use core::ptr::{read_volatile, write_volatile};
    for five_ghz in [false, true] {
        let mut fixture = Fixture::aperture(ChipId::Rtl8852A, 0x40020).unwrap();
        fixture.activate().unwrap();
        let mut source = FactorySource::new();
        let mut factory = crate::rtw89::factory::Factory::default();
        if ready(factory.read(&mut source)) != Some(Ok(())) {
            return TestResult::Fail("A factory/PHY-cap observation fixture");
        }
        fixture.native.factory = Some(factory);
        let mut rx = RxModel::new();
        // SAFETY: inert RX model with no DMA/reset/IRQ producer.
        if ready(unsafe {
            fixture
                .native
                .receive
                .prepare_for(&mut rx, ChipId::Rtl8852A, 4)
        }) != Some(Ok(()))
        {
            return TestResult::Fail("A polling RX observation fixture");
        }
        let (calibration, authority) = crate::rtw89::calibration_policy::tests::revocable_model_a();
        fixture.native.calibration = Some(calibration);
        fixture.native.coex_ready = true;
        fixture.native.nctl_ready = true;
        // Channel program facts, without declaring completed RFK or ordinary
        // readiness. The source WONLY action controls both grant bands.
        fixture.words[0x14644 / 4] = if five_ghz { 0 } else { 1 << 30 };
        fixture.words[0x14718 / 4] = if five_ghz { 0 } else { 1 << 30 };
        fixture.words[0xda48 / 4] = 0x1234_5678; // C-only grant must survive.
        fixture.words[0xdaf8 / 4] = 0x7700_7700; // LTE 0x38 read response.
        let pointer = fixture.words.as_mut_ptr();
        let mut saw_write = false;
        let mut saw_value = false;
        let result = {
            let mut operation =
                alloc::boxed::Box::pin(rfk::Interface::coex_switch_band(&mut fixture.native));
            let scripted = core::future::poll_fn(|cx| {
                // SAFETY: this fixture owns all BAR RAM. No Rust reference
                // into it lives across polling. The same-thread remote
                // script acknowledges LTE writes between host polls.
                let command = unsafe { read_volatile(pointer.add(0xdaf0 / 4)) };
                if command & !(1 << 29) == 0xc00f_0038 {
                    saw_write = true;
                    // SAFETY: the fixture exclusively owns this in-bounds BAR
                    // RAM; this read runs between polls on the same thread.
                    saw_value = unsafe { read_volatile(pointer.add(0xdaf4 / 4)) } == 0x7700_7700;
                }
                // The Native future retains its real monotonic delay. The
                // kernel-test BSP has no active timer pump, so the spin
                // bridge drives hrtimers without depending on its timer IRQ.
                // SAFETY: the fixture exclusively owns this in-bounds BAR
                // RAM; the remote acknowledgement runs between host polls.
                unsafe {
                    write_volatile(pointer.add(0xdaf0 / 4), command | (1 << 29));
                }
                operation.as_mut().poll(cx)
            });
            narf_scheduler::block_on_spin(scripted)
        };
        if result.is_err()
            || !saw_write
            || !saw_value
            || fixture.words[0xdaf0 / 4] != 0x800f_0038
            || fixture.words[0xc67c / 4] & 0xffff != 0x111
            || fixture.words[0x70 / 4] & (4 << 24) == 0
            || fixture.words[0xda48 / 4] != 0x1234_5678
            || fixture.native.channel.is_some()
            || fixture.native.ordinary_current().is_ok()
            || fixture.native.queue.pending() != 0
        {
            return TestResult::Fail("A WONLY band notify used the wrong grants/readiness");
        }
        authority.revoke();
        let before = fixture.words.clone();
        if ready(rfk::Interface::coex_switch_band(&mut fixture.native))
            != Some(Err(rfk::Error::Register(power::Error::Access)))
            || fixture.words != before
        {
            return TestResult::Fail("revoked A band notify touched Native BAR");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_band_notify_keeps_wlan_only_grants
);
