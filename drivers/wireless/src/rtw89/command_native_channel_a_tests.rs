// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use crate::rtw89::radio_a::observations::{Observations, Snapshot, State as ObservationState};
use crate::rtw89::{channel_a, operating_channel::Profile, power, rfk};

type FirmwareGrant = narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>;
fn thermal_fixture() -> (Fixture, FirmwareGrant, FirmwareGrant) {
    let mut fixture = Fixture::aperture(ChipId::Rtl8852A, 0x40020).unwrap();
    fixture.activate().unwrap();
    let mut source = FactorySource::new();
    let mut factory = crate::rtw89::factory::Factory::default();
    assert_eq!(ready(factory.read(&mut source)), Some(Ok(())));
    fixture.native.factory = Some(factory);
    let mut rx = RxModel::new();
    assert_eq!(
        // SAFETY: independently owned inert RX/DMA model, never hardware.
        ready(unsafe {
            fixture
                .native
                .receive
                .prepare_for(&mut rx, ChipId::Rtl8852A, 4)
        }),
        Some(Ok(()))
    );
    let (calibration, calibration_grant) =
        crate::rtw89::calibration_policy::tests::revocable_model_a();
    let (qualification, qualification_grant) =
        crate::rtw89::radio_policy_a::tests::revocable_model();
    fixture.native.calibration = Some(calibration);
    fixture.native.mac_a = Some(alloc::sync::Arc::new(
        crate::rtw89::mac_a_policy::tests::model().0,
    ));
    fixture.native.qualification_a = Some(alloc::sync::Arc::new(qualification));
    fixture.native.coex_ready = true;
    fixture.native.nctl_ready = true;
    (fixture, calibration_grant, qualification_grant)
}

fn smoke_rtw8852a_native_channel_program_queries_use_exact_current_a_owner() -> TestResult {
    for optional in [false, true] {
        let (mut fixture, _, mut original) = thermal_fixture();
        if optional {
            let (q, cap) = crate::rtw89::radio_policy_a::tests::programs_model();
            fixture.native.qualification_a = Some(alloc::sync::Arc::new(q));
            original = cap;
        }
        let qualification = fixture.native.qualification_a.clone().unwrap();
        // Explicit inert full-receipt boundary for adapter dispatch only;
        // no calibration or native hardware receipt is asserted by the case.
        fixture.native.ordinary = Some(OrdinaryGrant::A(qualification));
        if fixture.native.admitted_channels() != Ok(2)
            || !fixture
                .native
                .admitted_wide()
                .is_ok_and(|profiles| profiles.is_empty())
            || fixture.native.station_ht_allowed() != Ok(optional)
            || fixture.native.station_he_allowed() != Ok(optional)
            || fixture.native.station_ampdu_allowed() != Ok(optional)
            || fixture.native.station_firmware_ra_allowed() != Ok(optional)
            || fixture.native.station_qos_all_allowed() != Ok(optional)
            || fixture.native.station_wmm_allowed() != Ok(optional)
            || fixture.native.station_amsdu_allowed() != Ok(false)
            || !fixture
                .native
                .station_regulatory()
                .is_ok_and(|policy| policy.is_some())
            || fixture.native.full_radio_scope().is_some()
        {
            return TestResult::Fail(
                "A program/channel dispatch borrowed B or lost its current A flags",
            );
        }
        let before = fixture.words.clone();
        original.revoke();
        if fixture.native.admitted_channels().is_ok()
            || fixture.native.station_ht_allowed().is_ok()
            || fixture.native.station_regulatory().is_ok()
            || fixture.words != before
        {
            return TestResult::Fail("A program queries bypassed original signed grant revocation");
        }
    }
    let (mut fixture, _, _) = thermal_fixture();
    fixture.native.ordinary = fixture.native.qualification_a.clone().map(OrdinaryGrant::A);
    fixture.native.authority.revoke();
    if fixture.native.admitted_channels().is_ok() || fixture.native.station_wmm_allowed().is_ok() {
        return TestResult::Fail("A metadata admission bypassed original current Bus");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_channel_program_queries_use_exact_current_a_owner
);

fn smoke_rtw8852a_terminal_shutdown_uses_a_masks_without_xtal_or_rf_receipt() -> TestResult {
    for revoke in [false, true] {
        let (mut fixture, calibration, qualification) = thermal_fixture();
        fixture.native.radio_started = true;
        fixture.words[0x109c4 / 4] = 0x8000_0011;
        fixture.words[0x2f0 / 4] = 0x1234_ffff;
        fixture.words[0x8040 / 4] = 0xa5a5_ffff;
        fixture.words[0x2 / 4] = 0x55ff_1234;
        fixture.words[0x270 / 4] = 0x7654_3210; // B XTAL command aperture
        calibration.revoke();
        qualification.revoke();
        fixture.native.fail();
        let before = fixture.words.clone();
        if revoke {
            fixture.native.authority.revoke();
        }
        let result = ready(fixture.native.finish_radio_shutdown());
        if result.is_some_and(|r| r.is_ok()) == revoke
            || fixture.words != before
            || fixture.words[0x109c4 / 4] != 0x8000_0000
            || fixture.words[0x2f0 / 4] != 0x1234_7d7d
            || fixture.words[0x8040 / 4] != 0xa5a5_fff7
            || fixture.words[0x2 / 4] != 0x55fc_1234
            || fixture.words[0x270 / 4] != 0x7654_3210
            || fixture.native.channel.is_some()
            || fixture.native.state != State::Terminal
            || fixture.native.calibrating.is_some()
        {
            return TestResult::Fail(
                "A terminal completion borrowed B XTAL or revived RF/current owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_terminal_shutdown_uses_a_masks_without_xtal_or_rf_receipt
);

fn smoke_rtw8852a_native_thermal_uses_original_direct_rf_and_both_current_grants() -> TestResult {
    let (mut fixture, _, _) = thermal_fixture();
    // Source A direct RF42 at CRbase + {c000,d000} + 42*4. The B
    // apertures are deliberately different and must remain untouched.
    fixture.words[0x1c108 / 4] = 0x4000_0000 | (22 << 1);
    fixture.words[0x1d108 / 4] = 0x2000_0000 | (42 << 1);
    fixture.words[0x1e108 / 4] = 0x1234_5678;
    fixture.words[0x1f108 / 4] = 0x8765_4321;
    let mut owner = Observations::default();
    // SAFETY: actual Native/Port/current-cap path on inert source-owned
    // BAR RAM; no physical device, TSSI producer or station admission.
    if narf_scheduler::block_on_spin(unsafe { owner.non_tssi(&mut fixture.native) }).is_err()
        || owner.snapshot()
            != Some(Snapshot {
                sample: [22, 42],
                average: [22, 42],
                last_thermal_max: 42,
            })
        || fixture.words[0x1c108 / 4] != 0x4008_002c
        || fixture.words[0x1d108 / 4] != 0x2008_0054
        || fixture.words[0x1e108 / 4] != 0x1234_5678
        || fixture.words[0x1f108 / 4] != 0x8765_4321
        || fixture.native.channel.is_some()
        || fixture.native.ordinary_current().is_ok()
        || fixture.native.calibrating.is_some()
        || fixture.native.queue.pending() != 0
    {
        return TestResult::Fail("A live thermal source/base/preservation/readiness differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_thermal_uses_original_direct_rf_and_both_current_grants
);

fn smoke_rtw8852a_native_thermal_revocation_or_drop_never_refreshes_observations() -> TestResult {
    for revoke in 0..4 {
        let (mut fixture, calibration, qualification) = thermal_fixture();
        fixture.words[0x1c108 / 4] = 22 << 1;
        fixture.words[0x1d108 / 4] = 42 << 1;
        let bus = fixture.native.authority;
        let mut owner = Observations::default();
        // SAFETY: actual serialized Native RF/Port over inert RAM. Suspend
        // at an actual RF/sensor delay; its exact poll boundary is immaterial.
        let mut operation = alloc::boxed::Box::pin(unsafe { owner.non_tssi(&mut fixture.native) });
        if !matches!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("A native observation did not expose actual RF delay");
        }
        let observed = [fixture.words[0x1c108 / 4], fixture.words[0x1d108 / 4]];
        match revoke {
            0 => bus.revoke(),
            1 => calibration.revoke(),
            2 => qualification.revoke(),
            _ => {} // Drop the actual pending hardware-operation future.
        }
        if revoke != 3 && narf_scheduler::block_on_spin(operation.as_mut()).is_ok() {
            return TestResult::Fail("A revoked current observation completed");
        }
        drop(operation);
        if owner.state() != ObservationState::Busy
            || owner.snapshot().is_some()
            || ![0, 22].contains(&owner.averages()[0])
            || ![0, 42].contains(&owner.averages()[1])
            || [fixture.words[0x1c108 / 4], fixture.words[0x1d108 / 4]] != observed
            || fixture.native.channel.is_some()
            || fixture.native.ordinary_current().is_ok()
        {
            return TestResult::Fail("A revoked/dropped observation ran past uncertain RF effect");
        }
        let before = fixture.words.clone();
        // SAFETY: inert repeat must be rejected by the retained Busy owner.
        if ready(unsafe { owner.non_tssi(&mut fixture.native) }) != Some(Err(rfk::Error::Terminal))
            || fixture.words != before
        {
            return TestResult::Fail("A original observer was replaced/retried after uncertainty");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_thermal_revocation_or_drop_never_refreshes_observations
);

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
    if result != Some(Err(rfk::Error::Policy))
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

fn smoke_rtw8852a_old_cold_record_cannot_authorize_new_dig_xtal_or_rfk_effects() -> TestResult {
    let (mut fixture, _, _) = thermal_fixture();
    fixture.native.qualification_a = None;
    fixture.native.mac_a = None;
    fixture.native.nctl_ready = false;
    if fixture
        .native
        .calibration
        .as_ref()
        .unwrap()
        .current()
        .is_err()
    {
        return TestResult::Fail("A cold authority fixture not current");
    }
    let identity = fixture.native.factory.as_ref().unwrap().identity().unwrap();
    let before = fixture.words.clone();
    let mut owner = crate::rtw89::phy_operating::Operating::default();
    // SAFETY: original actual Native adapter over inert BAR, old cold-only
    // authority is deliberately current; no new full/MAC receipt is supplied.
    if ready(unsafe { owner.prepare_a(&mut fixture.native, identity) })
        != Some(Err(rfk::Error::Policy))
        || crate::rtw89::rfk::Interface::admit(&mut fixture.native) != Err(rfk::Error::Policy)
        || fixture.words != before
        || owner.a_gains().is_some()
    {
        return TestResult::Fail("A historical cold scope acquired new DIG/RFK hardware authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_old_cold_record_cannot_authorize_new_dig_xtal_or_rfk_effects
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
        fixture.native.qualification_a = Some(alloc::sync::Arc::new(
            crate::rtw89::radio_policy_a::tests::revocable_model().0,
        ));
        fixture.native.mac_a = Some(alloc::sync::Arc::new(
            crate::rtw89::mac_a_policy::tests::model().0,
        ));
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

fn smoke_rtw8852a_native_cancel_closes_pmac_in_original_restrictive_scope() -> TestResult {
    for revoke in 0..4 {
        let (mut fixture, calibration, qualification) = thermal_fixture();
        if ready(fixture.native.send(Kind::Header, &[0x5a; 16])) != Some(Ok(())) {
            return TestResult::Fail("A retained DMA cancellation setup");
        }
        let ring = fixture.native.ring.as_ref().unwrap().dma_addr().raw();
        let command = fixture
            .native
            .queue
            .model_resource(0)
            .unwrap()
            .dma_addr()
            .raw();
        let pending = fixture.native.queue.pending();
        fixture.native.radio_started = true;
        for (a, value) in [
            (0x109c4, 0x5011),
            (0x10980, 0xa5010001),
            (0x10988, 0xa500003f),
            (0x10994, 0xa50000f0),
            (0x109a4, 0xa5a1041c),
            (0x2f0, 0x12348282),
            (0x8040, 0x1234565a),
            (0, 0x00a30000),
        ] {
            fixture.words[a / 4] = value;
        }
        let before = fixture.words.clone();
        let bus = fixture.native.authority;
        // SAFETY: inert pending-operation actor, no hardware. The production
        // outer Attempt is actually retained across await and dropped; its
        // exact Native::fail branch sees the source-enabled PMAC fields.
        let mut future = alloc::boxed::Box::pin(async {
            let _attempt = crate::rtw89::startup::Attempt::new(&mut fixture.native);
            core::future::pending::<()>().await;
        });
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("A original cancellation guard not retained");
        }
        match revoke {
            1 => calibration.revoke(),
            2 => qualification.revoke(),
            3 => bus.revoke(),
            _ => {}
        }
        drop(future);
        if fixture.native.state != State::Terminal
            || fixture.native.queue.pending() != pending
            || fixture.native.ring.as_ref().unwrap().dma_addr().raw() != ring
            || fixture
                .native
                .queue
                .model_resource(0)
                .unwrap()
                .dma_addr()
                .raw()
                != command
            || fixture.native.channel.is_some()
            || fixture.native.dma_reclaimed
        {
            return TestResult::Fail(
                "A terminal PMAC closure discarded uncertain DMA or granted RF",
            );
        }
        if revoke == 3 {
            if fixture.words != before {
                return TestResult::Fail("revoked original A Bus touched closure registers");
            }
        } else if fixture.words[0x109c4 / 4] != 0x5000
            || fixture.words[0x10980 / 4] != 0xa5000000
            || fixture.words[0x10988 / 4] != 0xa5000000
            || fixture.words[0x10994 / 4] != 0xa5000000
            || fixture.words[0x109a4 / 4] != 0xa5a00000
            || fixture.words[0x2f0 / 4] != 0x12340000
            || fixture.words[0x8040 / 4] != 0x12345652
            || fixture.words[0] != 0x00a00000
        {
            return TestResult::Fail(
                "A cancellation missed source PMAC/TMAC/reset/RF/PHYREG closure",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_native_cancel_closes_pmac_in_original_restrictive_scope
);
