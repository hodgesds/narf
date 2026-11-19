//! Passive native host-vote service retains unknown input and PM deferral.
use super::*;

fn smoke_ath10k_host_bus_pm_passive_poll_is_opt_in_and_retains_native_input() -> TestResult {
    let mut radio = radio_boot_features(4, Dialect::Tlv, 1 << 10);
    if !matches!(drive(radio.start(&[2412, 5180])), Poll::Ready(Ok(_))) {
        return TestResult::Fail("hostPM passive actual HTC/WMI/HTT/vdev initialization");
    }
    let transport = &mut radio.htt.wmi.htc.transport;
    let polls = transport.host_power.polls;
    let sent = transport.sent.len();
    if radio.poll_passive_host_idle().is_err()
        || radio.htt.wmi.htc.transport.host_power.polls != polls
    {
        return TestResult::Fail("default passive transport gained an unrequested native poll");
    }
    radio.htt.wmi.htc.transport.host_power.enabled = true;
    if radio.poll_passive_host_idle().is_err()
        || !radio.htt.wmi.htc.transport.host_power.eligible
        || radio.htt.wmi.htc.transport.host_power.polls == polls
        || radio.has_station_data()
        || radio.associated_station().is_some()
        || radio.htt.wmi.htc.transport.sent.len() != sent
    {
        return TestResult::Fail(
            "passive current host idle required a peer or emitted an RF command",
        );
    }
    let polls = radio.htt.wmi.htc.transport.host_power.polls;
    radio.htt.wmi.htc.transport.host_power.defer = true;
    if radio.poll_passive_host_idle().is_err()
        || radio.htt.wmi.htc.transport.host_power.polls != polls
        || radio.take_event().is_some()
        || radio.has_station_data()
    {
        return TestResult::Fail("passive PM defer invented native input or station ownership");
    }
    // Native input represents an actual IRQ change and defeats the fixture's
    // idle defer. Its complete original payload must remain queued, not turn
    // into a false empty receive prefix or satisfy a future control exchange.
    add_event(
        &mut radio.htt.wmi.htc.transport,
        0x123456,
        &[0x91, 0x82, 0x73],
    );
    if radio.poll_passive_host_idle().is_err() || radio.htt.wmi.htc.transport.host_power.eligible {
        return TestResult::Fail(
            "unknown passive native event failed to close host idle admission",
        );
    }
    let polls = radio.htt.wmi.htc.transport.host_power.polls;
    if radio.poll_passive_host_idle().is_err()
        || radio.htt.wmi.htc.transport.host_power.polls != polls
    {
        return TestResult::Fail(
            "retained unknown native input was bypassed by passive idle service",
        );
    }
    let mut expected = 0x123456u32.to_le_bytes().to_vec();
    expected.extend_from_slice(&[0x91, 0x82, 0x73]);
    if !matches!(radio.take_event(), Some(htt::Event::Wmi(bytes)) if bytes == expected) {
        return TestResult::Fail(
            "passive host idle discarded or changed the original native input",
        );
    }
    // Current executable/board capability remains mandatory even when all
    // native rings are quiet and the next physical BAR poll would be deferred.
    #[cfg(feature = "kernel-test")]
    {
        let Ok((source, caps)) = crate::ath10k::firmware_source::fixture() else {
            return TestResult::Fail("passive hostPM original source fixture");
        };
        radio.htt.wmi.htc.transport.sources = Some(source);
        caps[1].revoke();
        let polls = radio.htt.wmi.htc.transport.host_power.polls;
        if radio.poll_passive_host_idle().is_ok()
            || radio.htt.wmi.htc.transport.host_power.polls != polls
            || radio.htt.wmi.htc.transport.sent.len() != sent
            || radio.has_station_data()
        {
            return TestResult::Fail(
                "revoked passive source reached native PM polling/publication",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/host-bus-pm",
    smoke_ath10k_host_bus_pm_passive_poll_is_opt_in_and_retains_native_input
);
