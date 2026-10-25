use super::super::super::runtime;
use super::super::{
    power::tests::{ready_link_fixture, retained_source},
    queue::tests::Fixture,
};
use super::*;
use alloc::vec;
use core::{
    cell::Cell,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule};

fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn policy() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 10,
            flags: RegFlags::empty(),
        }],
    }
}
fn mcc(flags: u32) -> Vec<u8> {
    let mut bytes = vec![0; 456];
    bytes[12..16].copy_from_slice(&110u32.to_le_bytes());
    for word in bytes[16..].chunks_exact_mut(4) {
        word.copy_from_slice(&flags.to_le_bytes());
    }
    bytes
}

fn link_wire(
    trace: &runtime::model::TxTrace,
    sequence: u16,
    active: bool,
    cck: u8,
    ofdm: u8,
) -> Result<(), &'static str> {
    let observed = trace.take().ok_or("missing actual LINK_CONFIG DMA")?;
    // Literal fw/api/mac-cfg.h v1 offsets. Expected values are independent
    // of the production builder and the actual DMA has already been posted.
    let mut expected = [0; 208];
    expected[0] = 2;
    expected[16..22].fill(2);
    expected[24] = if active { 3 } else { 1 };
    expected[28] = u8::from(active);
    if active {
        expected[36] = cck;
        expected[40] = ofdm;
    }
    if observed.queue != 0
        || observed.bytes.len() != 216
        || observed.bytes[..2] != [9, 3]
        || observed.bytes[2..4] != sequence.to_le_bytes()
        || observed.bytes[7] != 0
        || observed.bytes[8..] != expected
        || observed.doorbell != u32::from(observed.pointer)
    {
        return Err("actual link DMA differs from legacy-header0/v1 payload wire contract");
    }
    Ok(())
}
fn awake_wire(trace: &runtime::model::TxTrace, sequence: u16) -> Result<(), &'static str> {
    let observed = trace
        .take()
        .ok_or("missing post-activation MAC-power DMA")?;
    let mut expected = [0; 40];
    expected[6] = 25;
    if observed.bytes.len() != 48
        || observed.bytes[..2] != [0xa9, 1]
        || observed.bytes[2..4] != sequence.to_le_bytes()
        || observed.bytes[7] != 0
        || observed.bytes[8..] != expected
    {
        return Err("post-activation MAC power was not the exact awake/keepalive25 legacy command");
    }
    Ok(())
}
fn activate(fixture: &mut Fixture, lar: bool) -> Result<u16, &'static str> {
    let owner = fixture.owner.as_mut().unwrap();
    let mut operation = pin!(owner.activate_link_using(|| Ok(policy())));
    let mut sequence = 4;
    if !poll(operation.as_mut()).is_pending() {
        return Err("link activation did not await native transport");
    }
    if lar {
        let observed = fixture
            .trace
            .take()
            .ok_or("missing active-link fresh MCC query")?;
        if observed.bytes[..2] != [0xc8, 1]
            || observed.bytes[7] != 0
            || observed.bytes[8..10] != *b"ZZ"
        {
            return Err("link used stale MCC permission or a negotiated-layout header version");
        }
        fixture.firmware.inject(0xc8, 1, sequence, &mcc(0x109));
        sequence += 1;
        if !poll(operation.as_mut()).is_pending() {
            return Err("fresh MCC did not reach link activation");
        }
    }
    link_wire(&fixture.trace, sequence, true, 1, 0x15)?;
    fixture.firmware.inject(9, 3, sequence, &[]);
    sequence += 1;
    if !poll(operation.as_mut()).is_pending() {
        return Err("link ACK bypassed mandatory MAC-power receipt");
    }
    awake_wire(&fixture.trace, sequence)?;
    fixture.firmware.inject(0xa9, 1, sequence, &[]);
    sequence += 1;
    if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
        return Err("exact active-link/MAC-power receipts failed");
    }
    Ok(sequence)
}
fn composed(lar: bool) -> Result<(), &'static str> {
    let mut fixture = ready_link_fixture(lar)?;
    let mut sequence = activate(&mut fixture, lar)?;
    let owner = fixture.owner.as_mut().unwrap();
    if owner.prepared_active_link()
        != Some(ActiveLinkStatus {
            bssid: [2, 4, 6, 8, 10, 12],
            channel: 1,
            cck_response_rates: 1,
            ofdm_response_rates: 0x15,
        })
        || owner.prepared_ap_peer().is_none()
        || owner.prepared_management_queue() != Some(23)
        || !owner.hardware.idle_tx_binding(23, 0, 15)
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("completed link did not retain exact disabled peer/idle queue/power ownership");
    }
    let before = fixture.firmware.tx_write();
    if owner.release_transmit_power().is_ok() {
        return Err("active link released its qualification before deactivation");
    }
    {
        let mut removal = pin!(owner.release_management_queue());
        if !matches!(poll(removal.as_mut()), Poll::Ready(Err(_))) {
            return Err("active link retired management DMA before deactivation");
        }
    }
    if fixture.firmware.tx_write() != before {
        return Err("blocked link teardown published a command");
    }
    {
        let mut operation = pin!(owner.deactivate_link());
        if !poll(operation.as_mut()).is_pending() {
            return Err("deactivation did not await native receipt");
        }
        link_wire(&fixture.trace, sequence, false, 0, 0)?;
        fixture.firmware.inject(9, 3, sequence, &[]);
        sequence += 1;
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("exact inactive link receipt failed");
        }
    }
    if owner.phase() != Phase::TransmitPowerPrepared || owner.prepared_active_link().is_some() {
        return Err("inactive receipt did not reopen only the completed power stage");
    }
    owner.release_transmit_power()?;
    {
        let mut operation = pin!(owner.release_management_queue());
        if !poll(operation.as_mut()).is_pending() {
            return Err("post-link queue REMOVE did not await native8 receipt");
        }
        let mut reply = [0; 8];
        reply[0] = 23;
        fixture.firmware.inject(0x17, 5, sequence, &reply);
        sequence += 1;
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("ordered link/power/queue teardown failed");
        }
    }
    {
        let mut operation = pin!(owner.release_ap_peer());
        if !poll(operation.as_mut()).is_pending() {
            return Err("post-queue AP REMOVE did not wait");
        }
        fixture.firmware.inject(0x19, 0, sequence, &[]);
        sequence += 1;
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("ordered AP removal failed");
        }
    }
    {
        let mut operation = pin!(owner.release_inactive_channel());
        if !poll(operation.as_mut()).is_pending() {
            return Err("PHY unbind did not wait");
        }
        fixture.firmware.inject(9, 3, sequence, &[]);
        sequence += 1;
        if !poll(operation.as_mut()).is_pending() {
            return Err("PHY REMOVE did not wait");
        }
        fixture.firmware.inject(8, 1, sequence, &[]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("ordered inactive PHY retirement failed");
        }
    }
    if owner.phase() != Phase::Configured || runtime::model::retained(&owner.hardware) != (0, 0, 0)
    {
        return Err("ordered teardown lost its owned boot lifecycle");
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_native_receipts_and_ordered_retirement() -> TestResult {
    for lar in [false, true] {
        if let Err(error) = composed(lar) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_native_receipts_and_ordered_retirement
);

fn rates() -> Result<(), &'static str> {
    for (ies, channel, expected) in [
        (&[1, 1, 0x82][..], 1, (1, 0x15)),
        (&[1, 4, 2, 4, 0x8b, 0x96][..], 1, (15, 0x15)),
        (&[1, 1, 0xb0][..], 36, (15, 0x15)),
        (&[1, 1, 0xec][..], 36, (15, 0x95)),
        (&[1, 1, 0x92][..], 36, (15, 3)),
        (&[1, 2, 0x82, 0x8c, 50, 1, 0xec][..], 1, (1, 0x81)),
    ] {
        if response_rates(ies, channel) != Ok(expected) {
            return Err("source mandatory response-rate completion changed");
        }
    }
    for (ies, channel) in [
        (&[1, 1, 2][..], 1),     // no actual basic bit: never infer an AP grant
        (&[1, 1, 0x82][..], 36), // CCK-only basic rate on5GHz
        (&[1, 1, 0xff][..], 1),  // membership selector requires another PHY
        (&[1, 2, 0x82][..], 1),
        (&[1, 0][..], 1),
        (&[1, 1, 0x82, 1, 1, 0x84][..], 1),
        (&[50, 1, 0x8c][..], 36),
        (&[1, 1, 0x82, 50, 1, 0x8c, 50, 1, 0x98][..], 1),
    ] {
        if response_rates(ies, channel).is_ok() {
            return Err("unsupported/malformed basic rate set admitted an active link");
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_observed_basic_and_mandatory_response_rate_sets() -> TestResult {
    rates().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_observed_basic_and_mandatory_response_rate_sets
);

fn cancel(stage: u8) -> Result<(), &'static str> {
    let mut fixture = ready_link_fixture(stage == 0)?;
    if stage == 3 {
        activate(&mut fixture, false)?;
    }
    let owner = fixture.owner.as_mut().unwrap();
    if stage == 3 {
        let mut operation = pin!(owner.deactivate_link());
        if !poll(operation.as_mut()).is_pending() {
            return Err("cancelled deactivate did not publish");
        }
    } else {
        let mut operation = pin!(owner.activate_link_using(|| Ok(policy())));
        if !poll(operation.as_mut()).is_pending() {
            return Err("cancelled activation did not publish");
        }
        if stage == 2 {
            fixture.firmware.inject(9, 3, 4, &[]);
            if !poll(operation.as_mut()).is_pending() {
                return Err("cancellation did not reach post-link power wait");
            }
        }
    }
    if owner.phase()
        != if stage == 3 {
            Phase::DeactivatingLink
        } else {
            Phase::ActivatingLink
        }
        || owner.prepared_active_link().is_some()
        || owner
            .power
            .prepared
            .as_ref()
            .is_none_or(|power| power.active_link.is_none())
        || runtime::model::retained(&owner.hardware) != (1, 1, 0)
        || owner.release_transmit_power().is_ok()
    {
        return Err(
            "cancelled link transaction lost qualification/identity/command/queue ownership",
        );
    }
    if stage == 0 {
        fixture.firmware.inject(0xc8, 1, 4, &mcc(0x109));
    } else {
        fixture.firmware.inject(
            if stage == 2 { 0xa9 } else { 9 },
            if stage == 2 { 1 } else { 3 },
            if stage == 3 {
                6
            } else if stage == 2 {
                5
            } else {
                4
            },
            &[],
        );
    }
    let before = fixture.firmware.tx_write();
    {
        let mut retry = pin!(owner.activate_link_using(|| Ok(policy())));
        if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
            return Err("late native ACK reopened a cancelled link");
        }
    }
    {
        let mut retry = pin!(owner.deactivate_link());
        if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
            return Err("cancelled link repeated an ambiguous deactivation");
        }
    }
    if fixture.firmware.tx_write() != before {
        return Err("cancelled link retry published IO");
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_cancellation_pins_each_native_boundary() -> TestResult {
    for stage in 0..4 {
        if let Err(error) = cancel(stage) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_cancellation_pins_each_native_boundary
);

fn authority(stage: u8, revoked: bool) -> Result<(), &'static str> {
    let mut fixture = ready_link_fixture(stage == 0)?;
    let owner = fixture.owner.as_mut().unwrap();
    let cap = retained_source(owner);
    let changed = Cell::new(false);
    {
        let mut operation = pin!(owner.activate_link_using(|| {
            let mut domain = policy();
            if changed.get() {
                domain.rules[0].flags = RegFlags::NO_IR;
            }
            Ok(domain)
        }));
        if !poll(operation.as_mut()).is_pending() {
            return Err("authority fixture did not wait on native link path");
        }
        if stage == 2 {
            fixture.firmware.inject(9, 3, 4, &[]);
            if !poll(operation.as_mut()).is_pending() {
                return Err("authority fixture did not reach power wait");
            }
        }
        if revoked {
            cap.revoke();
        } else {
            changed.set(true);
        }
        // No receipt is injected: authority loss must stop the waiter itself,
        // retaining its pending command instead of waiting for a fresh ACK.
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
            return Err("lost authority did not fence the pending native future poll");
        }
    }
    if owner.phase() != Phase::Failed
        || owner.prepared_active_link().is_some()
        || runtime::model::retained(&owner.hardware) != (1, 1, 0)
        || fixture.firmware.tx_write() != if stage == 2 { 6 } else { 5 }
    {
        return Err("authority loss released ambiguous DMA or published another command");
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_current_policy_and_source_fence_every_native_wait() -> TestResult {
    for stage in 0..3 {
        for revoked in [false, true] {
            if let Err(error) = authority(stage, revoked) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_current_policy_and_source_fence_every_native_wait
);

fn final_policy() -> Result<(), &'static str> {
    let mut fixture = ready_link_fixture(false)?;
    let owner = fixture.owner.as_mut().unwrap();
    let calls = Cell::new(0);
    {
        let mut operation = pin!(owner.activate_link_using(|| {
            let count = calls.get() + 1;
            calls.set(count);
            let mut domain = policy();
            if count >= 8 {
                domain.rules[0].max_power_dbm = 4;
            }
            Ok(domain)
        }));
        if !poll(operation.as_mut()).is_pending() {
            return Err("final policy fixture did not reach link wait");
        }
        fixture.firmware.inject(9, 3, 4, &[]);
        if !poll(operation.as_mut()).is_pending() {
            return Err("final policy fixture did not reach power wait");
        }
        fixture.firmware.inject(0xa9, 1, 5, &[]);
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
            return Err("post-receipt tighter policy published active-link readiness");
        }
    }
    if owner.phase() != Phase::Failed
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
        || owner.prepared_active_link().is_some()
    {
        return Err("final policy denial lost its retained inactive prerequisites");
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_final_readiness_rechecks_acknowledged_power() -> TestResult {
    final_policy().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_final_readiness_rechecks_acknowledged_power
);

fn bad_receipt(stage: u8, case: u8) -> Result<(), &'static str> {
    let mut fixture = ready_link_fixture(false)?;
    if stage == 2 {
        activate(&mut fixture, false)?;
    }
    let owner = fixture.owner.as_mut().unwrap();
    {
        let mut operation = pin!(async {
            if stage == 2 {
                owner.deactivate_link().await
            } else {
                owner.activate_link_using(|| Ok(policy())).await
            }
        });
        if !poll(operation.as_mut()).is_pending() {
            return Err("bad receipt fixture never published");
        }
        if stage == 1 {
            fixture.firmware.inject(9, 3, 4, &[]);
            if !poll(operation.as_mut()).is_pending() {
                return Err("bad receipt fixture did not reach MAC power");
            }
        }
        let (id, group, sequence) = match stage {
            0 => (9, 3, 4),
            1 => (0xa9, 1, 5),
            _ => (9, 3, 6),
        };
        fixture.firmware.inject(
            if case == 1 { id - 1 } else { id },
            if case == 2 { group + 1 } else { group },
            if case == 3 { sequence + 1 } else { sequence },
            if case == 0 { &[0; 4] } else { &[] },
        );
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
            return Err("malformed/foreign link receipt authorized state change");
        }
    }
    if owner.phase() != Phase::Failed
        || owner.prepared_active_link().is_some()
        || owner
            .power
            .prepared
            .as_ref()
            .is_none_or(|power| power.active_link.is_none())
        || runtime::model::retained(&owner.hardware).1 != 1
    {
        return Err("bad native receipt retired its retained link/queue identity");
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_exact_native_activation_power_and_deactivation_receipts() -> TestResult
{
    for stage in 0..3 {
        for case in 0..4 {
            if let Err(error) = bad_receipt(stage, case) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_exact_native_activation_power_and_deactivation_receipts
);

fn profiles() -> Result<(), &'static str> {
    for version in [None, Some((0, 0)), Some((1, 0)), Some((99, 99))] {
        let mut fixture = ready_link_fixture(false)?;
        let mut commands = vec![0xa9, 1, 1, 0];
        if let Some((command, response)) = version {
            commands.extend_from_slice(&[9, 3, command, response]);
        }
        runtime::model::versions(&mut fixture.owner.as_mut().unwrap().hardware, &commands);
        activate(&mut fixture, false)?;
    }
    for case in 0..10 {
        let mut fixture = ready_link_fixture(false)?;
        let owner = fixture.owner.as_mut().unwrap();
        let mut domain = policy();
        match case {
            0 => runtime::model::versions(&mut owner.hardware, &[9, 3, 2, 0, 0xa9, 1, 1, 0]),
            1 => runtime::model::versions(&mut owner.hardware, &[9, 3, 1, 1, 0xa9, 1, 1, 0]),
            2 => runtime::model::versions(&mut owner.hardware, &[0xa9, 1, 2, 0]),
            3 => retained_source(owner).revoke(),
            4 => domain.rules[0].max_power_dbm = 4,
            5 => domain.rules[0].flags = RegFlags::DFS,
            6 => domain.rules.push(RegRule {
                freq_start_mhz: 2403,
                freq_end_mhz: 2404,
                flags: RegFlags::NO_IR,
                ..domain.rules[0].clone()
            }),
            7 => owner.beacons[0].information_elements = vec![1, 1, 2],
            8 => owner.channel.current = Some(6),
            9 => owner.hardware.enqueue_transmit(23, &[0; 24], 24, Some(0))?,
            _ => unreachable!(),
        }
        let before = fixture.firmware.tx_write();
        {
            let mut operation = pin!(owner.activate_link_using(|| Ok(domain.clone())));
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err(
                    "unsupported/mismatched active-link preflight published native commands",
                );
            }
        }
        if owner.phase() != Phase::TransmitPowerPrepared
            || fixture.firmware.tx_write() != before
            || owner
                .power
                .prepared
                .as_ref()
                .is_none_or(|power| power.active_link.is_some())
        {
            return Err("link preflight failure changed its retained power stage");
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_legacy_layout_fallback_and_restrictive_preflight() -> TestResult {
    profiles().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_legacy_layout_fallback_and_restrictive_preflight
);

fn revoked_close() -> Result<(), &'static str> {
    let mut fixture = ready_link_fixture(false)?;
    activate(&mut fixture, false)?;
    let owner = fixture.owner.as_mut().unwrap();
    retained_source(owner).revoke();
    if owner.prepared_active_link().is_some() || owner.release_transmit_power().is_ok() {
        return Err("revocation exposed active metadata or bypassed close ordering");
    }
    {
        let mut operation = pin!(owner.deactivate_link());
        if !poll(operation.as_mut()).is_pending() {
            return Err("loss of TX authority prohibited safe native deactivation");
        }
        fixture.firmware.inject(9, 3, 6, &[]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("native inactive receipt did not close a revoked qualified link");
        }
    }
    owner.release_transmit_power()?;
    if owner.phase() != Phase::ManagementQueuePrepared
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("revoked link close changed retained queue DMA");
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_deactivation_remains_available_after_qualification_revocation(
) -> TestResult {
    revoked_close().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_deactivation_remains_available_after_qualification_revocation
);

fn fresh_permission() -> Result<(), &'static str> {
    for flags in [0, 0x101, 0x108, 0x119, 9] {
        let mut fixture = ready_link_fixture(true)?;
        let owner = fixture.owner.as_mut().unwrap();
        {
            let mut operation = pin!(owner.activate_link_using(|| Ok(policy())));
            if !poll(operation.as_mut()).is_pending() {
                return Err("fresh MCC denial did not query native firmware");
            }
            fixture.firmware.inject(0xc8, 1, 4, &mcc(flags));
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("fresh firmware receive-only/radar/width flags admitted active link");
            }
        }
        if owner.phase() != Phase::Failed
            || fixture.firmware.tx_write() != 5
            || runtime::model::retained(&owner.hardware) != (0, 1, 0)
        {
            return Err(
                "fresh firmware prohibition published LINK or released retained prerequisites",
            );
        }
    }
    let mut fixture = ready_link_fixture(true)?;
    let next = activate(&mut fixture, true)?;
    let owner = fixture.owner.as_mut().unwrap();
    {
        let mut close = pin!(owner.deactivate_link());
        if !poll(close.as_mut()).is_pending() {
            return Err("repeat-MCC fixture did not deactivate");
        }
        fixture.firmware.inject(9, 3, next, &[]);
        if poll(close.as_mut()) != Poll::Ready(Ok(())) {
            return Err("repeat-MCC fixture inactive receipt failed");
        }
    }
    {
        let mut repeat = pin!(owner.activate_link_using(|| Ok(policy())));
        if !poll(repeat.as_mut()).is_pending() {
            return Err("completed deactivation did not permit fresh qualified attempt");
        }
        let _ = fixture.trace.take(); // acknowledged deactivation's observation
        let observed = fixture
            .trace
            .take()
            .ok_or("missing repeated activation MCC query")?;
        if observed.bytes[..2] != [0xc8, 1] {
            return Err("earlier MCC grant bypassed requery on a later activation");
        }
        fixture.firmware.inject(0xc8, 1, next + 1, &mcc(0x101));
        if !matches!(poll(repeat.as_mut()), Poll::Ready(Err(_))) {
            return Err("stale earlier MCC profile authorized a repeated link");
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_active_link_refreshes_and_intersects_firmware_permission_every_attempt(
) -> TestResult {
    fresh_permission().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_active_link_refreshes_and_intersects_firmware_permission_every_attempt
);

fn header_contract() -> Result<(), &'static str> {
    use super::super::super::rx_rfh::CompletionFormat;
    struct Transport {
        hardware: Option<runtime::Hardware>,
        firmware: runtime::model::Firmware,
        trace: runtime::model::TxTrace,
    }
    impl Drop for Transport {
        fn drop(&mut self) {
            if let Some(hardware) = self.hardware.take() {
                // SAFETY: these are the private native RAM/RFH/TFH fixtures;
                // no physical PCI function ever observed their DMA addresses.
                unsafe { runtime::model::destroy(hardware) };
            }
        }
    }
    // Authored command-ID/payload-layout cases from the reached Linux MVM
    // callers: fw.c, coex.c, power.c, scan.c, mld-mac.c, link.c, phy-ctxt.c,
    // sta.c, nvm.c and pcie/gen1_2/tx-gen2.c. These callers use bare IDs or
    // WIDE_ID; version bits16..23 are0, regardless of the payload lookup.
    // The opaque four-byte bodies below test command transport only. The
    // composed owner smokes separately validate actual payloads/readiness.
    let cases = [
        (2, 3, 1),
        (0xc, 0, 1),
        (0xc, 2, 1),
        (1, 0x98, 1),
        (1, 0x9b, 6),
        (2, 1, 2),
        (1, 0x77, 6),
        (5, 0, 1),
        (1, 0xc, 5),
        (3, 8, 1),
        (1, 0xd2, 4),
        (1, 0xd1, 3),
        (3, 9, 1),
        (1, 0xa9, 1),
        (1, 0xc8, 1),
        (1, 0xd, 15),
        (1, 8, 1),
        (5, 8, 2),
        (1, 0x18, 12),
        (1, 0x19, 2),
        (5, 0x17, 3),
        (1, 0x9f, 5),
    ];
    for format in [CompletionFormat::Qu, CompletionFormat::Bz] {
        let (hardware, firmware, trace) = runtime::model::station_model_for_format(format);
        let mut transport = Transport {
            hardware: Some(hardware),
            firmware,
            trace,
        };
        let versions = cases
            .iter()
            .flat_map(|&(group, id, version)| [id, group, version, 0])
            .collect::<Vec<_>>();
        runtime::model::versions(transport.hardware.as_mut().unwrap(), &versions);
        for (sequence, &(group, id, payload_version)) in cases.iter().enumerate() {
            let mut operation = pin!(transport
                .hardware
                .as_mut()
                .unwrap()
                .command(group, id, &[0x5a; 4]));
            if !poll(operation.as_mut()).is_pending() {
                return Err("header contract did not publish actual native command DMA");
            }
            let observed = transport
                .trace
                .take()
                .ok_or("missing native header contract DMA")?;
            let expected = if format == CompletionFormat::Qu {
                0
            } else {
                payload_version
            };
            if observed.bytes.len() != 12
                || observed.bytes[..2] != [id, group]
                || observed.bytes[2..4] != (sequence as u16).to_le_bytes()
                || observed.bytes[7] != expected
                || observed.bytes[8..] != [0x5a; 4]
            {
                return Err("Gen2 copied a payload version into its header or changed the existing Gen3 branch");
            }
            transport.firmware.inject(id, group, sequence as u16, &[]);
            if !matches!(poll(operation.as_mut()), Poll::Ready(Ok(_))) {
                return Err("native header contract receipt did not retire its exact DMA owner");
            }
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_all_reached_prerequisite_headers_are_zero_and_gen3_is_unchanged() -> TestResult {
    header_contract().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_all_reached_prerequisite_headers_are_zero_and_gen3_is_unchanged
);
