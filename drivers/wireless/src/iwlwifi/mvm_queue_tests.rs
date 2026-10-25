use super::super::super::{
    connection::Beacon, firmware_api::FirmwareApi, gen2_profile, runtime, rx_rfh, station_api::Nvm,
};
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
const QUEUE: u16 = 23;
const VERSIONS: &[u8] = &[
    0xd, 1, 15, 0, 0x18, 1, 12, 2, 0x19, 1, 2, 0, 0xc, 1, 5, 0, 8, 3, 1, 0, 0xd2, 1, 4, 0, 0xd1, 1,
    3, 0, 0xa9, 1, 1, 0, 0xc8, 1, 1, 3, 0x17, 5, 3, 2,
];

pub(in crate::iwlwifi::mvm_boot) struct Fixture {
    pub(in crate::iwlwifi::mvm_boot) owner: Option<Owner>,
    pub(in crate::iwlwifi::mvm_boot) firmware: runtime::model::Firmware,
    pub(in crate::iwlwifi::mvm_boot) trace: runtime::model::TxTrace,
}
impl Fixture {
    pub(in crate::iwlwifi::mvm_boot) fn new() -> Self {
        let (mut hardware, firmware, trace) =
            runtime::model::station_model_for_format(rx_rfh::CompletionFormat::Qu);
        runtime::model::versions(&mut hardware, VERSIONS);
        let mut api = FirmwareApi::default();
        api.api_changes[1] = (1 << 24) | (1 << 15);
        api.capabilities[3] = 1 << 14;
        let mut scan = super::super::scan::ScanContext::new(&api);
        scan.ready = true;
        let mut channel = super::super::channel::ChannelContext::new(&api);
        channel.current = Some(1);
        let mut bytes = vec![0; 28 + 110 * 4];
        bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[28] = 1;
        Self {
            owner: Some(Owner {
                hardware,
                firmware: vec![],
                profile: gen2_profile::select(0xa0f0, 0x351, 0x10c000).unwrap(),
                phase: Phase::ChannelPrepared,
                mac: Some([2; 6]),
                nvm: Some(Nvm::parse(4, &bytes).unwrap()),
                beacons: vec![Beacon {
                    bssid: AP,
                    ssid: b"net".to_vec(),
                    channel: 1,
                    interval: 100,
                    dtim: 1,
                    rsn: None,
                    privacy: false,
                    capabilities: 1,
                    information_elements: vec![0, 3, b'n', b'e', b't', 1, 1, 0x82, 3, 1, 1],
                }],
                scan,
                channel,
                peer: None,
                management_queue: None,
                power: super::super::power::Context::new(&api),
            }),
            firmware,
            trace,
        }
    }
    pub(in crate::iwlwifi::mvm_boot) fn prepare_peer(&mut self) -> Result<(), &'static str> {
        let owner = self.owner.as_mut().unwrap();
        let domain = policy();
        let mut operation = pin!(owner.prepare_peer_in_domain(AP, &domain));
        if !poll(operation.as_mut()).is_pending() {
            return Err("disabled AP ADD did not retain native ownership");
        }
        self.firmware.inject(0x18, 0, 0, &[1, 0, 0, 0]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("disabled AP native status was not accepted");
        }
        self.trace
            .take()
            .ok_or("missing actual ADD_STA DMA trace")?;
        Ok(())
    }
    pub(in crate::iwlwifi::mvm_boot) fn prepare_queue(&mut self) -> Result<(), &'static str> {
        let owner = self.owner.as_mut().unwrap();
        let mut operation = pin!(owner.prepare_management_queue());
        if !poll(operation.as_mut()).is_pending() {
            return Err("management queue ADD did not wait for native receipt");
        }
        self.firmware.inject(0x17, 5, 1, &allocation(QUEUE));
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return Err("management queue native allocation was not accepted");
        }
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // SAFETY: only private RAM/RFH/TFH fixtures observed these DMA
            // addresses. No physical PCI function or MMIO producer exists.
            unsafe { runtime::model::destroy(owner.hardware) };
        }
    }
}
fn policy() -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 10,
            // Queue/disabled-peer prerequisites remain possible on receive-only
            // channels. Neither operation may send a packet or activate PHY.
            flags: narf_wireless::reg::RegFlags::NO_IR,
        }],
    }
}
fn allocation(id: u16) -> [u8; 8] {
    let mut body = [0; 8];
    body[..2].copy_from_slice(&id.to_le_bytes());
    body[4..6].copy_from_slice(&0x45u16.to_le_bytes());
    body
}
fn retirement(id: u16, pointer: u16) -> [u8; 8] {
    let mut body = [0; 8];
    body[..2].copy_from_slice(&id.to_le_bytes());
    body[4..6].copy_from_slice(&pointer.to_le_bytes());
    body
}
fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn add_wire(observed: &runtime::model::Published, owned: (u64, u64)) -> bool {
    if observed.queue != 0
        || observed.bytes.len() != 44
        || observed.bytes[..2] != [0x17, 5]
        || observed.bytes[7] != 0
    {
        return false;
    }
    let body = &observed.bytes[8..];
    let byte_counts = u64::from_le_bytes(body[20..28].try_into().unwrap());
    let descriptors = u64::from_le_bytes(body[28..36].try_into().unwrap());
    // Source-cited literal v3 payload with WIDE_ID header0; dynamic addresses
    // must be distinct, aligned and owned by this actual native queue.
    body[..20] == [0, 0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0]
        && byte_counts != 0
        && descriptors != 0
        && byte_counts != descriptors
        && (byte_counts, descriptors) == owned
        && byte_counts % 256 == 0
        && descriptors % 256 == 0
        && observed.doorbell == u32::from(observed.pointer)
}

fn composed(pointer: u16) -> Result<(), &'static str> {
    let mut fixture = Fixture::new();
    fixture.prepare_peer()?;
    fixture.prepare_queue()?;
    let native = fixture.trace.take().ok_or("missing native queue ADD DMA")?;
    let owned =
        runtime::model::queue_dma_addresses(&fixture.owner.as_ref().unwrap().hardware, QUEUE)
            .ok_or("missing owned native queue buffers")?;
    if !add_wire(&native, owned) {
        return Err("actual queue ADD does not match Linux v3 wire geometry");
    }
    let owner = fixture.owner.as_mut().unwrap();
    if owner.prepared_management_queue() != Some(QUEUE)
        || owner.prepared_ap_peer() != Some((AP, 1))
        || runtime::model::retained(&owner.hardware) != (0, 1, 0)
    {
        return Err("queue identity appeared before ADD receipt or lost retained DMA");
    }
    {
        let mut peer_remove = pin!(owner.release_ap_peer());
        if !matches!(poll(peer_remove.as_mut()), Poll::Ready(Err(_))) {
            return Err("peer removed before its firmware queue retired");
        }
    }
    {
        let mut release = pin!(owner.release_management_queue());
        if !poll(release.as_mut()).is_pending() {
            return Err("queue removal did not await native receipt");
        }
        let observed = fixture.trace.take().ok_or("missing native REMOVE DMA")?;
        let mut expected = [0; 36];
        expected[0] = 1;
        expected[4] = 1;
        expected[8] = 15;
        if observed.bytes[8..] != expected {
            return Err("actual REMOVE body differs from Linux v3 union");
        }
        fixture
            .firmware
            .inject(0x17, 5, 2, &retirement(QUEUE, pointer));
        if poll(release.as_mut()) != Poll::Ready(Ok(())) {
            return Err("exact queue removal receipt failed");
        }
    }
    if runtime::model::retained(&owner.hardware) != (0, 0, 0)
        || owner.prepared_management_queue().is_some()
        || owner.phase() != Phase::PeerPrepared
    {
        return Err("queue retirement did not release exactly its DMA and restore disabled peer");
    }
    {
        let mut removal = pin!(owner.release_ap_peer());
        if !poll(removal.as_mut()).is_pending() {
            return Err("peer did not await removal after queue retirement");
        }
        fixture.firmware.inject(0x19, 0, 3, &[]);
        if poll(removal.as_mut()) != Poll::Ready(Ok(())) {
            return Err("queue/peer ordered native retirement failed");
        }
    }
    if owner.phase() != Phase::ChannelPrepared || owner.channel.current != Some(1) {
        return Err("retiring queue/peer destroyed still-owned inactive PHY");
    }
    Ok(())
}
fn smoke_iwl_mvm_management_queue_native_add_remove_and_peer_fence() -> TestResult {
    // The initial-pointer field is used only for ADD. A valid REMOVE must
    // retire the same idle queue without interpreting it as a new producer.
    for pointer in [0, 0x45, u16::MAX] {
        if let Err(error) = composed(pointer) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_management_queue_native_add_remove_and_peer_fence
);

fn cancel(removing: bool) -> Result<(), &'static str> {
    let mut fixture = Fixture::new();
    fixture.prepare_peer()?;
    if removing {
        fixture.prepare_queue()?;
    }
    let owner = fixture.owner.as_mut().unwrap();
    if removing {
        let mut operation = pin!(owner.release_management_queue());
        if !poll(operation.as_mut()).is_pending() {
            return Err("queue REMOVE failed to wait");
        }
    } else {
        let mut operation = pin!(owner.prepare_management_queue());
        if !poll(operation.as_mut()).is_pending() {
            return Err("queue ADD failed to wait");
        }
    }
    if owner.phase()
        != if removing {
            Phase::RemovingManagementQueue
        } else {
            Phase::PreparingManagementQueue
        }
        || owner.prepared_management_queue().is_some()
        || runtime::model::retained(&owner.hardware) != (1, 1, 0)
    {
        return Err("cancelled queue operation released DMA or published usable identity");
    }
    let receipt = if removing {
        retirement(QUEUE, 0)
    } else {
        allocation(QUEUE)
    };
    fixture
        .firmware
        .inject(0x17, 5, if removing { 2 } else { 1 }, &receipt);
    for remove in [false, true] {
        let mut operation = pin!(async {
            if remove {
                owner.release_management_queue().await
            } else {
                owner.prepare_management_queue().await
            }
        });
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
            return Err("late queue receipt reopened cancelled allocation/retirement");
        }
    }
    let mut peer_remove = pin!(owner.release_ap_peer());
    if !matches!(poll(peer_remove.as_mut()), Poll::Ready(Err(_))) {
        return Err("cancelled queue operation allowed peer identity reuse");
    }
    Ok(())
}
fn smoke_iwl_mvm_management_queue_cancelled_native_ownership_is_retained() -> TestResult {
    for removing in [false, true] {
        if let Err(error) = cancel(removing) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_management_queue_cancelled_native_ownership_is_retained
);

fn bad_allocations() -> Result<(), &'static str> {
    let mut rejected = vec![
        vec![],
        vec![0; 4],
        vec![0; 7],
        vec![0; 9],
        allocation(0).to_vec(),
        allocation(512).to_vec(),
    ];
    let mut flagged = allocation(QUEUE);
    flagged[2] = 1;
    rejected.push(flagged.to_vec());
    for body in rejected {
        let mut fixture = Fixture::new();
        fixture.prepare_peer()?;
        let owner = fixture.owner.as_mut().unwrap();
        {
            let mut operation = pin!(owner.prepare_management_queue());
            if !poll(operation.as_mut()).is_pending() {
                return Err("bad allocation never published");
            }
            fixture.firmware.inject(0x17, 5, 1, &body);
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("malformed native queue allocation was accepted");
            }
        }
        if owner.phase() != Phase::Failed
            || !owner.hardware.is_failed()
            || owner.prepared_management_queue().is_some()
            || runtime::model::retained(&owner.hardware).1 != 1
        {
            return Err("rejected queue allocation freed uncertain DMA or exposed owner");
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_management_queue_malformed_native_allocation_stays_closed() -> TestResult {
    bad_allocations().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_management_queue_malformed_native_allocation_stays_closed
);

fn bad_removal() -> Result<(), &'static str> {
    let valid = retirement(QUEUE, 0);
    let mut failures = vec![
        (0x17, 5, 2, vec![]),
        (0x17, 5, 2, vec![0; 4]),
        (0x17, 5, 2, valid[..7].to_vec()),
        (0x17, 5, 2, vec![0; 9]),
        (0x17, 5, 2, retirement(QUEUE + 1, 0).to_vec()),
        (0x17, 5, 2, retirement(0, 0).to_vec()),
        (0x18, 5, 2, valid.to_vec()),
        (0x17, 3, 2, valid.to_vec()),
        (0x17, 5, 3, valid.to_vec()),
    ];
    for offset in [2, 3, 6, 7] {
        let mut malformed = valid;
        malformed[offset] = 1;
        failures.push((0x17, 5, 2, malformed.to_vec()));
    }
    for (command, group, sequence, payload) in failures {
        let mut fixture = Fixture::new();
        fixture.prepare_peer()?;
        fixture.prepare_queue()?;
        let owner = fixture.owner.as_mut().unwrap();
        {
            let mut operation = pin!(owner.release_management_queue());
            if !poll(operation.as_mut()).is_pending() {
                return Err("bad remove never published");
            }
            fixture.firmware.inject(command, group, sequence, &payload);
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("malformed or foreign queue remove receipt was accepted");
            }
        }
        if owner.phase() != Phase::Failed
            || runtime::model::retained(&owner.hardware).1 != 1
            || owner.prepared_management_queue().is_some()
        {
            return Err("failed queue remove released or exposed a live firmware identity");
        }
    }
    Ok(())
}
fn smoke_iwl_mvm_management_queue_requires_exact_native_removal_receipt() -> TestResult {
    bad_removal().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_management_queue_requires_exact_native_removal_receipt
);

fn idle_fence() -> Result<(), &'static str> {
    let mut fixture = Fixture::new();
    fixture.prepare_peer()?;
    fixture.prepare_queue()?;
    let owner = fixture.owner.as_mut().unwrap();
    let before = fixture.firmware.tx_write();
    for (station, tid) in [(1, 15), (0, 3)] {
        let mut operation = pin!(owner.hardware.remove_idle_tx(QUEUE, station, tid));
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_)))
            || fixture.firmware.tx_write() != before
        {
            return Err("idle queue removal accepted another station/TID or published IO");
        }
    }
    // A future internal producer must not turn this prerequisite's terminal
    // release into an active-queue drain. Seed a private native descriptor to
    // prove that unexpected DMA ownership keeps the entire queue retained.
    owner
        .hardware
        .enqueue_transmit(QUEUE, &[0; 24], 24, Some(0))?;
    {
        let mut operation = pin!(owner.release_management_queue());
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
            return Err("nonempty management prerequisite queue retired");
        }
    }
    if owner.phase() != Phase::Failed || runtime::model::retained(&owner.hardware) != (0, 1, 1) {
        return Err("unexpected management TX DMA was not retained on retirement failure");
    }
    Ok(())
}
fn smoke_iwl_mvm_management_queue_checks_binding_and_idle_before_retirement() -> TestResult {
    idle_fence().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_management_queue_checks_binding_and_idle_before_retirement
);

fn metadata() -> Result<(), &'static str> {
    for version in [
        None,
        Some((0, 0)),
        Some((3, 0)),
        Some((3, 99)),
        Some((4, 2)),
    ] {
        let mut fixture = Fixture::new();
        fixture.prepare_peer()?;
        let owner = fixture.owner.as_mut().unwrap();
        let commands = version.map_or_else(alloc::vec::Vec::new, |(command, response)| {
            vec![0x17, 5, command, response]
        });
        runtime::model::versions(&mut owner.hardware, &commands);
        let before = fixture.firmware.tx_write();
        {
            let mut operation = pin!(owner.prepare_management_queue());
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return Err("unknown native queue ABI was not rejected before allocation");
            }
        }
        if fixture.firmware.tx_write() != before
            || runtime::model::retained(&owner.hardware) != (0, 0, 0)
            || owner.phase() != Phase::PeerPrepared
            || owner.management_queue.is_some()
        {
            return Err("queue ABI preflight changed peer state or published/retained new DMA");
        }
    }
    let bytes = super::super::super::firmware_parser_tests::mvm_image();
    let parsed = super::super::super::parse_ucode(&bytes).unwrap();
    if parsed.api.versions(5, 0x17) != Some((3, 2)) {
        return Err("authored MVM table does not advertise native queue v3/response2");
    }
    let mut fixture = Fixture::new();
    runtime::model::versions(
        &mut fixture.owner.as_mut().unwrap().hardware,
        parsed.api.commands,
    );
    fixture.prepare_peer()?;
    fixture.prepare_queue()?;
    if fixture.owner.as_ref().unwrap().prepared_management_queue() != Some(QUEUE) {
        return Err("authored MVM negotiation did not reach retained native queue");
    }
    Ok(())
}
fn smoke_iwl_mvm_management_queue_uses_authored_api77_command_profile() -> TestResult {
    metadata().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_management_queue_uses_authored_api77_command_profile
);
