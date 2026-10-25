use super::super::super::{
    connection::Beacon, firmware_api::FirmwareApi, gen2_profile, runtime, rx_rfh, station_api::Nvm,
};
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
const VERSIONS: &[u8] = &[
    0xd, 1, 15, 0, 0x18, 1, 12, 2, 0x19, 1, 2, 0, 0xc, 1, 5, 0, 8, 3, 1, 0, 0xd2, 1, 4, 0, 0xd1, 1,
    3, 0, 0xa9, 1, 1, 0, 0xc8, 1, 1, 3,
];

struct Fixture {
    owner: Option<Owner>,
    firmware: runtime::model::Firmware,
}
impl Fixture {
    fn new(lar: bool) -> Self {
        let (mut hardware, firmware) =
            runtime::model::create_for_format(false, rx_rfh::CompletionFormat::Qu);
        runtime::model::versions(&mut hardware, VERSIONS);
        let mut api = FirmwareApi::default();
        api.api_changes[1] = (1 << 24) | (1 << 15);
        api.capabilities[3] = 1 << 14;
        if lar {
            api.capabilities[0] |= 1 << 1;
        }
        let mut scan = super::super::scan::ScanContext::new(&api);
        scan.ready = true;
        scan.nvm_lar = lar;
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
                power: super::super::power::Context::new(&FirmwareApi::default()),
            }),
            firmware,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // SAFETY: only the private RAM/RFH/TFH fixture saw these addresses.
            unsafe { runtime::model::destroy(owner.hardware) };
        }
    }
}

fn policy() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 10,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
async fn prepare(owner: &mut Owner) -> Result<(), &'static str> {
    owner.prepare_peer_in_domain(AP, &policy()).await
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
fn mcc(flags: u32) -> Vec<u8> {
    let mut body = vec![0; 20];
    body[12..16].copy_from_slice(&1u32.to_le_bytes());
    body[16..20].copy_from_slice(&flags.to_le_bytes());
    body
}

fn smoke_iwl_mvm_disabled_peer_native_status_and_remove_receipts() -> TestResult {
    let mut fixture = Fixture::new(false);
    let owner = fixture.owner.as_mut().unwrap();
    for round in 0..2u16 {
        if owner.prepared_ap_peer().is_some() {
            return TestResult::Fail("peer metadata survived a completed removal");
        }
        {
            let mut operation = pin!(prepare(owner));
            if !poll(operation.as_mut()).is_pending()
                || fixture.firmware.tx_write() != u32::from(round * 2 + 1)
            {
                return TestResult::Fail("peer ADD did not retain actual native command ownership");
            }
            // Legacy long-group commands can return group0 headers. The
            // command queue validates that alias and the exact command/SSN.
            fixture
                .firmware
                .inject(ADD_STA, 0, round * 2, &[1, 0, 0, 0]);
            if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
                return TestResult::Fail("native ADD_STA_SUCCESS failed peer preparation");
            }
        }
        if owner.phase() != Phase::PeerPrepared || owner.prepared_ap_peer() != Some((AP, 1)) {
            return TestResult::Fail("prepared peer identity did not follow ADD status");
        }
        {
            let mut conflicting = pin!(owner.release_inactive_channel());
            if !matches!(poll(conflicting.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("PHY unbound while the firmware AP peer was retained");
            }
        }
        {
            let mut removal = pin!(owner.release_ap_peer());
            if !poll(removal.as_mut()).is_pending()
                || fixture.firmware.tx_write() != u32::from(round * 2 + 2)
            {
                return TestResult::Fail("peer removal did not await a native receipt");
            }
            fixture.firmware.inject(REMOVE_STA, 0, round * 2 + 1, &[]);
            if poll(removal.as_mut()) != Poll::Ready(Ok(())) {
                return TestResult::Fail("native REMOVE_STA receipt did not retire peer");
            }
        }
        if owner.phase() != Phase::ChannelPrepared
            || owner.peer.is_some()
            || owner.channel.current != Some(1)
        {
            return TestResult::Fail("peer retirement lost the still-owned inactive PHY");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_disabled_peer_native_status_and_remove_receipts
);

fn smoke_iwl_mvm_disabled_peer_status_and_foreign_receipts_fail_closed() -> TestResult {
    for (command, group, sequence, payload) in [
        (ADD_STA, 0, 0, vec![]),
        (ADD_STA, 0, 0, vec![1; 3]),
        (ADD_STA, 0, 0, vec![1; 8]),
        (ADD_STA, 0, 0, vec![0; 4]),
        (ADD_STA, 0, 0, vec![2, 0, 0, 0]),
        (ADD_STA, 0, 0, vec![4, 0, 0, 0]),
        (ADD_STA, 0, 0, vec![8, 0, 0, 0]),
        (REMOVE_STA, 0, 0, vec![1, 0, 0, 0]),
        (ADD_STA, 3, 0, vec![1, 0, 0, 0]),
        (ADD_STA, 0, 1, vec![1, 0, 0, 0]),
    ] {
        let mut fixture = Fixture::new(false);
        let owner = fixture.owner.as_mut().unwrap();
        {
            let mut operation = pin!(prepare(owner));
            if !poll(operation.as_mut()).is_pending() {
                return TestResult::Fail("peer status negative did not publish ADD");
            }
            fixture.firmware.inject(command, group, sequence, &payload);
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("invalid or foreign ADD response accepted");
            }
        }
        if owner.phase() != Phase::Failed
            || owner.prepared_ap_peer().is_some()
            || owner.peer.is_none()
        {
            return TestResult::Fail("failed ADD released identity or advertised prepared peer");
        }
        let before = fixture.firmware.tx_write();
        let mut retry = pin!(prepare(owner));
        if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_)))
            || before != fixture.firmware.tx_write()
        {
            return TestResult::Fail("failed peer ADD reopened native publication");
        }
    }
    for (command, group, sequence, payload) in [
        (REMOVE_STA, 0, 1, vec![1]),
        (ADD_STA, 0, 1, vec![]),
        (REMOVE_STA, 0, 0, vec![]),
    ] {
        let mut fixture = Fixture::new(false);
        let owner = fixture.owner.as_mut().unwrap();
        {
            let mut operation = pin!(prepare(owner));
            if !poll(operation.as_mut()).is_pending() {
                return TestResult::Fail("remove negative did not publish ADD");
            }
            fixture.firmware.inject(ADD_STA, 0, 0, &[1, 0, 0, 0]);
            if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
                return TestResult::Fail("remove negative could not prepare the peer");
            }
        }
        {
            let mut removal = pin!(owner.release_ap_peer());
            if !poll(removal.as_mut()).is_pending() {
                return TestResult::Fail("remove negative did not publish REMOVE");
            }
            fixture.firmware.inject(command, group, sequence, &payload);
            if !matches!(poll(removal.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("malformed or stale REMOVE receipt retired the peer");
            }
        }
        if owner.phase() != Phase::Failed || owner.peer.is_none() {
            return TestResult::Fail("failed REMOVE released the firmware peer identity");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_disabled_peer_status_and_foreign_receipts_fail_closed
);

fn smoke_iwl_mvm_disabled_peer_requeries_mcc_before_add() -> TestResult {
    let mut fixture = Fixture::new(true);
    let owner = fixture.owner.as_mut().unwrap();
    {
        let mut operation = pin!(prepare(owner));
        if !poll(operation.as_mut()).is_pending() || fixture.firmware.tx_write() != 1 {
            return TestResult::Fail("peer did not query current MCC before ADD");
        }
        fixture.firmware.inject(0xc8, 0, 0, &mcc(1));
        if !poll(operation.as_mut()).is_pending() || fixture.firmware.tx_write() != 2 {
            return TestResult::Fail("peer ADD was not ordered after permitted MCC");
        }
        fixture.firmware.inject(ADD_STA, 0, 1, &[1, 0, 0, 0]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return TestResult::Fail("MCC-permitted native peer did not complete");
        }
    }
    {
        let mut removal = pin!(owner.release_ap_peer());
        if !poll(removal.as_mut()).is_pending() {
            return TestResult::Fail("MCC peer removal did not await receipt");
        }
        fixture.firmware.inject(REMOVE_STA, 0, 2, &[]);
        if poll(removal.as_mut()) != Poll::Ready(Ok(())) {
            return TestResult::Fail("MCC peer removal failed");
        }
    }
    {
        let mut operation = pin!(prepare(owner));
        if !poll(operation.as_mut()).is_pending() || fixture.firmware.tx_write() != 4 {
            return TestResult::Fail("second peer retained an old MCC permission");
        }
        fixture.firmware.inject(0xc8, 0, 3, &mcc(0));
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_)))
            || fixture.firmware.tx_write() != 4
        {
            return TestResult::Fail("newly denied MCC still published ADD_STA");
        }
    }
    if owner.phase() != Phase::Failed || owner.peer.is_none() {
        return TestResult::Fail("failed MCC released the reserved peer transaction");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_disabled_peer_requeries_mcc_before_add
);

fn smoke_iwl_mvm_disabled_peer_cancel_each_native_boundary_stays_closed() -> TestResult {
    for boundary in 0..3 {
        let mut fixture = Fixture::new(true);
        let owner = fixture.owner.as_mut().unwrap();
        {
            let mut operation = pin!(prepare(owner));
            if !poll(operation.as_mut()).is_pending() {
                return TestResult::Fail("peer cancellation fixture did not publish MCC");
            }
            if boundary >= 1 {
                fixture.firmware.inject(0xc8, 0, 0, &mcc(1));
                if !poll(operation.as_mut()).is_pending() || fixture.firmware.tx_write() != 2 {
                    return TestResult::Fail("peer cancellation fixture did not publish ADD");
                }
            }
            if boundary == 2 {
                fixture.firmware.inject(ADD_STA, 0, 1, &[1, 0, 0, 0]);
                if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
                    return TestResult::Fail("peer cancellation fixture did not complete ADD");
                }
            }
        }
        if boundary == 2 {
            let mut removal = pin!(owner.release_ap_peer());
            if !poll(removal.as_mut()).is_pending() {
                return TestResult::Fail("peer cancellation removal unexpectedly completed");
            }
        }
        let phase = if boundary == 2 {
            Phase::RemovingPeer
        } else {
            Phase::PreparingPeer
        };
        if owner.phase() != phase || owner.peer.is_none() || owner.prepared_ap_peer().is_some() {
            return TestResult::Fail("dropped peer operation lost its reserved identity");
        }
        let before = fixture.firmware.tx_write();
        {
            let mut retry = pin!(prepare(owner));
            if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("cancelled peer preparation reopened");
            }
        }
        {
            let mut retry = pin!(owner.release_ap_peer());
            if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("cancelled peer removal replayed");
            }
        }
        {
            let mut retry = pin!(owner.release_inactive_channel());
            if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("cancelled peer permitted PHY unbinding");
            }
        }
        if fixture.firmware.tx_write() != before {
            return TestResult::Fail("cancelled peer submitted a conflicting command");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_disabled_peer_cancel_each_native_boundary_stays_closed
);

fn smoke_iwl_mvm_disabled_peer_identity_policy_and_abi_preflight() -> TestResult {
    for case in 0..22 {
        let mut fixture = Fixture::new(false);
        let owner = fixture.owner.as_mut().unwrap();
        let mut domain = policy();
        let mut bssid = AP;
        match case {
            0 => owner.phase = Phase::Configured,
            1 => owner.hardware.fail(),
            2 => owner.scan.ready = false,
            3 => runtime::model::versions(
                &mut owner.hardware,
                &[ADD_STA, 1, 11, 2, REMOVE_STA, 1, 2, 0],
            ),
            4 => runtime::model::versions(
                &mut owner.hardware,
                &[ADD_STA, 1, 12, 1, REMOVE_STA, 1, 2, 0],
            ),
            5 => runtime::model::versions(
                &mut owner.hardware,
                &[ADD_STA, 1, 12, 2, REMOVE_STA, 1, 3, 0],
            ),
            6 => owner.channel.current = None,
            7 => owner.nvm = None,
            8 => owner.mac = None,
            9 => bssid = [0; 6],
            10 => bssid[0] |= 1,
            11 => bssid = [2; 6],
            12 => bssid[1] ^= 1,
            13 => owner.beacons[0].channel = 6,
            14 => owner.beacons[0].capabilities = 2,
            15 => owner.nvm.as_mut().unwrap().channels.clear(),
            16 => owner.nvm.as_mut().unwrap().tx_chains = 0,
            17 => owner.nvm.as_mut().unwrap().rx_chains = 0,
            18 => domain.rules.clear(),
            19 => domain.rules[0].max_bandwidth_mhz = 10,
            _ => runtime::model::versions(
                &mut owner.hardware,
                &[
                    ADD_STA,
                    1,
                    12,
                    2,
                    REMOVE_STA,
                    1,
                    2,
                    if case == 20 { 1 } else { 99 },
                ],
            ),
        }
        let phase = owner.phase();
        {
            let mut operation = pin!(owner.prepare_peer_in_domain(bssid, &domain));
            if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_)))
                || fixture.firmware.tx_write() != 0
            {
                return TestResult::Fail(
                    "invalid peer profile/identity/policy published native IO",
                );
            }
        }
        if owner.phase() != phase || owner.peer.is_some() {
            return TestResult::Fail("peer preflight failure consumed an unpublished identity");
        }
    }
    for response in [1, 99] {
        let mut fixture = Fixture::new(false);
        let owner = fixture.owner.as_mut().unwrap();
        owner.phase = Phase::PeerPrepared;
        owner.peer = Some(ApPeer {
            bssid: AP,
            channel: 1,
        });
        runtime::model::versions(&mut owner.hardware, &[REMOVE_STA, 1, 2, response]);
        {
            let mut removal = pin!(owner.release_ap_peer());
            if !matches!(poll(removal.as_mut()), Poll::Ready(Err(_)))
                || fixture.firmware.tx_write() != 0
            {
                return TestResult::Fail("unknown REMOVE response ABI published native IO");
            }
        }
        if owner.phase() != Phase::PeerPrepared || owner.prepared_ap_peer() != Some((AP, 1)) {
            return TestResult::Fail("REMOVE ABI preflight failure discarded retained peer");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_disabled_peer_identity_policy_and_abi_preflight
);

fn smoke_iwl_mvm_disabled_peer_linux_packed_body_and_captured_api() -> TestResult {
    // Full output of mvm_peer_linux_oracle.py compiled against Linux sta.h.
    const LINUX_ADD: [u8; 48] = [
        0, 0, 255, 255, 0, 0, 0, 0, 2, 4, 6, 8, 10, 12, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 16, 0, 2,
        60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    if add_command(AP) != LINUX_ADD {
        return TestResult::Fail("disabled peer body differs from independent Linux C layout");
    }
    let replay = super::super::super::firmware_golden_tests::api77_replay();
    let parsed = match super::super::super::parse_ucode(&replay) {
        Ok(parsed) => parsed,
        Err(_) => return TestResult::Fail("pinned API77 metadata failed decode"),
    };
    if parsed.api.versions(1, ADD_STA) != Some((12, 2))
        || parsed.api.versions(1, REMOVE_STA) != Some((2, 0))
        || parsed.api.versions(3, 0xa).is_some()
    {
        return TestResult::Fail("API77 legacy peer command profile changed");
    }
    let mut fixture = Fixture::new(false);
    let owner = fixture.owner.as_mut().unwrap();
    runtime::model::versions(&mut owner.hardware, parsed.api.commands);
    owner.scan = super::super::scan::ScanContext::new(&parsed.api);
    owner.scan.ready = true;
    {
        let mut operation = pin!(prepare(owner));
        if !poll(operation.as_mut()).is_pending() || fixture.firmware.tx_write() != 1 {
            return TestResult::Fail(
                "actual captured API77 profile could not publish disabled ADD",
            );
        }
        fixture.firmware.inject(ADD_STA, 0, 0, &[1, 0, 0, 0]);
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return TestResult::Fail("actual captured API77 profile rejected native ADD status");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_disabled_peer_linux_packed_body_and_captured_api
);
