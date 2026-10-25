use super::super::super::{gen2_profile, runtime, rx_rfh};
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fixture {
    owner: Option<Owner>,
    firmware: runtime::model::Firmware,
}
fn api() -> FirmwareApi<'static> {
    let mut api = FirmwareApi {
        commands: &[8, 5, 2, 0],
        ..FirmwareApi::default()
    };
    api.api_changes[1] = (1 << 24) | (1 << 15);
    api.capabilities[1] = 1 << 16;
    api.capabilities[3] = 1 << 14;
    api
}
fn nvm() -> Nvm {
    let mut nvm = vec![0; 28 + 110 * 4];
    nvm[12..16].copy_from_slice(&3u32.to_le_bytes());
    nvm[16..20].copy_from_slice(&3u32.to_le_bytes());
    nvm[24..28].copy_from_slice(&1u32.to_le_bytes());
    nvm[28] = 1;
    Nvm::parse(4, &nvm).unwrap()
}
impl Fixture {
    fn new() -> Self {
        let (mut hardware, firmware) =
            runtime::model::create_for_format(false, rx_rfh::CompletionFormat::Qu);
        runtime::model::versions(
            &mut hardware,
            &[
                0xd, 1, 15, 0, 0x18, 1, 12, 2, 0xc, 1, 5, 0, 8, 3, 1, 0, 0xd2, 1, 4, 0, 0xd1, 1, 3,
                0, 0xa9, 1, 1, 0, 0xc8, 1, 1, 5, 8, 5, 2, 0,
            ],
        );
        let api = api();
        Self {
            owner: Some(Owner {
                hardware,
                firmware: vec![],
                profile: gen2_profile::select(0xa0f0, 0x351, 0x10c000).unwrap(),
                phase: Phase::Configured,
                mac: Some([2; 6]),
                nvm: Some(nvm()),
                peer: None,
                management_queue: None,
                power: super::super::power::Context::new(&FirmwareApi::default()),
                beacons: vec![],
                scan: super::super::scan::ScanContext::new(&api),
                channel: ChannelContext::new(&api),
            }),
            firmware,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // SAFETY: this private RAM/DMA fixture never published to a device.
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
    owner.prepare_channel_in_domain(1, &policy()).await
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
const COMMANDS: [(u8, u8); 9] = [
    (0xc, 1),
    (8, 3),
    (0xd2, 0),
    (0xd1, 0),
    (9, 3),
    (0xa9, 0),
    (8, 1),
    (8, 5),
    (9, 3),
];

fn smoke_iwl_mvm_inactive_phy_native_receipts_and_fenced_reuse() -> TestResult {
    let mut f = Fixture::new();
    let owner = f.owner.as_mut().unwrap();
    {
        let mut operation = pin!(prepare(owner));
        for (sequence, (command, group)) in COMMANDS.into_iter().enumerate() {
            if !poll(operation.as_mut()).is_pending()
                || f.firmware.tx_write() != sequence as u32 + 1
            {
                return TestResult::Fail("inactive PHY published before prerequisite receipt");
            }
            f.firmware.inject(command, group, sequence as u16, &[]);
        }
        if poll(operation.as_mut()) != Poll::Ready(Ok(())) {
            return TestResult::Fail("exact inactive PHY binding receipt did not finish");
        }
    }
    if owner.phase() != Phase::ChannelPrepared || owner.channel.current != Some(1) {
        return TestResult::Fail("MVM channel ownership did not follow binding ACK");
    }
    {
        let mut release = pin!(owner.release_inactive_channel());
        if !poll(release.as_mut()).is_pending()
            || f.firmware.tx_write() != COMMANDS.len() as u32 + 1
        {
            return TestResult::Fail("MVM channel unbind not published first");
        }
        f.firmware.inject(9, 3, COMMANDS.len() as u16, &[]);
        if !poll(release.as_mut()).is_pending()
            || f.firmware.tx_write() != COMMANDS.len() as u32 + 2
        {
            return TestResult::Fail("PHY remove did not wait for binding retirement");
        }
        f.firmware.inject(8, 1, COMMANDS.len() as u16 + 1, &[]);
        if poll(release.as_mut()) != Poll::Ready(Ok(())) {
            return TestResult::Fail("PHY remove exact receipt did not reopen owner");
        }
    }
    if owner.phase() != Phase::Configured || owner.channel.current.is_some() {
        return TestResult::Fail("retired PHY retained stale channel or admission");
    }
    let mut reuse = pin!(prepare(owner));
    if !poll(reuse.as_mut()).is_pending() || f.firmware.tx_write() != COMMANDS.len() as u32 + 3 {
        return TestResult::Fail("ACK-fenced channel could not be prepared again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_inactive_phy_native_receipts_and_fenced_reuse
);

fn smoke_iwl_mvm_inactive_phy_cancel_each_native_boundary_stays_closed() -> TestResult {
    for acknowledged in 0..=COMMANDS.len() + 1 {
        let mut f = Fixture::new();
        let owner = f.owner.as_mut().unwrap();
        {
            let mut operation = pin!(prepare(owner));
            for (sequence, (command, group)) in COMMANDS
                .into_iter()
                .enumerate()
                .take(acknowledged.min(COMMANDS.len()))
            {
                if !poll(operation.as_mut()).is_pending() {
                    return TestResult::Fail("PHY preparation completed before receipt");
                }
                f.firmware.inject(command, group, sequence as u16, &[]);
            }
            let result = poll(operation.as_mut());
            if acknowledged < COMMANDS.len() && !result.is_pending() {
                return TestResult::Fail("PHY preparation prematurely completed");
            }
            if acknowledged >= COMMANDS.len() && result != Poll::Ready(Ok(())) {
                return TestResult::Fail("could not prepare PHY cancellation fixture");
            }
        }
        if acknowledged >= COMMANDS.len() {
            let mut release = pin!(owner.release_inactive_channel());
            if !poll(release.as_mut()).is_pending() {
                return TestResult::Fail("PHY release completed before receipt");
            }
            if acknowledged == COMMANDS.len() + 1 {
                f.firmware.inject(9, 3, COMMANDS.len() as u16, &[]);
                if !poll(release.as_mut()).is_pending() {
                    return TestResult::Fail("PHY remove completed before receipt");
                }
            }
        }
        let before = f.firmware.tx_write();
        {
            let mut retry = pin!(prepare(owner));
            if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("cancelled PHY reopened preparation");
            }
        }
        {
            let mut retry = pin!(owner.release_inactive_channel());
            if !matches!(poll(retry.as_mut()), Poll::Ready(Err(_))) {
                return TestResult::Fail("cancelled PHY replayed release");
            }
        }
        if before != f.firmware.tx_write() {
            return TestResult::Fail("cancelled PHY published a second native command");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_inactive_phy_cancel_each_native_boundary_stays_closed
);

fn smoke_iwl_mvm_inactive_phy_policy_and_abi_fail_before_commands() -> TestResult {
    for case in 0..5 {
        let mut f = Fixture::new();
        let owner = f.owner.as_mut().unwrap();
        let mut domain = policy();
        match case {
            0 => owner.channel.version = 6,
            1 => domain.rules.clear(),
            2 => domain.rules[0].max_bandwidth_mhz = 10,
            3 => owner.nvm.as_mut().unwrap().channels.clear(),
            _ => owner.nvm.as_mut().unwrap().rx_chains = 0,
        }
        let mut operation = pin!(owner.prepare_channel_in_domain(1, &domain));
        if !matches!(poll(operation.as_mut()), Poll::Ready(Err(_))) || f.firmware.tx_write() != 0 {
            return TestResult::Fail("invalid MVM inactive PHY policy/ABI published commands");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_inactive_phy_policy_and_abi_fail_before_commands
);

fn smoke_iwl_mvm_inactive_phy_linux_packed_geometry_and_masks() -> TestResult {
    let nvm = nvm();
    let mut context = ChannelContext::new(&api());
    let wide = context.command(1, 1, &nvm).unwrap();
    if wide.len() != 40
        || wide[4..8] != 1u32.to_le_bytes()
        || wide[16..24] != [1, 0, 0, 0, 1, 0, 0, 0]
        || wide[24..28] != 3u32.to_le_bytes()
        || wide[28..32] != 0x2806u32.to_le_bytes()
    {
        return TestResult::Fail("MVM v1 PHY does not match native40-byte API77 layout");
    }
    let rlc = context.rlc_command(&nvm).unwrap();
    if rlc[..4] != [0; 4] || rlc[4..8] != 0x2806u32.to_le_bytes() || rlc[8..] != [0; 24] {
        return TestResult::Fail("MVM RLCv2 native32-byte profile differs from Linux");
    }
    for version in [0, 1, 3, 4] {
        context.rlc_version = version;
        if context.rlc_command(&nvm).is_some() {
            return TestResult::Fail("MVM RLC command sent for absent/old/offloaded profile");
        }
    }
    context.ultra_channels = false;
    let narrow = context.command(3, 1, &nvm).unwrap();
    if narrow.len() != 36
        || narrow[4..8] != 3u32.to_le_bytes()
        || narrow[16..20] != [1, 1, 0, 0]
        || narrow[20..24] != 3u32.to_le_bytes()
        || narrow[24..28] != 0x2806u32.to_le_bytes()
    {
        return TestResult::Fail("MVM old channel-v1 PHY tail placement differs from Linux");
    }
    let binding = inactive_binding([2; 6], true);
    let unbind = inactive_binding([2; 6], false);
    if binding[24..32] != [0; 8] || binding[12..16] != [0; 4] || unbind[12..16] != [255; 4] {
        return TestResult::Fail("MVM PHY binding activated a link or retained retired PHY");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_inactive_phy_linux_packed_geometry_and_masks
);
