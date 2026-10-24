use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Fixture {
    owner: Option<Owner>,
    firmware: super::super::runtime::model::Firmware,
}
impl Fixture {
    fn new() -> Self {
        let (mut hardware, firmware) = super::super::runtime::model::create_for_format(
            false,
            super::super::rx_rfh::CompletionFormat::Qu,
        );
        super::super::runtime::model::versions(
            &mut hardware,
            &[
                2, 12, 1, 4, 0x98, 1, 1, 0, 0x9b, 1, 6, 0, 1, 2, 2, 0, 0x77, 1, 6, 0, 12, 1, 5, 0,
            ],
        );
        Self {
            owner: Some(Owner {
                hardware,
                firmware: vec![],
                profile: super::super::gen2_profile::select(0xa0f0, 0x351, 0x10c000).unwrap(),
                phase: Phase::Starting,
                mac: None,
                nvm: None,
                peer: None,
                beacons: Vec::new(),
                channel: super::channel::ChannelContext::new(
                    &super::super::firmware_api::FirmwareApi::default(),
                ),
                scan: super::scan::ScanContext::new(
                    &super::super::firmware_api::FirmwareApi::default(),
                ),
            }),
            firmware,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // SAFETY: this private RAM/DMA fixture has never published to a device.
            unsafe { super::super::runtime::model::destroy(owner.hardware) };
        }
    }
}
fn poll<T>(future: core::pin::Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        // Private RAM has no interrupt source. Allow the production 1 ms
        // no-IRQ fallback to expire before the next manual poll; polling
        // repeatedly at the same timestamp cannot wake that real timer.
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}

fn nvm() -> Vec<u8> {
    let mut b = vec![0; 28 + 110 * 4];
    b[12..16].copy_from_slice(&3u32.to_le_bytes());
    b[16..20].copy_from_slice(&3u32.to_le_bytes());
    b[24..28].copy_from_slice(&14u32.to_le_bytes());
    for channel in 0..14 {
        b[28 + channel * 4] = 1;
    }
    b
}
fn smoke_iwl_mvm_boot_defaults_native_command_receipts() -> TestResult {
    let mut fixture = Fixture::new();
    let owner = fixture.owner.as_mut().unwrap();
    {
        let mut configure = pin!(owner.configure([2; 6]));
        for (index, (command, group, body)) in [
            (2, 12, nvm()),
            (0x98, 1, vec![]),
            (0x9b, 1, vec![]),
            (1, 2, vec![]),
            (0x77, 1, vec![]),
        ]
        .into_iter()
        .enumerate()
        {
            let mut submitted = false;
            for _ in 0..4 {
                if !poll(configure.as_mut()).is_pending() {
                    return TestResult::Fail(
                        "MVM post-init completed before all correlated firmware receipts",
                    );
                }
                if fixture.firmware.tx_write() == index as u32 + 1 {
                    submitted = true;
                    break;
                }
            }
            if !submitted {
                return TestResult::Fail("MVM command did not publish on real TFH command queue");
            }
            fixture.firmware.inject(command, group, index as u16, &body);
        }
        let mut done = false;
        for _ in 0..4 {
            match poll(configure.as_mut()) {
                Poll::Ready(Ok(())) => {
                    done = true;
                    break;
                }
                Poll::Ready(Err(_)) => return TestResult::Fail("MVM real RFH receipt rejected"),
                Poll::Pending => {}
            }
        }
        if !done {
            return TestResult::Fail("final MVM config receipt did not finish owner");
        }
    }
    if owner.phase() != Phase::Configured
        || owner
            .identity()
            .is_none_or(|(mac, n)| mac != [2; 6] || n.channels.len() != 14 || n.tx_chains != 3)
    {
        return TestResult::Fail("MVM identity/NVM appeared before complete runtime configuration");
    }
    let before = fixture.firmware.tx_write();
    let mut retry = pin!(owner.initialize());
    if poll(retry.as_mut()) != Poll::Ready(Err("MVM boot already attempted"))
        || fixture.firmware.tx_write() != before
    {
        return TestResult::Fail("configured MVM boot replayed a reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_boot_defaults_native_command_receipts
);
fn smoke_iwl_mvm_boot_cancel_retains_native_pending_command_and_identity_closed() -> TestResult {
    let mut fixture = Fixture::new();
    let owner = fixture.owner.as_mut().unwrap();
    {
        let mut configure = pin!(owner.configure([2; 6]));
        if !poll(configure.as_mut()).is_pending() || fixture.firmware.tx_write() != 1 {
            return TestResult::Fail("MVM NVM request was not submitted before cancellation");
        }
    }
    if owner.identity().is_some() || owner.phase() != Phase::Starting {
        return TestResult::Fail("cancelled MVM boot published identity or reopened owner");
    }
    let mut retry = pin!(owner.initialize());
    if poll(retry.as_mut()) != Poll::Ready(Err("MVM boot already attempted"))
        || fixture.firmware.tx_write() != 1
    {
        return TestResult::Fail("dropped MVM NVM waiter replayed native submission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_boot_cancel_retains_native_pending_command_and_identity_closed
);
fn smoke_iwl_mvm_soc_defaults_match_exact_pci_latency_profiles() -> TestResult {
    for (did, hw, expected) in [
        (0x2723, 0x340, [1, 0, 0, 0, 0, 0, 0, 0]),
        (0x02f0, 0x351, [4, 0, 0, 0, 0xf4, 1, 0, 0]),
        (0xa0f0, 0x351, [10, 0, 0, 0, 0xe0, 0x2e, 0, 0]),
    ] {
        let c = configuration(super::super::gen2_profile::select(did, hw, 0x10c000).unwrap());
        if c.soc != expected || c.coexistence != [1, 0, 0, 0, 17, 0, 0, 0] {
            return TestResult::Fail("MVM exact PCI SoC latency/BT defaults");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_mvm_soc_defaults_match_exact_pci_latency_profiles
);
