use super::*;
use crate::firmware_asset::tests::install;
use alloc::vec::Vec;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
fn header() -> Vec<u8> {
    // Minimal non-executable Intel TLV container; it must never pass the
    // deliberately revoked native PCI boundary in this boot-order fixture.
    let mut bytes = alloc::vec![0;super::super::TLV_HEADER_BYTES];
    bytes[4..8].copy_from_slice(&super::super::IWL_TLV_UCODE_MAGIC.to_le_bytes());
    bytes
}
fn owner() -> Owner {
    let address = narf_bus::PcieAddr::new(0xfffe, 0xfb, 0x1a, 3);
    let device = BusDevice {
        addr: narf_bus::BusAddr::Pcie(address),
        id: narf_bus::DeviceId {
            vendor: 0x8086,
            device: 0xe340,
            subsystem_vendor: 0x8086,
            subsystem_id: 0xffff,
            class: 0x028000,
        },
        kind: narf_bus::BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    Owner::new(
        device,
        Cap::bootstrap(),
        super::super::chip_config_for_pci_id(0x8086, 0xe340).unwrap(),
    )
}
fn smoke_iwlwifi_deferred_assets_and_cancelled_wait_keep_same_binding_then_native_failure_is_terminal(
) -> TestResult {
    let owner = owner();
    let (write, read) = narf_firmware::bootstrap_authority();
    let names = alloc::vec![String::from("narf-test/iwlwifi/deferred-input-1.ucode")];
    if !matches!(ready(owner.provision_using(&read, &names)), Some(Err(_)))
        || owner.phase() != ProvisionState::Parking
    {
        return TestResult::Fail("retry became admissible before initial verified PCI parking");
    }
    owner.parked();

    if !matches!(ready(owner.provision_using(&read, &names)), Some(Err(_)))
        || owner.phase() != ProvisionState::Parked
    {
        return TestResult::Fail("pre-Late missing firmware consumed retained Intel startup");
    }
    let binding = owner.cap.slot();
    let guard = ready(owner.state.lock()).unwrap();
    {
        let mut future = core::pin::pin!(owner.provision_using(&read, &names));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("Intel startup did not serialize retained state");
        }
    }
    drop(guard);
    if owner.phase() != ProvisionState::Parked || owner.cap.slot() != binding {
        return TestResult::Fail("cancelled pre-attempt wait replaced or closed Intel binding");
    }
    install(
        &write,
        "narf-test/iwlwifi/deferred-input-1.ucode",
        &header(),
        true,
    )
    .unwrap();
    owner.cap.revoke();
    if !matches!(ready(owner.provision_using(&read, &names)), Some(Err(_)))
        || owner.phase() != ProvisionState::Failed
        || !matches!(ready(owner.provision_using(&read, &names)), Some(Err(_)))
        || ready(async { owner.state.lock().await.interface.is_none() }) != Some(true)
    {
        return TestResult::Fail(
            "staged Intel startup touched revoked native ECAM or retried terminal attempt",
        );
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/iwlwifi/bootstrap",smoke_iwlwifi_deferred_assets_and_cancelled_wait_keep_same_binding_then_native_failure_is_terminal);
fn smoke_iwlwifi_current_asset_ladder_and_owned_optional_pnvm() -> TestResult {
    let (write, read) = narf_firmware::bootstrap_authority();
    install(
        &write,
        "narf-test/iwlwifi/ladder-good-1.ucode",
        &header(),
        true,
    )
    .unwrap();
    install(
        &write,
        "narf-test/iwlwifi/ladder-good.pnvm",
        b"inert-pnvm-copy",
        true,
    )
    .unwrap();
    let names = alloc::vec![
        String::from("narf-test/iwlwifi/absent-1.ucode"),
        String::from("narf-test/iwlwifi/ladder-good-1.ucode")
    ];
    let inputs = resolve(&read, &names).unwrap();
    if inputs.firmware.bytes != header()
        || inputs.pnvm.as_ref().map(|asset| asset.bytes.as_slice())
            != Some(b"inert-pnvm-copy".as_slice())
    {
        return TestResult::Fail("Intel deferred ladder or sibling PNVM copied different bytes");
    }
    inputs.pnvm.as_ref().unwrap().cap.revoke();
    if inputs.pnvm.as_ref().unwrap().current() {
        return TestResult::Fail("Intel PNVM source epoch remained current");
    }
    install(
        &write,
        "narf-test/iwlwifi/ladder-bad-1.ucode",
        b"invalid-TLV",
        true,
    )
    .unwrap();
    let names = alloc::vec![
        String::from("narf-test/iwlwifi/ladder-bad-1.ucode"),
        String::from("narf-test/iwlwifi/ladder-good-1.ucode")
    ];
    if resolve(&read, &names).is_ok() {
        return TestResult::Fail("present invalid Intel image fell through to older firmware");
    }
    read.revoke();
    if resolve(&read, &names).is_ok() {
        return TestResult::Fail("Intel ladder bypassed current registry epoch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bootstrap",
    smoke_iwlwifi_current_asset_ladder_and_owned_optional_pnvm
);

fn smoke_iwlwifi_staged_assets_cannot_start_until_initial_parking_readback() -> TestResult {
    let owner = owner();
    let (write, read) = narf_firmware::bootstrap_authority();
    let name = "narf-test/iwlwifi/parking-input-1.ucode";
    install(&write, name, &header(), true).unwrap();
    let names = alloc::vec![String::from(name)];
    if !matches!(ready(owner.provision_using(&read, &names)), Some(Err(_)))
        || owner.phase() != ProvisionState::Parking
    {
        return TestResult::Fail("public retry raced initial probe parking into native startup");
    }
    // The parked transition becomes visible only after probe's successful
    // command readback. Revoked PCI then proves this same staged input reaches
    // the genuine current native boundary, with no fake hardware activation.
    owner.parked();
    owner.cap.revoke();
    if !matches!(ready(owner.provision_using(&read, &names)), Some(Err(_)))
        || owner.phase() != ProvisionState::Failed
    {
        return TestResult::Fail("verified parking transition lost same-owner startup admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bootstrap",
    smoke_iwlwifi_staged_assets_cannot_start_until_initial_parking_readback
);
