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

fn discovery(owner: &Owner, words: &mut [u32]) {
    ready(async {
        owner.state.lock().await.discovery = Some(narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: words.as_mut_ptr() as u64,
            len: core::mem::size_of_val(words) as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        });
    })
    .unwrap();
}

fn smoke_iwlwifi_sc_native_identity_selects_exact_staged_rf_with_other_images_present() -> TestResult
{
    let owner = owner();
    owner.parked();
    let mut registers = [0u32; 0xa0 / 4];
    // Independent Linux CSR fields: MAC Sc=0x48/A0, RF FM=0x112/C0,
    // jacket bit29. WH-b0 is first in the old static cross-RF ladder.
    registers[0x28 / 4] = 0x480;
    registers[0x9c / 4] = 0x2011_2200;
    discovery(&owner, &mut registers);
    let (write, read) = narf_firmware::bootstrap_authority();
    // Test-only registry namespace: inert headers cannot shadow production
    // firmware even when smokes run on a machine containing a real Sc device.
    install(
        &write,
        "narf-test/sc-selection/iwlwifi/iwlwifi-sc-a0-wh-b0-c107.ucode",
        &header(),
        true,
    )
    .unwrap();
    install(
        &write,
        "narf-test/sc-selection/iwlwifi/iwlwifi-sc-a0-gf-a0-c107.ucode",
        &header(),
        true,
    )
    .unwrap();
    let (names, identity) = ready(async {
        let mut state = owner.state.lock().await;
        owner.candidates(&mut state)
    })
    .unwrap()
    .unwrap();
    let scoped: Vec<String> = names
        .iter()
        .map(|name| alloc::format!("narf-test/sc-selection/{name}"))
        .collect();
    if !matches!(ready(owner.provision_using(&read, &scoped)), Some(Err(_)))
        || owner.phase() != ProvisionState::Parked
        || ready(async { owner.state.lock().await.interface.is_none() }) != Some(true)
    {
        return TestResult::Fail(
            "Sc selected another installed RF or consumed missing-image startup",
        );
    }
    let mut expected = header();
    expected[8] = b'F';
    install(
        &write,
        "narf-test/sc-selection/iwlwifi/iwlwifi-sc-a0-fm-c0-c103.ucode",
        &expected,
        true,
    )
    .unwrap();
    install(
        &write,
        "narf-test/sc-selection/iwlwifi/iwlwifi-sc-a0-fm-c0.pnvm",
        b"exact-FM-C0-PNVM",
        true,
    )
    .unwrap();
    let inputs = resolve(&read, &scoped).unwrap();
    if names.len() != 6
        || names[0] != "iwlwifi/iwlwifi-sc-a0-fm-c0-c107.ucode"
        || names[5] != "iwlwifi/iwlwifi-sc-a0-fm-c0-c102.ucode"
        || inputs.firmware.bytes != expected
        || inputs.pnvm.as_ref().map(|asset| asset.bytes.as_slice())
            != Some(b"exact-FM-C0-PNVM".as_slice())
    {
        return TestResult::Fail("Sc RF-specific API ladder or selected sibling PNVM changed");
    }
    let mut io = super::super::IwlMmioImpl::new(
        ready(async { owner.state.lock().await.discovery.unwrap() }).unwrap(),
        owner.cap,
    );
    registers[0x9c / 4] = 0x2011_2100; // Same FM family, different firmware step.
    if identity.unwrap().check(&mut io).is_ok() {
        return TestResult::Fail("Sc startup/restart accepted a changed RF step");
    }
    registers[0x9c / 4] = 0x2011_2200;
    install(
        &write,
        "narf-test/sc-selection/iwlwifi/iwlwifi-sc-a0-fm-c0-c107.ucode",
        b"bad-selected-image",
        true,
    )
    .unwrap();
    if resolve(&read, &scoped).is_ok() {
        return TestResult::Fail("present invalid exact Sc image fell through to older API");
    }
    // The actual current MMIO invocation, not a cached identity token, guards
    // the next public startup. No ECAM/firmware/DMA access follows revocation.
    owner.cap.revoke();
    if !matches!(ready(owner.provision_with_authority(&read)), Some(Err(_)))
        || owner.phase() != ProvisionState::Parked
        || identity.unwrap().check(&mut io).is_ok()
        || registers[0x28 / 4] != 0x480
        || registers[0x9c / 4] != 0x2011_2200
    {
        return TestResult::Fail(
            "Sc deferred selection bypassed current native identity authority",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bootstrap",
    smoke_iwlwifi_sc_native_identity_selects_exact_staged_rf_with_other_images_present
);

fn smoke_iwlwifi_sc_csr_mac_step_rf_cdb_profile_boundaries() -> TestResult {
    let owner = owner();
    owner.parked();
    let mut registers = [0u32; 0xa0 / 4];
    discovery(&owner, &mut registers);
    // Literal source CSR values, deliberately not produced by the selector.
    // GF uses A firmware even for another physical RF step (iwl-drv.c).
    for (revision, radio, suffix) in [
        (0x480, 0x2011_3100, Some("wh-b0")),
        (0x480, 0x2011_2100, Some("fm-b0")),
        (0x480, 0x2011_2200, Some("fm-c0")),
        (0x480, 0x0010_d500, Some("gf-a0")),
        (0x481, 0x2011_3100, None),
        (0x460, 0x2011_3100, None),
        (0x480, 0x2011_3000, None),
        (0x480, 0x2011_2300, None),
        (0x480, 0x1010_d000, None),
        (0x480, 0, None),
        (u32::MAX, 0x2011_3100, None),
        (0x480, u32::MAX, None),
    ] {
        registers[0x28 / 4] = revision;
        registers[0x9c / 4] = radio;
        let result = ready(async {
            let mut state = owner.state.lock().await;
            owner.candidates(&mut state)
        })
        .unwrap();
        match (result, suffix) {
            (Ok((names, Some(_))), Some(suffix))
                if names.len() == 6
                    && names[0] == alloc::format!("iwlwifi/iwlwifi-sc-a0-{suffix}-c107.ucode") => {}
            (Err(_), None) => {}
            _ => return TestResult::Fail("Sc actual CSR MAC/step/RF/CDB profile mismatch"),
        }
        if owner.phase() != ProvisionState::Parked {
            return TestResult::Fail("Sc identity-only admission began a firmware attempt");
        }
    }
    // A complete revision dword with a truncated RF register is a real native
    // read failure, not a zero/default RF identity.
    ready(async {
        owner.state.lock().await.discovery.as_mut().unwrap().len = 0x9c;
    })
    .unwrap();
    if ready(async {
        let mut state = owner.state.lock().await;
        owner.candidates(&mut state)
    })
    .unwrap()
    .is_ok()
    {
        return TestResult::Fail("Sc admitted an unreadable actual RF dword");
    }
    // No public/native constructor can omit the selected Sc identity. The
    // deliberately invalid ECAM/MMIO proves rejection precedes native access.
    let bytes = header();
    let parsed = super::super::parse_ucode(&bytes).unwrap();
    let result = super::super::runtime::Hardware::new(
        owner.device,
        owner.cap,
        narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0xa0,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        },
        &parsed,
        CompletionFormat::Bz,
        None,
    );
    if !matches!(
        result,
        Err("Sc startup requires selected hardware identity")
    ) {
        return TestResult::Fail("native Sc constructor accepted an unbound selected image");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bootstrap",
    smoke_iwlwifi_sc_csr_mac_step_rf_cdb_profile_boundaries
);
