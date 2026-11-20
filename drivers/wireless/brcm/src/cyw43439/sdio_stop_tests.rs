// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal native F0/F1/EROM/CM3 stop through the real SdioTransport and
//! SDPCM Runtime. Card-level SDHCI/CCCR/CPU-route failures are independently
//! exercised by the two native drivers/sdio/card prerequisite cases.
use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

fn native() -> SdioTransport<Host> {
    let mut host = Host {
        line: true,
        sleep_model: true,
        stop_model: true,
        ..Host::default()
    };
    host.words.insert(0x18000000, 0x1000a9af);
    host.words.insert(0x180000fc, 0x18100000);
    let descriptors = [
        0x4bf80001, 0x18080001, 0x18000005, 0x18110085, 0x4bf82a01, 0x07080001, 0x18002005,
        0x18114085, 0x4bf80e01, 0x18080001, 0x18004005, 0x18116085, 0x4bf81201, 0x18080001,
        0x18003005, 0x18118085, 0x4bf82901, 0x18080001, 0x18011005, 0x1811a085, 0xf,
    ];
    for (index, word) in descriptors.into_iter().enumerate() {
        host.words.insert(0x18100000 + index as u32 * 4, word);
    }
    host.words.insert(CORE + 0x20, 0x200000f0);
    let mut transport = SdioTransport::new(host);
    transport.prepare().unwrap();
    transport.initialize_packets(CORE).unwrap();
    transport
}

fn smoke_cyw_native_stop_requires_f2_off_cm3_passive_and_original_irq_retirement() -> TestResult {
    for asleep in [false, true] {
        let mut transport = native();
        if asleep {
            transport.func.words.insert(0x18000604, 17);
            transport.func.words.insert(0x18000508, 1);
            if transport.initialize_sleep(24) != Ok(true)
                || transport.enter_sleep().is_err()
                || !transport.sleep.is_some_and(|sleep| sleep.asleep)
            {
                return TestResult::Fail("native save-restore/KSO sleep setup before stop");
            }
        }
        if PacketTransport::confirmed_stop(&mut transport).is_err() {
            return TestResult::Fail("actual native SDIO/CM3 stop sequence");
        }
        let host = &transport.func;
        if host.enabled != 0
            || host.regs.get(&(0, 2)) != Some(&0)
            || host.regs.get(&(0, 3)) != Some(&0)
            || host.notify.is_some()
            || host.claimed.is_some()
            || transport.interrupt.is_some()
            || host.words.get(&(CORE + 0x24)) != Some(&0)
            || host.words.get(&(CORE + 0x20)) != Some(&0)
            || host.words.get(&0x18114800) != Some(&1)
            || host.words.get(&0x18118800) != Some(&0)
            || host.words.get(&0x18118408) != Some(&5)
            || host.words.get(&0x18116800) != Some(&0)
            || host.words.get(&0x18004010) != Some(&3)
            || host.words.get(&0x18004044) != Some(&0)
            || host.regs.get(&(1, 0x1000e)) != Some(&0)
        {
            return TestResult::Fail("stop invented function/interrupt/passive/clock receipt");
        }
        let off = host
            .ops
            .iter()
            .filter(|op| op.0 == 56)
            .map(|op| op.1)
            .collect::<Vec<_>>();
        if off != [2, 1] {
            return TestResult::Fail("F1 retired before native F2/passive work");
        }
        let before = host.ops.len();
        if transport.receive_packet(&mut [0; 64]) != Err(TransportError::NotReady)
            || transport.transmit_packet(&[0; 12]) != Err(TransportError::NotReady)
            || transport.prepare().is_ok()
            || transport.func.ops.len() != before
            || PacketTransport::confirmed_stop(&mut transport).is_err()
            || transport.func.ops.len() != before
        {
            return TestResult::Fail(
                "stopped original owner reissued work or replayed native stop",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/stop",
    smoke_cyw_native_stop_requires_f2_off_cm3_passive_and_original_irq_retirement
);

fn smoke_cyw_native_stop_partial_or_foreign_geometry_never_grants_reclamation() -> TestResult {
    for fault in 0..6 {
        let mut transport = native();
        match fault {
            0 => transport.func.refuse_irq_disable = true,
            1 => transport.func.refuse_disable = true,
            2 => {
                transport.func.words.insert(0x18000000, 0x1000a9a6);
            }
            3 => {
                transport.packet_core = Some(CORE + 0x1000);
            }
            4 => transport.func.held_word = Some(0x18114800),
            _ => transport.func.fail_write = true,
        }
        if PacketTransport::confirmed_stop(&mut transport).is_ok()
            || transport.stopped
            || !transport.failed
            || transport.func.notify.is_some()
            || transport.func.claimed.is_some()
            || transport.interrupt.is_some()
        {
            return TestResult::Fail(
                "partial/foreign stop manufactured proof or kept original CPU route",
            );
        }
        let calls = transport.func.ops.len();
        if transport.receive_packet(&mut [0; 64]).is_ok()
            || transport.transmit_packet(&[0; 12]).is_ok()
            || transport.func.ops.len() != calls
        {
            return TestResult::Fail("failed native stop reopened original physical work");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/stop",
    smoke_cyw_native_stop_partial_or_foreign_geometry_never_grants_reclamation
);

fn smoke_cyw_native_runtime_releases_only_after_actual_stop_and_retains_uncertain_owner(
) -> TestResult {
    for refused in [false, true] {
        let mut transport = native();
        transport.func.refuse_disable = refused;
        let retired = alloc::sync::Arc::new(AtomicUsize::new(0));
        transport.func.retired = Some(Retirement(retired.clone()));
        let mut runtime = super::super::super::runtime::Runtime::new(transport);
        // A prior protocol failure cannot stand in for native retirement,
        // nor prevent the original physical cleanup from being attempted.
        runtime.fail();
        if runtime.release_transport() || retired.load(Ordering::Acquire) != 0 {
            return TestResult::Fail("ordinary failed flag supplied native release authority");
        }
        if runtime.stop_transport().is_ok() == refused
            || runtime.release_transport() == refused
            || retired.load(Ordering::Acquire) != usize::from(!refused)
        {
            return TestResult::Fail(
                "Runtime release did not follow complete original native proof",
            );
        }
        drop(runtime);
        if retired.load(Ordering::Acquire) != usize::from(!refused) {
            return TestResult::Fail("late Runtime drop released unproved original host/card");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/stop",
    smoke_cyw_native_runtime_releases_only_after_actual_stop_and_retains_uncertain_owner
);

fn smoke_cyw_native_stop_revoked_selected_source_keeps_only_original_irq_cleanup() -> TestResult {
    use crate::brcmfmac::provision::{
        tests::{revoke_fixture_calibration, selected_fixture},
        Family,
    };
    let (_, assets) = match selected_fixture(Family::Sdio43439) {
        Ok(value) => value,
        Err(reason) => return TestResult::Fail(reason),
    };
    let mut transport = native().qualify(assets.proof.clone());
    let before = transport.func.ops.len();
    revoke_fixture_calibration(&assets.proof);
    if PacketTransport::confirmed_stop(&mut transport).is_ok()
        || transport.stopped
        || transport.func.notify.is_some()
        || transport.func.claimed.is_some()
    {
        return TestResult::Fail(
            "revoked selected owner supplied native stop or retained CPU subscriber",
        );
    }
    let cleanup = &transport.func.ops[before..];
    if !cleanup.iter().any(|op| op.0 == 57)
        || cleanup
            .iter()
            .any(|op| op.1 != 0 || !matches!(op.0, 52 | 57))
        || transport.func.words.contains_key(&0x18114800)
    {
        return TestResult::Fail(
            "revoked selection dispatched F1/F2/core work beyond original denial cleanup",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/stop",
    smoke_cyw_native_stop_revoked_selected_source_keeps_only_original_irq_cleanup
);
