// SPDX-License-Identifier: GPL-2.0-or-later
//! BCM43602 removal, dead-firmware stop and generation swap over the
//! msgbuf model behind a published station shell.
use super::*;
use crate::cyw43439::interface::generation::{Generation, Publish, Removal};
use core::task::Poll as Step;

/// Republish a rebooted generation exactly as the harness built the first
/// one: station initialization replayed over the fresh firmware, then a
/// shell registered under the retired name.
fn publisher() -> Publish<TestAdapter> {
    Box::new(|name, adapter| {
        Box::pin(async move {
            let station = Station::initialize(adapter, &[], firmware::domain()).await?;
            narf_net::iface::register(name, OWN, send);
            Ok(shell(String::from(name), station))
        })
    })
}
fn poll_once<F: Future + ?Sized>(future: core::pin::Pin<&mut F>) -> Step<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn joined() -> Result<Harness, &'static str> {
    let harness = Harness::new(6, false, false)?;
    harness.associate(false)?;
    Ok(harness)
}
/// Put the retired netdev back so the harness drop unregisters it.
fn restore(harness: &Harness) {
    narf_net::iface::register(&harness.name, OWN, send);
}

/// Linux v7.2 `brcmf_pcie_remove` over a joined station: the shell
/// withdraws (registrations gone, netdev retired for a rebind, admission
/// closed), the device stops behind the D3-ack/drain/BME/flush proof and
/// only then is every published mapping freed.
fn smoke_brcmf_remove_withdraws_then_reclaims_after_stop_proof() -> TestResult {
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.d3_ack(true);
    let generation = Generation::new(harness.device.clone());
    if ready(generation.remove()) != Ok(Removal::Reclaimed) {
        return TestResult::Fail("acknowledged stop did not reclaim on removal");
    }
    let (allocated, dropped) = harness.bus.mappings();
    let (frame, _) = packets();
    if !harness.device.withdrawn()
        || !generation.removed()
        || harness.device.link_up()
        || harness.device.connected_bssid().is_some()
        || harness.device.enqueue(&frame).is_ok()
        || narf_net::iface::lookup(&harness.name).is_some()
        || narf_net::iface::rebind_name(&harness.name).is_none()
        || harness.bus.dma_enabled()
        || allocated != dropped
    {
        return TestResult::Fail("removal left the shell open or DMA mapped");
    }
    if ready(generation.remove()) != Ok(Removal::Absent)
        || !matches!(
            ready(harness.device.associate(Harness::request(false))),
            Ok(Err(_))
        )
    {
        return TestResult::Fail("removed owner reopened");
    }
    restore(&harness);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_remove_withdraws_then_reclaims_after_stop_proof
);

/// A device write observed after the BME clear voids the proof: removal
/// still withdraws and drops the generation, but no mapping is freed.
fn smoke_brcmf_remove_without_stop_proof_keeps_mappings_pinned() -> TestResult {
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.d3_ack(true);
    harness.bus.late_dma(true);
    let (_, before) = harness.bus.mappings();
    let generation = Generation::new(harness.device.clone());
    if ready(generation.remove()) != Ok(Removal::Pinned) {
        return TestResult::Fail("unproven stop reported reclaimed");
    }
    let (allocated, dropped) = harness.bus.mappings();
    if dropped != before
        || allocated == dropped
        || harness.bus.dma_enabled()
        || !harness.device.withdrawn()
        || narf_net::iface::lookup(&harness.name).is_some()
    {
        return TestResult::Fail("unproven stop freed DMA or left the shell published");
    }
    restore(&harness);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_remove_without_stop_proof_keeps_mappings_pinned
);

/// FWHALT (Linux `brcmf_fw_crashed`) fails the joined generation; removal
/// cannot get a D3 ack and takes the dead-firmware stop: BME clear, flush,
/// ChipCommon watchdog, halted CR4, and only then every mapping is freed.
fn smoke_brcmf_remove_after_fwhalt_takes_dead_stop_and_reclaims() -> TestResult {
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.fwhalt();
    harness.device.drain();
    if harness.device.link_up() {
        return TestResult::Fail("FWHALT left the carrier up");
    }
    let generation = Generation::new(harness.device.clone());
    if narf_scheduler::block_on(generation.remove()) != Removal::Reclaimed {
        return TestResult::Fail("halted generation was not reclaimed by the dead stop");
    }
    let (allocated, dropped) = harness.bus.mappings();
    let (watchdogs, shadows, _) = harness.bus.resets();
    if allocated != dropped
        || watchdogs != 1
        || shadows != 11
        || harness.bus.cr4_ioctrl() & 0x20 == 0
        || harness.bus.dma_enabled()
    {
        return TestResult::Fail("dead stop skipped reset/halt or left DMA mapped");
    }
    restore(&harness);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_remove_after_fwhalt_takes_dead_stop_and_reclaims
);

/// Linux v7.2 `brcmf_fw_crashed` -> `brcmf_pcie_reset`: FWHALT, dead stop,
/// `brcmf_pcie_reset_device`, a fresh download through the retained
/// authority, station initialization replay and the retained association
/// rejoined on a new shell under the same netdev name. Removal afterwards
/// frees the mappings of both generations.
fn smoke_brcmf_fwhalt_reset_reboots_replays_and_rejoins_same_netdev() -> TestResult {
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.fwhalt();
    harness.device.drain();
    if !harness.device.transport_failed() {
        return TestResult::Fail("FWHALT did not mark the transport terminal");
    }
    let generation = Generation::with_publisher(harness.device.clone(), publisher());
    if narf_scheduler::block_on(generation.recover()).is_err() {
        return TestResult::Fail("transport reset did not republish the station");
    }
    let Some(device) = generation.current() else {
        return TestResult::Fail("no generation after reset");
    };
    let (watchdogs, _, _) = harness.bus.resets();
    if Arc::ptr_eq(&device, &harness.device)
        || !harness.device.withdrawn()
        || device.withdrawn()
        || device.interface_name() != harness.name
        || narf_net::iface::lookup(&harness.name).is_none()
        || generation.resets() != 1
        || watchdogs < 1
        || !harness.bus.dma_enabled()
        || device.transport_failed()
    {
        return TestResult::Fail("reset did not publish a fresh generation under the same name");
    }
    if device.connected_bssid() != Some(AP) || !device.link_up() {
        return TestResult::Fail("retained association was not rejoined after reset");
    }
    harness.bus.d3_ack(true);
    if narf_scheduler::block_on(generation.remove()) != Removal::Reclaimed {
        return TestResult::Fail("rebooted generation was not reclaimed on removal");
    }
    let (allocated, dropped) = harness.bus.mappings();
    if allocated != dropped || narf_net::iface::lookup(&harness.name).is_some() {
        return TestResult::Fail("mappings of a generation survived removal");
    }
    restore(&harness);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_fwhalt_reset_reboots_replays_and_rejoins_same_netdev
);

/// A removal that arrives while the reset is in flight waits for it, and
/// the reset then never publishes: the fresh generation is stopped behind
/// its own proof and released; the netdev stays retired.
fn smoke_brcmf_remove_racing_reset_never_republishes() -> TestResult {
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.d3_ack(true);
    harness.bus.fwhalt();
    harness.device.drain();
    let generation = Generation::with_publisher(harness.device.clone(), publisher());
    let mut recovery = Box::pin(generation.recover());
    if poll_once(recovery.as_mut()).is_ready() {
        return TestResult::Fail("reset finished without the watchdog settle");
    }
    let mut removal = Box::pin(generation.remove());
    if poll_once(removal.as_mut()).is_ready() {
        return TestResult::Fail("removal did not wait for the in-flight reset");
    }
    if narf_scheduler::block_on(recovery.as_mut()) != Err(crate::cyw43439::runtime::Error::Busy) {
        return TestResult::Fail("reset published after a removal request");
    }
    if narf_scheduler::block_on(removal.as_mut()) != Removal::Absent {
        return TestResult::Fail("raced removal did not report a released function");
    }
    let (allocated, dropped) = harness.bus.mappings();
    if allocated != dropped
        || narf_net::iface::lookup(&harness.name).is_some()
        || generation.current().is_some()
        || harness.bus.dma_enabled()
    {
        return TestResult::Fail("raced reset left a shell or mappings behind");
    }
    restore(&harness);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_remove_racing_reset_never_republishes
);

/// A refused download keeps the reset bus (Cr4 refusal returns it) but
/// publishes nothing; the old generation was proven stopped and freed. A
/// healthy generation whose stop proof sees post-clear DMA never resets
/// and its mappings stay pinned through removal.
fn smoke_brcmf_reset_failures_stay_terminal_or_pinned() -> TestResult {
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.fwhalt();
    harness.device.drain();
    harness.bus.fail_tcm(true);
    let generation = Generation::with_publisher(harness.device.clone(), publisher());
    if narf_scheduler::block_on(generation.recover()).is_ok()
        || generation.current().is_some()
        || narf_net::iface::lookup(&harness.name).is_some()
    {
        return TestResult::Fail("refused download republished or stayed resettable");
    }
    let (allocated, dropped) = harness.bus.mappings();
    if allocated != dropped || narf_scheduler::block_on(generation.remove()) != Removal::Absent {
        return TestResult::Fail("refused download leaked the stopped generation");
    }
    restore(&harness);
    drop(harness);
    let harness = match joined() {
        Ok(harness) => harness,
        Err(error) => return TestResult::Fail(error),
    };
    harness.bus.d3_ack(true);
    harness.bus.late_dma(true);
    let (_, before) = harness.bus.mappings();
    let generation = Generation::with_publisher(harness.device.clone(), publisher());
    if narf_scheduler::block_on(generation.recover()).is_ok()
        || harness.bus.resets().0 != 0
        || harness.bus.mappings().1 != before
        || narf_scheduler::block_on(generation.remove()) != Removal::Pinned
    {
        return TestResult::Fail("unproven stop reset the chip or released DMA");
    }
    restore(&harness);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/station",
    smoke_brcmf_reset_failures_stay_terminal_or_pinned
);
