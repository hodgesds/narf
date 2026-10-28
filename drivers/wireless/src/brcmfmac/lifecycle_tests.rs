// SPDX-License-Identifier: GPL-2.0-or-later
//! BCM43602 removal, dead-firmware stop and generation swap over the
//! msgbuf model behind a published station shell.
use super::*;
use crate::cyw43439::interface::generation::{Generation, Removal};

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
