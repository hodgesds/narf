// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 SDIO reset authority over the actual SDHCI `Card`, signed
//! selection and AI/CM3 loader; only device bytes are modeled
//! (`sdio_ap_model`). Written for the kernel-test harness.
use super::*;
use crate::brcmfmac::provision::tests::{choose, registry, TEST_MANIFEST};
use crate::cyw43439::runtime::Runtime;
use alloc::boxed::Box;
use narf_drivers_sdio::card::{tests::Model, Config};
use narf_kernel_test::{kernel_test_in, TestResult};

type Fixture = (Runtime<SdioTransport<Card<Model>>>, Model, Clm);

/// A booted generation; `function` is the F1 identity the authority retains.
fn booted(function: Option<(u16, u16)>) -> Result<Fixture, &'static str> {
    let (_, read) = registry()?;
    let selection = choose(&read, Family::Sdio43439).map_err(|_| "signed selection")?;
    let assets = selection
        .load_using(&read)
        .map_err(|_| "signed selected assets")?;
    let nvram = crate::brcmfmac::boot::pack_nvram(&assets.nvram).map_err(|_| "NVRAM")?;
    let (endpoint, _bus) = super::super::sdio_ap_model::Device::new();
    let host = Model::with_endpoint(Box::new(endpoint), Some(selection.host()));
    let card = Card::initialize(host.clone(), Config::default()).map_err(|_| "card init")?;
    let actual = card.function(1).map(|f| (f.vendor, f.device)).ok_or("F1")?;
    let transport = boot_card(card, &assets, &nvram, selection.revisions())?;
    let clm: Clm = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    let reboot = Reprovision::new(
        read,
        TEST_MANIFEST,
        selection.host(),
        function.unwrap_or(actual),
        clm.clone(),
    );
    let runtime = Runtime::new(transport).with_reboot(Box::new(reboot));
    Ok((runtime, host, clm))
}

/// `brcmf_sdio_bus_reset` then re-probe: the stop comes first, the card is
/// power-cycled and re-enumerated before any backplane access, the firmware
/// is downloaded again under a fresh signed selection, and the fresh
/// generation moves out leaving the old one terminal.
fn reset_reboots_fresh_generation() -> Result<(), &'static str> {
    let (mut runtime, host, clm) = booted(None)?;
    runtime.fail();
    if runtime.reset_transport() != Err(Error::Busy) {
        return Err("reset ran before the generation stopped");
    }
    runtime
        .stop_for_reset()
        .map_err(|_| "native stop of a live card")?;
    let before = host.native_commands().len();
    runtime.reset_transport().map_err(|_| "SDIO reset/reboot")?;
    let opcodes: Vec<u8> = host.native_commands()[before..]
        .iter()
        .map(|c| c.0)
        .collect();
    // mmc_hw_reset precedes every command of the re-probe.
    if opcodes.get(..7) != Some(&[52, 52, 0, 5, 5, 3, 7][..]) || !opcodes[7..].contains(&53) {
        return Err("reset was not power cycle + reinit + firmware download");
    }
    if clm.lock().is_empty() {
        return Err("fresh selection did not publish its CLM");
    }
    let mut fresh = runtime.take_generation().ok_or("no fresh generation")?;
    if !runtime.is_failed() || runtime.take_generation().is_some() || !runtime.release_transport() {
        return Err("the old generation was not left terminal and empty");
    }
    if fresh.is_failed() || !fresh.resettable() || fresh.poll().is_err() {
        return Err("fresh generation not serviceable");
    }
    Ok(())
}
fn smoke_cyw_sdio_reset_power_cycles_card_and_reboots_fresh_generation() -> TestResult {
    match reset_reboots_fresh_generation() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio",
    smoke_cyw_sdio_reset_power_cycles_card_and_reboots_fresh_generation
);

/// A generation whose native stop is impossible takes the
/// `brcmf_sdio_bus_reset` prelude (host bus power off). A card that does
/// not come back as the same F1 identity fails the reset: no firmware
/// command follows, nothing is pinned, the generation stays terminal. A
/// runtime without a reset authority keeps the strict stop and refuses.
fn reset_fails_closed() -> Result<(), &'static str> {
    let (mut runtime, host, _) = booted(Some((0x2d0, 0xbeef)))?;
    runtime.fail();
    // A fatal transport error: the native stop is no longer provable.
    runtime.transport_mut().ok_or("transport")?.fail_for_test();
    runtime
        .stop_for_reset()
        .map_err(|_| "dead-firmware host power-off stop refused")?;
    let before = host.native_commands().len();
    if runtime.reset_transport() != Err(Error::Authority) {
        return Err("reset accepted a card with a different identity");
    }
    let opcodes: Vec<u8> = host.native_commands()[before..]
        .iter()
        .map(|c| c.0)
        .collect();
    if opcodes.get(..7) != Some(&[52, 52, 0, 5, 5, 3, 7][..]) || opcodes[7..].contains(&53) {
        return Err("mismatched card reached the firmware loader");
    }
    if runtime.take_generation().is_some() || !runtime.release_transport() {
        return Err("failed reset left a generation or pinned the dropped card");
    }
    // Without the authority: strict confirmed stop only, no reset.
    let (runtime, host, _) = booted(None)?;
    let mut plain = runtime.without_reboot();
    plain.transport_mut().ok_or("transport")?.fail_for_test();
    let before = host.native_commands().len();
    if plain.stop_for_reset().is_ok()
        || plain.reset_transport() != Err(Error::Unsupported)
        || plain.release_transport()
        || host.native_commands()[before..].iter().any(|c| c.0 == 0)
    {
        return Err("runtime without a reset authority stopped dead or reset");
    }
    Ok(())
}
fn smoke_cyw_sdio_reset_dead_stop_and_foreign_card_fail_closed() -> TestResult {
    match reset_fails_closed() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio",
    smoke_cyw_sdio_reset_dead_stop_and_foreign_card_fail_closed
);
